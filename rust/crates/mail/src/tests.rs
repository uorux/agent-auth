//! The IMAP and SMTP clients against the fake servers, over TLS.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use crate::imap::{self, ImapError, or_all};
use crate::smtp::{self, Envelope, SmtpError};
use crate::testing::{FakeImap, FakeSmtp, TestCa};

#[tokio::test]
async fn imap_login_search_fetch() {
    let ca = TestCa::new();
    let fake = FakeImap::start(&ca, "me@mail.example", "p\u{e9}ss \"w\"").await;
    fake.add("INBOX", b"Subject: one\r\n\r\nhello\r\n");
    let big = vec![b'x'; 70_000];
    fake.add("INBOX", &big);
    let tls = ca.client_config();
    let mut s = imap::connect(
        &tls,
        "localhost",
        fake.port,
        "me@mail.example",
        "p\u{e9}ss \"w\"",
    )
    .await
    .unwrap();
    let sel = s.examine("INBOX").await.unwrap().unwrap();
    assert_eq!(sel.uidvalidity, 7);
    assert!(s.examine("Nope").await.unwrap().is_none());
    s.examine("INBOX").await.unwrap();
    let criteria = or_all(&[vec!["FROM".into(), imap::quote("a@b.example").unwrap()]]);
    let uids = s.uid_search(&criteria).await.unwrap();
    assert_eq!(uids, vec![1, 2]);
    assert_eq!(
        s.uid_fetch(1).await.unwrap(),
        b"Subject: one\r\n\r\nhello\r\n"
    );
    assert_eq!(s.uid_fetch(2).await.unwrap().len(), 70_000);
    assert_eq!(s.uid_fetch(9).await, Err(ImapError::Gone));
    s.logout().await;
    let commands = fake.state.lock().unwrap().commands.clone();
    // The non-ASCII password went as a literal; the folder quoted.
    assert!(commands[0].starts_with("A1 LOGIN me@mail.example p\u{e9}ss"));
    assert!(commands.iter().any(|c| c == "A2 EXAMINE INBOX"));
}

#[tokio::test]
async fn imap_wrong_password_and_untrusted_certificate() {
    let ca = TestCa::new();
    let fake = FakeImap::start(&ca, "u", "right").await;
    let tls = ca.client_config();
    let err = imap::connect(&tls, "localhost", fake.port, "u", "wrong")
        .await
        .unwrap_err();
    assert_eq!(err, ImapError::Login);
    // Another CA: the handshake fails, nothing is sent.
    let other = TestCa::new().client_config();
    let err = imap::connect(&other, "localhost", fake.port, "u", "right")
        .await
        .unwrap_err();
    assert_eq!(err, ImapError::Conn(crate::conn::ConnError::Tls));
    assert!(
        fake.state
            .lock()
            .unwrap()
            .commands
            .iter()
            .all(|c| !c.contains("right"))
    );
}

fn envelope<'a>(rcpts: &'a [String], msg: &'a [u8]) -> Envelope<'a> {
    Envelope {
        sender: "me@mail.example",
        recipients: rcpts,
        message: msg,
    }
}

#[tokio::test]
async fn smtp_implicit_tls() {
    let ca = TestCa::new();
    let fake = FakeSmtp::start(&ca, true, "me@mail.example", "pw").await;
    let tls: Arc<rustls::ClientConfig> = ca.client_config();
    let rcpts = vec!["a@x.example".to_owned(), "b@x.example".to_owned()];
    fake.state.lock().unwrap().refuse.push("b@x.example".into());
    let refused = smtp::send(
        &tls,
        "localhost",
        fake.port,
        true,
        "me@mail.example",
        "pw",
        envelope(&rcpts, b"Subject: hi\r\n\r\n.dot\r\nbody\r\n"),
    )
    .await
    .unwrap();
    assert_eq!(refused, vec!["b@x.example"]);
    let st = fake.state.lock().unwrap();
    assert_eq!(st.received.len(), 1);
    assert_eq!(st.received[0].recipients, vec!["a@x.example"]);
    assert_eq!(st.received[0].data, b"Subject: hi\r\n\r\n.dot\r\nbody\r\n");
}

#[tokio::test]
async fn smtp_starttls_is_required() {
    let ca = TestCa::new();
    let fake = FakeSmtp::start(&ca, false, "me@mail.example", "pw").await;
    let tls = ca.client_config();
    let rcpts = vec!["a@x.example".to_owned()];
    smtp::send(
        &tls,
        "localhost",
        fake.port,
        false,
        "me@mail.example",
        "pw",
        envelope(&rcpts, b"x\r\n"),
    )
    .await
    .unwrap();
    assert_eq!(fake.state.lock().unwrap().auth_over_tls, vec![true]);
    // A server that does not offer STARTTLS gets nothing.
    fake.state.lock().unwrap().offer_starttls = false;
    let err = smtp::send(
        &tls,
        "localhost",
        fake.port,
        false,
        "me@mail.example",
        "pw",
        envelope(&rcpts, b"x\r\n"),
    )
    .await
    .unwrap_err();
    assert_eq!(err, SmtpError::NoStartTls);
    assert_eq!(fake.state.lock().unwrap().auth_over_tls, vec![true]);
    // Wrong password; every recipient refused.
    fake.state.lock().unwrap().offer_starttls = true;
    let err = smtp::send(
        &tls,
        "localhost",
        fake.port,
        false,
        "me@mail.example",
        "no",
        envelope(&rcpts, b"x\r\n"),
    )
    .await
    .unwrap_err();
    assert_eq!(err, SmtpError::Login);
    fake.state.lock().unwrap().refuse.push("a@x.example".into());
    let err = smtp::send(
        &tls,
        "localhost",
        fake.port,
        false,
        "me@mail.example",
        "pw",
        envelope(&rcpts, b"x\r\n"),
    )
    .await
    .unwrap_err();
    assert_eq!(err, SmtpError::AllRecipientsRefused);
    // An address that would inject a command is refused before connecting.
    let bad = vec!["a@x.example>\r\nRCPT TO:<c@y.example".to_owned()];
    let err = smtp::send(
        &tls,
        "localhost",
        fake.port,
        false,
        "me@mail.example",
        "pw",
        envelope(&bad, b"x\r\n"),
    )
    .await
    .unwrap_err();
    assert_eq!(err, SmtpError::Refused("an address"));
}
