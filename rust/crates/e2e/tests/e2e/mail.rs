//! Platform `mail`: an agent reads and sends on a mailbox through the
//! broker (never holding its password), over IMAP and SMTP with TLS; the
//! operator releases what it wants to send.

use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use agent_auth_mail::testing::{FakeImap, FakeSmtp, TestCa};

use crate::harness::{Broker, Setup, TempDir, Who, database_url};

#[sqlx::test(migrations = false)]
async fn an_agent_reads_and_sends_mail_it_never_holds_a_password_for(
    _: PgPoolOptions,
    opts: PgConnectOptions,
) {
    let ca = TestCa::new();
    let imap = FakeImap::start(&ca, "me@mail.example", "mailbox-pw").await;
    let smtp = FakeSmtp::start(&ca, false, "me@mail.example", "mailbox-pw").await;
    let files = TempDir::new();
    let password = files.path().join("mailbox-pw");
    std::fs::write(&password, "mailbox-pw\n").unwrap();
    let ca_file = files.path().join("ca.pem");
    std::fs::write(&ca_file, &ca.ca_pem).unwrap();
    let policy = format!(
        r#"
defaults: {{action: surface, max_duration: 24h}}
platforms:
  mail:
    mailboxes:
      main: {{address: me@mail.example, backend: imap, imap_host: localhost, imap_port: {},
              smtp_host: localhost, smtp_port: {}, password_file: "{}", direct: true}}
"#,
        imap.port,
        smtp.port,
        password.display()
    );
    // No OPENROUTER_API_KEY: no judge, so every send waits for a human.
    let setup =
        Setup::new(database_url(&opts), &policy).env("MAIL_CA_FILE", ca_file.to_str().unwrap());
    let b = Broker::start(setup).await;
    let agent = b.create_agent("travel-agent", &[]).await;

    // A mailbox itself, with correspondents: always a human.
    let req = b
        .cli(
            agent.who(),
            &[
                "request",
                "mail",
                "read+send",
                "me@mail.example",
                "--scope",
                r#"{"correspondents": ["*@qantas.example"]}"#,
                "--why",
                "rebook my Perth flight with the airline",
            ],
        )
        .await
        .ok();
    assert_eq!(req["status"], "awaiting_human", "{req}");
    let id = req["id"].as_str().unwrap();
    b.cli(Who::Admin, &["admin", "decide", id, "--approve"])
        .await
        .ok();
    let req = b.cli(agent.who(), &["status", id]).await.ok();
    let grant = req["grant_id"].as_str().unwrap().to_owned();
    let cred = b.cli(agent.who(), &["cred", &grant]).await.ok();
    assert_eq!(cred["kind"], "mail_gateway");
    assert_eq!(cred["value"], Value::Null);

    imap.add(
        "INBOX",
        b"From: Desk <desk@qantas.example>\r\nTo: me@mail.example\r\nSubject: Your seat\r\nDate: Sat, 24 Oct 2026 10:00:00 +0000\r\n\r\nSeat 12A is yours.\r\n",
    );
    imap.add(
        "INBOX",
        b"From: friend@private.example\r\nTo: me@mail.example\r\nSubject: Dinner\r\n\r\nprivate\r\n",
    );
    let list = b.cli(agent.who(), &["mail-list", &grant]).await.ok();
    let messages = list["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1, "{list}");
    assert_eq!(messages[0]["subject"], "Your seat");
    let message = messages[0]["id"].as_str().unwrap();
    let read = b
        .cli(agent.who(), &["mail-read", &grant, message])
        .await
        .ok();
    assert_eq!(read["text"], "Seat 12A is yours.");

    let body = files.path().join("body.txt");
    std::fs::write(&body, "An aisle seat, please.").unwrap();
    let sent = b
        .cli(
            agent.who(),
            &[
                "mail-send",
                &grant,
                "--reply-to",
                message,
                "--body-file",
                body.to_str().unwrap(),
            ],
        )
        .await
        .ok();
    assert_eq!(sent["status"], "held", "{sent}");
    let held = b.cli(Who::Admin, &["admin", "mail-held"]).await.ok();
    assert_eq!(held[0]["excerpt"], "An aisle seat, please.", "{held}");
    let item = sent["id"].as_str().unwrap();
    let released = b
        .cli(Who::Admin, &["admin", "mail-release", item, "--by", "jrt"])
        .await
        .ok();
    assert_eq!(released["status"], "sent", "{released}");
    assert_eq!(released["decided_by"], "jrt");
    let again = b
        .cli(Who::Admin, &["admin", "mail-release", item])
        .await
        .refused();
    assert!(again.starts_with("[409]"), "{again}");

    let got = smtp.state.lock().unwrap().received.clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].recipients, vec!["desk@qantas.example"]);
    let data = String::from_utf8_lossy(&got[0].data).into_owned();
    assert!(data.contains("Subject: Re: Your seat"), "{data}");
    assert!(data.contains("An aisle seat, please."), "{data}");
}
