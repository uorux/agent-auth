//! Test doubles (feature `testing`): a throwaway CA and server certificate,
//! and small IMAP and SMTP servers over TLS speaking just enough of the
//! protocols for the client here. Never built into a release binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A CA and a server certificate for `localhost` and `127.0.0.1`.
pub struct TestCa {
    pub ca_pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

impl std::fmt::Debug for TestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestCa")
    }
}

impl TestCa {
    #[must_use]
    pub fn new() -> TestCa {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "agent-auth test CA");
        let ca = rcgen::CertifiedIssuer::self_signed(params, ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .unwrap()
                .signed_by(&leaf_key, &ca)
                .unwrap();
        TestCa {
            ca_pem: ca.pem(),
            chain: vec![leaf.der().clone()],
            key: leaf_key.serialize_der(),
        }
    }

    /// The broker's client config trusting this CA (and the usual roots).
    #[must_use]
    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        let roots = agent_auth_tls_roots(self.ca_pem.as_bytes());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                self.chain.clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
            )
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

fn agent_auth_tls_roots(pem: &[u8]) -> rustls::RootCertStore {
    use rustls::pki_types::pem::PemObject;
    let mut store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        store.add(cert.unwrap()).unwrap();
    }
    store
}

// ------------------------------------------------------------------ IMAP

/// One message in a fake folder.
#[derive(Debug, Clone)]
pub struct Stored {
    pub uid: u32,
    pub raw: Vec<u8>,
}

/// The fake IMAP server's state.
#[derive(Debug, Default)]
pub struct ImapState {
    pub user: String,
    pub password: String,
    pub uidvalidity: u32,
    pub folders: BTreeMap<String, Vec<Stored>>,
    /// Every command line received (passwords included: tests only).
    pub commands: Vec<String>,
}

/// A fake IMAP server over implicit TLS on 127.0.0.1.
#[derive(Debug, Clone)]
pub struct FakeImap {
    pub port: u16,
    pub state: Arc<Mutex<ImapState>>,
}

impl FakeImap {
    pub async fn start(ca: &TestCa, user: &str, password: &str) -> FakeImap {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(ImapState {
            user: user.to_owned(),
            password: password.to_owned(),
            uidvalidity: 7,
            ..ImapState::default()
        }));
        let acceptor = ca.acceptor();
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let st = Arc::clone(&st);
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = imap_session(tls, st).await;
                    }
                });
            }
        });
        FakeImap { port, state }
    }

    pub fn add(&self, folder: &str, raw: &[u8]) -> u32 {
        let mut st = self.state.lock().unwrap();
        let list = st.folders.entry(folder.to_owned()).or_default();
        let uid = u32::try_from(list.len()).unwrap() + 1;
        list.push(Stored {
            uid,
            raw: raw.to_vec(),
        });
        uid
    }
}

/// A command's words, honouring quoted strings and one literal.
async fn read_command<R: AsyncRead + AsyncWrite + Unpin>(
    r: &mut BufReader<R>,
) -> Option<(String, Vec<String>)> {
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut words: Vec<String> = Vec::new();
    loop {
        let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
        // A trailing literal: answer `+`, read it.
        let literal = trimmed
            .rsplit_once('{')
            .and_then(|(head, n)| n.strip_suffix('}').map(|n| (head.to_owned(), n)))
            .and_then(|(head, n)| n.parse::<usize>().ok().map(|n| (head, n)));
        match literal {
            Some((head, n)) => {
                words.extend(split_words(&head));
                r.get_mut().write_all(b"+ go\r\n").await.ok()?;
                let mut buf = vec![0u8; n];
                r.read_exact(&mut buf).await.ok()?;
                words.push(String::from_utf8_lossy(&buf).into_owned());
                line.clear();
                r.read_line(&mut line).await.ok()?;
            }
            None => {
                words.extend(split_words(&trimmed));
                break;
            }
        }
    }
    let tag = words.first()?.clone();
    Some((tag, words.into_iter().skip(1).collect()))
}

fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = s.chars();
    let mut had = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' if quoted => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '"' => {
                quoted = !quoted;
                had = true;
            }
            ' ' if !quoted => {
                if !cur.is_empty() || had {
                    out.push(std::mem::take(&mut cur));
                }
                had = false;
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() || had {
        out.push(cur);
    }
    out
}

async fn imap_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    st: Arc<Mutex<ImapState>>,
) -> Option<()> {
    let mut r = BufReader::new(stream);
    r.get_mut()
        .write_all(b"* OK [CAPABILITY IMAP4rev1] fake ready\r\n")
        .await
        .ok()?;
    let mut logged_in = false;
    let mut selected: Option<String> = None;
    while let Some((tag, words)) = read_command(&mut r).await {
        st.lock()
            .unwrap()
            .commands
            .push(format!("{tag} {}", words.join(" ")));
        let verb = words
            .first()
            .map(|w| w.to_ascii_uppercase())
            .unwrap_or_default();
        let mut out = Vec::new();
        match verb.as_str() {
            "LOGIN" => {
                let s = st.lock().unwrap();
                if words.get(1) == Some(&s.user) && words.get(2) == Some(&s.password) {
                    logged_in = true;
                    out.extend_from_slice(format!("{tag} OK logged in\r\n").as_bytes());
                } else {
                    out.extend_from_slice(
                        format!("{tag} NO [AUTHENTICATIONFAILED] nope\r\n").as_bytes(),
                    );
                }
            }
            "EXAMINE" | "SELECT" if logged_in => {
                let s = st.lock().unwrap();
                let folder = words.get(1).cloned().unwrap_or_default();
                match s.folders.get(&folder) {
                    Some(list) => {
                        selected = Some(folder);
                        out.extend_from_slice(
                            format!(
                                "* {} EXISTS\r\n* OK [UIDVALIDITY {}] UIDs valid\r\n{tag} OK [READ-ONLY] done\r\n",
                                list.len(),
                                s.uidvalidity
                            )
                            .as_bytes(),
                        );
                    }
                    None => {
                        out.extend_from_slice(format!("{tag} NO no such folder\r\n").as_bytes())
                    }
                }
            }
            "UID" if logged_in && selected.is_some() => {
                let s = st.lock().unwrap();
                let list = s
                    .folders
                    .get(selected.as_deref().unwrap_or(""))
                    .cloned()
                    .unwrap_or_default();
                let sub = words
                    .get(1)
                    .map(|w| w.to_ascii_uppercase())
                    .unwrap_or_default();
                if sub == "SEARCH" {
                    // The criteria are recorded, not applied: the gateway
                    // never trusts a server's search.
                    let uids: Vec<String> = list.iter().map(|m| m.uid.to_string()).collect();
                    out.extend_from_slice(
                        format!("* SEARCH {}\r\n{tag} OK done\r\n", uids.join(" ")).as_bytes(),
                    );
                } else if sub == "FETCH" {
                    let uid: u32 = words.get(2).and_then(|u| u.parse().ok()).unwrap_or(0);
                    if let Some(m) = list.iter().find(|m| m.uid == uid) {
                        out.extend_from_slice(
                            format!("* 1 FETCH (UID {uid} BODY[] {{{}}}\r\n", m.raw.len())
                                .as_bytes(),
                        );
                        out.extend_from_slice(&m.raw);
                        out.extend_from_slice(b")\r\n");
                    }
                    out.extend_from_slice(format!("{tag} OK done\r\n").as_bytes());
                } else {
                    out.extend_from_slice(format!("{tag} BAD what\r\n").as_bytes());
                }
            }
            "LOGOUT" => {
                out.extend_from_slice(format!("* BYE bye\r\n{tag} OK done\r\n").as_bytes());
                r.get_mut().write_all(&out).await.ok()?;
                return Some(());
            }
            _ => out.extend_from_slice(format!("{tag} BAD not now\r\n").as_bytes()),
        }
        r.get_mut().write_all(&out).await.ok()?;
    }
    Some(())
}

// ------------------------------------------------------------------ SMTP

/// What the fake SMTP server received.
#[derive(Debug, Clone, Default)]
pub struct Received {
    pub sender: String,
    pub recipients: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SmtpState {
    pub user: String,
    pub password: String,
    /// Recipients answered 550.
    pub refuse: Vec<String>,
    pub received: Vec<Received>,
    /// Whether AUTH came after TLS was up (always, if the client is right).
    pub auth_over_tls: Vec<bool>,
    /// Offer STARTTLS (only matters in STARTTLS mode).
    pub offer_starttls: bool,
}

/// A fake submission server on 127.0.0.1: implicit TLS, or plaintext that
/// must be upgraded with STARTTLS.
#[derive(Debug, Clone)]
pub struct FakeSmtp {
    pub port: u16,
    pub state: Arc<Mutex<SmtpState>>,
}

impl FakeSmtp {
    pub async fn start(ca: &TestCa, implicit: bool, user: &str, password: &str) -> FakeSmtp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(SmtpState {
            user: user.to_owned(),
            password: password.to_owned(),
            offer_starttls: true,
            ..SmtpState::default()
        }));
        let acceptor = ca.acceptor();
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let st = Arc::clone(&st);
                tokio::spawn(async move {
                    if implicit {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            let _ = smtp_session(BufReader::new(tls), &st, true).await;
                        }
                    } else {
                        let mut plain = BufReader::new(tcp);
                        if let Some(true) = smtp_plain(&mut plain, &st).await
                            && let Ok(tls) = acceptor.accept(plain.into_inner()).await
                        {
                            let _ = smtp_session(BufReader::new(tls), &st, false).await;
                        }
                    }
                });
            }
        });
        FakeSmtp { port, state }
    }
}

/// The plaintext part of a STARTTLS session: true when the client asked
/// to upgrade.
async fn smtp_plain<S: AsyncRead + AsyncWrite + Unpin>(
    r: &mut BufReader<S>,
    st: &Arc<Mutex<SmtpState>>,
) -> Option<bool> {
    r.get_mut().write_all(b"220 fake ESMTP\r\n").await.ok()?;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await.ok()? == 0 {
            return Some(false);
        }
        let upper = line.trim_end().to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            let offer = st.lock().unwrap().offer_starttls;
            let caps = if offer {
                "250-fake\r\n250-AUTH PLAIN\r\n250 STARTTLS\r\n"
            } else {
                "250-fake\r\n250 AUTH PLAIN\r\n"
            };
            r.get_mut().write_all(caps.as_bytes()).await.ok()?;
        } else if upper == "STARTTLS" {
            r.get_mut().write_all(b"220 go ahead\r\n").await.ok()?;
            return Some(true);
        } else if upper.starts_with("AUTH") {
            st.lock().unwrap().auth_over_tls.push(false);
            r.get_mut().write_all(b"530 TLS first\r\n").await.ok()?;
        } else {
            r.get_mut().write_all(b"530 TLS first\r\n").await.ok()?;
        }
    }
}

async fn smtp_session<S: AsyncRead + AsyncWrite + Unpin>(
    mut r: BufReader<S>,
    st: &Arc<Mutex<SmtpState>>,
    greet: bool,
) -> Option<()> {
    use base64::Engine as _;
    if greet {
        r.get_mut().write_all(b"220 fake ESMTP\r\n").await.ok()?;
    }
    let mut current = Received::default();
    let mut authed = false;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await.ok()? == 0 {
            return Some(());
        }
        let cmd = line.trim_end().to_owned();
        let upper = cmd.to_ascii_uppercase();
        let reply: String = if upper.starts_with("EHLO") {
            "250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n".into()
        } else if let Some(token) = cmd.strip_prefix("AUTH PLAIN ") {
            st.lock().unwrap().auth_over_tls.push(true);
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(token)
                .unwrap_or_default();
            let s = st.lock().unwrap();
            let want = format!("\0{}\0{}", s.user, s.password);
            if decoded == want.as_bytes() {
                authed = true;
                "235 ok\r\n".into()
            } else {
                "535 no\r\n".into()
            }
        } else if let Some(from) = upper.strip_prefix("MAIL FROM:") {
            if !authed {
                "530 auth first\r\n".into()
            } else {
                current = Received {
                    sender: cmd[10..].trim_matches(['<', '>']).to_owned(),
                    ..Received::default()
                };
                let _ = from;
                "250 ok\r\n".into()
            }
        } else if upper.starts_with("RCPT TO:") {
            let rcpt = cmd[8..].trim_matches(['<', '>']).to_owned();
            if st.lock().unwrap().refuse.contains(&rcpt) {
                "550 no such user\r\n".into()
            } else {
                current.recipients.push(rcpt);
                "250 ok\r\n".into()
            }
        } else if upper == "DATA" {
            r.get_mut().write_all(b"354 go\r\n").await.ok()?;
            let mut data = Vec::new();
            loop {
                let mut l = Vec::new();
                if r.read_until(b'\n', &mut l).await.ok()? == 0 {
                    return Some(());
                }
                if l == b".\r\n" {
                    break;
                }
                let l = if l.starts_with(b"..") {
                    l[1..].to_vec()
                } else {
                    l
                };
                data.extend_from_slice(&l);
            }
            current.data = data;
            st.lock()
                .unwrap()
                .received
                .push(std::mem::take(&mut current));
            "250 queued\r\n".into()
        } else if upper == "RSET" {
            current = Received::default();
            "250 ok\r\n".into()
        } else if upper == "QUIT" {
            r.get_mut().write_all(b"221 bye\r\n").await.ok()?;
            return Some(());
        } else {
            "500 what\r\n".into()
        };
        r.get_mut().write_all(reply.as_bytes()).await.ok()?;
    }
}
