//! Setting an LLDAP password over LDAP (RFC 4511 simple bind, then the
//! RFC 3062 Password Modify extended operation), so the broker never runs
//! `lldap_set_password` with the admin JWT on its command line
//! (provisioners spec B4). LLDAP performs the OPAQUE registration itself
//! for a password set this way.
//!
//! Only what this needs: three request shapes, and reading `LDAPResult`s.
//! The reader is bounded (64 KiB per message) and never panics on what a
//! server sends (property-tested below).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_auth_crypto::Secret;

use super::setup::ConfigError;

const PASSWORD_MODIFY_OID: &[u8] = b"1.3.6.1.4.1.4203.1.11.1";
const MAX_MESSAGE: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const DEADLINE: Duration = Duration::from_secs(30);

/// Why a password was not set. Logged; the agent sees a fixed text.
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    #[error("connecting to {0} failed: {1}")]
    Connect(String, std::io::Error),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed LDAP response")]
    Malformed,
    #[error("{what} refused: result {code} ({diagnostic})")]
    Refused {
        what: &'static str,
        code: u32,
        diagnostic: String,
    },
    #[error("timed out")]
    Timeout,
    #[error("task failed")]
    Task,
}

/// Where and how to reach LLDAP's LDAP interface.
#[derive(Clone)]
pub struct LdapTarget {
    host: String,
    port: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
    base_dn: String,
}

impl std::fmt::Debug for LdapTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapTarget")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls.is_some())
            .field("base_dn", &self.base_dn)
            .finish()
    }
}

impl LdapTarget {
    /// `ldap://host[:3890]` or `ldaps://host[:6360]`, and the base DN
    /// (`dc=example,dc=com`). Plain `ldap://` sends the admin password in
    /// the clear: it is refused unless the host is loopback or
    /// `allow_plaintext` (`LLDAP_LDAP_ALLOW_PLAINTEXT=1`) says so.
    pub fn parse(
        url: &str,
        base_dn: &str,
        allow_plaintext: bool,
    ) -> Result<LdapTarget, ConfigError> {
        let bad = || {
            ConfigError(format!(
                "LLDAP_LDAP_URL {url:?}: expected ldap://host[:port] or ldaps://host[:port]"
            ))
        };
        let (tls, rest) = if let Some(r) = url.strip_prefix("ldaps://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("ldap://") {
            (false, r)
        } else {
            return Err(bad());
        };
        let rest = rest.trim_end_matches('/');
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad())?),
            None => (rest, if tls { 6360 } else { 3890 }),
        };
        if host.is_empty() || host.contains(['/', '@', '?', '#']) {
            return Err(bad());
        }
        let loopback = host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if !tls && !loopback {
            if !allow_plaintext {
                return Err(ConfigError(format!(
                    "LLDAP_LDAP_URL {url:?} would send the LLDAP admin password in the clear: use ldaps://, or set LLDAP_LDAP_ALLOW_PLAINTEXT=1"
                )));
            }
            tracing::warn!(
                url,
                "LLDAP_LDAP_ALLOW_PLAINTEXT: the LLDAP admin password goes over plain LDAP"
            );
        }
        if base_dn.trim().is_empty() {
            return Err(ConfigError(
                "LLDAP_BASE_DN is required with LLDAP_LDAP_URL".to_owned(),
            ));
        }
        let tls = if tls {
            let cfg = agent_auth_tls::default_client_config()
                .map_err(|e| ConfigError(format!("TLS client configuration: {e}")))?;
            Some(Arc::new(cfg))
        } else {
            None
        };
        Ok(LdapTarget {
            host: host.to_owned(),
            port,
            tls,
            base_dn: base_dn.trim().to_owned(),
        })
    }

    fn user_dn(&self, user: &str) -> String {
        format!("uid={},ou=people,{}", escape_dn_value(user), self.base_dn)
    }

    /// Bind as the admin and set `user`'s password.
    pub async fn set_password(
        &self,
        admin_user: &str,
        admin_password: &Secret<String>,
        user: &str,
        new_password: &Secret<String>,
    ) -> Result<(), LdapError> {
        let target = self.clone();
        let admin_dn = self.user_dn(admin_user);
        let user_dn = self.user_dn(user);
        let admin_password = admin_password.clone();
        let new_password = new_password.clone();
        tokio::task::spawn_blocking(move || {
            target.set_password_blocking(&admin_dn, &admin_password, &user_dn, &new_password)
        })
        .await
        .map_err(|_| LdapError::Task)?
    }

    fn connect(&self) -> Result<Box<dyn Stream>, LdapError> {
        let label = format!("{}:{}", self.host, self.port);
        let addrs = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| LdapError::Connect(label.clone(), e))?;
        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no address");
        let mut tcp = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let tcp = tcp.ok_or(LdapError::Connect(label, last))?;
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        match &self.tls {
            None => Ok(Box::new(tcp)),
            Some(cfg) => {
                let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                    .map_err(|e| LdapError::Tls(e.to_string()))?;
                let conn = rustls::ClientConnection::new(Arc::clone(cfg), name)
                    .map_err(|e| LdapError::Tls(e.to_string()))?;
                Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
            }
        }
    }

    fn set_password_blocking(
        &self,
        admin_dn: &str,
        admin_password: &Secret<String>,
        user_dn: &str,
        new_password: &Secret<String>,
    ) -> Result<(), LdapError> {
        let started = Instant::now();
        let mut s = self.connect()?;
        let bind = Secret::new(bind_request(1, admin_dn, admin_password.expose()));
        s.write_all(bind.expose())?;
        s.flush()?;
        expect_success(&read_message(&mut s, started)?, 1, BIND_RESPONSE, "bind")?;
        let modify = Secret::new(password_modify_request(2, user_dn, new_password.expose()));
        s.write_all(modify.expose())?;
        s.flush()?;
        expect_success(
            &read_message(&mut s, started)?,
            2,
            EXTENDED_RESPONSE,
            "password modify",
        )?;
        // Best effort: the server closes the session either way.
        let _ = s.write_all(&unbind_request(3));
        let _ = s.flush();
        Ok(())
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// RFC 4514 escaping of an attribute value.
fn escape_dn_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let last = v.chars().count().saturating_sub(1);
    for (i, c) in v.chars().enumerate() {
        match c {
            '\\' | ',' | '+' | '"' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '#' | ' ' if i == 0 => {
                out.push('\\');
                out.push(c);
            }
            ' ' if i == last => out.push_str("\\ "),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

// ------------------------------------------------------------------ BER

const BIND_REQUEST: u8 = 0x60;
const BIND_RESPONSE: u8 = 0x61;
const UNBIND_REQUEST: u8 = 0x42;
const EXTENDED_REQUEST: u8 = 0x77;
const EXTENDED_RESPONSE: u8 = 0x78;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = Vec::with_capacity(len.saturating_add(6));
    out.push(tag);
    let bytes = u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes();
    if len < 0x80 {
        out.extend_from_slice(bytes.get(3..).unwrap_or_default());
    } else {
        let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
        let used = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(used.len()).unwrap_or(4));
        out.extend_from_slice(used);
    }
    out.extend_from_slice(content);
    out
}

fn integer(n: u8) -> Vec<u8> {
    // Message ids and the version here are small positive numbers.
    tlv(0x02, &[n & 0x7f])
}

fn message(id: u8, op: &[u8]) -> Vec<u8> {
    let mut content = integer(id);
    content.extend_from_slice(op);
    tlv(0x30, &content)
}

fn bind_request(id: u8, dn: &str, password: &str) -> Vec<u8> {
    let mut body = integer(3);
    body.extend(tlv(0x04, dn.as_bytes()));
    body.extend(tlv(0x80, password.as_bytes()));
    message(id, &tlv(BIND_REQUEST, &body))
}

fn password_modify_request(id: u8, user_dn: &str, new_password: &str) -> Vec<u8> {
    let mut value = tlv(0x80, user_dn.as_bytes());
    value.extend(tlv(0x82, new_password.as_bytes()));
    let mut body = tlv(0x80, PASSWORD_MODIFY_OID);
    body.extend(tlv(0x81, &tlv(0x30, &value)));
    message(id, &tlv(EXTENDED_REQUEST, &body))
}

fn unbind_request(id: u8) -> Vec<u8> {
    message(id, &tlv(UNBIND_REQUEST, &[]))
}

/// One TLV off the front of `buf`: (tag, value, rest).
fn take_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (digits, rest) = (rest.get(..n)?, rest.get(n..)?);
        let len = digits
            .iter()
            .fold(0usize, |acc, d| (acc << 8) | usize::from(*d));
        (len, rest)
    };
    Some((tag, rest.get(..len)?, rest.get(len..)?))
}

/// An `LDAPResult` the server sent: (message id, operation tag, result
/// code, diagnostic message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    pub id: u32,
    pub op: u8,
    pub code: u32,
    pub diagnostic: String,
}

fn small_uint(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    Some(bytes.iter().fold(0u32, |acc, d| (acc << 8) | u32::from(*d)))
}

/// Parse one complete `LDAPMessage` carrying a result.
pub fn parse_result(msg: &[u8]) -> Option<LdapResult> {
    let (tag, body, _) = take_tlv(msg)?;
    if tag != 0x30 {
        return None;
    }
    let (itag, id, rest) = take_tlv(body)?;
    if itag != 0x02 {
        return None;
    }
    let (op, result, _) = take_tlv(rest)?;
    let (ctag, code, rest) = take_tlv(result)?;
    if ctag != 0x0a {
        return None;
    }
    let diagnostic = take_tlv(rest)
        .and_then(|(_, _, rest)| take_tlv(rest))
        .filter(|(t, _, _)| *t == 0x04)
        .map(|(_, d, _)| String::from_utf8_lossy(d).chars().take(300).collect())
        .unwrap_or_default();
    Some(LdapResult {
        id: small_uint(id)?,
        op,
        code: small_uint(code)?,
        diagnostic,
    })
}

/// Read one whole message (tag, length, content), at most [`MAX_MESSAGE`].
fn read_message(r: &mut dyn Read, started: Instant) -> Result<Vec<u8>, LdapError> {
    if started.elapsed() > DEADLINE {
        return Err(LdapError::Timeout);
    }
    let mut head = [0u8; 2];
    r.read_exact(&mut head)?;
    let mut msg = head.to_vec();
    let [_, first] = head;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(LdapError::Malformed);
        }
        let mut digits = vec![0u8; n];
        r.read_exact(&mut digits)?;
        msg.extend_from_slice(&digits);
        digits
            .iter()
            .fold(0usize, |acc, d| (acc << 8) | usize::from(*d))
    };
    if len > MAX_MESSAGE {
        return Err(LdapError::Malformed);
    }
    let mut content = vec![0u8; len];
    r.read_exact(&mut content)?;
    msg.extend_from_slice(&content);
    Ok(msg)
}

fn expect_success(msg: &[u8], id: u32, op: u8, what: &'static str) -> Result<(), LdapError> {
    let r = parse_result(msg).ok_or(LdapError::Malformed)?;
    if r.id != id || r.op != op {
        // e.g. a Notice of Disconnection (id 0).
        return Err(LdapError::Refused {
            what,
            code: r.code,
            diagnostic: r.diagnostic,
        });
    }
    if r.code != 0 {
        return Err(LdapError::Refused {
            what,
            code: r.code,
            diagnostic: r.diagnostic,
        });
    }
    Ok(())
}

/// Decoding the requests this module sends, for fake servers in tests.
#[doc(hidden)]
pub mod decode {
    use super::take_tlv;

    /// A request as a fake server sees it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Request {
        Bind {
            id: u8,
            dn: String,
            password: String,
        },
        PasswordModify {
            id: u8,
            user: String,
            new_password: String,
        },
        Unbind {
            id: u8,
        },
        Other,
    }

    pub fn request(msg: &[u8]) -> Option<Request> {
        let (_, body, _) = take_tlv(msg)?;
        let (_, id, rest) = take_tlv(body)?;
        let id = *id.first()?;
        let (op, content, _) = take_tlv(rest)?;
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        Some(match op {
            0x60 => {
                let (_, _, rest) = take_tlv(content)?;
                let (_, dn, rest) = take_tlv(rest)?;
                let (_, pw, _) = take_tlv(rest)?;
                Request::Bind {
                    id,
                    dn: s(dn),
                    password: s(pw),
                }
            }
            0x77 => {
                let (_, _oid, rest) = take_tlv(content)?;
                let (_, value, _) = take_tlv(rest)?;
                let (_, seq, _) = take_tlv(value)?;
                let (_, user, rest) = take_tlv(seq)?;
                let (_, pw, _) = take_tlv(rest)?;
                Request::PasswordModify {
                    id,
                    user: s(user),
                    new_password: s(pw),
                }
            }
            0x42 => Request::Unbind { id },
            _ => Request::Other,
        })
    }

    /// A result message (`op` 0x61 bind, 0x78 extended).
    #[must_use]
    pub fn result(id: u8, op: u8, code: u8, diagnostic: &str) -> Vec<u8> {
        let mut body = super::tlv(0x0a, &[code]);
        body.extend(super::tlv(0x04, b""));
        body.extend(super::tlv(0x04, diagnostic.as_bytes()));
        super::message(id, &super::tlv(op, &body))
    }

    /// Read one message from a blocking reader.
    pub fn read(r: &mut dyn std::io::Read) -> Option<Vec<u8>> {
        super::read_message(r, std::time::Instant::now()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn requests_round_trip() {
        let b = bind_request(1, "uid=admin,ou=people,dc=x", "pw");
        assert_eq!(
            decode::request(&b),
            Some(decode::Request::Bind {
                id: 1,
                dn: "uid=admin,ou=people,dc=x".into(),
                password: "pw".into()
            })
        );
        let long = "p".repeat(300);
        let m = password_modify_request(2, "uid=svc-a,ou=people,dc=x", &long);
        assert_eq!(
            decode::request(&m),
            Some(decode::Request::PasswordModify {
                id: 2,
                user: "uid=svc-a,ou=people,dc=x".into(),
                new_password: long
            })
        );
        assert_eq!(
            decode::request(&unbind_request(3)),
            Some(decode::Request::Unbind { id: 3 })
        );
    }

    #[test]
    fn results_parse() {
        let r = parse_result(&decode::result(2, EXTENDED_RESPONSE, 50, "insufficient")).unwrap();
        assert_eq!(
            r,
            LdapResult {
                id: 2,
                op: EXTENDED_RESPONSE,
                code: 50,
                diagnostic: "insufficient".into()
            }
        );
        assert!(
            expect_success(
                &decode::result(1, BIND_RESPONSE, 0, ""),
                1,
                BIND_RESPONSE,
                "bind"
            )
            .is_ok()
        );
        assert!(
            expect_success(
                &decode::result(0, EXTENDED_RESPONSE, 0, ""),
                1,
                BIND_RESPONSE,
                "bind"
            )
            .is_err()
        );
    }

    #[test]
    fn dn_escaping() {
        assert_eq!(escape_dn_value("svc-a"), "svc-a");
        assert_eq!(escape_dn_value("a,b=c"), "a\\,b\\=c");
        assert_eq!(escape_dn_value(" #x "), "\\ #x\\ ");
    }

    #[test]
    fn urls() {
        assert!(LdapTarget::parse("ldap://lldap.auth:3890", "dc=x", false).is_err());
        assert!(LdapTarget::parse("ldap://127.0.0.1:3890", "dc=x", false).is_ok());
        assert!(LdapTarget::parse("ldap://localhost", "dc=x", false).is_ok());
        let t = LdapTarget::parse("ldap://lldap.auth:3890", "dc=x", true).unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.tls.is_some()),
            ("lldap.auth", 3890, false)
        );
        let t = LdapTarget::parse("ldaps://lldap", "dc=x", false).unwrap();
        assert_eq!((t.port, t.tls.is_some()), (6360, true));
        assert!(LdapTarget::parse("http://lldap", "dc=x", true).is_err());
        assert!(LdapTarget::parse("ldap://lldap", "", true).is_err());
    }

    proptest! {
        #[test]
        fn parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_result(&bytes);
            let _ = decode::request(&bytes);
            let _ = read_message(&mut bytes.as_slice(), Instant::now());
        }
    }
}
