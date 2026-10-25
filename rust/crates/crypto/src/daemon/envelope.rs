//! Signed envelopes: every message on a channel after the hello.
//!
//! Wire form (one text frame): `{"p": base64url(P), "s": base64url(sig)}`
//! where `P` is the UTF-8 JSON body and
//! `sig = ed25519(transcript("agent-auth/v1/msg", session id, P))`. The body
//! is the payload plus `id` (uuid4 hex), `iss` (sender principal), `aud`
//! (recipient principal), `seq` (per-direction counter from 1), `iat` and
//! `exp` (Unix seconds, floats). The receiver verifies over the bytes of
//! `P` as received and never re-serializes them.
//!
//! [`EnvelopeVerifier::open`] checks, in this order (the Python's): outer
//! shape, signature, body shape, `iss`/`aud`, `seq` strictly increasing,
//! `iat ≤ now + 30`, `exp ≥ now`, `exp − iat ≤ 3600`; only then does it
//! advance its sequence number.

use serde_json::{Map, Number, Value};

use crate::encoding::{b64url_decode, b64url_encode};
use crate::rng::{RandomError, uuid4_hex};

use super::hello::SessionId;
use super::keys::{PublicKey, SigningKey};
use super::{CTX_MSG, MAX_CLOCK_SKEW_SECS, MAX_ENVELOPE_TTL_SECS, MAX_FIELD_BYTES, transcript};

/// The keys the envelope sets; a payload may not use them.
pub const RESERVED_KEYS: [&str; 6] = ["id", "iss", "aud", "seq", "iat", "exp"];

/// An envelope failed verification. Never act on its contents. The
/// messages are the Python's.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("malformed envelope")]
    Malformed,
    #[error("bad signature")]
    BadSignature,
    #[error("malformed envelope body")]
    MalformedBody,
    #[error("envelope from {iss} to {aud} is not for this channel")]
    WrongChannel { iss: String, aud: String },
    #[error("replayed or reordered envelope")]
    Replayed,
    #[error("envelope issued in the future")]
    FromTheFuture,
    #[error("envelope expired")]
    Expired,
    #[error("envelope lifetime too long")]
    LifetimeTooLong,
}

/// A message could not be sealed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SealError {
    /// The Python silently overwrote these; refusing is safer.
    #[error("payload key {0:?} is reserved for the envelope")]
    ReservedKey(String),
    #[error("envelope ttl must be in (0, 3600] seconds")]
    BadTtl,
    #[error("envelope time is not a finite number")]
    BadTime,
    #[error("envelope body too large")]
    TooLarge,
    #[error("sequence number exhausted")]
    SeqExhausted,
    #[error(transparent)]
    Random(#[from] RandomError),
}

/// Seals one direction of one connection, numbering messages from 1.
/// Callers sending concurrently must seal and send under one lock, so the
/// peer sees sequence numbers in the order they were assigned.
#[derive(Debug)]
pub struct EnvelopeSealer {
    key: SigningKey,
    sender: String,
    audience: String,
    session: SessionId,
    seq: u64,
}

impl EnvelopeSealer {
    pub(crate) fn new(
        key: SigningKey,
        sender: String,
        audience: String,
        session: SessionId,
    ) -> Self {
        Self {
            key,
            sender,
            audience,
            session,
            seq: 0,
        }
    }

    /// The next envelope for `payload`, valid from `now` for `ttl_secs`.
    pub fn seal(
        &mut self,
        payload: &Map<String, Value>,
        ttl_secs: f64,
        now: f64,
    ) -> Result<String, SealError> {
        let seq = self.seq.checked_add(1).ok_or(SealError::SeqExhausted)?;
        let id = uuid4_hex()?;
        let text = seal_with(
            &self.key,
            payload,
            &Fields {
                id: &id,
                sender: &self.sender,
                audience: &self.audience,
                session: &self.session,
                seq,
                ttl_secs,
                now,
            },
        )?;
        self.seq = seq;
        Ok(text)
    }

    /// [`EnvelopeSealer::seal`] at the current time.
    pub fn seal_now(
        &mut self,
        payload: &Map<String, Value>,
        ttl_secs: f64,
    ) -> Result<String, SealError> {
        self.seal(payload, ttl_secs, super::unix_now())
    }

    /// The sequence number of the last envelope sealed (0 before the first).
    pub fn last_seq(&self) -> u64 {
        self.seq
    }
}

pub(crate) struct Fields<'a> {
    pub id: &'a str,
    pub sender: &'a str,
    pub audience: &'a str,
    pub session: &'a SessionId,
    pub seq: u64,
    pub ttl_secs: f64,
    pub now: f64,
}

/// Seals with every field given (deterministic; for the sealer and tests).
pub(crate) fn seal_with(
    key: &SigningKey,
    payload: &Map<String, Value>,
    f: &Fields<'_>,
) -> Result<String, SealError> {
    if let Some(k) = RESERVED_KEYS.iter().find(|k| payload.contains_key(**k)) {
        return Err(SealError::ReservedKey((*k).to_owned()));
    }
    if !(f.ttl_secs > 0.0 && f.ttl_secs <= MAX_ENVELOPE_TTL_SECS) {
        return Err(SealError::BadTtl);
    }
    let iat = Number::from_f64(f.now).ok_or(SealError::BadTime)?;
    let exp = Number::from_f64(f.now + f.ttl_secs).ok_or(SealError::BadTime)?;
    let mut body = payload.clone();
    body.insert("id".into(), Value::String(f.id.to_owned()));
    body.insert("iss".into(), Value::String(f.sender.to_owned()));
    body.insert("aud".into(), Value::String(f.audience.to_owned()));
    body.insert("seq".into(), Value::Number(f.seq.into()));
    body.insert("iat".into(), Value::Number(iat));
    body.insert("exp".into(), Value::Number(exp));
    let p = serde_json::to_vec(&Value::Object(body)).map_err(|_| SealError::TooLarge)?;
    if p.len() > MAX_FIELD_BYTES {
        return Err(SealError::TooLarge);
    }
    let sig = key.sign(&transcript(&[CTX_MSG, f.session.as_bytes(), &p]));
    let outer = serde_json::json!({"p": b64url_encode(&p), "s": b64url_encode(&sig)});
    Ok(outer.to_string())
}

/// Verifies one peer's envelopes on one connection. Sequence numbers must
/// strictly increase, so a captured message can't be replayed or reordered.
#[derive(Debug)]
pub struct EnvelopeVerifier {
    peer: PublicKey,
    sender: String,
    audience: String,
    session: SessionId,
    last_seq: u64,
}

impl EnvelopeVerifier {
    pub(crate) fn new(
        peer: PublicKey,
        sender: String,
        audience: String,
        session: SessionId,
    ) -> Self {
        Self {
            peer,
            sender,
            audience,
            session,
            last_seq: 0,
        }
    }

    /// Verifies `raw` (one frame) at `now` and returns the body (payload
    /// and the six envelope keys).
    pub fn open(&mut self, raw: &[u8], now: f64) -> Result<Map<String, Value>, EnvelopeError> {
        if raw.len() > MAX_FIELD_BYTES.saturating_mul(2) {
            return Err(EnvelopeError::Malformed);
        }
        let outer: Value = serde_json::from_slice(raw).map_err(|_| EnvelopeError::Malformed)?;
        let field = |k: &str| {
            outer
                .get(k)
                .and_then(Value::as_str)
                .and_then(b64url_decode)
                .ok_or(EnvelopeError::Malformed)
        };
        let p = field("p")?;
        let s = field("s")?;
        if p.len() > MAX_FIELD_BYTES
            || !self
                .peer
                .verify(&transcript(&[CTX_MSG, self.session.as_bytes(), &p]), &s)
        {
            return Err(EnvelopeError::BadSignature);
        }
        let body: Map<String, Value> =
            serde_json::from_slice(&p).map_err(|_| EnvelopeError::MalformedBody)?;
        let (iss, aud, seq, iat, exp) = parse_fields(&body).ok_or(EnvelopeError::MalformedBody)?;
        if iss != Some(self.sender.as_str()) || aud != Some(self.audience.as_str()) {
            return Err(EnvelopeError::WrongChannel {
                iss: show(body.get("iss")),
                aud: show(body.get("aud")),
            });
        }
        if seq <= self.last_seq {
            return Err(EnvelopeError::Replayed);
        }
        if iat > now + MAX_CLOCK_SKEW_SECS {
            return Err(EnvelopeError::FromTheFuture);
        }
        if exp < now {
            return Err(EnvelopeError::Expired);
        }
        if exp - iat > MAX_ENVELOPE_TTL_SECS {
            return Err(EnvelopeError::LifetimeTooLong);
        }
        self.last_seq = seq;
        Ok(body)
    }

    /// [`EnvelopeVerifier::open`] at the current time.
    pub fn open_now(&mut self, raw: &[u8]) -> Result<Map<String, Value>, EnvelopeError> {
        self.open(raw, super::unix_now())
    }

    /// The last accepted sequence number (0 before the first).
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }
}

type BodyFields<'a> = (Option<&'a str>, Option<&'a str>, u64, f64, f64);

/// `id` a string; `iss`, `aud` present (any type; checked next); `seq` an
/// integer (a negative one counts as 0, which is always a replay); `iat`,
/// `exp` finite numbers.
fn parse_fields(body: &Map<String, Value>) -> Option<BodyFields<'_>> {
    body.get("id")?.as_str()?;
    let iss = body.get("iss")?.as_str();
    let aud = body.get("aud")?.as_str();
    let seq = match body.get("seq")? {
        Value::Number(n) if n.is_u64() => n.as_u64()?,
        Value::Number(n) if n.is_i64() => 0,
        _ => return None,
    };
    let num = |k: &str| body.get(k)?.as_f64().filter(|f| f.is_finite());
    Some((iss, aud, seq, num("iat")?, num("exp")?))
}

fn show(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => format!("{s:?}"),
        Some(other) => other.to_string(),
        None => "null".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::hello::{Handshake, Nonce, Speaker};
    use crate::daemon::{BROKER, DaemonId, DaemonName, Role};
    use crate::testvec::{s, vectors};
    use proptest::prelude::*;
    use serde_json::json;

    fn id() -> DaemonId {
        DaemonId::new(Role::Host, DaemonName::parse("excelsior").unwrap())
    }

    /// A broker/daemon pair of channels over one verified hello.
    fn channel() -> (
        (EnvelopeSealer, EnvelopeVerifier),
        (EnvelopeSealer, EnvelopeVerifier),
    ) {
        let broker = SigningKey::from_seed(&[1; 32]).unwrap();
        let daemon = SigningKey::from_seed(&[2; 32]).unwrap();
        let hs = Handshake::new(id(), Nonce::generate().unwrap(), Nonce::generate().unwrap());
        let sd = hs.sign(&daemon, Speaker::Daemon, "{}").unwrap();
        let at_broker = hs
            .clone()
            .verify(&daemon.public_key(), Speaker::Daemon, "{}", &sd)
            .unwrap();
        let sb = at_broker.sign_reply(&broker, "{}").unwrap();
        let at_daemon = hs
            .verify(&broker.public_key(), Speaker::Broker, "{}", &sb)
            .unwrap();
        (
            at_broker.into_channel(&broker),
            at_daemon.into_channel(&daemon),
        )
    }

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    const NOW: f64 = 1_761_400_000.5;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn roundtrip_both_directions() {
        let ((mut b_seal, mut b_open), (mut d_seal, mut d_open)) = channel();
        let m = b_seal
            .seal(&obj(json!({"type": "job.start", "x": [1]})), 60.0, NOW)
            .unwrap();
        let body = d_open.open(m.as_bytes(), NOW).unwrap();
        assert_eq!(body["type"], "job.start");
        assert_eq!(body["iss"], BROKER);
        assert_eq!(body["aud"], "host:excelsior");
        assert_eq!(body["seq"], 1);
        let r = d_seal
            .seal(&obj(json!({"type": "reply"})), 60.0, NOW)
            .unwrap();
        let body = b_open.open(r.as_bytes(), NOW).unwrap();
        assert_eq!(body["iss"], "host:excelsior");
        assert_eq!(body["aud"], BROKER);
        // A broker envelope is not a daemon one (wrong iss/aud).
        assert!(matches!(
            b_open.open(m.as_bytes(), NOW),
            Err(EnvelopeError::BadSignature | EnvelopeError::WrongChannel { .. })
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sequence_replay_and_time() {
        let ((mut seal, _), (_, mut open)) = channel();
        let p = obj(json!({"type": "t"}));
        let m1 = seal.seal(&p, 60.0, NOW).unwrap();
        let m2 = seal.seal(&p, 60.0, NOW).unwrap();
        let m3 = seal.seal(&p, 60.0, NOW).unwrap();
        assert_eq!(seal.last_seq(), 3);
        assert!(open.open(m2.as_bytes(), NOW).is_ok());
        assert_eq!(open.open(m1.as_bytes(), NOW), Err(EnvelopeError::Replayed));
        assert_eq!(open.open(m2.as_bytes(), NOW), Err(EnvelopeError::Replayed));
        // Expired: rejected, and the sequence number is not consumed.
        assert_eq!(
            open.open(m3.as_bytes(), NOW + 61.0),
            Err(EnvelopeError::Expired)
        );
        assert_eq!(open.last_seq(), 2);
        assert_eq!(
            open.open(m3.as_bytes(), NOW - 31.0),
            Err(EnvelopeError::FromTheFuture)
        );
        assert!(open.open(m3.as_bytes(), NOW - 29.0).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn seal_refusals() {
        let ((mut seal, _), _) = channel();
        assert_eq!(
            seal.seal(&obj(json!({"seq": 9})), 60.0, NOW),
            Err(SealError::ReservedKey("seq".into()))
        );
        assert_eq!(seal.seal(&Map::new(), 3600.5, NOW), Err(SealError::BadTtl));
        assert_eq!(seal.seal(&Map::new(), 0.0, NOW), Err(SealError::BadTtl));
        assert_eq!(
            seal.seal(&Map::new(), f64::NAN, NOW),
            Err(SealError::BadTtl)
        );
        assert_eq!(
            seal.seal(&Map::new(), 1.0, f64::INFINITY),
            Err(SealError::BadTime)
        );
        assert_eq!(seal.last_seq(), 0);
        assert!(seal.seal(&Map::new(), 3600.0, NOW).is_ok());
    }

    /// Envelopes with hand-made bodies, signed correctly, to test the body
    /// checks behind the signature.
    fn forge(key: &SigningKey, session: &SessionId, p: &[u8]) -> String {
        let sig = key.sign(&transcript(&[CTX_MSG, session.as_bytes(), p]));
        json!({"p": b64url_encode(p), "s": b64url_encode(&sig)}).to_string()
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn body_checks() {
        let key = SigningKey::from_seed(&[3; 32]).unwrap();
        let session = SessionId::for_tests([7; 32]);
        let mut open =
            EnvelopeVerifier::new(key.public_key(), "broker".into(), "host:h".into(), session);
        let base = r#""id":"x","iss":"broker","aud":"host:h""#;
        for (p, want) in [
            (
                format!(r#"{{{base},"seq":1,"iat":NaN,"exp":2}}"#),
                EnvelopeError::MalformedBody,
            ),
            (
                format!(r#"{{{base},"seq":true,"iat":1,"exp":2}}"#),
                EnvelopeError::MalformedBody,
            ),
            (
                format!(r#"{{{base},"seq":1.0,"iat":1,"exp":2}}"#),
                EnvelopeError::MalformedBody,
            ),
            (
                format!(r#"{{{base},"seq":1,"iat":"1","exp":2}}"#),
                EnvelopeError::MalformedBody,
            ),
            (
                format!(r#"{{{base},"seq":1,"iat":1,"exp":1e999}}"#),
                EnvelopeError::MalformedBody,
            ),
            (
                format!(r#"{{{base},"seq":1,"iat":1}}"#),
                EnvelopeError::MalformedBody,
            ),
            (
                r#"{"id":1,"iss":"broker","aud":"host:h","seq":1,"iat":1,"exp":2}"#.into(),
                EnvelopeError::MalformedBody,
            ),
            ("[1]".into(), EnvelopeError::MalformedBody),
            (
                format!(r#"{{{base},"seq":-5,"iat":1,"exp":2}}"#),
                EnvelopeError::Replayed,
            ),
            (
                format!(r#"{{{base},"seq":0,"iat":1,"exp":2}}"#),
                EnvelopeError::Replayed,
            ),
            (
                format!(r#"{{{base},"seq":1,"iat":1,"exp":3602}}"#),
                EnvelopeError::LifetimeTooLong,
            ),
        ] {
            assert_eq!(
                open.open(forge(&key, &session, p.as_bytes()).as_bytes(), 2.0),
                Err(want),
                "{p}"
            );
        }
        let wrong = r#"{"id":"x","iss":"broker","aud":"host:other","seq":1,"iat":1,"exp":2}"#;
        assert!(matches!(
            open.open(forge(&key, &session, wrong.as_bytes()).as_bytes(), 2.0),
            Err(EnvelopeError::WrongChannel { .. })
        ));
        let ok = format!(r#"{{{base},"seq":1,"iat":1,"exp":2,"type":"x"}}"#);
        assert!(
            open.open(forge(&key, &session, ok.as_bytes()).as_bytes(), 2.0)
                .is_ok()
        );
        // Another session's envelope does not verify.
        let other = SessionId::for_tests([8; 32]);
        let ok2 = format!(r#"{{{base},"seq":2,"iat":1,"exp":2}}"#);
        assert_eq!(
            open.open(forge(&key, &other, ok2.as_bytes()).as_bytes(), 2.0),
            Err(EnvelopeError::BadSignature)
        );
        for raw in ["", "[]", "{}", r#"{"p":1,"s":"x"}"#, r#"{"p":"!","s":""}"#] {
            assert_eq!(
                open.open(raw.as_bytes(), 2.0),
                Err(EnvelopeError::Malformed),
                "{raw}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn python_sealed_opens_in_rust() {
        let v = &vectors()["envelope"];
        let key = SigningKey::from_text(s(&v["private"])).unwrap();
        let session =
            SessionId::for_tests(hex::decode(s(&v["session"])).unwrap().try_into().unwrap());
        let mut open = EnvelopeVerifier::new(
            key.public_key(),
            s(&v["sender"]).into(),
            s(&v["audience"]).into(),
            session,
        );
        let now = v["now"].as_f64().unwrap();
        let body = open.open(s(&v["python_sealed"]).as_bytes(), now).unwrap();
        assert_eq!(Value::Object(body), v["python_body"]);
    }

    /// The bytes the Python verifier was run on (see generate.py): Rust's
    /// sealing of these inputs must not change.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn rust_sealed_is_what_python_verified() {
        let v = &vectors()["envelope"];
        assert_eq!(
            rust_sealed(),
            include_str!("../../tests/vectors/rust_sealed.txt").trim()
        );
        assert_eq!(v["python_opened_rust_sealed"], Value::Bool(true));
    }

    fn rust_sealed() -> String {
        let v = &vectors()["envelope"];
        let key = SigningKey::from_text(s(&v["private"])).unwrap();
        let session =
            SessionId::for_tests(hex::decode(s(&v["session"])).unwrap().try_into().unwrap());
        seal_with(
            &key,
            &obj(v["payload"].clone()),
            &Fields {
                id: s(&v["id"]),
                sender: s(&v["sender"]),
                audience: s(&v["audience"]),
                session: &session,
                seq: 7,
                ttl_secs: 60.0,
                now: v["now"].as_f64().unwrap(),
            },
        )
        .unwrap()
    }

    /// Writes tests/vectors/rust_sealed.txt for generate.py to check.
    #[test]
    #[ignore = "regenerates a test vector"]
    fn write_rust_artifacts() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/rust_sealed.txt");
        std::fs::write(path, rust_sealed() + "\n").unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Flipping any bit of an envelope's text makes it fail.
        #[test]
        #[cfg_attr(miri, ignore)]
        fn tampering_fails(idx in any::<usize>(), bit in 0u8..8, text in "[a-z]{0,20}") {
            let ((mut seal, _), (_, mut open)) = channel();
            let m = seal.seal(&obj(json!({"type": "t", "text": text})), 60.0, NOW).unwrap();
            let mut raw = m.into_bytes();
            let i = idx.checked_rem(raw.len()).unwrap();
            raw[i] ^= 1 << bit;
            prop_assert!(open.open(&raw, NOW).is_err());
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn wrong_parameters_fail(which in 0u8..5) {
            let broker = SigningKey::from_seed(&[1; 32]).unwrap();
            let session = SessionId::for_tests([5; 32]);
            let mut sealer = EnvelopeSealer::new(broker.clone(), "broker".into(), "host:a".into(), session);
            let m = sealer.seal(&Map::new(), 60.0, NOW).unwrap();
            let (key, iss, aud, sess, now) = match which {
                0 => (SigningKey::from_seed(&[9; 32]).unwrap().public_key(), "broker", "host:a", session, NOW),
                1 => (broker.public_key(), "host:a", "host:a", session, NOW),
                2 => (broker.public_key(), "broker", "host:b", session, NOW),
                3 => (broker.public_key(), "broker", "host:a", SessionId::for_tests([6; 32]), NOW),
                _ => (broker.public_key(), "broker", "host:a", session, NOW + 61.0),
            };
            let mut v = EnvelopeVerifier::new(key, iss.into(), aud.into(), sess);
            prop_assert!(v.open(m.as_bytes(), now).is_err());
            let mut good = EnvelopeVerifier::new(broker.public_key(), "broker".into(), "host:a".into(), session);
            prop_assert!(good.open(m.as_bytes(), NOW).is_ok());
        }
    }
}
