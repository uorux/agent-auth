//! The hello that authenticates each channel connection.
//!
//! ```text
//! broker → {"type":"challenge","nonce": bn}
//! daemon → {"type":"hello","role","name","nonce": dn,"params": P_d,"sig": S_d}
//! broker → {"type":"welcome","params": P_b,"sig": S_b}
//! ```
//!
//! `S = base64url(ed25519(transcript("agent-auth/v1/hello", speaker, role,
//! name, bn, dn, params)))` where the speaker is `daemon` or `broker` (so a
//! welcome can't be reflected as a hello) and `params` is the exact JSON
//! string sent. The session id is `SHA-256(transcript("agent-auth/v1/session",
//! role, name, bn, dn))`; every envelope on the connection is signed over it.
//!
//! Typestate: a [`Handshake`] holds the identity and both nonces; verifying
//! the peer's signature turns it into a [`VerifiedHello`], and only that
//! makes the connection's [`EnvelopeSealer`] and [`EnvelopeVerifier`].
//!
//! Broker: `Handshake::new(id, bn, dn).verify(&stored_key, Speaker::Daemon,
//! P_d, S_d)?`, then `sign_reply(&broker_key, P_b)` and `into_channel`.
//! Daemon: `handshake.sign(&own_key, Speaker::Daemon, P_d)`, send, then
//! `verify(&pinned_broker_key, Speaker::Broker, P_b, S_b)?` and
//! `into_channel`.

use std::fmt;

use ring::digest;

use crate::encoding::{b64url_decode, b64url_encode};
use crate::rng::{RandomError, array};

use super::envelope::{EnvelopeSealer, EnvelopeVerifier};
use super::keys::{PublicKey, SigningKey};
use super::{BROKER, CTX_HELLO, CTX_SESSION, DaemonId, MAX_FIELD_BYTES, transcript};

/// Who signs a hello transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speaker {
    Daemon,
    Broker,
}

impl Speaker {
    pub fn as_str(self) -> &'static str {
        match self {
            Speaker::Daemon => "daemon",
            Speaker::Broker => BROKER,
        }
    }

    fn other(self) -> Self {
        match self {
            Speaker::Daemon => Speaker::Broker,
            Speaker::Broker => Speaker::Daemon,
        }
    }
}

/// A handshake nonce: 32 bytes in URL-safe base64 (43 characters). Peers'
/// nonces are parsed strictly; the Python accepted any string but only ever
/// sent this shape.
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce(String);

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", self.0)
    }
}

impl Nonce {
    /// A fresh random nonce.
    pub fn generate() -> Result<Self, RandomError> {
        Ok(Self(b64url_encode(&array::<32>()?)))
    }

    /// A nonce received from the peer.
    pub fn parse(text: &str) -> Option<Self> {
        let raw = b64url_decode(text)?;
        (raw.len() == 32 && !text.ends_with('=')).then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The connection's session id: 32 bytes every envelope is signed over.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId([u8; 32]);

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", hex::encode(self.0))
    }
}

impl SessionId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_tests(raw: [u8; 32]) -> Self {
        Self(raw)
    }
}

/// A hello signature did not verify (or could not be made).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HelloError {
    #[error("bad hello signature")]
    BadSignature,
    #[error("hello params too long")]
    ParamsTooLong,
}

/// One connection's identity and nonces, before the peer is verified.
#[derive(Debug, Clone)]
pub struct Handshake {
    id: DaemonId,
    broker_nonce: Nonce,
    daemon_nonce: Nonce,
}

impl Handshake {
    pub fn new(id: DaemonId, broker_nonce: Nonce, daemon_nonce: Nonce) -> Self {
        Self {
            id,
            broker_nonce,
            daemon_nonce,
        }
    }

    pub fn id(&self) -> &DaemonId {
        &self.id
    }

    /// The bytes a hello signature covers.
    pub fn transcript(&self, speaker: Speaker, params: &str) -> Vec<u8> {
        transcript(&[
            CTX_HELLO,
            speaker.as_str().as_bytes(),
            self.id.role.as_str().as_bytes(),
            self.id.name.as_str().as_bytes(),
            self.broker_nonce.as_str().as_bytes(),
            self.daemon_nonce.as_str().as_bytes(),
            params.as_bytes(),
        ])
    }

    /// The connection's session id.
    pub fn session_id(&self) -> SessionId {
        let t = transcript(&[
            CTX_SESSION,
            self.id.role.as_str().as_bytes(),
            self.id.name.as_str().as_bytes(),
            self.broker_nonce.as_str().as_bytes(),
            self.daemon_nonce.as_str().as_bytes(),
        ]);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest::digest(&digest::SHA256, &t).as_ref());
        SessionId(out)
    }

    /// Signs our side of the hello (the daemon's hello, or the broker's
    /// welcome via [`VerifiedHello::sign_reply`]).
    pub fn sign(
        &self,
        key: &SigningKey,
        speaker: Speaker,
        params: &str,
    ) -> Result<String, HelloError> {
        if params.len() > MAX_FIELD_BYTES {
            return Err(HelloError::ParamsTooLong);
        }
        Ok(b64url_encode(&key.sign(&self.transcript(speaker, params))))
    }

    /// Verifies the peer's signature under the key we trust for it (the
    /// stored daemon key, or the pinned broker key).
    pub fn verify(
        self,
        peer: &PublicKey,
        speaker: Speaker,
        params: &str,
        signature: &str,
    ) -> Result<VerifiedHello, HelloError> {
        if params.len() > MAX_FIELD_BYTES {
            return Err(HelloError::ParamsTooLong);
        }
        let sig = b64url_decode(signature).ok_or(HelloError::BadSignature)?;
        if !peer.verify(&self.transcript(speaker, params), &sig) {
            return Err(HelloError::BadSignature);
        }
        Ok(VerifiedHello {
            handshake: self,
            peer: *peer,
            peer_speaker: speaker,
        })
    }
}

/// A handshake whose peer proved possession of its key.
#[derive(Debug, Clone)]
pub struct VerifiedHello {
    handshake: Handshake,
    peer: PublicKey,
    peer_speaker: Speaker,
}

impl VerifiedHello {
    pub fn id(&self) -> &DaemonId {
        &self.handshake.id
    }

    /// The key the peer authenticated with.
    pub fn peer_key(&self) -> &PublicKey {
        &self.peer
    }

    pub fn session_id(&self) -> SessionId {
        self.handshake.session_id()
    }

    /// Signs our reply as the other speaker (the broker's welcome).
    pub fn sign_reply(&self, own_key: &SigningKey, params: &str) -> Result<String, HelloError> {
        self.handshake
            .sign(own_key, self.peer_speaker.other(), params)
    }

    /// The connection's sealer (our messages) and verifier (the peer's).
    pub fn into_channel(self, own_key: &SigningKey) -> (EnvelopeSealer, EnvelopeVerifier) {
        let session = self.handshake.session_id();
        let daemon = self.handshake.id.principal();
        let (ours, theirs) = match self.peer_speaker {
            Speaker::Daemon => (BROKER.to_owned(), daemon),
            Speaker::Broker => (daemon, BROKER.to_owned()),
        };
        (
            EnvelopeSealer::new(own_key.clone(), ours.clone(), theirs.clone(), session),
            EnvelopeVerifier::new(self.peer, theirs, ours, session),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{DaemonName, Role};
    use crate::testvec::{s, vectors};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn matches_python() {
        let v = &vectors()["hello"];
        let daemon = SigningKey::from_text(s(&v["daemon_private"])).unwrap();
        let broker = SigningKey::from_text(s(&v["broker_private"])).unwrap();
        let id = DaemonId::new(
            Role::parse(s(&v["role"])).unwrap(),
            DaemonName::parse(s(&v["name"])).unwrap(),
        );
        let hs = Handshake::new(
            id,
            Nonce::parse(s(&v["broker_nonce"])).unwrap(),
            Nonce::parse(s(&v["daemon_nonce"])).unwrap(),
        );
        assert_eq!(hex::encode(hs.session_id().as_bytes()), s(&v["session_id"]));
        assert_eq!(
            hex::encode(hs.transcript(Speaker::Daemon, s(&v["daemon_params"]))),
            s(&v["daemon_transcript"])
        );
        // Ed25519 is deterministic: the same signature as the Python's.
        let sd = hs
            .sign(&daemon, Speaker::Daemon, s(&v["daemon_params"]))
            .unwrap();
        assert_eq!(sd, s(&v["daemon_sig"]));
        let verified = hs
            .clone()
            .verify(
                &daemon.public_key(),
                Speaker::Daemon,
                s(&v["daemon_params"]),
                &sd,
            )
            .unwrap();
        let sb = verified
            .sign_reply(&broker, s(&v["broker_params"]))
            .unwrap();
        assert_eq!(sb, s(&v["broker_sig"]));
        assert!(
            hs.clone()
                .verify(
                    &broker.public_key(),
                    Speaker::Broker,
                    s(&v["broker_params"]),
                    &sb
                )
                .is_ok()
        );
    }

    /// The transcript alone (no ring): runs under Miri.
    #[test]
    fn transcript_matches_python() {
        let v = &vectors()["hello"];
        let id = DaemonId::new(
            Role::parse(s(&v["role"])).unwrap(),
            DaemonName::parse(s(&v["name"])).unwrap(),
        );
        let hs = Handshake::new(
            id,
            Nonce::parse(s(&v["broker_nonce"])).unwrap(),
            Nonce::parse(s(&v["daemon_nonce"])).unwrap(),
        );
        assert_eq!(
            hex::encode(hs.transcript(Speaker::Daemon, s(&v["daemon_params"]))),
            s(&v["daemon_transcript"])
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn binds_speaker_nonces_and_params() {
        let daemon = SigningKey::generate().unwrap();
        let id = DaemonId::new(Role::Host, DaemonName::parse("h").unwrap());
        let bn = Nonce::generate().unwrap();
        let dn = Nonce::generate().unwrap();
        let hs = Handshake::new(id.clone(), bn.clone(), dn.clone());
        let sig = hs.sign(&daemon, Speaker::Daemon, "{}").unwrap();
        let pk = daemon.public_key();
        assert!(hs.clone().verify(&pk, Speaker::Daemon, "{}", &sig).is_ok());
        // Reflected as the other speaker, other params, other nonce, other key.
        assert!(hs.clone().verify(&pk, Speaker::Broker, "{}", &sig).is_err());
        assert!(
            hs.clone()
                .verify(&pk, Speaker::Daemon, "{ }", &sig)
                .is_err()
        );
        let other = Handshake::new(id, Nonce::generate().unwrap(), dn);
        assert!(other.verify(&pk, Speaker::Daemon, "{}", &sig).is_err());
        let stranger = SigningKey::generate().unwrap().public_key();
        assert!(
            hs.clone()
                .verify(&stranger, Speaker::Daemon, "{}", &sig)
                .is_err()
        );
        assert!(hs.verify(&pk, Speaker::Daemon, "{}", "!!").is_err());
    }

    #[test]
    fn nonce_parsing() {
        let good = b64url_encode(&[9u8; 32]);
        assert!(Nonce::parse(&good).is_some());
        assert!(Nonce::parse(&format!("{good}=")).is_none());
        assert!(Nonce::parse(&b64url_encode(&[9u8; 31])).is_none());
        assert!(Nonce::parse("").is_none());
    }
}
