//! Envelope verification on untrusted frames. Odd first byte: the rest is
//! a raw frame. Even: the rest is a body `P`, correctly signed by the peer,
//! so the checks behind the signature get exercised too.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_crypto::b64url_encode;
use agent_auth_crypto::daemon::{
    DaemonId, DaemonName, EnvelopeError, Handshake, Nonce, Role, SigningKey, Speaker, transcript,
};
use libfuzzer_sys::fuzz_target;
use ring::signature::Ed25519KeyPair;

const NOW: f64 = 1_761_400_000.0;

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let (Ok(broker), Ok(daemon)) = (
        SigningKey::from_seed(&[1; 32]),
        SigningKey::from_seed(&[2; 32]),
    ) else {
        return;
    };
    let (Some(bn), Some(dn), Some(name)) = (
        Nonce::parse(&b64url_encode(&[3; 32])),
        Nonce::parse(&b64url_encode(&[4; 32])),
        DaemonName::parse("h"),
    ) else {
        return;
    };
    let hs = Handshake::new(DaemonId::new(Role::Host, name), bn, dn);
    let session = hs.session_id();
    let Ok(sig) = hs.sign(&daemon, Speaker::Daemon, "{}") else {
        return;
    };
    let Ok(verified) = hs.verify(&daemon.public_key(), Speaker::Daemon, "{}", &sig) else {
        return;
    };
    let (_, mut verifier) = verified.into_channel(&broker);
    let frame = if mode & 1 == 1 {
        rest.to_vec()
    } else {
        let Ok(pair) = Ed25519KeyPair::from_seed_unchecked(&[2; 32]) else {
            return;
        };
        let sig = pair.sign(&transcript(&[
            b"agent-auth/v1/msg",
            session.as_bytes(),
            rest,
        ]));
        serde_json::json!({"p": b64url_encode(rest), "s": b64url_encode(sig.as_ref())})
            .to_string()
            .into_bytes()
    };
    if let Ok(body) = verifier.open(&frame, NOW) {
        // Whatever was accepted names this channel and is in date...
        assert_eq!(body.get("iss").and_then(|v| v.as_str()), Some("host:h"));
        assert_eq!(body.get("aud").and_then(|v| v.as_str()), Some("broker"));
        assert!(verifier.last_seq() >= 1);
        // ...and is never accepted twice.
        assert_eq!(verifier.open(&frame, NOW), Err(EnvelopeError::Replayed));
    }
});
