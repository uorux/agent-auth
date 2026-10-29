//! Verifying an OpenID provider's ID token against the provider's JWKS
//! (the admin panel's sign-in, surfaces spec §B.5): RS256 or ES256 only,
//! the key chosen by `kid` (the first key when the token names none), and
//! PyJWT's claim rules (`exp, iat, sub, aud, iss` required; `aud` must hold
//! the client id; `iss` one of the accepted spellings; 5 s leeway).
//!
//! The key's type must fit the token's algorithm (an RSA key for RS256, a
//! P-256 key for ES256), and a key that names its own `alg` must name the
//! token's, so no key is ever used with an algorithm it was not made for.
//! RSA keys need at least 2048 bits (ring's rule).

use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde_json::{Map, Value};

use crate::encoding::b64url_decode;
use crate::jwt::{MAX_TOKEN_BYTES, validate_claims};

/// The algorithms an ID token may use.
pub const ALGORITHMS: [&str; 2] = ["RS256", "ES256"];

/// Why an ID token was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdTokenError {
    /// No published key fits the token's `kid`: fetch the JWKS again (the
    /// provider may have rotated its keys) and retry once.
    #[error("the ID token is signed with a key the provider does not publish")]
    UnknownKey,
    /// Anything else: malformed, wrong algorithm, bad signature, or a claim
    /// that does not check out. The text (PyJWT's where it has one) is for
    /// the log, not for the person signing in.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(msg: &str) -> IdTokenError {
    IdTokenError::Invalid(msg.to_owned())
}

fn b64_json_object(part: &str) -> Option<Map<String, Value>> {
    let bytes = b64url_decode(part)?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn key_field(key: &Map<String, Value>, name: &str) -> Result<Vec<u8>, IdTokenError> {
    key.get(name)
        .and_then(Value::as_str)
        .and_then(b64url_decode)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| IdTokenError::Invalid(format!("the key's {name:?} is missing or malformed")))
}

/// Verifies `token` with the key `jwks` publishes for it, for `audience`
/// (the client id), issued by one of `issuers`, at `now_unix`. Returns the
/// claims. The nonce is the caller's to check.
pub fn verify_id_token(
    token: &str,
    jwks: &Value,
    audience: &str,
    issuers: &[&str],
    now_unix: f64,
) -> Result<Map<String, Value>, IdTokenError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(invalid("Token too long"));
    }
    let mut parts = token.split('.');
    let (Some(h64), Some(p64), Some(s64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("Not enough segments"));
    };
    let header = b64_json_object(h64).ok_or_else(|| invalid("Invalid header string"))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .filter(|a| ALGORITHMS.contains(a))
        .ok_or_else(|| invalid("The specified alg value is not allowed"))?;
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.as_str()),
        Some(_) => return Err(invalid("Key ID header parameter must be a string")),
    };

    let keys = jwks.get("keys").and_then(Value::as_array);
    let key = keys
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .find(|k| kid.is_none() || k.get("kid").and_then(Value::as_str) == kid)
        .ok_or(IdTokenError::UnknownKey)?;
    if let Some(key_alg) = key.get("alg")
        && key_alg.as_str() != Some(alg)
    {
        return Err(invalid("The key is not for this token's algorithm"));
    }

    let sig = b64url_decode(s64).ok_or_else(|| invalid("Invalid crypto padding"))?;
    let signing_input = token
        .get(..h64.len().saturating_add(1).saturating_add(p64.len()))
        .ok_or_else(|| invalid("Not enough segments"))?;
    let kty = key.get("kty").and_then(Value::as_str);
    let verified = match (alg, kty) {
        ("RS256", Some("RSA")) => {
            let n = key_field(key, "n")?;
            let e = key_field(key, "e")?;
            RsaPublicKeyComponents { n: &n, e: &e }.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                signing_input.as_bytes(),
                &sig,
            )
        }
        ("ES256", Some("EC")) => {
            if key.get("crv").and_then(Value::as_str) != Some("P-256") {
                return Err(invalid("The key is not a P-256 key"));
            }
            let x = key_field(key, "x")?;
            let y = key_field(key, "y")?;
            if x.len() != 32 || y.len() != 32 {
                return Err(invalid("The key is not a P-256 key"));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point)
                .verify(signing_input.as_bytes(), &sig)
        }
        _ => return Err(invalid("The key's type does not fit the token's algorithm")),
    };
    verified.map_err(|_| invalid("Signature verification failed"))?;

    let claims = b64_json_object(p64)
        .ok_or_else(|| invalid("Invalid payload string: must be a json object"))?;
    validate_claims(&claims, audience, issuers, now_unix)
        .map_err(|e| IdTokenError::Invalid(e.0))?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    use serde_json::json;

    use super::*;
    use crate::encoding::b64url_encode;

    struct Key {
        pair: EcdsaKeyPair,
        kid: &'static str,
    }

    impl Key {
        fn new(kid: &'static str) -> Key {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Key { pair, kid }
        }
        fn jwk(&self) -> Value {
            let point = self.pair.public_key().as_ref();
            json!({"kty": "EC", "crv": "P-256", "kid": self.kid, "alg": "ES256",
                   "x": b64url_encode(&point[1..33]), "y": b64url_encode(&point[33..65])})
        }
        fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                b64url_encode(header.to_string().as_bytes()),
                b64url_encode(claims.to_string().as_bytes())
            );
            let sig = self
                .pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .unwrap();
            format!("{input}.{}", b64url_encode(sig.as_ref()))
        }
        fn token(&self, claims: &Value) -> String {
            self.sign(&json!({"alg": "ES256", "kid": self.kid}), claims)
        }
    }

    fn claims() -> Value {
        json!({"iss": "https://id.test", "aud": "client", "sub": "s", "iat": 1000, "exp": 1300,
               "nonce": "n"})
    }

    fn check(token: &str, jwks: &Value) -> Result<Map<String, Value>, IdTokenError> {
        verify_id_token(
            token,
            jwks,
            "client",
            &["https://id.test", "https://id.test/"],
            1100.0,
        )
    }

    #[test]
    fn verifies_and_refuses() {
        let k1 = Key::new("k1");
        let jwks = json!({"keys": [k1.jwk()]});
        let ok = check(&k1.token(&claims()), &jwks).unwrap();
        assert_eq!(ok["nonce"], "n");

        // Another key under the same kid: the signature fails.
        let forger = Key::new("k1");
        assert_eq!(
            check(&forger.token(&claims()), &jwks).unwrap_err(),
            invalid("Signature verification failed")
        );
        // A kid nobody publishes.
        assert_eq!(
            check(&Key::new("k2").token(&claims()), &jwks).unwrap_err(),
            IdTokenError::UnknownKey
        );
        // No kid: the first key.
        let no_kid = k1.sign(&json!({"alg": "ES256"}), &claims());
        assert!(check(&no_kid, &jwks).is_ok());

        let mut c = claims();
        c["aud"] = json!("other");
        assert_eq!(
            check(&k1.token(&c), &jwks).unwrap_err(),
            invalid("Audience doesn't match")
        );
        let mut c = claims();
        c["iss"] = json!("https://evil.test");
        assert_eq!(
            check(&k1.token(&c), &jwks).unwrap_err(),
            invalid("Invalid issuer")
        );
        let mut c = claims();
        c["iss"] = json!("https://id.test/");
        assert!(check(&k1.token(&c), &jwks).is_ok());
        let mut c = claims();
        c["exp"] = json!(1050);
        assert_eq!(
            check(&k1.token(&c), &jwks).unwrap_err(),
            invalid("Signature has expired")
        );
        let mut c = claims();
        c.as_object_mut().unwrap().remove("iat");
        assert!(check(&k1.token(&c), &jwks).is_err());
    }

    #[test]
    fn algorithms_and_key_types() {
        let k1 = Key::new("k1");
        let jwks = json!({"keys": [k1.jwk()]});
        for alg in ["none", "HS256", "RS512", "EdDSA"] {
            let t = k1.sign(&json!({"alg": alg, "kid": "k1"}), &claims());
            assert_eq!(
                check(&t, &jwks).unwrap_err(),
                invalid("The specified alg value is not allowed"),
                "{alg}"
            );
        }
        // An RS256 header over an EC key: refused before any verification.
        let t = k1.sign(&json!({"alg": "RS256", "kid": "k1"}), &claims());
        assert!(matches!(check(&t, &jwks), Err(IdTokenError::Invalid(_))));
        // A key that names another algorithm.
        let mut jwk = k1.jwk();
        jwk["alg"] = json!("RS256");
        assert!(matches!(
            check(&k1.token(&claims()), &json!({"keys": [jwk]})),
            Err(IdTokenError::Invalid(_))
        ));
        assert_eq!(
            check("a.b", &jwks).unwrap_err(),
            invalid("Not enough segments")
        );
        assert_eq!(
            check(&k1.token(&claims()), &json!({})).unwrap_err(),
            IdTokenError::UnknownKey
        );
    }
}
