//! JWTs the broker signs.
//!
//! - [`TokenIssuer`]: short-lived ES256 tokens an MCP server's proxy
//!   validates from `/.well-known/jwks.json` (Python `core/tokens.py`).
//!   ES256 because the validators accept RSA and ECDSA, not EdDSA. The P-256
//!   key is derived from the broker's Ed25519 signing key, exactly as the
//!   Python derived it, so the published key (and `kid`) survive the switch:
//!   `okm = HKDF-SHA256(ikm = seed, salt = none, info = "agent-auth token
//!   signing key v1 (ES256)", 48 bytes)`, `d = int(okm) mod (n − 1) + 1`.
//! - [`GitHubAppKey`]: the RS256 JWT a GitHub App authenticates with
//!   (`iat` = now − 60, `exp` = now + 540, `iss` = the app id).

use std::fmt;

use agent_auth_core::canonical_json::to_canonical_string;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair as _, RsaKeyPair};
use ring::{digest, hkdf};
use serde_json::{Map, Value, json};
use zeroize::Zeroize;

use crate::daemon::SigningKey;
use crate::encoding::{b64url_decode, b64url_encode};
use crate::pem::{self, PemError};
use crate::rng::{RandomError, uuid4_string};
use crate::secret::Secret;

/// The algorithm of the broker's tokens.
pub const ALGORITHM: &str = "ES256";
const LABEL: &[u8] = b"agent-auth token signing key v1 (ES256)";
/// Clock leeway when verifying, seconds.
pub const LEEWAY_SECS: f64 = 5.0;
/// The longest token [`TokenIssuer::verify`] looks at.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// A key could not be set up, or a token could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    #[error("could not derive the token signing key")]
    Derive,
    #[error("GitHub App private key: {0}")]
    Pem(#[from] PemError),
    #[error("GitHub App private key is not a usable RSA key: {0}")]
    RsaKey(String),
    #[error("signing failed")]
    Sign,
    #[error(transparent)]
    Random(#[from] RandomError),
}

/// A token did not verify. The message is PyJWT's where there is one; it
/// is for logs, not for the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TokenError(pub String);

fn token_err(msg: &str) -> TokenError {
    TokenError(msg.to_owned())
}

/// Issues and verifies the broker's ES256 tokens.
pub struct TokenIssuer {
    pair: EcdsaKeyPair,
    issuer: String,
    kid: String,
    jwk: Map<String, Value>,
}

impl fmt::Debug for TokenIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenIssuer")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// P-256's group order minus one, as little-endian 64-bit limbs.
const N_MINUS_1: [u64; 4] = [
    0xF3B9_CAC2_FC63_2550,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// `int_be(okm) mod (n − 1) + 1`, as 32 big-endian bytes. Constant time:
/// a shift-and-subtract over every bit, selecting with masks.
fn p256_scalar_from_okm(okm: &[u8; 48]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for byte in okm {
        for bit in (0..8u32).rev() {
            let b = u64::from((byte >> bit) & 1);
            let carry = r[3] >> 63;
            r = [
                (r[0] << 1) | b,
                (r[1] << 1) | (r[0] >> 63),
                (r[2] << 1) | (r[1] >> 63),
                (r[3] << 1) | (r[2] >> 63),
            ];
            let (t, borrow) = sub_256(&r, &N_MINUS_1);
            let mask = 0u64.wrapping_sub(carry | (borrow ^ 1));
            for (ri, ti) in r.iter_mut().zip(t) {
                *ri = (ti & mask) | (*ri & !mask);
            }
        }
    }
    // + 1: r ≤ n − 2, so no carry leaves the top limb.
    let mut carry = 1u64;
    for limb in &mut r {
        let (sum, c) = limb.overflowing_add(carry);
        *limb = sum;
        carry = u64::from(c);
    }
    let mut out = [0u8; 32];
    let (chunks, _) = out.as_chunks_mut::<8>();
    for (chunk, limb) in chunks.iter_mut().zip(r.iter().rev()) {
        *chunk = limb.to_be_bytes();
    }
    r.zeroize();
    out
}

/// `a − b` mod 2²⁵⁶ and the final borrow (1 if `a < b`).
fn sub_256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        let (d1, b1) = x.overflowing_sub(*y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *o = d2;
        borrow = u64::from(b1 | b2);
    }
    (out, borrow)
}

struct Len48;

impl hkdf::KeyType for Len48 {
    fn len(&self) -> usize {
        48
    }
}

/// The P-256 key pair for scalar `d` (big-endian, in [1, n − 1]).
///
/// ring has no "private scalar → key pair" constructor (its PKCS#8 parser
/// requires the public key, which only ring itself can compute here), so
/// the scalar is fed to ring's own key generation as its "random" input:
/// generation takes the first candidate in range, which `d` is. This uses
/// ring's `FixedSliceRandom` (a deprecated test helper; see DEVIATIONS.md).
#[allow(deprecated)]
fn p256_key_pair(d: &[u8; 32]) -> Result<EcdsaKeyPair, JwtError> {
    let fixed = ring::test::rand::FixedSliceRandom { bytes: d };
    let doc = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &fixed)
        .map_err(|_| JwtError::Derive)?;
    EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        doc.as_ref(),
        &SystemRandom::new(),
    )
    .map_err(|_| JwtError::Derive)
}

impl TokenIssuer {
    /// The issuer for `issuer` (a URL; a trailing `/` is dropped), with the
    /// key derived from the broker's signing key.
    pub fn new(broker_key: &SigningKey, issuer: &str) -> Result<Self, JwtError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(broker_key.seed());
        let mut okm = [0u8; 48];
        prk.expand(&[LABEL], Len48)
            .and_then(|o| o.fill(&mut okm))
            .map_err(|_| JwtError::Derive)?;
        let mut d = p256_scalar_from_okm(&okm);
        okm.zeroize();
        let pair = p256_key_pair(&d);
        d.zeroize();
        let pair = pair?;
        let public = pair.public_key().as_ref();
        let (x, y) = match public {
            [0x04, rest @ ..] if rest.len() == 64 => rest.split_at(32),
            _ => return Err(JwtError::Derive),
        };
        let mut jwk = Map::new();
        jwk.insert("crv".into(), json!("P-256"));
        jwk.insert("kty".into(), json!("EC"));
        jwk.insert("x".into(), json!(b64url_encode(x)));
        jwk.insert("y".into(), json!(b64url_encode(y)));
        // RFC 7638 thumbprint: the members above, sorted, no whitespace.
        let thumb_input =
            to_canonical_string(&Value::Object(jwk.clone())).map_err(|_| JwtError::Derive)?;
        let kid = b64url_encode(digest::digest(&digest::SHA256, thumb_input.as_bytes()).as_ref());
        jwk.insert("kid".into(), json!(kid));
        jwk.insert("use".into(), json!("sig"));
        jwk.insert("alg".into(), json!(ALGORITHM));
        Ok(Self {
            pair,
            issuer: issuer.trim_end_matches('/').to_owned(),
            kid,
            jwk,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The published key: `crv, kty, x, y, kid, use, alg`.
    pub fn jwk(&self) -> Value {
        Value::Object(self.jwk.clone())
    }

    /// `{"keys": [jwk]}`.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.jwk()] })
    }

    /// Enough of an OIDC discovery document for a validator to find the keys.
    pub fn discovery(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "jwks_uri": format!("{}/.well-known/jwks.json", self.issuer),
            "id_token_signing_alg_values_supported": [ALGORITHM],
            "subject_types_supported": ["public"],
            "response_types_supported": ["token"],
        })
    }

    /// A token for `subject` and `audience` with extra `claims`, valid for
    /// `max(1, ttl_secs)` from `now_unix`. Returns the token and its expiry
    /// (Unix seconds). `iss, sub, aud, iat, nbf (now − 5), exp, jti`
    /// override same-named `claims`.
    pub fn mint(
        &self,
        subject: &str,
        audience: &str,
        ttl_secs: i64,
        claims: &Map<String, Value>,
        now_unix: i64,
    ) -> Result<(Secret<String>, i64), JwtError> {
        let expires = now_unix.saturating_add(ttl_secs.max(1));
        let mut payload = claims.clone();
        payload.insert("iss".into(), json!(self.issuer));
        payload.insert("sub".into(), json!(subject));
        payload.insert("aud".into(), json!(audience));
        payload.insert("iat".into(), json!(now_unix));
        payload.insert("nbf".into(), json!(now_unix.saturating_sub(5)));
        payload.insert("exp".into(), json!(expires));
        payload.insert("jti".into(), json!(uuid4_string()?));
        let header = json!({"alg": ALGORITHM, "kid": self.kid, "typ": "JWT"});
        let signing_input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(Value::Object(payload).to_string().as_bytes())
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| JwtError::Sign)?;
        Ok((
            Secret::new(format!("{signing_input}.{}", b64url_encode(sig.as_ref()))),
            expires,
        ))
    }

    /// Verifies a token for `audience` at `now_unix` (PyJWT's rules: ES256
    /// only; `exp, iat, sub, aud, iss` required; issuer and audience must
    /// match; 5 s leeway). Returns the claims.
    pub fn verify(
        &self,
        token: &str,
        audience: &str,
        now_unix: f64,
    ) -> Result<Map<String, Value>, TokenError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(token_err("Token too long"));
        }
        let mut parts = token.split('.');
        let (Some(h64), Some(p64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(token_err("Not enough segments"));
        };
        let header: Value = b64url_decode(h64)
            .and_then(|h| serde_json::from_slice(&h).ok())
            .ok_or_else(|| token_err("Invalid header string"))?;
        if header.get("alg").and_then(Value::as_str) != Some(ALGORITHM) {
            return Err(token_err("The specified alg value is not allowed"));
        }
        let sig = b64url_decode(s64).ok_or_else(|| token_err("Invalid crypto padding"))?;
        let signing_input = token
            .get(..h64.len().saturating_add(1).saturating_add(p64.len()))
            .ok_or_else(|| token_err("Not enough segments"))?;
        signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            self.pair.public_key().as_ref(),
        )
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| token_err("Signature verification failed"))?;
        let claims: Map<String, Value> = b64url_decode(p64)
            .and_then(|p| serde_json::from_slice(&p).ok())
            .ok_or_else(|| token_err("Invalid payload string: must be a json object"))?;
        validate_claims(&claims, audience, &self.issuer, now_unix)?;
        Ok(claims)
    }
}

fn validate_claims(
    claims: &Map<String, Value>,
    audience: &str,
    issuer: &str,
    now: f64,
) -> Result<(), TokenError> {
    for claim in ["exp", "iat", "sub", "aud", "iss"] {
        if claims.get(claim).is_none_or(Value::is_null) {
            return Err(TokenError(format!(
                "Token is missing the \"{claim}\" claim"
            )));
        }
    }
    let int = |k: &str, msg: &str| -> Result<Option<f64>, TokenError> {
        match claims.get(k) {
            None => Ok(None),
            Some(v) => v
                .as_f64()
                .filter(|f| f.is_finite())
                .map(f64::trunc)
                .map(Some)
                .ok_or_else(|| token_err(msg)),
        }
    };
    if let Some(iat) = int("iat", "Issued At claim (iat) must be an integer.")?
        && iat > now + LEEWAY_SECS
    {
        return Err(token_err("The token is not yet valid (iat)"));
    }
    if let Some(nbf) = int("nbf", "Not Before claim (nbf) must be an integer.")?
        && nbf > now + LEEWAY_SECS
    {
        return Err(token_err("The token is not yet valid (nbf)"));
    }
    if let Some(exp) = int("exp", "Expiration Time claim (exp) must be an integer.")?
        && exp <= now - LEEWAY_SECS
    {
        return Err(token_err("Signature has expired"));
    }
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(token_err("Invalid issuer"));
    }
    let auds: Vec<&Value> = match claims.get("aud") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(v @ Value::String(_)) => vec![v],
        _ => return Err(token_err("Invalid claim format in token")),
    };
    if auds.iter().any(|a| !a.is_string()) {
        return Err(token_err("Invalid claim format in token"));
    }
    if !auds.iter().any(|a| a.as_str() == Some(audience)) {
        return Err(token_err("Audience doesn't match"));
    }
    if !claims.get("sub").is_some_and(Value::is_string) {
        return Err(token_err("Subject must be a string"));
    }
    if claims.get("jti").is_some_and(|j| !j.is_string()) {
        return Err(token_err("JWT ID must be a string"));
    }
    Ok(())
}

/// A GitHub App's private key, for the app JWT.
pub struct GitHubAppKey {
    pair: RsaKeyPair,
}

impl fmt::Debug for GitHubAppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GitHubAppKey(..)")
    }
}

impl GitHubAppKey {
    /// From the PEM GitHub hands out (`RSA PRIVATE KEY`, PKCS#1) or a
    /// PKCS#8 `PRIVATE KEY`. ring requires at least 2048 bits.
    pub fn from_pem(text: &str) -> Result<Self, JwtError> {
        let block = pem::parse(text)?;
        let der = block.der.expose();
        let pair = match block.label.as_str() {
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(der),
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(der),
            other => return Err(JwtError::RsaKey(format!("unexpected PEM label {other:?}"))),
        }
        .map_err(|e| JwtError::RsaKey(e.to_string()))?;
        Ok(Self { pair })
    }

    /// The app JWT at `now_unix`: `{"iat": now − 60, "exp": now + 540,
    /// "iss": app_id}`, RS256 (byte-identical to PyJWT's output).
    pub fn app_jwt(&self, app_id: &str, now_unix: i64) -> Result<Secret<String>, JwtError> {
        let iss =
            to_canonical_string(&Value::String(app_id.to_owned())).map_err(|_| JwtError::Sign)?;
        let payload = format!(
            r#"{{"iat":{},"exp":{},"iss":{iss}}}"#,
            now_unix.saturating_sub(60),
            now_unix.saturating_add(540)
        );
        let signing_input = format!(
            "{}.{}",
            b64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            b64url_encode(payload.as_bytes())
        );
        let mut sig = vec![0u8; self.pair.public().modulus_len()];
        self.pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut sig,
            )
            .map_err(|_| JwtError::Sign)?;
        Ok(Secret::new(format!(
            "{signing_input}.{}",
            b64url_encode(&sig)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{s, vectors};

    #[test]
    fn scalar_reduction() {
        // 0 → 1; n − 1 → 1 (it is ≡ 0); n − 2 → n − 1; 2³⁸⁴ − 1 checked
        // against Python below.
        let mut okm = [0u8; 48];
        let one = {
            let mut o = [0u8; 32];
            o[31] = 1;
            o
        };
        assert_eq!(p256_scalar_from_okm(&okm), one);
        let n_minus_1 =
            hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550")
                .unwrap();
        okm[16..].copy_from_slice(&n_minus_1);
        assert_eq!(p256_scalar_from_okm(&okm), one);
        okm[47] = 0x4f; // n − 2
        assert_eq!(p256_scalar_from_okm(&okm).to_vec(), n_minus_1);
        let v = &vectors()["es256"];
        let all_ones = [0xffu8; 48];
        assert_eq!(
            hex::encode(p256_scalar_from_okm(&all_ones)),
            s(&v["d_of_all_ones"])
        );
    }

    fn issuer() -> TokenIssuer {
        let v = &vectors()["es256"];
        TokenIssuer::new(
            &SigningKey::from_text(s(&v["broker_private"])).unwrap(),
            s(&v["issuer"]),
        )
        .unwrap()
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn derivation_matches_python() {
        let v = &vectors()["es256"];
        let t = issuer();
        assert_eq!(t.kid(), s(&v["kid"]));
        assert_eq!(t.jwks(), v["jwks"]);
        assert_eq!(t.discovery(), v["discovery"]);
        assert_eq!(t.issuer(), s(&v["issuer"]).trim_end_matches('/'));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn verifies_python_tokens() {
        let v = &vectors()["es256"];
        let t = issuer();
        let now = v["now"].as_f64().unwrap();
        let claims = t
            .verify(s(&v["python_token"]), s(&v["audience"]), now)
            .unwrap();
        assert_eq!(claims["grant"], v["claims"]["grant"]);
        assert_eq!(claims["sub"], "agent-a");
        assert_eq!(
            t.verify(s(&v["python_token"]), "other", now).unwrap_err().0,
            "Audience doesn't match"
        );
        assert_eq!(
            t.verify(s(&v["python_token"]), s(&v["audience"]), now + 4000.0)
                .unwrap_err()
                .0,
            "Signature has expired"
        );
        assert_eq!(
            t.verify(s(&v["python_token"]), s(&v["audience"]), now - 100.0)
                .unwrap_err()
                .0,
            "The token is not yet valid (iat)"
        );
        // Also the token this crate minted once, which the Python verified.
        let rust = include_str!("../tests/vectors/rust_es256_token.txt").trim();
        assert!(t.verify(rust, s(&v["audience"]), now).is_ok());
        assert_eq!(v["python_verified_rust_token"], Value::Bool(true));
    }

    /// Writes tests/vectors/rust_es256_token.txt for generate.py to check.
    #[test]
    #[ignore = "regenerates a test vector"]
    fn write_rust_artifacts() {
        let v = &vectors()["es256"];
        let claims = v["claims"].as_object().unwrap();
        let (token, _) = issuer()
            .mint(
                "agent-a",
                s(&v["audience"]),
                300,
                claims,
                v["now"].as_i64().unwrap(),
            )
            .unwrap();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/rust_es256_token.txt"
        );
        std::fs::write(path, token.expose().clone() + "\n").unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mint_verify() {
        let t = issuer();
        let mut claims = Map::new();
        claims.insert("grant".into(), json!("g1"));
        claims.insert("iss".into(), json!("spoofed"));
        let (token, exp) = t
            .mint("agent-a", "mcp:srv", 300, &claims, 1_000_000)
            .unwrap();
        assert_eq!(exp, 1_000_300);
        let got = t.verify(token.expose(), "mcp:srv", 1_000_001.0).unwrap();
        assert_eq!(got["grant"], "g1");
        assert_eq!(got["iss"], t.issuer());
        assert_eq!(got["nbf"], 999_995);
        assert_eq!(t.mint("a", "b", 0, &Map::new(), 10).unwrap().1, 11);
        // Within the leeway, then expired.
        assert!(t.verify(token.expose(), "mcp:srv", 1_000_304.0).is_ok());
        assert!(t.verify(token.expose(), "mcp:srv", 1_000_305.0).is_err());
        // Tampering with the payload breaks the signature.
        let parts: Vec<&str> = token.expose().split('.').collect();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            b64url_encode(br#"{"sub":"x"}"#),
            parts[2]
        );
        assert_eq!(
            t.verify(&forged, "mcp:srv", 1_000_001.0).unwrap_err().0,
            "Signature verification failed"
        );
        // Another broker key's issuer does not accept it.
        let other =
            TokenIssuer::new(&SigningKey::from_seed(&[5; 32]).unwrap(), t.issuer()).unwrap();
        assert!(
            other
                .verify(token.expose(), "mcp:srv", 1_000_001.0)
                .is_err()
        );
        // alg none / HS256 refused.
        let none = format!("{}.{}.", b64url_encode(br#"{"alg":"none"}"#), parts[1]);
        assert_eq!(
            t.verify(&none, "mcp:srv", 1_000_001.0).unwrap_err().0,
            "The specified alg value is not allowed"
        );
        assert_eq!(
            t.verify("a.b", "mcp:srv", 1.0).unwrap_err().0,
            "Not enough segments"
        );
    }

    #[test]
    fn claim_rules() {
        let base = json!({"exp": 100, "iat": 10, "sub": "s", "aud": ["x", "y"], "iss": "i"});
        let ok = |v: &Value, now| validate_claims(v.as_object().unwrap(), "y", "i", now);
        assert!(ok(&base, 50.0).is_ok());
        let mut m = base.clone();
        m["iss"] = json!("j");
        assert_eq!(ok(&m, 50.0).unwrap_err().0, "Invalid issuer");
        let mut m = base.clone();
        m["aud"] = json!([1]);
        assert_eq!(ok(&m, 50.0).unwrap_err().0, "Invalid claim format in token");
        let mut m = base.clone();
        m["sub"] = Value::Null;
        assert_eq!(
            ok(&m, 50.0).unwrap_err().0,
            "Token is missing the \"sub\" claim"
        );
        let mut m = base.clone();
        m["nbf"] = json!(60);
        assert_eq!(
            ok(&m, 50.0).unwrap_err().0,
            "The token is not yet valid (nbf)"
        );
        assert!(ok(&m, 55.0).is_ok());
        let mut m = base;
        m["exp"] = json!("100");
        assert_eq!(
            ok(&m, 50.0).unwrap_err().0,
            "Expiration Time claim (exp) must be an integer."
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn github_app_jwt_matches_pyjwt() {
        let v = &vectors()["github_app"];
        for (pem_key, token_key) in [("pkcs1_pem", "token"), ("pkcs8_pem", "token")] {
            let key = GitHubAppKey::from_pem(s(&v[pem_key])).unwrap();
            let now = v["now"].as_i64().unwrap();
            assert_eq!(
                key.app_jwt(s(&v["app_id"]), now).unwrap().expose(),
                s(&v[token_key])
            );
        }
        assert!(matches!(
            GitHubAppKey::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"),
            Err(JwtError::RsaKey(_))
        ));
        assert!(GitHubAppKey::from_pem("nope").is_err());
    }
}

#[cfg(kani)]
mod proofs {
    use super::sub_256;

    /// `sub_256` is 256-bit subtraction: `a − b + b ≡ a`, and the borrow says
    /// whether `a < b` (limbs compared from the most significant).
    #[kani::proof]
    #[kani::unwind(5)]
    fn sub_256_is_subtraction() {
        let a: [u64; 4] = kani::any();
        let b: [u64; 4] = kani::any();
        let (d, borrow) = sub_256(&a, &b);
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = d[i].overflowing_add(b[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            assert_eq!(s2, a[i]);
            carry = u64::from(c1 | c2);
        }
        let less = a.iter().rev().cmp(b.iter().rev()) == core::cmp::Ordering::Less;
        assert_eq!(borrow == 1, less);
        assert_eq!(carry, borrow);
    }
}
