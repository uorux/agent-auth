//! Random tokens (Python's `secrets.token_hex` / `token_urlsafe`), from the
//! system CSPRNG.

use agent_auth_crypto::RandomError;
use ring::rand::{SecureRandom, SystemRandom};

fn bytes(n: usize) -> Result<Vec<u8>, RandomError> {
    let mut out = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| RandomError)?;
    Ok(out)
}

/// `secrets.token_hex(n)`: `2n` lowercase hex digits.
pub fn token_hex(n: usize) -> Result<String, RandomError> {
    Ok(bytes(n)?.iter().map(|b| format!("{b:02x}")).collect())
}

/// `secrets.token_urlsafe(n)`: URL-safe base64 of `n` bytes, no padding.
pub fn token_urlsafe(n: usize) -> Result<String, RandomError> {
    Ok(agent_auth_crypto::b64url_encode(&bytes(n)?))
}

#[cfg(test)]
mod tests {
    #[test]
    fn shapes() {
        let h = super::token_hex(4).unwrap_or_default();
        assert_eq!(h.len(), 8);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(super::token_urlsafe(32).unwrap_or_default().len(), 43);
    }
}
