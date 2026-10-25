//! The system CSPRNG.

use ring::rand::{SecureRandom, SystemRandom};

/// The operating system's random source failed. Nothing that needs fresh
/// randomness can proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the system random number generator failed")]
pub struct RandomError;

pub(crate) fn fill(dest: &mut [u8]) -> Result<(), RandomError> {
    SystemRandom::new().fill(dest).map_err(|_| RandomError)
}

pub(crate) fn array<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// `secrets.token_urlsafe(nbytes)`: `nbytes` random bytes in URL-safe
/// base64 without padding (state, nonces, OAuth tokens, CSRF tokens).
pub fn token_urlsafe(nbytes: usize) -> Result<String, RandomError> {
    let mut buf = vec![0u8; nbytes];
    fill(&mut buf)?;
    Ok(crate::encoding::b64url_encode(&buf))
}

/// A random version-4 UUID, as 16 bytes.
pub(crate) fn uuid4() -> Result<[u8; 16], RandomError> {
    let mut b: [u8; 16] = array()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(b)
}

/// `uuid.uuid4().hex`.
pub(crate) fn uuid4_hex() -> Result<String, RandomError> {
    Ok(hex::encode(uuid4()?))
}

/// `str(uuid.uuid4())`.
pub(crate) fn uuid4_string() -> Result<String, RandomError> {
    let h = uuid4_hex()?;
    let part = |r: std::ops::Range<usize>| h.get(r).unwrap_or_default();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        part(0..8),
        part(8..12),
        part(12..16),
        part(16..20),
        part(20..32)
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(miri, ignore)]
    fn uuid_shapes() {
        let h = super::uuid4_hex().unwrap();
        assert_eq!(h.len(), 32);
        assert_eq!(&h[12..13], "4");
        let s = super::uuid4_string().unwrap();
        assert_eq!(s.len(), 36);
        assert_eq!(s.matches('-').count(), 4);
    }
}
