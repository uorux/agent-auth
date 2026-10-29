//! `Secret<T>`: tokens, keys, passwords and seeds.

use std::fmt;
use std::hint::black_box;

use zeroize::Zeroize;

/// A secret value: zeroized when dropped, `Debug` prints `Secret(..)`, and
/// there is no `Display` or `Serialize`. Read it with [`Secret::expose`],
/// at the one place that needs the plaintext.
///
/// Byte-like secrets compare in constant time (`==` uses [`ct_eq`]).
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps `value`. Its earlier copies (if any) are the caller's business.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The plaintext. Keep the borrow short; never log it.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize + AsRef<[u8]>> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl<T: Zeroize + AsRef<[u8]>> Eq for Secret<T> {}

impl<T: Zeroize + AsRef<[u8]>> Secret<T> {
    /// Constant-time comparison with a candidate (e.g. a presented token).
    pub fn ct_eq(&self, candidate: &[u8]) -> bool {
        ct_eq(self.0.as_ref(), candidate)
    }
}

/// Compares two byte strings in time that depends only on their lengths
/// (the lengths themselves are not secret: hashes, MACs and codes have
/// fixed lengths).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .iter()
        .zip(b)
        .fold(0u8, |acc, (x, y)| black_box(acc | (x ^ y)));
    black_box(diff) == 0
}

/// Compares two secrets in time independent of both their contents and
/// their lengths: SHA-256 of each, then [`ct_eq`] on the digests. For
/// presented tokens of arbitrary length (the admin token).
pub fn ct_eq_hashed(a: &[u8], b: &[u8]) -> bool {
    let da = ring::digest::digest(&ring::digest::SHA256, a);
    let db = ring::digest::digest(&ring::digest::SHA256, b);
    ct_eq(da.as_ref(), db.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new(String::from("hunter2"));
        assert_eq!(format!("{s:?}"), "Secret(..)");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hashed_eq() {
        assert!(ct_eq_hashed(b"admin-token", b"admin-token"));
        assert!(!ct_eq_hashed(b"admin-token", b"admin-tokem"));
        assert!(!ct_eq_hashed(b"admin-token", b"admin"));
        assert!(!ct_eq_hashed(b"", b"x"));
        assert!(ct_eq_hashed(b"", b""));
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
        let a = Secret::new(vec![1u8, 2, 3]);
        assert_eq!(a, Secret::new(vec![1u8, 2, 3]));
        assert_ne!(a, Secret::new(vec![1u8, 2, 4]));
        assert!(a.ct_eq(&[1, 2, 3]));
    }
}

#[cfg(kani)]
mod proofs {
    use super::ct_eq;

    /// `ct_eq` is equality, for every pair of byte strings up to 4 bytes.
    #[kani::proof]
    #[kani::unwind(5)]
    fn ct_eq_is_equality() {
        let a: [u8; 4] = kani::any();
        let b: [u8; 4] = kani::any();
        let la: usize = kani::any();
        let lb: usize = kani::any();
        kani::assume(la <= 4 && lb <= 4);
        assert_eq!(ct_eq(&a[..la], &b[..lb]), a[..la] == b[..lb]);
    }
}
