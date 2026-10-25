//! Base64 as the Python wrote and read it.

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD_PAD_INDIFFERENT, URL_SAFE_NO_PAD, URL_SAFE_NO_PAD_INDIFFERENT,
};

/// URL-safe base64 without padding (Python `_b64`).
pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// URL-safe base64, padding optional (Python `_unb64`). Stricter than
/// Python's decoder, which also skipped stray characters: only the URL-safe
/// alphabet is accepted, and non-zero trailing bits are refused (no honest
/// peer produces either).
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD_INDIFFERENT.decode(text).ok()
}

/// A 32-byte key in base64: URL-safe or standard alphabet, padding optional.
pub(crate) fn decode_key32(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    let bytes = URL_SAFE_NO_PAD_INDIFFERENT
        .decode(text)
        .or_else(|_| STANDARD_PAD_INDIFFERENT.decode(text))
        .ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_padding() {
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(b64url_decode("-_8="), Some(vec![0xfb, 0xff]));
        assert_eq!(b64url_decode("+/8="), None);
        assert_eq!(b64url_decode("-_9"), None, "trailing bits");
        assert_eq!(b64url_decode(""), Some(vec![]));
    }

    #[test]
    fn key32() {
        let k = [7u8; 32];
        assert_eq!(decode_key32(&b64url_encode(&k)), Some(k));
        assert_eq!(decode_key32(&format!(" {}=\n", b64url_encode(&k))), Some(k));
        assert_eq!(decode_key32("AAAA"), None);
    }
}
