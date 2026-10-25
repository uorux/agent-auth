//! A minimal PEM decoder (RFC 7468): enough for the private keys the
//! broker is given (GitHub App keys: `RSA PRIVATE KEY`, or `PRIVATE KEY`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_PAD_INDIFFERENT;

use crate::secret::Secret;

/// The largest PEM accepted (an RSA-8192 key is about 6.4 KiB).
pub const MAX_PEM_BYTES: usize = 64 * 1024;

/// One decoded PEM block.
#[derive(Debug)]
pub struct Pem {
    /// The label, e.g. `RSA PRIVATE KEY`.
    pub label: String,
    /// The DER bytes (secret: these are private keys).
    pub der: Secret<Vec<u8>>,
}

/// Why a PEM did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PemError {
    #[error("PEM too large")]
    TooLarge,
    #[error("no PEM BEGIN line")]
    NoBegin,
    #[error("no matching PEM END line")]
    NoEnd,
    #[error("encrypted or annotated PEM is not supported")]
    Headers,
    #[error("PEM body is not base64")]
    Base64,
}

/// The first PEM block in `text` (text before it is ignored, as are blank
/// lines and surrounding whitespace on each line).
pub fn parse(text: &str) -> Result<Pem, PemError> {
    if text.len() > MAX_PEM_BYTES {
        return Err(PemError::TooLarge);
    }
    let mut lines = text.lines().map(str::trim);
    let label = lines
        .by_ref()
        .find_map(|l| l.strip_prefix("-----BEGIN ")?.strip_suffix("-----"))
        .ok_or(PemError::NoBegin)?;
    let end = format!("-----END {label}-----");
    let mut body = String::new();
    let mut ended = false;
    for line in lines {
        if line == end {
            ended = true;
            break;
        }
        if line.contains(':') || line.starts_with("-----") {
            return Err(PemError::Headers);
        }
        body.push_str(line);
    }
    if !ended {
        zeroize::Zeroize::zeroize(&mut body);
        return Err(PemError::NoEnd);
    }
    let der = STANDARD_PAD_INDIFFERENT.decode(body.as_bytes());
    zeroize::Zeroize::zeroize(&mut body);
    Ok(Pem {
        label: label.to_owned(),
        der: Secret::new(der.map_err(|_| PemError::Base64)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blocks() {
        let p =
            parse("junk\n-----BEGIN TEST KEY-----\nAAEC\nAw==\n-----END TEST KEY-----\n").unwrap();
        assert_eq!(p.label, "TEST KEY");
        assert_eq!(p.der.expose(), &[0, 1, 2, 3]);
        let p = parse("-----BEGIN X-----\r\n  AAEC  \r\n\r\n-----END X-----").unwrap();
        assert_eq!(p.der.expose(), &[0, 1, 2]);
    }

    #[test]
    fn refuses() {
        assert_eq!(parse("AAEC").unwrap_err(), PemError::NoBegin);
        assert_eq!(
            parse("-----BEGIN X-----\nAAEC\n").unwrap_err(),
            PemError::NoEnd
        );
        assert_eq!(
            parse("-----BEGIN X-----\nAAEC\n-----END Y-----\n").unwrap_err(),
            PemError::Headers
        );
        assert_eq!(
            parse("-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\nAAEC\n-----END X-----").unwrap_err(),
            PemError::Headers
        );
        assert_eq!(
            parse("-----BEGIN X-----\nA!EC\n-----END X-----").unwrap_err(),
            PemError::Base64
        );
        assert_eq!(
            parse(&"A".repeat(MAX_PEM_BYTES + 1)).unwrap_err(),
            PemError::TooLarge
        );
    }
}
