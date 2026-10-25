#![forbid(unsafe_code)]
//! The one TLS client configuration every outbound connection uses: the
//! broker's calls to GitHub, Discord, LiteLLM, OpenRouter, LLDAP and the
//! OpenID provider; agents' calls to the broker; daemons' channel.
//!
//! - rustls with the `ring` provider only, TLS 1.2 and 1.3.
//! - Roots: the Mozilla bundle (`webpki-roots`) minus [`DISTRUSTED`], plus
//!   any extra CA the deployment names (a cluster CA, a private LLDAP CA).
//!   Not the system store: what is trusted is pinned by Cargo.lock and
//!   reviewed, as the Python pinned certifi.

use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

/// Roots never trusted, whatever the bundle says: those the recoverable
/// eMudhra intermediates chain to (2026-10), matched by subject substring.
/// webpki-roots 1.0.11 dropped them; this guards against a regression.
pub const DISTRUSTED: &[&str] = &["emSign", "eMudhra", "AAA Certificate Services"];

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("no certificate in the extra CA file")]
    NoCertificates,
    #[error("bad PEM in the extra CA file: {0}")]
    Pem(String),
    #[error("certificate rejected: {0}")]
    Rejected(String),
    #[error("TLS configuration: {0}")]
    Config(String),
}

fn distrusted(subject: &[u8]) -> bool {
    DISTRUSTED.iter().any(|name| {
        let name = name.as_bytes();
        subject.windows(name.len()).any(|w| w == name)
    })
}

/// The Mozilla roots minus the distrusted ones.
#[must_use]
pub fn root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .filter(|anchor| !distrusted(anchor.subject.as_ref()))
            .cloned()
            .collect(),
    }
}

/// `root_store()` plus the certificates in `extra_pem` (a deployment's own
/// CA, e.g. the Kubernetes service-account `ca.crt`).
pub fn root_store_with(extra_pem: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut store = root_store();
    let mut added = 0usize;
    for cert in CertificateDer::pem_slice_iter(extra_pem) {
        let cert = cert.map_err(|e| TlsError::Pem(e.to_string()))?;
        store
            .add(cert)
            .map_err(|e| TlsError::Rejected(e.to_string()))?;
        added = added.saturating_add(1);
    }
    if added == 0 {
        return Err(TlsError::NoCertificates);
    }
    Ok(store)
}

/// A client config over `roots` with the ring provider.
pub fn client_config(roots: RootCertStore) -> Result<rustls::ClientConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

/// The default client config: `client_config(root_store())`.
pub fn default_client_config() -> Result<rustls::ClientConfig, TlsError> {
    client_config(root_store())
}

/// A reqwest builder with this TLS config, no proxy from the environment,
/// no redirects, and the given timeout. Callers add what else they need.
#[cfg(feature = "reqwest")]
#[allow(
    clippy::disallowed_methods,
    reason = "the one sanctioned construction site"
)]
pub fn reqwest_builder(
    config: rustls::ClientConfig,
    timeout: std::time::Duration,
) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(std::time::Duration::from_secs(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distrusted_roots_are_absent() {
        let store = root_store();
        assert!(store.roots.len() > 100, "the Mozilla bundle loaded");
        for anchor in &store.roots {
            assert!(!distrusted(anchor.subject.as_ref()));
        }
        // The guard really filters: the raw bundle minus ours is exactly
        // the distrusted ones (none, with webpki-roots >= 1.0.11).
        let removed = webpki_roots::TLS_SERVER_ROOTS.len() - store.roots.len();
        let expected = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .filter(|a| distrusted(a.subject.as_ref()))
            .count();
        assert_eq!(removed, expected);
    }

    #[test]
    fn subject_matching() {
        assert!(distrusted(b"\x13\x16emSign ECC Root CA - G3"));
        assert!(distrusted(b"AAA Certificate Services"));
        assert!(!distrusted(b"ISRG Root X1"));
    }

    #[test]
    fn config_builds() {
        assert!(default_client_config().is_ok());
        assert!(matches!(
            root_store_with(b"not pem"),
            Err(TlsError::NoCertificates)
        ));
    }
}
