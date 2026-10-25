#![forbid(unsafe_code)]
//! The one TLS client configuration every outbound connection uses: the
//! broker's calls to GitHub, Discord, LiteLLM, OpenRouter, LLDAP and the
//! OpenID provider; agents' calls to the broker; daemons' channel.
//!
//! - rustls with the `ring` provider only, TLS 1.2 and 1.3.
//! - Roots: the Mozilla bundle (`webpki-roots`) minus [`DISTRUSTED`]; or,
//!   for a service with its own CA (the cluster CA), only that CA
//!   ([`private_root_store`]); or, for mail only, the bundle plus a
//!   private CA ([`root_store_plus`]).
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

/// Only the certificates in `pem`: the roots for a service that has its
/// own CA (the Kubernetes API server's cluster CA). The public roots are
/// not trusted for it, so a publicly trusted certificate for that name
/// (the API server's name may be a public one) cannot receive what the
/// broker sends there (a service-account token). This is what a private
/// CA means unless the caller says otherwise ([`root_store_plus`]); the
/// Python's `httpx.AsyncClient(verify=ca_file)` trusted only that file too.
pub fn private_root_store(pem: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    add_pem(&mut store, pem)?;
    Ok(store)
}

/// `root_store()` plus the certificates in `extra_pem`. Only for a client
/// whose one config also talks to public services (mail: a private IMAP
/// server next to Gmail and SimpleLogin); a client for one private
/// service takes [`private_root_store`].
pub fn root_store_plus(extra_pem: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut store = root_store();
    add_pem(&mut store, extra_pem)?;
    Ok(store)
}

fn add_pem(store: &mut RootCertStore, pem: &[u8]) -> Result<(), TlsError> {
    let mut added = 0usize;
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|e| TlsError::Pem(e.to_string()))?;
        store
            .add(cert)
            .map_err(|e| TlsError::Rejected(e.to_string()))?;
        added = added.saturating_add(1);
    }
    if added == 0 {
        return Err(TlsError::NoCertificates);
    }
    Ok(())
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
            root_store_plus(b"not pem"),
            Err(TlsError::NoCertificates)
        ));
        assert!(matches!(
            private_root_store(b"not pem"),
            Err(TlsError::NoCertificates)
        ));
    }

    const PUBLIC_CHAIN: &[u8] = include_bytes!("../tests/data/public-chain.pem");
    const PRIVATE_CA: &[u8] = include_bytes!("../tests/data/private-ca.pem");
    const PRIVATE_LEAF: &[u8] = include_bytes!("../tests/data/private-leaf.pem");

    /// Verifies `chain` (leaf first) for `name` against `roots`, at
    /// 2026-11-01 (inside both fixtures' validity).
    fn verify(roots: RootCertStore, chain: &[u8], name: &str) -> Result<(), rustls::Error> {
        use rustls::pki_types::{ServerName, UnixTime};
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap();
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain)
            .collect::<Result<_, _>>()
            .unwrap();
        let (leaf, intermediates) = certs.split_first().unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_793_491_200));
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            verifier.as_ref(),
            leaf,
            intermediates,
            &ServerName::try_from(name.to_owned()).unwrap(),
            &[],
            now,
        )
        .map(|_| ())
    }

    #[test]
    fn public_chain_is_trusted_by_the_public_roots() {
        // The fixture really chains to a root in our bundle, so the
        // refusal below is the private store's doing.
        verify(root_store(), PUBLIC_CHAIN, "letsencrypt.org").unwrap();
        verify(
            root_store_plus(PRIVATE_CA).unwrap(),
            PUBLIC_CHAIN,
            "letsencrypt.org",
        )
        .unwrap();
    }

    #[test]
    fn private_ca_refuses_a_publicly_trusted_certificate() {
        let roots = private_root_store(PRIVATE_CA).unwrap();
        assert_eq!(roots.len(), 1, "only the private CA");
        let err = verify(roots, PUBLIC_CHAIN, "letsencrypt.org").unwrap_err();
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "{err:?}"
        );
    }

    #[test]
    fn private_ca_trusts_its_own_certificates() {
        let roots = private_root_store(PRIVATE_CA).unwrap();
        verify(roots, PRIVATE_LEAF, "kubernetes.default.svc").unwrap();
        // ... which the public roots do not.
        assert!(verify(root_store(), PRIVATE_LEAF, "kubernetes.default.svc").is_err());
    }
}
