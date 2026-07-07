// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client-side TLS 1.3 configuration (ADR-0004 / #766, client side #957) — compiled only under
//! `--features tls`.
//!
//! This builds the rustls `ClientConfig` the client uses to VERIFY a broker's certificate and connect
//! inside a TLS 1.3 session (so a bearer/password credential travels encrypted), and optionally to
//! present a client certificate for mTLS. It enforces the normative `docs/TRANSPORT.md` §1.4 client
//! rules in one place:
//!
//!   * **TLS 1.3 only** — floor == ceiling == 1.3, aws-lc-rs provider (the same as the server).
//!   * **Server-certificate verification is MANDATORY** — the chain is verified against the configured
//!     trust anchor and the server name is checked. There is NO accept-any / insecure-skip-verify path;
//!     an empty/invalid trust store is an error, not a silent skip.
//!   * **mTLS is optional** — a configured client cert+key is presented at the handshake.

use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

/// TLS 1.3 and nothing older (docs/TRANSPORT.md §1.1).
static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// A typed client-TLS configuration error.
#[derive(Debug)]
pub enum TlsClientError {
    /// The trust-anchor (CA) PEM contained no usable certificate.
    NoTrustAnchor,
    /// The client-certificate PEM contained no certificate.
    NoClientCert,
    /// The client private-key PEM contained no key.
    NoClientKey,
    /// The configured server name is not a valid DNS name / IP for SNI + verification.
    BadServerName,
    /// rustls rejected the material (e.g. a client cert/key that do not match).
    Rustls(rustls::Error),
}

impl std::fmt::Display for TlsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTrustAnchor => {
                write!(f, "the TLS CA bundle contained no usable trust anchor")
            }
            Self::NoClientCert => write!(f, "the client-certificate PEM contained no certificate"),
            Self::NoClientKey => write!(f, "the client-key PEM contained no private key"),
            Self::BadServerName => write!(f, "the TLS server name is not a valid DNS name or IP"),
            Self::Rustls(e) => write!(f, "rustls rejected the client TLS material: {e}"),
        }
    }
}

impl std::error::Error for TlsClientError {}

/// The client's TLS settings for a connection (ADR-0004, #957): the trust anchor to verify the broker
/// against, the expected server name, and an OPTIONAL client certificate for mTLS. Cloneable so it can
/// live on the shared [`ClientConfig`](crate::ClientConfig). Its `Debug` REDACTS the secret client key.
#[derive(Clone)]
pub struct TlsClientConfig {
    /// The PEM trust-anchor bundle (one or more CA certs) the broker's chain must verify against.
    ca_pem: Vec<u8>,
    /// The expected server name (SNI + certificate name verification).
    server_name: String,
    /// An optional `(client_cert_pem, client_key_pem)` for mTLS — the cert the client presents.
    client_auth: Option<(Vec<u8>, Vec<u8>)>,
}

impl std::fmt::Debug for TlsClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the CA bytes or (especially) the client key. Shape only.
        f.debug_struct("TlsClientConfig")
            .field("server_name", &self.server_name)
            .field("has_client_cert", &self.client_auth.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsClientConfig {
    /// Server-verification-only client TLS: verify the broker's chain against `ca_pem`, checking the
    /// certificate against `server_name` (also used as SNI). No client certificate is presented.
    #[must_use]
    pub fn new(ca_pem: impl Into<Vec<u8>>, server_name: impl Into<String>) -> Self {
        Self {
            ca_pem: ca_pem.into(),
            server_name: server_name.into(),
            client_auth: None,
        }
    }

    /// Add a client certificate for mTLS: the client presents `client_cert_pem` + `client_key_pem` at
    /// the handshake, so a broker configured with `--tls-client-ca` can authenticate it by certificate.
    #[must_use]
    pub fn with_client_cert(
        mut self,
        client_cert_pem: impl Into<Vec<u8>>,
        client_key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_auth = Some((client_cert_pem.into(), client_key_pem.into()));
        self
    }

    /// The configured server name (SNI + verification).
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Whether a client certificate is configured (mTLS).
    #[must_use]
    pub fn has_client_cert(&self) -> bool {
        self.client_auth.is_some()
    }

    /// Build the rustls [`ClientConfig`]: TLS 1.3-only, aws-lc-rs, MANDATORY server verification against
    /// the configured trust anchor, and — when a client cert is set — mTLS client authentication.
    ///
    /// # Errors
    /// [`TlsClientError`] if the CA bundle has no usable anchor, the client cert/key is missing or
    /// malformed, or rustls rejects the material.
    ///
    /// # Panics
    /// Panics only if the aws-lc-rs provider cannot offer TLS 1.3 — impossible for this build, where the
    /// provider always supports 1.3; the `expect` documents that invariant rather than propagating an
    /// error that cannot occur.
    pub fn build(&self) -> Result<ClientConfig, TlsClientError> {
        let anchors = CertificateDer::pem_slice_iter(&self.ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TlsClientError::NoTrustAnchor)?;
        let mut roots = RootCertStore::empty();
        let (added, _ignored) = roots.add_parsable_certificates(anchors);
        if added == 0 {
            return Err(TlsClientError::NoTrustAnchor);
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13_ONLY)
            .expect("TLS 1.3 is supported by the aws-lc-rs provider")
            .with_root_certificates(roots);
        let config = match &self.client_auth {
            Some((cert_pem, key_pem)) => {
                let certs = CertificateDer::pem_slice_iter(cert_pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TlsClientError::NoClientCert)?;
                if certs.is_empty() {
                    return Err(TlsClientError::NoClientCert);
                }
                let key = PrivateKeyDer::from_pem_slice(key_pem)
                    .map_err(|_| TlsClientError::NoClientKey)?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(TlsClientError::Rustls)?
            }
            None => builder.with_no_client_auth(),
        };
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A long-lived self-signed cert + key (the server test fixture) used here only as a trust anchor /
    // client-cert pair to exercise the builder — the handshake itself is tested in the client crate's
    // integration test against a real broker.
    const CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBVzCB/aADAgECAhMjGIxpQAwb+081fMl2nX2WEMQ8MAoGCCqGSM49BAMCMB4x
HDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIwIBcNMjAwMTAxMDAwMDAwWhgP
MjEwMDAxMDEwMDAwMDBaMB4xHDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+AoxgwFjAU
BgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJ+smDY9Jybx
FoJDOjOor9Cb56IyQQ64ts0roLO5NVx9AiEAnB1pAliacK3UDfG6xKEig12h4tzf
UrjVOalNQ4uwFJg=
-----END CERTIFICATE-----
";
    const KEY: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWd4kisc5NnK6Nv0I
RL0rrbnn9ozoIOti7I4eisF3CHWhRANCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+A
-----END PRIVATE KEY-----
";

    #[test]
    fn server_verify_only_config_builds() {
        let cfg = TlsClientConfig::new(CERT.to_vec(), "localhost");
        assert!(!cfg.has_client_cert());
        cfg.build()
            .expect("a valid trust anchor builds a client config");
    }

    #[test]
    fn mtls_config_with_a_client_cert_builds() {
        let cfg = TlsClientConfig::new(CERT.to_vec(), "localhost")
            .with_client_cert(CERT.to_vec(), KEY.to_vec());
        assert!(cfg.has_client_cert());
        cfg.build()
            .expect("a client cert+key builds an mTLS client config");
    }

    #[test]
    fn an_empty_or_garbage_trust_anchor_is_rejected() {
        assert!(matches!(
            TlsClientConfig::new(b"not a pem".to_vec(), "localhost").build(),
            Err(TlsClientError::NoTrustAnchor)
        ));
    }

    #[test]
    fn debug_redacts_the_secret_key() {
        let cfg = TlsClientConfig::new(CERT.to_vec(), "localhost")
            .with_client_cert(CERT.to_vec(), KEY.to_vec());
        let s = format!("{cfg:?}");
        assert!(s.contains("localhost") && s.contains("has_client_cert"));
        // The key/cert bytes never appear.
        assert!(!s.contains("MIGHAgEA") && !s.contains("BEGIN"));
    }
}
