// SPDX-License-Identifier: MIT OR Apache-2.0
//! TLS 1.3 transport configuration (ADR-0004, #766 / #107) — compiled only under `--features tls`.
//!
//! This is the crypto FOUNDATION: it builds the `rustls` configs IronBus uses to terminate (server)
//! and initiate (client) TLS 1.3 with the **aws-lc-rs** provider (the owner-ratified choice,
//! ADR-0004). It is deliberately CONFIG-ONLY — wiring these into the accept loop and the client
//! stream is the transport increment (#766). Keeping the config in one audited module means the
//! normative `docs/TRANSPORT.md` §1 invariants are enforced in exactly one place:
//!
//!   * **TLS 1.3 only** — the protocol version floor and ceiling are both pinned to 1.3
//!     ([`TLS13_ONLY`]); there is no 1.2 fallback and no downgrade knob (§1.1). rustls is built
//!     `default-features = false` so its ring-backed webpki path and its tls12 code are not even
//!     compiled: the provider is aws-lc-rs and the only version is 1.3.
//!   * **Mandatory server verification on the client** — [`client_config_from_pem`] verifies the
//!     broker chain against a supplied trust anchor; there is NO accept-any / skip-verify path here
//!     or anywhere (§1.4).
//!   * **Fail-closed key permissions** — [`ensure_key_file_not_group_or_world_readable`] refuses a
//!     private-key file that any principal other than the owner can read (§1.4, #109).
//!
//! mTLS (a REQUIRED, handshake-verified client certificate) is the next increment; the server config
//! here is server-authentication only (`with_no_client_auth`).

use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// TLS 1.3 and nothing older (docs/TRANSPORT.md §1.1: the min and max protocol version are both
/// pinned to 1.3 — no negotiation down-step exists).
static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// A typed configuration error so the caller fails closed with a precise, non-leaky message.
#[derive(Debug)]
pub enum TlsConfigError {
    /// Reading a PEM file from disk failed.
    Io(std::io::Error),
    /// The certificate PEM contained no certificate.
    NoCertificate,
    /// The key PEM contained no private key.
    NoPrivateKey,
    /// The trust-anchor PEM contained no usable CA certificate.
    NoTrustAnchor,
    /// The private-key file is readable by group or others (fail-closed secret-file rule, #109).
    /// `mode` is the file's permission bits.
    KeyFileTooOpen { mode: u32 },
    /// rustls rejected the material (bad/mismatched key or cert, empty trust store, ...).
    Rustls(rustls::Error),
}

impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "reading TLS material failed: {e}"),
            Self::NoCertificate => write!(f, "the certificate PEM contained no certificate"),
            Self::NoPrivateKey => write!(f, "the key PEM contained no private key"),
            Self::NoTrustAnchor => write!(f, "the trust-anchor PEM contained no CA certificate"),
            Self::KeyFileTooOpen { mode } => write!(
                f,
                "TLS private-key file is group/world-readable (mode {mode:o}); \
                 refusing to start — restrict it to owner-only (chmod 600)"
            ),
            Self::Rustls(e) => write!(f, "rustls rejected the TLS material: {e}"),
        }
    }
}

impl std::error::Error for TlsConfigError {}

impl From<rustls::Error> for TlsConfigError {
    fn from(e: rustls::Error) -> Self {
        Self::Rustls(e)
    }
}

/// The aws-lc-rs crypto provider (ADR-0004), pinned EXPLICITLY on every config so IronBus never
/// depends on a process-global default provider being installed — the config carries its own.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Parse a PEM certificate chain (leaf first) into DER certs, via the maintained `rustls-pki-types`
/// PEM decoder. A missing or malformed certificate maps to [`TlsConfigError::NoCertificate`].
fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsConfigError::NoCertificate)?;
    if certs.is_empty() {
        return Err(TlsConfigError::NoCertificate);
    }
    Ok(certs)
}

/// Parse a single PEM private key (PKCS#8 / SEC1 / PKCS#1) into a DER key. A missing or malformed key
/// maps to [`TlsConfigError::NoPrivateKey`].
fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|_| TlsConfigError::NoPrivateKey)
}

/// Build the SERVER config from PEM bytes: TLS 1.3-only, aws-lc-rs, server-authentication only
/// (no client certificate required — mTLS is the next increment). The bytes form lets callers load
/// from files, an embedded secret store, or a test fixture without a filesystem round-trip.
///
/// # Errors
/// Returns [`TlsConfigError`] if the certificate PEM holds no certificate, the key PEM holds no
/// private key, or rustls rejects the material (e.g. the private key does not match the certificate).
///
/// # Panics
/// Panics only if the aws-lc-rs provider cannot offer TLS 1.3 — impossible for this build, where the
/// provider always supports 1.3; the `expect` documents that invariant rather than propagating an
/// error that cannot occur.
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<ServerConfig, TlsConfigError> {
    let certs = parse_certs(cert_pem)?;
    let key = parse_key(key_pem)?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(TLS13_ONLY)
        .expect("TLS 1.3 is supported by the aws-lc-rs provider")
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(config)
}

/// Build the CLIENT config from a trust-anchor PEM bundle: TLS 1.3-only, aws-lc-rs, and MANDATORY
/// server-certificate verification against the supplied anchors. There is no accept-any path
/// (docs/TRANSPORT.md §1.4) — an empty/invalid trust store is an error, not a silent skip.
///
/// # Errors
/// Returns [`TlsConfigError::NoTrustAnchor`] if the PEM contains no parseable CA certificate (an
/// empty trust store would silently accept nothing, so it is rejected up front).
///
/// # Panics
/// Panics only if the aws-lc-rs provider cannot offer TLS 1.3 — impossible for this build (see
/// [`server_config_from_pem`]).
pub fn client_config_from_pem(ca_pem: &[u8]) -> Result<ClientConfig, TlsConfigError> {
    let anchors = parse_certs(ca_pem).map_err(|_| TlsConfigError::NoTrustAnchor)?;
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(anchors);
    if added == 0 {
        return Err(TlsConfigError::NoTrustAnchor);
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(TLS13_ONLY)
        .expect("TLS 1.3 is supported by the aws-lc-rs provider")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

/// Fail-closed secret-file rule (docs/TRANSPORT.md §1.4, #109): refuse a private-key file that any
/// principal other than the owner can read. On Unix this inspects the mode bits; any group/other
/// read/write/execute bit set is refused. On non-Unix targets the check is a no-op (the mode model
/// does not apply) and returns `Ok`.
///
/// # Errors
/// Returns [`TlsConfigError::KeyFileTooOpen`] if any group/other permission bit is set, or
/// [`TlsConfigError::Io`] if the file's metadata cannot be read.
pub fn ensure_key_file_not_group_or_world_readable(
    path: &std::path::Path,
) -> Result<(), TlsConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(TlsConfigError::Io)?;
        let mode = meta.permissions().mode();
        // Any group or other bit (0o077) set means someone other than the owner can touch the key.
        if mode & 0o077 != 0 {
            return Err(TlsConfigError::KeyFileTooOpen {
                mode: mode & 0o7777,
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::ServerName;

    use super::*;

    // A long-lived (valid 2020-01-01 .. 2100-01-01) self-signed P-256 server certificate for
    // "localhost" (CN ironbus-test-server) and its PKCS#8 key, generated once with rcgen out of tree
    // (rcgen pulls the banned `ring`, so it is NOT a dependency — the fixture is embedded instead).
    const SERVER_CERT: &[u8] = b"\
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
    const SERVER_KEY: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWd4kisc5NnK6Nv0I
RL0rrbnn9ozoIOti7I4eisF3CHWhRANCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+A
-----END PRIVATE KEY-----
";

    // A DIFFERENT self-signed cert (an unrelated trust anchor) used to prove the client refuses a
    // server it cannot verify. Generated the same way, CN ironbus-test-other.
    const OTHER_CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBWjCCAQCgAwIBAgIUfIjY91xg+z0LSwh5bngCs73UQLswCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSaXJvbmJ1cy10ZXN0LW90aGVyMCAXDTIwMDEwMTAwMDAwMFoY
DzIxMDAwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJpcm9uYnVzLXRlc3Qtb3RoZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS/sQWpzoGIBq0tyDdZLN7918LWW/j0
+CsRiYQa+vfAdERrw1POkGOIed4wUocAT9+tMkOY/VB/OSbHJxeZwPSBoxwwGjAY
BgNVHREEETAPgg1vdGhlci5pbnZhbGlkMAoGCCqGSM49BAMCA0gAMEUCIC4trwko
Aq57VS5iw0sm+NFBdTHX5XSCUQvACWp0elXzAiEArjyI3F1SeVHMY/DKGtuy7J/3
toYtkjmdU2eQ2pK/3gM=
-----END CERTIFICATE-----
";

    fn server_config() -> ServerConfig {
        server_config_from_pem(SERVER_CERT, SERVER_KEY).expect("server config from fixtures")
    }

    /// Drive a full in-memory handshake between a rustls server and client, returning the negotiated
    /// protocol version (server side). Panics if either side errors.
    fn handshake(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
    ) -> rustls::ProtocolVersion {
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(
            client_config,
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        for _ in 0..16 {
            pump(&mut client, &mut server);
            pump(&mut server, &mut client);
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(
            !client.is_handshaking(),
            "client never completed the handshake"
        );
        assert!(
            !server.is_handshaking(),
            "server never completed the handshake"
        );
        server
            .protocol_version()
            .expect("a negotiated protocol version")
    }

    /// Move all pending TLS bytes from `src` to `dst`, then let `dst` process them.
    fn pump<A, B>(src: &mut rustls::ConnectionCommon<A>, dst: &mut rustls::ConnectionCommon<B>) {
        let mut buf = Vec::new();
        while src.wants_write() {
            src.write_tls(&mut buf).unwrap();
        }
        if buf.is_empty() {
            return;
        }
        let mut rd: &[u8] = &buf;
        while !rd.is_empty() {
            if dst.read_tls(&mut rd).unwrap() == 0 {
                break;
            }
        }
        dst.process_new_packets().unwrap();
    }

    #[test]
    fn a_verifying_client_completes_a_tls_1_3_handshake_with_the_server_config() {
        let sc = Arc::new(server_config());
        let cc =
            Arc::new(client_config_from_pem(SERVER_CERT).expect("client trusts the server cert"));
        let version = handshake(sc, cc);
        assert_eq!(
            version,
            rustls::ProtocolVersion::TLSv1_3,
            "the negotiated version must be exactly TLS 1.3"
        );
    }

    #[test]
    fn the_client_refuses_a_server_it_cannot_verify() {
        // Client trusts OTHER_CERT but the server presents SERVER_CERT → verification must fail.
        let sc = Arc::new(server_config());
        let cc =
            Arc::new(client_config_from_pem(OTHER_CERT).expect("a valid but wrong trust anchor"));
        let mut server = rustls::ServerConnection::new(sc).unwrap();
        let mut client =
            rustls::ClientConnection::new(cc, ServerName::try_from("localhost").unwrap()).unwrap();
        // Pump until one side errors; the client must reject the server's certificate.
        let mut errored = false;
        for _ in 0..16 {
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                let mut rd: &[u8] = &buf;
                while !rd.is_empty() {
                    if server.read_tls(&mut rd).unwrap() == 0 {
                        break;
                    }
                }
                let _ = server.process_new_packets();
            }
            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                let mut rd: &[u8] = &buf;
                while !rd.is_empty() {
                    if client.read_tls(&mut rd).unwrap() == 0 {
                        break;
                    }
                }
                if client.process_new_packets().is_err() {
                    errored = true;
                    break;
                }
            }
        }
        assert!(
            errored,
            "client must refuse a server certificate it cannot verify"
        );
    }

    #[test]
    fn server_config_rejects_empty_or_garbage_material() {
        assert!(matches!(
            server_config_from_pem(b"not a pem", SERVER_KEY),
            Err(TlsConfigError::NoCertificate)
        ));
        assert!(matches!(
            server_config_from_pem(SERVER_CERT, b"not a pem"),
            Err(TlsConfigError::NoPrivateKey)
        ));
    }

    #[test]
    fn client_config_rejects_an_empty_trust_store() {
        assert!(matches!(
            client_config_from_pem(
                b"-----BEGIN CERTIFICATE-----\nnonsense\n-----END CERTIFICATE-----\n"
            ),
            Err(TlsConfigError::NoTrustAnchor)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_key_file_is_refused_but_owner_only_passes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("tls.key");
        std::fs::write(&key, SERVER_KEY).unwrap();

        // 0o644 (group + world readable) → refused.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ensure_key_file_not_group_or_world_readable(&key),
            Err(TlsConfigError::KeyFileTooOpen { .. })
        ));

        // 0o600 (owner-only) → accepted.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ensure_key_file_not_group_or_world_readable(&key).is_ok());
    }
}
