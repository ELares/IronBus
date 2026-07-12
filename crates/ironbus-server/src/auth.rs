// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connection-scoped authentication and the three-scope authorization model (#631, V2-M7).
//!
//! This is the broker-side half of the auth contract specified in `docs/AUTHENTICATION.md` (the
//! mechanisms and scopes) and `docs/SECRETS.md` (the redacting newtype, the fail-closed secret-file
//! permission check). It owns three mechanisms — bearer token, username+password, mTLS — crossed
//! with three INDEPENDENT scopes — `publish`, `subscribe`, `admin`, with **no implication** (`admin`
//! does NOT grant `publish` or `subscribe`). Authentication is established ONCE, at the `Connect`
//! handshake, and the resolved identity's scope set is pinned to the connection for its lifetime
//! ([`crate::session`] does the pinning); a verb is authorized against that pinned set, never against
//! anything the client asserts in a later frame.
//!
//! Two sharp risks the design forecloses, per the spec:
//! 1. A timing oracle in bearer-token comparison — defeated by the constant-time digest compare
//!    ([`subtle`]) and the uniform [`AuthError::Violation`] (one error for every failure, no oracle).
//! 2. An authz bypass where a verifying cert gets a default scope — defeated by requiring an explicit
//!    SAN-to-identity match: chain verification grants NO scope; only a configured match does, and a
//!    verifying cert with no match is rejected.
//!
//! The TLS 1.3 transport that wraps the credential on a non-loopback bind is the FLAGGED follow-up
//! (the rustls provider decision is owned by #107); this module supplies the "an auth identity is
//! configured" precondition the fail-closed bind invariant checks, and verifies a presented
//! credential, independently of whether the wire is yet TLS-wrapped.

use std::collections::BTreeMap;
use std::fmt;

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use ironbus_proto::message::{
    unpack_password_material, AuthCredential, AuthMechanism as WireMechanism,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A redacting newtype over secret bytes (#635, `docs/SECRETS.md` "The redacting newtype"). Redaction
/// is by CONSTRUCTION, not discipline: `Debug` and `Display` emit a fixed `<redacted>` placeholder
/// (identical for every secret, leaking not even the length), the raw bytes are reachable only through
/// the single explicit [`Secret::expose`] accessor (no `Deref`, no public field), and the bytes are
/// zeroed on drop with a non-elidable write so the optimizer cannot remove the clear. A struct that
/// holds a `Secret` and derives `Debug` therefore renders the field as the placeholder for free.
///
/// Equality is DELIBERATELY not derived (#897): a derived `PartialEq`/`Eq` synthesizes a
/// data-dependent, early-exit `==` over the secret bytes — precisely the timing-oracle primitive the
/// bearer path avoids via `subtle::ConstantTimeEq`. The type has no equality consumers, and its
/// safety narrative (redaction by construction) implies callers need not think about how a `Secret`
/// compares; leaving the derive off keeps that footgun unreachable. If secret equality is ever needed,
/// hand-implement it over `subtle::ConstantTimeEq` and document that the comparison is constant-time.
#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wraps secret bytes. The bytes are owned and will be zeroed on drop.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Secret {
        Secret(bytes)
    }

    /// The ONLY way to read the wrapped bytes — a greppable, review-visible call. There is
    /// deliberately no `Deref` and no public field, so every secret read is an explicit `expose()`.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// The fixed redaction placeholder, identical for every secret so it leaks nothing (not even length).
const REDACTED: &str = "<redacted>";

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Non-elidable zeroization (the `zeroize` crate's volatile write), so the optimizer cannot
        // remove the clear as dead. Best-effort by construction (see docs/SECRETS.md "Zeroization":
        // this does not defend a core dump or swap, it narrows the freed-secret window).
        self.0.zeroize();
    }
}

/// One of the three INDEPENDENT authorization scopes (#631). No scope implies another: in
/// particular `Admin` does NOT grant `Publish` or `Subscribe`. The pinned scope set is the complete
/// authority of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Produce records (the `Pub` / `PubTo` / `PubSubject` verbs). Grants ONLY producing.
    Publish,
    /// Subscribe and consume: `Sub`/`Unsub`/`Flow`/`Fetch`/`StreamFetch`/`StreamCommit` and the full
    /// ack vocabulary. Grants ONLY consuming.
    Subscribe,
    /// The admin-gated verbs and diagnostics. Grants ONLY administration; NOT producing or consuming.
    Admin,
}

impl Scope {
    /// The lowercase wire/log name (`publish` / `subscribe` / `admin`), used in the audit event and
    /// the actionable startup error. Never a secret.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Publish => "publish",
            Scope::Subscribe => "subscribe",
            Scope::Admin => "admin",
        }
    }
}

/// A connection's pinned authority: the exact set of scopes granted, with NO implication between
/// them. Backed by three independent booleans (not a hierarchy), so a query for one scope never
/// answers `true` because another is present. The empty set is a valid, fully-unprivileged identity
/// (e.g. a verifying mTLS cert that matched an identity configured with no scopes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScopeSet {
    publish: bool,
    subscribe: bool,
    admin: bool,
}

impl ScopeSet {
    /// An empty scope set (no authority).
    #[must_use]
    pub fn empty() -> ScopeSet {
        ScopeSet::default()
    }

    /// Builds a scope set from an explicit list of scopes. Each listed scope is granted; an unlisted
    /// scope is NOT granted (no implication). Duplicates are harmless.
    #[must_use]
    pub fn from_scopes(scopes: &[Scope]) -> ScopeSet {
        let mut s = ScopeSet::empty();
        for &scope in scopes {
            s.grant(scope);
        }
        s
    }

    /// Grants one scope. Does NOT grant any other scope.
    pub fn grant(&mut self, scope: Scope) {
        match scope {
            Scope::Publish => self.publish = true,
            Scope::Subscribe => self.subscribe = true,
            Scope::Admin => self.admin = true,
        }
    }

    /// Whether this set grants exactly the named scope. This is the ONLY authorization query, and it
    /// is per-scope with NO implication: `has(Scope::Publish)` is `true` ONLY if `publish` was
    /// granted, never because `admin` is present.
    #[must_use]
    pub fn has(self, scope: Scope) -> bool {
        match scope {
            Scope::Publish => self.publish,
            Scope::Subscribe => self.subscribe,
            Scope::Admin => self.admin,
        }
    }
}

/// The single uniform authentication/authorization failure (#631, `docs/AUTHENTICATION.md` "The
/// uniform Authorization Violation"). EVERY failure — unknown mechanism, bad token, bad password,
/// unknown username, a verifying mTLS cert that matches no identity, or an authenticated connection
/// attempting a verb its scope set lacks — maps to this ONE result, so the wire carries no oracle
/// that distinguishes a bad credential from an insufficient scope or enumerates usernames. The
/// broker MAY record the distinct internal reason in its own audit log (the safe side); the
/// distinction never crosses the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthError;

impl AuthError {
    /// The fixed on-the-wire message. There is no numeric code field to leak a sub-reason.
    pub const MESSAGE: &'static str = "Authorization Violation";
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(AuthError::MESSAGE)
    }
}

impl std::error::Error for AuthError {}

/// The internal, audit-side detail of a SUCCESSFUL auth (#635, the "Authn outcome" audit event). This
/// is the TRUSTED-side distinction the operator may see; it is NEVER sent to the client (which always
/// gets the uniform [`AuthError`]). Carries only safe handles (the resolved identity name, the pinned
/// scope set), never a credential.
///
/// FAILURE is NOT a variant here: [`AuthConfig::authenticate`] returns [`Err(AuthError)`] on every
/// failure, so an `Ok(AuthOutcome)` is by construction a success. Keeping this a value that can ONLY
/// mean "authenticated" is deliberate: the session handshake destructures it with an irrefutable
/// `let`, so the connection's `authenticated` flag can never be set without pinning a real identity's
/// scopes, and adding any non-success variant here becomes a compile error at that call site rather
/// than a silently-skipped bind (#889).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authentication succeeded; the connection is this identity with this pinned scope set.
    Authenticated {
        /// The resolved identity name (safe to log).
        identity: String,
        /// The pinned scope set.
        scopes: ScopeSet,
        /// The resolved tenant (#765), pinned to the connection alongside the scopes. `None` is the
        /// single-tenant default (no name prefixing). Carried here so the session pins the tenant
        /// from the SAME irrefutable authentication outcome as the scopes — a connection can never be
        /// authenticated into a tenant it did not authenticate as.
        tenant: Option<crate::tenant::TenantId>,
    },
}

/// A configured identity (#631, `docs/AUTHENTICATION.md`, the identity table). It binds a NAME (a safe
/// handle, never a secret) to an explicit scope set and an ADDITIVE credential set for exactly one
/// mechanism. The credential set is a list, not a scalar, so rotation is two deploys with no clock
/// dependence: add the new credential, deploy, then remove the old, deploy.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The identity name. Used as the audit-event subject; never a secret.
    pub name: String,
    /// The scopes granted to this identity, with no implication between them.
    pub scopes: ScopeSet,
    /// The credential binding for this identity's mechanism.
    pub credential: CredentialSet,
    /// The TENANT (account) this identity belongs to (#765, V2-M7). `None` is the single-tenant
    /// default: the identity's names are NOT prefixed and behavior is byte-for-byte the pre-tenant
    /// broker. `Some(_)` binds every name this connection uses under `<tenant>/…` (streams/groups) or
    /// `<tenant>.…` (subjects). This is the ONLY source of a connection's tenant — it is a property
    /// of the resolved credential, never anything the client asserts, so it is non-spoofable.
    pub tenant: Option<crate::tenant::TenantId>,
}

/// The additive credential set for an identity, one variant per mechanism (#631). Each carries a
/// LIST so rotation is set-membership (add then remove), never an expiry timer.
// NOTE: `Debug` is HAND-WRITTEN (below), NOT derived (#888): the `Bearer` variant holds raw SHA-256
// `digests` as bare `[u8; 32]` (no `Secret` wrapper), so a derived `Debug` would print the stored
// verifier-at-rest verbatim — and any embedding type that derives `Debug` (`Identity`, `AuthConfig`)
// would transitively leak it. A bearer digest is the at-rest verifier and is offline
// dictionary-attackable for a low-entropy token, so it is sensitive. The manual impl redacts the
// digests (count only), making redaction by CONSTRUCTION like the `Password` path (whose `phc_hashes`
// are `Secret`) — so `Identity`/`AuthConfig` inherit the redaction for free through their derived impls.
#[derive(Clone)]
pub enum CredentialSet {
    /// Accepted bearer-token SHA-256 hex digests (lowercase). The broker stores ONLY the digest; a
    /// presented token authenticates if its SHA-256 matches ANY digest, constant-time.
    Bearer {
        /// The accepted 32-byte digests (decoded from the configured hex).
        digests: Vec<[u8; 32]>,
    },
    /// Accepted Argon2id PHC strings for this identity's username. A presented password authenticates
    /// if it verifies against ANY of them.
    Password {
        /// The username this credential authenticates (matched exact-string).
        username: String,
        /// The accepted Argon2id PHC strings (self-describing: each carries its own m/t/p + salt).
        phc_hashes: Vec<Secret>,
    },
    /// Accepted SAN identities for mTLS. A verified client certificate authenticates if its resolved
    /// SAN identity exact-string matches ANY of these. Chain verification alone grants NO scope.
    Mtls {
        /// The accepted SAN identity strings (URI-then-DNS precedence, CN excluded; see [`mtls_san_identity`]).
        san_identities: Vec<String>,
    },
}

impl fmt::Debug for CredentialSet {
    /// REDACTS the bearer digests (#888): a SHA-256 digest of a bearer token is the stored
    /// verifier-at-rest and is offline dictionary-attackable for a low-entropy token, so it is
    /// treated as sensitive. The `Bearer` variant prints only the digest COUNT, never a digest
    /// byte, so neither a direct `{:?}` nor a transitive `Debug` through `Identity`/`AuthConfig`
    /// can leak the verifier. The `Password` variant's `phc_hashes` are already `Secret` (redacted
    /// for free); the `Mtls` SAN identities are safe handles, not secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialSet::Bearer { digests } => f
                .debug_struct("Bearer")
                .field(
                    "digests",
                    &format_args!("<redacted; {} digests>", digests.len()),
                )
                .finish(),
            CredentialSet::Password {
                username,
                phc_hashes,
            } => f
                .debug_struct("Password")
                .field("username", username)
                .field("phc_hashes", phc_hashes)
                .finish(),
            CredentialSet::Mtls { san_identities } => f
                .debug_struct("Mtls")
                .field("san_identities", san_identities)
                .finish(),
        }
    }
}

/// The broker's complete auth configuration: the identity table plus whether mTLS is required (#631).
/// When this is `Some(_)` on a broker, the connection handshake authenticates; when `None`, the broker
/// is in the zero-config loopback-dev mode (no auth), which the fail-closed bind invariant permits
/// ONLY on a loopback bind.
#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    /// Bearer-token identities, keyed by name for a stable audit subject.
    bearer: Vec<Identity>,
    /// Username+password identities, indexed by username for an O(1) lookup (and to make
    /// unknown-username and wrong-password indistinguishable: both run a verify and fail uniformly).
    password_by_username: BTreeMap<String, Identity>,
    /// mTLS identities, indexed by accepted SAN identity string.
    mtls_by_san: BTreeMap<String, Identity>,
    /// The broker's per-tenant quota registry (#765), if any tenant is configured. Rides the auth
    /// config (a cohesive "who + which tenant + which ceilings" unit) so a session picks it up from
    /// the same `Arc<AuthConfig>` it already receives — no new serve-path plumbing. `None` disables
    /// quota enforcement; isolation (name prefixing) is independent and comes from `Identity::tenant`.
    tenants: Option<std::sync::Arc<crate::tenant::TenantRegistry>>,
    /// The broker's cross-tenant sharing (import/export) registry (#1163, multi-tenant phase-2), if
    /// any tenant declared an `[[tenant.export]]` / `[[tenant.import]]`. Rides the auth config for the
    /// same reason as `tenants`. `None` means no sharing is configured and EVERY resource resolution
    /// stays in the caller's own tenant — byte-for-byte the phase-1 isolated broker. This is the ONLY
    /// controlled path across the (otherwise absolute) tenant boundary.
    sharing: Option<std::sync::Arc<crate::tenant::SharingRegistry>>,
}

impl AuthConfig {
    /// An empty auth config (no identities). Used as the builder seed.
    #[must_use]
    pub fn new() -> AuthConfig {
        AuthConfig::default()
    }

    /// Attaches the broker's per-tenant quota registry (#765).
    pub fn set_tenants(&mut self, tenants: std::sync::Arc<crate::tenant::TenantRegistry>) {
        self.tenants = Some(tenants);
    }

    /// The broker's per-tenant quota registry (#765), if configured (a cheap `Arc` clone). The
    /// session consults it at the connect / declare / produce quota gates.
    #[must_use]
    pub fn tenants(&self) -> Option<std::sync::Arc<crate::tenant::TenantRegistry>> {
        self.tenants.clone()
    }

    /// Attaches the broker's cross-tenant sharing (import/export) registry (#1163).
    pub fn set_sharing(&mut self, sharing: std::sync::Arc<crate::tenant::SharingRegistry>) {
        self.sharing = Some(sharing);
    }

    /// The broker's cross-tenant sharing (import/export) registry (#1163), if configured (a cheap
    /// `Arc` clone). The session consults it at every subscribe/publish resolution seam to (with
    /// authorization) resolve an import alias to the exporter's resource.
    #[must_use]
    pub fn sharing(&self) -> Option<std::sync::Arc<crate::tenant::SharingRegistry>> {
        self.sharing.clone()
    }

    /// Whether ANY auth identity is configured (#631 / #629). This is the "at least one auth identity
    /// is configured" precondition the fail-closed bind invariant requires for a non-loopback bind: a
    /// network client must be authenticated, never anonymous.
    #[must_use]
    pub fn has_any_identity(&self) -> bool {
        !self.bearer.is_empty()
            || !self.password_by_username.is_empty()
            || !self.mtls_by_san.is_empty()
    }

    /// Adds an identity to the table (#631). Routes it into the per-mechanism index so verification is
    /// O(1)/O(log n) and so the additive credential set composes (re-adding a name with more
    /// credentials is the operator's job via the config; this is the in-memory build step).
    pub fn add_identity(&mut self, identity: Identity) {
        match &identity.credential {
            CredentialSet::Bearer { .. } => self.bearer.push(identity),
            CredentialSet::Password { username, .. } => {
                self.password_by_username.insert(username.clone(), identity);
            }
            CredentialSet::Mtls { san_identities } => {
                for san in san_identities.clone() {
                    self.mtls_by_san.insert(san, identity.clone());
                }
            }
        }
    }

    /// Authenticates a presented `Connect` credential against the table, resolving it to an identity
    /// and its pinned scope set, or the uniform [`AuthError`] (#631). `peer_san` is the verified mTLS
    /// peer certificate's resolved SAN identity, if the connection presented one at the TLS layer
    /// (`None` otherwise); it is consulted ONLY for the `Mtls` mechanism.
    ///
    /// Every failure path returns the SAME [`AuthError`], so the caller cannot leak an oracle. The
    /// `AuthOutcome` is the trusted-side audit detail.
    ///
    /// # Errors
    /// [`AuthError`] (the uniform Authorization Violation) for an unknown mechanism, a bad/unmatched
    /// credential, a malformed credential body, or an mTLS selection with no verified-and-matched
    /// peer certificate.
    pub fn authenticate(
        &self,
        cred: &AuthCredential,
        peer_san: Option<&str>,
    ) -> Result<(Identity, AuthOutcome), AuthError> {
        match cred.mechanism {
            WireMechanism::Bearer => self.authenticate_bearer(&cred.material),
            WireMechanism::Password => self.authenticate_password(&cred.material),
            WireMechanism::Mtls => self.authenticate_mtls(peer_san),
            // `AuthMechanism` is `#[non_exhaustive]` (a future v-N mechanism the wire might learn).
            // An unknown mechanism FAILS CLOSED with the uniform error: this broker speaks only the
            // three v1 mechanisms, and a selector it does not implement is never a silent allow.
            _ => Err(AuthError),
        }
    }

    fn authenticate_bearer(&self, token: &[u8]) -> Result<(Identity, AuthOutcome), AuthError> {
        // Store-only-the-digest: hash the presented token, compare its digest to every configured
        // digest with a CONSTANT-TIME compare (no early exit on the first differing byte). We scan
        // all identities and all their digests unconditionally so the compare count does not depend
        // on which identity (if any) matched — no short-circuit oracle.
        let presented = Sha256::digest(token);
        let mut matched: Option<&Identity> = None;
        for identity in &self.bearer {
            if let CredentialSet::Bearer { digests } = &identity.credential {
                for digest in digests {
                    // ct_eq returns a Choice; fold into the match without branching on the per-digest
                    // result so the loop is constant-time with respect to which digest matched.
                    if bool::from(presented.as_slice().ct_eq(digest)) {
                        matched = Some(identity);
                    }
                }
            }
        }
        match matched {
            Some(identity) => Ok((
                identity.clone(),
                AuthOutcome::Authenticated {
                    identity: identity.name.clone(),
                    scopes: identity.scopes,
                    tenant: identity.tenant.clone(),
                },
            )),
            None => Err(AuthError),
        }
    }

    fn authenticate_password(&self, material: &[u8]) -> Result<(Identity, AuthOutcome), AuthError> {
        // The material packs username then password (u16-length-prefixed). A malformed body fails
        // closed (uniform error), never a panic.
        let Ok((username_bytes, password_bytes)) = unpack_password_material(material) else {
            return Err(AuthError);
        };
        let Ok(username) = std::str::from_utf8(username_bytes) else {
            return Err(AuthError);
        };
        // Unknown username and wrong password BOTH return the uniform error: no username-enumeration
        // oracle. (We do not run a dummy Argon2 on an unknown username here; the uniform error and the
        // accept-time lockout/delay — owned by the DoS layer — provide the anti-enumeration property.
        // The verify itself is constant-time w.r.t. the stored hash bytes.)
        let Some(identity) = self.password_by_username.get(username) else {
            return Err(AuthError);
        };
        let CredentialSet::Password { phc_hashes, .. } = &identity.credential else {
            return Err(AuthError);
        };
        let argon2 = Argon2::default();
        // Any PHC hash in the additive set that verifies authenticates (rotation = add then remove).
        let mut ok = false;
        for phc in phc_hashes {
            let Ok(phc_str) = std::str::from_utf8(phc.expose()) else {
                continue;
            };
            let Ok(parsed) = PasswordHash::new(phc_str) else {
                continue;
            };
            if argon2.verify_password(password_bytes, &parsed).is_ok() {
                ok = true;
            }
        }
        if ok {
            Ok((
                identity.clone(),
                AuthOutcome::Authenticated {
                    identity: identity.name.clone(),
                    scopes: identity.scopes,
                    tenant: identity.tenant.clone(),
                },
            ))
        } else {
            Err(AuthError)
        }
    }

    fn authenticate_mtls(
        &self,
        peer_san: Option<&str>,
    ) -> Result<(Identity, AuthOutcome), AuthError> {
        // The load-bearing rule (#631, "No default scope for a verifying cert"): chain verification
        // (done at the TLS layer, producing `peer_san`) grants NO scope. Only an EXACT SAN-to-identity
        // match in the configured table grants any scope; a verifying cert with no match is rejected.
        // A connection that selected mTLS but presented no verified peer certificate (peer_san None)
        // is also rejected with the uniform error.
        let Some(san) = peer_san else {
            return Err(AuthError);
        };
        match self.mtls_by_san.get(san) {
            Some(identity) => Ok((
                identity.clone(),
                AuthOutcome::Authenticated {
                    identity: identity.name.clone(),
                    scopes: identity.scopes,
                    tenant: identity.tenant.clone(),
                },
            )),
            None => Err(AuthError),
        }
    }
}

/// Resolves the SAN-based identity from a verified client certificate's SAN extension, by the fixed
/// precedence rule (#631, "Identity is the SAN, by a fixed rule"): the FIRST URI SAN if any URI SAN
/// is present, otherwise the FIRST DNS SAN. The certificate Common Name is NEVER used, not even as a
/// fallback. A cert with no URI SAN and no DNS SAN has no usable identity (`None`), and the caller
/// rejects it.
///
/// This takes the already-extracted SAN lists (the TLS layer that verifies the chain extracts them);
/// it does not parse a certificate here, so it stays testable and free of the (FLAGGED) TLS stack.
#[must_use]
pub fn mtls_san_identity(uri_sans: &[String], dns_sans: &[String]) -> Option<String> {
    if let Some(uri) = uri_sans.first() {
        return Some(uri.clone());
    }
    dns_sans.first().cloned()
}

/// Parses a lowercase hex SHA-256 digest string into 32 bytes (#631, the configured bearer-token
/// `token_hashes` entry). Rejects a wrong-length or non-hex string with a typed error so a malformed
/// config fails closed at load, never silently producing a digest that can never match.
///
/// # Errors
/// Returns an error string naming the problem (wrong length or a non-hex character).
pub fn parse_token_digest_hex(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!(
            "a bearer-token SHA-256 digest must be 64 hex characters, got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!(
            "non-hex character `{}` in a bearer-token digest",
            other as char
        )),
    }
}

/// The OWASP-recommended Argon2id EDGE profile (#631, `docs/AUTHENTICATION.md`): memory cost m = 19
/// MiB (in KiB units, the `argon2` crate's unit), time cost t = 2, parallelism p = 1. These are the
/// parameters the `ironbus server passwd` minting path stamps into the PHC string; the broker only
/// VERIFIES, so it reads the m/t/p back out of each stored PHC string (rotation can mix profiles).
const ARGON2ID_EDGE_M_COST_KIB: u32 = 19 * 1024;
const ARGON2ID_EDGE_T_COST: u32 = 2;
const ARGON2ID_EDGE_P_COST: u32 = 1;

/// The salt length in bytes for a minted Argon2id PHC string (#631): 16 bytes (128 bits) of OS CSPRNG
/// randomness, the `RustCrypto` / OWASP default. Per-credential, stored self-describing in the PHC string.
const ARGON2ID_SALT_LEN: usize = 16;

/// Mints a fresh Argon2id PHC string for `password` at the OWASP edge profile (#631), for the
/// `ironbus server passwd` operator tool. The salt is 16 bytes of OS CSPRNG randomness (per
/// credential), and the returned PHC string is SELF-DESCRIBING (it carries its own m/t/p and salt), so
/// the broker can later verify against it with no out-of-band parameters. This is the ONLY place the
/// broker codebase HASHES a password for storage; the verify path ([`AuthConfig::authenticate_password`])
/// reads the parameters back out of the stored string.
///
/// The plaintext `password` is borrowed and never retained, logged, or echoed here; the caller owns
/// reading it securely and zeroizing its buffer. The output is a HASH (a secret-at-rest the operator
/// writes to the `0o600` identity table), never the plaintext.
///
/// # Errors
/// A string naming the failure if the OS CSPRNG read fails or the hasher rejects the parameters
/// (neither happens with the fixed edge profile in practice; surfaced rather than panicked so the CLI
/// reports a clean error).
pub fn mint_password_phc(password: &[u8]) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Params, Version};

    // 16 bytes of OS CSPRNG randomness for the per-credential salt. getrandom reads the OS CSPRNG
    // (`getrandom(2)` on Linux/musl), so the salt is cryptographically random, not derived from a
    // seedable PRNG.
    let mut salt_bytes = [0u8; ARGON2ID_SALT_LEN];
    getrandom::getrandom(&mut salt_bytes)
        .map_err(|e| format!("could not read the OS CSPRNG for a password salt: {e}"))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| format!("could not encode the password salt: {e}"))?;

    let params = Params::new(
        ARGON2ID_EDGE_M_COST_KIB,
        ARGON2ID_EDGE_T_COST,
        ARGON2ID_EDGE_P_COST,
        None,
    )
    .map_err(|e| format!("invalid Argon2id parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let phc = argon2
        .hash_password(password, &salt)
        .map_err(|e| format!("could not hash the password: {e}"))?
        .to_string();
    Ok(phc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_proto::message::{pack_password_material, AuthMechanism as WireMechanism};

    fn sha256_hex(input: &[u8]) -> String {
        use std::fmt::Write as _;
        let d = Sha256::digest(input);
        let mut s = String::with_capacity(64);
        for b in d {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    // A known-good Argon2id PHC for password "correct horse" at a TEST profile (low cost so the test
    // is fast); the broker only VERIFIES, so the cost here is irrelevant to the production m=19MiB
    // profile the operator mints with. Generated deterministically below.
    fn make_phc(password: &[u8]) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(b"a-fixed-test-salt").unwrap();
        Argon2::default()
            .hash_password(password, &salt)
            .unwrap()
            .to_string()
    }

    /// A struct that holds a `Secret` and derives `Debug`, to prove the field renders redacted for
    /// free (defined at module scope so it does not trip the items-after-statements lint).
    #[derive(Debug)]
    struct SecretHolder {
        #[allow(dead_code)]
        key: Secret,
    }

    #[test]
    fn secret_redacts_in_debug_and_display_and_never_shows_bytes() {
        let s = Secret::new(b"super-secret-sentinel-XYZ".to_vec());
        let dbg = format!("{s:?}");
        let disp = format!("{s}");
        assert!(
            !dbg.contains("sentinel"),
            "debug must not show the bytes: {dbg}"
        );
        assert!(
            !disp.contains("sentinel"),
            "display must not show the bytes: {disp}"
        );
        assert!(dbg.contains("redacted"));
        assert!(disp.contains("redacted"));
        // The single accessor still returns the bytes.
        assert_eq!(s.expose(), b"super-secret-sentinel-XYZ");
        // A struct that holds a Secret and derives Debug renders the field redacted, for free.
        let h = SecretHolder {
            key: Secret::new(b"another-sentinel-ABC".to_vec()),
        };
        assert!(!format!("{h:?}").contains("sentinel"));
    }

    #[test]
    fn bearer_digests_redact_in_debug_of_credentialset_identity_and_authconfig() {
        // #888: a bearer digest is the stored verifier-at-rest and is offline dictionary-attackable
        // for a low-entropy token, so it must be redaction-by-construction like the password path.
        // Build an identity with a KNOWN digest and assert the digest bytes never surface via `{:?}`
        // of the `CredentialSet`, the embedding `Identity`, or the whole `AuthConfig`.
        let token = b"a-32-byte-high-entropy-token!!!!";
        let digest = parse_token_digest_hex(&sha256_hex(token)).unwrap();
        let digest_hex = sha256_hex(token);
        // A representative fragment of the raw digest bytes' Debug (e.g. `[123, 45, ...]`), so a
        // derived `Debug` (which would print the byte array) is caught even if the hex is not used.
        let first_byte_dbg = format!("{}", digest[0]);

        let cred = CredentialSet::Bearer {
            digests: vec![digest],
        };
        let identity = Identity {
            name: "producer".to_string(),
            scopes: ScopeSet::from_scopes(&[Scope::Publish]),
            credential: cred,
            tenant: None,
        };
        let mut cfg = AuthConfig::new();
        cfg.add_identity(identity.clone());

        for (label, rendered) in [
            ("CredentialSet", format!("{:?}", identity.credential)),
            ("Identity", format!("{identity:?}")),
            ("AuthConfig", format!("{cfg:?}")),
        ] {
            assert!(
                !rendered.contains(&digest_hex),
                "{label} debug leaked the digest hex: {rendered}"
            );
            // The bare byte-array form a derived Debug would emit: `digests: [[123, 45, ...]]`.
            assert!(
                !rendered.contains(&format!("[{first_byte_dbg}, ")),
                "{label} debug leaked the raw digest byte array: {rendered}"
            );
            assert!(
                rendered.contains("redacted"),
                "{label} debug must mark the digests redacted: {rendered}"
            );
        }
    }

    #[test]
    fn scopes_have_no_implication_admin_does_not_grant_publish_or_subscribe() {
        // The load-bearing authz property (#631): admin does NOT imply publish or subscribe.
        let admin_only = ScopeSet::from_scopes(&[Scope::Admin]);
        assert!(admin_only.has(Scope::Admin));
        assert!(
            !admin_only.has(Scope::Publish),
            "admin must NOT grant publish"
        );
        assert!(
            !admin_only.has(Scope::Subscribe),
            "admin must NOT grant subscribe"
        );

        let pub_only = ScopeSet::from_scopes(&[Scope::Publish]);
        assert!(pub_only.has(Scope::Publish));
        assert!(!pub_only.has(Scope::Subscribe));
        assert!(!pub_only.has(Scope::Admin), "publish must NOT grant admin");

        let all = ScopeSet::from_scopes(&[Scope::Publish, Scope::Subscribe, Scope::Admin]);
        assert!(all.has(Scope::Publish) && all.has(Scope::Subscribe) && all.has(Scope::Admin));

        assert!(!ScopeSet::empty().has(Scope::Publish));
    }

    #[test]
    fn bearer_authenticates_a_valid_token_and_rejects_others() {
        let token = b"a-32-byte-high-entropy-token!!!!";
        let mut cfg = AuthConfig::new();
        cfg.add_identity(Identity {
            name: "producer".to_string(),
            scopes: ScopeSet::from_scopes(&[Scope::Publish]),
            credential: CredentialSet::Bearer {
                digests: vec![parse_token_digest_hex(&sha256_hex(token)).unwrap()],
            },
            tenant: None,
        });
        assert!(cfg.has_any_identity());

        let good = AuthCredential {
            mechanism: WireMechanism::Bearer,
            material: token.to_vec(),
        };
        let (id, outcome) = cfg.authenticate(&good, None).unwrap();
        assert_eq!(id.name, "producer");
        assert!(id.scopes.has(Scope::Publish) && !id.scopes.has(Scope::Subscribe));
        // #889: an `Ok` outcome is by construction `Authenticated` and CARRIES the real pinned state —
        // the identity name and the identity's actual (non-empty) scope set, exactly what the session
        // handshake flips `authenticated` on. A success outcome can never be a no-scope shell.
        let AuthOutcome::Authenticated {
            identity,
            scopes,
            tenant: _,
        } = &outcome;
        assert_eq!(identity, "producer");
        assert_eq!(*scopes, id.scopes);
        assert!(scopes.has(Scope::Publish) && !scopes.has(Scope::Subscribe));

        let bad = AuthCredential {
            mechanism: WireMechanism::Bearer,
            material: b"the-wrong-token-entirely-here!!!".to_vec(),
        };
        // The failure path is `Err(AuthError)`, NEVER `Ok(some-failed-outcome)` — the reason there is no
        // `AuthOutcome::Failed` for an `Ok` to smuggle a decoupled auth state through (#889).
        assert_eq!(cfg.authenticate(&bad, None).unwrap_err(), AuthError);
    }

    #[test]
    fn password_authenticates_and_unknown_user_and_wrong_pw_are_uniform() {
        let mut cfg = AuthConfig::new();
        cfg.add_identity(Identity {
            name: "operator".to_string(),
            scopes: ScopeSet::from_scopes(&[Scope::Admin]),
            credential: CredentialSet::Password {
                username: "alice".to_string(),
                phc_hashes: vec![Secret::new(make_phc(b"correct horse").into_bytes())],
            },
            tenant: None,
        });

        let good = AuthCredential {
            mechanism: WireMechanism::Password,
            material: pack_password_material(b"alice", b"correct horse").unwrap(),
        };
        let (id, _) = cfg.authenticate(&good, None).unwrap();
        assert_eq!(id.name, "operator");
        assert!(id.scopes.has(Scope::Admin) && !id.scopes.has(Scope::Publish));

        let wrong_pw = AuthCredential {
            mechanism: WireMechanism::Password,
            material: pack_password_material(b"alice", b"wrong").unwrap(),
        };
        let unknown_user = AuthCredential {
            mechanism: WireMechanism::Password,
            material: pack_password_material(b"mallory", b"correct horse").unwrap(),
        };
        // Both fail with the IDENTICAL uniform error: no wrong-password vs unknown-username oracle.
        assert_eq!(cfg.authenticate(&wrong_pw, None).unwrap_err(), AuthError);
        assert_eq!(
            cfg.authenticate(&unknown_user, None).unwrap_err(),
            AuthError
        );
    }

    #[test]
    fn mtls_requires_an_explicit_san_match_and_grants_no_default_scope() {
        let mut cfg = AuthConfig::new();
        cfg.add_identity(Identity {
            name: "edge-fleet".to_string(),
            scopes: ScopeSet::from_scopes(&[Scope::Publish, Scope::Subscribe]),
            credential: CredentialSet::Mtls {
                san_identities: vec!["spiffe://example.org/edge-fleet".to_string()],
            },
            tenant: None,
        });
        let sel = AuthCredential {
            mechanism: WireMechanism::Mtls,
            material: Vec::new(),
        };
        // A verifying cert whose SAN matches authenticates with the configured scopes.
        let (id, _) = cfg
            .authenticate(&sel, Some("spiffe://example.org/edge-fleet"))
            .unwrap();
        assert_eq!(id.name, "edge-fleet");
        assert!(id.scopes.has(Scope::Publish) && id.scopes.has(Scope::Subscribe));
        assert!(!id.scopes.has(Scope::Admin));

        // A verifying cert (chain ok) whose SAN matches NO configured identity is REJECTED — no
        // default/baseline scope. This is the authz-bypass the spec forecloses.
        assert_eq!(
            cfg.authenticate(&sel, Some("spiffe://example.org/some-other-unknown"))
                .unwrap_err(),
            AuthError
        );
        // mTLS selected with NO verified peer cert is rejected.
        assert_eq!(cfg.authenticate(&sel, None).unwrap_err(), AuthError);
    }

    #[test]
    fn mtls_san_identity_prefers_uri_then_dns_and_never_cn() {
        // URI SAN wins when present.
        assert_eq!(
            mtls_san_identity(
                &["spiffe://x/uri".to_string()],
                &["dns.example".to_string()]
            ),
            Some("spiffe://x/uri".to_string())
        );
        // DNS SAN is the fallback only when no URI SAN.
        assert_eq!(
            mtls_san_identity(
                &[],
                &["dns.example".to_string(), "second.example".to_string()]
            ),
            Some("dns.example".to_string())
        );
        // No URI and no DNS SAN = no usable identity (CN is never consulted here).
        assert_eq!(mtls_san_identity(&[], &[]), None);
    }

    #[test]
    fn unknown_wire_mechanism_path_is_covered_by_the_three_arms() {
        // The wire layer rejects an unknown selector before this module is reached (parse_connect_auth
        // returns a typed error), so authenticate only ever sees a known mechanism; this asserts each
        // known mechanism with no matching identity uniformly fails.
        let cfg = AuthConfig::new();
        for mech in [
            WireMechanism::Bearer,
            WireMechanism::Password,
            WireMechanism::Mtls,
        ] {
            let cred = AuthCredential {
                mechanism: mech,
                material: if matches!(mech, WireMechanism::Password) {
                    pack_password_material(b"u", b"p").unwrap()
                } else {
                    Vec::new()
                },
            };
            assert_eq!(
                cfg.authenticate(&cred, Some("nobody")).unwrap_err(),
                AuthError
            );
        }
    }

    #[test]
    fn parse_token_digest_hex_rejects_bad_input() {
        assert!(parse_token_digest_hex("not-hex").is_err());
        assert!(parse_token_digest_hex(&"zz".repeat(32)).is_err());
        assert!(parse_token_digest_hex(&"ab".repeat(32)).is_ok());
    }

    #[test]
    fn mint_password_phc_round_trips_through_the_verify_path_and_salts_uniquely() {
        // The `ironbus server passwd` minting path (#631): a minted PHC verifies the right password and
        // rejects the wrong one, AND a freshly minted hash for the SAME password is DIFFERENT each time
        // (a fresh random salt), so two operators setting the same password never collide on the hash.
        let phc1 = mint_password_phc(b"correct horse battery staple").unwrap();
        let phc2 = mint_password_phc(b"correct horse battery staple").unwrap();
        assert_ne!(phc1, phc2, "each mint must use a fresh random salt");
        // It is a self-describing Argon2id PHC string carrying the edge profile.
        assert!(phc1.starts_with("$argon2id$"), "minted: {phc1}");
        assert!(
            phc1.contains("m=19456"),
            "edge m=19 MiB (19456 KiB): {phc1}"
        );
        assert!(
            phc1.contains("t=2") && phc1.contains("p=1"),
            "edge t/p: {phc1}"
        );

        // Wire the minted hash into an identity and verify through the SAME path the broker uses.
        let mut cfg = AuthConfig::new();
        cfg.add_identity(Identity {
            name: "human".to_string(),
            scopes: ScopeSet::from_scopes(&[Scope::Subscribe]),
            credential: CredentialSet::Password {
                username: "bob".to_string(),
                phc_hashes: vec![Secret::new(phc1.into_bytes())],
            },
            tenant: None,
        });
        // The right password authenticates.
        let good = AuthCredential {
            mechanism: WireMechanism::Password,
            material: pack_password_material(b"bob", b"correct horse battery staple").unwrap(),
        };
        assert!(cfg.authenticate(&good, None).is_ok());
        // The wrong password is the uniform violation.
        let bad = AuthCredential {
            mechanism: WireMechanism::Password,
            material: pack_password_material(b"bob", b"wrong").unwrap(),
        };
        assert_eq!(cfg.authenticate(&bad, None).unwrap_err(), AuthError);
    }
}
