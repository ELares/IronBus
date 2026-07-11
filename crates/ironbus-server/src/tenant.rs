// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multi-tenant account isolation and per-tenant quotas (#765, V2-M7, phase 1).
//!
//! A *tenant* (account) is a first-class namespace that partitions the three resources the bus
//! already owns — the subject space, the stream-id space, and the consumer-group space — plus caps
//! a tenant's aggregate use of connections, streams, and durable bytes. This is a SECURITY BOUNDARY:
//! two mutually-untrusting tenants must never be able to observe or clobber one another's data.
//!
//! # Isolation by construction, not by check
//!
//! A connection's tenant is resolved from its AUTHENTICATED identity at `Connect` (see
//! [`crate::auth::Identity::tenant`] and the pin in [`crate::session`]); it is NEVER supplied by the
//! client, so it is structurally non-spoofable. The session then SERVER-APPLIES the tenant as a
//! prefix to every client-supplied resource name before it reaches the engine:
//!
//! * a stream id `orders` becomes `<tenant>/orders`, and the client's *default* (empty) stream
//!   becomes the tenant's own named stream `<tenant>` — [`TenantId::scope_stream`];
//! * a subject / bind pattern `orders.*` becomes the token-led `<tenant>.orders.*`, so a wildcard
//!   can never descend into another tenant's subtree (subject matching is token-by-token and the
//!   tenant id is a whole leading token) — [`TenantId::scope_subject`];
//! * a consumer-group name is scoped by the stream it is paired with (group state is keyed by
//!   `(stream, group)`), so scoping the stream already isolates the group; the one group-only
//!   routing seam (the transaction back-check listener group) is scoped explicitly via
//!   [`TenantId::scope_group`].
//!
//! Because the tenant id is drawn from a charset that excludes both delimiters (`/` and `.`) — and
//! every reserved rune — a client can never inject a delimiter to escape its own prefix: the map
//! `name -> <tenant><delim>name` is injective per tenant and the images of two distinct tenants are
//! disjoint. When NO tenant is configured (a no-auth loopback broker, or an identity with no
//! tenant), scoping is the identity function and behavior is byte-for-byte the single-tenant broker.
//!
//! # Quotas
//!
//! [`TenantRegistry`] holds the per-tenant configured ceilings and the live, cross-connection usage
//! (connection count, live stream set, produced bytes). Enforcement is fail-closed at the gate — a
//! connection is refused at `Connect`, a stream at declare, a produce at the byte ceiling — BEFORE
//! the work reaches the log, each with a distinct typed error code. The per-tenant ceilings sit
//! ABOVE the per-connection #633 `DoS` controls: a single greedy connection still hits its own #633
//! limit first, while the tenant ceiling caps the whole fleet.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

/// The stream / consumer-group namespace delimiter. A tenant's named stream `orders` is stored as
/// `<tenant>/orders`; the tenant's default (empty) stream is the bare `<tenant>`. `/` is graphic
/// ASCII (a valid stream-name byte) but is EXCLUDED from the tenant-id charset, so it can only ever
/// appear as this server-applied separator, never as part of a tenant id.
pub const STREAM_DELIM: char = '/';

/// The subject namespace delimiter — the subject grammar's own token separator (`.`). The tenant
/// becomes an implicit LEADING token (`<tenant>.orders`), so a wildcard subscription resolves
/// strictly within the tenant's subtree. Excluded from the tenant-id charset for the same reason.
pub const SUBJECT_DELIM: char = '.';

/// The maximum length of a tenant id, in bytes. Bounded so a tenant-prefixed stream/subject stays
/// well inside the engine's name caps and the routing trie's per-token bound.
pub const MAX_TENANT_ID_LEN: usize = 64;

/// Why a tenant id string was rejected. Validation is fail-closed: anything not provably a safe,
/// unambiguous single token is refused at config load, never silently coerced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantIdError {
    /// The tenant id was empty.
    Empty,
    /// The tenant id exceeded [`MAX_TENANT_ID_LEN`] bytes.
    TooLong {
        /// The offending length.
        len: usize,
    },
    /// The tenant id contained a byte outside the allowed charset `[A-Za-z0-9_-]`. In particular the
    /// two namespace delimiters (`/`, `.`), the subject wildcards (`*`, `>`), and any control byte
    /// are rejected here, which is what makes the server-applied prefix injective and unforgeable.
    IllegalChar {
        /// The offending character.
        ch: char,
        /// Its 0-based byte index.
        index: usize,
    },
}

impl fmt::Display for TenantIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TenantIdError::Empty => write!(f, "tenant id is empty"),
            TenantIdError::TooLong { len } => {
                write!(f, "tenant id is {len} bytes (max {MAX_TENANT_ID_LEN})")
            }
            TenantIdError::IllegalChar { ch, index } => write!(
                f,
                "tenant id has an illegal character {ch:?} at byte {index} \
                 (allowed: ASCII letters, digits, '_', '-')"
            ),
        }
    }
}

impl std::error::Error for TenantIdError {}

/// A validated tenant identifier: a non-empty, bounded token over `[A-Za-z0-9_-]`. The charset is
/// the invariant the whole isolation guarantee rests on — it excludes both namespace delimiters and
/// every subject rune, so a tenant id is simultaneously a valid single subject token AND an
/// unambiguous stream/group prefix that a client can never forge from within its own names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(String);

impl TenantId {
    /// Parses and validates a tenant id, fail-closed.
    ///
    /// # Errors
    /// [`TenantIdError`] if the string is empty, over [`MAX_TENANT_ID_LEN`], or carries any byte
    /// outside `[A-Za-z0-9_-]`.
    pub fn parse(s: &str) -> Result<TenantId, TenantIdError> {
        if s.is_empty() {
            return Err(TenantIdError::Empty);
        }
        if s.len() > MAX_TENANT_ID_LEN {
            return Err(TenantIdError::TooLong { len: s.len() });
        }
        for (index, b) in s.bytes().enumerate() {
            let ok = b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
            if !ok {
                return Err(TenantIdError::IllegalChar {
                    ch: b as char,
                    index,
                });
            }
        }
        Ok(TenantId(s.to_string()))
    }

    /// The tenant id as a string slice (safe to log; never a secret).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// SERVER-APPLIES this tenant to a client-supplied stream id. The client's DEFAULT (empty) stream
    /// maps to the tenant's own named stream — the bare tenant id — and a named stream `orders` maps
    /// to `<tenant>/orders`. Injective per tenant, and disjoint across tenants (the `/` after the
    /// tenant token can never appear in a tenant id), so a client can only ever name within its own
    /// namespace.
    #[must_use]
    pub fn scope_stream(&self, client_name: &str) -> String {
        if client_name.is_empty() {
            self.0.clone()
        } else {
            format!("{}{}{}", self.0, STREAM_DELIM, client_name)
        }
    }

    /// SERVER-APPLIES this tenant to a client-supplied subject or bind pattern, as an implicit
    /// LEADING token: `orders.*` becomes `<tenant>.orders.*` and `>` becomes `<tenant>.>`. Because
    /// subject matching is token-by-token with whole-token equality on the first token, a pattern
    /// under one tenant's leading token can never match a subject under another's.
    #[must_use]
    pub fn scope_subject(&self, client_subject: &str) -> String {
        format!("{}{}{}", self.0, SUBJECT_DELIM, client_subject)
    }

    /// SERVER-APPLIES this tenant to a client-supplied consumer-group name, for the one group-only
    /// routing seam that is not already isolated by its paired (scoped) stream — the transaction
    /// back-check listener group. Uses the stream delimiter so it shares the stream namespace's
    /// injectivity argument.
    #[must_use]
    pub fn scope_group(&self, client_group: &str) -> String {
        format!("{}{}{}", self.0, STREAM_DELIM, client_group)
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A per-tenant set of resource ceilings (#765). Each is optional: `None` is unlimited. A ceiling
/// counts a tenant's aggregate use ACROSS ALL of its connections, distinct from the per-connection
/// #633 `DoS` controls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TenantQuotas {
    /// The maximum number of live named streams the tenant may own (including its default stream).
    pub max_streams: Option<u64>,
    /// The maximum total produced bytes (payload + key + headers) admitted for the tenant. A
    /// conservative, monotonic upper bound on live bytes for phase 1: retention/trim reclamation is
    /// not yet credited back (that refinement is a phase-2 follow-up), so the ceiling only ever
    /// refuses, never under-counts.
    pub max_storage_bytes: Option<u64>,
    /// The maximum number of concurrent connections the tenant may hold across the whole fleet.
    pub max_connections: Option<u64>,
}

/// Why a per-tenant quota gate refused a verb (#765). Each maps to a distinct, stable wire error
/// code so a client (and a test) can tell the ceilings apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaError {
    /// The tenant is at its concurrent-connection ceiling.
    MaxConnections,
    /// The tenant is at its live-stream ceiling.
    MaxStreams,
    /// The tenant is at its produced-bytes ceiling.
    MaxStorageBytes,
}

impl QuotaError {
    /// The stable wire error-code token for this rejection (see [`crate::codes`]).
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            QuotaError::MaxConnections => "ERR_TENANT_MAX_CONNECTIONS",
            QuotaError::MaxStreams => "ERR_TENANT_MAX_STREAMS",
            QuotaError::MaxStorageBytes => "ERR_TENANT_MAX_STORAGE_BYTES",
        }
    }

    /// A human-readable reason string (safe to send on the wire; never a secret).
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            QuotaError::MaxConnections => "tenant connection quota exceeded",
            QuotaError::MaxStreams => "tenant stream quota exceeded",
            QuotaError::MaxStorageBytes => "tenant storage-bytes quota exceeded",
        }
    }
}

/// The live, cross-connection usage of one tenant. Mutated under the registry's single lock so the
/// check-then-increment at each gate is atomic (no TOCTOU between two of a tenant's connections).
#[derive(Debug, Default)]
struct TenantUsage {
    /// Concurrent connections currently held.
    connections: u64,
    /// The set of live SCOPED stream names created for the tenant. A set (not a bare count) so
    /// declare/produce is idempotent — re-declaring or re-producing to an existing stream does not
    /// re-charge the ceiling.
    streams: HashSet<String>,
    /// Produced bytes admitted so far (the monotonic phase-1 approximation, see
    /// [`TenantQuotas::max_storage_bytes`]).
    bytes: u64,
}

/// The broker's tenant registry (#765): the configured per-tenant ceilings plus the live usage,
/// shared immutably across every connection via `Arc`. Absent (`None` on a session) means quotas are
/// not enforced — isolation (the prefixing) is independent of and does not require this registry.
#[derive(Debug)]
pub struct TenantRegistry {
    quotas: HashMap<TenantId, TenantQuotas>,
    usage: Mutex<HashMap<TenantId, TenantUsage>>,
}

impl TenantRegistry {
    /// Builds a registry from a per-tenant quota table. A tenant absent from the table (but present
    /// on an identity) is valid and simply unlimited.
    #[must_use]
    pub fn new(quotas: HashMap<TenantId, TenantQuotas>) -> TenantRegistry {
        TenantRegistry {
            quotas,
            usage: Mutex::new(HashMap::new()),
        }
    }

    /// Whether any tenant carries a configured ceiling (a purely informational helper).
    #[must_use]
    pub fn has_quotas(&self) -> bool {
        self.quotas.values().any(|q| {
            q.max_streams.is_some() || q.max_storage_bytes.is_some() || q.max_connections.is_some()
        })
    }

    fn quotas_for(&self, tenant: &TenantId) -> TenantQuotas {
        self.quotas.get(tenant).copied().unwrap_or_default()
    }

    /// Atomically reserves a connection slot for the tenant, or refuses at the ceiling. On success
    /// returns an RAII [`ConnGuard`] that releases the slot on drop (connection close), so the count
    /// is self-healing even if a connection tears down abnormally.
    ///
    /// # Errors
    /// [`QuotaError::MaxConnections`] if the tenant already holds its configured maximum.
    pub fn acquire_connection(
        self: &Arc<Self>,
        tenant: &TenantId,
    ) -> Result<ConnGuard, QuotaError> {
        let max = self.quotas_for(tenant).max_connections;
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = usage.entry(tenant.clone()).or_default();
        if let Some(max) = max {
            if entry.connections >= max {
                return Err(QuotaError::MaxConnections);
            }
        }
        entry.connections += 1;
        Ok(ConnGuard {
            registry: Arc::clone(self),
            tenant: tenant.clone(),
        })
    }

    fn release_connection(&self, tenant: &TenantId) {
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = usage.get_mut(tenant) {
            entry.connections = entry.connections.saturating_sub(1);
        }
    }

    /// Atomically records that the tenant owns the SCOPED stream `scoped_name`, or refuses at the
    /// stream ceiling. Idempotent: recording an already-known stream always succeeds and does not
    /// re-charge the ceiling (declare / produce-on-first-produce may both reach here for the same
    /// stream).
    ///
    /// # Errors
    /// [`QuotaError::MaxStreams`] if this is a NEW stream and the tenant is already at its maximum.
    pub fn reserve_stream(&self, tenant: &TenantId, scoped_name: &str) -> Result<(), QuotaError> {
        let max = self.quotas_for(tenant).max_streams;
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = usage.entry(tenant.clone()).or_default();
        if entry.streams.contains(scoped_name) {
            return Ok(());
        }
        if let Some(max) = max {
            if entry.streams.len() as u64 >= max {
                return Err(QuotaError::MaxStreams);
            }
        }
        entry.streams.insert(scoped_name.to_string());
        Ok(())
    }

    /// Atomically charges `n` produced bytes against the tenant's byte ceiling, or refuses at it.
    ///
    /// # Errors
    /// [`QuotaError::MaxStorageBytes`] if admitting `n` more bytes would cross the tenant's maximum.
    pub fn reserve_bytes(&self, tenant: &TenantId, n: u64) -> Result<(), QuotaError> {
        let max = self.quotas_for(tenant).max_storage_bytes;
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = usage.entry(tenant.clone()).or_default();
        if let Some(max) = max {
            if entry.bytes.saturating_add(n) > max {
                return Err(QuotaError::MaxStorageBytes);
            }
        }
        entry.bytes = entry.bytes.saturating_add(n);
        Ok(())
    }

    /// The tenant's current concurrent-connection count (test/introspection helper).
    #[must_use]
    pub fn connection_count(&self, tenant: &TenantId) -> u64 {
        self.usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tenant)
            .map_or(0, |u| u.connections)
    }

    /// The tenant's current live-stream count (test/introspection helper).
    #[must_use]
    pub fn stream_count(&self, tenant: &TenantId) -> u64 {
        self.usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tenant)
            .map_or(0, |u| u.streams.len() as u64)
    }
}

/// An RAII connection reservation (#765): decrements the tenant's live connection count when the
/// connection's [`crate::session::Session`] is dropped, so the fleet ceiling is self-healing.
#[derive(Debug)]
pub struct ConnGuard {
    registry: Arc<TenantRegistry>,
    tenant: TenantId,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.registry.release_connection(&self.tenant);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_charset_is_fail_closed() {
        assert!(TenantId::parse("acme").is_ok());
        assert!(TenantId::parse("acme-corp_1").is_ok());
        assert_eq!(TenantId::parse(""), Err(TenantIdError::Empty));
        // Every escape byte is rejected: the two delimiters, both wildcards, a dot, a control byte.
        for bad in ["a/b", "a.b", "a*b", "a>b", "a b", "a\u{0}b", "tenant/../x"] {
            assert!(
                matches!(TenantId::parse(bad), Err(TenantIdError::IllegalChar { .. })),
                "expected {bad:?} rejected"
            );
        }
        assert!(matches!(
            TenantId::parse(&"x".repeat(MAX_TENANT_ID_LEN + 1)),
            Err(TenantIdError::TooLong { .. })
        ));
    }

    #[test]
    fn scoping_is_injective_and_disjoint_across_tenants() {
        let a = TenantId::parse("a").unwrap();
        let b = TenantId::parse("b").unwrap();
        // Default stream maps to the bare tenant id; named streams nest under it.
        assert_eq!(a.scope_stream(""), "a");
        assert_eq!(a.scope_stream("orders"), "a/orders");
        assert_eq!(b.scope_stream("orders"), "b/orders");
        assert_ne!(a.scope_stream("orders"), b.scope_stream("orders"));
        // A client trying to inject the delimiter cannot escape its own prefix: the leading
        // `<tenant>/` token still dominates, and the injected name is refused as a stream name by
        // the engine anyway. The point here is only that it stays under the tenant.
        assert!(a.scope_stream("b/orders").starts_with("a/"));
        // Subjects: the tenant is a whole leading token.
        assert_eq!(a.scope_subject("orders.*"), "a.orders.*");
        assert_eq!(a.scope_subject(">"), "a.>");
        assert_ne!(a.scope_subject("orders"), b.scope_subject("orders"));
        // A prefix-substring tenant pair (`a` vs `ab`) stays disjoint because the delimiter follows.
        let ab = TenantId::parse("ab").unwrap();
        assert_ne!(a.scope_subject("x"), ab.scope_subject("x")); // "a.x" != "ab.x"
        assert_ne!(a.scope_stream("x"), ab.scope_stream("x")); // "a/x" != "ab/x"
    }

    #[test]
    fn connection_quota_counts_across_connections_and_self_heals() {
        let mut q = HashMap::new();
        let t = TenantId::parse("t").unwrap();
        q.insert(
            t.clone(),
            TenantQuotas {
                max_connections: Some(2),
                ..TenantQuotas::default()
            },
        );
        let reg = Arc::new(TenantRegistry::new(q));
        let g1 = reg.acquire_connection(&t).unwrap();
        let g2 = reg.acquire_connection(&t).unwrap();
        assert_eq!(reg.connection_count(&t), 2);
        assert_eq!(
            reg.acquire_connection(&t).unwrap_err(),
            QuotaError::MaxConnections
        );
        drop(g1);
        assert_eq!(reg.connection_count(&t), 1);
        // A slot freed by a closed connection is reusable.
        let _g3 = reg.acquire_connection(&t).unwrap();
        assert_eq!(reg.connection_count(&t), 2);
        drop(g2);
    }

    #[test]
    fn stream_quota_is_idempotent_and_capped() {
        let mut q = HashMap::new();
        let t = TenantId::parse("t").unwrap();
        q.insert(
            t.clone(),
            TenantQuotas {
                max_streams: Some(2),
                ..TenantQuotas::default()
            },
        );
        let reg = TenantRegistry::new(q);
        assert!(reg.reserve_stream(&t, "t").is_ok());
        assert!(reg.reserve_stream(&t, "t").is_ok()); // idempotent, still one
        assert!(reg.reserve_stream(&t, "t/orders").is_ok());
        assert_eq!(reg.stream_count(&t), 2);
        assert_eq!(reg.reserve_stream(&t, "t/new"), Err(QuotaError::MaxStreams));
    }

    #[test]
    fn byte_quota_refuses_at_ceiling() {
        let mut q = HashMap::new();
        let t = TenantId::parse("t").unwrap();
        q.insert(
            t.clone(),
            TenantQuotas {
                max_storage_bytes: Some(100),
                ..TenantQuotas::default()
            },
        );
        let reg = TenantRegistry::new(q);
        assert!(reg.reserve_bytes(&t, 60).is_ok());
        assert!(reg.reserve_bytes(&t, 40).is_ok());
        assert_eq!(reg.reserve_bytes(&t, 1), Err(QuotaError::MaxStorageBytes));
    }

    #[test]
    fn absent_quota_is_unlimited() {
        let t = TenantId::parse("t").unwrap();
        let reg = Arc::new(TenantRegistry::new(HashMap::new()));
        for _ in 0..1000 {
            let _g = reg.acquire_connection(&t).unwrap();
        }
        assert!(reg.reserve_stream(&t, "t/x").is_ok());
        assert!(reg.reserve_bytes(&t, u64::MAX).is_ok());
    }
}
