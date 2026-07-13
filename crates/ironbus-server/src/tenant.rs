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

// ================================================================================================
// #1163 — CONTROLLED cross-tenant IMPORT / EXPORT (multi-tenant phase-2).
//
// Phase-1 (#1162) made the tenant boundary ABSOLUTE by server-applied prefixing (above). Phase-2
// adds the ONE deliberate, allowlisted, revocable way to cross it — NATS-accounts-style. It is a
// controlled ALIAS, never a new namespace: an import resolves (WITH authorization) a local alias to
// the EXPORTER's already-prefixed resource. Nothing crosses without a matching export on the other
// side, so the default (no import/export config) is byte-for-byte the phase-1 broker.
//
// The whole authorization decision is this one pure, side-effect-free module — [`SharingRegistry`]
// plus the token matchers below — so the security argument is auditable in one place and unit-tested
// exhaustively. The session layer merely applies the [`Resolution`] it returns.
//
// ------------------------------------------------------------------------------------------------
// #1170 — cross-tenant sharing SECURITY / CORRECTNESS policy (the #1169-review follow-ups).
//
// RETENTION ISOLATION (a foreign importer never holds the exporter's disk hostage). A live importer
// cross-subscribe keeps a cursor on the EXPORTER's stream, keyed `(<exporter>/stream,
// <importer>/group)` (the importer's group is scoped under ITSELF, never the exporter). That guest
// cursor is DELIBERATELY EXCLUDED from the exporter's consumer-safe retention reap floor
// (`Engine::min_committed_offset_named` via `Engine::is_foreign_importer_group`): a dead or lagging
// importer must NOT be able to pin the exporter's log from reaping (a cross-tenant availability/DoS
// vector). The exporter therefore reclaims disk strictly on ITS OWN retention policy regardless of a
// foreign guest's position. A LIVE, keeping-up importer is unaffected (its cursor sits near the head,
// well above any reaped prefix); an importer that falls outside the exporter's retention window is
// subject to it exactly like any consumer that lags past the window — it can never HOLD the window
// open. The exclusion is by NAME (the importer's `<importer>/…` token differs from the exporter's
// stream-owner token), so it holds for a live guest, a durable ghost, AND across a restart, with no
// new durable state.
//
// This name test is GATED on `Engine::cross_tenant_sharing_active` — set true ONLY when a non-empty
// SharingRegistry is wired at serve time — because `/` is a fully LEGAL, user-choosable character in
// stream AND group names on a single-tenant broker. Without the gate, a single-tenant consumer group
// `b/g` on a stream `a/orders` would be misread as a "foreign importer" and its unread records
// silently reaped (a #566 consumer-safety violation). With the gate, the exclusion applies ONLY where
// tenancy's server-scoping invariant actually holds (sharing implies tenancy), so a SAME-tenant own
// group — a bare client name with no `/`, enforced at the CLIENT wire ingress (ITEM 4) — is never
// excluded, and on a NON-sharing broker no group is EVER excluded (every group keeps its full
// consumer-safe protection). NOTE the engine deliberately still ACCEPTS `/` in a group name: a
// server-applied cross-tenant guest group is legitimately `<importer>/<group>`, and `/` is a
// long-supported path-unsafe group-name character (hex-encoded in checkpoint filenames); only the
// client-facing wire ingress forbids it.
//
// REVOKE SEMANTICS (effective on the next resolution; live cross-subs are NOT torn down). A grant is
// AUTHORIZED at resolution time (SubTo / PubTo / StreamInfo / SubSubject / PubSubject); the whole
// sharing config is loaded at broker start into the immutable [`crate::auth::AuthConfig`] and pinned
// per-connection at `Connect`. Removing an export/import (a revoke) is therefore effective for every
// resolution that happens AFTER the new config is in force — a new connection, or a re-subscribe on a
// connection that re-reads the registry — but an ALREADY-BOUND live cross-subscription keeps
// delivering off its established binding until it re-resolves (a reconnect/rebind). IronBus does NOT
// proactively tear down live cross-subscriptions on revoke: the broker is thread-per-connection with
// no central live-session registry and no cross-thread teardown channel, so enumerating and dropping
// exactly the cross-subs bound under a now-revoked grant — WITHOUT risking a same-tenant session — is
// not a contained change. The STRONGER "revoke is immediately effective (tear down live cross-subs)"
// behavior is an intentional, separately-tracked owner decision, NOT a silent default here.
//
// GROUP-NAME INGRESS GUARD (defense-in-depth). A consumer-group is server-scoped `<tenant>/<group>`
// for the txn back-check listener seam and `<importer>/<group>` for a cross-tenant importer cursor,
// both using the `/` [`STREAM_DELIM`]. A CLIENT-supplied group name may therefore NOT contain `/`
// (rejected at every group ingress with `ERR_INVALID_GROUP_NAME`): it stops a tenant self-colliding
// by naming a group `<importer>/…` on its own stream, and it keeps the retention-floor guest
// classification above precise (an own group is then guaranteed `/`-free). `.` is NOT a group prefix
// delimiter, so a dotted group name is unaffected.
// ================================================================================================

/// The direction of a single resource access at a resolution seam. An export grants a subset of
/// these; a cross-tenant access is authorized only for a direction the export actually permits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// A READ (a `SubTo` / `SubSubject` / `StreamInfo` — the importer consumes the exporter's data).
    Subscribe,
    /// A WRITE (a `PubTo` / `PubSubject` — the importer produces INTO the exporter's resource).
    Publish,
}

/// The kind of resource a sharing grant covers. A grant is kind-typed so a stream export can never be
/// satisfied by a subject import (or vice-versa), even if the names collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareKind {
    /// A named stream (exact name; streams are not patterns).
    Stream,
    /// A subject or subject pattern (may carry `*` / `>` wildcards in an EXPORT; an IMPORT alias is
    /// always a literal token prefix).
    Subject,
}

/// The direction(s) an export permits its importers. At least one is always set (a grant that
/// permits neither is refused at config load — it could never authorize anything).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GrantDirection {
    /// The importer may READ (consume) the exported resource.
    pub subscribe: bool,
    /// The importer may WRITE (produce into) the exported resource.
    pub publish: bool,
}

impl GrantDirection {
    /// Whether this grant permits `access`.
    #[must_use]
    pub fn allows(self, access: Access) -> bool {
        match access {
            Access::Subscribe => self.subscribe,
            Access::Publish => self.publish,
        }
    }
}

/// Who an export is offered to. `Public` admits every tenant; `Tenants` is an explicit allowlist.
/// Default-deny is structural: an importer not named (and no `Public`) simply finds no matching
/// export, so the alias resolves to a typed reject — never to ambient cross-tenant access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Audience {
    /// Any tenant may import this export.
    Public,
    /// Only the named tenants may import this export.
    Tenants(std::collections::BTreeSet<TenantId>),
}

impl Audience {
    /// Whether `importer` is admitted by this audience.
    #[must_use]
    pub fn admits(&self, importer: &TenantId) -> bool {
        match self {
            Audience::Public => true,
            Audience::Tenants(set) => set.contains(importer),
        }
    }
}

/// An EXPORT grant declared by an exporting tenant: the exporter's OWN resource name/pattern, who it
/// is offered to, and in which direction(s). The export defines EXACTLY what is shared — an importer
/// can reach nothing beyond a name this grant's `name` pattern covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    /// Whether this exports a stream or a subject.
    pub kind: ShareKind,
    /// The exporter's LOCAL resource name (a `Stream` exact name, or a `Subject` pattern that may
    /// carry `*` / `>`). This is in the exporter's own namespace, BEFORE the exporter's prefix.
    pub name: String,
    /// Which importing tenant(s) may use this export.
    pub audience: Audience,
    /// The direction(s) the importer is permitted.
    pub direction: GrantDirection,
}

/// An IMPORT declared by an importing tenant: a LOCAL alias, in the importer's own namespace, for a
/// resource EXPORTED by another tenant. `local` (the importer's alias) rewrites to `remote` (the
/// exporter's name) at resolution, and the resolution succeeds ONLY IF a matching [`Export`] exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// Whether this imports a stream or a subject.
    pub kind: ShareKind,
    /// The EXPORTING tenant this import references.
    pub from: TenantId,
    /// The exporter's resource name this import points at (a `Stream` exact name, or a `Subject`
    /// LITERAL prefix — an import alias never carries wildcards; the export's pattern bounds it).
    pub remote: String,
    /// The importer's LOCAL alias, in its own namespace (a `Stream` exact name, or a `Subject`
    /// LITERAL prefix). A client naming this alias reaches the exporter's `remote` resource.
    pub local: String,
}

/// The outcome of resolving a client-supplied resource name for an importing tenant through the
/// import/export layer. It is the ONE decision that can (with authorization) cross the tenant
/// boundary; the session layer simply applies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The name is NOT an import alias — the caller scopes it in its OWN tenant, exactly as phase-1.
    Own,
    /// An import alias matched a valid export grant: the fully EXPORTER-scoped engine name plus the
    /// owning (exporter) tenant, so the caller can charge the owner's quotas and route to its log.
    Crossed {
        /// The exporter (the tenant that owns the resolved resource).
        owner: TenantId,
        /// The exporter-scoped engine name (`<exporter>/…` for a stream, `<exporter>.…` for a
        /// subject) — already prefixed, ready for the engine.
        scoped: String,
    },
    /// The name matched an import alias, but NO export authorizes it for the requested direction —
    /// a typed reject. The caller must NOT fall back to its own namespace (that would silently hide
    /// a mis-configuration) and MUST never reach the exporter's data.
    Denied,
}

/// The broker's cross-tenant sharing registry (#1163): the configured exports (per exporter) and
/// imports (per importer), shared immutably across every connection via `Arc`. Absent (`None` on a
/// session) means no sharing is configured and every resolution is [`Resolution::Own`] — byte-for-
/// byte the phase-1 isolated broker.
#[derive(Debug, Default)]
pub struct SharingRegistry {
    /// Exports keyed by the EXPORTING tenant.
    exports: HashMap<TenantId, Vec<Export>>,
    /// Imports keyed by the IMPORTING tenant.
    imports: HashMap<TenantId, Vec<Import>>,
}

impl SharingRegistry {
    /// Builds a registry from the per-tenant export and import tables.
    #[must_use]
    pub fn new(
        exports: HashMap<TenantId, Vec<Export>>,
        imports: HashMap<TenantId, Vec<Import>>,
    ) -> SharingRegistry {
        SharingRegistry { exports, imports }
    }

    /// Whether no sharing is configured at all (a purely informational helper; a `true` registry is
    /// equivalent to `None`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty() && self.imports.is_empty()
    }

    /// Resolves a client-supplied STREAM name for `importer` in the given direction.
    #[must_use]
    pub fn resolve_stream(
        &self,
        importer: &TenantId,
        client_name: &str,
        access: Access,
    ) -> Resolution {
        self.resolve(importer, ShareKind::Stream, client_name, access)
    }

    /// Resolves a client-supplied SUBJECT (a concrete subject for a publish, or a pattern for a
    /// subscribe) for `importer` in the given direction.
    #[must_use]
    pub fn resolve_subject(
        &self,
        importer: &TenantId,
        client_subject: &str,
        access: Access,
    ) -> Resolution {
        self.resolve(importer, ShareKind::Subject, client_subject, access)
    }

    /// The single resolution decision, shared by both kinds. Fail-closed at every step: it returns
    /// [`Resolution::Own`] only when the name is NOT an import alias, [`Resolution::Crossed`] only
    /// when a matching export authorizes the exact name for the exact direction, and
    /// [`Resolution::Denied`] whenever an alias matched but no grant backs it.
    fn resolve(
        &self,
        importer: &TenantId,
        kind: ShareKind,
        client_name: &str,
        access: Access,
    ) -> Resolution {
        // 1. Is this name one of the importer's import aliases? If not, it is the importer's OWN
        //    resource — phase-1 behavior, untouched. (A tenant with no imports takes this fast path.)
        let Some(imports) = self.imports.get(importer) else {
            return Resolution::Own;
        };
        let Some((imp, remote)) = best_import_match(imports, kind, client_name) else {
            return Resolution::Own;
        };
        // 2. An alias matched. It crosses the boundary ONLY IF the referenced exporter has a matching
        //    export: same kind, admits THIS importer, permits THIS direction, and whose pattern
        //    covers the resolved remote name. No such export → a typed reject (NEVER own-namespace,
        //    NEVER the exporter's other resources).
        let granted = self.exports.get(&imp.from).is_some_and(|exports| {
            exports.iter().any(|ex| {
                ex.kind == kind
                    && ex.direction.allows(access)
                    && ex.audience.admits(importer)
                    && export_covers(ex, &remote, access)
            })
        });
        if !granted {
            return Resolution::Denied;
        }
        // 3. Authorized. Resolve to the EXPORTER's prefixed resource — the alias is a controlled
        //    pointer into the exporter's namespace, bounded to exactly what the export covers.
        let scoped = match kind {
            ShareKind::Stream => imp.from.scope_stream(&remote),
            ShareKind::Subject => imp.from.scope_subject(&remote),
        };
        Resolution::Crossed {
            owner: imp.from.clone(),
            scoped,
        }
    }
}

/// Finds the import alias (of `kind`) that matches `client_name`, returning the import plus the
/// exporter-side `remote` name the alias rewrites to. For a stream the alias is an EXACT name; for a
/// subject the alias is a literal token PREFIX and the client's suffix (which may carry the client's
/// own wildcards on a subscribe) is preserved. When several aliases match, the MOST SPECIFIC (longest
/// local prefix) wins, so a general and a specific import never resolve ambiguously.
fn best_import_match<'a>(
    imports: &'a [Import],
    kind: ShareKind,
    client_name: &str,
) -> Option<(&'a Import, String)> {
    let mut best: Option<(&Import, String)> = None;
    for imp in imports.iter().filter(|i| i.kind == kind) {
        let remote = match kind {
            ShareKind::Stream => (imp.local == client_name).then(|| imp.remote.clone()),
            ShareKind::Subject => rewrite_subject_prefix(&imp.local, &imp.remote, client_name),
        };
        if let Some(remote) = remote {
            if best
                .as_ref()
                .map_or(true, |(b, _)| imp.local.len() > b.local.len())
            {
                best = Some((imp, remote));
            }
        }
    }
    best
}

/// Rewrites `client_name`'s `local` alias prefix to the exporter's `remote` prefix, on a TOKEN
/// boundary. Returns `None` when `client_name` is not the alias itself and does not descend under it
/// (so `partnerX` never matches alias `partner`). The preserved suffix keeps its leading `.`.
fn rewrite_subject_prefix(local: &str, remote: &str, client_name: &str) -> Option<String> {
    if client_name == local {
        return Some(remote.to_string());
    }
    let rest = client_name.strip_prefix(local)?;
    // A real descent requires the delimiter immediately after the alias, so `partner` matches
    // `partner.orders` but NOT `partnerize`.
    if rest.starts_with(SUBJECT_DELIM) {
        Some(format!("{remote}{rest}"))
    } else {
        None
    }
}

/// Whether `export` covers the resolved `remote` name for `access`. Streams are exact; a subject
/// PUBLISH resolves a concrete subject (must MATCH the export pattern) and a subject SUBSCRIBE
/// resolves a pattern (must be WITHIN the export pattern — no broadening past the grant).
fn export_covers(export: &Export, remote: &str, access: Access) -> bool {
    match export.kind {
        ShareKind::Stream => export.name == remote,
        ShareKind::Subject => match access {
            Access::Publish => subject_matches(&export.name, remote),
            Access::Subscribe => pattern_within(&export.name, remote),
        },
    }
}

/// Standard subject matching: a `pattern` token `*` matches exactly one subject token, `>` matches
/// one-or-more trailing tokens (and is only meaningful last), and a concrete token matches itself.
/// Used to check a concrete PUBLISH subject against an export pattern.
fn subject_matches(pattern: &str, subject: &str) -> bool {
    let p: Vec<&str> = pattern.split(SUBJECT_DELIM).collect();
    let s: Vec<&str> = subject.split(SUBJECT_DELIM).collect();
    let mut i = 0;
    while i < p.len() {
        if p[i] == ">" {
            // `>` matches one-or-more remaining tokens: the subject must have at least one left.
            return i < s.len();
        }
        if i >= s.len() {
            return false;
        }
        if p[i] != "*" && p[i] != s[i] {
            return false;
        }
        i += 1;
    }
    i == s.len()
}

/// Whether SUBSCRIBING to `req` stays WITHIN what the export pattern `grant` permits — i.e. every
/// subject `req` could match is also covered by `grant`, so a subscribe can never widen past the
/// grant (a sibling subject, or a `>` reaching deeper than the grant allows, is refused). This is
/// the subscribe-direction bound that stops a wildcard import from over-reading.
fn pattern_within(grant: &str, req: &str) -> bool {
    let g: Vec<&str> = grant.split(SUBJECT_DELIM).collect();
    let r: Vec<&str> = req.split(SUBJECT_DELIM).collect();
    let (mut i, mut j) = (0usize, 0usize);
    while i < g.len() && j < r.len() {
        if g[i] == ">" {
            // The grant covers one-or-more tokens from here; `req` has at least one (j < r.len()),
            // and everything it can match from here is under the grant's `>`.
            return true;
        }
        if r[j] == ">" {
            // `req` wants one-or-more tokens where the grant permits only a single token (`*` or a
            // concrete token): `req` is BROADER than the grant — refuse.
            return false;
        }
        if g[i] != "*" && g[i] != r[j] {
            // A concrete grant token must be met by the same concrete `req` token; a `*` in `req`
            // here would be broader than the concrete grant, and `g[i] != r[j]` catches it.
            return false;
        }
        i += 1;
        j += 1;
    }
    // Within iff both ran out together: a leftover grant token (`a.*` vs `a`) means the grant covers
    // a deeper subject space than `req`, and a leftover `req` token (`a` vs `a.b`) the reverse — both
    // are disjoint-or-broader, not "within".
    i == g.len() && j == r.len()
}

/// Validates a subject name for a sharing grant. `allow_wildcards` is `true` for an EXPORT pattern
/// (`*` / `>` permitted, `>` only as the final token) and `false` for an IMPORT literal alias/prefix.
/// Rejects the tenant delimiters and empty tokens fail-closed, so a resolved name can never escape a
/// prefix or resolve ambiguously.
///
/// # Errors
/// A human-readable reason when the subject is empty, has an empty token, carries `/`, or (when
/// `!allow_wildcards`) carries a wildcard, or places `>` anywhere but last.
pub fn validate_share_subject(name: &str, allow_wildcards: bool) -> Result<(), String> {
    if name.is_empty() {
        return Err("subject is empty".to_string());
    }
    let tokens: Vec<&str> = name.split(SUBJECT_DELIM).collect();
    for (idx, tok) in tokens.iter().enumerate() {
        if tok.is_empty() {
            return Err(format!("subject {name:?} has an empty token"));
        }
        if *tok == ">" {
            if !allow_wildcards {
                return Err(format!(
                    "import alias {name:?} must be a literal prefix (no `>` wildcard)"
                ));
            }
            if idx != tokens.len() - 1 {
                return Err(format!(
                    "subject {name:?}: `>` is only valid as the final token"
                ));
            }
            continue;
        }
        if *tok == "*" {
            if !allow_wildcards {
                return Err(format!(
                    "import alias {name:?} must be a literal prefix (no `*` wildcard)"
                ));
            }
            continue;
        }
        for ch in tok.chars() {
            if ch == STREAM_DELIM {
                return Err(format!("subject {name:?} may not contain '/'"));
            }
            if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-') {
                return Err(format!(
                    "subject {name:?} token {tok:?} has an illegal character {ch:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Validates a stream name for a sharing grant: non-empty and free of the stream delimiter `/` and
/// the subject wildcards, so a resolved `<exporter>/<name>` names EXACTLY one stream within the
/// exporter and can never fan out or escape the exporter's prefix.
///
/// # Errors
/// A human-readable reason when the stream name is empty or carries `/`, `*`, or `>`.
pub fn validate_share_stream(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("stream name is empty".to_string());
    }
    for ch in name.chars() {
        if ch == STREAM_DELIM || ch == '*' || ch == '>' {
            return Err(format!(
                "stream name {name:?} may not contain '/', '*', or '>'"
            ));
        }
    }
    Ok(())
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

    // -------------------------------------------------------------------------------------------
    // #1163 — the import/export authorization core (the pure decision, exhaustively tested).
    // -------------------------------------------------------------------------------------------

    fn tid(s: &str) -> TenantId {
        TenantId::parse(s).unwrap()
    }

    /// A registry: `a` exports `orders.*` (subscribe-only) to `b`; `b` imports it as `partner.orders`.
    fn subject_sub_registry() -> SharingRegistry {
        let mut exports = HashMap::new();
        exports.insert(
            tid("a"),
            vec![Export {
                kind: ShareKind::Subject,
                name: "orders.*".to_string(),
                audience: Audience::Tenants([tid("b")].into_iter().collect()),
                direction: GrantDirection {
                    subscribe: true,
                    publish: false,
                },
            }],
        );
        let mut imports = HashMap::new();
        imports.insert(
            tid("b"),
            vec![Import {
                kind: ShareKind::Subject,
                from: tid("a"),
                remote: "orders".to_string(),
                local: "partner.orders".to_string(),
            }],
        );
        SharingRegistry::new(exports, imports)
    }

    #[test]
    fn subject_matcher_and_pattern_within_are_correct() {
        assert!(subject_matches("orders.*", "orders.us"));
        assert!(!subject_matches("orders.*", "orders.us.west")); // `*` is one token
        assert!(subject_matches("orders.>", "orders.us.west"));
        assert!(!subject_matches("orders.>", "orders")); // `>` needs >=1 trailing token
        assert!(subject_matches("orders.us", "orders.us"));

        assert!(pattern_within("orders.*", "orders.us")); // literal within `*`
        assert!(pattern_within("orders.*", "orders.*")); // same pattern
        assert!(!pattern_within("orders.*", "orders.>")); // `>` broader than `*`
        assert!(!pattern_within("orders.*", "orders")); // shorter — disjoint
        assert!(pattern_within("orders.>", "orders.us.west"));
        assert!(pattern_within("orders.>", "orders.*"));
        assert!(!pattern_within("orders.us", "orders.*")); // `*` broader than a concrete token
        assert!(!pattern_within("orders.us", "billing.us")); // sibling subject
    }

    #[test]
    fn import_resolves_only_with_a_matching_export() {
        let reg = subject_sub_registry();
        // b's alias `partner.orders.us` resolves cross-tenant to a's `a.orders.us`.
        assert_eq!(
            reg.resolve_subject(&tid("b"), "partner.orders.us", Access::Subscribe),
            Resolution::Crossed {
                owner: tid("a"),
                scoped: "a.orders.us".to_string(),
            }
        );
    }

    #[test]
    fn import_without_a_matching_export_is_denied_not_own() {
        // b imports from `a`, but `a` exports NOTHING → the alias is a typed reject, never own-space
        // and never the exporter's data.
        let mut imports = HashMap::new();
        imports.insert(
            tid("b"),
            vec![Import {
                kind: ShareKind::Subject,
                from: tid("a"),
                remote: "orders".to_string(),
                local: "partner.orders".to_string(),
            }],
        );
        let reg = SharingRegistry::new(HashMap::new(), imports);
        assert_eq!(
            reg.resolve_subject(&tid("b"), "partner.orders.us", Access::Subscribe),
            Resolution::Denied
        );
    }

    #[test]
    fn beyond_the_grant_is_denied_no_wildcard_escalation() {
        let reg = subject_sub_registry(); // grant is `orders.*` (exactly two tokens)
                                          // A sibling subtree the grant never named.
        assert_eq!(
            reg.resolve_subject(&tid("b"), "partner.billing.us", Access::Subscribe),
            Resolution::Own, // `partner.billing` is not even an alias → own namespace, not the export
        );
        // A subscribe that widens past `orders.*` (a deeper `>`): the alias matches but the export
        // does not cover it → denied.
        assert_eq!(
            reg.resolve_subject(&tid("b"), "partner.orders.>", Access::Subscribe),
            Resolution::Denied
        );
        // A deeper concrete subject than `orders.*` allows (three tokens under a two-token grant).
        assert_eq!(
            reg.resolve_subject(&tid("b"), "partner.orders.us.west", Access::Subscribe),
            Resolution::Denied
        );
    }

    #[test]
    fn direction_is_respected_subscribe_only_export_denies_publish() {
        let reg = subject_sub_registry(); // subscribe-only
        assert!(matches!(
            reg.resolve_subject(&tid("b"), "partner.orders.us", Access::Subscribe),
            Resolution::Crossed { .. }
        ));
        // The same alias for a PUBLISH is denied — the export granted subscribe only.
        assert_eq!(
            reg.resolve_subject(&tid("b"), "partner.orders.us", Access::Publish),
            Resolution::Denied
        );
    }

    #[test]
    fn revoking_the_export_stops_the_import() {
        let granted = subject_sub_registry();
        assert!(matches!(
            granted.resolve_subject(&tid("b"), "partner.orders.us", Access::Subscribe),
            Resolution::Crossed { .. }
        ));
        // Reload with the export REMOVED (imports unchanged): the very same alias now resolves to a
        // typed reject — the grant, not the import, is what authorizes the crossing.
        let mut imports = HashMap::new();
        imports.insert(
            tid("b"),
            vec![Import {
                kind: ShareKind::Subject,
                from: tid("a"),
                remote: "orders".to_string(),
                local: "partner.orders".to_string(),
            }],
        );
        let revoked = SharingRegistry::new(HashMap::new(), imports);
        assert_eq!(
            revoked.resolve_subject(&tid("b"), "partner.orders.us", Access::Subscribe),
            Resolution::Denied
        );
    }

    #[test]
    fn audience_default_deny_and_public() {
        let mk = |audience: Audience| {
            let mut exports = HashMap::new();
            exports.insert(
                tid("a"),
                vec![Export {
                    kind: ShareKind::Stream,
                    name: "orders".to_string(),
                    audience,
                    direction: GrantDirection {
                        subscribe: true,
                        publish: false,
                    },
                }],
            );
            let mut imports = HashMap::new();
            for who in ["b", "c"] {
                imports.insert(
                    tid(who),
                    vec![Import {
                        kind: ShareKind::Stream,
                        from: tid("a"),
                        remote: "orders".to_string(),
                        local: "partner".to_string(),
                    }],
                );
            }
            SharingRegistry::new(exports, imports)
        };
        // Named only `b`: `c` (also importing) is denied — default-deny for the non-listed tenant.
        let named = mk(Audience::Tenants([tid("b")].into_iter().collect()));
        assert!(matches!(
            named.resolve_stream(&tid("b"), "partner", Access::Subscribe),
            Resolution::Crossed { .. }
        ));
        assert_eq!(
            named.resolve_stream(&tid("c"), "partner", Access::Subscribe),
            Resolution::Denied
        );
        // Public admits both.
        let public = mk(Audience::Public);
        assert!(matches!(
            public.resolve_stream(&tid("c"), "partner", Access::Subscribe),
            Resolution::Crossed { .. }
        ));
    }

    #[test]
    fn a_non_imported_name_stays_in_the_importers_own_namespace() {
        let reg = subject_sub_registry();
        // b names something with no import alias → phase-1 own-namespace resolution.
        assert_eq!(
            reg.resolve_subject(&tid("b"), "internal.metrics", Access::Subscribe),
            Resolution::Own
        );
        assert_eq!(
            reg.resolve_stream(&tid("b"), "my-own-stream", Access::Publish),
            Resolution::Own
        );
        // And a tenant with no imports at all is always Own (the fast path).
        assert_eq!(
            reg.resolve_stream(&tid("z"), "anything", Access::Publish),
            Resolution::Own
        );
    }

    #[test]
    fn stream_import_exact_and_bidirectional_direction() {
        let mut exports = HashMap::new();
        exports.insert(
            tid("a"),
            vec![Export {
                kind: ShareKind::Stream,
                name: "orders".to_string(),
                audience: Audience::Public,
                direction: GrantDirection {
                    subscribe: true,
                    publish: true,
                },
            }],
        );
        let mut imports = HashMap::new();
        imports.insert(
            tid("b"),
            vec![Import {
                kind: ShareKind::Stream,
                from: tid("a"),
                remote: "orders".to_string(),
                local: "partner-orders".to_string(),
            }],
        );
        let reg = SharingRegistry::new(exports, imports);
        // Exact alias → exporter's exact stream, both directions.
        for access in [Access::Subscribe, Access::Publish] {
            assert_eq!(
                reg.resolve_stream(&tid("b"), "partner-orders", access),
                Resolution::Crossed {
                    owner: tid("a"),
                    scoped: "a/orders".to_string(),
                }
            );
        }
        // A near-miss on the exact stream alias is NOT an alias → own namespace.
        assert_eq!(
            reg.resolve_stream(&tid("b"), "partner-orders-x", Access::Subscribe),
            Resolution::Own
        );
    }

    #[test]
    fn two_importers_of_the_same_export_are_independent() {
        let mut exports = HashMap::new();
        exports.insert(
            tid("a"),
            vec![Export {
                kind: ShareKind::Stream,
                name: "feed".to_string(),
                audience: Audience::Public,
                direction: GrantDirection {
                    subscribe: true,
                    publish: false,
                },
            }],
        );
        let mut imports = HashMap::new();
        imports.insert(
            tid("b"),
            vec![Import {
                kind: ShareKind::Stream,
                from: tid("a"),
                remote: "feed".to_string(),
                local: "b-feed".to_string(),
            }],
        );
        imports.insert(
            tid("c"),
            vec![Import {
                kind: ShareKind::Stream,
                from: tid("a"),
                remote: "feed".to_string(),
                local: "c-feed".to_string(),
            }],
        );
        let reg = SharingRegistry::new(exports, imports);
        // Both resolve to the SAME exporter stream under their OWN alias — independent aliases, one
        // shared source.
        assert_eq!(
            reg.resolve_stream(&tid("b"), "b-feed", Access::Subscribe),
            Resolution::Crossed {
                owner: tid("a"),
                scoped: "a/feed".to_string()
            }
        );
        assert_eq!(
            reg.resolve_stream(&tid("c"), "c-feed", Access::Subscribe),
            Resolution::Crossed {
                owner: tid("a"),
                scoped: "a/feed".to_string()
            }
        );
        // b's alias is meaningless for c and vice-versa.
        assert_eq!(
            reg.resolve_stream(&tid("c"), "b-feed", Access::Subscribe),
            Resolution::Own
        );
    }

    #[test]
    fn validators_are_fail_closed() {
        assert!(validate_share_subject("orders.*", true).is_ok());
        assert!(validate_share_subject("orders.>", true).is_ok());
        assert!(validate_share_subject("orders.>.tail", true).is_err()); // `>` not last
        assert!(validate_share_subject("orders.*", false).is_err()); // no wildcards in an alias
        assert!(validate_share_subject("a..b", true).is_err()); // empty token
        assert!(validate_share_subject("a/b", true).is_err()); // `/` forbidden
        assert!(validate_share_subject("partner.orders", false).is_ok());
        assert!(validate_share_stream("orders").is_ok());
        assert!(validate_share_stream("a/b").is_err());
        assert!(validate_share_stream("a*").is_err());
        assert!(validate_share_stream("").is_err());
    }
}
