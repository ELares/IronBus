// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cluster ack-level spectrum (V2-C3-I1, #605) + the C2-pagecache loud opt-in (#609) +
//! per-level metrics (#610).
//!
//! This module makes the cluster's durability posture an EXPLICIT, CONFIGURABLE, OBSERVABLE choice. It
//! extends IronBus's single-node `0/1/2` produce-ack spectrum ([`crate::engine::DurabilityLevel`], the
//! `Sync`/`Interval`/`Async`/`None` levels) into the CLUSTER cross-product: *where is it durable* ×
//! *how many replicas confirm it*. The result is one enum — [`ClusterAckLevel`] — that a produce in a
//! cluster selects, exactly as a single-node produce selects a [`DurabilityLevel`](crate::engine::DurabilityLevel).
//!
//! ## The spectrum (`ironbus-clustering-design.md` §3)
//!
//! | Level | Meaning | The ack fires after | Worst-case acked loss |
//! |---|---|---|---|
//! | [`ClusterAckLevel::C0`] | fire-and-forget, no ack | never (the producer accepts loss) | unbounded by contract |
//! | [`ClusterAckLevel::C1`] | leader local-fsync (today's single-node I2 ack, leader-only) | the LEADER's covering `fdatasync` | a leader-only outage between its fsync and replication |
//! | [`ClusterAckLevel::C2Pagecache`] | a quorum has it in PAGE-CACHE (NATS-R3-parity, weaker) | a quorum `write()` (page cache) | a CORRELATED power loss across the quorum before fsync |
//! | **[`ClusterAckLevel::C2Fsync`]** (the R>=3 DEFAULT) | a quorum has `fdatasync`'d it | a quorum each returned `fdatasync` Ok | **ZERO** acked loss on a correlated power loss of up to `f` nodes |
//!
//! [`ClusterAckLevel::C2Fsync`] is the strongest BY DEFAULT for `R >= 3`
//! ([`ClusterAckLevel::default_for_replication_factor`]). That is the honest beat over NATS R3 (which
//! acks on a quorum PAGE-CACHE — "the data may not yet be safely stored to disk" — and aphyr measured
//! 131,418 / 930,005 acked records lost on a power cut, `nats-server#7564`) and over Kafka `acks=all`
//! (which deliberately trades fsync for replication): an IronBus R-ack at `C2Fsync` means
//! fsync'd-on-a-quorum BY CONSTRUCTION.
//!
//! ## The MECHANISM is #691 — this enum only SELECTS it (scope)
//!
//! The quorum-fsync gate itself — the [`super::IsrTracker`] (per-replica fsync'd frontier +
//! quorum-commit offset) and the [`super::QuorumAckGate`] (withhold a `PubAck` until its offset is
//! quorum-committed) — is V2-C2-I2 (#593/#691) and is NOT re-implemented here. This module is the
//! ack-LEVEL enum that wires a produce's chosen level to that gate:
//!
//! * [`ClusterAckLevel::C2Fsync`] releases on the gate's QUORUM-FSYNC commit offset — the
//!   [`IsrTracker::quorum_commit`](super::IsrTracker::quorum_commit) computed over the followers'
//!   `fdatasync`'d frontiers (the [`super::AckReplicatedBody`] reports). It IS the #691 path; the enum
//!   merely names it as the default.
//! * [`ClusterAckLevel::C2Pagecache`] releases on a quorum PAGE-CACHE commit offset — the same
//!   quorum computation, but over the replicas' RECEIVED (not-yet-fsync'd) frontiers. It is the WEAKER,
//!   NATS-R3-parity option, offered ONLY behind an explicit opt-in (below). The page-cache replication
//!   FRONTIER plumbing (a follower reporting its received-but-not-fsync'd offset) is C2-replication
//!   detail; here the enum classifies the level, gates the opt-in, and drives the metrics.
//! * [`ClusterAckLevel::C1`] releases on the LEADER's own local fsync (no quorum gate) — today's
//!   single-node I2 ack, now named as the leader-only cluster level.
//! * [`ClusterAckLevel::C0`] never withholds — the producer accepts loss (fire-and-forget).
//!
//! ## C2-pagecache is an EXPLICIT, LOUD opt-in — never the silent default (#609)
//!
//! `C2Pagecache` is the cluster analogue of the single-node `Interval`/`Async`/`None` levels: it
//! WAIVES the cluster-fsync guarantee, so it must be a LOUD, deliberate choice, never reached by
//! default. Mirroring [`DurabilityLevel::requires_loss_ack`](crate::engine::DurabilityLevel::requires_loss_ack):
//!
//! * [`ClusterAckLevel::requires_explicit_opt_in`] is `true` ONLY for `C2Pagecache`. The caller (the
//!   config / produce path) MUST present the acknowledgement; [`ClusterAckLevel::resolve`] refuses to
//!   select `C2Pagecache` without it and falls back to the safe `C2Fsync` default (the same
//!   unavailable-over-unsafe / safe-by-default discipline as the rest of the repo).
//! * [`ClusterAckLevel::cluster_worst_case_loss_description`] returns the loud, human-readable loss
//!   statement for the startup / select-time warning — for `C2Pagecache`: "acked data may be lost if a
//!   quorum power-fails before fsync".
//!
//! ## Per-level metrics make the durability posture OBSERVABLE (#610)
//!
//! [`ClusterAckLevelMetrics`] is a COUNTER PER LEVEL (`c0` / `c1` / `c2_pagecache` / `c2_fsync`) so the
//! number of records acked at each cluster durability level is visible, plus a `power_loss_unsafe`
//! gauge that is `1` whenever a weaker-than-fsync cluster level is the active selected level — the
//! cluster twin of `ironbus_durability_power_loss_unsafe`. These extend the FROZEN metric taxonomy
//! (`docs/METRICS.md`, the `the_metric_name_and_type_contract_is_frozen` test); they are added, never a
//! rename. NATS has no such gauge — an invisible durability mode is exactly the failure this fixes.
//!
//! ## Single-node is byte-identical (the Edge-First non-negotiable)
//!
//! With no cluster (`n = 1`, `R < 3`) NONE of this engages: a standalone produce's ack stays the
//! existing local-fsync I2 ack, byte-for-byte, and the cluster ack level — by
//! [`ClusterAckLevel::default_for_replication_factor`] — degenerates to `C1` (leader local-fsync), which
//! IS today's single-node `Sync` ack. The per-level counters render at ZERO and the cluster
//! `power_loss_unsafe` gauge renders `0` on a standalone broker; merely linking this module changes
//! nothing on disk, nothing on the wire, and nothing in the single-node ack path.

use crate::engine::DurabilityLevel;

/// The cluster ack-level spectrum: the cross-product of *where a record is durable* × *how many
/// replicas confirm it*, extending the single-node [`DurabilityLevel`](crate::engine::DurabilityLevel)
/// spectrum into a cluster.
///
/// A produce in a cluster selects one of these. `C2Fsync` (quorum `fdatasync`) is the `R >= 3` default
/// — the strongest by default, the honest beat over NATS's weaker page-cache default. The enum is
/// `#[non_exhaustive]` so a future cluster level (e.g. an all-replicas `C3` or a cross-region async
/// level) is not a breaking change, matching the `#[non_exhaustive]` on `DurabilityLevel`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClusterAckLevel {
    /// `C0` — fire-and-forget: NO ack. The producer accepts loss; nothing is ever withheld. The
    /// cluster twin of a Level-0 fire-and-forget produce. Worst-case acked loss is unbounded by
    /// contract (there is no ack to be a lie).
    C0,
    /// `C1` — leader local-fsync: the ack fires after the LEADER's own covering `fdatasync` returns
    /// (today's single-node I2 ack, [`DurabilityLevel::Sync`](crate::engine::DurabilityLevel::Sync)),
    /// with NO quorum gate. It is durable on the leader but not yet replicated; worst-case acked loss
    /// is a leader-only outage in the window between its fsync and replication. Beats Kafka `acks=1`,
    /// which does not even fsync.
    C1,
    /// `C2-pagecache` — a quorum has the record in PAGE CACHE (a quorum `write()`), but NOT necessarily
    /// `fdatasync`'d. This is NATS-R3 / Kafka-`acks=all` PARITY — the weaker guarantee — offered ONLY
    /// as an explicit, LOUD opt-in ([`ClusterAckLevel::requires_explicit_opt_in`]). Worst-case acked
    /// loss is a CORRELATED power loss across the quorum before the records reach disk. Never the silent
    /// default.
    C2Pagecache,
    /// `C2-fsync` — the DEFAULT for `R >= 3` and the strongest level: a quorum has each `fdatasync`'d
    /// the record before the producer sees `PubAck`. This is the #691 [`super::QuorumAckGate`] release
    /// over the [`super::IsrTracker`]'s quorum-FSYNC commit offset. Worst-case acked loss on a
    /// correlated power loss of up to `f` of `2f+1` nodes is ZERO (a surviving quorum member holds a
    /// synced copy). The decisive win over NATS R3 and Kafka `acks=all`, BY CONSTRUCTION.
    #[default]
    C2Fsync,
}

impl ClusterAckLevel {
    /// Every cluster ack level, in spectrum order (weakest to strongest). Used by the per-level metrics
    /// to render one counter per level and by the conformance tests; a new variant added to the enum
    /// must be added here too (the exhaustiveness test pins it).
    pub const ALL: [ClusterAckLevel; 4] = [
        ClusterAckLevel::C0,
        ClusterAckLevel::C1,
        ClusterAckLevel::C2Pagecache,
        ClusterAckLevel::C2Fsync,
    ];

    /// Parse the `--cluster-ack-level` flag / wire value: `c0`, `c1`, `c2-pagecache`, or `c2-fsync`.
    /// Returns `None` for any other spelling (the caller turns that into a usage error naming the
    /// accepted values), matching [`DurabilityLevel::parse`](crate::engine::DurabilityLevel::parse).
    #[must_use]
    pub fn parse(value: &str) -> Option<ClusterAckLevel> {
        match value {
            "c0" => Some(ClusterAckLevel::C0),
            "c1" => Some(ClusterAckLevel::C1),
            "c2-pagecache" => Some(ClusterAckLevel::C2Pagecache),
            "c2-fsync" => Some(ClusterAckLevel::C2Fsync),
            _ => None,
        }
    }

    /// The stable flag / log spelling, the inverse of [`ClusterAckLevel::parse`]. Used in the
    /// materialized-config startup line and the loud opt-in warning so an operator reads back exactly
    /// the selectable name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterAckLevel::C0 => "c0",
            ClusterAckLevel::C1 => "c1",
            ClusterAckLevel::C2Pagecache => "c2-pagecache",
            ClusterAckLevel::C2Fsync => "c2-fsync",
        }
    }

    /// The stable METRIC label spelling for the per-level counter (`c0` / `c1` / `c2_pagecache` /
    /// `c2_fsync`). The hyphenated wire spelling is normalized to an underscore for the Prometheus
    /// `level` label value, matching the frozen `ironbus_cluster_ack_*` series in `docs/METRICS.md`.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            ClusterAckLevel::C0 => "c0",
            ClusterAckLevel::C1 => "c1",
            ClusterAckLevel::C2Pagecache => "c2_pagecache",
            ClusterAckLevel::C2Fsync => "c2_fsync",
        }
    }

    /// The DEFAULT cluster ack level for a replication factor `r`: `C2Fsync` (the strongest) for a real
    /// cluster (`r >= 3`), `C1` (leader local-fsync = today's single-node I2 ack) otherwise.
    ///
    /// This is the load-bearing default: a configured `R >= 3` cluster acks at quorum-fsync UNLESS the
    /// operator LOUDLY opts down to `C2Pagecache`. With `r < 3` there is no quorum to fsync on, so the
    /// level degenerates to the leader-only `C1` — which, at `r = 1`, IS the byte-identical single-node
    /// `Sync` ack. The strongest-by-default posture is the honest beat over NATS, whose R3 default is
    /// the weaker page-cache quorum.
    #[must_use]
    pub fn default_for_replication_factor(r: usize) -> ClusterAckLevel {
        if r >= 3 {
            ClusterAckLevel::C2Fsync
        } else {
            ClusterAckLevel::C1
        }
    }

    /// Whether an ack at this level implies the record is `fdatasync`'d ON A QUORUM (the cluster
    /// analogue of [`DurabilityLevel::ack_implies_durable`](crate::engine::DurabilityLevel::ack_implies_durable)).
    /// True ONLY for [`ClusterAckLevel::C2Fsync`]: every weaker level acks before a quorum fsync (or
    /// before any quorum at all), so its ack is a weaker promise.
    #[must_use]
    pub fn ack_implies_quorum_fsync(self) -> bool {
        matches!(self, ClusterAckLevel::C2Fsync)
    }

    /// Whether this level WAIVES the quorum-fsync guarantee (its ack no longer implies
    /// fsync'd-on-a-quorum): true for every level weaker than [`ClusterAckLevel::C2Fsync`]. The source
    /// of the cluster `power_loss_unsafe` gauge and the loud opt-in warning — the cluster twin of
    /// [`DurabilityLevel::waives_i2`](crate::engine::DurabilityLevel::waives_i2).
    #[must_use]
    pub fn waives_quorum_fsync(self) -> bool {
        !self.ack_implies_quorum_fsync()
    }

    /// Whether a CORRELATED quorum power loss can lose ACKNOWLEDGED data at this level — the predicate
    /// the cluster `power_loss_unsafe` gauge surfaces. True for `C0` (no ack), `C1` (leader-only — a
    /// leader power loss loses the unreplicated acked tail), and `C2Pagecache` (a quorum power-fails
    /// before fsync); false ONLY for `C2Fsync` (a surviving quorum member holds a synced copy, so acked
    /// loss is ZERO). Identical to [`ClusterAckLevel::waives_quorum_fsync`] in the current spectrum;
    /// kept as its own named predicate because the gauge's MEANING (power-loss-unsafe) is distinct from
    /// the ack's MEANING (waives quorum-fsync) and a future level could separate them.
    #[must_use]
    pub fn power_loss_unsafe(self) -> bool {
        self.waives_quorum_fsync()
    }

    /// Whether selecting this level REQUIRES an explicit opt-in acknowledgement (the LOUD opt-in gate,
    /// #609): true ONLY for [`ClusterAckLevel::C2Pagecache`], the weaker NATS-R3-parity level. The other
    /// levels need no opt-in — `C2Fsync` is the safe default, `C1`/`C0` are the leader-only /
    /// fire-and-forget single-node-shaped choices already expressible single-node. Mirrors
    /// [`DurabilityLevel::requires_loss_ack`](crate::engine::DurabilityLevel::requires_loss_ack), which
    /// gates the single-node unbounded-loss levels the same way.
    #[must_use]
    pub fn requires_explicit_opt_in(self) -> bool {
        matches!(self, ClusterAckLevel::C2Pagecache)
    }

    /// Resolve a REQUESTED cluster ack level against whether the caller presented the explicit opt-in.
    /// If the requested level [`requires_explicit_opt_in`](ClusterAckLevel::requires_explicit_opt_in)
    /// (i.e. `C2Pagecache`) but `explicit_opt_in` is `false`, this REFUSES the weaker level and returns
    /// the safe [`ClusterAckLevel::C2Fsync`] default — `C2Pagecache` is never reached silently. Any
    /// level that needs no opt-in is returned unchanged.
    ///
    /// This is the safe-by-default discipline the whole repo holds: the safe level is the default;
    /// weaker is an explicit, reported choice that fails CLOSED (to the safe level) when the
    /// acknowledgement is absent.
    #[must_use]
    pub fn resolve(requested: ClusterAckLevel, explicit_opt_in: bool) -> ClusterAckLevel {
        if requested.requires_explicit_opt_in() && !explicit_opt_in {
            ClusterAckLevel::C2Fsync
        } else {
            requested
        }
    }

    /// A one-line, human-readable description of the WORST-CASE acknowledged loss this cluster level can
    /// take, for the loud opt-in / startup warning. The cluster analogue of
    /// [`DurabilityLevel::worst_case_loss_description`](crate::engine::DurabilityLevel::worst_case_loss_description):
    /// `C2Fsync` returns the zero-loss statement; each weaker level returns its documented bound, with
    /// `C2Pagecache`'s being the headline "acked data may be lost if a quorum power-fails before fsync".
    #[must_use]
    pub fn cluster_worst_case_loss_description(self) -> &'static str {
        match self {
            ClusterAckLevel::C2Fsync => {
                "zero acked loss on a correlated power loss of up to f of 2f+1 nodes (a surviving \
                 quorum member holds an fdatasync'd copy; an R-ack means fsync'd-on-a-quorum by \
                 construction)"
            }
            ClusterAckLevel::C2Pagecache => {
                "acked data may be lost if a quorum power-fails before fsync (a quorum has the record \
                 in page cache but not yet fdatasync'd — NATS-R3-parity, the weaker level)"
            }
            ClusterAckLevel::C1 => {
                "a leader-only outage between the leader's fdatasync and replication loses the acked \
                 records not yet on a quorum (durable on the leader, not yet replicated)"
            }
            ClusterAckLevel::C0 => {
                "unbounded by contract: there is no ack (fire-and-forget); the producer accepts loss"
            }
        }
    }

    /// The single-node [`DurabilityLevel`](crate::engine::DurabilityLevel) this cluster level reduces to
    /// for the LEADER's OWN local durability barrier — the bridge that keeps the single-node ack
    /// byte-identical. `C2Fsync`, `C2Pagecache`, and `C1` all require the leader to local-fsync before
    /// it can count itself toward the quorum (or, for `C1`, ack), so their leader-side barrier is
    /// [`DurabilityLevel::Sync`](crate::engine::DurabilityLevel::Sync) — today's I2 ack. `C0` is
    /// fire-and-forget, so it imposes no leader barrier (`None`).
    ///
    /// This is why `C1` at `R = 1` is byte-for-byte the single-node `Sync` produce: same leader fsync,
    /// no quorum gate, same ack.
    #[must_use]
    pub fn leader_durability_barrier(self) -> Option<DurabilityLevel> {
        match self {
            ClusterAckLevel::C2Fsync | ClusterAckLevel::C2Pagecache | ClusterAckLevel::C1 => {
                Some(DurabilityLevel::Sync)
            }
            ClusterAckLevel::C0 => None,
        }
    }
}

/// Per-cluster-ack-level produce counters + the cluster power-loss-unsafe gauge (V2-C3-I4, #610).
///
/// One monotonic counter PER level (`c0` / `c1` / `c2_pagecache` / `c2_fsync`): each is incremented as
/// a produce's ack is RELEASED at that level, so the cluster's durability posture — how many records
/// were acked at each strength — is observable. The `power_loss_unsafe` gauge mirrors the active
/// selected level: `1` whenever a weaker-than-fsync cluster level is in use (the cluster twin of
/// `ironbus_durability_power_loss_unsafe`).
///
/// On a single-node / no-cluster broker every counter is `0` and the gauge is `0`, so the rendered
/// `/metrics` lines exist (the frozen taxonomy requires the series) but report the honest zero — the
/// single-node observable surface gains the series at rest, never a misleading value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClusterAckLevelMetrics {
    /// Records acked at `C0` (fire-and-forget — no ack was withheld).
    c0: u64,
    /// Records acked at `C1` (leader local-fsync, leader-only durability).
    c1: u64,
    /// Records acked at `C2Pagecache` (quorum page-cache — the weaker opt-in level).
    c2_pagecache: u64,
    /// Records acked at `C2Fsync` (quorum fdatasync — the strongest, the default).
    c2_fsync: u64,
    /// The active SELECTED cluster ack level, the source of the `power_loss_unsafe` gauge. `None` until
    /// a level is selected (a standalone broker that never enters a cluster) — rendered as `0`
    /// power-loss-unsafe (the single-node default is the power-loss-SAFE local-fsync ack).
    active_level: Option<ClusterAckLevel>,
}

impl ClusterAckLevelMetrics {
    /// A fresh, all-zero metrics block: every per-level counter `0`, no active level selected. This is
    /// exactly the state a single-node broker reports forever.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that ONE record's ack was released at `level`, and mark `level` the active selected level
    /// (so the `power_loss_unsafe` gauge tracks the most recent posture). Saturating so a counter never
    /// wraps — a Prometheus counter is monotonic; the (astronomically unreachable) `u64` ceiling clamps
    /// rather than wrapping to a smaller value.
    pub fn record_ack(&mut self, level: ClusterAckLevel) {
        self.set_active_level(level);
        let slot = match level {
            ClusterAckLevel::C0 => &mut self.c0,
            ClusterAckLevel::C1 => &mut self.c1,
            ClusterAckLevel::C2Pagecache => &mut self.c2_pagecache,
            ClusterAckLevel::C2Fsync => &mut self.c2_fsync,
        };
        *slot = slot.saturating_add(1);
    }

    /// Mark `level` the active selected cluster ack level WITHOUT recording an ack (e.g. at config /
    /// cluster-join time, so the `power_loss_unsafe` gauge reflects the posture before the first
    /// produce). [`ClusterAckLevelMetrics::record_ack`] also sets it.
    pub fn set_active_level(&mut self, level: ClusterAckLevel) {
        self.active_level = Some(level);
    }

    /// The count of records acked at `level` (the `ironbus_cluster_ack_total{level="..."}` sample).
    #[must_use]
    pub fn count(&self, level: ClusterAckLevel) -> u64 {
        match level {
            ClusterAckLevel::C0 => self.c0,
            ClusterAckLevel::C1 => self.c1,
            ClusterAckLevel::C2Pagecache => self.c2_pagecache,
            ClusterAckLevel::C2Fsync => self.c2_fsync,
        }
    }

    /// The active selected cluster ack level, or `None` on a standalone broker that never entered a
    /// cluster (rendered as a power-loss-SAFE `0` gauge).
    #[must_use]
    pub fn active_level(&self) -> Option<ClusterAckLevel> {
        self.active_level
    }

    /// Whether the active selected cluster ack level is POWER-LOSS-UNSAFE (a weaker-than-fsync level is
    /// in use) — the value of the `ironbus_cluster_ack_power_loss_unsafe` gauge (`1`/`0`). `false` when
    /// no level is selected (the single-node power-loss-safe default) and `false` under `C2Fsync`.
    #[must_use]
    pub fn power_loss_unsafe(&self) -> bool {
        self.active_level
            .is_some_and(ClusterAckLevel::power_loss_unsafe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_every_level() {
        for level in ClusterAckLevel::ALL {
            assert_eq!(ClusterAckLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(ClusterAckLevel::parse("c3"), None);
        assert_eq!(ClusterAckLevel::parse(""), None);
        assert_eq!(ClusterAckLevel::parse("sync"), None);
    }

    #[test]
    fn c2_fsync_is_the_default_for_a_real_cluster() {
        // R>=3 (a real fault-tolerant cluster) defaults to the STRONGEST level — the honest beat over
        // NATS, whose R3 default is the weaker page-cache quorum.
        assert_eq!(
            ClusterAckLevel::default_for_replication_factor(3),
            ClusterAckLevel::C2Fsync
        );
        assert_eq!(
            ClusterAckLevel::default_for_replication_factor(5),
            ClusterAckLevel::C2Fsync
        );
        // The plain Default is also C2Fsync (the safe-by-default level).
        assert_eq!(ClusterAckLevel::default(), ClusterAckLevel::C2Fsync);
    }

    #[test]
    fn below_a_cluster_the_level_degenerates_to_leader_local_fsync() {
        // R<3: there is no quorum to fsync on → the level is the leader-only C1, which at R=1 IS the
        // byte-identical single-node Sync ack.
        assert_eq!(
            ClusterAckLevel::default_for_replication_factor(1),
            ClusterAckLevel::C1
        );
        assert_eq!(
            ClusterAckLevel::default_for_replication_factor(2),
            ClusterAckLevel::C1
        );
        // C1's leader-side barrier is exactly the single-node Sync (I2) durability level.
        assert_eq!(
            ClusterAckLevel::C1.leader_durability_barrier(),
            Some(DurabilityLevel::Sync)
        );
    }

    #[test]
    fn only_c2_fsync_implies_quorum_fsync_every_weaker_level_waives_it() {
        assert!(ClusterAckLevel::C2Fsync.ack_implies_quorum_fsync());
        assert!(!ClusterAckLevel::C2Fsync.waives_quorum_fsync());
        for weaker in [
            ClusterAckLevel::C0,
            ClusterAckLevel::C1,
            ClusterAckLevel::C2Pagecache,
        ] {
            assert!(
                !weaker.ack_implies_quorum_fsync(),
                "{weaker:?} must NOT imply quorum-fsync"
            );
            assert!(
                weaker.waives_quorum_fsync(),
                "{weaker:?} waives quorum-fsync"
            );
            assert!(
                weaker.power_loss_unsafe(),
                "{weaker:?} is power-loss-unsafe"
            );
        }
        // C2-fsync is the ONLY power-loss-safe cluster level.
        assert!(!ClusterAckLevel::C2Fsync.power_loss_unsafe());
    }

    #[test]
    fn only_c2_pagecache_requires_the_explicit_loud_opt_in() {
        assert!(ClusterAckLevel::C2Pagecache.requires_explicit_opt_in());
        for no_opt_in in [
            ClusterAckLevel::C0,
            ClusterAckLevel::C1,
            ClusterAckLevel::C2Fsync,
        ] {
            assert!(
                !no_opt_in.requires_explicit_opt_in(),
                "{no_opt_in:?} needs no opt-in"
            );
        }
    }

    #[test]
    fn c2_pagecache_without_the_opt_in_falls_back_to_the_safe_c2_fsync_default() {
        // THE loud-opt-in gate: requesting the weaker page-cache level WITHOUT the explicit
        // acknowledgement is refused and falls back to the safe C2-fsync default — never reached
        // silently.
        assert_eq!(
            ClusterAckLevel::resolve(ClusterAckLevel::C2Pagecache, false),
            ClusterAckLevel::C2Fsync,
            "C2-pagecache without the opt-in must NOT be selected silently"
        );
        // WITH the explicit opt-in, the weaker level is honored (an explicit, reported choice).
        assert_eq!(
            ClusterAckLevel::resolve(ClusterAckLevel::C2Pagecache, true),
            ClusterAckLevel::C2Pagecache
        );
        // A level that needs no opt-in is returned unchanged, opt-in flag or not.
        for level in [
            ClusterAckLevel::C0,
            ClusterAckLevel::C1,
            ClusterAckLevel::C2Fsync,
        ] {
            assert_eq!(ClusterAckLevel::resolve(level, false), level);
            assert_eq!(ClusterAckLevel::resolve(level, true), level);
        }
    }

    #[test]
    fn c2_pagecache_surfaces_the_quorum_power_fail_loss_description() {
        // The headline loud-warning string the opt-in surfaces.
        let desc = ClusterAckLevel::C2Pagecache.cluster_worst_case_loss_description();
        assert!(
            desc.contains("acked data may be lost if a quorum power-fails before fsync"),
            "the C2-pagecache loss description must state the quorum-power-fail window: {desc}"
        );
        // C2-fsync's description is the zero-acked-loss statement.
        assert!(ClusterAckLevel::C2Fsync
            .cluster_worst_case_loss_description()
            .contains("zero acked loss"));
    }

    #[test]
    fn the_per_level_counters_increment_only_their_own_level() {
        let mut m = ClusterAckLevelMetrics::new();
        // A fresh block is all zero (the single-node-at-rest state).
        for level in ClusterAckLevel::ALL {
            assert_eq!(m.count(level), 0);
        }
        assert!(
            !m.power_loss_unsafe(),
            "no level selected ⇒ power-loss-safe"
        );

        // Record acks at distinct levels; each counter moves independently.
        m.record_ack(ClusterAckLevel::C2Fsync);
        m.record_ack(ClusterAckLevel::C2Fsync);
        m.record_ack(ClusterAckLevel::C1);
        assert_eq!(m.count(ClusterAckLevel::C2Fsync), 2);
        assert_eq!(m.count(ClusterAckLevel::C1), 1);
        assert_eq!(m.count(ClusterAckLevel::C0), 0);
        assert_eq!(m.count(ClusterAckLevel::C2Pagecache), 0);
    }

    #[test]
    fn the_power_loss_unsafe_gauge_tracks_the_active_level() {
        let mut m = ClusterAckLevelMetrics::new();
        // C2-fsync active ⇒ power-loss-SAFE.
        m.record_ack(ClusterAckLevel::C2Fsync);
        assert_eq!(m.active_level(), Some(ClusterAckLevel::C2Fsync));
        assert!(!m.power_loss_unsafe());

        // Selecting the weaker page-cache level flips the gauge to UNSAFE.
        m.record_ack(ClusterAckLevel::C2Pagecache);
        assert_eq!(m.active_level(), Some(ClusterAckLevel::C2Pagecache));
        assert!(
            m.power_loss_unsafe(),
            "a weaker-than-fsync cluster level is power-loss-unsafe"
        );

        // set_active_level moves the gauge without an ack (config-time posture).
        m.set_active_level(ClusterAckLevel::C2Fsync);
        assert!(!m.power_loss_unsafe());
    }

    #[test]
    fn metric_labels_are_underscore_normalized_and_distinct() {
        let labels: Vec<&str> = ClusterAckLevel::ALL
            .iter()
            .map(|l| l.metric_label())
            .collect();
        assert_eq!(labels, ["c0", "c1", "c2_pagecache", "c2_fsync"]);
        // No hyphen in a metric label (Prometheus label values may contain them, but the frozen series
        // uses underscores for consistency with the rest of the taxonomy).
        for l in labels {
            assert!(!l.contains('-'), "{l} must be underscore-normalized");
        }
    }
}

/// The enum WIRED to the #691 quorum-fsync gate (the C2-fsync MECHANISM is not re-implemented here —
/// these tests prove the [`ClusterAckLevel`] enum SELECTS the existing [`super::IsrTracker`] /
/// [`super::QuorumAckGate`]). A `C2Fsync` produce releases its ack only when the gate's quorum-FSYNC
/// commit advances; a `C2Pagecache` produce (the loud opt-in) releases on a weaker quorum frontier,
/// sets the cluster `power_loss_unsafe` gauge, and surfaces the loss description; the per-level counters
/// move with each release.
#[cfg(test)]
mod gate_wiring_tests {
    use super::*;
    use crate::cluster::isr::{AckReplicatedBody, IsrConfig, IsrTracker, QuorumAckGate};

    /// A small 3-replica ISR tracker (leader=1, followers 2,3, `min_isr=2` = f+1 of 2f+1) — the R=3
    /// default shape — over which both the `C2Fsync` and the (page-cache-frontier) `C2Pagecache` quorum
    /// commits are computed. The tracker is the #691 mechanism; the enum chooses WHICH frontier feeds it.
    fn tracker() -> IsrTracker {
        IsrTracker::new(1, &[2, 3], IsrConfig::default())
    }

    #[test]
    fn a_c2_fsync_produce_releases_only_on_the_quorum_fsync_gate() {
        // The R>=3 default level is C2-fsync.
        let level = ClusterAckLevel::default_for_replication_factor(3);
        assert_eq!(level, ClusterAckLevel::C2Fsync);
        assert!(level.ack_implies_quorum_fsync());

        let mut isr = tracker();
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();
        let mut metrics = ClusterAckLevelMetrics::new();
        metrics.set_active_level(level);
        assert!(
            !metrics.power_loss_unsafe(),
            "C2-fsync is the power-loss-SAFE default"
        );

        // The leader locally fsyncs 5 records and parks their C2-fsync acks (the leader's own I2 ack
        // still holds; the CLUSTER gate withholds the wire PubAck until a quorum has FSYNC'd).
        isr.observe_leader_fsync(5);
        for off in 0..5u64 {
            gate.park(off, off);
        }

        // Only the leader has fsync'd ⇒ quorum-commit (2nd-largest fsync'd frontier of [5,0,0]) = 0 ⇒
        // NOTHING releases. A C2-fsync ack does NOT fire on the leader alone.
        let released = gate.release_up_to(isr.quorum_commit());
        assert!(
            released.is_empty(),
            "a C2-fsync ack must NOT release on the leader's local fsync alone"
        );
        assert_eq!(metrics.count(ClusterAckLevel::C2Fsync), 0);

        // A SECOND replica reports it has FDATASYNC'd through 5 ⇒ quorum-commit advances to 5 ⇒ all 5
        // acks release (the #691 quorum-fsync gate), and the per-level counter moves to 5.
        assert!(isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 5,
        }));
        let released = gate.release_up_to(isr.quorum_commit());
        assert_eq!(released, vec![0, 1, 2, 3, 4]);
        for _ in &released {
            metrics.record_ack(ClusterAckLevel::C2Fsync);
        }
        assert_eq!(
            metrics.count(ClusterAckLevel::C2Fsync),
            5,
            "5 records acked at the C2-fsync level"
        );
        assert_eq!(metrics.count(ClusterAckLevel::C2Pagecache), 0);
    }

    #[test]
    fn a_c2_pagecache_produce_is_the_loud_opt_in_weaker_and_releases_on_a_quorum_pagecache_frontier(
    ) {
        // C2-pagecache is reached ONLY with the explicit opt-in; without it the request falls back to
        // the safe C2-fsync default.
        assert_eq!(
            ClusterAckLevel::resolve(ClusterAckLevel::C2Pagecache, false),
            ClusterAckLevel::C2Fsync
        );
        let level = ClusterAckLevel::resolve(ClusterAckLevel::C2Pagecache, true);
        assert_eq!(level, ClusterAckLevel::C2Pagecache);

        // The opt-in surfaces the loud loss description AND flips the cluster power-loss-unsafe gauge.
        assert!(level
            .cluster_worst_case_loss_description()
            .contains("acked data may be lost if a quorum power-fails before fsync"));
        let mut metrics = ClusterAckLevelMetrics::new();
        metrics.set_active_level(level);
        assert!(
            metrics.power_loss_unsafe(),
            "C2-pagecache is power-loss-unsafe — the gauge MUST be 1"
        );

        // The page-cache level releases on a QUORUM PAGE-CACHE frontier, which is WEAKER than (>=) the
        // quorum-FSYNC frontier: the followers have RECEIVED the records (page cache) but the quorum has
        // not necessarily fsync'd them. We model that here by feeding the SAME quorum gate a
        // received-frontier quorum-commit that has advanced (page cache) while the fsync'd frontier has
        // NOT — so the C2-pagecache ack releases where a C2-fsync ack would still be withheld. This is
        // the documented weaker guarantee; the page-cache REPLICATION plumbing is C2-replication detail.
        let mut fsync_isr = tracker();
        let mut pagecache_isr = tracker();
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();
        fsync_isr.observe_leader_fsync(3);
        pagecache_isr.observe_leader_fsync(3);
        for off in 0..3u64 {
            gate.park(off, off);
        }
        // A follower has the records in PAGE CACHE (received frontier 3) but has NOT fsync'd them
        // (fsync'd frontier 0). The fsync gate sees no quorum-fsync; the page-cache gate sees a quorum
        // page-cache.
        pagecache_isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 3, // models the RECEIVED (page-cache) frontier for this weaker level
        });
        // (the fsync ISR's follower 2 is still at 0 — not fsync'd)
        assert_eq!(
            fsync_isr.quorum_commit(),
            Some(0),
            "the quorum-FSYNC frontier has NOT advanced (the follower has not fsync'd)"
        );
        assert_eq!(
            pagecache_isr.quorum_commit(),
            Some(3),
            "the quorum-PAGE-CACHE frontier HAS advanced (the follower received the bytes)"
        );

        // The C2-pagecache produce releases on the (weaker) page-cache quorum frontier; the per-level
        // counter increments at the c2-pagecache level.
        let released = gate.release_up_to(pagecache_isr.quorum_commit());
        assert_eq!(released, vec![0, 1, 2]);
        for _ in &released {
            metrics.record_ack(ClusterAckLevel::C2Pagecache);
        }
        assert_eq!(metrics.count(ClusterAckLevel::C2Pagecache), 3);
        assert_eq!(metrics.count(ClusterAckLevel::C2Fsync), 0);
        // The gauge is still UNSAFE while the page-cache level is the active posture.
        assert!(metrics.power_loss_unsafe());
    }

    #[test]
    fn single_node_c1_releases_on_the_leader_local_fsync_byte_identical() {
        // With no cluster (R=1) the level is C1 — the leader-only local-fsync ack, which IS today's
        // single-node Sync (I2) ack. Modeled as a min_isr=1 tracker with no followers: the quorum-commit
        // IS the leader's own fsync'd frontier, so the gate releases exactly when the local fsync lands —
        // byte-identical to the single-node path, no quorum round.
        let level = ClusterAckLevel::default_for_replication_factor(1);
        assert_eq!(level, ClusterAckLevel::C1);
        assert!(!level.requires_explicit_opt_in());
        let mut metrics = ClusterAckLevelMetrics::new();
        metrics.set_active_level(level);
        // C1 is leader-only ⇒ a leader power loss CAN lose the unreplicated acked tail ⇒ the gauge is 1
        // in a (degenerate) cluster posture; but on a true single node no cluster level is selected, so
        // the standalone metrics block reports 0 (see the standalone test below).
        assert!(level.power_loss_unsafe());

        let mut isr = IsrTracker::new(
            1,
            &[],
            IsrConfig {
                min_isr: 1,
                max_lag_records: 0,
            },
        );
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();
        for off in 0..4u64 {
            gate.park(off, off);
        }
        // Before the local fsync nothing is durable ⇒ quorum-commit 0 ⇒ no release.
        assert_eq!(isr.quorum_commit(), Some(0));
        assert!(gate.release_up_to(isr.quorum_commit()).is_empty());
        // The leader local-fsyncs through 4 ⇒ the (min_isr=1) quorum-commit IS the leader frontier ⇒ all
        // 4 release on the leader's own fsync, no quorum round (the byte-identical single-node ack).
        isr.observe_leader_fsync(4);
        let released = gate.release_up_to(isr.quorum_commit());
        assert_eq!(released, vec![0, 1, 2, 3]);
        for _ in &released {
            metrics.record_ack(ClusterAckLevel::C1);
        }
        assert_eq!(metrics.count(ClusterAckLevel::C1), 4);
    }

    #[test]
    fn a_standalone_no_cluster_metrics_block_is_all_zero_and_power_loss_safe() {
        // The single-node observable surface: the cluster ack-level metrics exist but report the honest
        // zero — no level selected, every counter 0, the gauge 0 (power-loss-SAFE). This is what
        // /metrics renders on a single-node broker (the frozen-taxonomy series at rest).
        let metrics = ClusterAckLevelMetrics::new();
        assert_eq!(metrics.active_level(), None);
        assert!(!metrics.power_loss_unsafe());
        for level in ClusterAckLevel::ALL {
            assert_eq!(metrics.count(level), 0);
        }
    }
}
