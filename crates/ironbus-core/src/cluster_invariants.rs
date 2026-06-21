// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CLUSTER recovery invariant checkers (CI1 to CI4) and the leader-completeness eligibility
//! predicate (V2-C4-I4 / C4-I5, #614 / #615): the cluster analogue of the single-node resilience
//! checkers in `ironbus-storage/src/invariants.rs`, kept here IO-free in `ironbus-core` so the same
//! pure functions run in a unit test, a property sweep, a corpus fixture, AND the cluster runtime.
//!
//! These mirror the I1 to I4 checker STYLE exactly: each checker is a pure function over plain,
//! observable value-types (NOT the heavy `ironbus-server` cluster types — that keeps them in the
//! IO-free core), and each returns the FIRST [`ClusterInvariantViolation`] it finds or `Ok(())`.
//! A checker that wrongly always passes is guarded by the negative fixtures in this module's tests:
//! each checker has a known-bad input it MUST reject, so the checkers themselves are falsifiable.
//!
//! ## The four cluster recovery invariants (ratified by the doc `docs/CLUSTER_INVARIANTS.md`)
//!
//! * **CI1 — cluster durable prefix.** The committed prefix up to the high-watermark (HW) is
//!   IDENTICAL on every in-sync replica; divergence is only ever ABOVE the HW (uncommitted), where
//!   epoch truncation removes it — it is never committed. [`check_cluster_durable_prefix`].
//! * **CI2 — cluster ack implies quorum-fsync.** A released `C2-fsync` ack at offset `o` implies at
//!   least `min_isr` replicas have `fdatasync`'d every offset `<= o` (the #691 quorum-fsync
//!   property). A sub-quorum ack is a violation. [`check_quorum_fsync_ack`].
//! * **CI3 — bounded, reported, repaired divergence.** Detected divergence is bounded (within the
//!   I3 caps), reported (a typed event), and either auto-repaired from the quorum or fails closed —
//!   NEVER silently served and NEVER deletes data (the #697 property). [`check_divergence_handled`].
//! * **CI4 — epoch monotonicity / no stale-leader-commit.** Leadership epochs are monotonic and a
//!   record may not be committed under an epoch older than the cluster-known epoch — a stale leader
//!   cannot commit (the #668 + #614 property). [`check_epoch_monotonic`].
//! * **CI5 — leaderless-node failover preserves committed data + fences the old leader.** On a leader
//!   death the successor promoted from the surviving replicas must be an ISR member, must hold every
//!   offset that was quorum-acked before the death (no committed record is lost on promotion — the
//!   data-plane analogue of CI1 across a leadership change), and must carry a strictly higher epoch so
//!   the old leader is fenced (KIP-101). This is the #618 leaderless-failover property, the data-plane
//!   twin of the #614 leader-completeness restriction. [`check_failover_preserves_committed`].
//!
//! ## The leader-completeness ELIGIBILITY predicate (C4-I4, #614)
//!
//! CI4's "no stale-leader-commit" is enforced at the ELECTION boundary by [`LeaderEligibility`]:
//! when a partition leader is (re)assigned, only a replica that is COMPLETE (holds the committed log
//! to the cluster-known HW), NON-DIVERGENT (no detected fingerprint mismatch), and IN-SYNC (in the
//! ISR) is eligible. A stale/corrupt replica is INELIGIBLE — by construction it can never win
//! leadership, which is the construction that prevents the Jepsen NATS 2.12.1 failure where a corrupt
//! node "managed to become the leader of the cluster despite its corrupt state" and then deleted the
//! stream. The eligibility predicate is the pure function the metadata-plane PLACEMENT consults; the
//! placement/rebalance itself (which eligible replica to pick, and when) is C5 (#616+).
//!
//! These types are IO-free value types: a replica's eligibility inputs are three small numbers/flags
//! (its durable-prefix frontier, the committed HW, an in-ISR flag, and a divergence-detected flag).
//! The `ironbus-server` cluster plane projects its rich state (the [`crate::leader_lease::LeaderEpoch`]
//! ISR membership, the divergence report) onto these inputs and calls these predicates.

use crate::leader_lease::LeaderEpoch;
use std::collections::BTreeMap;

/// A cluster recovery invariant that an observed cluster state violated. The cluster analogue of
/// `ironbus-storage`'s `InvariantViolation` (the single-node I1 to I4 set).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterInvariantViolation {
    /// CI1: two in-sync replicas disagree on a committed offset (an offset at or below the
    /// high-watermark whose record differs between replicas) — the committed prefix is not identical.
    CommittedPrefixDiverges {
        /// The replica node id whose committed prefix disagreed with the reference replica.
        replica: u64,
        /// The first committed offset (at or below the HW) at which the two replicas disagree.
        offset: u64,
    },
    /// CI2: a `C2-fsync` ack was released for an offset that fewer than `min_isr` replicas had
    /// `fdatasync`'d — the ack does NOT imply a quorum fsync (a sub-quorum / page-cache ack).
    SubQuorumAck {
        /// The acked offset whose quorum-fsync condition was not met.
        offset: u64,
        /// How many replicas had `fdatasync`'d this offset (strictly below `min_isr`).
        fsynced_replicas: usize,
        /// The required quorum size.
        min_isr: usize,
    },
    /// CI3: a detected divergence was mishandled — it was silently served, it deleted data, or its
    /// repair exceeded the bounded cap (instead of failing closed).
    DivergenceMishandled {
        /// The id of the divergent segment.
        segment_id: u64,
        /// Why the handling violated the contract.
        reason: DivergenceMishandling,
    },
    /// CI4: a leadership epoch regressed (a non-monotonic epoch sequence), or a record was committed
    /// under an epoch older than the cluster-known epoch (a stale-leader commit).
    EpochRegressed {
        /// The cluster-known (current) epoch that fences the offending epoch.
        current: LeaderEpoch,
        /// The offending (older or regressed) epoch that was observed/committed.
        offending: LeaderEpoch,
    },
    /// CI5: a leaderless-node FAILOVER lost a committed record — the successor leader promoted on a
    /// leader death does NOT hold an offset that was quorum-acked BEFORE the death. The successor must
    /// have been chosen from the ISR (the set that holds every committed record); promoting a replica
    /// missing a committed offset would silently lose acknowledged data. This is the data-plane analogue
    /// of CI1 across a leadership change (the #618 leaderless-failover property, the data-plane twin of
    /// the #614 leader-completeness restriction).
    FailoverLostCommitted {
        /// The successor leader promoted on the old leader's death.
        successor: u64,
        /// The committed offset (quorum-acked before the death) the successor does NOT hold.
        offset: u64,
    },
    /// CI5: a leaderless-node FAILOVER did NOT fence the dead leader — the successor's leadership epoch
    /// did not strictly exceed the dead leader's, so a stale/returning old leader is not fenced
    /// (KIP-101). A failover MUST bump the partition's leader epoch so the old leader can no longer ack
    /// or serve as leader.
    FailoverEpochNotFenced {
        /// The dead leader's epoch at the time of failover.
        dead_epoch: LeaderEpoch,
        /// The successor's epoch (which must strictly exceed `dead_epoch` to fence the old leader).
        successor_epoch: LeaderEpoch,
    },
    /// CI5: a leaderless-node FAILOVER promoted a successor that is NOT in the in-sync replica set — a
    /// non-ISR replica may be missing committed records, so promoting it can lose acknowledged data
    /// (the exact Jepsen failure the #614 restriction forbids, here at failover time). The successor
    /// MUST be an ISR member that already holds the committed log.
    FailoverPromotedNonIsr {
        /// The successor that was promoted despite being out of the ISR.
        successor: u64,
    },
}

/// Why a detected divergence violated CI3 (it was NOT bounded + reported + repaired / fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DivergenceMishandling {
    /// The divergent data was served to a consumer without being detected/repaired first (NATS's
    /// silent-drift class, #5576): a divergence must never be silently served.
    SilentlyServed,
    /// The divergent (e.g. minority-corrupt) data was DELETED rather than quarantined + re-synced
    /// (NATS's permanent-delete class, #7556): a divergence must never delete data.
    DataDeleted,
    /// The repair exceeded the bounded I3 cap but did NOT fail closed (it was neither capped nor
    /// surfaced as a typed error): over-cap repair must fail closed, never proceed unbounded.
    UnboundedRepair {
        /// The bytes the repair would have touched.
        bytes: u64,
        /// The per-event cap it exceeded.
        cap: u64,
    },
}

impl std::fmt::Display for ClusterInvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterInvariantViolation::CommittedPrefixDiverges { replica, offset } => write!(
                f,
                "CI1: in-sync replica {replica} disagrees on committed offset {offset}"
            ),
            ClusterInvariantViolation::SubQuorumAck {
                offset,
                fsynced_replicas,
                min_isr,
            } => write!(
                f,
                "CI2: offset {offset} was acked with only {fsynced_replicas} fsync'd replicas, \
                 below the quorum of {min_isr}"
            ),
            ClusterInvariantViolation::DivergenceMishandled { segment_id, reason } => {
                write!(f, "CI3: divergence on segment {segment_id}: {reason}")
            }
            ClusterInvariantViolation::EpochRegressed { current, offending } => write!(
                f,
                "CI4: epoch {} is stale/regressed against the cluster epoch {}",
                offending.get(),
                current.get()
            ),
            ClusterInvariantViolation::FailoverLostCommitted { successor, offset } => write!(
                f,
                "CI5: failover successor {successor} does not hold committed offset {offset} \
                 (a quorum-acked record was lost on promotion)"
            ),
            ClusterInvariantViolation::FailoverEpochNotFenced {
                dead_epoch,
                successor_epoch,
            } => write!(
                f,
                "CI5: failover did not fence the dead leader: successor epoch {} does not exceed the \
                 dead leader's epoch {} (old leader not fenced)",
                successor_epoch.get(),
                dead_epoch.get()
            ),
            ClusterInvariantViolation::FailoverPromotedNonIsr { successor } => write!(
                f,
                "CI5: failover promoted out-of-ISR replica {successor} (it may be missing committed records)"
            ),
        }
    }
}

impl std::fmt::Display for DivergenceMishandling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DivergenceMishandling::SilentlyServed => {
                write!(f, "served silently without detection/repair")
            }
            DivergenceMishandling::DataDeleted => write!(f, "data was deleted, not quarantined"),
            DivergenceMishandling::UnboundedRepair { bytes, cap } => {
                write!(
                    f,
                    "repair of {bytes} bytes exceeded the {cap}-byte cap unbounded"
                )
            }
        }
    }
}

impl std::error::Error for ClusterInvariantViolation {}

/// One in-sync replica's committed prefix, as a fingerprint per committed offset. The fingerprint is
/// whatever opaque content identity the caller already computes (a per-record CRC, the xxh3 content
/// hash, or the record bytes); equality of fingerprints at an offset means the two replicas hold the
/// SAME committed record there. `prefix[i]` is the fingerprint of committed offset `i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaPrefix {
    /// The replica's cluster node id.
    pub replica: u64,
    /// The replica's per-offset committed fingerprints, offset `0` first. The replica is in-sync, so
    /// this covers the committed prefix up to (at least) the cluster HW.
    pub prefix: Vec<u64>,
}

/// CI1 — cluster durable prefix. The committed prefix (offsets `0..=hw - 1`, i.e. strictly below the
/// HW) is IDENTICAL on every in-sync replica. `replicas` must be non-empty; the first is the
/// reference and every other in-sync replica must match it byte-for-byte over the committed range.
/// Divergence is allowed ONLY above the HW (uncommitted, epoch-truncatable) — this checker never
/// inspects offsets at or above `committed_hw`.
///
/// # Errors
/// Returns [`ClusterInvariantViolation::CommittedPrefixDiverges`] for the first in-sync replica that
/// disagrees with the reference on a committed offset (below `committed_hw`).
pub fn check_cluster_durable_prefix(
    replicas: &[ReplicaPrefix],
    committed_hw: u64,
) -> Result<(), ClusterInvariantViolation> {
    let Some((reference, rest)) = replicas.split_first() else {
        // No replicas: vacuously identical (and the n=1 lone replica is trivially self-consistent).
        return Ok(());
    };
    for replica in rest {
        // Compare only the committed range [0, committed_hw). A replica missing a committed offset, or
        // holding a different fingerprint there, breaks CI1. Offsets are `u64` throughout; an offset
        // that does not fit `usize` cannot be an index into either prefix, so both sides read `None`
        // there and agree (a vacuous match on a platform that cannot hold the log anyway).
        for offset in 0..committed_hw {
            let index = usize::try_from(offset).ok();
            let reference_fp = index.and_then(|i| reference.prefix.get(i));
            let replica_fp = index.and_then(|i| replica.prefix.get(i));
            if reference_fp != replica_fp {
                return Err(ClusterInvariantViolation::CommittedPrefixDiverges {
                    replica: replica.replica,
                    offset,
                });
            }
        }
    }
    Ok(())
}

/// One released `C2-fsync` ack: the offset that was acked, and how many replicas had `fdatasync`'d
/// it (strictly: had a durable frontier strictly past it) at the moment the ack was released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckEvidence {
    /// The acked offset.
    pub offset: u64,
    /// How many replicas (including the leader) had `fdatasync`'d every offset `<= offset` when the
    /// ack was released.
    pub fsynced_replicas: usize,
}

/// CI2 — cluster ack implies quorum-fsync. Every released `C2-fsync` ack must have been backed by at
/// least `min_isr` replicas having `fdatasync`'d its offset. This is the cluster extension of the
/// single-node I2 (ack implies durable): the #691 quorum-fsync gate must never release a sub-quorum
/// ack (the no-false-ack property, the win over NATS R3's quorum-page-cache ack).
///
/// # Errors
/// Returns [`ClusterInvariantViolation::SubQuorumAck`] for the first ack released below quorum.
pub fn check_quorum_fsync_ack(
    acks: &[AckEvidence],
    min_isr: usize,
) -> Result<(), ClusterInvariantViolation> {
    for ack in acks {
        if ack.fsynced_replicas < min_isr {
            return Err(ClusterInvariantViolation::SubQuorumAck {
                offset: ack.offset,
                fsynced_replicas: ack.fsynced_replicas,
                min_isr,
            });
        }
    }
    Ok(())
}

/// How a detected cross-replica divergence was handled. CI3 demands it be detected, bounded,
/// reported, and either repaired from the quorum or failed closed — never silently served, never
/// deleted, never repaired past the cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DivergenceOutcome {
    /// The divergence was REPAIRED from the quorum within the cap (truncate + re-fetch clean bytes).
    /// `repaired_bytes` is the bounded amount re-synced; it must be `<= cap`.
    Repaired {
        /// The bytes re-synced from the quorum.
        repaired_bytes: u64,
    },
    /// The divergence exceeded the cap and FAILED CLOSED (a typed error, the partition refuses to
    /// serve the divergent data rather than proceed unbounded). This is a VALID outcome.
    FailedClosed {
        /// The bytes the repair would have touched (over the cap).
        bytes: u64,
    },
    /// The divergent data was QUARANTINED (copy-then-drop into the forensic store) and re-synced. A
    /// VALID outcome — the corrupt bytes are preserved, never deleted.
    Quarantined {
        /// The quarantined byte count.
        quarantined_bytes: u64,
    },
    /// VIOLATION: the divergent data was served to a consumer without repair (silent drift).
    SilentlyServed,
    /// VIOLATION: the divergent data was deleted rather than quarantined + re-synced.
    Deleted,
}

/// One detected divergence and how it was handled, for the CI3 checker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DivergenceHandling {
    /// The id of the divergent segment.
    pub segment_id: u64,
    /// How the divergence was handled.
    pub outcome: DivergenceOutcome,
    /// The per-event repair cap (the I3 bound) in bytes.
    pub per_event_cap: u64,
}

/// CI3 — bounded, reported, repaired divergence. Every detected divergence must have been handled by
/// a VALID outcome: repaired within the cap, failed closed over the cap, or quarantined + re-synced.
/// It must NEVER have been silently served or deleted, and a repair must never exceed the cap without
/// failing closed (the #697 property; the beat over NATS #5576 silent-drift and #7556 minority-delete).
///
/// # Errors
/// Returns [`ClusterInvariantViolation::DivergenceMishandled`] for the first divergence handled by an
/// invalid outcome (silently served, deleted, or repaired past the cap).
pub fn check_divergence_handled(
    handlings: &[DivergenceHandling],
) -> Result<(), ClusterInvariantViolation> {
    for handling in handlings {
        let reason = match handling.outcome {
            DivergenceOutcome::Repaired { repaired_bytes } => {
                if repaired_bytes > handling.per_event_cap {
                    Some(DivergenceMishandling::UnboundedRepair {
                        bytes: repaired_bytes,
                        cap: handling.per_event_cap,
                    })
                } else {
                    None
                }
            }
            // Failing closed over the cap, and quarantine-then-resync, are the FAIL-CLOSED valid
            // outcomes: bounded, reported, never deletes.
            DivergenceOutcome::FailedClosed { .. } | DivergenceOutcome::Quarantined { .. } => None,
            DivergenceOutcome::SilentlyServed => Some(DivergenceMishandling::SilentlyServed),
            DivergenceOutcome::Deleted => Some(DivergenceMishandling::DataDeleted),
        };
        if let Some(reason) = reason {
            return Err(ClusterInvariantViolation::DivergenceMishandled {
                segment_id: handling.segment_id,
                reason,
            });
        }
    }
    Ok(())
}

/// One committed record's leadership epoch, for the CI4 checker: the offset and the epoch it was
/// committed under. The cluster-known epoch (the current, highest term) fences any older one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedEpoch {
    /// The committed offset.
    pub offset: u64,
    /// The leadership epoch the record was committed under.
    pub epoch: LeaderEpoch,
}

/// CI4 — epoch monotonicity / no stale-leader-commit. Committed records' epochs, scanned in offset
/// order, must be NON-DECREASING (a later offset never carries an older epoch — the leadership term
/// only moves forward across the committed log), AND no record may be committed under an epoch
/// strictly below the cluster-known epoch (a stale leader cannot commit). This is the #668 leader-epoch
/// monotonicity extended by the #614 leader-completeness restriction.
///
/// `committed` must be in ascending offset order (the committed prefix is contiguous from 0).
///
/// # Errors
/// Returns [`ClusterInvariantViolation::EpochRegressed`] at the first offset whose epoch regresses
/// below its predecessor's, or below `cluster_epoch`.
pub fn check_epoch_monotonic(
    committed: &[CommittedEpoch],
    cluster_epoch: LeaderEpoch,
) -> Result<(), ClusterInvariantViolation> {
    let mut prev: Option<LeaderEpoch> = None;
    for entry in committed {
        // No committed record may carry an epoch above the cluster-known epoch (a commit under a
        // future epoch the cluster has not adopted) NOR one strictly below a previously-committed
        // record's epoch (a backwards step in the leadership term over the log).
        if entry.epoch.get() > cluster_epoch.get() {
            return Err(ClusterInvariantViolation::EpochRegressed {
                current: cluster_epoch,
                offending: entry.epoch,
            });
        }
        if let Some(prev) = prev {
            if entry.epoch < prev {
                return Err(ClusterInvariantViolation::EpochRegressed {
                    current: prev,
                    offending: entry.epoch,
                });
            }
        }
        prev = Some(entry.epoch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// CI5 — leaderless-node failover preserves committed data + fences the old leader (C5-I3, #618).
// ---------------------------------------------------------------------------------------------------

/// The observable state of a leaderless-node FAILOVER, for the CI5 checker: who died, who was promoted,
/// what the cluster had quorum-acked before the death, and the successor's own durable prefix + epoch.
///
/// These are small, IO-free value-types (the same shape as the I1 to I4 / eligibility inputs): the
/// `ironbus-server` plane projects its rich state (the ISR tracker, the committed placement's epoch, the
/// successor's replica-log frontier) onto them and calls the checker. A `Failover` describes the result
/// of promoting `successor` when `dead_leader` left; CI5 falsifies it against the three failover faults
/// (lost-committed, unfenced, non-ISR successor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failover {
    /// The node id of the leader that died / left, triggering the failover.
    pub dead_leader: u64,
    /// The successor leader promoted from the surviving replicas. MUST be an ISR member that already
    /// holds the committed log (`successor_in_isr`) — promoting a non-ISR replica is a CI5 violation.
    pub successor: u64,
    /// Whether the successor was in the in-sync replica set at the moment of failover. Only an ISR
    /// member is guaranteed to hold every committed record, so only an ISR member may be promoted.
    pub successor_in_isr: bool,
    /// The successor's durable (fsync'd) prefix frontier at failover: the first offset it has NOT durably
    /// appended. It must cover every offset that was quorum-acked before the death (`>= committed_hw`).
    pub successor_durable_prefix: u64,
    /// The cluster-known committed high-watermark at the death: every offset strictly below this was
    /// quorum-acked (fsync'd on `min_isr` replicas), so it is acknowledged and MUST survive the failover.
    pub committed_hw: u64,
    /// The dead leader's leadership epoch at the time of failover (the epoch the successor must exceed).
    pub dead_leader_epoch: LeaderEpoch,
    /// The successor's NEW leadership epoch, assigned by the failover re-placement. It MUST strictly
    /// exceed `dead_leader_epoch` so a stale/returning old leader is fenced (KIP-101): the old leader
    /// can no longer ack or serve as leader once a higher epoch exists.
    pub successor_epoch: LeaderEpoch,
}

/// CI5 — a leaderless-node failover NEVER loses a committed record and ALWAYS fences the old leader.
///
/// When a leader dies, the successor leader (promoted from the surviving replicas) must, by
/// construction:
///
/// 1. be an ISR member (`successor_in_isr`) — the set that holds every quorum-fsync'd record; promoting
///    a non-ISR replica risks losing acknowledged data (the #614 Jepsen failure, at failover time);
/// 2. hold every committed offset (`successor_durable_prefix >= committed_hw`) — its log covers every
///    record that was quorum-acked before the death, so no acknowledged record is lost on promotion
///    (the data-plane analogue of CI1 across a leadership change); and
/// 3. carry a strictly higher leadership epoch (`successor_epoch > dead_leader_epoch`) — so the old
///    leader is fenced (KIP-101): it can no longer ack or serve as leader once the higher epoch exists.
///
/// The checks are ordered most-fundamental-first (ISR membership → committed completeness → epoch
/// fence), so a violated failover is always explained by its first failure. A clean failover (an ISR
/// successor, complete to the committed HW, with a bumped epoch) passes.
///
/// # Errors
/// - [`ClusterInvariantViolation::FailoverPromotedNonIsr`] if the successor was not in the ISR;
/// - [`ClusterInvariantViolation::FailoverLostCommitted`] if the successor's durable prefix is behind
///   the committed HW (so it is missing a quorum-acked offset — the FIRST such offset is reported);
/// - [`ClusterInvariantViolation::FailoverEpochNotFenced`] if the successor's epoch does not strictly
///   exceed the dead leader's (so the old leader is not fenced).
pub fn check_failover_preserves_committed(
    failover: &Failover,
) -> Result<(), ClusterInvariantViolation> {
    // (1) The successor MUST be an ISR member — only the ISR is guaranteed to hold every committed
    // record. A non-ISR successor is the Jepsen failure (a replica that "managed to become leader
    // despite its [incomplete] state"), here at failover time.
    if !failover.successor_in_isr {
        return Err(ClusterInvariantViolation::FailoverPromotedNonIsr {
            successor: failover.successor,
        });
    }
    // (2) The successor MUST hold every quorum-acked-before-death offset. If its durable prefix is
    // behind the committed HW it is missing a committed record; report the FIRST missing offset (the
    // first offset at or above its durable prefix that is still below the committed HW).
    if failover.successor_durable_prefix < failover.committed_hw {
        return Err(ClusterInvariantViolation::FailoverLostCommitted {
            successor: failover.successor,
            offset: failover.successor_durable_prefix,
        });
    }
    // (3) The failover MUST bump the epoch so the dead leader is fenced (KIP-101). A successor epoch
    // that does not strictly exceed the dead leader's leaves the old leader able to ack/serve.
    if failover.successor_epoch <= failover.dead_leader_epoch {
        return Err(ClusterInvariantViolation::FailoverEpochNotFenced {
            dead_epoch: failover.dead_leader_epoch,
            successor_epoch: failover.successor_epoch,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Leader-completeness eligibility (C4-I4, #614) — the pure predicate the placement plane consults.
// ---------------------------------------------------------------------------------------------------

/// The reason a replica is INELIGIBLE to become a partition leader. Eligibility is the conjunction
/// `in-ISR AND durable-prefix >= committed-HW AND no-detected-divergence`; this enumerates the ways
/// it can fail, so an ineligible verdict is always explained (never a silent exclusion).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineligible {
    /// The replica is not in the in-sync replica set (it has been evicted for lag, or is down): it
    /// may not hold the committed prefix and cannot be trusted to lead.
    NotInIsr,
    /// The replica's durable (fsync'd) prefix is BEHIND the cluster-known committed high-watermark:
    /// it is missing committed records and would lose them if it led (the stale-replica case).
    BehindCommittedHw {
        /// The replica's durable-prefix frontier (first offset it has NOT durably appended).
        durable_prefix: u64,
        /// The cluster-known committed high-watermark it must reach to be complete.
        committed_hw: u64,
    },
    /// The replica's log DIVERGES from the committed lineage (a detected fingerprint mismatch, #697):
    /// it holds corrupt/divergent data and must never lead (the corrupt-replica case — the Jepsen fix).
    Divergent,
}

impl std::fmt::Display for Ineligible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ineligible::NotInIsr => write!(f, "not in the in-sync replica set"),
            Ineligible::BehindCommittedHw {
                durable_prefix,
                committed_hw,
            } => write!(
                f,
                "durable prefix {durable_prefix} is behind the committed high-watermark {committed_hw}"
            ),
            Ineligible::Divergent => write!(f, "log diverges from the committed lineage"),
        }
    }
}

/// A candidate replica's leader-completeness inputs: the small projection of its cluster state the
/// eligibility predicate needs. The `ironbus-server` plane fills this from the ISR tracker, the
/// follower's durable frontier, and the divergence report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaderCandidate {
    /// The candidate replica's cluster node id.
    pub replica: u64,
    /// Whether the replica is currently in the in-sync replica set (the #691 ISR).
    pub in_isr: bool,
    /// The replica's durable (fsync'd) prefix frontier: the first offset it has NOT durably appended,
    /// i.e. it holds the committed log up to (but not including) this offset.
    pub durable_prefix: u64,
    /// Whether a divergence has been detected for this replica's log against the committed lineage
    /// (the #697 fingerprint mismatch). `true` => corrupt/divergent => ineligible.
    pub divergent: bool,
}

/// The leader-completeness eligibility decision for one candidate at a known committed HW. This is the
/// C4-I4 (#614) construction: only a COMPLETE, NON-DIVERGENT, IN-SYNC replica is eligible to lead, so
/// a stale/corrupt replica is excluded BY CONSTRUCTION (it can never win), which is what prevents the
/// Jepsen NATS corrupt-node-wins-and-deletes failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaderEligibility;

impl LeaderEligibility {
    /// Decide whether `candidate` is eligible to become the partition leader given the cluster-known
    /// committed high-watermark `committed_hw`. Eligible iff ALL hold:
    ///
    /// 1. the candidate is in the ISR (`in_isr`),
    /// 2. its durable prefix has reached the committed HW (`durable_prefix >= committed_hw`), and
    /// 3. no divergence has been detected for it (`!divergent`).
    ///
    /// Returns `Ok(())` when eligible, or the FIRST [`Ineligible`] reason it fails (checked in the
    /// order ISR → completeness → divergence, so the most fundamental exclusion is reported first).
    ///
    /// # Errors
    /// Returns the [`Ineligible`] reason the candidate is excluded from leadership.
    pub fn evaluate(candidate: &LeaderCandidate, committed_hw: u64) -> Result<(), Ineligible> {
        if !candidate.in_isr {
            return Err(Ineligible::NotInIsr);
        }
        if candidate.durable_prefix < committed_hw {
            return Err(Ineligible::BehindCommittedHw {
                durable_prefix: candidate.durable_prefix,
                committed_hw,
            });
        }
        if candidate.divergent {
            return Err(Ineligible::Divergent);
        }
        Ok(())
    }

    /// Whether `candidate` is eligible at `committed_hw` (the boolean form of [`Self::evaluate`]).
    #[must_use]
    pub fn is_eligible(candidate: &LeaderCandidate, committed_hw: u64) -> bool {
        Self::evaluate(candidate, committed_hw).is_ok()
    }

    /// Filter `candidates` to exactly the replicas ELIGIBLE to lead at `committed_hw`, preserving the
    /// input order. The metadata-plane PLACEMENT (C5, #616+) chooses WHICH of these to designate
    /// leader; this function only guarantees the set it chooses from contains no stale/corrupt
    /// replica — an ineligible node is never offered to the placement, so it can never be chosen.
    #[must_use]
    pub fn eligible_set(candidates: &[LeaderCandidate], committed_hw: u64) -> Vec<u64> {
        candidates
            .iter()
            .filter(|c| Self::is_eligible(c, committed_hw))
            .map(|c| c.replica)
            .collect()
    }

    /// Every candidate's ineligibility reason (or `None` if eligible), keyed by node id — the full,
    /// explained verdict for observability / a placement audit log. A clean, complete cluster yields
    /// all-`None`.
    #[must_use]
    pub fn explain(
        candidates: &[LeaderCandidate],
        committed_hw: u64,
    ) -> BTreeMap<u64, Option<Ineligible>> {
        candidates
            .iter()
            .map(|c| (c.replica, Self::evaluate(c, committed_hw).err()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> LeaderEpoch {
        LeaderEpoch::new(n)
    }

    // ----- CI1: cluster durable prefix -----

    fn prefix(replica: u64, fps: &[u64]) -> ReplicaPrefix {
        ReplicaPrefix {
            replica,
            prefix: fps.to_vec(),
        }
    }

    #[test]
    fn ci1_passes_when_in_sync_replicas_share_the_committed_prefix() {
        // Three replicas agree on offsets 0..5 (the committed range below HW=5); replica 3 diverges
        // ABOVE the HW (offset 5), which is allowed (uncommitted, epoch-truncatable).
        let replicas = vec![
            prefix(1, &[10, 11, 12, 13, 14, 99]),
            prefix(2, &[10, 11, 12, 13, 14, 88]),
            prefix(3, &[10, 11, 12, 13, 14]),
        ];
        check_cluster_durable_prefix(&replicas, 5).unwrap();
        // The empty / single-replica cases are trivially consistent.
        check_cluster_durable_prefix(&[], 5).unwrap();
        check_cluster_durable_prefix(&replicas[..1], 5).unwrap();
    }

    #[test]
    fn ci1_negative_fixture_a_committed_offset_diverges() {
        // Replica 2 holds a DIFFERENT record at committed offset 2 (below HW=4): CI1 violated.
        let replicas = vec![prefix(1, &[10, 11, 12, 13]), prefix(2, &[10, 11, 77, 13])];
        assert_eq!(
            check_cluster_durable_prefix(&replicas, 4),
            Err(ClusterInvariantViolation::CommittedPrefixDiverges {
                replica: 2,
                offset: 2,
            })
        );
    }

    #[test]
    fn ci1_negative_fixture_a_replica_missing_a_committed_offset() {
        // Replica 2 is SHORT of the committed HW (missing offset 3): CI1 violated.
        let replicas = vec![prefix(1, &[10, 11, 12, 13]), prefix(2, &[10, 11, 12])];
        assert_eq!(
            check_cluster_durable_prefix(&replicas, 4),
            Err(ClusterInvariantViolation::CommittedPrefixDiverges {
                replica: 2,
                offset: 3,
            })
        );
    }

    // ----- CI2: cluster ack implies quorum-fsync -----

    #[test]
    fn ci2_passes_when_every_ack_had_a_quorum_of_fsyncs() {
        let acks = vec![
            AckEvidence {
                offset: 0,
                fsynced_replicas: 2,
            },
            AckEvidence {
                offset: 1,
                fsynced_replicas: 3,
            },
        ];
        check_quorum_fsync_ack(&acks, 2).unwrap();
        check_quorum_fsync_ack(&[], 2).unwrap();
    }

    #[test]
    fn ci2_negative_fixture_a_sub_quorum_ack() {
        // An ack released with only 1 fsync'd replica under a quorum of 2: a page-cache / sub-quorum
        // ack — exactly the NATS R3 weakness CI2 forbids.
        let acks = vec![
            AckEvidence {
                offset: 7,
                fsynced_replicas: 2,
            },
            AckEvidence {
                offset: 8,
                fsynced_replicas: 1,
            },
        ];
        assert_eq!(
            check_quorum_fsync_ack(&acks, 2),
            Err(ClusterInvariantViolation::SubQuorumAck {
                offset: 8,
                fsynced_replicas: 1,
                min_isr: 2,
            })
        );
    }

    // ----- CI3: bounded, reported, repaired divergence -----

    fn handling(segment_id: u64, outcome: DivergenceOutcome) -> DivergenceHandling {
        DivergenceHandling {
            segment_id,
            outcome,
            per_event_cap: 1024,
        }
    }

    #[test]
    fn ci3_passes_for_repaired_failed_closed_and_quarantined_outcomes() {
        let handlings = vec![
            handling(
                1,
                DivergenceOutcome::Repaired {
                    repaired_bytes: 512,
                },
            ),
            handling(2, DivergenceOutcome::FailedClosed { bytes: 4096 }),
            handling(
                3,
                DivergenceOutcome::Quarantined {
                    quarantined_bytes: 256,
                },
            ),
        ];
        check_divergence_handled(&handlings).unwrap();
        check_divergence_handled(&[]).unwrap();
    }

    #[test]
    fn ci3_negative_fixture_a_silently_served_divergence() {
        // A detected divergence served to a consumer without repair — the NATS #5576 silent-drift class.
        let handlings = vec![handling(9, DivergenceOutcome::SilentlyServed)];
        assert_eq!(
            check_divergence_handled(&handlings),
            Err(ClusterInvariantViolation::DivergenceMishandled {
                segment_id: 9,
                reason: DivergenceMishandling::SilentlyServed,
            })
        );
    }

    #[test]
    fn ci3_negative_fixture_a_deleted_divergence() {
        // Divergent data DELETED rather than quarantined — the NATS #7556 minority-delete class.
        let handlings = vec![handling(4, DivergenceOutcome::Deleted)];
        assert_eq!(
            check_divergence_handled(&handlings),
            Err(ClusterInvariantViolation::DivergenceMishandled {
                segment_id: 4,
                reason: DivergenceMishandling::DataDeleted,
            })
        );
    }

    #[test]
    fn ci3_negative_fixture_a_repair_past_the_cap_that_did_not_fail_closed() {
        // A "Repaired" outcome over the cap is unbounded — it should have failed closed instead.
        let handlings = vec![handling(
            5,
            DivergenceOutcome::Repaired {
                repaired_bytes: 4096,
            },
        )];
        assert_eq!(
            check_divergence_handled(&handlings),
            Err(ClusterInvariantViolation::DivergenceMishandled {
                segment_id: 5,
                reason: DivergenceMishandling::UnboundedRepair {
                    bytes: 4096,
                    cap: 1024,
                },
            })
        );
    }

    // ----- CI4: epoch monotonicity / no stale-leader-commit -----

    #[test]
    fn ci4_passes_for_a_monotonic_committed_epoch_sequence() {
        let committed = vec![
            CommittedEpoch {
                offset: 0,
                epoch: epoch(3),
            },
            CommittedEpoch {
                offset: 1,
                epoch: epoch(3),
            },
            CommittedEpoch {
                offset: 2,
                epoch: epoch(5),
            },
        ];
        check_epoch_monotonic(&committed, epoch(5)).unwrap();
        check_epoch_monotonic(&[], epoch(5)).unwrap();
    }

    #[test]
    fn ci4_negative_fixture_an_epoch_regression_across_offsets() {
        // Offset 2 was committed under epoch 2, BELOW offset 1's epoch 4: a backwards leadership step
        // (a stale leader committed after a newer one) — the stale-leader-commit CI4 forbids.
        let committed = vec![
            CommittedEpoch {
                offset: 0,
                epoch: epoch(4),
            },
            CommittedEpoch {
                offset: 1,
                epoch: epoch(4),
            },
            CommittedEpoch {
                offset: 2,
                epoch: epoch(2),
            },
        ];
        assert_eq!(
            check_epoch_monotonic(&committed, epoch(4)),
            Err(ClusterInvariantViolation::EpochRegressed {
                current: epoch(4),
                offending: epoch(2),
            })
        );
    }

    #[test]
    fn ci4_negative_fixture_a_commit_above_the_cluster_epoch() {
        // A record committed under epoch 9 when the cluster epoch is only 5: a commit under an epoch
        // the cluster has not adopted (a future/forged epoch).
        let committed = vec![CommittedEpoch {
            offset: 0,
            epoch: epoch(9),
        }];
        assert_eq!(
            check_epoch_monotonic(&committed, epoch(5)),
            Err(ClusterInvariantViolation::EpochRegressed {
                current: epoch(5),
                offending: epoch(9),
            })
        );
    }

    // ----- CI5: leaderless-node failover preserves committed data + fences the old leader -----

    fn failover(
        successor: u64,
        in_isr: bool,
        durable: u64,
        hw: u64,
        dead_e: u64,
        succ_e: u64,
    ) -> Failover {
        Failover {
            dead_leader: 1,
            successor,
            successor_in_isr: in_isr,
            successor_durable_prefix: durable,
            committed_hw: hw,
            dead_leader_epoch: epoch(dead_e),
            successor_epoch: epoch(succ_e),
        }
    }

    #[test]
    fn ci5_passes_for_an_isr_successor_complete_to_hw_with_a_bumped_epoch() {
        // The successor was in the ISR, holds every committed offset (durable 100 >= HW 100), and its
        // epoch (6) strictly exceeds the dead leader's (5): a clean, committed-data-preserving,
        // old-leader-fencing failover.
        check_failover_preserves_committed(&failover(2, true, 100, 100, 5, 6)).unwrap();
        // A successor AHEAD of the HW (it held an uncommitted suffix too) is still complete => passes.
        check_failover_preserves_committed(&failover(2, true, 150, 100, 5, 6)).unwrap();
    }

    #[test]
    fn ci5_negative_fixture_a_successor_missing_a_committed_offset_loses_data() {
        // The successor's durable prefix (80) is BEHIND the committed HW (100): offsets 80..100 were
        // quorum-acked before the death but the successor does NOT hold them — promoting it loses
        // acknowledged data. CI5 reports the FIRST missing offset (80).
        assert_eq!(
            check_failover_preserves_committed(&failover(2, true, 80, 100, 5, 6)),
            Err(ClusterInvariantViolation::FailoverLostCommitted {
                successor: 2,
                offset: 80,
            })
        );
    }

    #[test]
    fn ci5_negative_fixture_a_failover_that_does_not_bump_the_epoch_does_not_fence_the_old_leader()
    {
        // The successor is complete, but its epoch (5) equals the dead leader's (5): the old leader is
        // NOT fenced — a stale/returning old leader at epoch 5 could still ack/serve. A failover MUST
        // strictly bump the epoch.
        assert_eq!(
            check_failover_preserves_committed(&failover(2, true, 100, 100, 5, 5)),
            Err(ClusterInvariantViolation::FailoverEpochNotFenced {
                dead_epoch: epoch(5),
                successor_epoch: epoch(5),
            })
        );
        // An epoch that goes BACKWARD is even worse — still reported as unfenced.
        assert_eq!(
            check_failover_preserves_committed(&failover(2, true, 100, 100, 5, 4)),
            Err(ClusterInvariantViolation::FailoverEpochNotFenced {
                dead_epoch: epoch(5),
                successor_epoch: epoch(4),
            })
        );
    }

    #[test]
    fn ci5_negative_fixture_promoting_a_non_isr_replica_is_a_violation() {
        // The successor was NOT in the ISR: it may be missing committed records (it lagged out / was
        // never caught up). Promoting it is the Jepsen failure at failover time, regardless of the
        // (possibly stale) durable-prefix number it reports.
        assert_eq!(
            check_failover_preserves_committed(&failover(3, false, 100, 100, 5, 6)),
            Err(ClusterInvariantViolation::FailoverPromotedNonIsr { successor: 3 })
        );
    }

    #[test]
    fn ci5_checks_are_ordered_most_fundamental_first() {
        // A failover that violates ALL THREE (non-ISR, behind HW, no epoch bump) is reported by its
        // most fundamental failure first: NOT-IN-ISR. This keeps the verdict deterministic + the most
        // load-bearing exclusion surfaced.
        assert_eq!(
            check_failover_preserves_committed(&failover(3, false, 50, 100, 5, 5)),
            Err(ClusterInvariantViolation::FailoverPromotedNonIsr { successor: 3 })
        );
    }

    // ----- C4-I4 leader-completeness eligibility -----

    fn candidate(
        replica: u64,
        in_isr: bool,
        durable_prefix: u64,
        divergent: bool,
    ) -> LeaderCandidate {
        LeaderCandidate {
            replica,
            in_isr,
            durable_prefix,
            divergent,
        }
    }

    #[test]
    fn a_complete_in_sync_non_divergent_replica_is_eligible() {
        // In-ISR, durable prefix AT the committed HW, no divergence => eligible.
        let c = candidate(1, true, 100, false);
        assert_eq!(LeaderEligibility::evaluate(&c, 100), Ok(()));
        assert!(LeaderEligibility::is_eligible(&c, 100));
        // A replica AHEAD of the HW (has uncommitted suffix) is still complete => eligible.
        assert!(LeaderEligibility::is_eligible(
            &candidate(1, true, 150, false),
            100
        ));
    }

    #[test]
    fn a_replica_behind_the_committed_hw_is_ineligible() {
        // Durable prefix 80 < committed HW 100: it is MISSING committed records => ineligible.
        let c = candidate(2, true, 80, false);
        assert_eq!(
            LeaderEligibility::evaluate(&c, 100),
            Err(Ineligible::BehindCommittedHw {
                durable_prefix: 80,
                committed_hw: 100,
            })
        );
        assert!(!LeaderEligibility::is_eligible(&c, 100));
    }

    #[test]
    fn a_divergent_replica_is_ineligible() {
        // In-ISR and complete, but a detected divergence (corrupt/divergent log) => ineligible.
        let c = candidate(3, true, 100, true);
        assert_eq!(
            LeaderEligibility::evaluate(&c, 100),
            Err(Ineligible::Divergent)
        );
        assert!(!LeaderEligibility::is_eligible(&c, 100));
    }

    #[test]
    fn a_replica_not_in_the_isr_is_ineligible() {
        let c = candidate(4, false, 100, false);
        assert_eq!(
            LeaderEligibility::evaluate(&c, 100),
            Err(Ineligible::NotInIsr)
        );
    }

    #[test]
    fn the_jepsen_fix_a_stale_or_corrupt_node_is_never_in_the_eligible_set() {
        // THE leader-completeness / Jepsen-prevention test: a cluster where one node is stale (behind
        // the HW) and another is corrupt (divergent). The eligible set the placement chooses from
        // contains ONLY the complete, in-sync, non-divergent replica — the stale and corrupt nodes
        // are excluded BY CONSTRUCTION, so the placement can NEVER designate them leader. This is the
        // construction that prevents the NATS 2.12.1 corrupt-node-wins-and-deletes-the-stream failure.
        let candidates = vec![
            candidate(1, true, 100, false),  // complete, in-sync, clean — ELIGIBLE
            candidate(2, true, 60, false),   // STALE: behind the committed HW — ineligible
            candidate(3, true, 100, true),   // CORRUPT: divergent log — ineligible
            candidate(4, false, 100, false), // out of ISR — ineligible
        ];
        let eligible = LeaderEligibility::eligible_set(&candidates, 100);
        assert_eq!(
            eligible,
            vec![1],
            "only the complete, in-sync, non-divergent replica is eligible to lead"
        );
        // No matter which node the placement picks from the eligible set, it CANNOT be the stale (2)
        // or the corrupt (3) node — they are not in the set.
        assert!(
            !eligible.contains(&2),
            "the stale node can never win leadership"
        );
        assert!(
            !eligible.contains(&3),
            "the corrupt node can never win leadership"
        );

        // The explained verdict names exactly why each ineligible node is excluded.
        let explained = LeaderEligibility::explain(&candidates, 100);
        assert_eq!(explained[&1], None);
        assert_eq!(
            explained[&2],
            Some(Ineligible::BehindCommittedHw {
                durable_prefix: 60,
                committed_hw: 100,
            })
        );
        assert_eq!(explained[&3], Some(Ineligible::Divergent));
        assert_eq!(explained[&4], Some(Ineligible::NotInIsr));
    }

    #[test]
    fn single_node_lone_replica_is_trivially_eligible() {
        // n=1: the lone replica IS the committed log by definition — its durable prefix equals the
        // committed HW (the leader's own fsync'd frontier), it is trivially in its own ISR, and it
        // cannot diverge from itself. So it is ALWAYS eligible, and clustering eligibility never
        // excludes the single-node leader (byte-identical to today's broker).
        let lone = candidate(1, true, 42, false);
        assert!(LeaderEligibility::is_eligible(&lone, 42));
        assert_eq!(LeaderEligibility::eligible_set(&[lone], 42), vec![1]);
    }
}
