// SPDX-License-Identifier: MIT OR Apache-2.0
//! Leader-completeness election restriction (V2-C4-I4, #614): the ELIGIBILITY a partition leader
//! candidate must satisfy before the metadata plane may designate it leader.
//!
//! This is the construction that prevents the Jepsen NATS 2.12.1 failure — a node that "managed to
//! become the leader of the cluster despite its corrupt state" and then deleted the stream, losing
//! ~49.7% of acknowledged writes. IronBus closes that hole at the ELECTION boundary: a partition
//! leader candidate must hold the COMPLETE committed log up to the cluster-known high-watermark (the
//! #691 quorum HW), be IN the in-sync replica set (the #691 ISR), and have NO detected divergence
//! (the #697 fingerprint mismatch). A stale (behind-HW) or corrupt (divergent) replica is therefore
//! INELIGIBLE — by construction it can never win leadership.
//!
//! ## Eligibility = (in ISR) AND (durable prefix >= committed HW) AND (no detected divergence)
//!
//! The pure predicate itself lives IO-free in
//! [`ironbus_core::cluster_invariants::LeaderEligibility`] (the Kafka ELR "Leader Candidate
//! Completeness" / KIP-966 shape). THIS module is the thin server-side adapter that PROJECTS the
//! rich cluster state onto that predicate's small value-type input:
//!
//! * **in ISR** — from the leader's [`super::isr::IsrTracker`]: the candidate is in-sync iff its
//!   membership is [`super::isr::IsrMembership::InSync`] (the leader itself is always in-sync). An
//!   evicted-for-lag follower is NOT in the ISR and so is ineligible.
//! * **durable prefix >= committed HW** — the candidate's reported fsync'd frontier
//!   ([`super::isr::AckReplicatedBody::fsynced_offset`], the leader's own
//!   [`ironbus_storage::log::Log::flushed_offset`]) must have reached the quorum-committed HW
//!   ([`super::isr::IsrTracker::quorum_commit`]). A replica behind the committed HW is missing
//!   committed records and is ineligible.
//! * **no detected divergence** — from the C4 [`super::divergence::DivergenceReport`]: a replica with
//!   a detected fingerprint mismatch against the committed lineage is corrupt/divergent and ineligible.
//!
//! ## Scope boundary (FLAGGED): this is the ELIGIBILITY function, NOT the placement
//!
//! C4-I4 enforces *who is allowed to lead*. It does NOT *assign* or *rebalance* leadership — the
//! metadata-placement-driven leader assignment / rebalance is **C5** (#616+). The placement plane
//! CONSULTS [`eligible_leaders`] (or [`is_eligible_leader`]) and chooses a leader only from the
//! eligible set; this module guarantees that set never contains a stale/corrupt replica, so the
//! placement can never designate one. Wiring this into the running `serve`-path metadata placement is
//! the follow-up, exactly like the rest of the C1–C4 cluster layer (a testable layer first).
//!
//! ## Single node is byte-identical (the Edge-First non-negotiable)
//!
//! With no cluster (n=1), the lone replica IS the committed log by definition: it is trivially in its
//! own ISR, its durable prefix equals the committed HW (its own local-fsync frontier, the I2 ack),
//! and it cannot diverge from itself — so it is ALWAYS eligible. The eligibility layer never
//! constructs in a standalone broker; merely linking it changes nothing on disk or on the wire.

use ironbus_core::cluster_invariants::{Ineligible, LeaderCandidate, LeaderEligibility};

use super::divergence::DivergenceReport;
use super::isr::{IsrMembership, IsrTracker};

pub use ironbus_core::cluster_invariants::Ineligible as IneligibleReason;

/// One replica's observed cluster state, as the leader's ISR tracker + the C4 divergence detection
/// see it. The adapter projects this onto the IO-free [`LeaderCandidate`] the pure predicate consumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicaState {
    /// The replica's cluster node id.
    pub replica: u64,
    /// The replica's durable (fsync'd) prefix frontier: the first offset it has NOT durably appended
    /// (its [`super::isr::AckReplicatedBody::fsynced_offset`], or the leader's own
    /// [`ironbus_storage::log::Log::flushed_offset`] for the leader itself).
    pub durable_prefix: u64,
    /// Whether the replica is currently in the in-sync replica set under the lag bound.
    pub in_isr: bool,
    /// Whether a divergence has been detected for this replica's log against the committed lineage.
    pub divergent: bool,
}

impl ReplicaState {
    /// Project this server-side state onto the IO-free [`LeaderCandidate`] the core predicate consumes.
    #[must_use]
    pub fn as_candidate(&self) -> LeaderCandidate {
        LeaderCandidate {
            replica: self.replica,
            in_isr: self.in_isr,
            durable_prefix: self.durable_prefix,
            divergent: self.divergent,
        }
    }
}

/// Build a [`ReplicaState`] for `replica` from the leader's [`IsrTracker`] and the (optional) C4
/// [`DivergenceReport`] for that replica, at the tracker's current quorum-committed HW.
///
/// * `durable_prefix` is the replica's tracked fsync'd frontier (the leader's own
///   [`IsrTracker::leader_high_watermark`] for the leader, or the follower's tracked frontier).
/// * `in_isr` is `true` iff the replica's [`IsrMembership`] is [`IsrMembership::InSync`] (the leader
///   is always in-sync with itself).
/// * `divergent` is `true` iff a non-clean divergence report names this replica's log.
///
/// Returns `None` if `replica` is neither the leader nor a tracked follower (an unknown node is never
/// eligible — it is simply not a candidate).
#[must_use]
pub fn replica_state_from(
    tracker: &IsrTracker,
    replica: u64,
    durable_prefix: u64,
    divergence: Option<&DivergenceReport>,
) -> Option<ReplicaState> {
    let in_isr = if replica == tracker.leader_id() {
        // The leader is always an in-sync member of its own partition.
        true
    } else {
        match tracker.membership(replica)? {
            IsrMembership::InSync => true,
            IsrMembership::EvictedForLag => false,
        }
    };
    // A divergence report that is NOT clean means the compared replica diverges from the committed
    // lineage. The report is per-replica (the result of comparing THIS replica against the quorum),
    // so a non-clean report makes this replica divergent.
    let divergent = divergence.is_some_and(|d| !d.is_clean());
    Some(ReplicaState {
        replica,
        durable_prefix,
        in_isr,
        divergent,
    })
}

/// Whether `state` is eligible to become the partition leader at the cluster-known committed
/// high-watermark `committed_hw`. The boolean form of [`evaluate_eligibility`].
#[must_use]
pub fn is_eligible_leader(state: &ReplicaState, committed_hw: u64) -> bool {
    LeaderEligibility::is_eligible(&state.as_candidate(), committed_hw)
}

/// Evaluate `state`'s leader-completeness eligibility at `committed_hw`, returning `Ok(())` when
/// eligible or the FIRST [`Ineligible`] reason it is excluded (ISR → completeness → divergence order).
///
/// # Errors
/// Returns the [`Ineligible`] reason the replica is excluded from leadership.
pub fn evaluate_eligibility(state: &ReplicaState, committed_hw: u64) -> Result<(), Ineligible> {
    LeaderEligibility::evaluate(&state.as_candidate(), committed_hw)
}

/// The node ids ELIGIBLE to lead at `committed_hw`, in input order — the set the metadata-plane
/// placement (C5, #616+) chooses a leader from. A stale/corrupt replica is never in this set, so the
/// placement can never designate it leader (the Jepsen-failure prevention).
#[must_use]
pub fn eligible_leaders(states: &[ReplicaState], committed_hw: u64) -> Vec<u64> {
    let candidates: Vec<LeaderCandidate> = states.iter().map(ReplicaState::as_candidate).collect();
    LeaderEligibility::eligible_set(&candidates, committed_hw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::divergence::{
        DivergenceDetected, DivergenceField, DivergenceReport, SegmentFingerprint,
    };
    use crate::cluster::isr::{AckReplicatedBody, IsrConfig, IsrTracker};

    fn state(replica: u64, durable_prefix: u64, in_isr: bool, divergent: bool) -> ReplicaState {
        ReplicaState {
            replica,
            durable_prefix,
            in_isr,
            divergent,
        }
    }

    fn divergent_report(segment_id: u64, hw: u64) -> DivergenceReport {
        DivergenceReport {
            divergences: vec![DivergenceDetected {
                segment_id,
                field: DivergenceField::ContentHash,
                local: Some(SegmentFingerprint {
                    segment_id,
                    last_seq: 9,
                    record_count: 3,
                    footer_crc: 1,
                    content_hash: 0xDEAD,
                }),
                quorum: Some(SegmentFingerprint {
                    segment_id,
                    last_seq: 9,
                    record_count: 3,
                    footer_crc: 1,
                    content_hash: 0xBEEF,
                }),
            }],
            quorum_committed_hw: hw,
        }
    }

    #[test]
    fn a_complete_in_sync_non_divergent_replica_is_eligible() {
        assert!(is_eligible_leader(&state(1, 100, true, false), 100));
        assert_eq!(
            evaluate_eligibility(&state(1, 100, true, false), 100),
            Ok(())
        );
    }

    #[test]
    fn a_replica_behind_the_committed_hw_is_ineligible() {
        let s = state(2, 80, true, false);
        assert!(!is_eligible_leader(&s, 100));
        assert_eq!(
            evaluate_eligibility(&s, 100),
            Err(Ineligible::BehindCommittedHw {
                durable_prefix: 80,
                committed_hw: 100,
            })
        );
    }

    #[test]
    fn a_divergent_replica_is_ineligible() {
        let s = state(3, 100, true, true);
        assert!(!is_eligible_leader(&s, 100));
        assert_eq!(evaluate_eligibility(&s, 100), Err(Ineligible::Divergent));
    }

    #[test]
    fn an_evicted_replica_out_of_the_isr_is_ineligible() {
        let s = state(4, 100, false, false);
        assert!(!is_eligible_leader(&s, 100));
        assert_eq!(evaluate_eligibility(&s, 100), Err(Ineligible::NotInIsr));
    }

    // ----- the adapter: project a REAL ISR tracker + divergence report onto eligibility -----

    #[test]
    fn replica_state_projects_an_evicted_follower_as_out_of_isr() {
        // A 3-node tracker; the leader has fsync'd to 100, follower 2 keeps up, follower 3 lags out.
        let config = IsrConfig {
            min_isr: 2,
            max_lag_records: 10,
        };
        let mut tracker = IsrTracker::new(1, &[2, 3], config);
        tracker.observe_leader_fsync(100);
        tracker.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 95,
        });
        tracker.observe_follower_report(&AckReplicatedBody {
            follower_id: 3,
            fsynced_offset: 50, // lag 50 > 10 => evicted from the ISR
        });

        // The leader is always in-sync and complete to its own HW.
        let leader = replica_state_from(&tracker, 1, 100, None).unwrap();
        assert!(leader.in_isr);
        assert!(is_eligible_leader(&leader, 95));

        // Follower 2 is in-sync; complete to the quorum HW (95) => eligible.
        let f2 = replica_state_from(&tracker, 2, 95, None).unwrap();
        assert!(f2.in_isr);
        assert!(is_eligible_leader(&f2, 95));

        // Follower 3 is EVICTED for lag => not in the ISR => ineligible, regardless of its prefix.
        let f3 = replica_state_from(&tracker, 3, 50, None).unwrap();
        assert!(!f3.in_isr);
        assert!(!is_eligible_leader(&f3, 95));
        assert_eq!(evaluate_eligibility(&f3, 95), Err(Ineligible::NotInIsr));

        // An unknown node is not a candidate at all.
        assert!(replica_state_from(&tracker, 99, 0, None).is_none());
    }

    #[test]
    fn replica_state_projects_a_divergence_report_as_divergent() {
        let mut tracker = IsrTracker::new(1, &[2], IsrConfig::default());
        tracker.observe_leader_fsync(100);
        tracker.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 100,
        });
        // Follower 2 is in-sync and complete, BUT a divergence was detected for its log => ineligible.
        let report = divergent_report(7, 100);
        let f2 = replica_state_from(&tracker, 2, 100, Some(&report)).unwrap();
        assert!(f2.in_isr);
        assert!(f2.divergent);
        assert!(!is_eligible_leader(&f2, 100));
        assert_eq!(evaluate_eligibility(&f2, 100), Err(Ineligible::Divergent));

        // A CLEAN report leaves the same replica eligible (no false exclusion).
        let clean = DivergenceReport {
            divergences: vec![],
            quorum_committed_hw: 100,
        };
        let f2_clean = replica_state_from(&tracker, 2, 100, Some(&clean)).unwrap();
        assert!(!f2_clean.divergent);
        assert!(is_eligible_leader(&f2_clean, 100));
    }

    // ----- THE Jepsen-failure prevention test over the real cluster types -----

    #[test]
    fn a_corrupt_or_stale_node_can_never_be_chosen_leader() {
        // A 4-replica partition where the metadata-plane placement is about to pick a leader. One node
        // is STALE (behind the committed HW), one is CORRUPT (a detected divergence), one is OUT of
        // the ISR. The eligible set the placement chooses from contains ONLY the complete, in-sync,
        // non-divergent replica — so the stale/corrupt nodes can NEVER be designated leader. This is
        // the construction that prevents NATS 2.12.1's corrupt-node-wins-and-deletes-the-stream.
        let committed_hw = 100;
        let states = vec![
            state(1, 100, true, false),  // complete, in-sync, clean -> ELIGIBLE
            state(2, 60, true, false),   // STALE: durable prefix behind the committed HW
            state(3, 100, true, true),   // CORRUPT: divergent log
            state(4, 100, false, false), // out of the ISR
        ];
        let eligible = eligible_leaders(&states, committed_hw);
        assert_eq!(
            eligible,
            vec![1],
            "only the complete, in-sync, non-divergent replica is eligible to lead"
        );
        // The placement picks from `eligible`; it is IMPOSSIBLE for it to pick the stale or corrupt
        // node — the Jepsen failure cannot occur by construction.
        for ineligible in [2u64, 3, 4] {
            assert!(
                !eligible.contains(&ineligible),
                "node {ineligible} (stale/corrupt/out-of-ISR) must never be eligible to lead"
            );
        }
    }

    #[test]
    fn single_node_lone_replica_is_trivially_eligible() {
        // n=1: the lone replica is its own ISR and is complete to its own HW by definition; it cannot
        // diverge from itself. Always eligible — clustering eligibility never excludes the single-node
        // leader (byte-identical to today's broker, which has no cluster layer at all).
        let mut tracker = IsrTracker::new(1, &[], IsrConfig::default());
        tracker.observe_leader_fsync(42);
        let lone = replica_state_from(&tracker, 1, 42, None).unwrap();
        assert!(lone.in_isr);
        assert!(!lone.divergent);
        assert!(is_eligible_leader(&lone, 42));
        assert_eq!(eligible_leaders(&[lone], 42), vec![1]);
    }
}
