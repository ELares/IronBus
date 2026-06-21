// SPDX-License-Identifier: MIT OR Apache-2.0
//! Replica placement: the server-side bridge from the IO-free placement POLICY to a metadata-log
//! COMMAND (V2-C5-I1, #616).
//!
//! The placement POLICY itself — spread `R` replicas across distinct nodes / failure domains and pick
//! a balanced, ELIGIBLE leader — lives IO-free in [`ironbus_core::placement`] (a pure function over
//! small value-types, the same shape as the [`super::eligibility`] predicate). THIS module is the thin
//! `ironbus-server` adapter that:
//!
//! * builds the policy's [`PlacementNode`] inputs from the live cluster state — the membership table
//!   (node ids + optional failure-domain labels) plus, for each candidate, the leader-completeness
//!   inputs the [`super::isr::IsrTracker`] and the C4 divergence report already expose (so a replica's
//!   eligibility to LEAD a placement is the SAME predicate as its eligibility to WIN that partition's
//!   election — #700, composed straight into placement); and
//! * turns the policy's decision into a [`MetadataCommand::PlacePartition`] — the command the metadata
//!   plane commits through the metadata raft log as ONE entry (durable, replicated; NOT a per-partition
//!   Raft group), after which a read serves the committed placement.
//!
//! ## Eligibility is composed into the placement, never bypassed (the part to scrutinize most)
//!
//! [`placement_command`] returns a command ONLY when the policy found an ELIGIBLE leader. A policy
//! result with no eligible leader (every placed replica stale / corrupt / out-of-ISR) yields
//! [`PlacementOutcome::Leaderless`] — NOT a command — so a stale/corrupt replica can never be COMMITTED
//! as a leader. This is the construction that carries the Jepsen-failure prevention (#700) all the way
//! to the committed metadata: the only leaders that ever reach the log are eligible ones.
//!
//! ## Single node is degenerate (the Edge-First non-negotiable)
//!
//! With one node the policy places `[the node]` and (the node being its own ISR, complete to its own
//! HW, unable to diverge) names it leader; this module emits the corresponding `PlacePartition` whose
//! replica set is exactly `[the node]` — identical in effect to the C1 leader-only `AssignPartition`.
//! A standalone broker never constructs a placement at all; merely linking this changes nothing.
//!
//! ## Scope boundary (FLAGGED)
//!
//! This DECIDES + emits a placement command; it does not ACT on the placement (the data-plane wiring
//! that actually replicates to the placed replicas is a follow-up), does not REBALANCE on join/leave
//! (C5-I2, #617), and does not do leaderless-node FAILOVER (C5-I3, #618).

use ironbus_core::placement::{place_partition, LeaderLoad, PlacementNode, PlacementShortfall};

use super::divergence::DivergenceReport;
use super::isr::{IsrMembership, IsrTracker};
use super::state_machine::MetadataCommand;

/// The result of deciding a placement for one partition: either a committable command, or a flagged
/// "no eligible leader" outcome (which is NEVER committed — a stale/corrupt replica is never made a
/// committed leader).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementOutcome {
    /// The placement found an eligible leader; this is the [`MetadataCommand::PlacePartition`] to
    /// commit through the metadata log. `under_replicated` carries the (honest) shortfall reason iff
    /// fewer than `R` distinct nodes were available, so the caller can surface a degraded-but-led
    /// placement.
    Placed {
        /// The command to commit through the metadata raft log.
        command: MetadataCommand,
        /// `Some(reason)` iff the placement holds fewer than `R` replicas (under-replicated but led).
        under_replicated: Option<PlacementShortfall>,
    },
    /// No placed replica is eligible to lead (every candidate is stale / corrupt / out-of-ISR). NO
    /// command is produced — the partition is left leaderless (unavailable for writes) until an
    /// eligible replica appears, rather than committing a stale/corrupt leader. Fail-closed.
    Leaderless {
        /// The replica nodes that WERE placed (they back-fill toward eligibility), for observability.
        replicas: Vec<u64>,
    },
}

/// Decide the placement for `partition` over `candidates` at replication factor `r`, balancing the
/// leader against `leader_load` (how many partitions each node already leads), and committed to
/// `committed_hw`.
///
/// Returns a [`PlacementOutcome::Placed`] carrying a [`MetadataCommand::PlacePartition`] when an
/// eligible leader is found, or [`PlacementOutcome::Leaderless`] when none is — so a stale/corrupt
/// replica is never committed as leader. The decision is the IO-free [`place_partition`] policy, so it
/// reads no wall clock and is deterministic (I6).
#[must_use]
pub fn decide_placement(
    partition: u64,
    candidates: &[PlacementNode],
    r: usize,
    committed_hw: u64,
    epoch: u64,
    leader_load: &LeaderLoad,
) -> PlacementOutcome {
    let placement = place_partition(candidates, r, committed_hw, leader_load);
    match placement.leader {
        Some(leader) => PlacementOutcome::Placed {
            command: MetadataCommand::PlacePartition {
                partition,
                replicas: placement.replicas,
                leader,
                epoch,
            },
            under_replicated: match placement.under_replicated {
                // A "no eligible leader" shortfall cannot co-occur with a `Some(leader)`; only the
                // under-replication reason is meaningful here.
                Some(PlacementShortfall::TooFewNodes { requested, placed }) => {
                    Some(PlacementShortfall::TooFewNodes { requested, placed })
                }
                _ => None,
            },
        },
        None => PlacementOutcome::Leaderless {
            replicas: placement.replicas,
        },
    }
}

/// Convenience: decide a placement and return JUST the committable command, or `None` if no eligible
/// leader exists (the leaderless, fail-closed case). The `under_replicated` reason is dropped; use
/// [`decide_placement`] when the caller needs it.
#[must_use]
pub fn placement_command(
    partition: u64,
    candidates: &[PlacementNode],
    r: usize,
    committed_hw: u64,
    epoch: u64,
    leader_load: &LeaderLoad,
) -> Option<MetadataCommand> {
    match decide_placement(partition, candidates, r, committed_hw, epoch, leader_load) {
        PlacementOutcome::Placed { command, .. } => Some(command),
        PlacementOutcome::Leaderless { .. } => None,
    }
}

/// The outcome of re-assigning a partition's leadership after its leader DIED / left the cluster
/// (V2-C5-I3, #618): a pure-metadata FAILOVER that promotes an in-sync follower already holding the
/// committed log — NO data copy. Either a committable [`MetadataCommand::PlacePartition`] naming the
/// new leader (chosen ONLY from the in-sync, complete survivors), or a flagged "no eligible successor"
/// outcome (every survivor is stale / out-of-ISR / divergent) which is NEVER committed — fail-closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailoverOutcome {
    /// An in-sync, complete survivor was promoted: this is the [`MetadataCommand::PlacePartition`] to
    /// commit through the metadata raft log. Its `epoch` STRICTLY exceeds the dead leader's (the
    /// KIP-101 fence), its `replicas` are the old replica set MINUS the dead leader (no node moves —
    /// the survivors already hold the log), and its `leader` is the chosen ISR successor.
    Promoted {
        /// The command to commit through the metadata raft log (one entry, all nodes converge on it).
        command: MetadataCommand,
        /// The successor node id promoted to leader (always an in-sync, complete survivor).
        successor: u64,
    },
    /// No surviving replica is eligible to lead (every survivor is out-of-ISR, behind the committed HW,
    /// or divergent). NO command is produced — the partition is left leaderless (unavailable for
    /// writes) until an eligible replica appears, rather than promoting a stale/incomplete successor
    /// that would lose committed data. Fail-closed (the data-plane analogue of the #700 restriction).
    NoEligibleSuccessor {
        /// The surviving replica nodes (they back-fill toward eligibility), for observability.
        survivors: Vec<u64>,
    },
}

/// Re-assign `partition`'s leadership after its `dead_leader` died / left (the #618 leaderless
/// FAILOVER). The successor is chosen ONLY from the SURVIVING replicas that are in-sync and complete to
/// the committed high-watermark (the ISR — the set that already holds every quorum-acked record), via
/// the SAME [`place_partition`] eligibility policy a fresh placement uses; so a stale / out-of-ISR /
/// divergent survivor can NEVER be promoted (committed data is never lost on failover).
///
/// The result is a SINGLE [`MetadataCommand::PlacePartition`] (committed through the metadata raft log,
/// so every node converges on the same new placement — no per-node ad-hoc decision):
///
/// * its `replicas` are `placement.replicas` with `dead_leader` REMOVED (no node moves — the surviving
///   replicas already hold the log; failover is pure metadata, zero byte copy);
/// * its `leader` is the chosen in-sync, complete successor; and
/// * its `epoch` is `max(placement.epoch, dead_leader_epoch) + 1` — STRICTLY above the dead leader's,
///   so a stale/returning old leader is FENCED (KIP-101): followers reject its stale epoch.
///
/// `survivor_states` carries each surviving replica's projected [`PlacementNode`] (build them with
/// [`placement_node_from`] from the partition's [`IsrTracker`] + each survivor's durable frontier +
/// its C4 divergence report). `committed_hw` is the cluster-known committed high-watermark the
/// successor must be complete to; `leader_load` balances the choice across the survivors (least-loaded
/// eligible, ties by ascending id — deterministic).
///
/// Returns [`FailoverOutcome::Promoted`] with the command when an eligible successor exists, or
/// [`FailoverOutcome::NoEligibleSuccessor`] (NO command — fail-closed) when none does. Deterministic
/// and IO-free (it reads no wall clock; the choice is the pure [`place_partition`] policy).
///
/// The single-node degenerate case never reaches here: a lone replica IS the leader, so there is no
/// surviving replica to fail over TO. Off-cluster this is never constructed at all.
#[must_use]
#[allow(clippy::too_many_arguments)]
// each input is a distinct, irreducible fact about the failover: which partition, which leader died,
// the old replica set + epoch, the dead leader's own epoch (for the fence), the survivors' ISR-aware
// states, the committed HW the successor must be complete to, and the leader-load balance. A bundling
// struct would only move the noise; the inputs match the sibling `decide_placement` shape.
pub fn reassign_leadership(
    partition: u64,
    dead_leader: u64,
    placement_replicas: &[u64],
    placement_epoch: u64,
    dead_leader_epoch: u64,
    survivor_states: &[PlacementNode],
    committed_hw: u64,
    leader_load: &LeaderLoad,
) -> FailoverOutcome {
    // The surviving replica set: the old replicas MINUS the dead leader. No node MOVES — every survivor
    // already holds the log; the new placement just re-points leadership. The candidate set passed to
    // the policy is the survivors' projected states (already restricted to surviving replicas), so an
    // already-dead or unknown node is never a candidate.
    let survivors: Vec<u64> = placement_replicas
        .iter()
        .copied()
        .filter(|&n| n != dead_leader)
        .collect();
    // The new epoch STRICTLY exceeds both the placement's current epoch and the dead leader's epoch, so
    // the dead leader is fenced regardless of which was higher (saturating so the arithmetic is safe).
    let new_epoch = placement_epoch.max(dead_leader_epoch).saturating_add(1);

    // Choose a leader using the SAME eligible-leader-only policy a fresh placement uses, over EXACTLY
    // the surviving replicas at replication factor = the survivor count (we do NOT re-replicate / move
    // data here — failover is leadership-only; widening the replica set is a separate rebalance, #617).
    // `place_partition` filters to in-ISR + complete (>= committed_hw) + non-divergent candidates and
    // picks the least-loaded eligible one, so a stale/incomplete survivor can never be chosen.
    let r = survivors.len().max(1);
    let placed = place_partition(survivor_states, r, committed_hw, leader_load);
    match placed.leader {
        Some(successor) => FailoverOutcome::Promoted {
            command: MetadataCommand::PlacePartition {
                partition,
                // Use the deterministic surviving replica set (leader-first ordering does not matter to
                // the state machine; the command's leader field is authoritative). We keep the full
                // surviving set rather than `placed.replicas` so a survivor that is momentarily
                // ineligible to LEAD still keeps its replica slot (it back-fills toward eligibility).
                replicas: survivors,
                leader: successor,
                epoch: new_epoch,
            },
            successor,
        },
        None => FailoverOutcome::NoEligibleSuccessor { survivors },
    }
}

/// Build a [`PlacementNode`] for `node` from the leader's [`IsrTracker`], the node's reported durable
/// (fsync'd) frontier, and the (optional) C4 [`DivergenceReport`] for it — the SAME projection
/// [`super::eligibility::replica_state_from`] uses, so a node placed here is eligible to LEAD iff it is
/// eligible to WIN the partition's election (#700). `failure_domain` is the operator-assigned domain
/// label (a rack / host / AZ id) when the membership models it, else `None`.
///
/// Returns `None` if `node` is neither the leader nor a tracked follower (an unknown node is never a
/// placement candidate).
#[must_use]
pub fn placement_node_from(
    tracker: &IsrTracker,
    node: u64,
    durable_prefix: u64,
    failure_domain: Option<u64>,
    divergence: Option<&DivergenceReport>,
) -> Option<PlacementNode> {
    let in_isr = if node == tracker.leader_id() {
        true
    } else {
        match tracker.membership(node)? {
            IsrMembership::InSync => true,
            IsrMembership::EvictedForLag => false,
        }
    };
    let divergent = divergence.is_some_and(|d| !d.is_clean());
    Some(PlacementNode {
        node,
        failure_domain,
        in_isr,
        durable_prefix,
        divergent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::isr::{AckReplicatedBody, IsrConfig};
    use crate::cluster::state_machine::{MetadataStateMachine, Placement};

    fn nodes(ids: &[u64]) -> Vec<PlacementNode> {
        ids.iter()
            .map(|&n| PlacementNode::healthy(n, 100))
            .collect()
    }

    #[test]
    fn decide_placement_emits_a_place_partition_command() {
        let outcome = decide_placement(5, &nodes(&[1, 2, 3]), 3, 100, 7, &LeaderLoad::new());
        match outcome {
            PlacementOutcome::Placed {
                command,
                under_replicated,
            } => {
                assert_eq!(under_replicated, None, "3 nodes, R=3 is fully replicated");
                match command {
                    MetadataCommand::PlacePartition {
                        partition,
                        replicas,
                        leader,
                        epoch,
                    } => {
                        assert_eq!(partition, 5);
                        assert_eq!(epoch, 7);
                        assert_eq!(replicas.len(), 3, "R distinct replicas");
                        assert!(
                            replicas.contains(&leader),
                            "the leader is one of the replicas"
                        );
                    }
                    other => panic!("expected PlacePartition, got {other:?}"),
                }
            }
            PlacementOutcome::Leaderless { .. } => panic!("expected Placed, got Leaderless"),
        }
    }

    #[test]
    fn the_committed_placement_holds_the_replica_set_and_an_eligible_leader() {
        // The end-to-end shape: decide -> command -> apply into the state machine -> read it back.
        let outcome = decide_placement(9, &nodes(&[1, 2, 3]), 3, 100, 4, &LeaderLoad::new());
        let command = match outcome {
            PlacementOutcome::Placed { command, .. } => command,
            PlacementOutcome::Leaderless { .. } => panic!("expected Placed, got Leaderless"),
        };
        let mut sm = MetadataStateMachine::new();
        sm.apply(1, &command);
        let placement: Placement = sm.placement(9).expect("placement committed");
        assert_eq!(placement.replication_factor(), 3);
        assert!(
            placement.replicas.contains(&placement.leader),
            "the committed leader is one of the committed replicas"
        );
    }

    #[test]
    fn a_stale_replica_is_never_committed_as_leader() {
        // Node 1 is behind the committed HW (stale). The emitted command's leader must be eligible —
        // never node 1 — so the stale node can never be COMMITTED as leader.
        let candidates = vec![
            PlacementNode::healthy(1, 60), // stale: durable 60 < HW 100
            PlacementNode::healthy(2, 100),
            PlacementNode::healthy(3, 100),
        ];
        let outcome = decide_placement(1, &candidates, 3, 100, 1, &LeaderLoad::new());
        if let PlacementOutcome::Placed { command, .. } = outcome {
            if let MetadataCommand::PlacePartition {
                leader, replicas, ..
            } = command
            {
                assert!(
                    replicas.contains(&1),
                    "the stale node still HOLDS a replica"
                );
                assert_ne!(
                    leader, 1,
                    "but the stale node is NEVER the committed leader"
                );
            } else {
                panic!("expected PlacePartition");
            }
        } else {
            panic!("expected Placed (an eligible leader exists among 2/3)");
        }
    }

    #[test]
    fn no_eligible_leader_yields_leaderless_and_no_command() {
        // Every candidate is behind the committed HW: no command is produced (fail-closed), so a
        // stale/corrupt replica is never committed as leader.
        let candidates = vec![
            PlacementNode::healthy(1, 50),
            PlacementNode::healthy(2, 50),
            PlacementNode::healthy(3, 50),
        ];
        let outcome = decide_placement(1, &candidates, 3, 100, 1, &LeaderLoad::new());
        assert!(
            matches!(outcome, PlacementOutcome::Leaderless { .. }),
            "no eligible replica => leaderless, never a stale committed leader"
        );
        assert_eq!(
            placement_command(1, &candidates, 3, 100, 1, &LeaderLoad::new()),
            None
        );
    }

    #[test]
    fn placement_node_from_projects_an_evicted_follower_as_out_of_isr() {
        // A 3-node tracker; follower 3 lags out of the ISR. The projected placement node is not-in-ISR,
        // so it is never chosen leader by the policy.
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
            fsynced_offset: 50, // lag 50 > 10 => evicted
        });

        let leader = placement_node_from(&tracker, 1, 100, None, None).unwrap();
        assert!(leader.in_isr);
        let f2 = placement_node_from(&tracker, 2, 95, None, None).unwrap();
        assert!(f2.in_isr);
        let f3 = placement_node_from(&tracker, 3, 50, None, None).unwrap();
        assert!(!f3.in_isr, "the evicted follower projects as out-of-ISR");

        // Placing over these projected nodes never makes the evicted follower leader.
        let candidates = vec![leader, f2, f3];
        let cmd = placement_command(7, &candidates, 3, 95, 1, &LeaderLoad::new()).unwrap();
        if let MetadataCommand::PlacePartition { leader, .. } = cmd {
            assert_ne!(
                leader, 3,
                "the out-of-ISR follower is never the placed leader"
            );
        } else {
            panic!("expected PlacePartition");
        }

        // An unknown node is not a placement candidate.
        assert!(placement_node_from(&tracker, 99, 0, None, None).is_none());
    }

    // ----- #618 leaderless-node failover: re-assign leadership to an in-sync survivor, no data move ---

    #[test]
    fn failover_promotes_an_in_sync_survivor_and_bumps_the_epoch() {
        // Partition led by node 1 over replicas {1,2,3} at epoch 5. Node 1 dies. Survivors 2 + 3 are
        // both in-sync + complete to the committed HW. The failover promotes one of them (deterministic:
        // least-loaded, ties by ascending id => node 2), drops the dead leader from the replica set, and
        // bumps the epoch STRICTLY above 5 (the fence). No node moves — the survivors already hold the log.
        let survivors = vec![
            PlacementNode::healthy(2, 100),
            PlacementNode::healthy(3, 100),
        ];
        let outcome =
            reassign_leadership(0, 1, &[1, 2, 3], 5, 5, &survivors, 100, &LeaderLoad::new());
        match outcome {
            FailoverOutcome::Promoted { command, successor } => {
                assert_eq!(
                    successor, 2,
                    "deterministic: least-loaded eligible, ties by ascending id"
                );
                match command {
                    MetadataCommand::PlacePartition {
                        partition,
                        replicas,
                        leader,
                        epoch,
                    } => {
                        assert_eq!(partition, 0);
                        assert_eq!(
                            replicas,
                            vec![2, 3],
                            "the dead leader is dropped; survivors keep their slots"
                        );
                        assert_eq!(leader, 2);
                        assert!(
                            replicas.contains(&leader),
                            "the new leader is one of the replicas"
                        );
                        assert_eq!(
                            epoch, 6,
                            "the epoch is bumped STRICTLY above the dead leader's (5) — the fence"
                        );
                    }
                    other => panic!("expected PlacePartition, got {other:?}"),
                }
            }
            FailoverOutcome::NoEligibleSuccessor { .. } => panic!("expected a promotion"),
        }
    }

    #[test]
    fn failover_never_promotes_a_stale_or_out_of_isr_survivor() {
        // Node 1 dies. Survivor 2 is STALE (durable 60 < committed HW 100) and survivor 3 is OUT of the
        // ISR (in_isr=false). Neither is eligible to lead — there is NO eligible successor, so the
        // failover produces NO command (fail-closed): committed data is never lost by promoting an
        // incomplete replica. The partition is left leaderless until a survivor catches up.
        let mut stale = PlacementNode::healthy(2, 60); // behind the committed HW
        stale.durable_prefix = 60;
        let mut out_of_isr = PlacementNode::healthy(3, 100);
        out_of_isr.in_isr = false;
        let outcome = reassign_leadership(
            0,
            1,
            &[1, 2, 3],
            5,
            5,
            &[stale, out_of_isr],
            100,
            &LeaderLoad::new(),
        );
        match outcome {
            FailoverOutcome::NoEligibleSuccessor { survivors } => {
                assert_eq!(
                    survivors,
                    vec![2, 3],
                    "the survivors are reported (they back-fill)"
                );
            }
            FailoverOutcome::Promoted { successor, .. } => {
                panic!("must NOT promote an ineligible successor, but promoted {successor}")
            }
        }
    }

    #[test]
    fn failover_promotes_the_only_in_sync_survivor_when_the_other_is_ineligible() {
        // Node 1 dies. Survivor 2 is in-sync + complete; survivor 3 is divergent (corrupt). The ONLY
        // eligible successor is node 2 — it is promoted; the corrupt node can never win (the Jepsen fix
        // at failover time). Both survivors keep their replica slot (3 back-fills after a re-sync).
        let healthy = PlacementNode::healthy(2, 100);
        let mut divergent = PlacementNode::healthy(3, 100);
        divergent.divergent = true;
        let outcome = reassign_leadership(
            0,
            1,
            &[1, 2, 3],
            5,
            5,
            &[healthy, divergent],
            100,
            &LeaderLoad::new(),
        );
        match outcome {
            FailoverOutcome::Promoted { command, successor } => {
                assert_eq!(successor, 2, "the corrupt survivor is never promoted");
                if let MetadataCommand::PlacePartition {
                    leader, replicas, ..
                } = command
                {
                    assert_eq!(leader, 2);
                    assert_eq!(replicas, vec![2, 3]);
                } else {
                    panic!("expected PlacePartition");
                }
            }
            FailoverOutcome::NoEligibleSuccessor { .. } => panic!("expected a promotion to node 2"),
        }
    }

    #[test]
    fn failover_emits_exactly_one_metadata_entry_that_applies_to_the_state_machine() {
        // The failover command is ONE metadata entry that applies through the state machine, so every
        // surviving node converges on the SAME new placement (no per-node ad-hoc decision). The applied
        // placement names the successor leader at the bumped epoch over the surviving replica set.
        let survivors = vec![
            PlacementNode::healthy(2, 100),
            PlacementNode::healthy(3, 100),
        ];
        let outcome =
            reassign_leadership(7, 1, &[1, 2, 3], 9, 9, &survivors, 100, &LeaderLoad::new());
        let command = match outcome {
            FailoverOutcome::Promoted { command, .. } => command,
            FailoverOutcome::NoEligibleSuccessor { .. } => panic!("expected a promotion"),
        };
        let mut sm = MetadataStateMachine::new();
        sm.apply(1, &command); // ONE entry
        let placement: Placement = sm.placement(7).expect("the failover placement committed");
        assert_eq!(placement.leader, 2, "the successor leads after failover");
        assert_eq!(
            placement.epoch, 10,
            "the epoch is fenced strictly above the dead leader's (9)"
        );
        assert_eq!(
            placement.replicas,
            vec![2, 3],
            "no node moved; only the dead leader left"
        );
        assert!(placement.replicas.contains(&placement.leader));
    }

    #[test]
    fn failover_fences_against_whichever_epoch_was_higher() {
        // The new epoch must exceed BOTH the placement's epoch and the dead leader's own epoch (they can
        // differ if the dead leader advanced its epoch since the last committed placement). Here the dead
        // leader's epoch (12) exceeds the placement's (8); the fence must be 13, not 9.
        let survivors = vec![PlacementNode::healthy(2, 50)];
        let outcome = reassign_leadership(0, 1, &[1, 2], 8, 12, &survivors, 50, &LeaderLoad::new());
        if let FailoverOutcome::Promoted { command, .. } = outcome {
            if let MetadataCommand::PlacePartition { epoch, .. } = command {
                assert_eq!(
                    epoch, 13,
                    "fenced strictly above the HIGHER of the two epochs (12)"
                );
            } else {
                panic!("expected PlacePartition");
            }
        } else {
            panic!("expected a promotion (the lone survivor is complete to HW 50)");
        }
    }

    #[test]
    fn single_node_emits_a_lone_replica_placement() {
        let candidates = vec![PlacementNode::healthy(1, 42)];
        let cmd = placement_command(0, &candidates, 1, 42, 1, &LeaderLoad::new()).unwrap();
        match cmd {
            MetadataCommand::PlacePartition {
                replicas, leader, ..
            } => {
                assert_eq!(replicas, vec![1], "the lone node holds the only replica");
                assert_eq!(leader, 1, "and leads it");
            }
            other => panic!("expected PlacePartition, got {other:?}"),
        }
    }
}
