// SPDX-License-Identifier: MIT OR Apache-2.0
//! The replica-placement POLICY (V2-C5-I1, #616): the deterministic, IO-free function that decides
//! WHICH nodes hold a partition's `R` replicas and WHICH eligible replica leads it.
//!
//! This is the prerequisite for data-plane serve-wiring: before a partition can be replicated, the
//! cluster must AGREE on the ordered set of `R` nodes that hold it and the one node that leads it.
//! The metadata plane commits that decision as ONE metadata-log entry (a [`crate::placement`]-shaped
//! `Placement`, assigned by a `MetadataCommand` in `ironbus-server`) — NOT a new Raft group per
//! partition, the group-explosion / per-asset-meta-SPOF the design indicts NATS for (`#4502`).
//!
//! The POLICY itself lives HERE, IO-free in `ironbus-core`, for the same reason the leader-eligibility
//! predicate ([`crate::cluster_invariants::LeaderEligibility`]) does: it is a pure function over small
//! value-types, so the identical decision runs in a unit test, a property sweep, AND the running
//! metadata state machine. The `ironbus-server` plane projects its rich cluster state (the live
//! membership table + the ISR tracker + the divergence report) onto these inputs and commits the
//! result; this module never touches the disk, the wire, or the clock.
//!
//! ## The policy in one paragraph (deterministic; same inputs -> same placement)
//!
//! Given the candidate nodes (each with an optional failure-domain label), a replication factor `R`,
//! the cluster-known committed high-watermark, and a running tally of how many partitions each node
//! already LEADS, the policy:
//!
//! 1. **Spreads the `R` replicas across DISTINCT nodes** — a partition is never placed twice on one
//!    node (a node holding two copies tolerates zero of its own failures). Where failure-domain labels
//!    exist, it prefers spreading across DISTINCT domains first (so an entire rack/host/AZ failure
//!    takes at most one replica), filling within a domain only once every domain holds one. If fewer
//!    than `R` distinct nodes (or domains) exist, it places as many as it can and FLAGS the shortfall
//!    in the returned [`Placement::under_replicated`] reason — it never invents a node or doubles up.
//! 2. **Picks a BALANCED, ELIGIBLE leader** — the leader is chosen from the placed replicas that are
//!    ELIGIBLE ([`crate::cluster_invariants::LeaderEligibility`]: in-ISR, complete to the committed HW,
//!    non-divergent), preferring the eligible replica that currently LEADS the FEWEST partitions
//!    (least-loaded leader balancing, ties broken by ascending node id for determinism). A
//!    stale/corrupt/out-of-ISR replica is NEVER chosen leader — the Jepsen-failure prevention,
//!    composed straight into placement.
//!
//! Determinism (I6): the decision reads NO wall clock and NO RNG. Ties are always broken by ascending
//! node id, so the same membership + the same leader tally + the same eligibility inputs yield a
//! byte-identical placement on every voter — which is exactly what a replicated state machine needs.
//!
//! ## Failure domains: modeled, but optional (FLAGGED)
//!
//! A node MAY carry a [`PlacementNode::failure_domain`] label (a small integer the operator assigns —
//! a rack / host / AZ id). When present, the spread prefers distinct domains. When ABSENT (every node
//! `failure_domain == None`), the policy degrades cleanly to plain distinct-NODE spread — which is the
//! current reality, since the metadata membership table does not yet carry domain labels. Wiring a
//! real domain label INTO the membership table (so the metadata plane can supply it) is a follow-up;
//! this module already accepts and honors the label so that wiring is purely additive.
//!
//! ## Scope boundary (FLAGGED)
//!
//! This is the placement POLICY + the placement VALUE only. It DECIDES a placement; it does not ACT on
//! one. The cooperative REBALANCE on node join/leave (minimal-reshuffle learner back-fill) is C5-I2
//! (#617); leaderless-node FAILOVER is C5-I3 (#618); the DATA-plane serve-wiring that actually
//! replicates to the placed replicas is a follow-up. None of those are done here.
//!
//! ## Single node is degenerate (the Edge-First non-negotiable)
//!
//! With `n = 1` the lone node is the only candidate: it trivially HOLDS the single replica and (being
//! its own ISR, complete to its own HW, unable to diverge from itself) is trivially ELIGIBLE, so it
//! LEADS. The placement is `{ replicas: [the node], leader: the node }` with no shortfall — exactly
//! the degenerate "the lone node holds + leads everything" the single-node broker already implies. A
//! standalone broker never constructs a placement at all; this is the n=1 cluster case.

use crate::cluster_invariants::{LeaderCandidate, LeaderEligibility};
use std::collections::{BTreeMap, BTreeSet};

/// One candidate node the placement policy may place a replica on: its cluster node id, an optional
/// failure-domain label, and the leader-completeness inputs the eligibility predicate needs.
///
/// The `ironbus-server` plane builds this from its membership table (the id + domain) and the live ISR
/// tracker + divergence report (the eligibility fields), exactly as
/// [`crate::cluster_invariants::LeaderCandidate`] is built for the eligibility predicate today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementNode {
    /// The candidate node's cluster id.
    pub node: u64,
    /// The node's failure-domain label (a rack / host / AZ id the operator assigns), if known. `None`
    /// means the cluster does not (yet) model this node's domain, and the policy spreads by node only.
    pub failure_domain: Option<u64>,
    /// Whether this node is currently in the in-sync replica set (the #691 ISR). A node that is not
    /// in-sync may still HOLD a replica (it back-fills), but it is NOT eligible to LEAD.
    pub in_isr: bool,
    /// The node's durable (fsync'd) prefix frontier: the first offset it has NOT durably appended. A
    /// node behind the committed HW is missing committed records and is not eligible to lead.
    pub durable_prefix: u64,
    /// Whether a divergence has been detected for this node's log against the committed lineage (#697).
    /// A divergent node holds corrupt data and is never eligible to lead.
    pub divergent: bool,
}

impl PlacementNode {
    /// A convenience constructor for a node with NO failure-domain label and the leader-completeness
    /// inputs of a healthy, in-sync, complete, non-divergent replica (the common test / n=1 case).
    #[must_use]
    pub fn healthy(node: u64, durable_prefix: u64) -> Self {
        PlacementNode {
            node,
            failure_domain: None,
            in_isr: true,
            durable_prefix,
            divergent: false,
        }
    }

    /// Set this node's failure-domain label (builder-style), returning the updated node.
    #[must_use]
    pub fn with_failure_domain(mut self, domain: u64) -> Self {
        self.failure_domain = Some(domain);
        self
    }

    /// Project this node onto the IO-free [`LeaderCandidate`] the eligibility predicate consumes — the
    /// SAME projection [`crate::cluster_invariants::LeaderEligibility`] uses, so a node is eligible to
    /// LEAD a partition iff it would be eligible to win that partition's election.
    #[must_use]
    fn as_candidate(&self) -> LeaderCandidate {
        LeaderCandidate {
            replica: self.node,
            in_isr: self.in_isr,
            durable_prefix: self.durable_prefix,
            divergent: self.divergent,
        }
    }
}

/// Why a partition could not be placed at the full replication factor `R`. A placement that achieves
/// `R` distinct replicas with an eligible leader carries `None`; a degraded placement explains itself
/// (never a silent shortfall), so the metadata plane can surface it and a later rebalance (C5-I2) can
/// repair it once more capacity exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementShortfall {
    /// Fewer than `R` distinct candidate NODES exist, so the partition is under-replicated. The
    /// placement holds as many distinct nodes as the cluster offers.
    TooFewNodes {
        /// The replication factor that was requested.
        requested: usize,
        /// The number of distinct replicas actually placed.
        placed: usize,
    },
    /// `R` replicas were placed, but NONE of them is eligible to lead (every placed replica is
    /// out-of-ISR, behind the committed HW, or divergent). The placement holds the replicas but has NO
    /// leader — the partition is unavailable for writes until an eligible replica appears (which a
    /// re-sync / rebalance will produce). This is fail-closed: a stale/corrupt replica is NEVER named
    /// leader just to fill the slot.
    NoEligibleLeader {
        /// The number of replicas placed (all ineligible to lead).
        placed: usize,
    },
}

/// A computed replica placement for one partition: the ordered set of `R` (or as many as possible)
/// distinct replica nodes plus the designated leader among them. This is the value the metadata plane
/// commits as ONE metadata-log entry; reads serve the committed value.
///
/// `replicas` is in placement order (the order the spread chose, leader-first when a leader was
/// designated); `leader` is `Some(node)` iff an ELIGIBLE replica was found, else `None` with a
/// [`PlacementShortfall::NoEligibleLeader`] reason. `under_replicated` is `Some(reason)` iff the
/// placement is degraded (fewer than `R` replicas, or no eligible leader).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The ordered set of distinct replica nodes (leader first when a leader was designated).
    pub replicas: Vec<u64>,
    /// The designated leader (an ELIGIBLE replica), or `None` if no placed replica is eligible to lead.
    pub leader: Option<u64>,
    /// `Some(reason)` iff the placement is degraded (under-replicated or leaderless); `None` if it
    /// achieved `R` distinct replicas with an eligible leader.
    pub under_replicated: Option<PlacementShortfall>,
}

impl Placement {
    /// The number of distinct replicas this placement holds.
    #[must_use]
    pub fn replication_factor(&self) -> usize {
        self.replicas.len()
    }

    /// Whether the placement is fully healthy: `R` distinct replicas AND an eligible leader.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.under_replicated.is_none()
    }
}

/// The leader-balance tally the policy reads (and the caller maintains across a batch of placements):
/// how many partitions each node currently LEADS. Passing the running tally in — rather than computing
/// it from nothing — is what lets a sweep of placements spread leadership evenly across nodes (each
/// placement picks the least-loaded eligible node, then the caller bumps that node's count).
///
/// It is a plain `BTreeMap` (deterministic iteration order) so the balance decision is reproducible.
pub type LeaderLoad = BTreeMap<u64, usize>;

/// Compute the placement for ONE partition deterministically.
///
/// * `candidates` — the nodes the partition MAY be placed on (the cluster membership, projected). The
///   order is irrelevant to the result: the policy sorts internally so the placement is a pure function
///   of the SET of candidates, not their argument order.
/// * `replication_factor` — the desired `R` (clamped to `>= 1`; `0` is treated as `1`).
/// * `committed_hw` — the cluster-known committed high-watermark the leader must be complete to.
/// * `leader_load` — how many partitions each node currently leads (for least-loaded leader balancing).
///   READ-ONLY here; the caller bumps the chosen leader's count (see [`place_partitions`]).
///
/// The result spreads the `R` replicas across distinct nodes (distinct failure domains first, when
/// labeled) and designates the least-loaded ELIGIBLE replica as leader. It reads no wall clock and no
/// RNG; ties break by ascending node id, so it is fully deterministic (I6).
#[must_use]
pub fn place_partition(
    candidates: &[PlacementNode],
    replication_factor: usize,
    committed_hw: u64,
    leader_load: &LeaderLoad,
) -> Placement {
    let r = replication_factor.max(1);

    // Spread the R replicas across distinct nodes, preferring distinct failure domains. The candidate
    // set is reduced to one entry per node id (a duplicate id is ignored, never doubled up) and sorted
    // by (failure_domain, node) so the spread is deterministic regardless of input order.
    let replicas = spread_replicas(candidates, r);

    // Pick the least-loaded ELIGIBLE leader from the placed replicas. Eligibility composes the SAME
    // predicate as a partition election, so a stale/corrupt/out-of-ISR replica is never named leader.
    let by_id: BTreeMap<u64, &PlacementNode> = candidates.iter().map(|c| (c.node, c)).collect();
    let leader = choose_leader(&replicas, &by_id, committed_hw, leader_load);

    // Order the replica list leader-first (a stable, deterministic presentation) when a leader exists.
    let ordered = order_leader_first(replicas, leader);

    let under_replicated = if ordered.len() < r {
        Some(PlacementShortfall::TooFewNodes {
            requested: r,
            placed: ordered.len(),
        })
    } else if leader.is_none() {
        Some(PlacementShortfall::NoEligibleLeader {
            placed: ordered.len(),
        })
    } else {
        None
    };

    Placement {
        replicas: ordered,
        leader,
        under_replicated,
    }
}

/// Compute placements for a BATCH of partitions, balancing leadership ACROSS the batch.
///
/// This is the function that delivers "leaders balanced across nodes": it threads a running
/// [`LeaderLoad`] tally through the partitions in ascending id order, so each partition's leader is the
/// least-loaded eligible node AT THAT POINT, and the next partition sees the updated tally. Over many
/// partitions on a healthy cluster this round-robins leadership evenly (no node piles up
/// disproportionately many leaders).
///
/// `partitions` is the list of partition ids to place; the same `candidates` / `replication_factor` /
/// `committed_hw` apply to all of them (the common case — a per-partition override is a future
/// refinement). Returns a deterministic map of partition id -> its [`Placement`]. Reads no wall clock.
#[must_use]
pub fn place_partitions(
    partitions: &[u64],
    candidates: &[PlacementNode],
    replication_factor: usize,
    committed_hw: u64,
) -> BTreeMap<u64, Placement> {
    let mut load: LeaderLoad = LeaderLoad::new();
    let mut out: BTreeMap<u64, Placement> = BTreeMap::new();
    // Place in ascending partition id so the balance is reproducible regardless of input order.
    let mut ids: Vec<u64> = partitions.to_vec();
    ids.sort_unstable();
    ids.dedup();
    for partition in ids {
        let placement = place_partition(candidates, replication_factor, committed_hw, &load);
        if let Some(leader) = placement.leader {
            *load.entry(leader).or_insert(0) += 1;
        }
        out.insert(partition, placement);
    }
    out
}

/// Spread up to `r` replicas across distinct nodes, preferring distinct failure domains.
///
/// Dedup by node id, then sort by `(failure_domain, node_id)` (an unlabeled node sorts as if its domain
/// were the maximum, so labeled domains are filled first). Walk the sorted candidates in ROUNDS: each
/// round takes one node from each not-yet-used domain (and one per unlabeled node), so the first `r`
/// chosen land in as many distinct domains as exist before any domain gets a second replica.
fn spread_replicas(candidates: &[PlacementNode], r: usize) -> Vec<u64> {
    // One entry per node id (lowest occurrence wins is irrelevant — same id, same node), sorted for
    // determinism by (domain-present-first, domain, node).
    let mut nodes: Vec<&PlacementNode> = {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut v: Vec<&PlacementNode> = Vec::new();
        for c in candidates {
            if seen.insert(c.node) {
                v.push(c);
            }
        }
        v
    };
    // Sort key: labeled domains first (ascending), then unlabeled; ties by node id. `None` domains sort
    // after every labeled one but among themselves keep ascending node order.
    nodes.sort_by(|a, b| {
        let ka = a.failure_domain;
        let kb = b.failure_domain;
        match (ka, kb) {
            (Some(x), Some(y)) => x.cmp(&y).then(a.node.cmp(&b.node)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.node.cmp(&b.node),
        }
    });

    // Round-robin across distinct domains: a node with no domain label is its own singleton "domain"
    // keyed by a unique sentinel so two unlabeled nodes are never treated as the same domain.
    let mut chosen: Vec<u64> = Vec::with_capacity(r.min(nodes.len()));
    let mut used_in_domain: BTreeMap<DomainKey, usize> = BTreeMap::new();
    let mut round = 0usize;
    while chosen.len() < r && chosen.len() < nodes.len() {
        let mut progressed = false;
        for n in &nodes {
            if chosen.len() >= r {
                break;
            }
            if chosen.contains(&n.node) {
                continue;
            }
            let key = domain_key(n);
            let count = used_in_domain.get(&key).copied().unwrap_or(0);
            // In round `k` (0-based) take a node from a domain only if it already holds exactly `k`
            // replicas — i.e. every domain gets its first replica before any gets its second.
            if count == round {
                chosen.push(n.node);
                *used_in_domain.entry(key).or_insert(0) += 1;
                progressed = true;
            }
        }
        if !progressed {
            // No domain could take another replica at this round level: every remaining slot would
            // double a domain, so advance the round (allow a second replica per domain) — but only if
            // there are still unplaced nodes, which the outer `while` guards.
            round += 1;
        }
        // Safety: `round` can never exceed the node count (each round places at least one node when
        // any node is unplaced), so the loop terminates.
        if round > nodes.len() {
            break;
        }
    }
    chosen
}

/// A domain identity for the round-robin spread: a labeled node groups by its domain; an unlabeled node
/// is its own singleton (keyed by node id) so two unlabeled nodes never collapse into one "domain".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DomainKey {
    Labeled(u64),
    Unlabeled(u64),
}

fn domain_key(n: &PlacementNode) -> DomainKey {
    match n.failure_domain {
        Some(d) => DomainKey::Labeled(d),
        None => DomainKey::Unlabeled(n.node),
    }
}

/// Choose the least-loaded ELIGIBLE leader from the placed replicas, or `None` if none is eligible.
///
/// Eligibility composes [`LeaderEligibility::is_eligible`] (in-ISR AND complete to `committed_hw` AND
/// non-divergent) — the SAME predicate a partition election uses — so a stale/corrupt/out-of-ISR
/// replica is never returned. Among the eligible replicas, the one currently leading the FEWEST
/// partitions wins (least-loaded balancing); ties break by ascending node id (determinism).
fn choose_leader(
    replicas: &[u64],
    by_id: &BTreeMap<u64, &PlacementNode>,
    committed_hw: u64,
    leader_load: &LeaderLoad,
) -> Option<u64> {
    replicas
        .iter()
        .filter_map(|&node| by_id.get(&node).copied().map(|n| (node, n)))
        .filter(|(_, n)| LeaderEligibility::is_eligible(&n.as_candidate(), committed_hw))
        .min_by(|(a_node, _), (b_node, _)| {
            let la = leader_load.get(a_node).copied().unwrap_or(0);
            let lb = leader_load.get(b_node).copied().unwrap_or(0);
            la.cmp(&lb).then(a_node.cmp(b_node))
        })
        .map(|(node, _)| node)
}

/// Present the replica list leader-first when a leader exists (a stable, deterministic ordering the
/// metadata plane stores), keeping the remaining replicas in ascending node-id order.
fn order_leader_first(replicas: Vec<u64>, leader: Option<u64>) -> Vec<u64> {
    match leader {
        Some(l) if replicas.contains(&l) => {
            let mut rest: Vec<u64> = replicas.into_iter().filter(|&n| n != l).collect();
            rest.sort_unstable();
            let mut out = Vec::with_capacity(rest.len() + 1);
            out.push(l);
            out.extend(rest);
            out
        }
        _ => {
            let mut out = replicas;
            out.sort_unstable();
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy(node: u64) -> PlacementNode {
        PlacementNode::healthy(node, 100)
    }

    // ----- spread: R replicas land on R DISTINCT nodes -----

    #[test]
    fn r_replicas_land_on_r_distinct_nodes() {
        let nodes: Vec<PlacementNode> = (1..=5).map(healthy).collect();
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        assert_eq!(p.replication_factor(), 3);
        let distinct: BTreeSet<u64> = p.replicas.iter().copied().collect();
        assert_eq!(distinct.len(), 3, "all placed replicas are distinct nodes");
        assert!(p.is_complete());
        assert!(p.under_replicated.is_none());
    }

    #[test]
    fn a_node_is_never_placed_twice_even_with_duplicate_candidates() {
        // The same node id appears twice in the candidate list; it must still be placed at most once.
        let nodes = vec![healthy(1), healthy(1), healthy(2)];
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        let distinct: BTreeSet<u64> = p.replicas.iter().copied().collect();
        assert_eq!(distinct.len(), p.replicas.len(), "no node placed twice");
        assert_eq!(p.replicas.len(), 2, "only two distinct nodes exist");
        assert_eq!(
            p.under_replicated,
            Some(PlacementShortfall::TooFewNodes {
                requested: 3,
                placed: 2
            }),
            "fewer than R distinct nodes is a flagged shortfall, not a doubled-up node"
        );
    }

    #[test]
    fn fewer_than_r_nodes_is_flagged_under_replicated() {
        let nodes = vec![healthy(1), healthy(2)];
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        assert_eq!(p.replicas.len(), 2);
        assert_eq!(
            p.under_replicated,
            Some(PlacementShortfall::TooFewNodes {
                requested: 3,
                placed: 2
            })
        );
        assert!(!p.is_complete());
        // Even degraded, a leader is still chosen from the placed (eligible) replicas.
        assert!(p.leader.is_some());
    }

    // ----- failure domains: spread across DISTINCT domains first -----

    #[test]
    fn replicas_spread_across_distinct_failure_domains_first() {
        // Two domains, two nodes each. R=2 must take one from EACH domain (not two from one), so a
        // whole-domain failure loses at most one replica.
        let nodes = vec![
            healthy(1).with_failure_domain(10),
            healthy(2).with_failure_domain(10),
            healthy(3).with_failure_domain(20),
            healthy(4).with_failure_domain(20),
        ];
        let p = place_partition(&nodes, 2, 100, &LeaderLoad::new());
        assert_eq!(p.replicas.len(), 2);
        let domains: BTreeSet<u64> = p
            .replicas
            .iter()
            .map(|n| {
                nodes
                    .iter()
                    .find(|c| c.node == *n)
                    .unwrap()
                    .failure_domain
                    .unwrap()
            })
            .collect();
        assert_eq!(
            domains.len(),
            2,
            "the two replicas land in two distinct domains"
        );
    }

    #[test]
    fn more_replicas_than_domains_doubles_up_only_after_each_domain_has_one() {
        // Two domains, R=3: each domain gets one, then one domain gets a second — never a domain with
        // three while the other has zero.
        let nodes = vec![
            healthy(1).with_failure_domain(10),
            healthy(2).with_failure_domain(10),
            healthy(3).with_failure_domain(20),
        ];
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        assert_eq!(p.replicas.len(), 3);
        let mut per_domain: BTreeMap<u64, usize> = BTreeMap::new();
        for n in &p.replicas {
            let d = nodes
                .iter()
                .find(|c| c.node == *n)
                .unwrap()
                .failure_domain
                .unwrap();
            *per_domain.entry(d).or_insert(0) += 1;
        }
        assert_eq!(per_domain.get(&10), Some(&2));
        assert_eq!(per_domain.get(&20), Some(&1));
    }

    #[test]
    fn unlabeled_nodes_spread_across_distinct_nodes() {
        // With no domain labels the policy degrades to distinct-NODE spread (the current reality).
        let nodes: Vec<PlacementNode> = (1..=4).map(healthy).collect();
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        let distinct: BTreeSet<u64> = p.replicas.iter().copied().collect();
        assert_eq!(distinct.len(), 3);
    }

    // ----- leader balance: leadership is balanced across nodes over many partitions -----

    #[test]
    fn leadership_is_balanced_across_nodes_over_many_partitions() {
        let nodes: Vec<PlacementNode> = (1..=3).map(healthy).collect();
        let partitions: Vec<u64> = (0..30).collect();
        let placements = place_partitions(&partitions, &nodes, 3, 100);

        let mut leader_count: BTreeMap<u64, usize> = BTreeMap::new();
        for p in placements.values() {
            *leader_count
                .entry(p.leader.expect("eligible leader"))
                .or_insert(0) += 1;
        }
        // 30 partitions over 3 nodes: a perfectly balanced round-robin gives each node 10. Assert no
        // node holds disproportionately many leaders (within 1 of the even share).
        for node in 1..=3u64 {
            let c = leader_count.get(&node).copied().unwrap_or(0);
            assert!(
                (9..=11).contains(&c),
                "node {node} leads {c} partitions; expected ~10 (balanced)"
            );
        }
        let max = leader_count.values().max().copied().unwrap_or(0);
        let min = leader_count.values().min().copied().unwrap_or(0);
        assert!(
            max - min <= 1,
            "leadership spread is within 1 (max {max}, min {min})"
        );
    }

    // ----- eligibility composed into placement: a stale/corrupt node is NEVER placed as leader -----

    #[test]
    fn a_stale_replica_is_never_placed_as_leader() {
        // Node 1 is behind the committed HW (stale); nodes 2 and 3 are complete. The leader must be an
        // eligible replica — never the stale node — even if node 1 leads the fewest partitions.
        let nodes = vec![
            PlacementNode::healthy(1, 60), // durable prefix 60 < HW 100 => INELIGIBLE
            PlacementNode::healthy(2, 100),
            PlacementNode::healthy(3, 100),
        ];
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        assert!(
            p.replicas.contains(&1),
            "the stale node still HOLDS a replica"
        );
        let leader = p.leader.expect("an eligible leader exists");
        assert_ne!(leader, 1, "the stale node is NEVER the leader");
        assert!([2, 3].contains(&leader));
    }

    #[test]
    fn a_corrupt_replica_is_never_placed_as_leader() {
        let mut corrupt = PlacementNode::healthy(1, 100);
        corrupt.divergent = true; // detected divergence => INELIGIBLE
        let nodes = vec![
            corrupt,
            PlacementNode::healthy(2, 100),
            PlacementNode::healthy(3, 100),
        ];
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        let leader = p.leader.expect("an eligible leader exists");
        assert_ne!(leader, 1, "the corrupt node is NEVER the leader");
    }

    #[test]
    fn an_out_of_isr_replica_is_never_placed_as_leader() {
        let mut evicted = PlacementNode::healthy(1, 100);
        evicted.in_isr = false; // evicted for lag => INELIGIBLE
        let nodes = vec![
            evicted,
            PlacementNode::healthy(2, 100),
            PlacementNode::healthy(3, 100),
        ];
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        let leader = p.leader.expect("an eligible leader exists");
        assert_ne!(leader, 1, "the out-of-ISR node is NEVER the leader");
    }

    #[test]
    fn no_eligible_replica_yields_a_leaderless_flagged_placement() {
        // Every candidate is ineligible (all behind the committed HW). The replicas are still placed
        // (they back-fill), but NO leader is named — fail-closed, never a stale leader to fill the slot.
        let nodes = vec![
            PlacementNode::healthy(1, 50),
            PlacementNode::healthy(2, 50),
            PlacementNode::healthy(3, 50),
        ];
        let p = place_partition(&nodes, 3, 100, &LeaderLoad::new());
        assert_eq!(
            p.replicas.len(),
            3,
            "replicas are still placed (they back-fill)"
        );
        assert_eq!(p.leader, None, "no eligible replica => no leader");
        assert_eq!(
            p.under_replicated,
            Some(PlacementShortfall::NoEligibleLeader { placed: 3 })
        );
    }

    // ----- determinism (I6): same inputs -> identical placement -----

    #[test]
    fn placement_is_deterministic_regardless_of_input_order() {
        let a = vec![healthy(3), healthy(1), healthy(5), healthy(2), healthy(4)];
        let b = vec![healthy(5), healthy(4), healthy(3), healthy(2), healthy(1)];
        let pa = place_partition(&a, 3, 100, &LeaderLoad::new());
        let pb = place_partition(&b, 3, 100, &LeaderLoad::new());
        assert_eq!(
            pa, pb,
            "the placement is a pure function of the candidate SET, not its order"
        );
    }

    #[test]
    fn batch_placement_is_deterministic() {
        let nodes: Vec<PlacementNode> = (1..=4).map(healthy).collect();
        let partitions: Vec<u64> = (0..20).collect();
        let first = place_partitions(&partitions, &nodes, 3, 100);
        let second = place_partitions(&partitions, &nodes, 3, 100);
        assert_eq!(
            first, second,
            "the same membership + partitions yield an identical batch placement"
        );
    }

    // ----- single node degenerate: n=1 holds + leads everything -----

    #[test]
    fn single_node_holds_and_leads_everything() {
        let lone = vec![PlacementNode::healthy(1, 42)];
        let p = place_partition(&lone, 3, 42, &LeaderLoad::new());
        assert_eq!(p.replicas, vec![1], "the lone node holds the only replica");
        assert_eq!(p.leader, Some(1), "the lone node leads");
        // R=3 requested but only one node exists: a flagged (honest) shortfall, not a silent one.
        assert_eq!(
            p.under_replicated,
            Some(PlacementShortfall::TooFewNodes {
                requested: 3,
                placed: 1
            })
        );
    }

    #[test]
    fn single_node_rf_one_is_a_complete_placement() {
        // The true single-node case (R=1): the lone node holds + leads, with no shortfall at all.
        let lone = vec![PlacementNode::healthy(1, 42)];
        let p = place_partition(&lone, 1, 42, &LeaderLoad::new());
        assert_eq!(p.replicas, vec![1]);
        assert_eq!(p.leader, Some(1));
        assert!(
            p.is_complete(),
            "n=1, R=1 is a complete, degenerate placement"
        );
    }

    #[test]
    fn zero_replication_factor_is_clamped_to_one() {
        let nodes: Vec<PlacementNode> = (1..=3).map(healthy).collect();
        let p = place_partition(&nodes, 0, 100, &LeaderLoad::new());
        assert_eq!(p.replicas.len(), 1, "R=0 is clamped to R=1");
    }
}
