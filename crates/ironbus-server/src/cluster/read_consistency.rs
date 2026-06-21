// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cluster READ-consistency tiers: reads that scale with replicas (V2-C6, #620/#621/#622).
//!
//! This is the PURE, IO-free heart of the C6 read story — the watermark math + the read-tier
//! classification that the [`dataplane`](super::dataplane) controller wires onto the off-actor read
//! plane. It holds NO log, NO clock, and does NO IO (exactly like
//! [`ironbus_core::cluster_invariants`]): the caller supplies the offsets / the lease-validity bit and
//! gets back a fail-closed decision. That keeps the load-bearing correctness argument unit-testable
//! against constructed states without standing up a cluster.
//!
//! ## The three read-consistency tiers
//!
//! Where C1-C5 made the cluster committed-safe (consensus, replication, quorum-fsync ack,
//! committed-safe failover), C6 turns "where you read" into a principled CHOICE — not a stale-read
//! bug. There are three tiers, ordered weakest-coupling-to-the-leader to strongest:
//!
//! * **[`ReadTier::FollowerCommitted`] (CRAQ "clean", #621):** a FOLLOWER serves a read LOCALLY — with
//!   NO round-trip to the leader — for any offset at or below its SAFE committed watermark. Read
//!   throughput therefore scales ~linearly with replicas (CRAQ): every replica can serve committed
//!   reads. The safe watermark is the load-bearing bound (below).
//! * **[`ReadTier::FollowerLatest`] (CRAQ "dirty", #621):** a read ABOVE the follower's known safe
//!   watermark needs the leader's CURRENT committed HW before it can be served — a tiny HW-VERSION
//!   query (not the data) to the leader confirms how far the follower may serve, then the follower
//!   serves the now-confirmed prefix LOCALLY (still zero-copy, still no data round-trip). This turns a
//!   stale-follower-read (a NATS bug class) into a strongly-consistent latest read.
//! * **[`ReadTier::LeaderLocal`] (leader-lease linearizable, #620):** the LEASEHOLDER serves a
//!   linearizable read LOCALLY from its own read plane with NO quorum round (0-RTT linearizable read),
//!   valid ONLY while its leader lease is live at the current epoch (the [`#722`](super) fence). If the
//!   lease is in doubt it does NOT serve a stale local read — it refuses ([`LeaderReadDecision::Refuse`]).
//!
//! ## The follower SAFE watermark (the non-negotiable, #621 correctness 1)
//!
//! A follower must NEVER serve a record past the committed bar it can prove it holds. That bar is the
//! MIN of two independently-trustworthy quantities — [`follower_safe_watermark`]:
//!
//! 1. its OWN read plane's [`flushed`](ironbus_storage::read_plane::ReadPlane::flushed) frontier — the
//!    durably-replicated, CRC-revalidated, non-divergent prefix it actually holds (a follower's
//!    [`Log::append`](ironbus_storage::log::Log::append) path gives I1-I4: CRC, longest-valid-prefix
//!    recovery, and the C2-I4/C4 epoch truncation can only ever LOWER it, never expose an uncommitted
//!    record); AND
//! 2. the KNOWN committed HW — the [`CheckpointCommittedHw`](super::state_machine::MetadataCommand::CheckpointCommittedHw)
//!    bar the metadata plane replicated (#722): every offset strictly below it was quorum-fsync'd on
//!    `min_isr` replicas, so it can never be rolled back by a KIP-101 epoch truncation.
//!
//! The MIN is safe because BOTH conditions must hold for an offset to be servable: the follower must
//! durably hold it (1) AND the cluster must have committed it (2). Taking the min means an offset above
//! EITHER bar is withheld. An uncommitted tail the follower happens to hold (flushed but not yet
//! quorum-committed — it can still be epoch-truncated) is excluded by (2); a committed offset the
//! follower has not yet replicated is excluded by (1). Serving `<= min(...)` is exactly the CRAQ clean
//! tier.
//!
//! ## Single-node / no-cluster
//!
//! Nothing here is constructed off-cluster: the [`dataplane`](super::dataplane) controller (which owns
//! these decisions) is built ONLY on a clustered serve, so the single-node consume path never reaches
//! this module — it is zero non-cluster cost BY CONSTRUCTION.

use ironbus_core::types::Offset;

/// The committed read-consistency tier a CONSUMER (or a routing client) asks for. The data plane maps a
/// requested tier + the local role to a concrete serve decision ([`classify_follower_read`] /
/// [`LeaderReadDecision`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadTier {
    /// CRAQ "clean": serve any committed offset (`<=` the follower's SAFE committed watermark) LOCALLY,
    /// no leader round-trip. The throughput-scaling tier (#621).
    FollowerCommitted,
    /// CRAQ "dirty": a read that may reach ABOVE the follower's known safe watermark — confirm the
    /// leader's current committed HW (a tiny HW-version query, NOT the data) before serving the
    /// now-confirmed prefix locally (#621). Strongly-consistent latest read.
    FollowerLatest,
    /// Leader-lease linearizable: the leaseholder serves a 0-RTT linearizable read from its own read
    /// plane while its lease is live at the current epoch (#620).
    LeaderLocal,
}

/// The SAFE committed watermark a follower may serve reads up to: `min(own_flushed, known_committed_hw)`
/// — the bar BOTH durably-held-here AND committed-on-a-quorum. A follower NEVER serves a record at or
/// past this (the per-record bound is `< watermark`, exactly as the read plane's flushed frontier is the
/// exclusive read bound). See the module docs for why the MIN is the safe bar.
///
/// `own_flushed` is the follower's read-plane flushed frontier (its durably-replicated, CRC-revalidated,
/// non-divergent prefix). `known_committed_hw` is the last [`CheckpointCommittedHw`](super::state_machine::MetadataCommand::CheckpointCommittedHw)
/// bar the follower has applied from the replicated metadata (#722); pass `None` when no checkpoint has
/// committed yet, in which case the safe bar is `0` (serve nothing — fail closed — until the cluster has
/// recorded a committed HW the follower can trust).
#[must_use]
pub fn follower_safe_watermark(own_flushed: u64, known_committed_hw: Option<u64>) -> u64 {
    match known_committed_hw {
        // BOTH bars must admit the offset: take the MIN. An uncommitted tail (held but not yet
        // quorum-committed) is cut by the committed-HW bar; a committed offset not yet replicated here
        // is cut by the follower's own flushed frontier.
        Some(hw) => own_flushed.min(hw),
        // No committed-HW checkpoint has been replicated yet: fail closed. The follower has no proof any
        // offset is quorum-committed, so it serves NOTHING locally — a latest read confirms with the
        // leader (the dirty tier), and a clean read simply finds nothing safe yet.
        None => 0,
    }
}

/// The outcome of classifying a FOLLOWER read request against its safe watermark — the pure decision the
/// data plane acts on (#621). It NEVER admits an offset the follower cannot prove is committed-and-held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FollowerReadDecision {
    /// Serve `[from, serve_up_to)` LOCALLY from the follower's read plane — no leader round-trip. The
    /// CRAQ clean serve: every offset in the range is at or below the follower's safe committed
    /// watermark. `serve_up_to` is the exclusive upper bound (it equals the safe watermark clamped to
    /// the request's wanted end), so the follower serves only committed-and-held records.
    ServeLocal {
        /// The first offset to serve (the request's `from`).
        from: Offset,
        /// The exclusive upper bound to serve up to (`<= follower_safe_watermark`). Records at or past
        /// this are NOT served locally.
        serve_up_to: Offset,
    },
    /// The read reaches ABOVE the follower's known safe watermark (a "latest/dirty" read): the data
    /// plane must CONFIRM the leader's current committed HW (a tiny HW-version query) before serving the
    /// confirmed prefix. Carries the follower's current safe watermark so the caller knows the clean
    /// prefix it could serve immediately without confirmation.
    ConfirmWithLeader {
        /// The follower's CURRENT safe watermark (the clean prefix servable without confirmation). The
        /// caller queries the leader for a HW at or above this, then re-classifies.
        current_safe: Offset,
    },
    /// Nothing to serve from this request at this tier (the request is empty, or `from` is already at or
    /// past the safe watermark on a CLEAN-only request). Not an error — the caller serves an empty run.
    Nothing,
}

/// Classify a FOLLOWER read of `[from, wanted_end)` at `tier` against the follower's `safe_watermark`
/// (= [`follower_safe_watermark`]). PURE and fail-closed — it never admits an offset above the proven
/// committed bar.
///
/// * [`ReadTier::FollowerCommitted`] (clean): serve `[from, min(wanted_end, safe_watermark))` locally,
///   or [`FollowerReadDecision::Nothing`] if `from` is already at/past the safe watermark.
/// * [`ReadTier::FollowerLatest`] (dirty): if the wanted range stays at or below the safe watermark it
///   is served locally exactly like the clean tier (no confirmation needed); only if it reaches ABOVE
///   the safe watermark does it return [`FollowerReadDecision::ConfirmWithLeader`] so the caller does the
///   HW-version query first — NEVER speculatively serving unconfirmed bytes.
/// * [`ReadTier::LeaderLocal`] on a FOLLOWER is a wrong-tier request: a follower cannot serve a
///   leader-lease linearizable read, so it degrades to the strongly-consistent latest path
///   ([`FollowerReadDecision::ConfirmWithLeader`]) rather than serving stale local data.
///
/// `wanted_end` is the exclusive upper bound the request wants (e.g. `from + max_records`, saturated);
/// pass `u64::MAX`-saturated for "as much as is safe".
#[must_use]
pub fn classify_follower_read(
    tier: ReadTier,
    from: Offset,
    wanted_end: Offset,
    safe_watermark: u64,
) -> FollowerReadDecision {
    let from_raw = from.get();
    let wanted = wanted_end.get();
    // An empty or backwards request serves nothing (a degenerate `from >= wanted_end`).
    if wanted <= from_raw {
        return FollowerReadDecision::Nothing;
    }
    match tier {
        ReadTier::FollowerCommitted => {
            // Clean: serve only the prefix at or below the safe watermark.
            if from_raw >= safe_watermark {
                FollowerReadDecision::Nothing
            } else {
                FollowerReadDecision::ServeLocal {
                    from,
                    serve_up_to: Offset::new(wanted.min(safe_watermark)),
                }
            }
        }
        ReadTier::FollowerLatest => {
            // Dirty: serve what is PROVABLY committed-and-held right now, and round-trip to confirm the
            // leader's current HW ONLY when `from` is already at/past the known safe watermark — i.e. the
            // follower would otherwise return EMPTY but the caller wants the LATEST. This is the CRAQ
            // dirty semantics: never serve unconfirmed bytes, but never round-trip when there is a clean
            // committed prefix to serve from `from` either.
            //
            // * `from < safe_watermark`: serve `[from, min(wanted, safe_watermark))` LOCALLY — the clean
            //   committed prefix from the requested position, exactly like the clean tier. (If the caller
            //   wants strictly newer-than-safe data it re-reads from the new position, which then lands in
            //   the confirm branch.)
            // * `from >= safe_watermark`: the follower has nothing committed to serve from here with its
            //   current knowledge, so it CONFIRMS the leader's current HW before serving — never
            //   speculatively serving the unconfirmed tail.
            if from_raw < safe_watermark {
                FollowerReadDecision::ServeLocal {
                    from,
                    serve_up_to: Offset::new(wanted.min(safe_watermark)),
                }
            } else {
                FollowerReadDecision::ConfirmWithLeader {
                    current_safe: Offset::new(safe_watermark),
                }
            }
        }
        // A leader-lease linearizable read cannot be served by a follower; do NOT serve stale local
        // data — escalate to the strongly-consistent latest path (confirm with the leader).
        ReadTier::LeaderLocal => FollowerReadDecision::ConfirmWithLeader {
            current_safe: Offset::new(safe_watermark),
        },
    }
}

/// The outcome of asking whether the LEASEHOLDER may serve a leader-lease linearizable LOCAL read
/// (#620). Sound by the #694/#722 fence: a leader on a stale epoch / lapsed lease must NOT serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaderReadDecision {
    /// Serve `[from, serve_up_to)` LOCALLY from the leader's own read plane — a 0-RTT linearizable read.
    /// The lease is live at the current epoch, so the leader's committed prefix IS the linearizable
    /// state. `serve_up_to` is the leader's read-plane flushed frontier clamped to the wanted end.
    ServeLocal {
        /// The first offset to serve.
        from: Offset,
        /// The exclusive upper bound (`<=` the leader's flushed frontier).
        serve_up_to: Offset,
    },
    /// Nothing to serve (empty request, or `from` is already at/past the leader's flushed frontier).
    Nothing,
    /// REFUSE the local read: the lease is in doubt (expired, or this node is not the current
    /// leaseholder / is on a stale epoch). Serving locally would risk a stale read, so the leader does
    /// NOT serve — the caller falls back to a read-index/quorum confirm or returns unavailable. This is
    /// the soundness fence: no serving-as-leader on a stale epoch.
    Refuse,
}

/// Decide whether the LEASEHOLDER may serve a leader-lease linearizable LOCAL read of `[from,
/// wanted_end)` (#620). `lease_valid` is the leaseholder's lease-validity bit at the current monotonic
/// time and epoch — exactly [`can_act_as_leader`](super::metadata_group::MetadataRaftGroup::can_act_as_leader)
/// for the metadata leader, or the per-partition equivalent (a held, unexpired lease under the current
/// epoch). `leader_flushed` is the leader's read-plane flushed frontier (its committed/linearizable
/// prefix).
///
/// Returns [`LeaderReadDecision::Refuse`] when the lease is NOT valid — never a stale local read.
/// Otherwise serves `[from, min(wanted_end, leader_flushed))` from the leader's own read plane.
#[must_use]
pub fn classify_leader_local_read(
    lease_valid: bool,
    from: Offset,
    wanted_end: Offset,
    leader_flushed: u64,
) -> LeaderReadDecision {
    // The SOUNDNESS FENCE: a leader whose lease is in doubt must not serve a local read. No
    // serving-as-leader on a stale epoch (the #694/#722 fence).
    if !lease_valid {
        return LeaderReadDecision::Refuse;
    }
    let from_raw = from.get();
    let wanted = wanted_end.get();
    if wanted <= from_raw || from_raw >= leader_flushed {
        return LeaderReadDecision::Nothing;
    }
    LeaderReadDecision::ServeLocal {
        from,
        serve_up_to: Offset::new(wanted.min(leader_flushed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the SAFE watermark = min(own_flushed, known_committed_hw) (#621 correctness 1) ----------

    #[test]
    fn safe_watermark_is_the_min_of_own_flushed_and_known_committed_hw() {
        // The committed HW is BELOW the follower's flushed prefix: the follower holds an uncommitted
        // tail (flushed but not yet quorum-committed). The safe bar is the committed HW — the
        // uncommitted tail is NEVER servable (it could still be epoch-truncated).
        assert_eq!(follower_safe_watermark(100, Some(80)), 80);
        // The follower has not yet replicated the whole committed prefix: the safe bar is its own
        // flushed frontier — it cannot serve an offset it does not durably hold.
        assert_eq!(follower_safe_watermark(60, Some(80)), 60);
        // Equal: the whole flushed prefix is committed.
        assert_eq!(follower_safe_watermark(80, Some(80)), 80);
    }

    #[test]
    fn no_committed_hw_checkpoint_yet_serves_nothing_fail_closed() {
        // With no replicated committed-HW checkpoint the follower has NO proof any offset is
        // quorum-committed, so the safe bar is 0 (serve nothing locally — fail closed).
        assert_eq!(follower_safe_watermark(100, None), 0);
        assert_eq!(follower_safe_watermark(0, None), 0);
    }

    /// THE safety property: a follower whose FLUSHED prefix is BEYOND the known committed HW serves only
    /// `<= committed HW` — never the uncommitted tail. This is the constructed-state form of the
    /// integration safety test.
    #[test]
    fn a_follower_ahead_of_the_committed_hw_never_serves_the_uncommitted_tail() {
        let own_flushed = 100; // the follower durably holds [0,100)
        let committed_hw = 70; // but only [0,70) is quorum-committed
        let safe = follower_safe_watermark(own_flushed, Some(committed_hw));
        assert_eq!(safe, 70);
        // A clean read asking for everything serves ONLY up to the committed HW (70), never to 100.
        match classify_follower_read(
            ReadTier::FollowerCommitted,
            Offset::ZERO,
            Offset::new(u64::MAX),
            safe,
        ) {
            FollowerReadDecision::ServeLocal { from, serve_up_to } => {
                assert_eq!(from, Offset::ZERO);
                assert_eq!(
                    serve_up_to,
                    Offset::new(70),
                    "never serves the uncommitted tail [70,100)"
                );
            }
            other => panic!("expected a local serve up to the committed HW, got {other:?}"),
        }
        // A read STARTING in the uncommitted tail serves nothing clean.
        assert_eq!(
            classify_follower_read(
                ReadTier::FollowerCommitted,
                Offset::new(85),
                Offset::new(100),
                safe,
            ),
            FollowerReadDecision::Nothing,
        );
    }

    // ---- CRAQ clean tier (FollowerCommitted) ----------------------------------------------------

    #[test]
    fn clean_tier_serves_the_committed_prefix_locally() {
        let safe = follower_safe_watermark(50, Some(50));
        match classify_follower_read(
            ReadTier::FollowerCommitted,
            Offset::new(10),
            Offset::new(30),
            safe,
        ) {
            FollowerReadDecision::ServeLocal { from, serve_up_to } => {
                assert_eq!(from, Offset::new(10));
                assert_eq!(
                    serve_up_to,
                    Offset::new(30),
                    "the whole wanted range is committed"
                );
            }
            other => panic!("expected a local serve, got {other:?}"),
        }
    }

    #[test]
    fn clean_tier_clamps_the_serve_to_the_safe_watermark() {
        let safe = follower_safe_watermark(50, Some(40)); // safe = 40
        match classify_follower_read(
            ReadTier::FollowerCommitted,
            Offset::new(30),
            Offset::new(60),
            safe,
        ) {
            FollowerReadDecision::ServeLocal { serve_up_to, .. } => {
                assert_eq!(
                    serve_up_to,
                    Offset::new(40),
                    "clamped to the safe watermark"
                );
            }
            other => panic!("expected a clamped local serve, got {other:?}"),
        }
    }

    // ---- CRAQ dirty tier (FollowerLatest) -------------------------------------------------------

    #[test]
    fn dirty_tier_serves_the_committed_prefix_from_within_the_safe_watermark() {
        let safe = follower_safe_watermark(100, Some(100));
        // `from` is below the safe watermark: serve the committed prefix locally with NO confirmation.
        assert_eq!(
            classify_follower_read(
                ReadTier::FollowerLatest,
                Offset::new(10),
                Offset::new(90),
                safe,
            ),
            FollowerReadDecision::ServeLocal {
                from: Offset::new(10),
                serve_up_to: Offset::new(90),
            },
        );
    }

    #[test]
    fn dirty_tier_clamps_a_within_range_serve_to_the_safe_watermark_no_confirm() {
        let safe = follower_safe_watermark(50, Some(50)); // safe = 50
                                                          // `from` (40) is below the safe watermark, but the wanted range reaches above it: serve the clean
                                                          // committed prefix [40,50) LOCALLY (never the unconfirmed [50,80)) with no round-trip. The caller
                                                          // that wants strictly-newer data re-reads from 50, which then confirms.
        assert_eq!(
            classify_follower_read(
                ReadTier::FollowerLatest,
                Offset::new(40),
                Offset::new(80),
                safe,
            ),
            FollowerReadDecision::ServeLocal {
                from: Offset::new(40),
                serve_up_to: Offset::new(50),
            },
        );
    }

    #[test]
    fn dirty_tier_confirms_with_the_leader_when_from_is_at_or_past_the_safe_watermark() {
        let safe = follower_safe_watermark(50, Some(50)); // safe = 50
                                                          // `from` (50) is AT the safe watermark: the follower has nothing committed to serve from here, so
                                                          // it confirms the leader's current HW before serving — never speculatively serving [50,80).
        assert_eq!(
            classify_follower_read(
                ReadTier::FollowerLatest,
                Offset::new(50),
                Offset::new(80),
                safe,
            ),
            FollowerReadDecision::ConfirmWithLeader {
                current_safe: Offset::new(50),
            },
        );
    }

    #[test]
    fn a_follower_never_serves_a_leader_local_tier_request_stale() {
        // A LeaderLocal request landing on a follower must NOT serve stale local data; it escalates to
        // the strongly-consistent latest path (confirm with the leader).
        let safe = follower_safe_watermark(50, Some(50));
        assert_eq!(
            classify_follower_read(ReadTier::LeaderLocal, Offset::ZERO, Offset::new(40), safe,),
            FollowerReadDecision::ConfirmWithLeader {
                current_safe: Offset::new(50),
            },
        );
    }

    #[test]
    fn an_empty_or_backwards_request_serves_nothing() {
        let safe = 100;
        for tier in [
            ReadTier::FollowerCommitted,
            ReadTier::FollowerLatest,
            ReadTier::LeaderLocal,
        ] {
            assert_eq!(
                classify_follower_read(tier, Offset::new(10), Offset::new(10), safe),
                FollowerReadDecision::Nothing,
                "an empty request serves nothing at {tier:?}"
            );
            assert_eq!(
                classify_follower_read(tier, Offset::new(20), Offset::new(10), safe),
                FollowerReadDecision::Nothing,
                "a backwards request serves nothing at {tier:?}"
            );
        }
    }

    // ---- leader-lease linearizable LOCAL read (#620) --------------------------------------------

    #[test]
    fn a_valid_leaseholder_serves_a_local_linearizable_read() {
        // The lease is live: the leader serves [from, min(wanted, flushed)) locally with no quorum round.
        assert_eq!(
            classify_leader_local_read(true, Offset::new(10), Offset::new(40), 100),
            LeaderReadDecision::ServeLocal {
                from: Offset::new(10),
                serve_up_to: Offset::new(40),
            },
        );
        // Clamped to the leader's flushed frontier (never serves past its committed prefix).
        assert_eq!(
            classify_leader_local_read(true, Offset::new(10), Offset::new(200), 100),
            LeaderReadDecision::ServeLocal {
                from: Offset::new(10),
                serve_up_to: Offset::new(100),
            },
        );
    }

    #[test]
    fn an_invalid_lease_refuses_the_local_read_never_serving_stale() {
        // The lease is in doubt (expired / not the leaseholder / stale epoch): REFUSE — never a stale
        // local read. This is the #694/#722 soundness fence.
        assert_eq!(
            classify_leader_local_read(false, Offset::ZERO, Offset::new(40), 100),
            LeaderReadDecision::Refuse,
        );
        // Even a fully-committed range is refused while the lease is invalid.
        assert_eq!(
            classify_leader_local_read(false, Offset::ZERO, Offset::new(10), 100),
            LeaderReadDecision::Refuse,
        );
    }

    #[test]
    fn a_valid_leaseholder_with_an_exhausted_range_serves_nothing() {
        // The lease is valid but `from` is already at/past the flushed frontier: nothing to serve.
        assert_eq!(
            classify_leader_local_read(true, Offset::new(100), Offset::new(120), 100),
            LeaderReadDecision::Nothing,
        );
        assert_eq!(
            classify_leader_local_read(true, Offset::new(10), Offset::new(10), 100),
            LeaderReadDecision::Nothing,
        );
    }
}
