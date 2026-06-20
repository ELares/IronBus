// SPDX-License-Identifier: MIT OR Apache-2.0
//! The leader-epoch cache + divergence-point detection (V2-C2-I4, KIP-101, #599).
//!
//! This is the correctness primitive that makes replication SAFE under a leader change: where
//! [`replication`](../../ironbus-server/src/cluster/replication.rs) (C2-I1, #686) lets a follower
//! PULL the leader's CRC-framed log and [`isr`](../../ironbus-server/src/cluster/isr.rs) (C2-I2,
//! #691) gates a `C2-fsync` ack on a quorum, this module answers the question those two leave open:
//! after a leader CHANGES, a follower may hold uncommitted records from an OLD leader's epoch that
//! the NEW leader never had (or has DIFFERENT records at the same offsets). Truncating such a
//! divergent suffix to the high-watermark is INSUFFICIENT — it can leave divergent committed-looking
//! data or over-truncate good data. Kafka's KIP-101 fix is to track, per log, the LEADER EPOCH a
//! range of records was appended under, and on a leader change to truncate to the DIVERGENCE POINT
//! of the correct lineage — the first offset where the follower's epoch history disagrees with the
//! leader's — keeping the longest common prefix and dropping ONLY the genuinely-divergent suffix.
//!
//! ## The representation — an epoch → start-offset map (the "epoch cache")
//!
//! [`EpochCache`] is exactly Kafka's leader-epoch cache: a strictly-increasing list of
//! [`EpochEntry`] `(epoch, start_offset)` boundaries, where each entry says "every record from
//! `start_offset` (inclusive) up to the NEXT entry's `start_offset` (exclusive) was appended under
//! `epoch`". A leader minting a record at the current epoch [`assign`](EpochCache::assign)s it; the
//! cache appends a NEW boundary ONLY when the epoch actually changes (a leadership change), so the
//! cache is O(number of leadership changes), not O(records) — tiny in practice.
//!
//! ### Why a map, not a per-record stamp (the on-disk-format decision)
//!
//! Stamping each record (or each segment) with its epoch on disk would version the frozen segment
//! format and risk making old logs unreadable. We DELIBERATELY do NOT: the epoch cache is an
//! IN-MEMORY, RECONSTRUCTIBLE structure carried by the cluster layer, never written into a record
//! or segment frame. A follower reconstructs it from the epoch boundaries the leader advertises over
//! the wire (the new `OffsetForLeaderEpoch` exchange, #599) as it replicates; a single node never
//! builds one at all. So the on-disk format is byte-for-byte unchanged, every existing log stays
//! readable, and recovery stays a pure function of the durable bytes (the epoch cache is cluster
//! control state, not log data). This is the same posture `lease.rs` / `leader_lease.rs` take: the
//! fencing metadata is pure, IO-free, and reconstructible, never coupled into the durable log frame.
//!
//! ## Divergence-point detection (the KIP-101 algorithm)
//!
//! [`EpochCache::divergence_point`] computes where a follower must truncate when it adopts a leader.
//! Given the leader's view of "the last offset it holds for a given epoch" (the
//! [`LeaderEpochEndOffset`] the leader answers, Kafka's `OffsetForLeaderEpoch` response), the
//! follower walks its OWN epoch cache from the HIGHEST epoch downward and finds the first epoch the
//! two SHARE; the divergence point is the smaller of (the follower's end-offset for that shared
//! epoch) and (the leader's end-offset for it). The follower truncates to that offset — every record
//! below it is in the common lineage (same epoch history ⇒ byte-identical), every record at or above
//! it is the divergent suffix to drop. This is loss-free for committed data BY CONSTRUCTION: the
//! cluster only ever asks for a divergence point AT OR ABOVE the committed high-watermark (the caller
//! clamps it; see [`DivergencePoint`]), so a record below the HW — fsync'd on a quorum (#691) — is
//! never in a truncated suffix.
//!
//! The whole module is PURE and IO-free, exactly like [`leader_lease`](crate::leader_lease): it
//! holds no clock, does no IO, and never consults the wall clock, so it composes with the
//! single-writer actor without coloring the data path and stays inside `ironbus-core`'s IO-free
//! guarantee. Truncating the actual durable bytes is the storage layer's job
//! ([`Log::truncate_to`](../../ironbus-storage/src/log.rs)); this module only DECIDES the offset.

use crate::leader_lease::LeaderEpoch;
use crate::types::Offset;

/// One boundary in a [`EpochCache`]: the leadership `epoch` a contiguous range of records was
/// appended under, and the `start_offset` (inclusive) of that range. The range runs to the NEXT
/// entry's `start_offset` (exclusive), or to the log's end offset for the final (current) entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochEntry {
    /// The leadership epoch the records `[start_offset, next.start_offset)` were appended under.
    pub epoch: LeaderEpoch,
    /// The first log offset (inclusive) appended under `epoch`.
    pub start_offset: Offset,
}

/// The leader's answer to "what is the last offset you hold for leadership epoch `E`?" — Kafka's
/// `OffsetForLeaderEpoch` response. `end_offset` is the offset just PAST the last record the leader
/// holds under the REQUESTED epoch (so the records under that epoch are `[start, end_offset)`).
///
/// When the leader has the epoch, `end_offset` is the start of the NEXT epoch (or the leader's log
/// end if the requested epoch is the leader's current one). When the leader has NEVER SEEN the
/// requested epoch but DID lead at a HIGHER epoch, it answers the start offset of the FIRST epoch it
/// holds that is strictly greater than the requested one (Kafka's "undefined epoch" handling),
/// which bounds the follower's truncation from above. The `epoch` echoes which epoch this end-offset
/// describes so the follower can match it against its own cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaderEpochEndOffset {
    /// The epoch the follower asked about (echoed for matching).
    pub requested_epoch: LeaderEpoch,
    /// The epoch the `end_offset` actually describes: the requested epoch when the leader holds it,
    /// else the next-higher epoch the leader does hold (the bound). Equal to `requested_epoch` on
    /// the common path.
    pub answered_epoch: LeaderEpoch,
    /// The offset just past the last record the leader holds under `answered_epoch`.
    pub end_offset: Offset,
}

/// The decided truncation target for a follower adopting a (possibly-new) leader: the offset the
/// follower must truncate its log to, keeping `[0, offset)` (the common prefix) and dropping
/// `[offset, ..)` (the divergent suffix). Carries the epoch the divergence was found at and whether
/// any truncation is actually needed, so the caller can REPORT it as a typed event (never a silent
/// drop — the I3 bounded-and-reported discipline lifted to a leader change).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DivergencePoint {
    /// The offset to truncate to: the end of the longest common prefix the follower shares with the
    /// leader. Records at or above this are the divergent suffix.
    pub truncate_to: Offset,
    /// The shared epoch the divergence was resolved at (the highest epoch the follower and leader
    /// have in common at this point). [`LeaderEpoch::GENESIS`] when they share nothing (truncate to
    /// the follower's start, a full re-sync).
    pub diverged_at_epoch: LeaderEpoch,
}

impl DivergencePoint {
    /// True if the follower must actually drop records: its current log end is strictly above the
    /// truncation point. When the follower's end is already at or below `truncate_to` (it holds only
    /// the common prefix), no suffix is divergent and this is `false` — a clean no-op.
    #[must_use]
    pub fn needs_truncation(self, follower_log_end: Offset) -> bool {
        follower_log_end.get() > self.truncate_to.get()
    }
}

/// The errors a leader-epoch cache operation can fail with — all are fail-closed programming-contract
/// violations of the strictly-increasing invariant, never silent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochCacheError {
    /// An [`assign`](EpochCache::assign) tried to record an epoch STRICTLY LOWER than the cache's
    /// current highest — a leadership epoch can only ever move forward (it IS the Raft term, which is
    /// monotonic). Carries the offending and current epochs.
    EpochWentBackward {
        /// The epoch the caller tried to assign.
        attempted: LeaderEpoch,
        /// The cache's current (higher) epoch.
        current: LeaderEpoch,
    },
    /// An [`assign`](EpochCache::assign) tried to start a NEW epoch boundary at an offset at or below
    /// the previous boundary's start — boundaries must strictly increase in offset.
    OffsetWentBackward {
        /// The offset the caller tried to start the new epoch at.
        attempted: Offset,
        /// The previous boundary's start offset (which the new one must exceed).
        previous: Offset,
    },
}

impl core::fmt::Display for EpochCacheError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EpochCacheError::EpochWentBackward { attempted, current } => write!(
                f,
                "epoch cache assign went backward: attempted epoch {} below current {}",
                attempted.get(),
                current.get()
            ),
            EpochCacheError::OffsetWentBackward {
                attempted,
                previous,
            } => write!(
                f,
                "epoch cache boundary offset went backward: attempted {} at or below previous {}",
                attempted.get(),
                previous.get()
            ),
        }
    }
}

/// The leader-epoch cache for ONE partition log: the ordered `(epoch, start_offset)` boundaries that
/// record which leadership epoch each contiguous offset range was appended under (KIP-101). It is the
/// in-memory, reconstructible, IO-free structure the cluster layer carries beside a log — NEVER part
/// of the on-disk frame format.
///
/// Invariants (checked by [`assign`](EpochCache::assign), so the cache can never represent an
/// impossible lineage): the entries are strictly increasing in BOTH `epoch` AND `start_offset`. The
/// first entry's `start_offset` is the log's start offset (0 for a fresh log, or its earliest
/// retained offset after a reap); the last entry's epoch is the current leadership epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochCache {
    /// The boundaries, strictly increasing in epoch and in `start_offset`. Empty before any epoch is
    /// assigned (a fresh follower that has replicated nothing, or a single node that never clusters).
    entries: Vec<EpochEntry>,
}

impl EpochCache {
    /// A fresh, empty epoch cache (no leadership history yet).
    #[must_use]
    pub const fn new() -> EpochCache {
        EpochCache {
            entries: Vec::new(),
        }
    }

    /// Rebuilds a cache from a known set of boundaries (e.g. reconstructed from the leader's
    /// advertised epoch history, or rehydrated after a reopen), validating the strictly-increasing
    /// invariant so a malformed history is rejected fail-closed rather than silently accepted.
    ///
    /// # Errors
    /// Returns [`EpochCacheError`] if `entries` are not strictly increasing in both epoch and offset.
    pub fn from_entries(entries: Vec<EpochEntry>) -> Result<EpochCache, EpochCacheError> {
        let mut cache = EpochCache::new();
        for e in entries {
            cache.assign(e.epoch, e.start_offset)?;
        }
        Ok(cache)
    }

    /// The boundaries, oldest first. The slice is always strictly increasing in epoch and offset.
    #[must_use]
    pub fn entries(&self) -> &[EpochEntry] {
        &self.entries
    }

    /// True if the cache holds no leadership history (a fresh follower / a single node).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The current (highest) leadership epoch the cache records, or [`LeaderEpoch::GENESIS`] if it is
    /// empty.
    #[must_use]
    pub fn current_epoch(&self) -> LeaderEpoch {
        self.entries
            .last()
            .map_or(LeaderEpoch::GENESIS, |e| e.epoch)
    }

    /// Records that records starting at `start_offset` are (and from here on will be) appended under
    /// leadership `epoch`. A NEW boundary is appended ONLY when `epoch` is strictly greater than the
    /// current one (a real leadership change); assigning the SAME epoch again is a no-op (the current
    /// epoch's range simply extends as more records are appended, no new boundary needed). This is
    /// Kafka's `assign` — the cache grows by one entry per leadership change, not per record.
    ///
    /// # Errors
    /// - [`EpochCacheError::EpochWentBackward`] if `epoch` is strictly below the current epoch (a
    ///   leadership epoch is monotonic — it IS the Raft term).
    /// - [`EpochCacheError::OffsetWentBackward`] if a new epoch's `start_offset` is at or below the
    ///   previous boundary's start (boundaries strictly increase in offset).
    pub fn assign(
        &mut self,
        epoch: LeaderEpoch,
        start_offset: Offset,
    ) -> Result<(), EpochCacheError> {
        match self.entries.last().copied() {
            None => {
                self.entries.push(EpochEntry {
                    epoch,
                    start_offset,
                });
                Ok(())
            }
            Some(last) => {
                if epoch < last.epoch {
                    return Err(EpochCacheError::EpochWentBackward {
                        attempted: epoch,
                        current: last.epoch,
                    });
                }
                if epoch == last.epoch {
                    // Same leadership: the current range just extends, no new boundary.
                    return Ok(());
                }
                // A strictly-higher epoch: a leadership change. Its boundary offset must strictly
                // exceed the previous boundary's start (records were appended in between).
                if start_offset.get() <= last.start_offset.get() {
                    return Err(EpochCacheError::OffsetWentBackward {
                        attempted: start_offset,
                        previous: last.start_offset,
                    });
                }
                self.entries.push(EpochEntry {
                    epoch,
                    start_offset,
                });
                Ok(())
            }
        }
    }

    /// The leadership epoch a record at `offset` was appended under, i.e. the epoch of the boundary
    /// whose range contains `offset`. `None` if `offset` is below the cache's first boundary (the
    /// cache does not cover it — e.g. a reaped prefix) or the cache is empty.
    #[must_use]
    pub fn epoch_for_offset(&self, offset: Offset) -> Option<LeaderEpoch> {
        // The boundary with the largest start_offset that is <= offset owns it.
        let idx = self
            .entries
            .partition_point(|e| e.start_offset.get() <= offset.get());
        if idx == 0 {
            return None;
        }
        Some(self.entries[idx - 1].epoch)
    }

    /// The offset just PAST the last record THIS log holds under `epoch`, given the log's current end
    /// offset (`log_end`) — Kafka's "end offset for a leader epoch", the value a LEADER answers to a
    /// follower's `OffsetForLeaderEpoch`. The records under `epoch` are `[start, end_offset)`.
    ///
    /// Resolution, matching Kafka's semantics:
    /// - The cache holds `epoch` exactly: `end_offset` is the start of the NEXT-higher boundary, or
    ///   `log_end` if `epoch` is the current (last) one. `answered_epoch == epoch`.
    /// - The cache does NOT hold `epoch` but holds a HIGHER one: answer the start offset of the
    ///   first boundary strictly greater than `epoch` (the bound: the follower's records under the
    ///   unknown epoch cannot extend past where this log's known higher epoch began).
    ///   `answered_epoch` is that higher epoch.
    /// - `epoch` is at or above the current epoch (the requested epoch is this log's own latest, or
    ///   the cache is empty): answer `log_end` under the current epoch — the follower is fully caught
    ///   up to this log's lineage.
    #[must_use]
    pub fn end_offset_for_epoch(
        &self,
        epoch: LeaderEpoch,
        log_end: Offset,
    ) -> LeaderEpochEndOffset {
        // Find the first boundary whose epoch is STRICTLY GREATER than the requested one.
        let next_idx = self.entries.partition_point(|e| e.epoch <= epoch);
        if next_idx < self.entries.len() {
            // There is a higher epoch boundary. Its start offset bounds the requested epoch's range.
            let next = self.entries[next_idx];
            // Did we actually hold the requested epoch? Yes iff the boundary just before `next_idx`
            // has exactly that epoch.
            let answered_epoch = if next_idx > 0 && self.entries[next_idx - 1].epoch == epoch {
                epoch
            } else {
                // The requested epoch is unknown (it falls in a gap below `next`); answer the
                // next-higher epoch's start as the upper bound (Kafka's undefined-epoch handling).
                next.epoch
            };
            LeaderEpochEndOffset {
                requested_epoch: epoch,
                answered_epoch,
                end_offset: next.start_offset,
            }
        } else {
            // No higher epoch: the requested epoch is at or above this log's current epoch, so the
            // range runs to the log end under the current epoch.
            LeaderEpochEndOffset {
                requested_epoch: epoch,
                answered_epoch: self.current_epoch(),
                end_offset: log_end,
            }
        }
    }

    /// Computes the DIVERGENCE POINT this (follower) cache must truncate to when adopting a leader,
    /// given the follower's own current `log_end` and a way to ask the LEADER for its end-offset of a
    /// given epoch (`leader_end_offset`, which the caller wires to the leader's
    /// [`end_offset_for_epoch`](EpochCache::end_offset_for_epoch) — over the wire in production, or
    /// directly against the leader's cache in a test).
    ///
    /// The KIP-101 algorithm: walk the follower's boundaries from the HIGHEST epoch DOWNWARD. For
    /// each follower epoch, ask the leader for its end-offset of that epoch. The FIRST follower epoch
    /// the leader ALSO holds (its answered epoch equals the requested one) is the shared lineage; the
    /// divergence point is `min(follower_end_offset_for_that_epoch, leader_end_offset)`:
    /// - if the leader's end is LOWER, the follower has extra records under that epoch the leader
    ///   never had ⇒ truncate to the leader's end (drop the divergent tail under a shared epoch);
    /// - if the follower's end is LOWER (or equal), the follower's records under that epoch are a
    ///   prefix of the leader's ⇒ keep them all, truncate only above the follower's end (which is a
    ///   no-op when the follower has nothing above, i.e. it just keeps fetching forward).
    ///
    /// If NO follower epoch is shared with the leader (the leader answered a different/lower epoch for
    /// every one of the follower's), the whole follower log diverges from the start ⇒ truncate to the
    /// follower's first boundary (a full re-sync), reported at [`LeaderEpoch::GENESIS`].
    ///
    /// `leader_end_offset(epoch)` returns the leader's [`LeaderEpochEndOffset`] for `epoch`.
    pub fn divergence_point<L>(&self, log_end: Offset, mut leader_end_offset: L) -> DivergencePoint
    where
        L: FnMut(LeaderEpoch) -> LeaderEpochEndOffset,
    {
        // An empty follower cache shares nothing; it simply fetches forward from its start (no
        // divergent suffix exists because it has no epoch-stamped records). Truncate-to == log_end is
        // a no-op the caller treats as "fetch forward".
        if self.entries.is_empty() {
            return DivergencePoint {
                truncate_to: log_end,
                diverged_at_epoch: LeaderEpoch::GENESIS,
            };
        }
        // Walk follower boundaries highest-epoch first.
        for i in (0..self.entries.len()).rev() {
            let follower_epoch = self.entries[i].epoch;
            // The follower's end offset for this epoch is the next boundary's start, or its log end
            // for the last boundary.
            let follower_end = self
                .entries
                .get(i + 1)
                .map_or(log_end, |next| next.start_offset);
            let leader = leader_end_offset(follower_epoch);
            // The leader SHARES this epoch iff it answered the very epoch we asked about. (When the
            // leader does not hold it, it answers a higher epoch as a bound — not a shared lineage.)
            if leader.answered_epoch == follower_epoch {
                let truncate_to = follower_end.get().min(leader.end_offset.get());
                return DivergencePoint {
                    truncate_to: Offset::new(truncate_to),
                    diverged_at_epoch: follower_epoch,
                };
            }
            // The leader does not hold this follower epoch. If it answered a LOWER epoch (the leader
            // never reached this epoch), the divergence is at or below this epoch's start: keep
            // walking down to the next-lower shared epoch. Its answered end offset still bounds us
            // from above, so remember the tightest bound as we descend.
        }
        // No shared epoch at all: the follower diverges from its very first boundary. Truncate to the
        // follower's start offset (its earliest retained offset) — a full re-sync of this log.
        DivergencePoint {
            truncate_to: self.entries[0].start_offset,
            diverged_at_epoch: LeaderEpoch::GENESIS,
        }
    }

    /// Drops every boundary whose range is entirely at or above `offset`, and clamps a boundary that
    /// straddles `offset` so the cache describes only `[start, offset)` — the in-memory mirror of a
    /// [`Log::truncate_to`](../../ironbus-storage/src/log.rs) on the durable bytes. After this the
    /// cache's covered range ends exactly at `offset`, so a subsequent [`assign`](EpochCache::assign)
    /// of the new leader's epoch starts a boundary at `offset` cleanly.
    ///
    /// A boundary whose `start_offset >= offset` is removed wholesale (its whole range is divergent);
    /// a boundary with `start_offset < offset` is KEPT (its range `[start, offset)` survives). The
    /// kept boundaries' epochs and starts are unchanged — truncation only ever drops a suffix, it
    /// never rewrites a surviving boundary, so the common prefix's epoch history is preserved exactly.
    pub fn truncate_to(&mut self, offset: Offset) {
        self.entries.retain(|e| e.start_offset.get() < offset.get());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn off(v: u64) -> Offset {
        Offset::new(v)
    }
    fn ep(v: u64) -> LeaderEpoch {
        LeaderEpoch::new(v)
    }

    // ----- the representation: assign grows one boundary per leadership change -----

    #[test]
    fn assign_appends_one_boundary_per_epoch_change_not_per_record() {
        let mut cache = EpochCache::new();
        assert!(cache.is_empty());
        // Epoch 1 from offset 0. Re-assigning epoch 1 (as more records append) is a no-op.
        cache.assign(ep(1), off(0)).unwrap();
        cache.assign(ep(1), off(5)).unwrap();
        cache.assign(ep(1), off(9)).unwrap();
        assert_eq!(cache.entries().len(), 1, "same epoch never adds a boundary");
        // Epoch 3 takes over at offset 10 (a leadership change skipped term 2 — terms can skip).
        cache.assign(ep(3), off(10)).unwrap();
        assert_eq!(cache.entries().len(), 2);
        assert_eq!(cache.current_epoch(), ep(3));
        assert_eq!(
            cache.entries(),
            &[
                EpochEntry {
                    epoch: ep(1),
                    start_offset: off(0)
                },
                EpochEntry {
                    epoch: ep(3),
                    start_offset: off(10)
                },
            ]
        );
    }

    #[test]
    fn assign_rejects_a_backward_epoch_or_offset_fail_closed() {
        let mut cache = EpochCache::new();
        cache.assign(ep(5), off(0)).unwrap();
        cache.assign(ep(7), off(10)).unwrap();
        // A lower epoch than the current is rejected (the term is monotonic).
        assert_eq!(
            cache.assign(ep(6), off(20)),
            Err(EpochCacheError::EpochWentBackward {
                attempted: ep(6),
                current: ep(7),
            })
        );
        // A new epoch at an offset not strictly above the previous boundary is rejected.
        assert_eq!(
            cache.assign(ep(8), off(10)),
            Err(EpochCacheError::OffsetWentBackward {
                attempted: off(10),
                previous: off(10),
            })
        );
        // The cache is unchanged by the rejected assigns.
        assert_eq!(cache.entries().len(), 2);
    }

    #[test]
    fn epoch_for_offset_maps_a_record_to_its_leadership_epoch() {
        let cache = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(4),
                start_offset: off(10),
            },
            EpochEntry {
                epoch: ep(9),
                start_offset: off(25),
            },
        ])
        .unwrap();
        assert_eq!(cache.epoch_for_offset(off(0)), Some(ep(1)));
        assert_eq!(cache.epoch_for_offset(off(9)), Some(ep(1)));
        assert_eq!(cache.epoch_for_offset(off(10)), Some(ep(4)));
        assert_eq!(cache.epoch_for_offset(off(24)), Some(ep(4)));
        assert_eq!(cache.epoch_for_offset(off(25)), Some(ep(9)));
        assert_eq!(cache.epoch_for_offset(off(1000)), Some(ep(9)));
    }

    #[test]
    fn end_offset_for_epoch_answers_the_next_boundary_or_log_end() {
        // Leader holds epoch 1 at [0,10), epoch 4 at [10,25), epoch 9 at [25, log_end).
        let cache = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(4),
                start_offset: off(10),
            },
            EpochEntry {
                epoch: ep(9),
                start_offset: off(25),
            },
        ])
        .unwrap();
        let log_end = off(40);
        // A held epoch's end is the next boundary's start.
        let e1 = cache.end_offset_for_epoch(ep(1), log_end);
        assert_eq!(e1.answered_epoch, ep(1));
        assert_eq!(e1.end_offset, off(10));
        let e4 = cache.end_offset_for_epoch(ep(4), log_end);
        assert_eq!(e4.answered_epoch, ep(4));
        assert_eq!(e4.end_offset, off(25));
        // The current (last) epoch's end is the log end.
        let e9 = cache.end_offset_for_epoch(ep(9), log_end);
        assert_eq!(e9.answered_epoch, ep(9));
        assert_eq!(e9.end_offset, log_end);
        // An UNKNOWN epoch BELOW a held higher one: bound by the next-higher boundary's start.
        let e2 = cache.end_offset_for_epoch(ep(2), log_end);
        assert_eq!(e2.answered_epoch, ep(4), "epoch 2 is bounded by epoch 4");
        assert_eq!(e2.end_offset, off(10));
        // An epoch ABOVE the current: caught up to the log end under the current epoch.
        let e_hi = cache.end_offset_for_epoch(ep(99), log_end);
        assert_eq!(e_hi.answered_epoch, ep(9));
        assert_eq!(e_hi.end_offset, log_end);
    }

    // ----- the headline: divergence-point detection across a leader change -----

    #[test]
    fn divergence_point_truncates_a_divergent_suffix_under_a_shared_epoch() {
        // The follower replicated up to offset 30 with epoch history 1@[0,10), 5@[10,30).
        // The NEW leader's history is 1@[0,10), 5@[10,20), 6@[20, end): under the SHARED epoch 5 the
        // leader only ever reached offset 20, so the follower's records [20,30) under epoch 5 are a
        // divergent suffix the new leader never had. Divergence point = 20.
        let follower = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(5),
                start_offset: off(10),
            },
        ])
        .unwrap();
        let leader = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(5),
                start_offset: off(10),
            },
            EpochEntry {
                epoch: ep(6),
                start_offset: off(20),
            },
        ])
        .unwrap();
        let leader_log_end = off(35);
        let dp =
            follower.divergence_point(off(30), |e| leader.end_offset_for_epoch(e, leader_log_end));
        assert_eq!(dp.diverged_at_epoch, ep(5));
        assert_eq!(
            dp.truncate_to,
            off(20),
            "truncate to where the shared epoch 5 ended on the leader"
        );
        assert!(
            dp.needs_truncation(off(30)),
            "the follower must drop [20,30)"
        );
    }

    #[test]
    fn divergence_point_keeps_a_common_prefix_when_the_follower_is_a_strict_prefix() {
        // The follower (offset 15) is a strict PREFIX of the leader under the shared epoch 5: it has
        // [10,15) under epoch 5, the leader has [10,30). Nothing diverges — keep everything, just
        // fetch forward. truncate_to == the follower's own end, so needs_truncation is false.
        let follower = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(5),
                start_offset: off(10),
            },
        ])
        .unwrap();
        let leader = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(5),
                start_offset: off(10),
            },
        ])
        .unwrap();
        let dp = follower.divergence_point(off(15), |e| leader.end_offset_for_epoch(e, off(30)));
        assert_eq!(dp.diverged_at_epoch, ep(5));
        assert_eq!(dp.truncate_to, off(15));
        assert!(
            !dp.needs_truncation(off(15)),
            "a prefix needs no truncation"
        );
    }

    #[test]
    fn divergence_point_descends_past_an_epoch_the_leader_never_reached() {
        // The follower has an epoch 8 the new leader NEVER had (the old leader minted epoch-8 records
        // that never committed anywhere else). The leader's highest epoch is 6. The follower must
        // descend past epoch 8 to the shared epoch 5 and truncate there.
        // Follower: 1@[0,10), 5@[10,20), 8@[20,30).
        let follower = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(5),
                start_offset: off(10),
            },
            EpochEntry {
                epoch: ep(8),
                start_offset: off(20),
            },
        ])
        .unwrap();
        // Leader: 1@[0,10), 5@[10,20), 6@[20, end). It never had epoch 8.
        let leader = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(5),
                start_offset: off(10),
            },
            EpochEntry {
                epoch: ep(6),
                start_offset: off(20),
            },
        ])
        .unwrap();
        let dp = follower.divergence_point(off(30), |e| leader.end_offset_for_epoch(e, off(40)));
        // Shared epoch is 5; the leader's epoch-5 range ended at 20 (epoch 6 started there). The
        // follower's epoch-5 range also ended at 20, so truncate_to = min(20, 20) = 20: drop the
        // whole divergent epoch-8 suffix [20,30).
        assert_eq!(dp.diverged_at_epoch, ep(5));
        assert_eq!(dp.truncate_to, off(20));
        assert!(dp.needs_truncation(off(30)));
    }

    #[test]
    fn divergence_point_across_multiple_epoch_changes_is_correct() {
        // A deeper history with several changes; the divergence is several epochs down.
        // Follower: 2@[0,5), 4@[5,12), 7@[12,20), 11@[20,28).
        let follower = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(2),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(4),
                start_offset: off(5),
            },
            EpochEntry {
                epoch: ep(7),
                start_offset: off(12),
            },
            EpochEntry {
                epoch: ep(11),
                start_offset: off(20),
            },
        ])
        .unwrap();
        // Leader shares 2,4 then diverges: 2@[0,5), 4@[5,12), 8@[12, end). It never had 7 or 11; its
        // epoch-4 range ALSO ended at 12 (epoch 8 took over there), so the common prefix is [0,12).
        let leader = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(2),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(4),
                start_offset: off(5),
            },
            EpochEntry {
                epoch: ep(8),
                start_offset: off(12),
            },
        ])
        .unwrap();
        let dp = follower.divergence_point(off(28), |e| leader.end_offset_for_epoch(e, off(50)));
        assert_eq!(dp.diverged_at_epoch, ep(4));
        assert_eq!(
            dp.truncate_to,
            off(12),
            "common prefix ends where epoch 4 did"
        );
        assert!(dp.needs_truncation(off(28)));
    }

    #[test]
    fn divergence_point_with_no_shared_epoch_truncates_to_the_start() {
        // The follower and leader share NO epoch at all (entirely different lineages from the start).
        let follower = EpochCache::from_entries(vec![EpochEntry {
            epoch: ep(3),
            start_offset: off(0),
        }])
        .unwrap();
        let leader = EpochCache::from_entries(vec![EpochEntry {
            epoch: ep(9),
            start_offset: off(0),
        }])
        .unwrap();
        // The leader answers epoch 9 for everything (it never had epoch 3); descending finds nothing
        // shared, so the follower truncates to its first boundary (offset 0): a full re-sync.
        let dp = follower.divergence_point(off(10), |e| leader.end_offset_for_epoch(e, off(20)));
        assert_eq!(dp.diverged_at_epoch, LeaderEpoch::GENESIS);
        assert_eq!(dp.truncate_to, off(0));
        assert!(dp.needs_truncation(off(10)));
    }

    #[test]
    fn divergence_point_of_an_empty_follower_is_a_no_op_fetch_forward() {
        let follower = EpochCache::new();
        let leader = EpochCache::from_entries(vec![EpochEntry {
            epoch: ep(1),
            start_offset: off(0),
        }])
        .unwrap();
        let dp = follower.divergence_point(off(0), |e| leader.end_offset_for_epoch(e, off(10)));
        assert_eq!(dp.diverged_at_epoch, LeaderEpoch::GENESIS);
        assert_eq!(dp.truncate_to, off(0));
        assert!(!dp.needs_truncation(off(0)));
    }

    #[test]
    fn truncate_to_drops_a_divergent_suffix_and_keeps_the_common_prefix() {
        let mut cache = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(5),
                start_offset: off(10),
            },
            EpochEntry {
                epoch: ep(8),
                start_offset: off(20),
            },
        ])
        .unwrap();
        // Truncate to 20: the epoch-8 boundary (start 20) is dropped wholesale; epochs 1 and 5 (which
        // start below 20) are KEPT unchanged — the common-prefix epoch history survives exactly.
        cache.truncate_to(off(20));
        assert_eq!(
            cache.entries(),
            &[
                EpochEntry {
                    epoch: ep(1),
                    start_offset: off(0)
                },
                EpochEntry {
                    epoch: ep(5),
                    start_offset: off(10)
                },
            ]
        );
        assert_eq!(cache.current_epoch(), ep(5));
        // A truncate that lands inside epoch 5's range keeps epoch 5 (its start is below the point).
        cache.truncate_to(off(15));
        assert_eq!(cache.entries().len(), 2);
        // A truncate to 10 drops epoch 5 too (its start == 10 is not < 10).
        cache.truncate_to(off(10));
        assert_eq!(cache.entries().len(), 1);
        assert_eq!(cache.current_epoch(), ep(1));
    }

    #[test]
    fn epoch_cache_reconstructs_from_its_entries_round_trip() {
        // The "reconstructs after a reopen" property at the pure-data level: a cache's entries fully
        // determine it, so rebuilding from them yields an identical cache (the storage layer rehydrates
        // the cache from the leader's advertised history the same way).
        let original = EpochCache::from_entries(vec![
            EpochEntry {
                epoch: ep(1),
                start_offset: off(0),
            },
            EpochEntry {
                epoch: ep(4),
                start_offset: off(10),
            },
            EpochEntry {
                epoch: ep(9),
                start_offset: off(25),
            },
        ])
        .unwrap();
        let rebuilt = EpochCache::from_entries(original.entries().to_vec()).unwrap();
        assert_eq!(original, rebuilt);
    }
}
