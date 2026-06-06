// SPDX-License-Identifier: MIT OR Apache-2.0
//! The work-group commit cursor: how one shared cursor advances under out-of-order acks.
//!
//! A work-group shares a single committed offset, but its members drain in parallel and
//! acknowledge messages out of order. Two naive rules are both wrong: advancing the
//! cursor to the highest acked offset silently skips the unacked gaps below it (data
//! loss, since recovery would resume past records that were never processed), while
//! refusing to advance until the next offset is acked in strict order collapses the
//! group into an exclusive consumer (no parallelism).
//!
//! [`AckCursor`] is the correct middle. It keeps `committed`, the watermark below which
//! every offset is acked, plus a sparse, run-length-encoded set of offsets acked AHEAD
//! of the watermark. An out-of-order ack lands in that set; whenever the offset at the
//! watermark becomes acked, the watermark jumps over the now-contiguous run. The cursor
//! is pure and IO-free; durability of `committed` and bounding the ahead set (via the
//! consumer's max-in-flight) are the caller's responsibility. The ahead set is also
//! persistable: [`AckCursor::ahead_ranges`] snapshots it and [`AckCursor::resume_with_ahead`]
//! restores it (validating the shape), so a durable consumer-state store (#60) can resume a
//! restart that redelivers only genuinely unacked offsets, not the acked-ahead ones too.

use crate::types::Offset;

/// Tracks a work-group's committed cursor as acks arrive, possibly out of order.
///
/// `committed` is the next offset to deliver: every offset strictly below it is acked.
/// Acks at or above it that are not yet contiguous are held in a compact set until the
/// gap below them fills, at which point the cursor advances over the contiguous prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AckCursor {
    committed: u64,
    /// Sorted, disjoint, non-adjacent half-open ranges `[start, end)` of acked offsets,
    /// every range starting strictly above `committed`.
    ahead: Vec<(u64, u64)>,
}

impl AckCursor {
    /// A fresh cursor committed at offset zero, with nothing acked.
    #[must_use]
    pub fn new() -> AckCursor {
        AckCursor {
            committed: 0,
            ahead: Vec::new(),
        }
    }

    /// A cursor resumed at a recovered committed offset (the ahead set does not survive
    /// a restart; in-flight messages are redelivered).
    #[must_use]
    pub fn resume(committed: Offset) -> AckCursor {
        AckCursor {
            committed: committed.get(),
            ahead: Vec::new(),
        }
    }

    /// Resumes a cursor at `committed` WITH a persisted acked-ahead set (the run-length ranges
    /// a prior [`AckCursor::ahead_ranges`] snapshot produced), so a restart redelivers only
    /// genuinely unacked offsets rather than the acked-ahead ones too. The ranges must be the
    /// exact shape the cursor maintains: each `[start, end)` non-empty, sorted, pairwise
    /// disjoint, non-adjacent, and strictly above `committed`.
    ///
    /// # Errors
    /// Returns [`AckCursorError`] if the ranges are malformed (a corrupt or torn snapshot), so
    /// the caller can fall back to [`AckCursor::resume`] (drop the ahead set and redeliver)
    /// rather than trust bad state. A rejected snapshot never yields a half-built cursor.
    pub fn resume_with_ahead(
        committed: Offset,
        ahead: Vec<(u64, u64)>,
    ) -> Result<AckCursor, AckCursorError> {
        let committed = committed.get();
        let mut prev_end = committed;
        for &(start, end) in &ahead {
            if start >= end {
                return Err(AckCursorError::EmptyRange { start, end });
            }
            // `start > prev_end` enforces, in one check, that the first range is strictly above
            // `committed` (a range starting AT `committed` would be contiguous and should have
            // advanced) and that every later range is sorted, disjoint, and non-adjacent.
            if start <= prev_end {
                return Err(AckCursorError::NotSortedDisjointAndAboveCommitted { start, prev_end });
            }
            prev_end = end;
        }
        Ok(AckCursor { committed, ahead })
    }

    /// The acked-ahead set as run-length `[start, end)` ranges: sorted, disjoint, non-adjacent,
    /// every range strictly above [`AckCursor::committed`]. This is the compact snapshot a
    /// durable consumer-state store (#60) persists and later hands to
    /// [`AckCursor::resume_with_ahead`].
    #[must_use]
    pub fn ahead_ranges(&self) -> &[(u64, u64)] {
        &self.ahead
    }

    /// The committed offset: every offset below it is acked, and it is the next offset a
    /// recovery or a fresh consumer should resume from.
    #[must_use]
    pub fn committed(&self) -> Offset {
        Offset::new(self.committed)
    }

    /// Whether `offset` has been acked (below the watermark or in the ahead set).
    #[must_use]
    pub fn is_acked(&self, offset: Offset) -> bool {
        let offset = offset.get();
        offset < self.committed || self.contains_ahead(offset)
    }

    /// The number of offsets acked ahead of the watermark (the out-of-order acks still
    /// waiting on a gap below them). The caller bounds this through its max-in-flight.
    #[must_use]
    pub fn ahead_len(&self) -> u64 {
        self.ahead.iter().map(|&(s, e)| e - s).sum()
    }

    /// The number of run-length ranges in the ahead set (a fragmentation measure).
    #[must_use]
    pub fn ahead_runs(&self) -> usize {
        self.ahead.len()
    }

    /// Records an ack for `offset`, advancing the committed cursor over any newly
    /// contiguous prefix. Returns `true` if this ack was new, `false` if `offset` was
    /// already acked (a duplicate, which at-least-once delivery permits and ignores).
    pub fn ack(&mut self, offset: Offset) -> bool {
        let offset = offset.get();
        if offset < self.committed || self.contains_ahead(offset) {
            return false;
        }
        // The offset space treats `u64::MAX` as exhausted (see [`Offset::checked_next`])
        // and a real deployment never reaches it. Refuse the ack rather than overflow the
        // half-open range end, which would otherwise wrap and collapse `committed` to 0.
        let Some(next) = offset.checked_add(1) else {
            return false;
        };
        self.insert(offset, next);
        self.advance();
        true
    }

    fn contains_ahead(&self, offset: u64) -> bool {
        self.ahead.iter().any(|&(s, e)| offset >= s && offset < e)
    }

    /// Inserts `[offset, next)` (where `next == offset + 1`) into the ahead set, merging
    /// with adjacent ranges so the set stays disjoint and non-adjacent. `offset` is known
    /// not to be present and to be at or above `committed`.
    fn insert(&mut self, offset: u64, next: u64) {
        let i = self
            .ahead
            .iter()
            .position(|&(s, _)| s > offset)
            .unwrap_or(self.ahead.len());
        let merge_left = i > 0 && self.ahead[i - 1].1 == offset;
        let merge_right = i < self.ahead.len() && self.ahead[i].0 == next;
        match (merge_left, merge_right) {
            (true, true) => {
                self.ahead[i - 1].1 = self.ahead[i].1;
                self.ahead.remove(i);
            }
            (true, false) => self.ahead[i - 1].1 = next,
            (false, true) => self.ahead[i].0 = offset,
            (false, false) => self.ahead.insert(i, (offset, next)),
        }
    }

    /// If the lowest ahead range now begins at the watermark, advance the watermark over
    /// it. Ranges are non-adjacent, so at most one range can ever be contiguous.
    fn advance(&mut self) {
        if let Some(&(start, end)) = self.ahead.first() {
            if start == self.committed {
                self.committed = end;
                self.ahead.remove(0);
            }
        }
    }
}

/// A malformed acked-ahead snapshot rejected by [`AckCursor::resume_with_ahead`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckCursorError {
    /// A range `[start, end)` was empty or reversed (`start >= end`).
    EmptyRange {
        /// The range start.
        start: u64,
        /// The range end.
        end: u64,
    },
    /// A range was not strictly above the watermark, not sorted, or adjacent to or
    /// overlapping its predecessor (`start <= prev_end`, where `prev_end` is `committed` for
    /// the first range).
    NotSortedDisjointAndAboveCommitted {
        /// The offending range start.
        start: u64,
        /// The end of the previous range, or `committed` for the first range.
        prev_end: u64,
    },
}

impl core::fmt::Display for AckCursorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AckCursorError::EmptyRange { start, end } => {
                write!(f, "acked-ahead range [{start}, {end}) is empty or reversed")
            }
            AckCursorError::NotSortedDisjointAndAboveCommitted { start, prev_end } => write!(
                f,
                "acked-ahead range start {start} is not strictly above the previous end {prev_end}"
            ),
        }
    }
}

impl std::error::Error for AckCursorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn off(n: u64) -> Offset {
        Offset::new(n)
    }

    #[test]
    fn in_order_acks_advance_one_at_a_time() {
        let mut c = AckCursor::new();
        for i in 0..5 {
            assert!(c.ack(off(i)));
            assert_eq!(c.committed(), off(i + 1));
            assert_eq!(c.ahead_len(), 0);
        }
    }

    #[test]
    fn out_of_order_acks_wait_then_collapse() {
        let mut c = AckCursor::new();
        // Ack 2 and 3 ahead of the gap at 0 and 1.
        assert!(c.ack(off(2)));
        assert!(c.ack(off(3)));
        assert_eq!(c.committed(), off(0), "cannot advance past the gap at 0");
        assert_eq!(c.ahead_len(), 2);
        assert_eq!(c.ahead_runs(), 1, "2 and 3 are one contiguous run");
        // Filling 0 advances only over 0 (1 is still a gap).
        assert!(c.ack(off(0)));
        assert_eq!(c.committed(), off(1));
        assert_eq!(c.ahead_len(), 2);
        // Filling 1 collapses the whole run: committed jumps to 4.
        assert!(c.ack(off(1)));
        assert_eq!(c.committed(), off(4));
        assert_eq!(c.ahead_len(), 0);
    }

    #[test]
    fn duplicate_acks_are_ignored() {
        let mut c = AckCursor::new();
        assert!(c.ack(off(0)));
        assert!(!c.ack(off(0)), "below the watermark is a duplicate");
        assert!(c.ack(off(5)));
        assert!(!c.ack(off(5)), "already in the ahead set is a duplicate");
        assert_eq!(c.committed(), off(1));
        assert_eq!(c.ahead_len(), 1);
    }

    #[test]
    fn bridging_two_runs_merges_them() {
        let mut c = AckCursor::new();
        c.ack(off(1));
        c.ack(off(3));
        assert_eq!(c.ahead_runs(), 2);
        c.ack(off(2)); // bridges 1..2 and 3..4 into 1..4
        assert_eq!(c.ahead_runs(), 1);
        assert_eq!(c.ahead_len(), 3);
        assert!(c.is_acked(off(1)) && c.is_acked(off(2)) && c.is_acked(off(3)));
        assert!(!c.is_acked(off(0)));
    }

    #[test]
    fn resume_treats_everything_below_as_committed() {
        let mut c = AckCursor::resume(off(10));
        assert_eq!(c.committed(), off(10));
        assert!(c.is_acked(off(9)));
        assert!(!c.is_acked(off(10)));
        assert!(!c.ack(off(7)), "below the resumed watermark is a duplicate");
        assert!(c.ack(off(10)));
        assert_eq!(c.committed(), off(11));
    }

    #[test]
    fn acking_the_max_offset_never_overflows_or_collapses_committed() {
        // The offset-space boundary must not panic (debug) or wrap `committed` to 0
        // (release): acking u64::MAX is refused as the exhausted boundary.
        let mut c = AckCursor::resume(off(u64::MAX));
        assert!(!c.ack(off(u64::MAX)));
        assert_eq!(c.committed(), off(u64::MAX), "committed must not collapse");
        assert_eq!(c.ahead_len(), 0);

        let mut fresh = AckCursor::new();
        assert!(!fresh.ack(off(u64::MAX)));
        assert_eq!(fresh.committed(), off(0));
        assert_eq!(fresh.ahead_len(), 0);
    }

    #[test]
    fn far_apart_offsets_do_not_merge() {
        let mut c = AckCursor::new();
        c.ack(off(5));
        c.ack(off(1_000_000));
        assert_eq!(c.ahead_runs(), 2);
        assert_eq!(c.ahead_len(), 2);
        assert!(c.is_acked(off(5)) && c.is_acked(off(1_000_000)));
        assert!(!c.is_acked(off(6)));
        assert_eq!(c.committed(), off(0));
    }

    #[test]
    fn resume_with_ahead_restores_the_sparse_set_exactly() {
        // Build a cursor with a gap so the ahead set is non-trivial: commit 0, ack 2,3 and 5.
        let mut c = AckCursor::new();
        c.ack(off(0));
        c.ack(off(2));
        c.ack(off(3));
        c.ack(off(5));
        assert_eq!(c.committed(), off(1));
        let snapshot = c.ahead_ranges().to_vec();
        assert_eq!(snapshot, vec![(2, 4), (5, 6)]);

        // Resuming with that snapshot reconstructs the cursor exactly: same committed, same
        // ahead, same is_acked, so a restart redelivers only the genuine gaps (1 and 4).
        let restored = AckCursor::resume_with_ahead(c.committed(), snapshot).unwrap();
        assert_eq!(restored, c);
        assert!(
            !restored.is_acked(off(1)) && !restored.is_acked(off(4)),
            "gaps redeliver"
        );
        assert!(
            restored.is_acked(off(2)) && restored.is_acked(off(5)),
            "acked-ahead survives"
        );
    }

    #[test]
    fn resume_with_ahead_rejects_a_malformed_snapshot() {
        // A range at or below the watermark (would have advanced), out of order, overlapping,
        // adjacent (should have merged), or empty: each is a corrupt snapshot.
        let bad = [
            vec![(5u64, 5u64)],   // empty / reversed
            vec![(10, 9)],        // reversed
            vec![(5, 6), (5, 7)], // not sorted / overlapping
            vec![(5, 7), (6, 8)], // overlapping
            vec![(5, 7), (7, 9)], // adjacent (should be one run)
        ];
        for ranges in bad {
            assert!(
                AckCursor::resume_with_ahead(off(5), ranges.clone()).is_err(),
                "malformed snapshot {ranges:?} must be rejected"
            );
        }
        // A range starting AT committed is contiguous and invalid (the watermark should hold it).
        assert!(AckCursor::resume_with_ahead(off(5), vec![(5, 6)]).is_err());
        // A well-formed snapshot above the watermark is accepted.
        AckCursor::resume_with_ahead(off(5), vec![(7, 9), (11, 12)]).unwrap();
    }

    proptest! {
        #[test]
        fn acking_a_permutation_commits_everything(perm in any_permutation(1..40usize)) {
            let mut c = AckCursor::new();
            let n = perm.len() as u64;
            for &o in &perm {
                c.ack(off(o as u64));
            }
            // Every offset acked, in any order, leaves the cursor fully committed.
            prop_assert_eq!(c.committed(), off(n));
            prop_assert_eq!(c.ahead_len(), 0);
            prop_assert_eq!(c.ahead_runs(), 0);
        }

        /// #61 criterion: no offset below `committed` is ever unacked (no silent skip). The
        /// watermark only advances over genuinely contiguous acked runs, under any ack order.
        #[test]
        fn no_offset_below_committed_is_ever_unacked(acks in prop::collection::vec(0u64..40, 0..80)) {
            let mut c = AckCursor::new();
            for &o in &acks {
                c.ack(off(o));
                for below in 0..c.committed().get() {
                    prop_assert!(c.is_acked(off(below)), "offset {below} below committed must be acked");
                }
            }
        }

        /// Snapshot then resume round-trips exactly: a persisted ahead set restores to an
        /// identical cursor, so the durable consumer-state store (#60) loses no acked-ahead work.
        #[test]
        fn snapshot_then_resume_with_ahead_round_trips(acks in prop::collection::vec(0u64..40, 0..80)) {
            let mut c = AckCursor::new();
            for &o in &acks {
                c.ack(off(o));
            }
            let restored = AckCursor::resume_with_ahead(c.committed(), c.ahead_ranges().to_vec())
                .expect("a cursor's own snapshot is always well-formed");
            prop_assert_eq!(&restored, &c);
            for o in 0..45u64 {
                prop_assert_eq!(restored.is_acked(off(o)), c.is_acked(off(o)));
            }
        }

        #[test]
        fn invariants_hold_after_any_ack_sequence(acks in prop::collection::vec(0u64..30, 0..60)) {
            let mut c = AckCursor::new();
            let mut last_committed = 0u64;
            for &o in &acks {
                c.ack(off(o));
                // committed is monotonic non-decreasing.
                prop_assert!(c.committed().get() >= last_committed);
                last_committed = c.committed().get();
                // ahead ranges are sorted, disjoint, non-adjacent, and above committed.
                let mut prev_end = c.committed().get();
                for &(s, e) in &c.ahead {
                    prop_assert!(s < e, "range is non-empty");
                    prop_assert!(s > prev_end, "ranges are above committed, disjoint, non-adjacent");
                    prev_end = e;
                }
            }
            // Acked-ahead count equals the distinct out-of-order offsets seen above the watermark.
            let distinct_ahead = acks
                .iter()
                .filter(|&&o| o >= c.committed().get())
                .collect::<std::collections::BTreeSet<_>>()
                .len() as u64;
            prop_assert_eq!(c.ahead_len(), distinct_ahead);
        }

        #[test]
        fn is_acked_agrees_with_the_ack_history(acks in prop::collection::vec(0u64..25, 0..40)) {
            let mut c = AckCursor::new();
            for &o in &acks {
                c.ack(off(o));
            }
            let acked: std::collections::BTreeSet<u64> = acks.iter().copied().collect();
            for o in 0..25u64 {
                prop_assert_eq!(c.is_acked(off(o)), acked.contains(&o));
            }
        }

        /// Arbitrary offsets across the FULL u64 domain (including `u64::MAX`) never panic
        /// or corrupt: the invariants hold and `committed` stays monotonic.
        #[test]
        fn invariants_hold_over_the_full_offset_domain(
            acks in prop::collection::vec(any::<u64>(), 0..50),
        ) {
            let mut c = AckCursor::new();
            let mut last_committed = 0u64;
            for &o in &acks {
                c.ack(off(o));
                prop_assert!(c.committed().get() >= last_committed);
                last_committed = c.committed().get();
                let mut prev_end = c.committed().get();
                for &(s, e) in &c.ahead {
                    prop_assert!(s < e);
                    prop_assert!(s > prev_end);
                    prev_end = e;
                }
            }
        }

        /// A cursor resumed from a non-zero base stays consistent under further acks.
        #[test]
        fn resume_base_then_acks_stays_consistent(
            base in 0u64..1000,
            acks in prop::collection::vec(0u64..1100, 0..40),
        ) {
            let mut c = AckCursor::resume(off(base));
            let mut last_committed = base;
            for &o in &acks {
                c.ack(off(o));
                prop_assert!(c.committed().get() >= last_committed);
                last_committed = c.committed().get();
            }
            prop_assert!(c.committed().get() >= base);
            let mut prev_end = c.committed().get();
            for &(s, e) in &c.ahead {
                prop_assert!(s < e);
                prop_assert!(s > prev_end);
                prev_end = e;
            }
            for o in 0..base {
                prop_assert!(c.is_acked(off(o)));
            }
        }
    }

    prop_compose! {
        fn any_permutation(len: std::ops::Range<usize>)(n in len)(perm in {
            let v: Vec<usize> = (0..n).collect();
            Just(v).prop_shuffle()
        }) -> Vec<usize> {
            perm
        }
    }
}
