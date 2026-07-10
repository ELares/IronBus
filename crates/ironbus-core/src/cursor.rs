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
//! is pure and IO-free; durability of `committed` is the caller's responsibility. The
//! ahead set is bounded two ways: the caller's delivery window (offsets past
//! `committed + max_in_flight` are never delivered, so never acked) and, hardening that,
//! the explicit RANGE cap of [`AckCursor::ack_bounded`] (#543), which refuses to record a
//! FRAGMENTING ack once the run count would pass the cap — the refused offset simply reads
//! as unacked and redelivers later (an at-least-once duplicate, never a loss). The ahead
//! set is also persistable: [`AckCursor::ahead_ranges`] snapshots it and
//! [`AckCursor::resume_with_ahead`] restores it (validating the shape), so a durable
//! consumer-state store (#60) can resume a restart that redelivers only genuinely unacked
//! offsets, not the acked-ahead ones too.

use crate::types::Offset;

/// The on-disk snapshot format version for an [`AckCursor`] (see [`AckCursor::encode_snapshot`]).
const SNAPSHOT_VERSION: u8 = 1;

/// Reads a little-endian `u64` at `pos`; the caller has bounds-checked the slice length.
fn read_u64(buf: &[u8], pos: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[pos..pos + 8]);
    u64::from_le_bytes(b)
}

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

    /// The minimum length in bytes of an [`AckCursor::encode_snapshot`] output: the fixed
    /// header (a 1-byte version plus the 8-byte committed watermark) and the trailing 4-byte
    /// crc32c, with no acked-ahead runs. A payload shorter than this cannot be a snapshot, so
    /// a caller framing a snapshot alongside an older committed-only format can tell them
    /// apart by length.
    pub const SNAPSHOT_MIN_LEN: usize = 1 + 8 + 4;

    /// Encodes a durable snapshot of this cursor for a consumer-state store (#60): a 1-byte
    /// version, the committed watermark, the run-length acked-ahead ranges, then a trailing
    /// crc32c over everything before it. The run count is implicit (the bytes between the
    /// header and the checksum), so [`AckCursor::decode_snapshot`] needs no separate length.
    pub fn encode_snapshot(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&self.committed.to_le_bytes());
        for &(s, e) in &self.ahead {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
        }
        let crc = crc32c::crc32c(&out[start..]);
        out.extend_from_slice(&crc.to_le_bytes());
    }

    /// Decodes a snapshot produced by [`AckCursor::encode_snapshot`], validating the version,
    /// the checksum, and the acked-ahead range shape (via the same rules as
    /// [`AckCursor::resume_with_ahead`]). A torn or corrupt snapshot is rejected with a typed
    /// [`SnapshotError`] so the caller can fall back to the previous snapshot rather than
    /// restore a broken cursor.
    ///
    /// # Errors
    /// Returns [`SnapshotError`] for a short, mis-sized, wrong-version, bad-checksum, or
    /// structurally invalid snapshot.
    pub fn decode_snapshot(input: &[u8]) -> Result<AckCursor, SnapshotError> {
        // version (1) + committed (8) + crc (4) = 13 fixed bytes, plus 16 per ahead range.
        let fixed = Self::SNAPSHOT_MIN_LEN;
        if input.len() < fixed {
            return Err(SnapshotError::Truncated);
        }
        let runs_len = input.len() - fixed;
        if runs_len % 16 != 0 {
            return Err(SnapshotError::BadLength { len: input.len() });
        }
        let version = input[0];
        if version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        let crc_at = input.len() - 4;
        let stored = u32::from_le_bytes([
            input[crc_at],
            input[crc_at + 1],
            input[crc_at + 2],
            input[crc_at + 3],
        ]);
        if crc32c::crc32c(&input[..crc_at]) != stored {
            return Err(SnapshotError::BadCrc);
        }
        let committed = read_u64(input, 1);
        let mut ahead = Vec::with_capacity(runs_len / 16);
        let mut pos = 9;
        while pos < crc_at {
            ahead.push((read_u64(input, pos), read_u64(input, pos + 8)));
            pos += 16;
        }
        AckCursor::resume_with_ahead(Offset::new(committed), ahead).map_err(SnapshotError::Ranges)
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
    /// The UNBOUNDED form of [`AckCursor::ack_bounded`]: it never sheds, so the caller
    /// is trusting its delivery window to bound the ahead set.
    pub fn ack(&mut self, offset: Offset) -> bool {
        matches!(self.ack_bounded(offset, usize::MAX), BoundedAck::Recorded)
    }

    /// Records an ack for `offset` like [`AckCursor::ack`], but BOUNDS the acked-ahead set at
    /// `max_runs` run-length ranges (#543, Pulsar's `individuallyDeletedMessages` design with its
    /// unbounded-R hazard fixed): an out-of-order ack that would CREATE a new disjoint run once
    /// `max_runs` ranges already exist is refused as [`BoundedAck::Shed`] and the cursor is left
    /// untouched, so the ahead set's memory is O(`max_runs`), never O(unacked-gaps).
    ///
    /// The shed choice is the at-least-once-SAFE one at the cap. The committed watermark can
    /// NEVER be forced past an unacked gap (that would be silent loss); instead the fragmenting
    /// ack is simply not remembered: the offset still reads as unacked ([`AckCursor::is_acked`]
    /// stays `false`), so the caller's redelivery machinery delivers it again later and a future
    /// re-ack lands normally (usually merging into a neighbor run by then). A shed is therefore a
    /// bounded DUPLICATE, never a loss, and exactly one offset of tracking is dropped per shed
    /// (the newest), never a whole previously-recorded range.
    ///
    /// Never shed, even at the cap:
    /// - an ack AT the watermark (`offset == committed`): it ADVANCES the watermark (absorbing
    ///   any now-contiguous run), monotonically SHRINKING the ahead set — refusing it could
    ///   deadlock progress;
    /// - a MERGING ack (adjacent to an existing run on either side): it never grows the run
    ///   count (bridging two runs shrinks it), so gap-filling toward the watermark always lands.
    ///
    /// A `max_runs` of `0` therefore accepts ONLY in-order acks at the watermark (no
    /// out-of-order tracking at all); a caller offering a `0 = unbounded` config convention
    /// should map that `0` to `usize::MAX` BEFORE calling.
    pub fn ack_bounded(&mut self, offset: Offset, max_runs: usize) -> BoundedAck {
        let offset = offset.get();
        if offset < self.committed || self.contains_ahead(offset) {
            return BoundedAck::Duplicate;
        }
        // The offset space treats `u64::MAX` as exhausted (see [`Offset::checked_next`])
        // and a real deployment never reaches it. Refuse the ack rather than overflow the
        // half-open range end, which would otherwise wrap and collapse `committed` to 0.
        let Some(next) = offset.checked_add(1) else {
            return BoundedAck::Duplicate;
        };
        // Only a FRAGMENTING ack (strictly above the watermark, adjacent to no existing run) can
        // grow the run count, so only it is ever shed. The merge probes mirror `insert` exactly:
        // the ranges are sorted and `offset` is known absent, so the partition point is the
        // insertion index and the two neighbors are the only possible merges. An ack at the
        // watermark is exempt outright: `insert` + `advance` nets the run count to at most its
        // old value (the transient run is absorbed into `committed` immediately).
        if self.ahead.len() >= max_runs && offset != self.committed {
            let i = self.ahead.partition_point(|&(s, _)| s <= offset);
            let merges_left = i > 0 && self.ahead[i - 1].1 == offset;
            let merges_right = i < self.ahead.len() && self.ahead[i].0 == next;
            if !merges_left && !merges_right {
                return BoundedAck::Shed;
            }
        }
        self.insert(offset, next);
        self.advance();
        BoundedAck::Recorded
    }

    /// Commits the watermark up to the EXCLUSIVE offset `up_to` (every offset strictly below
    /// `up_to` becomes acked), the cumulative-ack ("ack-all-up-to-offset") move for a BROADCAST
    /// consumer (#288): a group-of-one that sees every record in order can commit its single
    /// cursor straight to an offset without the gap-filling an out-of-order [`AckCursor::ack`]
    /// sequence does. Returns `true` if the watermark advanced, `false` if `up_to` was at or below
    /// the current watermark (an idempotent re-ack, a no-op success).
    ///
    /// The watermark NEVER moves backwards: an `up_to` at or below `committed` is ignored. Any
    /// acked-ahead ranges the new watermark now subsumes are dropped (their offsets are below the
    /// watermark, so they are committed); a range straddling `up_to` is clipped to begin at
    /// `up_to`. The caller is responsible for validating `up_to` against the durable head and the
    /// earliest-retained offset BEFORE calling this (the cursor is pure and has no view of the
    /// log); this method only maintains the cursor's own shape invariants.
    pub fn commit_up_to(&mut self, up_to: Offset) -> bool {
        let up_to = up_to.get();
        // Idempotent / monotonic: an up_to at or below the watermark is a no-op success. This is
        // the re-ack case (the same or a lower offset is acked again) and the only way the cursor
        // could otherwise regress, so it is refused here.
        if up_to <= self.committed {
            return false;
        }
        self.committed = up_to;
        // Drop every ahead range now fully below the watermark, and clip a range that straddles
        // `up_to` so it starts at the watermark (its lower offsets are committed). A range whose
        // start is at or above `up_to` is untouched; ranges stay sorted, so the first surviving
        // range bounds the rest. retain_mut keeps the in-place clip and the drop in one pass.
        self.ahead.retain_mut(|(s, e)| {
            if *e <= up_to {
                false
            } else {
                *s = (*s).max(up_to);
                true
            }
        });
        // A range that now begins exactly at the watermark is contiguous: advance over it (and any
        // further contiguous run), exactly as an in-order ack would, so the cursor's "first ahead
        // range starts strictly above committed" invariant holds.
        while let Some(&(start, end)) = self.ahead.first() {
            if start == self.committed {
                self.committed = end;
                self.ahead.remove(0);
            } else {
                break;
            }
        }
        true
    }

    fn contains_ahead(&self, offset: u64) -> bool {
        // The ahead ranges are sorted, disjoint, and non-adjacent, so at most one can contain
        // `offset` and binary search locates it in O(log R) rather than scanning all R runs.
        // A range `[s, e)` compares Less when it lies wholly below `offset` (`e <= offset`),
        // Greater when wholly above (`s > offset`), and Equal exactly when it contains `offset`.
        self.ahead
            .binary_search_by(|&(s, e)| {
                if e <= offset {
                    core::cmp::Ordering::Less
                } else if s > offset {
                    core::cmp::Ordering::Greater
                } else {
                    core::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Inserts `[offset, next)` (where `next == offset + 1`) into the ahead set, merging
    /// with adjacent ranges so the set stays disjoint and non-adjacent. `offset` is known
    /// not to be present and to be at or above `committed`.
    fn insert(&mut self, offset: u64, next: u64) {
        // The ranges are sorted by start, so the insertion point is the first index whose start
        // exceeds `offset`. `offset` is known absent (the caller guards on `contains_ahead`), so a
        // binary search on the start key always misses and yields exactly that index in O(log R),
        // replacing the linear `position` scan. `partition_point` returns the same index directly.
        let i = self.ahead.partition_point(|&(s, _)| s <= offset);
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

/// The outcome of a bounded ack ([`AckCursor::ack_bounded`], #543).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedAck {
    /// The ack was new and recorded: the watermark advanced and/or the ahead set absorbed it.
    Recorded,
    /// The offset was already acked (below the watermark or inside the ahead set) — or sits at
    /// the exhausted `u64::MAX` offset-space boundary — so nothing changed. At-least-once
    /// delivery permits and ignores a duplicate ack.
    Duplicate,
    /// The ack was refused under the range cap: recording it would have created a NEW
    /// acked-ahead run past `max_runs`. The cursor is untouched — the offset still reads as
    /// unacked, so it redelivers later (an at-least-once duplicate, never a loss) and the
    /// committed watermark cannot have passed an unacked gap. The caller should count the shed
    /// (it is backpressure evidence of a pathologically fragmented ack pattern).
    Shed,
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

/// A failure decoding an [`AckCursor`] snapshot (see [`AckCursor::decode_snapshot`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The snapshot is shorter than the fixed header plus checksum.
    Truncated,
    /// The snapshot length is not a fixed header plus a whole number of 16-byte ranges.
    BadLength {
        /// The rejected length.
        len: usize,
    },
    /// The snapshot's version byte is one this build does not understand.
    UnsupportedVersion(u8),
    /// The trailing crc32c did not match the body (a torn or corrupt snapshot).
    BadCrc,
    /// The decoded acked-ahead ranges were structurally invalid.
    Ranges(AckCursorError),
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SnapshotError::Truncated => write!(f, "cursor snapshot is too short for its header"),
            SnapshotError::BadLength { len } => {
                write!(
                    f,
                    "cursor snapshot length {len} is not a header plus whole ranges"
                )
            }
            SnapshotError::UnsupportedVersion(v) => {
                write!(f, "cursor snapshot version {v} is not supported")
            }
            SnapshotError::BadCrc => write!(f, "cursor snapshot checksum did not match"),
            SnapshotError::Ranges(e) => write!(f, "cursor snapshot ranges are invalid: {e}"),
        }
    }
}

impl std::error::Error for SnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnapshotError::Ranges(e) => Some(e),
            _ => None,
        }
    }
}

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
    fn commit_up_to_advances_the_watermark() {
        let mut c = AckCursor::new();
        // Commit up to an exclusive offset: every offset strictly below it is acked.
        assert!(c.commit_up_to(off(5)));
        assert_eq!(c.committed(), off(5));
        assert!(c.is_acked(off(4)) && !c.is_acked(off(5)));
        assert_eq!(c.ahead_len(), 0);
    }

    #[test]
    fn commit_up_to_is_idempotent_and_never_regresses() {
        let mut c = AckCursor::new();
        assert!(c.commit_up_to(off(10)));
        assert_eq!(c.committed(), off(10));
        // A re-ack at the same offset is a no-op success, not a regression.
        assert!(!c.commit_up_to(off(10)));
        assert_eq!(c.committed(), off(10));
        // A lower up_to is also a no-op success: the watermark holds.
        assert!(!c.commit_up_to(off(3)));
        assert_eq!(c.committed(), off(10));
        // up_to == 0 on a fresh cursor is the trivial no-op.
        let mut fresh = AckCursor::new();
        assert!(!fresh.commit_up_to(off(0)));
        assert_eq!(fresh.committed(), off(0));
    }

    #[test]
    fn commit_up_to_subsumes_and_clips_the_ahead_set() {
        let mut c = AckCursor::new();
        // Ahead set: 2..5 and 7..9 (gaps at 0,1,5,6). Committed stays at 0.
        for o in [2u64, 3, 4, 7, 8] {
            c.ack(off(o));
        }
        assert_eq!(c.committed(), off(0));
        assert_eq!(c.ahead_ranges(), &[(2, 5), (7, 9)]);
        // Commit up to 3 (exclusive): 2..5 straddles, so it clips to 3..5; since 3 is now contiguous
        // with the watermark, the advance loop absorbs the whole clipped 3..5 run, so committed
        // jumps to 5. The 7..9 run is untouched (still a gap at 5,6 below it).
        assert!(c.commit_up_to(off(3)));
        assert_eq!(
            c.committed(),
            off(5),
            "the clipped contiguous run is absorbed"
        );
        assert_eq!(c.ahead_ranges(), &[(7, 9)]);
        assert!(c.is_acked(off(4)) && !c.is_acked(off(5)) && !c.is_acked(off(6)));
        // Commit past the second run: 7..9 is fully subsumed (offsets 7,8 are below the watermark).
        assert!(c.commit_up_to(off(9)));
        assert_eq!(c.committed(), off(9));
        assert_eq!(c.ahead_len(), 0);
        assert!(c.is_acked(off(7)) && c.is_acked(off(8)));
    }

    #[test]
    fn commit_up_to_into_a_gap_does_not_absorb_a_non_contiguous_run() {
        let mut c = AckCursor::new();
        // Ahead set: 5..7 (gaps at 0..5). Committed stays at 0.
        c.ack(off(5));
        c.ack(off(6));
        assert_eq!(c.ahead_ranges(), &[(5, 7)]);
        // Commit up to 3 (exclusive): lands in the gap below 5, so the 5..7 run is NOT contiguous
        // and stays put. Committed is exactly 3; 3 and 4 remain unacked gaps.
        assert!(c.commit_up_to(off(3)));
        assert_eq!(c.committed(), off(3));
        assert_eq!(c.ahead_ranges(), &[(5, 7)]);
        assert!(!c.is_acked(off(3)) && !c.is_acked(off(4)));
        assert!(c.is_acked(off(5)) && c.is_acked(off(6)));
    }

    #[test]
    fn commit_up_to_then_advance_over_a_contiguous_run() {
        let mut c = AckCursor::new();
        // Ahead set has 5..7. Committing up to exactly 5 makes it contiguous, so the watermark
        // jumps the whole run to 7 in one call (no separate ack needed).
        c.ack(off(5));
        c.ack(off(6));
        assert_eq!(c.ahead_ranges(), &[(5, 7)]);
        assert!(c.commit_up_to(off(5)));
        assert_eq!(c.committed(), off(7), "the contiguous run is absorbed");
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
    fn is_acked_probes_every_boundary_of_many_ranges() {
        // Exercise the binary-search comparator in `contains_ahead` across many disjoint,
        // non-adjacent runs: each range start is inclusive, each end exclusive, and the gaps
        // between runs (and the offsets bracketing the whole set) must read as unacked. A
        // comparator that mishandled the half-open boundary would fail exactly here.
        let mut c = AckCursor::new();
        // Acks leave runs 2..4, 6..7, 10..13, 20..21 with gaps at 0,1,4,5,7,8,9,13..20.
        for o in [2u64, 3, 6, 10, 11, 12, 20] {
            c.ack(off(o));
        }
        assert_eq!(c.ahead_ranges(), &[(2, 4), (6, 7), (10, 13), (20, 21)]);
        // Below the watermark (0) is the empty gap before the first run.
        assert!(!c.is_acked(off(0)) && !c.is_acked(off(1)));
        for &(s, e) in c.ahead_ranges() {
            assert!(c.is_acked(off(s)), "range start {s} is inclusive");
            assert!(c.is_acked(off(e - 1)), "last offset {} is acked", e - 1);
            assert!(!c.is_acked(off(e)), "range end {e} is exclusive");
        }
        // Interior gaps between runs and an offset far past the last run all read unacked.
        for gap in [4u64, 5, 7, 8, 9, 13, 14, 19, 21, 1_000] {
            assert!(!c.is_acked(off(gap)), "gap offset {gap} must be unacked");
        }
    }

    #[test]
    fn fragmenting_ack_at_the_cap_is_shed_and_reads_unacked() {
        // Cap of 2 runs. Acks at 2, 4 fragment into two disjoint runs; the third fragmenting ack
        // (6) must be SHED: refused, unrecorded, cursor untouched.
        let mut c = AckCursor::new();
        assert_eq!(c.ack_bounded(off(2), 2), BoundedAck::Recorded);
        assert_eq!(c.ack_bounded(off(4), 2), BoundedAck::Recorded);
        assert_eq!(c.ahead_runs(), 2);
        let before = c.clone();
        assert_eq!(c.ack_bounded(off(6), 2), BoundedAck::Shed);
        assert_eq!(c, before, "a shed leaves the cursor untouched");
        assert!(
            !c.is_acked(off(6)),
            "the shed offset reads unacked (it will redeliver)"
        );
        assert_eq!(c.ahead_runs(), 2, "the run count never passes the cap");
        // A re-ack of the shed offset lands once it MERGES (5 bridges toward it first).
        assert_eq!(
            c.ack_bounded(off(5), 2),
            BoundedAck::Recorded,
            "merge with 4..5 is never shed"
        );
        assert_eq!(
            c.ack_bounded(off(6), 2),
            BoundedAck::Recorded,
            "now merges into 4..6"
        );
        assert_eq!(c.ahead_ranges(), &[(2, 3), (4, 7)]);
    }

    #[test]
    fn watermark_and_merging_acks_are_never_shed_at_the_cap() {
        // Saturate the cap (2 runs at 2..3 and 4..5), then prove every progress-making ack still
        // lands: the watermark ack (0), the gap-fill merges (1, then 3 bridging both runs).
        let mut c = AckCursor::new();
        assert_eq!(c.ack_bounded(off(2), 2), BoundedAck::Recorded);
        assert_eq!(c.ack_bounded(off(4), 2), BoundedAck::Recorded);
        assert_eq!(
            c.ack_bounded(off(0), 2),
            BoundedAck::Recorded,
            "watermark ack always lands"
        );
        assert_eq!(c.committed(), off(1));
        assert_eq!(
            c.ack_bounded(off(1), 2),
            BoundedAck::Recorded,
            "gap fill absorbs 2..3"
        );
        assert_eq!(c.committed(), off(3));
        assert_eq!(
            c.ack_bounded(off(3), 2),
            BoundedAck::Recorded,
            "bridges into 4..5"
        );
        assert_eq!(
            c.committed(),
            off(5),
            "fully committed despite the saturated cap"
        );
        assert_eq!(c.ahead_runs(), 0);
        // Duplicates at the cap are still duplicates, not sheds.
        assert_eq!(c.ack_bounded(off(4), 2), BoundedAck::Duplicate);
    }

    #[test]
    fn cap_zero_accepts_only_in_order_acks() {
        // max_runs == 0: no out-of-order tracking at all — only the watermark ack lands. (A
        // caller with a `0 = unbounded` config convention maps 0 to usize::MAX before calling.)
        let mut c = AckCursor::new();
        assert_eq!(c.ack_bounded(off(1), 0), BoundedAck::Shed);
        assert_eq!(c.ack_bounded(off(0), 0), BoundedAck::Recorded);
        assert_eq!(c.committed(), off(1));
        assert_eq!(c.ahead_runs(), 0);
    }

    #[test]
    fn bounded_ack_refuses_the_exhausted_offset_boundary() {
        // Parity with `ack`: u64::MAX is the exhausted offset space, refused without wrap.
        let mut c = AckCursor::resume(off(u64::MAX));
        assert_eq!(c.ack_bounded(off(u64::MAX), 8), BoundedAck::Duplicate);
        assert_eq!(c.committed(), off(u64::MAX));
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

    /// Builds a crc-correct snapshot from arbitrary, possibly invalid, parts, so a test can feed
    /// `decode_snapshot` a structurally broken body that still passes the checksum.
    fn raw_snapshot(committed: u64, ranges: &[(u64, u64)]) -> Vec<u8> {
        let mut out = vec![SNAPSHOT_VERSION];
        out.extend_from_slice(&committed.to_le_bytes());
        for &(s, e) in ranges {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
        }
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    #[test]
    fn snapshot_round_trips_an_empty_cursor() {
        let c = AckCursor::resume(off(42));
        let mut buf = Vec::new();
        c.encode_snapshot(&mut buf);
        // No acked-ahead runs: just version (1) + committed (8) + crc (4).
        assert_eq!(buf.len(), 13);
        let restored = AckCursor::decode_snapshot(&buf).expect("own snapshot decodes");
        assert_eq!(restored, c);
    }

    #[test]
    fn snapshot_round_trips_multiple_runs() {
        let mut c = AckCursor::new();
        // Leave gaps so the acked-ahead set keeps several disjoint, non-adjacent runs.
        for o in [1u64, 2, 5, 8, 9, 10, 20] {
            c.ack(off(o));
        }
        assert!(
            c.ahead_runs() >= 3,
            "test needs several runs, got {}",
            c.ahead_runs()
        );
        let mut buf = Vec::new();
        c.encode_snapshot(&mut buf);
        assert_eq!(buf.len(), 13 + 16 * c.ahead_runs());
        let restored = AckCursor::decode_snapshot(&buf).expect("own snapshot decodes");
        assert_eq!(restored, c);
        assert_eq!(restored.ahead_ranges(), c.ahead_ranges());
    }

    #[test]
    fn decode_rejects_a_truncated_snapshot() {
        // Anything shorter than the 13-byte fixed header cannot hold a version + committed + crc.
        for len in 0..13usize {
            let buf = vec![0u8; len];
            assert_eq!(
                AckCursor::decode_snapshot(&buf),
                Err(SnapshotError::Truncated),
                "length {len} must be Truncated"
            );
        }
    }

    #[test]
    fn decode_rejects_a_mis_sized_snapshot() {
        // 13 + a partial range (not a whole 16-byte multiple) is a corrupt length.
        let snapshot = raw_snapshot(0, &[]);
        for extra in 1..16usize {
            let mut bad = snapshot.clone();
            // Insert junk bytes before the crc so the run region is not 16-aligned.
            bad.splice(9..9, vec![0u8; extra]);
            assert_eq!(
                AckCursor::decode_snapshot(&bad),
                Err(SnapshotError::BadLength { len: bad.len() }),
                "an extra {extra} bytes must be BadLength"
            );
        }
    }

    #[test]
    fn decode_rejects_an_unsupported_version() {
        let mut buf = raw_snapshot(7, &[(9, 11)]);
        buf[0] = SNAPSHOT_VERSION + 1;
        // Re-checksum so the only fault is the version byte: this proves the version is validated,
        // not merely caught by the crc.
        let crc_at = buf.len() - 4;
        let crc = crc32c::crc32c(&buf[..crc_at]);
        buf[crc_at..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            AckCursor::decode_snapshot(&buf),
            Err(SnapshotError::UnsupportedVersion(SNAPSHOT_VERSION + 1))
        );
    }

    #[test]
    fn decode_rejects_a_corrupt_checksum() {
        let mut c = AckCursor::new();
        for o in [0u64, 1, 4, 5] {
            c.ack(off(o));
        }
        let mut buf = Vec::new();
        c.encode_snapshot(&mut buf);
        // Flip one bit in the committed watermark; the trailing crc no longer matches.
        buf[1] ^= 0x01;
        assert_eq!(AckCursor::decode_snapshot(&buf), Err(SnapshotError::BadCrc));
    }

    #[test]
    fn decode_rejects_structurally_invalid_ranges() {
        // A crc-correct body whose ranges break the cursor's shape rules must still be rejected:
        // the codec delegates range validation to `resume_with_ahead`.
        let adjacent = raw_snapshot(5, &[(7, 9), (9, 11)]); // adjacent: should be one run
        assert!(matches!(
            AckCursor::decode_snapshot(&adjacent),
            Err(SnapshotError::Ranges(_))
        ));
        let below = raw_snapshot(5, &[(3, 4)]); // below the watermark
        assert!(matches!(
            AckCursor::decode_snapshot(&below),
            Err(SnapshotError::Ranges(_))
        ));
        let empty_run = raw_snapshot(5, &[(7, 7)]); // empty / reversed
        assert!(matches!(
            AckCursor::decode_snapshot(&empty_run),
            Err(SnapshotError::Ranges(_))
        ));
    }

    #[test]
    fn encode_appends_to_a_prefixed_buffer() {
        // The storage layer frames the snapshot after other bytes, so encode must not assume an
        // empty buffer and the appended suffix must decode on its own.
        let mut c = AckCursor::new();
        for o in [0u64, 2, 3] {
            c.ack(off(o));
        }
        let mut buf = vec![0xAA, 0xBB, 0xCC];
        let start = buf.len();
        c.encode_snapshot(&mut buf);
        let restored = AckCursor::decode_snapshot(&buf[start..]).expect("suffix decodes");
        assert_eq!(restored, c);
        assert_eq!(&buf[..start], &[0xAA, 0xBB, 0xCC]);
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

        /// The on-disk snapshot codec round-trips any reachable cursor: encode then decode is the
        /// identity, the checksum accepts the cursor's own bytes, and the framing length is exact.
        #[test]
        fn snapshot_codec_round_trips(acks in prop::collection::vec(0u64..40, 0..80)) {
            let mut c = AckCursor::new();
            for &o in &acks {
                c.ack(off(o));
            }
            let mut buf = Vec::new();
            c.encode_snapshot(&mut buf);
            // version (1) + committed (8) + crc (4) + 16 bytes per acked-ahead run.
            prop_assert_eq!(buf.len(), 13 + 16 * c.ahead_runs());
            let restored = AckCursor::decode_snapshot(&buf)
                .expect("a cursor's own snapshot is always well-formed");
            prop_assert_eq!(&restored, &c);
            for o in 0..45u64 {
                prop_assert_eq!(restored.is_acked(off(o)), c.is_acked(off(o)));
            }
        }

        /// crc32c detects every single-bit error in a message this small, so flipping any one bit
        /// of a snapshot is always rejected: no silently corrupted cursor is ever restored.
        #[test]
        fn snapshot_codec_detects_single_bit_flips(
            acks in prop::collection::vec(0u64..40, 0..40),
            idx in 0usize..4096,
            bit in 0u8..8,
        ) {
            let mut c = AckCursor::new();
            for &o in &acks {
                c.ack(off(o));
            }
            let mut buf = Vec::new();
            c.encode_snapshot(&mut buf);
            let i = idx % buf.len();
            buf[i] ^= 1u8 << bit;
            prop_assert!(
                AckCursor::decode_snapshot(&buf).is_err(),
                "a flip of byte {i} bit {bit} must be detected"
            );
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

        /// Interleaving per-message acks with cumulative `commit_up_to` jumps keeps every cursor
        /// invariant: the watermark is monotonic non-decreasing (never regresses, even on a lower
        /// `up_to`), the ahead set stays sorted/disjoint/non-adjacent/above-committed, and every
        /// offset below the watermark reads as acked. This is the broadcast cumulative-ack safety
        /// contract at the cursor level (#288): a commit-up-to never silently drops a gap below it.
        #[test]
        fn commit_up_to_interleaved_with_acks_holds_invariants(
            ops in prop::collection::vec((any::<bool>(), 0u64..40), 0..80),
        ) {
            let mut c = AckCursor::new();
            let mut last_committed = 0u64;
            for &(is_commit, o) in &ops {
                if is_commit {
                    c.commit_up_to(off(o));
                } else {
                    c.ack(off(o));
                }
                // Monotonic: the watermark never moves backwards under either op.
                prop_assert!(c.committed().get() >= last_committed, "committed regressed");
                last_committed = c.committed().get();
                // Shape: ranges non-empty, sorted, disjoint, non-adjacent, strictly above committed.
                let mut prev_end = c.committed().get();
                for &(s, e) in &c.ahead {
                    prop_assert!(s < e, "range is non-empty");
                    prop_assert!(s > prev_end, "ranges are above committed, disjoint, non-adjacent");
                    prev_end = e;
                }
                // No silent skip: every offset below the watermark is acked.
                for below in c.committed().get().saturating_sub(5)..c.committed().get() {
                    prop_assert!(c.is_acked(off(below)), "offset {below} below committed must be acked");
                }
            }
        }

        /// #543 criterion: under ANY ack order and any cap R >= 1, the run count never exceeds R,
        /// the watermark stays monotonic and never passes an unacked offset, a Recorded ack reads
        /// acked, and a Shed ack reads unacked with the cursor bit-identical (dup-not-loss). With
        /// R = usize::MAX the bounded ack is exactly the unbounded `ack`.
        #[test]
        fn bounded_ack_caps_the_runs_and_never_skips_a_gap(
            acks in prop::collection::vec(0u64..60, 0..120),
            cap in 1usize..6,
        ) {
            let mut c = AckCursor::new();
            let mut unbounded = AckCursor::new();
            let mut last_committed = 0u64;
            for &o in &acks {
                let before = c.clone();
                match c.ack_bounded(off(o), cap) {
                    BoundedAck::Recorded => prop_assert!(c.is_acked(off(o))),
                    BoundedAck::Duplicate => prop_assert_eq!(&c, &before),
                    BoundedAck::Shed => {
                        prop_assert_eq!(&c, &before, "a shed must leave the cursor untouched");
                        prop_assert!(!c.is_acked(off(o)), "a shed offset must read unacked");
                    }
                }
                prop_assert!(c.ahead_runs() <= cap, "run count {} passed the cap {cap}", c.ahead_runs());
                prop_assert!(c.committed().get() >= last_committed, "watermark regressed");
                last_committed = c.committed().get();
                // The load-bearing safety line: nothing below the watermark is ever unacked.
                for below in 0..c.committed().get() {
                    prop_assert!(c.is_acked(off(below)), "offset {below} below committed must be acked");
                }
                // usize::MAX-capped bounded ack tracks the unbounded ack exactly.
                unbounded.ack_bounded(off(o), usize::MAX);
            }
            let mut plain = AckCursor::new();
            for &o in &acks {
                plain.ack(off(o));
            }
            prop_assert_eq!(&unbounded, &plain, "usize::MAX cap must equal the unbounded ack");
            // The bounded cursor never commits PAST the unbounded one (sheds only defer progress).
            prop_assert!(c.committed().get() <= plain.committed().get());
        }

        /// A shed is a DEFERRAL, not a loss: re-acking every offset after a capped first pass
        /// (redelivery + re-ack, which is what the engine's poll loop does) always converges to
        /// the fully-committed cursor, because merges and watermark acks are never shed.
        #[test]
        fn shed_offsets_converge_after_redelivery(perm in any_permutation(1..30usize), cap in 1usize..4) {
            let mut c = AckCursor::new();
            let n = perm.len() as u64;
            for &o in &perm {
                let _ = c.ack_bounded(off(o as u64), cap);
            }
            // Redeliver-and-re-ack every still-unacked offset, in order (the engine's poll scan
            // is in-order from the watermark, so in-order is the faithful model).
            for o in 0..n {
                if !c.is_acked(off(o)) {
                    prop_assert_eq!(
                        c.ack_bounded(off(o), cap),
                        BoundedAck::Recorded,
                        "an in-order re-ack at the watermark can never shed"
                    );
                }
            }
            prop_assert_eq!(c.committed(), off(n), "every message eventually commits");
            prop_assert_eq!(c.ahead_runs(), 0);
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
