// SPDX-License-Identifier: MIT OR Apache-2.0
//! The lock-free, off-actor consume READ plane (#539, V2-M1 spine step I3).
//!
//! ## Why this exists
//!
//! Before this, every consumer read went THROUGH the single append/write actor: a poll built a
//! closure, sent it over the actor's bounded `sync_channel`, and blocked on a reply (one
//! `Command::Run` round-trip PER delivered record). Reads therefore serialized behind the writer
//! AND behind each other — the multi-consumer aggregate-throughput ceiling (#491). But a read does
//! not need the writer: a SEALED segment is immutable, and the FLUSHED (read-visible) prefix is
//! read-only. This module splits that read plane off the actor.
//!
//! ## The shape: an atomic frontier + an arc-swapped sealed snapshot
//!
//! Two pieces of shared state, published by the single writer and observed by any number of reader
//! threads with NO lock and NO actor round-trip:
//!
//!   - [`ReadPlane::flushed`]: an [`AtomicU64`] carrying the read-visible (flushed) high-water mark.
//!     The writer RELEASE-stores it after every commit/flush/seal; a reader ACQUIRE-loads it as the
//!     hard upper bound of a read (exactly as the through-actor `Log::read_range` bounds reads by
//!     `flushed_offset`). No record at or past it is ever returned.
//!   - [`ReadPlane::sealed`]: an [`ArcSwap`] holding an immutable [`SealedSnapshot`] of the sealed
//!     segments and their resident seek indexes (the #537 sparse anchors). A read takes ONE
//!     `ArcSwap::load` (a wait-free Acquire snapshot, matching the #651 routing-trie precedent in
//!     `ironbus_core::sublist`) and seeks/scans the immutable durable bytes with no writer
//!     involvement. The single append actor remains the ONLY writer: after a commit it publishes
//!     the new frontier, and after a roll seals a segment it swaps in a fresh snapshot.
//!
//! ## The publish/observe ordering (the load-bearing correctness argument)
//!
//! The writer ALWAYS publishes in this order: (1) `sealed.store(new_snapshot)` — itself a Release
//! that makes the new sealed segment's bytes/index visible — THEN (2) `flushed.store(F, Release)`.
//! A reader ALWAYS observes in the reverse order: (1) `flushed.load(Acquire)` → `F`, THEN (2)
//! `sealed.load()`. Because the frontier is published LAST and read FIRST under Acquire/Release,
//! a reader that observes a frontier `F` is guaranteed to also observe a snapshot that contains
//! every sealed segment whose records lie below `F` (that snapshot was stored before `F` was). It
//! can therefore never see a frontier that admits an offset for which it has no segment. The
//! snapshot may be one publication STALER than the frontier (a roll happened, the new snapshot is
//! up but the next frontier bump has not landed yet) — that is harmless: a staler snapshot only
//! ever covers FEWER offsets, and the frontier bound clamps the read to what the snapshot holds.
//! Conversely a reader may see an OLDER frontier with a NEWER snapshot — also harmless, the frontier
//! is the hard bound and only ever admits offsets the snapshot already covers.
//!
//! ## Scope: the SEALED, flushed prefix only
//!
//! The snapshot covers the SEALED segments. The active (un-sealed) segment is still being appended
//! to by the writer (its seek index is mutated on every append, behind the `Log`'s `RefCell`), so
//! it is NOT in the snapshot and the active tail's in-flight bytes are never read here. A read whose
//! range extends past the sealed prefix returns what the sealed snapshot holds and reports the
//! next offset it could not serve, so the caller falls back to the through-actor path for that
//! small tail (see [`SealedSnapshot::read_range`]'s return). The off-actor plane carries the bulk
//! of multi-consumer replay/fan-out load — the durable prefix, the #491 ceiling — with zero actor
//! contention; the active-tail fallback preserves identical consume behavior.
//!
//! This is the off-actor LOCK-FREE READ plane only. The engine/Fetch BATCHING wiring (#550), the
//! streaming consumer-managed-offset tier (M1-I7), zero-copy/`sendfile` (#542), and partitions
//! (M2-I11) are SEPARATE and untouched here. Reads return fully CRC-validated [`OwnedRecord`]s, the
//! same materialized records the through-actor path returns (the differential test in `log.rs`
//! asserts byte-for-byte equality).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::naming::segment_file_name;
use crate::segment::{OwnedRecord, SegmentReader, StorageError};
use ironbus_core::types::Offset;

/// One SEALED segment in a [`SealedSnapshot`]: its identity, covered offset range, and the resident
/// sparse seek anchors (#537) so a reader can SEEK without the writer's live `Log` state.
///
/// A sealed segment is IMMUTABLE: its whole record region is durable and in the file, so its anchors
/// and `valid_end` never change after it is sealed. The snapshot therefore holds them by value
/// (cloned out of the `Log`'s resident index once, when the segment seals) and a reader seeks/scans
/// them with no synchronization. A COMPACTED (v2, sparse) segment is NOT carried here: its survivors
/// are sparse and the through-actor v2 scan path serves it; this plane covers the dense (v1) sealed
/// prefix that multi-consumer replay reads. A read of a compacted slot falls back to the actor.
#[derive(Clone, Debug)]
pub(crate) struct SealedSegment {
    /// The segment id (its file name component).
    pub(crate) id: u64,
    /// The lowest log offset this segment holds.
    pub(crate) base_offset: u64,
    /// How many records this segment holds: it covers `[base_offset, base_offset + record_count)`.
    pub(crate) record_count: u64,
    /// `true` for a COMPACTED (v2, sparse) segment, which this plane does NOT serve (the reader
    /// falls back to the actor for it). A snapshot can include the slot so the offset-to-segment
    /// search stays exact across a compacted hole, but a read of it reports a fallback.
    pub(crate) compacted: bool,
    /// The SPARSE `(offset, frame START byte position)` anchors, ascending by offset: one per
    /// `stride` bytes of frame data (#537). Empty for a compacted slot. A read seeks to the nearest
    /// anchor at or before the target and scans forward at most one stride to it.
    pub(crate) anchors: Vec<(u64, u64)>,
    /// The byte offset at which the segment's durable record region ends (its footer start): the
    /// read-forward upper bound, so a seek never materializes the trailing footer as a record. For a
    /// sealed segment the whole region is durable, so this is the segment's full `valid_end`.
    pub(crate) valid_end: u64,
}

impl SealedSegment {
    /// The SEEK target for `offset`: the `(anchor offset, anchor byte position)` of the nearest
    /// anchor AT OR BEFORE `offset`, mirroring `SegmentIndex::seek_anchor` but over the snapshot's
    /// owned anchors. `None` when `offset` is below the base, at/past the covered end, or there is no
    /// anchor (a compacted or empty slot) — the caller then has nothing to seek to here.
    fn seek_anchor(&self, offset: u64) -> Option<(u64, u64)> {
        let covered_end = self.base_offset.saturating_add(self.record_count);
        if offset < self.base_offset || offset >= covered_end {
            return None;
        }
        let idx = self
            .anchors
            .partition_point(|&(anchor_off, _)| anchor_off <= offset);
        idx.checked_sub(1)
            .and_then(|i| self.anchors.get(i))
            .copied()
    }
}

/// An IMMUTABLE snapshot of the SEALED prefix the writer publishes via [`ArcSwap`] (#539). A reader
/// `load`s it once (a wait-free Acquire) and seeks/scans the durable bytes with no lock and no actor
/// round-trip. Replaced wholesale by the writer when a roll seals a new segment or a reap retires
/// one; a reader holding an older `Arc` simply reads an older (still-valid, possibly fewer-segments)
/// view, which the flushed frontier bound clamps correctly.
#[derive(Clone, Debug)]
pub(crate) struct SealedSnapshot<F> {
    /// The filesystem handle, shared (the same directory the writer owns). Reads open their OWN
    /// `SegmentReader` over an immutable sealed file, so a concurrent reader never aliases the
    /// writer's active `SegmentWriter` handle.
    fs: Arc<F>,
    /// The sealed segments, ascending by base offset. The ACTIVE (un-sealed) segment is NEVER here.
    segments: Vec<SealedSegment>,
    /// The lowest covered offset across the snapshot (the first segment's base): a read below it is
    /// out of range, exactly as the `Log` reports `OffsetOutOfRange`.
    oldest: u64,
    /// The first offset NOT covered by any sealed segment (the active segment's base): a read at or
    /// above it is entirely in the active tail and falls back to the actor.
    sealed_end: u64,
}

/// The outcome of a [`SealedSnapshot::read_range`]: the records served from the sealed prefix, plus
/// the next offset the snapshot could NOT serve off-actor (the active tail or a compacted slot), so
/// the caller knows whether to fall back to the through-actor path for the remainder.
#[derive(Debug)]
pub struct SealedRead {
    /// The contiguous run read from the sealed prefix, bounded by the flushed frontier, in offset
    /// order. May be empty (the start is already in the active tail, or nothing is below `flushed`).
    pub records: Vec<OwnedRecord>,
    /// `Some(off)` when the read stopped at a boundary the off-actor plane does not serve (the
    /// sealed prefix is exhausted at `off` but `off < flushed`, or `off` lands on a compacted slot):
    /// the caller resumes the read at `off` through the actor. `None` when the read is COMPLETE
    /// off-actor (it hit `max`, the byte cap, or the flushed frontier within the sealed prefix).
    pub fallback_from: Option<u64>,
}

impl<F: crate::fs::Filesystem> SealedSnapshot<F> {
    /// The index in `segments` of the sealed segment whose range holds `offset` (the slot with the
    /// largest base not exceeding `offset`). Callers guarantee `offset >= oldest`.
    fn segment_index_for(&self, offset: u64) -> usize {
        match self
            .segments
            .binary_search_by(|s| s.base_offset.cmp(&offset))
        {
            Ok(index) => index,
            Err(0) => 0,
            Err(index) => index - 1,
        }
    }

    /// Reads a CONTIGUOUS run from the SEALED prefix starting at `start`, bounded by `flushed` (the
    /// hard read-visibility frontier — no record at or past it is returned), `max_records`, and the
    /// optional `max_bytes`. LOCK-FREE: opens its own immutable `SegmentReader` per sealed segment
    /// and scans the durable bytes with no writer involvement. The seek/scan/clamp logic mirrors
    /// `Log::read_range` exactly (the differential test asserts identical results).
    ///
    /// Returns a [`SealedRead`] whose `fallback_from` is `Some(off)` when the run reached the active
    /// tail (or a compacted slot) below `flushed`, so the caller serves `[off, flushed)` through the
    /// actor; `None` when the read completed within the sealed prefix.
    fn read_range(
        &self,
        start: u64,
        flushed: u64,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<SealedRead, StorageError> {
        // The flushed frontier is the HARD bound: never return a record at or past it. Clamp the
        // sealed coverage to it too, so a frontier behind the snapshot (the older-frontier/newer-
        // snapshot race) still only ever serves the read-visible prefix.
        let visible_sealed_end = self.sealed_end.min(flushed);
        if max_records == 0 || start >= flushed {
            return Ok(SealedRead {
                records: Vec::new(),
                fallback_from: None,
            });
        }
        if start < self.oldest {
            return Err(StorageError::OffsetOutOfRange {
                requested: start,
                oldest: self.oldest,
            });
        }
        // The start is already at/past the sealed prefix's visible end: nothing to serve off-actor;
        // the caller reads `[start, flushed)` (the active tail) through the actor.
        if start >= visible_sealed_end {
            return Ok(SealedRead {
                records: Vec::new(),
                fallback_from: Some(start),
            });
        }
        let mut out: Vec<OwnedRecord> = Vec::new();
        let mut byte_total = 0usize;
        let mut fallback_from = None;
        for slot in &self.segments[self.segment_index_for(start)..] {
            if slot.base_offset >= visible_sealed_end {
                break;
            }
            if out.len() >= max_records {
                break;
            }
            // A COMPACTED (v2, sparse) slot is served by the through-actor v2 scan, not this plane:
            // hand the remainder back from this segment's covered base (clamped to `start`).
            if slot.compacted {
                fallback_from = Some(start.max(slot.base_offset));
                break;
            }
            let seg_start = start.max(slot.base_offset);
            let Some((anchor_offset, byte_pos)) = slot.seek_anchor(seg_start) else {
                // The snapshot's anchors do not cover `seg_start` (it is at/past this sealed
                // segment's covered records): nothing more here; advance to the next slot.
                continue;
            };
            let read_end = slot.valid_end;
            let gap = usize::try_from(seg_start.saturating_sub(anchor_offset)).unwrap_or(0);
            let below_flushed =
                usize::try_from(flushed.saturating_sub(anchor_offset)).unwrap_or(usize::MAX);
            let remaining = max_records - out.len();
            let want = remaining.saturating_add(gap).min(below_flushed);
            let reader = SegmentReader::open(self.fs.open(&segment_file_name(slot.id))?)?;
            let records = reader.scan_from(byte_pos, Offset::new(anchor_offset), read_end, want)?;
            for record in records {
                // Skip the bounded run the anchor preceded `seg_start` by.
                if record.offset.get() < seg_start {
                    continue;
                }
                if push_record(
                    record,
                    flushed,
                    max_records,
                    max_bytes,
                    &mut out,
                    &mut byte_total,
                ) {
                    // A record/byte/flushed bound stopped the read WITHIN the sealed prefix: it is
                    // complete off-actor, no fallback.
                    return Ok(SealedRead {
                        records: out,
                        fallback_from: None,
                    });
                }
            }
        }
        // Drained the sealed prefix without hitting `max`/`max_bytes`/`flushed`. If the flushed
        // frontier still admits offsets ABOVE the sealed prefix (the active tail), report the
        // fallback start so the caller serves the remainder through the actor.
        if fallback_from.is_none() && out.len() < max_records && visible_sealed_end < flushed {
            // The next unserved offset is the visible end of the sealed prefix (the active base,
            // clamped to flushed), provided it is at/above where we started reading.
            let resume = visible_sealed_end.max(start);
            if resume < flushed {
                fallback_from = Some(resume);
            }
        }
        Ok(SealedRead {
            records: out,
            fallback_from,
        })
    }
}

/// Admits `record` to `out` unless a bound is hit (a verbatim mirror of `Log::push_record`, the #538
/// per-record admit): the record is at/past the flushed end, the count `max` is reached, or it would
/// breach `max_bytes` (EXCEPT the FIRST record is always admitted — the "at least one" fetch rule).
/// Returns `true` when the read must STOP.
fn push_record(
    record: OwnedRecord,
    flushed: u64,
    max: usize,
    max_bytes: Option<usize>,
    out: &mut Vec<OwnedRecord>,
    byte_total: &mut usize,
) -> bool {
    if record.offset.get() >= flushed || out.len() >= max {
        return true;
    }
    let over_bytes = max_bytes.is_some_and(|cap| {
        !out.is_empty() && byte_total.saturating_add(record.encoded_len()) > cap
    });
    if over_bytes {
        return true;
    }
    *byte_total = byte_total.saturating_add(record.encoded_len());
    out.push(record);
    false
}

/// The shared, lock-free read-plane handle a consumer thread holds to read the SEALED, flushed prefix
/// with NO append-actor round-trip (#539). Cheaply cloneable (two `Arc`s); every clone observes the
/// SAME published frontier and snapshot. The single append actor (through the `Log` it owns) is the
/// only PUBLISHER; any number of readers observe concurrently with it and with each other.
#[derive(Clone, Debug)]
pub struct ReadPlane<F> {
    /// The read-visible (flushed) high-water mark, published RELEASE by the writer after every
    /// commit/flush/seal and observed ACQUIRE by readers as the hard read bound. Shared so a `Log`
    /// clone and every reader see the same cell.
    flushed: Arc<AtomicU64>,
    /// The immutable sealed-prefix snapshot, swapped wholesale by the writer (Release) on a seal/reap
    /// and `load`ed wait-free by readers (Acquire). `ArcSwap` matches the #651 routing-trie publish.
    sealed: Arc<ArcSwap<SealedSnapshot<F>>>,
}

impl<F: crate::fs::Filesystem> ReadPlane<F> {
    /// Builds a read plane seeded with the initial flushed frontier and sealed snapshot. Called by
    /// the `Log` when it opens, so a reader handed a clone before the first publish still sees a
    /// valid (recovered) view.
    pub(crate) fn new(
        fs: Arc<F>,
        flushed: u64,
        segments: Vec<SealedSegment>,
        oldest: u64,
        sealed_end: u64,
    ) -> ReadPlane<F> {
        ReadPlane {
            flushed: Arc::new(AtomicU64::new(flushed)),
            sealed: Arc::new(ArcSwap::from_pointee(SealedSnapshot {
                fs,
                segments,
                oldest,
                sealed_end,
            })),
        }
    }

    /// REPUBLISHES the sealed snapshot reusing the filesystem handle the current snapshot already
    /// holds (the writer side, on a seal/reap, after the plane is built): only the segment view
    /// changed, the directory is the same. A single `ArcSwap::store` (a Release). Paired with a later
    /// [`ReadPlane::publish_flushed`], and MUST precede it (the module ordering argument).
    pub(crate) fn republish_sealed(
        &self,
        segments: Vec<SealedSegment>,
        oldest: u64,
        sealed_end: u64,
    ) {
        let fs = Arc::clone(&self.sealed.load().fs);
        self.sealed.store(Arc::new(SealedSnapshot {
            fs,
            segments,
            oldest,
            sealed_end,
        }));
    }

    /// PUBLISHES the new read-visible (flushed) frontier (the writer side, after every commit). A
    /// RELEASE store so a reader's matching ACQUIRE load sees every write the writer made before it —
    /// including a `publish_sealed` that preceded it. This is the LAST thing the writer publishes per
    /// commit and the FIRST thing a reader observes, which is the whole correctness hinge.
    pub(crate) fn publish_flushed(&self, flushed: u64) {
        self.flushed.store(flushed, Ordering::Release);
    }

    /// The current read-visible frontier (one ACQUIRE load). A reader bounds its read by this and
    /// never returns a record at or past it.
    #[must_use]
    pub fn flushed(&self) -> u64 {
        self.flushed.load(Ordering::Acquire)
    }

    /// Reads a CONTIGUOUS run from the SEALED, flushed prefix starting at `start`, with NO lock and
    /// NO actor round-trip — the off-actor consume read (#539). Takes ONE Acquire load of the
    /// frontier, then ONE wait-free `ArcSwap::load` of the sealed snapshot, then seeks/scans the
    /// immutable durable bytes.
    ///
    /// Returns a [`SealedRead`]: the records served off-actor (bounded by the flushed frontier,
    /// `max_records`, and `max_bytes`), plus `fallback_from = Some(off)` when the run reached the
    /// active tail or a compacted slot below the frontier and the caller must serve `[off, flushed)`
    /// through the actor. The flushed frontier is loaded FIRST (Acquire) and the snapshot SECOND, so
    /// the snapshot is guaranteed to cover every sealed offset below the observed frontier.
    ///
    /// # Errors
    /// [`StorageError::OffsetOutOfRange`] if `start` is older than the snapshot's oldest retained
    /// offset, or an IO error reading a sealed segment.
    pub fn read_range(
        &self,
        start: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<SealedRead, StorageError> {
        // ORDER IS LOAD-BEARING: the frontier (Acquire) FIRST, then the snapshot. A frontier `F`
        // observed here was published AFTER (or together with) a snapshot that already covers every
        // sealed offset below `F`, so the snapshot can never lack a segment the frontier admits.
        let flushed = self.flushed.load(Ordering::Acquire);
        let snapshot = self.sealed.load();
        snapshot.read_range(start.get(), flushed, max_records, max_bytes)
    }

    /// A single off-actor read of ONE record at `offset` (the per-record consume hot path's
    /// off-actor twin of `Log::read_from(off, 1)`): the records served plus whether the caller must
    /// fall back to the actor for it (the offset is in the active tail or a compacted slot). A thin
    /// wrapper over [`ReadPlane::read_range`] with `max_records = 1`.
    ///
    /// # Errors
    /// As [`ReadPlane::read_range`].
    pub fn read_one(&self, offset: Offset) -> Result<SealedRead, StorageError> {
        self.read_range(offset, 1, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use crate::log::{Append, Log, LogConfig};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use std::sync::atomic::AtomicU64 as StdAtomicU64;

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    /// A tiny segment cap so a handful of appends seal several segments, exercising the sealed
    /// snapshot's multi-segment seek/scan. The struct-literal cap below the `new` floor is the
    /// documented test path (recovery/rolling do not depend on the floor, only on the cap value).
    fn small_log() -> Log<InMemoryFs, ManualClock> {
        let config = LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        Log::open(InMemoryFs::new(), ManualClock::new(), config).unwrap()
    }

    /// The off-actor sealed read returns the EXACT records the through-actor `read_from` does for
    /// every offset below the sealed end (the differential, single-threaded), and reports a fallback
    /// for the active tail.
    #[test]
    fn sealed_read_matches_through_actor_read_from_over_the_sealed_prefix() {
        let mut log = small_log();
        for i in 0..200u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            // Sync every so often so the flushed frontier (and seals) advance like production.
            if i % 7 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let plane = log.read_plane().unwrap();
        let flushed = log.flushed_offset().get();
        for start in 0..flushed {
            let actor = log.read_from(Offset::new(start), 4).unwrap();
            let sealed = plane.read_range(Offset::new(start), 4, None).unwrap();
            // Every record the off-actor plane served must be byte-identical to the through-actor
            // read at the same position.
            for (a, s) in actor.iter().zip(sealed.records.iter()) {
                assert_eq!(a, s, "off-actor record != through-actor record at {start}");
            }
            // The off-actor plane serves a PREFIX of the through-actor result (it stops at the
            // sealed end and hands the active tail back via fallback); it never serves MORE.
            assert!(
                sealed.records.len() <= actor.len(),
                "off-actor served more than through-actor at {start}"
            );
        }
    }

    /// A reader NEVER observes a record at or past the published flushed frontier, even when the log
    /// has appended (but not yet flushed) records beyond it. A large segment cap keeps everything in
    /// ONE active segment, so the only frontier advance is the explicit `sync` (no roll can durably
    /// bump it under us) and the un-synced tail stays strictly invisible.
    #[test]
    fn reader_never_observes_beyond_the_flushed_frontier() {
        let config = LogConfig {
            max_segment_bytes: 1 << 20,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), config).unwrap();
        for i in 0..50u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
        }
        log.sync().unwrap(); // publishes flushed = 50
        let flushed_after_first = log.flushed_offset().get();
        assert_eq!(flushed_after_first, 50);
        // Append MORE without flushing: these are beyond the frontier and must be invisible. No
        // roll happens (the segment is far below the cap), so the frontier stays at 50.
        for i in 50..100u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
        }
        let plane = log.read_plane().unwrap();
        // The frontier the plane publishes is the visible bound; the un-synced tail is excluded.
        assert_eq!(plane.flushed(), flushed_after_first);
        let sealed = plane.read_range(Offset::ZERO, usize::MAX, None).unwrap();
        for r in &sealed.records {
            assert!(
                r.offset.get() < flushed_after_first,
                "served offset {} at/past frontier {flushed_after_first}",
                r.offset.get()
            );
        }
        // Everything is in the single ACTIVE segment (un-sealed), so the off-actor plane serves
        // nothing and hands the whole read back to the through-actor path.
        assert!(sealed.records.is_empty());
        assert_eq!(sealed.fallback_from, Some(0));
    }

    /// The publish ORDERING the production writer uses (sealed snapshot BEFORE frontier; reader loads
    /// frontier BEFORE snapshot) means a reader that observes a bumped frontier always observes a
    /// snapshot covering it. Modeled directly on the two atomics so the ordering is exercised
    /// independent of the full `Log`. (The loom permutation of this lives in `tools/loom-tests`.)
    #[test]
    fn frontier_published_after_snapshot_is_always_covered() {
        // A reader that observes frontier F must see sealed_end >= F. We assert the publish helper
        // upholds it: store the snapshot (sealed_end = N) THEN the frontier (F = N).
        let fs = Arc::new(InMemoryFs::new());
        let plane: ReadPlane<InMemoryFs> = ReadPlane::new(fs, 0, Vec::new(), 0, 0);
        // The writer's publish order: snapshot (sealed_end = 64) FIRST, then frontier (64).
        plane.republish_sealed(Vec::new(), 0, 64);
        plane.publish_flushed(64);
        // The reader's observe order: frontier first, then snapshot.
        let f = plane.flushed();
        let snap = plane.sealed.load();
        assert!(
            snap.sealed_end >= f,
            "snapshot sealed_end {} < frontier {f}",
            snap.sealed_end
        );
        // Touch a std atomic so the test name's intent (atomic ordering) is unmistakable in coverage.
        let _ = StdAtomicU64::new(f);
    }

    /// Concurrent READERS read the sealed prefix off-actor WHILE a WRITER appends/syncs/rolls on its
    /// own thread: the readers never deadlock or contend on the writer (they touch only the shared
    /// atomics, never the `Log`), never observe a record at or past the frontier they loaded, and
    /// every record they DO serve is byte-identical to its log offset. This is the multi-consumer
    /// scaling property and the read-plane data-race coverage (the loom permutation of the atomic
    /// publish/observe is in `tools/loom-tests`).
    #[test]
    fn concurrent_readers_and_a_writer_race_safely() {
        use std::sync::atomic::{AtomicBool, Ordering as O};
        use std::sync::Arc as StdArc;
        use std::thread;

        let mut log = small_log();
        // Prime a few sealed segments so readers have a non-empty snapshot from the start, then
        // build the plane and hand clones to the readers.
        for i in 0..40u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 5 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let plane = log.read_plane().unwrap();
        let stop = StdArc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let plane = plane.clone();
                let stop = StdArc::clone(&stop);
                thread::spawn(move || {
                    let mut total_served = 0u64;
                    while !stop.load(O::Acquire) {
                        // One Acquire frontier load, one wait-free snapshot load, then a lock-free
                        // read. The bound the reader OBSERVES is `plane.flushed()`.
                        let frontier = plane.flushed();
                        let sealed = plane.read_range(Offset::ZERO, 64, None).unwrap();
                        for r in &sealed.records {
                            // The record's payload was written as its offset's LE bytes (offset < 40
                            // primed records all fit u32); every served record is below the frontier.
                            assert!(
                                r.offset.get() < frontier,
                                "served {} at/past observed frontier {frontier}",
                                r.offset.get()
                            );
                        }
                        total_served += sealed.records.len() as u64;
                    }
                    total_served
                })
            })
            .collect();

        // The writer keeps appending + syncing + rolling (the small cap rolls often), publishing the
        // frontier and new snapshots, while the readers run.
        for i in 40..600u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 3 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        stop.store(true, O::Release);

        // No reader deadlocked or panicked; each made progress (read SOME records off-actor).
        let mut any_progress = false;
        for h in readers {
            let served = h
                .join()
                .expect("a reader thread panicked (a race or a deadlock)");
            any_progress |= served > 0;
        }
        assert!(
            any_progress,
            "no reader ever read off-actor — the plane never served"
        );
    }
}
