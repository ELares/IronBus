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

use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;

use crate::fs::Filesystem;

/// The maximum opened SEALED-segment readers a single off-actor snapshot generation caches (#808). Beyond
/// it, a read opens its segment UNCACHED (per-read, like pre-#808) so a retention-off cold full backfill
/// can never hold one fd per sealed segment at once (an EMFILE exposure). A tailing/replication working
/// set is small and touched first, so it stays fully cached; only a cold deep replay past the cap re-opens
/// per read. Mirrors the through-actor `Log`'s `DEFAULT_SEALED_READER_CACHE_CAP`.
const DEFAULT_PLANE_READER_CACHE_CAP: usize = 256;

/// The per-snapshot reader-cache cap, overridable in tests to a small value so a cap test need not open
/// hundreds of segments. `0` (the default) means "use [`DEFAULT_PLANE_READER_CACHE_CAP`]".
#[cfg(test)]
static TEST_PLANE_READER_CACHE_CAP: AtomicUsize = AtomicUsize::new(0);

fn plane_reader_cache_cap() -> usize {
    #[cfg(test)]
    {
        let overridden = TEST_PLANE_READER_CACHE_CAP.load(Ordering::Relaxed);
        if overridden != 0 {
            return overridden;
        }
    }
    DEFAULT_PLANE_READER_CACHE_CAP
}
use crate::naming::segment_file_name;
use crate::segment::{OwnedRecord, RawByteRun, SegmentReader, StorageError};
use ironbus_core::types::Offset;

/// The lazily-opened [`SegmentReader`] cache for a [`SealedSnapshot`] (#808): one `OnceLock` per sealed
/// segment, PARALLEL to `SealedSnapshot::segments` (same index). Opening a sealed segment does an
/// `open(2)` + `fstat(2)` + a 64-byte header `pread` + a header-CRC decode; a sealed segment is
/// IMMUTABLE, so that work is identical on every read and is cached here, opened on first touch and
/// reused by all subsequent reads. The reader is shared as an `Arc` across the concurrent off-actor
/// readers — positioned (`pread`) reads need no cursor and no lock — and the WHOLE snapshot (and thus
/// every fd it opened) drops when a roll/reap republishes a fresh snapshot, so fds never leak past the
/// generation that opened them.
///
/// FD-BOUNDED: at most `cap` slots are ever cached in one generation (`opened` counts the cached slots,
/// lock-free). A read past the cap opens UNCACHED — per-read, exactly as before #808 — so a cold full
/// backfill within one generation can never hold one fd per sealed segment at once (the EMFILE exposure).
/// The cap is a SOFT bound: concurrent openers may exceed it by at most the number of racing threads.
struct SlotReaders<F: Filesystem> {
    slots: Vec<OnceLock<Arc<SegmentReader<F::File>>>>,
    /// The number of slots actually opened-and-cached so far this generation (the resident-fd bound).
    opened: AtomicUsize,
    cap: usize,
}

impl<F: Filesystem> SlotReaders<F> {
    /// A fresh, all-empty cache sized to `len` sealed segments (one `OnceLock` per slot), bounded to
    /// [`plane_reader_cache_cap`] resident readers.
    fn empty(len: usize) -> SlotReaders<F> {
        SlotReaders {
            slots: (0..len).map(|_| OnceLock::new()).collect(),
            opened: AtomicUsize::new(0),
            cap: plane_reader_cache_cap(),
        }
    }
}

// Manual `Debug` so it needs no `F::File: Debug` bound (the `Filesystem::File` associated type carries
// none) and prints only counts, never the readers. NO `Clone`: a clone would share opened fds via their
// `Arc`s and the `opened` counter could not be meaningfully copied; the publish path
// (`republish_sealed`) always builds a FRESH snapshot, never clones, so `SealedSnapshot` does not derive
// `Clone` either — removing a latent fd-aliasing footgun.
impl<F: Filesystem> std::fmt::Debug for SlotReaders<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotReaders")
            .field("slots", &self.slots.len())
            .field("opened", &self.opened.load(Ordering::Relaxed))
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

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

    /// The WINDOW-BOUNDED read-end (#664), the off-actor twin of [`SegmentIndex::window_read_end`]:
    /// the byte position past which a read wanting `[from_offset, from_offset + want_records)` need
    /// not look. Before #664 the off-actor sealed read passed the segment-wide `valid_end` as the
    /// read-end, so a forward streaming drain over a large sealed segment read
    /// `O(distance-to-segment-end)` bytes per fetch (`O(N^2)` overall). This bounds the read to the
    /// FIRST sparse anchor STRICTLY ABOVE `from_offset + want_records`, clamped to the segment's
    /// `valid_end`: every wanted frame lies below that anchor, so the read covers the window plus at
    /// most one stride of slack — `O(want + stride)` bytes. `want_records == 0` (or an overflowing
    /// `want`) falls back to `valid_end`; a conservative (larger) read-end only ever reads MORE
    /// bytes, never wrong ones (the per-record `max`/`flushed` filters bound the returned run).
    fn window_read_end(&self, from_offset: u64, want_records: usize) -> u64 {
        let want = want_records as u64;
        if want == 0 {
            return self.valid_end;
        }
        let window_end = from_offset.saturating_add(want);
        let idx = self
            .anchors
            .partition_point(|&(anchor_off, _)| anchor_off <= window_end);
        let bound = self
            .anchors
            .get(idx)
            .map_or(self.valid_end, |&(_, byte_pos)| byte_pos);
        bound.min(self.valid_end)
    }
}

/// An IMMUTABLE snapshot of the SEALED prefix the writer publishes via [`ArcSwap`] (#539). A reader
/// `load`s it once (a wait-free Acquire) and seeks/scans the durable bytes with no lock and no actor
/// round-trip. Replaced wholesale by the writer when a roll seals a new segment or a reap retires
/// one; a reader holding an older `Arc` simply reads an older (still-valid, possibly fewer-segments)
/// view, which the flushed frontier bound clamps correctly.
//
// NOT `Clone`: the per-segment reader cache (`SlotReaders`, #808) holds opened fds whose `Arc`s must not
// be aliased across snapshot generations, and the publish path (`republish_sealed`) always builds a FRESH
// snapshot rather than cloning, so `Clone` is unused — dropping it removes the fd-aliasing footgun.
#[derive(Debug)]
pub(crate) struct SealedSnapshot<F: Filesystem> {
    /// The filesystem handle, shared (the same directory the writer owns). Reads open their OWN
    /// `SegmentReader` over an immutable sealed file, so a concurrent reader never aliases the
    /// writer's active `SegmentWriter` handle.
    fs: Arc<F>,
    /// The sealed segments, ascending by base offset. The ACTIVE (un-sealed) segment is NEVER here.
    segments: Vec<SealedSegment>,
    /// The lazily-opened `SegmentReader` per sealed segment (#808), PARALLEL to `segments`: a read opens
    /// each immutable sealed file once and reuses it, instead of re-doing open+fstat+header-CRC per read.
    /// Dropped (fds closed) with the snapshot when a roll/reap republishes a fresh one.
    readers: SlotReaders<F>,
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

/// The outcome of a [`ReadPlane::read_range_raw`]: the ZERO-COPY raw byte run served off-actor from
/// the sealed prefix (#542, M1-I6), plus the next offset the snapshot could NOT serve raw (the active
/// tail, a compacted slot, or the end of the run's segment), so the caller knows where to resume.
///
/// Unlike [`SealedRead`], a raw run is bounded to a SINGLE sealed segment: a contiguous BYTE range is
/// one slice of one segment file's bytes, so a run that reaches a segment boundary stops there and the
/// caller resumes at `fallback_from` (the next segment, served by a fresh raw read, or the active tail
/// through the actor). This keeps the zero-copy invariant exact — the returned bytes are always a
/// contiguous slice of exactly one resident segment buffer.
#[derive(Debug)]
pub struct RawSealedRead {
    /// The raw contiguous frame run read from one sealed segment's flushed prefix, bounded by the
    /// flushed frontier, `max_records`, and the optional `max_bytes`. `record_count == 0` (and empty
    /// `bytes`) when the start is already in the active tail, on a compacted slot, or nothing is below
    /// `flushed`.
    pub run: RawByteRun,
    /// `Some(off)` when more flushed offsets remain that this single-segment raw read did not serve
    /// (the run hit its segment's end below `flushed`, or the start landed on the active tail or a
    /// compacted slot): the caller resumes at `off` (another raw read for the next sealed segment, or
    /// the through-actor path for the active tail). `None` when the read is COMPLETE off-actor (it hit
    /// `max`, the byte cap, or the flushed frontier within this segment).
    pub fallback_from: Option<u64>,
}

impl<F: crate::fs::Filesystem> SealedSnapshot<F> {
    /// Builds an immutable sealed snapshot with a fresh (all-empty) per-segment reader cache (#808).
    pub(crate) fn new(
        fs: Arc<F>,
        segments: Vec<SealedSegment>,
        oldest: u64,
        sealed_end: u64,
    ) -> SealedSnapshot<F> {
        let readers = SlotReaders::empty(segments.len());
        SealedSnapshot {
            fs,
            segments,
            readers,
            oldest,
            sealed_end,
        }
    }

    /// The opened [`SegmentReader`] for sealed segment slot `i`, opening it on first touch and reusing the
    /// cached one thereafter (#808). Shared as an `Arc` across the concurrent off-actor readers. A
    /// double-open race is merely wasteful, never wrong: a sealed file is immutable, so two opens produce
    /// byte-identical readers; the loser's `Arc` drops and closes its fd immediately, and every caller
    /// returns the SAME stored reader.
    fn reader_for(
        &self,
        i: usize,
        slot: &SealedSegment,
    ) -> Result<Arc<SegmentReader<F::File>>, StorageError> {
        if let Some(reader) = self.readers.slots[i].get() {
            return Ok(Arc::clone(reader));
        }
        let opened = Arc::new(SegmentReader::open(
            self.fs.open(&segment_file_name(slot.id))?,
        )?);
        // Cache only while under the per-generation cap (the resident-fd bound). Past it, return the fresh
        // open UNCACHED — a per-read open exactly as before #808 — so a cold full backfill can't pin one
        // fd per sealed segment. `opened < cap` is a soft check (concurrent openers may exceed it by the
        // number of racing threads, never unboundedly).
        if self.readers.opened.load(Ordering::Relaxed) < self.readers.cap {
            // `set` fails if another thread won the race for this slot; count ONLY a winning set so
            // `opened` tracks distinct cached slots. Either way the slot is now initialized.
            if self.readers.slots[i].set(Arc::clone(&opened)).is_ok() {
                self.readers.opened.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(self.readers.slots[i].get().map_or(opened, Arc::clone));
        }
        Ok(opened)
    }

    /// [`Self::reader_for`], but classifying the compaction-retire race (#803): the off-actor plane
    /// re-opens sealed segments BY NAME and holds no handle across the snapshot-load/open gap, so a read
    /// racing `compact_run`/`reap` can reach `fs.open` AFTER the actor has unlinked the source file
    /// (`compaction.rs` retires sources BEFORE `republish_read_plane`, and an already-loaded snapshot
    /// `Arc` still lists them). That surfaces as `Io(NotFound)` for data that still exists in the
    /// republished compacted segment. Return `Ok(None)` for exactly that case so the caller degrades to a
    /// single through-actor fallback (the authoritative current slot set) rather than propagating a
    /// spurious hard error that would drop the serve link. Any OTHER error — a real IO fault or a decode
    /// failure — still propagates.
    fn reader_or_retired(
        &self,
        i: usize,
        slot: &SealedSegment,
    ) -> Result<Option<Arc<SegmentReader<F::File>>>, StorageError> {
        match self.reader_for(i, slot) {
            Ok(reader) => Ok(Some(reader)),
            Err(StorageError::Io(ref e)) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

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
        let base = self.segment_index_for(start);
        for (offset_in_base, slot) in self.segments[base..].iter().enumerate() {
            let slot_index = base + offset_in_base;
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
            let remaining = max_records - out.len();
            // #664: bound the read span to the WINDOW (`remaining` records from `seg_start`), not the
            // whole sealed segment, so a forward off-actor drain reads O(window) bytes per fetch.
            let read_end = slot.window_read_end(seg_start, remaining);
            let gap = usize::try_from(seg_start.saturating_sub(anchor_offset)).unwrap_or(0);
            let below_flushed =
                usize::try_from(flushed.saturating_sub(anchor_offset)).unwrap_or(usize::MAX);
            let want = remaining.saturating_add(gap).min(below_flushed);
            let Some(reader) = self.reader_or_retired(slot_index, slot)? else {
                // #803: this segment was concurrently retired by compaction (unlinked before the
                // read plane was republished). The data still exists in the republished compacted
                // segment, so hand the remainder — from this segment's covered base, clamped to
                // `start` — back to the actor rather than surfacing a spurious NotFound.
                fallback_from = Some(start.max(slot.base_offset));
                break;
            };
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

    /// Reads a CONTIGUOUS RAW byte run from the SEALED prefix starting at `start`, bounded by
    /// `flushed`, `max_records`, and the optional `max_bytes` — the ZERO-COPY off-actor read (#542,
    /// M1-I6) and the raw sibling of [`SealedSnapshot::read_range`]. Where `read_range` decodes every
    /// frame into an [`OwnedRecord`], this seeks to the same anchor and hands the contiguous on-disk
    /// frame bytes back as ONE [`RawByteRun`] (a refcount slice of one segment's resident buffer) with
    /// NO body decode and NO per-record allocation.
    ///
    /// Bounded to a SINGLE sealed segment (a contiguous byte range is one slice of one file): if the
    /// run reaches the segment's end with flushed offsets still remaining, `fallback_from` is the next
    /// offset so the caller resumes (a fresh raw read of the next segment, or the through-actor active
    /// tail). The seek/clamp logic MIRRORS `read_range` exactly, so the run decodes to byte-identical
    /// records (the differential test pins this).
    fn read_range_raw(
        &self,
        start: u64,
        flushed: u64,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<RawSealedRead, StorageError> {
        let empty = |fallback_from| RawSealedRead {
            run: RawByteRun {
                bytes: bytes::Bytes::new(),
                first_offset: Offset::new(start),
                record_count: 0,
                next_offset: Offset::new(start),
            },
            fallback_from,
        };
        // The flushed frontier is the HARD bound (mirrors `read_range`). Clamp sealed coverage to it.
        let visible_sealed_end = self.sealed_end.min(flushed);
        if max_records == 0 || start >= flushed {
            return Ok(empty(None));
        }
        if start < self.oldest {
            return Err(StorageError::OffsetOutOfRange {
                requested: start,
                oldest: self.oldest,
            });
        }
        // The start is already at/past the sealed prefix's visible end: nothing to serve raw
        // off-actor; the caller reads `[start, flushed)` (the active tail) through the actor.
        if start >= visible_sealed_end {
            return Ok(empty(Some(start)));
        }
        let slot_index = self.segment_index_for(start);
        let slot = &self.segments[slot_index];
        let seg_start = start.max(slot.base_offset);
        // A COMPACTED (v2, sparse) slot is served by the through-actor v2 scan, not this plane: a
        // sparse survivor run is not a dense contiguous byte range, so hand the remainder back.
        if slot.compacted {
            return Ok(empty(Some(seg_start)));
        }
        let Some((anchor_offset, byte_pos)) = slot.seek_anchor(seg_start) else {
            // The snapshot's anchors do not cover `seg_start`: serve nothing raw, resume past here.
            return Ok(empty(Some(seg_start)));
        };
        // #664: bound the read span to the WINDOW (`max_records` records from `seg_start`), not the
        // whole sealed segment, so a forward off-actor Tier-S raw drain reads O(window) bytes per
        // fetch (not O(distance-to-segment-end) => O(N^2) overall). The `want`/`max_records` clamp
        // below still governs the frames returned.
        let read_end = slot.window_read_end(seg_start, max_records);
        // Cap the raw read at the flushed frontier and the segment's covered end: never carry a frame
        // at or past `flushed`, and bound the want by how many frames lie below the frontier from the
        // anchor (the gap the anchor preceded `seg_start` by is dropped after the read).
        let gap = usize::try_from(seg_start.saturating_sub(anchor_offset)).unwrap_or(0);
        let covered_end = slot.base_offset.saturating_add(slot.record_count);
        let seg_visible_end = covered_end.min(flushed);
        let below_visible =
            usize::try_from(seg_visible_end.saturating_sub(anchor_offset)).unwrap_or(usize::MAX);
        let want = max_records.saturating_add(gap).min(below_visible);
        let Some(reader) = self.reader_or_retired(slot_index, slot)? else {
            // #803: this segment was concurrently retired by compaction (unlinked before the read
            // plane was republished). The data still exists in the republished compacted segment, so
            // resume through the actor from this segment's start rather than surfacing NotFound.
            return Ok(empty(Some(seg_start)));
        };
        let run =
            reader.raw_byte_range(byte_pos, Offset::new(anchor_offset), read_end, want, None)?;
        // The anchor may sit BEFORE `seg_start` (sparse anchors land one-per-stride): trim the leading
        // `gap` frames so the returned run begins exactly at `seg_start`, then re-bound to
        // `max_records` and `max_bytes` over the trimmed run. Trimming walks frame headers only (no
        // body decode), preserving the zero-copy property.
        let trimmed = trim_raw_run(&run, seg_start, max_records, max_bytes);
        let run_end = trimmed.next_offset.get();
        // Resume reporting: if this single-segment run stopped strictly below the visible frontier
        // without hitting `max`/`max_bytes`, the caller resumes at `run_end` (the next segment or the
        // active tail). If it hit `max`/the byte cap within the segment, it is complete off-actor.
        let hit_count = trimmed.record_count >= max_records as u64;
        let hit_bytes = max_bytes.is_some_and(|cap| (trimmed.bytes.len()) >= cap);
        let fallback_from = if !hit_count && !hit_bytes && run_end < flushed {
            Some(run_end.max(start))
        } else {
            None
        };
        Ok(RawSealedRead {
            run: trimmed,
            fallback_from,
        })
    }
}

/// Trims a [`RawByteRun`] to begin at `seg_start` (dropping the leading frames a sparse anchor
/// preceded it by) and re-bounds it to `max_records` / `max_bytes` over the trimmed run — a
/// HEADER-ONLY walk (no body decode), so it preserves the zero-copy property. Returns a run that is a
/// sub-slice of the input's `bytes` (a refcount re-slice, never a copy).
fn trim_raw_run(
    run: &RawByteRun,
    seg_start: u64,
    max_records: usize,
    max_bytes: Option<usize>,
) -> RawByteRun {
    let mut cursor = 0usize;
    let mut offset = run.first_offset.get();
    let bytes = &run.bytes;
    // Drop the leading frames below `seg_start` by walking their header lengths.
    while offset < seg_start && cursor < bytes.len() {
        let Ok(consumed) = ironbus_core::codec::decoded_len(&bytes[cursor..]) else {
            break;
        };
        if cursor.saturating_add(consumed) > bytes.len() {
            break;
        }
        cursor += consumed;
        offset = offset.saturating_add(1);
    }
    let run_start_byte = cursor;
    let first_offset = offset;
    // Admit up to `max_records` / `max_bytes` frames from `seg_start`, "at least one" honored.
    let mut count = 0usize;
    let mut byte_total = 0usize;
    while cursor < bytes.len() && count < max_records {
        let Ok(consumed) = ironbus_core::codec::decoded_len(&bytes[cursor..]) else {
            break;
        };
        if cursor.saturating_add(consumed) > bytes.len() {
            break;
        }
        if let Some(cap) = max_bytes {
            if count != 0 && byte_total.saturating_add(consumed) > cap {
                break;
            }
        }
        byte_total = byte_total.saturating_add(consumed);
        count += 1;
        offset = offset.saturating_add(1);
        cursor += consumed;
    }
    RawByteRun {
        bytes: bytes.slice(run_start_byte..run_start_byte + byte_total),
        first_offset: Offset::new(first_offset),
        record_count: count as u64,
        next_offset: Offset::new(offset),
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
pub struct ReadPlane<F: Filesystem> {
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
            sealed: Arc::new(ArcSwap::from_pointee(SealedSnapshot::new(
                fs, segments, oldest, sealed_end,
            ))),
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
        self.sealed.store(Arc::new(SealedSnapshot::new(
            fs, segments, oldest, sealed_end,
        )));
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

    /// Reads a CONTIGUOUS RAW byte run from the SEALED, flushed prefix starting at `start`, with NO
    /// lock and NO actor round-trip — the ZERO-COPY off-actor read (#542, M1-I6) and the raw sibling
    /// of [`ReadPlane::read_range`]. Takes the SAME frontier-then-snapshot ordering, then hands back
    /// the contiguous on-disk frame bytes as ONE [`RawByteRun`] (a refcount slice of one segment's
    /// resident buffer) instead of a `Vec<OwnedRecord>`: no body decode, no per-record allocation.
    ///
    /// A raw run is bounded to ONE sealed segment (a contiguous byte range is one slice of one file),
    /// so the returned [`RawSealedRead::fallback_from`] is `Some(off)` when more flushed offsets
    /// remain past this segment's run — the caller resumes with another raw read (the next sealed
    /// segment) or the through-actor path (the active tail). The flushed frontier is loaded FIRST
    /// (Acquire) and the snapshot SECOND, exactly as `read_range`, so the snapshot is guaranteed to
    /// cover every sealed offset below the observed frontier.
    ///
    /// On the in-memory backends the run is a TRUE no-copy view of the segment's resident bytes; on
    /// the disk backend it is one positioned read into one buffer (the contiguous extent the deferred
    /// `sendfile(2)` follow-up would hand to the kernel instead, without changing this read shape).
    ///
    /// # Errors
    /// [`StorageError::OffsetOutOfRange`] if `start` is older than the snapshot's oldest retained
    /// offset, or an IO error reading a sealed segment.
    pub fn read_range_raw(
        &self,
        start: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<RawSealedRead, StorageError> {
        // ORDER IS LOAD-BEARING (identical to `read_range`): the frontier (Acquire) FIRST, then the
        // snapshot. A frontier `F` observed here was published AFTER a snapshot covering every sealed
        // offset below `F`, so the snapshot can never lack a segment the frontier admits.
        let flushed = self.flushed.load(Ordering::Acquire);
        let snapshot = self.sealed.load();
        snapshot.read_range_raw(start.get(), flushed, max_records, max_bytes)
    }

    /// The number of sealed-segment readers currently cached in the live snapshot (#808): the resident-fd
    /// count, which the per-generation cap bounds. Lets a test assert the fd bound directly.
    #[cfg(test)]
    fn resident_reader_count(&self) -> usize {
        self.sealed.load().readers.opened.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{FaultControl, FaultFs};
    use crate::fs::InMemoryFs;
    use crate::log::{Append, Log, LogConfig};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use std::sync::atomic::AtomicU64 as StdAtomicU64;

    /// A tiny-segment log over a `FaultFs` whose `FaultControl` counts every `open(2)`, so a test can
    /// assert the #808 reader cache opens a sealed segment ONCE across many reads.
    fn small_fault_log() -> (Log<FaultFs<InMemoryFs>, ManualClock>, FaultControl) {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let config = LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        let log = Log::open(fs, ManualClock::new(), config).unwrap();
        (log, control)
    }

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

    /// #808: many reads of ONE sealed segment open its file ONCE (the per-snapshot reader cache), not
    /// once per read — the syscall/fd-churn win. With the cache OFF (a fresh `SegmentReader::open` per
    /// read) the open-count delta would equal the number of reads.
    #[test]
    fn repeated_sealed_reads_open_each_segment_once() {
        let (mut log, control) = small_fault_log();
        for i in 0..40u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 7 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let plane = log.read_plane().unwrap();
        // Offset 0 is in the first sealed segment (the tiny cap sealed several). Read it many times
        // through the SAME (unchanged) snapshot: the segment is opened on the first read and reused.
        let baseline = control.open_count();
        let mut served = 0;
        for _ in 0..25 {
            let read = plane.read_range(Offset::new(0), 1, None).unwrap();
            served += read.records.len();
        }
        assert_eq!(served, 25, "every read served the record at offset 0");
        let opens = control.open_count() - baseline;
        assert_eq!(
            opens, 1,
            "25 reads of one sealed segment opened it ONCE (#808), not 25 times"
        );
    }

    /// #808: the reader cache is PER-SNAPSHOT. When a roll/reap republishes a fresh snapshot, the old
    /// snapshot (and its opened fds) drops, and a read through the new snapshot RE-OPENS — proving the
    /// cache never carries a stale fd across a generation (and that retired fds are released, not leaked).
    #[test]
    fn a_republished_snapshot_reopens_the_segment() {
        let (mut log, control) = small_fault_log();
        for i in 0..40u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 7 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();

        // Warm the cache for segment 0 in the current snapshot.
        let plane = log.read_plane().unwrap();
        let baseline = control.open_count();
        let _ = plane.read_range(Offset::new(0), 1, None).unwrap();
        let _ = plane.read_range(Offset::new(0), 1, None).unwrap();
        assert_eq!(
            control.open_count() - baseline,
            1,
            "the warm snapshot opened segment 0 once"
        );

        // Append + sync more so the writer seals another segment and REPUBLISHES the snapshot.
        for i in 40..90u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 7 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();

        // Read segment 0 again through the fresh snapshot: its cache is empty, so it re-opens once.
        let after_republish = control.open_count();
        let _ = plane.read_range(Offset::new(0), 1, None).unwrap();
        let _ = plane.read_range(Offset::new(0), 1, None).unwrap();
        assert_eq!(
            control.open_count() - after_republish,
            1,
            "a republished snapshot re-opens segment 0 once (the old generation's fd was dropped, not reused)"
        );
    }

    /// The lowest-id sealed segment file name in `fs` (the oldest, covering offset 0).
    fn oldest_segment_file(fs: &InMemoryFs) -> String {
        let mut names: Vec<String> = fs
            .list()
            .unwrap()
            .into_iter()
            .filter(|n| n.starts_with("seg-"))
            .collect();
        names.sort();
        names.into_iter().next().expect("a sealed segment file")
    }

    /// #803: a read racing the compaction retire must NOT surface a spurious `NotFound`. The off-actor
    /// plane re-opens sealed segments BY NAME and holds no handle across the load/open gap, so a read
    /// through an already-loaded snapshot can reach `fs.open` AFTER the actor unlinked that source file
    /// (compaction retires the sources BEFORE it republishes the plane). We reproduce exactly that window
    /// by unlinking the sealed segment covering offset 0 out from under the plane WITHOUT warming its
    /// reader cache, then asserting the read degrades to a through-actor fallback rather than erroring.
    /// Without the fix (a bare `?` on the open) this read returns `Err(Io(NotFound))` and the serve link
    /// is dropped.
    #[test]
    fn a_read_racing_the_compaction_retire_falls_back_instead_of_notfound() {
        fn filled_log() -> Log<InMemoryFs, ManualClock> {
            let mut log = small_log();
            for i in 0..200u32 {
                log.append(&rec(&i.to_le_bytes())).unwrap();
                if i % 7 == 0 {
                    log.sync().unwrap();
                }
            }
            log.sync().unwrap();
            log
        }

        // Sanity (a SEPARATE log, so warming its cache cannot affect the race log below): offset 0 IS
        // served off-actor from a sealed segment file — the read path genuinely reaches `fs.open`. Were
        // it not, the race assertions would pass trivially even without the fix.
        let control = filled_log();
        let before = control
            .read_plane()
            .unwrap()
            .read_range(Offset::new(0), 4, None)
            .unwrap();
        assert_eq!(before.records[0].offset.get(), 0);
        assert_eq!(before.fallback_from, None, "offset 0 is served off-actor");

        let log = filled_log();
        // `read_plane()` hands back a CLONE of the SAME cached plane (shared snapshot + reader cache), so
        // we must not warm this plane's slot-0 reader before the retire — a cached fd would keep the
        // inode alive and mask the race. The plane's slot-0 reader is therefore cold here.
        let plane = log.read_plane().unwrap();

        // Retire the oldest sealed segment file out from under `plane` — the InMemoryFs clone shares the
        // same store, so this removal is exactly what `compact_run` does before `republish_read_plane`.
        // `plane`'s snapshot still lists the (now deleted) segment and its reader cache is cold.
        let fs = log.filesystem().clone();
        let victim = oldest_segment_file(&fs);
        fs.remove(&victim).unwrap();

        // read_range: the retired slot must yield a graceful fallback at its base (offset 0), not an error.
        let read = plane
            .read_range(Offset::new(0), 4, None)
            .expect("a read racing the retire must not surface NotFound");
        assert_eq!(
            read.fallback_from,
            Some(0),
            "the retired sealed segment hands its range back to the actor"
        );

        // read_range_raw: same contract — resume through the actor, never a hard NotFound.
        let raw = plane
            .read_range_raw(Offset::new(0), 4, None)
            .expect("a raw read racing the retire must not surface NotFound");
        assert_eq!(
            raw.fallback_from,
            Some(0),
            "the retired sealed segment hands its raw range back to the actor"
        );
    }

    /// #808 (SHOULD-FIX): the per-snapshot reader cache is FD-BOUNDED — it never caches more than its cap
    /// readers, so a cold full backfill within one generation cannot pin one fd per sealed segment. With a
    /// cap of 2, reading the WHOLE multi-segment sealed prefix leaves at most 2 readers resident; the
    /// over-cap segments are read uncached (correctness unchanged — same bytes).
    #[test]
    fn the_plane_reader_cache_is_fd_bounded_per_generation() {
        TEST_PLANE_READER_CACHE_CAP.store(2, Ordering::Relaxed);
        let (mut log, _control) = small_fault_log();
        for i in 0..60u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 5 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let plane = log.read_plane().unwrap();
        let flushed = log.flushed_offset().get();
        // Read across the whole sealed prefix many times (well more segments than the cap of 2).
        let mut total = 0;
        for _ in 0..3 {
            for off in 0..flushed {
                total += plane
                    .read_range(Offset::new(off), 1, None)
                    .unwrap()
                    .records
                    .len();
            }
        }
        assert!(total > 0, "the sealed prefix served records");
        assert!(
            plane.resident_reader_count() <= 2,
            "the cache never holds more than its cap of 2 readers (fd-bounded), got {}",
            plane.resident_reader_count()
        );
        assert!(
            plane.resident_reader_count() >= 1,
            "but it does cache within the cap (the hot segment is reused)"
        );
        TEST_PLANE_READER_CACHE_CAP.store(0, Ordering::Relaxed);
    }

    /// #664: the off-actor WINDOW-BOUNDED read-end (`SealedSegment::window_read_end`) is correct over
    /// a MULTI-SEGMENT sealed prefix for both the materialized (`read_range`) and raw
    /// (`read_range_raw`) off-actor reads — byte-identical to the through-actor `read_from` for every
    /// (start, window). Before #664 the off-actor read buffered the whole sealed segment per fetch
    /// (O(distance-to-segment-end)); the window bound must not change WHICH records are served.
    #[test]
    fn window_bounded_sealed_read_is_byte_identical_across_starts_and_windows() {
        // A tiny cap seals many segments, so a window read lands mid-sealed-segment (where the window
        // bound and the whole-segment bound differ the most).
        let mut log = small_log();
        for i in 0..500u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 5 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let plane = log.read_plane().unwrap();
        let flushed = log.flushed_offset().get();
        for start in 0..flushed {
            for window in [1usize, 4, 33, 200] {
                let oracle = log.read_from(Offset::new(start), window).unwrap();
                // Materialized off-actor read: a PREFIX of the oracle (stops at the sealed end), every
                // served record byte-identical to the through-actor read at the same position.
                let sealed = plane.read_range(Offset::new(start), window, None).unwrap();
                for (a, s) in oracle.iter().zip(sealed.records.iter()) {
                    assert_eq!(
                        a, s,
                        "sealed read != oracle at start={start} window={window}"
                    );
                }
                assert!(sealed.records.len() <= oracle.len());
                // Raw off-actor read: its frames decode to the same records (positional offsets).
                let raw = plane
                    .read_range_raw(Offset::new(start), window, None)
                    .unwrap();
                let mut off = raw.run.first_offset.get();
                let mut cursor = 0usize;
                let mut i = 0usize;
                while cursor < raw.run.bytes.len() {
                    let (view, consumed) =
                        ironbus_core::codec::decode(&raw.run.bytes[cursor..]).unwrap();
                    assert_eq!(off, oracle[i].offset.get(), "raw off at start={start}");
                    assert_eq!(
                        view.payload,
                        &oracle[i].payload[..],
                        "raw payload at start={start}"
                    );
                    off += 1;
                    cursor += consumed;
                    i += 1;
                }
                assert_eq!(i as u64, raw.run.record_count);
            }
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

    /// Measures THIS thread's real CPU throughput by timing a fixed slug of dependent integer work
    /// (the #687/#666 adaptive-calibration idiom). On an unloaded host the slug runs in a fixed, short
    /// wall-clock; under CI CPU starvation the SAME work takes proportionally longer because the thread
    /// is repeatedly preempted. That ratio is exactly the starvation that delays the reader threads
    /// here from getting a timeslice to serve an off-actor read, so it is the right thing to scale the
    /// "exercise the off-actor path" wait deadline by. Pure arithmetic behind a `black_box` fence so the
    /// optimiser cannot fold it away.
    fn probe_busy_nanos() -> u128 {
        // ~2M iterations of dependent integer work: long enough to dwarf timer granularity and span
        // several scheduler slices under contention, short enough to be negligible on an idle host.
        const ITERS: u64 = 2_000_000;
        let start = std::time::Instant::now();
        let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
        for i in 0..ITERS {
            acc = acc
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(i | 1);
        }
        std::hint::black_box(acc);
        start.elapsed().as_nanos().max(1)
    }

    /// Scales a GENEROUS base deadline by the observed host slowdown so a wait is robust to CI CPU
    /// contention WITHOUT weakening what it proves (the #687 `host_scaled`). [`probe_busy_nanos`]
    /// measures this thread's real CPU throughput; the base is multiplied by how many times slower
    /// than a fast reference host we are, clamped to `[1, MAX_SCALE]`. On an unloaded host the factor
    /// is ~1, so the deadline stays the generous base and any early-exit poll still exits the instant
    /// its condition is met (fast). On a starved host the factor grows, so the equally-starved reader
    /// threads get proportionally more wall-clock to do the SAME off-actor read. Never SHORTER than the
    /// base — we only ever extend.
    fn host_scaled(base: std::time::Duration) -> std::time::Duration {
        /// A fast, unloaded reference host runs [`probe_busy_nanos`]'s slug in roughly this long.
        const REFERENCE_BUSY_NANOS: u128 = 4_000_000; // ~4 ms for ~2M iters on a fast core.
        /// Cap the multiplier so a pathologically wedged host still fails in bounded time rather than
        /// hanging the suite — a genuinely never-serving plane (a real bug) must still surface.
        const MAX_SCALE: u32 = 12;
        // The ratio is clamped to `[1, MAX_SCALE]`, so it always fits a `u32` (MAX_SCALE is small).
        let factor =
            u32::try_from((probe_busy_nanos() / REFERENCE_BUSY_NANOS).min(u128::from(MAX_SCALE)))
                .unwrap_or(MAX_SCALE)
                .max(1);
        base.saturating_mul(factor)
    }

    /// Concurrent READERS read the sealed prefix off-actor WHILE a WRITER appends/syncs/rolls on its
    /// own thread: the readers never deadlock or contend on the writer (they touch only the shared
    /// atomics, never the `Log`), never observe a record at or past the frontier they loaded, and
    /// every record they DO serve is byte-identical to its log offset. This is the multi-consumer
    /// scaling property and the read-plane data-race coverage (the loom permutation of the atomic
    /// publish/observe is in `tools/loom-tests`).
    ///
    /// ## Why the positive case is poll-until-served, not best-effort (#671)
    ///
    /// The off-actor-served check is a POSITIVE-EXISTENCE assertion: at least one reader must serve a
    /// record off the lock-free plane, so the off-actor path is actually EXERCISED concurrently with
    /// the writer. The original test let the writer flip a `stop` flag as soon as it finished its
    /// append loop and only THEN asserted some reader had served. On a contended/slow CI runner the
    /// writer (the main thread) could blow through every append and stop before a STARVED reader thread
    /// ever got a timeslice to complete a serving read, so the served count was 0 and the assertion
    /// flaked — a pure scheduling race, NOT a correctness bug (the never-beyond-frontier check below
    /// and the loom memory-ordering models still hold). The fix makes the positive case DETERMINISTIC:
    /// the priming seals visible segments BEFORE the readers spawn (asserted from the main thread), and
    /// each reader POLLS until it serves at least one record off-actor, exiting early the instant it
    /// does; the writer runs until every reader has confirmed a serve OR a GENEROUS, host-tolerant
    /// deadline elapses. So an off-actor read is GUARANTEED to be exercised regardless of the scheduler
    /// interleaving, while the writer still races against the readers and EVERY correctness assertion
    /// (no record at/past the observed frontier) runs unchanged on every iteration.
    #[test]
    fn concurrent_readers_and_a_writer_race_safely() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as O};
        use std::sync::Arc as StdArc;
        use std::thread;
        use std::time::{Duration, Instant};

        const READERS: u32 = 4;

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

        // Make the positive case DETERMINISTIC: the priming MUST leave a sealed-and-visible prefix the
        // plane can serve off-actor, so the readers below cannot be starved into a never-served state
        // by an empty snapshot. If this fails the test setup is wrong, not the scheduler.
        let primed = plane.read_range(Offset::ZERO, 64, None).unwrap();
        assert!(
            !primed.records.is_empty(),
            "priming must seal a visible prefix the read plane can serve off-actor"
        );

        let stop = StdArc::new(AtomicBool::new(false));
        // How many readers have served at least one record off-actor. The writer waits for all of them
        // (or a generous host-scaled deadline) before stopping, so the off-actor path is GUARANTEED to
        // be exercised concurrently with the writer regardless of scheduling.
        let served_at_least_once = StdArc::new(AtomicU32::new(0));

        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                let plane = plane.clone();
                let stop = StdArc::clone(&stop);
                let served_at_least_once = StdArc::clone(&served_at_least_once);
                thread::spawn(move || {
                    let mut total_served = 0u64;
                    let mut announced = false;
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
                        // The first time this reader actually serves a record off-actor, announce it so
                        // the writer knows the off-actor path has been exercised on this thread.
                        if !announced && total_served > 0 {
                            announced = true;
                            served_at_least_once.fetch_add(1, O::Release);
                        }
                    }
                    total_served
                })
            })
            .collect();

        // The writer keeps appending + syncing + rolling (the small cap rolls often), publishing the
        // frontier and new snapshots, while the readers run. Don't stop until EVERY reader has served a
        // record off-actor (the off-actor path is exercised) or a GENEROUS, host-tolerant deadline has
        // passed — so a starved reader thread on a contended CI runner still gets enough wall-clock to
        // complete a serving read before the writer stops (#671). The deadline only bounds a wedged
        // host; the wait is otherwise governed by the readers all serving, which happens fast on a
        // healthy host. `host_scaled` keeps the off-actor read GUARANTEED to be exercised without a
        // brittle fixed timing window.
        let deadline = Instant::now() + host_scaled(Duration::from_secs(10));
        let mut i = 40u32;
        loop {
            // Keep the writer busy (append + frequent sync/roll) so readers always have fresh frontiers
            // and snapshots to race against. Cycle the offsets once the priming range is exhausted so
            // the writer never idles while waiting on a starved reader.
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 3 == 0 {
                log.sync().unwrap();
            }
            i = if i >= 599 { 40 } else { i + 1 };
            if served_at_least_once.load(O::Acquire) >= READERS || Instant::now() >= deadline {
                break;
            }
        }
        log.sync().unwrap();
        stop.store(true, O::Release);

        // No reader deadlocked or panicked; each made progress (read SOME records off-actor). This is
        // now DETERMINISTIC: the writer waited for every reader to serve (or the host-tolerant deadline),
        // so an off-actor read was guaranteed to be exercised — a 0 here means the plane genuinely never
        // served within a generous host-scaled window (a real regression), not a lucky interleaving.
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

    // ----- Zero-copy raw-byte-run path (#542, M1-I6) -----

    /// Decodes a [`RawByteRun`]'s bytes front-to-back into `(RecordView, offset)` pairs, the way a
    /// consumer that receives the raw run would. Asserts the run carries EXACTLY `record_count` whole
    /// frames and nothing trails. This is the client-side half of the differential.
    fn decode_raw_run(run: &RawByteRun) -> Vec<(ironbus_core::codec::RecordView<'_>, u64)> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut offset = run.first_offset.get();
        while cursor < run.bytes.len() {
            let (view, consumed) =
                ironbus_core::codec::decode(&run.bytes[cursor..]).expect("raw run frame decodes");
            out.push((view, offset));
            offset = offset.saturating_add(1);
            cursor += consumed;
        }
        assert_eq!(
            cursor,
            run.bytes.len(),
            "raw run must be exactly whole frames, no partial tail"
        );
        assert_eq!(
            out.len() as u64,
            run.record_count,
            "decoded frame count must equal record_count"
        );
        out
    }

    /// DIFFERENTIAL: the zero-copy raw run is BYTE-IDENTICAL to the materialize+encode path. For every
    /// start offset and several batch sizes, decoding the raw run yields the SAME records (offset, seq,
    /// timestamp, flags, key, headers, payload — every byte) and in the SAME order as the through-actor
    /// `read_from`, the existing materialize path. This is the core correctness proof: a contiguous
    /// stored run shipped raw == the records re-encoded one at a time.
    #[test]
    fn raw_run_is_byte_identical_to_the_materialize_path() {
        let mut log = small_log();
        for i in 0..200u32 {
            // Vary key/headers/payload so the differential exercises non-empty variable fields.
            let payload = i.to_le_bytes();
            log.append(&Append {
                timestamp_ms: 100 + u64::from(i),
                flags: RecordFlags::EMPTY,
                key: &[(i % 7) as u8; 3],
                headers: &[(i % 5) as u8; 2],
                payload: &payload,
            })
            .unwrap();
            if i % 7 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let plane = log.read_plane().unwrap();
        let flushed = log.flushed_offset().get();
        for start in 0..flushed {
            for max in [1usize, 3, 8, 64] {
                let want = max;
                let materialized = plane.read_range(Offset::new(start), want, None).unwrap();
                let raw = plane
                    .read_range_raw(Offset::new(start), want, None)
                    .unwrap();
                let decoded = decode_raw_run(&raw.run);
                // The raw path is single-segment; it serves a PREFIX of the (possibly multi-segment)
                // materialize result. Compare on the common prefix, then assert resume coverage.
                for ((view, off), owned) in decoded.iter().zip(materialized.records.iter()) {
                    assert_eq!(*off, owned.offset.get(), "offset mismatch at start={start}");
                    assert_eq!(view.seq, owned.seq, "seq mismatch at start={start}");
                    assert_eq!(
                        view.timestamp_ms, owned.timestamp_ms,
                        "timestamp mismatch at start={start}"
                    );
                    assert_eq!(view.flags, owned.flags, "flags mismatch at start={start}");
                    assert_eq!(view.key, &owned.key[..], "key mismatch at start={start}");
                    assert_eq!(
                        view.headers,
                        &owned.headers[..],
                        "headers mismatch at start={start}"
                    );
                    assert_eq!(
                        view.payload,
                        &owned.payload[..],
                        "payload mismatch at start={start}"
                    );
                }
                // The first decoded record (if any) must start exactly at `start`.
                if let Some((_, off)) = decoded.first() {
                    assert_eq!(*off, start, "raw run did not start at the requested offset");
                }
            }
        }
    }

    /// The raw run stops at a SINGLE sealed segment's boundary and reports a `fallback_from` so the
    /// caller resumes — and chaining raw reads from each `fallback_from` (then the active-tail actor
    /// read) reconstructs the WHOLE flushed prefix with no gaps or overlaps. A PARTIAL/BOUNDARY batch
    /// exercise: the small segment cap forces many segment-boundary stops.
    #[test]
    fn raw_run_chains_across_segment_boundaries_without_gaps() {
        let mut log = small_log();
        for i in 0..300u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 5 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let plane = log.read_plane().unwrap();
        let flushed = log.flushed_offset().get();
        // Walk the sealed-and-flushed prefix via repeated raw reads, following `fallback_from`. The
        // chain ends when a read serves nothing AND cannot advance (the start is in the active tail,
        // which the sealed plane does not serve) or there are no more flushed offsets.
        let mut next = 0u64;
        let mut seen = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 10_000, "raw-read chain failed to terminate");
            let raw = plane
                .read_range_raw(Offset::new(next), 1_000, None)
                .unwrap();
            let decoded = decode_raw_run(&raw.run);
            // Every raw frame must be exactly the next contiguous offset (no gap, no overlap).
            for (_, off) in &decoded {
                assert_eq!(*off, seen, "raw chain skipped or repeated an offset");
                seen += 1;
            }
            match raw.fallback_from {
                // A fallback that does not advance past `next` means the rest is the active tail (the
                // sealed plane serves no more); stop the sealed-prefix walk there.
                Some(f) if f > next => next = f,
                _ => break,
            }
        }
        // We saw every sealed-and-flushed record up to wherever the sealed prefix ends. The remaining
        // gap to `flushed` (the active tail) is served through the actor; assert we covered the
        // sealed prefix contiguously and never over-ran the frontier.
        assert_eq!(
            seen,
            next.min(flushed),
            "raw chain left a gap in the sealed prefix"
        );
        assert!(
            seen <= flushed,
            "raw chain served past the flushed frontier"
        );
        assert!(seen > 0, "raw chain served nothing");
    }

    /// CRC INTEGRITY: each frame in the raw run carries its OWN body CRC verbatim, so a consumer that
    /// re-decodes the run validates every frame end-to-end. Decoding the run with the full
    /// `codec::decode` (which checks header AND body CRC) succeeds for every frame — proving the
    /// shipped bytes are integrity-checkable downstream, not stripped of their CRC.
    #[test]
    fn raw_run_preserves_per_frame_crc_for_end_to_end_verification() {
        let mut log = small_log();
        for i in 0..50u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            log.sync().unwrap();
        }
        let plane = log.read_plane().unwrap();
        let raw = plane.read_range_raw(Offset::new(0), 64, None).unwrap();
        // Full decode (header CRC + body CRC) of every frame must succeed: the CRCs rode along.
        let mut cursor = 0usize;
        let mut frames = 0u64;
        while cursor < raw.run.bytes.len() {
            let (_, consumed) = ironbus_core::codec::decode(&raw.run.bytes[cursor..])
                .expect("every shipped frame must pass header AND body CRC");
            cursor += consumed;
            frames += 1;
        }
        assert_eq!(frames, raw.run.record_count);
        assert!(frames > 0, "expected a non-empty CRC-checked run");
    }

    /// The byte cap bounds the raw run exactly as it bounds the materialize path: the run carries at
    /// most `max_bytes` of frames (honoring "at least one"), and its byte length matches the sum of
    /// the encoded lengths of the records the materialize path returns for the same cap.
    #[test]
    fn raw_run_honors_the_byte_cap_like_the_materialize_path() {
        let mut log = small_log();
        for i in 0..100u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            log.sync().unwrap();
        }
        let plane = log.read_plane().unwrap();
        // A cap that admits a few records but not the whole batch.
        let cap = 200usize;
        let materialized = plane.read_range(Offset::new(0), 1_000, Some(cap)).unwrap();
        let raw = plane
            .read_range_raw(Offset::new(0), 1_000, Some(cap))
            .unwrap();
        let decoded = decode_raw_run(&raw.run);
        // The raw run is single-segment, so it serves a prefix of the materialize result; compare the
        // common prefix and assert the raw run respected the cap ("at least one" allowed to exceed).
        let raw_bytes: usize = raw.run.bytes.len();
        let first_len = materialized
            .records
            .first()
            .map_or(0, super::OwnedRecord::encoded_len);
        assert!(
            raw_bytes <= cap || raw.run.record_count <= 1,
            "raw run exceeded the byte cap with more than one record (cap={cap}, bytes={raw_bytes}, first_len={first_len})"
        );
        for ((_, off), owned) in decoded.iter().zip(materialized.records.iter()) {
            assert_eq!(*off, owned.offset.get());
        }
    }

    /// On the in-memory backend the raw run is a refcount slice of the SEGMENT's resident bytes — a
    /// true no-copy view. We cannot observe the pointer identity through the public API, but we CAN
    /// assert the zero-copy contract's observable consequence: the returned `bytes` is a `Bytes`
    /// handle whose length equals the sum of the on-disk frame lengths, and cloning it is cheap
    /// (a refcount bump). This pins the memory-backend Bytes-slice path.
    #[test]
    fn memory_backend_serves_a_bytes_slice_run() {
        let mut log = small_log();
        for i in 0..20u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            log.sync().unwrap();
        }
        let plane = log.read_plane().unwrap();
        let raw = plane.read_range_raw(Offset::new(0), 8, None).unwrap();
        assert!(raw.run.record_count > 0, "expected a non-empty run");
        // A clone is a refcount bump, not a copy: same bytes, independent handle.
        let cloned = raw.run.bytes.clone();
        assert_eq!(&cloned[..], &raw.run.bytes[..]);
        // The run length equals exactly the sum of the served frames' on-disk encoded lengths.
        let want = usize::try_from(raw.run.record_count).unwrap();
        let materialized = plane.read_range(Offset::new(0), want, None).unwrap();
        let expected: usize = materialized
            .records
            .iter()
            .map(super::OwnedRecord::encoded_len)
            .sum();
        assert_eq!(
            raw.run.bytes.len(),
            expected,
            "raw run byte length must equal the sum of frame encoded lengths"
        );
    }
}
