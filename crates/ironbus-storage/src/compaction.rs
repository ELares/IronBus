// SPDX-License-Identifier: MIT OR Apache-2.0
//! Optional, opt-in, key-based log compaction: the CLEANER (#337, #83, parent #13).
//!
//! Compaction keeps, for each key, AT LEAST the last value, plus a bounded retention of
//! tombstones (empty-payload deletes), and rewrites only the SURVIVORS into a fresh `version` = 2
//! COMPACTED segment. Every survivor keeps its ORIGINAL log offset and original per-segment
//! sequence verbatim, so the result is a SPARSE offset range: offsets are never renumbered or
//! reused, which is exactly what preserves invariant I5. This is the opposite of the reaper, which
//! deletes whole sealed segments without looking inside; the compactor looks inside, keeps a
//! per-key subset, and is expensive, so it is OFF by default and edge-hostile (see
//! [`docs/COMPACTION.md`](../../../docs/COMPACTION.md)).
//!
//! The clean is a write-new-then-retire-originals sequence whose SINGLE commit point is the
//! durable appearance of the new compacted segment file (the parent-directory `sync_dir`). The
//! originals stay authoritative until that instant; afterwards they are redundant and removed with
//! the same unlink-then-dir-fsync discipline the reaper uses, so an open reader drains rather than
//! reading freed bytes. A crash at ANY step leaves a recoverable log: either the originals survive
//! (crash before commit) or the compacted segment is durable and the covered originals are removed
//! (crash after commit), NEVER a torn mix. Recovery
//! ([`crate::log::Log`]) resolves an overlapping range from the self-describing v2 metadata alone,
//! with no compaction-specific repair and no manifest.
//!
//! Everything here routes through the [`Filesystem`] and [`Clock`] seams, so the deterministic
//! simulation (the fault-injecting in-memory disk plus the manual clock) drives the whole crash
//! and tombstone-TTL behavior with no real IO and no wall-clock read.

use crate::fs::Filesystem;
use crate::naming::{parse_segment_file_name, segment_file_name, segment_ids};
use crate::segment::{OwnedRecord, SegmentReader, SegmentWriter, StorageError};
use bytes::Bytes;
use ironbus_core::clock::Clock;
use ironbus_core::codec::RecordView;
use ironbus_core::segment::{CompactionMeta, SegmentFooter, SegmentHeader};
use ironbus_core::types::{Offset, Seq};
use std::collections::HashMap;

/// The default tombstone retention: 24 hours, in milliseconds. A tombstone (an empty-payload
/// delete for a key) is retained as a survivor until it is older than this, measured against the
/// engine clock seam (never the host wall clock), so an offline consumer that was down can come
/// back and still observe the delete. Once a tombstone has aged past this AND is still the latest
/// record for its key, a later pass may drop it, finally reclaiming the key.
pub const DEFAULT_TOMBSTONE_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// The default minimum dirty ratio at which a run of adjacent sealed segments is worth compacting:
/// `0.5` (at least half the records are superseded, so the rewrite pays for itself). Expressed as
/// a per-mille integer to stay deterministic and avoid float comparisons in the trigger; see
/// [`CompactionConfig::min_dirty_ratio_permille`].
pub const DEFAULT_MIN_DIRTY_RATIO_PERMILLE: u32 = 500;

/// The default cap on how many adjacent dirty sealed segments one compaction pass consumes: `8`.
/// The key map is the cost line (peak memory is one record plus the key map), so this bounds the
/// edge RAM budget per pass; a pass is rate-limited to at most this many source segments.
pub const DEFAULT_MAX_SOURCE_SEGMENTS: usize = 8;

/// The opt-in configuration for key-based compaction (#337). OFF by default: a broker that changes
/// nothing never runs a compaction pass, and its durable-queue behavior (append, seal, reap whole
/// segments) is byte-for-byte unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactionConfig {
    /// Whether compaction is enabled at all. `false` (the default) means no pass ever runs.
    pub enabled: bool,
    /// The trigger: a run of adjacent dirty sealed segments whose combined dirty ratio is at or
    /// over this per-mille value is eligible for a pass (`500` = 0.5). Dirty is the superseded
    /// record COUNT over the run's total record count (the bytes-vs-count accounting is an open
    /// question in the spec; count is the conservative, deterministic choice shipped here).
    pub min_dirty_ratio_permille: u32,
    /// The tombstone retention window in milliseconds (default [`DEFAULT_TOMBSTONE_TTL_MS`], 24h),
    /// measured against the clock seam.
    pub tombstone_ttl_ms: u64,
    /// The cap on adjacent source segments one pass consumes (default
    /// [`DEFAULT_MAX_SOURCE_SEGMENTS`]). Bounds the key-map memory and the per-pass work.
    pub max_source_segments: usize,
}

impl Default for CompactionConfig {
    fn default() -> CompactionConfig {
        CompactionConfig {
            // OFF by default: an operator opts a topic in. This is the load-bearing default.
            enabled: false,
            min_dirty_ratio_permille: DEFAULT_MIN_DIRTY_RATIO_PERMILLE,
            tombstone_ttl_ms: DEFAULT_TOMBSTONE_TTL_MS,
            max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
        }
    }
}

impl CompactionConfig {
    /// Builds an ENABLED config with the default trigger and tombstone TTL. The plain [`Default`]
    /// is disabled; this is the opt-in entry point.
    #[must_use]
    pub fn enabled() -> CompactionConfig {
        CompactionConfig {
            enabled: true,
            ..CompactionConfig::default()
        }
    }
}

/// What one compaction pass did, for observability and tests. Zero/empty fields mean nothing was
/// compacted (compaction is off, no dirty run met the ratio, or the run had nothing to drop).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompactionOutcome {
    /// The fresh id of the compacted segment this pass wrote (`None` if no pass ran).
    pub compacted_segment_id: Option<u64>,
    /// How many source (original) sealed segments this pass covered and retired.
    pub source_segments: u64,
    /// How many SURVIVOR records the compacted segment kept (the sparse set).
    pub survivors: u64,
    /// How many records the pass DROPPED (superseded values plus aged-out tombstones).
    pub dropped: u64,
    /// The covered offset span `[covered_base_offset, covered_end_offset)` this pass superseded.
    pub covered_base_offset: u64,
    /// One past the highest covered SOURCE offset.
    pub covered_end_offset: u64,
}

/// One source segment selected for a compaction pass: its id and the validated, in-order records
/// it holds. The cleaner reads these in offset order to build the key map.
struct SourceSegment {
    id: u64,
    base_offset: u64,
    base_seq: u64,
    records: Vec<OwnedRecord>,
}

/// Reads one sealed source segment fully (header, records, footer) for compaction. Only a SEALED
/// segment is ever an input, so the footer must be present and body-consistent; an unsealed or
/// torn segment is refused (the active segment and any not-yet-sealed file is never a source).
fn read_source_segment<F: Filesystem>(fs: &F, id: u64) -> Result<SourceSegment, StorageError> {
    let scan = SegmentReader::open(fs.open(&segment_file_name(id))?)?.scan()?;
    if scan.footer.is_none() {
        // The compactor only ever reads SEALED segments; refuse an unsealed/torn one rather than
        // partially compact a tail. This should never happen for a caller that passes sealed ids.
        return Err(StorageError::UnsealedPredecessor { segment_id: id });
    }
    Ok(SourceSegment {
        id,
        base_offset: scan.header.base_offset.get(),
        base_seq: scan.header.base_seq.get(),
        records: scan.records,
    })
}

/// Whether a record is a TOMBSTONE: a keyed record with an empty payload (the empty-payload delete
/// convention, no new flag bit, per the spec). A keyless record is never a tombstone (it has no
/// compaction key to delete).
fn is_tombstone(rec: &OwnedRecord) -> bool {
    !rec.key.is_empty() && rec.payload.is_empty()
}

/// The decision the cleaner makes per record while scanning the source set in offset order.
struct Survivors {
    /// The survivor records in ASCENDING offset order (never reordered).
    keep: Vec<OwnedRecord>,
    /// How many records were dropped (superseded values plus aged-out tombstones).
    dropped: u64,
    /// The source set's true covered offset span `[covered_base_offset, covered_end_offset)`.
    covered_base_offset: u64,
    covered_end_offset: u64,
    /// The source set's true covered sequence span `[covered_base_seq, covered_end_seq)`.
    covered_base_seq: u64,
    covered_end_seq: u64,
    /// The highest covered source segment id (the recovery tie-break).
    highest_covered_source_id: u64,
}

/// Selects the survivors over a set of adjacent source segments scanned in offset order (#337).
///
/// The rule (the acceptance core):
/// - the HIGHEST-offset record per key wins; every earlier record for that key is superseded and
///   dropped;
/// - a KEYLESS record (`key_len == 0`) is always a survivor (compaction is meaningful only for
///   keyed topics; a keyless record is carried through verbatim, never silently dropped);
/// - a TOMBSTONE (empty-payload delete for a key) supersedes earlier values for its key like any
///   newer record, and is RETAINED until it is older than `tombstone_ttl_ms` (measured against
///   `now_ms` from the clock seam) AND it is still the latest record for its key, at which point
///   it is dropped, reclaiming the key.
///
/// Survivors keep their ORIGINAL offset and ORIGINAL sequence verbatim (no reorder, no offset
/// rewrite), so I5 holds at the record level: compaction removes offsets, it never invents or
/// shifts one. The covered spans are the source set's TRUE ranges (the predecessor's end through
/// the last source record + 1), independent of which survivor happens to be lowest, so recovery
/// can abut the chain even when the first source segment's leading records were all superseded.
fn select_survivors(sources: &[SourceSegment], now_ms: u64, tombstone_ttl_ms: u64) -> Survivors {
    // The covered offset/seq spans are the WHOLE source set's ranges, computed from the source
    // headers and record counts, NOT from the (sparse) survivors. The set is contiguous and in
    // ascending id/offset order (the caller selects adjacent sealed segments).
    let first = &sources[0];
    let last = &sources[sources.len() - 1];
    let covered_base_offset = first.base_offset;
    let covered_base_seq = first.base_seq;
    let last_count = u64::try_from(last.records.len()).unwrap_or(0);
    let covered_end_offset = last.base_offset.saturating_add(last_count);
    let covered_end_seq = last.base_seq.saturating_add(last_count);
    let highest_covered_source_id = sources.iter().map(|s| s.id).max().unwrap_or(first.id);

    // First pass: record, per key, the HIGHEST offset seen (the latest value for the key). This is
    // streamed in offset order; the map is the cost line that bounds N on an edge core.
    // Keyed on the survivor's `Bytes` key (#480): `OwnedRecord::key` is now a refcounted slice, so
    // `rec.key.clone()` is a refcount bump rather than a `Vec` deep copy, and `get(&rec.key)` borrows
    // the `Bytes` directly. `Bytes` is `Hash + Eq` over its bytes, so the per-key dedup is unchanged.
    let mut latest_for_key: HashMap<Bytes, u64> = HashMap::new();
    for src in sources {
        for rec in &src.records {
            if !rec.key.is_empty() {
                // Records are scanned in ascending offset order, so the last write per key is its
                // highest offset; overwrite unconditionally.
                latest_for_key.insert(rec.key.clone(), rec.offset.get());
            }
        }
    }

    // Second pass: keep a record iff it is keyless (always), or it is the latest for its key AND it
    // is not an aged-out tombstone. Survivors are emitted in ascending offset order, which the scan
    // already is.
    let mut keep: Vec<OwnedRecord> = Vec::new();
    let mut dropped = 0u64;
    for src in sources {
        for rec in &src.records {
            let survives = if rec.key.is_empty() {
                // A keyless record is always a survivor (carried through verbatim).
                true
            } else if latest_for_key.get(&rec.key) == Some(&rec.offset.get()) {
                // This is the latest record for its key. Keep it UNLESS it is an aged-out
                // tombstone: a tombstone older than the TTL whose key has no later value is finally
                // reclaimed. Age is measured against the clock seam (never the host wall clock).
                if is_tombstone(rec) {
                    let aged_out = rec.timestamp_ms.saturating_add(tombstone_ttl_ms) < now_ms;
                    !aged_out
                } else {
                    true
                }
            } else {
                // A superseded value (an earlier record for a key with a higher-offset survivor).
                false
            };
            if survives {
                keep.push(rec.clone());
            } else {
                dropped = dropped.saturating_add(1);
            }
        }
    }

    Survivors {
        keep,
        dropped,
        covered_base_offset,
        covered_end_offset,
        covered_base_seq,
        covered_end_seq,
        highest_covered_source_id,
    }
}

/// Writes the survivors into a fresh `version` = 2 COMPACTED segment, fsyncs it, then dir-fsyncs
/// the parent directory (THE ATOMIC COMMIT POINT), then retires the source segments
/// (unlink-then-dir-fsync). After this returns Ok the compacted segment is durably authoritative
/// for its covered range and every covered original is gone; a crash at any step leaves a
/// recoverable log.
///
/// `fresh_id` MUST be strictly greater than any segment id ever used (ADR 0002: ids are never
/// recycled). The caller guarantees the `sources` are adjacent, sealed, and in ascending id order,
/// and that `fresh_id` does not collide with a live segment.
fn write_and_swap<F, C>(
    fs: &F,
    clock: &C,
    fresh_id: u64,
    sources: &[SourceSegment],
    survivors: &Survivors,
) -> Result<CompactionOutcome, StorageError>
where
    F: Filesystem,
    C: Clock,
{
    // The compacted segment's header base offset/seq is the LOWEST survivor's offset/seq (as for
    // any segment); the covered base (the source set's TRUE start) lives in the trailing v2 block.
    // An all-dropped source set (every record superseded) is possible in principle; in that case
    // the segment has no survivors and its header base is the covered base (nothing to abut from a
    // survivor). We never produce an empty compacted segment here (the trigger requires a dirty run
    // with at least the latest value per key surviving), but be defensive about the base.
    let (base_offset, base_seq) = survivors.keep.first().map_or(
        (survivors.covered_base_offset, survivors.covered_base_seq),
        |r| (r.offset.get(), r.seq.get()),
    );

    let header = SegmentHeader {
        segment_id: fresh_id,
        base_seq: Seq::new(base_seq),
        base_offset: Offset::new(base_offset),
        created_unix_ms: clock.now_unix_millis(),
        // The COMPACTED flag is what makes this a v2 segment: the header encodes version 2.
        flags: ironbus_core::format::SEGMENT_FLAG_COMPACTED,
    };

    let name = segment_file_name(fresh_id);
    // create_new can never clobber an existing segment: a fresh, never-recycled id (ADR 0002).
    let file = fs.create_new(&name)?;
    let mut writer = SegmentWriter::create_compacted(file, header)?;
    let mut last_seq = Seq::new(base_seq);
    for rec in &survivors.keep {
        let view = RecordView {
            seq: rec.seq,
            timestamp_ms: rec.timestamp_ms,
            flags: rec.flags,
            // `OwnedRecord`'s blobs are `Bytes` (#480); deref to the `&[u8]` the borrowing view takes.
            key: &rec.key,
            headers: &rec.headers,
            payload: &rec.payload,
        };
        // Write each survivor at its ORIGINAL offset/seq (no renumber). The writer keeps the
        // sparse last_seq so the footer pins the last survivor's true sequence. The survivor's
        // stored subject (#594) is preserved so a compacted record still matches subject filters.
        writer.append_at(rec.offset, &view, &rec.subject)?;
        last_seq = rec.seq;
    }
    let footer = SegmentFooter {
        segment_id: fresh_id,
        last_seq,
        record_count: u32::try_from(survivors.keep.len()).map_err(|_| StorageError::SegmentFull)?,
    };
    let meta = CompactionMeta {
        covered_base_offset: survivors.covered_base_offset,
        covered_end_offset: survivors.covered_end_offset,
        covered_base_seq: survivors.covered_base_seq,
        covered_end_seq: survivors.covered_end_seq,
        highest_covered_source_id: survivors.highest_covered_source_id,
    };
    // Seal: write the v2 footer then the 44-byte compaction-metadata block as ONE contiguous final
    // write, then fsync the file (so footer+block are durable together), then dir-fsync the parent
    // directory. THE DIRECTORY FSYNC IS THE ATOMIC COMMIT POINT. Before it the new segment may not
    // survive a power loss and the originals are authoritative; after it the compacted segment is
    // durably present and authoritative for its covered range.
    writer.seal_compacted(&footer, &meta)?;
    // THE COMMIT POINT: make the new file's directory entry durable.
    fs.sync_dir()?;

    // Retire the source segments now that the compacted segment is durable. Unlink each, then
    // dir-fsync, the SAME discipline the reaper uses (`Log::reap`): a reader still holding an open
    // handle to an original drains its bytes (the inode stays until the handle closes), and a
    // reader that has not opened it simply will not find it and falls through to the compacted
    // segment. A crash partway leaves SOME originals; recovery drops any original fully covered by
    // the now-durable compacted segment, so the end state is deterministic. We unlink in DESCENDING
    // id order so that if a crash interrupts the loop, the survivors-on-disk are always a PREFIX of
    // the original chain (lower ids first), which recovery's contiguous-chain check already
    // accepts.
    let mut retired = 0u64;
    let mut ids: Vec<u64> = sources.iter().map(|s| s.id).collect();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    for id in ids {
        let src_name = segment_file_name(id);
        if fs.exists(&src_name)? {
            fs.remove(&src_name)?;
            fs.sync_dir()?;
            retired = retired.saturating_add(1);
        }
    }

    Ok(CompactionOutcome {
        compacted_segment_id: Some(fresh_id),
        source_segments: retired,
        survivors: u64::try_from(survivors.keep.len()).unwrap_or(u64::MAX),
        dropped: survivors.dropped,
        covered_base_offset: survivors.covered_base_offset,
        covered_end_offset: survivors.covered_end_offset,
    })
}

/// Runs ONE rate-limited compaction pass over the given adjacent SEALED source segment ids,
/// writing the survivors into a fresh `version` = 2 compacted segment and atomically swapping it in
/// for the originals (#337). This is the off-hot-path entry point: it only ever reads sealed
/// segments and writes a NEW file, never the active segment, so it never races an append for the
/// same bytes and is safe to run outside the append actor's critical section.
///
/// `source_ids` must be a non-empty, ascending, contiguous run of SEALED segment ids (never the
/// active segment). `fresh_id` must be strictly greater than any id ever used (ADR 0002), so it
/// cannot collide with a live or reaped segment.
///
/// # Errors
/// Propagates an IO error, a segment decode error, or [`StorageError::SegmentFull`] if a count or
/// id would overflow. On an error during retire the compacted segment may already be durable and
/// some originals removed; recovery reconciles the partial state deterministically, so a caller may
/// surface the error and let the next open recover.
pub fn compact_run<F, C>(
    fs: &F,
    clock: &C,
    config: &CompactionConfig,
    source_ids: &[u64],
    fresh_id: u64,
) -> Result<CompactionOutcome, StorageError>
where
    F: Filesystem,
    C: Clock,
{
    if !config.enabled || source_ids.is_empty() {
        return Ok(CompactionOutcome::default());
    }
    let mut sources = Vec::with_capacity(source_ids.len());
    for &id in source_ids {
        sources.push(read_source_segment(fs, id)?);
    }
    let now_ms = clock.now_unix_millis();
    let survivors = select_survivors(&sources, now_ms, config.tombstone_ttl_ms);
    write_and_swap(fs, clock, fresh_id, &sources, &survivors)
}

/// Whether a contiguous run of sealed source segments is DIRTY enough to be worth compacting: its
/// superseded-record ratio is at or over `min_dirty_ratio_permille` (#337). Dirty is the count of
/// records that a compaction WOULD drop (superseded values; aged-out tombstones are also counted)
/// over the run's total record count. A run that would drop nothing (every record is the latest for
/// a distinct key, or every record is keyless) is never compacted. Pure: it reads the already-loaded
/// source records and the clock-seam `now_ms`, no IO of its own beyond the caller's reads.
#[must_use]
fn run_is_dirty_enough(sources: &[SourceSegment], now_ms: u64, config: &CompactionConfig) -> bool {
    let total: u64 = sources
        .iter()
        .map(|s| u64::try_from(s.records.len()).unwrap_or(0))
        .sum();
    if total == 0 {
        return false;
    }
    let survivors = select_survivors(sources, now_ms, config.tombstone_ttl_ms);
    // dirty ratio = dropped / total, compared per-mille to avoid floats.
    let ratio_permille = survivors.dropped.saturating_mul(1000) / total;
    ratio_permille >= u64::from(config.min_dirty_ratio_permille)
}

/// A candidate source segment for [`select_dirty_run`]: a sealed, ordinary, non-active segment and
/// its dense offset range, so the trigger can choose an offset-contiguous run of whole segments.
struct Candidate {
    id: u64,
    base_offset: u64,
    end_offset: u64,
}

/// The resident metadata one sealed segment contributes to compaction-trigger DISCOVERY (#824): the
/// three facts [`select_dirty_run`] needs to build a [`Candidate`] without touching disk. The Log
/// feeds these straight from its in-memory `SegmentSlot`s (`id`, `base_offset`, `record_count`, and
/// whether the slot is a compacted survivor), so the per-produce-commit trigger no longer re-reads +
/// CRC-validates every sealed segment just to learn counts it already holds in RAM. Selection does
/// NOT need body validation: the chosen run is fully re-read and re-validated by
/// [`read_source_segment`] before any commit, so an untrusted count at selection time can only pick a
/// different (still fully validated) run, never corrupt state.
///
/// For an ORDINARY sealed segment `record_count` is its dense record count, so its dense range is
/// `[base_offset, base_offset + record_count)` — identical to the old `scan.records.len()` fact. A
/// COMPACTED segment is flagged `is_compacted` and is never a source, so its fields are ignored.
#[derive(Clone, Copy, Debug)]
pub struct SealedSegmentMeta {
    /// The segment id.
    pub id: u64,
    /// The dense base (lowest) offset of the segment.
    pub base_offset: u64,
    /// The sealed record count (the dense count for an ordinary segment).
    pub record_count: u64,
    /// Whether this slot is a COMPACTED (v2) survivor segment, which is never a compaction source.
    pub is_compacted: bool,
}

/// Picks the FIRST adjacent run of up to `max_source_segments` sealed segments (the OLDEST sealed
/// segments, never the active one) whose combined dirty ratio meets the trigger, and returns their
/// ids (#337). Returns `None` when compaction is off, there are fewer than two segments (so nothing
/// but the active one), or no eligible run meets `min_dirty_ratio`.
///
/// This is the event-driven trigger the engine consults off the hot path: discovery reads NOTHING
/// from disk — it builds the candidate set from the caller's resident `sealed` slot metadata (#824)
/// — and then reads ONLY the chosen bounded run (capped to `max_source_segments`) to score its dirty
/// ratio, so the pass it feeds [`compact_run`] is rate-capped to `max_source_segments`.
///
/// `sealed` is the Log's in-memory view of every SEALED segment (the active one is excluded by the
/// caller and, defensively, by the `id >= active_segment_id` guard here). Before #824 discovery
/// re-opened, fully re-read and CRC-validated EVERY sealed segment on each produce commit purely to
/// recover `base_offset` (a header fact) and the record count (the sealed footer's `record_count`,
/// also resident in each slot), an O(total sealed records) cost per commit that grew with the log.
///
/// # Errors
/// Propagates an IO error or a segment decode error from reading the chosen run to score it.
pub fn select_dirty_run<F, C>(
    fs: &F,
    clock: &C,
    config: &CompactionConfig,
    active_segment_id: u64,
    sealed: &[SealedSegmentMeta],
) -> Result<Option<Vec<u64>>, StorageError>
where
    F: Filesystem,
    C: Clock,
{
    if !config.enabled || config.max_source_segments == 0 {
        return Ok(None);
    }
    // Candidate sources are SEALED, ORDINARY (never already-compacted), non-active segments. A
    // compacted segment is never re-compacted as a source: it is already the survivor set for its
    // covered range. Each candidate carries its base offset and dense record range (both resident in
    // the slot) so the run can be chosen offset-CONTIGUOUS (a clean covers a contiguous run of WHOLE
    // source segments, so the resulting compacted segment abuts its predecessor and successor in the
    // chain). No disk IO: the counts come straight from RAM, not a full rescan + CRC of every sealed
    // segment (#824).
    let mut candidates: Vec<Candidate> = Vec::new();
    for meta in sealed {
        if meta.id >= active_segment_id {
            continue; // never the active segment (or anything above it, defensively)
        }
        if meta.is_compacted {
            continue; // an already-compacted segment is never a source
        }
        let base = meta.base_offset;
        let end = base.saturating_add(meta.record_count);
        candidates.push(Candidate {
            id: meta.id,
            base_offset: base,
            end_offset: end,
        });
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    // Sort by base offset and take the LOWEST run of up to `max_source_segments` that is
    // offset-CONTIGUOUS (each segment's base equals the previous segment's end). Stop the run at the
    // first gap (e.g. a compacted segment occupies that covered range) so the source set is always a
    // contiguous run of whole segments.
    candidates.sort_by_key(|c| c.base_offset);
    let mut run: Vec<u64> = Vec::new();
    let mut expected_base = candidates[0].base_offset;
    for c in &candidates {
        if run.len() >= config.max_source_segments {
            break;
        }
        if c.base_offset != expected_base {
            break; // a gap in the covered chain ends the adjacent run
        }
        run.push(c.id);
        expected_base = c.end_offset;
    }
    if run.len() < 2 {
        // A single segment is not worth a compaction pass (nothing adjacent to merge across); the
        // trigger wants an adjacent RUN. This also keeps a lone dirty segment from being rewritten
        // repeatedly with no net reclamation.
        return Ok(None);
    }
    let now_ms = clock.now_unix_millis();
    let mut sources = Vec::with_capacity(run.len());
    for &id in &run {
        sources.push(read_source_segment(fs, id)?);
    }
    if run_is_dirty_enough(&sources, now_ms, config) {
        Ok(Some(run))
    } else {
        Ok(None)
    }
}

/// Whether `name` is the kind of file `parse_segment_file_name` rejects (a foreign/transient file),
/// used by recovery to skip a leftover transient the cleaner might have created. Re-exported for the
/// recovery path; kept here so the transient-naming convention lives with the cleaner.
#[must_use]
pub fn is_recoverable_segment_name(name: &str) -> bool {
    parse_segment_file_name(name).is_some()
}

/// Whether the data directory contains at least one COMPACTED (v2) segment (#337). Recovery uses
/// this cheap probe to decide whether it must run the v2-aware overlapping-range reconciliation, or
/// fall through to the unchanged v1 recovery for an all-ordinary directory. It validates each
/// segment header (so a torn or foreign header surfaces here exactly as in recovery) and stops at
/// the first compacted one.
///
/// # Errors
/// Propagates an IO error or a segment header decode error.
pub fn directory_has_compacted_segment<F: Filesystem>(fs: &F) -> Result<bool, StorageError> {
    for id in segment_ids(fs)? {
        let reader = SegmentReader::open(fs.open(&segment_file_name(id))?)?;
        if reader.header().is_compacted() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use crate::log::{Append, Log, LogConfig};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;

    /// A tiny segment cap so a handful of keyed records roll into several sealed segments, giving
    /// the compactor multiple adjacent sources to clean.
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 200,
            ..LogConfig::default()
        }
    }

    fn put(log: &mut Log<InMemoryFs, ManualClock>, key: &[u8], payload: &[u8]) {
        log.append(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key,
            headers: b"",
            payload,
        })
        .unwrap();
        log.sync().unwrap();
    }

    fn put_at(log: &mut Log<InMemoryFs, ManualClock>, ts: u64, key: &[u8], payload: &[u8]) {
        log.append(&Append {
            timestamp_ms: ts,
            flags: RecordFlags::EMPTY,
            key,
            headers: b"",
            payload,
        })
        .unwrap();
        log.sync().unwrap();
    }

    /// Reads every durable record across the log in order (the dense + sparse offsets the read path
    /// yields), so a test can assert the surviving set and the offsets they kept.
    fn all_records(log: &Log<InMemoryFs, ManualClock>) -> Vec<OwnedRecord> {
        let head = log.flushed_offset().get();
        log.read_from(Offset::ZERO, usize::try_from(head).unwrap_or(usize::MAX))
            .unwrap()
    }

    /// Builds a log with several SEALED keyed segments plus an open active one, returning the log
    /// and the sealed source ids the compactor will clean (every id below the active one).
    fn keyed_log() -> (Log<InMemoryFs, ManualClock>, Vec<u64>) {
        let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        // Write multiple versions per key plus distinct keys, forcing several rolls under the tiny
        // cap so there are multiple adjacent sealed sources.
        for v in 0..6u8 {
            put(&mut log, b"alpha", &[v; 12]);
            put(&mut log, b"beta", &[v + 100; 12]);
        }
        // A keyless record (must always survive) and a distinct one-shot key.
        put(&mut log, b"", b"keyless-carry");
        put(&mut log, b"gamma", b"only-gamma");
        let active = log.active_segment_id();
        let sources: Vec<u64> = (0..active).collect();
        (log, sources)
    }

    #[test]
    fn off_by_default_runs_nothing() {
        let fs = InMemoryFs::new();
        let clock = ManualClock::new();
        let cfg = CompactionConfig::default();
        assert!(!cfg.enabled);
        let out = compact_run(&fs, &clock, &cfg, &[0], 99).unwrap();
        assert_eq!(out, CompactionOutcome::default());
        assert!(select_dirty_run(&fs, &clock, &cfg, 1, &[])
            .unwrap()
            .is_none());
    }

    /// Reads the resident sealed-segment metadata a Log would hold, straight from each sealed
    /// segment's header + footer, mirroring `SegmentSlot { id, base_offset, record_count, .. }`. Test
    /// setup only: it stands in for the in-memory slots the engine feeds `select_dirty_run` (#824).
    fn sealed_meta(fs: &InMemoryFs, active_id: u64) -> Vec<SealedSegmentMeta> {
        let mut out = Vec::new();
        for id in segment_ids(fs).unwrap() {
            if id >= active_id {
                continue;
            }
            let reader = SegmentReader::open(fs.open(&segment_file_name(id)).unwrap()).unwrap();
            let is_compacted = reader.header().is_compacted();
            let scan = reader.scan().unwrap();
            out.push(SealedSegmentMeta {
                id,
                base_offset: scan.header.base_offset.get(),
                record_count: u64::try_from(scan.records.len()).unwrap(),
                is_compacted,
            });
        }
        out
    }

    /// #824: candidate discovery builds its set from the resident slot metadata (`SealedSegmentMeta`)
    /// and opens ONLY the chosen run — it no longer opens + CRC-scans every sealed segment on the
    /// per-produce path. This pins that metadata-only property: after capturing the metadata we DELETE
    /// the highest sealed segment's file (an unselected candidate), and `select_dirty_run` still
    /// selects the dirty LOW run (capped to `max_source_segments`, which excludes the high segment) —
    /// had discovery opened every sealed segment, the missing high file would surface as an error.
    ///
    /// This is a perf change: on a valid log the SELECTION is identical to the old scan-driven path,
    /// so a *behavioral* regression is guarded by the existing compaction / determinism suite — this
    /// test pins the new metadata-only entry point (it does not, and cannot, discriminate against the
    /// behavior-preserving old code).
    #[test]
    fn select_dirty_run_discovers_from_metadata_and_skips_unselected_segments() {
        let fs = InMemoryFs::new();
        let mut log = Log::open(fs.clone(), ManualClock::new(), small_config()).unwrap();
        // Many superseding versions per key force several sealed rolls, each with dropped versions.
        for v in 0..10u8 {
            put(&mut log, b"alpha", &[v; 12]);
            put(&mut log, b"beta", &[v.wrapping_add(100); 12]);
        }
        let active = log.active_segment_id();
        let meta = sealed_meta(&fs, active);
        drop(log);
        assert!(
            meta.len() >= 3,
            "need several sealed segments for a low run and a distinct high one, got {}",
            meta.len()
        );

        // Delete the HIGHEST sealed segment's file (an unselected candidate). Metadata-driven
        // discovery opens only the chosen low run, so selection must still succeed; had it opened
        // every sealed segment, this missing file would surface as an error.
        let highest = meta.iter().map(|m| m.id).max().unwrap();
        fs.remove(&segment_file_name(highest)).unwrap();

        let cfg = CompactionConfig {
            max_source_segments: 2,
            min_dirty_ratio_permille: 1,
            ..CompactionConfig::enabled()
        };
        let clock = ManualClock::new();
        let run = select_dirty_run(&fs, &clock, &cfg, active, &meta)
            .expect("discovery must not open the unselected high segment")
            .expect("the dirty low run should be selected");
        assert_eq!(run.len(), 2, "the run is capped to max_source_segments");
        assert!(
            !run.contains(&highest),
            "the unselected high segment is never part of the low run"
        );
    }

    #[test]
    fn compaction_keeps_latest_per_key_at_original_offsets_drops_superseded() {
        let (mut log, _) = keyed_log();
        // Capture the full pre-compaction record set and the latest offset per key.
        let before = all_records(&log);
        let latest_alpha = before
            .iter()
            .filter(|r| r.key.as_ref() == b"alpha")
            .map(|r| r.offset.get())
            .max()
            .unwrap();
        let latest_beta = before
            .iter()
            .filter(|r| r.key.as_ref() == b"beta")
            .map(|r| r.offset.get())
            .max()
            .unwrap();
        let keyless_off = before
            .iter()
            .find(|r| r.key.is_empty())
            .unwrap()
            .offset
            .get();
        let gamma_off = before
            .iter()
            .find(|r| r.key.as_ref() == b"gamma")
            .unwrap()
            .offset
            .get();

        let cfg = CompactionConfig::enabled();
        let out = log.maybe_compact(&cfg).unwrap();
        assert!(
            out.compacted_segment_id.is_some(),
            "a dirty keyed log should compact"
        );
        assert!(out.dropped > 0, "superseded versions should be dropped");

        // After compaction, the read path yields the SURVIVORS at their ORIGINAL offsets, sparse.
        let after = all_records(&log);
        let alpha_records: Vec<_> = after
            .iter()
            .filter(|r| r.key.as_ref() == b"alpha")
            .collect();
        let beta_records: Vec<_> = after.iter().filter(|r| r.key.as_ref() == b"beta").collect();
        // Exactly one survivor per key (the latest), at its original offset, with its latest value.
        assert_eq!(alpha_records.len(), 1, "only the latest alpha survives");
        assert_eq!(
            alpha_records[0].offset.get(),
            latest_alpha,
            "kept its ORIGINAL offset"
        );
        assert_eq!(alpha_records[0].payload, vec![5u8; 12]);
        assert_eq!(beta_records.len(), 1);
        assert_eq!(beta_records[0].offset.get(), latest_beta);
        // The keyless record and the one-shot key are carried through verbatim at their offsets.
        assert!(after
            .iter()
            .any(|r| r.key.is_empty() && r.offset.get() == keyless_off));
        assert!(after
            .iter()
            .any(|r| r.key.as_ref() == b"gamma" && r.offset.get() == gamma_off));
        // Offsets never decreased and never repeated: I5 holds (monotonic, never reused).
        let offs: Vec<u64> = after.iter().map(|r| r.offset.get()).collect();
        let mut sorted = offs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            offs, sorted,
            "survivor offsets are strictly increasing and unique"
        );
        // The head and next offset never regressed (I5): the log still appends past the same head.
        assert_eq!(log.next_offset().get(), gamma_off + 1);
    }

    #[test]
    fn a_tombstone_within_ttl_is_kept_then_dropped_when_aged_out() {
        // Write a value then a tombstone (empty payload) for the same key, across two sealed
        // segments, then a few distinct keys to make the run dirty. The tombstone is the LATEST
        // record for its key.
        let clock = ManualClock::new();
        let mut log = Log::open(InMemoryFs::new(), clock, small_config()).unwrap();
        put_at(&mut log, 1000, b"k", b"v1");
        put_at(&mut log, 1000, b"k", b"v2");
        put_at(&mut log, 2000, b"k", b""); // tombstone for k
                                           // filler to roll and to make the run dirty (superseded v1/v2).
        for v in 0..4u8 {
            put_at(&mut log, 1000, b"filler", &[v; 12]);
        }
        let active = log.active_segment_id();
        let sources: Vec<u64> = (0..active).collect();

        // Within the TTL: the tombstone is retained as a survivor (so an offline consumer can see
        // the delete), and v1/v2 are dropped.
        let mut cfg = CompactionConfig::enabled();
        cfg.tombstone_ttl_ms = 10_000;
        let mut sources_loaded = Vec::new();
        for &id in &sources {
            sources_loaded.push(read_source_segment(log.filesystem(), id).unwrap());
        }
        let within = select_survivors(&sources_loaded, 5_000, cfg.tombstone_ttl_ms);
        let k_survivors: Vec<_> = within
            .keep
            .iter()
            .filter(|r| r.key.as_ref() == b"k")
            .collect();
        assert_eq!(k_survivors.len(), 1, "the tombstone is retained within TTL");
        assert!(
            k_survivors[0].payload.is_empty(),
            "the survivor IS the tombstone"
        );

        // Past the TTL AND still the latest record for its key: the tombstone is dropped, finally
        // reclaiming the key (no record for k at all).
        let aged = select_survivors(&sources_loaded, 1_000_000, cfg.tombstone_ttl_ms);
        assert!(
            aged.keep.iter().all(|r| r.key.as_ref() != b"k"),
            "aged-out tombstone reclaims the key"
        );
    }

    #[test]
    fn recovery_round_trips_a_compacted_log() {
        let (mut log, _) = keyed_log();
        let cfg = CompactionConfig::enabled();
        log.maybe_compact(&cfg).unwrap();
        let before = all_records(&log);
        let head = log.flushed_offset();
        let next = log.next_offset();
        let fs = log.into_filesystem();

        // Reopen: recovery must read the compacted segment, resolve the chain, and yield the SAME
        // survivors at the SAME sparse offsets, with the head and next offset unchanged (I1 to I4).
        let recovered = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(
            recovered.flushed_offset(),
            head,
            "durable head unchanged across recovery"
        );
        assert_eq!(
            recovered.next_offset(),
            next,
            "next offset never regressed (I5)"
        );
        assert!(
            recovered.loss_report().is_empty(),
            "compaction recovery loses nothing"
        );
        let after = all_records(&recovered);
        assert_eq!(
            before, after,
            "the same survivors recover at the same offsets"
        );
    }
}
