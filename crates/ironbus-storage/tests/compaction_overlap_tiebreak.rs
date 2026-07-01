// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recovery step-3 tie-break gate for TWO committed COMPACTED segments over an OVERLAPPING covered
//! range (#845). This is the divergence-resolution arm of `Log::recover_with_compaction`: a crash
//! that leaves two clean compacted segments spanning the same offsets must deterministically keep
//! exactly ONE — the HIGHER segment id (ADR 0002 monotonicity: the higher id is the later clean) —
//! and irreversibly `fs.remove` the lower. Keeping both would double an offset range (an I5
//! violation); unlinking the higher would drop the later survivor set.
//!
//! The existing overlap coverage (`compaction_crash.rs::crash_after_the_commit_during_retire`)
//! exercises an ORDINARY-vs-COMPACTED overlap (recovery step 2). NO existing test places two
//! COMMITTED compacted segments with overlapping covered ranges on disk, so neither tie-break arm
//! (higher-id-is-`cand` vs higher-id-is-`prev`) was exercised. These two tests build exactly that
//! image with REAL compaction passes and assert the higher id wins in both arms.
//!
//! How the two clean compacted segments are placed on ONE disk (the realistic crash shape: a pass
//! committed a compacted segment but crashed before retiring the originals, then a later pass
//! re-compacted the still-present originals and committed a SECOND compacted segment before recovery
//! reconciled): a real `compact_run` writes the LOWER-id compacted segment and retires its sources;
//! the retired source files are then restored byte-for-byte from a pre-pass snapshot; a second
//! `compact_run` writes the HIGHER-id compacted segment over the (restored) originals. The result is
//! two committed, CRC-valid compacted segments whose covered ranges overlap, exactly as recovery
//! must reconcile.

use ironbus_core::clock::ManualClock;
use ironbus_core::types::Offset;
use ironbus_storage::compaction::{compact_run, CompactionConfig};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::naming::{segment_file_name, segment_ids};
use ironbus_storage::segment::{OwnedRecord, SegmentReader};

/// A tiny cap so a handful of keyed records roll into several sealed segments (multiple adjacent
/// compaction sources, and a low-id source segment 0 distinct from the rest for the sub-range arm).
fn small_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 200,
        ..LogConfig::default()
    }
}

/// The two fresh compacted-segment ids. Both are far above any id a `small_config` dirty log uses,
/// so they never collide with a live segment (ADR 0002: ids are never recycled), and `LOWER < HIGHER`
/// so the recovery tie-break must keep `HIGHER` and unlink `LOWER`.
const LOWER_ID: u64 = 1000;
const HIGHER_ID: u64 = 1001;

fn put(log: &mut Log<InMemoryFs, ManualClock>, key: &[u8], payload: &[u8]) {
    log.append(&Append {
        timestamp_ms: 0,
        flags: ironbus_core::types::RecordFlags::EMPTY,
        key,
        headers: b"",
        payload,
    })
    .unwrap();
    log.sync().unwrap();
}

/// Builds a dirty keyed log (several versions per key across several sealed segments plus an open
/// active segment) on a FRESH in-memory disk. Returns the disk and the durable head. Deterministic,
/// so two independent calls produce byte-identical disks (no shared-`Arc` clone).
fn build_dirty_log() -> (InMemoryFs, Offset) {
    let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
    for v in 0..6u8 {
        put(&mut log, b"alpha", &[v; 12]);
        put(&mut log, b"beta", &[v + 100; 12]);
    }
    put(&mut log, b"", b"keyless"); // a keyless record always survives compaction
    let head = log.flushed_offset();
    (log.into_filesystem(), head)
}

/// Reads every durable record across a recovered log, in order.
fn all_records(log: &Log<InMemoryFs, ManualClock>) -> Vec<OwnedRecord> {
    let head = log.flushed_offset().get();
    log.read_from(Offset::ZERO, usize::try_from(head).unwrap())
        .unwrap()
}

/// The sealed source ids of a freshly built dirty log: every id below the trailing (active) one.
fn sealed_source_ids(fs: &InMemoryFs) -> (Vec<u64>, u64) {
    let ids = segment_ids(fs).unwrap();
    let active = *ids.last().unwrap();
    let sources: Vec<u64> = ids[..ids.len() - 1].to_vec();
    (sources, active)
}

/// Snapshots the full bytes of `name` on `fs`.
fn snapshot(fs: &InMemoryFs, name: &str) -> Vec<u8> {
    let file = fs.open(name).unwrap();
    let len = usize::try_from(file.len().unwrap()).unwrap();
    let mut buf = vec![0u8; len];
    file.read_exact_at(&mut buf, 0).unwrap();
    buf
}

/// Restores `name` on `fs` from a snapshot IFF it is currently absent (a source a compaction retired).
fn restore_if_absent(fs: &InMemoryFs, name: &str, bytes: &[u8]) {
    if !fs.exists(name).unwrap() {
        let file = fs.create_new(name).unwrap();
        file.write_all_at(bytes, 0).unwrap();
        file.sync_all().unwrap();
    }
}

/// The ground-truth recovered read of a SINGLE clean full compaction over `[0, active_base)` plus the
/// active tail: exactly the survivor set the surviving HIGHER-id compacted segment must yield. Built
/// on an independent disk (a fresh dirty log), so it does not alias the disk under test.
fn reference_survivors() -> Vec<OwnedRecord> {
    let (fs, _head) = build_dirty_log();
    let (sources, _active) = sealed_source_ids(&fs);
    let out = compact_run(
        &fs,
        &ManualClock::new(),
        &CompactionConfig::enabled(),
        &sources,
        HIGHER_ID,
    )
    .unwrap();
    assert!(
        out.compacted_segment_id.is_some() && out.survivors > 0,
        "the reference full compaction produced a committed compacted segment"
    );
    let recovered = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    assert!(
        recovered.loss_report().is_empty(),
        "a clean single full compaction loses nothing on recovery"
    );
    all_records(&recovered)
}

/// Builds a disk carrying TWO committed, CRC-valid compacted segments (`LOWER_ID` and `HIGHER_ID`)
/// whose covered ranges OVERLAP, plus the untouched active segment.
///
/// `lower_is_full`:
/// - `true`  — both segments compact the FULL source run `[0, active_base)`, so they share the SAME
///   covered base offset. In recovery step 3 the covered-base sort is stable over the ascending-id
///   candidate list, so `LOWER_ID` is `prev` and `HIGHER_ID` is `cand`: the `cand.id > prev.id`
///   pop-`prev` arm keeps `HIGHER_ID`.
/// - `false` — `LOWER_ID` compacts only the SUB-run `[1..]` (a HIGHER covered base than `HIGHER_ID`'s
///   full `[0, active_base)`). After the covered-base sort, `HIGHER_ID` is `prev` (lower base) and
///   `LOWER_ID` is `cand`: the else drop-`cand` arm keeps `HIGHER_ID`.
///
/// In BOTH arms the HIGHER id must survive and the LOWER id must be unlinked.
fn two_overlapping_compacted(lower_is_full: bool) -> InMemoryFs {
    let (fs, _head) = build_dirty_log();
    let (full_sources, active) = sealed_source_ids(&fs);
    assert!(
        full_sources.len() >= 2,
        "need at least two sealed sources (one distinct low-id source for the sub-range arm), got {}",
        full_sources.len()
    );
    assert!(
        active < LOWER_ID,
        "the fresh compacted ids must sit above every live segment id (active={active})"
    );

    // Snapshot every source BEFORE any pass retires it, so the second pass can compact the same
    // originals over again.
    let names: Vec<String> = full_sources
        .iter()
        .map(|&id| segment_file_name(id))
        .collect();
    let snapshots: Vec<Vec<u8>> = names.iter().map(|n| snapshot(&fs, n)).collect();

    // Pass 1: write the LOWER-id compacted segment. In the sub-range arm it covers only `[1..]`
    // (segment 0 is left out, giving it a higher covered base); in the full arm it covers everything.
    let lower_sources: &[u64] = if lower_is_full {
        &full_sources
    } else {
        &full_sources[1..]
    };
    let clock = ManualClock::new();
    let cfg = CompactionConfig::enabled();
    compact_run(&fs, &clock, &cfg, lower_sources, LOWER_ID).unwrap();

    // Restore any source the first pass retired, so the second pass re-compacts the SAME originals.
    for (name, bytes) in names.iter().zip(&snapshots) {
        restore_if_absent(&fs, name, bytes);
    }

    // Pass 2: write the HIGHER-id compacted segment over the FULL original run, retiring the sources.
    compact_run(&fs, &clock, &cfg, &full_sources, HIGHER_ID).unwrap();

    // The disk now holds exactly the two committed compacted segments plus the active segment: an
    // overlapping-covered-range pair recovery must reconcile.
    let ids = segment_ids(&fs).unwrap();
    assert!(
        ids.contains(&LOWER_ID) && ids.contains(&HIGHER_ID),
        "both committed compacted segments are on disk before recovery: {ids:?}"
    );
    let both_compacted = [LOWER_ID, HIGHER_ID].iter().all(|&id| {
        SegmentReader::open(fs.open(&segment_file_name(id)).unwrap())
            .unwrap()
            .header()
            .is_compacted()
    });
    assert!(
        both_compacted,
        "both survivors carry the v2 COMPACTED header"
    );
    fs
}

/// The shared assertion for both arms: after `Log::open`, the LOWER-id compacted file is UNLINKED,
/// the HIGHER-id file SURVIVES, and the recovered read equals the single-clean-compaction survivor
/// set with strictly increasing, unique offsets (I5). The file-survival check is the discriminator:
/// inverting the id tie-break flips exactly which file is removed.
fn assert_higher_id_wins(fs: InMemoryFs) {
    let expected = reference_survivors();

    let recovered = Log::open(fs, ManualClock::new(), small_config())
        .expect("recovery reconciles two overlapping compacted segments into a valid chain");
    let got = all_records(&recovered);

    // (I5) offsets strictly increasing and unique across the recovered read.
    let offs: Vec<u64> = got.iter().map(|r| r.offset.get()).collect();
    let mut sorted = offs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        offs, sorted,
        "recovered survivor offsets are strictly increasing and unique (I5)"
    );

    // The kept (HIGHER-id) segment's survivor set is exactly the single-clean-compaction ground truth.
    assert_eq!(
        got, expected,
        "the recovered records equal the higher segment's survivor set at its sparse offsets"
    );

    // The tie-break's irreversible unlink: the LOWER id is gone, the HIGHER id survives.
    let fs = recovered.into_filesystem();
    assert!(
        !fs.exists(&segment_file_name(LOWER_ID)).unwrap(),
        "the LOWER-id compacted segment must be unlinked by the overlap tie-break"
    );
    assert!(
        fs.exists(&segment_file_name(HIGHER_ID)).unwrap(),
        "the HIGHER-id compacted segment (the later clean) must survive the overlap tie-break"
    );
    // Exactly one compacted segment remains: the doubled range was resolved, not left duplicated (I5).
    let compacted_left: Vec<u64> = segment_ids(&fs)
        .unwrap()
        .into_iter()
        .filter(|&id| {
            SegmentReader::open(fs.open(&segment_file_name(id)).unwrap())
                .unwrap()
                .header()
                .is_compacted()
        })
        .collect();
    assert_eq!(
        compacted_left,
        vec![HIGHER_ID],
        "exactly the higher-id compacted segment survives; the overlapping pair is de-duplicated"
    );
}

/// Arm A (`recover_with_compaction` step 3, the `cand.id > prev.id` pop-`prev` branch): two compacted
/// segments over the SAME covered range. After the stable covered-base sort the lower id is `prev`
/// and the higher id is `cand`, so the pop-`prev`-keep-`cand` arm fires. The higher id must win.
#[test]
fn two_compacted_same_covered_range_keeps_the_higher_id_pop_prev_arm() {
    let fs = two_overlapping_compacted(true);
    assert_higher_id_wins(fs);
}

/// Arm B (`recover_with_compaction` step 3, the else drop-`cand` branch): the HIGHER-id compacted
/// segment covers the WIDER, lower-based range `[0, end)` and the LOWER-id one covers only the tail
/// sub-range `[k, end)`. After the covered-base sort the higher id is `prev` (lower base) and the
/// lower id is `cand`, so the else drop-`cand` arm fires. The higher id must STILL win.
#[test]
fn two_compacted_overlapping_ranges_keeps_the_higher_id_drop_cand_arm() {
    let fs = two_overlapping_compacted(false);
    assert_higher_id_wins(fs);
}
