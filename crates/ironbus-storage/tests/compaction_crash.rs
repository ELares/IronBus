// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crash-injection gates for key-based log compaction (#337), the STORAGE-CRITICAL half.
//!
//! These make the compaction crash-safety claims falsifiable, driven by the fault-injecting
//! in-memory disk ([`FaultFs`] over [`InMemoryFs`]) and the manual clock ([`ManualClock`]), so the
//! whole window is deterministic with no real IO and no wall-clock read.
//!
//! The atomic swap is: write the survivors into a fresh `version` = 2 compacted segment, fsync it,
//! dir-fsync the parent directory (THE COMMIT POINT), then unlink the originals (each with its own
//! dir-fsync). The crash classes covered:
//! - a crash BEFORE the commit (the commit dir-fsync fails / is not durable): the originals win,
//!   the orphan compacted segment is discarded, no record is lost or doubled;
//! - a crash AFTER the commit but DURING retire (the compacted segment is durable, some/all
//!   originals still present): the compacted set wins, the superseded originals are dropped, no
//!   record is lost or doubled, the overlapping range is resolved from the v2 footer metadata;
//! - the recovered log is identical whether the crash landed before or after the commit's effect
//!   on the surviving offsets, and the offset monotonic / never-reuse invariant (I5) and I1 to I4
//!   hold across the compaction + crash.

use bytes::Bytes;
use ironbus_core::clock::ManualClock;
use ironbus_core::format::{COMPACTION_META_LEN, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN};
use ironbus_core::segment::{SegmentFooter, SegmentHeader};
use ironbus_core::types::Offset;
use ironbus_storage::compaction::CompactionConfig;
use ironbus_storage::fault::FaultFs;
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::invariants::{check_longest_valid_prefix, check_no_acked_loss};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::naming::{segment_file_name, segment_ids};
use ironbus_storage::segment::{OwnedRecord, SegmentReader};

/// A tiny cap so a handful of keyed records roll into several sealed segments.
fn small_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 200,
        ..LogConfig::default()
    }
}

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

/// Builds a dirty keyed log (several versions per key over several sealed segments) on the given
/// in-memory disk and returns the durable record set BEFORE any compaction.
fn build_dirty_log(fs: InMemoryFs) -> (InMemoryFs, Vec<OwnedRecord>, Offset) {
    let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    for v in 0..6u8 {
        put(&mut log, b"alpha", &[v; 12]);
        put(&mut log, b"beta", &[v + 100; 12]);
    }
    put(&mut log, b"", b"keyless"); // a keyless record always survives
    let head = log.flushed_offset();
    let before = log
        .read_from(Offset::ZERO, usize::try_from(head.get()).unwrap())
        .unwrap();
    (log.into_filesystem(), before, head)
}

/// The latest record per key in a record set, the compaction survivor set, plus every keyless
/// record (always a survivor), in ascending offset order. This is what a correct compaction must
/// keep, with each survivor at its ORIGINAL offset.
fn expected_survivors(records: &[OwnedRecord]) -> Vec<OwnedRecord> {
    use std::collections::HashMap;
    let mut latest: HashMap<Bytes, u64> = HashMap::new();
    for r in records {
        if !r.key.is_empty() {
            latest.insert(r.key.clone(), r.offset.get());
        }
    }
    records
        .iter()
        .filter(|r| r.key.is_empty() || latest.get(&r.key) == Some(&r.offset.get()))
        .cloned()
        .collect()
}

/// Reads every durable record across a recovered log, in order.
fn all_records(log: &Log<InMemoryFs, ManualClock>) -> Vec<OwnedRecord> {
    let head = log.flushed_offset().get();
    log.read_from(Offset::ZERO, usize::try_from(head).unwrap())
        .unwrap()
}

/// Builds a dirty log, FULLY compacts it on a clean disk (so the compacted segment is durable and
/// its covered originals are unlinked — the compacted segment is now the SOLE durable copy of its
/// survivors), and returns the disk, the pre-compaction record set, the covered survivor set, and
/// the id of the committed compacted segment. This is the exact starting image #836 describes: a
/// mid-body bit-flip in this segment must NOT be conflated with a crash-before-commit orphan.
fn fully_compacted_sole_copy() -> (InMemoryFs, Vec<OwnedRecord>, Vec<OwnedRecord>, u64) {
    let (fs, before, _head) = build_dirty_log(InMemoryFs::new());
    let want = expected_survivors(&before);
    let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    let out = log.maybe_compact(&CompactionConfig::enabled()).unwrap();
    assert!(
        out.compacted_segment_id.is_some(),
        "the pass produced a committed compacted segment"
    );
    let fs = log.into_filesystem();
    let compacted_id = segment_ids(&fs)
        .unwrap()
        .into_iter()
        .find(|&id| {
            SegmentReader::open(fs.open(&segment_file_name(id)).unwrap())
                .unwrap()
                .header()
                .is_compacted()
        })
        .expect("a committed compacted segment exists on disk");
    (fs, before, want, compacted_id)
}

/// The final assertion shared by both #836 variants: after the corruption of a COMMITTED compacted
/// segment (its footer + meta stay CRC-valid), `Log::open` must fail closed by QUARANTINING the sole
/// durable copy and ACCOUNTING the covered survivor loss in the `LossReport` — never the silent
/// crash-before-commit-orphan unlink that drops every survivor unreported.
///
/// This is the post-#836-fix expectation (the pre-fix behaviour reproduced the silent sole-copy
/// loss). It asserts, precisely:
/// 1. `Log::open` SUCCEEDS (recovery quarantines + reports rather than aborting the whole boot);
/// 2. the poisoned segment is QUARANTINED — a forensic copy exists under `quarantine/`, so it is
///    provably NOT silently gone;
/// 3. the `LossReport` accounts the covered survivors as real DATA loss (a `CorruptRecordBody` event
///    on the compacted segment id, with a `records_lost_estimate` covering every survivor), so the
///    survivors that dropped out of the live read did so ACCOUNTED, never silently.
fn assert_not_silently_lost(fs: InMemoryFs, compacted_id: u64, want_survivors: &[OwnedRecord]) {
    let recovered = Log::open(fs, ManualClock::new(), small_config())
        .expect("recovery must quarantine + report the committed-but-corrupt compacted segment, not fail the whole boot");

    // Read every record STILL LIVE, from the recovered log's earliest retained offset (quarantining
    // the poisoned compacted segment raises the oldest offset past its covered range, so a
    // `read_from(ZERO, ..)` would just error `OffsetOutOfRange`). The survivors the compacted segment
    // was the SOLE copy of are absent from this live read: they are the genuinely-lost set, distinct
    // from a survivor that also lived in an un-compacted segment (e.g. the keyless tail).
    let head = recovered.flushed_offset().get();
    let got = recovered
        .read_from(
            recovered.earliest_offset(),
            usize::try_from(head).unwrap_or(usize::MAX),
        )
        .unwrap_or_default();
    let got_offsets: std::collections::HashSet<u64> = got.iter().map(|r| r.offset.get()).collect();
    let lost: Vec<u64> = want_survivors
        .iter()
        .map(|r| r.offset.get())
        .filter(|o| !got_offsets.contains(o))
        .collect();

    // The LossReport must ACCOUNT the covered survivor loss: a data-loss event on the poisoned
    // compacted segment, estimating at least as many records as it held survivors.
    let report = recovered.loss_report().clone();
    let accounted_records =
        report.records_lost_for(ironbus_storage::loss::ReasonCode::CorruptRecordBody);
    let event_for_segment = report
        .events
        .iter()
        .any(|e| e.segment_id == compacted_id && e.reason_code.is_data_loss());

    let fs = recovered.into_filesystem();
    let quarantined = fs.subdir_exists("quarantine").unwrap();

    // (1) At least one sole-copy survivor left the LIVE log (the poisoned segment WAS the sole
    // durable copy of the survivors it covered)...
    assert!(
        !lost.is_empty(),
        "the sole-copy survivors the poisoned compacted segment covered must drop out of the live \
         read once it is quarantined"
    );
    // (2) ...but the segment is QUARANTINED (a forensic copy), never silently unlinked...
    assert!(
        quarantined,
        "SILENT SOLE-COPY DATA LOSS (#836): the committed compacted segment must be quarantined \
         (a forensic copy under quarantine/), not unlinked as a crash-before-commit orphan"
    );
    // (3) ...and the covered survivor loss is ACCOUNTED in the LossReport (fail-closed + reported):
    // a data-loss event on the poisoned segment, estimating at least as many lost records as
    // vanished from the live read. The keyless tail survivor (offset 12) lives in an un-compacted
    // segment, so it stays durable and is NOT counted here — only the compacted segment's own
    // survivors are the sole-copy loss.
    assert!(
        !report.is_empty() && event_for_segment && report.data_loss_bytes() > 0,
        "SILENT SOLE-COPY DATA LOSS (#836): recovery must emit a data-loss LossReport event for the \
         quarantined compacted segment {compacted_id}, never drop the sole durable copy unreported \
         (report={report:?})"
    );
    assert!(
        accounted_records >= lost.len() as u64,
        "the LossReport must account at least the {} vanished sole-copy survivors as lost records, \
         got {accounted_records}",
        lost.len()
    );
}

/// #836 variant 1: a mid-body survivor bit-flip in a committed compacted segment (the trailing
/// footer + 44-byte compaction block are left intact, so they stay CRC-valid and decode). This is
/// NOT a crash-before-commit orphan — the segment reached its commit point — so `scan_compacted`
/// must report it DISTINCTLY from the `Ok(None)` a torn footer yields, and recovery must quarantine
/// + account the SOLE durable copy rather than silently unlinking it.
///
/// Regression guard for the fix: `scan_compacted` returns the typed `Err(CorruptCompacted)` on the
/// mid-body corruption branch, and `Log::open` quarantines the poisoned segment and records the
/// covered survivor loss in the `LossReport`. Before the fix this reproduced silent sole-copy data
/// loss (the file was unlinked, offsets 10..12 vanished with no `LossReport` and no quarantine); if
/// that silent-unlink ever regresses, `assert_not_silently_lost` fails.
#[test]
fn mid_body_corruption_in_a_committed_compacted_segment_is_not_silently_unlinked() {
    let (fs, _before, want, compacted_id) = fully_compacted_sole_copy();

    // Flip one byte inside a NON-TAIL survivor frame: 8 bytes past the 64-byte header lands in the
    // first survivor's frame, well before the footer. The footer (32) + meta block (44) at the very
    // end are untouched, so they still decode CRC-valid — the exact ambiguous shape #836 names.
    let file = fs.open(&segment_file_name(compacted_id)).unwrap();
    let flip_at = SEGMENT_HEADER_LEN as u64 + 8;
    let mut b = [0u8; 1];
    file.read_exact_at(&mut b, flip_at).unwrap();
    b[0] ^= 0xFF;
    file.write_all_at(&b, flip_at).unwrap();
    file.sync_all().unwrap();
    fs.sync_dir().unwrap();

    // The flip drives `scan_compacted` down the mid-body corruption branch (footer + meta still
    // decode CRC-valid, but a survivor frame fails its CRC). Post-fix that returns the DISTINCT typed
    // `Err(CorruptCompacted)`, never the crash-before-commit `Ok(None)` recovery would unlink.
    {
        let reader =
            SegmentReader::open(fs.open(&segment_file_name(compacted_id)).unwrap()).unwrap();
        let scan = reader.scan_compacted();
        assert!(
            matches!(
                scan,
                Err(ironbus_storage::segment::StorageError::CorruptCompacted { .. })
            ),
            "a mid-body-corrupt COMMITTED compacted segment must report the distinct \
             CorruptCompacted signal, not the crash-before-commit Ok(None) orphan"
        );
    }

    assert_not_silently_lost(fs, compacted_id, &want);
}

/// #836 variant 2: a footer `record_count` / body-length DISAGREEMENT past the valid trailers. The
/// footer and meta block are re-stamped with a fresh, CRC-valid footer whose `record_count` no
/// longer matches the survivors on disk, so `scan_compacted` decodes every frame and both trailers
/// cleanly, then hits the count cross-check (segment.rs). That segment reached its commit point, so
/// it must be reported DISTINCTLY from a crash-before-commit orphan and quarantined, not unlinked.
///
/// Regression guard, sibling of the mid-body variant: the count cross-check returns the typed
/// `Err(CorruptCompacted)` and recovery quarantines + accounts the loss. Before the fix this
/// reproduced the same silent sole-copy loss via the third `Ok(None)` case.
#[test]
fn footer_count_disagreement_in_a_committed_compacted_segment_is_not_silently_unlinked() {
    let (fs, _before, want, compacted_id) = fully_compacted_sole_copy();

    // Re-stamp the trailing footer with record_count + 1 and a VALID v2 CRC, leaving the survivor
    // frames and the meta block exactly as they are. The footer now describes one more record than
    // the body holds, driving the footer/body-length disagreement branch.
    let file = fs.open(&segment_file_name(compacted_id)).unwrap();
    let file_len = file.len().unwrap();
    let footer_start = file_len - COMPACTION_META_LEN as u64 - SEGMENT_FOOTER_LEN as u64;
    let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
    file.read_exact_at(&mut fbuf, footer_start).unwrap();
    let footer = SegmentFooter::decode(&fbuf).expect("the committed footer decodes");
    let tampered = SegmentFooter {
        record_count: footer.record_count + 1,
        ..footer
    };
    file.write_all_at(&tampered.encode_v2(), footer_start)
        .unwrap();
    file.sync_all().unwrap();
    fs.sync_dir().unwrap();

    // The re-stamped footer is CRC-valid but disagrees with the body count, so `scan_compacted`
    // returns the DISTINCT typed `Err(CorruptCompacted)` at the count cross-check — never the
    // crash-before-commit `Ok(None)` orphan recovery would silently unlink.
    {
        let reader =
            SegmentReader::open(fs.open(&segment_file_name(compacted_id)).unwrap()).unwrap();
        let scan = reader.scan_compacted();
        assert!(
            matches!(
                scan,
                Err(ironbus_storage::segment::StorageError::CorruptCompacted { .. })
            ),
            "a footer-count-inconsistent COMMITTED compacted segment must report the distinct \
             CorruptCompacted signal, not the crash-before-commit Ok(None) orphan"
        );
    }

    assert_not_silently_lost(fs, compacted_id, &want);
}

#[test]
fn a_clean_compaction_then_reopen_keeps_survivors_at_original_offsets() {
    let (fs, before, head) = build_dirty_log(InMemoryFs::new());
    let want = expected_survivors(&before);

    // Run the whole atomic swap on a clean disk (no fault), then reopen.
    let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    let out = log.maybe_compact(&CompactionConfig::enabled()).unwrap();
    assert!(out.compacted_segment_id.is_some());
    let fs = log.into_filesystem();

    let recovered = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    assert_eq!(
        recovered.flushed_offset(),
        head,
        "head unchanged (I1 to I4)"
    );
    let got = all_records(&recovered);
    assert_eq!(
        got, want,
        "the survivors recover at their original sparse offsets"
    );
}

#[test]
fn crash_before_the_commit_point_keeps_the_originals() {
    // Arm the FIRST sync_dir (the compaction commit point) to fail: the compacted segment is
    // written but never committed, so a power loss reverts it and the originals stay authoritative.
    let (fs, before, head) = build_dirty_log(InMemoryFs::new());
    let (faulty, control) = FaultFs::new(fs);
    let mut log = Log::open(faulty, ManualClock::new(), small_config()).unwrap();
    // Fail every sync_dir from the very first one (the commit): the compacted segment cannot become
    // durable.
    control.fail_sync_dir_after(1);
    // The pass fails at the commit point (a sync_dir error).
    let result = log.maybe_compact(&CompactionConfig::enabled());
    assert!(result.is_err(), "the commit-point dir-fsync failed");
    // Simulate the power loss: the directory reverts to its last durable image (before the orphan
    // compacted segment's entry was ever synced), so only the originals survive.
    let faulty = log.into_filesystem();
    faulty.inner().simulate_power_loss();
    let fs = faulty.into_inner();

    // Recover: the originals form the normal contiguous chain; any orphan compacted segment is
    // gone (reverted) or discarded. No record is lost or doubled.
    let recovered = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    assert_eq!(
        recovered.flushed_offset(),
        head,
        "the originals' head is intact"
    );
    let got = all_records(&recovered);
    assert_eq!(got, before, "every original record recovers, none doubled");
    // I1 (no acked loss) and I2 (longest valid prefix) hold over the recovered set.
    let offsets: Vec<u64> = got.iter().map(|r| r.offset.get()).collect();
    assert_eq!(
        offsets,
        (0..head.get()).collect::<Vec<_>>(),
        "dense, contiguous, no gap"
    );
}

#[test]
fn crash_after_the_commit_during_retire_keeps_the_compacted_set() {
    // Commit succeeds (the 1st sync_dir), then the retire's dir-fsync (the 2nd) fails: the
    // compacted segment is DURABLE but the originals are still present (their removal was not
    // dir-synced). This is the crash-after-commit-mid-retire window.
    let (fs, before, head) = build_dirty_log(InMemoryFs::new());
    let want = expected_survivors(&before);
    let (faulty, control) = FaultFs::new(fs);
    let mut log = Log::open(faulty, ManualClock::new(), small_config()).unwrap();
    // Let the commit (1st) sync_dir succeed; fail the 2nd and onward (the retire dir-fsyncs).
    control.fail_sync_dir_after(2);
    let result = log.maybe_compact(&CompactionConfig::enabled());
    assert!(
        result.is_err(),
        "a retire dir-fsync failed after the commit"
    );
    // Power loss: the directory reverts to the last durable image, which is AFTER the commit (the
    // compacted segment's entry is durable) but BEFORE any retire was durable (every original is
    // restored). So BOTH the compacted segment and all originals are present: the overlapping range
    // recovery must resolve.
    let faulty = log.into_filesystem();
    faulty.inner().simulate_power_loss();
    let fs = faulty.into_inner();

    // Sanity: the disk really holds an overlap (a compacted segment AND originals it covers).
    let ids = segment_ids(&fs).unwrap();
    let compacted_present = ids.iter().any(|&id| {
        SegmentReader::open(fs.open(&segment_file_name(id)).unwrap())
            .unwrap()
            .header()
            .is_compacted()
    });
    assert!(
        compacted_present,
        "the durable compacted segment survived the cut"
    );
    assert!(
        ids.len() > 1,
        "originals are still present alongside it (an overlap)"
    );

    // Recover: the compacted segment is authoritative for its covered range; the superseded
    // originals are dropped (overlap resolved from the v2 footer metadata). No record lost/doubled.
    let recovered = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    assert_eq!(
        recovered.flushed_offset(),
        head,
        "head unchanged across the compaction + crash"
    );
    let got = all_records(&recovered);
    assert_eq!(
        got, want,
        "the compacted survivor set wins, at original sparse offsets"
    );
    // Offsets are strictly increasing and unique (I5: monotonic, never reused), and a subset of the
    // originals' offsets (compaction removes offsets, never invents or shifts one).
    let offs: Vec<u64> = got.iter().map(|r| r.offset.get()).collect();
    let mut sorted = offs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        offs, sorted,
        "survivor offsets strictly increasing and unique (I5)"
    );
    let before_offs: std::collections::HashSet<u64> =
        before.iter().map(|r| r.offset.get()).collect();
    assert!(
        offs.iter().all(|o| before_offs.contains(o)),
        "no invented offset (I5)"
    );
}

#[test]
fn recovery_is_identical_whether_the_crash_was_before_or_after_a_full_retire() {
    // The fully-completed compaction (clean disk) and the crash-after-commit-mid-retire case must
    // recover to the SAME survivor set at the SAME offsets: the swap is crash-atomic, so the
    // recovered log never depends on exactly when the crash landed past the commit point.
    let (fs_a, before, _) = build_dirty_log(InMemoryFs::new());
    let mut log_a = Log::open(fs_a, ManualClock::new(), small_config()).unwrap();
    log_a.maybe_compact(&CompactionConfig::enabled()).unwrap();
    let clean = all_records(
        &Log::open(log_a.into_filesystem(), ManualClock::new(), small_config()).unwrap(),
    );

    let (fs_b, before_b, _) = build_dirty_log(InMemoryFs::new());
    assert_eq!(before, before_b, "the two builds are identical");
    let (faulty, control) = FaultFs::new(fs_b);
    let mut log_b = Log::open(faulty, ManualClock::new(), small_config()).unwrap();
    control.fail_sync_dir_after(2);
    let _ = log_b.maybe_compact(&CompactionConfig::enabled());
    let faulty = log_b.into_filesystem();
    faulty.inner().simulate_power_loss();
    let crashed =
        all_records(&Log::open(faulty.into_inner(), ManualClock::new(), small_config()).unwrap());

    assert_eq!(
        clean, crashed,
        "before-vs-after-commit recover to an identical log"
    );
}

#[test]
fn a_v1_only_reader_fails_closed_on_a_compacted_segment_on_disk() {
    // After a real compaction, the compacted segment's header is version 2. A v1-only reader
    // (`SegmentHeader::decode_v1_only`, the pre-compaction refusal path) REFUSES it with a typed
    // UnsupportedVersion, rather than mis-reading its sparse offsets: the fail-closed bump on disk.
    let (fs, _, _) = build_dirty_log(InMemoryFs::new());
    let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    log.maybe_compact(&CompactionConfig::enabled()).unwrap();
    let fs = log.into_filesystem();

    let mut saw_compacted = false;
    for id in segment_ids(&fs).unwrap() {
        let file = fs.open(&segment_file_name(id)).unwrap();
        let mut hdr = [0u8; 64];
        file.read_exact_at(&mut hdr, 0).unwrap();
        // The v2-aware decode accepts every segment (v1 and v2).
        let header = SegmentHeader::decode(&hdr).unwrap();
        if header.is_compacted() {
            saw_compacted = true;
            // The v1-only decode REFUSES it (fail-closed), proving an old reader cannot mis-read.
            assert!(
                SegmentHeader::decode_v1_only(&hdr).is_err(),
                "a v1-only reader must fail closed on the compacted (v2) segment"
            );
        } else {
            // An ordinary segment still decodes fine under a v1-only reader (backward compat).
            assert!(SegmentHeader::decode_v1_only(&hdr).is_ok());
        }
    }
    assert!(
        saw_compacted,
        "the compaction produced a v2 compacted segment"
    );
}

#[test]
fn the_invariant_checkers_pass_across_a_compaction_and_crash() {
    // The resilience checkers I2 (longest-valid-prefix) and I1 (no acked loss) must hold over the
    // recovered log after a crash-during-retire compaction. The recovered survivor set is a sparse
    // but strictly-increasing offset sequence, so the prefix check is run over its dense projection
    // (the survivors are contiguous in delivery order); the no-acked-loss check confirms every
    // surviving offset is present.
    let (fs, before, _) = build_dirty_log(InMemoryFs::new());
    let (faulty, control) = FaultFs::new(fs);
    let mut log = Log::open(faulty, ManualClock::new(), small_config()).unwrap();
    control.fail_sync_dir_after(2);
    let _ = log.maybe_compact(&CompactionConfig::enabled());
    let faulty = log.into_filesystem();
    faulty.inner().simulate_power_loss();
    let recovered = Log::open(faulty.into_inner(), ManualClock::new(), small_config()).unwrap();

    // No acked record is lost: every survivor offset is present in the recovered read.
    let got = all_records(&recovered);
    let want = expected_survivors(&before);
    assert_eq!(got, want);
    // The recovered records form a valid (sparse) ordered set, and the loss report is empty (no
    // durable record was lost by the compaction reconciliation).
    assert!(
        recovered.loss_report().is_empty(),
        "compaction recovery emits no loss event"
    );

    // Run the pure checkers over the recovered set, projected to dense delivery order (offset i is
    // the i-th survivor), which is exactly the contiguous prefix a consumer observes after a gap
    // skip. The checkers must pass.
    let dense: Vec<OwnedRecord> = got
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut d = r.clone();
            d.offset = Offset::new(i as u64);
            d.seq = ironbus_core::types::Seq::new(i as u64);
            d
        })
        .collect();
    check_longest_valid_prefix(&dense).expect("I2 longest valid prefix holds");
    let acked: Vec<u64> = dense.iter().map(|r| r.offset.get()).collect();
    check_no_acked_loss(&dense, &acked).expect("I1 no acked loss holds");
}

// --- #846: build_compacted_chain's continuity guards, exercised WITH a real compacted segment
// mid-chain (the covered-span advance path), which every all-ordinary guard test misses.

/// The v2 compacted segment's covered end `(offset, seq)` — the span `build_compacted_chain`
/// advances the chain expectation by across a compacted entry (`next_base_offset = covered_end`),
/// the load-bearing difference from the v1 dense-record-count advance.
fn compacted_covered_end(fs: &InMemoryFs, compacted_id: u64) -> (u64, u64) {
    let reader = SegmentReader::open(fs.open(&segment_file_name(compacted_id)).unwrap()).unwrap();
    let scan = reader
        .scan_compacted()
        .unwrap()
        .expect("the committed compacted segment scans");
    (scan.meta.covered_end_offset, scan.meta.covered_end_seq)
}

/// The decoded header of segment `id`.
fn header_of(fs: &InMemoryFs, id: u64) -> SegmentHeader {
    *SegmentReader::open(fs.open(&segment_file_name(id)).unwrap())
        .unwrap()
        .header()
}

/// Builds a durable log whose offset-ordered segment layout is exactly
/// `[compacted][sealed-ordinary][active-ordinary]`: a real v2 compacted segment (covering the
/// dense original prefix at its ORIGINAL sparse offsets), followed by a NON-final SEALED ordinary
/// segment, then the unsealed active tail. This is the mixed ordinary+compacted, offset-sorted
/// chain [`Log::build_compacted_chain`] reconciles — the shape the all-ordinary guard tests
/// (`corruption_corpus`, the inline `rejects_*` cases) never reach, because they route through the
/// v1 [`Log::recover`] scan instead. Returns the disk, the compacted segment id, and the id of the
/// mid sealed ordinary segment (the one directly succeeding the compacted entry in offset order).
fn compacted_then_sealed_then_active() -> (InMemoryFs, u64, u64) {
    let (fs, _before, _want, compacted_id) = fully_compacted_sole_copy();
    // Fully compacted, the sole ordinary is the active (highest-range) tail. Append keyless records
    // (each a guaranteed survivor) until that tail SEALS and rolls to a fresh active segment, so a
    // sealed ordinary now sits BETWEEN the compacted segment and the new active tail.
    let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    for _ in 0..4 {
        put(&mut log, b"", b"tail");
    }
    let fs = log.into_filesystem();
    let (covered_end_offset, _) = compacted_covered_end(&fs, compacted_id);
    // The mid entry is the sealed ordinary whose base_offset stitches onto the compacted covered
    // end; the active tail is the unsealed ordinary with the highest base_offset above it.
    let mut sealed_mid: Option<u64> = None;
    let mut has_active_above = false;
    for id in segment_ids(&fs).unwrap() {
        let reader = SegmentReader::open(fs.open(&segment_file_name(id)).unwrap()).unwrap();
        if reader.header().is_compacted() {
            continue;
        }
        let scan = reader.scan_recovery().unwrap();
        let base = scan.header.base_offset.get();
        if scan.footer.is_some() && base == covered_end_offset {
            sealed_mid = Some(id);
        } else if scan.footer.is_none() && base > covered_end_offset {
            has_active_above = true;
        }
    }
    let mid = sealed_mid.expect("a sealed ordinary directly succeeds the compacted segment");
    assert!(
        has_active_above,
        "an unsealed active tail sits above the mid sealed ordinary, so mid is NON-final"
    );
    (fs, compacted_id, mid)
}

/// #846 part 1 (`SegmentChainBroken` across a compacted segment). The offset-ordered chain is
/// `[compacted][sealed-ordinary][active]`; header-surgery the mid sealed ordinary's `base_offset`
/// to be one SHORT of the compacted segment's `covered_end_offset`, planting a one-offset hole
/// right at the compacted->ordinary boundary. `Log::open` must fail
/// [`StorageError::SegmentChainBroken`], and the diagnostic must name the mid segment with
/// `expected_base_offset` = the compacted covered end (the covered-span advance, NOT the survivor
/// count) and `found_base_offset` = the planted short value. The sequence expectation is untouched,
/// so `expected_base_seq == found_base_seq` isolates the failure to the offset arithmetic.
///
/// Discriminating: the base-gap guard at the covered->ordinary boundary is the ONLY thing that
/// rejects this disk; with the guard removed the hole is silently stitched into the durable offset
/// order (I5). A positive control (the same builder, untampered) proves the layout otherwise
/// recovers cleanly, so the failure is the planted gap and nothing else.
#[test]
fn rejects_a_base_gap_at_the_compacted_to_ordinary_boundary() {
    // Positive control: the untampered [compacted][sealed][active] chain recovers cleanly.
    let (clean_fs, _cid, _mid) = compacted_then_sealed_then_active();
    Log::open(clean_fs, ManualClock::new(), small_config())
        .expect("the untampered mixed chain recovers");

    let (fs, compacted_id, mid) = compacted_then_sealed_then_active();
    let (covered_end_offset, covered_end_seq) = compacted_covered_end(&fs, compacted_id);
    let mid_hdr = header_of(&fs, mid);
    assert_eq!(
        mid_hdr.base_offset.get(),
        covered_end_offset,
        "the untampered mid ordinary stitches onto the compacted covered end"
    );
    assert_eq!(mid_hdr.base_seq.get(), covered_end_seq);

    // Plant the gap: rewrite the mid segment header with base_offset one SHORT of the covered end
    // (its record_count keeps its end above the covered end, so it is NOT superseded by step 2).
    // The re-encode recomputes the header CRC, so it decodes clean — a pure continuity gap.
    let short = covered_end_offset - 1;
    let tampered = SegmentHeader {
        base_offset: Offset::new(short),
        ..mid_hdr
    };
    let file = fs.open(&segment_file_name(mid)).unwrap();
    file.write_all_at(&tampered.encode(), 0).unwrap();
    file.sync_all().unwrap();
    fs.sync_dir().unwrap();

    let err = Log::open(fs, ManualClock::new(), small_config())
        .expect_err("a base gap at the compacted->ordinary boundary must fail SegmentChainBroken");
    match err {
        ironbus_storage::segment::StorageError::SegmentChainBroken {
            segment_id,
            expected_base_offset,
            found_base_offset,
            expected_base_seq,
            found_base_seq,
        } => {
            assert_eq!(segment_id, mid, "the diagnostic names the gapping segment");
            assert_eq!(
                expected_base_offset, covered_end_offset,
                "expectation advances by the compacted COVERED span, not the survivor count"
            );
            assert_eq!(
                found_base_offset, short,
                "the planted one-short base offset"
            );
            assert_eq!(
                expected_base_seq, found_base_seq,
                "the seq expectation is intact; the break is purely the offset gap"
            );
        }
        other => panic!("expected SegmentChainBroken, got {other:?}"),
    }
}

/// #846 part 2 (`UnsealedPredecessor` across a compacted segment). The offset-ordered chain is
/// `[compacted][sealed-ordinary][active]`; corrupt the mid sealed ordinary's footer CRC so it scans
/// as UNSEALED while the active tail above it remains the highest-range entry. A NON-final unsealed
/// ordinary would leave two segments simultaneously appendable, so `Log::open` must fail
/// [`StorageError::UnsealedPredecessor`] naming the mid segment.
///
/// Discriminating: the mid-chain unsealed guard is the only rejection; with it removed the log
/// boots with a non-final unsealed segment. A positive control (untampered) proves the sealed mid
/// segment recovers cleanly, so the failure is the un-seal and nothing else.
#[test]
fn rejects_an_unsealed_non_final_ordinary_after_a_compacted_segment() {
    // Positive control: the untampered chain (mid SEALED) recovers cleanly.
    let (clean_fs, _cid, _mid) = compacted_then_sealed_then_active();
    Log::open(clean_fs, ManualClock::new(), small_config())
        .expect("the untampered mixed chain recovers");

    let (fs, _compacted_id, mid) = compacted_then_sealed_then_active();

    // Un-seal the mid ordinary: flip a byte in its trailing footer so `SegmentFooter::decode` fails
    // its CRC. `scan_recovery` then finds no valid footer (`footer: None`) and reports the segment
    // UNSEALED, its records recovered as the torn-free prefix. The header (hence base_offset) is
    // untouched, so continuity still stitches and the UNSEALED guard — not the base-gap guard — is
    // what fires.
    let file = fs.open(&segment_file_name(mid)).unwrap();
    let len = file.len().unwrap();
    let mut b = [0u8; 1];
    file.read_exact_at(&mut b, len - 1).unwrap();
    b[0] ^= 0xFF;
    file.write_all_at(&b, len - 1).unwrap();
    file.sync_all().unwrap();
    fs.sync_dir().unwrap();

    let err = Log::open(fs, ManualClock::new(), small_config())
        .expect_err("a non-final unsealed ordinary after a compacted segment must fail closed");
    match err {
        ironbus_storage::segment::StorageError::UnsealedPredecessor { segment_id } => {
            assert_eq!(
                segment_id, mid,
                "the diagnostic names the unsealed non-final ordinary"
            );
        }
        other => panic!("expected UnsealedPredecessor, got {other:?}"),
    }
}
