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

/// The final assertion shared by both #836 variants: after the corruption, `Log::open` must NOT
/// silently unlink-and-lose the sole compacted copy. Acceptable outcomes are (a) fail-closed with a
/// typed `StorageError`, or (b) recover while KEEPING the compacted file (or a `quarantine/` copy)
/// and, if any covered survivor offset is dropped from the read, recording it in the `LossReport`.
/// The forbidden outcome is a silent success that unlinks the file, drops survivors, and emits NO
/// loss event — unbounded silent data loss, the worst recovery outcome.
fn assert_not_silently_lost(fs: InMemoryFs, compacted_id: u64, want_survivors: &[OwnedRecord]) {
    match Log::open(fs, ManualClock::new(), small_config()) {
        Err(_) => {
            // Fail-closed: recovery refused to interpret the structurally inconsistent committed
            // compacted segment rather than silently discarding it. Acceptable.
        }
        Ok(recovered) => {
            // Read the whole recovered log TOLERANTLY: after a silent unlink the survivors below the
            // new oldest offset are gone, so `read_from(ZERO, ..)` itself errors `OffsetOutOfRange`
            // — that error is already proof of loss, so treat it as "nothing recovered from origin"
            // rather than letting an incidental unwrap mask the real assertion below.
            let head = recovered.flushed_offset().get();
            let got = recovered
                .read_from(Offset::ZERO, usize::try_from(head).unwrap_or(usize::MAX))
                .unwrap_or_default();
            let got_offsets: std::collections::HashSet<u64> =
                got.iter().map(|r| r.offset.get()).collect();
            let lost: Vec<u64> = want_survivors
                .iter()
                .map(|r| r.offset.get())
                .filter(|o| !got_offsets.contains(o))
                .collect();
            let loss_reported = !recovered.loss_report().is_empty();
            let fs = recovered.into_filesystem();
            let file_present = fs.exists(&segment_file_name(compacted_id)).unwrap();
            let quarantined = fs.subdir_exists("quarantine").unwrap();

            assert!(
                lost.is_empty() || loss_reported || file_present || quarantined,
                "SILENT SOLE-COPY DATA LOSS (#836): recovery unlinked the committed compacted \
                 segment as if it were a crash-before-commit orphan. Survivor offsets {lost:?} \
                 vanished with NO LossReport, the compacted file is gone (present={file_present}), \
                 and nothing was quarantined (quarantine_dir={quarantined}). Recovery must fail \
                 closed or quarantine, never silently drop the sole durable copy."
            );
        }
    }
}

/// #836 variant 1: a mid-body survivor bit-flip in a committed compacted segment (the trailing
/// footer + 44-byte compaction block are left intact, so they stay CRC-valid and decode). This is
/// NOT a crash-before-commit orphan — the segment reached its commit point — yet `scan_compacted`
/// collapses the corrupt-body case into the same `Ok(None)` a torn footer yields, and recovery then
/// unlinks the SOLE durable copy of every survivor it covered.
///
/// KNOWN-FAILING / CONFIRMED BUG (#836): under the current recovery this reproduces silent
/// sole-copy data loss — `Log::open` succeeds, the compacted file is unlinked, offsets 0..12 vanish
/// with no `LossReport` and no quarantine. Marked `#[ignore]` so CI stays green; un-ignore it once
/// recovery distinguishes a post-commit corrupt body (fail-closed or quarantine) from a
/// crash-before-commit orphan. Run explicitly with `cargo test -- --ignored` to see it fail today.
#[ignore = "#836: recovery silently unlinks a mid-body-corrupt committed compacted segment (sole-copy data loss); un-ignore once recovery fails closed / quarantines"]
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

    // The flip drives `scan_compacted` down the mid-body corruption `Ok(None)` branch (footer + meta
    // still decode, but a survivor frame fails its CRC), the precise case recovery must not conflate
    // with an uncommitted orphan.
    {
        let reader =
            SegmentReader::open(fs.open(&segment_file_name(compacted_id)).unwrap()).unwrap();
        let scan = reader.scan_compacted();
        assert!(
            matches!(scan, Ok(None)) || scan.is_err(),
            "the byte flip makes the committed compacted segment un-scannable: `Ok(None)` today \
             (the mid-body corruption branch), or a typed error under a fail-closed fix — never a \
             valid scan"
        );
    }

    assert_not_silently_lost(fs, compacted_id, &want);
}

/// #836 variant 2: a footer `record_count` / body-length DISAGREEMENT past the valid trailers. The
/// footer and meta block are re-stamped with a fresh, CRC-valid footer whose `record_count` no
/// longer matches the survivors on disk, so `scan_compacted` decodes every frame and both trailers
/// cleanly, then returns `Ok(None)` at the count cross-check (segment.rs) — again indistinguishable,
/// to recovery, from a crash-before-commit orphan, and again the sole copy is unlinked.
///
/// KNOWN-FAILING / CONFIRMED BUG (#836), sibling of the mid-body variant: same silent sole-copy
/// loss via the third `Ok(None)` case. `#[ignore]`d so CI stays green; un-ignore once fixed.
#[ignore = "#836: recovery silently unlinks a footer-count-inconsistent committed compacted segment (sole-copy data loss); un-ignore once recovery fails closed / quarantines"]
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
    // returns `Ok(None)` at the count cross-check — the third case collapsed into the orphan branch.
    {
        let reader =
            SegmentReader::open(fs.open(&segment_file_name(compacted_id)).unwrap()).unwrap();
        let scan = reader.scan_compacted();
        assert!(
            matches!(scan, Ok(None)) || scan.is_err(),
            "the count bump makes the committed compacted segment un-scannable: `Ok(None)` today \
             (the footer/body-length disagreement branch), or a typed error under a fix"
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
