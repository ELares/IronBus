// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the forensic QUARANTINE store on the real recovery path (#134): a
//! corruption skip COPIES the corrupt bytes into `quarantine/` while recovery recovers the valid
//! prefix, the live log is unaffected, the cap is enforced, a clean torn tail is never quarantined,
//! and a quarantine WRITE FAILURE never fails `Log::open`.
//!
//! These drive the same `Log::open` recovery path the corruption corpus does, but assert the
//! ADDITIVE forensic copy on top: the corpus already pins that recovery recovers the right prefix
//! and reports the right loss, so here we focus on the quarantine blob, the cap, and the
//! never-blocks-recovery contract.

use ironbus_core::clock::ManualClock;
use ironbus_core::format::{RECORD_HEADER_LEN, RECORD_TRAILER_LEN, SEGMENT_HEADER_LEN};
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::fault::FaultFs;
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::loss::ReasonCode;
use ironbus_storage::naming::segment_file_name;
use ironbus_storage::quarantine::{blob_file_name, QUARANTINE_SUBDIR};

/// A large segment cap so a small workload stays in segment 0 with predictable byte offsets.
fn config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 1 << 30,
        max_total_bytes: 0,
        ..LogConfig::default()
    }
}

/// The on-disk length of one 8-byte-payload record frame (no key, no headers, below the xxh3
/// threshold): header + 8-byte body + trailer. Used to locate per-record boundaries.
const FRAME_LEN: usize = RECORD_HEADER_LEN + 8 + RECORD_TRAILER_LEN;

/// The byte offset within segment 0 where record `index` begins.
fn frame_start(index: u64) -> usize {
    SEGMENT_HEADER_LEN + usize::try_from(index).unwrap() * FRAME_LEN
}

fn payload(i: u64) -> Vec<u8> {
    i.to_le_bytes().to_vec()
}

/// Builds segment 0 with `n` synced (unsealed) records and returns its raw on-disk bytes.
fn good_unsealed_segment(n: u64) -> Vec<u8> {
    let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), config()).unwrap();
    for i in 0..n {
        log.append(&Append {
            timestamp_ms: i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload(i),
        })
        .unwrap();
    }
    log.sync().unwrap();
    log.into_filesystem()
        .open(&segment_file_name(0))
        .unwrap()
        .snapshot()
}

/// Lays `bytes` down as segment 0 on a fresh durable in-memory disk so recovery sees exactly them.
fn disk_with_segment0(bytes: &[u8]) -> InMemoryFs {
    let fs = InMemoryFs::new();
    let file = fs.create_new(&segment_file_name(0)).unwrap();
    file.write_all_at(bytes, 0).unwrap();
    file.sync_all().unwrap();
    fs.sync_dir().unwrap();
    fs
}

/// A segment-0 image whose LAST record's body CRC is flipped, so recovery recovers the first `n-1`
/// records and reports a `CorruptRecordBody` over the last frame (the corpus `flipped_record_body_crc`
/// case). Returns the bytes and the last frame's [start, end) span.
fn corrupt_body_segment(n: u64) -> (Vec<u8>, usize, usize) {
    let good = good_unsealed_segment(n);
    let last_start = frame_start(n - 1);
    let mut bytes = good.clone();
    // Flip a byte in the last record's payload: passes the header CRC, fails the body CRC.
    bytes[last_start + RECORD_HEADER_LEN] ^= 0x01;
    let end = bytes.len();
    (bytes, last_start, end)
}

#[test]
fn a_corrupt_segment_is_copied_to_quarantine_while_recovery_recovers_the_prefix() {
    let n = 5u64;
    let (bytes, corrupt_start, corrupt_end) = corrupt_body_segment(n);
    let fs = disk_with_segment0(&bytes);

    let log = Log::open(fs, ManualClock::new(), config()).unwrap();

    // Recovery recovered exactly the valid prefix (the first n-1 records), unchanged by quarantine.
    let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
    assert_eq!(records.len() as u64, n - 1, "valid prefix recovered");
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.payload, payload(i as u64));
    }
    // The loss report holds the one CorruptRecordBody event.
    assert_eq!(log.loss_report().events.len(), 1);
    assert_eq!(
        log.loss_report().events[0].reason_code,
        ReasonCode::CorruptRecordBody
    );

    // The quarantine accounting: exactly the corrupt span's bytes were captured.
    let span = (corrupt_end - corrupt_start) as u64;
    assert_eq!(
        log.quarantined_bytes(),
        span,
        "quarantined the corrupt span"
    );

    // The blob holds the corrupt bytes verbatim, and lives in the quarantine/ subdir (never scanned
    // as a live segment).
    let fs = log.into_filesystem();
    let qfs = fs.subdir(QUARANTINE_SUBDIR).unwrap();
    let blob_name = blob_file_name(
        0,
        ReasonCode::CorruptRecordBody,
        corrupt_start as u64,
        corrupt_end as u64,
    );
    let blob = qfs.open(&blob_name).unwrap();
    let mut got = vec![0u8; usize::try_from(span).unwrap()];
    blob.read_exact_at(&mut got, 0).unwrap();
    assert_eq!(
        got,
        bytes[corrupt_start..corrupt_end],
        "blob holds the corrupt bytes verbatim"
    );

    // The live segment was truncated to the durable head (copy-not-move: the corrupt bytes are gone
    // from the LIVE log but preserved in quarantine).
    let live_len = fs.open(&segment_file_name(0)).unwrap().len().unwrap();
    assert_eq!(
        live_len, corrupt_start as u64,
        "live segment truncated to the prefix"
    );

    // Recovery never scanned the quarantine blob as a live segment: the live directory lists only
    // the segment file, never the blob.
    assert_eq!(fs.list().unwrap(), vec![segment_file_name(0)]);
}

#[test]
fn a_clean_torn_tail_is_never_quarantined() {
    // A torn tail (the last frame's header is only partially written) is the expected power-loss
    // case, not corruption: recovery truncates it but quarantine captures nothing.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let head_start = frame_start(n - 1);
    let mut bytes = good.clone();
    bytes.truncate(head_start + 4); // a partial record header: a torn tail
    let fs = disk_with_segment0(&bytes);

    let log = Log::open(fs, ManualClock::new(), config()).unwrap();
    assert_eq!(
        log.read_from(Offset::ZERO, usize::MAX).unwrap().len() as u64,
        n - 1
    );
    assert_eq!(
        log.loss_report().events[0].reason_code,
        ReasonCode::TornTail
    );
    assert_eq!(log.quarantined_bytes(), 0, "a torn tail is not quarantined");
    // The quarantine subdir was never even materialized.
    assert!(!log
        .into_filesystem()
        .subdir_exists(QUARANTINE_SUBDIR)
        .unwrap());
}

#[test]
fn the_quarantine_cap_bounds_the_store() {
    // A cap smaller than the corrupt span means the span cannot fit: it is skipped (no blob), but
    // recovery still recovers the prefix unchanged.
    let n = 5u64;
    let (bytes, corrupt_start, corrupt_end) = corrupt_body_segment(n);
    let span = (corrupt_end - corrupt_start) as u64;
    let fs = disk_with_segment0(&bytes);

    // Cap one byte below the span: the single corrupt span cannot fit, so it is skipped.
    let cfg = config().with_max_quarantine_bytes(span - 1);
    let log = Log::open(fs, ManualClock::new(), cfg).unwrap();

    assert_eq!(
        log.read_from(Offset::ZERO, usize::MAX).unwrap().len() as u64,
        n - 1
    );
    assert_eq!(log.quarantined_bytes(), 0, "a span over the cap is skipped");
    // The cap exactly equal to the span DOES capture it (a separate open).
    let fs2 = disk_with_segment0(&bytes);
    let cfg2 = config().with_max_quarantine_bytes(span);
    let log2 = Log::open(fs2, ManualClock::new(), cfg2).unwrap();
    assert_eq!(
        log2.quarantined_bytes(),
        span,
        "a span equal to the cap fits"
    );
}

#[test]
fn a_quarantine_write_failure_does_not_fail_recovery() {
    // Inject a filesystem whose every write_all_at fails. The quarantine blob write then fails, but
    // recovery's own truncation (set_len + sync_all, not write_all_at) is unaffected, so Log::open
    // still succeeds and recovers the valid prefix. The quarantine is best-effort: it captured
    // nothing, but it never blocked recovery.
    let n = 5u64;
    let (bytes, _start, _end) = corrupt_body_segment(n);
    let inner = disk_with_segment0(&bytes);
    let (fs, control) = FaultFs::new(inner);

    // Arm write failure: the quarantine blob's write_all_at fails. (The live segment is already on
    // disk; recovery only truncates it, which is set_len + sync_all, not a write_all_at.)
    control.set_fail_write(true);

    let log = Log::open(fs, ManualClock::new(), config())
        .expect("open must not fail on a quarantine write error");
    let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
    assert_eq!(
        records.len() as u64,
        n - 1,
        "recovery recovered the prefix despite the quarantine failure"
    );
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.payload, payload(i as u64));
    }
    assert_eq!(
        log.loss_report().events[0].reason_code,
        ReasonCode::CorruptRecordBody
    );
    // The forensic copy failed best-effort, so nothing was captured, but the live log is correct.
    assert_eq!(
        log.quarantined_bytes(),
        0,
        "the failed quarantine captured nothing"
    );

    // The live segment was still truncated to the durable head (recovery's own path is independent).
    let fs = log.into_filesystem();
    let live_len = fs
        .inner()
        .open(&segment_file_name(0))
        .unwrap()
        .len()
        .unwrap();
    assert_eq!(
        live_len,
        frame_start(n - 1) as u64,
        "live segment truncated despite the quarantine failure"
    );
}

#[test]
fn the_gauge_reflects_the_persisted_quarantine_footprint_after_a_clean_reopen() {
    // The gauge is the PERSISTED on-disk footprint, surviving restart (#315). After a corruption
    // skip captured a blob, reopening the (now clean, truncated) log recovers cleanly with NO new
    // corruption, yet the gauge still reports the prior blob's bytes from a read-only scan-on-open,
    // so a tool reading ironbus_quarantine_bytes sees the real disk pressure the forensic copies
    // create rather than 0.
    let n = 5u64;
    let (bytes, corrupt_start, corrupt_end) = corrupt_body_segment(n);
    let span = (corrupt_end - corrupt_start) as u64;
    let fs = disk_with_segment0(&bytes);

    let log = Log::open(fs, ManualClock::new(), config()).unwrap();
    assert_eq!(
        log.quarantined_bytes(),
        span,
        "first open captured the span"
    );
    let fs = log.into_filesystem();

    // Reopen: the live segment is now clean (truncated), so recovery is clean and captures nothing
    // NEW, but the prior blob still occupies the quarantine store, so the gauge reflects it.
    let reopened = Log::open(fs, ManualClock::new(), config()).unwrap();
    assert!(
        reopened.loss_report().is_empty(),
        "the reopened log is clean"
    );
    assert_eq!(
        reopened.quarantined_bytes(),
        span,
        "the gauge reflects the PERSISTED footprint after a clean reopen (not 0)"
    );
    // The prior blob persists in the quarantine subdir.
    let fs = reopened.into_filesystem();
    let qfs = fs.subdir(QUARANTINE_SUBDIR).unwrap();
    let blobs: Vec<String> = qfs.list().unwrap();
    assert_eq!(
        blobs.len(),
        1,
        "the prior forensic blob persists across the reopen"
    );
}

#[test]
fn the_scan_on_open_never_materializes_the_quarantine_subdir_for_a_clean_log() {
    // The #315 scan-on-open must preserve the #134 contract that a clean log (no corruption skip,
    // ever) never creates the quarantine/ subdir: the read-only scan probes subdir_exists FIRST and
    // degrades to 0 without side effects. A pristine fresh log and a reopen of it both stay clean.
    let good = good_unsealed_segment(5);
    let fs = disk_with_segment0(&good);

    let log = Log::open(fs, ManualClock::new(), config()).unwrap();
    assert!(
        log.loss_report().is_empty(),
        "a good segment recovers clean"
    );
    assert_eq!(log.quarantined_bytes(), 0, "no blobs, so the gauge is 0");
    let fs = log.into_filesystem();
    assert!(
        !fs.subdir_exists(QUARANTINE_SUBDIR).unwrap(),
        "the clean open never materialized the quarantine subdir"
    );

    // A reopen of the still-clean log likewise leaves the subdir un-created.
    let reopened = Log::open(fs, ManualClock::new(), config()).unwrap();
    assert_eq!(reopened.quarantined_bytes(), 0);
    assert!(
        !reopened
            .into_filesystem()
            .subdir_exists(QUARANTINE_SUBDIR)
            .unwrap(),
        "the clean reopen never materialized the quarantine subdir"
    );
}
