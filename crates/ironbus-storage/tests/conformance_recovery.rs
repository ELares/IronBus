// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cross-crate wiring of the #45 conformance corpus into the REAL recovery path.
//!
//! The conformance corpus lives in `ironbus-core` (its fixtures are pure byte vectors with no
//! IO). Its segment fixtures declare a recovery verdict, a loss tuple `(reason, start, end)`,
//! that only the storage recovery path can actually produce. This test loads the SAME checked-in
//! corpus bytes (`crates/ironbus-core/tests/corpus/*.bin`) onto an in-memory durable disk and
//! drives them through `Log::open`, asserting recovery emits exactly the loss reason and span the
//! corpus claims. So the corpus is not only a decode-level gate (in core) but a recovery-level
//! gate (here): a format or recovery change that altered the verdict fails in one crate or the
//! other.
//!
//! The corpus segment fixtures are built under a fixed header (`segment_id` = 7, `base_seq` =
//! 100, `base_offset` = 4096), the reaped-prefix shape recovery explicitly tolerates (a non-zero
//! start, documented in `docs/COMPATIBILITY.md`). The recovered offsets therefore start at 4096.

use std::path::PathBuf;

use ironbus_core::clock::ManualClock;
use ironbus_core::types::Offset;
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Log, LogConfig};
use ironbus_storage::loss::ReasonCode;
use ironbus_storage::naming::segment_file_name;

/// The fixed segment id the core corpus builds its segment fixtures under (must match
/// `corpus_segment_header().segment_id` in `ironbus-core/tests/conformance/mod.rs`).
const CORPUS_SEGMENT_ID: u64 = 7;
/// The fixed base offset of the corpus segment header (recovery assigns offsets from here).
const CORPUS_BASE_OFFSET: u64 = 4096;

/// Reads a checked-in corpus fixture's raw bytes by name. The corpus lives in the sibling
/// `ironbus-core` crate; this test reaches across the workspace to read the SAME bytes the core
/// gate froze, so both crates assert against one source of truth.
fn corpus_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("ironbus-core")
        .join("tests")
        .join("corpus")
        .join(format!("{name}.bin"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read corpus fixture {}: {e}", path.display()))
}

/// A large segment cap so a single corpus segment holds the workload without rolling, and the
/// byte offsets stay predictable.
fn big_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 1 << 30,
        max_total_bytes: 0,
        ..LogConfig::default()
    }
}

/// Loads `bytes` as the corpus segment (id 7) onto a fresh durable in-memory disk, so recovery
/// sees exactly those bytes.
fn disk_with_corpus_segment(bytes: &[u8]) -> InMemoryFs {
    let fs = InMemoryFs::new();
    let file = fs
        .create_new(&segment_file_name(CORPUS_SEGMENT_ID))
        .expect("create corpus segment file");
    file.write_all_at(bytes, 0).expect("write corpus bytes");
    file.sync_all().expect("sync corpus file");
    fs.sync_dir().expect("sync dir");
    fs
}

/// Opens the corpus segment through real recovery and returns the recovered record count, the
/// single loss event (if any), and the live segment length after recovery truncated any torn
/// tail.
struct Recovered {
    record_count: usize,
    loss: Option<ironbus_storage::loss::LossEvent>,
    seg_len: u64,
}

fn recover(bytes: &[u8]) -> Recovered {
    let log = Log::open(
        disk_with_corpus_segment(bytes),
        ManualClock::new(),
        big_config(),
    )
    .expect("corpus segment recovers without a fail-closed error");
    let records = log
        .read_from(Offset::new(CORPUS_BASE_OFFSET), usize::MAX)
        .expect("read recovered records");
    let report = log.loss_report().clone();
    assert!(
        report.events.len() <= 1,
        "corpus fixtures produce at most one loss event"
    );
    let loss = report.events.first().copied();
    let seg_len = log
        .filesystem()
        .open(&segment_file_name(CORPUS_SEGMENT_ID))
        .expect("open recovered segment")
        .len()
        .expect("segment length");
    Recovered {
        record_count: records.len(),
        loss,
        seg_len,
    }
}

#[test]
fn active_no_footer_recovers_all_three_records_cleanly() {
    // The intact active segment: all three records survive, no loss.
    let rec = recover(&corpus_bytes("segment_active_no_footer"));
    assert_eq!(rec.record_count, 3, "all three records recovered");
    assert!(rec.loss.is_none(), "a clean active segment reports no loss");
}

#[test]
fn sealed_with_footer_recovers_all_three_records_cleanly() {
    // The sealed segment: all three records survive, the footer is trusted, no loss.
    let rec = recover(&corpus_bytes("segment_sealed_with_footer"));
    assert_eq!(
        rec.record_count, 3,
        "all three records recovered from the sealed segment"
    );
    assert!(rec.loss.is_none(), "a clean sealed segment reports no loss");
}

#[test]
fn torn_tail_mid_body_matches_the_corpus_loss_tuple() {
    // The third record's body is truncated: recovery keeps the first two and reports a TornTail
    // over the partial third frame, truncating to the second record's end. The loss START is the
    // third record's frame start (the value the corpus fixture's TornTruncate verdict declares).
    let bytes = corpus_bytes("segment_torn_tail_mid_body");
    let rec = recover(&bytes);
    assert_eq!(
        rec.record_count, 2,
        "two whole records survive the torn third"
    );
    let loss = rec.loss.expect("a torn tail reports one loss event");
    assert_eq!(loss.reason_code, ReasonCode::TornTail, "torn-tail reason");
    assert_eq!(loss.segment_id, CORPUS_SEGMENT_ID);
    assert_eq!(
        loss.byte_offset_end,
        bytes.len() as u64,
        "loss ends at the file end"
    );
    // Recovery truncated the live segment to the loss start, never reading past the torn tail.
    assert_eq!(
        rec.seg_len, loss.byte_offset_start,
        "truncated to the torn head"
    );
}

#[test]
fn torn_tail_mid_trailer_matches_the_corpus_loss_tuple() {
    // The third record's trailer is partially written: still a TornTail, truncated to the second
    // record's end.
    let bytes = corpus_bytes("segment_torn_tail_mid_trailer");
    let rec = recover(&bytes);
    assert_eq!(
        rec.record_count, 2,
        "two whole records survive the torn trailer"
    );
    let loss = rec.loss.expect("a torn trailer reports one loss event");
    assert_eq!(loss.reason_code, ReasonCode::TornTail, "torn-tail reason");
    assert_eq!(
        loss.byte_offset_end,
        bytes.len() as u64,
        "loss ends at the file end"
    );
    assert_eq!(
        rec.seg_len, loss.byte_offset_start,
        "truncated to the torn head"
    );
}

#[test]
fn mid_log_bit_flip_skips_and_reports_corrupt_body() {
    // A body byte of the SECOND record is flipped: the first survives, recovery stops at the
    // second frame and reports CorruptRecordBody from there (the corpus SkipAndReport verdict).
    // The reported end is BOUNDED at one past the tail's last NON-ZERO byte (the zero-tail rule
    // a preallocated logical extension requires): this frozen fixture's discarded tail happens
    // to end in zero bytes, so the span excludes exactly those informationless zeros — it may
    // never extend to a (possibly roll-size) file end.
    let bytes = corpus_bytes("segment_mid_log_bit_flip");
    let rec = recover(&bytes);
    assert_eq!(
        rec.record_count, 1,
        "only the first record survives the mid-log flip"
    );
    let loss = rec.loss.expect("a mid-log flip reports one loss event");
    assert_eq!(
        loss.reason_code,
        ReasonCode::CorruptRecordBody,
        "corrupt-body reason"
    );
    let last_nonzero_end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i as u64 + 1);
    assert_eq!(
        loss.byte_offset_end, last_nonzero_end,
        "loss ends at one past the tail's last non-zero byte"
    );
    assert!(loss.byte_offset_end <= bytes.len() as u64);
    assert_eq!(
        rec.seg_len, loss.byte_offset_start,
        "truncated to the corrupt head"
    );
}

#[test]
fn zero_window_tail_recovers_no_records_and_truncates_silently() {
    // A valid header then an ALL-ZERO record region: exactly the shape a preallocated,
    // logically-extended active segment leaves when its records never landed (the corpus
    // UnwrittenZeroTailTruncate verdict). No record decodes (a zero word is never a valid
    // magic), and recovery truncates the unwritten span SILENTLY: it is provably never-written
    // space — no frame was ever written there, nothing was acked — so it is NOT a loss event
    // and nothing is quarantined. (Production preallocates every active segment to the roll
    // size, so reporting this span would claim up to a whole roll size of "loss" on every
    // boot and trip the I3 caps for bytes that never held data.)
    let bytes = corpus_bytes("segment_zero_window_tail");
    let rec = recover(&bytes);
    assert_eq!(rec.record_count, 0, "no record decodes from a zero window");
    assert!(
        rec.loss.is_none(),
        "an all-zero (unwritten) tail is not reported as loss"
    );
    // The live segment is truncated to the header end (no records landed past it).
    assert_eq!(
        rec.seg_len,
        ironbus_core::format::SEGMENT_HEADER_LEN as u64,
        "truncated to the record-region start"
    );
}
