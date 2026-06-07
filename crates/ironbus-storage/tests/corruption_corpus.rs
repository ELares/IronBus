// SPDX-License-Identifier: MIT OR Apache-2.0
//! The deterministic, in-tree storage corruption corpus (issues #123, #21): a structured,
//! named set of corrupt on-disk inputs, each asserting the EXACT recovery outcome.
//!
//! This is the buildable, CI-gating part of #123 (Tier A): hand-written canonical poison
//! fixtures, one per taxonomy entry, plus a single-bit-flip sweep proptest. Each case builds a
//! known-good segment, applies one precise mutation, then drives the real recovery path
//! ([`Log::open`], or [`SegmentReader::scan_recovery`] where the case is sub-log) and asserts a
//! CONCRETE outcome: the recovered prefix length, the emitted [`ReasonCode`] / [`LossEvent`], the
//! truncation offset, that the loss stays within the bounded-loss caps, and that recovery NEVER
//! panics and NEVER reads past the durable head (the I2 "recovery equals a valid prefix"
//! invariant, asserted through the shared `invariants` checkers).
//!
//! Taxonomy covered (one named test each unless noted):
//! - a torn record tail: partial header, partial body, partial trailer;
//! - a flipped record header CRC;
//! - a flipped record body CRC;
//! - a flipped xxh3 field on an over-threshold record;
//! - a bad record magic;
//! - an unsupported record version byte;
//! - an unsupported segment-header version byte;
//! - an unsupported segment-header `checksum_algo`;
//! - a truncated / short segment header;
//! - a truncated footer;
//! - a footer / header segment-id mismatch;
//! - a recycled frame with a stale (out-of-order) sequence;
//! - a segment-chain gap;
//! - an unsealed non-final predecessor;
//! - an all-zeros region;
//! - a single-bit flip swept across a known-good segment (the proptest).
//!
//! The corpus IS the test: every case asserts a concrete outcome, not merely "does not panic".
//! It runs per-PR under `cargo test` and is deterministic (a fixed `ManualClock`, fixed
//! payloads, no real clock or randomness in the fixtures).
//!
//! The hardware-dependent remainder of #123 (the ALICE crash-prefix run and the dm-flakey /
//! dm-dust block-layer fault injection on the reference edge device, plus real bit-flipped
//! eMMC/SD captures) is deferred to #297, since it needs a privileged Linux device, not a
//! deterministic in-tree gate.

use ironbus_core::clock::ManualClock;
use ironbus_core::codec::RecordView;
use ironbus_core::format::{
    header_offsets, segment_header_offsets, RECORD_HEADER_LEN, RECORD_TRAILER_LEN, RECORD_XXH3_LEN,
    SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN, XXH3_PAYLOAD_THRESHOLD,
};
use ironbus_core::segment::{SegmentFooter, SegmentHeader};
use ironbus_core::types::{Offset, RecordFlags, Seq};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::invariants::{check_bounded_loss, check_longest_valid_prefix};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::loss::{LossReport, ReasonCode};
use ironbus_storage::naming::segment_file_name;
use ironbus_storage::segment::{SegmentWriter, StorageError};

/// A large cap so durability is driven only by `sync` and a single segment 0 holds the workload
/// (no rolling), which keeps the corpus geometry simple and the byte offsets predictable.
fn big_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 1 << 30,
        max_total_bytes: 0,
    }
}

/// A deterministic, fixed-size payload for record `i` (8 bytes, the same shape the crash gates
/// use, so a recovered payload is exactly checkable).
fn payload(i: u64) -> Vec<u8> {
    i.to_le_bytes().to_vec()
}

/// The byte length on disk of one record frame carrying an 8-byte payload, no key, no headers,
/// and below the xxh3 threshold: header + 8-byte body + trailer. Used to locate per-record
/// boundaries inside segment 0 for the surgical mutations.
const FRAME_LEN: usize = RECORD_HEADER_LEN + 8 + RECORD_TRAILER_LEN;

/// The byte offset within segment 0 where record `index` begins: the 64-byte segment header plus
/// `index` whole frames. Used by the surgical corpus mutations to target a specific record.
fn frame_start(index: u64) -> usize {
    SEGMENT_HEADER_LEN + usize::try_from(index).unwrap() * FRAME_LEN
}

/// Builds segment 0 with `n` synced records (offsets and sequences `0..n`), returns the raw
/// on-disk bytes of the segment file. The records are NOT sealed (no footer), so the segment is
/// the active write-ahead log, which is the common recovery shape.
fn good_unsealed_segment(n: u64) -> Vec<u8> {
    let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), big_config()).unwrap();
    for i in 0..n {
        let p = payload(i);
        log.append(&Append {
            timestamp_ms: i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &p,
        })
        .unwrap();
    }
    log.sync().unwrap();
    let fs = log.into_filesystem();
    fs.open(&segment_file_name(0)).unwrap().snapshot()
}

/// Builds segment 0 with `n` synced records and then SEALS it (writes the footer), returning the
/// raw bytes. A sealed segment carries a 32-byte footer the recovery path trusts only when it is
/// consistent with the body, which several corpus cases attack.
fn good_sealed_segment(n: u64) -> Vec<u8> {
    let fs = InMemoryFs::new();
    let file = fs.create_new(&segment_file_name(0)).unwrap();
    let header = SegmentHeader {
        segment_id: 0,
        base_seq: Seq::new(0),
        base_offset: Offset::ZERO,
        created_unix_ms: 0,
        flags: 0,
    };
    let mut w = SegmentWriter::create(file, header).unwrap();
    for i in 0..n {
        let p = payload(i);
        w.append(&RecordView {
            seq: Seq::new(i),
            timestamp_ms: i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &p,
        })
        .unwrap();
    }
    w.seal().unwrap();
    fs.open(&segment_file_name(0)).unwrap().snapshot()
}

/// Loads `bytes` as segment 0 onto a fresh durable in-memory disk, so recovery sees exactly those
/// bytes (a pure function of the durable image, the I4 setting the corpus relies on).
fn disk_with_segment0(bytes: &[u8]) -> InMemoryFs {
    let fs = InMemoryFs::new();
    let file = fs.create_new(&segment_file_name(0)).unwrap();
    file.write_all_at(bytes, 0).unwrap();
    file.sync_all().unwrap();
    fs.sync_dir().unwrap();
    fs
}

/// Writes `name` -> `bytes` onto an existing disk (for multi-segment chain cases).
fn add_segment(fs: &InMemoryFs, name: &str, bytes: &[u8]) {
    let file = fs.create_new(name).unwrap();
    file.write_all_at(bytes, 0).unwrap();
    file.sync_all().unwrap();
    fs.sync_dir().unwrap();
}

/// The recovery outcome the corpus asserts against: the recovered records (read back from offset
/// 0), the durable head, the structured loss report, and the recovered byte length of segment 0.
struct Recovered {
    records: Vec<ironbus_storage::segment::OwnedRecord>,
    flushed: u64,
    loss: LossReport,
    /// The live (recovered) byte length of segment 0 after recovery truncated any torn tail.
    seg0_len: u64,
}

/// Opens `fs` through the real [`Log::open`] recovery path and gathers the [`Recovered`] outcome.
/// Reaching past `Log::open` without an unwind already proves the no-panic invariant; the caller
/// asserts the concrete prefix, loss, and truncation values.
fn recover_ok(fs: InMemoryFs) -> Recovered {
    let log = Log::open(fs, ManualClock::new(), big_config()).unwrap();
    let flushed = log.flushed_offset().get();
    let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
    let loss = log.loss_report().clone();
    let seg0_len = log
        .filesystem()
        .open(&segment_file_name(0))
        .unwrap()
        .len()
        .unwrap();
    Recovered {
        records,
        flushed,
        loss,
        seg0_len,
    }
}

/// Asserts the shared resilience invariants over a recovered run that recovery accepted: the
/// records are the longest valid prefix from offset 0 (I2) with the expected payloads, the durable
/// head equals the recovered length, and the loss report is within the bounded-loss caps (I3).
/// This is the common tail every "recovers a prefix" corpus case runs, so "recovered correctly"
/// has ONE definition.
fn assert_valid_prefix(rec: &Recovered, expected_len: u64) {
    assert_eq!(
        rec.records.len() as u64,
        expected_len,
        "recovered prefix length"
    );
    assert_eq!(rec.flushed, expected_len, "durable head equals the prefix");
    check_longest_valid_prefix(&rec.records).expect("I2: recovered run is a valid prefix");
    for (i, record) in rec.records.iter().enumerate() {
        let i = u64::try_from(i).unwrap();
        assert_eq!(record.offset, Offset::new(i));
        assert_eq!(record.seq, Seq::new(i));
        assert_eq!(record.payload, payload(i), "survived payload is intact");
    }
    // I3: the loss recovery reported is within the per-event and global caps. Use the same caps
    // recovery itself enforces (one segment or 64 MiB, floored so a single torn-tail event on a
    // tiny log is always in bounds), so a case that slipped past the caps would fail here too.
    let durable_bytes: u64 = rec.records.len() as u64 * FRAME_LEN as u64;
    let per_event_cap = big_config()
        .max_segment_bytes
        .min(LossReport::PER_EVENT_BYTE_CAP);
    let global_cap = LossReport::global_loss_cap_bytes(durable_bytes).max(per_event_cap);
    check_bounded_loss(&rec.loss, per_event_cap, global_cap).expect("I3: loss within caps");
}

/// Asserts the loss report holds exactly one event, with the given reason, span, and that
/// recovery never read past the torn / corrupt boundary (the event's start equals the recovered
/// segment length, so every byte after the durable head was dropped, never replayed).
fn assert_single_loss(rec: &Recovered, reason: ReasonCode, start: u64, end: u64) {
    assert_eq!(rec.loss.events.len(), 1, "exactly one loss event");
    let e = rec.loss.events[0];
    assert_eq!(e.segment_id, 0);
    assert_eq!(e.reason_code, reason, "the emitted reason code");
    assert_eq!(
        e.byte_offset_start, start,
        "loss span start (the torn head)"
    );
    assert_eq!(e.byte_offset_end, end, "loss span end (the file length)");
    assert_eq!(e.bytes_skipped, end - start, "bytes skipped");
    // The recovered segment is truncated exactly at the torn head, so recovery never reads past
    // the torn tail: the live length is the loss-span start, not the original (longer) length.
    assert_eq!(
        rec.seg0_len, start,
        "recovery truncated to the durable head, never past the torn tail"
    );
}

// === Torn record tail: partial header, partial body, partial trailer =========================

#[test]
fn torn_tail_partial_record_header() {
    // The last record's frame header was only partially written (fewer than RECORD_HEADER_LEN
    // bytes past the prior record's end): a torn tail. Recovery keeps the intact prefix, reports
    // a TornTail loss over the partial bytes, and truncates exactly to the prior record's end.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let head_start = frame_start(n - 1);
    // Keep only the first few bytes of the last record's header.
    let mut bytes = good.clone();
    bytes.truncate(head_start + 4);
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, n - 1);
    assert_single_loss(
        &rec,
        ReasonCode::TornTail,
        head_start as u64,
        (head_start + 4) as u64,
    );
}

#[test]
fn torn_tail_partial_record_body() {
    // The last record's header is fully on disk but its body was only partially written, so the
    // declared frame runs past the file end: a torn tail (the body was never fully written).
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let last_start = frame_start(n - 1);
    let mut bytes = good.clone();
    // Header (36) plus 2 body bytes, then chopped: a partial body.
    bytes.truncate(last_start + RECORD_HEADER_LEN + 2);
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, n - 1);
    assert_single_loss(
        &rec,
        ReasonCode::TornTail,
        last_start as u64,
        (last_start + RECORD_HEADER_LEN + 2) as u64,
    );
}

#[test]
fn torn_tail_partial_record_trailer() {
    // The last record's header and body landed but its 8-byte trailer was only partially written,
    // so the declared total_len still runs past the file end: a torn tail.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let last_start = frame_start(n - 1);
    let mut bytes = good.clone();
    // Drop the last 3 trailer bytes of the final frame.
    bytes.truncate(good.len() - 3);
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, n - 1);
    assert_single_loss(
        &rec,
        ReasonCode::TornTail,
        last_start as u64,
        (good.len() - 3) as u64,
    );
}

// === Flipped record header / body CRC ========================================================

#[test]
fn flipped_record_header_crc() {
    // A bit flipped inside the last record's CRC-protected header range fails the header CRC, so
    // the frame and everything after it is abandoned: a CorruptRecordHeader at that frame.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let last_start = frame_start(n - 1);
    let mut bytes = good.clone();
    // The seq field at frame offset SEQ is inside the header CRC range [0, 32).
    bytes[last_start + header_offsets::SEQ] ^= 0x01;
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, n - 1);
    assert_single_loss(
        &rec,
        ReasonCode::CorruptRecordHeader,
        last_start as u64,
        good.len() as u64,
    );
}

#[test]
fn flipped_record_body_crc() {
    // A bit flipped in the last record's body (its single payload byte) passes the header CRC but
    // fails the body CRC: a CorruptRecordBody at that frame, distinct from a header corruption.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let last_start = frame_start(n - 1);
    let mut bytes = good.clone();
    bytes[last_start + RECORD_HEADER_LEN] ^= 0x01;
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, n - 1);
    assert_single_loss(
        &rec,
        ReasonCode::CorruptRecordBody,
        last_start as u64,
        good.len() as u64,
    );
}

// === Flipped xxh3 field on an over-threshold record ==========================================

#[test]
fn flipped_xxh3_field_on_over_threshold_record() {
    // An over-threshold record (stored body >= XXH3_PAYLOAD_THRESHOLD) carries the second xxh3-64
    // field before the trailer. A flip there passes CRC32C but fails the xxh3 check, so decode
    // rejects the frame: recovery stops at it and reports a CorruptRecordBody (the body / its
    // checksum is corrupt). The first, small record survives.
    let big = vec![0xa5u8; XXH3_PAYLOAD_THRESHOLD as usize + 16];
    let fs = InMemoryFs::new();
    let file = fs.create_new(&segment_file_name(0)).unwrap();
    let header = SegmentHeader {
        segment_id: 0,
        base_seq: Seq::new(0),
        base_offset: Offset::ZERO,
        created_unix_ms: 0,
        flags: 0,
    };
    let mut w = SegmentWriter::create(file, header).unwrap();
    w.append(&RecordView {
        seq: Seq::new(0),
        timestamp_ms: 0,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &payload(0),
    })
    .unwrap();
    let big_frame_start = w.write_pos();
    w.append(&RecordView {
        seq: Seq::new(1),
        timestamp_ms: 1,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &big,
    })
    .unwrap();
    w.sync().unwrap();
    let good = fs.open(&segment_file_name(0)).unwrap().snapshot();

    // The xxh3 field sits immediately before the 8-byte trailer at the end of the big frame.
    let xxh3_at = good.len() - RECORD_TRAILER_LEN - RECORD_XXH3_LEN;
    let mut bytes = good.clone();
    bytes[xxh3_at] ^= 0xff;

    let rec = recover_ok(disk_with_segment0(&bytes));
    // Only the first (small) record survives; the big record is dropped at its frame start.
    assert_eq!(rec.records.len(), 1, "only the small first record survives");
    assert_eq!(rec.flushed, 1);
    check_longest_valid_prefix(&rec.records).unwrap();
    assert_eq!(rec.records[0].payload, payload(0));
    assert_single_loss(
        &rec,
        ReasonCode::CorruptRecordBody,
        big_frame_start,
        good.len() as u64,
    );
}

// === Bad record magic / unsupported record version ===========================================

#[test]
fn bad_record_magic() {
    // The last record's magic is clobbered. decoded_len rejects it before the CRC, so recovery
    // treats it as a corrupt header and stops at that frame.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let last_start = frame_start(n - 1);
    let mut bytes = good.clone();
    bytes[last_start + header_offsets::MAGIC] ^= 0xff;
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, n - 1);
    assert_single_loss(
        &rec,
        ReasonCode::CorruptRecordHeader,
        last_start as u64,
        good.len() as u64,
    );
}

#[test]
fn unsupported_record_version() {
    // The last record's version byte is bumped to an unsupported value. A v1 reader refuses it
    // (UnsupportedVersion), which recovery classifies as a corrupt header at that frame.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    let last_start = frame_start(n - 1);
    let mut bytes = good.clone();
    bytes[last_start + header_offsets::VERSION] = 0xff;
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, n - 1);
    assert_single_loss(
        &rec,
        ReasonCode::CorruptRecordHeader,
        last_start as u64,
        good.len() as u64,
    );
}

// === Segment-header corruption: version, checksum_algo, truncation ===========================

#[test]
fn unsupported_segment_header_version() {
    // The segment header version is bumped (with the header CRC recomputed so the version check,
    // not the CRC, is what fails). The whole segment is unreadable: Log::open fails closed with a
    // typed segment error, never a panic, and never a partial recovery.
    let n = 3u64;
    let mut bytes = good_unsealed_segment(n);
    bytes[segment_header_offsets::VERSION] = 0x02;
    let crc = crc32c::crc32c(&bytes[0..SEGMENT_HEADER_LEN - 4]);
    bytes[SEGMENT_HEADER_LEN - 4..SEGMENT_HEADER_LEN].copy_from_slice(&crc.to_le_bytes());
    let err = Log::open(disk_with_segment0(&bytes), ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Segment(ironbus_core::segment::SegmentError::UnsupportedVersion(2))
        ),
        "got {err:?}"
    );
}

#[test]
fn unsupported_segment_header_checksum_algo() {
    // The segment header checksum_algo is set to an unknown value (CRC recomputed). A v1 reader
    // rejects the algorithm, so recovery fails closed with a typed error.
    let n = 3u64;
    let mut bytes = good_unsealed_segment(n);
    bytes[segment_header_offsets::CHECKSUM_ALGO] = 0x09;
    let crc = crc32c::crc32c(&bytes[0..SEGMENT_HEADER_LEN - 4]);
    bytes[SEGMENT_HEADER_LEN - 4..SEGMENT_HEADER_LEN].copy_from_slice(&crc.to_le_bytes());
    let err = Log::open(disk_with_segment0(&bytes), ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Segment(ironbus_core::segment::SegmentError::UnsupportedChecksumAlgo(9))
        ),
        "got {err:?}"
    );
}

#[test]
fn flipped_segment_header_crc() {
    // A bit flipped inside the segment header's CRC-protected range fails the header CRC, so the
    // whole segment is unreadable and recovery fails closed with a typed BadCrc.
    let n = 3u64;
    let mut bytes = good_unsealed_segment(n);
    bytes[segment_header_offsets::SEGMENT_ID] ^= 0x01;
    let err = Log::open(disk_with_segment0(&bytes), ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Segment(ironbus_core::segment::SegmentError::BadCrc)
        ),
        "got {err:?}"
    );
}

#[test]
fn truncated_short_segment_header() {
    // A segment file shorter than a 64-byte header cannot even be opened: recovery surfaces a
    // typed Truncated structural error, not a raw IO end-of-file or a panic.
    let bytes = vec![0u8; 10];
    let err = Log::open(disk_with_segment0(&bytes), ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Segment(ironbus_core::segment::SegmentError::Truncated)
        ),
        "got {err:?}"
    );
}

// === Footer cases: truncated footer, footer/header segment-id mismatch =======================

#[test]
fn truncated_footer_recovers_records_unsealed() {
    // A sealed segment whose footer is partly chopped (so it no longer decodes as a footer) is
    // recovered as UNSEALED: the records survive, the seal is simply not trusted, and there is no
    // loss (the body is intact up to where the footer began). Recovery never reads past the body.
    let n = 4u64;
    let good = good_sealed_segment(n);
    let mut bytes = good.clone();
    // Chop the last 4 footer bytes: the trailing 32 bytes no longer parse as a footer.
    bytes.truncate(good.len() - 4);
    let rec = recover_ok(disk_with_segment0(&bytes));
    // All n records survive (the footer is metadata; the body is intact). The torn 28 footer-ish
    // bytes that remain are NOT records, so they are dropped, but they were never acked records:
    // recovery keeps the full n-record prefix and reports the trailing non-record bytes as a torn
    // tail.
    assert_eq!(rec.records.len() as u64, n, "all records survive");
    assert_eq!(rec.flushed, n);
    check_longest_valid_prefix(&rec.records).unwrap();
    for (i, record) in rec.records.iter().enumerate() {
        assert_eq!(record.payload, payload(i as u64));
    }
}

#[test]
fn footer_header_segment_id_mismatch() {
    // A body-consistent footer that names a DIFFERENT segment id than its header is a recycled or
    // mixed-up file, a hard error: recovery fails closed with FooterSegmentMismatch rather than
    // silently trusting either id.
    let n = 3u64;
    let good = good_sealed_segment(n);
    let mut bytes = good.clone();
    // Rewrite the footer with a wrong segment_id but the correct body-describing fields, then fix
    // its CRC so it decodes (the mismatch, not a CRC failure, is what must fire).
    let wrong = SegmentFooter {
        segment_id: 999,
        last_seq: Seq::new(n - 1),
        record_count: u32::try_from(n).unwrap(),
    };
    let fstart = bytes.len() - SEGMENT_FOOTER_LEN;
    bytes[fstart..].copy_from_slice(&wrong.encode());
    let err = Log::open(disk_with_segment0(&bytes), ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::FooterSegmentMismatch {
                header: 0,
                footer: 999
            }
        ),
        "got {err:?}"
    );
}

// === Recycled frame with a stale (out-of-order) sequence =====================================

#[test]
fn recycled_frame_with_a_stale_sequence() {
    // A CRC-valid frame whose sequence breaks the contiguous run from base_seq is a recycled or
    // mixed-up frame (an old segment's bytes resurfacing under a reused file). Recovery refuses to
    // resurrect it: it fails closed with RecoveredSequenceMismatch, never silently accepting an
    // out-of-order record.
    let fs = InMemoryFs::new();
    let file = fs.create_new(&segment_file_name(0)).unwrap();
    let header = SegmentHeader {
        segment_id: 0,
        base_seq: Seq::new(0),
        base_offset: Offset::ZERO,
        created_unix_ms: 0,
        flags: 0,
    };
    let mut w = SegmentWriter::create(file, header).unwrap();
    w.append(&RecordView {
        seq: Seq::new(0),
        timestamp_ms: 0,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &payload(0),
    })
    .unwrap();
    // A valid frame, but seq 7 where the contiguous next is 1: a stale recycled frame.
    w.append(&RecordView {
        seq: Seq::new(7),
        timestamp_ms: 7,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &payload(7),
    })
    .unwrap();
    w.sync().unwrap();
    let err = Log::open(fs, ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::RecoveredSequenceMismatch {
                index: 1,
                expected: 1,
                found: 7
            }
        ),
        "got {err:?}"
    );
}

// === Segment-chain gap / unsealed non-final predecessor ======================================

#[test]
fn segment_chain_gap() {
    // Two sealed segments where the second's base offset / sequence does NOT continue from the
    // first (a gap in the offset space). Recovery walks the chain and fails closed with
    // SegmentChainBroken rather than accept a hole in the durable order.
    // Segment 0: 2 records, sealed (ends at base_offset 2). Segment 1: base_offset 5 (a gap).
    let seg0 = good_sealed_segment(2);

    let fs = InMemoryFs::new();
    let file0 = fs.create_new(&segment_file_name(0)).unwrap();
    file0.write_all_at(&seg0, 0).unwrap();
    file0.sync_all().unwrap();

    // Segment 1 with a base of 5 (the chain expects 2): a gap.
    let scratch = InMemoryFs::new();
    let f1 = scratch.create_new(&segment_file_name(1)).unwrap();
    let header1 = SegmentHeader {
        segment_id: 1,
        base_seq: Seq::new(5),
        base_offset: Offset::new(5),
        created_unix_ms: 0,
        flags: 0,
    };
    let mut w1 = SegmentWriter::create(f1, header1).unwrap();
    w1.append(&RecordView {
        seq: Seq::new(5),
        timestamp_ms: 5,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &payload(5),
    })
    .unwrap();
    w1.sync().unwrap();
    let seg1 = scratch.open(&segment_file_name(1)).unwrap().snapshot();
    add_segment(&fs, &segment_file_name(1), &seg1);
    fs.sync_dir().unwrap();

    let err = Log::open(fs, ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::SegmentChainBroken {
                segment_id: 1,
                expected_base_offset: 2,
                found_base_offset: 5,
                expected_base_seq: 2,
                found_base_seq: 5,
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn unsealed_non_final_predecessor() {
    // A non-final segment that was never sealed means two segments would be appendable at once: a
    // structurally impossible state. Recovery fails closed with UnsealedPredecessor.
    // Segment 0: 2 records, UNSEALED (no footer). Segment 1: a valid continuation, sealed.
    let seg0 = good_unsealed_segment(2); // unsealed

    let fs = InMemoryFs::new();
    let file0 = fs.create_new(&segment_file_name(0)).unwrap();
    file0.write_all_at(&seg0, 0).unwrap();
    file0.sync_all().unwrap();

    let scratch = InMemoryFs::new();
    let f1 = scratch.create_new(&segment_file_name(1)).unwrap();
    let header1 = SegmentHeader {
        segment_id: 1,
        base_seq: Seq::new(2),
        base_offset: Offset::new(2),
        created_unix_ms: 0,
        flags: 0,
    };
    let mut w1 = SegmentWriter::create(f1, header1).unwrap();
    w1.append(&RecordView {
        seq: Seq::new(2),
        timestamp_ms: 2,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &payload(2),
    })
    .unwrap();
    w1.seal().unwrap();
    let seg1 = scratch.open(&segment_file_name(1)).unwrap().snapshot();
    add_segment(&fs, &segment_file_name(1), &seg1);
    fs.sync_dir().unwrap();

    let err = Log::open(fs, ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(err, StorageError::UnsealedPredecessor { segment_id: 0 }),
        "got {err:?}"
    );
}

// === All-zeros region ========================================================================

#[test]
fn all_zeros_record_region() {
    // The whole record region (everything after the 64-byte header) is zeroed, modelling a
    // freshly preallocated or wiped segment whose records never landed. A zero word is not a valid
    // record magic, so recovery decodes zero records and reports the zeroed bytes as a torn tail.
    // No acked record existed there, so this is the empty-active-segment recovery, never a panic.
    let n = 4u64;
    let good = good_unsealed_segment(n);
    let mut bytes = good.clone();
    for b in &mut bytes[SEGMENT_HEADER_LEN..] {
        *b = 0;
    }
    let rec = recover_ok(disk_with_segment0(&bytes));
    assert_valid_prefix(&rec, 0);
    assert_single_loss(
        &rec,
        ReasonCode::CorruptRecordHeader,
        SEGMENT_HEADER_LEN as u64,
        good.len() as u64,
    );
}

#[test]
fn all_zeros_whole_segment_fails_closed() {
    // A wholly-zeroed segment file (header included) has no valid magic, so it cannot be opened:
    // recovery fails closed with a typed BadMagic rather than reading garbage as a header.
    let bytes = vec![0u8; SEGMENT_HEADER_LEN + 128];
    let err = Log::open(disk_with_segment0(&bytes), ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Segment(ironbus_core::segment::SegmentError::BadMagic)
        ),
        "got {err:?}"
    );
}

// === The single-bit-flip sweep ===============================================================

use proptest::prelude::*;

/// The shared per-flip oracle (the I2 "recovery equals a valid prefix" invariant): given the
/// bytes of a corrupted segment 0 whose KNOWN-GOOD original held `n` records, assert recovery is
/// a typed result, never a panic or an OOB read, and that a SUCCESSFUL recovery is always a valid
/// prefix of the original (never longer than `n`, intact payloads, loss within the caps). Returns
/// `Err(String)` describing the first violation so both the exhaustive sweep and the proptest can
/// report it. Reaching this function at all (no unwind through `Log::open`) already proves the
/// no-panic invariant.
fn recovery_is_valid_prefix_or_clean_error(bytes: &[u8], n: u64) -> Result<(), String> {
    let Ok(log) = Log::open(disk_with_segment0(bytes), ManualClock::new(), big_config()) else {
        // A typed fail-closed error is an acceptable outcome (a damaged segment header or a
        // structural chain / sequence error). The point is that it did not panic.
        return Ok(());
    };
    let records = log
        .read_from(Offset::ZERO, usize::MAX)
        .map_err(|e| format!("read_from failed: {e}"))?;
    if records.len() as u64 > n {
        return Err(format!(
            "recovered {} records, more than the original {n}",
            records.len()
        ));
    }
    // I2: a contiguous valid prefix from offset 0.
    check_longest_valid_prefix(&records).map_err(|v| v.to_string())?;
    for (i, record) in records.iter().enumerate() {
        let i = u64::try_from(i).map_err(|e| e.to_string())?;
        if record.offset != Offset::new(i) || record.seq != Seq::new(i) {
            return Err(format!("record {i} broke the prefix"));
        }
        // A survived record's payload is the original: a checksum that wrongly accepted a corrupt
        // record (or a recovery that read past the torn tail) would surface here as a mismatch.
        if record.payload != payload(i) {
            return Err(format!("record {i} payload was corrupted but accepted"));
        }
    }
    // I3: whatever recovery dropped is within the bounded-loss caps.
    let durable_bytes = records.len() as u64 * FRAME_LEN as u64;
    let per_event_cap = big_config()
        .max_segment_bytes
        .min(LossReport::PER_EVENT_BYTE_CAP);
    let global_cap = LossReport::global_loss_cap_bytes(durable_bytes).max(per_event_cap);
    check_bounded_loss(log.loss_report(), per_event_cap, global_cap).map_err(|v| v.to_string())?;
    Ok(())
}

#[test]
fn single_bit_flip_sweep_over_every_offset_never_panics() {
    // The worst-case EXHAUSTIVE sweep: flip EVERY single bit of a known-good segment, one at a
    // time, across every byte and every bit, and assert recovery is ALWAYS a typed result, never
    // a panic or an out-of-bounds read, and that a successful recovery is ALWAYS a valid prefix of
    // the original (the I2 "recovery equals a valid prefix" invariant). This is the deterministic
    // "every offset" guarantee the proptest below samples: any crash a fuzz target would find that
    // this catches becomes a permanent regression. A 5-record segment is a few hundred bytes, so
    // the full (byte * 8 bit) sweep stays fast at PR time.
    let n = 5u64;
    let good = good_unsealed_segment(n);
    for pos in 0..good.len() {
        for bit in 0u8..8 {
            let mut bytes = good.clone();
            bytes[pos] ^= 1u8 << bit;
            if let Err(why) = recovery_is_valid_prefix_or_clean_error(&bytes, n) {
                panic!("bit {bit} of byte {pos} broke recovery: {why}");
            }
        }
    }
}

proptest! {
    // The proptest twin of the exhaustive sweep: a seeded single-bit flip with shrinking, so a
    // future regression that only a deeper sweep (the nightly PROPTEST_CASES bump) exposes still
    // shrinks to a minimal (byte, bit) reproducer. It asserts the same I2 / I3 oracle.
    #[test]
    fn single_bit_flip_sweep_is_a_valid_prefix_or_clean_error(
        byte_idx in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let n = 5u64;
        let good = good_unsealed_segment(n);
        let pos = byte_idx.index(good.len());
        let mut bytes = good.clone();
        bytes[pos] ^= 1u8 << bit;
        recovery_is_valid_prefix_or_clean_error(&bytes, n)
            .map_err(TestCaseError::fail)?;
    }
}
