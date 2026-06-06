// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crash-injection gates for the storage log (issues #21, #55).
//!
//! These make the resilience claims falsifiable: at every durability boundary, after a
//! power loss or after tail/arbitrary corruption, recovery must yield a consistent,
//! monotonic prefix with no acknowledged record lost and bounded, valid loss, and it
//! must never panic or hang. They run per-PR under `cargo test`.
//!
//! Crash classes covered here, over the in-memory disk model:
//! - power loss before fsync (every unsynced write may vanish), at every op boundary;
//! - a torn tail (the file truncated mid-record);
//! - tail corruption (the last record's bytes damaged);
//! - mid-log rot and arbitrary single-byte corruption anywhere in the segment.
//!
//! Block-layer fault injection (an fsync that returns EIO, page-cache reordering, a
//! both-slots-torn checkpoint) needs a fault-injecting file layer and is tracked
//! separately.

use ironbus_core::clock::ManualClock;
use ironbus_core::format::{RECORD_HEADER_LEN, SEGMENT_HEADER_LEN};
use ironbus_core::types::{Offset, RecordFlags, Seq};
use ironbus_storage::fault::{FaultControl, FaultFs};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::invariants::{
    check_longest_valid_prefix, check_no_acked_loss, check_pure_recovery,
};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::naming::segment_file_name;
use proptest::prelude::*;

/// A large cap so durability is driven only by `sync` (no rolling).
fn big_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 1 << 30,
    }
}

/// A small cap so a handful of records force rolling.
fn small_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 256,
    }
}

/// A deterministic, fixed-size payload for record `i`.
fn payload(i: u64) -> Vec<u8> {
    i.to_le_bytes().to_vec()
}

fn append_at<F: Filesystem>(log: &mut Log<F, ManualClock>, i: u64) {
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

#[derive(Clone, Copy, Debug)]
enum Op {
    Append,
    Sync,
}

/// Opens a fresh log on `fs` and applies `ops`, numbering appends from 0.
fn apply(fs: InMemoryFs, config: LogConfig, ops: &[Op]) -> Log<InMemoryFs, ManualClock> {
    let mut log = Log::open(fs, ManualClock::new(), config).unwrap();
    let mut next = 0u64;
    for op in ops {
        match op {
            Op::Append => {
                append_at(&mut log, next);
                next += 1;
            }
            Op::Sync => log.sync().unwrap(),
        }
    }
    log
}

/// Reopens the log and asserts the recovered records are exactly the durable prefix:
/// contiguous offsets and sequences from zero, correct payloads, length in
/// `[durable, appended]`. With the in-memory model power loss reverts to the durable
/// image exactly, so `recovered == durable`.
fn assert_recovers_durable_prefix(fs: InMemoryFs, config: LogConfig, durable: u64, appended: u64) {
    let log = Log::open(fs, ManualClock::new(), config).unwrap();
    let recovered = log.flushed_offset().get();
    assert!(
        recovered >= durable,
        "lost an acknowledged record: recovered {recovered} < durable {durable}"
    );
    assert!(
        recovered <= appended,
        "invented a record: recovered {recovered} > appended {appended}"
    );
    assert_eq!(recovered, durable, "in-memory power loss is exact");
    assert_prefix(&log, recovered);
}

/// Asserts the readable records are a contiguous, correctly-numbered prefix of length
/// `expected`.
fn assert_prefix<F: Filesystem>(log: &Log<F, ManualClock>, expected: u64) {
    let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
    assert_eq!(records.len() as u64, expected);
    for (i, record) in records.iter().enumerate() {
        let i = u64::try_from(i).unwrap();
        assert_eq!(record.offset, Offset::new(i));
        assert_eq!(record.seq, Seq::new(i));
        assert_eq!(record.payload, payload(i));
    }
}

/// The fixed workload replayed prefix-by-prefix in the every-boundary tests.
fn boundary_workload() -> Vec<Op> {
    use Op::{Append, Sync};
    vec![
        Append, Append, Append, Sync, Append, Append, Sync, Append, Sync, Append, Append, Append,
        Append, Sync, Append, Append,
    ]
}

#[test]
fn power_loss_at_every_boundary_no_roll() {
    let ops = boundary_workload();
    for k in 0..=ops.len() {
        let log = apply(InMemoryFs::new(), big_config(), &ops[..k]);
        let durable = log.flushed_offset().get();
        let appended = log.next_offset().get();
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();
        assert_recovers_durable_prefix(fs, big_config(), durable, appended);
    }
}

#[test]
fn power_loss_at_every_boundary_with_rolling() {
    let ops = boundary_workload();
    for k in 0..=ops.len() {
        let log = apply(InMemoryFs::new(), small_config(), &ops[..k]);
        let durable = log.flushed_offset().get();
        let appended = log.next_offset().get();
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();
        assert_recovers_durable_prefix(fs, small_config(), durable, appended);
    }
}

#[test]
fn last_record_corruption_drops_only_that_record() {
    // Append and sync N records (all durable), then damage the last record's bytes.
    // Recovery must drop exactly that record and keep the intact prefix.
    let n = 6u64;
    let ops: Vec<Op> = (0..n).map(|_| Op::Append).chain([Op::Sync]).collect();
    let log = apply(InMemoryFs::new(), big_config(), &ops);
    let fs = log.into_filesystem();

    let file = fs.open(&segment_file_name(0)).unwrap();
    let mut bytes = file.snapshot();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    file.set_len(0).unwrap();
    file.write_all_at(&bytes, 0).unwrap();
    file.sync_data().unwrap();

    let log = Log::open(fs, ManualClock::new(), big_config()).unwrap();
    assert_eq!(log.flushed_offset(), Offset::new(n - 1));
    assert_prefix(&log, n - 1);
}

#[test]
fn tail_truncation_drops_the_partial_record() {
    // A torn write that left only a prefix of the last record's bytes on disk.
    let n = 6u64;
    let ops: Vec<Op> = (0..n).map(|_| Op::Append).chain([Op::Sync]).collect();
    let log = apply(InMemoryFs::new(), big_config(), &ops);
    let fs = log.into_filesystem();

    let file = fs.open(&segment_file_name(0)).unwrap();
    let len = file.len().unwrap();
    file.set_len(len - 3).unwrap(); // chop a few bytes off the last record
    file.sync_data().unwrap();

    let log = Log::open(fs, ManualClock::new(), big_config()).unwrap();
    assert_eq!(log.flushed_offset(), Offset::new(n - 1));
    assert_prefix(&log, n - 1);
}

/// Flips the byte at `in_frame` bytes into record `k` of an n-record sealed segment,
/// then asserts recovery stops exactly before record k (its prefix kept).
fn assert_corruption_in_record_stops_before_it(n: u64, k: u64, in_frame: usize) {
    let ops: Vec<Op> = (0..n).map(|_| Op::Append).chain([Op::Sync]).collect();
    let log = apply(InMemoryFs::new(), big_config(), &ops);
    let fs = log.into_filesystem();

    let file = fs.open(&segment_file_name(0)).unwrap();
    let mut bytes = file.snapshot();
    let header = SEGMENT_HEADER_LEN;
    let frame = (bytes.len() - header) / usize::try_from(n).unwrap();
    let target = header + usize::try_from(k).unwrap() * frame + in_frame;
    bytes[target] ^= 0xff;
    file.set_len(0).unwrap();
    file.write_all_at(&bytes, 0).unwrap();
    file.sync_data().unwrap();

    let log = Log::open(fs, ManualClock::new(), big_config()).unwrap();
    assert_eq!(log.flushed_offset(), Offset::new(k));
    assert_prefix(&log, k);
}

#[test]
fn mid_log_header_corruption_stops_at_the_first_bad_record() {
    // A byte in record 3's frame header, exercising the record HEADER checksum.
    assert_corruption_in_record_stops_before_it(8, 3, RECORD_HEADER_LEN / 2);
}

#[test]
fn mid_log_body_corruption_stops_at_the_first_bad_record() {
    // A byte in record 3's payload, exercising the record BODY checksum (the header
    // checksum cannot see this byte, so it proves body-CRC verification runs).
    assert_corruption_in_record_stops_before_it(8, 3, RECORD_HEADER_LEN + 1);
}

#[test]
fn recovery_rejects_a_synthesized_sequence_gap() {
    // The harness must be able to falsify a broken sequence-contiguity guard itself, not
    // lean on a separate unit test: hand-build a segment whose second record skips a
    // sequence number and assert recovery rejects it.
    use ironbus_core::codec::RecordView;
    use ironbus_core::segment::SegmentHeader;
    use ironbus_storage::segment::{SegmentWriter, StorageError};

    let fs = InMemoryFs::new();
    let file = fs.create_new(&segment_file_name(0)).unwrap();
    let header = SegmentHeader {
        segment_id: 0,
        base_seq: Seq::new(0),
        base_offset: Offset::ZERO,
        created_unix_ms: 0,
        flags: 0,
    };
    let mut writer = SegmentWriter::create(file, header).unwrap();
    writer
        .append(&RecordView {
            seq: Seq::new(0),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"a",
        })
        .unwrap();
    writer
        .append(&RecordView {
            seq: Seq::new(5), // a gap: the contiguous next sequence is 1
            timestamp_ms: 5,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"b",
        })
        .unwrap();
    writer.sync().unwrap();
    drop(writer);

    let err = Log::open(fs, ManualClock::new(), big_config()).unwrap_err();
    assert!(matches!(
        err,
        StorageError::RecoveredSequenceMismatch {
            index: 1,
            expected: 1,
            found: 5
        }
    ));
}

#[test]
fn fatal_fsync_freeze_loses_no_acked_record() {
    // Block-layer fault, the fsyncgate EIO mode: a fatal fdatasync while the writer is live.
    // The acked prefix must survive the crash that accompanies the failed fsync; the unsynced
    // tail (its page-cache bytes) may vanish. No acknowledged record is lost.
    for durable in [1u64, 3, 5] {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), big_config()).unwrap();
        for i in 0..durable {
            append_at(&mut log, i);
        }
        log.sync().unwrap(); // these `durable` records are acked
        assert_eq!(log.flushed_offset(), Offset::new(durable));

        // An unsynced tail, then a fatal fsync: the sync freezes the writer read-only.
        append_at(&mut log, durable);
        append_at(&mut log, durable + 1);
        let appended = log.next_offset().get();
        control.set_fail_sync(true);
        assert!(matches!(
            log.sync(),
            Err(ironbus_storage::segment::StorageError::WriterFrozen)
        ));
        assert!(!log.is_writable(), "a fatal fsync freezes the writer");
        assert_eq!(
            log.flushed_offset(),
            Offset::new(durable),
            "the durable mark never advanced past the acked prefix"
        );

        // Model the crash: the unsynced page-cache bytes are lost. Reopen and assert the
        // acked prefix recovered exactly, monotone and intact.
        control.set_fail_sync(false);
        let faultfs = log.into_filesystem();
        faultfs.inner().simulate_power_loss();
        let log = Log::open(faultfs, ManualClock::new(), big_config()).unwrap();
        let recovered = log.flushed_offset().get();
        assert!(
            recovered >= durable,
            "lost an acknowledged record: recovered {recovered} < durable {durable}"
        );
        assert!(
            recovered <= appended,
            "invented a record beyond what was appended"
        );
        assert_eq!(
            recovered, durable,
            "the unsynced tail did not survive the crash"
        );
        assert_prefix(&log, durable);
    }
}

#[test]
fn fatal_fsync_freeze_during_a_roll_loses_no_acked_record() {
    // The freeze can also strike inside a segment roll, where the seal's sync_all (not an
    // explicit Log::sync) is the faulting fdatasync. The acked prefix written before the roll
    // must still survive the crash.
    let (fs, control) = FaultFs::new(InMemoryFs::new());
    let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
    // A durable prefix kept under the cap (no roll yet), each record acked.
    let durable = 4u64;
    for i in 0..durable {
        append_at(&mut log, i);
        log.sync().unwrap();
    }
    let acked = log.flushed_offset().get();
    assert_eq!(acked, durable, "the whole prefix is acked before any roll");

    // Arm the fault, then append (without syncing) until a roll fires: the seal's sync_all
    // faults and freezes the writer from inside the roll path, not an explicit sync.
    control.set_fail_sync(true);
    let mut froze = false;
    for i in durable..durable + 60 {
        match log.append(&Append {
            timestamp_ms: i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload(i),
        }) {
            Ok(_) => {}
            Err(ironbus_storage::segment::StorageError::WriterFrozen) => {
                froze = true;
                break;
            }
            Err(other) => panic!("a freezing roll must be fatal, got {other:?}"),
        }
    }
    assert!(froze, "a roll's seal fsync should have frozen the writer");
    assert!(!log.is_writable());
    assert_eq!(
        log.flushed_offset().get(),
        acked,
        "the durable mark never advanced past the acked prefix during the failed roll"
    );

    // Crash and reopen: the acked prefix (everything synced before the roll) survives, and
    // the recovered records are a valid, monotone prefix.
    control.set_fail_sync(false);
    let faultfs = log.into_filesystem();
    faultfs.inner().simulate_power_loss();
    let log = Log::open(faultfs, ManualClock::new(), small_config()).unwrap();
    let recovered = log.flushed_offset().get();
    // Exactly the acked prefix: the seal faulted before segment 1 was ever created, so no
    // uncommitted record can survive (no acked record lost, none invented). This mirrors the
    // tight assertion in the non-roll gate.
    assert_eq!(
        recovered, acked,
        "the roll freeze must recover exactly the acked prefix"
    );
    assert_prefix(&log, recovered);
}

#[test]
fn a_write_eio_during_append_recovers_the_acked_prefix() {
    // A write that fails cleanly (no bytes persisted) leaves the record unacked and the
    // writer consistent (a write fault, unlike a fatal fsync, does not freeze the writer).
    // Recovery yields exactly the acked prefix.
    let durable = 5u64;
    let (fs, control) = FaultFs::new(InMemoryFs::new());
    let mut log = Log::open(fs, ManualClock::new(), big_config()).unwrap();
    for i in 0..durable {
        append_at(&mut log, i);
    }
    log.sync().unwrap();

    control.set_fail_write(true);
    let p = payload(durable);
    let err = log.append(&Append {
        timestamp_ms: durable,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &p,
    });
    assert!(matches!(
        err,
        Err(ironbus_storage::segment::StorageError::Io(_))
    ));
    assert_eq!(
        log.next_offset(),
        Offset::new(durable),
        "a failed write does not advance the offset"
    );
    assert!(
        log.is_writable(),
        "a write fault does not freeze the writer"
    );

    control.set_fail_write(false);
    let faultfs = log.into_filesystem();
    let log = Log::open(faultfs, ManualClock::new(), big_config()).unwrap();
    assert_eq!(log.flushed_offset(), Offset::new(durable));
    assert_prefix(&log, durable);
}

#[test]
fn a_torn_write_during_append_is_truncated_by_recovery() {
    // A torn write persists a prefix of the record's bytes, then fails. The record is not
    // acked; recovery truncates the torn tail and yields exactly the intact acked prefix,
    // never reading past the torn bytes. No power loss: this exercises truncation of a real
    // torn write left in the live image, not an all-or-nothing revert.
    let durable = 5u64;
    let (fs, control) = FaultFs::new(InMemoryFs::new());
    let mut log = Log::open(fs, ManualClock::new(), big_config()).unwrap();
    for i in 0..durable {
        append_at(&mut log, i);
    }
    log.sync().unwrap();

    // Tear the next record a few bytes in (a partial record header on disk).
    control.arm_torn_write(4);
    let p = payload(durable);
    let err = log.append(&Append {
        timestamp_ms: durable,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &p,
    });
    assert!(matches!(
        err,
        Err(ironbus_storage::segment::StorageError::Io(_))
    ));
    assert_eq!(
        log.next_offset(),
        Offset::new(durable),
        "a torn write does not advance the offset"
    );

    let faultfs = log.into_filesystem();
    let log = Log::open(faultfs, ManualClock::new(), big_config()).unwrap();
    assert_eq!(log.flushed_offset(), Offset::new(durable));
    assert_prefix(&log, durable);
}

#[test]
fn recovery_is_idempotent_after_a_fault_during_recovery() {
    // Build a synced log with a torn tail on a SHARED in-memory disk. A fault during the
    // first recovery makes its truncation's sync_all fail, so the first reopen errors. Then
    // model the crash (a power loss) that accompanies that failed sync: the durable image
    // still holds the torn tail, so a second reopen must RE-RUN recovery's truncation and
    // recover the same valid prefix. Recovery is idempotent, never leaving the log unopenable.
    let disk = InMemoryFs::new();
    let n = 6u64;
    {
        let mut log = Log::open(disk.clone(), ManualClock::new(), big_config()).unwrap();
        for i in 0..n {
            append_at(&mut log, i);
        }
        log.sync().unwrap();
    }
    // Tear a few bytes off the last record so recovery must truncate it. The torn-tail
    // image must be DURABLE so it survives the power loss below and forces recovery to
    // re-truncate: a `set_len` shrink is metadata that only `sync_all` persists (#158), so
    // pair it with `sync_all`, not `sync_data` (which a power loss would revert).
    let seg = disk.open(&segment_file_name(0)).unwrap();
    let len = seg.len().unwrap();
    seg.set_len(len - 3).unwrap();
    seg.sync_all().unwrap();
    drop(seg);

    // Crash during recovery: wrap a shared handle in a FaultFs, arm a sync fault. Recovery's
    // set_len succeeds but its sync_all faults, so the first open fails cleanly (no panic).
    let (faultfs, control) = FaultFs::new(disk.clone());
    control.set_fail_sync(true);
    assert!(
        Log::open(faultfs, ManualClock::new(), big_config()).is_err(),
        "a fault during recovery surfaces as a clean error"
    );

    // Model the crash that accompanies the failed sync: the live image reverts to durable,
    // which still holds the torn tail (the first recovery's truncation never synced). Without
    // this, the shared live image would already be truncated and the retry would skip the
    // truncation branch, testing nothing.
    disk.simulate_power_loss();
    // Idempotent retry: a clean reopen RE-RUNS recovery's truncation and recovers the prefix.
    let log = Log::open(disk.clone(), ManualClock::new(), big_config()).unwrap();
    assert!(
        log.recovered_truncated_bytes() > 0,
        "the retry actually re-entered recovery's truncation branch"
    );
    assert_eq!(log.flushed_offset(), Offset::new(n - 1));
    assert_prefix(&log, n - 1);
}

#[test]
fn recovery_is_a_pure_function_of_the_durable_bytes() {
    // I4 (#120): recovering twice from IDENTICAL durable bytes yields identical records. Build
    // a log with a torn tail, capture each segment file's bytes, then recover from two
    // INDEPENDENT disks loaded with those same bytes and assert the records match via the
    // shared checker.
    let log = apply(
        InMemoryFs::new(),
        big_config(),
        &(0..7)
            .map(|_| Op::Append)
            .chain([Op::Sync])
            .collect::<Vec<_>>(),
    );
    let src = log.into_filesystem();
    // Tear a few bytes off the active segment so recovery must truncate (a non-clean image).
    let last = src.list().unwrap().into_iter().last().unwrap();
    let f = src.open(&last).unwrap();
    let torn = f.len().unwrap() - 3;
    f.set_len(torn).unwrap();
    f.sync_data().unwrap();

    // Snapshot every segment file's bytes.
    let images: Vec<(String, Vec<u8>)> = src
        .list()
        .unwrap()
        .into_iter()
        .map(|n| {
            let bytes = src.open(&n).unwrap().snapshot();
            (n, bytes)
        })
        .collect();
    let build = || {
        let disk = InMemoryFs::new();
        for (name, bytes) in &images {
            let file = disk.create_new(name).unwrap();
            file.write_all_at(bytes, 0).unwrap();
            file.sync_all().unwrap();
        }
        disk.sync_dir().unwrap();
        disk
    };

    let first = Log::open(build(), ManualClock::new(), big_config())
        .unwrap()
        .read_from(Offset::ZERO, usize::MAX)
        .unwrap();
    let second = Log::open(build(), ManualClock::new(), big_config())
        .unwrap()
        .read_from(Offset::ZERO, usize::MAX)
        .unwrap();
    assert!(!first.is_empty(), "the recovery is non-trivial");
    check_pure_recovery(&first, &second).unwrap();
}

#[test]
fn recovery_recovers_the_full_prefix_under_persistent_short_reads() {
    // Cap every read to a single byte: recovery's read_exact_at must loop over the short reads
    // and still recover the whole durable prefix, so no acked record is lost to a partial read
    // (#151). This exercises the storage IO layer's short-read handling end to end.
    let n = 6u64;
    let ops: Vec<Op> = (0..n).map(|_| Op::Append).chain([Op::Sync]).collect();
    let log = apply(InMemoryFs::new(), big_config(), &ops);
    let disk = log.into_filesystem();

    let (faultfs, control) = FaultFs::new(disk);
    control.set_short_read(1);
    let log = Log::open(faultfs, ManualClock::new(), big_config()).unwrap();
    assert_eq!(
        log.flushed_offset(),
        Offset::new(n),
        "every durable record recovered"
    );
    assert_prefix(&log, n);
}

#[test]
fn recovery_fails_cleanly_under_an_injected_read_error() {
    // An injected read error during recovery surfaces as a clean StorageError, never a panic or
    // silent partial recovery (#151).
    let n = 6u64;
    let ops: Vec<Op> = (0..n).map(|_| Op::Append).chain([Op::Sync]).collect();
    let log = apply(InMemoryFs::new(), big_config(), &ops);
    let disk = log.into_filesystem();

    let (faultfs, control) = FaultFs::new(disk);
    control.set_fail_read(true);
    let err = Log::open(faultfs, ManualClock::new(), big_config()).unwrap_err();
    assert!(
        matches!(err, ironbus_storage::segment::StorageError::Io(_)),
        "an injected read error must surface as a clean IO error, got {err:?}"
    );
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Append),
        1 => Just(Op::Sync),
    ]
}

proptest! {
    /// Power loss after an arbitrary workload, under either config, recovers exactly
    /// the durable prefix.
    #[test]
    fn power_loss_recovers_the_durable_prefix(
        ops in prop::collection::vec(op_strategy(), 0..40),
        roll in any::<bool>(),
    ) {
        let config = if roll { small_config() } else { big_config() };
        let log = apply(InMemoryFs::new(), config, &ops);
        let durable = log.flushed_offset().get();
        let appended = log.next_offset().get();
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();

        let log = Log::open(fs, ManualClock::new(), config).unwrap();
        let recovered = log.flushed_offset().get();
        prop_assert_eq!(recovered, durable);
        prop_assert!(recovered <= appended);
        let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
        prop_assert_eq!(records.len() as u64, recovered);
        // Assert the resilience invariants through the shared checkers (#120): the recovered
        // run is the longest valid prefix (I2) and every durable (acked) offset survived (I1).
        let i2 = check_longest_valid_prefix(&records);
        prop_assert!(i2.is_ok(), "{i2:?}");
        let acked: Vec<u64> = (0..durable).collect();
        let i1 = check_no_acked_loss(&records, &acked);
        prop_assert!(i1.is_ok(), "{i1:?}");
        for (i, record) in records.iter().enumerate() {
            let i = u64::try_from(i).unwrap();
            prop_assert_eq!(record.offset, Offset::new(i));
            prop_assert_eq!(record.seq, Seq::new(i));
            let expected = payload(i);
            prop_assert_eq!(record.payload.as_slice(), expected.as_slice());
        }
    }

    /// A single corrupted byte anywhere in the segment never panics or hangs: recovery
    /// either fails cleanly (a damaged header) or returns a valid, monotonic prefix that
    /// never reads past the corruption.
    #[test]
    fn arbitrary_byte_corruption_yields_a_valid_prefix_or_clean_error(
        n in 1u64..12,
        idx in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let ops: Vec<Op> = (0..n).map(|_| Op::Append).chain([Op::Sync]).collect();
        let log = apply(InMemoryFs::new(), big_config(), &ops);
        let fs = log.into_filesystem();

        let file = fs.open(&segment_file_name(0)).unwrap();
        let mut bytes = file.snapshot();
        let pos = idx.index(bytes.len());
        bytes[pos] ^= xor;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();

        // A damaged header is a clean, reported error; otherwise a valid prefix of <= n.
        if let Ok(log) = Log::open(fs, ManualClock::new(), big_config()) {
            let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
            prop_assert!(records.len() as u64 <= n);
            for (i, record) in records.iter().enumerate() {
                let i = u64::try_from(i).unwrap();
                prop_assert_eq!(record.offset, Offset::new(i));
                prop_assert_eq!(record.seq, Seq::new(i));
                // Every SURVIVED record has intact bytes (the corruption fell in a record
                // that was dropped, or in the segment header), so a checksum that wrongly
                // accepted a corrupt record would surface here as a mismatched payload.
                let expected = payload(i);
                prop_assert_eq!(record.payload.as_slice(), expected.as_slice());
            }
        }
    }
}

proptest! {
    /// A fatal fsync forced after an arbitrary clean prefix of an arbitrary workload (and
    /// asserted to actually freeze the writer, so the case is never vacuous), then a power
    /// loss, recovers exactly the prefix that was durable at the fault: no acknowledged
    /// record is lost, none is invented, and the recovered records are a valid monotone run.
    /// This sweeps the fsync-EIO crash class over many workloads and freeze points (the
    /// seeded sim lane), where the point gates above pin specific cases.
    #[test]
    fn a_sync_fault_at_any_point_loses_no_acked_record(
        ops in prop::collection::vec(op_strategy(), 0..40),
        roll in any::<bool>(),
        fault_after in 0usize..40,
    ) {
        let config = if roll { small_config() } else { big_config() };
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), config).unwrap();
        let mut next = 0u64;
        let k = fault_after.min(ops.len());

        // Phase 1: apply a clean prefix of the workload, establishing the durable mark.
        for op in &ops[..k] {
            match op {
                Op::Append => {
                    append_at(&mut log, next);
                    next += 1;
                }
                Op::Sync => log.sync().unwrap(),
            }
        }
        let durable_at_fault = log.flushed_offset().get();

        // Phase 2: arm a fatal fsync and FORCE it to fire with an explicit sync, so every
        // generated case actually exercises the freeze and the property never passes
        // vacuously (and a shrunk failure still exercises it). The freezing sync surfaces
        // WriterFrozen and the writer stays frozen for the rest.
        control.set_fail_sync(true);
        prop_assert!(
            matches!(
                log.sync(),
                Err(ironbus_storage::segment::StorageError::WriterFrozen)
            ),
            "the armed fsync must freeze the writer"
        );
        prop_assert!(!log.is_writable(), "the writer is frozen after the fatal fsync");
        // Any further ops on the frozen writer fail and cannot advance durability.
        for op in &ops[k..] {
            match op {
                Op::Append => {
                    let _ = log.append(&Append {
                        timestamp_ms: next,
                        flags: RecordFlags::EMPTY,
                        key: b"",
                        headers: b"",
                        payload: &payload(next),
                    });
                }
                Op::Sync => {
                    let _ = log.sync();
                }
            }
        }
        prop_assert_eq!(
            log.flushed_offset().get(),
            durable_at_fault,
            "a frozen writer makes no durable progress"
        );
        control.set_fail_sync(false);
        let appended = log.next_offset().get();

        // The crash drops every unsynced byte; reopen and check the invariant.
        let faultfs = log.into_filesystem();
        faultfs.inner().simulate_power_loss();
        let log = Log::open(faultfs, ManualClock::new(), config).unwrap();
        let recovered = log.flushed_offset().get();
        prop_assert!(
            recovered >= durable_at_fault,
            "lost an acked record: recovered {} < durable {}",
            recovered,
            durable_at_fault
        );
        prop_assert!(recovered <= appended, "invented a record beyond what was appended");
        prop_assert_eq!(recovered, durable_at_fault, "recovered exactly the durable prefix");
        let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
        prop_assert_eq!(records.len() as u64, recovered);
        for (i, record) in records.iter().enumerate() {
            let i = u64::try_from(i).unwrap();
            prop_assert_eq!(record.offset, Offset::new(i));
            prop_assert_eq!(record.seq, Seq::new(i));
            let expected = payload(i);
            prop_assert_eq!(record.payload.as_slice(), expected.as_slice());
        }
    }
}

/// One injected storage fault, chosen from the proptest seed so a failure replays exactly.
#[derive(Clone, Debug)]
enum Fault {
    /// Every `sync_data` / `sync_all` returns an injected error.
    FailSync,
    /// Every `write_all_at` fails cleanly without writing.
    FailWrite,
    /// Every `read_at` returns an injected error.
    FailRead,
    /// Every `read_at` returns at most this many bytes (a partial read), 1 or more.
    ShortRead(u64),
    /// The next `write_all_at` persists this many bytes then errors (a torn write).
    TornWrite(u64),
}

fn fault_strategy() -> impl Strategy<Value = Fault> {
    prop_oneof![
        Just(Fault::FailSync),
        Just(Fault::FailWrite),
        Just(Fault::FailRead),
        (1u64..8).prop_map(Fault::ShortRead),
        (0u64..16).prop_map(Fault::TornWrite),
    ]
}

fn arm_fault(control: &FaultControl, fault: &Fault) {
    match *fault {
        Fault::FailSync => control.set_fail_sync(true),
        Fault::FailWrite => control.set_fail_write(true),
        Fault::FailRead => control.set_fail_read(true),
        Fault::ShortRead(n) => control.set_short_read(n),
        Fault::TornWrite(n) => control.arm_torn_write(n),
    }
}

fn disarm_all(control: &FaultControl) {
    control.set_fail_sync(false);
    control.set_fail_write(false);
    control.set_fail_read(false);
    control.set_short_read(0);
}

proptest! {
    /// The seed-driven half of the fault-injection contract (#151): for an arbitrary workload
    /// and an arbitrary one of the five injected faults (fsync EIO, clean write failure, read
    /// error, short read, torn write), recovery under that fault must hold the resilience
    /// invariants. It must NEVER panic; it either recovers a valid prefix (I2) that preserves
    /// every durably acked record (I1), or fails closed with a typed error. A buggy recovery
    /// that lost an acked record, read past a torn tail, or panicked on an IO fault fails here.
    #[test]
    fn recovery_under_an_arbitrary_seeded_fault_holds_the_invariants(
        ops in prop::collection::vec(op_strategy(), 0..30),
        roll in any::<bool>(),
        fault in fault_strategy(),
    ) {
        let config = if roll { small_config() } else { big_config() };
        let log = apply(InMemoryFs::new(), config, &ops);
        let durable = log.flushed_offset().get();
        let disk = log.into_filesystem();

        let (faultfs, control) = FaultFs::new(disk);
        arm_fault(&control, &fault);

        // Recover under the fault. Reaching past this call at all (no unwind) already proves
        // the no-panic invariant; an `Err` is the fail-closed outcome (a clean typed error),
        // which is acceptable. Only a successful recovery is held to the I1/I2 invariants.
        if let Ok(log) = Log::open(faultfs, ManualClock::new(), config) {
            // Recovery succeeded despite the fault. Disarm so the invariant check inspects the
            // recovered STATE, not reads taken under a still-armed fault.
            disarm_all(&control);
            let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
            // I2: the recovered run is a contiguous valid prefix from offset 0.
            check_longest_valid_prefix(&records).map_err(|v| TestCaseError::fail(v.to_string()))?;
            // I1: every durably acked offset survived (recovery may keep more, never less).
            let acked: Vec<u64> = (0..durable).collect();
            check_no_acked_loss(&records, &acked).map_err(|v| TestCaseError::fail(v.to_string()))?;
        }
    }
}
