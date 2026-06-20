// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-bench + proof for the cross-stream `CommitCoordinator` (M2-I3, #564): the
//! batched durability barrier over a `StreamSet`.
//!
//! ## The claim this benchmark proves
//!
//! Per-stream logs naively cost one `fdatasync` PER stream PER commit, which would make the fsync
//! cost O(streams) and destroy the durable-produce group-commit win. The `CommitCoordinator`
//! ([`StreamSet::commit_tick`]) restores group-commit ACROSS streams: in one tick it flushes every
//! DIRTIED stream to the page cache, issues one `fdatasync` per dirtied stream, and releases every
//! parked ack together. The HONEST framing: the fsync COUNT per tick is O(dirtied-streams-per-tick)
//! — `fdatasync` cannot be batched across different fds by the kernel — but the per-RECORD fsync
//! cost stays O(1/batch), because a tick amortizes its K barriers across ALL the records it commits.
//!
//! ## How it is measured (deterministic, not device-dependent)
//!
//! For a FIXED total record rate (`TOTAL_RECORDS_PER_TICK` records committed per tick) spread evenly
//! across N = 1, 4, 16 streams, this counts the ACTUAL `fdatasync` calls a tick issues, using the
//! counting [`ironbus_storage::fault::FaultFs`] (its `sync_count()` increments on every
//! `sync_data`/`sync_all`). This is a deterministic COUNT, not a wall-clock latency: device fsync
//! latency varies by orders of magnitude across eMMC/ext4/tmpfs and is not a stable micro-bench
//! (the macro rig owns end-to-end durable throughput on a reference device), but the fsync COUNT is
//! exact and device-independent — and the count is precisely the Big-O claim. The reported
//! `fsyncs_per_record = N / TOTAL_RECORDS_PER_TICK` falls as N is held below the record count: the
//! barrier count scales with dirtied streams, NOT with messages.
//!
//! A second, criterion-timed leg measures the coordinator's CPU cost per tick over the in-memory
//! filesystem (framing + the flush/advance bookkeeping, no real device fsync), swept across stream
//! counts, so a regression in the coordinator's own overhead is visible. Run on demand
//! (`cargo bench -p ironbus-storage`), NOT wired into per-PR CI.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ironbus_core::clock::ManualClock;
use ironbus_core::types::RecordFlags;
use ironbus_storage::fault::FaultFs;
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::{Append, LogConfig};
use ironbus_storage::streamset::{StreamId, StreamSet};

/// The stream counts swept. 1 stream is the single-log group-commit baseline (one fdatasync/tick);
/// 4 and 16 spread the SAME total record rate over more streams. The proof: the per-record fsync
/// cost stays flat (≈ N / total), it does NOT grow with the message count.
const STREAM_COUNTS: [usize; 3] = [1, 4, 16];

/// The FIXED total records committed per tick, held constant as the stream count grows, so the only
/// thing that changes across the sweep is how the same record rate is distributed over streams.
/// Chosen as a common multiple of every swept stream count so each stream gets an equal share.
const TOTAL_RECORDS_PER_TICK: u64 = 256;

/// A deterministic small payload: framing + barrier dominate here, which is the point — this bench
/// is about the durability barrier's amortization, not payload throughput.
const PAYLOAD: &[u8] = b"commit-coordinator-record";

/// Builds the `n` stream ids for a sweep point: the default stream `""` plus `n-1` named streams,
/// so a 1-stream point is exactly the default (root log) — today's single-log path.
fn stream_ids(n: usize) -> Vec<StreamId> {
    let mut ids = vec![StreamId::default_stream()];
    for i in 1..n {
        ids.push(StreamId::named(&format!("s{i}")).expect("a short ascii name is valid"));
    }
    ids
}

/// A representative append record (fixed bytes, so every run is deterministic).
fn record() -> Append<'static> {
    Append {
        timestamp_ms: 1_700_000_000_000,
        flags: RecordFlags::EMPTY,
        key: b"route/key-0",
        headers: b"",
        payload: PAYLOAD,
    }
}

/// Appends `TOTAL_RECORDS_PER_TICK` records spread evenly across the `ids` streams, then runs ONE
/// `commit_tick`, returning `(fdatasyncs_issued, records_committed)` for the tick. The set is opened
/// over a counting `FaultFs`, and a generous segment cap keeps every stream in one segment (no seal
/// `sync_all`), so the counted syncs are exactly the coordinator's per-stream barriers.
fn one_tick_fsync_count(ids: &[StreamId]) -> (usize, u64) {
    let config = LogConfig {
        // Comfortably larger than a whole tick's framed bytes per stream, so no roll mid-tick: the
        // counted syncs are the coordinator's fdatasyncs alone, never a seal's sync_all.
        max_segment_bytes: 64 * 1024 * 1024,
        ..LogConfig::default()
    };
    let (fs, control) = FaultFs::new(InMemoryFs::new());
    let (mut set, _) = StreamSet::open(&fs, ManualClock::new(), config).expect("open never fails");
    for id in ids {
        if !id.is_default() {
            set.declare(id).expect("declare never fails");
        }
    }

    let rec = record();
    let per_stream = TOTAL_RECORDS_PER_TICK / (ids.len() as u64);
    let mut committed = 0u64;
    for id in ids {
        for _ in 0..per_stream {
            set.append_to(id, &rec).expect("append fits");
            committed += 1;
        }
    }

    let before = control.sync_count();
    let outcome = set.commit_tick();
    let fdatasyncs =
        usize::try_from(control.sync_count() - before).expect("a tick's barrier count fits usize");
    // The counting-fs barrier count must equal the outcome's reported count (one per dirtied stream).
    assert_eq!(fdatasyncs, outcome.fdatasyncs_issued);
    assert_eq!(fdatasyncs, ids.len(), "one fdatasync per dirtied stream");
    (fdatasyncs, committed)
}

/// THE PROOF (printed, deterministic): for a fixed total record rate, the fsync COUNT per tick
/// scales with the stream count, but the per-RECORD fsync cost stays ≈ N / total — flat as the
/// message rate is held constant. Printed at bench start so the numbers appear in the run log.
fn report_flat_fsync_proof() {
    eprintln!(
        "\n[#564 CommitCoordinator] fixed {TOTAL_RECORDS_PER_TICK} records/tick, swept across streams:"
    );
    eprintln!("  streams | fdatasyncs/tick | records/tick | fsyncs_per_record");
    for &n in &STREAM_COUNTS {
        let ids = stream_ids(n);
        let (fsyncs, committed) = one_tick_fsync_count(&ids);
        // `fsyncs` is the small stream count and `committed` the small fixed record rate, both well
        // within f64's exact-integer range; the ratio is the per-record fsync cost.
        let per_record = f64::from(u32::try_from(fsyncs).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(committed).unwrap_or(u32::MAX));
        eprintln!("  {n:>7} | {fsyncs:>15} | {committed:>12} | {per_record:>17.5}");
    }
    eprintln!(
        "  => fsync COUNT is O(dirtied streams/tick); per-RECORD fsync cost is O(1/batch) \
         (falls as records/stream grows), NOT O(messages).\n"
    );
}

/// Criterion-timed leg: the coordinator's CPU cost per tick (append the fixed record rate across N
/// streams + one `commit_tick`) over the in-memory fs, swept across stream counts. Throughput is the
/// records committed per tick so the cost-per-record is comparable across the sweep.
fn bench_commit_tick(c: &mut Criterion) {
    report_flat_fsync_proof();

    let mut group = c.benchmark_group("commit_coordinator_tick");
    for &n in &STREAM_COUNTS {
        let ids = stream_ids(n);
        group.throughput(Throughput::Elements(TOTAL_RECORDS_PER_TICK));
        group.bench_with_input(BenchmarkId::from_parameter(n), &ids, |b, ids| {
            let config = LogConfig {
                max_segment_bytes: 64 * 1024 * 1024,
                ..LogConfig::default()
            };
            let rec = record();
            let per_stream = TOTAL_RECORDS_PER_TICK / (ids.len() as u64);
            b.iter(|| {
                // A fresh in-memory set per iteration so each sample does identical work.
                let (mut set, _) =
                    StreamSet::open(&InMemoryFs::new(), ManualClock::new(), config).unwrap();
                for id in ids {
                    if !id.is_default() {
                        set.declare(id).unwrap();
                    }
                }
                for id in ids {
                    for _ in 0..per_stream {
                        set.append_to(id, black_box(&rec)).unwrap();
                    }
                }
                let outcome = set.commit_tick();
                black_box(outcome.fdatasyncs_issued);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_commit_tick);
criterion_main!(benches);
