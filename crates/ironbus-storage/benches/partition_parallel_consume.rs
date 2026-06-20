// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-bench + proof for PARTITIONS as the parallel-consume lever (#591, V2-M2
//! M2-I11): a stream split into `P` independent sub-logs lets `P` consumers drain `P` partitions in
//! PARALLEL, where a single total-order log (`P = 1`) admits at most one ordered reader.
//!
//! ## The claim this benchmark proves
//!
//! A single total-order log has ONE order, so an ordered consumer must read it as one sequence —
//! there is no second independent position to hand a second consumer. Partitioning the SAME total
//! record rate over `P` partitions gives `P` INDEPENDENT logs, each with its own order/cursor, so `P`
//! consumers each drain a different partition fully in parallel (per-partition order, no cross-partition
//! order — Kafka's model). Aggregate consume throughput therefore scales with `P` while per-partition
//! order is preserved. Composed with the off-actor lock-free read plane (#539), the per-partition
//! reads have no shared lock either, so the scaling is real, not just nominal.
//!
//! ## How it is measured (deterministic, not device-dependent)
//!
//! For a FIXED total record count spread evenly across `P = 1, 2, 4, 8` partitions, this spawns `P`
//! threads, each reading ITS OWN partition's records end-to-end (the real codec decode + CRC32C +
//! seek/scan over the in-memory [`InMemoryFs`], reading from memory, not a device — device fsync
//! latency is the macro rig's job, not a stable micro-bench), and times the aggregate wall clock to
//! drain ALL partitions. As `P` rises the partitions drain concurrently, so the aggregate time falls
//! (throughput rises) — the parallel-consume win. `P = 1` is the single total-order log baseline (one
//! reader, one order). Run on demand (`cargo bench -p ironbus-storage`), NOT wired into per-PR CI.

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ironbus_core::clock::ManualClock;
use ironbus_core::partition::{PartitionCount, PartitionIndex};
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::{Append, LogConfig};
use ironbus_storage::partitioned::PartitionedStream;

/// Partition counts to sweep. `P = 1` is the single total-order log (one ordered reader); `P > 1`
/// spreads the SAME total record rate so `P` readers drain `P` partitions in parallel. The aggregate
/// drain time falls as `P` rises — the parallel-consume lever.
const PARTITION_COUNTS: [u32; 4] = [1, 2, 4, 8];

/// The FIXED total records spread across the partitions, held constant as `P` grows so the only thing
/// that changes is how the same record rate is distributed over partitions (and how many readers can
/// drain it in parallel). A common multiple of every swept `P` so each partition gets an equal share.
const TOTAL_RECORDS: u64 = 8192;

/// How many records each per-partition read pulls (a representative consume batch). Each reader walks
/// its partition's whole offset space in `BATCH`-sized reads.
const BATCH: usize = 64;

/// A deterministic small payload: the bench isolates the per-partition read + cross-partition
/// parallelism, not payload throughput.
const PAYLOAD: &[u8] = b"partition-parallel-consume-record";

/// The log config used for both fill and reopen: a small segment cap so each partition's records roll
/// into several sealed segments (the read crosses segment boundaries, the way a replaying consumer
/// does).
fn bench_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 8192,
        max_total_bytes: 0,
        ..LogConfig::default()
    }
}

/// Builds a fresh in-memory fs holding a partitioned stream of `count` partitions, with
/// `TOTAL_RECORDS` KEYLESS records spread evenly across the partitions (round-robin) and synced, so
/// each partition holds an equal, durable, flushed share ready to drain. Returns the fs (which
/// `Clone`s share the backing store), so each reader thread can open its OWN handle over it — the
/// `Log` holds non-`Sync` interior state, so a handle is per-thread, exactly as a real consumer
/// connection opens its own.
fn filled_fs(count: PartitionCount) -> InMemoryFs {
    let fs = InMemoryFs::new();
    let (mut stream, _) =
        PartitionedStream::open(&fs, ManualClock::new(), bench_config(), count).expect("open");
    for _ in 0..TOTAL_RECORDS {
        let rec = Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: PAYLOAD,
        };
        stream.append_keyless(&rec).expect("append");
    }
    stream.sync_all().expect("sync");
    fs
}

/// Drains ONE partition end-to-end: repeated `BATCH`-sized reads from offset 0 until exhausted,
/// returning the record count read (so the work cannot be optimized away). The real decode + CRC +
/// seek/scan work per record.
fn drain_partition(
    stream: &PartitionedStream<InMemoryFs, ManualClock>,
    idx: PartitionIndex,
) -> u64 {
    let mut next = Offset::ZERO;
    let mut seen = 0u64;
    loop {
        let recs = stream
            .read_range(idx, next, BATCH, None)
            .expect("read_range");
        if recs.is_empty() {
            break;
        }
        seen += recs.len() as u64;
        // Advance past the last record read (its offset + 1).
        let last = recs.last().expect("non-empty").offset;
        next = Offset::new(last.get() + 1);
    }
    seen
}

/// The aggregate parallel drain: `P` threads, each draining its own partition concurrently, timed by
/// the wall clock to drain ALL partitions. As `P` rises the partitions drain in parallel, so the
/// aggregate time falls — the parallel-consume scaling the partition lever buys.
fn bench_partition_parallel_consume(c: &mut Criterion) {
    let mut group = c.benchmark_group("partition_parallel_consume");
    for &p in &PARTITION_COUNTS {
        let count = PartitionCount::new(p).expect("p >= 1");
        // The filled fs (Clone shares the backing store). Each reader thread opens its OWN
        // PartitionedStream handle over it — a Log holds non-Sync interior state, so the handle is
        // per-thread, exactly as a real consumer connection opens its own.
        let fs = filled_fs(count);
        group.throughput(Throughput::Elements(TOTAL_RECORDS));
        group.bench_with_input(BenchmarkId::from_parameter(p), &p, |b, &p| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    // A barrier so all P reader threads start together (the parallelism is real, not
                    // staggered by spawn order).
                    let barrier = Arc::new(Barrier::new(p as usize));
                    let mut handles = Vec::with_capacity(p as usize);
                    let start = Instant::now();
                    for i in 0..p {
                        let fs = fs.clone();
                        let barrier = Arc::clone(&barrier);
                        handles.push(thread::spawn(move || {
                            // Each thread reopens its own read handle over the shared backing store.
                            let (stream, _) = PartitionedStream::open(
                                &fs,
                                ManualClock::new(),
                                bench_config(),
                                count,
                            )
                            .expect("reopen");
                            barrier.wait();
                            black_box(drain_partition(&stream, PartitionIndex::new(i)))
                        }));
                    }
                    let mut drained = 0u64;
                    for h in handles {
                        drained += h.join().expect("join");
                    }
                    total += start.elapsed();
                    assert_eq!(drained, TOTAL_RECORDS, "every record drained exactly once");
                }
                total
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_partition_parallel_consume);
criterion_main!(benches);
