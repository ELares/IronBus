// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmark for the off-actor consume READ plane's multi-consumer SCALING
//! (#539, V2-M1 step I3). The local scaling proof for the lock-free read plane; the full
//! multi-consumer t4g + NATS comparison is the milestone gate (#554).
//!
//! ## What it isolates: aggregate read throughput as consumers are added
//!
//! It compares the SAME work — N consumers each reading the sealed, flushed prefix of one log —
//! under two read planes:
//!
//! - THROUGH-ACTOR (the BEFORE): every read goes through the single append/write actor, modeled
//!   here as a `Mutex<Log>` the N consumer threads contend on (the production actor serializes reads
//!   on ONE thread behind a bounded `sync_channel` round-trip; a `Mutex` is the faithful, lighter
//!   in-process stand-in — both force reads to run ONE AT A TIME). Adding consumers does NOT add
//!   throughput: they serialize on the single shared lock/actor — the multi-consumer ceiling (#491).
//! - OFF-ACTOR (this issue): every read takes a wait-free `ReadPlane` snapshot (one Acquire frontier
//!   load + one `ArcSwap::load`) and scans the IMMUTABLE sealed bytes with NO lock and NO actor
//!   round-trip, so the N consumers run FULLY IN PARALLEL. Aggregate throughput SCALES with the
//!   consumer count instead of flat-lining.
//!
//! The expected result: at 1 consumer the two are within noise (the off-actor read does the same
//! seek+scan+CRC work, just without the lock); as consumers are added, the off-actor aggregate
//! throughput rises toward `N x` while the through-actor aggregate stays roughly flat (serialized).
//!
//! What it measures and what it does NOT: the log is opened over the in-memory [`InMemoryFs`], so the
//! work is the real codec decode + CRC32C + seek/scan, reading from memory rather than a device —
//! device fsync latency is owned by the macro rig (#114/#554), not a stable micro-bench. There is no
//! concurrent WRITER in the measured loop (the prefix is sealed up front), so the bench isolates the
//! READER-vs-READER contention the lock removes; the writer-concurrent-with-readers safety is proven
//! by the loom models and the `read_plane` concurrency test, not here. Run on demand
//! (`cargo bench -p ironbus-storage`), NOT in per-PR CI.

use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ironbus_core::clock::ManualClock;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::read_plane::ReadPlane;

/// Consumer counts to sweep. The through-actor aggregate stays ~flat across these (serialized on the
/// one lock); the off-actor aggregate rises toward `N x` (parallel). The gap IS the scaling win.
const CONSUMERS: [usize; 4] = [1, 2, 4, 8];

/// Records to pre-seal into the prefix. A small segment cap rolls these into MANY sealed segments,
/// so the off-actor snapshot's multi-segment seek/scan is exercised, and the read batch crosses
/// segment boundaries the way a replaying consumer does.
const RECORDS: u64 = 4096;

/// How many records each read pulls (a representative consume batch). Every consumer repeatedly reads
/// `[0, BATCH)` from the sealed prefix — the same work under both planes, so the only difference is
/// the lock/actor serialization the off-actor plane removes.
const BATCH: usize = 64;

/// Reads PER consumer per measured iteration: enough seek+scan work that the lock-contention vs
/// lock-free difference dominates the thread spawn/join overhead.
const READS_PER_CONSUMER: usize = 256;

/// Builds one in-memory log with `RECORDS` records pre-sealed into many small segments, synced so the
/// whole prefix is flushed and visible, plus its off-actor read plane.
fn sealed_log() -> (Log<InMemoryFs, ManualClock>, ReadPlane<InMemoryFs>) {
    let config = LogConfig {
        // A small cap so the records roll into many SEALED segments (the off-actor snapshot covers
        // the sealed prefix; the last, active segment is served via the through-actor fallback).
        max_segment_bytes: 4096,
        max_total_bytes: 0,
        ..LogConfig::default()
    };
    let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), config).expect("open log");
    for i in 0..RECORDS {
        let payload = i.to_le_bytes();
        let _ = log
            .append(&Append {
                timestamp_ms: 1,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &payload,
            })
            .expect("append");
        // Sync periodically so seals/flushes publish the frontier + snapshot like production.
        if i % 16 == 0 {
            log.sync().expect("sync");
        }
    }
    log.sync().expect("final sync");
    let plane = log.read_plane().expect("build read plane");
    (log, plane)
}

/// Drives `consumers` threads, each issuing `READS_PER_CONSUMER` reads via `read_one_read`, all
/// released together by a barrier so the measured span is the PARALLEL read phase (not thread
/// startup). Returns the wall-clock span; Criterion converts it to aggregate throughput.
fn drive<R>(consumers: usize, read_one_read: R) -> std::time::Duration
where
    R: Fn() + Send + Sync + 'static,
{
    let read_one_read = Arc::new(read_one_read);
    let barrier = Arc::new(Barrier::new(consumers + 1));
    let handles: Vec<_> = (0..consumers)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let read_one_read = Arc::clone(&read_one_read);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..READS_PER_CONSUMER {
                    read_one_read();
                }
            })
        })
        .collect();
    barrier.wait();
    let start = Instant::now();
    for h in handles {
        h.join().expect("consumer thread");
    }
    start.elapsed()
}

fn bench_consume_scaling(c: &mut Criterion) {
    let (log, plane) = sealed_log();
    // The through-actor stand-in: the single Log behind one Mutex that every consumer contends on
    // (the production single-actor read serialization).
    let shared_log = Arc::new(Mutex::new(log));

    let mut group = c.benchmark_group("consume_scaling");
    for &consumers in &CONSUMERS {
        // OFF-ACTOR: each consumer reads the sealed prefix lock-free through its own ReadPlane clone.
        group.bench_with_input(
            BenchmarkId::new("off_actor", consumers),
            &consumers,
            |b, &consumers| {
                let plane = plane.clone();
                b.iter_custom(|iters| {
                    let mut total = std::time::Duration::ZERO;
                    for _ in 0..iters {
                        let plane = plane.clone();
                        total += drive(consumers, move || {
                            let out = plane
                                .read_range(Offset::ZERO, BATCH, None)
                                .expect("off-actor read");
                            black_box(out.records.len());
                        });
                    }
                    total
                });
            },
        );
        // THROUGH-ACTOR: each consumer's read takes the single shared Mutex<Log> (the serialized
        // actor). Adding consumers only adds lock contention, not throughput.
        group.bench_with_input(
            BenchmarkId::new("through_actor", consumers),
            &consumers,
            |b, &consumers| {
                let shared_log = Arc::clone(&shared_log);
                b.iter_custom(|iters| {
                    let mut total = std::time::Duration::ZERO;
                    for _ in 0..iters {
                        let shared_log = Arc::clone(&shared_log);
                        total += drive(consumers, move || {
                            let guard = shared_log.lock().expect("actor lock");
                            let out = guard
                                .read_from(Offset::ZERO, BATCH)
                                .expect("through-actor read");
                            black_box(out.len());
                        });
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_consume_scaling);
criterion_main!(benches);
