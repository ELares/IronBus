// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmark for the WAL append path (#386, the #112 residual).
//!
//! This measures the CPU cost of the framing-and-append hot path in
//! [`ironbus_storage::log::Log::append`]: codec framing (header + body + CRC32C + trailer),
//! the per-record bookkeeping, and the positioned write into the segment buffer. It runs on
//! demand (`cargo bench -p ironbus-storage`), NOT in per-PR CI; the regression gate is tracked
//! separately (#114).
//!
//! What it measures, and what it deliberately does NOT: the log is opened over the in-memory
//! [`InMemoryFs`] (the deterministic-simulation backend), so every `append` exercises the real
//! framing, CRC32C, and buffer copy but writes into memory, never a device. The bench also does
//! NOT call [`Log::sync`], so it never charges an `fdatasync`/`fsync`. That is on purpose: disk
//! flush latency is device-dependent (eMMC vs ext4 vs tmpfs differ by orders of magnitude) and so
//! is not a stable micro-benchmark; the macro rig (#111, #114) owns end-to-end durable throughput
//! on a reference device. This bench isolates the IO-light CPU cost of framing + CRC + buffer that
//! the broker pays per record regardless of the disk underneath.
//!
//! Inputs are built from fixed bytes so a run is deterministic (no ambient randomness), and
//! `black_box` hides them from the optimizer. The bench uses only portable, architecture-neutral
//! code (no x86-only intrinsics), so the same `cargo bench -p ironbus-storage` runs on an aarch64
//! reference core (the ARM device residual, see `CHANGELOG.md`); the committed numbers are x86.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ironbus_core::clock::ManualClock;
use ironbus_core::types::RecordFlags;
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::{Append, Log, LogConfig};

/// Representative append batch sizes: a 1-byte record (the framing-overhead-dominated case), a
/// 16 KiB record (a mid-size body), and a 1 MiB record (a large body where the CRC32C and the
/// buffer copy dominate). These bracket the per-record cost from "all framing" to "all payload".
const BATCH_SIZES: [usize; 3] = [1, 16 * 1024, 1024 * 1024];

/// How many records of the given size are appended per measured iteration, so each sample frames a
/// representative run of records rather than a single one. Kept small for the 1 MiB case so the
/// largest batch is a bounded, in-memory amount of work.
const RECORDS_PER_BATCH: u64 = 16;

/// Builds a deterministic payload of `len` bytes: a fixed byte ramp, never random, so every run
/// frames the identical bytes.
fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// Opens a fresh in-memory log with a segment cap large enough that a whole batch lands in one
/// segment (no roll mid-batch), so the measured work is purely framing + append, not segment
/// rolling. `ManualClock` keeps the segment-header timestamps fixed and the run reproducible.
fn fresh_log(max_segment_bytes: u64) -> Log<InMemoryFs, ManualClock> {
    let config = LogConfig {
        max_segment_bytes,
        ..LogConfig::default()
    };
    Log::open(InMemoryFs::new(), ManualClock::new(), config)
        .expect("opening a fresh in-memory log never fails")
}

/// Appends `RECORDS_PER_BATCH` records of `body` into a fresh in-memory log, returning the log so
/// the optimizer cannot discard the appends. Each iteration starts from a fresh log so the work is
/// identical every sample (no growing segment count, no roll history).
fn append_batch(max_segment_bytes: u64, body: &[u8]) -> Log<InMemoryFs, ManualClock> {
    let mut log = fresh_log(max_segment_bytes);
    let record = Append {
        timestamp_ms: 1_700_000_000_000,
        flags: RecordFlags::EMPTY,
        key: b"route/key-0",
        headers: b"content-type=application/octet-stream",
        payload: body,
    };
    for _ in 0..RECORDS_PER_BATCH {
        log.append(black_box(&record))
            .expect("a representative record always fits the segment");
    }
    log
}

/// `Log::append` of a batch of records at each representative size. Throughput is the total payload
/// bytes per batch so the cases are comparable per byte. A large per-size segment cap (the body
/// rounded up plus generous slack times the batch count) keeps a whole batch in one segment, so the
/// bench measures framing + CRC + buffer, never a roll.
fn bench_wal_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("wal_append");
    for &size in &BATCH_SIZES {
        let body = payload(size);
        // A cap comfortably larger than a whole batch's framed bytes, so no roll happens mid-batch
        // (the framing+append cost is what we measure). 4 KiB of fixed framing slack per record
        // covers the header, trailer, and any optional checksum field for these sizes.
        let per_record = (size as u64) + 4096;
        let max_segment_bytes = per_record * (RECORDS_PER_BATCH + 1);
        group.throughput(Throughput::Bytes((size as u64) * RECORDS_PER_BATCH));
        group.bench_with_input(BenchmarkId::from_parameter(size), &body, |b, body| {
            b.iter(|| {
                let log = append_batch(black_box(max_segment_bytes), black_box(body));
                black_box(log.next_offset().get());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_wal_append);
criterion_main!(benches);
