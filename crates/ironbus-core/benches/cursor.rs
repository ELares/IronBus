// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmarks for the IO-free work-group ack cursor (#112).
//!
//! These measure the genuine hot paths in [`ironbus_core::cursor::AckCursor`]: a stream of
//! in-order acks (the watermark advances one at a time, the ahead set stays empty), an
//! out-of-order ack pattern (the acked-ahead set grows into many runs before collapsing),
//! and the durable snapshot round-trip (`encode_snapshot` / `decode_snapshot`). They are
//! run on demand (`cargo bench -p ironbus-core`), NOT in per-PR CI; the regression gate is
//! tracked separately (#114).
//!
//! Every ack sequence is built from fixed values so a run is deterministic (no ambient
//! randomness), and `black_box` hides inputs from the optimizer.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ironbus_core::cursor::AckCursor;
use ironbus_core::types::Offset;

/// The number of offsets acked in each cursor workload.
const ACKS: u64 = 1024;

/// A stream of strictly in-order acks: each ack advances the watermark by one and the
/// ahead set never grows, the cheap common path.
fn bench_ack_in_order(c: &mut Criterion) {
    let mut group = c.benchmark_group("cursor/ack_in_order");
    group.throughput(Throughput::Elements(ACKS));
    group.bench_function(format!("acks_{ACKS}"), |b| {
        b.iter(|| {
            let mut cursor = AckCursor::new();
            for offset in 0..ACKS {
                cursor.ack(black_box(Offset::new(offset)));
            }
            black_box(cursor.committed().get());
        });
    });
    group.finish();
}

/// An out-of-order ack pattern that grows the acked-ahead set: ack every odd offset first
/// (so each lands as its own run far from the watermark), then fill the even gaps (which
/// merge runs and finally collapse the watermark). This exercises `insert`'s search/merge
/// and `advance` under a deep ahead set, the worst common case.
fn bench_ack_out_of_order(c: &mut Criterion) {
    let mut group = c.benchmark_group("cursor/ack_out_of_order");
    group.throughput(Throughput::Elements(ACKS));
    group.bench_function(format!("acks_{ACKS}"), |b| {
        b.iter(|| {
            let mut cursor = AckCursor::new();
            // Odd offsets first: each is isolated, so the ahead set grows to ~ACKS/2 runs.
            let mut offset = 1;
            while offset < ACKS {
                cursor.ack(black_box(Offset::new(offset)));
                offset += 2;
            }
            // Even offsets next: each bridges two runs, draining the ahead set and advancing.
            let mut offset = 0;
            while offset < ACKS {
                cursor.ack(black_box(Offset::new(offset)));
                offset += 2;
            }
            black_box((cursor.committed().get(), cursor.ahead_runs()));
        });
    });
    group.finish();
}

/// Builds a cursor with a deterministic, fragmented acked-ahead set: ack the odd offsets
/// below `ACKS` so the watermark stays at 0 and the ahead set holds ~ACKS/2 single-offset
/// runs, a representative non-trivial snapshot.
fn fragmented_cursor() -> AckCursor {
    let mut cursor = AckCursor::new();
    let mut offset = 1;
    while offset < ACKS {
        cursor.ack(Offset::new(offset));
        offset += 2;
    }
    cursor
}

/// `encode_snapshot` of a fragmented cursor into a reused buffer, and `decode_snapshot` of
/// that snapshot back into a cursor. Throughput is the snapshot byte size.
fn bench_snapshot(c: &mut Criterion) {
    let cursor = fragmented_cursor();
    let mut snapshot = Vec::new();
    cursor.encode_snapshot(&mut snapshot);
    let snapshot_len = snapshot.len() as u64;

    let mut group = c.benchmark_group("cursor/snapshot");
    group.throughput(Throughput::Bytes(snapshot_len));
    group.bench_function("encode", |b| {
        let mut out = Vec::with_capacity(snapshot.len());
        b.iter(|| {
            out.clear();
            black_box(&cursor).encode_snapshot(&mut out);
            black_box(out.len());
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            let restored =
                AckCursor::decode_snapshot(black_box(&snapshot)).expect("own snapshot decodes");
            black_box(restored.ahead_runs());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_ack_in_order,
    bench_ack_out_of_order,
    bench_snapshot
);
criterion_main!(benches);
