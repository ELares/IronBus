// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmark for the zero-copy slice handoff (#386, the #112 residual).
//!
//! The issue scopes this as the "`bytes::BytesMut` freeze-to-`Bytes` O(1) slice-handoff" bench.
//! IronBus does NOT depend on the `bytes` crate (it frames into `Vec<u8>`/`&[u8]` and shares
//! read-side payloads behind an `Arc`), so we do NOT add `bytes` just for a bench. Instead this
//! benches the EQUIVALENT zero-copy handoff IronBus actually uses: freezing an owned buffer into a
//! shared, immutable `Arc<[u8]>` and then handing out refcounted sub-slices of it. That is the same
//! O(1)-refcount-bump, no-payload-copy property `BytesMut::freeze` + `Bytes::slice` give, expressed
//! with std types.
//!
//! Three paths over the same fixed buffer, so the win is visible:
//! 1. `freeze`: `Vec<u8>` -> `Arc<[u8]>` once (the one-time conversion cost), the analogue of
//!    `BytesMut::freeze`.
//! 2. `arc_slice_handoff`: hand out a sub-range of an already-frozen `Arc<[u8]>` as
//!    `(Arc<[u8]>, Range)`, an O(1) refcount bump with NO payload copy, the analogue of
//!    `Bytes::slice`.
//! 3. `copy_handoff`: the baseline it avoids, `slice.to_vec()`, an O(n) payload copy per handoff.
//!
//! The handoff vs copy contrast is the point: the refcounted handoff is flat in the slice size, the
//! copy grows with it. Architecture-neutral source (no x86-only intrinsics), so the same
//! `cargo bench -p ironbus-core` runs on an aarch64 reference core (the ARM device residual; the
//! committed numbers are x86). Inputs are fixed bytes (deterministic) and `black_box` hides them
//! from the optimizer. Run on demand, NOT in per-PR CI; the regression gate is #114.

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Representative shared-buffer sizes: a 64 B body, a 4 KiB body, and a 64 KiB body, so the flat
/// refcount handoff is contrasted against the size-growing copy across a useful range.
const SIZES: [usize; 3] = [64, 4 * 1024, 64 * 1024];

/// Builds a deterministic buffer of `len` bytes: a fixed byte ramp, never random.
fn buffer(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// A refcounted handoff of a sub-range of a shared `Arc<[u8]>`: cloning the `Arc` is an O(1)
/// refcount bump and the range names the sub-slice, so NO payload bytes are copied. This is the
/// `Bytes::slice` analogue (a shared, immutable view), returned as an owned pair so the optimizer
/// cannot fold the clone away.
fn arc_slice_handoff(buf: &Arc<[u8]>, range: std::ops::Range<usize>) -> (Arc<[u8]>, usize, usize) {
    (Arc::clone(buf), range.start, range.end)
}

/// `Vec<u8>` -> `Arc<[u8]>` (the `BytesMut::freeze` analogue): the one-time freeze of an owned
/// buffer into a shared, immutable one. Throughput is the buffer size.
fn bench_freeze(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy/freeze");
    for &size in &SIZES {
        let buf = buffer(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &buf, |b, buf| {
            b.iter(|| {
                let frozen: Arc<[u8]> = Arc::from(black_box(buf).as_slice());
                black_box(frozen.len());
            });
        });
    }
    group.finish();
}

/// The refcounted slice handoff (O(1), no copy) versus the copy baseline (`to_vec`, O(n)) over an
/// already-frozen `Arc<[u8]>`, so the saved per-handoff payload copy is visible. Throughput is the
/// handed-off slice size, so the copy path's per-byte cost shows and the handoff path stays flat.
fn bench_handoff(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy/handoff");
    for &size in &SIZES {
        let frozen: Arc<[u8]> = Arc::from(buffer(size).as_slice());
        let range = 0..size;
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("arc_slice", size), &frozen, |b, frozen| {
            b.iter(|| {
                let handed = arc_slice_handoff(black_box(frozen), range.clone());
                black_box(handed.2 - handed.1);
            });
        });
        group.bench_with_input(BenchmarkId::new("copy", size), &frozen, |b, frozen| {
            b.iter(|| {
                let copied = black_box(frozen)[range.clone()].to_vec();
                black_box(copied.len());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_freeze, bench_handoff);
criterion_main!(benches);
