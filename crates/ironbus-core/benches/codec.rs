// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmarks for the IO-free record-frame codec (#112).
//!
//! These measure the genuine hot paths in [`ironbus_core::codec`]: framing a record
//! ([`encode`]), parsing one back ([`decode`]), and reading a frame's length from its
//! header alone ([`decoded_len`]). They are run on demand (`cargo bench -p ironbus-core`),
//! NOT in per-PR CI; the regression gate is tracked separately (#114).
//!
//! Inputs are built from fixed bytes so a run is deterministic (no ambient randomness),
//! and `black_box` hides them from the optimizer so the work is not folded away.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ironbus_core::codec::{decode, decoded_len, encode, RecordView};
use ironbus_core::format::RECORD_HEADER_LEN;
use ironbus_core::types::{RecordFlags, Seq};

/// A small, representative payload size (a typical short message body).
const SMALL_PAYLOAD: usize = 64;
/// A larger payload size (a few KiB body), the second framing case.
const LARGE_PAYLOAD: usize = 4 * 1024;

/// Builds a representative record with a fixed key, fixed headers, and a deterministic
/// payload of `payload_len` bytes. The payload is a fixed byte ramp, never random, so
/// every run frames the identical bytes.
fn record(payload_len: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = b"route/key-0".to_vec();
    let headers = b"content-type=application/octet-stream".to_vec();
    let payload: Vec<u8> = (0..payload_len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    (key, headers, payload)
}

/// Frames `key`/`headers`/`payload` into `out`, reusing the buffer (cleared, capacity kept).
fn encode_into(out: &mut Vec<u8>, key: &[u8], headers: &[u8], payload: &[u8]) {
    let rec = RecordView {
        seq: Seq::new(42),
        timestamp_ms: 1_700_000_000_000,
        flags: RecordFlags::EMPTY,
        key,
        headers,
        payload,
    };
    out.clear();
    encode(black_box(&rec), out).expect("a representative record always fits the ceiling");
}

/// `encode` of a small and a larger record into a reused buffer. Throughput is the payload
/// size so the two cases are comparable per byte.
fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec/encode");
    for &payload_len in &[SMALL_PAYLOAD, LARGE_PAYLOAD] {
        let (key, headers, payload) = record(payload_len);
        group.throughput(Throughput::Bytes(payload_len as u64));
        let mut out =
            Vec::with_capacity(RECORD_HEADER_LEN + key.len() + headers.len() + payload_len + 8);
        group.bench_function(format!("payload_{payload_len}"), |b| {
            b.iter(|| {
                encode_into(
                    &mut out,
                    black_box(&key),
                    black_box(&headers),
                    black_box(&payload),
                );
                black_box(out.len());
            });
        });
    }
    group.finish();
}

/// `decode` of a pre-encoded frame, plus the header-only `decoded_len` length helper.
/// Throughput is the payload size so the two cases are comparable per byte.
fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec/decode");
    for &payload_len in &[SMALL_PAYLOAD, LARGE_PAYLOAD] {
        let (key, headers, payload) = record(payload_len);
        let mut frame = Vec::new();
        encode_into(&mut frame, &key, &headers, &payload);
        group.throughput(Throughput::Bytes(payload_len as u64));
        group.bench_function(format!("decode/payload_{payload_len}"), |b| {
            b.iter(|| {
                let (view, consumed) = decode(black_box(&frame)).expect("own frame decodes");
                black_box((view.payload.len(), consumed));
            });
        });
        group.bench_function(format!("decoded_len/payload_{payload_len}"), |b| {
            b.iter(|| {
                let len = decoded_len(black_box(&frame)).expect("own header is valid");
                black_box(len);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
