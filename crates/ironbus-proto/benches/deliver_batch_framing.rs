// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmark for the `DeliverBatch` raw-framed delivery FRAMING + WRITE overhead the
//! batch frame removes versus N per-record Deliver frames (#541, M1-I5). The local proof for the
//! batch-framing lever; the full t4g + NATS consume comparison is the milestone gate (#554).
//!
//! ## What it isolates: the per-record framing + re-encode the batch removes
//!
//! For a Tier-S streaming fetch the broker serves a CONTIGUOUS run of stored records. Two delivery
//! framings carry the SAME run:
//!
//! - PER-RECORD (the BEFORE): N `Deliver` frames. For each record the broker re-encodes the wire body
//!   (`encode_deliver`: offset, generation, flags, timestamp, length-prefixed key/headers, then the
//!   payload — a copy of every field) and wraps it in a frame envelope (`encode_frame`: the 4-byte
//!   length prefix + 1-byte tag). N body re-encodes + N envelopes + N payload copies into the wire
//!   buffer.
//! - DELIVERBATCH (this issue): ONE `DeliverBatch` frame. The broker writes the small fixed header
//!   (`encode_deliver_batch`: version + `field_len` + `first_offset` + generation + `record_count`) ONCE,
//!   then copies the contiguous run's ON-DISK frame bytes VERBATIM (the bytes it already holds as a
//!   storage `RawByteRun`, modeled here as a precomputed blob the broker does not re-encode), wrapped
//!   in ONE frame envelope. ONE header + ONE envelope + ONE bulk copy, zero per-record re-encode.
//!
//! The expected result: the batch framing is a clear multiple cheaper, because it does ONE envelope +
//! ONE header + ONE bulk copy where the per-record path does N envelopes + N body re-encodes + N field
//! copies. The gap IS the framing/write lever this issue targets, measured at the wire-encode boundary
//! (the disk `sendfile(2)` that turns the batch's stored-bytes body into a zero-USER-SPACE-copy socket
//! splice is the deferred follow-up #658, for which the on-disk-bytes batch body is the prerequisite).
//!
//! What it measures and what it does NOT: this is the pure wire-encode cost (no IO, no socket). The
//! on-disk run bytes are precomputed and held as a `bytes::Bytes`-like `Vec` to model the broker
//! NEVER touching them on the batch path — exactly the zero-re-encode property #658 splices on. Run on
//! demand (`cargo bench -p ironbus-proto`), NOT in per-PR CI; the full consume-vs-NATS leg is #554.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ironbus_proto::frame::{encode_frame, FrameType};
use ironbus_proto::message::{
    encode_deliver, encode_deliver_batch, DeliverBatchHeader, DeliverBody,
};

/// Records per delivered batch (a representative streaming run).
const BATCH: usize = 64;

/// Payload sizes to sweep: a small record (framing/encode-dominated, where the per-record envelope +
/// body-field overhead dominates) and larger ones (copy-dominated).
const PAYLOADS: [usize; 3] = [16, 256, 4096];

/// One record's fields for the bench (the broker holds these as a stored `OwnedRecord`).
struct Rec {
    offset: u64,
    flags: u8,
    timestamp_ms: u64,
    key: Vec<u8>,
    headers: Vec<u8>,
    payload: Vec<u8>,
}

fn make_records(payload_len: usize) -> Vec<Rec> {
    (0..BATCH as u64)
        .map(|i| Rec {
            offset: i,
            flags: 0,
            timestamp_ms: 1000 + i,
            key: vec![(i % 7) as u8; 4],
            headers: vec![(i % 5) as u8; 2],
            payload: vec![(i % 251) as u8; payload_len],
        })
        .collect()
}

/// Models the contiguous ON-DISK run bytes the broker already holds for the batch path (a
/// `RawByteRun`), built once OUTSIDE the timed loop so the batch path's cost is the header write + the
/// ONE bulk copy, NOT a re-encode. The exact on-disk codec lives in `ironbus-storage` (below this
/// crate), so the blob here is a faithful stand-in of the same total byte count.
fn on_disk_blob(records: &[Rec]) -> Vec<u8> {
    // Per the frozen on-disk layout: 36-byte header + body (key+headers+payload) + 8-byte trailer.
    let mut blob = Vec::new();
    for r in records {
        blob.extend_from_slice(&[0u8; 36]);
        blob.extend_from_slice(&r.key);
        blob.extend_from_slice(&r.headers);
        blob.extend_from_slice(&r.payload);
        blob.extend_from_slice(&[0u8; 8]);
    }
    blob
}

fn bench_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("deliver_batch_framing");
    for payload_len in PAYLOADS {
        let records = make_records(payload_len);
        let blob = on_disk_blob(&records);

        // BEFORE: N per-record Deliver frames (re-encode each body + wrap each in a frame envelope).
        group.bench_with_input(
            BenchmarkId::new("per_record_deliver", payload_len),
            &payload_len,
            |b, _| {
                b.iter(|| {
                    let mut out = Vec::new();
                    for r in &records {
                        let mut body = Vec::new();
                        encode_deliver(
                            &DeliverBody {
                                offset: r.offset,
                                generation: 0,
                                flags: r.flags,
                                timestamp_ms: r.timestamp_ms,
                                key: &r.key,
                                headers: &r.headers,
                                payload: &r.payload,
                            },
                            &mut body,
                        )
                        .unwrap();
                        encode_frame(FrameType::Deliver, &body, &mut out).unwrap();
                    }
                    black_box(out.len())
                });
            },
        );

        // AFTER: ONE DeliverBatch frame (one header + one bulk copy of the precomputed on-disk run).
        group.bench_with_input(
            BenchmarkId::new("deliver_batch", payload_len),
            &payload_len,
            |b, _| {
                b.iter(|| {
                    let mut body = Vec::new();
                    encode_deliver_batch(
                        &DeliverBatchHeader {
                            first_offset: 0,
                            generation: 0,
                            record_count: u32::try_from(BATCH).unwrap(),
                        },
                        &blob,
                        &mut body,
                    );
                    let mut out = Vec::new();
                    encode_frame(FrameType::DeliverBatch, &body, &mut out).unwrap();
                    black_box(out.len())
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_framing);
criterion_main!(benches);
