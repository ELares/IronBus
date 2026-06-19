// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmark for the ZERO-COPY consume delivery read primitive (#542, M1-I6).
//! The local read-boundary proof for the streaming-tier zero-copy path; the full t4g + NATS consume
//! comparison is the milestone gate (#554).
//!
//! ## What it isolates: the read-side cost the zero-copy path removes
//!
//! For a Tier-S streaming fetch the broker serves a CONTIGUOUS run of stored records off the durable
//! prefix. Two read planes serve the SAME run:
//!
//! - MATERIALIZE+ENCODE (the BEFORE): the current delivery path reads the run into per-record
//!   [`ironbus_storage::segment::OwnedRecord`]s (one body-CRC decode + three refcounted slices each,
//!   via `read_range`), then re-encodes every record's fields into a wire-delivery body (offset,
//!   generation, flags, timestamp, length-prefixed key/headers, then the payload — the exact field
//!   copies the `Deliver` body codec lays down). Each record is decoded once and its bytes are copied
//!   once into the wire buffer.
//! - ZERO-COPY (this issue): the run is read as ONE contiguous [`ironbus_storage::segment::RawByteRun`]
//!   (`read_range_raw`) — one read into one buffer, the on-disk frame bytes handed back as a single
//!   refcounted `bytes::Bytes` slice. NO body decode, NO per-record re-encode: the stored frames ARE
//!   the batch (the consumer decodes them end-to-end, validating the per-frame CRC that rode along).
//!
//! The expected result: the zero-copy read is a large multiple faster on this run, because it does ONE
//! allocation and ZERO per-record decode/encode where the materialize path does N decodes plus a
//! payload copy per record. The gap IS the consume throughput lever this issue targets, measured at
//! the storage read boundary (the wire `sendfile(2)` + `DeliverBatch` framing that turns this into a
//! zero-USER-SPACE-copy socket write is the deferred follow-up; see #542 / #541).
//!
//! What it measures and what it does NOT: the log is opened over the in-memory `InMemoryFs`, so the
//! work is the real codec decode + CRC32C + buffer/copy cost reading from memory rather than a device.
//! It models the wire-body re-encode inline (the storage crate sits below `ironbus-proto`, so it does
//! not link the proto codec) using the SAME field layout the `Deliver` body codec writes, so the
//! BEFORE cost is faithful. Run on demand (`cargo bench -p ironbus-storage`), NOT in per-PR CI; the
//! full consume-vs-NATS leg is #554.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ironbus_core::clock::ManualClock;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::read_plane::ReadPlane;
use ironbus_storage::segment::OwnedRecord;

/// Records to pre-seal into the prefix. A small segment cap rolls these into many sealed segments, so
/// both planes seek/scan the sealed snapshot the way a replaying streaming consumer does.
const RECORDS: u64 = 4096;

/// Payload sizes to sweep: a small record (framing/decode-dominated) and a larger one (copy-dominated).
/// The zero-copy win grows with payload size (the materialize path copies every payload byte into the
/// wire buffer; the zero-copy path never touches it).
const PAYLOADS: [usize; 3] = [16, 256, 4096];

/// Records pulled per fetch (a representative streaming batch). Both planes serve `[0, BATCH)` from the
/// sealed prefix — the same run, so the only difference is the decode+re-encode the zero-copy path
/// removes.
const BATCH: usize = 64;

/// Builds one in-memory log with `RECORDS` records of `payload_len`-byte payloads pre-sealed into many
/// small segments, synced so the whole prefix is flushed and visible, plus its off-actor read plane.
fn sealed_log(payload_len: usize) -> (Log<InMemoryFs, ManualClock>, ReadPlane<InMemoryFs>) {
    let config = LogConfig {
        max_segment_bytes: 1 << 16,
        max_total_bytes: 0,
        ..LogConfig::default()
    };
    let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), config).expect("open log");
    let payload = vec![0xABu8; payload_len];
    for i in 0..RECORDS {
        let _ = log
            .append(&Append {
                timestamp_ms: 1 + i,
                flags: RecordFlags::EMPTY,
                key: b"route-key",
                headers: b"h",
                payload: &payload,
            })
            .expect("append");
        if i % 16 == 0 {
            log.sync().expect("sync");
        }
    }
    log.sync().expect("final sync");
    let plane = log.read_plane().expect("build read plane");
    (log, plane)
}

/// Re-encodes one record into a wire-delivery body the way the `Deliver` body codec does: the fixed
/// fields, then the length-prefixed key/headers, then the payload copied in. This is the per-record
/// cost the MATERIALIZE+ENCODE path pays and the zero-copy path removes. Modeled inline because the
/// storage crate sits below `ironbus-proto` and does not link its codec; the field layout matches.
fn encode_deliver_like(rec: &OwnedRecord, out: &mut Vec<u8>) {
    out.extend_from_slice(&rec.offset.get().to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // generation (0 on Tier-S)
    out.push(rec.flags.bits());
    out.extend_from_slice(&rec.timestamp_ms.to_le_bytes());
    out.extend_from_slice(
        &u16::try_from(rec.key.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&rec.key);
    out.extend_from_slice(
        &u16::try_from(rec.headers.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&rec.headers);
    out.extend_from_slice(&rec.payload); // the payload copy the zero-copy path never makes
}

fn bench_zero_copy_delivery(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy_delivery");
    for &payload_len in &PAYLOADS {
        let (_log, plane) = sealed_log(payload_len);

        // BEFORE: read_range materializes OwnedRecords (decode + slices), then re-encode each into the
        // wire-delivery buffer (the per-record copy). One reusable output buffer, as the session has.
        group.bench_with_input(
            BenchmarkId::new("materialize_encode", payload_len),
            &payload_len,
            |b, _| {
                let plane = plane.clone();
                let mut out = Vec::with_capacity(BATCH * (payload_len + 64));
                b.iter(|| {
                    out.clear();
                    let read = plane
                        .read_range(Offset::ZERO, BATCH, None)
                        .expect("materialize read");
                    for rec in &read.records {
                        encode_deliver_like(rec, &mut out);
                    }
                    black_box(out.len());
                });
            },
        );

        // AFTER: read_range_raw hands back the contiguous run as one Bytes slice — no decode, no
        // re-encode, no payload copy. The bytes ARE the batch the consumer decodes end-to-end.
        group.bench_with_input(
            BenchmarkId::new("zero_copy_raw", payload_len),
            &payload_len,
            |b, _| {
                let plane = plane.clone();
                b.iter(|| {
                    let raw = plane
                        .read_range_raw(Offset::ZERO, BATCH, None)
                        .expect("zero-copy read");
                    // The "write" is shipping `raw.run.bytes` verbatim; here we just observe its size
                    // and record count, the work the broker does on this path (no copy, no decode).
                    black_box(raw.run.bytes.len());
                    black_box(raw.run.record_count);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_zero_copy_delivery);
criterion_main!(benches);
