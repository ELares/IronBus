// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmark for the consume read locate (#537, the #483 spine).
//!
//! This isolates the cost of LOCATING a record in a segment on the consume hot path, which the
//! consumer pays once per delivery (the engine reads `read_from(off, 1)` per record). It compares
//! two strategies over a single segment packed with many small records:
//!
//! - BEFORE (the pre-#483/#537 behavior): each delivery FULL-SCANS the segment from its base —
//!   `SegmentReader::scan()` decodes and double-CRCs EVERY record, then all but the requested one
//!   are discarded. Delivering a batch of N records is then `O(N * records-per-segment)`: quadratic
//!   in the segment's record count.
//! - AFTER (this issue): `Log::read_from(off, 1)` SEEKS via the resident SPARSE byte index to the
//!   nearest anchor at or before the offset and scans forward a BOUNDED (`<= stride` bytes) number
//!   of frames to the exact record, so a delivery is `O(stride)` — a small constant independent of
//!   the segment's record count. The index itself is `O(region_bytes / stride)` resident, far below
//!   the dense one-entry-per-record it replaces.
//!
//! What it measures, and what it deliberately does NOT: the log is opened over the in-memory
//! [`InMemoryFs`] (the deterministic-simulation backend), so the work is the real codec decode +
//! CRC32C + the seek/scan logic, reading from memory rather than a device — disk-flush latency is
//! device-dependent and is owned by the macro rig, not a stable micro-benchmark. It runs on demand
//! (`cargo bench -p ironbus-storage`), NOT in per-PR CI; the full consume-vs-NATS leg is #554.
//!
//! Inputs are fixed bytes so a run is deterministic, and `black_box` hides them from the optimizer.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ironbus_core::clock::ManualClock;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::naming::segment_file_name;
use ironbus_storage::segment::SegmentReader;

/// Segment record counts to sweep. The BEFORE (full-scan) cost grows with this; the AFTER (seek)
/// cost is flat, so the gap WIDENS as the segment packs more records — the quadratic-vs-constant
/// story. Kept to a single large segment (no rolling) so the locate cost is what is measured.
const RECORD_COUNTS: [u64; 3] = [256, 1024, 4096];

/// A small fixed payload, so a frame is framing-dominated and many records pack into one segment
/// (maximizing the records-per-segment the BEFORE path must scan).
const PAYLOAD: &[u8] = b"detection-row";

/// How many distinct offsets are delivered per measured iteration (a representative consume batch),
/// each via a single-record read — the per-delivery locate the consumer actually issues.
const BATCH: u64 = 32;

/// Builds one in-memory log with all `count` records in a SINGLE segment (an 8 MiB cap, far above
/// the framed bytes for these counts), synced so every record is visible and in the file.
fn packed_log(count: u64) -> Log<InMemoryFs, ManualClock> {
    let config = LogConfig {
        max_segment_bytes: 8 * 1024 * 1024,
        ..LogConfig::default()
    };
    let mut log =
        Log::open(InMemoryFs::new(), ManualClock::new(), config).expect("open in-memory log");
    let record = Append {
        timestamp_ms: 1_700_000_000_000,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: PAYLOAD,
    };
    for _ in 0..count {
        log.append(&record).expect("a tiny record always fits");
    }
    log.sync().expect("sync the batch");
    log
}

/// The BEFORE locate: full-scan the segment and take the record at `offset`, the pre-#483 behavior
/// the consumer paid PER delivery. Returns the payload length so the optimizer cannot elide it.
fn locate_by_full_scan(log: &Log<InMemoryFs, ManualClock>, offset: u64) -> usize {
    // Segment 0 holds the whole packed batch (no rolling at an 8 MiB cap for these counts).
    let reader =
        SegmentReader::open(log.filesystem().open(&segment_file_name(0)).unwrap()).unwrap();
    let scan = reader.scan().unwrap();
    scan.records
        .into_iter()
        .find(|r| r.offset.get() == offset)
        .map_or(0, |r| r.payload.len())
}

fn bench_read_seek(c: &mut Criterion) {
    let mut group = c.benchmark_group("consume_locate");
    for &count in &RECORD_COUNTS {
        let log = packed_log(count);
        // Deliver BATCH evenly-spread offsets across the segment (a representative consume sweep).
        let step = (count / BATCH).max(1);
        let offsets: Vec<u64> = (0..BATCH).map(|i| (i * step) % count).collect();

        group.bench_with_input(
            BenchmarkId::new("before_full_scan", count),
            &offsets,
            |b, offsets| {
                b.iter(|| {
                    let mut total = 0usize;
                    for &off in offsets {
                        total += locate_by_full_scan(black_box(&log), black_box(off));
                    }
                    black_box(total);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("after_sparse_seek", count),
            &offsets,
            |b, offsets| {
                b.iter(|| {
                    let mut total = 0usize;
                    for &off in offsets {
                        let recs = log.read_from(Offset::new(black_box(off)), 1).unwrap();
                        total += recs.first().map_or(0, |r| r.payload.len());
                    }
                    black_box(total);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_read_seek);
criterion_main!(benches);
