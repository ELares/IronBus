// SPDX-License-Identifier: MIT OR Apache-2.0
//! Determinism meta-test (#119): the storage layer must be a pure function of its inputs,
//! with no ambient time or randomness leaking into the on-disk bytes. The deterministic
//! simulation and crash-class reproduction both rely on this: a seed (or a fixed workload)
//! must always produce the same disk image.
//!
//! Two runs of the same workload, under a fresh manual clock, must produce a byte-identical
//! disk image. This fails the moment a `SystemTime`, `Instant::now`, or ambient RNG creeps
//! into a header, record, or footer, which the design forbids (IO/clock go through seams).

use ironbus_core::clock::ManualClock;
use ironbus_core::partition::PartitionCount;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::partitioned::PartitionedStream;
use ironbus_storage::streamset::{StreamId, StreamSet};

/// A small cap so the workload rolls across several segments (exercising the per-segment
/// header, whose `created_unix_ms` comes from the clock seam, and the sealed footers).
fn small_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 256,
        max_total_bytes: 0,
        ..LogConfig::default()
    }
}

/// Runs a fixed produce/sync workload and returns the full disk image as a sorted list of
/// (file name, bytes). Every input is explicit: the timestamps are part of the workload, not
/// read from a wall clock, and the clock starts at a fixed zero.
fn run_workload() -> Vec<(String, Vec<u8>)> {
    let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
    for i in 0..24u64 {
        let payload = i.to_le_bytes();
        log.append(&Append {
            timestamp_ms: i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        })
        .unwrap();
        log.sync().unwrap();
    }
    let fs = log.into_filesystem();
    let mut image: Vec<(String, Vec<u8>)> = fs
        .list()
        .unwrap()
        .into_iter()
        .map(|name| {
            let bytes = fs.open(&name).unwrap().snapshot();
            (name, bytes)
        })
        .collect();
    image.sort();
    image
}

#[test]
fn the_same_workload_produces_a_byte_identical_disk_image() {
    let first = run_workload();
    let second = run_workload();
    assert!(
        first.len() >= 2,
        "the workload should span multiple segments, got {}",
        first.len()
    );
    assert_eq!(
        first, second,
        "the storage layer is not deterministic: ambient time or randomness leaked into the \
         on-disk bytes"
    );
}

// ---------------------------------------------------------------------------------------------
// #964: extend the determinism gate to the MULTI-STREAM / MULTI-PARTITION workload so the standing
// gate exercises #822's parallel recovery (`par_recover_open`) instead of only the single default
// `Log`. The single-`Log` gate above opens exactly one root log (no `streams/` subtree, one
// partition), so it never drives the bounded outer worker pool that opens N named streams / P
// partitions in parallel. These workloads build > the worker cap of byte-isolated subtrees, COLD
// REOPEN them (so the parallel path runs), and fold BOTH the full on-disk image AND the recovered
// per-subtree view into one fingerprint. Two runs under a fresh manual clock must agree byte-for
// -byte: ambient time/randomness in the multi-subtree WRITE path, OR any worker-order
// non-determinism in the parallel-recovery REASSEMBLY (a wrong subtree getting a sibling's records),
// would diverge here.

/// A record with a fixed producer timestamp (part of the workload, never a wall clock).
fn record(payload: &[u8]) -> Append<'_> {
    Append {
        timestamp_ms: 3,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload,
    }
}

/// The FULL durable image of `fs`: this level's files AND every subtree the multi-stream /
/// partitioned layouts create (`streams/<hex>/…`, `p-<hex>/…`), as a sorted list of (path, bytes).
/// The flat [`Filesystem::list`] the single-`Log` gate uses reports only the root files, so it would
/// silently MISS the parallel subtrees' bytes; this descends them so the comparison covers them.
fn full_image(fs: &InMemoryFs, prefix: &str) -> Vec<(String, Vec<u8>)> {
    let mut image: Vec<(String, Vec<u8>)> = fs
        .list()
        .unwrap()
        .into_iter()
        .map(|name| {
            let bytes = fs.open(&name).unwrap().snapshot();
            (format!("{prefix}{name}"), bytes)
        })
        .collect();
    for dir in fs.list_subdirs().unwrap() {
        let child = fs.subdir(&dir).unwrap();
        image.extend(full_image(&child, &format!("{prefix}{dir}/")));
    }
    image.sort();
    image
}

/// `> RECOVERY_OPEN_MAX_WORKERS` (8), so the parallel open genuinely steals work off the shared
/// cursor rather than running inline.
const PARALLEL_FANOUT: usize = 12;

/// Builds a [`StreamSet`] of many named streams (each a byte-isolated subtree under `streams/`),
/// COLD-REOPENS it (driving #822's `par_recover_open` over > the worker cap), and returns a
/// fingerprint of BOTH the full on-disk image and the recovered per-stream payloads + loss summary.
/// Stream `i` gets `i+1` records tagged with `(i, r)`, so a mis-assembled (worker-order) recovery —
/// a stream holding a sibling's records — would diverge the read-back across the two runs.
fn run_streamset_workload() -> Vec<(String, Vec<u8>)> {
    let fs = InMemoryFs::new();
    let ids: Vec<StreamId> = (0..PARALLEL_FANOUT)
        .map(|i| StreamId::named(&format!("s{i:03}")).unwrap())
        .collect();
    {
        let (mut set, _) = StreamSet::open(&fs, ManualClock::new(), small_config()).unwrap();
        for (i, id) in ids.iter().enumerate() {
            set.declare(id).unwrap();
            for r in 0..=i {
                set.append_to(id, &record(format!("s{i:03}-r{r}").as_bytes()))
                    .unwrap();
            }
        }
        set.sync_all().unwrap();
    }
    // COLD REOPEN => #822 parallel recovery across the > worker-cap named subtrees.
    let (set, recoveries) = StreamSet::open(&fs, ManualClock::new(), small_config()).unwrap();
    let mut fingerprint = full_image(&fs, "");
    for id in set.stream_ids() {
        let read = set.read_range(&id, Offset::ZERO, 10_000, None).unwrap();
        let mut payloads = Vec::new();
        for r in &read {
            payloads.extend_from_slice(&r.payload);
            payloads.push(b'\n');
        }
        fingerprint.push((format!("recovered:{}", id.name()), payloads));
        fingerprint.push((
            format!("loss:{}", id.name()),
            recoveries[&id]
                .recovered_truncated_bytes
                .to_le_bytes()
                .into(),
        ));
    }
    fingerprint.sort();
    fingerprint
}

/// Builds a [`PartitionedStream`] of `P` partitions (each a byte-isolated `p-<hex>/` subtree),
/// COLD-REOPENS it (driving #822's `par_recover_open` over `P >` the worker cap), and returns a
/// fingerprint of BOTH the full on-disk image and the recovered per-partition payloads + loss
/// summary. Keyless round-robin appends spread the records deterministically across every partition.
fn run_partitioned_workload() -> Vec<(String, Vec<u8>)> {
    let fs = InMemoryFs::new();
    let count = PartitionCount::new(u32::try_from(PARALLEL_FANOUT).unwrap()).unwrap();
    {
        let (mut stream, _) =
            PartitionedStream::open(&fs, ManualClock::new(), small_config(), count).unwrap();
        // Round-robin keyless appends give every partition several records in a deterministic order.
        for n in 0..PARALLEL_FANOUT * 3 {
            stream
                .append_keyless(&record(format!("r{n:03}").as_bytes()))
                .unwrap();
        }
        stream.sync_all().unwrap();
    }
    // COLD REOPEN => #822 parallel recovery across the P > worker-cap partition subtrees.
    let (stream, recoveries) =
        PartitionedStream::open(&fs, ManualClock::new(), small_config(), count).unwrap();
    let mut fingerprint = full_image(&fs, "");
    for p in 0..count.get() {
        let idx = ironbus_core::partition::PartitionIndex::new(p);
        let read = stream.read_range(idx, Offset::ZERO, 10_000, None).unwrap();
        let mut payloads = Vec::new();
        for r in &read {
            payloads.extend_from_slice(&r.payload);
            payloads.push(b'\n');
        }
        fingerprint.push((format!("recovered:p{p}"), payloads));
        fingerprint.push((
            format!("loss:p{p}"),
            recoveries[p as usize]
                .recovered_truncated_bytes
                .to_le_bytes()
                .into(),
        ));
    }
    fingerprint.sort();
    fingerprint
}

#[test]
fn the_multi_stream_workload_recovers_byte_identically_across_runs() {
    let first = run_streamset_workload();
    let second = run_streamset_workload();
    // Non-vacuity: the `streams/` subtree is present, so the parallel-open path really ran (this is
    // NOT the single-default-`Log` image the gate above already covers).
    assert!(
        first.iter().any(|(path, _)| path.starts_with("streams/")),
        "the workload should materialize the streams/ subtree, got {:?}",
        first.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(
        first, second,
        "the multi-stream write+parallel-recovery path is not deterministic: ambient time/\
         randomness in the write, or worker-order non-determinism in the parallel reassembly, \
         leaked into the recovered image"
    );
}

#[test]
fn the_partitioned_workload_recovers_byte_identically_across_runs() {
    let first = run_partitioned_workload();
    let second = run_partitioned_workload();
    // Non-vacuity: more than one `p-*/` partition subtree materialized, so the parallel-open path
    // (P > 1) really ran rather than the single-partition inline open.
    let partition_dirs = first
        .iter()
        .filter_map(|(path, _)| path.split_once('/').map(|(head, _)| head))
        .filter(|head| head.starts_with("p-"))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        partition_dirs.len() > 1,
        "the workload should materialize >1 partition subtree, got {partition_dirs:?}"
    );
    assert_eq!(
        first, second,
        "the partitioned write+parallel-recovery path is not deterministic: ambient time/\
         randomness in the write, or worker-order non-determinism in the parallel reassembly, \
         leaked into the recovered image"
    );
}
