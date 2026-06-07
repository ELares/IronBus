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
use ironbus_core::types::RecordFlags;
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::log::{Append, Log, LogConfig};

/// A small cap so the workload rolls across several segments (exercising the per-segment
/// header, whose `created_unix_ms` comes from the clock seam, and the sealed footers).
fn small_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 256,
        max_total_bytes: 0,
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
