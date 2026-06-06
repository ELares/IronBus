// SPDX-License-Identifier: MIT OR Apache-2.0
//! Engine-level determinism (#119): the full produce / poll / ack lifecycle, including the
//! durable consumer-cursor checkpoint, must be a pure function of its inputs. The storage
//! determinism gate covers the segment bytes; this extends it to the engine and the
//! `cursor.ckpt` file. Two identical runs, under a fresh manual clock, produce a byte-identical
//! disk image, so ambient time or randomness leaking into the checkpoint (or the engine's
//! write path) would fail here.

use ironbus_core::clock::ManualClock;
use ironbus_core::delivery::DeliveryConfig;
use ironbus_core::lease::LeaseConfig;
use ironbus_core::types::RecordFlags;
use ironbus_server::engine::{Engine, EngineConfig, Poll};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::log::{Append, LogConfig};

fn config() -> EngineConfig {
    EngineConfig {
        log: LogConfig::default(),
        lease: LeaseConfig::from_millis(1000, 5000),
        delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
        max_in_flight: 16,
        // Checkpoint on every commit, so the durable cursor checkpoint is exercised and part
        // of the compared image.
        checkpoint_interval: 1,
    }
}

/// Produces three messages, then polls and acks each (advancing and checkpointing the durable
/// cursor), and returns the full disk image (segments AND `cursor.ckpt`) as a sorted list of
/// (file name, bytes).
fn run_workload() -> Vec<(String, Vec<u8>)> {
    let mut engine = Engine::open(InMemoryFs::new(), ManualClock::new(), config()).unwrap();
    for payload in [&b"a"[..], b"b", b"c"] {
        engine
            .produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
    }
    for _ in 0..3 {
        match engine.poll(0).unwrap() {
            Poll::Message(d) => {
                engine.ack(&d.token);
            }
            other => panic!("expected a message, got {other:?}"),
        }
    }
    let fs = engine.into_filesystem();
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
fn the_same_engine_lifecycle_produces_a_byte_identical_disk_image() {
    let first = run_workload();
    let second = run_workload();
    assert!(
        first.iter().any(|(name, _)| name.contains("ckpt")),
        "the durable cursor checkpoint is part of the compared image, got {:?}",
        first.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    assert_eq!(
        first, second,
        "the engine lifecycle is not deterministic: ambient time or randomness leaked into the \
         disk image (segments or the cursor checkpoint)"
    );
}
