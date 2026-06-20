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
use ironbus_server::engine::{
    DiskFullPolicy, Engine, EngineConfig, Poll, DEFAULT_GROUP_IDLE_EVICT_MS, DEFAULT_MAX_GROUPS,
};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::log::{Append, LogConfig};

fn config() -> EngineConfig {
    EngineConfig {
        log: LogConfig::default(),
        lease: LeaseConfig::from_millis(1000, 5000),
        delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
        max_in_flight: 16,
        consumer_credit: 64,
        // Unlimited byte budget (#275): `0` = off, so the determinism image is unchanged by the new
        // field (the message-count credit alone bounds delivery in this image).
        consumer_credit_bytes: 0,
        // Checkpoint on every commit, so the durable cursor checkpoint is exercised and part
        // of the compared image.
        checkpoint_interval: 1,
        // Retention off (the default), so the determinism image is unchanged.
        max_retained_bytes: 0,
        max_age_ms: 0,
        max_messages: 0,
        // The default work-group cap (#240): the determinism image is unchanged by this field.
        max_groups: DEFAULT_MAX_GROUPS,
        // Idle named-group eviction OFF (#277), the default: the determinism image is unchanged.
        group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
        ram_ceiling_bytes: 0,
        // Drop-new (the default): the determinism image is unchanged by the new policy field.
        disk_full_policy: DiskFullPolicy::DropNew,
        dedup: ironbus_core::dedup::DedupConfig::default(),
        durability_level: ironbus_server::engine::DurabilityLevel::Sync,
        flush_interval_ms: 0,
        flush_max_bytes: 0,
        // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
        // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
        codel_target_ms: 0,
        codel_interval_ms: 0,
        retry_budget_ratio_per_million: 0,
        retry_budget_window_ms: 0,
        fire_and_forget_msg_rate: 0,
        fire_and_forget_byte_rate: 0,
        fire_and_forget_refill_ms: 0,
        egress_limit: 0,
        wal_fsync_headroom_bytes: 0,
        // Compression OFF (#430): the determinism image is unchanged by the new compression
        // field; the lz4 determinism case builds its config explicitly.
        compression: ironbus_core::compress::Codec::None,
        // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
        // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
        default_message_ttl_ms: 0,
        dead_letter_exchange: None,
        dead_letter_expired: false,
    }
}

/// Produces three messages, polls and acks each, then checkpoints the durable cursor: `ack`
/// only advances the cursor in memory, so `maybe_checkpoint` is what actually persists it to
/// `cursor.ckpt` (exactly as the server session loop does). Returns the full disk image
/// (segments AND a non-empty `cursor.ckpt`) as a sorted list of (file name, bytes).
fn run_workload() -> Vec<(String, Vec<u8>)> {
    run_workload_with(config(), &[&b"a"[..], b"b", b"c"])
}

/// [`run_workload`], parameterized over the engine config and the produced payloads, so the lz4
/// determinism case (#430) drives the same lifecycle with write-path compression on and payloads
/// large enough (>= the 64-byte raw-store threshold) that the codec genuinely runs.
fn run_workload_with(config: EngineConfig, payloads: &[&[u8]]) -> Vec<(String, Vec<u8>)> {
    let mut engine = Engine::open(InMemoryFs::new(), ManualClock::new(), config).unwrap();
    for payload in payloads {
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
    for _ in 0..payloads.len() {
        match engine.poll(0).unwrap() {
            Poll::Message(d) => {
                engine.ack(&d.token);
            }
            other => panic!("expected a message, got {other:?}"),
        }
    }
    // ack only advances the in-memory cursor; the session loop is what checkpoints it. Do that
    // here so cursor.ckpt is actually written (committed advanced 3 >= the interval of 1), and
    // its bytes are part of the compared image.
    assert!(
        engine.maybe_checkpoint().unwrap(),
        "the cursor checkpoint should have been written"
    );
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
    // The cursor checkpoint must be present AND non-empty, so the byte comparison genuinely
    // covers the checkpoint write path (not an empty, never-written file).
    let ckpt = first.iter().find(|(name, _)| name.contains("ckpt"));
    assert!(
        ckpt.is_some_and(|(_, bytes)| !bytes.is_empty()),
        "the cursor checkpoint should be written and non-empty, got {:?}",
        first
            .iter()
            .map(|(n, b)| (n.as_str(), b.len()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        first, second,
        "the engine lifecycle is not deterministic: ambient time or randomness leaked into the \
         disk image (segments or the cursor checkpoint)"
    );
}

#[test]
fn the_lz4_lifecycle_produces_a_byte_identical_disk_image() {
    // The same determinism property with write-path compression ON (#430): lz4 (`lz4_flex` block
    // compression) is a pure function of its input, so two identical runs under the manual clock
    // still produce byte-identical images. The payloads are repeated text well over the 64-byte
    // raw-store threshold, so the codec genuinely runs (the COMPRESSED flag is set on disk); a
    // run-vs-run comparison deliberately avoids freezing the compressed bytes themselves, which
    // would couple the format gate to the `lz4_flex` version.
    let lz4_config = || EngineConfig {
        compression: ironbus_core::compress::Codec::Lz4,
        ..config()
    };
    let big_a = b"alpha ".repeat(64);
    let big_b = b"beta ".repeat(64);
    let big_c = b"gamma ".repeat(64);
    let payloads: [&[u8]; 3] = [&big_a, &big_b, &big_c];
    let first = run_workload_with(lz4_config(), &payloads);
    let second = run_workload_with(lz4_config(), &payloads);
    assert_eq!(
        first, second,
        "the lz4 write path is not deterministic: run-vs-run images differ"
    );
    // Non-vacuity: the compressed image is genuinely smaller than the raw-store image of the
    // same workload, so this test really exercised the codec, not three raw stores.
    let none_image = run_workload_with(config(), &payloads);
    let total =
        |image: &[(String, Vec<u8>)]| -> usize { image.iter().map(|(_, bytes)| bytes.len()).sum() };
    assert!(
        total(&first) < total(&none_image),
        "the lz4 image ({}) undercuts the raw image ({}), proving compression ran",
        total(&first),
        total(&none_image)
    );
}
