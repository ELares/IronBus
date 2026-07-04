// SPDX-License-Identifier: MIT OR Apache-2.0
//! TIER-S STREAMING CONSUME: high-throughput replay with periodic cumulative commit.
//!
//! The work-group consumer ([`Client::fetch`] + per-lease [`Client::ack`], see the
//! `consume_ack_group` example) leases each record and settles it individually — the model for a
//! COMPETING pool where any worker may take any record. The Tier-S STREAMING consumer is the other
//! model: a single ordered reader that pulls the log in WINDOWS by offset and commits its cursor
//! CUMULATIVELY (not per record), the shape a throughput drain or a replay wants.
//!
//! Tier-S is a NEGOTIATED capability. The connection advertises it (via [`ClientConfig::understands_streaming`]
//! and a streaming [`ClientConfig::default_consume_tier`]); the `subscribe` then marks the group
//! streaming server-side, and [`Client::streaming_consumer`] rides that wiring. [`StreamingConsumer::next_batch`]
//! fetches the next window, advances the cursor, PREFETCHES the window after it (bounded read-ahead),
//! and commits the cumulative offset every few windows. The caller processes each window and calls
//! `next_batch` again — it does NOT ack records one by one.
//!
//! Delivery is at-least-once: everything in `[committed_offset(), next_offset())` redelivers on a
//! crash, so processing must be idempotent. [`StreamingConsumer::finish`] flushes a final commit, so a
//! rerun of this example resumes from the durable cursor and sees only new records.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client --example streaming_consumer
//! cargo run -p ironbus-client --example streaming_consumer -- 127.0.0.1:7777
//! ```

use ironbus_client::{Client, ClientConfig};
use ironbus_proto::message::{ConsumeTier, PubBody};

/// The broker address: the first CLI argument, else `IRONBUS_ADDR`, else the loopback default.
fn broker_addr() -> String {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("IRONBUS_ADDR").ok())
        .unwrap_or_else(|| "127.0.0.1:7777".to_string())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();

    // Seed a durable prefix for the streaming consumer to read (one connection could produce and
    // stream; two mirror a real topology).
    let mut producer = Client::connect(&addr)?;
    let seeded = 25u64;
    for i in 0..seeded {
        let payload = format!("event-{i}");
        producer.produce(&PubBody {
            flags: 0,
            timestamp_ms: now_ms(),
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: payload.as_bytes(),
        })?;
    }
    println!("seeded {seeded} records");

    // Negotiate the streaming tier in the handshake: advertise that this client understands Tier-S
    // AND request it as the connection default, so the `subscribe` below marks the group streaming
    // server-side (which is what makes `stream_fetch` / `stream_commit` accepted). `streaming_enabled()`
    // reports the negotiated AND of client-advertised and server-confirmed.
    let config = ClientConfig {
        understands_streaming: true,
        default_consume_tier: Some(ConsumeTier::Streaming),
        ..ClientConfig::default()
    };
    let mut consumer = Client::connect_with(&addr, &config)?;
    assert!(
        consumer.streaming_enabled(),
        "the broker did not confirm the streaming tier"
    );
    // The streaming group's committed cursor is durable broker-side state, keyed by this group name.
    consumer.subscribe("example-stream-reader")?;
    println!("connected to {addr} with Tier-S streaming negotiated");

    // Open the batched-default streaming consumer. Its window size and commit cadence come from
    // `StreamConsumerConfig::default()`; `streaming_consumer_with` takes an explicit config to tune
    // the window / cadence / start offset / read-ahead.
    let mut stream = consumer.streaming_consumer("example-stream-reader");

    let mut total = 0u64;
    // Pull windows until the stream drains to its durable head (an EMPTY window). Each `next_batch`
    // advances the cursor and periodically commits it; we never ack individual records.
    loop {
        let batch = stream.next_batch()?;

        // A window can also carry in-band advisories (dead-letter / truncation / gap notices) exactly
        // like a work-group fetch — a real reader should at least log them.
        for gap in &batch.gaps {
            println!(
                "advisory: offsets [{}, {}) were skipped (a retention reap)",
                gap.from, gap.to
            );
        }

        if batch.is_empty() {
            break;
        }
        for m in &batch.messages {
            total += 1;
            if total <= 3 || total % 10 == 0 {
                println!(
                    "processed #{total}: {:?}",
                    String::from_utf8_lossy(&m.payload)
                );
            }
        }
    }

    // Flush a final commit and report the durable cursor. A rerun resumes from here: it will see
    // only records produced after this point, because the periodic + final commits advanced the
    // group's durable offset cumulatively.
    let committed = stream.finish()?;
    println!("done: streamed {total} records; durable cursor now at offset {committed}");
    Ok(())
}
