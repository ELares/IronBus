// SPDX-License-Identifier: MIT OR Apache-2.0
//! ASYNC TIER-S STREAMING CONSUME: the tokio twin of the synchronous `streaming_consumer` example.
//!
//! Same model as the sync client (same wire, same types): negotiate Tier-S in the handshake,
//! `subscribe` to mark the group streaming, then pull the log in WINDOWS with
//! [`AsyncStreamingConsumer::next_batch`], which advances the cursor, prefetches the next window, and
//! commits the cumulative offset periodically. The caller processes each window and awaits the next —
//! it does NOT ack records individually. Delivery is at-least-once:
//! `[committed_offset(), next_offset())` redelivers on a crash, so processing must be idempotent, and
//! [`AsyncStreamingConsumer::finish`] flushes a final commit so a rerun resumes from the durable cursor.
//!
//! One `AsyncClient` per task: the wire is request-response FIFO per connection.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client-async --example streaming_consumer_async
//! cargo run -p ironbus-client-async --example streaming_consumer_async -- 127.0.0.1:7777
//! ```

use ironbus_client_async::proto::{ConsumeTier, PubBody};
use ironbus_client_async::{AsyncClient, ClientConfig};

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();

    // Seed a durable prefix for the streaming consumer to read.
    let mut producer = AsyncClient::connect(addr.as_str()).await?;
    let seeded = 25u64;
    for i in 0..seeded {
        let payload = format!("event-{i}");
        producer
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: now_ms(),
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: payload.as_bytes(),
            })
            .await?;
    }
    println!("seeded {seeded} records");

    // Negotiate Tier-S in the handshake, then subscribe (which marks the group streaming server-side).
    let config = ClientConfig {
        understands_streaming: true,
        default_consume_tier: Some(ConsumeTier::Streaming),
        ..ClientConfig::default()
    };
    let mut consumer = AsyncClient::connect_with(addr.as_str(), &config).await?;
    assert!(
        consumer.streaming_enabled(),
        "the broker did not confirm the streaming tier"
    );
    consumer.subscribe("example-async-stream-reader").await?;
    println!("connected to {addr} with Tier-S streaming negotiated");

    let mut stream = consumer.streaming_consumer("example-async-stream-reader");
    let mut total = 0u64;
    loop {
        let batch = stream.next_batch().await?;
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

    let committed = stream.finish().await?;
    println!("done: streamed {total} records; durable cursor now at offset {committed}");
    Ok(())
}
