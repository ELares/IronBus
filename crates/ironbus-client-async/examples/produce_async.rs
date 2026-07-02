// SPDX-License-Identifier: MIT OR Apache-2.0
//! ASYNC PRODUCE: the tokio twin of the synchronous `produce` example.
//!
//! [`AsyncClient`] speaks the EXACT same wire as the blocking client — every produce shape, every
//! guarantee, every returned type is shared — only the IO is tokio. The wire is request-response
//! FIFO per connection, so every method takes `&mut self` and awaits its own reply; for concurrent
//! producers, open one `AsyncClient` per task.
//!
//! Three durable produce shapes:
//!
//! 1. [`AsyncClient::produce`]        — awaited, durable-on-return (ack-implies-durable).
//! 2. [`AsyncClient::produce_dedup`]  — the same, plus the opt-in effectively-once dedup window
//!    (a retried `msg_id` acks the ORIGINAL offset with `duplicate = true`).
//! 3. [`AsyncClient::produce_window`] — a PIPELINED window: every frame is written before any ack
//!    is awaited, so the broker's group commit covers the window with ONE fsync.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client-async --example produce_async
//! cargo run -p ironbus-client-async --example produce_async -- 127.0.0.1:7777
//! ```

use ironbus_client_async::proto::{PubBody, PubDedup};
use ironbus_client_async::AsyncClient;

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

// The crate enables tokio's single-threaded runtime (`rt`); the client is one connection driven
// by one task, so the current-thread flavor is all an example needs.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();
    let mut client = AsyncClient::connect(addr.as_str()).await?;
    println!("connected to {addr}");

    // ---- 1. The awaited, durable-on-return produce -------------------------------------------
    // When the future resolves, the record is fsynced-durable on the broker and `offset` names it
    // in the log forever. See the sync `produce` example for every `PubBody` field's story.
    let offset = client
        .produce(&PubBody {
            flags: 0,
            timestamp_ms: now_ms(),
            key: b"sensor-42",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"temperature=21.5",
        })
        .await?;
    println!("produce: durable at offset {offset}");

    // ---- 2. The idempotent (dedup) produce ----------------------------------------------------
    // Attach a dedup block (stable producer_id, fencing epoch, idempotency key msg_id) and a
    // timeout-retry of the same publish becomes a benign duplicate ack, not a second record.
    let msg_id = format!("order-{}", now_ms());
    let order = PubBody {
        flags: 0,
        timestamp_ms: now_ms(),
        key: b"orders",
        headers: b"",
        dedup: Some(PubDedup {
            producer_id: b"example-async-producer",
            epoch: 1,
            msg_id: msg_id.as_bytes(),
            seq: None,
        }),
        fire_and_forget: false,
        payload: b"{\"item\":\"widget\",\"qty\":3}",
    };
    let first = client.produce_dedup(&order).await?;
    let retry = client.produce_dedup(&order).await?; // simulated timeout retry, same msg_id
    println!(
        "produce_dedup: first offset {} (duplicate: {}), retry offset {} (duplicate: {})",
        first.offset, first.duplicate, retry.offset, retry.duplicate
    );

    // ---- 3. The pipelined window ---------------------------------------------------------------
    // All 128 `Pub` frames are written before any ack is awaited, so the broker group-commits the
    // whole window under one fsync. The acks come back FIFO — the Nth ack belongs to the Nth
    // message — and every ack still means fsynced-durable. Keep the window bounded.
    let payloads: Vec<String> = (0..128).map(|i| format!("event-{i}")).collect();
    let window: Vec<PubBody<'_>> = payloads
        .iter()
        .map(|p| PubBody {
            flags: 0,
            timestamp_ms: now_ms(),
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p.as_bytes(),
        })
        .collect();
    let acks = client.produce_window(&window).await?;
    println!(
        "produce_window: {} durable acks, offsets {}..={}",
        acks.len(),
        acks.first().map_or(0, |a| a.offset),
        acks.last().map_or(0, |a| a.offset)
    );

    Ok(())
}
