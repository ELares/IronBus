// SPDX-License-Identifier: MIT OR Apache-2.0
//! ASYNC CONSUME + ACK: the tokio twin of the synchronous `consume_ack_group` example.
//!
//! The model is identical to the sync client (same wire, same types): SUBSCRIBE to a competing
//! work-group, FETCH batches, and settle every delivered lease with its `(offset, generation)`
//! fencing token — ack (done), nack (retry, dead-letter after `max_deliver` attempts), or term
//! (intentional drop). An unsettled lease redelivers after the visibility timeout, so a consumer
//! task that dies loses nothing (at-least-once).
//!
//! One `AsyncClient` per task: the wire is request-response FIFO per connection, so a fetch and
//! its acks are awaited sequentially on the same connection. Scale out by running MORE tasks with
//! their own connections in the SAME group — they compete for leases, which is the point.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client-async --example consume_async
//! cargo run -p ironbus-client-async --example consume_async -- 127.0.0.1:7777
//! ```

use ironbus_client_async::proto::PubBody;
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();

    // Seed a few records so the consumer below has work, whatever state the broker is in.
    let mut producer = AsyncClient::connect(addr.as_str()).await?;
    for i in 0..3u32 {
        let payload = format!("job-{i}");
        let offset = producer
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
        println!("produced {payload} at offset {offset}");
    }

    // Join the competing work-group. The group's committed cursor is durable broker-side state:
    // a rerun resumes where the group left off, and other connections in the same group compete
    // for the remaining leases.
    let mut consumer = AsyncClient::connect(addr.as_str()).await?;
    consumer.subscribe("example-async-workers").await?;

    let mut settled = 0u32;
    let mut idle_polls = 0u32;
    while settled < 3 && idle_polls < 200 {
        // Up to 64 messages per fetch; the pull is additionally capped at the per-consumer credit
        // negotiated at connect time. The batch can also carry in-band advisories (dead-letter,
        // truncation/gap notices) — real consumers should at least log them.
        let batch = consumer.fetch(64).await?;
        for dl in &batch.dead_letters {
            println!("advisory: offset {} was dead-lettered (poison)", dl.offset);
        }
        if batch.messages.is_empty() {
            // Drained (or a retrying record is waiting out its backoff): poll again shortly.
            idle_polls += 1;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            continue;
        }
        for m in &batch.messages {
            // Settle each delivery with its OWN (offset, generation) lease. `true` means the
            // group committed past it; `false` means the token was fenced (the lease expired and
            // the record redelivered elsewhere) — process idempotently, the at-least-once
            // contract. On failure call `consumer.nack(m.offset, m.generation, None).await`
            // instead, and the broker redelivers on its backoff schedule.
            let accepted = consumer.ack(m.offset, m.generation).await?;
            println!(
                "ack offset {} payload {:?} (accepted: {accepted})",
                m.offset,
                String::from_utf8_lossy(&m.payload)
            );
            if accepted {
                settled += 1;
            }
        }
    }

    println!("done: {settled} records processed and acked");
    Ok(())
}
