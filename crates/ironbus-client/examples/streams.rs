// SPDX-License-Identifier: MIT OR Apache-2.0
//! NAMED STREAMS: independent logs on one broker, addressed by id.
//!
//! Besides the default stream (the empty name, which every plain `produce`/`subscribe` uses), the
//! broker hosts NAMED streams: each has its OWN log, its own offset space, and its own per-stream
//! work-groups, so `orders` and `payments` never interleave and a slow consumer on one never
//! stalls the other.
//!
//! Stream addressing is a NEGOTIATED capability: set [`ClientConfig::understands_streams`] before
//! connecting and check [`Client::streams_enabled`] after — an old client that never advertises it
//! keeps the default-stream-only wire, byte-for-byte. The verbs:
//!
//! * [`Client::declare_stream`]  — create-or-ensure a named stream (idempotent).
//! * [`Client::stream_info`]     — does it exist, and what is its durable head offset?
//! * [`Client::publish_to`]      — produce into the named stream's own log (at-least-once,
//!   ack-implies-durable, exactly like the default-stream `produce`).
//! * [`Client::subscribe_to`]    — bind this connection's fetch/ack path to the named stream's
//!   own competing work-group; the SAME group name on two streams is two unrelated cursors.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client --example streams
//! cargo run -p ironbus-client --example streams -- 127.0.0.1:7777
//! ```

use ironbus_client::{Client, ClientConfig};
use ironbus_proto::message::PubBody;

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

/// A minimal publish body around `payload`; see the `produce` example for every field's story.
fn body(payload: &[u8]) -> PubBody<'_> {
    PubBody {
        flags: 0,
        timestamp_ms: now_ms(),
        key: b"",
        headers: b"",
        dedup: None,
        fire_and_forget: false,
        payload,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();

    // Advertise the stream-addressing capability in the connect handshake. The server confirms it
    // in its Info reply; `streams_enabled()` reports the negotiated AND of the two.
    let config = ClientConfig {
        understands_streams: true,
        ..ClientConfig::default()
    };
    let mut client = Client::connect_with(&addr, &config)?;
    assert!(
        client.streams_enabled(),
        "the broker did not confirm stream addressing"
    );
    println!("connected to {addr} with stream addressing negotiated");

    // Create-or-ensure two independent streams. Declaring an existing stream is a no-op success,
    // so services can declare what they use at startup without coordination.
    client.declare_stream("orders")?;
    client.declare_stream("payments")?;

    // `stream_info` reports existence and the durable head (the offset the NEXT record gets).
    let (exists, head) = client.stream_info("orders")?;
    println!("stream orders: exists={exists} head={head}");

    // Publish into each stream BY ID. Each stream assigns offsets from its OWN offset space, and
    // each ack means the record is fsynced-durable in THAT stream's log.
    let o0 = client.publish_to("orders", &body(b"order: 3 widgets"))?;
    let o1 = client.publish_to("orders", &body(b"order: 1 gadget"))?;
    let p0 = client.publish_to("payments", &body(b"payment: $42.00"))?;
    println!("published orders@{o0} orders@{o1} payments@{p0}");

    // Bind a consumer connection to the ORDERS stream's own work-group and drain it. Note the
    // isolation: this consumer will NEVER see the payments record, and the group name "workers"
    // on the payments stream would be a completely separate cursor.
    let mut consumer = Client::connect_with(&addr, &config)?;
    consumer.subscribe_to("orders", "workers")?;
    let mut drained = 0u32;
    let mut idle_polls = 0u32;
    while drained < 2 && idle_polls < 200 {
        let batch = consumer.fetch(64)?;
        if batch.messages.is_empty() {
            idle_polls += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        for m in &batch.messages {
            // The same lease discipline as the default stream: settle each delivery with its
            // (offset, generation) fencing token. See the consume_ack_group example.
            let accepted = consumer.ack(m.offset, m.generation)?;
            println!(
                "orders consumer: offset {} payload {:?} (acked: {accepted})",
                m.offset,
                String::from_utf8_lossy(&m.payload)
            );
            drained += 1;
        }
    }

    // Rebinding the SAME connection to another stream switches its fetch/ack path there; the
    // payments record is exactly where it was produced, untouched by the orders consumption.
    consumer.subscribe_to("payments", "workers")?;
    let batch = consumer.fetch(64)?;
    for m in &batch.messages {
        consumer.ack(m.offset, m.generation)?;
        println!(
            "payments consumer: offset {} payload {:?}",
            m.offset,
            String::from_utf8_lossy(&m.payload)
        );
    }

    Ok(())
}
