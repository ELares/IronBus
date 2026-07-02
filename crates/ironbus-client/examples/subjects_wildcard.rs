// SPDX-License-Identifier: MIT OR Apache-2.0
//! SUBJECTS + WILDCARDS: NATS-style routing over durable streams, fail-closed.
//!
//! A SUBJECT is a dotted routing name (`orders.us`, `telemetry.eu.site1.temp`). Instead of
//! publishing to a stream by id, a producer publishes ON A SUBJECT and the broker routes the
//! record through the subject->stream binding table:
//!
//! * [`Client::bind_subject`]      — bind a PATTERN to a stream (wildcards live HERE, on the
//!   bind side): `*` matches exactly one token, `>` matches one-or-more trailing tokens (final
//!   position only). The bind declares its target stream if needed.
//! * [`Client::publish_subject`]   — publish on a LITERAL subject (no wildcards in a published
//!   subject); the broker resolves it to the ONE covering stream and appends there.
//! * [`Client::subscribe_subject`] — resolve a LITERAL subject and bind this connection's
//!   fetch/ack to the covering stream's work-group. A wildcard in the subscribed subject is
//!   rejected fail-closed this phase (the multi-stream fan-out subscribe is a flagged follow-up).
//!
//! The routing is FAIL-CLOSED and single-home, deliberately stricter than NATS: a subject bound
//! to NO stream is a typed `NoStreamForSubject` rejection — never a silent drop — and a subject
//! covered by TWO OR MORE streams is a typed `AmbiguousSubject` rejection.
//!
//! Subjects ride the stream-addressing capability, so connect with
//! [`ClientConfig::understands_streams`] set. On an auth-enabled broker, `bind_subject` mutates
//! routing state and therefore needs the `admin` scope.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client --example subjects_wildcard
//! cargo run -p ironbus-client --example subjects_wildcard -- 127.0.0.1:7777
//! ```

use ironbus_client::{Client, ClientConfig, ClientError, ServerErrorCode};
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
    let config = ClientConfig {
        understands_streams: true, // subjects ride the stream-addressing capability
        ..ClientConfig::default()
    };
    let mut client = Client::connect_with(&addr, &config)?;
    assert!(
        client.streams_enabled(),
        "the broker did not confirm stream addressing"
    );
    println!("connected to {addr} with stream addressing negotiated");

    // ---- Bind patterns to streams -------------------------------------------------------------
    // `orders.*` covers any TWO-token subject under orders (orders.us, orders.eu — but not
    // orders.eu.vip); `telemetry.>` covers ANY depth under telemetry. Binding is idempotent and
    // declares the target stream on first use (declare-on-bind).
    client.bind_subject("orders", "orders.*")?;
    client.bind_subject("telemetry", "telemetry.>")?;
    println!("bound orders.* -> orders, telemetry.> -> telemetry");

    // ---- Publish on literal subjects ----------------------------------------------------------
    // Both orders subjects resolve to the SAME stream, so they share one offset space; the
    // telemetry subject resolves to its own stream. Each ack is fsynced-durable, exactly like a
    // stream-addressed publish.
    let o0 = client.publish_subject("orders.us", &body(b"order from us-east"))?;
    let o1 = client.publish_subject("orders.eu", &body(b"order from eu-west"))?;
    let t0 = client.publish_subject("telemetry.eu.site1.temp", &body(b"21.5C"))?;
    println!("published orders.us@{o0} orders.eu@{o1} telemetry.eu.site1.temp@{t0}");

    // ---- Fail-closed: an unbound subject is a typed rejection ---------------------------------
    // NATS silently drops a publish nobody subscribes to; IronBus refuses it with a stable
    // machine-readable code, so a routing misconfiguration is loud at the producer.
    match client.publish_subject("invoices.us", &body(b"lost?")) {
        Err(ClientError::Server(e)) if e.code() == Some(ServerErrorCode::NoStreamForSubject) => {
            println!("unbound subject invoices.us rejected fail-closed: {e}");
        }
        other => return Err(format!("expected NoStreamForSubject, got {other:?}").into()),
    }

    // ---- Subscribe by (literal) subject --------------------------------------------------------
    // `orders.us` resolves through the trie to the ONE stream `orders.*` routes it to, and the
    // subscribe joins that stream's competing work-group — so this consumer receives EVERY record
    // in the orders stream (orders.eu included), because the wildcard fan-in happened at publish
    // time. Fetch/ack then follow the same lease discipline as everywhere else (see the
    // consume_ack_group example). A wildcard in the SUBSCRIBED subject is rejected fail-closed
    // this phase; wildcards belong to bind patterns.
    let mut consumer = Client::connect_with(&addr, &config)?;
    consumer.subscribe_subject("orders.us", "order-workers")?;
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
            let accepted = consumer.ack(m.offset, m.generation)?;
            println!(
                "orders consumer: offset {} payload {:?} (acked: {accepted})",
                m.offset,
                String::from_utf8_lossy(&m.payload)
            );
            drained += 1;
        }
    }

    // A literal subject subscribe resolves through the same trie: `telemetry.eu.site1.temp` is
    // covered by `telemetry.>`, so this binds to the telemetry stream's work-group.
    consumer.subscribe_subject("telemetry.eu.site1.temp", "telemetry-workers")?;
    let batch = consumer.fetch(64)?;
    for m in &batch.messages {
        consumer.ack(m.offset, m.generation)?;
        println!(
            "telemetry consumer: offset {} payload {:?}",
            m.offset,
            String::from_utf8_lossy(&m.payload)
        );
    }

    Ok(())
}
