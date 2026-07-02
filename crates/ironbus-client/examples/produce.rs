// SPDX-License-Identifier: MIT OR Apache-2.0
//! PRODUCE: the three durable produce shapes of the synchronous client.
//!
//! 1. [`Client::produce`] — the fully synchronous default: one publish in flight, and the call
//!    blocks until the broker's covering `fdatasync` has made the record durable and the `PubAck`
//!    arrived (ack-implies-durable). The right choice when each publish must be durable before the
//!    next line of your code runs.
//! 2. [`Client::produce_dedup`] — the same at-least-once produce, plus the OPT-IN effectively-once
//!    dedup window: a retried publish carrying the same `msg_id` is acked with the ORIGINAL offset
//!    and `duplicate = true` instead of being appended twice.
//! 3. [`Client::pipelined_producer`] — the ergonomic high-throughput handle: it buffers a small
//!    window of publishes and flushes them as ONE group-committed batch, so the broker covers the
//!    whole window with a single fsync. Every ack still means fsynced-durable; only WHEN you
//!    observe the acks moves.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data        # or: --storage memory
//! cargo run -p ironbus-client --example produce      # default 127.0.0.1:7777
//! cargo run -p ironbus-client --example produce -- 127.0.0.1:7777
//! IRONBUS_ADDR=10.0.0.5:7777 cargo run -p ironbus-client --example produce
//! ```

use ironbus_client::Client;
use ironbus_proto::message::{PubBody, PubDedup};

/// The broker address: the first CLI argument, else `IRONBUS_ADDR`, else the loopback default —
/// the same flag > env > default precedence the `ironbus` CLI uses.
fn broker_addr() -> String {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("IRONBUS_ADDR").ok())
        .unwrap_or_else(|| "127.0.0.1:7777".to_string())
}

/// The producer-side timestamp for a record: milliseconds since the Unix epoch. The broker stores
/// it verbatim and hands it back to consumers; it never affects ordering (the log offset does).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();
    // One `Client` owns one TCP connection and speaks the request-response wire FIFO. Timeouts
    // (connect/read/write) come from `ClientConfig::default()` via `connect`; use `connect_with`
    // to tune them or to negotiate capabilities (see the streams / subjects examples).
    let mut client = Client::connect(&addr)?;
    println!("connected to {addr}");

    // ---- 1. The awaited, durable-on-return produce ------------------------------------------
    // `PubBody` is the one publish shape every produce path shares: optional routing/ordering
    // `key`, an opaque `headers` blob, and the `payload`. When `produce` returns, the record is
    // fsynced-durable on the broker and `offset` names it in the log forever.
    let offset = client.produce(&PubBody {
        flags: 0,
        timestamp_ms: now_ms(),
        key: b"sensor-42", // records with the same key keep their relative order
        headers: b"",      // application-defined; the broker never parses it
        dedup: None,       // no dedup: a plain at-least-once publish
        fire_and_forget: false, // false = at-least-once (the QoS-0 path is its own method)
        payload: b"temperature=21.5",
    })?;
    println!("produce: durable at offset {offset}");

    // ---- 2. The idempotent (dedup) produce ---------------------------------------------------
    // Opt into the broker's effectively-once window by attaching a dedup block: a stable
    // `producer_id`, a fencing `epoch`, and the idempotency key `msg_id` (dedup is keyed by
    // `msg_id` ONLY, never the body). Publishing the same `msg_id` twice — a timeout retry, a
    // crashed-and-restarted producer — appends ONE record; the second ack carries the original
    // offset and `duplicate = true`, a benign success rather than an error.
    let msg_id = format!("order-{}", now_ms());
    let order = PubBody {
        flags: 0,
        timestamp_ms: now_ms(),
        key: b"orders",
        headers: b"",
        dedup: Some(PubDedup {
            producer_id: b"example-producer",
            epoch: 1, // bump on producer restart to fence the old session
            msg_id: msg_id.as_bytes(),
            seq: None, // Some(n) opts into the Kafka-style monotonic sequence
        }),
        fire_and_forget: false,
        payload: b"{\"item\":\"widget\",\"qty\":3}",
    };
    let first = client.produce_dedup(&order)?;
    let retry = client.produce_dedup(&order)?; // the same msg_id: a simulated timeout retry
    println!(
        "produce_dedup: first offset {} (duplicate: {}), retry offset {} (duplicate: {})",
        first.offset, first.duplicate, retry.offset, retry.duplicate
    );
    assert!(retry.duplicate, "the retried msg_id deduplicates");
    assert_eq!(
        first.offset, retry.offset,
        "the retry acks the ORIGINAL offset"
    );

    // ---- 3. The auto-pipelining durable producer ---------------------------------------------
    // A single producer using the awaited `produce` pays one fsync per publish (nothing else is
    // in flight for the broker's group commit to amortize across). The pipelined handle keeps a
    // window of publishes in flight so ONE fsync covers the whole window: same at-least-once,
    // ack-implies-durable contract, dramatically higher single-producer durable throughput.
    let mut producer = client.pipelined_producer(); // or pipelined_producer_with_window(n)
    for i in 0..1000u32 {
        let payload = format!("event-{i}");
        // Returns as soon as the publish is buffered (input buffers are immediately reusable);
        // when the buffer reaches the window it auto-flushes and returns that flush's tally.
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
    // `finish` (or an explicit `flush`) drains the acks for the tail of the run: only after it
    // returns is the WHOLE run durably acked. Every counted ack means fsynced-durable.
    let summary = producer.finish()?;
    println!(
        "pipelined_producer: {} acked in the final flush (last offset {:?})",
        summary.acked, summary.last_offset
    );

    Ok(())
}
