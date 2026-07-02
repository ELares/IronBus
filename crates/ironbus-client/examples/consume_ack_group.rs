// SPDX-License-Identifier: MIT OR Apache-2.0
//! CONSUME + ACK in a competing work-group.
//!
//! The consume model: a connection SUBSCRIBES to a named work-group, then FETCHES batches. Every
//! delivered message carries a lease — `(offset, generation)`, the fencing token — and the
//! consumer settles each lease exactly one way:
//!
//! * [`Client::ack`]  — done: the group commits past it, it never redelivers.
//! * [`Client::nack`] — failed here, try again: it redelivers (optionally after a delay), and
//!   after the broker's `max_deliver` attempts it is DEAD-LETTERED (poison quarantine), not
//!   retried forever.
//! * [`Client::term`] — intentional drop: commit past it without dead-lettering.
//!
//! An UNSETTLED lease redelivers by itself after the visibility timeout, so a consumer that
//! crashes mid-batch loses nothing (at-least-once). The `generation` fences stale settles: an ack
//! for a lease that already expired and redelivered returns `false` instead of committing the
//! wrong delivery.
//!
//! Consumers in the SAME group COMPETE (each record is leased to one of them); different groups
//! have independent cursors over the same log, so a second group replays the full history.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client --example consume_ack_group
//! cargo run -p ironbus-client --example consume_ack_group -- 127.0.0.1:7777
//! ```

use ironbus_client::Client;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();

    // Seed a few records so the consumer below has work, whatever state the broker is in.
    // (One connection can both produce and consume; two are used here to mirror a real topology.)
    let mut producer = Client::connect(&addr)?;
    for i in 0..3u32 {
        let payload = format!("job-{i}");
        let offset = producer.produce(&PubBody {
            flags: 0,
            timestamp_ms: now_ms(),
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: payload.as_bytes(),
        })?;
        println!("produced {payload} at offset {offset}");
    }

    let mut consumer = Client::connect(&addr)?;
    // Join the competing work-group "example-workers". The group's committed cursor is DURABLE
    // broker-side state: a rerun of this example resumes where the group left off, and a second
    // process subscribing to the same group competes for the remaining records.
    consumer.subscribe("example-workers")?;

    let mut settled = 0u32;
    let mut nacked_once = false;
    let mut idle_polls = 0u32;
    // Fetch in batches until the group is drained. `fetch(64)` asks for up to 64 messages; the
    // pull is additionally capped at the per-consumer credit negotiated at connect time.
    while settled < 3 && idle_polls < 200 {
        let batch = consumer.fetch(64)?;

        // A fetch can also carry in-band ADVISORIES instead of payloads: dead-letter notices for
        // offsets the broker quarantined as poison, and truncation/gap notices for spans a
        // retention policy reaped. Real consumers should at least log them.
        for dl in &batch.dead_letters {
            println!("advisory: offset {} was dead-lettered (poison)", dl.offset);
        }

        if batch.messages.is_empty() {
            // Nothing leased right now: either the log is drained or a nacked record is waiting
            // out its redelivery schedule. Poll again shortly (a real worker would back off).
            idle_polls += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }

        for m in &batch.messages {
            let payload = String::from_utf8_lossy(&m.payload);

            // Simulate ONE transient failure to show the redelivery path: nack the first
            // delivery with an explicit zero delay, so the broker redelivers it immediately
            // (omit the delay, `None`, to use the broker's exponential backoff schedule).
            if !nacked_once {
                nacked_once = true;
                let accepted = consumer.nack(m.offset, m.generation, Some(0))?;
                println!(
                    "nack  offset {} (accepted: {accepted}) — it will redeliver",
                    m.offset
                );
                continue;
            }

            // The happy path: process, then ack with the delivery's OWN (offset, generation)
            // lease. `true` means the group committed past it; `false` means the token was
            // fenced (the lease timed out and the record was redelivered elsewhere) — the work
            // must be idempotent, the at-least-once contract.
            let accepted = consumer.ack(m.offset, m.generation)?;
            println!(
                "ack   offset {} payload {payload:?} (accepted: {accepted})",
                m.offset
            );
            if accepted {
                settled += 1;
            }
        }
    }

    println!("done: {settled} records processed and acked");
    Ok(())
}
