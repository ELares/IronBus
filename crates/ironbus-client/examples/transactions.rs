// SPDX-License-Identifier: MIT OR Apache-2.0
//! TRANSACTIONAL PRODUCE (2PC half-messages): publish a record only if a local transaction commits.
//!
//! The pattern solves the dual-write problem — "update my database AND publish an event, atomically."
//! A [`Client::prepare`] durably buffers a HALF MESSAGE that is INVISIBLE to consumers; the producer
//! then runs its local work and either [`Client::commit`]s (the half message becomes visible, exactly
//! once) or [`Client::rollback`]s (it is discarded, never delivered). No consumer ever sees a record
//! whose local transaction did not commit.
//!
//! [`Client::transact`] wraps that dance: prepare → run your closure → commit on `Ok`, rollback on
//! `Err`. This example commits one transaction and rolls another back, then consumes to prove ONLY the
//! committed record is visible.
//!
//! The [`TxnId`] is the idempotency anchor. Here we supply stable ids so a re-run is a benign no-op
//! server-side; [`Client::prepare`] mints a per-connection id if you don't need your own.
//!
//! Run a broker, then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client --example transactions
//! cargo run -p ironbus-client --example transactions -- 127.0.0.1:7777
//! ```

use ironbus_client::{Client, ClientError, TxnId};
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

/// One transactional record for the default stream (empty stream id = the default log).
fn event(payload: &[u8]) -> PubBody<'_> {
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
    let mut producer = Client::connect(&addr)?;

    // A UNIQUE run tag so this example is self-verifying across re-runs (each run's committed record
    // is distinct, and the ids below are stable within a run).
    let tag = now_ms();

    // --- 1) A transaction whose local work SUCCEEDS: the half message is committed and becomes visible.
    let committed_payload = format!("order-committed-{tag}");
    let txn_ok = TxnId::new(format!("txn-ok-{tag}").into_bytes());
    let offset = producer.transact(&txn_ok, "", &event(committed_payload.as_bytes()), || {
        // Your local transaction goes here (write to a DB, charge a card, ...). Returning Ok commits
        // the half message; returning Err rolls it back. The closure's error type only needs Display.
        println!("local transaction succeeded — committing the event");
        Ok::<(), String>(())
    })?;
    println!("committed {committed_payload:?} at offset {offset}");

    // --- 2) A transaction whose local work FAILS: the half message is rolled back, never delivered.
    let rolled_back_payload = format!("order-rolledback-{tag}");
    let txn_bad = TxnId::new(format!("txn-bad-{tag}").into_bytes());
    let result = producer.transact(&txn_bad, "", &event(rolled_back_payload.as_bytes()), || {
        println!("local transaction failed — rolling back the event");
        Err::<(), String>("insufficient funds".to_string())
    });
    match result {
        // `transact` surfaces a rolled-back local transaction as `LocalTransaction`, carrying your
        // closure's error message. The half message was discarded; no consumer will ever see it.
        Err(ClientError::LocalTransaction(why)) => {
            println!("rolled back {rolled_back_payload:?} (reason: {why})");
        }
        Err(e) => return Err(e.into()),
        Ok(off) => panic!("expected a rollback, but it committed at offset {off}"),
    }

    // --- 3) Consume from a fresh group over the full log and prove the rolled-back record is absent.
    let mut consumer = Client::connect(&addr)?;
    let group = format!("txn-verify-{tag}");
    consumer.subscribe(&group)?;
    let mut saw_committed = false;
    let mut idle = 0u32;
    while idle < 100 {
        let batch = consumer.fetch(256)?;
        if batch.messages.is_empty() {
            idle += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        for m in &batch.messages {
            let payload = String::from_utf8_lossy(&m.payload);
            assert_ne!(
                payload, rolled_back_payload,
                "a rolled-back half message must never be delivered"
            );
            if payload == committed_payload {
                saw_committed = true;
                println!("consumer saw the committed event at offset {}", m.offset);
            }
            consumer.ack(m.offset, m.generation)?;
        }
        if saw_committed {
            break;
        }
    }

    assert!(
        saw_committed,
        "the committed event should have been delivered"
    );
    println!("done: committed record delivered, rolled-back record never was");
    Ok(())
}
