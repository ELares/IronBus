// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLUSTER PRODUCE with NOT-LEADER redirect handling.
//!
//! In a cluster, each partition has ONE leader that accepts writes. If a client is connected to a
//! follower (e.g. after a failover moved leadership), a produce is rejected with
//! [`ClientError::NotLeader`], carrying the current leader's client-address HINT. A robust producer
//! reconnects to that hint and retries — which is exactly what [`Client::produce_to_leader`] does,
//! bounded by a small redirect budget.
//!
//! This example shows both:
//!   1. the built-in [`Client::produce_to_leader`] (the one call you normally want), and
//!   2. the manual pattern — matching [`ClientError::NotLeader`] yourself and reconnecting to the
//!      hint — for callers that want their own retry/backoff policy.
//!
//! On a SINGLE-NODE broker there is no other leader, so the connected node always accepts the write
//! and neither path ever redirects: the example is a no-op-safe demonstration of the API, and the
//! redirect branch is the code that matters in a real cluster. See `docs/OPERATIONS.md` for cluster
//! bring-up.
//!
//! Run a broker (single node is fine), then the example:
//!
//! ```sh
//! ironbus serve --data-dir /tmp/ironbus-data
//! cargo run -p ironbus-client --example not_leader
//! cargo run -p ironbus-client --example not_leader -- 127.0.0.1:7777
//! ```

use ironbus_client::{Client, ClientConfig, ClientError};
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

fn message(payload: &[u8]) -> PubBody<'_> {
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
    // The handshake config is reused for any reconnect, so the leader connection negotiates the same
    // capabilities as the original.
    let config = ClientConfig::default();
    let mut client = Client::connect_with(&addr, &config)?;

    // --- 1) The built-in helper: produce, transparently chasing up to 3 leader redirects. On a
    // single node it is exactly `produce()`; in a cluster it reconnects to the leader hint and
    // retries there, leaving the client connected to the leader for subsequent produces.
    let offset = client.produce_to_leader(&message(b"via-produce-to-leader"), &config, 3)?;
    println!("produced at offset {offset} (produce_to_leader followed any redirect)");

    // --- 2) The manual pattern: own your retry policy by matching NotLeader yourself. This is what
    // `produce_to_leader` does internally; write it out when you want custom backoff, metrics, or to
    // fall back to your own peer list when the hint is absent.
    let mut attempts = 0;
    let offset = loop {
        match client.produce(&message(b"via-manual-redirect")) {
            Ok(offset) => break offset,
            Err(ClientError::NotLeader {
                leader_hint: Some(leader),
            }) if attempts < 3 => {
                // The follower told us who the leader is: reconnect there (preserving capabilities)
                // and retry. A real client might sleep/backoff here before retrying.
                println!("not the leader — redirecting to {leader}");
                client = Client::connect_with(leader.as_str(), &config)?;
                attempts += 1;
            }
            Err(ClientError::NotLeader { leader_hint: None }) => {
                // No hint (the cluster does not yet know the leader, e.g. mid-election): a real client
                // would re-discover from its own configured peer list and back off. Nothing to do here.
                eprintln!(
                    "not the leader and no hint yet — would re-discover from configured peers"
                );
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("produced at offset {offset} (manual redirect handling)");

    println!("done");
    Ok(())
}
