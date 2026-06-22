// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire-compatibility tests for [`ironbus_client_async::AsyncClient`] against the REAL broker.
//!
//! These mirror the synchronous client's `start_server()` test helper: an in-memory engine, a
//! `spawn_actor` append actor, and a `std::thread` accept loop running the real `ironbus_server::serve`
//! with a shutdown `AtomicBool`. The server is sync / thread-per-connection, so its accept loop runs on
//! a BLOCKING std thread; the async client connects to it over loopback via `tokio::net::TcpStream`.
//! This proves the async client speaks the same wire as the broker, end to end.

use ironbus_client_async::proto::PubBody;
use ironbus_client_async::AsyncClient;
use ironbus_core::clock::Clock;
use ironbus_core::delivery::DeliveryConfig;
use ironbus_core::lease::LeaseConfig;
use ironbus_server::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
use ironbus_server::clock::SystemClock;
use ironbus_server::engine::{
    DiskFullPolicy, Engine, EngineConfig, DEFAULT_GROUP_IDLE_EVICT_MS, DEFAULT_MAX_GROUPS,
};
use ironbus_server::server::serve;
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::LogConfig;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Starts an in-process broker on a loopback port and returns its bound address, a shutdown flag, and
/// the accept-loop thread handle. A faithful copy of the sync client's `start_server` /
/// `start_server_with` / `spawn_serving` helpers: an in-memory engine driven by a `spawn_actor` append
/// actor, served by the real `serve` accept loop on a blocking std thread.
fn start_server() -> (SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
    let engine = Engine::open(
        InMemoryFs::new(),
        SystemClock::new(),
        EngineConfig {
            log: LogConfig::default(),
            lease: LeaseConfig::default(),
            delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
            max_in_flight: 16,
            consumer_credit: 64,
            consumer_credit_bytes: 0,
            checkpoint_interval: 1024,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
            max_groups: DEFAULT_MAX_GROUPS,
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
            ram_ceiling_bytes: 0,
            disk_full_policy: DiskFullPolicy::DropNew,
            dedup: ironbus_core::dedup::DedupConfig::default(),
            durability_level: ironbus_server::engine::DurabilityLevel::Sync,
            flush_interval_ms: 0,
            flush_max_bytes: 0,
            codel_target_ms: 0,
            codel_interval_ms: 0,
            retry_budget_ratio_per_million: 0,
            retry_budget_window_ms: 0,
            fire_and_forget_msg_rate: 0,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: 0,
            egress_limit: 0,
            wal_fsync_headroom_bytes: 0,
            compression: ironbus_core::compress::Codec::None,
            default_message_ttl_ms: 0,
            dead_letter_exchange: None,
            dead_letter_expired: false,
        },
    )
    .unwrap();

    // The engine is owned by the append actor; the wire server reaches it through the handle. The
    // actor join handle is detached: when the server thread stops, the actor's channel disconnects and
    // it drains and exits on its own.
    let (handle_engine, _actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = std::thread::spawn({
        let shutdown = Arc::clone(&shutdown);
        move || {
            let clock = SystemClock::new();
            let beacon = ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
            serve(&listener, &handle_engine, &shutdown, 16, &clock, &beacon).unwrap();
        }
    });
    (addr, shutdown, handle)
}

/// The headline round-trip: connect the async client to the real broker over loopback, produce a
/// record (offset 0), subscribe, fetch it back (payload matches), and ack it. Proves the async client
/// is wire-compatible with the broker end to end.
#[tokio::test]
async fn async_client_produce_subscribe_fetch_ack_round_trip_against_a_real_server() {
    let (addr, shutdown, handle) = start_server();

    let mut c = AsyncClient::connect(addr).await.unwrap();
    // A keepalive proves the simplest request-response works before the data path.
    c.ping().await.unwrap();

    let offset = c
        .produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"k",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"async-msg",
        })
        .await
        .unwrap();
    assert_eq!(offset, 0, "the first produced record lands at offset 0");

    c.subscribe("workers").await.unwrap();

    let fetched = c.fetch(10).await.unwrap();
    assert_eq!(
        fetched.messages.len(),
        1,
        "the produced record is delivered"
    );
    assert_eq!(
        fetched.messages[0].payload, b"async-msg",
        "the payload round-trips byte-for-byte"
    );
    assert_eq!(fetched.messages[0].offset, 0);

    assert!(
        c.ack(fetched.messages[0].offset, fetched.messages[0].generation)
            .await
            .unwrap(),
        "the ack commits the lease"
    );
    // Nothing left to fetch once the only record is acked.
    assert!(
        c.fetch(10).await.unwrap().messages.is_empty(),
        "the acked record is not redelivered"
    );

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// A fire-and-forget produce reads NO reply, so a desync there would corrupt every later
/// request-response. This proves no desync: after a faf produce (offset 0), a following AWAITED produce
/// must get the NEXT offset (1), and both records fetch back in order.
#[tokio::test]
async fn async_fire_and_forget_does_not_desync_the_connection() {
    let (addr, shutdown, handle) = start_server();

    let mut c = AsyncClient::connect(addr).await.unwrap();

    // Fire-and-forget: no reply is read. This lands at offset 0 on a quiet, unloaded broker.
    c.produce_fire_and_forget(&PubBody {
        flags: 0,
        timestamp_ms: 0,
        key: b"",
        headers: b"",
        dedup: None,
        fire_and_forget: true,
        payload: b"faf-0",
    })
    .await
    .unwrap();

    // The very next AWAITED produce must read ITS OWN PubAck (not the absent faf reply) and get the
    // next offset (1). A wrong offset here would prove the faf path left a stale frame in the buffer.
    let offset = c
        .produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"awaited-1",
        })
        .await
        .unwrap();
    assert_eq!(
        offset, 1,
        "the awaited produce gets offset 1, proving the faf produce landed at 0 and left no desync"
    );

    // Both records are present and in order from the default group.
    let fetched = c.fetch(10).await.unwrap();
    assert_eq!(fetched.messages.len(), 2, "both records are delivered");
    assert_eq!(fetched.messages[0].payload, b"faf-0");
    assert_eq!(fetched.messages[0].offset, 0);
    assert_eq!(fetched.messages[1].payload, b"awaited-1");
    assert_eq!(fetched.messages[1].offset, 1);

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// The coalescing fire-and-forget producer must also leave the connection framed: buffer two faf
/// produces, flush them, then prove a following awaited produce reads its own ack at the next offset.
/// Gated unix-only for determinism parity with the sync client's unix-scoped wire tests.
#[cfg(all(test, unix))]
#[tokio::test]
async fn async_coalescing_faf_producer_flushes_and_leaves_no_desync() {
    let (addr, shutdown, handle) = start_server();

    let mut c = AsyncClient::connect(addr).await.unwrap();
    {
        let mut faf = c.fire_and_forget_producer();
        for payload in [b"c0".as_slice(), b"c1".as_slice()] {
            faf.produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: true,
                payload,
            })
            .await
            .unwrap();
        }
        // Push the buffered tail (the two small frames never crossed the 32 KiB auto-flush threshold).
        faf.flush().await.unwrap();
    }

    // A following awaited produce must read its own ack at offset 2 (the two coalesced faf records took
    // 0 and 1), proving the coalesced write left the connection framed.
    let offset = c
        .produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"awaited-2",
        })
        .await
        .unwrap();
    assert_eq!(
        offset, 2,
        "the awaited produce follows the two coalesced faf records"
    );

    let fetched = c.fetch(10).await.unwrap();
    assert_eq!(fetched.messages.len(), 3, "all three records are delivered");
    assert_eq!(fetched.messages[2].payload, b"awaited-2");

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}
