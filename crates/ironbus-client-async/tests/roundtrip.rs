// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire-compatibility tests for [`ironbus_client_async::AsyncClient`] against the REAL broker.
//!
//! These mirror the synchronous client's `start_server()` test helper: an in-memory engine, a
//! `spawn_actor` append actor, and a `std::thread` accept loop running the real `ironbus_server::serve`
//! with a shutdown `AtomicBool`. The server is sync / thread-per-connection, so its accept loop runs on
//! a BLOCKING std thread; the async client connects to it over loopback via `tokio::net::TcpStream`.
//! This proves the async client speaks the same wire as the broker, end to end.

use ironbus_client_async::proto::{ConsumeTier, PubBody};
use ironbus_client_async::{AsyncClient, ClientConfig, ProgressOutcome, StreamConsumerConfig};
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

/// Opens the in-memory test engine shared by the plaintext and (feature-gated) TLS broker helpers: an
/// `InMemoryFs` + `SystemClock` with the historical test `EngineConfig` (64 credit, no caps).
fn open_engine() -> Engine<InMemoryFs, SystemClock> {
    Engine::open(
        InMemoryFs::new(),
        SystemClock::new(),
        EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig::default(),
            lease: LeaseConfig::default(),
            delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
            max_in_flight: 16,
            consumer_credit: 64,
            consumer_credit_bytes: 0,
            checkpoint_interval: 1024,
            max_acked_ahead_runs: 1024,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
            max_groups: DEFAULT_MAX_GROUPS,
            // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
            max_streams: 0,
            max_open_streams: 0,
            max_metric_streams: 1024,
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
            sync_max_dirty_bytes: 0,
            compression: ironbus_core::compress::Codec::None,
            default_message_ttl_ms: 0,
            dead_letter_exchange: None,
            dead_letter_expired: false,
        },
    )
    .unwrap()
}

/// Starts an in-process broker on a loopback port and returns its bound address, a shutdown flag, and
/// the accept-loop thread handle. A faithful copy of the sync client's `start_server` /
/// `start_server_with` / `spawn_serving` helpers: an in-memory engine driven by a `spawn_actor` append
/// actor, served by the real `serve` accept loop on a blocking std thread.
fn start_server() -> (SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
    let engine = open_engine();

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

/// A `ClientConfig` that advertises the stream-addressing capability (#588), so the server confirms
/// `streams_enabled()` and the stream-addressed verbs are accepted.
fn config_understanding_streams() -> ClientConfig {
    ClientConfig {
        understands_streams: true,
        ..ClientConfig::default()
    }
}

/// A `ClientConfig` that negotiates Tier-S (#543 / #550): advertises streaming + `DeliverBatch` and
/// requests the streaming connection default, so a SUB auto-marks its group streaming server-side — the
/// wiring the durable [`AsyncStreamingConsumer`] rides on.
fn config_streaming() -> ClientConfig {
    ClientConfig {
        understands_streaming: true,
        default_consume_tier: Some(ConsumeTier::Streaming),
        understands_deliver_batch: true,
        ..ClientConfig::default()
    }
}

/// The LOAD-BEARING producer path for the gateway migration: `produce_window` writes a window of N
/// publishes with one coalesced write and drains N `PubAck`s FIFO, returning the offsets in input order.
/// This proves the pipelined durable producer is wire-compatible end to end against the real broker:
/// the window's offsets are `0..N` in order, and every record fetches back in the same order.
#[tokio::test]
async fn async_produce_window_returns_fifo_offsets_against_a_real_server() {
    let (addr, shutdown, handle) = start_server();

    let mut c = AsyncClient::connect(addr).await.unwrap();

    // A window of five durable publishes in ONE pipelined batch.
    let payloads: [&[u8]; 5] = [b"w0", b"w1", b"w2", b"w3", b"w4"];
    let window: Vec<PubBody<'_>> = payloads
        .iter()
        .map(|p| PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p,
        })
        .collect();

    let acks = c.produce_window(&window).await.unwrap();
    assert_eq!(acks.len(), 5, "one ack per windowed publish");
    let offsets: Vec<u64> = acks.iter().map(|a| a.offset).collect();
    assert_eq!(
        offsets,
        vec![0, 1, 2, 3, 4],
        "the window's acks are FIFO: the Nth ack belongs to the Nth publish"
    );
    assert!(
        acks.iter().all(|a| !a.duplicate),
        "no dedup blocks set, so no slot is a duplicate"
    );

    // An empty window never touches the wire and leaves the connection framed.
    assert!(
        c.produce_window(&[]).await.unwrap().is_empty(),
        "an empty window is a no-op empty vec"
    );

    // Every windowed record is durable and fetches back in order.
    c.subscribe("workers").await.unwrap();
    let fetched = c.fetch(10).await.unwrap();
    assert_eq!(fetched.messages.len(), 5, "all five records are delivered");
    for (i, payload) in payloads.iter().enumerate() {
        assert_eq!(fetched.messages[i].payload, *payload);
        assert_eq!(fetched.messages[i].offset, i as u64);
    }

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// The consume-settle NAK path end to end: produce a record, subscribe, fetch it, NAK it (the broker
/// requeues it), then a re-fetch REDELIVERS it under a fresh generation — proving the async `nack`
/// requeued it. The stale (nacked) token can no longer ack; the fresh one commits and drains. The async
/// port of the sync client's `a_nacked_message_is_redelivered_against_a_real_server`.
#[tokio::test]
async fn async_nack_redelivers_a_message_against_a_real_server() {
    let (addr, shutdown, handle) = start_server();

    let mut c = AsyncClient::connect(addr).await.unwrap();
    let off = c
        .produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"retry-me",
        })
        .await
        .unwrap();

    c.subscribe("workers").await.unwrap();
    let first = c.fetch(10).await.unwrap().messages;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].payload, b"retry-me");

    // Nack with no explicit delay: the default 30s visibility means the record would not otherwise
    // redeliver within this test, so the nack is what brings it back. The in-process server has an
    // empty backoff schedule, so `None` requeues it immediately.
    assert!(c
        .nack(first[0].offset, first[0].generation, None)
        .await
        .unwrap());

    let second = c.fetch(10).await.unwrap().messages;
    assert_eq!(second.len(), 1, "the nacked record is redelivered");
    assert_eq!(second[0].offset, off);
    assert_eq!(second[0].payload, b"retry-me");
    assert_ne!(
        second[0].generation, first[0].generation,
        "redelivery fences the old generation"
    );

    // The stale (nacked) token can no longer commit; the fresh one does.
    assert!(
        !c.ack(first[0].offset, first[0].generation).await.unwrap(),
        "the nacked generation is fenced"
    );
    assert!(
        c.ack(second[0].offset, second[0].generation).await.unwrap(),
        "the redelivered generation commits"
    );
    assert!(
        c.fetch(10).await.unwrap().messages.is_empty(),
        "the committed record is not redelivered"
    );

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// The consume-settle TERM and PROGRESS paths end to end: produce two records, fetch both, extend the
/// first's lease with `progress` (Extended), `term` the second (an intentional drop — committed past,
/// never redelivered), then ack the first so the whole prefix is committed and nothing remains. A
/// `progress`/`term` on a now-stale token is fenced. The async port of the sync client's
/// `term_drops_a_message_and_progress_extends_a_lease`.
#[tokio::test]
async fn async_term_drops_and_progress_extends_against_a_real_server() {
    let (addr, shutdown, handle) = start_server();

    let mut c = AsyncClient::connect(addr).await.unwrap();
    for p in [&b"keep"[..], b"drop"] {
        c.produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p,
        })
        .await
        .unwrap();
    }

    c.subscribe("workers").await.unwrap();
    let msgs = c.fetch(10).await.unwrap().messages;
    assert_eq!(msgs.len(), 2);

    // Progress on the first: the lease is extended.
    assert_eq!(
        c.progress(msgs[0].offset, msgs[0].generation)
            .await
            .unwrap(),
        ProgressOutcome::Extended
    );
    // Term the second: an intentional drop (committed past, never redelivered, not dead-lettered).
    assert!(c.term(msgs[1].offset, msgs[1].generation).await.unwrap());

    // Ack the first; now the whole prefix is committed and nothing remains.
    assert!(c.ack(msgs[0].offset, msgs[0].generation).await.unwrap());
    assert!(
        c.fetch(10).await.unwrap().messages.is_empty(),
        "the termed record never redelivers"
    );

    // A progress or term on a now-stale token is fenced.
    assert_eq!(
        c.progress(msgs[0].offset, msgs[0].generation)
            .await
            .unwrap(),
        ProgressOutcome::Fenced
    );
    assert!(!c.term(msgs[1].offset, msgs[1].generation).await.unwrap());

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// The stream-addressed verbs end to end (#588): a streams-capable async client DECLARES a named
/// stream, queries its `stream_info`, PUBLISHES to it by id (offset 0), and consumes the record back
/// via the named stream's own work-group (`subscribe_to` + `fetch` + `ack`). Proves `declare_stream` /
/// `stream_info` / `publish_to` are wire-compatible with the broker.
#[tokio::test]
async fn async_stream_addressed_declare_publish_consume_round_trip() {
    let (addr, shutdown, handle) = start_server();

    let mut c = AsyncClient::connect_with(addr, &config_understanding_streams())
        .await
        .unwrap();
    assert!(
        c.streams_enabled(),
        "the server confirms stream addressing for a client that advertised it"
    );

    // A query before declare: the named stream does not exist yet.
    let (exists, _head) = c.stream_info("s").await.unwrap();
    assert!(!exists, "an undeclared named stream does not exist");

    // Declare it (idempotent), then a re-declare is still Ok.
    c.declare_stream("s").await.unwrap();
    c.declare_stream("s").await.unwrap();
    let (exists, head) = c.stream_info("s").await.unwrap();
    assert!(exists, "the declared named stream now exists");
    assert_eq!(head, 0, "a freshly declared stream has an empty head");

    // Publish to the NAMED stream by id: the first record lands at the stream's OWN offset 0.
    let off = c
        .publish_to(
            "s",
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"stream-record",
            },
        )
        .await
        .unwrap();
    assert_eq!(
        off, 0,
        "the named stream has its own offset space starting at 0"
    );

    let (_exists, head) = c.stream_info("s").await.unwrap();
    assert_eq!(head, 1, "the named stream's durable head advanced by one");

    // Subscribe to the named stream's work-group and consume + ack the record via that group.
    c.subscribe_to("s", "g").await.unwrap();
    let fetched = c.fetch(10).await.unwrap();
    assert_eq!(
        fetched.messages.len(),
        1,
        "the named-stream record is delivered"
    );
    assert_eq!(
        fetched.messages[0].payload, b"stream-record",
        "the named-stream payload round-trips byte-for-byte"
    );
    assert_eq!(fetched.messages[0].offset, 0);
    assert!(
        c.ack(fetched.messages[0].offset, fetched.messages[0].generation)
            .await
            .unwrap(),
        "the named-stream record acks"
    );

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// The DURABLE Tier-S streaming consume path end to end (#544 / #550): produce a prefix to the default
/// stream, then consume it with the batched-default [`AsyncStreamingConsumer`] (windowed `stream_fetch`
/// + PERIODIC cumulative `stream_commit`, the consumer-managed-offset NATS-pull contract). The payloads
/// match in order and the commit advances; a FRESH streaming consumer resuming from the committed offset
/// sees NOTHING, proving the periodic cumulative commit durably advanced the cursor. This is the path a
/// JetStream-pull-style durable named-stream consumer reuses.
#[tokio::test]
async fn async_streaming_consumer_durably_consumes_and_commits_against_a_real_server() {
    let (addr, shutdown, handle) = start_server();

    // Produce a durable prefix of 10 records to the default stream.
    {
        let mut p = AsyncClient::connect(addr).await.unwrap();
        for i in 0..10u64 {
            p.produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: &[(i & 0xff) as u8],
            })
            .await
            .unwrap();
        }
    }

    // A Tier-S consumer subscribed to a streaming group consumes in windows of 4 with a commit cadence
    // of 2 (commit after windows 2 and 3 — periodic, NOT per record). Read-ahead off keeps the assertions
    // on committed/next offsets deterministic.
    let mut c = AsyncClient::connect_with(addr, &config_streaming())
        .await
        .unwrap();
    assert!(
        c.streaming_enabled(),
        "the server confirmed the streaming tier"
    );
    c.subscribe("s").await.unwrap();

    let cfg = StreamConsumerConfig {
        max_records: 4,
        max_bytes: 0,
        commit_every_batches: 2,
        start_offset: 0,
        read_ahead: false,
    };

    let mut seen = Vec::new();
    {
        let mut consumer = c.streaming_consumer_with("s", &cfg);

        let b0 = consumer.next_batch().await.unwrap();
        assert_eq!(
            b0.messages.len(),
            4,
            "window one is a full batch, not one record"
        );
        assert_eq!(b0.messages[0].offset, 0);
        for m in &b0.messages {
            seen.push(m.offset);
        }
        assert_eq!(
            consumer.committed_offset(),
            0,
            "no commit after one window (cadence 2)"
        );
        assert_eq!(consumer.next_offset(), 4);

        let b1 = consumer.next_batch().await.unwrap();
        assert_eq!(b1.messages.len(), 4);
        for m in &b1.messages {
            seen.push(m.offset);
        }
        // The cadence (2) is reached: the cumulative commit covers offsets [0, 8).
        assert_eq!(
            consumer.committed_offset(),
            8,
            "periodic commit after two windows"
        );

        let b2 = consumer.next_batch().await.unwrap();
        assert_eq!(b2.messages.len(), 2, "the short tail window");
        for m in &b2.messages {
            seen.push(m.offset);
        }
        assert_eq!(consumer.next_offset(), 10);

        // Drained: an empty window flushes the final commit so the whole prefix is durable.
        let b3 = consumer.next_batch().await.unwrap();
        assert!(b3.is_empty(), "the stream has drained to its head");
        assert_eq!(
            consumer.committed_offset(),
            10,
            "the drain flushed the final commit"
        );
    }
    assert_eq!(
        seen,
        (0..10).collect::<Vec<u64>>(),
        "all ten records were delivered in order"
    );
    drop(c);

    // A fresh streaming consumer resuming from the committed offset sees nothing: the periodic
    // cumulative commit durably advanced the group cursor past every record (no per-record ack needed).
    let mut c2 = AsyncClient::connect_with(addr, &config_streaming())
        .await
        .unwrap();
    c2.subscribe("s").await.unwrap();
    let resumed = c2.stream_fetch(10, 16, 0).await.unwrap();
    assert!(
        resumed.messages.is_empty(),
        "everything below offset 10 was durably committed"
    );

    drop(c2);
    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// End-to-end async client TLS (ADR-0004 / #957), compiled only under `--features tls`. The async twin of
/// the sync client's `a_client_produces_over_a_verified_tls_connection_and_a_wrong_anchor_is_rejected`:
/// an `AsyncClient` VERIFIES a real TLS-terminating broker and produces over the encrypted session, while
/// a client pointed at the WRONG trust anchor is rejected at the handshake (mandatory verification, no
/// plaintext fallback).
#[cfg(feature = "tls")]
mod tls {
    use super::*;
    use ironbus_client_async::TlsClientConfig;

    // A long-lived self-signed server cert + key for "localhost", and a DIFFERENT (wrong) trust anchor.
    // The SAME embedded fixtures the sync client's TLS test uses (rcgen pulls banned ring, so no runtime
    // cert generation).
    const TLS_SERVER_CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBVzCB/aADAgECAhMjGIxpQAwb+081fMl2nX2WEMQ8MAoGCCqGSM49BAMCMB4x
HDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIwIBcNMjAwMTAxMDAwMDAwWhgP
MjEwMDAxMDEwMDAwMDBaMB4xHDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+AoxgwFjAU
BgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJ+smDY9Jybx
FoJDOjOor9Cb56IyQQ64ts0roLO5NVx9AiEAnB1pAliacK3UDfG6xKEig12h4tzf
UrjVOalNQ4uwFJg=
-----END CERTIFICATE-----
";
    const TLS_SERVER_KEY: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWd4kisc5NnK6Nv0I
RL0rrbnn9ozoIOti7I4eisF3CHWhRANCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+A
-----END PRIVATE KEY-----
";
    const TLS_OTHER_CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBWjCCAQCgAwIBAgIUfIjY91xg+z0LSwh5bngCs73UQLswCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSaXJvbmJ1cy10ZXN0LW90aGVyMCAXDTIwMDEwMTAwMDAwMFoY
DzIxMDAwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJpcm9uYnVzLXRlc3Qtb3RoZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS/sQWpzoGIBq0tyDdZLN7918LWW/j0
+CsRiYQa+vfAdERrw1POkGOIed4wUocAT9+tMkOY/VB/OSbHJxeZwPSBoxwwGjAY
BgNVHREEETAPgg1vdGhlci5pbnZhbGlkMAoGCCqGSM49BAMCA0gAMEUCIC4trwko
Aq57VS5iw0sm+NFBdTHX5XSCUQvACWp0elXzAiEArjyI3F1SeVHMY/DKGtuy7J/3
toYtkjmdU2eQ2pK/3gM=
-----END CERTIFICATE-----
";

    /// Spins a TLS-terminating in-process broker: the same engine + append actor as [`start_server`], but
    /// served by `serve_with_auth_connz_preauth_audit` with a `TlsTermination`, so every accepted
    /// connection completes a TLS 1.3 handshake before the app-level `Connect`.
    fn start_tls_server() -> (SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
        let (handle_engine, _actor) = spawn_actor(open_engine(), DEFAULT_CHANNEL_BOUND);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_config =
            ironbus_server::tls::server_config_from_pem(TLS_SERVER_CERT, TLS_SERVER_KEY).unwrap();
        let tls = ironbus_server::server::TlsTermination::with_config(Arc::new(server_config));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = SystemClock::new();
                let beacon =
                    ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                let connz = Arc::new(ironbus_server::connz::ConnectionMetrics::new());
                ironbus_server::server::serve_with_auth_connz_preauth_audit(
                    &listener,
                    &handle_engine,
                    &shutdown,
                    16,
                    &clock,
                    &beacon,
                    None,
                    &connz,
                    None,
                    None,
                    tls,
                )
                .unwrap();
            }
        });
        (addr, shutdown, handle)
    }

    #[tokio::test]
    async fn async_client_produces_over_a_verified_tls_connection_and_a_wrong_anchor_is_rejected() {
        let (addr, shutdown, handle) = start_tls_server();

        // Correct trust anchor: verify the broker, connect over TLS 1.3, and produce.
        let config = ClientConfig {
            tls: Some(TlsClientConfig::new(TLS_SERVER_CERT.to_vec(), "localhost")),
            ..Default::default()
        };
        let mut client = AsyncClient::connect_with(addr, &config)
            .await
            .expect("the async client verifies the broker and connects");
        let offset = client
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"produced-over-async-client-tls",
            })
            .await
            .expect("a produce travels over the TLS connection");
        assert_eq!(offset, 0, "the produce is durable at offset 0");

        // Wrong trust anchor: the server certificate does not verify, so the handshake FAILS at connect.
        let bad = ClientConfig {
            tls: Some(TlsClientConfig::new(TLS_OTHER_CERT.to_vec(), "localhost")),
            ..Default::default()
        };
        assert!(
            AsyncClient::connect_with(addr, &bad).await.is_err(),
            "a client with the wrong trust anchor must be rejected at the TLS handshake"
        );

        shutdown.store(true, Ordering::Release);
        drop(client);
        let _ = handle.join();
    }
}
