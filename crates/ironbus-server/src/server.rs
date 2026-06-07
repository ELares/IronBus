// SPDX-License-Identifier: MIT OR Apache-2.0
//! A blocking, thread-per-connection TCP server that drives [`Session`]s over the append actor.
//!
//! Edge boxes carry a bounded number of local connections, so a thread per connection over
//! blocking IO keeps the binary small (no async runtime) and the model simple. The engine is owned
//! by a single APPEND ACTOR (#177); connection handlers fan in over a bounded channel and SEND
//! commands instead of locking the engine, so no handler holds a lock across an fsync. A produce is
//! group-committed by the actor (one `fdatasync` per drained batch), which removes the per-produce
//! fsync and the head-of-line block: a stalled disk no longer blocks every connection. Pings (and
//! anything that needs no engine state) are answered by the handler WITHOUT the actor, so a stalled
//! produce fsync never blocks another connection's ping. Concurrency is bounded by a connection cap
//! so a connection flood cannot spawn unbounded threads.

use crate::actor::EngineHandle;
use crate::session::Session;
use ironbus_core::clock::Clock;
use ironbus_core::keyshared::MemberId;
use ironbus_storage::fs::Filesystem;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How long the accept loop blocks before re-checking the shutdown flag.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Idle timeout on an accepted connection: a client must make progress (a ping suffices)
/// within this window or the connection is closed, bounding slow-client (slowloris) holds
/// on the connection cap.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Decrements the active-connection count on drop, so the count is released on both a
/// normal handler return and a panic unwind.
struct ConnectionSlot<'a>(&'a AtomicUsize);

impl Drop for ConnectionSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serves connections on `listener` until `shutdown` is set, spawning one thread per
/// connection (up to `max_connections` concurrently; further connections are refused). Each
/// connection drives a [`Session`] against the shared engine.
///
/// # Errors
/// Propagates a fatal listener error. A transient (would-block) accept is retried; a
/// per-connection IO error closes only that connection.
pub fn serve<F, C>(
    listener: &TcpListener,
    engine: &EngineHandle<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
{
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    // A monotonic per-connection counter that mints a distinct key_shared member id (#64) for each
    // accepted connection, so two concurrently-live members never collide in the rendezvous hash.
    // It only needs to be unique among the live connections; wraparound after 2^64 connections is
    // unreachable in any real deployment.
    let next_member = Arc::new(AtomicU64::new(0));
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                if active.load(Ordering::Acquire) >= max_connections {
                    // At capacity: refuse by dropping the stream (it closes).
                    drop(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::AcqRel);
                // Each handler gets its own cheap clone of the actor handle (a `SyncSender` clone);
                // they all fan into the same single actor, preserving the single-writer rule.
                let engine = engine.clone();
                let active = Arc::clone(&active);
                let member_id = MemberId::new(next_member.fetch_add(1, Ordering::Relaxed));
                std::thread::spawn(move || {
                    // The guard decrements the slot on return AND on a panic unwind, so a
                    // panicking handler can never permanently leak a connection-cap slot.
                    let _slot = ConnectionSlot(&active);
                    let _ = handle_connection(stream, &engine, member_id);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            // A transient accept failure (fd exhaustion, an aborted/interrupted connection)
            // must not tear down the whole listener: back off briefly and keep serving.
            Err(_) => std::thread::sleep(ACCEPT_POLL),
        }
    }
    Ok(())
}

/// Drives one connection: read bytes, run the session, write responses, until the client
/// closes or the session ends.
fn handle_connection<F, C>(
    mut stream: TcpStream,
    engine: &EngineHandle<F, C>,
    member_id: MemberId,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
{
    stream.set_nonblocking(false)?; // the handler reads blocking
                                    // Bound how long a stalled client can hold this slot (slowloris defense): a read or
                                    // write that makes no progress within the window errors out and closes the connection.
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let mut session = Session::with_member_id(member_id);
    // The read/dispatch loop, run to completion so the cleanup below ALWAYS executes on exit:
    // whether the client closed cleanly, a read/write timed out, or a malformed frame ended the
    // session, this connection must leave any key_shared group it joined (#64) and flush its cursor.
    let outcome = connection_loop(&mut stream, engine, &mut session);
    // Leave any key_shared group (#64) so this member's keys re-route to their new owners (its
    // in-flight records drain or expire, the drain-or-expire guard), then flush its work-group's
    // committed cursor so a clean reconnect resumes past acked messages. Both go through the actor
    // (the single writer). Best-effort: the checkpoint is a lagging optimization, and if the actor
    // is already gone (a shutdown drain races a disconnect) these are no-ops, never a hang. Routed
    // to the session's group (#60), default-group if unsubscribed.
    let _ = session.leave_current_key_shared(engine);
    // Deregister this connection's active subscription (#288) so a broadcast group's group-of-one
    // slot frees for the next subscriber on disconnect, not just on an explicit UNSUB. Best-effort,
    // like the key_shared leave: a no-op for an unsubscribed connection or a gone actor.
    //
    // This is a best-effort PLAIN call (not run from a Drop guard): a panic unwinding out of
    // `connection_loop` would skip it and leak the registration, leaving the broadcast slot stuck
    // `BroadcastGroupBusy`. That is the same panic-unwind exposure as the `leave_current_key_shared`
    // cleanup directly above; there is no panic source in those lib paths today, so it is not a
    // live bug, but a future panic-prone refactor of the loop must keep this on every exit path.
    let _ = session.leave_current_subscription(engine);
    let group = session.subscription().to_string();
    let _ = engine.with(move |e| {
        let _ = e.checkpoint_group(&group);
    });
    outcome
}

/// The per-connection read/dispatch loop, factored out so [`handle_connection`] can run its
/// cleanup (`key_shared` leave, cursor flush) on EVERY exit path: a clean close, a read/write
/// error, or a session-ending malformed frame. Returns when the client closes or the session ends.
///
/// The `needed` hint from [`Session::process`] avoids the O(n^2) re-decode of a trickled near-cap
/// frame (#176): after a pass leaves a partial trailing frame needing `needed` bytes, the loop does
/// not re-run `process` until the buffer has reached that length, so each frame is decoded a constant
/// number of times no matter how the client drips it.
fn connection_loop<F, C>(
    stream: &mut TcpStream,
    engine: &EngineHandle<F, C>,
    session: &mut Session,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
{
    let mut inbuf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    // The minimum buffer length before re-running `process` is worth it: `0` means run on any new
    // byte; a larger value is the trailing partial frame's `needed` hint, so a near-cap frame
    // trickled byte-by-byte is decoded once it is whole, not once per byte (#176).
    let mut needed: usize = 0;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(()); // the client closed the connection
        }
        inbuf.extend_from_slice(&chunk[..n]);
        // Skip the dispatch until the buffer can make progress on the known-partial trailing frame.
        if inbuf.len() < needed {
            continue;
        }

        let mut out = Vec::new();
        let Ok(progress) = session.process(engine, &inbuf, &mut out) else {
            // A malformed frame, a fatal engine error, or a gone actor: flush any queued response
            // and close (a length-prefixed stream cannot resync).
            let _ = stream.write_all(&out);
            return Ok(());
        };
        inbuf.drain(..progress.consumed);
        // Persist the session's work-group cursor on the configured interval so a crash redelivers a
        // bounded tail. ONLY when this pass actually advanced a committed cursor (an ack/flow/unsub):
        // a ping- or connect-only pass skips the checkpoint entirely, so it never sends a command to
        // the actor and therefore CANNOT be head-of-line-blocked by another connection's stalled
        // produce fsync (#177 invariant 4). Best-effort: a checkpoint write failure only costs
        // redelivery on restart, never correctness, so it must not fail the connection. Routed to the
        // session's group (#60); a gone actor is a no-op, never a hang.
        if progress.committed_progress {
            let group = session.subscription().to_string();
            let _ = engine.with(move |e| {
                let _ = e.maybe_checkpoint_group(&group);
            });
        }
        // Remember how many bytes the trailing partial frame needs before the next pass.
        needed = progress.needed;
        if !out.is_empty() {
            stream.write_all(&out)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::{spawn_actor, EngineHandle, DEFAULT_CHANNEL_BOUND};
    use crate::clock::SystemClock;
    use crate::engine::{DiskFullPolicy, Engine, EngineConfig, Poll};
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameType};
    use ironbus_proto::message::{decode_deliver, encode_ack, encode_pub, AckBody, AckOp, PubBody};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;

    fn config() -> EngineConfig {
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
            max_groups: crate::engine::DEFAULT_MAX_GROUPS,
            group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
            disk_full_policy: DiskFullPolicy::DropNew,
        }
    }

    fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode_frame(ty, body, &mut v).unwrap();
        v
    }

    /// Reads from `stream` until one complete frame is available, returning its type and
    /// body. `buf` carries leftover bytes between calls so a read that delivers several
    /// frames at once is not lost.
    fn read_one_frame(stream: &mut TcpStream, buf: &mut Vec<u8>) -> (FrameType, Vec<u8>) {
        let mut chunk = [0u8; 256];
        loop {
            if let Ok(FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            }) = decode_frame(buf)
            {
                let result = (FrameType::from_u8(type_tag).unwrap(), body.to_vec());
                buf.drain(..consumed);
                return result;
            }
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "connection closed before a full frame");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    #[test]
    fn a_panicking_handler_releases_its_connection_slot() {
        // The drop-guard must release the slot on a panic unwind, not just a normal return,
        // so a panicking handler can never permanently leak a connection-cap slot.
        let active = Arc::new(AtomicUsize::new(0));
        active.fetch_add(1, Ordering::AcqRel);
        let a = Arc::clone(&active);
        let handle = std::thread::spawn(move || {
            let _slot = ConnectionSlot(&a);
            panic!("simulate a handler panic");
        });
        assert!(handle.join().is_err(), "the handler panicked");
        assert_eq!(
            active.load(Ordering::Acquire),
            0,
            "the connection slot was released on unwind"
        );
    }

    /// Opens an in-memory engine and spawns the append actor over it, returning a handle plus the
    /// actor's join handle (which yields the engine back on a clean exit so a test can inspect it).
    fn spawn_inmem() -> (
        EngineHandle<InMemoryFs, SystemClock>,
        std::thread::JoinHandle<Engine<InMemoryFs, SystemClock>>,
    ) {
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), config()).unwrap();
        spawn_actor(engine, DEFAULT_CHANNEL_BOUND)
    }

    /// Drops the last handle held by the test and joins the actor, recovering the engine. The server
    /// thread holds its own clone of the handle, so the caller must have already joined the server
    /// (or dropped its handle) for the actor's command channel to disconnect and the actor to exit.
    fn recover_engine(
        handle: EngineHandle<InMemoryFs, SystemClock>,
        actor: std::thread::JoinHandle<Engine<InMemoryFs, SystemClock>>,
    ) -> Engine<InMemoryFs, SystemClock> {
        // An explicit shutdown drains the actor deterministically (flush + checkpoint), then the
        // join yields the owned engine.
        let _ = handle.shutdown();
        drop(handle);
        actor.join().unwrap()
    }

    #[test]
    fn produce_over_tcp_appends_to_the_engine() {
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));

        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &engine, &shutdown, 16).unwrap()
        });

        // Client: connect, handshake, publish, read the responses.
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = Vec::new();
        client.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut client, &mut buf).0, FrameType::Info);

        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                payload: b"net",
            },
            &mut pub_body,
        )
        .unwrap();
        client.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
        let (ty, body) = read_one_frame(&mut client, &mut buf);
        assert_eq!(ty, FrameType::PubAck);
        assert_eq!(
            body,
            0u64.to_le_bytes(),
            "PubAck carries the assigned offset 0"
        );

        drop(client);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();

        // The message is durable in the engine and deliverable.
        let mut engine = recover_engine(handle, actor);
        match engine.poll(0).unwrap() {
            Poll::Message(d) => assert_eq!(d.record.payload, b"net"),
            other => panic!("expected the produced message, got {other:?}"),
        }
    }

    #[test]
    fn full_produce_fetch_ack_round_trip_over_tcp() {
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &engine, &shutdown, 16).unwrap()
        });

        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        c.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::Info);

        // Produce.
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"e2e",
            },
            &mut pub_body,
        )
        .unwrap();
        c.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::PubAck);

        // Fetch: a Deliver frame then the FlowEnd terminator.
        c.write_all(&frame(FrameType::Flow, &1u32.to_le_bytes()))
            .unwrap();
        let (ty, body) = read_one_frame(&mut c, &mut buf);
        assert_eq!(ty, FrameType::Deliver);
        let delivered = decode_deliver(&body).unwrap();
        assert_eq!(delivered.payload, b"e2e");
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::FlowEnd); // batch terminator

        // Ack it.
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: delivered.offset,
                generation: delivered.generation,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        c.write_all(&frame(FrameType::Ack, &ack_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::AckStatus);

        drop(c);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();

        // The message was committed: nothing left to deliver.
        let engine = recover_engine(handle, actor);
        assert_eq!(engine.committed_offset().get(), 1);
    }

    #[test]
    fn a_clean_disconnect_checkpoints_the_cursor() {
        // The default interval is 1024, so a single ack does NOT trigger maybe_checkpoint:
        // the committed cursor can only become durable here via the close-path checkpoint the
        // server forces when the client disconnects. Reopening then proves that path fired.
        let (handle, actor) = spawn_inmem();

        // Drive one connection through handle_connection directly so we can JOIN it: when it
        // returns, the EOF-triggered checkpoint is deterministically complete (no race).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn({
            let engine = handle.clone();
            move || {
                let (stream, _) = listener.accept().unwrap();
                handle_connection(stream, &engine, MemberId::new(0))
            }
        });

        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        c.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::Info);

        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"persist-me",
            },
            &mut pub_body,
        )
        .unwrap();
        c.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::PubAck);

        c.write_all(&frame(FrameType::Flow, &1u32.to_le_bytes()))
            .unwrap();
        let (ty, body) = read_one_frame(&mut c, &mut buf);
        assert_eq!(ty, FrameType::Deliver);
        let delivered = decode_deliver(&body).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::FlowEnd);

        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: delivered.offset,
                generation: delivered.generation,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        c.write_all(&frame(FrameType::Ack, &ack_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::AckStatus);

        // Clean disconnect: handle_connection reads EOF, forces the checkpoint (through the actor),
        // and returns.
        drop(c);
        server.join().unwrap().unwrap();

        // Recover the engine's filesystem and reopen it: the committed cursor (1) was persisted by
        // the close path, so the engine resumes at 1 rather than redelivering the acked message.
        let engine = recover_engine(handle, actor);
        let fs = engine.into_filesystem();
        let reopened = Engine::open(fs, SystemClock::new(), config()).unwrap();
        assert_eq!(
            reopened.committed_offset().get(),
            1,
            "a clean disconnect must persist the committed cursor"
        );
    }

    #[test]
    fn a_malformed_frame_closes_the_connection() {
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &engine, &shutdown, 16).unwrap()
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // A zero-length frame prefix is a malformed envelope: the server closes the conn.
        client.write_all(&[0u8, 0, 0, 0]).unwrap();
        let mut chunk = [0u8; 16];
        // The server closes, so the read returns 0 (EOF).
        let n = client.read(&mut chunk).unwrap();
        assert_eq!(
            n, 0,
            "server should close the connection on a malformed frame"
        );

        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        let _ = recover_engine(handle, actor);
    }

    #[test]
    fn a_stalled_produce_fsync_does_not_block_another_connections_ping() {
        // The #177 acceptance test: a stalled produce `sync_data` on ONE producer's group must not
        // head-of-line-block another connection's ping. Pre-#177 every connection waited on the same
        // engine `Mutex`, which a produce held across its fsync, so a stalled disk froze pings too.
        // Now the engine is owned by the append actor and pings are answered by the connection handler
        // WITHOUT touching the actor, so a producer parked in the actor's group-commit fsync cannot
        // delay another connection's ping. We prove it with the fault fs's sync GATE (no wall-clock
        // sleep): producer A's produce parks mid-fsync, and meanwhile B's ping returns Pong.
        use ironbus_core::clock::ManualClock;
        use ironbus_proto::message::{encode_pub, PubBody};
        use ironbus_storage::fault::FaultFs;

        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &engine, &shutdown, 16).unwrap()
        });

        // Connection A: connect, then publish. Close the sync gate FIRST so A's produce parks inside
        // the actor's group-commit fsync and never returns until we open the gate.
        control.close_sync_gate();
        let mut a = TcpStream::connect(addr).unwrap();
        a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut abuf = Vec::new();
        a.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut a, &mut abuf).0, FrameType::Info);
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"stalled",
            },
            &mut pub_body,
        )
        .unwrap();
        // A's produce blocks in the actor's fsync; A does NOT get a PubAck yet. Send it from a thread
        // (it would otherwise block this test thread waiting for the never-arriving PubAck).
        let a_producer = std::thread::spawn(move || {
            a.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
            // This read blocks until the gate opens and the PubAck finally arrives.
            let (ty, _) = read_one_frame(&mut a, &mut abuf);
            assert_eq!(
                ty,
                FrameType::PubAck,
                "A's produce eventually acks once durable"
            );
            a
        });

        // Wait until A's produce is actually parked inside the closed gate (no wall-clock sleep).
        control.wait_for_sync_gate_entered(1);

        // Connection B: while A's fsync is stalled, B's ping must be answered. This is the head-of-line
        // property: the ping never reaches the actor, so the stalled produce cannot block it.
        let mut b = TcpStream::connect(addr).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut bbuf = Vec::new();
        b.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut b, &mut bbuf).0, FrameType::Info);
        b.write_all(&frame(FrameType::Ping, b"")).unwrap();
        assert_eq!(
            read_one_frame(&mut b, &mut bbuf).0,
            FrameType::Pong,
            "B's ping is answered while A's produce fsync is stalled (no head-of-line block)"
        );

        // Release the gate: A's produce now completes (its PubAck arrives) and its thread joins.
        control.open_sync_gate();
        let a = a_producer.join().unwrap();
        drop(a);
        drop(b);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        // Drain and stop the actor (it owns the fault-fs engine).
        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join();
    }
}
