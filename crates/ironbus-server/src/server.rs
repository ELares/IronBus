// SPDX-License-Identifier: MIT OR Apache-2.0
//! A blocking, thread-per-connection TCP server that drives [`Session`]s over the engine.
//!
//! Edge boxes carry a bounded number of local connections, so a thread per connection over
//! blocking IO keeps the binary small (no async runtime) and the model simple. The engine
//! is shared behind a `Mutex`, which serializes all access into the single logical writer
//! the storage layer requires; group-commit batching behind a dedicated append actor is a
//! throughput follow-up. Concurrency is bounded by a connection cap so a connection flood
//! cannot spawn unbounded threads. CAVEAT: a produce, and an interval or close-path cursor
//! checkpoint, holds the engine `Mutex` across its fsync, so one stalled disk
//! head-of-line-blocks every connection; the append-actor + group-commit follow-up removes
//! this.

use crate::engine::Engine;
use crate::session::Session;
use ironbus_core::clock::Clock;
use ironbus_storage::fs::Filesystem;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// A shared, single-writer engine: the `Mutex` serializes all access.
pub type SharedEngine<F, C> = Arc<Mutex<Engine<F, C>>>;

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
    engine: &SharedEngine<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + 'static,
{
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                if active.load(Ordering::Acquire) >= max_connections {
                    // At capacity: refuse by dropping the stream (it closes).
                    drop(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::AcqRel);
                let engine = Arc::clone(engine);
                let active = Arc::clone(&active);
                std::thread::spawn(move || {
                    // The guard decrements the slot on return AND on a panic unwind, so a
                    // panicking handler can never permanently leak a connection-cap slot.
                    let _slot = ConnectionSlot(&active);
                    let _ = handle_connection(stream, &engine);
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
    engine: &SharedEngine<F, C>,
) -> std::io::Result<()>
where
    F: Filesystem,
    C: Clock,
{
    stream.set_nonblocking(false)?; // the handler reads blocking
                                    // Bound how long a stalled client can hold this slot (slowloris defense): a read or
                                    // write that makes no progress within the window errors out and closes the connection.
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let mut session = Session::new();
    let mut inbuf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            // The client closed: flush its work-group's committed cursor so a clean reconnect
            // resumes past acked messages. Best-effort: the checkpoint is a lagging
            // optimization. Routed to the session's group (#60), default-group if unsubscribed.
            let mut guard = engine.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = guard.checkpoint_group(session.subscription());
            return Ok(()); // the client closed the connection
        }
        inbuf.extend_from_slice(&chunk[..n]);

        let mut out = Vec::new();
        // Hold the engine lock only for the (synchronous, non-blocking) dispatch.
        let result = {
            let mut guard = engine.lock().unwrap_or_else(PoisonError::into_inner);
            let r = session.process(&mut guard, &inbuf, &mut out);
            if r.is_ok() {
                // Persist the session's work-group cursor on the configured interval so a
                // crash redelivers a bounded tail. Best-effort: a checkpoint write failure only
                // costs redelivery on restart, never correctness, so it must not fail the
                // connection. Routed to the session's group (#60).
                let _ = guard.maybe_checkpoint_group(session.subscription());
            }
            r
        };
        if let Ok(consumed) = result {
            inbuf.drain(..consumed);
            if !out.is_empty() {
                stream.write_all(&out)?;
            }
        } else {
            // A malformed frame or a fatal engine error: flush any queued response and
            // close (a length-prefixed stream cannot resync).
            let _ = stream.write_all(&out);
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::engine::{Engine, EngineConfig, Poll};
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
            checkpoint_interval: 1024,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
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

    #[test]
    fn produce_over_tcp_appends_to_the_engine() {
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), config()).unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));

        let server = std::thread::spawn({
            let engine = Arc::clone(&shared);
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
        let mut engine = shared.lock().unwrap();
        match engine.poll(0).unwrap() {
            Poll::Message(d) => assert_eq!(d.record.payload, b"net"),
            other => panic!("expected the produced message, got {other:?}"),
        }
    }

    #[test]
    fn full_produce_fetch_ack_round_trip_over_tcp() {
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), config()).unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = Arc::clone(&shared);
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
        assert_eq!(shared.lock().unwrap().committed_offset().get(), 1);
    }

    #[test]
    fn a_clean_disconnect_checkpoints_the_cursor() {
        // The default interval is 1024, so a single ack does NOT trigger maybe_checkpoint:
        // the committed cursor can only become durable here via the close-path checkpoint the
        // server forces when the client disconnects. Reopening then proves that path fired.
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), config()).unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));

        // Drive one connection through handle_connection directly so we can JOIN it: when it
        // returns, the EOF-triggered checkpoint is deterministically complete (no race).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn({
            let shared = Arc::clone(&shared);
            move || {
                let (stream, _) = listener.accept().unwrap();
                handle_connection(stream, &shared)
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

        // Clean disconnect: handle_connection reads EOF, forces the checkpoint, and returns.
        drop(c);
        server.join().unwrap().unwrap();

        // Reopen the SAME filesystem: the committed cursor (1) was persisted by the close
        // path, so the engine resumes at 1 rather than redelivering the acked message.
        let Ok(mutex) = Arc::try_unwrap(shared) else {
            panic!("engine still shared after join");
        };
        let fs = mutex.into_inner().unwrap().into_filesystem();
        let reopened = Engine::open(fs, SystemClock::new(), config()).unwrap();
        assert_eq!(
            reopened.committed_offset().get(),
            1,
            "a clean disconnect must persist the committed cursor"
        );
    }

    #[test]
    fn a_malformed_frame_closes_the_connection() {
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), config()).unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = Arc::clone(&shared);
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
    }
}
