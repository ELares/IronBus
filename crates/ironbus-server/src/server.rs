// SPDX-License-Identifier: MIT OR Apache-2.0
//! A blocking, thread-per-connection TCP server that drives [`Session`]s over the engine.
//!
//! Edge boxes carry a bounded number of local connections, so a thread per connection over
//! blocking IO keeps the binary small (no async runtime) and the model simple. The engine
//! is shared behind a `Mutex`, which serializes all access into the single logical writer
//! the storage layer requires; group-commit batching behind a dedicated append actor is a
//! throughput follow-up. Concurrency is bounded by a connection cap so a connection flood
//! cannot spawn unbounded threads.

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
                    let _ = handle_connection(stream, &engine);
                    active.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(e) => return Err(e),
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
    let mut session = Session::new();
    let mut inbuf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(()); // the client closed the connection
        }
        inbuf.extend_from_slice(&chunk[..n]);

        let mut out = Vec::new();
        // Hold the engine lock only for the (synchronous, non-blocking) dispatch.
        let result = {
            let mut guard = engine.lock().unwrap_or_else(PoisonError::into_inner);
            session.process(&mut guard, &inbuf, &mut out)
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
    use ironbus_proto::message::{encode_pub, PubBody};
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::log::LogConfig;

    fn config() -> EngineConfig {
        EngineConfig {
            log: LogConfig::default(),
            lease: LeaseConfig::default(),
            delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
            max_in_flight: 16,
        }
    }

    fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode_frame(ty, body, &mut v).unwrap();
        v
    }

    /// Reads from `stream` until one complete frame is available, returning its type and body.
    fn read_one_frame(stream: &mut TcpStream) -> (FrameType, Vec<u8>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            if let Ok(FrameDecode::Frame { type_tag, body, .. }) = decode_frame(&buf) {
                return (FrameType::from_u8(type_tag).unwrap(), body.to_vec());
            }
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "connection closed before a full frame");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    #[test]
    fn produce_over_tcp_appends_to_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            StdFs::new(dir.path().to_path_buf()),
            SystemClock::new(),
            config(),
        )
        .unwrap();
        let shared: SharedEngine<StdFs, SystemClock> = Arc::new(Mutex::new(engine));

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
        client.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut client).0, FrameType::Info);

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
        let (ty, body) = read_one_frame(&mut client);
        assert_eq!(ty, FrameType::Ok);
        assert_eq!(body, 0u64.to_le_bytes(), "Ok carries the assigned offset 0");

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
    fn a_malformed_frame_closes_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            StdFs::new(dir.path().to_path_buf()),
            SystemClock::new(),
            config(),
        )
        .unwrap();
        let shared: SharedEngine<StdFs, SystemClock> = Arc::new(Mutex::new(engine));
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
