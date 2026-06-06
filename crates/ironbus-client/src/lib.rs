// SPDX-License-Identifier: MIT OR Apache-2.0
//! A synchronous IronBus client: connect to a broker, produce, fetch, and acknowledge.
//!
//! The client owns one TCP connection and speaks the wire protocol (`ironbus-proto`)
//! request/response: it sends a frame and reads the response, framing the byte stream with
//! a persistent buffer so a read that delivers several frames at once is never lost. It is
//! blocking and minimal, matching the edge-first server.
//!
//! Connect, read, and write timeouts (see [`ClientConfig`]) bound every blocking call, so a
//! silent or slow broker surfaces as an error rather than wedging the caller forever. The
//! client also never trusts the peer's framing: it rejects an unknown frame type, a
//! wrong-shape response body, and more deliveries than it asked for.

use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{
    decode_deliver, encode_ack, encode_pub, encode_sub, AckBody, AckOp, BodyError, PubBody, SubBody,
};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// An error from the client.
#[derive(Debug)]
pub enum ClientError {
    /// An underlying IO or connection error (including a timeout).
    Io(io::Error),
    /// A malformed frame from the server (the connection cannot continue).
    Frame(FrameError),
    /// A malformed message body from the server.
    Body(BodyError),
    /// The server replied with an error: the UTF-8 message it sent.
    Server(String),
    /// The server replied with an unexpected (but known) frame type for the request.
    Unexpected(FrameType),
    /// The server sent a frame whose type tag this client does not recognize.
    UnknownFrameType(u8),
    /// The response had the expected type but a malformed shape for the request.
    BadResponse(&'static str),
    /// The connection closed before a complete response arrived.
    Closed,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io error: {e}"),
            ClientError::Frame(e) => write!(f, "frame error: {e}"),
            ClientError::Body(e) => write!(f, "message body error: {e}"),
            ClientError::Server(m) => write!(f, "server error: {m}"),
            ClientError::Unexpected(t) => write!(f, "unexpected response frame {t:?}"),
            ClientError::UnknownFrameType(tag) => {
                write!(f, "unknown response frame type tag {tag}")
            }
            ClientError::BadResponse(why) => write!(f, "malformed response: {why}"),
            ClientError::Closed => write!(f, "connection closed mid-response"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// Connection tunables: the timeouts that bound every blocking call.
///
/// The defaults are conservative but finite, so a misbehaving broker fails the call instead
/// of hanging the caller indefinitely. Set a field to `None` to block forever on that
/// operation (the pre-timeout behavior), which is rarely what you want.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Cap on the initial TCP connect. `None` uses the OS default, which can be minutes.
    pub connect_timeout: Option<Duration>,
    /// Cap on each blocking read while awaiting a response. `None` blocks forever.
    pub read_timeout: Option<Duration>,
    /// Cap on each blocking write while sending a request. `None` blocks forever.
    pub write_timeout: Option<Duration>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
        }
    }
}

/// A message delivered to the consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The log offset that names this message (carried back in the ack).
    pub offset: u64,
    /// The lease generation (the fencing token) to ack it with.
    pub generation: u64,
    /// Record flags as stored.
    pub flags: u8,
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The routing or ordering key (empty if none).
    pub key: Vec<u8>,
    /// The headers blob (empty if none).
    pub headers: Vec<u8>,
    /// The message payload.
    pub payload: Vec<u8>,
}

/// The outcome of a [`Client::progress`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressOutcome {
    /// The lease was extended by one visibility window.
    Extended,
    /// The lease reached its hard cap and cannot be extended further; it will expire and the
    /// message redeliver on schedule.
    CapReached,
    /// The token was stale (already acked, or redelivered); the progress was ignored.
    Fenced,
}

/// A connected IronBus client over one TCP connection.
#[derive(Debug)]
pub struct Client {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Client {
    /// Connects to a broker at `addr` with the default [`ClientConfig`] and completes the
    /// handshake.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on a connection failure, a timeout, or an unexpected
    /// handshake reply.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<Client, ClientError> {
        Client::connect_with(addr, &ClientConfig::default())
    }

    /// Connects to a broker at `addr` using `config` and completes the handshake.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on a connection failure, a timeout, or an unexpected
    /// handshake reply.
    pub fn connect_with<A: ToSocketAddrs>(
        addr: A,
        config: &ClientConfig,
    ) -> Result<Client, ClientError> {
        let stream = Client::dial(addr, config.connect_timeout)?;
        stream.set_read_timeout(config.read_timeout)?;
        stream.set_write_timeout(config.write_timeout)?;
        let mut client = Client {
            stream,
            buf: Vec::new(),
        };
        client.send(FrameType::Connect, &[])?;
        match client.read_frame()? {
            (FrameType::Info, _) => Ok(client),
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Resolves `addr` and connects to the first address that accepts, honoring an optional
    /// connect timeout so a black-holed host cannot block for the OS default.
    fn dial<A: ToSocketAddrs>(
        addr: A,
        timeout: Option<Duration>,
    ) -> Result<TcpStream, ClientError> {
        let mut last_err: Option<io::Error> = None;
        for sa in addr.to_socket_addrs()? {
            let attempt = match timeout {
                Some(t) => TcpStream::connect_timeout(&sa, t),
                None => TcpStream::connect(sa),
            };
            match attempt {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
        Err(ClientError::Io(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket address to connect to",
            )
        })))
    }

    /// Produces a message and returns its assigned log offset.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or a server error.
    pub fn produce(&mut self, message: &PubBody<'_>) -> Result<u64, ClientError> {
        let mut body = Vec::new();
        encode_pub(message, &mut body).map_err(ClientError::Body)?;
        self.send(FrameType::Pub, &body)?;
        match self.read_frame()? {
            (FrameType::PubAck, body) => {
                let bytes = <[u8; 8]>::try_from(body.as_slice()).map_err(|_| {
                    ClientError::BadResponse("produce reply was not an eight-byte offset")
                })?;
                Ok(u64::from_le_bytes(bytes))
            }
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Fetches up to `max` messages. Returns the delivered messages (possibly fewer, or
    /// none if the queue is empty within the consumer window).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a server that delivers
    /// more messages than the requested credit.
    pub fn fetch(&mut self, max: u32) -> Result<Vec<Message>, ClientError> {
        self.send(FrameType::Flow, &max.to_le_bytes())?;
        // The credit we granted is the hard ceiling on what we will accept back.
        let limit = usize::try_from(max).unwrap_or(usize::MAX);
        let mut messages = Vec::new();
        loop {
            match self.read_frame()? {
                (FrameType::Deliver, body) => {
                    // Never accept more deliveries than the credit we granted: a buggy or
                    // hostile server could otherwise stream Deliver frames without bound.
                    if messages.len() >= limit {
                        return Err(ClientError::BadResponse(
                            "server delivered more messages than the requested credit",
                        ));
                    }
                    let d = decode_deliver(&body).map_err(ClientError::Body)?;
                    messages.push(Message {
                        offset: d.offset,
                        generation: d.generation,
                        flags: d.flags,
                        timestamp_ms: d.timestamp_ms,
                        key: d.key.to_vec(),
                        headers: d.headers.to_vec(),
                        payload: d.payload.to_vec(),
                    });
                }
                // The FlowEnd frame terminates the batch (its body is the delivered count).
                (FrameType::FlowEnd, _) => return Ok(messages),
                (FrameType::Err, body) => {
                    return Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
                }
                (other, _) => return Err(ClientError::Unexpected(other)),
            }
        }
    }

    /// Acknowledges a fetched message by its offset and fencing generation. Returns `true`
    /// if the ack committed, `false` if it was fenced (stale: the message will redeliver).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub fn ack(&mut self, offset: u64, generation: u64) -> Result<bool, ClientError> {
        let mut body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset,
                generation,
                delay_ms: 0,
            },
            &mut body,
        );
        self.send(FrameType::Ack, &body)?;
        match self.read_frame()? {
            // The ack reply is a distinct AckStatus frame (#179) carrying exactly one status
            // byte (1 = committed, 0 = fenced). The frame TYPE now disambiguates the reply, so a
            // pub offset arrives as a PubAck (handled as Unexpected below), never as a same-tagged
            // eight-byte body that could be misread as a commit; the length check still rejects a
            // malformed AckStatus.
            (FrameType::AckStatus, body) => match body.as_slice() {
                [status] => Ok(*status == 1),
                _ => Err(ClientError::BadResponse(
                    "ack reply was not a one-byte status",
                )),
            },
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Nacks a fetched message by its offset and fencing generation, asking the broker to
    /// redeliver it. `delay_ms` is `Some(ms)` for an explicit delay (`Some(0)` = immediate) or
    /// `None` to let the broker apply its configured backoff schedule for the attempt. Returns
    /// `true` if the broker requeued it, `false` if the token was fenced (stale: it already
    /// redelivered, was acked, or you nacked it before; either way do not drop local state).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub fn nack(
        &mut self,
        offset: u64,
        generation: u64,
        delay_ms: Option<u64>,
    ) -> Result<bool, ClientError> {
        let mut body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Nack,
                offset,
                generation,
                // u64::MAX is the wire sentinel for "no explicit delay, use the server schedule".
                delay_ms: delay_ms.unwrap_or(u64::MAX),
            },
            &mut body,
        );
        self.send(FrameType::Ack, &body)?;
        match self.read_frame()? {
            (FrameType::AckStatus, body) => match body.as_slice() {
                [status] => Ok(*status == 1),
                _ => Err(ClientError::BadResponse(
                    "nack reply was not a one-byte status",
                )),
            },
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Terminates delivery of a fetched message: an intentional drop. The broker commits past
    /// it so it never redelivers and is NOT dead-lettered. Returns `true` if it was dropped,
    /// `false` if the token was fenced (stale: it already redelivered or was acked).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub fn term(&mut self, offset: u64, generation: u64) -> Result<bool, ClientError> {
        let mut body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Term,
                offset,
                generation,
                delay_ms: 0,
            },
            &mut body,
        );
        self.send(FrameType::Ack, &body)?;
        match self.read_frame()? {
            (FrameType::AckStatus, body) => match body.as_slice() {
                [status] => Ok(*status == 1),
                _ => Err(ClientError::BadResponse(
                    "term reply was not a one-byte status",
                )),
            },
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Reports that work on a fetched message is still in progress, extending its lease by one
    /// visibility window so it is not redelivered while the consumer keeps working.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub fn progress(
        &mut self,
        offset: u64,
        generation: u64,
    ) -> Result<ProgressOutcome, ClientError> {
        let mut body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Progress,
                offset,
                generation,
                delay_ms: 0,
            },
            &mut body,
        );
        self.send(FrameType::Ack, &body)?;
        match self.read_frame()? {
            (FrameType::AckStatus, body) => match body.as_slice() {
                [1] => Ok(ProgressOutcome::Extended),
                [2] => Ok(ProgressOutcome::CapReached),
                [0] => Ok(ProgressOutcome::Fenced),
                _ => Err(ClientError::BadResponse(
                    "progress reply was not a known one-byte status",
                )),
            },
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Sends a keepalive ping and waits for the pong.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or an unexpected reply.
    pub fn ping(&mut self) -> Result<(), ClientError> {
        self.send(FrameType::Ping, &[])?;
        match self.read_frame()? {
            (FrameType::Pong, _) => Ok(()),
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Subscribes this connection to a named work-group (#9): subsequent [`Client::fetch`]
    /// calls and acks route to that group, so the same log can fan out to a broadcast
    /// consumer and a competing group. An empty name selects the default group. Any leases
    /// this connection still holds in its previous group are abandoned (they redeliver there
    /// after the visibility timeout).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the name (not UTF-8, malformed,
    /// or the group cap reached), or a connection error.
    pub fn subscribe(&mut self, group: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_sub(
            &SubBody {
                group: group.as_bytes(),
            },
            &mut body,
        );
        self.send(FrameType::Sub, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Reverts this connection to the default work-group (#9), abandoning any leases it
    /// still holds in the named group (they redeliver there after the visibility timeout).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] on a server error, or a connection error.
    pub fn unsubscribe(&mut self) -> Result<(), ClientError> {
        self.send(FrameType::Unsub, &[])?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    fn send(&mut self, frame_type: FrameType, body: &[u8]) -> Result<(), ClientError> {
        let mut frame = Vec::new();
        encode_frame(frame_type, body, &mut frame).map_err(ClientError::Frame)?;
        self.stream.write_all(&frame)?;
        Ok(())
    }

    /// Reads one complete frame, buffering leftover bytes for the next call.
    fn read_frame(&mut self) -> Result<(FrameType, Vec<u8>), ClientError> {
        let mut chunk = [0u8; 4096];
        loop {
            match decode_frame(&self.buf).map_err(ClientError::Frame)? {
                FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed,
                } => {
                    // An unknown tag (e.g. from a newer server) has no client handler; name
                    // the raw tag rather than pretending it was some known frame.
                    let ty = FrameType::from_u8(type_tag)
                        .ok_or(ClientError::UnknownFrameType(type_tag))?;
                    let body = body.to_vec();
                    self.buf.drain(..consumed);
                    return Ok((ty, body));
                }
                FrameDecode::Incomplete { .. } => {}
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(ClientError::Closed);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_proto::message::{encode_deliver, DeliverBody};
    use ironbus_server::clock::SystemClock;
    use ironbus_server::engine::{Engine, EngineConfig};
    use ironbus_server::server::{serve, SharedEngine};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn start_server() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 16,
                checkpoint_interval: 1024,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &shared, &shutdown, 16).unwrap()
        });
        (addr, shutdown, handle)
    }

    /// Encodes one framed reply (length prefix, type, body).
    fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_frame(ty, body, &mut out).unwrap();
        out
    }

    /// Encodes a frame with an arbitrary (possibly unknown) raw type tag by hand:
    /// `[len: u32 LE][tag: u8][body]`, where `len` counts the tag byte plus the body.
    fn raw_frame(tag: u8, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(1 + body.len()).unwrap();
        let mut out = len.to_le_bytes().to_vec();
        out.push(tag);
        out.extend_from_slice(body);
        out
    }

    /// A one-shot listener that, on the single connection it accepts, writes `script` and
    /// then drains (discarding) until the client closes. The client drives request/response
    /// purely off its own buffer, so emitting every reply frame up front is read back in
    /// order. Lets a test stand in a hostile or buggy server with exact control of the bytes.
    fn raw_server(script: Vec<u8>) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.write_all(&script).unwrap();
            let mut sink = [0u8; 1024];
            while let Ok(n) = sock.read(&mut sink) {
                if n == 0 {
                    break;
                }
            }
        });
        (addr, handle)
    }

    #[test]
    fn produce_fetch_ack_round_trip_against_a_real_server() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        c.ping().unwrap();

        let offset = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                payload: b"client-msg",
            })
            .unwrap();
        assert_eq!(offset, 0);

        let messages = c.fetch(10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, b"client-msg");
        assert_eq!(messages[0].offset, 0);

        assert!(c.ack(messages[0].offset, messages[0].generation).unwrap());
        // Nothing left to fetch.
        assert!(c.fetch(10).unwrap().is_empty());

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn subscribed_groups_each_see_every_message() {
        // Broadcast fan-out end to end (#9): two connections subscribed to different
        // groups each independently receive every message; neither acks.
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect(addr).unwrap();
        for p in [&b"a"[..], &b"b"[..]] {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    payload: p,
                })
                .unwrap();
        }
        for group in ["alpha", "beta"] {
            let mut c = Client::connect(addr).unwrap();
            c.subscribe(group).unwrap();
            let payloads: Vec<Vec<u8>> = c
                .fetch(10)
                .unwrap()
                .into_iter()
                .map(|m| m.payload)
                .collect();
            assert_eq!(
                payloads,
                vec![b"a".to_vec(), b"b".to_vec()],
                "group {group} independently sees the whole log"
            );
        }
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn fetching_an_invalid_group_surfaces_a_server_error() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        // The name is valid UTF-8, so SUB is accepted; the engine rejects its shape on the
        // first fetch (a space is not a graphic-ASCII group name), surfaced as a server error.
        c.subscribe("has space").unwrap();
        let err = c.fetch(10).unwrap_err();
        assert!(matches!(err, ClientError::Server(_)), "got {err:?}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn fetching_an_empty_queue_returns_no_messages() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        assert!(c.fetch(5).unwrap().is_empty());
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_multi_message_fetch_returns_every_message() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        for i in 0..3u8 {
            c.produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                payload: &[i],
            })
            .unwrap();
        }
        let messages = c.fetch(10).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].payload, vec![0]);
        assert_eq!(messages[1].payload, vec![1]);
        assert_eq!(messages[2].payload, vec![2]);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_server_error_reply_is_surfaced() {
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::Err, b"boom"));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        match c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"x",
            })
            .unwrap_err()
        {
            ClientError::Server(m) => assert_eq!(m, "boom"),
            other => panic!("expected Server, got {other:?}"),
        }
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_fenced_ack_returns_false() {
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::AckStatus, &[0u8])); // fenced
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        assert!(!c.ack(7, 3).unwrap());
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_pub_ack_in_response_to_an_ack_is_unexpected_not_misread() {
        // With distinct response frames (#179), a pub offset arrives as a PubAck, a frame
        // type the ack path never accepts. The eight-byte body whose low byte is 1 can no
        // longer masquerade as a one-byte committed AckStatus: the TYPE disambiguates, so
        // this is a clean Unexpected, not a body-length guess.
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::PubAck, &1u64.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        match c.ack(0, 0).unwrap_err() {
            ClientError::Unexpected(FrameType::PubAck) => {}
            other => panic!("expected Unexpected(PubAck), got {other:?}"),
        }
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn fetch_rejects_more_deliveries_than_the_requested_credit() {
        fn deliver(offset: u64) -> Vec<u8> {
            let mut body = Vec::new();
            encode_deliver(
                &DeliverBody {
                    offset,
                    generation: 1,
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    payload: b"m",
                },
                &mut body,
            )
            .unwrap();
            frame(FrameType::Deliver, &body)
        }
        let mut script = frame(FrameType::Info, b"");
        script.extend(deliver(0));
        script.extend(deliver(1)); // one past the credit of 1
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        match c.fetch(1).unwrap_err() {
            ClientError::BadResponse(_) => {}
            other => panic!("expected BadResponse, got {other:?}"),
        }
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn an_unknown_frame_type_is_reported_with_its_tag() {
        let mut script = frame(FrameType::Info, b"");
        script.extend(raw_frame(200, b"")); // tag 200 is not a known FrameType
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        match c.ping().unwrap_err() {
            ClientError::UnknownFrameType(200) => {}
            other => panic!("expected UnknownFrameType(200), got {other:?}"),
        }
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_nacked_message_is_redelivered_against_a_real_server() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let off = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"retry-me",
            })
            .unwrap();

        let first = c.fetch(10).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].payload, b"retry-me");

        // Nack with no delay: the broker requeues it (the default 30s visibility means it
        // would not otherwise redeliver within this test, so the nack is what brings it back).
        // None: no explicit delay; the in-process server has an empty schedule, so immediate.
        assert!(c.nack(first[0].offset, first[0].generation, None).unwrap());

        let second = c.fetch(10).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].offset, off);
        assert_eq!(second[0].payload, b"retry-me");
        assert_ne!(
            second[0].generation, first[0].generation,
            "redelivery fences the old generation"
        );

        // The stale (nacked) token can no longer commit; the fresh one does.
        assert!(!c.ack(first[0].offset, first[0].generation).unwrap());
        assert!(c.ack(second[0].offset, second[0].generation).unwrap());
        assert!(c.fetch(10).unwrap().is_empty());

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn term_drops_a_message_and_progress_extends_a_lease() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        for p in [&b"keep"[..], b"drop"] {
            c.produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: p,
            })
            .unwrap();
        }
        let msgs = c.fetch(10).unwrap();
        assert_eq!(msgs.len(), 2);

        // Progress on the first: the lease is extended.
        assert_eq!(
            c.progress(msgs[0].offset, msgs[0].generation).unwrap(),
            ProgressOutcome::Extended
        );
        // Term the second: an intentional drop (committed past, never redelivered).
        assert!(c.term(msgs[1].offset, msgs[1].generation).unwrap());

        // Ack the first; now the whole prefix is committed and nothing remains.
        assert!(c.ack(msgs[0].offset, msgs[0].generation).unwrap());
        assert!(c.fetch(10).unwrap().is_empty());

        // A progress or term on a now-stale token is fenced.
        assert_eq!(
            c.progress(msgs[0].offset, msgs[0].generation).unwrap(),
            ProgressOutcome::Fenced
        );
        assert!(!c.term(msgs[1].offset, msgs[1].generation).unwrap());

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }
}
