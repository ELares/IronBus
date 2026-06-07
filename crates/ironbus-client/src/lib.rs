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
    decode_dead_letter, decode_deliver, decode_truncated, encode_ack, encode_pub, encode_sub,
    AckBody, AckOp, BodyError, PubBody, SubBody,
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

/// A dead-letter advisory: the broker dropped a message from delivery because it exceeded
/// `MaxDeliver` (poison). The consumer learns the offset was skipped rather than silently
/// never seeing it (#63). The durable DLQ topic write is separate from this notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadLetter {
    /// The log offset of the dead-lettered message.
    pub offset: u64,
    /// Why it was dead-lettered (0 = exceeded `MaxDeliver`; other values reserved).
    pub reason: u8,
}

/// A truncation advisory: the broker reset this consumer's cursor UP to `earliest_retained`
/// because the disk-full drop-oldest policy force-reaped its old segments out from under it
/// (#82, #84). The consumer lost the span `[old_cursor, earliest_retained)` and delivery resumes
/// at `earliest_retained`; it is surfaced exactly once per gap, never repeated for the same gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Truncation {
    /// The new earliest-retained log offset the cursor was reset to (delivery resumes here).
    pub earliest_retained: u64,
    /// How many records were skipped (`earliest_retained - old_cursor`).
    pub skipped: u64,
}

/// The result of a [`Client::fetch`]: the messages delivered in the batch, any in-band dead-letter
/// advisories for offsets the broker skipped as poison, and any truncation advisories for a cursor
/// the broker reset because the disk-full drop-oldest policy reaped its records, all during the
/// same batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fetch {
    /// The messages delivered, in log order.
    pub messages: Vec<Message>,
    /// Dead-letter advisories for offsets dropped as poison during this fetch (usually empty).
    pub dead_letters: Vec<DeadLetter>,
    /// Truncation advisories for a cursor reset below the oldest retained record during this fetch
    /// (usually empty; only under the disk-full drop-oldest policy, #82, #84).
    pub truncations: Vec<Truncation>,
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
    pub fn fetch(&mut self, max: u32) -> Result<Fetch, ClientError> {
        self.send(FrameType::Flow, &max.to_le_bytes())?;
        // The credit caps the TOTAL frames the server may stream back before FlowEnd: each granted
        // slot yields at most one delivery OR one dead-letter advisory OR one truncation advisory,
        // so a buggy or hostile server cannot stream any of them without bound.
        let limit = usize::try_from(max).unwrap_or(usize::MAX);
        let mut messages = Vec::new();
        let mut dead_letters = Vec::new();
        let mut truncations = Vec::new();
        // The total advisory + delivery frames seen so far, the quantity the credit bounds.
        let over_credit = |m: &[Message], d: &[DeadLetter], t: &[Truncation]| {
            m.len() + d.len() + t.len() >= limit
        };
        loop {
            match self.read_frame()? {
                (FrameType::Deliver, body) => {
                    if over_credit(&messages, &dead_letters, &truncations) {
                        return Err(ClientError::BadResponse(
                            "server streamed more frames than the requested credit",
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
                // An in-band dead-letter advisory for an offset skipped as poison (#63). It is
                // not a delivery, so it carries its own offset and does not ack.
                (FrameType::DeadLetter, body) => {
                    if over_credit(&messages, &dead_letters, &truncations) {
                        return Err(ClientError::BadResponse(
                            "server streamed more frames than the requested credit",
                        ));
                    }
                    let dl = decode_dead_letter(&body).map_err(ClientError::Body)?;
                    dead_letters.push(DeadLetter {
                        offset: dl.offset,
                        reason: dl.reason,
                    });
                }
                // An in-band truncation advisory: the broker reset this cursor below the oldest
                // retained record because the disk-full drop-oldest policy reaped its records
                // (#82, #84). It is not a delivery and does not ack; it names where delivery
                // resumed and how many records were skipped.
                (FrameType::Truncated, body) => {
                    if over_credit(&messages, &dead_letters, &truncations) {
                        return Err(ClientError::BadResponse(
                            "server streamed more frames than the requested credit",
                        ));
                    }
                    let t = decode_truncated(&body).map_err(ClientError::Body)?;
                    truncations.push(Truncation {
                        earliest_retained: t.earliest_retained,
                        skipped: t.skipped,
                    });
                }
                // The FlowEnd frame terminates the batch (its body is the delivered count).
                (FrameType::FlowEnd, _) => {
                    return Ok(Fetch {
                        messages,
                        dead_letters,
                        truncations,
                    })
                }
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
    /// The name's shape (graphic ASCII, length) and the per-engine group cap are validated
    /// by the server when the group is first used, so a malformed or excess group name is
    /// reported by the next [`Client::fetch`] as a [`ClientError::Server`], not here.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the subscription, or a frame or
    /// connection error.
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
    use ironbus_proto::message::{
        encode_dead_letter, encode_deliver, DeadLetterBody, DeliverBody, DEAD_LETTER_MAX_DELIVER,
    };
    use ironbus_server::clock::SystemClock;
    use ironbus_server::engine::{
        DiskFullPolicy, Engine, EngineConfig, DEFAULT_GROUP_IDLE_EVICT_MS, DEFAULT_MAX_GROUPS,
    };
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
        start_server_with_credit(64)
    }

    /// Starts an in-process broker with an explicit per-consumer `consumer_credit` and an UNLIMITED
    /// byte budget, for the #65 credit tests; the roomy `max_in_flight` of 16 keeps the per-group
    /// window from being the binding bound for the small credits these tests use.
    fn start_server_with_credit(
        consumer_credit: u32,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        // The #65 tests exercise the message-count bound, so the byte budget must not bind (0 = off).
        start_server_with_credit_and_bytes(consumer_credit, 0)
    }

    /// Starts an in-process broker with an explicit per-consumer message credit AND byte budget, for
    /// the #275 byte-budget end-to-end tests; the roomy `max_in_flight` of 16 keeps the per-group
    /// window from binding for the small credits these tests use.
    fn start_server_with_credit_and_bytes(
        consumer_credit: u32,
        consumer_credit_bytes: u64,
    ) -> (
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
                consumer_credit,
                consumer_credit_bytes,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
                disk_full_policy: DiskFullPolicy::DropNew,
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

        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, b"client-msg");
        assert_eq!(messages[0].offset, 0);

        assert!(c.ack(messages[0].offset, messages[0].generation).unwrap());
        // Nothing left to fetch.
        assert!(c.fetch(10).unwrap().messages.is_empty());

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
                .messages
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
        assert!(c.fetch(5).unwrap().messages.is_empty());
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
        let messages = c.fetch(10).unwrap().messages;
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
    fn fetch_surfaces_a_dead_letter_advisory() {
        // A poison offset the broker skipped arrives as an in-band DEAD_LETTER frame inside the
        // Flow batch (#63): fetch returns it in `dead_letters`, separate from `messages`, and
        // the FlowEnd still terminates the batch normally.
        let mut dl_body = Vec::new();
        encode_dead_letter(
            &DeadLetterBody {
                offset: 7,
                reason: DEAD_LETTER_MAX_DELIVER,
            },
            &mut dl_body,
        );
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::DeadLetter, &dl_body));
        script.extend(frame(FrameType::FlowEnd, &0u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        let fetched = c.fetch(10).unwrap();
        assert!(fetched.messages.is_empty(), "no messages in this batch");
        assert_eq!(
            fetched.dead_letters,
            vec![DeadLetter {
                offset: 7,
                reason: DEAD_LETTER_MAX_DELIVER
            }],
            "the dead-letter advisory is surfaced with its offset and reason"
        );
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn fetch_surfaces_a_truncation_advisory() {
        // A cursor the broker reset below the oldest retained record (the disk-full drop-oldest
        // policy reaped its records, #82, #84) arrives as an in-band Truncated frame inside the
        // Flow batch: fetch returns it in `truncations`, separate from `messages` and
        // `dead_letters`, and the FlowEnd still terminates the batch normally.
        let mut t_body = Vec::new();
        ironbus_proto::message::encode_truncated(
            &ironbus_proto::message::TruncatedBody {
                earliest_retained: 12,
                skipped: 5,
            },
            &mut t_body,
        );
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::Truncated, &t_body));
        script.extend(frame(FrameType::FlowEnd, &0u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        let fetched = c.fetch(10).unwrap();
        assert!(fetched.messages.is_empty(), "no messages in this batch");
        assert!(
            fetched.dead_letters.is_empty(),
            "no dead-letters in this batch"
        );
        assert_eq!(
            fetched.truncations,
            vec![Truncation {
                earliest_retained: 12,
                skipped: 5
            }],
            "the truncation advisory is surfaced with its resume offset and skipped count"
        );
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn fetch_truncation_counts_against_the_credit() {
        // A Truncated advisory counts as one frame toward the credit bound, so a server that
        // streams more total frames (deliveries + advisories) than the credit is rejected.
        fn truncated(off: u64) -> Vec<u8> {
            let mut body = Vec::new();
            ironbus_proto::message::encode_truncated(
                &ironbus_proto::message::TruncatedBody {
                    earliest_retained: off,
                    skipped: 1,
                },
                &mut body,
            );
            frame(FrameType::Truncated, &body)
        }
        let mut script = frame(FrameType::Info, b"");
        script.extend(truncated(1));
        script.extend(truncated(2)); // one past the credit of 1
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

        let first = c.fetch(10).unwrap().messages;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].payload, b"retry-me");

        // Nack with no delay: the broker requeues it (the default 30s visibility means it
        // would not otherwise redeliver within this test, so the nack is what brings it back).
        // None: no explicit delay; the in-process server has an empty schedule, so immediate.
        assert!(c.nack(first[0].offset, first[0].generation, None).unwrap());

        let second = c.fetch(10).unwrap().messages;
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
        assert!(c.fetch(10).unwrap().messages.is_empty());

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
        let msgs = c.fetch(10).unwrap().messages;
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
        assert!(c.fetch(10).unwrap().messages.is_empty());

        // A progress or term on a now-stale token is fenced.
        assert_eq!(
            c.progress(msgs[0].offset, msgs[0].generation).unwrap(),
            ProgressOutcome::Fenced
        );
        assert!(!c.term(msgs[1].offset, msgs[1].generation).unwrap());

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_fetch_is_capped_at_the_per_consumer_credit_over_a_real_server() {
        // End to end (#65): with a broker per-consumer credit of 3, a single client fetching with a
        // huge requested credit gets at most 3 un-acked at once, then nothing until it acks. Acking
        // frees the slots so the next fetch delivers again. The default 30s visibility means nothing
        // redelivers within the test, so a non-empty second fetch can only come from freed credit.
        let (addr, shutdown, handle) = start_server_with_credit(3);
        let mut producer = Client::connect(addr).unwrap();
        for _ in 0..10 {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    payload: b"m",
                })
                .unwrap();
        }
        let mut c = Client::connect(addr).unwrap();
        let first = c.fetch(1000).unwrap().messages;
        assert_eq!(
            first.len(),
            3,
            "the per-consumer credit of 3 caps the fetch, not the requested 1000"
        );
        // Saturated: a second fetch gets nothing while the 3 stay un-acked.
        assert!(
            c.fetch(1000).unwrap().messages.is_empty(),
            "a saturated consumer gets nothing until it acks"
        );
        // Ack all three: the slots free.
        for m in &first {
            assert!(c.ack(m.offset, m.generation).unwrap());
        }
        let second = c.fetch(1000).unwrap().messages;
        assert_eq!(
            second.len(),
            3,
            "acking the three freed the credit for three more"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn one_stuck_consumer_does_not_starve_a_peer_over_a_real_server() {
        // THE core property end to end (#65, isolation from #10): two clients in the SAME default
        // competing group, each with a per-consumer credit of 2. Client A fetches its full credit
        // and never acks (stuck). Client B still receives its full credit of 2; A's held leases do
        // not consume B's budget. The roomy group window (16) is not the binding bound, so the only
        // bound is each consumer's own credit.
        let (addr, shutdown, handle) = start_server_with_credit(2);
        let mut producer = Client::connect(addr).unwrap();
        for _ in 0..8 {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    payload: b"m",
                })
                .unwrap();
        }
        let mut a = Client::connect(addr).unwrap();
        let mut b = Client::connect(addr).unwrap();
        // A fills its credit and goes stuck (never acks).
        let a_msgs = a.fetch(1000).unwrap().messages;
        assert_eq!(a_msgs.len(), 2, "A holds its full credit of 2");
        assert!(a.fetch(1000).unwrap().messages.is_empty(), "A is saturated");
        // B still gets its full credit of 2: A's stuck leases did not starve it.
        let b_msgs = b.fetch(1000).unwrap().messages;
        assert_eq!(
            b_msgs.len(),
            2,
            "B receives its full credit; the stuck consumer A did not reduce it"
        );
        // The competing group hands each message to one member, so A and B hold disjoint offsets.
        let a_offsets: std::collections::BTreeSet<u64> = a_msgs.iter().map(|m| m.offset).collect();
        let b_offsets: std::collections::BTreeSet<u64> = b_msgs.iter().map(|m| m.offset).collect();
        assert!(
            a_offsets.is_disjoint(&b_offsets),
            "A and B hold disjoint offsets: {a_offsets:?} vs {b_offsets:?}"
        );
        // B keeps draining at its full credit while A stays stuck forever.
        for m in &b_msgs {
            assert!(b.ack(m.offset, m.generation).unwrap());
        }
        assert_eq!(
            b.fetch(1000).unwrap().messages.len(),
            2,
            "B keeps making progress while A holds its slots"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_byte_budget_binds_over_a_real_server() {
        // End to end (#275): a roomy message credit (64) but a tight BYTE budget (200) with 100-byte
        // payloads. A single client fetching with a huge requested credit gets only 2 messages (the
        // in-flight bytes reach the 200-byte budget), NOT the 64 the message credit would allow.
        // Acking frees the bytes so the next fetch delivers again. The default 30s visibility means
        // nothing redelivers within the test, so a non-empty second fetch is freed bytes, not expiry.
        let (addr, shutdown, handle) = start_server_with_credit_and_bytes(64, 200);
        let mut producer = Client::connect(addr).unwrap();
        let payload = [0xab_u8; 100];
        for _ in 0..10 {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    payload: &payload,
                })
                .unwrap();
        }
        let mut c = Client::connect(addr).unwrap();
        let first = c.fetch(1000).unwrap().messages;
        assert_eq!(
            first.len(),
            2,
            "the 200-byte budget caps the fetch at 2x100 bytes, not the message credit of 64"
        );
        // Saturated on bytes: a second fetch gets nothing while the 200 bytes stay un-acked.
        assert!(
            c.fetch(1000).unwrap().messages.is_empty(),
            "in-flight bytes have reached the budget, so no more deliveries until an ack"
        );
        // Ack both: their 200 bytes free.
        for m in &first {
            assert!(c.ack(m.offset, m.generation).unwrap());
        }
        let second = c.fetch(1000).unwrap().messages;
        assert_eq!(
            second.len(),
            2,
            "acking the two freed their bytes, so the next fetch delivers two more"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_byte_budget_floor_of_one_over_a_real_server() {
        // End to end (#275): the hard floor of ONE. A 100-byte budget with a single 500-byte payload
        // (larger than the whole budget) still delivers that one message, so an over-budget message
        // never wedges the consumer. A second over-budget message waits until the first frees bytes.
        let (addr, shutdown, handle) = start_server_with_credit_and_bytes(64, 100);
        let mut producer = Client::connect(addr).unwrap();
        let big = [0xcd_u8; 500];
        for _ in 0..2 {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    payload: &big,
                })
                .unwrap();
        }
        let mut c = Client::connect(addr).unwrap();
        let first = c.fetch(1000).unwrap().messages;
        assert_eq!(
            first.len(),
            1,
            "the floor-of-one delivers one over-budget message so it never wedges the consumer"
        );
        // Only one: the second over-budget message waits until the first frees its bytes.
        assert!(
            c.fetch(1000).unwrap().messages.is_empty(),
            "the floor is one; the second over-budget message waits for bytes to free"
        );
        // Ack the first; its bytes free, so the second now passes the floor and delivers.
        assert!(c.ack(first[0].offset, first[0].generation).unwrap());
        assert_eq!(
            c.fetch(1000).unwrap().messages.len(),
            1,
            "freeing the first over-budget message lets the second through (again by the floor)"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }
}
