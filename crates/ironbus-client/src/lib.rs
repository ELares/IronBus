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
//!
//! Broker-side payload compression (#430, ADR-0003) is TRANSPARENT here: a delivery whose
//! flags carry the `COMPRESSED` bit is decompressed back to the original payload before it is
//! handed to the caller (with the bit cleared from [`Message::flags`]), so the end-to-end
//! pub/sub payload contract is byte-identical whether the broker ran `--compression none` or
//! `lz4`. The decode is bounded by the per-record decompressed-size cap (a bomb guard) and
//! resolves NO trained dictionaries: a record referencing a missing dictionary (a `zstd`-build
//! broker concern; the `lz4` path never references one) surfaces as the typed
//! [`ClientError::Decompress`] with `PoisonUnresolvedDict`, never a panic, as does an unknown
//! codec or a corrupt stream.

use ironbus_core::compress::{
    decompress_payload, DecompressError, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES,
};
use ironbus_core::types::RecordFlags;
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{
    decode_dead_letter, decode_deliver, decode_gap_marker, decode_info, decode_pub_ack,
    decode_truncated, encode_ack, encode_connect, encode_cumulative_ack, encode_fetch, encode_pub,
    encode_sub, AckBody, AckOp, BodyError, ConnectBody, CumulativeAckBody, FetchBody, PubBody,
    SubBody,
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
    /// A delivered payload carried the `COMPRESSED` flag but could not be decompressed back to
    /// the original bytes (#430): an unknown codec (e.g. a `zstd` record read by this pure-Rust
    /// client), a dictionary this client cannot resolve (`PoisonUnresolvedDict`; the client
    /// resolves none), an over-cap claimed size (a decompression bomb), or a corrupt stream. A
    /// typed error, never a panic; the broker stored and delivered the record faithfully, so the
    /// mismatch is between the record's codec needs and THIS client build.
    ///
    /// The batch's state after this error: the connection REMAINS USABLE, because
    /// [`Client::fetch`] drains the rest of the batch (the remaining frames and the terminating
    /// `FlowEnd`) before returning it, so the next request reads no stale frames. Everything the
    /// batch carried is DROPPED, though: messages decoded before (and after) the poison record
    /// are discarded un-acked, so the broker redelivers them after their visibility timeout, and
    /// any dead-letter / truncation / gap advisories in the batch are lost with them. `offset`
    /// and `generation` name the poison record's lease, so a caller can ack it
    /// ([`Client::ack`]) to skip it, or nack it toward the broker's `max_deliver` dead-letter
    /// path, instead of stalling on endless redelivery. Only the FIRST failure in a batch is
    /// reported. Since #438 the broker ALSO validates the descriptor SHAPE at produce time (a
    /// truncated descriptor, an unregistered codec id, an over-cap claimed size, a
    /// length-inconsistent `none` stream, or an empty `lz4`/`zstd` stream is rejected with a
    /// `malformed compressed descriptor` `Err`, never acked), so on a #438+ broker this error
    /// indicates a capability mismatch this build cannot resolve (a `zstd` record on a default
    /// build, an unresolvable `dict_id`), a corrupt stream behind a well-shaped descriptor, or
    /// a malformed record produced before the broker was upgraded.
    Decompress {
        /// The typed decompression failure.
        source: DecompressError,
        /// The log offset of the poison record this error names.
        offset: u64,
        /// The lease generation (the fencing token) the poison delivery carried; with `offset`
        /// it names the exact lease for an ack/nack that skips the record.
        generation: u64,
    },
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
            ClientError::Decompress { source, offset, .. } => {
                write!(
                    f,
                    "delivered payload at offset {offset} failed decompression: {source}"
                )
            }
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
    /// The per-consumer MESSAGE credit this client REQUESTS in its `Connect` handshake body (#292),
    /// or `None` to defer to the server default. The server NEGOTIATES the effective credit as
    /// `min(request, server cap)`; the client adopts the negotiated value the server advertises in
    /// `Info` (see [`Client::negotiated_credit`]). There is no unbounded request: a finite `u32` or
    /// nothing. An empty/old server ignores it, and the client keeps its local default.
    pub requested_consumer_credit: Option<u32>,
    /// The per-consumer BYTE budget this client requests in its `Connect` handshake body (#292), or
    /// `None` to defer to the server default. Negotiated and adopted exactly like
    /// `requested_consumer_credit`.
    pub requested_consumer_credit_bytes: Option<u64>,
    /// Whether this client ADVERTISES that it understands the consumer-visible `GapMarker` frame
    /// (#346): when `true`, the `Connect` sets the gap-marker capability bit, and the server may
    /// surface a skipped span as a typed `Gap` ([`Fetch::gaps`]) instead of the legacy `Truncation`.
    /// When `false` (the default, backward-compatible) the client does not advertise it and keeps
    /// receiving the legacy `Truncation` advisory. A caller checks [`Client::gap_marker_enabled`]
    /// after connecting to learn whether the server confirmed it.
    pub request_gap_marker: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            // The client requests nothing by default, so an unconfigured client behaves the same as
            // before #292 (it sends an all-absent Connect body, which the server reads as "use my
            // defaults"); a caller opts into a specific credit by setting these.
            requested_consumer_credit: None,
            requested_consumer_credit_bytes: None,
            // Off by default: an unconfigured client does not advertise gap-marker support, so it
            // keeps receiving the legacy `Truncation` advisory exactly as before (#346). A caller
            // that tracks contiguity opts in by setting this.
            request_gap_marker: false,
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
    /// Record flags for the payload AS HANDED TO THE CALLER: the stored flags, except that the
    /// `COMPRESSED` bit is CLEARED after the client's transparent decompression (#430), because
    /// the payload below is the decompressed original, not the stored object. A delivery this
    /// client cannot decompress never reaches here (it is the typed
    /// [`ClientError::Decompress`]), so the bit is never set on a returned message.
    pub flags: u8,
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The routing or ordering key (empty if none).
    pub key: Vec<u8>,
    /// The headers blob (empty if none).
    pub headers: Vec<u8>,
    /// The message payload: the ORIGINAL produced bytes, after any transparent decompression
    /// (#430).
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

/// A consumer-visible GAP marker (#346): the broker told this consumer that the half-open offset
/// span `[from, to)` is PERMANENTLY ABSENT (skipped) from the DELIVER stream, so a reader tracking
/// contiguity knows the offset jump is a bounded, REPORTED gap rather than message loss. It is the
/// richer, opt-in replacement for [`Truncation`]: a client that advertised gap-marker support (see
/// [`ClientConfig::request_gap_marker`] / [`Client::gap_marker_enabled`]) receives this typed event
/// for a skipped span INSTEAD of a `Truncation`, so the two never both fire for the same gap. The
/// next delivery in the batch (if any) is at offset `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap {
    /// The first absent offset (inclusive): where the hole begins (the last seen offset plus one).
    pub from: u64,
    /// The first present offset after the hole (exclusive): delivery resumes here.
    pub to: u64,
    /// The reported bytes lost in the hole (from the recovery-side `loss-report.v1`); `0` when the
    /// cause is byte-untracked (a plain retention/trim reap, whose span is the record count
    /// `to - from`).
    pub bytes_skipped: u64,
    /// Why the span is absent: `1` = trimmed (a retention/disk-full reap), `2` = compacted (#337,
    /// reserved); an unknown future value is surfaced verbatim, never an error.
    pub reason: u8,
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
    /// (usually empty; only under the disk-full drop-oldest policy, #82, #84). For a
    /// gap-marker-capable connection (#346) a skipped span arrives in `gaps` instead, so this stays
    /// empty.
    pub truncations: Vec<Truncation>,
    /// Consumer-visible gap markers for skipped offset spans during this fetch (#346): present only
    /// when this connection negotiated gap-marker support (see [`Client::gap_marker_enabled`]), in
    /// which case a skipped span arrives here as a typed [`Gap`] instead of in `truncations`. Usually
    /// empty.
    pub gaps: Vec<Gap>,
}

/// The outcome of a [`Client::produce`] / [`Client::produce_dedup`] call: the assigned (or, on a
/// dedup hit, the ORIGINAL) durable offset, plus whether the broker treated this publish as a
/// duplicate (#33). For a plain produce that sends no `msg_id`, `duplicate` is always `false`; for
/// an opt-in dedup produce, `duplicate` is `true` when the `msg_id` was already seen within the
/// producer's dedup window, in which case `offset` is the original offset and the broker appended
/// no second copy. A dedup hit is a BENIGN success (`rc = 0`), never an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProduceAck {
    /// The assigned offset for a fresh produce, or the ORIGINAL offset for a dedup hit.
    pub offset: u64,
    /// Whether the broker deduplicated this publish (returned the original offset without appending
    /// a second copy). `true` only on a dedup hit; `false` for a fresh produce.
    pub duplicate: bool,
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

/// One produce reply, classified: the single decode point shared by the half-duplex
/// [`Client::produce_window`] drain and the [`Client::produce_stream`] reader thread (#458), so
/// the two paths can never drift on the reply contract.
enum PubReply {
    Acked(u64),
    Duplicate(u64),
    ServerErr(String),
    Pong,
}

/// One coalesced write's byte budget for [`Client::produce_stream`] (#458): large enough to
/// amortize the syscall, small enough that the first acks stream back while later frames are
/// still being written.
const STREAM_FLUSH_BYTES: usize = 32 * 1024;

/// The shared tally between [`Client::produce_stream`]'s writer (the caller thread) and its
/// reader thread, guarded by a mutex with a condvar the reader signals as window room opens.
#[derive(Default)]
struct StreamFlow {
    /// Reply slots consumed so far (acks + duplicates + server errors).
    done: u64,
    acked: u64,
    duplicates: u64,
    server_errors: u64,
    last_offset: Option<u64>,
    first_server_err: Option<String>,
    /// The reader hit a fatal error and exited; the writer must stop waiting on it.
    reader_dead: bool,
}

/// The reader half of [`Client::produce_stream`] (#458): drains produce replies into `flow`
/// (notifying `room` as slots free) until the terminal `Pong` or a fatal error. Runs on the
/// scoped reader thread over the cloned read half.
fn drain_stream_replies(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    flow: &std::sync::Mutex<StreamFlow>,
    room: &std::sync::Condvar,
) -> Result<(), ClientError> {
    let outcome: Result<(), ClientError> = loop {
        let (ty, body) = match read_frame_from(stream, buf) {
            Ok(f) => f,
            Err(e) => break Err(e),
        };
        let reply = match classify_pub_reply(ty, &body) {
            Ok(r) => r,
            Err(e) => break Err(e),
        };
        let mut f = flow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match reply {
            PubReply::Acked(offset) => {
                f.done += 1;
                f.acked += 1;
                f.last_offset = Some(offset);
            }
            PubReply::Duplicate(offset) => {
                f.done += 1;
                f.acked += 1;
                f.duplicates += 1;
                f.last_offset = Some(offset);
            }
            PubReply::ServerErr(msg) => {
                f.done += 1;
                f.server_errors += 1;
                if f.first_server_err.is_none() {
                    f.first_server_err = Some(msg);
                }
            }
            // The terminal marker: the server's FIFO frame order guarantees every prior
            // produce's reply has already been consumed.
            PubReply::Pong => break Ok(()),
        }
        room.notify_all();
        drop(f);
    };
    if outcome.is_err() {
        let mut f = flow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.reader_dead = true;
        room.notify_all();
    }
    outcome
}

fn classify_pub_reply(ty: FrameType, body: &[u8]) -> Result<PubReply, ClientError> {
    match ty {
        FrameType::PubAck => {
            let ack = decode_pub_ack(body).map_err(|_| {
                ClientError::BadResponse("produce reply was not an eight-byte offset")
            })?;
            Ok(PubReply::Acked(ack.offset))
        }
        FrameType::PubAckDuplicate => {
            let ack = decode_pub_ack(body).map_err(|_| {
                ClientError::BadResponse("dedup-hit reply was not an eight-byte offset")
            })?;
            Ok(PubReply::Duplicate(ack.offset))
        }
        FrameType::Err => Ok(PubReply::ServerErr(String::from_utf8_lossy(body).into())),
        FrameType::Pong => Ok(PubReply::Pong),
        other => Err(ClientError::Unexpected(other)),
    }
}

/// Reads one whole frame from `stream`, buffering partial bytes in `buf`. The free-function
/// form of [`Client::read_frame`] so [`Client::produce_stream`]'s reader thread can drain a
/// cloned read half with its own buffer (#458).
fn read_frame_from(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> Result<(FrameType, Vec<u8>), ClientError> {
    let mut chunk = [0u8; 4096];
    loop {
        match decode_frame(buf).map_err(ClientError::Frame)? {
            FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            } => {
                // An unknown tag (e.g. from a newer server) has no client handler; name
                // the raw tag rather than pretending it was some known frame.
                let ty =
                    FrameType::from_u8(type_tag).ok_or(ClientError::UnknownFrameType(type_tag))?;
                let body = body.to_vec();
                buf.drain(..consumed);
                return Ok((ty, body));
            }
            FrameDecode::Incomplete { .. } => {}
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The tally a fully-drained [`Client::produce_stream`] returns (#458). A stream is a TALLY,
/// not a transcript: by the time a server `Err` could be surfaced the stream has already fully
/// drained, and failing the call would discard the whole run's counts, so server-side rejections
/// (a shed under `drop-new`, a malformed produce) are COUNTED here instead of returned as
/// `Err` (the documented divergence from [`Client::produce_window`], which fails on the first
/// server error). The call still fails for transport-level problems: IO errors, decode errors,
/// an unexpected frame, or a reply-count mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamSummary {
    /// Messages acknowledged (including dedup hits).
    pub acked: u64,
    /// How many of `acked` were `PubAckDuplicate` dedup hits.
    pub duplicates: u64,
    /// Produces the server rejected with an `Err` reply (each consumed its FIFO slot).
    pub server_errors: u64,
    /// The first server `Err` body, kept verbatim so a caller can distinguish a benign shed
    /// (`at capacity` under `drop-new`) from a real rejection.
    pub first_server_error: Option<String>,
    /// The offset carried by the last ack observed, if any message was acked.
    pub last_offset: Option<u64>,
}

/// A connected IronBus client over one TCP connection.
#[derive(Debug)]
pub struct Client {
    stream: TcpStream,
    buf: Vec<u8>,
    /// The per-consumer MESSAGE credit NEGOTIATED for this connection (#292), learned from the
    /// server's `Info` body at handshake: the server has already clamped this client's `Connect`
    /// request to its cap (or substituted its default). `None` if the server did not advertise (an
    /// old/empty `Info`), in which case the client keeps its own local credit (backward-compat).
    /// [`Client::fetch`] caps its requested batch at this value, so the negotiated credit GOVERNS the
    /// consumer pull on the client side too (the server enforces it independently).
    negotiated_credit: Option<u32>,
    /// The per-consumer BYTE budget negotiated for this connection (#292), the byte-side companion to
    /// `negotiated_credit`. `None` if the server did not advertise.
    negotiated_credit_bytes: Option<u64>,
    /// Whether the gap-marker capability is ACTIVE on this connection (#346): `true` only when this
    /// client advertised it ([`ClientConfig::request_gap_marker`]) AND the server confirmed it in
    /// `Info`. When `true`, a skipped span arrives in [`Fetch::gaps`] as a typed [`Gap`]; when `false`
    /// (an old server, or the client did not advertise), a skipped span arrives in
    /// [`Fetch::truncations`] as the legacy advisory.
    gap_marker_enabled: bool,
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
            negotiated_credit: None,
            negotiated_credit_bytes: None,
            gap_marker_enabled: false,
        };
        // The #292 handshake: send a versioned Connect body carrying any requested credit (an
        // all-absent body when the caller requested nothing, which the server reads as "use my
        // defaults") and the #346 gap-marker capability bit, then read the Info advertisement and
        // adopt the negotiated credit and the confirmed gap-marker capability.
        let mut connect_body = Vec::new();
        encode_connect(
            &ConnectBody {
                requested_credit: config.requested_consumer_credit,
                requested_credit_bytes: config.requested_consumer_credit_bytes,
                wants_gap_marker: config.request_gap_marker,
                // #494 is PROTO/CODEC only: the client does not request a connection-wide default ack
                // level yet (that is phase #496), so this stays `None` and the body is byte-for-byte
                // the pre-#494 Connect.
                default_ack_level: None,
            },
            &mut connect_body,
        );
        client.send(FrameType::Connect, &connect_body)?;
        match client.read_frame()? {
            (FrameType::Info, body) => {
                // Parse the (possibly empty) Info body. An EMPTY/old-server Info decodes to no
                // advertisement, leaving the negotiated credit `None`, so the client keeps its local
                // credit (backward-compat in the server->client direction). A malformed Info body is a
                // typed error, never a panic.
                let info = decode_info(&body).map_err(ClientError::Body)?;
                client.negotiated_credit = info.credit.map(|c| c.negotiated);
                client.negotiated_credit_bytes = info.credit_bytes.map(|c| c.negotiated);
                // The gap-marker capability is active only when the server CONFIRMED it (it does so
                // only when the client advertised it), so an old server's empty Info leaves it off.
                client.gap_marker_enabled = info.gap_marker;
                Ok(client)
            }
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// The per-consumer MESSAGE credit NEGOTIATED for this connection (#292), or `None` if the server
    /// did not advertise one (an old or empty `Info`, in which case the client keeps its local
    /// credit). The server has already clamped this client's `Connect` request to its cap, so this is
    /// the effective `min(request, server cap)` (or the server default when the client requested
    /// nothing). [`Client::fetch`] caps its batch at this value.
    #[must_use]
    pub fn negotiated_credit(&self) -> Option<u32> {
        self.negotiated_credit
    }

    /// The per-consumer BYTE budget negotiated for this connection (#292), or `None` if the server did
    /// not advertise one. `Some(0)` means the server advertised an UNLIMITED byte budget.
    #[must_use]
    pub fn negotiated_credit_bytes(&self) -> Option<u64> {
        self.negotiated_credit_bytes
    }

    /// Whether the consumer-visible gap-marker capability is ACTIVE on this connection (#346): `true`
    /// only when this client advertised it ([`ClientConfig::request_gap_marker`]) AND the server
    /// confirmed it. When `true`, a skipped offset span arrives in [`Fetch::gaps`] as a typed [`Gap`];
    /// when `false`, it arrives in [`Fetch::truncations`] as the legacy advisory.
    #[must_use]
    pub fn gap_marker_enabled(&self) -> bool {
        self.gap_marker_enabled
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
    /// A plain produce sends no `msg_id`, so it never opts into dedup and the reply is always a
    /// fresh `PubAck`; for the dedup-aware variant that may surface `duplicate = true`, use
    /// [`Client::produce_dedup`]. (A `PubAckDuplicate` reply is still parsed here defensively and
    /// its offset returned, so an old caller never errors on a dedup-capable broker.)
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or a server error.
    pub fn produce(&mut self, message: &PubBody<'_>) -> Result<u64, ClientError> {
        self.produce_dedup(message).map(|ack| ack.offset)
    }

    /// Produces a message and returns the full [`ProduceAck`]: the assigned (or, on a dedup hit, the
    /// ORIGINAL) offset plus the `duplicate` indication (#33). When `message.dedup` is `Some`, the
    /// publish opts into the broker's effectively-once dedup window; if the `msg_id` was already seen
    /// within the window, the broker replies with a `PubAckDuplicate` carrying the original offset and
    /// this returns `duplicate = true` (a BENIGN success, never an error). When `message.dedup` is
    /// `None`, this behaves exactly like [`Client::produce`] (`duplicate` is always `false`).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or a server error.
    pub fn produce_dedup(&mut self, message: &PubBody<'_>) -> Result<ProduceAck, ClientError> {
        let mut body = Vec::new();
        // The default produce path is ALWAYS at-least-once: force the fire-and-forget bit clear so a
        // caller who set it on the body still gets the unchanged PubAck path here (the opt-in QoS-0
        // path is the explicit `produce_fire_and_forget`). Backward-compat: an old caller never set
        // the field (it defaults false), so this is a no-op for them.
        let at_least_once = PubBody {
            fire_and_forget: false,
            ..*message
        };
        encode_pub(&at_least_once, &mut body).map_err(ClientError::Body)?;
        self.send(FrameType::Pub, &body)?;
        match self.read_frame()? {
            // A fresh produce: a PubAck whose body is the 8-byte assigned offset.
            (FrameType::PubAck, body) => {
                let ack = decode_pub_ack(&body).map_err(|_| {
                    ClientError::BadResponse("produce reply was not an eight-byte offset")
                })?;
                Ok(ProduceAck {
                    offset: ack.offset,
                    duplicate: false,
                })
            }
            // A dedup hit (#33): a PubAckDuplicate whose body is the 8-byte ORIGINAL offset. The
            // frame type ALONE signals duplicate = true; the frozen PubAck body is untouched.
            (FrameType::PubAckDuplicate, body) => {
                let ack = decode_pub_ack(&body).map_err(|_| {
                    ClientError::BadResponse("dedup-hit reply was not an eight-byte offset")
                })?;
                Ok(ProduceAck {
                    offset: ack.offset,
                    duplicate: true,
                })
            }
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Produces a WINDOW of messages PIPELINED (#450): every `Pub` frame is written before any
    /// ack is awaited, so the broker's group commit covers the whole window with ONE `fdatasync`
    /// instead of one per message (the session parks the pending acks and the append actor
    /// drains the window as a single batch). The replies are FIFO in frame order, the
    /// per-connection wire contract, so the Nth returned ack belongs to the Nth message. Every
    /// ack keeps the unchanged at-least-once meaning: the record is fsynced-durable before the
    /// ack exists. Pipelining changes WHEN the client awaits, never what an ack means.
    ///
    /// Per-message `dedup` blocks are honored exactly as in [`Client::produce_dedup`] (a dedup
    /// hit returns `duplicate = true` for that slot). The `fire_and_forget` field is forced
    /// clear on every message: a QoS-0 produce has no reply and would desynchronize the FIFO
    /// window; use [`Client::produce_fire_and_forget`] for that path.
    ///
    /// On a server `Err` reply mid-window, the REMAINING replies are still drained (one reply
    /// per message is the contract, so the connection stays usable for the next call, the same
    /// discipline as the decompress drain) and the FIRST error returns; offsets acked before or
    /// after the failing slot in the same window are durable on the broker but not returned. An
    /// IO error or an unexpected frame type aborts immediately: the stream itself is broken and
    /// the connection should be dropped.
    ///
    /// An empty window returns an empty vec without touching the wire.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, an unexpected frame, or
    /// the first server error in the window.
    pub fn produce_window(
        &mut self,
        messages: &[PubBody<'_>],
    ) -> Result<Vec<ProduceAck>, ClientError> {
        // Phase 1: encode the WHOLE window into ONE buffer and write it with ONE syscall. This
        // is what puts all N produces in front of the actor's drain loop as one group-commit
        // batch (#450), and the coalesced write keeps the per-message client overhead flat (a
        // write() per frame measurably floors the window's throughput on small payloads: one
        // syscall per message costs more than the amortized fsync at large windows).
        let mut body = Vec::new();
        let mut wire = Vec::with_capacity(messages.len() * 64);
        for message in messages {
            body.clear();
            let at_least_once = PubBody {
                fire_and_forget: false,
                ..*message
            };
            encode_pub(&at_least_once, &mut body).map_err(ClientError::Body)?;
            encode_frame(FrameType::Pub, &body, &mut wire).map_err(ClientError::Frame)?;
        }
        self.stream.write_all(&wire)?;
        // Phase 2: drain exactly one reply per message, FIFO. A server Err consumes its slot and
        // is remembered; the drain continues so the connection is not desynchronized.
        let mut acks = Vec::with_capacity(messages.len());
        let mut first_err: Option<ClientError> = None;
        for _ in 0..messages.len() {
            let (ty, body) = self.read_frame()?;
            match classify_pub_reply(ty, &body)? {
                PubReply::Acked(offset) => acks.push(ProduceAck {
                    offset,
                    duplicate: false,
                }),
                PubReply::Duplicate(offset) => acks.push(ProduceAck {
                    offset,
                    duplicate: true,
                }),
                PubReply::ServerErr(msg) => {
                    if first_err.is_none() {
                        first_err = Some(ClientError::Server(msg));
                    }
                }
                PubReply::Pong => return Err(ClientError::Unexpected(FrameType::Pong)),
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(acks),
        }
    }

    /// Produces a stream of messages FULL-DUPLEX with a sliding in-flight window (#458): the
    /// caller's thread keeps encoding and writing PUB frames (coalesced into batched writes)
    /// while a scoped reader thread drains the FIFO acks concurrently from a cloned read half,
    /// so neither side ever idles waiting for the other the way the half-duplex
    /// [`produce_window`](Client::produce_window) round-trips do. At most `window` produces are
    /// unacknowledged at any moment (a full window blocks the WRITER only, never the reader).
    ///
    /// The reply contract is `produce_window`'s, applied as a running tally instead of a
    /// returned `Vec`: one reply per message FIFO, `PubAckDuplicate` counts as acked-and-
    /// duplicate, a server `Err` consumes its slot and is COUNTED in the summary (the first
    /// one kept verbatim) rather than failing the call, and `fire_and_forget` is forced
    /// CLEAR on every message. See [`StreamSummary`] for why server errors tally instead of
    /// erroring: the stream has fully drained by then, and the counts are the product. Termination uses the wire's frame-order guarantee: after the
    /// last produce the writer sends a `Ping`, and the `Pong` (which the server emits only
    /// after every prior reply) tells the reader the drain is complete, with no read timeout
    /// and no protocol change.
    ///
    /// On success the connection is fully reusable (the reader's leftover bytes are restored
    /// to this client's buffer). On any error the connection state is undefined, exactly like
    /// an errored `produce_window`: drop the client.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO/encode error, an unexpected frame, or a reply-count
    /// mismatch. Server `Err` replies do NOT fail the call; they are counted in the summary.
    pub fn produce_stream<'a, I>(
        &mut self,
        messages: I,
        window: usize,
    ) -> Result<StreamSummary, ClientError>
    where
        I: IntoIterator<Item = PubBody<'a>>,
    {
        let window = window.max(1) as u64;
        let mut reader_stream = self.stream.try_clone()?;
        let mut reader_buf = std::mem::take(&mut self.buf);
        let flow = std::sync::Mutex::new(StreamFlow::default());
        let room = std::sync::Condvar::new();

        let (writer_result, reader_outcome) = std::thread::scope(|s| {
            let reader =
                s.spawn(|| drain_stream_replies(&mut reader_stream, &mut reader_buf, &flow, &room));

            let mut body = Vec::new();
            let mut wire: Vec<u8> = Vec::with_capacity(STREAM_FLUSH_BYTES + 1024);
            let mut sent: u64 = 0;
            let mut buffered: u64 = 0;
            let writer_result: Result<u64, ClientError> = (|| {
                for message in messages {
                    body.clear();
                    let at_least_once = PubBody {
                        fire_and_forget: false,
                        ..message
                    };
                    encode_pub(&at_least_once, &mut body).map_err(ClientError::Body)?;
                    encode_frame(FrameType::Pub, &body, &mut wire).map_err(ClientError::Frame)?;
                    buffered += 1;
                    if wire.len() >= STREAM_FLUSH_BYTES || buffered >= window {
                        // Wait for window room for the WHOLE buffered batch, then one write.
                        let mut f = flow
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        while !f.reader_dead && sent + buffered - f.done > window {
                            f = room
                                .wait(f)
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                        }
                        let dead = f.reader_dead;
                        drop(f);
                        if dead {
                            // The reader's own error is the root cause; surface it after join.
                            return Ok(sent);
                        }
                        self.stream.write_all(&wire)?;
                        sent += buffered;
                        buffered = 0;
                        wire.clear();
                    }
                }
                if buffered > 0 {
                    self.stream.write_all(&wire)?;
                    sent += buffered;
                }
                // The terminal Ping: its Pong arrives after every produce reply (FIFO), which
                // is what releases the reader without a read timeout.
                let mut ping = Vec::new();
                encode_frame(FrameType::Ping, &[], &mut ping).map_err(ClientError::Frame)?;
                self.stream.write_all(&ping)?;
                Ok(sent)
            })();
            if writer_result.is_err() {
                // The writer failed mid-stream (encode or write): the connection is undefined,
                // so unblock a reader parked in read() by shutting the socket's read half.
                let _ = self.stream.shutdown(std::net::Shutdown::Both);
            }
            (writer_result, reader.join())
        });

        let reader_result = match reader_outcome {
            Ok(r) => r,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        let sent = writer_result?;
        reader_result?;
        // The reader exited cleanly on the Pong: restore its leftover bytes so this client
        // stays usable, then settle the tallies.
        self.buf = reader_buf;
        let f = flow
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if f.done != sent {
            return Err(ClientError::BadResponse(
                "the produce stream's reply count did not match the messages sent",
            ));
        }
        Ok(StreamSummary {
            acked: f.acked,
            duplicates: f.duplicates,
            server_errors: f.server_errors,
            first_server_error: f.first_server_err,
            last_offset: f.last_offset,
        })
    }

    /// Produces a message on the FIRE-AND-FORGET (QoS-0, #11, #402) fast path: it sets the additive
    /// `PUB_FLAG_FIRE_AND_FORGET` wire bit and does NOT wait for a `PubAck`, so it returns the moment
    /// the frame is written. The broker MAY drop the produce under load (gated by its fire-and-forget
    /// token bucket) WITHOUT acking, and otherwise appends it durably but sends no `PubAck`, so the
    /// producer accepts loss BY CONTRACT. This is the README "optional fire-and-forget fast path": it
    /// trades the at-least-once guarantee for throughput and no round-trip. Use [`Client::produce`]
    /// for the default at-least-once path (an assigned offset, unchanged).
    ///
    /// The `message.fire_and_forget` field is forced `true` by this method, so the flag and the
    /// caller's intent can never disagree; any `dedup` block the caller set is still sent (a QoS-0
    /// produce may also opt into dedup). No reply is read, so this never blocks on the broker.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error or an over-large field. It does NOT surface a
    /// broker-side drop (there is no reply to surface), by the QoS-0 contract.
    pub fn produce_fire_and_forget(&mut self, message: &PubBody<'_>) -> Result<(), ClientError> {
        let mut body = Vec::new();
        // Force the fire-and-forget marker regardless of the caller's field, so the wire bit always
        // reflects the method's contract.
        let faf = PubBody {
            fire_and_forget: true,
            ..*message
        };
        encode_pub(&faf, &mut body).map_err(ClientError::Body)?;
        self.send(FrameType::Pub, &body)?;
        // Fire and forget: do NOT read a reply. The broker sends no PubAck for a fire-and-forget
        // produce (whether it appended it or dropped it under load), so awaiting one would hang.
        Ok(())
    }

    /// Fetches up to `max` messages. Returns the delivered messages (possibly fewer, or
    /// none if the queue is empty within the consumer window).
    ///
    /// The requested batch is capped at the NEGOTIATED per-consumer credit (#292) when the server
    /// advertised one: a `max` above the negotiated credit is reduced to it, so the negotiated value
    /// GOVERNS the client-side pull (the server enforces the same ceiling independently, so this is the
    /// client honoring what it agreed to rather than over-requesting and being clamped). When the
    /// server advertised no credit (an old/empty `Info`), `max` is sent unchanged (the client keeps its
    /// local credit, backward-compat).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a server that delivers
    /// more messages than the requested credit.
    pub fn fetch(&mut self, max: u32) -> Result<Fetch, ClientError> {
        // Cap the request at the negotiated credit (when known): the negotiated value governs the pull.
        let max = match self.negotiated_credit {
            Some(credit) => max.min(credit),
            None => max,
        };
        self.send(FrameType::Flow, &max.to_le_bytes())?;
        // The credit caps the TOTAL frames the server may stream back before FlowEnd: each granted
        // slot yields at most one delivery OR one dead-letter advisory OR one truncation advisory,
        // so a buggy or hostile server cannot stream any of them without bound.
        let limit = usize::try_from(max).unwrap_or(usize::MAX);
        self.read_fetch_response(limit)
    }

    /// Reads and decodes a batch delivery response (the shared tail of [`Client::fetch`] and
    /// [`Client::fetch_batch`]): a run of `Deliver` frames (transparently decompressed, #430), with any
    /// interleaved `DeadLetter` / `Truncated` / `GapMarker` advisories, terminated by exactly one
    /// `FlowEnd` (or an `Err`). `limit` bounds the TOTAL advisory + delivery frames the server may stream
    /// before the terminator, so a buggy or hostile server cannot stream without bound. The batch-pull
    /// fetch (#489) reuses this verbatim because its wire response is byte-for-byte a `Flow` response past
    /// the request frame.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, a decode failure, or a server that
    /// streams more frames than `limit`.
    fn read_fetch_response(&mut self, limit: usize) -> Result<Fetch, ClientError> {
        let mut messages = Vec::new();
        let mut dead_letters = Vec::new();
        let mut truncations = Vec::new();
        let mut gaps = Vec::new();
        // The FIRST in-batch decompression failure (#430), held until the batch's terminating
        // FlowEnd has been read: the remaining frames are DRAINED first so the connection stays
        // framed and usable for the next request, then the error is returned. Aborting
        // mid-window instead would leave the unread batch tail (and the FlowEnd) in the buffer,
        // desynchronizing every later request on this connection.
        let mut poison: Option<ClientError> = None;
        // The total advisory + delivery frames seen so far, the quantity the credit bounds. A
        // GapMarker, like a delivery / dead-letter / truncation, consumes one credit slot
        // server-side, so it counts here too, as does every frame drained after a decompression
        // failure (a buggy or hostile server cannot stream any of them without bound).
        let mut frames = 0usize;
        loop {
            let (frame_type, body) = self.read_frame()?;
            // The credit check binds every batch frame uniformly (deliveries, advisories, and
            // the post-poison drain); FlowEnd and Err terminate the batch and are exempt.
            if !matches!(frame_type, FrameType::FlowEnd | FrameType::Err) {
                if frames >= limit {
                    return Err(ClientError::BadResponse(
                        "server streamed more frames than the requested credit",
                    ));
                }
                frames += 1;
            }
            match (frame_type, body) {
                (FrameType::Deliver, body) => {
                    let d = decode_deliver(&body).map_err(ClientError::Body)?;
                    // Draining after a decompression failure: the frame is consumed (keeping the
                    // connection framed) but the delivery is dropped un-acked, so the broker
                    // redelivers it after its visibility timeout.
                    if poison.is_some() {
                        continue;
                    }
                    // Transparent broker-side decompression (#430): a delivery carrying the
                    // COMPRESSED bit is decompressed back to the original payload (and the bit
                    // cleared), so the caller sees exactly the bytes the producer published,
                    // codec-independent. Bounded by the decompressed-size cap (a bomb guard) and
                    // dictionary-free (`NoDictionaries`; the lz4 path never references one); a
                    // payload this build cannot decode is the typed `Decompress` error, no panic.
                    let flags = RecordFlags::from_bits(d.flags);
                    let (flags, payload) = if flags.contains(RecordFlags::COMPRESSED) {
                        match decompress_payload(
                            flags,
                            d.payload,
                            &NoDictionaries,
                            DEFAULT_MAX_DECOMPRESSED_BYTES,
                        ) {
                            Ok(payload) => (d.flags & !RecordFlags::COMPRESSED.bits(), payload),
                            // The poison record's offset and lease generation travel with the
                            // error, so the caller can ack/nack-skip it; the rest of the batch
                            // is drained (see `poison` above) before the error is returned.
                            Err(source) => {
                                poison = Some(ClientError::Decompress {
                                    source,
                                    offset: d.offset,
                                    generation: d.generation,
                                });
                                continue;
                            }
                        }
                    } else {
                        (d.flags, d.payload.to_vec())
                    };
                    messages.push(Message {
                        offset: d.offset,
                        generation: d.generation,
                        flags,
                        timestamp_ms: d.timestamp_ms,
                        key: d.key.to_vec(),
                        headers: d.headers.to_vec(),
                        payload,
                    });
                }
                // An in-band dead-letter advisory for an offset skipped as poison (#63). It is
                // not a delivery, so it carries its own offset and does not ack.
                (FrameType::DeadLetter, body) => {
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
                    let t = decode_truncated(&body).map_err(ClientError::Body)?;
                    truncations.push(Truncation {
                        earliest_retained: t.earliest_retained,
                        skipped: t.skipped,
                    });
                }
                // An in-band gap marker (#346): the consumer-visible, opt-in replacement for the
                // Truncated advisory. A skipped offset span `[from, to)` is permanently absent, so a
                // reader tracking contiguity learns the jump is a bounded, reported gap rather than
                // loss. Only seen on a gap-marker-capable connection; an old server never sends it.
                (FrameType::GapMarker, body) => {
                    let g = decode_gap_marker(&body).map_err(ClientError::Body)?;
                    gaps.push(Gap {
                        from: g.from,
                        to: g.to,
                        bytes_skipped: g.bytes_skipped,
                        reason: g.reason,
                    });
                }
                // The FlowEnd frame terminates the batch (its body is the delivered count). A
                // pending decompression failure is surfaced HERE, after the whole batch
                // (including this FlowEnd) has been consumed, so the connection is left exactly
                // where a successful fetch would leave it.
                (FrameType::FlowEnd, _) => {
                    return match poison {
                        Some(e) => Err(e),
                        None => Ok(Fetch {
                            messages,
                            dead_letters,
                            truncations,
                            gaps,
                        }),
                    }
                }
                (FrameType::Err, body) => {
                    return Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
                }
                (other, _) => return Err(ClientError::Unexpected(other)),
            }
        }
    }

    /// Batch-pull FETCH (#489): drains up to `max_records` records (and at most `max_bytes` total
    /// payload-equivalent bytes) in ONE round-trip, the amortized twin of [`Client::fetch`]. The server
    /// runs the SAME per-record poll the per-record path runs, so a batch fetch delivers EXACTLY the
    /// records that many successive [`Client::fetch`] calls would, leasing each one identically and
    /// preserving the at-least-once contract and the broadcast/`key_shared`/competing semantics — it only
    /// amortizes the actor hop and per-poll read cost across the batch.
    ///
    /// - `max_records`: the most records to return. As with [`Client::fetch`], it is capped at the
    ///   NEGOTIATED per-consumer credit (#292) when the server advertised one, so the client honors what
    ///   it agreed to (the server enforces the same ceiling independently).
    /// - `max_bytes`: the byte budget for the batch (`0` = unbounded by bytes; the record count, credit,
    ///   and deadline still bind). The server applies the floor-of-one, so a single over-budget record is
    ///   never wedged.
    /// - `expires`: a deadline budget; the server returns whatever it has gathered by the deadline. `0`
    ///   means no deadline. Ignored when `no_wait` is set.
    /// - `no_wait`: when `true`, the server returns IMMEDIATELY with whatever is ready (a single drain
    ///   pass), never waiting out `expires` — the NATS pull-consumer `no_wait` behavior.
    ///
    /// The response is byte-for-byte a [`Client::fetch`] response past the request frame (a run of
    /// deliveries plus any advisories, terminated by `FlowEnd`), so the returned [`Fetch`] is shaped
    /// identically.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a server that delivers more frames
    /// than the requested record cap.
    pub fn fetch_batch(
        &mut self,
        max_records: u32,
        max_bytes: u64,
        expires: Duration,
        no_wait: bool,
    ) -> Result<Fetch, ClientError> {
        // Cap the record request at the negotiated credit (when known): the negotiated value governs the
        // pull, exactly as `fetch` does, so the client never over-requests past what it agreed to.
        let max_records = match self.negotiated_credit {
            Some(credit) => max_records.min(credit),
            None => max_records,
        };
        // The deadline budget in milliseconds, saturated to u64 so an absurd Duration cannot overflow.
        let expires_ms = u64::try_from(expires.as_millis()).unwrap_or(u64::MAX);
        let req = FetchBody {
            max_records,
            max_bytes,
            expires_ms,
            no_wait,
        };
        let mut body = Vec::new();
        encode_fetch(&req, &mut body);
        self.send(FrameType::Fetch, &body)?;
        // The record cap bounds the TOTAL delivery + advisory frames the server may stream before
        // FlowEnd, exactly as the per-record credit does for `fetch`: each granted slot yields at most one
        // such frame, so a buggy or hostile server cannot stream without bound.
        let limit = usize::try_from(max_records).unwrap_or(usize::MAX);
        self.read_fetch_response(limit)
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

    /// Acks MANY fetched messages in ONE pipelined round-trip: the consume-side counterpart to
    /// [`produce_window`](Client::produce_window). Encodes every `(offset, generation)` ack into one
    /// buffer, writes them with one syscall, then drains exactly one `AckStatus` reply per ack in
    /// FIFO order. This removes the per-message round-trip that floors a competing work-group's drain
    /// throughput (one [`ack`](Client::ack) RPC per record), so a consumer settles a whole fetched
    /// batch at the broker's commit rate instead of stalling on ack latency.
    ///
    /// Returns one `bool` per ack IN INPUT ORDER: `true` = committed, `false` = fenced (a stale
    /// token — the lease already expired and redelivered, or it was already settled; do not drop
    /// local state). Each offset is committed INDIVIDUALLY by the broker, so this is correct for a
    /// competing work-group, unlike [`cumulative_ack`](Client::cumulative_ack) (broadcast-only). An
    /// empty slice is a no-op `Ok(vec![])`.
    ///
    /// Keep the batch BOUNDED (ack at most a fetched batch, i.e. within the consumer credit): the
    /// write-all-then-drain shape can deadlock against the socket buffers for an unbounded batch,
    /// exactly like an oversized `produce_window`. A server `Err` reply consumes its slot (the drain
    /// continues so the connection stays framed) and is returned as the call's error.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO/encode error, a wrong-shape reply, an unexpected frame, or
    /// a server `Err` reply (the first one kept).
    pub fn ack_many(&mut self, acks: &[(u64, u64)]) -> Result<Vec<bool>, ClientError> {
        if acks.is_empty() {
            return Ok(Vec::new());
        }
        // Phase 1: encode every Ack into ONE buffer and write it with ONE syscall (mirrors
        // produce_window): all N acks land in front of the broker's loop back-to-back, so the
        // per-ack client overhead stays flat instead of paying a write()+read() round-trip each.
        let mut body = Vec::new();
        let mut wire = Vec::with_capacity(acks.len() * 32);
        for &(offset, generation) in acks {
            body.clear();
            encode_ack(
                &AckBody {
                    op: AckOp::Ack,
                    offset,
                    generation,
                    delay_ms: 0,
                },
                &mut body,
            );
            encode_frame(FrameType::Ack, &body, &mut wire).map_err(ClientError::Frame)?;
        }
        self.stream.write_all(&wire)?;
        // Phase 2: drain exactly one reply per ack, FIFO. A server Err consumes its slot and is
        // remembered; the drain continues so the connection is not desynchronized.
        let mut statuses = Vec::with_capacity(acks.len());
        let mut first_err: Option<ClientError> = None;
        for _ in 0..acks.len() {
            match self.read_frame()? {
                (FrameType::AckStatus, body) => match body.as_slice() {
                    [status] => statuses.push(*status == 1),
                    _ => {
                        return Err(ClientError::BadResponse(
                            "ack reply was not a one-byte status",
                        ))
                    }
                },
                (FrameType::Err, body) => {
                    if first_err.is_none() {
                        first_err =
                            Some(ClientError::Server(String::from_utf8_lossy(&body).into()));
                    }
                }
                (other, _) => return Err(ClientError::Unexpected(other)),
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(statuses),
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

    /// Sends a BROADCAST cumulative ack (the tag-19 `CumulativeAck` verb, #288): commits the named
    /// broadcast group's single cursor up to the EXCLUSIVE offset `up_to` in one move. The verb is
    /// safe ONLY for a broadcast group (a group-of-one that sees every record in order); the server
    /// hard-rejects it for a competing or `key_shared` work-group, and validates `up_to` against the
    /// durable head and the earliest-retained offset. An empty `group` selects the default group. A
    /// re-ack at or below the current commit is an idempotent no-op success.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the verb (the group is not a broadcast
    /// consumer, or `up_to` is outside the retained window), or a frame or connection error.
    pub fn cumulative_ack(&mut self, group: &str, up_to: u64) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_cumulative_ack(
            &CumulativeAckBody {
                up_to,
                group: group.as_bytes(),
            },
            &mut body,
        );
        self.send(FrameType::CumulativeAck, &body)?;
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
        read_frame_from(&mut self.stream, &mut self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::Clock as _; // the monotonic seam for the serve loop's #95 beacon
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_proto::message::{
        encode_dead_letter, encode_deliver, DeadLetterBody, DeliverBody, PubDedup,
        DEAD_LETTER_MAX_DELIVER,
    };
    use ironbus_server::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
    use ironbus_server::clock::SystemClock;
    use ironbus_server::engine::{
        DiskFullPolicy, Engine, EngineConfig, DEFAULT_GROUP_IDLE_EVICT_MS, DEFAULT_MAX_GROUPS,
    };
    use ironbus_server::server::serve;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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
        start_server_with(
            consumer_credit,
            consumer_credit_bytes,
            ironbus_core::compress::Codec::None,
        )
    }

    /// The full rig: an in-process broker with an explicit per-consumer credit, byte budget, AND
    /// write-path compression codec (#430), for the transparent-decompression end-to-end test.
    fn start_server_with(
        consumer_credit: u32,
        consumer_credit_bytes: u64,
        compression: ironbus_core::compress::Codec,
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
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: ironbus_server::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                // The write-path codec under test (#430): `None` for every historical test
                // (byte-identical broker), `Lz4` for the transparency end-to-end test.
                compression,
            },
        )
        .unwrap();
        // The engine is owned by the append actor (#177); the wire server reaches it through the
        // handle. The actor join handle is detached (these client tests drive the broker only over the
        // wire and never inspect the engine): when the server thread drops its handle on stop, the
        // actor's channel disconnects and it drains and exits on its own.
        let (handle_engine, _actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                // These client tests drive the broker over the wire only; the serve loop's liveness
                // beacon (#95) is unread, so a throwaway beacon on a fresh SystemClock suffices.
                let clock = SystemClock::new();
                let beacon =
                    ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &handle_engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
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
    fn a_produce_stream_slides_its_window_full_duplex_against_a_real_server() {
        // The #458 full-duplex sliding window over the real wire: far more messages than the
        // window, so the writer must interleave with the reader's ack drain; every message acked
        // exactly once, the last offset is the final message's, and the connection is fully
        // usable afterwards (the reader's leftover buffer is restored).
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();

        let payloads: Vec<Vec<u8>> = (0..100u8).map(|i| vec![b's', i]).collect();
        let summary = c
            .produce_stream(
                payloads.iter().map(|p| PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"k",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: p,
                }),
                8,
            )
            .unwrap();
        assert_eq!(summary.acked, 100, "every streamed message acked");
        assert_eq!(summary.duplicates, 0);
        assert_eq!(summary.server_errors, 0);
        assert_eq!(summary.first_server_error, None);
        assert_eq!(
            summary.last_offset,
            Some(99),
            "offsets assigned in send order"
        );
        // An empty stream is a clean no-op round trip (just the terminal ping/pong).
        let empty = c.produce_stream(std::iter::empty(), 8).unwrap();
        assert_eq!((empty.acked, empty.last_offset), (0, None));
        // The connection stays healthy: a plain produce gets the next offset.
        let next = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"after-stream",
            })
            .unwrap();
        assert_eq!(next, 100);
        shutdown.store(true, Ordering::Relaxed);
        drop(c);
        let _ = handle.join();
    }

    #[test]
    fn a_pipelined_window_returns_fifo_offsets_and_round_trips_against_a_real_server() {
        // The #450 pipelined window over the real wire: all PUB frames written before any ack
        // is awaited, FIFO acks one per message with consecutive offsets, payloads consumable
        // in order, and the connection healthy for a follow-up plain produce.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();

        let payloads: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'w', i]).collect();
        let window: Vec<PubBody<'_>> = payloads
            .iter()
            .map(|p| PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: p,
            })
            .collect();
        let acks = c.produce_window(&window).unwrap();
        assert_eq!(acks.len(), 8, "one ack per message");
        for (i, ack) in acks.iter().enumerate() {
            assert_eq!(ack.offset, i as u64, "FIFO acks carry consecutive offsets");
            assert!(!ack.duplicate);
        }
        // An empty window is a no-op that never touches the wire.
        assert!(c.produce_window(&[]).unwrap().is_empty());
        // The connection is fully usable afterwards: a plain produce gets the next offset.
        let next = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"after-window",
            })
            .unwrap();
        assert_eq!(next, 8);
        let messages = c.fetch(16).unwrap().messages;
        assert_eq!(messages.len(), 9, "the window and the follow-up all landed");
        assert_eq!(messages[0].payload, payloads[0]);
        assert_eq!(messages[7].payload, payloads[7]);

        shutdown.store(true, Ordering::Relaxed);
        drop(c);
        let _ = handle.join();
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
                dedup: None,
                fire_and_forget: false,
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
    fn fetch_batch_round_trips_against_a_real_server() {
        // #489: a batch-pull fetch_batch drains the produced records in ONE round-trip, identically to
        // the per-record fetch path, and each delivered record can be acked with the lease generation it
        // carried (the lease the batch hands out is the same fencing lease the per-record poll hands out).
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let n = 5u8;
        for i in 0..n {
            c.produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: &[i; 8],
            })
            .unwrap();
        }

        // One batch fetch drains all n records.
        let fetched = c
            .fetch_batch(u32::from(n), 0, std::time::Duration::from_secs(1), false)
            .unwrap();
        assert_eq!(
            fetched.messages.len(),
            usize::from(n),
            "all records in one round-trip"
        );
        for (i, m) in fetched.messages.iter().enumerate() {
            assert_eq!(
                m.offset,
                u64::try_from(i).unwrap(),
                "offsets are in log order"
            );
        }
        // Ack them all with the generations the batch carried, proving the leases are the real fencing
        // leases (at-least-once / lease semantics preserved).
        for m in &fetched.messages {
            assert!(
                c.ack(m.offset, m.generation).unwrap(),
                "the fetch-leased record commits"
            );
        }
        // Nothing left.
        assert!(c
            .fetch_batch(u32::from(n), 0, std::time::Duration::ZERO, true)
            .unwrap()
            .messages
            .is_empty());

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn fetch_batch_no_wait_on_an_empty_queue_returns_immediately() {
        // #489 no_wait: a fetch against an empty queue returns an empty batch immediately, never hanging.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let fetched = c
            .fetch_batch(10, 0, std::time::Duration::ZERO, true)
            .unwrap();
        assert!(
            fetched.messages.is_empty(),
            "no_wait on an empty queue returns nothing"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn fetch_batch_max_records_bounds_the_batch_against_a_real_server() {
        // #489: max_records caps the batch below what is available, end-to-end over the wire.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        for i in 0..10u8 {
            c.produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: &[i; 4],
            })
            .unwrap();
        }
        let fetched = c
            .fetch_batch(3, 0, std::time::Duration::from_secs(1), false)
            .unwrap();
        assert_eq!(
            fetched.messages.len(),
            3,
            "max_records bounds the batch to 3 of 10"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn ack_many_batch_commits_every_message_in_one_round_trip() {
        // The consume-side counterpart to produce_window: produce N records, fetch the batch, and
        // settle them ALL with ONE ack_many call. Every offset comes back committed (true) in input
        // order, and nothing remains to fetch -- a competing work-group drains at batch rate with no
        // per-message ack RPC (the #464 consume-throughput fix).
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let n = 8usize;
        let window: Vec<PubBody> = (0..n)
            .map(|_| PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"batch",
            })
            .collect();
        assert_eq!(c.produce_window(&window).unwrap().len(), n);

        let messages = c.fetch(u32::try_from(n).unwrap()).unwrap().messages;
        assert_eq!(messages.len(), n);
        let acks: Vec<(u64, u64)> = messages.iter().map(|m| (m.offset, m.generation)).collect();

        let statuses = c.ack_many(&acks).unwrap();
        assert_eq!(statuses.len(), n, "one status per ack, in input order");
        assert!(
            statuses.iter().all(|&committed| committed),
            "every offset committed"
        );

        // All settled: nothing left to fetch.
        assert!(c
            .fetch(u32::try_from(n).unwrap())
            .unwrap()
            .messages
            .is_empty());
        // An empty batch is a no-op.
        assert!(c.ack_many(&[]).unwrap().is_empty());

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn produce_fire_and_forget_sends_no_ack_yet_the_record_is_durable_end_to_end() {
        // The #11 QoS-0 fast path end-to-end: `produce_fire_and_forget` returns WITHOUT awaiting a
        // PubAck (the producer fired and forgot), yet the broker still appended the record durably
        // (the default bucket is disabled, so it is appended, not dropped). A following at-least-once
        // produce on the SAME connection still gets its PubAck (the no-ack did NOT desync the stream),
        // and a fetch sees BOTH records, proving the QoS-0 one landed.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        // Fire-and-forget: returns immediately, no reply read.
        c.produce_fire_and_forget(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false, // forced true by the method
            payload: b"qos0",
        })
        .unwrap();
        // A normal at-least-once produce on the same connection still gets its PubAck at offset 1,
        // proving the prior no-ack frame did not leave a stray reply on the wire.
        let offset = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"alo",
            })
            .unwrap();
        assert_eq!(
            offset, 1,
            "the at-least-once produce landed after the QoS-0 one"
        );
        // Fetch: both records are durable; the QoS-0 record landed at offset 0.
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 2, "both records are durable");
        assert_eq!(messages[0].offset, 0);
        assert_eq!(messages[0].payload, b"qos0");
        assert_eq!(messages[1].payload, b"alo");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn produce_dedup_surfaces_duplicate_true_on_a_retry_end_to_end() {
        // The #33 end-to-end client property: an opt-in dedup produce is a fresh PubAck (duplicate =
        // false) the first time; the SAME (producer, msg_id) retried is a PubAckDuplicate the client
        // surfaces as duplicate = true with the ORIGINAL offset, and the broker stored only ONE copy.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let dedup = PubDedup {
            producer_id: b"producer-1",
            epoch: 1,
            msg_id: b"order-42",
        };
        let body = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: Some(dedup),
            fire_and_forget: false,
            payload: b"v1",
        };
        let first = c.produce_dedup(&body).unwrap();
        assert_eq!(
            first,
            ProduceAck {
                offset: 0,
                duplicate: false
            },
            "fresh produce"
        );
        // The idempotent retry (same producer + msg_id; payload differs but dedup keys on msg_id).
        let retry = c
            .produce_dedup(&PubBody {
                fire_and_forget: false,
                payload: b"v2-ignored",
                ..body
            })
            .unwrap();
        assert_eq!(
            retry,
            ProduceAck {
                offset: 0,
                duplicate: true
            },
            "the retry is a benign dedup hit with the ORIGINAL offset"
        );
        // Only ONE record is in the log: a single fetch yields exactly the first copy.
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 1, "the dedup hit stored no second copy");
        assert_eq!(
            messages[0].payload, b"v1",
            "the ORIGINAL payload, not the retry's"
        );
        assert_eq!(messages[0].offset, 0);

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
                    dedup: None,
                    fire_and_forget: false,
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
                dedup: None,
                fire_and_forget: false,
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
                dedup: None,
                fire_and_forget: false,
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
    fn a_cumulative_ack_ok_reply_succeeds() {
        // The broadcast cumulative-ack verb (#288): the server answers Ok, so the call succeeds.
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::Ok, b""));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        c.cumulative_ack("bcast", 5).unwrap();
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_cumulative_ack_error_reply_is_surfaced() {
        // The server rejects the verb (a competing group, or an out-of-range up_to): the typed Err
        // reason is surfaced to the caller (#288).
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(
            FrameType::Err,
            b"cumulative ack is not allowed on a competing work-group (broadcast consumers only)",
        ));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        match c.cumulative_ack("", 2).unwrap_err() {
            ClientError::Server(m) => assert!(m.contains("competing work-group"), "{m}"),
            other => panic!("expected Server, got {other:?}"),
        }
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
    fn an_empty_info_from_an_old_server_leaves_the_client_on_its_local_credit() {
        // #292 backward-compat (server->client direction): a pre-#292 server replies an EMPTY Info
        // body. The client decodes it to "no advertisement", so its negotiated credit is None and a
        // fetch sends the requested credit UNCHANGED (the client keeps its own local credit). The
        // client even requested a credit in its Connect, which the old server simply ignored.
        let script = frame(FrameType::Info, b""); // an old server's empty Info
        let (addr, handle) = raw_server(script);
        let c = Client::connect_with(addr, &config_requesting_credit(Some(7), Some(99))).unwrap();
        assert_eq!(
            c.negotiated_credit(),
            None,
            "an empty Info advertises nothing: the client keeps its local credit"
        );
        assert_eq!(c.negotiated_credit_bytes(), None);
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_malformed_info_body_is_a_typed_error_not_a_panic() {
        // #292 decode safety: a hostile/corrupt Info body (an unknown handshake version) is a typed
        // ClientError::Body, never a panic. version byte 9, then a zero field length.
        let script = frame(FrameType::Info, &[9u8, 0, 0]);
        let (addr, handle) = raw_server(script);
        match Client::connect(addr).unwrap_err() {
            ClientError::Body(_) => {}
            other => panic!("expected a typed Body error, got {other:?}"),
        }
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

    /// An `Info` body that confirms the gap-marker capability (#346).
    fn info_with_gap_marker() -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_info(
            &ironbus_proto::message::InfoBody {
                credit: None,
                credit_bytes: None,
                gap_marker: true,
                default_ack_level: None,
            },
            &mut body,
        );
        frame(FrameType::Info, &body)
    }

    /// A `ClientConfig` that advertises gap-marker support.
    fn config_wanting_gap_marker() -> ClientConfig {
        ClientConfig {
            request_gap_marker: true,
            ..ClientConfig::default()
        }
    }

    #[test]
    fn a_gap_marker_capable_client_surfaces_a_gap_as_a_typed_event() {
        // TEETH (#346): a client that advertised gap-marker support and whose server confirmed it
        // receives a skipped span as a typed `Gap` in `fetch().gaps` (NOT a `Truncation`), with the
        // exact [from, to), byte count, and reason. The FlowEnd still terminates the batch.
        let mut g_body = Vec::new();
        ironbus_proto::message::encode_gap_marker(
            &ironbus_proto::message::GapMarkerBody {
                from: 7,
                to: 12,
                bytes_skipped: 0,
                reason: ironbus_proto::message::gap_reason::TRIMMED,
            },
            &mut g_body,
        );
        let mut script = info_with_gap_marker();
        script.extend(frame(FrameType::GapMarker, &g_body));
        script.extend(frame(FrameType::FlowEnd, &0u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect_with(addr, &config_wanting_gap_marker()).unwrap();
        assert!(
            c.gap_marker_enabled(),
            "the server confirmed the gap-marker capability"
        );
        let fetched = c.fetch(10).unwrap();
        assert!(fetched.messages.is_empty(), "no messages in this batch");
        assert!(
            fetched.truncations.is_empty(),
            "a gap-marker client gets a Gap, never a Truncation"
        );
        assert_eq!(
            fetched.gaps,
            vec![Gap {
                from: 7,
                to: 12,
                bytes_skipped: 0,
                reason: ironbus_proto::message::gap_reason::TRIMMED,
            }],
            "the skipped span is surfaced as a typed Gap with the exact range and reason"
        );
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn fetch_gap_marker_counts_against_the_credit() {
        // A GapMarker counts as one frame toward the credit bound (like a delivery / dead-letter /
        // truncation), so a server that streams more than the credit is rejected.
        fn gap(off: u64) -> Vec<u8> {
            let mut body = Vec::new();
            ironbus_proto::message::encode_gap_marker(
                &ironbus_proto::message::GapMarkerBody {
                    from: off,
                    to: off + 1,
                    bytes_skipped: 0,
                    reason: ironbus_proto::message::gap_reason::TRIMMED,
                },
                &mut body,
            );
            frame(FrameType::GapMarker, &body)
        }
        let mut script = info_with_gap_marker();
        script.extend(gap(1));
        script.extend(gap(2)); // one past the credit of 1
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect_with(addr, &config_wanting_gap_marker()).unwrap();
        match c.fetch(1).unwrap_err() {
            ClientError::BadResponse(_) => {}
            other => panic!("expected BadResponse, got {other:?}"),
        }
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn an_old_server_leaves_the_gap_marker_capability_off() {
        // BACKWARD-COMPAT (#346): a client may advertise gap-marker support, but a pre-#346 server
        // replies an EMPTY Info (no confirmation), so the capability stays OFF and the client keeps
        // receiving the legacy Truncation advisory. The client is not broken by opting in.
        let mut t_body = Vec::new();
        ironbus_proto::message::encode_truncated(
            &ironbus_proto::message::TruncatedBody {
                earliest_retained: 9,
                skipped: 2,
            },
            &mut t_body,
        );
        let mut script = frame(FrameType::Info, b""); // an old server's empty Info: no confirmation
        script.extend(frame(FrameType::Truncated, &t_body));
        script.extend(frame(FrameType::FlowEnd, &0u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect_with(addr, &config_wanting_gap_marker()).unwrap();
        assert!(
            !c.gap_marker_enabled(),
            "an old server does not confirm the capability, so it stays off"
        );
        let fetched = c.fetch(10).unwrap();
        assert!(fetched.gaps.is_empty(), "no Gap from an old server");
        assert_eq!(
            fetched.truncations,
            vec![Truncation {
                earliest_retained: 9,
                skipped: 2
            }],
            "the legacy Truncation advisory is still surfaced"
        );
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
                dedup: None,
                fire_and_forget: false,
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
                dedup: None,
                fire_and_forget: false,
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
                    dedup: None,
                    fire_and_forget: false,
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

    /// A `ClientConfig` that requests a per-consumer credit, for the #292 negotiation tests.
    fn config_requesting_credit(credit: Option<u32>, credit_bytes: Option<u64>) -> ClientConfig {
        ClientConfig {
            requested_consumer_credit: credit,
            requested_consumer_credit_bytes: credit_bytes,
            ..ClientConfig::default()
        }
    }

    #[test]
    fn a_client_request_below_the_cap_is_honored_as_the_negotiated_credit() {
        // #292: a broker cap of 10, a client that requests 4 -> negotiated min(4, 10) = 4. The Info
        // advertisement carries 4 as the negotiated value and 10 as the cap, and the negotiated credit
        // governs the pull: a fetch(1000) delivers at most 4.
        let (addr, shutdown, handle) = start_server_with_credit(10);
        let mut producer = Client::connect(addr).unwrap();
        for _ in 0..20 {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: b"m",
                })
                .unwrap();
        }
        let mut c = Client::connect_with(addr, &config_requesting_credit(Some(4), None)).unwrap();
        assert_eq!(
            c.negotiated_credit(),
            Some(4),
            "min(request 4, cap 10) = 4 is advertised"
        );
        let first = c.fetch(1000).unwrap().messages;
        assert_eq!(
            first.len(),
            4,
            "the negotiated credit of 4 governs the pull"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_client_request_above_the_cap_is_clamped_to_the_cap() {
        // #292: a broker cap of 3, a client that requests 100 -> negotiated min(100, 3) = 3. A request
        // can only TIGHTEN, never raise, the server cap; the client cannot exceed it.
        let (addr, shutdown, handle) = start_server_with_credit(3);
        let mut producer = Client::connect(addr).unwrap();
        for _ in 0..10 {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: b"m",
                })
                .unwrap();
        }
        let mut c = Client::connect_with(addr, &config_requesting_credit(Some(100), None)).unwrap();
        assert_eq!(
            c.negotiated_credit(),
            Some(3),
            "min(request 100, cap 3) = 3: the request cannot raise the cap"
        );
        let first = c.fetch(1000).unwrap().messages;
        assert_eq!(
            first.len(),
            3,
            "the server enforces the cap of 3 regardless of the request"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_client_that_requests_nothing_gets_the_server_default() {
        // #292 backward-compat (an "old client" semantics): a client that requests no credit gets the
        // server default advertised as the negotiated value, and the pull is governed by that default.
        let (addr, shutdown, handle) = start_server_with_credit(5);
        let mut producer = Client::connect(addr).unwrap();
        for _ in 0..12 {
            producer
                .produce(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: b"m",
                })
                .unwrap();
        }
        // The default ClientConfig requests nothing.
        let mut c = Client::connect(addr).unwrap();
        assert_eq!(
            c.negotiated_credit(),
            Some(5),
            "no request -> the server default (5) is the negotiated value"
        );
        let first = c.fetch(1000).unwrap().messages;
        assert_eq!(first.len(), 5, "the server default of 5 governs the pull");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_negotiated_byte_budget_is_advertised() {
        // #292/#275: the server advertises its byte budget too. With a cap of 4096 and a client that
        // requests 1024, the negotiated byte budget is min(1024, 4096) = 1024.
        let (addr, shutdown, handle) = start_server_with_credit_and_bytes(64, 4096);
        let c = Client::connect_with(addr, &config_requesting_credit(None, Some(1024))).unwrap();
        assert_eq!(
            c.negotiated_credit_bytes(),
            Some(1024),
            "min(request 1024, cap 4096) = 1024"
        );
        assert_eq!(
            c.negotiated_credit(),
            Some(64),
            "no message-credit request -> the server default (64)"
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
                    dedup: None,
                    fire_and_forget: false,
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
                    dedup: None,
                    fire_and_forget: false,
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
                    dedup: None,
                    fire_and_forget: false,
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

    #[test]
    fn a_broker_compressed_delivery_is_transparently_decompressed() {
        // The #430 end-to-end transparency contract: an lz4 broker stores a compressible >= 64 B
        // payload compressed (pinned by the engine tests) and delivers the STORED bytes with the
        // COMPRESSED flag; the client decompresses on deliver, so the caller sees exactly the
        // produced bytes with the flag cleared, indistinguishable from a --compression none run.
        let (addr, shutdown, handle) = start_server_with(64, 0, ironbus_core::compress::Codec::Lz4);
        let original: Vec<u8> = b"edge node telemetry "
            .iter()
            .copied()
            .cycle()
            .take(4096)
            .collect();
        let mut c = Client::connect(addr).unwrap();
        c.produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"k",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: &original,
        })
        .unwrap();
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].payload, original,
            "the caller sees the original produced bytes, codec-independent"
        );
        assert_eq!(
            messages[0].flags & RecordFlags::COMPRESSED.bits(),
            0,
            "the COMPRESSED bit is cleared on the transparently decompressed message"
        );
        assert!(c.ack(messages[0].offset, messages[0].generation).unwrap());
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_scripted_compressed_deliver_decodes_to_the_original_payload() {
        // The deliver-path decode in isolation (#430): a scripted server streams one Deliver
        // whose payload is a REAL compressed stored object with bit 0 set; the client returns
        // the original bytes with the bit cleared. Direct proof the wire bit drives the decode.
        use ironbus_core::compress::{compress_payload, CompressConfig};
        let original: Vec<u8> = b"edge node telemetry "
            .iter()
            .copied()
            .cycle()
            .take(1024)
            .collect();
        let comp = compress_payload(&original, &CompressConfig::default()).unwrap();
        assert!(comp.compressed, "the fixture payload genuinely compresses");
        let mut body = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 0,
                generation: 1,
                flags: RecordFlags::COMPRESSED.bits(),
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: &comp.stored,
            },
            &mut body,
        )
        .unwrap();
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::Deliver, &body));
        script.extend(frame(FrameType::FlowEnd, &1u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, original);
        assert_eq!(messages[0].flags & RecordFlags::COMPRESSED.bits(), 0);
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_hostile_compressed_deliver_is_a_typed_error_never_a_panic() {
        // A hostile or mismatched-build deliver (#430): bit 0 set over a descriptor naming a
        // codec id this build does not implement. The fetch fails with the typed Decompress
        // error (unknown codec), never a panic and never garbage handed to the caller.
        use ironbus_core::compress::DecompressError;
        let mut stored = vec![7u8]; // codec id 7: unallocated
        stored.extend_from_slice(&0u32.to_le_bytes()); // dict_id 0
        stored.extend_from_slice(&16u32.to_le_bytes()); // claimed uncompressed_len
        stored.extend_from_slice(b"not a real stream");
        let mut body = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 0,
                generation: 1,
                flags: RecordFlags::COMPRESSED.bits(),
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: &stored,
            },
            &mut body,
        )
        .unwrap();
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::Deliver, &body));
        script.extend(frame(FrameType::FlowEnd, &1u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        match c.fetch(10).unwrap_err() {
            ClientError::Decompress {
                source: DecompressError::PoisonUnknownCodec(7),
                offset: 0,
                generation: 1,
            } => {}
            other => panic!("expected Decompress with PoisonUnknownCodec(7), got {other:?}"),
        }
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_decompress_error_drains_the_batch_so_the_same_client_can_fetch_again() {
        // The #430 desync fix: a mid-batch decompression failure must not abort mid-window
        // (that would leave the batch tail and the FlowEnd unread, so every later request on
        // the connection reads stale frames). The client drains the batch-mates and the FlowEnd
        // first, carries the poison record's offset + lease generation in the error (so the
        // caller can ack/nack-skip it), and the SAME client's next fetch reads the next batch
        // cleanly.
        use ironbus_core::compress::DecompressError;
        let mut stored = vec![7u8]; // codec id 7: unallocated
        stored.extend_from_slice(&0u32.to_le_bytes()); // dict_id 0
        stored.extend_from_slice(&16u32.to_le_bytes()); // claimed uncompressed_len
        stored.extend_from_slice(b"not a real stream");
        let mut poison_body = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 5,
                generation: 9,
                flags: RecordFlags::COMPRESSED.bits(),
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: &stored,
            },
            &mut poison_body,
        )
        .unwrap();
        let mut mate_body = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 6,
                generation: 1,
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"batch-mate",
            },
            &mut mate_body,
        )
        .unwrap();
        let mut next_body = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 7,
                generation: 1,
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"next-batch",
            },
            &mut next_body,
        )
        .unwrap();
        let mut script = frame(FrameType::Info, b"");
        // Batch one: the poison delivery, then a healthy batch-mate, then the FlowEnd.
        script.extend(frame(FrameType::Deliver, &poison_body));
        script.extend(frame(FrameType::Deliver, &mate_body));
        script.extend(frame(FrameType::FlowEnd, &2u32.to_le_bytes()));
        // Batch two: one healthy delivery. Were the read desynced, the first batch's unread
        // tail (the batch-mate or its FlowEnd) would surface here instead.
        script.extend(frame(FrameType::Deliver, &next_body));
        script.extend(frame(FrameType::FlowEnd, &1u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect(addr).unwrap();
        match c.fetch(10).unwrap_err() {
            ClientError::Decompress {
                source: DecompressError::PoisonUnknownCodec(7),
                offset: 5,
                generation: 9,
            } => {}
            other => panic!("expected the offset-carrying Decompress error, got {other:?}"),
        }
        // The same client, no reconnect: the poison batch was fully drained (its batch-mates
        // dropped un-acked, for redelivery), so this fetch reads batch two cleanly.
        let fetched = c.fetch(10).unwrap();
        assert_eq!(
            fetched.messages.len(),
            1,
            "no stale frames bleed over from the poisoned batch"
        );
        assert_eq!(fetched.messages[0].offset, 7);
        assert_eq!(fetched.messages[0].payload, b"next-batch");
        drop(c);
        handle.join().unwrap();
    }
}
