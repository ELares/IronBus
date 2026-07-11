// SPDX-License-Identifier: MIT OR Apache-2.0
//! An async (tokio) IronBus client: the ASYNC TWIN of the synchronous [`ironbus_client`].
//!
//! [`AsyncClient`] owns one [`tokio::net::TcpStream`] and speaks the EXACT SAME wire protocol
//! ([`ironbus_proto`]) request/response the blocking [`ironbus_client::Client`] does: it sends a
//! frame and reads the response, framing the byte stream with a persistent buffer so a read that
//! delivers several frames at once is never lost. Every wire codec, every body type, and every
//! returned data type is REUSED unchanged from the sync client (this crate redefines none of them);
//! only the IO is swapped from blocking `std::net` to async `tokio::net`. It is plain TCP — no TLS,
//! no openssl, no C-FFI — exactly like the sync client.
//!
//! Broker-side payload compression (ADR-0003) is TRANSPARENT here, identically to the sync client: a
//! delivery whose flags carry the `COMPRESSED` bit is decompressed back to the original payload
//! before it is handed to the caller (with the bit cleared from [`Message::flags`]), bounded by the
//! per-record decompressed-size cap; an unresolvable codec/dictionary or a corrupt stream surfaces as
//! the typed [`ClientError::Decompress`], never a panic.
//!
//! # Concurrency model
//!
//! The wire contract is request-response, FIFO per connection: one in-flight request-response at a
//! time. So every method takes `&mut self` and `await`s its own reply before returning, mirroring the
//! sync client's one-in-flight discipline exactly. This crate deliberately does NOT build a concurrent
//! multiplexer (one that pipelines many awaited requests over the single connection and demuxes
//! replies), because the replies are positional — interleaving awaited requests risks handing one
//! caller another's reply. A multiplexer (a background reader task plus per-request oneshot channels)
//! is possible FUTURE WORK; for now, drive concurrency by using one [`AsyncClient`] per task.
//!
//! # Example
//!
//! ```no_run
//! use ironbus_client_async::AsyncClient;
//! use ironbus_client_async::proto::PubBody;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = AsyncClient::connect("127.0.0.1:7000").await?;
//!
//! // Produce a record (durable on the awaited ack).
//! let offset = client
//!     .produce(&PubBody {
//!         flags: 0,
//!         timestamp_ms: 0,
//!         key: b"key",
//!         headers: b"",
//!         dedup: None,
//!         fire_and_forget: false,
//!         payload: b"hello",
//!     })
//!     .await?;
//! assert_eq!(offset, 0);
//!
//! // Subscribe to a work-group, fetch the record back, and ack it.
//! client.subscribe("workers").await?;
//! let fetched = client.fetch(10).await?;
//! for message in &fetched.messages {
//!     client.ack(message.offset, message.generation).await?;
//! }
//! # Ok(())
//! # }
//! ```

use ironbus_core::compress::{decompress_payload, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES};
use ironbus_core::types::RecordFlags;
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameType};
use ironbus_proto::message::{
    decode_dead_letter, decode_deliver, decode_deliver_batch, decode_gap_marker, decode_info,
    decode_not_leader, decode_pub_ack, decode_stream_info_response, encode_ack, encode_connect,
    encode_cumulative_ack, encode_fetch, encode_pause_group, encode_pub, encode_pub_to,
    encode_stream_commit, encode_stream_declare, encode_stream_fetch, encode_stream_info,
    encode_sub, encode_sub_to, encode_txn_prepare, encode_txn_resolve, AckBody, AckLevel, AckOp,
    ConnectBody, ConsumeTier, CumulativeAckBody, DeliverBody, FetchBody, PauseGroupBody, PubBody,
    PubToBody, StreamCommitBody, StreamDeclareBody, StreamFetchBody, StreamInfoBody, SubBody,
    SubToBody, TxnPrepareBody, TxnResolveBody,
};
// The connection-scoped auth encoder (#631, #884): appends the auth section the broker verifies to
// an already-encoded `Connect` body. A verbatim port of the sync client's `connect_with` auth wiring;
// the credential itself lives on the re-exported `ClientConfig::credential`.
use ironbus_proto::message::append_connect_auth;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

/// The smallest per-read scratch size. Reading at least this many bytes even when the decoder asks
/// for fewer preserves the small-frame batching the client has always relied on: one socket read can
/// pull several tiny frames, so the trailing frames stay buffered rather than forcing a read apiece.
/// Matches the historical fixed 4 KiB read chunk. VERBATIM port of the sync client's `READ_WINDOW`.
const READ_WINDOW: usize = 4096;

/// The largest per-read scratch size. Bounds the reused scratch buffer so a large frame (a ~16 MiB
/// `DeliverBatch`) is assembled in ~64 capped reads rather than one giant allocation, while the
/// decoder's `needed` hint still lets a single read pull as much of the frame as the socket has.
/// VERBATIM port of the sync client's `READ_CAP`.
const READ_CAP: usize = 256 * 1024;

/// How many bytes to read next while completing a frame, given the decoder's `needed` total-length
/// hint and how many valid bytes are already buffered (`filled`). Sizes the read to the outstanding
/// deficit, clamped into `[READ_WINDOW, READ_CAP]`. Reading past `needed` (when the deficit is under
/// the window) is harmless — the extra bytes belong to following frames and stay buffered. VERBATIM
/// port of the sync client's `frame_read_size`.
fn frame_read_size(needed: usize, filled: usize) -> usize {
    needed.saturating_sub(filled).clamp(READ_WINDOW, READ_CAP)
}

// Re-export the sync client's public data types VERBATIM: this crate's API RETURNS these exact types
// (it does not redefine them), so a caller can name them without depending on `ironbus-client`
// directly. They are the SYNC client's types, shared unchanged — the wire contract is identical.
#[doc(no_inline)]
pub use ironbus_client::{
    pack_password_material, AuthCredential, AuthMechanism, ClientConfig, ClientError, DeadLetter,
    Fetch, Gap, Message, ProduceAck, ProgressOutcome, ServerError, ServerErrorCode, StreamBatch,
    StreamConsumerConfig, Truncation, TxnId, DEFAULT_STREAM_COMMIT_EVERY_BATCHES,
    DEFAULT_STREAM_FETCH_RECORDS,
};

// Re-export the SHARED client TLS config (ADR-0004 / #957) under the `tls` feature, so an async caller
// can build [`ClientConfig::tls`] without depending on `ironbus-client` directly. This is the SAME type
// the sync client uses — there is no async-specific TLS config; the async client just drives its handshake
// on the tokio runtime. Brings `TlsClientConfig` into module scope for the async `Wire::connect_tls`.
#[cfg(feature = "tls")]
#[doc(no_inline)]
pub use ironbus_client::{TlsClientConfig, TlsClientError};

/// The proto body/codec types a caller constructs to drive [`AsyncClient`] (e.g. [`PubBody`]),
/// re-exported so a caller can build requests without depending on `ironbus-proto` directly.
pub mod proto {
    pub use ironbus_proto::message::{AckLevel, ConsumeTier, PubBody, PubDedup};
}

/// One coalesced write's byte budget for the async coalescing fire-and-forget producer
/// ([`AsyncClient::fire_and_forget_producer`]): large enough to amortize the syscall, small enough
/// that the buffered tail a flush makes durable-on-the-wire is bounded. Mirrors the sync client's
/// `STREAM_FLUSH_BYTES` (32 KiB).
const FAF_FLUSH_BYTES: usize = 32 * 1024;

/// Reconstructs the typed [`ClientError::NotLeader`] from a `NotLeader` redirect body, mapping an
/// empty hint to `None` (a malformed body also falls back to `None`, so a redirect is always
/// actionable). Mirrors the sync client's `not_leader_error`.
fn not_leader_error(body: &[u8]) -> ClientError {
    let leader_hint = decode_not_leader(body).ok().and_then(|r| {
        if r.leader_hint.is_empty() {
            None
        } else {
            Some(r.leader_hint.to_string())
        }
    });
    ClientError::NotLeader { leader_hint }
}

/// One produce reply, classified by [`classify_pub_reply`]: the single decode point the pipelined
/// [`AsyncClient::produce_window`] drain shares, mirroring the sync client's `PubReply`. The decode is
/// IO-free; only the surrounding `read_frame` awaits.
#[derive(Debug)]
enum PubReply {
    Acked(u64),
    Duplicate(u64),
    ServerErr(ServerError),
    Pong,
    /// A cluster `NotLeader` redirect (#735): the produce landed on a non-leader replica and was NOT
    /// appended/acked; the leader's CLIENT-address hint (or `None` when unknown).
    NotLeader(Option<String>),
}

/// Classifies one produce reply frame into a [`PubReply`]. A verbatim port of the sync client's
/// `classify_pub_reply` — the decode/match logic is IO-free and identical; only the caller's
/// `read_frame` awaits.
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
        FrameType::Err => Ok(PubReply::ServerErr(ServerError::from_wire(body))),
        FrameType::Pong => Ok(PubReply::Pong),
        // A cluster NotLeader redirect (#735): decode the leader hint (an empty hint -> `None`). The
        // produce was NOT appended/acked here; the caller reconnects/retries to the leader.
        FrameType::NotLeader => {
            let redirect = decode_not_leader(body)
                .map_err(|_| ClientError::BadResponse("malformed NotLeader redirect body"))?;
            let hint = if redirect.leader_hint.is_empty() {
                None
            } else {
                Some(redirect.leader_hint.to_string())
            };
            Ok(PubReply::NotLeader(hint))
        }
        other => Err(ClientError::Unexpected(other)),
    }
}

/// The AGGREGATE materialized-payload-bytes ceiling for ONE fetch window (#879), the async port of the
/// sync client's `MAX_FETCH_DECOMPRESSED_BYTES`: the running sum of decompressed/raw payload bytes a
/// single fetch may push into its `messages` Vec before it fails closed with
/// [`ClientError::BadResponse`]. The per-record decompression cap (`DEFAULT_MAX_DECOMPRESSED_BYTES`,
/// 8 MiB) bounds ONE record; this bounds the WHOLE window, so a credit-bounded fetch of many tiny
/// high-ratio frames cannot materialize `credit x 8 MiB` resident. 256 MiB = 32 max-size records.
const MAX_FETCH_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// Ingests one decoded delivery into the fetch result, applying the SAME transparent broker-side
/// decompression the sync client's `ingest_delivery` does and pushing the resulting [`Message`] onto
/// `messages` — UNLESS a prior decompression failure already poisoned the batch (`poison.is_some()`),
/// in which case the delivery is consumed and dropped un-acked (the broker redelivers it). The FIRST
/// failure is recorded in `poison` (carrying the record's offset/generation for an ack/nack-skip); the
/// rest of the batch is still drained before the error surfaces. This is a verbatim port of the sync
/// helper — the decode/decompress logic is IO-free and identical.
///
/// `decompressed_bytes`/`max_aggregate` bound the WHOLE fetch window's materialized bytes (#879):
/// crossing the ceiling poisons the batch with [`ClientError::BadResponse`], exactly like the sync port.
fn ingest_delivery(
    d: &DeliverBody<'_>,
    messages: &mut Vec<Message>,
    poison: &mut Option<ClientError>,
    decompressed_bytes: &mut usize,
    max_aggregate: usize,
) {
    if poison.is_some() {
        return;
    }
    let flags = RecordFlags::from_bits(d.flags);
    let (flags, payload) = if flags.contains(RecordFlags::COMPRESSED) {
        match decompress_payload(
            flags,
            d.payload,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        ) {
            Ok(payload) => (d.flags & !RecordFlags::COMPRESSED.bits(), payload),
            Err(source) => {
                *poison = Some(ClientError::Decompress {
                    source,
                    offset: d.offset,
                    generation: d.generation,
                });
                return;
            }
        }
    } else {
        (d.flags, d.payload.to_vec())
    };
    // #879: bound the AGGREGATE materialized payload bytes for the fetch window, not just the per-record
    // 8 MiB cap, so a credit-bounded fetch of many tiny high-ratio frames cannot OOM the client. Fail
    // closed once the running total crosses the ceiling; the over-cap record (and every later one) is
    // not materialized and the remaining frames are drained before the error returns.
    *decompressed_bytes = decompressed_bytes.saturating_add(payload.len());
    if *decompressed_bytes > max_aggregate {
        *poison = Some(ClientError::BadResponse(
            "fetch response exceeded the aggregate decompressed-bytes cap",
        ));
        return;
    }
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

/// Reads one whole frame from `stream`, buffering partial bytes in `buf`. The async port of the sync
/// client's `read_frame_from`: the decode/buffer logic is IDENTICAL — loop `decode_frame(buf)`, and on
/// `Incomplete` read more bytes from the socket and append. The ONLY change is the read: tokio's
/// `AsyncReadExt::read(...).await` in place of the blocking `std::io::Read::read`.
async fn read_frame_from(
    stream: &mut (impl AsyncRead + Unpin),
    buf: &mut Vec<u8>,
) -> Result<(FrameType, Vec<u8>), ClientError> {
    // Reused scratch for each socket read. `buf` grows ONLY via `extend_from_slice`, run
    // SYNCHRONOUSLY after the read future resolves — so `buf.len()` is always exactly the count of
    // valid buffered bytes. This is cancellation-safe: if the read future is dropped (a
    // `tokio::time::timeout` firing mid-read), the `extend` never runs and `buf` is untouched, so a
    // later read decodes from clean bytes instead of zero pollution. Error-safe too: `?` propagates
    // without having touched `buf`.
    let mut scratch: Vec<u8> = Vec::new();
    loop {
        let needed = match decode_frame(buf).map_err(ClientError::Frame)? {
            FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            } => {
                let ty =
                    FrameType::from_u8(type_tag).ok_or(ClientError::UnknownFrameType(type_tag))?;
                let body = body.to_vec();
                buf.drain(..consumed);
                return Ok((ty, body));
            }
            FrameDecode::Incomplete { needed } => needed,
        };
        let read_size = frame_read_size(needed, buf.len());
        if scratch.len() < read_size {
            scratch.resize(read_size, 0);
        }
        let n = stream.read(&mut scratch[..read_size]).await?;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

/// The transport under an [`AsyncClient`]: a plain tokio TCP stream, or — behind the `tls` feature and
/// when [`ClientConfig::tls`] is set — a TLS 1.3 session over that stream. `AsyncClient` performs ALL of
/// its IO through this enum, so the produce/consume/handshake paths are transport-agnostic. The async twin
/// of the sync client's `Wire` (same Plain/Tls shape); it implements tokio's [`AsyncRead`]/[`AsyncWrite`]
/// so the existing `read_frame_from` / `write_all` sites work UNCHANGED over either transport. There is no
/// `try_clone` analog: the async client never splits its stream (its pipelined `produce_window` writes the
/// whole window on the one owned stream), so a TLS session is never asked to span two owners.
enum Wire {
    /// A plaintext TCP connection (the default; the only variant on a non-`tls` build).
    Plain(TcpStream),
    /// A TLS 1.3 session over the TCP connection (broker verified; optional mTLS client cert). Boxed so
    /// the large rustls connection state does not bloat the `Plain` variant.
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Wire::Plain(_) => f.write_str("Wire::Plain"),
            #[cfg(feature = "tls")]
            Wire::Tls(_) => f.write_str("Wire::Tls"),
        }
    }
}

impl Wire {
    /// The local socket address of the underlying TCP connection (a stable per-connection seed for
    /// transaction ids), whether plaintext or wrapped in TLS.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] when the OS cannot report the local address.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Wire::Plain(s) => s.local_addr(),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.get_ref().0.local_addr(),
        }
    }

    /// Read back the `TCP_NODELAY` state of the underlying socket (used by a test), whether plaintext or
    /// wrapped in TLS.
    #[cfg(test)]
    fn nodelay(&self) -> io::Result<bool> {
        match self {
            Wire::Plain(s) => s.nodelay(),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.get_ref().0.nodelay(),
        }
    }

    /// Establish a TLS 1.3 client session over an already-connected socket (#957): VERIFY the broker's
    /// certificate against the configured trust anchor (mandatory — a verification failure returns an
    /// error, never a silent fallback to plaintext), drive the async handshake to completion, and wrap.
    /// The async twin of the sync client's `Wire::connect_tls`, using `tokio_rustls::TlsConnector` in
    /// place of the blocking `complete_io`. The shared [`TlsClientConfig::build`] yields the rustls
    /// `ClientConfig`; both crates resolve the SAME rustls 0.23, so the config type unifies.
    #[cfg(feature = "tls")]
    async fn connect_tls(socket: TcpStream, config: &TlsClientConfig) -> Result<Wire, ClientError> {
        let client_config = config
            .build()
            .map_err(|e| ClientError::Tls(e.to_string()))?;
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(config.server_name().to_string())
                .map_err(|_| {
                    ClientError::Tls(format!("invalid server name `{}`", config.server_name()))
                })?;
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        // Drive the TLS 1.3 handshake to completion. A certificate that does not verify, or a server
        // name mismatch, fails HERE and returns the error — before any Connect frame is sent.
        let tls = connector
            .connect(server_name, socket)
            .await
            .map_err(ClientError::Io)?;
        Ok(Wire::Tls(Box::new(tls)))
    }
}

// `Wire` delegates every poll to the active variant. Both variants are `Unpin` (a tokio `TcpStream` is
// `Unpin`, and a `Box<T>` is always `Unpin`), so `self.get_mut()` + `Pin::new(inner)` is sound without a
// pin-projection crate.
impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Wire::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Wire::Plain(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Wire::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Wire::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A connected async IronBus client over one [`tokio::net::TcpStream`].
///
/// The async twin of [`ironbus_client::Client`]: it carries the same negotiated-capability state and
/// exposes the same method surface, but every IO call `await`s. One in-flight request-response at a
/// time (the FIFO wire contract); see the crate docs for the concurrency model.
// Each bool records a DISTINCT server-CONFIRMED wire capability for this connection (gap-marker /
// streaming / deliver-batch / streams), each set from its `Info` echo bit — protocol negotiation
// state, not internal flags a bitfield could replace. Mirrors the sync `Client` struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct AsyncClient {
    stream: Wire,
    buf: Vec<u8>,
    /// The per-consumer MESSAGE credit NEGOTIATED for this connection, learned from the server's
    /// `Info` at handshake. `None` if the server did not advertise (an old/empty `Info`).
    negotiated_credit: Option<u32>,
    /// The per-consumer BYTE budget negotiated for this connection. `None` if not advertised.
    negotiated_credit_bytes: Option<u64>,
    /// Whether the gap-marker capability is ACTIVE on this connection (a skipped span arrives in
    /// [`Fetch::gaps`] when `true`, else in [`Fetch::truncations`]).
    gap_marker_enabled: bool,
    /// Whether the streaming consume tier (Tier-S) is ACTIVE on this connection.
    streaming_enabled: bool,
    /// Whether the raw-framed `DeliverBatch` frame is ACTIVE on this connection.
    deliver_batch_enabled: bool,
    /// Whether the stream-addressed wire verbs are ACTIVE on this connection.
    streams_enabled: bool,
    /// Whether the server CONFIRMED the ephemeral-groups capability for this connection (#771):
    /// `true` only when [`ClientConfig::request_ephemeral_groups`] was advertised AND the server's
    /// `Info` echoed the confirmation. Gates the ephemeral subscribe locally: an OLD server never
    /// confirms, so the client fails typed instead of silently binding a durable group.
    ephemeral_groups_enabled: bool,
    /// The connection-wide DEFAULT consume tier the SERVER adopted for this connection (echoed in
    /// `Info`), or `None`.
    negotiated_default_tier: Option<ConsumeTier>,
    /// A per-connection monotonic counter used to mint a UNIQUE [`TxnId`] for each [`AsyncClient::prepare`].
    next_txn_seq: u64,
}

impl AsyncClient {
    /// Connects to a broker at `addr` with the default [`ClientConfig`] and completes the async
    /// handshake.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on a connection failure or an unexpected handshake reply.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<AsyncClient, ClientError> {
        AsyncClient::connect_with(addr, &ClientConfig::default()).await
    }

    /// Connects to a broker at `addr` using `config` and completes the async handshake.
    ///
    /// The handshake is a verbatim port of the sync client's: build a `ConnectBody` from `config`,
    /// `encode_connect`, send a `Connect` frame, read one frame; on `Info` adopt the negotiated
    /// credit/gap-marker/streaming/deliver-batch/streams/default-tier state, on `Err` surface
    /// [`ClientError::Server`], else [`ClientError::Unexpected`].
    ///
    /// Note: the connect/read/write TIMEOUTS in [`ClientConfig`] are a blocking-socket concept and do
    /// NOT apply here — an async caller bounds a slow broker with [`tokio::time::timeout`] around the
    /// call instead. The credit / capability fields of `config` ARE honored (they shape the `Connect`
    /// body identically to the sync client), including the connection-scoped
    /// [`ClientConfig::credential`] (#884): when set, the auth section the broker verifies is appended
    /// to the `Connect` body exactly as the sync client does. TLS remains a follow-up (this stays plain
    /// TCP), so a bearer/password credential is for loopback or an already-secured transport.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on a connection failure or an unexpected handshake reply.
    pub async fn connect_with<A: ToSocketAddrs>(
        addr: A,
        config: &ClientConfig,
    ) -> Result<AsyncClient, ClientError> {
        let stream = TcpStream::connect(addr).await?;
        // Disable Nagle (#1028), a verbatim port of the sync client's `dial`: the produce/ack and
        // fetch paths are small-frame request-response, where Nagle + the broker's delayed ACK
        // stacks an RTT-scale stall onto every awaited round-trip on a real network. BEST-EFFORT:
        // a failed setsockopt degrades latency only, never correctness, so it must not fail an
        // otherwise-successful connect.
        let _ = stream.set_nodelay(true);
        // Wrap the socket: TLS 1.3 when `config.tls` is set (verify the broker + drive the handshake
        // HERE, so a bad certificate fails the connect, never a silent plaintext fallback), else a
        // zero-cost plaintext `Wire`. On a non-tls build every connection is plaintext. A verbatim port
        // of the sync client's `connect_with` wrap, swapping the blocking handshake for the async one.
        #[cfg(feature = "tls")]
        let stream = match &config.tls {
            Some(tls_config) => Wire::connect_tls(stream, tls_config).await?,
            None => Wire::Plain(stream),
        };
        #[cfg(not(feature = "tls"))]
        let stream = Wire::Plain(stream);
        let mut client = AsyncClient {
            stream,
            buf: Vec::new(),
            negotiated_credit: None,
            negotiated_credit_bytes: None,
            gap_marker_enabled: false,
            streaming_enabled: false,
            deliver_batch_enabled: false,
            streams_enabled: false,
            ephemeral_groups_enabled: false,
            negotiated_default_tier: None,
            next_txn_seq: 0,
        };
        // The handshake: send a versioned Connect body carrying any requested credit and the
        // capability bits, then read the Info advertisement and adopt the negotiated state. Byte-for-byte
        // the sync client's `connect_with` body.
        let mut connect_body = Vec::new();
        encode_connect(
            &ConnectBody {
                wants_ephemeral_groups: config.request_ephemeral_groups,
                requested_credit: config.requested_consumer_credit,
                requested_credit_bytes: config.requested_consumer_credit_bytes,
                wants_gap_marker: config.request_gap_marker,
                default_ack_level: config.default_ack_level.map(AckLevel::as_u8),
                understands_streaming: config.understands_streaming,
                default_tier: config.default_consume_tier.map(ConsumeTier::as_u8),
                understands_deliver_batch: config.understands_deliver_batch,
                understands_streams: config.understands_streams,
                // The compressed-delivery capability bit (#1066), ON by default — byte-for-byte the sync
                // client's body, so a `--compression` broker ships this decode-capable client
                // stored-compressed records verbatim.
                understands_compressed_delivery: config.understands_compressed_delivery,
                wants_subject_filter: false,
            },
            &mut connect_body,
        );
        // Append the connection-scoped auth section (#631, #884) IFF the caller configured a credential,
        // AFTER the v1 body — byte-for-byte the sync client's `connect_with` auth wiring and the exact
        // wire the server parses with `parse_connect_auth`. With no credential (the default) nothing is
        // appended and the body stays the pre-#631 `Connect`, so an unauthenticated connect is unchanged.
        if let Some(cred) = &config.credential {
            // The `Mtls` mechanism authenticates on the client CERTIFICATE presented at the TLS handshake
            // — its `Connect` body carries no credential bytes (#957). Guard it client-side: sending
            // `Mtls` without a configured client certificate would be rejected by the server as an
            // authorization violation, so fail fast here with an actionable error instead. A verbatim port
            // of the sync client's guard.
            #[cfg(feature = "tls")]
            if matches!(cred.mechanism, AuthMechanism::Mtls)
                && !config
                    .tls
                    .as_ref()
                    .is_some_and(TlsClientConfig::has_client_cert)
            {
                return Err(ClientError::Tls(
                    "the Mtls credential authenticates on a client certificate, but none is \
                     configured: set ClientConfig.tls to a TlsClientConfig::with_client_cert(...)"
                        .to_string(),
                ));
            }
            append_connect_auth(&mut connect_body, cred).map_err(ClientError::Body)?;
        }
        client.send(FrameType::Connect, &connect_body).await?;
        match client.read_frame().await? {
            (FrameType::Info, body) => {
                // An EMPTY/old-server Info decodes to no advertisement, leaving the negotiated state at
                // its defaults (backward-compat); a malformed Info body is a typed error, never a panic.
                let info = decode_info(&body).map_err(ClientError::Body)?;
                client.negotiated_credit = info.credit.map(|c| c.negotiated);
                client.negotiated_credit_bytes = info.credit_bytes.map(|c| c.negotiated);
                client.gap_marker_enabled = info.gap_marker;
                client.streaming_enabled = info.streaming;
                client.negotiated_default_tier = info.default_tier.map(ConsumeTier::from_u8);
                client.deliver_batch_enabled = info.deliver_batch;
                client.streams_enabled = info.streams;
                client.ephemeral_groups_enabled = info.ephemeral_groups;
                Ok(client)
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// The local socket address of this connection, if the OS reports it.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] (as a [`ClientError::Io`]) when the OS cannot report
    /// the address.
    pub fn local_addr(&self) -> Result<SocketAddr, ClientError> {
        self.stream.local_addr().map_err(ClientError::Io)
    }

    /// The per-consumer MESSAGE credit NEGOTIATED for this connection, or `None` if the server did not
    /// advertise one. [`AsyncClient::fetch`] caps its batch at this value.
    #[must_use]
    pub fn negotiated_credit(&self) -> Option<u32> {
        self.negotiated_credit
    }

    /// The per-consumer BYTE budget negotiated for this connection, or `None` if not advertised.
    #[must_use]
    pub fn negotiated_credit_bytes(&self) -> Option<u64> {
        self.negotiated_credit_bytes
    }

    /// Whether the gap-marker capability is ACTIVE on this connection: when `true`, a skipped span
    /// arrives in [`Fetch::gaps`] as a typed [`Gap`]; when `false`, in [`Fetch::truncations`].
    #[must_use]
    pub fn gap_marker_enabled(&self) -> bool {
        self.gap_marker_enabled
    }

    /// Whether the streaming consume tier (Tier-S) is ACTIVE on this connection.
    #[must_use]
    pub fn streaming_enabled(&self) -> bool {
        self.streaming_enabled
    }

    /// Whether the raw-framed `DeliverBatch` frame is ACTIVE on this connection.
    #[must_use]
    pub fn deliver_batch_enabled(&self) -> bool {
        self.deliver_batch_enabled
    }

    /// Whether the stream-addressed wire verbs are ACTIVE on this connection.
    #[must_use]
    pub fn streams_enabled(&self) -> bool {
        self.streams_enabled
    }

    /// Whether EPHEMERAL consumer groups are ACTIVE on this connection (#771): `true` only when
    /// this client advertised [`ClientConfig::request_ephemeral_groups`] AND the server confirmed
    /// the capability in `Info`. When `false`, [`AsyncClient::subscribe_ephemeral`] fails locally
    /// with [`ClientError::CapabilityNotNegotiated`] — the guard against an OLD server that would
    /// tolerate the subscribe flag and silently bind a DURABLE group.
    #[must_use]
    pub fn ephemeral_groups_enabled(&self) -> bool {
        self.ephemeral_groups_enabled
    }

    /// The connection-wide DEFAULT consume tier the SERVER adopted for this connection (echoed in
    /// `Info`), or `None`.
    #[must_use]
    pub fn negotiated_default_tier(&self) -> Option<ConsumeTier> {
        self.negotiated_default_tier
    }

    /// Produces a message and returns its assigned log offset.
    ///
    /// The async port of [`ironbus_client::Client::produce`]: it writes the `Pub` frame and `await`s
    /// the covering group-commit `PubAck`, so on return the record is durable (ack-implies-durable).
    /// One publish in flight at a time.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or a server error.
    pub async fn produce(&mut self, message: &PubBody<'_>) -> Result<u64, ClientError> {
        self.produce_dedup(message).await.map(|ack| ack.offset)
    }

    /// Produces a message and returns the full [`ProduceAck`]: the assigned (or, on a dedup hit, the
    /// ORIGINAL) offset plus the `duplicate` indication. The async port of
    /// [`ironbus_client::Client::produce_dedup`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or a server error.
    pub async fn produce_dedup(
        &mut self,
        message: &PubBody<'_>,
    ) -> Result<ProduceAck, ClientError> {
        // The default produce path is ALWAYS at-least-once: force the fire-and-forget bit clear so a
        // caller who set it on the body still gets the unchanged PubAck path here.
        let at_least_once = PubBody {
            fire_and_forget: false,
            ..*message
        };
        let mut body = Vec::new();
        encode_pub(&at_least_once, &mut body).map_err(ClientError::Body)?;
        self.send(FrameType::Pub, &body).await?;
        match self.read_frame().await? {
            (FrameType::PubAck, body) => {
                let ack = decode_pub_ack(&body).map_err(|_| {
                    ClientError::BadResponse("produce reply was not an eight-byte offset")
                })?;
                Ok(ProduceAck {
                    offset: ack.offset,
                    duplicate: false,
                })
            }
            (FrameType::PubAckDuplicate, body) => {
                let ack = decode_pub_ack(&body).map_err(|_| {
                    ClientError::BadResponse("dedup-hit reply was not an eight-byte offset")
                })?;
                Ok(ProduceAck {
                    offset: ack.offset,
                    duplicate: true,
                })
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            // A cluster NotLeader redirect: this node is not the leader, so the produce did NOT land
            // here. Surface the typed `NotLeader` error; the connection stays usable.
            (FrameType::NotLeader, body) => Err(not_leader_error(&body)),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Produces a message FIRE-AND-FORGET (QoS-0): writes the `Pub` frame with the canonical
    /// fire-and-forget bit set and returns WITHOUT reading a reply (the broker sends no `PubAck` for a
    /// faf produce). The async port of [`ironbus_client::Client::produce_fire_and_forget`]; the broker
    /// may drop the publish under load and the producer accepts loss by contract.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error or an over-large field. There is no reply, so a
    /// broker-side drop is not reported.
    pub async fn produce_fire_and_forget(
        &mut self,
        message: &PubBody<'_>,
    ) -> Result<(), ClientError> {
        let faf = PubBody {
            fire_and_forget: true,
            ..*message
        };
        let mut body = Vec::new();
        encode_pub(&faf, &mut body).map_err(ClientError::Body)?;
        self.send(FrameType::Pub, &body).await?;
        Ok(())
    }

    /// Produces a WINDOW of messages PIPELINED (#450): every `Pub` frame is written before any ack is
    /// awaited, so the broker's group commit covers the whole window with ONE `fdatasync` instead of one
    /// per message. The async port of [`ironbus_client::Client::produce_window`]. The replies are FIFO in
    /// frame order, the per-connection wire contract, so the Nth returned ack belongs to the Nth message.
    /// Every ack keeps the unchanged at-least-once meaning: the record is fsynced-durable before the ack
    /// exists. Pipelining changes WHEN the client awaits, never what an ack means.
    ///
    /// Per-message `dedup` blocks are honored exactly as in [`AsyncClient::produce_dedup`] (a dedup hit
    /// returns `duplicate = true` for that slot). The `fire_and_forget` field is forced clear on every
    /// message: a QoS-0 produce has no reply and would desynchronize the FIFO window; use
    /// [`AsyncClient::produce_fire_and_forget`] for that path.
    ///
    /// Keep the window BOUNDED (within the consumer/produce credit): an unbounded write-all-then-drain
    /// can deadlock against the socket buffers, exactly as the sync method cautions.
    ///
    /// On a server `Err` reply mid-window, the REMAINING replies are still drained (one reply per message
    /// is the contract, so the connection stays usable for the next call) and the FIRST error returns; a
    /// `NotLeader` redirect is surfaced the same way (the produces did NOT land). An IO error or an
    /// unexpected frame type aborts immediately: the stream itself is broken and the connection should be
    /// dropped. An empty window returns an empty vec without touching the wire.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, an unexpected frame, or the first
    /// server error (or `NotLeader` redirect) in the window.
    pub async fn produce_window(
        &mut self,
        messages: &[PubBody<'_>],
    ) -> Result<Vec<ProduceAck>, ClientError> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        // Phase 1: encode the WHOLE window into ONE buffer and write it with ONE syscall — what puts all
        // N produces in front of the actor's drain loop as one group-commit batch (#450). The
        // `fire_and_forget` bit is forced clear so a QoS-0 produce never desynchronizes the FIFO window.
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
        self.stream.write_all(&wire).await?;
        // Phase 2: drain exactly one reply per message, FIFO. A server Err (or NotLeader redirect)
        // consumes its slot and is remembered; the drain continues so the connection is not desynchronized.
        let mut acks = Vec::with_capacity(messages.len());
        let mut first_err: Option<ClientError> = None;
        for _ in 0..messages.len() {
            let (ty, body) = self.read_frame().await?;
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
                PubReply::NotLeader(leader_hint) => {
                    if first_err.is_none() {
                        first_err = Some(ClientError::NotLeader { leader_hint });
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

    /// Fetches up to `max` messages. Returns the delivered messages (possibly fewer, or none).
    ///
    /// The async port of [`ironbus_client::Client::fetch`]: the requested batch is capped at the
    /// negotiated per-consumer credit when the server advertised one, and the deliver path applies the
    /// same transparent decompression. The decode/credit-bound logic is identical to the sync client.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, a decode failure, or a server that
    /// streams more frames than the requested credit.
    pub async fn fetch(&mut self, max: u32) -> Result<Fetch, ClientError> {
        let max = match self.negotiated_credit {
            Some(credit) => max.min(credit),
            None => max,
        };
        self.send(FrameType::Flow, &max.to_le_bytes()).await?;
        let limit = usize::try_from(max).unwrap_or(usize::MAX);
        self.read_fetch_response(limit).await
    }

    /// Derives the AGGREGATE materialized-payload-bytes ceiling for one fetch window (#938). A verbatim
    /// port of the sync client's `fetch_decompressed_cap`: the default [`MAX_FETCH_DECOMPRESSED_BYTES`]
    /// (256 MiB) is a generous FLOOR, not an absolute cap; when this consumer negotiated a LARGER
    /// per-consumer byte budget (`negotiated_credit_bytes`, itself `min(client-request, server-cap)`),
    /// the server may legitimately stream a window that big, so bounding it at the floor would falsely
    /// trip [`ClientError::BadResponse`]. The ceiling is thus
    /// `max(negotiated_credit_bytes, MAX_FETCH_DECOMPRESSED_BYTES)`: a consumer that negotiated a bigger
    /// window is honored, while an un-negotiated (`None`) or hostile fetch stays fail-closed at 256 MiB.
    fn fetch_decompressed_cap(&self) -> usize {
        self.negotiated_credit_bytes
            .and_then(|b| usize::try_from(b).ok())
            .map_or(MAX_FETCH_DECOMPRESSED_BYTES, |b| {
                b.max(MAX_FETCH_DECOMPRESSED_BYTES)
            })
    }

    /// Reads and decodes a batch delivery response (the shared tail of [`AsyncClient::fetch`]): a run of
    /// `Deliver` / `DeliverBatch` frames (transparently decompressed), with any interleaved
    /// `DeadLetter` / `Truncated` / `GapMarker` advisories, terminated by exactly one `FlowEnd` (or an
    /// `Err`). `limit` bounds the TOTAL frames so a buggy or hostile server cannot stream without bound.
    /// A verbatim port of the sync client's `read_fetch_response` with the reads awaited.
    #[allow(clippy::too_many_lines)] // one cohesive frame-dispatch loop (deliver / batch / advisory / poison-drain)
    async fn read_fetch_response(&mut self, limit: usize) -> Result<Fetch, ClientError> {
        let mut messages = Vec::new();
        let mut dead_letters = Vec::new();
        let mut truncations = Vec::new();
        let mut gaps = Vec::new();
        // The FIRST in-batch decompression failure, held until the terminating FlowEnd has been read so
        // the connection stays framed for the next request.
        let mut poison: Option<ClientError> = None;
        let mut frames = 0usize;
        // #879/#938: the running total of materialized payload bytes, capped at the negotiated byte budget
        // (floored at [`MAX_FETCH_DECOMPRESSED_BYTES`]) so a credit-bounded fetch of a tiny wire response
        // cannot expand to credit x 8 MiB of resident RAM, while a consumer that negotiated a larger byte
        // window is not falsely rejected.
        let max_aggregate = self.fetch_decompressed_cap();
        let mut decompressed_bytes = 0usize;
        loop {
            // Buffer one complete frame, then decode its body by BORROWING it out of `self.buf`
            // (#818) rather than copying it into a throwaway owned `Vec` as `read_frame` does. Every
            // byte that survives into a `Message` is copied exactly once, while the borrow is live;
            // the frame is drained only after all surviving copies are made (`self.buf.drain` at the
            // loop bottom / before each terminal return), so the borrow-then-drain ordering holds.
            self.fill_frame().await?;
            let FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            } = decode_frame(&self.buf).map_err(ClientError::Frame)?
            else {
                // `fill_frame` returns only once `decode_frame` yielded a complete `Frame`, and
                // `self.buf` is unchanged since, so a re-decode here cannot be `Incomplete`.
                unreachable!("fill_frame guarantees a complete frame at the front of the buffer");
            };
            let frame_type =
                FrameType::from_u8(type_tag).ok_or(ClientError::UnknownFrameType(type_tag))?;
            if !matches!(frame_type, FrameType::FlowEnd | FrameType::Err) {
                if frames >= limit {
                    return Err(ClientError::BadResponse(
                        "server streamed more frames than the requested credit",
                    ));
                }
                frames += 1;
            }
            match frame_type {
                FrameType::Deliver => {
                    let d = decode_deliver(body).map_err(ClientError::Body)?;
                    ingest_delivery(
                        &d,
                        &mut messages,
                        &mut poison,
                        &mut decompressed_bytes,
                        max_aggregate,
                    );
                }
                // A raw-framed batch: ONE frame carrying a contiguous run of records as their ON-DISK
                // frame bytes. Decode the header, then each on-disk frame, reconstructing each offset
                // POSITIONALLY (first_offset + i) and feeding it through the SAME per-record path a
                // `Deliver` takes — byte-for-byte the sync client's DeliverBatch arm.
                FrameType::DeliverBatch => {
                    let (header, record_bytes) =
                        decode_deliver_batch(body).map_err(ClientError::Body)?;
                    frames = frames
                        .saturating_add(header.record_count as usize)
                        .saturating_sub(1);
                    if frames > limit {
                        return Err(ClientError::BadResponse(
                            "server streamed more records than the requested credit",
                        ));
                    }
                    let mut cursor = 0usize;
                    let mut offset = header.first_offset;
                    let mut decoded = 0u32;
                    while cursor < record_bytes.len() {
                        let (view, consumed) = ironbus_core::codec::decode(&record_bytes[cursor..])
                            .map_err(|_| {
                                ClientError::BadResponse("malformed record in DeliverBatch body")
                            })?;
                        let d = DeliverBody {
                            offset,
                            generation: header.generation,
                            flags: view.flags.bits(),
                            timestamp_ms: view.timestamp_ms,
                            key: view.key,
                            headers: view.headers,
                            payload: view.payload,
                        };
                        ingest_delivery(
                            &d,
                            &mut messages,
                            &mut poison,
                            &mut decompressed_bytes,
                            max_aggregate,
                        );
                        offset = offset.saturating_add(1);
                        decoded = decoded.saturating_add(1);
                        cursor += consumed;
                    }
                    if cursor != record_bytes.len() || decoded != header.record_count {
                        return Err(ClientError::BadResponse(
                            "DeliverBatch record_count or body length mismatch",
                        ));
                    }
                }
                FrameType::DeadLetter => {
                    let dl = decode_dead_letter(body).map_err(ClientError::Body)?;
                    dead_letters.push(DeadLetter {
                        offset: dl.offset,
                        reason: dl.reason,
                    });
                }
                FrameType::Truncated => {
                    let t = decode_truncated(body)?;
                    truncations.push(t);
                }
                FrameType::GapMarker => {
                    let g = decode_gap_marker(body).map_err(ClientError::Body)?;
                    gaps.push(Gap {
                        from: g.from,
                        to: g.to,
                        bytes_skipped: g.bytes_skipped,
                        reason: g.reason,
                    });
                }
                FrameType::FlowEnd => {
                    // Drain the terminating FlowEnd before returning so the connection is left framed
                    // for the next request, exactly as the old `read_frame` (drain-then-return) did.
                    self.buf.drain(..consumed);
                    return match poison {
                        Some(e) => Err(e),
                        None => Ok(Fetch {
                            messages,
                            dead_letters,
                            truncations,
                            gaps,
                        }),
                    };
                }
                FrameType::Err => {
                    // Err is a connection-preserving per-Flow terminator (the server keeps the
                    // connection open after a fetch Err), so drain the terminating Err frame before
                    // returning to keep the connection framed for reuse, exactly as FlowEnd and the
                    // old `read_frame` (drain-then-return) did. Materialize the owned message first
                    // since `body` borrows `self.buf`, which the drain then mutates.
                    let err = ServerError::from_wire(body);
                    self.buf.drain(..consumed);
                    return Err(ClientError::Server(err));
                }
                other => return Err(ClientError::Unexpected(other)),
            }
            // A non-terminating frame (delivery / batch / advisory) was fully ingested above; every
            // surviving byte is now owned by a `Message`, so the borrow is dead and the frame can be
            // dropped from the buffer.
            self.buf.drain(..consumed);
        }
    }

    /// Acks a fetched message by its offset and fencing generation. Returns `true` if committed,
    /// `false` if the token was fenced (stale). The async port of [`ironbus_client::Client::ack`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub async fn ack(&mut self, offset: u64, generation: u64) -> Result<bool, ClientError> {
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
        self.send(FrameType::Ack, &body).await?;
        match self.read_frame().await? {
            (FrameType::AckStatus, body) => match body.as_slice() {
                [status] => Ok(*status == 1),
                _ => Err(ClientError::BadResponse(
                    "ack reply was not a one-byte status",
                )),
            },
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Acks MANY fetched messages in ONE pipelined round-trip: encode every `(offset, generation)` ack
    /// into one buffer, write it once, then drain exactly one `AckStatus` reply per ack in FIFO order.
    /// Returns one `bool` per ack IN INPUT ORDER (`true` = committed, `false` = fenced). The async port
    /// of [`ironbus_client::Client::ack_many`]. Keep the batch BOUNDED (within the consumer credit): an
    /// unbounded write-all-then-drain can deadlock against the socket buffers. An empty slice is a
    /// no-op `Ok(vec![])`.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO/encode error, a wrong-shape reply, an unexpected frame, or a
    /// server `Err` reply (the first one kept).
    pub async fn ack_many(&mut self, acks: &[(u64, u64)]) -> Result<Vec<bool>, ClientError> {
        if acks.is_empty() {
            return Ok(Vec::new());
        }
        // Phase 1: encode every Ack into ONE buffer and write it with ONE write.
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
        self.stream.write_all(&wire).await?;
        // Phase 2: drain exactly one reply per ack, FIFO. A server Err consumes its slot and is
        // remembered; the drain continues so the connection is not desynchronized.
        let mut statuses = Vec::with_capacity(acks.len());
        let mut first_err: Option<ClientError> = None;
        for _ in 0..acks.len() {
            match self.read_frame().await? {
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
                        first_err = Some(ClientError::Server(ServerError::from_wire(&body)));
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

    /// Negatively-acks a fetched message so the broker requeues it for redelivery. `delay_ms`
    /// caps the redelivery backoff for this attempt; `None` lets the broker apply its configured
    /// backoff schedule. Returns `true` if the broker requeued it, `false` if the token was fenced
    /// (stale: it already redelivered, was acked, or you nacked it before; either way do not drop
    /// local state). The async port of [`ironbus_client::Client::nack`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub async fn nack(
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
        self.send(FrameType::Ack, &body).await?;
        match self.read_frame().await? {
            (FrameType::AckStatus, body) => match body.as_slice() {
                [status] => Ok(*status == 1),
                _ => Err(ClientError::BadResponse(
                    "nack reply was not a one-byte status",
                )),
            },
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Terminates delivery of a fetched message: an intentional drop. The broker commits past it so
    /// it never redelivers and is NOT dead-lettered. Returns `true` if it was dropped, `false` if the
    /// token was fenced (stale: it already redelivered or was acked). The async port of
    /// [`ironbus_client::Client::term`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub async fn term(&mut self, offset: u64, generation: u64) -> Result<bool, ClientError> {
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
        self.send(FrameType::Ack, &body).await?;
        match self.read_frame().await? {
            (FrameType::AckStatus, body) => match body.as_slice() {
                [status] => Ok(*status == 1),
                _ => Err(ClientError::BadResponse(
                    "term reply was not a one-byte status",
                )),
            },
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Reports that work on a fetched message is still in progress, extending its lease by one
    /// visibility window so it is not redelivered while the consumer keeps working. The async port
    /// of [`ironbus_client::Client::progress`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a wrong-shape reply.
    pub async fn progress(
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
        self.send(FrameType::Ack, &body).await?;
        match self.read_frame().await? {
            (FrameType::AckStatus, body) => match body.as_slice() {
                [1] => Ok(ProgressOutcome::Extended),
                [2] => Ok(ProgressOutcome::CapReached),
                [0] => Ok(ProgressOutcome::Fenced),
                _ => Err(ClientError::BadResponse(
                    "progress reply was not a known one-byte status",
                )),
            },
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Sends a keepalive ping and awaits the pong. The async port of [`ironbus_client::Client::ping`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or an unexpected reply.
    pub async fn ping(&mut self) -> Result<(), ClientError> {
        self.send(FrameType::Ping, &[]).await?;
        match self.read_frame().await? {
            (FrameType::Pong, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Subscribes this connection to a named work-group: subsequent fetches and acks route to that
    /// group. An empty name selects the default group. The async port of
    /// [`ironbus_client::Client::subscribe`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the subscription, or a frame/connection error.
    pub async fn subscribe(&mut self, group: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_sub(
            &SubBody {
                group: group.as_bytes(),
            },
            &mut body,
        );
        self.send(FrameType::Sub, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Reverts this connection to the default work-group. The async port of
    /// [`ironbus_client::Client::unsubscribe`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] on a server error, or a connection error.
    pub async fn unsubscribe(&mut self) -> Result<(), ClientError> {
        self.send(FrameType::Unsub, &[]).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Sends a BROADCAST cumulative ack: commits the named broadcast group's single cursor up to the
    /// EXCLUSIVE offset `up_to` in one move. Safe ONLY for a broadcast group (the server hard-rejects it
    /// for a competing/`key_shared` group). An empty `group` selects the default group. The async port
    /// of [`ironbus_client::Client::cumulative_ack`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the verb, or a frame/connection error.
    pub async fn cumulative_ack(&mut self, group: &str, up_to: u64) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_cumulative_ack(
            &CumulativeAckBody {
                up_to,
                group: group.as_bytes(),
            },
            &mut body,
        );
        self.send(FrameType::CumulativeAck, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Batch-pull FETCH: drains up to `max_records` records (and at most `max_bytes` total payload
    /// bytes) in ONE round-trip, the amortized twin of [`AsyncClient::fetch`]. The response is
    /// byte-for-byte a `fetch` response past the request frame. The async port of
    /// [`ironbus_client::Client::fetch_batch`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a server that delivers more frames
    /// than the requested record cap.
    pub async fn fetch_batch(
        &mut self,
        max_records: u32,
        max_bytes: u64,
        expires: u64,
        no_wait: bool,
    ) -> Result<Fetch, ClientError> {
        let max_records = match self.negotiated_credit {
            Some(credit) => max_records.min(credit),
            None => max_records,
        };
        let mut body = Vec::new();
        encode_fetch(
            &FetchBody {
                max_records,
                max_bytes,
                expires_ms: expires,
                no_wait,
            },
            &mut body,
        );
        self.send(FrameType::Fetch, &body).await?;
        let limit = usize::try_from(max_records).unwrap_or(usize::MAX);
        self.read_fetch_response(limit).await
    }

    // ---- stream-addressed wire verbs (#588) ----

    /// CREATE-OR-ENSURE a NAMED stream by id (#588): the `StreamDeclare` verb. The async port of
    /// [`ironbus_client::Client::declare_stream`]. Idempotent — re-declaring an existing stream is a
    /// no-op success — and the broker materializes the stream's independent log on the first declare.
    /// Requires the connection to have negotiated stream addressing
    /// ([`ClientConfig::understands_streams`] AND the server confirming it, observable via
    /// [`AsyncClient::streams_enabled`]); a server that did not negotiate it replies an `Err`. The
    /// default stream (the empty name) is always present and need not be declared.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the declare (capability not negotiated, or
    /// a malformed/over-long name), [`ClientError::Body`] on an over-large field, or a frame/connection
    /// error.
    pub async fn declare_stream(&mut self, stream: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_stream_declare(
            &StreamDeclareBody {
                stream_id: stream.as_bytes(),
                partition_count: 1,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::StreamDeclare, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// PAUSES delivery for the named work-group `group` of `stream` for `pause_ms` milliseconds
    /// (#771, the `PauseGroup` verb): the async port of [`ironbus_client::Client::pause_group`].
    /// The empty stream name addresses the default stream; `pause_ms = 0` is exactly
    /// [`AsyncClient::resume_group`]. The broker gates the group's delivery until the window
    /// elapses (auto-resume) or an explicit resume, with the group's cursor, in-flight leases
    /// (their visibility clock stopped for the paused span), and subscriptions intact. Requires
    /// the `admin` scope on an auth-enabled broker; a NAMED stream additionally requires the
    /// negotiated streams capability.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the broker rejects the pause (a malformed/default group
    /// name, an unknown stream, the group cap, or a missing scope/capability),
    /// [`ClientError::Body`] on an over-large field, or a frame/connection error.
    pub async fn pause_group(
        &mut self,
        stream: &str,
        group: &str,
        pause_ms: u64,
    ) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_pause_group(
            &PauseGroupBody {
                stream_id: stream.as_bytes(),
                group: group.as_bytes(),
                pause_ms,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::PauseGroup, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// RESUMES delivery for a paused work-group immediately (#771): sugar for
    /// [`AsyncClient::pause_group`] with `pause_ms = 0`. A no-op success on a group that is not
    /// paused.
    ///
    /// # Errors
    /// As [`AsyncClient::pause_group`].
    pub async fn resume_group(&mut self, stream: &str, group: &str) -> Result<(), ClientError> {
        self.pause_group(stream, group, 0).await
    }

    /// Queries a NAMED stream's existence and durable head (#588): the `StreamInfo` verb. The async port
    /// of [`ironbus_client::Client::stream_info`]. Returns `(exists, head)` — `exists = true` and the
    /// stream's durable head offset when the stream is open, or `(false, 0)` when it does not exist. The
    /// default stream (the empty name) always reports `exists = true`. Requires the stream-addressing
    /// capability (see [`AsyncClient::declare_stream`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the query (capability not negotiated, or a
    /// malformed name), [`ClientError::Body`] on an over-large field, [`ClientError::BadResponse`] on a
    /// malformed reply, or a frame/connection error.
    pub async fn stream_info(&mut self, stream: &str) -> Result<(bool, u64), ClientError> {
        let mut body = Vec::new();
        encode_stream_info(
            &StreamInfoBody {
                stream_id: stream.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::StreamInfo, &body).await?;
        match self.read_frame().await? {
            (FrameType::StreamInfo, body) => {
                let resp = decode_stream_info_response(&body)
                    .map_err(|_| ClientError::BadResponse("malformed stream-info response"))?;
                Ok((resp.exists, resp.head))
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Publishes a message to a NAMED stream by id (#588): the `PubTo` verb, the stream-addressed twin
    /// of [`AsyncClient::produce`]. The async port of [`ironbus_client::Client::publish_to`]. The publish
    /// body is the SAME [`PubBody`] the default-stream produce carries, prefixed with the target stream
    /// id, so the broker appends it to that named stream's own log and replies a `PubAck` with the
    /// assigned offset (ack-implies-durable per stream). An EMPTY `stream` targets the default stream
    /// (equivalent to [`AsyncClient::produce`]). The publish is at-least-once (server-ack, Level 1).
    /// Requires the stream-addressing capability (see [`AsyncClient::declare_stream`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the publish (capability not negotiated, a
    /// malformed name, or a non-server-ack level), [`ClientError::Body`] on an over-large field,
    /// [`ClientError::BadResponse`] on a malformed ack, or a frame/connection error.
    pub async fn publish_to(
        &mut self,
        stream: &str,
        message: &PubBody<'_>,
    ) -> Result<u64, ClientError> {
        // Force at-least-once server-ack (Level 1) on the carried body: the named-stream path accepts
        // only that level this phase, mirroring the sync `publish_to` exactly. An old caller never set a
        // level bit, so this is a no-op for them and a guard against a mismatched method/wire for everyone.
        let at_least_once = PubBody {
            fire_and_forget: false,
            ..*message
        };
        let mut pub_body = Vec::new();
        encode_pub(&at_least_once, &mut pub_body).map_err(ClientError::Body)?;
        let mut body = Vec::new();
        encode_pub_to(
            &PubToBody {
                stream_id: stream.as_bytes(),
                pub_body: &pub_body,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::PubTo, &body).await?;
        match self.read_frame().await? {
            (FrameType::PubAck, body) => {
                let ack = decode_pub_ack(&body)
                    .map_err(|_| ClientError::BadResponse("publish-to reply was not an offset"))?;
                Ok(ack.offset)
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Subscribes this connection's consume path to a NAMED stream's work-group (#588): the `SubTo`
    /// verb, the stream-addressed twin of [`AsyncClient::subscribe`]. The async port of
    /// [`ironbus_client::Client::subscribe_to`]. Subsequent [`AsyncClient::fetch`] and
    /// [`AsyncClient::ack`] consume from and commit to THAT stream's own competing work-group
    /// (independent per stream). The stream must already exist (declare or publish to it first); an EMPTY
    /// `stream` targets the default stream (equivalent to [`AsyncClient::subscribe`]). Requires the
    /// stream-addressing capability (see [`AsyncClient::declare_stream`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the subscription (capability not negotiated,
    /// an unknown stream, or a malformed name), [`ClientError::Body`] on an over-large field, or a
    /// frame/connection error.
    pub async fn subscribe_to(&mut self, stream: &str, group: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_sub_to(
            &SubToBody {
                stream_id: stream.as_bytes(),
                group: group.as_bytes(),
                partition: None,
                ephemeral: false,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::SubTo, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Subscribes this connection's consume path to an EPHEMERAL work-group (#771, V2-M1), the
    /// async port of the sync client's `subscribe_ephemeral` (see there for the full contract): a
    /// `SubTo` carrying the ephemeral subscribe flag binds a group with NO durable broker state,
    /// reaped in full when its last subscriber disconnects or unsubscribes — at-least-once within
    /// this subscription's lifetime only; a re-subscribe starts fresh at the earliest retained
    /// offset. An EMPTY `stream` targets the default stream; a NAMED stream must already exist.
    /// Checked LOCALLY against the negotiated capability, because an old server would tolerate the
    /// flag byte and silently bind a DURABLE group.
    ///
    /// # Errors
    /// [`ClientError::CapabilityNotNegotiated`] when ephemeral groups were not negotiated,
    /// [`ClientError::Server`] on a typed broker reject (unknown stream, name/cap validation, a
    /// durability-mode conflict), [`ClientError::Body`] on an over-large field, or a
    /// frame/connection error.
    pub async fn subscribe_ephemeral(
        &mut self,
        stream: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        if !self.ephemeral_groups_enabled {
            return Err(ClientError::CapabilityNotNegotiated(
                "ephemeral consumer groups (#771)",
            ));
        }
        let mut body = Vec::new();
        encode_sub_to(
            &SubToBody {
                stream_id: stream.as_bytes(),
                group: group.as_bytes(),
                partition: None,
                ephemeral: true,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::SubTo, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    // ---- durable Tier-S streaming consume (#544 / #550) ----

    /// Writes ONE `StreamFetch` request (Tier-S) WITHOUT reading its response: the low-level write half
    /// of [`AsyncClient::stream_fetch`], pulled out so an [`AsyncStreamingConsumer`] can PIPELINE the
    /// next window's request ahead of processing the current batch (the bounded read-ahead). The matching
    /// response is drained by [`AsyncClient::read_stream_fetch_response`]. The async port of the sync
    /// client's `send_stream_fetch`.
    ///
    /// Returns the client-side `limit` (the frame cap the matching read must honor): `max_records`
    /// capped at the negotiated per-consumer credit (#292) when the server advertised one, exactly as
    /// the per-record and batch-pull fetches cap.
    async fn send_stream_fetch(
        &mut self,
        start_offset: u64,
        max_records: u32,
        max_bytes: u64,
    ) -> Result<usize, ClientError> {
        let max_records = match self.negotiated_credit {
            Some(credit) => max_records.min(credit),
            None => max_records,
        };
        let mut body = Vec::new();
        encode_stream_fetch(
            &StreamFetchBody {
                start_offset,
                max_records,
                max_bytes,
            },
            &mut body,
        );
        self.send(FrameType::StreamFetch, &body).await?;
        Ok(usize::try_from(max_records).unwrap_or(usize::MAX))
    }

    /// Reads the response to a previously-sent `StreamFetch` (the read half of
    /// [`AsyncClient::stream_fetch`]). The Tier-S delivery response is byte-for-byte a
    /// [`AsyncClient::fetch`] response past the request frame — a run of `Deliver` (or one raw-framed
    /// `DeliverBatch`) frames plus any advisories, terminated by exactly one `FlowEnd` — so it shares
    /// [`AsyncClient::read_fetch_response`] verbatim (including the transparent deliver-path
    /// decompression). The async port of the sync client's `read_stream_fetch_response`.
    async fn read_stream_fetch_response(&mut self, limit: usize) -> Result<Fetch, ClientError> {
        self.read_fetch_response(limit).await
    }

    /// STREAMING (Tier-S, #544 / #550) consumer-managed-offset fetch: serves a CONTIGUOUS batch of
    /// records `[start_offset, ...)` off the durable prefix, bounded by `max_records` and `max_bytes`,
    /// with NO lease, NO generation fence, and NO per-record cursor write. The async port of
    /// [`ironbus_client::Client::stream_fetch`]. The consumer NAMES its own `start_offset` (normally its
    /// last committed offset) and advances durability separately via a PERIODIC
    /// [`AsyncClient::stream_commit`] — the Kafka / NATS-pull contract.
    ///
    /// AT-LEAST-ONCE holds BY CONSTRUCTION: because the consumer drives the offset, a crash or reconnect
    /// simply re-fetches from its last committed offset and the uncommitted span redelivers. The returned
    /// messages carry `generation = 0` (there is no fence on this path) and MUST be settled by offset via
    /// [`AsyncClient::stream_commit`], never by [`AsyncClient::ack`].
    ///
    /// The connection MUST have negotiated Tier-S ([`ClientConfig::understands_streaming`], confirmed by
    /// [`AsyncClient::streaming_enabled`]) and be subscribed to a streaming group; otherwise the server
    /// rejects the verb with a [`ClientError::Server`]. The ergonomic batched-default loop is
    /// [`AsyncClient::streaming_consumer`]; reach for this raw method only for precise, hand-driven control.
    ///
    /// - `start_offset`: the inclusive offset to begin the contiguous read at.
    /// - `max_records`: the most records to return, capped at the negotiated per-consumer credit (#292)
    ///   when the server advertised one.
    /// - `max_bytes`: the byte budget (`0` = unbounded by bytes; the record count and the durable prefix
    ///   still bind). The server applies the floor-of-one.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error (e.g. the group is not streaming, or the
    /// connection did not negotiate Tier-S), or a server that streams more frames than the cap.
    pub async fn stream_fetch(
        &mut self,
        start_offset: u64,
        max_records: u32,
        max_bytes: u64,
    ) -> Result<Fetch, ClientError> {
        let limit = self
            .send_stream_fetch(start_offset, max_records, max_bytes)
            .await?;
        self.read_stream_fetch_response(limit).await
    }

    /// STREAMING (Tier-S, #544 / #550) periodic CUMULATIVE COMMIT: advances the streaming group's
    /// committed cursor up to the EXCLUSIVE offset `up_to`. The async port of
    /// [`ironbus_client::Client::stream_commit`]. This is the durability point of the
    /// consumer-managed-offset model: a [`AsyncClient::stream_fetch`] never advances the cursor, so
    /// retention is pinned only by this commit, and a crash redelivers everything fetched-but-not-yet-
    /// committed (the at-least-once window).
    ///
    /// Commit PERIODICALLY (once per N batches or T milliseconds), NOT per record. A re-commit at or
    /// below the current commit is an idempotent no-op success; the server HARD-REJECTS the verb on a
    /// group that is not streaming. An empty `group` selects the default group.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the verb (the group is not a streaming
    /// consumer, or `up_to` is outside the retained window), or a frame or connection error.
    pub async fn stream_commit(&mut self, group: &str, up_to: u64) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_stream_commit(
            &StreamCommitBody {
                up_to,
                group: group.as_bytes(),
            },
            &mut body,
        );
        self.send(FrameType::StreamCommit, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Opens the ERGONOMIC batched-default streaming consumer (Tier-S, #550): the high-throughput
    /// companion to the raw [`AsyncClient::stream_fetch`] / [`AsyncClient::stream_commit`] pair, and the
    /// recommended way to durably consume a streaming group. The async port of
    /// [`ironbus_client::Client::streaming_consumer`]. The handle's [`AsyncStreamingConsumer::next_batch`]
    /// loop FETCHES A WINDOW at a time, commits the offset PERIODICALLY and cumulatively rather than per
    /// record, and PREFETCHES the next window while the caller processes the current batch — the Kafka /
    /// NATS-pull ergonomic default.
    ///
    /// The connection MUST have negotiated Tier-S and be subscribed to the streaming `group` (the handle
    /// commits to that group name) before the first batch.
    #[must_use]
    pub fn streaming_consumer<'a>(&'a mut self, group: &str) -> AsyncStreamingConsumer<'a> {
        self.streaming_consumer_with(group, &StreamConsumerConfig::default())
    }

    /// Opens the batched-default streaming consumer (Tier-S, #550) with an explicit
    /// [`StreamConsumerConfig`]: the window size, the periodic-commit cadence, the starting offset, and
    /// whether read-ahead is on. The async port of [`ironbus_client::Client::streaming_consumer_with`].
    /// See [`AsyncClient::streaming_consumer`] for the default-config entry point and the full contract.
    #[must_use]
    pub fn streaming_consumer_with<'a>(
        &'a mut self,
        group: &str,
        config: &StreamConsumerConfig,
    ) -> AsyncStreamingConsumer<'a> {
        AsyncStreamingConsumer {
            client: self,
            group: group.to_string(),
            config: config.clone(),
            next_offset: config.start_offset,
            committed: config.start_offset,
            batches_since_commit: 0,
            prefetch: None,
            stashed: None,
        }
    }

    /// PREPAREs a transactional half-message on `stream` (a NAMED stream id; empty selects the default),
    /// returning a connection-minted [`TxnId`] for a later [`AsyncClient::commit`] /
    /// [`AsyncClient::rollback`]. The async port of [`ironbus_client::Client::prepare`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the prepare, [`ClientError::Body`] on an
    /// over-large field, or a frame/connection error.
    pub async fn prepare(
        &mut self,
        stream: &str,
        message: &PubBody<'_>,
    ) -> Result<TxnId, ClientError> {
        let txn = self.mint_txn_id();
        self.prepare_with_id(&txn, stream, message).await?;
        Ok(txn)
    }

    /// Like [`AsyncClient::prepare`] but with a producer-SUPPLIED `txn` id. The async port of
    /// [`ironbus_client::Client::prepare_with_id`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the prepare, [`ClientError::Body`] on an
    /// over-large field, or a frame/connection error.
    pub async fn prepare_with_id(
        &mut self,
        txn: &TxnId,
        stream: &str,
        message: &PubBody<'_>,
    ) -> Result<(), ClientError> {
        // The half message is always at-least-once server-ack; clear the wire-only faf bit so a half
        // message is never a QoS-0 drop (it must be durably buffered to commit).
        let durable = PubBody {
            fire_and_forget: false,
            ..*message
        };
        let mut pub_body = Vec::new();
        encode_pub(&durable, &mut pub_body).map_err(ClientError::Body)?;
        let mut body = Vec::new();
        encode_txn_prepare(
            &TxnPrepareBody {
                txn_id: txn.as_bytes(),
                stream_id: stream.as_bytes(),
                pub_body: &pub_body,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::TxnPrepare, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// COMMITs the prepared half message named by `txn`: the broker appends the buffered payload to the
    /// real target stream (it becomes VISIBLE) and returns the committed offset. IDEMPOTENT. The async
    /// port of [`ironbus_client::Client::commit`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] for an unknown / already-rolled-back txn, [`ClientError::Body`] on
    /// an over-large field, [`ClientError::BadResponse`] on a malformed reply, or a frame/connection error.
    pub async fn commit(&mut self, txn: &TxnId) -> Result<u64, ClientError> {
        let mut body = Vec::new();
        encode_txn_resolve(
            &TxnResolveBody {
                txn_id: txn.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::TxnCommit, &body).await?;
        match self.read_frame().await? {
            (FrameType::PubAck, body) => {
                let ack = decode_pub_ack(&body)
                    .map_err(|_| ClientError::BadResponse("txn-commit reply was not an offset"))?;
                Ok(ack.offset)
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// ROLLs BACK the prepared half message named by `txn`: the broker discards the buffered payload (it
    /// is never appended, never delivered). IDEMPOTENT. The async port of
    /// [`ironbus_client::Client::rollback`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] for an unknown / already-committed txn, [`ClientError::Body`] on an
    /// over-large field, or a frame/connection error.
    pub async fn rollback(&mut self, txn: &TxnId) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_txn_resolve(
            &TxnResolveBody {
                txn_id: txn.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::TxnRollback, &body).await?;
        match self.read_frame().await? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Opens a COALESCING fire-and-forget producer over this client: a handle that BUFFERS `Pub` frames
    /// and flushes them with one `write_all` once the buffer reaches [`FAF_FLUSH_BYTES`] (32 KiB) — the
    /// async twin of the sync client's coalesced fire-and-forget write path. No reply is ever read (the
    /// QoS-0 contract), so this amortizes the per-publish syscall across a buffer's worth of records. The
    /// caller MUST [`AsyncFireForgetProducer::flush`] (or drop, which cannot flush) at the end to push the
    /// buffered tail; an un-flushed tail is never written.
    pub fn fire_and_forget_producer(&mut self) -> AsyncFireForgetProducer<'_> {
        AsyncFireForgetProducer {
            client: self,
            wire: Vec::with_capacity(FAF_FLUSH_BYTES),
        }
    }

    /// Mints a UNIQUE transaction id for this connection: the local socket address (a per-connection
    /// seed) plus a monotonic per-connection counter. Bounded well under the 256-byte wire cap. A
    /// verbatim port of the sync client's `mint_txn_id`.
    fn mint_txn_id(&mut self) -> TxnId {
        let seq = self.next_txn_seq;
        self.next_txn_seq = self.next_txn_seq.wrapping_add(1);
        let seed = self
            .stream
            .local_addr()
            .map_or_else(|_| "txn".to_string(), |a| a.to_string());
        TxnId::new(format!("{seed}#{seq}").into_bytes())
    }

    /// Sends one framed request (length prefix, type, body). The async port of the sync client's `send`:
    /// `encode_frame` then `write_all(...).await`.
    async fn send(&mut self, frame_type: FrameType, body: &[u8]) -> Result<(), ClientError> {
        let mut frame = Vec::new();
        encode_frame(frame_type, body, &mut frame).map_err(ClientError::Frame)?;
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Reads one complete frame, buffering leftover bytes for the next call. The async port of the sync
    /// client's `read_frame`.
    async fn read_frame(&mut self) -> Result<(FrameType, Vec<u8>), ClientError> {
        read_frame_from(&mut self.stream, &mut self.buf).await
    }

    /// Buffers bytes from the socket until at least one complete frame sits at the front of
    /// `self.buf`, WITHOUT consuming it. The borrowing counterpart to [`AsyncClient::read_frame`]
    /// (#818): the delivery fan-in ([`AsyncClient::read_fetch_response`]) decodes each
    /// `Deliver` / `DeliverBatch` body directly out of `self.buf` and copies each surviving payload
    /// exactly once into its `Message`, then drains — avoiding the throwaway owned `Vec` (a heap alloc
    /// plus a full-body memcpy, a whole-batch copy for `DeliverBatch`) that `read_frame` materializes
    /// per frame. The decoded `Message`s handed to the caller are byte-for-byte identical either way.
    /// The async port of the sync client's `fill_frame`, with the read awaited.
    ///
    /// On return, `decode_frame(&self.buf)` is guaranteed to yield [`FrameDecode::Frame`].
    async fn fill_frame(&mut self) -> Result<(), ClientError> {
        // See `read_frame_from`: `self.buf` grows ONLY via a synchronous `extend_from_slice` after
        // the read future resolves, so dropping this future mid-read (a timeout) leaves `self.buf`
        // holding exactly its valid bytes — the next read decodes clean, no zero pollution.
        let mut scratch: Vec<u8> = Vec::new();
        loop {
            let needed = match decode_frame(&self.buf).map_err(ClientError::Frame)? {
                FrameDecode::Frame { .. } => return Ok(()),
                FrameDecode::Incomplete { needed } => needed,
            };
            let read_size = frame_read_size(needed, self.buf.len());
            if scratch.len() < read_size {
                scratch.resize(read_size, 0);
            }
            let n = self.stream.read(&mut scratch[..read_size]).await?;
            if n == 0 {
                return Err(ClientError::Closed);
            }
            self.buf.extend_from_slice(&scratch[..n]);
        }
    }
}

/// Decodes a `Truncated` advisory body into the public [`Truncation`]. A tiny local helper so the
/// fetch loop reads the same as the sync client's (whose `decode_truncated` returns the proto body it
/// then maps field-for-field).
fn decode_truncated(body: &[u8]) -> Result<Truncation, ClientError> {
    let t = ironbus_proto::message::decode_truncated(body).map_err(ClientError::Body)?;
    Ok(Truncation {
        earliest_retained: t.earliest_retained,
        skipped: t.skipped,
    })
}

/// A COALESCING fire-and-forget producer (QoS-0) over an [`AsyncClient`]: it buffers `Pub` frames and
/// flushes them with one `write_all` once the buffer reaches [`FAF_FLUSH_BYTES`], never reading a reply.
/// The async twin of the sync client's coalesced fire-and-forget write path. Borrows the client
/// exclusively for its lifetime (one in-flight write path at a time, the FIFO contract).
#[derive(Debug)]
pub struct AsyncFireForgetProducer<'a> {
    client: &'a mut AsyncClient,
    /// The coalescing buffer of encoded `Pub` frames, flushed once it crosses [`FAF_FLUSH_BYTES`].
    wire: Vec<u8>,
}

impl AsyncFireForgetProducer<'_> {
    /// Buffers one fire-and-forget produce, flushing the buffer to the socket with one `write_all` if it
    /// crosses [`FAF_FLUSH_BYTES`] (32 KiB). No reply is read (QoS-0). The broker may drop the publish
    /// under load and the producer accepts loss by contract.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error (during a triggered flush) or an over-large field.
    pub async fn produce(&mut self, message: &PubBody<'_>) -> Result<(), ClientError> {
        let faf = PubBody {
            fire_and_forget: true,
            ..*message
        };
        let mut body = Vec::new();
        encode_pub(&faf, &mut body).map_err(ClientError::Body)?;
        encode_frame(FrameType::Pub, &body, &mut self.wire).map_err(ClientError::Frame)?;
        if self.wire.len() >= FAF_FLUSH_BYTES {
            self.flush().await?;
        }
        Ok(())
    }

    /// Flushes the buffered `Pub` frames to the socket with one `write_all`. A no-op when the buffer is
    /// empty. The caller MUST call this at the end to push the buffered tail (a dropped producer cannot
    /// flush, since flushing is async).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error.
    pub async fn flush(&mut self) -> Result<(), ClientError> {
        if self.wire.is_empty() {
            return Ok(());
        }
        self.client.stream.write_all(&self.wire).await?;
        self.wire.clear();
        Ok(())
    }
}

/// The ERGONOMIC batched-default streaming consumer (Tier-S, #550), opened by
/// [`AsyncClient::streaming_consumer`] / [`AsyncClient::streaming_consumer_with`]: the async twin of the
/// sync client's [`ironbus_client::StreamConsumerConfig`]-driven `StreamingConsumer`. Per
/// [`AsyncStreamingConsumer::next_batch`] it fetches a WINDOW (one [`AsyncClient::stream_fetch`]),
/// commits the cumulative offset PERIODICALLY ([`AsyncClient::stream_commit`]) rather than per record,
/// and (by default) PREFETCHES the next window while the caller processes the current one.
///
/// # Bounded read-ahead
///
/// When [`StreamConsumerConfig::read_ahead`] is on (the default), the handle pipelines the NEXT window's
/// `StreamFetch` the instant it has read the current batch off the wire, so at most ONE window is
/// outstanding ahead of the caller, bounded by the same `max_records` / `max_bytes` budget — the
/// outstanding memory is at most two windows and never an unbounded buffer.
///
/// # At-least-once preserved
///
/// The handle commits only offsets it has HANDED to the caller and whose window the commit cadence has
/// reached; a prefetched-but-not-yet-returned window is never committed. A crash redelivers every
/// fetched-but-uncommitted record and loses nothing — the consumer-managed at-least-once contract.
///
/// # Errors and connection state
///
/// An IO error, a server error (e.g. the group is not streaming), or an unexpected frame leaves the
/// connection state undefined: drop the underlying [`AsyncClient`]. A verbatim port of the sync
/// `StreamingConsumer`'s FIFO discipline — the single-connection commit-on-a-clean-wire rule (drain any
/// outstanding prefetch into the stash before a `StreamCommit`) holds identically, since the wire
/// contract is unchanged and only the IO awaits.
#[derive(Debug)]
pub struct AsyncStreamingConsumer<'a> {
    client: &'a mut AsyncClient,
    /// The streaming group this handle commits to (the `StreamCommit` group name).
    group: String,
    /// The window size, commit cadence, and read-ahead policy.
    config: StreamConsumerConfig,
    /// The next offset to fetch from: advanced by the count of records each window delivers (the
    /// consumer's own cursor, what a reconnect would resume from).
    next_offset: u64,
    /// The highest offset the handle has COMMITTED up to (exclusive). Starts at `start_offset`.
    committed: u64,
    /// How many windows have been fetched since the last commit; when it reaches `commit_every_batches`
    /// the handle commits up to `next_offset` and resets this to `0`.
    batches_since_commit: u32,
    /// The BOUNDED read-ahead slot: `Some(limit)` when a next-window `StreamFetch` has been pipelined and
    /// its response is not yet drained (the `limit` is the frame cap that read must honor); `None` when
    /// no prefetch is outstanding. At most one is ever held, which bounds the read-ahead.
    prefetch: Option<usize>,
    /// A drained-but-not-yet-returned read-ahead window, held when [`AsyncStreamingConsumer::commit_now`]
    /// had to clear the wire (a `StreamCommit` is a request/reply that cannot run with a prefetch response
    /// unread on the FIFO). The next [`AsyncStreamingConsumer::next_batch`] returns this BEFORE issuing a
    /// new fetch, so no record is lost and the at-most-one-window-ahead bound still holds.
    stashed: Option<Fetch>,
}

impl AsyncStreamingConsumer<'_> {
    /// The effective per-window record cap (the configured `max_records`, floored at `1` so the consumer
    /// always makes progress). The actual pull is additionally capped at the negotiated per-consumer
    /// credit inside [`AsyncClient::stream_fetch`].
    fn window_records(&self) -> u32 {
        self.config.max_records.max(1)
    }

    /// The effective commit cadence (the configured `commit_every_batches`, floored at `1`).
    fn commit_cadence(&self) -> u32 {
        self.config.commit_every_batches.max(1)
    }

    /// Fetches the NEXT window of streaming records (Tier-S, #550) and advances the consumer's cursor,
    /// committing the cumulative offset PERIODICALLY (per [`StreamConsumerConfig::commit_every_batches`])
    /// and (by default) PREFETCHING the window after this one. Returns the batch's messages and any
    /// advisories; an EMPTY batch ([`StreamBatch::is_empty`]) means the stream has drained to its durable
    /// head. The async port of the sync `StreamingConsumer::next_batch`.
    ///
    /// The caller processes the returned `messages` and then calls `next_batch` again; it does NOT ack
    /// them individually (the handle commits cumulatively by offset). To force a commit at a precise
    /// processed-up-to point, call [`AsyncStreamingConsumer::commit_now`] between batches.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error (the group is not streaming, or Tier-S
    /// was not negotiated), or a malformed/over-cap response. On error the connection state is undefined;
    /// drop the [`AsyncClient`].
    pub async fn next_batch(&mut self) -> Result<StreamBatch, ClientError> {
        let start = self.next_offset;
        // Read this window, in priority order: (1) a window a precise `commit_now` already drained and
        // stashed; (2) a pipelined read-ahead response outstanding on the wire; (3) a fresh awaited fetch.
        // All three yield the SAME contiguous run starting at `start` — the read-ahead only moves WHEN the
        // request was written, never WHICH records come back. A verbatim port of the sync next_batch.
        let fetch = if let Some(stashed) = self.stashed.take() {
            stashed
        } else if let Some(limit) = self.prefetch.take() {
            self.client.read_stream_fetch_response(limit).await?
        } else {
            self.client
                .stream_fetch(start, self.window_records(), self.config.max_bytes)
                .await?
        };
        let delivered = u64::try_from(fetch.messages.len()).unwrap_or(u64::MAX);
        self.next_offset = self.next_offset.saturating_add(delivered);

        // Periodic cumulative commit FIRST, before any read-ahead is in flight. A `StreamCommit` is a
        // request/REPLY round-trip on this single FIFO connection: committing while a pipelined prefetch
        // response sat unread would make the commit's `read_frame` consume the prefetch's delivery instead
        // of the commit's `Ok`. Doing the commit on a CLEAN wire (no prefetch outstanding — the slot was
        // `take`n above) keeps the FIFO unambiguous. An empty window does not tick the cadence (no new
        // ground) but still flushes any pending progress so a drained stream durably checkpoints.
        if delivered > 0 {
            self.batches_since_commit = self.batches_since_commit.saturating_add(1);
            if self.batches_since_commit >= self.commit_cadence() {
                self.commit_now().await?;
            }
        } else {
            self.commit_now().await?;
        }

        // Bounded read-ahead: with the commit's round-trip settled, pipeline the NEXT window's request so
        // its response arrives while the caller processes this batch. Only when a non-empty window came
        // back, and only ONE is ever outstanding (`self.prefetch` holds at most one slot), which bounds it.
        if self.config.read_ahead && delivered > 0 {
            let limit = self
                .client
                .send_stream_fetch(
                    self.next_offset,
                    self.window_records(),
                    self.config.max_bytes,
                )
                .await?;
            self.prefetch = Some(limit);
        }

        Ok(StreamBatch {
            messages: fetch.messages,
            dead_letters: fetch.dead_letters,
            truncations: fetch.truncations,
            gaps: fetch.gaps,
        })
    }

    /// Commits the cumulative offset NOW, up to the consumer's current cursor (every record handed to the
    /// caller so far): the precise-commit hook over the handle's periodic auto-commit. Idempotent — a
    /// no-op when nothing new has been fetched since the last commit. The async port of the sync
    /// `StreamingConsumer::commit_now`.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the commit (the group is not streaming, or
    /// the offset is outside the retained window), or a frame or connection error.
    pub async fn commit_now(&mut self) -> Result<(), ClientError> {
        // A `StreamCommit` is a request/reply round-trip on this single FIFO connection, so it cannot run
        // with a read-ahead response unread (the commit's `read_frame` would consume the prefetched
        // delivery). DRAIN any outstanding prefetch into the stash first, clearing the wire WITHOUT losing
        // the records: the next `next_batch` returns the stash. The prefetched window is NOT part of
        // `[committed, next_offset)` (the caller has not been handed it), so committing up to `next_offset`
        // after draining stays correct.
        if let Some(limit) = self.prefetch.take() {
            self.stashed = Some(self.client.read_stream_fetch_response(limit).await?);
        }
        if self.next_offset <= self.committed {
            return Ok(());
        }
        self.client
            .stream_commit(&self.group, self.next_offset)
            .await?;
        self.committed = self.next_offset;
        self.batches_since_commit = 0;
        Ok(())
    }

    /// Drains any outstanding read-ahead response and COMMITS the consumer's cursor, returning the final
    /// committed offset (exclusive). Call this before dropping the handle so a pending periodic commit is
    /// flushed and a pipelined prefetch is not left half-read on the wire. The async port of the sync
    /// `StreamingConsumer::finish`. After this the connection is clean for the next request.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a malformed response while draining
    /// the prefetch or committing.
    pub async fn finish(mut self) -> Result<u64, ClientError> {
        // `commit_now` drains any outstanding read-ahead response into the stash (leaving the wire framed)
        // and commits up to the consumer's cursor. The stashed window's records are NOT committed (the
        // caller never processed them), so they redeliver on the next run — the at-least-once contract.
        self.commit_now().await?;
        Ok(self.committed)
    }

    /// The offset the handle will fetch from next (the consumer's cursor, exclusive of everything already
    /// delivered). A reconnect would resume from the last COMMITTED offset, not this.
    #[must_use]
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// The highest offset committed so far (exclusive): the durable checkpoint a crash would resume from.
    /// Everything in `[committed_offset(), next_offset())` is the at-least-once window that redelivers on
    /// a crash.
    #[must_use]
    pub fn committed_offset(&self) -> u64 {
        self.committed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_streaming_fetch_window_is_pinned_at_2048() {
        // #1027 PIN (async port): the re-exported sync-client default is the peer-comparable 2048
        // window (the measured ~1M rec/s streaming-drain plateau point, and the broker's default
        // per-consumer credit ceiling); 256 left a tight drain loop round-trip-latency-bound. This
        // FAILS if the re-export drifts from the pinned sizing.
        assert_eq!(DEFAULT_STREAM_FETCH_RECORDS, 2048);
        assert_eq!(
            StreamConsumerConfig::default().max_records,
            DEFAULT_STREAM_FETCH_RECORDS,
            "the config default rides the pinned constant"
        );
    }

    #[test]
    fn ingest_delivery_caps_the_aggregate_decompressed_bytes() {
        // #879 (async port): the running aggregate of materialized payload bytes is bounded across a
        // fetch window, not just per-record. Once the running total would exceed the ceiling the batch
        // is poisoned (BadResponse) and the over-cap record (and every later one) is NOT materialized,
        // so a credit-bounded fetch of many tiny high-ratio frames can never OOM the client.
        let cap = 1000usize;
        let big = vec![0u8; 400]; // an uncompressed payload; the COMPRESSED path uses the same accounting
        let rec = |off: u64| DeliverBody {
            offset: off,
            generation: 0,
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            payload: &big,
        };
        let mut messages = Vec::new();
        let mut poison: Option<ClientError> = None;
        let mut total = 0usize;

        ingest_delivery(&rec(0), &mut messages, &mut poison, &mut total, cap);
        ingest_delivery(&rec(1), &mut messages, &mut poison, &mut total, cap);
        assert!(poison.is_none(), "under the cap nothing is poisoned");
        assert_eq!(messages.len(), 2);

        ingest_delivery(&rec(2), &mut messages, &mut poison, &mut total, cap);
        assert!(
            matches!(poison, Some(ClientError::BadResponse(_))),
            "crossing the cap poisons the batch"
        );
        assert_eq!(messages.len(), 2, "the over-cap record is not materialized");

        ingest_delivery(&rec(3), &mut messages, &mut poison, &mut total, cap);
        assert_eq!(
            messages.len(),
            2,
            "later records are dropped while poisoned"
        );
    }

    /// Encodes one frame (`[len][tag][body]`) for the scripted server.
    fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_frame(ty, body, &mut out).unwrap();
        out
    }

    /// A one-shot blocking listener that writes `script` up front on the single connection it accepts,
    /// then drains (discarding) until the async client closes. The async client drives request/response
    /// purely off its own buffer, so emitting every reply frame up front is read back in order.
    fn raw_server(script: Vec<u8>) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read as _, Write as _};
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

    /// An `Info` body advertising a per-consumer negotiated BYTE budget of `negotiated` (#938).
    fn info_with_credit_bytes(negotiated: u64) -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_info(
            &ironbus_proto::message::InfoBody {
                ephemeral_groups: false,
                credit: None,
                credit_bytes: Some(ironbus_proto::message::CreditAdvert {
                    negotiated,
                    cap: negotiated,
                }),
                gap_marker: false,
                default_ack_level: None,
                streaming: false,
                default_tier: None,
                deliver_batch: false,
                streams: false,
            },
            &mut body,
        );
        frame(FrameType::Info, &body)
    }

    #[tokio::test]
    async fn the_fetch_decompressed_cap_is_derived_from_the_negotiated_byte_budget() {
        // #938 (async port): the AGGREGATE materialized-payload ceiling for a fetch window is the LARGER
        // of the negotiated per-consumer byte budget and the 256 MiB floor, so a consumer that negotiated
        // a window bigger than 256 MiB is not falsely tripped with BadResponse, while an un-negotiated or
        // smaller budget stays fail-closed at the 256 MiB default.
        let floor = MAX_FETCH_DECOMPRESSED_BYTES;

        // A budget ABOVE the floor raises the ceiling to the negotiated value.
        let big = u64::try_from(floor).unwrap() + 4096;
        let (addr, handle) = raw_server(info_with_credit_bytes(big));
        let c = AsyncClient::connect(addr).await.unwrap();
        assert_eq!(c.negotiated_credit_bytes(), Some(big));
        assert_eq!(
            c.fetch_decompressed_cap(),
            usize::try_from(big).unwrap(),
            "a negotiated budget above the floor raises the aggregate ceiling"
        );
        drop(c);
        handle.join().unwrap();

        // A budget BELOW the floor keeps the 256 MiB default (fail-closed).
        let (addr, handle) = raw_server(info_with_credit_bytes(4096));
        let c = AsyncClient::connect(addr).await.unwrap();
        assert_eq!(c.negotiated_credit_bytes(), Some(4096));
        assert_eq!(
            c.fetch_decompressed_cap(),
            floor,
            "a negotiated budget below the floor keeps the 256 MiB default"
        );
        drop(c);
        handle.join().unwrap();

        // No advertisement (an old/empty Info) -> the 256 MiB default.
        let (addr, handle) = raw_server(frame(FrameType::Info, b""));
        let c = AsyncClient::connect(addr).await.unwrap();
        assert_eq!(c.negotiated_credit_bytes(), None);
        assert_eq!(c.fetch_decompressed_cap(), floor);
        drop(c);
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn connect_disables_nagle_on_the_client_socket() {
        // #1028 (async port): the connect path sets TCP_NODELAY on the dialed socket, byte-for-byte
        // the sync client's `dial` behavior — the produce/ack and fetch paths are small-frame
        // request-response, where Nagle + the broker's delayed ACK stacks an RTT-scale stall onto
        // every awaited round-trip on a real network. Read the option back via getsockopt on the
        // LIVE connection, so this pins the real socket state, not the call site.
        let (addr, handle) = raw_server(frame(FrameType::Info, b""));
        let c = AsyncClient::connect(addr).await.unwrap();
        assert!(
            c.stream.nodelay().expect("read TCP_NODELAY back"),
            "the connected client socket must have TCP_NODELAY set"
        );
        drop(c);
        handle.join().unwrap();
    }

    /// Like [`raw_server`] but CAPTURES every byte the client sends and returns it from the join
    /// handle, so a test can assert on the handshake bytes the client wrote (e.g. the #884 auth
    /// section in the `Connect` frame). Writes `script` up front, then reads until the client closes.
    fn capturing_raw_server(
        script: Vec<u8>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.write_all(&script).unwrap();
            let mut captured = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = sock.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                captured.extend_from_slice(&chunk[..n]);
            }
            captured
        });
        (addr, handle)
    }

    /// Decodes a captured byte stream into its `(FrameType, body)` frames in order.
    fn decode_all_frames(bytes: &[u8]) -> Vec<(FrameType, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            match decode_frame(&bytes[pos..]).unwrap() {
                FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed,
                } => {
                    out.push((FrameType::from_u8(type_tag).unwrap(), body.to_vec()));
                    pos += consumed;
                }
                FrameDecode::Incomplete { .. } => break,
            }
        }
        out
    }

    #[tokio::test]
    async fn connect_with_a_credential_appends_the_auth_section() {
        // #884 (async port): AsyncClient::connect_with presents a configured credential — it appends
        // the auth section the server verifies (append_connect_auth), byte-for-byte the sync client.
        // Fails WITHOUT the fix (connect_with never appended an auth section). The credential's Debug
        // redaction is shared with (and covered by) the sync client's ClientConfig test.
        use ironbus_proto::message::{pack_password_material, parse_connect_auth};

        let secret_user = b"alice";
        let secret_pw = b"correct horse battery staple";
        let material = pack_password_material(secret_user, secret_pw).unwrap();
        let config = ClientConfig {
            credential: Some(AuthCredential {
                mechanism: AuthMechanism::Password,
                material: material.clone(),
            }),
            ..ClientConfig::default()
        };
        // Redaction: the plaintext password must not appear in a Debug of the config, and the
        // redaction marker MUST be present (a positive check, symmetric with the sync client's test).
        let dbg = format!("{config:?}");
        assert!(
            !dbg.contains("correct horse"),
            "the credential material must be redacted in Debug, got: {dbg}"
        );
        assert!(
            dbg.contains("redacted"),
            "the credential Debug must carry the redaction marker, got: {dbg}"
        );

        let (addr, handle) = capturing_raw_server(frame(FrameType::Info, b""));
        let c = AsyncClient::connect_with(addr, &config).await.unwrap();
        drop(c);
        let captured = handle.join().unwrap();
        let frames = decode_all_frames(&captured);
        assert_eq!(frames[0].0, FrameType::Connect);
        let parsed = parse_connect_auth(&frames[0].1)
            .expect("the auth section is well formed")
            .expect("connect_with with a credential appends an auth section");
        assert_eq!(parsed.mechanism, AuthMechanism::Password);
        assert_eq!(parsed.material, material);
    }

    #[tokio::test]
    async fn connect_with_no_credential_appends_no_auth_section() {
        // #884 backward-compat (async port): the default config (credential = None) appends NO auth
        // section, so an unauthenticated async connect is byte-for-byte unchanged.
        use ironbus_proto::message::parse_connect_auth;

        let (addr, handle) = capturing_raw_server(frame(FrameType::Info, b""));
        let c = AsyncClient::connect_with(addr, &ClientConfig::default())
            .await
            .unwrap();
        drop(c);
        let captured = handle.join().unwrap();
        let frames = decode_all_frames(&captured);
        assert_eq!(frames[0].0, FrameType::Connect);
        assert_eq!(parse_connect_auth(&frames[0].1).unwrap(), None);
    }

    /// A connected loopback tokio TCP pair `(client, server)`, both ends owned by the caller so a
    /// test can drive reads and writes deterministically. `connect` completes into the listener
    /// backlog, so the subsequent `accept` returns the peer end.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn read_frame_from_reassembles_a_large_frame_dribbled_in_pieces() {
        // #819 (async port): a frame far larger than the per-read cap is completed by sizing each read
        // from the decoder's `needed` hint (clamped at READ_CAP), so a ~1 MiB frame takes a handful of
        // capped reads. Dribbling it in small pieces from the peer — with the reader stitching between
        // pieces — must reassemble the exact bytes, proving the needed-hint sizing loses no byte.
        let body = vec![0xABu8; 1_000_000]; // >> READ_CAP, forcing several capped reads
        let wire = frame(FrameType::Deliver, &body);

        let (mut client, mut server) = tcp_pair().await;
        let wire_for_writer = wire.clone();
        let writer = tokio::spawn(async move {
            for chunk in wire_for_writer.chunks(7000) {
                server.write_all(chunk).await.unwrap();
                server.flush().await.unwrap();
            }
        });

        let mut buf = Vec::new();
        let (ty, got) = read_frame_from(&mut client, &mut buf).await.unwrap();
        writer.await.unwrap();
        assert_eq!(ty, FrameType::Deliver);
        assert_eq!(
            got, body,
            "the dribbled large frame reassembles byte-for-byte"
        );
        assert!(
            buf.is_empty(),
            "the frame drained cleanly, nothing left over"
        );
    }

    #[tokio::test]
    async fn a_dropped_read_future_mid_frame_leaves_the_buffer_uncorrupted_and_a_retry_completes() {
        // #819 THE cancellation-safety guarantee (async): `buf` grows ONLY by a SYNCHRONOUS
        // `extend_from_slice` AFTER the read future resolves — never pre-grown with placeholder zeros.
        // So when `tokio::time::timeout` fires and DROPS the fill future mid-read, the `extend` never
        // runs and `buf` is left holding EXACTLY the valid bytes received so far, with no zero
        // pollution. A retry on that SAME buffer must then complete the frame with no desync — the
        // failure mode a truncate-on-error patch could never fix, since the drop happens across the
        // await with no error to truncate on.
        let body = vec![0x5Au8; 8000];
        let wire = frame(FrameType::Deliver, &body);
        let split = 100; // an arbitrary partial prefix, mid-frame

        let (mut client, mut server) = tcp_pair().await;

        // Only the first `split` bytes are available; the rest is withheld so the fill future is parked
        // in the socket read when the timeout fires and drops it.
        server.write_all(&wire[..split]).await.unwrap();
        server.flush().await.unwrap();

        let mut buf = Vec::new();
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            read_frame_from(&mut client, &mut buf),
        )
        .await;
        assert!(
            timed_out.is_err(),
            "the fill future is dropped by the timeout mid-read"
        );
        // THE INVARIANT: the dropped future never ran its `extend`, so `buf` holds exactly the valid
        // bytes — no zero padding across the await.
        assert_eq!(
            buf.len(),
            split,
            "buf.len() equals the valid buffered byte count after the drop"
        );
        assert_eq!(
            buf,
            &wire[..split],
            "the buffered bytes are the exact prefix, not zero pollution"
        );

        // The rest arrives; a fresh read on the same (pollution-free) buffer completes the frame.
        server.write_all(&wire[split..]).await.unwrap();
        server.flush().await.unwrap();
        let (ty, got) = read_frame_from(&mut client, &mut buf).await.unwrap();
        assert_eq!(ty, FrameType::Deliver);
        assert_eq!(
            got, body,
            "the retry reassembles the full frame — no desync"
        );
        assert!(buf.is_empty(), "the completed frame drained cleanly");
    }

    #[tokio::test]
    async fn read_frame_from_batches_small_frames_from_a_single_read() {
        // #819 non-regression (async port): sizing the read from the `needed` hint must NOT lose the
        // small-frame batching — one socket read can pull several tiny frames. Two small frames written
        // together are pulled in one read; the first `read_frame_from` returns frame A while frame B
        // stays BUFFERED (`buf` non-empty), and a second call returns B with no further bytes sent.
        let a = frame(FrameType::Info, b"alpha");
        let b = frame(FrameType::Pong, b"");
        let mut both = a.clone();
        both.extend_from_slice(&b);

        let (mut client, mut server) = tcp_pair().await;
        server.write_all(&both).await.unwrap();
        server.flush().await.unwrap();

        let mut buf = Vec::new();
        let (ty_a, body_a) = read_frame_from(&mut client, &mut buf).await.unwrap();
        assert_eq!(ty_a, FrameType::Info);
        assert_eq!(body_a, b"alpha");
        assert!(
            !buf.is_empty(),
            "frame B was batched into the same read and stays buffered"
        );

        // No more bytes are sent; B decodes purely from the buffer.
        let (ty_b, body_b) = read_frame_from(&mut client, &mut buf).await.unwrap();
        assert_eq!(ty_b, FrameType::Pong);
        assert!(body_b.is_empty());
        assert!(buf.is_empty(), "both frames drained");
    }

    #[tokio::test]
    async fn back_to_back_fetch_responses_stay_framed_across_the_borrowing_drain() {
        // #818 (async port): the delivery fan-in decodes each frame body by BORROWING it out of the
        // client buffer and drains only AFTER every surviving byte is copied into its `Message`. The
        // reordered drain must consume EXACTLY one frame each iteration (and the terminating FlowEnd).
        // Two complete fetch responses are buffered back-to-back (the server writes the whole script up
        // front), so the SECOND response already sits in the client's buffer when the FIRST fetch
        // returns. If any per-frame or FlowEnd drain were off by a byte, the second fetch would misframe.
        use ironbus_proto::message::encode_deliver;
        let mut d0 = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 0,
                generation: 7,
                flags: 0,
                timestamp_ms: 11,
                key: b"k0",
                headers: b"h0",
                payload: b"first-a",
            },
            &mut d0,
        )
        .unwrap();
        let mut d1 = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 1,
                generation: 7,
                flags: 0,
                timestamp_ms: 12,
                key: b"k1",
                headers: b"",
                payload: b"first-b",
            },
            &mut d1,
        )
        .unwrap();
        let mut d2 = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 2,
                generation: 9,
                flags: 0,
                timestamp_ms: 13,
                key: b"",
                headers: b"h2",
                payload: b"second-only",
            },
            &mut d2,
        )
        .unwrap();

        let mut script = frame(FrameType::Info, b"");
        // Response 1: two deliveries + FlowEnd(2).
        script.extend(frame(FrameType::Deliver, &d0));
        script.extend(frame(FrameType::Deliver, &d1));
        script.extend(frame(FrameType::FlowEnd, &2u32.to_le_bytes()));
        // Response 2: one delivery + FlowEnd(1), already buffered behind response 1.
        script.extend(frame(FrameType::Deliver, &d2));
        script.extend(frame(FrameType::FlowEnd, &1u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);

        let mut c = AsyncClient::connect(addr).await.unwrap();
        let first = c.fetch(10).await.unwrap().messages;
        assert_eq!(first.len(), 2, "response 1 yields both buffered deliveries");
        assert_eq!(first[0].offset, 0);
        assert_eq!(first[0].key, b"k0");
        assert_eq!(first[0].headers, b"h0");
        assert_eq!(first[0].payload, b"first-a");
        assert_eq!(first[1].offset, 1);
        assert_eq!(first[1].key, b"k1");
        assert_eq!(first[1].payload, b"first-b");
        // The second response was ALREADY in the buffer when the first fetch returned; that it decodes
        // cleanly proves the reordered borrow-then-drain left the connection exactly framed.
        let second = c.fetch(10).await.unwrap().messages;
        assert_eq!(second.len(), 1, "response 2 survives the reordered drain");
        assert_eq!(second[0].offset, 2);
        assert_eq!(second[0].generation, 9);
        assert_eq!(second[0].headers, b"h2");
        assert_eq!(second[0].payload, b"second-only");
        drop(c);
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn a_fetch_server_err_leaves_the_connection_framed_for_reuse() {
        // #818 regression (async port): `Err` is a CONNECTION-PRESERVING per-Flow terminator — the
        // server keeps the connection open after a fetch `Err` — so the borrow-then-drain fetch loop
        // must DRAIN the terminating `Err` frame before returning, exactly as it drains the sibling
        // `FlowEnd` terminator. Response 1 ends in an `Err`; response 2 (a valid delivery + FlowEnd) is
        // already buffered behind it. If the `Err` frame were left in the buffer, the second fetch would
        // re-read those stale bytes and misframe (re-surfacing the server error instead of decoding
        // response 2). That the second fetch succeeds proves the `Err` was drained and the connection
        // stayed exactly framed for reuse.
        use ironbus_proto::message::encode_deliver;
        let mut d0 = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 0,
                generation: 3,
                flags: 0,
                timestamp_ms: 21,
                key: b"k0",
                headers: b"h0",
                payload: b"before-the-err",
            },
            &mut d0,
        )
        .unwrap();
        let mut d1 = Vec::new();
        encode_deliver(
            &DeliverBody {
                offset: 5,
                generation: 4,
                flags: 0,
                timestamp_ms: 22,
                key: b"k1",
                headers: b"h1",
                payload: b"after-the-err",
            },
            &mut d1,
        )
        .unwrap();

        let mut script = frame(FrameType::Info, b"");
        // Response 1: one delivery, then an Err terminator (a per-Flow server error).
        script.extend(frame(FrameType::Deliver, &d0));
        script.extend(frame(FrameType::Err, b"consumer fenced"));
        // Response 2: a valid delivery + FlowEnd(1), already buffered behind the Err.
        script.extend(frame(FrameType::Deliver, &d1));
        script.extend(frame(FrameType::FlowEnd, &1u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);

        let mut c = AsyncClient::connect(addr).await.unwrap();
        // The first fetch surfaces the server Err (and, per the fix, drains that Err frame).
        match c.fetch(10).await.unwrap_err() {
            ClientError::Server(msg) => assert_eq!(msg, "consumer fenced"),
            other => panic!("expected a server error, got {other:?}"),
        }
        // The second response was ALREADY buffered behind the Err when the first fetch returned; that it
        // decodes cleanly proves the Err terminator was drained and left the connection exactly framed.
        let second = c.fetch(10).await.unwrap().messages;
        assert_eq!(
            second.len(),
            1,
            "response 2 survives the Err-terminator drain"
        );
        assert_eq!(second[0].offset, 5);
        assert_eq!(second[0].generation, 4);
        assert_eq!(second[0].key, b"k1");
        assert_eq!(second[0].payload, b"after-the-err");
        drop(c);
        handle.join().unwrap();
    }

    // ===================== EPHEMERAL CONSUMER GROUPS (#771, V2-M1) =====================

    /// An `Info` body confirming (or not) the ephemeral-groups capability (#771).
    fn info_with_ephemeral(confirmed: bool) -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_info(
            &ironbus_proto::message::InfoBody {
                credit: None,
                credit_bytes: None,
                gap_marker: false,
                default_ack_level: None,
                streaming: false,
                default_tier: None,
                deliver_batch: false,
                streams: true,
                ephemeral_groups: confirmed,
            },
            &mut body,
        );
        frame(FrameType::Info, &body)
    }

    #[tokio::test]
    async fn subscribe_ephemeral_requires_the_confirmed_capability_and_binds_when_it_is() {
        // CONFIRMED: the scripted server echoes the capability, so the subscribe goes to the wire
        // and its scripted Ok completes it.
        let mut script = info_with_ephemeral(true);
        script.extend_from_slice(&frame(FrameType::Ok, b""));
        let (addr, handle) = raw_server(script);
        let cfg = ClientConfig {
            request_ephemeral_groups: true,
            understands_streams: true,
            ..ClientConfig::default()
        };
        let mut c = AsyncClient::connect_with(addr, &cfg).await.unwrap();
        assert!(c.ephemeral_groups_enabled());
        c.subscribe_ephemeral("orders", "eph").await.unwrap();
        drop(c);
        handle.join().unwrap();

        // NOT confirmed (an OLD server never emits the Info flags2 byte): the subscribe fails
        // LOCALLY with the typed error and puts NOTHING on the wire — an old server would tolerate
        // the flag byte and silently bind a DURABLE group, the exact failure this gate forecloses.
        let (addr, handle) = raw_server(info_with_ephemeral(false));
        let mut c = AsyncClient::connect_with(addr, &cfg).await.unwrap();
        assert!(!c.ephemeral_groups_enabled());
        assert!(matches!(
            c.subscribe_ephemeral("orders", "eph").await,
            Err(ClientError::CapabilityNotNegotiated(_))
        ));
        drop(c);
        handle.join().unwrap();
    }
}
