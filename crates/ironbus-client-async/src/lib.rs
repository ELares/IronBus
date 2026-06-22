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
    decode_not_leader, decode_pub_ack, encode_ack, encode_connect, encode_cumulative_ack,
    encode_fetch, encode_pub, encode_sub, encode_txn_prepare, encode_txn_resolve, AckBody,
    AckLevel, AckOp, ConnectBody, ConsumeTier, CumulativeAckBody, DeliverBody, FetchBody, PubBody,
    SubBody, TxnPrepareBody, TxnResolveBody,
};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

// Re-export the sync client's public data types VERBATIM: this crate's API RETURNS these exact types
// (it does not redefine them), so a caller can name them without depending on `ironbus-client`
// directly. They are the SYNC client's types, shared unchanged — the wire contract is identical.
#[doc(no_inline)]
pub use ironbus_client::{
    ClientConfig, ClientError, DeadLetter, Fetch, Gap, Message, ProduceAck, Truncation, TxnId,
};

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

/// Ingests one decoded delivery into the fetch result, applying the SAME transparent broker-side
/// decompression the sync client's `ingest_delivery` does and pushing the resulting [`Message`] onto
/// `messages` — UNLESS a prior decompression failure already poisoned the batch (`poison.is_some()`),
/// in which case the delivery is consumed and dropped un-acked (the broker redelivers it). The FIRST
/// failure is recorded in `poison` (carrying the record's offset/generation for an ack/nack-skip); the
/// rest of the batch is still drained before the error surfaces. This is a verbatim port of the sync
/// helper — the decode/decompress logic is IO-free and identical.
fn ingest_delivery(
    d: &DeliverBody<'_>,
    messages: &mut Vec<Message>,
    poison: &mut Option<ClientError>,
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
                let ty =
                    FrameType::from_u8(type_tag).ok_or(ClientError::UnknownFrameType(type_tag))?;
                let body = body.to_vec();
                buf.drain(..consumed);
                return Ok((ty, body));
            }
            FrameDecode::Incomplete { .. } => {}
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
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
    stream: TcpStream,
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
    /// body identically to the sync client).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on a connection failure or an unexpected handshake reply.
    pub async fn connect_with<A: ToSocketAddrs>(
        addr: A,
        config: &ClientConfig,
    ) -> Result<AsyncClient, ClientError> {
        let stream = TcpStream::connect(addr).await?;
        let mut client = AsyncClient {
            stream,
            buf: Vec::new(),
            negotiated_credit: None,
            negotiated_credit_bytes: None,
            gap_marker_enabled: false,
            streaming_enabled: false,
            deliver_batch_enabled: false,
            streams_enabled: false,
            negotiated_default_tier: None,
            next_txn_seq: 0,
        };
        // The handshake: send a versioned Connect body carrying any requested credit and the
        // capability bits, then read the Info advertisement and adopt the negotiated state. Byte-for-byte
        // the sync client's `connect_with` body.
        let mut connect_body = Vec::new();
        encode_connect(
            &ConnectBody {
                requested_credit: config.requested_consumer_credit,
                requested_credit_bytes: config.requested_consumer_credit_bytes,
                wants_gap_marker: config.request_gap_marker,
                default_ack_level: config.default_ack_level.map(AckLevel::as_u8),
                understands_streaming: config.understands_streaming,
                default_tier: config.default_consume_tier.map(ConsumeTier::as_u8),
                understands_deliver_batch: config.understands_deliver_batch,
                understands_streams: config.understands_streams,
            },
            &mut connect_body,
        );
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
                Ok(client)
            }
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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

    /// Reads and decodes a batch delivery response (the shared tail of [`AsyncClient::fetch`]): a run of
    /// `Deliver` / `DeliverBatch` frames (transparently decompressed), with any interleaved
    /// `DeadLetter` / `Truncated` / `GapMarker` advisories, terminated by exactly one `FlowEnd` (or an
    /// `Err`). `limit` bounds the TOTAL frames so a buggy or hostile server cannot stream without bound.
    /// A verbatim port of the sync client's `read_fetch_response` with the reads awaited.
    async fn read_fetch_response(&mut self, limit: usize) -> Result<Fetch, ClientError> {
        let mut messages = Vec::new();
        let mut dead_letters = Vec::new();
        let mut truncations = Vec::new();
        let mut gaps = Vec::new();
        // The FIRST in-batch decompression failure, held until the terminating FlowEnd has been read so
        // the connection stays framed for the next request.
        let mut poison: Option<ClientError> = None;
        let mut frames = 0usize;
        loop {
            let (frame_type, body) = self.read_frame().await?;
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
                    ingest_delivery(&d, &mut messages, &mut poison);
                }
                // A raw-framed batch: ONE frame carrying a contiguous run of records as their ON-DISK
                // frame bytes. Decode the header, then each on-disk frame, reconstructing each offset
                // POSITIONALLY (first_offset + i) and feeding it through the SAME per-record path a
                // `Deliver` takes — byte-for-byte the sync client's DeliverBatch arm.
                (FrameType::DeliverBatch, body) => {
                    let (header, record_bytes) =
                        decode_deliver_batch(&body).map_err(ClientError::Body)?;
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
                        ingest_delivery(&d, &mut messages, &mut poison);
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
                (FrameType::DeadLetter, body) => {
                    let dl = decode_dead_letter(&body).map_err(ClientError::Body)?;
                    dead_letters.push(DeadLetter {
                        offset: dl.offset,
                        reason: dl.reason,
                    });
                }
                (FrameType::Truncated, body) => {
                    let t = decode_truncated(&body)?;
                    truncations.push(t);
                }
                (FrameType::GapMarker, body) => {
                    let g = decode_gap_marker(&body).map_err(ClientError::Body)?;
                    gaps.push(Gap {
                        from: g.from,
                        to: g.to,
                        bytes_skipped: g.bytes_skipped,
                        reason: g.reason,
                    });
                }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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

    /// Sends a keepalive ping and awaits the pong. The async port of [`ironbus_client::Client::ping`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or an unexpected reply.
    pub async fn ping(&mut self) -> Result<(), ClientError> {
        self.send(FrameType::Ping, &[]).await?;
        match self.read_frame().await? {
            (FrameType::Pong, _) => Ok(()),
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
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
