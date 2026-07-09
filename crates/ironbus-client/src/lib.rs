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
//!
//! # Example
//!
//! ```no_run
//! use ironbus_client::Client;
//! use ironbus_client::proto::PubBody;
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = Client::connect("127.0.0.1:7000")?;
//!
//! // Produce a record (durable on the returned ack).
//! let offset = client.produce(&PubBody {
//!     flags: 0,
//!     timestamp_ms: 0,
//!     key: b"key",
//!     headers: b"",
//!     dedup: None,
//!     fire_and_forget: false,
//!     payload: b"hello",
//! })?;
//! assert_eq!(offset, 0);
//!
//! // Subscribe to a work-group, fetch the record back, and ack each delivery by its lease.
//! client.subscribe("workers")?;
//! let fetched = client.fetch(10)?;
//! for message in &fetched.messages {
//!     client.ack(message.offset, message.generation)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! More runnable programs are in this crate's `examples/` directory (produce, consume, streaming
//! consumer, transactions, subjects, cluster not-leader, auth).

use ironbus_core::compress::{
    decompress_payload, DecompressError, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES,
};
use ironbus_core::types::RecordFlags;
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{
    decode_dead_letter, decode_deliver, decode_deliver_batch, decode_gap_marker, decode_info,
    decode_not_leader, decode_produce_confirm, decode_pub_ack, decode_stream_info_response,
    decode_truncated, decode_txn_resolve, encode_ack, encode_bind_subject, encode_connect,
    encode_cumulative_ack, encode_fetch, encode_pub, encode_pub_subject, encode_pub_to,
    encode_stream_commit, encode_stream_declare, encode_stream_fetch, encode_stream_info,
    encode_sub, encode_sub_subject, encode_sub_to, encode_txn_check_result, encode_txn_listen,
    encode_txn_prepare, encode_txn_resolve, produce_confirm_status, AckBody, AckLevel, AckOp,
    BindSubjectBody, BodyError, ConnectBody, ConsumeTier, CumulativeAckBody, DeliverBody,
    FetchBody, PubBody, PubSubjectBody, PubToBody, StreamCommitBody, StreamDeclareBody,
    StreamFetchBody, StreamInfoBody, SubBody, SubSubjectBody, SubToBody, TxnCheckDecision,
    TxnCheckResultBody, TxnListenBody, TxnPrepareBody, TxnResolveBody, PUB_FLAG_ACK_LEVEL_MASK,
    PUB_FLAG_ACK_LEVEL_SHIFT,
};
// The connection-scoped auth wire surface (#631, #884): the credential type and the encoder that
// appends the auth section to an already-encoded `Connect` body. Re-exported below so a caller can
// construct a `ClientConfig::credential` without depending on `ironbus-proto` directly.
use ironbus_proto::message::append_connect_auth;
#[doc(no_inline)]
pub use ironbus_proto::message::{pack_password_material, AuthCredential, AuthMechanism};

/// The wire body/enum types a caller constructs to drive the client (`PubBody` to produce, the
/// `AckLevel` / `ConsumeTier` selectors, `PubDedup` for idempotent produce), re-exported so a caller
/// need not depend on `ironbus-proto` directly. Mirrors the `ironbus-client-async` crate's `proto`
/// module so the sync and async clients share one import surface. The RETURNED data types ([`Message`], [`Fetch`],
/// [`ProduceAck`], …) are defined in this crate, not here.
pub mod proto {
    pub use ironbus_proto::message::{AckLevel, ConsumeTier, PubBody, PubDedup};
}

// Client-side TLS 1.3 (ADR-0004 / #766, client side #957) — compiled only under `--features tls`. The
// default client links no TLS code and stays byte-for-byte plain-TCP.
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
pub use tls::{TlsClientConfig, TlsClientError};

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The smallest per-read scratch size. Reading at least this many bytes even when the decoder
/// asks for fewer preserves the small-frame batching the client has always relied on: one socket
/// read can pull several tiny frames (e.g. a released `PubAck` flushed alongside a `Pong`), so the
/// trailing frames stay buffered rather than forcing a read apiece. Matches the historical fixed
/// 4 KiB read chunk.
const READ_WINDOW: usize = 4096;

/// The largest per-read scratch size. Bounds the reused scratch buffer so a large frame (a ~16 MiB
/// `DeliverBatch`) is assembled in ~64 capped reads rather than one giant allocation, while the
/// decoder's `needed` hint still lets a single read pull as much of the frame as the socket has.
const READ_CAP: usize = 256 * 1024;

/// How many bytes to read next while completing a frame, given the decoder's `needed` total-length
/// hint and how many valid bytes are already buffered (`filled`). Sizes the read to the outstanding
/// deficit, clamped into `[READ_WINDOW, READ_CAP]`: never smaller than the batching window, never
/// larger than the scratch cap. Reading past `needed` (when the deficit is under the window) is
/// harmless — the extra bytes belong to following frames and stay buffered.
fn frame_read_size(needed: usize, filled: usize) -> usize {
    needed.saturating_sub(filled).clamp(READ_WINDOW, READ_CAP)
}

/// An error from the client.
#[derive(Debug)]
pub enum ClientError {
    /// An underlying IO or connection error (including a timeout).
    Io(io::Error),
    /// A malformed frame from the server (the connection cannot continue).
    Frame(FrameError),
    /// A malformed message body from the server.
    Body(BodyError),
    /// The server replied with an error: the human message it sent, PLUS the stable
    /// machine-readable [`ServerErrorCode`] the broker tagged it with when one applies (#883), so a
    /// caller branches on [`ServerError::code`] (retry-vs-fail, backpressure-vs-permanent-reject)
    /// instead of substring-matching prose the broker is free to reword. The code is `None` for an
    /// uncoded rejection (a malformed-body literal, the uniform auth violation, or a code this build
    /// predates); the human message is always present.
    Server(ServerError),
    /// The server replied with an unexpected (but known) frame type for the request.
    Unexpected(FrameType),
    /// The server sent a frame whose type tag this client does not recognize.
    UnknownFrameType(u8),
    /// The response had the expected type but a malformed shape for the request.
    BadResponse(&'static str),
    /// The producer's LOCAL transaction failed inside [`Client::transact`] (#640 part 2): the half
    /// message was ROLLED BACK (discarded, never delivered) and the local transaction's error message is
    /// carried here. The broker side is consistent (the half message is gone); this surfaces the local
    /// failure to the caller after the clean rollback.
    LocalTransaction(String),
    /// The connection closed before a complete response arrived.
    Closed,
    /// A client-side TLS configuration or handshake failure (#957, `--features tls`): a bad trust
    /// anchor / client certificate, an invalid server name, or the broker's certificate failing
    /// verification. (A verification failure at the handshake itself surfaces as [`ClientError::Io`].)
    #[cfg(feature = "tls")]
    Tls(String),
    /// The server REDIRECTED a produce: the node this client is connected to holds a clustered replica
    /// role for the target partition but is NOT its current leader (#735), so the produce was NOT
    /// appended/acked here — it must go to the leader. `leader_hint` is the current leader's CLIENT
    /// address when the server knew it (`Some`), or `None` (mid-failover, or no advertised client address),
    /// in which case the caller re-discovers the leader from its own known peers. A RECOVERABLE error: the
    /// connection stays usable (the client can keep producing once it reconnects to the leader); see
    /// [`Client::produce_to_leader`] for the transparent reconnect/retry helper.
    NotLeader {
        /// The current leader's CLIENT address to reconnect to, or `None` when the server did not know it.
        leader_hint: Option<String>,
    },
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
            ClientError::LocalTransaction(m) => {
                write!(
                    f,
                    "local transaction failed (half message rolled back): {m}"
                )
            }
            ClientError::Closed => write!(f, "connection closed mid-response"),
            #[cfg(feature = "tls")]
            ClientError::Tls(why) => write!(f, "client TLS error: {why}"),
            ClientError::Decompress { source, offset, .. } => {
                write!(
                    f,
                    "delivered payload at offset {offset} failed decompression: {source}"
                )
            }
            ClientError::NotLeader { leader_hint } => match leader_hint {
                Some(addr) => write!(f, "not leader: produce to the leader at {addr}"),
                None => write!(f, "not leader: the current leader is unknown"),
            },
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Io(e) => Some(e),
            ClientError::Frame(e) => Some(e),
            ClientError::Body(e) => Some(e),
            ClientError::Decompress { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// The stable, machine-readable server rejection code (#883, #35), re-exported from `ironbus-proto`.
#[doc(no_inline)]
pub use ironbus_proto::err::ServerErrorCode;

/// A server rejection: the stable machine-readable [`ServerErrorCode`] the broker tagged it with (when
/// one applies), plus the human message it sent (#883). Carried by [`ClientError::Server`].
///
/// Branch on [`ServerError::code`] for control flow (retry-vs-fail, backpressure-vs-permanent-reject)
/// — e.g. `Some(ServerErrorCode::AtCapacity)` is a benign, retryable drop-new shed, distinct from a
/// permanent reject — and use the message for display only. `code` is `None` for an uncoded rejection
/// (a malformed-body literal, the uniform anti-enumeration auth violation, or a newer code this build
/// predates); the human message is always present.
///
/// The type dereferences to its message `str`, so an older caller that substring-matched the message
/// keeps compiling and working unchanged while it migrates to the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerError {
    /// The stable code the broker tagged this rejection with, or `None` when uncoded / unrecognized.
    pub code: Option<ServerErrorCode>,
    /// The human-readable message, for display.
    pub message: String,
}

impl ServerError {
    /// Decodes a wire `Err` frame body into its optional code and human message (#883).
    #[must_use]
    pub fn from_wire(body: &[u8]) -> ServerError {
        let decoded = ironbus_proto::err::decode_err_body(body);
        ServerError {
            code: decoded.code,
            message: decoded.message.into_owned(),
        }
    }

    /// An uncoded rejection carrying only a human message (a client-synthesized error, e.g. a
    /// `NotLeader` summary), with no stable code.
    #[must_use]
    pub fn uncoded(message: String) -> ServerError {
        ServerError {
            code: None,
            message,
        }
    }

    /// The stable machine-readable code the broker tagged this rejection with, or `None` when uncoded.
    #[must_use]
    pub fn code(&self) -> Option<ServerErrorCode> {
        self.code
    }

    /// The human-readable message, for display.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for ServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::ops::Deref for ServerError {
    type Target = str;
    fn deref(&self) -> &str {
        &self.message
    }
}

impl PartialEq<&str> for ServerError {
    fn eq(&self, other: &&str) -> bool {
        self.message == *other
    }
}

impl PartialEq<str> for ServerError {
    fn eq(&self, other: &str) -> bool {
        self.message == other
    }
}

impl PartialEq<String> for ServerError {
    fn eq(&self, other: &String) -> bool {
        &self.message == other
    }
}

impl From<String> for ServerError {
    fn from(message: String) -> ServerError {
        ServerError::uncoded(message)
    }
}

impl From<&str> for ServerError {
    fn from(message: &str) -> ServerError {
        ServerError::uncoded(message.to_string())
    }
}

/// Connection tunables: the timeouts that bound every blocking call.
///
/// The defaults are conservative but finite, so a misbehaving broker fails the call instead
/// of hanging the caller indefinitely. Set a field to `None` to block forever on that
/// operation (the pre-timeout behavior), which is rarely what you want.
// Each bool advertises a DISTINCT wire CAPABILITY this client understands (gap-marker / streaming /
// deliver-batch / streams, #346/#543/#541/#588), mapped one-to-one to a `Connect` handshake bit — a
// documented protocol surface, not internal state a bitfield could replace.
#[allow(clippy::struct_excessive_bools)]
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
    /// The connection-wide DEFAULT produce ack level this client REQUESTS in its `Connect` handshake
    /// body (#494, #496), or `None` to defer to the server default. When `Some(level)`, `connect_with`
    /// sends the raw level value (see [`AckLevel::as_u8`]) in the `Connect` body so the connection's
    /// default is negotiated; a publish that does not name its own level then adopts this default
    /// server-side. `None` (the default, backward-compatible) sends no default, so the body is
    /// byte-for-byte the pre-#494 `Connect` and the server applies its own default. The server echoes
    /// the adopted default in `Info` once that path lands (#497); until then a `Some` request is sent
    /// and decoded by the server but not yet echoed back.
    pub default_ack_level: Option<AckLevel>,
    /// Whether this client ADVERTISES that it understands the streaming consume tier (Tier-S, #543,
    /// V2-M1): when `true`, the `Connect` sets the [`CONNECT_FLAG_UNDERSTANDS_STREAMING`] capability
    /// bit, so the server may serve this connection at Tier-S and honor a Tier-S `default_consume_tier`.
    /// When `false` (the default, backward-compatible) the client does not advertise it and is ALWAYS
    /// served Tier-W — byte-for-byte today's behavior — and any Tier-S default it set is ignored. A
    /// caller checks [`Client::streaming_enabled`] after connecting to learn whether the server
    /// confirmed it.
    pub understands_streaming: bool,
    /// The connection-wide DEFAULT consume tier this client REQUESTS in its `Connect` handshake body
    /// (#543, V2-M1), or `None` to defer to the server default (Tier-W). When `Some(tier)`,
    /// `connect_with` sends the raw tier value (see [`ConsumeTier::as_u8`]) so a subscription that does
    /// not pick its own tier adopts this default server-side. Only HONORED when `understands_streaming`
    /// is also `true`; a Tier-S default without the capability is ignored. `None` (the default,
    /// backward-compatible) sends no default tier, so the body carries no tier byte and the server
    /// applies Tier-W.
    pub default_consume_tier: Option<ConsumeTier>,
    /// Whether this client ADVERTISES that it understands the raw-framed `DeliverBatch` frame (tag 26,
    /// #541, M1-I5): when `true`, the `Connect` sets the [`CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH`]
    /// capability bit, so the server MAY deliver a contiguous Tier-S run as ONE `DeliverBatch` (the
    /// records' on-disk frame bytes, which this client decodes locally) instead of N per-record
    /// `Deliver` frames. When `false` (the default, backward-compatible) the client does not advertise
    /// it and ALWAYS receives per-record `Deliver` frames — byte-for-byte today's behavior. A caller
    /// checks [`Client::deliver_batch_enabled`] after connecting to learn whether the server confirmed
    /// it. The decoded `Message`s are IDENTICAL either way; this only changes the wire framing.
    pub understands_deliver_batch: bool,
    /// Whether this client ADVERTISES that it understands the stream-addressed wire verbs
    /// (`StreamDeclare`/`StreamInfo`/`PubTo`/`SubTo`, tags 28-31, #588, V2-M2-I10): when `true`, the
    /// `Connect` sets the [`CONNECT_FLAG_UNDERSTANDS_STREAMS`] capability bit, so the server confirms it
    /// in `Info` and the client may declare / publish-to / subscribe-to NAMED streams by id
    /// ([`Client::declare_stream`] / [`Client::publish_to`] / [`Client::subscribe_to`]). When `false`
    /// (the default, backward-compatible) the client uses only the default-stream verbs — byte-for-byte
    /// today's behavior. A caller checks [`Client::streams_enabled`] after connecting to learn whether
    /// the server confirmed it.
    pub understands_streams: bool,
    /// Whether this client ADVERTISES that it can DECODE a compression-codec-encoded delivery — the
    /// per-record `COMPRESSED` flag and `descriptor + codec-stream` payload a `--compression` broker
    /// stores (#1066): when `true` (the DEFAULT), the `Connect` sets the
    /// [`CONNECT_FLAG2_COMPRESSED_DELIVERY`] capability bit, so a `--compression lz4` broker ships
    /// stored-compressed records to this client verbatim (which it decodes on read, as every client has
    /// since #430). When `false`, the client does NOT advertise it, so the broker DECOMPRESSES a
    /// stored-compressed record before delivering it — the plain payload, byte-for-byte the produced
    /// bytes. The default is `true` because this client decodes compression; a caller that wraps a
    /// legacy consumer which cannot decode the descriptor bytes sets it `false` to force uncompressed
    /// delivery. The decoded `Message` payload is IDENTICAL either way; this only governs whether the
    /// bytes travel compressed on the wire.
    pub understands_compressed_delivery: bool,
    /// The connection-scoped authentication credential this client presents in its `Connect`
    /// handshake (#631, #884), or `None` (the default) for an unauthenticated connection. When
    /// `Some(cred)`, `connect_with` appends the auth section the broker verifies (via
    /// [`append_connect_auth`], the exact wire the server parses with `parse_connect_auth`) to the
    /// `Connect` body after the v1 fields, so a client can talk to an AUTH-REQUIRED broker (bearer
    /// token or username+password; build a `Password` credential's material with
    /// [`pack_password_material`]). When `None` (the default, backward-compatible) NO auth section is
    /// appended and the body is byte-for-byte the pre-#631 `Connect`, so an unauthenticated connect to
    /// a no-auth broker is unchanged.
    ///
    /// This field DOES NOT log its secret: [`AuthCredential`]'s `Debug` redacts the credential
    /// material (#882), so a `{:?}` of a `ClientConfig` — directly or transitively through any
    /// embedding type — prints the mechanism and material LENGTH only, never the token/password bytes.
    ///
    /// NOTE (#884 scope): TLS is a SEPARATE follow-up. The bearer-token mechanism's threat model wants
    /// the token presented inside an established TLS session on a non-loopback bind; this client is
    /// still plain TCP, so a bearer/password credential is safe to use over loopback or an already-
    /// secured transport, and a TLS-wrapped stream (and the `Mtls` mechanism) is deferred.
    pub credential: Option<AuthCredential>,

    /// The client TLS configuration (ADR-0004 / #957), or `None` for a plaintext connection. When
    /// `Some`, [`Client::connect_with`] VERIFIES the broker's certificate and connects INSIDE a TLS 1.3
    /// session, so the `credential` above travels ENCRYPTED (and a configured client certificate
    /// authenticates the connection as mTLS). Mandatory server verification — a broker whose
    /// certificate does not verify fails the connect, never a silent fallback to plaintext. Present
    /// only behind `--features tls`; the default (plain-TCP) build has no TLS and this field is absent.
    #[cfg(feature = "tls")]
    pub tls: Option<TlsClientConfig>,
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
            // None by default: an unconfigured client requests no connection-wide default ack level, so
            // it sends a byte-for-byte pre-#494 `Connect` body and the server applies its own default
            // (#494, #496). A caller opts into a connection default by setting this.
            default_ack_level: None,
            // Off by default: an unconfigured client does not advertise streaming support, so it is
            // always served Tier-W exactly as before (#543). A caller that wants the streaming tier
            // opts in by setting this (and typically a Tier-S `default_consume_tier`).
            understands_streaming: false,
            // None by default: an unconfigured client requests no connection-wide default consume tier,
            // so it sends no tier byte and the server applies Tier-W (#543). A caller opts into a
            // connection default by setting this AND `understands_streaming`.
            default_consume_tier: None,
            // Off by default: an unconfigured client does not advertise DeliverBatch support, so it
            // always receives per-record `Deliver` frames exactly as before (#541). A caller opts into
            // the raw-framed batch path by setting this (typically alongside `understands_streaming`).
            understands_deliver_batch: false,
            // Off by default: an unconfigured client does not advertise stream addressing, so it uses
            // only the default-stream verbs exactly as before (#588). A caller that wants to address
            // named streams opts in by setting this.
            understands_streams: false,
            // ON by default (#1066): this client decodes compression (every client has since #430), so
            // it advertises the capability and a `--compression` broker may ship it stored-compressed
            // records verbatim. This is safe by construction and preserves the broker's zero-CPU
            // passthrough. A caller wrapping a legacy consumer that cannot decode the descriptor sets it
            // `false` to force the broker to decompress before delivery (the silent-corruption guard).
            understands_compressed_delivery: true,
            // None by default: an unconfigured client presents NO credential, so `connect_with`
            // appends no auth section and the `Connect` body is byte-for-byte the pre-#631 layout — an
            // unauthenticated connect to a no-auth broker is unchanged (#884). A caller opts into auth
            // by setting this to the credential the broker verifies.
            credential: None,
            // None by default: an unconfigured client is plain TCP (byte-for-byte the pre-#957 path). A
            // caller opts into TLS by setting this to a `TlsClientConfig` (#957, `--features tls`).
            #[cfg(feature = "tls")]
            tls: None,
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

/// The terminal outcome of a Level-2 (server+client-ack) produce confirmation (#497), returned by
/// [`Client::produce_confirmed`]. The record was ALREADY made durable (the durability `PubAck` arrived
/// before the wait began, I2); this is the SECOND ack, reporting what became of it CONSUMER-side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// A consumer in the broker's designated group ACKED the record: the Level-2 produce is fully
    /// confirmed (durable AND consumed), the success terminal.
    Consumed,
    /// No consumer acked the record within the broker's confirm window, so the broker timed the
    /// confirmation out: it will never arrive. The record stayed durable (its `PubAck` was returned),
    /// but its consumption is unconfirmed.
    TimedOut,
    /// The record was dead-lettered (poison / force-reaped) or the broker's bounded confirm registry
    /// dropped the pending confirmation before any consumer acked it: the consumed confirmation can
    /// never be satisfied. The record stayed durable; only its consumed-confirmation is lost.
    DeadLettered,
    /// The CLIENT-side wait elapsed before any terminal `ProduceConfirm` arrived (distinct from the
    /// BROKER-side `TimedOut`: this is the local deadline the caller passed expiring). The record is
    /// durable; the caller may keep using the connection and a later confirmation, if any, will arrive
    /// on a subsequent pass. Carries the durable offset so the caller can correlate or re-await.
    LocalTimeout,
    /// The broker sent a confirmation `status` byte this client build does not recognize (a forward-
    /// compatible future status). The record is durable; the specific consumer-side outcome is unknown
    /// to this build. Carries the raw status byte.
    Unknown(u8),
}

/// A Level-2 produce confirmation (#497): the durable `offset` (the same one the durability `PubAck`
/// returned) plus its terminal [`ConfirmOutcome`]. Returned by [`Client::produce_confirmed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProduceConfirmation {
    /// The durable offset the confirmation is keyed to.
    pub offset: u64,
    /// What became of the record consumer-side (consumed / timed-out / dead-lettered / local-timeout).
    pub outcome: ConfirmOutcome,
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
#[derive(Debug)]
enum PubReply {
    Acked(u64),
    Duplicate(u64),
    ServerErr(ServerError),
    Pong,
    /// A cluster `NotLeader` redirect (#735): the produce landed on a non-leader replica of the
    /// partition and was NOT appended/acked; the leader's CLIENT-address hint (or `None` when unknown).
    NotLeader(Option<String>),
}

/// One coalesced write's byte budget for [`Client::produce_stream`] (#458): large enough to
/// amortize the syscall, small enough that the first acks stream back while later frames are
/// still being written.
const STREAM_FLUSH_BYTES: usize = 32 * 1024;

/// The default in-flight window for [`Client::pipelined_producer`] (#508): how many publishes the
/// auto-pipelining handle buffers and sends before awaiting acks, so a SINGLE producer keeps that
/// many produces in flight and the broker's group commit collapses them under one `fdatasync`
/// instead of one per publish. Chosen small enough that the buffered (not-yet-flushed) tail a
/// [`PipelinedProducer::flush`] / [`PipelinedProducer::finish`] makes durable is bounded and the
/// per-flush memory is modest, yet large enough to lift a tight single-producer durable loop well
/// past the one-fsync-per-publish floor of the awaited [`Client::produce`]. The handle's window is
/// configurable via [`Client::pipelined_producer_with_window`] for a caller that wants a different
/// latency/throughput trade.
pub const DEFAULT_PIPELINE_WINDOW: usize = 64;

/// The default streaming-consumer fetch window (Tier-S, #550): the `max_records` a
/// [`StreamingConsumer`]'s [`StreamingConsumer::next_batch`] pulls per `StreamFetch`. 2048, not
/// 256 (#1027): at 256 a tight drain loop is round-trip-latency-bound (~700 fetch RTTs/s of
/// ~1.4 ms each drained 128 B records at ~180k msg/s on the baseline rig, even with read-ahead),
/// while 2048 reaches the ~1M rec/s per-record plateau there (969k-1217k msg/s at 128 B; 8192
/// measured 931k, no further gain). 2048 is PEER-COMPARABLE consumer sizing (a stock Kafka
/// consumer fetches ~50 MB / 500+ records per poll) and exactly the broker's default per-consumer
/// credit ceiling, which the actual pull is capped at anyway (the negotiated credit, #292), so the
/// default never over-asks a default broker. Configurable via
/// [`StreamConsumerConfig::max_records`].
pub const DEFAULT_STREAM_FETCH_RECORDS: u32 = 2048;

/// The default periodic-commit cadence (Tier-S, #550): a [`StreamingConsumer`] auto-commits its
/// cumulative offset once every this-many fetched windows (and always when the stream drains or the
/// handle finishes). Commit cadence is the at-least-once knob — a larger cadence amortizes the commit
/// across more windows (cheaper) at the cost of a larger redeliver-on-crash span; `1` commits after
/// every window. Configurable via [`StreamConsumerConfig::commit_every_batches`].
pub const DEFAULT_STREAM_COMMIT_EVERY_BATCHES: u32 = 8;

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
    first_server_err: Option<ServerError>,
    /// The reader hit a fatal error and exited; the writer must stop waiting on it.
    reader_dead: bool,
}

/// The reader half of [`Client::produce_stream`] (#458): drains produce replies into `flow`
/// (notifying `room` as slots free) until the terminal `Pong` or a fatal error. Runs on the
/// scoped reader thread over the cloned read half.
fn drain_stream_replies(
    stream: &mut impl Read,
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
            // A cluster NotLeader redirect (#735) mid-stream: this node is not the leader, so these
            // streamed produces did NOT land. Surface it like a server error (the first one is reported),
            // so the caller learns the stream went to the wrong node and re-streams to the leader. Counted
            // as done so the writer's window does not stall waiting on a reply that will never ack.
            PubReply::NotLeader(hint) => {
                f.done += 1;
                f.server_errors += 1;
                if f.first_server_err.is_none() {
                    f.first_server_err = Some(ServerError::uncoded(match hint {
                        Some(addr) => format!("not leader: produce to the leader at {addr}"),
                        None => "not leader: the current leader is unknown".to_string(),
                    }));
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

/// Writes the CANONICAL [`PUB_FLAG_ACK_LEVEL_MASK`] field value for an AT-LEAST-ONCE `level` (Level 1
/// or Level 2) into `flags`, clearing any ack-level bits the caller already set, and returns the
/// result (#494, #496). Only the 2-bit ack-level field is touched; every other flag bit (the real
/// record flags, the dedup bit, the faf bit) is left exactly as the caller set it.
///
/// The written field value is NOT [`AckLevel::as_u8`] for Level 1: [`pub_ack_level`](ironbus_proto::message::pub_ack_level)
/// decodes the raw field value `1` as Level 0 (it is the level-bit ALIAS for fire-and-forget), so the
/// CANONICAL Level-1 encoding is the field value `0` (which is also exactly how a pre-feature client
/// encodes a default produce, so `flags == 0` is Level 1). Level 2 writes the field value `2`. Level 0
/// is NOT encoded here at all (it rides the canonical fire-and-forget bit via `produce_fire_and_forget`);
/// passing it is a logic error this never receives, so it is treated as the safe Level-1 default
/// (field `0`).
fn with_ack_level_bits(flags: u8, level: AckLevel) -> u8 {
    let field = match level {
        // The canonical Level-1 encoding is field 0 (a raw `1` would decode as Level 0), matching how a
        // pre-feature default produce encodes; Level 0 should never reach here, default it to Level 1.
        AckLevel::ServerAck | AckLevel::NoAck => 0,
        AckLevel::ServerAndClientAck => 2,
    };
    let bits = (field << PUB_FLAG_ACK_LEVEL_SHIFT) & PUB_FLAG_ACK_LEVEL_MASK;
    (flags & !PUB_FLAG_ACK_LEVEL_MASK) | bits
}

/// The AGGREGATE materialized-payload-bytes ceiling for ONE fetch window (#879): the running sum of
/// decompressed/raw payload bytes a single `fetch`/`fetch_batch` may push into its `messages` Vec before
/// it fails closed with [`ClientError::BadResponse`]. The per-record decompression cap
/// (`DEFAULT_MAX_DECOMPRESSED_BYTES`, 8 MiB) bounds ONE record; this bounds the WHOLE window, so a
/// credit-bounded fetch of many tiny high-ratio frames cannot materialize `credit x 8 MiB` resident.
/// 256 MiB = 32 max-size records, generous for a legitimate batch yet far below a multi-GiB OOM.
const MAX_FETCH_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// Ingests one decoded delivery (`d`) into the fetch result, applying the SAME transparent broker-side
/// decompression (#430) the per-record path does and pushing the resulting [`Message`] onto `messages`
/// — UNLESS a prior decompression failure already poisoned the batch (`poison.is_some()`), in which case
/// the delivery is consumed and dropped un-acked (the broker redelivers it). Shared by the per-record
/// `Deliver` arm and the `DeliverBatch` arm (#541) so a batched delivery yields byte-for-byte the same
/// `Message` an equivalent per-record `Deliver` would. The FIRST decompression failure is recorded in
/// `poison` (carrying the record's offset/generation so the caller can ack/nack-skip it); the rest of
/// the batch is still drained before the error surfaces.
///
/// `decompressed_bytes` is the running total of materialized payload bytes for the whole fetch window;
/// once it would exceed `max_aggregate` ([`MAX_FETCH_DECOMPRESSED_BYTES`]) the batch is poisoned with a
/// [`ClientError::BadResponse`] (#879), so a credit-bounded fetch of a tiny wire response can never
/// expand to credit x the per-record cap of resident RAM.
fn ingest_delivery(
    d: &DeliverBody<'_>,
    messages: &mut Vec<Message>,
    poison: &mut Option<ClientError>,
    decompressed_bytes: &mut usize,
    max_aggregate: usize,
) {
    // Draining after a decompression failure: the frame is consumed (keeping the connection framed) but
    // the delivery is dropped un-acked, so the broker redelivers it after its visibility timeout.
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
            // The poison record's offset and lease generation travel with the error, so the caller can
            // ack/nack-skip it; the rest of the batch is drained before the error is returned.
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
    // #879: bound the AGGREGATE materialized payload bytes for this fetch window, not just the
    // per-record 8 MiB decompression cap. A producer can pre-store many high-ratio records that each
    // claim ~the per-record cap but are a few wire bytes, so a credit-bounded fetch of a tiny wire
    // response could otherwise materialize credit x 8 MiB resident in `messages` (an OOM the per-record
    // cap does not prevent). Charge the just-decoded payload and fail closed once the running total
    // crosses the ceiling; like a per-record decompression failure, the remaining frames are drained
    // (poison set) so the connection stays framed, then the error is returned.
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

/// Maps a wire `ProduceConfirm` status byte (#497) to a client [`ConfirmOutcome`]. An unknown future
/// status decodes to [`ConfirmOutcome::Unknown`] (forward-compatible: the codec already tolerated it),
/// never an error.
fn confirm_outcome(status: u8) -> ConfirmOutcome {
    match status {
        produce_confirm_status::CONSUMED => ConfirmOutcome::Consumed,
        produce_confirm_status::TIMED_OUT => ConfirmOutcome::TimedOut,
        produce_confirm_status::DEAD_LETTERED => ConfirmOutcome::DeadLettered,
        other => ConfirmOutcome::Unknown(other),
    }
}

/// Decode a `NotLeader` redirect body (#735) into the typed [`ClientError::NotLeader`] with the leader
/// hint (an empty hint -> `None`). A malformed body falls back to a `None` hint rather than a parse error,
/// so a redirect is always actionable (the client re-tries its known peers).
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

/// Reads one whole frame from `stream`, buffering partial bytes in `buf`. The free-function
/// form of [`Client::read_frame`] so [`Client::produce_stream`]'s reader thread can drain a
/// cloned read half with its own buffer (#458).
fn read_frame_from(
    stream: &mut impl Read,
    buf: &mut Vec<u8>,
) -> Result<(FrameType, Vec<u8>), ClientError> {
    // Reused scratch for each socket read. `buf` is mutated ONLY by `extend_from_slice` AFTER a read
    // has successfully returned bytes, so `buf.len()` is always exactly the count of valid buffered
    // bytes: a propagated read error (via `?`) leaves `buf` untouched, never polluting it with
    // placeholder bytes that a retry would misdecode.
    let mut scratch: Vec<u8> = Vec::new();
    loop {
        let needed = match decode_frame(buf).map_err(ClientError::Frame)? {
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
            FrameDecode::Incomplete { needed } => needed,
        };
        let read_size = frame_read_size(needed, buf.len());
        if scratch.len() < read_size {
            scratch.resize(read_size, 0);
        }
        let n = stream.read(&mut scratch[..read_size])?;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        buf.extend_from_slice(&scratch[..n]);
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
    /// The first server rejection, carrying the stable [`ServerErrorCode`] (#883) so a caller can
    /// distinguish a benign shed (`Some(ServerErrorCode::AtCapacity)` under `drop-new`) from a real
    /// rejection by branching on [`ServerError::code`] rather than substring-matching the message. The
    /// human message is still available (the type dereferences to it) for display.
    pub first_server_error: Option<ServerError>,
    /// The offset carried by the last ack observed, if any message was acked.
    pub last_offset: Option<u64>,
}

/// A transaction id minted by [`Client::prepare`] (or supplied via [`Client::prepare_with_id`]) for
/// the transactional half-message 2PC (#640, V2-M8). It names the prepared half message for a later
/// [`Client::commit`] / [`Client::rollback`]. It is an opaque byte string (a UUID, a snowflake, or the
/// client's `addr+counter` default); the producer keeps it across its local transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxnId(Vec<u8>);

impl TxnId {
    /// Wraps an explicit producer-supplied transaction id (a UUID, a snowflake, a content hash). The
    /// id must be non-empty and at most 256 bytes (the wire cap); the server rejects an over-long id.
    #[must_use]
    pub fn new(id: impl Into<Vec<u8>>) -> TxnId {
        TxnId(id.into())
    }

    /// The transaction id bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A producer's transaction-state listener's answer to a broker back-check (#640 part 2): the
/// resolution the broker should apply to an in-doubt half message. Returned by the `check_transaction`
/// callback a producer passes to [`Client::transact`] / [`Client::register_transaction_listener`]. The
/// client-facing mirror of the wire [`TxnCheckDecision`] (the proto type), so a caller never depends on
/// the proto crate directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnDecision {
    /// The producer's local transaction COMMITTED: the broker should commit the half message (it
    /// becomes visible), exactly once, via the part-1 path.
    Commit,
    /// The producer's local transaction ROLLED BACK (or never committed): the broker should discard the
    /// half message (never delivered).
    Rollback,
    /// The producer CANNOT decide yet (its local state is still in-doubt): the broker reschedules a
    /// later back-check and, after the bounded attempt cap, applies the SAFE terminal default
    /// (rollback/discard).
    Unknown,
}

impl TxnDecision {
    /// Maps to the wire [`TxnCheckDecision`].
    fn to_wire(self) -> TxnCheckDecision {
        match self {
            TxnDecision::Commit => TxnCheckDecision::Commit,
            TxnDecision::Rollback => TxnCheckDecision::Rollback,
            TxnDecision::Unknown => TxnCheckDecision::Unknown,
        }
    }
}

/// A connected IronBus client over one TCP connection.
// Each bool records a DISTINCT server-CONFIRMED wire capability for this connection (gap-marker /
// streaming / deliver-batch / streams), each set from its `Info` echo bit — protocol negotiation
// state, not internal flags a bitfield could replace.
/// The client's per-connection byte stream: plaintext TCP, or — behind `--features tls` (#957) — a
/// rustls-terminated TCP carrying a completed TLS 1.3 session. `Read`/`Write` flow through the
/// (possibly TLS) layer; the lifecycle shims (`try_clone`, `shutdown`) reach the underlying socket.
enum Wire {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
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
    /// The underlying accepted TCP socket, for the socket-level lifecycle operations.
    fn socket(&self) -> &TcpStream {
        match self {
            Wire::Plain(s) => s,
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.get_ref(),
        }
    }

    /// Clone the stream so a reader thread can drain replies while the main thread writes (the
    /// pipelined `produce_stream`/`produce_window` fan-out). A plaintext socket clones fine; a TLS
    /// session is single-owner and CANNOT be split across threads, so this returns `Unsupported` for a
    /// TLS wire — pipelined produce over TLS is a documented follow-up (use `produce()` over TLS, or a
    /// plaintext connection for pipelined produce).
    fn try_clone(&self) -> io::Result<Wire> {
        match self {
            Wire::Plain(s) => Ok(Wire::Plain(s.try_clone()?)),
            #[cfg(feature = "tls")]
            Wire::Tls(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pipelined produce (produce_stream / produce_window) is not supported over TLS: a TLS \
                 session cannot be split across threads. Use produce() over TLS, or a plaintext \
                 connection for pipelined produce.",
            )),
        }
    }

    /// Shut down the connection in `how` direction(s) on the underlying socket.
    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.socket().shutdown(how)
    }

    /// The local socket address (a stable per-connection seed for transaction ids).
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.socket().local_addr()
    }

    /// Read back the `TCP_NODELAY` state of the underlying socket (used by a test).
    #[cfg(test)]
    fn nodelay(&self) -> io::Result<bool> {
        self.socket().nodelay()
    }

    /// Establish a TLS 1.3 client session over an already-connected socket (#957): VERIFY the broker's
    /// certificate against the configured trust anchor (mandatory — a verification failure returns an
    /// error, never a silent fallback to plaintext), complete the handshake, and wrap.
    #[cfg(feature = "tls")]
    fn connect_tls(mut socket: TcpStream, config: &TlsClientConfig) -> Result<Wire, ClientError> {
        let client_config = config
            .build()
            .map_err(|e| ClientError::Tls(e.to_string()))?;
        let server_name = rustls::pki_types::ServerName::try_from(config.server_name().to_string())
            .map_err(|_| {
                ClientError::Tls(format!("invalid server name `{}`", config.server_name()))
            })?;
        let mut conn =
            rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name)
                .map_err(|e| ClientError::Tls(e.to_string()))?;
        // Drive the TLS 1.3 handshake to completion (blocking). A certificate that does not verify, or a
        // server name mismatch, fails HERE and returns the error — before any Connect frame is sent.
        conn.complete_io(&mut socket).map_err(ClientError::Io)?;
        Ok(Wire::Tls(Box::new(rustls::StreamOwned::new(conn, socket))))
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Wire::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Wire::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Wire::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.flush(),
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct Client {
    stream: Wire,
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
    /// Whether the streaming consume tier (Tier-S) is ACTIVE on this connection (#543, V2-M1): `true`
    /// only when this client advertised it ([`ClientConfig::understands_streaming`]) AND the server
    /// confirmed it in `Info`. When `false` (an old server, or the client did not advertise), this
    /// connection is only ever served Tier-W.
    streaming_enabled: bool,
    /// Whether the raw-framed `DeliverBatch` frame (tag 26) is ACTIVE on this connection (#541, M1-I5):
    /// `true` only when this client advertised it ([`ClientConfig::understands_deliver_batch`]) AND the
    /// server confirmed it in `Info`. When `true`, a contiguous Tier-S run may arrive as ONE
    /// `DeliverBatch` (decoded locally into the same `Message`s); when `false` (an old server, or the
    /// client did not advertise), every delivery is a per-record `Deliver`.
    deliver_batch_enabled: bool,
    /// Whether the stream-addressed wire verbs (`StreamDeclare`/`StreamInfo`/`PubTo`/`SubTo`, tags
    /// 28-31) are ACTIVE on this connection (#588, V2-M2-I10): `true` only when this client advertised
    /// it ([`ClientConfig::understands_streams`]) AND the server confirmed it in `Info`. When `false`
    /// (an old server, or the client did not advertise), the client may use only the default-stream
    /// verbs.
    streams_enabled: bool,
    /// The connection-wide DEFAULT consume tier the SERVER adopted for this connection (#543, V2-M1),
    /// echoed in `Info`, or `None` if the server did not echo one (an old server, or it defaulted to
    /// Tier-W). A subscription that does not pick its own tier consumes at this default server-side.
    negotiated_default_tier: Option<ConsumeTier>,
    /// Level-2 `ProduceConfirm`s (#497) that arrived for an offset OTHER than the one a
    /// [`Client::produce_confirmed`] call was awaiting, cached so a later call for that offset returns
    /// without re-waiting. Bounded in practice by the number of in-flight L2 produces a single
    /// half-duplex producer can have outstanding (it awaits each before issuing the next), so this
    /// stays tiny; entries are removed on the matching call. Empty for any connection that never uses
    /// `produce_confirmed`.
    confirm_cache: Vec<(u64, ConfirmOutcome)>,
    /// A per-connection monotonic counter used to mint a UNIQUE [`TxnId`] for each [`Client::prepare`]
    /// (#640, V2-M8). Combined with the connection's local socket address (a per-connection seed) it
    /// yields a transaction id unique across this producer's transactions; the producer may also supply
    /// its own id via [`Client::prepare_with_id`]. Starts at 0; bumped per `prepare`.
    next_txn_seq: u64,
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
        // Set the slowloris timeouts on the RAW socket before wrapping — they persist on the same fd
        // inside the `Wire` (the handshake below also runs under the read timeout).
        stream.set_read_timeout(config.read_timeout)?;
        stream.set_write_timeout(config.write_timeout)?;
        // Wrap the socket: TLS 1.3 when `config.tls` is set (verify the broker + complete the handshake
        // HERE, so a bad certificate fails the connect, never a silent plaintext fallback), else a
        // zero-cost plaintext `Wire`. On a non-tls build every connection is plaintext.
        #[cfg(feature = "tls")]
        let stream = match &config.tls {
            Some(tls_config) => Wire::connect_tls(stream, tls_config)?,
            None => Wire::Plain(stream),
        };
        #[cfg(not(feature = "tls"))]
        let stream = Wire::Plain(stream);
        let mut client = Client {
            stream,
            buf: Vec::new(),
            negotiated_credit: None,
            negotiated_credit_bytes: None,
            gap_marker_enabled: false,
            streaming_enabled: false,
            deliver_batch_enabled: false,
            streams_enabled: false,
            negotiated_default_tier: None,
            confirm_cache: Vec::new(),
            next_txn_seq: 0,
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
                // The connection-wide DEFAULT produce ack level the client requests (#494, #496),
                // carried as the raw 0/1/2 level value. `None` (the default) sends no default byte, so
                // the body is byte-for-byte the pre-#494 `Connect`; `Some(level)` negotiates the
                // connection default a level-less publish then adopts server-side.
                default_ack_level: config.default_ack_level.map(AckLevel::as_u8),
                // The streaming-tier capability bit and connection-wide default consume tier (#543).
                // Off/None by default, so the body carries no tier byte and the connection stays Tier-W
                // (byte-for-byte today's behavior); a caller opts in via the config.
                understands_streaming: config.understands_streaming,
                default_tier: config.default_consume_tier.map(ConsumeTier::as_u8),
                // The DeliverBatch capability bit (#541). Off by default, so the body is byte-for-byte
                // the pre-#541 `Connect` and the client receives only per-record `Deliver` frames; a
                // caller opts in via the config to receive raw-framed batches.
                understands_deliver_batch: config.understands_deliver_batch,
                // The stream-addressing capability bit (#588). Off by default, so the body is
                // byte-for-byte the pre-#588 `Connect` and the client uses only the default-stream
                // verbs; a caller opts in via the config to address named streams by id.
                understands_streams: config.understands_streams,
                // The compressed-delivery capability bit (#1066, the `flags2` byte). ON by default, so
                // a `--compression` broker ships stored-compressed records to this (decode-capable)
                // client verbatim; a caller wrapping a legacy consumer sets it `false` to force the
                // broker to decompress before delivery.
                understands_compressed_delivery: config.understands_compressed_delivery,
                wants_subject_filter: false,
            },
            &mut connect_body,
        );
        // Append the connection-scoped auth section (#631, #884) IFF the caller configured a
        // credential, AFTER the v1 body (the auth section rides the trailing zone past the `field_len`
        // block, exactly the wire the server parses with `parse_connect_auth`). With no credential (the
        // default) nothing is appended and the body stays byte-for-byte the pre-#631 `Connect`, so an
        // unauthenticated connect is unchanged. An oversized credential fails closed here (a typed
        // `ClientError::Body`) rather than sending a truncated auth section.
        if let Some(cred) = &config.credential {
            // The `Mtls` mechanism authenticates on the client CERTIFICATE presented at the TLS
            // handshake — its `Connect` body carries no credential bytes (#957). Guard it client-side:
            // sending `Mtls` without a configured client certificate would be rejected by the server as
            // an authorization violation, so fail fast here with an actionable error instead.
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
                // The streaming tier is active only when the server CONFIRMED it (it does so only when
                // the client advertised it understands streaming), so an old server's empty Info leaves
                // it off and the connection stays Tier-W (#543). The echoed default tier is adopted as
                // the connection default a tier-less subscription consumes at.
                client.streaming_enabled = info.streaming;
                client.negotiated_default_tier = info.default_tier.map(ConsumeTier::from_u8);
                // The DeliverBatch frame is active only when the server CONFIRMED it (it does so only
                // when the client advertised it understands the frame), so an old server's empty Info
                // leaves it off and every delivery is a per-record `Deliver` (#541).
                client.deliver_batch_enabled = info.deliver_batch;
                // The stream-addressed verbs are active only when the server CONFIRMED them (it does so
                // only when the client advertised it understands them), so an old server's empty Info
                // leaves it off and the client uses only the default-stream verbs (#588).
                client.streams_enabled = info.streams;
                Ok(client)
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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

    /// Whether the streaming consume tier (Tier-S) is ACTIVE on this connection (#543, V2-M1): `true`
    /// only when this client advertised it ([`ClientConfig::understands_streaming`]) AND the server
    /// confirmed it in `Info`. When `false` (an old server, or the client did not advertise), this
    /// connection is only ever served Tier-W.
    #[must_use]
    pub fn streaming_enabled(&self) -> bool {
        self.streaming_enabled
    }

    /// Whether the raw-framed `DeliverBatch` frame (tag 26) is ACTIVE on this connection (#541, M1-I5):
    /// `true` only when this client advertised it ([`ClientConfig::understands_deliver_batch`]) AND the
    /// server confirmed it in `Info`. When `true`, a contiguous Tier-S run may arrive as ONE
    /// `DeliverBatch` (transparently decoded into the same `Message`s a per-record `Deliver` run would
    /// yield); when `false`, every delivery is a per-record `Deliver`.
    #[must_use]
    pub fn deliver_batch_enabled(&self) -> bool {
        self.deliver_batch_enabled
    }

    /// Whether the stream-addressed wire verbs (`StreamDeclare`/`StreamInfo`/`PubTo`/`SubTo`, tags
    /// 28-31) are ACTIVE on this connection (#588, V2-M2-I10): `true` only when this client advertised
    /// it ([`ClientConfig::understands_streams`]) AND the server confirmed it in `Info`. When `false`
    /// (an old server, or the client did not advertise), the client may use only the default-stream
    /// verbs ([`Client::produce`] / [`Client::subscribe`] target the default stream).
    #[must_use]
    pub fn streams_enabled(&self) -> bool {
        self.streams_enabled
    }

    /// The connection-wide DEFAULT consume tier the server adopted for this connection (#543, V2-M1),
    /// echoed in `Info`, or `None` if the server did not echo one (an old server, or it defaulted to
    /// Tier-W). A subscription that does not pick its own tier consumes at this default server-side.
    #[must_use]
    pub fn negotiated_default_tier(&self) -> Option<ConsumeTier> {
        self.negotiated_default_tier
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
                Ok(stream) => {
                    // Disable Nagle (#1028): the client's produce/ack and fetch paths are small-frame
                    // request-response, where Nagle + the broker's delayed ACK stacks an RTT-scale
                    // stall onto every awaited round-trip on a real network. BEST-EFFORT: a failed
                    // setsockopt degrades latency only, never correctness, so it must not fail an
                    // otherwise-successful connect.
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
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
    /// This is the FULLY SYNCHRONOUS path: it writes the `Pub` frame and BLOCKS until the
    /// covering group-commit `fdatasync` has made the record durable and the broker's `PubAck`
    /// has arrived, so on return the message is durable (the ack-implies-durable contract). One
    /// publish is in flight at a time, so a SINGLE producer using this path pays one fsync per
    /// publish: the broker's group commit can only amortize an fsync across produces that are
    /// concurrently in flight, and an awaited `produce` never has a second one pending. That is
    /// the right default for a producer that needs each publish durable before it does anything
    /// else, but it caps a tight single-producer durable loop at roughly one publish per fsync.
    ///
    /// To LIFT a single producer's durable throughput without giving up the ack-implies-durable
    /// guarantee, keep several publishes in flight so the broker's group commit covers them with
    /// ONE fsync: use [`Client::pipelined_producer`] (the ergonomic auto-pipelining handle, which
    /// buffers a small window and flushes it as one group-committed batch) or, for an
    /// already-batched caller, [`Client::produce_window`] / [`Client::produce_stream`] directly.
    /// All three keep every ack's meaning unchanged (durable before the ack exists); they change
    /// only HOW MANY publishes are in flight when the fsync runs. This method's synchronous
    /// one-in-flight contract is deliberately left UNCHANGED so an existing caller's durability and
    /// blocking behavior are byte-for-byte identical.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or a server error.
    pub fn produce(&mut self, message: &PubBody<'_>) -> Result<u64, ClientError> {
        self.produce_dedup(message).map(|ack| ack.offset)
    }

    /// Produce `message`, transparently following a cluster [`ClientError::NotLeader`] redirect (#735) to
    /// the leader. On a non-cluster broker (or when already connected to the leader) this is exactly
    /// [`Client::produce`]: one produce, no extra work. In a cluster, if the connected node is NOT the
    /// leader of the partition, the server replies `NotLeader` with the current leader's CLIENT-address
    /// hint; this RECONNECTS this client to the hinted leader (using `config` for the handshake, so the
    /// negotiated capabilities are preserved) and RETRIES the produce there — so a client connected to the
    /// wrong node (e.g. after a failover moved leadership) recovers automatically. Bounded by
    /// `max_redirects` reconnects (a small value like 3 is ample; it guards against a redirect loop / a
    /// rebalance storm).
    ///
    /// A `NotLeader` with NO hint (`leader_hint == None` — the server did not yet know the leader, e.g.
    /// mid-failover) is returned to the caller UNCHANGED (this helper cannot guess an address): the caller
    /// re-tries its own known peers. Every other error (a real server `Err`, a transport error) is
    /// returned unchanged. On success the client REMAINS connected to the leader, so subsequent produces
    /// go straight there.
    ///
    /// # Errors
    /// Returns [`ClientError::NotLeader`] when the redirect carried no hint, or when `max_redirects`
    /// reconnects were exhausted (the last redirect is surfaced); a [`ClientError`] on a reconnect failure
    /// or any non-redirect produce error.
    pub fn produce_to_leader(
        &mut self,
        message: &PubBody<'_>,
        config: &ClientConfig,
        max_redirects: u32,
    ) -> Result<u64, ClientError> {
        let mut attempts = 0;
        loop {
            match self.produce(message) {
                Ok(offset) => return Ok(offset),
                Err(ClientError::NotLeader { leader_hint }) => {
                    // No hint, or redirect budget exhausted: surface the redirect for the caller to handle
                    // (re-discover the leader from its own peers). Never loop unbounded.
                    match leader_hint {
                        Some(addr) if attempts < max_redirects => {
                            // Reconnect to the hinted leader (preserving the handshake-negotiated
                            // capabilities), then retry the produce there. A reconnect failure surfaces as
                            // the connect error.
                            *self = Client::connect_with(addr.as_str(), config)?;
                            attempts += 1;
                        }
                        other => return Err(ClientError::NotLeader { leader_hint: other }),
                    }
                }
                Err(e) => return Err(e),
            }
        }
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            // A cluster NotLeader redirect (#735): this node is not the leader, so the produce did NOT
            // land here. Surface the typed `NotLeader` error (with the leader hint) so the caller can
            // reconnect/retry to the leader; the connection stays usable. `produce_to_leader` automates it.
            (FrameType::NotLeader, body) => Err(not_leader_error(&body)),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Produces a message at an EXPLICIT per-publish produce ACK LEVEL (#494, #496, part of the
    /// Cassandra-consistency-style spectrum #499), selecting the durability/round-trip trade per call.
    /// The level is carried in the PUB body's flags exactly as [`pub_ack_level`](ironbus_proto::message::pub_ack_level)
    /// decodes it, so the server routes the produce by the same rule a connection default or an old
    /// faf publish does. The caller's own [`PubBody::flags`] ack-level / fire-and-forget bits are
    /// REPLACED by the chosen level, so the method and the wire can never disagree; any `dedup` block
    /// the caller set is preserved (a publish at any level may also opt into dedup).
    ///
    /// The levels map to:
    ///
    /// - [`AckLevel::NoAck`] (Level 0): the FIRE-AND-FORGET / no-ack fast path. It sets
    ///   [`PUB_FLAG_FIRE_AND_FORGET`](ironbus_proto::message::PUB_FLAG_FIRE_AND_FORGET) (the canonical
    ///   Level-0 encoding) and returns the moment the frame is written WITHOUT awaiting a reply, so the
    ///   broker may drop the publish under load without acking and the producer accepts loss by
    ///   contract. Returns `Ok(None)` (no offset, by the QoS-0 no-reply contract). This is exactly
    ///   [`Client::produce_fire_and_forget`]'s wire behavior.
    /// - [`AckLevel::ServerAck`] (Level 1, the DEFAULT): today's at-least-once produce. It awaits the
    ///   `PubAck` after the covering group-commit fsync (I2: durable-on-return) and returns
    ///   `Ok(Some(offset))`. Wire-identical to [`Client::produce`].
    /// - [`AckLevel::ServerAndClientAck`] (Level 2): sets the ack-level field to 2 in the PUB flags and
    ///   awaits the `PubAck`, returning `Ok(Some(offset))`. The server FALLS BACK to the Level-1
    ///   await for THIS phase (#495): the record is accepted and acked exactly like Level 1, and the
    ///   out-of-band consumer-ack notification (the `ProduceConfirm` frame, #497) is NOT delivered yet,
    ///   so the returned offset reflects server-durability, not consumer-ack. When #497 lands this
    ///   method's Level-2 path is where the producer-side confirmation wait is added; until then it is
    ///   a Level-1-equivalent await with the Level-2 intent recorded on the wire.
    ///
    /// This is ADDITIVE: [`Client::produce`], [`Client::produce_window`], and
    /// [`Client::produce_fire_and_forget`] are unchanged. A `flags` with no ack-level / faf bit is
    /// Level 1, matching those paths; this method only lets a caller pick the level per publish.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or (Levels 1 and 2) a server
    /// error. Level 0 has no reply to surface, so a broker-side drop is not reported (the QoS-0
    /// contract).
    pub fn produce_with_ack_level(
        &mut self,
        message: &PubBody<'_>,
        level: AckLevel,
    ) -> Result<Option<u64>, ClientError> {
        match level {
            // Level 0: the no-ack fire-and-forget fast path. `produce_fire_and_forget` forces the
            // canonical faf bit and reads no reply, so the wire behavior is identical; there is no
            // offset to return by the QoS-0 contract.
            AckLevel::NoAck => self.produce_fire_and_forget(message).map(|()| None),
            // Level 1: today's at-least-once produce. Clear any caller-set ack-level bits so the wire
            // carries the canonical Level-1 encoding (field 0), then take the normal awaited PubAck
            // path (durable-on-return, I2). `produce` forces the faf bit clear, so a faf bit the caller
            // left set does not leak into this at-least-once path.
            AckLevel::ServerAck => {
                let leveled = PubBody {
                    flags: with_ack_level_bits(message.flags, AckLevel::ServerAck),
                    ..*message
                };
                self.produce(&leveled).map(Some)
            }
            // Level 2: set the ack-level field to 2 on the wire and await the PubAck. The server accepts
            // and acks it like Level 1 for THIS phase (#495); the producer-notify ProduceConfirm wait is
            // #497. `produce` forces the faf bit clear, so the level-2 publish is at-least-once.
            AckLevel::ServerAndClientAck => {
                let leveled = PubBody {
                    flags: with_ack_level_bits(message.flags, AckLevel::ServerAndClientAck),
                    ..*message
                };
                self.produce(&leveled).map(Some)
            }
        }
    }

    /// Produces a message at Level 2 (server+client ack, #497, part of #499) and AWAITS its
    /// `ProduceConfirm`: the publish is confirmed only after a CONSUMER acks it, so this returns once
    /// the record is BOTH durable AND consumed (or a terminal failure / the `timeout` elapses).
    ///
    /// TWO acks, in order:
    /// 1. The DURABILITY ack: the publish goes out at Level 2 and this first awaits the `PubAck` after
    ///    the covering group-commit fsync (I2), exactly like [`Client::produce`]. If this fails (a
    ///    server `Err`, a transport error) the call returns that error and never reaches the wait.
    /// 2. The CONSUMED ack: the broker registered the durable offset in its bounded confirm registry;
    ///    when a consumer in the broker's designated group acks the record, the broker sends a
    ///    server->producer `ProduceConfirm{offset, status}` frame, which this awaits (keyed by the
    ///    offset the `PubAck` returned) up to `timeout`.
    ///
    /// ## How the wait works (and why it polls)
    ///
    /// The broker is a blocking, thread-per-connection, request-response server: it only writes a
    /// connection's socket from THAT connection's own pass, so it cannot push a confirm to a producer
    /// blocked in `read`. This call therefore DRIVES the broker to flush by interleaving lightweight
    /// `Ping`s while it waits: each round sends a `Ping` and reads the frames the broker returns
    /// (`Pong` plus any ready `ProduceConfirm`s for this connection), until the matching confirm
    /// arrives or `timeout` elapses. A confirm for a DIFFERENT offset (an earlier L2 publish on the
    /// same connection) is matched and CACHED so a later `produce_confirmed` for that offset returns it
    /// without re-waiting. The poll keeps the await fully within the existing wire/threading contract:
    /// no out-of-band push, no second socket, no new race.
    ///
    /// Returns a [`ProduceConfirmation`] carrying the durable `offset` and the terminal
    /// [`ConfirmOutcome`] (`Consumed` / `TimedOut` / `DeadLettered` / `LocalTimeout` / `Unknown`). A
    /// `LocalTimeout` means the local deadline elapsed first; the record is durable regardless, and the
    /// connection stays usable.
    ///
    /// This is ADDITIVE and SEPARATE from [`Client::produce_with_ack_level`]: that method records the
    /// Level-2 intent on the wire but returns at the durability ack (it does NOT await the consumer-ack
    /// confirmation); this method is the one that awaits the `ProduceConfirm`.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on a transport error, an over-large field, an unexpected frame, or a
    /// server `Err` for the durability ack. A broker-side timeout / dead-letter is NOT an error: it is
    /// reported as the corresponding [`ConfirmOutcome`].
    pub fn produce_confirmed(
        &mut self,
        message: &PubBody<'_>,
        timeout: Duration,
    ) -> Result<ProduceConfirmation, ClientError> {
        // Step 1 — the durability ack. Send at Level 2 (the ack-level field on the wire) and await the
        // PubAck, exactly like `produce`. `produce` forces the faf bit clear, so this is at-least-once.
        let leveled = PubBody {
            flags: with_ack_level_bits(message.flags, AckLevel::ServerAndClientAck),
            ..*message
        };
        let offset = self.produce(&leveled)?;
        // A confirm for THIS offset may already be cached from an earlier round (a prior
        // `produce_confirmed` drained it while waiting on a different offset). Serve it without waiting.
        if let Some(outcome) = self.take_cached_confirm(offset) {
            return Ok(ProduceConfirmation { offset, outcome });
        }
        // Step 2 — the consumed ack. Poll for the matching `ProduceConfirm` within the deadline,
        // driving broker passes with Pings.
        let outcome = self.await_produce_confirm(offset, timeout)?;
        Ok(ProduceConfirmation { offset, outcome })
    }

    /// Awaits the `ProduceConfirm` for `offset` up to `timeout` (#497), driving broker passes with
    /// `Ping`s (see [`Client::produce_confirmed`]). Returns the terminal [`ConfirmOutcome`], or
    /// `LocalTimeout` if the deadline elapses first. A `ProduceConfirm` for a DIFFERENT offset is
    /// cached for a later `produce_confirmed`. A read that times out (the connection read timeout) is
    /// treated as "no confirm this round" while the deadline has not passed.
    fn await_produce_confirm(
        &mut self,
        offset: u64,
        timeout: Duration,
    ) -> Result<ConfirmOutcome, ClientError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // Drive a broker pass: a Ping makes the connection do a `process` pass, which flushes any
            // ready ProduceConfirms for this connection alongside the Pong.
            self.send(FrameType::Ping, &[])?;
            // Read frames until this round yields the Pong boundary (every ready confirm precedes or
            // accompanies it in the same flush), the matching confirm arrives, or the read times out.
            loop {
                match self.read_frame_or_timeout()? {
                    Some((FrameType::ProduceConfirm, body)) => {
                        let confirm = decode_produce_confirm(&body).map_err(|_| {
                            ClientError::BadResponse("produce-confirm body was not nine bytes")
                        })?;
                        let outcome = confirm_outcome(confirm.status);
                        if confirm.offset == offset {
                            return Ok(outcome);
                        }
                        // A confirm for an earlier L2 publish on this connection: cache it so a later
                        // `produce_confirmed` for that offset returns without re-waiting.
                        self.confirm_cache.push((confirm.offset, outcome));
                    }
                    // Two round-ending cases, same action (stop reading, re-check the deadline,
                    // re-Ping): `None` is a read timeout with no frame, and `Pong` is this round's
                    // flush boundary (every ready confirm precedes or accompanies it in the same flush).
                    None | Some((FrameType::Pong, _)) => break,
                    // An Err for a Ping is not expected; surface it. Any other frame (e.g. a stray
                    // Deliver on a mixed producer/consumer connection) is not what this wait is for.
                    Some((FrameType::Err, body)) => {
                        return Err(ClientError::Server(ServerError::from_wire(&body)))
                    }
                    Some((other, _)) => return Err(ClientError::Unexpected(other)),
                }
            }
            if std::time::Instant::now() >= deadline {
                return Ok(ConfirmOutcome::LocalTimeout);
            }
        }
    }

    /// Reads one frame, returning `Ok(None)` if the connection read TIMED OUT (the OS read timeout
    /// elapsed) rather than propagating it as an error (#497): the confirm-await poll treats a timed-out
    /// read as "no confirm yet this round". A genuine close or malformed frame still errors.
    fn read_frame_or_timeout(&mut self) -> Result<Option<(FrameType, Vec<u8>)>, ClientError> {
        match self.read_frame() {
            Ok(frame) => Ok(Some(frame)),
            // A read timeout surfaces as a `WouldBlock`/`TimedOut` IO error on a blocking socket with a
            // read timeout set; that is "no data yet", not a fatal error, during the bounded poll.
            Err(ClientError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Removes and returns a cached `ProduceConfirm` outcome for `offset` if one arrived on an earlier
    /// round (#497), else `None`.
    fn take_cached_confirm(&mut self, offset: u64) -> Option<ConfirmOutcome> {
        let pos = self.confirm_cache.iter().position(|&(o, _)| o == offset)?;
        Some(self.confirm_cache.swap_remove(pos).1)
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
                // A cluster NotLeader redirect (#735): this node is not the leader, so the windowed
                // produces did NOT land. Remember it as the first error (with the leader hint); the drain
                // continues so the connection stays framed, then the call returns the typed redirect.
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

    /// Opens a COALESCING at-most-once (QoS-0) producer over this client: the batched companion to the
    /// per-call [`Client::produce_fire_and_forget`]. It frames each fire-and-forget publish into a wire
    /// buffer and writes that buffer to the socket with ONE `write_all` only at [`STREAM_FLUSH_BYTES`]
    /// boundaries (or on an explicit [`FireForgetProducer::flush`]), turning a tight per-message send
    /// loop's thousands of tiny per-publish socket writes into a handful of large ones — the same
    /// syscall coalescing a core pub/sub client performs — without changing the wire bytes the broker
    /// sees. For a single producer that wants maximum at-most-once send throughput. No reply is ever
    /// read (a fire-and-forget `Pub` is unacked by contract). Call [`FireForgetProducer::flush`] after
    /// the last publish to push the final partial batch.
    #[must_use]
    pub fn fire_and_forget_producer(&mut self) -> FireForgetProducer<'_> {
        FireForgetProducer {
            client: self,
            wire: Vec::with_capacity(STREAM_FLUSH_BYTES + 1024),
            body: Vec::new(),
        }
    }

    /// Opens an AUTO-PIPELINING durable producer (#508) over this client with the default in-flight
    /// window ([`DEFAULT_PIPELINE_WINDOW`]): the ergonomic high-throughput companion to the awaited
    /// [`Client::produce`], for a SINGLE producer that wants its publishes durable (at-least-once,
    /// ack-implies-durable) but does not want to pay one `fdatasync` per publish.
    ///
    /// A [`PipelinedProducer`] buffers each [`PipelinedProducer::produce`] into an in-flight window
    /// and writes the window as ONE pipelined batch (the proven [`Client::produce_window`] wire
    /// discipline), so the broker's group commit covers the whole window with a single fsync. The
    /// caller drains the resulting acks at flush points ([`PipelinedProducer::flush`]) or at the end
    /// ([`PipelinedProducer::finish`]). Every ack still means the record is fsynced-durable (I2 is
    /// untouched); only WHEN a publish's ack is observed moves, never what it means.
    ///
    /// This is ADDITIVE: it does not change [`Client::produce`], whose fully-synchronous,
    /// one-in-flight, durable-on-return contract is unchanged. Reach for the handle when a single
    /// producer's durable THROUGHPUT matters; reach for `produce` when each publish must be durable
    /// before the next line of caller code runs.
    pub fn pipelined_producer(&mut self) -> PipelinedProducer<'_> {
        self.pipelined_producer_with_window(DEFAULT_PIPELINE_WINDOW)
    }

    /// Opens an auto-pipelining durable producer (#508) with an explicit in-flight `window`: the
    /// number of publishes buffered before the handle flushes them as one group-committed batch. A
    /// `window` of `0` is treated as `1` (no pipelining: each publish flushes and awaits on its own,
    /// matching the awaited [`Client::produce`] throughput). A larger window keeps more publishes in
    /// flight per fsync (higher durable throughput) at the cost of a larger not-yet-flushed tail and
    /// more buffered memory. See [`Client::pipelined_producer`] for the default-window entry point
    /// and the full contract.
    pub fn pipelined_producer_with_window(&mut self, window: usize) -> PipelinedProducer<'_> {
        PipelinedProducer {
            client: self,
            window: window.max(1),
            buffered: 0,
            wire: Vec::new(),
        }
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

    /// Derives the AGGREGATE materialized-payload-bytes ceiling for one fetch window (#938). The default
    /// [`MAX_FETCH_DECOMPRESSED_BYTES`] (256 MiB) is a generous FLOOR, not an absolute cap: when this
    /// consumer negotiated a LARGER per-consumer byte budget (`negotiated_credit_bytes`, itself
    /// `min(client-request, server-cap)`), the server may legitimately stream a window that big, so
    /// bounding it at the floor would falsely trip [`ClientError::BadResponse`]. The ceiling is thus
    /// `max(negotiated_credit_bytes, MAX_FETCH_DECOMPRESSED_BYTES)`: a consumer that negotiated a bigger
    /// window is honored, while an un-negotiated (`None`) or hostile fetch stays fail-closed at 256 MiB.
    fn fetch_decompressed_cap(&self) -> usize {
        self.negotiated_credit_bytes
            .and_then(|b| usize::try_from(b).ok())
            .map_or(MAX_FETCH_DECOMPRESSED_BYTES, |b| {
                b.max(MAX_FETCH_DECOMPRESSED_BYTES)
            })
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
    #[allow(clippy::too_many_lines)] // one cohesive frame-dispatch loop (deliver / batch / advisory / poison-drain)
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
        // #879/#938: the running total of materialized payload bytes across this fetch window, capped at
        // the negotiated byte budget (floored at [`MAX_FETCH_DECOMPRESSED_BYTES`]) so a credit-bounded
        // fetch of a tiny wire response cannot expand to credit x the per-record 8 MiB cap of resident
        // RAM, while a consumer that negotiated a larger byte window is not falsely rejected.
        let max_aggregate = self.fetch_decompressed_cap();
        let mut decompressed_bytes = 0usize;
        loop {
            // Buffer one complete frame, then decode its body by BORROWING it out of `self.buf`
            // (#818) rather than copying it into a throwaway owned `Vec` as `read_frame` does. Every
            // byte that survives into a `Message` is copied exactly once, while the borrow is live;
            // the frame is drained only after all surviving copies are made (`self.buf.drain` at the
            // loop bottom / before each terminal return), so the borrow-then-drain ordering holds.
            self.fill_frame()?;
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
            // An unknown tag (e.g. from a newer server) has no client handler; name the raw tag
            // rather than pretending it was some known frame.
            let frame_type =
                FrameType::from_u8(type_tag).ok_or(ClientError::UnknownFrameType(type_tag))?;
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
                // A raw-framed batch (#541): ONE frame carrying a contiguous run of records as their
                // ON-DISK frame bytes. Decode the header (the run's first_offset / generation /
                // record_count), then decode each on-disk frame and reconstruct its offset POSITIONALLY
                // (first_offset + i, the run being dense and contiguous), feeding each through the SAME
                // per-record path a `Deliver` takes — so the resulting `Message`s are byte-for-byte what
                // an equivalent run of per-record `Deliver` frames would yield. Each frame's CRC is
                // VERIFIED here by `codec::decode` (header and body), so integrity is checked end-to-end;
                // a corrupt frame is a typed error, never silently accepted. Only seen on a
                // batch-capable connection; an old server never sends this tag.
                FrameType::DeliverBatch => {
                    let (header, record_bytes) =
                        decode_deliver_batch(body).map_err(ClientError::Body)?;
                    // A batch carries N records but counted as ONE frame at the loop top; charge the
                    // remaining (N - 1) records against the credit bound so a hostile server cannot
                    // smuggle an unbounded run of records inside one batch frame. The server bounds a
                    // real batch by the negotiated credit, so this never trips for a well-behaved peer.
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
                        // CRC-verify and decode ONE on-disk record frame. A bad frame (torn, or a CRC
                        // mismatch) is a typed `BadResponse`, so the broker never slips a corrupt or
                        // truncated batch past the client unnoticed.
                        let (view, consumed) = ironbus_core::codec::decode(&record_bytes[cursor..])
                            .map_err(|_| {
                                ClientError::BadResponse("malformed record in DeliverBatch body")
                            })?;
                        // Reconstruct the on-wire per-record `Deliver` from the on-disk record: the
                        // OFFSET is positional (the on-disk frame carries `seq`, not offset), and the
                        // generation is the batch's (0 for the lease-free Tier-S path). The remaining
                        // fields (flags/timestamp/key/headers/payload) are the stored record's, so the
                        // delivery is identical to a per-record `Deliver` for the same record.
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
                    // The decoded frame count MUST match the header's record_count and consume the body
                    // exactly: a mismatch means a malformed batch (a partial frame, or a wrong count),
                    // which is a typed error rather than a silently short batch.
                    if cursor != record_bytes.len() || decoded != header.record_count {
                        return Err(ClientError::BadResponse(
                            "DeliverBatch record_count or body length mismatch",
                        ));
                    }
                }
                // An in-band dead-letter advisory for an offset skipped as poison (#63). It is
                // not a delivery, so it carries its own offset and does not ack.
                FrameType::DeadLetter => {
                    let dl = decode_dead_letter(body).map_err(ClientError::Body)?;
                    dead_letters.push(DeadLetter {
                        offset: dl.offset,
                        reason: dl.reason,
                    });
                }
                // An in-band truncation advisory: the broker reset this cursor below the oldest
                // retained record because the disk-full drop-oldest policy reaped its records
                // (#82, #84). It is not a delivery and does not ack; it names where delivery
                // resumed and how many records were skipped.
                FrameType::Truncated => {
                    let t = decode_truncated(body).map_err(ClientError::Body)?;
                    truncations.push(Truncation {
                        earliest_retained: t.earliest_retained,
                        skipped: t.skipped,
                    });
                }
                // An in-band gap marker (#346): the consumer-visible, opt-in replacement for the
                // Truncated advisory. A skipped offset span `[from, to)` is permanently absent, so a
                // reader tracking contiguity learns the jump is a bounded, reported gap rather than
                // loss. Only seen on a gap-marker-capable connection; an old server never sends it.
                FrameType::GapMarker => {
                    let g = decode_gap_marker(body).map_err(ClientError::Body)?;
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

    /// Writes ONE `StreamFetch` request (Tier-S, #544 / #550) WITHOUT reading its response: the
    /// low-level write half of [`Client::stream_fetch`], pulled out so a [`StreamingConsumer`] can
    /// PIPELINE the next window's request ahead of processing the current batch (the bounded
    /// read-ahead). The matching response is drained by [`Client::read_stream_fetch_response`].
    ///
    /// Returns the client-side `limit` (the frame cap the matching read must honor): `max_records`
    /// capped at the negotiated per-consumer credit (#292) when the server advertised one, exactly as
    /// the per-record and batch-pull fetches cap. The negotiated value governs the pull, so the client
    /// never over-requests past what it agreed to.
    fn send_stream_fetch(
        &mut self,
        start_offset: u64,
        max_records: u32,
        max_bytes: u64,
    ) -> Result<usize, ClientError> {
        let max_records = match self.negotiated_credit {
            Some(credit) => max_records.min(credit),
            None => max_records,
        };
        let req = StreamFetchBody {
            start_offset,
            max_records,
            max_bytes,
        };
        let mut body = Vec::new();
        encode_stream_fetch(&req, &mut body);
        self.send(FrameType::StreamFetch, &body)?;
        Ok(usize::try_from(max_records).unwrap_or(usize::MAX))
    }

    /// Reads the response to a previously-sent `StreamFetch` (the read half of
    /// [`Client::stream_fetch`]). The Tier-S delivery response is byte-for-byte a [`Client::fetch`]
    /// response past the request frame — a run of `Deliver` (or one raw-framed `DeliverBatch`, #541)
    /// frames plus any advisories, terminated by exactly one `FlowEnd` — so it shares
    /// [`Client::read_fetch_response`] verbatim. `limit` is the value [`Client::send_stream_fetch`]
    /// returned for the matching request, bounding the frames the server may stream before `FlowEnd`.
    fn read_stream_fetch_response(&mut self, limit: usize) -> Result<Fetch, ClientError> {
        self.read_fetch_response(limit)
    }

    /// STREAMING (Tier-S, #544 / #550) consumer-managed-offset fetch: serves a CONTIGUOUS batch of
    /// records `[start_offset, ...)` off the durable prefix, bounded by `max_records` and `max_bytes`,
    /// with NO lease, NO generation fence, and NO per-record cursor write. The consumer NAMES its own
    /// `start_offset` (normally its last committed offset) and advances durability separately via a
    /// PERIODIC [`Client::stream_commit`] — the Kafka / NATS-pull contract. This is the low-cost twin
    /// of the per-record-leased [`Client::fetch_batch`]: removing the per-record lease/cursor work is
    /// exactly what lets a single durable consumer keep up.
    ///
    /// AT-LEAST-ONCE holds BY CONSTRUCTION: because the consumer drives the offset, a crash or
    /// reconnect simply re-fetches from its last committed offset and the uncommitted span redelivers
    /// (none is lost). The delivered [`Message`]s are byte-for-byte what the leased path yields; only
    /// the settlement bookkeeping differs. The returned messages carry `generation = 0` (there is no
    /// fence on this path) and MUST be settled by offset via [`Client::stream_commit`], never by
    /// [`Client::ack`].
    ///
    /// The connection MUST have negotiated Tier-S ([`ClientConfig::understands_streaming`], confirmed
    /// by [`Client::streaming_enabled`]) and be [`Client::subscribe`]d to a streaming group; otherwise
    /// the server rejects the verb with a [`ClientError::Server`]. The ergonomic batched-default loop
    /// (a handle that fetches windows and auto-commits periodically, WITH bounded read-ahead) is
    /// [`Client::streaming_consumer`]; reach for this raw method only for precise, hand-driven control.
    ///
    /// - `start_offset`: the inclusive offset to begin the contiguous read at (the consumer's
    ///   position).
    /// - `max_records`: the most records to return, capped at the negotiated per-consumer credit
    ///   (#292) when the server advertised one.
    /// - `max_bytes`: the byte budget (`0` = unbounded by bytes; the record count and the durable
    ///   prefix still bind). The server applies the floor-of-one, so a single over-budget record is
    ///   never wedged.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error (e.g. the group is not streaming, or
    /// the connection did not negotiate Tier-S), or a server that streams more frames than the cap.
    pub fn stream_fetch(
        &mut self,
        start_offset: u64,
        max_records: u32,
        max_bytes: u64,
    ) -> Result<Fetch, ClientError> {
        let limit = self.send_stream_fetch(start_offset, max_records, max_bytes)?;
        self.read_stream_fetch_response(limit)
    }

    /// STREAMING (Tier-S, #544 / #550) periodic CUMULATIVE COMMIT: advances the streaming group's
    /// committed cursor up to the EXCLUSIVE offset `up_to` — the consumer's "everything below `up_to`
    /// is durably processed" checkpoint. This is the durability point of the consumer-managed-offset
    /// model: a [`Client::stream_fetch`] never advances the cursor, so retention is pinned only by this
    /// commit, and a crash redelivers everything fetched-but-not-yet-committed (the at-least-once
    /// window).
    ///
    /// Commit PERIODICALLY (once per N batches or T milliseconds), NOT per record: amortizing the
    /// commit across a window is the whole ergonomic win over a per-record ack. A re-commit at or below
    /// the current commit is an idempotent no-op success; the server validates `up_to` against the
    /// durable head and the earliest-retained offset, and HARD-REJECTS the verb on a group that is not
    /// streaming. An empty `group` selects the default group.
    ///
    /// The [`StreamingConsumer`] handle ([`Client::streaming_consumer`]) drives this automatically on a
    /// configurable cadence; call it directly only for hand-driven precise commits (e.g. an exactly
    /// processed-up-to checkpoint).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the verb (the group is not a streaming
    /// consumer, or `up_to` is outside the retained window), or a frame or connection error.
    pub fn stream_commit(&mut self, group: &str, up_to: u64) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_stream_commit(
            &StreamCommitBody {
                up_to,
                group: group.as_bytes(),
            },
            &mut body,
        );
        self.send(FrameType::StreamCommit, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Opens the ERGONOMIC batched-default streaming consumer (Tier-S, #550): the high-throughput
    /// companion to the raw [`Client::stream_fetch`] / [`Client::stream_commit`] pair, and the
    /// recommended way to consume a streaming group. The handle's [`StreamingConsumer::next_batch`]
    /// loop FETCHES A WINDOW at a time (a [`Client::stream_fetch`] of `max_records` / `max_bytes`,
    /// delivered as one `DeliverBatch` when the connection negotiated it, #541), commits the offset
    /// PERIODICALLY and cumulatively ([`Client::stream_commit`]) rather than per record, and PREFETCHES
    /// the next window while the caller processes the current batch — the Kafka / NATS-pull ergonomic
    /// default. The per-record fetch-and-ack path is the explicit opt-out, not the default.
    ///
    /// The read-ahead is BOUNDED: at most ONE window is in flight ahead of the caller (the next
    /// window's `StreamFetch` is pipelined the moment the current batch is read, so the next response
    /// is already arriving while the caller works), and that window is bounded by the SAME
    /// `max_records` / `max_bytes` budget as the visible one. There is never an unbounded prefetch
    /// buffer, and because this is a single consumer reading its OWN offset (not a per-group
    /// server-side buffer fanned out to many consumers) it never duplicates payloads across groups.
    ///
    /// AT-LEAST-ONCE is preserved: the consumer commits only what it has processed, so a crash
    /// redelivers the uncommitted (including the prefetched-but-unprocessed) window and loses nothing.
    /// See [`StreamConsumerConfig`] for the window size, the commit cadence, the starting offset, and
    /// the precise-commit opt-out; [`Client::streaming_consumer`] uses the defaults.
    ///
    /// The connection MUST have negotiated Tier-S and be [`Client::subscribe`]d to the streaming
    /// `group` (the handle commits to that group name) before the first batch.
    #[must_use]
    pub fn streaming_consumer<'a>(&'a mut self, group: &str) -> StreamingConsumer<'a> {
        self.streaming_consumer_with(group, &StreamConsumerConfig::default())
    }

    /// Opens the batched-default streaming consumer (Tier-S, #550) with an explicit
    /// [`StreamConsumerConfig`]: the window size, the periodic-commit cadence, the starting offset, and
    /// whether read-ahead is on. See [`Client::streaming_consumer`] for the default-config entry point
    /// and the full contract.
    #[must_use]
    pub fn streaming_consumer_with<'a>(
        &'a mut self,
        group: &str,
        config: &StreamConsumerConfig,
    ) -> StreamingConsumer<'a> {
        StreamingConsumer {
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// CREATE-OR-ENSURE a NAMED stream by id (#588, M2-I10): the `StreamDeclare` verb. Idempotent —
    /// re-declaring an existing stream is a no-op success — and the broker materializes the stream's
    /// independent log on the first declare. Requires the connection to have negotiated stream
    /// addressing ([`ClientConfig::understands_streams`] AND the server confirming it, observable via
    /// [`Client::streams_enabled`]); a server that did not negotiate it replies an `Err`. The default
    /// stream (the empty name) is always present and need not be declared.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the declare (capability not negotiated, or
    /// a malformed/over-long name), [`ClientError::Body`] on an over-large field, or a frame/connection
    /// error.
    pub fn declare_stream(&mut self, stream: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_stream_declare(
            &StreamDeclareBody {
                stream_id: stream.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::StreamDeclare, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Queries a NAMED stream's existence and durable head (#588, M2-I10): the `StreamInfo` verb.
    /// Returns `(exists, head)` — `exists = true` and the stream's durable head offset when the stream
    /// is open, or `(false, 0)` when it does not exist. The default stream (the empty name) always
    /// reports `exists = true`. Requires the stream-addressing capability (see
    /// [`Client::declare_stream`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the query (capability not negotiated, or a
    /// malformed name), [`ClientError::Body`] on an over-large field, [`ClientError::BadResponse`] on a
    /// malformed reply, or a frame/connection error.
    pub fn stream_info(&mut self, stream: &str) -> Result<(bool, u64), ClientError> {
        let mut body = Vec::new();
        encode_stream_info(
            &StreamInfoBody {
                stream_id: stream.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::StreamInfo, &body)?;
        match self.read_frame()? {
            (FrameType::StreamInfo, body) => {
                let resp = decode_stream_info_response(&body)
                    .map_err(|_| ClientError::BadResponse("malformed stream-info response"))?;
                Ok((resp.exists, resp.head))
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Publishes a message to a NAMED stream by id (#588, M2-I10): the `PubTo` verb, the stream-
    /// addressed twin of [`Client::produce`]. The publish body is the SAME [`PubBody`] the default-
    /// stream produce carries, prefixed with the target stream id, so the broker appends it to that
    /// named stream's own log and replies a `PubAck` with the assigned offset (ack-implies-durable per
    /// stream). An EMPTY `stream` targets the default stream (equivalent to [`Client::produce`]). The
    /// publish is at-least-once (server-ack, Level 1); the fire-and-forget / consumer-ack tiers are the
    /// default stream's this phase. Requires the stream-addressing capability (see
    /// [`Client::declare_stream`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the publish (capability not negotiated, a
    /// malformed name, or a non-server-ack level), [`ClientError::Body`] on an over-large field,
    /// [`ClientError::BadResponse`] on a malformed ack, or a frame/connection error.
    pub fn publish_to(&mut self, stream: &str, message: &PubBody<'_>) -> Result<u64, ClientError> {
        // Force at-least-once server-ack (Level 1) on the carried body: the named-stream path accepts
        // only that level this phase, and an old caller never set a level bit, so this is a no-op for
        // them and a guard against a mismatched method/wire for everyone.
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
        self.send(FrameType::PubTo, &body)?;
        match self.read_frame()? {
            (FrameType::PubAck, body) => {
                let ack = decode_pub_ack(&body)
                    .map_err(|_| ClientError::BadResponse("publish-to reply was not an offset"))?;
                Ok(ack.offset)
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    // ---- transactional half-message 2PC (#640, V2-M8) ----

    /// PREPAREs a transactional half message (#640): durably buffers `message` for a freshly-minted
    /// [`TxnId`] targeting `stream` (empty = the default stream), INVISIBLE to consumers, and returns
    /// the id. The producer then runs its local transaction and calls [`Client::commit`] (the half
    /// message becomes visible) or [`Client::rollback`] (it is discarded). The id is unique to this
    /// connection (its local address + a per-connection counter); to supply your OWN id (a UUID, a
    /// snowflake) use [`Client::prepare_with_id`].
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the prepare (too many prepared, a spent
    /// id), [`ClientError::Body`] on an over-large field, or a frame/connection error.
    pub fn prepare(&mut self, stream: &str, message: &PubBody<'_>) -> Result<TxnId, ClientError> {
        let txn = self.mint_txn_id();
        self.prepare_with_id(&txn, stream, message)?;
        Ok(txn)
    }

    /// Like [`Client::prepare`] but with a producer-SUPPLIED `txn` id (a UUID, a snowflake, a content
    /// hash) instead of a minted one — the idempotency anchor for a producer that derives its
    /// transaction id from its own local transaction. Re-preparing a still-prepared id is a benign
    /// no-op server-side; preparing a resolved (spent) id is refused.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the prepare (a spent id, too many
    /// prepared, an over-long id), [`ClientError::Body`] on an over-large field, or a frame/connection
    /// error.
    pub fn prepare_with_id(
        &mut self,
        txn: &TxnId,
        stream: &str,
        message: &PubBody<'_>,
    ) -> Result<(), ClientError> {
        // The half message is always at-least-once server-ack; the wire-only fire-and-forget bit is
        // cleared so a half message is never a QoS-0 drop (it must be durably buffered to commit).
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
        self.send(FrameType::TxnPrepare, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// COMMITs the prepared half message named by `txn` (#640): the broker appends the buffered payload
    /// to the real target stream (it becomes VISIBLE to consumers) and returns the committed offset.
    /// IDEMPOTENT: a retried commit of an already-committed txn returns the same offset (never an
    /// error); a commit of an already-rolled-back txn is a [`ClientError::Server`] rejection (the
    /// outcome is never flipped).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] for an unknown / already-rolled-back txn, [`ClientError::Body`]
    /// on an over-large field, [`ClientError::BadResponse`] on a malformed reply, or a frame/connection
    /// error.
    pub fn commit(&mut self, txn: &TxnId) -> Result<u64, ClientError> {
        let mut body = Vec::new();
        encode_txn_resolve(
            &TxnResolveBody {
                txn_id: txn.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::TxnCommit, &body)?;
        match self.read_frame()? {
            (FrameType::PubAck, body) => {
                let ack = decode_pub_ack(&body)
                    .map_err(|_| ClientError::BadResponse("txn-commit reply was not an offset"))?;
                Ok(ack.offset)
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// ROLLs BACK the prepared half message named by `txn` (#640): the broker discards the buffered
    /// payload — it is never appended to the real stream, never delivered. IDEMPOTENT: a retried
    /// rollback is a benign success; a rollback of an already-committed txn is a [`ClientError::Server`]
    /// rejection (never flipped).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] for an unknown / already-committed txn, [`ClientError::Body`] on
    /// an over-large field, or a frame/connection error.
    pub fn rollback(&mut self, txn: &TxnId) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_txn_resolve(
            &TxnResolveBody {
                txn_id: txn.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::TxnRollback, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Mints a UNIQUE transaction id for this connection (#640): the local socket address (a
    /// per-connection seed) plus a monotonic per-connection counter, so two `prepare`s on this
    /// connection — and on different connections (distinct local addresses) — never collide. Bounded
    /// well under the 256-byte wire cap.
    ///
    /// COLLISION SCOPE: the `<local_addr>#<seq>` id is unique only WITHIN a connection's lifetime. An
    /// EPHEMERAL local port REUSED by a later connection (after this one closes) whose per-connection
    /// counter has reset to 0 can re-mint an id a still-prepared txn already holds. Because the id is
    /// the broker's idempotency key, this surfaces as a broker ERROR (a spent / still-prepared id is
    /// refused) — NEVER a silent merge of two distinct half messages. For transactions that must
    /// survive a reconnect (or that derive their identity from a local transaction), supply a stable
    /// caller-chosen id via [`Client::prepare_with_id`] (a UUID, a snowflake, a content hash) instead
    /// of an auto-minted one — that is the durable choice.
    fn mint_txn_id(&mut self) -> TxnId {
        let seq = self.next_txn_seq;
        self.next_txn_seq = self.next_txn_seq.wrapping_add(1);
        // The local address is a stable per-connection seed; pair it with the monotonic counter.
        let seed = self
            .stream
            .local_addr()
            .map_or_else(|_| "txn".to_string(), |a| a.to_string());
        TxnId(format!("{seed}#{seq}").into_bytes())
    }

    /// Registers this connection as the transaction-state LISTENER for the stable `group` (#640
    /// part 2, the `TxnListen` verb): the broker binds the group to this connection so a back-check
    /// [`crate::FrameType::TxnCheck`] for an in-doubt half message this producer prepared (under this
    /// group) is routed here — even after a CRASH and reconnect (the producer reconnects and calls this
    /// again with the SAME group to re-point the route). After registering, the producer prepares its
    /// transactions on this connection (their half messages record the group as owner) and drives the
    /// back-check by calling [`Client::transact`] (or [`Client::run_transaction_listener`]) so an
    /// inbound `TxnCheck` is answered. A stable, producer-chosen group (e.g. the producer's durable id)
    /// is what makes the route survive a reconnect; an EMPTY group is rejected by the broker.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the broker rejects the registration (an empty group, or the
    /// `publish` scope is missing), [`ClientError::Body`] on an over-large group, or a frame/connection
    /// error.
    pub fn register_transaction_listener(&mut self, group: &[u8]) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_txn_listen(&TxnListenBody { group }, &mut body).map_err(ClientError::Body)?;
        self.send(FrameType::TxnListen, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Answers one inbound `TxnCheck` (#640 part 2): decode the txn id, run the producer's
    /// `check_transaction` callback to decide the resolution, and reply a `TxnCheckResult`. The broker
    /// then resolves the in-doubt half message through the part-1 idempotent path (a `Commit` commits it
    /// exactly once, a `Rollback` discards it, an `Unknown` reschedules). Used by the listener loop.
    fn answer_txn_check<L: FnMut(&[u8]) -> TxnDecision>(
        &mut self,
        check_body: &[u8],
        listener: &mut L,
    ) -> Result<(), ClientError> {
        let decoded = decode_txn_resolve(check_body)
            .map_err(|_| ClientError::BadResponse("malformed txn-check body"))?;
        let decision = listener(decoded.txn_id).to_wire();
        let mut body = Vec::new();
        encode_txn_check_result(
            &TxnCheckResultBody {
                txn_id: decoded.txn_id,
                decision,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::TxnCheckResult, &body)?;
        Ok(())
    }

    /// Runs the producer's transaction-state listener for up to `timeout` (#640 part 2): it DRIVES
    /// broker passes by interleaving lightweight `Ping`s (exactly like [`Client::produce_confirmed`]),
    /// and for every inbound `TxnCheck` it runs `check_transaction(txn_id)` and replies the answer — so
    /// the broker's back-check resolves this producer's in-doubt half messages (e.g. ones it prepared
    /// before a crash, now recovered after this reconnect). Returns the number of `TxnCheck`s answered.
    ///
    /// A producer that crashed mid-transaction reconnects, calls
    /// [`Client::register_transaction_listener`] with its stable group, then calls this to settle any
    /// in-doubt transactions. The callback should consult the producer's OWN durable local-transaction
    /// state for `txn_id` and return [`TxnDecision::Commit`] / [`TxnDecision::Rollback`], or
    /// [`TxnDecision::Unknown`] if it cannot yet decide (the broker retries, then safely rolls back).
    ///
    /// # Errors
    /// A frame/connection error, or [`ClientError::Server`] if a `Ping` is answered with an `Err`.
    pub fn run_transaction_listener<L: FnMut(&[u8]) -> TxnDecision>(
        &mut self,
        mut check_transaction: L,
        timeout: Duration,
    ) -> Result<usize, ClientError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut answered = 0;
        loop {
            // Drive a broker pass: a Ping makes the connection do a `process` pass, which runs the
            // back-check scan and flushes any TxnChecks routed to this connection alongside the Pong.
            self.send(FrameType::Ping, &[])?;
            loop {
                match self.read_frame_or_timeout()? {
                    Some((FrameType::TxnCheck, body)) => {
                        self.answer_txn_check(&body, &mut check_transaction)?;
                        answered += 1;
                    }
                    // Round-ending cases (stop reading, re-check the deadline, re-Ping): a read timeout
                    // with no frame, or the Pong flush boundary (every routed check precedes or
                    // accompanies it in the same flush).
                    None | Some((FrameType::Pong, _)) => break,
                    Some((FrameType::Err, body)) => {
                        return Err(ClientError::Server(ServerError::from_wire(&body)))
                    }
                    // A stray frame (e.g. an Ok reply to a TxnCheckResult, or another frame on a mixed
                    // connection) is not what this loop is for: ignore it and keep draining the round.
                    Some(_) => {}
                }
            }
            if std::time::Instant::now() >= deadline {
                return Ok(answered);
            }
        }
    }

    /// Runs a full local transaction with the broker 2PC (#640 part 2): PREPARE a half message,
    /// run `local_txn_fn`, then COMMIT if it succeeded or ROLLBACK if it failed (or panicked-as-`Err`).
    /// This is the ergonomic transactional path: the half message is invisible until the local
    /// transaction commits, and if this producer CRASHES between prepare and resolve, the broker's
    /// back-check later asks this producer's registered listener
    /// ([`Client::register_transaction_listener`] + [`Client::run_transaction_listener`]) to settle the
    /// in-doubt transaction — so no half message is ever stuck, lost, or double-delivered.
    ///
    /// `txn` is the producer-supplied STABLE transaction id (use a UUID / snowflake / content hash so
    /// it survives a reconnect — the listener answers a back-check by THIS id). `local_txn_fn` runs the
    /// producer's own local transaction and returns `Ok(())` to commit or `Err(_)` to roll back; its
    /// error is propagated after the rollback. Returns the committed offset on a commit.
    ///
    /// # Errors
    /// Returns [`ClientError::LocalTransaction`] (wrapping the `local_txn_fn` error) after a successful
    /// rollback, [`ClientError::Server`] / a frame error from the prepare/commit/rollback, or
    /// [`ClientError::Body`] on an over-large field.
    pub fn transact<T: FnOnce() -> Result<(), E>, E: std::fmt::Display>(
        &mut self,
        txn: &TxnId,
        stream: &str,
        message: &PubBody<'_>,
        local_txn_fn: T,
    ) -> Result<u64, ClientError> {
        // PREPARE the half message (durable, invisible) under the stable id.
        self.prepare_with_id(txn, stream, message)?;
        // Run the producer's local transaction.
        match local_txn_fn() {
            Ok(()) => {
                // The local transaction committed: make the half message visible (exactly once).
                self.commit(txn)
            }
            Err(e) => {
                // The local transaction failed: discard the half message. Propagate the original error
                // after the rollback (a rollback failure supersedes it — the connection is in trouble).
                self.rollback(txn)?;
                Err(ClientError::LocalTransaction(e.to_string()))
            }
        }
    }

    /// Subscribes this connection's consume path to a NAMED stream's work-group (#588, M2-I10): the
    /// `SubTo` verb, the stream-addressed twin of [`Client::subscribe`]. Subsequent [`Client::fetch`] /
    /// [`Client::flow`] and [`Client::ack`] consume from and commit to THAT stream's own competing
    /// work-group (independent per stream, so the same group name in two streams is two unrelated
    /// cursors). The stream must already exist (declare or publish to it first); an EMPTY `stream`
    /// targets the default stream (equivalent to [`Client::subscribe`]). Requires the stream-addressing
    /// capability (see [`Client::declare_stream`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the subscription (capability not
    /// negotiated, an unknown stream, or a malformed name), [`ClientError::Body`] on an over-large
    /// field, or a frame/connection error.
    pub fn subscribe_to(&mut self, stream: &str, group: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_sub_to(
            &SubToBody {
                stream_id: stream.as_bytes(),
                group: group.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::SubTo, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    // ---- subject-addressed routing (#585, M2-I9) ----

    /// BINDs a subject PATTERN to a NAMED stream (#585, M2-I9): the `BindSubject` verb, the routing
    /// half of the subjects story. The broker validates the pattern through the #567 grammar
    /// (dot-separated tokens; `*` matches exactly one token, `>` matches one-or-more trailing tokens
    /// and is legal only as the final token), DECLARES `stream` if it does not exist yet (a
    /// subject-addressed publish needs a log to land in), registers `(pattern -> stream)` in the
    /// routing trie, and replies `Ok`. Idempotent — re-binding the same pattern to the same stream is
    /// a benign success. Requires the stream-addressing capability
    /// ([`ClientConfig::understands_streams`] confirmed via [`Client::streams_enabled`]); on an
    /// auth-enabled broker the verb additionally requires the `admin` scope (it mutates routing
    /// state, #631).
    ///
    /// After the bind, a [`Client::publish_subject`] whose literal subject the pattern covers routes
    /// to `stream`, and a [`Client::subscribe_subject`] resolves through the same trie. The
    /// resolution is FAIL-CLOSED single-home: a subject covered by ZERO bindings is rejected
    /// ([`ServerErrorCode`] `NoStreamForSubject` — the explicit beat over a silent NATS-style drop)
    /// and one covered by TWO OR MORE streams is rejected as ambiguous (`AmbiguousSubject`).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the bind (capability not negotiated, a
    /// malformed pattern/name, a missing `admin` scope, or a fork-bound rejection),
    /// [`ClientError::Body`] on an over-large field, or a frame/connection error.
    pub fn bind_subject(&mut self, stream: &str, pattern: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_bind_subject(
            &BindSubjectBody {
                stream_id: stream.as_bytes(),
                pattern: pattern.as_bytes(),
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::BindSubject, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Publishes a message BY SUBJECT (#585, M2-I9): the `PubSubject` verb, the subject-addressed
    /// twin of [`Client::publish_to`]. The broker resolves the LITERAL `subject` (wildcards live only
    /// on the bind/subscribe side, never in a published subject) through the routing trie under the
    /// fail-closed single-home rule — exactly ONE bound stream routes the append there, ZERO is a
    /// `NoStreamForSubject` reject, two-or-more is an `AmbiguousSubject` reject — and replies a
    /// `PubAck` with the offset assigned in the RESOLVED stream's own offset space. The publish body
    /// is the SAME [`PubBody`] every other produce carries, and the publish is at-least-once
    /// (server-ack, Level 1; the ack implies the covering fsync), exactly like [`Client::publish_to`].
    /// Requires the stream-addressing capability (see [`Client::bind_subject`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the publish (capability not negotiated,
    /// an unbound/ambiguous/malformed subject, or a non-server-ack level), [`ClientError::Body`] on
    /// an over-large field, [`ClientError::BadResponse`] on a malformed ack, or a frame/connection
    /// error.
    pub fn publish_subject(
        &mut self,
        subject: &str,
        message: &PubBody<'_>,
    ) -> Result<u64, ClientError> {
        // Force at-least-once server-ack (Level 1) on the carried body, exactly like `publish_to`:
        // the subject-addressed path accepts only that level this phase, and an old caller never set
        // a level bit, so this is a no-op for them and a guard against a mismatched method/wire.
        let at_least_once = PubBody {
            fire_and_forget: false,
            ..*message
        };
        let mut pub_body = Vec::new();
        encode_pub(&at_least_once, &mut pub_body).map_err(ClientError::Body)?;
        let mut body = Vec::new();
        encode_pub_subject(
            &PubSubjectBody {
                subject: subject.as_bytes(),
                pub_body: &pub_body,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::PubSubject, &body)?;
        match self.read_frame()? {
            (FrameType::PubAck, body) => {
                let ack = decode_pub_ack(&body).map_err(|_| {
                    ClientError::BadResponse("publish-subject reply was not an offset")
                })?;
                Ok(ack.offset)
            }
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Subscribes this connection's consume path BY SUBJECT (#585, M2-I9): the `SubSubject` verb,
    /// the subject-addressed twin of [`Client::subscribe_to`]. The broker resolves the LITERAL
    /// `subject` through the routing trie under the fail-closed single-home rule and binds this
    /// connection's subsequent [`Client::fetch`] / [`Client::ack`] to the RESOLVED stream's own
    /// competing work-`group`. An unbound subject is a `NoStreamForSubject` reject and one covered
    /// by two-or-more streams an `AmbiguousSubject` reject. Wildcards live on the BIND side
    /// ([`Client::bind_subject`] patterns): a wildcard in the SUBSCRIBED subject is an
    /// `InvalidSubject` reject this phase (the multi-stream wildcard fan-out subscribe is a flagged
    /// follow-up). Requires the stream-addressing capability (see [`Client::bind_subject`]).
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the subscription (capability not
    /// negotiated, an unbound/ambiguous/malformed/wildcard subject), [`ClientError::Body`] on an
    /// over-large field, or a frame/connection error.
    pub fn subscribe_subject(&mut self, subject: &str, group: &str) -> Result<(), ClientError> {
        let mut body = Vec::new();
        encode_sub_subject(
            &SubSubjectBody {
                subject: subject.as_bytes(),
                group: group.as_bytes(),
                // The sync client subscribes single-home for now (#594); filtered consume is a
                // client follow-up, so it never advertises the capability or sends filter_mode = 1.
                filter_mode: 0,
            },
            &mut body,
        )
        .map_err(ClientError::Body)?;
        self.send(FrameType::SubSubject, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, _) => Ok(()),
            (FrameType::Err, body) => Err(ClientError::Server(ServerError::from_wire(&body))),
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

    /// Buffers bytes from the socket until at least one complete frame sits at the front of
    /// `self.buf`, WITHOUT consuming it. The borrowing counterpart to [`Client::read_frame`] (#818):
    /// the delivery fan-in ([`Client::read_fetch_response`]) decodes each `Deliver` / `DeliverBatch`
    /// body directly out of `self.buf` and copies each surviving payload exactly once into its
    /// `Message`, then drains — avoiding the throwaway owned `Vec` (a heap alloc plus a full-body
    /// memcpy, a whole-batch copy for `DeliverBatch`) that `read_frame` materializes per frame. The
    /// decoded `Message`s handed to the caller are byte-for-byte identical either way.
    ///
    /// On return, `decode_frame(&self.buf)` is guaranteed to yield [`FrameDecode::Frame`] (the buffer
    /// is unchanged between the last decode here and the caller's).
    fn fill_frame(&mut self) -> Result<(), ClientError> {
        // See `read_frame_from`: `self.buf` grows ONLY via `extend_from_slice` after a successful
        // read, so a propagated read error leaves it holding exactly its valid bytes.
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
            let n = self.stream.read(&mut scratch[..read_size])?;
            if n == 0 {
                return Err(ClientError::Closed);
            }
            self.buf.extend_from_slice(&scratch[..n]);
        }
    }
}

/// Tunables for the batched-default streaming consumer (Tier-S, #550), opened by
/// [`Client::streaming_consumer_with`]. The defaults are the ergonomic batched path: a healthy fetch
/// window, periodic (not per-record) commit, and bounded read-ahead ON.
#[derive(Clone, Debug)]
pub struct StreamConsumerConfig {
    /// The fetch window's record cap: the `max_records` each `StreamFetch` pulls (the actual pull is
    /// additionally capped at the negotiated per-consumer credit, #292). Defaults to
    /// [`DEFAULT_STREAM_FETCH_RECORDS`]. A `0` is treated as `1` so the consumer always makes progress.
    pub max_records: u32,
    /// The fetch window's byte budget: the `max_bytes` each `StreamFetch` pulls (`0` = unbounded by
    /// bytes; the record count and the durable prefix still bind). This ALSO bounds the read-ahead
    /// buffer — the prefetched window obeys the same byte budget — so the consumer's outstanding
    /// memory is at most two windows of this size. Defaults to `0`.
    pub max_bytes: u64,
    /// The periodic-commit cadence: auto-commit the cumulative offset once every this-many fetched
    /// windows (and always on drain / [`StreamingConsumer::finish`]). Defaults to
    /// [`DEFAULT_STREAM_COMMIT_EVERY_BATCHES`]. A `0` is treated as `1` (commit after every window).
    /// This is the at-least-once knob: a crash redelivers everything fetched since the last commit.
    pub commit_every_batches: u32,
    /// The offset to begin consuming at: normally the consumer's last committed offset (so a reconnect
    /// resumes exactly where it left off and the uncommitted span redelivers). Defaults to `0` (the
    /// log's start).
    pub start_offset: u64,
    /// Whether bounded READ-AHEAD is on (the default): when `true`, the handle pipelines the NEXT
    /// window's `StreamFetch` the moment it reads the current batch, so the next response is already
    /// arriving while the caller processes — hiding the fetch round-trip behind processing. At most ONE
    /// window is ever in flight ahead (bounded by the same `max_records` / `max_bytes` budget), so the
    /// prefetch buffer never grows without bound. Set `false` for the strict request-then-process loop
    /// (the no-prefetch baseline), which delivers the SAME records in the SAME order.
    pub read_ahead: bool,
}

impl Default for StreamConsumerConfig {
    fn default() -> Self {
        StreamConsumerConfig {
            max_records: DEFAULT_STREAM_FETCH_RECORDS,
            max_bytes: 0,
            commit_every_batches: DEFAULT_STREAM_COMMIT_EVERY_BATCHES,
            start_offset: 0,
            read_ahead: true,
        }
    }
}

/// One batch handed back by [`StreamingConsumer::next_batch`]: the contiguous run of streaming
/// messages (Tier-S, #550) plus any in-band advisories the fetch surfaced. The consumer processes
/// `messages` and the handle commits the covered offset PERIODICALLY (not per record); the caller does
/// NOT ack these individually (a streaming message carries no fencing lease — `generation` is `0`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamBatch {
    /// The messages delivered in this window, in log order (empty when the stream is fully drained).
    pub messages: Vec<Message>,
    /// Dead-letter advisories surfaced during this window (usually empty).
    pub dead_letters: Vec<DeadLetter>,
    /// Truncation advisories surfaced during this window (usually empty).
    pub truncations: Vec<Truncation>,
    /// Gap markers surfaced during this window for a gap-marker-capable connection (usually empty).
    pub gaps: Vec<Gap>,
}

impl StreamBatch {
    /// Whether this batch delivered no messages: the signal the stream has drained to its durable head
    /// (a `next_batch` that returns an empty batch has caught up; the caller typically pauses or polls
    /// again). Advisories without messages also yield `true` here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// The ERGONOMIC batched-default streaming consumer (Tier-S, #550), opened by
/// [`Client::streaming_consumer`] / [`Client::streaming_consumer_with`]. This is the recommended way
/// to consume a streaming group, and it makes the BATCHED path the default: per [`StreamingConsumer::next_batch`] call it
/// fetches a WINDOW (one [`Client::stream_fetch`], delivered as a `DeliverBatch` when negotiated),
/// commits the cumulative offset PERIODICALLY ([`Client::stream_commit`]) rather than per record, and
/// (by default) PREFETCHES the next window while the caller processes the current one.
///
/// # Why this is the default
///
/// The per-record fetch-and-ack loop pays one fetch round-trip and one cursor-writing ack PER RECORD —
/// the dominant cost that makes a single durable consumer lose to NATS. Fetching a window amortizes
/// the round-trip across the whole batch, periodic cumulative commit removes the per-record ack, and
/// read-ahead hides the next fetch's latency behind the current batch's processing. The raw
/// [`Client::stream_fetch`] / [`Client::stream_commit`] pair remains the explicit precise-control
/// opt-out; this handle is the batched ergonomic default.
///
/// # Bounded read-ahead
///
/// When [`StreamConsumerConfig::read_ahead`] is on (the default), the handle pipelines the NEXT
/// window's `StreamFetch` request the instant it has read the current batch off the wire, so the next
/// response is already in flight (server-side work + the socket buffer) while the caller processes.
/// At most ONE window is outstanding ahead of the caller, and it is bounded by the SAME `max_records` /
/// `max_bytes` budget as the visible window — so the outstanding memory is at most two windows and the
/// prefetch buffer never grows without bound. Because this consumer reads its OWN offset over its OWN
/// connection (it is NOT a per-group server-side read-ahead buffer fanned out to many consumers), it
/// never duplicates a payload across consumers — the hazard a per-group prefetch would have.
///
/// # At-least-once preserved
///
/// The handle commits only offsets it has HANDED to the caller and whose window the commit cadence has
/// reached; a prefetched-but-not-yet-returned window is never committed. So a crash redelivers every
/// fetched-but-uncommitted record (including anything read-ahead pulled) and loses nothing — the same
/// consumer-managed at-least-once contract as the raw [`Client::stream_fetch`]. To tighten the
/// redeliver window, lower [`StreamConsumerConfig::commit_every_batches`] or call
/// [`StreamingConsumer::commit_now`] at a precise processed-up-to point.
///
/// # Errors and connection state
///
/// An IO error, a server error (e.g. the group is not streaming), or an unexpected frame leaves the
/// connection state undefined: drop the underlying [`Client`], exactly like an errored
/// [`Client::fetch_batch`]. A pending read-ahead request whose response is never drained is harmless
/// to the dropped connection.
#[derive(Debug)]
pub struct StreamingConsumer<'a> {
    client: &'a mut Client,
    /// The streaming group this handle commits to (the `StreamCommit` group name).
    group: String,
    /// The window size, commit cadence, and read-ahead policy.
    config: StreamConsumerConfig,
    /// The next offset to fetch from: advanced by the count of records each window delivers. This is
    /// the consumer's own cursor; it is what a reconnect would resume from.
    next_offset: u64,
    /// The highest offset the handle has COMMITTED up to (exclusive). Starts at `start_offset` (already
    /// durable from a prior run). The retention floor for this group is pinned here, not at
    /// `next_offset`.
    committed: u64,
    /// How many windows have been fetched since the last commit: when it reaches
    /// `commit_every_batches`, the handle commits up to `next_offset` and resets this to `0`.
    batches_since_commit: u32,
    /// The BOUNDED read-ahead slot: `Some(limit)` when a next-window `StreamFetch` has been pipelined
    /// and its response is not yet drained (the `limit` is the frame cap that read must honor); `None`
    /// when no prefetch is outstanding. At most one is ever held, which is what bounds the read-ahead.
    prefetch: Option<usize>,
    /// A drained-but-not-yet-returned read-ahead window, held when [`StreamingConsumer::commit_now`] had
    /// to clear the wire (a `StreamCommit` is a request/reply that cannot run with a prefetch response
    /// unread on the FIFO). The next [`StreamingConsumer::next_batch`] returns this BEFORE issuing a new
    /// fetch, so no record is lost and the at-most-one-window-ahead bound still holds (the stash IS that
    /// one window, just already materialized). `None` in the common path, where the periodic commit runs
    /// on an already-clean wire and never needs to drain a prefetch.
    stashed: Option<Fetch>,
}

impl StreamingConsumer<'_> {
    /// The effective per-window record cap (the configured `max_records`, floored at `1` so the
    /// consumer always makes progress). The actual pull is additionally capped at the negotiated
    /// per-consumer credit inside [`Client::stream_fetch`].
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
    /// advisories; an EMPTY batch ([`StreamBatch::is_empty`]) means the stream has drained to its
    /// durable head.
    ///
    /// The caller processes the returned `messages` and then calls `next_batch` again; it does NOT ack
    /// them individually (the handle commits cumulatively by offset). To force a commit at a precise
    /// processed-up-to point, call [`StreamingConsumer::commit_now`] between batches.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error (the group is not streaming, or Tier-S
    /// was not negotiated), or a malformed/over-cap response. On error the connection state is
    /// undefined; drop the [`Client`].
    pub fn next_batch(&mut self) -> Result<StreamBatch, ClientError> {
        let start = self.next_offset;
        // Read this window, in priority order: (1) a window a precise `commit_now` already drained and
        // stashed; (2) a pipelined read-ahead response outstanding on the wire; (3) a fresh synchronous
        // fetch. All three yield the SAME contiguous run starting at `start` — the read-ahead only moves
        // WHEN the request was written, never WHICH records come back.
        let fetch = if let Some(stashed) = self.stashed.take() {
            stashed
        } else if let Some(limit) = self.prefetch.take() {
            self.client.read_stream_fetch_response(limit)?
        } else {
            self.client
                .stream_fetch(start, self.window_records(), self.config.max_bytes)?
        };
        let delivered = u64::try_from(fetch.messages.len()).unwrap_or(u64::MAX);
        self.next_offset = self.next_offset.saturating_add(delivered);

        // Periodic cumulative commit FIRST, before any read-ahead is in flight. A `StreamCommit` is a
        // request/REPLY round-trip, and this is a single FIFO connection: committing while a pipelined
        // prefetch response sat unread would make the commit's `read_frame` consume the prefetch's
        // delivery instead of the commit's `Ok`. Doing the commit on a CLEAN wire (no prefetch
        // outstanding — the slot was `take`n above) keeps the FIFO unambiguous. Count this window, and
        // when the cadence is reached commit up to the consumer's cursor (exclusive) so retention
        // advances and the at-least-once redeliver window is bounded to the windows fetched since. An
        // empty window does not tick the cadence (no new ground) but still flushes any pending progress
        // so a drained stream durably checkpoints.
        if delivered > 0 {
            self.batches_since_commit = self.batches_since_commit.saturating_add(1);
            if self.batches_since_commit >= self.commit_cadence() {
                self.commit_now()?;
            }
        } else {
            self.commit_now()?;
        }

        // Bounded read-ahead: with the commit's round-trip settled, pipeline the NEXT window's request so
        // its response arrives while the caller processes this batch. Only when a non-empty window came
        // back (an empty window means the stream has drained: prefetching past the head would just
        // block), and only ONE is ever outstanding (`self.prefetch` holds at most one slot), which bounds
        // it. The prefetched window obeys the same `max_records` / `max_bytes` budget, so the outstanding
        // memory is at most two windows and never an unbounded buffer.
        if self.config.read_ahead && delivered > 0 {
            let limit = self.client.send_stream_fetch(
                self.next_offset,
                self.window_records(),
                self.config.max_bytes,
            )?;
            self.prefetch = Some(limit);
        }

        Ok(StreamBatch {
            messages: fetch.messages,
            dead_letters: fetch.dead_letters,
            truncations: fetch.truncations,
            gaps: fetch.gaps,
        })
    }

    /// Commits the cumulative offset NOW, up to the consumer's current cursor (every record handed to
    /// the caller so far): the precise-commit hook over the handle's periodic auto-commit. Idempotent —
    /// a no-op when nothing new has been fetched since the last commit. Use it to checkpoint at an exact
    /// processed boundary, or before pausing, so the at-least-once redeliver window is exactly the
    /// records not yet processed.
    ///
    /// # Errors
    /// Returns [`ClientError::Server`] if the server rejects the commit (the group is not streaming, or
    /// the offset is outside the retained window), or a frame or connection error.
    pub fn commit_now(&mut self) -> Result<(), ClientError> {
        // A `StreamCommit` is a request/reply round-trip on this single FIFO connection, so it cannot
        // run with a read-ahead response unread (the commit's `read_frame` would consume the prefetched
        // delivery). DRAIN any outstanding prefetch into the stash first, clearing the wire WITHOUT
        // losing the records: the next `next_batch` returns the stash. The prefetched window is NOT part
        // of `[committed, next_offset)` (the caller has not been handed it), so committing up to
        // `next_offset` after draining stays correct.
        if let Some(limit) = self.prefetch.take() {
            self.stashed = Some(self.client.read_stream_fetch_response(limit)?);
        }
        if self.next_offset <= self.committed {
            return Ok(());
        }
        self.client.stream_commit(&self.group, self.next_offset)?;
        self.committed = self.next_offset;
        self.batches_since_commit = 0;
        Ok(())
    }

    /// Drains any outstanding read-ahead response and COMMITS the consumer's cursor, returning the
    /// final committed offset (exclusive). Call this before dropping the handle so a pending periodic
    /// commit is flushed and a pipelined prefetch is not left half-read on the wire. After this the
    /// connection is clean for the next request.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, a server error, or a malformed response while draining
    /// the prefetch or committing.
    pub fn finish(mut self) -> Result<u64, ClientError> {
        // `commit_now` drains any outstanding read-ahead response into the stash (leaving the wire
        // framed) and commits up to the consumer's cursor. The stashed window's records are NOT
        // committed (the caller never processed them), so they redeliver on the next run — the
        // at-least-once contract. Dropping the stash here is correct: it was fetched, never handed out,
        // and `next_offset` never advanced past it.
        self.commit_now()?;
        Ok(self.committed)
    }

    /// The offset the handle will fetch from next (the consumer's cursor, exclusive of everything
    /// already delivered). A reconnect would resume from the last COMMITTED offset, not this.
    #[must_use]
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// The highest offset committed so far (exclusive): the durable checkpoint a crash would resume
    /// from. Everything in `[committed_offset(), next_offset())` is the at-least-once window that
    /// redelivers on a crash.
    #[must_use]
    pub fn committed_offset(&self) -> u64 {
        self.committed
    }
}

/// An auto-pipelining DURABLE producer (#508): the ergonomic high-throughput companion to the
/// awaited [`Client::produce`], opened by [`Client::pipelined_producer`].
///
/// # Why this exists
///
/// The broker group-commits produces: one `fdatasync` covers every produce a drain pass holds, so a
/// PIPELINED publisher (several produces in flight) pays one fsync for the whole window. But the
/// fully-synchronous [`Client::produce`] awaits each `PubAck` before sending the next frame, so a
/// SINGLE producer never has more than one produce in flight and the group commit has nothing to
/// amortize across: it pays one fsync PER publish, the single-producer durable-throughput floor.
///
/// This handle removes that floor without changing `produce`'s contract: it BUFFERS up to `window`
/// publishes (serializing each into an owned wire frame so the caller's input buffers are free
/// again the instant [`PipelinedProducer::produce`] returns), then writes the whole window as ONE
/// pipelined batch — the exact wire discipline of [`Client::produce_window`] — so the broker's
/// group commit collapses the window under a single fsync. On a tight single-producer durable loop
/// this lifts throughput from roughly one-publish-per-fsync to the group-commit rate.
///
/// # Durability contract (I2 preserved)
///
/// Every publish is at-least-once and ack-implies-durable, exactly like [`Client::produce`]: the
/// broker fsyncs the record before the `PubAck` exists. What changes is only WHEN this client
/// OBSERVES the ack. [`PipelinedProducer::produce`] returns as soon as the publish is buffered
/// (and possibly flushed-and-drained if it filled the window), which is BEFORE its ack is guaranteed
/// observed. To learn that a span of publishes is durably acked, call [`PipelinedProducer::flush`]
/// (drains the in-flight window's acks) or [`PipelinedProducer::finish`] (flushes and drains the
/// rest, returning the run's tally). A buffered-but-not-yet-flushed publish has been HANDED to this
/// handle but NOT yet written to the broker, so — as with any producer — a process crash before the
/// covering flush loses only those un-flushed publishes; nothing that has been acked is ever lost.
/// This is the standard pipelined-producer trade and is why the handle is a distinct, explicitly
/// chosen API rather than a silent change to [`Client::produce`].
///
/// # Errors and connection state
///
/// A flush drains exactly one reply per buffered publish, FIFO, the per-connection wire contract,
/// so the Nth ack belongs to the Nth publish. A server `Err` reply mid-window is drained (the
/// connection stays framed) and the FIRST one is returned by the flush; offsets acked before or
/// after it in the same window are durable on the broker. An IO error, an over-large field, or an
/// unexpected frame leaves the connection state undefined: drop the underlying [`Client`], exactly
/// like an errored [`Client::produce_window`].
#[derive(Debug)]
pub struct PipelinedProducer<'a> {
    client: &'a mut Client,
    /// The in-flight window: how many publishes are buffered before an automatic flush.
    window: usize,
    /// How many publishes are buffered (framed into `wire`) but not yet flushed. One reply is owed
    /// per buffered publish; the FIFO drain reads exactly this many replies. The replies are keyed
    /// by FRAME TYPE (`PubAck` vs `PubAckDuplicate`), the per-connection wire contract, so the drain
    /// needs only the COUNT, not per-publish state — exactly like [`Client::produce_window`], which
    /// drains `messages.len()` replies.
    buffered: usize,
    /// The coalesced wire bytes for every buffered publish, written with one syscall on flush. The
    /// publishes are already framed (`encode_frame`), so a flush is a single `write_all`.
    wire: Vec<u8>,
}

/// A COALESCING at-most-once (QoS-0) producer: the batched companion to [`Client::produce_fire_and_forget`],
/// opened by [`Client::fire_and_forget_producer`]. Each [`send`](FireForgetProducer::send) frames one
/// fire-and-forget `Pub` into a shared wire buffer and writes the buffer to the socket with ONE
/// `write_all` only when it reaches [`STREAM_FLUSH_BYTES`] (or on an explicit
/// [`flush`](FireForgetProducer::flush)), instead of one `write_all` syscall per publish. For a tight
/// single-producer at-most-once loop this collapses thousands of tiny per-message socket writes into a
/// handful of large ones — the same coalescing a core pub/sub client (e.g. NATS) does — lifting QoS-0
/// send throughput several-fold without changing the wire bytes the broker decodes.
///
/// No reply is read (a fire-and-forget `Pub` is unacked by contract), so there is no flow-control
/// window: it pushes as fast as the socket drains, and TCP backpressure is the only pacing. The
/// buffered (not-yet-flushed) tail is not on the broker yet; this is at-most-once either way (the
/// broker may itself drop a send under its fire-and-forget token bucket), so a lost tail on a
/// mid-stream IO error is consistent with the no-guarantee contract. Call
/// [`flush`](FireForgetProducer::flush) after the last [`send`](FireForgetProducer::send) to push the
/// final partial batch.
#[derive(Debug)]
pub struct FireForgetProducer<'a> {
    client: &'a mut Client,
    /// The coalesced wire bytes for the buffered publishes, written with one `write_all` on flush.
    wire: Vec<u8>,
    /// Scratch reused to encode each publish body before it is framed into `wire`.
    body: Vec<u8>,
}

impl FireForgetProducer<'_> {
    /// Buffers one AT-MOST-ONCE (QoS-0) publish, flushing the coalesced buffer to the socket with one
    /// `write_all` when it reaches [`STREAM_FLUSH_BYTES`]. The publish's `fire_and_forget` field is
    /// forced SET on the wire (the method's contract), exactly like [`Client::produce_fire_and_forget`].
    /// No reply is read; the caller's input buffers are free to reuse on return.
    ///
    /// # Errors
    /// [`ClientError::Body`] / [`ClientError::Frame`] on an encode failure, or an IO error on the
    /// triggered flush `write_all`. On an IO error the connection state is undefined (drop the
    /// [`Client`]).
    pub fn send(&mut self, message: &PubBody<'_>) -> Result<(), ClientError> {
        self.body.clear();
        let faf = PubBody {
            fire_and_forget: true,
            ..*message
        };
        encode_pub(&faf, &mut self.body).map_err(ClientError::Body)?;
        encode_frame(FrameType::Pub, &self.body, &mut self.wire).map_err(ClientError::Frame)?;
        if self.wire.len() >= STREAM_FLUSH_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    /// Writes any buffered-but-unflushed publishes to the socket with one `write_all`; a no-op when the
    /// buffer is empty. Call this after the last [`send`](FireForgetProducer::send) so the final partial
    /// batch reaches the broker.
    ///
    /// # Errors
    /// An IO error on the `write_all` (the connection state is then undefined).
    pub fn flush(&mut self) -> Result<(), ClientError> {
        if !self.wire.is_empty() {
            self.client.stream.write_all(&self.wire)?;
            self.wire.clear();
        }
        Ok(())
    }
}

impl PipelinedProducer<'_> {
    /// The configured in-flight window: how many publishes are buffered before an automatic flush.
    #[must_use]
    pub fn window(&self) -> usize {
        self.window
    }

    /// How many publishes are buffered but not yet flushed to the broker.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Buffers one DURABLE (at-least-once) publish into the in-flight window. Returns immediately
    /// once the publish is serialized and buffered (its input buffers are free to reuse); when the
    /// buffer reaches the window it is AUTOMATICALLY flushed (written and its acks drained), so this
    /// call returns the flush's tally in that case and an empty tally otherwise.
    ///
    /// The publish's `fire_and_forget` field is forced CLEAR: a QoS-0 publish has no reply and would
    /// desynchronize the FIFO window. Per-publish `dedup` is honored exactly as in
    /// [`Client::produce_dedup`].
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an over-large field (the encode), or — when this publish
    /// triggered an automatic flush — on an IO error, an unexpected frame, or the first server error
    /// in the flushed window.
    pub fn produce(&mut self, message: &PubBody<'_>) -> Result<FlushSummary, ClientError> {
        let mut body = Vec::new();
        // Force at-least-once: a fire-and-forget publish gets no reply and would break the FIFO
        // one-reply-per-publish drain this window depends on, exactly as `produce_window` forces it.
        let at_least_once = PubBody {
            fire_and_forget: false,
            ..*message
        };
        encode_pub(&at_least_once, &mut body).map_err(ClientError::Body)?;
        // Frame and APPEND to the coalesced wire buffer now, so the caller's `message` borrows are
        // not retained past this call (the producer owns the bytes it will flush).
        encode_frame(FrameType::Pub, &body, &mut self.wire).map_err(ClientError::Frame)?;
        self.buffered += 1;
        if self.buffered >= self.window {
            self.flush()
        } else {
            Ok(FlushSummary::default())
        }
    }

    /// Flushes the buffered window: writes every buffered publish in ONE syscall (so the broker's
    /// group commit covers them with one fsync) and drains exactly one reply per publish, FIFO,
    /// returning the flushed window's tally. After a clean flush nothing is buffered and the
    /// underlying [`Client`] is fully usable for any other call. An empty buffer is a no-op that
    /// never touches the wire.
    ///
    /// Every returned ack means the record is fsynced-durable (I2). A server `Err` reply is drained
    /// and the FIRST one returned as the call's error, after the whole window has been drained so
    /// the connection stays framed (the [`Client::produce_window`] discipline).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an unexpected frame, or the first server error in
    /// the flushed window. On any error the connection state is undefined: drop the [`Client`].
    pub fn flush(&mut self) -> Result<FlushSummary, ClientError> {
        let count = self.buffered;
        if count == 0 {
            return Ok(FlushSummary::default());
        }
        // Phase 1: one coalesced write of the whole buffered window. This is what puts all N
        // produces in front of the actor's drain loop as one group-commit batch.
        self.client.stream.write_all(&self.wire)?;
        self.wire.clear();
        // Phase 2: drain exactly one reply per buffered publish, FIFO. A server `Err` consumes its
        // slot and is remembered; the drain continues so the connection is not desynchronized,
        // exactly like `produce_window`.
        let mut summary = FlushSummary::default();
        let mut first_err: Option<ClientError> = None;
        for _ in 0..count {
            let (ty, body) = self.client.read_frame()?;
            match classify_pub_reply(ty, &body)? {
                PubReply::Acked(offset) => {
                    summary.acked += 1;
                    summary.last_offset = Some(offset);
                }
                PubReply::Duplicate(offset) => {
                    summary.acked += 1;
                    summary.duplicates += 1;
                    summary.last_offset = Some(offset);
                }
                PubReply::ServerErr(msg) => {
                    if first_err.is_none() {
                        first_err = Some(ClientError::Server(msg));
                    }
                }
                // A cluster NotLeader redirect (#735): the pipelined produces did NOT land on this
                // non-leader node. Remember the typed redirect (with the leader hint) as the first error;
                // the drain continues so the connection stays framed.
                PubReply::NotLeader(leader_hint) => {
                    if first_err.is_none() {
                        first_err = Some(ClientError::NotLeader { leader_hint });
                    }
                }
                PubReply::Pong => return Err(ClientError::Unexpected(FrameType::Pong)),
            }
        }
        self.buffered = 0;
        match first_err {
            Some(e) => Err(e),
            None => Ok(summary),
        }
    }

    /// Flushes any remaining buffered publishes and returns the FINAL flush's tally (empty if
    /// nothing was buffered). Consumes the handle; after it returns the borrowed [`Client`] is free
    /// for any other call. Call this (or [`PipelinedProducer::flush`]) before relying on the tail
    /// of a producing run being durably acked, since a publish that was buffered but never flushed
    /// has not yet reached the broker.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an unexpected frame, or the first server error in
    /// the final flushed window.
    pub fn finish(mut self) -> Result<FlushSummary, ClientError> {
        self.flush()
    }
}

/// The tally a [`PipelinedProducer`] flush returns (#508): the acks observed for the publishes the
/// flush drained. A flush drains one reply per buffered publish, so `acked` plus the server errors
/// the flush's `Err` surfaces account for every publish in that window. This is the pipelined
/// analog of the per-call `Vec<ProduceAck>` [`Client::produce_window`] returns, summarized because
/// the handle's value is the throughput, not a per-message offset transcript (a caller that needs
/// every offset should drive [`Client::produce_window`] directly).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushSummary {
    /// Publishes acknowledged in this flush (including dedup hits).
    pub acked: u64,
    /// How many of `acked` were `PubAckDuplicate` dedup hits.
    pub duplicates: u64,
    /// The offset carried by the last ack observed in this flush, if any.
    pub last_offset: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_streaming_fetch_window_is_pinned_at_2048() {
        // #1027 PIN: 2048 is peer-comparable consumer sizing (a stock Kafka consumer pulls 500+
        // records / ~50 MB per poll), the measured ~1M rec/s streaming-drain plateau point, and
        // exactly the broker's default per-consumer credit ceiling the pull is capped at; 256 left
        // a tight drain loop round-trip-latency-bound. This FAILS if the default drifts.
        assert_eq!(DEFAULT_STREAM_FETCH_RECORDS, 2048);
        assert_eq!(
            StreamConsumerConfig::default().max_records,
            DEFAULT_STREAM_FETCH_RECORDS,
            "the config default rides the pinned constant"
        );
    }

    #[test]
    fn client_error_source_chain_exposes_the_wrapped_inner_cause() {
        // #892: a WRAPPING ClientError variant now overrides `source()` to return its typed inner
        // error, so chain-walkers (`anyhow`/`eyre` `.source()` loops, structured loggers) and
        // `downcast_ref` reach the root cause instead of stopping at the wrapper. Before the fix the
        // impl body was empty and `source()` returned `None` for every variant.
        use std::error::Error as _;

        // Io wraps an io::Error: the source is present AND downcasts back to the concrete kind.
        let io = ClientError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        let src = io
            .source()
            .expect("Io must expose its wrapped io::Error as source()");
        let inner: &io::Error = src
            .downcast_ref::<io::Error>()
            .expect("the source downcasts back to io::Error");
        assert_eq!(inner.kind(), io::ErrorKind::UnexpectedEof);

        // Frame wraps a FrameError.
        let frame = ClientError::Frame(FrameError::EmptyFrame);
        assert!(
            frame.source().is_some(),
            "Frame must expose its wrapped FrameError as source()"
        );

        // Decompress carries its inner cause in the `source` field.
        let decomp = ClientError::Decompress {
            source: DecompressError::CorruptStream,
            offset: 7,
            generation: 3,
        };
        assert!(
            decomp.source().is_some(),
            "Decompress must expose its wrapped DecompressError as source()"
        );

        // A LEAF / stringly variant genuinely has no inner error, so it must still return None
        // (the discriminating half: we did NOT blanket-return Some).
        let leaf = ClientError::BadResponse("nope");
        assert!(
            leaf.source().is_none(),
            "a leaf variant carries no inner error and must return None"
        );
        let closed = ClientError::Closed;
        assert!(closed.source().is_none(), "a unit variant has no source");
    }

    #[test]
    fn ingest_delivery_caps_the_aggregate_decompressed_bytes() {
        // #879: the running aggregate of materialized payload bytes is bounded across a fetch window,
        // not just per-record. Once the running total would exceed the ceiling, the batch is poisoned
        // (BadResponse) and the over-cap record (and every later one) is NOT materialized — so a
        // credit-bounded fetch of many tiny high-ratio frames can never OOM the client.
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

        // Two records (800 bytes) fit under the 1000-byte cap.
        ingest_delivery(&rec(0), &mut messages, &mut poison, &mut total, cap);
        ingest_delivery(&rec(1), &mut messages, &mut poison, &mut total, cap);
        assert!(poison.is_none(), "under the cap nothing is poisoned");
        assert_eq!(messages.len(), 2);
        assert_eq!(total, 800);

        // The third record (1200 total) crosses the cap: the batch is poisoned and it is NOT pushed.
        ingest_delivery(&rec(2), &mut messages, &mut poison, &mut total, cap);
        assert!(
            matches!(poison, Some(ClientError::BadResponse(_))),
            "crossing the cap poisons the batch"
        );
        assert_eq!(messages.len(), 2, "the over-cap record is not materialized");

        // A subsequent record is drained un-materialized (the poison short-circuits ingest).
        ingest_delivery(&rec(3), &mut messages, &mut poison, &mut total, cap);
        assert_eq!(
            messages.len(),
            2,
            "later records are dropped while poisoned"
        );
    }

    use ironbus_core::clock::Clock as _; // the monotonic seam for the serve loop's #95 beacon
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_proto::message::{
        decode_connect, decode_pub, encode_dead_letter, encode_deliver, encode_info,
        encode_pub_ack, pub_ack_level, DeadLetterBody, DeliverBody, InfoBody, PubAckBody, PubDedup,
        DEAD_LETTER_MAX_DELIVER, PUB_FLAG_FIRE_AND_FORGET,
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
                consume_longpoll_ms: 0,
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
                sync_max_dirty_bytes: 0,
                // The write-path codec under test (#430): `None` for every historical test
                // (byte-identical broker), `Lz4` for the transparency end-to-end test.
                compression,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap();
        spawn_serving(engine)
    }

    /// Like [`start_server_with`] but configures a SHORT back-check schedule (#640 part 2) so an
    /// over-the-wire test can drive the broker back-check WITHOUT waiting out the production 30 s
    /// timeout: a 0-nanosecond timeout (a Prepared half is immediately eligible) and a 1-attempt cap (the
    /// terminal default fires on the first attempt), with a roomy default credit. The server runs on the
    /// real `SystemClock`, so the schedule is driven by the producer's own listener-loop passes.
    fn start_server_with_back_check(
        timeout: u64,
        max_attempts: u32,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let mut engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
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
        .unwrap();
        engine.set_back_check_config(ironbus_core::txn::BackCheckConfig {
            timeout,
            retry: 1, // floored to 1; with a real clock every scan pass is past the 1 ns retry
            max_attempts,
            batch: 256,
        });
        spawn_serving(engine)
    }

    /// Spawns the append actor over `engine` and the wire serve loop on a fresh ephemeral port,
    /// returning the bound address, the shutdown flag, and the serve thread handle (shared by the
    /// `start_server_*` helpers).
    fn spawn_serving(
        engine: Engine<InMemoryFs, SystemClock>,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
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

    /// Opens an in-memory test engine with the shared default config, extracted so the client-TLS
    /// integration test can reuse it.
    #[cfg(feature = "tls")]
    fn open_test_engine(
        consumer_credit: u32,
        consumer_credit_bytes: u64,
        compression: ironbus_core::compress::Codec,
    ) -> Engine<InMemoryFs, SystemClock> {
        Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
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
                compression,
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    // A long-lived self-signed server cert + key for "localhost", and a DIFFERENT (wrong) trust
    // anchor, for the client-TLS integration test. Embedded (rcgen pulls banned ring).
    #[cfg(feature = "tls")]
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
    #[cfg(feature = "tls")]
    const TLS_SERVER_KEY: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWd4kisc5NnK6Nv0I
RL0rrbnn9ozoIOti7I4eisF3CHWhRANCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+A
-----END PRIVATE KEY-----
";
    #[cfg(feature = "tls")]
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

    /// Spins a TLS-terminating in-memory broker (ADR-0004 / #957): the same engine + serve loop as
    /// [`spawn_serving`], but every accepted connection completes a TLS 1.3 handshake first.
    #[cfg(feature = "tls")]
    fn spawn_serving_tls(
        engine: Engine<InMemoryFs, SystemClock>,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let (handle_engine, _actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_config =
            ironbus_server::tls::server_config_from_pem(TLS_SERVER_CERT, TLS_SERVER_KEY).unwrap();
        let tls =
            ironbus_server::server::TlsTermination::with_config(std::sync::Arc::new(server_config));
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

    /// End-to-end client TLS (ADR-0004 / #957): a `Client` VERIFIES the broker and connects over a real
    /// TLS 1.3 session (so its `Connect`/credential travels encrypted), then produces over it. A client
    /// pointed at the WRONG trust anchor fails the handshake — mandatory verification, no plaintext
    /// fallback.
    #[cfg(feature = "tls")]
    #[test]
    fn a_client_produces_over_a_verified_tls_connection_and_a_wrong_anchor_is_rejected() {
        let engine = open_test_engine(64, 0, ironbus_core::compress::Codec::None);
        let (addr, shutdown, handle) = spawn_serving_tls(engine);

        // Correct trust anchor: verify the broker, connect over TLS 1.3, and produce.
        let config = ClientConfig {
            tls: Some(crate::tls::TlsClientConfig::new(
                TLS_SERVER_CERT.to_vec(),
                "localhost",
            )),
            ..Default::default()
        };
        let mut client = Client::connect_with(addr, &config)
            .expect("the client verifies the broker and connects");
        let offset = client
            .produce(&proto::PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"produced-over-client-tls",
            })
            .expect("a produce travels over the TLS connection");
        assert_eq!(offset, 0, "the produce is durable at offset 0");

        // Wrong trust anchor: the server certificate does not verify, so the handshake FAILS at connect.
        let bad = ClientConfig {
            tls: Some(crate::tls::TlsClientConfig::new(
                TLS_OTHER_CERT.to_vec(),
                "localhost",
            )),
            ..Default::default()
        };
        assert!(
            Client::connect_with(addr, &bad).is_err(),
            "a client with the wrong trust anchor must be rejected at the TLS handshake"
        );

        shutdown.store(true, Ordering::Release);
        drop(client);
        let _ = handle.join();
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

    /// A connected loopback TCP pair `(client, server)`, both ends owned by the caller so a test can
    /// drive reads and writes deterministically with no background thread. `connect` completes into
    /// the listener backlog, so the subsequent `accept` returns the peer end.
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn read_frame_from_reassembles_a_large_frame_dribbled_in_pieces() {
        // #819: a frame far larger than the per-read cap is completed by sizing each read from the
        // decoder's `needed` hint (clamped at READ_CAP), so a ~1 MiB frame takes a handful of capped
        // reads rather than one giant buffer. Dribbling it in small pieces from the peer — with the
        // reader stitching between pieces — must reassemble the exact bytes, proving the needed-hint
        // sizing never drops or duplicates a byte across the many partial reads.
        let body = vec![0xABu8; 1_000_000]; // >> READ_CAP, forcing several capped reads
        let wire = frame(FrameType::Deliver, &body);

        let (mut client, mut server) = tcp_pair();
        let wire_for_writer = wire.clone();
        let writer = std::thread::spawn(move || {
            // Hand the bytes over in small chunks so the reader must stitch many partial reads; the
            // main thread consumes concurrently, so these writes drain and never block.
            for chunk in wire_for_writer.chunks(7000) {
                server.write_all(chunk).unwrap();
                server.flush().unwrap();
            }
        });

        let mut buf = Vec::new();
        let (ty, got) = read_frame_from(&mut client, &mut buf).unwrap();
        writer.join().unwrap();
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

    #[test]
    fn a_read_timeout_mid_frame_leaves_the_buffer_uncorrupted_and_a_retry_completes() {
        // #819 THE cancellation-/error-safety guarantee (sync): `buf` grows ONLY by
        // `extend_from_slice` AFTER a read returns bytes — never pre-grown with placeholder zeros. So
        // a read that fails mid-assembly (here a REAL socket read timeout -> WouldBlock/TimedOut,
        // propagated via `?`) must leave `buf` holding EXACTLY the valid bytes received so far, with
        // no zero pollution, and a retry on that SAME buffer must complete the frame with no desync
        // (no spurious EmptyFrame, no garbage decode).
        let body = vec![0x5Au8; 8000];
        let wire = frame(FrameType::Deliver, &body);
        let split = 100; // an arbitrary partial prefix, mid-frame

        let (mut client, mut server) = tcp_pair();
        client
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();

        // Only the first `split` bytes are available; the rest is withheld so the fill loop blocks and
        // times out mid-frame.
        server.write_all(&wire[..split]).unwrap();
        server.flush().unwrap();

        let mut buf = Vec::new();
        let err = read_frame_from(&mut client, &mut buf).unwrap_err();
        assert!(
            matches!(err, ClientError::Io(_)),
            "an idle-socket read times out as an IO error, got {err:?}"
        );
        // THE INVARIANT: `buf.len()` equals the count of valid buffered bytes — no zero padding.
        assert_eq!(
            buf.len(),
            split,
            "buf.len() equals the valid buffered byte count after the timeout"
        );
        assert_eq!(
            buf,
            &wire[..split],
            "the buffered bytes are the exact prefix, not zero pollution"
        );

        // The rest arrives; retrying on the same (pollution-free) buffer completes the frame cleanly.
        server.write_all(&wire[split..]).unwrap();
        server.flush().unwrap();
        let (ty, got) = read_frame_from(&mut client, &mut buf).unwrap();
        assert_eq!(ty, FrameType::Deliver);
        assert_eq!(
            got, body,
            "the retry reassembles the full frame — no desync"
        );
        assert!(buf.is_empty(), "the completed frame drained cleanly");
    }

    #[test]
    fn read_frame_from_batches_small_frames_from_a_single_read() {
        // #819 non-regression (sync): sizing the read from the `needed` hint must NOT lose the
        // small-frame batching the client relies on — one socket read can pull several tiny frames.
        // Two small frames written together are pulled in one read; the first `read_frame_from`
        // returns frame A while frame B stays BUFFERED (`buf` non-empty), and a second call returns B
        // with no further bytes sent — proving the trailing frame was batched, not dropped.
        let a = frame(FrameType::Info, b"alpha");
        let b = frame(FrameType::Pong, b"");
        let mut both = a.clone();
        both.extend_from_slice(&b);

        let (mut client, mut server) = tcp_pair();
        client
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        server.write_all(&both).unwrap();
        server.flush().unwrap();

        let mut buf = Vec::new();
        let (ty_a, body_a) = read_frame_from(&mut client, &mut buf).unwrap();
        assert_eq!(ty_a, FrameType::Info);
        assert_eq!(body_a, b"alpha");
        assert!(
            !buf.is_empty(),
            "frame B was batched into the same read and stays buffered"
        );

        // No more bytes are sent; B decodes purely from the buffer.
        let (ty_b, body_b) = read_frame_from(&mut client, &mut buf).unwrap();
        assert_eq!(ty_b, FrameType::Pong);
        assert!(body_b.is_empty());
        assert!(buf.is_empty(), "both frames drained");
    }

    /// A one-shot listener like [`raw_server`] that ALSO captures every byte the client sends: it
    /// writes `script` up front (the handshake `Info` and any `PubAck` replies the client will read
    /// off its own buffer), then drains the client's request bytes into a buffer the returned join
    /// handle yields after the client closes. Lets a test assert the exact WIRE the client produced
    /// (e.g. the `Connect` body or the `Pub` flags it stamped), which a real server would consume
    /// internally. The caller decodes the captured frames with [`decode_frame`].
    fn capturing_server(
        script: Vec<u8>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
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

    /// Decodes every whole frame in `bytes` into `(type, body)` pairs (the captured-request decoder
    /// for the wire-assertion tests). Panics on a malformed or incomplete trailing frame, which in a
    /// test means the client wrote something unexpected.
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
                FrameDecode::Incomplete { .. } => panic!("incomplete trailing frame in capture"),
            }
        }
        out
    }

    /// The framed `Info` reply a `capturing_server` script needs so [`Client::connect_with`] completes
    /// its handshake: an empty advertisement (the client keeps its local defaults), which is all these
    /// wire-assertion tests need past the handshake.
    fn empty_info_frame() -> Vec<u8> {
        let mut info_body = Vec::new();
        encode_info(&InfoBody::default(), &mut info_body);
        frame(FrameType::Info, &info_body)
    }

    #[test]
    fn produce_with_ack_level_stamps_the_level_into_the_pub_flags_on_the_wire() {
        // #496: produce_with_ack_level encodes each level into the PUB body flags exactly as the
        // server's `pub_ack_level` decodes it. We capture the bytes the client sends and decode the
        // PUB bodies: Level 0 sets the canonical fire-and-forget bit (no reply read), Level 1 sets the
        // canonical Level-1 encoding (no faf bit, ack-level field 0), Level 2 sets the ack-level field
        // to 2. A pre-set ack-level bit on the caller's flags is REPLACED, never OR-ed.
        let mut script = empty_info_frame();
        // The L1 and L2 produces each await one PubAck; L0 reads no reply. Two acks scripted (FIFO).
        let mut ack0 = Vec::new();
        encode_pub_ack(&PubAckBody { offset: 0 }, &mut ack0);
        let mut ack1 = Vec::new();
        encode_pub_ack(&PubAckBody { offset: 1 }, &mut ack1);
        script.extend(frame(FrameType::PubAck, &ack0));
        script.extend(frame(FrameType::PubAck, &ack1));
        let (addr, handle) = capturing_server(script);

        let mut c = Client::connect(addr).unwrap();
        // A caller who set a stray ack-level bit (value 2 here): the method must REPLACE it with the
        // chosen level, never combine, so the L1 publish below still decodes as Level 1.
        let stray = 2u8 << PUB_FLAG_ACK_LEVEL_SHIFT;
        let base = PubBody {
            flags: stray,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"p",
        };
        // Level 0: returns no offset (QoS-0), sets the faf bit.
        assert_eq!(
            c.produce_with_ack_level(&base, AckLevel::NoAck).unwrap(),
            None
        );
        // Level 1: returns the assigned offset.
        assert_eq!(
            c.produce_with_ack_level(&base, AckLevel::ServerAck)
                .unwrap(),
            Some(0)
        );
        // Level 2: returns the assigned offset (server falls back to L1-await this phase, #495).
        assert_eq!(
            c.produce_with_ack_level(&base, AckLevel::ServerAndClientAck)
                .unwrap(),
            Some(1)
        );
        drop(c);

        let captured = handle.join().unwrap();
        let frames = decode_all_frames(&captured);
        // Connect, then three Pub frames in order (no reply was read for L0, so its frame was still
        // sent first).
        assert_eq!(frames[0].0, FrameType::Connect, "the handshake Connect");
        let pubs: Vec<&(FrameType, Vec<u8>)> = frames
            .iter()
            .filter(|(t, _)| *t == FrameType::Pub)
            .collect();
        assert_eq!(pubs.len(), 3, "one Pub frame per produce");

        // Level 0: the canonical fire-and-forget bit, and `pub_ack_level` reads it as NoAck.
        let l0 = decode_pub(&pubs[0].1).unwrap();
        assert_ne!(
            l0.flags & PUB_FLAG_FIRE_AND_FORGET,
            0,
            "Level 0 sets the canonical fire-and-forget bit"
        );
        assert_eq!(pub_ack_level(l0.flags), AckLevel::NoAck);

        // Level 1: no faf bit, ack-level field cleared (the stray bit was replaced), decodes as ServerAck.
        let l1 = decode_pub(&pubs[1].1).unwrap();
        assert_eq!(
            l1.flags & PUB_FLAG_FIRE_AND_FORGET,
            0,
            "Level 1 is not fire-and-forget"
        );
        assert_eq!(
            l1.flags & PUB_FLAG_ACK_LEVEL_MASK,
            0,
            "Level 1 is the canonical zero ack-level encoding (the stray bit was replaced)"
        );
        assert_eq!(pub_ack_level(l1.flags), AckLevel::ServerAck);

        // Level 2: the ack-level field is exactly 2, decodes as ServerAndClientAck.
        let l2 = decode_pub(&pubs[2].1).unwrap();
        assert_eq!(
            (l2.flags & PUB_FLAG_ACK_LEVEL_MASK) >> PUB_FLAG_ACK_LEVEL_SHIFT,
            2,
            "Level 2 stamps the ack-level field to 2"
        );
        assert_eq!(pub_ack_level(l2.flags), AckLevel::ServerAndClientAck);
    }

    #[test]
    fn produce_with_ack_level_routes_each_level_against_a_real_server() {
        // #496/#495 end-to-end: against the REAL server, Level 0 gets NO reply yet lands durably, and
        // Levels 1 and 2 each return their assigned offset (the server acks L2 like L1 this phase). A
        // following fetch sees all three records in log order, proving every level appended.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let body = |p: &'static [u8]| PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p,
        };
        // Level 0: no reply, no offset (the default fire-and-forget bucket is off, so it appends).
        assert_eq!(
            c.produce_with_ack_level(&body(b"l0"), AckLevel::NoAck)
                .unwrap(),
            None,
            "Level 0 returns no offset (QoS-0 no-reply)"
        );
        // Level 1: the at-least-once PubAck at offset 1.
        assert_eq!(
            c.produce_with_ack_level(&body(b"l1"), AckLevel::ServerAck)
                .unwrap(),
            Some(1),
            "Level 1 returns the assigned offset, durable-on-return"
        );
        // Level 2: the server falls back to a Level-1 await this phase (#495), so a PubAck at offset 2.
        assert_eq!(
            c.produce_with_ack_level(&body(b"l2"), AckLevel::ServerAndClientAck)
                .unwrap(),
            Some(2),
            "Level 2 falls back to a Level-1 PubAck this phase (#495); ProduceConfirm is #497"
        );
        // All three records are durable in log order, proving the L0 no-reply produce also landed and
        // did not desynchronize the stream for the L1/L2 awaits that followed it.
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 3, "all three levels appended");
        assert_eq!(messages[0].payload, b"l0");
        assert_eq!(messages[1].payload, b"l1");
        assert_eq!(messages[2].payload, b"l2");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn produce_confirmed_returns_consumed_once_a_consumer_acks_against_a_real_server() {
        // #497 end-to-end against the REAL wire server: a producer calls `produce_confirmed` (send L2,
        // await the durability PubAck, then poll for the ProduceConfirm). A SEPARATE consumer thread
        // fetches the record and acks it, which fires the server->producer Consumed confirm. The
        // producer's call returns `Consumed` keyed to the produced offset.
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect(addr).unwrap();

        // The consumer runs on its own thread: it fetches the one record and acks it (in the default
        // group, the broker's designated confirm group), which is what fires the producer's confirm.
        let consumer = std::thread::spawn({
            move || {
                let mut c = Client::connect(addr).unwrap();
                // Retry the fetch until the record is visible (the producer's L2 publish lands first).
                loop {
                    let messages = c.fetch(10).unwrap().messages;
                    if let Some(m) = messages.first() {
                        assert!(c.ack(m.offset, m.generation).unwrap());
                        return m.offset;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });

        let body = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"l2-confirmed",
        };
        let confirmation = producer
            .produce_confirmed(&body, Duration::from_secs(5))
            .unwrap();
        let acked_offset = consumer.join().unwrap();
        assert_eq!(
            confirmation.offset, acked_offset,
            "the confirm is keyed to the produced offset"
        );
        assert_eq!(
            confirmation.outcome,
            ConfirmOutcome::Consumed,
            "a consumer ack confirms the L2 produce as consumed"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn produce_confirmed_reports_local_timeout_when_no_consumer_acks() {
        // #497: with no consumer ever acking, `produce_confirmed` returns `LocalTimeout` once the
        // caller's deadline elapses (the record stayed durable; only its consumed-confirmation is
        // pending). The broker-side TTL is far longer than this local deadline, so the LOCAL deadline
        // is what fires here, exactly as documented.
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect(addr).unwrap();
        let body = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"unconfirmed",
        };
        let confirmation = producer
            .produce_confirmed(&body, Duration::from_millis(150))
            .unwrap();
        assert_eq!(
            confirmation.outcome,
            ConfirmOutcome::LocalTimeout,
            "no consumer acked within the local deadline"
        );
        // The record is durable regardless: a fetch sees it.
        assert_eq!(producer.fetch(10).unwrap().messages.len(), 1);

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn connect_with_sends_the_configured_default_ack_level_in_the_connect_body() {
        // #496: a ClientConfig default_ack_level is carried in the Connect handshake body. We capture
        // the Connect frame and decode it, asserting the raw level value the client sent matches the
        // configured AckLevel. (The server echo in Info is #497; here we prove the CLIENT puts it on
        // the wire, the in-scope half of this phase.)
        for level in [
            AckLevel::NoAck,
            AckLevel::ServerAck,
            AckLevel::ServerAndClientAck,
        ] {
            let (addr, handle) = capturing_server(empty_info_frame());
            let config = ClientConfig {
                default_ack_level: Some(level),
                ..ClientConfig::default()
            };
            let c = Client::connect_with(addr, &config).unwrap();
            drop(c);
            let captured = handle.join().unwrap();
            let frames = decode_all_frames(&captured);
            assert_eq!(frames[0].0, FrameType::Connect);
            let connect = decode_connect(&frames[0].1).unwrap();
            assert_eq!(
                connect.default_ack_level,
                Some(level.as_u8()),
                "the Connect body carries the configured default ack level"
            );
        }
    }

    #[test]
    fn connect_with_a_credential_appends_the_auth_section_and_redacts_the_secret() {
        // #884: a ClientConfig::credential is presented in the Connect handshake — connect_with appends
        // the auth section the server verifies (append_connect_auth), and the credential material never
        // leaks in Debug (#882). Both halves fail WITHOUT the fix: an old ClientConfig has no credential
        // field, and connect_with never appended an auth section.
        use ironbus_proto::message::parse_connect_auth;

        // The plaintext secret must NOT appear in a Debug render of the config (transitive redaction).
        let secret = b"a-secret-bearer-token-of-32-byte";
        let config = ClientConfig {
            credential: Some(AuthCredential {
                mechanism: AuthMechanism::Bearer,
                material: secret.to_vec(),
            }),
            ..ClientConfig::default()
        };
        let dbg = format!("{config:?}");
        assert!(
            !dbg.contains("a-secret-bearer-token"),
            "the credential material must be redacted in Debug, got: {dbg}"
        );
        assert!(
            dbg.contains("redacted"),
            "the redacted marker should be present, got: {dbg}"
        );

        // The Connect frame the client sends carries the auth section the server parses.
        let (addr, handle) = capturing_server(empty_info_frame());
        let c = Client::connect_with(addr, &config).unwrap();
        drop(c);
        let captured = handle.join().unwrap();
        let frames = decode_all_frames(&captured);
        assert_eq!(frames[0].0, FrameType::Connect);
        let parsed = parse_connect_auth(&frames[0].1)
            .expect("the auth section is well formed")
            .expect("connect_with with a credential appends an auth section");
        assert_eq!(parsed.mechanism, AuthMechanism::Bearer);
        assert_eq!(
            parsed.material, secret,
            "the exact credential material is on the wire the server verifies"
        );
    }

    #[test]
    fn connect_with_no_credential_appends_no_auth_section() {
        // #884 backward-compat: the default config (credential = None) appends NO auth section, so the
        // Connect body stays byte-for-byte the pre-#631 layout and an unauthenticated connect to a
        // no-auth broker is unchanged. parse_connect_auth reports no auth.
        use ironbus_proto::message::parse_connect_auth;

        let (addr, handle) = capturing_server(empty_info_frame());
        let c = Client::connect_with(addr, &ClientConfig::default()).unwrap();
        drop(c);
        let captured = handle.join().unwrap();
        let frames = decode_all_frames(&captured);
        assert_eq!(frames[0].0, FrameType::Connect);
        assert_eq!(
            parse_connect_auth(&frames[0].1).unwrap(),
            None,
            "an unconfigured client presents no credential"
        );
    }

    #[test]
    fn connect_with_omits_the_default_ack_level_when_unset() {
        // #496 backward-compat: the default config (default_ack_level = None) sends NO default in the
        // Connect body, so the body is byte-for-byte the pre-#494 layout and the server applies its own
        // default. We capture and decode the Connect frame and assert the field is absent.
        let (addr, handle) = capturing_server(empty_info_frame());
        let c = Client::connect_with(addr, &ClientConfig::default()).unwrap();
        drop(c);
        let captured = handle.join().unwrap();
        let frames = decode_all_frames(&captured);
        assert_eq!(frames[0].0, FrameType::Connect);
        let connect = decode_connect(&frames[0].1).unwrap();
        assert_eq!(
            connect.default_ack_level, None,
            "an unconfigured client sends no connection default ack level"
        );
    }

    #[test]
    fn connect_with_a_default_ack_level_handshakes_against_a_real_server() {
        // #496: a connection configured with a default ack level still completes the handshake against
        // the REAL server (which decodes the field; the server-side honor + Info echo is #497) and the
        // connection is usable for a normal produce afterwards.
        let (addr, shutdown, handle) = start_server();
        let config = ClientConfig {
            default_ack_level: Some(AckLevel::ServerAck),
            ..ClientConfig::default()
        };
        let mut c = Client::connect_with(addr, &config).unwrap();
        let offset = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"after-default-handshake",
            })
            .unwrap();
        assert_eq!(
            offset, 0,
            "the connection works after the default handshake"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
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
    fn a_pipelined_producer_auto_flushes_the_window_and_every_publish_is_durable() {
        // The #508 auto-pipelining durable producer over the real wire: a single producer buffers
        // publishes into a small window that auto-flushes when it fills, plus a partial tail that
        // `finish` flushes. Every publish must be acked exactly once, in order, and durably
        // readable back — the single-producer durable-throughput lever, with I2 intact.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();

        let total = 10u8; // window of 4 => two full auto-flushes (8) + a 2-message tail at finish.
        let payloads: Vec<Vec<u8>> = (0..total).map(|i| vec![b'p', i]).collect();
        let mut total_acked = 0u64;
        let mut last_offset = None;
        {
            let mut producer = c.pipelined_producer_with_window(4);
            assert_eq!(producer.window(), 4);
            for (i, p) in payloads.iter().enumerate() {
                // The caller's buffer is borrowed only for the duration of THIS call: the producer
                // serializes it into its own owned wire frame, so a `Vec` we drop right after would
                // be fine. Here we just confirm the buffered count tracks the un-flushed tail.
                let summary = producer
                    .produce(&PubBody {
                        flags: 0,
                        timestamp_ms: 0,
                        key: b"k",
                        headers: b"",
                        dedup: None,
                        fire_and_forget: false,
                        payload: p,
                    })
                    .unwrap();
                total_acked += summary.acked;
                if summary.last_offset.is_some() {
                    last_offset = summary.last_offset;
                }
                // After the 4th and 8th publish the window auto-flushed (buffered resets to 0).
                let expect_buffered = (i + 1) % 4;
                assert_eq!(producer.buffered(), expect_buffered);
            }
            // Two windows of 4 auto-flushed during the loop; the 2-message tail flushes at finish.
            assert_eq!(total_acked, 8, "the two full windows acked during the loop");
            let tail = producer.finish().unwrap();
            total_acked += tail.acked;
            if tail.last_offset.is_some() {
                last_offset = tail.last_offset;
            }
        }
        assert_eq!(
            total_acked,
            u64::from(total),
            "every publish acked exactly once"
        );
        assert_eq!(
            last_offset,
            Some(u64::from(total) - 1),
            "FIFO offsets in send order"
        );

        // Durability (I2): every publish is readable back in order — the acks meant durable.
        let messages = c.fetch(32).unwrap().messages;
        assert_eq!(messages.len(), usize::from(total));
        for (i, m) in messages.iter().enumerate() {
            assert_eq!(m.payload, payloads[i]);
        }
        // The connection is fully usable afterwards: a plain produce gets the next offset.
        let next = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"after-pipeline",
            })
            .unwrap();
        assert_eq!(next, u64::from(total));

        shutdown.store(true, Ordering::Relaxed);
        drop(c);
        let _ = handle.join();
    }

    #[test]
    fn a_pipelined_producer_finish_with_no_buffered_publishes_is_a_clean_no_op() {
        // An immediate finish (nothing produced) never touches the wire and leaves the connection
        // pristine, and a window of 0 is treated as 1 (no panic, no pipelining).
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        {
            let producer = c.pipelined_producer_with_window(0);
            assert_eq!(producer.window(), 1, "a zero window clamps to 1");
            assert_eq!(producer.finish().unwrap(), FlushSummary::default());
        }
        // The default-window handle also no-ops on an immediate finish.
        {
            let producer = c.pipelined_producer();
            assert_eq!(producer.window(), DEFAULT_PIPELINE_WINDOW);
            assert_eq!(producer.finish().unwrap(), FlushSummary::default());
        }
        // The connection is untouched: a plain produce still gets offset 0.
        let off = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"first",
            })
            .unwrap();
        assert_eq!(off, 0);
        shutdown.store(true, Ordering::Relaxed);
        drop(c);
        let _ = handle.join();
    }

    #[test]
    fn a_pipelined_producer_honors_per_publish_dedup() {
        // A dedup-keyed publish through the handle is deduplicated exactly as `produce_dedup`: the
        // second publish of the same msg_id is a benign duplicate hit counted in the flush tally,
        // and the original record is the only one stored. Window of 1 so each publish flushes on
        // its own and the duplicate is observed deterministically.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let dedup = PubDedup {
            producer_id: b"prod-1",
            epoch: 1,
            msg_id: b"id-A",
            seq: None,
        };
        let body = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"k",
            headers: b"",
            dedup: Some(dedup),
            fire_and_forget: false,
            payload: b"dedup-payload",
        };
        let mut producer = c.pipelined_producer_with_window(1);
        let first = producer.produce(&body).unwrap();
        assert_eq!(first.acked, 1);
        assert_eq!(first.duplicates, 0, "the first publish is fresh");
        let second = producer.produce(&body).unwrap();
        assert_eq!(second.acked, 1);
        assert_eq!(second.duplicates, 1, "the repeat msg_id is a dedup hit");
        assert_eq!(
            second.last_offset, first.last_offset,
            "a dedup hit returns the original offset"
        );
        let _ = producer.finish().unwrap();
        // Only ONE record is stored despite two publishes.
        let messages = c.fetch(16).unwrap().messages;
        assert_eq!(
            messages.len(),
            1,
            "the duplicate was not stored a second time"
        );
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
    fn fire_and_forget_producer_coalesces_yet_every_record_lands_in_order_end_to_end() {
        // The coalescing QoS-0 producer batches many fire-and-forget Pubs into the wire buffer and
        // writes them with one `write_all` (here via the explicit flush, the batch being well under the
        // 32 KiB auto-flush threshold), yet every record still lands durably IN ORDER, and the coalesced
        // no-ack batch does NOT desync the connection: a following at-least-once produce on the SAME
        // connection still gets its PubAck at the next offset.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        {
            let mut producer = c.fire_and_forget_producer();
            for i in 0..5u8 {
                producer
                    .send(&PubBody {
                        flags: 0,
                        timestamp_ms: 0,
                        key: b"",
                        headers: b"",
                        dedup: None,
                        fire_and_forget: false, // forced true by the producer
                        payload: &[b'a' + i],
                    })
                    .unwrap();
            }
            // The 5 small publishes are still buffered (well under the 32 KiB flush threshold); the
            // explicit flush is what puts them on the wire with one `write_all`.
            producer.flush().unwrap();
        }
        // A normal at-least-once produce on the SAME connection still gets its PubAck at offset 5,
        // proving the 5 coalesced no-ack frames did not leave a stray reply on the wire.
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
            offset, 5,
            "the at-least-once produce landed after the 5 coalesced QoS-0 ones"
        );
        // Fetch: all 6 records are durable and in order; the coalesced batch landed at offsets 0..=4.
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(
            messages.len(),
            6,
            "all 5 coalesced records plus the at-least-once one are durable"
        );
        for i in 0u8..5 {
            let m = &messages[usize::from(i)];
            assert_eq!(m.offset, u64::from(i));
            assert_eq!(m.payload, vec![b'a' + i]);
        }
        assert_eq!(messages[5].payload, b"alo");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn fire_and_forget_producer_auto_flushes_at_the_32kib_boundary_in_order_end_to_end() {
        // The COMPANION to the explicit-flush test above. This drives enough bytes that `send` itself
        // crosses the STREAM_FLUSH_BYTES (32 KiB) boundary and AUTO-flushes mid-loop — the core
        // coalescing mechanism — with NO explicit flush between sends. Eighty ~1 KiB publishes frame to
        // ~80 KiB, so the in-`send` auto-flush fires twice during the loop (around 32 KiB and 64 KiB),
        // leaving a partial tail the explicit flush pushes. Every record must still land durably IN
        // ORDER, and the coalesced no-ack stream must not desync the connection: a following
        // at-least-once produce still gets its PubAck at the next offset.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        let payload = vec![b'q'; 1000];
        let count: u8 = 80;
        {
            let mut faf = c.fire_and_forget_producer();
            for _ in 0..count {
                faf.send(&PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false, // forced true by the producer
                    payload: &payload,
                })
                .unwrap();
            }
            // Push the partial tail left after the in-`send` auto-flushes.
            faf.flush().unwrap();
        }
        // Synchronize on an at-least-once produce: its awaited PubAck proves the broker has appended
        // every prior coalesced L0 (the auto-flushed ones included). It lands right after them.
        let offset = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"sync",
            })
            .unwrap();
        assert_eq!(
            offset,
            u64::from(count),
            "the at-least-once produce landed after all the auto-flushed QoS-0 records"
        );
        // `offset == count` above is the proof that all `count` auto-flushed records landed durably and
        // IN ORDER: a single-writer connection assigns the sync produce offset `count` only if exactly
        // `count` records preceded it (a dropped or reordered auto-flush would shift it). Additionally
        // spot-check byte integrity of the auto-flushed prefix -- one fetch window must come back as the
        // exact payload at sequential offsets, proving the 32 KiB-boundary flush never split or corrupted
        // a frame. One `fetch` returns at most the negotiated credit window, so this checks the prefix,
        // not all `count`.
        let prefix = c.fetch(u32::from(count)).unwrap().messages;
        assert!(
            !prefix.is_empty(),
            "the auto-flushed prefix is durable and fetchable"
        );
        for (i, m) in prefix.iter().enumerate() {
            assert_eq!(m.offset, u64::try_from(i).unwrap());
            assert_eq!(m.payload, payload);
        }
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
            seq: None,
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

    /// An `Info` body advertising a per-consumer negotiated BYTE budget of `negotiated` (#938).
    fn info_with_credit_bytes(negotiated: u64) -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_info(
            &ironbus_proto::message::InfoBody {
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

    #[test]
    fn the_fetch_decompressed_cap_is_derived_from_the_negotiated_byte_budget() {
        // #938: the AGGREGATE materialized-payload ceiling for a fetch window is the LARGER of the
        // negotiated per-consumer byte budget and the 256 MiB floor, so a consumer that negotiated a
        // window bigger than 256 MiB is not falsely tripped with BadResponse, while an un-negotiated or
        // smaller budget stays fail-closed at the 256 MiB default.
        let floor = MAX_FETCH_DECOMPRESSED_BYTES;

        // A budget ABOVE the floor raises the ceiling to the negotiated value.
        let big = u64::try_from(floor).unwrap() + 4096;
        let (addr, handle) = raw_server(info_with_credit_bytes(big));
        let c = Client::connect(addr).unwrap();
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
        let c = Client::connect(addr).unwrap();
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
        let c = Client::connect(addr).unwrap();
        assert_eq!(c.negotiated_credit_bytes(), None);
        assert_eq!(c.fetch_decompressed_cap(), floor);
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn connect_disables_nagle_on_the_client_socket() {
        // #1028: the connect path sets TCP_NODELAY on the dialed socket — the produce/ack and fetch
        // paths are small-frame request-response, where Nagle + the broker's delayed ACK stacks an
        // RTT-scale stall onto every awaited round-trip on a real network. Read the option back via
        // getsockopt on the LIVE connection, so this pins the real socket state, not the call site.
        let (addr, handle) = raw_server(frame(FrameType::Info, b""));
        let c = Client::connect(addr).unwrap();
        assert!(
            c.stream.nodelay().expect("read TCP_NODELAY back"),
            "the connected client socket must have TCP_NODELAY set"
        );
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
                streaming: false,
                default_tier: None,
                deliver_batch: false,
                streams: false,
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
    fn back_to_back_fetch_responses_stay_framed_across_the_borrowing_drain() {
        // #818: the delivery fan-in now decodes each frame body by BORROWING it out of the client
        // buffer and drains only AFTER every surviving byte is copied into its `Message`. The reordered
        // drain must consume EXACTLY one frame each iteration (and the terminating FlowEnd). Two complete
        // fetch responses are buffered back-to-back (raw_server writes the whole script up front), so the
        // SECOND response is already sitting in the client's buffer when the FIRST fetch returns. If any
        // per-frame or FlowEnd drain were off by a byte, the second fetch would misframe. Each fetch must
        // decode its own records byte-for-byte, and the two deliveries buffered together in response 1
        // prove the per-frame drain length is exact.
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

        let mut c = Client::connect(addr).unwrap();
        let first = c.fetch(10).unwrap().messages;
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
        let second = c.fetch(10).unwrap().messages;
        assert_eq!(second.len(), 1, "response 2 survives the reordered drain");
        assert_eq!(second[0].offset, 2);
        assert_eq!(second[0].generation, 9);
        assert_eq!(second[0].headers, b"h2");
        assert_eq!(second[0].payload, b"second-only");
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_fetch_server_err_leaves_the_connection_framed_for_reuse() {
        // #818 regression: `Err` is a CONNECTION-PRESERVING per-Flow terminator — the server keeps the
        // connection open after a fetch `Err` — so the borrow-then-drain fetch loop must DRAIN the
        // terminating `Err` frame before returning, exactly as it drains the sibling `FlowEnd`
        // terminator. Response 1 ends in an `Err`; response 2 (a valid delivery + FlowEnd) is already
        // buffered behind it. If the `Err` frame were left in the buffer, the second fetch would re-read
        // those stale bytes and misframe (re-surfacing the server error instead of decoding response 2).
        // That the second fetch succeeds proves the `Err` was drained and the connection stayed exactly
        // framed for reuse.
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

        let mut c = Client::connect(addr).unwrap();
        // The first fetch surfaces the server Err (and, per the fix, drains that Err frame).
        match c.fetch(10).unwrap_err() {
            ClientError::Server(msg) => assert_eq!(msg, "consumer fenced"),
            other => panic!("expected a server error, got {other:?}"),
        }
        // The second response was ALREADY buffered behind the Err when the first fetch returned; that it
        // decodes cleanly proves the Err terminator was drained and left the connection exactly framed.
        let second = c.fetch(10).unwrap().messages;
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

    /// One test record's fields `(flags, key, headers, payload)` for building on-disk batch bytes.
    type BatchRec<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

    /// Builds the contiguous on-disk frame bytes for `records` (seq starting at `base_seq`), the body a
    /// real broker would splice into a `DeliverBatch` from a stored segment.
    fn on_disk_record_bytes(base_seq: u64, records: &[BatchRec<'_>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (i, (flags, key, headers, payload)) in records.iter().enumerate() {
            ironbus_core::codec::encode(
                &ironbus_core::codec::RecordView {
                    seq: ironbus_core::types::Seq::new(base_seq + i as u64),
                    timestamp_ms: 1000 + i as u64,
                    flags: RecordFlags::from_bits(*flags),
                    key,
                    headers,
                    payload,
                },
                &mut bytes,
            )
            .unwrap();
        }
        bytes
    }

    #[test]
    fn a_scripted_deliver_batch_decodes_to_the_same_messages_as_n_delivers() {
        // #541 client-side: a scripted server streams ONE DeliverBatch carrying a contiguous run as
        // on-disk frame bytes; the client decodes it into the SAME `Message`s a per-record `Deliver` run
        // would yield — offsets reconstructed positionally from the header's first_offset, each record's
        // CRC verified by the on-disk decode. The decoded messages match a per-record reference exactly.
        let recs: Vec<BatchRec<'_>> = vec![
            (0, b"k0", b"h0", b"payload-zero"),
            (0, b"k1", b"", b"payload-one"),
            (0, b"", b"h2", b"two"),
        ];
        let record_bytes = on_disk_record_bytes(0, &recs);
        let mut batch_body = Vec::new();
        ironbus_proto::message::encode_deliver_batch(
            &ironbus_proto::message::DeliverBatchHeader {
                first_offset: 100,
                generation: 0,
                record_count: 3,
            },
            &record_bytes,
            &mut batch_body,
        );
        // The Info advertises the DeliverBatch capability so the client's handshake records it (not
        // required for decode, but it is the realistic wire). The client decodes the tag regardless.
        let mut info_body = Vec::new();
        encode_info(
            &InfoBody {
                deliver_batch: true,
                ..InfoBody::default()
            },
            &mut info_body,
        );
        let mut script = frame(FrameType::Info, &info_body);
        script.extend(frame(FrameType::DeliverBatch, &batch_body));
        script.extend(frame(FrameType::FlowEnd, &3u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);

        let mut c = Client::connect_with(
            addr,
            &ClientConfig {
                understands_deliver_batch: true,
                understands_streaming: true,
                ..ClientConfig::default()
            },
        )
        .unwrap();
        assert!(c.deliver_batch_enabled(), "the capability is confirmed");
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 3);
        // Offsets reconstructed positionally: 100, 101, 102.
        for (i, m) in messages.iter().enumerate() {
            assert_eq!(m.offset, 100 + i as u64, "positional offset");
            assert_eq!(m.generation, 0, "the lease-free streaming generation");
        }
        assert_eq!(messages[0].key, b"k0");
        assert_eq!(messages[0].headers, b"h0");
        assert_eq!(messages[0].payload, b"payload-zero");
        assert_eq!(messages[1].key, b"k1");
        assert_eq!(messages[1].payload, b"payload-one");
        assert_eq!(messages[2].headers, b"h2");
        assert_eq!(messages[2].payload, b"two");
        drop(c);
        handle.join().unwrap();
    }

    #[test]
    fn a_scripted_deliver_batch_with_a_corrupt_record_is_a_typed_error_never_a_panic() {
        // CRC end-to-end: a DeliverBatch body whose on-disk record bytes are corrupted (a flipped byte
        // breaks the body CRC) is a typed `BadResponse`, never a panic and never a corrupt message handed
        // to the caller — the client verifies each record's CRC as it decodes the batch.
        let recs: Vec<BatchRec<'_>> = vec![(0, b"", b"", b"good-record")];
        let mut record_bytes = on_disk_record_bytes(0, &recs);
        // Flip a payload byte: the header CRC still passes (the header is untouched), but the body CRC
        // now mismatches, so `codec::decode` rejects it.
        let last = record_bytes.len() - ironbus_core::format::RECORD_TRAILER_LEN - 1;
        record_bytes[last] ^= 0xFF;
        let mut batch_body = Vec::new();
        ironbus_proto::message::encode_deliver_batch(
            &ironbus_proto::message::DeliverBatchHeader {
                first_offset: 0,
                generation: 0,
                record_count: 1,
            },
            &record_bytes,
            &mut batch_body,
        );
        let mut script = frame(FrameType::Info, b"");
        script.extend(frame(FrameType::DeliverBatch, &batch_body));
        script.extend(frame(FrameType::FlowEnd, &1u32.to_le_bytes()));
        let (addr, handle) = raw_server(script);
        let mut c = Client::connect_with(
            addr,
            &ClientConfig {
                understands_deliver_batch: true,
                ..ClientConfig::default()
            },
        )
        .unwrap();
        let err = c.fetch(10).unwrap_err();
        assert!(
            matches!(err, ClientError::BadResponse(_)),
            "a corrupt batch record is a typed BadResponse, got {err:?}"
        );
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

    // --- Tier-S batched-default streaming consumer (#550) -------------------------------------

    /// A `ClientConfig` that negotiates Tier-S: advertises streaming + `DeliverBatch` and requests the
    /// streaming connection default, so a SUB auto-marks its group streaming server-side (the wiring
    /// the batched-default consumer rides on).
    fn streaming_config() -> ClientConfig {
        ClientConfig {
            understands_streaming: true,
            default_consume_tier: Some(ConsumeTier::Streaming),
            understands_deliver_batch: true,
            ..ClientConfig::default()
        }
    }

    /// Connects a Tier-S consumer subscribed to `group` against the given address, asserting the
    /// streaming tier negotiated. The connection's streaming default makes the SUB mark the group
    /// streaming, so the consumer's `stream_fetch` / `stream_commit` are accepted.
    fn connect_streaming(addr: std::net::SocketAddr, group: &str) -> Client {
        let mut c = Client::connect_with(addr, &streaming_config()).unwrap();
        assert!(
            c.streaming_enabled(),
            "the server confirmed the streaming tier"
        );
        c.subscribe(group).unwrap();
        c
    }

    /// Produces `n` single-byte records (offsets `0..n`) on a fresh producer connection, so a
    /// streaming consumer has a durable prefix to read.
    fn produce_n(addr: std::net::SocketAddr, n: u64) {
        let mut p = Client::connect(addr).unwrap();
        for i in 0..n {
            p.produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: &[(i & 0xff) as u8],
            })
            .unwrap();
        }
    }

    #[test]
    fn streaming_consumer_default_fetches_in_batches_and_commits_periodically_not_per_record() {
        // #550: the batched DEFAULT. A window of 4 over 10 records is 3 fetches (4 + 4 + 2), and a
        // commit cadence of 2 commits after windows 2 and 3 — NOT once per record. We drive the
        // consumer to drain, then a SECOND streaming consumer subscribed to the SAME group resumes
        // from the committed offset and sees NOTHING (everything was committed), proving the periodic
        // commit advanced the durable cursor cumulatively.
        let (addr, shutdown, handle) = start_server();
        produce_n(addr, 10);

        let mut c = connect_streaming(addr, "s");
        let cfg = StreamConsumerConfig {
            max_records: 4,
            max_bytes: 0,
            commit_every_batches: 2,
            start_offset: 0,
            read_ahead: false,
        };
        let mut consumer = c.streaming_consumer_with("s", &cfg);

        let b0 = consumer.next_batch().unwrap();
        assert_eq!(
            b0.messages.len(),
            4,
            "window one is a full batch, not one record"
        );
        assert_eq!(b0.messages[0].offset, 0);
        assert_eq!(b0.messages[3].offset, 3);
        // Cadence is 2: after ONE window nothing is committed yet (batched, not per-record).
        assert_eq!(consumer.committed_offset(), 0, "no commit after one window");
        assert_eq!(consumer.next_offset(), 4);

        let b1 = consumer.next_batch().unwrap();
        assert_eq!(b1.messages.len(), 4);
        assert_eq!(b1.messages[0].offset, 4);
        // The cadence (2) is reached: the cumulative commit covers offsets [0, 8).
        assert_eq!(
            consumer.committed_offset(),
            8,
            "periodic commit after two windows"
        );

        let b2 = consumer.next_batch().unwrap();
        assert_eq!(b2.messages.len(), 2, "the short tail window");
        assert_eq!(consumer.next_offset(), 10);

        // Drained: an empty window flushes the final commit so the whole prefix is durable.
        let b3 = consumer.next_batch().unwrap();
        assert!(b3.is_empty(), "the stream has drained to its head");
        assert_eq!(
            consumer.committed_offset(),
            10,
            "the drain flushed the final commit"
        );
        drop(c);

        // A fresh consumer resuming from the committed offset sees nothing: the periodic cumulative
        // commit durably advanced the group cursor past every record (no per-record ack was needed).
        let mut c2 = connect_streaming(addr, "s");
        let committed = c2.streaming_consumer_with(
            "s",
            &StreamConsumerConfig {
                start_offset: 10,
                ..cfg.clone()
            },
        );
        drop(committed);
        // Re-fetch from the committed head directly: empty.
        let resumed = c2.stream_fetch(10, 16, 0).unwrap();
        assert!(
            resumed.messages.is_empty(),
            "everything below 10 was committed"
        );

        drop(c2);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn streaming_at_least_once_a_crash_mid_window_redelivers_only_the_uncommitted_span() {
        // #550 / #544: at-least-once by construction. The consumer fetches [0,10) with a window of 4
        // and a cadence of 2, so [0,8) is committed but [8,10) is NOT when it "crashes" (drops the
        // connection). A reconnecting consumer resuming from the committed offset (8) re-reads exactly
        // the uncommitted span [8,10) — none lost, only the uncommitted window redelivered.
        let (addr, shutdown, handle) = start_server();
        produce_n(addr, 10);

        let mut c = connect_streaming(addr, "s");
        let cfg = StreamConsumerConfig {
            max_records: 4,
            commit_every_batches: 2,
            read_ahead: false,
            ..StreamConsumerConfig::default()
        };
        let mut consumer = c.streaming_consumer_with("s", &cfg);

        let mut seen = Vec::new();
        // Two windows: [0,4) then [4,8). The cadence-2 commit fires after the second, committing [0,8).
        for _ in 0..2 {
            for m in consumer.next_batch().unwrap().messages {
                seen.push(m.offset);
            }
        }
        let committed = consumer.committed_offset();
        assert_eq!(
            committed, 8,
            "the periodic commit durably checkpointed [0,8)"
        );
        // A third window fetches [8,10) and hands it to the caller, but the cadence has NOT been
        // reached again, so it is NOT committed: this is the uncommitted, at-risk span.
        for m in consumer.next_batch().unwrap().messages {
            seen.push(m.offset);
        }
        assert_eq!(
            seen,
            (0..10).collect::<Vec<u64>>(),
            "all 10 delivered pre-crash"
        );
        assert_eq!(
            consumer.committed_offset(),
            8,
            "[8,10) is uncommitted at crash"
        );
        // CRASH: drop the consumer and the connection WITHOUT finishing/committing the last window.
        drop(consumer);
        drop(c);

        // Reconnect and resume from the last committed offset: re-read the uncommitted span.
        let mut c2 = connect_streaming(addr, "s");
        let redelivered = c2.stream_fetch(committed, 16, 0).unwrap();
        let redelivered_offsets: Vec<u64> = redelivered.messages.iter().map(|m| m.offset).collect();
        assert_eq!(
            redelivered_offsets,
            vec![8, 9],
            "exactly the uncommitted span [8,10) redelivers — none lost, none below the commit"
        );

        drop(c2);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn streaming_read_ahead_is_bounded_and_delivers_the_same_records_in_order_as_no_prefetch() {
        // #550: the read-ahead is a DIFFERENTIAL no-op on the records — prefetch only moves WHEN the
        // next request is written, never WHICH records come back. We drain the same 20-record prefix
        // twice over independent connections, once with read_ahead ON and once OFF, and assert the two
        // delivered sequences are byte-for-byte identical and in order. The bound is structural: at
        // most ONE prefetch slot is ever held (`prefetch: Option<usize>`), so the read-ahead buffer
        // cannot grow without bound regardless of how many windows are drained.
        let (addr, shutdown, handle) = start_server();
        produce_n(addr, 20);

        let drain = |read_ahead: bool| -> Vec<(u64, Vec<u8>)> {
            let mut c = connect_streaming(addr, "s");
            let cfg = StreamConsumerConfig {
                max_records: 3,
                commit_every_batches: 4,
                read_ahead,
                ..StreamConsumerConfig::default()
            };
            let mut consumer = c.streaming_consumer_with("s", &cfg);
            let mut out = Vec::new();
            loop {
                let batch = consumer.next_batch().unwrap();
                if batch.is_empty() {
                    break;
                }
                for m in batch.messages {
                    out.push((m.offset, m.payload));
                }
            }
            consumer.finish().unwrap();
            out
        };

        let with_prefetch = drain(true);
        let without_prefetch = drain(false);
        assert_eq!(
            with_prefetch, without_prefetch,
            "read-ahead delivers the SAME records in the SAME order as the no-prefetch baseline"
        );
        assert_eq!(
            with_prefetch.len(),
            20,
            "the whole prefix, exactly once each"
        );
        assert_eq!(
            with_prefetch.iter().map(|(o, _)| *o).collect::<Vec<_>>(),
            (0..20).collect::<Vec<u64>>(),
            "offsets are contiguous and in order"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn streaming_read_ahead_respects_the_byte_budget_so_the_prefetch_window_stays_bounded() {
        // #550: the prefetched window obeys the SAME byte budget as the visible one, so the
        // outstanding memory is at most two bounded windows, never an unbounded buffer. With a tiny
        // byte budget the server's floor-of-one delivers one record per window, and the consumer still
        // drains the whole prefix in order with read-ahead on — the bound holds at the small end.
        let (addr, shutdown, handle) = start_server();
        produce_n(addr, 6);

        let mut c = connect_streaming(addr, "s");
        let cfg = StreamConsumerConfig {
            max_records: 100,
            // A byte budget below one record's encoded size: the floor-of-one still delivers a single
            // record per window, so each window (visible AND prefetched) is bounded to one record.
            max_bytes: 1,
            commit_every_batches: 3,
            read_ahead: true,
            ..StreamConsumerConfig::default()
        };
        let mut consumer = c.streaming_consumer_with("s", &cfg);
        let mut offsets = Vec::new();
        let mut windows = 0u32;
        loop {
            let batch = consumer.next_batch().unwrap();
            if batch.is_empty() {
                break;
            }
            // The byte budget binds each window (visible AND prefetched) to a small, bounded count
            // despite the roomy 100-record cap: the prefetch buffer cannot balloon to the record cap.
            assert!(
                batch.messages.len() <= 2,
                "the byte budget bounds each window to a small count (got {}), not the 100-record cap",
                batch.messages.len()
            );
            windows += 1;
            for m in batch.messages {
                offsets.push(m.offset);
            }
        }
        consumer.finish().unwrap();
        assert_eq!(
            offsets,
            (0..6).collect::<Vec<u64>>(),
            "all records, in order, across bounded windows"
        );
        assert!(
            windows >= 3,
            "the byte budget forced several small windows, not one big fetch"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn tier_w_lease_mode_is_unchanged_a_non_streaming_client_fetches_and_acks_per_record() {
        // #550: back-compat. A default (non-streaming) client is served Tier-W exactly as before — it
        // leases per record and acks by fencing generation — and the new streaming-default consumer
        // changes nothing about it. The lease generation is real (non-zero is allowed) and the ack
        // commits, the unchanged work-queue contract.
        let (addr, shutdown, handle) = start_server();
        produce_n(addr, 3);

        // A plain client: no streaming advertised, so it is Tier-W.
        let mut c = Client::connect(addr).unwrap();
        assert!(
            !c.streaming_enabled(),
            "an unconfigured client stays Tier-W"
        );
        let fetched = c
            .fetch_batch(3, 0, std::time::Duration::from_secs(1), false)
            .unwrap();
        assert_eq!(fetched.messages.len(), 3, "Tier-W batch pull is unchanged");
        // Each record is leased and acked individually by its fencing generation (the Tier-W contract).
        let acks: Vec<(u64, u64)> = fetched
            .messages
            .iter()
            .map(|m| (m.offset, m.generation))
            .collect();
        let statuses = c.ack_many(&acks).unwrap();
        assert!(
            statuses.iter().all(|&ok| ok),
            "every per-record Tier-W ack commits"
        );
        // Nothing left after the per-record acks: the cursor advanced exactly as before.
        assert!(
            c.fetch_batch(3, 0, std::time::Duration::from_secs(1), false)
                .unwrap()
                .messages
                .is_empty(),
            "the Tier-W cursor advanced on the per-record acks, unchanged by #550"
        );

        drop(c);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    // ===== Stream-addressed wire verbs (#588, V2-M2-I10), END-TO-END over the REAL server =====

    /// A client config that advertises the stream-addressing capability (#588).
    fn config_understanding_streams() -> ClientConfig {
        ClientConfig {
            understands_streams: true,
            ..ClientConfig::default()
        }
    }

    #[test]
    fn streams_capability_negotiates_against_a_real_server() {
        // #588: a client that advertises `understands_streams` has it CONFIRMED by the server
        // (`streams_enabled()` true); a client that does NOT advertise it leaves it off, so an old
        // client is never told it may address named streams. The negotiation is the server->client AND.
        let (addr, shutdown, handle) = start_server();

        let capable = Client::connect_with(addr, &config_understanding_streams()).unwrap();
        assert!(
            capable.streams_enabled(),
            "the server confirms stream addressing for a client that advertised it"
        );

        let old = Client::connect(addr).unwrap();
        assert!(
            !old.streams_enabled(),
            "a client that did not advertise stream addressing is never told it may use it"
        );

        drop(capable);
        drop(old);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn declare_publish_subscribe_consume_ack_a_named_stream_end_to_end() {
        // TEETH (#588): the whole named-stream round-trip over the REAL wire server — a streams-capable
        // client DECLARES a named stream, PUBLISHES to it by id, SUBSCRIBES to its per-stream
        // work-group, CONSUMES the record via that group, and ACKS it. StreamInfo reports the stream
        // exists with the right durable head along the way.
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect_with(addr, &config_understanding_streams()).unwrap();
        assert!(c.streams_enabled());

        // A query before declare: the named stream does not exist yet.
        let (exists, _head) = c.stream_info("orders").unwrap();
        assert!(!exists, "an undeclared named stream does not exist");

        // Declare it (idempotent), then a re-declare is still Ok.
        c.declare_stream("orders").unwrap();
        c.declare_stream("orders").unwrap();
        let (exists, head) = c.stream_info("orders").unwrap();
        assert!(exists, "the declared named stream now exists");
        assert_eq!(
            head, 0,
            "a freshly declared stream has an empty durable head"
        );

        // Publish two records to the NAMED stream by id; the offsets are the stream's OWN.
        let body = |p: &'static [u8]| PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p,
        };
        let off0 = c.publish_to("orders", &body(b"order-A")).unwrap();
        let off1 = c.publish_to("orders", &body(b"order-B")).unwrap();
        assert_eq!(
            (off0, off1),
            (0, 1),
            "the named stream has its own offset space"
        );

        let (_exists, head) = c.stream_info("orders").unwrap();
        assert_eq!(
            head, 2,
            "the named stream's durable head advanced to two records"
        );

        // Subscribe to the named stream's work-group, then consume + ack both records via that group.
        c.subscribe_to("orders", "workers").unwrap();
        let mut got = Vec::new();
        for _ in 0..10 {
            let messages = c.fetch(10).unwrap().messages;
            for m in &messages {
                got.push(m.payload.clone());
                assert!(
                    c.ack(m.offset, m.generation).unwrap(),
                    "the named-stream ack commits"
                );
            }
            if got.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            got,
            vec![b"order-A".to_vec(), b"order-B".to_vec()],
            "the consumer received exactly the named stream's records, in order"
        );

        // A re-fetch after acking both delivers nothing: the named stream's cursor advanced.
        assert!(
            c.fetch(10).unwrap().messages.is_empty(),
            "the named stream's committed cursor advanced past both acked records"
        );

        drop(c);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn bind_publish_subscribe_consume_ack_by_subject_end_to_end() {
        // TEETH (#585): the whole subject-addressed round-trip over the REAL wire server — a
        // streams-capable client BINDS a wildcard pattern to a stream, PUBLISHES two records by
        // LITERAL subjects the pattern covers, SUBSCRIBES by a literal subject (which single-home-
        // resolves to the bound stream), CONSUMES both records via the resolved stream's
        // work-group, and ACKS them. An UNBOUND subject publish is the typed fail-closed reject
        // (`NoStreamForSubject`), never a silent drop, and a WILDCARD subscribe subject is the
        // typed `InvalidSubject` reject (wildcards live on the bind side this phase).
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect_with(addr, &config_understanding_streams()).unwrap();
        assert!(c.streams_enabled());

        // Bind `orders.*` -> `orders`; the bind DECLARES the target stream (declare-on-bind), and a
        // re-bind is a benign idempotent success.
        c.bind_subject("orders", "orders.*").unwrap();
        c.bind_subject("orders", "orders.*").unwrap();
        let (exists, _head) = c.stream_info("orders").unwrap();
        assert!(exists, "the bind declared its target stream");

        // Publish by two LITERAL subjects the pattern covers: both land in `orders`' own log.
        let body = |p: &'static [u8]| PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p,
        };
        let off0 = c.publish_subject("orders.us", &body(b"order-US")).unwrap();
        let off1 = c.publish_subject("orders.eu", &body(b"order-EU")).unwrap();
        assert_eq!(
            (off0, off1),
            (0, 1),
            "both covered subjects route to the SAME bound stream's offset space"
        );

        // An UNBOUND subject is the typed fail-closed reject, never a silent drop.
        let err = c
            .publish_subject("invoices.us", &body(b"nope"))
            .unwrap_err();
        match err {
            ClientError::Server(e) => assert_eq!(
                e.code(),
                Some(ServerErrorCode::NoStreamForSubject),
                "an unbound subject publish carries the stable NoStreamForSubject code"
            ),
            other => panic!("expected a typed server reject, got {other:?}"),
        }

        // Subscribe BY SUBJECT (a literal the pattern covers) and consume + ack both records.
        c.subscribe_subject("orders.us", "workers").unwrap();
        let mut got = Vec::new();
        for _ in 0..10 {
            let messages = c.fetch(10).unwrap().messages;
            for m in &messages {
                got.push(m.payload.clone());
                assert!(c.ack(m.offset, m.generation).unwrap());
            }
            if got.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            got,
            vec![b"order-US".to_vec(), b"order-EU".to_vec()],
            "the subject-resolved consumer received the bound stream's records, in order"
        );

        // Wildcards live on the BIND side only: a wildcard in the SUBSCRIBED subject is the typed
        // fail-closed `InvalidSubject` reject this phase (the fan-out subscribe is a follow-up).
        let err = c.subscribe_subject("orders.*", "workers").unwrap_err();
        match err {
            ClientError::Server(e) => assert_eq!(
                e.code(),
                Some(ServerErrorCode::InvalidSubject),
                "a wildcard subscribe subject is the typed InvalidSubject reject"
            ),
            other => panic!("expected a typed server reject, got {other:?}"),
        }

        drop(c);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn cross_stream_isolation_over_the_wire() {
        // TEETH (#588): a publish to stream A is NEVER seen by a consumer subscribed to stream B — two
        // named streams are fully independent over the wire (their own logs AND their own per-stream
        // work-group cursors). The consumer on B sees only B's record; the default stream stays empty.
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect_with(addr, &config_understanding_streams()).unwrap();
        producer.declare_stream("stream-a").unwrap();
        producer.declare_stream("stream-b").unwrap();

        let body = |p: &'static [u8]| PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p,
        };
        producer
            .publish_to("stream-a", &body(b"only-in-a"))
            .unwrap();
        producer
            .publish_to("stream-b", &body(b"only-in-b"))
            .unwrap();

        // A consumer bound to stream B sees ONLY B's record, never A's.
        let mut consumer = Client::connect_with(addr, &config_understanding_streams()).unwrap();
        consumer.subscribe_to("stream-b", "g").unwrap();
        let mut got = Vec::new();
        for _ in 0..10 {
            let messages = consumer.fetch(10).unwrap().messages;
            for m in &messages {
                got.push(m.payload.clone());
                assert!(consumer.ack(m.offset, m.generation).unwrap());
            }
            if !got.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            got,
            vec![b"only-in-b".to_vec()],
            "a consumer on stream B sees B's record and NEVER stream A's"
        );

        // Switch the SAME consumer to stream A and it now sees ONLY A's record (its own cursor).
        consumer.subscribe_to("stream-a", "g").unwrap();
        let mut got_a = Vec::new();
        for _ in 0..10 {
            let messages = consumer.fetch(10).unwrap().messages;
            for m in &messages {
                got_a.push(m.payload.clone());
                assert!(consumer.ack(m.offset, m.generation).unwrap());
            }
            if !got_a.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            got_a,
            vec![b"only-in-a".to_vec()],
            "the same connection on stream A sees ONLY A's record (independent per-stream cursor)"
        );

        // The DEFAULT stream was never published to, so a default-stream consumer sees nothing.
        let mut default_consumer = Client::connect(addr).unwrap();
        assert!(
            default_consumer.fetch(10).unwrap().messages.is_empty(),
            "the default stream is untouched by the named-stream publishes"
        );

        drop(producer);
        drop(consumer);
        drop(default_consumer);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn an_old_client_hits_the_default_stream_byte_identically() {
        // #588 back-compat: a client that did NOT negotiate stream addressing (the capability bit
        // clear) uses only the default-stream verbs (`produce` / `subscribe` / `fetch` / `ack`), which
        // target the default stream `""` byte-for-byte today's behavior — a streams-capable client
        // publishing to the EMPTY stream id (`publish_to("", ...)`) lands in the SAME default stream
        // and is consumed by the OLD client's plain default subscription, proving the empty-id path is
        // exactly the default path.
        let (addr, shutdown, handle) = start_server();

        // The old client produces to the default stream the classic way.
        let mut old = Client::connect(addr).unwrap();
        assert!(!old.streams_enabled());
        let body = |p: &'static [u8]| PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: p,
        };
        let off_old = old.produce(&body(b"classic")).unwrap();
        assert_eq!(off_old, 0, "the default stream starts at offset 0");

        // A streams-capable client publishes to the EMPTY stream id: it MUST land in the default stream
        // at the next default offset, indistinguishable from a plain `produce`.
        let mut capable = Client::connect_with(addr, &config_understanding_streams()).unwrap();
        let off_empty = capable.publish_to("", &body(b"via-empty-id")).unwrap();
        assert_eq!(
            off_empty, 1,
            "an empty stream id routes to the DEFAULT stream's offset space (byte-identical)"
        );

        // The old client's plain default subscription consumes BOTH records in order — the empty-id
        // publish is in the same default stream it always was.
        old.subscribe("").unwrap();
        let mut got = Vec::new();
        for _ in 0..10 {
            let messages = old.fetch(10).unwrap().messages;
            for m in &messages {
                got.push(m.payload.clone());
                assert!(old.ack(m.offset, m.generation).unwrap());
            }
            if got.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            got,
            vec![b"classic".to_vec(), b"via-empty-id".to_vec()],
            "the default stream carries both the classic produce and the empty-id publish-to, in order"
        );

        drop(old);
        drop(capable);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_stream_verbs_are_refused_without_the_negotiated_capability() {
        // #588 fail-closed: a client that did NOT negotiate stream addressing is REFUSED the
        // stream-addressed verbs with a typed server error — it can never reach the named-stream path
        // by accident. (The default-stream verbs stay fully available, exercised above.)
        let (addr, shutdown, handle) = start_server();
        let mut old = Client::connect(addr).unwrap();
        assert!(!old.streams_enabled());

        let declare = old.declare_stream("nope");
        assert!(
            matches!(declare, Err(ClientError::Server(_))),
            "declare without the capability is a typed server error, got {declare:?}"
        );
        let info = old.stream_info("nope");
        assert!(
            matches!(info, Err(ClientError::Server(_))),
            "stream_info without the capability is a typed server error, got {info:?}"
        );

        drop(old);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    // ---------------------------------------------------------------------------------------------
    // #719 (V2-C2): a REAL client connection over a clustered C2-fsync broker observes QUORUM-FSYNC
    // ack timing — its wire PubAck arrives ONLY after the data plane's follower report brings
    // quorum-fsync, NOT on leader-only-fsync.
    // ---------------------------------------------------------------------------------------------

    /// The default partition the single-stream broker maps to (the client produce-ack gate routes every
    /// produce here; multi-partition is #693).
    #[cfg(unix)]
    const C2_PARTITION: u64 = 0;

    /// Start an in-process broker whose produce-ack path is gated by a CLUSTERED C2-fsync
    /// `ClientAckGate` (#719): this node LEADS partition 0 of `{1,2,3}` with `min_isr = 2`. Returns the
    /// broker address, its shutdown flag + serve-thread handle, and the SHARED gate so the test can
    /// DRIVE a follower's quorum-fsync report (standing in for the data-plane runtime's follower thread).
    /// A real `serve` loop accepts the real client connection; only the produce-ack gating + the
    /// follower-report driver are simulated in-process.
    #[cfg(unix)]
    #[allow(clippy::type_complexity)]
    fn start_clustered_c2_server() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        Arc<ironbus_server::cluster::ClientAckGate<InMemoryFs, SystemClock>>,
    ) {
        use ironbus_server::actor::EngineHandle;
        use ironbus_server::cluster::{
            ClientAckGate, ClusterAckLevel, DataPlaneController, DataPlaneServer, IsrConfig,
            ProduceAckSeam,
        };
        use ironbus_storage::log::Log;
        use std::sync::{Mutex, OnceLock};

        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
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
        .unwrap();

        // Build a data-plane server that LEADS partition 0 of {1,2,3} with min_isr=2. A leaked, empty
        // leader log gives the read plane a `'static` lifetime; the gate's quorum decision (not the read
        // plane content) is what the test exercises, and the leader-fsync frontier is advanced by the
        // produce path itself (#719) as records append.
        let leader_log: &'static Log<InMemoryFs, SystemClock> = Box::leak(Box::new(
            Log::open(InMemoryFs::new(), SystemClock::new(), LogConfig::default()).unwrap(),
        ));
        let plane = Arc::new(leader_log.read_plane().unwrap());
        let mut controller = DataPlaneController::new(1);
        controller.start_leader(
            C2_PARTITION,
            plane,
            ironbus_core::epoch_cache::EpochCache::new(),
            &[1, 2, 3],
            IsrConfig {
                min_isr: 2,
                max_lag_records: 0,
            },
        );
        let server = Arc::new(Mutex::new(DataPlaneServer::new(
            1,
            ProduceAckSeam::new(controller),
        )));
        let gate = Arc::new(ClientAckGate::new(server, ClusterAckLevel::C2Fsync));

        // Install the gate on the engine handle via the shared set-once slot (exactly the serve path:
        // the slot is filled, then the handle is installed before any per-connection clone).
        let slot: ironbus_server::actor::ClientAckSlot<InMemoryFs, SystemClock> =
            Arc::new(OnceLock::new());
        slot.set(Arc::clone(&gate)).ok();
        let (handle_engine, _actor): (EngineHandle<InMemoryFs, SystemClock>, _) =
            spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let handle_engine = handle_engine.with_client_ack_slot(slot);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let serve_handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = SystemClock::new();
                let beacon =
                    ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &handle_engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });
        (addr, shutdown, serve_handle, gate)
    }

    /// A raw wire connection that keeps a PERSISTENT read buffer across reads, so a single TCP read that
    /// returns several frames (e.g. a released `PubAck` flushed alongside the Pong on one pass) never
    /// drops the trailing frames.
    #[cfg(unix)]
    struct RawConn {
        stream: std::net::TcpStream,
        buf: Vec<u8>,
    }

    #[cfg(unix)]
    impl RawConn {
        /// Pull the next whole frame, decoding from the persistent buffer first and reading more bytes
        /// only when no whole frame is buffered. `None` on a clean close or a read timeout with no whole
        /// frame.
        fn next_frame(&mut self) -> Option<(FrameType, Vec<u8>)> {
            let mut chunk = [0u8; 4096];
            loop {
                match decode_frame(&self.buf) {
                    Ok(FrameDecode::Frame {
                        type_tag,
                        body,
                        consumed,
                    }) => {
                        let f = (FrameType::from_u8(type_tag).unwrap(), body.to_vec());
                        self.buf.drain(..consumed);
                        return Some(f);
                    }
                    _ => match self.stream.read(&mut chunk) {
                        // A clean close (0) or a read timeout (Err) with no whole frame: stop.
                        Ok(0) | Err(_) => return None,
                        Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                    },
                }
            }
        }

        fn write_frame(&mut self, ty: FrameType, body: &[u8]) {
            self.stream.write_all(&frame(ty, body)).unwrap();
        }

        /// Send a `Ping` and collect every frame the broker flushes this round, up to (and including) the
        /// `Pong` boundary. A withheld-then-released `PubAck` is flushed alongside (or before) the Pong on
        /// the pass the Ping drives, exactly as the L2 `ProduceConfirm` drain works.
        fn ping_round(&mut self) -> Vec<(FrameType, Vec<u8>)> {
            self.write_frame(FrameType::Ping, &[]);
            let mut frames = Vec::new();
            while let Some((ty, body)) = self.next_frame() {
                let is_pong = ty == FrameType::Pong;
                frames.push((ty, body));
                if is_pong {
                    break;
                }
            }
            frames
        }
    }

    /// Do the Connect handshake by hand on a raw stream against the real serve: send a default
    /// `Connect`, read the `Info` reply. Returns the connected [`RawConn`] (persistent buffer).
    #[cfg(unix)]
    fn raw_connect(addr: std::net::SocketAddr) -> RawConn {
        use ironbus_proto::message::{encode_connect, ConnectBody};
        let stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut conn = RawConn {
            stream,
            buf: Vec::new(),
        };
        let mut body = Vec::new();
        encode_connect(&ConnectBody::default(), &mut body);
        conn.write_frame(FrameType::Connect, &body);
        let (ty, _b) = conn.next_frame().expect("Info handshake reply");
        assert_eq!(ty, FrameType::Info, "the broker replies Info to a Connect");
        conn
    }

    #[cfg(unix)]
    #[test]
    fn a_real_client_c2_fsync_produce_acks_only_after_quorum_fsync_not_leader_only() {
        use ironbus_proto::message::{encode_pub, PubBody as ProtoPubBody};
        let (addr, shutdown, serve_handle, gate) = start_clustered_c2_server();

        // A REAL client connection over loopback.
        let mut conn = raw_connect(addr);

        // Send a normal (Level-1) PUB. On this clustered C2-fsync serve the produce is durable on the
        // leader (its local fsync, I2) but its wire PubAck is WITHHELD by the gate until the ISR quorum
        // fsyncs the offset — the leader-only-fsync ack is NOT sent.
        let mut pub_body = Vec::new();
        encode_pub(
            &ProtoPubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"quorum-gated",
            },
            &mut pub_body,
        )
        .unwrap();
        conn.write_frame(FrameType::Pub, &pub_body);

        // BEFORE quorum: drive a few broker passes (Pings). The PubAck must NOT appear — the leader has
        // locally fsync'd (durable) but no follower has reported, so the 2-of-3 quorum is not met. This
        // is the property under test: NO leader-only-fsync ack on the real client wire.
        for _ in 0..3 {
            let frames = conn.ping_round();
            assert!(
                frames.iter().all(|(ty, _)| *ty != FrameType::PubAck),
                "the C2-fsync produce's wire PubAck is WITHHELD before quorum-fsync (got {frames:?})"
            );
        }

        // The data plane (here, the test driving the SHARED gate exactly as the runtime's follower
        // thread does) receives a follower's report bringing the 2-of-3 quorum: follower 2 has fsync'd
        // offset 0 (frontier 1), and the leader already fsync'd it (the produce path advanced the leader
        // frontier), so the quorum-commit now covers offset 0 and the parked ack RELEASES into this
        // connection's outbox.
        let released = gate.on_follower_report(
            C2_PARTITION,
            &ironbus_server::cluster::AckReplicatedBody {
                follower_id: 2,
                fsynced_offset: 1,
            },
        );
        assert_eq!(
            released, 1,
            "the follower report brought quorum and released the parked ack"
        );

        // AFTER quorum: the next broker pass (Ping) flushes the released PubAck onto the wire. The CLIENT
        // now observes its quorum-durable ack — only after quorum-fsync, never on leader-only-fsync.
        let mut got_ack = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while got_ack.is_none() && std::time::Instant::now() < deadline {
            for (ty, body) in conn.ping_round() {
                if ty == FrameType::PubAck {
                    got_ack = Some(body);
                    break;
                }
            }
        }
        let ack_body = got_ack.expect("the wire PubAck arrives after the quorum-fsync report");
        let ack = ironbus_proto::message::decode_pub_ack(&ack_body).unwrap();
        assert_eq!(
            ack.offset, 0,
            "the released PubAck is the REAL reply for the produced offset (the durable offset 0)"
        );

        drop(conn);
        shutdown.store(true, Ordering::Release);
        serve_handle.join().unwrap();
    }

    // ---- #735 client NOT_LEADER redirect classification ----------------------------------------

    #[test]
    fn a_not_leader_frame_classifies_as_a_redirect_with_the_leader_hint() {
        use ironbus_proto::message::{encode_not_leader, NotLeaderBody};
        // A NotLeader frame carrying a concrete leader hint classifies as a redirect to that address.
        let mut body = Vec::new();
        encode_not_leader(
            &NotLeaderBody {
                leader_hint: "127.0.0.1:9002",
            },
            &mut body,
        )
        .unwrap();
        match classify_pub_reply(FrameType::NotLeader, &body).unwrap() {
            PubReply::NotLeader(Some(addr)) => assert_eq!(addr, "127.0.0.1:9002"),
            other => panic!("expected a NotLeader redirect with a hint, got {other:?}"),
        }
        // The single-produce path surfaces it as the typed ClientError::NotLeader with the hint.
        match not_leader_error(&body) {
            ClientError::NotLeader {
                leader_hint: Some(addr),
            } => assert_eq!(addr, "127.0.0.1:9002"),
            other => panic!("expected ClientError::NotLeader with a hint, got {other}"),
        }
    }

    #[test]
    fn a_hintless_not_leader_frame_classifies_as_a_redirect_with_no_hint() {
        use ironbus_proto::message::{encode_not_leader, NotLeaderBody};
        // An EMPTY leader hint (the server did not yet know the leader) classifies as a redirect with no
        // hint — the caller re-discovers the leader from its own peers.
        let mut body = Vec::new();
        encode_not_leader(&NotLeaderBody { leader_hint: "" }, &mut body).unwrap();
        match classify_pub_reply(FrameType::NotLeader, &body).unwrap() {
            PubReply::NotLeader(None) => {}
            other => panic!("expected a hintless NotLeader redirect, got {other:?}"),
        }
        match not_leader_error(&body) {
            ClientError::NotLeader { leader_hint: None } => {}
            other => panic!("expected a hintless ClientError::NotLeader, got {other}"),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // #735 (V2 client cluster-awareness): a REAL client connection is transparently routed —
    //   A. a produce to a NON-leader node is answered NOT_LEADER + a leader hint, and the client
    //      retries to the leader where the produce succeeds (quorum-acked);
    //   B. a consume from a FOLLOWER node serves committed records over the wire, never past the
    //      safe watermark.
    // ---------------------------------------------------------------------------------------------

    /// A handle to one in-process broker spun up for the #735 tests: its address + the shared gate (so a
    /// test can drive a follower's quorum-fsync report, like the runtime's follower thread), plus the
    /// shutdown flag and serve thread.
    #[cfg(unix)]
    #[allow(dead_code)]
    struct ClusterBroker {
        addr: std::net::SocketAddr,
        gate: Arc<ironbus_server::cluster::ClientAckGate<InMemoryFs, SystemClock>>,
        shutdown: Arc<AtomicBool>,
        serve: std::thread::JoinHandle<()>,
    }

    #[cfg(unix)]
    impl ClusterBroker {
        fn stop(self) {
            self.shutdown.store(true, Ordering::Release);
            self.serve.join().unwrap();
        }
    }

    /// The shared engine config for the #735 brokers (sync durability, a generous credit).
    #[cfg(unix)]
    fn cluster_test_engine_config() -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
            log: LogConfig::default(),
            lease: LeaseConfig::default(),
            delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
            max_in_flight: 16,
            consumer_credit: 256,
            consumer_credit_bytes: 0,
            checkpoint_interval: 1024,
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
        }
    }

    /// Build one clustered broker for partition 0 of `{1,2,3}` (`min_isr = 2`). When `lead` is true this
    /// node LEADS (so a produce here is quorum-gated, never redirected); when false it FOLLOWS (leader is
    /// node 2) over a replica log pre-seeded by replicating `seed_records` from a leader plane, so a real
    /// client consume here serves committed records. `leader_client_addr` is advertised as node 2's CLIENT
    /// address (the `NOT_LEADER` hint). The follower's committed-HW status covers the whole replicated
    /// prefix.
    #[cfg(unix)]
    #[allow(clippy::too_many_lines)] // one cohesive broker-build helper (leader or follower role + wiring)
    fn start_cluster_broker(
        lead: bool,
        leader_client_addr: Option<std::net::SocketAddr>,
        seed_records: u32,
    ) -> ClusterBroker {
        use ironbus_server::actor::EngineHandle;
        use ironbus_server::cluster::{
            ClientAckGate, ClusterAckLevel, ClusterStatus, DataPlaneController, DataPlaneServer,
            IsrConfig, ProduceAckSeam,
        };
        use ironbus_storage::log::{Append, Log};
        use std::collections::BTreeMap;
        use std::sync::{Mutex, OnceLock};

        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            cluster_test_engine_config(),
        )
        .unwrap();

        let isr = IsrConfig {
            min_isr: 2,
            max_lag_records: 0,
        };
        let self_id = if lead { 1 } else { 3 };
        let mut controller = DataPlaneController::new(self_id);
        let mut committed_hw = 0u64;
        if lead {
            let leader_log: &'static mut Log<InMemoryFs, SystemClock> = Box::leak(Box::new(
                Log::open(InMemoryFs::new(), SystemClock::new(), LogConfig::default()).unwrap(),
            ));
            controller.start_leader(
                C2_PARTITION,
                Arc::new(leader_log.read_plane().unwrap()),
                ironbus_core::epoch_cache::EpochCache::new(),
                &[1, 2, 3],
                isr,
            );
        } else {
            // Seed a leader plane, then replicate it into this node's follower log (the in-process
            // catch-up the dataplane tests use), so the follower holds a committed prefix to serve.
            let small = LogConfig {
                max_segment_bytes: 256,
                max_total_bytes: 0,
                ..LogConfig::default()
            };
            let leader_log: &'static mut Log<InMemoryFs, SystemClock> = Box::leak(Box::new(
                Log::open(InMemoryFs::new(), SystemClock::new(), small).unwrap(),
            ));
            for i in 0..seed_records {
                leader_log
                    .append(&Append {
                        timestamp_ms: 7,
                        flags: ironbus_core::types::RecordFlags::EMPTY,
                        key: b"",
                        headers: b"",
                        payload: format!("c735-{i:02}").as_bytes(),
                    })
                    .unwrap();
            }
            leader_log.sync().unwrap();
            let plane = Arc::new(leader_log.read_plane().unwrap());
            let mut served_end = 0u64;
            loop {
                let raw = plane
                    .read_range_raw(ironbus_core::types::Offset::new(served_end), 1_000, None)
                    .unwrap();
                let next = raw.run.next_offset.get();
                if next <= served_end {
                    break;
                }
                served_end = next;
            }
            committed_hw = served_end;
            let mut leader_ctrl: DataPlaneController<InMemoryFs, SystemClock> =
                DataPlaneController::new(2);
            leader_ctrl.start_leader(
                C2_PARTITION,
                Arc::clone(&plane),
                ironbus_core::epoch_cache::EpochCache::new(),
                &[1, 2, 3],
                isr,
            );
            controller.start_follower(
                C2_PARTITION,
                Log::open(InMemoryFs::new(), SystemClock::new(), small).unwrap(),
            );
            for _ in 0..(served_end + 8) {
                if controller.follower_high_watermark(C2_PARTITION).unwrap() >= served_end {
                    break;
                }
                let req = controller
                    .make_fetch_request(C2_PARTITION, 8, 4096)
                    .unwrap();
                let resp = leader_ctrl.serve_fetch(C2_PARTITION, &req).unwrap();
                controller
                    .apply_fetch_response(C2_PARTITION, &resp)
                    .unwrap();
            }
        }

        let mut server = DataPlaneServer::new(self_id, ProduceAckSeam::new(controller));
        if !lead {
            server.set_follower_target(C2_PARTITION, 2);
        }
        let mut addrs: BTreeMap<u64, std::net::SocketAddr> = BTreeMap::new();
        if let Some(a) = leader_client_addr {
            addrs.insert(2, a);
        }
        let mut status = ClusterStatus::default();
        status.last_committed_hw.insert(C2_PARTITION, committed_hw);
        let gate = Arc::new(
            ClientAckGate::new(Arc::new(Mutex::new(server)), ClusterAckLevel::C2Fsync)
                .with_leader_client_addrs(addrs)
                .with_status_handle(Arc::new(Mutex::new(status))),
        );

        let slot: ironbus_server::actor::ClientAckSlot<InMemoryFs, SystemClock> =
            Arc::new(OnceLock::new());
        slot.set(Arc::clone(&gate)).ok();
        let (handle_engine, _actor): (EngineHandle<InMemoryFs, SystemClock>, _) =
            spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let handle_engine = handle_engine.with_client_ack_slot(slot);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let serve = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = SystemClock::new();
                let beacon =
                    ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &handle_engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });
        ClusterBroker {
            addr,
            gate,
            shutdown,
            serve,
        }
    }

    /// Drive a follower quorum-fsync report on `gate` until it RELEASES a parked C2-fsync ack (or a
    /// deadline) — standing in for the data-plane runtime's follower thread, on a side thread so a client
    /// can await its quorum-gated `PubAck`.
    #[cfg(unix)]
    fn spawn_quorum_releaser(
        gate: Arc<ironbus_server::cluster::ClientAckGate<InMemoryFs, SystemClock>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if gate.on_follower_report(
                    C2_PARTITION,
                    &ironbus_server::cluster::AckReplicatedBody {
                        follower_id: 2,
                        fsynced_offset: 1,
                    },
                ) > 0
                {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    }

    /// A: a real client produces to a NON-leader node, gets `NOT_LEADER` + the leader hint, transparently
    /// retries to the leader where the produce SUCCEEDS and is quorum-acked (#720). The end-to-end #735
    /// half-A proof over real sockets.
    #[cfg(unix)]
    #[test]
    fn a_real_client_redirects_a_not_leader_produce_to_the_leader_and_succeeds() {
        let leader = start_cluster_broker(true, None, 0);
        let follower = start_cluster_broker(false, Some(leader.addr), 0);

        let mut client = Client::connect(follower.addr).unwrap();
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"to-the-leader",
        };
        // A bare produce on the FOLLOWER gets a typed NotLeader redirect carrying the leader's address.
        match client.produce(&msg) {
            Err(ClientError::NotLeader { leader_hint }) => {
                assert_eq!(
                    leader_hint.as_deref(),
                    Some(leader.addr.to_string().as_str()),
                    "the redirect carries the current leader's client address as the hint"
                );
            }
            other => panic!("expected a NotLeader redirect from the follower, got {other:?}"),
        }

        // produce_to_leader follows the hint: it reconnects to the leader and retries there, where the
        // C2-fsync ack is quorum-gated (#719) — release it on a side thread.
        let releaser = spawn_quorum_releaser(Arc::clone(&leader.gate));
        let offset = client
            .produce_to_leader(&msg, &ClientConfig::default(), 3)
            .expect("the produce succeeds on the leader after the redirect");
        assert_eq!(offset, 0, "the leader assigned the durable offset 0");
        releaser.join().unwrap();

        leader.stop();
        follower.stop();
    }

    /// A no-false-NOT_LEADER guard: a produce to the actual LEADER proceeds (quorum-gated), never a
    /// redirect.
    #[cfg(unix)]
    #[test]
    fn a_real_client_produce_to_the_leader_is_not_redirected() {
        let leader = start_cluster_broker(true, None, 0);
        let mut client = Client::connect(leader.addr).unwrap();
        let releaser = spawn_quorum_releaser(Arc::clone(&leader.gate));
        let offset = client
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"on-the-leader",
            })
            .expect("a produce to the leader proceeds (never a NotLeader redirect)");
        assert_eq!(offset, 0, "the leader assigned offset 0 (no redirect)");
        releaser.join().unwrap();
        leader.stop();
    }

    /// B: a real client CONSUMES committed records from a FOLLOWER node over the wire (a Tier-S
    /// `StreamFetch`), byte-faithfully, never past the safe watermark. The end-to-end #735 half-B proof.
    #[cfg(unix)]
    #[test]
    fn a_real_client_consumes_committed_records_from_a_follower_over_the_wire() {
        use ironbus_proto::message::{encode_stream_fetch, StreamFetchBody};
        const N: u32 = 12;
        let follower = start_cluster_broker(false, None, N);

        let cfg = ClientConfig {
            understands_streaming: true,
            ..ClientConfig::default()
        };
        let mut conn = raw_connect_with(follower.addr, &cfg);

        let mut body = Vec::new();
        encode_stream_fetch(
            &StreamFetchBody {
                start_offset: 0,
                max_records: 1_000,
                max_bytes: 0,
            },
            &mut body,
        );
        conn.write_frame(FrameType::StreamFetch, &body);

        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                std::time::Instant::now() <= deadline,
                "follower-read response did not terminate"
            );
            match conn.next_frame() {
                Some((FrameType::Deliver, b)) => {
                    let d = ironbus_proto::message::decode_deliver(&b).unwrap();
                    payloads.push(d.payload.to_vec());
                }
                Some((FrameType::FlowEnd, _)) => break,
                Some((other, _)) => {
                    panic!("unexpected frame in a follower-read response: {other:?}")
                }
                // A read-timeout with no whole frame yet: loop and re-check the deadline.
                None => {}
            }
        }
        assert!(
            !payloads.is_empty(),
            "the follower served committed records over the wire (not vacuously empty)"
        );
        assert!(
            payloads.len() <= N as usize,
            "the follower never serves more than the committed prefix"
        );
        for (i, p) in payloads.iter().enumerate() {
            assert_eq!(
                p.as_slice(),
                format!("c735-{i:02}").as_bytes(),
                "follower-read payload {i} is byte-faithful"
            );
        }

        drop(conn);
        follower.stop();
    }

    /// A raw connection with an explicit handshake `config` (so a test can advertise Tier-S streaming).
    #[cfg(unix)]
    fn raw_connect_with(addr: std::net::SocketAddr, config: &ClientConfig) -> RawConn {
        use ironbus_proto::message::{encode_connect, ConnectBody};
        let stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut conn = RawConn {
            stream,
            buf: Vec::new(),
        };
        let mut body = Vec::new();
        encode_connect(
            &ConnectBody {
                understands_streaming: config.understands_streaming,
                ..ConnectBody::default()
            },
            &mut body,
        );
        conn.write_frame(FrameType::Connect, &body);
        let (ty, _b) = conn.next_frame().expect("Info handshake reply");
        assert_eq!(ty, FrameType::Info);
        conn
    }

    /// Byte-identical guarantee (#735 non-negotiable 1): a NON-cluster broker's produce + consume hot
    /// path is unchanged — a produce returns a normal `PubAck` (NEVER a `NotLeader` redirect), and the
    /// record round-trips byte-faithfully on consume. The non-cluster `start_server` broker builds NO
    /// `ClientAckGate`, so `cluster_produce_routing`/`cluster_follower_consume` take their cheap default
    /// (`Local` / `None`) and the produce + consume paths are the existing ones.
    #[test]
    fn a_non_cluster_produce_and_consume_is_never_redirected_or_follower_routed() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        // A produce on a non-cluster broker returns a normal PubAck offset — never a NotLeader redirect.
        let offset = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"single-node",
            })
            .expect("a non-cluster produce returns a PubAck, never a NotLeader redirect");
        assert_eq!(offset, 0, "the single-node broker assigned offset 0");
        // The consume round-trips the record byte-faithfully through the normal (non-follower) path.
        let messages = c.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 1, "the record is consumed normally");
        assert_eq!(messages[0].offset, 0);
        assert_eq!(messages[0].payload.as_slice(), b"single-node");
        drop(c);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    // ---- transactional half-message 2PC client API (#640, V2-M8) ----

    fn txn_pub(payload: &'static [u8]) -> PubBody<'static> {
        PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload,
        }
    }

    #[test]
    fn txn_prepare_commit_delivers_only_after_commit_against_a_real_server() {
        // End-to-end over the real wire: a prepared half message is INVISIBLE to a fetch until commit,
        // then it appears exactly once.
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect(addr).unwrap();
        let txn = producer.prepare("", &txn_pub(b"half")).unwrap();

        // A separate consumer connection sees NOTHING while the txn is only prepared.
        let mut consumer = Client::connect(addr).unwrap();
        assert!(
            consumer.fetch(10).unwrap().messages.is_empty(),
            "a prepared-but-uncommitted half message is invisible"
        );

        // Commit returns the committed offset.
        let offset = producer.commit(&txn).unwrap();
        assert_eq!(offset, 0);
        // A retried commit is idempotent (same offset, no double-append).
        assert_eq!(producer.commit(&txn).unwrap(), 0);

        // Now the consumer sees the committed record exactly once.
        let messages = consumer.fetch(10).unwrap().messages;
        assert_eq!(
            messages.len(),
            1,
            "the committed half message is delivered exactly once"
        );
        assert_eq!(messages[0].payload.as_slice(), b"half");

        drop(producer);
        drop(consumer);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn txn_rollback_never_delivers_against_a_real_server() {
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect(addr).unwrap();
        let txn = producer.prepare("", &txn_pub(b"secret")).unwrap();
        producer.rollback(&txn).unwrap();
        // A retried rollback is a benign success.
        producer.rollback(&txn).unwrap();
        // commit-after-rollback is refused (Server error), never flipped.
        assert!(matches!(producer.commit(&txn), Err(ClientError::Server(_))));

        let mut consumer = Client::connect(addr).unwrap();
        assert!(
            consumer.fetch(10).unwrap().messages.is_empty(),
            "a rolled-back half message is never delivered"
        );

        drop(producer);
        drop(consumer);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn txn_prepare_with_a_producer_supplied_id_round_trips() {
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect(addr).unwrap();
        let txn = TxnId::new(b"my-own-uuid-1234".to_vec());
        producer.prepare_with_id(&txn, "", &txn_pub(b"v")).unwrap();
        // Re-preparing the same id is a benign no-op server-side.
        producer.prepare_with_id(&txn, "", &txn_pub(b"v")).unwrap();
        let offset = producer.commit(&txn).unwrap();
        assert_eq!(offset, 0);
        let mut consumer = Client::connect(addr).unwrap();
        assert_eq!(consumer.fetch(10).unwrap().messages.len(), 1);
        drop(producer);
        drop(consumer);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn transact_commits_a_successful_local_transaction_and_rolls_back_a_failed_one() {
        // #640 part 2: the `transact` runner — a successful local transaction commits the half message
        // (visible), a failed one rolls it back (never delivered, the local error surfaced).
        let (addr, shutdown, handle) = start_server();
        let mut producer = Client::connect(addr).unwrap();
        // A successful local transaction: commit -> visible.
        let ok_txn = TxnId::new(b"txn-ok".to_vec());
        let off = producer
            .transact(&ok_txn, "", &txn_pub(b"committed"), || Ok::<(), String>(()))
            .unwrap();
        assert_eq!(off, 0);
        // A failed local transaction: rollback -> never delivered, the error surfaces.
        let bad_txn = TxnId::new(b"txn-bad".to_vec());
        let err = producer
            .transact(&bad_txn, "", &txn_pub(b"discarded"), || {
                Err::<(), String>("local failure".to_string())
            })
            .unwrap_err();
        assert!(
            matches!(err, ClientError::LocalTransaction(m) if m.contains("local failure")),
            "a failed local transaction rolls back and surfaces the error"
        );
        // Only the committed record is visible.
        let mut consumer = Client::connect(addr).unwrap();
        let messages = consumer.fetch(10).unwrap().messages;
        assert_eq!(messages.len(), 1, "only the committed half is delivered");
        assert_eq!(messages[0].payload, b"committed");
        drop(producer);
        drop(consumer);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_headline_back_check_resolves_a_crashed_producers_half_over_the_wire() {
        // THE HEADLINE over the REAL wire: producer A registers a listener (group "svc"), prepares a half
        // message with a STABLE id, then DISCONNECTS before resolving (a crash). Producer B reconnects,
        // re-registers the SAME group, and runs its transaction-state listener; the broker's back-check
        // routes a TxnCheck to it, the listener answers Commit, and the half message is committed exactly
        // once — a consumer then sees it. A 0-timeout back-check makes the half immediately eligible so
        // the test does not wait out the production window.
        let (addr, shutdown, handle) = start_server_with_back_check(0, 5);
        let txn_id = b"order-stable-uuid".to_vec();
        // Producer A: register the listener, prepare, then "crash" (drop the connection without
        // resolving).
        {
            let mut a = Client::connect(addr).unwrap();
            a.register_transaction_listener(b"svc").unwrap();
            a.prepare_with_id(&TxnId::new(txn_id.clone()), "", &txn_pub(b"order-42"))
                .unwrap();
            // CRASH: drop A without commit/rollback. Its half message is now in-doubt.
        }
        // Producer B: the SAME producer reconnecting. Re-register the SAME group, then run the listener
        // loop, which answers the broker's back-check for the in-doubt txn with Commit.
        let mut b = Client::connect(addr).unwrap();
        b.register_transaction_listener(b"svc").unwrap();
        let answered = b
            .run_transaction_listener(
                |id| {
                    // The producer's durable local state says this transaction committed.
                    if id == txn_id.as_slice() {
                        TxnDecision::Commit
                    } else {
                        TxnDecision::Unknown
                    }
                },
                Duration::from_secs(5),
            )
            .unwrap();
        assert!(answered >= 1, "the back-check was answered at least once");
        // The half message is now committed exactly once: a consumer sees it.
        let mut consumer = Client::connect(addr).unwrap();
        let mut delivered = Vec::new();
        for _ in 0..20 {
            let messages = consumer.fetch(10).unwrap().messages;
            for m in messages {
                delivered.push(m.payload.clone());
                consumer.ack(m.offset, m.generation).unwrap();
            }
            if !delivered.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            delivered,
            vec![b"order-42".to_vec()],
            "the crashed producer's half is committed exactly once by the back-check"
        );
        drop(b);
        drop(consumer);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_back_check_rollback_answer_never_delivers_over_the_wire() {
        // The sibling of the headline: the reconnected listener answers Rollback -> the in-doubt half is
        // discarded and never delivered.
        let (addr, shutdown, handle) = start_server_with_back_check(0, 5);
        let txn_id = b"abort-stable-uuid".to_vec();
        {
            let mut a = Client::connect(addr).unwrap();
            a.register_transaction_listener(b"svc").unwrap();
            a.prepare_with_id(&TxnId::new(txn_id.clone()), "", &txn_pub(b"secret"))
                .unwrap();
        }
        let mut b = Client::connect(addr).unwrap();
        b.register_transaction_listener(b"svc").unwrap();
        b.run_transaction_listener(|_id| TxnDecision::Rollback, Duration::from_secs(5))
            .unwrap();
        // The half is discarded: a consumer sees nothing even after a few fetch attempts.
        let mut consumer = Client::connect(addr).unwrap();
        for _ in 0..10 {
            assert!(
                consumer.fetch(10).unwrap().messages.is_empty(),
                "a rolled-back half is never delivered"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(b);
        drop(consumer);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }
}
