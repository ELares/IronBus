// SPDX-License-Identifier: MIT OR Apache-2.0
//! The connection session: it frames the wire protocol onto the engine.
//!
//! A session reads frames from a connection's input buffer, dispatches each to the
//! [`Engine`], and writes response frames back. It is synchronous and buffer-driven: it
//! consumes only the complete frames at the front of the input (a partial trailing frame
//! is left for the next read) and never blocks, so the async TCP server can drive it from
//! a byte stream without owning any IO here. Request/response verbs only: produce (`Pub`),
//! acknowledge (`Ack`), the handshake (`Connect`/`Info`), and keepalive (`Ping`/`Pong`).
//! The streaming consumer-fetch path and capability negotiation are follow-ups.
//!
//! Response frames are self-describing per verb (#179): a `Pub` is answered by a `PubAck`
//! whose body is the 8-byte little-endian assigned offset; an `Ack`/`Nack`/`Term`/`Progress`
//! by an `AckStatus` whose body is a one-byte status; a `Flow` batch by a `FlowEnd` whose
//! body is the 4-byte little-endian delivered count; and `Err` carries a UTF-8 message. A
//! malformed frame envelope is unrecoverable for a length-prefixed stream, so it ends the
//! session.

use crate::actor::{
    ActorGone, EngineAccess, OwnedAppend, OwnedDedup, ProduceOutcome, ProduceSubmission, TryTake,
};
use crate::cluster::dataplane::FollowerReadOutcome;
use crate::cluster::read_consistency::ReadTier;
use crate::engine::{
    AckResult, Engine, EngineError, NackResult, Poll, ProgressResult, StreamBatch, StreamRawBatch,
};
use bytes::Bytes;
use ironbus_core::binding::{single_home, Resolution};
use ironbus_core::clock::Clock;
use ironbus_core::codec::BodyChecksums;
use ironbus_core::compress::{
    decompress_payload, validate_descriptor_shape, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES,
};
use ironbus_core::confirm::{ConfirmStatus, ReadyConfirm};
use ironbus_core::dedup::{MAX_MSG_ID_LEN, MAX_PRODUCER_ID_LEN};
use ironbus_core::keyshared::{KeyOrdering, MemberId};
use ironbus_core::lease::LeaseToken;
use ironbus_core::resolve_cache::ResolveCache;
use ironbus_core::subject::Subject;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{
    decode_ack, decode_bind_subject, decode_connect, decode_cumulative_ack, decode_fetch,
    decode_pub, decode_pub_subject, decode_pub_to, decode_stream_commit, decode_stream_declare,
    decode_stream_fetch, decode_stream_info, decode_sub, decode_sub_subject, decode_sub_to,
    decode_txn_check_result, decode_txn_listen, decode_txn_prepare, decode_txn_resolve,
    encode_dead_letter, encode_deliver, encode_deliver_batch_frame, encode_gap_marker, encode_info,
    encode_not_leader, encode_produce_confirm, encode_pub_ack, encode_stream_info_response,
    encode_truncated, encode_txn_resolve, gap_reason, parse_connect_auth, produce_confirm_status,
    pub_ack_level, AckLevel, AckOp, ConsumeTier, CreditAdvert, DeadLetterBody, DeliverBatchHeader,
    DeliverBody, GapMarkerBody, InfoBody, NotLeaderBody, ProduceConfirmBody, PubAckBody,
    StreamInfoResponseBody, TruncatedBody, TxnResolveBody, DEAD_LETTER_MAX_DELIVER,
    PUB_WIRE_ONLY_FLAGS,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Append;
use ironbus_storage::streamset::StreamId;
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// A session error that ends the connection.
#[derive(Debug)]
pub enum SessionError {
    /// The frame envelope was malformed (a zero or over-cap length prefix); a
    /// length-prefixed stream cannot resync, so the connection must close.
    BadFrame(FrameError),
    /// The engine hit a fatal, unrecoverable error (a frozen writer or a broken
    /// invariant): retrying is pointless, so the session ends. The real error is carried
    /// for the caller to log.
    EngineFatal(EngineError),
    /// The append actor is no longer running (it exited or panicked), so no engine command can
    /// be served: the session ends cleanly rather than hanging on a dead actor. This is the
    /// typed "actor gone" path (#177): a closed channel is an error, never a panic.
    ActorGone,
    /// An authentication or authorization failure on an auth-required broker (#631, V2-M7): the
    /// uniform "Authorization Violation" `Err` frame has ALREADY been written to the output buffer
    /// (so the client receives it), and the connection must now CLOSE — per the auth contract, every
    /// authn/authz failure replies the one uniform error and then closes. The variant carries no
    /// sub-reason on the wire (the `Err` body is the fixed message with no code), so it leaks no
    /// oracle; the trusted-side detail lives in the (future #635) audit log, never here.
    AuthViolation,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::BadFrame(e) => write!(f, "malformed frame, closing session: {e}"),
            SessionError::EngineFatal(e) => write!(f, "fatal engine error, closing session: {e}"),
            SessionError::ActorGone => {
                write!(f, "the append actor is gone, closing session")
            }
            SessionError::AuthViolation => {
                write!(f, "authorization violation, closing session")
            }
        }
    }
}

impl From<ActorGone> for SessionError {
    fn from(_: ActorGone) -> Self {
        SessionError::ActorGone
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionError::BadFrame(e) => Some(e),
            SessionError::EngineFatal(e) => Some(e),
            _ => None,
        }
    }
}

/// The result of one [`Session::process`] pass over a connection's input buffer: how much was
/// consumed and the minimum buffer length before the next pass can make progress on the partial
/// trailing frame. The `needed` hint is what lets the connection loop avoid the O(n^2) re-decode of
/// a trickled near-cap frame (#176): it only re-calls `process` once the buffer reaches `needed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// The number of input bytes consumed (the complete frames at the front were dispatched).
    pub consumed: usize,
    /// The minimum length the POST-DRAIN buffer (after `consumed` bytes are drained) must reach
    /// before another `process` pass can make progress on the trailing partial frame. `0` when no
    /// partial frame remains (everything decoded cleanly), so the next pass should run as soon as
    /// ANY new byte arrives.
    pub needed: usize,
    /// Whether this pass processed any frame that may have advanced a work-group's committed cursor
    /// (an `Ack`/`Flow`), so the caller knows whether the interval checkpoint is worth running. It is
    /// `false` for a ping-only (or connect-only) pass, which is what keeps a ping off the actor's
    /// checkpoint path entirely: a ping never triggers a `maybe_checkpoint` command, so a stalled
    /// produce fsync on another connection cannot head-of-line-block it (invariant 4, #177).
    pub committed_progress: bool,
}

/// One entry in a session's connection-scoped in-flight set (#175, #275): the generation the lease
/// was granted under (the fencing token half) and the message's byte size (its key plus headers plus
/// payload length, matching the engine's produced-bytes accounting). The generation fences acks to
/// the exact lease this connection received; the byte size lets the per-consumer byte budget be
/// DERIVED from the in-flight set rather than tracked in a separate, driftable counter.
#[derive(Clone, Copy, Debug)]
struct Lease {
    /// The lease generation this connection was granted, for fencing acks (#175).
    generation: u64,
    /// The message's byte size (key + headers + payload), for the per-consumer byte budget (#275).
    bytes: u64,
}

/// Per-connection session state over a shared [`Engine`].
///
/// # Per-consumer credit (refs #65, #275, #9, #10)
///
/// Each session has its own standing in-flight credit: a connection may hold at most
/// `credit_ceiling` un-acked messages at once (the ceiling comes from
/// [`Engine::consumer_credit`], read once on the first Flow and cached, default 64, NOT 65535).
/// The accounting is DERIVED from the connection-scoped `leased` set (#175) rather than a separate
/// counter, so it can never drift from true ownership: the messages this connection currently holds
/// ARE exactly the entries in `leased`, so its remaining message credit is always
/// `credit_ceiling - leased.len()`.
///
/// A parallel per-consumer BYTE budget (#275) caps the un-acked PAYLOAD bytes a connection may hold,
/// the RAM-side companion to the message count (the ceiling comes from
/// [`Engine::consumer_credit_bytes`], read once on the first Flow and cached, default 8 MiB, `0` =
/// unlimited). It too is DERIVED from `leased`: each entry carries the byte size of its message, so
/// the bytes in flight are always the sum of `leased`'s values, and the byte budget cannot drift any
/// more than the message count can. The EFFECTIVE per-Flow credit is
/// `min(message credits remaining, byte credits remaining)`, with a hard floor of ONE message: a
/// single message larger than the whole byte budget is still delivered (so an over-budget message
/// never wedges the consumer), but no further message is sent until bytes free up.
///
/// A Flow fetch (see [`Session::handle_flow`]) delivers at most
/// `min(requested_credit, message credits remaining, byte credits remaining, whatever the group
/// makes available)` (subject to the floor of one), so the EFFECTIVE bound is the MIN of the
/// producer-side group window ([`crate::engine::EngineConfig::max_in_flight`]), this per-consumer
/// message ceiling, and this per-consumer byte budget. Each delivery inserts into `leased` (occupying
/// one message slot and its bytes); an ack, a successful nack/term, the per-batch prune of committed
/// offsets, and the start-of-Flow prune of leases the engine no longer holds (redelivery accounting)
/// all REMOVE from `leased`, restoring BOTH the message slot and its bytes. At zero remaining message
/// credit OR a full byte budget a Flow delivers nothing (beyond the floor of one) until the consumer
/// frees a slot, even if the group has messages and other consumers are draining.
///
/// ## Per-consumer isolation
///
/// Because the credit and the `leased` set are per CONNECTION, one stuck consumer that fills its
/// ceiling and stops acking pins ONLY its own slots; it never touches another connection's `leased`
/// set or its remaining credit, so it cannot reduce a peer's available deliveries. When the
/// per-group window is the binding constraint instead, both consumers share the same group
/// backpressure, which is the intended behavior.
///
/// ## Redelivery accounting
///
/// When one of this session's leases expires, the engine redelivers the message to whoever next
/// polls (the same or another consumer), under a fresh generation. The stale `(offset, generation)`
/// this session still holds is no longer a live lease the engine recognizes. At the start of each
/// Flow, [`Session::release_stale_leases`] drops every `leased` entry the engine no longer holds
/// ACTIVELY (via [`Engine::holds_active_lease_in`]), which FREES this consumer's slot; the redelivery to whoever
/// next polls is counted against THAT consumer's credit when their Flow inserts it. No message is
/// lost or double-counted, and at-least-once is preserved (the message is still leased and will
/// redeliver until acked). The freed slot restores BOTH the message credit and the message's bytes;
/// when the message is recounted against whoever next claims it, it re-occupies exactly its bytes
/// once (the redelivery overwrites the same offset key in `leased`, so the byte total never doubles).
// Each bool is an INDEPENDENT piece of per-connection protocol state (handshake done, key_shared
// membership, broadcast registration, gap-marker capability), not a set of related options that
// would read better as one enum/bitset, so the four-bool count is intentional rather than a smell.
/// A work-group name held cheaply for per-op hand-off to the engine actor (#487). Wraps an
/// `Arc<str>` so each clone is an atomic refcount bump (no per-op heap allocation) and derefs to
/// `str`, so the engine's `BTreeMap<String, _>` lookup still receives a plain `&str`. The manual
/// `Default` (an empty name selects the default group) keeps the broker's 1.78 MSRV, since
/// `Arc<str>: Default` only exists from Rust 1.80.
#[derive(Debug, Clone)]
struct GroupName(Arc<str>);

impl Default for GroupName {
    fn default() -> Self {
        GroupName(Arc::from(""))
    }
}

impl std::ops::Deref for GroupName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for GroupName {
    fn from(s: &str) -> Self {
        GroupName(Arc::from(s))
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub struct Session {
    connected: bool,
    /// The pass-scoped LEVEL-0 (no-ack / fire-and-forget) produce batch (#11 fast path): Level-0
    /// produces decoded from one socket read accumulate here and are handed to the actor as ONE
    /// `produce_no_reply_batch` send at the flush boundary, instead of one channel send per message —
    /// the broker-side twin of the client's coalescing `FireForgetProducer`, cutting the per-message
    /// session->actor handoff that caps QoS-0 ingest. It is FLUSHED (so the actor observes this
    /// connection's single total order) before any Level-1 produce or non-produce job and at the end of
    /// every pass, so it never holds state across passes. Empty (the `Default`) for a connection that
    /// never publishes Level-0, so a non-publishing or at-least-once-only connection is unchanged.
    level0_pending: Vec<OwnedAppend>,
    /// The PERSISTENT pipelined at-least-once produce window (#450, #1045): produces SUBMITTED to the
    /// append actor whose acks have not yet been released, kept ACROSS passes (unlike the pass-scoped
    /// `Vec` this used to be). Each pass parks new produces at the BACK and releases only the READY
    /// FRONT PREFIX ([`ProduceSubmission::try_take`], non-blocking) — it never block-awaits an
    /// un-fsync'd produce at the pass boundary anymore. That is what lets ONE connection keep reading
    /// and submitting the NEXT batch while the actor group-commits the CURRENT one (closing the
    /// single-connection ceiling #1045): the `Vec`-scoped drain used to stall the pass on batch N's
    /// fdatasync, starving batch N+1. A [`VecDeque`] so front-prefix release (`pop_front`) and back
    /// park (`push_back`) are both O(1). FIFO submission order is the wire ack order (#917): the front
    /// prefix is released strictly in order and a not-ready front stops the release (the rest are also
    /// not ready). Bounded at [`MAX_PARKED_PRODUCES`] (the connection block-drains the front when acks
    /// lag arrivals). Empty (the `Default`) for a connection that never at-least-once-publishes.
    parked: VecDeque<ParkedPub>,
    /// The work-group this connection is subscribed to, set by SUB and cleared by UNSUB.
    /// Empty selects the default group (#9), so an unsubscribed consumer behaves exactly as
    /// before. FLOW fetches and ACKs route to this group.
    ///
    /// Held as `Arc<str>` (#487): every consume op (ack/poll/cumulative-ack) hands the group name
    /// to the engine actor by VALUE because the job closure is `'static` (it crosses the actor
    /// channel), so the name must be owned, not borrowed. Cloning an `Arc<str>` is an atomic
    /// refcount bump with NO heap allocation, where cloning a `String` would allocate a fresh
    /// buffer per op — one allocation per delivered message on the FLOW hot path. The engine still
    /// receives a plain `&str` (the `Arc<str>` derefs), so its `BTreeMap<String, _>` lookup is
    /// unchanged. Empty (`Arc::default()`) selects the default group, exactly as the empty `String`
    /// did.
    subscription: GroupName,
    /// The leases this session was delivered via Flow and may still act on, keyed by offset to the
    /// granted generation AND the message's byte size (#65, #275). Acks are scoped to this map
    /// (#175), so one connection cannot ack a message delivered to another. Keying by offset bounds
    /// it to one entry per offset (a redelivery overwrites the stale lease), and committed offsets
    /// are pruned per batch, so it stays within the in-flight window. Its SIZE is this connection's
    /// in-flight message count and the SUM of its `bytes` is its in-flight byte total, so BOTH the
    /// per-consumer message credit and the byte budget (#275) are derived from it directly and cannot
    /// drift.
    leased: HashMap<u64, Lease>,
    /// The per-CONSUMER (per-connection) in-flight credit ceiling (#65), the NEGOTIATED value for this
    /// connection (#292). `None` until it is fixed; once set it never changes for the life of the
    /// connection, and the remaining message credit at any moment is `ceiling - leased.len()`. It is
    /// fixed at the FIRST of two points: at `Connect` time, to `min(client request, server cap)` when
    /// the client's `Connect` body requested a credit (the #292 negotiation); otherwise lazily on the
    /// first Flow, to the engine default ([`Engine::consumer_credit`]), exactly the pre-#292 behavior
    /// (so an old client that sends an empty `Connect` still gets the server default). The engine is the
    /// source of truth for the cap (a `serve` flag sets it once for every connection), and a session is
    /// created before it has an engine handle, so the default cannot be read at construction.
    credit_ceiling: Option<u32>,
    /// The per-CONSUMER (per-connection) in-flight BYTE budget (#275), the NEGOTIATED value for this
    /// connection (#292), fixed alongside `credit_ceiling` at `Connect` time (clamped to the server
    /// cap) or lazily on the first Flow (the engine default). `None` until fixed; once set it never
    /// changes. `0` means UNLIMITED (the byte budget is off, only the message credit binds). The
    /// remaining byte budget at any moment is `ceiling_bytes - (sum of leased values' bytes)`.
    credit_ceiling_bytes: Option<u64>,
    /// The per-consumer message credit the client REQUESTED in its `Connect` body (#292), `None` if it
    /// requested nothing (an old client, or a deliberate defer-to-default). Held so the clamp against
    /// the server cap can be applied LAZILY on the first Flow if the engine could not be read at
    /// `Connect` time (a transiently unavailable actor): `credit_ceiling` is normally fixed at Connect,
    /// but if that read fails this request is honored the next time the ceiling is computed. Never an
    /// unbounded value (the wire has no `request(MAX)`).
    requested_credit: Option<u32>,
    /// The per-consumer byte budget the client requested in its `Connect` body (#292), the byte-side
    /// companion to `requested_credit`. Same lazy-clamp fallback.
    requested_credit_bytes: Option<u64>,
    /// The per-consumer AUTO-TUNING credit window (#552): the message-count flow-control window that
    /// GROWS from the historical floor (64) toward the negotiated `credit_ceiling` as this consumer
    /// keeps draining, and BACKS OFF under backpressure (a would-block at a near-full in-flight set, or
    /// a nack). It reuses the egress [`ironbus_core::backpressure::CreditAutotuner`] (AIMD) so a
    /// fast/loopback consumer fills the pipe instead of being pinned at 64/RTT (the #464/#532 floor),
    /// while the byte budget (`credit_ceiling_bytes`) stays the FIRM RAM bound the count grows UNDER.
    ///
    /// `None` until the first Flow/Fetch fixes it (it needs the negotiated `credit_ceiling`, which is
    /// the auto-tune's ceiling); once set its CEILING never changes for the life of the connection,
    /// though its current window moves with keep-up / back-off. A consumer whose negotiated ceiling is
    /// at or below the floor never grows past its own cap (so an explicit small `--consumer-credit` is
    /// byte-for-byte the historical fixed window). At-least-once is untouched: the window only paces how
    /// many records may be in flight, never which are leased / acked / redelivered.
    credit_autotune: Option<ironbus_core::backpressure::CreditAutotuner>,
    /// This connection's stable `key_shared` member identity (#64): the rendezvous-hash seed the
    /// engine routes a key's records to. Minted once per connection by the server from an atomic
    /// counter, so two concurrently-live connections never collide. Only consulted for a group
    /// configured `key_shared`; a plain competing group ignores it.
    member_id: MemberId,
    /// Whether this connection is currently JOINED as a member of its subscribed `key_shared`
    /// group (#64), so leave-on-switch / leave-on-disconnect is exact: it only leaves a group it
    /// actually joined, and only joins once per subscription. `false` for a plain competing group.
    joined_key_shared: bool,
    /// Whether this connection is currently REGISTERED as an active subscriber of `subscription`
    /// (#288), so the broadcast group-of-one cap is exact and a deregister only ever targets a
    /// group this connection actually registered with. Set when a SUB to a NAMED group succeeds
    /// (the engine accepted the subscriber), cleared on UNSUB / subscription switch / disconnect.
    /// The default group (`""`) is never registered (its consumers do not SUB), so this stays
    /// `false` for an unsubscribed connection.
    registered_subscription: bool,
    /// Whether this consumer negotiated the consumer-visible `GapMarker` frame (#346): set at
    /// `Connect` time when the client advertised [`ironbus_proto::message::CONNECT_FLAG_WANTS_GAP_MARKER`].
    /// When `true`, a skipped span is surfaced as a `GapMarker` (tag 21, the richer `[from, to)` +
    /// `bytes_skipped` + reason marker); when `false` (an old client, or one that opted out) the
    /// SAME gap is surfaced as the legacy `Truncated` advisory (tag 18), so the two NEVER
    /// double-signal and an old consumer that would error on an unknown frame is never sent the new
    /// tag. Default `false` (backward-compatible).
    gap_marker_enabled: bool,
    /// Whether this connection negotiated the streaming consume tier (Tier-S, #543, V2-M1): set at
    /// `Connect` time when the client advertised
    /// [`ironbus_proto::message::CONNECT_FLAG_UNDERSTANDS_STREAMING`]. When `true`, the connection may be
    /// served Tier-S — including honoring a Tier-S `default_tier` so an unmarked SUB streams. When
    /// `false` (an old client, or one that opts out) the connection is ALWAYS Tier-W and any Tier-S
    /// default is ignored, so a pre-streaming client is never moved onto a tier it cannot follow.
    /// Default `false` (backward-compatible).
    streaming_enabled: bool,
    /// This connection's negotiated DEFAULT consume tier (#543, V2-M1): the tier a SUBSCRIPTION adopts
    /// when it does not explicitly pick one. Fixed at `Connect` time from the client's `default_tier`
    /// request, folded via [`ironbus_proto::message::ConsumeTier::from_u8`], and gated by
    /// `streaming_enabled` — a Tier-S default is only honored when the capability bit was also set, so it
    /// is forced back to [`ConsumeTier::Work`] otherwise. [`ConsumeTier::Work`] by default (an old
    /// client, or no request), so an unmarked SUB stays on the work-queue tier exactly as before. An
    /// explicit per-subscription tier selection (#544) still overrides this default.
    default_tier: ConsumeTier,
    /// Whether this connection negotiated the raw-framed `DeliverBatch` frame (tag 26, #541, M1-I5): set
    /// at `Connect` time when the client advertised
    /// [`ironbus_proto::message::CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH`]. When `true`, the server MAY ship
    /// a contiguous Tier-S run as ONE `DeliverBatch` (the records' on-disk frame bytes, decoded
    /// client-side) instead of N per-record `Deliver` frames. When `false` (an old client, or one that
    /// opts out) the server ALWAYS sends per-record `Deliver` frames — byte-for-byte today's behavior —
    /// and never sends the new tag, so a pre-batch client is never sent a frame it cannot decode. Default
    /// `false` (backward-compatible).
    deliver_batch_enabled: bool,
    /// Whether this connection negotiated the stream-ADDRESSED wire verbs (#588, M2-I10): set at
    /// `Connect` time when the client advertised
    /// [`ironbus_proto::message::CONNECT_FLAG_UNDERSTANDS_STREAMS`]. When `true`, the connection may
    /// declare / publish-to / subscribe-to a NAMED stream by id (`StreamDeclare` / `StreamInfo` /
    /// `PubTo` / `SubTo`, tags 28-31), each routed to the engine's id-routed entry points (#676/#679);
    /// the server confirms it in `Info` ([`ironbus_proto::message::INFO_FLAG_STREAMS`]). When `false`
    /// (an old client, or one that opts out) those verbs are REFUSED with a typed `Err` and the
    /// connection uses ONLY the default-stream verbs (`Pub`/`Sub`/`Flow`/`Fetch`), which target the
    /// default stream `""` — byte-for-byte today's behavior. Default `false` (backward-compatible).
    streams_enabled: bool,
    /// Whether this consumer negotiated COMPRESSED delivery (#1066): set at `Connect` time when the
    /// client advertised [`ironbus_proto::message::CONNECT_FLAG2_COMPRESSED_DELIVERY`]. When `true`, a
    /// stored-COMPRESSED record (a `--compression` broker's `descriptor + codec-stream` payload with the
    /// `COMPRESSED` record flag) is delivered VERBATIM — the codec bytes and the flag pass through, the
    /// broker's zero-CPU passthrough, which a #430+ client decodes. When `false` (an old client, one that
    /// opts out, or the empty `Connect` body) a stored-COMPRESSED record is DECOMPRESSED before delivery
    /// and the `COMPRESSED` bit is cleared, so a pre-#430 consumer that would mis-decode the descriptor
    /// bytes receives the plain produced payload instead — the ONE silent-wrong-data path is closed.
    /// UNCOMPRESSED records are unaffected either way (identity passthrough). Default `false`
    /// (backward-compatible): the safe choice for an unmarked consumer even on a `--compression lz4`
    /// broker.
    compressed_delivery_enabled: bool,
    /// The NAMED stream this connection's consume path is bound to (#588, M2-I10), `""` (the default
    /// stream) until a `SubTo` binds a named one. A `SubTo` sets BOTH this and `subscription` (the
    /// work-group within the stream); a plain `Sub`/`Unsub` resets it to the default stream. The Flow
    /// poll loop and the Ack path route through the engine's id-routed `poll_in_stream` /
    /// `ack_in_stream` when this is non-empty, and through the unchanged default-stream
    /// `poll_now_in_member` / `ack_in` when it is empty — so an OLD client (which never sends `SubTo`)
    /// consumes the default stream byte-for-byte. Held as `Arc<str>` (#487) so handing the name to the
    /// engine job by value across the actor channel is a refcount bump, not an allocation, exactly like
    /// `subscription`.
    stream: GroupName,
    /// Whether this connection has EVER published a Level-2 (server+client-ack) produce (#497): set
    /// when an L2 publish is registered for confirmation, and NEVER cleared. It is the gate that keeps
    /// the per-pass `ProduceConfirm` drain off the actor for a connection that never opted into Level 2
    /// — CRITICALLY a ping-only or pure-consumer connection, which must answer a `Ping` WITHOUT touching
    /// the actor so a stalled produce fsync on another connection cannot head-of-line-block it (#177,
    /// invariant 4). Only a connection that actually produced an L2 publish ever routes the confirm
    /// drain through the actor, and such a connection opted into the L2 protocol (its
    /// `produce_confirmed` already tolerates the wait), so the head-of-line property holds for every
    /// connection that did not. `false` by default, so an L0/L1-only connection is byte-for-byte
    /// unchanged.
    produced_l2: bool,
    /// The transaction-LISTENER group this connection registered (#640 part 2, via `TxnListen`), or
    /// `None` if it never registered one. When `Some`, the connection has opted into back-checking: it
    /// drives the periodic back-check scan and drains any `TxnCheck`s the broker routed to it on its own
    /// pass — exactly the `produced_l2` discipline, so a connection that never registers a listener
    /// never touches the back-check path and is byte-for-byte unchanged (a ping-only/consumer connection
    /// answers a `Ping` without the scan). It is ALSO the group every `TxnPrepare` on this connection
    /// records as the half message's back-check owner, so the broker can route a `TxnCheck` to this
    /// producer's listener even after a reconnect. `None` by default.
    txn_listener_group: Option<Vec<u8>>,
    /// The per-connection, generation-guarded subject-resolve cache (#585, M2-I9): caches a literal
    /// subject's single-home resolution (the bound [`StreamId`]) so a hot publisher to the same subject
    /// routes in O(1) — a hash lookup, no trie walk — after the first publish. It is consulted INSIDE
    /// the actor job (where the engine's wait-free routing snapshot lives) and moved back out, so the
    /// cache state stays per-connection while the resolve runs against the shared, lock-free trie. A
    /// bind change advances the snapshot generation; this cache's generation-guard drops its stale
    /// answer on the next resolve (one O(1) compare — no global flush, the beat over NATS's per-change
    /// Sublist-cache flush). EMPTY until this connection publishes/subscribes BY SUBJECT, so a
    /// connection that never uses subject addressing costs nothing here. Bounded (LRU), so a firehose of
    /// distinct subjects can never grow it without bound.
    subject_cache: ResolveCache<StreamId>,
    /// The connection-scoped AUTHORIZATION authority pinned at `Connect` time (#631, V2-M7): the
    /// resolved identity's scope set, bound to the connection for its entire lifetime. A verb is
    /// authorized against THIS set, never against anything the client asserts in a later frame, so a
    /// client cannot escalate by re-sending a scope. On a broker with NO auth configured (the
    /// zero-config loopback-dev mode), the scope gate is BYPASSED entirely (see `authenticated`), so
    /// the empty default here is never consulted and the dev experience is byte-for-byte unchanged.
    /// On an auth-required broker it is the empty set until a successful `Connect` pins the identity's
    /// scopes; a verb attempted before that (or after a failed auth) is an Authorization Violation.
    scopes: crate::auth::ScopeSet,
    /// Whether THIS connection has completed a successful authenticating `Connect` (#631). Distinct
    /// from `connected` (which means "the Connect handshake ran"): on an auth-required broker a
    /// `connected` connection is only `authenticated` after the credential verified, and a verb is
    /// gated on `authenticated && scopes.has(required)`. On a no-auth broker the gate is bypassed
    /// (the broker has no identities, so there is nothing to authenticate against). Default `false`.
    authenticated: bool,
    /// The broker's connection-scoped auth table (#631), shared immutably across connections via
    /// `Arc` (a clone is a refcount bump, no per-connection deep copy of the identity table). `None`
    /// is the zero-config loopback-dev broker: no identities, the scope gate is bypassed, and the
    /// dev experience is byte-for-byte unchanged. `Some(_)` is an auth-required broker: the `Connect`
    /// handshake must authenticate and every scope-gated verb is checked against `scopes`.
    auth_config: Option<std::sync::Arc<crate::auth::AuthConfig>>,
    /// The verified mTLS peer certificate's resolved SAN identity (#631), if the connection presented
    /// one at the TLS layer. `None` until the TLS handshake (the FLAGGED follow-up) extracts and
    /// verifies a client certificate; consulted ONLY by the mTLS mechanism at `Connect`. In this PR it
    /// is always `None`, so an mTLS-mechanism connect fails closed (no verified cert) until TLS lands —
    /// the safe behavior, never a default-scope grant.
    peer_san: Option<String>,
    /// The shared connection-signal ("connz") metric (#572), if the server wired one in. `None` for a
    /// session that does not report connz (every test, and a `serve` overload built with the legacy
    /// un-scraped metric). When `Some(_)`, the session records the AUTHED-FLIP (a successful `Connect`
    /// handshake) on it; accept/close/refuse are recorded by the accept loop / slot guard, not here. A
    /// cheap `Arc`-clone reference, never per-connection deep state.
    connz: Option<std::sync::Arc<crate::connz::ConnectionMetrics>>,
    /// The pre-auth `DoS` guard (#633) and this connection's source IP, if the server wired one in.
    /// `None` when no `DoS` defense is configured (the byte-identical historical path — no failed-auth
    /// lockout bookkeeping, no `rejected_total{reason="auth_failed"}`). When `Some((guard, ip))`, the
    /// `Connect` handshake reports its auth OUTCOME to the guard: a failure feeds the per-IP lockout
    /// (and bumps the auth-failed counter), a success clears the IP's failed window. The IP is the
    /// only per-connection datum here; it is NEVER a metric label (the guard keeps it internal), so the
    /// metric surface stays low-cardinality.
    preauth: Option<(
        std::sync::Arc<crate::preauth::PreAuthGuard>,
        std::net::IpAddr,
    )>,
    /// The structured security audit-event emitter (#635, V2-M7). The connect-time auth OUTCOME
    /// (success/failure) and every per-verb SCOPE DENIAL are emitted through it, carrying the identity
    /// NAME (never a credential). `None` is the default for a session that does not audit (every test
    /// that does not assert on the stream, and a serve built with no audit sink); when present it is a
    /// cheap `Arc`-clone of the broker's single emitter, shared across connections so the sequence is
    /// one monotonic space. A `None` emitter, or an emitter over the `Null` sink, is the zero-cost path.
    audit: Option<crate::audit::AuditEmitter>,
    /// The resolved identity NAME pinned at a successful `Connect` (#635), used as the audit subject for
    /// a later scope denial. Empty until authenticated; never a credential. Only meaningful on an
    /// auth-required broker (a no-auth broker never authenticates and never denies a scope).
    identity_name: String,
    /// The half-open (accepted-but-not-yet-authenticated) slot (#633, #880): held from accept until the
    /// `Connect` handshake RESOLVES, then dropped here (decrementing the global half-open count) so the
    /// `--max-preauth-connections` cap measures connections still mid-handshake, NOT authenticated
    /// long-lived ones. `None` when no half-open cap is wired, or once the handshake has resolved. A
    /// slowloris that never sends a well-formed `Connect` keeps it until the connection times out.
    half_open_slot: Option<crate::preauth::HalfOpenSlot>,
    /// The event-driven consume LONG-POLL budget in MILLISECONDS (push delivery), seeded once at
    /// connection setup from [`crate::actor::EngineHandle::consume_longpoll_ms`] (a local read, no
    /// round-trip). `0` (the default) is OFF: an idle `Flow`/`Fetch` on an empty group returns
    /// `FlowEnd(0)` immediately, byte-for-byte today's behavior. When non-zero AND the engine exposes a
    /// [`crate::commit_notify::CommitNotify`], a `Flow`/`Fetch` that drew NOTHING blocks up to this
    /// budget on that seam and re-polls ONCE the instant a record commits (or the budget elapses),
    /// turning the client's poll-interval latency floor into a commit-driven wakeup. Purely opt-in — the
    /// wire, the client, and the response framing are unchanged.
    consume_longpoll_ms: u64,
}

impl Session {
    /// A new, not-yet-handshaked session with the default member identity (member 0). The server
    /// uses [`Session::with_member_id`] to give each connection a distinct `key_shared` identity;
    /// `new` is for callers (and tests) that do not exercise `key_shared` routing.
    #[must_use]
    pub fn new() -> Session {
        Session::default()
    }

    /// A new session with an explicit `key_shared` member identity (#64). The server mints a
    /// distinct id per connection so two concurrently-live members never collide in the rendezvous
    /// hash; a plain competing group ignores the id.
    #[must_use]
    pub fn with_member_id(member_id: MemberId) -> Session {
        Session {
            member_id,
            ..Session::default()
        }
    }

    /// A new session bound to an AUTH-REQUIRED broker (#631, V2-M7): the explicit member identity plus
    /// the shared (immutable, `Arc`-clone) auth table and the verified mTLS peer SAN identity (if the
    /// TLS layer presented one — `None` until the FLAGGED TLS handshake lands). On a session built this
    /// way the `Connect` handshake MUST authenticate against the table and every scope-gated verb is
    /// checked against the pinned scope set. A no-auth (loopback-dev) connection uses
    /// [`Session::with_member_id`] instead and is byte-for-byte unchanged.
    #[must_use]
    pub fn with_member_id_and_auth(
        member_id: MemberId,
        auth_config: std::sync::Arc<crate::auth::AuthConfig>,
        peer_san: Option<String>,
    ) -> Session {
        Session {
            member_id,
            auth_config: Some(auth_config),
            peer_san,
            ..Session::default()
        }
    }

    /// Attaches the shared connz metric (#572) to this session so a successful `Connect` handshake
    /// records the AUTHED-FLIP on it. A builder-style setter (rather than a new constructor) so every
    /// existing `Session::new` / `with_member_id` / `with_member_id_and_auth` call site is unchanged
    /// and only the server's live accept path opts in. Takes a cheap `Arc` clone.
    #[must_use]
    pub fn with_connz(mut self, connz: std::sync::Arc<crate::connz::ConnectionMetrics>) -> Session {
        self.connz = Some(connz);
        self
    }

    /// Seeds the event-driven consume LONG-POLL budget in MILLISECONDS (push delivery) from the engine
    /// config (via [`crate::actor::EngineHandle::consume_longpoll_ms`]). A builder-style setter (like
    /// [`with_connz`](Session::with_connz)) so every existing call site is unchanged and only the
    /// server's live accept path opts in. `0` (the default when never called) keeps the byte-identical
    /// empty-and-return consume path.
    #[must_use]
    pub fn with_consume_longpoll_ms(mut self, consume_longpoll_ms: u64) -> Session {
        self.consume_longpoll_ms = consume_longpoll_ms;
        self
    }

    /// Attaches the pre-auth `DoS` guard (#633) and this connection's source IP so the `Connect`
    /// handshake reports its auth outcome to the guard's per-IP failed-auth lockout. A builder-style
    /// setter (like [`with_connz`](Session::with_connz)) so every existing call site is unchanged and
    /// only the server's live accept path opts in. Takes a cheap `Arc` clone. When never called the
    /// handshake runs the byte-identical historical path (no lockout bookkeeping).
    #[must_use]
    pub fn with_preauth(
        mut self,
        guard: std::sync::Arc<crate::preauth::PreAuthGuard>,
        peer_ip: std::net::IpAddr,
    ) -> Session {
        self.preauth = Some((guard, peer_ip));
        self
    }

    /// Hands the connection's half-open (#633) RAII slot to the session, so it is dropped when the
    /// `Connect` handshake RESOLVES (a well-formed `Connect`, success or failure) rather than at
    /// connection teardown — making the `--max-preauth-connections` cap measure connections still
    /// mid-handshake, NOT authenticated long-lived ones (#880). A builder-style setter (like
    /// [`with_preauth`](Session::with_preauth)) so only the server's live accept path opts in; an inert
    /// slot (no half-open cap configured) is a harmless no-op on drop.
    #[must_use]
    pub fn with_half_open_slot(mut self, slot: crate::preauth::HalfOpenSlot) -> Session {
        self.half_open_slot = Some(slot);
        self
    }

    /// Attaches the shared security audit-event emitter (#635, V2-M7) so the `Connect` handshake emits
    /// the auth OUTCOME (success/failure) and every scope-gated verb emits a SCOPE DENIAL through it,
    /// carrying the identity NAME (never a credential). A builder-style setter (like
    /// [`with_connz`](Session::with_connz) / [`with_preauth`](Session::with_preauth)) so every existing
    /// call site is unchanged and only the server's live accept path opts in. Takes a cheap `Clone` of
    /// the broker's single emitter (a shared sequence + sink). When never called the handshake/gate run
    /// the byte-for-byte historical path (no audit emission).
    #[must_use]
    pub fn with_audit(mut self, audit: crate::audit::AuditEmitter) -> Session {
        self.audit = Some(audit);
        self
    }

    /// The work-group this connection is subscribed to (`""` is the default group). Used to
    /// route the connection's durable cursor checkpoint to the right group (#60).
    #[must_use]
    pub fn subscription(&self) -> &str {
        &self.subscription
    }

    /// Whether this connection ever published a Level-2 (server+client-ack) produce (#497). The
    /// connection-cleanup path consults it so only an L2 producer routes the confirm-registry cleanup
    /// through the actor; an L0/L1-only or pure-consumer connection skips it entirely.
    #[must_use]
    pub fn produced_l2(&self) -> bool {
        self.produced_l2
    }

    /// Whether this connection registered a transaction-state LISTENER (#640 part 2, via `TxnListen`).
    /// The per-pass back-check scan + `TxnCheck` drain are GATED on this, so a connection that never
    /// registers a listener never touches the back-check path (byte-for-byte unchanged). The
    /// connection-cleanup path also consults it so only a back-checking connection routes the listener
    /// cleanup through the actor.
    #[must_use]
    pub fn registered_txn_listener(&self) -> bool {
        self.txn_listener_group.is_some()
    }

    /// Processes the complete frames at the front of `input`, dispatching each to the engine (via
    /// the append actor `engine`) and appending response frames to `out`. Returns a [`Progress`]:
    /// the number of input bytes consumed, plus the `needed` hint, the minimum TOTAL input length
    /// before the next call can make progress on the partial trailing frame (`0` when nothing
    /// partial remains). A partial trailing frame is not consumed and should be retried once more
    /// bytes arrive.
    ///
    /// # The `needed` hint (#176 O(n^2) re-decode fix)
    ///
    /// Without the hint a connection re-runs `process` over its whole input buffer on every read,
    /// so a client trickling a near-cap frame byte-by-byte forces a full re-decode per byte: O(n^2)
    /// in the frame size. The `needed` value is the frame parser's [`FrameDecode::Incomplete`]
    /// hint, the total length the trailing frame needs; the caller skips re-calling `process` until
    /// the buffer has at least that many bytes, so each frame is decoded at most a constant number
    /// of times regardless of how it is trickled.
    ///
    /// # The pipelined produce window (#450)
    ///
    /// Within one pass, `Pub` frames are SUBMITTED to the append actor without awaiting their
    /// outcomes (the pending ack is PARKED), so a client that pipelines N PUBs into one buffer puts
    /// all N produces in front of the actor before the first ack is awaited; the actor drains them
    /// as ONE batch and covers it with one group-commit fsync instead of N. The parked acks are
    /// released in FIFO submission order BEFORE any non-produce frame's reply, at the
    /// [`MAX_PARKED_PRODUCES`] safety cap, and at the end of the pass, so the wire reply order is
    /// exactly the frame order (the per-connection ordering contract) and every non-fire-and-forget
    /// `Pub` still gets exactly one reply frame. I2 is untouched: the actor releases no produce
    /// reply before the covering `commit_batch`, so a parked ack can never precede its fsync.
    ///
    /// # Errors
    /// Returns [`SessionError::BadFrame`] if a frame envelope is malformed (the caller must then
    /// close the connection, a length-prefixed stream cannot resync), [`SessionError::EngineFatal`]
    /// on an unrecoverable engine error, or [`SessionError::ActorGone`] if the append actor exited.
    pub fn process<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Progress, SessionError> {
        let mut consumed = 0;
        let mut committed_progress = false;
        // This connection's stable id (#64), captured up front (it is `Copy`) so the parked-window
        // drain can register a Level-2 produce's confirm (#497) against this producer without
        // re-borrowing `self` while `handle_pub`/`dispatch` hold it.
        let member_id = self.member_id;
        // Resume the PERSISTENT pipelined window (#450, #1045): the produces submitted to the actor but
        // not yet acked, carried over from prior passes. Taken into a LOCAL so `handle_pub`/`dispatch`
        // can borrow `&mut self` without the borrow checker also seeing the field borrowed; it is stored
        // back into `self.parked` before this method returns (both the normal-exit and error-exit
        // paths), so a produce parked in one pass survives into the next. That persistence is the seam
        // the connection loop overlaps the NEXT batch through — the pass no longer block-awaits the
        // window at its end, so batch N's fdatasync no longer starves batch N+1 on one connection.
        let mut parked = std::mem::take(&mut self.parked);
        let result = loop {
            match decode_frame(&input[consumed..]).map_err(SessionError::BadFrame) {
                Err(e) => break Err(e),
                // The trailing frame is partial: report how many bytes it needs so the caller does
                // not re-decode until at least that many have arrived (the #176 fix). `needed` is
                // relative to the UNCONSUMED remainder (`&input[consumed..]`): the caller drains the
                // `consumed` prefix, after which the partial frame sits at the front of its buffer
                // and needs exactly `needed` bytes there, so the threshold the caller compares its
                // post-drain buffer length against is this `needed` directly.
                Ok(FrameDecode::Incomplete { needed }) => {
                    break Ok(Progress {
                        consumed,
                        needed,
                        committed_progress,
                    });
                }
                Ok(FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed: n,
                }) => {
                    // A fatal engine error ends the session AFTER its Err response is
                    // queued (the caller flushes `out`, then closes).
                    if matches!(FrameType::from_u8(type_tag), Some(FrameType::Pub)) {
                        // The produce path parks its pending ack (the pipelined window, #450)
                        // instead of awaiting it inline, so the actor can group-commit the whole
                        // window under one fsync. A produce never advances a COMMITTED cursor, so
                        // `committed_progress` is untouched, exactly as before.
                        if let Err(e) = self.handle_pub(engine, body, &mut parked, out) {
                            break Err(e);
                        }
                        // The Level-0 safety cap (#11 fast path): a buffer packed with tiny QoS-0 PUB
                        // frames cannot accumulate the no-ack batch without bound. At the cap, flush the
                        // batch to the actor in one send and start a fresh one, so memory stays bounded.
                        if self.level0_pending.len() >= MAX_PARKED_PRODUCES {
                            if let Err(e) = self.flush_level0(engine) {
                                break Err(e);
                            }
                        }
                        // Release any acks that are already ready (front prefix, NON-BLOCKING, #1045),
                        // so a saturating producer's window stays small and its acks flow WITHIN the
                        // pass instead of piling up. This does NOT block on an un-fsync'd produce — that
                        // is the whole point: the pass keeps parsing/submitting the next frames while the
                        // actor group-commits the batch already in flight.
                        if let Err(e) = release_ready_prefix(engine, member_id, &mut parked, out) {
                            break Err(e);
                        }
                        // The MAX_PARKED memory backstop (#450, #1045): if acks lag arrivals and the
                        // window is STILL at the cap after releasing the ready prefix, block-drain the
                        // front until it is bounded again (produce backpressure). The rare pathological
                        // path — the actor is a full window of fsyncs behind — not the steady state.
                        if parked.len() >= MAX_PARKED_PRODUCES {
                            if let Err(e) = enforce_parked_cap(engine, member_id, &mut parked, out)
                            {
                                break Err(e);
                            }
                        }
                    } else {
                        // Any non-produce frame first releases the parked acks, so the reply order
                        // on the wire is exactly the frame order (FIFO per connection). The
                        // actor-side ordering is also preserved: the actor flushes its pending
                        // produce batch before running any job, so an ack/flow/sub still observes
                        // every prior produce durable. A Level-0 batch accumulated BEFORE this
                        // non-produce frame must reach the actor FIRST too (single total order), so
                        // flush it before the ack drain + dispatch.
                        if let Err(e) = self.flush_level0(engine) {
                            break Err(e);
                        }
                        if let Err(e) = drain_parked(engine, member_id, &mut parked, out) {
                            break Err(e);
                        }
                        match self.dispatch(engine, type_tag, body, out) {
                            Ok(c) => committed_progress |= c,
                            Err(e) => break Err(e),
                        }
                    }
                    consumed += n;
                }
            }
        };
        // End of the pass. Flush any trailing Level-0 batch to the actor (#11 fast path) so the
        // connection's last QoS-0 produces are submitted before the pass returns.
        //
        // Then handle the still-parked at-least-once window (#1045). This is the crux of closing the
        // single-connection ceiling: on a NORMAL exit the pass releases only the READY front prefix
        // (non-blocking) and PERSISTS the rest in `self.parked` for the next pass / the connection
        // loop's drain-one — it does NOT block-await the window, so one connection keeps reading and
        // submitting the next batch while the actor group-commits the current one. On a CLOSING exit (a
        // malformed frame / fatal engine error / auth violation broke the loop) the connection is going
        // away, so block-drain the WHOLE remaining window FIFO — those produces already reached the
        // actor and their acks belong on the wire before the close (the invariant), and the first error
        // still wins (a drain error after a loop error is the same fatal engine event, subsumed).
        let level0_flushed = self.flush_level0(engine);
        let drained = if result.is_err() {
            drain_parked(engine, member_id, &mut parked, out)
        } else {
            release_ready_prefix(engine, member_id, &mut parked, out)
        };
        // Drain any CLUSTER produce-acks the data plane RELEASED for this connection onto the wire
        // (#719): a clustered `C2-fsync` produce's wire `PubAck` was WITHHELD when it parked (in
        // `drain_parked` above), and the data plane flushes it onto this connection's outbox once the
        // ISR quorum has fsync'd the offset — on a peer-I/O thread, which may not write this socket. So
        // the OWNING connection drains and writes them HERE on its own pass (the cross-thread hand-off,
        // exactly like the L2 confirm drain below). BYTE-IDENTICAL single-node guarantee: the default
        // `drain_client_acks` (no cluster) returns empty with ZERO work — no lock, no actor round-trip —
        // so a single-node / no-cluster / pre-bootstrap connection's pass is unchanged. Off the actor
        // (an outbox lock only), so it never head-of-line-blocks a ping (#177). FIFO/offset order is the
        // gate's release order, written after this window's own replies and before the L2 confirms.
        for frame in engine.drain_client_acks(member_id) {
            out.extend_from_slice(&frame);
        }
        // Drain any READY Level-2 `ProduceConfirm`s for THIS producer connection onto the wire (#497),
        // so a producer awaiting a confirm receives it on its next pass. A confirm becomes ready when a
        // consumer in the designated group acks the record (or it dead-letters / force-reaps / times
        // out). The client's `produce_confirmed` drives these passes (it interleaves Pings while it
        // waits), so a confirm is delivered without any out-of-band server push (the thread-per-
        // connection server only writes a connection's socket from that connection's own pass). A no-op
        // for a connection with no outstanding L2 confirms, so L0/L1 producers and consumers are
        // byte-for-byte unchanged. Drained even on an error exit: the confirms belong on the wire before
        // the connection closes, exactly like the parked acks above.
        //
        // GATED on `produced_l2`: a connection that has NEVER published a Level-2 produce never routes
        // the drain through the actor, so a ping-only or pure-consumer connection answers a `Ping`
        // WITHOUT touching the actor and a stalled produce fsync elsewhere cannot head-of-line-block it
        // (#177, invariant 4). A connection that DID produce L2 opted into the protocol and its
        // `produce_confirmed` tolerates the wait, so the head-of-line property holds for everyone else.
        if self.produced_l2 {
            drain_produce_confirms(engine, member_id, out);
        }
        // Drive the back-check scan + drain any routed `TxnCheck`s for THIS producer connection (#640
        // part 2), so a producer that registered a transaction listener (and is interleaving Pings via
        // its `transact`/listener loop) (a) advances the periodic in-doubt-txn scan and (b) receives any
        // `TxnCheck` the broker routed to its group on its own pass — the only place the
        // thread-per-connection server may write this socket, exactly like the L2 confirm drain above.
        // GATED on `registered_txn_listener`: a connection that never registered a listener never runs
        // the scan or the drain, so a ping-only/consumer/non-transactional connection is byte-for-byte
        // unchanged (no actor round-trip for the scan). The scan itself is a no-op when there are no
        // in-doubt txns, so even a back-checking broker with nothing prepared pays ~nothing.
        if self.registered_txn_listener() {
            drive_back_check(engine, member_id, out);
        }
        // Persist the (possibly non-empty) pipelined window back onto the session (#1045), so produces
        // parked but not yet acked survive into the next pass. Empty after a closing exit (the block
        // drain above emptied it) or when every parked ack was already released; otherwise it carries
        // the not-yet-committed tail the connection loop will drain-one or the next pass will release.
        self.parked = parked;
        match result {
            Err(e) => Err(e),
            Ok(progress) => level0_flushed.and(drained).map(|()| progress),
        }
    }

    /// Whether this connection has at-least-once produces PARKED in its pipelined window (#1045) whose
    /// acks have not yet been released. The connection loop consults it to choose its read mode: with a
    /// non-empty window it reads NON-BLOCKING (so a would-block means "no new bytes right now", the cue
    /// to release an ack a bounded-window client is waiting on) and, when empty, reads BLOCKING (an idle
    /// connection sleeps on the socket rather than spinning).
    #[must_use]
    pub(crate) fn has_parked(&self) -> bool {
        !self.parked.is_empty()
    }

    /// BLOCK-awaits the FRONT parked produce's ack (its covering group-commit fsync), writes its reply,
    /// pops it (FIFO #917), then releases any further now-ready prefix (non-blocking) — so a whole
    /// group-committed batch's acks flush in one call. The connection loop calls this when a
    /// non-blocking read WOULD BLOCK while the window is non-empty: the socket has no new bytes, so a
    /// client that pipelined W produces and is waiting on their acks is unblocked by releasing the front
    /// ack (it can then send more). This is what keeps a bounded-window producer from deadlocking under
    /// the non-blocking pass. Preserves #719/#497: the release goes through the SAME gated write +
    /// confirm registration as every other drain path ([`release_parked_outcome`]).
    ///
    /// # Errors
    /// [`SessionError::EngineFatal`]/[`SessionError::ActorGone`] if the front produce's outcome is fatal
    /// or the actor exited — the connection then closes cleanly.
    pub(crate) fn drain_one_parked_blocking<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        let member_id = self.member_id;
        drain_front_one_blocking(engine, member_id, &mut self.parked, out)?;
        // The front's siblings in the same group-commit batch are almost certainly ready now (they
        // share the fsync we just waited on): release them without blocking, so the whole batch's acks
        // go out in one write.
        release_ready_prefix(engine, member_id, &mut self.parked, out)
    }

    /// BLOCK-drains EVERY remaining parked ack onto `out` in FIFO order (#1045): the connection is
    /// closing on a clean EOF, so the whole window's acks belong on the wire before the socket goes
    /// away. A no-op on an empty window.
    ///
    /// # Errors
    /// [`SessionError::EngineFatal`]/[`SessionError::ActorGone`] if a remaining produce's outcome is
    /// fatal or the actor exited.
    pub(crate) fn flush_all_parked_blocking<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        let member_id = self.member_id;
        drain_parked(engine, member_id, &mut self.parked, out)
    }

    /// The number of produces currently parked in the pipelined window (#1045). Test-only: the overlap
    /// and cap tests assert the persistent window accumulates across passes and stays bounded.
    #[cfg(test)]
    pub(crate) fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// Dispatches one decoded frame, returning whether it may have advanced a work-group's committed
    /// cursor (so the caller knows whether to run the interval checkpoint). A `Ping`/`Connect`/`Pub`
    /// returns `false`: a ping changes no cursor (and must not reach the actor's checkpoint path, so a
    /// stalled produce fsync cannot block it, #177); a produce advances the durable head but not a
    /// COMMITTED cursor. An `Ack`/`Flow`/`Unsub` returns `true` (an ack commits, a flow can commit
    /// past a dead-letter, an unsub may evict a caught-up group).
    #[allow(clippy::too_many_lines)] // one match arm per wire verb; splitting it would obscure the dispatch
    fn dispatch<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        type_tag: u8,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<bool, SessionError> {
        match FrameType::from_u8(type_tag) {
            // The handshake: parse any negotiated credit request, clamp it to the server cap, and
            // reply the advertised Info (#292). A repeated Connect re-negotiates idempotently. It is
            // infallible (the caps are read LOCALLY off the handle, no actor round-trip, #177), so it
            // returns `false` directly (no committed-cursor progress).
            Some(FrameType::Connect) => {
                // Auth (#631) rides the Connect handshake: a failed authentication writes the uniform
                // Authorization Violation and returns `Err(AuthViolation)` so the connection closes,
                // exactly as the auth contract requires. A successful (or no-auth) connect returns
                // `false` (no committed-cursor progress), byte-for-byte the historical path.
                self.handle_connect(engine, body, out)?;
                Ok(false)
            }
            Some(FrameType::Ping) => {
                reply(out, FrameType::Pong, &[]);
                Ok(false)
            }
            // The un-pipelined produce path for a DIRECT dispatch call (the `process` loop
            // intercepts Pub frames before dispatch so it can park them across the pass, #450): a
            // one-entry window, submitted and immediately drained, byte-identical replies.
            Some(FrameType::Pub) => {
                let member_id = self.member_id;
                let mut parked = VecDeque::new();
                self.handle_pub(engine, body, &mut parked, out)?;
                // This one-off Pub path submits and immediately drains, so flush any Level-0 it batched
                // right away (no cross-frame accumulation here) — keeping the pass-scoped batch empty for
                // the main loop and preserving the single total order.
                self.flush_level0(engine)?;
                drain_parked(engine, member_id, &mut parked, out).map(|()| false)
            }
            // The consume/ack vocabulary all requires the `subscribe` scope (#631): a connection
            // without `subscribe` is refused with the uniform Authorization Violation, BEFORE the verb
            // runs, with no implication from any other scope it might hold (admin does NOT grant it).
            Some(FrameType::Ack) => {
                self.require_scope(crate::auth::Scope::Subscribe, "Ack", out)?;
                self.handle_ack(engine, body, out).map(|()| true)
            }
            // A cumulative ack commits the broadcast cursor (when accepted), so it returns `true` to
            // run the interval checkpoint, exactly like a per-message Ack (#288).
            Some(FrameType::CumulativeAck) => {
                self.require_scope(crate::auth::Scope::Subscribe, "CumulativeAck", out)?;
                self.handle_cumulative_ack(engine, body, out).map(|()| true)
            }
            Some(FrameType::Flow) => {
                self.require_scope(crate::auth::Scope::Subscribe, "Flow", out)?;
                self.handle_flow(engine, body, out).map(|()| true)
            }
            // The batch-pull FETCH (#489): the amortized twin of Flow. It runs the SAME per-record poll
            // loop bounded by max_records/max_bytes/expires/no_wait, so it returns `true` to run the
            // interval checkpoint exactly like Flow (it commits cursor progress the same way).
            Some(FrameType::Fetch) => {
                self.require_scope(crate::auth::Scope::Subscribe, "Fetch", out)?;
                self.handle_fetch(engine, body, out).map(|()| true)
            }
            // The Tier-S STREAMING fetch (#544): a consumer-managed-offset contiguous read. It grants
            // NO lease and writes NO cursor, so it never commits progress and there is nothing for the
            // interval checkpoint to flush — it returns `false`. Durability is the separate periodic
            // StreamCommit below.
            Some(FrameType::StreamFetch) => {
                self.require_scope(crate::auth::Scope::Subscribe, "StreamFetch", out)?;
                self.handle_stream_fetch(engine, body, out).map(|()| false)
            }
            // The Tier-S periodic CUMULATIVE COMMIT (#544): advances the streaming group's committed
            // cursor (when accepted), so it returns `true` to run the interval checkpoint, exactly like
            // the broadcast CumulativeAck.
            Some(FrameType::StreamCommit) => {
                self.require_scope(crate::auth::Scope::Subscribe, "StreamCommit", out)?;
                self.handle_stream_commit(engine, body, out).map(|()| true)
            }
            Some(FrameType::Sub) => {
                self.require_scope(crate::auth::Scope::Subscribe, "Sub", out)?;
                self.handle_sub(engine, body, out).map(|()| false)
            }
            // The stream-addressed verbs (#588, M2-I10): each is GATED on the negotiated
            // `streams_enabled` capability (a client that did not advertise `understands_streams` gets
            // a typed `Err`, never the new behavior), then routes to the engine's id-routed entry
            // points (#676/#679). A StreamDeclare/StreamInfo changes no committed cursor (`false`); a
            // SubTo only binds the subscription (`false`, like Sub); a PubTo never advances a COMMITTED
            // cursor (`false`, like Pub).
            // Stream/subject MANAGEMENT verbs that create a stream or mutate the routing trie
            // (StreamDeclare, BindSubject) require the `admin` scope (#631: "anything that mutates
            // retention, identities, or consumer state"). StreamInfo is a read of a stream's existence
            // and durable head — stored operational state — so it requires `subscribe` (a consumer
            // read), not anonymous. None is reachable from `publish` alone.
            Some(FrameType::StreamDeclare) => {
                self.require_scope(crate::auth::Scope::Admin, "StreamDeclare", out)?;
                self.handle_stream_declare(engine, body, out)
                    .map(|()| false)
            }
            Some(FrameType::StreamInfo) => {
                self.require_scope(crate::auth::Scope::Subscribe, "StreamInfo", out)?;
                self.handle_stream_info(engine, body, out).map(|()| false)
            }
            // Stream-addressed produce/consume require the same scopes as their default-stream twins:
            // PubTo needs `publish`, SubTo needs `subscribe`.
            Some(FrameType::PubTo) => {
                self.require_scope(crate::auth::Scope::Publish, "PubTo", out)?;
                self.handle_pub_to(engine, body, out).map(|()| false)
            }
            Some(FrameType::SubTo) => {
                self.require_scope(crate::auth::Scope::Subscribe, "SubTo", out)?;
                self.handle_sub_to(engine, body, out).map(|()| false)
            }
            // The subject-addressed verbs (#585, M2-I9): also GATED on the negotiated `streams_enabled`
            // capability (subject routing is the subjects half of the same streams story). A BindSubject
            // registers a binding (changes no committed cursor, `false`); a SubSubject only binds the
            // subscription (`false`, like Sub/SubTo); a PubSubject never advances a COMMITTED cursor
            // (`false`, like Pub/PubTo). BindSubject mutates the routing trie -> `admin`; PubSubject
            // produces -> `publish`; SubSubject consumes -> `subscribe`.
            Some(FrameType::BindSubject) => {
                self.require_scope(crate::auth::Scope::Admin, "BindSubject", out)?;
                self.handle_bind_subject(engine, body, out).map(|()| false)
            }
            Some(FrameType::PubSubject) => {
                self.require_scope(crate::auth::Scope::Publish, "PubSubject", out)?;
                self.handle_pub_subject(engine, body, out).map(|()| false)
            }
            Some(FrameType::SubSubject) => {
                self.require_scope(crate::auth::Scope::Subscribe, "SubSubject", out)?;
                self.handle_sub_subject(engine, body, out).map(|()| false)
            }
            // The TRANSACTIONAL half-message verbs (#640, V2-M8): a producer-side 2PC. Prepare/commit/
            // rollback all PRODUCE (or resolve a produce), so they require the `publish` scope, exactly
            // like Pub/PubTo. None advances a COMMITTED CONSUMER cursor (a commit appends to the real
            // stream, which is a produce, not a consumer-cursor commit), so each returns `false` (no
            // interval checkpoint). They route through the single-writer engine via `engine.with`.
            Some(FrameType::TxnPrepare) => {
                self.require_scope(crate::auth::Scope::Publish, "TxnPrepare", out)?;
                self.handle_txn_prepare(engine, body, out).map(|()| false)
            }
            Some(FrameType::TxnCommit) => {
                self.require_scope(crate::auth::Scope::Publish, "TxnCommit", out)?;
                self.handle_txn_commit(engine, body, out).map(|()| false)
            }
            Some(FrameType::TxnRollback) => {
                self.require_scope(crate::auth::Scope::Publish, "TxnRollback", out)?;
                self.handle_txn_rollback(engine, body, out).map(|()| false)
            }
            // The BACK-CHECK verbs (#640 part 2): TxnListen registers this connection as the listener
            // for a group (so the broker can route a TxnCheck to it), and TxnCheckResult answers a
            // broker back-check (resolving an in-doubt half message through the part-1 path). Both are
            // producer-side, so they require the `publish` scope. Neither advances a committed consumer
            // cursor, so each returns `false`.
            Some(FrameType::TxnListen) => {
                self.require_scope(crate::auth::Scope::Publish, "TxnListen", out)?;
                self.handle_txn_listen(engine, body, out).map(|()| false)
            }
            Some(FrameType::TxnCheckResult) => {
                self.require_scope(crate::auth::Scope::Publish, "TxnCheckResult", out)?;
                self.handle_txn_check_result(engine, body, out)
                    .map(|()| false)
            }
            Some(FrameType::Unsub) => {
                self.require_scope(crate::auth::Scope::Subscribe, "Unsub", out)?;
                self.handle_unsub(engine, out).map(|()| true)
            }
            // The standalone Nack frame type (a client sends a nack as an Ack frame with the
            // Nack op, handled above), or a response-only verb (Info/Pong/Ok/Err/Deliver) a
            // client should not send.
            Some(_) => {
                reply_err(out, "verb not supported on this connection");
                Ok(false)
            }
            // An unknown tag is forward-compatible at the envelope level but has no handler.
            None => {
                reply_err(out, "unknown frame type");
                Ok(false)
            }
        }
    }

    /// Handles a `Connect` (#292): decodes the (possibly empty) handshake body, NEGOTIATES the
    /// per-consumer credit as `min(client request, server cap)` (or the server default when the client
    /// requested nothing), fixes it for this connection, and replies an `Info` advertising the
    /// negotiated value plus the server cap.
    ///
    /// Backward-compat both directions:
    /// - An OLD client sends an EMPTY `Connect` body, which decodes to an all-absent request, so the
    ///   negotiated credit is the server default (exactly the pre-#292 behavior).
    /// - The reply is always a versioned `Info` body; an OLD client ignores the body and is unaffected,
    ///   and an OLD server (no #292) replies an empty `Info`, which a new client tolerates by keeping
    ///   its local credit (handled client-side).
    ///
    /// A malformed (non-empty but unparseable) `Connect` body is a typed reject (`Err` reply), never a
    /// panic, and the connection stays open so the client can re-handshake.
    fn handle_connect<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        let req = match decode_connect(body) {
            Ok(req) => req,
            // A non-empty but malformed Connect body: surface a typed error and keep the connection
            // open. The credit is not fixed, so a subsequent valid Connect/Flow still negotiates. The
            // handshake is NOT resolved, so the half-open slot is intentionally KEPT — the client is
            // still mid-handshake and a slowloris must not be able to free its slot with garbage.
            Err(e) => {
                reply_err(out, &e.to_string());
                return Ok(());
            }
        };
        // AUTHENTICATE FIRST (#631, V2-M7), before any negotiation or `connected` flip. On an
        // auth-required broker (an identity table is configured) the `Connect` MUST carry a valid
        // credential; the resolved identity's scope set is PINNED to the connection for its lifetime. On
        // a no-auth broker (`auth_config` is `None`, the zero-config loopback-dev path) this is a no-op
        // and the handshake is byte-for-byte unchanged. Every auth failure replies the ONE uniform
        // Authorization Violation and closes — no oracle, no anonymous fallback on a configured-auth
        // broker.
        if let Some(auth) = self.auth_config.clone() {
            // Resolve the presented credential to a pinned scope set, or fall through to the single
            // uniform Authorization Violation. EVERY failure path — no credential (no anonymous
            // fallback), a malformed/unknown-mechanism auth section, or a bad/unmatched credential —
            // collapses to the SAME outcome, so there is no oracle, and the close happens after the
            // one uniform Err. A well-formed, verified credential pins the identity's scopes.
            // Parse the credential ONCE (the same single parse as the historical path), then derive
            // BOTH the audit mechanism handle and the auth resolution from it — so the audit wiring adds
            // no second parse and the no-audit path is byte-for-byte unchanged. The mechanism for the
            // audit event (#635) is the SAFE handle (`bearer` / `password` / `mtls` / `unknown`), never
            // the credential; `unknown` covers a missing/malformed section.
            let parsed_cred = parse_connect_auth(body);
            let mechanism = match &parsed_cred {
                Ok(Some(cred)) => audit_mechanism(cred.mechanism),
                Ok(None) | Err(_) => crate::audit::Mechanism::Unknown,
            };
            let resolved = match &parsed_cred {
                Ok(Some(cred)) => auth.authenticate(cred, self.peer_san.as_deref()).ok(),
                // No credential, a malformed section, or an unknown mechanism: all "no resolution",
                // which becomes the uniform violation below.
                Ok(None) | Err(_) => None,
            };
            let Some((_identity, outcome)) = resolved else {
                // Report the FAILED auth to the pre-auth `DoS` guard (#633): it feeds the per-IP
                // failed-auth lockout and bumps `rejected_total{reason="auth_failed"}`. A no-op when no
                // `DoS` defense is wired (the byte-identical path). No credential is passed — only the IP
                // the guard already holds — so nothing secret crosses here.
                if let Some((guard, ip)) = self.preauth.as_ref() {
                    guard.on_auth_failure(*ip);
                }
                // Emit the FAILED authn outcome to the audit stream (#635): the mechanism and the
                // `<unknown>` subject (a failed lookup never echoes attacker-supplied bytes), never the
                // presented credential. The wire still sees only the uniform Authorization Violation.
                self.emit_audit(&crate::audit::AuditEvent::AuthOutcome {
                    identity: crate::audit::UNKNOWN_IDENTITY.to_string(),
                    mechanism,
                    outcome: crate::audit::Outcome::Failure,
                });
                // The handshake has RESOLVED (auth FAILED, AFTER the memory-hard Argon2id verify above):
                // release the half-open slot (#880). Dropping it only AFTER the verify keeps the #633
                // half-open cap as the documented GLOBAL backstop on concurrent unauthenticated verifies
                // (preauth.rs §2) — a distributed flood must not be able to run more concurrent verifies
                // than the cap by freeing the slot before the verify.
                self.half_open_slot = None;
                reply_auth_violation(out);
                return Err(SessionError::AuthViolation);
            };
            // Pin the identity's scopes (and the identity NAME, for a later scope-denial audit subject)
            // for the connection lifetime, then flip the auth flag. The NAME is a safe handle; no
            // credential is retained. This is an IRREFUTABLE `let`: `authenticate` returns `Err` on every
            // failure (handled by the `else` above), so an `Ok` outcome is by construction `Authenticated`.
            // Binding here — rather than an `if let` with the flag flipped outside — couples the flag to
            // the scope-pinning: `self.authenticated` can never be set without a resolved identity, and if
            // a non-success variant is ever added to `AuthOutcome` this destructure fails to compile rather
            // than silently leaving an authenticated-but-no-scope connection (#889).
            let crate::auth::AuthOutcome::Authenticated { identity, scopes } = &outcome;
            self.scopes = *scopes;
            self.identity_name.clone_from(identity);
            self.authenticated = true;
            // Emit the SUCCESSFUL authn outcome to the audit stream (#635): the resolved identity NAME,
            // the mechanism, success — never the credential. Emitted AFTER the scopes are pinned, so a
            // success event always reflects a fully-authenticated connection.
            self.emit_audit(&crate::audit::AuditEvent::AuthOutcome {
                identity: self.identity_name.clone(),
                mechanism,
                outcome: crate::audit::Outcome::Success,
            });
            // Report the SUCCESSFUL auth to the pre-auth `DoS` guard (#633): it clears this IP's
            // failed-auth window so an occasional fat-fingered password before a correct one never
            // accumulates toward a lockout. A no-op when no `DoS` defense is wired.
            if let Some((guard, ip)) = self.preauth.as_ref() {
                guard.on_auth_success(*ip);
            }
            // Record the AUTHED-FLIP on the shared connz metric (#572): a `Connect` handshake that
            // successfully resolved a credential. Recorded ONLY on the auth-required path (a no-auth
            // broker authenticates nothing, so its authenticated total is honestly 0), off the engine
            // lock, a single relaxed atomic. `None` (a session with no wired connz) is a no-op.
            if let Some(connz) = self.connz.as_ref() {
                connz.record_authenticated();
            }
        }
        // The handshake has RESOLVED (authenticated, or a no-auth broker with nothing to verify): release
        // the half-open slot (#880) so an authenticated long-lived connection no longer pins it. Done
        // AFTER the auth block (the memory-hard Argon2id verify), so the #633 half-open cap stays the
        // documented GLOBAL backstop on concurrent unauthenticated verifies; a slowloris that never
        // reaches here keeps its slot until the connection times out. An inert / `None` slot is a no-op,
        // and a repeated Connect re-runs this idempotently (the slot is already released).
        self.half_open_slot = None;
        self.connected = true;
        // Record the client's request (re-recorded on a repeated Connect, which re-negotiates
        // idempotently). It is also used by the lazy `credit_ceiling` fallback for a session that never
        // ran a Connect through this handler (some tests inject `connected` directly).
        self.requested_credit = req.requested_credit;
        self.requested_credit_bytes = req.requested_credit_bytes;
        // Negotiate the consumer-visible gap marker (#346): the server always SUPPORTS it, so the
        // capability is active exactly when this consumer advertised it understands the frame. A
        // gap-marker consumer receives `GapMarker` (tag 21) for a skipped span; one that did not
        // advertise keeps the legacy `Truncated` (tag 18), so an old client is never sent the new tag.
        self.gap_marker_enabled = req.wants_gap_marker;
        // Negotiate the streaming consume tier (#543, V2-M1): the server always SUPPORTS Tier-S, so the
        // capability is active exactly when this consumer advertised it understands streaming. The
        // negotiated connection DEFAULT tier is the client's requested `default_tier` (folded from the
        // raw byte), but ONLY when the capability is active — a Tier-S default from a client that did
        // NOT advertise the capability is ignored and the connection stays Tier-W, so a pre-streaming
        // client can never be moved onto a tier it cannot follow. With the capability clear the default
        // is forced to Tier-W (today's behavior, byte-for-byte).
        self.streaming_enabled = req.understands_streaming;
        self.default_tier = if self.streaming_enabled {
            req.default_tier
                .map(ConsumeTier::from_u8)
                .unwrap_or_default()
        } else {
            ConsumeTier::Work
        };
        // Negotiate the raw-framed DeliverBatch frame (#541, M1-I5): the server always SUPPORTS it, so
        // the capability is active exactly when this consumer advertised it understands the frame. A
        // batch-capable consumer may receive a contiguous Tier-S run as ONE `DeliverBatch` (tag 26); one
        // that did not advertise keeps receiving per-record `Deliver` frames and is never sent the new
        // tag, so an old client that cannot decode the on-disk record layout is never broken.
        self.deliver_batch_enabled = req.understands_deliver_batch;
        // Negotiate the stream-ADDRESSED wire verbs (#588, M2-I10): the server always SUPPORTS named
        // streams, so the capability is active exactly when this client advertised it understands the
        // verbs. A streams-capable client may declare / publish-to / subscribe-to a NAMED stream; one
        // that did not advertise is REFUSED those verbs (a typed `Err`) and is never sent a streams
        // reply it did not ask for, so an old client uses only the default-stream verbs unchanged.
        self.streams_enabled = req.understands_streams;
        // Negotiate COMPRESSED delivery (#1066): the capability is active exactly when this consumer
        // advertised it can DECODE a compression-codec-encoded delivery. A capable consumer receives a
        // stored-COMPRESSED record VERBATIM (the codec bytes + `COMPRESSED` flag, the broker's zero-CPU
        // passthrough); one that did NOT advertise (an old client, or the empty `Connect`) has a
        // stored-COMPRESSED record DECOMPRESSED before delivery with the `COMPRESSED` bit cleared, so a
        // pre-#430 consumer that would mis-decode the descriptor bytes never receives them — even on a
        // `--compression lz4` broker. This is the silent-corruption fix: the safe default is uncompressed.
        self.compressed_delivery_enabled = req.understands_compressed_delivery;
        // A repeated Connect re-negotiates idempotently: reset the active named stream to the default
        // so a re-handshake never leaves a stale named-stream binding from a prior negotiation.
        self.stream = GroupName::default();
        // The server caps, read LOCALLY off the handle (NO actor round-trip), so the handshake never
        // touches the actor's checkpoint/fsync path and a stalled produce on one connection cannot
        // head-of-line-block this Connect (invariant 4, #177). The caps are static engine config.
        let (cap_credit, cap_credit_bytes) = engine.consumer_credit_caps();
        // NEGOTIATE: min(client request, server cap), or the server default when nothing was requested.
        let negotiated_credit = negotiate_credit(req.requested_credit, cap_credit);
        let negotiated_credit_bytes =
            negotiate_credit_bytes(req.requested_credit_bytes, cap_credit_bytes);
        // Fix the negotiated values for this connection (the lazy `credit_ceiling` /
        // `credit_ceiling_bytes` accessors return these cached values without re-reading the engine).
        self.credit_ceiling = Some(negotiated_credit);
        self.credit_ceiling_bytes = Some(negotiated_credit_bytes);
        // Advertise the negotiated value plus the server cap, so the client adopts the negotiated
        // credit for its own flow control and learns the cap it can never exceed.
        let info = InfoBody {
            credit: Some(CreditAdvert {
                negotiated: negotiated_credit,
                cap: cap_credit,
            }),
            credit_bytes: Some(CreditAdvert {
                negotiated: negotiated_credit_bytes,
                cap: cap_credit_bytes,
            }),
            // Confirm the gap-marker capability the server activated for this connection, so the
            // client knows whether to expect `GapMarker` (tag 21) or the legacy `Truncated` (#346).
            gap_marker: self.gap_marker_enabled,
            // #494 is PROTO/CODEC only: the server does not echo a connection-wide default ack level
            // yet (that is phase #497), so this stays `None` and the `Info` body is byte-for-byte the
            // pre-#494 layout.
            default_ack_level: None,
            // Confirm the streaming-tier capability the server activated for this connection (#543), so
            // the client learns whether it may consume at Tier-S, mirroring the gap-marker confirmation.
            streaming: self.streaming_enabled,
            // Echo the negotiated connection-default tier ONLY when it is Tier-S (the streaming-capable
            // case): a Tier-W default echoes nothing, so a connection that negotiated nothing keeps the
            // `Info` body byte-for-byte the pre-#543 layout (no tier byte) and an old/Tier-W client sees
            // no change. The echo is the value a tier-less subscription consumes at.
            default_tier: match self.default_tier {
                ConsumeTier::Streaming => Some(ConsumeTier::Streaming.as_u8()),
                ConsumeTier::Work => None,
            },
            // Confirm the DeliverBatch capability the server activated for this connection (#541), so the
            // client learns whether to expect `DeliverBatch` (tag 26) or only per-record `Deliver`,
            // mirroring the gap-marker / streaming confirmations.
            deliver_batch: self.deliver_batch_enabled,
            // Confirm the stream-ADDRESSED capability the server activated for this connection (#588),
            // so the client learns whether it may address named streams by id, mirroring the
            // gap-marker / streaming / deliver-batch confirmations. The negotiation is AND: this is
            // `true` only when the client advertised the verbs AND the server supports named streams.
            streams: self.streams_enabled,
        };
        let mut info_body = Vec::new();
        encode_info(&info, &mut info_body);
        reply(out, FrameType::Info, &info_body);
        Ok(())
    }

    /// The per-verb AUTHORIZATION gate (#631, V2-M7): on an auth-required broker, a verb is allowed
    /// only when this connection authenticated AND its pinned scope set grants the required scope, with
    /// NO implication between scopes (`admin` does NOT grant `publish` or `subscribe`). A denial writes
    /// the ONE uniform Authorization Violation (indistinguishable on the wire from an authn failure)
    /// and returns [`SessionError::AuthViolation`] so the caller closes the connection.
    ///
    /// On a NO-AUTH broker (`auth_config` is `None`, the zero-config loopback-dev path) this is a
    /// no-op `Ok(())`: the gate is bypassed and every verb behaves byte-for-byte as before, so the dev
    /// experience is unchanged. This is the single choke point every scope-gated verb funnels through,
    /// so the no-implication property lives in exactly one tested place.
    fn require_scope(
        &self,
        scope: crate::auth::Scope,
        verb: &'static str,
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if self.scope_denied(scope) {
            // Emit the SCOPE DENIAL audit event (#635): the pinned identity NAME, the required scope,
            // and the verb. The wire still sees only the uniform Authorization Violation (no oracle);
            // the audit event, on the trusted side, distinguishes the denial for the operator.
            self.emit_audit(&crate::audit::AuditEvent::AuthzDenial {
                identity: self.identity_name.clone(),
                scope: scope.as_str(),
                verb,
            });
            reply_auth_violation(out);
            return Err(SessionError::AuthViolation);
        }
        Ok(())
    }

    /// Emits one security audit event (#635) through the attached emitter, or does nothing when no
    /// emitter is attached (the default; the byte-for-byte historical path). The emitter itself is also
    /// zero-cost over the `Null` sink, so this is cheap on both the no-emitter and no-sink paths. The
    /// event carries only safe handles (the identity NAME, the mechanism/scope/verb tags), never a
    /// credential — the type forecloses a leak.
    fn emit_audit(&self, event: &crate::audit::AuditEvent) {
        if let Some(audit) = self.audit.as_ref() {
            audit.emit(event);
        }
    }

    /// The pure (no side-effect) half of the scope gate: whether the named scope is DENIED for this
    /// connection (#631). `false` on a no-auth broker (the gate is inert, loopback-dev unchanged) and
    /// on an authenticated connection that holds the scope; `true` only on an auth-required broker
    /// where the connection did not authenticate OR its pinned scope set lacks the scope (with NO
    /// implication from any other scope). Used by the `Pub` path, which must drain its parked acks
    /// before writing the violation, so it needs the predicate without the write.
    fn scope_denied(&self, scope: crate::auth::Scope) -> bool {
        // No auth configured: never denied (loopback-dev, byte-for-byte unchanged).
        if self.auth_config.is_none() {
            return false;
        }
        // Auth-required: allowed only when authenticated AND holding exactly the named scope.
        !(self.authenticated && self.scopes.has(scope))
    }

    /// Handles a `Pub`: validates the wire body, then SUBMITS the produce to the actor and PARKS
    /// the pending ack in `parked` (the pipelined window, #450) instead of awaiting it inline. The
    /// caller releases the parked acks in FIFO submission order (see [`drain_parked`]); every
    /// immediate (pre-submit) reply below first drains `parked`, so a validation error's `Err`
    /// frame never overtakes an earlier produce's ack on the wire.
    fn handle_pub<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
        body: &[u8],
        parked: &mut VecDeque<ParkedPub>,
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        // Captured up front (it is `Copy`) so the pre-submit error-path drains can register a parked
        // Level-2 produce's confirm (#497) without re-borrowing `self`.
        let member_id = self.member_id;
        if !self.connected {
            drain_parked(engine, member_id, parked, out)?;
            reply_err(out, "not connected");
            return Ok(());
        }
        // The `publish` scope gate (#631), checked here (not only in `dispatch`) because the `process`
        // pipelined loop intercepts `Pub` frames and calls `handle_pub` DIRECTLY, bypassing `dispatch`
        // — so gating here is the single point that covers BOTH paths. A connection without `publish`
        // (with no implication from `admin`/`subscribe`) is refused with the uniform Authorization
        // Violation, after draining any parked acks so the wire order is preserved, then the connection
        // closes. On a no-auth broker the gate is inert (loopback-dev, byte-for-byte unchanged).
        if self.scope_denied(crate::auth::Scope::Publish) {
            // Emit the SCOPE DENIAL audit event (#635) for the direct `Pub` path (the pipelined loop
            // calls `handle_pub` directly, bypassing `dispatch`/`require_scope`, so the audit emission
            // lives here too). Identity NAME + scope + verb, never a credential.
            self.emit_audit(&crate::audit::AuditEvent::AuthzDenial {
                identity: self.identity_name.clone(),
                scope: crate::auth::Scope::Publish.as_str(),
                verb: "Pub",
            });
            // Drain the earlier produces' acks FIRST (so they reach the wire ahead of the close), then
            // write the uniform violation, then close — the same pre-submit error ordering as above.
            drain_parked(engine, member_id, parked, out)?;
            reply_auth_violation(out);
            return Err(SessionError::AuthViolation);
        }
        let Ok(msg) = decode_pub(body) else {
            drain_parked(engine, member_id, parked, out)?;
            reply_err(out, "malformed pub body");
            return Ok(());
        };
        // The per-publish produce ACK LEVEL (#494/#495): the server reads it from the decoded PUB
        // flags and routes the produce accordingly. `pub_ack_level` folds BOTH the canonical
        // fire-and-forget bit and the 2-bit ack-level field into one [`AckLevel`]:
        //
        // - LEVEL 1 (`AckLevel::ServerAck`) is TODAY's behavior EXACTLY: a `PubAck` after the covering
        //   group-commit fsync (I2). A pre-feature client sets NEITHER the faf bit NOR a level bit, so
        //   it decodes as Level 1 and its path below is byte-for-byte unchanged.
        // - LEVEL 0 (`AckLevel::NoAck`) is the no-ack fire-and-forget fast path (#495), the
        //   generalization of the historical `PUB_FLAG_FIRE_AND_FORGET` path (an old faf publish IS a
        //   Level-0 publish): it gets NO PubAck, allocates NO reply channel, parks NOTHING, and does not
        //   wait for the fsync. Routed to `produce_no_reply` below.
        // - LEVEL 2 (`AckLevel::ServerAndClientAck`, #497): accepted and made DURABLE exactly like
        //   Level 1 (the `PubAck` stays the DURABILITY ack, I2), AND the durable offset is registered
        //   in the engine's bounded confirm registry so that, when a CONSUMER in the designated group
        //   later acks it, a server->producer `ProduceConfirm{status = consumed}` fires. The Level-1
        //   `PubAck` and the Level-2 confirm are TWO acks: durable-then-consumed.
        let ack_level = pub_ack_level(msg.flags);
        // Whether this publish wants a Level-2 consumer-ack confirmation in addition to its durability
        // `PubAck` (#497). Only the at-least-once L2 level does; L0 (no reply) and L1 do not.
        let wants_confirm = matches!(ack_level, AckLevel::ServerAndClientAck);
        // Mark the connection as having opted into Level 2 (#497) so its passes drain confirms. Set at
        // parse time, BEFORE the produce is even submitted: it never clears, and it is what keeps the
        // per-pass confirm drain OFF the actor for an L0/L1-only or ping-only connection (#177).
        if wants_confirm {
            self.produced_l2 = true;
        }
        // A LEVEL-0 publish is the generalized fire-and-forget: it gets no ack and is governed by the
        // fire-and-forget token bucket, REGARDLESS of which Level-0 encoding the producer used (the
        // canonical faf bit, where `msg.fire_and_forget` is already true, OR the level-bit value 1,
        // where it is not). Deriving the faf marker from the ack level here makes the level-bit and the
        // faf-bit Level-0 encodings behave identically downstream (one no-ack path). Level 1 and the
        // Level-2-as-Level-1 fallback are at-least-once, so `fire_and_forget` is false for them and the
        // existing parked-ack path is unchanged.
        let level0 = matches!(ack_level, AckLevel::NoAck);
        let fire_and_forget = level0;
        // CLUSTER `NOT_LEADER` PRODUCE REDIRECT (#735, half A): on a clustered serve, if this node holds a
        // replica role for the partition but is NOT its current leader, the produce must go to the leader
        // — redirect it BEFORE any local append/ack, so it is never acked by the wrong node (no
        // double-append, no false ack; the client retries to the leader where the #720 quorum gate
        // applies). SINGLE-NODE / no-cluster is BYTE-IDENTICAL: `cluster_produce_routing` returns
        // `Local` via a cheap default (no gate, no lock, no alloc), so this whole branch is skipped and
        // the produce path is byte-for-byte today's. NEVER a false `NOT_LEADER` on the leader (it returns
        // `Local`) or on a non-clustered / pre-bootstrap partition (also `Local`). The default-stream log
        // maps to the cluster default partition; multi-partition routing is the flagged #693 follow-up.
        if let crate::cluster::client_ack::ClusterProduceRouting::Redirect { leader_hint } =
            engine.cluster_produce_routing(crate::cluster::client_ack::DEFAULT_PARTITION)
        {
            // Preserve the wire reply order: flush the earlier pipelined produces' acks FIRST (exactly
            // like every other pre-submit return in this function), THEN the redirect.
            drain_parked(engine, member_id, parked, out)?;
            // A LEVEL-0 (fire-and-forget) produce expects NO reply by contract: drop it silently (the
            // record is simply not appended on this wrong node — the QoS-0 producer accepts loss and will
            // re-fire to the leader on its own). An at-least-once produce gets the typed `NOT_LEADER` frame
            // carrying the leader hint so the client transparently reconnects/retries to the leader.
            if !fire_and_forget {
                reply_not_leader(out, leader_hint);
            }
            return Ok(());
        }
        // Enforce the dedup id length caps (#33) at the wire boundary, BEFORE the bytes cross into
        // owned storage. The `producer_id` keys the per-producer window map and the `msg_id` keys the
        // per-window ring; both are wire-supplied and attacker-chosen (up to the 64 KiB wire field
        // limit), so an unbounded id would bloat per-entry memory. A too-long id is a typed,
        // connection-preserving rejection (NOT a panic, NOT a frame change), like a malformed body.
        if let Some(d) = msg.dedup.as_ref() {
            if d.producer_id.len() > MAX_PRODUCER_ID_LEN {
                if !fire_and_forget {
                    drain_parked(engine, member_id, parked, out)?;
                    reply_err(out, "producer_id too long");
                }
                return Ok(());
            }
            if d.msg_id.len() > MAX_MSG_ID_LEN {
                if !fire_and_forget {
                    drain_parked(engine, member_id, parked, out)?;
                    reply_err(out, "msg_id too long");
                }
                return Ok(());
            }
            // The idempotent-producer SEQUENCE (V2-M8) requires a NON-EMPTY producer_id: the durable
            // high-water is keyed by producer_id, so an anonymous (empty) id would collapse every
            // sequenced producer onto one shared high-water and false-dedup/false-reject across them.
            // Fail closed (a typed, connection-preserving rejection), exactly like the over-long id
            // rejections above. A sequenced producer with no identity is a client error, not silently
            // accepted.
            if d.seq.is_some() && d.producer_id.is_empty() {
                if !fire_and_forget {
                    drain_parked(engine, member_id, parked, out)?;
                    reply_err(out, "idempotent sequence requires a non-empty producer_id");
                }
                return Ok(());
            }
        }
        // Produce-time COMPRESSED-descriptor SHAPE validation (#438), shared with the three other
        // produce verbs (see `compressed_descriptor_rejection`). Bit 0 of the PUB flags is a REAL
        // stored record flag the wire legally carries (`PUB_WIRE_ONLY_FLAGS` masks only the wire-only
        // high bits, never bit 0): a producer may publish a pre-compressed stored object and the
        // engine's write seam passes it through untouched (#437, never double-wrapped), so without
        // this gate a producer could durably ack a record no reader can decode.
        if let Some(reason) = compressed_descriptor_rejection(msg.flags, msg.payload) {
            // A failure is a typed, connection-preserving rejection exactly like the wire-boundary
            // rejections above; for a fire-and-forget produce it is a silent drop with NO frame (the
            // QoS-0 no-frame contract, #11) and no counter, matching the dedup-id-cap precedent.
            if !fire_and_forget {
                drain_parked(engine, member_id, parked, out)?;
                reply_err(out, &reason);
            }
            return Ok(());
        }
        // Hand the produce to the append actor as an OWNED payload (the wire body borrows the
        // connection's input buffer, which the actor cannot hold) and AWAIT its outcome. The reply
        // arrives only after the covering group-commit fsync, so the PubAck is ack-implies-durable
        // (I2): the actor never replies Appended before the fdatasync that made the record durable.
        // The codec already normalized the HAS_KEY bit and preserved unknown bits for forward
        // compatibility; the storage layer never acts on unknown bits.
        //
        // The opt-in dedup block (#33): if the publish carried a `msg_id`, carry the producer id /
        // epoch / msg_id to the engine's dedup window. Mask the WIRE-only dedup bit OUT of the stored
        // record flags so it never becomes a record flag (it is a wire signal, not stored state).
        let dedup = msg.dedup.map(|d| OwnedDedup {
            producer_id: Bytes::copy_from_slice(d.producer_id),
            epoch: d.epoch,
            msg_id: Bytes::copy_from_slice(d.msg_id),
            // The opt-in idempotent SEQUENCE (V2-M8) rides through to the engine's durable per-producer
            // high-water; `None` keeps the existing time-bounded `msg_id`-window dedup path.
            seq: d.seq,
        });
        // Carry the produce's bytes as refcounted `Bytes` (#474) so moving/cloning the `OwnedAppend`
        // across the append-actor channel is a refcount bump, not a `Vec` deep copy. The wire body
        // still borrows the connection's input buffer (which the actor cannot hold), so this fill
        // copies the slice ONCE here at the boundary; the FULL zero-copy (a `Bytes` slice OF the read
        // buffer, retired by refcount) is the follow-on read-buffer rework flagged on #474. The
        // storage encode copies the payload into the segment buffer when it appends regardless, so
        // durability and the on-disk image are unchanged.
        let append = OwnedAppend {
            timestamp_ms: msg.timestamp_ms,
            // Mask the wire-only PUB flag bits (dedup bit 7, fire-and-forget bit 6, the ack-level
            // field bits 3..=4, and the idempotent-sequence bit 5, #33/#11/#494/#638) out of the
            // stored record flags: none is record state. The fire-and-forget marker and the sequence
            // are carried in their own fields, not in the stored flags.
            flags: msg.flags & !PUB_WIRE_ONLY_FLAGS,
            key: Bytes::copy_from_slice(msg.key),
            headers: Bytes::copy_from_slice(msg.headers),
            payload: Bytes::copy_from_slice(msg.payload),
            // Offload the per-record body CRC32C (and xxh3-64 for a large body) onto THIS producing
            // connection thread (#830), over the same wire slices copied above, so the single-writer
            // actor stores the checksum instead of computing it on its serialized path.
            body_checksums: Some(BodyChecksums::compute(msg.key, msg.headers, msg.payload)),
            dedup,
            // Stamp the ENQUEUE instant from the engine's clock seam (a LOCAL read, no actor
            // round-trip), so the engine can measure the admission SOJOURN for the CoDel shed (#68).
            // Read just before the produce crosses the channel, so the sojourn captures the queue
            // wait. CoDel-off (the default) ignores this entirely.
            enqueue_monotonic_nanos: engine.now_monotonic_nanos(),
            // The QoS-0 / Level-0 fire-and-forget marker (#11, #402, #495): set for every Level-0
            // publish (derived from the ack level above, so the canonical faf bit and the level-bit
            // Level-0 encoding are equivalent). When set, the broker may drop the produce under the
            // fire-and-forget bucket WITHOUT acking, and otherwise appends it durably but sends NO
            // PubAck. Level 1 (and the Level-2-as-Level-1 fallback) leave it clear.
            fire_and_forget,
            // The produce ACK LEVEL (#571), captured from the wire PUB flags ABOVE (before the
            // wire-only level bits were masked out of `flags`), so the actor can attribute the
            // accepted record to its level (c0/c1/c2) for the per-ack-level produce counters.
            ack_level,
        };
        // LEVEL 0 (no-ack fast path, #495): submit the produce with NO reply channel and return
        // immediately — do NOT park. The producer fired and forgot, so there is no PubAck to write, no
        // reply-channel allocation, and no fsync to wait for. The connection-thread byte-cap pre-check
        // (#476) inside `produce_no_reply` sheds an over-cap L0 here (counted in the fire-and-forget
        // shed metric), droppable under overload; an admitted L0 is appended into the actor's batch
        // (single-writer storage / single total order) but never acked. An old fire-and-forget publish
        // takes exactly this path (it decodes as Level 0).
        if level0 {
            // COALESCE into the pass-scoped Level-0 batch (#11 fast path): accumulate this no-ack
            // produce and hand the whole socket-read's worth to the actor in ONE
            // `produce_no_reply_batch` send at the flush boundary, instead of one channel send per
            // message. The batch is flushed before any Level-1 produce or non-produce job and at the end
            // of the pass, so the actor still observes this connection's single total order.
            self.level0_pending.push(append);
            return Ok(());
        }
        // LEVEL 1 / LEVEL 2 (at-least-once; L2 falls back to L1 this phase): SUBMIT the produce to the
        // actor WITHOUT awaiting (#450) and PARK the pending ack. The caller releases parked acks in
        // FIFO submission order, so the reply this produce eventually gets is byte-identical to the
        // awaited path's, only written later in the same pass. The submission still blocks on a FULL
        // actor channel (backpressure), and the actor still releases the reply only after the covering
        // group-commit fsync (I2). This path is unchanged from before the ack-level feature.
        //
        // A Level-0 batch accumulated BEFORE this at-least-once produce must reach the actor FIRST so the
        // single total order holds (the L0s decoded earlier are appended before this L1): flush it now.
        self.flush_level0(engine)?;
        let submission = engine.produce_submit(append)?;
        parked.push_back(ParkedPub {
            submission,
            fire_and_forget,
            wants_confirm,
        });
        Ok(())
    }

    /// Flushes the pass-scoped Level-0 batch ([`Session::level0_pending`]) to the actor as ONE
    /// `produce_no_reply_batch` send (#11 fast path), draining it; a no-op when empty. Called before any
    /// Level-1 produce or non-produce job on this connection — so the actor observes the connection's
    /// single total order — and at the end of every pass (so it never holds state across passes).
    ///
    /// # Errors
    /// [`SessionError::ActorGone`] if the append actor exited before the batch could be enqueued.
    fn flush_level0<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
    ) -> Result<(), SessionError> {
        if self.level0_pending.is_empty() {
            return Ok(());
        }
        engine.produce_no_reply_batch(std::mem::take(&mut self.level0_pending))?;
        Ok(())
    }

    /// Handles a consumer acknowledgement (ack, nack, term, or progress) for a delivered
    /// message. Acks are connection-scoped (#175): the session tracks the lease tokens it
    /// handed out via Flow, and an op whose `(offset, generation)` was not delivered to THIS
    /// session is fenced (status 0) without touching the engine, so a second connection cannot
    /// commit or requeue a message destined for another consumer. The generation token still
    /// fences a stale op on an own-but-already-redelivered lease.
    fn handle_ack<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(ack) = decode_ack(body) else {
            reply_err(out, "malformed ack body");
            return Ok(());
        };
        let token = LeaseToken {
            offset: Offset::new(ack.offset),
            generation: ack.generation,
        };
        // Connection-scoped ownership (#175): only the session this lease was delivered to may
        // act on it. A token this session never received (or whose generation does not match
        // the one delivered) is fenced (status 0) without touching the engine, so a second
        // connection cannot commit or requeue another consumer's message.
        if self.leased.get(&ack.offset).map(|l| l.generation) != Some(ack.generation) {
            reply(out, FrameType::AckStatus, &[0]);
            return Ok(());
        }
        // The group is sent to the actor by value (the engine job is `'static`); cloning the
        // subscription name per ack is cheap against the round-trip and keeps the session state in
        // the handler. Each op replies a one-byte status documented per arm below (e.g. progress can
        // reply 2 = cap reached). A status of 0 always means fenced: the token was stale (the message
        // already redelivered or was acked), so the client must NOT drop its state.
        let group = self.subscription.clone();
        // A NAMED-stream consumer (#588) routes its ACK to the stream's OWN per-stream group cursor via
        // the engine's id-routed `ack_in_stream` (#676/#679); the nack/term/progress and the egress-AIMD
        // keep-up are the DEFAULT stream's lease machinery (the named path is plain ack-or-fence this
        // phase, the #676 scope), so a named-stream consumer that sends one of those gets a fence rather
        // than a cross-stream effect. The default stream (`self.stream` empty) is byte-for-byte unchanged.
        let stream = self.stream.clone();
        if !stream.is_empty() {
            return self.handle_ack_in_stream(engine, stream, group, ack, &token, out);
        }
        match ack.op {
            AckOp::Ack => {
                let status = match engine.with(move |e| e.ack_in(&group, &token))? {
                    AckResult::Acked => {
                        // EGRESS AIMD keep-up signal (#69, #402): a clean ack is the consumer keeping
                        // up, so additive-increase the egress limit (a no-op when the AIMD is inert).
                        // It feeds the SAME limiter the Flow path reads through `egress_grant_within`,
                        // so a consumer that acks promptly slowly recovers its egress credit.
                        engine.with(crate::engine::Engine::egress_keep_up)?;
                        1u8
                    }
                    AckResult::Fenced => 0u8,
                };
                self.leased.remove(&ack.offset);
                reply(out, FrameType::AckStatus, &[status]);
                Ok(())
            }
            AckOp::Nack => {
                let delay = ack.delay_ms;
                match engine.with(move |e| e.nack_in(&group, &token, delay))? {
                    Ok(NackResult::Requeued) => {
                        // EGRESS AIMD falling-behind signal (#69, #402): a nack means the consumer
                        // could not process the message, so multiplicatively-decrease the egress limit
                        // (a no-op when the AIMD is inert). Repeated nacks throttle the egress credit
                        // smoothly, the failure half of the AIMD asymmetry.
                        engine.with(crate::engine::Engine::egress_falling_behind)?;
                        // CREDIT AUTO-TUNE back-off (#552): a nack is the consumer signalling it could
                        // NOT process the message — it is not draining what it already holds — so halve
                        // the per-consumer credit window toward the floor (never below it, so forward
                        // progress is guaranteed). This is the back-pressure half of the auto-tune: a
                        // window grown for a keeping-up consumer is shed promptly once it stops draining,
                        // so a non-draining consumer does not sit on a large in-flight set.
                        self.credit_back_off();
                        self.leased.remove(&ack.offset);
                        reply(out, FrameType::AckStatus, &[1]);
                        Ok(())
                    }
                    Ok(NackResult::Fenced) => {
                        self.leased.remove(&ack.offset);
                        reply(out, FrameType::AckStatus, &[0]);
                        Ok(())
                    }
                    // Generation exhaustion is fatal: it wedges every future claim and nack, so
                    // end the session rather than let the client hammer a dead engine, exactly as
                    // the produce path does, instead of masquerading it as a transient failure.
                    Err(e) if e.is_fatal() => {
                        reply_err(out, "fatal storage error");
                        Err(SessionError::EngineFatal(e))
                    }
                    Err(_) => {
                        reply_err(out, "nack failed");
                        Ok(())
                    }
                }
            }
            // Term is an intentional drop: commit past the message (the same mechanism as
            // ack) so it never redelivers and is not dead-lettered. 1 = dropped, 0 = fenced.
            AckOp::Term => {
                let status = match engine.with(move |e| e.term_in(&group, &token))? {
                    AckResult::Acked => 1u8,
                    AckResult::Fenced => 0u8,
                };
                self.leased.remove(&ack.offset);
                reply(out, FrameType::AckStatus, &[status]);
                Ok(())
            }
            // Progress extends the lease (the consumer is still working). 1 = extended,
            // 2 = cap reached (the lease will expire and the message redeliver on schedule),
            // 0 = fenced.
            AckOp::Progress => {
                let status = match engine.with(move |e| e.progress_in(&group, &token))? {
                    ProgressResult::Extended => 1u8,
                    ProgressResult::CapReached => 2u8,
                    ProgressResult::Fenced => {
                        self.leased.remove(&ack.offset);
                        0u8
                    }
                };
                reply(out, FrameType::AckStatus, &[status]);
                Ok(())
            }
        }
    }

    /// The ACK path for a NAMED-stream consumer (#588, M2-I10): commits the ack `token` in the active
    /// named stream's OWN per-stream work-group cursor via the engine's id-routed `ack_in_stream`
    /// (#676/#679), connection-scoped exactly like the default-stream ack (the lease-ownership check ran
    /// in [`Session::handle_ack`] before this is reached). The named consume path is plain ack-or-fence
    /// this phase (no nack/term/progress per stream, the #676 scope), so those ops reply FENCED (status
    /// 0) — a named-stream consumer that re-processes a message simply lets the lease expire and
    /// redeliver, never crossing into the default stream's lease machinery.
    fn handle_ack_in_stream<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        stream: GroupName,
        group: GroupName,
        ack: ironbus_proto::message::AckBody,
        token: &LeaseToken,
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        match ack.op {
            AckOp::Ack => {
                let token = *token;
                let status = match engine.with(move |e| e.ack_in_stream(&stream, &group, &token))? {
                    AckResult::Acked => 1u8,
                    AckResult::Fenced => 0u8,
                };
                self.leased.remove(&ack.offset);
                reply(out, FrameType::AckStatus, &[status]);
                Ok(())
            }
            // Nack/Term/Progress are not on the per-stream consume path this phase (#676 scope): fence
            // them (status 0) rather than acting on the default stream's lease table. The lease expires
            // and redelivers on schedule, so at-least-once for the named stream is preserved.
            AckOp::Nack | AckOp::Term | AckOp::Progress => {
                self.leased.remove(&ack.offset);
                reply(out, FrameType::AckStatus, &[0]);
                Ok(())
            }
        }
    }

    /// Handles a BROADCAST cumulative ack (the tag-19 `CumulativeAck` frame, #288): commits the
    /// named broadcast group's single cursor up to the body's exclusive `up_to` offset. The body
    /// carries its own group name (it does not depend on a prior SUB), so a broadcast consumer can
    /// drive the verb on any group it owns. The engine enforces the safety contract: only a group
    /// MARKED broadcast accepts the verb (a competing or `key_shared` group is rejected with the
    /// work-group error, unchanged from #63), `up_to` is validated against the durable head and the
    /// earliest-retained offset, and a re-ack is an idempotent no-op success. A success replies the
    /// generic `Ok`; a rejection replies a typed `Err` with the engine's reason; a fatal engine
    /// error ends the session, exactly like the produce and nack paths.
    fn handle_cumulative_ack<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(ack) = decode_cumulative_ack(body) else {
            reply_err(out, "malformed cumulative-ack body");
            return Ok(());
        };
        let Ok(group) = core::str::from_utf8(ack.group) else {
            reply_err(out, "cumulative-ack group name must be valid UTF-8");
            return Ok(());
        };
        let group = group.to_string();
        let up_to = Offset::new(ack.up_to);
        let up_to_exclusive = ack.up_to;
        match engine.with(move |e| e.cumulative_ack_in(&group, up_to))? {
            Ok(()) => {
                // A committed (or idempotent no-op) cumulative ack: the generic body-less success.
                // Release the per-connection leases this bulk commit covers (every offset strictly
                // below the exclusive `up_to`), so a broadcast consumer that fetches-then-cumulative-
                // acks gets its in-flight credit back. Per-message ack/nack/term remove from `leased`
                // one offset at a time; #288 added this bulk commit path but omitted the bookkeeping,
                // so `leased` only ever GREW and the consumer eventually starved its own fetches (its
                // remaining message credit is `ceiling - leased.len()`).
                self.leased.retain(|&offset, _| offset >= up_to_exclusive);
                reply(out, FrameType::Ok, &[]);
                Ok(())
            }
            // A fatal engine error (a frozen writer surfaced through a storage fault) wedges every
            // future op, so end the session rather than masquerade it as a transient rejection.
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            // The work-group reject (#63) and the out-of-range reject (#288) are both client-visible,
            // recoverable rejections: surface the engine's typed reason so the client learns why and
            // the connection stays open.
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }
    /// The per-CONSUMER (per-connection) in-flight credit ceiling (#65) for this session: the
    /// NEGOTIATED value (#292). Normally fixed at `Connect` time (to `min(client request, server cap)`)
    /// and returned from the cache here; if it was not fixed (an old client that never sent a Connect,
    /// or a Connect whose engine read failed), it is computed here on the first Flow by reading the
    /// engine cap and clamping the stored client request to it. The engine is the source of truth for
    /// the cap (a `serve` flag sets it once for every connection), already floored to at least 1.
    /// Reads through the actor at most once, then caches.
    ///
    /// # Errors
    /// Returns [`SessionError::ActorGone`] if the actor exited before the read.
    fn credit_ceiling<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
    ) -> Result<u32, SessionError> {
        if let Some(c) = self.credit_ceiling {
            return Ok(c);
        }
        // Not fixed at Connect: read the cap and clamp the stored request to it (the lazy half of the
        // #292 negotiation), so a client request honored late behaves exactly as if fixed at Connect.
        let cap = engine.with(|e| e.consumer_credit())?;
        let c = negotiate_credit(self.requested_credit, cap);
        self.credit_ceiling = Some(c);
        Ok(c)
    }

    /// The per-CONSUMER (per-connection) in-flight BYTE budget (#275) for this session: the NEGOTIATED
    /// value (#292), the byte-side companion to [`Session::credit_ceiling`]. Normally fixed at
    /// `Connect`; otherwise computed here on the first Flow by clamping the stored request to the
    /// engine cap. The engine is the source of truth (a `serve` flag sets it once for every
    /// connection). `0` means unlimited.
    ///
    /// # Errors
    /// Returns [`SessionError::ActorGone`] if the actor exited before the read.
    fn credit_ceiling_bytes<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
    ) -> Result<u64, SessionError> {
        if let Some(c) = self.credit_ceiling_bytes {
            return Ok(c);
        }
        let cap = engine.with(|e| e.consumer_credit_bytes())?;
        let c = negotiate_credit_bytes(self.requested_credit_bytes, cap);
        self.credit_ceiling_bytes = Some(c);
        Ok(c)
    }

    /// The CURRENT auto-tuned per-consumer message window (#552): the most un-acked messages this
    /// connection may hold in flight right now, BEFORE the byte budget intersects it. Lazily builds the
    /// [`ironbus_core::backpressure::CreditAutotuner`] from the negotiated `credit_ceiling` on the first
    /// call (the auto-tune's ceiling is the negotiated #292 cap, the same value the RAM guard charges),
    /// then returns its current window, which grows toward the ceiling as the consumer keeps up and
    /// halves under backpressure. A consumer that never keeps up sits at the floor (64, or its lower
    /// negotiated ceiling), so it is byte-for-byte the historical fixed window.
    ///
    /// # Errors
    /// Returns [`SessionError::ActorGone`] if the actor exited before the ceiling read.
    fn credit_window<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
    ) -> Result<u32, SessionError> {
        if self.credit_autotune.is_none() {
            let ceiling = self.credit_ceiling(engine)?;
            self.credit_autotune = Some(ironbus_core::backpressure::CreditAutotuner::with_ceiling(
                ceiling,
            ));
        }
        // Just-set above, so the unwrap is infallible; `expect` documents the invariant.
        Ok(self
            .credit_autotune
            .as_ref()
            .expect("credit_autotune set above")
            .window())
    }

    /// KEEP-UP signal to the credit auto-tune (#552): the consumer DRAINED its window without stalling
    /// (it took a full requested batch and never hit a would-block), so GROW the window toward the
    /// ceiling. A no-op before the auto-tuner is built (no Flow has run yet) or once the window is at
    /// the ceiling. This is the additive-increase half of the AIMD asymmetry; the back-off is on the
    /// would-block / nack paths.
    fn credit_keep_up(&mut self) {
        if let Some(a) = self.credit_autotune.as_mut() {
            a.keep_up();
        }
    }

    /// BACK-OFF signal to the credit auto-tune (#552): the consumer is not draining (a would-block at
    /// the window with a near-full in-flight set, or a nack), so multiplicatively DECREASE the window
    /// (halve, floored at the floor). A no-op before the auto-tuner is built. Forward progress is
    /// guaranteed: the window never collapses below the historical static floor.
    fn credit_back_off(&mut self) {
        if let Some(a) = self.credit_autotune.as_mut() {
            a.back_off();
        }
    }

    /// The total in-flight PAYLOAD bytes this connection currently holds un-acked (#275): the sum of
    /// every leased message's byte size. The byte budget is DERIVED from this, never a separate
    /// counter, so it cannot drift from true ownership. Saturating so it can never wrap.
    fn in_flight_bytes(&self) -> u64 {
        self.leased
            .values()
            .map(|l| l.bytes)
            .fold(0u64, u64::saturating_add)
    }

    /// Drops every `leased` entry the engine no longer holds as an ACTIVE (live and not expired)
    /// lease for this exact `(offset, generation)` (#65 redelivery accounting): a lease that was
    /// committed past, redelivered (to this or another consumer) under a fresh generation, OR has
    /// merely EXPIRED is no longer actively this connection's, so its slot must be freed before the
    /// remaining credit is computed. Freeing on expiry is what lets the message be recounted against
    /// whoever next claims it (possibly this same consumer, which then re-occupies exactly one slot
    /// because the re-claim overwrites the same offset key). A still-active, unexpired lease keeps
    /// its slot. Pure bookkeeping: it never mutates engine state.
    ///
    /// It batches the whole check into ONE actor round-trip (not one per lease): it sends the live
    /// `(offset, generation)` pairs, the actor returns the subset the engine still holds active, and
    /// the session retains only those. A no-op (no round-trip) when nothing is leased.
    ///
    /// # Errors
    /// Returns [`SessionError::ActorGone`] if the actor exited before the check.
    fn release_stale_leases<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
    ) -> Result<(), SessionError> {
        if self.leased.is_empty() {
            return Ok(());
        }
        // A NAMED-stream consumer (#588) prunes its leases by the stream's COMMITTED cursor rather than
        // the default stream's per-lease active-lease probe: the #676 named consume path exposes the
        // per-stream committed offset but not a per-stream `holds_active_lease_in`, so an offset at or
        // below the named stream's committed watermark is dropped (it was acked), and an expired-but-
        // not-committed lease stays — it is harmlessly re-leased and overwritten in `leased` on its
        // redelivery. This keeps `leased` bounded for the named path without the default-stream probe.
        if !self.stream.is_empty() {
            let stream = self.stream.clone();
            let group = self.subscription.clone();
            let committed =
                engine.with(move |e| e.committed_offset_in_stream(&stream, &group).get())?;
            self.leased.retain(|&offset, _| offset >= committed);
            return Ok(());
        }
        let group = self.subscription.clone();
        let pairs: Vec<(u64, u64)> = self
            .leased
            .iter()
            .map(|(&offset, lease)| (offset, lease.generation))
            .collect();
        // One job checks every pair on the engine and returns the offsets still held ACTIVE, so the
        // whole stale-lease prune is a single round-trip rather than one per in-flight message.
        let live: std::collections::HashSet<u64> = engine.with(move |e| {
            pairs
                .into_iter()
                .filter(|&(offset, generation)| {
                    e.holds_active_lease_in(
                        &group,
                        &LeaseToken {
                            offset: Offset::new(offset),
                            generation,
                        },
                    )
                })
                .map(|(offset, _)| offset)
                .collect()
        })?;
        self.leased.retain(|offset, _| live.contains(offset));
        Ok(())
    }

    /// Fetches up to the requested number of messages and streams them as DELIVER frames,
    /// terminated by a `FlowEnd` whose body is the count delivered (so the client knows the
    /// batch is complete). The credit count is a little-endian `u32`.
    ///
    /// The batch is bounded by the PER-CONSUMER credit (#65, #275): it delivers at most
    /// `min(requested_credit, message ceiling - already held, byte budget remaining, whatever the
    /// group makes available)`, with a hard floor of ONE message so a single over-budget message
    /// never wedges the consumer. Before counting, it releases any stale leases
    /// (expired-and-redelivered, or committed) so this connection's remaining credit reflects only
    /// what it still truly holds (redelivery accounting). Each delivery occupies one of this
    /// connection's message slots AND its bytes until it is acked, nacked, termed, or expires, so a
    /// single connection can never hold more than its message ceiling un-acked (nor, beyond the floor
    /// of one message, more than its byte budget), and one stuck consumer cannot consume a peer's
    /// budget (per-consumer isolation). The advisory frames (dead-letter, truncation) still count
    /// against the REQUESTED credit (they bound the total frames a batch streams) but do NOT occupy
    /// an in-flight slot or any bytes, since they commit past or reset rather than lease.
    // One cohesive credit/byte-budget/AIMD/auto-tune-bounded drain loop (the #65/#275/#402/#552 bounds
    // must bind in order in one place), the per-record analogue of `handle_fetch`; splitting it would
    // scatter the single in-flight-window walk across helpers and obscure the order the bounds compose.
    #[allow(clippy::too_many_lines)]
    fn handle_flow<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(credit_bytes) = <[u8; 4]>::try_from(body) else {
            reply_err(out, "flow credit must be a u32");
            return Ok(());
        };
        let requested = u32::from_le_bytes(credit_bytes);
        // Redelivery accounting (#65): free the slots of any leases this connection no longer holds
        // (expired-and-redelivered, or committed) BEFORE computing remaining credit, so a stuck
        // consumer's expired leases stop counting against it and its peers stay isolated.
        self.release_stale_leases(engine)?;
        // The per-consumer remaining credit: the AUTO-TUNED window (#552) minus what this connection
        // already holds un-acked. The effective batch bound is min(requested, remaining); the per-group
        // `max_in_flight` window further caps it inside the engine's poll (a full window returns
        // Poll::Idle, ending the batch early), so the delivered total is the MIN of the requested
        // credit, this consumer's remaining credit, and whatever the group makes available. Bounding
        // the WHOLE loop by `credits` (not `requested`) is what stops the engine from leasing an
        // offset this connection has no credit to deliver: at zero remaining credit the loop body
        // never runs, so a saturated consumer gets an empty batch even with messages available.
        //
        // The window AUTO-TUNES (#552): it starts at the historical floor (64) and grows toward the
        // negotiated `credit_ceiling` as the consumer keeps draining, so a fast/loopback consumer is no
        // longer pinned at 64/RTT (the #464/#532 floor). The ceiling is the negotiated #292 cap and the
        // RAM-guard's worst-case count; the byte budget below stays the firm RAM bound (the count grows
        // UNDER it).
        let window = self.credit_window(engine)?;
        let held = u32::try_from(self.leased.len()).unwrap_or(u32::MAX);
        let remaining = window.saturating_sub(held);
        // The per-consumer credit bound, before the egress AIMD. The consumer is COUNT-BOUND by its own
        // window when it asked for at least the whole window's worth and the window (not the requested
        // credit) is what capped `want`: that is the auto-tune keep-up signal once it actually drains.
        let want = requested.min(remaining);
        let window_was_binding = requested >= remaining && remaining > 0;
        // EGRESS AIMD (#69, #402): adjust the EFFECTIVE per-consumer egress credit WITHIN the
        // negotiated #292 ceiling. This is the SEPARATE (default-inert) downstream-sink limiter, kept
        // distinct from the #552 credit auto-tune: it bounds the per-Flow grant by the broker-wide
        // downstream health, the auto-tune bounds it by THIS consumer's keep-up. `egress_grant_within`
        // is `min(ceiling, AIMD limit)`, so the limiter never exceeds the negotiated cap; when the AIMD
        // is inert (the default) it returns the ceiling unchanged, so `credits` is exactly `want` and
        // the egress path is byte-for-byte historical. A real, observable WOULD-BLOCK is when the
        // consumer wanted MORE than the limiter grants while ALREADY holding a near-full in-flight set
        // (it is not keeping up): that is the falling-behind signal, so the AIMD multiplicatively
        // decreases (and counts the throttled grant). A clean keep-up (prompt acks) drives its additive
        // increase on the ack path.
        let ceiling = self.credit_ceiling(engine)?;
        let aimd_grant = engine.with(move |e| e.egress_grant_within(ceiling))?;
        let credits = want.min(aimd_grant);
        if aimd_grant < want && held >= aimd_grant {
            // The limiter is binding below what the consumer wants AND the consumer is already holding
            // at least a grant's worth un-acked (slow acks / falling behind): decrease and count it.
            engine.with(crate::engine::Engine::egress_falling_behind)?;
        }
        // The per-consumer BYTE budget (#275): `0` means unlimited (the byte budget is off, only the
        // message credit binds). When set, a delivery is refused once this connection's in-flight
        // bytes have reached the budget, EXCEPT the floor-of-one: a connection holding nothing
        // in-flight always gets at least one message even if it alone exceeds the budget, so a single
        // over-budget message never wedges the consumer. The check is BEFORE each poll because a poll
        // that returns Poll::Message has already leased the message in the engine (its size is not
        // knowable until then); delivering when at-or-below budget lets the in-flight total overshoot
        // by at most one message, which is the standard credit semantics and stays bounded.
        let ceiling_bytes = self.credit_ceiling_bytes(engine)?;
        let mut delivered = 0u32;
        // One reusable scratch buffer for this batch's per-record frame bodies (#826): cleared and
        // reused each iteration instead of allocating a fresh `Vec` per delivered record/advisory.
        let mut frame_body = Vec::with_capacity(DELIVER_FRAME_SCRATCH_CAP);
        // Event-driven long-poll (push delivery), PER-STREAM (#1100 L2): grab THIS consumer's stream
        // cell ONCE — keyed by `self.stream` (`""` for the default/root stream, else the named stream
        // this Flow polls) — and snapshot its generation BEFORE the poll batch (per-stream lost-wakeup
        // safety: a commit to THIS stream racing the snapshot bumps its cell past the snapshot, so the
        // wait predicate is already false and never parks). Run the delivery drain, and if it drew
        // NOTHING and long-poll is configured, block up to the budget on THAT cell and re-run the drain
        // EXACTLY ONCE. A commit to a DIFFERENT stream never wakes this waiter (the thundering-herd fix),
        // and a named-stream commit now wakes it early instead of eating its full budget. The repoll is
        // safe from `delivered == 0`: nothing was leased, no frame was emitted, and the
        // credit/ceiling/AIMD bounds were computed above and stay unconsumed, so a second drain is
        // byte-for-byte a fresh batch. A `None` seam or a zero budget skips straight to the unchanged
        // tail. Holding the cell (not re-looking-it-up) guarantees the snapshot and the wait target the
        // SAME cell.
        let longpoll_cell = engine.commit_notify().map(|n| n.cell(&self.stream));
        let longpoll_snapshot = longpoll_cell.as_ref().map(|c| c.seq());
        for longpoll_attempt in 0..2u8 {
            for _ in 0..credits {
                // The byte budget binds (#275): stop once in-flight bytes have reached the budget, unless
                // this connection holds nothing in-flight (the floor-of-one). A budget of 0 is unlimited,
                // so it never binds.
                if ceiling_bytes != 0
                    && !self.leased.is_empty()
                    && self.in_flight_bytes() >= ceiling_bytes
                {
                    break;
                }
                // Member-aware poll (#64): for a key_shared group this routes by the connection's
                // member id; for a plain competing group it is identical to poll_now_in, so the
                // KeyOrdering::None path is unchanged. One poll = one actor round-trip; the actor flushes
                // any pending produce batch first, so each poll sees a consistent durable head.
                //
                // A NAMED-stream consumer (#588) routes to the engine's id-routed `poll_in_stream` instead
                // (its OWN log + per-stream competing work-group, #676/#679), reading the engine's monotonic
                // `now` inside the job. The named path is plain competing (no key_shared/Tier-S/compaction
                // this phase, the #676 scope), so it returns only `Poll::Message`/`Poll::Idle`/an error; the
                // advisory arms below are unreachable for it but cost nothing. The default stream
                // (`self.stream` empty) is byte-for-byte the existing member-aware poll.
                let group = self.subscription.clone();
                let member = self.member_id;
                let stream = self.stream.clone();
                let poll = engine.with(move |e| {
                    if stream.is_empty() {
                        e.poll_now_in_member(&group, member)
                    } else {
                        let now = e.now_monotonic();
                        e.poll_in_stream(&stream, &group, now)
                    }
                })?;
                match poll {
                    Ok(Poll::Message(d)) => {
                        // Gate the delivery encoding on the negotiated compressed-delivery capability
                        // (#1066): a non-capable consumer gets a stored-COMPRESSED record DECOMPRESSED
                        // with the COMPRESSED bit cleared; a capable consumer (and every uncompressed
                        // record) passes through verbatim. `None` = the record cannot be safely
                        // delivered, so stop the batch rather than ship a byte it cannot decode.
                        let Some((wire_flags, wire_payload)) =
                            self.deliver_encoding(d.record.flags.bits(), &d.record.payload)
                        else {
                            break;
                        };
                        let msg = DeliverBody {
                            offset: d.offset.get(),
                            generation: d.token.generation,
                            flags: wire_flags,
                            timestamp_ms: d.record.timestamp_ms,
                            key: &d.record.key,
                            headers: &d.record.headers,
                            payload: wire_payload.as_ref(),
                        };
                        frame_body.clear();
                        // The record's key/headers came through PUB (u16-bounded), so this cannot
                        // exceed the field limit; on the impossible error, stop the batch.
                        if encode_deliver(&msg, &mut frame_body).is_err() {
                            break;
                        }
                        reply(out, FrameType::Deliver, &frame_body);
                        // Record ownership so only this session can later act on this lease (#175), and
                        // the message's byte size so the byte budget (#275) is derived from `leased`. The
                        // size is key + headers + payload, matching the engine's produced-bytes accounting.
                        let bytes = lease_bytes(&d.record);
                        self.leased.insert(
                            d.offset.get(),
                            Lease {
                                generation: d.token.generation,
                                bytes,
                            },
                        );
                        delivered += 1;
                    }
                    // A parked (poison, over max-deliver) message is committed past by the engine
                    // and skipped from delivery. Emit an in-band dead-letter advisory so the
                    // consumer learns the offset was dropped rather than silently never seeing it
                    // (#63); the durable DLQ topic write is still separate. The advisory does not
                    // count toward the delivered total. Keep draining the batch.
                    Ok(Poll::Parked { offset, .. }) => {
                        frame_body.clear();
                        encode_dead_letter(
                            &DeadLetterBody {
                                offset: offset.get(),
                                reason: DEAD_LETTER_MAX_DELIVER,
                            },
                            &mut frame_body,
                        );
                        reply(out, FrameType::DeadLetter, &frame_body);
                    }
                    // The group's cursor fell below the oldest retained record because the disk-full
                    // drop-oldest policy force-reaped its old segments (#82, #84). The engine has just
                    // reset the cursor to `earliest_retained` and returned this ONCE. Emit the in-band
                    // truncation advisory so the consumer learns it lost a span and where delivery
                    // resumes, then keep draining: the next poll delivers normally from the reset
                    // cursor. This consumes one credit slot (like a delivery or a dead-letter), so the
                    // credit still bounds the total frames a batch streams. Any in-flight leases this
                    // session held below the reset are now meaningless; drop them so a later ack is a
                    // no-op fence rather than acting on a reaped offset.
                    Ok(Poll::Truncated {
                        earliest_retained,
                        skipped,
                    }) => {
                        self.leased
                            .retain(|&offset, _| offset >= earliest_retained.get());
                        self.emit_truncation(
                            out,
                            &mut frame_body,
                            earliest_retained.get(),
                            skipped,
                        );
                    }
                    // The group's cursor advanced across a KEY-COMPACTION hole (#337, #411): the offsets
                    // in `[from, to)` were superseded by a later record for the same key, so they are
                    // permanently absent mid-stream (the engine already acked the cursor past them). A
                    // gap-marker-capable consumer (#292/#346) gets a `GapMarker` with reason COMPACTED so
                    // it can tell the offset jump is a bounded, reported gap rather than message loss; a
                    // non-capable consumer takes the unchanged SILENT advance (it has no gap-marker frame,
                    // and a compacted hole is not a loss, so emitting the legacy `Truncated` would
                    // mislabel it as a reap). The marker only consumes a credit slot when it is actually
                    // emitted, so a non-capable consumer's batch is byte-for-byte unchanged. Keep draining
                    // either way: the next poll resumes at `to`.
                    Ok(Poll::Compacted { from, to }) => {
                        if self.gap_marker_enabled {
                            Self::emit_compaction(out, &mut frame_body, from.get(), to.get());
                        }
                    }
                    // Nothing more deliverable right now: end the batch early.
                    Ok(Poll::Idle) => break,
                    Err(e) if e.is_fatal() => {
                        reply_err(out, "fatal storage error");
                        return Err(SessionError::EngineFatal(e));
                    }
                    Err(_) => {
                        // The Err is this batch's terminator; do NOT also send a FlowEnd (that
                        // would desync the client, which expects exactly one terminator per Flow).
                        reply_err(out, "fetch failed");
                        return Ok(());
                    }
                }
            }
            // Long-poll decision (push delivery): the drain drew NOTHING on the FIRST attempt and a budget
            // + a commit-notify seam are both configured, so block until a commit advances the durable
            // frontier (or the budget elapses) and repoll EXACTLY ONCE. Any other outcome — a non-empty
            // drain, the second attempt, a zero budget, or no seam (a non-actor engine) — breaks to the
            // unchanged tail below, which runs EXACTLY once regardless.
            if longpoll_attempt == 0 && delivered == 0 && self.consume_longpoll_ms > 0 {
                if let (Some(cell), Some(snapshot)) = (&longpoll_cell, longpoll_snapshot) {
                    cell.wait_for_change(
                        snapshot,
                        std::time::Duration::from_millis(self.consume_longpoll_ms),
                        // Spin-before-park (#1100) on the no-pre-ack-fsync tiers only — the produce
                        // path's spin discriminant, so a real-fsync broker never burns a core here.
                        engine.consume_wait_spin(),
                    );
                    continue;
                }
            }
            break;
        }
        // Drop ownership of any offset now committed (acked here, or committed past on a
        // dead-letter), keeping `leased` bounded to the in-flight window. A NAMED-stream consumer
        // (#588) reads its OWN per-stream committed cursor; the default stream reads the default
        // cursor byte-for-byte.
        let group = self.subscription.clone();
        let stream = self.stream.clone();
        let committed = engine.with(move |e| {
            if stream.is_empty() {
                e.committed_offset_in(&group).get()
            } else {
                e.committed_offset_in_stream(&stream, &group).get()
            }
        })?;
        self.leased.retain(|&offset, _| offset >= committed);
        // CREDIT AUTO-TUNE keep-up (#552): the consumer was COUNT-BOUND by its own window (it asked for
        // at least the whole remaining window) AND drained the full grant it was given (`delivered ==
        // credits`, every credit became a real delivery, not an early Idle / advisory). That is the
        // window FILLING THE PIPE — the consumer could use more in-flight than the window allowed, so
        // GROW it toward the ceiling. Bounding the keep-up on a window-binding, fully-drained batch (not
        // merely a non-empty one) is what removes the 64/RTT floor for a fast consumer without growing a
        // service-bound or starved consumer that never saturates its window. The byte budget still caps
        // the in-flight bytes, so the grown count can only ever deliver byte-budget-worth of RAM.
        if window_was_binding && delivered == credits && credits > 0 {
            self.credit_keep_up();
        }
        reply(out, FrameType::FlowEnd, &delivered.to_le_bytes());
        Ok(())
    }

    /// Handles a batch-pull `Fetch` (#489): the AMORTIZED twin of [`Session::handle_flow`]. It drains up
    /// to `max_records` / `max_bytes` of deliverable records in ONE round-trip by running the SAME
    /// per-record poll the `Flow` path runs, so it delivers EXACTLY the records that many successive
    /// per-record `Flow`/poll calls would, leasing each one identically. The whole at-least-once,
    /// lease/credit, and broadcast/`key_shared`/competing contract is preserved verbatim because every
    /// delivery goes through the same [`Engine::poll_now_in_member`] + `leased` insert as `handle_flow`;
    /// the batch only changes HOW MANY polls one request performs, never WHAT a poll does.
    ///
    /// The bounds compose as the MIN of: `max_records`, the per-consumer remaining credit
    /// (`ceiling - leased.len()`, #65), the egress AIMD grant (#69), the group's `max_in_flight` window
    /// (the engine returns `Poll::Idle` when it is full, ending the batch early, so the server never
    /// over-delivers), `max_bytes` (the per-consumer byte budget, #275, with the same floor-of-one), and
    /// the `expires` deadline. A `no_wait` fetch makes a SINGLE drain pass and returns whatever is ready
    /// immediately, never waiting out the deadline. Because the engine poll is non-blocking (no record
    /// arrives mid-call), `expires` bounds only the WORK a large drain may do; it never changes which
    /// records are delivered. The response reuses the existing delivery frames (`Deliver` /`DeadLetter`/
    /// `Truncated`/`GapMarker`) terminated by a single `FlowEnd`, byte-for-byte the `Flow` response, so a
    /// fetch and an equivalent flow are indistinguishable on the wire past the request frame.
    // The fetch drain is one cohesive loop (deadline, byte cap, claim, disposition, advisories), the
    // batch analogue of `handle_flow` plus the #489 bounds; splitting it would scatter the single
    // in-flight-window walk across helpers and obscure the order the bounds must bind in. Mirrors the
    // `Engine::poll_in` allowance for the same reason.
    #[allow(clippy::too_many_lines)]
    fn handle_fetch<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(req) = decode_fetch(body) else {
            reply_err(out, "malformed fetch body");
            return Ok(());
        };
        // Redelivery accounting (#65): free the slots of any leases this connection no longer holds
        // (expired-and-redelivered, or committed) BEFORE computing remaining credit, exactly as the
        // per-record Flow path does, so a stuck consumer's expired leases stop counting against it.
        self.release_stale_leases(engine)?;
        // The per-consumer remaining message credit: the AUTO-TUNED window (#552) minus what this
        // connection already holds un-acked (identical to `handle_flow`). The batch is bounded by the
        // MIN of the requested `max_records`, this remaining credit, and the egress AIMD grant, so a
        // generous `max_records` can NEVER over-deliver past the window — the same guard the per-record
        // path uses. The window auto-tunes from 64 toward the negotiated ceiling as this consumer keeps
        // up (so a batched/streaming consumer is not pinned at 64/RTT, the #464/#532 floor), bounded by
        // the byte budget (the firm RAM bound the count grows UNDER).
        let window = self.credit_window(engine)?;
        let held = u32::try_from(self.leased.len()).unwrap_or(u32::MAX);
        let remaining = window.saturating_sub(held);
        // The requested record cap, clamped to the per-consumer remaining credit (the window binds
        // before the engine ever leases an offset this connection cannot deliver).
        let want = req.max_records.min(remaining);
        // COUNT-BOUND keep-up signal: the consumer asked for at least the whole remaining window, so the
        // window (not `max_records`) is what capped it — the auto-tune grows once it actually drains.
        let window_was_binding = req.max_records >= remaining && remaining > 0;
        // EGRESS AIMD (#69, #402), identical to `handle_flow`: keep the effective egress credit within
        // the negotiated ceiling, and count a real would-block (the consumer wants more than the limiter
        // grants while already holding near a grant's worth un-acked) as a falling-behind signal.
        let ceiling = self.credit_ceiling(engine)?;
        let aimd_grant = engine.with(move |e| e.egress_grant_within(ceiling))?;
        let credits = want.min(aimd_grant);
        if aimd_grant < want && held >= aimd_grant {
            engine.with(crate::engine::Engine::egress_falling_behind)?;
        }
        // The per-consumer BYTE budget (#275): `0` is unlimited. The fetch also carries its OWN
        // `max_bytes` cap; the effective byte ceiling is the MIN of the two (each treated as unlimited
        // when `0`). The floor-of-one is preserved: a connection holding nothing in-flight always gets at
        // least one record even if it alone exceeds the budget, so a single over-budget record never
        // wedges the consumer — exactly the per-record semantics.
        let ceiling_bytes = self.credit_ceiling_bytes(engine)?;
        let byte_cap = min_budget(ceiling_bytes, req.max_bytes);
        // The deadline (#489): `expires_ms == 0` means no deadline. Read the monotonic clock ONCE at the
        // start; a `no_wait` fetch ignores it entirely (a single immediate pass). The engine poll never
        // blocks, so the deadline only bounds the WORK of a large drain, never which records are
        // delivered (no record appears mid-call to be missed). `started` is `None` when there is no
        // deadline to check, so the common path reads the clock zero extra times. `deadline` is `None`
        // when there is no deadline to check (no_wait or a zero budget).
        let deadline = if req.no_wait || req.expires_ms == 0 {
            None
        } else {
            let now = engine.with(|e| e.now_monotonic())?;
            // ms -> ns, saturating so a huge `expires_ms` cannot overflow into a too-early deadline.
            let budget_nanos = req.expires_ms.saturating_mul(1_000_000);
            Some(now.saturating_add(budget_nanos))
        };
        let mut delivered = 0u32;
        // One reusable scratch buffer for this batch's per-record frame bodies (#826): cleared and
        // reused each iteration instead of allocating a fresh `Vec` per delivered record/advisory.
        let mut frame_body = Vec::with_capacity(DELIVER_FRAME_SCRATCH_CAP);
        // Event-driven long-poll (push delivery), PER-STREAM (#1100 L2): the batch twin of the
        // `handle_flow` wrap. This batch-fetch path polls the DEFAULT/root stream (`poll_now_in_member`),
        // so it grabs the default stream's cell (`""`) — the cell it snapshots and waits on must match
        // the stream it polls, so a default commit wakes it and a named-stream commit does not disturb
        // it. Snapshot the cell's generation BEFORE the drain, and if the drain drew NOTHING re-run it
        // EXACTLY ONCE after waking on a commit (or the budget elapsing). A `no_wait` fetch (#489) is
        // EXEMPT: it is contractually a single immediate pass, so the wait is skipped and it returns as
        // today.
        let longpoll_cell = engine.commit_notify().map(|n| n.cell(""));
        let longpoll_snapshot = longpoll_cell.as_ref().map(|c| c.seq());
        for longpoll_attempt in 0..2u8 {
            for _ in 0..credits {
                // The deadline binds (#489): once the monotonic clock has reached it, end the batch with
                // whatever was gathered. Skipped for a no-wait / no-deadline fetch (`deadline` is `None`).
                if let Some(deadline) = deadline {
                    if engine.with(|e| e.now_monotonic())? >= deadline {
                        break;
                    }
                }
                // The byte cap binds (#275/#489): stop once delivering would exceed the cap, unless this
                // connection holds nothing in-flight AND this batch has delivered nothing (the floor-of-one).
                // A cap of 0 is unlimited, so it never binds. Mirrors the per-record byte-budget check, with
                // the in-flight total taken as the connection's standing in-flight bytes (the budget is
                // per-connection, so a fetch's own running total is already included once it leases).
                if byte_cap != 0
                    && !(self.leased.is_empty() && delivered == 0)
                    && self.in_flight_bytes() >= byte_cap
                {
                    break;
                }
                // Member-aware poll (#64): IDENTICAL to the per-record Flow path — one poll = one actor
                // round-trip, routing by the connection's member for a key_shared group and behaving as a
                // plain competing poll otherwise. This is THE shared primitive that makes a batch fetch
                // deliver the same records, in the same order, leased the same way, as N per-record polls.
                let group = self.subscription.clone();
                let member = self.member_id;
                match engine.with(move |e| e.poll_now_in_member(&group, member))? {
                    Ok(Poll::Message(d)) => {
                        // Compressed-delivery gate (#1066), IDENTICAL to `handle_flow`: a non-capable
                        // consumer gets a stored-COMPRESSED record decompressed (COMPRESSED bit cleared);
                        // a capable consumer and every uncompressed record pass through verbatim. `None`
                        // stops the batch rather than ship a byte the consumer cannot decode.
                        let Some((wire_flags, wire_payload)) =
                            self.deliver_encoding(d.record.flags.bits(), &d.record.payload)
                        else {
                            break;
                        };
                        let msg = DeliverBody {
                            offset: d.offset.get(),
                            generation: d.token.generation,
                            flags: wire_flags,
                            timestamp_ms: d.record.timestamp_ms,
                            key: &d.record.key,
                            headers: &d.record.headers,
                            payload: wire_payload.as_ref(),
                        };
                        frame_body.clear();
                        if encode_deliver(&msg, &mut frame_body).is_err() {
                            break;
                        }
                        reply(out, FrameType::Deliver, &frame_body);
                        // Lease ownership and byte accounting are IDENTICAL to `handle_flow`: only this
                        // session can later act on the lease (#175), and the byte size feeds the byte budget
                        // (#275). At-least-once holds because the record stays leased until acked.
                        let bytes = lease_bytes(&d.record);
                        self.leased.insert(
                            d.offset.get(),
                            Lease {
                                generation: d.token.generation,
                                bytes,
                            },
                        );
                        delivered += 1;
                    }
                    // A parked (poison) message: the same in-band dead-letter advisory as `handle_flow`. It
                    // consumes a credit slot (it ran a poll) but does not count toward `delivered`.
                    Ok(Poll::Parked { offset, .. }) => {
                        frame_body.clear();
                        encode_dead_letter(
                            &DeadLetterBody {
                                offset: offset.get(),
                                reason: DEAD_LETTER_MAX_DELIVER,
                            },
                            &mut frame_body,
                        );
                        reply(out, FrameType::DeadLetter, &frame_body);
                    }
                    // A below-earliest truncation: identical handling to `handle_flow` — drop the now-meaningless
                    // leases below the reset and emit the in-band advisory (GapMarker or Truncated per the
                    // negotiated capability), then keep draining.
                    Ok(Poll::Truncated {
                        earliest_retained,
                        skipped,
                    }) => {
                        self.leased
                            .retain(|&offset, _| offset >= earliest_retained.get());
                        self.emit_truncation(
                            out,
                            &mut frame_body,
                            earliest_retained.get(),
                            skipped,
                        );
                    }
                    // A key-compaction hole: identical to `handle_flow` — a gap-marker-capable consumer gets
                    // the COMPACTED marker, a non-capable one silently advances. Keep draining.
                    Ok(Poll::Compacted { from, to }) => {
                        if self.gap_marker_enabled {
                            Self::emit_compaction(out, &mut frame_body, from.get(), to.get());
                        }
                    }
                    // Nothing more deliverable right now: end the batch early (the no_wait / ready-now case).
                    Ok(Poll::Idle) => break,
                    Err(e) if e.is_fatal() => {
                        reply_err(out, "fatal storage error");
                        return Err(SessionError::EngineFatal(e));
                    }
                    Err(_) => {
                        // The Err is this batch's terminator; do NOT also send a FlowEnd (that would desync
                        // the client, which expects exactly one terminator per fetch), matching `handle_flow`.
                        reply_err(out, "fetch failed");
                        return Ok(());
                    }
                }
            }
            // Long-poll decision (push delivery), the `handle_flow` twin plus the `no_wait` exemption: an
            // empty FIRST drain on a waiting fetch with a configured budget + seam blocks until a commit
            // advances the frontier (or the budget elapses) and repolls ONCE; any other outcome (delivered,
            // second attempt, zero budget, no seam, or `no_wait`) falls through to the unchanged tail.
            if longpoll_attempt == 0
                && delivered == 0
                && self.consume_longpoll_ms > 0
                && !req.no_wait
            {
                if let (Some(cell), Some(snapshot)) = (&longpoll_cell, longpoll_snapshot) {
                    cell.wait_for_change(
                        snapshot,
                        std::time::Duration::from_millis(self.consume_longpoll_ms),
                        // Spin-before-park (#1100) on the no-pre-ack-fsync tiers only — the produce
                        // path's spin discriminant, so a real-fsync broker never burns a core here.
                        engine.consume_wait_spin(),
                    );
                    continue;
                }
            }
            break;
        }
        // Drop ownership of any offset now committed, keeping `leased` bounded — identical to `handle_flow`.
        let group = self.subscription.clone();
        let committed = engine.with(move |e| e.committed_offset_in(&group).get())?;
        self.leased.retain(|&offset, _| offset >= committed);
        // CREDIT AUTO-TUNE keep-up (#552), identical to `handle_flow`: the consumer was window-bound and
        // drained the full grant, so grow the window toward the ceiling. A deadline-cut batch leaves
        // `delivered < credits`, so it correctly does NOT register as keep-up.
        if window_was_binding && delivered == credits && credits > 0 {
            self.credit_keep_up();
        }
        // The batch terminates with the SAME FlowEnd the Flow path uses (its body the delivered count),
        // so the response is byte-for-byte a Flow response past the request frame.
        reply(out, FrameType::FlowEnd, &delivered.to_le_bytes());
        Ok(())
    }

    /// Handles a Tier-S STREAMING fetch (the tag-24 `StreamFetch` frame, #544 / M1-I7): the
    /// consumer-managed-offset consume mode. The body carries the consumer's OWN `start_offset` plus
    /// the batch caps; the broker serves a CONTIGUOUS run of records `[start_offset, ...)` off the
    /// durable, flushed prefix with NO lease grant and NO per-record cursor write — exactly the
    /// per-record cost the Tier-W `Fetch`/`Flow` path pays and Tier-S removes. The records ride the
    /// SAME `Deliver` frames the Tier-W path uses, terminated by one `FlowEnd` carrying the delivered
    /// count, so the response is byte-for-byte a Flow/Fetch response past the request frame — but
    /// `self.leased` is NEVER touched (there is no lease to track; the consumer acks by offset via the
    /// periodic `StreamCommit`).
    ///
    /// At-least-once holds BY CONSTRUCTION: the consumer drives the offset, so a crash/reconnect simply
    /// re-fetches from its last committed offset and the uncommitted span redelivers. The engine
    /// rejects a streaming fetch on a non-streaming group (the group must be declared streaming via
    /// `set_streaming_in`), which surfaces here as a recoverable `Err`. The `Deliver` frame's
    /// `generation` field is sent as `0` because there is no lease/fence on this path; a streaming
    /// consumer commits by offset, not by fencing token.
    #[allow(clippy::too_many_lines)]
    fn handle_stream_fetch<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(req) = decode_stream_fetch(body) else {
            reply_err(out, "malformed stream-fetch body");
            return Ok(());
        };
        // Bound the batch by the negotiated per-consumer AUTO-TUNED credit WINDOW and byte budget,
        // exactly as the Tier-W Fetch does (#292/#275/#552), so a generous max_records/max_bytes never
        // lets one fetch run away. Tier-S holds no leases, so the window is the standing PER-FETCH cap
        // (a streaming consumer's "in-flight" is whatever it has read-but-not-committed, which it tracks
        // itself) — but it is ALSO the loopback floor: with a fixed 64-record per-fetch cap, a fast/
        // loopback streaming consumer is pinned at 64/RTT (the #464/#532 floor). The window AUTO-TUNES:
        // a streaming consumer that keeps pulling full window-bound batches grows it toward the ceiling,
        // filling the pipe. The byte budget (`max_bytes` below) stays the firm bound on bytes-per-fetch.
        let window = self.credit_window(engine)?;
        let ceiling_bytes = self.credit_ceiling_bytes(engine)?;
        // The number of records to serve: the client's request clamped to the per-consumer credit
        // window. A request of 0 (or a 0 window) serves nothing and replies an empty batch.
        let want = req.max_records.min(window) as usize;
        // COUNT-BOUND keep-up: the consumer asked for at least the whole window, so the window (not
        // `max_records`) capped this fetch. If it then returns a FULL window's worth, the consumer is
        // keeping up and could pull more per RTT, so the auto-tune grows toward the ceiling.
        let window_was_binding = req.max_records >= window && window > 0;
        // The byte cap: the smaller of the negotiated per-consumer byte budget and the client's
        // requested max_bytes (each `0` meaning unbounded), passed to the engine read as the contiguous
        // read's byte bound. `None` means unbounded (only the record count binds).
        let max_bytes = match min_budget(ceiling_bytes, req.max_bytes) {
            0 => None,
            cap => Some(usize::try_from(cap).unwrap_or(usize::MAX)),
        };
        let start = Offset::new(req.start_offset);
        let group = self.subscription.clone();
        let member = self.member_id;
        // CLUSTER FOLLOWER-READ over the wire (#735, half B): if this node FOLLOWS the partition, serve the
        // Tier-S streaming fetch from its OWN follower read plane via the #723 read-consistency tiers —
        // fail-closed by the SAFE committed watermark `min(own_flushed, known_committed_hw)`, so a follower
        // NEVER serves a record past the committed bar (CRAQ committed reads off a replica). This is the
        // lease-FREE, cursor-FREE Tier-S contract, which is exactly the stateless follower-read shape (the
        // follower serves via the read plane and never writes — single-writer preserved). SINGLE-NODE /
        // no-cluster is BYTE-IDENTICAL: `cluster_follower_consume` returns `None` via a cheap default (no
        // gate), so this branch is skipped and the normal (leader/local-engine) Tier-S path runs unchanged.
        // A `Some` outcome means this node follows the partition: serve from the follower run (or, for a
        // latest/dirty read above the safe bar, reply an empty batch — never a speculative unconfirmed
        // serve; the dirty-tier leader confirm over the wire is the flagged follow-up).
        if let Some(outcome) = engine.cluster_follower_consume(
            crate::cluster::client_ack::DEFAULT_PARTITION,
            ReadTier::FollowerCommitted,
            start,
            want,
            max_bytes,
        ) {
            let delivered =
                Self::serve_follower_read_outcome(outcome, self.compressed_delivery_enabled, out);
            // Terminate with the SAME FlowEnd a leader Tier-S batch uses, so the client frames a
            // follower-read response exactly like any other streaming batch. No keep-up auto-tune on the
            // follower path (the credit window is the leader engine's concern); a follower-read just serves
            // its committed prefix.
            reply(out, FrameType::FlowEnd, &delivered.to_le_bytes());
            return Ok(());
        }
        // A consumer that advertised the DeliverBatch capability (#541) takes the RAW-FRAMED batch path:
        // a contiguous run ships as ONE `DeliverBatch` (the on-disk frame bytes verbatim, sendfile-ready
        // for #658) instead of N per-record `Deliver` frames, with no broker re-encode of the sealed run.
        // A consumer that did NOT advertise it takes the byte-for-byte-unchanged per-record path below.
        // Serve the batch (raw-framed if the consumer advertised DeliverBatch, else per-record), getting
        // back how many records were delivered (`None` = a recoverable reject already replied as an Err,
        // which is the response terminator, so there is no keep-up and no FlowEnd to add).
        let capable = self.compressed_delivery_enabled;
        let delivered = if self.deliver_batch_enabled {
            // The RAW DeliverBatch path ships the on-disk frame bytes VERBATIM (including any stored
            // COMPRESSED records), which is sound WITHOUT a compressed-delivery gate: decoding a raw
            // batch means decoding the on-disk record layout, so a DeliverBatch-capable consumer is
            // compression-capable by construction. The ACTIVE-tail per-record remainder is still gated
            // via `capable` inside the fn. (#1066)
            Self::serve_stream_fetch_batch(
                engine, &group, member, start, want, max_bytes, capable, out,
            )?
        } else {
            Self::serve_stream_fetch_per_record(
                engine, &group, member, start, want, max_bytes, capable, out,
            )?
        };
        let Some(delivered) = delivered else {
            // A recoverable engine reject already wrote its Err terminator; nothing more to send.
            return Ok(());
        };
        // CREDIT AUTO-TUNE keep-up (#552) on the lease-FREE Tier-S path: the consumer was window-bound
        // and the broker returned a FULL window's worth of records, so the consumer can pull more per
        // RTT — grow the window toward the ceiling. This is THE removal of the 64/RTT loopback floor for
        // the streaming default: each successive full fetch grows the per-fetch window, so a fast
        // consumer's steady-state per-fetch size climbs from 64 toward the ceiling. A short batch (the
        // log ran dry) leaves `delivered < window`, so a caught-up consumer does not over-grow.
        if window_was_binding && u64::from(delivered) >= u64::from(window) {
            self.credit_keep_up();
        }
        // Terminate with the SAME FlowEnd the Tier-W batch uses (its body the delivered count), so a
        // client frames the streaming batch exactly like a Fetch batch.
        reply(out, FrameType::FlowEnd, &delivered.to_le_bytes());
        Ok(())
    }

    /// Chooses the WIRE encoding of a stored record's `(flags, payload)` for delivery to THIS consumer,
    /// honoring the negotiated compressed-delivery capability (#1066). The instance method reads this
    /// connection's `compressed_delivery_enabled`; see [`Session::deliver_encoding_for`] for the shared
    /// logic (the lease-free Tier-S / follower-read serves are associated fns, so they pass the flag in).
    fn deliver_encoding<'p>(&self, flags: u8, payload: &'p [u8]) -> Option<(u8, Cow<'p, [u8]>)> {
        Self::deliver_encoding_for(self.compressed_delivery_enabled, flags, payload)
    }

    /// The shared compressed-delivery gate (#1066): given whether the consumer advertised it can decode
    /// a compression-codec-encoded delivery, returns the `(wire_flags, wire_payload)` to put on the
    /// `Deliver` frame, or `None` when the record cannot be safely delivered (never ship a bad byte).
    ///
    /// - A CAPABLE consumer, or an UNCOMPRESSED record, is the PASSTHROUGH: the stored flags and a
    ///   borrowed payload go on the wire verbatim — zero copy, zero codec CPU, byte-for-byte today's
    ///   behavior (the common case, and every record on a `--compression none` broker).
    /// - A NON-capable consumer receiving a stored-COMPRESSED record is the #1066 FIX: the payload is
    ///   DECOMPRESSED here and the `COMPRESSED` bit is cleared, so the consumer receives the plain
    ///   produced payload it can actually read, never the descriptor bytes it would mis-decode. The
    ///   default build is dict-free lz4, so [`NoDictionaries`] resolves every default-codec record; a
    ///   decode failure (e.g. a zstd-with-dictionary record on an opt-in build, whose dictionary this
    ///   dict-free resolver cannot supply) is FAIL-LOUD — `None`, so the caller stops the batch rather
    ///   than deliver a byte the consumer cannot decode. It is NEVER silent corruption.
    fn deliver_encoding_for(
        capable: bool,
        flags: u8,
        payload: &[u8],
    ) -> Option<(u8, Cow<'_, [u8]>)> {
        let rf = RecordFlags::from_bits(flags);
        if capable || !rf.contains(RecordFlags::COMPRESSED) {
            return Some((flags, Cow::Borrowed(payload)));
        }
        let plain =
            decompress_payload(rf, payload, &NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES)
                .ok()?;
        Some((flags & !RecordFlags::COMPRESSED.bits(), Cow::Owned(plain)))
    }

    /// Emit a CLUSTER FOLLOWER-READ outcome (#735, half B) as per-record `Deliver` frames, returning the
    /// number of records written. The follower serves the committed prefix from its OWN read plane as a
    /// zero-copy [`RawSealedRead`] run; this decodes each CRC-framed record (re-validating the header AND
    /// body CRC via [`ironbus_core::codec::decode`] — fail-closed, a torn/corrupt frame stops the run
    /// rather than shipping a bad byte) into the SAME `Deliver` wire shape a leader Tier-S serve uses.
    /// Generation `0` (lease-free, like every Tier-S delivery): a follower-read consumer commits by offset,
    /// never by a fencing token. A [`FollowerReadOutcome::ConfirmWithLeader`] (a latest/dirty read above
    /// the safe watermark) serves NOTHING here — never a speculative unconfirmed serve; the over-the-wire
    /// dirty-tier leader confirm is the flagged follow-up.
    fn serve_follower_read_outcome(
        outcome: FollowerReadOutcome,
        capable: bool,
        out: &mut Vec<u8>,
    ) -> u32 {
        let run = match outcome {
            FollowerReadOutcome::Served(read) => read.run,
            // A latest/dirty read above the safe watermark: do NOT speculatively serve unconfirmed bytes.
            // Serve nothing (an empty batch); the client re-reads / the wire dirty-tier confirm is the
            // flagged follow-up.
            FollowerReadOutcome::ConfirmWithLeader { .. } => return 0,
        };
        let mut delivered = 0u32;
        let mut cursor = 0usize;
        let mut offset = run.first_offset.get();
        // One reusable scratch buffer for the run's per-record frame bodies (#826): cleared and
        // reused each iteration instead of allocating a fresh `Vec` per delivered record.
        let mut frame_body = Vec::with_capacity(DELIVER_FRAME_SCRATCH_CAP);
        while cursor < run.bytes.len() {
            // Re-validate and decode each stored frame (header + body CRC). A torn/corrupt frame is
            // fail-closed: stop the run here rather than ship a bad record (never a blind-trusted byte).
            let Ok((view, consumed)) = ironbus_core::codec::decode(&run.bytes[cursor..]) else {
                break;
            };
            // Compressed-delivery gate (#1066): a non-capable consumer gets a stored-COMPRESSED record
            // decompressed (COMPRESSED bit cleared); a capable consumer and every uncompressed record
            // pass through verbatim. `None` stops the run rather than ship an undecodable byte.
            let Some((wire_flags, wire_payload)) =
                Self::deliver_encoding_for(capable, view.flags.bits(), view.payload)
            else {
                break;
            };
            let msg = DeliverBody {
                offset,
                // Lease-free Tier-S follower-read: generation 0, commit-by-offset (no fencing token).
                generation: 0,
                flags: wire_flags,
                timestamp_ms: view.timestamp_ms,
                key: view.key,
                headers: view.headers,
                payload: wire_payload.as_ref(),
            };
            frame_body.clear();
            if encode_deliver(&msg, &mut frame_body).is_err() {
                break;
            }
            reply(out, FrameType::Deliver, &frame_body);
            delivered += 1;
            offset += 1;
            cursor += consumed;
        }
        delivered
    }

    /// The per-record half of [`Session::handle_stream_fetch`] (the consumer did NOT advertise
    /// `DeliverBatch`): serves the contiguous run as N per-record `Deliver` frames. Returns the number
    /// of records delivered (`Some(n)`), or `None` when a recoverable engine reject was surfaced as an
    /// `Err` terminator (so the caller adds no `FlowEnd`). Does NOT write the `FlowEnd`; the caller
    /// does, after the shared #552 keep-up check, so both batch halves terminate identically.
    #[allow(clippy::too_many_arguments)]
    fn serve_stream_fetch_per_record<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        engine: &E,
        group: &GroupName,
        member: MemberId,
        start: Offset,
        want: usize,
        max_bytes: Option<usize>,
        capable: bool,
        out: &mut Vec<u8>,
    ) -> Result<Option<u32>, SessionError> {
        let group = group.clone();
        // ONE actor round-trip serves the whole contiguous batch — the heart of the Tier-S win versus
        // the N per-record round-trips the Tier-W poll loop makes. The engine reads off the shared
        // durable read path, claims no lease, and writes no cursor.
        match engine.with(move |e| e.stream_fetch_in(&group, member, start, want, max_bytes))? {
            Ok(StreamBatch { records, .. }) => {
                let mut delivered = 0u32;
                // One reusable scratch buffer for this batch's per-record frame bodies (#826):
                // cleared and reused each iteration instead of a fresh `Vec` per delivered record.
                let mut frame_body = Vec::with_capacity(DELIVER_FRAME_SCRATCH_CAP);
                for record in &records {
                    // Compressed-delivery gate (#1066): a non-capable consumer gets a stored-COMPRESSED
                    // record decompressed (COMPRESSED bit cleared); a capable consumer and every
                    // uncompressed record pass through verbatim. `None` stops the batch here.
                    let Some((wire_flags, wire_payload)) =
                        Self::deliver_encoding_for(capable, record.flags.bits(), &record.payload)
                    else {
                        break;
                    };
                    let msg = DeliverBody {
                        offset: record.offset.get(),
                        // No lease, no fence: a streaming delivery carries generation 0. The consumer
                        // commits by offset (StreamCommit), never by a per-record fencing token.
                        generation: 0,
                        flags: wire_flags,
                        timestamp_ms: record.timestamp_ms,
                        key: &record.key,
                        headers: &record.headers,
                        payload: wire_payload.as_ref(),
                    };
                    frame_body.clear();
                    if encode_deliver(&msg, &mut frame_body).is_err() {
                        break;
                    }
                    reply(out, FrameType::Deliver, &frame_body);
                    // CRITICAL: NO `self.leased.insert` here. Tier-S grants no lease, so the consumer's
                    // in-flight set is its own concern. This is what removes the per-record bookkeeping.
                    delivered += 1;
                }
                Ok(Some(delivered))
            }
            // A fatal engine error wedges every future op: end the session rather than masquerade it as
            // a transient rejection (matching the Fetch/cumulative-ack paths).
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            // The wrong-mode reject (a non-streaming group) and an out-of-range start are client-visible,
            // recoverable rejections: surface the engine's typed reason and keep the connection open. Do
            // NOT also send a FlowEnd (the Err is the terminator), matching the Fetch error path.
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(None)
            }
        }
    }

    /// Serves a Tier-S streaming fetch as a RAW-FRAMED `DeliverBatch` (#541, M1-I5), the batch-capable
    /// half of [`Session::handle_stream_fetch`]. The contiguous SEALED prefix of the run ships as ONE
    /// `DeliverBatch` frame whose body is the records' on-disk frame bytes VERBATIM (never re-encoded, so
    /// #658's disk `sendfile(2)` can splice them); any ACTIVE-tail remainder follows as ordinary
    /// per-record `Deliver` frames, so the consumer always receives one continuous contiguous run.
    ///
    /// Returns the TOTAL records delivered (`Some(n)`), or `None` when a recoverable engine reject was
    /// surfaced as an `Err` terminator. It does NOT write the `FlowEnd`; the caller writes it after the
    /// shared #552 keep-up check, so the batch and per-record halves terminate identically (one `FlowEnd`
    /// carrying the total delivered count), and the client frames the response the same way either way.
    ///
    /// CRC integrity end-to-end: the broker copies the stored bytes UNTOUCHED into the batch body, so
    /// each record's header/body CRC ships verbatim for the client to verify exactly as it does a
    /// per-record `Deliver`. NO lease, NO generation fence, NO cursor write — the same lease-free Tier-S
    /// contract; the batch header's `generation` is `0`, matching the per-record streaming delivery.
    #[allow(clippy::too_many_arguments)]
    fn serve_stream_fetch_batch<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        engine: &E,
        group: &GroupName,
        member: MemberId,
        start: Offset,
        want: usize,
        max_bytes: Option<usize>,
        capable: bool,
        out: &mut Vec<u8>,
    ) -> Result<Option<u32>, SessionError> {
        let group = group.clone();
        match engine.with(move |e| e.stream_fetch_raw_in(&group, member, start, want, max_bytes))? {
            Ok(StreamRawBatch { raw, tail, .. }) => {
                let mut delivered: u32 = 0;
                // The contiguous SEALED prefix as ONE DeliverBatch: the on-disk frame bytes verbatim. A
                // zero-record run is NOT framed (no empty batch on the wire); the per-record tail and the
                // FlowEnd still terminate the response.
                if raw.record_count > 0 {
                    let header = DeliverBatchHeader {
                        first_offset: raw.first_offset.get(),
                        // No lease, no fence: a streaming batch carries generation 0, exactly as the
                        // per-record streaming `Deliver`. The consumer commits by offset (StreamCommit).
                        generation: 0,
                        // The record_count is bounded by `want` (a u32 on the wire), so this conversion
                        // never truncates a real batch; saturate defensively rather than wrap.
                        record_count: u32::try_from(raw.record_count).unwrap_or(u32::MAX),
                    };
                    // Frame the batch DIRECTLY into `out` in one pass (#812): the zero-copy `raw.bytes`
                    // segment slice is copied exactly once, dropping the redundant full-batch memcpy into a
                    // temporary `frame_body` Vec and that per-batch allocation. Byte-identical to the old
                    // `encode_deliver_batch` + `reply` path; matches `reply`'s cap handling (the cap is
                    // checked before any write, so `out` is unchanged on the unreachable over-cap case).
                    let result = encode_deliver_batch_frame(&header, &raw.bytes, out);
                    debug_assert!(result.is_ok(), "DeliverBatch frame exceeded the frame cap");
                    delivered = delivered.saturating_add(header.record_count);
                }
                // The ACTIVE-tail remainder (which the raw read does not serve) as ordinary per-record
                // `Deliver` frames, immediately following the batch — so the run stays contiguous.
                // One reusable scratch buffer for the tail's per-record frame bodies (#826): cleared
                // and reused each iteration instead of a fresh `Vec` per delivered record.
                let mut frame_body = Vec::with_capacity(DELIVER_FRAME_SCRATCH_CAP);
                for record in &tail {
                    // Compressed-delivery gate (#1066) on the ACTIVE-tail per-record remainder: a
                    // non-capable consumer gets a stored-COMPRESSED record decompressed (COMPRESSED bit
                    // cleared); a capable consumer and every uncompressed record pass through verbatim.
                    // (The raw SEALED prefix above ships verbatim — sound, see the call site.)
                    let Some((wire_flags, wire_payload)) =
                        Self::deliver_encoding_for(capable, record.flags.bits(), &record.payload)
                    else {
                        break;
                    };
                    let msg = DeliverBody {
                        offset: record.offset.get(),
                        generation: 0,
                        flags: wire_flags,
                        timestamp_ms: record.timestamp_ms,
                        key: &record.key,
                        headers: &record.headers,
                        payload: wire_payload.as_ref(),
                    };
                    frame_body.clear();
                    if encode_deliver(&msg, &mut frame_body).is_err() {
                        break;
                    }
                    reply(out, FrameType::Deliver, &frame_body);
                    delivered = delivered.saturating_add(1);
                }
                Ok(Some(delivered))
            }
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(None)
            }
        }
    }

    /// Handles a Tier-S periodic CUMULATIVE COMMIT (the tag-25 `StreamCommit` frame, #544 / M1-I7):
    /// advances the named streaming group's committed cursor up to the body's exclusive `up_to` offset,
    /// the consumer's durability checkpoint. The body carries its own group name (like `CumulativeAck`),
    /// so a streaming consumer drives it on any group it owns. The engine enforces the contract: only a
    /// group MARKED streaming accepts the verb (a Tier-W or broadcast group is rejected with the
    /// work-group error), `up_to` is validated against the durable head and the earliest-retained
    /// offset, and a re-commit is an idempotent no-op success. Because Tier-S holds no leases, the
    /// commit only advances the watermark (it frees retention and stops any redeliver below it); there
    /// is no `self.leased` to prune. A success replies the generic body-less `Ok` (matching
    /// `CumulativeAck`); a rejection replies a typed `Err`; a fatal engine error ends the session.
    fn handle_stream_commit<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(commit) = decode_stream_commit(body) else {
            reply_err(out, "malformed stream-commit body");
            return Ok(());
        };
        let Ok(group) = core::str::from_utf8(commit.group) else {
            reply_err(out, "stream-commit group name must be valid UTF-8");
            return Ok(());
        };
        let group = group.to_string();
        let up_to = Offset::new(commit.up_to);
        match engine.with(move |e| e.stream_commit_in(&group, up_to))? {
            // A committed (or idempotent no-op) streaming commit: the generic body-less success. There
            // is no per-connection lease to release (Tier-S grants none), so unlike the broadcast
            // cumulative-ack path there is no `self.leased` bookkeeping here.
            Ok(()) => {
                reply(out, FrameType::Ok, &[]);
                Ok(())
            }
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            // The wrong-mode reject and the out-of-range reject are client-visible, recoverable
            // rejections: surface the engine's typed reason and keep the connection open.
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }

    /// Emits the in-band advisory for a `Poll::Truncated` skip: a consumer that negotiated the
    /// gap-marker capability (#346) gets the richer, consumer-visible `GapMarker` (tag 21) for the
    /// skipped span `[from, to)` where `to == earliest_retained` (delivery resumes at the oldest
    /// record still present) and `from == earliest_retained - skipped` (where the cursor was), reason
    /// TRIMMED (the disk-full drop-oldest reap) with `bytes_skipped == 0` (a force-reap trim is
    /// byte-untracked: the span is reported by its record count `to - from`, matching the recovery-side
    /// `loss-report.v1` convention). A consumer WITHOUT the capability gets the legacy `Truncated`
    /// (tag 18) instead, so the two NEVER double-signal and an old consumer is never sent the new tag.
    fn emit_truncation(
        &self,
        out: &mut Vec<u8>,
        frame_body: &mut Vec<u8>,
        earliest_retained: u64,
        skipped: u64,
    ) {
        // `frame_body` is the caller's reusable per-batch scratch (#826): clear (retaining capacity)
        // before encoding this advisory, exactly as the per-record delivery path does.
        frame_body.clear();
        if self.gap_marker_enabled {
            let to = earliest_retained;
            let from = to.saturating_sub(skipped);
            encode_gap_marker(
                &GapMarkerBody {
                    from,
                    to,
                    bytes_skipped: 0,
                    reason: gap_reason::TRIMMED,
                },
                frame_body,
            );
            reply(out, FrameType::GapMarker, frame_body);
        } else {
            encode_truncated(
                &TruncatedBody {
                    earliest_retained,
                    skipped,
                },
                frame_body,
            );
            reply(out, FrameType::Truncated, frame_body);
        }
    }

    /// Emits the consumer-visible `GapMarker` (tag 21) for a KEY-COMPACTION hole (#337, #411): the
    /// half-open span `[from, to)` was removed by compaction (a later record for the same key
    /// superseded those offsets), so they are PERMANENTLY ABSENT mid-stream while the surrounding
    /// segment is present. This is the COMPACTED twin of [`Session::emit_truncation`]'s TRIMMED case:
    /// same delivery path, same frame, only the `reason` differs (`COMPACTED` vs `TRIMMED`), so the
    /// distinct cause is correct on the wire. `bytes_skipped` is `0` (a compaction hole is reported by
    /// its record-count span `to - from`, not a byte total, matching the trim convention and the
    /// already-frozen `loss-report.v1` field). The caller only invokes this for a gap-marker-capable
    /// consumer; a non-capable consumer silently advances (a compacted hole is not a loss, so it gets
    /// NO frame and never the legacy `Truncated`), so the two never double-signal. The capability gate
    /// lives at the call site (the per-poll loop), so this carries no `&self` state.
    fn emit_compaction(out: &mut Vec<u8>, frame_body: &mut Vec<u8>, from: u64, to: u64) {
        // `frame_body` is the caller's reusable per-batch scratch (#826): clear (retaining capacity)
        // before encoding, matching the per-record delivery path.
        frame_body.clear();
        encode_gap_marker(
            &GapMarkerBody {
                from,
                to,
                bytes_skipped: 0,
                reason: gap_reason::COMPACTED,
            },
            frame_body,
        );
        reply(out, FrameType::GapMarker, frame_body);
    }

    fn handle_sub<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(group) = core::str::from_utf8(decode_sub(body).group) else {
            reply_err(out, "subscription name must be valid UTF-8");
            return Ok(());
        };
        // Register as an active subscriber of the NEW group FIRST (#288), so the BROADCAST
        // group-of-one cap is enforced BEFORE any of this connection's state is torn down. A
        // broadcast group already holding a different subscriber rejects here with
        // `BroadcastGroupBusy`; the SUB is refused and this connection keeps its CURRENT
        // subscription intact (it was never left), so a rejected second consumer cannot strand the
        // connection. The default group (`""`) and any plain competing / key_shared group accept
        // any number of subscribers, so this only ever rejects a second SUB to a broadcast group.
        // Registering before deregistering the old group is safe because the engine keys the
        // subscriber set per group and per member: a same-group re-SUB is idempotent, and a switch
        // briefly holds both registrations before the old one is dropped below.
        let new_group = group.to_string();
        let member = self.member_id;
        if !new_group.is_empty() {
            let sub = new_group.clone();
            match engine.with(move |e| e.subscribe_in(&sub, member))? {
                Ok(()) => {}
                // The broadcast group-of-one cap rejected a second subscriber: surface the typed
                // reason and leave this connection on its existing subscription (it was never left).
                // `subscribe_in` only ever returns this rejection (name/cap are still validated on
                // the first FLOW, as before), so SUB stays infallible for the name/cap checks.
                Err(e) => {
                    reply_err_coded(out, e.code().as_str(), &e.to_string());
                    return Ok(());
                }
            }
        }
        // The new group is accepted. Deregister the OLD subscription (if it was a different named
        // group) and leave its key_shared membership before switching, so its keys re-route and its
        // broadcast slot frees. Done AFTER the new registration succeeds so a rejected SUB never
        // tears down a working subscription.
        let old_group = self.subscription.clone();
        self.leave_current_key_shared(engine)?;
        if self.registered_subscription && *old_group != *new_group {
            engine.with(move |e| {
                e.unsubscribe_in(&old_group, member);
            })?;
        }
        // Switching subscriptions abandons this connection's in-flight leases in the
        // previous group (they redeliver there after the visibility timeout), so the new
        // subscription starts with no outstanding leases. The name's shape and the group
        // cap are validated by the engine on the first FLOW (#240), surfaced as an Err.
        self.subscription = GroupName::from(group);
        self.registered_subscription = !new_group.is_empty();
        // A plain `Sub` binds the DEFAULT stream (#588): clear any named-stream binding a prior
        // `SubTo` set, so this connection's Flow/Ack route to the default stream byte-for-byte. (An old
        // client never sends `SubTo`, so `self.stream` is already default for it; this only matters for
        // a streams-capable client switching from a named stream back to a plain default subscribe.)
        self.stream = GroupName::default();
        self.leased.clear();
        // If the new group is configured key_shared (#64), put it into that mode and join as a
        // member so this connection's keys route to it. A failure to enable the mode (an invalid
        // name or the group cap) is surfaced on the first FLOW as today, so SUB stays infallible
        // here: only join when the mode is actually active. The whole "is it key_shared, if so
        // enable + join" decision is one actor job, so SUB stays a single round-trip; it returns
        // whether this connection joined so the session can record it for leave-on-switch.
        let sub = self.subscription.clone();
        let joined = engine.with(move |e| {
            if e.is_configured_key_shared(&sub)
                && e.set_key_ordering_in(&sub, KeyOrdering::KeyShared).is_ok()
            {
                e.join_member_in(&sub, member);
                true
            } else {
                false
            }
        })?;
        self.joined_key_shared = joined;
        // Apply the connection's negotiated DEFAULT consume tier (#543, V2-M1) to the newly-subscribed
        // group, so a subscription that does not explicitly pick a tier consumes at the connection
        // default. This is ADDITIVE — it marks the group streaming ONLY when the connection default is
        // Tier-S, and NEVER clears the flag — so:
        //   - a connection with a Tier-W default (the back-compat case, an old client, or no negotiation)
        //     leaves the group's tier untouched, so it stays Tier-W exactly as before;
        //   - an EXPLICIT per-subscription Tier-S selection (#544 `set_streaming_in`) is never undone by a
        //     Tier-W-default connection, so the explicit selection always OVERRIDES the default;
        //   - a Tier-S default marks the group streaming, which an explicit selection (made out of band
        //     via #544) may already have done — the mark is idempotent.
        // The default tier is already gated by the streaming capability bit at Connect (a Tier-S default
        // is forced to Tier-W when the client did not advertise the capability), so a pre-streaming
        // client never reaches this branch and its groups stay Tier-W.
        if self.default_tier == ConsumeTier::Streaming {
            let sub = self.subscription.clone();
            // A failure here is surfaced exactly like the key_shared mode enable above: it is best-effort
            // at SUB time (the streaming fetch path re-checks the mode and rejects a non-streaming group),
            // so SUB stays infallible for the tier selection and a transient engine error does not strand
            // the subscription.
            engine.with(move |e| {
                let _ = e.set_streaming_in(&sub, true);
            })?;
        }
        reply(out, FrameType::Ok, &[]);
        Ok(())
    }

    /// Handles a `StreamDeclare` (#588, M2-I10): CREATE-OR-ENSURE a named stream by id, then reply a
    /// body-less `Ok`. Routes to the engine's [`Engine::declare_stream`] (which `declare`s the named
    /// stream in the [`StreamSet`], materializing its independent log + recovery; idempotent). GATED on
    /// the negotiated streams capability and fail-closed: a client that did not advertise
    /// `understands_streams` is refused; a malformed/over-long stream id is a typed `Err`; the EMPTY
    /// name (the default stream, always present) is rejected as a malformed name (the default stream is
    /// never declared this way). Never panics.
    fn handle_stream_declare<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        if !self.streams_enabled {
            reply_err(
                out,
                "stream addressing not negotiated (set understands_streams)",
            );
            return Ok(());
        }
        let Ok(decoded) = decode_stream_declare(body) else {
            reply_err(out, "malformed stream-declare body");
            return Ok(());
        };
        let Ok(stream) = core::str::from_utf8(decoded.stream_id) else {
            reply_err(out, "stream id must be valid UTF-8");
            return Ok(());
        };
        // The DEFAULT stream is always present and is NEVER declared via the named subtree (#588): an
        // empty id is a malformed name here, not a silent success, so a client cannot conflate the
        // default stream with a named one.
        if stream.is_empty() {
            reply_err(out, "cannot declare the default stream (empty id)");
            return Ok(());
        }
        let stream = stream.to_string();
        match engine.with(move |e| e.declare_stream(&stream))? {
            // Idempotent: a first declare (`true`) and a re-declare (`false`) both reply a body-less Ok.
            Ok(_) => reply(out, FrameType::Ok, &[]),
            // A malformed/over-long NAMED name fails closed with the engine's typed reason.
            Err(e) => reply_err_coded(out, e.code().as_str(), &e.to_string()),
        }
        Ok(())
    }

    /// Handles a `StreamInfo` query (#588, M2-I10): reply a `StreamInfo` RESPONSE frame carrying
    /// whether the named stream EXISTS and, if so, its durable head offset. The default stream `""`
    /// always reports `exists = true`. GATED on the negotiated streams capability; a malformed id is a
    /// typed `Err`. Never panics, never declares (a query is read-only).
    fn handle_stream_info<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        if !self.streams_enabled {
            reply_err(
                out,
                "stream addressing not negotiated (set understands_streams)",
            );
            return Ok(());
        }
        let Ok(decoded) = decode_stream_info(body) else {
            reply_err(out, "malformed stream-info body");
            return Ok(());
        };
        let Ok(stream) = core::str::from_utf8(decoded.stream_id) else {
            reply_err(out, "stream id must be valid UTF-8");
            return Ok(());
        };
        let stream = stream.to_string();
        // One round-trip reads both the existence bit and the durable head: the head is meaningful only
        // when the stream exists, and `stream_head` reports `0` for an unknown/malformed stream (which
        // the response folds with `exists = false`), so the two reads are consistent.
        let (exists, head) =
            engine.with(move |e| (e.stream_exists(&stream), e.stream_head(&stream).get()))?;
        let resp = StreamInfoResponseBody { exists, head };
        let mut resp_body = Vec::new();
        encode_stream_info_response(&resp, &mut resp_body);
        reply(out, FrameType::StreamInfo, &resp_body);
        Ok(())
    }

    /// Handles a `PubTo` (#588, M2-I10): publish to a NAMED stream by id. The stream-id prefix is
    /// stripped here and the verbatim `PubBody` tail is decoded with the UNCHANGED [`decode_pub`] codec,
    /// so the publish body is shared byte-for-byte with the default-stream `Pub`. An EMPTY stream id is
    /// exactly a default-stream publish and is routed to the existing [`Session::handle_pub`] path
    /// (byte-for-byte today's behavior, including the pipelined window). A NAMED stream's append is
    /// routed through the engine's id-routed [`Engine::produce_in_stream`] (which declares-on-first-
    /// produce and commits via the cross-stream group-commit tick), via one actor `with` job so the
    /// covering fsync is the engine's, not a parked window. GATED on the negotiated streams capability;
    /// fail-closed on a malformed prefix or pub body. Never panics.
    ///
    /// SCOPE (#588): this is EXPLICIT-stream-id addressing only. The Level-2 confirm registry, the
    /// dedup-id-cap pre-check, the CoDel/headroom shed taxonomy, and the pipelined window are the
    /// DEFAULT stream's; a named-stream publish here is at-least-once Level-1-equivalent (a `PubAck`
    /// after the named stream's covering fsync) and rejects an unsupported ack level. Per-stream
    /// dedup / ack-levels / Tier-S are the flagged follow-ups (#681 and the #676 scope notes).
    #[allow(clippy::too_many_lines)]
    fn handle_pub_to<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        if !self.streams_enabled {
            reply_err(
                out,
                "stream addressing not negotiated (set understands_streams)",
            );
            return Ok(());
        }
        let Ok(decoded) = decode_pub_to(body) else {
            reply_err(out, "malformed pub-to body");
            return Ok(());
        };
        // An EMPTY stream id is a default-stream publish: route the verbatim PubBody tail through the
        // EXISTING default-stream produce path, byte-for-byte (#588 back-compat — a `PubTo("")` is
        // indistinguishable from a plain `Pub` downstream).
        if decoded.stream_id.is_empty() {
            let mut parked = VecDeque::new();
            self.handle_pub(engine, decoded.pub_body, &mut parked, out)?;
            // Flush any Level-0 this one-off subject-routed publish batched before draining (no
            // cross-frame accumulation here), keeping the single total order.
            self.flush_level0(engine)?;
            return drain_parked(engine, self.member_id, &mut parked, out);
        }

        let Ok(stream) = core::str::from_utf8(decoded.stream_id) else {
            reply_err(out, "stream id must be valid UTF-8");
            return Ok(());
        };
        let Ok(msg) = decode_pub(decoded.pub_body) else {
            reply_err(out, "malformed pub body");
            return Ok(());
        };
        // A named-stream publish is at-least-once Level-1-equivalent this phase: the no-ack (Level-0)
        // and consumer-ack (Level-2) tiers are the default stream's, so a non-Level-1 ack level on a
        // PubTo is refused rather than silently downgraded (the producer must use the default stream for
        // those tiers, or wait for the per-stream ack-level follow-up).
        if !matches!(pub_ack_level(msg.flags), AckLevel::ServerAck) {
            reply_err(
                out,
                "named-stream publish supports only server-ack (level 1) this phase",
            );
            return Ok(());
        }
        // The dedup-id wire caps (#33), enforced at the boundary exactly as the default `handle_pub`
        // does, BEFORE the bytes cross into owned storage.
        if let Some(d) = msg.dedup.as_ref() {
            if d.producer_id.len() > MAX_PRODUCER_ID_LEN {
                reply_err(out, "producer_id too long");
                return Ok(());
            }
            if d.msg_id.len() > MAX_MSG_ID_LEN {
                reply_err(out, "msg_id too long");
                return Ok(());
            }
            // The idempotent SEQUENCE (V2-M8) requires a non-empty producer_id (the durable high-water
            // is keyed by it), same fail-closed gate as the default `handle_pub`.
            if d.seq.is_some() && d.producer_id.is_empty() {
                reply_err(out, "idempotent sequence requires a non-empty producer_id");
                return Ok(());
            }
        }
        // Compressed-descriptor SHAPE validation at the wire boundary (#438), the same shared gate as
        // the default path (`compressed_descriptor_rejection`): a stored compressed object must be
        // decodable by every reader, or a consumer burns max-deliver cycles on it.
        if let Some(reason) = compressed_descriptor_rejection(msg.flags, msg.payload) {
            reply_err(out, &reason);
            return Ok(());
        }
        // Build the OWNED append (the wire body borrows the connection buffer, which the closure
        // cannot hold), then route it to the NAMED stream via the engine's id-routed produce in ONE
        // actor job. `produce_in_stream` declares-on-first-produce and commits the named stream's log
        // with the cross-stream group-commit tick, so the `PubAck` below is ack-implies-durable for the
        // named stream (I2 per stream). The default stream's batched/pipelined produce path is entirely
        // untouched — this is a separate, additive route reached only for a non-empty stream id.
        let dedup = msg.dedup.map(|d| OwnedDedup {
            producer_id: Bytes::copy_from_slice(d.producer_id),
            epoch: d.epoch,
            msg_id: Bytes::copy_from_slice(d.msg_id),
            // The opt-in idempotent SEQUENCE (V2-M8) rides through to the engine's durable per-producer
            // high-water; `None` keeps the existing time-bounded `msg_id`-window dedup path.
            seq: d.seq,
        });
        let append = OwnedAppend {
            timestamp_ms: msg.timestamp_ms,
            flags: msg.flags & !PUB_WIRE_ONLY_FLAGS,
            key: Bytes::copy_from_slice(msg.key),
            headers: Bytes::copy_from_slice(msg.headers),
            payload: Bytes::copy_from_slice(msg.payload),
            // The named-stream produce routes through `produce_in_stream` (its own StreamSet log),
            // NOT the default-stream actor append path that consumes the offloaded checksum (#830), so
            // computing one here would be discarded work: leave it `None` and let that path checksum as
            // before.
            body_checksums: None,
            dedup,
            enqueue_monotonic_nanos: engine.now_monotonic_nanos(),
            fire_and_forget: false,
            // The produce ACK LEVEL (#571) from the wire PUB flags, for the per-ack-level produce
            // counters; this named-stream produce path counts it explicitly in the engine job below.
            ack_level: ironbus_proto::message::pub_ack_level(msg.flags),
        };
        let stream = stream.to_string();
        // Route the named-stream produce to its append SHARD (#811): hash the name (by ref) BEFORE the
        // job moves it, so no extra allocation. With one shard (today) this is always 0 and `with_on_shard`
        // is byte-for-byte `with`.
        let shard = crate::actor::shard_of(&stream, engine.shard_count());
        let outcome = engine.with_on_shard(shard, move |e| {
            let view = Append {
                timestamp_ms: append.timestamp_ms,
                flags: RecordFlags::from_bits(append.flags),
                key: &append.key,
                headers: &append.headers,
                payload: &append.payload,
            };
            let level = append.ack_level;
            let result = e.produce_in_stream(&stream, &view);
            // Per-ack-level PRODUCE throughput (#571) for the named-stream produce path (which does not
            // route through the actor drain that counts the default path): attribute the accepted record
            // to its level only on a successful append, so the per-level sum matches the fresh-append
            // count. Allocation-free under the same engine job.
            if result.is_ok() {
                e.record_produce_ack_level(level);
            }
            result
        })?;
        match outcome {
            Ok(offset) => {
                let ack = PubAckBody {
                    offset: offset.get(),
                };
                let mut ack_body = Vec::new();
                encode_pub_ack(&ack, &mut ack_body);
                reply(out, FrameType::PubAck, &ack_body);
                Ok(())
            }
            // A fatal storage error on the named stream ends the session, exactly like the default
            // produce path (a frozen writer / broken invariant is unrecoverable).
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            // A malformed name or a non-fatal storage error (e.g. a byte-cap shed) is a typed,
            // connection-preserving reject, never a panic.
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }

    /// Handles a `TxnPrepare` (#640, V2-M8): durably buffer a transactional HALF (prepared) message
    /// targeting a real stream, INVISIBLE to consumers, and ack. The half message survives a restart
    /// as `Prepared` until a `TxnCommit`/`TxnRollback` resolves it. The body carries the txn id + the
    /// target stream + the verbatim `PubBody` payload. Replies a body-less `Ok` on a durable prepare,
    /// or `Err` on a malformed body / over-long id / too-many-prepared. Routes through the single-writer
    /// engine via `engine.with`; never panics, fail-closed at the boundary.
    fn handle_txn_prepare<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(decoded) = decode_txn_prepare(body) else {
            reply_err(out, "malformed txn-prepare body");
            return Ok(());
        };
        // The txn-id wire cap is enforced by the decoder (cap-before-alloc); an empty id is refused
        // here (a half message needs a stable identity to commit/rollback against).
        if decoded.txn_id.is_empty() {
            reply_err(out, "txn_id must not be empty");
            return Ok(());
        }
        let Ok(stream) = core::str::from_utf8(decoded.stream_id) else {
            reply_err(out, "stream id must be valid UTF-8");
            return Ok(());
        };
        let Ok(msg) = decode_pub(decoded.pub_body) else {
            reply_err(out, "malformed pub body");
            return Ok(());
        };
        // Compressed-descriptor SHAPE validation at the wire boundary (#438/#877). This is the FOURTH
        // produce verb and previously skipped the gate the other three apply: a Publish-scoped producer
        // could stage and `TxnCommit` a poison compressed record (over-cap claim / unknown codec /
        // mismatched raw length) that every consumer group then burns max-deliver cycles on. Gate it
        // BEFORE staging the half message so no poison record is ever prepared, let alone committed.
        if let Some(reason) = compressed_descriptor_rejection(msg.flags, msg.payload) {
            reply_err(out, &reason);
            return Ok(());
        }
        // Build the OWNED half message (the wire body borrows the connection buffer, which the closure
        // cannot hold). The wire-only PUB flags (dedup/fire-and-forget bits) are masked off so only the
        // real stored content flags reach the durable half record.
        let txn_id = Bytes::copy_from_slice(decoded.txn_id);
        let stream = stream.to_string();
        let timestamp_ms = msg.timestamp_ms;
        let flags = msg.flags & !PUB_WIRE_ONLY_FLAGS;
        let key = Bytes::copy_from_slice(msg.key);
        let headers = Bytes::copy_from_slice(msg.headers);
        let payload = Bytes::copy_from_slice(msg.payload);
        // The half message's back-check OWNER is this connection's registered listener group (#640
        // part 2), so the broker can route a `TxnCheck` to this producer's listener even after a
        // reconnect. Empty when the connection never registered a listener — such a half message is not
        // back-check-routable, but the bounded attempt cap still rolls it back safely if it is crashed.
        let listener_group = self.txn_listener_group.clone().unwrap_or_default();
        let outcome = engine.with(move |e| {
            let view = Append {
                timestamp_ms,
                flags: RecordFlags::from_bits(flags),
                key: &key,
                headers: &headers,
                payload: &payload,
            };
            e.txn_prepare(&txn_id, &stream, &view, &listener_group)
        })?;
        match outcome {
            Ok(()) => {
                reply(out, FrameType::Ok, &[]);
                Ok(())
            }
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }

    /// Handles a `TxnCommit` (#640, V2-M8): commit the prepared half message named by `txn_id`. The
    /// broker appends the buffered payload to the real target stream (it becomes VISIBLE) and writes
    /// the committed op-marker, then replies a `PubAck` carrying the committed offset. Idempotent: a
    /// retried commit returns the original offset; a commit of an already-rolled-back txn is an `Err`.
    /// Routes through the single-writer engine; fail-closed at the boundary, never panics.
    fn handle_txn_commit<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(decoded) = decode_txn_resolve(body) else {
            reply_err(out, "malformed txn-commit body");
            return Ok(());
        };
        if decoded.txn_id.is_empty() {
            reply_err(out, "txn_id must not be empty");
            return Ok(());
        }
        let txn_id = Bytes::copy_from_slice(decoded.txn_id);
        let outcome = engine.with(move |e| e.txn_commit(&txn_id))?;
        match outcome {
            Ok(offset) => {
                let mut ack_body = Vec::new();
                encode_pub_ack(
                    &PubAckBody {
                        offset: offset.get(),
                    },
                    &mut ack_body,
                );
                reply(out, FrameType::PubAck, &ack_body);
                Ok(())
            }
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }

    /// Handles a `TxnRollback` (#640, V2-M8): roll back the prepared half message named by `txn_id`.
    /// The broker writes a rolled-back op-marker; the buffered payload is DISCARDED and never appended
    /// to the real stream (never delivered). Replies a body-less `Ok`. Idempotent: a retried rollback
    /// is a benign success; a rollback of an already-committed txn is an `Err`. Routes through the
    /// single-writer engine; fail-closed at the boundary, never panics.
    fn handle_txn_rollback<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(decoded) = decode_txn_resolve(body) else {
            reply_err(out, "malformed txn-rollback body");
            return Ok(());
        };
        if decoded.txn_id.is_empty() {
            reply_err(out, "txn_id must not be empty");
            return Ok(());
        }
        let txn_id = Bytes::copy_from_slice(decoded.txn_id);
        let outcome = engine.with(move |e| e.txn_rollback(&txn_id))?;
        match outcome {
            Ok(()) => {
                reply(out, FrameType::Ok, &[]);
                Ok(())
            }
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }

    /// Handles a `TxnListen` (#640 part 2, V2-M8): register THIS connection as the live transaction-state
    /// listener for a stable `group`, so the broker can ROUTE a `TxnCheck` for an in-doubt half message
    /// owned by the group to this connection — even after the original preparing connection crashed and
    /// this NEW connection re-registered the same group (the crash-and-reconnect route). It also opts the
    /// connection into the per-pass back-check scan + drain (so its `transact`/listener loop drives the
    /// resolution), and binds the group every subsequent `TxnPrepare` on this connection records as the
    /// half message's back-check owner. Replies a body-less `Ok`. Idempotent: re-registering the same (or
    /// a new) group supersedes the binding. Routes through the single-writer engine; fail-closed at the
    /// boundary, never panics.
    fn handle_txn_listen<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(decoded) = decode_txn_listen(body) else {
            reply_err(out, "malformed txn-listen body");
            return Ok(());
        };
        // A listener group must have a stable identity to route against; an empty group is refused (it
        // could not distinguish two producers and would not survive as a routable owner on prepare).
        if decoded.group.is_empty() {
            reply_err(out, "listener group must not be empty");
            return Ok(());
        }
        let group = decoded.group.to_vec();
        // Bind the group to this connection in the engine's back-check router (superseding any prior
        // binding), and remember it on the session so future prepares record it as the half message
        // owner and the per-pass scan/drain is enabled for this connection.
        let member_id = self.member_id;
        let group_for_engine = group.clone();
        // Per-connection cap (#876): a connection may hold only a bounded number of DISTINCT group
        // listeners (re-registering the SAME group is always fine). Past the cap the engine refuses with
        // a typed error rather than pinning another unbounded owned-key entry; surface it as a clean
        // protocol Err and leave the connection's prior binding untouched.
        if engine
            .with(move |e| e.register_txn_listener(&group_for_engine, member_id))?
            .is_err()
        {
            reply_err(out, "txn-listen group listener cap exceeded");
            return Ok(());
        }
        self.txn_listener_group = Some(group);
        reply(out, FrameType::Ok, &[]);
        Ok(())
    }

    /// Handles a `TxnCheckResult` (#640 part 2, V2-M8): the producer's listener's answer to a broker
    /// `TxnCheck`. A `Commit` drives the SAME idempotent `TxnCommit` path (the half message becomes
    /// visible EXACTLY ONCE), a `Rollback` the SAME `TxnRollback` path (discarded, never delivered), and
    /// an `Unknown` is a no-op (the back-check reschedules; the bounded attempt cap eventually applies
    /// the terminal default). Replies a body-less `Ok` on a clean resolve (or a benign duplicate /
    /// no-op), or an `Err` for a conflicting flip (a `Commit` of an already-rolled-back txn, or
    /// vice-versa — the part-1 `AlreadyResolved` rule). The back-check NEVER introduces a new commit
    /// path, so part 1's exactly-once guarantee is inherited. Routes through the single-writer engine;
    /// fail-closed at the boundary, never panics.
    fn handle_txn_check_result<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(decoded) = decode_txn_check_result(body) else {
            reply_err(out, "malformed txn-check-result body");
            return Ok(());
        };
        if decoded.txn_id.is_empty() {
            reply_err(out, "txn_id must not be empty");
            return Ok(());
        }
        let txn_id = Bytes::copy_from_slice(decoded.txn_id);
        let decision = decoded.decision;
        // OWNERSHIP (#640 part 2, BLOCKER 1): pass THIS connection's registered listener group so the
        // engine can verify the answerer OWNS the txn's group before resolving an in-doubt half message.
        // EMPTY when the connection never registered a `TxnListen` listener — which the engine treats as
        // "does not own", so a forged `TxnCheckResult` from a non-owner is REFUSED (a typed `Err`, not a
        // flip and not a connection close), leaving the txn Prepared so its real owner can still answer.
        let answering_group = self.txn_listener_group.clone().unwrap_or_default();
        let outcome =
            engine.with(move |e| e.resolve_txn_check(&txn_id, decision, &answering_group))?;
        match outcome {
            Ok(()) => {
                reply(out, FrameType::Ok, &[]);
                Ok(())
            }
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            Err(e) => {
                // A conflicting flip (a Commit after the terminal default already rolled it back, or a
                // racing producer-driven resolve) is refused by the part-1 path — surfaced as an Err, not
                // a flip. The producer's listener treats this as "already settled", which is correct.
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }

    /// Handles a `SubTo` (#588, M2-I10): subscribe to a NAMED stream's per-stream work-group. Binds
    /// BOTH `self.stream` (the named stream) and `self.subscription` (the work-group within it), so
    /// this connection's subsequent `Flow`/`Ack` route to that stream's OWN competing work-group via
    /// the engine's id-routed `poll_in_stream` / `ack_in_stream` (#676/#679 — the same group name in
    /// two streams is two unrelated cursors). The named stream must already EXIST (a `StreamDeclare` or
    /// a prior `PubTo` declared it); an unknown stream is an `Err`. An EMPTY stream id targets the
    /// default stream and is equivalent to a plain `Sub`. GATED on the negotiated streams capability;
    /// fail-closed on a malformed body. Never panics.
    fn handle_sub_to<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        if !self.streams_enabled {
            reply_err(
                out,
                "stream addressing not negotiated (set understands_streams)",
            );
            return Ok(());
        }
        let Ok(decoded) = decode_sub_to(body) else {
            reply_err(out, "malformed sub-to body");
            return Ok(());
        };
        // An EMPTY stream id is a default-stream subscribe: route through the EXISTING `handle_sub` so
        // a `SubTo("", group)` is byte-for-byte a plain `Sub` (it also clears any prior named binding).
        // A `Sub` body IS the raw group-name bytes (see `decode_sub`), so the decoded group slice is
        // exactly the `Sub` body `handle_sub` expects.
        if decoded.stream_id.is_empty() {
            return self.handle_sub(engine, decoded.group, out);
        }
        let Ok(stream) = core::str::from_utf8(decoded.stream_id) else {
            reply_err(out, "stream id must be valid UTF-8");
            return Ok(());
        };
        let Ok(group) = core::str::from_utf8(decoded.group) else {
            reply_err(out, "group name must be valid UTF-8");
            return Ok(());
        };
        // The named stream must already exist: a SubTo binds a consume cursor, and consuming an
        // unknown (never-declared) stream is a typed rejection, never a silent empty subscription.
        let stream_owned = stream.to_string();
        if !engine.with(move |e| e.stream_exists(&stream_owned))? {
            reply_err(
                out,
                &format!("stream {stream:?} does not exist (declare or publish to it first)"),
            );
            return Ok(());
        }
        // Switching to a named stream abandons this connection's default-stream leases (they redeliver
        // there after the visibility timeout); the named subscription starts clean. The per-stream
        // work-group is created lazily on the first named poll under the per-stream group cap (#676).
        self.stream = GroupName::from(stream);
        self.subscription = GroupName::from(group);
        // A named-stream consume is plain competing (#676): it does not register in the default-stream
        // key_shared/broadcast subscriber sets, so leave any such default-stream membership/registration
        // behind (a no-op for a connection that never had one) rather than stranding it.
        self.registered_subscription = false;
        self.joined_key_shared = false;
        self.leased.clear();
        reply(out, FrameType::Ok, &[]);
        Ok(())
    }

    /// Handles a `BindSubject` (#585, M2-I9): BIND a subject PATTERN to a stream. Routes to the engine's
    /// [`Engine::bind_subject`] (which validates the pattern, declares the stream, registers the binding,
    /// and swaps the rebuilt trie in — invalidating every connection's resolve cache via the advanced
    /// generation). GATED on the negotiated streams capability and fail-closed: a malformed pattern /
    /// stream name or a fork-bound rejection is a typed `Err`. Idempotent. Never panics.
    fn handle_bind_subject<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        if !self.streams_enabled {
            reply_err(
                out,
                "stream addressing not negotiated (set understands_streams)",
            );
            return Ok(());
        }
        let Ok(decoded) = decode_bind_subject(body) else {
            reply_err(out, "malformed bind-subject body");
            return Ok(());
        };
        let Ok(stream) = core::str::from_utf8(decoded.stream_id) else {
            reply_err(out, "stream id must be valid UTF-8");
            return Ok(());
        };
        let Ok(pattern) = core::str::from_utf8(decoded.pattern) else {
            reply_err(out, "subject pattern must be valid UTF-8");
            return Ok(());
        };
        let stream = stream.to_string();
        let pattern = pattern.to_string();
        match engine.with(move |e| e.bind_subject(&stream, &pattern))? {
            Ok(_generation) => reply(out, FrameType::Ok, &[]),
            // A malformed pattern/name or a fork-bound rejection fails closed with the engine's typed
            // reason (and stable code); the previous binding table stays installed on a rejection.
            Err(e) => reply_err_coded(out, e.code().as_str(), &e.to_string()),
        }
        Ok(())
    }

    /// Handles a `PubSubject` (#585, M2-I9): publish BY SUBJECT. Resolves the literal subject through
    /// THIS connection's generation-guarded resolve cache (an O(1) hash lookup on a hot subject, a single
    /// wait-free trie walk on a miss) under the FAIL-CLOSED single-home default — exactly ONE bound
    /// stream routes the append there (via [`Engine::produce_in_stream`]), ZERO is a
    /// `NoStreamForSubject` reject (the explicit beat over NATS's silent drop), two-or-more is an
    /// `AmbiguousSubject` reject. The verbatim `PubBody` tail is decoded with the UNCHANGED
    /// [`decode_pub`] codec, so the publish body is shared byte-for-byte with `Pub`/`PubTo`. GATED on the
    /// negotiated streams capability; fail-closed on a malformed prefix or pub body. Never panics.
    ///
    /// The resolve runs INSIDE the actor job (where the engine's wait-free routing snapshot lives): the
    /// per-connection cache is moved into the job and back out, so the cache stays connection-local while
    /// the resolve reads the shared, lock-free trie. The append then routes through the SAME id-routed
    /// produce path a `PubTo` uses, so a subject-addressed publish is at-least-once Level-1-equivalent
    /// (a `PubAck` after the resolved stream's covering fsync), exactly like `PubTo`.
    fn handle_pub_subject<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        if !self.streams_enabled {
            reply_err(
                out,
                "stream addressing not negotiated (set understands_streams)",
            );
            return Ok(());
        }
        let Ok(decoded) = decode_pub_subject(body) else {
            reply_err(out, "malformed pub-subject body");
            return Ok(());
        };
        let Ok(subject) = core::str::from_utf8(decoded.subject) else {
            reply_err(out, "subject must be valid UTF-8");
            return Ok(());
        };
        let Ok(msg) = decode_pub(decoded.pub_body) else {
            reply_err(out, "malformed pub body");
            return Ok(());
        };
        // A subject-addressed publish is at-least-once Level-1-equivalent this phase (same scope as
        // `PubTo`): a non-Level-1 ack level is refused rather than silently downgraded.
        if !matches!(pub_ack_level(msg.flags), AckLevel::ServerAck) {
            reply_err(
                out,
                "subject-addressed publish supports only server-ack (level 1) this phase",
            );
            return Ok(());
        }
        // The dedup-id wire caps (#33), enforced at the boundary exactly as the default `handle_pub` and
        // `handle_pub_to` do, BEFORE the bytes cross into owned storage.
        if let Some(d) = msg.dedup.as_ref() {
            if d.producer_id.len() > MAX_PRODUCER_ID_LEN {
                reply_err(out, "producer_id too long");
                return Ok(());
            }
            if d.msg_id.len() > MAX_MSG_ID_LEN {
                reply_err(out, "msg_id too long");
                return Ok(());
            }
            // The idempotent SEQUENCE (V2-M8) requires a non-empty producer_id (the durable high-water
            // is keyed by it), same fail-closed gate as `handle_pub` / `handle_pub_to`.
            if d.seq.is_some() && d.producer_id.is_empty() {
                reply_err(out, "idempotent sequence requires a non-empty producer_id");
                return Ok(());
            }
        }
        // Compressed-descriptor SHAPE validation at the wire boundary (#438), the same shared gate as
        // the other publish paths (`compressed_descriptor_rejection`): a stored compressed object must
        // be decodable by every reader.
        if let Some(reason) = compressed_descriptor_rejection(msg.flags, msg.payload) {
            reply_err(out, &reason);
            return Ok(());
        }
        // Build the OWNED append (the wire body borrows the connection buffer, which the closure cannot
        // hold), then RESOLVE + PRODUCE in ONE actor job: the resolve reads the engine's wait-free
        // routing snapshot through this connection's cache (moved in and back out), and on a single-home
        // hit the resolved stream's id-routed produce runs in the same job. A NoStream/Ambiguous
        // resolution is returned as a typed reject WITHOUT touching a log (no silent drop, no partial
        // write — the fail-closed beat over NATS).
        let dedup = msg.dedup.map(|d| OwnedDedup {
            producer_id: Bytes::copy_from_slice(d.producer_id),
            epoch: d.epoch,
            msg_id: Bytes::copy_from_slice(d.msg_id),
            // The opt-in idempotent SEQUENCE (V2-M8) rides through to the engine's durable per-producer
            // high-water; `None` keeps the existing time-bounded `msg_id`-window dedup path.
            seq: d.seq,
        });
        let append = OwnedAppend {
            timestamp_ms: msg.timestamp_ms,
            flags: msg.flags & !PUB_WIRE_ONLY_FLAGS,
            key: Bytes::copy_from_slice(msg.key),
            headers: Bytes::copy_from_slice(msg.headers),
            payload: Bytes::copy_from_slice(msg.payload),
            // The subject-routed produce resolves to a stream and appends via `produce_in_stream` (its
            // own StreamSet log), NOT the default-stream actor append path that consumes the offloaded
            // checksum (#830), so leave it `None` rather than compute a value that path discards.
            body_checksums: None,
            dedup,
            enqueue_monotonic_nanos: engine.now_monotonic_nanos(),
            fire_and_forget: false,
            // The produce ACK LEVEL (#571) from the wire PUB flags, for the per-ack-level produce
            // counters; this subject-routed produce path counts it explicitly in the engine job below.
            ack_level: ironbus_proto::message::pub_ack_level(msg.flags),
        };
        let subject = subject.to_string();
        // Move the per-connection resolve cache into the job; the job returns it (and the produce
        // outcome) so the cache's freshly-cached entry + adopted generation persist across publishes.
        let cache = std::mem::take(&mut self.subject_cache);
        let (cache, outcome) = engine.with(move |e| {
            let mut cache = cache;
            let level = append.ack_level;
            let outcome = resolve_then_produce(e, &mut cache, &subject, &append);
            // Per-ack-level PRODUCE throughput (#571) for the subject-routed produce path (which runs
            // synchronously in this engine job, not through the actor drain that counts the default
            // batched path): count only on a successful append, so the per-level sum matches the
            // fresh-append count. Allocation-free under the same job.
            if outcome.is_ok() {
                e.record_produce_ack_level(level);
            }
            (cache, outcome)
        })?;
        self.subject_cache = cache;
        match outcome {
            Ok(offset) => {
                let ack = PubAckBody {
                    offset: offset.get(),
                };
                let mut ack_body = Vec::new();
                encode_pub_ack(&ack, &mut ack_body);
                reply(out, FrameType::PubAck, &ack_body);
                Ok(())
            }
            // A fatal storage error on the resolved stream ends the session, exactly like the other
            // produce paths (a frozen writer / broken invariant is unrecoverable).
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            // An unbound (NoStreamForSubject) or ambiguous (AmbiguousSubject) subject, a malformed
            // subject, or a non-fatal storage shed is a typed, connection-preserving reject — never a
            // panic and (critically) NEVER a silent drop.
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                Ok(())
            }
        }
    }

    /// Handles a `SubSubject` (#585, M2-I9): subscribe BY SUBJECT. Resolves the subject through this
    /// connection's generation-guarded resolve cache under the single-home default; a LITERAL subject
    /// resolves to ONE bound stream and this connection's subsequent `Flow`/`Ack` bind to that stream's
    /// own competing work-group (via the id-routed `poll_in_stream`/`ack_in_stream`). An unbound subject
    /// is a `NoStreamForSubject` reject and an ambiguous one an `AmbiguousSubject` reject (single-home;
    /// fanning a wildcard sub over multiple covered streams is the FLAGGED follow-up). GATED on the
    /// negotiated streams capability; fail-closed on a malformed body. Never panics.
    ///
    /// NOTE the scope: a `SubSubject` resolves the subject to ONE stream and binds THAT stream's
    /// work-group (single-home). A wildcard subject that single-home-resolves (covers exactly one bound
    /// stream) is accepted; a wildcard covering MANY bound streams is `AmbiguousSubject` here (the
    /// multi-stream wildcard fan-out subscribe is the flagged later issue, not this PR).
    fn handle_sub_subject<
        F: Filesystem + Clone + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        if !self.streams_enabled {
            reply_err(
                out,
                "stream addressing not negotiated (set understands_streams)",
            );
            return Ok(());
        }
        let Ok(decoded) = decode_sub_subject(body) else {
            reply_err(out, "malformed sub-subject body");
            return Ok(());
        };
        let Ok(subject) = core::str::from_utf8(decoded.subject) else {
            reply_err(out, "subject must be valid UTF-8");
            return Ok(());
        };
        let Ok(group) = core::str::from_utf8(decoded.group) else {
            reply_err(out, "group name must be valid UTF-8");
            return Ok(());
        };
        // Resolve the subject to its single bound stream INSIDE the actor (through this connection's
        // cache, moved in and back out). A wildcard subject is parsed as a literal here only for the
        // single-home walk — `Subject::parse_literal` rejects a wildcard, so a wildcard subject that the
        // client sends is resolved through the engine's pattern-aware path below instead. To keep the
        // bind simple and single-home, resolve via `resolve_subject` (literal) and fall back to a typed
        // reject for a non-literal/unbound/ambiguous subject.
        let subject_owned = subject.to_string();
        let cache = std::mem::take(&mut self.subject_cache);
        let (cache, resolved) = engine.with(move |e| {
            let mut cache = cache;
            let resolved = resolve_subject_cached(e, &mut cache, &subject_owned);
            (cache, resolved)
        })?;
        self.subject_cache = cache;
        let stream = match resolved {
            Ok(id) => id,
            Err(e) => {
                reply_err_coded(out, e.code().as_str(), &e.to_string());
                return Ok(());
            }
        };
        // Bind this connection's consume path to the resolved stream + the requested work-group, exactly
        // as a `SubTo` binds an explicit stream id (the resolved stream is already declared by its bind).
        self.stream = GroupName::from(stream.name());
        self.subscription = GroupName::from(group);
        self.registered_subscription = false;
        self.joined_key_shared = false;
        self.leased.clear();
        reply(out, FrameType::Ok, &[]);
        Ok(())
    }

    fn handle_unsub<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        // Leave the key_shared group (if any) so its keys re-route, then revert to the default
        // group and drop any outstanding named-group leases (they redeliver after the timeout).
        self.leave_current_key_shared(engine)?;
        // Deregister this connection as an active subscriber (#288), freeing the group's broadcast
        // slot for a later subscriber. A no-op for an unregistered (default-group) connection.
        self.leave_current_subscription(engine)?;
        // The named group this connection is leaving. Captured BEFORE clearing the subscription so
        // the explicit-Unsub eviction (#277) can target it: if it is now fully caught up with no
        // in-flight leases, it is immediately reclaimable rather than waiting out the idle window.
        // It is a no-op for the default group, for a group still holding leases (they redeliver or
        // expire first, then the natural idle sweep reclaims it), and when eviction is disabled.
        let leaving = std::mem::take(&mut self.subscription);
        // Clear any named-stream binding (#588): after an Unsub the connection reverts to the default
        // stream, so a later Flow with no SubTo polls the default stream byte-for-byte. The named
        // stream's per-stream work-group is NOT registered in the default-stream key_shared/broadcast/
        // eviction structures (#676 named consume is plain competing only), so the leave/evict calls
        // above are no-ops for it; only this local binding needs resetting.
        self.stream = GroupName::default();
        self.leased.clear();
        if !leaving.is_empty() {
            engine.with(move |e| {
                e.evict_group_if_idle(&leaving);
            })?;
        }
        reply(out, FrameType::Ok, &[]);
        Ok(())
    }

    /// Leaves the currently-subscribed `key_shared` group's live-member set (#64), if this
    /// connection had joined one. Idempotent and a no-op for a plain competing subscription, so it
    /// is safe to call on every subscription switch, UNSUB, and connection close. The engine keeps
    /// the departed member's in-flight records leased until they drain or expire (the drain-or-expire
    /// guard), so its keys do not jump to a new owner mid-record.
    ///
    /// # Errors
    /// Returns [`SessionError::ActorGone`] if the actor exited before the leave could run. A no-op
    /// (no round-trip) when this connection had not joined a `key_shared` group.
    pub fn leave_current_key_shared<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
    ) -> Result<(), SessionError> {
        if self.joined_key_shared {
            let group = self.subscription.clone();
            let member = self.member_id;
            engine.with(move |e| {
                e.leave_member_in(&group, member);
            })?;
            self.joined_key_shared = false;
        }
        Ok(())
    }

    /// Deregisters this connection as an active subscriber of its current group (#288), if it had
    /// registered one. Idempotent and a no-op for an unregistered (default-group) connection, so it
    /// is safe to call on every subscription switch, UNSUB, and connection close. Freeing the slot
    /// lets a later consumer take over a broadcast group whose previous lone subscriber has left.
    ///
    /// # Errors
    /// Returns [`SessionError::ActorGone`] if the actor exited before the deregister could run. A
    /// no-op (no round-trip) when this connection had not registered a subscription.
    pub fn leave_current_subscription<
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
        E: EngineAccess<F, C>,
    >(
        &mut self,
        engine: &E,
    ) -> Result<(), SessionError> {
        if self.registered_subscription {
            let group = self.subscription.clone();
            let member = self.member_id;
            engine.with(move |e| {
                e.unsubscribe_in(&group, member);
            })?;
            self.registered_subscription = false;
        }
        Ok(())
    }
}

/// The byte size a delivered message occupies against the per-consumer byte budget (#275): its key
/// plus headers plus payload length, matching the engine's produced-bytes accounting (the framing
/// and fixed-header overhead is deliberately excluded, so the budget tracks the consumer's PAYLOAD
/// RAM, the thing #20 cross-checks against the RAM ceiling). Saturating so an impossibly large record
/// can never wrap the total.
fn lease_bytes(record: &ironbus_storage::segment::OwnedRecord) -> u64 {
    let len = record
        .key
        .len()
        .saturating_add(record.headers.len())
        .saturating_add(record.payload.len());
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Combines two byte budgets into the EFFECTIVE one, where `0` means UNLIMITED on EITHER side (#489,
/// #275): the per-consumer byte budget and a fetch's own `max_bytes`. When both are non-zero the tighter
/// (`min`) binds; when one is `0` (unlimited) the other binds; when both are `0` the result is `0`
/// (unlimited). So a fetch can only ever TIGHTEN the negotiated byte budget, never loosen it.
fn min_budget(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, x) | (x, 0) => x,
        (a, b) => a.min(b),
    }
}

/// The #292 per-consumer MESSAGE-credit negotiation. A finite request tightens via `min(request,
/// cap)`; a `0` request (no meaningful budget, since a 0 ceiling delivers nothing) or no request takes
/// the server cap. A request can only ever TIGHTEN the server cap, never raise it. The cap is already
/// floored to >= 1 by the engine, so the result is always >= 1.
fn negotiate_credit(requested: Option<u32>, cap: u32) -> u32 {
    // A request of 0 messages carries no meaningful budget (a 0 message ceiling delivers nothing),
    // so it is treated as "no request" and gets the server default; any finite request only
    // tightens via `min` and can never exceed the server cap.
    match requested {
        Some(0) | None => cap,
        Some(want) => want.min(cap),
    }
}

/// The #292 per-consumer BYTE-budget negotiation. A byte budget of `0` means UNLIMITED (the budget is
/// OFF). A client may only TIGHTEN, never raise: against an UNLIMITED server cap (`0`) a client may set
/// any finite budget (or stay unlimited); against a FINITE server cap an unlimited request (`0`) is
/// clamped DOWN to the cap, so a client can NEVER disable a budget the server set (the #275 byte-budget
/// guarantee). A client that requests nothing gets the server cap (the default).
fn negotiate_credit_bytes(requested: Option<u64>, cap: u64) -> u64 {
    match requested {
        // A `0` (unlimited) request, or no request, takes the server cap: unlimited only if the
        // server itself is unlimited (cap == 0), otherwise clamped to the finite cap.
        Some(0) | None => cap,
        // Server unlimited: the client tightens to a finite budget of its choosing.
        Some(want) if cap == 0 => want,
        // Both finite: tighten to the smaller.
        Some(want) => want.min(cap),
    }
}

/// Resolves the literal `subject` to its single bound stream (#585) THROUGH the per-connection
/// `cache`, against the engine's wait-free routing snapshot — INSIDE an actor job (where `&mut Engine`
/// is borrowable). A cache HIT is an O(1) hash lookup (no trie walk); a MISS walks the trie once and
/// caches the result; a bind change (a newer snapshot generation) drops the stale cache on the next
/// resolve. Returns the resolved [`StreamId`] or the typed fail-closed reject — a malformed/wildcard
/// subject ([`EngineError::InvalidSubject`]), an unbound subject ([`EngineError::NoStreamForSubject`],
/// NOT a silent drop), or an ambiguous subject ([`EngineError::AmbiguousSubject`]).
///
/// This is the cached twin of [`Engine::resolve_subject`]: the engine method walks the trie directly;
/// this resolves through the connection's cache so a hot subject is O(1). The single-home reduction is
/// the shared [`single_home`] policy, so the two agree.
fn resolve_subject_cached<F: Filesystem, C: Clock + Clone>(
    engine: &Engine<F, C>,
    cache: &mut ResolveCache<StreamId>,
    subject: &str,
) -> Result<StreamId, EngineError> {
    // Validate as a #567 LITERAL (no wildcards on the publish/subscribe-by-literal side); a wildcard or
    // malformed subject is a typed reject before any routing.
    let subj = Subject::parse_literal(subject).map_err(EngineError::InvalidSubject)?;
    // Resolve through the cache against the engine's wait-free snapshot, then reduce single-home over the
    // cached target slice WITHOUT cloning the whole Vec (only the one routed id is cloned on the happy
    // path).
    match cache.resolve_with(engine.binding_snapshot(), &subj, single_home) {
        Resolution::Routed(id) => Ok(id),
        Resolution::NoStream => Err(EngineError::NoStreamForSubject {
            subject: subject.to_string(),
        }),
        Resolution::Ambiguous { matched } => Err(EngineError::AmbiguousSubject {
            subject: subject.to_string(),
            matched,
        }),
    }
}

/// Resolves `subject` single-home through `cache` (fail-closed) and, on a single-home hit, routes the
/// owned `append` to the resolved stream via the id-routed [`Engine::produce_in_stream`] — the publish
/// half of a `PubSubject` (#585), run in ONE actor job. An unbound/ambiguous/malformed subject is
/// returned as a typed reject WITHOUT any append (no silent drop, no partial write — the fail-closed
/// beat over NATS). Returns the assigned [`Offset`] in the resolved stream on success.
fn resolve_then_produce<F: Filesystem + Clone, C: Clock + Clone>(
    engine: &mut Engine<F, C>,
    cache: &mut ResolveCache<StreamId>,
    subject: &str,
    append: &OwnedAppend,
) -> Result<Offset, EngineError> {
    // Resolve first (fail-closed): a NoStream/Ambiguous/Invalid subject is refused BEFORE any append.
    let stream = resolve_subject_cached(engine, cache, subject)?;
    // Route the append to the resolved stream's log via the id-routed produce (the default stream `""`
    // routes byte-for-byte through `produce`; a named stream appends to its own log + commit tick).
    let view = Append {
        timestamp_ms: append.timestamp_ms,
        flags: RecordFlags::from_bits(append.flags),
        key: &append.key,
        headers: &append.headers,
        payload: &append.payload,
    };
    engine.produce_in_stream(stream.name(), &view)
}

/// The #438 compressed-descriptor SHAPE gate, shared by ALL FOUR produce verbs (`handle_pub`,
/// `handle_pub_to`, `handle_pub_subject`, `handle_txn_prepare`). A COMPRESSED publish must carry a
/// well-formed, in-cap descriptor BEFORE it is stored, or a producer could durably ack a record no
/// reader can decode: every consumer group of that offset then burns max-deliver visibility-timeout
/// redelivery cycles on the poison pill before dead-lettering, and it survives restart — the
/// resource-amplification `DoS` this gate exists to prevent. The check is a 9-byte header parse, NO
/// decompression (the produce hot path pays no codec CPU; stream CONTENT stays a read-side concern),
/// against the read-side rules and the same [`DEFAULT_MAX_DECOMPRESSED_BYTES`] cap every shipped
/// reader enforces. Returns the one-line, connection-preserving rejection message to reply with, or
/// `None` to proceed.
///
/// Centralizing the gate here is the fix for #877: `handle_txn_prepare` was the one produce verb
/// that skipped it, so a Publish-scoped producer could stage and commit a poison compressed record
/// through a tiny `TxnPrepare`/`TxnCommit` pair. One funnel keeps the invariant from drifting on a
/// single verb again. The gate lives at the WIRE boundary ONLY — the engine's own compressed output
/// and the DLQ redrive's direct `Log::append` re-injection never pass through a session.
fn compressed_descriptor_rejection(flags: u8, payload: &[u8]) -> Option<String> {
    if RecordFlags::from_bits(flags).contains(RecordFlags::COMPRESSED) {
        if let Err(e) = validate_descriptor_shape(payload, DEFAULT_MAX_DECOMPRESSED_BYTES) {
            return Some(format!("malformed compressed descriptor: {e}"));
        }
    }
    None
}

/// Encodes a response frame. Bodies here are tiny (<= 8 bytes, or a short literal), well
/// under [`MAX_FRAME_LEN`](ironbus_proto::frame::MAX_FRAME_LEN), so the encode cannot fail;
/// the debug assert pins that invariant against a future large-body call site.
fn reply(out: &mut Vec<u8>, frame_type: FrameType, body: &[u8]) {
    let result = encode_frame(frame_type, body, out);
    debug_assert!(result.is_ok(), "response body exceeded the frame cap");
}

fn reply_err(out: &mut Vec<u8>, message: &str) {
    reply(out, FrameType::Err, message.as_bytes());
}

/// Writes an `Err` frame that carries the STABLE machine-readable code `token` (#883) in front of the
/// human `message`, so a client branches on the code rather than substring-matching prose the broker
/// is free to reword. `token` is the NORMATIVE [`ErrorCode`](crate::codes::ErrorCode) spelling
/// (e.g. `error.code().as_str()`); the human message is preserved verbatim for display. An UNCODED
/// [`reply_err`] stays byte-identical to the pre-#883 body (the coded shape is marked by a leading
/// sentinel a UTF-8 message never begins with), so the uniform auth violation and the malformed-body
/// literals are untouched.
fn reply_err_coded(out: &mut Vec<u8>, code_token: &str, message: &str) {
    let mut body = Vec::with_capacity(2 + code_token.len() + message.len());
    ironbus_proto::err::encode_err_body(Some(code_token), message, &mut body);
    reply(out, FrameType::Err, &body);
}

/// Writes the single UNIFORM "Authorization Violation" `Err` frame (#631, V2-M7,
/// `docs/AUTHENTICATION.md` "The uniform Authorization Violation"). EVERY authentication and
/// authorization failure — unknown mechanism, bad credential, unknown username, a verifying mTLS cert
/// that matches no identity, or a verb the pinned scope set does not grant — uses THIS one message,
/// with no numeric code and no sub-reason, so the wire carries no oracle distinguishing a bad
/// credential from an insufficient scope and no username-enumeration signal. The caller then closes
/// the connection (returns [`SessionError::AuthViolation`]).
fn reply_auth_violation(out: &mut Vec<u8>) {
    reply(
        out,
        FrameType::Err,
        crate::auth::AuthError::MESSAGE.as_bytes(),
    );
}

/// Maps a wire [`AuthMechanism`](ironbus_proto::message::AuthMechanism) to the SAFE audit mechanism
/// handle (#635): `bearer` / `password` / `mtls`, or `unknown` for any future/unrecognized selector
/// (the wire enum is `#[non_exhaustive]`). Never a credential — only the mechanism name.
fn audit_mechanism(m: ironbus_proto::message::AuthMechanism) -> crate::audit::Mechanism {
    use ironbus_proto::message::AuthMechanism as W;
    match m {
        W::Bearer => crate::audit::Mechanism::Bearer,
        W::Password => crate::audit::Mechanism::Password,
        W::Mtls => crate::audit::Mechanism::Mtls,
        _ => crate::audit::Mechanism::Unknown,
    }
}

/// Emits a publish-ack reply (`PubAck` for a fresh produce, `PubAckDuplicate` for a #33 dedup hit)
/// via the shared [`encode_pub_ack`] codec, so the wire body and the codec cannot drift: both frame
/// types share the exact 8-byte LE offset body the codec produces. The frame type alone distinguishes
/// a fresh ack from a benign dedup hit; the frozen `PubAck` body is unchanged.
fn reply_pub_ack(out: &mut Vec<u8>, frame_type: FrameType, offset: Offset) {
    let mut body = Vec::with_capacity(8);
    encode_pub_ack(
        &PubAckBody {
            offset: offset.get(),
        },
        &mut body,
    );
    reply(out, frame_type, &body);
}

/// Emits a cluster `NotLeader` produce-redirect reply (#735): the current leader's CLIENT-address hint
/// (or the EMPTY string when this node does not yet know it), via the shared [`encode_not_leader`] codec
/// so the wire body cannot drift from the proto definition. Written ONLY on a clustered serve when a
/// produce lands on a non-leader replica of the partition (see [`ClusterProduceRouting::Redirect`]); a
/// single-node broker never reaches this. The encode is infallible for an address (well under the u16
/// field cap); on the unreachable over-cap error it falls back to an empty hint so the redirect still
/// fires (the client re-tries its known peers) rather than panicking on the serve path (#11).
fn reply_not_leader(out: &mut Vec<u8>, leader_hint: Option<std::net::SocketAddr>) {
    let hint = leader_hint.map(|a| a.to_string()).unwrap_or_default();
    let mut body = Vec::new();
    if encode_not_leader(&NotLeaderBody { leader_hint: &hint }, &mut body).is_err() {
        body.clear();
        // Unreachable for a real address; emit an empty-hint redirect rather than panic.
        let _ = encode_not_leader(&NotLeaderBody { leader_hint: "" }, &mut body);
    }
    reply(out, FrameType::NotLeader, &body);
}

/// Writes one Level-2 `ProduceConfirm` frame (#497) for a ready terminal: the durable offset plus the
/// terminal status byte, via the shared [`encode_produce_confirm`] codec so the wire body cannot drift
/// from the proto definition. Maps the core [`ConfirmStatus`] to its wire
/// [`produce_confirm_status`] byte: `Consumed` -> `CONSUMED`, `TimedOut` -> `TIMED_OUT`, and BOTH
/// `DeadLettered` and the bounded-registry `Dropped` shed -> `DEAD_LETTERED` (a dropped confirm is a
/// non-success terminal whose record stayed durable but is no longer tracked, indistinguishable on the
/// wire from a dead-letter, which is the honest signal: the consumed confirmation will never arrive).
fn write_produce_confirm(confirm: &ReadyConfirm, out: &mut Vec<u8>) {
    let status = match confirm.status {
        ConfirmStatus::Consumed => produce_confirm_status::CONSUMED,
        ConfirmStatus::TimedOut => produce_confirm_status::TIMED_OUT,
        ConfirmStatus::DeadLettered | ConfirmStatus::Dropped => {
            produce_confirm_status::DEAD_LETTERED
        }
    };
    let mut body = Vec::with_capacity(9);
    encode_produce_confirm(
        &ProduceConfirmBody {
            offset: confirm.offset,
            status,
        },
        &mut body,
    );
    reply(out, FrameType::ProduceConfirm, &body);
}

/// Drains every READY Level-2 `ProduceConfirm` for the producer connection `member_id` (#497) and
/// writes one `ProduceConfirm` frame per terminal onto `out`, FIFO. The terminals are produced
/// out-of-band by CONSUMER acks (and the dead-letter / force-reap / TTL-timeout failure paths) on
/// OTHER connection threads, recorded in the engine's bounded registry keyed by this connection's
/// `member_id`, and drained HERE on this producer's own pass — the only place the blocking
/// thread-per-connection server may write this socket. A gone actor is a no-op. ADDITIVE: empty for
/// any connection with no outstanding L2 confirm.
fn drain_produce_confirms<
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
>(
    engine: &E,
    member_id: MemberId,
    out: &mut Vec<u8>,
) {
    let Ok(ready) = engine.with(move |e| e.drain_l2_confirms(member_id)) else {
        return; // a gone actor: the connection is ending, nothing to deliver
    };
    for confirm in ready {
        write_produce_confirm(&confirm, out);
    }
}

/// Writes one `TxnCheck` frame (#640 part 2) asking the producer's listener about an in-doubt
/// transaction. Reuses the frozen [`encode_txn_resolve`] codec (the same `txn_id`-only body shape as
/// `TxnCommit`/`TxnRollback`), so the wire body cannot drift from the proto definition.
fn write_txn_check(txn_id: &[u8], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    // The encode only fails for a txn id over the u16 wire cap, which the lifecycle bounds to 256, so
    // this is infallible in practice; on the unreachable error we simply emit no frame (the txn is
    // re-checked on a later scan).
    if encode_txn_resolve(&TxnResolveBody { txn_id }, &mut body).is_ok() {
        reply(out, FrameType::TxnCheck, &body);
    }
}

/// Drives the broker back-check for a producer connection that registered a transaction listener (#640
/// part 2): runs ONE periodic scan tick (find in-doubt txns due for a back-check, push a `TxnCheck`,
/// record the attempt durably, apply the terminal default after the bounded attempt cap), then drains
/// every `TxnCheck` the broker routed to THIS connection onto the wire, FIFO. The scan + drain both run
/// through the single-writer engine; a gone actor is a no-op. The scan is a no-op when there are no
/// in-doubt txns, so a back-checking connection on an idle broker pays ~nothing. A storage error in the
/// scan is swallowed here (the connection is mid-pass and the next scan retries); it never desyncs the
/// wire because no partial frame is written on the scan path.
fn drive_back_check<
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
>(
    engine: &E,
    member_id: MemberId,
    out: &mut Vec<u8>,
) {
    // Run one scan tick (single-writer). A gone actor or a storage error both mean "skip this pass".
    let _ = engine.with(move |e| {
        let _ = e.txn_back_check_tick();
    });
    // Drain the `TxnCheck`s routed to this connection and write them onto its own pass.
    let Ok(checks) = engine.with(move |e| e.drain_txn_checks(member_id)) else {
        return; // a gone actor: the connection is ending, nothing to deliver
    };
    for check in checks {
        write_txn_check(&check.txn_id, out);
    }
}

/// Reusable scratch capacity for a per-record `Deliver`/advisory frame body (#826). A hoisted
/// `frame_body` buffer starts at this size so a small-payload record encodes without a growth
/// realloc; `frame_body.clear()` retains the capacity across records, so the per-record malloc/free
/// and growth reallocs are removed and the buffer amortizes to the largest frame the loop has seen.
/// Covers the fixed 25-byte DELIVER header (offset + generation + flags + timestamp), the two u16
/// var-length prefixes for key/headers, and a small payload; a larger payload simply grows once and
/// stays grown for the rest of the batch. Scratch only — the bytes are copied into `out`, so the
/// value is a pure allocation hint and never affects the encoded frame.
const DELIVER_FRAME_SCRATCH_CAP: usize = 256;

/// The safety cap on a single pass's pipelined produce window (#450): how many produces a session
/// may PARK (submitted to the actor, ack not yet awaited) before it must release the window. It
/// bounds the parked-reply memory for a buffer packed with tiny PUB frames and matches the actor
/// channel's default bound ([`crate::actor::DEFAULT_CHANNEL_BOUND`]), so a session can never queue
/// more un-awaited produces than the channel was sized for. In practice the window is far smaller:
/// the connection loop hands the session one read buffer at a time.
const MAX_PARKED_PRODUCES: usize = 1024;

/// One produce PARKED in a session's pipelined window (#450): the un-awaited submission plus the
/// QoS-0 marker the reply mapping needs (a fire-and-forget produce gets NO frame for any
/// disposition, the #11 no-frame contract). `Debug` because the window is now a persistent
/// [`Session`] field (#1045), so it rides the struct's derived `Debug`.
#[derive(Debug)]
struct ParkedPub {
    /// The submitted-but-not-awaited produce; awaiting it yields the outcome only after the
    /// covering group-commit fsync (I2).
    submission: ProduceSubmission,
    /// Whether the producer marked this publish fire-and-forget (QoS-0, #11): suppresses every
    /// reply frame for this produce, exactly like the awaited path.
    fire_and_forget: bool,
    /// Whether this publish is Level 2 (server+client ack, #497): in addition to its durability
    /// `PubAck`, register the durable offset in the engine's bounded confirm registry so a later
    /// consumer ack fires a `ProduceConfirm`. `false` for L0/L1, so their paths are unchanged.
    wants_confirm: bool,
}

/// Writes ONE released produce's wire reply and, for a Level-2 publish (#497), registers its confirm —
/// the SHARED release tail every drain path funnels through (the blocking full-window [`drain_parked`],
/// the non-blocking ready-prefix [`release_ready_prefix`], and the blocking front-one
/// [`drain_front_one_blocking`]), so the #719 cluster produce-ack gate and the #497 confirm
/// registration are BYTE-IDENTICAL no matter which path releases the ack. `outcome` is the awaited or
/// polled disposition; `fire_and_forget`/`wants_confirm` are the parked entry's markers.
///
/// For a Level-2 publish, AFTER its durability `PubAck` is written (the record is durable first, I2),
/// the durable offset is REGISTERED in the engine's bounded confirm registry against `member_id`, so a
/// later consumer ack in the designated group fires a `ProduceConfirm` back to this producer. The
/// registration is layered ON TOP of the unchanged Level-1 reply; L0/L1 (`wants_confirm == false`)
/// skip it entirely.
fn release_parked_outcome<
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
>(
    engine: &E,
    member_id: MemberId,
    outcome: ProduceOutcome,
    fire_and_forget: bool,
    wants_confirm: bool,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    // A Level-2 publish whose record became durable registers its offset for the consumer-ack
    // confirmation, AFTER the durability ack is written below. Only a fresh `Appended` is a new durable
    // offset to confirm; a dedup hit (`AppendedDuplicate`) returns an ALREADY-confirmed-or-pending
    // earlier offset, a shed/fence/fatal never became durable, and a fire-and-forget L2 is not a thing
    // (L2 is at-least-once). So capture the offset to register only on `Appended`.
    let confirm_offset = match &outcome {
        ProduceOutcome::Appended(offset) if wants_confirm => Some(*offset),
        _ => None,
    };
    write_pub_reply_gated(engine, member_id, outcome, fire_and_forget, out)?;
    if let Some(offset) = confirm_offset {
        // Register AFTER the `PubAck` was written: the record is durable (the covering fsync ran before
        // the actor reported `Appended`) and its durability ack is already on the wire, so the Level-2
        // confirm wait is strictly layered on top of the Level-1 durability guarantee. A gone actor here
        // is a no-op (the connection is ending anyway); the registry is bounded, so this can never grow
        // without bound.
        let _ = engine.with(move |e| e.register_l2_confirm(offset, member_id));
    }
    Ok(())
}

/// BLOCK-drains the ENTIRE parked produce window (#450): awaits each submission IN SUBMISSION ORDER
/// and appends its reply frame(s) to `out`, so the wire sees exactly the FIFO ack order the
/// per-connection contract promises (#917). On a fatal outcome the error propagates immediately; the
/// remaining parked entries are dropped un-replied, which is safe because a batch-covering fsync
/// failure marks EVERY member of the batch fatal (the actor's `flush_pending`) and the session is
/// closing anyway (the actor tolerates a dropped reply receiver). After this returns, `parked` is
/// empty.
///
/// Used on the CLOSING paths only (#1045): a non-produce frame's ordering barrier (an ack/flow/sub
/// reply must come after every prior produce ack), a malformed/fatal pass exit, and the connection's
/// clean-EOF final flush — the cases where the whole window's acks belong on the wire before the next
/// (non-produce) reply or the close. The STEADY-STATE per-pass release does NOT block-await here; it
/// uses [`release_ready_prefix`], which is what lets one connection overlap the next batch with the
/// current batch's fsync.
fn drain_parked<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
    engine: &E,
    member_id: MemberId,
    parked: &mut VecDeque<ParkedPub>,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    while let Some(p) = parked.pop_front() {
        let ParkedPub {
            submission,
            fire_and_forget,
            wants_confirm,
        } = p;
        let outcome = submission.wait()?;
        release_parked_outcome(
            engine,
            member_id,
            outcome,
            fire_and_forget,
            wants_confirm,
            out,
        )?;
    }
    Ok(())
}

/// Releases only the READY FRONT PREFIX of the parked window (#1045): NON-BLOCKING — while the FRONT
/// parked produce's outcome is already available ([`ProduceSubmission::try_take`]), write its reply and
/// pop it; STOP at the first not-ready front and leave it (and everything behind it) parked. By the
/// per-connection FIFO submission order (#917) a not-ready front implies the rest are also not ready
/// (a later batch cannot commit before an earlier one), so releasing the ready prefix preserves the
/// exact wire ack order while NEVER block-awaiting an un-fsync'd produce. This is the seam that lets a
/// saturating producer keep reading and submitting the next batch instead of stalling the pass on the
/// fdatasync of the batch it just parked.
fn release_ready_prefix<
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
>(
    engine: &E,
    member_id: MemberId,
    parked: &mut VecDeque<ParkedPub>,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    while let Some(p) = parked.pop_front() {
        let ParkedPub {
            submission,
            fire_and_forget,
            wants_confirm,
        } = p;
        match submission.try_take()? {
            TryTake::Ready(outcome) => {
                release_parked_outcome(
                    engine,
                    member_id,
                    outcome,
                    fire_and_forget,
                    wants_confirm,
                    out,
                )?;
            }
            TryTake::NotReady(submission) => {
                // The front's covering commit has not landed yet: re-park it at the FRONT and stop. By
                // FIFO the rest of the window is also not ready, so we never reorder acks.
                parked.push_front(ParkedPub {
                    submission,
                    fire_and_forget,
                    wants_confirm,
                });
                break;
            }
        }
    }
    Ok(())
}

/// BLOCK-awaits the single FRONT parked produce's ack (its covering group-commit fsync), writes its
/// reply, and pops it (#1045, FIFO #917). The bounded-window primitive: when a non-blocking read would
/// block AND the window is non-empty, the socket has no new bytes, so the ONLY way to make progress for
/// a client waiting on acks it already sent is to release the FRONT ack — block on exactly that one
/// fsync. A no-op on an empty window.
fn drain_front_one_blocking<
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
>(
    engine: &E,
    member_id: MemberId,
    parked: &mut VecDeque<ParkedPub>,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    if let Some(p) = parked.pop_front() {
        let ParkedPub {
            submission,
            fire_and_forget,
            wants_confirm,
        } = p;
        let outcome = submission.wait()?;
        release_parked_outcome(
            engine,
            member_id,
            outcome,
            fire_and_forget,
            wants_confirm,
            out,
        )?;
    }
    Ok(())
}

/// Enforces the [`MAX_PARKED_PRODUCES`] memory backstop (#450, #1045): once the persistent window has
/// grown to the cap (acks lagging arrivals), release the ready front prefix and, if that is not enough,
/// BLOCK-drain the front one at a time until the window is back under the cap. Bounds the parked-window
/// memory at exactly `MAX_PARKED_PRODUCES` entries regardless of how far the actor's fsyncs lag; the
/// blocking drain is natural produce backpressure (a new produce waits for an old one to commit).
fn enforce_parked_cap<
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
>(
    engine: &E,
    member_id: MemberId,
    parked: &mut VecDeque<ParkedPub>,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    // Cheap first: release anything already-ready (no block). Usually enough on its own.
    release_ready_prefix(engine, member_id, parked, out)?;
    // Still at the cap: the front is genuinely un-committed, so block on it (backpressure) until the
    // window is bounded again.
    while parked.len() >= MAX_PARKED_PRODUCES {
        drain_front_one_blocking(engine, member_id, parked, out)?;
        release_ready_prefix(engine, member_id, parked, out)?;
    }
    Ok(())
}

/// Like [`write_pub_reply`], but for a FRESH durable `Appended` it routes the wire `PubAck` through the
/// CLUSTER produce-ack gate (#719) FIRST: on a clustered `C2-fsync` produce to a led partition the gate
/// PARKS the ack (returns [`AckDisposition::Parked`]) and this WITHHOLDS the frame — the data plane
/// flushes it onto this connection's outbox once the ISR quorum has fsync'd the offset, and the session
/// drains it on a later pass ([`EngineAccess::drain_client_acks`]). For every OTHER outcome — and for
/// `Appended` on a SINGLE-NODE / no-cluster broker (the gate returns `None`), a non-`C2-fsync` level, or
/// a non-led partition (the gate returns `WriteNow`) — it writes the SAME bytes immediately, BYTE-FOR-
/// BYTE today's path. A fire-and-forget produce never reaches the gate (its `Appended` is
/// `FireAndForgetAppended`, a no-frame outcome).
///
/// # Single-node byte-identical
/// On a single-node / no-cluster broker `engine.has_client_ack_gate()` is `false` (a cheap local bool,
/// zero work), so the `Appended` arm writes the `PubAck` DIRECTLY — same frame, same order, NO temp
/// allocation, NO lock, byte-for-byte [`write_pub_reply`]. The gate is consulted (and the bytes built
/// for it) ONLY on a clustered serve past bootstrap.
fn write_pub_reply_gated<
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
>(
    engine: &E,
    member_id: MemberId,
    outcome: ProduceOutcome,
    fire_and_forget: bool,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    // Both a fresh `Appended` and a dedup-hit `AppendedDuplicate` must clear the C2-fsync quorum gate
    // before their ack is released: an idempotent RETRY of a C2-fsync produce whose original offset is
    // NOT yet quorum-committed must NOT get an immediate `PubAckDuplicate` for a record that is durable
    // only on the leader (#917). They differ ONLY in the reply FRAME TYPE (`PubAck` vs `PubAckDuplicate`)
    // and the gate keys on the (original) offset, so a duplicate releases exactly when the original is
    // quorum-fsync'd — immediately if it already is. A fire-and-forget produce never yields either
    // outcome (it yields `FireAndForgetAppended`), so this never withholds a no-reply produce.
    let gated = match &outcome {
        ProduceOutcome::Appended(offset) => Some((*offset, FrameType::PubAck)),
        // Only a REPLY-wanting duplicate is gated. Today a fire-and-forget produce never reaches this
        // reply path at all (a QoS-0 publish early-returns into the no-reply L0 batch before a
        // `ParkedPub` is pushed, so `fire_and_forget` is always `false` here). Guard on the flag anyway
        // as defense-in-depth: the actor's dedup path yields `AppendedDuplicate` regardless of the flag
        // (unlike the fresh-append path, which maps a QoS-0 produce to `FireAndForgetAppended`), so a
        // future routing change must not be able to quorum-gate or write a frame for a QoS-0 duplicate.
        ProduceOutcome::AppendedDuplicate(offset) if !fire_and_forget => {
            Some((*offset, FrameType::PubAckDuplicate))
        }
        _ => None,
    };
    if let Some((offset, frame_type)) = gated {
        // SINGLE-NODE / no-cluster FAST PATH (zero added cost): with NO cluster gate the produce-ack is
        // written DIRECTLY into `out`, byte-for-byte today's path — no temp allocation, no lock, no extra
        // work. `has_client_ack_gate` is a cheap local bool (default `false`), so the non-cluster hot
        // path never even builds the bytes the gate would need.
        if !engine.has_client_ack_gate() {
            reply_pub_ack(out, frame_type, offset);
            return Ok(());
        }
        // CLUSTERED path: build the EXACT wire reply bytes the immediate-ack path would write, then let
        // the gate decide whether to write them now or withhold them for quorum-fsync.
        let mut reply_bytes = Vec::with_capacity(11);
        reply_pub_ack(&mut reply_bytes, frame_type, offset);
        match engine.client_ack_disposition(member_id, offset.get(), reply_bytes) {
            // The gate vanished between the bool check and here (a teardown race), or handed the bytes
            // back (non-C2-fsync level, or a partition this node does not lead): write them now,
            // byte-identical.
            None => {
                reply_pub_ack(out, frame_type, offset);
            }
            Some(crate::cluster::dataplane::AckDisposition::WriteNow(bytes)) => {
                out.extend_from_slice(&bytes);
            }
            // A just-parked C2-fsync ack whose quorum was ALREADY met (a fast follower reported first):
            // write the released real replies now, in offset order.
            Some(crate::cluster::dataplane::AckDisposition::WriteNowBatch(frames)) => {
                for f in frames {
                    out.extend_from_slice(&f);
                }
            }
            // Clustered C2-fsync to a led partition, below/at quorum: WITHHOLD the wire reply. The data
            // plane releases it onto this connection's outbox on quorum-fsync; the session drains it on a
            // later pass. No false ack below min_isr (the gate releases nothing).
            Some(crate::cluster::dataplane::AckDisposition::Parked) => {}
            // The partition's parked-ack backlog is at its cap (#864): an unsatisfiable ISR is already
            // withholding the cap's worth of acks and nothing is draining, so the data plane refused to
            // park another rather than grow memory toward OOM. Reply with an explicit, typed error (the
            // honest unavailable-over-unsafe signal) so the producer backs off — NEVER a PubAck (the
            // record is durable on the leader but is NOT quorum-fsync'd, so acking it would be a lie).
            // The connection stays open; the producer can retry once the ISR recovers.
            Some(crate::cluster::dataplane::AckDisposition::Rejected) => {
                reply_err_coded(
                    out,
                    crate::codes::ErrorCode::ERR_NOT_ENOUGH_ISR.as_str(),
                    "not enough in-sync replicas to quorum-commit; retry",
                );
            }
        }
        return Ok(());
    }
    write_pub_reply(outcome, fire_and_forget, out)
}

/// Maps one produce outcome to its wire reply, byte-identical to the pre-pipelining inline match:
/// exactly one frame for a non-fire-and-forget produce (`PubAck`, `PubAckDuplicate`, or a typed
/// `Err`), and NO frame for a fire-and-forget one (#11). A fatal outcome ends the session.
fn write_pub_reply(
    outcome: ProduceOutcome,
    fire_and_forget: bool,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    match outcome {
        ProduceOutcome::Appended(offset) => {
            reply_pub_ack(out, FrameType::PubAck, offset);
            Ok(())
        }
        // A FIRE-AND-FORGET (QoS-0, #11, #402) produce sends NO frame, in BOTH dispositions: when
        // APPENDED durably (the producer fired and forgot; the record is durable via the covering
        // group-commit fsync, exactly like a normal produce, the client simply did not wait for
        // the ack) and when DROPPED by the fire-and-forget token bucket (#336) under load (the
        // QoS-0 producer accepts loss by contract; the drop was counted in
        // `ironbus_fire_and_forget_shed_total`). The connection stays open either way.
        ProduceOutcome::FireAndForgetAppended(_) | ProduceOutcome::FireAndForgetDropped => Ok(()),
        // A BENIGN dedup hit (#33): the `msg_id` was already in the producer's window, so the
        // broker returns the ORIGINAL offset via the NEW PubAckDuplicate frame (the frozen PubAck
        // body is untouched). It is a SUCCESS (`rc = 0`, `duplicate = true`), never an error, so an
        // idempotent retry over a lossy edge link does not loop. The fire-and-forget arm is
        // defense-in-depth (a QoS-0 publish does not reach this reply path today): the actor's dedup
        // path yields `AppendedDuplicate` regardless of the flag, so honor the QoS-0 no-frame contract
        // here, exactly like every other outcome's fire-and-forget arm.
        ProduceOutcome::AppendedDuplicate(offset) => {
            if !fire_and_forget {
                reply_pub_ack(out, FrameType::PubAckDuplicate, offset);
            }
            Ok(())
        }
        // A stale-epoch fence (#33): a zombie session reused an old `producer_id` with an epoch
        // below the broker's known high-water. Reject it with a distinct, stable message; the
        // connection stays open so the producer can re-handshake with a fresh epoch.
        ProduceOutcome::Fenced => {
            if !fire_and_forget {
                reply_err_coded(
                    out,
                    crate::codes::ErrorCode::ERR_PRODUCER_FENCED.as_str(),
                    "fenced: stale producer epoch",
                );
            }
            Ok(())
        }
        // An out-of-order idempotent SEQUENCE (V2-M8): a sequenced publish skipped past the
        // next-expected sequence (the Kafka OutOfOrderSequence rejection), so nothing was appended and
        // a later retry of the skipped seq cannot double-append. Reject it with a distinct, stable
        // message; the connection stays open so the producer can resync from the expected sequence.
        ProduceOutcome::OutOfOrder => {
            if !fire_and_forget {
                reply_err_coded(
                    out,
                    crate::codes::ErrorCode::ERR_OUT_OF_ORDER_SEQUENCE.as_str(),
                    "out-of-order producer sequence",
                );
            }
            Ok(())
        }
        // A fatal error (frozen writer) would fail every future produce, so end the
        // session rather than masquerade as a transient failure.
        ProduceOutcome::Fatal(e) => {
            // The session ends either way; for a fire-and-forget produce even this frame is
            // suppressed (the client detects the close out of band, never a desync).
            if !fire_and_forget {
                reply_err(out, "fatal storage error");
            }
            Err(SessionError::EngineFatal(e))
        }
        // The durable-log byte cap shed (drop-new): a distinct, stable message so a
        // producer can tell a deliberate shed from a transient failure. The connection
        // stays open, so the producer can keep going (a later produce succeeds once
        // retention frees space).
        ProduceOutcome::AtCapacity => {
            if !fire_and_forget {
                reply_err_coded(
                    out,
                    crate::codes::ErrorCode::ERR_AT_CAPACITY.as_str(),
                    "at capacity",
                );
            }
            Ok(())
        }
        // The CoDel load-shed (#68): the broker is overloaded past the controlled-delay target,
        // so this NEW produce was shed to protect tail latency. A distinct, stable message so a
        // producer can tell a latency-load shed from a disk-full shed (`at capacity`) or a
        // transient failure. The connection stays open: a later produce succeeds once the standing
        // delay clears. It NEVER dropped an already-accepted record (the shed is decided before the
        // append), so I2 holds. The structured machine-actionable retry hint (`retry_after_ms` /
        // `shed`) waits on the frozen-protocol extension (#11), per docs/BACKPRESSURE.md; until
        // then the shed rides the existing bare `Err` frame, exactly like the byte-cap shed.
        ProduceOutcome::Shed => {
            if !fire_and_forget {
                reply_err(out, "shed under load");
            }
            Ok(())
        }
        // An fsync-HEADROOM shed (#378): the un-fsynced backlog (the loss window / RAM bound) is
        // at its configured headroom and a group-commit drain could not free it (a relaxed
        // durability level deferring the fsync), so this NEW produce is shed to keep the backlog
        // bounded. A distinct, stable message so a producer can tell it from the CoDel latency
        // shed ("shed under load") and the disk-full byte-cap shed ("at capacity"). The connection
        // stays open (a later produce succeeds once the writer catches up); no accepted record is
        // dropped, so this is reject-new-work only, like the byte-cap shed.
        ProduceOutcome::WalHeadroomShed => {
            if !fire_and_forget {
                reply_err(out, "wal fsync headroom exhausted");
            }
            Ok(())
        }
        ProduceOutcome::Failed(_) => {
            if !fire_and_forget {
                reply_err(out, "produce failed");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::DirectEngine;
    use crate::engine::{DiskFullPolicy, Engine, EngineConfig, Poll};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_core::types::RecordFlags;
    use ironbus_proto::message::{
        decode_deliver, decode_pub_ack, encode_ack, encode_pub, encode_txn_prepare,
        encode_txn_resolve, AckBody, PubBody, PubDedup, TxnPrepareBody, TxnResolveBody,
        PUB_FLAG_ACK_LEVEL_SHIFT, PUB_FLAG_FIRE_AND_FORGET,
    };
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::{Append, LogConfig};
    use std::sync::Arc;

    /// The shared session-test engine config, factored out so the pipelined-window test (#450) can
    /// open the SAME config over a fault-injecting filesystem (to count fsyncs).
    fn test_config() -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
            compression: ironbus_core::compress::Codec::None,
            log: LogConfig::default(),
            lease: LeaseConfig {
                visibility_nanos: 30,
                hard_cap_nanos: 100,
            },
            delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
            max_in_flight: 10,
            consumer_credit: 64,
            consumer_credit_bytes: 0,
            checkpoint_interval: 1024,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
            max_groups: crate::engine::DEFAULT_MAX_GROUPS,
            // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
            max_streams: 0,
            group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
            ram_ceiling_bytes: 0,
            disk_full_policy: DiskFullPolicy::DropNew,
            dedup: ironbus_core::dedup::DedupConfig::default(),
            durability_level: crate::engine::DurabilityLevel::Sync,
            flush_interval_ms: 0,
            flush_max_bytes: 0,
            // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
            // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
            // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
            // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
            default_message_ttl_ms: 0,
            dead_letter_exchange: None,
            dead_letter_expired: false,
        }
    }

    fn engine() -> Engine<InMemoryFs, ManualClock> {
        Engine::open(InMemoryFs::new(), ManualClock::new(), test_config()).unwrap()
    }

    /// Decodes one response frame from the front of `out`.
    fn one_response(out: &[u8]) -> (FrameType, Vec<u8>) {
        match decode_frame(out).unwrap() {
            FrameDecode::Frame { type_tag, body, .. } => {
                (FrameType::from_u8(type_tag).unwrap(), body.to_vec())
            }
            FrameDecode::Incomplete { .. } => panic!("expected a complete response"),
        }
    }

    fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode_frame(ty, body, &mut v).unwrap();
        v
    }

    /// Decodes every complete frame in `out`.
    fn decode_all(out: &[u8]) -> Vec<(FrameType, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut off = 0;
        while off < out.len() {
            match decode_frame(&out[off..]).unwrap() {
                FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed,
                } => {
                    frames.push((FrameType::from_u8(type_tag).unwrap(), body.to_vec()));
                    off += consumed;
                }
                FrameDecode::Incomplete { .. } => break,
            }
        }
        frames
    }

    fn produce<C: Clock + Clone>(e: &DirectEngine<InMemoryFs, C>, payload: &[u8]) {
        e.engine_mut()
            .produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
    }

    fn engine_with(
        clock: Arc<ManualClock>,
        max_deliver: u32,
    ) -> Engine<InMemoryFs, Arc<ManualClock>> {
        Engine::open(
            InMemoryFs::new(),
            clock,
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(max_deliver, false, vec![]).unwrap(),
                max_in_flight: 10,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    /// An engine over a shared clock with a small segment cap, a durable-log byte cap, and the
    /// disk-full DROP-OLDEST policy, for the below-earliest truncation wire test (#82, #84).
    fn engine_drop_oldest(
        clock: Arc<ManualClock>,
        max_total_bytes: u64,
    ) -> Engine<InMemoryFs, Arc<ManualClock>> {
        Engine::open(
            InMemoryFs::new(),
            clock,
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig {
                    max_segment_bytes: 160,
                    max_total_bytes,
                    ..LogConfig::default()
                },
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 64,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropOldest,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn a_truncated_consumer_gets_exactly_one_truncated_frame_and_stays_connected() {
        // Under DropOldest, a stuck consumer whose records were force-reaped gets EXACTLY ONE
        // Truncated frame on its next fetch, the connection stays open, and a later fetch delivers
        // normally without re-truncating the same gap.
        let clock = Arc::new(ManualClock::new());
        // Measure one record's framed bytes, then size the cap to ~4 records.
        let one = {
            let probe = DirectEngine::new(engine_drop_oldest(Arc::clone(&clock), 0));
            produce(&probe, &[0xab; 16]);
            let bytes = probe.engine_mut().durable_record_bytes();
            bytes
        };
        let e = DirectEngine::new(engine_drop_oldest(Arc::clone(&clock), 4 * one));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();

        // Produce offset 0, then the session leases it (a stuck consumer: it never acks).
        produce(&e, &[0xab; 16]);
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(delivered_tokens(&out).len(), 1, "leased offset 0");
        // The producer races past the cap so DropOldest force-reaps the leased records.
        for _ in 0..20 {
            produce(&e, &[0xab; 16]);
        }
        assert!(
            e.engine_mut().earliest_retained_offset().get() > 0,
            "the leased records were force-reaped"
        );

        // The next fetch returns EXACTLY ONE Truncated frame (then a FlowEnd terminator), and the
        // session stays open (process returns Ok). The first Truncated consumes a credit slot, so
        // with a credit of 1 the batch is just the advisory.
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .expect("the session stays open after a truncation");
        let frames = decode_all(&out);
        let truncated: Vec<_> = frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::Truncated)
            .collect();
        assert_eq!(
            truncated.len(),
            1,
            "exactly one Truncated frame: {frames:?}"
        );
        // The advisory body decodes to the new earliest-retained offset and the skipped count.
        let body = ironbus_proto::message::decode_truncated(&truncated[0].1)
            .expect("valid Truncated body");
        assert_eq!(
            body.earliest_retained,
            e.engine_mut().earliest_retained_offset().get()
        );
        assert!(body.skipped > 0, "the consumer skipped a non-empty span");
        assert_eq!(
            frames.last().map(|(ty, _)| *ty),
            Some(FrameType::FlowEnd),
            "the batch still terminates with FlowEnd"
        );

        // A later fetch delivers normally and does NOT emit another Truncated frame for the gap.
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames2 = decode_all(&out);
        assert!(
            !frames2.iter().any(|(ty, _)| *ty == FrameType::Truncated),
            "no re-truncation of the same gap: {frames2:?}"
        );
        assert!(
            frames2.iter().any(|(ty, _)| *ty == FrameType::Deliver),
            "delivery resumes from the oldest retained record: {frames2:?}"
        );
    }

    /// A `Connect` body that advertises the gap-marker capability (#346).
    fn gap_marker_connect_body() -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                requested_credit: None,
                requested_credit_bytes: None,
                wants_gap_marker: true,
                default_ack_level: None,
                understands_streaming: false,
                default_tier: None,
                understands_deliver_batch: false,
                understands_streams: false,
                understands_compressed_delivery: false,
            },
            &mut body,
        );
        body
    }

    #[test]
    fn the_info_confirms_the_gap_marker_capability_only_when_the_client_advertises_it() {
        // The server confirms the gap-marker capability in Info iff the client advertised it (#346):
        // an old (empty) Connect gets gap_marker=false, an advertising Connect gets gap_marker=true.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_drop_oldest(Arc::clone(&clock), 0));

        let mut s_old = Session::new();
        let mut out = Vec::new();
        s_old
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Info);
        assert!(
            !ironbus_proto::message::decode_info(&body)
                .unwrap()
                .gap_marker,
            "an old (empty) Connect is NOT confirmed for gap markers"
        );

        let mut s_new = Session::new();
        out.clear();
        s_new
            .process(
                &e,
                &frame(FrameType::Connect, &gap_marker_connect_body()),
                &mut out,
            )
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Info);
        assert!(
            ironbus_proto::message::decode_info(&body)
                .unwrap()
                .gap_marker,
            "an advertising Connect IS confirmed for gap markers"
        );
    }

    #[test]
    fn a_gap_marker_consumer_gets_a_gap_marker_not_truncated_with_the_exact_range_and_reason() {
        // TEETH (#346): a consumer that negotiated the gap marker, reading across a force-reaped
        // (trimmed) span, receives EXACTLY ONE GapMarker (tag 21) and NO legacy Truncated frame
        // (no double-signal); the marker's [from, to) and reason match the reaped span, delivery
        // resumes at `to`, and a later contiguous fetch emits NO spurious marker.
        let clock = Arc::new(ManualClock::new());
        let one = {
            let probe = DirectEngine::new(engine_drop_oldest(Arc::clone(&clock), 0));
            produce(&probe, &[0xab; 16]);
            let bytes = probe.engine_mut().durable_record_bytes();
            bytes
        };
        let e = DirectEngine::new(engine_drop_oldest(Arc::clone(&clock), 4 * one));
        let mut s = Session::new();
        let mut out = Vec::new();
        // Connect WITH the gap-marker capability.
        s.process(
            &e,
            &frame(FrameType::Connect, &gap_marker_connect_body()),
            &mut out,
        )
        .unwrap();

        // Lease offset 0 (a stuck consumer: the cursor sits at 0), then race the producer past the
        // cap so DropOldest force-reaps the leased prefix.
        produce(&e, &[0xab; 16]);
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(delivered_tokens(&out).len(), 1, "leased offset 0");
        for _ in 0..20 {
            produce(&e, &[0xab; 16]);
        }
        let earliest = e.engine_mut().earliest_retained_offset().get();
        assert!(earliest > 0, "the leased records were force-reaped");

        // The next fetch returns EXACTLY ONE GapMarker and ZERO Truncated frames.
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .expect("the session stays open after a gap");
        let frames = decode_all(&out);
        let markers: Vec<_> = frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::GapMarker)
            .collect();
        assert_eq!(markers.len(), 1, "exactly one GapMarker frame: {frames:?}");
        assert!(
            !frames.iter().any(|(ty, _)| *ty == FrameType::Truncated),
            "a gap-marker consumer is NEVER also sent the legacy Truncated (no double-signal): {frames:?}"
        );
        let marker =
            ironbus_proto::message::decode_gap_marker(&markers[0].1).expect("valid GapMarker body");
        // The cursor was at 0 (it leased but never acked offset 0), so the hole is [0, earliest).
        assert_eq!(marker.from, 0, "the hole begins where the cursor was");
        assert_eq!(marker.to, earliest, "delivery resumes at earliest-retained");
        assert!(marker.to > marker.from, "the skipped span is non-empty");
        assert_eq!(
            marker.reason,
            ironbus_proto::message::gap_reason::TRIMMED,
            "a force-reap trim is reason TRIMMED"
        );
        assert_eq!(
            marker.bytes_skipped, 0,
            "a trim is byte-untracked; the span is the record count to-from"
        );
        assert_eq!(
            frames.last().map(|(ty, _)| *ty),
            Some(FrameType::FlowEnd),
            "the batch still terminates with FlowEnd"
        );

        // A later fetch delivers normally and emits NO spurious gap marker for the same gap.
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames2 = decode_all(&out);
        assert!(
            !frames2.iter().any(|(ty, _)| *ty == FrameType::GapMarker),
            "no re-marking of the same gap: {frames2:?}"
        );
        assert!(
            frames2.iter().any(|(ty, _)| *ty == FrameType::Deliver),
            "delivery resumes from the oldest retained record: {frames2:?}"
        );
    }

    #[test]
    fn a_normal_contiguous_delivery_emits_no_gap_marker_for_a_gap_marker_consumer() {
        // TEETH (#346): a gap-marker consumer reading a contiguous stream (no trim) sees ONLY
        // deliveries, never a spurious GapMarker. The marker is for real holes only.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_drop_oldest(Arc::clone(&clock), 0));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(FrameType::Connect, &gap_marker_connect_body()),
            &mut out,
        )
        .unwrap();
        for _ in 0..3 {
            produce(&e, &[0xcd; 8]);
        }
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames = decode_all(&out);
        assert!(
            !frames.iter().any(|(ty, _)| *ty == FrameType::GapMarker),
            "no spurious gap marker on a contiguous stream: {frames:?}"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|(ty, _)| *ty == FrameType::Deliver)
                .count(),
            3,
            "all three contiguous records delivered: {frames:?}"
        );
    }

    /// Opens an engine with a tiny segment cap (so a handful of keyed produces roll into several
    /// sealed segments) and OPT-IN key compaction enabled (#337), so the off-hot-path compactor can
    /// remove superseded versions and leave a SPARSE-OFFSET interior hole for the #411 tests.
    fn compacting_engine() -> Engine<InMemoryFs, ManualClock> {
        let mut e = Engine::open(
            InMemoryFs::new(),
            ManualClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig {
                    max_segment_bytes: 200,
                    ..LogConfig::default()
                },
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 64,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
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
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap();
        e.set_compaction_config(ironbus_storage::compaction::CompactionConfig::enabled());
        e
    }

    /// Produces a churning keyed workload across several rolled segments, then runs the off-hot-path
    /// compaction pass, leaving an INTERIOR sparse-offset hole: only the latest version per key (plus
    /// the one-shot survivors) remains, so a poll that drains the log crosses at least one
    /// compacted-away run.
    fn produce_compacted_log<C: Clock + Clone>(e: &DirectEngine<InMemoryFs, C>) {
        // A one-shot survivor at offset 0, then a churning key whose old versions are superseded,
        // then more one-shot survivors: this puts a compacted-away run BETWEEN present records, so the
        // consumer reads ACROSS an interior hole (not just a leading one).
        produce_keyed(e, b"head", b"v");
        for v in 0..8u8 {
            produce_keyed(e, b"churn", &[v; 16]);
        }
        produce_keyed(e, b"tail", b"v");
        // One more produce after the rolls triggers the reaper-then-compactor pass (off the hot path).
        produce_keyed(e, b"flush", b"v");
    }

    /// The ground-truth compacted holes the workload leaves, discovered by draining a FRESH probe
    /// engine built and produced IDENTICALLY (same config, same in-memory FS, same deterministic key
    /// order) at the ENGINE level: each `Poll::Compacted { from, to }` is one half-open hole. This
    /// keeps the test honest WITHOUT adding a test-only read accessor to the engine: the session is
    /// asserted to emit a `GapMarker` for exactly these spans.
    fn compacted_holes_via_probe() -> Vec<(u64, u64)> {
        let probe = DirectEngine::new(compacting_engine());
        produce_compacted_log(&probe);
        let mut holes = Vec::new();
        loop {
            // Take the poll result by VALUE (the `RefMut` borrow ends at the semicolon) so the `ack`
            // below can re-borrow the engine without aliasing.
            let outcome = probe.engine_mut().poll(0).unwrap();
            match outcome {
                Poll::Message(d) => {
                    probe.engine_mut().ack(&d.token);
                }
                Poll::Compacted { from, to } => holes.push((from.get(), to.get())),
                Poll::Idle => break,
                other => panic!("unexpected probe poll outcome: {other:?}"),
            }
        }
        holes
    }

    #[test]
    #[allow(clippy::too_many_lines)] // a thorough end-to-end teeth test for the #411 COMPACTED marker
    fn a_gap_marker_consumer_reading_across_a_compacted_hole_gets_one_compacted_marker() {
        // TEETH (#411): a gap-marker-capable consumer draining a COMPACTED log receives a GapMarker
        // with reason COMPACTED for the interior sparse-offset hole, NOT a TRIMMED marker, NOT a
        // legacy Truncated, and NOT a loss; the marker's [from, to) is the exact compacted-away run,
        // delivery resumes at `to`, and every surviving record is still delivered.
        let e = DirectEngine::new(compacting_engine());
        produce_compacted_log(&e);
        let holes = compacted_holes_via_probe();
        assert!(
            !holes.is_empty(),
            "the workload must leave at least one compacted-away interior hole"
        );

        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(FrameType::Connect, &gap_marker_connect_body()),
            &mut out,
        )
        .unwrap();
        // Drain the whole log in one generous batch.
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &64u32.to_le_bytes()), &mut out)
            .expect("the session stays open across a compacted hole");
        let frames = decode_all(&out);

        // EXACTLY the holes are surfaced as COMPACTED GapMarkers, and NO legacy Truncated frame.
        let markers: Vec<_> = frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::GapMarker)
            .map(|(_, b)| ironbus_proto::message::decode_gap_marker(b).expect("valid GapMarker"))
            .collect();
        assert_eq!(
            markers.len(),
            holes.len(),
            "exactly one GapMarker per compacted hole: {frames:?}"
        );
        assert!(
            !frames.iter().any(|(ty, _)| *ty == FrameType::Truncated),
            "a compacted hole is NEVER the legacy Truncated (no double-signal): {frames:?}"
        );
        for (marker, &(from, to)) in markers.iter().zip(holes.iter()) {
            assert_eq!(
                marker.reason,
                ironbus_proto::message::gap_reason::COMPACTED,
                "a compaction hole is reason COMPACTED, not TRIMMED: {marker:?}"
            );
            assert_eq!(
                marker.from, from,
                "the marker begins at the first absent offset"
            );
            assert_eq!(marker.to, to, "delivery resumes at the next present offset");
            assert!(marker.to > marker.from, "the compacted span is non-empty");
            assert_eq!(
                marker.bytes_skipped, 0,
                "a compaction hole is byte-untracked; the span is the record count to-from"
            );
        }
        // Independently pin the span against the actual DELIVERY STREAM, NOT `holes` (which the probe
        // builds from the same engine code, so an engine-side off-by-one in `to` would mask itself,
        // #411 review): (a) the first Deliver after each COMPACTED marker resumes at exactly `to`, and
        // (b) no compacted-away offset in any [from, to) is ever delivered.
        let delivered: Vec<u64> = frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::Deliver)
            .map(|(_, b)| {
                ironbus_proto::message::decode_deliver(b)
                    .expect("valid Deliver")
                    .offset
            })
            .collect();
        let mut pending_to: Option<u64> = None;
        for (ty, b) in &frames {
            match *ty {
                FrameType::GapMarker => {
                    pending_to = Some(
                        ironbus_proto::message::decode_gap_marker(b)
                            .expect("valid GapMarker")
                            .to,
                    );
                }
                FrameType::Deliver => {
                    let off = ironbus_proto::message::decode_deliver(b)
                        .expect("valid Deliver")
                        .offset;
                    if let Some(to) = pending_to.take() {
                        assert_eq!(
                            off, to,
                            "delivery resumes at the marker `to`, verified against the stream not the probe"
                        );
                    }
                }
                _ => {}
            }
        }
        for marker in &markers {
            assert!(
                !delivered.iter().any(|&o| o >= marker.from && o < marker.to),
                "no compacted-away offset in [{}, {}) is delivered: {delivered:?}",
                marker.from,
                marker.to
            );
        }

        // Every survivor was still delivered (the latest-value-per-key view is intact).
        assert!(
            frames
                .iter()
                .filter(|(ty, _)| *ty == FrameType::Deliver)
                .count()
                >= 3,
            "the survivors (head, latest churn, tail, flush) are still delivered: {frames:?}"
        );

        // A later fetch emits NO spurious marker for the same gap (the cursor advanced past it once).
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &64u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames2 = decode_all(&out);
        assert!(
            !frames2.iter().any(|(ty, _)| *ty == FrameType::GapMarker),
            "no re-marking of the same compacted hole: {frames2:?}"
        );
    }

    #[test]
    fn a_non_capable_consumer_reading_across_a_compacted_hole_advances_silently() {
        // TEETH (#411): a consumer that did NOT negotiate the gap marker, draining the SAME compacted
        // log, advances SILENTLY across the hole: NO GapMarker, NO legacy Truncated, NO error. A
        // compacted hole is not a loss, so a non-capable consumer's stream is byte-for-byte unchanged
        // (the backward-compatible silent-advance the engine had before #411).
        let e = DirectEngine::new(compacting_engine());
        produce_compacted_log(&e);
        assert!(
            !compacted_holes_via_probe().is_empty(),
            "the workload must leave a compacted hole"
        );

        // Connect WITHOUT the gap-marker capability (an old, empty Connect).
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &64u32.to_le_bytes()), &mut out)
            .expect("the session stays open across a compacted hole");
        let frames = decode_all(&out);
        assert!(
            !frames.iter().any(|(ty, _)| *ty == FrameType::GapMarker),
            "a non-capable consumer is NEVER sent a GapMarker for a compacted hole: {frames:?}"
        );
        assert!(
            !frames.iter().any(|(ty, _)| *ty == FrameType::Truncated),
            "a compacted hole is NOT a trim; a non-capable consumer gets no Truncated either: {frames:?}"
        );
        // The survivors still all arrive, in ascending order, ending with FlowEnd: the silent advance
        // crossed the hole without dropping a survivor.
        let delivered: Vec<u64> = frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::Deliver)
            .map(|(_, b)| decode_deliver(b).expect("valid Deliver").offset)
            .collect();
        assert!(delivered.len() >= 3, "all survivors delivered: {frames:?}");
        let mut sorted = delivered.clone();
        sorted.sort_unstable();
        assert_eq!(delivered, sorted, "survivors delivered in ascending order");
        assert_eq!(
            frames.last().map(|(ty, _)| *ty),
            Some(FrameType::FlowEnd),
            "the batch still terminates with FlowEnd"
        );
    }

    /// Sends one acknowledgement op and returns the status body, asserting the reply is a
    /// single `AckStatus` frame.
    fn ack_reply<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
        op: AckOp,
        offset: u64,
        generation: u64,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        encode_ack(
            &AckBody {
                op,
                offset,
                generation,
                delay_ms: 0,
            },
            &mut body,
        );
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Ack, &body), &mut out)
            .unwrap();
        let replies = decode_all(&out);
        assert_eq!(replies.len(), 1, "exactly one reply frame");
        assert_eq!(
            replies[0].0,
            FrameType::AckStatus,
            "expected AckStatus, got {:?}",
            replies[0].0
        );
        replies[0].1.clone()
    }

    #[test]
    fn progress_then_cap_then_term_over_the_wire() {
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&e, b"x");

        // Fetch to lease offset 0 (deadline = now(0) + 30, hard cap at 100).
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let toks = delivered_tokens(&out);
        assert_eq!(toks.len(), 1);
        let (offset, generation) = toks[0];

        // Progress at t=25 extends the lease: status byte 1.
        clock.advance_monotonic_nanos(25);
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Progress, offset, generation),
            vec![1]
        );
        // Progress at t=100 (attempt_start 0 + hard cap 100) cannot extend: status byte 2.
        clock.advance_monotonic_nanos(75);
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Progress, offset, generation),
            vec![2]
        );
        // Term drops it (status byte 1) and commits past it.
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Term, offset, generation),
            vec![1]
        );
        assert_eq!(e.engine_mut().committed_offset().get(), 1);
        // A term of the now-stale token is fenced: status byte 0.
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Term, offset, generation),
            vec![0]
        );
    }

    #[test]
    fn term_before_connect_is_rejected() {
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        let mut s = Session::new();
        let mut body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Term,
                offset: 0,
                generation: 0,
                delay_ms: 0,
            },
            &mut body,
        );
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Ack, &body), &mut out)
            .unwrap();
        let replies = decode_all(&out);
        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies[0].0,
            FrameType::Err,
            "term before connect is rejected"
        );
    }

    /// Decodes every Deliver frame in a Flow response and returns (offset, generation).
    fn delivered_tokens(out: &[u8]) -> Vec<(u64, u64)> {
        decode_all(out)
            .into_iter()
            .filter(|(ty, _)| *ty == FrameType::Deliver)
            .map(|(_, body)| {
                let d = decode_deliver(&body).unwrap();
                (d.offset, d.generation)
            })
            .collect()
    }

    #[test]
    fn an_unacked_fetched_message_redelivers_after_the_visibility_timeout() {
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&e, b"x");

        // First fetch delivers and leases it (deadline = now(0) + 30).
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let first = delivered_tokens(&out);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, 0);

        // Re-fetch before the timeout: the lease is still held, nothing redelivers.
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert!(
            delivered_tokens(&out).is_empty(),
            "in-flight, not redelivered yet"
        );

        // Advance past the visibility timeout: now it redelivers with a NEW generation.
        clock.advance_monotonic_nanos(40);
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let second = delivered_tokens(&out);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].0, 0);
        assert_ne!(second[0].1, first[0].1, "redelivery fences the old token");

        // The session map now holds only the NEW generation, so acking the OLD one is fenced
        // by the session guard (status 0, nothing committed); the current one commits.
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Ack, first[0].0, first[0].1),
            vec![0u8],
            "the stale generation is fenced by the session guard"
        );
        assert_eq!(e.engine_mut().committed_offset().get(), 0);
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Ack, second[0].0, second[0].1),
            vec![1u8]
        );
        assert_eq!(e.engine_mut().committed_offset().get(), 1);
    }

    #[test]
    fn a_poison_message_is_parked_and_skipped_in_the_fetch() {
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 1)); // max_deliver = 1
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&e, b"poison");

        // First fetch delivers (delivery 1).
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(delivered_tokens(&out).len(), 1);

        // Expire it; the next fetch's claim is delivery 2 > max_deliver, so it is parked
        // (committed past) and NOT delivered: an empty batch (FlowEnd with no Deliver frames).
        clock.advance_monotonic_nanos(40);
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert!(
            delivered_tokens(&out).is_empty(),
            "the poison message is not delivered"
        );
        assert_eq!(
            e.engine_mut().committed_offset().get(),
            1,
            "the poison message is parked past"
        );
    }

    #[test]
    fn flow_fetches_messages_as_deliver_frames_then_flow_end() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&e, b"a");
        produce(&e, b"b");
        out.clear();
        // Fetch up to 5: two messages are available, then the batch terminates with FlowEnd(2).
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames = decode_all(&out);
        assert_eq!(
            frames.len(),
            3,
            "two Deliver frames then a FlowEnd terminator"
        );
        assert_eq!(frames[0].0, FrameType::Deliver);
        let d0 = decode_deliver(&frames[0].1).unwrap();
        assert_eq!(d0.offset, 0);
        assert_eq!(d0.payload, b"a");
        assert_eq!(frames[1].0, FrameType::Deliver);
        assert_eq!(decode_deliver(&frames[1].1).unwrap().payload, b"b");
        assert_eq!(frames[2].0, FrameType::FlowEnd);
        assert_eq!(
            frames[2].1,
            2u32.to_le_bytes(),
            "FlowEnd carries the delivered count"
        );
    }

    /// Reads the payloads of the `Deliver` frames in a response, ignoring the `FlowEnd`.
    fn delivered_payloads(out: &[u8]) -> Vec<Vec<u8>> {
        decode_all(out)
            .iter()
            .filter(|(t, _)| *t == FrameType::Deliver)
            .map(|(_, b)| decode_deliver(b).unwrap().payload.to_vec())
            .collect()
    }

    // ---- credit auto-tune over the wire (#552) ----

    /// An engine whose per-GROUP window and per-consumer credit CEILING are both high, so the #552
    /// auto-tune (which grows the per-consumer count window from the 64 floor toward the ceiling) is
    /// the binding constraint a test can observe — `max_in_flight` is generous so the per-group window
    /// never masks the per-consumer window, and `consumer_credit` (the ceiling) is well above 64 so the
    /// window has room to grow. `consumer_credit_bytes` is the caller's choice (0 = byte budget off).
    fn autotune_engine(consumer_credit_bytes: u64) -> Engine<InMemoryFs, ManualClock> {
        Engine::open(
            InMemoryFs::new(),
            ManualClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                max_in_flight: 100_000,
                consumer_credit: 2048,
                consumer_credit_bytes,
                ..test_config()
            },
        )
        .unwrap()
    }

    /// Connects + drives one Flow asking for `requested` credit, ACKING every delivered message (so the
    /// next Flow has a fully-drained window). Returns the count delivered in this batch. Repeated calls
    /// are the "keeping-up consumer": each one drains its whole window, which is the #552 keep-up signal
    /// that grows the window.
    fn flow_and_ack_all<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
        requested: u32,
    ) -> usize {
        let mut out = Vec::new();
        s.process(
            e,
            &frame(FrameType::Flow, &requested.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let toks = delivered_tokens(&out);
        for (offset, generation) in &toks {
            ack_reply(s, e, AckOp::Ack, *offset, *generation);
        }
        toks.len()
    }

    #[test]
    fn a_keeping_up_consumers_window_grows_past_64_toward_the_ceiling() {
        // THE CORE #552 CLAIM over the wire: a consumer that keeps draining its whole window grows the
        // per-consumer count window WELL past the old fixed 64, so a single Flow can eventually deliver
        // more than 64 records — throughput is no longer pinned at 64/RTT. With a static 64 ceiling this
        // would be impossible (a Flow could never exceed 64 in one batch).
        let e = DirectEngine::new(autotune_engine(0));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        // Seed plenty so the window, not the log, is the binding constraint every round.
        for i in 0..5000u32 {
            produce(&e, &i.to_le_bytes());
        }
        // Round 0 is capped at the floor (64): ask for a huge credit; only the window binds.
        let first = flow_and_ack_all(&mut s, &e, 100_000);
        assert_eq!(first, 64, "the first batch is bounded by the 64 floor");
        // Keep draining full windows; the window grows by the step each round.
        let mut last = first;
        for _ in 0..10 {
            last = flow_and_ack_all(&mut s, &e, 100_000);
        }
        assert!(
            last > 64,
            "a keeping-up consumer's window must grow past the old 64 floor, got a {last}-record batch"
        );
    }

    #[test]
    fn the_byte_budget_stays_a_hard_cap_as_the_window_grows() {
        // #552 RAM-BOUND: even as the COUNT window auto-tunes upward, the per-consumer BYTE budget is a
        // firm cap on in-flight bytes. With a budget of 10 * payload bytes, a Flow never leases more than
        // ~10 unacked messages regardless of how high the count window grows, so in-flight RAM stays
        // bounded by the byte budget, NOT the (growing) count.
        let payload = [0u8; 100];
        let budget = 10 * 100; // 10 messages' worth of payload bytes
        let e = DirectEngine::new(autotune_engine(budget));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        for _ in 0..5000u32 {
            produce(&e, &payload);
        }
        // Drain many full windows WITHOUT acking on the LAST one, so we can read the in-flight set the
        // byte budget actually allowed. First grow the window over several acked rounds.
        for _ in 0..20 {
            flow_and_ack_all(&mut s, &e, 100_000);
        }
        // Now a Flow that does NOT ack: the delivered (and thus leased) count is bounded by the byte
        // budget's floor-of-one semantics (at-or-below-budget delivery overshoots by at most one), so
        // even with a window grown far past 64 the batch is ~the byte-budget's worth, not the window's.
        out.clear();
        s.process(
            &e,
            &frame(FrameType::Flow, &100_000u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let delivered = delivered_payloads(&out).len();
        assert!(
            delivered <= 11,
            "the byte budget (10 msgs) must cap in-flight regardless of the grown count window, got {delivered}"
        );
        assert!(delivered >= 1, "the floor-of-one always makes progress");
    }

    #[test]
    fn a_non_draining_consumer_backs_the_window_off() {
        // #552 BACK-OFF: a consumer that NACKs (cannot process) sheds its grown window back toward the
        // floor. After growing the window, a burst of nacks must shrink the per-batch size a later
        // fully-acked Flow can reach — the window halved.
        let e = DirectEngine::new(autotune_engine(0));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        for _ in 0..5000u32 {
            produce(&e, b"p");
        }
        // Grow the window well past 64.
        let mut grown = 0;
        for _ in 0..12 {
            grown = flow_and_ack_all(&mut s, &e, 100_000);
        }
        assert!(
            grown > 64,
            "precondition: the window grew past 64, got {grown}"
        );
        // A non-draining round: Flow then NACK every delivered message (the consumer could not process).
        out.clear();
        s.process(
            &e,
            &frame(FrameType::Flow, &100_000u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        for (offset, generation) in delivered_tokens(&out) {
            ack_reply(&mut s, &e, AckOp::Nack, offset, generation);
        }
        // The window backed off (each nack halves it), so a subsequent fully-acked Flow delivers FEWER
        // than the grown peak — backpressure shed the window.
        let after = flow_and_ack_all(&mut s, &e, 100_000);
        assert!(
            after < grown,
            "a non-draining (nacking) consumer must back the window off below its grown peak: \
             grown={grown}, after-backoff={after}"
        );
    }

    #[test]
    fn the_autotune_preserves_at_least_once_no_message_is_lost() {
        // #552 AT-LEAST-ONCE: a larger auto-tuned window only means more in-flight at once; every record
        // is still leased and acked exactly once. Drain the WHOLE log through the auto-tuning path and
        // assert every produced offset arrives exactly once, in order, with none lost or duplicated.
        let total = 1000u32;
        let e = DirectEngine::new(autotune_engine(0));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        for i in 0..total {
            produce(&e, &i.to_le_bytes());
        }
        let mut seen: Vec<u32> = Vec::new();
        // Drain until the log is empty, acking every record (the keeping-up path that also grows the
        // window). The growing window changes batch sizes but never which records are delivered.
        loop {
            out.clear();
            s.process(
                &e,
                &frame(FrameType::Flow, &100_000u32.to_le_bytes()),
                &mut out,
            )
            .unwrap();
            let toks = delivered_tokens(&out);
            if toks.is_empty() {
                break;
            }
            for (offset, generation) in &toks {
                seen.push(u32::try_from(*offset).unwrap());
                ack_reply(&mut s, &e, AckOp::Ack, *offset, *generation);
            }
        }
        let expected: Vec<u32> = (0..total).collect();
        assert_eq!(
            seen, expected,
            "every produced record must arrive exactly once, in order (at-least-once preserved)"
        );
    }

    #[test]
    fn an_explicit_low_consumer_credit_is_byte_for_byte_the_historical_fixed_window() {
        // A consumer whose negotiated ceiling is the historical 64 (the `test_config` default) never
        // grows past 64: the auto-tune floor == ceiling == 64, so its behavior is byte-for-byte the
        // pre-#552 fixed window. This pins that the auto-tune NEVER over-delivers past a configured cap.
        let e = DirectEngine::new(engine()); // test_config(): consumer_credit 64, max_in_flight 10
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        for _ in 0..500u32 {
            produce(&e, b"p");
        }
        // Even after many fully-drained rounds, a Flow never delivers more than the per-group window (10
        // here) and never exceeds the 64 ceiling — there is no room above 64 to grow into.
        for _ in 0..20 {
            let n = flow_and_ack_all(&mut s, &e, 100_000);
            assert!(
                n <= 64,
                "a 64-ceiling consumer must never exceed 64 in a batch, got {n}"
            );
        }
    }

    #[test]
    fn two_groups_over_the_wire_each_see_every_message() {
        // Broadcast fan-out over the wire (#9, golden-path #133 step 4): two connections
        // subscribed to different groups each independently receive every message. Neither
        // acks, so if the groups shared one cursor and lease set the second would find the
        // offsets in-flight and get nothing; getting both proves the groups are independent.
        let e = DirectEngine::new(engine());
        produce(&e, b"a");
        produce(&e, b"b");
        for group in [&b"alpha"[..], &b"beta"[..]] {
            let mut s = Session::new();
            let mut out = Vec::new();
            s.process(&e, &frame(FrameType::Connect, b""), &mut out)
                .unwrap();
            out.clear();
            s.process(&e, &frame(FrameType::Sub, group), &mut out)
                .unwrap();
            assert_eq!(one_response(&out).0, FrameType::Ok, "SUB is acked");
            out.clear();
            s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
                .unwrap();
            assert_eq!(
                delivered_payloads(&out),
                vec![b"a".to_vec(), b"b".to_vec()],
                "group {group:?} independently sees the whole log"
            );
        }
    }

    #[test]
    fn broadcast_cumulative_ack_releases_the_per_connection_leases_it_commits() {
        // Regression for the credit leak in the #288 bulk-commit path: cumulative_ack committed the
        // engine cursor but did NOT remove the committed offsets from the connection's `leased` set,
        // the way per-message ack/nack/term do. A broadcast consumer that fetches-then-cumulative-acks
        // therefore only ever GREW `leased`, and once leased.len() reached its credit ceiling its
        // fetches starved (remaining message credit = ceiling - leased.len()). The ack must release them.
        use ironbus_proto::message::{encode_cumulative_ack, CumulativeAckBody};
        let e = DirectEngine::new(engine());
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&e, p);
        }
        e.with(|eng| eng.set_broadcast_in("g", true))
            .unwrap()
            .unwrap();
        let mut a = connect_and_sub(&e, MemberId::new(1), b"g");
        let mut out = Vec::new();
        // A fetch leases offsets 0, 1, 2 into the connection's `leased` set.
        a.process(&e, &frame(FrameType::Flow, &3u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "three records leased"
        );
        assert_eq!(
            a.leased.len(),
            3,
            "three leases held before the cumulative ack"
        );
        // Cumulative ack up to 3 (exclusive) commits 0,1,2 AND must release their leases.
        out.clear();
        let mut body = Vec::new();
        encode_cumulative_ack(
            &CumulativeAckBody {
                up_to: 3,
                group: b"g",
            },
            &mut body,
        );
        a.process(&e, &frame(FrameType::CumulativeAck, &body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "broadcast ack is Ok");
        assert_eq!(
            a.leased.len(),
            0,
            "the committed leases are released, restoring the connection's in-flight credit"
        );
        // Not starved: the consumer keeps fetching, and the uncommitted offset 3 is delivered.
        out.clear();
        a.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"d".to_vec()],
            "fetch still works after the bulk ack -- the credit was reclaimed"
        );
    }

    #[test]
    fn cumulative_ack_over_the_wire_commits_a_broadcast_group_and_rejects_a_work_group() {
        // The tag-19 CumulativeAck verb (#288) end to end through the session: the body carries its
        // own group name and the exclusive `up_to`. A group marked broadcast accepts it (reply Ok and
        // the cursor moves); a competing group is rejected with a typed Err and its cursor is
        // untouched; a re-ack is an idempotent Ok no-op.
        use ironbus_proto::message::{encode_cumulative_ack, CumulativeAckBody};
        let e = DirectEngine::new(engine());
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&e, p);
        }
        // Mark the "bcast" group broadcast server-side (the v1 mode-wiring seam).
        e.with(|eng| eng.set_broadcast_in("bcast", true))
            .unwrap()
            .unwrap();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        // Cumulative ack the broadcast group up to 3 (exclusive): reply Ok, cursor moves to 3.
        let mut body = Vec::new();
        encode_cumulative_ack(
            &CumulativeAckBody {
                up_to: 3,
                group: b"bcast",
            },
            &mut body,
        );
        s.process(&e, &frame(FrameType::CumulativeAck, &body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "broadcast ack is Ok");
        assert_eq!(
            e.with(|eng| eng.committed_offset_in("bcast")).unwrap(),
            Offset::new(3)
        );
        // A re-ack at a lower offset is an idempotent Ok no-op (no regression).
        out.clear();
        let mut body = Vec::new();
        encode_cumulative_ack(
            &CumulativeAckBody {
                up_to: 1,
                group: b"bcast",
            },
            &mut body,
        );
        s.process(&e, &frame(FrameType::CumulativeAck, &body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "re-ack is Ok");
        assert_eq!(
            e.with(|eng| eng.committed_offset_in("bcast")).unwrap(),
            Offset::new(3),
            "no regression"
        );
        // A competing group (default, never marked broadcast) is rejected with a typed Err and its
        // cursor is untouched, so the work-group safety trap holds over the wire too (#63).
        out.clear();
        let mut body = Vec::new();
        encode_cumulative_ack(
            &CumulativeAckBody {
                up_to: 2,
                group: b"",
            },
            &mut body,
        );
        s.process(&e, &frame(FrameType::CumulativeAck, &body), &mut out)
            .unwrap();
        let (ty, msg) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "a work-group cumulative ack is rejected"
        );
        assert!(
            String::from_utf8_lossy(&msg).contains("competing work-group"),
            "the typed reason is surfaced: {}",
            String::from_utf8_lossy(&msg)
        );
        assert_eq!(
            e.with(|eng| eng.committed_offset()).unwrap(),
            Offset::new(0),
            "the rejected work-group ack commits nothing"
        );
    }

    #[test]
    fn exploit_a_a_second_sub_to_a_broadcast_group_is_rejected_over_the_wire() {
        // EXPLOIT A end to end (#288): the silent-drop sequence needs TWO concurrent subscribers on
        // a broadcast group. Over the wire, the second SUB is now rejected with a typed Err, so the
        // sequence (A leases 0, B leases 1, B acks 1, cumulative ack to 2 skips A's offset 0) can
        // never begin. No produced record is silently dropped: the lone consumer drains them all.
        let e = DirectEngine::new(engine());
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&e, p);
        }
        e.with(|eng| eng.set_broadcast_in("g", true))
            .unwrap()
            .unwrap();
        // Consumer A (member 1) subscribes: accepted, it is the lone subscriber, and leases offset 0.
        let mut a = connect_and_sub(&e, MemberId::new(1), b"g");
        let mut out = Vec::new();
        a.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"a".to_vec()],
            "A leases offset 0"
        );
        assert_eq!(e.with(|eng| eng.subscriber_count_in("g")).unwrap(), 1);
        // Consumer B (member 2) subscribes to the SAME broadcast group: the SUB is REJECTED (the
        // exploit's step 3), so B never gets to lease offset 1.
        let mut b = Session::with_member_id(MemberId::new(2));
        let mut out = Vec::new();
        b.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        b.process(&e, &frame(FrameType::Sub, b"g"), &mut out)
            .unwrap();
        let (ty, msg) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "the second SUB to a broadcast group is rejected"
        );
        assert!(
            String::from_utf8_lossy(&msg).contains("group-of-one"),
            "the typed reason is surfaced: {}",
            String::from_utf8_lossy(&msg)
        );
        // Still exactly one subscriber; B never registered.
        assert_eq!(e.with(|eng| eng.subscriber_count_in("g")).unwrap(), 1);
        // The lone consumer A drains the rest in order: no offset is skipped.
        let mut out = Vec::new();
        a.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"b".to_vec(), b"c".to_vec()],
            "every remaining record is delivered to the lone consumer, none silently dropped"
        );
    }

    #[test]
    fn a_disconnect_frees_a_broadcast_groups_group_of_one_slot_over_the_wire() {
        // LIVENESS over the wire (#288): the disconnect-deregister must FREE a broadcast group's
        // group-of-one slot, not just an explicit UNSUB. A SUBs the broadcast group (taking the lone
        // slot), A's connection DROPS, then B SUBs the SAME group and SUCCEEDS. Without the disconnect
        // cleanup the slot would stay taken and B's SUB would be rejected `BroadcastGroupBusy`
        // forever, bricking the group; this pins that a future refactor dropping the cleanup fails
        // here. It exercises the real SUB frame path and the real per-connection disconnect cleanup
        // (`leave_current_key_shared` + `leave_current_subscription`), the exact pair the connection
        // handler runs on EVERY exit (clean close, timeout, or malformed frame) in `server.rs`.
        let e = DirectEngine::new(engine());
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&e, p);
        }
        e.with(|eng| eng.set_broadcast_in("g", true))
            .unwrap()
            .unwrap();
        // Consumer A (member 1) subscribes: accepted, it is the lone subscriber.
        let mut a = connect_and_sub(&e, MemberId::new(1), b"g");
        assert_eq!(
            e.with(|eng| eng.subscriber_count_in("g")).unwrap(),
            1,
            "A holds the group-of-one slot"
        );
        // A's connection DROPS. The server runs this exact cleanup pair on every connection exit
        // (see `handle_connection`), so calling it here replays an abrupt disconnect, not a graceful
        // UNSUB. Both are best-effort and idempotent.
        a.leave_current_key_shared(&e).unwrap();
        a.leave_current_subscription(&e).unwrap();
        drop(a);
        assert_eq!(
            e.with(|eng| eng.subscriber_count_in("g")).unwrap(),
            0,
            "the disconnect freed the slot"
        );
        // Consumer B (member 2) subscribes to the SAME broadcast group: it now SUCCEEDS because the
        // slot was freed on A's disconnect. (If the disconnect cleanup were removed, the slot would
        // still be held by A and this SUB would answer a typed `BroadcastGroupBusy` Err instead.)
        let mut b = Session::with_member_id(MemberId::new(2));
        let mut out = Vec::new();
        b.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        b.process(&e, &frame(FrameType::Sub, b"g"), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Ok,
            "B's SUB to the freed broadcast group succeeds"
        );
        assert_eq!(
            e.with(|eng| eng.subscriber_count_in("g")).unwrap(),
            1,
            "B now holds the group-of-one slot"
        );
        // B (the new lone consumer) can drain every record in order: the group is live, not bricked.
        let mut out = Vec::new();
        b.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "the freed group still delivers every record to its new lone consumer"
        );
    }

    /// Builds a `Connect` frame body advertising the streaming capability (#543) and, optionally, a
    /// connection-default consume tier. For the tier-negotiation session tests.
    fn tier_connect_body(
        understands_streaming: bool,
        default_tier: Option<ConsumeTier>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                requested_credit: None,
                requested_credit_bytes: None,
                wants_gap_marker: false,
                default_ack_level: None,
                understands_streaming,
                default_tier: default_tier.map(ConsumeTier::as_u8),
                understands_deliver_batch: false,
                understands_streams: false,
                understands_compressed_delivery: false,
            },
            &mut body,
        );
        body
    }

    #[test]
    fn a_streaming_default_connection_marks_an_unmarked_subscription_tier_s() {
        // #543, V2-M1: a streaming-CAPABLE client that negotiated a Tier-S connection default has its
        // unmarked SUB automatically placed on the streaming tier, and the server echoes both the
        // capability and the default in Info. This is the "one log serves both tiers" wiring: the SUB
        // never explicitly picked a tier, yet it streams because the connection default says so.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(
                FrameType::Connect,
                &tier_connect_body(true, Some(ConsumeTier::Streaming)),
            ),
            &mut out,
        )
        .unwrap();
        // Info confirms the capability AND echoes the Tier-S default.
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Info);
        let info = ironbus_proto::message::decode_info(&body).unwrap();
        assert!(
            info.streaming,
            "the server confirms the streaming capability"
        );
        assert_eq!(
            info.default_tier.map(ConsumeTier::from_u8),
            Some(ConsumeTier::Streaming),
            "the server echoes the negotiated Tier-S default"
        );

        // SUB to a named group WITHOUT picking a tier: it adopts the connection default (Tier-S).
        out.clear();
        s.process(&e, &frame(FrameType::Sub, b"orders"), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        assert!(
            e.engine_mut().is_streaming_in("orders"),
            "the unmarked subscription consumes at the connection's Tier-S default"
        );
    }

    #[test]
    fn an_explicit_per_subscription_tier_overrides_the_connection_default() {
        // #543 + #544: the explicit per-subscription selection (#544 `set_streaming_in`) OVERRIDES the
        // connection default. A connection whose default is Tier-W (it advertised the capability but
        // requested no Tier-S default) never un-marks a group that was explicitly placed on Tier-S, so
        // the explicit choice wins. Symmetrically, a Tier-S default does not require the explicit call.
        let e = DirectEngine::new(engine());
        // The explicit per-subscription Tier-S selection lands FIRST (as #544 exposes it on the engine).
        e.with(|eng| eng.set_streaming_in("orders", true).unwrap())
            .unwrap();
        assert!(e.engine_mut().is_streaming_in("orders"));

        // A streaming-capable client with a Tier-W (default) connection default subscribes to it.
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(FrameType::Connect, &tier_connect_body(true, None)),
            &mut out,
        )
        .unwrap();
        let info = ironbus_proto::message::decode_info(&one_response(&out).1).unwrap();
        assert!(info.streaming, "the capability is confirmed");
        assert_eq!(
            info.default_tier, None,
            "a Tier-W default echoes no tier byte (byte-identical to before)"
        );
        out.clear();
        s.process(&e, &frame(FrameType::Sub, b"orders"), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        assert!(
            e.engine_mut().is_streaming_in("orders"),
            "the explicit per-subscription Tier-S selection is NOT cleared by a Tier-W-default SUB: \
             the explicit tier overrides the connection default"
        );
    }

    #[test]
    fn a_pre_streaming_client_always_gets_tier_w_even_with_a_tier_s_default() {
        // BACK-COMPAT: a client that did NOT advertise the streaming capability is ALWAYS served
        // Tier-W, byte-for-byte today's behavior, EVEN IF its Connect body carried a Tier-S default —
        // the server ignores a default it cannot honor, so a pre-streaming client can never be moved
        // onto a tier it does not understand. An old (empty) Connect and a capability-clear Connect
        // both leave every subscribed group on the work-queue tier.
        let e = DirectEngine::new(engine());

        // (a) A capability-CLEAR Connect that nonetheless asks for a Tier-S default: ignored.
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(
                FrameType::Connect,
                &tier_connect_body(false, Some(ConsumeTier::Streaming)),
            ),
            &mut out,
        )
        .unwrap();
        let info = ironbus_proto::message::decode_info(&one_response(&out).1).unwrap();
        assert!(
            !info.streaming,
            "the capability is NOT confirmed for a pre-streaming client"
        );
        assert_eq!(
            info.default_tier, None,
            "a Tier-S default from a capability-clear client is ignored (no echo)"
        );
        out.clear();
        s.process(&e, &frame(FrameType::Sub, b"orders"), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        assert!(
            !e.engine_mut().is_streaming_in("orders"),
            "a pre-streaming client's subscription stays Tier-W despite the Tier-S default"
        );

        // (b) An OLD (empty) Connect: the historical case, also Tier-W.
        let mut old = Session::new();
        let mut out2 = Vec::new();
        old.process(&e, &frame(FrameType::Connect, b""), &mut out2)
            .unwrap();
        out2.clear();
        old.process(&e, &frame(FrameType::Sub, b"legacy"), &mut out2)
            .unwrap();
        assert_eq!(one_response(&out2).0, FrameType::Ok);
        assert!(
            !e.engine_mut().is_streaming_in("legacy"),
            "an old client's subscription is Tier-W, byte-for-byte today's behavior"
        );
    }

    // ----- Tier-S DeliverBatch raw-framed delivery (#541, M1-I5) -----

    /// A `Connect` body advertising the streaming and/or `DeliverBatch` capabilities (#541), for the
    /// batch-delivery session tests.
    fn batch_connect_body(understands_streaming: bool, understands_deliver_batch: bool) -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                requested_credit: None,
                requested_credit_bytes: None,
                wants_gap_marker: false,
                default_ack_level: None,
                understands_streaming,
                default_tier: None,
                understands_deliver_batch,
                understands_streams: false,
                understands_compressed_delivery: false,
            },
            &mut body,
        );
        body
    }

    /// Produces a record with explicit key/headers/payload through the engine, so the batch differential
    /// exercises non-empty variable fields.
    fn produce_kh<C: Clock + Clone>(
        e: &DirectEngine<InMemoryFs, C>,
        key: &[u8],
        headers: &[u8],
        payload: &[u8],
    ) {
        e.engine_mut()
            .produce(&Append {
                timestamp_ms: 42,
                flags: RecordFlags::EMPTY,
                key,
                headers,
                payload,
            })
            .unwrap();
    }

    /// Decodes a `DeliverBatch` (tag 26) frame body into the per-record `(offset, DeliverBody-equivalent)`
    /// the way a batch-capable client does: decode the header, then each on-disk frame (CRC-VERIFIED by
    /// `codec::decode`), reconstructing the offset POSITIONALLY (`first_offset + i`). Returns
    /// `(offset, generation, flags, ts, key, headers, payload)` per record. Panics on a CRC/length
    /// mismatch — exactly the integrity check a real client makes.
    #[allow(clippy::type_complexity)]
    fn decode_batch_records(body: &[u8]) -> Vec<(u64, u64, u8, u64, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let (header, record_bytes) =
            ironbus_proto::message::decode_deliver_batch(body).expect("batch header decodes");
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut offset = header.first_offset;
        while cursor < record_bytes.len() {
            // `codec::decode` validates the frame's HEADER and BODY CRC before returning a view, so a
            // record that decodes here is integrity-verified end-to-end.
            let (view, consumed) =
                ironbus_core::codec::decode(&record_bytes[cursor..]).expect("record CRC verifies");
            out.push((
                offset,
                header.generation,
                view.flags.bits(),
                view.timestamp_ms,
                view.key.to_vec(),
                view.headers.to_vec(),
                view.payload.to_vec(),
            ));
            offset += 1;
            cursor += consumed;
        }
        assert_eq!(
            cursor,
            record_bytes.len(),
            "batch body is exactly whole frames"
        );
        assert_eq!(
            out.len() as u64,
            u64::from(header.record_count),
            "count matches"
        );
        out
    }

    /// Connects a batch-capable session, marks `group` streaming, subscribes, and returns the session.
    fn batch_session(e: &DirectEngine<InMemoryFs, ManualClock>, group: &[u8]) -> Session {
        e.with({
            let g = String::from_utf8(group.to_vec()).unwrap();
            move |eng| eng.set_streaming_in(&g, true).unwrap()
        })
        .unwrap();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            e,
            &frame(FrameType::Connect, &batch_connect_body(true, true)),
            &mut out,
        )
        .unwrap();
        let info = ironbus_proto::message::decode_info(&one_response(&out).1).unwrap();
        assert!(
            info.deliver_batch,
            "the server confirms the DeliverBatch capability"
        );
        out.clear();
        s.process(e, &frame(FrameType::Sub, group), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        s
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn deliver_batch_yields_the_same_records_as_n_per_record_delivers() {
        // #541 DIFFERENTIAL (the headline correctness proof): a batch-capable consumer's StreamFetch is
        // answered with a `DeliverBatch` whose decoded records are BYTE-FOR-BYTE the records a per-record
        // (batch-incapable) consumer gets as N `Deliver` frames — same offsets, generation, flags,
        // timestamp, key, headers, payload, same order. Variable key/headers/payload exercise the codec.
        let e = DirectEngine::new(engine());
        for i in 0..12u8 {
            produce_kh(&e, &[i, 7], &[i, 9, 9], &[i; 5]);
        }
        let mut batch_s = batch_session(&e, b"s");
        let mut plain_s = {
            // A batch-INCAPABLE (streaming-only) consumer: it gets per-record Deliver frames.
            e.with(|eng| eng.set_streaming_in("s", true).unwrap())
                .unwrap();
            let mut s = Session::new();
            let mut out = Vec::new();
            s.process(
                &e,
                &frame(FrameType::Connect, &batch_connect_body(true, false)),
                &mut out,
            )
            .unwrap();
            let info = ironbus_proto::message::decode_info(&one_response(&out).1).unwrap();
            assert!(
                !info.deliver_batch,
                "a batch-incapable client gets no confirmation"
            );
            out.clear();
            s.process(&e, &frame(FrameType::Sub, b"s"), &mut out)
                .unwrap();
            s
        };

        let req = {
            let mut b = Vec::new();
            ironbus_proto::message::encode_stream_fetch(
                &ironbus_proto::message::StreamFetchBody {
                    start_offset: 0,
                    max_records: 100,
                    max_bytes: 0,
                },
                &mut b,
            );
            b
        };

        // The batch-capable response: ONE DeliverBatch (the whole sealed run) then a FlowEnd.
        let mut batch_out = Vec::new();
        batch_s
            .process(&e, &frame(FrameType::StreamFetch, &req), &mut batch_out)
            .unwrap();
        let batch_frames = decode_all(&batch_out);
        assert!(
            batch_frames
                .iter()
                .any(|(ty, _)| *ty == FrameType::DeliverBatch),
            "a batch-capable consumer is served a DeliverBatch"
        );
        assert!(
            !batch_frames.iter().any(|(ty, _)| *ty == FrameType::Deliver),
            "the whole sealed run ships as ONE batch, no per-record Deliver"
        );
        let batch_body = &batch_frames
            .iter()
            .find(|(ty, _)| *ty == FrameType::DeliverBatch)
            .unwrap()
            .1;
        let from_batch = decode_batch_records(batch_body);

        // The per-record response: N Deliver frames then a FlowEnd.
        let mut plain_out = Vec::new();
        plain_s
            .process(&e, &frame(FrameType::StreamFetch, &req), &mut plain_out)
            .unwrap();
        let plain_frames = decode_all(&plain_out);
        assert!(
            !plain_frames
                .iter()
                .any(|(ty, _)| *ty == FrameType::DeliverBatch),
            "a batch-incapable consumer NEVER gets a DeliverBatch (back-compat)"
        );
        let from_plain: Vec<_> = plain_frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::Deliver)
            .map(|(_, body)| {
                let d = decode_deliver(body).unwrap();
                (
                    d.offset,
                    d.generation,
                    d.flags,
                    d.timestamp_ms,
                    d.key.to_vec(),
                    d.headers.to_vec(),
                    d.payload.to_vec(),
                )
            })
            .collect();

        assert_eq!(from_batch.len(), 12, "all 12 records delivered");
        assert_eq!(
            from_batch, from_plain,
            "the batch decodes to EXACTLY the per-record Deliver run (offsets reconstructed, CRC verified)"
        );
        // Both responses terminate with one FlowEnd carrying the same delivered count.
        let batch_end = batch_frames
            .iter()
            .find(|(ty, _)| *ty == FrameType::FlowEnd)
            .unwrap();
        let plain_end = plain_frames
            .iter()
            .find(|(ty, _)| *ty == FrameType::FlowEnd)
            .unwrap();
        assert_eq!(batch_end.1, plain_end.1, "same FlowEnd delivered count");
        assert_eq!(
            batch_end.1,
            12u32.to_le_bytes(),
            "FlowEnd counts every record"
        );
    }

    #[test]
    fn deliver_batch_reconstructs_offsets_and_resumes_from_a_mid_run_start() {
        // Per-record offset reconstruction: a batch starting at a non-zero offset reconstructs each
        // record's offset POSITIONALLY from the header's first_offset, and a bounded batch resumes
        // exactly where it left off, contiguous with the previous batch (no gap, no overlap).
        let e = DirectEngine::new(engine());
        for i in 0..20u8 {
            produce_kh(&e, b"", b"", &[i]);
        }
        let mut s = batch_session(&e, b"s");

        let fetch_from = |s: &mut Session, start: u64, max: u32| -> Vec<u64> {
            let mut b = Vec::new();
            ironbus_proto::message::encode_stream_fetch(
                &ironbus_proto::message::StreamFetchBody {
                    start_offset: start,
                    max_records: max,
                    max_bytes: 0,
                },
                &mut b,
            );
            let mut out = Vec::new();
            s.process(&e, &frame(FrameType::StreamFetch, &b), &mut out)
                .unwrap();
            let mut offs = Vec::new();
            for (ty, body) in decode_all(&out) {
                if ty == FrameType::DeliverBatch {
                    for r in decode_batch_records(&body) {
                        offs.push(r.0);
                    }
                }
            }
            offs
        };

        // A batch of 5 starting at offset 5 reconstructs offsets [5, 10).
        assert_eq!(fetch_from(&mut s, 5, 5), vec![5, 6, 7, 8, 9]);
        // Resuming at 10 with no overlap/gap.
        assert_eq!(fetch_from(&mut s, 10, 5), vec![10, 11, 12, 13, 14]);
        // The full run from 0.
        assert_eq!(fetch_from(&mut s, 0, 100), (0..20).collect::<Vec<_>>());
    }

    #[test]
    fn deliver_batch_tolerates_a_future_appended_header_field() {
        // FORWARD-COMPAT: a future server may append fields to the DeliverBatch header; a client decodes
        // its known fields and the record bytes still begin right after the DECLARED header block. Build a
        // batch frame whose header block is one byte longer than v1, then assert it decodes correctly.
        let e = DirectEngine::new(engine());
        for i in 0..3u8 {
            produce_kh(&e, b"", b"", &[i]);
        }
        let mut s = batch_session(&e, b"s");
        let mut req = Vec::new();
        ironbus_proto::message::encode_stream_fetch(
            &ironbus_proto::message::StreamFetchBody {
                start_offset: 0,
                max_records: 100,
                max_bytes: 0,
            },
            &mut req,
        );
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::StreamFetch, &req), &mut out)
            .unwrap();
        let batch_body = decode_all(&out)
            .into_iter()
            .find(|(ty, _)| *ty == FrameType::DeliverBatch)
            .unwrap()
            .1;
        // Splice a future header byte INSIDE the declared block: bump field_len, insert a byte after the
        // v1 fields, and shift the record bytes after it. The header (version, field_len) is the first 3
        // bytes; the v1 block is the next 20 (first_offset 8 + generation 8 + record_count 4).
        let mut extended = Vec::new();
        extended.push(batch_body[0]); // version
        let new_field_len = (20u16) + 1;
        extended.extend_from_slice(&new_field_len.to_le_bytes());
        extended.extend_from_slice(&batch_body[3..3 + 20]); // the v1 block
        extended.push(0xEE); // a FUTURE appended header byte, inside the declared block
        extended.extend_from_slice(&batch_body[3 + 20..]); // the record bytes, unchanged
                                                           // The client decoder recovers the same records despite the future header field.
        let records = decode_batch_records(&extended);
        assert_eq!(records.len(), 3);
        assert_eq!(
            records.iter().map(|r| r.6.clone()).collect::<Vec<_>>(),
            vec![vec![0], vec![1], vec![2]]
        );
    }

    /// An engine with a SMALL segment cap, so a run of records spans several sealed segments plus the
    /// active tail — the boundary the raw batch (single-segment) splits on.
    fn small_segment_engine() -> Engine<InMemoryFs, ManualClock> {
        Engine::open(
            InMemoryFs::new(),
            ManualClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                log: LogConfig {
                    max_segment_bytes: 160,
                    ..LogConfig::default()
                },
                ..test_config()
            },
        )
        .unwrap()
    }

    #[test]
    fn deliver_batch_spans_a_sealed_segment_then_a_per_record_active_tail_partial_batch() {
        // BOUNDARY / PARTIAL BATCH: with a small segment cap the run spans several sealed segments and the
        // active tail. The raw batch is bounded to ONE sealed segment, so the response is a SEQUENCE of
        // DeliverBatch frames (each a sealed segment's run) and per-record Deliver frames (the active
        // tail), and decoding the whole response in order yields EXACTLY the records — same offsets, same
        // order — that a per-record-only consumer gets. Integrity (CRC) is verified per record.
        let e = DirectEngine::new(small_segment_engine());
        for i in 0..16u8 {
            produce_kh(&e, &[i], &[i, 1], &[i; 6]);
        }
        assert!(
            e.engine_mut().segment_count() >= 2,
            "the small cap must have rolled into several segments"
        );
        let mut batch_s = batch_session(&e, b"s");
        let mut plain_s = {
            e.with(|eng| eng.set_streaming_in("s", true).unwrap())
                .unwrap();
            let mut s = Session::new();
            let mut out = Vec::new();
            s.process(
                &e,
                &frame(FrameType::Connect, &batch_connect_body(true, false)),
                &mut out,
            )
            .unwrap();
            out.clear();
            s.process(&e, &frame(FrameType::Sub, b"s"), &mut out)
                .unwrap();
            s
        };
        let mut req = Vec::new();
        ironbus_proto::message::encode_stream_fetch(
            &ironbus_proto::message::StreamFetchBody {
                start_offset: 0,
                max_records: 100,
                max_bytes: 0,
            },
            &mut req,
        );

        // Decode the batch-capable response in order: each DeliverBatch expands to its records, each
        // Deliver is one record; the concatenation is the whole run.
        let mut batch_out = Vec::new();
        batch_s
            .process(&e, &frame(FrameType::StreamFetch, &req), &mut batch_out)
            .unwrap();
        let batch_frames = decode_all(&batch_out);
        assert!(
            batch_frames
                .iter()
                .any(|(ty, _)| *ty == FrameType::DeliverBatch),
            "at least one sealed segment ships as a DeliverBatch"
        );
        let mut from_batch: Vec<(u64, Vec<u8>)> = Vec::new();
        for (ty, body) in &batch_frames {
            match ty {
                FrameType::DeliverBatch => {
                    for r in decode_batch_records(body) {
                        from_batch.push((r.0, r.6));
                    }
                }
                FrameType::Deliver => {
                    let d = decode_deliver(body).unwrap();
                    from_batch.push((d.offset, d.payload.to_vec()));
                }
                _ => {}
            }
        }

        let mut plain_out = Vec::new();
        plain_s
            .process(&e, &frame(FrameType::StreamFetch, &req), &mut plain_out)
            .unwrap();
        let from_plain: Vec<(u64, Vec<u8>)> = decode_all(&plain_out)
            .iter()
            .filter(|(ty, _)| *ty == FrameType::Deliver)
            .map(|(_, body)| {
                let d = decode_deliver(body).unwrap();
                (d.offset, d.payload.to_vec())
            })
            .collect();

        assert_eq!(
            from_batch.len(),
            16,
            "every record delivered across the boundary"
        );
        assert_eq!(
            from_batch, from_plain,
            "batch (sealed segments) + per-record tail == the per-record-only run, in order"
        );
        // The offsets are exactly 0..16 with no gap or overlap across the sealed/active boundary.
        assert_eq!(
            from_batch.iter().map(|r| r.0).collect::<Vec<_>>(),
            (0..16).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_old_client_never_gets_a_deliver_batch_and_the_wire_is_byte_identical() {
        // BACK-COMPAT: a batch-INCAPABLE consumer (an old client, or one that did not advertise) is
        // served the per-record `Deliver` run byte-for-byte the pre-#541 wire, and NEVER the new tag.
        let e = DirectEngine::new(engine());
        for i in 0..5u8 {
            produce_kh(&e, b"", b"", &[i]);
        }
        // A streaming-but-NOT-batch consumer.
        e.with(|eng| eng.set_streaming_in("s", true).unwrap())
            .unwrap();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(FrameType::Connect, &batch_connect_body(true, false)),
            &mut out,
        )
        .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Sub, b"s"), &mut out)
            .unwrap();
        out.clear();
        let mut req = Vec::new();
        ironbus_proto::message::encode_stream_fetch(
            &ironbus_proto::message::StreamFetchBody {
                start_offset: 0,
                max_records: 100,
                max_bytes: 0,
            },
            &mut req,
        );
        s.process(&e, &frame(FrameType::StreamFetch, &req), &mut out)
            .unwrap();
        let frames = decode_all(&out);
        assert!(
            !frames.iter().any(|(ty, _)| *ty == FrameType::DeliverBatch),
            "an old client is NEVER sent the DeliverBatch tag"
        );
        let delivers = frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::Deliver)
            .count();
        assert_eq!(delivers, 5, "every record arrives as a per-record Deliver");
        assert_eq!(frames.last().unwrap().0, FrameType::FlowEnd);
    }

    /// Produces a keyed record through the engine, for the `key_shared` session tests.
    fn produce_keyed<C: Clock + Clone>(
        e: &DirectEngine<InMemoryFs, C>,
        key: &[u8],
        payload: &[u8],
    ) {
        e.engine_mut()
            .produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key,
                headers: b"",
                payload,
            })
            .unwrap();
    }

    /// Connects and subscribes a fresh session (with the given member id) to `group`, returning it.
    fn connect_and_sub(
        e: &DirectEngine<InMemoryFs, ManualClock>,
        member: MemberId,
        group: &[u8],
    ) -> Session {
        let mut s = Session::with_member_id(member);
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(e, &frame(FrameType::Sub, group), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "SUB is acked");
        s
    }

    #[test]
    fn key_shared_over_the_wire_routes_a_key_to_one_member_in_order() {
        // End-to-end over the session layer (#64): a configured key_shared group, two member
        // connections, keyed records. A key's records all go to its one owner, in offset order, and
        // the non-owner never sees them. The default (unconfigured) behavior is untouched.
        let e = DirectEngine::new(engine());
        e.engine_mut()
            .set_configured_key_shared_groups(["shared".to_string()]);
        let m1 = MemberId::new(101);
        let m2 = MemberId::new(202);
        let mut s1 = connect_and_sub(&e, m1, b"shared");
        let mut s2 = connect_and_sub(&e, m2, b"shared");
        // The SUB put the group into key_shared mode and joined both members.
        assert_eq!(
            e.engine_mut().key_ordering_in("shared"),
            KeyOrdering::KeyShared
        );
        // Find a key owned by m1.
        let key = (0..2000u32)
            .map(|n| format!("k{n}").into_bytes())
            .find(|k| {
                matches!(
                    e.engine_mut().route_decision_in(
                        "shared",
                        m1,
                        k,
                        ironbus_core::types::Offset::ZERO
                    ),
                    Some(ironbus_core::keyshared::RouteDecision::Deliver)
                )
            })
            .expect("a key owned by m1");
        produce_keyed(&e, &key, b"first");
        produce_keyed(&e, &key, b"second");
        // m2 (the non-owner) fetches: it gets nothing for this key.
        let mut out = Vec::new();
        s2.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        assert!(
            delivered_payloads(&out).is_empty(),
            "the non-owner sees no record for the owner's key"
        );
        // m1 (the owner) fetches: it gets the first record (only one, since the key is then busy).
        out.clear();
        s1.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        let got = delivered_payloads(&out);
        assert_eq!(
            got,
            vec![b"first".to_vec()],
            "owner gets the first record only"
        );
        // Ack it, then the second delivers (per-key order over the wire).
        let frames = decode_all(&out);
        let d = decode_deliver(&frames[0].1).unwrap();
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                offset: d.offset,
                generation: d.generation,
                op: AckOp::Ack,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        out.clear();
        s1.process(&e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        out.clear();
        s1.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"second".to_vec()],
            "the second record delivers only after the first is acked"
        );
    }

    #[test]
    fn an_unconfigured_group_stays_plain_competing_over_the_wire() {
        // A group NOT in the configured key_shared set keeps plain competing distribution even
        // though another group is key_shared: the default path is unaffected (#64).
        let e = DirectEngine::new(engine());
        e.engine_mut()
            .set_configured_key_shared_groups(["shared".to_string()]);
        produce_keyed(&e, b"some-key", b"a");
        produce_keyed(&e, b"some-key", b"b");
        let mut s = connect_and_sub(&e, MemberId::new(1), b"plain");
        assert_eq!(
            e.engine_mut().key_ordering_in("plain"),
            KeyOrdering::None,
            "an unconfigured group is not key_shared"
        );
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        // Plain competing: both same-key records deliver to the single member with no affinity gate.
        assert_eq!(
            delivered_payloads(&out),
            vec![b"a".to_vec(), b"b".to_vec()],
            "a plain group delivers same-key records normally"
        );
    }

    #[test]
    fn leaving_a_key_shared_group_drops_membership() {
        // UNSUB (and switching subscriptions) leaves the key_shared group's member set (#64).
        let e = DirectEngine::new(engine());
        e.engine_mut()
            .set_configured_key_shared_groups(["shared".to_string()]);
        let m = MemberId::new(5);
        let mut s = connect_and_sub(&e, m, b"shared");
        assert!(
            !e.engine_mut().join_member_in("shared", m),
            "the member is already joined via SUB"
        );
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Unsub, b""), &mut out)
            .unwrap();
        assert!(
            e.engine_mut().join_member_in("shared", m),
            "after UNSUB the member is no longer in the set (re-join changes it)"
        );
    }

    #[test]
    fn ack_in_a_subscribed_group_commits_only_that_group() {
        let e = DirectEngine::new(engine());
        produce(&e, b"a");
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        s.process(&e, &frame(FrameType::Sub, b"workers"), &mut out)
            .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames = decode_all(&out);
        let d = decode_deliver(&frames[0].1).unwrap();
        assert_eq!(d.offset, 0);
        let ack = AckBody {
            offset: d.offset,
            generation: d.generation,
            op: AckOp::Ack,
            delay_ms: 0,
        };
        let mut body = Vec::new();
        encode_ack(&ack, &mut body);
        out.clear();
        s.process(&e, &frame(FrameType::Ack, &body), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out),
            (FrameType::AckStatus, vec![1]),
            "committed"
        );
        // The subscribed group committed past 0; the default group is untouched.
        assert_eq!(e.engine_mut().committed_offset_in("workers").get(), 1);
        assert_eq!(e.engine_mut().committed_offset().get(), 0);
    }

    #[test]
    fn unsubscribe_reverts_to_the_default_group() {
        let e = DirectEngine::new(engine());
        produce(&e, b"a");
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        // Consume the message in a named group (lease, no ack).
        s.process(&e, &frame(FrameType::Sub, b"temp"), &mut out)
            .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(delivered_payloads(&out), vec![b"a".to_vec()]);
        // Unsubscribe: back to the default group, which has consumed nothing.
        out.clear();
        s.process(&e, &frame(FrameType::Unsub, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &5u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"a".to_vec()],
            "the default group sees offset 0 fresh"
        );
    }

    #[test]
    fn a_non_utf8_subscription_name_is_rejected() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Sub, &[0xff, 0xfe]), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn flow_with_nothing_available_replies_ok_zero() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &3u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames = decode_all(&out);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, FrameType::FlowEnd);
        assert_eq!(frames[0].1, 0u32.to_le_bytes());
    }

    #[test]
    fn flow_before_connect_is_rejected() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    /// A CoDel-enabled engine over a shared `ManualClock` the test drives, so the controlled-delay
    /// sojourn is deterministic (#68). Everything else is the default `engine()` shape.
    fn codel_engine(clock: Arc<ManualClock>) -> Engine<InMemoryFs, Arc<ManualClock>> {
        Engine::open(
            InMemoryFs::new(),
            clock,
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 10,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // CoDel ON (5 ms target / 100 ms interval); the rest inert.
                codel_target_ms: 5,
                codel_interval_ms: 100,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    fn connect_and_pub<C: Clock + Clone + 'static, E: crate::actor::EngineAccess<InMemoryFs, C>>(
        s: &mut Session,
        e: &E,
        out: &mut Vec<u8>,
    ) {
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"p",
            },
            &mut pub_body,
        )
        .unwrap();
        s.process(e, &frame(FrameType::Pub, &pub_body), out)
            .unwrap();
    }

    /// Sends a FIRE-AND-FORGET pub (the QoS-0 flag set) against any mock engine and returns the
    /// raw reply bytes, for the per-disposition no-frame contract tests (#11).
    fn connect_and_pub_faf<
        C: Clock + Clone + 'static,
        E: crate::actor::EngineAccess<InMemoryFs, C>,
    >(
        s: &mut Session,
        e: &E,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: true,
                payload: b"qos0",
            },
            &mut pub_body,
        )
        .unwrap();
        s.process(e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap();
        out
    }

    /// A mock whose produce path always reports the durable-log byte cap (drop-new) shed.
    struct AtCapacityEngine;
    impl crate::actor::EngineAccess<InMemoryFs, ManualClock> for AtCapacityEngine {
        fn produce(
            &self,
            _append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            Ok(ProduceOutcome::AtCapacity)
        }
        fn with<R, J>(&self, _job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(crate::actor::ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            (64, 0)
        }
    }

    /// A mock whose produce path always fences (a stale producer epoch, #33).
    struct FencedEngine;
    impl crate::actor::EngineAccess<InMemoryFs, ManualClock> for FencedEngine {
        fn produce(
            &self,
            _append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            Ok(ProduceOutcome::Fenced)
        }
        fn with<R, J>(&self, _job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(crate::actor::ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            (64, 0)
        }
    }

    #[test]
    fn a_fire_and_forget_pub_sends_no_frame_on_every_non_appended_disposition() {
        // THE QoS-0 NO-FRAME CONTRACT (#11, the review blocker): a fire-and-forget producer never
        // reads a reply, so ANY frame on ANY disposition (a CoDel shed, the byte-cap shed, the
        // fsync-headroom shed, a dedup fence) would permanently desync its reply stream. Each mock
        // forces one disposition; all must produce ZERO reply bytes while the session stays open.
        let mut s = Session::new();
        let out = connect_and_pub_faf(&mut s, &ShedEngine);
        assert!(
            out.is_empty(),
            "CoDel shed sent a frame to a QoS-0 pub: {out:?}"
        );

        let mut s = Session::new();
        let out = connect_and_pub_faf(&mut s, &HeadroomShedEngine);
        assert!(
            out.is_empty(),
            "headroom shed sent a frame to a QoS-0 pub: {out:?}"
        );

        let mut s = Session::new();
        let out = connect_and_pub_faf(&mut s, &AtCapacityEngine);
        assert!(
            out.is_empty(),
            "at-capacity sent a frame to a QoS-0 pub: {out:?}"
        );

        let mut s = Session::new();
        let out = connect_and_pub_faf(&mut s, &FencedEngine);
        assert!(
            out.is_empty(),
            "a fence sent a frame to a QoS-0 pub: {out:?}"
        );
    }

    /// A mock whose produce path always reports a dedup HIT (`AppendedDuplicate`), with a cluster ack
    /// gate present that PARKS the ack (the original offset is below quorum). For #917.
    struct DedupParkingEngine;
    impl crate::actor::EngineAccess<InMemoryFs, ManualClock> for DedupParkingEngine {
        fn produce(
            &self,
            _append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            Ok(ProduceOutcome::AppendedDuplicate(Offset::new(5)))
        }
        fn with<R, J>(&self, _job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(crate::actor::ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            (64, 0)
        }
        fn has_client_ack_gate(&self) -> bool {
            true
        }
        fn client_ack_disposition(
            &self,
            _member: MemberId,
            _offset: u64,
            _reply_bytes: Vec<u8>,
        ) -> Option<crate::cluster::dataplane::AckDisposition> {
            Some(crate::cluster::dataplane::AckDisposition::Parked)
        }
    }

    /// Same dedup hit, but the gate RELEASES the duplicate-ack now (the original is already
    /// quorum-committed): the `PubAckDuplicate` is written, byte-identical to the immediate path (#917).
    struct DedupReleasingEngine;
    impl crate::actor::EngineAccess<InMemoryFs, ManualClock> for DedupReleasingEngine {
        fn produce(
            &self,
            _append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            Ok(ProduceOutcome::AppendedDuplicate(Offset::new(5)))
        }
        fn with<R, J>(&self, _job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(crate::actor::ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            (64, 0)
        }
        fn has_client_ack_gate(&self) -> bool {
            true
        }
        fn client_ack_disposition(
            &self,
            _member: MemberId,
            _offset: u64,
            reply_bytes: Vec<u8>,
        ) -> Option<crate::cluster::dataplane::AckDisposition> {
            Some(crate::cluster::dataplane::AckDisposition::WriteNow(
                reply_bytes,
            ))
        }
    }

    #[test]
    fn a_dedup_hit_c2_fsync_produce_routes_through_the_quorum_gate() {
        // #917: a dedup-hit (AppendedDuplicate) on a clustered C2-fsync serve must clear the SAME quorum
        // gate as a fresh Appended. Below quorum the duplicate-ack is WITHHELD (no immediate
        // PubAckDuplicate for a record durable only on the leader); at quorum it is written.
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &DedupParkingEngine,
            &frame(FrameType::Connect, b""),
            &mut out,
        )
        .unwrap();
        out.clear();
        connect_and_pub(&mut s, &DedupParkingEngine, &mut out);
        assert!(
            out.is_empty(),
            "a dedup hit below quorum must withhold the PubAckDuplicate: {out:?}"
        );

        // When the gate releases (the original IS quorum-committed), the PubAckDuplicate IS written.
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &DedupReleasingEngine,
            &frame(FrameType::Connect, b""),
            &mut out,
        )
        .unwrap();
        out.clear();
        connect_and_pub(&mut s, &DedupReleasingEngine, &mut out);
        assert_eq!(
            one_response(&out).0,
            FrameType::PubAckDuplicate,
            "a dedup hit at quorum writes the duplicate-ack"
        );

        // A FIRE-AND-FORGET produce that dedup-hits sends NO frame (the QoS-0 no-frame contract), even
        // with a cluster gate present: the actor returns `AppendedDuplicate` regardless of the flag, so
        // a QoS-0 duplicate must never be quorum-gated or written (it would desync the reply stream).
        let mut s = Session::new();
        let out = connect_and_pub_faf(&mut s, &DedupParkingEngine);
        assert!(
            out.is_empty(),
            "a fire-and-forget dedup hit must send no frame: {out:?}"
        );
    }

    /// A mock whose fresh produce clears the actor (`Appended`) but whose cluster ack gate REJECTS the
    /// quorum-commit (the parked-ack backlog is at its cap under an unsatisfiable ISR): the reply site
    /// must emit the RETRYABLE `ERR_NOT_ENOUGH_ISR`-coded Err, not a `PubAck`. For #965.
    struct IsrRejectingEngine;
    impl crate::actor::EngineAccess<InMemoryFs, ManualClock> for IsrRejectingEngine {
        fn produce(
            &self,
            _append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            Ok(ProduceOutcome::Appended(Offset::new(7)))
        }
        fn with<R, J>(&self, _job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(crate::actor::ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            (64, 0)
        }
        fn has_client_ack_gate(&self) -> bool {
            true
        }
        fn client_ack_disposition(
            &self,
            _member: MemberId,
            _offset: u64,
            _reply_bytes: Vec<u8>,
        ) -> Option<crate::cluster::dataplane::AckDisposition> {
            Some(crate::cluster::dataplane::AckDisposition::Rejected)
        }
    }

    #[test]
    fn an_isr_rejected_produce_carries_the_stable_retryable_code() {
        // #965: the ISR-rejected quorum-commit (`AckDisposition::Rejected`) is a genuinely RETRYABLE
        // condition. It must reply with an Err carrying the STABLE `ERR_NOT_ENOUGH_ISR` code in front of
        // the human message, so a client branches on the code (retry) instead of substring-matching prose
        // — never a PubAck (the record is durable only on the leader, so acking it would be a lie).
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &IsrRejectingEngine,
            &frame(FrameType::Connect, b""),
            &mut out,
        )
        .unwrap();
        out.clear();
        connect_and_pub(&mut s, &IsrRejectingEngine, &mut out);

        let (ty, body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "an ISR reject must be an Err, not a PubAck"
        );
        let decoded = ironbus_proto::err::decode_err_body(&body);
        assert_eq!(
            decoded.code,
            Some(ironbus_proto::err::ServerErrorCode::NotEnoughIsr),
            "the ISR reject must carry the stable retryable code",
        );
        assert_eq!(
            decoded.message, "not enough in-sync replicas to quorum-commit; retry",
            "the human message is preserved verbatim",
        );
    }

    #[test]
    fn the_half_open_slot_is_released_when_the_connect_handshake_resolves() {
        use crate::preauth::{PreAuthConfig, PreAuthGuard};
        // #880: a well-formed Connect must release the half-open (#633) slot when the handshake
        // resolves, so `--max-preauth-connections` measures connections still mid-handshake, NOT
        // authenticated long-lived ones. With a cap of 1, an authed connection that kept its slot would
        // block every later accept — a self-inflicted availability outage.
        let cfg = PreAuthConfig {
            per_ip_rate_per_sec: 0,
            per_ip_burst: 0,
            half_open_cap: 1,
            lockout_threshold: 0,
            lockout_window_ms: 0,
            lockout_cooldown_ms: 0,
        };
        let connz = Arc::new(crate::connz::ConnectionMetrics::new());
        let guard = Arc::new(PreAuthGuard::new(
            cfg,
            Arc::new(ManualClock::new()) as Arc<dyn Clock>,
            connz,
        ));
        let slot = guard.on_accept("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(
            guard.half_open_count(),
            1,
            "the accept reserved the half-open slot"
        );
        // The cap of 1 is full while the first connection is mid-handshake: a second accept is refused.
        assert!(guard.on_accept("5.6.7.8".parse().unwrap()).is_err());

        // The connection sends a well-formed Connect: the handshake resolves and the slot is released.
        let mut s = Session::new().with_half_open_slot(slot);
        let mut out = Vec::new();
        s.process(&AtCapacityEngine, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        assert_eq!(
            guard.half_open_count(),
            0,
            "the slot was released when the Connect handshake resolved (#880)"
        );

        // The cap is free again: a new accept succeeds even though the first connection is still open
        // and authenticated. Pre-fix the slot stayed held for the whole connection and this failed.
        assert!(guard.on_accept("5.6.7.8".parse().unwrap()).is_ok());
    }

    #[test]
    fn the_half_open_slot_releases_after_the_auth_verdict_on_both_success_and_failure() {
        use crate::preauth::{PreAuthConfig, PreAuthGuard};
        // #880 (post-verdict release): on an AUTH-REQUIRED broker the half-open slot is dropped only
        // AFTER the auth verdict (so the #633 cap stays the global backstop on concurrent unauthenticated
        // Argon2id verifies). It is released on BOTH a FAILED Connect (through the auth-failure branch)
        // and a successful one — but never before the verify runs.
        let cfg = PreAuthConfig {
            per_ip_rate_per_sec: 0,
            per_ip_burst: 0,
            half_open_cap: 4,
            lockout_threshold: 0,
            lockout_window_ms: 0,
            lockout_cooldown_ms: 0,
        };
        let connz = Arc::new(crate::connz::ConnectionMetrics::new());
        let guard = Arc::new(PreAuthGuard::new(
            cfg,
            Arc::new(ManualClock::new()) as Arc<dyn Clock>,
            connz,
        ));
        let e = DirectEngine::new(engine());
        let token = b"a-secret-token-of-32-bytes-len!!";

        // A FAILED auth (no credential on an auth-required broker) still releases the slot — through the
        // auth-failure branch, AFTER the verify.
        let slot_fail = guard.on_accept("1.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(guard.half_open_count(), 1);
        let mut s = Session::with_member_id_and_auth(
            MemberId::new(0),
            bearer_auth(token, &[Scope::Publish]),
            None,
        )
        .with_half_open_slot(slot_fail);
        let mut out = Vec::new();
        assert!(matches!(
            s.process(&e, &frame(FrameType::Connect, b""), &mut out)
                .unwrap_err(),
            SessionError::AuthViolation
        ));
        assert_eq!(
            guard.half_open_count(),
            0,
            "a failed auth releases the slot (in the auth-failure branch, after the verify)"
        );

        // A SUCCESSFUL auth releases the slot too.
        let slot_ok = guard.on_accept("2.2.2.2".parse().unwrap()).unwrap();
        assert_eq!(guard.half_open_count(), 1);
        let mut s2 = Session::with_member_id_and_auth(
            MemberId::new(1),
            bearer_auth(token, &[Scope::Publish]),
            None,
        )
        .with_half_open_slot(slot_ok);
        let mut out2 = Vec::new();
        s2.process(&e, &connect_with_bearer(token), &mut out2)
            .unwrap();
        assert!(s2.authenticated);
        assert_eq!(
            guard.half_open_count(),
            0,
            "a successful auth releases the slot"
        );
    }

    #[test]
    fn a_codel_enabled_session_still_pub_acks_under_normal_load() {
        // The safe-default-when-on property at the session layer: a CoDel-enabled broker under normal
        // admission latency (a zero sojourn, the direct path's enqueue == dequeue) still PubAcks every
        // produce. CoDel never false-sheds a healthy producer.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(codel_engine(Arc::clone(&clock)));
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        for _ in 0..50 {
            out.clear();
            connect_and_pub(&mut s, &e, &mut out);
            assert_eq!(
                one_response(&out).0,
                FrameType::PubAck,
                "a healthy produce is acked"
            );
        }
    }

    /// A mock [`EngineAccess`] that ALWAYS returns a given [`ProduceOutcome`] for a produce (and
    /// records nothing else), so the session's outcome-to-wire mapping can be tested in isolation. It
    /// proves the `ProduceOutcome::Shed` mapping surfaces the typed "shed under load" `Err`. The
    /// `with`/`now_monotonic_nanos` paths are unused by a produce-only test, so they return inert
    /// values.
    struct ShedEngine;
    impl crate::actor::EngineAccess<InMemoryFs, ManualClock> for ShedEngine {
        fn produce(
            &self,
            _append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            // The engine decided to SHED this NEW produce under load (#68): the reply is a typed,
            // self-announcing signal, and NOTHING was appended (the mock has no log to advance), so
            // the no-data-loss property holds by construction.
            Ok(ProduceOutcome::Shed)
        }
        fn with<R, J>(&self, _job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(crate::actor::ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            // The default caps, read locally (this mock has no engine to query): the #292 handshake
            // negotiation uses these without an actor round-trip, so a produce-only test is unaffected.
            (64, 0)
        }
    }

    #[test]
    fn a_codel_shed_surfaces_the_typed_shed_under_load_err_over_the_session() {
        // The wire-facing #68 property: a `ProduceOutcome::Shed` (the CoDel load-shed) maps to a
        // typed, self-announcing "shed under load" `Err` frame, NOT a silent drop and NOT a generic
        // failure, so a producer can distinguish a latency-load shed and back off. The connection
        // stays open (the session keeps processing).
        let e = ShedEngine;
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        connect_and_pub(&mut s, &e, &mut out);
        let (ty, body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "a CoDel shed is a typed Err, not a silent drop"
        );
        assert_eq!(
            body, b"shed under load",
            "the shed Err is self-announcing and distinct from `at capacity` and a generic failure"
        );
        // The session keeps going (the shed did not end the connection): a follow-up frame is still
        // processed (here a Ping -> Pong).
        out.clear();
        s.process(&e, &frame(FrameType::Ping, b""), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Pong,
            "the connection stays open after a shed"
        );
    }

    /// A mock [`EngineAccess`] that ALWAYS returns [`ProduceOutcome::WalHeadroomShed`] for a produce
    /// (#378), so the session's outcome-to-wire mapping for the fsync-headroom shed is tested in
    /// isolation: it must surface the typed, distinct `wal fsync headroom exhausted` `Err`. The
    /// `with`/`now_monotonic_nanos` paths are unused by a produce-only test.
    struct HeadroomShedEngine;
    impl crate::actor::EngineAccess<InMemoryFs, ManualClock> for HeadroomShedEngine {
        fn produce(
            &self,
            _append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            // The engine shed this NEW produce because the un-fsynced backlog hit the headroom and a
            // drain could not free it (#378). Nothing was appended (the mock has no log), so the
            // no-data-loss property holds by construction.
            Ok(ProduceOutcome::WalHeadroomShed)
        }
        fn with<R, J>(&self, _job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(crate::actor::ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            (64, 0)
        }
    }

    #[test]
    fn an_fsync_headroom_shed_surfaces_the_typed_distinct_err_over_the_session() {
        // The wire-facing #378 property: a `ProduceOutcome::WalHeadroomShed` maps to a typed,
        // self-announcing `wal fsync headroom exhausted` `Err`, DISTINCT from the CoDel "shed under
        // load" and the byte-cap "at capacity", so a producer can tell which control fired and back
        // off. The connection stays open (the session keeps processing).
        let e = HeadroomShedEngine;
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        connect_and_pub(&mut s, &e, &mut out);
        let (ty, body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "an fsync-headroom shed is a typed Err, not a silent drop"
        );
        assert_eq!(
            body, b"wal fsync headroom exhausted",
            "the headroom shed Err is self-announcing and distinct from `shed under load` and `at capacity`"
        );
        // The session keeps going (the shed did not end the connection).
        out.clear();
        s.process(&e, &frame(FrameType::Ping, b""), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Pong,
            "the connection stays open after an fsync-headroom shed"
        );
    }

    #[test]
    fn end_to_end_produce_fetch_ack_over_the_session() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        // Produce via the session (PUB).
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"round-trip",
            },
            &mut pub_body,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap();
        out.clear();
        // Fetch it.
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames = decode_all(&out);
        let delivered = decode_deliver(&frames[0].1).unwrap();
        assert_eq!(delivered.payload, b"round-trip");
        // Ack it with the delivered token; the cursor commits.
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
        out.clear();
        s.process(&e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        assert_eq!(e.engine_mut().committed_offset().get(), 1);
    }

    /// Encodes a PUB body carrying an opt-in dedup block (#33), for the wire dedup tests.
    fn dedup_pub_body(producer_id: &[u8], epoch: u64, msg_id: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: Some(PubDedup {
                    producer_id,
                    epoch,
                    msg_id,
                    seq: None,
                }),
                fire_and_forget: false,
                payload,
            },
            &mut body,
        )
        .unwrap();
        body
    }

    /// Encodes a PUB body carrying an opt-in idempotent SEQUENCE block (V2-M8), for the wire
    /// sequenced-idempotence tests.
    fn seq_pub_body(producer_id: &[u8], epoch: u64, seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: Some(PubDedup {
                    producer_id,
                    epoch,
                    msg_id: b"",
                    seq: Some(seq),
                }),
                fire_and_forget: false,
                payload,
            },
            &mut body,
        )
        .unwrap();
        body
    }

    #[test]
    fn a_sequenced_retry_over_the_wire_replies_pub_ack_duplicate_and_an_out_of_order_replies_err() {
        // V2-M8 wire properties: a fresh sequenced produce replies PubAck; a RETRY of the same
        // (producer, epoch, seq) replies PubAckDuplicate (tag 20) with the ORIGINAL offset and adds
        // NO record; a GAP (out-of-order seq) replies Err and adds no record.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        // Fresh seq 0: PubAck(0).
        s.process(
            &e,
            &frame(FrameType::Pub, &seq_pub_body(b"p", 1, 0, b"v0")),
            &mut out,
        )
        .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::PubAck);
        assert_eq!(body, 0u64.to_le_bytes());
        out.clear();
        // A RETRY of seq 0: PubAckDuplicate(0), no second record.
        s.process(
            &e,
            &frame(FrameType::Pub, &seq_pub_body(b"p", 1, 0, b"v0-retry")),
            &mut out,
        )
        .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::PubAckDuplicate,
            "a sequenced retry uses the tag 20 duplicate frame"
        );
        assert_eq!(body, 0u64.to_le_bytes(), "the original offset");
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the sequenced retry appended nothing"
        );
        out.clear();
        // A GAP (seq 2, expected 1): Err, no record.
        s.process(
            &e,
            &frame(FrameType::Pub, &seq_pub_body(b"p", 1, 2, b"skip")),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "an out-of-order sequence is rejected with an Err"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the out-of-order produce appended nothing"
        );
        assert_eq!(e.engine_mut().producer_out_of_order(), 1);
    }

    #[test]
    fn a_sequenced_zombie_epoch_over_the_wire_is_fenced_while_the_new_epoch_writes() {
        // V2-M8: a restarted producer's higher epoch supersedes; a zombie at the stale epoch is
        // fenced (Err) and appends nothing, while the new epoch keeps writing.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(
            &e,
            &frame(FrameType::Pub, &seq_pub_body(b"p", 5, 0, b"e5")),
            &mut out,
        )
        .unwrap();
        assert_eq!(one_response(&out).0, FrameType::PubAck);
        out.clear();
        // The new session (epoch 6) supersedes.
        s.process(
            &e,
            &frame(FrameType::Pub, &seq_pub_body(b"p", 6, 0, b"e6")),
            &mut out,
        )
        .unwrap();
        assert_eq!(one_response(&out).0, FrameType::PubAck);
        out.clear();
        // A zombie at the OLD epoch 5 is fenced.
        s.process(
            &e,
            &frame(FrameType::Pub, &seq_pub_body(b"p", 5, 1, b"zombie")),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "a stale-epoch zombie is fenced with an Err"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            2,
            "the fenced zombie appended nothing"
        );
    }

    #[test]
    fn a_sequenced_publish_with_an_empty_producer_id_is_rejected_at_the_wire_boundary() {
        // V2-M8 fail-closed gate: a `seq` requires a non-empty producer_id (the durable high-water is
        // keyed by it), else a typed Err and no record (the connection stays open).
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(
            &e,
            &frame(FrameType::Pub, &seq_pub_body(b"", 0, 0, b"v")),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "a sequenced publish with an empty producer_id is rejected"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            0,
            "the rejected sequenced publish appended nothing"
        );
    }

    #[test]
    fn a_duplicate_msg_id_over_the_wire_replies_pub_ack_duplicate_with_the_original_offset() {
        // The headline #33 wire property: a fresh dedup produce replies PubAck(0); the same
        // (producer, msg_id) replies the NEW PubAckDuplicate frame (tag 20) carrying the ORIGINAL
        // offset, and the durable log gains NO second record.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        // Fresh produce: PubAck with offset 0.
        s.process(
            &e,
            &frame(FrameType::Pub, &dedup_pub_body(b"p1", 1, b"idem", b"v1")),
            &mut out,
        )
        .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::PubAck);
        assert_eq!(body, 0u64.to_le_bytes());
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "one record durable"
        );
        out.clear();
        // The SAME msg_id again (different payload): a PubAckDuplicate (tag 20) with the ORIGINAL
        // offset 0, and NO second record appended.
        s.process(
            &e,
            &frame(
                FrameType::Pub,
                &dedup_pub_body(b"p1", 1, b"idem", b"v2-ignored"),
            ),
            &mut out,
        )
        .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::PubAckDuplicate,
            "a dedup hit uses the new tag 20 frame"
        );
        assert_eq!(
            body,
            0u64.to_le_bytes(),
            "the duplicate carries the ORIGINAL offset"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the durable head did NOT advance on the dedup hit"
        );
        assert_eq!(e.engine_mut().dedup_hits(), 1);
    }

    #[test]
    fn a_no_msg_id_produce_over_the_wire_is_unchanged_and_never_dedups() {
        // Two identical no-msg-id produces both PubAck with DISTINCT offsets (today's behavior); the
        // dedup hit counter never moves.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        for expected in [0u64, 1] {
            out.clear();
            let mut body = Vec::new();
            encode_pub(
                &PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: b"same",
                },
                &mut body,
            )
            .unwrap();
            s.process(&e, &frame(FrameType::Pub, &body), &mut out)
                .unwrap();
            let (ty, ack) = one_response(&out);
            assert_eq!(ty, FrameType::PubAck);
            assert_eq!(
                ack,
                expected.to_le_bytes(),
                "each no-dedup produce gets a fresh offset"
            );
        }
        assert_eq!(e.engine_mut().flushed_offset().get(), 2, "both appended");
        assert_eq!(e.engine_mut().dedup_hits(), 0, "no msg_id, no dedup");
    }

    #[test]
    fn a_stale_epoch_produce_over_the_wire_is_fenced_with_an_err() {
        // Epoch fencing over the wire: epoch 5 establishes the producer; a produce at the older epoch
        // 4 replies Err (fenced) and appends nothing.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(
            &e,
            &frame(FrameType::Pub, &dedup_pub_body(b"p1", 5, b"m1", b"a")),
            &mut out,
        )
        .unwrap();
        assert_eq!(one_response(&out).0, FrameType::PubAck);
        out.clear();
        s.process(
            &e,
            &frame(FrameType::Pub, &dedup_pub_body(b"p1", 4, b"m2", b"b")),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "a stale epoch is fenced with an Err"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the fenced produce appended nothing"
        );
    }

    #[test]
    fn an_oversized_producer_id_is_rejected_at_the_wire_boundary() {
        // The #33 memory-exhaustion length cap: a producer_id over MAX_PRODUCER_ID_LEN is rejected
        // with a typed Err (the connection stays open) and appends nothing, so a hostile 64 KiB id
        // never reaches the dedup map as a key. A producer_id exactly at the cap is accepted.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        let too_long = vec![b'p'; MAX_PRODUCER_ID_LEN + 1];
        s.process(
            &e,
            &frame(FrameType::Pub, &dedup_pub_body(&too_long, 1, b"m", b"v")),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "an oversized producer_id is a typed rejection"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            0,
            "the rejected produce appended nothing"
        );
        out.clear();
        // A producer_id exactly at the cap is fine (the boundary is inclusive).
        let at_cap = vec![b'p'; MAX_PRODUCER_ID_LEN];
        s.process(
            &e,
            &frame(FrameType::Pub, &dedup_pub_body(&at_cap, 1, b"m", b"v")),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::PubAck,
            "at-cap is accepted"
        );
    }

    #[test]
    fn an_oversized_msg_id_is_rejected_at_the_wire_boundary() {
        // The msg_id length cap mirror of the producer_id cap: an oversized msg_id is a typed
        // rejection and appends nothing.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        let too_long = vec![b'm'; MAX_MSG_ID_LEN + 1];
        s.process(
            &e,
            &frame(FrameType::Pub, &dedup_pub_body(b"p1", 1, &too_long, b"v")),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "an oversized msg_id is a typed rejection"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            0,
            "the rejected produce appended nothing"
        );
    }

    #[test]
    fn ping_is_answered_with_pong() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        let input = frame(FrameType::Ping, b"");
        let progress = s.process(&e, &input, &mut out).unwrap();
        assert_eq!(progress.consumed, input.len());
        assert_eq!(one_response(&out).0, FrameType::Pong);
    }

    #[test]
    fn connect_is_answered_with_info() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
    }

    #[test]
    fn pub_after_connect_appends_and_replies_ok_with_the_offset() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut input = frame(FrameType::Connect, b"");
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 5,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"hello",
            },
            &mut pub_body,
        )
        .unwrap();
        input.extend_from_slice(&frame(FrameType::Pub, &pub_body));

        let progress = s.process(&e, &input, &mut out).unwrap();
        assert_eq!(progress.consumed, input.len());
        // Two responses: Info, then PubAck with offset 0.
        let info = decode_frame(&out).unwrap();
        let FrameDecode::Frame { consumed: c0, .. } = info else {
            panic!("info incomplete");
        };
        let (ty, body) = one_response(&out[c0..]);
        assert_eq!(ty, FrameType::PubAck);
        assert_eq!(body, 0u64.to_le_bytes());
        // The message is durable in the engine and deliverable.
        let polled = e.engine_mut().poll(0).unwrap();
        match polled {
            Poll::Message(d) => assert_eq!(d.record.payload.as_ref(), b"hello"),
            other => panic!("expected the produced message, got {other:?}"),
        }
    }

    /// Encodes and sends one `Pub` over the session and returns the single response frame,
    /// asserting `process` did NOT end the session (a non-fatal reply keeps the connection
    /// open).
    fn pub_reply<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
        payload: &[u8],
    ) -> (FrameType, Vec<u8>) {
        let mut body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload,
            },
            &mut body,
        )
        .unwrap();
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Pub, &body), &mut out)
            .expect("a non-fatal pub never ends the session");
        let replies = decode_all(&out);
        assert_eq!(replies.len(), 1, "exactly one reply frame");
        replies[0].clone()
    }

    #[test]
    fn an_over_cap_pub_replies_at_capacity_and_keeps_the_connection_open() {
        // Cap the broker at one record's worth of durable bytes, so the SECOND wire produce is
        // shed. The reply is a distinct "at capacity" Err frame (not "produce failed"), the
        // session stays open, and a later op still works, the producer can keep going. This is
        // the wire contract a producer relies on to tell a deliberate shed from a transient
        // failure or a connection-ending fatal error.
        let payload = b"capacity";
        // Measure one record's framed durable bytes on a throwaway engine.
        let one = {
            let probe = DirectEngine::new(engine());
            produce(&probe, payload);
            let bytes = probe.engine_mut().durable_record_bytes();
            bytes
        };
        let e = DirectEngine::new(
            Engine::open(
                InMemoryFs::new(),
                ManualClock::new(),
                EngineConfig {
                    consume_longpoll_ms: 0,
                    compression: ironbus_core::compress::Codec::None,
                    log: LogConfig::default().with_max_total_bytes(one),
                    lease: LeaseConfig {
                        visibility_nanos: 30,
                        hard_cap_nanos: 100,
                    },
                    delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                    max_in_flight: 10,
                    consumer_credit: 64,
                    consumer_credit_bytes: 0,
                    checkpoint_interval: 1024,
                    max_retained_bytes: 0,
                    max_age_ms: 0,
                    max_messages: 0,
                    max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                    // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                    max_streams: 0,
                    group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                    ram_ceiling_bytes: 0,
                    disk_full_policy: DiskFullPolicy::DropNew,
                    dedup: ironbus_core::dedup::DedupConfig::default(),
                    durability_level: crate::engine::DurabilityLevel::Sync,
                    flush_interval_ms: 0,
                    flush_max_bytes: 0,
                    // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                    // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
                    // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                    // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                    default_message_ttl_ms: 0,
                    dead_letter_exchange: None,
                    dead_letter_expired: false,
                },
            )
            .unwrap(),
        );
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();

        // The first produce fits: a PubAck with offset 0.
        let (ty, body) = pub_reply(&mut s, &e, payload);
        assert_eq!(ty, FrameType::PubAck);
        assert_eq!(body, 0u64.to_le_bytes());

        // The second is over the cap: a distinct Err frame marking the capacity shed, NOT the
        // generic "produce failed". The session did NOT end (pub_reply asserts process is Ok).
        let (ty, body) = pub_reply(&mut s, &e, payload);
        assert_eq!(ty, FrameType::Err);
        // #883: the shed now carries the STABLE `ERR_AT_CAPACITY` code in front of the human message,
        // so a client branches on the code instead of substring-matching "at capacity". The message is
        // preserved verbatim.
        let decoded = ironbus_proto::err::decode_err_body(&body);
        assert_eq!(
            decoded.code,
            Some(ironbus_proto::err::ServerErrorCode::AtCapacity)
        );
        assert_eq!(decoded.message, "at capacity");
        assert_ne!(
            body, b"produce failed",
            "a shed must be distinguishable from a transient failure"
        );

        // The connection is still usable: a follow-up Ping is answered (the session never
        // closed), and another over-cap produce is still a shed, not a fatal error.
        out.clear();
        s.process(&e, &frame(FrameType::Ping, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Pong);
        let (ty, body) = pub_reply(&mut s, &e, payload);
        assert_eq!(ty, FrameType::Err);
        // #883: the shed now carries the STABLE `ERR_AT_CAPACITY` code in front of the human message,
        // so a client branches on the code instead of substring-matching "at capacity". The message is
        // preserved verbatim.
        let decoded = ironbus_proto::err::decode_err_body(&body);
        assert_eq!(
            decoded.code,
            Some(ironbus_proto::err::ServerErrorCode::AtCapacity)
        );
        assert_eq!(decoded.message, "at capacity");
        // The shed counter reflects both rejections; the one success was counted once.
        assert_eq!(e.engine_mut().counters().produce_rejected, 2);
        assert_eq!(e.engine_mut().counters().produced, 1);
    }

    #[test]
    fn pub_before_connect_is_rejected() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"x",
            },
            &mut pub_body,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn ack_commits_a_delivered_message() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&e, b"m");
        // Deliver THROUGH the session (Flow) so it owns the lease, then ack it.
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let toks = delivered_tokens(&out);
        assert_eq!(toks.len(), 1);
        let (offset, generation) = toks[0];
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Ack, offset, generation),
            vec![1u8],
            "status 1 = committed"
        );
        assert_eq!(e.engine_mut().committed_offset().get(), 1);
    }

    #[test]
    fn a_partial_trailing_frame_is_not_consumed() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        let ping = frame(FrameType::Ping, b"");
        let mut input = ping.clone();
        input.extend_from_slice(&frame(FrameType::Ping, b"")[..2]); // half of a second frame
        let progress = s.process(&e, &input, &mut out).unwrap();
        assert_eq!(
            progress.consumed,
            ping.len(),
            "only the complete frame is consumed"
        );
        assert_eq!(one_response(&out).0, FrameType::Pong);
    }

    #[test]
    fn the_needed_hint_reports_the_trailing_frames_full_length_for_the_n_squared_fix() {
        // The #176 O(n^2) re-decode fix: after a pass that leaves a partial trailing frame, `process`
        // reports `needed` (the bytes that frame still wants, relative to the post-drain buffer). The
        // connection loop uses it to avoid re-decoding a trickled near-cap frame until it is whole.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        // A complete Ping, then the first 2 bytes of a 6-byte-ish Pub frame (a partial trailing frame).
        let ping = frame(FrameType::Ping, b"");
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"trickled-payload",
            },
            &mut pub_body,
        )
        .unwrap();
        let full_pub = frame(FrameType::Pub, &pub_body);
        let mut input = ping.clone();
        // Enough of the Pub frame for its 4-byte length prefix to be readable (so the parser knows the
        // full frame length) but not the whole frame: the partial trailing frame.
        input.extend_from_slice(&full_pub[..6]);
        let progress = s.process(&e, &input, &mut out).unwrap();
        assert_eq!(
            progress.consumed,
            ping.len(),
            "the complete ping is consumed"
        );
        // After draining the ping prefix, the partial Pub sits at the front and needs its FULL framed
        // length before another pass can make progress: that is exactly the `needed` hint, so the loop
        // waits for the whole frame rather than re-decoding per trickled byte.
        assert_eq!(
            progress.needed,
            full_pub.len(),
            "the needed hint is the trailing frame's full length once its prefix is readable"
        );
        assert!(
            !progress.committed_progress,
            "a ping advances no committed cursor, so the interval checkpoint (and the actor) is skipped"
        );
    }

    #[test]
    fn empty_input_consumes_nothing() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        assert_eq!(s.process(&e, &[], &mut out).unwrap().consumed, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn ack_before_connect_is_rejected() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: 0,
                generation: 0,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        s.process(&e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn a_fenced_ack_replies_ok_with_status_zero() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        // A token never delivered to this session is fenced: status 0, the client must not
        // drop state (and nothing is committed).
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: 999,
                generation: 42,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        s.process(&e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::AckStatus);
        assert_eq!(body, vec![0u8], "status 0 = fenced");
        assert_eq!(e.engine_mut().committed_offset().get(), 0);
    }

    #[test]
    fn a_malformed_body_does_not_desync_the_stream() {
        // [Connect][Pub with a truncated body][Ping] in one buffer: the bad body is
        // contained (Err reply), and the trailing Ping still gets a Pong.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut input = frame(FrameType::Connect, b"");
        input.extend_from_slice(&frame(FrameType::Pub, b"\x01")); // 1 byte: not a valid pub body
        input.extend_from_slice(&frame(FrameType::Ping, b""));

        let progress = s.process(&e, &input, &mut out).unwrap();
        assert_eq!(
            progress.consumed,
            input.len(),
            "all three frames consumed, no desync"
        );
        // Responses: Info, Err (bad pub), Pong.
        let mut off = 0;
        let mut types = Vec::new();
        while off < out.len() {
            match decode_frame(&out[off..]).unwrap() {
                FrameDecode::Frame {
                    type_tag,
                    consumed: n,
                    ..
                } => {
                    types.push(FrameType::from_u8(type_tag).unwrap());
                    off += n;
                }
                FrameDecode::Incomplete { .. } => break,
            }
        }
        assert_eq!(
            types,
            vec![FrameType::Info, FrameType::Err, FrameType::Pong]
        );
    }

    #[test]
    fn a_second_connection_cannot_ack_a_message_delivered_to_another() {
        // #175 regression: acks are connection-scoped. A message delivered to session A cannot
        // be committed by session B presenting the same token; only A, the owner, can ack it.
        let e = DirectEngine::new(engine());
        let mut a = Session::new();
        let mut b = Session::new();
        let mut out = Vec::new();
        a.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        b.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&e, b"m");
        // Deliver to A via its Flow.
        out.clear();
        a.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let toks = delivered_tokens(&out);
        assert_eq!(toks.len(), 1);
        let (offset, generation) = toks[0];

        // B never received this lease: every disposition from B is fenced (status 0) by the
        // guard that runs before the op match, and commits/requeues nothing.
        assert_eq!(
            ack_reply(&mut b, &e, AckOp::Ack, offset, generation),
            vec![0u8],
            "B cannot commit A's message"
        );
        assert_eq!(
            ack_reply(&mut b, &e, AckOp::Nack, offset, generation),
            vec![0u8],
            "B cannot requeue A's message"
        );
        assert_eq!(
            ack_reply(&mut b, &e, AckOp::Term, offset, generation),
            vec![0u8],
            "B cannot drop A's message"
        );
        assert_eq!(
            ack_reply(&mut b, &e, AckOp::Progress, offset, generation),
            vec![0u8],
            "B cannot extend A's lease"
        );
        assert_eq!(
            e.engine_mut().committed_offset().get(),
            0,
            "none of B's foreign ops committed"
        );

        // A, the owner, commits it.
        assert_eq!(
            ack_reply(&mut a, &e, AckOp::Ack, offset, generation),
            vec![1u8],
            "A owns the lease and commits"
        );
        assert_eq!(e.engine_mut().committed_offset().get(), 1);
    }

    #[test]
    fn a_malformed_frame_ends_the_session() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        let bad = [0u8, 0, 0, 0]; // zero-length prefix
        assert!(matches!(
            s.process(&e, &bad, &mut out),
            Err(SessionError::BadFrame(_))
        ));
    }

    #[test]
    fn an_unsupported_verb_replies_err_without_closing() {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        // Info is a response-only verb; a client must not send it.
        s.process(&e, &frame(FrameType::Info, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    // ----- Per-consumer credit and in-flight window (refs #65, #9, #10) -----

    /// An engine with an explicit per-consumer `consumer_credit` and a roomy per-group
    /// `max_in_flight`, so the per-CONSUMER credit is the binding constraint (not the group window)
    /// and the #65 credit behavior is exercised in isolation. A long visibility timeout keeps
    /// leases live unless the test advances the clock past it.
    fn engine_credit(
        clock: Arc<ManualClock>,
        consumer_credit: u32,
        max_in_flight: u32,
    ) -> Engine<InMemoryFs, Arc<ManualClock>> {
        Engine::open(
            InMemoryFs::new(),
            clock,
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight,
                consumer_credit,
                // Unlimited byte budget (#275): the message-credit tests below exercise the
                // message-count bound in isolation, so the byte budget must never bind here.
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    /// An engine with an explicit per-consumer message credit AND byte budget (#275), so the byte
    /// budget can be made the binding constraint. A roomy `max_in_flight` keeps the per-group window
    /// from binding; a long visibility timeout keeps leases live unless the test advances the clock.
    fn engine_credit_bytes(
        clock: Arc<ManualClock>,
        consumer_credit: u32,
        consumer_credit_bytes: u64,
        max_in_flight: u32,
    ) -> Engine<InMemoryFs, Arc<ManualClock>> {
        Engine::open(
            InMemoryFs::new(),
            clock,
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight,
                consumer_credit,
                consumer_credit_bytes,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    /// Connects a fresh session and returns it. The credit ceiling is read from the engine on the
    /// first Flow, so a session built here starts with full credit.
    fn connected_session<C: Clock + Clone + 'static>(e: &DirectEngine<InMemoryFs, C>) -> Session {
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        s
    }

    /// Runs one Flow of `credit` for `s` against `e` and returns the (offset, generation) of each
    /// delivered message in the batch.
    fn fetch<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
        credit: u32,
    ) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Flow, &credit.to_le_bytes()), &mut out)
            .unwrap();
        delivered_tokens(&out)
    }

    #[test]
    fn a_flow_is_capped_at_the_per_consumer_credit() {
        // A single connection cannot hold more than its credit un-acked: a Flow asking for a huge
        // credit is capped at the connection's ceiling (4 here), not the group window (roomy at 64)
        // nor the requested credit (1000).
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 4, 64));
        let mut s = connected_session(&e);
        for _ in 0..20 {
            produce(&e, b"m");
        }
        let batch = fetch(&mut s, &e, 1000);
        assert_eq!(
            batch.len(),
            4,
            "the per-consumer credit of 4 caps the batch, not the requested 1000 or the group 64"
        );
        // A second Flow with the credit still full delivers nothing: at zero remaining credit a
        // Flow delivers nothing even though 16 messages remain available in the group.
        let batch2 = fetch(&mut s, &e, 1000);
        assert!(
            batch2.is_empty(),
            "a saturated consumer gets an empty batch until it frees a slot"
        );
    }

    /// Processes a PUB (built from `msg`) on a connected session against `e`, returning EVERY reply
    /// frame (zero for a fire-and-forget produce). For the #11 QoS-0 wire-tier session tests.
    fn pub_replies<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
        msg: &PubBody<'_>,
    ) -> Vec<(FrameType, Vec<u8>)> {
        let mut body = Vec::new();
        encode_pub(msg, &mut body).unwrap();
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Pub, &body), &mut out)
            .expect("a non-fatal pub never ends the session");
        decode_all(&out)
    }

    #[test]
    fn an_old_client_without_the_qos0_flag_gets_the_unchanged_at_least_once_pub_ack() {
        // BACKWARD-COMPAT (#11): a client that never sets the fire-and-forget flag takes the
        // historical at-least-once path and ALWAYS gets a PubAck with the assigned offset, unchanged.
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let replies = pub_replies(
            &mut s,
            &e,
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"v",
            },
        );
        assert_eq!(replies.len(), 1, "the at-least-once path always replies");
        assert_eq!(replies[0].0, FrameType::PubAck, "an unchanged PubAck");
        assert_eq!(
            decode_pub_ack(&replies[0].1).unwrap().offset,
            0,
            "the assigned offset"
        );
    }

    #[test]
    fn a_fire_and_forget_pub_gets_no_reply_but_is_durable() {
        // THE TEETH for the QoS-0 wire tier at the session boundary (#11): a fire-and-forget PUB
        // (the additive flag set) produces NO reply frame, yet the record is appended durably (the
        // producer fired and forgot). The default bucket is disabled, so it is appended, not dropped.
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let replies = pub_replies(
            &mut s,
            &e,
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: true,
                payload: b"qos0",
            },
        );
        assert!(
            replies.is_empty(),
            "a fire-and-forget produce sends NO frame (the client fired and forgot), got {replies:?}"
        );
        // The record is still durable: the connection appended it, only the ack was withheld.
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the QoS-0 record is durable even though no PubAck was sent"
        );
    }

    #[test]
    fn the_qos0_wire_flag_does_not_leak_into_the_stored_record_flags() {
        // The fire-and-forget bit is WIRE-ONLY (#11): like the dedup bit, it is masked out before the
        // flags byte becomes a stored RecordFlags, so a delivered/stored record never carries it.
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let _ = pub_replies(
            &mut s,
            &e,
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: true,
                payload: b"v",
            },
        );
        // Poll the stored record and inspect its delivered flags: the wire-only fire-and-forget bit
        // (64) must NOT be present (it never crossed into the stored record state).
        let d = match e.engine_mut().poll_now().unwrap() {
            Poll::Message(d) => d,
            other => panic!("expected the QoS-0 record to be deliverable, got {other:?}"),
        };
        assert_eq!(
            d.record.flags.bits() & PUB_FLAG_FIRE_AND_FORGET,
            0,
            "the wire-only QoS-0 bit never pollutes the stored record flags"
        );
    }

    // ---- Produce-time COMPRESSED-descriptor shape validation at the wire boundary (#438) ----

    /// An engine with the lz4 write-path compression seam ON (#430), so the #438 wire tests can
    /// pin that a producer-compressed PUB passes THROUGH the seam untouched (the #437
    /// pass-through guard), not merely past a disabled codec.
    fn engine_lz4() -> Engine<InMemoryFs, ManualClock> {
        Engine::open(
            InMemoryFs::new(),
            ManualClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::Lz4,
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 10,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    /// Builds a raw `descriptor + stream` compressed-object payload for the #438 wire tests.
    fn raw_descriptor(codec_id: u8, dict_id: u32, uncompressed_len: u32, stream: &[u8]) -> Vec<u8> {
        let mut v = vec![codec_id];
        v.extend_from_slice(&dict_id.to_le_bytes());
        v.extend_from_slice(&uncompressed_len.to_le_bytes());
        v.extend_from_slice(stream);
        v
    }

    /// Sends one PUB whose record flags carry the COMPRESSED bit over `payload`, returning every
    /// reply frame.
    fn compressed_pub_replies<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
        payload: &[u8],
        fire_and_forget: bool,
    ) -> Vec<(FrameType, Vec<u8>)> {
        pub_replies(
            s,
            e,
            &PubBody {
                flags: RecordFlags::COMPRESSED.bits(),
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget,
                payload,
            },
        )
    }

    #[test]
    fn a_well_formed_producer_compressed_pub_still_round_trips() {
        // The #437 pass-through behavior is UNCHANGED by the #438 gate: a producer-compressed
        // PUB (bit 0 over a real compressed object) is acked, stored byte-identical (never
        // double-wrapped, even through an lz4-compression engine), and one read-side decode
        // recovers the original.
        use ironbus_core::compress::{
            compress_payload, decompress_payload, CompressConfig, NoDictionaries,
        };
        let original = vec![0u8; 1024 * 1024];
        let comp = compress_payload(&original, &CompressConfig::default()).unwrap();
        assert!(comp.compressed, "the fixture genuinely compresses");

        let e = DirectEngine::new(engine_lz4());
        let mut s = connected_session(&e);
        let replies = compressed_pub_replies(&mut s, &e, &comp.stored, false);
        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies[0].0,
            FrameType::PubAck,
            "a legal producer-compressed publish is acked"
        );
        assert_eq!(decode_pub_ack(&replies[0].1).unwrap().offset, 0);

        let d = match e.engine_mut().poll_now().unwrap() {
            Poll::Message(d) => d,
            other => panic!("expected the compressed record, got {other:?}"),
        };
        assert!(d.record.flags.contains(RecordFlags::COMPRESSED));
        assert_eq!(
            d.record.payload, comp.stored,
            "stored verbatim, never double-wrapped"
        );
        let back = decompress_payload(
            d.record.flags,
            &d.record.payload,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, original, "one decode recovers the original");
    }

    // ---- Compressed-delivery capability gate (#1066) ----

    /// A `Connect` body advertising the compressed-delivery capability (#1066).
    fn compressed_delivery_connect_body() -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                understands_compressed_delivery: true,
                ..Default::default()
            },
            &mut body,
        );
        body
    }

    /// A large, highly compressible payload — well over the raw-store threshold, so a `--compression
    /// lz4` engine stores it COMPRESSED (the #1066 fixture).
    fn lz4_compressible_payload() -> Vec<u8> {
        b"ironbus.telemetry.sensor.v1 compressed-delivery-gate #1066 "
            .iter()
            .copied()
            .cycle()
            .take(8192)
            .collect()
    }

    /// The `(flags, payload)` of every `Deliver` frame in `out` (the wire form the consumer receives).
    fn delivered_flags_and_payloads(out: &[u8]) -> Vec<(u8, Vec<u8>)> {
        decode_all(out)
            .iter()
            .filter(|(t, _)| *t == FrameType::Deliver)
            .map(|(_, b)| {
                let d = decode_deliver(b).unwrap();
                (d.flags, d.payload.to_vec())
            })
            .collect()
    }

    #[test]
    fn a_non_capable_consumer_gets_uncompressed_delivery_from_an_lz4_broker() {
        // THE #1066 FIX: on a `--compression lz4` broker a stored-COMPRESSED record is delivered
        // DECOMPRESSED (the COMPRESSED bit CLEAR, the plain produced payload) to a consumer that did
        // NOT advertise it can decode compression (an old/empty Connect) — never the descriptor bytes
        // it would silently mis-decode. This is the ONE silent-wrong-data path, now closed.
        use ironbus_core::compress::{compress_payload, CompressConfig};
        let original = lz4_compressible_payload();
        // The fixture genuinely compresses, so the lz4 engine stores it COMPRESSED — otherwise this
        // test would be vacuous (a raw store would deliver `original` with no decompression exercised).
        assert!(
            compress_payload(&original, &CompressConfig::default())
                .unwrap()
                .compressed,
            "the fixture must genuinely compress"
        );

        let e = DirectEngine::new(engine_lz4());
        produce(&e, &original);
        // A NON-capable consumer: the empty (old-client) Connect never advertises the capability.
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let delivered = delivered_flags_and_payloads(&out);
        assert_eq!(delivered.len(), 1, "exactly one record delivered");
        assert_eq!(
            delivered[0].0 & RecordFlags::COMPRESSED.bits(),
            0,
            "the COMPRESSED bit is CLEARED for a non-capable consumer"
        );
        assert_eq!(
            delivered[0].1, original,
            "the non-capable consumer receives the PLAIN produced payload, not the descriptor bytes"
        );
    }

    #[test]
    fn a_capable_consumer_gets_compressed_delivery_from_an_lz4_broker() {
        // The complement of the fix: a consumer that ADVERTISES the capability receives the stored
        // record VERBATIM (COMPRESSED bit SET, the codec bytes) — the broker's zero-CPU passthrough —
        // and those bytes decode back to the produced payload end-to-end.
        let e = DirectEngine::new(engine_lz4());
        let original = lz4_compressible_payload();
        produce(&e, &original);
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(FrameType::Connect, &compressed_delivery_connect_body()),
            &mut out,
        )
        .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let delivered = delivered_flags_and_payloads(&out);
        assert_eq!(delivered.len(), 1, "exactly one record delivered");
        assert_ne!(
            delivered[0].0 & RecordFlags::COMPRESSED.bits(),
            0,
            "the COMPRESSED bit is PRESERVED for a capable consumer"
        );
        assert_ne!(
            delivered[0].1, original,
            "a capable consumer receives the compressed codec bytes, not the plain payload"
        );
        let back = decompress_payload(
            RecordFlags::from_bits(delivered[0].0),
            &delivered[0].1,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(
            back, original,
            "the compressed delivery decodes to the produced payload"
        );
    }

    #[test]
    fn a_connect_that_omits_the_compressed_delivery_bit_still_gets_uncompressed_delivery() {
        // The gate keys on the SPECIFIC capability bit, not merely "empty vs non-empty Connect": a
        // consumer that advertises OTHER capabilities (here gap-marker) but NOT compressed-delivery is
        // still served DECOMPRESSED on an lz4 broker — the safe default holds for any client that does
        // not opt into compressed delivery.
        let e = DirectEngine::new(engine_lz4());
        let original = lz4_compressible_payload();
        produce(&e, &original);
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(FrameType::Connect, &gap_marker_connect_body()),
            &mut out,
        )
        .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let delivered = delivered_flags_and_payloads(&out);
        assert_eq!(delivered.len(), 1, "exactly one record delivered");
        assert_eq!(
            delivered[0].0 & RecordFlags::COMPRESSED.bits(),
            0,
            "a client that did not advertise compressed delivery gets the COMPRESSED bit cleared"
        );
        assert_eq!(delivered[0].1, original, "and the plain produced payload");
    }

    #[test]
    fn a_compressed_pub_over_garbage_is_rejected_and_appends_nothing() {
        // THE #438 TEETH: bit 0 over bytes that are not a descriptor used to be acked durably
        // (the broker is store-and-forward), and post-#430 every consumer group then burned
        // max-deliver visibility-timeout cycles failing to decode the record. The broker now
        // rejects it at produce: a typed, connection-preserving Err, the durable head does not
        // move, and the connection stays usable.
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let replies = compressed_pub_replies(&mut s, &e, b"garbage!", false);
        assert_eq!(replies.len(), 1, "exactly one reply frame");
        assert_eq!(
            replies[0].0,
            FrameType::Err,
            "a typed rejection, not an ack"
        );
        assert!(
            replies[0].1.starts_with(b"malformed compressed descriptor"),
            "the Err is self-announcing, got {:?}",
            String::from_utf8_lossy(&replies[0].1)
        );
        // Nothing was appended: the durable head is unchanged and nothing is deliverable.
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            0,
            "the durable head did not move"
        );
        assert_eq!(
            e.engine_mut().counters().produced,
            0,
            "no produce was counted"
        );
        assert!(matches!(e.engine_mut().poll_now().unwrap(), Poll::Idle));
        // The connection is still open and usable: a follow-up legal produce is acked at the
        // offset the rejected publish never consumed.
        let (ty, body) = pub_reply(&mut s, &e, b"after");
        assert_eq!(ty, FrameType::PubAck);
        assert_eq!(
            body,
            0u64.to_le_bytes(),
            "the rejected publish consumed no offset"
        );
    }

    #[test]
    fn a_compressed_pub_with_an_over_cap_claim_is_rejected() {
        // The claimed uncompressed_len binds every reader's bomb guard (#76) BEFORE allocation,
        // so an acked over-cap record would be refused by every consumer on every delivery
        // attempt; the gate uses the same DEFAULT_MAX_DECOMPRESSED_BYTES constant the readers
        // and the #437 write seam use.
        use ironbus_core::compress::CODEC_ID_LZ4;
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let payload = raw_descriptor(CODEC_ID_LZ4, 0, DEFAULT_MAX_DECOMPRESSED_BYTES + 1, b"xx");
        let replies = compressed_pub_replies(&mut s, &e, &payload, false);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].0, FrameType::Err);
        assert!(
            String::from_utf8_lossy(&replies[0].1).contains("exceeds the decompressed cap"),
            "got {:?}",
            String::from_utf8_lossy(&replies[0].1)
        );
        assert_eq!(e.engine_mut().flushed_offset().get(), 0);
    }

    #[test]
    fn a_compressed_pub_with_an_unregistered_codec_id_is_rejected() {
        // An id outside the append-only registry (none/lz4/zstd, docs/compat/versions.md) is
        // decodable by NO conforming reader: a typo'd future producer fails fast at the source
        // instead of poisoning every consumer group.
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let payload = raw_descriptor(9, 0, 4, b"abcd");
        let replies = compressed_pub_replies(&mut s, &e, &payload, false);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].0, FrameType::Err);
        assert!(
            String::from_utf8_lossy(&replies[0].1).contains("unknown compression codec id 9"),
            "got {:?}",
            String::from_utf8_lossy(&replies[0].1)
        );
        assert_eq!(e.engine_mut().flushed_offset().get(), 0);
    }

    #[test]
    fn wire_legal_descriptor_variants_are_still_acked() {
        // COMPRESSED + codec none with a length-consistent stream is wire-legal (the read side
        // returns the inner bytes verbatim), and the REGISTERED-but-opt-in zstd id (2) must be
        // accepted by a store-and-forward broker on ANY build: a zstd-capable consumer can
        // decode what this broker's own build cannot.
        use ironbus_core::compress::{CODEC_ID_NONE, CODEC_ID_ZSTD};
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let none_codec = raw_descriptor(CODEC_ID_NONE, 0, 2, b"ab");
        let replies = compressed_pub_replies(&mut s, &e, &none_codec, false);
        assert_eq!(replies[0].0, FrameType::PubAck, "codec none is wire-legal");
        let zstd = raw_descriptor(CODEC_ID_ZSTD, 0, 64, b"opaque-to-this-build");
        let replies = compressed_pub_replies(&mut s, &e, &zstd, false);
        assert_eq!(
            replies[0].0,
            FrameType::PubAck,
            "the registered zstd id is accepted on every build"
        );
    }

    #[test]
    fn a_fire_and_forget_compressed_pub_over_garbage_sends_no_frame_and_appends_nothing() {
        // The QoS-0 no-frame contract (#11) holds for the #438 rejection too: a fire-and-forget
        // producer never reads a reply, so even this rejection sends NO frame (one frame would
        // permanently desync the reply stream); the record is dropped, nothing is appended, and
        // the session stays usable. This matches the dedup-id-cap precedent (a silent drop, no
        // counter: the engine's shed counters meter engine-decided load sheds, not
        // wire-malformed input that never reached the engine).
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let replies = compressed_pub_replies(&mut s, &e, b"garbage!", true);
        assert!(
            replies.is_empty(),
            "no frame to a QoS-0 producer, got {replies:?}"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            0,
            "nothing was appended"
        );
        // The session is still open: a ping answers.
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Ping, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Pong);
    }

    /// Connects a session with a `Connect` body REQUESTING a per-consumer credit (#292), returning the
    /// session and the negotiated credit the server advertised in its Info reply.
    fn connected_session_requesting<C: Clock + Clone + 'static>(
        e: &DirectEngine<InMemoryFs, C>,
        requested_credit: Option<u32>,
        requested_credit_bytes: Option<u64>,
    ) -> (Session, CreditAdvert<u32>) {
        let mut s = Session::new();
        let mut connect_body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                requested_credit,
                requested_credit_bytes,
                wants_gap_marker: false,
                default_ack_level: None,
                understands_streaming: false,
                default_tier: None,
                understands_deliver_batch: false,
                understands_streams: false,
                understands_compressed_delivery: false,
            },
            &mut connect_body,
        );
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Connect, &connect_body), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Info, "Connect is answered with Info");
        let info = ironbus_proto::message::decode_info(&body).unwrap();
        (s, info.credit.expect("the server advertises its credit"))
    }

    #[test]
    fn a_connect_credit_request_below_the_cap_is_the_negotiated_credit() {
        // #292 negotiation at the session layer: a server cap of 10, a Connect requesting 4 ->
        // negotiated min(4, 10) = 4, advertised in Info, and it GOVERNS the pull (a Flow asking 1000
        // delivers exactly 4).
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 10, 64));
        let (mut s, advert) = connected_session_requesting(&e, Some(4), None);
        assert_eq!(advert.negotiated, 4, "min(request 4, cap 10) = 4");
        assert_eq!(advert.cap, 10, "the server cap is advertised");
        for _ in 0..20 {
            produce(&e, b"m");
        }
        let batch = fetch(&mut s, &e, 1000);
        assert_eq!(
            batch.len(),
            4,
            "the negotiated credit of 4 governs the pull, not the cap 10 or the requested 1000"
        );
    }

    #[test]
    fn a_connect_credit_request_above_the_cap_is_clamped_to_the_cap() {
        // #292: a server cap of 3, a Connect requesting 100 -> negotiated min(100, 3) = 3. A request
        // can only TIGHTEN, never raise, the server cap.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 3, 64));
        let (mut s, advert) = connected_session_requesting(&e, Some(100), None);
        assert_eq!(advert.negotiated, 3, "min(request 100, cap 3) = 3");
        for _ in 0..20 {
            produce(&e, b"m");
        }
        assert_eq!(
            fetch(&mut s, &e, 1000).len(),
            3,
            "the cap of 3 binds the pull regardless of the request"
        );
    }

    #[test]
    fn a_zero_byte_request_cannot_disable_a_finite_cap() {
        // A byte budget of 0 means UNLIMITED. A client requesting 0 against a FINITE server cap
        // must be clamped DOWN to the cap, never granted unlimited, so it cannot turn off the
        // in-flight-byte ceiling the server set (the #275 byte-budget / memory-exhaustion guard).
        assert_eq!(negotiate_credit_bytes(Some(0), 8), 8);
        assert_eq!(negotiate_credit_bytes(Some(0), 64 * 1024), 64 * 1024);
        // Against an unlimited server (cap 0), a 0 request stays unlimited (both off).
        assert_eq!(negotiate_credit_bytes(Some(0), 0), 0);
        // A finite request still only tightens.
        assert_eq!(negotiate_credit_bytes(Some(4), 8), 4);
        assert_eq!(negotiate_credit_bytes(Some(20), 8), 8);
        assert_eq!(negotiate_credit_bytes(None, 8), 8);
    }

    #[test]
    fn a_zero_message_request_falls_back_to_the_server_credit() {
        // A 0-message request carries no budget (delivers nothing), so it takes the server default
        // rather than self-disabling; finite requests tighten.
        assert_eq!(negotiate_credit(Some(0), 64), 64);
        assert_eq!(negotiate_credit(None, 64), 64);
        assert_eq!(negotiate_credit(Some(16), 64), 16);
        assert_eq!(negotiate_credit(Some(100), 64), 64);
    }

    #[test]
    fn an_empty_connect_uses_the_server_default_credit() {
        // #292 backward-compat (client->server): an OLD client sends an EMPTY Connect body, so the
        // negotiated credit is the server default (the cap), advertised in Info and governing the pull.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 5, 64));
        // An empty Connect body, exactly as a pre-#292 client sends.
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Info);
        let info = ironbus_proto::message::decode_info(&body).unwrap();
        let advert = info
            .credit
            .expect("the server still advertises on an empty Connect");
        assert_eq!(
            advert.negotiated, 5,
            "an empty Connect -> the server default (5) is the negotiated credit"
        );
        for _ in 0..12 {
            produce(&e, b"m");
        }
        assert_eq!(
            fetch(&mut s, &e, 1000).len(),
            5,
            "the server default of 5 governs the pull for an old client"
        );
    }

    #[test]
    fn a_malformed_connect_body_is_a_typed_error_not_a_panic() {
        // #292 decode safety at the server: a hostile/corrupt Connect body (an unknown handshake
        // version) is answered with a typed Err, never a panic, and the connection stays open.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 5, 64));
        let mut s = Session::new();
        let mut out = Vec::new();
        // version 9 (unknown), then a zero field-length: a typed BadHandshakeVersion inside decode.
        s.process(&e, &frame(FrameType::Connect, &[9u8, 0, 0]), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "a malformed Connect body is a typed Err, not a panic"
        );
    }

    #[test]
    fn acking_restores_per_consumer_credit() {
        // After acking, the connection's credit frees and it can fetch more. With a credit of 2,
        // the first Flow delivers 2; acking one frees a slot so the next Flow delivers exactly 1.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 2, 64));
        let mut s = connected_session(&e);
        for _ in 0..10 {
            produce(&e, b"m");
        }
        let batch = fetch(&mut s, &e, 100);
        assert_eq!(batch.len(), 2, "credit 2 caps the first batch");
        // Saturated: nothing more until a slot frees.
        assert!(fetch(&mut s, &e, 100).is_empty(), "no credit left");
        // Ack one of the two: status 1 (committed), freeing exactly one slot.
        let (offset, generation) = batch[0];
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Ack, offset, generation),
            vec![1u8],
            "the ack commits and frees a slot"
        );
        // Exactly one delivery is now available again (the freed slot), not two.
        let batch2 = fetch(&mut s, &e, 100);
        assert_eq!(
            batch2.len(),
            1,
            "acking one freed exactly one credit, so the next Flow delivers exactly one"
        );
    }

    #[test]
    fn nack_and_term_each_restore_per_consumer_credit() {
        // A successful nack and a successful term both free the consumer's slot (#65), exactly like
        // an ack: a credit-1 consumer that nacks (then waits out the requeue delay) or terms can
        // fetch again.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 1, 64));
        let mut s = connected_session(&e);
        for _ in 0..3 {
            produce(&e, b"m");
        }
        // Term path: fetch one (credit now full), term it (frees the slot), fetch one more.
        let first = fetch(&mut s, &e, 10);
        assert_eq!(first.len(), 1, "credit 1 caps the batch");
        assert!(fetch(&mut s, &e, 10).is_empty(), "saturated");
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Term, first[0].0, first[0].1),
            vec![1u8],
            "term drops it and frees the slot"
        );
        let second = fetch(&mut s, &e, 10);
        assert_eq!(second.len(), 1, "term freed the slot");
        // Nack path: nack the second with no delay (the engine has an empty schedule, so it is
        // immediately reclaimable), which frees the slot; a later fetch redelivers it.
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Nack, second[0].0, second[0].1),
            vec![1u8],
            "nack requeues and frees the slot"
        );
        let third = fetch(&mut s, &e, 10);
        assert_eq!(third.len(), 1, "the freed slot lets the next Flow deliver");
    }

    #[test]
    fn one_stuck_consumer_does_not_starve_a_peer_in_the_same_group() {
        // THE core property (#65, per-consumer isolation from #10): two connections in the SAME
        // competing group, each with a credit of 2. Consumer A fills its credit and goes stuck (it
        // never acks). Consumer B still receives its FULL credit of deliveries; A's held leases do
        // not reduce B's available budget. The group window is roomy (64), so the only binding
        // bound is each consumer's own credit.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 2, 64));
        let mut a = connected_session(&e);
        let mut b = connected_session(&e);
        for _ in 0..10 {
            produce(&e, b"m");
        }
        // A fills its credit (2) and never acks: it is now stuck at its ceiling.
        let a_batch = fetch(&mut a, &e, 100);
        assert_eq!(a_batch.len(), 2, "A holds its full credit of 2");
        assert!(
            fetch(&mut a, &e, 100).is_empty(),
            "A is saturated and stuck"
        );
        // B, in the same group, still gets its full credit of 2: A's stuck leases did not touch B.
        let b_batch = fetch(&mut b, &e, 100);
        assert_eq!(
            b_batch.len(),
            2,
            "B receives its full credit; the stuck consumer A did not starve it"
        );
        // The two consumers hold disjoint offsets (a competing group hands each message to one
        // member), proving the budgets are independent, not shared.
        let a_offsets: std::collections::BTreeSet<u64> = a_batch.iter().map(|&(o, _)| o).collect();
        let b_offsets: std::collections::BTreeSet<u64> = b_batch.iter().map(|&(o, _)| o).collect();
        assert!(
            a_offsets.is_disjoint(&b_offsets),
            "A and B hold disjoint offsets: {a_offsets:?} vs {b_offsets:?}"
        );
        // B can keep draining as long as it acks; A staying stuck never blocks B. Ack B's two and
        // fetch two more: B makes unbounded progress while A holds its slots forever.
        for &(o, g) in &b_batch {
            assert_eq!(ack_reply(&mut b, &e, AckOp::Ack, o, g), vec![1u8]);
        }
        assert_eq!(
            fetch(&mut b, &e, 100).len(),
            2,
            "B keeps draining at its full credit while A stays stuck"
        );
    }

    #[test]
    fn an_expired_lease_frees_the_original_consumer_and_is_recounted_on_redelivery() {
        // Redelivery accounting (#65): a leased message whose lease EXPIRES frees the original
        // consumer's slot, and on redelivery counts against whoever next receives it. No message is
        // lost or double-counted; at-least-once holds. Credit 1 each, so the accounting is exact.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 1, 64));
        let mut a = connected_session(&e);
        let mut b = connected_session(&e);
        produce(&e, b"only");
        // A leases offset 0 (its single credit is now spent) and goes stuck.
        let a_first = fetch(&mut a, &e, 10);
        assert_eq!(a_first.len(), 1, "A leases offset 0");
        assert_eq!(a_first[0].0, 0);
        assert!(fetch(&mut a, &e, 10).is_empty(), "A is saturated");
        // The lease expires (visibility 30 ns). B fetches: the message redelivers to B under a NEW
        // generation, counting against B's credit. At-least-once: the message is not lost.
        clock.advance_monotonic_nanos(40);
        let b_first = fetch(&mut b, &e, 10);
        assert_eq!(b_first.len(), 1, "the expired message redelivers to B");
        assert_eq!(b_first[0].0, 0, "same offset, redelivered");
        assert_ne!(
            b_first[0].1, a_first[0].1,
            "redelivery fences A's generation with a fresh one for B"
        );
        // B is now saturated (its one credit holds offset 0); A, whose lease expired, has had its
        // slot freed by the start-of-Flow stale-lease prune, so A can fetch again. But the only
        // message is in flight to B, so A gets nothing until it expires again: A's credit is free
        // (proving the slot was released) yet no double-delivery occurs.
        assert!(fetch(&mut b, &e, 10).is_empty(), "B is now saturated");
        let a_after = fetch(&mut a, &e, 10);
        assert!(
            a_after.is_empty(),
            "A's slot is free but offset 0 is leased to B, so no double-delivery"
        );
        // A's stale token is fenced (B owns the live lease now): status 0, nothing committed.
        assert_eq!(
            ack_reply(&mut a, &e, AckOp::Ack, a_first[0].0, a_first[0].1),
            vec![0u8],
            "A's stale generation is fenced"
        );
        assert_eq!(
            e.engine_mut().committed_offset().get(),
            0,
            "nothing committed by the fence"
        );
        // B, the live holder, acks and commits exactly once: no double-count.
        assert_eq!(
            ack_reply(&mut b, &e, AckOp::Ack, b_first[0].0, b_first[0].1),
            vec![1u8],
            "B owns the live lease and commits"
        );
        assert_eq!(
            e.engine_mut().committed_offset().get(),
            1,
            "the message is committed exactly once across the expire-and-redeliver"
        );
    }

    #[test]
    fn a_redelivery_to_the_same_consumer_still_counts_as_one_slot() {
        // An own expired lease redelivered back to the SAME consumer re-occupies exactly ONE slot,
        // not two (#65): the redelivery overwrites the same offset key, so a credit-1 consumer that
        // re-fetches its own expired message holds one, not zero-then-overflow.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 1, 64));
        let mut s = connected_session(&e);
        produce(&e, b"x");
        let first = fetch(&mut s, &e, 10);
        assert_eq!(first.len(), 1);
        // Expire and re-fetch: the same offset redelivers to the same consumer under a new
        // generation, still occupying exactly its one slot.
        clock.advance_monotonic_nanos(40);
        let second = fetch(&mut s, &e, 10);
        assert_eq!(second.len(), 1, "the own expired message redelivers");
        assert_eq!(second[0].0, 0, "same offset");
        assert_ne!(second[0].1, first[0].1, "fresh generation");
        // Still exactly one slot held: a second Flow delivers nothing (credit 1 is full), proving
        // the redelivery did not leak a second slot.
        assert!(
            fetch(&mut s, &e, 10).is_empty(),
            "the redelivery re-occupied one slot, not two"
        );
        // Acking the live token commits and frees the slot.
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Ack, second[0].0, second[0].1),
            vec![1u8]
        );
        assert_eq!(e.engine_mut().committed_offset().get(), 1);
    }

    #[test]
    fn the_effective_bound_is_the_min_of_the_group_window_and_the_consumer_credit() {
        // The effective Flow bound is min(producer-side group window, consumer credit). Here the
        // GROUP window (2) is smaller than the consumer credit (64), so a single consumer is capped
        // at the group window, exactly as before #65 (no regression to the per-group bound).
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit(Arc::clone(&clock), 64, 2));
        let mut s = connected_session(&e);
        for _ in 0..10 {
            produce(&e, b"m");
        }
        let batch = fetch(&mut s, &e, 100);
        assert_eq!(
            batch.len(),
            2,
            "the group window of 2 is the binding bound when it is below the consumer credit"
        );
    }

    #[test]
    fn the_default_single_consumer_flow_path_is_unchanged() {
        // The existing single-consumer Flow path (credit defaulted) still works: a connect, a
        // produce, and a fetch deliver the message, with the default credit large enough not to be
        // the binding bound for a small batch.
        let e = DirectEngine::new(engine()); // consumer_credit defaulted to 64 in the test helper
        let mut s = connected_session(&e);
        produce(&e, b"a");
        produce(&e, b"b");
        let batch = fetch(&mut s, &e, 10);
        assert_eq!(
            batch.len(),
            2,
            "both messages delivered on the default path"
        );
        for (o, g) in batch {
            assert_eq!(ack_reply(&mut s, &e, AckOp::Ack, o, g), vec![1u8]);
        }
        assert_eq!(e.engine_mut().committed_offset().get(), 2);
    }

    // ----- Per-consumer BYTE budget (refs #65, #275, #10, #20) -----

    /// Produces a record whose total byte size (key + headers + payload) is exactly `size`: an empty
    /// key and headers, so the payload alone carries the bytes the per-consumer byte budget counts.
    fn produce_sized<C: Clock + Clone>(e: &DirectEngine<InMemoryFs, C>, size: usize) {
        produce(e, &vec![0xab; size]);
    }

    #[test]
    fn the_byte_budget_binds_before_the_message_credit() {
        // The byte budget binds (#275): a roomy MESSAGE credit (64) but a tight BYTE budget (200)
        // with 100-byte messages stops the batch at 2 messages (in-flight reaches 200 = the budget,
        // so the third is refused), even though message credit and the group window are far from
        // exhausted. The byte budget is the binding constraint. Delivery proceeds while in-flight
        // bytes are BELOW the budget and stops once they reach it, so the in-flight total is bounded
        // by the budget rounded up to a whole message.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 200, 64));
        let mut s = connected_session(&e);
        for _ in 0..10 {
            produce_sized(&e, 100);
        }
        let batch = fetch(&mut s, &e, 100);
        assert_eq!(
            batch.len(),
            2,
            "the byte budget of 200 caps the batch at 2x100 bytes, not the message credit of 64"
        );
        // Saturated on bytes: a second Flow delivers nothing until bytes free up.
        assert!(
            fetch(&mut s, &e, 100).is_empty(),
            "in-flight bytes have reached the budget, so no more deliveries"
        );
    }

    #[test]
    fn the_floor_of_one_lets_a_single_over_budget_message_through() {
        // The hard floor of ONE (#275): a single message LARGER than the whole byte budget is still
        // delivered when the connection holds nothing in-flight, so an over-budget message never
        // wedges the consumer. Budget 100, one 500-byte message: it is delivered.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 100, 64));
        let mut s = connected_session(&e);
        produce_sized(&e, 500);
        produce_sized(&e, 500);
        let batch = fetch(&mut s, &e, 100);
        assert_eq!(
            batch.len(),
            1,
            "the floor-of-one delivers one over-budget message so it never wedges the consumer"
        );
        // But ONLY one: with one over-budget message in flight, the floor no longer applies, so the
        // second over-budget message waits until the first frees its bytes.
        assert!(
            fetch(&mut s, &e, 100).is_empty(),
            "the floor is one; the second over-budget message waits for bytes to free"
        );
    }

    #[test]
    fn acking_restores_the_byte_budget() {
        // The byte budget is restored on ack exactly like the message credit (#275): a budget of 100
        // with 100-byte messages holds exactly one (in-flight reaches the budget, so a second is
        // refused); acking it frees its 100 bytes so the next Flow delivers one more.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 100, 64));
        let mut s = connected_session(&e);
        for _ in 0..5 {
            produce_sized(&e, 100);
        }
        let first = fetch(&mut s, &e, 100);
        assert_eq!(first.len(), 1, "100 bytes in flight reaches the budget");
        assert!(fetch(&mut s, &e, 100).is_empty(), "byte-saturated");
        // Ack frees the 100 bytes.
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Ack, first[0].0, first[0].1),
            vec![1u8],
            "the ack commits and frees the message's bytes"
        );
        let second = fetch(&mut s, &e, 100);
        assert_eq!(
            second.len(),
            1,
            "acking freed exactly the message's bytes, so the next Flow delivers one"
        );
    }

    #[test]
    fn nack_and_term_each_restore_the_byte_budget() {
        // A successful nack and a successful term both restore the message's bytes (#275), exactly
        // like the message credit: a byte-saturated consumer that nacks or terms can fetch again.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 100, 64));
        let mut s = connected_session(&e);
        for _ in 0..3 {
            produce_sized(&e, 100);
        }
        // Term path: fetch one (byte budget now full), term it (frees its bytes), fetch one more.
        let first = fetch(&mut s, &e, 10);
        assert_eq!(first.len(), 1, "100 bytes in flight caps the batch");
        assert!(fetch(&mut s, &e, 10).is_empty(), "byte-saturated");
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Term, first[0].0, first[0].1),
            vec![1u8],
            "term drops it and frees its bytes"
        );
        let second = fetch(&mut s, &e, 10);
        assert_eq!(second.len(), 1, "term freed the bytes");
        // Nack path: nack with no delay (immediately reclaimable), which frees the bytes.
        assert_eq!(
            ack_reply(&mut s, &e, AckOp::Nack, second[0].0, second[0].1),
            vec![1u8],
            "nack requeues and frees its bytes"
        );
        let third = fetch(&mut s, &e, 10);
        assert_eq!(third.len(), 1, "the freed bytes let the next Flow deliver");
    }

    #[test]
    fn an_expired_lease_restores_the_byte_budget_on_start_of_flow_release() {
        // The byte budget is restored on the start-of-Flow stale-lease release (#275), the redelivery
        // accounting seam: a byte-saturated consumer whose lease EXPIRES has its bytes freed by the
        // next Flow's stale-lease prune, so it can fetch again. Budget 100, one 100-byte message.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 100, 64));
        let mut s = connected_session(&e);
        produce_sized(&e, 100);
        produce_sized(&e, 50);
        let first = fetch(&mut s, &e, 10);
        assert_eq!(first.len(), 1, "the 100-byte message fills the budget");
        assert!(fetch(&mut s, &e, 10).is_empty(), "byte-saturated");
        // Expire the lease: the next Flow's stale-lease prune frees the 100 bytes, so the 50-byte
        // message (offset 1) is now deliverable. The expired message also redelivers, but to whoever
        // next polls; here the same consumer re-claims offset 0 first (lower offset), then offset 1.
        clock.advance_monotonic_nanos(40);
        let after = fetch(&mut s, &e, 10);
        assert!(
            !after.is_empty(),
            "the start-of-Flow stale-lease prune freed the bytes, so delivery resumes"
        );
        // The first re-delivered offset is 0 (the expired message, re-occupying its 100 bytes once).
        assert_eq!(after[0].0, 0, "the expired message redelivers first");
    }

    #[test]
    fn a_redelivery_re_occupies_its_bytes_exactly_once() {
        // A redelivered message re-occupies its bytes ONCE (#275): the redelivery overwrites the same
        // offset key in `leased`, so the byte total never doubles. Budget 100, one 100-byte message
        // re-fetched after expiry still holds exactly 100 bytes, not 200.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 100, 64));
        let mut s = connected_session(&e);
        produce_sized(&e, 100);
        let first = fetch(&mut s, &e, 10);
        assert_eq!(first.len(), 1);
        // Expire and re-fetch: the same offset redelivers, re-occupying exactly its 100 bytes.
        clock.advance_monotonic_nanos(40);
        let second = fetch(&mut s, &e, 10);
        assert_eq!(second.len(), 1, "the own expired message redelivers");
        assert_eq!(second[0].0, 0, "same offset");
        assert_ne!(second[0].1, first[0].1, "fresh generation");
        // Still exactly 100 bytes in flight (one slot), so a second Flow delivers nothing: the
        // redelivery did not leak a second 100-byte occupancy.
        assert!(
            fetch(&mut s, &e, 10).is_empty(),
            "the redelivery re-occupied its bytes once, not twice"
        );
    }

    #[test]
    fn the_effective_credit_is_the_min_of_message_and_byte_both_directions() {
        // The effective per-Flow credit is min(message credits remaining, byte credits remaining),
        // verified BOTH directions (#275).
        let clock = Arc::new(ManualClock::new());
        // Direction 1: bytes bind. Message credit 64 (roomy), byte budget 200 with 100-byte
        // messages, group window 64 -> 2 deliveries (the byte budget is the min).
        {
            let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 200, 64));
            let mut s = connected_session(&e);
            for _ in 0..10 {
                produce_sized(&e, 100);
            }
            assert_eq!(
                fetch(&mut s, &e, 100).len(),
                2,
                "bytes bind: min(64 msgs, 200/100 bytes) = 2"
            );
        }
        // Direction 2: the message credit binds. Message credit 2 (tight), byte budget 100_000
        // (roomy) with 100-byte messages, group window 64 -> 2 deliveries (the message credit is the
        // min).
        {
            let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 2, 100_000, 64));
            let mut s = connected_session(&e);
            for _ in 0..10 {
                produce_sized(&e, 100);
            }
            assert_eq!(
                fetch(&mut s, &e, 100).len(),
                2,
                "the message credit binds: min(2 msgs, roomy bytes) = 2"
            );
        }
    }

    #[test]
    fn a_zero_byte_budget_is_unlimited() {
        // `0` = unlimited (#275): the byte budget is off, so only the message credit binds. A roomy
        // message credit (64) with a zero byte budget and many large messages delivers up to the
        // group window, never stopping on bytes.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(Arc::clone(&clock), 64, 0, 64));
        let mut s = connected_session(&e);
        for _ in 0..10 {
            produce_sized(&e, 100_000);
        }
        let batch = fetch(&mut s, &e, 100);
        assert_eq!(
            batch.len(),
            10,
            "a zero byte budget is unlimited, so only the message credit (and availability) bounds"
        );
    }

    #[test]
    fn the_default_byte_budget_does_not_bind_small_messages() {
        // The default 8 MiB byte budget is generous for the small records an edge broker carries: a
        // handful of tiny messages all deliver, the byte budget never binding. Wired with the real
        // production default const so the default path is exercised, not a test-local 0.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_credit_bytes(
            Arc::clone(&clock),
            64,
            crate::engine::DEFAULT_CONSUMER_CREDIT_BYTES,
            64,
        ));
        let mut s = connected_session(&e);
        for _ in 0..5 {
            produce(&e, b"small");
        }
        let batch = fetch(&mut s, &e, 100);
        assert_eq!(
            batch.len(),
            5,
            "the default 8 MiB byte budget does not bind a handful of small messages"
        );
    }

    /// An engine with idle named-group eviction ENABLED (#277), for the explicit-Unsub reclaim test.
    /// The window value is irrelevant to the explicit-Unsub path (it bypasses the idle wait), but it
    /// must be non-zero so the lifecycle policy is on at all.
    fn engine_evict(clock: Arc<ManualClock>) -> Engine<InMemoryFs, Arc<ManualClock>> {
        Engine::open(
            InMemoryFs::new(),
            clock,
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 10,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: 10, // eviction ON; the explicit-Unsub path ignores the window
                disk_full_policy: DiskFullPolicy::DropNew,
                ram_ceiling_bytes: 0,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
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
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn unsub_reclaims_a_caught_up_named_group_immediately() {
        // The Unsub interaction (#277): a connection that subscribes to a NAMED group, drains and
        // acks it (caught up, lease-free), then UNSUBs has that group reclaimed RIGHT NOW, freeing
        // its slot. A re-subscribe resumes at the head and redelivers nothing it had acked.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_evict(Arc::clone(&clock)));
        produce(&e, b"a");
        produce(&e, b"b");
        let mut s = connected_session(&e);
        // SUB to "orders", FLOW to drain both, then ACK both: the group is caught up and lease-free.
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Sub, b"orders"), &mut out)
            .unwrap();
        assert!(
            !e.engine_mut().has_group("orders"),
            "SUB alone does not create the group; the first FLOW does"
        );
        let batch = fetch(&mut s, &e, 10);
        assert_eq!(batch.len(), 2, "both messages delivered to the named group");
        assert!(
            e.engine_mut().has_group("orders"),
            "the FLOW created the named group"
        );
        for (offset, generation) in &batch {
            ack_reply(&mut s, &e, AckOp::Ack, *offset, *generation);
        }
        let committed = e.engine_mut().committed_offset_in("orders");
        let flushed = e.engine_mut().flushed_offset();
        assert_eq!(committed, flushed, "caught up");
        // UNSUB: the now-idle, caught-up, lease-free named group is reclaimed immediately.
        out.clear();
        s.process(&e, &frame(FrameType::Unsub, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "UNSUB is acked");
        assert!(
            !e.engine_mut().has_group("orders"),
            "UNSUB reclaimed the caught-up, lease-free named group"
        );
        // Re-subscribe and produce one more: the re-created group resumes at the head and delivers
        // ONLY the new record, never the acked a/b (the never-lose-committed-position invariant).
        produce(&e, b"c");
        s.process(&e, &frame(FrameType::Sub, b"orders"), &mut out)
            .unwrap();
        let again = fetch(&mut s, &e, 10);
        assert_eq!(
            again.len(),
            1,
            "only the new record redelivers, nothing acked"
        );
        assert_eq!(
            again[0].0, 2,
            "resumes at the head (offset 2), not the log start"
        );
    }

    #[test]
    fn unsub_does_not_reclaim_a_group_with_an_unacked_in_flight_lease() {
        // A connection that drained a named group but did NOT ack still holds that delivery as an
        // in-flight lease in the engine; UNSUB must NOT reclaim the group while a lease is live, so
        // the in-flight bookkeeping (and the eventual redelivery after the timeout) is never dropped.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_evict(Arc::clone(&clock)));
        produce(&e, b"a");
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Sub, b"orders"), &mut out)
            .unwrap();
        let batch = fetch(&mut s, &e, 10);
        assert_eq!(batch.len(), 1, "the one message is delivered but NOT acked");
        // UNSUB without acking: the lease is still live in the engine, so the group is kept.
        out.clear();
        s.process(&e, &frame(FrameType::Unsub, b""), &mut out)
            .unwrap();
        assert!(
            e.engine_mut().has_group("orders"),
            "UNSUB must not reclaim a group with an in-flight lease"
        );
    }

    /// Encodes one at-least-once PUB frame carrying `payload`, for the pipelined-window tests
    /// (#450).
    fn pub_frame(payload: &[u8]) -> Vec<u8> {
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload,
            },
            &mut pub_body,
        )
        .unwrap();
        frame(FrameType::Pub, &pub_body)
    }

    #[test]
    fn pipelined_pubs_in_one_pass_reply_fifo_acks_in_frame_order() {
        // The pipelined window's WIRE contract (#450): N PUB frames in ONE input buffer get N
        // PubAcks with the assigned offsets in FRAME order, and a non-produce frame between them
        // (a Ping) gets its reply IN PLACE: the parked acks before it are released first, so the
        // reply order on the wire is exactly the frame order (the per-connection FIFO contract).
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let mut input = Vec::new();
        input.extend_from_slice(&pub_frame(b"a"));
        input.extend_from_slice(&pub_frame(b"b"));
        input.extend_from_slice(&frame(FrameType::Ping, b""));
        input.extend_from_slice(&pub_frame(b"c"));
        let mut out = Vec::new();
        let progress = s.process(&e, &input, &mut out).unwrap();
        assert_eq!(progress.consumed, input.len(), "the whole pass consumed");
        let frames = decode_all(&out);
        let kinds: Vec<FrameType> = frames.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            kinds,
            vec![
                FrameType::PubAck,
                FrameType::PubAck,
                FrameType::Pong,
                FrameType::PubAck
            ],
            "replies in frame order: the parked acks are released before the Pong"
        );
        let offsets: Vec<u64> = frames
            .iter()
            .filter(|(t, _)| *t == FrameType::PubAck)
            .map(|(_, body)| decode_pub_ack(body).unwrap().offset)
            .collect();
        assert_eq!(offsets, vec![0, 1, 2], "FIFO acks carry the FIFO offsets");
    }

    #[test]
    fn a_malformed_pub_mid_window_consumes_its_reply_slot_in_order() {
        // A mid-window rejection must not desync the pipelined reply stream (#450): the malformed
        // PUB's `Err` frame occupies ITS slot in the FIFO reply order (after the first produce's
        // ack, before the next produce's), so a pipelining client can map reply k to message k.
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let mut input = Vec::new();
        input.extend_from_slice(&pub_frame(b"a"));
        // A PUB whose body is too short to decode: a typed, connection-preserving reject.
        input.extend_from_slice(&frame(FrameType::Pub, b""));
        input.extend_from_slice(&pub_frame(b"c"));
        let mut out = Vec::new();
        let progress = s.process(&e, &input, &mut out).unwrap();
        assert_eq!(progress.consumed, input.len());
        let frames = decode_all(&out);
        let kinds: Vec<FrameType> = frames.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            kinds,
            vec![FrameType::PubAck, FrameType::Err, FrameType::PubAck],
            "the rejection's Err frame sits in its own reply slot, in frame order"
        );
        assert_eq!(decode_pub_ack(&frames[0].1).unwrap().offset, 0);
        assert_eq!(
            decode_pub_ack(&frames[2].1).unwrap().offset,
            1,
            "the rejected PUB appended nothing, so the next produce takes offset 1"
        );
    }

    /// A test-only [`EngineAccess`] wrapper over the REAL [`crate::actor::EngineHandle`] that opens
    /// the fault-fs sync gate the moment the LAST produce of the expected window has been
    /// SUBMITTED (#450). It is the determinism seam for the fewer-fsyncs-than-N proof: while the
    /// gate is closed the actor is provably parked inside the primer's covering fsync, so every
    /// windowed produce is queued in the channel by the time the gate opens, and the actor's next
    /// drain covers the WHOLE window with one `commit_batch`. No wall-clock sleep anywhere.
    struct GateOpeningHandle {
        inner: crate::actor::EngineHandle<ironbus_storage::fault::FaultFs<InMemoryFs>, ManualClock>,
        control: ironbus_storage::fault::FaultControl,
        /// Produces left before the gate opens; `Cell` suffices because a session drives its
        /// engine access from one thread.
        remaining: std::cell::Cell<usize>,
    }

    impl EngineAccess<ironbus_storage::fault::FaultFs<InMemoryFs>, ManualClock> for GateOpeningHandle {
        fn produce(
            &self,
            append: crate::actor::OwnedAppend,
        ) -> Result<ProduceOutcome, crate::actor::ActorGone> {
            self.inner.produce(append)
        }
        fn produce_submit(
            &self,
            append: crate::actor::OwnedAppend,
        ) -> Result<ProduceSubmission, crate::actor::ActorGone> {
            let submission = self.inner.produce_submit(append)?;
            let left = self.remaining.get().saturating_sub(1);
            self.remaining.set(left);
            if left == 0 {
                // The whole window is in the actor's channel: release the parked primer fsync.
                self.control.open_sync_gate();
            }
            Ok(submission)
        }
        fn with<R, J>(&self, job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<ironbus_storage::fault::FaultFs<InMemoryFs>, ManualClock>) -> R
                + Send
                + 'static,
        {
            self.inner.with(job)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            self.inner.now_monotonic_nanos()
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            self.inner.consumer_credit_caps()
        }
    }

    #[test]
    fn a_pipelined_window_from_one_connection_group_commits_with_fewer_fsyncs_than_n() {
        // THE TEETH for the pipelined publish window (#450), at the WIRE/session layer over the
        // REAL append actor: N PUB frames pipelined into ONE process pass from ONE connection are
        // covered by ONE group-commit fsync (not N), every record durably lands, and the acks come
        // back as N correct FIFO PubAcks in frame order. Determinism: the sync gate parks the actor
        // on a primer produce's covering fsync; the GateOpeningHandle opens the gate only after the
        // session has SUBMITTED the whole window, so the actor's next drain provably sees all N.
        use crate::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
        use ironbus_storage::fault::FaultFs;

        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), test_config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);

        // Handshake BEFORE the gate closes (Connect never touches the actor's fsync path).
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&handle, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();

        // Park the actor inside a primer produce's covering fsync: a provable barrier. Until the
        // gate opens the actor consumes NO further command, so the whole window below queues into
        // the channel and is drained as ONE batch (the same trick as the actor group-commit test).
        control.close_sync_gate();
        let primer = handle
            .produce_submit(crate::actor::OwnedAppend {
                timestamp_ms: 0,
                flags: 0,
                key: Bytes::new(),
                headers: Bytes::new(),
                payload: Bytes::from_static(b"primer"),
                body_checksums: None,
                dedup: None,
                enqueue_monotonic_nanos: 0,
                fire_and_forget: false,
                ack_level: ironbus_proto::message::AckLevel::ServerAck,
            })
            .unwrap();
        control.wait_for_sync_gate_entered(1);

        // The pipelined window: N PUB frames in ONE input buffer, ONE process pass. The pass submits
        // all N (opening the gate on the last submission) and PARKS them. Since #1045 the pass no longer
        // block-awaits the window at its end — it releases only the ready front prefix and persists the
        // rest — so the acks are collected with an explicit `flush_all_parked_blocking`, exactly what
        // the connection loop does on a clean EOF or a would-block. The #450 teeth are unchanged: N
        // pipelined produces are still covered by ONE group-commit fsync and acked as N FIFO PubAcks.
        let n: u64 = 8;
        let mut input = Vec::new();
        for i in 0..n {
            input.extend_from_slice(&pub_frame(format!("m{i}").as_bytes()));
        }
        let before = control.sync_count();
        let window_handle = GateOpeningHandle {
            inner: handle.clone(),
            control: control.clone(),
            remaining: std::cell::Cell::new(usize::try_from(n).unwrap()),
        };
        let progress = s.process(&window_handle, &input, &mut out).unwrap();
        assert_eq!(progress.consumed, input.len(), "the whole window consumed");
        // Drain the persistent window (the gate is already open, so the actor group-commits all N and
        // the FIFO acks flush into `out` — combined with any the pass's ready-prefix already released).
        s.flush_all_parked_blocking(&handle, &mut out).unwrap();

        // The primer (awaited only now) and the window are all durable.
        assert!(matches!(primer.wait().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0));

        // N CORRECT FIFO ACKS: one PubAck per PUB, in frame order, with the contiguous offsets
        // after the primer.
        let frames = decode_all(&out);
        assert_eq!(frames.len(), usize::try_from(n).unwrap());
        let offsets: Vec<u64> = frames
            .iter()
            .map(|(t, body)| {
                assert_eq!(*t, FrameType::PubAck);
                decode_pub_ack(body).unwrap().offset
            })
            .collect();
        assert_eq!(
            offsets,
            (1..=n).collect::<Vec<_>>(),
            "FIFO acks with contiguous offsets after the primer"
        );

        // FEWER FSYNCS THAN N: the primer's gated fsync plus ONE covering `commit_batch` for the
        // whole window. (The `before` snapshot was taken while the actor was parked, so the
        // primer's own sync is already counted; the delta is the window's.)
        let window_syncs = control.sync_count() - before;
        assert_eq!(
            window_syncs, 1,
            "the whole pipelined window was covered by ONE group-commit fsync, not {n}"
        );

        // Durability: every record (primer + window) is at or below the flushed head.
        let head = handle.with(|e| e.flushed_offset().get()).unwrap();
        assert_eq!(head, n + 1, "primer + window all durable");

        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join().unwrap();
    }

    #[test]
    fn overlap_a_second_pass_of_produces_is_in_flight_before_the_first_ack_1045() {
        // #1045 OVERLAP TEETH: a `process` pass no longer block-awaits its parked window at the pass
        // boundary, so ONE connection can submit batch N+1 while batch N's group-commit fdatasync is
        // still in flight — the single-connection ceiling this closes. Proven deterministically with the
        // fault-fs sync gate: park the actor inside a primer's fsync (gate closed), then run TWO
        // SEPARATE process passes of PUBs. Under the OLD block-at-pass-end design the FIRST pass would
        // hang inside its drain; under #1045 both passes RETURN with the actor still parked, so 2*BATCH
        // produces are in flight and ZERO acks have been written. Opening the gate then drains them as
        // 2*BATCH FIFO PubAcks under ONE covering fsync (group commit preserved).
        use crate::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
        use ironbus_storage::fault::FaultFs;

        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), test_config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);

        // Handshake before the gate closes (Connect never touches the fsync path).
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&handle, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();

        // Park the actor inside a primer produce's covering fsync: a provable barrier. Until the gate
        // opens the actor consumes NO further command, so every windowed produce stays queued/parked.
        control.close_sync_gate();
        let primer = handle
            .produce_submit(crate::actor::OwnedAppend {
                timestamp_ms: 0,
                flags: 0,
                key: Bytes::new(),
                headers: Bytes::new(),
                payload: Bytes::from_static(b"primer"),
                body_checksums: None,
                dedup: None,
                enqueue_monotonic_nanos: 0,
                fire_and_forget: false,
                ack_level: ironbus_proto::message::AckLevel::ServerAck,
            })
            .unwrap();
        control.wait_for_sync_gate_entered(1);
        let before = control.sync_count();

        // PASS 1: submit a batch of PUBs. The pass parks them and RETURNS without block-awaiting (the
        // actor is still parked in the primer fsync, so nothing is ready to release).
        let batch: u64 = 4;
        let mut pass1 = Vec::new();
        for i in 0..batch {
            pass1.extend_from_slice(&pub_frame(format!("a{i}").as_bytes()));
        }
        s.process(&handle, &pass1, &mut out).unwrap();
        assert!(
            out.is_empty(),
            "pass 1 wrote no ack — the batch's covering fsync is still gated"
        );
        assert_eq!(
            s.parked_len(),
            usize::try_from(batch).unwrap(),
            "pass 1's batch is parked, not block-awaited"
        );

        // PASS 2: submit a SECOND batch. This pass is only reachable because pass 1 did NOT block on its
        // window (the overlap). The window now spans BOTH passes with the actor still parked.
        let mut pass2 = Vec::new();
        for i in 0..batch {
            pass2.extend_from_slice(&pub_frame(format!("b{i}").as_bytes()));
        }
        s.process(&handle, &pass2, &mut out).unwrap();
        assert!(out.is_empty(), "pass 2 wrote no ack either — still gated");
        assert_eq!(
            s.parked_len(),
            usize::try_from(2 * batch).unwrap(),
            "MORE THAN ONE PASS's worth of produces are in flight before the first ack (the #1045 overlap)"
        );

        // Release the gate: the primer commits, then the actor drains the WHOLE 2*BATCH window and
        // covers it with ONE group-commit fsync. Drain: 2*BATCH FIFO PubAcks, contiguous offsets after
        // the primer.
        control.open_sync_gate();
        assert!(matches!(primer.wait().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0));
        s.flush_all_parked_blocking(&handle, &mut out).unwrap();
        assert_eq!(s.parked_len(), 0, "the whole window drained");
        let offsets: Vec<u64> = decode_all(&out)
            .iter()
            .map(|(t, body)| {
                assert_eq!(*t, FrameType::PubAck);
                decode_pub_ack(body).unwrap().offset
            })
            .collect();
        assert_eq!(
            offsets,
            (1..=2 * batch).collect::<Vec<_>>(),
            "FIFO acks with contiguous offsets after the primer (order preserved across two passes)"
        );
        let window_syncs = control.sync_count() - before;
        assert_eq!(
            window_syncs,
            1,
            "both passes' produces group-committed under ONE fsync, not {}",
            2 * batch
        );

        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join().unwrap();
    }

    #[test]
    fn interleaved_produce_and_non_produce_frames_reply_in_frame_order_under_the_nonblocking_release_1045(
    ) {
        // #1045 + #917: with the non-blocking ready-prefix release, the wire reply order under
        // INTERLEAVED produce and non-produce frames must STILL be exactly the frame order. A
        // non-produce frame block-drains the full parked prefix before its own reply (a pong must come
        // after every prior produce ack), and the ready-prefix releases produces FIFO — so the replies
        // are frame-order no matter which path released each produce.
        use crate::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};

        let engine = Engine::open(InMemoryFs::new(), ManualClock::new(), test_config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&handle, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();

        // Interleave PUB, PING, PUB, PING in ONE buffer / ONE pass. Ending on a non-produce frame keeps
        // the pass deterministic: each PING's block-drain flushes the preceding PUB's ack before its
        // Pong, so `out` carries the full sequence in exact frame order.
        let mut input = Vec::new();
        input.extend_from_slice(&pub_frame(b"x0"));
        input.extend_from_slice(&frame(FrameType::Ping, b""));
        input.extend_from_slice(&pub_frame(b"x1"));
        input.extend_from_slice(&frame(FrameType::Ping, b""));
        s.process(&handle, &input, &mut out).unwrap();
        // Any produce still parked at the final pass boundary would be flushed by the connection loop;
        // do it explicitly (a no-op here, since the trailing PING already block-drained the window).
        s.flush_all_parked_blocking(&handle, &mut out).unwrap();

        let frames = decode_all(&out);
        let kinds: Vec<FrameType> = frames.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            kinds,
            vec![
                FrameType::PubAck,
                FrameType::Pong,
                FrameType::PubAck,
                FrameType::Pong
            ],
            "interleaved replies are in exact frame order (FIFO #917 across the non-blocking release)"
        );
        assert_eq!(decode_pub_ack(&frames[0].1).unwrap().offset, 0);
        assert_eq!(
            decode_pub_ack(&frames[2].1).unwrap().offset,
            1,
            "the second produce takes the next offset — FIFO, no reorder"
        );

        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join().unwrap();
    }

    /// A test [`EngineAccess`] that hands out PRE-BUILT pending produce submissions (#1045), so a test
    /// can control DETERMINISTICALLY when each parked produce's outcome becomes ready — exercising the
    /// persistent parked-window ring and its `MAX_PARKED_PRODUCES` cap without a real actor or fsync.
    /// `produce_submit` pops the next queued submission; the test drives readiness by sending on the
    /// matching [`std::sync::mpsc::SyncSender`] returned by [`ProduceSubmission::pending_for_test`].
    struct ScriptedSubmitEngine {
        submissions: std::cell::RefCell<VecDeque<ProduceSubmission>>,
    }

    impl ScriptedSubmitEngine {
        /// Builds `n` pending submissions, returning the engine and the per-submission senders (index-
        /// aligned): sending `ProduceOutcome::Appended(Offset::new(i))` on `senders[i]` makes the i-th
        /// produce observe as ready with offset `i`, so the released acks are FIFO-checkable.
        fn new(n: usize) -> (Self, Vec<std::sync::mpsc::SyncSender<ProduceOutcome>>) {
            let mut submissions = VecDeque::with_capacity(n);
            let mut senders = Vec::with_capacity(n);
            for _ in 0..n {
                let (submission, tx) = ProduceSubmission::pending_for_test();
                submissions.push_back(submission);
                senders.push(tx);
            }
            (
                Self {
                    submissions: std::cell::RefCell::new(submissions),
                },
                senders,
            )
        }
    }

    impl EngineAccess<InMemoryFs, ManualClock> for ScriptedSubmitEngine {
        fn produce(&self, _append: OwnedAppend) -> Result<ProduceOutcome, ActorGone> {
            // Never reached: `handle_pub` routes an at-least-once produce through `produce_submit`.
            Ok(ProduceOutcome::Appended(Offset::new(0)))
        }
        fn produce_submit(&self, _append: OwnedAppend) -> Result<ProduceSubmission, ActorGone> {
            Ok(self
                .submissions
                .borrow_mut()
                .pop_front()
                .expect("scripted submission underflow"))
        }
        fn with<R, J>(&self, _job: J) -> Result<R, ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, ManualClock>) -> R + Send + 'static,
        {
            Err(ActorGone)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            0
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            (64, 0)
        }
    }

    #[test]
    fn the_persistent_parked_window_is_bounded_by_the_max_parked_cap_1045() {
        // #1045: the pipelined window is PERSISTENT (survives across passes) and BOUNDED at
        // `MAX_PARKED_PRODUCES` entries even when acks lag arrivals. First prove persistence + unbounded-
        // free accumulation up to just under the cap with NO outcomes released (deterministic, no
        // threads); then release every outcome from a background thread and drive the window PAST the
        // cap, so `enforce_parked_cap` (release-ready-prefix, then block-drain the front until under the
        // cap) keeps memory bounded while every ack is still delivered exactly once in FIFO order.
        let n = MAX_PARKED_PRODUCES + 4;
        let (engine, senders) = ScriptedSubmitEngine::new(n);
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&engine, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();

        // PASS 1 then PASS 2, one PUB each, no outcomes released: the window PERSISTS across passes.
        s.process(&engine, &pub_frame(b"p"), &mut out).unwrap();
        assert_eq!(s.parked_len(), 1, "pass 1's produce persists");
        s.process(&engine, &pub_frame(b"p"), &mut out).unwrap();
        assert_eq!(
            s.parked_len(),
            2,
            "pass 2's produce is ADDED to the persisted window (it survived the pass boundary)"
        );

        // PASS 3: fill to exactly MAX_PARKED_PRODUCES - 1, still no outcomes: accumulates the backlog up
        // to just under the cap WITHOUT blocking (the pass never block-awaits an un-fsync'd produce).
        let mut fill = Vec::new();
        for _ in 0..(MAX_PARKED_PRODUCES - 1 - 2) {
            fill.extend_from_slice(&pub_frame(b"p"));
        }
        s.process(&engine, &fill, &mut out).unwrap();
        assert_eq!(
            s.parked_len(),
            MAX_PARKED_PRODUCES - 1,
            "the persistent window holds the whole un-acked backlog, just under the cap"
        );
        assert!(
            out.is_empty(),
            "nothing acked yet — no outcome has been released"
        );

        // Release every outcome from a background thread (in submission order), so the cap's front
        // block-drain never wedges. Then feed the remaining PUBs so the window CROSSES the cap: the pass
        // hits `enforce_parked_cap`, which keeps `parked` bounded at MAX_PARKED_PRODUCES.
        let sender_thread = std::thread::spawn(move || {
            for (i, tx) in senders.into_iter().enumerate() {
                let _ = tx.send(ProduceOutcome::Appended(Offset::new(i as u64)));
            }
        });
        let mut rest = Vec::new();
        for _ in 0..(n - (MAX_PARKED_PRODUCES - 1)) {
            rest.extend_from_slice(&pub_frame(b"p"));
        }
        s.process(&engine, &rest, &mut out).unwrap();
        // Flush any straggler the pass could not yet release (an outcome the background thread had not
        // sent when the pass ended); block-awaits it, so the window ends empty.
        s.flush_all_parked_blocking(&engine, &mut out).unwrap();
        sender_thread.join().unwrap();
        assert_eq!(
            s.parked_len(),
            0,
            "the whole window drained after the cap crossing"
        );

        // Every one of the N produces acked EXACTLY ONCE, in FIFO offset order 0..N — no loss, no
        // reorder, across the cap-enforcing block drains.
        let offsets: Vec<u64> = decode_all(&out)
            .iter()
            .map(|(t, body)| {
                assert_eq!(*t, FrameType::PubAck);
                decode_pub_ack(body).unwrap().offset
            })
            .collect();
        assert_eq!(
            offsets,
            (0..n as u64).collect::<Vec<_>>(),
            "N FIFO PubAcks — the cap bounded the window without dropping or reordering an ack"
        );
    }

    // --- Ack-level server accept-path (#495) ------------------------------------------------------

    /// Builds a PUB body with an EXPLICIT raw flags byte, so a test can set the ack-level field
    /// (#494/#495) that the safe `encode_pub` does not emit (it derives only the dedup + faf bits).
    /// Hand-rolls the historical PUB layout: `flags(u8) + timestamp_ms(u64 LE) + key(u16len) +
    /// headers(u16len) + payload`, with no dedup block (so the layout is byte-for-byte a default
    /// publish, only the `flags` byte carries the level bits).
    fn pub_body_with_flags(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(flags);
        body.extend_from_slice(&0u64.to_le_bytes()); // timestamp_ms
        body.extend_from_slice(&0u16.to_le_bytes()); // key len 0
        body.extend_from_slice(&0u16.to_le_bytes()); // headers len 0
        body.extend_from_slice(payload);
        body
    }

    /// Connects a session over a `DirectEngine` and returns the (session, engine, out) tuple ready for
    /// a PUB, so the ack-level routing tests share the handshake boilerplate.
    fn connected_direct() -> (Session, DirectEngine<InMemoryFs, ManualClock>, Vec<u8>) {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        (s, e, out)
    }

    #[test]
    fn level1_is_unchanged_acks_after_the_fsync_with_the_record_durable() {
        // LEVEL 1 (#495) is TODAY's behavior EXACTLY: a default publish (no faf bit, no level bit)
        // decodes as Level 1 and is answered by a `PubAck` carrying the assigned offset, AFTER the
        // covering group-commit fsync made the record durable (I2). This is the byte-identical path.
        let (mut s, e, mut out) = connected_direct();
        s.process(
            &e,
            &frame(FrameType::Pub, &pub_body_with_flags(0, b"l1")),
            &mut out,
        )
        .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::PubAck, "Level 1 acks with a PubAck");
        assert_eq!(body, 0u64.to_le_bytes(), "the PubAck carries offset 0");
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the L1 record is durable before the ack (I2)"
        );
    }

    #[test]
    fn level0_via_the_fire_and_forget_bit_gets_no_frame_and_appends() {
        // LEVEL 0 (#495) via the CANONICAL fire-and-forget encoding (an old faf publish IS a Level-0
        // publish): NO PubAck (no frame at all), and the record is still appended durably (the no-reply
        // path appends on the single-writer storage, it just never acks).
        let (mut s, e, mut out) = connected_direct();
        let body = pub_body_with_flags(PUB_FLAG_FIRE_AND_FORGET, b"l0-faf");
        s.process(&e, &frame(FrameType::Pub, &body), &mut out)
            .unwrap();
        assert!(
            out.is_empty(),
            "a Level-0 (faf) publish gets NO frame: {out:?}"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the L0 record is appended durably even though it is never acked"
        );
    }

    #[test]
    fn level0_via_the_level_bit_gets_no_frame_and_appends() {
        // LEVEL 0 (#495) via the LEVEL-BIT encoding (raw ack-level value 1, distinct from the faf bit):
        // it must behave IDENTICALLY to the faf encoding — no frame, record appended. This proves the
        // server derives Level-0-ness from `pub_ack_level` (which folds both encodings), not just the
        // faf bit, so a level-bit Level-0 client is the generalized fire-and-forget path.
        let (mut s, e, mut out) = connected_direct();
        // Raw level value 1 in the ack-level field (the level-bit Level-0 alias), faf bit CLEAR.
        let flags = 1u8 << PUB_FLAG_ACK_LEVEL_SHIFT;
        assert_eq!(
            flags & PUB_FLAG_FIRE_AND_FORGET,
            0,
            "this encoding does NOT set the faf bit"
        );
        let body = pub_body_with_flags(flags, b"l0-levelbit");
        s.process(&e, &frame(FrameType::Pub, &body), &mut out)
            .unwrap();
        assert!(
            out.is_empty(),
            "a Level-0 (level-bit) publish gets NO frame, exactly like the faf encoding: {out:?}"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the level-bit L0 record is appended durably even though it is never acked"
        );
    }

    #[test]
    fn level2_falls_back_to_level1_and_acks() {
        // LEVEL 2 (#495) for THIS phase FALLS BACK to Level 1: the consumer-ack producer-notify is
        // phase 4 (#497), not yet end-to-end, so an L2 publish is accepted and acked EXACTLY like L1
        // (a `PubAck` after the fsync, record durable). No ProduceConfirm is emitted here.
        let (mut s, e, mut out) = connected_direct();
        // Raw level value 2 in the ack-level field (the Level-2 encoding).
        let flags = 2u8 << PUB_FLAG_ACK_LEVEL_SHIFT;
        let body = pub_body_with_flags(flags, b"l2");
        s.process(&e, &frame(FrameType::Pub, &body), &mut out)
            .unwrap();
        let (ty, ack_body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::PubAck,
            "Level 2 falls back to a Level-1 PubAck this phase (the L2 notify is #497)"
        );
        assert_eq!(
            ack_body,
            0u64.to_le_bytes(),
            "the fallback PubAck carries offset 0"
        );
        assert_eq!(
            e.engine_mut().flushed_offset().get(),
            1,
            "the L2-as-L1 record is durable before the ack (I2)"
        );
    }

    // -----------------------------------------------------------------------
    // #489 batch-pull FETCH: the amortized twin of the per-record Flow path.
    // -----------------------------------------------------------------------

    /// Builds a Fetch request frame body from its fields (the wire a client's `fetch_batch` sends).
    fn fetch_frame(max_records: u32, max_bytes: u64, expires_ms: u64, no_wait: bool) -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_fetch(
            &ironbus_proto::message::FetchBody {
                max_records,
                max_bytes,
                expires_ms,
                no_wait,
            },
            &mut body,
        );
        frame(FrameType::Fetch, &body)
    }

    #[test]
    fn batch_fetch_delivers_the_same_records_and_leases_as_n_per_record_polls() {
        // THE core #489 contract: a single batch fetch delivers EXACTLY the records (offsets AND lease
        // generations) that N successive per-record Flow(1) polls would, leasing each one the same way.
        // Two identical engines, two fresh sessions: one drained by a batch fetch, the other by N
        // per-record polls. The delivered (offset, generation) sequences must be byte-for-byte equal.
        const N: u8 = 6;

        // The batch path.
        let e_batch = DirectEngine::new(engine());
        for i in 0..N {
            produce(&e_batch, &[i; 8]);
        }
        let mut s_batch = connected_session(&e_batch);
        let mut out_batch = Vec::new();
        s_batch
            .process(
                &e_batch,
                &fetch_frame(u32::from(N), 0, 0, false),
                &mut out_batch,
            )
            .unwrap();
        let batch_tokens = delivered_tokens(&out_batch);

        // The per-record path: N successive Flow(1) calls on an identical fresh engine/session.
        let e_poll = DirectEngine::new(engine());
        for i in 0..N {
            produce(&e_poll, &[i; 8]);
        }
        let mut s_poll = connected_session(&e_poll);
        let mut poll_tokens = Vec::new();
        for _ in 0..N {
            let mut out = Vec::new();
            s_poll
                .process(
                    &e_poll,
                    &frame(FrameType::Flow, &1u32.to_le_bytes()),
                    &mut out,
                )
                .unwrap();
            poll_tokens.extend(delivered_tokens(&out));
        }

        assert_eq!(
            batch_tokens, poll_tokens,
            "the batch fetch delivers the same (offset, generation) sequence as N per-record polls"
        );
        assert_eq!(
            batch_tokens.len(),
            usize::from(N),
            "all {N} records delivered"
        );
        // The batch terminates with exactly one FlowEnd whose count equals the deliveries (same wire
        // terminator as the Flow path).
        let frames = decode_all(&out_batch);
        let flow_ends: Vec<_> = frames
            .iter()
            .filter(|(ty, _)| *ty == FrameType::FlowEnd)
            .collect();
        assert_eq!(flow_ends.len(), 1, "exactly one FlowEnd terminator");
        assert_eq!(
            u32::from_le_bytes(flow_ends[0].1.as_slice().try_into().unwrap()),
            u32::from(N),
            "the FlowEnd count equals the delivered records"
        );
    }

    #[test]
    fn batch_fetch_preserves_at_least_once_an_unacked_batch_redelivers() {
        // At-least-once: a fetched-but-unacked record stays leased and REDELIVERS after the lease
        // expires, exactly as a per-record poll does. The batch is an amortization, not a fire-and-forget.
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        produce(&e, b"x");
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &fetch_frame(10, 0, 0, false), &mut out)
            .unwrap();
        let first = delivered_tokens(&out);
        assert_eq!(first.len(), 1, "the one record is delivered");
        assert_eq!(
            e.engine_mut().committed_offset().get(),
            0,
            "an unacked fetched record does NOT advance the committed cursor"
        );

        // Expire the lease (visibility + hard cap are tiny in engine_with), then re-fetch: the unacked
        // record redelivers (at-least-once), with a FRESH lease generation.
        clock.advance_monotonic_nanos(10_000);
        let mut out2 = Vec::new();
        s.process(&e, &fetch_frame(10, 0, 0, false), &mut out2)
            .unwrap();
        let redelivered = delivered_tokens(&out2);
        assert_eq!(redelivered.len(), 1, "the unacked record redelivers");
        assert_eq!(redelivered[0].0, first[0].0, "same offset redelivers");
    }

    #[test]
    fn batch_fetch_acking_a_delivered_record_commits_it_like_a_poll() {
        // A record delivered by a batch fetch is leased identically: acking it (with the lease
        // generation the fetch carried) commits it, proving the lease the batch hands out is the SAME
        // fencing lease the per-record poll hands out.
        let e = DirectEngine::new(engine());
        produce(&e, b"a");
        produce(&e, b"b");
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &fetch_frame(10, 0, 0, false), &mut out)
            .unwrap();
        let tokens = delivered_tokens(&out);
        assert_eq!(tokens.len(), 2);
        // Ack the first delivered record with the generation the FETCH carried.
        let ack = AckBody {
            offset: tokens[0].0,
            generation: tokens[0].1,
            op: AckOp::Ack,
            delay_ms: 0,
        };
        let mut body = Vec::new();
        encode_ack(&ack, &mut body);
        out.clear();
        s.process(&e, &frame(FrameType::Ack, &body), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out),
            (FrameType::AckStatus, vec![1]),
            "the fetch-leased record commits on ack"
        );
        assert_eq!(e.engine_mut().committed_offset().get(), 1);
    }

    #[test]
    fn batch_fetch_max_records_bounds_the_batch() {
        // max_records caps the batch below what is available: 10 records present, max_records = 3.
        let e = DirectEngine::new(engine());
        for i in 0..10u8 {
            produce(&e, &[i; 4]);
        }
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &fetch_frame(3, 0, 0, false), &mut out)
            .unwrap();
        assert_eq!(
            delivered_tokens(&out).len(),
            3,
            "max_records bounds the batch to 3 of the 10 available"
        );
    }

    #[test]
    fn batch_fetch_max_bytes_bounds_the_batch_with_a_floor_of_one() {
        // max_bytes caps the batch with EXACTLY the per-record byte-budget semantics (#275): the check
        // is BEFORE each poll, so the in-flight total may overshoot the cap by at most one record (the
        // standard credit semantics the per-record Flow path also uses). Each record's lease size is
        // key+headers+payload (here just the 4-byte payload). With max_bytes = 4, after the first record
        // in-flight bytes reach 4 (>= the cap), so the batch stops at exactly 1.
        let e = DirectEngine::new(engine());
        for i in 0..5u8 {
            produce(&e, &[i; 4]);
        }
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &fetch_frame(10, 4, 0, false), &mut out)
            .unwrap();
        assert_eq!(
            delivered_tokens(&out).len(),
            1,
            "max_bytes (with the floor-of-one and the at-most-one overshoot) bounds the batch to one record"
        );

        // A single record larger than the whole budget is STILL delivered (the floor-of-one prevents a
        // wedge), exactly the per-consumer byte-budget floor.
        let e2 = DirectEngine::new(engine());
        produce(&e2, &[0xff; 64]);
        let mut s2 = connected_session(&e2);
        let mut out2 = Vec::new();
        s2.process(&e2, &fetch_frame(10, 8, 0, false), &mut out2)
            .unwrap();
        assert_eq!(
            delivered_tokens(&out2).len(),
            1,
            "the floor-of-one delivers a single over-budget record"
        );
    }

    #[test]
    fn batch_fetch_no_wait_returns_immediately_with_whatever_is_ready() {
        // no_wait returns what is ready right now (a single drain pass): with 2 records available and a
        // generous max_records, all ready records come back, and an empty queue returns an empty batch
        // (just the FlowEnd terminator) without waiting.
        let e = DirectEngine::new(engine());
        produce(&e, b"a");
        produce(&e, b"b");
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &fetch_frame(10, 0, 1_000, true), &mut out)
            .unwrap();
        assert_eq!(
            delivered_tokens(&out).len(),
            2,
            "no_wait returns the 2 ready records immediately"
        );

        // A second no_wait fetch on the now-empty (all leased) queue returns nothing but the terminator.
        let mut out2 = Vec::new();
        s.process(&e, &fetch_frame(10, 0, 1_000, true), &mut out2)
            .unwrap();
        let frames = decode_all(&out2);
        assert!(
            !frames.iter().any(|(ty, _)| *ty == FrameType::Deliver),
            "no_wait on a drained queue delivers nothing: {frames:?}"
        );
        assert_eq!(
            frames.last().map(|(ty, _)| *ty),
            Some(FrameType::FlowEnd),
            "no_wait still terminates with FlowEnd"
        );
    }

    #[test]
    fn batch_fetch_expires_bounds_work_not_which_records_are_delivered() {
        // The `expires` deadline bounds the WORK a drain may do, never WHICH records a ready queue yields:
        // the engine poll is non-blocking, so no record arrives mid-call to be missed, and under the
        // deterministic ManualClock the clock does not tick mid-call, so a generous deadline delivers the
        // whole ready batch. (This is the property #489 relies on for the same-records-as-poll argument:
        // the deadline is a work cap, not a selection filter.)
        let e = DirectEngine::new(engine());
        for i in 0..4u8 {
            produce(&e, &[i; 4]);
        }
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        s.process(&e, &fetch_frame(10, 0, 60_000, false), &mut out)
            .unwrap();
        assert_eq!(
            delivered_tokens(&out).len(),
            4,
            "a generous deadline does not cut a ready batch short"
        );
    }

    #[test]
    fn batch_fetch_respects_the_per_consumer_credit_ceiling() {
        // The negotiated per-consumer credit ceiling binds the batch even past max_records: an undersized
        // ceiling caps the batch, and held (unacked) leases reduce the remaining credit, so a batch never
        // over-delivers past the ceiling (the same guard the per-record Flow path enforces).
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        for i in 0..20u8 {
            produce(&e, &[i; 4]);
        }
        // Connect requesting a small credit of 3 (the negotiation clamps to min(request, cap)).
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut connect_body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                requested_credit: Some(3),
                requested_credit_bytes: None,
                wants_gap_marker: false,
                default_ack_level: None,
                understands_streaming: false,
                default_tier: None,
                understands_deliver_batch: false,
                understands_streams: false,
                understands_compressed_delivery: false,
            },
            &mut connect_body,
        );
        s.process(&e, &frame(FrameType::Connect, &connect_body), &mut out)
            .unwrap();
        out.clear();
        // A generous max_records still cannot exceed the negotiated ceiling of 3.
        s.process(&e, &fetch_frame(100, 0, 0, false), &mut out)
            .unwrap();
        assert_eq!(
            delivered_tokens(&out).len(),
            3,
            "the per-consumer credit ceiling of 3 bounds the batch, not max_records=100"
        );
        // Those 3 are held unacked, so remaining credit is 0: a second fetch (before any ack/expiry)
        // delivers nothing, proving the ceiling is enforced across the in-flight set, never over-delivered.
        out.clear();
        s.process(&e, &fetch_frame(100, 0, 0, false), &mut out)
            .unwrap();
        assert_eq!(
            delivered_tokens(&out).len(),
            0,
            "a saturated consumer (3/3 held) gets an empty batch"
        );
    }

    #[test]
    fn batch_fetch_rejects_a_malformed_body_without_dropping_the_connection() {
        // A malformed Fetch body is a typed Err reply, never a panic, and the session stays open.
        let e = DirectEngine::new(engine());
        let mut s = connected_session(&e);
        let mut out = Vec::new();
        // A 1-byte body with a bogus version cannot decode.
        s.process(&e, &frame(FrameType::Fetch, &[9u8]), &mut out)
            .expect("the session stays open after a malformed fetch");
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn batch_fetch_before_connect_is_rejected() {
        // A Fetch before Connect is rejected (the same guard as Flow), and the session stays open.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&e, &fetch_frame(10, 0, 0, false), &mut out)
            .expect("the session stays open");
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    // -------- Level-2 produce-confirm (#497) --------

    /// Produces ONE message at the given ack level through `s` and returns the `PubAck` offset (`None`
    /// for a non-acking level). The ack-level field is stamped into the PUB flags exactly as the wire
    /// carries it, so the server routes it by `pub_ack_level`.
    fn pub_at_level<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
        level: AckLevel,
        payload: &[u8],
    ) -> Option<u64> {
        let flags = match level {
            AckLevel::NoAck => PUB_FLAG_FIRE_AND_FORGET,
            AckLevel::ServerAck => 0,
            AckLevel::ServerAndClientAck => 2 << PUB_FLAG_ACK_LEVEL_SHIFT,
        };
        let mut body = Vec::new();
        encode_pub(
            &PubBody {
                flags,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload,
            },
            &mut body,
        )
        .unwrap();
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Pub, &body), &mut out)
            .unwrap();
        decode_all(&out)
            .into_iter()
            .find(|(ty, _)| *ty == FrameType::PubAck)
            .map(|(_, b)| decode_pub_ack(&b).unwrap().offset)
    }

    /// Drives one producer pass on `s` (a Ping) and returns every `ProduceConfirm` (offset, status)
    /// flushed onto the wire for that connection.
    fn drain_confirms<C: Clock + Clone + 'static>(
        s: &mut Session,
        e: &DirectEngine<InMemoryFs, C>,
    ) -> Vec<(u64, u8)> {
        let mut out = Vec::new();
        s.process(e, &frame(FrameType::Ping, b""), &mut out)
            .unwrap();
        decode_all(&out)
            .into_iter()
            .filter(|(ty, _)| *ty == FrameType::ProduceConfirm)
            .map(|(_, b)| {
                let c = ironbus_proto::message::decode_produce_confirm(&b)
                    .expect("9-byte confirm body");
                (c.offset, c.status)
            })
            .collect()
    }

    #[test]
    fn an_l2_produce_is_confirmed_when_a_consumer_acks_it() {
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        // Producer and consumer are two sessions over the same engine (distinct member ids).
        let mut producer = Session::with_member_id(MemberId::new(1));
        let mut consumer = Session::with_member_id(MemberId::new(2));
        let mut out = Vec::new();
        producer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        consumer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();

        // L2 produce: the durability PubAck returns the offset.
        let offset = pub_at_level(&mut producer, &e, AckLevel::ServerAndClientAck, b"l2").unwrap();
        // No confirm yet (no consumer has acked).
        assert!(drain_confirms(&mut producer, &e).is_empty());

        // The consumer flows and acks the record in the DESIGNATED (default) group.
        out.clear();
        consumer
            .process(&e, &frame(FrameType::Flow, &4u32.to_le_bytes()), &mut out)
            .unwrap();
        let toks = delivered_tokens(&out);
        let (off, generation) = *toks.iter().find(|(o, _)| *o == offset).expect("delivered");
        assert_eq!(
            ack_reply(&mut consumer, &e, AckOp::Ack, off, generation),
            vec![1]
        );

        // The producer's next pass carries the CONSUMED ProduceConfirm for the offset.
        let confirms = drain_confirms(&mut producer, &e);
        assert_eq!(
            confirms,
            vec![(offset, produce_confirm_status::CONSUMED)],
            "the L2 confirm fires on the consumer ack"
        );
        // Drained: a second pass yields nothing.
        assert!(drain_confirms(&mut producer, &e).is_empty());
    }

    #[test]
    fn an_l1_produce_registers_no_confirm() {
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        let mut producer = Session::with_member_id(MemberId::new(1));
        let mut consumer = Session::with_member_id(MemberId::new(2));
        let mut out = Vec::new();
        producer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        consumer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        // A Level-1 produce: the unchanged at-least-once PubAck path, NO confirm registered.
        let offset = pub_at_level(&mut producer, &e, AckLevel::ServerAck, b"l1").unwrap();
        out.clear();
        consumer
            .process(&e, &frame(FrameType::Flow, &4u32.to_le_bytes()), &mut out)
            .unwrap();
        let (off, generation) = *delivered_tokens(&out)
            .iter()
            .find(|(o, _)| *o == offset)
            .expect("delivered");
        ack_reply(&mut consumer, &e, AckOp::Ack, off, generation);
        // No ProduceConfirm is ever produced for an L1 publish (L0/L1 byte-for-byte unchanged).
        assert!(
            drain_confirms(&mut producer, &e).is_empty(),
            "L1 never registers an L2 confirm"
        );
        assert_eq!(
            e.engine_mut().confirm_group(),
            "",
            "the designated confirm group defaults to the unnamed group"
        );
    }

    #[test]
    fn an_unacked_l2_produce_times_out() {
        let clock = Arc::new(ManualClock::new());
        // The default confirm TTL is large; drive a short one directly on the registry semantics by
        // advancing the clock past the configured TTL. The registry uses DEFAULT_CONFIRM_TTL_NANOS.
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        let mut producer = Session::with_member_id(MemberId::new(1));
        let mut out = Vec::new();
        producer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        let offset = pub_at_level(&mut producer, &e, AckLevel::ServerAndClientAck, b"l2").unwrap();
        // Advance well past the default TTL, then drive the produce/commit tick (a fresh L1 produce
        // by another path) so the timeout sweep runs.
        clock.advance_monotonic_nanos(ironbus_core::confirm::DEFAULT_CONFIRM_TTL_NANOS + 1);
        produce(&e, b"tick"); // a commit_batch runs the L2 timeout sweep
        let confirms = drain_confirms(&mut producer, &e);
        assert_eq!(
            confirms,
            vec![(offset, produce_confirm_status::TIMED_OUT)],
            "an L2 confirm no consumer acks within the TTL times out"
        );
    }

    #[test]
    fn an_l2_produce_dead_lettered_before_any_ack_is_terminated() {
        let clock = Arc::new(ManualClock::new());
        // max_deliver = 1: the first redelivery dead-letters the poison record.
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 1));
        let mut producer = Session::with_member_id(MemberId::new(1));
        let mut consumer = Session::with_member_id(MemberId::new(2));
        let mut out = Vec::new();
        producer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        consumer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        let offset =
            pub_at_level(&mut producer, &e, AckLevel::ServerAndClientAck, b"poison").unwrap();

        // Deliver once (attempt 1), let the lease expire, then re-poll: attempt 2 > max_deliver(1)
        // dead-letters it WITHOUT any ack.
        out.clear();
        consumer
            .process(&e, &frame(FrameType::Flow, &4u32.to_le_bytes()), &mut out)
            .unwrap();
        assert!(delivered_tokens(&out).iter().any(|(o, _)| *o == offset));
        clock.advance_monotonic_nanos(1_000); // past the visibility window + hard cap
        out.clear();
        consumer
            .process(&e, &frame(FrameType::Flow, &4u32.to_le_bytes()), &mut out)
            .unwrap();
        // The dead-letter terminal fires a DEAD_LETTERED confirm to the producer.
        let confirms = drain_confirms(&mut producer, &e);
        assert_eq!(
            confirms,
            vec![(offset, produce_confirm_status::DEAD_LETTERED)],
            "a dead-letter before any ack terminates the L2 confirm"
        );
    }

    #[test]
    fn a_producer_disconnect_drops_its_pending_l2_confirms() {
        let clock = Arc::new(ManualClock::new());
        let e = DirectEngine::new(engine_with(Arc::clone(&clock), 5));
        let mut producer = Session::with_member_id(MemberId::new(7));
        let mut out = Vec::new();
        producer
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        let offset = pub_at_level(&mut producer, &e, AckLevel::ServerAndClientAck, b"l2").unwrap();
        assert_eq!(
            e.engine_mut().drain_l2_confirms(MemberId::new(7)).len(),
            0,
            "nothing ready yet (no consumer acked)"
        );
        // The producer disconnects: the connection cleanup drops its registry entries.
        e.engine_mut().drop_l2_confirms(MemberId::new(7));
        // Even committing past the offset now fires nothing for the gone producer.
        produce(&e, b"x");
        e.engine_mut().ack_in(
            "",
            &ironbus_core::lease::LeaseToken {
                offset: Offset::new(offset),
                generation: 0,
            },
        );
        assert!(
            e.engine_mut()
                .drain_l2_confirms(MemberId::new(7))
                .is_empty(),
            "a disconnected producer's confirms are dropped, never delivered"
        );
    }

    // =================================================================================
    // #585 (V2-M2-I9): subject->stream binding + subject-addressed pub/sub OVER THE WIRE.
    // A streams-capable client BindSubjects a pattern, then publishes/subscribes BY SUBJECT
    // and the broker resolves single-home (fail-closed) through the connection's resolve cache.
    // The explicit-stream-id (#588) and default verbs are unchanged.
    // =================================================================================

    /// A Connect body that advertises the streams capability (#588/#585): required to use the
    /// subject-addressed verbs (they are gated on the negotiated `understands_streams`).
    fn streams_connect_body() -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                requested_credit: None,
                requested_credit_bytes: None,
                wants_gap_marker: false,
                default_ack_level: None,
                understands_streaming: false,
                default_tier: None,
                understands_deliver_batch: false,
                understands_streams: true,
                understands_compressed_delivery: false,
            },
            &mut body,
        );
        body
    }

    /// A level-1 (server-ack) `PubBody` carrying `payload`, the body shared by Pub/PubTo/PubSubject.
    fn pub_body(payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload,
                dedup: None,
                fire_and_forget: false,
            },
            &mut b,
        )
        .unwrap();
        b
    }

    /// Connects a streams-capable session against a fresh direct engine.
    fn connect_streams() -> (DirectEngine<InMemoryFs, ManualClock>, Session, Vec<u8>) {
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &e,
            &frame(FrameType::Connect, &streams_connect_body()),
            &mut out,
        )
        .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
        out.clear();
        (e, s, out)
    }

    #[test]
    fn bind_publish_and_subscribe_by_subject_end_to_end_over_the_wire() {
        // THE wire end-to-end: BindSubject "order.>" -> "orders"; PubSubject "order.us.created"
        // resolves single-home and lands in "orders" (a PubAck comes back); then a SubSubject on a
        // literal subject covered by the binding resolves to "orders" and a Flow delivers the record.
        let (e, mut s, mut out) = connect_streams();

        // BIND "order.>" to "orders".
        let mut bind = Vec::new();
        ironbus_proto::message::encode_bind_subject(
            &ironbus_proto::message::BindSubjectBody {
                stream_id: b"orders",
                pattern: b"order.>",
            },
            &mut bind,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::BindSubject, &bind), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "bind acknowledged");
        out.clear();

        // PUBLISH BY SUBJECT -> PubAck at offset 0 in "orders".
        let mut pubsub = Vec::new();
        ironbus_proto::message::encode_pub_subject(
            &ironbus_proto::message::PubSubjectBody {
                subject: b"order.us.created",
                pub_body: &pub_body(b"hello"),
            },
            &mut pubsub,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::PubSubject, &pubsub), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::PubAck, "publish-by-subject is acked");
        assert_eq!(decode_pub_ack(&body).unwrap().offset, 0);
        out.clear();
        // The record landed in "orders" (the bound stream), NOT the default stream.
        assert_eq!(e.engine_mut().stream_head("orders").get(), 1);
        assert_eq!(e.engine_mut().stream_head("").get(), 0);

        // SUBSCRIBE BY SUBJECT (a literal the binding covers) -> Ok, then a Flow delivers the record.
        let mut subsub = Vec::new();
        ironbus_proto::message::encode_sub_subject(
            &ironbus_proto::message::SubSubjectBody {
                subject: b"order.us.created",
                group: b"workers",
            },
            &mut subsub,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::SubSubject, &subsub), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Ok,
            "subscribe-by-subject resolved"
        );
        out.clear();
        // A Flow on the subject-bound subscription delivers the record off "orders".
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        let frames = decode_all(&out);
        let delivers: Vec<_> = frames
            .iter()
            .filter(|(t, _)| *t == FrameType::Deliver)
            .collect();
        assert_eq!(
            delivers.len(),
            1,
            "the subject-resolved consumer got the record: {frames:?}"
        );
        assert_eq!(decode_deliver(&delivers[0].1).unwrap().payload, b"hello");
    }

    #[test]
    fn publish_to_an_unbound_subject_is_a_typed_err_over_the_wire_not_a_silent_drop() {
        // THE beat over NATS, on the wire: a PubSubject to a subject with NO binding gets a typed Err
        // (fail-closed), NOT a PubAck-and-silent-discard. Nothing is written.
        let (e, mut s, mut out) = connect_streams();
        let mut pubsub = Vec::new();
        ironbus_proto::message::encode_pub_subject(
            &ironbus_proto::message::PubSubjectBody {
                subject: b"telemetry.cpu",
                pub_body: &pub_body(b"x"),
            },
            &mut pubsub,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::PubSubject, &pubsub), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "an unbound subject is a typed Err, never a silent drop"
        );
        assert!(
            String::from_utf8_lossy(&body).contains("no stream is bound"),
            "the reject names the cause: {}",
            String::from_utf8_lossy(&body)
        );
        // No silent drop: the default stream got nothing.
        assert_eq!(e.engine_mut().stream_head("").get(), 0);
    }

    #[test]
    fn publish_to_an_ambiguous_subject_is_a_typed_err_over_the_wire() {
        // A subject bound to TWO streams is AmbiguousSubject (single-home) on the wire.
        let (e, mut s, mut out) = connect_streams();
        for (stream, pattern) in [
            (&b"orders"[..], &b"order.>"[..]),
            (&b"audit"[..], &b"order.us.*"[..]),
        ] {
            let mut bind = Vec::new();
            ironbus_proto::message::encode_bind_subject(
                &ironbus_proto::message::BindSubjectBody {
                    stream_id: stream,
                    pattern,
                },
                &mut bind,
            )
            .unwrap();
            s.process(&e, &frame(FrameType::BindSubject, &bind), &mut out)
                .unwrap();
            assert_eq!(one_response(&out).0, FrameType::Ok);
            out.clear();
        }
        let mut pubsub = Vec::new();
        ironbus_proto::message::encode_pub_subject(
            &ironbus_proto::message::PubSubjectBody {
                subject: b"order.us.created",
                pub_body: &pub_body(b"x"),
            },
            &mut pubsub,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::PubSubject, &pubsub), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Err);
        assert!(
            String::from_utf8_lossy(&body).contains("resolves to 2 bound streams"),
            "the ambiguous reject names the count: {}",
            String::from_utf8_lossy(&body)
        );
    }

    #[test]
    fn a_bind_change_invalidates_the_connection_resolve_cache_no_stale_routing() {
        // A connection publishes by subject (caching the route), then a SECOND bind makes the subject
        // ambiguous. The connection's NEXT publish must see the change (a typed AmbiguousSubject Err),
        // proving the per-connection resolve cache was invalidated by the bind's generation bump — no
        // stale single-route. (This is the wire-level proof of the cache-invalidation property.)
        let (e, mut s, mut out) = connect_streams();
        let bind = |stream: &[u8], pattern: &[u8]| {
            let mut b = Vec::new();
            ironbus_proto::message::encode_bind_subject(
                &ironbus_proto::message::BindSubjectBody {
                    stream_id: stream,
                    pattern,
                },
                &mut b,
            )
            .unwrap();
            b
        };
        let pub_subject = || {
            let mut p = Vec::new();
            ironbus_proto::message::encode_pub_subject(
                &ironbus_proto::message::PubSubjectBody {
                    subject: b"order.us.created",
                    pub_body: &pub_body(b"x"),
                },
                &mut p,
            )
            .unwrap();
            p
        };

        // Bind "order.>" -> "orders", publish (caches the single-home route to "orders").
        s.process(
            &e,
            &frame(FrameType::BindSubject, &bind(b"orders", b"order.>")),
            &mut out,
        )
        .unwrap();
        out.clear();
        s.process(&e, &frame(FrameType::PubSubject, &pub_subject()), &mut out)
            .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::PubAck,
            "first publish routed"
        );
        out.clear();

        // SECOND bind: "audit" also binds a pattern covering the subject -> now ambiguous.
        s.process(
            &e,
            &frame(FrameType::BindSubject, &bind(b"audit", b"order.us.*")),
            &mut out,
        )
        .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        out.clear();

        // The SAME connection's next publish of the SAME subject now sees the AMBIGUITY (cache dropped
        // its stale single-route via the generation guard) — a typed Err, not a stale PubAck.
        s.process(&e, &frame(FrameType::PubSubject, &pub_subject()), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "the bind change invalidated the cached route"
        );
        assert!(String::from_utf8_lossy(&body).contains("resolves to 2 bound streams"));
    }

    #[test]
    fn the_subject_verbs_are_refused_without_the_streams_capability() {
        // An old client (no understands_streams) is REFUSED the subject verbs with a typed Err, never
        // the new behavior — so it can only use the default-stream verbs, byte-for-byte unchanged.
        let e = DirectEngine::new(engine());
        let mut s = Session::new();
        let mut out = Vec::new();
        // Connect WITHOUT the streams capability.
        s.process(
            &e,
            &frame(FrameType::Connect, &gap_marker_connect_body()),
            &mut out,
        )
        .unwrap();
        out.clear();
        let mut bind = Vec::new();
        ironbus_proto::message::encode_bind_subject(
            &ironbus_proto::message::BindSubjectBody {
                stream_id: b"orders",
                pattern: b"order.>",
            },
            &mut bind,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::BindSubject, &bind), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Err);
        assert!(String::from_utf8_lossy(&body).contains("not negotiated"));
    }

    #[test]
    fn the_explicit_stream_id_and_default_publish_paths_are_unchanged_with_subject_routing_present()
    {
        // PRESERVE: a plain default-stream Pub and an explicit-id PubTo still work exactly as before even
        // with subject bindings present — subject routing is an additive parallel path, never a re-route.
        let (e, mut s, mut out) = connect_streams();
        // A binding exists, but it must not affect the default/explicit paths.
        let mut bind = Vec::new();
        ironbus_proto::message::encode_bind_subject(
            &ironbus_proto::message::BindSubjectBody {
                stream_id: b"orders",
                pattern: b"order.>",
            },
            &mut bind,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::BindSubject, &bind), &mut out)
            .unwrap();
        out.clear();

        // A plain default-stream Pub still lands in the default stream and is acked.
        s.process(&e, &frame(FrameType::Pub, &pub_body(b"d0")), &mut out)
            .unwrap();
        let dframes = decode_all(&out);
        assert!(
            dframes.iter().any(|(t, _)| *t == FrameType::PubAck),
            "a plain Pub is still acked: {dframes:?}"
        );
        assert_eq!(
            e.engine_mut().stream_head("").get(),
            1,
            "the default Pub landed in the default stream"
        );
        out.clear();

        // An explicit-id PubTo to "shipments" still routes there (NOT via any subject binding).
        let mut pubto = Vec::new();
        ironbus_proto::message::encode_pub_to(
            &ironbus_proto::message::PubToBody {
                stream_id: b"shipments",
                pub_body: &pub_body(b"s0"),
            },
            &mut pubto,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::PubTo, &pubto), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::PubAck);
        assert_eq!(e.engine_mut().stream_head("shipments").get(), 1);
    }

    // ---- Connection-scoped auth + three-scope authorization (#631, V2-M7) ----
    //
    // These exercise the load-bearing security properties: a connect must authenticate on an
    // auth-required broker, a verb is gated on the pinned scope set with NO implication, and a no-auth
    // (loopback-dev) broker is byte-for-byte unchanged.

    use crate::auth::{AuthConfig, CredentialSet, Identity, Scope, ScopeSet, Secret};
    use ironbus_proto::message::{
        append_connect_auth, encode_connect, pack_password_material, AuthCredential,
        AuthMechanism as WireMechanism, ConnectBody,
    };

    fn sha256_hex_token(token: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;
        let d = Sha256::digest(token);
        let mut s = String::with_capacity(64);
        for b in d {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Builds an `Arc<AuthConfig>` with a single bearer identity holding exactly `scopes`.
    fn bearer_auth(token: &[u8], scopes: &[Scope]) -> Arc<AuthConfig> {
        let mut cfg = AuthConfig::new();
        cfg.add_identity(Identity {
            name: "id".to_string(),
            scopes: ScopeSet::from_scopes(scopes),
            credential: CredentialSet::Bearer {
                digests: vec![
                    crate::auth::parse_token_digest_hex(&sha256_hex_token(token)).unwrap(),
                ],
            },
        });
        Arc::new(cfg)
    }

    /// Encodes a `Connect` body carrying a bearer credential for `token`.
    fn connect_with_bearer(token: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        encode_connect(&ConnectBody::default(), &mut body);
        append_connect_auth(
            &mut body,
            &AuthCredential {
                mechanism: WireMechanism::Bearer,
                material: token.to_vec(),
            },
        )
        .unwrap();
        frame(FrameType::Connect, &body)
    }

    #[test]
    fn an_unauthenticated_connect_to_an_auth_required_broker_is_refused() {
        // An empty (no-credential) Connect on an auth-required broker is the uniform Authorization
        // Violation and the connection closes. There is no anonymous fallback.
        let e = DirectEngine::new(engine());
        let auth = bearer_auth(b"a-secret-token-of-32-bytes-len!!", &[Scope::Publish]);
        let mut s = Session::with_member_id_and_auth(MemberId::new(0), auth, None);
        let mut out = Vec::new();
        let err = s
            .process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap_err();
        assert!(matches!(err, SessionError::AuthViolation));
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Err);
        assert_eq!(body, crate::auth::AuthError::MESSAGE.as_bytes());
    }

    #[test]
    fn a_valid_bearer_credential_authenticates_and_pins_its_scopes() {
        let e = DirectEngine::new(engine());
        let token = b"a-secret-token-of-32-bytes-len!!";
        let auth = bearer_auth(token, &[Scope::Publish]);
        let mut s = Session::with_member_id_and_auth(MemberId::new(0), auth, None);
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        // The handshake replies Info (success), and a subsequent Pub (publish scope) is allowed.
        assert_eq!(one_response(&out).0, FrameType::Info);
        assert!(s.authenticated);
        assert!(s.scopes.has(Scope::Publish));

        out.clear();
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"hi",
            },
            &mut pub_body,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::PubAck);
    }

    #[test]
    fn a_produce_without_the_publish_scope_is_refused() {
        // The identity holds ONLY subscribe; a Pub is the uniform violation and closes.
        let e = DirectEngine::new(engine());
        let token = b"sub-only-token-padding-32bytes!!";
        let auth = bearer_auth(token, &[Scope::Subscribe]);
        let mut s = Session::with_member_id_and_auth(MemberId::new(0), auth, None);
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);

        out.clear();
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"nope",
            },
            &mut pub_body,
        )
        .unwrap();
        let err = s
            .process(&e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap_err();
        assert!(matches!(err, SessionError::AuthViolation));
        assert_eq!(one_response(&out).0, FrameType::Err);
        assert_eq!(
            one_response(&out).1,
            crate::auth::AuthError::MESSAGE.as_bytes()
        );
    }

    #[test]
    fn a_subscribe_without_the_subscribe_scope_is_refused() {
        let e = DirectEngine::new(engine());
        let token = b"pub-only-token-padding-32bytes!!";
        let auth = bearer_auth(token, &[Scope::Publish]);
        let mut s = Session::with_member_id_and_auth(MemberId::new(0), auth, None);
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);

        out.clear();
        // A Flow (consume) requires subscribe; a publish-only identity is refused.
        let err = s
            .process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap_err();
        assert!(matches!(err, SessionError::AuthViolation));
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn admin_does_not_imply_publish_or_subscribe() {
        // The headline no-implication property: an admin-only identity is refused BOTH a Pub and a
        // Flow. admin grants neither.
        let e = DirectEngine::new(engine());
        let token = b"admin-only-token-pad-32-bytes!!!";
        let auth = bearer_auth(token, &[Scope::Admin]);
        let mut s = Session::with_member_id_and_auth(MemberId::new(0), auth, None);
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
        assert!(s.scopes.has(Scope::Admin));

        // Pub is refused (admin does NOT grant publish).
        out.clear();
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"x",
            },
            &mut pub_body,
        )
        .unwrap();
        assert!(matches!(
            s.process(&e, &frame(FrameType::Pub, &pub_body), &mut out)
                .unwrap_err(),
            SessionError::AuthViolation
        ));

        // A fresh connection (the old one is closed) is refused a Flow too (admin does NOT grant
        // subscribe).
        let mut s2 = Session::with_member_id_and_auth(
            MemberId::new(1),
            bearer_auth(token, &[Scope::Admin]),
            None,
        );
        let mut out2 = Vec::new();
        s2.process(&e, &connect_with_bearer(token), &mut out2)
            .unwrap();
        out2.clear();
        assert!(matches!(
            s2.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out2)
                .unwrap_err(),
            SessionError::AuthViolation
        ));
    }

    #[test]
    fn a_password_credential_authenticates_with_argon2() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::Argon2;
        let salt = SaltString::encode_b64(b"a-fixed-test-salt-bytes").unwrap();
        let phc = Argon2::default()
            .hash_password(b"hunter2", &salt)
            .unwrap()
            .to_string();
        let mut cfg = AuthConfig::new();
        cfg.add_identity(Identity {
            name: "alice".to_string(),
            scopes: ScopeSet::from_scopes(&[Scope::Publish, Scope::Subscribe]),
            credential: CredentialSet::Password {
                username: "alice".to_string(),
                phc_hashes: vec![Secret::new(phc.into_bytes())],
            },
        });
        let e = DirectEngine::new(engine());
        let mut s = Session::with_member_id_and_auth(MemberId::new(0), Arc::new(cfg), None);
        let mut body = Vec::new();
        encode_connect(&ConnectBody::default(), &mut body);
        append_connect_auth(
            &mut body,
            &AuthCredential {
                mechanism: WireMechanism::Password,
                material: pack_password_material(b"alice", b"hunter2").unwrap(),
            },
        )
        .unwrap();
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, &body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
        assert!(s.authenticated && s.scopes.has(Scope::Publish) && s.scopes.has(Scope::Subscribe));
    }

    #[test]
    fn a_no_auth_broker_is_byte_for_byte_unchanged_zero_config_dev() {
        // The loopback-dev path: a session built WITHOUT an auth config requires no credential and
        // gates no verb. An empty Connect succeeds and a Pub + Flow round-trips, exactly as before.
        let e = DirectEngine::new(engine());
        let mut s = Session::new(); // no auth_config
        let mut out = Vec::new();
        s.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
        assert!(
            !s.authenticated,
            "no auth was required, so authenticated stays false"
        );

        out.clear();
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"dev",
            },
            &mut pub_body,
        )
        .unwrap();
        s.process(&e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::PubAck);

        out.clear();
        s.process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap();
        // The Flow returns the delivered record then a FlowEnd terminator — no auth gate in the way.
        assert_eq!(decode_all(&out)[0].0, FrameType::Deliver);
    }

    // --- The security AUDIT-EVENT stream (#635, V2-M7) wired through the session. ---

    /// A `Write` over a shared `Vec<u8>` for the audit-capture helper. At module scope (not inside
    /// `capturing_audit`) so it does not trip the items-after-statements lint.
    struct AuditCaptureBuf(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for AuditCaptureBuf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A capturing audit emitter over a shared `Vec<u8>` so a test reads back exactly what was emitted,
    /// plus a `ManualClock` so the wall-clock stamp is deterministic.
    fn capturing_audit() -> (crate::audit::AuditEmitter, Arc<std::sync::Mutex<Vec<u8>>>) {
        use ironbus_core::clock::ManualClock;
        let buf = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let buf_clone = Arc::clone(&buf);
        let clock = Arc::new(ManualClock::at_unix_millis(1_700_000_000_123))
            as Arc<dyn ironbus_core::clock::Clock>;
        let emitter = crate::audit::AuditEmitter::new(
            crate::audit::AuditSink::writer(Box::new(AuditCaptureBuf(buf_clone))),
            clock,
        );
        (emitter, buf)
    }

    fn audit_text(buf: &Arc<std::sync::Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn a_successful_connect_emits_an_authn_success_event_with_the_name_not_the_credential() {
        let e = DirectEngine::new(engine());
        let token = b"audit-success-token-32-bytes!!!!";
        let auth = bearer_auth(token, &[Scope::Publish]);
        let (audit, buf) = capturing_audit();
        let mut s =
            Session::with_member_id_and_auth(MemberId::new(0), auth, None).with_audit(audit);
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);

        let text = audit_text(&buf);
        assert!(text.contains("event=authn_outcome"), "{text}");
        assert!(
            text.contains("identity=\"id\""),
            "the resolved name: {text}"
        );
        assert!(text.contains("mechanism=bearer"), "{text}");
        assert!(text.contains("outcome=success"), "{text}");
        // The load-bearing no-leak property: the presented token never appears in the audit stream.
        assert!(
            !text.contains("audit-success-token"),
            "the credential must never reach the audit stream: {text}"
        );
    }

    #[test]
    fn a_failed_connect_emits_an_authn_failure_event_with_unknown_and_no_credential() {
        let e = DirectEngine::new(engine());
        let auth = bearer_auth(b"the-right-token-padding-32bytes!", &[Scope::Publish]);
        let (audit, buf) = capturing_audit();
        let mut s =
            Session::with_member_id_and_auth(MemberId::new(0), auth, None).with_audit(audit);
        let mut out = Vec::new();
        // Present the WRONG token: the connect fails (uniform violation) and closes.
        let wrong = b"a-totally-wrong-token-32-bytes!!";
        let err = s
            .process(&e, &connect_with_bearer(wrong), &mut out)
            .unwrap_err();
        assert!(matches!(err, SessionError::AuthViolation));

        let text = audit_text(&buf);
        assert!(text.contains("event=authn_outcome"), "{text}");
        assert!(text.contains("outcome=failure"), "{text}");
        assert!(text.contains("mechanism=bearer"), "{text}");
        // A failed lookup records `<unknown>`, never the attacker-supplied or stored credential.
        assert!(text.contains("identity=\"<unknown>\""), "{text}");
        assert!(
            !text.contains("wrong-token") && !text.contains("the-right-token"),
            "no credential (presented or stored) in the audit stream: {text}"
        );
    }

    #[test]
    fn a_scope_denial_emits_an_authz_denial_event_with_the_scope_and_verb() {
        let e = DirectEngine::new(engine());
        // A subscribe-only identity attempts a Pub (publish scope): denied + audited.
        let token = b"sub-only-audit-token-32-bytes!!!";
        let auth = bearer_auth(token, &[Scope::Subscribe]);
        let (audit, buf) = capturing_audit();
        let mut s =
            Session::with_member_id_and_auth(MemberId::new(0), auth, None).with_audit(audit);
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        out.clear();
        // Clear the buffer's success event so the assertion targets the denial only.
        buf.lock().unwrap().clear();

        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"x",
            },
            &mut pub_body,
        )
        .unwrap();
        let err = s
            .process(&e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap_err();
        assert!(matches!(err, SessionError::AuthViolation));

        let text = audit_text(&buf);
        assert!(text.contains("event=authz_denial"), "{text}");
        assert!(text.contains("identity=\"id\""), "the pinned name: {text}");
        assert!(text.contains("scope=publish"), "{text}");
        assert!(text.contains("verb=Pub"), "{text}");
    }

    #[test]
    fn a_consume_scope_denial_via_dispatch_is_audited_with_the_verb_name() {
        let e = DirectEngine::new(engine());
        // A publish-only identity attempts a Flow (subscribe scope), denied through `require_scope`.
        let token = b"pub-only-audit-token-32-bytes!!!";
        let auth = bearer_auth(token, &[Scope::Publish]);
        let (audit, buf) = capturing_audit();
        let mut s =
            Session::with_member_id_and_auth(MemberId::new(0), auth, None).with_audit(audit);
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        buf.lock().unwrap().clear();

        let _ = s
            .process(&e, &frame(FrameType::Flow, &1u32.to_le_bytes()), &mut out)
            .unwrap_err();
        let text = audit_text(&buf);
        assert!(text.contains("event=authz_denial"), "{text}");
        assert!(text.contains("scope=subscribe"), "{text}");
        assert!(text.contains("verb=Flow"), "{text}");
    }

    #[test]
    fn no_audit_emitter_is_byte_for_byte_the_historical_path() {
        // A session built WITHOUT `.with_audit(..)` runs the exact historical auth path: a valid
        // connect still succeeds, a denial still closes, and nothing is emitted (there is no sink).
        let e = DirectEngine::new(engine());
        let token = b"no-audit-emitter-token-32bytes!!";
        let auth = bearer_auth(token, &[Scope::Publish]);
        let mut s = Session::with_member_id_and_auth(MemberId::new(0), auth, None); // no .with_audit
        let mut out = Vec::new();
        s.process(&e, &connect_with_bearer(token), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
        assert!(s.authenticated && s.audit.is_none());
    }

    // ---- transactional half-message 2PC over the wire (#640, V2-M8) ----

    /// Builds a `TxnPrepare` frame for `txn_id` targeting the default stream with `payload`.
    fn txn_prepare_frame(txn_id: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload,
            },
            &mut pub_body,
        )
        .unwrap();
        let mut body = Vec::new();
        encode_txn_prepare(
            &TxnPrepareBody {
                txn_id,
                stream_id: b"",
                pub_body: &pub_body,
            },
            &mut body,
        )
        .unwrap();
        frame(FrameType::TxnPrepare, &body)
    }

    fn txn_resolve_frame(ty: FrameType, txn_id: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        encode_txn_resolve(&TxnResolveBody { txn_id }, &mut body).unwrap();
        frame(ty, &body)
    }

    #[test]
    fn txn_prepare_is_invisible_then_commit_delivers_over_the_wire() {
        // The end-to-end INVISIBILITY invariant over the real consume path: a prepared half message is
        // NEVER delivered by Flow/Deliver; it appears ONLY after commit.
        let e = DirectEngine::new(engine());
        // Producer connection prepares + commits.
        let mut prod = Session::with_member_id(MemberId::new(1));
        let mut out = Vec::new();
        prod.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        prod.process(&e, &txn_prepare_frame(b"tx1", b"half"), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "prepare is acked Ok");

        // A consumer Flow sees NOTHING (the half message is invisible).
        let mut cons = connect_and_sub(&e, MemberId::new(2), b"");
        out.clear();
        cons.process(&e, &frame(FrameType::Flow, &10u32.to_le_bytes()), &mut out)
            .unwrap();
        assert!(
            delivered_payloads(&out).is_empty(),
            "a prepared-but-uncommitted half message is never delivered"
        );

        // Commit: the producer gets a PubAck with the committed offset.
        out.clear();
        prod.process(
            &e,
            &txn_resolve_frame(FrameType::TxnCommit, b"tx1"),
            &mut out,
        )
        .unwrap();
        let (ty, ack) = one_response(&out);
        assert_eq!(ty, FrameType::PubAck, "commit replies a PubAck");
        assert_eq!(decode_pub_ack(&ack).unwrap().offset, 0);

        // Now the consumer Flow delivers the committed record exactly once.
        out.clear();
        cons.process(&e, &frame(FrameType::Flow, &10u32.to_le_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            delivered_payloads(&out),
            vec![b"half".to_vec()],
            "the committed half message becomes visible exactly once"
        );
    }

    #[test]
    fn txn_rollback_over_the_wire_never_delivers() {
        let e = DirectEngine::new(engine());
        let mut prod = Session::with_member_id(MemberId::new(1));
        let mut out = Vec::new();
        prod.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        prod.process(&e, &txn_prepare_frame(b"tx1", b"secret"), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        out.clear();
        prod.process(
            &e,
            &txn_resolve_frame(FrameType::TxnRollback, b"tx1"),
            &mut out,
        )
        .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "rollback is acked Ok");

        // A consumer never sees the rolled-back payload.
        let mut cons = connect_and_sub(&e, MemberId::new(2), b"");
        out.clear();
        cons.process(&e, &frame(FrameType::Flow, &10u32.to_le_bytes()), &mut out)
            .unwrap();
        assert!(
            delivered_payloads(&out).is_empty(),
            "a rolled-back half message is never delivered"
        );
    }

    #[test]
    fn txn_commit_after_rollback_over_the_wire_is_an_error() {
        let e = DirectEngine::new(engine());
        let mut prod = Session::with_member_id(MemberId::new(1));
        let mut out = Vec::new();
        prod.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        prod.process(&e, &txn_prepare_frame(b"tx1", b"v"), &mut out)
            .unwrap();
        out.clear();
        prod.process(
            &e,
            &txn_resolve_frame(FrameType::TxnRollback, b"tx1"),
            &mut out,
        )
        .unwrap();
        out.clear();
        // commit-after-rollback is refused, never flipped: an Err frame, never a PubAck.
        prod.process(
            &e,
            &txn_resolve_frame(FrameType::TxnCommit, b"tx1"),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "commit-after-rollback is an Err, never a PubAck"
        );
    }

    #[test]
    fn a_compressed_poison_record_is_rejected_at_txn_prepare_not_staged_or_committed() {
        // #877: `TxnPrepare` is the FOURTH produce verb and previously SKIPPED the #438 compressed-
        // descriptor shape gate the other three apply. A Publish-scoped producer could therefore stage
        // and `TxnCommit` a poison compressed record - here an over-cap descriptor claiming
        // uncompressed_len = u32::MAX - that every consumer group would then burn max-deliver
        // visibility-timeout cycles on before dead-lettering, and that survives restart. The gate must
        // reject it AT PREPARE, before any half message is staged, so the commit finds no txn and no
        // consumer ever sees an undecodable record.
        let e = DirectEngine::new(engine());
        let mut prod = Session::with_member_id(MemberId::new(1));
        let mut out = Vec::new();
        prod.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();

        // A COMPRESSED PubBody whose 9-byte descriptor claims u32::MAX decompressed bytes (over the
        // DEFAULT_MAX_DECOMPRESSED_BYTES cap): codec_id = zstd (a registered codec, so it clears the
        // codec check and reaches the cap check), dict_id = 0, uncompressed_len = u32::MAX.
        let mut poison = vec![ironbus_core::compress::CODEC_ID_ZSTD];
        poison.extend_from_slice(&0u32.to_le_bytes()); // dict_id
        poison.extend_from_slice(&u32::MAX.to_le_bytes()); // uncompressed_len, over the cap
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: RecordFlags::COMPRESSED.bits(),
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: &poison,
            },
            &mut pub_body,
        )
        .unwrap();
        let mut body = Vec::new();
        encode_txn_prepare(
            &TxnPrepareBody {
                txn_id: b"tx1",
                stream_id: b"",
                pub_body: &pub_body,
            },
            &mut body,
        )
        .unwrap();

        // Prepare is REJECTED with the shared descriptor reason, never acked Ok.
        out.clear();
        prod.process(&e, &frame(FrameType::TxnPrepare, &body), &mut out)
            .unwrap();
        let (ty, msg) = one_response(&out);
        assert_eq!(
            ty,
            FrameType::Err,
            "a poison compressed prepare is rejected, never acked Ok"
        );
        assert!(
            String::from_utf8_lossy(&msg).contains("malformed compressed descriptor"),
            "the rejection names the malformed descriptor, got: {:?}",
            String::from_utf8_lossy(&msg)
        );

        // No half message was staged: committing the same txn id finds nothing and is an Err, never a
        // fabricated PubAck for a record that was never appended.
        out.clear();
        prod.process(
            &e,
            &txn_resolve_frame(FrameType::TxnCommit, b"tx1"),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            one_response(&out).0,
            FrameType::Err,
            "the rejected prepare staged no half message, so commit finds no txn"
        );

        // And no consumer ever sees an undecodable record.
        let mut cons = connect_and_sub(&e, MemberId::new(2), b"");
        out.clear();
        cons.process(&e, &frame(FrameType::Flow, &10u32.to_le_bytes()), &mut out)
            .unwrap();
        assert!(
            delivered_payloads(&out).is_empty(),
            "no poison record was committed, so nothing is delivered"
        );
    }

    #[test]
    fn txn_malformed_and_empty_id_are_rejected_over_the_wire() {
        let e = DirectEngine::new(engine());
        let mut prod = Session::with_member_id(MemberId::new(1));
        let mut out = Vec::new();
        prod.process(&e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        // A malformed (empty) prepare body is an Err, not a panic.
        out.clear();
        prod.process(&e, &frame(FrameType::TxnPrepare, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
        // An empty txn id is refused.
        out.clear();
        prod.process(&e, &txn_resolve_frame(FrameType::TxnCommit, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    // ---- Event-driven consume long-poll (push delivery) ---------------------------------------
    // These drive a REAL spawned append actor (so `EngineHandle::commit_notify` is `Some` and the
    // actor bumps the seam on every durable-frontier advance), the only `EngineAccess` that carries a
    // commit-notify seam — the in-process `DirectEngine` returns `None`, so it always takes the
    // byte-for-byte empty-and-return path even with a budget set.

    /// A spawned-actor engine whose config carries `consume_longpoll_ms`, returning the handle + the
    /// actor's join handle. Reuses `test_config()` via struct-update for the one new field.
    fn longpoll_rig(
        consume_longpoll_ms: u64,
    ) -> (
        crate::actor::EngineHandle<InMemoryFs, ManualClock>,
        std::thread::JoinHandle<Engine<InMemoryFs, ManualClock>>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            ManualClock::new(),
            EngineConfig {
                consume_longpoll_ms,
                ..test_config()
            },
        )
        .unwrap();
        crate::actor::spawn_actor(engine, crate::actor::DEFAULT_CHANNEL_BOUND)
    }

    /// A Level-1 owned produce for the long-poll tests (mirrors the actor harness `append`).
    fn longpoll_append(payload: &[u8]) -> crate::actor::OwnedAppend {
        crate::actor::OwnedAppend {
            timestamp_ms: 0,
            flags: 0,
            key: bytes::Bytes::new(),
            headers: bytes::Bytes::new(),
            payload: bytes::Bytes::copy_from_slice(payload),
            body_checksums: Some(ironbus_core::codec::BodyChecksums::compute(
                b"", b"", payload,
            )),
            dedup: None,
            enqueue_monotonic_nanos: 0,
            fire_and_forget: false,
            ack_level: ironbus_proto::message::AckLevel::ServerAck,
        }
    }

    /// The `delivered` count carried by the terminating `FlowEnd` frame in `out`.
    fn flow_end_count(out: &[u8]) -> u32 {
        let frames = decode_all(out);
        let (ty, body) = frames.last().expect("at least a FlowEnd frame");
        assert_eq!(*ty, FrameType::FlowEnd, "the batch terminates with FlowEnd");
        u32::from_le_bytes(body.as_slice().try_into().expect("FlowEnd body is a u32"))
    }

    /// Connects a fresh consumer session over the handle, its long-poll budget seeded from the
    /// engine-config snapshot exactly as the live serve path does.
    fn longpoll_consumer(handle: &crate::actor::EngineHandle<InMemoryFs, ManualClock>) -> Session {
        let mut s = Session::new().with_consume_longpoll_ms(handle.consume_longpoll_ms());
        let mut out = Vec::new();
        s.process(handle, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        s
    }

    #[test]
    fn longpoll_off_returns_empty_flow_immediately() {
        // Budget 0 (the default): an empty group returns FlowEnd(0) at once, byte-for-byte today.
        let (handle, actor) = longpoll_rig(0);
        let mut s = longpoll_consumer(&handle);
        let mut out = Vec::new();
        let start = std::time::Instant::now();
        s.process(
            &handle,
            &frame(FrameType::Flow, &10u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(flow_end_count(&out), 0, "empty group yields FlowEnd(0)");
        // OFF engages NO wait, so this returns after only the poll round-trips. A generous ceiling keeps
        // the assertion robust on a loaded/coarse-timer CI runner (Windows) while still catching a hang.
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "long-poll OFF must return promptly (no wait), took {elapsed:?}"
        );
        drop(s);
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn longpoll_wakes_on_a_concurrent_produce() {
        // A generous budget the wakeup should beat by an order of magnitude.
        let budget_ms = 2_000u64;
        let (handle, actor) = longpoll_rig(budget_ms);
        let mut s = longpoll_consumer(&handle);
        let mut out = Vec::new();
        // A producer that publishes shortly AFTER the consumer begins long-polling the empty group.
        let producer = handle.clone();
        let jh = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(40));
            producer
                .produce(longpoll_append(b"hello"))
                .expect("a clean produce");
        });
        let start = std::time::Instant::now();
        s.process(
            &handle,
            &frame(FrameType::Flow, &10u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let elapsed = start.elapsed();
        jh.join().unwrap();
        assert_eq!(
            flow_end_count(&out),
            1,
            "the committed record is delivered on the commit-notify wakeup"
        );
        // A commit-driven wakeup lands far below the 2 s budget; a broken bump would only free the
        // consumer at the ~2 s timeout. The 1.5 s bound clears that timeout with room to spare while
        // leaving generous slack for Windows Condvar-wakeup + scheduler jitter (real wakeup is ~tens of
        // ms), so it proves the event path fired without being timing-fragile.
        assert!(
            elapsed < std::time::Duration::from_millis(1_500),
            "delivery must arrive well before the budget, took {elapsed:?}"
        );
        drop(s);
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn longpoll_times_out_to_empty_without_a_producer() {
        // A budget large enough that a lower-bound assertion has a wide margin below the timeout, so
        // Windows' ~15 ms timer granularity on `wait_timeout` can never dip the measured wait under it.
        let budget_ms = 400u64;
        let (handle, actor) = longpoll_rig(budget_ms);
        let mut s = longpoll_consumer(&handle);
        let mut out = Vec::new();
        let start = std::time::Instant::now();
        s.process(
            &handle,
            &frame(FrameType::Flow, &10u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            flow_end_count(&out),
            0,
            "no producer: the batch ends empty after waiting out the budget"
        );
        // It must have actually blocked out most of the budget, proving the wait ran rather than
        // returning empty immediately. The 200 ms floor (half the 400 ms budget) is a wide margin that
        // no timer-granularity slack can breach, so the assertion is deterministic on Windows.
        assert!(
            elapsed >= std::time::Duration::from_millis(200),
            "the consumer must wait out ~the budget, took {elapsed:?}"
        );
        drop(s);
        drop(handle);
        actor.join().unwrap();
    }

    // ---- Per-stream commit-notify (#1100 L2): fan-out + named-stream early wake -----------------

    /// A streams-capable consumer: connects advertising `understands_streams` so it may `SubTo` a
    /// named stream, its long-poll budget seeded from the engine-config snapshot as the serve path does.
    fn longpoll_streams_consumer(
        handle: &crate::actor::EngineHandle<InMemoryFs, ManualClock>,
    ) -> Session {
        let mut s = Session::new().with_consume_longpoll_ms(handle.consume_longpoll_ms());
        let mut body = Vec::new();
        ironbus_proto::message::encode_connect(
            &ironbus_proto::message::ConnectBody {
                requested_credit: None,
                requested_credit_bytes: None,
                wants_gap_marker: false,
                default_ack_level: None,
                understands_streaming: false,
                default_tier: None,
                understands_deliver_batch: false,
                understands_streams: true,
                understands_compressed_delivery: false,
            },
            &mut body,
        );
        let mut out = Vec::new();
        s.process(handle, &frame(FrameType::Connect, &body), &mut out)
            .unwrap();
        s
    }

    /// A `SubTo(stream, group)` wire frame.
    fn sub_to_frame(stream: &[u8], group: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        ironbus_proto::message::encode_sub_to(
            &ironbus_proto::message::SubToBody {
                stream_id: stream,
                group,
            },
            &mut body,
        )
        .unwrap();
        frame(FrameType::SubTo, &body)
    }

    /// A Level-1 owned produce to a NAMED stream through the actor's `with` job, mirroring
    /// `longpoll_append` but routed to the named stream's own log. Returns once the produce commits.
    fn produce_to_named_stream(
        handle: &crate::actor::EngineHandle<InMemoryFs, ManualClock>,
        stream: &'static str,
        payload: &'static [u8],
    ) {
        handle
            .with(move |e| {
                e.produce_in_stream(
                    stream,
                    &ironbus_storage::log::Append {
                        timestamp_ms: 0,
                        flags: ironbus_core::types::RecordFlags::EMPTY,
                        key: b"",
                        headers: b"",
                        payload,
                    },
                )
            })
            .expect("actor alive")
            .expect("a clean named-stream produce");
    }

    #[test]
    fn longpoll_named_stream_wakes_early_on_its_own_commit() {
        // #1100 L2: a consumer long-polling a NAMED stream wakes on a commit to THAT stream, far below
        // its budget — where L1 (which bumped only on the root log's frontier) stranded it to the full
        // timeout. Proves the actor now observes per-stream frontiers and bumps the named stream's cell.
        let budget_ms = 2_000u64;
        let (handle, actor) = longpoll_rig(budget_ms);
        // Declare the named stream (empty) so the consumer can bind + poll it before any record exists.
        handle
            .with(|e| e.declare_stream("orders"))
            .expect("actor alive")
            .expect("declare");
        let mut s = longpoll_streams_consumer(&handle);
        let mut out = Vec::new();
        // Bind the consumer to the named stream's work-group; SubTo replies Ok.
        s.process(&handle, &sub_to_frame(b"orders", b"g"), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "SubTo is accepted");
        out.clear();
        // A producer publishes to "orders" shortly after the consumer begins long-polling it empty.
        let producer = handle.clone();
        let jh = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(40));
            produce_to_named_stream(&producer, "orders", b"hello");
        });
        let start = std::time::Instant::now();
        s.process(
            &handle,
            &frame(FrameType::Flow, &10u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let elapsed = start.elapsed();
        jh.join().unwrap();
        assert_eq!(
            flow_end_count(&out),
            1,
            "the named-stream record is delivered on the per-stream commit-notify wakeup"
        );
        // Well below the 2 s budget: a broken per-stream bump would only free it at the ~2 s timeout.
        assert!(
            elapsed < std::time::Duration::from_millis(1_500),
            "the named-stream delivery must arrive well before the budget, took {elapsed:?}"
        );
        drop(s);
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn longpoll_named_stream_waiter_is_not_woken_by_a_default_stream_commit() {
        // #1100 L2 THUNDERING-HERD FIX, end-to-end: a consumer long-polling the named stream "orders"
        // is NOT woken by a produce to the DEFAULT stream — that commit bumps only the default cell, so
        // the "orders" waiter sleeps on its own cell and times out empty. Under L1's single global
        // counter this default produce would have woken every idle consumer (the herd L2 kills).
        let budget_ms = 400u64;
        let (handle, actor) = longpoll_rig(budget_ms);
        handle
            .with(|e| e.declare_stream("orders"))
            .expect("actor alive")
            .expect("declare");
        let mut s = longpoll_streams_consumer(&handle);
        let mut out = Vec::new();
        s.process(&handle, &sub_to_frame(b"orders", b"g"), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok, "SubTo is accepted");
        out.clear();
        // A producer commits to the DEFAULT stream while the "orders" consumer long-polls.
        let producer = handle.clone();
        let jh = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(40));
            producer
                .produce(longpoll_append(b"on-default"))
                .expect("a clean default-stream produce");
        });
        let start = std::time::Instant::now();
        s.process(
            &handle,
            &frame(FrameType::Flow, &10u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let elapsed = start.elapsed();
        jh.join().unwrap();
        assert_eq!(
            flow_end_count(&out),
            0,
            "a default-stream commit must NOT deliver to a named-stream long-poller"
        );
        // It must have waited out ~the budget rather than being spuriously woken by the default commit.
        // The 200 ms floor (half the 400 ms budget) is a wide, timer-granularity-safe margin.
        assert!(
            elapsed >= std::time::Duration::from_millis(200),
            "a named-stream waiter must NOT wake on a default-stream commit; it must wait out its \
             budget, took {elapsed:?}"
        );
        drop(s);
        drop(handle);
        actor.join().unwrap();
    }
}
