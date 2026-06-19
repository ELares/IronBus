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
    ActorGone, EngineAccess, OwnedAppend, OwnedDedup, ProduceOutcome, ProduceSubmission,
};
use crate::engine::{AckResult, EngineError, NackResult, Poll, ProgressResult};
use bytes::Bytes;
use ironbus_core::clock::Clock;
use ironbus_core::compress::{validate_descriptor_shape, DEFAULT_MAX_DECOMPRESSED_BYTES};
use ironbus_core::dedup::{MAX_MSG_ID_LEN, MAX_PRODUCER_ID_LEN};
use ironbus_core::keyshared::{KeyOrdering, MemberId};
use ironbus_core::lease::LeaseToken;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{
    decode_ack, decode_connect, decode_cumulative_ack, decode_fetch, decode_pub, decode_sub,
    encode_dead_letter, encode_deliver, encode_gap_marker, encode_info, encode_pub_ack,
    encode_truncated, gap_reason, pub_ack_level, AckLevel, AckOp, CreditAdvert, DeadLetterBody,
    DeliverBody, GapMarkerBody, InfoBody, PubAckBody, TruncatedBody, DEAD_LETTER_MAX_DELIVER,
    PUB_WIRE_ONLY_FLAGS,
};
use ironbus_storage::fs::Filesystem;
use std::collections::HashMap;
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
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::BadFrame(e) => write!(f, "malformed frame, closing session: {e}"),
            SessionError::EngineFatal(e) => write!(f, "fatal engine error, closing session: {e}"),
            SessionError::ActorGone => {
                write!(f, "the append actor is gone, closing session")
            }
        }
    }
}

impl From<ActorGone> for SessionError {
    fn from(_: ActorGone) -> Self {
        SessionError::ActorGone
    }
}

impl std::error::Error for SessionError {}

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

    /// The work-group this connection is subscribed to (`""` is the default group). Used to
    /// route the connection's durable cursor checkpoint to the right group (#60).
    #[must_use]
    pub fn subscription(&self) -> &str {
        &self.subscription
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
    pub fn process<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Progress, SessionError> {
        let mut consumed = 0;
        let mut committed_progress = false;
        // The pass-scoped pipelined window (#450): produces submitted to the actor but not yet
        // awaited. Scoped to ONE pass so the caller's flush boundary is unchanged: every parked ack
        // is released into `out` before this method returns.
        let mut parked: Vec<ParkedPub> = Vec::new();
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
                        // The safety cap: a buffer packed with tiny PUB frames cannot park without
                        // bound. At the cap the window is released (awaited FIFO) and a new window
                        // starts; the cap matches the actor channel's default bound, so a capped
                        // window still group-commits in at most a couple of batches.
                        if parked.len() >= MAX_PARKED_PRODUCES {
                            if let Err(e) = drain_parked(&mut parked, out) {
                                break Err(e);
                            }
                        }
                    } else {
                        // Any non-produce frame first releases the parked acks, so the reply order
                        // on the wire is exactly the frame order (FIFO per connection). The
                        // actor-side ordering is also preserved: the actor flushes its pending
                        // produce batch before running any job, so an ack/flow/sub still observes
                        // every prior produce durable.
                        if let Err(e) = drain_parked(&mut parked, out) {
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
        // End of the pass: release every still-parked ack (FIFO) before returning, so the caller's
        // single `out` flush carries the whole window's replies. On an error exit the drain still
        // runs (those produces already reached the actor and their acks belong on the wire before
        // the close), but the FIRST error wins: a drain error after a loop error is the same fatal
        // engine event and is subsumed by it.
        let drained = drain_parked(&mut parked, out);
        match result {
            Err(e) => Err(e),
            Ok(progress) => drained.map(|()| progress),
        }
    }

    /// Dispatches one decoded frame, returning whether it may have advanced a work-group's committed
    /// cursor (so the caller knows whether to run the interval checkpoint). A `Ping`/`Connect`/`Pub`
    /// returns `false`: a ping changes no cursor (and must not reach the actor's checkpoint path, so a
    /// stalled produce fsync cannot block it, #177); a produce advances the durable head but not a
    /// COMMITTED cursor. An `Ack`/`Flow`/`Unsub` returns `true` (an ack commits, a flow can commit
    /// past a dead-letter, an unsub may evict a caught-up group).
    fn dispatch<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
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
                self.handle_connect(engine, body, out);
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
                let mut parked = Vec::new();
                self.handle_pub(engine, body, &mut parked, out)?;
                drain_parked(&mut parked, out).map(|()| false)
            }
            Some(FrameType::Ack) => self.handle_ack(engine, body, out).map(|()| true),
            // A cumulative ack commits the broadcast cursor (when accepted), so it returns `true` to
            // run the interval checkpoint, exactly like a per-message Ack (#288).
            Some(FrameType::CumulativeAck) => {
                self.handle_cumulative_ack(engine, body, out).map(|()| true)
            }
            Some(FrameType::Flow) => self.handle_flow(engine, body, out).map(|()| true),
            // The batch-pull FETCH (#489): the amortized twin of Flow. It runs the SAME per-record poll
            // loop bounded by max_records/max_bytes/expires/no_wait, so it returns `true` to run the
            // interval checkpoint exactly like Flow (it commits cursor progress the same way).
            Some(FrameType::Fetch) => self.handle_fetch(engine, body, out).map(|()| true),
            Some(FrameType::Sub) => self.handle_sub(engine, body, out).map(|()| false),
            Some(FrameType::Unsub) => self.handle_unsub(engine, out).map(|()| true),
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
    ) {
        let req = match decode_connect(body) {
            Ok(req) => req,
            // A non-empty but malformed Connect body: surface a typed error and keep the connection
            // open. The credit is not fixed, so a subsequent valid Connect/Flow still negotiates.
            Err(e) => {
                reply_err(out, &e.to_string());
                return;
            }
        };
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
        };
        let mut info_body = Vec::new();
        encode_info(&info, &mut info_body);
        reply(out, FrameType::Info, &info_body);
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
        parked: &mut Vec<ParkedPub>,
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            drain_parked(parked, out)?;
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(msg) = decode_pub(body) else {
            drain_parked(parked, out)?;
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
        // - LEVEL 2 (`AckLevel::ServerAndClientAck`) FALLS BACK to Level 1 for THIS phase (#495): the
        //   producer-notify ProduceConfirm is phase 4 (#497), not yet end-to-end. So an L2 publish is
        //   accepted and acked exactly like L1; the consumer-ack notify is simply not delivered yet.
        let ack_level = pub_ack_level(msg.flags);
        // A LEVEL-0 publish is the generalized fire-and-forget: it gets no ack and is governed by the
        // fire-and-forget token bucket, REGARDLESS of which Level-0 encoding the producer used (the
        // canonical faf bit, where `msg.fire_and_forget` is already true, OR the level-bit value 1,
        // where it is not). Deriving the faf marker from the ack level here makes the level-bit and the
        // faf-bit Level-0 encodings behave identically downstream (one no-ack path). Level 1 and the
        // Level-2-as-Level-1 fallback are at-least-once, so `fire_and_forget` is false for them and the
        // existing parked-ack path is unchanged.
        let level0 = matches!(ack_level, AckLevel::NoAck);
        let fire_and_forget = level0;
        // Enforce the dedup id length caps (#33) at the wire boundary, BEFORE the bytes cross into
        // owned storage. The `producer_id` keys the per-producer window map and the `msg_id` keys the
        // per-window ring; both are wire-supplied and attacker-chosen (up to the 64 KiB wire field
        // limit), so an unbounded id would bloat per-entry memory. A too-long id is a typed,
        // connection-preserving rejection (NOT a panic, NOT a frame change), like a malformed body.
        if let Some(d) = msg.dedup.as_ref() {
            if d.producer_id.len() > MAX_PRODUCER_ID_LEN {
                if !fire_and_forget {
                    drain_parked(parked, out)?;
                    reply_err(out, "producer_id too long");
                }
                return Ok(());
            }
            if d.msg_id.len() > MAX_MSG_ID_LEN {
                if !fire_and_forget {
                    drain_parked(parked, out)?;
                    reply_err(out, "msg_id too long");
                }
                return Ok(());
            }
        }
        // Produce-time COMPRESSED-descriptor SHAPE validation (#438). Bit 0 of the PUB flags is a
        // REAL stored record flag the wire legally carries (`PUB_WIRE_ONLY_FLAGS` masks only bits
        // 6 and 7): a producer may publish a pre-compressed stored object, and the engine's write
        // seam deliberately passes it through untouched (#437, never double-wrapped). The broker
        // is store-and-forward, so nothing downstream ever parses the bytes: without this gate any
        // producer could durably ack a record NO reader can decode, and post-#430 every consumer
        // group of that offset burns max-deliver visibility-timeout cycles of typed
        // `ClientError::Decompress` failures before the record dead-letters. The check is a
        // 9-byte header parse, NO decompression (the produce hot path pays no codec CPU; stream
        // CONTENT stays a read-side concern), against the read-side rules (deliberately STRICTER
        // than the zstd read side on exactly one degenerate input, the empty-stream claim-0
        // descriptor; see `validate_descriptor_shape`) and the same
        // `DEFAULT_MAX_DECOMPRESSED_BYTES` cap every shipped reader and the #437 seam enforce. A
        // failure is a typed, connection-preserving rejection exactly like the wire-boundary
        // rejections above (a malformed body, an over-long dedup id); for a fire-and-forget
        // produce it is a silent drop with NO frame (the QoS-0 no-frame contract, #11) and no
        // counter, matching the dedup-id-cap precedent (the engine's shed counters meter only
        // engine-decided load sheds, which this is not). This gate lives at the WIRE boundary
        // ONLY: the engine's own compressed output and the DLQ redrive's direct `Log::append`
        // re-injection (`ironbus_storage::admin::redrive_dlq`) never pass through a session, so
        // neither is affected.
        if RecordFlags::from_bits(msg.flags).contains(RecordFlags::COMPRESSED) {
            if let Err(e) = validate_descriptor_shape(msg.payload, DEFAULT_MAX_DECOMPRESSED_BYTES) {
                if !fire_and_forget {
                    drain_parked(parked, out)?;
                    reply_err(out, &format!("malformed compressed descriptor: {e}"));
                }
                return Ok(());
            }
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
            // Mask BOTH wire-only PUB flag bits (dedup bit 7, fire-and-forget bit 6) out of the
            // stored record flags (#33, #11): neither is record state. The fire-and-forget marker is
            // carried in its own field below, not in the stored flags.
            flags: msg.flags & !PUB_WIRE_ONLY_FLAGS,
            key: Bytes::copy_from_slice(msg.key),
            headers: Bytes::copy_from_slice(msg.headers),
            payload: Bytes::copy_from_slice(msg.payload),
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
        };
        // LEVEL 0 (no-ack fast path, #495): submit the produce with NO reply channel and return
        // immediately — do NOT park. The producer fired and forgot, so there is no PubAck to write, no
        // reply-channel allocation, and no fsync to wait for. The connection-thread byte-cap pre-check
        // (#476) inside `produce_no_reply` sheds an over-cap L0 here (counted in the fire-and-forget
        // shed metric), droppable under overload; an admitted L0 is appended into the actor's batch
        // (single-writer storage / single total order) but never acked. An old fire-and-forget publish
        // takes exactly this path (it decodes as Level 0).
        if level0 {
            engine.produce_no_reply(append)?;
            return Ok(());
        }
        // LEVEL 1 / LEVEL 2 (at-least-once; L2 falls back to L1 this phase): SUBMIT the produce to the
        // actor WITHOUT awaiting (#450) and PARK the pending ack. The caller releases parked acks in
        // FIFO submission order, so the reply this produce eventually gets is byte-identical to the
        // awaited path's, only written later in the same pass. The submission still blocks on a FULL
        // actor channel (backpressure), and the actor still releases the reply only after the covering
        // group-commit fsync (I2). This path is unchanged from before the ack-level feature.
        let submission = engine.produce_submit(append)?;
        parked.push(ParkedPub {
            submission,
            fire_and_forget,
        });
        Ok(())
    }

    /// Handles a consumer acknowledgement (ack, nack, term, or progress) for a delivered
    /// message. Acks are connection-scoped (#175): the session tracks the lease tokens it
    /// handed out via Flow, and an op whose `(offset, generation)` was not delivered to THIS
    /// session is fenced (status 0) without touching the engine, so a second connection cannot
    /// commit or requeue a message destined for another consumer. The generation token still
    /// fences a stale op on an own-but-already-redelivered lease.
    fn handle_ack<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
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
                reply_err(out, &e.to_string());
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
        // The per-consumer remaining credit: the ceiling minus what this connection already holds
        // un-acked. The effective batch bound is min(requested, remaining); the per-group
        // `max_in_flight` window further caps it inside the engine's poll (a full window returns
        // Poll::Idle, ending the batch early), so the delivered total is the MIN of the requested
        // credit, this consumer's remaining credit, and whatever the group makes available. Bounding
        // the WHOLE loop by `credits` (not `requested`) is what stops the engine from leasing an
        // offset this connection has no credit to deliver: at zero remaining credit the loop body
        // never runs, so a saturated consumer gets an empty batch even with messages available.
        let ceiling = self.credit_ceiling(engine)?;
        let held = u32::try_from(self.leased.len()).unwrap_or(u32::MAX);
        let remaining = ceiling.saturating_sub(held);
        // The negotiated per-consumer credit bound, before the egress AIMD.
        let want = requested.min(remaining);
        // EGRESS AIMD (#69, #402): adjust the EFFECTIVE per-consumer egress credit WITHIN the
        // negotiated #292 ceiling. `egress_grant_within(ceiling)` is `min(ceiling, AIMD limit)`, so the
        // limiter never exceeds the negotiated cap; when the AIMD is inert (the default) it returns the
        // ceiling unchanged, so `credits` is exactly `want` and the path is byte-for-byte historical.
        // A real, observable WOULD-BLOCK is when the consumer wanted MORE than the limiter grants while
        // ALREADY holding a near-full in-flight set (it is not keeping up): that is the falling-behind
        // signal, so the AIMD multiplicatively decreases (and counts the throttled grant). A clean
        // keep-up (prompt acks) drives the additive increase on the ack path.
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
            let group = self.subscription.clone();
            let member = self.member_id;
            match engine.with(move |e| e.poll_now_in_member(&group, member))? {
                Ok(Poll::Message(d)) => {
                    let msg = DeliverBody {
                        offset: d.offset.get(),
                        generation: d.token.generation,
                        flags: d.record.flags.bits(),
                        timestamp_ms: d.record.timestamp_ms,
                        key: &d.record.key,
                        headers: &d.record.headers,
                        payload: &d.record.payload,
                    };
                    let mut frame_body = Vec::new();
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
                    let mut frame_body = Vec::new();
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
                    self.emit_truncation(out, earliest_retained.get(), skipped);
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
                        Self::emit_compaction(out, from.get(), to.get());
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
        // Drop ownership of any offset now committed (acked here, or committed past on a
        // dead-letter), keeping `leased` bounded to the in-flight window.
        let group = self.subscription.clone();
        let committed = engine.with(move |e| e.committed_offset_in(&group).get())?;
        self.leased.retain(|&offset, _| offset >= committed);
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
        // The per-consumer remaining message credit: the ceiling minus what this connection already
        // holds un-acked (identical to `handle_flow`). The batch is bounded by the MIN of the requested
        // `max_records`, this remaining credit, and the egress AIMD grant, so a generous `max_records`
        // can NEVER over-deliver past the negotiated ceiling — the same guard the per-record path uses.
        let ceiling = self.credit_ceiling(engine)?;
        let held = u32::try_from(self.leased.len()).unwrap_or(u32::MAX);
        let remaining = ceiling.saturating_sub(held);
        // The requested record cap, clamped to the per-consumer remaining credit (the negotiated #292
        // ceiling binds before the engine ever leases an offset this connection cannot deliver).
        let want = req.max_records.min(remaining);
        // EGRESS AIMD (#69, #402), identical to `handle_flow`: keep the effective egress credit within
        // the negotiated ceiling, and count a real would-block (the consumer wants more than the limiter
        // grants while already holding near a grant's worth un-acked) as a falling-behind signal.
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
                    let msg = DeliverBody {
                        offset: d.offset.get(),
                        generation: d.token.generation,
                        flags: d.record.flags.bits(),
                        timestamp_ms: d.record.timestamp_ms,
                        key: &d.record.key,
                        headers: &d.record.headers,
                        payload: &d.record.payload,
                    };
                    let mut frame_body = Vec::new();
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
                    let mut frame_body = Vec::new();
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
                    self.emit_truncation(out, earliest_retained.get(), skipped);
                }
                // A key-compaction hole: identical to `handle_flow` — a gap-marker-capable consumer gets
                // the COMPACTED marker, a non-capable one silently advances. Keep draining.
                Ok(Poll::Compacted { from, to }) => {
                    if self.gap_marker_enabled {
                        Self::emit_compaction(out, from.get(), to.get());
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
        // Drop ownership of any offset now committed, keeping `leased` bounded — identical to `handle_flow`.
        let group = self.subscription.clone();
        let committed = engine.with(move |e| e.committed_offset_in(&group).get())?;
        self.leased.retain(|&offset, _| offset >= committed);
        // The batch terminates with the SAME FlowEnd the Flow path uses (its body the delivered count),
        // so the response is byte-for-byte a Flow response past the request frame.
        reply(out, FrameType::FlowEnd, &delivered.to_le_bytes());
        Ok(())
    }

    /// Emits the in-band advisory for a `Poll::Truncated` skip: a consumer that negotiated the
    /// gap-marker capability (#346) gets the richer, consumer-visible `GapMarker` (tag 21) for the
    /// skipped span `[from, to)` where `to == earliest_retained` (delivery resumes at the oldest
    /// record still present) and `from == earliest_retained - skipped` (where the cursor was), reason
    /// TRIMMED (the disk-full drop-oldest reap) with `bytes_skipped == 0` (a force-reap trim is
    /// byte-untracked: the span is reported by its record count `to - from`, matching the recovery-side
    /// `loss-report.v1` convention). A consumer WITHOUT the capability gets the legacy `Truncated`
    /// (tag 18) instead, so the two NEVER double-signal and an old consumer is never sent the new tag.
    fn emit_truncation(&self, out: &mut Vec<u8>, earliest_retained: u64, skipped: u64) {
        let mut frame_body = Vec::new();
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
                &mut frame_body,
            );
            reply(out, FrameType::GapMarker, &frame_body);
        } else {
            encode_truncated(
                &TruncatedBody {
                    earliest_retained,
                    skipped,
                },
                &mut frame_body,
            );
            reply(out, FrameType::Truncated, &frame_body);
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
    fn emit_compaction(out: &mut Vec<u8>, from: u64, to: u64) {
        let mut frame_body = Vec::new();
        encode_gap_marker(
            &GapMarkerBody {
                from,
                to,
                bytes_skipped: 0,
                reason: gap_reason::COMPACTED,
            },
            &mut frame_body,
        );
        reply(out, FrameType::GapMarker, &frame_body);
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
                    reply_err(out, &e.to_string());
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

/// The safety cap on a single pass's pipelined produce window (#450): how many produces a session
/// may PARK (submitted to the actor, ack not yet awaited) before it must release the window. It
/// bounds the parked-reply memory for a buffer packed with tiny PUB frames and matches the actor
/// channel's default bound ([`crate::actor::DEFAULT_CHANNEL_BOUND`]), so a session can never queue
/// more un-awaited produces than the channel was sized for. In practice the window is far smaller:
/// the connection loop hands the session one read buffer at a time.
const MAX_PARKED_PRODUCES: usize = 1024;

/// One produce PARKED in a session's pipelined window (#450): the un-awaited submission plus the
/// QoS-0 marker the reply mapping needs (a fire-and-forget produce gets NO frame for any
/// disposition, the #11 no-frame contract).
struct ParkedPub {
    /// The submitted-but-not-awaited produce; awaiting it yields the outcome only after the
    /// covering group-commit fsync (I2).
    submission: ProduceSubmission,
    /// Whether the producer marked this publish fire-and-forget (QoS-0, #11): suppresses every
    /// reply frame for this produce, exactly like the awaited path.
    fire_and_forget: bool,
}

/// Releases a parked produce window (#450): awaits each submission IN SUBMISSION ORDER and appends
/// its reply frame(s) to `out`, so the wire sees exactly the FIFO ack order the per-connection
/// contract promises. On a fatal outcome the error propagates immediately; the remaining parked
/// entries are dropped un-replied, which is safe because a batch-covering fsync failure marks EVERY
/// member of the batch fatal (the actor's `flush_pending`) and the session is closing anyway (the
/// actor tolerates a dropped reply receiver). After this returns, `parked` is empty.
fn drain_parked(parked: &mut Vec<ParkedPub>, out: &mut Vec<u8>) -> Result<(), SessionError> {
    for p in parked.drain(..) {
        let outcome = p.submission.wait()?;
        write_pub_reply(outcome, p.fire_and_forget, out)?;
    }
    Ok(())
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
        // idempotent retry over a lossy edge link does not loop.
        ProduceOutcome::AppendedDuplicate(offset) => {
            reply_pub_ack(out, FrameType::PubAckDuplicate, offset);
            Ok(())
        }
        // A stale-epoch fence (#33): a zombie session reused an old `producer_id` with an epoch
        // below the broker's known high-water. Reject it with a distinct, stable message; the
        // connection stays open so the producer can re-handshake with a fresh epoch.
        ProduceOutcome::Fenced => {
            if !fire_and_forget {
                reply_err(out, "fenced: stale producer epoch");
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
                reply_err(out, "at capacity");
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
        decode_deliver, decode_pub_ack, encode_ack, encode_pub, AckBody, PubBody, PubDedup,
        PUB_FLAG_ACK_LEVEL_SHIFT, PUB_FLAG_FIRE_AND_FORGET,
    };
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::{Append, LogConfig};
    use std::sync::Arc;

    /// The shared session-test engine config, factored out so the pipelined-window test (#450) can
    /// open the SAME config over a fault-injecting filesystem (to count fsyncs).
    fn test_config() -> EngineConfig {
        EngineConfig {
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
        assert_eq!(body, b"at capacity");
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
        assert_eq!(body, b"at capacity");
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
                dedup: None,
                enqueue_monotonic_nanos: 0,
                fire_and_forget: false,
            })
            .unwrap();
        control.wait_for_sync_gate_entered(1);

        // The pipelined window: N PUB frames in ONE input buffer, ONE process pass. The pass
        // submits all N (opening the gate on the last submission), then awaits the parked acks.
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
}
