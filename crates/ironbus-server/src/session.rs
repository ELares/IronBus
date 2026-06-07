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

use crate::actor::{ActorGone, EngineAccess, OwnedAppend, ProduceOutcome};
use crate::engine::{AckResult, EngineError, NackResult, Poll, ProgressResult};
use ironbus_core::clock::Clock;
use ironbus_core::keyshared::{KeyOrdering, MemberId};
use ironbus_core::lease::LeaseToken;
use ironbus_core::types::Offset;
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{
    decode_ack, decode_cumulative_ack, decode_pub, decode_sub, encode_dead_letter, encode_deliver,
    encode_truncated, AckOp, DeadLetterBody, DeliverBody, TruncatedBody, DEAD_LETTER_MAX_DELIVER,
};
use ironbus_storage::fs::Filesystem;
use std::collections::HashMap;

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
#[derive(Debug, Default)]
pub struct Session {
    connected: bool,
    /// The work-group this connection is subscribed to, set by SUB and cleared by UNSUB.
    /// Empty selects the default group (#9), so an unsubscribed consumer behaves exactly as
    /// before. FLOW fetches and ACKs route to this group.
    subscription: String,
    /// The leases this session was delivered via Flow and may still act on, keyed by offset to the
    /// granted generation AND the message's byte size (#65, #275). Acks are scoped to this map
    /// (#175), so one connection cannot ack a message delivered to another. Keying by offset bounds
    /// it to one entry per offset (a redelivery overwrites the stale lease), and committed offsets
    /// are pruned per batch, so it stays within the in-flight window. Its SIZE is this connection's
    /// in-flight message count and the SUM of its `bytes` is its in-flight byte total, so BOTH the
    /// per-consumer message credit and the byte budget (#275) are derived from it directly and cannot
    /// drift.
    leased: HashMap<u64, Lease>,
    /// The per-CONSUMER (per-connection) in-flight credit ceiling (#65), cached from
    /// [`Engine::consumer_credit`] on the first Flow. `None` until then: the engine is the source of
    /// truth for the ceiling (so a `serve` flag sets it once for every connection), and a session is
    /// created before it has an engine handle. Once set it never changes for the life of the
    /// connection. The remaining message credit at any moment is `ceiling - leased.len()`.
    credit_ceiling: Option<u32>,
    /// The per-CONSUMER (per-connection) in-flight BYTE budget (#275), cached from
    /// [`Engine::consumer_credit_bytes`] on the first Flow alongside `credit_ceiling`. `None` until
    /// then, for the same reason. Once set it never changes for the life of the connection. `0` means
    /// UNLIMITED (the byte budget is off, only the message credit binds). The remaining byte budget
    /// at any moment is `ceiling_bytes - (sum of leased values' bytes)`.
    credit_ceiling_bytes: Option<u64>,
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
        loop {
            match decode_frame(&input[consumed..]).map_err(SessionError::BadFrame)? {
                // The trailing frame is partial: report how many bytes it needs so the caller does
                // not re-decode until at least that many have arrived (the #176 fix). `needed` is
                // relative to the UNCONSUMED remainder (`&input[consumed..]`): the caller drains the
                // `consumed` prefix, after which the partial frame sits at the front of its buffer
                // and needs exactly `needed` bytes there, so the threshold the caller compares its
                // post-drain buffer length against is this `needed` directly.
                FrameDecode::Incomplete { needed } => {
                    return Ok(Progress {
                        consumed,
                        needed,
                        committed_progress,
                    });
                }
                FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed: n,
                } => {
                    // A fatal engine error ends the session AFTER its Err response is
                    // queued (the caller flushes `out`, then closes).
                    committed_progress |= self.dispatch(engine, type_tag, body, out)?;
                    consumed += n;
                }
            }
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
            // A repeated Connect is idempotent today (the handshake carries no negotiated
            // state yet); once Connect carries capabilities, decide whether to reject one.
            Some(FrameType::Connect) => {
                self.connected = true;
                reply(out, FrameType::Info, &[]);
                Ok(false)
            }
            Some(FrameType::Ping) => {
                reply(out, FrameType::Pong, &[]);
                Ok(false)
            }
            Some(FrameType::Pub) => self.handle_pub(engine, body, out).map(|()| false),
            Some(FrameType::Ack) => self.handle_ack(engine, body, out).map(|()| true),
            // A cumulative ack commits the broadcast cursor (when accepted), so it returns `true` to
            // run the interval checkpoint, exactly like a per-message Ack (#288).
            Some(FrameType::CumulativeAck) => {
                self.handle_cumulative_ack(engine, body, out).map(|()| true)
            }
            Some(FrameType::Flow) => self.handle_flow(engine, body, out).map(|()| true),
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

    fn handle_pub<F: Filesystem + 'static, C: Clock + Clone + 'static, E: EngineAccess<F, C>>(
        &mut self,
        engine: &E,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        if !self.connected {
            reply_err(out, "not connected");
            return Ok(());
        }
        let Ok(msg) = decode_pub(body) else {
            reply_err(out, "malformed pub body");
            return Ok(());
        };
        // Hand the produce to the append actor as an OWNED payload (the wire body borrows the
        // connection's input buffer, which the actor cannot hold) and AWAIT its outcome. The reply
        // arrives only after the covering group-commit fsync, so the PubAck is ack-implies-durable
        // (I2): the actor never replies Appended before the fdatasync that made the record durable.
        // The codec already normalized the HAS_KEY bit and preserved unknown bits for forward
        // compatibility; the storage layer never acts on unknown bits.
        let append = OwnedAppend {
            timestamp_ms: msg.timestamp_ms,
            flags: msg.flags,
            key: msg.key.to_vec(),
            headers: msg.headers.to_vec(),
            payload: msg.payload.to_vec(),
        };
        match engine.produce(append)? {
            ProduceOutcome::Appended(offset) => {
                reply(out, FrameType::PubAck, &offset.get().to_le_bytes());
                Ok(())
            }
            // A fatal error (frozen writer) would fail every future produce, so end the
            // session rather than masquerade as a transient failure.
            ProduceOutcome::Fatal(e) => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            // The durable-log byte cap shed (drop-new): a distinct, stable message so a
            // producer can tell a deliberate shed from a transient failure. The connection
            // stays open, so the producer can keep going (a later produce succeeds once
            // retention frees space).
            ProduceOutcome::AtCapacity => {
                reply_err(out, "at capacity");
                Ok(())
            }
            ProduceOutcome::Failed(_) => {
                reply_err(out, "produce failed");
                Ok(())
            }
        }
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
                    AckResult::Acked => 1u8,
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
        match engine.with(move |e| e.cumulative_ack_in(&group, up_to))? {
            Ok(()) => {
                // A committed (or idempotent no-op) cumulative ack: the generic body-less success.
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
    /// The per-CONSUMER (per-connection) in-flight credit ceiling (#65) for this session, cached
    /// from the engine on the first call. The engine is the source of truth (a `serve` flag sets it
    /// once for every connection), and it is already floored to at least 1. Reads through the actor
    /// once, then caches, so the round-trip is paid only on the first Flow.
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
        let c = engine.with(|e| e.consumer_credit())?;
        self.credit_ceiling = Some(c);
        Ok(c)
    }

    /// The per-CONSUMER (per-connection) in-flight BYTE budget (#275) for this session, cached from
    /// the engine on the first call alongside [`Session::credit_ceiling`]. The engine is the source
    /// of truth (a `serve` flag sets it once for every connection). `0` means unlimited.
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
        let c = engine.with(|e| e.consumer_credit_bytes())?;
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
        let credits = requested.min(remaining);
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
                    let mut frame_body = Vec::new();
                    encode_truncated(
                        &TruncatedBody {
                            earliest_retained: earliest_retained.get(),
                            skipped,
                        },
                        &mut frame_body,
                    );
                    reply(out, FrameType::Truncated, &frame_body);
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
        if self.registered_subscription && old_group != new_group {
            engine.with(move |e| {
                e.unsubscribe_in(&old_group, member);
            })?;
        }
        // Switching subscriptions abandons this connection's in-flight leases in the
        // previous group (they redeliver there after the visibility timeout), so the new
        // subscription starts with no outstanding leases. The name's shape and the group
        // cap are validated by the engine on the first FLOW (#240), surfaced as an Err.
        group.clone_into(&mut self.subscription);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::DirectEngine;
    use crate::engine::{DiskFullPolicy, Engine, EngineConfig, Poll};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_core::types::RecordFlags;
    use ironbus_proto::message::{decode_deliver, encode_ack, encode_pub, AckBody, PubBody};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::{Append, LogConfig};
    use std::sync::Arc;

    fn engine() -> Engine<InMemoryFs, ManualClock> {
        Engine::open(
            InMemoryFs::new(),
            ManualClock::new(),
            EngineConfig {
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
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap()
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
                disk_full_policy: DiskFullPolicy::DropNew,
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
                disk_full_policy: DiskFullPolicy::DropOldest,
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
            Poll::Message(d) => assert_eq!(d.record.payload, b"hello"),
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
                    disk_full_policy: DiskFullPolicy::DropNew,
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
                disk_full_policy: DiskFullPolicy::DropNew,
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
                disk_full_policy: DiskFullPolicy::DropNew,
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
}
