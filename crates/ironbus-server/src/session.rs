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
//! Response body conventions: an `Ok` to a `Pub` carries the 8-byte little-endian assigned
//! offset; other `Ok`s have an empty body; an `Err` carries a UTF-8 message. A malformed
//! frame envelope is unrecoverable for a length-prefixed stream, so it ends the session.

use crate::engine::{AckResult, Engine, EngineError, NackResult, Poll, ProgressResult};
use ironbus_core::clock::Clock;
use ironbus_core::types::RecordFlags;
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{decode_ack, decode_pub, encode_deliver, AckOp, DeliverBody};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Append;

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
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::BadFrame(e) => write!(f, "malformed frame, closing session: {e}"),
            SessionError::EngineFatal(e) => write!(f, "fatal engine error, closing session: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Per-connection session state over a shared [`Engine`].
#[derive(Debug, Default)]
pub struct Session {
    connected: bool,
}

impl Session {
    /// A new, not-yet-handshaked session.
    #[must_use]
    pub fn new() -> Session {
        Session::default()
    }

    /// Processes the complete frames at the front of `input`, dispatching each to `engine`
    /// and appending response frames to `out`. Returns the number of input bytes consumed;
    /// a partial trailing frame is not consumed and should be retried once more bytes
    /// arrive.
    ///
    /// # Errors
    /// Returns [`SessionError::BadFrame`] if a frame envelope is malformed; the caller must
    /// then close the connection (a length-prefixed stream cannot resync).
    pub fn process<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<usize, SessionError> {
        let mut consumed = 0;
        loop {
            match decode_frame(&input[consumed..]).map_err(SessionError::BadFrame)? {
                FrameDecode::Incomplete { .. } => return Ok(consumed),
                FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed: n,
                } => {
                    // A fatal engine error ends the session AFTER its Err response is
                    // queued (the caller flushes `out`, then closes).
                    self.dispatch(engine, type_tag, body, out)?;
                    consumed += n;
                }
            }
        }
    }

    fn dispatch<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
        type_tag: u8,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SessionError> {
        match FrameType::from_u8(type_tag) {
            // A repeated Connect is idempotent today (the handshake carries no negotiated
            // state yet); once Connect carries capabilities, decide whether to reject one.
            Some(FrameType::Connect) => {
                self.connected = true;
                reply(out, FrameType::Info, &[]);
                Ok(())
            }
            Some(FrameType::Ping) => {
                reply(out, FrameType::Pong, &[]);
                Ok(())
            }
            Some(FrameType::Pub) => self.handle_pub(engine, body, out),
            Some(FrameType::Ack) => self.handle_ack(engine, body, out),
            Some(FrameType::Flow) => self.handle_flow(engine, body, out),
            // Sub/Unsub (not yet wired) and the standalone Nack frame type (a client sends a
            // nack as an Ack frame with the Nack op, handled above), or a response-only verb
            // (Info/Pong/Ok/Err/Deliver) a client should not send.
            Some(_) => {
                reply_err(out, "verb not supported on this connection");
                Ok(())
            }
            // An unknown tag is forward-compatible at the envelope level but has no handler.
            None => {
                reply_err(out, "unknown frame type");
                Ok(())
            }
        }
    }

    fn handle_pub<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
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
        let append = Append {
            timestamp_ms: msg.timestamp_ms,
            // The codec normalizes the HAS_KEY bit and preserves unknown bits for
            // forward compatibility; the storage layer never acts on unknown bits.
            flags: RecordFlags::from_bits(msg.flags),
            key: msg.key,
            headers: msg.headers,
            payload: msg.payload,
        };
        match engine.produce(&append) {
            Ok(offset) => {
                reply(out, FrameType::Ok, &offset.get().to_le_bytes());
                Ok(())
            }
            // A fatal error (frozen writer) would fail every future produce, so end the
            // session rather than masquerade as a transient failure.
            Err(e) if e.is_fatal() => {
                reply_err(out, "fatal storage error");
                Err(SessionError::EngineFatal(e))
            }
            Err(_) => {
                reply_err(out, "produce failed");
                Ok(())
            }
        }
    }

    /// Handles a consumer acknowledgement (ack, nack, term, or progress) for a delivered
    /// message. NOTE: acknowledgements are not connection-scoped,
    /// the generation token is the sole authority, so any session presenting a matching
    /// `(offset, generation)` commits or requeues it. Per-connection ack ownership is tracked
    /// as #175 for the consumer path.
    fn handle_ack<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
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
        let token = ironbus_core::lease::LeaseToken {
            offset: ironbus_core::types::Offset::new(ack.offset),
            generation: ack.generation,
        };
        // Each op replies a one-byte status whose exact meaning is documented per arm below
        // (e.g. progress can reply 2 = cap reached). A status of 0 always means fenced: the
        // token was stale (the message already redelivered or was acked), so the client must
        // NOT drop its state.
        match ack.op {
            AckOp::Ack => {
                let status = match engine.ack(&token) {
                    AckResult::Acked => 1u8,
                    AckResult::Fenced => 0u8,
                };
                reply(out, FrameType::Ok, &[status]);
                Ok(())
            }
            AckOp::Nack => match engine.nack(&token, ack.delay_ms) {
                Ok(NackResult::Requeued) => {
                    reply(out, FrameType::Ok, &[1]);
                    Ok(())
                }
                Ok(NackResult::Fenced) => {
                    reply(out, FrameType::Ok, &[0]);
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
            },
            // Term is an intentional drop: commit past the message (the same mechanism as
            // ack) so it never redelivers and is not dead-lettered. 1 = dropped, 0 = fenced.
            AckOp::Term => {
                let status = match engine.term(&token) {
                    AckResult::Acked => 1u8,
                    AckResult::Fenced => 0u8,
                };
                reply(out, FrameType::Ok, &[status]);
                Ok(())
            }
            // Progress extends the lease (the consumer is still working). 1 = extended,
            // 2 = cap reached (the lease will expire and the message redeliver on schedule),
            // 0 = fenced.
            AckOp::Progress => {
                let status = match engine.progress(&token) {
                    ProgressResult::Extended => 1u8,
                    ProgressResult::CapReached => 2u8,
                    ProgressResult::Fenced => 0u8,
                };
                reply(out, FrameType::Ok, &[status]);
                Ok(())
            }
        }
    }
    /// Fetches up to the requested number of messages and streams them as DELIVER frames,
    /// terminated by an `Ok` whose body is the count delivered (so the client knows the
    /// batch is complete). The credit count is a little-endian `u32`.
    fn handle_flow<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
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
        let credits = u32::from_le_bytes(credit_bytes);
        let mut delivered = 0u32;
        for _ in 0..credits {
            match engine.poll_now() {
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
                    delivered += 1;
                }
                // A parked (poison, over max-deliver) message is committed past by the
                // engine and skipped from delivery. The dead-letter advisory + DLQ write
                // (#63) is not yet wired, so the consumer is not told here; keep draining.
                Ok(Poll::Parked { .. }) => {}
                // Nothing more deliverable right now: end the batch early.
                Ok(Poll::Idle) => break,
                Err(e) if e.is_fatal() => {
                    reply_err(out, "fatal storage error");
                    return Err(SessionError::EngineFatal(e));
                }
                Err(_) => {
                    // The Err is this batch's terminator; do NOT also send Ok (that would
                    // desync the client, which expects exactly one terminator per Flow).
                    reply_err(out, "fetch failed");
                    return Ok(());
                }
            }
        }
        reply(out, FrameType::Ok, &delivered.to_le_bytes());
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Engine, EngineConfig, Poll};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_proto::message::{decode_deliver, encode_ack, encode_pub, AckBody, PubBody};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;
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
                checkpoint_interval: 1024,
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

    fn produce<C: Clock>(e: &mut Engine<InMemoryFs, C>, payload: &[u8]) {
        e.produce(&Append {
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
                checkpoint_interval: 1024,
            },
        )
        .unwrap()
    }

    /// Sends one acknowledgement op and returns the Ok status body, asserting the reply is a
    /// single Ok frame.
    fn ack_reply<C: Clock>(
        s: &mut Session,
        e: &mut Engine<InMemoryFs, C>,
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
            FrameType::Ok,
            "expected Ok, got {:?}",
            replies[0].0
        );
        replies[0].1.clone()
    }

    #[test]
    fn progress_then_cap_then_term_over_the_wire() {
        let clock = Arc::new(ManualClock::new());
        let mut e = engine_with(Arc::clone(&clock), 5);
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&mut e, b"x");

        // Fetch to lease offset 0 (deadline = now(0) + 30, hard cap at 100).
        out.clear();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let toks = delivered_tokens(&out);
        assert_eq!(toks.len(), 1);
        let (offset, generation) = toks[0];

        // Progress at t=25 extends the lease: status byte 1.
        clock.advance_monotonic_nanos(25);
        assert_eq!(
            ack_reply(&mut s, &mut e, AckOp::Progress, offset, generation),
            vec![1]
        );
        // Progress at t=100 (attempt_start 0 + hard cap 100) cannot extend: status byte 2.
        clock.advance_monotonic_nanos(75);
        assert_eq!(
            ack_reply(&mut s, &mut e, AckOp::Progress, offset, generation),
            vec![2]
        );
        // Term drops it (status byte 1) and commits past it.
        assert_eq!(
            ack_reply(&mut s, &mut e, AckOp::Term, offset, generation),
            vec![1]
        );
        assert_eq!(e.committed_offset().get(), 1);
        // A term of the now-stale token is fenced: status byte 0.
        assert_eq!(
            ack_reply(&mut s, &mut e, AckOp::Term, offset, generation),
            vec![0]
        );
    }

    #[test]
    fn term_before_connect_is_rejected() {
        let clock = Arc::new(ManualClock::new());
        let mut e = engine_with(Arc::clone(&clock), 5);
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
        s.process(&mut e, &frame(FrameType::Ack, &body), &mut out)
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
        let mut e = engine_with(Arc::clone(&clock), 5);
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&mut e, b"x");

        // First fetch delivers and leases it (deadline = now(0) + 30).
        out.clear();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let first = delivered_tokens(&out);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, 0);

        // Re-fetch before the timeout: the lease is still held, nothing redelivers.
        out.clear();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        assert!(
            delivered_tokens(&out).is_empty(),
            "in-flight, not redelivered yet"
        );

        // Advance past the visibility timeout: now it redelivers with a NEW generation.
        clock.advance_monotonic_nanos(40);
        out.clear();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let second = delivered_tokens(&out);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].0, 0);
        assert_ne!(second[0].1, first[0].1, "redelivery fences the old token");
    }

    #[test]
    fn a_poison_message_is_parked_and_skipped_in_the_fetch() {
        let clock = Arc::new(ManualClock::new());
        let mut e = engine_with(Arc::clone(&clock), 1); // max_deliver = 1
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&mut e, b"poison");

        // First fetch delivers (delivery 1).
        out.clear();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        assert_eq!(delivered_tokens(&out).len(), 1);

        // Expire it; the next fetch's claim is delivery 2 > max_deliver, so it is parked
        // (committed past) and NOT delivered: an empty batch (Ok with no Deliver frames).
        clock.advance_monotonic_nanos(40);
        out.clear();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        assert!(
            delivered_tokens(&out).is_empty(),
            "the poison message is not delivered"
        );
        assert_eq!(
            e.committed_offset().get(),
            1,
            "the poison message is parked past"
        );
    }

    #[test]
    fn flow_fetches_messages_as_deliver_frames_then_ok() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        out.clear();
        // Fetch up to 5: two messages are available, then the batch terminates with Ok(2).
        s.process(
            &mut e,
            &frame(FrameType::Flow, &5u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let frames = decode_all(&out);
        assert_eq!(frames.len(), 3, "two Deliver frames then an Ok terminator");
        assert_eq!(frames[0].0, FrameType::Deliver);
        let d0 = decode_deliver(&frames[0].1).unwrap();
        assert_eq!(d0.offset, 0);
        assert_eq!(d0.payload, b"a");
        assert_eq!(frames[1].0, FrameType::Deliver);
        assert_eq!(decode_deliver(&frames[1].1).unwrap().payload, b"b");
        assert_eq!(frames[2].0, FrameType::Ok);
        assert_eq!(
            frames[2].1,
            2u32.to_le_bytes(),
            "Ok carries the delivered count"
        );
    }

    #[test]
    fn flow_with_nothing_available_replies_ok_zero() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &3u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        let frames = decode_all(&out);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, FrameType::Ok);
        assert_eq!(frames[0].1, 0u32.to_le_bytes());
    }

    #[test]
    fn flow_before_connect_is_rejected() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
        .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn end_to_end_produce_fetch_ack_over_the_session() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
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
        s.process(&mut e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap();
        out.clear();
        // Fetch it.
        s.process(
            &mut e,
            &frame(FrameType::Flow, &1u32.to_le_bytes()),
            &mut out,
        )
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
        s.process(&mut e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        assert_eq!(e.committed_offset().get(), 1);
    }

    #[test]
    fn ping_is_answered_with_pong() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let input = frame(FrameType::Ping, b"");
        let consumed = s.process(&mut e, &input, &mut out).unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(one_response(&out).0, FrameType::Pong);
    }

    #[test]
    fn connect_is_answered_with_info() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
    }

    #[test]
    fn pub_after_connect_appends_and_replies_ok_with_the_offset() {
        let mut e = engine();
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

        let consumed = s.process(&mut e, &input, &mut out).unwrap();
        assert_eq!(consumed, input.len());
        // Two responses: Info, then Ok with offset 0.
        let info = decode_frame(&out).unwrap();
        let FrameDecode::Frame { consumed: c0, .. } = info else {
            panic!("info incomplete");
        };
        let (ty, body) = one_response(&out[c0..]);
        assert_eq!(ty, FrameType::Ok);
        assert_eq!(body, 0u64.to_le_bytes());
        // The message is durable in the engine and deliverable.
        match e.poll(0).unwrap() {
            Poll::Message(d) => assert_eq!(d.record.payload, b"hello"),
            other => panic!("expected the produced message, got {other:?}"),
        }
    }

    #[test]
    fn pub_before_connect_is_rejected() {
        let mut e = engine();
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
        s.process(&mut e, &frame(FrameType::Pub, &pub_body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn ack_commits_a_delivered_message() {
        let mut e = engine();
        let mut s = Session::new();
        // Connect + produce + deliver out of band, then ack via the session.
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"m",
        })
        .unwrap();
        let token = match e.poll(0).unwrap() {
            Poll::Message(d) => d.token,
            other => panic!("expected a delivery, got {other:?}"),
        };
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: token.offset.get(),
                generation: token.generation,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        out.clear();
        s.process(&mut e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Ok);
        assert_eq!(body, vec![1u8], "status 1 = committed");
        assert_eq!(e.committed_offset().get(), 1);
    }

    #[test]
    fn a_partial_trailing_frame_is_not_consumed() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let ping = frame(FrameType::Ping, b"");
        let mut input = ping.clone();
        input.extend_from_slice(&frame(FrameType::Ping, b"")[..2]); // half of a second frame
        let consumed = s.process(&mut e, &input, &mut out).unwrap();
        assert_eq!(consumed, ping.len(), "only the complete frame is consumed");
        assert_eq!(one_response(&out).0, FrameType::Pong);
    }

    #[test]
    fn empty_input_consumes_nothing() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        assert_eq!(s.process(&mut e, &[], &mut out).unwrap(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn ack_before_connect_is_rejected() {
        let mut e = engine();
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
        s.process(&mut e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn a_fenced_ack_replies_ok_with_status_zero() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        // A never-delivered token is stale: fenced, status 0, the client must not drop state.
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
        s.process(&mut e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        let (ty, body) = one_response(&out);
        assert_eq!(ty, FrameType::Ok);
        assert_eq!(body, vec![0u8], "status 0 = fenced");
        assert_eq!(e.committed_offset().get(), 0);
    }

    #[test]
    fn a_malformed_body_does_not_desync_the_stream() {
        // [Connect][Pub with a truncated body][Ping] in one buffer: the bad body is
        // contained (Err reply), and the trailing Ping still gets a Pong.
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut input = frame(FrameType::Connect, b"");
        input.extend_from_slice(&frame(FrameType::Pub, b"\x01")); // 1 byte: not a valid pub body
        input.extend_from_slice(&frame(FrameType::Ping, b""));

        let consumed = s.process(&mut e, &input, &mut out).unwrap();
        assert_eq!(
            consumed,
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
    fn a_second_connection_can_ack_a_message_delivered_to_the_first() {
        // Documents the current model (issue #175): acks are not connection-scoped; the
        // generation token is the sole authority, so any session with a valid token commits.
        let mut e = engine();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"m",
        })
        .unwrap();
        let token = match e.poll(0).unwrap() {
            Poll::Message(d) => d.token,
            other => panic!("expected a delivery, got {other:?}"),
        };
        // A fresh session B (never delivered the message) acks it with the token.
        let mut b = Session::new();
        let mut out = Vec::new();
        b.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: token.offset.get(),
                generation: token.generation,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        b.process(&mut e, &frame(FrameType::Ack, &ack_body), &mut out)
            .unwrap();
        assert_eq!(e.committed_offset().get(), 1, "B committed A's message");
    }

    #[test]
    fn a_malformed_frame_ends_the_session() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let bad = [0u8, 0, 0, 0]; // zero-length prefix
        assert!(matches!(
            s.process(&mut e, &bad, &mut out),
            Err(SessionError::BadFrame(_))
        ));
    }

    #[test]
    fn an_unsupported_verb_replies_err_without_closing() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out)
            .unwrap();
        out.clear();
        // Sub is recognized but not wired on this connection.
        s.process(&mut e, &frame(FrameType::Sub, b""), &mut out)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }
}
