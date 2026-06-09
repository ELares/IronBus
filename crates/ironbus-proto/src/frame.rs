// SPDX-License-Identifier: MIT OR Apache-2.0
//! The wire frame envelope: length-prefixed, type-tagged binary framing.
//!
//! Every protocol message travels in one frame: a little-endian `u32` length prefix over
//! the rest of the frame, a one-byte type tag, then a type-specific body. The length
//! prefix lets a reader know a frame's full size before reading its body (so framing is
//! independent of the body codecs, which later work defines), and it is validated against
//! a hard cap BEFORE any allocation, so a hostile or corrupt length cannot force a large
//! reservation. Decoding is a streaming parser: it reports how many bytes a complete frame
//! consumed, or how many it still needs, so a connection can frame a byte stream without
//! over-reading. Unknown type tags decode at the envelope level (the length lets a reader
//! skip a frame it does not understand), which keeps the protocol forward-compatible.
//!
//! Layout: `[ len: u32 LE ][ type: u8 ][ body: len - 1 bytes ]`, where `len` counts the
//! type byte plus the body.

/// The number of bytes in the length prefix.
const LEN_PREFIX: usize = 4;

/// The largest a single frame (type byte plus body) may be: 16 MiB plus 64 KiB of
/// protocol overhead, sized for a max-size record payload plus its frame fields. A frame
/// whose length prefix exceeds this is rejected without allocating.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024 + 64 * 1024;

/// The protocol verb carried by a frame. The one-byte tag is stable across versions; the
/// per-type body layout is defined by the message codecs (later work).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FrameType {
    /// Client opens a session and negotiates capabilities.
    Connect,
    /// Server announces its identity and limits.
    Info,
    /// Keepalive request.
    Ping,
    /// Keepalive response.
    Pong,
    /// Producer publishes a message.
    Pub,
    /// Consumer subscribes to the topic.
    Sub,
    /// Consumer cancels a subscription.
    Unsub,
    /// Consumer acknowledges a message.
    Ack,
    /// Consumer negatively acknowledges a message (retry).
    Nack,
    /// Flow-control credit grant.
    Flow,
    /// Generic, body-less success response. Reserved for an acknowledgement that carries
    /// no payload; never overload it with a typed body. A response that carries data uses
    /// its own self-describing frame ([`FrameType::PubAck`], [`FrameType::AckStatus`],
    /// [`FrameType::FlowEnd`]) so a generic reader is never ambiguous (#179).
    Ok,
    /// Generic error response. Body: a UTF-8 message.
    Err,
    /// Server delivers a message to a consumer.
    Deliver,
    /// Producer publish acknowledgement. Body: the assigned durable `offset` as a
    /// little-endian `u64` (8 bytes).
    PubAck,
    /// Consumer acknowledgement status (the response to an Ack, Nack, Term, or Progress).
    /// Body: a one-byte status (0 = fenced, 1 = committed/requeued/extended, 2 = progress
    /// cap reached).
    AckStatus,
    /// End of a Flow delivery batch. Body: the number of messages delivered in the batch
    /// as a little-endian `u32` (4 bytes).
    FlowEnd,
    /// Server advisory that a message was dead-lettered (poison: it exceeded `MaxDeliver`)
    /// and skipped from delivery, so the consumer learns the offset was dropped rather than
    /// silently never seeing it (#63). Body: the dead-lettered `offset` as a little-endian
    /// `u64` (8 bytes) followed by a one-byte reason (0 = max-deliver exhausted).
    DeadLetter,
    /// Server advisory that the consumer's cursor fell BELOW the oldest retained record because
    /// the disk-full drop-oldest policy force-reaped old segments out from under a slow consumer
    /// (#82, #84), so the consumer learns it lost a span and where delivery resumes rather than
    /// silently skipping records. Emitted exactly once per gap, just before the resumed
    /// deliveries. Body: the new earliest-retained `offset` the cursor was reset to, then the
    /// number of `skipped` records, each a little-endian `u64` (16 bytes total).
    Truncated,
    /// Consumer cumulative ack (ack-all-up-to-offset) for a BROADCAST group (#288, refs #63, #11):
    /// commits the group's single cursor up to an exclusive `up_to` offset, the safe broadcast half
    /// of the `JetStream` `AckAll` verb (a broadcast group is a group-of-one that sees every record
    /// in order, so committing past `up_to` drops nothing). The server hard-rejects it on any
    /// competing or `key_shared` work-group. Body: the exclusive `up_to` offset as a little-endian
    /// `u64` (8 bytes) followed by the work-group name as the remainder of the body (empty selects
    /// the default group).
    CumulativeAck,
    /// Producer dedup-hit acknowledgement (#33): the broker's BENIGN response to a publish whose
    /// `msg_id` was already seen within the producer's dedup window. It carries the ORIGINAL durable
    /// offset the first copy was assigned (so the producer learns where its message landed) and a
    /// `duplicate = true` indication by its frame type ALONE; the broker appends NO second copy and
    /// this is NEVER an error (`rc = 0`). It is the dedup-aware twin of [`FrameType::PubAck`]: the
    /// frozen `PubAck` (tag 14) body is left untouched (exactly the 8-byte offset), and a dedup hit
    /// is signaled by this NEW append-only frame type instead, so an old client that never sends a
    /// `msg_id` never receives it. Body: the original durable `offset` as a little-endian `u64`
    /// (8 bytes), identical in shape to `PubAck`.
    PubAckDuplicate,
    /// Server advisory that a half-open span of offsets `[from, to)` is PERMANENTLY ABSENT from the
    /// DELIVER stream (skipped), so a consumer that tracks contiguity learns the jump is a bounded,
    /// reported gap rather than message loss (#346, #59, #9). Emitted just BEFORE the next delivery
    /// across the gap, exactly once per gap. It is the consumer-visible, per-consumer-OPT-IN twin of
    /// [`FrameType::Truncated`] (tag 18): a consumer that advertised it understands gap markers (via
    /// the `Connect` capability bit, #292) receives this richer marker INSTEAD of `Truncated` (no
    /// double-signal), and an old consumer that never advertised it keeps receiving the legacy
    /// `Truncated` and is never sent this NEW append-only tag. Body: the gap's `from`/`to` (exclusive)
    /// offsets and `bytes_skipped` as little-endian `u64`s, then a one-byte `reason` (trimmed /
    /// compacted), sourced from the already-frozen `loss-report.v1` skip record. The `Deliver` (tag
    /// 13) body is UNCHANGED.
    GapMarker,
}

impl FrameType {
    /// The one-byte wire tag for this frame type.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            FrameType::Connect => 1,
            FrameType::Info => 2,
            FrameType::Ping => 3,
            FrameType::Pong => 4,
            FrameType::Pub => 5,
            FrameType::Sub => 6,
            FrameType::Unsub => 7,
            FrameType::Ack => 8,
            FrameType::Nack => 9,
            FrameType::Flow => 10,
            FrameType::Ok => 11,
            FrameType::Err => 12,
            FrameType::Deliver => 13,
            FrameType::PubAck => 14,
            FrameType::AckStatus => 15,
            FrameType::FlowEnd => 16,
            FrameType::DeadLetter => 17,
            FrameType::Truncated => 18,
            FrameType::CumulativeAck => 19,
            FrameType::PubAckDuplicate => 20,
            FrameType::GapMarker => 21,
        }
    }

    /// Parses a wire tag, returning `None` for an unknown type (which a forward-compatible
    /// reader skips using the frame length rather than failing the connection).
    #[must_use]
    pub fn from_u8(tag: u8) -> Option<FrameType> {
        Some(match tag {
            1 => FrameType::Connect,
            2 => FrameType::Info,
            3 => FrameType::Ping,
            4 => FrameType::Pong,
            5 => FrameType::Pub,
            6 => FrameType::Sub,
            7 => FrameType::Unsub,
            8 => FrameType::Ack,
            9 => FrameType::Nack,
            10 => FrameType::Flow,
            11 => FrameType::Ok,
            12 => FrameType::Err,
            13 => FrameType::Deliver,
            14 => FrameType::PubAck,
            15 => FrameType::AckStatus,
            16 => FrameType::FlowEnd,
            17 => FrameType::DeadLetter,
            18 => FrameType::Truncated,
            19 => FrameType::CumulativeAck,
            20 => FrameType::PubAckDuplicate,
            21 => FrameType::GapMarker,
            _ => return None,
        })
    }
}

/// An error encoding or decoding a frame envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The body would make the frame exceed [`MAX_FRAME_LEN`].
    FrameTooLarge {
        /// The frame length that was attempted or seen.
        len: u64,
    },
    /// The length prefix was zero: a frame must carry at least its type byte.
    EmptyFrame,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::FrameTooLarge { len } => {
                write!(f, "frame length {len} exceeds the {MAX_FRAME_LEN}-byte cap")
            }
            FrameError::EmptyFrame => write!(f, "frame length prefix is zero"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The result of decoding from the front of a byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameDecode<'a> {
    /// A complete frame: its raw type tag, body, and the number of bytes it consumed from
    /// the input.
    Frame {
        /// The raw type tag (use [`FrameType::from_u8`] to interpret it).
        type_tag: u8,
        /// The frame body (type-specific; empty for bodyless frames like `Ping`).
        body: &'a [u8],
        /// The total bytes this frame occupied at the front of the input.
        consumed: usize,
    },
    /// Not enough bytes yet for a complete frame: at least `needed` total bytes are
    /// required at the front of the input before a frame can be decoded.
    Incomplete {
        /// The minimum input length needed to make progress.
        needed: usize,
    },
}

/// Encodes one frame (type tag plus body) onto the end of `out`.
///
/// # Errors
/// Returns [`FrameError::FrameTooLarge`] if the type byte plus body would exceed
/// [`MAX_FRAME_LEN`].
pub fn encode_frame(
    frame_type: FrameType,
    body: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), FrameError> {
    // The frame length is the type byte plus the body; compute in u64 so a huge body on a
    // 64-bit host cannot overflow before the cap check.
    let frame_len = 1u64 + body.len() as u64;
    if frame_len > u64::from(MAX_FRAME_LEN) {
        return Err(FrameError::FrameTooLarge { len: frame_len });
    }
    // `frame_len <= MAX_FRAME_LEN` (a u32), so this conversion always succeeds.
    let Ok(frame_len) = u32::try_from(frame_len) else {
        return Err(FrameError::FrameTooLarge { len: frame_len });
    };
    out.extend_from_slice(&frame_len.to_le_bytes());
    out.push(frame_type.as_u8());
    out.extend_from_slice(body);
    Ok(())
}

/// Decodes one frame from the front of `input`, validating the length against the absolute
/// [`MAX_FRAME_LEN`] cap.
///
/// Returns [`FrameDecode::Incomplete`] when more bytes are needed (a partial stream); the
/// length is checked before it is trusted, so a hostile prefix cannot force a large read.
///
/// # Errors
/// Returns [`FrameError::FrameTooLarge`] if the length prefix exceeds the cap, or
/// [`FrameError::EmptyFrame`] if it is zero.
pub fn decode_frame(input: &[u8]) -> Result<FrameDecode<'_>, FrameError> {
    decode_frame_with_cap(input, MAX_FRAME_LEN)
}

/// Like [`decode_frame`] but rejects a frame longer than `max_len` (a per-connection
/// negotiated maximum). The effective cap is `min(max_len, MAX_FRAME_LEN)`, so a caller can
/// only tighten the absolute cap, never raise it.
///
/// # Errors
/// Returns [`FrameError::FrameTooLarge`] if the length prefix exceeds the effective cap, or
/// [`FrameError::EmptyFrame`] if it is zero.
pub fn decode_frame_with_cap(input: &[u8], max_len: u32) -> Result<FrameDecode<'_>, FrameError> {
    let cap = max_len.min(MAX_FRAME_LEN);
    if input.len() < LEN_PREFIX {
        return Ok(FrameDecode::Incomplete { needed: LEN_PREFIX });
    }
    let mut len_bytes = [0u8; LEN_PREFIX];
    len_bytes.copy_from_slice(&input[..LEN_PREFIX]);
    let frame_len = u32::from_le_bytes(len_bytes);
    if frame_len == 0 {
        return Err(FrameError::EmptyFrame);
    }
    if frame_len > cap {
        return Err(FrameError::FrameTooLarge {
            len: u64::from(frame_len),
        });
    }
    // frame_len <= MAX_FRAME_LEN, so this addition fits in usize on every supported target.
    let needed = LEN_PREFIX + frame_len as usize;
    if input.len() < needed {
        return Ok(FrameDecode::Incomplete { needed });
    }
    let type_tag = input[LEN_PREFIX];
    let body = &input[LEN_PREFIX + 1..needed];
    Ok(FrameDecode::Frame {
        type_tag,
        body,
        consumed: needed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ALL_TYPES: [FrameType; 21] = [
        FrameType::Connect,
        FrameType::Info,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Pub,
        FrameType::Sub,
        FrameType::Unsub,
        FrameType::Ack,
        FrameType::Nack,
        FrameType::Flow,
        FrameType::Ok,
        FrameType::Err,
        FrameType::Deliver,
        FrameType::PubAck,
        FrameType::AckStatus,
        FrameType::FlowEnd,
        FrameType::DeadLetter,
        FrameType::Truncated,
        FrameType::CumulativeAck,
        FrameType::PubAckDuplicate,
        FrameType::GapMarker,
    ];

    #[test]
    fn type_tags_are_a_stable_bijection() {
        let mut seen = std::collections::BTreeSet::new();
        for ty in ALL_TYPES {
            let tag = ty.as_u8();
            assert!(seen.insert(tag), "duplicate tag {tag}");
            assert_eq!(FrameType::from_u8(tag), Some(ty));
        }
        assert_eq!(FrameType::from_u8(0), None);
        assert_eq!(FrameType::from_u8(255), None);
    }

    #[test]
    fn type_tags_have_their_exact_frozen_wire_values() {
        // Pin the on-the-wire numbers so a future reorder or insertion breaks a test here,
        // not a deployed protocol. These values are part of the frozen wire contract.
        assert_eq!(FrameType::Connect.as_u8(), 1);
        assert_eq!(FrameType::Info.as_u8(), 2);
        assert_eq!(FrameType::Ping.as_u8(), 3);
        assert_eq!(FrameType::Pong.as_u8(), 4);
        assert_eq!(FrameType::Pub.as_u8(), 5);
        assert_eq!(FrameType::Sub.as_u8(), 6);
        assert_eq!(FrameType::Unsub.as_u8(), 7);
        assert_eq!(FrameType::Ack.as_u8(), 8);
        assert_eq!(FrameType::Nack.as_u8(), 9);
        assert_eq!(FrameType::Flow.as_u8(), 10);
        assert_eq!(FrameType::Ok.as_u8(), 11);
        assert_eq!(FrameType::Err.as_u8(), 12);
        assert_eq!(FrameType::Deliver.as_u8(), 13);
        assert_eq!(FrameType::PubAck.as_u8(), 14);
        assert_eq!(FrameType::AckStatus.as_u8(), 15);
        assert_eq!(FrameType::FlowEnd.as_u8(), 16);
        assert_eq!(FrameType::DeadLetter.as_u8(), 17);
        assert_eq!(FrameType::Truncated.as_u8(), 18);
        assert_eq!(FrameType::CumulativeAck.as_u8(), 19);
        assert_eq!(FrameType::PubAckDuplicate.as_u8(), 20);
        assert_eq!(FrameType::GapMarker.as_u8(), 21);
    }

    #[test]
    fn round_trips_a_frame() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Pub, b"hello", &mut buf).unwrap();
        match decode_frame(&buf).unwrap() {
            FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            } => {
                assert_eq!(FrameType::from_u8(type_tag), Some(FrameType::Pub));
                assert_eq!(body, b"hello");
                assert_eq!(consumed, buf.len());
            }
            FrameDecode::Incomplete { .. } => panic!("should be complete"),
        }
    }

    #[test]
    fn an_empty_body_frame_round_trips() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Ping, b"", &mut buf).unwrap();
        assert_eq!(buf.len(), LEN_PREFIX + 1);
        match decode_frame(&buf).unwrap() {
            FrameDecode::Frame { type_tag, body, .. } => {
                assert_eq!(FrameType::from_u8(type_tag), Some(FrameType::Ping));
                assert!(body.is_empty());
            }
            FrameDecode::Incomplete { .. } => panic!("complete"),
        }
    }

    #[test]
    fn a_partial_stream_reports_incomplete_with_the_needed_length() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Pub, b"abcdef", &mut buf).unwrap();
        // Fewer than four bytes: need the prefix.
        assert_eq!(
            decode_frame(&buf[..2]).unwrap(),
            FrameDecode::Incomplete { needed: LEN_PREFIX }
        );
        // Prefix present but body short: need the whole frame.
        assert_eq!(
            decode_frame(&buf[..LEN_PREFIX + 2]).unwrap(),
            FrameDecode::Incomplete { needed: buf.len() }
        );
    }

    #[test]
    fn decodes_consecutive_frames_from_one_buffer() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Ping, b"", &mut buf).unwrap();
        encode_frame(FrameType::Pub, b"second", &mut buf).unwrap();
        let first = decode_frame(&buf).unwrap();
        let FrameDecode::Frame { consumed, .. } = first else {
            panic!("first frame incomplete");
        };
        match decode_frame(&buf[consumed..]).unwrap() {
            FrameDecode::Frame { type_tag, body, .. } => {
                assert_eq!(FrameType::from_u8(type_tag), Some(FrameType::Pub));
                assert_eq!(body, b"second");
            }
            FrameDecode::Incomplete { .. } => panic!("second frame should be complete"),
        }
    }

    #[test]
    fn a_zero_length_prefix_is_rejected() {
        let buf = [0u8, 0, 0, 0]; // len = 0
        assert_eq!(decode_frame(&buf), Err(FrameError::EmptyFrame));
    }

    #[test]
    fn an_oversized_length_prefix_is_rejected_without_reading_the_body() {
        // A hostile prefix claiming a huge frame: rejected on the 4-byte prefix alone.
        let mut buf = (MAX_FRAME_LEN + 1).to_le_bytes().to_vec();
        buf.push(FrameType::Pub.as_u8());
        assert_eq!(
            decode_frame(&buf),
            Err(FrameError::FrameTooLarge {
                len: u64::from(MAX_FRAME_LEN) + 1
            })
        );
    }

    #[test]
    fn encode_rejects_an_oversized_body() {
        // A body one byte too large for the cap (the +1 type byte tips it over).
        let body = vec![0u8; MAX_FRAME_LEN as usize];
        let mut out = Vec::new();
        assert_eq!(
            encode_frame(FrameType::Pub, &body, &mut out),
            Err(FrameError::FrameTooLarge {
                len: u64::from(MAX_FRAME_LEN) + 1
            })
        );
        assert!(out.is_empty(), "nothing is written on rejection");
    }

    #[test]
    fn a_frame_at_exactly_the_cap_decodes() {
        // The largest legal frame: total length == MAX_FRAME_LEN (body == cap - 1 type byte).
        let body = vec![0x5a_u8; MAX_FRAME_LEN as usize - 1];
        let mut buf = Vec::new();
        encode_frame(FrameType::Pub, &body, &mut buf).unwrap();
        match decode_frame(&buf).unwrap() {
            FrameDecode::Frame {
                type_tag,
                body: out,
                consumed,
            } => {
                assert_eq!(FrameType::from_u8(type_tag), Some(FrameType::Pub));
                assert_eq!(out.len(), MAX_FRAME_LEN as usize - 1);
                assert_eq!(consumed, buf.len());
            }
            FrameDecode::Incomplete { .. } => panic!("a cap-sized frame should decode"),
        }
    }

    #[test]
    fn trailing_bytes_after_a_frame_are_not_consumed() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Ack, b"id", &mut buf).unwrap();
        let frame_len = buf.len();
        buf.extend_from_slice(b"leftover junk");
        match decode_frame(&buf).unwrap() {
            FrameDecode::Frame { body, consumed, .. } => {
                assert_eq!(body, b"id");
                assert_eq!(
                    consumed, frame_len,
                    "consumes exactly one frame, not the junk"
                );
                assert_eq!(&buf[consumed..], b"leftover junk");
            }
            FrameDecode::Incomplete { .. } => panic!("complete"),
        }
    }

    #[test]
    fn a_negotiated_cap_rejects_a_frame_above_it_but_below_the_absolute_max() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Pub, &vec![0u8; 1000], &mut buf).unwrap();
        // The absolute decoder accepts it; a tighter per-connection cap rejects it.
        assert!(matches!(decode_frame(&buf), Ok(FrameDecode::Frame { .. })));
        assert!(matches!(
            decode_frame_with_cap(&buf, 100),
            Err(FrameError::FrameTooLarge { .. })
        ));
    }

    proptest! {
        #[test]
        fn any_frame_round_trips(tag_index in 0usize..ALL_TYPES.len(), body in prop::collection::vec(any::<u8>(), 0..2048)) {
            let frame_type = ALL_TYPES[tag_index];
            let mut buf = Vec::new();
            encode_frame(frame_type, &body, &mut buf).unwrap();
            match decode_frame(&buf).unwrap() {
                FrameDecode::Frame { type_tag, body: out, consumed } => {
                    prop_assert_eq!(FrameType::from_u8(type_tag), Some(frame_type));
                    prop_assert_eq!(out, body.as_slice());
                    prop_assert_eq!(consumed, buf.len());
                }
                FrameDecode::Incomplete { .. } => prop_assert!(false, "should be complete"),
            }
        }

        /// Decoding any strict prefix of a valid frame reports Incomplete, never a wrong
        /// frame or an error.
        #[test]
        fn a_truncated_frame_is_incomplete(body in prop::collection::vec(any::<u8>(), 0..512), cut in 0usize..600) {
            let mut buf = Vec::new();
            encode_frame(FrameType::Sub, &body, &mut buf).unwrap();
            let cut = cut.min(buf.len().saturating_sub(1));
            let decoded = decode_frame(&buf[..cut]);
            prop_assert!(
                matches!(decoded, Ok(FrameDecode::Incomplete { .. })),
                "a strict prefix should be Incomplete, got {decoded:?}"
            );
        }

        /// An unknown type tag still decodes at the envelope level (forward compatibility):
        /// the body and length are recovered; only `from_u8` reports it unknown.
        #[test]
        fn an_unknown_type_tag_still_frames(tag in 22u8..=255, body in prop::collection::vec(any::<u8>(), 0..256)) {
            let frame_len = 1u32 + u32::try_from(body.len()).unwrap();
            let mut buf = frame_len.to_le_bytes().to_vec();
            buf.push(tag);
            buf.extend_from_slice(&body);
            match decode_frame(&buf).unwrap() {
                FrameDecode::Frame { type_tag, body: out, consumed } => {
                    prop_assert_eq!(type_tag, tag);
                    prop_assert_eq!(FrameType::from_u8(type_tag), None);
                    prop_assert_eq!(out, body.as_slice());
                    prop_assert_eq!(consumed, buf.len());
                }
                FrameDecode::Incomplete { .. } => prop_assert!(false, "should frame"),
            }
        }

        /// Decoding ARBITRARY bytes never panics and never reads out of bounds: the decoder
        /// always returns a typed Ok(Frame)/Ok(Incomplete)/Err, the property-level complement
        /// to the `frame_decode` fuzz target. When it frames, `consumed` stays within the input
        /// and the reported body length matches `consumed`; when it is Incomplete, it asks for
        /// strictly more than the input it was given.
        #[test]
        fn decode_frame_on_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            match decode_frame(&bytes) {
                Ok(FrameDecode::Frame { body, consumed, .. }) => {
                    prop_assert!(consumed <= bytes.len(), "consumed past the input");
                    prop_assert_eq!(consumed, LEN_PREFIX + 1 + body.len());
                }
                Ok(FrameDecode::Incomplete { needed }) => {
                    prop_assert!(needed > bytes.len(), "incomplete must need more than it has");
                }
                Err(_) => {}
            }
        }

        /// A declared length over the cap is rejected as a typed `FrameTooLarge`, never an
        /// allocation blowup: the decoder reads only the 4-byte prefix, so the input here is
        /// just the prefix and (optionally) a tag byte. The cap is `min(max_len, MAX_FRAME_LEN)`,
        /// so any declared length strictly above the effective cap is the error, regardless of
        /// how few body bytes are actually present.
        #[test]
        fn decode_frame_with_cap_rejects_an_over_cap_length(
            declared in 1u32..=u32::MAX,
            max_len in any::<u32>(),
            include_tag in any::<bool>(),
        ) {
            let cap = max_len.min(MAX_FRAME_LEN);
            prop_assume!(declared > cap);
            let mut buf = declared.to_le_bytes().to_vec();
            if include_tag {
                buf.push(0x05);
            }
            prop_assert_eq!(
                decode_frame_with_cap(&buf, max_len),
                Err(FrameError::FrameTooLarge { len: u64::from(declared) }),
                "an over-cap declared length is a typed error, not an allocation"
            );
        }
    }
}
