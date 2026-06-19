// SPDX-License-Identifier: MIT OR Apache-2.0
//! Codecs for the message frame bodies: PUB (a producer's message) and ACK (a consumer's
//! acknowledgement). These are the two bodies the at-least-once produce/consume path
//! rides in; they sit inside the [`crate::frame`] envelope, which owns the length prefix
//! and type tag, so these codecs only frame the body fields.
//!
//! Decoding is bounds-checked and never panics on a malformed body: a short or
//! inconsistent body is a typed [`BodyError`], not a slice out of range. The wire uses
//! little-endian fixed-width fields and explicit `u16` lengths for the variable parts, so
//! a body parses identically on every target. These are wire types: the server maps them
//! to the storage and consumer domain types.

/// An error decoding (or encoding) a message body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// The body ended before a field could be read.
    Truncated,
    /// A length-prefixed field claimed more bytes than the body held.
    BadLength,
    /// A variable field (key or headers) was longer than `u16::MAX`, the wire limit.
    FieldTooLarge,
    /// The acknowledgement op tag was not a known verb.
    BadAckOp {
        /// The unrecognized op byte.
        op: u8,
    },
    /// Trailing bytes remained after a fixed-layout body was fully read.
    TrailingBytes,
    /// A handshake (`Connect`/`Info`) body carried an unknown body-framing version (#292): the
    /// reader cannot interpret a version it does not know, so it is a typed error rather than a
    /// best-effort parse. An EMPTY body is never this error (it is the historical no-fields case).
    BadHandshakeVersion {
        /// The unrecognized handshake body version byte.
        version: u8,
    },
}

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BodyError::Truncated => write!(f, "message body is truncated"),
            BodyError::BadLength => write!(f, "a length field exceeds the body"),
            BodyError::FieldTooLarge => write!(f, "a variable field exceeds the u16 wire limit"),
            BodyError::BadAckOp { op } => write!(f, "unknown ack op {op}"),
            BodyError::TrailingBytes => write!(f, "unexpected trailing bytes in the body"),
            BodyError::BadHandshakeVersion { version } => {
                write!(f, "unknown handshake body version {version}")
            }
        }
    }
}

impl std::error::Error for BodyError {}

/// A bounds-checked, panic-free reader over a body slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], BodyError> {
        let end = self.pos.checked_add(n).ok_or(BodyError::BadLength)?;
        let slice = self.buf.get(self.pos..end).ok_or(BodyError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BodyError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BodyError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, BodyError> {
        let b = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        Ok(u32::from_le_bytes(a))
    }

    fn u64(&mut self) -> Result<u64, BodyError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    /// Reads a `u16`-length-prefixed byte field.
    fn var(&mut self) -> Result<&'a [u8], BodyError> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    fn rest(self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn push_var(out: &mut Vec<u8>, field: &[u8]) -> Result<(), BodyError> {
    let len = u16::try_from(field.len()).map_err(|_| BodyError::FieldTooLarge)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// The PUB-body WIRE flag bit that signals an OPT-IN dedup block (`producer_id` + `epoch` +
/// `msg_id`) follows the headers, before the payload (#33). It is a WIRE-ONLY flag on the PUB
/// body's `flags` byte, NOT a stored record flag: the server masks it OUT before the byte
/// becomes [`ironbus_core::types::RecordFlags`], so it never pollutes the stored record flags
/// and never collides with a future record-flag bit. It sits at bit 7 (`0b1000_0000`), well
/// above `RecordFlags::KNOWN` (`0b111`). A dedup-disabled produce OMITS the block and leaves
/// this bit clear, so the body is byte-for-byte the historical layout (additive, opt-in).
pub const PUB_FLAG_HAS_DEDUP: u8 = 0b1000_0000;

/// The PUB-body WIRE flag bit that marks a publish as FIRE-AND-FORGET (QoS-0, #11, #402): the
/// producer does NOT wait for a `PubAck` and accepts loss by contract, so the broker MAY drop this
/// produce under load (gated by the fire-and-forget token bucket, #336) WITHOUT acking, and when it
/// does NOT shed it appends the record durably as usual but sends NO `PubAck` (the producer fired
/// and forgot). Like [`PUB_FLAG_HAS_DEDUP`] this is a WIRE-ONLY flag on the PUB body's `flags` byte,
/// NOT a stored record flag: the server masks it OUT before the byte becomes
/// [`ironbus_core::types::RecordFlags`], so it never pollutes the stored record flags. It sits at
/// bit 6 (`0b0100_0000`), well above `RecordFlags::KNOWN` (`0b111`) and distinct from the dedup bit
/// (bit 7). The default (at-least-once) produce leaves this bit clear, so the body is byte-for-byte
/// the historical layout and an old client always gets the unchanged `PubAck` path (additive,
/// opt-in). Adds NO new frame tag (the `FrameType` vocabulary is unchanged); only this additive flag.
pub const PUB_FLAG_FIRE_AND_FORGET: u8 = 0b0100_0000;

/// The 2-bit WIRE-ONLY PUB-body field that carries the per-publish produce ACK LEVEL (#494, part of
/// the Cassandra-consistency-style ack spectrum #499). It occupies the two currently-FREE PUB flag
/// bits 3 and 4 (`0b0001_1000`), which sit between the stored record flags (`RecordFlags::KNOWN` =
/// bits 0..=2) and the existing wire-only bits (fire-and-forget bit 6, dedup bit 7), so it collides
/// with neither. The encoded values are:
///
/// - `0` = Level 1 (server ack, today's `PubAck` behavior). A `flags` byte with NEITHER the
///   fire-and-forget bit NOR an ack-level bit set therefore means Level 1, which is EXACTLY how every
///   pre-feature client encodes a default at-least-once publish — so an old client is Level 1 by
///   construction and its body is byte-for-byte unchanged.
/// - `1` (`0b0000_1000`, bit 3) = Level 0 (no-ack, fire-and-forget). This is the level-bit ALIAS for
///   Level 0; the canonical Level-0 encoding remains [`PUB_FLAG_FIRE_AND_FORGET`] (an old faf publish
///   IS a Level-0 publish), and [`pub_ack_level`] reports Level 0 when EITHER the fire-and-forget bit
///   OR this level value is set.
/// - `2` (`0b0001_0000`, bit 4) = Level 2 (server+client ack): the producer confirmation waits for a
///   CONSUMER ack, delivered out-of-band by the new [`crate::frame::FrameType::ProduceConfirm`] frame.
/// - `3` (`0b0001_1000`, both bits) = RESERVED for a future level; it decodes to Level 1 (the safe
///   default) today, never an error, so the field can grow without a wire break.
///
/// Like the other wire-only bits this field is masked OUT of the stored record flags
/// ([`PUB_WIRE_ONLY_FLAGS`]) by the server, so it never becomes record state. PROTO/CODEC ONLY in this
/// phase: the bits are defined and round-trip here, but NO server accept-path, client API, or ack
/// behavior reads them yet (phases #495/#496/#497).
pub const PUB_FLAG_ACK_LEVEL_MASK: u8 = 0b0001_1000;

/// The bit shift from the low edge of the `flags` byte to the [`PUB_FLAG_ACK_LEVEL_MASK`] field, so
/// `(flags & PUB_FLAG_ACK_LEVEL_MASK) >> PUB_FLAG_ACK_LEVEL_SHIFT` yields the raw 0..=3 level value.
pub const PUB_FLAG_ACK_LEVEL_SHIFT: u8 = 3;

/// The MASK of WIRE-ONLY PUB-body flag bits that the server MUST clear before the `flags` byte
/// becomes a stored [`ironbus_core::types::RecordFlags`] (#33, #11, #494): the dedup-block bit, the
/// fire-and-forget bit, and the 2-bit ack-level field. NONE is record state, so none may pollute the
/// stored flags or collide with a future record-flag bit. All sit well above `RecordFlags::KNOWN`
/// (`0b111`), so masking them off leaves the stored record byte-for-byte what a pre-feature publish
/// produced (the conformance byte-identity gate is unaffected).
pub const PUB_WIRE_ONLY_FLAGS: u8 =
    PUB_FLAG_HAS_DEDUP | PUB_FLAG_FIRE_AND_FORGET | PUB_FLAG_ACK_LEVEL_MASK;

/// The per-publish produce ACK LEVEL a [`PubBody`] requests (#494, part of #499): the
/// Cassandra-consistency-style spectrum from no-ack to server+client-ack. Carried on the wire in the
/// [`PUB_FLAG_ACK_LEVEL_MASK`] bits (with [`PUB_FLAG_FIRE_AND_FORGET`] as the canonical Level-0
/// encoding), masked off the stored record. PROTO/CODEC ONLY in this phase: no path acts on it yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AckLevel {
    /// Level 0: no-ack / fire-and-forget. The producer never waits and accepts loss by contract; the
    /// broker MAY drop the publish under load. Generalizes [`PUB_FLAG_FIRE_AND_FORGET`] (an old faf
    /// publish is a Level-0 publish). The fastest path.
    NoAck,
    /// Level 1: server ack. A `PubAck` once the record is accepted into the log at the configured
    /// durability level. This is today's behavior and the DEFAULT, so an old client (which encodes
    /// neither the faf bit nor a level bit) is Level 1.
    #[default]
    ServerAck,
    /// Level 2: server+client ack. The producer's confirmation completes only after a CONSUMER acks
    /// the record, signalled out-of-band by the new [`crate::frame::FrameType::ProduceConfirm`] frame.
    ServerAndClientAck,
}

impl AckLevel {
    /// The raw 0..=2 value this level encodes into the [`PUB_FLAG_ACK_LEVEL_MASK`] bits. (Level 0 is
    /// ALSO representable as [`PUB_FLAG_FIRE_AND_FORGET`] with a clear level field; the encoder writes
    /// the canonical fire-and-forget bit for Level 0 and leaves the level bits clear, see
    /// [`encode_pub`].)
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            AckLevel::NoAck => 0,
            AckLevel::ServerAck => 1,
            AckLevel::ServerAndClientAck => 2,
        }
    }
}

/// Reads the produce ACK LEVEL a PUB `flags` byte requests (#494), folding BOTH the canonical
/// fire-and-forget Level-0 encoding ([`PUB_FLAG_FIRE_AND_FORGET`]) and the 2-bit
/// [`PUB_FLAG_ACK_LEVEL_MASK`] field into a single [`AckLevel`]:
///
/// - the fire-and-forget bit OR a raw level value of `1` => [`AckLevel::NoAck`] (Level 0),
/// - a raw level value of `2` => [`AckLevel::ServerAndClientAck`] (Level 2),
/// - a raw level value of `0` (the old-client default) OR the RESERVED value `3` => the safe default
///   [`AckLevel::ServerAck`] (Level 1).
///
/// So an old client whose `flags` set NEITHER the faf bit nor a level bit is reported as Level 1,
/// preserving today's behavior, and an old fire-and-forget publish is reported as Level 0.
#[must_use]
pub fn pub_ack_level(flags: u8) -> AckLevel {
    if flags & PUB_FLAG_FIRE_AND_FORGET != 0 {
        return AckLevel::NoAck;
    }
    match (flags & PUB_FLAG_ACK_LEVEL_MASK) >> PUB_FLAG_ACK_LEVEL_SHIFT {
        1 => AckLevel::NoAck,
        2 => AckLevel::ServerAndClientAck,
        // Everything else is the safe Level-1 default: value 0 is the old-client / explicit Level-1
        // encoding (a pre-feature publish stays Level 1), and value 3 is RESERVED and decodes to
        // Level 1 rather than erroring, so the field can grow without a wire break. (The mask is 2
        // bits, so the only other value reaching here is 0 or 3.)
        _ => AckLevel::ServerAck,
    }
}

/// The opt-in dedup metadata a producer attaches to a PUB to request effectively-once dedup
/// (#33): a `producer_id` (the dedup identity; empty is the anonymous/session-scoped default),
/// a monotonic `epoch` (the fencing token; a higher epoch fences an older zombie session), and
/// the `msg_id` (the idempotency key the broker deduplicates on, NEVER the body). Present on the
/// wire only when [`PUB_FLAG_HAS_DEDUP`] is set; absent for the default (no-dedup) produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubDedup<'a> {
    /// The stable producer identity for dedup keying and epoch fencing (empty = anonymous,
    /// session-scoped). Each producer has its own bounded dedup window keyed by this.
    pub producer_id: &'a [u8],
    /// The producer's monotonic epoch (the fencing token). A produce whose epoch is below the
    /// broker's known high-water for `producer_id` is fenced; a higher epoch supersedes the old
    /// session's window.
    pub epoch: u64,
    /// The idempotency key the broker deduplicates on (keying is by `msg_id` ONLY, never the
    /// body). Empty is permitted but pointless (it never matches a meaningful prior id).
    pub msg_id: &'a [u8],
}

/// A producer's published message (the PUB frame body).
///
/// Layout: `flags: u8`, `timestamp_ms: u64`, `key: u16-len + bytes`,
/// `headers: u16-len + bytes`, an OPT-IN dedup block (present iff the [`PUB_FLAG_HAS_DEDUP`] bit of
/// `flags` is set: `producer_id: u16-len + bytes`, `epoch: u64`, `msg_id: u16-len + bytes`), then
/// `payload` (the remainder of the body). With the dedup bit clear the layout is byte-for-byte
/// the historical one (#33, additive). The [`PUB_FLAG_FIRE_AND_FORGET`] bit (bit 6) is an additive
/// boolean signal carried in the SAME `flags` byte (no extra block, so it never changes the layout);
/// it marks a QoS-0 publish (#11, #402). The produce ACK LEVEL (#494) likewise rides the 2-bit
/// [`PUB_FLAG_ACK_LEVEL_MASK`] field of the SAME `flags` byte (bits 3..=4); it too adds no block, so
/// the layout is unchanged. The ack level is carried IN `flags` (not a separate struct field, so the
/// `PubBody` shape is unchanged) and read with [`pub_ack_level`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubBody<'a> {
    /// Producer record flags (the codec/server derives storage flags such as `HAS_KEY`). The
    /// wire-only [`PUB_FLAG_HAS_DEDUP`] bit (bit 7) signals the dedup block, the
    /// [`PUB_FLAG_FIRE_AND_FORGET`] bit (bit 6) marks a QoS-0 publish, and the
    /// [`PUB_FLAG_ACK_LEVEL_MASK`] bits (bits 3..=4) carry the produce ack level (#494, read via
    /// [`pub_ack_level`]); ALL are masked off ([`PUB_WIRE_ONLY_FLAGS`]) by the server before this
    /// becomes a stored record flag.
    pub flags: u8,
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The routing or ordering key (empty if none).
    pub key: &'a [u8],
    /// The headers blob (empty if none).
    pub headers: &'a [u8],
    /// The OPT-IN dedup metadata (#33): `Some` iff the producer requested effectively-once dedup
    /// (the [`PUB_FLAG_HAS_DEDUP`] bit). `None` for the default no-dedup produce, so today's
    /// behavior is unchanged.
    pub dedup: Option<PubDedup<'a>>,
    /// Whether this publish is FIRE-AND-FORGET (QoS-0, #11, #402): `true` sets the
    /// [`PUB_FLAG_FIRE_AND_FORGET`] wire bit, so the broker may drop the produce under load WITHOUT
    /// acking and otherwise appends it durably but sends NO `PubAck`. `false` (the default) is the
    /// historical at-least-once path with the unchanged `PubAck`, so an old client is byte-for-byte
    /// unchanged. The bit is derived from THIS field by the encoder, not from `flags`.
    pub fire_and_forget: bool,
    /// The message payload.
    pub payload: &'a [u8],
}

/// Encodes a PUB body onto the end of `out`. When `msg.dedup` is `Some`, the
/// [`PUB_FLAG_HAS_DEDUP`] bit is forced set in the written flags byte and the dedup block is
/// emitted after the headers; when `None`, the bit is forced clear, so the encoded body cannot
/// claim a dedup block it does not carry (or omit one it does). The [`PUB_FLAG_FIRE_AND_FORGET`]
/// bit is set iff `msg.fire_and_forget` (the QoS-0 marker, #11), derived from the field so it and
/// the caller's intent can never disagree. The 2-bit [`PUB_FLAG_ACK_LEVEL_MASK`] ack-level field
/// (#494) is carried IN `msg.flags` and PRESERVED here (set it with the level bits, or use the
/// canonical [`PUB_FLAG_FIRE_AND_FORGET`] bit for Level 0); only the dedup and fire-and-forget bits
/// are re-derived from the fields. The default produce (no faf, no ack-level bit) is therefore
/// byte-for-byte the historical layout and decodes as Level 1 via [`pub_ack_level`].
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the key, headers, `producer_id`, or `msg_id` exceed
/// `u16::MAX`.
pub fn encode_pub(msg: &PubBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    // Derive the on-wire dedup and fire-and-forget bits from the fields, not from the caller's flags,
    // so those bits and the body/intent can never disagree. The ack-level field (#494) is the
    // EXCEPTION: it has no dedicated `PubBody` field, so it is carried IN `flags` and must be
    // PRESERVED. Clear ONLY the two field-derived bits (dedup, faf), keeping the caller's ack-level
    // bits, then OR in exactly what the dedup/faf fields say.
    let mut flags = msg.flags & !(PUB_FLAG_HAS_DEDUP | PUB_FLAG_FIRE_AND_FORGET);
    if msg.dedup.is_some() {
        flags |= PUB_FLAG_HAS_DEDUP;
    }
    if msg.fire_and_forget {
        flags |= PUB_FLAG_FIRE_AND_FORGET;
    }
    out.push(flags);
    out.extend_from_slice(&msg.timestamp_ms.to_le_bytes());
    push_var(out, msg.key)?;
    push_var(out, msg.headers)?;
    if let Some(dedup) = msg.dedup {
        push_var(out, dedup.producer_id)?;
        out.extend_from_slice(&dedup.epoch.to_le_bytes());
        push_var(out, dedup.msg_id)?;
    }
    out.extend_from_slice(msg.payload);
    Ok(())
}

/// Decodes a PUB body. The payload is whatever remains after the framed fields (and the opt-in
/// dedup block), so `body` MUST be exactly one frame's body (as handed out by
/// [`crate::frame::decode_frame`]): any trailing bytes would be folded into the payload.
///
/// # Errors
/// Returns a [`BodyError`] on a short or inconsistent body (including a dedup block that the
/// [`PUB_FLAG_HAS_DEDUP`] bit claims but the body is too short to hold).
pub fn decode_pub(body: &[u8]) -> Result<PubBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let flags = r.u8()?;
    let timestamp_ms = r.u64()?;
    let key = r.var()?;
    let headers = r.var()?;
    // The opt-in dedup block follows the headers ONLY when the wire bit is set; otherwise the
    // remainder is the payload exactly as before (the historical layout).
    let dedup = if flags & PUB_FLAG_HAS_DEDUP != 0 {
        let producer_id = r.var()?;
        let epoch = r.u64()?;
        let msg_id = r.var()?;
        Some(PubDedup {
            producer_id,
            epoch,
            msg_id,
        })
    } else {
        None
    };
    // The fire-and-forget (QoS-0) marker is a boolean read directly off the SAME flags byte (#11):
    // it adds no block, so it never changes the layout or the payload boundary. The produce ACK LEVEL
    // (#494) likewise rides this flags byte and is read on demand with `pub_ack_level(flags)`; it adds
    // no field here so the `PubBody` shape (and every caller) is unchanged.
    let fire_and_forget = flags & PUB_FLAG_FIRE_AND_FORGET != 0;
    let payload = r.rest();
    Ok(PubBody {
        flags,
        timestamp_ms,
        key,
        headers,
        dedup,
        fire_and_forget,
        payload,
    })
}

/// A consumer acknowledgement op (the wire verb).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOp {
    /// Done; commit the message.
    Ack,
    /// Failed; retry (optionally after `delay_ms`).
    Nack,
    /// Stop redelivering without dead-lettering.
    Term,
    /// Extend the lease (work in progress).
    Progress,
}

impl AckOp {
    /// The one-byte wire tag.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            AckOp::Ack => 0,
            AckOp::Nack => 1,
            AckOp::Term => 2,
            AckOp::Progress => 3,
        }
    }

    /// Parses a wire tag.
    fn from_u8(op: u8) -> Result<AckOp, BodyError> {
        Ok(match op {
            0 => AckOp::Ack,
            1 => AckOp::Nack,
            2 => AckOp::Term,
            3 => AckOp::Progress,
            other => return Err(BodyError::BadAckOp { op: other }),
        })
    }
}

/// A consumer acknowledgement (the ACK frame body).
///
/// Layout: `op: u8`, `offset: u64`, `generation: u64`, `delay_ms: u64`. The offset names
/// the message; the generation is the lease fencing token; `delay_ms` is meaningful only
/// for [`AckOp::Nack`] (zero otherwise).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckBody {
    /// The acknowledgement op.
    pub op: AckOp,
    /// The log offset of the message being acknowledged.
    pub offset: u64,
    /// The lease generation the message was delivered under (the fencing token).
    pub generation: u64,
    /// For a nack, the redelivery delay in milliseconds, where `u64::MAX` is the sentinel for
    /// "no explicit delay" (the broker then applies its backoff schedule for the attempt) and
    /// any other value is an explicit delay (0 = redeliver immediately). Zero for non-nack ops.
    pub delay_ms: u64,
}

/// Encodes an ACK body onto the end of `out`.
pub fn encode_ack(ack: &AckBody, out: &mut Vec<u8>) {
    out.push(ack.op.as_u8());
    out.extend_from_slice(&ack.offset.to_le_bytes());
    out.extend_from_slice(&ack.generation.to_le_bytes());
    out.extend_from_slice(&ack.delay_ms.to_le_bytes());
}

/// Decodes an ACK body (a fixed 25-byte layout; trailing bytes are rejected).
///
/// # Errors
/// Returns a [`BodyError`] on a short body, an unknown op, or trailing bytes.
pub fn decode_ack(body: &[u8]) -> Result<AckBody, BodyError> {
    let mut r = Reader::new(body);
    let op = AckOp::from_u8(r.u8()?)?;
    let offset = r.u64()?;
    let generation = r.u64()?;
    let delay_ms = r.u64()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok(AckBody {
        op,
        offset,
        generation,
        delay_ms,
    })
}

/// A message delivered to a consumer (the DELIVER frame body): the message plus the
/// `offset` that names it and the lease `generation` (fencing token) to ack it with.
///
/// Layout: `offset: u64`, `generation: u64`, then a `PubBody`-shaped tail (`flags: u8`,
/// `timestamp_ms: u64`, `key` and `headers` as u16-length fields, then the payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliverBody<'a> {
    /// The log offset of the delivered message.
    pub offset: u64,
    /// The lease generation to carry on the ack (the fencing token).
    pub generation: u64,
    /// Record flags as stored.
    pub flags: u8,
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The routing or ordering key (empty if none).
    pub key: &'a [u8],
    /// The headers blob (empty if none).
    pub headers: &'a [u8],
    /// The message payload.
    pub payload: &'a [u8],
}

/// Encodes a DELIVER body onto the end of `out`.
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the key or headers exceed `u16::MAX`.
pub fn encode_deliver(msg: &DeliverBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    out.extend_from_slice(&msg.offset.to_le_bytes());
    out.extend_from_slice(&msg.generation.to_le_bytes());
    out.push(msg.flags);
    out.extend_from_slice(&msg.timestamp_ms.to_le_bytes());
    push_var(out, msg.key)?;
    push_var(out, msg.headers)?;
    out.extend_from_slice(msg.payload);
    Ok(())
}

/// Decodes a DELIVER body. The payload is whatever remains after the framed fields, so
/// `body` MUST be exactly one frame's body.
///
/// # Errors
/// Returns a [`BodyError`] on a short or inconsistent body.
pub fn decode_deliver(body: &[u8]) -> Result<DeliverBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let offset = r.u64()?;
    let generation = r.u64()?;
    let flags = r.u8()?;
    let timestamp_ms = r.u64()?;
    let key = r.var()?;
    let headers = r.var()?;
    let payload = r.rest();
    Ok(DeliverBody {
        offset,
        generation,
        flags,
        timestamp_ms,
        key,
        headers,
        payload,
    })
}

/// A consumer's subscription request (the SUB frame body): the work-group name the consumer
/// joins for subsequent FLOW fetches and ACKs. The entire body is the name; an empty name
/// selects the default group (the same one an unsubscribed consumer reads). The server
/// validates the name's shape and bounds (graphic ASCII, length, group cap) when the group is
/// first used, per #240; this codec only carries the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubBody<'a> {
    /// The work-group name the consumer subscribes to (empty selects the default group).
    pub group: &'a [u8],
}

/// Encodes a SUB body onto the end of `out`: the whole body is the work-group name.
pub fn encode_sub(sub: &SubBody<'_>, out: &mut Vec<u8>) {
    out.extend_from_slice(sub.group);
}

/// Decodes a SUB body: the entire body is the work-group name. Infallible (any byte string is
/// a syntactically valid frame body); the server validates the name when the group is used.
#[must_use]
pub fn decode_sub(body: &[u8]) -> SubBody<'_> {
    SubBody { group: body }
}

/// A consumer cumulative ack (the `CumulativeAck` frame body, #288): ack-all-up-to-offset for a
/// BROADCAST group. The broadcast half of the `JetStream` `AckAll` verb (refs #63): a broadcast
/// group is a group-of-one that sees every record in order, so committing its single cursor up to
/// an exclusive `up_to` offset is well-defined and drops nothing. The server validates `up_to`
/// against the durable head and the earliest-retained offset, is idempotent on a re-ack, and
/// HARD-REJECTS the verb on any competing or `key_shared` work-group.
///
/// Layout: `up_to: u64` (the exclusive commit offset, little-endian), then `group` (the
/// work-group name as the remainder of the body, exactly like [`SubBody`]; empty selects the
/// default group). The fixed `u64` leads so the variable-length name is the tail, mirroring the
/// whole-body-is-the-name shape of `SubBody`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CumulativeAckBody<'a> {
    /// The exclusive offset to commit the broadcast cursor up to (every offset strictly below it
    /// is acked).
    pub up_to: u64,
    /// The work-group name (empty selects the default group). Validated server-side.
    pub group: &'a [u8],
}

/// Encodes a `CumulativeAck` body onto the end of `out`: the 8-byte LE `up_to` offset, then the
/// group name as the remainder.
pub fn encode_cumulative_ack(ack: &CumulativeAckBody<'_>, out: &mut Vec<u8>) {
    out.extend_from_slice(&ack.up_to.to_le_bytes());
    out.extend_from_slice(ack.group);
}

/// Decodes a `CumulativeAck` body: the leading 8-byte LE `up_to` offset, then the remainder is the
/// group name. The body MUST be exactly one frame's body (any trailing bytes are the group name).
///
/// # Errors
/// Returns [`BodyError::Truncated`] if the body is shorter than the 8-byte `up_to` field.
pub fn decode_cumulative_ack(body: &[u8]) -> Result<CumulativeAckBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let up_to = r.u64()?;
    let group = r.rest();
    Ok(CumulativeAckBody { up_to, group })
}

/// A producer publish acknowledgement carrying the assigned durable offset: the body of BOTH
/// [`crate::frame::FrameType::PubAck`] (a fresh produce) and [`crate::frame::FrameType::PubAckDuplicate`]
/// (a dedup hit returning the ORIGINAL offset, #33). The body is a fixed 8-byte little-endian
/// `u64` offset for both; the FRAME TYPE alone distinguishes a fresh ack (tag 14) from a benign
/// dedup hit (tag 20, `duplicate = true`), which is why the frozen `PubAck` body is left exactly
/// as it was. Held as a shared codec so both frame types agree on the byte layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubAckBody {
    /// The assigned (fresh) or original (dedup hit) durable log offset.
    pub offset: u64,
}

/// Encodes a publish-ack body (the 8-byte LE offset) onto the end of `out`. Used for both the
/// fresh `PubAck` (tag 14) and the dedup-hit `PubAckDuplicate` (tag 20), which share this body.
pub fn encode_pub_ack(ack: &PubAckBody, out: &mut Vec<u8>) {
    out.extend_from_slice(&ack.offset.to_le_bytes());
}

/// Decodes a publish-ack body (a fixed 8-byte LE offset; trailing bytes are rejected). The caller
/// reads the FRAME TYPE to know whether this is a fresh `PubAck` or a `PubAckDuplicate` dedup hit.
///
/// # Errors
/// Returns a [`BodyError`] on a short or overlong body.
pub fn decode_pub_ack(body: &[u8]) -> Result<PubAckBody, BodyError> {
    let mut r = Reader::new(body);
    let offset = r.u64()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok(PubAckBody { offset })
}

/// The dead-letter reason for a message that exceeded `MaxDeliver` (poison). Only this reason
/// is emitted today; the one-byte reason field leaves room for future causes (#63).
pub const DEAD_LETTER_MAX_DELIVER: u8 = 0;

/// A dead-letter advisory (the `DEAD_LETTER` frame body): the broker tells a fetching consumer
/// that a message was dropped from delivery because it exceeded `MaxDeliver` (poison), so the
/// consumer learns the offset was skipped rather than silently never seeing it (#63). The DLQ
/// topic write is separate; this is only the in-band notification.
///
/// Layout: `offset: u64`, then a one-byte `reason` ([`DEAD_LETTER_MAX_DELIVER`] today).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadLetterBody {
    /// The log offset of the dead-lettered message.
    pub offset: u64,
    /// Why the message was dead-lettered (0 = exceeded `MaxDeliver`; other values reserved).
    pub reason: u8,
}

/// Encodes a `DEAD_LETTER` body onto the end of `out` (a fixed 9-byte layout).
pub fn encode_dead_letter(advisory: &DeadLetterBody, out: &mut Vec<u8>) {
    out.extend_from_slice(&advisory.offset.to_le_bytes());
    out.push(advisory.reason);
}

/// Decodes a `DEAD_LETTER` body (a fixed 9-byte layout; trailing bytes are rejected).
///
/// # Errors
/// Returns a [`BodyError`] on a short body or trailing bytes.
pub fn decode_dead_letter(body: &[u8]) -> Result<DeadLetterBody, BodyError> {
    let mut r = Reader::new(body);
    let offset = r.u64()?;
    let reason = r.u8()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok(DeadLetterBody { offset, reason })
}

/// A truncation advisory (the `TRUNCATED` frame body): the broker tells a consumer that its
/// cursor fell BELOW the oldest retained record because the disk-full drop-oldest policy
/// force-reaped old segments out from under it (#82, #84), so the consumer learns it lost a
/// span and where delivery resumes rather than silently skipping records. The advisory is
/// emitted exactly once per gap, just before the resumed deliveries; the consumer's cursor is
/// reset to `earliest_retained` server-side, so its next ack offsets line up with what follows.
///
/// Layout: `earliest_retained: u64`, then `skipped: u64` (a fixed 16-byte layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TruncatedBody {
    /// The new earliest-retained log offset the consumer's cursor was reset to (delivery
    /// resumes at the oldest record still present).
    pub earliest_retained: u64,
    /// How many records the consumer skipped: the size of the gap between where its cursor was
    /// and `earliest_retained` (`earliest_retained - old_cursor`).
    pub skipped: u64,
}

/// Encodes a `TRUNCATED` body onto the end of `out` (a fixed 16-byte layout).
pub fn encode_truncated(advisory: &TruncatedBody, out: &mut Vec<u8>) {
    out.extend_from_slice(&advisory.earliest_retained.to_le_bytes());
    out.extend_from_slice(&advisory.skipped.to_le_bytes());
}

/// Decodes a `TRUNCATED` body (a fixed 16-byte layout; a short or overlong body is rejected).
///
/// # Errors
/// Returns a [`BodyError`] on a short body or trailing bytes.
pub fn decode_truncated(body: &[u8]) -> Result<TruncatedBody, BodyError> {
    let mut r = Reader::new(body);
    let earliest_retained = r.u64()?;
    let skipped = r.u64()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok(TruncatedBody {
        earliest_retained,
        skipped,
    })
}

/// The reason a span of offsets is permanently absent from the DELIVER stream, carried in the
/// one-byte `reason` field of a [`GapMarkerBody`] (#346). The values are append-only and map onto
/// the recovery-side cause: a retention/trim reap, or a future key-compaction skip (#337). An
/// unknown value a future server might send is tolerated by the client as "absent for an
/// unspecified reason" rather than rejected, so the reason field can grow without a new frame.
pub mod gap_reason {
    /// The span fell below the trim/retention horizon: the disk-full drop-oldest policy (or a
    /// retention reap) removed a contiguous prefix out from under a slow consumer, so its cursor
    /// resumed above the hole (#82, #84). This is the cause the legacy `Truncated` frame (tag 18)
    /// signals; a gap-marker-capable consumer receives this richer marker instead.
    pub const TRIMMED: u8 = 1;
    /// The span was removed by key-compaction: a later record for the same key superseded the
    /// offsets in the hole, so they are permanently absent mid-stream (#337). Reserved for the
    /// compaction work; no path emits it yet, but the wire reason is pinned so compaction is purely
    /// additive when it lands.
    pub const COMPACTED: u8 = 2;
}

/// A consumer-visible gap marker (the `GapMarker` frame body, #346, refs #59, #9): the broker tells
/// a consumer that the half-open offset span `[from, to)` is PERMANENTLY ABSENT (skipped) from the
/// DELIVER stream, so a consumer tracking contiguity learns the jump is a bounded, reported gap
/// rather than message loss. It is the OPT-IN, richer twin of [`TruncatedBody`]: a consumer that
/// advertised gap-marker support (the #292 `Connect` capability bit) receives this INSTEAD of a
/// `Truncated` advisory, so the two never double-signal the same gap; an old consumer keeps the
/// legacy `Truncated`. The `bytes_skipped` and `reason` are sourced from the already-frozen
/// `loss-report.v1` skip record (`0` bytes when the cause is byte-untracked, e.g. a plain trim).
///
/// Layout: `from: u64`, `to: u64`, `bytes_skipped: u64`, then a one-byte `reason` (a fixed 25-byte
/// layout; see [`gap_reason`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GapMarkerBody {
    /// The first absent offset (inclusive): the last offset the consumer saw plus one, i.e. where
    /// the hole begins.
    pub from: u64,
    /// The first present offset after the hole (exclusive): delivery resumes here, and this is the
    /// offset of the record the marker immediately precedes.
    pub to: u64,
    /// The reported bytes lost in the hole, from the `loss-report.v1` skip record; `0` when the
    /// cause is byte-untracked (a plain retention/trim reap reports the record-count span via
    /// `to - from`, not a byte total).
    pub bytes_skipped: u64,
    /// Why the span is absent (a [`gap_reason`] value: trimmed / compacted). An unknown value is
    /// tolerated by a reader as "absent for an unspecified reason", never an error.
    pub reason: u8,
}

/// Encodes a `GapMarker` body onto the end of `out` (a fixed 25-byte layout).
pub fn encode_gap_marker(marker: &GapMarkerBody, out: &mut Vec<u8>) {
    out.extend_from_slice(&marker.from.to_le_bytes());
    out.extend_from_slice(&marker.to.to_le_bytes());
    out.extend_from_slice(&marker.bytes_skipped.to_le_bytes());
    out.push(marker.reason);
}

/// Decodes a `GapMarker` body (a fixed 25-byte layout; a short or overlong body is rejected). The
/// `reason` byte is NOT validated here (an unknown reason is a valid, tolerated marker, decoded
/// verbatim), only the length is, so the codec stays cap-before-alloc and panic-free.
///
/// # Errors
/// Returns a [`BodyError`] on a short body or trailing bytes.
pub fn decode_gap_marker(body: &[u8]) -> Result<GapMarkerBody, BodyError> {
    let mut r = Reader::new(body);
    let from = r.u64()?;
    let to = r.u64()?;
    let bytes_skipped = r.u64()?;
    let reason = r.u8()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok(GapMarkerBody {
        from,
        to,
        bytes_skipped,
        reason,
    })
}

/// The terminal status of an ack-level-2 produce, carried in the one-byte `status` field of a
/// [`ProduceConfirmBody`] (#494): the producer's confirmation completes when the broker reports one of
/// these. The values are append-only; an unknown value a FUTURE server might send is tolerated by the
/// codec (decoded verbatim, never an error), so the status field can grow without a new frame.
pub mod produce_confirm_status {
    /// The record was CONSUMED: a consumer acked it, so the Level-2 produce is confirmed (the success
    /// terminal, the analogue of a `JetStream` consumer ack flowing back to the producer).
    pub const CONSUMED: u8 = 0;
    /// The Level-2 confirmation TIMED OUT: no consumer acked the record within the broker's confirm
    /// window, so the producer is told the confirmation will never arrive (a non-success terminal).
    pub const TIMED_OUT: u8 = 1;
    /// The record was DEAD-LETTERED (poison / force-reaped) before any consumer acked it, so the
    /// Level-2 confirmation can never be satisfied (a non-success terminal).
    pub const DEAD_LETTERED: u8 = 2;
}

/// A server->producer Level-2 produce confirmation (the `ProduceConfirm` frame body, #494, part of
/// #499): the broker tells a producer that an ack-level-2 (server+client-ack) publish has reached its
/// terminal outcome — a consumer acked it, the confirm window timed out, or it was dead-lettered. It
/// keys the confirmation by the record's durable `offset` (the same offset the matching `PubAck`
/// returned) so the producer can match it to the publish it is awaiting.
///
/// Layout: `offset: u64` (the record's durable offset, little-endian), then a one-byte `status` (a
/// [`produce_confirm_status`] value; a fixed 9-byte layout). PROTO/CODEC ONLY in this phase: the codec
/// is defined and round-trips here, but NO path emits or consumes the frame yet (the server emit path
/// is phase #497, the client wait path is phase #496).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProduceConfirmBody {
    /// The durable log offset of the record the Level-2 produce was confirmed (or failed) for, matching
    /// the offset the publish's `PubAck` returned.
    pub offset: u64,
    /// The terminal status of the Level-2 confirmation (a [`produce_confirm_status`] value: consumed /
    /// timed-out / dead-lettered). An unknown future value is tolerated by the reader, never an error.
    pub status: u8,
}

/// Encodes a `ProduceConfirm` body onto the end of `out` (a fixed 9-byte layout): the 8-byte LE offset
/// then the one-byte status.
pub fn encode_produce_confirm(confirm: &ProduceConfirmBody, out: &mut Vec<u8>) {
    out.extend_from_slice(&confirm.offset.to_le_bytes());
    out.push(confirm.status);
}

/// Decodes a `ProduceConfirm` body (a fixed 9-byte layout; a short or overlong body is rejected). The
/// `status` byte is NOT validated here (an unknown future status is a valid, tolerated confirmation,
/// decoded verbatim), only the length is, so the codec stays cap-before-alloc and panic-free.
///
/// # Errors
/// Returns a [`BodyError`] on a short body or trailing bytes.
pub fn decode_produce_confirm(body: &[u8]) -> Result<ProduceConfirmBody, BodyError> {
    let mut r = Reader::new(body);
    let offset = r.u64()?;
    let status = r.u8()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok(ProduceConfirmBody { offset, status })
}

/// The version of the `Connect`/`Info` handshake body framing (#292, refs #275, #65, #11). The
/// handshake bodies were EMPTY before this; version `1` is the first non-empty layout. It is the
/// handshake-BODY version, distinct from the (still un-wired) `wire_protocol_version` integer #71/#11
/// will carry as a FIELD inside this same body. An empty body (length 0) is the historical case and
/// stays valid: it decodes to "no advertised/requested values" (see [`decode_connect`] /
/// [`decode_info`]), so an old peer that sends an empty body still negotiates correctly.
pub const HANDSHAKE_BODY_VERSION: u8 = 1;

/// The `Connect` presence-flag bit signalling that a `requested_credit` (the per-consumer message
/// credit the client wants) is present and meaningful. When clear, the client requests NO specific
/// message credit and the server applies its own default (#292). There is no `request(MAX)`/unbounded
/// value: a client either names a finite `u32` it wants (clamped to the server cap) or names nothing.
pub const CONNECT_FLAG_HAS_CREDIT: u8 = 0b0000_0001;

/// The `Connect` presence-flag bit signalling that a `requested_credit_bytes` (the per-consumer byte
/// budget the client wants) is present and meaningful. When clear, the client requests NO specific
/// byte budget and the server applies its own default (#292).
pub const CONNECT_FLAG_HAS_CREDIT_BYTES: u8 = 0b0000_0010;

/// The `Connect` CAPABILITY bit (#346) by which a consumer advertises that it UNDERSTANDS the
/// consumer-visible `GapMarker` frame (tag 21): when set, the server may send a [`GapMarkerBody`] in
/// place of the legacy `Truncated` advisory across a skipped span; when clear (an old client, or one
/// that opts out) the server keeps sending `Truncated` and NEVER sends the new `GapMarker` tag, so an
/// old consumer that would error on an unknown frame is not broken. It is a pure capability flag (no
/// associated value), so it occupies no slot in the v1 field block beyond this `flags` bit.
pub const CONNECT_FLAG_WANTS_GAP_MARKER: u8 = 0b0000_0100;

/// The `Connect` presence-flag bit signalling that a `default_ack_level` (the connection-wide default
/// produce ack level a client adopts when a publish does not name its own, #494) is present and
/// meaningful. When clear (an old client, or one that defers) the client requests NO default and the
/// server applies its own. The level VALUE is an appended v1-block byte (see [`ConnectBody`]); this
/// presence bit governs only whether that byte is meaningful, so the field is forward+backward
/// compatible (an old body omits the byte and leaves this bit clear).
pub const CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL: u8 = 0b0000_1000;

/// The `Info` presence-flag bit signalling that the server's advertised per-consumer message-credit
/// fields (`negotiated` + `cap`) are present (#292). A server that does not advertise leaves it clear,
/// and a client then keeps its own local credit (backward-compat).
pub const INFO_FLAG_HAS_CREDIT: u8 = 0b0000_0001;

/// The `Info` presence-flag bit signalling that the server's advertised per-consumer byte-budget
/// fields (`negotiated` + `cap`) are present (#292).
pub const INFO_FLAG_HAS_CREDIT_BYTES: u8 = 0b0000_0010;

/// The `Info` CAPABILITY bit (#346) by which the server CONFIRMS it will emit consumer-visible
/// `GapMarker` frames for this connection (the consumer requested it via [`CONNECT_FLAG_WANTS_GAP_MARKER`]
/// AND the server supports it). When clear (an old server, or one with the marker disabled) the
/// client knows it will still see the legacy `Truncated` advisory and keeps handling it. The
/// negotiation is AND: the marker is active only when both peers set their bit, so either side opting
/// out falls back to the legacy advisory.
pub const INFO_FLAG_GAP_MARKER: u8 = 0b0000_0100;

/// The `Info` presence-flag bit by which the server ECHOES the connection-wide `default_ack_level` it
/// adopted for this connection (#494), the server->client twin of [`CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL`].
/// When clear (an old server, or one that does not echo) the client keeps whatever default it asked
/// for. The level VALUE is an appended v1-block byte (see [`InfoBody`]); this presence bit governs
/// only whether it is meaningful, so the field is forward+backward compatible.
pub const INFO_FLAG_HAS_DEFAULT_ACK_LEVEL: u8 = 0b0000_1000;

/// A client's handshake request (the `Connect` frame body, #292). The client MAY request a
/// per-consumer message credit and/or byte budget; the server clamps each to its own cap and replies
/// the negotiated value in [`InfoBody`]. A field is REQUESTED only when its presence bit is set in
/// `flags`; an absent field means "use the server default" (there is no unbounded/`MAX` request on the
/// wire). An EMPTY `Connect` body (an old client) decodes to all-absent, so the server uses its
/// defaults: backward-compatible by construction.
///
/// Layout (version-prefixed, length-prefixed, forward-compatible): `body_version: u8`
/// ([`HANDSHAKE_BODY_VERSION`]), `field_len: u16` (the length of the v1 known-field block that
/// follows), then the v1 block: `flags: u8`, `requested_credit: u32 LE`, `requested_credit_bytes:
/// u64 LE`, and then — ONLY when [`CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL`] is set — an APPENDED
/// `default_ack_level: u8` (#494). The ack-level byte is OMITTED (and `field_len` is the historical
/// length) when the field is absent, so a request without it is byte-for-byte the pre-#494 body. Any
/// bytes past `field_len` (a FUTURE version's appended fields, e.g. the #71 `wire_protocol_version`)
/// are TOLERATED and ignored by a v1 reader. An empty body is the all-absent default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectBody {
    /// The per-consumer message credit the client requests, or `None` to defer to the server default.
    /// `Some(n)` asks for at most `n` un-acked messages; the server delivers `min(n, server cap)`.
    pub requested_credit: Option<u32>,
    /// The per-consumer byte budget the client requests, or `None` to defer to the server default.
    /// `Some(b)` asks for at most `b` un-acked payload bytes; the server clamps it to its cap.
    pub requested_credit_bytes: Option<u64>,
    /// Whether this consumer UNDERSTANDS the `GapMarker` frame (tag 21) and wants it in place of the
    /// legacy `Truncated` advisory across a skipped span (#346). `false` (the default, and an old
    /// client) means the server keeps sending `Truncated` and never sends the new tag.
    pub wants_gap_marker: bool,
    /// The connection-wide DEFAULT produce ack level the client requests (#494, part of #499): the raw
    /// 0/1/2 value (matching [`AckLevel::as_u8`]; `3` is reserved) a publish adopts when it does not
    /// name its own. `None` (an old client, or one that defers) means the server applies its own
    /// default. APPENDED v1 field: it is emitted only when `Some`, so a `None` request is byte-for-byte
    /// the pre-#494 body and an old client (which never sets the presence bit) decodes to `None`. The
    /// value is carried raw as a `u8` so a future level the proto does not yet name still round-trips.
    pub default_ack_level: Option<u8>,
}

/// The number of bytes in the `Connect` v1 known-field block WITHOUT the appended `default_ack_level`
/// byte (#494): `flags: u8` + `requested_credit: u32` + `requested_credit_bytes: u64`. This is the
/// historical, pre-#494 block length, emitted whenever `default_ack_level` is `None` so the body is
/// byte-for-byte the old one.
const CONNECT_V1_FIELD_LEN: u16 = 1 + 4 + 8;

/// The `Connect` v1 block length WITH the appended `default_ack_level` byte (#494): the historical
/// block plus one byte, emitted only when the field is present.
const CONNECT_V1_FIELD_LEN_WITH_ACK_LEVEL: u16 = CONNECT_V1_FIELD_LEN + 1;

/// Encodes a `Connect` body onto the end of `out` (#292, #494). The result is the version byte, the v1
/// field-block length, then the v1 block; an all-`None` request still encodes a well-formed
/// (non-empty) v1 body whose presence flags are clear, which the server reads as "use my defaults".
/// The `default_ack_level` byte (#494) is APPENDED to the block ONLY when present, and `field_len`
/// grows by exactly that byte; when absent the body is byte-for-byte the pre-#494 layout. To emit the
/// historical EMPTY `Connect` body (the old-client case) the caller simply sends an empty body and
/// does NOT call this; [`decode_connect`] accepts both.
pub fn encode_connect(req: &ConnectBody, out: &mut Vec<u8>) {
    out.push(HANDSHAKE_BODY_VERSION);
    // The block length depends ONLY on whether the appended ack-level byte is present, so a request
    // without it encodes the historical length and bytes (byte-identity, #494).
    let field_len = if req.default_ack_level.is_some() {
        CONNECT_V1_FIELD_LEN_WITH_ACK_LEVEL
    } else {
        CONNECT_V1_FIELD_LEN
    };
    out.extend_from_slice(&field_len.to_le_bytes());
    let mut flags = 0u8;
    if req.requested_credit.is_some() {
        flags |= CONNECT_FLAG_HAS_CREDIT;
    }
    if req.requested_credit_bytes.is_some() {
        flags |= CONNECT_FLAG_HAS_CREDIT_BYTES;
    }
    if req.wants_gap_marker {
        flags |= CONNECT_FLAG_WANTS_GAP_MARKER;
    }
    if req.default_ack_level.is_some() {
        flags |= CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL;
    }
    out.push(flags);
    out.extend_from_slice(&req.requested_credit.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&req.requested_credit_bytes.unwrap_or(0).to_le_bytes());
    // The appended ack-level byte is emitted LAST in the block and ONLY when present, so the historical
    // fields keep their exact offsets and a `None` request omits the byte entirely (#494).
    if let Some(level) = req.default_ack_level {
        out.push(level);
    }
}

/// Decodes a `Connect` body (#292), cap-before-alloc and panic-free.
///
/// An EMPTY body is the historical old-client case and decodes to an all-`None` request (the server
/// then uses its defaults). A non-empty body MUST carry the version byte and the `u16` field-length;
/// the v1 known fields are read from the front of the declared block and any trailing bytes (a future
/// version's appended fields) are tolerated and ignored, so a newer client's longer body still decodes
/// its v1 fields here. A body that is non-empty but too short to hold the `field_len` it declares is a
/// typed [`BodyError`], never a panic or an over-read (the `field_len` is bounded against the actual
/// body by [`Reader::take`] BEFORE any read, so a hostile length cannot force an over-allocation).
///
/// # Errors
/// Returns [`BodyError::Truncated`] if a non-empty body is too short for the version/length header or
/// the declared field block, or [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_connect(body: &[u8]) -> Result<ConnectBody, BodyError> {
    // The empty body is the old-client case: no fields requested, server uses its defaults.
    if body.is_empty() {
        return Ok(ConnectBody::default());
    }
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != HANDSHAKE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    // `field_len` is the declared length of the version's known-field block; the reader takes exactly
    // that many bytes (cap-before-alloc: `take` bounds-checks it against the actual body, so a hostile
    // length is a typed Truncated, never an allocation), and only the v1 fields are parsed from the
    // front of it. Any bytes past the v1 fields, and any bytes after the whole block, are a future
    // version's appended fields, tolerated and ignored (forward-compat).
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    // The v1 fields sit at FIXED positions in the block (`flags`, then the credit u32, then the byte
    // budget u64); the presence flags govern only whether a slot's VALUE is meaningful, not whether it
    // occupies space. Every slot is therefore always consumed in order, so a clear flag still advances
    // past its bytes and a later set flag reads from the right offset. A v1 block shorter than the v1
    // fields (a sender that declared a smaller block) reads what is present and defaults the rest.
    let flags = fr.u8().unwrap_or(0);
    let credit = fr.u32().unwrap_or(0);
    let credit_bytes = fr.u64().unwrap_or(0);
    // The appended ack-level byte (#494) follows the historical fixed fields and is present in the
    // block ONLY when the presence bit is set; a clear bit (an old client, or a short block) reads no
    // byte and defaults to `None`. The `unwrap_or` keeps the read panic-free even if a malformed sender
    // set the bit but truncated the block.
    let default_ack_level =
        (flags & CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL != 0).then(|| fr.u8().unwrap_or(0));
    let requested_credit = (flags & CONNECT_FLAG_HAS_CREDIT != 0).then_some(credit);
    let requested_credit_bytes =
        (flags & CONNECT_FLAG_HAS_CREDIT_BYTES != 0).then_some(credit_bytes);
    let wants_gap_marker = flags & CONNECT_FLAG_WANTS_GAP_MARKER != 0;
    Ok(ConnectBody {
        requested_credit,
        requested_credit_bytes,
        wants_gap_marker,
        default_ack_level,
    })
}

/// One advertised credit dimension in the `Info` body (#292): the NEGOTIATED value the client should
/// adopt for this connection and the server's hard CAP it can never exceed. Generic over the credit
/// width (`u32` for the message count, `u64` for the byte budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditAdvert<T> {
    /// The negotiated value for THIS connection (the server has already clamped the client's request to
    /// its cap, or substituted its default when the client requested nothing).
    pub negotiated: T,
    /// The server's hard cap for this dimension (informational; the negotiated value never exceeds it).
    pub cap: T,
}

/// The server's handshake advertisement (the `Info` frame body, #292). The server advertises the
/// NEGOTIATED per-consumer credit (already clamped to its cap, or its default when the client
/// requested nothing) and its hard CAP, for both the message count and the byte budget; the client
/// reads them and applies the negotiated value to its consumer flow control. An EMPTY `Info` body (an
/// old server) decodes to all-absent, so a new client keeps its own local credit: backward-compatible
/// in this direction too.
///
/// Layout (the same version/length framing as [`ConnectBody`]): `body_version: u8`, `field_len: u16`,
/// then the v1 block: `flags: u8`, `credit.negotiated: u32 LE`, `credit.cap: u32 LE`,
/// `credit_bytes.negotiated: u64 LE`, `credit_bytes.cap: u64 LE`, and then — ONLY when
/// [`INFO_FLAG_HAS_DEFAULT_ACK_LEVEL`] is set — an APPENDED `default_ack_level: u8` (#494). The
/// ack-level byte is OMITTED (and `field_len` is the historical length) when absent, so an
/// advertisement without it is byte-for-byte the pre-#494 body. Trailing bytes past the block are a
/// future version's fields, tolerated and ignored. An empty body is the all-absent case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InfoBody {
    /// The server's per-consumer message-credit advertisement, or `None` if the server does not
    /// advertise (an old server, or a deliberate non-advertisement). When `Some`, the client adopts
    /// `negotiated` as its message credit for this connection.
    pub credit: Option<CreditAdvert<u32>>,
    /// The server's per-consumer byte-budget advertisement, or `None` if the server does not
    /// advertise. When `Some`, the client adopts `negotiated` as its byte budget for this connection.
    pub credit_bytes: Option<CreditAdvert<u64>>,
    /// Whether the server CONFIRMS it will emit `GapMarker` frames (tag 21) for this connection
    /// (#346): `true` only when the client advertised [`ConnectBody::wants_gap_marker`] AND the
    /// server supports it. `false` (an old server, or the marker disabled) tells the client it will
    /// still see the legacy `Truncated` advisory.
    pub gap_marker: bool,
    /// The connection-wide DEFAULT produce ack level the server ECHOES for this connection (#494), the
    /// server->client twin of [`ConnectBody::default_ack_level`]: the raw 0/1/2 value (matching
    /// [`AckLevel::as_u8`]; `3` reserved). `None` (an old server, or one that does not echo) means the
    /// client keeps whatever default it requested. APPENDED v1 field: emitted only when `Some`, so a
    /// `None` advertisement is byte-for-byte the pre-#494 body and an old server decodes to `None`.
    pub default_ack_level: Option<u8>,
}

/// The number of bytes in the `Info` v1 known-field block WITHOUT the appended `default_ack_level`
/// byte (#494): `flags: u8` + `credit.negotiated: u32` + `credit.cap: u32` + `credit_bytes.negotiated:
/// u64` + `credit_bytes.cap: u64`. This is the historical, pre-#494 block length.
const INFO_V1_FIELD_LEN: u16 = 1 + 4 + 4 + 8 + 8;

/// The `Info` v1 block length WITH the appended `default_ack_level` byte (#494): the historical block
/// plus one byte, emitted only when the field is present.
const INFO_V1_FIELD_LEN_WITH_ACK_LEVEL: u16 = INFO_V1_FIELD_LEN + 1;

/// Encodes an `Info` body onto the end of `out` (#292, #494): the version byte, the v1 field-block
/// length, then the v1 block. An all-`None` advertisement still encodes a well-formed (non-empty) v1
/// body whose presence flags are clear, which a client reads as "no advertisement, keep my local
/// credit". The `default_ack_level` byte (#494) is APPENDED to the block ONLY when present, and
/// `field_len` grows by exactly that byte; when absent the body is byte-for-byte the pre-#494 layout.
/// To emit the historical EMPTY `Info` body (the old-server case) the caller sends an empty body and
/// does NOT call this; [`decode_info`] accepts both.
pub fn encode_info(info: &InfoBody, out: &mut Vec<u8>) {
    out.push(HANDSHAKE_BODY_VERSION);
    let field_len = if info.default_ack_level.is_some() {
        INFO_V1_FIELD_LEN_WITH_ACK_LEVEL
    } else {
        INFO_V1_FIELD_LEN
    };
    out.extend_from_slice(&field_len.to_le_bytes());
    let mut flags = 0u8;
    if info.credit.is_some() {
        flags |= INFO_FLAG_HAS_CREDIT;
    }
    if info.credit_bytes.is_some() {
        flags |= INFO_FLAG_HAS_CREDIT_BYTES;
    }
    if info.gap_marker {
        flags |= INFO_FLAG_GAP_MARKER;
    }
    if info.default_ack_level.is_some() {
        flags |= INFO_FLAG_HAS_DEFAULT_ACK_LEVEL;
    }
    out.push(flags);
    let credit = info.credit.unwrap_or(CreditAdvert {
        negotiated: 0,
        cap: 0,
    });
    out.extend_from_slice(&credit.negotiated.to_le_bytes());
    out.extend_from_slice(&credit.cap.to_le_bytes());
    let credit_bytes = info.credit_bytes.unwrap_or(CreditAdvert {
        negotiated: 0,
        cap: 0,
    });
    out.extend_from_slice(&credit_bytes.negotiated.to_le_bytes());
    out.extend_from_slice(&credit_bytes.cap.to_le_bytes());
    // The appended ack-level byte is emitted LAST in the block and ONLY when present, so the historical
    // fields keep their exact offsets and a `None` advertisement omits the byte entirely (#494).
    if let Some(level) = info.default_ack_level {
        out.push(level);
    }
}

/// Decodes an `Info` body (#292), cap-before-alloc and panic-free.
///
/// An EMPTY body is the historical old-server case and decodes to an all-`None` advertisement (the
/// client then keeps its own local credit). A non-empty body carries the version byte and `u16`
/// field-length; the v1 fields are read from the front of the declared block and any trailing bytes (a
/// future version's appended fields) are tolerated and ignored. A non-empty body too short for its
/// declared block is a typed [`BodyError`], never a panic or over-read (the declared `field_len` is
/// bounds-checked against the actual body BEFORE any read).
///
/// # Errors
/// Returns [`BodyError::Truncated`] if a non-empty body is too short for the header or the declared
/// field block, or [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_info(body: &[u8]) -> Result<InfoBody, BodyError> {
    // The empty body is the old-server case: no advertisement, the client keeps its local credit.
    if body.is_empty() {
        return Ok(InfoBody::default());
    }
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != HANDSHAKE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    // As in `decode_connect`, every v1 slot occupies a fixed position and is always consumed in order;
    // the presence flag only governs whether the slot's value is meaningful.
    let flags = fr.u8().unwrap_or(0);
    let credit_negotiated = fr.u32().unwrap_or(0);
    let credit_cap = fr.u32().unwrap_or(0);
    let credit_bytes_negotiated = fr.u64().unwrap_or(0);
    let credit_bytes_cap = fr.u64().unwrap_or(0);
    // The appended ack-level byte (#494) follows the historical fixed fields and is present in the
    // block ONLY when the presence bit is set; a clear bit (an old server, or a short block) reads no
    // byte and defaults to `None`.
    let default_ack_level =
        (flags & INFO_FLAG_HAS_DEFAULT_ACK_LEVEL != 0).then(|| fr.u8().unwrap_or(0));
    let credit = (flags & INFO_FLAG_HAS_CREDIT != 0).then_some(CreditAdvert {
        negotiated: credit_negotiated,
        cap: credit_cap,
    });
    let credit_bytes = (flags & INFO_FLAG_HAS_CREDIT_BYTES != 0).then_some(CreditAdvert {
        negotiated: credit_bytes_negotiated,
        cap: credit_bytes_cap,
    });
    let gap_marker = flags & INFO_FLAG_GAP_MARKER != 0;
    Ok(InfoBody {
        credit,
        credit_bytes,
        gap_marker,
        default_ack_level,
    })
}

/// The version of the `Fetch` (batch-pull) body framing (#489). Version `1` is the first (and only)
/// layout. Carried as a leading byte so a future version can extend the body without a wire break: a
/// reader rejects a version it does not understand rather than mis-parsing it.
pub const FETCH_BODY_VERSION: u8 = 1;

/// The `Fetch` flag bit (#489) marking the request NO-WAIT: the server returns IMMEDIATELY with
/// whatever records are ready, draining a single pass and never waiting out the `expires` deadline for
/// more to arrive. When clear, the server may drain up to the `expires` deadline. The bit is the
/// direct analogue of a NATS pull consumer's `no_wait`.
pub const FETCH_FLAG_NO_WAIT: u8 = 0b0000_0001;

/// A consumer batch-pull FETCH request (the `Fetch` frame body, #489): a NATS pull-consumer-style
/// request to drain up to `max_records` / `max_bytes` of deliverable records in ONE round-trip,
/// amortizing the per-poll actor hop and read cost across the whole batch. It is the BATCH twin of the
/// per-record `Flow` request; the server runs the SAME per-record poll (preserving the lease/credit,
/// at-least-once, and broadcast/`key_shared`/competing semantics exactly), so a batch fetch delivers
/// EXACTLY the records N successive per-record polls would, just in one request. The effective batch is
/// further bounded server-side by the negotiated per-consumer credit and byte budget (#292/#275) and
/// the group's `max_in_flight` window, so a generous `max_records` / `max_bytes` never over-delivers.
///
/// Layout (version+length framed, forward-compatible, mirroring [`ConnectBody`]): `body_version: u8`
/// ([`FETCH_BODY_VERSION`]), `field_len: u16` (the length of the v1 known-field block that follows),
/// then the v1 block: `flags: u8`, `max_records: u32 LE`, `max_bytes: u64 LE`, `expires_ms: u64 LE`.
/// Bytes past `field_len` (a future version's appended fields) are TOLERATED and ignored by a v1
/// reader.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchBody {
    /// The maximum number of records to deliver in this batch. The server delivers at most this many
    /// (and possibly fewer: the negotiated credit, the byte budget, the group's available records, the
    /// byte cap, and the deadline all bind first). A value of `0` requests nothing.
    pub max_records: u32,
    /// The maximum total payload-equivalent bytes to deliver in this batch (key + headers + payload per
    /// record, matching the per-consumer byte-budget accounting). `0` means UNBOUNDED by bytes (only the
    /// record count, credit, and deadline bind). The server stops once delivering the next record would
    /// exceed this, EXCEPT the floor-of-one (a batch always delivers at least one ready record so a
    /// single over-cap record never wedges the consumer), exactly the existing per-consumer byte-budget
    /// floor.
    pub max_bytes: u64,
    /// The batch's deadline budget in milliseconds: the maximum wall-clock time the server spends
    /// draining this batch before terminating it with whatever it has gathered. `0` means NO deadline
    /// (drain until a bound binds). Measured on the server's monotonic clock; it bounds server WORK and
    /// never changes WHICH records are delivered (the engine poll is non-blocking, so the deadline only
    /// caps how long a large drain may run). Ignored when `no_wait` is set (a no-wait fetch is a single
    /// immediate pass).
    pub expires_ms: u64,
    /// Whether this fetch is NO-WAIT (#489): when `true`, the server drains a single pass and returns
    /// immediately with whatever is ready, never waiting out `expires_ms`. When `false`, the server may
    /// drain up to the `expires_ms` deadline. The direct analogue of a NATS pull consumer's `no_wait`.
    /// Carried in the [`FETCH_FLAG_NO_WAIT`] bit of the body's `flags`.
    pub no_wait: bool,
}

/// The number of bytes in the `Fetch` v1 known-field block: `flags: u8` + `max_records: u32` +
/// `max_bytes: u64` + `expires_ms: u64`.
const FETCH_V1_FIELD_LEN: u16 = 1 + 4 + 8 + 8;

/// Encodes a `Fetch` body onto the end of `out` (#489): the version byte, the v1 field-block length,
/// then the v1 block. The `no_wait` field is derived into the [`FETCH_FLAG_NO_WAIT`] bit of the written
/// `flags`, so the flag and the field can never disagree.
pub fn encode_fetch(req: &FetchBody, out: &mut Vec<u8>) {
    out.push(FETCH_BODY_VERSION);
    out.extend_from_slice(&FETCH_V1_FIELD_LEN.to_le_bytes());
    let mut flags = 0u8;
    if req.no_wait {
        flags |= FETCH_FLAG_NO_WAIT;
    }
    out.push(flags);
    out.extend_from_slice(&req.max_records.to_le_bytes());
    out.extend_from_slice(&req.max_bytes.to_le_bytes());
    out.extend_from_slice(&req.expires_ms.to_le_bytes());
}

/// Decodes a `Fetch` body (#489), cap-before-alloc and panic-free.
///
/// The body MUST carry the version byte and the `u16` field-length; the v1 known fields are read from
/// the front of the declared block and any trailing bytes (a future version's appended fields) are
/// tolerated and ignored, so a newer client's longer body still decodes its v1 fields here. A body too
/// short to hold the `field_len` it declares is a typed [`BodyError`], never a panic or an over-read
/// (the `field_len` is bounded against the actual body by [`Reader::take`] BEFORE any read). Unlike the
/// handshake bodies an EMPTY body is NOT a valid `Fetch` (there is no historical empty-`Fetch` case: the
/// frame type itself is new), so it is a typed [`BodyError::Truncated`].
///
/// # Errors
/// Returns [`BodyError::Truncated`] if the body is too short for the version/length header or the
/// declared field block, or [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_fetch(body: &[u8]) -> Result<FetchBody, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != FETCH_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    // Every v1 slot occupies a fixed position and is always consumed in order; a short block (a sender
    // that declared fewer bytes) reads what is present and defaults the rest, never panicking.
    let flags = fr.u8().unwrap_or(0);
    let max_records = fr.u32().unwrap_or(0);
    let max_bytes = fr.u64().unwrap_or(0);
    let expires_ms = fr.u64().unwrap_or(0);
    let no_wait = flags & FETCH_FLAG_NO_WAIT != 0;
    Ok(FetchBody {
        max_records,
        max_bytes,
        expires_ms,
        no_wait,
    })
}

/// The version of the Tier-S `StreamFetch` (streaming consumer-managed-offset) body framing (#544,
/// M1-I7). Version `1` is the first (and only) layout. Carried as a leading byte so a future version
/// can extend the body without a wire break: a reader rejects a version it does not understand rather
/// than mis-parsing it, exactly like [`FETCH_BODY_VERSION`].
pub const STREAM_FETCH_BODY_VERSION: u8 = 1;

/// A consumer Tier-S STREAMING fetch request (the `StreamFetch` frame body, #544 / M1-I7): the
/// consumer-managed-offset twin of [`FetchBody`]. The consumer names its OWN `start_offset` and the
/// broker serves a CONTIGUOUS batch of records `[start_offset, ...)` bounded by `max_records` /
/// `max_bytes` — with NO lease, NO generation fence, and NO per-record cursor write. At-least-once
/// holds BY CONSTRUCTION: a crash or reconnect re-reads from the consumer's last committed offset
/// (advanced via a periodic [`crate::frame::FrameType::StreamCommit`]), so at most the uncommitted
/// records redeliver — the Kafka / NATS-pull contract. Where [`FetchBody`] drives the per-record
/// lease/cursor poll (Tier-W, the work-queue), this drives a contiguous read off the durable prefix,
/// which removes exactly the per-record cost that makes single-consumer durable consume lose to NATS.
///
/// Layout (version+length framed, forward-compatible, mirroring [`FetchBody`]): `body_version: u8`
/// ([`STREAM_FETCH_BODY_VERSION`]), `field_len: u16` (the length of the v1 known-field block that
/// follows), then the v1 block: `start_offset: u64 LE`, `max_records: u32 LE`, `max_bytes: u64 LE`.
/// Bytes past `field_len` (a future version's appended fields) are TOLERATED and ignored by a v1
/// reader.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamFetchBody {
    /// The consumer-managed offset to begin the contiguous read at (inclusive). The consumer owns this
    /// position: it is normally the consumer's last committed offset, so a reconnect resumes exactly
    /// where it left off. The broker reads forward from here off the durable prefix, bounded by the
    /// flushed frontier (no un-flushed record is ever served).
    pub start_offset: u64,
    /// The maximum number of records to deliver in this batch. The server delivers at most this many
    /// (the durable prefix's available records and the byte cap also bind). A value of `0` requests
    /// nothing.
    pub max_records: u32,
    /// The maximum total ENCODED record bytes to deliver in this batch. `0` means UNBOUNDED by bytes
    /// (only the record count and the available durable prefix bind). The server stops once delivering
    /// the next record would exceed this, EXCEPT the floor-of-one (a batch always delivers at least one
    /// ready record so a single over-cap record never wedges the consumer).
    pub max_bytes: u64,
}

/// The number of bytes in the `StreamFetch` v1 known-field block: `start_offset: u64` +
/// `max_records: u32` + `max_bytes: u64`.
const STREAM_FETCH_V1_FIELD_LEN: u16 = 8 + 4 + 8;

/// Encodes a `StreamFetch` body onto the end of `out` (#544): the version byte, the v1 field-block
/// length, then the v1 block.
pub fn encode_stream_fetch(req: &StreamFetchBody, out: &mut Vec<u8>) {
    out.push(STREAM_FETCH_BODY_VERSION);
    out.extend_from_slice(&STREAM_FETCH_V1_FIELD_LEN.to_le_bytes());
    out.extend_from_slice(&req.start_offset.to_le_bytes());
    out.extend_from_slice(&req.max_records.to_le_bytes());
    out.extend_from_slice(&req.max_bytes.to_le_bytes());
}

/// Decodes a `StreamFetch` body (#544), cap-before-alloc and panic-free.
///
/// The body MUST carry the version byte and the `u16` field-length; the v1 known fields are read from
/// the front of the declared block and any trailing bytes (a future version's appended fields) are
/// tolerated and ignored. A body too short to hold the `field_len` it declares is a typed
/// [`BodyError`], never a panic or an over-read (the `field_len` is bounded against the actual body by
/// [`Reader::take`] BEFORE any read). An EMPTY body is NOT a valid `StreamFetch` (the frame type is
/// new, with no historical empty case), so it is a typed [`BodyError::Truncated`].
///
/// # Errors
/// Returns [`BodyError::Truncated`] if the body is too short for the version/length header or the
/// declared field block, or [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_stream_fetch(body: &[u8]) -> Result<StreamFetchBody, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_FETCH_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    // Every v1 slot occupies a fixed position and is always consumed in order; a short block (a sender
    // that declared fewer bytes) reads what is present and defaults the rest, never panicking.
    let start_offset = fr.u64().unwrap_or(0);
    let max_records = fr.u32().unwrap_or(0);
    let max_bytes = fr.u64().unwrap_or(0);
    Ok(StreamFetchBody {
        start_offset,
        max_records,
        max_bytes,
    })
}

/// A consumer Tier-S periodic CUMULATIVE COMMIT (the `StreamCommit` frame body, #544 / M1-I7): the
/// consumer-managed-offset durability point. It advances the STREAMING group's committed watermark up
/// to an exclusive `up_to` offset, the consumer's periodic "everything below `up_to` is durably
/// processed" checkpoint. It REUSES the same cursor primitive
/// (`AckCursor::commit_up_to` in `ironbus-core`) the broadcast [`CumulativeAckBody`] rides on —
/// no new durable structure is invented — but targets a STREAMING group rather than a BROADCAST one,
/// so the two never collide. The server validates `up_to` against the durable head and the
/// earliest-retained offset, is idempotent / monotonic on a re-commit, and HARD-REJECTS the verb on a
/// group that is not streaming.
///
/// Layout: `up_to: u64` (the exclusive commit offset, little-endian), then `group` (the work-group
/// name as the remainder of the body; empty selects the default group). This is BYTE-IDENTICAL to
/// [`CumulativeAckBody`]'s layout (a shared shape, distinct frame type); the server dispatches on the
/// FRAME TYPE (Tier-S streaming vs Tier-W broadcast) to pick the right group-mode guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamCommitBody<'a> {
    /// The exclusive offset to commit the streaming cursor up to (every offset strictly below it is
    /// committed).
    pub up_to: u64,
    /// The work-group name (empty selects the default group). Validated server-side.
    pub group: &'a [u8],
}

/// Encodes a `StreamCommit` body onto the end of `out`: the 8-byte LE `up_to` offset, then the group
/// name as the remainder (the same shape as [`encode_cumulative_ack`]).
pub fn encode_stream_commit(commit: &StreamCommitBody<'_>, out: &mut Vec<u8>) {
    out.extend_from_slice(&commit.up_to.to_le_bytes());
    out.extend_from_slice(commit.group);
}

/// Decodes a `StreamCommit` body: the leading 8-byte LE `up_to` offset, then the remainder is the group
/// name (the same shape as [`decode_cumulative_ack`]).
///
/// # Errors
/// Returns [`BodyError::Truncated`] if the body is shorter than the 8-byte `up_to` field.
pub fn decode_stream_commit(body: &[u8]) -> Result<StreamCommitBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let up_to = r.u64()?;
    let group = r.rest();
    Ok(StreamCommitBody { up_to, group })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dead_letter_round_trips() {
        let advisory = DeadLetterBody {
            offset: 0x0102_0304_0506_0708,
            reason: DEAD_LETTER_MAX_DELIVER,
        };
        let mut buf = Vec::new();
        encode_dead_letter(&advisory, &mut buf);
        assert_eq!(buf.len(), 9, "fixed 9-byte body: u64 offset + u8 reason");
        assert_eq!(decode_dead_letter(&buf).unwrap(), advisory);
    }

    #[test]
    fn dead_letter_rejects_a_short_or_overlong_body() {
        assert_eq!(decode_dead_letter(&[0u8; 8]), Err(BodyError::Truncated));
        assert_eq!(
            decode_dead_letter(&[0u8; 10]),
            Err(BodyError::TrailingBytes)
        );
    }

    #[test]
    fn truncated_round_trips() {
        let advisory = TruncatedBody {
            earliest_retained: 0x0102_0304_0506_0708,
            skipped: 0x1112_1314_1516_1718,
        };
        let mut buf = Vec::new();
        encode_truncated(&advisory, &mut buf);
        assert_eq!(
            buf.len(),
            16,
            "fixed 16-byte body: u64 offset + u64 skipped"
        );
        assert_eq!(decode_truncated(&buf).unwrap(), advisory);
    }

    #[test]
    fn truncated_rejects_a_short_or_overlong_body() {
        assert_eq!(decode_truncated(&[0u8; 15]), Err(BodyError::Truncated));
        assert_eq!(decode_truncated(&[0u8; 17]), Err(BodyError::TrailingBytes));
    }

    #[test]
    fn gap_marker_round_trips() {
        let marker = GapMarkerBody {
            from: 0x0102_0304_0506_0708,
            to: 0x1112_1314_1516_1718,
            bytes_skipped: 0x2122_2324_2526_2728,
            reason: gap_reason::TRIMMED,
        };
        let mut buf = Vec::new();
        encode_gap_marker(&marker, &mut buf);
        assert_eq!(
            buf.len(),
            25,
            "fixed 25-byte body: three u64 fields + u8 reason"
        );
        assert_eq!(decode_gap_marker(&buf).unwrap(), marker);
        // The fields are LE in declared order: from, to, bytes_skipped, reason.
        assert_eq!(&buf[..8], &marker.from.to_le_bytes());
        assert_eq!(&buf[8..16], &marker.to.to_le_bytes());
        assert_eq!(&buf[16..24], &marker.bytes_skipped.to_le_bytes());
        assert_eq!(buf[24], gap_reason::TRIMMED);
    }

    #[test]
    fn gap_marker_rejects_a_short_or_overlong_body() {
        assert_eq!(decode_gap_marker(&[0u8; 24]), Err(BodyError::Truncated));
        assert_eq!(decode_gap_marker(&[0u8; 26]), Err(BodyError::TrailingBytes));
    }

    #[test]
    fn gap_marker_tolerates_an_unknown_reason() {
        // An unknown future reason byte (e.g. 200) is a VALID, tolerated marker, decoded verbatim,
        // not an error: the reason field can grow without a new frame.
        let marker = GapMarkerBody {
            from: 10,
            to: 14,
            bytes_skipped: 99,
            reason: 200,
        };
        let mut buf = Vec::new();
        encode_gap_marker(&marker, &mut buf);
        assert_eq!(decode_gap_marker(&buf).unwrap(), marker);
        assert_eq!(decode_gap_marker(&buf).unwrap().reason, 200);
    }

    #[test]
    fn connect_carries_the_gap_marker_capability_bit() {
        // A consumer that wants gap markers sets the capability bit; the bit round-trips and a
        // default (old client) request leaves it clear.
        let req = ConnectBody {
            requested_credit: None,
            requested_credit_bytes: None,
            wants_gap_marker: true,
            default_ack_level: None,
        };
        let mut buf = Vec::new();
        encode_connect(&req, &mut buf);
        // The flags byte sits right after the 3-byte version/length header.
        assert_eq!(
            buf[3] & CONNECT_FLAG_WANTS_GAP_MARKER,
            CONNECT_FLAG_WANTS_GAP_MARKER,
            "the capability bit is set in the flags byte"
        );
        assert!(decode_connect(&buf).unwrap().wants_gap_marker);
        // An EMPTY (old-client) Connect body never advertises the capability.
        assert!(!decode_connect(&[]).unwrap().wants_gap_marker);
    }

    #[test]
    fn info_carries_the_gap_marker_capability_bit() {
        let info = InfoBody {
            credit: None,
            credit_bytes: None,
            gap_marker: true,
            default_ack_level: None,
        };
        let mut buf = Vec::new();
        encode_info(&info, &mut buf);
        assert_eq!(
            buf[3] & INFO_FLAG_GAP_MARKER,
            INFO_FLAG_GAP_MARKER,
            "the capability confirmation bit is set in the flags byte"
        );
        assert!(decode_info(&buf).unwrap().gap_marker);
        // An EMPTY (old-server) Info body never confirms the capability.
        assert!(!decode_info(&[]).unwrap().gap_marker);
    }

    #[test]
    fn cumulative_ack_round_trips() {
        for group in [&b""[..], b"orders", b"a-very/long.name_1:2"] {
            let ack = CumulativeAckBody {
                up_to: 0x0102_0304_0506_0708,
                group,
            };
            let mut buf = Vec::new();
            encode_cumulative_ack(&ack, &mut buf);
            assert_eq!(buf.len(), 8 + group.len(), "u64 up_to then the group tail");
            assert_eq!(decode_cumulative_ack(&buf).unwrap(), ack);
            assert_eq!(&buf[..8], &ack.up_to.to_le_bytes(), "up_to leads, LE");
            assert_eq!(&buf[8..], group, "the group is the body tail");
        }
    }

    #[test]
    fn cumulative_ack_rejects_a_short_body() {
        // Anything shorter than the leading 8-byte up_to cannot be decoded.
        for len in 0..8usize {
            assert_eq!(
                decode_cumulative_ack(&vec![0u8; len]),
                Err(BodyError::Truncated),
                "length {len} is too short for the up_to field"
            );
        }
        // Exactly 8 bytes is the default group (empty name tail), not an error.
        assert_eq!(
            decode_cumulative_ack(&[0u8; 8]).unwrap(),
            CumulativeAckBody {
                up_to: 0,
                group: b""
            }
        );
    }

    #[test]
    fn pub_round_trips() {
        let msg = PubBody {
            flags: 0b0000_0010,
            timestamp_ms: 1_700_000_000_000,
            key: b"order-42",
            headers: b"h",
            dedup: None,
            fire_and_forget: false,
            payload: b"the payload bytes",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(decode_pub(&buf).unwrap(), msg);
    }

    #[test]
    fn sub_round_trips() {
        for group in [&b""[..], b"orders", b"a-very/long.name_1:2"] {
            let mut buf = Vec::new();
            encode_sub(&SubBody { group }, &mut buf);
            assert_eq!(decode_sub(&buf), SubBody { group });
            assert_eq!(buf, group, "the SUB body is exactly the group name");
        }
    }

    #[test]
    fn deliver_round_trips() {
        let msg = DeliverBody {
            offset: 12_345,
            generation: 9,
            flags: 0,
            timestamp_ms: 42,
            key: b"key",
            headers: b"",
            payload: b"delivered payload",
        };
        let mut buf = Vec::new();
        encode_deliver(&msg, &mut buf).unwrap();
        assert_eq!(decode_deliver(&buf).unwrap(), msg);
    }

    #[test]
    fn pub_with_empty_fields_round_trips() {
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        let got = decode_pub(&buf).unwrap();
        assert_eq!(got, msg);
        assert!(got.key.is_empty() && got.headers.is_empty() && got.payload.is_empty());
    }

    #[test]
    fn pub_rejects_an_oversized_key() {
        let big = vec![0u8; usize::from(u16::MAX) + 1];
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: &big,
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"",
        };
        let mut buf = Vec::new();
        assert_eq!(encode_pub(&msg, &mut buf), Err(BodyError::FieldTooLarge));
    }

    #[test]
    fn pub_decode_is_truncation_safe() {
        let mut buf = Vec::new();
        encode_pub(
            &PubBody {
                flags: 1,
                timestamp_ms: 9,
                key: b"abc",
                headers: b"de",
                dedup: None,
                fire_and_forget: false,
                payload: b"xyz",
            },
            &mut buf,
        )
        .unwrap();
        // Framed header = flags(1) + ts(8) + key_len(2) + key(3) + hdr_len(2) + hdr(2) = 18.
        let framed = 1 + 8 + 2 + 3 + 2 + 2;
        // Cutting inside the framed header errors (never panics).
        for cut in 0..framed {
            assert!(
                decode_pub(&buf[..cut]).is_err(),
                "header prefix {cut} should error"
            );
        }
        // The payload is the remainder, so cutting into it just yields a shorter payload.
        for cut in framed..=buf.len() {
            assert_eq!(decode_pub(&buf[..cut]).unwrap().payload.len(), cut - framed);
        }
    }

    #[test]
    fn pub_rejects_a_key_length_past_the_body() {
        // flags(1) + ts(8) + key_len(2)=0xffff but no key bytes.
        let mut buf = vec![0u8; 9];
        buf.extend_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode_pub(&buf), Err(BodyError::Truncated));
    }

    #[test]
    fn ack_round_trips_every_op() {
        for op in [AckOp::Ack, AckOp::Nack, AckOp::Term, AckOp::Progress] {
            let ack = AckBody {
                op,
                offset: 12_345,
                generation: 7,
                delay_ms: if op == AckOp::Nack { 250 } else { 0 },
            };
            let mut buf = Vec::new();
            encode_ack(&ack, &mut buf);
            assert_eq!(buf.len(), 25);
            assert_eq!(decode_ack(&buf).unwrap(), ack);
        }
    }

    #[test]
    fn ackop_tags_have_their_exact_frozen_wire_values() {
        // Pin the on-the-wire op numbers so a future reorder breaks a test here, not a
        // deployed peer. Part of the frozen wire contract.
        assert_eq!(AckOp::Ack.as_u8(), 0);
        assert_eq!(AckOp::Nack.as_u8(), 1);
        assert_eq!(AckOp::Term.as_u8(), 2);
        assert_eq!(AckOp::Progress.as_u8(), 3);
    }

    #[test]
    fn pub_round_trips_at_the_u16_field_boundary() {
        // key and headers each at exactly u16::MAX, the largest a length field can name.
        let big = vec![0xa5_u8; usize::from(u16::MAX)];
        let msg = PubBody {
            flags: 7,
            timestamp_ms: 1,
            key: &big,
            headers: &big,
            dedup: None,
            fire_and_forget: false,
            payload: b"tail",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(decode_pub(&buf).unwrap(), msg);
    }

    #[test]
    fn pub_with_dedup_round_trips_and_sets_the_wire_bit() {
        let dedup = PubDedup {
            producer_id: b"producer-7",
            epoch: 42,
            msg_id: b"idem-key-abc",
        };
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 9,
            key: b"k",
            headers: b"h",
            dedup: Some(dedup),
            fire_and_forget: false,
            payload: b"p",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        // The encoded flags byte carries the wire dedup bit even though the caller passed flags 0.
        assert_eq!(buf[0] & PUB_FLAG_HAS_DEDUP, PUB_FLAG_HAS_DEDUP);
        let got = decode_pub(&buf).unwrap();
        assert_eq!(got.dedup, Some(dedup));
        assert_eq!(got.payload, b"p");
    }

    #[test]
    fn a_no_dedup_pub_is_byte_for_byte_the_historical_layout() {
        // The dedup-disabled body must be EXACTLY the pre-#33 layout, so an old broker reads it
        // unchanged. Build the historical body by hand and compare.
        let msg = PubBody {
            flags: 0b0000_0010,
            timestamp_ms: 0x0102_0304_0506_0708,
            key: b"key",
            headers: b"hd",
            dedup: None,
            fire_and_forget: false,
            payload: b"payload",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        let mut expected = Vec::new();
        expected.push(0b0000_0010); // flags, dedup bit clear
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        expected.extend_from_slice(&3u16.to_le_bytes());
        expected.extend_from_slice(b"key");
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(b"hd");
        expected.extend_from_slice(b"payload");
        assert_eq!(
            buf, expected,
            "no-dedup PUB must match the frozen historical layout"
        );
    }

    #[test]
    fn a_fire_and_forget_pub_sets_the_wire_bit_and_round_trips() {
        // The QoS-0 marker (#11): `fire_and_forget: true` sets bit 6 in the encoded flags byte and
        // round-trips, while the dedup bit and the layout are untouched (no extra block).
        let msg = PubBody {
            flags: 0b0000_0010,
            timestamp_ms: 7,
            key: b"k",
            headers: b"h",
            dedup: None,
            fire_and_forget: true,
            payload: b"p",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(
            buf[0] & PUB_FLAG_FIRE_AND_FORGET,
            PUB_FLAG_FIRE_AND_FORGET,
            "the fire-and-forget wire bit is set"
        );
        assert_eq!(buf[0] & PUB_FLAG_HAS_DEDUP, 0, "the dedup bit stays clear");
        let got = decode_pub(&buf).unwrap();
        assert!(got.fire_and_forget, "decode recovers the QoS-0 marker");
        assert_eq!(got.dedup, None);
        assert_eq!(got.payload, b"p");
    }

    #[test]
    fn a_non_fire_and_forget_pub_leaves_the_bit_clear_and_is_the_historical_layout() {
        // The DEFAULT (at-least-once) produce never sets bit 6, so the body is byte-for-byte the
        // historical layout and an old broker reads it unchanged (backward-compat).
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"x",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(buf[0], 0, "no wire-only bit set on the default produce");
        let got = decode_pub(&buf).unwrap();
        assert!(!got.fire_and_forget);
    }

    #[test]
    fn fire_and_forget_and_dedup_compose_in_the_one_flags_byte() {
        // Both wire-only bits can be set at once: a QoS-0 produce that also opts into dedup. They
        // occupy distinct bits (6 and 7) and both round-trip, with the dedup block present.
        let dedup = PubDedup {
            producer_id: b"p",
            epoch: 3,
            msg_id: b"m",
        };
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 1,
            key: b"",
            headers: b"",
            dedup: Some(dedup),
            fire_and_forget: true,
            payload: b"z",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(buf[0] & PUB_FLAG_FIRE_AND_FORGET, PUB_FLAG_FIRE_AND_FORGET);
        assert_eq!(buf[0] & PUB_FLAG_HAS_DEDUP, PUB_FLAG_HAS_DEDUP);
        let got = decode_pub(&buf).unwrap();
        assert!(got.fire_and_forget);
        assert_eq!(got.dedup, Some(dedup));
        assert_eq!(got.payload, b"z");
    }

    #[test]
    fn encode_clears_a_stray_dedup_bit_when_there_is_no_block() {
        // A caller that sets bit 7 in flags but provides no dedup block must NOT produce a body that
        // claims a block: the bit is derived from `dedup`, so it is force-cleared.
        let msg = PubBody {
            flags: PUB_FLAG_HAS_DEDUP | 0b0000_0001,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"x",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(
            buf[0] & PUB_FLAG_HAS_DEDUP,
            0,
            "the stray dedup bit is cleared"
        );
        let got = decode_pub(&buf).unwrap();
        assert_eq!(got.dedup, None);
        assert_eq!(got.payload, b"x");
    }

    #[test]
    fn pub_with_dedup_bit_set_but_truncated_block_errors() {
        // The dedup bit claims a block the body is too short to hold: a typed error, never a panic.
        let mut buf = Vec::new();
        buf.push(PUB_FLAG_HAS_DEDUP); // flags with the dedup bit
        buf.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u16.to_le_bytes()); // empty key
        buf.extend_from_slice(&0u16.to_le_bytes()); // empty headers
                                                    // The producer_id length field is missing entirely.
        assert_eq!(decode_pub(&buf), Err(BodyError::Truncated));
    }

    #[test]
    fn pub_ack_body_round_trips_and_rejects_a_bad_length() {
        let ack = PubAckBody {
            offset: 0x0102_0304_0506_0708,
        };
        let mut buf = Vec::new();
        encode_pub_ack(&ack, &mut buf);
        assert_eq!(
            buf.len(),
            8,
            "fixed 8-byte LE offset, like the frozen PubAck body"
        );
        assert_eq!(decode_pub_ack(&buf).unwrap(), ack);
        assert_eq!(decode_pub_ack(&[0u8; 7]), Err(BodyError::Truncated));
        assert_eq!(decode_pub_ack(&[0u8; 9]), Err(BodyError::TrailingBytes));
    }

    #[test]
    fn ack_rejects_an_unknown_op() {
        let mut buf = vec![9u8]; // op 9 is unknown
        buf.extend_from_slice(&[0u8; 24]);
        assert_eq!(decode_ack(&buf), Err(BodyError::BadAckOp { op: 9 }));
    }

    #[test]
    fn ack_rejects_a_short_or_overlong_body() {
        assert_eq!(decode_ack(&[0u8; 24]), Err(BodyError::Truncated));
        assert_eq!(decode_ack(&[0u8; 26]), Err(BodyError::TrailingBytes));
    }

    #[test]
    fn fetch_round_trips_and_derives_the_no_wait_bit() {
        // #489: every field round-trips, and `no_wait` is carried in the FETCH_FLAG_NO_WAIT bit.
        let req = FetchBody {
            max_records: 0x0102_0304,
            max_bytes: 0x0506_0708_090a_0b0c,
            expires_ms: 5_000,
            no_wait: true,
        };
        let mut buf = Vec::new();
        encode_fetch(&req, &mut buf);
        // version(1) + field_len(2) + flags(1) + max_records(4) + max_bytes(8) + expires_ms(8) = 24.
        assert_eq!(buf.len(), 1 + 2 + 1 + 4 + 8 + 8);
        // The no_wait field set the flag bit on the wire (the flags byte is the first block byte).
        assert_eq!(buf[3] & FETCH_FLAG_NO_WAIT, FETCH_FLAG_NO_WAIT);
        assert_eq!(decode_fetch(&buf).unwrap(), req);

        // A waiting (no_wait = false) fetch clears the bit.
        let waiting = FetchBody {
            no_wait: false,
            ..req
        };
        let mut buf2 = Vec::new();
        encode_fetch(&waiting, &mut buf2);
        assert_eq!(buf2[3] & FETCH_FLAG_NO_WAIT, 0);
        assert_eq!(decode_fetch(&buf2).unwrap(), waiting);
    }

    #[test]
    fn fetch_rejects_an_empty_or_short_body_and_an_unknown_version() {
        // The Fetch frame type is new, so there is NO historical empty-body case: an empty body is a
        // typed Truncated, never a default request.
        assert_eq!(decode_fetch(&[]), Err(BodyError::Truncated));
        // A non-empty body too short to hold the version+length header is Truncated, not a panic.
        assert_eq!(
            decode_fetch(&[FETCH_BODY_VERSION]),
            Err(BodyError::Truncated)
        );
        // An unknown body version is a typed reject (a future layout this build cannot interpret).
        let mut bad = Vec::new();
        encode_fetch(&FetchBody::default(), &mut bad);
        bad[0] = 2; // bump the version byte past what this build knows
        assert_eq!(
            decode_fetch(&bad),
            Err(BodyError::BadHandshakeVersion { version: 2 })
        );
    }

    #[test]
    fn fetch_tolerates_a_future_appended_field() {
        // A newer client may append fields past the declared v1 block; a v1 reader decodes its known
        // fields and ignores the tail (forward-compat), exactly like the handshake bodies.
        let req = FetchBody {
            max_records: 7,
            max_bytes: 4096,
            expires_ms: 250,
            no_wait: false,
        };
        let mut buf = Vec::new();
        encode_fetch(&req, &mut buf);
        buf.extend_from_slice(b"future-fields"); // appended past field_len
        assert_eq!(decode_fetch(&buf).unwrap(), req);
    }

    #[test]
    fn stream_fetch_round_trips() {
        // #544: the Tier-S streaming fetch carries the consumer-managed start_offset + the batch caps.
        let req = StreamFetchBody {
            start_offset: 0x0102_0304_0506_0708,
            max_records: 256,
            max_bytes: 1 << 20,
        };
        let mut buf = Vec::new();
        encode_stream_fetch(&req, &mut buf);
        assert_eq!(decode_stream_fetch(&buf).unwrap(), req);
    }

    #[test]
    fn stream_fetch_rejects_an_empty_or_short_body_and_an_unknown_version() {
        // The frame type is new: an empty body is not a valid request (no historical empty case).
        assert_eq!(decode_stream_fetch(&[]), Err(BodyError::Truncated));
        // A declared field_len longer than the body is a typed length error, never an over-read.
        let mut bad = vec![STREAM_FETCH_BODY_VERSION];
        bad.extend_from_slice(&99u16.to_le_bytes()); // declares 99 bytes but supplies none
        assert!(matches!(
            decode_stream_fetch(&bad),
            Err(BodyError::Truncated | BodyError::BadLength)
        ));
        // An unknown body version is rejected, not best-effort parsed.
        let mut wrong = Vec::new();
        encode_stream_fetch(
            &StreamFetchBody {
                start_offset: 1,
                max_records: 1,
                max_bytes: 0,
            },
            &mut wrong,
        );
        wrong[0] = STREAM_FETCH_BODY_VERSION + 1;
        assert_eq!(
            decode_stream_fetch(&wrong),
            Err(BodyError::BadHandshakeVersion {
                version: STREAM_FETCH_BODY_VERSION + 1
            })
        );
    }

    #[test]
    fn stream_fetch_tolerates_a_future_appended_field() {
        // A newer client may append fields past the declared v1 block; a v1 reader decodes its known
        // fields and ignores the tail (forward-compat), exactly like FetchBody.
        let req = StreamFetchBody {
            start_offset: 42,
            max_records: 7,
            max_bytes: 4096,
        };
        let mut buf = Vec::new();
        encode_stream_fetch(&req, &mut buf);
        buf.extend_from_slice(b"future-fields");
        assert_eq!(decode_stream_fetch(&buf).unwrap(), req);
    }

    #[test]
    fn stream_commit_round_trips_and_shares_the_cumulative_ack_shape() {
        // #544: StreamCommit carries the same (u64 up_to, group name) shape as CumulativeAck — a shared
        // byte layout, a DISTINCT frame type. The server dispatches on the frame type to pick the
        // group-mode guard (streaming vs broadcast).
        let commit = StreamCommitBody {
            up_to: 0x1122_3344_5566_7788,
            group: b"stream-group",
        };
        let mut buf = Vec::new();
        encode_stream_commit(&commit, &mut buf);
        assert_eq!(decode_stream_commit(&buf).unwrap(), commit);
        // The bytes are identical to a CumulativeAck body with the same fields.
        let mut ca = Vec::new();
        encode_cumulative_ack(
            &CumulativeAckBody {
                up_to: commit.up_to,
                group: commit.group,
            },
            &mut ca,
        );
        assert_eq!(
            buf, ca,
            "StreamCommit and CumulativeAck share the wire shape"
        );
        // An empty group selects the default group.
        let default_group = StreamCommitBody {
            up_to: 5,
            group: b"",
        };
        let mut db = Vec::new();
        encode_stream_commit(&default_group, &mut db);
        assert_eq!(decode_stream_commit(&db).unwrap(), default_group);
    }

    #[test]
    fn stream_commit_rejects_a_short_body() {
        // Anything shorter than the 8-byte up_to cannot carry the commit offset.
        for len in 0..8usize {
            assert_eq!(
                decode_stream_commit(&vec![0u8; len]),
                Err(BodyError::Truncated),
                "a {len}-byte body must be Truncated"
            );
        }
    }

    proptest! {
        #[test]
        fn any_pub_round_trips(
            flags in any::<u8>(),
            timestamp_ms in any::<u64>(),
            key in prop::collection::vec(any::<u8>(), 0..300),
            headers in prop::collection::vec(any::<u8>(), 0..300),
            payload in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            // The wire-only bits are DERIVED, not passed through `flags`: the dedup bit from
            // `dedup` and the fire-and-forget bit from the `fire_and_forget` field. Clear BOTH in the
            // input flags and derive `fire_and_forget` from the (cleared) input so the round-trip is
            // exact regardless of which bits the arbitrary `flags` set (#33, #11).
            let flags = flags & !PUB_WIRE_ONLY_FLAGS;
            let msg = PubBody { flags, timestamp_ms, key: &key, headers: &headers, dedup: None, fire_and_forget: false, payload: &payload };
            let mut buf = Vec::new();
            encode_pub(&msg, &mut buf).unwrap();
            prop_assert_eq!(decode_pub(&buf).unwrap(), msg);
        }

        /// A PUB body WITH the opt-in dedup block round-trips for any producer_id / epoch / msg_id:
        /// the dedup bit is set, the block is emitted after the headers, and decode recovers the
        /// exact `(producer_id, epoch, msg_id)` plus the payload tail (#33).
        #[test]
        fn any_pub_with_dedup_round_trips(
            flags in any::<u8>(),
            timestamp_ms in any::<u64>(),
            key in prop::collection::vec(any::<u8>(), 0..200),
            headers in prop::collection::vec(any::<u8>(), 0..200),
            producer_id in prop::collection::vec(any::<u8>(), 0..200),
            epoch in any::<u64>(),
            msg_id in prop::collection::vec(any::<u8>(), 0..200),
            payload in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let dedup = PubDedup { producer_id: &producer_id, epoch, msg_id: &msg_id };
            let msg = PubBody { flags, timestamp_ms, key: &key, headers: &headers, dedup: Some(dedup), fire_and_forget: false, payload: &payload };
            let mut buf = Vec::new();
            encode_pub(&msg, &mut buf).unwrap();
            let got = decode_pub(&buf).unwrap();
            // The wire body carries the dedup bit regardless of the caller's flags input.
            prop_assert_eq!(got.flags & PUB_FLAG_HAS_DEDUP, PUB_FLAG_HAS_DEDUP);
            prop_assert_eq!(got.dedup, Some(dedup));
            prop_assert_eq!(got.payload, payload.as_slice());
        }

        #[test]
        fn any_ack_round_trips(op_idx in 0u8..4, offset in any::<u64>(), generation in any::<u64>(), delay_ms in any::<u64>()) {
            let op = AckOp::from_u8(op_idx).unwrap();
            let ack = AckBody { op, offset, generation, delay_ms };
            let mut buf = Vec::new();
            encode_ack(&ack, &mut buf);
            prop_assert_eq!(decode_ack(&buf).unwrap(), ack);
        }

        /// Decoding arbitrary bytes as any fallible body codec (PUB, ACK, DELIVER, DEAD_LETTER,
        /// TRUNCATED) never panics and never reads out of bounds: each returns a typed
        /// `BodyError` or a valid view, the property-level complement to the per-codec fuzz targets.
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode_pub(&bytes);
            let _ = decode_ack(&bytes);
            let _ = decode_deliver(&bytes);
            let _ = decode_dead_letter(&bytes);
            let _ = decode_truncated(&bytes);
            let _ = decode_gap_marker(&bytes);
            let _ = decode_cumulative_ack(&bytes);
            let _ = decode_pub_ack(&bytes);
            // The #292 handshake bodies are attack surface too (a hostile Connect at the server, a
            // hostile Info at the client): decoding any byte string is a typed BodyError or a valid
            // view, never a panic / over-read / over-allocation.
            let _ = decode_connect(&bytes);
            let _ = decode_info(&bytes);
            // SUB is infallible: any byte string is a valid body, and decoding it recovers the
            // exact bytes as the group, so it cannot panic either.
            prop_assert_eq!(decode_sub(&bytes).group, bytes.as_slice());
        }

        #[test]
        fn any_deliver_round_trips(
            offset in any::<u64>(),
            generation in any::<u64>(),
            flags in any::<u8>(),
            timestamp_ms in any::<u64>(),
            key in prop::collection::vec(any::<u8>(), 0..200),
            headers in prop::collection::vec(any::<u8>(), 0..200),
            payload in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let msg = DeliverBody { offset, generation, flags, timestamp_ms, key: &key, headers: &headers, payload: &payload };
            let mut buf = Vec::new();
            encode_deliver(&msg, &mut buf).unwrap();
            prop_assert_eq!(decode_deliver(&buf).unwrap(), msg);
        }

        /// A DEAD_LETTER body round-trips for any offset and reason, and is always exactly the
        /// fixed 9-byte layout (a u64 offset plus a one-byte reason).
        #[test]
        fn any_dead_letter_round_trips(offset in any::<u64>(), reason in any::<u8>()) {
            let advisory = DeadLetterBody { offset, reason };
            let mut buf = Vec::new();
            encode_dead_letter(&advisory, &mut buf);
            prop_assert_eq!(buf.len(), 9, "DEAD_LETTER is a fixed 9-byte body");
            prop_assert_eq!(decode_dead_letter(&buf).unwrap(), advisory);
        }

        /// A TRUNCATED body round-trips for any earliest-retained offset and skipped count, and
        /// is always exactly the fixed 16-byte layout (two LE u64 fields).
        #[test]
        fn any_truncated_round_trips(earliest_retained in any::<u64>(), skipped in any::<u64>()) {
            let advisory = TruncatedBody { earliest_retained, skipped };
            let mut buf = Vec::new();
            encode_truncated(&advisory, &mut buf);
            prop_assert_eq!(buf.len(), 16, "TRUNCATED is a fixed 16-byte body");
            prop_assert_eq!(decode_truncated(&buf).unwrap(), advisory);
        }

        /// A CumulativeAck body round-trips for any up_to and group: the 8-byte LE up_to leads,
        /// then the group is the body tail (any byte string is a valid name, like SUB).
        #[test]
        fn any_cumulative_ack_round_trips(up_to in any::<u64>(), group in prop::collection::vec(any::<u8>(), 0..512)) {
            let ack = CumulativeAckBody { up_to, group: &group };
            let mut buf = Vec::new();
            encode_cumulative_ack(&ack, &mut buf);
            prop_assert_eq!(buf.len(), 8 + group.len());
            prop_assert_eq!(&buf[..8], &up_to.to_le_bytes());
            prop_assert_eq!(decode_cumulative_ack(&buf).unwrap(), ack);
        }

        /// A SUB body is the whole-body-is-the-group case: any byte string is a valid name and
        /// round-trips, and the encoded body is exactly the group bytes (no framing of its own).
        #[test]
        fn any_sub_round_trips(group in prop::collection::vec(any::<u8>(), 0..512)) {
            let mut buf = Vec::new();
            encode_sub(&SubBody { group: &group }, &mut buf);
            prop_assert_eq!(buf.as_slice(), group.as_slice(), "the SUB body is exactly the group name");
            prop_assert_eq!(decode_sub(&buf), SubBody { group: &group });
        }

        /// A Connect body round-trips for any combination of present/absent requested credit and
        /// byte budget (#292) and the appended `default_ack_level` (#494): the version/length framing
        /// is recovered and each optional field comes back exactly as sent (present -> Some(value),
        /// absent -> None), including the raw ack-level byte for every 0..=255 value.
        #[test]
        fn any_connect_round_trips(
            credit in proptest::option::of(any::<u32>()),
            credit_bytes in proptest::option::of(any::<u64>()),
            wants_gap_marker in any::<bool>(),
            default_ack_level in proptest::option::of(any::<u8>()),
        ) {
            let req = ConnectBody { requested_credit: credit, requested_credit_bytes: credit_bytes, wants_gap_marker, default_ack_level };
            let mut buf = Vec::new();
            encode_connect(&req, &mut buf);
            prop_assert_eq!(buf[0], HANDSHAKE_BODY_VERSION, "the body leads with its version");
            prop_assert_eq!(decode_connect(&buf).unwrap(), req);
        }

        /// An Info body round-trips for any combination of present/absent advertised credit and byte
        /// budget (#292), the gap-marker capability bit (#346), and the appended `default_ack_level`
        /// (#494): each survives the round-trip.
        #[test]
        fn any_info_round_trips(
            credit in proptest::option::of((any::<u32>(), any::<u32>())),
            credit_bytes in proptest::option::of((any::<u64>(), any::<u64>())),
            gap_marker in any::<bool>(),
            default_ack_level in proptest::option::of(any::<u8>()),
        ) {
            let info = InfoBody {
                credit: credit.map(|(negotiated, cap)| CreditAdvert { negotiated, cap }),
                credit_bytes: credit_bytes.map(|(negotiated, cap)| CreditAdvert { negotiated, cap }),
                gap_marker,
                default_ack_level,
            };
            let mut buf = Vec::new();
            encode_info(&info, &mut buf);
            prop_assert_eq!(buf[0], HANDSHAKE_BODY_VERSION, "the body leads with its version");
            prop_assert_eq!(decode_info(&buf).unwrap(), info);
        }

        /// A GapMarker body round-trips for any from/to/bytes/reason (#346) and is always exactly the
        /// fixed 25-byte layout (three LE u64 fields then a one-byte reason). Any reason byte is a
        /// valid, tolerated marker (the codec does not validate the reason), so an unknown future
        /// reason still round-trips.
        #[test]
        fn any_gap_marker_round_trips(from in any::<u64>(), to in any::<u64>(), bytes_skipped in any::<u64>(), reason in any::<u8>()) {
            let marker = GapMarkerBody { from, to, bytes_skipped, reason };
            let mut buf = Vec::new();
            encode_gap_marker(&marker, &mut buf);
            prop_assert_eq!(buf.len(), 25, "GapMarker is a fixed 25-byte body");
            prop_assert_eq!(decode_gap_marker(&buf).unwrap(), marker);
        }

        /// FORWARD-COMPAT: a future version may append fields after the v1 block; a v1 reader tolerates
        /// the trailing bytes and still recovers the v1 fields. Appending arbitrary bytes to a v1
        /// Connect/Info body never changes the decoded v1 fields and never errors.
        #[test]
        fn handshake_tolerates_trailing_future_fields(
            credit in proptest::option::of(any::<u32>()),
            trailing in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let req = ConnectBody { requested_credit: credit, requested_credit_bytes: None, wants_gap_marker: false, default_ack_level: None };
            let mut buf = Vec::new();
            encode_connect(&req, &mut buf);
            let mut extended = buf.clone();
            extended.extend_from_slice(&trailing);
            prop_assert_eq!(decode_connect(&extended).unwrap(), req, "trailing future bytes are ignored");

            let info = InfoBody {
                credit: credit.map(|c| CreditAdvert { negotiated: c, cap: c }),
                credit_bytes: None,
                gap_marker: false,
                default_ack_level: None,
            };
            let mut ibuf = Vec::new();
            encode_info(&info, &mut ibuf);
            ibuf.extend_from_slice(&trailing);
            prop_assert_eq!(decode_info(&ibuf).unwrap(), info, "trailing future bytes are ignored");
        }

        /// DECODE SAFETY: a hostile handshake body (an arbitrary version byte and an arbitrary declared
        /// field length, with too few bytes to back it) is a typed BodyError, never a panic or an
        /// over-allocation. The declared `field_len` can claim up to 65535 bytes while the body holds
        /// only a few; the cap-before-alloc `take` rejects it as Truncated.
        #[test]
        fn handshake_oversized_declared_length_is_a_typed_error(
            version in any::<u8>(),
            declared in any::<u16>(),
            tail in prop::collection::vec(any::<u8>(), 0..8),
        ) {
            let mut buf = vec![version];
            buf.extend_from_slice(&declared.to_le_bytes());
            buf.extend_from_slice(&tail);
            // Whatever the inputs, decode returns a typed Result and never panics or over-allocates.
            let c = decode_connect(&buf);
            let i = decode_info(&buf);
            if version != HANDSHAKE_BODY_VERSION {
                prop_assert_eq!(c, Err(BodyError::BadHandshakeVersion { version }));
                prop_assert_eq!(i, Err(BodyError::BadHandshakeVersion { version }));
            } else if usize::from(declared) > tail.len() {
                prop_assert_eq!(c, Err(BodyError::Truncated));
                prop_assert_eq!(i, Err(BodyError::Truncated));
            } else {
                prop_assert!(c.is_ok() && i.is_ok());
            }
        }

        /// A Fetch body round-trips every field for any inputs (#489): the encoder is the exact inverse
        /// of the decoder, and the `no_wait` flag bit and the field agree.
        #[test]
        fn any_fetch_round_trips(
            max_records in any::<u32>(),
            max_bytes in any::<u64>(),
            expires_ms in any::<u64>(),
            no_wait in any::<bool>(),
        ) {
            let req = FetchBody { max_records, max_bytes, expires_ms, no_wait };
            let mut buf = Vec::new();
            encode_fetch(&req, &mut buf);
            prop_assert_eq!(decode_fetch(&buf).unwrap(), req);
        }

        /// Decoding ARBITRARY bytes as a Fetch body never panics and never over-allocates: a hostile
        /// version/length is always a typed Result, mirroring the handshake-body fuzz property.
        #[test]
        fn decode_fetch_on_arbitrary_bytes_never_panics(
            bytes in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let _ = decode_fetch(&bytes);
        }
    }

    #[test]
    fn empty_connect_body_is_the_old_client_no_request() {
        // The historical empty Connect body (an old client) decodes to all-absent: the server then
        // uses its defaults. This is the backward-compat anchor in the client->server direction.
        assert_eq!(decode_connect(&[]).unwrap(), ConnectBody::default());
        assert_eq!(
            decode_connect(&[]).unwrap(),
            ConnectBody {
                requested_credit: None,
                requested_credit_bytes: None,
                wants_gap_marker: false,
                default_ack_level: None,
            }
        );
    }

    #[test]
    fn empty_info_body_is_the_old_server_no_advert() {
        // The historical empty Info body (an old server) decodes to all-absent: a new client keeps its
        // own local credit. This is the backward-compat anchor in the server->client direction.
        assert_eq!(decode_info(&[]).unwrap(), InfoBody::default());
        assert_eq!(
            decode_info(&[]).unwrap(),
            InfoBody {
                credit: None,
                credit_bytes: None,
                gap_marker: false,
                default_ack_level: None,
            }
        );
    }

    #[test]
    fn connect_round_trips_a_full_request() {
        let req = ConnectBody {
            requested_credit: Some(32),
            requested_credit_bytes: Some(1024),
            wants_gap_marker: true,
            default_ack_level: None,
        };
        let mut buf = Vec::new();
        encode_connect(&req, &mut buf);
        // version(1) + field_len(2) + flags(1) + credit(4) + credit_bytes(8) = 16 bytes. The gap-marker
        // capability is a pure flags bit, so it adds NO bytes to the v1 field block, and a `None`
        // default_ack_level (#494) appends NO byte, so a full request is still the historical length.
        assert_eq!(buf.len(), 3 + usize::from(CONNECT_V1_FIELD_LEN));
        assert_eq!(buf[0], HANDSHAKE_BODY_VERSION);
        assert_eq!(decode_connect(&buf).unwrap(), req);
    }

    #[test]
    fn info_round_trips_a_full_advert() {
        let info = InfoBody {
            credit: Some(CreditAdvert {
                negotiated: 32,
                cap: 64,
            }),
            credit_bytes: Some(CreditAdvert {
                negotiated: 1024,
                cap: 8 * 1024 * 1024,
            }),
            gap_marker: true,
            default_ack_level: None,
        };
        let mut buf = Vec::new();
        encode_info(&info, &mut buf);
        // The gap-marker confirmation is a pure flags bit, so it adds NO bytes to the v1 field block,
        // and a `None` default_ack_level (#494) appends NO byte, so a full advert is the historical len.
        assert_eq!(buf.len(), 3 + usize::from(INFO_V1_FIELD_LEN));
        assert_eq!(buf[0], HANDSHAKE_BODY_VERSION);
        assert_eq!(decode_info(&buf).unwrap(), info);
    }

    #[test]
    fn handshake_rejects_an_unknown_body_version() {
        // version 2 is unknown to this v1 reader: a typed error, never a best-effort parse.
        let buf = [2u8, 0, 0];
        assert_eq!(
            decode_connect(&buf),
            Err(BodyError::BadHandshakeVersion { version: 2 })
        );
        assert_eq!(
            decode_info(&buf),
            Err(BodyError::BadHandshakeVersion { version: 2 })
        );
    }

    #[test]
    fn handshake_rejects_a_declared_length_past_the_body() {
        // version 1, field_len = 0xffff, but no field bytes follow: cap-before-alloc Truncated.
        let mut buf = vec![HANDSHAKE_BODY_VERSION];
        buf.extend_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode_connect(&buf), Err(BodyError::Truncated));
        assert_eq!(decode_info(&buf), Err(BodyError::Truncated));
    }

    #[test]
    fn handshake_header_alone_without_a_block_is_truncated() {
        // A single version byte with no u16 length is too short for the header.
        assert_eq!(
            decode_connect(&[HANDSHAKE_BODY_VERSION]),
            Err(BodyError::Truncated)
        );
        assert_eq!(
            decode_info(&[HANDSHAKE_BODY_VERSION]),
            Err(BodyError::Truncated)
        );
    }

    // -----------------------------------------------------------------------
    // #494 — produce ack-level wire encoding (part of #499). PROTO/CODEC ONLY.
    // -----------------------------------------------------------------------

    #[test]
    fn ack_level_bits_are_genuinely_free_and_distinct() {
        // The 2 ack-level bits (3 and 4) sit ABOVE the stored record flags (RecordFlags::KNOWN = bits
        // 0..=2) and BELOW the existing wire-only bits (faf bit 6, dedup bit 7), colliding with
        // neither. This pins the chosen free bits so a future flag steals a different bit, not these.
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK, 0b0001_1000);
        assert_eq!(PUB_FLAG_ACK_LEVEL_SHIFT, 3);
        // No overlap with the other wire-only bits.
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK & PUB_FLAG_FIRE_AND_FORGET, 0);
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK & PUB_FLAG_HAS_DEDUP, 0);
        // No overlap with the stored record flags (the low 3 bits, RecordFlags::KNOWN = 0b111).
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK & 0b0000_0111, 0);
        // And the full wire-only mask is exactly the union of the three.
        assert_eq!(
            PUB_WIRE_ONLY_FLAGS,
            PUB_FLAG_HAS_DEDUP | PUB_FLAG_FIRE_AND_FORGET | PUB_FLAG_ACK_LEVEL_MASK
        );
        assert_eq!(PUB_WIRE_ONLY_FLAGS, 0b1101_1000);
    }

    #[test]
    fn pub_ack_level_default_and_faf_and_levels() {
        // flags == 0 (neither faf nor a level bit): an OLD client, which MUST mean Level 1.
        assert_eq!(pub_ack_level(0), AckLevel::ServerAck);
        // The canonical Level-0 encoding is the fire-and-forget bit (an old faf publish IS Level 0).
        assert_eq!(pub_ack_level(PUB_FLAG_FIRE_AND_FORGET), AckLevel::NoAck);
        // The level-bit ALIAS for Level 0 (raw value 1, bit 3) also reads as Level 0.
        assert_eq!(pub_ack_level(0b0000_1000), AckLevel::NoAck);
        // Raw value 2 (bit 4) is Level 2.
        assert_eq!(pub_ack_level(0b0001_0000), AckLevel::ServerAndClientAck);
        // The RESERVED raw value 3 (both bits) decodes to the safe Level-1 default, never an error.
        assert_eq!(pub_ack_level(0b0001_1000), AckLevel::ServerAck);
        // The faf bit DOMINATES any level bits (Level 0 wins).
        assert_eq!(
            pub_ack_level(PUB_FLAG_FIRE_AND_FORGET | 0b0001_0000),
            AckLevel::NoAck
        );
        // Stored record flags (low bits) and the other wire bits never perturb the read level.
        assert_eq!(pub_ack_level(0b1000_0111), AckLevel::ServerAck);
        // The enum's raw values are the frozen wire numbers.
        assert_eq!(AckLevel::NoAck.as_u8(), 0);
        assert_eq!(AckLevel::ServerAck.as_u8(), 1);
        assert_eq!(AckLevel::ServerAndClientAck.as_u8(), 2);
        // The default level is Level 1 (server ack), matching the old-client default.
        assert_eq!(AckLevel::default(), AckLevel::ServerAck);
    }

    #[test]
    fn pub_preserves_caller_ack_level_bits_and_masks_them_off_the_stored_record() {
        // A producer sets the Level-2 bits in `flags`; encode PRESERVES them (only dedup/faf are
        // re-derived), so a decode reports Level 2. The server's `flags & !PUB_WIRE_ONLY_FLAGS` then
        // strips them so the stored record flag is byte-for-byte unchanged. `HAS_KEY` (bit 1) mirrors
        // `ironbus_core::types::RecordFlags::HAS_KEY`, a genuine stored record flag, asserted here
        // WITHOUT an ironbus-core dependency so this stays a pure proto-crate test.
        const HAS_KEY: u8 = 0b0000_0010;
        let level2 = (AckLevel::ServerAndClientAck.as_u8() << PUB_FLAG_ACK_LEVEL_SHIFT)
            & PUB_FLAG_ACK_LEVEL_MASK;
        let msg = PubBody {
            flags: HAS_KEY | level2,
            timestamp_ms: 7,
            key: b"k",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"p",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        // The ack-level bits survive the encode (carried in flags, not stripped).
        assert_eq!(buf[0] & PUB_FLAG_ACK_LEVEL_MASK, level2);
        let got = decode_pub(&buf).unwrap();
        assert_eq!(pub_ack_level(got.flags), AckLevel::ServerAndClientAck);
        // The stored record flags (what the server keeps) drop every wire-only bit, leaving only the
        // genuine record flag the caller set (HAS_KEY, bit 1).
        assert_eq!(
            got.flags & !PUB_WIRE_ONLY_FLAGS,
            HAS_KEY,
            "ack-level bits are masked OUT of the stored record flags"
        );
    }

    #[test]
    fn a_pre_feature_pub_round_trips_byte_identical() {
        // OLD-CLIENT BYTE-IDENTITY: a publish a pre-#494 client built (no faf, no ack-level bit, only
        // a genuine stored record flag) must encode to EXACTLY the frozen historical bytes, decode as
        // Level 1 (today's behavior), and have its stored-record flag unchanged. Build the expected
        // historical body by hand and compare byte-for-byte.
        let msg = PubBody {
            flags: 0b0000_0010, // HAS_KEY, a genuine stored record flag — no wire-only bits
            timestamp_ms: 0x0102_0304_0506_0708,
            key: b"key",
            headers: b"hd",
            dedup: None,
            fire_and_forget: false,
            payload: b"payload",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        let mut expected = Vec::new();
        expected.push(0b0000_0010);
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        expected.extend_from_slice(&3u16.to_le_bytes());
        expected.extend_from_slice(b"key");
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(b"hd");
        expected.extend_from_slice(b"payload");
        assert_eq!(
            buf, expected,
            "a pre-#494 PUB is byte-for-byte the frozen historical layout"
        );
        // It decodes as Level 1 (the old-client default) and its stored flag is unchanged.
        let got = decode_pub(&buf).unwrap();
        assert_eq!(pub_ack_level(got.flags), AckLevel::ServerAck);
        assert_eq!(got.flags & !PUB_WIRE_ONLY_FLAGS, 0b0000_0010);
    }

    #[test]
    fn produce_confirm_round_trips_every_status() {
        for status in [
            produce_confirm_status::CONSUMED,
            produce_confirm_status::TIMED_OUT,
            produce_confirm_status::DEAD_LETTERED,
        ] {
            let confirm = ProduceConfirmBody {
                offset: 0x0102_0304_0506_0708,
                status,
            };
            let mut buf = Vec::new();
            encode_produce_confirm(&confirm, &mut buf);
            assert_eq!(buf.len(), 9, "fixed 9-byte body: u64 offset + u8 status");
            assert_eq!(&buf[..8], &confirm.offset.to_le_bytes(), "offset leads, LE");
            assert_eq!(buf[8], status);
            assert_eq!(decode_produce_confirm(&buf).unwrap(), confirm);
        }
    }

    #[test]
    fn produce_confirm_tolerates_an_unknown_status() {
        // An unknown future status byte (e.g. 200) is a VALID, tolerated confirmation decoded
        // verbatim, never an error: the status field can grow without a new frame.
        let confirm = ProduceConfirmBody {
            offset: 42,
            status: 200,
        };
        let mut buf = Vec::new();
        encode_produce_confirm(&confirm, &mut buf);
        assert_eq!(decode_produce_confirm(&buf).unwrap(), confirm);
    }

    #[test]
    fn produce_confirm_rejects_a_short_or_overlong_body() {
        assert_eq!(decode_produce_confirm(&[0u8; 8]), Err(BodyError::Truncated));
        assert_eq!(
            decode_produce_confirm(&[0u8; 10]),
            Err(BodyError::TrailingBytes)
        );
    }

    #[test]
    fn produce_confirm_status_tags_have_their_frozen_wire_values() {
        assert_eq!(produce_confirm_status::CONSUMED, 0);
        assert_eq!(produce_confirm_status::TIMED_OUT, 1);
        assert_eq!(produce_confirm_status::DEAD_LETTERED, 2);
    }

    #[test]
    fn connect_carries_the_default_ack_level_and_old_client_is_byte_identical() {
        // An OLD client (or one that defers) leaves `default_ack_level` None: the encoded body is
        // byte-for-byte the pre-#494 Connect (no appended byte, the historical field_len). Compare the
        // two encodings directly.
        let no_level = ConnectBody {
            requested_credit: Some(7),
            requested_credit_bytes: None,
            wants_gap_marker: false,
            default_ack_level: None,
        };
        let mut pre = Vec::new();
        encode_connect(&no_level, &mut pre);
        // The historical body: version + field_len(=CONNECT_V1_FIELD_LEN) + the v1 fixed fields, with
        // the HAS_DEFAULT_ACK_LEVEL bit CLEAR and no appended byte.
        assert_eq!(
            &pre[1..3],
            &CONNECT_V1_FIELD_LEN.to_le_bytes(),
            "a None default keeps the historical field_len"
        );
        assert_eq!(
            pre[3] & CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL,
            0,
            "the presence bit is clear for a None default"
        );
        assert_eq!(
            pre.len(),
            3 + usize::from(CONNECT_V1_FIELD_LEN),
            "no appended byte"
        );
        assert_eq!(decode_connect(&pre).unwrap(), no_level);

        // A NEW client that DOES request a default appends exactly one byte and sets the presence bit.
        let with_level = ConnectBody {
            default_ack_level: Some(AckLevel::ServerAndClientAck.as_u8()),
            ..no_level
        };
        let mut buf = Vec::new();
        encode_connect(&with_level, &mut buf);
        assert_eq!(
            &buf[1..3],
            &CONNECT_V1_FIELD_LEN_WITH_ACK_LEVEL.to_le_bytes(),
            "a Some default grows field_len by one byte"
        );
        assert_eq!(
            buf[3] & CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL,
            CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL
        );
        assert_eq!(buf.len(), pre.len() + 1, "exactly one appended byte");
        assert_eq!(*buf.last().unwrap(), AckLevel::ServerAndClientAck.as_u8());
        assert_eq!(decode_connect(&buf).unwrap(), with_level);
    }

    #[test]
    fn info_carries_the_default_ack_level_and_old_server_is_byte_identical() {
        let no_level = InfoBody {
            credit: None,
            credit_bytes: None,
            gap_marker: false,
            default_ack_level: None,
        };
        let mut pre = Vec::new();
        encode_info(&no_level, &mut pre);
        assert_eq!(&pre[1..3], &INFO_V1_FIELD_LEN.to_le_bytes());
        assert_eq!(pre[3] & INFO_FLAG_HAS_DEFAULT_ACK_LEVEL, 0);
        assert_eq!(pre.len(), 3 + usize::from(INFO_V1_FIELD_LEN));
        assert_eq!(decode_info(&pre).unwrap(), no_level);

        let with_level = InfoBody {
            default_ack_level: Some(2),
            ..no_level
        };
        let mut buf = Vec::new();
        encode_info(&with_level, &mut buf);
        assert_eq!(&buf[1..3], &INFO_V1_FIELD_LEN_WITH_ACK_LEVEL.to_le_bytes());
        assert_eq!(
            buf[3] & INFO_FLAG_HAS_DEFAULT_ACK_LEVEL,
            INFO_FLAG_HAS_DEFAULT_ACK_LEVEL
        );
        assert_eq!(buf.len(), pre.len() + 1);
        assert_eq!(*buf.last().unwrap(), 2);
        assert_eq!(decode_info(&buf).unwrap(), with_level);
    }

    #[test]
    fn old_connect_info_decode_under_new_reader_yields_none_default_ack_level() {
        // FORWARD/BACKWARD COMPAT: a body the OLD (pre-#494) encoder produced — the historical fixed
        // v1 block with NO appended ack-level byte and the presence bit clear — decodes under the new
        // reader with `default_ack_level: None`, every other field intact. Build the historical bodies
        // by hand (independent of the new encoder) and decode them.
        let mut connect = vec![HANDSHAKE_BODY_VERSION];
        connect.extend_from_slice(&CONNECT_V1_FIELD_LEN.to_le_bytes());
        connect.push(CONNECT_FLAG_HAS_CREDIT); // only the credit presence bit
        connect.extend_from_slice(&9u32.to_le_bytes()); // requested_credit = 9
        connect.extend_from_slice(&0u64.to_le_bytes()); // requested_credit_bytes
        assert_eq!(
            decode_connect(&connect).unwrap(),
            ConnectBody {
                requested_credit: Some(9),
                requested_credit_bytes: None,
                wants_gap_marker: false,
                default_ack_level: None,
            }
        );

        let mut info = vec![HANDSHAKE_BODY_VERSION];
        info.extend_from_slice(&INFO_V1_FIELD_LEN.to_le_bytes());
        info.push(0); // no presence bits
        info.extend_from_slice(&0u32.to_le_bytes()); // credit.negotiated
        info.extend_from_slice(&0u32.to_le_bytes()); // credit.cap
        info.extend_from_slice(&0u64.to_le_bytes()); // credit_bytes.negotiated
        info.extend_from_slice(&0u64.to_le_bytes()); // credit_bytes.cap
        assert_eq!(
            decode_info(&info).unwrap(),
            InfoBody {
                credit: None,
                credit_bytes: None,
                gap_marker: false,
                default_ack_level: None,
            }
        );
    }
}
