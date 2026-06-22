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

/// The PUB-body WIRE flag bit that signals an OPT-IN idempotent-producer SEQUENCE rides the dedup
/// block (V2-M8, #638): an extra `u64 sequence` follows the `(producer_id, epoch, msg_id)` dedup
/// block when set. It is the Kafka-style monotonic per-producer sequence the broker deduplicates a
/// RETRIED publish on to exactly-once-append, fences a zombie epoch on, and rejects an out-of-order
/// gap on — the EFFECTIVELY-ONCE primitive that survives a restart + a long offline gap (where the
/// time-bounded `msg_id` window, like NATS's `Nats-Msg-Id`, lapses).
///
/// It is VALID only ALONGSIDE [`PUB_FLAG_HAS_DEDUP`] (the sequence rides inside the dedup block,
/// after the `msg_id`), so a `seq` without a dedup block is a malformed body the decoder rejects.
/// Like the other wire-only bits it is a WIRE-ONLY flag on the PUB body's `flags` byte, masked OUT
/// ([`PUB_WIRE_ONLY_FLAGS`]) before the byte becomes a stored record flag. It sits at bit 5
/// (`0b0010_0000`), between the ack-level field (bits 3..=4) and the fire-and-forget bit (bit 6), so
/// it collides with none of them. A producer that does not use sequence-based idempotence leaves
/// this bit clear, so the body is byte-for-byte the existing (dedup-or-not) layout (additive,
/// opt-in): the existing `msg_id`-only dedup path is UNCHANGED.
pub const PUB_FLAG_HAS_SEQ: u8 = 0b0010_0000;

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
    PUB_FLAG_HAS_DEDUP | PUB_FLAG_FIRE_AND_FORGET | PUB_FLAG_ACK_LEVEL_MASK | PUB_FLAG_HAS_SEQ;

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

/// The consume TIER a consumer reads a log at (#543, V2-M1, the consume spine of #544). The storage
/// log is identical for both tiers; only the per-CONSUMER consume bookkeeping differs, so the tier is
/// a per-consumer choice the broker honors per subscription, never a per-stream property. It rides the
/// `Connect`/`Info` handshake as a connection-wide DEFAULT (see [`ConnectBody::default_tier`]) which a
/// subscription adopts unless it explicitly picks a tier (the #544 per-subscription selection still
/// overrides). PROTO/CODEC + SELECTION metadata only: it changes no storage and no ack/durability path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ConsumeTier {
    /// Tier-W (work-queue): the existing default — per-message lease + generation fence + visibility
    /// timeout + per-message ack + DLQ + key-shared. This is today's behavior EXACTLY and the DEFAULT,
    /// so a connection that negotiates nothing (and an old client) consumes at Tier-W, byte-for-byte
    /// unchanged.
    #[default]
    Work,
    /// Tier-S (streaming, #544): the CONSUMER manages its own offset; the broker serves a contiguous
    /// batch with no per-record lease/fence/cursor write, and the ack is a periodic cumulative
    /// `StreamCommit`. A connection reaches Tier-S only when it advertised it UNDERSTANDS streaming (the
    /// [`CONNECT_FLAG_UNDERSTANDS_STREAMING`] capability bit), so a pre-streaming client never lands here.
    Streaming,
}

impl ConsumeTier {
    /// The raw `u8` this tier encodes into the appended `default_tier` byte of the handshake bodies
    /// (`0` = Tier-W, `1` = Tier-S). Carried raw so a FUTURE tier the proto does not yet name still
    /// round-trips the wire as an opaque byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            ConsumeTier::Work => 0,
            ConsumeTier::Streaming => 1,
        }
    }

    /// Folds a raw handshake `default_tier` byte into a [`ConsumeTier`]: `1` is Tier-S; EVERYTHING else
    /// — `0` (the explicit Tier-W / old-client encoding) and any RESERVED future value — folds to the
    /// safe Tier-W default rather than erroring, so the field can grow without a wire break and a peer
    /// that names a tier this build does not understand degrades to today's work-queue behavior.
    #[must_use]
    pub fn from_u8(raw: u8) -> ConsumeTier {
        match raw {
            1 => ConsumeTier::Streaming,
            _ => ConsumeTier::Work,
        }
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
    /// The OPT-IN Kafka-style idempotent-producer SEQUENCE (V2-M8, #638): a per-producer MONOTONIC
    /// sequence the broker deduplicates a RETRIED publish on to exactly-once-append, surviving a
    /// restart + a long offline gap. `Some` iff the wire [`PUB_FLAG_HAS_SEQ`] bit was set (it rides
    /// inside this dedup block, after the `msg_id`); `None` for the existing `msg_id`-window dedup,
    /// which is then byte-for-byte unchanged. A `seq <= last-accepted` is a duplicate (return the
    /// original offset), `seq == last + 1` is fresh, a gap is rejected (out-of-order), and the
    /// producer's `epoch` fences a zombie session.
    pub seq: Option<u64>,
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
    let mut flags = msg.flags & !(PUB_FLAG_HAS_DEDUP | PUB_FLAG_FIRE_AND_FORGET | PUB_FLAG_HAS_SEQ);
    if msg.dedup.is_some() {
        flags |= PUB_FLAG_HAS_DEDUP;
    }
    // The idempotent-producer SEQUENCE bit (V2-M8) is derived from the field too, so it and the body
    // can never disagree. It rides INSIDE the dedup block (a `seq` is meaningless without a producer
    // identity), so it is only ever set when the dedup block is also present.
    if msg.dedup.is_some_and(|d| d.seq.is_some()) {
        flags |= PUB_FLAG_HAS_SEQ;
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
        // The opt-in idempotent SEQUENCE (V2-M8) is the LAST field of the dedup block when present,
        // so the historical dedup-block layout (no seq) is byte-for-byte unchanged.
        if let Some(seq) = dedup.seq {
            out.extend_from_slice(&seq.to_le_bytes());
        }
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
        // The opt-in idempotent SEQUENCE (V2-M8) is the LAST field of the dedup block, present iff
        // the wire bit is set; absent leaves the historical dedup-block layout byte-for-byte
        // unchanged. A `seq` bit WITHOUT a dedup block never reaches here (the bit only rides inside
        // this block), but if a malformed body sets the seq bit and the body is too short for the
        // u64, `r.u64()?` returns a typed `BodyError` rather than panicking.
        let seq = if flags & PUB_FLAG_HAS_SEQ != 0 {
            Some(r.u64()?)
        } else {
            None
        };
        Some(PubDedup {
            producer_id,
            epoch,
            msg_id,
            seq,
        })
    } else {
        // A `seq` bit set WITHOUT a dedup block is a protocol violation (the sequence rides inside
        // the dedup block, after the `msg_id`): fail closed rather than silently fold the would-be
        // sequence into the payload. The encoder never produces this; a malformed peer does.
        if flags & PUB_FLAG_HAS_SEQ != 0 {
            return Err(BodyError::BadLength);
        }
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

/// The version of the [`crate::frame::FrameType::DeliverBatch`] (raw-framed batch delivery, tag 26)
/// HEADER framing (#541, M1-I5). Version `1` is the first (and only) layout. Carried as a leading byte
/// so a future version can extend the header without a wire break: a reader rejects a version it does
/// not understand rather than mis-parsing it, exactly like [`STREAM_FETCH_BODY_VERSION`].
pub const DELIVER_BATCH_HEADER_VERSION: u8 = 1;

/// The FIXED header of a [`crate::frame::FrameType::DeliverBatch`] frame (#541, M1-I5): the small,
/// length-framed prefix that precedes the contiguous ON-DISK record-frame bytes in the frame body. It
/// is the RAW-FRAMED batch delivery's only re-encoded part — the records themselves ship as their
/// stored bytes VERBATIM (the broker never re-encodes per record), so a later disk `sendfile(2)` path
/// (#658) can splice the segment's page-cache bytes straight in after this header.
///
/// ## Why an on-disk body, and how the client reconstructs offsets
///
/// The on-disk record frame carries `seq` (its in-segment sequence), NOT the log `offset` the on-wire
/// [`DeliverBody`] carries. A contiguous run is DENSE and offset-ordered, so the client reconstructs
/// each record's offset POSITIONALLY: the i-th frame in the body has offset `first_offset + i`. The
/// header therefore carries only `first_offset` (the run's base) — the client never needs the per-record
/// seq->offset mapping, it just increments. `generation` is the lease fencing token to carry on an ack;
/// for the Tier-S streaming path (#544, the first user of this frame) it is `0`, exactly as the
/// per-record `Deliver` on that path. `record_count` lets the client size its work and validate it
/// decoded exactly the frames the broker counted.
///
/// ## CRC integrity end-to-end
///
/// Each on-disk record frame in the body still carries its own header CRC32C and body CRC32C (and the
/// optional xxh3-64 for a large body). The broker copies the bytes without touching them, so the
/// consumer verifies every record exactly as it verifies a per-record `Deliver` — integrity is moved to
/// the only place that still decodes the bytes (the client), never silently dropped.
///
/// Layout (version+length framed, forward-compatible, mirroring [`StreamFetchBody`]): `header_version:
/// u8` ([`DELIVER_BATCH_HEADER_VERSION`]), `field_len: u16` (the length of the v1 known-field block that
/// follows), then the v1 block: `first_offset: u64 LE`, `generation: u64 LE`, `record_count: u32 LE`.
/// Bytes past `field_len` (a future version's appended header fields) are TOLERATED and ignored by a v1
/// reader; everything AFTER the declared block is the contiguous on-disk record-frame bytes (the batch
/// body), returned to the caller as a borrowed slice so it can be decoded (or spliced) without a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliverBatchHeader {
    /// The log offset of the FIRST record in the batch body. The i-th on-disk frame in the body has
    /// offset `first_offset + i` (the run is dense and contiguous), which is how the client reconstructs
    /// per-record offsets without reading each frame's stored `seq`.
    pub first_offset: u64,
    /// The lease generation to carry on the ack for these records (the fencing token). `0` on the
    /// lease-free Tier-S streaming path (#544), matching the per-record `Deliver`'s `generation` there.
    pub generation: u64,
    /// How many complete on-disk record frames the batch body carries. The client asserts it decodes
    /// exactly this many whole frames with no partial tail.
    pub record_count: u32,
}

/// The number of bytes in the `DeliverBatch` header v1 known-field block: `first_offset: u64` +
/// `generation: u64` + `record_count: u32`.
const DELIVER_BATCH_V1_FIELD_LEN: u16 = 8 + 8 + 4;

/// Encodes a `DeliverBatch` frame body onto the end of `out` (#541): the header version byte, the v1
/// field-block length, the v1 block, then the contiguous on-disk record-frame bytes VERBATIM. `record_bytes`
/// is the concatenation of `header.record_count` complete on-disk frames (e.g. an `ironbus-storage`
/// `RawByteRun`'s bytes), copied through UNCHANGED so each record's CRC ships end-to-end. The fixed header
/// precedes the variable body, so a future `sendfile(2)` path writes this header then splices the stored
/// bytes.
pub fn encode_deliver_batch(header: &DeliverBatchHeader, record_bytes: &[u8], out: &mut Vec<u8>) {
    out.push(DELIVER_BATCH_HEADER_VERSION);
    out.extend_from_slice(&DELIVER_BATCH_V1_FIELD_LEN.to_le_bytes());
    out.extend_from_slice(&header.first_offset.to_le_bytes());
    out.extend_from_slice(&header.generation.to_le_bytes());
    out.extend_from_slice(&header.record_count.to_le_bytes());
    out.extend_from_slice(record_bytes);
}

/// Decodes a `DeliverBatch` frame body (#541) into its fixed [`DeliverBatchHeader`] and a BORROWED slice
/// of the contiguous on-disk record-frame bytes that follow it, cap-before-alloc and panic-free.
///
/// The body MUST carry the version byte and the `u16` field-length; the v1 known fields are read from the
/// front of the declared block and any trailing bytes WITHIN the block (a future version's appended header
/// fields) are tolerated and ignored. Everything AFTER the declared block is the record-bytes slice,
/// returned by reference so the caller decodes (or splices) it with no copy. A body too short to hold the
/// `field_len` it declares is a typed [`BodyError`], never a panic or an over-read (the `field_len` is
/// bounded against the actual body by [`Reader::take`] BEFORE any read). An EMPTY body is NOT a valid
/// `DeliverBatch` (the frame type is new, with no historical empty case), so it is a typed
/// [`BodyError::Truncated`].
///
/// This decodes ONLY the wire framing; the per-record on-disk frames in `record_bytes` are decoded by the
/// storage/record codec (`ironbus_core::codec::decode`), kept out of this dependency-light proto crate.
///
/// # Errors
/// Returns [`BodyError::Truncated`] if the body is too short for the version/length header or the declared
/// field block, or [`BodyError::BadHandshakeVersion`] for an unknown header version.
pub fn decode_deliver_batch(body: &[u8]) -> Result<(DeliverBatchHeader, &[u8]), BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != DELIVER_BATCH_HEADER_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    // Everything after the declared header block is the contiguous on-disk record-frame bytes.
    let record_bytes = r.rest();
    let mut fr = Reader::new(block);
    // Every v1 slot occupies a fixed position and is always consumed in order; a short block (a sender
    // that declared fewer bytes) reads what is present and defaults the rest, never panicking.
    let first_offset = fr.u64().unwrap_or(0);
    let generation = fr.u64().unwrap_or(0);
    let record_count = fr.u32().unwrap_or(0);
    Ok((
        DeliverBatchHeader {
            first_offset,
            generation,
            record_count,
        },
        record_bytes,
    ))
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

/// The version of the [`crate::frame::FrameType::NotLeader`] redirect body (#735). Version `1` is the
/// first (and only) layout: a `body_version: u8` followed by the leader-hint address as a
/// u16-length-prefixed UTF-8 string. The version byte lets a future field be appended after the address
/// without a new frame tag (an old reader stops at the address it knows). A NON-cluster broker NEVER
/// emits this frame, so it never appears on a single-node wire.
pub const NOT_LEADER_BODY_VERSION: u8 = 1;

/// A cluster `NotLeader` produce-redirect body (the [`crate::frame::FrameType::NotLeader`] frame, #735):
/// the server tells a producer that the node it produced to is NOT the current leader of the target
/// (clustered) partition, carrying a LEADER HINT — the current committed leader's CLIENT-facing address —
/// so the client transparently reconnects/retries to the leader. The redirect happens BEFORE any local
/// append or ack, so a redirected produce is never acked by the wrong node (no double-append, no false
/// ack).
///
/// Layout (version-prefixed, forward-compatible): `body_version: u8` ([`NOT_LEADER_BODY_VERSION`]), then
/// the `leader_hint` address as a u16-length-prefixed UTF-8 string. The hint is EMPTY (a zero-length
/// string) when the current leader's client address is not yet known to this node (e.g. mid-failover, or
/// the leader has not advertised a client address); the client then falls back to re-discovering the
/// leader from its own known peer set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotLeaderBody<'a> {
    /// The current leader's CLIENT-facing address (e.g. `"127.0.0.1:9000"`), or the EMPTY string when
    /// this node does not yet know it. Borrowed from the decoded frame body (UTF-8 validated by the
    /// caller — the bytes are taken verbatim here so the codec stays panic-free and allocation-free).
    pub leader_hint: &'a str,
}

/// Encodes a `NotLeader` body onto the end of `out`: the version byte then the u16-length-prefixed
/// leader-hint address.
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if `leader_hint` exceeds the `u16` wire field limit (an address
/// is far shorter, so this is unreachable in practice).
pub fn encode_not_leader(redirect: &NotLeaderBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    out.push(NOT_LEADER_BODY_VERSION);
    push_var(out, redirect.leader_hint.as_bytes())
}

/// Decodes a `NotLeader` body: the version byte then the u16-length-prefixed leader-hint address. The
/// `body_version` is NOT rejected if unknown (a future version is forward-compatible: the v1 address
/// field is still read, and any appended bytes past it are tolerated and ignored), so a newer server's
/// extended redirect still routes an older client. The address must be valid UTF-8 (an address always
/// is); a non-UTF-8 hint is a [`BodyError::Truncated`]-class malformed body.
///
/// # Errors
/// Returns a [`BodyError`] on a short body (no version byte / a length field exceeding the body) or a
/// non-UTF-8 leader-hint.
pub fn decode_not_leader(body: &[u8]) -> Result<NotLeaderBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    // Read and discard the version byte: v1 is the only layout, but an unknown future version still
    // carries the v1 address field first, so we stay forward-compatible by reading the field regardless.
    let _body_version = r.u8()?;
    let hint_bytes = r.var()?;
    // Trailing bytes past the v1 address are a FUTURE version's appended fields: tolerated and ignored
    // (no `at_end` check), so a newer server's extended redirect still decodes here.
    let leader_hint = core::str::from_utf8(hint_bytes).map_err(|_| BodyError::Truncated)?;
    Ok(NotLeaderBody { leader_hint })
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

/// The `Connect` CAPABILITY bit (#543, V2-M1) by which a consumer advertises that it UNDERSTANDS the
/// streaming consume tier (Tier-S: the `StreamFetch`/`StreamCommit` consumer-managed-offset path, #544).
/// When set, the server may serve this connection at Tier-S — including honoring a Tier-S
/// [`ConnectBody::default_tier`] so an unmarked subscription streams. When CLEAR (an old client, or one
/// that opts out) the connection ALWAYS consumes at Tier-W (the work-queue default), byte-for-byte
/// today's behavior, and a Tier-S default it might have sent is ignored — a pre-streaming client can
/// never be silently moved onto a tier it does not understand. Like [`CONNECT_FLAG_WANTS_GAP_MARKER`]
/// it is a pure capability flag (no associated value), so it occupies no slot in the v1 field block
/// beyond this `flags` bit.
pub const CONNECT_FLAG_UNDERSTANDS_STREAMING: u8 = 0b0001_0000;

/// The `Connect` presence-flag bit (#543, V2-M1) signalling that a `default_tier` (the connection-wide
/// default consume tier a subscription adopts when it does not pick its own) is present and meaningful.
/// When clear (an old client, or one that defers) the client requests NO default tier and the server
/// applies Tier-W (the work-queue default). The tier VALUE is an APPENDED v1-block byte (see
/// [`ConnectBody`], folded via [`ConsumeTier::from_u8`]); this presence bit governs only whether that
/// byte is meaningful, mirroring [`CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL`], so the field is
/// forward+backward compatible (an old body omits the byte and leaves this bit clear). The default is
/// only HONORED when the streaming capability bit ([`CONNECT_FLAG_UNDERSTANDS_STREAMING`]) is also set;
/// a default of Tier-S without the capability bit is ignored (the connection stays Tier-W).
pub const CONNECT_FLAG_HAS_DEFAULT_TIER: u8 = 0b0010_0000;

/// The `Connect` CAPABILITY bit (#541, M1-I5) by which a consumer advertises that it UNDERSTANDS the
/// raw-framed [`crate::frame::FrameType::DeliverBatch`] frame (tag 26): when set, the server MAY ship a
/// contiguous delivery run as ONE `DeliverBatch` whose body carries the records' on-disk frame bytes
/// verbatim, instead of N per-record [`crate::frame::FrameType::Deliver`] frames. When CLEAR (an old
/// client, or one that opts out) the server keeps sending the per-record `Deliver` run, byte-for-byte
/// unchanged, and NEVER sends the new tag — so a consumer that would error on an unknown frame, or that
/// cannot decode the on-disk record layout, is never broken. It is a pure capability flag (no associated
/// value), so it occupies no slot in the v1 field block beyond this `flags` bit, exactly like
/// [`CONNECT_FLAG_WANTS_GAP_MARKER`] / [`CONNECT_FLAG_UNDERSTANDS_STREAMING`].
pub const CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH: u8 = 0b0100_0000;

/// The `Connect` CAPABILITY bit (#588, V2-M2-I10) by which a client advertises that it UNDERSTANDS
/// the stream-ADDRESSED wire verbs — `StreamDeclare` (tag 28), `StreamInfo` (tag 29), `PubTo` (tag
/// 30), and `SubTo` (tag 31) — that make NAMED streams client-reachable. When set, the server
/// confirms the capability with [`INFO_FLAG_STREAMS`] and the client may declare / publish-to /
/// subscribe-to a named stream by its explicit id. When CLEAR (an old client, or one that opts out)
/// the client uses only the default-stream verbs (`Pub`/`Sub`/`Flow`/`Fetch`), which target the
/// default stream `""` — byte-for-byte today's behavior — and is NEVER sent a streams reply it did
/// not ask for. Distinct from [`CONNECT_FLAG_UNDERSTANDS_STREAMING`] (the Tier-S consume-tier
/// capability, #543): that bit names the consume MODE; this bit names multi-stream ADDRESSING. It is
/// a pure capability flag (no associated value), so it occupies no slot in the v1 field block beyond
/// this `flags` bit, exactly like [`CONNECT_FLAG_WANTS_GAP_MARKER`]. It is the LAST free bit (bit 7)
/// of the handshake `flags` byte; a future capability needs an appended flags byte (the version+len
/// framing already tolerates it).
pub const CONNECT_FLAG_UNDERSTANDS_STREAMS: u8 = 0b1000_0000;

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

/// The `Info` CAPABILITY bit (#543, V2-M1) by which the server CONFIRMS this connection may consume at
/// the streaming tier (Tier-S): `true` only when the client advertised
/// [`CONNECT_FLAG_UNDERSTANDS_STREAMING`] AND the server supports the tier. When clear (an old server,
/// or a client that did not advertise) the client knows it will only ever be served Tier-W and keeps
/// using the work-queue path. The negotiation is AND, the server->client twin of
/// [`CONNECT_FLAG_UNDERSTANDS_STREAMING`], mirroring the [`INFO_FLAG_GAP_MARKER`] confirmation.
pub const INFO_FLAG_STREAMING: u8 = 0b0001_0000;

/// The `Info` presence-flag bit (#543, V2-M1) by which the server ECHOES the connection-wide
/// `default_tier` it adopted for this connection, the server->client twin of
/// [`CONNECT_FLAG_HAS_DEFAULT_TIER`]. When clear (an old server, or one that defaulted to Tier-W) the
/// client reads no default-tier echo. The tier VALUE is an APPENDED v1-block byte (see [`InfoBody`],
/// folded via [`ConsumeTier::from_u8`]); this presence bit governs only whether it is meaningful,
/// mirroring [`INFO_FLAG_HAS_DEFAULT_ACK_LEVEL`], so the field is forward+backward compatible.
pub const INFO_FLAG_HAS_DEFAULT_TIER: u8 = 0b0010_0000;

/// The `Info` CAPABILITY bit (#541, M1-I5) by which the server CONFIRMS it will deliver contiguous runs
/// as raw-framed [`crate::frame::FrameType::DeliverBatch`] frames for this connection: `true` only when
/// the client advertised [`CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH`] AND the server supports the frame.
/// When clear (an old server, or a client that did not advertise) the client knows it will only ever see
/// per-record `Deliver` runs and keeps handling them. The negotiation is AND, the server->client twin of
/// [`CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH`], mirroring the [`INFO_FLAG_GAP_MARKER`] /
/// [`INFO_FLAG_STREAMING`] confirmations.
pub const INFO_FLAG_DELIVER_BATCH: u8 = 0b0100_0000;

/// The `Info` CAPABILITY bit (#588, V2-M2-I10) by which the server CONFIRMS this connection may use
/// the stream-addressed wire verbs (`StreamDeclare`/`StreamInfo`/`PubTo`/`SubTo`): `true` only when
/// the client advertised [`CONNECT_FLAG_UNDERSTANDS_STREAMS`] AND the server supports named streams.
/// When clear (an old server, or a client that did not advertise) the client knows it will only ever
/// use the default-stream verbs. The negotiation is AND, the server->client twin of
/// [`CONNECT_FLAG_UNDERSTANDS_STREAMS`], mirroring the [`INFO_FLAG_GAP_MARKER`] / [`INFO_FLAG_STREAMING`]
/// / [`INFO_FLAG_DELIVER_BATCH`] confirmations. It is the LAST free bit (bit 7) of the `Info` `flags`
/// byte.
pub const INFO_FLAG_STREAMS: u8 = 0b1000_0000;

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
/// u64 LE`, then — each ONLY when its presence bit is set, in this fixed order — an APPENDED
/// `default_ack_level: u8` (#494, when [`CONNECT_FLAG_HAS_DEFAULT_ACK_LEVEL`]) and an APPENDED
/// `default_tier: u8` (#543, when [`CONNECT_FLAG_HAS_DEFAULT_TIER`]). Each appended byte is OMITTED
/// (and `field_len` shrinks by it) when its field is absent; the encoder and decoder walk them in the
/// SAME conditional order, so an absent earlier byte never shifts a present later one. A request with
/// neither appended byte is byte-for-byte the historical body. Any bytes past `field_len` (a FUTURE
/// version's appended fields, e.g. the #71 `wire_protocol_version`) are TOLERATED and ignored by a v1
/// reader. An empty body is the all-absent default.
// Each bool is a DISTINCT negotiated wire CAPABILITY flag (gap-marker / streaming / deliver-batch /
// streams, #346/#543/#541/#588), one bit of the handshake `flags` byte — a documented wire ABI, not
// internal state a bitfield could replace, so the clippy "more than 3 bools" suggestion does not apply.
#[allow(clippy::struct_excessive_bools)]
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
    /// Whether this consumer UNDERSTANDS the streaming consume tier (#543, V2-M1): the
    /// [`CONNECT_FLAG_UNDERSTANDS_STREAMING`] capability bit. When `true`, the server may serve the
    /// connection at Tier-S and may honor a Tier-S `default_tier`. When `false` (the default, and an
    /// old client) the connection ALWAYS consumes at Tier-W — byte-for-byte today's behavior — and any
    /// Tier-S `default_tier` is ignored, so a pre-streaming client is never moved onto a tier it cannot
    /// follow. A pure capability flag, so it adds no block slot beyond its `flags` bit.
    pub understands_streaming: bool,
    /// The connection-wide DEFAULT consume tier the client requests (#543, V2-M1): the raw value folded
    /// via [`ConsumeTier::from_u8`] (`0` = Tier-W, `1` = Tier-S) a SUBSCRIPTION adopts when it does not
    /// pick its own tier. `None` (an old client, or one that defers) means the server applies Tier-W,
    /// the work-queue default. APPENDED v1 field mirroring `default_ack_level`: emitted only when
    /// `Some`, so a `None` request keeps the body byte-for-byte the layout without it, and an old client
    /// decodes to `None`. The default is only HONORED when `understands_streaming` is also set; a
    /// Tier-S default without the capability is ignored. The value is carried raw as a `u8` so a future
    /// tier the proto does not yet name still round-trips.
    pub default_tier: Option<u8>,
    /// Whether this consumer UNDERSTANDS the raw-framed `DeliverBatch` frame (tag 26, #541, M1-I5): the
    /// [`CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH`] capability bit. When `true`, the server may deliver a
    /// contiguous run as ONE `DeliverBatch` (the records' on-disk frame bytes, decoded client-side) in
    /// place of N per-record `Deliver` frames. When `false` (the default, and an old client) the server
    /// ALWAYS sends per-record `Deliver` frames — byte-for-byte today's behavior — and never sends the
    /// new tag, so a pre-batch client is never sent a frame it cannot decode. A pure capability flag, so
    /// it adds no block slot beyond its `flags` bit.
    pub understands_deliver_batch: bool,
    /// Whether this client UNDERSTANDS the stream-addressed wire verbs (`StreamDeclare`/`StreamInfo`/
    /// `PubTo`/`SubTo`, tags 28-31, #588, V2-M2-I10): the [`CONNECT_FLAG_UNDERSTANDS_STREAMS`]
    /// capability bit. When `true`, the client may address NAMED streams by id and the server confirms
    /// with [`InfoBody::streams`]. When `false` (the default, and an old client) the client uses only
    /// the default-stream verbs (`Pub`/`Sub`/`Flow`/`Fetch`) — byte-for-byte today's behavior — and is
    /// never sent a streams reply it did not request. A pure capability flag, so it adds no block slot
    /// beyond its `flags` bit.
    pub understands_streams: bool,
}

/// The number of bytes in the `Connect` v1 known-field block with NO appended bytes (#494, #543):
/// `flags: u8` + `requested_credit: u32` + `requested_credit_bytes: u64`. This is the historical,
/// pre-appended-byte block length; each present appended byte (`default_ack_level`, then
/// `default_tier`) adds exactly one to it, so an all-absent request is byte-for-byte the old body.
const CONNECT_V1_FIELD_LEN: u16 = 1 + 4 + 8;

/// The mechanism selector for a connection-scoped authentication credential carried in the
/// `Connect` body (#631, V2-M7, the auth contract in `docs/AUTHENTICATION.md`). It is the WIRE
/// selector only — the proto layer carries the OPAQUE credential bytes and never hashes, compares,
/// or interprets them; the server resolves a credential to an identity and a scope set
/// ([`crate::frame::FrameType::Connect`] handling in `ironbus-server`). v1 specifies exactly three
/// mechanisms (bearer token, username+password, mTLS); nkey/JWT are deliberately out of scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMechanism {
    /// A high-entropy opaque bearer token. The credential bytes are the raw token (presented inside
    /// the established TLS session on a non-loopback bind); the server stores only its SHA-256 and
    /// compares constant-time. Possession is proof of identity.
    Bearer,
    /// A username plus password. The credential carries the two as `u16`-length-prefixed fields
    /// (`username`, then `password`); the server verifies the password against the stored Argon2id
    /// PHC hash for the username, constant-time.
    Password,
    /// Mutual TLS: the credential is the peer certificate already presented at the TLS layer, so the
    /// `Connect` body carries NO credential bytes (the selector alone). The server maps the verified
    /// certificate's SAN identity to a configured scope set. Selecting this on a connection with no
    /// verified client certificate is an Authorization Violation.
    Mtls,
}

impl AuthMechanism {
    /// The wire selector byte. `1`/`2`/`3` are used (not `0`) so a zero byte can never be mistaken
    /// for a present-but-default mechanism in a malformed body.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            AuthMechanism::Bearer => 1,
            AuthMechanism::Password => 2,
            AuthMechanism::Mtls => 3,
        }
    }

    /// Folds a wire selector byte to a mechanism, or `None` for an unknown selector (which the
    /// server treats as an Authorization Violation, never a silent fall-through to no-auth).
    #[must_use]
    pub fn from_u8(b: u8) -> Option<AuthMechanism> {
        Some(match b {
            1 => AuthMechanism::Bearer,
            2 => AuthMechanism::Password,
            3 => AuthMechanism::Mtls,
            _ => return None,
        })
    }
}

/// A connection-scoped authentication credential carried in the `Connect` body (#631, V2-M7). It is
/// a WIRE type: the proto layer frames the mechanism selector and the OPAQUE credential bytes and
/// never inspects the secret (no hashing, no comparison, no logging happens here). The server owns
/// the verification.
///
/// The credential rides an APPENDED, length-prefixed section AFTER the `field_len` v1 block (in the
/// "bytes past `field_len`, tolerated and ignored by an old reader" zone that
/// [`decode_connect`] already documents), so the wire stays strictly backward-compatible: an old
/// client, and the empty `Connect` body, decode to `auth = None`, byte-for-byte unchanged. A client
/// that authenticates appends this section; the section is the ONLY place a secret travels on the
/// wire, and on a non-loopback bind it travels only inside the established TLS session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCredential {
    /// Which of the three v1 mechanisms this credential is for.
    pub mechanism: AuthMechanism,
    /// The mechanism-specific credential bytes, opaque to the proto layer:
    /// - `Bearer`: the raw token bytes.
    /// - `Password`: `username` then `password`, each `u16`-length-prefixed.
    /// - `Mtls`: empty (the credential is the TLS peer certificate, not body bytes).
    pub material: Vec<u8>,
}

/// The TRAILING-section marker byte that introduces an appended auth credential in the `Connect`
/// body (#631, V2-M7). The auth section lives ENTIRELY AFTER the `field_len` v1 block (and after any
/// appended `default_ack_level`/`default_tier` bytes), in the "bytes past `field_len`, tolerated and
/// ignored by an old reader" zone [`decode_connect`] documents — so it disturbs NO existing fixed
/// offset and does NOT consume a bit of the (full) historical `flags` byte. The layout of the
/// section is exactly: `[AUTH_SECTION_MARKER: u8][mechanism: u8][material: u16-length-prefixed]`.
///
/// A body with no trailing bytes (an old client, the empty `Connect` body, a connection that does
/// not authenticate) decodes to `auth = None`, byte-for-byte the historical body. The marker is a
/// fixed sentinel (not zero, not a printable ASCII run) so a stray future trailing field is never
/// silently misread as an auth section: a trailing byte that is not this marker leaves `auth = None`
/// and is ignored, exactly as the forward-compat rule requires.
pub const CONNECT_AUTH_SECTION_MARKER: u8 = 0xA7;

/// Encodes a `Connect` body onto the end of `out` (#292, #494, #543). The result is the version byte,
/// the v1 field-block length, then the v1 block; an all-`None` request still encodes a well-formed
/// (non-empty) v1 body whose presence flags are clear, which the server reads as "use my defaults".
/// The appended `default_ack_level` (#494) and `default_tier` (#543) bytes are each APPENDED to the
/// block ONLY when present, in that fixed order, and `field_len` grows by exactly the present bytes;
/// when both are absent the body is byte-for-byte the historical layout. To emit the historical EMPTY
/// `Connect` body (the old-client case) the caller simply sends an empty body and does NOT call this;
/// [`decode_connect`] accepts both.
pub fn encode_connect(req: &ConnectBody, out: &mut Vec<u8>) {
    out.push(HANDSHAKE_BODY_VERSION);
    // The block length is the historical fixed block plus ONE byte for each present appended field, in
    // declared order (ack-level, then tier). An all-absent request encodes the historical length and
    // bytes verbatim (byte-identity, #494/#543).
    let mut field_len = CONNECT_V1_FIELD_LEN;
    if req.default_ack_level.is_some() {
        field_len += 1;
    }
    if req.default_tier.is_some() {
        field_len += 1;
    }
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
    if req.understands_streaming {
        flags |= CONNECT_FLAG_UNDERSTANDS_STREAMING;
    }
    if req.default_tier.is_some() {
        flags |= CONNECT_FLAG_HAS_DEFAULT_TIER;
    }
    if req.understands_deliver_batch {
        flags |= CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH;
    }
    if req.understands_streams {
        flags |= CONNECT_FLAG_UNDERSTANDS_STREAMS;
    }
    out.push(flags);
    out.extend_from_slice(&req.requested_credit.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&req.requested_credit_bytes.unwrap_or(0).to_le_bytes());
    // The appended bytes follow the historical fixed fields, each ONLY when present, in declared order
    // (ack-level, then tier). The decoder reads them in the SAME conditional order, so an absent earlier
    // byte never shifts a present later one and the historical fields keep their exact offsets.
    if let Some(level) = req.default_ack_level {
        out.push(level);
    }
    if let Some(tier) = req.default_tier {
        out.push(tier);
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
    // The appended tier byte (#543) follows the ack-level byte in the SAME conditional order the
    // encoder wrote them, so a present tier byte is read from the right offset whether or not the
    // ack-level byte preceded it. Read AFTER ack-level; a clear bit (or short block) reads no byte.
    let default_tier = (flags & CONNECT_FLAG_HAS_DEFAULT_TIER != 0).then(|| fr.u8().unwrap_or(0));
    let requested_credit = (flags & CONNECT_FLAG_HAS_CREDIT != 0).then_some(credit);
    let requested_credit_bytes =
        (flags & CONNECT_FLAG_HAS_CREDIT_BYTES != 0).then_some(credit_bytes);
    let wants_gap_marker = flags & CONNECT_FLAG_WANTS_GAP_MARKER != 0;
    let understands_streaming = flags & CONNECT_FLAG_UNDERSTANDS_STREAMING != 0;
    let understands_deliver_batch = flags & CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH != 0;
    let understands_streams = flags & CONNECT_FLAG_UNDERSTANDS_STREAMS != 0;
    Ok(ConnectBody {
        requested_credit,
        requested_credit_bytes,
        wants_gap_marker,
        default_ack_level,
        understands_streaming,
        default_tier,
        understands_deliver_batch,
        understands_streams,
    })
}

/// Appends a connection-scoped auth section to an ALREADY-ENCODED, NON-EMPTY `Connect` body (#631,
/// V2-M7). The caller MUST first write a valid v1 body with [`encode_connect`] (the auth section
/// rides in the trailing zone past the v1 `field_len` block, so a version header must precede it; an
/// mTLS client that has no other v1 fields to request still calls `encode_connect(&ConnectBody::
/// default(), ..)` first to lay down the version header). This then appends the credential. The
/// section is strictly additive: a body without it decodes to no-auth on every reader, and an old
/// reader ignores these trailing bytes entirely.
///
/// Layout: `[CONNECT_AUTH_SECTION_MARKER: u8][mechanism: u8][material: u16-length-prefixed]`. This is
/// a WIRE codec only — the credential bytes are opaque here; the server verifies them.
///
/// # Errors
/// [`BodyError::FieldTooLarge`] if the credential material exceeds the `u16` wire limit (a token or
/// username+password far beyond any legitimate credential size), so an oversized credential fails
/// closed at encode rather than silently truncating.
pub fn append_connect_auth(out: &mut Vec<u8>, cred: &AuthCredential) -> Result<(), BodyError> {
    debug_assert!(
        !out.is_empty(),
        "append_connect_auth requires a v1 Connect body (version header) to be written first"
    );
    out.push(CONNECT_AUTH_SECTION_MARKER);
    out.push(cred.mechanism.as_u8());
    push_var(out, &cred.material)
}

/// Parses a connection-scoped auth section from a raw `Connect` body, if one is present (#631,
/// V2-M7). It re-walks the body past the v1 `field_len` block (and any appended
/// `default_ack_level`/`default_tier` bytes) to the trailing zone and reads the auth section IFF the
/// trailing bytes begin with [`CONNECT_AUTH_SECTION_MARKER`].
///
/// Returns `Ok(None)` for the no-auth cases that MUST stay byte-for-byte compatible: an empty body,
/// an old-client body with no trailing bytes, or trailing bytes that do not begin with the auth
/// marker. Returns `Ok(Some(cred))` when a well-formed auth section is present. This is decoupled
/// from [`decode_connect`] on purpose: the credential is opaque wire bytes the server (not the
/// proto layer) verifies, and keeping it separate leaves [`ConnectBody`] a `Copy` POD.
///
/// # Errors
/// [`BodyError::BadHandshakeVersion`] for an unknown body version, or [`BodyError::Truncated`] /
/// [`BodyError::BadLength`] if a PRESENT auth section (the marker was seen) is malformed — a started
/// but truncated credential is an error, never a silent fall-through to no-auth, so a corrupt auth
/// section fails closed. An UNKNOWN mechanism selector is a typed `Truncated`-class reject here is
/// avoided: the selector is validated by the server (so it can map to the uniform Authorization
/// Violation), and this parser returns the raw selector via [`AuthMechanism::from_u8`] failing into
/// a `BadAckOp`-free typed error below.
pub fn parse_connect_auth(body: &[u8]) -> Result<Option<AuthCredential>, BodyError> {
    // The empty body is the historical no-auth case.
    if body.is_empty() {
        return Ok(None);
    }
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != HANDSHAKE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    // Skip the v1 field block exactly as decode_connect bounds it (cap-before-alloc via `take`). The
    // encoder writes `field_len` to INCLUDE the appended default_ack_level / default_tier bytes, so
    // taking the whole block lands the reader directly on the trailing zone — no separate skip of the
    // appended bytes is needed (they live inside the block, not after it).
    let field_len = r.u16()? as usize;
    let _block = r.take(field_len)?;
    // The trailing zone. No bytes, or a leading byte that is not the auth marker, is the no-auth
    // case (an old body, or some other future trailing field): ignore and report no auth.
    if r.at_end() {
        return Ok(None);
    }
    let marker = r.u8()?;
    if marker != CONNECT_AUTH_SECTION_MARKER {
        return Ok(None);
    }
    // The marker was seen, so a malformed remainder is now a fail-closed error, not no-auth.
    let mech_byte = r.u8()?;
    let Some(mechanism) = AuthMechanism::from_u8(mech_byte) else {
        // An unknown mechanism selector: a typed error so the server can refuse with the uniform
        // Authorization Violation rather than silently treating the connection as anonymous.
        return Err(BodyError::BadAckOp { op: mech_byte });
    };
    let material = r.var()?.to_vec();
    Ok(Some(AuthCredential {
        mechanism,
        material,
    }))
}

/// Packs a username and password into the `Password`-mechanism credential material (#631): each is
/// `u16`-length-prefixed, username first. The server unpacks with [`unpack_password_material`]. The
/// password bytes are opaque here; the server verifies them against the stored Argon2id hash.
///
/// # Errors
/// [`BodyError::FieldTooLarge`] if the username or password exceeds the `u16` wire limit.
pub fn pack_password_material(username: &[u8], password: &[u8]) -> Result<Vec<u8>, BodyError> {
    let mut v = Vec::with_capacity(4 + username.len() + password.len());
    push_var(&mut v, username)?;
    push_var(&mut v, password)?;
    Ok(v)
}

/// Unpacks the `Password`-mechanism credential material into `(username, password)` (#631). The
/// inverse of [`pack_password_material`].
///
/// # Errors
/// [`BodyError::Truncated`] / [`BodyError::BadLength`] if the material is not two well-formed
/// `u16`-length-prefixed fields, or [`BodyError::TrailingBytes`] if extra bytes follow — a malformed
/// password credential fails closed.
pub fn unpack_password_material(material: &[u8]) -> Result<(&[u8], &[u8]), BodyError> {
    let mut r = Reader::new(material);
    let username = r.var()?;
    let password = r.var()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok((username, password))
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
/// `credit_bytes.negotiated: u64 LE`, `credit_bytes.cap: u64 LE`, then — each ONLY when its presence
/// bit is set, in this fixed order — an APPENDED `default_ack_level: u8` (#494, when
/// [`INFO_FLAG_HAS_DEFAULT_ACK_LEVEL`]) and an APPENDED `default_tier: u8` (#543, when
/// [`INFO_FLAG_HAS_DEFAULT_TIER`]). Each appended byte is OMITTED (and `field_len` shrinks by it) when
/// absent; an advertisement with neither is byte-for-byte the historical body. Trailing bytes past the
/// block are a future version's fields, tolerated and ignored. An empty body is the all-absent case.
// Each bool is a DISTINCT server-confirmed wire CAPABILITY echo (gap-marker / streaming /
// deliver-batch / streams), one bit of the `Info` `flags` byte — a documented wire ABI, not internal
// state a bitfield could replace, so the clippy "more than 3 bools" suggestion does not apply.
#[allow(clippy::struct_excessive_bools)]
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
    /// Whether the server CONFIRMS this connection may consume at the streaming tier (#543, V2-M1): the
    /// [`INFO_FLAG_STREAMING`] capability echo, the server->client twin of
    /// [`ConnectBody::understands_streaming`]. `true` only when the client advertised it understands
    /// streaming AND the server supports the tier. `false` (an old server, or a client that did not
    /// advertise) tells the client it will only ever be served Tier-W.
    pub streaming: bool,
    /// The connection-wide DEFAULT consume tier the server ECHOES for this connection (#543, V2-M1), the
    /// server->client twin of [`ConnectBody::default_tier`]: the raw value folded via
    /// [`ConsumeTier::from_u8`] (`0` = Tier-W, `1` = Tier-S). `None` (an old server, or one that
    /// defaulted to Tier-W) means no echo. APPENDED v1 field mirroring `default_ack_level`: emitted only
    /// when `Some`, so a `None` advertisement is byte-for-byte the body without it.
    pub default_tier: Option<u8>,
    /// Whether the server CONFIRMS it will deliver contiguous runs as raw-framed `DeliverBatch` frames
    /// (tag 26) for this connection (#541, M1-I5): the [`INFO_FLAG_DELIVER_BATCH`] capability echo, the
    /// server->client twin of [`ConnectBody::understands_deliver_batch`]. `true` only when the client
    /// advertised it understands the frame AND the server supports it. `false` (an old server, or a
    /// client that did not advertise) tells the client it will only ever see per-record `Deliver` runs.
    pub deliver_batch: bool,
    /// Whether the server CONFIRMS this connection may use the stream-addressed wire verbs
    /// (`StreamDeclare`/`StreamInfo`/`PubTo`/`SubTo`, tags 28-31, #588, V2-M2-I10): the
    /// [`INFO_FLAG_STREAMS`] capability echo, the server->client twin of
    /// [`ConnectBody::understands_streams`]. `true` only when the client advertised it understands the
    /// verbs AND the server supports named streams. `false` (an old server, or a client that did not
    /// advertise) tells the client it will only ever use the default-stream verbs.
    pub streams: bool,
}

/// The number of bytes in the `Info` v1 known-field block with NO appended bytes (#494, #543):
/// `flags: u8` + `credit.negotiated: u32` + `credit.cap: u32` + `credit_bytes.negotiated: u64` +
/// `credit_bytes.cap: u64`. This is the historical, pre-appended-byte block length; each present
/// appended byte (`default_ack_level`, then `default_tier`) adds exactly one to it.
const INFO_V1_FIELD_LEN: u16 = 1 + 4 + 4 + 8 + 8;

/// Encodes an `Info` body onto the end of `out` (#292, #494, #543): the version byte, the v1
/// field-block length, then the v1 block. An all-`None` advertisement still encodes a well-formed
/// (non-empty) v1 body whose presence flags are clear, which a client reads as "no advertisement, keep
/// my local credit". The appended `default_ack_level` (#494) and `default_tier` (#543) bytes are each
/// APPENDED to the block ONLY when present, in that fixed order, and `field_len` grows by exactly the
/// present bytes; when both are absent the body is byte-for-byte the historical layout. To emit the
/// historical EMPTY `Info` body (the old-server case) the caller sends an empty body and does NOT call
/// this; [`decode_info`] accepts both.
pub fn encode_info(info: &InfoBody, out: &mut Vec<u8>) {
    out.push(HANDSHAKE_BODY_VERSION);
    let mut field_len = INFO_V1_FIELD_LEN;
    if info.default_ack_level.is_some() {
        field_len += 1;
    }
    if info.default_tier.is_some() {
        field_len += 1;
    }
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
    if info.streaming {
        flags |= INFO_FLAG_STREAMING;
    }
    if info.default_tier.is_some() {
        flags |= INFO_FLAG_HAS_DEFAULT_TIER;
    }
    if info.deliver_batch {
        flags |= INFO_FLAG_DELIVER_BATCH;
    }
    if info.streams {
        flags |= INFO_FLAG_STREAMS;
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
    // The appended bytes follow the historical fixed fields, each ONLY when present, in declared order
    // (ack-level, then tier), exactly as the decoder reads them, so an absent earlier byte never shifts
    // a present later one and the historical fields keep their exact offsets.
    if let Some(level) = info.default_ack_level {
        out.push(level);
    }
    if let Some(tier) = info.default_tier {
        out.push(tier);
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
    // The appended tier byte (#543) follows the ack-level byte in the SAME conditional order the
    // encoder wrote them, read AFTER ack-level; a clear bit (or short block) reads no byte.
    let default_tier = (flags & INFO_FLAG_HAS_DEFAULT_TIER != 0).then(|| fr.u8().unwrap_or(0));
    let credit = (flags & INFO_FLAG_HAS_CREDIT != 0).then_some(CreditAdvert {
        negotiated: credit_negotiated,
        cap: credit_cap,
    });
    let credit_bytes = (flags & INFO_FLAG_HAS_CREDIT_BYTES != 0).then_some(CreditAdvert {
        negotiated: credit_bytes_negotiated,
        cap: credit_bytes_cap,
    });
    let gap_marker = flags & INFO_FLAG_GAP_MARKER != 0;
    let streaming = flags & INFO_FLAG_STREAMING != 0;
    let deliver_batch = flags & INFO_FLAG_DELIVER_BATCH != 0;
    let streams = flags & INFO_FLAG_STREAMS != 0;
    Ok(InfoBody {
        credit,
        credit_bytes,
        gap_marker,
        default_ack_level,
        streaming,
        default_tier,
        deliver_batch,
        streams,
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

// ===================================================================================
// STREAM-ADDRESSED WIRE BODIES (#588, V2-M2-I10): the explicit-stream-id verbs that make NAMED
// streams CLIENT-reachable — StreamDeclare (tag 28), StreamInfo (tag 29), PubTo (tag 30), SubTo
// (tag 31). Each rides a `body_version: u8` + `field_len: u16` frame (mirroring `FetchBody` /
// `StreamFetchBody`) so a future version can append fields without a wire break: a v1 reader reads
// the known fields from the front of the declared block and TOLERATES (ignores) trailing bytes. The
// stream id is a `u16`-length-prefixed byte field, capped BEFORE any read by `Reader::take`, so a
// malformed/oversized id is a typed [`BodyError`], never a panic or over-read (fail-closed). The
// SUBJECT->stream binding + subject-addressed routing (a `SubTo` resolving a subject/wildcard to a
// stream) is the SEPARATE M2-I9 (#585) work; THESE bodies carry an EXPLICIT stream id only.
// ===================================================================================

/// The version of the stream-addressed body framing (#588). Version `1` is the first (and only)
/// layout. Carried as a leading byte so a future version can extend a body without a wire break: a
/// reader rejects a version it does not understand rather than mis-parsing it, exactly like
/// [`FETCH_BODY_VERSION`]. Shared by `StreamDeclare`, `StreamInfo` (request + response), `PubTo`, and
/// `SubTo`, which all use the same version/length framing.
pub const STREAM_WIRE_BODY_VERSION: u8 = 1;

/// The hard cap on a stream-id byte length the proto codecs enforce at the wire boundary (#588): the
/// engine's `StreamId::named` further validates the name's SHAPE (graphic ASCII, non-empty, its own
/// length bound), but this cap fails a hostile/oversized id closed at decode time BEFORE the name
/// crosses into the server, so a malformed-id frame is a typed [`BodyError::BadLength`] rather than a
/// large reservation. It is generous (the engine's own bound is tighter) so it never rejects a name
/// the engine would accept; it only stops an absurdly long id.
pub const MAX_STREAM_ID_LEN: usize = 1024;

/// Reads a `u16`-length-prefixed stream-id field, enforcing [`MAX_STREAM_ID_LEN`] (#588). A declared
/// length over the cap is a typed [`BodyError::BadLength`] (fail-closed) BEFORE the bytes are taken,
/// so a hostile id cannot force an over-read; a short body is [`BodyError::Truncated`] via
/// [`Reader::take`]. The returned slice borrows the body (zero-copy).
fn read_stream_id<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], BodyError> {
    let len = r.u16()? as usize;
    if len > MAX_STREAM_ID_LEN {
        return Err(BodyError::BadLength);
    }
    r.take(len)
}

/// A client's request to CREATE-OR-ENSURE a named stream (the `StreamDeclare` frame body, tag 28,
/// #588): it carries the explicit `stream_id` to declare. The broker `declare`s it (idempotent) and
/// replies `Ok`, or `Err` on a malformed/over-long name (the empty name `""` is rejected — the
/// default stream is always present and is never declared this way).
///
/// Layout (version+length framed, forward-compatible): `body_version: u8`
/// ([`STREAM_WIRE_BODY_VERSION`]), `field_len: u16` (the length of the v1 known-field block), then the
/// v1 block: `stream_id: u16-len + bytes`. Bytes past `field_len` (a future version's appended fields)
/// are TOLERATED and ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamDeclareBody<'a> {
    /// The name of the stream to create-or-ensure (validated server-side by `StreamId::named`).
    pub stream_id: &'a [u8],
}

/// Encodes a `StreamDeclare` body onto the end of `out` (#588).
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the stream id exceeds the `u16` wire limit.
pub fn encode_stream_declare(
    req: &StreamDeclareBody<'_>,
    out: &mut Vec<u8>,
) -> Result<(), BodyError> {
    let id_len = u16::try_from(req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&id_len.to_le_bytes());
    out.extend_from_slice(req.stream_id);
    Ok(())
}

/// Decodes a `StreamDeclare` body (#588), cap-before-alloc and panic-free.
///
/// The body MUST carry the version byte and `u16` field-length; the v1 `stream_id` is read from the
/// front of the declared block and trailing block bytes (a future version's fields) are tolerated. A
/// body too short for its declared block, or a stream id over [`MAX_STREAM_ID_LEN`], is a typed
/// [`BodyError`] (fail-closed), never a panic or over-read. An EMPTY body is NOT valid (the frame type
/// is new, with no historical empty case), so it is [`BodyError::Truncated`].
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap id, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_stream_declare(body: &[u8]) -> Result<StreamDeclareBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    let stream_id = read_stream_id(&mut fr)?;
    Ok(StreamDeclareBody { stream_id })
}

/// A client's query for a named stream (the `StreamInfo` REQUEST body, tag 29, #588): it carries the
/// `stream_id` to query. The broker replies a `StreamInfo` frame whose body is a
/// [`StreamInfoResponseBody`], or `Err` on a malformed name. Same version/length framing as
/// [`StreamDeclareBody`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamInfoBody<'a> {
    /// The name of the stream being queried (validated server-side).
    pub stream_id: &'a [u8],
}

/// Encodes a `StreamInfo` REQUEST body onto the end of `out` (#588).
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the stream id exceeds the `u16` wire limit.
pub fn encode_stream_info(req: &StreamInfoBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    let id_len = u16::try_from(req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&id_len.to_le_bytes());
    out.extend_from_slice(req.stream_id);
    Ok(())
}

/// Decodes a `StreamInfo` REQUEST body (#588), cap-before-alloc and panic-free (same discipline as
/// [`decode_stream_declare`]).
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap id, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_stream_info(body: &[u8]) -> Result<StreamInfoBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    let stream_id = read_stream_id(&mut fr)?;
    Ok(StreamInfoBody { stream_id })
}

/// The server's reply to a `StreamInfo` query (the `StreamInfo` RESPONSE body, tag 29, #588): whether
/// the queried stream EXISTS and, if so, its durable head offset. The default stream `""` always
/// reports `exists = true`. An unknown future `exists` byte is folded to `false` by the decoder (never
/// an error), so the field stays forward-compatible.
///
/// Layout (version+length framed): `body_version: u8`, `field_len: u16`, then the v1 block:
/// `exists: u8` (`0` = absent, `1` = present), `head: u64 LE` (the durable head; `0` when absent).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StreamInfoResponseBody {
    /// Whether the queried stream exists (has been declared / produced-to). The default stream is
    /// always `true`.
    pub exists: bool,
    /// The stream's durable head (flushed) offset; `0` when the stream does not exist.
    pub head: u64,
}

/// The number of bytes in the `StreamInfo` RESPONSE v1 known-field block: `exists: u8` + `head: u64`.
const STREAM_INFO_RESP_V1_FIELD_LEN: u16 = 1 + 8;

/// Encodes a `StreamInfo` RESPONSE body onto the end of `out` (#588): the version byte, the v1
/// field-block length, then the v1 block.
pub fn encode_stream_info_response(resp: &StreamInfoResponseBody, out: &mut Vec<u8>) {
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&STREAM_INFO_RESP_V1_FIELD_LEN.to_le_bytes());
    out.push(u8::from(resp.exists));
    out.extend_from_slice(&resp.head.to_le_bytes());
}

/// Decodes a `StreamInfo` RESPONSE body (#588), cap-before-alloc and panic-free. A short block reads
/// what is present and defaults the rest (never panicking); a non-`0`/`1` `exists` byte folds to
/// `false`. An EMPTY body is NOT valid, so it is [`BodyError::Truncated`].
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, or [`BodyError::BadHandshakeVersion`] for an unknown
/// body version.
pub fn decode_stream_info_response(body: &[u8]) -> Result<StreamInfoResponseBody, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    let exists = fr.u8().unwrap_or(0) == 1;
    let head = fr.u64().unwrap_or(0);
    Ok(StreamInfoResponseBody { exists, head })
}

/// A producer's publish to a NAMED stream (the `PubTo` frame body, tag 30, #588): an explicit target
/// `stream_id` followed by a body that IS the verbatim [`PubBody`] bytes (the default-stream `Pub`
/// body). It deliberately carries the `pub_body` as an opaque borrowed slice rather than a decoded
/// [`PubBody`], so the stream-addressed publish reuses the EXISTING [`decode_pub`] codec UNCHANGED
/// (the session decodes the prefix here, then the `pub_body` with `decode_pub`), and the `Pub` (tag 5)
/// wire stays byte-for-byte identical — the only added bytes are the version/length-framed stream-id
/// prefix.
///
/// Layout (version+length framed): `body_version: u8`, `field_len: u16` (over the `stream_id` field
/// ONLY), then the v1 block: `stream_id: u16-len + bytes`; then the verbatim `PubBody` bytes as the
/// REMAINDER after the block. Putting the `PubBody` after the declared block (not inside it) lets a
/// future version append PubTo-specific fields to the block while the `PubBody` stays the tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubToBody<'a> {
    /// The target stream name (empty routes to the default stream, byte-for-byte a plain `Pub`).
    pub stream_id: &'a [u8],
    /// The verbatim [`PubBody`] bytes, decoded by the caller with [`decode_pub`] (so the publish body
    /// codec is shared UNCHANGED with the default-stream `Pub`).
    pub pub_body: &'a [u8],
}

/// Encodes a `PubTo` body onto the end of `out` (#588): the version byte, the field-block length over
/// the stream id, the stream id, then the verbatim `pub_body` bytes. The caller produces `pub_body`
/// with [`encode_pub`].
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the stream id exceeds the `u16` wire limit.
pub fn encode_pub_to(req: &PubToBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    let id_len = u16::try_from(req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&id_len.to_le_bytes());
    out.extend_from_slice(req.stream_id);
    out.extend_from_slice(req.pub_body);
    Ok(())
}

/// Decodes a `PubTo` body (#588) into its `stream_id` and the verbatim `pub_body` tail, cap-before-alloc
/// and panic-free. The caller decodes `pub_body` with [`decode_pub`]. A body too short for its declared
/// block, or a stream id over [`MAX_STREAM_ID_LEN`], is a typed [`BodyError`] (fail-closed). An EMPTY
/// body is NOT valid, so it is [`BodyError::Truncated`].
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap id, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_pub_to(body: &[u8]) -> Result<PubToBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    // The PubBody is everything AFTER the declared block (so a future version may grow the block
    // without disturbing the PubBody tail).
    let pub_body = r.rest();
    let mut fr = Reader::new(block);
    let stream_id = read_stream_id(&mut fr)?;
    Ok(PubToBody {
        stream_id,
        pub_body,
    })
}

/// A consumer's subscribe to a NAMED stream's work-group (the `SubTo` frame body, tag 31, #588): an
/// explicit `stream_id` plus the work-`group` name. It binds the connection's subsequent
/// stream-scoped `Flow`/`Ack` to that stream's OWN competing work-group (independent per stream). The
/// EMPTY stream id targets the default stream (equivalent to a plain `Sub`); the empty group selects
/// the default group.
///
/// Layout (version+length framed): `body_version: u8`, `field_len: u16`, then the v1 block:
/// `stream_id: u16-len + bytes`, `group: u16-len + bytes`. Both fields ride INSIDE the declared block
/// (each `u16`-length-prefixed), so a future version appends after them. Trailing block bytes are
/// tolerated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubToBody<'a> {
    /// The target stream name (empty selects the default stream).
    pub stream_id: &'a [u8],
    /// The work-group name (empty selects the default group), validated server-side.
    pub group: &'a [u8],
}

/// Encodes a `SubTo` body onto the end of `out` (#588): the version byte, the field-block length, then
/// the stream id and group, each `u16`-length-prefixed.
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the stream id or group exceeds the `u16` wire limit.
pub fn encode_sub_to(req: &SubToBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    let id_len = u16::try_from(req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let group_len = u16::try_from(req.group.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.stream_id.len() + 2 + req.group.len())
        .map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&id_len.to_le_bytes());
    out.extend_from_slice(req.stream_id);
    out.extend_from_slice(&group_len.to_le_bytes());
    out.extend_from_slice(req.group);
    Ok(())
}

/// Decodes a `SubTo` body (#588), cap-before-alloc and panic-free. The stream id is capped at
/// [`MAX_STREAM_ID_LEN`]; the group is `u16`-length-prefixed (its SHAPE is validated server-side, as
/// for a plain `Sub`). A body too short for its declared block is a typed [`BodyError`] (fail-closed).
/// An EMPTY body is NOT valid, so it is [`BodyError::Truncated`].
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap id, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_sub_to(body: &[u8]) -> Result<SubToBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    let stream_id = read_stream_id(&mut fr)?;
    let group = fr.var()?;
    Ok(SubToBody { stream_id, group })
}

// ===================================================================================
// TRANSACTIONAL HALF-MESSAGE WIRE BODIES (#640, V2-M8): the prepare/commit/rollback verbs for the
// RocketMQ-style transactional half-message 2PC. Each rides the SAME `body_version: u8` + `field_len:
// u16` frame as the explicit-stream-id verbs (#588), so a future version appends fields without a wire
// break. TxnPrepare carries the txn id + target stream + the verbatim `PubBody` tail; TxnCommit and
// TxnRollback share one `TxnResolveBody` shape (just the txn id). The txn-id field is `u16`-length-
// prefixed and capped at `MAX_TXN_ID_LEN` BEFORE any read (fail-closed): a malformed/oversized id is a
// typed `BodyError`, never a panic or over-read.
// ===================================================================================

/// The hard cap on a transaction-id byte length the proto codecs enforce at the wire boundary (#640):
/// the engine's `ironbus_core::txn` further bounds it (the same 256), but this cap fails a
/// hostile/oversized id closed at decode time BEFORE it crosses into the server, so a malformed-id
/// frame is a typed [`BodyError::BadLength`] rather than a large reservation. Kept in lockstep with
/// `ironbus_core::txn::MAX_TXN_ID_LEN` (proto is dependency-light and does not import core).
pub const MAX_TXN_ID_LEN: usize = 256;

/// Reads a `u16`-length-prefixed transaction-id field, enforcing [`MAX_TXN_ID_LEN`] (#640). A declared
/// length over the cap is a typed [`BodyError::BadLength`] (fail-closed) BEFORE the bytes are taken, so
/// a hostile id cannot force an over-read; a short body is [`BodyError::Truncated`] via [`Reader::take`].
/// The returned slice borrows the body (zero-copy).
fn read_txn_id<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], BodyError> {
    let len = r.u16()? as usize;
    if len > MAX_TXN_ID_LEN {
        return Err(BodyError::BadLength);
    }
    r.take(len)
}

/// A producer's TRANSACTIONAL HALF-MESSAGE PREPARE (the `TxnPrepare` frame body, tag 44, #640): a
/// producer-supplied `txn_id`, the REAL target `stream_id`, and the verbatim [`PubBody`] bytes (the
/// half message's payload). The broker durably stores the half message INVISIBLE to consumers and acks;
/// a later [`TxnResolveBody`] commit/rollback resolves it. The `pub_body` is carried as an opaque
/// borrowed slice (decoded by the caller with [`decode_pub`]), so the publish body codec is shared
/// UNCHANGED with `Pub`/`PubTo`.
///
/// Layout (version+length framed): `body_version: u8`, `field_len: u16` (over the `txn_id` + `stream_id`
/// fields), then the v1 block: `txn_id: u16-len + bytes`, `stream_id: u16-len + bytes`; then the verbatim
/// `PubBody` bytes as the REMAINDER after the block (so a future version may grow the block while the
/// `PubBody` stays the tail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxnPrepareBody<'a> {
    /// The producer-supplied transaction id (the lifecycle key, capped at [`MAX_TXN_ID_LEN`]).
    pub txn_id: &'a [u8],
    /// The REAL target stream the committed payload is appended to (empty = the default stream).
    pub stream_id: &'a [u8],
    /// The verbatim [`PubBody`] bytes, decoded by the caller with [`decode_pub`].
    pub pub_body: &'a [u8],
}

/// Encodes a `TxnPrepare` body onto the end of `out` (#640): the version byte, the field-block length
/// over the `txn_id` + `stream_id` fields, those two fields, then the verbatim `pub_body` bytes. The
/// caller produces `pub_body` with [`encode_pub`].
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the txn id, stream id, or their framed block exceeds the
/// `u16` wire limit.
pub fn encode_txn_prepare(req: &TxnPrepareBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    // The block is the two u16-len-prefixed fields: (2 + txn_id) + (2 + stream_id).
    let block_len = 2usize
        .checked_add(req.txn_id.len())
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_add(req.stream_id.len()))
        .ok_or(BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(block_len).map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    push_var(out, req.txn_id)?;
    push_var(out, req.stream_id)?;
    out.extend_from_slice(req.pub_body);
    Ok(())
}

/// Decodes a `TxnPrepare` body (#640) into its `txn_id`, `stream_id`, and the verbatim `pub_body` tail,
/// cap-before-alloc and panic-free. The caller decodes `pub_body` with [`decode_pub`]. A body too short
/// for its declared block, a txn id over [`MAX_TXN_ID_LEN`], or a stream id over [`MAX_STREAM_ID_LEN`]
/// is a typed [`BodyError`] (fail-closed). An EMPTY body is NOT valid ([`BodyError::Truncated`]).
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap id/stream, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_txn_prepare(body: &[u8]) -> Result<TxnPrepareBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    // The PubBody is everything AFTER the declared block (a future version may grow the block without
    // disturbing the PubBody tail).
    let pub_body = r.rest();
    let mut fr = Reader::new(block);
    let txn_id = read_txn_id(&mut fr)?;
    let stream_id = read_stream_id(&mut fr)?;
    Ok(TxnPrepareBody {
        txn_id,
        stream_id,
        pub_body,
    })
}

/// A producer's TRANSACTIONAL COMMIT or ROLLBACK (the `TxnCommit` tag 45 / `TxnRollback` tag 46 frame
/// body, #640): it names the `txn_id` to resolve. The two verbs share this one body shape (the
/// [`FrameType`](crate::frame::FrameType)
/// disambiguates commit vs rollback), exactly as a request/response pair shares a tag elsewhere. A commit
/// replies a [`PubAck`](crate::frame::FrameType::PubAck) carrying the committed offset; a rollback replies
/// a body-less `Ok`.
///
/// Layout (version+length framed, forward-compatible): `body_version: u8` ([`STREAM_WIRE_BODY_VERSION`]),
/// `field_len: u16` (the length of the v1 block), then the v1 block: `txn_id: u16-len + bytes`. Bytes past
/// `field_len` (a future version's appended fields) are TOLERATED and ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxnResolveBody<'a> {
    /// The transaction id to commit or roll back (capped at [`MAX_TXN_ID_LEN`]).
    pub txn_id: &'a [u8],
}

/// Encodes a `TxnCommit` / `TxnRollback` body onto the end of `out` (#640): the version byte, the
/// field-block length over the `txn_id`, then the `txn_id`.
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the txn id exceeds the `u16` wire limit.
pub fn encode_txn_resolve(req: &TxnResolveBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    let id_len = u16::try_from(req.txn_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.txn_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&id_len.to_le_bytes());
    out.extend_from_slice(req.txn_id);
    Ok(())
}

/// Decodes a `TxnCommit` / `TxnRollback` body (#640) into its `txn_id`, cap-before-alloc and panic-free.
/// A body too short for its declared block, or a txn id over [`MAX_TXN_ID_LEN`], is a typed
/// [`BodyError`] (fail-closed). An EMPTY body is NOT valid ([`BodyError::Truncated`]).
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap id, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_txn_resolve(body: &[u8]) -> Result<TxnResolveBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    let txn_id = read_txn_id(&mut fr)?;
    Ok(TxnResolveBody { txn_id })
}

// ===================================================================================
// SUBJECT-ADDRESSED WIRE BODIES (#585, V2-M2-I9): the subject->stream binding + subject-addressed
// pub/sub verbs that complete the SUBJECTS story — BindSubject (tag 34), PubSubject (tag 35), SubSubject
// (tag 36). Each rides the SAME `body_version: u8` + `field_len: u16` frame as the explicit-stream-id
// verbs (#588), so a future version appends fields without a wire break. A subject/pattern field is a
// `u16`-length-prefixed byte field capped at [`MAX_STREAM_ID_LEN`] BEFORE any read (fail-closed): a
// malformed/oversized subject is a typed [`BodyError`], never a panic or over-read. The server further
// validates a subject through the #567 grammar; the wire cap only stops an absurdly long field. These are
// ADDITIVE tags an old client never sends; the explicit-stream-id verbs (tags 28-31) are unchanged.
// ===================================================================================

/// Reads a `u16`-length-prefixed subject/pattern field, reusing [`MAX_STREAM_ID_LEN`] as the wire cap
/// (#585). A declared length over the cap is a typed [`BodyError::BadLength`] (fail-closed) BEFORE the
/// bytes are taken; a short body is [`BodyError::Truncated`] via [`Reader::take`]. The slice borrows the
/// body (zero-copy). The server's #567 grammar is the real validator; this only fails a hostile length.
fn read_subject<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], BodyError> {
    let len = r.u16()? as usize;
    if len > MAX_STREAM_ID_LEN {
        return Err(BodyError::BadLength);
    }
    r.take(len)
}

/// A client's request to BIND a subject PATTERN to a stream (the `BindSubject` frame body, tag 34,
/// #585): an explicit `stream_id` (the empty name binds the DEFAULT stream) and a `pattern` (#567
/// pattern, wildcards allowed). The broker registers `(pattern -> stream)` and replies `Ok`, or `Err`
/// on a malformed pattern / stream name or a fork-bound rejection.
///
/// Layout (version+length framed): `body_version: u8`, `field_len: u16`, then the v1 block:
/// `stream_id: u16-len + bytes`, `pattern: u16-len + bytes`. Trailing block bytes are tolerated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindSubjectBody<'a> {
    /// The bound stream's name (empty binds the default stream), validated server-side.
    pub stream_id: &'a [u8],
    /// The subject PATTERN to bind (#567 pattern, validated server-side).
    pub pattern: &'a [u8],
}

/// Encodes a `BindSubject` body onto the end of `out` (#585).
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the stream id or pattern exceeds the `u16` wire limit.
pub fn encode_bind_subject(req: &BindSubjectBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    let id_len = u16::try_from(req.stream_id.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let pat_len = u16::try_from(req.pattern.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.stream_id.len() + 2 + req.pattern.len())
        .map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&id_len.to_le_bytes());
    out.extend_from_slice(req.stream_id);
    out.extend_from_slice(&pat_len.to_le_bytes());
    out.extend_from_slice(req.pattern);
    Ok(())
}

/// Decodes a `BindSubject` body (#585), cap-before-alloc and panic-free. A short body or an over-cap
/// field is a typed [`BodyError`]; an EMPTY body is [`BodyError::Truncated`].
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap field, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_bind_subject(body: &[u8]) -> Result<BindSubjectBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    let stream_id = read_stream_id(&mut fr)?;
    let pattern = read_subject(&mut fr)?;
    Ok(BindSubjectBody { stream_id, pattern })
}

/// A producer's publish BY SUBJECT (the `PubSubject` frame body, tag 35, #585): a literal `subject`
/// followed by the verbatim [`PubBody`] bytes (decoded by the caller with [`decode_pub`], so the publish
/// body codec is shared UNCHANGED with `Pub`/`PubTo`). The broker resolves the subject single-home to one
/// bound stream and routes the append there (or rejects unbound/ambiguous, fail-closed).
///
/// Layout (version+length framed): `body_version: u8`, `field_len: u16` (over the `subject` field ONLY),
/// then the v1 block: `subject: u16-len + bytes`; then the verbatim `PubBody` bytes as the REMAINDER.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubSubjectBody<'a> {
    /// The literal subject to publish on (validated #567 literal server-side).
    pub subject: &'a [u8],
    /// The verbatim [`PubBody`] bytes, decoded by the caller with [`decode_pub`].
    pub pub_body: &'a [u8],
}

/// Encodes a `PubSubject` body onto the end of `out` (#585): the version byte, the field-block length
/// over the subject, the subject, then the verbatim `pub_body` bytes.
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the subject exceeds the `u16` wire limit.
pub fn encode_pub_subject(req: &PubSubjectBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    let subj_len = u16::try_from(req.subject.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.subject.len()).map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&subj_len.to_le_bytes());
    out.extend_from_slice(req.subject);
    out.extend_from_slice(req.pub_body);
    Ok(())
}

/// Decodes a `PubSubject` body (#585) into its `subject` and the verbatim `pub_body` tail,
/// cap-before-alloc and panic-free. A short body or an over-cap subject is a typed [`BodyError`]; an
/// EMPTY body is [`BodyError::Truncated`].
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap subject, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_pub_subject(body: &[u8]) -> Result<PubSubjectBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let pub_body = r.rest();
    let mut fr = Reader::new(block);
    let subject = read_subject(&mut fr)?;
    Ok(PubSubjectBody { subject, pub_body })
}

/// A consumer's subscribe BY SUBJECT (the `SubSubject` frame body, tag 36, #585): a `subject` (literal
/// or wildcard) plus the work-`group` name. The broker resolves the subject single-home to one bound
/// stream and binds the connection's subsequent `Flow`/`Ack` to that stream's competing work-group (or
/// rejects unbound/ambiguous, fail-closed).
///
/// Layout (version+length framed): `body_version: u8`, `field_len: u16`, then the v1 block:
/// `subject: u16-len + bytes`, `group: u16-len + bytes`. Trailing block bytes are tolerated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubSubjectBody<'a> {
    /// The subject to subscribe on (a literal or wildcard pattern, validated server-side).
    pub subject: &'a [u8],
    /// The work-group name (empty selects the default group), validated server-side.
    pub group: &'a [u8],
}

/// Encodes a `SubSubject` body onto the end of `out` (#585): the version byte, the field-block length,
/// then the subject and group, each `u16`-length-prefixed.
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the subject or group exceeds the `u16` wire limit.
pub fn encode_sub_subject(req: &SubSubjectBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    let subj_len = u16::try_from(req.subject.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let group_len = u16::try_from(req.group.len()).map_err(|_| BodyError::FieldTooLarge)?;
    let field_len = u16::try_from(2 + req.subject.len() + 2 + req.group.len())
        .map_err(|_| BodyError::FieldTooLarge)?;
    out.push(STREAM_WIRE_BODY_VERSION);
    out.extend_from_slice(&field_len.to_le_bytes());
    out.extend_from_slice(&subj_len.to_le_bytes());
    out.extend_from_slice(req.subject);
    out.extend_from_slice(&group_len.to_le_bytes());
    out.extend_from_slice(req.group);
    Ok(())
}

/// Decodes a `SubSubject` body (#585), cap-before-alloc and panic-free. A short body or an over-cap
/// subject is a typed [`BodyError`]; an EMPTY body is [`BodyError::Truncated`].
///
/// # Errors
/// [`BodyError::Truncated`] for a short body, [`BodyError::BadLength`] for an over-cap subject, or
/// [`BodyError::BadHandshakeVersion`] for an unknown body version.
pub fn decode_sub_subject(body: &[u8]) -> Result<SubSubjectBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != STREAM_WIRE_BODY_VERSION {
        return Err(BodyError::BadHandshakeVersion { version });
    }
    let field_len = r.u16()? as usize;
    let block = r.take(field_len)?;
    let mut fr = Reader::new(block);
    let subject = read_subject(&mut fr)?;
    let group = fr.var()?;
    Ok(SubSubjectBody { subject, group })
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
            understands_streaming: false,
            default_tier: None,
            understands_deliver_batch: false,
            understands_streams: false,
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
            streaming: false,
            default_tier: None,
            deliver_batch: false,
            streams: false,
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
            seq: None,
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
    fn pub_with_an_idempotent_sequence_round_trips_and_sets_the_seq_bit() {
        // V2-M8: the opt-in idempotent SEQUENCE rides inside the dedup block, after the msg_id, and
        // sets PUB_FLAG_HAS_SEQ (bit 5). It round-trips and carries the u64 sequence.
        let dedup = PubDedup {
            producer_id: b"producer-9",
            epoch: 7,
            msg_id: b"k",
            seq: Some(0xDEAD_BEEF),
        };
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 3,
            key: b"",
            headers: b"",
            dedup: Some(dedup),
            fire_and_forget: false,
            payload: b"body",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(buf[0] & PUB_FLAG_HAS_SEQ, PUB_FLAG_HAS_SEQ);
        assert_eq!(buf[0] & PUB_FLAG_HAS_DEDUP, PUB_FLAG_HAS_DEDUP);
        let got = decode_pub(&buf).unwrap();
        assert_eq!(got.dedup, Some(dedup));
        assert_eq!(got.dedup.unwrap().seq, Some(0xDEAD_BEEF));
        assert_eq!(got.payload, b"body");
    }

    #[test]
    fn a_dedup_pub_without_a_sequence_is_byte_for_byte_the_pre_m8_dedup_layout() {
        // Back-compat: a dedup block with NO sequence must be EXACTLY the pre-M8 dedup-block layout
        // (no trailing u64, the seq bit clear), so the existing msg_id-window dedup path is unchanged.
        let dedup = PubDedup {
            producer_id: b"pid",
            epoch: 0x1122_3344_5566_7788,
            msg_id: b"mid",
            seq: None,
        };
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 1,
            key: b"k",
            headers: b"h",
            dedup: Some(dedup),
            fire_and_forget: false,
            payload: b"p",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        let mut expected = Vec::new();
        expected.push(PUB_FLAG_HAS_DEDUP); // only the dedup bit, NOT the seq bit
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(b"k");
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(b"h");
        expected.extend_from_slice(&3u16.to_le_bytes());
        expected.extend_from_slice(b"pid");
        expected.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        expected.extend_from_slice(&3u16.to_le_bytes());
        expected.extend_from_slice(b"mid");
        expected.extend_from_slice(b"p"); // payload immediately after msg_id, NO trailing seq u64
        assert_eq!(
            buf, expected,
            "a no-seq dedup PUB must match the pre-M8 layout"
        );
        assert_eq!(buf[0] & PUB_FLAG_HAS_SEQ, 0, "the seq bit stays clear");
    }

    #[test]
    fn a_seq_bit_without_a_dedup_block_is_rejected_fail_closed() {
        // A malformed body that sets the seq bit but no dedup bit is a protocol violation: the
        // decoder rejects it rather than folding the would-be sequence into the payload.
        let mut buf = Vec::new();
        buf.push(PUB_FLAG_HAS_SEQ); // seq bit set, dedup bit clear
        buf.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u16.to_le_bytes()); // key len 0
        buf.extend_from_slice(&0u16.to_le_bytes()); // headers len 0
        assert_eq!(decode_pub(&buf), Err(BodyError::BadLength));
    }

    #[test]
    fn a_truncated_sequence_field_is_rejected_not_panicked() {
        // The seq bit is set and the dedup block is present, but the body ends before the u64
        // sequence: a typed error, never a panic.
        let mut buf = Vec::new();
        buf.push(PUB_FLAG_HAS_DEDUP | PUB_FLAG_HAS_SEQ);
        buf.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u16.to_le_bytes()); // key
        buf.extend_from_slice(&0u16.to_le_bytes()); // headers
        buf.extend_from_slice(&0u16.to_le_bytes()); // producer_id len 0
        buf.extend_from_slice(&0u64.to_le_bytes()); // epoch
        buf.extend_from_slice(&0u16.to_le_bytes()); // msg_id len 0
        buf.extend_from_slice(&[0u8; 3]); // only 3 of the 8 seq bytes
        assert!(decode_pub(&buf).is_err());
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
            seq: None,
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
    fn deliver_batch_header_round_trips_with_the_record_bytes_carried_verbatim() {
        // #541: the DeliverBatch frame body is the fixed header (first_offset / generation /
        // record_count) followed by the contiguous on-disk record-frame bytes carried VERBATIM. The
        // header round-trips and the record bytes are returned by reference, byte-for-byte unchanged.
        let header = DeliverBatchHeader {
            first_offset: 0x0102_0304_0506_0708,
            generation: 0,
            record_count: 3,
        };
        let record_bytes = b"on-disk-frame-bytes-here";
        let mut buf = Vec::new();
        encode_deliver_batch(&header, record_bytes, &mut buf);
        let (decoded, decoded_bytes) = decode_deliver_batch(&buf).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(decoded_bytes, record_bytes, "record bytes ship verbatim");
        // An EMPTY record body is valid (a zero-record batch): the header still frames.
        let empty_header = DeliverBatchHeader {
            first_offset: 7,
            generation: 0,
            record_count: 0,
        };
        let mut ebuf = Vec::new();
        encode_deliver_batch(&empty_header, &[], &mut ebuf);
        let (eh, eb) = decode_deliver_batch(&ebuf).unwrap();
        assert_eq!(eh, empty_header);
        assert!(eb.is_empty());
    }

    #[test]
    fn deliver_batch_rejects_an_empty_or_short_body_and_an_unknown_version() {
        // The frame type is new: an empty body is not a valid frame (no historical empty case).
        assert_eq!(decode_deliver_batch(&[]), Err(BodyError::Truncated));
        // A declared field_len longer than the body is a typed length error, never an over-read.
        let mut bad = vec![DELIVER_BATCH_HEADER_VERSION];
        bad.extend_from_slice(&99u16.to_le_bytes()); // declares 99 header bytes but supplies none
        assert!(matches!(
            decode_deliver_batch(&bad),
            Err(BodyError::Truncated | BodyError::BadLength)
        ));
        // An unknown header version is rejected, not best-effort parsed (so a future layout is never
        // mis-decoded as v1).
        let mut wrong = Vec::new();
        encode_deliver_batch(
            &DeliverBatchHeader {
                first_offset: 1,
                generation: 0,
                record_count: 0,
            },
            &[],
            &mut wrong,
        );
        wrong[0] = DELIVER_BATCH_HEADER_VERSION + 1;
        assert_eq!(
            decode_deliver_batch(&wrong),
            Err(BodyError::BadHandshakeVersion {
                version: DELIVER_BATCH_HEADER_VERSION + 1
            })
        );
    }

    #[test]
    fn deliver_batch_tolerates_a_future_appended_header_field() {
        // FORWARD-COMPAT: a future version may APPEND fields inside the declared header block; a v1
        // reader reads its known fields and the record bytes still begin right after the declared block,
        // so a present future header field never bleeds into the record bytes. Hand-build a body whose
        // header block is one byte longer than v1 (a future field), then a record-bytes tail.
        let mut buf = vec![DELIVER_BATCH_HEADER_VERSION];
        let extended_len = DELIVER_BATCH_V1_FIELD_LEN + 1;
        buf.extend_from_slice(&extended_len.to_le_bytes());
        buf.extend_from_slice(&123u64.to_le_bytes()); // first_offset
        buf.extend_from_slice(&0u64.to_le_bytes()); // generation
        buf.extend_from_slice(&5u32.to_le_bytes()); // record_count
        buf.push(0xAB); // a FUTURE appended header byte, inside the declared block
        buf.extend_from_slice(b"record-bytes"); // the body proper begins AFTER the declared block
        let (header, record_bytes) = decode_deliver_batch(&buf).unwrap();
        assert_eq!(header.first_offset, 123);
        assert_eq!(header.record_count, 5);
        assert_eq!(
            record_bytes, b"record-bytes",
            "record bytes begin after the declared header block, not after the v1 fields"
        );
    }

    #[test]
    fn connect_and_info_carry_the_deliver_batch_capability_bit() {
        // #541: a batch-capable consumer sets the capability bit (a pure flags bit, no block byte); the
        // bit round-trips and an EMPTY (old-client) Connect never advertises it. The Info echo mirrors it.
        let req = ConnectBody {
            understands_deliver_batch: true,
            ..ConnectBody::default()
        };
        let mut buf = Vec::new();
        encode_connect(&req, &mut buf);
        assert_eq!(
            buf[3] & CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH,
            CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH,
            "the capability bit is set in the flags byte"
        );
        // The capability is a PURE flags bit: setting it appends NO byte to the v1 block.
        let mut plain = Vec::new();
        encode_connect(&ConnectBody::default(), &mut plain);
        assert_eq!(buf.len(), plain.len(), "the capability bit appends no byte");
        assert_eq!(decode_connect(&buf).unwrap(), req);
        // An EMPTY (old-client) Connect body never advertises the capability.
        assert!(!decode_connect(&[]).unwrap().understands_deliver_batch);

        let info = InfoBody {
            deliver_batch: true,
            ..InfoBody::default()
        };
        let mut ibuf = Vec::new();
        encode_info(&info, &mut ibuf);
        assert_eq!(
            ibuf[3] & INFO_FLAG_DELIVER_BATCH,
            INFO_FLAG_DELIVER_BATCH,
            "the capability confirmation bit is set in the flags byte"
        );
        assert_eq!(decode_info(&ibuf).unwrap(), info);
        // An EMPTY (old-server) Info body never confirms the capability.
        assert!(!decode_info(&[]).unwrap().deliver_batch);
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
            seq in prop::option::of(any::<u64>()),
            payload in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let dedup = PubDedup { producer_id: &producer_id, epoch, msg_id: &msg_id, seq };
            let msg = PubBody { flags, timestamp_ms, key: &key, headers: &headers, dedup: Some(dedup), fire_and_forget: false, payload: &payload };
            let mut buf = Vec::new();
            encode_pub(&msg, &mut buf).unwrap();
            let got = decode_pub(&buf).unwrap();
            // The wire body carries the dedup bit regardless of the caller's flags input, and the
            // idempotent-SEQUENCE bit (V2-M8) is set iff a `seq` was present.
            prop_assert_eq!(got.flags & PUB_FLAG_HAS_DEDUP, PUB_FLAG_HAS_DEDUP);
            prop_assert_eq!(got.flags & PUB_FLAG_HAS_SEQ != 0, seq.is_some());
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
            understands_streaming in any::<bool>(),
            default_tier in proptest::option::of(any::<u8>()),
            understands_deliver_batch in any::<bool>(),
            understands_streams in any::<bool>(),
        ) {
            let req = ConnectBody { requested_credit: credit, requested_credit_bytes: credit_bytes, wants_gap_marker, default_ack_level, understands_streaming, default_tier, understands_deliver_batch, understands_streams };
            let mut buf = Vec::new();
            encode_connect(&req, &mut buf);
            prop_assert_eq!(buf[0], HANDSHAKE_BODY_VERSION, "the body leads with its version");
            prop_assert_eq!(decode_connect(&buf).unwrap(), req);
        }

        /// An Info body round-trips for any combination of present/absent advertised credit and byte
        /// budget (#292), the gap-marker capability bit (#346), the appended `default_ack_level`
        /// (#494), the streaming capability bit and the appended `default_tier` (#543): each survives
        /// the round-trip, including BOTH appended bytes present together at independent offsets.
        #[test]
        fn any_info_round_trips(
            credit in proptest::option::of((any::<u32>(), any::<u32>())),
            credit_bytes in proptest::option::of((any::<u64>(), any::<u64>())),
            gap_marker in any::<bool>(),
            default_ack_level in proptest::option::of(any::<u8>()),
            streaming in any::<bool>(),
            default_tier in proptest::option::of(any::<u8>()),
            deliver_batch in any::<bool>(),
            streams in any::<bool>(),
        ) {
            let info = InfoBody {
                credit: credit.map(|(negotiated, cap)| CreditAdvert { negotiated, cap }),
                credit_bytes: credit_bytes.map(|(negotiated, cap)| CreditAdvert { negotiated, cap }),
                gap_marker,
                default_ack_level,
                streaming,
                default_tier,
                deliver_batch,
                streams,
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
            let req = ConnectBody { requested_credit: credit, requested_credit_bytes: None, wants_gap_marker: false, default_ack_level: None, understands_streaming: false, default_tier: None, understands_deliver_batch: false, understands_streams: false };
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
                streaming: false,
                default_tier: None,
                deliver_batch: false,
                streams: false,
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
                understands_streaming: false,
                default_tier: None,
                understands_deliver_batch: false,
                understands_streams: false,
            }
        );
    }

    #[test]
    fn connect_auth_is_absent_on_old_and_empty_bodies() {
        // The load-bearing backward-compat property (#631): a body that carries no auth section
        // parses to `None` on EVERY no-auth shape, so an old client (and the empty Connect body)
        // is byte-for-byte unchanged and authenticates nothing on the wire.
        assert_eq!(
            parse_connect_auth(&[]).unwrap(),
            None,
            "empty body = no auth"
        );
        let mut full = Vec::new();
        encode_connect(
            &ConnectBody {
                requested_credit: Some(32),
                requested_credit_bytes: Some(1024),
                wants_gap_marker: true,
                default_ack_level: Some(2),
                understands_streaming: true,
                default_tier: Some(1),
                understands_deliver_batch: true,
                understands_streams: true,
            },
            &mut full,
        );
        // A full v1 body WITHOUT an appended auth section still parses to no auth: the appended
        // ack-level/tier bytes are skipped and the reader lands at end with nothing trailing.
        assert_eq!(
            parse_connect_auth(&full).unwrap(),
            None,
            "a full v1 body with no auth section = no auth"
        );
    }

    #[test]
    fn connect_auth_round_trips_each_mechanism() {
        for cred in [
            AuthCredential {
                mechanism: AuthMechanism::Bearer,
                material: b"a-high-entropy-token".to_vec(),
            },
            AuthCredential {
                mechanism: AuthMechanism::Password,
                material: pack_password_material(b"alice", b"correct horse").unwrap(),
            },
            AuthCredential {
                mechanism: AuthMechanism::Mtls,
                material: Vec::new(),
            },
        ] {
            // Minimal-body base (mTLS-style: the client lays down a default v1 body, then the
            // selector). A version header must precede the trailing auth section.
            let mut buf = Vec::new();
            encode_connect(&ConnectBody::default(), &mut buf);
            append_connect_auth(&mut buf, &cred).unwrap();
            assert_eq!(parse_connect_auth(&buf).unwrap(), Some(cred.clone()));

            // And appended onto a real v1 body with appended ack-level + tier bytes, to prove the
            // reader walks PAST those to find the trailing auth section at the right offset.
            let mut body = Vec::new();
            encode_connect(
                &ConnectBody {
                    requested_credit: Some(7),
                    requested_credit_bytes: None,
                    wants_gap_marker: false,
                    default_ack_level: Some(1),
                    understands_streaming: true,
                    default_tier: Some(1),
                    understands_deliver_batch: false,
                    understands_streams: false,
                },
                &mut body,
            );
            append_connect_auth(&mut body, &cred).unwrap();
            assert_eq!(parse_connect_auth(&body).unwrap(), Some(cred.clone()));
            // The v1 fields still decode correctly with the auth section trailing (it is ignored by
            // decode_connect, which only reads its field_len block + appended bytes).
            let decoded = decode_connect(&body).unwrap();
            assert_eq!(decoded.requested_credit, Some(7));
            assert_eq!(decoded.default_tier, Some(1));
        }
    }

    #[test]
    fn connect_password_material_round_trips_and_rejects_trailing() {
        let m = pack_password_material(b"user", b"pw").unwrap();
        assert_eq!(
            unpack_password_material(&m).unwrap(),
            (&b"user"[..], &b"pw"[..])
        );
        // A malformed (extra-byte) material fails closed.
        let mut bad = m.clone();
        bad.push(0);
        assert_eq!(
            unpack_password_material(&bad),
            Err(BodyError::TrailingBytes)
        );
    }

    #[test]
    fn connect_auth_unknown_mechanism_is_fail_closed() {
        // A present auth section (marker seen) with an unknown mechanism selector is a typed error,
        // NOT a silent fall-through to no-auth: the server maps it to the uniform Authorization
        // Violation. This is the no-silent-weakening property at the wire layer.
        let mut buf = Vec::new();
        encode_connect(&ConnectBody::default(), &mut buf);
        buf.push(CONNECT_AUTH_SECTION_MARKER);
        buf.push(0xFF); // unknown mechanism selector
        buf.extend_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            parse_connect_auth(&buf),
            Err(BodyError::BadAckOp { op: 0xFF })
        ));
    }

    #[test]
    fn connect_auth_truncated_section_is_fail_closed() {
        // Marker present but the credential is truncated: an error, never no-auth.
        let mut truncated = Vec::new();
        encode_connect(&ConnectBody::default(), &mut truncated);
        truncated.push(CONNECT_AUTH_SECTION_MARKER);
        truncated.push(AuthMechanism::Bearer.as_u8());
        // no u16 length / material follows
        assert!(parse_connect_auth(&truncated).is_err());
    }

    #[test]
    fn connect_non_marker_trailing_byte_is_ignored_as_no_auth() {
        // Forward-compat: a trailing byte that is not the auth marker (a hypothetical future trailing
        // field) leaves auth = None and never errors, exactly as the tolerate-trailing rule requires.
        let mut buf = Vec::new();
        encode_connect(&ConnectBody::default(), &mut buf);
        buf.push(0x01); // not CONNECT_AUTH_SECTION_MARKER
        assert_eq!(parse_connect_auth(&buf).unwrap(), None);
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
                streaming: false,
                default_tier: None,
                deliver_batch: false,
                streams: false,
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
            understands_streaming: false,
            default_tier: None,
            understands_deliver_batch: false,
            understands_streams: false,
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
            streaming: false,
            default_tier: None,
            deliver_batch: false,
            streams: false,
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
        // 0..=2) and BELOW the existing wire-only bits (the idempotent-seq bit 5, faf bit 6, dedup bit
        // 7), colliding with none. This pins the chosen free bits so a future flag steals a different
        // bit, not these.
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK, 0b0001_1000);
        assert_eq!(PUB_FLAG_ACK_LEVEL_SHIFT, 3);
        // The idempotent-producer SEQUENCE bit (V2-M8) is bit 5, between the ack-level field and faf.
        assert_eq!(PUB_FLAG_HAS_SEQ, 0b0010_0000);
        // No overlap with the other wire-only bits.
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK & PUB_FLAG_FIRE_AND_FORGET, 0);
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK & PUB_FLAG_HAS_DEDUP, 0);
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK & PUB_FLAG_HAS_SEQ, 0);
        assert_eq!(PUB_FLAG_HAS_SEQ & PUB_FLAG_FIRE_AND_FORGET, 0);
        assert_eq!(PUB_FLAG_HAS_SEQ & PUB_FLAG_HAS_DEDUP, 0);
        // No overlap with the stored record flags (the low 3 bits, RecordFlags::KNOWN = 0b111).
        assert_eq!(PUB_FLAG_ACK_LEVEL_MASK & 0b0000_0111, 0);
        assert_eq!(PUB_FLAG_HAS_SEQ & 0b0000_0111, 0);
        // And the full wire-only mask is exactly the union of the four.
        assert_eq!(
            PUB_WIRE_ONLY_FLAGS,
            PUB_FLAG_HAS_DEDUP
                | PUB_FLAG_FIRE_AND_FORGET
                | PUB_FLAG_ACK_LEVEL_MASK
                | PUB_FLAG_HAS_SEQ
        );
        assert_eq!(PUB_WIRE_ONLY_FLAGS, 0b1111_1000);
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
            understands_streaming: false,
            default_tier: None,
            understands_deliver_batch: false,
            understands_streams: false,
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
            &(CONNECT_V1_FIELD_LEN + 1).to_le_bytes(),
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
            streaming: false,
            default_tier: None,
            deliver_batch: false,
            streams: false,
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
        assert_eq!(&buf[1..3], &(INFO_V1_FIELD_LEN + 1).to_le_bytes());
        assert_eq!(
            buf[3] & INFO_FLAG_HAS_DEFAULT_ACK_LEVEL,
            INFO_FLAG_HAS_DEFAULT_ACK_LEVEL
        );
        assert_eq!(buf.len(), pre.len() + 1);
        assert_eq!(*buf.last().unwrap(), 2);
        assert_eq!(decode_info(&buf).unwrap(), with_level);
    }

    #[test]
    fn connect_carries_the_streaming_capability_and_default_tier_and_old_client_is_byte_identical()
    {
        // #543: a streaming-capable consumer sets the capability bit (a pure flags bit, no block byte)
        // and MAY append a connection-default tier byte. An old client (or one that defers both) leaves
        // them clear/None, so the body is byte-for-byte the layout WITHOUT them.
        let none = ConnectBody {
            requested_credit: Some(7),
            requested_credit_bytes: None,
            wants_gap_marker: false,
            default_ack_level: None,
            understands_streaming: false,
            default_tier: None,
            understands_deliver_batch: false,
            understands_streams: false,
        };
        let mut pre = Vec::new();
        encode_connect(&none, &mut pre);
        assert_eq!(
            pre[3] & (CONNECT_FLAG_UNDERSTANDS_STREAMING | CONNECT_FLAG_HAS_DEFAULT_TIER),
            0,
            "neither the capability nor the default-tier bit is set"
        );
        assert_eq!(
            pre.len(),
            3 + usize::from(CONNECT_V1_FIELD_LEN),
            "no appended tier byte"
        );
        assert_eq!(decode_connect(&pre).unwrap(), none);

        // The capability bit is a PURE flags bit: setting it adds NO appended byte, so the body length
        // is unchanged, only the flags bit flips.
        let cap_only = ConnectBody {
            understands_streaming: true,
            ..none
        };
        let mut cap_buf = Vec::new();
        encode_connect(&cap_only, &mut cap_buf);
        assert_eq!(
            cap_buf[3] & CONNECT_FLAG_UNDERSTANDS_STREAMING,
            CONNECT_FLAG_UNDERSTANDS_STREAMING
        );
        assert_eq!(
            cap_buf.len(),
            pre.len(),
            "the capability bit appends no byte"
        );
        assert_eq!(decode_connect(&cap_buf).unwrap(), cap_only);

        // A streaming-capable client that ALSO requests a Tier-S default appends exactly one tier byte
        // and sets the default-tier presence bit; the value round-trips via `ConsumeTier::from_u8`.
        let with_tier = ConnectBody {
            understands_streaming: true,
            default_tier: Some(ConsumeTier::Streaming.as_u8()),
            ..none
        };
        let mut buf = Vec::new();
        encode_connect(&with_tier, &mut buf);
        assert_eq!(
            buf[3] & CONNECT_FLAG_HAS_DEFAULT_TIER,
            CONNECT_FLAG_HAS_DEFAULT_TIER
        );
        assert_eq!(buf.len(), pre.len() + 1, "exactly one appended tier byte");
        assert_eq!(*buf.last().unwrap(), ConsumeTier::Streaming.as_u8());
        let decoded = decode_connect(&buf).unwrap();
        assert_eq!(decoded, with_tier);
        assert_eq!(
            decoded.default_tier.map(ConsumeTier::from_u8),
            Some(ConsumeTier::Streaming)
        );
    }

    #[test]
    fn info_echoes_the_streaming_capability_and_default_tier_and_old_server_is_byte_identical() {
        // #543: the server->client twin. An old server (or one that confirms neither) is byte-for-byte
        // the layout without the echo; a confirming server flips the capability bit and may append the
        // echoed default-tier byte.
        let none = InfoBody {
            credit: None,
            credit_bytes: None,
            gap_marker: false,
            default_ack_level: None,
            streaming: false,
            default_tier: None,
            deliver_batch: false,
            streams: false,
        };
        let mut pre = Vec::new();
        encode_info(&none, &mut pre);
        assert_eq!(
            pre[3] & (INFO_FLAG_STREAMING | INFO_FLAG_HAS_DEFAULT_TIER),
            0
        );
        assert_eq!(pre.len(), 3 + usize::from(INFO_V1_FIELD_LEN));
        assert_eq!(decode_info(&pre).unwrap(), none);

        let with_tier = InfoBody {
            streaming: true,
            default_tier: Some(ConsumeTier::Streaming.as_u8()),
            ..none
        };
        let mut buf = Vec::new();
        encode_info(&with_tier, &mut buf);
        assert_eq!(buf[3] & INFO_FLAG_STREAMING, INFO_FLAG_STREAMING);
        assert_eq!(
            buf[3] & INFO_FLAG_HAS_DEFAULT_TIER,
            INFO_FLAG_HAS_DEFAULT_TIER
        );
        assert_eq!(buf.len(), pre.len() + 1, "exactly one appended tier byte");
        assert_eq!(*buf.last().unwrap(), ConsumeTier::Streaming.as_u8());
        assert_eq!(decode_info(&buf).unwrap(), with_tier);
    }

    #[test]
    fn connect_with_both_appended_bytes_keeps_them_at_independent_offsets() {
        // #494 + #543 together: BOTH appended bytes present. They are written in declared order
        // (ack-level, then tier) and read in the SAME order, so each lands at its own offset and both
        // round-trip — the appended-byte discipline composes.
        let both = ConnectBody {
            requested_credit: None,
            requested_credit_bytes: None,
            wants_gap_marker: false,
            default_ack_level: Some(AckLevel::ServerAndClientAck.as_u8()),
            understands_streaming: true,
            default_tier: Some(ConsumeTier::Streaming.as_u8()),
            understands_deliver_batch: false,
            understands_streams: false,
        };
        let mut buf = Vec::new();
        encode_connect(&both, &mut buf);
        // field_len = historical + 2 appended bytes; the last two block bytes are ack-level then tier.
        assert_eq!(&buf[1..3], &(CONNECT_V1_FIELD_LEN + 2).to_le_bytes());
        assert_eq!(buf[buf.len() - 2], AckLevel::ServerAndClientAck.as_u8());
        assert_eq!(buf[buf.len() - 1], ConsumeTier::Streaming.as_u8());
        assert_eq!(decode_connect(&buf).unwrap(), both);

        // FORWARD-COMPAT: a future version appends MORE fields past the declared block; a v1 reader
        // tolerates the trailing bytes and still recovers every v1 field (including both appended bytes).
        let mut extended = buf.clone();
        extended.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(
            decode_connect(&extended).unwrap(),
            both,
            "trailing future bytes are ignored, the appended bytes still decode"
        );
    }

    #[test]
    fn consume_tier_folds_unknown_values_to_work() {
        // A future tier value the proto does not yet name folds to the safe Tier-W default rather than
        // erroring, so the field can grow without a wire break (mirrors `pub_ack_level`'s reserved-value
        // handling). Only the exact value 1 is Tier-S.
        assert_eq!(ConsumeTier::from_u8(0), ConsumeTier::Work);
        assert_eq!(ConsumeTier::from_u8(1), ConsumeTier::Streaming);
        for raw in 2u8..=255 {
            assert_eq!(
                ConsumeTier::from_u8(raw),
                ConsumeTier::Work,
                "an unknown future tier {raw} degrades to Tier-W"
            );
        }
        assert_eq!(ConsumeTier::Work.as_u8(), 0);
        assert_eq!(ConsumeTier::Streaming.as_u8(), 1);
        assert_eq!(ConsumeTier::default(), ConsumeTier::Work);
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
                understands_streaming: false,
                default_tier: None,
                understands_deliver_batch: false,
                understands_streams: false,
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
                streaming: false,
                default_tier: None,
                deliver_batch: false,
                streams: false,
            }
        );
    }

    // ===== Stream-addressed wire bodies (#588, V2-M2-I10) =====

    #[test]
    fn connect_and_info_carry_the_streams_capability_bit() {
        // #588: a streams-capable client sets CONNECT_FLAG_UNDERSTANDS_STREAMS (a pure flags bit, no
        // block byte); the bit round-trips, appends no byte, and an EMPTY (old-client) Connect never
        // advertises it. The Info echo (INFO_FLAG_STREAMS) mirrors it.
        let req = ConnectBody {
            understands_streams: true,
            ..ConnectBody::default()
        };
        let mut buf = Vec::new();
        encode_connect(&req, &mut buf);
        assert_eq!(
            buf[3] & CONNECT_FLAG_UNDERSTANDS_STREAMS,
            CONNECT_FLAG_UNDERSTANDS_STREAMS,
            "the streams capability bit is set in the flags byte"
        );
        let mut plain = Vec::new();
        encode_connect(&ConnectBody::default(), &mut plain);
        assert_eq!(
            buf.len(),
            plain.len(),
            "the streams capability bit appends no block byte"
        );
        assert_eq!(decode_connect(&buf).unwrap(), req);
        // An EMPTY (old-client) Connect never advertises streams.
        assert!(!decode_connect(&[]).unwrap().understands_streams);

        let info = InfoBody {
            streams: true,
            ..InfoBody::default()
        };
        let mut ibuf = Vec::new();
        encode_info(&info, &mut ibuf);
        assert_eq!(
            ibuf[3] & INFO_FLAG_STREAMS,
            INFO_FLAG_STREAMS,
            "the Info streams echo bit is set"
        );
        assert_eq!(decode_info(&ibuf).unwrap(), info);
        assert!(!decode_info(&[]).unwrap().streams);
    }

    #[test]
    fn stream_declare_and_info_round_trip_with_the_stream_id() {
        // #588: StreamDeclare / StreamInfo (request) carry the stream id under version+length framing,
        // round-tripping exactly. The default-stream empty id round-trips too.
        for id in [b"orders".as_slice(), b"", b"a/b.c-1"] {
            let mut buf = Vec::new();
            encode_stream_declare(&StreamDeclareBody { stream_id: id }, &mut buf).unwrap();
            assert_eq!(
                buf[0], STREAM_WIRE_BODY_VERSION,
                "leads with the body version"
            );
            assert_eq!(decode_stream_declare(&buf).unwrap().stream_id, id);

            let mut ibuf = Vec::new();
            encode_stream_info(&StreamInfoBody { stream_id: id }, &mut ibuf).unwrap();
            assert_eq!(decode_stream_info(&ibuf).unwrap().stream_id, id);
        }
    }

    #[test]
    fn stream_info_response_round_trips_existence_and_head() {
        // #588: the StreamInfo response carries exists + head; a non-existent stream reports head 0.
        for (exists, head) in [(true, 42u64), (false, 0), (true, 0)] {
            let resp = StreamInfoResponseBody { exists, head };
            let mut buf = Vec::new();
            encode_stream_info_response(&resp, &mut buf);
            assert_eq!(decode_stream_info_response(&buf).unwrap(), resp);
        }
    }

    #[test]
    fn pub_to_carries_the_stream_id_and_the_verbatim_pub_body() {
        // #588: PubTo prefixes a stream id, then carries the EXISTING PubBody bytes verbatim, so the
        // session reuses decode_pub UNCHANGED. The pub_body round-trips byte-for-byte and decodes back
        // through the existing codec.
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 7,
                key: b"k",
                headers: b"h",
                dedup: None,
                fire_and_forget: false,
                payload: b"hello-named-stream",
            },
            &mut pub_body,
        )
        .unwrap();
        let mut buf = Vec::new();
        encode_pub_to(
            &PubToBody {
                stream_id: b"orders",
                pub_body: &pub_body,
            },
            &mut buf,
        )
        .unwrap();
        let decoded = decode_pub_to(&buf).unwrap();
        assert_eq!(decoded.stream_id, b"orders");
        assert_eq!(decoded.pub_body, pub_body.as_slice());
        // The carried pub_body decodes through the UNCHANGED PubBody codec.
        let pb = decode_pub(decoded.pub_body).unwrap();
        assert_eq!(pb.payload, b"hello-named-stream");
        assert_eq!(pb.key, b"k");
    }

    #[test]
    fn txn_prepare_carries_txn_id_stream_and_the_verbatim_pub_body() {
        // #640: TxnPrepare prefixes the txn id + target stream, then carries the EXISTING PubBody bytes
        // verbatim, so the session reuses decode_pub UNCHANGED. Every field round-trips and the pub_body
        // decodes back through the existing codec.
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 9,
                key: b"k",
                headers: b"h",
                dedup: None,
                fire_and_forget: false,
                payload: b"half-message",
            },
            &mut pub_body,
        )
        .unwrap();
        for (txn, stream) in [
            (b"tx-1".as_slice(), b"orders".as_slice()),
            (b"tx-1", b""), // default stream
        ] {
            let mut buf = Vec::new();
            encode_txn_prepare(
                &TxnPrepareBody {
                    txn_id: txn,
                    stream_id: stream,
                    pub_body: &pub_body,
                },
                &mut buf,
            )
            .unwrap();
            assert_eq!(
                buf[0], STREAM_WIRE_BODY_VERSION,
                "leads with the body version"
            );
            let decoded = decode_txn_prepare(&buf).unwrap();
            assert_eq!(decoded.txn_id, txn);
            assert_eq!(decoded.stream_id, stream);
            assert_eq!(decoded.pub_body, pub_body.as_slice());
            // The carried pub_body decodes through the UNCHANGED PubBody codec.
            let pb = decode_pub(decoded.pub_body).unwrap();
            assert_eq!(pb.payload, b"half-message");
        }
    }

    #[test]
    fn txn_resolve_round_trips_the_txn_id() {
        // #640: TxnCommit / TxnRollback share the TxnResolveBody shape, carrying just the txn id.
        for txn in [b"tx-1".as_slice(), b"a-very-distinct-uuid-1234"] {
            let mut buf = Vec::new();
            encode_txn_resolve(&TxnResolveBody { txn_id: txn }, &mut buf).unwrap();
            assert_eq!(buf[0], STREAM_WIRE_BODY_VERSION);
            assert_eq!(decode_txn_resolve(&buf).unwrap().txn_id, txn);
        }
    }

    #[test]
    fn txn_bodies_reject_malformed_and_oversized_input() {
        // An empty body is truncated (no version byte).
        assert_eq!(decode_txn_prepare(&[]), Err(BodyError::Truncated));
        assert_eq!(decode_txn_resolve(&[]), Err(BodyError::Truncated));
        // A wrong body version fails closed.
        let mut buf = Vec::new();
        encode_txn_resolve(&TxnResolveBody { txn_id: b"t" }, &mut buf).unwrap();
        buf[0] = STREAM_WIRE_BODY_VERSION + 1;
        assert!(matches!(
            decode_txn_resolve(&buf),
            Err(BodyError::BadHandshakeVersion { .. })
        ));
        // An over-cap txn id is rejected by the inner cap check (cap-before-alloc): the declared
        // inner length is over MAX_TXN_ID_LEN, so read_txn_id fails BadLength before taking the id
        // bytes. The outer block is fully supplied so the outer take succeeds first.
        let over = u16::try_from(MAX_TXN_ID_LEN + 1).unwrap();
        let mut bad = Vec::new();
        bad.push(STREAM_WIRE_BODY_VERSION);
        let field_len = 2u16 + over; // inner len field (2) + the declared id bytes
        bad.extend_from_slice(&field_len.to_le_bytes());
        bad.extend_from_slice(&over.to_le_bytes()); // declared txn_id len, over the cap
        bad.extend_from_slice(&vec![0u8; over as usize]); // fill the block so the outer take succeeds
        assert_eq!(decode_txn_resolve(&bad), Err(BodyError::BadLength));
    }

    #[test]
    fn txn_prepare_tolerates_a_future_appended_block_field() {
        // #640 forward-compat: a future version may append fields INSIDE the declared block; a v1 reader
        // takes the WHOLE declared block and reads only the v1 fields, leaving the PubBody tail intact.
        let mut buf = Vec::new();
        buf.push(STREAM_WIRE_BODY_VERSION);
        // block = txn_id("t") + stream_id("s") + a future trailing field, all inside field_len.
        let mut block = Vec::new();
        push_var(&mut block, b"t").unwrap();
        push_var(&mut block, b"s").unwrap();
        block.extend_from_slice(b"\xAA\xBB"); // a future field a v1 reader ignores
        buf.extend_from_slice(&u16::try_from(block.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&block);
        buf.extend_from_slice(b"PUBBODYTAIL"); // the verbatim pub_body after the block
        let decoded = decode_txn_prepare(&buf).unwrap();
        assert_eq!(decoded.txn_id, b"t");
        assert_eq!(decoded.stream_id, b"s");
        assert_eq!(decoded.pub_body, b"PUBBODYTAIL");
    }

    #[test]
    fn sub_to_round_trips_stream_id_and_group() {
        // #588: SubTo carries both a stream id and a work-group name, each round-tripping; empty
        // stream id (default stream) and empty group (default group) both round-trip.
        for (id, group) in [
            (b"orders".as_slice(), b"workers".as_slice()),
            (b"", b""),
            (b"s", b""),
            (b"", b"g"),
        ] {
            let mut buf = Vec::new();
            encode_sub_to(
                &SubToBody {
                    stream_id: id,
                    group,
                },
                &mut buf,
            )
            .unwrap();
            let decoded = decode_sub_to(&buf).unwrap();
            assert_eq!(decoded.stream_id, id);
            assert_eq!(decoded.group, group);
        }
    }

    #[test]
    fn stream_bodies_tolerate_a_future_appended_field() {
        // #588 forward-compat: a future version may append fields INSIDE the declared block; a v1
        // reader reads the known fields from the front and TOLERATES (ignores) the trailing bytes,
        // never erroring. Hand-craft a StreamDeclare body whose field_len is two bytes longer than the
        // v1 stream-id field and assert the id still decodes.
        let id = b"future";
        let mut buf = vec![STREAM_WIRE_BODY_VERSION];
        let v1_field_len = 2 + id.len();
        let field_len = u16::try_from(v1_field_len + 2).unwrap(); // two appended future bytes
        buf.extend_from_slice(&field_len.to_le_bytes());
        buf.extend_from_slice(&u16::try_from(id.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(id);
        buf.extend_from_slice(&[0xaa, 0xbb]); // a future version's appended block bytes
        assert_eq!(decode_stream_declare(&buf).unwrap().stream_id, id);
    }

    #[test]
    fn stream_bodies_fail_closed_on_malformed_input() {
        // #588 fail-closed: an empty body, an unknown version, a declared field_len past the body, and
        // an over-cap stream id are each a TYPED BodyError, never a panic or an over-read.
        // Empty body -> Truncated (no historical empty case for a new frame type).
        assert_eq!(decode_stream_declare(&[]), Err(BodyError::Truncated));
        assert_eq!(decode_pub_to(&[]), Err(BodyError::Truncated));
        assert_eq!(decode_sub_to(&[]), Err(BodyError::Truncated));
        // Unknown body version -> BadHandshakeVersion.
        assert_eq!(
            decode_stream_declare(&[STREAM_WIRE_BODY_VERSION + 1, 0, 0]),
            Err(BodyError::BadHandshakeVersion {
                version: STREAM_WIRE_BODY_VERSION + 1
            })
        );
        // A field_len that claims more than the body holds -> Truncated (cap-before-alloc).
        let mut over = vec![STREAM_WIRE_BODY_VERSION];
        over.extend_from_slice(&9999u16.to_le_bytes()); // declares 9999 block bytes, has none
        assert_eq!(decode_stream_declare(&over), Err(BodyError::Truncated));
        // An over-cap stream id length inside the block -> BadLength, never an over-read.
        let mut huge = vec![STREAM_WIRE_BODY_VERSION];
        let claimed_id_len = u16::try_from(MAX_STREAM_ID_LEN + 1).unwrap();
        let field_len = u16::try_from(2usize).unwrap(); // only room for the 2-byte len prefix
        huge.extend_from_slice(&field_len.to_le_bytes());
        huge.extend_from_slice(&claimed_id_len.to_le_bytes());
        assert_eq!(decode_stream_declare(&huge), Err(BodyError::BadLength));
    }

    // ---- #585 (M2-I9): subject-addressed bodies ----

    #[test]
    fn bind_subject_round_trips_stream_and_pattern() {
        // BindSubject carries both a stream id and a subject PATTERN, each round-tripping (wildcards
        // are part of the pattern bytes; the proto does not validate the grammar — the server does).
        for (stream, pattern) in [
            (&b"orders"[..], &b"order.>"[..]),
            (&b""[..], &b"payment.*.done"[..]), // empty stream binds the default stream
            (&b"metrics"[..], &b">"[..]),
        ] {
            let mut buf = Vec::new();
            encode_bind_subject(
                &BindSubjectBody {
                    stream_id: stream,
                    pattern,
                },
                &mut buf,
            )
            .unwrap();
            let decoded = decode_bind_subject(&buf).unwrap();
            assert_eq!(decoded.stream_id, stream);
            assert_eq!(decoded.pattern, pattern);
        }
    }

    #[test]
    fn pub_subject_round_trips_subject_and_verbatim_pub_body() {
        // PubSubject prefixes a literal subject, then carries the EXISTING PubBody bytes VERBATIM, so the
        // publish body codec is shared byte-for-byte with Pub/PubTo.
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 99,
                key: b"k",
                headers: b"h",
                payload: b"payload-bytes",
                dedup: None,
                fire_and_forget: false,
            },
            &mut pub_body,
        )
        .unwrap();
        let mut buf = Vec::new();
        encode_pub_subject(
            &PubSubjectBody {
                subject: b"order.us.created",
                pub_body: &pub_body,
            },
            &mut buf,
        )
        .unwrap();
        let decoded = decode_pub_subject(&buf).unwrap();
        assert_eq!(decoded.subject, b"order.us.created");
        // The verbatim tail decodes with the UNCHANGED decode_pub codec.
        assert_eq!(decoded.pub_body, pub_body.as_slice());
        let msg = decode_pub(decoded.pub_body).unwrap();
        assert_eq!(msg.payload, b"payload-bytes");
    }

    #[test]
    fn sub_subject_round_trips_subject_and_group() {
        for (subject, group) in [
            (&b"order.>"[..], &b"workers"[..]), // a wildcard subject is legal on the sub side
            (&b"metric.cpu"[..], &b""[..]),     // empty group selects the default group
        ] {
            let mut buf = Vec::new();
            encode_sub_subject(&SubSubjectBody { subject, group }, &mut buf).unwrap();
            let decoded = decode_sub_subject(&buf).unwrap();
            assert_eq!(decoded.subject, subject);
            assert_eq!(decoded.group, group);
        }
    }

    #[test]
    fn subject_bodies_fail_closed_on_malformed_input() {
        // Empty body -> Truncated; unknown version -> BadHandshakeVersion; over-cap subject -> BadLength.
        assert_eq!(decode_bind_subject(&[]), Err(BodyError::Truncated));
        assert_eq!(decode_pub_subject(&[]), Err(BodyError::Truncated));
        assert_eq!(decode_sub_subject(&[]), Err(BodyError::Truncated));
        assert_eq!(
            decode_pub_subject(&[STREAM_WIRE_BODY_VERSION + 1, 0, 0]),
            Err(BodyError::BadHandshakeVersion {
                version: STREAM_WIRE_BODY_VERSION + 1
            })
        );
        // An over-cap subject length inside the block -> BadLength, never an over-read.
        let mut huge = vec![STREAM_WIRE_BODY_VERSION];
        let claimed = u16::try_from(MAX_STREAM_ID_LEN + 1).unwrap();
        huge.extend_from_slice(&u16::try_from(2usize).unwrap().to_le_bytes());
        huge.extend_from_slice(&claimed.to_le_bytes());
        assert_eq!(decode_pub_subject(&huge), Err(BodyError::BadLength));
    }

    #[test]
    fn not_leader_round_trips_the_leader_hint() {
        for hint in ["127.0.0.1:9000", "[::1]:7000", ""] {
            let mut buf = Vec::new();
            encode_not_leader(&NotLeaderBody { leader_hint: hint }, &mut buf).unwrap();
            assert_eq!(
                buf[0], NOT_LEADER_BODY_VERSION,
                "version byte leads the body"
            );
            let decoded = decode_not_leader(&buf).unwrap();
            assert_eq!(decoded.leader_hint, hint);
        }
    }

    #[test]
    fn not_leader_tolerates_a_future_version_and_trailing_fields() {
        // A future version byte still carries the v1 address field first, and appended bytes past it are
        // tolerated (forward-compatible): an older client still routes a newer server's extended redirect.
        let mut buf = Vec::new();
        buf.push(NOT_LEADER_BODY_VERSION + 7);
        push_var(&mut buf, b"10.0.0.5:9000").unwrap();
        buf.extend_from_slice(b"FUTURE-APPENDED-FIELD"); // a v2 field an old reader ignores
        let decoded = decode_not_leader(&buf).unwrap();
        assert_eq!(decoded.leader_hint, "10.0.0.5:9000");
    }

    #[test]
    fn not_leader_fails_closed_on_malformed_input() {
        // Empty body -> Truncated (no version byte). A declared length past the body -> Truncated, never
        // an over-read. A non-UTF-8 hint -> Truncated (an address is always UTF-8).
        assert_eq!(decode_not_leader(&[]), Err(BodyError::Truncated));
        let mut short = vec![NOT_LEADER_BODY_VERSION];
        short.extend_from_slice(&5u16.to_le_bytes()); // claims 5 bytes, none follow
        assert_eq!(decode_not_leader(&short), Err(BodyError::Truncated));
        let mut bad_utf8 = vec![NOT_LEADER_BODY_VERSION];
        push_var(&mut bad_utf8, &[0xff, 0xfe]).unwrap();
        assert_eq!(decode_not_leader(&bad_utf8), Err(BodyError::Truncated));
    }
}
