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
    /// Server->producer confirmation that an ack-level-2 (server+client-ack) publish has reached its
    /// terminal produce outcome (#494, part of #499): the producer's confirmation completes only once
    /// a CONSUMER acked the record (or it timed out / was dead-lettered). It is the wire frame the
    /// Cassandra-style ack-level spectrum's Level 2 rides on; Level 0 (fire-and-forget, the existing
    /// [`crate::message::PUB_FLAG_FIRE_AND_FORGET`]) and Level 1 (the existing `PubAck`, tag 14) are
    /// unchanged and never use it. It is a NEW append-only tag, so an old producer that never requests
    /// Level 2 never receives it. Body: the record's durable `offset` as a little-endian `u64`
    /// (8 bytes) followed by a one-byte `status` (0 = consumed/confirmed, 1 = timed-out,
    /// 2 = dead-lettered). PROTO/CODEC ONLY in this phase: this frame is DEFINED here but NOTHING
    /// sends it yet (the server emit path is phase #497).
    ProduceConfirm,
    /// Consumer batch-pull FETCH request (#489): a NATS pull-consumer-style request that drains up to
    /// `max_records` / `max_bytes` of deliverable records in ONE round-trip, amortizing the per-poll
    /// actor hop and read cost across the whole batch. It is the BATCH twin of [`FrameType::Flow`]
    /// (tag 10): the server runs the SAME per-record poll the `Flow` path does (same lease/credit,
    /// at-least-once, broadcast/`key_shared`/competing semantics, never over-delivering past
    /// `max_in_flight`), so a batch fetch delivers EXACTLY the records N successive per-record polls
    /// would, just in one request. The RESPONSE reuses the existing delivery frames verbatim — a run
    /// of [`FrameType::Deliver`] (with any interleaved [`FrameType::DeadLetter`],
    /// [`FrameType::Truncated`], or [`FrameType::GapMarker`] advisories), terminated by exactly one
    /// [`FrameType::FlowEnd`] carrying the delivered count — so no new response frame is introduced.
    /// It is a NEW append-only request tag: an old client never sends it and the existing `Flow`
    /// wire (tag 10) is byte-for-byte unchanged. Body: a [`crate::message::FetchBody`]
    /// (`max_records: u32`, `max_bytes: u64`, `expires_ms: u64` relative deadline budget, and a
    /// `no_wait` flag), versioned and forward-compatible.
    Fetch,
    /// Consumer Tier-S STREAMING fetch request (the consumer-managed-offset consume mode, M1-I7 /
    /// #544): the consumer names its OWN `start_offset` and the broker serves a CONTIGUOUS batch of
    /// records `[start_offset, ...)` bounded by `max_records` / `max_bytes` — with NO lease grant, NO
    /// generation fence, and NO per-record cursor write. This is the Kafka / NATS-pull
    /// consumer-managed-offset contract: at-least-once holds BY CONSTRUCTION because a crash or
    /// reconnect simply re-reads from the consumer's last committed offset, so at most the uncommitted
    /// records redeliver. It is the STREAMING (Tier-S) twin of [`FrameType::Fetch`] (tag 23, the
    /// work-queue Tier-W batch pull): where `Fetch` runs the per-record lease/cursor poll, this serves
    /// a contiguous read off the durable prefix and leaves all offset bookkeeping to the consumer,
    /// which removes exactly the per-record lease + generation + cursor cost that makes single-consumer
    /// durable consume lose to NATS. The RESPONSE reuses the existing delivery frames verbatim — a run
    /// of [`FrameType::Deliver`] (with any interleaved [`FrameType::Truncated`] /
    /// [`FrameType::GapMarker`] advisory), terminated by exactly one [`FrameType::FlowEnd`] carrying
    /// the delivered count — so no new response frame is introduced. It is a NEW append-only request
    /// tag: an old client never sends it and the existing `Fetch` (tag 23) and `Flow` (tag 10) wires
    /// are byte-for-byte unchanged. Body: a [`crate::message::StreamFetchBody`] (`start_offset: u64`,
    /// `max_records: u32`, `max_bytes: u64`), versioned and forward-compatible.
    StreamFetch,
    /// Consumer Tier-S periodic CUMULATIVE COMMIT (the consumer-managed-offset durability point, M1-I7
    /// / #544): advances the streaming group's committed watermark up to an exclusive `up_to` offset,
    /// the consumer's PERIODIC "I have durably processed everything below `up_to`" checkpoint. It
    /// REUSES the same cumulative-ack cursor primitive (`AckCursor::commit_up_to` in `ironbus-core`)
    /// the broadcast [`FrameType::CumulativeAck`] (tag 19) rides on — no new durable structure is
    /// invented — but it targets a STREAMING group (where `CumulativeAck` targets a BROADCAST group),
    /// so the two never collide and `CumulativeAck`'s broadcast-only guard stays unchanged. Because
    /// tier-S grants no leases, this commit only advances the watermark (it frees retention and stops
    /// any redeliver below it); there is no per-record lease to reclaim. It is idempotent and monotonic
    /// (a re-commit at or below the watermark is a no-op success), exactly like `commit_up_to`. The
    /// SUCCESS response is a body-less [`FrameType::Ok`] (matching the `CumulativeAck` reply shape); an
    /// out-of-range or wrong-mode commit is an [`FrameType::Err`]. A NEW append-only request tag: an old
    /// client never sends it. Body: the exclusive `up_to` offset as a little-endian `u64` (8 bytes)
    /// followed by the work-group name as the remainder (empty selects the default group) — identical
    /// in shape to the [`crate::message::CumulativeAckBody`].
    StreamCommit,
    /// Server delivers a CONTIGUOUS run of records to a consumer as ONE batch frame (#541, M1-I5): the
    /// RAW-FRAMED batch delivery whose body carries the records' ON-DISK frame bytes VERBATIM, so a
    /// contiguous stored run ships in one frame without the broker re-encoding per record. It is the
    /// BATCH twin of [`FrameType::Deliver`] (tag 13): where `Deliver` carries ONE record re-encoded into
    /// the on-WIRE layout (offset / generation / u16 lengths), `DeliverBatch` carries N records as the
    /// concatenation of their on-DISK frames (seq / u32 lengths / header-CRC + body-CRC trailer) plus a
    /// small fixed header naming the run's `first_offset` and `generation`, so the CLIENT decodes the
    /// on-disk layout directly and reconstructs each record's offset POSITIONALLY (`first_offset + i`,
    /// the run being dense and contiguous). Because the body IS the stored bytes, a later disk
    /// `sendfile(2)`/`splice(2)` path (#658) can splice the segment's page-cache bytes straight into the
    /// socket after the fixed header — this frame is that path's HARD prerequisite. Each record's own
    /// CRC32C (header and body) ships inside the body, so the consumer verifies every record end-to-end
    /// exactly as it does a per-record `Deliver`; integrity is never silently dropped.
    ///
    /// It is OPT-IN and ADDITIVE: the server sends it ONLY to a consumer that advertised it understands
    /// the frame (the [`crate::message::CONNECT_FLAG_UNDERSTANDS_DELIVER_BATCH`] capability bit, confirmed
    /// by [`crate::message::INFO_FLAG_DELIVER_BATCH`]). An old client that did not advertise it keeps
    /// receiving the per-record `Deliver` run, byte-for-byte unchanged, and never sees this NEW
    /// append-only tag. Used today on the Tier-S `StreamFetch` delivery path (the contiguous
    /// consumer-managed-offset batch from #544); the response is terminated by exactly one
    /// [`FrameType::FlowEnd`] carrying the delivered count, exactly as the per-record path. Body: a
    /// [`crate::message::DeliverBatchHeader`] (`body_version: u8`, `field_len: u16`, then `first_offset:
    /// u64 LE`, `generation: u64 LE`, `record_count: u32 LE`), then the contiguous on-disk record-frame
    /// bytes as the remainder.
    DeliverBatch,
    /// CLUSTER PEER raft message (V2-C1 peer transport, #667): carries one serialized
    /// `raft::eraftpb::Message` between metadata-Raft cluster nodes over the SEPARATE peer link
    /// (never the client port). Body: the protobuf-2 wire encoding of the `eraftpb::Message`,
    /// length-prefixed by this envelope. The body is UNTRUSTED peer input — the cluster transport
    /// decodes it under a hard size cap (this envelope's length prefix) AND a tight protobuf
    /// recursion-depth bound, fail-closed, so a hostile peer cannot OOM or stack-overflow the node
    /// (the bound that makes RUSTSEC-2024-0437 unreachable). It is a NEW append-only tag carried only
    /// on the peer link, so the client protocol (tags 1-26) is byte-for-byte unchanged and a client
    /// connection never sees it.
    Raft,
    /// Client request to CREATE-OR-ENSURE a named stream (#588, V2-M2-I10): the explicit-stream-id
    /// "declare" verb that makes a named stream CLIENT-reachable. The broker `declare`s the stream in
    /// its [`ironbus_storage::streamset::StreamSet`] (materializing its independent log + recovery) and
    /// replies a body-less [`FrameType::Ok`] on success or [`FrameType::Err`] on a malformed/over-long
    /// stream name (fail-closed, never a panic). It is idempotent: re-declaring an existing stream is a
    /// no-op success. The DEFAULT stream (the empty name `""`) is ALWAYS present and is NOT declared
    /// this way; a declare of `""` is rejected as a malformed name. Body: a
    /// [`crate::message::StreamDeclareBody`] (`body_version: u8`, `field_len: u16`, then the
    /// `stream_id` as a u16-length-prefixed name). It is a NEW append-only request tag: an old client
    /// never sends it, and the existing tags 1-27 are byte-for-byte unchanged. (See the module doc on
    /// tag allocation: tags 22-27 were ALREADY taken before this PR, so the streams verbs start at 28,
    /// NOT the "tags 22+" the originating issue text predates.)
    StreamDeclare,
    /// Client query for a named stream's existence and durable head (#588, V2-M2-I10): the
    /// explicit-stream-id "info" verb. The broker replies a [`FrameType::StreamInfo`] response frame
    /// (reusing this same tag) carrying whether the stream EXISTS and, if so, its durable head offset,
    /// or [`FrameType::Err`] on a malformed name. A request and its response share this tag, framed and
    /// distinguished by their bodies (request = [`crate::message::StreamInfoBody`]; response =
    /// [`crate::message::StreamInfoResponseBody`]), exactly as `Connect`/`Info` pair across two tags —
    /// here a single verb round-trips request/response. The default stream `""` always reports
    /// `exists = true`. A NEW append-only tag; old clients never send it. Body (request): a
    /// `StreamInfoBody` (`stream_id` as a u16-length name); body (response): a
    /// `StreamInfoResponseBody` (`exists: u8`, `head: u64 LE`).
    StreamInfo,
    /// Producer publish to a NAMED stream (#588, V2-M2-I10): the stream-addressed twin of
    /// [`FrameType::Pub`] (tag 5). It carries an explicit target `stream_id` followed by a body that is
    /// BYTE-FOR-BYTE the existing [`crate::message::PubBody`] layout (the same `flags` / timestamp /
    /// key / headers / opt-in dedup / payload, including the ack-level and fire-and-forget wire bits),
    /// so the only difference from a plain `Pub` is the stream-id prefix. The broker routes the append
    /// to the named stream's own log via the engine's id-routed `produce_in_stream` (#676/#679), which
    /// `declare`s the stream on first produce; the reply is the SAME [`FrameType::PubAck`] (or
    /// [`FrameType::PubAckDuplicate`]/[`FrameType::Err`]) the default-stream `Pub` returns. A publish to
    /// the EMPTY stream id is exactly a default-stream publish (it routes through `produce_in_stream("",
    /// ...)`, byte-for-byte today's behavior). The existing `Pub` (tag 5) wire is UNCHANGED: this is an
    /// ADDITIVE tag an old client never sends. Body: a [`crate::message::PubToBody`] (`body_version:
    /// u8`, `field_len: u16` over the `stream_id` u16-length name, then the verbatim `PubBody` bytes as
    /// the remainder).
    PubTo,
    /// Consumer subscribe to a NAMED stream's per-stream work-group (#588, V2-M2-I10): the
    /// stream-addressed twin of [`FrameType::Sub`] (tag 6). It carries an explicit `stream_id` plus the
    /// work-`group` name, binding this connection's subsequent stream-scoped `Flow`/`Ack` to that
    /// stream's OWN competing work-group (independent per stream via the engine's id-routed
    /// `poll_in_stream`/`ack_in_stream`, #676/#679 — the same group name in two streams is two
    /// unrelated cursors). The reply is a body-less [`FrameType::Ok`] (the stream must already exist;
    /// an unknown stream is an [`FrameType::Err`]). A subscribe to the EMPTY stream id targets the
    /// default stream and is equivalent to a plain `Sub`. The existing `Sub` (tag 6) wire is UNCHANGED:
    /// this is an ADDITIVE tag an old client never sends. Body: a [`crate::message::SubToBody`]
    /// (`body_version: u8`, `field_len: u16` over `stream_id` then `group`, each u16-length-prefixed).
    SubTo,
    /// Cluster follower → leader replication fetch request (#590, V2-C2-I1): a follower asks the
    /// leader for the contiguous CRC-framed segment byte range of one partition log starting at
    /// `from_offset`, up to a bounded record/byte budget. This is the Kafka-ISR PULL model: the
    /// follower drives replication on its own cadence, the leader never pushes. It rides the SAME
    /// `[len][type][body]` envelope as every other frame and is an ADDITIVE, peer-only tag a client
    /// never sends. Body: a fixed little-endian header (see
    /// [`crate::cluster::replication`] in `ironbus-server`, the only encoder/decoder of these
    /// bodies) — `from_offset: u64`, `max_records: u32`, `max_bytes: u32`.
    FetchRecords,
    /// Cluster leader → follower replication fetch response (#590, V2-C2-I1): the leader's reply to a
    /// [`FrameType::FetchRecords`]. It carries the leader's current high-watermark (its flushed /
    /// committed offset) and a contiguous run of CRC-framed on-disk record frames (a zero-copy
    /// `RawByteRun`, #657) starting at the requested `from_offset`. The follower RE-VALIDATES every
    /// frame's CRC with the existing intact-record predicate before appending any of it (fail-closed:
    /// a corrupt / tampered frame is detected and NOT appended). Body: a fixed little-endian header —
    /// `high_watermark: u64`, `first_offset: u64`, `record_count: u32`, `frame_bytes_len: u32` — then
    /// the verbatim CRC-framed record bytes.
    FetchResponse,
    /// Client request to BIND a subject PATTERN to a stream (#585, V2-M2-I9): the subject-routing
    /// "bind" verb that completes the subjects story. The broker registers `(pattern -> stream)` in its
    /// wait-free routing trie (rebuilding it and advancing the routing generation, which invalidates
    /// every connection's resolve cache) and `declare`s the target stream, replying a body-less
    /// [`FrameType::Ok`] on success or [`FrameType::Err`] on a malformed pattern / stream name or a
    /// fork-bound rejection (fail-closed, never a panic). Idempotent: re-binding the same
    /// `(pattern, stream)` pair is a no-op success. The `pattern` is a #567 PATTERN (wildcards `*`/`>`
    /// allowed); the `stream` is the bound stream (the empty name binds the DEFAULT stream). It is a NEW
    /// append-only request tag: an old client never sends it, and tags 1-33 are byte-for-byte unchanged.
    /// Body: a [`crate::message::BindSubjectBody`] (`body_version: u8`, `field_len: u16`, then
    /// `stream_id` and `pattern`, each u16-length-prefixed).
    BindSubject,
    /// Producer publish BY SUBJECT (#585, V2-M2-I9): the subject-ADDRESSED twin of [`FrameType::PubTo`]
    /// (tag 30). It carries a literal `subject` followed by the verbatim [`crate::message::PubBody`]
    /// bytes (so the publish body codec is shared UNCHANGED with `Pub`/`PubTo`). The broker resolves the
    /// subject through the binding trie under the FAIL-CLOSED single-home default — EXACTLY ONE bound
    /// stream routes the append there (via the id-routed `produce_in_stream`), ZERO is an
    /// `ERR_NO_STREAM_FOR_SUBJECT` reject (the explicit beat over NATS's silent drop), two-or-more is an
    /// `ERR_AMBIGUOUS_SUBJECT` reject — and replies the SAME [`FrameType::PubAck`] (or [`FrameType::Err`])
    /// a `PubTo` returns. Resolution rides the connection's generation-guarded resolve cache, so
    /// steady-state routing is O(1). It is a NEW append-only tag an old client never sends; the existing
    /// `Pub` (tag 5) / `PubTo` (tag 30) wires are unchanged. Body: a [`crate::message::PubSubjectBody`]
    /// (`body_version: u8`, `field_len: u16` over the `subject` u16-length name, then the verbatim
    /// `PubBody` bytes as the remainder).
    PubSubject,
    /// Consumer subscribe BY SUBJECT (#585, V2-M2-I9): the subject-ADDRESSED twin of [`FrameType::SubTo`]
    /// (tag 31). It carries a `subject` (literal or WILDCARD pattern) plus the work-`group` name. The
    /// broker resolves the subject through the binding trie: a LITERAL subject resolves single-home to
    /// ONE bound stream and binds this connection's subsequent `Flow`/`Ack` to that stream's own
    /// competing work-group (via the id-routed `poll_in_stream`/`ack_in_stream`); an unbound subject is
    /// an `ERR_NO_STREAM_FOR_SUBJECT` reject and an ambiguous one an `ERR_AMBIGUOUS_SUBJECT` reject
    /// (single-home — fanning a wildcard sub over multiple streams is the flagged follow-up). The reply
    /// is a body-less [`FrameType::Ok`] on a resolved bind, else [`FrameType::Err`]. It is a NEW
    /// append-only tag an old client never sends; the existing `Sub` (tag 6) / `SubTo` (tag 31) wires
    /// are unchanged. Body: a [`crate::message::SubSubjectBody`] (`body_version: u8`, `field_len: u16`
    /// over `subject` then `group`, each u16-length-prefixed).
    SubSubject,
    /// Cluster follower → leader durably-replicated-offset REPORT (#593, V2-C2-I2): a follower tells
    /// the leader "I have `fdatasync`'d every record up to (but not including) `fsynced_offset`". This
    /// is the load-bearing distinction of the IronBus durability win: the follower reports its
    /// FSYNC'd (durably-replicated) offset, NOT merely what it has received, so the leader can compute
    /// a QUORUM-FSYNC commit offset and release a `C2-fsync` `PubAck` only once `min_isr` replicas
    /// have `fdatasync`'d the record (an R-ack = fsync'd-on-a-quorum BY CONSTRUCTION). It rides the
    /// SAME `[len][type][body]` envelope and is an ADDITIVE, peer-only tag a client never sends; it
    /// piggybacks on (or stands alone from) the [`FrameType::FetchRecords`] pull. Body: a fixed
    /// little-endian header (see [`crate::cluster::isr`] in `ironbus-server`, the only
    /// encoder/decoder of this body) — `follower_id: u64`, `fsynced_offset: u64`. Tags 1-36 are
    /// byte-for-byte unchanged.
    AckReplicated,
    /// Cluster follower ⇄ leader LEADER-EPOCH offset query (#599, V2-C2-I4, KIP-101): the
    /// divergence-truncation handshake that makes replication SAFE under a leader change. A follower
    /// that may have replicated from an OLD leader sends, per its highest leader epoch, "what is the
    /// last offset YOU hold for leadership epoch `E`?"; the leader answers its end-offset for that
    /// epoch (the start of its next epoch, or its log end if `E` is current, or the bound of the
    /// next-higher epoch it holds when it never saw `E`). The follower walks its epoch cache down
    /// until the leader SHARES an epoch, takes the divergence point = `min(its end, the leader's
    /// end)`, TRUNCATES its divergent suffix to exactly there ([`crate::cluster::replication`] in
    /// `ironbus-server`, the only encoder/decoder of these bodies), then resumes fetching — keeping
    /// the longest common prefix, dropping only the genuinely-divergent suffix. It rides the SAME
    /// `[len][type][body]` envelope and is an ADDITIVE, peer-only tag a client never sends. Request
    /// and response share this tag (like `StreamInfo`), distinguished by a leading `kind` byte. Body
    /// (request): `kind: u8 = 0`, `epoch: u64`. Body (response): `kind: u8 = 1`, `requested_epoch:
    /// u64`, `answered_epoch: u64`, `end_offset: u64`. Tags 1-37 are byte-for-byte unchanged.
    OffsetForLeaderEpoch,
    /// Cluster replica → peer SEGMENT-FINGERPRINT advertisement (#611, V2-C4-I1): the cross-replica
    /// divergence-DETECTION wire. A replica advertises, per SEALED segment, the cheap fingerprint
    /// `(segment_id, record_count, last_seq, footer_CRC, content_hash)` plus its committed
    /// high-watermark, so a peer can DETECT divergence/corruption in O(segments) WITHOUT shipping any
    /// record bytes — the signal NATS computes but never acts on (`errFirstSequenceMismatch`,
    /// nats-server #5576). On a mismatch the divergent replica truncates + re-fetches the clean bytes
    /// from the quorum (#612) or quarantines a corrupt minority segment and re-syncs (#613); a minority
    /// fault can never delete data or lose quorum (the beat over nats-server #7556). It rides the SAME
    /// `[len][type][body]` envelope and is an ADDITIVE, peer-only tag a client never sends. Body: a
    /// fixed little-endian header (`committed_hw: u64`, `count: u32`) followed by `count` fixed-layout
    /// fingerprints (see [`crate::cluster::divergence`] in `ironbus-server`, the only encoder/decoder of
    /// this body); the `count` is bounded before any allocation. Tags 1-38 are byte-for-byte unchanged.
    SegmentFingerprints,
    /// CROSS-CLUSTER mirror/source PULL request ⇄ response (#623, V2-C7-I1): the ASYNC geo-replication
    /// wire — the cross-cluster twin of the intra-cluster [`FrameType::FetchRecords`] /
    /// [`FrameType::FetchResponse`] pair (tags 32/33). A local MIRROR (read-only, single-origin) or a
    /// SOURCE (fan-in, N origins) opens a link to a REMOTE origin cluster and PULLS the CRC-framed
    /// records of ONE named origin stream from a durable resume cursor; the origin serves a contiguous
    /// run of its own on-disk record bytes VERBATIM (zero-copy, off its read plane), and the puller
    /// RE-VALIDATES every frame's CRC ([`crate::cluster`]'s `codec::decode`) before applying it locally
    /// in order — fail-closed, never a blind-trusted byte. It is ASYNC + eventually-consistent (no
    /// quorum, no ISR; the mirror lags the origin and catches up) and is carried on a SEPARATE
    /// cross-cluster link, never the intra-cluster partition data plane. Unlike `FetchRecords`/
    /// `FetchResponse` it names the origin STREAM (cross-cluster origins are named, not partition-ids),
    /// so request and response SHARE this one tag (distinguished by a leading `kind` byte, like
    /// [`FrameType::StreamInfo`] / [`FrameType::OffsetForLeaderEpoch`]). Body (request): `kind: u8 = 0`,
    /// `from_offset: u64`, `max_records: u32`, `max_bytes: u32`, then the origin `stream` as a
    /// u16-length-prefixed name. Body (response): `kind: u8 = 1`, `origin_high_watermark: u64`,
    /// `first_offset: u64`, `record_count: u32`, `frame_bytes_len: u32`, then the verbatim CRC-framed
    /// record bytes (bounded before allocation by the geo layer, the only encoder/decoder of this body
    /// — see `crate::cluster::geo` in `ironbus-server`). It is a NEW append-only tag a CLIENT never
    /// sends and an intra-cluster peer never sends; tags 1-39 are byte-for-byte unchanged.
    MirrorPull,
    /// The EDGE LEAF-SPOKE write-through PUSH frame (#625, V2-C7-I3, wire tag 41). The asymmetric twin
    /// of [`FrameType::MirrorPull`]: where a leaf MIRRORS a hub stream by PULLING (tag 40, the read-side
    /// bridge), a leaf FORWARDS its locally-produced records UP to the hub by PUSHING this frame on the
    /// SAME outbound link the leaf dialed (the hub never dials the leaf — leaves sit behind NAT). The
    /// leaf is NOT a Raft voter; this is an async, resumable, de-duplicated forward, not a quorum write.
    /// Request and response SHARE this one tag (distinguished by a leading `kind` byte, like
    /// [`FrameType::MirrorPull`]). Body (request): `kind: u8 = 0`, `from_leaf_offset: u64` (the leaf's
    /// own local offset the run starts at — the leaf's durable push cursor), `record_count: u32`,
    /// `frame_bytes_len: u32`, then the hub stream name as a u16-length-prefixed name, then the verbatim
    /// CRC-framed local record bytes (the hub RE-VALIDATES every frame before appending — fail-closed,
    /// never a blind-trusted byte). Body (response): `kind: u8 = 1`, `accepted_through_leaf_offset: u64`
    /// (the leaf offset the hub durably appended through; the leaf advances its push cursor to it). It is
    /// a NEW append-only tag a CLIENT never sends and an intra-cluster peer never sends; tags 1-40 are
    /// byte-for-byte unchanged. The geo leaf layer (`crate::cluster::leaf` in `ironbus-server`) is its
    /// only encoder/decoder.
    LeafPush,
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
            FrameType::ProduceConfirm => 22,
            FrameType::Fetch => 23,
            FrameType::StreamFetch => 24,
            FrameType::StreamCommit => 25,
            FrameType::DeliverBatch => 26,
            FrameType::Raft => 27,
            FrameType::StreamDeclare => 28,
            FrameType::StreamInfo => 29,
            FrameType::PubTo => 30,
            FrameType::SubTo => 31,
            FrameType::FetchRecords => 32,
            FrameType::FetchResponse => 33,
            FrameType::BindSubject => 34,
            FrameType::PubSubject => 35,
            FrameType::SubSubject => 36,
            FrameType::AckReplicated => 37,
            FrameType::OffsetForLeaderEpoch => 38,
            FrameType::SegmentFingerprints => 39,
            FrameType::MirrorPull => 40,
            FrameType::LeafPush => 41,
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
            22 => FrameType::ProduceConfirm,
            23 => FrameType::Fetch,
            24 => FrameType::StreamFetch,
            25 => FrameType::StreamCommit,
            26 => FrameType::DeliverBatch,
            27 => FrameType::Raft,
            28 => FrameType::StreamDeclare,
            29 => FrameType::StreamInfo,
            30 => FrameType::PubTo,
            31 => FrameType::SubTo,
            32 => FrameType::FetchRecords,
            33 => FrameType::FetchResponse,
            34 => FrameType::BindSubject,
            35 => FrameType::PubSubject,
            36 => FrameType::SubSubject,
            37 => FrameType::AckReplicated,
            38 => FrameType::OffsetForLeaderEpoch,
            39 => FrameType::SegmentFingerprints,
            40 => FrameType::MirrorPull,
            41 => FrameType::LeafPush,
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

    const ALL_TYPES: [FrameType; 41] = [
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
        FrameType::ProduceConfirm,
        FrameType::Fetch,
        FrameType::StreamFetch,
        FrameType::StreamCommit,
        FrameType::DeliverBatch,
        FrameType::Raft,
        FrameType::StreamDeclare,
        FrameType::StreamInfo,
        FrameType::PubTo,
        FrameType::SubTo,
        FrameType::FetchRecords,
        FrameType::FetchResponse,
        FrameType::BindSubject,
        FrameType::PubSubject,
        FrameType::SubSubject,
        FrameType::AckReplicated,
        FrameType::OffsetForLeaderEpoch,
        FrameType::SegmentFingerprints,
        FrameType::MirrorPull,
        FrameType::LeafPush,
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
        assert_eq!(FrameType::ProduceConfirm.as_u8(), 22);
        assert_eq!(FrameType::Fetch.as_u8(), 23);
        assert_eq!(FrameType::StreamFetch.as_u8(), 24);
        assert_eq!(FrameType::StreamCommit.as_u8(), 25);
        assert_eq!(FrameType::DeliverBatch.as_u8(), 26);
        assert_eq!(FrameType::Raft.as_u8(), 27);
        assert_eq!(FrameType::StreamDeclare.as_u8(), 28);
        assert_eq!(FrameType::StreamInfo.as_u8(), 29);
        assert_eq!(FrameType::PubTo.as_u8(), 30);
        assert_eq!(FrameType::SubTo.as_u8(), 31);
        assert_eq!(FrameType::FetchRecords.as_u8(), 32);
        assert_eq!(FrameType::FetchResponse.as_u8(), 33);
        assert_eq!(FrameType::BindSubject.as_u8(), 34);
        assert_eq!(FrameType::PubSubject.as_u8(), 35);
        assert_eq!(FrameType::SubSubject.as_u8(), 36);
        assert_eq!(FrameType::AckReplicated.as_u8(), 37);
        assert_eq!(FrameType::OffsetForLeaderEpoch.as_u8(), 38);
        assert_eq!(FrameType::SegmentFingerprints.as_u8(), 39);
        assert_eq!(FrameType::MirrorPull.as_u8(), 40);
        assert_eq!(FrameType::LeafPush.as_u8(), 41);
    }

    #[test]
    fn subject_routing_tags_are_the_next_free_tags_after_subto() {
        // #585 (M2-I9): the subject-addressed verbs BindSubject (34), PubSubject (35), and SubSubject
        // (36) take the next FREE tags after the cluster replication-fetch verbs FetchRecords (32) /
        // FetchResponse (33) (#590, V2-C2-I1), which a concurrent merge slotted into 32/33 (the tags
        // after the explicit-stream-id SubTo, 31) ahead of these — so the subject verbs SHIFTED up by
        // two to avoid the collision. Pinned here so a future reorder breaks a test, not a deployed
        // protocol. They are ADDITIVE: tags 1-33 are unchanged.
        assert_eq!(FrameType::from_u8(34), Some(FrameType::BindSubject));
        assert_eq!(FrameType::from_u8(35), Some(FrameType::PubSubject));
        assert_eq!(FrameType::from_u8(36), Some(FrameType::SubSubject));
        // 37 is the cluster AckReplicated report (#593, V2-C2-I2), the next free tag after the subject
        // verbs; 38 is the cluster OffsetForLeaderEpoch divergence-query (#599, V2-C2-I4); 39 is the
        // cluster SegmentFingerprints divergence-advertisement (#611, V2-C4-I1); 40 is the
        // cross-cluster MirrorPull (#623, V2-C7-I1); 41 is the edge leaf-spoke LeafPush write-through
        // (#625, V2-C7-I3); 42 is now the next-free (still unknown) tag, so it frames but is not known.
        assert_eq!(FrameType::from_u8(37), Some(FrameType::AckReplicated));
        assert_eq!(
            FrameType::from_u8(38),
            Some(FrameType::OffsetForLeaderEpoch)
        );
        assert_eq!(FrameType::from_u8(39), Some(FrameType::SegmentFingerprints));
        assert_eq!(FrameType::from_u8(40), Some(FrameType::MirrorPull));
        assert_eq!(FrameType::from_u8(41), Some(FrameType::LeafPush));
        assert_eq!(FrameType::from_u8(42), None);
        for ty in [
            FrameType::BindSubject,
            FrameType::PubSubject,
            FrameType::SubSubject,
        ] {
            let mut buf = Vec::new();
            encode_frame(ty, b"\x0b\x0c", &mut buf).unwrap();
            match decode_frame(&buf).unwrap() {
                FrameDecode::Frame { type_tag, body, .. } => {
                    assert_eq!(FrameType::from_u8(type_tag), Some(ty));
                    assert_eq!(body, b"\x0b\x0c");
                }
                FrameDecode::Incomplete { .. } => panic!("complete"),
            }
        }
    }

    #[test]
    fn stream_wire_tags_are_the_next_free_tags_after_raft_and_frame() {
        // #588 (M2-I10): the stream-addressed verbs StreamDeclare (28), StreamInfo (29), PubTo (30),
        // and SubTo (31) take the next FREE tags after the cluster-peer Raft frame (27). The
        // originating issue text said "tags 22+", but tags 22-27 (ProduceConfirm, Fetch, StreamFetch,
        // StreamCommit, DeliverBatch, Raft) were ALL allocated before this PR, so the streams verbs
        // start at 28 — pinned here so a future reorder breaks a test, not a deployed protocol. The
        // existing client verbs (Pub tag 5, Sub tag 6) are byte-for-byte unchanged: these are ADDITIVE
        // tags an old client never sends.
        assert_eq!(FrameType::from_u8(28), Some(FrameType::StreamDeclare));
        assert_eq!(FrameType::from_u8(29), Some(FrameType::StreamInfo));
        assert_eq!(FrameType::from_u8(30), Some(FrameType::PubTo));
        assert_eq!(FrameType::from_u8(31), Some(FrameType::SubTo));
        // The default-stream verbs are untouched.
        assert_eq!(FrameType::Pub.as_u8(), 5);
        assert_eq!(FrameType::Sub.as_u8(), 6);
        // 32/33 are the cluster replication-fetch tags (#590, V2-C2-I1), the next free tags after
        // SubTo (31); 34-36 are the subject-routing verbs (#585); 37 is the next-free (still unknown)
        // tag, so it frames but is not a known type.
        assert_eq!(FrameType::from_u8(32), Some(FrameType::FetchRecords));
        assert_eq!(FrameType::from_u8(33), Some(FrameType::FetchResponse));
        assert_eq!(FrameType::from_u8(34), Some(FrameType::BindSubject));
        // 37 is the cluster AckReplicated report (#593); 38 is the cluster OffsetForLeaderEpoch
        // divergence-query (#599); 39 is the cluster SegmentFingerprints divergence-advertisement
        // (#611); 40 is the cross-cluster MirrorPull (#623); 41 is the edge leaf-spoke LeafPush (#625);
        // 42 is the next-free (still unknown) tag.
        assert_eq!(FrameType::from_u8(37), Some(FrameType::AckReplicated));
        assert_eq!(
            FrameType::from_u8(38),
            Some(FrameType::OffsetForLeaderEpoch)
        );
        assert_eq!(FrameType::from_u8(39), Some(FrameType::SegmentFingerprints));
        assert_eq!(FrameType::from_u8(40), Some(FrameType::MirrorPull));
        assert_eq!(FrameType::from_u8(41), Some(FrameType::LeafPush));
        assert_eq!(FrameType::from_u8(42), None);
        for ty in [
            FrameType::StreamDeclare,
            FrameType::StreamInfo,
            FrameType::PubTo,
            FrameType::SubTo,
            FrameType::FetchRecords,
            FrameType::FetchResponse,
        ] {
            let mut buf = Vec::new();
            encode_frame(ty, b"\x0b\x0c", &mut buf).unwrap();
            match decode_frame(&buf).unwrap() {
                FrameDecode::Frame { type_tag, body, .. } => {
                    assert_eq!(FrameType::from_u8(type_tag), Some(ty));
                    assert_eq!(body, b"\x0b\x0c");
                }
                FrameDecode::Incomplete { .. } => panic!("complete"),
            }
        }
    }

    #[test]
    fn produce_confirm_is_a_frozen_tag_and_frames() {
        // #494: ProduceConfirm holds tag 22 (the FREE tag after GapMarker, 21); pinned here so a
        // future reorder breaks a test, not the wire, and confirmed to frame at the envelope level.
        assert_eq!(FrameType::ProduceConfirm.as_u8(), 22);
        assert_eq!(FrameType::from_u8(22), Some(FrameType::ProduceConfirm));
        let mut buf = Vec::new();
        encode_frame(FrameType::ProduceConfirm, b"\x01\x02", &mut buf).unwrap();
        match decode_frame(&buf).unwrap() {
            FrameDecode::Frame { type_tag, body, .. } => {
                assert_eq!(
                    FrameType::from_u8(type_tag),
                    Some(FrameType::ProduceConfirm)
                );
                assert_eq!(body, b"\x01\x02");
            }
            FrameDecode::Incomplete { .. } => panic!("complete"),
        }
    }

    #[test]
    fn fetch_is_the_next_free_tag_and_frames() {
        // #489: Fetch takes tag 23, the next FREE tag after ProduceConfirm (22). It was previously an
        // UNKNOWN tag, so this pins it as a known type now and confirms it frames at the envelope level
        // like any other. The existing Flow wire (tag 10) is unchanged: this is an ADDITIVE request tag.
        assert_eq!(FrameType::Fetch.as_u8(), 23);
        assert_eq!(FrameType::from_u8(23), Some(FrameType::Fetch));
        // The existing Flow tag is untouched (the batch fetch is additive, not a replacement).
        assert_eq!(FrameType::Flow.as_u8(), 10);
        let mut buf = Vec::new();
        encode_frame(FrameType::Fetch, b"\x03\x04", &mut buf).unwrap();
        match decode_frame(&buf).unwrap() {
            FrameDecode::Frame { type_tag, body, .. } => {
                assert_eq!(FrameType::from_u8(type_tag), Some(FrameType::Fetch));
                assert_eq!(body, b"\x03\x04");
            }
            FrameDecode::Incomplete { .. } => panic!("complete"),
        }
    }

    #[test]
    fn stream_tier_tags_are_the_next_free_tags_and_frame() {
        // #544 (M1-I7): StreamFetch (24) and StreamCommit (25) take the next FREE tags after Fetch
        // (23). They were previously UNKNOWN tags; pin them as known now and confirm they frame at the
        // envelope level. The existing Flow (10) and Fetch (23) wires are byte-for-byte unchanged: the
        // Tier-S streaming mode is ADDITIVE, not a replacement of the Tier-W work-queue verbs.
        assert_eq!(FrameType::StreamFetch.as_u8(), 24);
        assert_eq!(FrameType::StreamCommit.as_u8(), 25);
        assert_eq!(FrameType::from_u8(24), Some(FrameType::StreamFetch));
        assert_eq!(FrameType::from_u8(25), Some(FrameType::StreamCommit));
        // The Tier-W verbs are untouched.
        assert_eq!(FrameType::Flow.as_u8(), 10);
        assert_eq!(FrameType::Fetch.as_u8(), 23);
        // 37 is the cluster AckReplicated report (#593, V2-C2-I2); 38 is the cluster
        // OffsetForLeaderEpoch divergence-query (#599, V2-C2-I4); 39 is the cluster SegmentFingerprints
        // divergence-advertisement (#611, V2-C4-I1); 40 is the cross-cluster MirrorPull (#623,
        // V2-C7-I1); 41 is the edge leaf-spoke LeafPush write-through (#625, V2-C7-I3); 42 is now the
        // next-free (still unknown) tag, so it frames but is not a known type. (Tags 27 = cluster-peer
        // Raft #667; 28-31 = the stream-addressed verbs #588; 32-33 = the cluster replication-fetch
        // verbs #590; 34-36 = the subject-routing verbs #585.)
        assert_eq!(FrameType::from_u8(37), Some(FrameType::AckReplicated));
        assert_eq!(
            FrameType::from_u8(38),
            Some(FrameType::OffsetForLeaderEpoch)
        );
        assert_eq!(FrameType::from_u8(39), Some(FrameType::SegmentFingerprints));
        assert_eq!(FrameType::from_u8(40), Some(FrameType::MirrorPull));
        assert_eq!(FrameType::from_u8(41), Some(FrameType::LeafPush));
        assert_eq!(FrameType::from_u8(42), None);
        for ty in [FrameType::StreamFetch, FrameType::StreamCommit] {
            let mut buf = Vec::new();
            encode_frame(ty, b"\x07\x08", &mut buf).unwrap();
            match decode_frame(&buf).unwrap() {
                FrameDecode::Frame { type_tag, body, .. } => {
                    assert_eq!(FrameType::from_u8(type_tag), Some(ty));
                    assert_eq!(body, b"\x07\x08");
                }
                FrameDecode::Incomplete { .. } => panic!("complete"),
            }
        }
    }

    #[test]
    fn deliver_batch_is_the_next_free_tag_and_frames() {
        // #541 (M1-I5): DeliverBatch takes tag 26, the next FREE tag after StreamCommit (25). It was
        // previously an UNKNOWN tag; pin it as a known type now and confirm it frames at the envelope
        // level. The per-record Deliver wire (tag 13) is byte-for-byte unchanged: the batch frame is
        // ADDITIVE and opt-in, never a replacement of the per-record delivery path.
        assert_eq!(FrameType::DeliverBatch.as_u8(), 26);
        assert_eq!(FrameType::from_u8(26), Some(FrameType::DeliverBatch));
        // The per-record Deliver tag is untouched.
        assert_eq!(FrameType::Deliver.as_u8(), 13);
        // 37 is the cluster AckReplicated report (#593, V2-C2-I2); 38 is the cluster
        // OffsetForLeaderEpoch divergence-query (#599, V2-C2-I4); 39 is the cluster SegmentFingerprints
        // divergence-advertisement (#611, V2-C4-I1); 40 is the cross-cluster MirrorPull (#623,
        // V2-C7-I1); 41 is the edge leaf-spoke LeafPush write-through (#625, V2-C7-I3); 42 is now the
        // next-free (still unknown) tag, so it frames but is not a known type. (Tags 27 = cluster-peer
        // Raft #667; 28-31 = the stream-addressed verbs #588; 32-33 = the cluster replication-fetch
        // verbs #590; 34-36 = the subject-routing verbs #585.)
        assert_eq!(FrameType::from_u8(37), Some(FrameType::AckReplicated));
        assert_eq!(
            FrameType::from_u8(38),
            Some(FrameType::OffsetForLeaderEpoch)
        );
        assert_eq!(FrameType::from_u8(39), Some(FrameType::SegmentFingerprints));
        assert_eq!(FrameType::from_u8(40), Some(FrameType::MirrorPull));
        assert_eq!(FrameType::from_u8(41), Some(FrameType::LeafPush));
        assert_eq!(FrameType::from_u8(42), None);
        let mut buf = Vec::new();
        encode_frame(FrameType::DeliverBatch, b"\x09\x0a", &mut buf).unwrap();
        match decode_frame(&buf).unwrap() {
            FrameDecode::Frame { type_tag, body, .. } => {
                assert_eq!(FrameType::from_u8(type_tag), Some(FrameType::DeliverBatch));
                assert_eq!(body, b"\x09\x0a");
            }
            FrameDecode::Incomplete { .. } => panic!("complete"),
        }
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
        fn an_unknown_type_tag_still_frames(tag in 42u8..=255, body in prop::collection::vec(any::<u8>(), 0..256)) {
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
