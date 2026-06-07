# IronBus contract models

The normative, language-neutral reference for IronBus's on-disk, wire, config, and
runtime data models. It is the single byte-level contract a Rust struct, a fuzz corpus,
a CLI decoder, and a future replication peer must all agree with.

This document is DERIVED FROM and CROSS-CHECKED AGAINST the implementation. Where the
original design draft in [issue #137](https://github.com/ELares/IronBus/issues/137)
differs from the shipped code, the code is canonical and the divergence is listed in
[Discrepancies with the original #137 draft](#discrepancies-with-the-original-137-draft).
Models the draft names but the code does not yet implement are collected under
[Specified but not yet implemented](#specified-but-not-yet-implemented), so nothing
aspirational is presented as current fact.

## Conventions

- Every multi-byte on-disk and wire field is little-endian. There are no variable-length
  integers (varints) anywhere in the shipped format: every length is a fixed-width
  little-endian `u8`, `u16`, `u32`, or `u64`. (The draft posited LEB128 varints on the
  wire; the implementation does not use them. See the discrepancies section.)
- Field types are language-neutral: `u8`, `u16`, `u32`, `u64`, `bytes`, `enum` (a
  fixed-width tag), `string` (UTF-8 bytes, no NUL terminator unless stated).
- `CRC32C` is Castagnoli CRC-32. `xxh3-64` is XXH3 64-bit.
- "Source" cites the canonical Rust module each model is transcribed from. The owning
  design issue is given where the source pins it.

---

## On-disk record models

Source: `crates/ironbus-core/src/format.rs`, `crates/ironbus-core/src/codec.rs`,
`crates/ironbus-core/src/types.rs` (issues #5, #8, #146).

A record frame is a fixed 36-byte header, a variable body (`key` then `headers` then
`payload`), an OPTIONAL 8-byte xxh3-64 field, then a fixed 8-byte trailer.

### RecordHeader (on-disk, 36 bytes)

Tightly packed, little-endian. Field offsets are frozen (`header_offsets` in `format.rs`).

| offset | field        | type | notes |
|--------|--------------|------|-------|
| `[0, 2)`   | `magic`      | u16  | frozen `0x4942` (bytes `0x42 0x49` = `b'B' b'I'`) |
| `[2, 3)`   | `version`    | u8   | `FORMAT_VERSION` = 1; a decoder rejects any other value |
| `[3, 4)`   | `flags`      | u8   | `RecordFlags` bits (below) |
| `[4, 12)`  | `seq`        | u64  | per-segment sequence; must fall in `[base_seq, base_seq + record_count)` |
| `[12, 20)` | `timestamp`  | u64  | producer time, milliseconds since the Unix epoch |
| `[20, 24)` | `key_len`    | u32  | length of the key bytes |
| `[24, 28)` | `hdr_len`    | u32  | length of the headers bytes |
| `[28, 32)` | `payload_len`| u32  | length of the payload bytes |
| `[32, 36)` | `header_crc` | u32  | CRC32C over bytes `[0, 32)` (every header field except the CRC itself) |

The header is immediately followed by `key_len` key bytes, then `hdr_len` headers bytes,
then `payload_len` payload bytes.

### RecordFlags (the header `flags` byte)

Source: `types.rs`. Unknown bits are preserved on read so a future writer can add flags.

| bit       | name         | meaning |
|-----------|--------------|---------|
| `0b0000_0001` | `COMPRESSED` | the payload is compressed |
| `0b0000_0010` | `HAS_KEY`    | the record carries a key; DERIVED from `key_len != 0`, never taken from the caller |
| `0b0000_0100` | `HAS_XXH3`   | the record carries the xxh3-64 field; DERIVED from the stored body reaching the threshold |

`KNOWN` is `0b0000_0111`. `decode` rejects a frame whose `HAS_KEY` disagrees with
`key_len != 0`, or whose `HAS_XXH3` disagrees with `body_len >= XXH3_PAYLOAD_THRESHOLD`,
as `BadLength`.

### Optional xxh3-64 field (on-disk, 8 bytes, conditional)

When the STORED body (`key_len + hdr_len + payload_len`, the bytes actually written,
post-compression) is at least `XXH3_PAYLOAD_THRESHOLD` = 65536 (64 KiB), an 8-byte
little-endian `xxh3` u64 is written IMMEDIATELY BEFORE the trailer and counted in
`total_len`. It covers the same body byte range as `body_crc`. Its presence is flagged
by `HAS_XXH3`. A record below the threshold has no field and no flag, so its layout is
byte-for-byte the pre-xxh3 layout. CRC32C is verified first and remains the
resync-gating checksum; an xxh3-64 mismatch is the distinct `BadXxh3` error.

### RecordTrailer (on-disk, 8 bytes)

| offset (from frame start) | field      | type | notes |
|---------------------------|------------|------|-------|
| `[total-8, total-4)`      | `body_crc` | u32  | CRC32C over the body (`key`, `headers`, `payload` in wire order) |
| `[total-4, total)`        | `total_len`| u32  | the whole frame length |

### Relationships and limits

```
total_len = 36 (header) + key_len + hdr_len + payload_len + (HAS_XXH3 ? 8 : 0) + 8 (trailer)
```

A record is intact only when: `magic` matches, `version` == 1, `header_crc` passes,
the trailing `total_len` equals the computed total, `body_crc` passes, and (if present)
the `xxh3-64` matches.

- `DEFAULT_MAX_RECORD_BYTES` = 16 MiB (`16 * 1024 * 1024`), the default hard cap on a
  single record's total size.
- `MAX_RECORD_BYTES_CEILING` = 1 GiB (`1024 * 1024 * 1024`), bounded by the u32 length
  fields; `decode`/`encode` reject a total over this as `TooLarge`.
- `XXH3_PAYLOAD_THRESHOLD` = 64 KiB.

---

## On-disk segment models

Source: `crates/ironbus-core/src/format.rs`, `crates/ironbus-core/src/segment.rs`
(issues #4, #5).

A segment file begins with a 64-byte header (the file is 4 KiB-aligned) and, once
sealed, ends with a 32-byte footer. Both are little-endian and CRC32C-protected. The
records between them use the record frame above.

### SegmentHeader (on-disk, 64 bytes)

Frozen offsets (`segment_header_offsets`). Bytes `[44, 60)` are reserved (zero).

| offset | field            | type     | notes |
|--------|------------------|----------|-------|
| `[0, 8)`   | `magic`          | bytes[8] | frozen `"IRONBUS\0"` |
| `[8, 9)`   | `version`        | u8       | `FORMAT_VERSION` = 1 |
| `[9, 10)`  | `checksum_algo`  | u8       | frozen `0x1` = CRC32C; a v1 reader rejects any other value |
| `[10, 12)` | `flags`          | u16      | reserved in v1 (zero); preserved on read, not interpreted |
| `[12, 20)` | `segment_id`     | u64      | monotonic segment identifier |
| `[20, 28)` | `base_seq`       | u64      | sequence of the first record in the segment |
| `[28, 36)` | `base_offset`    | u64      | log offset of the first record in the segment |
| `[36, 44)` | `created_unix_ms`| u64      | wall-clock creation time, milliseconds |
| `[44, 60)` | reserved         | bytes[16]| zero |
| `[60, 64)` | `header_crc`     | u32      | CRC32C over bytes `[0, 60)` |

### SegmentFooter (on-disk, 32 bytes)

Written when a segment is sealed. Frozen offsets (`segment_footer_offsets`). Bytes
`[24, 28)` are reserved (zero).

| offset | field          | type | notes |
|--------|----------------|------|-------|
| `[0, 2)`   | `magic`        | u16  | frozen `0x4653` (`b"SF"`), distinct from the record magic |
| `[2, 3)`   | `version`      | u8   | `FORMAT_VERSION` = 1 |
| `[3, 4)`   | `checksum_algo`| u8   | frozen `0x1` = CRC32C |
| `[4, 12)`  | `segment_id`   | u64  | binds the footer to its header |
| `[12, 20)` | `last_seq`     | u64  | sequence of the last record in the sealed segment |
| `[20, 24)` | `record_count` | u32  | number of records in the sealed segment |
| `[24, 28)` | reserved       | bytes[4] | zero |
| `[28, 32)` | `footer_crc`   | u32  | CRC32C over bytes `[0, 28)` |

### Segment sizing constants

- `DEFAULT_SEGMENT_BYTES` = 64 MiB; `EDGE_SEGMENT_BYTES` = 8 MiB (edge profile).
- `DEFAULT_SEGMENT_ROLL_HOURS` = 1.
- A record never spans two segments (the config validator keeps the max record size
  below the segment size).

---

## On-disk checkpoint models

Source: `crates/ironbus-storage/src/checkpoint.rs`, `crates/ironbus-core/src/cursor.rs`
(issues #60, #61, #235).

### Checkpoint slot (on-disk)

A checkpoint file is exactly two fixed-size slots. Writes alternate slots by sequence
parity; on recovery the higher-sequence slot whose CRC validates wins, so a torn write
regresses to the prior durable value, never a torn or invented one.

Per slot (little-endian):

| field     | type      | width | notes |
|-----------|-----------|-------|-------|
| `seq`     | u64       | 8     | nonzero; `0` means "never written" |
| `len`     | u16       | 2     | meaningful payload length, `<= MAX_PAYLOAD` |
| `payload` | bytes     | 64    | `MAX_PAYLOAD` = 64; only the leading `len` bytes are meaningful, the rest is padding |
| `crc`     | u32       | 4     | CRC32C over `seq`, `len`, and the leading `len` payload bytes (padding and CRC excluded) |

Slot length = `8 + 2 + 64 + 4` = 78 bytes; `CHECKPOINT_LEN` = 156 bytes (two slots).

### AckCursor snapshot (the checkpoint payload)

Source: `cursor.rs`. This is the payload stored in a checkpoint slot for a work-group's
committed cursor. It is the committed watermark plus a run-length acked-ahead set.

| field        | type  | width | notes |
|--------------|-------|-------|-------|
| `version`    | u8    | 1     | `SNAPSHOT_VERSION` = 1 |
| `committed`  | u64   | 8     | committed watermark (every offset below it is acked) |
| `ahead[]`    | pairs | 16 each | zero or more `(start: u64, end: u64)` acked-ahead ranges; run count is implicit in the length |
| `crc`        | u32   | 4     | CRC32C over every preceding byte of the snapshot |

`SNAPSHOT_MIN_LEN` = `1 + 8 + 4` = 13 bytes (no ahead ranges). A payload shorter than
this is read as the legacy committed-only format (its leading 8 LE bytes the committed
offset). The default work-group's checkpoint file is `cursor.ckpt`; a named group's is
`cursor-<hex(name)>.ckpt`, where the group name is lowercase-hex-encoded so a path-unsafe
name is a safe, reversible filename.

---

## On-disk DLQ model

Source: `crates/ironbus-storage/src/dlq.rs` (issues #63, #9).

The dead-letter sink is a SECOND segmented log rooted at the `dlq/` subdirectory of the
data directory. A DLQ record reuses the exact record/segment format above: the original
poison record is preserved verbatim (its `key`, `payload`, and original `timestamp_ms`),
and the dead-letter metadata is packed as a fixed, self-describing prefix of the DLQ
record's `headers` blob, ahead of the original headers.

### DLQ headers metadata prefix (on-disk, within a DLQ record's `headers`)

`DLQ_META_LEN` = `4 + 8 + 4 + 2 + 2` = 20 bytes, then the two variable spans.

| offset (within the headers blob) | field            | type  | notes |
|----------------------------------|------------------|-------|-------|
| `[0, 4)`   | `magic`            | bytes[4] | `DLQ_HEADER_MAGIC` = `"DLQ1"` |
| `[4, 12)`  | `source_offset`    | u64   | the SOURCE log offset the poison message had in the main log |
| `[12, 16)` | `attempt`          | u32   | the delivery (attempt) count at which it was poisoned |
| `[16, 18)` | `group_len` (`g`)  | u16   | length of the consumer group name |
| `[18, 20)` | `orig_headers_len` (`h`) | u16 | length of the original headers |
| `[20, 20+g)`     | `group`      | string | the consumer group name bytes |
| `[20+g, 20+g+h)` | `orig_headers`| bytes | the original record's headers verbatim |

`decode_dlq_headers` requires the blob to be EXACTLY `20 + g + h` bytes (a longer or
shorter blob is rejected as foreign/corrupt).

### DlqEntry (the decoded view of one DLQ record)

`decode_entry` reconstructs this in-memory view (it is not a separate on-disk layout):

| field          | type   | notes |
|----------------|--------|-------|
| `dlq_offset`   | Offset | the entry's position in the DLQ sink (NOT the source offset) |
| `group`        | string | consumer group the message was poisoned in |
| `source_offset`| u64    | source log offset |
| `attempt`      | u32    | attempt count at dead-letter |
| `timestamp_ms` | u64    | the original record's producer timestamp (preserved) |
| `key`          | bytes  | the original key (preserved verbatim) |
| `headers`      | bytes  | the original headers (metadata stripped) |
| `payload`      | bytes  | the original payload (preserved verbatim) |

The reconciliation key for the crash-atomic, exactly-once move is
`(group, source_offset, attempt)`. The DLQ log itself is the source of truth: on open,
the sink rebuilds the per-group highest dead-lettered source offset; there is no sidecar.

---

## Wire frame models

Source: `crates/ironbus-proto/src/frame.rs` (envelope), `crates/ironbus-proto/src/message.rs`
(bodies), `crates/ironbus-server/src/session.rs` (server response bodies) (issues #11, #179).

### Frame envelope

```
[ len: u32 LE ][ type: u8 ][ body: (len - 1) bytes ]
```

`len` is a little-endian u32 counting the type byte plus the body (NOT a varint). The
envelope is forward-compatible: an unknown type tag still frames at the envelope level
(the length lets a reader skip it). `MAX_FRAME_LEN` = `16 * 1024 * 1024 + 64 * 1024`
(16 MiB + 64 KiB); a length prefix over the effective cap is rejected before any
allocation, and a zero length is `EmptyFrame`.

### FrameType tags (frozen wire bytes)

These are the REAL frozen tags, pinned by the `type_tags_have_their_exact_frozen_wire_values`
test in `frame.rs`. They start at 1 and are contiguous.

| tag | FrameType   | direction | body |
|-----|-------------|-----------|------|
| 1   | `Connect`   | client to server | empty today (no negotiated state yet); the server ignores the body |
| 2   | `Info`      | server to client | empty today |
| 3   | `Ping`      | either    | empty |
| 4   | `Pong`      | either    | empty |
| 5   | `Pub`       | client to server | `PubBody` (below) |
| 6   | `Sub`       | client to server | `SubBody` (the whole body is the work-group name) |
| 7   | `Unsub`     | client to server | empty (reverts to the default group) |
| 8   | `Ack`       | client to server | `AckBody` (carries the op: ack/nack/term/progress) |
| 9   | `Nack`      | reserved  | a client sends a nack as an `Ack` frame with the Nack op; the standalone tag is reserved |
| 10  | `Flow`      | client to server | a 4-byte LE u32 credit (the requested batch size) |
| 11  | `Ok`        | server to client | reserved body-less success; not overloaded with a typed body |
| 12  | `Err`       | server to client | a UTF-8 message |
| 13  | `Deliver`   | server to client | `DeliverBody` (below) |
| 14  | `PubAck`    | server to client | the assigned durable `offset` as an 8-byte LE u64 |
| 15  | `AckStatus` | server to client | a one-byte status (below) |
| 16  | `FlowEnd`   | server to client | the count delivered in the batch as a 4-byte LE u32 |
| 17  | `DeadLetter`| server to client | `DeadLetterBody` (9 bytes, below) |
| 18  | `Truncated` | server to client | `TruncatedBody` (16 bytes, below) |
| 19  | `CumulativeAck` | client to server | `CumulativeAckBody` (below): the exclusive `up_to` offset then the group name |

`from_u8` returns `None` for tag 0 and for tags 20 and above (unknown, still framed by the
envelope).

### PubBody (wire body of `Pub`)

Source: `message.rs`. Variable parts use explicit u16 length prefixes.

| field         | type   | width | notes |
|---------------|--------|-------|-------|
| `flags`       | u8     | 1     | producer record flags (the server derives storage flags like `HAS_KEY`) |
| `timestamp_ms`| u64    | 8     | producer time, milliseconds |
| `key_len`     | u16    | 2     | length of the key |
| `key`         | bytes  | `key_len` | routing/ordering key (empty if none) |
| `hdr_len`     | u16    | 2     | length of the headers |
| `headers`     | bytes  | `hdr_len` | headers blob |
| `payload`     | bytes  | rest  | the remainder of the body is the payload |

There is NO topic field and NO message-id/trace-id header list. `key` and `headers` are
each bounded by `u16::MAX`.

### AckBody (wire body of `Ack`, fixed 25 bytes)

| field        | type | width | notes |
|--------------|------|-------|-------|
| `op`         | enum u8 | 1  | 0 = Ack, 1 = Nack, 2 = Term, 3 = Progress (frozen `AckOp` tags) |
| `offset`     | u64  | 8     | the log offset of the message |
| `generation` | u64  | 8     | the lease generation (the fencing token) |
| `delay_ms`   | u64  | 8     | for a Nack: `u64::MAX` means "no explicit delay" (broker applies its backoff), any other value is an explicit delay (0 = immediate); zero for non-Nack ops |

Trailing bytes are rejected.

### DeliverBody (wire body of `Deliver`)

| field         | type  | width | notes |
|---------------|-------|-------|-------|
| `offset`      | u64   | 8     | the log offset of the delivered message |
| `generation`  | u64   | 8     | the lease generation to carry on the ack (the fencing token) |
| `flags`       | u8    | 1     | record flags as stored |
| `timestamp_ms`| u64   | 8     | producer time, milliseconds |
| `key_len`     | u16   | 2     | length of the key |
| `key`         | bytes | `key_len` | the key |
| `hdr_len`     | u16   | 2     | length of the headers |
| `headers`     | bytes | `hdr_len` | the headers |
| `payload`     | bytes | rest  | the remainder is the payload |

There is no `attempt`/delivery-count field on the wire DELIVER body.

### AckStatus status byte (wire body of `AckStatus`)

A one-byte status. From the session: `0` = fenced (stale or not owned by this
connection), `1` = committed / requeued / extended (success), `2` = progress cap
reached. (Source: `session.rs`; the `frame.rs` doc comment states the same.)

### DeadLetterBody (wire body of `DeadLetter`, fixed 9 bytes)

| field    | type | width | notes |
|----------|------|-------|-------|
| `offset` | u64  | 8     | the log offset of the dead-lettered message |
| `reason` | u8   | 1     | `DEAD_LETTER_MAX_DELIVER` = 0 (exceeded MaxDeliver); other values reserved |

Trailing bytes are rejected.

### TruncatedBody (wire body of `Truncated`, fixed 16 bytes)

| field               | type | width | notes |
|---------------------|------|-------|-------|
| `earliest_retained` | u64  | 8     | the new earliest-retained log offset the cursor was reset to |
| `skipped`           | u64  | 8     | how many records the consumer skipped (`earliest_retained - old_cursor`) |

Trailing bytes are rejected.

### SubBody (wire body of `Sub`)

The entire frame body is the work-group name bytes (no length prefix of its own). An
empty name selects the default group. The server validates the name's shape and the group
cap when the group is first used (#240); the codec only carries the bytes.

### CumulativeAckBody (wire body of `CumulativeAck`, tag 19)

The broadcast cumulative ack (ack-all-up-to-offset, #288): the safe broadcast half of the
`JetStream` `AckAll` verb. The leading 8-byte `up_to` is the EXCLUSIVE commit offset; the
remainder of the body is the work-group name (the same whole-tail-is-the-name shape as
`SubBody`).

| field   | type  | width | notes |
|---------|-------|-------|-------|
| `up_to` | u64   | 8     | the exclusive offset to commit the broadcast cursor up to (every offset strictly below it is acked), little-endian |
| `group` | bytes | rest  | the work-group name (empty selects the default group); the remainder of the body |

A body shorter than the 8-byte `up_to` is rejected (`BodyError::Truncated`); a body of
exactly 8 bytes is the default group (empty name). The server accepts the verb ONLY for a
group marked BROADCAST (a group-of-one that sees every record in order); a competing or
`key_shared` work-group is rejected with `EngineError::CumulativeAckOnWorkGroup`, and an
`up_to` past the durable head or below the earliest-retained offset is rejected with
`EngineError::CumulativeAckOutOfRange`. Both rejections answer a typed `Err` frame and leave
the cursor untouched; a successful (or idempotent re-ack) commit answers `Ok`. The commit is
idempotent and monotonic: an `up_to` at or below the current commit (within the window) is a
no-op success and the watermark never moves backwards.

The group-of-one invariant a broadcast group rests on is ENFORCED in code, not just
documented (#288): a broadcast group accepts AT MOST ONE active subscriber, so a cumulative
ack can only ever commit past that single consumer's OWN in-flight leases, never a peer's. A
SECOND concurrent `Sub` to a broadcast group answers a typed `Err` (`BroadcastGroupBusy`) and
does not join, and marking a group broadcast (`serve --broadcast-group`) is REFUSED with the
same error when the group already carries competing in-flight state (live in-flight leases, an
out-of-order acked-ahead set, or more than one active subscriber) that a later cumulative ack
could silently commit past. A consumer's slot frees on `Unsub`, a subscription switch, or
disconnect, so the next subscriber may take over. The single-consumer cumulative ack past the
consumer's own in-flight leases stays valid.

A broadcast group MUST be a NAMED group: the DEFAULT/empty group (`""`) can never be marked
broadcast (#288). `serve --broadcast-group ""` is REFUSED at startup with the typed
`EngineError::BroadcastGroupNotNamed`. The subscriber cap binds only a named group, but the
default group's consumers reach it on the implicit default subscription and never SUB a name,
so the cap could never bind them; an uncapped broadcast default group would let two pollers
hold competing in-flight leases that a cumulative ack (with an empty group name) commits past,
the same silent drop. So `--broadcast-group` marks a named group only.

---

## Config models

Source: `crates/ironbus-server/src/engine.rs` (`EngineConfig`),
`crates/ironbus-storage/src/log.rs` (`LogConfig`, `RetentionBounds`),
`crates/ironbus-core/src/lease.rs` (`LeaseConfig`),
`crates/ironbus-core/src/delivery.rs` (`DeliveryConfig`) (issue #14).

There is NO TOML config document in the implementation today: configuration is the
`EngineConfig` struct (and its nested configs), populated from `serve` CLI flags. The
draft's `[durability]`/`[storage]`/... TOML schema, the `profile` key, the
hot/cold/coupled tags, and `--allow-unknown-config` are NOT implemented. See the
discrepancies section.

### EngineConfig (runtime config struct)

| field                | type            | default | notes |
|----------------------|-----------------|---------|-------|
| `log`                | `LogConfig`     | -       | storage log config (segment and total-byte caps) |
| `lease`              | `LeaseConfig`   | -       | visibility timeout and hard cap |
| `delivery`           | `DeliveryConfig`| -       | max-deliver and backoff |
| `max_in_flight`      | u32             | -       | max-ack-pending window per group; `0` is rejected at open (`ZeroMaxInFlight`) |
| `consumer_credit`    | u32             | `DEFAULT_CONSUMER_CREDIT` = 64 | per-connection standing in-flight credit; `0` is floored to 1 at open |
| `checkpoint_interval`| u64             | -       | checkpoint after the committed cursor advances this many offsets; `0` treated as 1 |
| `max_retained_bytes` | u64             | 0 (unlimited) | consumer-safe size retention bound |
| `max_age_ms`         | u64             | 0 (off) | consumer-safe age retention bound, in milliseconds |
| `max_messages`       | u64             | 0 (off) | consumer-safe count retention bound |
| `disk_full_policy`   | `DiskFullPolicy`| `DropNew` | overflow policy: `DropNew` (default shed) or `DropOldest` (force-reap oldest) |
| `max_groups`         | usize           | `DEFAULT_MAX_GROUPS` = 1024 | cap on live work-groups including the default `""`; `0` = unlimited |

### LeaseConfig

| field              | type | default | notes |
|--------------------|------|---------|-------|
| `visibility_nanos` | u64  | 30 s (`DEFAULT_VISIBILITY_MS` = 30000) | how long a delivery stays in-flight before redelivery |
| `hard_cap_nanos`   | u64  | 5 min (`DEFAULT_HARD_CAP_MS` = 300000) | the most a single attempt's lease may be extended, from the attempt start |

### DeliveryConfig

| field           | type      | default | notes |
|-----------------|-----------|---------|-------|
| `max_deliver`   | u32       | `DEFAULT_MAX_DELIVER` = 5 | attempts before a message is poison; `0` or `u32::MAX` (unlimited) rejected unless explicitly opted in |
| `backoff_nanos` | list[u64] | -       | escalating nack-backoff schedule; clamps to the last entry, empty = no delay |

---

## Runtime models

Source: `crates/ironbus-server/src/engine.rs`, `crates/ironbus-core/src/lease.rs`.
These are in-memory, not on-disk; they have no frozen byte layout.

### WorkGroup (in-memory)

Per work-group consumer state over the shared log: an independent committed `AckCursor`
plus its own in-flight `LeaseTable`. The lease generation space is per-group, so a
`LeaseToken` is only meaningful within the group it was delivered from. The default group
is `""` (durable, `cursor.ckpt`); named groups are durable to their own
`cursor-<hex>.ckpt`.

### LeaseToken (in-memory fencing token)

| field        | type   | notes |
|--------------|--------|-------|
| `offset`     | Offset | the leased message's log offset |
| `generation` | u64    | the generation this lease was granted under |

On restart the lease table starts empty, so anything merely in flight (delivered but
unacked) at a crash redelivers (at-least-once safe).

### Delivery (in-memory, the result of a poll)

| field        | type        | notes |
|--------------|-------------|-------|
| `offset`     | Offset      | the log offset of the message |
| `token`      | LeaseToken  | the token to ack with |
| `deliveries` | u32         | how many times this message has now been delivered (starts at 1) |
| `record`     | OwnedRecord | the message itself |

### Poll (in-memory poll outcome)

A tagged enum: `Message(Delivery)`, `Parked { offset, record }` (poison, dead-lettered),
`Truncated { earliest_retained, skipped }` (cursor fell below the oldest retained record),
or `Idle` (nothing deliverable now).

### Counters (in-memory operational metrics)

Monotonic per-process counters, reset to zero on restart, exposed via `/metrics`. They
are statistics, not durable state: `produced`, `produced_bytes`, `produce_rejected`,
`delivered`, `redelivered`, `dead_lettered`, `acks`, `segments_reaped`,
`segments_force_reaped`.

---

## Report models

Source: `crates/ironbus-storage/src/loss.rs` (issues #120, #8, #7, #16).

The implementation has ONE structured recovery/loss report: `LossReport`. The draft's
separate `RecoveryReport` and `SkipEvent` shapes are NOT implemented; `LossReport` plus
`LossEvent` is the actual artifact (it is the schema both the metrics endpoint and the
offline inspector read). It derives `serde::{Serialize, Deserialize}`; the concrete JSON
format (`serde_json`) is a dev-only dependency, so the static edge binary does not carry it.
There is NO frozen byte layout for the report (it is serde-serialized, not a fixed binary
frame), so only the field set and the frozen numeric reason codes are normative here.

This report is the versioned, externally-frozen `ironbus.loss-report.v1` schema; the
[loss-report.v1 schema doc](schemas/loss-report.v1.md) is its standalone normative reference
(the canonical JSON form, the golden tests that freeze it, and the versioning policy). The
tables below are the in-catalog summary.

### LossReport

| field            | type            | notes |
|------------------|-----------------|-------|
| `schema_version` | u16             | `SCHEMA_VERSION` = 1 |
| `events`         | list[LossEvent] | loss spans in the order recovery encountered them; empty = clean recovery |

Caps (constants, enforced at recovery): `PER_EVENT_BYTE_CAP` = 64 MiB; the global cap is
1% of durable bytes (`GLOBAL_LOSS_CAP_NUMERATOR` = 1 over `GLOBAL_LOSS_CAP_DENOMINATOR` = 100).

### LossEvent

| field                  | type     | notes |
|------------------------|----------|-------|
| `segment_id`           | u64      | the segment the loss occurred in |
| `byte_offset_start`    | u64      | byte offset within the segment where the lost span begins |
| `byte_offset_end`      | u64      | byte offset within the segment where the lost span ends (exclusive) |
| `bytes_skipped`        | u64      | the span length (`end - start`, saturating) |
| `records_lost_estimate`| u64      | best-effort lower bound on records lost in this span |
| `reason_code`          | ReasonCode | why the span was dropped |

### ReasonCode (frozen numeric codes)

Pinned by `reason_codes_are_stable_and_distinct` in `loss.rs`. A new reason is appended
with a new number; existing numbers never change.

| code | variant                | metric label              |
|------|------------------------|---------------------------|
| 1    | `TornTail`             | `torn_tail`               |
| 2    | `CorruptRecordHeader`  | `corrupt_record_header`   |
| 3    | `CorruptRecordBody`    | `corrupt_record_body`     |
| 4    | `CorruptSegmentHeader` | `corrupt_segment_header`  |
| 5    | `SequenceGap`          | `sequence_gap`            |

---

## Discrepancies with the original #137 draft

The #137 issue body contains a draft table. The following entries differ from the shipped
code; the code is canonical.

### Wire protocol (the largest divergence)

- **Framing.** The draft framed every frame as `body_len varint, verb u8, body`, with
  header lists as `varint count` then `[u8 key_id][varint val_len][bytes val]`. The
  implementation uses `len: u32 LE, type: u8, body` and has NO varints and NO header
  lists anywhere. All lengths are fixed-width little-endian.
- **Verb tag numbers are completely different.** The draft assigned verb numbers like
  `PUB 0x01`, `SUB 0x02`, `ACK 0x03`, `NACK 0x04`, `MSG 0x05`, `FLOW 0x06`, `INFO 0x07`,
  `CONNECT 0x08`, `PING 0x09`, `PONG 0x0A`, `ERR 0x0B`. The frozen implementation tags are
  `Connect 1`, `Info 2`, `Ping 3`, `Pong 4`, `Pub 5`, `Sub 6`, `Unsub 7`, `Ack 8`,
  `Nack 9`, `Flow 10`, `Ok 11`, `Err 12`, `Deliver 13`, `PubAck 14`, `AckStatus 15`,
  `FlowEnd 16`, `DeadLetter 17`, `Truncated 18`, `CumulativeAck 19`. None of the draft's
  numbers match.
- **Deliver/MSG.** The draft's `MSG` carried `offset, attempt, header list, key, payload`.
  The real `DeliverBody` carries `offset, generation, flags, timestamp_ms, key, headers,
  payload` and has NO `attempt` field on the wire.
- **Ack.** The draft's `ACK` was `offset, lease_id`. The real `AckBody` is
  `op, offset, generation, delay_ms` (a fixed 25 bytes), and the op multiplexes
  ack/nack/term/progress (so `NACK` is not a separate sent frame; it is an `Ack` with op 1).
- **Pub.** The draft's `PUB` had a `flags` byte plus a header list (msg-id/trace-id/
  timestamp) and varint key/payload lengths. The real `PubBody` is `flags, timestamp_ms,
  u16-len key, u16-len headers, payload` with NO header list and NO message-id field.
- **PubAck.** The draft carried it "on ACK 0x03 server-to-client" with an optional
  `dedup_hit`. The implementation gives `PubAck` its own frame tag (14), and its body is
  exactly the 8-byte LE offset (no `dedup_hit`). This resolves the draft's open decision
  about whether PubAck deserves its own verb: it does (#179).
- **Connect/Info.** The draft's `CONNECT` carried `queue_name, auth_method, auth_blob,
  stream_id, max_frame_size` and `INFO` carried a version, negotiated max frame size, and a
  capabilities header list. Both bodies are EMPTY in the implementation today (the
  handshake carries no negotiated state yet). The reserved `stream_id` does not exist.
- **Sub.** The draft's `SUB` carried `consumer, credit, start_mode, start_offset` and a
  close flag. The real `SubBody` is just the work-group name (the whole body). There is no
  start-mode/start-offset selector and no in-frame credit; `Unsub` is its own frame (tag 7).
- **Flow.** The draft's `FLOW` carried `direction, credit-or-bytes_per_sec, pause`. The real
  `Flow` body is a single 4-byte LE u32 credit. There is no producer-flow direction, no
  bytes-per-second, and no pause flag.
- **Frames present in code but absent from the draft:** `Ok` (11), `AckStatus` (15),
  `FlowEnd` (16). These are real frozen tags. `DeadLetter` (17) and `Truncated` (18) exist
  in both but with different tag numbers and bodies than any draft assignment.
- **Error.** The draft's `ERR` carried a `u16 code` plus a UTF-8 reason. The real `Err`
  body is just a UTF-8 message (no numeric code field).

### On-disk record and segment

- **`magic`.** The draft and code agree on `0x4942`.
- **`header_crc` range and trailer.** The draft said `header_crc` covers `[0, 32)` and the
  8-byte trailer is `body_crc, total_len`; the code agrees.
- **xxh3-64 placement.** The draft said payloads "above 64 KiB" carry the xxh3-64 "in the
  header region". In the code the threshold is "at or above 64 KiB" measured on the STORED
  body, and the field sits IMMEDIATELY BEFORE the trailer (not in the header region), gated
  by the `HAS_XXH3` flag and counted in `total_len`.
- **SegmentHeader fields.** The draft listed `magic, version, checksum_algo, flags,
  segment_id, base_seq, created_unix_ms, generation`, with reserved bytes after, and said
  the CRC scope was unstated. The code has `magic, version, checksum_algo, flags,
  segment_id, base_seq, base_offset, created_unix_ms` then reserved `[44, 60)`, with
  `header_crc` over `[0, 60)`. There is NO `generation` field; there IS a `base_offset`
  field the draft omitted.
- **SegmentFooter fields and widths.** The draft listed `record_count: u64, last_seq: u64,
  footer_crc, reserved` and called `record_count`/`last_seq` the only seek-relevant fields.
  The code footer is `magic (0x4653), version, checksum_algo, segment_id, last_seq: u64,
  record_count: u32, reserved [24,28), footer_crc` over `[0, 28)`. `record_count` is a
  u32 (not u64), and the footer carries a magic, version, checksum_algo, and `segment_id`
  the draft did not list.

### Consumer-state, lease, and DLQ

- **`ConsumerStateEvent` is not implemented.** The draft's append-only per-consumer event
  log (`event_type, offset, attempt, lease_id, fence_token, timestamp, crc`) does not exist.
  Durable consumer state today is the `AckCursor` snapshot in a two-slot checkpoint
  (committed watermark plus a run-length acked-ahead set), not an event log.
- **`Lease` shape.** The draft's runtime `Lease` had `lease_id, consumer, offset, attempt,
  granted_unix_ms, visibility_deadline_ms, fence_token`. The implemented fencing token is
  `LeaseToken { offset, generation }`; the internal lease tracks `generation, attempt_start,
  deadline, deliveries` in monotonic nanoseconds. There is no separate `lease_id`/`fence_token`
  pair (the draft's open decision about unifying them is moot: there is one `generation`),
  and no `consumer` string on the token.
- **`DlqEntry`/dead-letter move shape.** The draft's `DlqEntry` was `source_offset,
  original_enqueue_unix_ms, attempts, reason enum, dlq_offset`. The real DLQ record stores
  its metadata as a `DLQ1`-magic headers prefix (`magic, source_offset: u64, attempt: u32,
  group_len: u16, orig_headers_len: u16`, then the group name and original headers) and the
  decoded `DlqEntry` carries `dlq_offset, group, source_offset, attempt, timestamp_ms, key,
  headers, payload`. The reconciliation key is `(group, source_offset, attempt)`. The
  original enqueue timestamp IS preserved (as the record's `timestamp_ms`), matching the
  draft's intent, but there is no separate `reason` enum field in the on-disk DLQ record
  (the dead-letter reason is a wire-only advisory field).

### Reports

- **`RecoveryReport` and `SkipEvent` are not implemented as drafted.** The draft's
  `RecoveryReport` (with `shutdown_type, checkpoint_seq, records_validated, bytes_truncated,
  loss_bound_*`, ...) and `SkipEvent` (with `reason_code, lost_offset_start/end, resync_offset,
  mode`, ...) do not exist. The shipped artifact is `LossReport { schema_version, events }`
  with `LossEvent { segment_id, byte_offset_start, byte_offset_end, bytes_skipped,
  records_lost_estimate, reason_code }`.
- **`ReasonCode` values differ.** The draft's `SkipEvent.reason_code` enumerated
  `RecordCrcMismatch, SegmentHeaderBad, InvariantViolation, TornTailTruncated,
  ScrubberSuspect`. The implemented `ReasonCode` is `TornTail (1), CorruptRecordHeader (2),
  CorruptRecordBody (3), CorruptSegmentHeader (4), SequenceGap (5)`.

### Config

- **No TOML config document.** The draft's `Config` TOML (locked tables `[durability]`,
  `[storage]`, `[retention]`, `[compression]`, `[backpressure]`, `[network]`/`[network.tls]`,
  the bare `profile` key, duration/size unit grammar, hot/cold/coupled tags, and
  `--allow-unknown-config`) is NOT implemented. Configuration today is the `EngineConfig`
  struct populated from `serve` CLI flags. The repository has no `toml` dependency.

---

## Specified but not yet implemented

These models appear in the #137 draft (or the README/diagram) but are not present in the
code today. They are aspirational and MUST NOT be treated as a current byte contract.

- **OffsetIndexEntry / `.index` sidecar** and **TimeIndexEntry / `.tindex` sidecar.** The
  draft's derived 8-byte offset index and 12-byte time index do not exist; there is no
  index sidecar in the storage layer. The README still describes a "derived offset / time
  index" as part of the model, but the offset index is rebuilt-on-read at the engine level
  rather than persisted as a sidecar file.
- **CurrentPointer / `current` file.** The draft's minimal `active_segment_id,
  active_base_offset, last_flushed_offset, crc` pointer is not implemented; recovery scans
  the directory and per-segment checksums directly.
- **ManifestEdit / `manifest-NNNNNN`.** The draft's advisory append-only manifest
  (`edit_type, segment_id, base_seq, timestamp, crc`) is not implemented; the directory
  scan plus per-segment checksums is the only source of truth.
- **ConsumerStateEvent log under `consumers/<name>/`.** Not implemented (see the
  discrepancies). Durable consumer state is the `AckCursor` checkpoint snapshot.
- **RecoveryReport and SkipEvent.** Not implemented as drafted; `LossReport`/`LossEvent`
  is the shipped artifact (see the discrepancies).
- **TOML Config document.** Not implemented (see the discrepancies).
- **Wire verbs from the draft with no implementation:** the auth handshake fields in
  `Connect` (`auth_method`, `auth_blob`, `stream_id`, `max_frame_size`), the `Info`
  capabilities list, the `Sub` start-mode/start-offset selector, and the producer-flow
  (`PFLOW`)/pause direction of `Flow`. The frame tags exist but carry empty or reduced
  bodies today; capability negotiation, auth, and producer flow control are future work.
