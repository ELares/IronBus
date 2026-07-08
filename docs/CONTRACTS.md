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
| `0b0000_0001` | `COMPRESSED` | the payload is a compressed object: a self-describing codec descriptor then the codec stream (see [Compressed payload descriptor](#compressed-payload-descriptor-when-compressed-is-set)). CLEAR means the payload is raw |
| `0b0000_0010` | `HAS_KEY`    | the record carries a key; DERIVED from `key_len != 0`, never taken from the caller |
| `0b0000_0100` | `HAS_XXH3`   | the record carries the xxh3-64 field; DERIVED from the stored body reaching the threshold |
| `0b0000_1000` | `HAS_SUBJECT` | the record carries a stored subject field (#594); DERIVED from a non-empty subject, never taken from the caller. See [Optional subject field](#optional-subject-field-on-disk-conditional) |

`KNOWN` is `0b0000_1111`. `decode` rejects a frame whose `HAS_KEY` disagrees with
`key_len != 0`, whose `HAS_XXH3` disagrees with `body_len >= XXH3_PAYLOAD_THRESHOLD`, or
whose `HAS_SUBJECT` is set with a zero-length subject, as `BadLength`.

### Compressed payload descriptor (when `COMPRESSED` is set)

Source: `crates/ironbus-core/src/compress.rs` (issues #12, #75, #76, #387). When the
`COMPRESSED` bit is set, the record's `payload` field IS a compressed object: a fixed
9-byte descriptor followed by the codec stream. The descriptor lives INSIDE the payload,
inside the CRC-covered body, so it consumes NO new header bytes and shifts NO existing
field; `FORMAT_VERSION` stays 1 and the format-registry digest (the `pub const` layout in
`format.rs`) is unchanged. This is the reservation `docs/DICTIONARY_LIFECYCLE.md` §8 and the
codec/dict id rows of [compat/versions.md](compat/versions.md) describe, now IMPLEMENTED for
the `lz4` codec (the pure-Rust default) and, behind the OPT-IN `zstd` feature, the `zstd`
codec + the trained-dictionary lifecycle (#357).

| offset (within the payload) | field             | type | notes |
|-----------------------------|-------------------|------|-------|
| `[0, 1)`   | `codec_id`         | u8   | frozen: `0` = none, `1` = lz4 (the ADR-0003 pure-Rust default), `2` = zstd (OPT-IN `zstd` feature only). On a default (non-zstd) build, codec id `2` (or any garbage) is an UNKNOWN id and is POISON on decode, never a crash |
| `[1, 5)`   | `dict_id`          | u32  | the compression dictionary id; `0` = no dictionary (the only value the `lz4` default writes). A non-zero id the reader cannot resolve (sidecar + embedded both absent) is POISON (`UnresolvedDictId`, see DICTIONARY_LIFECYCLE.md §5). Trained dictionaries are a `zstd`-feature capability (#357) |
| `[5, 9)`   | `uncompressed_len` | u32  | the original payload length, checked against the per-unit decompressed cap BEFORE allocation (the decompression-bomb guard, #76), for `lz4` and `zstd` alike |
| `[9, ...)` | `stream`           | bytes| the codec stream (for `lz4`, an lz4 block; for `zstd`, a zstd frame; for `none`, the raw bytes) |

Two write guards keep compression always safe and never lossy on size:

- **Raw-store threshold.** A payload below `~64` bytes (`DEFAULT_RAW_STORE_THRESHOLD`), or
  any payload when the codec is `none`, is stored RAW with the `COMPRESSED` bit CLEAR and no
  descriptor, so the record is BYTE-FOR-BYTE the uncompressed layout.
- **Never-expand guard.** If the descriptor + stream is not STRICTLY smaller than the raw
  payload, the payload is stored RAW instead, so a compressed record can never be larger
  than the same record stored raw.

A `COMPRESSED`-clear record is therefore indistinguishable on disk from one written by a
build with no compression at all, which is what keeps EVERY existing record and conformance
vector byte-identical (backward compatibility). `body_crc` (and the optional xxh3-64) cover
the STORED, post-compression bytes, so the verify-CRC-before-decompress ordering is the
existing decode path unchanged: `decode` verifies the CRC over the stored bytes FIRST, and
only those verified bytes are ever handed to the decompressor.

### Optional xxh3-64 field (on-disk, 8 bytes, conditional)

When the STORED body (`key_len + hdr_len + payload_len`, the bytes actually written,
post-compression) is at least `XXH3_PAYLOAD_THRESHOLD` = 65536 (64 KiB), an 8-byte
little-endian `xxh3` u64 is written IMMEDIATELY BEFORE the trailer and counted in
`total_len`. It covers the same body byte range as `body_crc`. Its presence is flagged
by `HAS_XXH3`. A record below the threshold has no field and no flag, so its layout is
byte-for-byte the pre-xxh3 layout. CRC32C is verified first and remains the
resync-gating checksum; an xxh3-64 mismatch is the distinct `BadXxh3` error.

### Optional subject field (on-disk, conditional)

When a record is published on a SUBJECT (#594, V2-M2), a `HAS_SUBJECT` record carries an
optional subject field placed IMMEDIATELY AFTER the 36-byte header and BEFORE the body:
`subject_len: u16` (`RECORD_SUBJECT_LEN_PREFIX` = 2 bytes, little-endian), then `subject_len`
subject bytes, then `subject_crc: u32` (`RECORD_SUBJECT_CRC_LEN` = 4 bytes, CRC32C over the
length prefix and the subject bytes). The whole field is counted in `total_len`. Its FIXED
post-header offset is what lets the header-only length walk (`codec::decoded_len`) size a
subject frame from the header plus the 2-byte prefix alone. The subject has its OWN CRC,
independent of the body — the body CRC32C/xxh3 machinery and their threshold are computed over
`key ++ headers ++ payload` EXACTLY as before, unchanged by the subject. A record without the
bit has no field and is byte-for-byte the pre-subject layout, so `FORMAT_VERSION` stays `1`. A
corrupted stored subject is the distinct `BadSubjectCrc` error. A record published via plain
`Pub`/`PubTo` carries no subject and the bit is clear; such a record is treated as NON-MATCHING
by any subject filter (never swallowed by a `>` catch-all).

### RecordTrailer (on-disk, 8 bytes)

| offset (from frame start) | field      | type | notes |
|---------------------------|------------|------|-------|
| `[total-8, total-4)`      | `body_crc` | u32  | CRC32C over the body (`key`, `headers`, `payload` in wire order) |
| `[total-4, total)`        | `total_len`| u32  | the whole frame length |

### Relationships and limits

```
total_len = 36 (header) + (HAS_SUBJECT ? 2 + subject_len + 4 : 0)
          + key_len + hdr_len + payload_len + (HAS_XXH3 ? 8 : 0) + 8 (trailer)
```

A record is intact only when: `magic` matches, `version` == 1, `header_crc` passes,
the trailing `total_len` equals the computed total, `body_crc` passes, (if present) the
`subject_crc` matches, and (if present) the `xxh3-64` matches.

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
| `[8, 9)`   | `version`        | u8       | `FORMAT_VERSION` = 1, or `FORMAT_VERSION_COMPACTED` = 2 on a COMPACTED segment ONLY (#337, below); a v1 reader rejects any other value |
| `[9, 10)`  | `checksum_algo`  | u8       | frozen `0x1` = CRC32C; a v1 reader rejects any other value |
| `[10, 12)` | `flags`          | u16      | reserved in v1 (zero); preserved on read, not interpreted. Bit 0 (`SEGMENT_FLAG_COMPACTED` = `0x0001`, #337) marks a COMPACTED segment, which stamps `version` = 2 (below) |
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

### v2 COMPACTED segment (the compaction delta, #337)

Source: `crates/ironbus-core/src/format.rs` (the v2 consts), `crates/ironbus-core/src/segment.rs`
(`CompactionMeta`), `crates/ironbus-storage/src/compaction.rs` (the writer).

A COMPACTED segment is the output of an optional key-compaction clean (see
[COMPACTION.md](COMPACTION.md)). It is structurally a normal segment with two ADDITIVE facts: the
`SEGMENT_FLAG_COMPACTED` (`0x0001`) bit in the header `flags`, and a 44-byte compaction-metadata
block written immediately AFTER the standard 32-byte footer as the file's FINAL bytes. The header
and footer `version` bytes are stamped `FORMAT_VERSION_COMPACTED` = 2 on a compacted segment
(only); the footer is otherwise the IDENTICAL 32-byte layout. A v1 (non-compacted) segment is
byte-for-byte unchanged: the version byte is `2` ONLY when the COMPACTED flag is set. A v1-only
reader REFUSES a `version` = 2 segment with a typed `UnsupportedVersion` (fail-closed). The
records inside a compacted segment are the SURVIVORS, written at their ORIGINAL (sparse) offsets
and sequences; each survivor's original offset is reconstructed on read from its stored sequence
and the constant offset-minus-sequence delta.

A compacted segment's on-disk shape is therefore:
`[64-byte header (version 2, COMPACTED flag)] [survivor record frames, sparse seqs] [32-byte footer (version 2)] [44-byte CompactionMeta block]`.

#### CompactionMeta block (on-disk, 44 bytes)

Frozen offsets (`compaction_meta_offsets`). `block_crc` covers `[0, 40)`. The covered spans are the
ORIGINAL source set's TRUE ranges (NOT the sparse survivor range), so recovery advances its
chain-continuity expectation across the compacted segment by the covered span, not the survivor
count.

| offset (from block start) | field | type | notes |
|---|---|---|---|
| `[0, 8)`   | `covered_base_offset` | u64 | the source set's TRUE starting offset (its own field, NOT an alias of `base_offset`) |
| `[8, 16)`  | `covered_end_offset`  | u64 | one past the highest covered SOURCE offset |
| `[16, 24)` | `covered_base_seq`    | u64 | the source set's TRUE starting sequence |
| `[24, 32)` | `covered_end_seq`     | u64 | one past the highest covered SOURCE sequence |
| `[32, 40)` | `highest_covered_source_id` | u64 | the highest segment id this clean supersedes (the recovery tie-break) |
| `[40, 44)` | `block_crc`           | u32 | CRC32C over `[0, 40)` of this block |

The block is self-validating exactly like the footer: a reader of a `version` = 2 segment reads
the trailing block, checks `block_crc`, and rejects a torn or mismatched block the same way a torn
footer is rejected, so a half-written compacted segment never parses as a valid compacted segment
(it falls into the crash-before-commit recovery case). The footer and this block are one
contiguous trailing write, so they become durable together. Nothing in the header reserved region
`[44, 60)` is touched (it stays owned by at-rest encryption), so a compacted-AND-encrypted segment
has room for both.

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
name is a safe, reversible filename. The OFFLINE `admin consumer-reset` verb (#299) rewrites
this exact file: it writes the `AckCursor::resume(target)` snapshot (committed watermark, no
ahead set) through the same dual-slot CRC checkpoint, so the broker's recovery reads it
natively. The canonical filename helper is `ironbus_storage::naming::cursor_checkpoint_name`,
which the engine and the offline verb share so the names cannot drift.

### DLQ redrive watermark (the offline redrive checkpoint, #299)

Source: `crates/ironbus-storage/src/admin.rs`. The OFFLINE `admin dlq-redrive` verb records how
far it has re-injected the durable DLQ records onto the main log in `dlq-redrive.ckpt`, which is
the SAME two-slot CRC checkpoint slot format above (no new on-disk format), with an 8-byte
payload: a little-endian `u64` count of leading DLQ records already redriven. Its absence means
"nothing redriven yet". The watermark is advanced ONLY after the re-injected records are fsynced
to the main log, so a crash before the advance re-redrives that suffix (at-least-once) rather than
skipping it, and a completed redrive re-run re-injects nothing (idempotent). The filename never
begins with `cursor`/`attempts` and is not a segment file, so it is inert to cursor/attempt
recovery and to the log.

### Attempt-count snapshot (the checkpoint payload, #358)

Source: `crates/ironbus-core/src/attempt.rs`. This is the payload stored in a separate
two-slot checkpoint for a work-group's durable per-message delivery-attempt counts: the
`{offset -> attempt}` map of its in-flight (delivered but unacked) entries, so `MaxDeliver`
survives an unclean restart. Bounded by `max_in_flight` per group.

| field        | type  | width   | notes |
|--------------|-------|---------|-------|
| `version`    | u8    | 1       | attempt `SNAPSHOT_VERSION` = 1 (distinct from the cursor's) |
| `count`      | u32   | 4       | number of `(offset, attempt)` pairs that follow |
| `pairs[]`    | pairs | 12 each | `count` `(offset: u64, attempt: u32)` pairs in strictly ascending offset order |
| `crc`        | u32   | 4       | CRC32C over every preceding byte of the snapshot |

`ATTEMPT_SNAPSHOT_MIN_LEN` = `1 + 4 + 4` = 9 bytes (no pairs). The default group's file is
`attempts.ckpt`; a named group's is `attempts-<hex(name)>.ckpt`. It is its OWN two-slot
checkpoint with a larger per-slot payload cap (`ATTEMPTS_PAYLOAD` = 32 KiB) than the 64-byte
cursor slot, since the map scales with `max_in_flight`. The format is ADDITIVE to the prior
model: a data directory written before #358 simply has no attempts file, which decodes as
"no carried counts" (every in-flight message resumes at attempt 1, the historical behavior);
a torn snapshot degrades the same way and never blocks open.

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
| 1   | `Connect`   | client to server | `ConnectBody` (below): the client's per-consumer credit request (#292); an EMPTY body is still valid (an old client, server uses its defaults) |
| 2   | `Info`      | server to client | `InfoBody` (below): the server's advertised per-consumer credit defaults/caps and the negotiated value (#292); an EMPTY body is still valid (an old server, client keeps its local credit) |
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
| 20  | `PubAckDuplicate` | server to client | the ORIGINAL durable `offset` as an 8-byte LE u64 (a benign dedup hit, #33): same body shape as `PubAck`, `duplicate = true` by the frame type alone, `rc = 0` |
| 21  | `GapMarker` | server to client | `GapMarkerBody` (25 bytes, below): a permanently-absent offset span `[from, to)` + `bytes_skipped` + reason (#346). The consumer-visible, per-consumer OPT-IN twin of `Truncated` (tag 18); sent only to a consumer that advertised the capability, in place of `Truncated`, so an old consumer never receives it |

Tags **22 through 49** were appended after the v1 core set above, under the same append-only
rule (no existing tag's meaning ever changed). Their authoritative byte-level body layouts
live in the `ironbus-proto` rustdoc on each variant (the normative encoder/decoder — restating
all 28 body specs here is the duplication that lets tables rot); this table freezes the tag
numbers, planes, and purposes:

| tag | FrameType | plane / direction | purpose |
|-----|-----------|-------------------|---------|
| 22  | `ProduceConfirm` | server to client | Level-2 consumed-confirmation for an opted-in produce: `offset` (8B LE) + one-byte status (0 consumed, 1 timed-out, 2 dead-lettered) (#494, #497) |
| 23  | `Fetch` | client to server | batched work-group pull; answered with the existing `Deliver`/advisory frames terminated by one `FlowEnd` (#464) |
| 24  | `StreamFetch` | client to server | Tier-S offset-addressed window fetch (`start_offset` + caps) (#543) |
| 25  | `StreamCommit` | client to server | Tier-S cumulative cursor commit for a streaming group (#550) |
| 26  | `DeliverBatch` | server to client | one contiguous Tier-S run as raw on-disk frame bytes; capability-gated (an old client always gets per-record `Deliver`s) (#541) |
| 27  | `Raft` | peer only | embedded metadata-Raft message envelope; a client never sends or receives it (#578) |
| 28  | `StreamDeclare` | client to server | declare/ensure a named stream (#588) |
| 29  | `StreamInfo` | client to server | named-stream existence + durable head query (#588) |
| 30  | `PubTo` | client to server | stream-addressed publish (stream id + embedded `PubBody`) (#588) |
| 31  | `SubTo` | client to server | stream-addressed subscribe (stream id + group) (#588) |
| 32  | `FetchRecords` | peer only | ISR follower fetch request (`from_offset` + caps); encoder/decoder in `ironbus-server` `cluster::replication` |
| 33  | `FetchResponse` | peer only | the leader's records + high-watermark reply to `FetchRecords` |
| 34  | `BindSubject` | client to server | bind a `*`/`>` subject pattern to a named stream; `admin`-scoped under auth (#585) |
| 35  | `PubSubject` | client to server | publish by literal subject; fail-closed single-home resolution (#585) |
| 36  | `SubSubject` | client to server | subscribe by literal subject (#585) |
| 37  | `AckReplicated` | peer only | quorum-`fdatasync` replication ack (releases the withheld cluster `PubAck`) (#719) |
| 38  | `OffsetForLeaderEpoch` | peer only | KIP-101-style epoch/offset divergence query on the fetch path (#873) |
| 39  | `SegmentFingerprints` | peer only | sealed-segment footer/CRC fingerprints for divergence self-heal (#612, #613) |
| 40  | `MirrorPull` | peer only (cross-cluster) | async geo mirror pull request/response (verbatim CRC-framed records) |
| 41  | `LeafPush` | peer only (leaf to hub) | leaf push replication; the hub re-validates every frame before appending |
| 42  | `NotLeader` | server to client | typed cluster produce redirect with the leader's client-address hint (#735) |
| 43  | `CommittedHwQuery` | peer only | committed high-watermark query/response |
| 44  | `TxnPrepare` | client to server | durably buffer an invisible transactional half message (#640) |
| 45  | `TxnCommit` | client to server | make a prepared half message visible, exactly once (#640) |
| 46  | `TxnRollback` | client to server | discard a prepared half message (#640) |
| 47  | `TxnCheck` | server to client | broker back-check of an in-doubt half message (pass-driven push, like tag 22) (#640) |
| 48  | `TxnCheckResult` | client to server | the producer's commit/rollback resolution answer (#640) |
| 49  | `TxnListen` | client to server | bind a transaction-state listener group to this connection (#640) |
| 50  | `RaftAuth` | peer only | HMAC-authenticated raft peer frame: the interim shared-secret integrity + origin-auth envelope `[ver:1][mac:32][raft_pb]` around a `Raft` (27) body; a client never sends or receives it (#1067 Inc 2) |
| 51  | `DataPlaneAuth` | peer only | HMAC-authenticated cluster DATA-plane peer frame: the interim shared-secret integrity + origin-auth envelope `[ver:1][mac:32][verb-tag:1][partition:u64-le][layer body]` wrapping ANY data-plane verb (`FetchRecords` 32 / `FetchResponse` 33 / `AckReplicated` 37 / `OffsetForLeaderEpoch` 38 / `CommittedHwQuery` 43), over a domain label distinct from `RaftAuth`; the real verb tag is re-embedded inside the authenticated content, and the MAC is streamed over the (up to 8 MiB) zero-copy `FetchResponse` run without copying it. A client never sends or receives it (#1067 Inc 3) |

`from_u8` returns `None` for tag 0 and for tags 52 and above (unknown, still framed by the
envelope). The tag map is HASH-PINNED by the registry gate (the `frame-tags-sha256` sentinel
in [compat/versions.md](compat/versions.md)): a tag addition cannot land without re-pinning
the registry and updating this table in the same commit. (This paragraph previously froze the
vocabulary at "22 and above" while the code shipped through 49 — the pin exists so this file
can never silently contradict `frame.rs` again.)

The dedup-hit response (#33) deliberately uses the NEW append-only tag 20 rather than mutating the
frozen `PubAck` (tag 14) body: a fresh produce answers `PubAck` (tag 14) and a dedup hit answers
`PubAckDuplicate` (tag 20), both carrying the 8-byte offset. The frozen `PubAck` body is therefore
untouched, and an old client that never sends a `msg_id` (see the opt-in dedup block below) never
receives tag 20.

The backpressure controls (#68, #69, implemented in #336) add NO new wire tag: a CoDel / retry
load-shed rejects a NEW produce with the existing `Err` (tag 12) frame carrying a distinct,
self-announcing UTF-8 message (`shed under load`, as opposed to the byte-cap shed's `at capacity`).
The structured, machine-actionable `retry_after_ms` (u32, sentinel `0xFFFFFFFF` = do-not-retry) /
`shed` (bool) fields the design specifies are owned by the frozen-protocol extension (#11) and are
NOT in the protocol yet; until #11 lands, the shed rides the bare `Err` frame, so the FrameType
vocabulary above is unchanged (no renumber, no new tag). See
[BACKPRESSURE.md](BACKPRESSURE.md), "What this changes on the wire".

### ConnectBody / InfoBody (wire bodies of `Connect` / `Info`, #292)

Source: `message.rs`. The handshake bodies were EMPTY before #292; they now carry the per-consumer
credit negotiation in a VERSIONED, LENGTH-PREFIXED, FORWARD-COMPATIBLE body so future fields (for
example the #71/#11 `wire_protocol_version` + capability bitset) can be appended without re-breaking.
The empty-body case stays valid in BOTH directions (the backward-compat anchor): an old client sends an
empty `Connect`, and a new client tolerates an old server's empty `Info`.

Both bodies share the same outer framing:

| field        | type | width | notes |
|--------------|------|-------|-------|
| `body_version`| u8  | 1     | the handshake-body framing version (`HANDSHAKE_BODY_VERSION` = 1). An unknown version is a typed `BodyError::BadHandshakeVersion`, never a best-effort parse. Distinct from the (un-wired) `wire_protocol_version`, which #71/#11 will carry as a FIELD inside the block. |
| `field_len`  | u16  | 2     | the length of the version's KNOWN-field block that follows. The decoder takes exactly this many bytes (cap-before-alloc: bounds-checked against the actual body BEFORE any read, so a hostile length is a typed `Truncated`, never an over-allocation). |
| `block`      | bytes| `field_len` | the version's known fields (below). The v1 fields are read from the FRONT of the block; any bytes past the v1 fields, and any bytes after the whole block, are a FUTURE version's appended fields, TOLERATED and ignored (forward-compat). |

An EMPTY body (length 0) is the historical case and decodes to "no fields": for `Connect`, no credit
requested (the server uses its defaults); for `Info`, no advertisement (the client keeps its local
credit). It carries no version byte.

`ConnectBody` v1 block (the client's request; each value is meaningful only when its presence flag is
set, so an absent value means "use the server default", and there is no unbounded/`request(MAX)` value):

| field         | type | width | notes |
|---------------|------|-------|-------|
| `flags`       | u8   | 1     | presence/capability bits: bit 0 (`CONNECT_FLAG_HAS_CREDIT`) the message-credit request is present; bit 1 (`CONNECT_FLAG_HAS_CREDIT_BYTES`) the byte-budget request is present; bit 2 (`CONNECT_FLAG_WANTS_GAP_MARKER`, #346) the consumer UNDERSTANDS the `GapMarker` frame (tag 21) and wants it in place of `Truncated` (a pure capability flag: no associated value, occupies no slot in the block) |
| `requested_credit` | u32 LE | 4 | the per-consumer MESSAGE credit the client wants (meaningful iff bit 0); the server negotiates `min(request, server cap)` |
| `requested_credit_bytes` | u64 LE | 8 | the per-consumer BYTE budget the client wants (meaningful iff bit 1) |

`InfoBody` v1 block (the server's advertisement; the server has already clamped the client's request to
its cap, so the advertised `negotiated` value is the one the client adopts):

| field         | type | width | notes |
|---------------|------|-------|-------|
| `flags`       | u8   | 1     | presence/capability bits: bit 0 (`INFO_FLAG_HAS_CREDIT`) the message-credit advert is present; bit 1 (`INFO_FLAG_HAS_CREDIT_BYTES`) the byte-budget advert is present; bit 2 (`INFO_FLAG_GAP_MARKER`, #346) the server CONFIRMS it will emit `GapMarker` frames for this connection (set iff the client advertised `CONNECT_FLAG_WANTS_GAP_MARKER` AND the server supports it; the negotiation is AND) |
| `credit.negotiated` | u32 LE | 4 | the per-consumer MESSAGE credit NEGOTIATED for this connection (`min(request, cap)`, or the default when the client requested nothing) |
| `credit.cap`  | u32 LE | 4 | the server's hard message-credit cap (informational; the negotiated value never exceeds it) |
| `credit_bytes.negotiated` | u64 LE | 8 | the per-consumer BYTE budget negotiated for this connection |
| `credit_bytes.cap` | u64 LE | 8 | the server's hard byte-budget cap (`0` = unlimited) |

The negotiation: the effective per-consumer credit is `min(client request, server cap)`, or the server
default when the client requests nothing. A request can only ever TIGHTEN the server cap, never raise
it; no unbounded value is representable on the wire. The negotiated credit then GOVERNS the consumer
pull (the existing `consumer_credit` / `consumer_credit_bytes` flow control, see
[FLOW_CONTROL.md](FLOW_CONTROL.md)). The `Connect`/`Info` FrameType tags (1, 2) are UNCHANGED: only the
previously-empty BODY gained this additive, version-prefixed format, so the frozen tag freeze holds.

### PubBody (wire body of `Pub`)

Source: `message.rs`. Variable parts use explicit u16 length prefixes.

| field         | type   | width | notes |
|---------------|--------|-------|-------|
| `flags`       | u8     | 1     | producer record flags (the server derives storage flags like `HAS_KEY`); bit 7 (`PUB_FLAG_HAS_DEDUP`, `0b1000_0000`) is a WIRE-only signal that the opt-in dedup block follows, and bit 6 (`PUB_FLAG_FIRE_AND_FORGET`, `0b0100_0000`) is a WIRE-only QoS-0 marker (#11); BOTH bits (`PUB_WIRE_ONLY_FLAGS`) are masked OFF before the byte becomes a stored record flag |
| `timestamp_ms`| u64    | 8     | producer time, milliseconds |
| `key_len`     | u16    | 2     | length of the key |
| `key`         | bytes  | `key_len` | routing/ordering key (empty if none) |
| `hdr_len`     | u16    | 2     | length of the headers |
| `headers`     | bytes  | `hdr_len` | headers blob |
| `pid_len`     | u16    | 2     | ONLY if bit 7 set: length of the dedup `producer_id` |
| `producer_id` | bytes  | `pid_len` | ONLY if bit 7 set: the dedup identity (empty = anonymous, session-scoped) |
| `epoch`       | u64    | 8     | ONLY if bit 7 set: the producer's monotonic epoch (the fencing token) |
| `mid_len`     | u16    | 2     | ONLY if bit 7 set: length of the dedup `msg_id` |
| `msg_id`      | bytes  | `mid_len` | ONLY if bit 7 set: the idempotency key the broker deduplicates on (NEVER the body) |
| `payload`     | bytes  | rest  | the remainder of the body is the payload |

The OPT-IN dedup block (`producer_id`, `epoch`, `msg_id`) is the effectively-once mechanism (#33):
it is present on the wire ONLY when bit 7 of `flags` is set, so a dedup-DISABLED produce omits it and
the body is byte-for-byte the historical layout (additive, opt-in). Dedup keys on `msg_id` ONLY,
never the body. A `msg_id` already seen within the producer's bounded window (the dual count + time
bound, default ~100k ids OR ~2 min on the monotonic clock) is a benign dedup hit: the broker answers
`PubAckDuplicate` (tag 20) with the ORIGINAL offset and appends no second copy. A produce whose
`epoch` is below the broker's known high-water for `producer_id` is FENCED (answered an `Err`), so a
zombie session reusing an old `producer_id` cannot replay stale ids.

The OPT-IN fire-and-forget marker (bit 6, `PUB_FLAG_FIRE_AND_FORGET`) is the QoS-0 fast path (#11,
#402): a producer sets it and does NOT wait for a `PubAck`. The broker may DROP the produce under its
fire-and-forget token bucket WITHOUT acking (the QoS-0 producer accepts loss by contract, counted in
`ironbus_fire_and_forget_shed_total`), and when NOT shed appends it durably as usual but sends NO
`PubAck`. It carries no extra block, so it never changes the body layout; the default (bit clear) is
the unchanged at-least-once `PubAck` path. A client opts in with `Client::produce_fire_and_forget`; the
default `Client::produce` is unchanged. The `FrameType` tag vocabulary is UNCHANGED (only the additive
flag).

A PUB whose `flags` carry `RecordFlags::COMPRESSED` (bit 0, a REAL stored record flag, not a
wire-only bit) declares its payload is an already-compressed object: the fixed 9-byte descriptor
plus the codec stream (see [Compressed payload descriptor](#compressed-payload-descriptor-when-compressed-is-set)).
The broker passes such a payload through its write seam untouched (never double-wrapped, #430),
and since #438 it validates the descriptor SHAPE at produce time, a header-only parse with NO
decompression: the payload must be at least the 9-byte descriptor, the codec id must be one of
the REGISTERED ids (`none`/`lz4`/`zstd` per [compat/versions.md](compat/versions.md), regardless
of the broker's own build: a `zstd` record is a consumer capability), the claimed
`uncompressed_len` must be within the readers' per-unit decompressed cap
(`DEFAULT_MAX_DECOMPRESSED_BYTES`), a `none`-codec stream's length must equal the claim exactly,
and an `lz4`/`zstd` stream must be non-empty. The non-empty rule is NORMATIVE: a genuine encoder
never emits an empty stream (an lz4 block needs at least one token byte even for empty output,
and zstd compresses even the empty payload to a non-empty frame), so on one hand-craftable
degenerate input (codec `zstd`, claimed length 0, EMPTY stream, which a permissive zstd decoder
accepts as a 0-byte output) the gate is deliberately STRICTER than the read side; everywhere
else its rejection set is a subset of the readers'. A violation is rejected with an `Err` (tag 12)
carrying `malformed compressed descriptor: <detail>` and nothing is appended (no offset is
consumed); a fire-and-forget violation is dropped with NO frame (the QoS-0 no-frame contract).
`dict_id` and stream CONTENT are deliberately not judged at produce (a reader capability and
codec work, respectively), so a corrupt stream behind a well-shaped descriptor remains a
read-side `ClientError::Decompress`. The gate sits at the WIRE boundary only: the engine's own
compressed writes and the DLQ redrive's direct re-injection do not pass through it. Rollout
coupling: because this produce gate rejects an UNREGISTERED codec id, registering a future codec
id requires brokers to learn the new id BEFORE producers emit it (upgrade brokers first, then
producers); a producer that emits the id against an older broker is rejected at produce.

There is NO topic field and NO trace-id header list. `key`, `headers`, `producer_id`, and `msg_id`
are each bounded by `u16::MAX`.

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

### GapMarkerBody (wire body of `GapMarker`, tag 21, fixed 25 bytes)

The consumer-visible gap marker (#346, refs #59, #9): the broker tells a consumer that the half-open
offset span `[from, to)` is PERMANENTLY ABSENT (skipped) from the DELIVER stream, so a reader tracking
contiguity learns the offset jump is a bounded, REPORTED gap rather than message loss. Emitted just
BEFORE the next delivery across the gap, exactly once per gap, and ONLY to a consumer that negotiated
gap-marker support (the `Connect` capability bit below); such a consumer receives this INSTEAD of a
`Truncated` advisory (no double-signal). `bytes_skipped` and `reason` are sourced from the
already-frozen `loss-report.v1` skip record.

| field           | type | width | notes |
|-----------------|------|-------|-------|
| `from`          | u64  | 8     | the first absent offset (inclusive): where the hole begins (the last delivered offset plus one) |
| `to`            | u64  | 8     | the first present offset after the hole (exclusive): delivery resumes here, and the next record (if any) carries this offset |
| `bytes_skipped` | u64  | 8     | the reported bytes lost in the hole (from `loss-report.v1`); `0` when the cause is byte-untracked (a plain retention/trim reap, whose span is the record count `to - from`) |
| `reason`        | u8   | 1     | why the span is absent: `1` = `gap_reason::TRIMMED` (a retention / disk-full drop-oldest reap), `2` = `gap_reason::COMPACTED` (#337 key-compaction; EMITTED since #411 when a gap-marker-capable consumer reads across a mid-stream compacted hole), `3` = `gap_reason::FILTERED` (#594 per-subject filtered consumer; the offsets in `[from, to)` did not match the group's subject filter, or carried no stored subject — a per-filter absence, the offsets are still present for an unfiltered group). An unknown future value is TOLERATED by a reader (decoded verbatim, never an error), so the reason field grows without a new frame |

Trailing bytes are rejected; the `reason` byte is NOT validated by the codec (an unknown reason is a
valid, tolerated marker). The frame is the OPT-IN, richer twin of `Truncated`: for a trim, `to ==
earliest_retained` and `from == earliest_retained - skipped`, so the same hole the legacy
`Truncated` (tag 18) names is carried with explicit `[from, to)` bounds and a reason. Key-compaction
(#337) emits MID-STREAM `[from, to)` holes with `reason = COMPACTED` through the SAME frame
(additively, no wire change): since #411, when a gap-marker-capable consumer reads across a compacted
hole the server sends one such `GapMarker` with `bytes_skipped == 0` (the span is the record count
`to - from`, a compaction hole is byte-untracked and is NOT a loss). A NON-capable consumer takes the
silent cursor-advance instead (no frame), so a compacted hole never reaches an old consumer and never
double-signals.

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

Configuration is the `EngineConfig` struct (and its nested configs), populated from a
layered `flag > env > FILE > default` precedence (`docs/CONFIG.md`). The TOML config FILE
is now IMPLEMENTED (#382): `serve --config <path>` whole-reads, parses (the pure-Rust `toml`
crate), and strictly validates a `[durability]`/`[storage]`/`[retention]`/`[backpressure]`/
`[delivery]`/`[network]` document with the bare `profile` key, then slots it between env and
default. The shared literal grammar (durations `{ms,s,m,h,d}`, binary byte sizes
`{B,KiB,MiB,GiB,TiB}`, unit-required, decimal-SI rejected, overflow-checked), the
reject-unknown-key-with-a-did-you-mean rule, `--allow-unknown-config`, and the coupled-set
validators live in `ironbus-core::config`; the immutable `Arc<EffectiveConfig>` plus the
atomic re-read RELOAD (validate the whole config, reject a cold-key change atomically, swap
only on success) are in `ironbus-cli`. The hot/cold/coupled reload classes are enforced by
that re-read engine. The engine runs as a startup self-check when `--config` is set, and it
ALSO has a runtime trigger now: SIGHUP re-reads the `--config` file and applies the
LIVE-reloadable subset (the consumer-safe retention bounds and the disk-full policy) to the
running engine without dropping connections, while a restart-required key change is reported
on stderr but not applied live (#380, refs #88). A cold-key change (segment size, data dir) is
rejected. SIGINT/SIGTERM remain the graceful stop (#195). The MUTATING wire `CONFIG SET` admin verbs need the #106 auth and
are deferred (no unauthenticated remote config mutation). See the discrepancies section.

### EngineConfig (runtime config struct)

| field                | type            | default | notes |
|----------------------|-----------------|---------|-------|
| `log`                | `LogConfig`     | -       | storage log config (segment and total-byte caps) |
| `lease`              | `LeaseConfig`   | -       | visibility timeout and hard cap |
| `delivery`           | `DeliveryConfig`| -       | max-deliver and backoff |
| `max_in_flight`      | u32             | -       | max-ack-pending window per group; `0` is rejected at open (`ZeroMaxInFlight`) |
| `consumer_credit`    | u32             | `DEFAULT_CONSUMER_CREDIT` = 2048 (the auto-tune CEILING) | per-connection in-flight credit; the message-count window auto-tunes from a 64 floor toward this ceiling, RAM-bounded by `consumer_credit_bytes`; `0` is floored to 1 at open, a value `<= 64` pins the historical fixed window |
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
`cursor-<hex>.ckpt`. The `LeaseTable`'s per-message delivery-attempt counts are ALSO
durable (#358): each group's in-flight `{offset -> attempt}` map is checkpointed (default
`attempts.ckpt`, named `attempts-<hex>.ckpt`) so `MaxDeliver` survives an unclean restart.
On open the table seeds its carried attempt counts so a redelivered message resumes at its
true attempt number instead of resetting to 1.

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
or `Idle` (nothing deliverable now). The `Truncated` outcome is engine-internal and consumer
capability-agnostic: the SESSION maps it to the wire `Truncated` frame (tag 18) for a legacy consumer,
or to the richer `GapMarker` frame (tag 21) for a consumer that negotiated gap-marker support (#346),
so the choice of wire frame is a session concern, not an engine one.

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
| 6    | `ScrubberSuspect`      | `scrubber_suspect`        |

Code 6 (`ScrubberSuspect`) is reserved for the at-rest scrubber (#92): silent bit rot found on a
background integrity pass. It was APPENDED per #59 without bumping `schema_version` (the
append-only rule: a new reason gets a new number, name, and label; existing codes never change).
A torn tail (code 1) is a reported skip but NOT data loss, so it is excluded from the
data-loss-bytes total (`LossReport::data_loss_bytes()`, the `ironbus_recovery_data_loss_bytes`
gauge); every other reason, including `ScrubberSuspect`, counts as data loss. See the
[loss-report.v1 schema doc](schemas/loss-report.v1.md) for the SkipEvent reconciliation (the
shipped `LossEvent` IS the canonical per-skip SkipEvent) and the v1-stays decision.

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
  `FlowEnd 16`, `DeadLetter 17`, `Truncated 18`, `CumulativeAck 19`, `PubAckDuplicate 20`,
  `GapMarker 21`. None of the draft's numbers match.
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
  capabilities header list. The implementation now carries the per-consumer CREDIT negotiation
  (#292: the client's requested credit in `Connect`, the server's advertised defaults/caps and the
  negotiated value in `Info`; see `ConnectBody`/`InfoBody` above) plus the first per-consumer
  CAPABILITY bit (#346: the gap-marker capability, `Connect` bit 2 / `Info` bit 2), in a versioned,
  length-prefixed, forward-compatible body. The OTHER draft fields (`auth_method`/`auth_blob`, the
  reserved `stream_id`, a negotiated `max_frame_size`, and the `wire_protocol_version` integer) are
  still NOT on the wire; the body framing is designed so they can be appended as future fields without
  a re-break. The empty-body case stays valid in both directions (an old peer).
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
  (committed watermark plus a run-length acked-ahead set), PLUS a separate two-slot
  per-message attempt-count snapshot (#358), not an event log.
- **The per-message delivery-attempt count IS durable (#358).** It was formerly in-memory
  and reset on restart; it is now persisted as a compact `{offset -> attempt}` map of the
  in-flight entries, in its own two-slot CRC checkpoint (`attempts.ckpt` for the default
  group, `attempts-<hex>.ckpt` for a named group), written on the cursor-checkpoint cadence.
  On open the lease table resumes each redelivery near its true attempt number, so `MaxDeliver`
  routes a poison record to the DLQ after at least `MaxDeliver` attempts TOTAL across an
  unclean restart (at most `MaxDeliver` plus the redeliveries not yet checkpointed when the
  crash hit). The count advances on the checkpoint cadence, so a crash replays only the
  un-checkpointed tail and never regresses below the durable floor, so a poison can no longer
  redeliver unboundedly across reboots. The map is bounded by `max_in_flight` per group. A torn or missing
  snapshot degrades to "resume at attempt 1" (the historical behavior) and never blocks open.
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
  CorruptRecordBody (3), CorruptSegmentHeader (4), SequenceGap (5), ScrubberSuspect (6)`.
  The draft names map onto the frozen ones: `TornTailTruncated` -> `TornTail`,
  `RecordCrcMismatch` -> `CorruptRecordHeader`/`CorruptRecordBody` (split by where the
  checksum failed), `SegmentHeaderBad` -> `CorruptSegmentHeader`, `InvariantViolation` ->
  `SequenceGap` (the concrete invariant recovery enforces inline), and `ScrubberSuspect` is
  appended as code 6 for the at-rest scrubber (#92). The full mapping is in the
  [loss-report.v1 schema doc](schemas/loss-report.v1.md#skipevent-the-shipped-lossevent-is-the-canonical-per-skip-schema).

### Config

- **TOML config FILE: IMPLEMENTED (#382).** The `Config` TOML (the frozen tables
  `[durability]`, `[storage]`, `[retention]`, `[backpressure]`, `[delivery]`, `[network]`, the
  reserved-but-unwired `[observability]`/`[auth]`/`[compression]` sections, the bare `profile`
  key, the duration/size unit grammar, the hot/cold/coupled tags, and `--allow-unknown-config`)
  is now wired: `serve --config <path>` slots the file between env and default (precedence
  `flag > env > FILE > default`). The repository carries the pure-Rust `toml` dependency. The
  DEFERRED residuals are the MUTATING wire `CONFIG SET`/`SAVE` admin verbs (they change runtime
  state and need the #106 connection-scoped auth, so there is no unauthenticated remote config
  mutation surface). The read of the
  materialized config ships, and the validate-whole-then-swap re-read RELOAD engine ships both as a
  startup self-check and on a runtime trigger: SIGHUP invokes it at runtime (#380, refs #88),
  re-reading `--config` and applying the live subset (the retention bounds + the disk-full policy)
  to the running engine, with restart-required keys reported on stderr but not applied live.

---

## Semantics error codes (the conformance taxonomy)

Source: `crates/ironbus-server/src/codes.rs` (issue #35).

The engine names a small set of OBSERVABLE outcomes the behavioral contract pins: a verb the
engine refuses, or a non-error signal a consumer must react to. `ErrorCode` formalizes them as
STABLE, NORMATIVE string tokens. The spelling is FROZEN: the conformance vectors (below) and any
external client assert against exactly these strings. The mapping from the engine's typed outcomes
to a code is the single source of truth (`ErrorCode::of_engine_error` plus `EngineError::code`), and
it is ADDITIVE: it does not change the existing `EngineError` Display text, the wire `Err` bodies, or
the `AckStatus` byte, so the frozen wire is byte-for-byte unchanged. A later wire error-code scheme
(a numeric tag on the `Err` frame) can adopt the same constants without a second taxonomy.

| code                              | observable outcome | source |
|-----------------------------------|--------------------|--------|
| `OK`                              | a verb succeeded (ack committed, cumulative ack advanced or a no-op, fresh produce appended) | generic success |
| `DUPLICATE`                       | a benign dedup hit: the `msg_id` was in the window, so the ORIGINAL offset is returned with no second append (`duplicate = true`, `rc = 0`, never an error) | `AppendOutcome::Duplicate` |
| `OFFSET_TRIMMED`                  | a read fell below the trim/retention horizon; the cursor reset up to `earliest_retained` and the skip is surfaced ONCE (as the wire `Truncated` frame, or, for a gap-marker consumer, the richer `GapMarker` frame with explicit `[from, to)` + reason, #346) | `Poll::Truncated` |
| `OFFSET_COMPACTED`                | a read crossed an INTERIOR key-compaction hole; the cursor advanced past the `[from, to)` run and the skip is surfaced ONCE as a `GapMarker(reason = COMPACTED)` to a gap-marker consumer (a non-capable consumer advances silently). NOT a loss: the latest-value-per-key view is intact, the cursor still reaches head, no `LossReport` (#337, #411) | `Poll::Compacted` |
| `ERR_CUMULATIVE_ACK_NOT_ALLOWED`  | a cumulative ack on a competing / `key_shared` / unknown / not-marked-broadcast group | `EngineError::CumulativeAckOnWorkGroup` |
| `ERR_ACK_NOT_OWNED`               | an ack/nack/term/progress on a lease this consumer does not own (never delivered, or a stale generation) | `AckResult::Fenced` / `NackResult::Fenced` (wire status `0`) |
| `ERR_CUMULATIVE_ACK_OUT_OF_RANGE` | a broadcast cumulative ack whose `up_to` is past the durable head or below earliest-retained | `EngineError::CumulativeAckOutOfRange` |
| `ERR_BROADCAST_GROUP_BUSY`        | a second subscriber, or an unsafe flip to broadcast on a group with competing in-flight state | `EngineError::BroadcastGroupBusy` |
| `ERR_BROADCAST_GROUP_NOT_NAMED`   | a flip to broadcast named the default/empty group, which can never be broadcast | `EngineError::BroadcastGroupNotNamed` |
| `ERR_TOO_MANY_GROUPS`             | a new named group exceeded the per-engine group cap | `EngineError::TooManyGroups` |
| `ERR_INVALID_GROUP_NAME`          | a group name was empty, too long, or non-graphic ASCII | `EngineError::InvalidGroupName` |
| `ERR_PRODUCER_FENCED`             | a produce presented a STALE producer epoch (a zombie session) | `AppendOutcome::Fenced` |
| `ERR_AT_CAPACITY`                 | a produce was shed at the durable-log byte cap (drop-new) | at-capacity `EngineError::Storage` |
| `ERR_GENERATION_EXHAUSTED`        | the lease generation space is exhausted (unreachable in practice) | `EngineError::GenerationExhausted` |
| `ERR_MISSING_RECORD`              | an internal invariant broke (a deliverable offset had no record) | `EngineError::MissingRecord` |
| `ERR_ZERO_MAX_IN_FLIGHT`          | `max_in_flight` was zero, rejected at open | `EngineError::ZeroMaxInFlight` |
| `ERR_STORAGE`                     | a residual storage error (not the byte-cap shed) | `EngineError::Storage` |

## Semantics conformance vectors (the executable spec)

Source: `crates/ironbus-server/tests/vectors/semantics.json` plus the harness
`crates/ironbus-server/tests/conformance_vectors.rs` (issue #35).

The vectors are a LANGUAGE-AGNOSTIC, checked-in data file of input-sequence to observable-output
cases that pin every observable behavior the parent #3 contract promises, so any IronBus
implementation or client can be checked against the same suite. They are the NORMATIVE executable
spec for the queue semantics; the prose contract above is the human-readable companion.

This is the BEHAVIORAL semantics suite, DISTINCT from the on-disk FORMAT corpus
(`ironbus-core/tests/conformance_corpus.rs`, #45): the corpus pins record/segment BYTES, these
vectors pin observable QUEUE BEHAVIOR.

Each vector is a `name`, a `category`, a `setup` (engine config), and an ordered list of `steps`.
Each step is one input operation (`produce`, `produce_dedup`, `poll`, `ack`, `nack`,
`cumulative_ack`, `set_broadcast`, `set_key_ordering`, `join_member`, `subscribe`,
`expect_committed`, ...) plus its EXPECTED observable output (an assigned offset, a delivery count,
a stable error/signal code from the table above, a committed cursor position, a dedup `duplicate`
flag, or a trim signal). The categories cover: ORDERING (monotonic offsets, no gaps; out-of-order
ack advances only the contiguous prefix); REDELIVERY (an expired lease redelivers, an acked message
does not, a nack requeues); DEDUP (a duplicate `msg_id` returns the original offset, an evicted id
is fresh, a stale epoch is fenced); ACK REJECTION (`ERR_CUMULATIVE_ACK_NOT_ALLOWED`,
`ERR_ACK_NOT_OWNED`, `ERR_CUMULATIVE_ACK_OUT_OF_RANGE` with the named codes); KEY ROUTING (per-key
head-of-line order, distinct keys do not block each other); BROADCAST (independent per-group
cursors, the cumulative-ack verb, the group-of-one cap); and TRIM (`OFFSET_TRIMMED` after retention
reaps).

The harness DRIVES THE REAL ENGINE: it loads each vector, runs the operation sequence against an
`Engine` over an `InMemoryFs`, and asserts the observed outputs match EXACTLY (a mismatch fails the
test, so the vectors gate the semantics). It is DETERMINISTIC: all time flows through an injected
logical clock (the clock seam, `ManualClock`); every poll carries an explicit monotonic `now`, so
lease expiry, dedup-window age-out, and trim are driven by ADVANCING LOGICAL TIME with NO real
sleeps, and the suite is reproducible bit-for-bit on a slow edge CI box. The harness has teeth: a
deliberately-wrong vector fails it, so it cannot silently degrade into a rubber stamp. An external
client harness can drive the same vector file over the wire to check a second implementation against
this one suite.

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
  discrepancies). Durable consumer state is the `AckCursor` checkpoint snapshot plus the
  per-message attempt-count checkpoint snapshot (#358), not an append-only event log.
- **RecoveryReport and SkipEvent.** Not implemented as drafted; `LossReport`/`LossEvent`
  is the shipped artifact (see the discrepancies).
- **TOML Config document.** IMPLEMENTED (#382): the `--config` file, the literal grammar, the
  strict typed-key validation, the coupled-set validators, and the immutable-config atomic reload
  engine ship (the engine runs as a startup self-check, and SIGHUP now re-reads `--config` at
  runtime to apply the live subset, #380, refs #88). The deferred half is the
  authed mutating wire `CONFIG SET`/`SAVE` verbs (#106). See the discrepancies section.
- **Wire verbs from the draft with no implementation:** the auth handshake fields in
  `Connect` (`auth_method`, `auth_blob`, `stream_id`, `max_frame_size`), the `Info`
  capabilities list, the `Sub` start-mode/start-offset selector, and the producer-flow
  (`PFLOW`)/pause direction of `Flow`. The `Connect`/`Info` bodies now carry the #292 per-consumer
  CREDIT negotiation (above); the auth fields, `stream_id`, a negotiated `max_frame_size`, the
  `wire_protocol_version` integer, and the capability bitset are still future work, appendable as
  future fields of the versioned handshake body. The `Sub` selector and producer flow control remain
  unimplemented.
