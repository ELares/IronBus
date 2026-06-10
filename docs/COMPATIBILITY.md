# Compatibility and versioning

The on-disk-format and wire-protocol compatibility rules for IronBus, derived from and
cross-checked against the source. Every rule below cites the code mechanism that enforces
it, and a separate section lists the negotiation and migration features the policy
specifies but the code does not yet provide.

For the byte-level layouts (record header, segment header and footer, frame envelope and
bodies, checkpoint snapshot) this document does NOT repeat the tables in
[CONTRACTS.md](CONTRACTS.md); it references them and documents the compatibility rules that
ride on top of those bytes.

This is the implementation reality at the current pre-release version (`0.0.0`). Where the
intent of the policy issues (#132, #126) diverges from what is implemented, it is called
out in the discrepancies section, never asserted as present.

## Compatibility guarantee level (the 0.x promise)

The workspace is pre-release: `Cargo.toml` pins `version = "0.0.0"` for every crate, and the
CHANGELOG states the project "aims to follow Semantic Versioning once it reaches a tagged
release." So there is no SemVer stability promise yet, and the Rust API may break on any
change before a `0.x` tag.

The two durable surfaces are versioned independently of the (absent) API version and of each
other, each by a single byte:

- The **on-disk format** is `FORMAT_VERSION` (`crates/ironbus-core/src/format.rs`), currently
  `1`. It stamps the record header, the segment header, and the segment footer.
- The **wire protocol** is, today, the frozen `FrameType` tag set plus the fixed body
  layouts. There is no separately negotiated `wire_protocol_version` INTEGER on the wire yet (see
  the discrepancies). The Connect/Info handshake bodies DO now carry the #292 per-consumer credit
  negotiation in a versioned, length-prefixed, forward-compatible body (the additive handshake-body
  change below), whose own `body_version` byte and appendable field block are the seam the
  `wire_protocol_version` integer will slot into.

Within version 1 both formats are frozen: the byte layouts and tag values do not change.
"Frozen" is enforced by pinning tests, described per surface below. A future incompatible
layout takes a NEW version integer rather than reinterpreting the old one. The MSRV is Rust
`1.78` (`workspace.package.rust-version` in `Cargo.toml`, exercised by the `msrv (1.78)` CI
job in `.github/workflows/ci.yml`, which pins `toolchain: "1.78.0"`). The README records the
MSRV bump rule: it may rise only in a minor release, and the new floor is always at least six
months old.

## Wire compatibility

### The frame envelope

Every protocol message is one frame: `[len: u32 LE][type: u8][body: len - 1 bytes]`, where
`len` counts the type byte plus the body (`crates/ironbus-proto/src/frame.rs`; bytes in
[CONTRACTS.md](CONTRACTS.md) under "Frame envelope"). The length prefix lets a reader learn a
frame's full size before reading its body, so framing is independent of the per-type body
codecs.

The length is validated against an absolute cap BEFORE any allocation. `MAX_FRAME_LEN` is
`16 MiB + 64 KiB`; a prefix above it is a typed `FrameError::FrameTooLarge` read from the
four prefix bytes alone, never an allocation (`decode_frame`; test
`an_oversized_length_prefix_is_rejected_without_reading_the_body` and the proptest
`decode_frame_with_cap_rejects_an_over_cap_length`). A zero-length prefix is
`FrameError::EmptyFrame` (test `a_zero_length_prefix_is_rejected`).

### The frozen FrameType tag set

The wire verb is a one-byte tag. The frozen set runs from `Connect` = 1 through `GapMarker`
= 21, contiguous (`FrameType::as_u8` / `from_u8` in `frame.rs`; the full table is in
[CONTRACTS.md](CONTRACTS.md) under "FrameType tags").

The tags are FROZEN by this discipline, each clause backed by a test in `frame.rs`:

- **A tag's meaning never changes.** The exact wire numbers are pinned by
  `type_tags_have_their_exact_frozen_wire_values`, which asserts every tag's literal value
  (`Connect.as_u8() == 1` and so on). A reorder or insertion that shifted a value breaks this
  test, not a deployed peer. The ack op sub-tags (`Ack` = 0, `Nack` = 1, `Term` = 2,
  `Progress` = 3) are pinned the same way by `ackop_tags_have_their_exact_frozen_wire_values`
  in `message.rs`.
- **The mapping is a stable bijection.** `type_tags_are_a_stable_bijection` asserts each tag
  round-trips through `as_u8`/`from_u8` with no duplicates, and that tags 0 and 255 are
  unknown.
- **A new frame takes a new tag.** The set is `#[non_exhaustive]` and append-only by
  convention; the next frame type takes tag 22, leaving every existing tag's meaning intact.
  This is how `PubAck`/`AckStatus`/`FlowEnd` (14 to 16), `DeadLetter`/`Truncated` (17, 18),
  `CumulativeAck` (19), `PubAckDuplicate` (20, the #33 dedup-hit response that keeps the
  frozen `PubAck` body intact), and `GapMarker` (21, the #346 consumer-visible gap marker that
  leaves the `Deliver` body frozen) were added without disturbing earlier verbs.

### Unknown tags are forward-compatible at the envelope level

Because the length prefix is independent of the body codecs, an unknown tag still frames:
`decode_frame` returns the raw `type_tag`, the body, and the consumed length for ANY tag
value. Only `FrameType::from_u8` reports the tag unknown (returns `None`). This is proven by
the proptest `an_unknown_type_tag_still_frames` (tags 22..=255 round-trip through the
envelope; `from_u8` is `None`).

What each peer does with an unknown KNOWN-envelope frame:

- **The client** surfaces it as a typed `ClientError::UnknownFrameType(tag)` rather than
  guessing a known frame (`crates/ironbus-client/src/lib.rs`, `read_frame`; named-tag error
  test asserting `UnknownFrameType(200)`).
- **The server** replies with a generic `Err` ("unknown frame type") for an unrecognized tag,
  and "verb not supported on this connection" for a known-but-response-only verb
  (`crates/ironbus-server/src/session.rs`, `dispatch`). It does not drop the connection on an
  unknown tag.

So an old peer meeting a newer peer's unknown frame fails that one frame loudly with a typed
error; it does not misread it as a known frame.

### max_frame_size is a tightening-only cap, not negotiated

`decode_frame_with_cap(input, max_len)` applies `min(max_len, MAX_FRAME_LEN)`, so a caller
can only TIGHTEN the absolute cap, never raise it (test
`a_negotiated_cap_rejects_a_frame_above_it_but_below_the_absolute_max`). The infrastructure
for a per-connection negotiated maximum exists in the decoder, but the value is not negotiated
on the wire today: the handshake carries no `max_frame_size`. See "Specified but not yet
implemented."

### Unknown record-flag bits travel over the wire unchanged

`PubBody.flags` and `DeliverBody.flags` are a raw `u8` carried verbatim by the body codecs
(`message.rs`); the server maps the producer flags to the stored `RecordFlags`. The
preservation guarantee for unknown flag bits is enforced on the storage side (next section)
and the wire codec does not strip bits, so a flag a newer producer sets is not silently
dropped at the framing layer.

Two exceptions are now DEFINED, both WIRE-ONLY producer-flag bits that the server STRIPS
(`PUB_WIRE_ONLY_FLAGS`) before the byte becomes a stored `RecordFlags` (`Session::handle_pub` masks
them off), and both sitting well above `RecordFlags::KNOWN` (`0b111`) so neither collides with any
storage flag:

- `PubBody.flags` bit 7 (`PUB_FLAG_HAS_DEDUP`, `0b1000_0000`) is the #33 wire-only signal that an
  opt-in dedup block follows the headers. A pre-#33 client that happened to set bit 7 on a no-dedup
  produce has that bit CLEARED in the stored record (and no dedup block is parsed, since the server
  reads bit 7 to decide whether the block is present).
- `PubBody.flags` bit 6 (`PUB_FLAG_FIRE_AND_FORGET`, `0b0100_0000`) is the #11/#402 wire-only QoS-0
  marker: a producer sets it to opt into the fire-and-forget tier (no `PubAck`, droppable under the
  fire-and-forget bucket). It carries no extra block, so it never changes the body layout; the
  default (bit clear) is the unchanged at-least-once `PubAck` path, so an old client is byte-for-byte
  unchanged. It is an ADDITIVE flag only: the `FrameType` tag vocabulary is unchanged (the
  `type_tags_have_their_exact_frozen_wire_values` pin still holds).

### Mixed-version rollout with write-path compression (#430)

Upgrading only the broker flips real compression on by default (`serve --compression` defaults
to `lz4`), and a pre-#430 client receives the descriptor + codec stream bytes verbatim with the
`COMPRESSED` bit set, which is spec-legal but silently different from the produced payload. The
operational rule is therefore: upgrade consumers to a #430+ client FIRST, or run the broker with
`--compression none` during the transition. A client downgrade after compressed data exists
regresses those consumers to the raw stored bytes for every compressed record still retained.

### The Connect/Info handshake bodies are an ADDITIVE, version-prefixed change (#292)

The `Connect` (tag 1) and `Info` (tag 2) bodies were EMPTY before #292; they now carry the
per-consumer credit negotiation. This is an ADDITIVE wire change, NOT a frozen-tag break: the
FrameType tags are unchanged (no renumber, no new tag, the `type_tags_have_their_exact_frozen_wire_values`
pin still holds); only the previously-empty BODY of two existing tags gained a format. The body
layout is in [CONTRACTS.md](CONTRACTS.md) under "ConnectBody / InfoBody"; the rules that ride on it:

- **The body is versioned and length-prefixed for forward compatibility.** It leads with a
  `body_version: u8` (`HANDSHAKE_BODY_VERSION` = 1) and a `field_len: u16` naming the known-field
  block, so a future version can APPEND fields (the #71/#11 `wire_protocol_version` integer and
  capability bitset are the planned ones) without re-breaking: a v1 reader reads its v1 fields from
  the front of the block and TOLERATES any trailing bytes (`handshake_tolerates_trailing_future_fields`
  proptest in `message.rs`). This is the same unknown-trailing-bytes forward-compat discipline
  `RecordFlags` uses for unknown flag bits, applied to a whole appendable body.
- **The empty-body case stays valid in BOTH directions (the backward-compat anchor).** An EMPTY
  `Connect` body (a pre-#292 client) decodes to "no request", so the server uses its defaults exactly
  as before (`empty_connect_body_is_the_old_client_no_request`; the server-side
  `an_empty_connect_uses_the_server_default_credit`). An EMPTY `Info` body (a pre-#292 server)
  decodes to "no advertisement", so a new client keeps its own LOCAL credit
  (`empty_info_body_is_the_old_server_no_advert`; the client-side
  `an_empty_info_from_an_old_server_leaves_the_client_on_its_local_credit`). So an old client meeting
  a new server, and a new client meeting an old server, both still negotiate (or fall back) correctly.
- **The negotiation can only TIGHTEN, never raise, the server cap.** The effective per-consumer
  credit is `min(client request, server cap)`, or the server default when the client requested
  nothing; no unbounded / `request(MAX)` value is representable on the wire (the request is a finite
  `u32`/`u64` or absent). So a hostile or buggy client cannot lift the server's per-consumer ceiling.
- **A malformed handshake body is a typed error, never a panic or over-allocation.** An unknown
  `body_version` is `BodyError::BadHandshakeVersion`; a declared `field_len` past the body is a
  cap-before-alloc `BodyError::Truncated` (the length is bounds-checked against the actual body BEFORE
  any read). The server answers a malformed `Connect` with a typed `Err` and keeps the connection
  open (`a_malformed_connect_body_is_a_typed_error_not_a_panic`); the client surfaces a malformed
  `Info` as `ClientError::Body` (`a_malformed_info_body_is_a_typed_error_not_a_panic`). Both decoders
  are fuzzed (`fuzz/fuzz_targets/connect_body.rs`, `info_body.rs`) and proptested
  (`handshake_oversized_declared_length_is_a_typed_error`).

### The GapMarker frame is per-consumer OPT-IN via the handshake capability (#346)

The `GapMarker` frame (tag 21) is the consumer-visible signal that a half-open offset span `[from,
to)` is PERMANENTLY ABSENT from the DELIVER stream (a trim today, key-compaction #337 tomorrow), so a
consumer tracking contiguity does not mistake the offset jump for message loss. Because the bundled
client REFUSES an unknown frame tag (`ClientError::UnknownFrameType`, the frozen-tag rule above), the
new frame is gated behind a HANDSHAKE CAPABILITY so an old client is never sent a tag it cannot parse:

- **The capability is a single AND-negotiated bit.** A consumer that understands the frame sets
  `Connect` flags bit 2 (`CONNECT_FLAG_WANTS_GAP_MARKER`); the server, which always supports it,
  confirms with `Info` flags bit 2 (`INFO_FLAG_GAP_MARKER`). The capability is ACTIVE only when both
  bits are set. It is a pure flag (no associated value), so it occupies no bytes in the v1 handshake
  block and is appendable exactly like the credit fields above.
- **An old consumer keeps the legacy `Truncated` (tag 18); it is never sent tag 21.** A consumer that
  did not advertise the capability (a pre-#346 client, or one that opted out) gets the same `Truncated`
  advisory for a skipped span it always did, so it is not broken. The server chooses the wire frame
  per-connection from its `gap_marker_enabled` flag, so the two NEVER both fire for the same gap (no
  double-signal). Proven by `a_gap_marker_consumer_gets_a_gap_marker_not_truncated_with_the_exact_range_and_reason`
  (server), `an_old_server_leaves_the_gap_marker_capability_off` and
  `a_gap_marker_capable_client_surfaces_a_gap_as_a_typed_event` (client).
- **The `Deliver` body is UNCHANGED.** The marker is a SEPARATE frame, not a flag or field added to
  `DeliverBody`, so the frozen DELIVER codec and a normal contiguous delivery are byte-for-byte as
  before (`a_normal_contiguous_delivery_emits_no_gap_marker_for_a_gap_marker_consumer`).
- **The `reason` byte is forward-tolerant.** `decode_gap_marker` does not validate the reason, so a
  future reason (`COMPACTED` = 2, or beyond) decodes as a valid marker rather than an error
  (`gap_marker_tolerates_an_unknown_reason`). The decoder is fuzzed
  (`fuzz/fuzz_targets/gap_marker_body.rs`) and proptested (`any_gap_marker_round_trips`).

## On-disk compatibility

The on-disk constants and field offsets live in `crates/ironbus-core/src/format.rs`; the
encode/decode logic that enforces the rules is in `segment.rs` (segment header and footer)
and `codec.rs` (record frame). The byte tables are in [CONTRACTS.md](CONTRACTS.md) under
"On-disk record models" and "On-disk segment models".

### Format identifiers (magic) and version fields

- **Record frame magic** `RECORD_MAGIC` = `0x4942` (the bytes `b'B' b'I'`); the record header
  carries `version: u8` at offset 2 (`header_offsets::VERSION`).
- **Segment magic** `SEGMENT_MAGIC` = `IRONBUS\0` (8 bytes); the 64-byte segment header carries
  `version: u8` and `checksum_algo: u8` at offsets 8 and 9, and the 32-byte sealed footer
  carries the same two fields plus `SEGMENT_FOOTER_MAGIC` = `0x4653` (`b"SF"`), distinct from
  the record magic so a torn tail cannot be mistaken for a footer on a CRC collision alone.

A wrong magic is a typed `BadMagic` (`SegmentError::BadMagic`, `DecodeError::BadMagic`); it is
not best-effort parsed.

### A v1 reader rejects any other version (fail-closed, refuse-and-report)

The rule is exact-match, not "greater-than": a version-1 build reads only version 1 and
refuses anything else loudly rather than guessing a layout it does not know.

- **Segment header and footer:** `SegmentHeader::decode` / `SegmentFooter::decode` return
  `SegmentError::UnsupportedVersion(v)` when the stored byte is not `FORMAT_VERSION`
  (`segment.rs`; test `header_bad_version_and_algo`).
- **Record frame:** `decode` returns `DecodeError::UnsupportedVersion(v)` when the header
  byte is not `FORMAT_VERSION`. The code comment states the intent directly: "a version-1
  reader cannot parse a future layout, so it rejects any other version loudly rather than
  guessing. Intentional; do not relax to `>` without a versioned layout" (`codec.rs`).
- **Cursor checkpoint snapshot:** `AckCursor::decode_snapshot` rejects any byte other than
  `SNAPSHOT_VERSION` (= 1) with `SnapshotError::UnsupportedVersion(v)` (`cursor.rs`; test
  `decode_snapshot` rejects `SNAPSHOT_VERSION + 1`). The checkpoint is versioned separately
  from the record/segment format.

### A v1 reader rejects an unknown checksum algorithm

`CHECKSUM_ALGO_CRC32C` = `0x1` identifies CRC32C (Castagnoli) in the segment header and
footer. A v1 reader requires exactly this value: `SegmentHeader::decode` /
`SegmentFooter::decode` return `SegmentError::UnsupportedChecksumAlgo(a)` for any other byte
(`segment.rs`; the `header_bad_version_and_algo` test injects algo `9` and asserts the typed
error). This is a hard refuse, consistent with the version rule above: an old binary never
best-effort parses a body under a checksum scheme it does not implement.

### Unknown flag bits are preserved (known-version, unknown-optional-field)

Distinct from an unknown VERSION (a hard refuse), an unknown FLAG BIT within a known version
is tolerated and preserved. This is the forward-compatibility seam that lets a future writer
add a record flag without an older reader corrupting it.

- `RecordFlags` (`crates/ironbus-core/src/types.rs`) defines `KNOWN` = `COMPRESSED | HAS_KEY
  | HAS_XXH3` (= `0b111`). `unknown_bits()` returns the set bits outside that mask, and the
  raw byte is kept verbatim by `from_bits` / `bits`.
- `codec::decode` reads `flags` from the CRC-protected header byte and carries it through
  unchanged; the `roundtrip` proptest in `codec.rs` sets a high bit (`0b0100_0000`),
  round-trips a record through encode/decode, and asserts `unknown_bits()` reports exactly
  that bit while the known bits still decode correctly. The unit test
  `flags_unknown_bits_detected_and_preserved` pins the same property at the type level.
- The 16-bit `flags` field in the segment header is likewise "preserved on read but not
  interpreted, so a future writer can add flags without older readers corrupting them"
  (`SegmentHeader` doc comment, `segment.rs`; the round-trip proptest carries an arbitrary
  `u16` flags value).

The segment header's reserved bytes `[44, 60)` and the footer's reserved bytes `[24, 28)`
(both zero in v1, both inside the CRC range) give a future version space to add fields.

### The optional xxh3-64 field is signalled, not version-gated

A record whose stored body reaches `XXH3_PAYLOAD_THRESHOLD` (64 KiB) carries a second
independent xxh3-64 checksum in an 8-byte field before the trailer, signalled by the
`HAS_XXH3` flag bit (`format.rs`, `codec.rs`). A record below the threshold has the exact
byte-for-byte layout it had before the field existed, so older-shaped records parse
unchanged. `HAS_XXH3` is derived by the codec from the body size, never taken from the caller,
and decode cross-checks the flag against the actual body size, so the flag and the field's
presence cannot disagree.

### Append-only, never-recycle segments (ADR 0002)

In v1 a segment id is never recycled: a new segment always takes a fresh id strictly greater
than any id ever used, across rolls and restarts, so deleting an old segment leaves a hole at
the bottom rather than freeing its id. This is required because the optional at-rest AEAD
nonce (#18) derives from the segment id, and reusing an id under a fixed key would reuse a
nonce. The rule is pinned by the storage test
`segment_ids_increase_monotonically_and_are_never_recycled` in
`crates/ironbus-storage/src/log.rs` and recorded in
[ADR 0002](adr/0002-segments-never-recycled-in-v1.md).

### Recovery tolerates a reaped prefix (non-zero start, shorter contiguous chain)

The recovery chain walk validates that each segment CONTINUES its predecessor, but it does
NOT require the chain to start at offset 0. In `Log::scan_recover_chain`
(`crates/ironbus-storage/src/log.rs`) the base-continuity check is guarded by `i > 0`, so the
FIRST surviving segment may have any `base_offset`/`base_seq`; the running expectation is
seeded from that first segment, and only later segments must match the predecessor. So a log
whose oldest segments were reaped (by retention or by the disk-full drop-oldest policy) still
recovers from its shorter contiguous tail. The test
`after_a_reap_a_reopen_recovers_the_remaining_contiguous_chain` reopens a reaped directory and
asserts recovery, and `earliest_offset_starts_at_zero_and_rises_after_a_reap` confirms the
earliest retained offset rises past zero. A genuine GAP between two surviving segments is
still rejected as `SegmentChainBroken` (test `rejects_a_segment_chain_with_a_base_gap`), and a
non-final unsealed segment is `UnsealedPredecessor`.

Recovery is also tolerant of a torn or partially written tail (it truncates to the
longest valid prefix) within the bounded-loss caps; that lifecycle is documented in
[WAL.md](WAL.md) and is out of scope here.

## Version registry and policy

Issues #126 (SemVer, MSRV, and the format-version registry policy) and #132 (the meta
compatibility policy) specify a single registry and a set of CI gates. The state today:

| Item | Specified by | State in code |
|------|--------------|---------------|
| MSRV pinned to Rust 1.78 | #126 | RATIFIED. `rust-version = "1.78"` in `Cargo.toml`; the `msrv (1.78)` CI job builds the workspace on `1.78.0`. |
| MSRV bump rule (minor-only, six-month-old floor, changelog note) | #126 | DOCUMENTED in the README; not separately CI-asserted. |
| SemVer / 0.x promise (formats versioned independently of the API) | #126, #132 | PARTIAL. The pre-release status is stated (CHANGELOG, `0.0.0`); the on-disk format is a single versioned byte; the wire has no separate version integer yet. |
| `storage_format_version` is a single versioned integer | #126 | IMPLEMENTED as `FORMAT_VERSION` (= 1), stamped in the record and segment headers/footer. |
| `wire_protocol_version` negotiated in the handshake | #126, #132 | PARTIAL. The Connect/Info handshake bodies are NO LONGER empty: they carry the #292 per-consumer CREDIT negotiation in a versioned, length-prefixed, forward-compatible body, and the credit is negotiated `min(client request, server cap)`. A separate `wire_protocol_version` INTEGER is still NOT on the wire; the body's `body_version` byte plus its appendable field block are the seam it slots into. |
| `docs/compat/versions.md` registry with a row per version | #126, #132 | PRESENT. [`docs/compat/versions.md`](compat/versions.md) holds the version table, the refuse/poison/negotiate classification table, and the wire-negotiation spec; one row per versioned id-space, each cited to its code symbol. |
| CI gate: an encoding change must touch the registry | #126, #132 | PRESENT. `scripts/check-format-registry.sh` (the `format-registry` CI job) hashes the layout `pub const`s in `format.rs` and fails unless the digest pinned in `docs/compat/versions.md` matches, so an encoding change cannot land without updating the registry. |
| CI gate: no duplicate version integer across branches | #132 | MECHANICAL via the registry. The `FORMAT_VERSION` value lives on one line in `format.rs` and one row in the registry, so two branches bumping to the same next integer collide as a git MERGE CONFLICT on the second merge (the "turn a collision into a git conflict" mechanism); there is no separate cross-branch CI scanner. |
| `migrate` subcommand for a format bump | #132 (#17) | IMPLEMENTED as a GATE. `ironbus migrate --data-dir <dir>` reads the data dir's stamped on-disk format version: within the current major it reports "no migration needed" (the dir opens with no migration); a stamped version that differs from this build's is REFUSED unless `--allow <to-version>` is passed, so a format bump is never silent. No in-place migrator across majors exists yet (refusing is honest, not faked). See `crates/ironbus-cli/src/main.rs` `cmd_migrate` and `crates/ironbus-cli/tests/upgrade_migrate.rs`. |

The append-only id sub-registries that #132 wants centrally allocated (checksum_algo, codec
id, dict_id, header key_id, NACK disposition, reason codes) are, in the shipped code, each a
small enum with its values pinned in tests. Their unknown-value classes match the policy
intent: an unknown `checksum_algo` or `version` is a hard refuse (above); an unknown ack op
(`AckOp::from_u8`) is a typed `BadAckOp`; the `ReasonCode` numeric codes are frozen in
`ironbus_storage::loss`. The single central registry table that #132 asks for (mapping each id
space to refuse / poison / negotiate, owner issue, and append-only) now lives in
[`docs/compat/versions.md`](compat/versions.md); the per-enum tests remain the runtime
enforcement, and the registry is the allocation document on top of them.

## Specified but not yet implemented

These compatibility features are specified by #132 / #126 (or the README/diagrams) but are
verifiably ABSENT from the code today. They MUST NOT be assumed present.

- **Capability and version negotiation in Connect/Info (PARTIAL).** The handshake bodies now
  carry the #292 per-consumer CREDIT negotiation (`session.rs` `handle_connect`,
  `client/lib.rs` `connect_with` sends a `ConnectBody` and parses the `InfoBody`), so the
  handshake is no longer empty and the per-consumer credit is negotiated `min(client request,
  server cap)`. What is STILL absent: a `wire_protocol_version` integer, `max_frame_size`,
  `auth_method`/`auth_blob`, `stream_id`, and a capability bitset. The body is designed to carry
  them as appended fields (its `body_version` byte and `field_len`-delimited block tolerate
  unknown trailing bytes), so the `min(client, server)` version pick, the capability list, and
  capability-gated behavior remain future work that slots into this body without a re-break.
- **A negotiated per-connection `max_frame_size`.** The decoder supports a tightening cap
  (`decode_frame_with_cap`), but no value is negotiated; every connection uses the absolute
  `MAX_FRAME_LEN`. (It would be a future field of the #292 handshake body.)
- **A separate `wire_protocol_version` integer on the wire.** The wire is versioned by the frozen
  tag set and fixed body layouts, plus (since #292) the handshake body's own `body_version` byte; a
  separate `wire_protocol_version` INTEGER negotiated `min(client, server)` is still not on the wire.
  The negotiation is SPECIFIED in [`docs/compat/versions.md`](compat/versions.md) (the architecture
  deliverable); the #292 versioned handshake body is now the carrier it appends a field to, and the
  remaining wiring is the residual owned by #11/#71.
- **A multi-version on-disk MIGRATION path (the migrator itself).** The `ironbus migrate` verb now
  exists as a GATE (it detects a differing on-disk format version and refuses a silent bump, see the
  registry table above), but there is still no code that REWRITES v1 bytes into a future layout: a v1
  reader refuses any other version outright, and a real cross-major migrator is future work. `migrate`
  makes the bump explicit and fail-closed; it does not yet perform an in-place conversion.
- **At-rest encryption (the consumer of the never-recycle id rule).** ADR 0002 exists because
  of the at-rest AEAD nonce (#18), but at-rest encryption itself is not implemented (see
  [THREAT_MODEL.md](THREAT_MODEL.md)); the never-recycle rule is enforced today regardless, as
  forward-protection.

## Discrepancies with the #132 intent

Where the implementation diverges from the #132 / #126 specification:

- **A partial wire-negotiation surface (credit wired, version integer not).** #132 mandates a
  handshake that "picks `min(client, server)` wire_protocol_version" and a server that "never
  speaks a version it did not advertise in INFO." That rule is fully SPECIFIED in
  [`docs/compat/versions.md`](compat/versions.md). The code now HAS a handshake PAYLOAD: the #292
  per-consumer credit negotiation rides a versioned, length-prefixed `Connect`/`Info` body and
  negotiates the credit `min(client request, server cap)`. What is still missing is the
  `wire_protocol_version` INTEGER itself and the `min(client, server)` version pick; the #292 body
  is the carrier those fields append to (its `body_version` byte and appendable block), so the
  remaining wiring is the residual owned by #11/#71. Forward compatibility on the wire rests on the
  frozen append-only tag set, typed unknown-tag handling, AND the new tolerant-trailing-bytes
  handshake body.
- **The central registry and the encoding-change CI gate now exist; the duplicate-integer
  check is conflict-based, not a scanner.** #126 / #132 require a single
  `docs/compat/versions.md` with a row per version, CI that fails an encoding change without a
  registry update, and a no-duplicate-integer guard. The registry and the encoding-change gate
  are present ([`docs/compat/versions.md`](compat/versions.md) plus the `format-registry` CI
  job hashing the `format.rs` layout consts against a pinned digest). The duplicate-integer
  guard is the "turn a collision into a git conflict" mechanism, not a separate cross-branch
  scanner: two branches bumping `FORMAT_VERSION` to the same integer conflict on the one line in
  `format.rs` and the one registry row. The frozen-layout tests (`frozen_sizes`, `frozen_values`,
  the offset tests in `format.rs`, the per-codec round-trips) remain the runtime enforcement
  that also breaks a silent CHANGE.
- **The classification table now exists; the sub-registries are still local enums underneath.**
  #132 wants checksum_algo, codec/dict ids, key_id, NACK disposition, and reason codes
  "centrally allocated here" with a per-id-space refuse / poison / negotiate classification. That
  single table now lives in [`docs/compat/versions.md`](compat/versions.md). The runtime
  enforcement is still a local pinned enum per id-space with the correct unknown-value behavior
  (hard refuse for checksum_algo/version, typed error for an unknown ack op). The codec/dict id
  spaces are now IMPLEMENTED for the default `lz4` path (#387): `ironbus_core::compress` carries the
  self-describing descriptor (codec id, `dict_id`, `uncompressed_len`), an unknown codec id or an
  unresolved `dict_id` is the POISON-on-unknown action the registry specified (routed to #8 via
  `ReasonCode::for_decompress_error`, never a crash), and the opt-in `zstd` codec plus ZDICT training
  stay deferred per ADR-0003.
- **`migrate` gates but does not yet convert.** #132 (via #17) requires that any format bump ship a
  `migrate` subcommand and a downgrade-safety statement. The subcommand now EXISTS and gates the bump
  (a differing on-disk version is refused unless explicitly allowed, never applied silently), and the
  policy is documented in `docs/DISTRIBUTION.md`. What is still missing is the actual byte-rewriting
  migrator across majors and a formal downgrade-safety statement; today the cross-major behavior is
  refuse-on-unknown plus the explicit `migrate` gate.

Accuracy note: every "implemented" claim above is tied to a named constant, function, or test
in the cited file. The handshake now carries a wire PAYLOAD (the #292 per-consumer credit
negotiation, `ConnectBody`/`InfoBody` in `message.rs`), so the credit half of the negotiation
surface is implemented and cited; the `wire_protocol_version` integer and the remaining capability
fields are still absent and are listed as such. The migration items are listed as absent because no
in-place migrator was found in the source; if any of these lands later, this document should move
the item from the "absent" list to the enforced rules with a citation.
