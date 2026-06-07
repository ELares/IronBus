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
  layouts. There is no separately negotiated wire-version integer on the wire yet (see the
  discrepancies); the Connect/Info handshake carries no version field.

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

The wire verb is a one-byte tag. The frozen set runs from `Connect` = 1 through `Truncated`
= 18, contiguous (`FrameType::as_u8` / `from_u8` in `frame.rs`; the full table is in
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
  convention; the next frame type takes tag 19, leaving every existing tag's meaning intact.
  This is how `PubAck`/`AckStatus`/`FlowEnd` (14 to 16) and `DeadLetter`/`Truncated` (17, 18)
  were added without disturbing earlier verbs.

### Unknown tags are forward-compatible at the envelope level

Because the length prefix is independent of the body codecs, an unknown tag still frames:
`decode_frame` returns the raw `type_tag`, the body, and the consumed length for ANY tag
value. Only `FrameType::from_u8` reports the tag unknown (returns `None`). This is proven by
the proptest `an_unknown_type_tag_still_frames` (tags 19..=255 round-trip through the
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
| `wire_protocol_version` negotiated in the handshake | #126, #132 | NOT IMPLEMENTED. The Connect/Info handshake bodies are empty; there is no wire-version field. |
| `docs/compat/versions.md` registry with a row per version | #126, #132 | NOT PRESENT. No registry file exists. |
| CI gate: an encoding change must touch the registry | #126, #132 | NOT PRESENT. No header-diff or registry-row CI check exists. |
| CI gate: no duplicate version integer across branches | #132 | NOT PRESENT. |
| `migrate` subcommand for a format bump | #132 (#17) | NOT IMPLEMENTED. The CLI has no `migrate` verb. |

The append-only id sub-registries that #132 wants centrally allocated (checksum_algo, codec
id, dict_id, header key_id, NACK disposition, reason codes) are, in the shipped code, each a
small enum with its values pinned in tests rather than a single registry document. Their
unknown-value classes match the policy intent: an unknown `checksum_algo` or `version` is a
hard refuse (above); an unknown ack op (`AckOp::from_u8`) is a typed `BadAckOp`; the
`ReasonCode` numeric codes are frozen in `ironbus_storage::loss`. The single central registry
table that #132 asks for (mapping each id space to refuse / poison / negotiate, owner issue,
and append-only) does not exist as a file.

## Specified but not yet implemented

These compatibility features are specified by #132 / #126 (or the README/diagrams) but are
verifiably ABSENT from the code today. They MUST NOT be assumed present.

- **Capability and version negotiation in Connect/Info.** The handshake carries no
  negotiated state: the client sends `Connect` with an empty body and the server replies
  `Info` with an empty body (`session.rs` `dispatch`, comment "the handshake carries no
  negotiated state yet"; `client/lib.rs` `connect_with` sends `&[]` and accepts `Info`). No
  `wire_protocol_version`, `max_frame_size`, `auth_method`/`auth_blob`, `stream_id`, or
  capability flags cross the wire. A `min(client, server)` version pick, an INFO capability
  list, and capability-gated optional behavior are all future work (the server module header
  notes "capability negotiation [is a] follow-up"; CONTRACTS.md lists the same draft fields as
  unimplemented).
- **A negotiated per-connection `max_frame_size`.** The decoder supports a tightening cap
  (`decode_frame_with_cap`), but no value is negotiated; every connection uses the absolute
  `MAX_FRAME_LEN`.
- **A separate `wire_protocol_version` integer.** The wire is versioned only implicitly by the
  frozen tag set and fixed body layouts; there is no version byte to negotiate down or reject.
- **The `docs/compat/versions.md` registry and its CI gates.** No registry file, no
  header-diff-requires-a-row check, no duplicate-integer check.
- **A multi-version on-disk migration path / `migrate` subcommand.** There is no upgrade path
  between format versions: a v1 reader refuses any other version outright (above), and there
  is no `migrate` CLI verb or downgrade-safety statement. A format bump today would require a
  new reader, not an in-place migration.
- **At-rest encryption (the consumer of the never-recycle id rule).** ADR 0002 exists because
  of the at-rest AEAD nonce (#18), but at-rest encryption itself is not implemented (see
  [THREAT_MODEL.md](THREAT_MODEL.md)); the never-recycle rule is enforced today regardless, as
  forward-protection.

## Discrepancies with the #132 intent

Where the implementation diverges from the #132 / #126 specification:

- **No wire-version negotiation surface.** #132 mandates a handshake that "picks
  `min(client, server)` wire_protocol_version" and a server that "never speaks a version it
  did not advertise in INFO." The code has neither a wire-version integer nor any handshake
  payload, so this rule is unenforceable today. Forward compatibility on the wire rests
  entirely on the frozen append-only tag set plus typed unknown-tag handling, not on
  negotiation.
- **No central registry, no registry CI gates.** #126 / #132 require a single
  `docs/compat/versions.md` with a row per version and CI that fails an encoding change
  without a matching bump and registry row, and fails a duplicate integer. None of this
  exists. The "turn a collision into a git conflict" mechanism the issues rely on is not in
  place; today the protection against a silent format change is the frozen-layout tests
  (`frozen_sizes`, `frozen_values`, the offset tests in `format.rs`, and the per-codec
  round-trip tests), which break a CHANGE but do not enforce a registry row.
- **Sub-registries are local enums, not one allocated table.** #132 wants checksum_algo,
  codec/dict ids, key_id, NACK disposition, and reason codes "centrally allocated here" with a
  per-id-space refuse / poison / negotiate classification. The code implements each as a local
  pinned enum with the correct unknown-value behavior (hard refuse for checksum_algo/version,
  typed error for an unknown ack op), but there is no single table that classifies them, and
  the codec/dict id spaces are not present at all (on-disk compression is not yet implemented;
  the stored codec is always "none").
- **No `migrate` subcommand.** #132 (via #17) requires that any format bump within a major
  version ship a `migrate` subcommand and a downgrade-safety statement. Neither exists; the
  only cross-version behavior is refuse-on-unknown.

Accuracy note: every "implemented" claim above is tied to a named constant, function, or test
in the cited file. The negotiation and migration items are listed as absent because no wire
payload, registry file, or `migrate` verb was found in the source; if any of these lands
later, this document should move the item from the "absent" list to the enforced rules with a
citation.
