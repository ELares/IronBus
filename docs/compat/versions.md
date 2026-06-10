<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Version registry

The single source of truth for every versioned id-space in IronBus: the on-disk format
versions, the wire protocol version, the loss-report schema version, and the append-only
id sub-registries (frame tags, reason codes, record flags, checksum algorithms, and the
reserved codec/dict id spaces). It is the file a header-format change MUST touch, and a CI
gate enforces that (see [The CI registry gate](#the-ci-registry-gate)).

This registry is the allocation discipline that #126 and #132 specify. It does NOT restate
the byte tables (those live in [CONTRACTS.md](../CONTRACTS.md)) and it does NOT restate the
compatibility rules and their code citations (those live in
[COMPATIBILITY.md](../COMPATIBILITY.md)). It is consistent with both: where a rule appears
in both files, COMPATIBILITY.md is the prose authority and this file is the allocation
table. Every value below is cited to a code symbol so the registry and the source cannot
silently drift.

This is the implementation reality at the pre-release version `0.0.0`. Where a row marks a
mechanism as NOT YET WIRED (the wire-protocol version is the only one), it is the
architecture deliverable here and the implementation residual is owned by the cited issue;
it is never asserted as present. COMPATIBILITY.md is the matching honest discrepancy list.

## The version table

One row per versioned id-space and its current value(s). "Defined in" cites the code symbol
that holds the value; "Bump rule" is append-only (a new id is appended, old ids never change)
or breaking (a new value means a new layout that an old reader fail-closed refuses).

| Id-space | Current value(s) | Defined in (code symbol) | Bump rule | Owner |
|----------|------------------|--------------------------|-----------|-------|
| Storage `FORMAT_VERSION` | `1` | `ironbus_core::format::FORMAT_VERSION` | Breaking. A new layout takes a new integer; a v1 reader refuses any other value. | #126, #5 |
| Record header version | `1` (= `FORMAT_VERSION`) | `format::header_offsets::VERSION` (offset 2), checked in `ironbus_core::codec::decode` | Breaking. Same integer as `FORMAT_VERSION`; stamped per record. | #5 |
| Segment header version | `1` (= `FORMAT_VERSION`) | `format::segment_header_offsets::VERSION` (offset 8), checked in `ironbus_core::segment::SegmentHeader::decode` | Breaking. Same integer as `FORMAT_VERSION`; stamped per segment. | #4, #5 |
| Segment footer version | `1` (= `FORMAT_VERSION`) | `format::segment_footer_offsets::VERSION` (offset 2), checked in `ironbus_core::segment::SegmentFooter::decode` | Breaking. Same integer as `FORMAT_VERSION`; stamped per sealed segment. | #4, #5 |
| Cursor checkpoint snapshot version | `1` | `ironbus_core::cursor` `SNAPSHOT_VERSION`, checked in `AckCursor::decode_snapshot` | Breaking. Versioned SEPARATELY from `FORMAT_VERSION`; a v1 reader refuses any other value. | #7 |
| Wire protocol version | `1` (specified; the version INTEGER is NOT YET ON THE WIRE) | specified as the `wire_protocol_version` handshake field; the `Connect`/`Info` bodies are now NON-empty (they carry the #292 credit negotiation) but carry no version integer yet (`ironbus_server::session` `handle_connect`) | Negotiate (`min(client, server)`); see [Wire-version negotiation](#wire-version-negotiation). The #292 versioned handshake body is the carrier; the integer field's wiring is owned by #11/#71. | #126, #132, #11 |
| Handshake body version (`Connect`/`Info`) | `1` | `ironbus_proto::message::HANDSHAKE_BODY_VERSION`; round-tripped by `any_connect_round_trips`/`any_info_round_trips`, rejected-on-unknown by `handshake_rejects_an_unknown_body_version` | Append-only WITHIN a version (a new optional field is appended after the v1 block and tolerated by an old reader, `handshake_tolerates_trailing_future_fields`); a field reinterpretation takes a new `body_version`. The EMPTY body stays valid (an old peer). This is the #292 carrier the `wire_protocol_version` integer + capability bitset append to. | #292, #11, #71 |
| Loss-report `schema_version` | `1` | `ironbus_storage::loss` `LossReport::SCHEMA_VERSION`; frozen by `golden_loss_report_v1_serialization_is_frozen` | Append-only within v1 (a new field or reason does not bump it); a field rename/removal/reorder takes a new version. | #120, #21 |
| CLI `--json` schema `ironbus.cli.scrub.vN` | `1` | `ironbus-cli` `SCRUB_SCHEMA_VERSION`; emitted by `write_plan_json`; pinned by `scrub_json_carries_the_versioned_schema_and_exit_code` | Append-only: a new OPTIONAL field does not bump `N`; a field rename/removal/type-change bumps `N` (gated by SemVer, cannot ride a patch). Per [CLI_CONTRACT.md](../CLI_CONTRACT.md) §1.5. | #136, #92 |
| CLI `--json` schema `ironbus.cli.repair.vN` | `1` | `ironbus-cli` `REPAIR_SCHEMA_VERSION`; emitted by `write_plan_json` | Append-only (same rule as the scrub schema; carries the additional `applied` field). | #136, #92 |
| CLI `--json` schema `ironbus.cli.admin-consumer-reset.vN` | `1` | `ironbus-cli` `ADMIN_CONSUMER_RESET_SCHEMA_VERSION`; emitted by `write_consumer_reset_result`; pinned by `admin_consumer_reset_rewrites_the_cursor_and_emits_the_versioned_json` | Append-only: a new OPTIONAL field does not bump `N`; a rename/removal/type-change bumps `N` (gated by SemVer). Per [CLI_CONTRACT.md](../CLI_CONTRACT.md) §1.5. | #136, #299 |
| CLI `--json` schema `ironbus.cli.admin-dlq-redrive.vN` | `1` | `ironbus-cli` `ADMIN_DLQ_REDRIVE_SCHEMA_VERSION`; emitted by `write_dlq_redrive_result`; pinned by `admin_dlq_redrive_re_injects_and_is_idempotent` | Append-only (same rule as the consumer-reset schema). | #136, #299 |
| `FrameType` tag set | `1..=21`, contiguous (`Connect`=1 .. `CumulativeAck`=19, `PubAckDuplicate`=20, `GapMarker`=21) | `ironbus_proto::frame::FrameType::as_u8`/`from_u8`; frozen by `type_tags_have_their_exact_frozen_wire_values` | Append-only. The next frame takes tag 22; no existing tag's meaning ever changes. | #11, #33, #346 |
| `GapMarker` reason vocabulary | `1` = `TRIMMED`, `2` = `COMPACTED` (both EMITTED: `TRIMMED` on a below-earliest reap, `COMPACTED` since #411 when a gap-marker-capable consumer reads across a mid-stream compacted hole) | `ironbus_proto::message::gap_reason` (`TRIMMED`/`COMPACTED`); round-tripped by `any_gap_marker_round_trips`, unknown-tolerant per `gap_marker_tolerates_an_unknown_reason`; `COMPACTED` emission pinned by `a_gap_marker_consumer_reading_across_a_compacted_hole_gets_one_compacted_marker` | Append-only and TOLERATED on unknown (a reader decodes an unknown reason verbatim as "absent for an unspecified reason", never an error), so the reason field grows without a new frame. The #411 emission added NO wire change: it only emits the already-defined `COMPACTED` reason. | #346, #337, #59, #411 |
| `Connect`/`Info` capability bits | `Connect` bit 2 (`CONNECT_FLAG_WANTS_GAP_MARKER`), `Info` bit 2 (`INFO_FLAG_GAP_MARKER`) | `ironbus_proto::message::{CONNECT_FLAG_WANTS_GAP_MARKER, INFO_FLAG_GAP_MARKER}`; round-tripped by `connect_carries_the_gap_marker_capability_bit` / `info_carries_the_gap_marker_capability_bit` | Append-only within the v1 handshake block: a new capability claims a higher flag bit (no new field bytes); an old peer leaves it clear and the feature falls back. The negotiation is AND (active iff both peers set their bit). | #346, #292, #11 |
| Storage compaction format `FORMAT_VERSION_COMPACTED` | `2` (only on a COMPACTED segment) | `ironbus_core::format::FORMAT_VERSION_COMPACTED`, checked in `ironbus_core::segment::SegmentHeader::decode` (paired with the `SEGMENT_FLAG_COMPACTED` flag); the fail-closed refusal in `SegmentHeader::decode_v1_only` | Breaking-on-the-new-shape. A compacted segment stamps `version = 2`; a v1-only reader REFUSES it. A log that has never been compacted is byte-identical v1, so the bump is invisible to it. | #337, #126 |
| `SegmentHeader.flags` `SEGMENT_FLAG_COMPACTED` bit | bit 0 (`0x0001`) | `ironbus_core::format::SEGMENT_FLAG_COMPACTED`; pinned by `frozen_compaction_v2_values_and_offsets` | Append-only segment-flag bit. Distinct from the at-rest encryption bit; a compacted segment sets it and stamps `version = 2`. A v1 reader treats `flags` as preserved-but-not-interpreted; the paired `version = 2` is what makes it fail closed. | #337, #18 |
| v2 compaction-metadata block | 44 bytes (`COMPACTION_META_LEN`): `covered_base_offset`/`covered_end_offset`/`covered_base_seq`/`covered_end_seq`/`highest_covered_source_id` (5 × u64) + `block_crc` (u32 over `[0,40)`) | `ironbus_core::format::{COMPACTION_META_LEN, compaction_meta_offsets, COMPACTION_META_CRC_RANGE}` and `ironbus_core::segment::CompactionMeta`; round-tripped by `compaction_meta_round_trips_and_rejects_corruption` | Additive on a `version = 2` segment ONLY: written after the footer as the file's final bytes, CRC-protected on its own so a torn block is rejected like a torn footer. Absent on any v1 segment. | #337 |
| `PubBody` dedup opt-in (`PUB_FLAG_HAS_DEDUP`) | flags bit 7 (`0b1000_0000`); when set, a `producer_id` (u16-var), `epoch` (u64), `msg_id` (u16-var) block follows the headers, before the payload | `ironbus_proto::message::PUB_FLAG_HAS_DEDUP` and `PubDedup`; round-tripped by `any_pub_with_dedup_round_trips` | Append-only and OPT-IN. A dedup-disabled produce leaves the bit clear and omits the block, so the body is byte-for-byte the pre-#33 layout. The bit is a WIRE signal, masked off before the byte becomes a stored record flag, so it never collides with a future `RecordFlags` bit. | #33, #3 |
| `PubBody` fire-and-forget (QoS-0) opt-in (`PUB_FLAG_FIRE_AND_FORGET`) | flags bit 6 (`0b0100_0000`); a boolean marker in the SAME flags byte (no extra block, layout unchanged) | `ironbus_proto::message::PUB_FLAG_FIRE_AND_FORGET` (masked with `PUB_FLAG_HAS_DEDUP` as `PUB_WIRE_ONLY_FLAGS`); round-tripped by `a_fire_and_forget_pub_sets_the_wire_bit_and_round_trips` and `fire_and_forget_and_dedup_compose_in_the_one_flags_byte` | Append-only and OPT-IN (#11, #402). The client sets it to skip the `PubAck` (the broker may drop the produce under the fire-and-forget bucket, or append it durably with no ack). A clear bit (the default) is the unchanged at-least-once path, byte-for-byte. A WIRE signal, masked off before the byte becomes a stored record flag, distinct from bit 7, so it never collides with a `RecordFlags` bit. The `FrameType` tag vocabulary is UNCHANGED. | #11, #402 |
| `AckOp` sub-tag set | `0..=3` (`Ack`=0, `Nack`=1, `Term`=2, `Progress`=3) | `ironbus_proto::message::AckOp::as_u8`/`from_u8`; frozen by `ackop_tags_have_their_exact_frozen_wire_values` | Append-only. The next op takes tag 4. | #9, #11 |
| `ReasonCode` vocabulary | codes `1..=7` (`TornTail`=1 .. `ScrubberSuspect`=6, `UnresolvedDictId`=7) | `ironbus_storage::loss::ReasonCode::code`; frozen by `golden_reason_code_vocabulary_is_frozen` and `reason_codes_are_stable_and_distinct` | Append-only. A new reason gets a new code/name/label and does NOT bump `schema_version`. | #11, #59, #357 |
| `RecordFlags` bits | `KNOWN` = `0b111` (`COMPRESSED`=bit0, `HAS_KEY`=bit1, `HAS_XXH3`=bit2) | `ironbus_core::types::RecordFlags` (`COMPRESSED`/`HAS_KEY`/`HAS_XXH3`/`KNOWN`) | Append-only. A new flag claims a higher bit; unknown bits are preserved, never interpreted, within a known version. | #5, #12 |
| `checksum_algo` | `CRC32C` = `0x1` | `ironbus_core::format::CHECKSUM_ALGO_CRC32C`; checked in `SegmentHeader::decode`/`SegmentFooter::decode` | Append-only. A new algo takes a new byte; a v1 reader refuses any unknown value. | #5 |
| `codec` id | `none` = `0`, `lz4` = `1` (implemented, pure-Rust default); `zstd` = `2` (implemented behind the OPT-IN `zstd` feature, NOT on the default build) | `ironbus_core::compress::Codec` (`CODEC_ID_NONE`/`CODEC_ID_LZ4`/`CODEC_ID_ZSTD`), carried in the compressed-payload descriptor behind `RecordFlags::COMPRESSED`; see [CONTRACTS.md](../CONTRACTS.md#compressed-payload-descriptor-when-compressed-is-set), [DICTIONARY_LIFECYCLE.md](../DICTIONARY_LIFECYCLE.md), and [ADR 0003](../adr/0003-default-compression-lz4-zstd-opt-in.md) | Append-only. New codec ids are appended; `lz4` (#387) is the pure-Rust default; `zstd` (#357) is implemented behind the opt-in feature, so a record with codec id 2 is UNKNOWN-codec POISON on a default (non-zstd) build, never a crash. Rollout coupling (#438): the broker's produce-time descriptor gate rejects a wire PUB naming an id outside this registry, so registering a future codec id requires brokers to learn it BEFORE producers emit it (upgrade brokers first, then producers). | #12, #387, #357, #438 |
| `dict_id` | `0` = no-dictionary sentinel (the only value the default `lz4` build writes); the `u32` field is carried per record | `u32` in the compressed-payload descriptor (`ironbus_core::compress`); content-addressed (`truncate_u32(BLAKE3-256(bytes))`) per [DICTIONARY_LIFECYCLE.md](../DICTIONARY_LIFECYCLE.md). The descriptor field, the `UnresolvedDictId` POISON path, ZDICT training (`ironbus_core::dict`), the sidecar IO + resolver (`ironbus_storage::dict_store`), and the `dict train`/`install`/`ls` CLI are all implemented behind the opt-in `zstd` feature (#357) | Append-only (content-addressed; reuse is structurally impossible). | #12, #78, #357 |

Notes on the two id-equal-to-`FORMAT_VERSION` rows: the record/segment/footer version bytes
are deliberately the SAME integer as `FORMAT_VERSION`, not independent counters. They are
listed separately because each is a distinct on-disk field at a distinct offset that a reader
checks independently; a layout bump moves all of them together.

## The classification table

This is the #132 core: every versioned id-space mapped to its compatibility ACTION on an
unknown value. The three actions, consistent with [COMPATIBILITY.md](../COMPATIBILITY.md):

- **REFUSE** (fail closed): a reader that meets an unknown value rejects it with a typed
  error and stops, rather than best-effort parsing a layout or scheme it does not implement.
  This is the old-binary-meets-new-data rule for the durable format.
- **POISON** (bounded #8 quarantine): the framing and checksums are intact but the value
  names a decode input the reader does not have; the reader reports the loss, advances, and
  continues, rather than crashing the process. This is for the per-record decode inputs
  (codec/dict id), NOT for a structural version.
- **NEGOTIATE** (`min(client, server)`): the two peers agree on the lower of their two
  values at handshake time; out of range is rejected, never silently downgraded below a
  floor. This is for the wire protocol version only.

| Id-space | Action on unknown | Append-only | Owner | Enforcing symbol / status |
|----------|-------------------|-------------|-------|---------------------------|
| Storage `FORMAT_VERSION` (record/segment/footer version bytes) | REFUSE | no (breaking) | #126, #5 | `DecodeError::UnsupportedVersion`, `SegmentError::UnsupportedVersion` |
| Cursor checkpoint snapshot version | REFUSE | no (breaking) | #7 | `SnapshotError::UnsupportedVersion` |
| `checksum_algo` | REFUSE | yes | #5 | `SegmentError::UnsupportedChecksumAlgo` |
| `RecordFlags` unknown bits (within a known version) | TOLERATE + PRESERVE | yes | #5, #12 | `RecordFlags::unknown_bits` (kept verbatim, never interpreted) |
| `codec` id (durable path) | POISON | yes | #12, #387 | IMPLEMENTED: `ironbus_core::compress::decompress_payload` returns `PoisonUnknownCodec` for an unknown id; `ReasonCode::for_decompress_error` routes it to #8 (reported loss, advance) as `CorruptRecordBody`, never a crash |
| `dict_id` (durable path) | POISON | yes | #12, #78, #357 | IMPLEMENTED: a non-zero unresolved `dict_id` returns `PoisonUnresolvedDict`, routed to #8 as `ReasonCode::UnresolvedDictId` (reported loss; see DICTIONARY_LIFECYCLE.md §5). ZDICT training + the sidecar resolver land behind the opt-in `zstd` feature (#357) |
| Wire protocol version | NEGOTIATE | n/a | #126, #132, #11 | specified `min(client, server)`; the handshake bodies now carry the #292 credit negotiation, but the version INTEGER's wiring is still owned by #11/#71 |
| Handshake body version (`Connect`/`Info`) | REFUSE an unknown `body_version` (typed, keep the connection); TOLERATE trailing future fields within a known version | yes (append-only fields within a version) | #292, #11 | `BodyError::BadHandshakeVersion` (unknown version is a typed error, the server replies `Err` / the client surfaces `ClientError::Body`, the connection is not silently misread); trailing-bytes tolerance proven by `handshake_tolerates_trailing_future_fields` |
| `FrameType` tag (unknown tag over a known envelope) | REFUSE that frame (typed), keep the connection | yes | #11 | `ClientError::UnknownFrameType` (client); server replies a generic `Err`, does not drop the connection |
| `AckOp` sub-tag | REFUSE that op (typed) | yes | #9, #11 | `AckOp::from_u8` returns the typed `BadAckOp` |
| `ReasonCode` (unknown code on read) | TOLERATE (render the numeric span; unknown name) | yes | #11, #59 | append-only rule: a pre-`ScrubberSuspect` reader still reads a code-6 event's numeric span |
| `GapMarker` reason (unknown reason byte) | TOLERATE (decode the marker verbatim; unknown reason) | yes | #346, #337 | `decode_gap_marker` does not validate the reason; `gap_marker_tolerates_an_unknown_reason` proves an unknown reason round-trips as a valid marker |
| `GapMarker` frame itself (unknown tag to an OLD client) | the OLD client never RECEIVES it: the frame is per-consumer OPT-IN via the `Connect` capability bit, so the server only sends it to a consumer that advertised it understands it | yes | #346, #292 | the server emits `GapMarker` only when `gap_marker_enabled`; an old/non-advertising consumer keeps the legacy `Truncated` (`a_gap_marker_consumer_gets_a_gap_marker_not_truncated_*`, `an_old_server_leaves_the_gap_marker_capability_off`) |
| Loss-report `schema_version` | REFUSE a higher version (a consumer reads only its known schema) | append within a version | #120, #21 | frozen golden tests force a deliberate `schema_version` bump on a breaking change |
| CLI `--json` schemas (`ironbus.cli.scrub.vN`, `ironbus.cli.repair.vN`) | REFUSE a higher `N` than known (a consumer matches the exact `schema` string and fails closed on a higher version), same rule the loss-report `schema_version` follows | yes (a new optional field does not bump `N`) | #136, #92 | `SCRUB_SCHEMA_VERSION` / `REPAIR_SCHEMA_VERSION`; the result object carries the full `ironbus.cli.<command>.vN` discriminator |
| CLI `--json` schemas (`ironbus.cli.admin-consumer-reset.vN`, `ironbus.cli.admin-dlq-redrive.vN`) | REFUSE a higher `N` than known (same exact-`schema`-string rule) | yes (a new optional field does not bump `N`) | #136, #299 | `ADMIN_CONSUMER_RESET_SCHEMA_VERSION` / `ADMIN_DLQ_REDRIVE_SCHEMA_VERSION`; the offline mutating-admin result objects |

The key reconciliation #132 asked for: an unknown **storage `FORMAT_VERSION`** or
**`checksum_algo`** is a hard REFUSE (#5 fail-closed), while an unknown **`codec`** or
**`dict_id`** on the durable path is bounded POISON handed to #8 (reported loss, advance), NOT
a process exit. The difference is structural: a version/checksum byte governs whether the
reader can frame the bytes AT ALL, so guessing risks misreading durable data; a codec/dict id
governs only the decode of an already-framed, already-checksummed record body, so a missing
decode input is a per-record loss, not a corruption of the log. This matches the
"Append-only id sub-registries" and "Resolve the unknown-codec contradiction" scope items of
#132 and does not contradict COMPATIBILITY.md.

## Wire-version negotiation

This is the architecture deliverable for the wire protocol version (#132). It specifies the
handshake; the WIRING of the version INTEGER is the implementation residual owned by #11/#71.
The handshake bodies are NO LONGER empty: since #292 they carry the per-consumer CREDIT
negotiation (`ironbus_server::session` `handle_connect` replies a versioned `InfoBody`;
`ironbus_client` `connect_with` sends a versioned `ConnectBody`), in a `body_version`-prefixed,
`field_len`-delimited body that TOLERATES trailing future fields. That body is the carrier the
`wire_protocol_version` integer and the capability bitset append to; only those fields, not the
body itself, are still unimplemented, so points 1 to 4 below remain a specification while point 5
(and the body-framing seam) is now realized.

Specification:

1. **The integer.** `wire_protocol_version` is an unsigned integer carried in the handshake.
   The first value is `1`. It is versioned independently of the storage `FORMAT_VERSION` and
   of the Rust API: a wire-codec change does not force a re-encode of durable bytes, and a
   durable-format change does not force a wire bump.
2. **The client advertises.** The client's `Connect` body carries the highest
   `wire_protocol_version` it speaks.
3. **The server advertises and picks.** The server's `Info` body carries the highest
   version it speaks. The agreed version is `min(client_version, server_version)`. A server
   NEVER speaks a version it did not advertise in `Info`; capability flags (for example
   `stream_id`, auth methods, a negotiated `max_frame_size`) gate optional behavior on top of
   the agreed version.
4. **Out of range.** If `min(client, server)` is below the server's minimum supported wire
   version (no overlap), the server refuses the connection with a typed handshake error
   rather than silently downgrading below its floor; the client surfaces a typed error so the
   operator upgrades one side. This is the NEGOTIATE-with-a-floor rule, distinct from the
   storage REFUSE: the wire can negotiate DOWN to a common version, but never below the floor.
5. **Frame envelope independence.** Negotiation rides on top of the frozen frame envelope
   (`[len][type][body]`) and the append-only `FrameType` tag set. An unknown tag still frames
   at the envelope level (forward compatibility) and is refused per-frame with a typed error;
   negotiation reduces, but does not replace, the frozen-tag forward-compatibility seam.

Until #11/#71 add the integer, the wire is versioned by the frozen tag set, the fixed body
layouts, AND (since #292) the handshake body's own `body_version` byte; there is no separate
`wire_protocol_version` integer to negotiate yet. The #292 per-consumer credit negotiation is the
first realized handshake-body content and follows the same NEGOTIATE-with-a-floor shape: the
effective per-consumer credit is `min(client request, server cap)`, no unbounded value is
representable, and the negotiated value is advertised in `Info`. See the "Specified but not yet
implemented" and "Discrepancies" sections of [COMPATIBILITY.md](../COMPATIBILITY.md), which state
the same residual.

## Migration and the 0.x promise

- **Format bumps.** Any storage `FORMAT_VERSION` bump within a major version ships through
  the `ironbus migrate` gate (`crates/ironbus-cli` `cmd_migrate`,
  `crates/ironbus-cli/tests/upgrade_migrate.rs`): a differing on-disk version is REFUSED
  unless `--allow <to-version>` is passed, so a bump is never silent. An in-place
  byte-rewriting migrator across majors is future work (#17); today the cross-major behavior
  is refuse-on-unknown plus the explicit `migrate` gate. The downgrade-safety statement and
  the full policy live in [DISTRIBUTION.md](../DISTRIBUTION.md).
- **The 0.x promise.** The workspace is pre-release (`version = "0.0.0"` for every crate), so
  there is no SemVer API-stability promise yet and the Rust API may break on any change. The
  two durable surfaces (storage format and wire protocol) are versioned independently of the
  API and of each other from day one, each by its own integer, and follow the
  refuse/poison/negotiate rules above regardless of the API churn. The MSRV is Rust `1.78`
  (`workspace.package.rust-version`, exercised by the `msrv (1.78)` CI job); it may rise only
  in a minor release and the new floor is always at least six months old (README).

## The CI registry gate

A change to the on-disk byte layout MUST touch this registry. The gate that enforces it is
`scripts/check-format-registry.sh`, run by the `format-registry (#126 #132)` job in
`.github/workflows/ci.yml`.

Mechanism (deterministic, host-independent, no git history required): the script extracts
every `pub const ...` layout/offset declaration from `crates/ironbus-core/src/format.rs`
(before the `#[cfg(test)]` block, so test edits never trip it; leading/trailing whitespace
normalized, so reindentation never trips it; duplicate offset lines across the header and
footer modules kept, so dropping a module changes the digest), computes the sha256 of the
normalized lines, and compares it to the digest pinned below. A layout change shifts the
computed digest and fails the job until both `format.rs` and this registry are updated in the
same commit. A pure git-diff approach was rejected because the diff base is unreliable across
CI fetch depths; the pinned-digest approach needs no history.

When you INTENTIONALLY change the layout: take a NEW storage `FORMAT_VERSION` (the current
one is frozen), update the affected rows above, then re-pin the digest with
`sh scripts/check-format-registry.sh --print` and replace the value on the sentinel line
below.

```text
format-layout-sha256: 1ba45310148ec1b9c613bd68d475793039e3e8994be5d8f1d5bd34ca9f9c1454
```

The digest was last re-pinned for the ADDITIVE v2 compaction delta (#337): the
`FORMAT_VERSION_COMPACTED` value, the `SEGMENT_FLAG_COMPACTED` flag bit, and the
`COMPACTION_META_LEN` / `compaction_meta_offsets` / `COMPACTION_META_CRC_RANGE` block layout were
APPENDED to `format.rs`. Every v1 layout-constant LINE is unchanged byte-for-byte (the v1
record/segment/footer offsets, magics, sizes, and `FORMAT_VERSION = 1` are untouched, so a v1
segment is byte-identical and a v1 reader is unchanged); only the new v2 lines were added, which
shifted the whole-file digest. A v2 (compacted) segment is the only one that carries `version = 2`;
a v1-only reader REFUSES it (fail-closed), so the bump is breaking-on-the-new-shape but invisible to
a log that has never been compacted.

The duplicate-integer check that #132 also asks for (no two open branches claiming the same
`FORMAT_VERSION`) is a git-server-side concern this registry makes mechanical: because the
`FORMAT_VERSION` value lives on one line in `format.rs` and one row here, two branches that
both bump to the same next integer produce a textual MERGE CONFLICT on the second to merge,
which is exactly the "turn a collision into a git conflict" mechanism #126 relies on. The
digest gate above is the encoding-change-needs-a-registry-row half; the conflict is the
no-duplicate-integer half.

## See also

- [COMPATIBILITY.md](../COMPATIBILITY.md): the prose compatibility rules and their code
  citations, plus the honest list of what is specified but not yet implemented.
- [CONTRACTS.md](../CONTRACTS.md): the byte-level on-disk, wire, and report tables.
- [schemas/loss-report.v1.md](../schemas/loss-report.v1.md): the `ReasonCode` vocabulary and
  the loss-report `schema_version`.
- [DISTRIBUTION.md](../DISTRIBUTION.md): the `migrate` gate and the downgrade-safety policy.
- The same compatibility discipline applied to OUTWARD interfaces: the `--json` schema
  versioning (#15) and the metric-name stability contract ([METRICS.md](../METRICS.md), #16).
