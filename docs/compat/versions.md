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
| Wire protocol version | `1` (specified; NOT YET ON THE WIRE) | specified as the `wire_protocol_version` handshake field; the `Connect`/`Info` bodies are EMPTY today (`ironbus_server::session` `dispatch`) | Negotiate (`min(client, server)`); see [Wire-version negotiation](#wire-version-negotiation). Wiring owned by #11. | #126, #132, #11 |
| Loss-report `schema_version` | `1` | `ironbus_storage::loss` `LossReport::SCHEMA_VERSION`; frozen by `golden_loss_report_v1_serialization_is_frozen` | Append-only within v1 (a new field or reason does not bump it); a field rename/removal/reorder takes a new version. | #120, #21 |
| CLI `--json` schema `ironbus.cli.scrub.vN` | `1` | `ironbus-cli` `SCRUB_SCHEMA_VERSION`; emitted by `write_plan_json`; pinned by `scrub_json_carries_the_versioned_schema_and_exit_code` | Append-only: a new OPTIONAL field does not bump `N`; a field rename/removal/type-change bumps `N` (gated by SemVer, cannot ride a patch). Per [CLI_CONTRACT.md](../CLI_CONTRACT.md) §1.5. | #136, #92 |
| CLI `--json` schema `ironbus.cli.repair.vN` | `1` | `ironbus-cli` `REPAIR_SCHEMA_VERSION`; emitted by `write_plan_json` | Append-only (same rule as the scrub schema; carries the additional `applied` field). | #136, #92 |
| `FrameType` tag set | `1..=20`, contiguous (`Connect`=1 .. `CumulativeAck`=19, `PubAckDuplicate`=20) | `ironbus_proto::frame::FrameType::as_u8`/`from_u8`; frozen by `type_tags_have_their_exact_frozen_wire_values` | Append-only. The next frame takes tag 21; no existing tag's meaning ever changes. | #11, #33 |
| `PubBody` dedup opt-in (`PUB_FLAG_HAS_DEDUP`) | flags bit 7 (`0b1000_0000`); when set, a `producer_id` (u16-var), `epoch` (u64), `msg_id` (u16-var) block follows the headers, before the payload | `ironbus_proto::message::PUB_FLAG_HAS_DEDUP` and `PubDedup`; round-tripped by `any_pub_with_dedup_round_trips` | Append-only and OPT-IN. A dedup-disabled produce leaves the bit clear and omits the block, so the body is byte-for-byte the pre-#33 layout. The bit is a WIRE signal, masked off before the byte becomes a stored record flag, so it never collides with a future `RecordFlags` bit. | #33, #3 |
| `AckOp` sub-tag set | `0..=3` (`Ack`=0, `Nack`=1, `Term`=2, `Progress`=3) | `ironbus_proto::message::AckOp::as_u8`/`from_u8`; frozen by `ackop_tags_have_their_exact_frozen_wire_values` | Append-only. The next op takes tag 4. | #9, #11 |
| `ReasonCode` vocabulary | codes `1..=6` (`TornTail`=1 .. `ScrubberSuspect`=6) | `ironbus_storage::loss::ReasonCode::code`; frozen by `golden_reason_code_vocabulary_is_frozen` and `reason_codes_are_stable_and_distinct` | Append-only. A new reason gets a new code/name/label and does NOT bump `schema_version`. | #11, #59 |
| `RecordFlags` bits | `KNOWN` = `0b111` (`COMPRESSED`=bit0, `HAS_KEY`=bit1, `HAS_XXH3`=bit2) | `ironbus_core::types::RecordFlags` (`COMPRESSED`/`HAS_KEY`/`HAS_XXH3`/`KNOWN`) | Append-only. A new flag claims a higher bit; unknown bits are preserved, never interpreted, within a known version. | #5, #12 |
| `checksum_algo` | `CRC32C` = `0x1` | `ironbus_core::format::CHECKSUM_ALGO_CRC32C`; checked in `SegmentHeader::decode`/`SegmentFooter::decode` | Append-only. A new algo takes a new byte; a v1 reader refuses any unknown value. | #5 |
| `codec` id | reserved, single value "none" (`COMPRESSED` never set in v1) | reserved in the compressed-payload descriptor behind `RecordFlags::COMPRESSED`; see [DICTIONARY_LIFECYCLE.md](../DICTIONARY_LIFECYCLE.md) and [ADR 0003](../adr/0003-default-compression-lz4-zstd-opt-in.md) | Append-only. New codec ids are appended; on-disk compression is not yet implemented. | #12 |
| `dict_id` | reserved, `0` = no-dictionary sentinel | reserved `u32` in the compressed-payload descriptor; content-addressed per [DICTIONARY_LIFECYCLE.md](../DICTIONARY_LIFECYCLE.md) | Append-only (content-addressed; reuse is structurally impossible). Not yet implemented. | #12, #78 |

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
| `codec` id (durable path) | POISON | yes | #12 | specified: routed to #8 as a poison unit (reported loss, advance), not implemented |
| `dict_id` (durable path) | POISON | yes | #12, #78 | specified: `UnresolvedDictId` reported loss via #8 (see DICTIONARY_LIFECYCLE.md), not implemented |
| Wire protocol version | NEGOTIATE | n/a | #126, #132, #11 | specified `min(client, server)`; handshake bodies empty today, wiring owned by #11 |
| `FrameType` tag (unknown tag over a known envelope) | REFUSE that frame (typed), keep the connection | yes | #11 | `ClientError::UnknownFrameType` (client); server replies a generic `Err`, does not drop the connection |
| `AckOp` sub-tag | REFUSE that op (typed) | yes | #9, #11 | `AckOp::from_u8` returns the typed `BadAckOp` |
| `ReasonCode` (unknown code on read) | TOLERATE (render the numeric span; unknown name) | yes | #11, #59 | append-only rule: a pre-`ScrubberSuspect` reader still reads a code-6 event's numeric span |
| Loss-report `schema_version` | REFUSE a higher version (a consumer reads only its known schema) | append within a version | #120, #21 | frozen golden tests force a deliberate `schema_version` bump on a breaking change |
| CLI `--json` schemas (`ironbus.cli.scrub.vN`, `ironbus.cli.repair.vN`) | REFUSE a higher `N` than known (a consumer matches the exact `schema` string and fails closed on a higher version), same rule the loss-report `schema_version` follows | yes (a new optional field does not bump `N`) | #136, #92 | `SCRUB_SCHEMA_VERSION` / `REPAIR_SCHEMA_VERSION`; the result object carries the full `ironbus.cli.<command>.vN` discriminator |

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
handshake; the WIRING is the implementation residual owned by #11. The handshake bodies are
EMPTY today (`ironbus_server::session` `dispatch` replies `Info` with `&[]`;
`ironbus_client` `connect_with` sends `&[]`), so nothing below is asserted as implemented.

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

Until #11 wires this, the wire is versioned only IMPLICITLY by the frozen tag set and the
fixed body layouts; there is no version integer to negotiate yet. See the "Specified but not
yet implemented" and "Discrepancies" sections of [COMPATIBILITY.md](../COMPATIBILITY.md),
which state the same residual.

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
format-layout-sha256: 59773de3d5eda9f78be52bda388df2a73b1accd2ca575c4100dfdd1179cbcb0a
```

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
