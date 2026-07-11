# `ironbus.loss-report.v1`

The normative, versioned schema for IronBus's structured recovery loss report: the single
source of truth for what recovery dropped to reach the last intact record. It is a stable,
externally-frozen contract, not an ad-hoc log line, so the metrics endpoint (#16), the offline
inspector (#15), and corpus or property fixtures all read and assert the SAME shape (#120, #21).

- **Schema name:** `ironbus.loss-report.v1`
- **`schema_version`:** `1`
- **Source of truth:** `crates/ironbus-storage/src/loss.rs` (`LossReport`, `LossEvent`,
  `ReasonCode`). This document is derived from and cross-checked against that source; the code is
  canonical.
- **Frozen by:** the golden tests in `loss.rs`. `golden_loss_report_v1_serialization_is_frozen`
  pins the exact JSON shape and field order of a representative report;
  `golden_reason_code_vocabulary_is_frozen` pins every reason's numeric code, metric label, and
  JSON variant name; and
  `reason_codes_are_stable_and_distinct` pins the numeric codes independently. Any field rename,
  removal, reorder, or reason-code renumber fails CI, forcing a deliberate `schema_version` bump
  rather than a silent break.

This is the report half of the contract catalog. For the byte-level on-disk and wire models, and
the report's place among them, see [CONTRACTS.md](../CONTRACTS.md#report-models). For the
resilience invariants the report serves (I1 to I4, in particular I3 bounded-and-reported loss),
see [INVARIANTS.md](../INVARIANTS.md).

## Serialization

The report derives `serde::{Serialize, Deserialize}`. The crate carries the `serde` derive only;
the concrete JSON format (`serde_json`) is a dev-only dependency, so the shipped static edge
binary does not pay for it until an emitter that needs a wire format is added. There is NO frozen
fixed-width BINARY layout for the report (unlike the on-disk record/segment frames): it is
serde-serialized, so only the FIELD SET, the field types, and the frozen numeric reason codes are
normative here. The JSON encoding below is the canonical, golden-pinned external form.

A representative `ironbus.loss-report.v1` document (the frozen golden):

```json
{
  "schema_version": 1,
  "events": [
    {
      "segment_id": 0,
      "byte_offset_start": 4096,
      "byte_offset_end": 8192,
      "bytes_skipped": 4096,
      "records_lost_estimate": 1,
      "reason_code": "TornTail"
    },
    {
      "segment_id": 2,
      "byte_offset_start": 65536,
      "byte_offset_end": 131072,
      "bytes_skipped": 65536,
      "records_lost_estimate": 7,
      "reason_code": "CorruptRecordBody"
    }
  ]
}
```

A report with an empty `events` list is a clean recovery (no loss).

## `LossReport`

| field            | type              | notes |
|------------------|-------------------|-------|
| `schema_version` | `u16`             | the schema version this report was written under; `SCHEMA_VERSION` = `1` |
| `events`         | `list[LossEvent]` | the loss spans, in the order recovery encountered them; an empty list is a clean recovery |

Bounded-loss caps (constants in `LossReport`, enforced at recovery, see I3):

| constant                        | value      | meaning |
|---------------------------------|------------|---------|
| `PER_EVENT_BYTE_CAP`            | `64 MiB`   | the ceiling on a SINGLE event's `bytes_skipped`; the effective per-event cap is the smaller of this and one segment |
| `GLOBAL_LOSS_CAP_NUMERATOR`    | `1`        | numerator of the global cap fraction |
| `GLOBAL_LOSS_CAP_DENOMINATOR`  | `100`      | denominator of the global cap fraction; the global cap is `1%` of durable bytes |

Exceeding either cap turns bounded reported loss into unbounded silent loss, so recovery must
fail closed (freeze read-only, exit non-zero) rather than accept it. The caps are documented as
safe defaults and are intended to be configurable per #14.

## `LossEvent`

One contiguous span of bytes that recovery dropped from one segment, with its cause and an
estimate of how many records it cost.

| field                   | type         | notes |
|-------------------------|--------------|-------|
| `segment_id`            | `u64`        | the segment the loss occurred in |
| `byte_offset_start`     | `u64`        | byte offset WITHIN the segment file where the lost span begins |
| `byte_offset_end`       | `u64`        | byte offset within the segment file where the lost span ends (exclusive) |
| `bytes_skipped`         | `u64`        | the span length; `byte_offset_end - byte_offset_start`, computed saturating so a reversed range is an empty span, never an underflow |
| `records_lost_estimate` | `u64`        | best-effort LOWER BOUND on records lost in this span (a torn/corrupt span is not fully parseable, so the exact count is unknown) |
| `reason_code`           | `ReasonCode` | why the span was dropped (see below) |

## `ReasonCode` (frozen numeric codes)

`reason_code` serializes as its variant NAME in JSON (the human-readable report a consumer
parses) and carries a stable numeric `code()` for the metrics endpoint and a stable
`metric_label()` for a metric series or log field. All three are frozen: a new reason is APPENDED
with a new number, name, and label; an existing one is NEVER reordered, renamed, or renumbered.
The numeric codes are pinned by `reason_codes_are_stable_and_distinct`; the full (code, label,
JSON name) triple is pinned by `golden_reason_code_vocabulary_is_frozen`.

| code | JSON name (`reason_code`) | metric label              | meaning |
|------|---------------------------|---------------------------|---------|
| `1`  | `"TornTail"`              | `torn_tail`               | a torn or unsynced active-segment tail: bytes after the last durable record were truncated to reach a consistent prefix (the common, expected power-loss case) |
| `2`  | `"CorruptRecordHeader"`   | `corrupt_record_header`   | a record header failed its checksum (or magic/version), so the frame and everything after it in the segment was abandoned |
| `3`  | `"CorruptRecordBody"`     | `corrupt_record_body`     | a record header was intact but its body failed its checksum, so the frame and everything after it was abandoned |
| `4`  | `"CorruptSegmentHeader"`  | `corrupt_segment_header`  | a segment header was unreadable, so the whole segment was abandoned |
| `5`  | `"SequenceGap"`           | `sequence_gap`            | a checksum-valid record carried an out-of-order sequence (a recycled or mixed-up frame), so the segment was abandoned at that record |
| `6`  | `"ScrubberSuspect"`       | `scrubber_suspect`        | the at-rest scrubber (#92) flagged a span as suspect during a background integrity pass (silent bit rot: a checksum that no longer verifies on a previously-durable record). Reserved for the scrubber; recovery itself never emits it today, but the reason is appended now so the scrubber emits into a frozen vocabulary. Appended per #59; APPEND-ONLY, so it does NOT bump `schema_version` |
| `7`  | `"UnresolvedDictId"`      | `unresolved_dict_id`      | a checksum-VALID record referenced a compression `dict_id` the reader could resolve from neither the on-disk `dicts/` sidecar nor the embedded active set, so the record could not be decompressed and was skipped as bounded, reported loss (#357, #78, `../DICTIONARY_LIFECYCLE.md` §5). DISTINCT from a corrupt body (codes 2/3): the framing and CRCs all PASS; the dictionary is simply ABSENT, so reporting it as bit-rot would mislead an operator. Appended per #357; APPEND-ONLY, so it does NOT bump `schema_version` |
| `8`  | `"UnknownKeyId"`          | `unknown_key_id`          | an at-rest-ENCRYPTED segment (#780, `../AT_REST_ENCRYPTION.md`) whose header `key_id` matches NO loaded key, so its records cannot be decrypted at all. DISTINCT from a corrupt body (codes 2/3): the framing and CRCs all PASS; the key is simply MISSING, so an operator sees an actionable key-management gap ("load key X for segment S"), not "your disk is corrupt". Appended per #780; APPEND-ONLY, so it does NOT bump `schema_version` |
| `9`  | `"AeadTagMismatch"`       | `aead_tag_mismatch`       | an at-rest-ENCRYPTED record (#780) whose `key_id` matched a loaded key and whose CRC over the ciphertext PASSED, but whose AEAD authentication tag FAILED under that key (a wrong/rotated key or a forgery). DELIBERATELY DISTINCT from `CorruptRecordBody` (code 3): the CRC is verified BEFORE the AEAD, so a tag failure here is genuine authenticity failure, NOT bit-rot — a wrong or rotated key must never masquerade as corruption. Appended per #780; APPEND-ONLY, so it does NOT bump `schema_version` |

Codes `6`, `7`, `8`, and `9` were appended without a `schema_version` bump, which is the whole point
of the append-only rule: a `v1` reader that predates
`ScrubberSuspect`/`UnresolvedDictId`/`UnknownKeyId`/`AeadTagMismatch` still reads such an event's
numeric span (`bytes_skipped`, the offset range, the record estimate); it just renders the reason as
an unknown name. Codes `1` through `5` are byte-identical to before.

## Data loss vs. reported skip (the torn-tail exclusion)

A `LossEvent` is always a REPORTED SKIP, but not every skip is real DATA loss. A
[`ReasonCode::TornTail`] (code `1`) is the expected power-loss / brownout case: the bytes after the
last durable record were simply never fully written, so they were never acked data. Counting them
as data loss would inflate fleet loss metrics on every clean restart. So:

- `LossReport::total_bytes_skipped()` is the full skip/truncation span and INCLUDES torn tails. It
  is what `ironbus_recovery_truncated_bytes` and the per-reason `ironbus_recovery_loss_bytes{reason}`
  series (which keep `torn_tail` as its own line) report.
- `LossReport::data_loss_bytes()` is the same sum with `TornTail` EXCLUDED: the headline "bytes of
  real data lost" figure, exposed as the `ironbus_recovery_data_loss_bytes` gauge (#59). It does not
  inflate on a brownout. Every reason except `TornTail` counts (`ReasonCode::is_data_loss()` is the
  per-reason predicate), the SAME boundary the quarantine store uses to decide what corrupt bytes
  are worth keeping (`quarantine::is_corruption_skip`), so the data-loss total and the forensic
  store agree on what "data loss" means.

`ScrubberSuspect` (code `6`) is silent bit rot on previously-durable bytes, so it DOES count as data
loss. `UnresolvedDictId` (code `7`) is intact, checksum-valid data that is undecodable because its
dictionary is absent, which IS a loss of decodable data, so it also counts as data loss.

## SkipEvent: the shipped `LossEvent` is the canonical per-skip schema

Issue #59 (and the #137 draft) sketched a `SkipEvent` struct with field names like
`lost_offset_start`, `lost_offset_end`, `lost_bytes`, `resync_offset`, `recovered`, and `mode`, and
a reason vocabulary of `RecordCrcMismatch, SegmentHeaderBad, InvariantViolation, TornTailTruncated,
ScrubberSuspect`. That draft predates the SHIPPED, frozen `loss-report.v1`. There is NO second,
divergent SkipEvent schema: the shipped `LossEvent` IS IronBus's per-skip SkipEvent, the SINGLE
schema shared with the metrics endpoint (#16) and the offline inspector (#15). The draft field and
reason names map onto the frozen ones as follows; the frozen names are canonical.

| #59 draft field   | frozen `LossEvent` field | mapping |
|-------------------|--------------------------|---------|
| `lost_offset_start` | `byte_offset_start`    | identical meaning: where the lost span begins (within the segment file) |
| `lost_offset_end`   | `byte_offset_end`      | identical meaning: exclusive end of the lost span |
| `lost_bytes`        | `bytes_skipped`        | identical meaning: the span length (`end - start`, saturating) |
| `resync_offset`     | `byte_offset_end`      | the resync point IS `byte_offset_end`: recovery resumes (and the valid prefix ends) exactly where the dropped span ends. A nullable separate field is not needed because recovery always resumes at the span end (it never resyncs PAST a corrupt frame onto a later magic; see the false-magic case), so the resync point is never absent and never distinct from `byte_offset_end` |
| `recovered` (bool)  | (not needed)           | every event in the report WAS recovered-and-reported by definition (an unrecovered loss fails the bounded-loss cap and fails recovery closed; it never lands as a `recovered=false` event). The bounded-loss caps (`check_caps`) carry the "is this acceptable loss" decision, so a per-event recovered flag adds no information |
| `mode`              | (not needed)            | the draft's `mode` distinguished shutdown kinds; that lives in recovery's operational state, not in a per-skip event. The per-skip schema stays minimal |

| #59 / #137 draft reason | frozen `ReasonCode`        |
|-------------------------|----------------------------|
| `TornTailTruncated`     | `TornTail` (1)             |
| `RecordCrcMismatch`     | `CorruptRecordHeader` (2) / `CorruptRecordBody` (3) (split by where the checksum failed) |
| `SegmentHeaderBad`      | `CorruptSegmentHeader` (4) |
| `InvariantViolation`    | `SequenceGap` (5) (the concrete invariant recovery enforces inline) |
| `ScrubberSuspect`       | `ScrubberSuspect` (6)      |

### Schema-bump decision: stay at v1

The draft's extra fields (`resync_offset` nullable, `recovered` bool, `mode`) were evaluated against
the frozen schema and do NOT justify bumping to a `v2`:

- `resync_offset` is fully captured by the existing `byte_offset_end` (recovery always resumes at the
  span end), so it is a rename of an existing field, not a new one.
- `recovered` and `mode` carry no per-event information the report needs: recovery either accepts a
  bounded, reported loss (the event lands) or fails closed (no event lands), so there is no
  `recovered=false` event to represent, and shutdown `mode` is operational state outside the per-skip
  schema.

Adding any of them would be an INCOMPATIBLE field change that bumps `schema_version` for no real
gain, breaking every deployed `v1` reader. So the schema stays at `v1`; only the append-only
`ScrubberSuspect` (code 6) and `UnresolvedDictId` (code 7) reasons were added (which by rule do not
bump the version). If a future need for a genuinely new field appears, it is a deliberate `v2`: bump
`SCHEMA_VERSION`, freeze a new golden, and update this document and CONTRACTS.md.

## Worked examples (the three headline scenarios)

Each example shows the exact loss event recovery emits, with its offset range, reason, and bytes,
and where recovery resumes (the resync point = `byte_offset_end`). They use a 64-byte segment header
and a fixed 52-byte record frame (the shape the crash and corpus tests use) so the offsets are
concrete. These are pinned by the crash-injection cases in
`crates/ironbus-storage/tests/{corruption_corpus,crash_recovery,conformance_recovery}.rs`.

1. **Torn tail** (the brownout case). Five records were written; the sixth was only partially
   written before power loss (a torn write left a partial header at offset `324`). Recovery keeps
   the five intact records and drops the partial tail:

   ```json
   { "segment_id": 0, "byte_offset_start": 324, "byte_offset_end": 328,
     "bytes_skipped": 4, "records_lost_estimate": 1, "reason_code": "TornTail" }
   ```

   Resync point: offset `324` (recovery truncates the segment to there and resumes appending). This
   is a REPORTED SKIP but NOT data loss: it contributes to `ironbus_recovery_truncated_bytes` and the
   `torn_tail` per-reason series, but NOT to `ironbus_recovery_data_loss_bytes`.

2. **Mid-log corruption** (silent bit rot or a planted false magic). Five records were durable; a bit
   flipped in the body of the third record (frame start `168`). Its header still scans, but the body
   checksum fails, so recovery stops at that frame and drops everything from it to EOF. Recovery does
   NOT resync onto any later (or planted/fabricated) record magic past the corrupt frame:

   ```json
   { "segment_id": 0, "byte_offset_start": 168, "byte_offset_end": 324,
     "bytes_skipped": 156, "records_lost_estimate": 1, "reason_code": "CorruptRecordBody" }
   ```

   Resync point: offset `168` (the valid prefix ends here; everything after is dropped as one span).
   This IS data loss: it counts toward `ironbus_recovery_data_loss_bytes`. A header-checksum failure
   on a valid-looking magic reports `CorruptRecordHeader` over the same shape.

3. **Bad segment header**. The segment header itself is unreadable (a flipped CRC, an unsupported
   version, or a too-short file). The WHOLE segment is abandoned, so recovery fails closed with a
   typed segment error rather than recovering a partial prefix. When the loss is recorded as an
   event (e.g. a chained sealed segment whose header is corrupt) it spans the whole segment:

   ```json
   { "segment_id": 7, "byte_offset_start": 0, "byte_offset_end": 65536,
     "bytes_skipped": 65536, "records_lost_estimate": 0, "reason_code": "CorruptSegmentHeader" }
   ```

   Resync point: there is no in-segment resync (the segment is wholly abandoned); recovery resumes at
   the next segment in the chain. This IS data loss.

## Versioning policy

`schema_version` is bumped only on an INCOMPATIBLE change to the fields or their meaning (a
rename, removal, reorder, or type change). Adding a new `ReasonCode` variant does NOT bump it: a
reader that does not know a new reason still reads the numeric span (`bytes_skipped`, the offset
range, the record estimate); it just cannot interpret the reason's meaning. When a bump is
genuinely required, the change is: bump `LossReport::SCHEMA_VERSION`, update this document and
[CONTRACTS.md](../CONTRACTS.md#report-models), and freeze a new golden in `loss.rs`.
