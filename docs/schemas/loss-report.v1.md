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

## Versioning policy

`schema_version` is bumped only on an INCOMPATIBLE change to the fields or their meaning (a
rename, removal, reorder, or type change). Adding a new `ReasonCode` variant does NOT bump it: a
reader that does not know a new reason still reads the numeric span (`bytes_skipped`, the offset
range, the record estimate); it just cannot interpret the reason's meaning. When a bump is
genuinely required, the change is: bump `LossReport::SCHEMA_VERSION`, update this document and
[CONTRACTS.md](../CONTRACTS.md#report-models), and freeze a new golden in `loss.rs`.
