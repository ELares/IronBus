// SPDX-License-Identifier: MIT OR Apache-2.0
//! The versioned, structured loss report: the single source of truth for what recovery
//! dropped.
//!
//! When recovery truncates a torn tail or stops at a corrupt frame, the bytes past the last
//! intact record are lost. A [`LossReport`] records that loss as a stable, versioned artifact
//! rather than an ad-hoc log line, so the metrics endpoint and the offline inspector can read
//! the SAME shape and corpus fixtures can assert exact values (#120). This module defines the
//! schema and its invariants; recovery emitting it, the I1 to I4 invariant checkers, and the
//! bounded-loss cap enforcement are layered on top in follow-ups.
//!
//! The report derives `serde::{Serialize, Deserialize}` so a consumer can render it to any
//! format. The crate keeps only the `serde` derive in its build: the concrete JSON format
//! (`serde_json`) is a test dependency, so the static edge binary does not pay for it until an
//! emitter that needs a wire format is added.

use serde::{Deserialize, Serialize};

/// Why recovery dropped a contiguous span of bytes. Each variant has a stable numeric
/// [`code`](ReasonCode::code) for the metrics endpoint; `serde` serializes the variant name
/// for a human-readable report. New variants are appended (never reordered or renumbered) so
/// the codes stay frozen across versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReasonCode {
    /// A torn or unsynced active-segment tail: the bytes after the last durable record were
    /// truncated to reach a consistent prefix (the common, expected power-loss case).
    TornTail,
    /// A record header failed its checksum (or magic/version), so the frame and everything
    /// after it in the segment was abandoned.
    CorruptRecordHeader,
    /// A record header was intact but its body failed its checksum, so the frame and
    /// everything after it was abandoned.
    CorruptRecordBody,
    /// A segment header was unreadable, so the whole segment was abandoned.
    CorruptSegmentHeader,
    /// A checksum-valid record carried an out-of-order sequence (a recycled or mixed-up
    /// frame), so the segment was abandoned at that record.
    SequenceGap,
}

impl ReasonCode {
    /// The stable numeric code for this reason, for the metrics endpoint (#16) and for
    /// fixtures that pin exact values. These numbers are part of the frozen schema: a new
    /// reason gets a new number, an existing one never changes.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            ReasonCode::TornTail => 1,
            ReasonCode::CorruptRecordHeader => 2,
            ReasonCode::CorruptRecordBody => 3,
            ReasonCode::CorruptSegmentHeader => 4,
            ReasonCode::SequenceGap => 5,
        }
    }

    /// Every reason, in code order, so a consumer can enumerate them (for example to emit a
    /// metric series per reason). Appended to, never reordered.
    pub const ALL: [ReasonCode; 5] = [
        ReasonCode::TornTail,
        ReasonCode::CorruptRecordHeader,
        ReasonCode::CorruptRecordBody,
        ReasonCode::CorruptSegmentHeader,
        ReasonCode::SequenceGap,
    ];

    /// A stable, lower-snake-case label for this reason, for a metric series or a log field.
    /// Frozen alongside [`ReasonCode::code`].
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            ReasonCode::TornTail => "torn_tail",
            ReasonCode::CorruptRecordHeader => "corrupt_record_header",
            ReasonCode::CorruptRecordBody => "corrupt_record_body",
            ReasonCode::CorruptSegmentHeader => "corrupt_segment_header",
            ReasonCode::SequenceGap => "sequence_gap",
        }
    }
}

/// One contiguous span of bytes that recovery dropped from one segment, with its cause and
/// an estimate of how many records it cost.
///
/// `bytes_skipped` is the length of the lost span; for a simple truncation it equals
/// `byte_offset_end - byte_offset_start`. `records_lost_estimate` is a best effort: a torn or
/// corrupt span is, by definition, not fully parseable, so the exact record count is unknown
/// and the estimate is a lower bound (for example `1` for a torn partial record).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossEvent {
    /// The segment the loss occurred in.
    pub segment_id: u64,
    /// The byte offset (within the segment file) where the lost span begins.
    pub byte_offset_start: u64,
    /// The byte offset (within the segment file) where the lost span ends (exclusive).
    pub byte_offset_end: u64,
    /// The number of bytes lost (the span length).
    pub bytes_skipped: u64,
    /// A best-effort lower bound on how many records were lost in this span.
    pub records_lost_estimate: u64,
    /// Why the span was dropped.
    pub reason_code: ReasonCode,
}

impl LossEvent {
    /// Builds an event for the byte span `[start, end)` of `segment_id`, computing
    /// `bytes_skipped` from the span so it cannot disagree with the offsets. `start > end` is
    /// treated as an empty span (`bytes_skipped == 0`) via a saturating subtraction.
    #[must_use]
    pub fn span(
        segment_id: u64,
        byte_offset_start: u64,
        byte_offset_end: u64,
        records_lost_estimate: u64,
        reason_code: ReasonCode,
    ) -> LossEvent {
        LossEvent {
            segment_id,
            byte_offset_start,
            byte_offset_end,
            bytes_skipped: byte_offset_end.saturating_sub(byte_offset_start),
            records_lost_estimate,
            reason_code,
        }
    }
}

/// A versioned, structured report of everything recovery dropped: the single source of truth
/// for the per-step loss that the metrics endpoint and the offline inspector both read.
///
/// `schema_version` is stamped to [`LossReport::SCHEMA_VERSION`] by the constructors so a
/// reader can detect a format it does not understand. A report with no events is a clean
/// recovery (no loss).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossReport {
    /// The schema version this report was written under.
    pub schema_version: u16,
    /// The loss spans, in the order recovery encountered them.
    pub events: Vec<LossEvent>,
}

impl LossReport {
    /// The current loss-report schema version. Bumped only on an incompatible change to the
    /// fields or their meaning; new [`ReasonCode`] variants do not bump it (readers ignore an
    /// unknown reason's meaning but still read the numeric span).
    pub const SCHEMA_VERSION: u16 = 1;

    /// The maximum bytes a SINGLE loss event may report before recovery must fail closed: one
    /// segment or 64 MiB, whichever is smaller. The per-event ceiling is 64 MiB here; the
    /// "one segment" half is applied with the runtime segment size where this is enforced.
    /// Defining it here keeps the bounded-loss policy in one place (#120, I3). Enforcement
    /// (freeze read-only and exit non-zero on exceed) is a follow-up.
    pub const PER_EVENT_BYTE_CAP: u64 = 64 * 1024 * 1024;

    /// The global loss cap as a fraction of durable bytes, expressed as a numerator over
    /// [`LossReport::GLOBAL_LOSS_CAP_DENOMINATOR`]: the default is 1% (`1 / 100`). Beyond this,
    /// bounded reported loss has become unbounded silent loss and recovery must fail closed.
    pub const GLOBAL_LOSS_CAP_NUMERATOR: u64 = 1;
    /// The denominator for [`LossReport::GLOBAL_LOSS_CAP_NUMERATOR`] (the default global cap is
    /// 1% = `1 / 100`).
    pub const GLOBAL_LOSS_CAP_DENOMINATOR: u64 = 100;

    /// Creates an empty report stamped with the current [`LossReport::SCHEMA_VERSION`].
    #[must_use]
    pub fn new() -> LossReport {
        LossReport {
            schema_version: LossReport::SCHEMA_VERSION,
            events: Vec::new(),
        }
    }

    /// Appends a loss event.
    pub fn push(&mut self, event: LossEvent) {
        self.events.push(event);
    }

    /// `true` if recovery dropped nothing (a clean recovery).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The total bytes dropped across all events (saturating, so a crafted report can never
    /// overflow this sum).
    #[must_use]
    pub fn total_bytes_skipped(&self) -> u64 {
        self.events
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.bytes_skipped))
    }

    /// The total estimated records lost across all events (saturating).
    #[must_use]
    pub fn total_records_lost_estimate(&self) -> u64 {
        self.events
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.records_lost_estimate))
    }

    /// The total bytes dropped by events with `reason` (saturating). Useful for a per-reason
    /// metric series.
    #[must_use]
    pub fn bytes_skipped_for(&self, reason: ReasonCode) -> u64 {
        self.events
            .iter()
            .filter(|e| e.reason_code == reason)
            .fold(0u64, |acc, e| acc.saturating_add(e.bytes_skipped))
    }

    /// The records dropped by events with `reason` (saturating estimate): the per-reason
    /// complement of [`LossReport::bytes_skipped_for`], for the `ironbus_recovery_loss_records`
    /// metric series so an operator sees not just how many bytes recovery dropped but how
    /// many records, by reason.
    #[must_use]
    pub fn records_lost_for(&self, reason: ReasonCode) -> u64 {
        self.events
            .iter()
            .filter(|e| e.reason_code == reason)
            .fold(0u64, |acc, e| acc.saturating_add(e.records_lost_estimate))
    }

    /// The global loss cap in bytes for a log holding `durable_bytes` of durable data, using
    /// the default fraction ([`LossReport::GLOBAL_LOSS_CAP_NUMERATOR`] over
    /// [`LossReport::GLOBAL_LOSS_CAP_DENOMINATOR`], 1%). Integer math, rounding down.
    #[must_use]
    pub fn global_loss_cap_bytes(durable_bytes: u64) -> u64 {
        durable_bytes / LossReport::GLOBAL_LOSS_CAP_DENOMINATOR
            * LossReport::GLOBAL_LOSS_CAP_NUMERATOR
    }

    /// Checks this report against the I3 bounded-loss caps (#120): no single event may drop
    /// more than `per_event_cap`, and the total dropped may not exceed `global_cap`. Returns
    /// the first violation, or `Ok(())` if the loss is within bounds.
    ///
    /// The caller computes the caps from the runtime config (the per-event cap is one segment
    /// or 64 MiB whichever is smaller; the global cap is derived from the durable byte count).
    /// This is a pure function so the recovery path, the sim, and corpus or property fixtures
    /// can all assert the same bound.
    ///
    /// # Errors
    /// Returns the first [`CapViolation`] found.
    pub fn check_caps(&self, per_event_cap: u64, global_cap: u64) -> Result<(), CapViolation> {
        for e in &self.events {
            if e.bytes_skipped > per_event_cap {
                return Err(CapViolation::PerEvent {
                    bytes_skipped: e.bytes_skipped,
                    cap: per_event_cap,
                });
            }
        }
        let total = self.total_bytes_skipped();
        if total > global_cap {
            return Err(CapViolation::Global {
                total_bytes_skipped: total,
                cap: global_cap,
            });
        }
        Ok(())
    }
}

/// A bounded-loss cap that [`LossReport::check_caps`] found exceeded: recovery must fail
/// closed rather than accept this as silent loss (#120, I3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapViolation {
    /// A single event dropped more than the per-event cap allows.
    PerEvent {
        /// The offending event's dropped bytes.
        bytes_skipped: u64,
        /// The per-event cap (one segment or 64 MiB, whichever is smaller).
        cap: u64,
    },
    /// The total dropped across all events exceeded the global cap.
    Global {
        /// The total dropped across the report.
        total_bytes_skipped: u64,
        /// The global cap (derived from the durable byte count).
        cap: u64,
    },
}

impl std::fmt::Display for CapViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapViolation::PerEvent { bytes_skipped, cap } => write!(
                f,
                "a recovery loss event dropped {bytes_skipped} bytes, over the per-event cap {cap}"
            ),
            CapViolation::Global {
                total_bytes_skipped,
                cap,
            } => write!(
                f,
                "recovery would drop {total_bytes_skipped} bytes total, over the global cap {cap}"
            ),
        }
    }
}

impl std::error::Error for CapViolation {}

impl Default for LossReport {
    fn default() -> LossReport {
        LossReport::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_report_is_empty_and_carries_the_current_schema_version() {
        let r = LossReport::new();
        assert!(r.is_empty());
        assert_eq!(r.schema_version, LossReport::SCHEMA_VERSION);
        assert_eq!(r.schema_version, 1);
        assert_eq!(LossReport::default(), r);
    }

    #[test]
    fn span_computes_bytes_skipped_and_saturates_a_reversed_range() {
        let e = LossEvent::span(3, 100, 180, 2, ReasonCode::TornTail);
        assert_eq!(e.bytes_skipped, 80);
        assert_eq!(e.byte_offset_start, 100);
        assert_eq!(e.byte_offset_end, 180);
        // A reversed range is an empty span, never an underflow.
        let empty = LossEvent::span(3, 180, 100, 0, ReasonCode::TornTail);
        assert_eq!(empty.bytes_skipped, 0);
    }

    #[test]
    fn totals_sum_across_events_and_saturate() {
        let mut r = LossReport::new();
        r.push(LossEvent::span(0, 0, 10, 1, ReasonCode::TornTail));
        r.push(LossEvent::span(1, 0, 30, 2, ReasonCode::CorruptRecordBody));
        assert!(!r.is_empty());
        assert_eq!(r.total_bytes_skipped(), 40);
        assert_eq!(r.total_records_lost_estimate(), 3);

        // Two near-u64::MAX spans saturate rather than wrap.
        let mut big = LossReport::new();
        big.push(LossEvent::span(
            0,
            0,
            u64::MAX,
            u64::MAX,
            ReasonCode::TornTail,
        ));
        big.push(LossEvent::span(
            1,
            0,
            u64::MAX,
            u64::MAX,
            ReasonCode::TornTail,
        ));
        assert_eq!(big.total_bytes_skipped(), u64::MAX);
        assert_eq!(big.total_records_lost_estimate(), u64::MAX);
    }

    #[test]
    fn reason_codes_are_stable_and_distinct() {
        let all = [
            ReasonCode::TornTail,
            ReasonCode::CorruptRecordHeader,
            ReasonCode::CorruptRecordBody,
            ReasonCode::CorruptSegmentHeader,
            ReasonCode::SequenceGap,
        ];
        // Frozen numeric codes (a renumber would break a deployed metrics consumer).
        assert_eq!(ReasonCode::TornTail.code(), 1);
        assert_eq!(ReasonCode::CorruptRecordHeader.code(), 2);
        assert_eq!(ReasonCode::CorruptRecordBody.code(), 3);
        assert_eq!(ReasonCode::CorruptSegmentHeader.code(), 4);
        assert_eq!(ReasonCode::SequenceGap.code(), 5);
        // No two reasons share a code.
        let mut seen = std::collections::BTreeSet::new();
        for r in all {
            assert!(seen.insert(r.code()), "duplicate reason code for {r:?}");
        }
    }

    #[test]
    fn global_loss_cap_is_one_percent_rounding_down() {
        assert_eq!(LossReport::global_loss_cap_bytes(0), 0);
        assert_eq!(LossReport::global_loss_cap_bytes(100), 1);
        assert_eq!(LossReport::global_loss_cap_bytes(12_345), 123);
        assert_eq!(LossReport::PER_EVENT_BYTE_CAP, 64 * 1024 * 1024);
    }

    #[test]
    fn json_round_trips_and_is_stable() {
        let mut r = LossReport::new();
        r.push(LossEvent::span(
            7,
            4096,
            8192,
            3,
            ReasonCode::CorruptRecordBody,
        ));
        let json = serde_json::to_string(&r).unwrap();
        // The shape a consumer reads: the version, the named reason, and the span fields.
        assert!(json.contains("\"schema_version\":1"), "{json}");
        assert!(
            json.contains("\"reason_code\":\"CorruptRecordBody\""),
            "{json}"
        );
        assert!(json.contains("\"bytes_skipped\":4096"), "{json}");
        // Round-trips back to an equal value.
        let back: LossReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.schema_version, LossReport::SCHEMA_VERSION);
    }

    /// The frozen golden for the `ironbus.loss-report.v1` schema: the EXACT serialized JSON of a
    /// representative report, byte for byte (pretty-printed for a human-readable, reviewable
    /// diff). This is the external contract the doc `docs/schemas/loss-report.v1.md` names. The
    /// weaker `json_round_trips_and_is_stable` above asserts only that three substrings appear,
    /// so it would not catch a field RENAME, a field REMOVAL, a field REORDER, or a `serde`
    /// rename attribute creeping in. This golden pins the whole shape: any such change is a CI
    /// failure here, forcing a deliberate `schema_version` bump rather than a silent break.
    ///
    /// The fixture exercises two events with distinct reasons so the per-event field set, the
    /// event ordering, and two of the five `ReasonCode` variant names are all pinned at once.
    #[test]
    fn golden_loss_report_v1_serialization_is_frozen() {
        // The frozen golden. Editing this string is a deliberate, reviewed schema change; a
        // change to the struct that is NOT mirrored here fails the assert.
        const GOLDEN: &str = r#"{
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
}"#;

        let mut r = LossReport::new();
        r.push(LossEvent::span(0, 4096, 8192, 1, ReasonCode::TornTail));
        r.push(LossEvent::span(
            2,
            65_536,
            131_072,
            7,
            ReasonCode::CorruptRecordBody,
        ));

        let json = serde_json::to_string_pretty(&r).unwrap();
        assert_eq!(
            json, GOLDEN,
            "the ironbus.loss-report.v1 JSON shape changed without a reviewed schema bump; if this \
             is intentional, bump LossReport::SCHEMA_VERSION, update docs/schemas/loss-report.v1.md, \
             and freeze a new golden"
        );

        // The golden also round-trips back to the exact value (the schema is symmetric).
        let back: LossReport = serde_json::from_str(GOLDEN).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.schema_version, LossReport::SCHEMA_VERSION);
    }

    /// Freeze the on-the-wire `serde` representation of every `ReasonCode` variant alongside its
    /// stable numeric `code()` and `metric_label()`. The numeric codes are already pinned by
    /// `reason_codes_are_stable_and_distinct`; this adds the third leg, the JSON variant NAME a
    /// `LossReport` consumer parses, so a `#[serde(rename = ...)]` or a variant rename can never
    /// silently change the externally-frozen `ironbus.loss-report.v1` reason vocabulary. Each
    /// triple (code, label, json-name) is the frozen contract `docs/schemas/loss-report.v1.md`
    /// enumerates.
    #[test]
    fn golden_reason_code_vocabulary_is_frozen() {
        // (numeric code, metric label, serde JSON name), in code order. Append-only: a new reason
        // adds a row; an existing row never changes.
        let frozen: [(u16, &str, &str); 5] = [
            (1, "torn_tail", "\"TornTail\""),
            (2, "corrupt_record_header", "\"CorruptRecordHeader\""),
            (3, "corrupt_record_body", "\"CorruptRecordBody\""),
            (4, "corrupt_segment_header", "\"CorruptSegmentHeader\""),
            (5, "sequence_gap", "\"SequenceGap\""),
        ];
        assert_eq!(
            ReasonCode::ALL.len(),
            frozen.len(),
            "a ReasonCode variant was added or removed without updating the frozen vocabulary"
        );
        for (rc, &(code, label, json_name)) in ReasonCode::ALL.iter().zip(frozen.iter()) {
            assert_eq!(rc.code(), code, "frozen numeric code for {rc:?}");
            assert_eq!(rc.metric_label(), label, "frozen metric label for {rc:?}");
            assert_eq!(
                serde_json::to_string(rc).unwrap(),
                json_name,
                "frozen serde JSON name for {rc:?}"
            );
            // The JSON name round-trips back to the same variant.
            let back: ReasonCode = serde_json::from_str(json_name).unwrap();
            assert_eq!(back, *rc, "reason code JSON name round-trips for {rc:?}");
        }
    }

    #[test]
    fn check_caps_accepts_loss_within_bounds() {
        let mut r = LossReport::new();
        r.push(LossEvent::span(0, 0, 100, 1, ReasonCode::TornTail));
        r.push(LossEvent::span(1, 0, 100, 1, ReasonCode::CorruptRecordBody));
        // Each event (100) is under the per-event cap, and the total (200) is under the global.
        assert_eq!(r.check_caps(150, 500), Ok(()));
        // An empty report is always within bounds.
        assert_eq!(LossReport::new().check_caps(0, 0), Ok(()));
    }

    #[test]
    fn check_caps_rejects_a_single_oversized_event() {
        let mut r = LossReport::new();
        r.push(LossEvent::span(0, 0, 50, 1, ReasonCode::TornTail));
        r.push(LossEvent::span(1, 0, 300, 1, ReasonCode::TornTail));
        // The second event (300) exceeds the per-event cap (200), even though the global cap
        // is generous. The per-event check fires first and names the offending event.
        assert_eq!(
            r.check_caps(200, 10_000),
            Err(CapViolation::PerEvent {
                bytes_skipped: 300,
                cap: 200,
            })
        );
    }

    #[test]
    fn bytes_skipped_for_sums_per_reason_and_labels_are_frozen() {
        let mut r = LossReport::new();
        r.push(LossEvent::span(0, 0, 10, 1, ReasonCode::TornTail));
        r.push(LossEvent::span(1, 0, 30, 1, ReasonCode::CorruptRecordBody));
        r.push(LossEvent::span(2, 0, 5, 1, ReasonCode::TornTail));
        assert_eq!(r.bytes_skipped_for(ReasonCode::TornTail), 15);
        assert_eq!(r.bytes_skipped_for(ReasonCode::CorruptRecordBody), 30);
        assert_eq!(r.bytes_skipped_for(ReasonCode::SequenceGap), 0);
        // The per-reason totals sum to the grand total.
        let by_reason: u64 = ReasonCode::ALL
            .iter()
            .map(|&rc| r.bytes_skipped_for(rc))
            .sum();
        assert_eq!(by_reason, r.total_bytes_skipped());
        // Labels are frozen and distinct, in code order.
        assert_eq!(ReasonCode::ALL.len(), 5);
        assert_eq!(ReasonCode::TornTail.metric_label(), "torn_tail");
        assert_eq!(
            ReasonCode::CorruptRecordHeader.metric_label(),
            "corrupt_record_header"
        );
        let labels: std::collections::BTreeSet<_> =
            ReasonCode::ALL.iter().map(|rc| rc.metric_label()).collect();
        assert_eq!(labels.len(), 5, "labels are distinct");
    }

    #[test]
    fn records_lost_for_sums_per_reason() {
        // Per-reason record counts mirror the per-reason byte counts: distinct estimates
        // sum by reason and across all reasons to the grand total.
        let mut r = LossReport::new();
        r.push(LossEvent::span(0, 0, 10, 2, ReasonCode::TornTail));
        r.push(LossEvent::span(1, 0, 30, 7, ReasonCode::CorruptRecordBody));
        r.push(LossEvent::span(2, 0, 5, 3, ReasonCode::TornTail));
        assert_eq!(r.records_lost_for(ReasonCode::TornTail), 5);
        assert_eq!(r.records_lost_for(ReasonCode::CorruptRecordBody), 7);
        assert_eq!(r.records_lost_for(ReasonCode::SequenceGap), 0);
        let by_reason: u64 = ReasonCode::ALL
            .iter()
            .map(|&rc| r.records_lost_for(rc))
            .sum();
        assert_eq!(by_reason, r.total_records_lost_estimate());
    }

    #[test]
    fn check_caps_rejects_a_cascade_over_the_global_cap() {
        // Many events, each under the per-event cap, summing past the global cap: a cascade of
        // skipped spans that turns bounded loss into unbounded loss.
        let mut r = LossReport::new();
        for i in 0..5u64 {
            r.push(LossEvent::span(i, 0, 100, 1, ReasonCode::CorruptRecordBody));
        }
        assert_eq!(r.total_bytes_skipped(), 500);
        // Per-event cap (200) holds for every event, but the total (500) exceeds the global (400).
        assert_eq!(
            r.check_caps(200, 400),
            Err(CapViolation::Global {
                total_bytes_skipped: 500,
                cap: 400,
            })
        );
    }
}
