// SPDX-License-Identifier: MIT OR Apache-2.0
//! The resilience invariant checkers (I1 to I4): reusable functions the simulation, the
//! corpus fixtures, and the property tests all assert against, so "recovered correctly" has
//! one definition rather than each layer inventing its own (#120, #21).
//!
//! The checkers are pure functions over observable recovery output (the recovered records,
//! the durable ack history, and the structured [`LossReport`]). They take the records a
//! recovery produced (`read_from` returns `OwnedRecord`s) and return the FIRST
//! [`InvariantViolation`] they find, or `Ok(())`. Being pure, the same check runs in a unit
//! test, a property sweep, or a corpus fixture. A checker that wrongly always passes is
//! guarded by the negative fixtures in this module's tests: each checker has a known-bad
//! input it must reject.

use crate::loss::{CapViolation, LossReport};
use crate::segment::OwnedRecord;
use std::collections::BTreeSet;

/// A resilience invariant that a recovered state violated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvariantViolation {
    /// I1: an acknowledged-durable offset is missing from the recovered log.
    AckedRecordLost {
        /// The acked offset that recovery did not produce.
        offset: u64,
        /// How many records recovery produced.
        recovered_len: u64,
    },
    /// I2: the recovered records are not a contiguous prefix from offset 0 (a gap, a reorder,
    /// or a record read past the torn tail).
    NotAPrefix {
        /// The position in the recovered run.
        index: u64,
        /// The offset that position must carry in a prefix from 0.
        expected_offset: u64,
        /// The offset actually found.
        found_offset: u64,
    },
    /// I2: a recovered record's sequence breaks the contiguous run from 0.
    SequenceBroken {
        /// The position in the recovered run.
        index: u64,
        /// The sequence that position must carry.
        expected_seq: u64,
        /// The sequence actually found.
        found_seq: u64,
    },
    /// I3: recovery's reported loss exceeded a bounded-loss cap.
    LossCapExceeded(CapViolation),
    /// I4: two recoveries from identical durable bytes produced different output, so recovery
    /// is not a pure function of the durable bytes.
    Nondeterministic {
        /// The first position at which the two recoveries diverged (or the shorter length if
        /// one run is a prefix of the other).
        index: u64,
    },
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvariantViolation::AckedRecordLost {
                offset,
                recovered_len,
            } => write!(
                f,
                "I1: acked offset {offset} is missing from the {recovered_len} recovered records"
            ),
            InvariantViolation::NotAPrefix {
                index,
                expected_offset,
                found_offset,
            } => write!(
                f,
                "I2: recovered record {index} has offset {found_offset}, expected {expected_offset}"
            ),
            InvariantViolation::SequenceBroken {
                index,
                expected_seq,
                found_seq,
            } => write!(
                f,
                "I2: recovered record {index} has sequence {found_seq}, expected {expected_seq}"
            ),
            InvariantViolation::LossCapExceeded(v) => write!(f, "I3: {v}"),
            InvariantViolation::Nondeterministic { index } => write!(
                f,
                "I4: two recoveries from identical durable bytes diverge at record {index}"
            ),
        }
    }
}

impl std::error::Error for InvariantViolation {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InvariantViolation::LossCapExceeded(e) => Some(e),
            _ => None,
        }
    }
}

/// I1: no acknowledged write is lost below its durability level. Every offset the producer was
/// told is durable must be present in the recovered log.
///
/// `acked_durable` is the set of offsets a producer was told were durable (an ack carries a
/// durable offset). Membership is checked by offset value, so this does not assume I2.
///
/// # Errors
/// Returns [`InvariantViolation::AckedRecordLost`] for the first acked offset that recovery
/// did not produce.
pub fn check_no_acked_loss(
    recovered: &[OwnedRecord],
    acked_durable: &[u64],
) -> Result<(), InvariantViolation> {
    let present: BTreeSet<u64> = recovered.iter().map(|r| r.offset.get()).collect();
    for &offset in acked_durable {
        if !present.contains(&offset) {
            return Err(InvariantViolation::AckedRecordLost {
                offset,
                recovered_len: recovered.len() as u64,
            });
        }
    }
    Ok(())
}

/// I2: recovery is the longest valid prefix. The recovered records are a contiguous run of
/// offsets `0, 1, ... n - 1` with matching sequences, so recovery never reordered a record,
/// left a gap, or read past a torn tail.
///
/// # Errors
/// Returns [`InvariantViolation::NotAPrefix`] or [`InvariantViolation::SequenceBroken`] at the
/// first record that breaks the run.
pub fn check_longest_valid_prefix(recovered: &[OwnedRecord]) -> Result<(), InvariantViolation> {
    for (i, r) in recovered.iter().enumerate() {
        let i = i as u64;
        if r.offset.get() != i {
            return Err(InvariantViolation::NotAPrefix {
                index: i,
                expected_offset: i,
                found_offset: r.offset.get(),
            });
        }
        if r.seq.get() != i {
            return Err(InvariantViolation::SequenceBroken {
                index: i,
                expected_seq: i,
                found_seq: r.seq.get(),
            });
        }
    }
    Ok(())
}

/// I3: skip loss is bounded and reported. The structured loss report must be within the
/// per-event and global caps (the caller computes the caps from the runtime config and the
/// durable byte count, as recovery does).
///
/// # Errors
/// Returns [`InvariantViolation::LossCapExceeded`] if the report exceeds either cap.
pub fn check_bounded_loss(
    report: &LossReport,
    per_event_cap: u64,
    global_cap: u64,
) -> Result<(), InvariantViolation> {
    report
        .check_caps(per_event_cap, global_cap)
        .map_err(InvariantViolation::LossCapExceeded)
}

/// I4: recovery is a pure function of the durable bytes. Recovering twice from the same durable
/// image must produce identical records.
///
/// # Errors
/// Returns [`InvariantViolation::Nondeterministic`] at the first record that differs (or at the
/// shorter length if one run is a strict prefix of the other).
pub fn check_pure_recovery(
    first: &[OwnedRecord],
    second: &[OwnedRecord],
) -> Result<(), InvariantViolation> {
    for (i, (a, b)) in first.iter().zip(second.iter()).enumerate() {
        if a != b {
            return Err(InvariantViolation::Nondeterministic { index: i as u64 });
        }
    }
    if first.len() != second.len() {
        return Err(InvariantViolation::Nondeterministic {
            index: first.len().min(second.len()) as u64,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loss::{LossEvent, ReasonCode};
    use bytes::Bytes;
    use ironbus_core::types::{Offset, RecordFlags, Seq};

    fn rec(offset: u64, seq: u64) -> OwnedRecord {
        OwnedRecord {
            offset: Offset::new(offset),
            seq: Seq::new(seq),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: Bytes::new(),
            headers: Bytes::new(),
            payload: Bytes::from(vec![u8::try_from(offset & 0xff).unwrap()]),
            subject: Bytes::new(),
        }
    }

    fn prefix(n: u64) -> Vec<OwnedRecord> {
        (0..n).map(|i| rec(i, i)).collect()
    }

    // I1 ---------------------------------------------------------------------------------

    #[test]
    fn i1_passes_when_every_acked_offset_is_present() {
        let recovered = prefix(5);
        check_no_acked_loss(&recovered, &[0, 2, 4]).unwrap();
        // The empty ack history is trivially satisfied.
        check_no_acked_loss(&recovered, &[]).unwrap();
    }

    #[test]
    fn i1_negative_fixture_an_acked_offset_was_lost() {
        // Recovery produced 0..3 but offset 4 was acked: an acked write was lost.
        let recovered = prefix(3);
        assert_eq!(
            check_no_acked_loss(&recovered, &[1, 4]),
            Err(InvariantViolation::AckedRecordLost {
                offset: 4,
                recovered_len: 3,
            })
        );
    }

    // I2 ---------------------------------------------------------------------------------

    #[test]
    fn i2_passes_on_a_contiguous_prefix() {
        check_longest_valid_prefix(&prefix(6)).unwrap();
        check_longest_valid_prefix(&[]).unwrap();
    }

    #[test]
    fn i2_negative_fixture_a_gap_in_offsets() {
        // 0, 1, then 3: a gap, so not a prefix.
        let recovered = vec![rec(0, 0), rec(1, 1), rec(3, 3)];
        assert_eq!(
            check_longest_valid_prefix(&recovered),
            Err(InvariantViolation::NotAPrefix {
                index: 2,
                expected_offset: 2,
                found_offset: 3,
            })
        );
    }

    #[test]
    fn i2_negative_fixture_a_broken_sequence() {
        // Offsets are a prefix but the sequence at index 1 is wrong (a recycled frame).
        let recovered = vec![rec(0, 0), rec(1, 9), rec(2, 2)];
        assert_eq!(
            check_longest_valid_prefix(&recovered),
            Err(InvariantViolation::SequenceBroken {
                index: 1,
                expected_seq: 1,
                found_seq: 9,
            })
        );
    }

    // I3 ---------------------------------------------------------------------------------

    #[test]
    fn i3_passes_within_caps_and_rejects_over_cap() {
        let mut report = LossReport::new();
        report.push(LossEvent::span(0, 0, 100, 1, ReasonCode::TornTail));
        check_bounded_loss(&report, 200, 1000).unwrap();

        // A single event over the per-event cap is an I3 violation.
        assert_eq!(
            check_bounded_loss(&report, 50, 1000),
            Err(InvariantViolation::LossCapExceeded(
                CapViolation::PerEvent {
                    bytes_skipped: 100,
                    cap: 50,
                }
            ))
        );
    }

    // I4 ---------------------------------------------------------------------------------

    #[test]
    fn i4_passes_for_identical_recoveries() {
        check_pure_recovery(&prefix(4), &prefix(4)).unwrap();
        check_pure_recovery(&[], &[]).unwrap();
    }

    #[test]
    fn i4_negative_fixture_diverging_payloads() {
        let a = prefix(3);
        let mut b = prefix(3);
        b[1].payload = Bytes::from_static(&[0xff]); // a different payload at index 1
        assert_eq!(
            check_pure_recovery(&a, &b),
            Err(InvariantViolation::Nondeterministic { index: 1 })
        );
    }

    #[test]
    fn i4_negative_fixture_different_lengths() {
        // One run is a strict prefix of the other: still nondeterministic.
        assert_eq!(
            check_pure_recovery(&prefix(3), &prefix(5)),
            Err(InvariantViolation::Nondeterministic { index: 3 })
        );
    }
}
