// SPDX-License-Identifier: MIT OR Apache-2.0
//! The consolidated resilience invariant gate (#120, #21): a single named per-PR test that
//! drives the real recovery path over a generated sweep of segment shapes and asserts ALL FOUR
//! checkers (I1 to I4) over each recovery, in one place, so "recovered correctly" has one
//! definition and one gate rather than the checkers being scattered ad-hoc across other tests.
//!
//! The four checkers (`crates/ironbus-storage/src/invariants.rs`) are also exercised individually
//! by the crash gates (`crash_recovery.rs`) and as oracles in the corruption corpus
//! (`corruption_corpus.rs`). This file adds the missing piece: ONE pass that runs every checker
//! against every shape, plus a colocated negative-fixture block that proves each checker is
//! non-vacuous (a known-bad input it must reject), so the gate cannot silently degrade into a
//! checker that always passes.
//!
//! - The exhaustive per-PR gate (`invariant_gate_holds_over_the_shape_sweep`) enumerates a fixed
//!   matrix of segment shapes (record count x segment cap x durability boundary x post-crash
//!   mutation), runs each through `Log::open`, and asserts I1 to I4 on the recovered output.
//! - A proptest twin (`invariant_gate_holds_under_a_proptest_sweep`) generates random shapes with
//!   shrinking, so the nightly deep sweep (`PROPTEST_CASES=50000`) drives the same gate at depth.
//! - The negative fixtures (`negative_fixtures`) feed each checker a deliberately-broken input and
//!   assert it FAILS, so a checker that wrongly always passes would fail the gate here.

use ironbus_core::clock::ManualClock;
use ironbus_core::format::{RECORD_HEADER_LEN, RECORD_TRAILER_LEN};
use ironbus_core::types::{Offset, RecordFlags, Seq};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::invariants::{
    check_bounded_loss, check_longest_valid_prefix, check_no_acked_loss, check_pure_recovery,
    InvariantViolation,
};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::loss::{CapViolation, LossEvent, LossReport, ReasonCode};
use ironbus_storage::naming::segment_file_name;
use ironbus_storage::segment::OwnedRecord;
use proptest::prelude::*;

/// A deterministic, fixed-size payload for record `i` (the same 8-byte shape the crash gates and
/// the corpus use, so a recovered payload is exactly checkable).
fn payload(i: u64) -> Vec<u8> {
    i.to_le_bytes().to_vec()
}

/// How the workload reaches its durability boundary: where the producer last got an ack.
#[derive(Clone, Copy, Debug)]
enum Durability {
    /// Sync after every append: every appended record is acked-durable.
    Always,
    /// Append all, then a single sync at the end: the whole run is acked-durable.
    AtEnd,
    /// Sync after the first `k` records, then append more WITHOUT syncing: only the first `k`
    /// are acked-durable; the unsynced tail may or may not survive a power loss.
    First(u64),
}

/// What happens to the disk image after the workload, before recovery reopens it.
#[derive(Clone, Copy, Debug)]
enum Crash {
    /// A clean reopen (no fault): recovery must return the full appended prefix.
    Clean,
    /// A power loss: every unsynced write may vanish (the in-memory model reverts to the durable
    /// image exactly).
    PowerLoss,
    /// A torn tail: truncate the segment file by `bytes` (a mid-record tail loss).
    TornTail(u64),
}

/// One generated segment shape: a record count, a segment-size cap (so the workload may roll
/// across several segments), a durability boundary, and a post-workload crash.
#[derive(Clone, Copy, Debug)]
struct Shape {
    records: u64,
    max_segment_bytes: u64,
    durability: Durability,
    crash: Crash,
}

impl Shape {
    fn config(self) -> LogConfig {
        LogConfig {
            max_segment_bytes: self.max_segment_bytes,
            max_total_bytes: 0,
        }
    }

    /// The number of records the producer was told are durable (acked) for this shape.
    fn acked_durable(self) -> u64 {
        match self.durability {
            Durability::Always | Durability::AtEnd => self.records,
            Durability::First(k) => k.min(self.records),
        }
    }
}

/// Builds the disk image for `shape` by driving the real append/sync path, applies the crash, and
/// returns the durable `InMemoryFs` ready for recovery. Every input is explicit (a fixed
/// `ManualClock`, fixed payloads), so the image is a pure function of the shape.
fn build_disk(shape: Shape) -> InMemoryFs {
    let log = run_workload(shape);

    match shape.crash {
        Crash::Clean => {}
        Crash::PowerLoss => log.filesystem().simulate_power_loss(),
        Crash::TornTail(bytes) => {
            // Truncate the active (last-written) segment file by `bytes`, modeling a torn tail.
            // Clamp so we never truncate below the durable head of THIS segment: a torn tail loses
            // only unsynced bytes, never an acked-durable record (tearing into acked-durable data
            // would be a synthetic I1 violation we injected, not a recovery bug). The durable
            // length of the active segment is exactly what a power loss of the same workload
            // leaves (every unsynced tail byte reverted), so we re-run the workload, power-loss it,
            // and read that segment's length as the floor.
            let last_seg = active_segment_id(log.filesystem());
            let durable = run_workload(shape).into_filesystem();
            durable.simulate_power_loss();
            let floor = durable
                .open(&segment_file_name(last_seg))
                .map(|f| f.len().unwrap())
                .unwrap_or(0);
            let file = log.filesystem().open(&segment_file_name(last_seg)).unwrap();
            let len = file.len().unwrap();
            let new_len = len.saturating_sub(bytes).max(floor.min(len));
            file.set_len(new_len).unwrap();
            file.sync_all().unwrap();
        }
    }
    log.into_filesystem()
}

/// Runs `shape`'s append/sync workload on a fresh in-memory disk and returns the open log (before
/// any crash). A pure function of the shape: a fixed `ManualClock`, fixed payloads, no real clock.
fn run_workload(shape: Shape) -> Log<InMemoryFs, ManualClock> {
    let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), shape.config()).unwrap();
    let sync_first = match shape.durability {
        Durability::First(k) => k.min(shape.records),
        _ => 0,
    };
    for i in 0..shape.records {
        let p = payload(i);
        log.append(&Append {
            timestamp_ms: i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &p,
        })
        .unwrap();
        match shape.durability {
            Durability::Always => log.sync().unwrap(),
            Durability::First(_) if i + 1 == sync_first => log.sync().unwrap(),
            _ => {}
        }
    }
    if matches!(shape.durability, Durability::AtEnd) && shape.records > 0 {
        log.sync().unwrap();
    }
    log
}

/// The id of the highest-numbered segment file on `fs` (the active segment the torn-tail crash
/// truncates). Segment files are named `segment_file_name(id)`; this scans them back to the id.
fn active_segment_id(fs: &InMemoryFs) -> u64 {
    let mut best = 0u64;
    for name in fs.list().unwrap() {
        for id in 0..4096u64 {
            if segment_file_name(id) == name {
                best = best.max(id);
            }
        }
    }
    best
}

/// Opens `fs` through the real recovery path and returns the recovered records and loss report,
/// or a typed error (a damaged header is an acceptable fail-closed outcome, never a panic).
fn recover(fs: InMemoryFs, config: LogConfig) -> Result<(Vec<OwnedRecord>, LossReport), String> {
    let log = match Log::open(fs, ManualClock::new(), config) {
        Ok(log) => log,
        // A typed fail-closed error (a damaged segment header) is acceptable; the point of the
        // gate is that recovery did not panic and did not produce an invariant-violating prefix.
        Err(e) => return Err(format!("recovery failed closed: {e}")),
    };
    let records = log
        .read_from(Offset::ZERO, usize::MAX)
        .map_err(|e| format!("read_from failed: {e}"))?;
    Ok((records, log.loss_report().clone()))
}

/// The single consolidated invariant check: runs I1 to I4 over one recovery output and returns the
/// first violation. This is the ONE definition of "recovered correctly" the gate enforces.
///
/// - I1 (`check_no_acked_loss`): every acked-durable offset is present.
/// - I2 (`check_longest_valid_prefix`): the recovered run is a contiguous valid prefix from 0.
/// - I3 (`check_bounded_loss`): the loss report is within the per-event and global caps.
/// - I4 (`check_pure_recovery`): a second recovery from the SAME durable image is identical.
///
/// `second` is the second recovery of the identical durable bytes (the caller recovers twice).
fn assert_all_invariants(
    shape: Shape,
    recovered: &[OwnedRecord],
    second: &[OwnedRecord],
    loss: &LossReport,
) -> Result<(), InvariantViolation> {
    // I2 first: a valid prefix is the precondition the others read against.
    check_longest_valid_prefix(recovered)?;

    // I1: no acked-durable offset was lost. A power loss / torn tail may drop the UNSYNCED tail,
    // but never an offset the producer was told is durable.
    let acked: Vec<u64> = (0..shape.acked_durable()).collect();
    check_no_acked_loss(recovered, &acked)?;

    // I3: the reported loss is within the bounded-loss caps recovery itself enforces (one segment
    // or 64 MiB per event, floored so a single torn-tail event on a tiny log is always in bounds;
    // 1% of durable bytes globally, floored to at least the per-event cap for the same reason).
    let frame_len = (RECORD_HEADER_LEN + 8 + RECORD_TRAILER_LEN) as u64;
    let durable_bytes: u64 = loss
        .total_bytes_skipped()
        .saturating_add(recovered.len() as u64 * frame_len);
    let per_event_cap = shape.max_segment_bytes.min(LossReport::PER_EVENT_BYTE_CAP);
    let global_cap = LossReport::global_loss_cap_bytes(durable_bytes).max(per_event_cap);
    check_bounded_loss(loss, per_event_cap, global_cap)?;

    // I4: recovery is a pure function of the durable bytes (the two recoveries agree).
    check_pure_recovery(recovered, second)?;
    Ok(())
}

/// Recovers `shape` twice from its identical durable image and asserts I1 to I4 over the result.
/// Recovering twice is exactly what I4 needs; reusing one recovery for both would not test purity.
fn check_shape(shape: Shape) -> Result<(), String> {
    let (first, loss) = recover(build_disk(shape), shape.config())?;
    let (second, _) = recover(build_disk(shape), shape.config())?;
    // Survived payloads must be the original bytes (a checksum that wrongly accepted a corrupt
    // record, or a recovery that read past a torn tail, would surface here, not just in the
    // structural prefix check).
    for (i, r) in first.iter().enumerate() {
        let i = u64::try_from(i).map_err(|e| e.to_string())?;
        if r.payload != payload(i) {
            return Err(format!(
                "shape {shape:?}: record {i} payload was corrupted but accepted"
            ));
        }
    }
    assert_all_invariants(shape, &first, &second, &loss)
        .map_err(|v| format!("shape {shape:?}: {v}"))
}

/// The fixed matrix of segment shapes the per-PR gate sweeps. Spans record counts that fit in one
/// segment and that roll across several, both durability boundaries and the partial-sync boundary,
/// and the clean / power-loss / torn-tail crash classes.
fn shape_matrix() -> Vec<Shape> {
    let mut shapes = Vec::new();
    for &records in &[0u64, 1, 2, 5, 12, 30] {
        for &cap in &[256u64, 1 << 30] {
            let mut durabilities = vec![Durability::Always, Durability::AtEnd];
            if records >= 2 {
                durabilities.push(Durability::First(records / 2));
            }
            for &durability in &durabilities {
                for &crash in &[
                    Crash::Clean,
                    Crash::PowerLoss,
                    Crash::TornTail(1),
                    Crash::TornTail(7),
                ] {
                    shapes.push(Shape {
                        records,
                        max_segment_bytes: cap,
                        durability,
                        crash,
                    });
                }
            }
        }
    }
    shapes
}

#[test]
fn invariant_gate_holds_over_the_shape_sweep() {
    let shapes = shape_matrix();
    assert!(
        shapes.len() >= 100,
        "the shape matrix should be a broad sweep, got {}",
        shapes.len()
    );
    for shape in shapes {
        if let Err(why) = check_shape(shape) {
            panic!("the I1 to I4 invariant gate failed: {why}");
        }
    }
}

// === Negative fixtures: each checker must REJECT a known-bad input (non-vacuity) ===============

#[test]
fn negative_fixtures() {
    // A helper to build a recovered record with a given (offset, seq).
    fn rec(offset: u64, seq: u64) -> OwnedRecord {
        OwnedRecord {
            offset: Offset::new(offset),
            seq: Seq::new(seq),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: Vec::new(),
            headers: Vec::new(),
            payload: payload(offset),
        }
    }
    let prefix: Vec<OwnedRecord> = (0..4).map(|i| rec(i, i)).collect();

    // I1: an acked offset (4) is missing from a 0..3 recovery. The checker must reject it.
    assert_eq!(
        check_no_acked_loss(&prefix[..3], &[1, 4]),
        Err(InvariantViolation::AckedRecordLost {
            offset: 4,
            recovered_len: 3,
        }),
        "I1 must reject a lost acked write"
    );

    // I2: a gap in the offsets (0, 1, 3) is not a valid prefix. The checker must reject it.
    let gapped = vec![rec(0, 0), rec(1, 1), rec(3, 3)];
    assert_eq!(
        check_longest_valid_prefix(&gapped),
        Err(InvariantViolation::NotAPrefix {
            index: 2,
            expected_offset: 2,
            found_offset: 3,
        }),
        "I2 must reject a gap in the recovered run"
    );

    // I3: a loss report over the per-event cap must be rejected.
    let mut over_cap = LossReport::new();
    over_cap.push(LossEvent::span(0, 0, 300, 1, ReasonCode::CorruptRecordBody));
    assert_eq!(
        check_bounded_loss(&over_cap, 200, 10_000),
        Err(InvariantViolation::LossCapExceeded(
            CapViolation::PerEvent {
                bytes_skipped: 300,
                cap: 200,
            }
        )),
        "I3 must reject loss over the per-event cap"
    );

    // I3: a cascade over the global cap must be rejected too (bounded report, unbounded total).
    let mut cascade = LossReport::new();
    for i in 0..5u64 {
        cascade.push(LossEvent::span(i, 0, 100, 1, ReasonCode::CorruptRecordBody));
    }
    assert_eq!(
        check_bounded_loss(&cascade, 200, 400),
        Err(InvariantViolation::LossCapExceeded(CapViolation::Global {
            total_bytes_skipped: 500,
            cap: 400,
        })),
        "I3 must reject a cascade over the global cap"
    );

    // I4: two recoveries that diverge (different payload at index 1) must be rejected.
    let mut diverged = prefix.clone();
    diverged[1].payload = vec![0xff];
    assert_eq!(
        check_pure_recovery(&prefix, &diverged),
        Err(InvariantViolation::Nondeterministic { index: 1 }),
        "I4 must reject diverging recoveries"
    );

    // The negative fixtures prove the gate is non-vacuous: every checker rejected its bad input.
    // The crash gate above proves it accepts every GOOD recovery, so the gate is two-sided.
}

// === The proptest twin: the nightly deep sweep drives the same gate at depth ===================

proptest! {
    /// The proptest twin of the exhaustive shape sweep: a random shape (record count, segment cap,
    /// durability boundary, crash class) with shrinking. Per-PR it samples the space; the nightly
    /// deep sweep (`PROPTEST_CASES=50000`) drives the same I1 to I4 gate at depth, and a regression
    /// shrinks to a minimal shape. The raw generated inputs are mapped into a valid `Shape` (a
    /// `First(k)` is clamped so `1 <= k <= records`), so no input is rejected.
    #[test]
    fn invariant_gate_holds_under_a_proptest_sweep(
        records in 0u64..40,
        roll in any::<bool>(),
        durability_kind in 0u8..3,
        sync_at in 1u64..40,
        crash_kind in 0u8..4,
        torn in 1u64..16,
    ) {
        let durability = match durability_kind {
            0 => Durability::Always,
            1 => Durability::AtEnd,
            // First(k) with 1 <= k <= records; falls back to AtEnd when records < 2.
            _ if records >= 2 => Durability::First(sync_at.min(records)),
            _ => Durability::AtEnd,
        };
        let crash = match crash_kind {
            0 => Crash::Clean,
            1 => Crash::PowerLoss,
            2 => Crash::TornTail(torn),
            _ => Crash::TornTail(torn.saturating_mul(3)),
        };
        let shape = Shape {
            records,
            max_segment_bytes: if roll { 256 } else { 1 << 30 },
            durability,
            crash,
        };
        check_shape(shape).map_err(TestCaseError::fail)?;
    }
}
