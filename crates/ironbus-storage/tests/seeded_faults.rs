// SPDX-License-Identifier: MIT OR Apache-2.0
//! The seeded fault scheduler, the same-seed determinism gate, and the per-PR fixed-seed recovery
//! sweep (#384, the #119 residual).
//!
//! The existing crash-recovery gates (`crash_recovery.rs`) ARM a specific fault at a chosen
//! boundary and the determinism gate (`determinism.rs`) compares the disk IMAGE. This file adds
//! the seeded half: one `u64` seed drives a whole crash workload (the workload shape AND every
//! fault decision) through the in-tree `SplitMix64` PRNG, so a failing case replays from the
//! printed seed alone.
//!
//! Three gates with teeth:
//! - [`the_same_seed_reproduces_the_same_trace_and_recovered_log`]: the SAME workload under the
//!   SAME seed, run TWICE, produces an IDENTICAL fault/op event trace AND an identical
//!   recovered-log hash. A DIFFERENT seed produces a different trace with high probability (so the
//!   gate is not vacuous).
//! - [`a_fixed_seed_recovery_sweep_holds_the_invariants`]: 256 fixed seeds, each driving faults
//!   through the crash + recovery path, assert the resilience invariants I1 to I4 hold, under a
//!   few-second per-PR budget. A failing seed PRINTS the seed for replay.
//! - [`a_recovery_side_seeded_fault_holds_the_invariants_or_fails_closed`]: a fault armed DURING
//!   recovery (read error / short read) must hold the invariants on success or fail closed with a
//!   typed error, never panic.

use ironbus_core::clock::ManualClock;
use ironbus_core::types::{Offset, RecordFlags, Seq};
use ironbus_storage::fault::{FaultControl, FaultFs};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::invariants::{
    check_bounded_loss, check_longest_valid_prefix, check_no_acked_loss, check_pure_recovery,
};
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::loss::LossReport;
use ironbus_storage::segment::{OwnedRecord, StorageError};
use ironbus_storage::sim::{FaultProbabilities, FaultSchedule, OpClass, SplitMix64};

/// A small segment cap so a workload rolls across several segments (exercising the seal/roll
/// durability boundary, where a faulted sync freezes the writer mid-roll).
fn small_config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 256,
        max_total_bytes: 0,
        ..LogConfig::default()
    }
}

/// A deterministic, fixed-size payload for record `i` (matches `crash_recovery.rs`).
fn payload(i: u64) -> Vec<u8> {
    i.to_le_bytes().to_vec()
}

/// The op the seed-derived workload performs at each step. Drawing the workload shape from the
/// SAME seed as the faults means a different seed varies BOTH, strengthening the not-vacuous
/// property: two seeds almost never agree on the whole run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkloadOp {
    Append,
    Sync,
}

/// One trace entry flattened to a comparable tuple: `(step, op_class_tag, fault)` where `fault` is
/// `Some((kind_tag, shaping_value))` or `None`. A plain tuple (not the `sim` types) so two outcomes
/// compare with a single `==` and a diff prints the raw decision.
type TraceEntry = (u64, u8, Option<(u8, u64)>);

/// The full, comparable outcome of one seeded crash + recovery run: the fault/op event trace the
/// schedule recorded, and a stable hash of the recovered log. Two same-seed runs produce equal
/// values of this; the same-seed gate asserts exactly that, and the sweep checks the invariants on
/// the recovered records inside [`run_seeded_crash_recovery`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct SeededOutcome {
    /// A flat, comparable encoding of the schedule's event trace (the sequence of fault decisions).
    trace: Vec<TraceEntry>,
    /// A stable 64-bit hash of the recovered records (offset, seq, payload of every record).
    recovered_hash: u64,
    /// How many records recovered, surfaced so the gate can assert the run is non-trivial.
    recovered_len: u64,
}

/// Derives a bounded workload (8 to 39 ops) from a dedicated `SplitMix64` stream, so the workload
/// shape is a pure function of the seed and bounded for the per-PR budget. Appends dominate (so the
/// log actually grows and rolls); syncs are interspersed so there is a real acked prefix.
fn workload_from_seed(seed: u64) -> Vec<WorkloadOp> {
    // A distinct stream from the fault stream (XOR a constant) so the workload and the fault
    // schedule do not march in lockstep off the same draws.
    let mut rng = SplitMix64::new(seed ^ 0x5DEE_CE66_D5B0_1357);
    let len = 8 + usize::try_from(rng.below(32)).unwrap_or(0);
    (0..len)
        .map(|_| {
            // ~30% syncs, ~70% appends.
            if rng.below(10) < 3 {
                WorkloadOp::Sync
            } else {
                WorkloadOp::Append
            }
        })
        .collect()
}

/// Encodes one schedule event as a comparable tuple `(step, op_class_tag, fault)`.
fn encode_trace(schedule: &FaultSchedule) -> Vec<TraceEntry> {
    schedule
        .trace()
        .iter()
        .map(|e| {
            let op = match e.op_class {
                OpClass::Read => 0u8,
                OpClass::Write => 1,
                OpClass::Sync => 2,
            };
            let fault = e.fault.map(|f| {
                use ironbus_storage::sim::FaultKind::{
                    FailRead, FailSync, FailWrite, ShortRead, TornWrite,
                };
                match f {
                    FailSync => (0u8, 0u64),
                    FailWrite => (1, 0),
                    FailRead => (2, 0),
                    ShortRead(n) => (3, n),
                    TornWrite(n) => (4, n),
                }
            });
            (e.step, op, fault)
        })
        .collect()
}

/// A stable, order-sensitive 64-bit hash of the recovered log (FNV-1a over the observable fields of
/// every record). Two recoveries that produce the same records hash equally; any divergence (a lost
/// record, a different payload, a reorder) changes the hash. Hand-rolled so it adds no dependency
/// and is identical across platforms.
fn hash_records(records: &[OwnedRecord]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
    };
    for r in records {
        mix(&r.offset.get().to_le_bytes());
        mix(&r.seq.get().to_le_bytes());
        mix(&r.timestamp_ms.to_le_bytes());
        mix(&r.key);
        mix(&[0xFF]); // a field separator so concatenations cannot collide
        mix(&r.headers);
        mix(&[0xFF]);
        mix(&r.payload);
        mix(&[0xFE]); // a record separator
    }
    h
}

/// Runs one full seeded crash + recovery scenario and returns its comparable outcome. The seed
/// drives the workload shape and EVERY fault decision through the schedule.
///
/// 1. Open a faulted log; run the seed-derived workload. Before each op, the schedule decides a
///    fault on that op's class (Write for an append, Sync for a sync); if it faults, arm it, run the
///    op (a clean/torn write just fails to advance; a faulted sync freezes the writer fatally),
///    then disarm. Track the acked (durable) prefix.
/// 2. Crash: revert the inner disk to its durable image (a power loss drops every unsynced byte).
/// 3. Recover with a CLEAN reopen, read the records, and (when `check` is set) assert I1 to I4.
///
/// `check` is `false` only for the same-seed gate's twin runs, which compare the OUTCOME directly
/// (a stronger equality than the invariants); the sweep passes `true`.
fn run_seeded_crash_recovery(seed: u64, check: bool) -> SeededOutcome {
    let config = small_config();
    let probs = FaultProbabilities {
        // Writes and syncs fault often enough to exercise the crash paths every few ops; reads do
        // not fault on the WRITE workload (they are exercised by the recovery-side gate below).
        read: 0,
        write: FaultProbabilities::uniform_percent(20).write,
        sync: FaultProbabilities::uniform_percent(25).sync,
    };
    let (control, mut schedule) = FaultControl::seeded_schedule(seed, probs);
    // The control must back the FaultFs; build the fs around a clone so the schedule's arming
    // reaches the file ops (FaultControl is shared by clone).
    let inner = InMemoryFs::new();
    let faultfs = FaultFs::with_control(inner.clone(), control.clone());
    let mut log = Log::open(faultfs, ManualClock::new(), config).unwrap();

    let workload = workload_from_seed(seed);
    let mut next = 0u64;
    let mut acked = 0u64; // the highest flushed offset confirmed durable

    for op in &workload {
        match op {
            WorkloadOp::Append => {
                let fault = schedule.decide(OpClass::Write);
                if let Some(f) = fault {
                    FaultSchedule::apply_to(&control, f);
                }
                let p = payload(next);
                let res = log.append(&Append {
                    timestamp_ms: next,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload: &p,
                });
                control.disarm_transient_faults();
                // A successful append advances the offset; a faulted one (clean or torn) does not.
                if res.is_ok() {
                    next += 1;
                }
                // If the writer froze (a prior faulted sync), no further op can advance durability.
            }
            WorkloadOp::Sync => {
                let fault = schedule.decide(OpClass::Sync);
                if let Some(f) = fault {
                    FaultSchedule::apply_to(&control, f);
                }
                let res = log.sync();
                control.disarm_transient_faults();
                if res.is_ok() {
                    // Everything appended so far is now durable (acked).
                    acked = log.flushed_offset().get();
                }
                // A faulted sync freezes the writer; the durable mark cannot advance past `acked`.
            }
        }
    }

    // Crash: drop every unsynced byte, reverting to the durable image.
    let faultfs = log.into_filesystem();
    faultfs.inner().simulate_power_loss();
    let recovered_fs = faultfs.into_inner();

    // Recover cleanly (no fault during recovery here; that is the separate recovery-side gate).
    let recovered = recover_records(&recovered_fs, config);
    let recovered_len = recovered.len() as u64;

    if check {
        // I2: the recovered run is the longest valid prefix from offset 0.
        check_longest_valid_prefix(&recovered)
            .unwrap_or_else(|v| panic!("seed {seed:#018x}: I2 violated: {v}"));
        // I1: every durably acked offset survived the crash.
        let acked_offsets: Vec<u64> = (0..acked).collect();
        check_no_acked_loss(&recovered, &acked_offsets)
            .unwrap_or_else(|v| panic!("seed {seed:#018x}: I1 violated: {v}"));
        // The payloads of the survived records are intact (a checksum that wrongly accepted a
        // corrupt record would surface as a mismatched payload here).
        for (i, r) in recovered.iter().enumerate() {
            let i = u64::try_from(i).unwrap();
            assert_eq!(r.offset, Offset::new(i), "seed {seed:#018x}: offset gap");
            assert_eq!(r.seq, Seq::new(i), "seed {seed:#018x}: seq gap");
            assert_eq!(
                r.payload,
                payload(i),
                "seed {seed:#018x}: corrupt payload survived"
            );
        }
        // I3: recovery's reported loss is within the bounded-loss caps. A clean power-loss revert
        // reports no loss, but assert the cap holds regardless, so the invariant is exercised.
        let report = clean_open_loss_report(&recovered_fs, config);
        let durable_bytes = total_durable_bytes(&recovered_fs);
        let per_event_cap = config.max_segment_bytes;
        let global_cap = LossReport::global_loss_cap_bytes(durable_bytes).max(per_event_cap);
        check_bounded_loss(&report, per_event_cap, global_cap)
            .unwrap_or_else(|v| panic!("seed {seed:#018x}: I3 violated: {v}"));
        // I4: recovering twice from the now-stable durable bytes yields identical records.
        let again = recover_records(&recovered_fs, config);
        check_pure_recovery(&recovered, &again)
            .unwrap_or_else(|v| panic!("seed {seed:#018x}: I4 violated: {v}"));
    }

    SeededOutcome {
        trace: encode_trace(&schedule),
        recovered_hash: hash_records(&recovered),
        recovered_len,
    }
}

/// Reopens `fs` cleanly and returns the recovered records (the durable prefix).
fn recover_records(fs: &InMemoryFs, config: LogConfig) -> Vec<OwnedRecord> {
    Log::open(fs.clone(), ManualClock::new(), config)
        .unwrap()
        .read_from(Offset::ZERO, usize::MAX)
        .unwrap()
}

/// Reopens `fs` cleanly and returns the recovery loss report (for the I3 cap check).
fn clean_open_loss_report(fs: &InMemoryFs, config: LogConfig) -> LossReport {
    Log::open(fs.clone(), ManualClock::new(), config)
        .unwrap()
        .loss_report()
        .clone()
}

/// Sums the durable byte length of every segment file, the denominator for the I3 global cap.
fn total_durable_bytes(fs: &InMemoryFs) -> u64 {
    use ironbus_storage::io::RandomAccessFile;
    fs.list()
        .unwrap()
        .iter()
        .map(|name| fs.open(name).unwrap().len().unwrap())
        .sum()
}

#[test]
fn the_same_seed_reproduces_the_same_trace_and_recovered_log() {
    // The same-seed determinism gate (#384): the SAME workload under the SAME seed, run twice,
    // produces an IDENTICAL fault/op event TRACE and an identical recovered-log HASH (not just the
    // disk image, which `determinism.rs` already covers). A different seed produces a different
    // trace with high probability, so the gate is not vacuous.
    //
    // Pick the seed deterministically: scan a fixed list and take the first whose run recovers a
    // NON-EMPTY prefix, so the recovered-log hash comparison is genuinely load-bearing (a seed
    // whose first sync faulted recovers nothing, which would compare two empty hashes). The list and
    // the choice are fixed, so the gate stays fully reproducible.
    let candidates = [
        0x1111_1111_1111_1111u64,
        0x2222_2222_2222_2222,
        0x3333_3333_3333_3333,
        0xCAFE_F00D_DEAD_BEEF,
        0x0123_4567_89AB_CDEF,
    ];
    let seed = *candidates
        .iter()
        .find(|&&s| run_seeded_crash_recovery(s, false).recovered_len >= 1)
        .expect("at least one candidate seed recovers a non-empty prefix");
    let first = run_seeded_crash_recovery(seed, false);
    let second = run_seeded_crash_recovery(seed, false);
    assert_eq!(
        first.trace, second.trace,
        "the same seed must reproduce the identical fault/op event trace"
    );
    assert_eq!(
        first.recovered_hash, second.recovered_hash,
        "the same seed must reproduce the identical recovered-log hash"
    );
    assert!(
        first.recovered_len >= 1,
        "the run must recover at least one record so the hash comparison is non-trivial"
    );

    // Not vacuous: a different seed yields a different fault schedule (and so, with high
    // probability, a different trace). Scan a handful of seeds and require that at least one
    // differs from the reference trace; identical traces across distinct seeds would mean the
    // seed does not actually drive the schedule.
    let mut any_trace_differs = false;
    for other in [0xDEAD_BEEFu64, 0x0BAD_F00D, 1, 2, 99] {
        let o = run_seeded_crash_recovery(other, false);
        if o.trace != first.trace {
            any_trace_differs = true;
        }
    }
    assert!(
        any_trace_differs,
        "a different seed must produce a different fault schedule (the gate would be vacuous \
         otherwise)"
    );
}

#[test]
fn a_fixed_seed_recovery_sweep_holds_the_invariants() {
    // The per-PR fixed-seed sweep (#384): 256 deterministic seeds, each driving faults through the
    // crash + recovery path, assert I1 to I4 hold. This is a hard per-PR `cargo test` (not a flaky
    // cron): the seed set is fixed (0..256) and the workload + op counts are bounded, so it runs in
    // well under a few seconds. A failing seed PRINTS its value (the `seed {seed:#018x}` panic
    // messages inside the run) so the exact case replays from `cargo test -- --exact`.
    const SEEDS: u64 = 256;
    for seed in 0..SEEDS {
        // Spread the small ordinals across the u64 range so the streams are well-separated (a
        // SplitMix64 of a tiny seed is still a fine stream, but mixing avoids near-identical
        // low-bit neighbours).
        let mixed = SplitMix64::new(seed).next_u64();
        let outcome = run_seeded_crash_recovery(mixed, true);
        // A sanity floor: most seeds recover a non-empty prefix (a seed whose very first sync
        // faulted may legitimately recover nothing, which is still a valid empty prefix).
        assert!(
            outcome.recovered_len <= 64,
            "seed {mixed:#018x}: recovered an implausible number of records ({})",
            outcome.recovered_len
        );
    }
}

#[test]
fn the_fixed_seed_sweep_is_itself_deterministic() {
    // Running the sweep's outcomes twice must agree seed-for-seed: the whole sweep is reproducible,
    // so a green run is not a fluke and a red one always reproduces. Cheap (no invariant re-checks),
    // so it stays inside the per-PR budget.
    const SEEDS: u64 = 64;
    let pass = || -> Vec<(u64, u64)> {
        (0..SEEDS)
            .map(|seed| {
                let mixed = SplitMix64::new(seed).next_u64();
                let o = run_seeded_crash_recovery(mixed, false);
                (o.recovered_hash, o.recovered_len)
            })
            .collect()
    };
    assert_eq!(
        pass(),
        pass(),
        "the seed sweep must be deterministic across runs (no flakes)"
    );
}

#[test]
fn a_recovery_side_seeded_fault_holds_the_invariants_or_fails_closed() {
    // The recovery-side arm (#384, mirrors `recovery_under_an_arbitrary_seeded_fault_holds_the
    // _invariants`): a fault armed DURING recovery (a read error or a short read, drawn from the
    // seeded schedule) must either recover a valid prefix that loses no acked record (I1 + I2) or
    // fail closed with a typed error, NEVER panic. Sweep a fixed set of seeds.
    const SEEDS: u64 = 128;
    let config = small_config();
    for seed in 0..SEEDS {
        let mixed = SplitMix64::new(seed ^ 0xA5A5_A5A5_A5A5_A5A5).next_u64();

        // Build a clean, durable log (a fixed small workload), capture the acked prefix.
        let durable = 6u64;
        let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), config).unwrap();
        for i in 0..durable {
            let p = payload(i);
            log.append(&Append {
                timestamp_ms: i,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &p,
            })
            .unwrap();
        }
        log.sync().unwrap();
        let disk = log.into_filesystem();

        // Draw ONE recovery-side fault from the seeded schedule (read-class only, so it fires on the
        // read-heavy recovery path). Force a read fault by using a 100% read probability, so every
        // seed genuinely exercises a fault rather than passing vacuously.
        let probs = FaultProbabilities {
            read: FaultProbabilities::uniform_percent(100).read,
            write: 0,
            sync: 0,
        };
        let (control, mut schedule) = FaultControl::seeded_schedule(mixed, probs);
        let fault = schedule.decide(OpClass::Read).expect("read faults at 100%");
        let faultfs = FaultFs::with_control(disk, control.clone());
        FaultSchedule::apply_to(&control, fault);

        // Recover under the armed read fault. Reaching past this call without unwinding already
        // proves no-panic; an Err is the fail-closed outcome (a clean typed error).
        match Log::open(faultfs, ManualClock::new(), config) {
            Ok(log) => {
                // Recovery succeeded despite the fault: disarm, then hold the recovered STATE to
                // I1 + I2.
                control.disarm_transient_faults();
                let records = log.read_from(Offset::ZERO, usize::MAX).unwrap();
                check_longest_valid_prefix(&records).unwrap_or_else(|v| {
                    panic!("seed {mixed:#018x}: I2 violated under a recovery-side fault: {v}")
                });
                let acked: Vec<u64> = (0..durable).collect();
                check_no_acked_loss(&records, &acked).unwrap_or_else(|v| {
                    panic!("seed {mixed:#018x}: I1 violated under a recovery-side fault: {v}")
                });
            }
            Err(StorageError::Io(_)) => { /* fail-closed on the injected IO fault: acceptable */ }
            Err(other) => {
                panic!(
                    "seed {mixed:#018x}: recovery must fail closed with an IO error, got {other:?}"
                )
            }
        }
    }
}
