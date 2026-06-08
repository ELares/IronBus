// SPDX-License-Identifier: MIT OR Apache-2.0
//! The seeded fault-schedule seam for the deterministic simulation (#384, #119 residual).
//!
//! The [`FaultFs`](crate::fault::FaultFs) ARMING model (arm a specific fault, see
//! [`fault`](crate::fault)) pins individual crash classes at a chosen boundary. This module adds
//! the complementary SEEDED model: a single seeded PRNG drives every fault decision (which op
//! class fails, and which fault), so a whole crash workload is a pure function of one `u64` seed.
//! A failing case is replayable by re-running with the printed seed, and the SAME seed always
//! produces the SAME [event trace](FaultEvent), which is what makes the same-seed determinism gate
//! and the fixed-seed recovery sweep in `tests/seeded_faults.rs` meaningful (and not vacuous).
//!
//! This is TEST/SIM infrastructure only: nothing in the production hot path constructs a
//! [`FaultSchedule`] or steps [`SplitMix64`]. It lives in the storage crate so the crash-recovery
//! tests can reach it, exactly as [`FaultControl`](crate::fault::FaultControl) does.
//!
//! No external RNG crate is pulled in (no `rand`/`rand_chacha`): the generator is a ~15-line,
//! fully in-tree [`SplitMix64`], the standard, well-documented finalizer-based PRNG. It is
//! deterministic, reproducible across platforms (pure `u64` wrapping arithmetic, no float, no
//! ambient state), and trivially seedable, which is all a fault schedule needs.

use crate::fault::FaultControl;

/// `SplitMix64`: a tiny, deterministic, splittable PRNG (Steele, Lea, and Flood, 2014).
///
/// One `u64` of state is advanced by the golden-ratio increment and run through the `MurmurHash3`
/// finalizer to decorrelate successive outputs. It is NOT cryptographic and is not meant to be:
/// its only jobs here are to be deterministic in its seed, reproducible on every platform (pure
/// wrapping `u64` arithmetic, no floats, no host entropy), and cheap. That makes a fault schedule
/// a pure function of one seed, so a failing sweep case replays exactly from the printed seed.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// The golden-ratio odd increment (2^64 / phi), the constant the published `SplitMix64` uses.
    const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

    /// Seeds the generator. Every distinct seed yields its own deterministic stream.
    #[must_use]
    pub fn new(seed: u64) -> SplitMix64 {
        SplitMix64 { state: seed }
    }

    /// Returns the next 64-bit output and advances the state. Pure wrapping arithmetic, so the
    /// stream is identical on every platform and across runs.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(Self::GAMMA);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns the next output mapped into `[0, 1)` as a fixed-point fraction over `2^32`, i.e.
    /// `next_u32_fraction() / 2^32`. Returning the raw `u32` (not an `f64`) keeps the schedule
    /// integer-only, so it stays byte-for-byte deterministic across platforms (no float rounding).
    /// A per-op probability is expressed as the same kind of `u32` threshold; the op faults when
    /// this draw is strictly below the threshold.
    pub fn next_u32_fraction(&mut self) -> u32 {
        // Take the high 32 bits: the finalizer's high bits are the best-mixed.
        u32::try_from(self.next_u64() >> 32).unwrap_or(u32::MAX)
    }

    /// Returns a value uniformly in `[0, n)` for `n >= 1` (and `0` for `n == 0`). Uses the simple
    /// modulo reduction: the residual bias is negligible for the tiny `n` a fault schedule uses
    /// (short-read and torn-write byte counts), and it keeps the draw a pure integer operation.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// The op classes a [`FaultSchedule`] can fault, each carrying its own probability. They map to
/// the existing [`FaultControl`] injectors, so the seeded model reuses the same fault primitives
/// the arming tests already exercise (no new fault mechanics, only a new way to choose them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpClass {
    /// A `read_at` during recovery: may be failed outright or shortened (a partial read).
    Read,
    /// A `write_all_at` recovery does (truncation, roll-forward header): may fail clean or tear.
    Write,
    /// A `sync_data`/`sync_all` recovery does (truncation sync): may return an injected EIO.
    Sync,
}

/// A single fault the schedule chose to inject, named so a trace is human-readable and a failing
/// case prints exactly what was injected. Each variant maps one-to-one onto a [`FaultControl`]
/// injector, so re-arming from a trace entry is unambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// Every `sync_data`/`sync_all` returns an injected error (the fsync-EIO / fsyncgate mode).
    FailSync,
    /// Every `write_all_at` fails cleanly, persisting no bytes.
    FailWrite,
    /// Every `read_at` returns an injected error.
    FailRead,
    /// Every `read_at` returns at most this many bytes (a partial read), always `>= 1`.
    ShortRead(u64),
    /// The next `write_all_at` persists this many bytes then errors (a torn write).
    TornWrite(u64),
}

/// One entry in a schedule's event trace: at logical `step`, an op of `op_class` was offered to
/// the schedule, and `fault` is the decision (a fault to inject, or `None` for a clean op). The
/// trace is the canonical record the same-seed determinism gate compares: two runs of the same
/// workload under the same seed must produce IDENTICAL traces (same steps, same op classes, same
/// fault decisions), and a different seed must produce a different trace with high probability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultEvent {
    /// The logical step index (0-based), incremented once per [`FaultSchedule::decide`] call.
    pub step: u64,
    /// The op class offered at this step.
    pub op_class: OpClass,
    /// The fault chosen for this step, or `None` if the op runs cleanly.
    pub fault: Option<FaultKind>,
}

/// Per-op-class fault probabilities, each a `u32` threshold over `2^32`: an op of that class
/// faults when [`SplitMix64::next_u32_fraction`] draws strictly below the threshold. `0` means the
/// class never faults; `u32::MAX` means it (almost) always does. Integer thresholds keep the whole
/// schedule float-free, so it is byte-for-byte deterministic across platforms.
#[derive(Clone, Copy, Debug)]
pub struct FaultProbabilities {
    /// The fault probability for a [`OpClass::Read`] op.
    pub read: u32,
    /// The fault probability for a [`OpClass::Write`] op.
    pub write: u32,
    /// The fault probability for a [`OpClass::Sync`] op.
    pub sync: u32,
}

impl FaultProbabilities {
    /// Builds a uniform probability from a percent in `[0, 100]` (clamped), applied to every op
    /// class. `25` means each op faults about a quarter of the time. A convenience for sweeps that
    /// want one knob rather than three.
    #[must_use]
    pub fn uniform_percent(percent: u32) -> FaultProbabilities {
        let p = threshold_from_percent(percent);
        FaultProbabilities {
            read: p,
            write: p,
            sync: p,
        }
    }

    fn for_class(&self, class: OpClass) -> u32 {
        match class {
            OpClass::Read => self.read,
            OpClass::Write => self.write,
            OpClass::Sync => self.sync,
        }
    }
}

/// Maps a percent in `[0, 100]` to a `u32` threshold over `2^32`. Saturates at 100, so `100`
/// yields `u32::MAX` (the op always faults) and `0` yields `0` (never).
fn threshold_from_percent(percent: u32) -> u32 {
    let p = percent.min(100);
    // (p / 100) * 2^32 in integer arithmetic, rounded down. `p <= 100`, so the product fits in u64.
    let scaled = (u64::from(p) * (u64::from(u32::MAX) + 1)) / 100;
    u32::try_from(scaled.min(u64::from(u32::MAX))).unwrap_or(u32::MAX)
}

/// A seeded fault scheduler: one [`SplitMix64`] drives every fault decision so a whole crash
/// workload is a pure function of the `seed`. Call [`decide`](FaultSchedule::decide) once per op
/// the recovery path performs; it returns the fault to inject (or `None`) and appends a
/// [`FaultEvent`] to the trace. Re-running with the same seed and the same op sequence reproduces
/// the identical trace and the identical recovery, so a failing sweep case replays from the
/// printed seed alone.
///
/// The schedule itself injects nothing: a caller applies the returned [`FaultKind`] to a
/// [`FaultControl`] via [`apply_to`](FaultSchedule::apply_to) (or hand-arms it), keeping the
/// fault MECHANICS in `fault.rs` and only the seeded CHOICE here.
#[derive(Clone, Debug)]
pub struct FaultSchedule {
    seed: u64,
    rng: SplitMix64,
    probs: FaultProbabilities,
    step: u64,
    trace: Vec<FaultEvent>,
}

impl FaultSchedule {
    /// Builds a schedule for `seed` with per-op-class fault probabilities `probs`.
    #[must_use]
    pub fn new(seed: u64, probs: FaultProbabilities) -> FaultSchedule {
        FaultSchedule {
            seed,
            rng: SplitMix64::new(seed),
            probs,
            step: 0,
            trace: Vec::new(),
        }
    }

    /// The seed this schedule was built from, for printing on a failing case so it replays.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Decides whether the next op of `class` faults, advancing the PRNG deterministically and
    /// recording a [`FaultEvent`]. Returns the chosen [`FaultKind`] (to arm) or `None` (run
    /// clean). Every draw comes from the one seeded stream, so the decision sequence is a pure
    /// function of the seed and the op-class sequence.
    pub fn decide(&mut self, class: OpClass) -> Option<FaultKind> {
        let threshold = self.probs.for_class(class);
        // Always draw the probability sample so the stream stays aligned regardless of the
        // threshold, then, when faulting, draw the fault-shaping value. A class with threshold 0
        // still consumes exactly one draw, so changing one class's probability does not desync the
        // others' streams in a confusing way.
        let faults = self.rng.next_u32_fraction() < threshold;
        let fault = if faults {
            Some(self.pick_fault(class))
        } else {
            None
        };
        let event = FaultEvent {
            step: self.step,
            op_class: class,
            fault,
        };
        self.trace.push(event);
        self.step += 1;
        fault
    }

    /// Picks the concrete fault for a faulting op of `class`, drawing any shaping value (a
    /// short-read cap, a torn-write prefix) from the same seeded stream.
    fn pick_fault(&mut self, class: OpClass) -> FaultKind {
        match class {
            OpClass::Read => {
                // Half the read faults are a hard error, half a short read of 1..=7 bytes.
                if self.rng.next_u64() & 1 == 0 {
                    FaultKind::FailRead
                } else {
                    FaultKind::ShortRead(1 + self.rng.below(7))
                }
            }
            OpClass::Write => {
                // Half the write faults are a clean failure, half a torn write of 0..=15 bytes.
                if self.rng.next_u64() & 1 == 0 {
                    FaultKind::FailWrite
                } else {
                    FaultKind::TornWrite(self.rng.below(16))
                }
            }
            OpClass::Sync => FaultKind::FailSync,
        }
    }

    /// The event trace recorded so far: the canonical, comparable record of every decision. Two
    /// same-seed runs over the same op sequence have byte-identical traces; the same-seed gate
    /// asserts exactly that.
    #[must_use]
    pub fn trace(&self) -> &[FaultEvent] {
        &self.trace
    }

    /// Arms `fault` on `control` (mapping each [`FaultKind`] to its [`FaultControl`] injector), so
    /// a caller can turn a schedule decision into a real injected fault without re-deriving the
    /// mapping. The arming mechanics stay in `fault.rs`; this is only the dispatch.
    pub fn apply_to(control: &FaultControl, fault: FaultKind) {
        match fault {
            FaultKind::FailSync => control.set_fail_sync(true),
            FaultKind::FailWrite => control.set_fail_write(true),
            FaultKind::FailRead => control.set_fail_read(true),
            FaultKind::ShortRead(n) => control.set_short_read(n),
            FaultKind::TornWrite(n) => control.arm_torn_write(n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_is_deterministic_and_seed_dependent() {
        // The same seed yields the same stream; a different seed yields a different one.
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        let mut c = SplitMix64::new(43);
        let sa: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let sb: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        let sc: Vec<u64> = (0..8).map(|_| c.next_u64()).collect();
        assert_eq!(sa, sb, "same seed, same stream (reproducible)");
        assert_ne!(sa, sc, "different seed, different stream");
    }

    #[test]
    fn splitmix64_matches_the_published_reference_vector() {
        // The reference SplitMix64 from seed 0: the first three outputs are well known, so this
        // pins the constants against the published algorithm (a transcription error would surface
        // here, not as a silent "still deterministic but wrong" stream).
        let mut g = SplitMix64::new(0);
        assert_eq!(g.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(g.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(g.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn below_is_in_range_and_zero_is_zero() {
        let mut g = SplitMix64::new(7);
        assert_eq!(
            g.below(0),
            0,
            "below(0) is defined as 0, never a divide-by-zero"
        );
        for _ in 0..1000 {
            assert!(g.below(5) < 5);
        }
    }

    #[test]
    fn threshold_zero_never_faults_and_full_always_faults() {
        // A 0% class never faults; a 100% class always does, over a long run.
        let mut never = FaultSchedule::new(1, FaultProbabilities::uniform_percent(0));
        let mut always = FaultSchedule::new(1, FaultProbabilities::uniform_percent(100));
        for _ in 0..256 {
            assert!(never.decide(OpClass::Read).is_none(), "0% never faults");
            assert!(always.decide(OpClass::Read).is_some(), "100% always faults");
        }
    }

    #[test]
    fn the_same_seed_reproduces_the_same_trace() {
        // The core replay property: same seed + same op sequence => identical trace.
        let ops = [OpClass::Read, OpClass::Write, OpClass::Sync, OpClass::Read];
        let run = |seed: u64| {
            let mut s = FaultSchedule::new(seed, FaultProbabilities::uniform_percent(50));
            for &c in &ops {
                let _ = s.decide(c);
            }
            s.trace().to_vec()
        };
        assert_eq!(run(0xABCD), run(0xABCD), "same seed, identical trace");
        assert_ne!(
            run(0xABCD),
            run(0x1234),
            "different seed, different trace (the gate is not vacuous)"
        );
    }

    #[test]
    fn a_faulting_read_is_a_read_class_fault_and_write_a_write_class_fault() {
        // Every chosen fault belongs to its op class, so apply_to arms the right injector.
        let mut s = FaultSchedule::new(99, FaultProbabilities::uniform_percent(100));
        for _ in 0..64 {
            match s.decide(OpClass::Read) {
                Some(FaultKind::FailRead | FaultKind::ShortRead(_)) => {}
                other => panic!("a read fault must be FailRead or ShortRead, got {other:?}"),
            }
            match s.decide(OpClass::Write) {
                Some(FaultKind::FailWrite | FaultKind::TornWrite(_)) => {}
                other => panic!("a write fault must be FailWrite or TornWrite, got {other:?}"),
            }
            assert_eq!(s.decide(OpClass::Sync), Some(FaultKind::FailSync));
        }
    }

    #[test]
    fn short_read_cap_is_at_least_one_and_torn_prefix_is_bounded() {
        // A ShortRead of 0 would be a spurious EOF (the fault layer forbids it), and a TornWrite
        // prefix stays within the documented 0..=15 range.
        let mut s = FaultSchedule::new(5, FaultProbabilities::uniform_percent(100));
        for _ in 0..256 {
            if let Some(FaultKind::ShortRead(n)) = s.decide(OpClass::Read) {
                assert!(n >= 1, "a short read never returns zero bytes");
            }
            if let Some(FaultKind::TornWrite(n)) = s.decide(OpClass::Write) {
                assert!(n <= 15, "the torn prefix stays in range");
            }
        }
    }
}
