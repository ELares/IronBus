// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ROLLING-MEDIAN regression gate (#114): given a history of per-device runs, compute a 7-day
//! rolling median per device and FAIL when throughput regresses, p99 worsens, or p99.9 worsens beyond
//! the thresholds versus the last released tag, while tolerating the inherent noise of edge hardware.
//!
//! # Why a rolling median, not a single-run percent gate
//!
//! Edge CI is noisy: a single-run percent gate would flap on thermal throttling and SD garbage
//! collection, training people to ignore it. The gate instead computes the MEDIAN of the last 7 days
//! of runs PER DEVICE and compares that median against the last released tag's median, so one bad run
//! cannot fire it and one lucky run cannot hide a real regression.
//!
//! # The thresholds (from the issue)
//!
//! Versus the last released tag's per-device median, the gate FAILS when, on any device:
//! - throughput median drops more than [`THROUGHPUT_DROP_LIMIT`] (10%),
//! - p99 median rises more than [`P99_RISE_LIMIT`] (15%),
//! - p99.9 median rises more than [`P999_RISE_LIMIT`] (25%, the wider tail tolerance).
//!
//! # The escape hatches (also from the issue)
//!
//! - ADVISORY-ONLY noisy runs. A run whose warm-up coefficient-of-variation (CoV) check FAILED is
//!   marked advisory and is EXCLUDED from the medians, so a warm-up-failed run can neither fire the
//!   gate nor mask a regression. If every run in a window is advisory, the gate cannot conclude and
//!   no-ops with a logged reason rather than firing.
//! - HUMAN-RATIFY override. An edge regression requires a human to ratify before it blocks a release;
//!   [`GateOutcome`] therefore distinguishes a FIRED gate from a HARD-FAIL, and a documented override
//!   ([`Override::human_ratified`]) converts a fired gate into a pass with an audit reason.
//! - GRACEFUL NO-OP on an empty baseline. There is NO released tag / baseline history yet (v0.1.0 is
//!   the user's action), so with no prior history the gate PASSES with a logged
//!   "no baseline history yet" rather than erroring. This is the explicit, tested first-run behavior.
//!
//! This module is pure computation over plain data: it ingests a synthetic or real history and
//! returns a typed outcome, so the fire/no-fire/advisory/no-op logic is unit-testable without a
//! broker, a clock, or a network. It lives in the `publish = false` `ironbus-bench` crate, off the
//! shipped binary graph.

use serde::{Deserialize, Serialize};

/// The maximum tolerated DROP in the throughput median before the gate fires (10%). A current median
/// below `(1 - LIMIT)` times the baseline median fires the gate.
pub const THROUGHPUT_DROP_LIMIT: f64 = 0.10;

/// The maximum tolerated RISE in the p99 latency median before the gate fires (15%).
pub const P99_RISE_LIMIT: f64 = 0.15;

/// The maximum tolerated RISE in the p99.9 latency median before the gate fires (25%, the wider tail
/// tolerance the issue mandates because the deep tail is inherently noisier on edge hardware).
pub const P999_RISE_LIMIT: f64 = 0.25;

/// The rolling window, in days. Runs older than this (relative to the newest current run) are not
/// part of the current median.
pub const ROLLING_WINDOW_DAYS: u64 = 7;

/// Seconds in a day, for the window arithmetic.
const SECONDS_PER_DAY: u64 = 86_400;

/// One archived run's headline numbers plus the metadata the gate needs: which device it ran on, when
/// it ran (Unix seconds), and whether its warm-up `CoV` check passed (an advisory run failed it).
/// This
/// is the per-run record the gate ingests; it maps directly onto the provenance JSON a real run emits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunPoint {
    /// The device the run executed on (e.g. `edge-min-pi4`). Medians are computed PER DEVICE.
    pub device: String,
    /// The run's wall-clock time, Unix seconds. Defines the rolling window membership.
    pub unix_secs: u64,
    /// Achieved throughput, messages per second (higher is better).
    pub throughput_msgs_per_sec: f64,
    /// p99 latency, microseconds (lower is better).
    pub p99_us: f64,
    /// p99.9 latency, microseconds (lower is better).
    pub p999_us: f64,
    /// Whether the run's WARM-UP coefficient-of-variation check PASSED. A run that failed it is
    /// ADVISORY-ONLY: excluded from the medians so it can neither fire the gate nor mask a regression.
    pub warmup_cov_ok: bool,
}

/// The released-tag BASELINE the current window is compared against: a set of archived runs from the
/// last released tag, per device. Empty on the very first run (no released tag yet), which the gate
/// handles as a graceful no-op.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// The released tag this baseline came from (e.g. `v0.1.0`), or empty when there is none yet.
    pub tag: String,
    /// The baseline runs, across all devices. The gate medians them per device.
    pub runs: Vec<RunPoint>,
}

/// The current-run history the gate evaluates, as it is read from a JSON file by the CI binary. The
/// `now_unix_secs` field anchors the rolling window; when absent the binary falls back to wall-clock
/// now, but a checked-in fixture supplies it so the window is deterministic.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct History {
    /// The current per-device runs to evaluate (across the rolling window).
    pub runs: Vec<RunPoint>,
    /// The Unix-seconds anchor for the rolling window. `None` => the binary uses wall-clock now.
    #[serde(default)]
    pub now_unix_secs: Option<u64>,
}

/// An operator override that can convert a FIRED gate into a documented pass: the human-ratify escape
/// hatch the issue requires for an edge regression. Defaults to "no override".
#[derive(Clone, Debug, Default)]
pub struct Override {
    /// When set, a fired gate is RATIFIED (allowed to pass) and this is the audit reason. The reason
    /// is recorded in the outcome so the override is never silent.
    pub human_ratified: Option<String>,
}

/// The reason a per-device comparison fired (which metric breached, with the numbers), so a report
/// can show exactly what regressed rather than a bare boolean.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Breach {
    /// The throughput median dropped beyond the limit.
    ThroughputDrop {
        /// The device that regressed.
        device: String,
        /// The baseline median throughput.
        baseline: f64,
        /// The current median throughput.
        current: f64,
        /// The fractional drop (`(baseline - current) / baseline`).
        drop_fraction: f64,
    },
    /// The p99 median rose beyond the limit.
    P99Rise {
        /// The device that regressed.
        device: String,
        /// The baseline median p99 (us).
        baseline: f64,
        /// The current median p99 (us).
        current: f64,
        /// The fractional rise (`(current - baseline) / baseline`).
        rise_fraction: f64,
    },
    /// The p99.9 median rose beyond the limit.
    P999Rise {
        /// The device that regressed.
        device: String,
        /// The baseline median p99.9 (us).
        baseline: f64,
        /// The current median p99.9 (us).
        current: f64,
        /// The fractional rise (`(current - baseline) / baseline`).
        rise_fraction: f64,
    },
}

impl core::fmt::Display for Breach {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Breach::ThroughputDrop {
                device,
                baseline,
                current,
                drop_fraction,
            } => write!(
                f,
                "[{device}] throughput median dropped {:.1}% (baseline {baseline:.0} -> current \
                 {current:.0} msg/s; limit {:.0}%)",
                drop_fraction * 100.0,
                THROUGHPUT_DROP_LIMIT * 100.0
            ),
            Breach::P99Rise {
                device,
                baseline,
                current,
                rise_fraction,
            } => write!(
                f,
                "[{device}] p99 median rose {:.1}% (baseline {baseline:.0} -> current {current:.0} \
                 us; limit {:.0}%)",
                rise_fraction * 100.0,
                P99_RISE_LIMIT * 100.0
            ),
            Breach::P999Rise {
                device,
                baseline,
                current,
                rise_fraction,
            } => write!(
                f,
                "[{device}] p99.9 median rose {:.1}% (baseline {baseline:.0} -> current \
                 {current:.0} us; limit {:.0}%)",
                rise_fraction * 100.0,
                P999_RISE_LIMIT * 100.0
            ),
        }
    }
}

/// The gate's decision after evaluating a window against a baseline.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum GateOutcome {
    /// PASS: no baseline history yet (no released tag), so the gate gracefully no-ops. The string is
    /// the logged reason ("no baseline history yet"). This is the explicit first-run behavior.
    NoBaseline(String),
    /// PASS: a baseline exists but the current window has no NON-ADVISORY run to compare (every run
    /// in the window failed its warm-up `CoV` check), so the gate cannot conclude and no-ops with a
    /// logged reason rather than firing on noise.
    InsufficientData(String),
    /// PASS: every device's medians are within the thresholds.
    Pass,
    /// FIRED but RATIFIED: at least one breach occurred, but a human ratified it. Carries the
    /// breaches and the audit reason. Treated as a PASS for the exit code (the documented override),
    /// never silently: the reason is recorded.
    Ratified {
        /// The breaches that were ratified.
        breaches: Vec<Breach>,
        /// The human-supplied audit reason.
        reason: String,
    },
    /// HARD-FAIL: at least one breach occurred and no human ratified it, so the gate blocks. Carries
    /// the breaches for the report.
    Fail(Vec<Breach>),
}

impl GateOutcome {
    /// Whether this outcome BLOCKS (a non-zero CI exit). Only [`GateOutcome::Fail`] blocks; the
    /// no-baseline, insufficient-data, pass, and ratified outcomes all pass. So an empty baseline and
    /// a ratified regression both exit 0, exactly as the issue requires.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        matches!(self, GateOutcome::Fail(_))
    }

    /// A one-line human summary for the CI log.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            GateOutcome::NoBaseline(reason) | GateOutcome::InsufficientData(reason) => {
                format!("regression gate: PASS ({reason})")
            }
            GateOutcome::Pass => {
                "regression gate: PASS (all device medians within thresholds)".to_string()
            }
            GateOutcome::Ratified { breaches, reason } => format!(
                "regression gate: PASS (RATIFIED override: {reason}); {} breach(es) ratified: {}",
                breaches.len(),
                join_breaches(breaches)
            ),
            GateOutcome::Fail(breaches) => format!(
                "regression gate: FAIL; {} breach(es): {}",
                breaches.len(),
                join_breaches(breaches)
            ),
        }
    }
}

/// Joins breach displays with "; " for the one-line summary.
fn join_breaches(breaches: &[Breach]) -> String {
    breaches
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Evaluates the regression gate. Computes per-device 7-day rolling medians of the CURRENT runs and
/// compares each against the BASELINE (last released tag) per-device medians, applying the thresholds
/// and the advisory/no-op/ratify rules.
///
/// `now_unix_secs` anchors the rolling window: a current run is in-window if it is no older than
/// [`ROLLING_WINDOW_DAYS`] before `now_unix_secs`. Advisory runs (warm-up `CoV` failed) are excluded
/// from the medians on BOTH sides.
///
/// Returns a typed [`GateOutcome`]; it never panics and performs no IO.
#[must_use]
pub fn evaluate(
    current: &[RunPoint],
    baseline: &Baseline,
    now_unix_secs: u64,
    over: &Override,
) -> GateOutcome {
    // GRACEFUL NO-OP: no released tag / baseline history yet (the first-run case). PASS with a logged
    // reason rather than erroring or failing.
    if baseline.runs.is_empty() {
        return GateOutcome::NoBaseline(format!(
            "no baseline history yet (no released tag{}): nothing to compare against, so the gate \
             passes by design until the first release archives a baseline",
            if baseline.tag.is_empty() {
                String::new()
            } else {
                format!(" `{}`", baseline.tag)
            }
        ));
    }

    // Keep only in-window, NON-ADVISORY current runs (a warm-up-failed run is advisory-only).
    let window_start = now_unix_secs.saturating_sub(ROLLING_WINDOW_DAYS * SECONDS_PER_DAY);
    let current_eligible: Vec<&RunPoint> = current
        .iter()
        .filter(|r| r.warmup_cov_ok && r.unix_secs >= window_start && r.unix_secs <= now_unix_secs)
        .collect();

    // INSUFFICIENT DATA: a baseline exists but every current run is advisory or out of window, so we
    // cannot conclude. No-op (PASS) with a reason rather than firing on noise.
    if current_eligible.is_empty() {
        let advisory = current.iter().filter(|r| !r.warmup_cov_ok).count();
        return GateOutcome::InsufficientData(format!(
            "no non-advisory current run in the {ROLLING_WINDOW_DAYS}-day window ({advisory} run(s) \
             were advisory-only due to a failed warm-up CoV check, {} total): the gate cannot \
             conclude and passes rather than fire on noise",
            current.len()
        ));
    }

    // Per-device baseline medians, computed over the baseline's NON-ADVISORY runs only.
    let baseline_eligible: Vec<&RunPoint> =
        baseline.runs.iter().filter(|r| r.warmup_cov_ok).collect();

    let devices = distinct_devices(&current_eligible);
    let mut breaches = Vec::new();
    for device in devices {
        let cur: Vec<&RunPoint> = current_eligible
            .iter()
            .copied()
            .filter(|r| r.device == device)
            .collect();
        let base: Vec<&RunPoint> = baseline_eligible
            .iter()
            .copied()
            .filter(|r| r.device == device)
            .collect();
        // A device with no baseline runs (a NEW device since the last release) cannot regress against
        // a baseline that does not have it; skip it (it is new, not regressed).
        if base.is_empty() {
            continue;
        }
        check_device(&device, &cur, &base, &mut breaches);
    }

    if breaches.is_empty() {
        return GateOutcome::Pass;
    }
    // A regression fired. The human-ratify escape hatch converts it to a documented pass.
    match &over.human_ratified {
        Some(reason) => GateOutcome::Ratified {
            breaches,
            reason: reason.clone(),
        },
        None => GateOutcome::Fail(breaches),
    }
}

/// Checks one device's current medians against its baseline medians and pushes any breach. Shared so
/// the per-metric threshold logic lives in one place.
fn check_device(device: &str, cur: &[&RunPoint], base: &[&RunPoint], breaches: &mut Vec<Breach>) {
    let (Some(cur_tput), Some(base_tput)) = (
        median(cur.iter().map(|r| r.throughput_msgs_per_sec)),
        median(base.iter().map(|r| r.throughput_msgs_per_sec)),
    ) else {
        return;
    };
    // Throughput: higher is better, so a DROP is a regression. Guard a zero/negative baseline (no
    // meaningful fractional drop) by skipping it.
    if base_tput > 0.0 {
        let drop_fraction = (base_tput - cur_tput) / base_tput;
        if drop_fraction > THROUGHPUT_DROP_LIMIT {
            breaches.push(Breach::ThroughputDrop {
                device: device.to_string(),
                baseline: base_tput,
                current: cur_tput,
                drop_fraction,
            });
        }
    }

    if let (Some(cur_p99), Some(base_p99)) = (
        median(cur.iter().map(|r| r.p99_us)),
        median(base.iter().map(|r| r.p99_us)),
    ) {
        if base_p99 > 0.0 {
            let rise_fraction = (cur_p99 - base_p99) / base_p99;
            if rise_fraction > P99_RISE_LIMIT {
                breaches.push(Breach::P99Rise {
                    device: device.to_string(),
                    baseline: base_p99,
                    current: cur_p99,
                    rise_fraction,
                });
            }
        }
    }

    if let (Some(cur_p999), Some(base_p999)) = (
        median(cur.iter().map(|r| r.p999_us)),
        median(base.iter().map(|r| r.p999_us)),
    ) {
        if base_p999 > 0.0 {
            let rise_fraction = (cur_p999 - base_p999) / base_p999;
            if rise_fraction > P999_RISE_LIMIT {
                breaches.push(Breach::P999Rise {
                    device: device.to_string(),
                    baseline: base_p999,
                    current: cur_p999,
                    rise_fraction,
                });
            }
        }
    }
}

/// The distinct device names among a set of run references, in first-seen order (so the report is
/// deterministic for a given input).
fn distinct_devices(runs: &[&RunPoint]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for r in runs {
        if !seen.iter().any(|d| d == &r.device) {
            seen.push(r.device.clone());
        }
    }
    seen
}

/// The median of a sequence of `f64` values, ignoring any non-finite value (NaN/inf cannot be a real
/// measurement and would corrupt the order). Returns `None` for an empty (or all-non-finite) input.
/// The median of an even count is the mean of the two middle values.
#[must_use]
pub fn median(values: impl Iterator<Item = f64>) -> Option<f64> {
    let mut v: Vec<f64> = values.filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    // `total_cmp` gives a total order over the finite values we kept, so the sort is well-defined
    // without an `unwrap` on a partial comparison.
    v.sort_by(f64::total_cmp);
    let n = v.len();
    let mid = n / 2;
    if n % 2 == 1 {
        Some(v[mid])
    } else {
        Some((v[mid - 1] + v[mid]) / 2.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-advisory run point on a device at a given day offset (days before `NOW`).
    fn run(device: &str, day_offset: u64, tput: f64, p99: f64, p999: f64) -> RunPoint {
        RunPoint {
            device: device.to_string(),
            unix_secs: NOW.saturating_sub(day_offset * SECONDS_PER_DAY),
            throughput_msgs_per_sec: tput,
            p99_us: p99,
            p999_us: p999,
            warmup_cov_ok: true,
        }
    }

    /// A fixed "now" anchor for the window arithmetic in tests (an arbitrary Unix time).
    const NOW: u64 = 1_700_000_000;

    fn baseline(runs: Vec<RunPoint>) -> Baseline {
        Baseline {
            tag: "v0.1.0".to_string(),
            runs,
        }
    }

    fn no_override() -> Override {
        Override::default()
    }

    // ---- the graceful no-op on an empty baseline (criterion #5) has teeth ----

    #[test]
    fn an_empty_baseline_passes_with_a_no_baseline_log() {
        // The dominant first-run requirement: NO released tag/baseline yet => PASS, not error/fail.
        let current = vec![run("edge-min-pi4", 0, 60_000.0, 5_000.0, 9_000.0)];
        let outcome = evaluate(&current, &Baseline::default(), NOW, &no_override());
        assert!(
            matches!(outcome, GateOutcome::NoBaseline(_)),
            "got {outcome:?}"
        );
        assert!(
            !outcome.is_blocking(),
            "an empty baseline must never block CI"
        );
        assert!(outcome.summary().contains("no baseline history yet"));
    }

    #[test]
    fn an_empty_current_against_an_empty_baseline_still_no_ops() {
        let outcome = evaluate(&[], &Baseline::default(), NOW, &no_override());
        assert!(matches!(outcome, GateOutcome::NoBaseline(_)));
        assert!(!outcome.is_blocking());
    }

    // ---- the gate PASSES on no drift ----

    #[test]
    fn matched_medians_pass() {
        let base = baseline(vec![
            run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0),
            run("edge-min-pi4", 31, 61_000.0, 4_900.0, 9_100.0),
        ]);
        let current = vec![
            run("edge-min-pi4", 0, 60_500.0, 5_050.0, 9_050.0),
            run("edge-min-pi4", 1, 59_800.0, 5_010.0, 9_200.0),
        ];
        let outcome = evaluate(&current, &base, NOW, &no_override());
        assert_eq!(outcome, GateOutcome::Pass, "{}", outcome.summary());
        assert!(!outcome.is_blocking());
    }

    // ---- the gate FIRES on synthetic drift (criterion #4) has teeth ----

    #[test]
    fn a_throughput_drop_beyond_10pct_fires() {
        let base = baseline(vec![
            run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0),
            run("edge-min-pi4", 31, 60_000.0, 5_000.0, 9_000.0),
        ]);
        // Current median ~50,000 => 16.7% drop, beyond the 10% limit.
        let current = vec![
            run("edge-min-pi4", 0, 50_000.0, 5_000.0, 9_000.0),
            run("edge-min-pi4", 1, 50_000.0, 5_000.0, 9_000.0),
        ];
        let outcome = evaluate(&current, &base, NOW, &no_override());
        assert!(outcome.is_blocking(), "a 16.7% drop must fire: {outcome:?}");
        let GateOutcome::Fail(breaches) = &outcome else {
            panic!("expected Fail, got {outcome:?}");
        };
        assert!(
            breaches
                .iter()
                .any(|b| matches!(b, Breach::ThroughputDrop { .. })),
            "expected a throughput-drop breach"
        );
    }

    #[test]
    fn a_p99_rise_beyond_15pct_fires() {
        let base = baseline(vec![run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0)]);
        // p99 6000 vs 5000 => 20% rise, beyond the 15% limit.
        let current = vec![run("edge-min-pi4", 0, 60_000.0, 6_000.0, 9_000.0)];
        let outcome = evaluate(&current, &base, NOW, &no_override());
        assert!(outcome.is_blocking(), "{outcome:?}");
        let GateOutcome::Fail(breaches) = &outcome else {
            panic!("expected Fail");
        };
        assert!(breaches.iter().any(|b| matches!(b, Breach::P99Rise { .. })));
    }

    #[test]
    fn a_p999_rise_beyond_25pct_fires_but_a_20pct_one_does_not() {
        // p99.9 has the wider 25% tolerance: a 20% rise must NOT fire, a 30% rise must.
        let base = baseline(vec![run("edge-min-pi4", 30, 60_000.0, 5_000.0, 10_000.0)]);
        let ok = vec![run("edge-min-pi4", 0, 60_000.0, 5_000.0, 12_000.0)]; // +20%
        assert_eq!(
            evaluate(&ok, &base, NOW, &no_override()),
            GateOutcome::Pass,
            "a 20% p99.9 rise is within the 25% tail tolerance"
        );
        let bad = vec![run("edge-min-pi4", 0, 60_000.0, 5_000.0, 13_000.0)]; // +30%
        assert!(evaluate(&bad, &base, NOW, &no_override()).is_blocking());
    }

    #[test]
    fn the_thresholds_are_exactly_the_issue_values() {
        // Pin the numbers so a silent loosening of the gate is a test failure.
        assert!((THROUGHPUT_DROP_LIMIT - 0.10).abs() < 1e-12);
        assert!((P99_RISE_LIMIT - 0.15).abs() < 1e-12);
        assert!((P999_RISE_LIMIT - 0.25).abs() < 1e-12);
        assert_eq!(ROLLING_WINDOW_DAYS, 7);
    }

    // ---- advisory (noisy) runs are advisory-only (criterion #4) ----

    #[test]
    fn an_advisory_run_does_not_fire_the_gate() {
        // A single catastrophic run that would fire the gate, but its warm-up CoV check FAILED, so it
        // is advisory-only and excluded. With no other current run, the gate no-ops (insufficient
        // data), never fires. This test FAILS if an advisory run is allowed to block.
        let base = baseline(vec![run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0)]);
        let mut noisy = run("edge-min-pi4", 0, 10_000.0, 50_000.0, 90_000.0); // a disaster
        noisy.warmup_cov_ok = false;
        let outcome = evaluate(&[noisy], &base, NOW, &no_override());
        assert!(
            matches!(outcome, GateOutcome::InsufficientData(_)),
            "an all-advisory window must no-op, got {outcome:?}"
        );
        assert!(!outcome.is_blocking());
    }

    #[test]
    fn an_advisory_run_does_not_mask_a_real_regression() {
        // A good (advisory) run alongside a bad (eligible) run: the advisory good run must NOT be
        // mixed into the median to dilute the regression. The eligible bad run alone fires.
        let base = baseline(vec![run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0)]);
        let mut advisory_good = run("edge-min-pi4", 0, 60_000.0, 5_000.0, 9_000.0);
        advisory_good.warmup_cov_ok = false;
        let eligible_bad = run("edge-min-pi4", 1, 40_000.0, 5_000.0, 9_000.0); // 33% drop
        let outcome = evaluate(&[advisory_good, eligible_bad], &base, NOW, &no_override());
        assert!(outcome.is_blocking(), "got {outcome:?}");
    }

    // ---- the human-ratify escape hatch ----

    #[test]
    fn a_human_ratified_regression_passes_with_an_audit_reason() {
        let base = baseline(vec![run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0)]);
        let current = vec![run("edge-min-pi4", 0, 40_000.0, 5_000.0, 9_000.0)]; // 33% drop, fires
        let over = Override {
            human_ratified: Some(
                "ratified: known thermal regression on the CI runner, RB-123".to_string(),
            ),
        };
        let outcome = evaluate(&current, &base, NOW, &over);
        assert!(
            !outcome.is_blocking(),
            "a ratified regression must not block: {outcome:?}"
        );
        let GateOutcome::Ratified { breaches, reason } = &outcome else {
            panic!("expected Ratified, got {outcome:?}");
        };
        assert!(!breaches.is_empty(), "the breaches are still recorded");
        assert!(reason.contains("RB-123"));
        assert!(outcome.summary().contains("RATIFIED"));
    }

    // ---- per-device isolation and the rolling window ----

    #[test]
    fn a_regression_on_one_device_does_not_implicate_another() {
        let base = baseline(vec![
            run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0),
            run("edge-mid-rk3399", 30, 120_000.0, 4_000.0, 8_000.0),
        ]);
        let current = vec![
            run("edge-min-pi4", 0, 40_000.0, 5_000.0, 9_000.0), // pi4 regresses 33%
            run("edge-mid-rk3399", 0, 121_000.0, 4_050.0, 8_100.0), // rk3399 fine
        ];
        let outcome = evaluate(&current, &base, NOW, &no_override());
        let GateOutcome::Fail(breaches) = &outcome else {
            panic!("expected Fail, got {outcome:?}");
        };
        // Exactly one device fired.
        assert!(breaches.iter().all(
            |b| matches!(b, Breach::ThroughputDrop { device, .. } if device == "edge-min-pi4")
        ));
    }

    #[test]
    fn runs_older_than_the_window_are_excluded() {
        let base = baseline(vec![run("edge-min-pi4", 60, 60_000.0, 5_000.0, 9_000.0)]);
        // The only current run is 10 days old, outside the 7-day window => no eligible current run.
        let current = vec![run("edge-min-pi4", 10, 40_000.0, 5_000.0, 9_000.0)];
        let outcome = evaluate(&current, &base, NOW, &no_override());
        assert!(
            matches!(outcome, GateOutcome::InsufficientData(_)),
            "an out-of-window current run must not be used: {outcome:?}"
        );
    }

    #[test]
    fn a_new_device_absent_from_the_baseline_does_not_fire() {
        // A device that did not exist at the last release cannot "regress" against it.
        let base = baseline(vec![run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0)]);
        let current = vec![run("brand-new-device", 0, 1.0, 999_999.0, 999_999.0)];
        let outcome = evaluate(&current, &base, NOW, &no_override());
        assert_eq!(outcome, GateOutcome::Pass, "{}", outcome.summary());
    }

    // ---- the median helper ----

    #[test]
    fn median_odd_and_even() {
        assert_eq!(median([3.0, 1.0, 2.0].into_iter()), Some(2.0));
        assert_eq!(median([4.0, 1.0, 3.0, 2.0].into_iter()), Some(2.5));
        assert_eq!(median(std::iter::empty()), None);
    }

    #[test]
    fn median_ignores_non_finite() {
        assert_eq!(median([1.0, f64::NAN, 3.0].into_iter()), Some(2.0));
        assert_eq!(median([f64::NAN, f64::INFINITY].into_iter()), None);
    }

    #[test]
    fn the_median_is_robust_to_one_outlier() {
        // The whole point of a median gate: one bad run in a window does not move the median enough to
        // fire. Baseline median 60k; current window {60k, 61k, 10k(outlier)} has median 60k => pass.
        let base = baseline(vec![run("edge-min-pi4", 30, 60_000.0, 5_000.0, 9_000.0)]);
        let current = vec![
            run("edge-min-pi4", 0, 60_000.0, 5_000.0, 9_000.0),
            run("edge-min-pi4", 1, 61_000.0, 5_000.0, 9_000.0),
            run("edge-min-pi4", 2, 10_000.0, 5_000.0, 9_000.0), // one disastrous run
        ];
        let outcome = evaluate(&current, &base, NOW, &no_override());
        assert_eq!(
            outcome,
            GateOutcome::Pass,
            "a single outlier must not fire a median gate: {}",
            outcome.summary()
        );
    }
}
