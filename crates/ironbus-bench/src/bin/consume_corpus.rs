// SPDX-License-Identifier: MIT OR Apache-2.0
//! Assemble the SINGLE-CONSUMER CONSUME corpus into a LINTED comparison report (#554, V2-M1).
//!
//! This is the consume-side twin of `assemble_corpus`: it reads the JSONL rows emitted by
//! `docs/benchmarks/consume_bench.py` (one `{system, tier, payload, mode, throughput, p50/p99/p999}`
//! per drain run) and builds a [`ComparisonReport`] for the V2-M1 headline claim — that IronBus's
//! Tier-S STREAMING consumer (the merged streaming-tier consume rearchitecture: `#655` Tier-S,
//! `#656` negotiation, `#661` `DeliverBatch`, `#662` the batched-fetch + periodic-cumulative-commit
//! client default) beats a NATS `JetStream` durable PULL consumer at single-consumer DURABLE consume,
//! the axis IronBus used to lose.
//!
//! The matched head-to-head pair is `ironbus`/`tier-s-streaming` (IronBus Tier-S streaming
//! single-consumer durable consume) vs `nats`/`js-pull` (a NATS `JetStream` durable pull consumer,
//! explicit batched ack). Both drain a durable file-backed prefix and persist their consume cursor,
//! so they share the [`DurabilityLabel::DurableConsume`] label and [`ComparisonReport::build`]'s
//! durability-label lint PAIRS them (a mislabeled pair — e.g. durable vs a non-durable core sub —
//! fails the build, exactly the anti-marketing guard the produce corpus relies on).
//!
//! The NATS CORE non-durable subscriber (`nats-core` / `core-sub`) is the at-most-once REFERENCE
//! point (no persistence, no ack, no replay): it is NOT durability-matched to the durable pair, so it
//! goes to the informational appendix, never force-paired against a durable consumer.
//!
//! Emits the validated report JSON and a markdown table. Off the shipped binary's graph; run on
//! demand after a `consume_bench.py` run:
//!   cargo run -p ironbus-bench --bin consume-corpus -- \
//!       --rows consume-rows.jsonl --json-out consume-report.json --md-out consume-report.md

use ironbus_bench::comparison::{
    ComparisonPair, ComparisonReport, ComparisonRow, DurabilityLabel, Placement, ReportError,
    RowPercentiles, System,
};
use serde::Deserialize;
use std::process::ExitCode;

#[derive(Deserialize, Clone)]
struct Raw {
    system: String,
    tier: String,
    payload: usize,
    throughput: f64,
    #[serde(default)]
    p50: Option<f64>,
    #[serde(default)]
    p99: Option<f64>,
    #[serde(default)]
    p999: Option<f64>,
    // `mode` is accepted but not read: every row in a consume corpus is a consume drain, so unlike
    // the produce `assemble-corpus` (which filters publish vs consume) there is nothing to branch on.
    // Allowing the extra key keeps the JSONL schema-compatible with the produce corpus rows.
    #[serde(default)]
    #[allow(dead_code)]
    mode: Option<String>,
}

/// The rig device label. A generic AWS Graviton (`t4g`) edge-class core in `us-west-2`; NO internal
/// hostname or address appears here (this is a PUBLIC repo). The reference produce corpus used the
/// `RPi4`; this consume corpus was run on the `t4g`, recorded honestly as a different reference box.
const DEVICE: &str = "t4g-aws-graviton2-2core";

fn sys(s: &str) -> Option<System> {
    match s {
        "ironbus" => Some(System::IronBus),
        "nats" => Some(System::Nats),
        "nats-core" => Some(System::NatsCore),
        _ => None,
    }
}

/// The durability label for a (system, consume-tier) row. The two DURABLE consume tiers share the
/// `DurableConsume` label so the lint pairs them head-to-head; the non-durable core sub carries
/// `AtMostOnce` so it can never be force-paired against a durable consumer.
fn label(tier: &str) -> Option<DurabilityLabel> {
    match tier {
        // The three DURABLE consumers share the matched durable-consume label so the lint pairs the
        // streaming/pull head-to-head and the Tier-W work-queue context column is well-typed:
        //   tier-s-streaming  IronBus Tier-S streaming (periodic cumulative StreamCommit cursor)
        //   js-pull           NATS JetStream durable pull (explicit batched ack on a file stream)
        //   tier-w-work       IronBus Tier-W per-message-lease work queue (the path it used to lose on)
        "tier-s-streaming" | "js-pull" | "tier-w-work" => Some(DurabilityLabel::DurableConsume),
        // NATS CORE subscriber: no JetStream, no persistence, no replay — at-most-once live delivery.
        "core-sub" => Some(DurabilityLabel::AtMostOnce),
        _ => None,
    }
}

fn pcts(r: &Raw) -> RowPercentiles {
    RowPercentiles {
        p50_us: r.p50.unwrap_or(0.0),
        p99_us: r.p99.unwrap_or(0.0),
        p999_us: r.p999.unwrap_or(0.0),
    }
}

fn row(r: &Raw, placement: Placement) -> Option<ComparisonRow> {
    Some(ComparisonRow {
        system: sys(&r.system)?,
        durability: label(&r.tier)?,
        message_size_bytes: r.payload,
        device: DEVICE.to_string(),
        placement,
        throughput_msgs_per_sec: r.throughput,
        percentiles: pcts(r),
    })
}

/// Build the lint-validated consume report: IronBus Tier-S streaming vs NATS JS pull at the matched
/// `DurableConsume` label (the headline head-to-head), with the IronBus Tier-W work-queue column and
/// the NATS core non-durable subscriber as appendix context.
fn assemble(raws: &[Raw]) -> Result<ComparisonReport, ReportError> {
    let get = |system: &str, tier: &str, payload: usize| -> Option<&Raw> {
        raws.iter()
            .find(|r| r.system == system && r.tier == tier && r.payload == payload)
    };
    let payloads: Vec<usize> = {
        let mut p: Vec<usize> = raws.iter().map(|r| r.payload).collect();
        p.sort_unstable();
        p.dedup();
        p
    };

    let mut pairs: Vec<ComparisonPair> = Vec::new();
    for &payload in &payloads {
        // THE HEADLINE PAIR: IronBus Tier-S streaming durable consume vs NATS JetStream durable pull
        // consume, matched durability + size + device, both edge-gate. The build lint refuses this
        // pair if the labels ever drift apart (the marketing guard).
        if let (Some(ib), Some(nats)) = (
            get("ironbus", "tier-s-streaming", payload).and_then(|r| row(r, Placement::EdgeGate)),
            get("nats", "js-pull", payload).and_then(|r| row(r, Placement::EdgeGate)),
        ) {
            pairs.push(ComparisonPair {
                left: ib,
                right: nats,
            });
        }
    }

    // Appendix (informational, not head-to-head): the IronBus Tier-W work-queue consume column (the
    // path IronBus used to be measured on) and the NATS core non-durable subscriber reference.
    let mut appendix: Vec<ComparisonRow> = Vec::new();
    for r in raws {
        let is_context = r.tier == "tier-w-work" || r.tier == "core-sub";
        if is_context {
            if let Some(row) = row(r, Placement::Appendix) {
                appendix.push(row);
            }
        }
    }

    ComparisonReport::build(pairs, appendix)
}

fn main() -> ExitCode {
    let mut rows_path = None;
    let mut json_out = None;
    let mut md_out = None;
    let mut args = std::env::args().skip(1);
    while let Some(f) = args.next() {
        match f.as_str() {
            "--rows" => rows_path = args.next(),
            "--json-out" => json_out = args.next(),
            "--md-out" => md_out = args.next(),
            other => {
                eprintln!("unknown arg: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(rows_path) = rows_path else {
        eprintln!("usage: consume-corpus --rows <jsonl> --json-out <path> --md-out <path>");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(&rows_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {rows_path}: {e}");
            return ExitCode::from(1);
        }
    };
    let raws: Vec<Raw> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| {
            eprintln!("bad rows JSON: {e}");
            std::process::exit(1);
        });

    let report = match assemble(&raws) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CONSUME CORPUS FAILED THE FAIRNESS LINT: {e}");
            return ExitCode::from(1);
        }
    };

    if let Some(path) = &json_out {
        let json = report.to_json().expect("serialize report");
        std::fs::write(path, json).expect("write json");
        eprintln!("wrote {path}");
    }
    let payloads: Vec<usize> = {
        let mut p: Vec<usize> = raws.iter().map(|r| r.payload).collect();
        p.sort_unstable();
        p.dedup();
        p
    };
    if let Some(path) = &md_out {
        std::fs::write(path, render_md(&raws, &payloads)).expect("write md");
        eprintln!("wrote {path}");
    }
    eprintln!(
        "assembled: {} matched consume pairs, {} appendix rows, all lints passed",
        report.pairs.len(),
        report.appendix.len()
    );
    ExitCode::SUCCESS
}

fn thr(raws: &[Raw], system: &str, tier: &str, payload: usize) -> String {
    raws.iter()
        .find(|r| r.system == system && r.tier == tier && r.payload == payload)
        .map_or_else(|| "--".to_string(), |r| format!("{:.0}", r.throughput))
}

/// IronBus Tier-S streaming consume divided by NATS JS pull consume at this payload — the headline
/// multiple. `--` when either side is missing.
fn speedup(raws: &[Raw], payload: usize) -> String {
    let ib = raws
        .iter()
        .find(|r| r.system == "ironbus" && r.tier == "tier-s-streaming" && r.payload == payload);
    let nats = raws
        .iter()
        .find(|r| r.system == "nats" && r.tier == "js-pull" && r.payload == payload);
    match (ib, nats) {
        (Some(ib), Some(nats)) if nats.throughput > 0.0 => {
            format!("{:.2}x", ib.throughput / nats.throughput)
        }
        _ => "--".to_string(),
    }
}

fn render_md(raws: &[Raw], payloads: &[usize]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# IronBus single-consumer consume corpus (#554, V2-M1)\n\n");
    s.push_str(
        "Generated by `consume-corpus` from `consume_bench.py` rows. Single-consumer DURABLE \
         consume, same device (t4g AWS Graviton2, 2 core, loopback), matched durability. The \
         headline head-to-head is IronBus's Tier-S STREAMING consumer vs a NATS JetStream durable \
         PULL consumer at the `durable-consume` label; the durability-label lint in \
         `ComparisonReport::build` rejects any mismatched (marketing) pair at assemble time. \
         Throughput is the comparable metric (msgs/sec).\n\n",
    );
    s.push_str(
        "## Durable single-consumer consume, matched durability (head-to-head)\n\n\
         Both sides drain a pre-filled durable file-backed prefix and persist their consume cursor \
         (IronBus: periodic cumulative `StreamCommit`; NATS: explicit batched ack on a durable pull \
         consumer), so a crash redelivers only the uncommitted span (at-least-once). Same \
         power-loss-safe consume guarantee on both sides.\n\n",
    );
    let _ = writeln!(
        s,
        "| payload | IronBus Tier-S streaming | NATS JS pull | IronBus / NATS |"
    );
    let _ = writeln!(s, "| --- | --- | --- | --- |");
    for &p in payloads {
        let _ = writeln!(
            s,
            "| {p} B | {} | {} | {} |",
            thr(raws, "ironbus", "tier-s-streaming", p),
            thr(raws, "nats", "js-pull", p),
            speedup(raws, p)
        );
    }
    s.push('\n');
    s.push_str("## Context (appendix, NOT a durable head-to-head)\n\n");
    s.push_str(
        "The IronBus Tier-W work-queue consume column (the per-message-lease path IronBus used to be \
         measured on, where it lost ~3-20x) and the NATS CORE non-durable subscriber (no JetStream, \
         no persistence, no replay — at-most-once live delivery, a different durability tier, shown \
         only as a reference ceiling).\n\n",
    );
    let _ = writeln!(
        s,
        "| payload | IronBus Tier-W work-queue | NATS core sub (non-durable) |"
    );
    let _ = writeln!(s, "| --- | --- | --- |");
    for &p in payloads {
        let _ = writeln!(
            s,
            "| {p} B | {} | {} |",
            thr(raws, "ironbus", "tier-w-work", p),
            thr(raws, "nats-core", "core-sub", p)
        );
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(system: &str, tier: &str, payload: usize, throughput: f64) -> Raw {
        Raw {
            system: system.into(),
            tier: tier.into(),
            payload,
            throughput,
            p50: None,
            p99: None,
            p999: None,
            mode: Some("consume".into()),
        }
    }

    #[test]
    fn ironbus_tier_s_and_nats_js_pull_share_the_durable_consume_label_so_they_pair() {
        // The headline matched pair: both DURABLE consumers carry the same `DurableConsume` label,
        // so ComparisonReport::build's identical-label lint PAIRS them. This is the #554 gate.
        assert_eq!(
            label("tier-s-streaming"),
            Some(DurabilityLabel::DurableConsume)
        );
        assert_eq!(label("js-pull"), Some(DurabilityLabel::DurableConsume));
        assert_eq!(label("tier-s-streaming"), label("js-pull"));
    }

    #[test]
    fn core_sub_is_at_most_once_so_it_never_pairs_with_a_durable_consumer() {
        // The NATS core non-durable sub is at-most-once: a DIFFERENT label from the durable pair, so
        // the lint can never assemble a durable-vs-non-durable consume head-to-head (the marketing
        // error the rig forbids on the consume axis exactly as on the produce axis).
        assert_eq!(label("core-sub"), Some(DurabilityLabel::AtMostOnce));
        assert_ne!(label("core-sub"), label("tier-s-streaming"));
        assert!(!DurabilityLabel::AtMostOnce.is_power_loss_safe());
        assert!(DurabilityLabel::DurableConsume.is_power_loss_safe());
    }

    #[test]
    fn a_matched_durable_consume_pair_builds_and_a_mismatch_is_caught() {
        // Matched: Tier-S streaming vs NATS JS pull, both DurableConsume, same size + device -> ok.
        let ib = row(
            &mk("ironbus", "tier-s-streaming", 256, 50_000.0),
            Placement::EdgeGate,
        )
        .unwrap();
        let nats = row(&mk("nats", "js-pull", 256, 40_000.0), Placement::EdgeGate).unwrap();
        assert!(ComparisonReport::build(
            vec![ComparisonPair {
                left: ib.clone(),
                right: nats,
            }],
            vec![],
        )
        .is_ok());
        // Mismatch: a durable consumer vs the non-durable core sub -> different labels -> build fails.
        let core = row(
            &mk("nats-core", "core-sub", 256, 200_000.0),
            Placement::EdgeGate,
        )
        .unwrap();
        assert!(ComparisonReport::build(
            vec![ComparisonPair {
                left: ib,
                right: core,
            }],
            vec![],
        )
        .is_err());
    }

    #[test]
    fn assemble_pairs_the_headline_and_appendixes_the_context() {
        // A full row set assembles into exactly one matched headline pair (Tier-S vs JS pull) and
        // two appendix context rows (Tier-W work-queue + core sub), all lints passing.
        let raws = vec![
            mk("ironbus", "tier-s-streaming", 256, 55_000.0),
            mk("nats", "js-pull", 256, 41_000.0),
            mk("ironbus", "tier-w-work", 256, 12_000.0),
            mk("nats-core", "core-sub", 256, 300_000.0),
        ];
        let report = assemble(&raws).expect("assembles and passes the fairness lint");
        assert_eq!(report.pairs.len(), 1, "exactly the headline durable pair");
        assert_eq!(report.appendix.len(), 2, "Tier-W + core-sub context rows");
    }
}
