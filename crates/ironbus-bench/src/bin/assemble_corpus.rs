// SPDX-License-Identifier: MIT OR Apache-2.0
//! Assemble the competitor benchmark corpus into a LINTED comparison report.
//!
//! Reads the JSONL rows emitted by `docs/benchmarks/corpus_bench.py` (one
//! `{system, tier, payload, mode, throughput, p50/p99/p999}` per run) and builds
//! a [`ComparisonReport`]: IronBus is paired head-to-head against each edge-class
//! LOG peer (NATS `JetStream`, Redis Streams) at MATCHED durability + size +
//! device, so `ComparisonReport::build`'s durability-label lint refuses a
//! mislabeled (marketing) comparison at assemble time. MQTT (a routing protocol,
//! not a durable log), IronBus's group-commit-fsync differentiator (no edge peer
//! matches it), and the consume-throughput rows go to the informational appendix.
//!
//! Emits the validated report JSON and a human markdown table. Off the shipped
//! binary's graph; run on demand:
//!   cargo run -p ironbus-bench --bin assemble-corpus -- \
//!       --rows corpus-full.jsonl --json-out report.json --md-out report.md

use ironbus_bench::comparison::{
    ComparisonPair, ComparisonReport, ComparisonRow, DurabilityLabel, Placement, RowPercentiles,
    System,
};
use serde::Deserialize;
use std::process::ExitCode;

#[derive(Deserialize, Clone)]
struct Raw {
    system: String,
    tier: String,
    payload: usize,
    mode: String,
    throughput: f64,
    #[serde(default)]
    p50: Option<f64>,
    #[serde(default)]
    p99: Option<f64>,
    #[serde(default)]
    p999: Option<f64>,
}

const DEVICE: &str = "edge-min-pi4-1000000088e76a84"; // RPi4 armv7, the canonical edge box

fn sys(s: &str) -> Option<System> {
    match s {
        "ironbus" => Some(System::IronBus),
        "nats" => Some(System::Nats),
        "redis" => Some(System::Redis),
        "mosquitto" => Some(System::Mosquitto),
        _ => None,
    }
}

/// The durability label for a (system, tier) publish row. Log systems share the
/// semantic labels (so they pair); MQTT carries its own QoS labels (so the lint
/// never pairs it head-to-head with a log system).
fn label(system: &str, tier: &str) -> Option<DurabilityLabel> {
    if system == "mosquitto" {
        return match tier {
            "sync-per-message" => Some(DurabilityLabel::MqttQos1),
            // page-cache and memory tiers both ran QoS 0 on Mosquitto.
            "page-cache-async" | "memory" => Some(DurabilityLabel::MqttQos0),
            _ => None,
        };
    }
    match tier {
        "sync-per-message" => Some(DurabilityLabel::SyncPerMessage),
        "page-cache-async" => Some(DurabilityLabel::PageCacheAsync),
        "memory" => Some(DurabilityLabel::Memory),
        "group-commit-fsync" => Some(DurabilityLabel::GroupCommitFsync),
        _ => None,
    }
}

fn pcts(r: &Raw) -> RowPercentiles {
    // Many rows have no measured latency (throughput is the comparable metric); 0.0
    // means "not measured" and renders as "--" in markdown. The lint never reads it.
    RowPercentiles {
        p50_us: r.p50.unwrap_or(0.0),
        p99_us: r.p99.unwrap_or(0.0),
        p999_us: r.p999.unwrap_or(0.0),
    }
}

fn row(r: &Raw, placement: Placement) -> Option<ComparisonRow> {
    Some(ComparisonRow {
        system: sys(&r.system)?,
        durability: label(&r.system, &r.tier)?,
        message_size_bytes: r.payload,
        device: DEVICE.to_string(),
        placement,
        throughput_msgs_per_sec: r.throughput,
        percentiles: pcts(r),
    })
}

/// Build the lint-validated report from the parsed rows: IronBus paired head-to-head with each
/// log peer at matched durability tiers (plus the IronBus-vs-Redis group-commit pair), with MQTT
/// and consume rows as appendix context. Returns the first fairness-lint error if any pair is
/// mislabeled.
fn assemble(raws: &[Raw]) -> Result<ComparisonReport, ironbus_bench::comparison::ReportError> {
    let pub_rows: Vec<&Raw> = raws.iter().filter(|r| r.mode == "publish").collect();
    let get = |system: &str, tier: &str, payload: usize| -> Option<&Raw> {
        pub_rows
            .iter()
            .copied()
            .find(|r| r.system == system && r.tier == tier && r.payload == payload)
    };
    let payloads: Vec<usize> = {
        let mut p: Vec<usize> = raws.iter().map(|r| r.payload).collect();
        p.sort_unstable();
        p.dedup();
        p
    };
    // The matched head-to-head tiers (log systems only).
    let tiers = ["sync-per-message", "page-cache-async", "memory"];
    let log_peers = ["nats", "redis"];

    let mut pairs: Vec<ComparisonPair> = Vec::new();
    for &payload in &payloads {
        for tier in tiers {
            let Some(ib) = get("ironbus", tier, payload).and_then(|r| row(r, Placement::EdgeGate))
            else {
                continue;
            };
            for peer in log_peers {
                if let Some(pr) = get(peer, tier, payload).and_then(|r| row(r, Placement::EdgeGate))
                {
                    pairs.push(ComparisonPair {
                        left: ib.clone(),
                        right: pr,
                    });
                }
            }
        }
        // Durable-at-throughput head-to-head: IronBus group-commit-fsync (1 connection,
        // pipelined) vs Redis appendfsync=always with concurrent writers. Both are
        // power-loss-safe ack-after-(coalesced)-fdatasync, so they share the GroupCommitFsync
        // label and pass the durability lint honestly. NATS has no such mode (FileStore acks
        // are page-cache), so it has no row here.
        if let (Some(ib), Some(rd)) = (
            get("ironbus", "group-commit-fsync", payload).and_then(|r| row(r, Placement::EdgeGate)),
            get("redis", "group-commit-fsync", payload).and_then(|r| row(r, Placement::EdgeGate)),
        ) {
            pairs.push(ComparisonPair {
                left: ib,
                right: rd,
            });
        }
    }

    // Appendix (informational, not head-to-head): MQTT publish rows, IronBus's
    // group-commit-fsync differentiator, and all consume-throughput rows.
    let mut appendix: Vec<ComparisonRow> = Vec::new();
    for r in raws {
        let take = (r.mode == "publish" && r.system == "mosquitto") || r.mode == "consume";
        if take {
            // consume rows have no durability meaning; label them Memory (measured off a
            // memory pre-fill) purely so the appendix row is well-typed.
            let dur = if r.mode == "consume" {
                Some(DurabilityLabel::Memory)
            } else {
                label(&r.system, &r.tier)
            };
            if let (Some(system), Some(durability)) = (sys(&r.system), dur) {
                appendix.push(ComparisonRow {
                    system,
                    durability,
                    message_size_bytes: r.payload,
                    device: DEVICE.to_string(),
                    placement: Placement::Appendix,
                    throughput_msgs_per_sec: r.throughput,
                    percentiles: pcts(r),
                });
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
        eprintln!("usage: assemble-corpus --rows <jsonl> --json-out <path> --md-out <path>");
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
            eprintln!("CORPUS FAILED THE FAIRNESS LINT: {e}");
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
        "assembled: {} matched pairs, {} appendix rows, all lints passed",
        report.pairs.len(),
        report.appendix.len()
    );
    ExitCode::SUCCESS
}

fn thr(raws: &[Raw], system: &str, tier: &str, payload: usize) -> String {
    raws.iter()
        .find(|r| {
            r.system == system && r.tier == tier && r.payload == payload && r.mode == "publish"
        })
        .map_or_else(|| "--".to_string(), |r| format!("{:.0}", r.throughput))
}

fn pub_table(s: &mut String, raws: &[Raw], payloads: &[usize], tier: &str) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "| payload | IronBus | NATS JetStream | Redis Streams |");
    let _ = writeln!(s, "| --- | --- | --- | --- |");
    for &p in payloads {
        let _ = writeln!(
            s,
            "| {p} B | {} | {} | {} |",
            thr(raws, "ironbus", tier, p),
            thr(raws, "nats", tier, p),
            thr(raws, "redis", tier, p)
        );
    }
    s.push('\n');
}

fn consume_str(raws: &[Raw], sysname: &str, p: usize) -> String {
    raws.iter()
        .find(|r| r.system == sysname && r.mode == "consume" && r.payload == p)
        .map_or_else(|| "--".to_string(), |r| format!("{:.0}", r.throughput))
}

fn render_md(raws: &[Raw], payloads: &[usize]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# IronBus competitor benchmark corpus\n\n");
    s.push_str(
        "Generated by `assemble-corpus` from `corpus_bench.py` rows. Same device \
         (RPi4 armv7, loopback), matched durability per tier. Throughput is the \
         comparable metric (msgs/sec); the durability-label lint in \
         `ComparisonReport::build` rejects any mismatched (marketing) pair at assemble time.\n\n",
    );
    s.push_str("## Publish throughput, matched durability (head-to-head)\n\n");
    for (tier, desc) in [
        (
            "sync-per-message",
            "durable, power-loss-safe (one fdatasync per ack)",
        ),
        (
            "page-cache-async",
            "NOT power-loss-safe (ack from page cache / ~1s window)",
        ),
        ("memory", "ephemeral (in-RAM, no disk)"),
    ] {
        let _ = writeln!(s, "### `{tier}` -- {desc}\n");
        pub_table(&mut s, raws, payloads, tier);
    }
    s.push_str("## Durable at throughput: `group-commit-fsync` (the differentiator)\n\n");
    s.push_str(
        "Power-loss-safe AND fast: ack only after a (batched) fdatasync. IronBus reaches it on \
         ONE connection via pipelined group commit; Redis reaches durable throughput only by \
         running many concurrent `appendfsync=always` writers so the fsync coalesces across \
         clients. NATS JetStream has no ack-after-fsync mode (its FileStore acks from page \
         cache), so it has no row here. Same power-loss-safe guarantee on both sides.\n\n",
    );
    let _ = writeln!(
        s,
        "| payload | IronBus (1 conn, pipelined) | Redis (50 conns, appendfsync=always) |"
    );
    let _ = writeln!(s, "| --- | --- | --- |");
    for &p in payloads {
        let _ = writeln!(
            s,
            "| {p} B | {} | {} |",
            thr(raws, "ironbus", "group-commit-fsync", p),
            thr(raws, "redis", "group-commit-fsync", p)
        );
    }
    s.push('\n');
    s.push_str("## Consume throughput (drain rate, durability-independent)\n\n");
    let _ = writeln!(s, "| payload | IronBus | NATS | Redis | Mosquitto |");
    let _ = writeln!(s, "| --- | --- | --- | --- | --- |");
    for &p in payloads {
        let _ = writeln!(
            s,
            "| {p} B | {} | {} | {} | {} |",
            consume_str(raws, "ironbus", p),
            consume_str(raws, "nats", p),
            consume_str(raws, "redis", p),
            consume_str(raws, "mosquitto", p)
        );
    }
    s.push('\n');
    s.push_str("## MQTT (Mosquitto) context\n\n");
    s.push_str(
        "MQTT is a routing protocol over broker session state, not a replayable durable log; its \
         persistence is periodic autosave, not per-ack fsync. Reported as context (QoS 1 = \
         at-least-once, QoS 0 = at-most-once), NOT paired head-to-head with the log systems.\n\n",
    );
    let _ = writeln!(s, "| payload | QoS 1 publish | QoS 0 publish |");
    let _ = writeln!(s, "| --- | --- | --- |");
    for &p in payloads {
        let _ = writeln!(
            s,
            "| {p} B | {} | {} |",
            thr(raws, "mosquitto", "sync-per-message", p),
            thr(raws, "mosquitto", "page-cache-async", p)
        );
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_systems_share_semantic_labels_so_they_pair() {
        // IronBus, NATS, Redis at the same tier get the SAME label -> the lint pairs them.
        for s in ["ironbus", "nats", "redis"] {
            assert_eq!(
                label(s, "sync-per-message"),
                Some(DurabilityLabel::SyncPerMessage)
            );
            assert_eq!(
                label(s, "page-cache-async"),
                Some(DurabilityLabel::PageCacheAsync)
            );
            assert_eq!(label(s, "memory"), Some(DurabilityLabel::Memory));
        }
        assert_eq!(
            label("ironbus", "group-commit-fsync"),
            Some(DurabilityLabel::GroupCommitFsync)
        );
        assert_eq!(
            label("redis", "group-commit-fsync"),
            Some(DurabilityLabel::GroupCommitFsync)
        );
    }

    #[test]
    fn mqtt_keeps_its_own_labels_so_it_never_pairs_with_a_log_system() {
        // QoS labels differ from every log-system label, so ComparisonReport::build's
        // identical-label lint can never assemble an MQTT-vs-log head-to-head pair.
        assert_eq!(
            label("mosquitto", "sync-per-message"),
            Some(DurabilityLabel::MqttQos1)
        );
        assert_eq!(
            label("mosquitto", "page-cache-async"),
            Some(DurabilityLabel::MqttQos0)
        );
        assert_ne!(
            label("mosquitto", "sync-per-message"),
            label("ironbus", "sync-per-message")
        );
    }

    #[test]
    fn a_matched_pair_from_rows_builds_and_a_mismatch_is_caught() {
        let ib = row(
            &Raw {
                system: "ironbus".into(),
                tier: "sync-per-message".into(),
                payload: 256,
                mode: "publish".into(),
                throughput: 200.0,
                p50: None,
                p99: None,
                p999: None,
            },
            Placement::EdgeGate,
        )
        .unwrap();
        let rd = row(
            &Raw {
                system: "redis".into(),
                tier: "sync-per-message".into(),
                payload: 256,
                mode: "publish".into(),
                throughput: 180.0,
                p50: None,
                p99: None,
                p999: None,
            },
            Placement::EdgeGate,
        )
        .unwrap();
        assert!(ComparisonReport::build(
            vec![ComparisonPair {
                left: ib.clone(),
                right: rd
            }],
            vec![]
        )
        .is_ok());
        // page-cache (not safe) vs sync-per-message (safe) -> mismatch -> build fails.
        let unsafe_redis = row(
            &Raw {
                system: "redis".into(),
                tier: "page-cache-async".into(),
                payload: 256,
                mode: "publish".into(),
                throughput: 30000.0,
                p50: None,
                p99: None,
                p999: None,
            },
            Placement::EdgeGate,
        )
        .unwrap();
        assert!(ComparisonReport::build(
            vec![ComparisonPair {
                left: ib,
                right: unsafe_redis
            }],
            vec![]
        )
        .is_err());
    }
}
