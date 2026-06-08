// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `ironbus-regression-gate` binary: the CI entry point for the rolling-median regression gate
//! (#114).
//!
//! It reads the current per-device run history and the last-released-tag baseline from JSON, runs the
//! gate ([`ironbus_bench::regression::evaluate`]), logs a one-line outcome, and exits:
//!
//! - `0` on PASS (within thresholds), on a graceful NO-OP when there is no baseline yet (the state
//!   today, before the first `v0.1.0` tag), on insufficient (all-advisory) data, and on a documented
//!   human-ratified override;
//! - non-zero ONLY on an un-ratified rolling-median regression.
//!
//! Usage:
//!
//! ```text
//! ironbus-regression-gate --history <history.json> [--baseline <baseline.json>] \
//!     [--ratify "<audit reason>"]
//! ```
//!
//! The `--baseline` path is OPTIONAL and a MISSING file is the graceful no-op (not an error): there is
//! no released tag / baseline history yet, so the gate passes with a logged reason. This binary's
//! `main` may use `expect` for one-time setup; the gate logic it calls (the `ironbus-bench` lib) never
//! panics and performs no IO.

use ironbus_bench::regression::{evaluate, Baseline, History, Override};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed command-line options.
struct Opts {
    history_path: PathBuf,
    baseline_path: Option<PathBuf>,
    ratify_reason: Option<String>,
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("error: {msg}\n");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // The current run history is required and must parse.
    let history: History = match read_json(&opts.history_path) {
        Ok(Some(h)) => h,
        Ok(None) => {
            eprintln!(
                "error: the --history file {} does not exist; the current run history is required",
                opts.history_path.display()
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!(
                "error: could not read/parse --history {}: {e}",
                opts.history_path.display()
            );
            return ExitCode::from(2);
        }
    };

    // The baseline is OPTIONAL. A missing baseline file is the GRACEFUL NO-OP, not an error: there is
    // no released tag yet, so the gate passes. An empty default baseline drives exactly that path.
    let baseline: Baseline = if let Some(path) = &opts.baseline_path {
        match read_json(path) {
            Ok(Some(b)) => b,
            Ok(None) => {
                eprintln!(
                    "note: the --baseline file {} does not exist yet; treating as no baseline \
                     history (the gate will no-op)",
                    path.display()
                );
                Baseline::default()
            }
            Err(e) => {
                eprintln!("error: could not parse --baseline {}: {e}", path.display());
                return ExitCode::from(2);
            }
        }
    } else {
        eprintln!(
            "note: no --baseline given; treating as no baseline history (the gate will no-op)"
        );
        Baseline::default()
    };

    let now = history.now_unix_secs.unwrap_or_else(wall_clock_now);
    let over = Override {
        human_ratified: opts.ratify_reason,
    };

    let outcome = evaluate(&history.runs, &baseline, now, &over);
    // The single machine-readable line CI greps, plus the human summary on stderr.
    println!("{}", outcome.summary());
    eprintln!("{}", outcome.summary());

    if outcome.is_blocking() {
        eprintln!(
            "the regression gate BLOCKS this build. To override an edge regression, a human must \
             ratify it: re-run with --ratify \"<reason>\" (the documented escape hatch)."
        );
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Reads and deserializes a JSON file. Returns `Ok(None)` when the file does not exist (the caller
/// decides whether that is fatal: it is for `--history`, the graceful no-op for `--baseline`).
///
/// # Errors
/// Returns a message on a non-not-found IO error or a JSON parse error.
fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<Option<T>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("invalid JSON: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("io error: {e}")),
    }
}

/// Wall-clock now in Unix seconds, used only when the history fixture omits its own anchor.
fn wall_clock_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The usage string, printed on a parse error or `--help`.
const USAGE: &str = "\
ironbus-regression-gate: the CI rolling-median performance regression gate (#114).

USAGE:
    ironbus-regression-gate --history <path> [--baseline <path>] [--ratify <reason>]

OPTIONS:
    --history <path>     The current per-device run history JSON (required).
    --baseline <path>    The last-released-tag baseline JSON (optional). A MISSING file is the
                         graceful no-op (no released tag yet), NOT an error.
    --ratify <reason>    Human-ratify a fired edge regression with an audit reason (the documented
                         override). Converts a FAIL into a logged PASS.
    --help               Print this help.

EXIT CODES:
    0   pass / graceful no-op (no baseline) / insufficient data / ratified override
    1   an un-ratified rolling-median regression fired
    2   a usage or input error (missing/invalid --history)
";

/// A minimal `--flag value` argument parser (no external dep, mirrors `src/main.rs`).
fn parse_args() -> Result<Opts, String> {
    let mut history_path: Option<PathBuf> = None;
    let mut baseline_path: Option<PathBuf> = None;
    let mut ratify_reason: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--history" => history_path = Some(PathBuf::from(next_value(&mut args, "--history")?)),
            "--baseline" => {
                baseline_path = Some(PathBuf::from(next_value(&mut args, "--baseline")?));
            }
            "--ratify" => ratify_reason = Some(next_value(&mut args, "--ratify")?),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let history_path = history_path.ok_or_else(|| "--history <path> is required".to_string())?;
    Ok(Opts {
        history_path,
        baseline_path,
        ratify_reason,
    })
}

/// Returns the next argument value for `flag`, with a clear error if missing.
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}
