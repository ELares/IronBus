// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ironbus server {info,healthz,ready,check}` (V2-M6, #592): operator-facing probes of the
//! broker's EXISTING health server. READ-ONLY — each verb is a single `GET` against
//! `/healthz`, `/readyz`, or `/metrics` (`crates/ironbus-server/src/health.rs`); this module NEVER
//! mutates the broker and NEVER changes the server crate.
//!
//! Verbs:
//! - `info`    — version + uptime (from `/metrics`: `ironbus_build_info` + `ironbus_uptime_seconds`).
//! - `healthz` — liveness (`GET /healthz`): is the accept loop progressing.
//! - `ready`   — readiness (`GET /readyz`): is the durable-log writer healthy (not frozen).
//! - `check`   — a Nagios-style one-line probe with a FROZEN exit code:
//!     - OK         (live AND ready)                         → exit 0, `IRONBUS OK - ...`
//!     - DEGRADED   (reachable but not ready / not live)     → exit 3, `IRONBUS CRITICAL - ...`
//!       (3 = the frozen "ran-to-completion, degraded finding" code: the probe SUCCEEDED, the
//!       non-zero is the finding, not a tool failure — the same contract `scrub`/`verify` use)
//!     - UNREACHABLE (health server down / connection failed) → exit 5
//!     - UNKNOWN     (a malformed / unexpected response)       → exit 70
//!
//! The broker already ships a real ready-vs-live SPLIT (`/healthz` liveness with a hysteresis
//! watchdog vs `/readyz` writer-health), so `ready` and `healthz` map to DISTINCT endpoints — no
//! server-side #577 gap to flag. The address resolves with the frozen `flag > current-context >
//! default` precedence, exactly like `top`/`admin`/`report`.

use crate::metrics_fetch::{self, HttpError};
use crate::prom::Metrics;
use crate::{context, CliError, DEFAULT_ADDR};
use std::fmt::Write as _;
use std::io::Write;

/// The `server` verbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verb {
    Info,
    Healthz,
    Ready,
    Check,
}

impl Verb {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "healthz" => Some(Self::Healthz),
            "ready" => Some(Self::Ready),
            "check" => Some(Self::Check),
            _ => None,
        }
    }
}

/// Dispatches `ironbus server <verb> [--addr|--health-addr <host:port>]`.
///
/// # Errors
/// [`CliError::Usage`] for a bad verb/flag; [`CliError::Unreachable`] (5) when the health server
/// cannot be reached; [`CliError::HandledCorruption`] (3) when `check` finds a reachable-but-
/// degraded broker; [`CliError::Internal`] (70) for a malformed response.
pub(crate) fn run_server(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let (verb_raw, rest) = args.split_first().ok_or_else(|| {
        CliError::Usage("server needs a verb: info | healthz | ready | check".to_string())
    })?;
    let verb = Verb::parse(verb_raw).ok_or_else(|| {
        CliError::Usage(format!(
            "unknown server verb `{verb_raw}` (expected info | healthz | ready | check)"
        ))
    })?;
    let addr = parse_addr(rest)?;
    let addr = context::resolve_addr(addr.as_deref(), DEFAULT_ADDR)?;
    match verb {
        Verb::Info => run_info(&addr, out),
        Verb::Healthz => run_probe(&addr, "/healthz", "healthz", out),
        Verb::Ready => run_probe(&addr, "/readyz", "ready", out),
        Verb::Check => run_check(&addr, out),
    }
}

/// Parses the optional `--addr`/`--health-addr <host:port>` (synonyms), rejecting any other flag or
/// positional.
fn parse_addr(rest: &[String]) -> Result<Option<String>, CliError> {
    let mut addr: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--addr" | "--health-addr" => {
                addr = Some(crate::take_value("--health-addr", rest, &mut i)?);
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for server")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "server takes no positional arguments after the verb, got `{other}`"
                )));
            }
        }
    }
    Ok(addr)
}

/// `server info`: version + uptime, read from `/metrics` (`ironbus_build_info{version=...}` and
/// `ironbus_uptime_seconds`). READ-ONLY; an unreachable broker is exit 5, a malformed body exit 70.
fn run_info(addr: &str, out: &mut impl Write) -> Result<(), CliError> {
    let body = metrics_fetch::fetch(addr, "/metrics").map_err(|e| map_error(addr, &e))?;
    let m = Metrics::parse(&body);
    let version = build_version(&m).unwrap_or_else(|| "unknown".to_string());
    let uptime = m.u64_or_zero("ironbus_uptime_seconds");
    let mut s = String::new();
    let _ = writeln!(s, "server info (broker at {addr})");
    let _ = writeln!(s, "  version:  {version}");
    let _ = writeln!(s, "  uptime:   {}", format_uptime(uptime));
    out.write_all(s.as_bytes())?;
    Ok(())
}

/// A liveness/readiness probe against `path`: prints `<label>: <state>` from the endpoint's status,
/// and SUCCEEDS (exit 0) whether the state is up OR down — these verbs REPORT the state; only
/// `check` turns a degraded state into a nonzero exit. A 200 is the healthy state; a 503 is the
/// degraded state the endpoint reports (and carries the broker's one-line reason). Unreachable is
/// still exit 5; a malformed response is exit 70.
fn run_probe(addr: &str, path: &str, label: &str, out: &mut impl Write) -> Result<(), CliError> {
    match metrics_fetch::fetch_status(addr, path) {
        Ok((200, body)) => {
            writeln!(out, "{label}: up ({})", body.trim())?;
            Ok(())
        }
        Ok((503, body)) => {
            writeln!(out, "{label}: down ({})", body.trim())?;
            Ok(())
        }
        Ok((status, body)) => writeln!(out, "{label}: unexpected HTTP {status} ({})", body.trim())
            .map_err(CliError::from),
        Err(HttpError::Unreachable(_)) => Err(CliError::Unreachable(format!(
            "probing {path} on broker at {addr}: health server unreachable"
        ))),
        Err(e) => Err(CliError::Internal(format!(
            "probing {path} on broker at {addr}: {e}"
        ))),
    }
}

/// The Nagios-style `check`: one line + a FROZEN exit code. It probes BOTH liveness (`/healthz`)
/// and readiness (`/readyz`) and reports the worst state:
/// - both up                 → `IRONBUS OK - live and ready`                    exit 0
/// - reachable but degraded  → `IRONBUS CRITICAL - <reason>`                    exit 3
/// - health server down      → `IRONBUS UNREACHABLE - <reason>`                 exit 5
/// - malformed response      → `IRONBUS UNKNOWN - <reason>`                     exit 70
///
/// The one-line status is ALWAYS written to `out` first (so a monitoring system captures the human
/// text even on the degraded path), THEN the frozen exit code is returned via the error type. The
/// degraded finding uses [`EXIT_HANDLED_CORRUPTION`] (3): the probe ran to completion and the
/// non-zero communicates the finding, NOT a tool failure (the same frozen contract `verify` uses).
fn run_check(addr: &str, out: &mut impl Write) -> Result<(), CliError> {
    // Liveness first: if the accept loop is wedged the broker is CRITICAL regardless of readiness.
    let live = match probe_state(addr, "/healthz") {
        ProbeState::Up => Probe::Up,
        ProbeState::Down(reason) => Probe::Down(reason),
        ProbeState::Unreachable => return unreachable(out, addr),
        ProbeState::Unknown(why) => return unknown(out, addr, &why),
    };
    let ready = match probe_state(addr, "/readyz") {
        ProbeState::Up => Probe::Up,
        ProbeState::Down(reason) => Probe::Down(reason),
        ProbeState::Unreachable => return unreachable(out, addr),
        ProbeState::Unknown(why) => return unknown(out, addr, &why),
    };
    if let (Probe::Up, Probe::Up) = (&live, &ready) {
        writeln!(out, "IRONBUS OK - live and ready")?;
        Ok(())
    } else {
        let reason = degraded_reason(&live, &ready);
        writeln!(out, "IRONBUS CRITICAL - {reason}")?;
        Err(CliError::HandledCorruption(format!(
            "broker at {addr} is reachable but degraded: {reason}"
        )))
    }
}

/// A single probe outcome usable in the `check` decision: up, down-with-reason, transport-
/// unreachable, or an unexpected response (UNKNOWN).
enum ProbeState {
    Up,
    Down(String),
    Unreachable,
    Unknown(String),
}

/// A liveness/readiness state for the `check` decision (the transport/unknown cases short-circuit
/// before this is built).
enum Probe {
    Up,
    Down(String),
}

/// Probes one liveness/readiness `path`, classifying the 200/503/other/transport outcomes.
fn probe_state(addr: &str, path: &str) -> ProbeState {
    match metrics_fetch::fetch_status(addr, path) {
        Ok((200, _)) => ProbeState::Up,
        Ok((503, body)) => ProbeState::Down(body.trim().to_string()),
        Ok((status, body)) => ProbeState::Unknown(format!("{path} HTTP {status}: {}", body.trim())),
        Err(HttpError::Unreachable(_)) => ProbeState::Unreachable,
        Err(e) => ProbeState::Unknown(format!("{path}: {e}")),
    }
}

/// Builds the CRITICAL one-line reason from the live/ready states, naming which dimension failed.
fn degraded_reason(live: &Probe, ready: &Probe) -> String {
    match (live, ready) {
        (Probe::Down(reason), _) => format!("not live ({reason})"),
        (_, Probe::Down(reason)) => format!("not ready ({reason})"),
        // Both Up is handled by the caller; this arm is unreachable in practice.
        _ => "degraded".to_string(),
    }
}

/// Writes the UNREACHABLE one-line status and returns the frozen exit-5 error.
fn unreachable(out: &mut impl Write, addr: &str) -> Result<(), CliError> {
    writeln!(
        out,
        "IRONBUS UNREACHABLE - cannot reach health server at {addr}"
    )?;
    Err(CliError::Unreachable(format!(
        "health server at {addr} is unreachable"
    )))
}

/// Writes the UNKNOWN one-line status and returns the frozen exit-70 error.
fn unknown(out: &mut impl Write, addr: &str, why: &str) -> Result<(), CliError> {
    writeln!(out, "IRONBUS UNKNOWN - {why}")?;
    Err(CliError::Internal(format!(
        "probing broker at {addr}: {why}"
    )))
}

/// Maps a `/metrics` fetch failure (for `info`) onto the frozen exit codes.
fn map_error(addr: &str, e: &HttpError) -> CliError {
    match e {
        HttpError::Unreachable(_) => {
            CliError::Unreachable(format!("reading broker info from {addr}: {e}"))
        }
        HttpError::Status { .. } | HttpError::Protocol(_) => {
            CliError::Internal(format!("reading broker info from {addr}: {e}"))
        }
    }
}

/// Extracts the build version from the `ironbus_build_info{version="..."}` sample.
fn build_version(m: &Metrics) -> Option<String> {
    m.family("ironbus_build_info")
        .iter()
        .find_map(|s| s.label("version").map(str::to_string))
}

/// Formats an uptime in seconds as a compact `Nd Nh Nm Ns` (omitting leading zero units), for the
/// human `info` view.
fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let s = secs % 60;
    let mut out = String::new();
    if days > 0 {
        let _ = write!(out, "{days}d ");
    }
    if days > 0 || hours > 0 {
        let _ = write!(out, "{hours}h ");
    }
    if days > 0 || hours > 0 || mins > 0 {
        let _ = write!(out, "{mins}m ");
    }
    let _ = write!(out, "{s}s");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_verb_is_a_usage_error() {
        let e = run_server(&["bogus".to_string()], &mut Vec::new()).unwrap_err();
        assert_eq!(e.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn no_verb_is_a_usage_error() {
        let e = run_server(&[], &mut Vec::new()).unwrap_err();
        assert_eq!(e.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn parse_addr_takes_both_synonyms_and_rejects_others() {
        assert_eq!(
            parse_addr(&["--addr".to_string(), "h:1".to_string()]).unwrap(),
            Some("h:1".to_string())
        );
        assert_eq!(
            parse_addr(&["--health-addr".to_string(), "h:2".to_string()]).unwrap(),
            Some("h:2".to_string())
        );
        assert!(parse_addr(&["--bogus".to_string()]).is_err());
        assert!(parse_addr(&["positional".to_string()]).is_err());
    }

    #[test]
    fn build_version_reads_the_label() {
        let m = Metrics::parse("ironbus_build_info{version=\"2026.0620.1\"} 1\n");
        assert_eq!(build_version(&m).as_deref(), Some("2026.0620.1"));
        let none = Metrics::parse("");
        assert_eq!(build_version(&none), None);
    }

    #[test]
    fn format_uptime_omits_leading_zero_units() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(59), "59s");
        assert_eq!(format_uptime(61), "1m 1s");
        assert_eq!(format_uptime(3_661), "1h 1m 1s");
        assert_eq!(format_uptime(90_061), "1d 1h 1m 1s");
    }

    #[test]
    fn degraded_reason_names_the_failed_dimension() {
        let live_down = Probe::Down("no event-loop progress".to_string());
        assert!(degraded_reason(&live_down, &Probe::Up).starts_with("not live"));
        let ready_down = Probe::Down("writer frozen".to_string());
        assert!(degraded_reason(&Probe::Up, &ready_down).starts_with("not ready"));
    }

    #[test]
    fn check_exit_codes_are_the_frozen_contract() {
        // The degraded finding is the frozen "ran-to-completion" code 3, not a tool failure; an
        // unreachable broker is 5; an unknown response is 70. (The OK path returns Ok(()) -> 0.)
        assert_eq!(
            CliError::HandledCorruption("x".to_string()).exit_code(),
            crate::EXIT_HANDLED_CORRUPTION
        );
        assert_eq!(
            CliError::Unreachable("x".to_string()).exit_code(),
            crate::EXIT_UNREACHABLE
        );
        assert_eq!(
            CliError::Internal("x".to_string()).exit_code(),
            crate::EXIT_INTERNAL
        );
    }
}
