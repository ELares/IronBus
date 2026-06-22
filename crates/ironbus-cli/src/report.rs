// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ironbus report {groups,streams,storage,recovery,connections}` (V2-M6, #589): a human +
//! `--json` operator report built ENTIRELY from the broker's existing `/metrics` Prometheus
//! endpoint. It is READ-ONLY — one `GET /metrics` per run — and NEVER mutates the broker or
//! changes `crates/ironbus-server/`; a missing series reads as a clean zero rather than a failure.
//!
//! Subcommands (each a focused slice of the same `/metrics` snapshot):
//! - `groups`      — per-work-group lag / in-flight / committed offset + consumed throughput.
//! - `streams`     — per-stream produced throughput.
//! - `storage`     — segments, on-disk footprint, disk-free, RAM headroom, write amplification.
//! - `recovery`    — recovery-run / loss / truncation / quarantine counters.
//! - `connections` — `ironbus_connections_*` lifecycle + pre-auth-rejection counters.
//!
//! Output: the human table by default; the WHOLE report as the uniform `ironbus.cli.v1` envelope
//! under the global `--json` (the dispatch captures the human text and wraps it — this module emits
//! the same clean table either way, so a script keys off the envelope). The address resolves with
//! the frozen `flag > current-context > default` precedence, exactly like `top`/`admin`.

use crate::metrics_fetch::{self, HttpError};
use crate::prom::Metrics;
use crate::{context, fuzzy, CliError, DEFAULT_ADDR};
use std::fmt::Write as _;
use std::io::Write;

/// The `report` subcommands. `Subject` is the noun the user picks; each maps to one renderer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Subject {
    Groups,
    Streams,
    Storage,
    Recovery,
    Connections,
}

impl Subject {
    /// Parses the subcommand noun.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "groups" => Some(Self::Groups),
            "streams" => Some(Self::Streams),
            "storage" => Some(Self::Storage),
            "recovery" => Some(Self::Recovery),
            "connections" => Some(Self::Connections),
            _ => None,
        }
    }
}

/// The parsed `report` invocation: which subject, which health-server address, and an optional
/// `--filter <name>` that narrows the `groups`/`streams` views to one name (an explicit selection;
/// it also SKIPS the interactive picker, keeping the verb scriptable).
#[derive(Debug)]
struct ReportArgs {
    subject: Subject,
    addr: Option<String>,
    filter: Option<String>,
}

/// Parses `report <subject> [--addr|--health-addr <host:port>] [--filter <name>]`. `--addr` and
/// `--health-addr` are synonyms (the health-server address), matching `top`/`admin`. An unknown
/// subject or flag is a usage error; the address is OPTIONAL and resolved (flag > context > default)
/// at fetch time. `--filter` applies only to the `groups`/`streams` subjects (a no-op for the
/// scalar subjects); when omitted on a TTY, those two subjects offer the interactive fuzzy picker.
fn parse_args(args: &[String]) -> Result<ReportArgs, CliError> {
    let (subject_raw, rest) = args.split_first().ok_or_else(|| {
        CliError::Usage(
            "report needs a subject: groups | streams | storage | recovery | connections"
                .to_string(),
        )
    })?;
    let subject = Subject::parse(subject_raw).ok_or_else(|| {
        CliError::Usage(format!(
            "unknown report subject `{subject_raw}` (expected groups | streams | storage | \
             recovery | connections)"
        ))
    })?;
    let mut addr: Option<String> = None;
    let mut filter: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--addr" | "--health-addr" => {
                addr = Some(crate::take_value("--health-addr", rest, &mut i)?);
            }
            "--filter" => filter = Some(crate::take_value("--filter", rest, &mut i)?),
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for report")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "report takes no positional arguments after the subject, got `{other}`"
                )));
            }
        }
    }
    Ok(ReportArgs {
        subject,
        addr,
        filter,
    })
}

/// Dispatches `ironbus report <subject>`: resolves the address, fetches `/metrics` once, and writes
/// the chosen subject's human table to `out`. The global `--json` envelope is applied by the
/// top-level dispatch (it captures this human output), so this renders the same table either way.
///
/// # Errors
/// [`CliError::Usage`] for a bad subject/flag; [`CliError::Unreachable`] when the broker's health
/// server cannot be reached; [`CliError::Internal`] for a non-200 or malformed `/metrics` response.
pub(crate) fn run_report(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let parsed = parse_args(args)?;
    let addr = context::resolve_addr(parsed.addr.as_deref(), DEFAULT_ADDR)?;
    let metrics = fetch_metrics(&addr)?;
    // For the per-name subjects (groups/streams), resolve an optional name filter: an explicit
    // `--filter` is used as-is (scriptable); otherwise, ON A TTY, the interactive fuzzy picker (#583)
    // offers a choice from the LIVE names; a non-interactive run with no `--filter` shows them all.
    let filter = resolve_filter(parsed.subject, parsed.filter.as_deref(), &metrics)?;
    let text = render(parsed.subject, &addr, &metrics, filter.as_deref());
    out.write_all(text.as_bytes())?;
    Ok(())
}

/// Resolves the name filter for the `groups`/`streams` subjects. With an explicit `--filter`, that
/// value is returned (no prompt — scriptable). With no `--filter` on an INTERACTIVE terminal, the
/// fuzzy picker (#583) runs over the live names and returns the chosen one. With no `--filter` and
/// NO terminal (a pipe / `--json` capture), it returns `None` — the full unfiltered table, exactly
/// the scriptable default. The scalar subjects (storage/recovery/connections) take no filter.
fn resolve_filter(
    subject: Subject,
    explicit: Option<&str>,
    m: &Metrics,
) -> Result<Option<String>, CliError> {
    let noun = match subject {
        Subject::Groups => "group",
        Subject::Streams => "stream",
        _ => return Ok(None),
    };
    if let Some(name) = explicit {
        return Ok(Some(name.to_string()));
    }
    if !fuzzy::is_interactive() {
        return Ok(None);
    }
    let candidates = match subject {
        Subject::Groups => group_names(m),
        Subject::Streams => stream_names(m),
        _ => Vec::new(),
    };
    if candidates.is_empty() {
        // Nothing to pick from: fall through to the (empty) table rather than prompting.
        return Ok(None);
    }
    fuzzy::resolve_or_pick(noun, None, &candidates).map(Some)
}

/// Fetches and parses the broker's `/metrics` snapshot, mapping the transport/HTTP error onto the
/// frozen CLI exit-code scheme (unreachable → 5, any other failure → internal 70).
fn fetch_metrics(addr: &str) -> Result<Metrics, CliError> {
    let body = metrics_fetch::fetch(addr, "/metrics").map_err(|e| map_metrics_error(addr, &e))?;
    Ok(Metrics::parse(&body))
}

/// Maps a `/metrics` fetch failure to a `CliError`: a transport failure is broker-unreachable (5);
/// a non-200 (e.g. the health server returned 503 while shutting down) or a malformed body is an
/// internal/protocol fault (70), the same split `top`/`admin` use.
fn map_metrics_error(addr: &str, e: &HttpError) -> CliError {
    match e {
        HttpError::Unreachable(_) => {
            CliError::Unreachable(format!("reading /metrics from broker at {addr}: {e}"))
        }
        HttpError::Status { .. } | HttpError::Protocol(_) => {
            CliError::Internal(format!("reading /metrics from broker at {addr}: {e}"))
        }
    }
}

/// Renders the chosen subject's human table from the parsed metrics. `filter`, when set, narrows the
/// `groups`/`streams` views to the single named row (a no-op for the scalar subjects).
fn render(subject: Subject, addr: &str, m: &Metrics, filter: Option<&str>) -> String {
    match subject {
        Subject::Groups => render_groups(addr, m, filter),
        Subject::Streams => render_streams(addr, m, filter),
        Subject::Storage => render_storage(addr, m),
        Subject::Recovery => render_recovery(addr, m),
        Subject::Connections => render_connections(addr, m),
    }
}

/// The per-work-group view: committed offset, lag, in-flight, and consumed throughput. The four
/// series are correlated by the `group` label; the default group renders as `(default)`. `filter`,
/// when set, restricts the table to that one group.
fn render_groups(addr: &str, m: &Metrics, filter: Option<&str>) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "report groups (broker /metrics at {addr})");
    let names: Vec<String> = group_names(m)
        .into_iter()
        .filter(|n| name_matches_filter(n, filter))
        .collect();
    if names.is_empty() {
        s.push_str("  (no work-groups)\n");
        return s;
    }
    let _ = writeln!(
        s,
        "{:<24} {:>14} {:>10} {:>10} {:>12}",
        "GROUP", "COMMITTED", "LAG", "IN-FLIGHT", "CONSUMED"
    );
    for name in &names {
        let committed = labeled(m, "ironbus_group_committed_offset", "group", name);
        let lag = labeled(m, "ironbus_group_consumer_lag", "group", name);
        let in_flight = labeled(m, "ironbus_group_in_flight", "group", name);
        let consumed = labeled(m, "ironbus_group_consumed_total", "group", name);
        let _ = writeln!(
            s,
            "{:<24} {committed:>14} {lag:>10} {in_flight:>10} {consumed:>12}",
            display_name(name)
        );
    }
    s
}

/// The per-stream view: produced-record throughput per stream label. `filter`, when set, restricts
/// the table to that one stream.
fn render_streams(addr: &str, m: &Metrics, filter: Option<&str>) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "report streams (broker /metrics at {addr})");
    let mut rows: Vec<(String, u64)> = m
        .family("ironbus_stream_produced_total")
        .iter()
        .map(|sample| {
            (
                sample.label("stream").unwrap_or("").to_string(),
                sample.as_u64().unwrap_or(0),
            )
        })
        .filter(|(stream, _)| name_matches_filter(stream, filter))
        .collect();
    if rows.is_empty() {
        s.push_str("  (no per-stream throughput)\n");
        return s;
    }
    let _ = writeln!(s, "{:<32} {:>14}", "STREAM", "PRODUCED");
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    for (stream, produced) in rows {
        let _ = writeln!(s, "{:<32} {produced:>14}", display_name(&stream));
    }
    s
}

/// The storage view: segments, durable footprint, disk-free, RAM headroom, write amplification. The
/// `-1` sentinels (disk-free / RAM headroom on an in-memory broker or unsupported platform) render
/// as `unavailable` so the report is honest, not a misleading zero.
fn render_storage(addr: &str, m: &Metrics) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "report storage (broker /metrics at {addr})");
    let _ = writeln!(
        s,
        "  segments:            {}",
        m.u64_or_zero("ironbus_segment_count")
    );
    let _ = writeln!(
        s,
        "  durable bytes:       {}",
        m.u64_or_zero("ironbus_durable_record_bytes")
    );
    let _ = writeln!(
        s,
        "  disk free:           {}",
        sentinel_bytes(m.i64_or("ironbus_disk_free_bytes", -1))
    );
    let _ = writeln!(
        s,
        "  RAM headroom:        {}",
        sentinel_bytes(m.i64_or("ironbus_ram_headroom_bytes", -1))
    );
    let _ = writeln!(
        s,
        "  logical written:     {}",
        m.u64_or_zero("ironbus_logical_bytes_written")
    );
    let _ = writeln!(
        s,
        "  physical written:    {}",
        m.u64_or_zero("ironbus_physical_bytes_written")
    );
    let _ = writeln!(
        s,
        "  write amp ratio:     {}",
        scalar_text(m, "ironbus_write_amp_ratio")
    );
    s
}

/// The recovery view: recovery-run / loss / truncation / quarantine counters, plus the resilience
/// freeze flag (`ironbus_writer_healthy`).
fn render_recovery(addr: &str, m: &Metrics) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "report recovery (broker /metrics at {addr})");
    let healthy = m.u64_or_zero("ironbus_writer_healthy") == 1;
    let _ = writeln!(s, "  writer healthy:        {healthy}");
    let _ = writeln!(
        s,
        "  recovery runs:         {}",
        m.u64_or_zero("ironbus_recovery_runs_total")
    );
    let _ = writeln!(
        s,
        "  recovery truncated B:  {}",
        m.u64_or_zero("ironbus_recovery_truncated_bytes")
    );
    let _ = writeln!(
        s,
        "  records skipped:       {}",
        m.u64_or_zero("ironbus_records_skipped")
    );
    let _ = writeln!(
        s,
        "  bytes skipped:         {}",
        m.u64_or_zero("ironbus_bytes_skipped")
    );
    let _ = writeln!(
        s,
        "  last skip offset:      {}",
        m.u64_or_zero("ironbus_last_skip_offset")
    );
    let _ = writeln!(
        s,
        "  truncations:           {}",
        m.u64_or_zero("ironbus_truncations_total")
    );
    let _ = writeln!(
        s,
        "  truncated records:     {}",
        m.u64_or_zero("ironbus_truncated_records_total")
    );
    let _ = writeln!(
        s,
        "  quarantine bytes:      {}",
        m.u64_or_zero("ironbus_quarantine_bytes")
    );
    // The per-reason recovery-loss breakdown, if the broker emits it. One line per reason that lost
    // any bytes (a clean broker emits zeros for every reason; we skip the all-zero rows so the
    // common case is a single summary block).
    let by_reason: Vec<(String, u64)> = m
        .family("ironbus_recovery_loss_bytes")
        .iter()
        .filter_map(|sample| {
            let bytes = sample.as_u64().unwrap_or(0);
            (bytes > 0).then(|| (sample.label("reason").unwrap_or("").to_string(), bytes))
        })
        .collect();
    if !by_reason.is_empty() {
        s.push_str("  loss by reason:\n");
        for (reason, bytes) in by_reason {
            let _ = writeln!(s, "    {reason:<22} {bytes}");
        }
    }
    s
}

/// The connections view: the lifecycle counters (`ironbus_connections_total{state}`), the live
/// gauge (`ironbus_connections_open`), and the pre-auth rejection breakdown
/// (`ironbus_connections_rejected_total{reason}`).
fn render_connections(addr: &str, m: &Metrics) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "report connections (broker /metrics at {addr})");
    let _ = writeln!(
        s,
        "  open:                  {}",
        m.u64_or_zero("ironbus_connections_open")
    );
    for state in ["accepted", "closed", "refused", "authenticated"] {
        let _ = writeln!(
            s,
            "  {:<20} {}",
            format!("{state}:"),
            m.labeled_u64("ironbus_connections_total", "state", state)
        );
    }
    s.push_str("  rejected (pre-auth):\n");
    for reason in ["rate_limited", "half_open_cap", "locked_out", "auth_failed"] {
        let _ = writeln!(
            s,
            "    {:<20} {}",
            format!("{reason}:"),
            m.labeled_u64("ironbus_connections_rejected_total", "reason", reason)
        );
    }
    s
}

// --- shared helpers ---

/// Whether `name` passes the optional exact-name `filter`: `None` ⇒ every name passes (the full
/// table); `Some(f)` ⇒ only the row whose name equals `f`. (The fuzzy MATCHING is done by the picker
/// when it CHOOSES the name; once chosen, the table shows exactly that one row.)
fn name_matches_filter(name: &str, filter: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(f) => f == name,
    }
}

/// The distinct work-group names across the group families, sorted for deterministic output. A
/// group appears if ANY of its series carries a `group` label, so a group present in only one
/// family is still listed.
pub(crate) fn group_names(m: &Metrics) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    for family in [
        "ironbus_group_committed_offset",
        "ironbus_group_consumer_lag",
        "ironbus_group_in_flight",
        "ironbus_group_consumed_total",
    ] {
        for sample in m.family(family) {
            if let Some(g) = sample.label("group") {
                names.insert(g.to_string());
            }
        }
    }
    names.into_iter().collect()
}

/// The distinct stream names from the per-stream throughput family, sorted.
pub(crate) fn stream_names(m: &Metrics) -> Vec<String> {
    let mut names: Vec<String> = m
        .family("ironbus_stream_produced_total")
        .iter()
        .filter_map(|s| s.label("stream").map(str::to_string))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Looks up one labeled `u64` sample, as a left-padded display string.
fn labeled(m: &Metrics, name: &str, key: &str, value: &str) -> u64 {
    m.labeled_u64(name, key, value)
}

/// Renders a possibly-empty label value: the empty default group/stream as `(default)`.
fn display_name(name: &str) -> &str {
    if name.is_empty() {
        "(default)"
    } else {
        name
    }
}

/// Renders a `-1` sentinel byte count as `unavailable`, else the number.
fn sentinel_bytes(v: i64) -> String {
    if v < 0 {
        "unavailable".to_string()
    } else {
        v.to_string()
    }
}

/// The raw text of a scalar series (for the float ratios), or `0` if absent.
fn scalar_text(m: &Metrics, name: &str) -> String {
    m.scalar(name)
        .map_or_else(|| "0".to_string(), |s| s.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative `/metrics` body covering every series the five subjects render, in the exact
    /// shapes the broker's health server emits (bare scalars, labeled families, `-1` sentinels).
    const FIXTURE: &str = "\
# TYPE ironbus_committed_offset gauge
ironbus_committed_offset 100
ironbus_flushed_offset 130
ironbus_in_flight 4
ironbus_writer_healthy 1
ironbus_segment_count 4
ironbus_durable_record_bytes 4096
ironbus_disk_free_bytes -1
ironbus_ram_headroom_bytes 1048576
ironbus_logical_bytes_written 5000
ironbus_physical_bytes_written 6000
ironbus_write_amp_ratio 1.2
ironbus_recovery_runs_total 2
ironbus_recovery_truncated_bytes 48
ironbus_records_skipped 3
ironbus_bytes_skipped 48
ironbus_last_skip_offset 12
ironbus_truncations_total 1
ironbus_truncated_records_total 3
ironbus_quarantine_bytes 16
ironbus_recovery_loss_bytes{reason=\"torn_tail\"} 48
ironbus_recovery_loss_bytes{reason=\"unsynced\"} 0
ironbus_connections_open 5
ironbus_connections_total{state=\"accepted\"} 20
ironbus_connections_total{state=\"closed\"} 15
ironbus_connections_total{state=\"refused\"} 1
ironbus_connections_total{state=\"authenticated\"} 18
ironbus_connections_rejected_total{reason=\"rate_limited\"} 2
ironbus_connections_rejected_total{reason=\"half_open_cap\"} 0
ironbus_connections_rejected_total{reason=\"locked_out\"} 0
ironbus_connections_rejected_total{reason=\"auth_failed\"} 4
ironbus_group_committed_offset{group=\"\"} 100
ironbus_group_committed_offset{group=\"orders\"} 120
ironbus_group_consumer_lag{group=\"\"} 30
ironbus_group_consumer_lag{group=\"orders\"} 10
ironbus_group_in_flight{group=\"\"} 0
ironbus_group_in_flight{group=\"orders\"} 4
ironbus_group_consumed_total{group=\"\"} 100
ironbus_group_consumed_total{group=\"orders\"} 120
ironbus_stream_produced_total{stream=\"events\"} 90
ironbus_stream_produced_total{stream=\"audit\"} 40
";

    fn metrics() -> Metrics {
        Metrics::parse(FIXTURE)
    }

    #[test]
    fn parse_args_rejects_a_bad_subject() {
        let args = vec!["bogus".to_string()];
        let e = parse_args(&args).unwrap_err();
        assert_eq!(e.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn parse_args_takes_every_subject_and_the_addr_synonyms() {
        for subject in ["groups", "streams", "storage", "recovery", "connections"] {
            let args = vec![subject.to_string()];
            assert!(parse_args(&args).is_ok(), "{subject}");
        }
        let a = parse_args(&[
            "groups".to_string(),
            "--addr".to_string(),
            "h:1".to_string(),
        ])
        .unwrap();
        assert_eq!(a.addr.as_deref(), Some("h:1"));
        let b = parse_args(&[
            "groups".to_string(),
            "--health-addr".to_string(),
            "h:2".to_string(),
        ])
        .unwrap();
        assert_eq!(b.addr.as_deref(), Some("h:2"));
    }

    #[test]
    fn groups_table_lists_every_group_with_correlated_series() {
        let text = render_groups("localhost:7000", &metrics(), None);
        assert!(text.contains("report groups (broker /metrics at localhost:7000)"));
        // The default group renders as (default), with its lag/in-flight/consumed correlated.
        assert!(text.contains("(default)"), "{text}");
        assert!(text.contains("orders"), "{text}");
        // orders: committed=120 lag=10 in_flight=4 consumed=120
        let orders_line = text.lines().find(|l| l.contains("orders")).unwrap();
        assert!(orders_line.contains("120"), "{orders_line}");
        assert!(orders_line.contains("10"), "{orders_line}");
        assert!(orders_line.contains('4'), "{orders_line}");
    }

    #[test]
    fn a_group_filter_restricts_the_table_to_one_row() {
        let text = render_groups("localhost:7000", &metrics(), Some("orders"));
        assert!(text.contains("orders"), "{text}");
        // The default group is excluded by the filter.
        assert!(!text.contains("(default)"), "{text}");
    }

    #[test]
    fn streams_table_lists_each_stream_sorted() {
        let text = render_streams("localhost:7000", &metrics(), None);
        let audit = text.find("audit").unwrap();
        let events = text.find("events").unwrap();
        assert!(audit < events, "streams are sorted: {text}");
        assert!(text.contains("90"), "{text}");
        assert!(text.contains("40"), "{text}");
    }

    #[test]
    fn a_stream_filter_restricts_the_table_to_one_row() {
        let text = render_streams("localhost:7000", &metrics(), Some("audit"));
        assert!(text.contains("audit"), "{text}");
        assert!(!text.contains("events"), "{text}");
    }

    #[test]
    fn storage_shows_sentinel_as_unavailable_and_real_bytes() {
        let text = render_storage("localhost:7000", &metrics());
        assert!(text.contains("segments:            4"), "{text}");
        // disk-free is the -1 sentinel here -> unavailable; RAM headroom is real.
        assert!(text.contains("disk free:           unavailable"), "{text}");
        assert!(text.contains("RAM headroom:        1048576"), "{text}");
        assert!(text.contains("write amp ratio:     1.2"), "{text}");
    }

    #[test]
    fn recovery_shows_counters_and_only_nonzero_reasons() {
        let text = render_recovery("localhost:7000", &metrics());
        assert!(text.contains("writer healthy:        true"), "{text}");
        assert!(text.contains("recovery runs:         2"), "{text}");
        assert!(text.contains("records skipped:       3"), "{text}");
        // Only the nonzero reason (torn_tail=48) is listed; the zero (unsynced) is suppressed.
        assert!(text.contains("torn_tail"), "{text}");
        assert!(
            !text.contains("unsynced"),
            "zero reasons suppressed: {text}"
        );
    }

    #[test]
    fn connections_shows_lifecycle_and_rejection_breakdown() {
        let text = render_connections("localhost:7000", &metrics());
        assert!(text.contains("open:                  5"), "{text}");
        assert!(text.contains("accepted:"), "{text}");
        assert!(text.contains("authenticated:"), "{text}");
        assert!(text.contains("rate_limited:"), "{text}");
        assert!(text.contains("auth_failed:"), "{text}");
        // auth_failed=4 present in the rejection block.
        let line = text.lines().find(|l| l.contains("auth_failed")).unwrap();
        assert!(line.contains('4'), "{line}");
    }

    #[test]
    fn group_and_stream_names_are_sorted_and_deduped() {
        let m = metrics();
        assert_eq!(group_names(&m), vec![String::new(), "orders".to_string()]);
        assert_eq!(
            stream_names(&m),
            vec!["audit".to_string(), "events".to_string()]
        );
    }

    #[test]
    fn an_empty_metrics_body_renders_a_clean_empty_table_not_a_panic() {
        let m = Metrics::parse("");
        assert!(render_groups("a", &m, None).contains("(no work-groups)"));
        assert!(render_streams("a", &m, None).contains("(no per-stream throughput)"));
        // The scalar views render zeros / unavailable, never panic.
        assert!(render_storage("a", &m).contains("segments:            0"));
        assert!(render_recovery("a", &m).contains("recovery runs:         0"));
        assert!(render_connections("a", &m).contains("open:                  0"));
    }
}
