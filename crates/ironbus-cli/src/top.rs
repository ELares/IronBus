// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ironbus top` (#93): a strictly READ-ONLY status view with two explicit modes and graceful text
//! degradation.
//!
//! - LIVE mode (`--addr`/`--health-addr`) polls the broker's read-only `/admin` v1 JSON on a fixed
//!   interval and renders the #16 counters: durable head, per-group lag and in-flight, the DLQ, the
//!   resilience counters, and the cumulative throughput counters. It reuses the SAME dependency-free
//!   `/admin` fetch and JSON extractors as `ironbus admin` ([`crate::admin`]), so there is one
//!   `/admin` client, not two, and no new dependency is pulled.
//! - OFFLINE mode (`--data-dir`) renders ONLY what the offline reader can compute from files with NO
//!   broker running (segments, durable head, the loss report, and the quarantine span), behind a
//!   MANDATORY banner that states it is the offline file-derived view, so an operator never misreads
//!   a missing volatile panel (throughput, fsync) as a real zero.
//!
//! `top` NEVER mutates anything: live mode only issues `GET /admin`; offline mode only reads the
//! data directory (the same read-only `OfflineReader` that backs `peek`/`dump`) and lists the
//! `quarantine/` subdirectory. Any operator "action" is PRINTED as the exact subcommand to run, it
//! is never executed.
//!
//! Graceful text degradation (no new dependency, hand-rolled): when stdout is a TTY and `NO_COLOR`
//! is unset and the view is refreshing (not `--once`), it does an in-place redraw with a couple of
//! simple ANSI escapes (clear-screen + cursor-home) and a colored mode banner. Otherwise (a piped /
//! non-TTY stdout, `NO_COLOR`, or `--once`) it prints a PLAIN snapshot with NO escape sequences, so
//! `ironbus top | cat` and a CI run produce clean text. The refresh SLEEPS between polls (it never
//! busy-spins), so a slow-poll on a constrained link does not burn CPU.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use std::time::Duration;

use crate::admin;
use crate::CliError;

/// The default refresh interval, in seconds (#93: "default ~1s, tunable"). The poll SLEEPS this long
/// between snapshots, so the refresh never busy-spins.
pub const DEFAULT_TOP_INTERVAL_SECS: u64 = 1;

/// The minimum refresh interval. `0` would busy-spin the poll against the broker (and the CPU),
/// which the constrained-edge requirement forbids, so it is a usage error.
const MIN_TOP_INTERVAL_SECS: u64 = 1;

/// The parsed `top` invocation: which mode, the refresh interval, and the output-shape choices.
#[derive(Debug)]
struct TopArgs {
    mode: TopMode,
    interval: Duration,
    once: bool,
    json: bool,
    /// `true` when color is suppressed by `NO_COLOR` or `--no-color`. Plain (non-TTY / `--once`)
    /// output is always escape-free regardless; this only gates the interactive redraw's color.
    no_color: bool,
}

/// The two `top` modes. They are mutually exclusive: a live address OR an offline data directory,
/// never both, never neither.
#[derive(Debug)]
enum TopMode {
    /// Poll the broker's `/admin` endpoint at `health_addr` (live).
    Live { health_addr: String },
    /// Read the data directory at `data_dir` with no broker (offline, file-derived).
    Offline { data_dir: String },
}

/// Parses and runs `top` (#93). Live mode if `--addr`/`--health-addr` is given, offline mode if
/// `--data-dir` is given; exactly one is required. Rendering is hand-rolled and degrades to plain
/// text off a TTY or under `NO_COLOR`/`--once`; the refresh sleeps between polls and never spins.
///
/// # Errors
/// [`CliError::Usage`] for a bad flag, both or neither mode, a zero interval, or a non-numeric
/// interval; [`CliError::Unreachable`] (exit 5) if a live broker is down; [`CliError::NotFound`]
/// (exit 2) if the offline data dir is absent; [`CliError::Corrupt`] (exit 4) if the chain is
/// unreadable; [`CliError::Internal`] (exit 70) on an admin protocol fault or an IO failure.
pub fn run_top(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let parsed = parse_top(args)?;
    match &parsed.mode {
        TopMode::Live { health_addr } => run_live(health_addr, &parsed, out),
        TopMode::Offline { data_dir } => run_offline(data_dir, &parsed, out),
    }
}

/// Hand-rolled flag parser, matching the rest of the CLI's style (no clap).
fn parse_top(args: &[String]) -> Result<TopArgs, CliError> {
    let mut health_addr: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let mut interval_secs = DEFAULT_TOP_INTERVAL_SECS;
    let mut once = false;
    let mut json = false;
    let mut no_color_flag = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            // `--addr` and `--health-addr` both name the broker's `/admin` HTTP endpoint (the
            // health-server address), so an operator can use either spelling, exactly as `admin` does.
            "--health-addr" | "--addr" => {
                health_addr = Some(crate::take_value("--health-addr", args, &mut i)?);
            }
            "--data-dir" => data_dir = Some(crate::take_value("--data-dir", args, &mut i)?),
            "--interval" => {
                let raw = crate::take_value("--interval", args, &mut i)?;
                interval_secs = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!(
                        "`--interval` needs a number of seconds, got `{raw}`"
                    ))
                })?;
            }
            "--once" => {
                once = true;
                i += 1;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--no-color" => {
                no_color_flag = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for top")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "top takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let mode = match (health_addr, data_dir) {
        (Some(_), Some(_)) => {
            return Err(CliError::Usage(
                "top is either LIVE (--addr/--health-addr) or OFFLINE (--data-dir), not both"
                    .to_string(),
            ));
        }
        (Some(health_addr), None) => TopMode::Live { health_addr },
        (None, Some(data_dir)) => TopMode::Offline { data_dir },
        (None, None) => {
            return Err(CliError::Usage(
                "top needs a mode: --addr/--health-addr <host:port> (live) or --data-dir <dir> (offline)"
                    .to_string(),
            ));
        }
    };
    if interval_secs < MIN_TOP_INTERVAL_SECS {
        return Err(CliError::Usage(format!(
            "`--interval` must be at least {MIN_TOP_INTERVAL_SECS} second(s) (0 would busy-spin)"
        )));
    }
    // `NO_COLOR` (any non-empty value) or `--no-color` suppresses color, per the `NO_COLOR`
    // convention; either way an interactive redraw stays uncolored.
    let no_color = no_color_flag || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    Ok(TopArgs {
        mode,
        interval: Duration::from_secs(interval_secs),
        once,
        json,
        no_color,
    })
}

/// `true` when the view should do an in-place ANSI redraw: stdout is a real terminal, color is not
/// suppressed, and this is a refreshing (not `--once`) run. Off a TTY, under `NO_COLOR`, or with
/// `--once`, this is `false` and the output is plain line-by-line text with NO escape sequences.
fn interactive(args: &TopArgs) -> bool {
    !args.once && !args.no_color && std::io::stdout().is_terminal()
}

// --- LIVE mode -------------------------------------------------------------------------------

/// Drives the live poll loop: fetch `/admin`, render, and (unless `--once`) sleep the interval and
/// repeat. A fetch failure exits with the mapped code (a down broker is exit 5), so a live `top`
/// against a dead broker fails rather than silently showing stale or zero values.
fn run_live(health_addr: &str, args: &TopArgs, out: &mut impl Write) -> Result<(), CliError> {
    let redraw = interactive(args);
    loop {
        let snapshot = fetch_live_snapshot(health_addr)?;
        let text = if args.json {
            render_live_json(health_addr, &snapshot)
        } else {
            render_live(health_addr, &snapshot, args)
        };
        emit(out, &text, redraw)?;
        if args.once {
            return Ok(());
        }
        // SLEEP between polls: the refresh is interval-driven, never a busy-spin, so a slow-poll on
        // a constrained link costs no CPU.
        std::thread::sleep(args.interval);
    }
}

/// The live counters `top` renders, projected out of the `/admin` v1 JSON (the #16 set). Parsed by
/// the shared [`crate::admin`] extractors, so the CLI has ONE `/admin` JSON parser.
#[derive(Debug)]
struct LiveSnapshot {
    schema_version: u64,
    frozen: bool,
    durable_head: u64,
    committed: u64,
    earliest_retained: u64,
    segment_count: u64,
    durable_record_count: u64,
    durable_record_bytes: u64,
    // Cumulative throughput counters (#16): the rate panels a live operator watches.
    produced: u64,
    produced_bytes: u64,
    delivered: u64,
    redelivered: u64,
    dead_lettered: u64,
    acks: u64,
    // Resilience (#8/#16): a bounded loss is never silent here either.
    last_skip_offset: u64,
    records_skipped: u64,
    bytes_skipped: u64,
    // DLQ depth (#63).
    dlq_records: u64,
    dlq_last_offset: i64,
    groups: Vec<admin::ConsumerRow>,
}

/// Fetches and parses one live `/admin` snapshot. Reuses [`crate::admin::fetch_admin`] (the v1
/// Accept header, the timeouts, the size bound) and the shared extractors; a broker that is down is
/// mapped to [`CliError::Unreachable`] (exit 5), an unparseable body to [`CliError::Internal`].
fn fetch_live_snapshot(health_addr: &str) -> Result<LiveSnapshot, CliError> {
    let body = admin::fetch_admin(health_addr).map_err(|e| match e {
        admin::AdminError::Unreachable(m) => CliError::Unreachable(m),
        admin::AdminError::Protocol(m) => CliError::Internal(m),
    })?;
    parse_live_snapshot(&body).map_err(CliError::Internal)
}

/// Parses the live snapshot out of an `/admin` v1 body. Pulls the broker/segments/resilience/dlq
/// objects by name and reuses [`crate::admin::parse_admin_v1`] for the per-group rows, so the group
/// table is the SAME shape `admin` renders. A missing required field names the offender.
fn parse_live_snapshot(body: &str) -> Result<LiveSnapshot, String> {
    let schema_version = admin::extract_u64(body, "schema_version")
        .ok_or_else(|| "admin body missing schema_version".to_string())?;
    if schema_version != 1 {
        return Err(format!(
            "unsupported admin schema_version {schema_version} (top understands v1)"
        ));
    }
    let broker = admin::object_slice(body, "broker")
        .ok_or_else(|| "admin body missing the broker object".to_string())?;
    let segments = admin::object_slice(body, "segments")
        .ok_or_else(|| "admin body missing the segments object".to_string())?;
    let resilience = admin::object_slice(body, "resilience")
        .ok_or_else(|| "admin body missing the resilience object".to_string())?;
    let dlq = admin::object_slice(body, "dlq")
        .ok_or_else(|| "admin body missing the dlq object".to_string())?;

    let field = |scope: &str, key: &'static str| {
        admin::extract_u64(scope, key).ok_or_else(|| format!("admin body missing {key}"))
    };

    // Reuse the admin v1 parser for the per-group consumer rows (and the frozen flag), so the table
    // `top` shows is byte-for-byte the same projection `admin` shows.
    let view = admin::parse_admin_v1(body).map_err(|e| e.to_string())?;

    Ok(LiveSnapshot {
        schema_version,
        frozen: view.frozen,
        durable_head: field(segments, "head_offset")?,
        committed: field(broker, "committed_offset")?,
        earliest_retained: field(segments, "earliest_retained_offset")?,
        segment_count: field(segments, "count")?,
        durable_record_count: field(segments, "durable_record_count")?,
        durable_record_bytes: field(segments, "durable_record_bytes")?,
        produced: field(broker, "produced")?,
        produced_bytes: field(broker, "produced_bytes")?,
        delivered: field(broker, "delivered")?,
        redelivered: field(broker, "redelivered")?,
        dead_lettered: field(broker, "dead_lettered")?,
        acks: field(broker, "acks")?,
        last_skip_offset: field(resilience, "last_skip_offset")?,
        records_skipped: field(resilience, "records_skipped")?,
        bytes_skipped: field(resilience, "bytes_skipped")?,
        dlq_records: field(dlq, "records")?,
        dlq_last_offset: admin::extract_i64(dlq, "last_dead_lettered_offset")
            .ok_or_else(|| "admin body missing dlq.last_dead_lettered_offset".to_string())?,
        groups: view.consumers,
    })
}

/// Renders the live snapshot as a plain, line-oriented text view (no ANSI escapes in the body), so
/// it reads cleanly on a degraded box and is easy to assert. The banner names the mode and source;
/// each panel names its `/admin` (#16) source so an operator can trace a number to its metric.
fn render_live(health_addr: &str, snap: &LiveSnapshot, args: &TopArgs) -> String {
    let mut s = String::new();
    let banner = format!(
        "ironbus top -- LIVE (broker /admin v{} at {health_addr})",
        snap.schema_version
    );
    push_banner(&mut s, &banner, interactive(args) && !args.no_color);
    let _ = writeln!(
        s,
        "broker: frozen={} durable_head={} committed={} retained_from={} [source: /admin broker, segments]",
        snap.frozen, snap.durable_head, snap.committed, snap.earliest_retained
    );
    let _ = writeln!(
        s,
        "log: segments={} records={} bytes={} [source: /admin segments]",
        snap.segment_count, snap.durable_record_count, snap.durable_record_bytes
    );
    let _ = writeln!(
        s,
        "throughput: produced={} produced_bytes={} delivered={} redelivered={} acks={} [source: /admin broker counters #16]",
        snap.produced, snap.produced_bytes, snap.delivered, snap.redelivered, snap.acks
    );
    let _ = writeln!(
        s,
        "dlq: records={} last_dead_lettered_offset={} dead_lettered={} [source: /admin dlq, broker]",
        snap.dlq_records, snap.dlq_last_offset, snap.dead_lettered
    );
    let _ = writeln!(
        s,
        "resilience: frozen={} last_skip_offset={} records_skipped={} bytes_skipped={} [source: /admin resilience]",
        snap.frozen, snap.last_skip_offset, snap.records_skipped, snap.bytes_skipped
    );
    s.push_str("consumers (per-group lag + in-flight) [source: /admin consumers]:\n");
    if snap.groups.is_empty() {
        s.push_str("  (none)\n");
    } else {
        for c in &snap.groups {
            let name = if c.name.is_empty() {
                "(default)"
            } else {
                &c.name
            };
            let _ = writeln!(
                s,
                "  {name}: committed={} lag={} in_flight={}",
                c.committed_offset, c.consumer_lag, c.in_flight
            );
        }
    }
    // top is READ-ONLY: an action is printed, never run.
    s.push_str("note: top is read-only. To act, run e.g. `ironbus dump --dlq --data-dir <dir>` or `ironbus repair --data-dir <dir>`.\n");
    s
}

/// Renders the live snapshot as a single versioned JSON object (`ironbus.cli.top.v1`), for scripting
/// and tests. Hand-rendered (no serde), matching the rest of the CLI's `--json` surfaces.
fn render_live_json(health_addr: &str, snap: &LiveSnapshot) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "{{\"schema\":\"ironbus.cli.top.v1\",\"mode\":\"live\",\"source\":\"{}\",\
\"frozen\":{},\"durable_head\":{},\"committed\":{},\"earliest_retained\":{},\
\"segment_count\":{},\"durable_record_count\":{},\"durable_record_bytes\":{},\
\"produced\":{},\"produced_bytes\":{},\"delivered\":{},\"redelivered\":{},\"acks\":{},\
\"dead_lettered\":{},\"dlq_records\":{},\"dlq_last_dead_lettered_offset\":{},\
\"last_skip_offset\":{},\"records_skipped\":{},\"bytes_skipped\":{},\"consumers\":[",
        json_escape(health_addr),
        snap.frozen,
        snap.durable_head,
        snap.committed,
        snap.earliest_retained,
        snap.segment_count,
        snap.durable_record_count,
        snap.durable_record_bytes,
        snap.produced,
        snap.produced_bytes,
        snap.delivered,
        snap.redelivered,
        snap.acks,
        snap.dead_lettered,
        snap.dlq_records,
        snap.dlq_last_offset,
        snap.last_skip_offset,
        snap.records_skipped,
        snap.bytes_skipped,
    );
    for (i, c) in snap.groups.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"name\":\"{}\",\"committed_offset\":{},\"consumer_lag\":{},\"in_flight\":{}}}",
            json_escape(&c.name),
            c.committed_offset,
            c.consumer_lag,
            c.in_flight
        );
    }
    s.push_str("]}\n");
    s
}

// --- OFFLINE mode ----------------------------------------------------------------------------

/// Drives the offline view: build a file-derived snapshot, render it behind the mandatory banner,
/// and (unless `--once`) sleep the interval and repeat. Strictly read-only: it only reads the data
/// directory (re-opening each cycle to reflect changes), and never writes.
fn run_offline(data_dir: &str, args: &TopArgs, out: &mut impl Write) -> Result<(), CliError> {
    let redraw = interactive(args);
    loop {
        let snapshot = build_offline_snapshot(std::path::Path::new(data_dir))?;
        let text = if args.json {
            render_offline_json(data_dir, &snapshot)
        } else {
            render_offline(data_dir, &snapshot, args)
        };
        emit(out, &text, redraw)?;
        if args.once {
            return Ok(());
        }
        std::thread::sleep(args.interval);
    }
}

/// The file-derived offline panels: segments, durable head, the loss report, and the quarantine
/// span. These are EXACTLY what the offline reader can compute with no broker; the volatile live
/// panels (throughput, fsync, in-flight) are intentionally ABSENT, and the banner says why.
#[derive(Debug)]
struct OfflineSnapshot {
    segment_count: usize,
    durable_head: u64,
    loss_events: usize,
    loss_bytes: u64,
    loss_records_estimate: u64,
    quarantine_blobs: usize,
    quarantine_bytes: u64,
}

/// Counts the quarantine forensic blobs (`quarantine/q-*.bin`) and their total bytes, READ-ONLY (a
/// directory listing, no writes). An absent or unreadable `quarantine/` is simply "none" (a clean
/// or quarantine-free directory), never an error: the forensic store is best-effort by design.
///
/// Gated `#[cfg(unix)]`: only the Unix offline-snapshot builder calls it (the on-disk store is
/// Unix-only in v1), so on a non-Unix host it would be dead code under `-D warnings`.
#[cfg(unix)]
fn quarantine_summary(data_dir: &std::path::Path) -> (usize, u64) {
    let dir = data_dir.join(ironbus_storage::quarantine::QUARANTINE_SUBDIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (0, 0);
    };
    let mut count = 0usize;
    let mut bytes = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // The quarantine store writes blobs with the EXACT lowercase `q-<...>.bin` name (see
        // `ironbus_storage::quarantine::blob_file_name`), so an exact, case-sensitive prefix/suffix
        // match is the correct identity test, not a case-insensitive extension compare.
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if name.starts_with("q-") && name.ends_with(".bin") {
            count += 1;
            if let Ok(meta) = entry.metadata() {
                bytes = bytes.saturating_add(meta.len());
            }
        }
    }
    (count, bytes)
}

#[cfg(unix)]
fn build_offline_snapshot(data_dir: &std::path::Path) -> Result<OfflineSnapshot, CliError> {
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::offline::OfflineReader;
    let reader = OfflineReader::open(StdFs::new(data_dir.to_path_buf()))
        .map_err(|e| crate::map_offline_err(data_dir, &e))?;
    let loss = reader.loss_report();
    let (quarantine_blobs, quarantine_bytes) = quarantine_summary(data_dir);
    Ok(OfflineSnapshot {
        segment_count: reader.segment_ids().len(),
        durable_head: reader.durable_head().get(),
        loss_events: loss.events.len(),
        loss_bytes: loss.total_bytes_skipped(),
        loss_records_estimate: loss.total_records_lost_estimate(),
        quarantine_blobs,
        quarantine_bytes,
    })
}

/// The on-disk store is Unix-only in v1 (positioned IO the Windows path lacks), matching
/// `peek`/`dump`/`scrub`; the offline `top` view errors out the same way on a non-Unix host.
#[cfg(not(unix))]
fn build_offline_snapshot(data_dir: &std::path::Path) -> Result<OfflineSnapshot, CliError> {
    let _ = data_dir;
    Err(CliError::Internal(
        "ironbus top --data-dir requires a Unix host in v1: on-disk storage is Unix-only"
            .to_string(),
    ))
}

/// Renders the offline file-derived view behind the MANDATORY offline banner (#93), so an operator
/// can NEVER confuse it with the live view. Only the file-derived panels are shown; the banner
/// explicitly states the volatile live panels are unavailable offline.
fn render_offline(data_dir: &str, snap: &OfflineSnapshot, args: &TopArgs) -> String {
    let mut s = String::new();
    let banner = format!("ironbus top -- OFFLINE file-derived view of {data_dir} (NO broker)");
    push_banner(&mut s, &banner, interactive(args) && !args.no_color);
    s.push_str(
        "note: OFFLINE. These panels are derived from files on disk with no running broker; the live\n",
    );
    s.push_str(
        "      volatile panels (throughput, fsync latency, in-flight depth) are NOT available offline.\n",
    );
    let _ = writeln!(
        s,
        "log: segments={} durable_head={} [source: offline reader]",
        snap.segment_count, snap.durable_head
    );
    let _ = writeln!(
        s,
        "loss: events={} bytes={} records_estimate={} [source: offline loss report]",
        snap.loss_events, snap.loss_bytes, snap.loss_records_estimate
    );
    let _ = writeln!(
        s,
        "quarantine: blobs={} bytes={} [source: quarantine/ subdirectory]",
        snap.quarantine_blobs, snap.quarantine_bytes
    );
    s.push_str("note: top is read-only. To inspect, run e.g. `ironbus scrub --data-dir <dir>` or `ironbus dump --data-dir <dir>`.\n");
    s
}

/// Renders the offline snapshot as a single versioned JSON object (`ironbus.cli.top.v1`), with the
/// mode tagged `"offline"` so a script can tell the two modes apart (the mandatory banner of the
/// human view, in machine form).
fn render_offline_json(data_dir: &str, snap: &OfflineSnapshot) -> String {
    format!(
        "{{\"schema\":\"ironbus.cli.top.v1\",\"mode\":\"offline\",\"source\":\"{}\",\
\"segment_count\":{},\"durable_head\":{},\
\"loss_events\":{},\"loss_bytes\":{},\"loss_records_estimate\":{},\
\"quarantine_blobs\":{},\"quarantine_bytes\":{}}}\n",
        json_escape(data_dir),
        snap.segment_count,
        snap.durable_head,
        snap.loss_events,
        snap.loss_bytes,
        snap.loss_records_estimate,
        snap.quarantine_blobs,
        snap.quarantine_bytes,
    )
}

// --- shared rendering / output ---------------------------------------------------------------

/// SGR bold + cyan for the banner, and the reset, used ONLY on the interactive (TTY, color-on)
/// path. They are the only color escapes `top` ever emits.
const BANNER_ON: &str = "\x1b[1;36m";
const SGR_RESET: &str = "\x1b[0m";
/// Clear the whole screen and move the cursor to the home position, for the in-place redraw. Used
/// ONLY on the interactive path; the plain path emits none of this.
const CLEAR_HOME: &str = "\x1b[2J\x1b[H";

/// Pushes the mode banner. With `color`, it is wrapped in bold-cyan SGR; otherwise it is plain text.
/// The banner is ALWAYS present (in both modes and both color states), only its styling changes, so
/// the offline-vs-live distinction is never lost to degradation.
fn push_banner(s: &mut String, banner: &str, color: bool) {
    if color {
        let _ = writeln!(s, "{BANNER_ON}{banner}{SGR_RESET}");
    } else {
        let _ = writeln!(s, "{banner}");
    }
}

/// Writes one rendered frame. On the interactive (TTY, color-on, refreshing) path it clears the
/// screen and homes the cursor first, so successive frames redraw in place. On the plain path it
/// writes the text as-is, with NO escape sequences, so a pipe or a CI log stays clean.
fn emit(out: &mut impl Write, text: &str, redraw: bool) -> Result<(), CliError> {
    if redraw {
        out.write_all(CLEAR_HOME.as_bytes())?;
    }
    out.write_all(text.as_bytes())?;
    out.flush()?;
    Ok(())
}

/// Escapes a string for a JSON string value (the two structural escapes plus the control characters
/// JSON requires). Addresses and paths are ASCII in practice, but the escape is unconditional so a
/// path with a quote can never produce malformed JSON.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `/admin` v1 body in the exact shape the server renders, for the live-parse/render tests.
    const SAMPLE: &str = "{\"schema_version\":1,\
        \"broker\":{\"healthy\":true,\"flushed_offset\":7,\"committed_offset\":3,\
            \"earliest_retained_offset\":1,\"consumer_lag\":4,\"durable_record_bytes\":120,\
            \"durable_record_count\":6,\"segment_count\":2,\"recovery_truncated_bytes\":0,\
            \"produced\":10,\"produced_bytes\":200,\"produce_rejected\":0,\"delivered\":8,\
            \"redelivered\":1,\"dead_lettered\":2,\"acks\":3,\"segments_reaped\":0,\
            \"segments_force_reaped\":0,\"truncations\":0,\"truncated_records\":0},\
        \"segments\":{\"count\":2,\"earliest_retained_offset\":1,\"head_offset\":7,\
            \"durable_record_count\":6,\"durable_record_bytes\":120},\
        \"consumers\":[\
            {\"name\":\"\",\"committed_offset\":3,\"consumer_lag\":4,\"in_flight\":1},\
            {\"name\":\"orders\",\"committed_offset\":5,\"consumer_lag\":2,\"in_flight\":0}],\
        \"groups\":[\
            {\"name\":\"\",\"committed_offset\":3,\"consumer_lag\":4,\"in_flight\":1},\
            {\"name\":\"orders\",\"committed_offset\":5,\"consumer_lag\":2,\"in_flight\":0}],\
        \"resilience\":{\"frozen\":false,\"last_skip_offset\":4,\"records_skipped\":3,\
            \"bytes_skipped\":48,\"recovery_truncated_bytes\":0,\"counter_checkpoint_repairs\":1},\
        \"dlq\":{\"records\":2,\"last_dead_lettered_offset\":6},\
        \"config\":{\"max_total_bytes\":1000000}}";

    fn live_args(json: bool) -> TopArgs {
        TopArgs {
            mode: TopMode::Live {
                health_addr: "x".to_string(),
            },
            interval: Duration::from_secs(1),
            once: true,
            json,
            no_color: true,
        }
    }

    fn offline_args(json: bool) -> TopArgs {
        TopArgs {
            mode: TopMode::Offline {
                data_dir: "d".to_string(),
            },
            interval: Duration::from_secs(1),
            once: true,
            json,
            no_color: true,
        }
    }

    #[test]
    fn parses_the_live_counters_from_admin_json() {
        let snap = parse_live_snapshot(SAMPLE).expect("the sample parses");
        assert_eq!(snap.durable_head, 7);
        assert_eq!(snap.committed, 3);
        assert_eq!(snap.earliest_retained, 1);
        assert_eq!(snap.segment_count, 2);
        assert_eq!(snap.produced, 10);
        assert_eq!(snap.delivered, 8);
        assert_eq!(snap.acks, 3);
        assert_eq!(snap.dead_lettered, 2);
        assert_eq!(snap.dlq_records, 2);
        assert_eq!(snap.dlq_last_offset, 6);
        assert_eq!(snap.last_skip_offset, 4);
        assert_eq!(snap.bytes_skipped, 48);
        assert!(!snap.frozen);
        assert_eq!(snap.groups.len(), 2);
        assert_eq!(snap.groups[1].name, "orders");
        assert_eq!(snap.groups[1].consumer_lag, 2);
    }

    #[test]
    fn a_non_v1_admin_schema_is_an_error_not_a_misrender() {
        let body = "{\"schema_version\":2}";
        let err = parse_live_snapshot(body).unwrap_err();
        assert!(err.contains("schema_version 2"), "{err}");
    }

    #[test]
    fn the_live_view_names_each_admin_source_and_is_plain() {
        let snap = parse_live_snapshot(SAMPLE).unwrap();
        let text = render_live("127.0.0.1:9", &snap, &live_args(false));
        // The mandatory mode banner is present and labelled LIVE.
        assert!(text.contains("LIVE"), "{text}");
        // The #16 counters render with their /admin source named.
        assert!(text.contains("durable_head=7"), "{text}");
        assert!(text.contains("produced=10"), "{text}");
        assert!(text.contains("[source: /admin"), "{text}");
        assert!(
            text.contains("(default): committed=3 lag=4 in_flight=1"),
            "{text}"
        );
        assert!(
            text.contains("orders: committed=5 lag=2 in_flight=0"),
            "{text}"
        );
        // top is read-only: it prints, never runs, an action.
        assert!(text.contains("read-only"), "{text}");
        // Degraded (no_color) output carries NO ANSI escape sequence.
        assert!(
            !text.contains('\x1b'),
            "plain live output must be escape-free: {text:?}"
        );
    }

    #[test]
    fn the_live_json_is_the_versioned_top_v1_shape() {
        let snap = parse_live_snapshot(SAMPLE).unwrap();
        let json = render_live_json("a:1", &snap);
        assert!(json.contains("\"schema\":\"ironbus.cli.top.v1\""), "{json}");
        assert!(json.contains("\"mode\":\"live\""), "{json}");
        assert!(json.contains("\"durable_head\":7"), "{json}");
        assert!(
            json.contains("\"dlq_last_dead_lettered_offset\":6"),
            "{json}"
        );
        assert!(!json.contains('\x1b'), "json must be escape-free");
    }

    #[test]
    fn the_offline_view_has_the_mandatory_banner_and_only_file_panels() {
        let snap = OfflineSnapshot {
            segment_count: 3,
            durable_head: 42,
            loss_events: 1,
            loss_bytes: 12,
            loss_records_estimate: 1,
            quarantine_blobs: 2,
            quarantine_bytes: 8192,
        };
        let text = render_offline("/tmp/d", &snap, &offline_args(false));
        // MANDATORY offline banner (#93): an operator can never mistake offline for live.
        assert!(text.contains("OFFLINE"), "{text}");
        assert!(text.contains("file-derived"), "{text}");
        assert!(text.contains("NO broker"), "{text}");
        // The file-derived panels.
        assert!(text.contains("segments=3"), "{text}");
        assert!(text.contains("durable_head=42"), "{text}");
        assert!(text.contains("quarantine: blobs=2"), "{text}");
        // The volatile live panels are explicitly stated unavailable, never shown as a fake zero.
        assert!(text.contains("NOT available offline"), "{text}");
        assert!(
            !text.contains("throughput: produced"),
            "no live throughput panel offline: {text}"
        );
        // Read-only and escape-free.
        assert!(text.contains("read-only"), "{text}");
        assert!(
            !text.contains('\x1b'),
            "plain offline output must be escape-free: {text:?}"
        );
    }

    #[test]
    fn the_offline_json_tags_the_mode() {
        let snap = OfflineSnapshot {
            segment_count: 1,
            durable_head: 5,
            loss_events: 0,
            loss_bytes: 0,
            loss_records_estimate: 0,
            quarantine_blobs: 0,
            quarantine_bytes: 0,
        };
        let json = render_offline_json("/d", &snap);
        assert!(json.contains("\"mode\":\"offline\""), "{json}");
        assert!(json.contains("\"durable_head\":5"), "{json}");
        assert!(!json.contains('\x1b'));
    }

    #[test]
    fn parse_rejects_both_modes_and_neither() {
        let both = parse_top(&[
            "--addr".to_string(),
            "a:1".to_string(),
            "--data-dir".to_string(),
            "d".to_string(),
        ])
        .unwrap_err();
        assert_eq!(both.exit_code(), crate::EXIT_USAGE);
        let neither = parse_top(&[]).unwrap_err();
        assert_eq!(neither.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn parse_rejects_a_zero_interval_so_it_cannot_busy_spin() {
        let err = parse_top(&[
            "--addr".to_string(),
            "a:1".to_string(),
            "--interval".to_string(),
            "0".to_string(),
        ])
        .unwrap_err();
        assert_eq!(err.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn no_color_flag_suppresses_color_in_the_banner() {
        // With color off, the banner is plain text (no SGR), proving the degradation gate.
        let mut plain = String::new();
        push_banner(&mut plain, "B", false);
        assert!(!plain.contains('\x1b'), "{plain:?}");
        let mut colored = String::new();
        push_banner(&mut colored, "B", true);
        assert!(
            colored.contains('\x1b'),
            "color path emits SGR: {colored:?}"
        );
    }
}
