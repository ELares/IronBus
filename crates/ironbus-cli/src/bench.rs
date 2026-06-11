// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `ironbus bench` subcommand: a publish / subscribe / round-trip load generator with
//! production-safety and flash-endurance guards (#94).
//!
//! # What it measures
//!
//! bench drives the broker through the REAL #11 wire client (`produce` / `fetch` / `ack`) over the
//! REAL #6 produce path, so the throughput, the p50/p99/p999 latency, the per-op fsync cost, and the
//! bytes/op it reports are the true product numbers, not a synthetic in-process stub. The
//! ROUND-TRIP mode (the default) stamps each payload with its send time, reads it back off the
//! consumer, and records producer-to-consumer latency, so the fsync-cost number is honest: every
//! recorded latency includes the broker's durable group-commit `fdatasync`.
//!
//! # The two guards (the dominant requirement)
//!
//! PRODUCTION-SAFETY. By default bench targets an ISOLATED synthetic namespace: it spawns its OWN
//! broker over a fresh, randomly-named `ironbus-bench-<random>` data directory and reads through a
//! fresh, randomly-named ephemeral consumer group, then auto-deletes the directory. Because the
//! synthetic data dir is physically separate from any real broker's data dir, bench CANNOT corrupt
//! real data, and because the group name is random it CANNOT steal messages from a real consumer
//! group. Pointing bench at an existing broker (`--addr`), or naming a non-bench consumer group
//! (`--group`), is REFUSED unless the operator passes `--i-understand-this-is-live`. If the
//! auto-delete of the synthetic directory fails, bench REPORTS it and exits with an internal
//! (70+) code, so a leftover never goes unnoticed.
//!
//! FLASH-ENDURANCE. A run MUST be bounded: exactly one of `--duration` or `--count` is required, so
//! there is no unbounded default that burns edge flash write endurance. A `--no-fsync` dry-run mode
//! batches the bench-spawned broker's cursor checkpoints instead of forcing one durable cursor write
//! per ack, cutting the bench's own flash writes for a quick capacity probe; in that mode the
//! reported fsync cost is flagged not-measured, because the honest fsync number requires the
//! per-ack durable path.
//!
//! # Why this lives in `ironbus-cli`, not the `ironbus-bench` crate
//!
//! The shipped `ironbus` binary's dependency graph must stay clean. The `ironbus-bench` crate is
//! `publish = false` and pulls `hdrhistogram`, `rand`, `rand_distr`, and `serde_json`; depending on
//! it from `ironbus-cli` would drag all of that into the shipped artifact. So `ironbus bench` is a
//! thin, self-contained subcommand that reuses only crates the binary ALREADY ships
//! (`ironbus-client`, `ironbus-proto`, and `serve` itself for the isolated broker), computes its
//! percentiles with a tiny in-module sorted-sample quantile, and emits its JSON by hand like every
//! other CLI verb. It adds ZERO new dependencies. The heavyweight open-loop, coordinated-omission-
//! free SLO instrument stays in `ironbus-bench`; this is the operator-facing, safety-guarded tool
//! the issue asks for.

use crate::{CliError, StorageArg};
use std::io::Write;
use std::time::Duration;

/// The JSON schema version for `ironbus bench --json` output. Bump on any breaking change to the
/// object shape so a downstream consumer can gate on it (mirrors the bench-crate provenance and the
/// #99 admin snapshot, which both carry a `schema_version`).
pub const BENCH_JSON_SCHEMA_VERSION: u32 = 1;

/// The required isolated synthetic-namespace prefix. The default bench data directory and consumer
/// group both begin with this, so the live-mode guard can recognize a bench-owned name and refuse
/// a non-bench one without the explicit override.
pub const BENCH_NAMESPACE_PREFIX: &str = "ironbus-bench-";

/// The exit code for a cleanup failure: an internal fault (70+), per the frozen #91 scheme. A
/// leftover synthetic directory is a resource leak the operator must see, so it is never a clean
/// exit.
pub const EXIT_CLEANUP_FAILED: u8 = 70;

/// Builds the typed error for a failed auto-delete of the synthetic data directory: an INTERNAL
/// fault (exit 70), naming the leftover directory and the cause, so the operator sees the leak and
/// can remove it by hand. Shared so the mapping is one place and a unit test pins that a cleanup
/// failure is never a clean (0) exit (the test FAILS if this is downgraded to a non-error).
#[must_use]
pub fn cleanup_failed_error(dir_display: &str, cause: &str) -> CliError {
    CliError::Internal(format!(
        "bench run finished but FAILED to delete the synthetic data directory {dir_display}: \
         {cause}. Remove it manually. (exit {EXIT_CLEANUP_FAILED})"
    ))
}

/// The bench workload: which path the load generator exercises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Producer only: append at the target rate, measure produce-side throughput and fsync cost.
    Publish,
    /// Consumer only: drain an already-populated queue, measure fetch/ack throughput.
    Subscribe,
    /// Producer-to-consumer: stamp each payload, read it back, measure end-to-end latency through
    /// the real #6 path so the fsync cost is honest. The default.
    RoundTrip,
}

impl Mode {
    /// Parses the `--mode` value.
    fn parse(value: &str) -> Option<Mode> {
        match value {
            "publish" | "pub" => Some(Mode::Publish),
            "subscribe" | "sub" => Some(Mode::Subscribe),
            "round-trip" | "roundtrip" | "rt" => Some(Mode::RoundTrip),
            _ => None,
        }
    }

    /// The stable string used in JSON and the reproduce line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Publish => "publish",
            Mode::Subscribe => "subscribe",
            Mode::RoundTrip => "round-trip",
        }
    }

    /// Whether this mode reads messages back (so latency and the honest fsync cost are measurable).
    #[must_use]
    pub fn measures_latency(self) -> bool {
        matches!(self, Mode::Subscribe | Mode::RoundTrip)
    }
}

/// The payload shape generated for each message. Default is `realistic`: a repetitive,
/// codec-friendly byte pattern that compresses like real edge telemetry, so the bytes/op and any
/// compression ratio are measured on REAL-shaped payloads, not incompressible noise (#94, #12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadShape {
    /// A repetitive, compressible pattern resembling real structured telemetry (the default).
    Realistic,
    /// Incompressible pseudo-random bytes, only for a worst-case stress probe (opt-in).
    Random,
}

impl PayloadShape {
    /// Parses the `--payload-shape` value.
    fn parse(value: &str) -> Option<PayloadShape> {
        match value {
            "realistic" | "real" => Some(PayloadShape::Realistic),
            "random" | "noise" => Some(PayloadShape::Random),
            _ => None,
        }
    }

    /// The stable string used in JSON and the reproduce line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadShape::Realistic => "realistic",
            PayloadShape::Random => "random",
        }
    }
}

/// Whether the run is bounded by a duration or a fixed message count. Exactly one is required:
/// there is no unbounded default (the flash-endurance guard).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    /// Stop after this wall-clock duration.
    Duration(Duration),
    /// Stop after producing (and, in a latency mode, recording) this many messages.
    Count(u64),
}

/// The fully-parsed, validated `bench` invocation.
#[derive(Clone, Debug)]
pub struct BenchConfig {
    /// The workload mode.
    pub mode: Mode,
    /// The bound that stops the run (the required `--duration` or `--count`).
    pub bound: Bound,
    /// Target arrival rate, messages per second; `None` means as-fast-as-possible (closed loop).
    pub target_rate_hz: Option<f64>,
    /// Total payload size in bytes per message (including the embedded round-trip token).
    pub payload_bytes: usize,
    /// The payload shape (realistic vs random).
    pub payload_shape: PayloadShape,
    /// Receiver fetch credit window.
    pub fetch_batch: u32,
    /// The synthetic consumer group name (random `ironbus-bench-<n>` by default).
    pub group: String,
    /// If set, target this EXISTING broker address instead of spawning an isolated one. Only ever
    /// populated when the operator passed `--i-understand-this-is-live` (the parse-time guard), so
    /// its presence alone means a deliberately-acknowledged live run.
    pub live_addr: Option<String>,
    /// Dry-run: batch the bench broker's cursor checkpoints instead of one durable write per ack,
    /// to spare edge flash. In this mode the fsync cost is not measured.
    pub no_fsync: bool,
    /// The pipelined publish window (#450): how many un-acked PUBs the publisher keeps in flight
    /// per produce call. `1` (the default) is the historical one-awaited-ack-per-publish path;
    /// `N > 1` uses [`ironbus_client::Client::produce_window`], so the broker's group commit
    /// covers the window with one fdatasync instead of N. Acks keep their unchanged
    /// fsynced-durable meaning; only WHEN the publisher awaits changes.
    pub pub_window: usize,
    /// The storage BACKEND of bench's own ISOLATED synthetic broker (#445, refs #443): `disk` (the
    /// default, the historical bench broker over an auto-deleted synthetic data dir) or `memory`
    /// (the same engine over the in-memory filesystem, for honest RAM-path numbers next to the
    /// disk numbers). The flag shapes ONLY the spawned broker, so it is refused alongside
    /// `--addr` (a live broker's backend is already decided by that broker).
    pub storage: StorageArg,
    /// Emit the versioned JSON object instead of (well, in addition to a suppressed) human view.
    pub json: bool,
}

impl BenchConfig {
    /// Whether the run is in production-safe ISOLATED mode (its own fresh broker + data dir), the
    /// default, versus LIVE mode (an existing broker named with `--addr` and `--i-understand-...`).
    #[must_use]
    pub fn is_isolated(&self) -> bool {
        self.live_addr.is_none()
    }

    /// Whether the run measures the HONEST per-op fsync cost (#445): only on the DISK backend
    /// (the in-memory engine issues NO fsync at all, so there is no durable-write cost to
    /// attribute; reporting one would be dishonest) and only outside the `--no-fsync` dry run
    /// (which batches the cursor checkpoints, so the per-ack durable path is not exercised).
    /// The callers live in `bench_run.rs` behind `cfg(unix)` (the bench broker is the real
    /// `serve` path, Unix-only in v1), so on a non-unix build this method is otherwise dead
    /// code and `-D warnings` refuses the build (the Windows CI lane caught exactly that).
    #[cfg_attr(not(unix), allow(dead_code))]
    #[must_use]
    pub fn fsync_is_measured(&self) -> bool {
        !self.no_fsync && self.storage == StorageArg::Disk
    }
}

/// A bench run's measured result, independent of how it is rendered. The latency fields are present
/// only for a mode that reads messages back; a publish-only run leaves them `None`.
#[derive(Clone, Debug, Default)]
pub struct BenchReport {
    /// Messages the producer successfully appended.
    pub produced: u64,
    /// Messages the consumer recorded end-to-end (latency modes only).
    pub recorded: u64,
    /// Wall-clock seconds the measured phase ran.
    pub elapsed_secs: f64,
    /// Achieved throughput, messages per second.
    pub msgs_per_sec: f64,
    /// Achieved throughput, megabytes per second (payload bytes moved per second).
    pub mb_per_sec: f64,
    /// Average wire bytes per op (payload bytes per recorded/produced message).
    pub bytes_per_op: f64,
    /// p50 latency, microseconds (latency modes only).
    pub p50_us: Option<f64>,
    /// p99 latency, microseconds (latency modes only).
    pub p99_us: Option<f64>,
    /// p999 latency, microseconds (latency modes only).
    pub p999_us: Option<f64>,
    /// Max observed latency, microseconds (latency modes only).
    pub max_us: Option<f64>,
    /// Mean per-op fsync cost, microseconds, attributed from the round-trip latency through the
    /// real durable path (latency modes only, and only when `fsync_measured`).
    pub fsync_cost_us: Option<f64>,
    /// Whether the fsync cost was measured through the real per-ack durable path. `false` in the
    /// `--no-fsync` dry run, so a consumer never mistakes a dry-run number for an honest one.
    pub fsync_measured: bool,
}

/// Parses the raw `bench` argument list into a validated [`BenchConfig`], or a usage error. This is
/// platform-neutral so the guard and bound rules are unit-tested on every target.
///
/// `random_suffix` injects the synthetic-name randomness through a seam so a test can assert a
/// deterministic group/data-dir name; production passes a real random suffix.
///
/// # Errors
/// Returns [`CliError::Usage`] for a bad flag, a missing/duplicate bound, a live target without the
/// acknowledgement, or a non-bench group name without the acknowledgement.
// One flat arm per `bench` flag plus the two guard checks: a single linear concern (the arg loop)
// that reads better unbroken than split across helpers, so the line count is allowed past the
// default ceiling, exactly like `collect_serve_flags`.
#[allow(clippy::too_many_lines)]
pub fn parse_bench(args: &[String], random_suffix: &str) -> Result<BenchConfig, CliError> {
    let mut mode = Mode::RoundTrip;
    let mut duration: Option<Duration> = None;
    let mut count: Option<u64> = None;
    let mut rate: Option<f64> = None;
    let mut payload_bytes: usize = DEFAULT_PAYLOAD_BYTES;
    let mut payload_shape = PayloadShape::Realistic;
    let mut fetch_batch: u32 = DEFAULT_FETCH_BATCH;
    let mut group: Option<String> = None;
    let mut live_addr: Option<String> = None;
    let mut live_ack = false;
    let mut no_fsync = false;
    let mut pub_window: usize = 1;
    let mut storage: Option<StorageArg> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                let raw = take(args, &mut i, "--mode")?;
                mode = Mode::parse(&raw).ok_or_else(|| {
                    CliError::Usage(format!(
                        "`--mode` must be publish, subscribe, or round-trip, got `{raw}`"
                    ))
                })?;
            }
            "--duration" | "--duration-secs" => {
                let raw = take(args, &mut i, "--duration")?;
                let secs = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!(
                        "`--duration` needs a number of seconds, got `{raw}`"
                    ))
                })?;
                if secs == 0 {
                    return Err(CliError::Usage(
                        "`--duration` must be at least 1 second".to_string(),
                    ));
                }
                duration = Some(Duration::from_secs(secs));
            }
            "--count" => {
                let raw = take(args, &mut i, "--count")?;
                let n = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--count` needs a number, got `{raw}`"))
                })?;
                if n == 0 {
                    return Err(CliError::Usage("`--count` must be at least 1".to_string()));
                }
                count = Some(n);
            }
            "--rate" => {
                let raw = take(args, &mut i, "--rate")?;
                let hz = raw.parse::<f64>().map_err(|_| {
                    CliError::Usage(format!("`--rate` needs a number, got `{raw}`"))
                })?;
                if !(hz.is_finite() && hz > 0.0) {
                    return Err(CliError::Usage(
                        "`--rate` must be a positive number of messages per second".to_string(),
                    ));
                }
                rate = Some(hz);
            }
            "--payload-bytes" => {
                let raw = take(args, &mut i, "--payload-bytes")?;
                payload_bytes = raw.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("`--payload-bytes` needs a number, got `{raw}`"))
                })?;
            }
            "--payload-shape" => {
                let raw = take(args, &mut i, "--payload-shape")?;
                payload_shape = PayloadShape::parse(&raw).ok_or_else(|| {
                    CliError::Usage(format!(
                        "`--payload-shape` must be realistic or random, got `{raw}`"
                    ))
                })?;
            }
            "--fetch-batch" => {
                let raw = take(args, &mut i, "--fetch-batch")?;
                fetch_batch = raw.parse::<u32>().map_err(|_| {
                    CliError::Usage(format!("`--fetch-batch` needs a number, got `{raw}`"))
                })?;
                if fetch_batch == 0 {
                    return Err(CliError::Usage(
                        "`--fetch-batch` must be at least 1".to_string(),
                    ));
                }
            }
            "--group" => group = Some(take(args, &mut i, "--group")?),
            "--addr" => live_addr = Some(take(args, &mut i, "--addr")?),
            "--i-understand-this-is-live" => {
                live_ack = true;
                i += 1;
            }
            "--no-fsync" => {
                no_fsync = true;
                i += 1;
            }
            // The pipelined publish window (#450): 0 is meaningless (nothing would ever be
            // published), so it is a usage error naming the bound.
            "--pubwindow" => {
                let raw = take(args, &mut i, "--pubwindow")?;
                let parsed: usize = raw.parse().map_err(|_| {
                    CliError::Usage(format!(
                        "`--pubwindow` must be a positive integer, got `{raw}`"
                    ))
                })?;
                if parsed == 0 {
                    return Err(CliError::Usage(
                        "`--pubwindow` must be at least 1 (1 = the unpipelined default)".into(),
                    ));
                }
                pub_window = parsed;
            }
            // The isolated broker's storage backend (#445): `disk` (default) or `memory`. Reuses
            // the serve-side parser so bench and serve can never drift on the accepted names.
            "--storage" => {
                let raw = take(args, &mut i, "--storage")?;
                storage = Some(StorageArg::parse(&raw).ok_or_else(|| {
                    CliError::Usage(format!(
                        "`--storage` must be `disk` or `memory`, got `{raw}`"
                    ))
                })?);
            }
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for bench")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "bench takes no positional arguments, got `{other}`"
                )));
            }
        }
    }

    // FLASH-ENDURANCE guard: exactly one bound is required, no unbounded default.
    let bound = match (duration, count) {
        (Some(_), Some(_)) => {
            return Err(CliError::Usage(
                "bench requires exactly one of `--duration` or `--count`, not both".to_string(),
            ));
        }
        (Some(d), None) => Bound::Duration(d),
        (None, Some(c)) => Bound::Count(c),
        (None, None) => {
            return Err(CliError::Usage(
                "bench requires a bounded run: pass `--duration <secs>` or `--count <n>` (there is \
                 no unbounded default, to protect edge flash write endurance)"
                    .to_string(),
            ));
        }
    };

    if payload_bytes < ROUND_TRIP_TOKEN_LEN {
        return Err(CliError::Usage(format!(
            "`--payload-bytes` must be at least {ROUND_TRIP_TOKEN_LEN} (the round-trip token size)"
        )));
    }

    // PRODUCTION-SAFETY guard: targeting an existing broker is live and needs the explicit ack.
    if live_addr.is_some() && !live_ack {
        return Err(CliError::Usage(
            "bench refuses to target an existing broker (`--addr`): that is a LIVE run that can \
             inject load into production. Re-run with `--i-understand-this-is-live` to confirm, or \
             drop `--addr` to use the default isolated synthetic broker."
                .to_string(),
        ));
    }

    // `--storage` shapes ONLY the isolated synthetic broker bench spawns (#445). With `--addr`
    // the target broker's backend was decided when THAT broker booted, so accepting the flag
    // would silently mean nothing; refuse it instead (a no-op flag on a live run is a footgun).
    if storage.is_some() && live_addr.is_some() {
        return Err(CliError::Usage(
            "`--storage` selects the backend of bench's own ISOLATED synthetic broker; with \
             `--addr` (a live run) the target broker's backend is already decided by that broker \
             and this flag would silently mean nothing. Drop `--storage`, or drop `--addr` to \
             bench an isolated broker."
                .to_string(),
        ));
    }
    let storage = storage.unwrap_or(StorageArg::Disk);

    // PRODUCTION-SAFETY guard: a caller-named group that is not a bench namespace could be a real
    // consumer group; joining it would steal that group's messages, so it needs the ack too.
    let group = match group {
        Some(name) => {
            if !name.starts_with(BENCH_NAMESPACE_PREFIX) && !live_ack {
                return Err(CliError::Usage(format!(
                    "bench refuses to join the named consumer group `{name}`: it is not a synthetic \
                     `{BENCH_NAMESPACE_PREFIX}*` group and could be a real consumer group whose \
                     messages bench would steal. Re-run with `--i-understand-this-is-live` to \
                     confirm, or use a `{BENCH_NAMESPACE_PREFIX}*` group name."
                )));
            }
            name
        }
        // The default is a fresh, isolated synthetic group with a random suffix: a fresh ephemeral
        // cursor that no real consumer is reading.
        None => format!("{BENCH_NAMESPACE_PREFIX}{random_suffix}"),
    };

    Ok(BenchConfig {
        mode,
        bound,
        target_rate_hz: rate,
        payload_bytes,
        payload_shape,
        fetch_batch,
        group,
        live_addr,
        no_fsync,
        pub_window,
        storage,
        json,
    })
}

/// Runs a parsed `bench` invocation: executes the load (the platform seam) and renders the report
/// in the chosen output mode. This top-level entry is CROSS-PLATFORM so the renderers and the report
/// type always have a live caller on every target (the actual load run is the Unix-only seam below),
/// which keeps the non-Unix bin build warning-clean under `-D warnings` without a dead-code dance.
///
/// # Errors
/// Returns [`CliError::Unreachable`] if a live broker is down, [`CliError::Internal`] for a run or
/// synthetic-directory cleanup failure (cleanup maps to exit 70) or an unsupported platform, or a
/// write error.
pub fn run<W: Write>(cfg: &BenchConfig, out: &mut W) -> Result<(), CliError> {
    let report = execute(cfg)?;
    emit(cfg, &report, out)
}

/// Renders a finished run in the chosen output mode (JSON object or human summary).
fn emit<W: Write>(cfg: &BenchConfig, report: &BenchReport, out: &mut W) -> Result<(), CliError> {
    if cfg.json {
        write_json(cfg, report, out)
    } else {
        write_human(cfg, report, out)
    }
}

/// Executes the bench load and returns the measured report. The Unix implementation
/// ([`crate::bench_run::execute`]) spins up the isolated (or live) broker, drives the real client,
/// and auto-deletes the synthetic data dir. On a non-Unix host the on-disk broker is unavailable
/// (positioned IO the Windows path lacks), so it is an unsupported-platform internal error.
#[cfg(unix)]
fn execute(cfg: &BenchConfig) -> Result<BenchReport, CliError> {
    crate::bench_run::execute(cfg)
}

/// The non-Unix stub for [`execute`]: `bench` cannot run without the Unix-only on-disk broker. It
/// references [`BenchReport`] (the type the Unix path returns) and [`percentiles_us`]/[`fill_payload`]
/// so the shared, otherwise Unix-only-consumed surface is not flagged dead in the non-Unix bin build
/// under `-D warnings` (the cfg(not(unix)) field-read footgun, generalized).
#[cfg(not(unix))]
fn execute(cfg: &BenchConfig) -> Result<BenchReport, CliError> {
    let _ = cfg;
    // Construct a report and touch the cross-platform measurement helpers and the cleanup-error
    // builder so none is dead code on a non-Unix target. Nothing is rendered and no error but the
    // unsupported-platform one is returned: this path always fails closed.
    let _report = BenchReport::default();
    let _ = percentiles_us(&[]);
    let mut probe = [0u8; ROUND_TRIP_TOKEN_LEN + 1];
    fill_payload(&mut probe, cfg.payload_shape, 0, ROUND_TRIP_TOKEN_LEN);
    let _ = nanos_to_us(0);
    let _ = cleanup_failed_error("", "");
    Err(CliError::Internal(
        "ironbus bench requires a Unix host in v1: the isolated broker uses the Unix-only on-disk \
         storage path"
            .to_string(),
    ))
}

/// Renders a finished run as the human-readable summary. Written to `out`.
///
/// # Errors
/// Returns [`CliError`] if writing to `out` fails.
pub fn write_human<W: Write + ?Sized>(
    cfg: &BenchConfig,
    report: &BenchReport,
    out: &mut W,
) -> Result<(), CliError> {
    writeln!(
        out,
        "ironbus bench: {} mode, {}",
        cfg.mode.as_str(),
        describe_bound(&cfg.bound)
    )?;
    writeln!(
        out,
        "target:         {}",
        if cfg.is_isolated() {
            match cfg.storage {
                StorageArg::Disk => "isolated synthetic broker (auto-created, auto-deleted)",
                StorageArg::Memory => {
                    "isolated synthetic IN-MEMORY broker (ephemeral: no files, no fsync)"
                }
            }
        } else {
            "LIVE broker (operator acknowledged)"
        }
    )?;
    writeln!(out, "group:          {}", cfg.group)?;
    writeln!(out, "produced:       {} messages", report.produced)?;
    if cfg.mode.measures_latency() {
        writeln!(out, "recorded:       {} messages", report.recorded)?;
    }
    writeln!(
        out,
        "throughput:     {:.0} msg/s, {:.2} MB/s",
        report.msgs_per_sec, report.mb_per_sec
    )?;
    writeln!(out, "bytes/op:       {:.1}", report.bytes_per_op)?;
    if cfg.mode.measures_latency() {
        write_latency_line(out, "latency p50", report.p50_us)?;
        write_latency_line(out, "latency p99", report.p99_us)?;
        write_latency_line(out, "latency p999", report.p999_us)?;
        write_latency_line(out, "latency max", report.max_us)?;
    }
    if report.fsync_measured {
        write_latency_line(out, "fsync cost", report.fsync_cost_us)?;
    } else if cfg.storage == StorageArg::Memory {
        // The HONEST memory-mode wording (#445): there is no fsync in the in-memory engine, so
        // the cost is not "skipped", it does not exist. A reader comparing RAM-path numbers next
        // to disk numbers must never mistake the absence for a dry-run shortcut.
        writeln!(
            out,
            "fsync cost:     not measured (--storage memory: the in-memory engine issues no \
             fsync, so there is no durable-write cost to attribute)"
        )?;
    } else {
        writeln!(
            out,
            "fsync cost:     not measured (--no-fsync dry run; the honest fsync number needs the \
             per-ack durable path)"
        )?;
    }
    Ok(())
}

/// Writes one optional-microsecond latency line, or `n/a` when the value is absent.
fn write_latency_line<W: Write + ?Sized>(
    out: &mut W,
    label: &str,
    value: Option<f64>,
) -> Result<(), CliError> {
    match value {
        Some(v) => writeln!(out, "{label}:     {v:.1} us")?,
        None => writeln!(out, "{label}:     n/a")?,
    }
    Ok(())
}

/// Renders a finished run as the single versioned JSON object (the `--json` contract). The
/// latency-histogram fields are named EXPLICITLY (`latency_p50_us`, `latency_p99_us`,
/// `latency_p999_us`, `latency_max_us`), null when the mode does not measure them. The `storage`
/// field (#445) is ADDITIVE (schema version unchanged, the #439 `payload_entropy` precedent), so
/// a recorded run self-describes which backend it measured and a RAM-path number is never
/// mistaken for a disk number. Written to `out`.
///
/// # Errors
/// Returns [`CliError`] if writing to `out` fails.
pub fn write_json<W: Write + ?Sized>(
    cfg: &BenchConfig,
    report: &BenchReport,
    out: &mut W,
) -> Result<(), CliError> {
    writeln!(out, "{}", bench_json(cfg, report))?;
    Ok(())
}

/// Builds the versioned JSON object string. Split from [`write_json`] so a test can assert the
/// exact shape without capturing IO.
#[must_use]
pub fn bench_json(cfg: &BenchConfig, report: &BenchReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(512);
    // A write into a String is infallible, so every `write!` result is intentionally discarded.
    let _ = write!(
        s,
        "{{\"schema_version\":{},\"mode\":\"{}\",\"isolated\":{},\"group\":\"{}\",\
         \"bound\":{{{}}},\"target_rate_hz\":{},\"payload_bytes\":{},\"payload_shape\":\"{}\",\
         \"fetch_batch\":{},\"no_fsync\":{},\"pubwindow\":{},\"storage\":\"{}\",\"results\":{{\
         \"produced\":{},\"recorded\":{},\"elapsed_secs\":{},\"msgs_per_sec\":{},\
         \"mb_per_sec\":{},\"bytes_per_op\":{},\
         \"latency_p50_us\":{},\"latency_p99_us\":{},\"latency_p999_us\":{},\"latency_max_us\":{},\
         \"fsync_cost_us\":{},\"fsync_measured\":{}}}}}",
        BENCH_JSON_SCHEMA_VERSION,
        cfg.mode.as_str(),
        cfg.is_isolated(),
        escape_json(&cfg.group),
        bound_json(&cfg.bound),
        opt_f64_json(cfg.target_rate_hz),
        cfg.payload_bytes,
        cfg.payload_shape.as_str(),
        cfg.fetch_batch,
        cfg.no_fsync,
        cfg.pub_window,
        cfg.storage.as_str(),
        report.produced,
        report.recorded,
        f64_json(report.elapsed_secs),
        f64_json(report.msgs_per_sec),
        f64_json(report.mb_per_sec),
        f64_json(report.bytes_per_op),
        opt_f64_json(report.p50_us),
        opt_f64_json(report.p99_us),
        opt_f64_json(report.p999_us),
        opt_f64_json(report.max_us),
        opt_f64_json(report.fsync_cost_us),
        report.fsync_measured,
    );
    s
}

/// The `bound` sub-object fields (exactly one of duration/count is present, the other null).
fn bound_json(bound: &Bound) -> String {
    match bound {
        Bound::Duration(d) => format!("\"duration_secs\":{},\"count\":null", d.as_secs()),
        Bound::Count(n) => format!("\"duration_secs\":null,\"count\":{n}"),
    }
}

/// Describes the bound for the human view.
fn describe_bound(bound: &Bound) -> String {
    match bound {
        Bound::Duration(d) => format!("{}s run", d.as_secs()),
        Bound::Count(n) => format!("{n}-message run"),
    }
}

/// Serializes an `f64` as a JSON number, emitting `null` for a non-finite value (JSON has no NaN).
fn f64_json(v: f64) -> String {
    if v.is_finite() {
        format!("{v}")
    } else {
        "null".to_string()
    }
}

/// Serializes an optional `f64` as a JSON number or `null`.
fn opt_f64_json(v: Option<f64>) -> String {
    v.map_or_else(|| "null".to_string(), f64_json)
}

/// Escapes a string for a JSON string literal (group names are graphic ASCII today, but the escape
/// is unconditional so a future relaxation cannot produce invalid JSON). Mirrors the offline-verb
/// `escape_json` in `main.rs`; kept local so this module is platform-neutral (the `main.rs` copy is
/// Unix-gated).
fn escape_json(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// The round-trip token length: an 8-byte send-time (monotonic nanos, little-endian) plus an 8-byte
/// sequence number, embedded at the front of every payload. The consumer reads it back to compute
/// end-to-end latency. Any payload too short to carry it is never timed (so a stray message cannot
/// poison the latency sample). Mirrors the bench-crate harness `TOKEN_LEN`.
pub const ROUND_TRIP_TOKEN_LEN: usize = 16;

/// The default per-message payload size.
const DEFAULT_PAYLOAD_BYTES: usize = 256;

/// The default receiver fetch credit window.
const DEFAULT_FETCH_BATCH: u32 = 256;

/// Fills `payload` with the chosen shape AFTER the round-trip token, leaving `payload[..token_len]`
/// untouched for the caller to stamp. `realistic` writes a repetitive, codec-friendly pattern (so
/// the bytes/op and any compression ratio reflect real edge telemetry, not incompressible noise);
/// `random` writes an LCG pseudo-random fill seeded by `seq` for a worst-case incompressible probe.
/// Self-contained (no `rand` dependency) so the shipped binary's graph stays clean.
pub fn fill_payload(payload: &mut [u8], shape: PayloadShape, seq: u64, token_len: usize) {
    if payload.len() <= token_len {
        return;
    }
    let body = &mut payload[token_len..];
    match shape {
        PayloadShape::Realistic => {
            // A short, repeating ASCII record-like pattern. Highly compressible, like the
            // structured key=value telemetry an edge sensor actually emits.
            const PATTERN: &[u8] = b"ts=000000 sensor=edge temp=21.5 occ=1 batt=98 rssi=-67; ";
            for (i, b) in body.iter_mut().enumerate() {
                *b = PATTERN[i % PATTERN.len()];
            }
        }
        PayloadShape::Random => {
            // A tiny self-contained LCG (Numerical Recipes constants), seeded per message so the
            // fill is incompressible yet deterministic for a given seq. No external `rand` dep.
            let mut state = seq.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            for b in body.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                // Keep the low 8 bits of a high-entropy word; the mask makes the narrowing explicit
                // and well-defined (not a truncating cast).
                *b = u8::try_from((state >> 33) & 0xff).unwrap_or(0);
            }
        }
    }
}

/// Computes p50/p99/p999/max in MICROSECONDS from a slice of latency samples in NANOSECONDS. Sorts
/// a copy (the sample set is bounded by the run). Returns `None` for every percentile when the set
/// is empty. A tiny, dependency-free nearest-rank quantile; the heavyweight `HdrHistogram` tail
/// lives in the `ironbus-bench` crate, which the shipped binary does not depend on.
#[must_use]
pub fn percentiles_us(samples_ns: &[u64]) -> Option<(f64, f64, f64, f64)> {
    if samples_ns.is_empty() {
        return None;
    }
    let mut v = samples_ns.to_vec();
    v.sort_unstable();
    let q = |p: f64| -> f64 {
        // Nearest-rank: index = ceil(p * n) - 1, clamped into range.
        let n = v.len();
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let rank = (p * n as f64).ceil() as usize;
        let idx = rank.saturating_sub(1).min(n - 1);
        nanos_to_us(v[idx])
    };
    let max = nanos_to_us(*v.last().unwrap_or(&0));
    Some((q(0.50), q(0.99), q(0.999), max))
}

/// Nanoseconds to microseconds as `f64`. The precision loss is far below any latency bucket bench
/// reports.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn nanos_to_us(nanos: u64) -> f64 {
    nanos as f64 / 1_000.0
}

/// Takes the value following the flag at `args[*i]`, advancing `*i` past both tokens.
fn take(args: &[String], i: &mut usize, flag: &str) -> Result<String, CliError> {
    let value = args
        .get(*i + 1)
        .ok_or_else(|| CliError::Usage(format!("`{flag}` needs a value")))?
        .clone();
    *i += 2;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<BenchConfig, CliError> {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        parse_bench(&owned, "deadbeef")
    }

    #[test]
    fn a_bound_is_required() {
        // FLASH-ENDURANCE guard: no bound is a usage error. This test FAILS if the required-bound
        // guard is removed.
        let err = parse(&["--mode", "publish"]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        assert_eq!(err.exit_code(), crate::EXIT_USAGE);
        assert!(err.to_string().contains("bounded run"));
    }

    #[test]
    fn two_bounds_are_rejected() {
        let err = parse(&["--duration", "5", "--count", "100"]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        assert!(err.to_string().contains("not both"));
    }

    #[test]
    fn duration_bound_parses() {
        let cfg = parse(&["--duration", "5"]).unwrap();
        assert_eq!(cfg.bound, Bound::Duration(Duration::from_secs(5)));
    }

    #[test]
    fn count_bound_parses() {
        let cfg = parse(&["--count", "1000"]).unwrap();
        assert_eq!(cfg.bound, Bound::Count(1000));
    }

    #[test]
    fn a_zero_bound_is_rejected() {
        assert!(parse(&["--duration", "0"]).is_err());
        assert!(parse(&["--count", "0"]).is_err());
    }

    #[test]
    fn default_is_isolated_round_trip() {
        let cfg = parse(&["--count", "1"]).unwrap();
        assert!(
            cfg.is_isolated(),
            "default must be the isolated synthetic broker"
        );
        assert_eq!(cfg.mode, Mode::RoundTrip);
        // The default group is a fresh synthetic namespace.
        assert!(cfg.group.starts_with(BENCH_NAMESPACE_PREFIX));
        assert_eq!(cfg.group, "ironbus-bench-deadbeef");
    }

    #[test]
    fn a_live_addr_without_the_ack_is_refused() {
        // PRODUCTION-SAFETY guard. This test FAILS if the live-target guard is removed.
        let err = parse(&["--count", "1", "--addr", "10.0.0.5:7777"]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        assert!(err.to_string().contains("i-understand-this-is-live"));
    }

    #[test]
    fn a_live_addr_with_the_ack_is_allowed() {
        let cfg = parse(&[
            "--count",
            "1",
            "--addr",
            "10.0.0.5:7777",
            "--i-understand-this-is-live",
        ])
        .unwrap();
        assert!(!cfg.is_isolated());
        assert_eq!(cfg.live_addr.as_deref(), Some("10.0.0.5:7777"));
    }

    #[test]
    fn a_non_bench_group_without_the_ack_is_refused() {
        // PRODUCTION-SAFETY guard: joining a real consumer group would steal its messages. This
        // test FAILS if the named-group guard is removed.
        let err = parse(&["--count", "1", "--group", "orders"]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        assert!(err.to_string().contains("real consumer group"));
    }

    #[test]
    fn a_bench_prefixed_group_is_allowed_without_the_ack() {
        let cfg = parse(&["--count", "1", "--group", "ironbus-bench-mine"]).unwrap();
        assert_eq!(cfg.group, "ironbus-bench-mine");
    }

    #[test]
    fn a_non_bench_group_with_the_ack_is_allowed() {
        let cfg = parse(&[
            "--count",
            "1",
            "--group",
            "orders",
            "--i-understand-this-is-live",
        ])
        .unwrap();
        assert_eq!(cfg.group, "orders");
    }

    #[test]
    fn payload_below_the_token_is_rejected() {
        let err = parse(&["--count", "1", "--payload-bytes", "8"]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn mode_and_shape_parse() {
        let cfg = parse(&[
            "--count",
            "1",
            "--mode",
            "publish",
            "--payload-shape",
            "random",
        ])
        .unwrap();
        assert_eq!(cfg.mode, Mode::Publish);
        assert_eq!(cfg.payload_shape, PayloadShape::Random);
        assert!(!cfg.mode.measures_latency());
    }

    #[test]
    fn unknown_flag_is_a_usage_error() {
        assert!(parse(&["--count", "1", "--bogus"]).is_err());
    }

    #[test]
    fn json_schema_shape_is_versioned_and_names_latency_fields() {
        let cfg = parse(&["--count", "10", "--mode", "round-trip"]).unwrap();
        let report = BenchReport {
            produced: 10,
            recorded: 10,
            elapsed_secs: 1.0,
            msgs_per_sec: 10.0,
            mb_per_sec: 0.5,
            bytes_per_op: 256.0,
            p50_us: Some(120.0),
            p99_us: Some(800.0),
            p999_us: Some(2500.0),
            max_us: Some(3000.0),
            fsync_cost_us: Some(900.0),
            fsync_measured: true,
        };
        let json = bench_json(&cfg, &report);
        // Versioned.
        assert!(json.contains("\"schema_version\":1"), "json: {json}");
        // Explicitly-named latency-histogram fields.
        assert!(json.contains("\"latency_p50_us\":120"), "json: {json}");
        assert!(json.contains("\"latency_p99_us\":800"), "json: {json}");
        assert!(json.contains("\"latency_p999_us\":2500"), "json: {json}");
        assert!(json.contains("\"latency_max_us\":3000"), "json: {json}");
        // fsync cost present and flagged honest.
        assert!(json.contains("\"fsync_cost_us\":900"), "json: {json}");
        assert!(json.contains("\"fsync_measured\":true"), "json: {json}");
        // bytes/op.
        assert!(json.contains("\"bytes_per_op\":256"), "json: {json}");
        // It is valid JSON the std test can at least bracket-balance.
        assert!(json.starts_with('{') && json.ends_with('}'));
    }

    #[test]
    fn publish_mode_json_nulls_the_latency_fields() {
        let cfg = parse(&["--count", "5", "--mode", "publish"]).unwrap();
        let report = BenchReport {
            produced: 5,
            elapsed_secs: 1.0,
            msgs_per_sec: 5.0,
            bytes_per_op: 256.0,
            fsync_measured: true,
            ..BenchReport::default()
        };
        let json = bench_json(&cfg, &report);
        assert!(json.contains("\"latency_p50_us\":null"), "json: {json}");
        assert!(json.contains("\"latency_p999_us\":null"), "json: {json}");
    }

    #[test]
    fn default_storage_is_disk_and_measures_fsync() {
        // The #445 default: a bench that names no backend runs the historical DISK broker and
        // measures the honest fsync cost, byte-for-byte the pre-#445 behavior. The additive JSON
        // field self-describes the backend.
        let cfg = parse(&["--count", "1"]).unwrap();
        assert_eq!(cfg.storage, StorageArg::Disk);
        assert!(cfg.fsync_is_measured(), "disk + per-ack durable path");
        let json = bench_json(&cfg, &BenchReport::default());
        assert!(json.contains("\"storage\":\"disk\""), "json: {json}");
    }

    #[test]
    fn memory_storage_parses_and_never_claims_an_fsync_cost() {
        // #445: `--storage memory` selects the in-memory isolated broker, and the fsync cost is
        // HONESTLY not measured (the in-memory engine issues no fsync at all, so there is no
        // durable-write cost to attribute). This test FAILS if memory mode ever starts claiming
        // a measured fsync number.
        let cfg = parse(&["--count", "1", "--storage", "memory"]).unwrap();
        assert_eq!(cfg.storage, StorageArg::Memory);
        assert!(
            !cfg.fsync_is_measured(),
            "no fsync exists in memory mode, so none may be claimed"
        );
        let report = BenchReport {
            fsync_measured: cfg.fsync_is_measured(),
            ..BenchReport::default()
        };
        let json = bench_json(&cfg, &report);
        assert!(json.contains("\"storage\":\"memory\""), "json: {json}");
        assert!(json.contains("\"fsync_measured\":false"), "json: {json}");
        assert!(json.contains("\"fsync_cost_us\":null"), "json: {json}");
        // The human view states WHY, naming the backend rather than the dry run.
        let mut human = Vec::new();
        write_human(&cfg, &report, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("IN-MEMORY"), "human: {human}");
        assert!(
            human.contains("issues no fsync"),
            "the memory-mode fsync line states the reason: {human}"
        );
    }

    #[test]
    fn an_unknown_storage_value_is_a_usage_error() {
        let err = parse(&["--count", "1", "--storage", "tmpfs"]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        assert!(err.to_string().contains("`disk` or `memory`"));
    }

    #[test]
    fn storage_with_a_live_addr_is_refused() {
        // The flag shapes only the ISOLATED spawned broker; on a live run it would silently mean
        // nothing, so it is refused even WITH the live acknowledgement. This test FAILS if the
        // no-op-flag guard is removed.
        let err = parse(&[
            "--count",
            "1",
            "--storage",
            "memory",
            "--addr",
            "10.0.0.5:7777",
            "--i-understand-this-is-live",
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        assert!(err.to_string().contains("ISOLATED"), "{err}");
    }

    #[test]
    fn memory_storage_composes_with_the_entropy_modes() {
        // #439's payload-entropy knob applies unchanged over the memory backend: the fill is
        // payload-side and knows nothing about storage, so `--payload-shape random` (and the
        // realistic default) parse and carry through with `--storage memory`.
        let cfg = parse(&[
            "--count",
            "1",
            "--storage",
            "memory",
            "--payload-shape",
            "random",
        ])
        .unwrap();
        assert_eq!(cfg.storage, StorageArg::Memory);
        assert_eq!(cfg.payload_shape, PayloadShape::Random);
        let json = bench_json(&cfg, &BenchReport::default());
        assert!(
            json.contains("\"payload_shape\":\"random\""),
            "json: {json}"
        );
        assert!(json.contains("\"storage\":\"memory\""), "json: {json}");
    }

    #[test]
    fn no_fsync_run_flags_the_cost_not_measured() {
        let cfg = parse(&["--count", "5", "--no-fsync"]).unwrap();
        assert_eq!(cfg.pub_window, 1, "the unpipelined default");
        let w = parse(&["--count", "5", "--pubwindow", "64"]).unwrap();
        assert_eq!(w.pub_window, 64);
        // Regression (#452 round 2 found it): the arm must not double-advance past its value,
        // or the NEXT flag is silently swallowed and its value becomes a positional error.
        let after = parse(&["--count", "5", "--pubwindow", "64", "--no-fsync"]).unwrap();
        assert_eq!(after.pub_window, 64);
        assert!(
            after.no_fsync,
            "the flag after --pubwindow must still parse"
        );
        assert!(
            parse(&["--count", "5", "--pubwindow", "0"]).is_err(),
            "0 is refused"
        );
        assert!(cfg.no_fsync);
        let report = BenchReport {
            fsync_measured: false,
            ..BenchReport::default()
        };
        let json = bench_json(&cfg, &report);
        assert!(json.contains("\"no_fsync\":true"), "json: {json}");
        assert!(json.contains("\"fsync_measured\":false"), "json: {json}");
        assert!(json.contains("\"fsync_cost_us\":null"), "json: {json}");
    }

    #[test]
    fn percentiles_on_a_known_set() {
        // 1000 samples 1..=1000 microseconds (in ns). Nearest-rank p50 ~ 500us, p99 ~ 990us.
        let samples: Vec<u64> = (1..=1000).map(|n| n * 1_000).collect();
        let (p50, p99, p999, max) = percentiles_us(&samples).unwrap();
        assert!((p50 - 500.0).abs() < 1.0, "p50={p50}");
        assert!((p99 - 990.0).abs() < 1.0, "p99={p99}");
        assert!((p999 - 999.0).abs() < 1.0, "p999={p999}");
        assert!((max - 1000.0).abs() < 1.0, "max={max}");
    }

    #[test]
    fn percentiles_empty_is_none() {
        assert!(percentiles_us(&[]).is_none());
    }

    #[test]
    fn a_cleanup_failure_is_an_internal_error_with_a_nonzero_exit() {
        // PRODUCTION-SAFETY: a failed auto-delete of the synthetic directory must surface as a
        // non-zero (internal, 70+) exit, never a clean one. This test FAILS if the cleanup-failure
        // mapping is downgraded to a clean exit or a non-error.
        let err = cleanup_failed_error("/tmp/ironbus-bench-abc", "permission denied");
        assert!(matches!(err, CliError::Usage(_) | CliError::Internal(_)));
        assert_eq!(err.exit_code(), EXIT_CLEANUP_FAILED);
        assert!(
            err.exit_code() >= 70,
            "cleanup failure must be a 70+ internal code"
        );
        assert!(
            err.exit_code() != 0,
            "cleanup failure must never be a clean exit"
        );
        assert!(err.to_string().contains("/tmp/ironbus-bench-abc"));
        assert!(err.to_string().contains("FAILED to delete"));
    }

    #[test]
    fn realistic_payload_is_compressible_random_is_not() {
        // The realistic fill repeats a short pattern (so it has few distinct bytes per window),
        // while the random fill spreads across the byte space. A crude distinct-byte count
        // captures the difference without pulling a codec in.
        let mut real = vec![0u8; ROUND_TRIP_TOKEN_LEN + 512];
        let mut rand = vec![0u8; ROUND_TRIP_TOKEN_LEN + 512];
        fill_payload(&mut real, PayloadShape::Realistic, 1, ROUND_TRIP_TOKEN_LEN);
        fill_payload(&mut rand, PayloadShape::Random, 1, ROUND_TRIP_TOKEN_LEN);
        let distinct = |buf: &[u8]| {
            let body = &buf[ROUND_TRIP_TOKEN_LEN..];
            let mut seen = [false; 256];
            for &b in body {
                seen[b as usize] = true;
            }
            seen.iter().filter(|&&s| s).count()
        };
        assert!(
            distinct(&real) < distinct(&rand),
            "realistic ({}) must use fewer distinct bytes than random ({})",
            distinct(&real),
            distinct(&rand)
        );
        // The token region is left untouched by the fill for the caller to stamp.
        assert_eq!(&real[..ROUND_TRIP_TOKEN_LEN], &[0u8; ROUND_TRIP_TOKEN_LEN]);
    }

    #[test]
    fn random_fill_is_deterministic_per_seq() {
        let mut a = vec![0u8; ROUND_TRIP_TOKEN_LEN + 64];
        let mut b = vec![0u8; ROUND_TRIP_TOKEN_LEN + 64];
        fill_payload(&mut a, PayloadShape::Random, 42, ROUND_TRIP_TOKEN_LEN);
        fill_payload(&mut b, PayloadShape::Random, 42, ROUND_TRIP_TOKEN_LEN);
        assert_eq!(a, b);
        let mut c = vec![0u8; ROUND_TRIP_TOKEN_LEN + 64];
        fill_payload(&mut c, PayloadShape::Random, 43, ROUND_TRIP_TOKEN_LEN);
        assert_ne!(a, c);
    }

    // GOLDEN VECTORS shared verbatim with the twin generator's test (the same arrays appear in
    // crates/ironbus-bench/src/harness.rs): the two fills cannot import each other (ironbus-cli ships only a binary target),
    // so each side pins its OUTPUT against the same constants. If either fork drifts, its own
    // test fails against the shared bytes, closing the unpinned-fork gap the #439 review found.
    const GOLDEN_REALISTIC_48: [u8; 48] = [
        116, 115, 61, 48, 48, 48, 48, 48, 48, 32, 115, 101, 110, 115, 111, 114, 61, 101, 100, 103,
        101, 32, 116, 101, 109, 112, 61, 50, 49, 46, 53, 32, 111, 99, 99, 61, 49, 32, 98, 97, 116,
        116, 61, 57, 56, 32, 114, 115,
    ];
    const GOLDEN_LCG_SEQ7_48: [u8; 48] = [
        13, 122, 233, 98, 194, 35, 231, 240, 4, 111, 220, 44, 176, 201, 62, 192, 123, 176, 80, 223,
        215, 244, 165, 51, 114, 152, 231, 209, 196, 159, 237, 222, 67, 193, 230, 97, 13, 30, 222,
        219, 123, 19, 219, 39, 236, 191, 169, 2,
    ];

    #[test]
    fn the_fill_matches_the_bench_harness_twin_golden_vectors() {
        let mut p = vec![0u8; 16 + 48];
        fill_payload(&mut p, PayloadShape::Realistic, 7, 16);
        assert_eq!(
            p[16..],
            GOLDEN_REALISTIC_48,
            "realistic fill drifted from the twin"
        );
        let mut p = vec![0u8; 16 + 48];
        fill_payload(&mut p, PayloadShape::Random, 7, 16);
        assert_eq!(
            p[16..],
            GOLDEN_LCG_SEQ7_48,
            "random fill drifted from the twin"
        );
    }
}
