// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `ironbus-bench` binary: run one open-loop macro-bench against the shipping `ironbus` broker
//! and emit the headline metrics plus a versioned provenance JSON.
//!
//! Run on demand (NOT in per-PR CI):
//!
//! ```text
//! cargo run --release -p ironbus-bench -- \
//!     --rate 20000 --duration-secs 30 --payload-bytes 256 \
//!     --json results.json [--max-total-bytes <cap>]
//! ```
//!
//! It launches its own `ironbus serve` over a temp data dir on a loopback port (so a run is
//! self-contained and reproducible), drives it through the real #11 client, prints the human
//! summary to stdout, and writes the provenance JSON to `--json <path>` (or stdout if omitted). The
//! `--max-total-bytes` cap drives the #10 overload (shed-not-OOM) workload.
//!
//! This binary's `main` may use `expect` for one-time setup and exits with a non-zero code on a run
//! error; the harness's measurement and library logic (the `ironbus-bench` lib) never panics on the
//! hot path.

use ironbus_bench::broker::{resolve_ironbus_binary, Broker};
use ironbus_bench::harness::{run_open_loop, RunConfig, DEFAULT_SEED};
use ironbus_bench::provenance::Provenance;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// Parsed command-line options.
struct Opts {
    rate_hz: f64,
    duration: Duration,
    payload_bytes: usize,
    fetch_batch: u32,
    seed: u64,
    max_total_bytes: Option<u64>,
    json_path: Option<PathBuf>,
}

impl Default for Opts {
    fn default() -> Self {
        let d = RunConfig::default();
        Opts {
            rate_hz: d.target_rate_hz,
            duration: d.duration,
            payload_bytes: d.payload_bytes,
            fetch_batch: d.fetch_batch,
            seed: DEFAULT_SEED,
            max_total_bytes: None,
            json_path: None,
        }
    }
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

    // Locate the shipping binary built alongside this one.
    let Some(bin) = resolve_ironbus_binary() else {
        eprintln!(
            "error: could not find the `ironbus` binary next to `ironbus-bench`.\n\
             Build it first: cargo build --release -p ironbus-cli"
        );
        return ExitCode::from(1);
    };

    // A self-contained temp data dir, removed first so each run starts clean.
    let data_dir = std::env::temp_dir().join(format!("ironbus-bench-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);

    let extra: Vec<String> = match opts.max_total_bytes {
        Some(cap) => vec!["--max-total-bytes".to_string(), cap.to_string()],
        None => Vec::new(),
    };
    let extra_refs: Vec<&str> = extra.iter().map(String::as_str).collect();

    let broker = match Broker::spawn(&bin, &data_dir, &extra_refs) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: could not start the broker: {e}");
            let _ = std::fs::remove_dir_all(&data_dir);
            return ExitCode::from(1);
        }
    };

    let config = RunConfig {
        target_rate_hz: opts.rate_hz,
        duration: opts.duration,
        payload_bytes: opts.payload_bytes,
        fetch_batch: opts.fetch_batch,
        seed: opts.seed,
    };

    eprintln!(
        "running open-loop bench: rate={} msg/s, duration={:?}, payload={} B, against {} (pid {})",
        config.target_rate_hz,
        config.duration,
        config.payload_bytes,
        broker.addr(),
        broker.pid(),
    );

    let report = match run_open_loop(broker.addr(), &data_dir, broker.pid(), &config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: the bench run failed: {e}");
            drop(broker);
            let _ = std::fs::remove_dir_all(&data_dir);
            return ExitCode::from(1);
        }
    };

    print_summary(&report);

    // Build the provenance, including a reproduce command that re-creates this exact run.
    let reproduce = reproduce_command(&opts);
    let provenance = Provenance::from_report(
        &report,
        env!("IRONBUS_BENCH_GIT_SHA").to_string(),
        env!("IRONBUS_BENCH_GIT_DIRTY") == "true",
        reproduce,
    );
    let json = match provenance.to_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: could not serialize provenance: {e}");
            drop(broker);
            let _ = std::fs::remove_dir_all(&data_dir);
            return ExitCode::from(1);
        }
    };

    match &opts.json_path {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &json) {
                eprintln!(
                    "error: could not write provenance to {}: {e}",
                    path.display()
                );
                drop(broker);
                let _ = std::fs::remove_dir_all(&data_dir);
                return ExitCode::from(1);
            }
            eprintln!("provenance written to {}", path.display());
        }
        None => println!("{json}"),
    }

    drop(broker);
    let _ = std::fs::remove_dir_all(&data_dir);
    ExitCode::SUCCESS
}

/// Prints the human-readable headline summary to stderr (stdout is reserved for the JSON when no
/// `--json` path is given, so the two never interleave on a pipe).
fn print_summary(report: &ironbus_bench::RunReport) {
    let p = &report.percentiles;
    eprintln!("--- results ---");
    eprintln!("recorded:       {} messages", report.recorded);
    eprintln!(
        "throughput:     {:.0} msg/s, {:.2} MB/s",
        report.msgs_per_sec, report.mb_per_sec
    );
    eprintln!("latency p50:    {:.1} us", p.p50_us);
    eprintln!("latency p99:    {:.1} us", p.p99_us);
    eprintln!("latency p99.9:  {:.1} us", p.p999_us);
    eprintln!("latency max:    {:.1} us", p.max_us);
    match report.steady_rss_bytes {
        Some(b) => eprintln!("steady RSS:     {:.1} MiB", bytes_to_mib(b)),
        None => eprintln!("steady RSS:     unavailable on this platform"),
    }
    eprintln!(
        "data dir:       {:.1} MiB on disk, {} payload bytes produced",
        bytes_to_mib(report.data_dir_bytes),
        report.payload_bytes_produced,
    );
    match report.write_amplification {
        Some(wa) => eprintln!("write amp:      {wa:.2}x (disk bytes per payload byte)"),
        None => eprintln!("write amp:      n/a (nothing produced)"),
    }
    if !report.has_tail_resolution() {
        eprintln!(
            "note:           only {} samples recorded; p99.9 is not yet a trustworthy quantile",
            report.recorded
        );
    }
}

/// Bytes to mebibytes, for the human summary. The precision loss above 2^52 bytes is irrelevant to
/// a one-decimal MiB figure.
#[allow(clippy::cast_precision_loss)]
fn bytes_to_mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// A copy-pasteable command that reproduces this run.
fn reproduce_command(opts: &Opts) -> String {
    use std::fmt::Write as _;
    let mut cmd = format!(
        "cargo run --release -p ironbus-bench -- --rate {} --duration-secs {} \
         --payload-bytes {} --fetch-batch {} --seed {}",
        opts.rate_hz,
        opts.duration.as_secs(),
        opts.payload_bytes,
        opts.fetch_batch,
        opts.seed,
    );
    if let Some(cap) = opts.max_total_bytes {
        // `write!` to the String avoids allocating a second `format!` just to append.
        let _ = write!(cmd, " --max-total-bytes {cap}");
    }
    cmd
}

/// The usage string, printed on a parse error or `--help`.
const USAGE: &str = "\
ironbus-bench: open-loop macro-bench harness for IronBus.

USAGE:
    ironbus-bench [OPTIONS]

OPTIONS:
    --rate <msg/s>            Target arrival rate (open-loop). Default 5000.
    --duration-secs <n>       Run duration in seconds. Default 5.
    --payload-bytes <n>       Payload size in bytes (>= 16). Default 256.
    --fetch-batch <n>         Receiver fetch credit window. Default 256.
    --seed <n>                Deterministic Poisson-jitter seed.
    --max-total-bytes <n>     Broker durable-log byte cap (drives the #10 shed-not-OOM overload).
    --json <path>             Write the provenance JSON to <path> (default: stdout).
    --help                    Print this help.
";

/// A minimal `--flag value` argument parser (no external dep). Returns the parsed options or an
/// error message.
fn parse_args() -> Result<Opts, String> {
    let mut opts = Opts::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--rate" => opts.rate_hz = next_parse(&mut args, "--rate")?,
            "--duration-secs" => {
                let secs: u64 = next_parse(&mut args, "--duration-secs")?;
                opts.duration = Duration::from_secs(secs);
            }
            "--payload-bytes" => opts.payload_bytes = next_parse(&mut args, "--payload-bytes")?,
            "--fetch-batch" => opts.fetch_batch = next_parse(&mut args, "--fetch-batch")?,
            "--seed" => opts.seed = next_parse(&mut args, "--seed")?,
            "--max-total-bytes" => {
                opts.max_total_bytes = Some(next_parse(&mut args, "--max-total-bytes")?);
            }
            "--json" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--json needs a path".to_string())?;
                opts.json_path = Some(PathBuf::from(path));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if opts.rate_hz <= 0.0 {
        return Err("--rate must be positive".to_string());
    }
    if opts.duration.is_zero() {
        return Err("--duration-secs must be non-zero".to_string());
    }
    Ok(opts)
}

/// Parses the next argument value for `flag`, with a clear error if it is missing or malformed.
fn next_parse<T: std::str::FromStr>(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T, String> {
    let raw = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
    raw.parse::<T>()
        .map_err(|_| format!("{flag} value {raw:?} is not valid"))
}
