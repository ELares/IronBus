// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tiny-profile EDGE-BUDGET gate (#118, the last residual now that the #87 `edge-tiny` profile
//! exists). This is the CI gate the issue's final acceptance criterion asks for ("power-loss and
//! RAM-burst tests gate the `tiny` profile in CI"), in the form the task prefers: a Rust integration
//! test that runs in the existing `test` CI matrix, so no new workflow is needed.
//!
//! It boots the REAL `ironbus serve --profile edge-tiny` binary over a real loopback wire socket and
//! a real loopback health socket, produces a small bounded workload, scrapes `GET /metrics`, and
//! asserts the edge-resource metrics are within the DOCUMENTED tiny-profile budget. The boot/scrape
//! mechanics mirror `acceptance.rs` (parse the bound wire and health addresses from the startup
//! stdout lines; the materialized-config line is on STDERR now, #87, so it is captured separately).
//!
//! WHAT THIS GATE PROVES (all CI-runnable, all structural/budget properties, NONE a flaky RSS
//! number):
//!
//! 1. The tiny-profile KNOBS ARE IN EFFECT. The binary's own materialized-config startup line (#87)
//!    reports `profile=edge-tiny` plus every resolved knob; this test asserts the edge-tiny preset
//!    values from `docs/EDGE_CONSTRAINTS.md` section 2 are the effective config (8 MiB segments,
//!    8 / 256 KiB consumer credits, 32 connections, 64 groups, 256 in-flight, `drop-new`, 1024
//!    checkpoint). This is the "the tiny budget is actually applied" half of the gate: a regression
//!    that silently dropped the edge-tiny knobs (or a profile-content drift) fails here.
//!
//! 2. The WRITE-AMPLIFICATION budget holds. `docs/EDGE_CONSTRAINTS.md` (the flash-endurance row)
//!    fixes the edge gate at `>= 4x fails the run`: a design that writes four or more device bytes
//!    per user byte burns out the card. After the bounded workload this test asserts
//!    `ironbus_write_amp_ratio` is finite, non-zero (the workload moved the counters), and strictly
//!    UNDER 4.0. The two raw counters that derive it (`ironbus_logical_bytes_written`,
//!    `ironbus_physical_bytes_written`) both advanced and `physical >= logical` (you never write
//!    fewer device bytes than user bytes). This is a REAL edge-budget check with teeth: a framing or
//!    checkpoint change that quadrupled physical writes would trip it.
//!
//! 3. The RAM-headroom gauge reports a REAL value. The edge-tiny profile now wires a runtime RAM
//!    ceiling: the `serve` path sets `ram_ceiling_bytes = 64 MiB` for `--profile edge-tiny` (#115),
//!    and the refuse-to-boot RAM guard let the broker start because the worst-case bounded-buffer
//!    footprint the edge-tiny caps imply (~15 MiB) fits under 64 MiB. So `ironbus_ram_headroom_bytes`
//!    reports a REAL `ceiling - RSS` headroom (a non-negative number BELOW the 64 MiB ceiling), NOT
//!    the `-1` UNAVAILABLE sentinel it reported when no ceiling was configured. This test asserts the
//!    gauge is non-negative and under the ceiling. It deliberately does NOT assert a tight RSS
//!    number: a precise on-device RSS-under-64-MiB measurement is DEVICE-ONLY (a shared CI runner's
//!    RSS is meaningless and would flake), so the full RAM-burst-under-ceiling RSS assertion is the
//!    device-only residual, called out below and in the docs.
//!
//! 4. The edge series are PRESENT and BOUNDED. The portable throughput-collapse gauge
//!    (`ironbus_produce_saturated`) reads 0 under this within-budget workload (no shed), and the
//!    opt-in daily-write-budget series are present and off (`ironbus_daily_write_budget_over 0`),
//!    confirming the budget governor is wired but unset by default.
//!
//! A SECOND test in this file (#439) is the lz4 COMPANION write-amp gate: the same boot and the
//! same workload with NO `--compression` flag, so the codec the SHIPPED binary defaults to (`lz4`,
//! ADR-0003, wired by #430) is bounded by its own DERIVED threshold (see
//! `WRITE_AMP_GATE_LZ4_MILLI`). The raw gate keeps `--compression none` and the historical 4x
//! contract; without the companion no CI gate would bound the write amplification of the
//! configuration operators actually get.
//!
//! WHAT THIS GATE DELIBERATELY LEAVES DEVICE-ONLY:
//! - A precise RSS-under-the-64-MiB-ceiling assertion. The guard proves the CONFIGURED CAPS fit (a
//!   provable-from-config property, asserted here via the real headroom value), but a shared CI
//!   runner's measured RSS is not a meaningful or stable edge signal. The RAM-burst RSS-ceiling
//!   measurement is exercised on the reference device under the run discipline (`docs/RAM_BUDGET.md`,
//!   `docs/EDGE_RUN_DISCIPLINE.md`). This test asserts the real headroom and the write-amp + knob
//!   budget that ARE meaningful in CI, so it is neither flaky nor vacuous.
//!
//! `serve` and `/metrics` are Unix-only in v1 (the on-disk store uses positioned IO the Windows path
//! lacks), so the whole gate is gated to Unix. Windows still compiles this file (the `#[cfg(unix)]`
//! leaves an empty module) so the `-D warnings` clean-on-all-targets requirement holds.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The freshly-BUILT `ironbus` binary (Cargo sets this for the crate's integration tests). The gate
/// boots THIS artifact, the same binary a release would ship.
const BUILT_BIN: &str = env!("CARGO_BIN_EXE_ironbus");

/// The documented edge write-amplification gate from `docs/EDGE_CONSTRAINTS.md` (the flash-endurance
/// row): a design that writes `>= 4x` device bytes per user byte FAILS on the edge. Asserted as a
/// strict `< 4.0` bound, compared in milli-units to stay integer-exact (the metric is rendered as a
/// fixed three-decimal string, no float in the exposition).
const WRITE_AMP_GATE_MILLI: u64 = 4000;

/// The #439 companion gate's write-amp bound for the SHIPPED DEFAULT `lz4` codec, in milli-units
/// (compared integer-exact like [`WRITE_AMP_GATE_MILLI`]). DERIVED for compressed brokers, not
/// inherited from the raw gate's 4x, because post-#430 the ratio's denominator is STORED
/// (post-compression) bytes (`docs/EDGE_CONSTRAINTS.md`), which lz4 shrinks for this workload
/// while the physical framing/page cost stays fixed.
///
/// Derivation, measured on this exact `publish_gate_workload` mix:
/// - Observed: `ironbus_logical_bytes_written = 54`, `ironbus_physical_bytes_written = 382`,
///   `ironbus_write_amp_ratio = 7.074x`, byte-identical across 30 consecutive runs (the workload
///   is deterministic: 6 sequential pubs, no timing-dependent checkpoint, and `lz4_flex` encoding
///   is deterministic). The stored 54 bytes are the four tiny payloads (1+2+3+2 = 8 bytes, each
///   under the 64-byte raw-store threshold so stored raw) plus the 512-byte and 1024-byte
///   repeated-letter payloads collapsed by lz4 to ~23 stored bytes each.
/// - Bound: 20.000x, about 2.8x headroom over the observed 7.074x. That is the same proportional
///   headroom philosophy as the raw gate (typical ~1.2x against its 4x contract bound: ~3.3x),
///   absorbing cross-platform or framing-detail drift in the fixed physical cost without ever
///   letting a real regression hide: an unexplained 10x regression (70.7x; broken compression
///   accounting, framing bloat, a checkpoint storm) fails it by 3.5x, and even a doubling of the
///   deterministic measurement plus margin stays diagnosable below it.
/// - Why not 4x: 4x is the flash-endurance contract over USER bytes (device bytes per user byte,
///   #19). Under lz4 this workload's real flash wear per USER byte is 382 physical bytes for 1544
///   user bytes, about 0.25x, BETTER than the raw run's 1.212x; only the stored-bytes denominator
///   makes the metric read 7.074x. Inheriting 4x here would fail a configuration whose real wear
///   improved, while a workload-derived 20x bound still catches every regression that actually
///   writes more device bytes.
const WRITE_AMP_GATE_LZ4_MILLI: u64 = 20_000;

/// The `-1` sentinel `ironbus_ram_headroom_bytes` reports when no RAM ceiling is configured or RSS
/// is unavailable. See `crates/ironbus-server/src/rss.rs`. The edge-tiny serve path now sets a real
/// ceiling, so the gauge reports a real headroom and this is what it must NO LONGER be.
const RAM_HEADROOM_UNAVAILABLE: i64 = -1;

/// The edge-tiny RAM ceiling (#115): `serve --profile edge-tiny` wires `ram_ceiling_bytes = 64 MiB`,
/// so the headroom gauge reports a real `ceiling - RSS` value strictly under this. Mirrors
/// `EDGE_TINY_RAM_CEILING` in `crates/ironbus-cli/src/main.rs`.
const EDGE_TINY_RAM_CEILING: i64 = 64 * 1024 * 1024;

/// Kills and reaps the broker on drop, so a panicking assertion never leaks a serve process.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A self-cleaning scratch directory under the system temp root, unique per run AND per test. The
/// process-wide counter is load-bearing now that this binary holds TWO tests: they start
/// concurrently in one process, so pid + wall-clock nanos alone COLLIDED on a coarse-granularity
/// clock (both tests read the same nanosecond), making the second broker hit the #89 single-broker
/// data-dir lock while the colliding `remove_dir_all` raced the first broker's live data dir.
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "ironbus-edge-tiny-budget-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after the epoch")
                .as_nanos(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create the scratch dir");
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a successful `edge-tiny` boot yields: the kill-guard, the bound wire address, the bound
/// health address, and the captured `materialized-config` STDERR line (#87).
struct Booted {
    _guard: ChildGuard,
    wire: String,
    health: String,
    materialized_config: String,
}

/// Boots the REAL `ironbus serve --profile edge-tiny` on ephemeral loopback wire and health ports
/// over `data_dir`, parsing the bound addresses from the startup STDOUT lines and capturing the
/// `materialized-config` line from STDERR (the same boot/parse pattern as `acceptance.rs`; the
/// config line moved to stderr in #87). Fails fast (a bounded recv timeout) if the broker dies
/// before announcing both addresses, so a broken boot is a prompt failure, never a hang.
///
/// `compression` is the `--compression` value to pin, or `None` to pass NO flag at all so the
/// broker runs whatever codec the SHIPPED binary defaults to (the #439 lz4 companion gate boots
/// this way on purpose: it gates the default configuration, not a hand-picked one).
fn boot_edge_tiny(data_dir: &str, compression: Option<&str>) -> Booted {
    let mut args = vec![
        "serve",
        "--profile",
        "edge-tiny",
        "--data-dir",
        data_dir,
        "--addr",
        "127.0.0.1:0",
        "--health-addr",
        "127.0.0.1:0",
    ];
    if let Some(codec) = compression {
        args.extend(["--compression", codec]);
    }
    let mut child = Command::new(BUILT_BIN)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve --profile edge-tiny");

    // Drain STDOUT on a thread, forwarding the startup lines (the "listening on" wire line and the
    // "health endpoints on" line). A few extra lines are forwarded to absorb any future startup line.
    let stdout = child.stdout.take().expect("piped stdout");
    let (otx, orx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        for _ in 0..8 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if otx.send(line).is_err() {
                break;
            }
        }
    });

    // Drain STDERR on a thread, capturing the `materialized-config` line (#87). Kept separate so a
    // consumer that stops reading stdout after the startup lines never SIGPIPEs the broker.
    let stderr = child.stderr.take().expect("piped stderr");
    let (etx, erx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        for _ in 0..8 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if line.contains("materialized-config") && etx.send(line).is_err() {
                break;
            }
        }
    });

    let guard = ChildGuard(child);

    // Read startup lines until BOTH the wire and health addresses are seen (the #87 config line is on
    // stderr, so it never sits between these two on stdout, but loop until both are bound regardless).
    let mut wire = None;
    let mut health = None;
    while wire.is_none() || health.is_none() {
        let Ok(line) = orx.recv_timeout(Duration::from_secs(10)) else {
            break;
        };
        if let Some(addr) = line
            .split("listening on ")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .map(str::trim)
        {
            wire = Some(addr.to_string());
        } else if let Some(addr) = line
            .split("health endpoints on ")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .map(str::trim)
        {
            health = Some(addr.to_string());
        }
    }
    let (Some(wire), Some(health)) = (wire, health) else {
        panic!("edge-tiny broker did not announce both wire and health addresses before timeout");
    };

    // The materialized-config line is emitted right after the listen line, so it is available by now;
    // give the stderr drain a brief bounded window to deliver it.
    let materialized_config = erx
        .recv_timeout(Duration::from_secs(10))
        .expect("edge-tiny broker logs its materialized-config line on stderr")
        .trim()
        .to_string();

    Booted {
        _guard: guard,
        wire,
        health,
        materialized_config,
    }
}

/// Runs `ironbus pub --addr <wire> <payload>` to completion, asserting the produce was accepted.
/// Retries briefly on a transient connection error (the wire listener is up by the time `boot`
/// returns, but a freshly-accepted connection on a loaded runner can race), so the workload is
/// deterministic without being flaky; a genuinely dead broker fails fast after the bounded retries.
fn pub_one(wire: &str, payload: &str) {
    for attempt in 0..20 {
        let out = Command::new(BUILT_BIN)
            .args(["pub", "--addr", wire, payload])
            .output()
            .expect("run ironbus pub");
        if out.status.success() {
            return;
        }
        // Only a connection-time race is retryable; any other failure is a real fault, surfaced now.
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("connecting to broker") || err.contains("Connection refused"),
            "pub of {payload:?} failed for a non-transient reason: {err}"
        );
        std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
    }
    panic!("pub of {payload:?} never succeeded; the edge-tiny broker appears dead");
}

/// THE gate workload, shared verbatim by the raw (`--compression none`) gate and the #439 lz4
/// companion gate so the two measure the SAME payload mix: a few pubs of mixed-but-small payloads
/// (a handful of KiB total, so no cap can trip). The two large repeated-letter payloads are highly
/// compressible, which is exactly what makes the lz4 gate's threshold derivation different from
/// the raw gate's (see `WRITE_AMP_GATE_LZ4_MILLI`). Bounded and deterministic; `pub_one` retries
/// only a connection-time race.
fn publish_gate_workload(wire: &str) {
    let big_d = "d".repeat(512);
    let big_f = "f".repeat(1024);
    let payloads = ["a", "bb", "ccc", &big_d, "ee", &big_f];
    for p in payloads {
        pub_one(wire, p);
    }
}

/// A minimal blocking HTTP/1.0 GET against a loopback health `addr`, retrying a just-spawned health
/// thread, used to read the broker's `/metrics`. Bounded retries + a read timeout keep it from
/// hanging on a dead endpoint.
fn http_get(addr: &str, path: &str) -> String {
    for _ in 0..40 {
        if let Ok(body) = http_get_once(addr, path) {
            if !body.is_empty() {
                return body;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("health endpoint {addr} did not answer GET {path} in time");
}

fn http_get_once(addr: &str, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    Ok(body)
}

/// Reads a single Prometheus sample by EXACT line key (`<key> <value>`), skipping `# HELP`/`# TYPE`,
/// returning the raw value token (so the caller can parse it as the right numeric type).
fn metric_raw<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key} ");
    body.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        line.strip_prefix(&prefix)
            .and_then(|rest| rest.split_whitespace().next())
    })
}

/// A `u64` counter/gauge sample.
fn metric_u64(body: &str, key: &str) -> Option<u64> {
    metric_raw(body, key).and_then(|v| v.parse().ok())
}

/// An `i64` gauge sample (the `ram_headroom` gauge can be the `-1` sentinel).
fn metric_i64(body: &str, key: &str) -> Option<i64> {
    metric_raw(body, key).and_then(|v| v.parse().ok())
}

/// The `ironbus_write_amp_ratio` gauge, returned in MILLI-units (the value times 1000) so the bound
/// check stays integer-exact. The metric is rendered as a fixed `<int>.<milli:03>` string (no float
/// in the exposition), so `"3.250"` parses to `3250`. Returns `None` if absent or malformed.
fn write_amp_milli(body: &str) -> Option<u64> {
    let raw = metric_raw(body, "ironbus_write_amp_ratio")?;
    let (int_part, frac_part) = raw.split_once('.')?;
    let int_val: u64 = int_part.parse().ok()?;
    // The fraction is always exactly three digits in the exposition; parse defensively anyway.
    if frac_part.len() != 3 {
        return None;
    }
    let milli: u64 = frac_part.parse().ok()?;
    if milli >= 1000 {
        return None;
    }
    int_val.checked_mul(1000)?.checked_add(milli)
}

/// Reads one `key=value` field out of the `materialized-config` line, returning the value token.
fn config_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace().find_map(|tok| {
        tok.split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v)
    })
}

/// Asserts a `materialized-config` field equals the expected edge-tiny preset value.
fn assert_config(line: &str, key: &str, want: &str) {
    let got = config_field(line, key)
        .unwrap_or_else(|| panic!("materialized-config is missing {key}: {line}"));
    assert_eq!(
        got, want,
        "edge-tiny preset {key} must be {want}, materialized-config reports {got}: {line}"
    );
}

/// THE tiny-profile edge-budget CI gate (#118). Boots `serve --profile edge-tiny`, runs a bounded
/// workload, scrapes `/metrics`, and asserts the documented tiny-profile edge-budget properties.
#[test]
fn edge_tiny_profile_is_within_the_documented_edge_budget() {
    let scratch = Scratch::new();
    let data_dir = scratch
        .0
        .join("data")
        .to_str()
        .expect("utf8 data dir")
        .to_string();

    // Compression OFF: the write-amp gate below is the HISTORICAL raw-bytes measurement
    // of the edge write path (group commit, page-aligned writes). Under the now-wired
    // default `lz4` (#430) the same tiny repeated-letter workload writes far fewer
    // LOGICAL (stored) bytes against the same fixed physical page cost, so the
    // physical/logical ratio of this synthetic workload would no longer measure the
    // write path. The gate is codec-independent; the codec's own accounting is pinned
    // by the engine compression tests. The SHIPPED default lz4 configuration has its
    // own companion write-amp gate below (#439).
    let booted = boot_edge_tiny(&data_dir, Some("none"));

    // ====================================================================================
    // PROPERTY 1: the tiny-profile KNOBS ARE IN EFFECT (the budget is actually applied).
    // The binary's own #87 materialized-config line reports the EFFECTIVE config; assert the
    // edge-tiny preset from docs/EDGE_CONSTRAINTS.md section 2. A profile-content drift or a
    // dropped edge-tiny knob fails HERE, before any metric is read.
    // ====================================================================================
    let cfg = &booted.materialized_config;
    assert_config(cfg, "profile", "edge-tiny");
    assert_config(cfg, "max_segment_bytes", "8388608"); // 8 MiB, erase-block-friendly
    assert_config(cfg, "consumer_credit", "8");
    assert_config(cfg, "consumer_credit_bytes", "262144"); // 256 KiB, the firm RAM bound
    assert_config(cfg, "max_connections", "32");
    assert_config(cfg, "max_groups", "64");
    assert_config(cfg, "max_in_flight", "256");
    assert_config(cfg, "disk_full_policy", "drop-new"); // brownout-friendly shed
    assert_config(cfg, "checkpoint_interval", "1024");
    assert_config(cfg, "ram_ceiling_bytes", "67108864"); // 64 MiB, the refuse-to-boot RAM guard (#115)

    // ====================================================================================
    // The bounded workload: a few pubs of mixed-but-small payloads, so the edge byte counters
    // are populated WITHOUT any chance of tripping a cap (no byte cap is set; the workload is a
    // handful of KiB). Bounded and deterministic; pub_one retries only a connection-time race.
    // ====================================================================================
    publish_gate_workload(&booted.wire);

    let metrics = http_get(&booted.health, "/metrics");

    // ====================================================================================
    // PROPERTY 2: the WRITE-AMPLIFICATION budget holds (the documented `>= 4x fails` edge gate).
    // The raw counters advanced and physical >= logical; the derived ratio is finite, non-zero,
    // and strictly under 4.0. This is the real flash-endurance edge-budget check.
    // ====================================================================================
    let logical = metric_u64(&metrics, "ironbus_logical_bytes_written")
        .expect("/metrics exposes ironbus_logical_bytes_written");
    let physical = metric_u64(&metrics, "ironbus_physical_bytes_written")
        .expect("/metrics exposes ironbus_physical_bytes_written");
    assert!(
        logical > 0,
        "the bounded workload advanced the logical-bytes counter: {metrics}"
    );
    assert!(
        physical >= logical,
        "physical bytes ({physical}) are never fewer than logical bytes ({logical}); \
         write amplification is >= 1x by construction: {metrics}"
    );
    let amp_milli =
        write_amp_milli(&metrics).expect("/metrics exposes a parseable ironbus_write_amp_ratio");
    eprintln!(
        "[edge-tiny-budget] logical={logical} physical={physical} write_amp={}.{:03}x",
        amp_milli / 1000,
        amp_milli % 1000
    );
    assert!(
        amp_milli > 0,
        "after a real produce the write-amp ratio is non-zero (the workload moved the counters): {metrics}"
    );
    assert!(
        amp_milli < WRITE_AMP_GATE_MILLI,
        "write amplification {}.{:03}x must be UNDER the documented edge gate of 4.0x \
         (docs/EDGE_CONSTRAINTS.md: a design writing >= 4x device bytes per user byte FAILS the \
         edge run): {metrics}",
        amp_milli / 1000,
        amp_milli % 1000,
    );

    // ====================================================================================
    // PROPERTY 3: the RAM-headroom gauge reports a REAL value (#115). The edge-tiny serve path now
    // wires a 64 MiB ram_ceiling_bytes and the refuse-to-boot guard let the broker start (the
    // edge-tiny caps' worst-case bounded-buffer footprint, ~15 MiB, fits under 64 MiB), so
    // ram_headroom is a real `ceiling - RSS`: NON-NEGATIVE (so NOT the -1 sentinel) and strictly
    // BELOW the 64 MiB ceiling (RSS is non-zero). We deliberately do NOT assert a tight RSS number:
    // a precise RSS-under-64-MiB measurement is DEVICE-ONLY (a shared CI runner's RSS would flake).
    // This is the honest, non-flaky form: the guard's provable-from-config fit is asserted, the live
    // RSS magnitude is left to the device residual.
    // ====================================================================================
    let headroom = metric_i64(&metrics, "ironbus_ram_headroom_bytes")
        .expect("/metrics exposes ironbus_ram_headroom_bytes");
    assert_ne!(
        headroom, RAM_HEADROOM_UNAVAILABLE,
        "with the edge-tiny 64 MiB RAM ceiling configured, ram_headroom reports a REAL value, NOT \
         the -1 unavailable sentinel: {metrics}"
    );
    assert!(
        headroom >= 0,
        "a real headroom is never negative (the -1 sentinel was ruled out above): got {headroom}: {metrics}"
    );
    assert!(
        headroom < EDGE_TINY_RAM_CEILING,
        "headroom (ceiling - RSS) is strictly under the 64 MiB ceiling because RSS is non-zero: \
         got {headroom}, ceiling {EDGE_TINY_RAM_CEILING}: {metrics}"
    );

    // ====================================================================================
    // PROPERTY 4: the edge series are PRESENT and BOUNDED. The within-budget workload shed nothing,
    // so the portable throughput-collapse gauge reads 0; the opt-in daily-write-budget governor is
    // wired but unset by default (over = 0). These confirm the edge observability surface is live
    // under edge-tiny and bounded (not firing) for a healthy within-budget broker.
    // ====================================================================================
    let saturated = metric_u64(&metrics, "ironbus_produce_saturated")
        .expect("/metrics exposes ironbus_produce_saturated");
    assert_eq!(
        saturated, 0,
        "the within-budget workload shed nothing, so the throughput-collapse gauge is 0: {metrics}"
    );
    let budget_over = metric_u64(&metrics, "ironbus_daily_write_budget_over")
        .expect("/metrics exposes ironbus_daily_write_budget_over");
    assert_eq!(
        budget_over, 0,
        "the daily write budget is unset by default, so the over-budget gauge is 0: {metrics}"
    );
}

/// The #439 lz4 COMPANION write-amp gate: the same edge-tiny boot and the same payload mix as the
/// raw gate above, but with NO `--compression` flag, so the broker runs the codec the SHIPPED
/// binary defaults to (`lz4`, ADR-0003, wired by #430). The raw gate above stays the historical
/// framing/checkpoint regression contract (`--compression none`, the 4x EDGE_CONSTRAINTS.md
/// bound); without this companion, NO CI gate would bound the write amplification of the
/// configuration operators actually get, which is the #439 gap.
///
/// WHY THE BOUND IS NOT THE RAW GATE'S 4x: post-#430 the ratio's denominator
/// (`ironbus_logical_bytes_written`, the #118 meter) is STORED bytes, post-compression
/// (`docs/EDGE_CONSTRAINTS.md`: "The ratio is defined over STORED (post-compression #430) bytes:
/// under the default codec it can inflate for small compressible payloads even as the real flash
/// wear per user byte falls"). This workload's two large repeated-letter payloads collapse from
/// 512/1024 bytes to a few dozen stored bytes each, while the physical cost per record (framing,
/// page-aligned group-commit writes, checkpoints) is essentially FIXED, so the same workload that
/// measures under 4x raw legitimately measures far above 4x here. The 4x flash-endurance contract
/// is about device bytes per USER byte; dividing by stored bytes after compression shrinks the
/// denominator without adding any flash wear, so 4x is the wrong contract for a compressed broker
/// and this gate derives its own bound (see `WRITE_AMP_GATE_LZ4_MILLI`).
#[test]
fn edge_tiny_write_amp_is_bounded_under_the_shipped_default_lz4_codec() {
    let scratch = Scratch::new();
    let data_dir = scratch
        .0
        .join("data")
        .to_str()
        .expect("utf8 data dir")
        .to_string();

    // NO --compression flag: this gate exercises the DEFAULT the shipped binary boots with.
    let booted = boot_edge_tiny(&data_dir, None);

    // Pin that the shipped default IS lz4 (ADR-0003). If the default codec ever changes, this
    // fails loudly and the bound below must be re-derived for the new default, instead of the
    // gate silently measuring something the derivation comment no longer describes.
    assert_config(&booted.materialized_config, "compression", "lz4");

    // The SAME bounded workload as the raw gate, byte for byte, so the derived bound below stays
    // tied to a known payload mix.
    publish_gate_workload(&booted.wire);

    let metrics = http_get(&booted.health, "/metrics");

    // The #118 meters are live and ordered under lz4 too: logical (STORED bytes) advanced, and
    // the device never writes fewer bytes than it stores.
    let logical = metric_u64(&metrics, "ironbus_logical_bytes_written")
        .expect("/metrics exposes ironbus_logical_bytes_written");
    let physical = metric_u64(&metrics, "ironbus_physical_bytes_written")
        .expect("/metrics exposes ironbus_physical_bytes_written");
    assert!(
        logical > 0,
        "the bounded workload advanced the logical-bytes counter: {metrics}"
    );
    assert!(
        physical >= logical,
        "physical bytes ({physical}) are never fewer than logical (stored) bytes ({logical}): {metrics}"
    );

    let amp_milli = write_amp_milli(&metrics)
        .expect("/metrics exposes a parseable ironbus_write_amp_ratio under lz4");
    eprintln!(
        "[edge-tiny-budget-lz4] logical={logical} physical={physical} write_amp={}.{:03}x",
        amp_milli / 1000,
        amp_milli % 1000
    );
    assert!(
        amp_milli > 0,
        "after a real produce the write-amp ratio is non-zero (the workload moved the counters): {metrics}"
    );
    assert!(
        amp_milli < WRITE_AMP_GATE_LZ4_MILLI,
        "write amplification {}.{:03}x under the shipped default lz4 codec must stay UNDER the \
         derived companion bound of {}.{:03}x (see WRITE_AMP_GATE_LZ4_MILLI for the derivation; \
         an unexplained jump here means the default configuration's write path regressed: framing \
         bloat, a checkpoint storm, or broken compression accounting): {metrics}",
        amp_milli / 1000,
        amp_milli % 1000,
        WRITE_AMP_GATE_LZ4_MILLI / 1000,
        WRITE_AMP_GATE_LZ4_MILLI % 1000,
    );
}
