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
//! runs the bench-spawned broker at `interval` durability (ack on the page-cache write, a
//! bounded-loss forced-fdatasync window — the honest "relaxed" tier a real
//! `serve --durability-level interval` broker runs, #1027) and batches its cursor checkpoints
//! instead of forcing one durable cursor write per ack, cutting the bench's own flash writes for a
//! quick capacity probe; in that mode the reported fsync cost is flagged not-measured, because the
//! honest fsync number requires the per-ack durable path.
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

/// How the SUBSCRIBE drain settles the messages it consumes (#464). Both modes consume AND ack every
/// fetched message (no record is left un-acked); they differ ONLY in whether the acks for a fetched
/// batch are issued as one pipelined round-trip or one synchronous round-trip per message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckMode {
    /// FAIR consume (the default): settle each fetched batch with ONE pipelined
    /// [`ironbus_client::Client::ack_many`] round-trip (#469), the consume-side twin of the publish
    /// window. This measures the broker's real fetch + batch-ack throughput, comparable to a NATS
    /// pull consumer or Redis `XREADGROUP` whose clients batch their acks, instead of self-handicapping
    /// the work-queue drain to one ack RPC per message.
    Batched,
    /// LEGACY per-message ack: settle each delivered message with one synchronous
    /// [`ironbus_client::Client::ack`] round-trip before the next, the historical drain. This is a
    /// legitimate measurement of the per-message ack-RPC LATENCY ceiling (it is ack-RPC-bound, NOT
    /// fetch-bound), kept available behind `--per-message-ack`; it is NOT a fair throughput head-to-head
    /// with peers whose clients batch their acks.
    PerMessage,
}

impl AckMode {
    /// The stable string used in JSON and the reproduce line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AckMode::Batched => "batched",
            AckMode::PerMessage => "per-message",
        }
    }
}

/// Which CONSUME TIER the SUBSCRIBE drain exercises (#554, V2-M1). The two tiers are two different
/// durable-consume contracts the broker serves, so a bench that measures one is NOT measuring the
/// other; the selector makes the measured path explicit instead of implicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeTier {
    /// TIER-W (the default): the per-message-lease WORK QUEUE. A fetched batch is settled with one
    /// pipelined `ack_many` round-trip (or one synchronous `ack` per message under
    /// [`AckMode::PerMessage`]); every lease is committed INDIVIDUALLY by the broker, so it is a
    /// COMPETING consumer with the at-least-once contract a work queue needs. The [`AckMode`] flag
    /// (`--per-message-ack`) shapes ONLY this tier.
    Work,
    /// TIER-S (#655/#656/#661/#662): the STREAMING consumer-managed-offset path. The drain drives
    /// the batched [`ironbus_client::StreamingConsumer`] default (a windowed `StreamFetch` with
    /// bounded read-ahead and a periodic CUMULATIVE `StreamCommit`, the #662 ergonomic default), the
    /// durable single-consumer streaming-consume contract — the head-to-head with a NATS `JetStream`
    /// pull consumer's batched-ack drain. The [`AckMode`] flag does not apply here (a streaming
    /// consumer commits a cursor, it does not ack leases), so `--per-message-ack` is refused with it.
    Streaming,
}

impl ConsumeTier {
    /// Parses the `--consume-tier` value.
    fn parse(value: &str) -> Option<ConsumeTier> {
        match value {
            "work" | "w" => Some(ConsumeTier::Work),
            "streaming" | "stream" | "s" => Some(ConsumeTier::Streaming),
            _ => None,
        }
    }

    /// The stable string used in JSON and the reproduce line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ConsumeTier::Work => "work",
            ConsumeTier::Streaming => "streaming",
        }
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
// Each bool here is an INDEPENDENT, orthogonal CLI flag (`--no-fsync`, `--stream`,
// `--fire-and-forget`, `--json`), each mapping 1:1 to a documented option, not interdependent state
// a state machine or two-variant enum would model more clearly. Collapsing them would obscure the
// flag-to-field correspondence the parser and JSON output rely on, so the lint is allowed here with
// this rationale, exactly as `parse_bench` carries a justified `too_many_lines`.
#[allow(clippy::struct_excessive_bools)]
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
    /// Dry-run (#1027): run the spawned isolated broker at `interval` durability (ack on the
    /// page-cache write, bounded-loss forced-fdatasync window — the honest "relaxed" tier a real
    /// `serve --durability-level interval` runs) AND batch its cursor checkpoints instead of one
    /// durable write per ack, to spare edge flash. In this mode the fsync cost is not measured
    /// (the per-ack durable path is not exercised).
    pub no_fsync: bool,
    /// The pipelined publish window (#450): how many un-acked PUBs the publisher keeps in flight
    /// per produce call. `1` (the default) is the historical one-awaited-ack-per-publish path;
    /// `N > 1` uses [`ironbus_client::Client::produce_window`], so the broker's group commit
    /// covers the window with one fdatasync instead of N. Acks keep their unchanged
    /// fsynced-durable meaning; only WHEN the publisher awaits changes.
    pub pub_window: usize,
    /// FULL-DUPLEX streaming publish (#458): with `--stream`, the publisher uses
    /// [`ironbus_client::Client::produce_stream`] (a writer that never stops for acks while a
    /// reader thread drains them concurrently, in-flight capped at `pub_window`) instead of the
    /// half-duplex write-window-then-drain `produce_window` round-trips. Requires
    /// `--pubwindow >= 2`. Per-produce fsync cost is NOT attributed in this mode (the overlap
    /// makes a per-message share dishonest), so the fsync histogram stays empty.
    pub stream: bool,
    /// AT-MOST-ONCE publish (QoS-0, the #11 fast path): with `--fire-and-forget`, publish mode
    /// drives [`ironbus_client::Client::produce_fire_and_forget`], which writes the `Pub` frame and
    /// returns WITHOUT awaiting a `PubAck` (the broker may even drop it under load by contract). It
    /// trades the at-least-once guarantee for raw send throughput and no round-trip, and is the
    /// matched analog to a core fire-and-forget pub on a routing broker (e.g. NATS core). Because no
    /// ack is awaited, there is no durable-write cost to attribute, so the fsync cost is forced
    /// not-measured (exactly like the memory backend). Publish-only, and mutually exclusive with the
    /// ack-pipelining flags (`--stream`, `--pubwindow > 1`), which pipeline awaited acks this path
    /// has none of.
    pub fire_and_forget: bool,
    /// AUTO-PIPELINING durable producer (#508): with `--autopipe`, publish mode drives
    /// [`ironbus_client::Client::pipelined_producer_with_window`] (sized by `--pubwindow`, default
    /// [`ironbus_client::DEFAULT_PIPELINE_WINDOW`]) instead of the awaited per-publish
    /// [`ironbus_client::Client::produce`]. The handle buffers a window of durable publishes and
    /// flushes them as one group-committed batch, so a SINGLE producer keeps the window in flight
    /// and the broker collapses it under one fsync — the single-producer durable-throughput lever
    /// that the awaited path cannot reach (it has one publish in flight at a time). Every publish
    /// stays at-least-once and ack-implies-durable; only WHEN the ack is observed moves. Publish
    /// mode only, and mutually exclusive with `--stream` and `--fire-and-forget` (each is its own
    /// distinct publish path).
    pub auto_pipeline: bool,
    /// MULTI-PRODUCER publish (#1040): how many INDEPENDENT client CONNECTIONS `--mode publish`
    /// drives concurrently (`--producers`, default 1). Each producer is its own TCP connection
    /// running its own produce loop with the configured `--pubwindow`/`--stream` shape — the
    /// multi-connection load the pipelined sync tier needs to fill its overlap window, which the
    /// #1040 design spec proved a SINGLE connection cannot (the session drains its parked window
    /// at pass end). A `--count` bound splits evenly across producers (remainder to the first);
    /// the aggregate throughput is total messages over the WHOLE-PHASE wall time (start-of-first
    /// leg to end-of-last leg). 1 is the historical single-connection path with its measurement
    /// window unchanged. Publish-only: a value above 1 is refused in subscribe/round-trip mode
    /// (each has its own fixed connection shape the flag says nothing about).
    pub producers: usize,
    /// The storage BACKEND of bench's own ISOLATED synthetic broker (#445, refs #443): `disk` (the
    /// default, the historical bench broker over an auto-deleted synthetic data dir) or `memory`
    /// (the same engine over the in-memory filesystem, for honest RAM-path numbers next to the
    /// disk numbers). The flag shapes ONLY the spawned broker, so it is refused alongside
    /// `--addr` (a live broker's backend is already decided by that broker).
    pub storage: StorageArg,
    /// How the SUBSCRIBE drain settles each fetched batch (#464): [`AckMode::Batched`] (the default,
    /// one pipelined `ack_many` per batch — the FAIR consume number) or [`AckMode::PerMessage`] (the
    /// legacy one synchronous `ack` per message — the ack-RPC-LATENCY ceiling, behind
    /// `--per-message-ack`). SUBSCRIBE-only: round-trip's overlapped consumer is unchanged, and
    /// publish never consumes.
    pub consume_ack: AckMode,
    /// Which CONSUME TIER the SUBSCRIBE drain exercises (#554): [`ConsumeTier::Work`] (the default,
    /// the per-message-lease work queue the [`AckMode`] flag shapes) or [`ConsumeTier::Streaming`]
    /// (the Tier-S streaming consumer's batched-fetch + periodic-cumulative-commit default, the
    /// durable single-consumer streaming-consume path benched head-to-head with a NATS `JetStream`
    /// pull consumer). SUBSCRIBE-only, exactly like [`Self::consume_ack`].
    pub consume_tier: ConsumeTier,
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
    /// (which runs the spawned broker at `interval` durability and batches the cursor
    /// checkpoints, #1027, so the per-ack durable path is not exercised).
    /// The callers live in `bench_run.rs` behind `cfg(unix)` (the bench broker is the real
    /// `serve` path, Unix-only in v1), so on a non-unix build this method is otherwise dead
    /// code and `-D warnings` refuses the build (the Windows CI lane caught exactly that).
    #[cfg_attr(not(unix), allow(dead_code))]
    #[must_use]
    pub fn fsync_is_measured(&self) -> bool {
        !self.no_fsync && self.storage == StorageArg::Disk
    }

    /// Whether PUBLISH mode awaits EVERY produce individually (#1024): the plain half-duplex path,
    /// `--pubwindow 1` without `--stream`, `--autopipe`, or `--faf`. Only then is each per-produce
    /// sample an honest produce-to-ack RTT, the number the cross-broker study compares against a
    /// Kafka/NATS synchronous publish. The pipelined paths (window > 1, stream, autopipe) amortize
    /// a flush across many messages, so a per-op share would be dishonest, and fire-and-forget
    /// awaits nothing at all. INDEPENDENT of the storage backend: an ack RTT is honest on the
    /// memory engine too (it is just not a durable-write cost), unlike [`Self::fsync_is_measured`].
    /// Unix-gated callers, exactly like [`Self::fsync_is_measured`].
    #[cfg_attr(not(unix), allow(dead_code))]
    #[must_use]
    pub fn publish_acks_are_awaited(&self) -> bool {
        self.pub_window == 1 && !self.stream && !self.auto_pipeline && !self.fire_and_forget
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
    /// p50 produce-to-ack RTT, microseconds (#1024): present ONLY when every produce was
    /// individually awaited (plain `--pubwindow 1` publish, or the round-trip producer leg),
    /// regardless of storage backend. `None` on the pipelined/fire-and-forget paths, where a
    /// per-op attribution would be amortized and dishonest.
    pub ack_p50_us: Option<f64>,
    /// p99 produce-to-ack RTT, microseconds (#1024). Same presence rule as [`Self::ack_p50_us`].
    pub ack_p99_us: Option<f64>,
    /// p999 produce-to-ack RTT, microseconds (#1024). Same presence rule as [`Self::ack_p50_us`].
    pub ack_p999_us: Option<f64>,
    /// Max observed produce-to-ack RTT, microseconds (#1024). Same presence rule as
    /// [`Self::ack_p50_us`].
    pub ack_max_us: Option<f64>,
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
    let mut stream = false;
    let mut fire_and_forget = false;
    let mut auto_pipeline = false;
    let mut pub_window: usize = 1;
    let mut producers: usize = 1;
    let mut storage: Option<StorageArg> = None;
    let mut per_message_ack = false;
    let mut consume_tier = ConsumeTier::Work;
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
            "--stream" => {
                stream = true;
                i += 1;
            }
            // AT-MOST-ONCE publish (QoS-0): drive `produce_fire_and_forget` (no awaited ack). The
            // `--faf` alias is accepted for brevity.
            "--fire-and-forget" | "--faf" => {
                fire_and_forget = true;
                i += 1;
            }
            // AUTO-PIPELINING durable producer (#508): drive `pipelined_producer_with_window`
            // (the default single-producer durable-throughput lever). Sized by `--pubwindow`.
            "--autopipe" => {
                auto_pipeline = true;
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
            // MULTI-PRODUCER publish (#1040): N independent client connections. 0 is meaningless
            // (nobody would ever publish), so it is a usage error naming the bound, exactly like
            // `--pubwindow 0`.
            "--producers" => {
                let raw = take(args, &mut i, "--producers")?;
                let parsed: usize = raw.parse().map_err(|_| {
                    CliError::Usage(format!(
                        "`--producers` must be a positive integer, got `{raw}`"
                    ))
                })?;
                if parsed == 0 {
                    return Err(CliError::Usage(
                        "`--producers` must be at least 1 (1 = the single-connection default)"
                            .into(),
                    ));
                }
                producers = parsed;
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
            // FAIR-CONSUME opt-out (#464): drain the subscribe queue with one SYNCHRONOUS ack per
            // message (the legacy ack-RPC-bound path) instead of the default batched `ack_many` per
            // fetched batch. A legitimate ack-RPC-LATENCY measurement; NOT a fair throughput compare.
            "--per-message-ack" => {
                per_message_ack = true;
                i += 1;
            }
            // CONSUME-TIER selector (#554, V2-M1): drive the SUBSCRIBE drain through the Tier-S
            // STREAMING consumer (`--consume-tier streaming`: batched `StreamFetch` + bounded
            // read-ahead + periodic cumulative `StreamCommit`, the #662 default) instead of the
            // default Tier-W per-message-lease work queue (`--consume-tier work`). The Tier-S leg is
            // the durable single-consumer streaming-consume path the #554 NATS head-to-head measures.
            "--consume-tier" => {
                let raw = take(args, &mut i, "--consume-tier")?;
                consume_tier = ConsumeTier::parse(&raw).ok_or_else(|| {
                    CliError::Usage(format!(
                        "`--consume-tier` must be `work` or `streaming`, got `{raw}`"
                    ))
                })?;
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

    if stream && pub_window < 2 {
        return Err(CliError::Usage(
            "`--stream` needs `--pubwindow` of at least 2 (the full-duplex slide is the point; \
             window 1 is the plain awaited-ack path)"
                .into(),
        ));
    }

    // AT-MOST-ONCE guards. Fire-and-forget is a produce-only fast path that never awaits an ack,
    // so it is meaningless in a mode that reads back (round-trip) or consumes (subscribe), and it
    // cannot combine with the flags that pipeline AWAITED acks (`--stream`, `--pubwindow > 1`):
    // there are no acks here to pipeline. Each is its own usage error naming the conflict.
    if fire_and_forget && mode != Mode::Publish {
        return Err(CliError::Usage(
            "`--fire-and-forget` is a produce-only QoS-0 path (it awaits no ack): it requires \
             `--mode publish`. subscribe and round-trip need an ack or a read-back, which a \
             fire-and-forget produce never sends."
                .into(),
        ));
    }
    if fire_and_forget && stream {
        return Err(CliError::Usage(
            "`--fire-and-forget` and `--stream` are mutually exclusive: `--stream` pipelines \
             AWAITED acks, while fire-and-forget awaits none. Pick one."
                .into(),
        ));
    }
    if fire_and_forget && pub_window > 1 {
        return Err(CliError::Usage(
            "`--fire-and-forget` cannot combine with `--pubwindow > 1`: the window pipelines \
             AWAITED acks, while fire-and-forget awaits none. Drop `--pubwindow` (fire-and-forget \
             is already maximally pipelined: it never stops for an ack)."
                .into(),
        ));
    }

    // FAIR-CONSUME guard (#464): the ack strategy only shapes the SUBSCRIBE drain. Publish never
    // consumes, and round-trip's consumer is the separate concurrent latency loop (left unchanged),
    // so accepting `--per-message-ack` there would silently mean nothing. Refuse it (a no-op flag is
    // a footgun), exactly as `--storage` is refused alongside `--addr`.
    if per_message_ack && mode != Mode::Subscribe {
        return Err(CliError::Usage(
            "`--per-message-ack` shapes the `--mode subscribe` consume drain (its ack strategy): \
             publish never consumes and round-trip uses a separate concurrent consumer, so the flag \
             would mean nothing there. Pass `--mode subscribe`, or drop `--per-message-ack` to keep \
             the default batched-ack consume."
                .into(),
        ));
    }
    let consume_ack = if per_message_ack {
        AckMode::PerMessage
    } else {
        AckMode::Batched
    };

    // CONSUME-TIER guards (#554). Like `--per-message-ack`, the tier selector only shapes the
    // SUBSCRIBE drain (publish never consumes; round-trip's overlapped consumer is a separate path),
    // so accepting it elsewhere would silently mean nothing — refuse it (a no-op flag is a footgun).
    if consume_tier != ConsumeTier::Work && mode != Mode::Subscribe {
        return Err(CliError::Usage(
            "`--consume-tier` selects the `--mode subscribe` consume path (work vs streaming): \
             publish never consumes and round-trip uses a separate concurrent consumer, so the flag \
             would mean nothing there. Pass `--mode subscribe`, or drop `--consume-tier` to keep the \
             default Tier-W work-queue drain."
                .into(),
        ));
    }
    // The Tier-S streaming consumer commits a CURSOR, not per-message leases, so the lease-ack
    // strategy (`--per-message-ack`) has nothing to shape there. Reject the combination explicitly so
    // a caller is never silently handed a flag the streaming path ignores.
    if consume_tier == ConsumeTier::Streaming && per_message_ack {
        return Err(CliError::Usage(
            "`--per-message-ack` shapes the Tier-W work-queue ack strategy and has no meaning for \
             `--consume-tier streaming` (a streaming consumer commits a cumulative cursor, it does \
             not ack per-message leases). Drop one of the two flags."
                .into(),
        ));
    }

    // AUTO-PIPELINE guards (#508). The auto-pipelining durable producer is a produce-side path that
    // awaits acks at flush points (so it is meaningful only in publish mode), and it is its own
    // distinct in-flight-window mechanism, so it does not stack with `--stream` (the full-duplex
    // window) or `--fire-and-forget` (no acks at all). Each is its own usage error naming the clash.
    if auto_pipeline && mode != Mode::Publish {
        return Err(CliError::Usage(
            "`--autopipe` is a produce-only durable-throughput path: it requires `--mode publish`. \
             subscribe and round-trip drive the consumer / read-back paths, which the \
             auto-pipelining producer does not exercise."
                .into(),
        ));
    }
    if auto_pipeline && stream {
        return Err(CliError::Usage(
            "`--autopipe` and `--stream` are mutually exclusive: both keep a window of awaited acks \
             in flight, by different mechanisms (the auto-pipelining handle vs the full-duplex \
             slide). Pick one."
                .into(),
        ));
    }
    if auto_pipeline && fire_and_forget {
        return Err(CliError::Usage(
            "`--autopipe` and `--fire-and-forget` are mutually exclusive: auto-pipelining keeps a \
             window of DURABLE awaited acks in flight, while fire-and-forget awaits none. Pick one."
                .into(),
        ));
    }

    // MULTI-PRODUCER guard (#1040). N producer CONNECTIONS shape only the publish load: subscribe
    // drives a consumer drain (no bench producer runs during the measured phase) and round-trip is
    // the fixed one-producer/one-consumer pair, so `--producers > 1` there would silently mean
    // nothing — refuse it (a no-op flag is a footgun), exactly as `--per-message-ack` is refused
    // outside subscribe. The explicit single-connection default (`--producers 1`) is accepted in
    // any mode, the `--consume-tier work` precedent.
    if producers > 1 && mode != Mode::Publish {
        return Err(CliError::Usage(
            "`--producers` runs N concurrent publisher connections and requires `--mode publish`: \
             subscribe drives a consumer drain and round-trip is the fixed one-producer/\
             one-consumer pair, so the flag would mean nothing there. Pass `--mode publish`, or \
             drop `--producers`."
                .into(),
        ));
    }

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
        stream,
        fire_and_forget,
        auto_pipeline,
        pub_window,
        producers,
        storage,
        consume_ack,
        consume_tier,
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
    // The multi-producer fleet (#1040): named only above the single-connection default, so the
    // historical `--producers 1` view is byte-identical.
    if cfg.mode == Mode::Publish && cfg.producers > 1 {
        writeln!(
            out,
            "producers:      {} concurrent connections (a count bound splits evenly, remainder \
             to the first)",
            cfg.producers
        )?;
    }
    if cfg.mode == Mode::Subscribe {
        writeln!(
            out,
            "consume tier:   {}",
            match cfg.consume_tier {
                ConsumeTier::Work =>
                    "TIER-W work queue (per-message lease + ack; the competing-consumer drain)",
                ConsumeTier::Streaming =>
                    "TIER-S streaming (batched StreamFetch + read-ahead + periodic cumulative \
                     StreamCommit — the durable single-consumer streaming-consume path)",
            }
        )?;
        if cfg.consume_tier == ConsumeTier::Work {
            writeln!(
                out,
                "consume ack:    {}",
                match cfg.consume_ack {
                    AckMode::Batched =>
                        "BATCHED (ack_many per fetched batch — the fair fetch+batch-ack throughput)",
                    AckMode::PerMessage =>
                        "per-message (one synchronous ack per message — the ack-RPC-LATENCY ceiling)",
                }
            )?;
        }
    }
    if cfg.fire_and_forget {
        writeln!(
            out,
            "delivery:       AT-MOST-ONCE (fire-and-forget QoS-0: no ack awaited; the broker may \
             drop a send under load by contract)"
        )?;
    }
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
    // The produce-to-ack RTT percentiles (#1024): printed only when the run awaited every produce
    // individually (plain `--pubwindow 1` publish, or the round-trip producer leg), so a reader
    // never sees an amortized pipelined number dressed up as a per-op ack RTT.
    if report.ack_p50_us.is_some() {
        write_latency_line(out, "ack p50", report.ack_p50_us)?;
        write_latency_line(out, "ack p99", report.ack_p99_us)?;
        write_latency_line(out, "ack p999", report.ack_p999_us)?;
        write_latency_line(out, "ack max", report.ack_max_us)?;
    }
    write_fsync_cost_line(cfg, report, out)?;
    Ok(())
}

/// Writes the fsync-cost line with the tier-honest wording for every non-measured case (#445,
/// #1027): measured -> the per-ack cost; memory -> no fsync exists; --no-fsync isolated -> the
/// spawned broker really ran INTERVAL durability; --no-fsync live -> no tier claim; otherwise ->
/// overlapped publishes make per-op attribution dishonest (and no dry run may be claimed).
fn write_fsync_cost_line<W: Write + ?Sized>(
    cfg: &BenchConfig,
    report: &BenchReport,
    out: &mut W,
) -> Result<(), CliError> {
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
    } else if cfg.no_fsync && cfg.is_isolated() {
        // The #1027 dry-run wording: the SPAWNED broker really ran the interval tier, so the
        // reader knows the numbers above are bounded-loss page-cache acks, not the sync tier.
        writeln!(
            out,
            "fsync cost:     not measured (--no-fsync dry run: the spawned broker ran INTERVAL \
             durability — bounded-loss page-cache acks, not the power-loss-safe sync tier; the \
             honest fsync number needs the per-ack durable path)"
        )?;
    } else if cfg.no_fsync {
        // LIVE mode never spawns (or reconfigures) a broker, so no tier claim may be made; the
        // flag only withholds the fsync attribution.
        writeln!(
            out,
            "fsync cost:     not measured (--no-fsync dry run; the honest fsync number needs the \
             per-ack durable path)"
        )?;
    } else if cfg.producers > 1 {
        // MULTI-PRODUCER (#1040): the broker's group commit gathers windows from MANY concurrent
        // connections under one covering fdatasync, so a per-op durable share would double-count
        // the shared fsync — dishonest for the same reason the overlapped single-connection paths
        // withhold it. The merged ack RTT percentiles above stay honest (each sample is one
        // self-contained awaited produce call).
        writeln!(
            out,
            "fsync cost:     not attributed (--producers {}: concurrent connections share \
             covering group-commit fsyncs; use --producers 1 --pubwindow 1 for the honest \
             per-ack cost)",
            cfg.producers
        )?;
    } else {
        // Overlapped disk paths without --no-fsync (windowed/stream/autopipe/faf): the durable
        // cost EXISTS but no single produce owns a covering fsync, so per-op attribution would be
        // dishonest. Never claim a dry run that was not requested (#1027).
        writeln!(
            out,
            "fsync cost:     not attributed (overlapped publishes share covering fsyncs; use \
             --pubwindow 1 for the honest per-ack cost)"
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
/// mistaken for a disk number. The produce-to-ack RTT percentile fields (#1024,
/// `ack_p50_us`/`ack_p99_us`/`ack_p999_us`/`ack_max_us`) are likewise ADDITIVE, null unless every
/// produce was individually awaited. The `producers` field (#1040) is ADDITIVE too (always
/// present, `1` for the historical single-connection run), so a multi-connection row
/// self-describes its concurrency; its ack percentiles are the honest MERGE of every producer's
/// individually-awaited RTT samples. Written to `out`.
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
         \"fetch_batch\":{},\"no_fsync\":{},\"pubwindow\":{},\"producers\":{},\"stream\":{},\"fire_and_forget\":{},\"auto_pipeline\":{},\"storage\":\"{}\",\"consume_ack\":\"{}\",\"consume_tier\":\"{}\",\"results\":{{\
         \"produced\":{},\"recorded\":{},\"elapsed_secs\":{},\"msgs_per_sec\":{},\
         \"mb_per_sec\":{},\"bytes_per_op\":{},\
         \"latency_p50_us\":{},\"latency_p99_us\":{},\"latency_p999_us\":{},\"latency_max_us\":{},\
         \"ack_p50_us\":{},\"ack_p99_us\":{},\"ack_p999_us\":{},\"ack_max_us\":{},\
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
        cfg.producers,
        cfg.stream,
        cfg.fire_and_forget,
        cfg.auto_pipeline,
        cfg.storage.as_str(),
        cfg.consume_ack.as_str(),
        cfg.consume_tier.as_str(),
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
        opt_f64_json(report.ack_p50_us),
        opt_f64_json(report.ack_p99_us),
        opt_f64_json(report.ack_p999_us),
        opt_f64_json(report.ack_max_us),
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

/// The default receiver fetch credit window (`--fetch-batch`), shared by the Tier-W work-queue
/// fetch and the Tier-S streaming window. 2048, not 256 (#1027): at 256 the streaming drain is
/// round-trip-latency-bound (~700 fetch RTTs/s of ~1.4 ms each, zero CPU hotspots — 128 B records
/// drained at ~180k msg/s on the baseline rig), while 2048 reaches the ~1M rec/s per-record
/// plateau there (969k-1217k msg/s at 128 B; 8192 measured 931k, so a larger window buys nothing —
/// the ~0.5 us/record cost is the real ceiling). 2048 is also PEER-COMPARABLE consumer sizing (a
/// stock Kafka consumer fetches ~50 MB / 500+ records per poll, so a 256-record default is not a
/// fair head-to-head) and exactly the broker's default per-consumer credit ceiling
/// (`DEFAULT_CONSUMER_CREDIT` = 2048), which every fetch is capped at anyway. `--fetch-batch`
/// still overrides.
const DEFAULT_FETCH_BATCH: u32 = 2048;

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
    fn the_default_fetch_batch_is_pinned_at_2048_and_the_flag_still_overrides() {
        // #1027 PIN: 2048 is peer-comparable consumer sizing (a stock Kafka consumer pulls 500+
        // records per poll) and the measured ~1M rec/s plateau point of the streaming drain; 256
        // was round-trip-latency-bound (~180k msg/s at 128 B). This FAILS if the default drifts.
        let cfg = parse(&["--count", "1"]).unwrap();
        assert_eq!(
            cfg.fetch_batch, 2048,
            "the default fetch window is pinned at the 2048 plateau point (#1027)"
        );
        let cfg = parse(&["--count", "1", "--fetch-batch", "256"]).unwrap();
        assert_eq!(cfg.fetch_batch, 256, "--fetch-batch still overrides");
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
            ack_p50_us: Some(880.0),
            ack_p99_us: Some(1500.0),
            ack_p999_us: Some(1900.0),
            ack_max_us: Some(2100.0),
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
        // The ADDITIVE produce-to-ack RTT percentile fields (#1024), explicitly named.
        assert!(json.contains("\"ack_p50_us\":880"), "json: {json}");
        assert!(json.contains("\"ack_p99_us\":1500"), "json: {json}");
        assert!(json.contains("\"ack_p999_us\":1900"), "json: {json}");
        assert!(json.contains("\"ack_max_us\":2100"), "json: {json}");
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
    fn ack_rtt_is_claimed_only_on_the_awaited_per_produce_publish_path() {
        // The #1024 gating condition, pinned: a per-produce ack RTT is honest ONLY when every
        // produce is individually awaited — the plain half-duplex `--pubwindow 1` publish. This
        // test FAILS if any amortized path (window > 1, --stream, --autopipe) or the un-awaited
        // --faf path starts claiming ack percentiles, or if the plain path stops claiming them.
        let plain = parse(&["--count", "10", "--mode", "publish"]).unwrap();
        assert!(
            plain.publish_acks_are_awaited(),
            "plain --pubwindow 1 publish awaits every produce"
        );
        // MUTATION TEETH for `pub_window == 1`: an explicit window of exactly 1 stays awaited,
        // while ANY window above 1 is amortized.
        let window_one =
            parse(&["--count", "10", "--mode", "publish", "--pubwindow", "1"]).unwrap();
        assert!(window_one.publish_acks_are_awaited());
        let windowed = parse(&["--count", "10", "--mode", "publish", "--pubwindow", "2"]).unwrap();
        assert!(
            !windowed.publish_acks_are_awaited(),
            "a pipelined window amortizes; no per-op ack RTT may be claimed"
        );
        let stream = parse(&[
            "--count",
            "10",
            "--mode",
            "publish",
            "--stream",
            "--pubwindow",
            "8",
        ])
        .unwrap();
        assert!(!stream.publish_acks_are_awaited(), "full-duplex overlap");
        let autopipe = parse(&["--count", "10", "--mode", "publish", "--autopipe"]).unwrap();
        assert!(
            !autopipe.publish_acks_are_awaited(),
            "auto-pipelined flushes"
        );
        let faf = parse(&["--count", "10", "--mode", "publish", "--faf"]).unwrap();
        assert!(!faf.publish_acks_are_awaited(), "no ack is awaited at all");
        // STORAGE-INDEPENDENT (unlike the fsync cost): an ack RTT is honest on memory too.
        let memory = parse(&["--count", "10", "--mode", "publish", "--storage", "memory"]).unwrap();
        assert!(
            memory.publish_acks_are_awaited(),
            "ack RTT is backend-agnostic"
        );
        assert!(!memory.fsync_is_measured(), "but the fsync cost is not");
    }

    #[test]
    fn ack_percentiles_land_in_the_json_and_null_when_not_awaited() {
        // Present: the four ADDITIVE #1024 fields carry numbers when the report has them.
        let cfg = parse(&["--count", "5", "--mode", "publish"]).unwrap();
        let report = BenchReport {
            produced: 5,
            elapsed_secs: 1.0,
            ack_p50_us: Some(150.0),
            ack_p99_us: Some(400.0),
            ack_p999_us: Some(650.0),
            ack_max_us: Some(700.0),
            ..BenchReport::default()
        };
        let json = bench_json(&cfg, &report);
        assert!(json.contains("\"ack_p50_us\":150"), "json: {json}");
        assert!(json.contains("\"ack_max_us\":700"), "json: {json}");
        // Absent (an amortized/un-awaited path): the same fields are null, never omitted.
        let json = bench_json(&cfg, &BenchReport::default());
        for field in [
            "\"ack_p50_us\":null",
            "\"ack_p99_us\":null",
            "\"ack_p999_us\":null",
            "\"ack_max_us\":null",
        ] {
            assert!(json.contains(field), "missing {field} in json: {json}");
        }
    }

    #[test]
    fn human_view_prints_ack_percentiles_only_when_present() {
        let cfg = parse(&["--count", "5", "--mode", "publish"]).unwrap();
        let report = BenchReport {
            produced: 5,
            elapsed_secs: 1.0,
            ack_p50_us: Some(150.0),
            ack_p99_us: Some(400.0),
            ack_p999_us: Some(650.0),
            ack_max_us: Some(700.0),
            fsync_measured: true,
            ..BenchReport::default()
        };
        let mut human = Vec::new();
        write_human(&cfg, &report, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("ack p50:     150.0 us"), "human: {human}");
        assert!(human.contains("ack p99:     400.0 us"), "human: {human}");
        assert!(human.contains("ack p999:     650.0 us"), "human: {human}");
        assert!(human.contains("ack max:     700.0 us"), "human: {human}");
        // An un-awaited run prints NO ack lines at all (no noisy n/a rows for a metric the mode
        // cannot honestly measure).
        let mut human = Vec::new();
        write_human(&cfg, &BenchReport::default(), &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(!human.contains("ack p"), "human: {human}");
        assert!(!human.contains("ack max"), "human: {human}");
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
    fn the_stream_flag_parses_requires_a_window_and_lands_in_the_json() {
        // The full-duplex publish flag (#458): default off; bare flag does not swallow the next
        // flag; refused without a pipelining window (>= 2); echoed in the JSON object.
        let off = parse(&["--count", "5", "--pubwindow", "64"]).unwrap();
        assert!(!off.stream, "stream defaults off");
        let on = parse(&[
            "--count",
            "5",
            "--stream",
            "--pubwindow",
            "64",
            "--no-fsync",
        ])
        .unwrap();
        assert!(on.stream);
        assert!(on.no_fsync, "the flag after --stream must still parse");
        assert_eq!(on.pub_window, 64);
        match parse(&["--count", "5", "--stream"]) {
            Err(CliError::Usage(msg)) => assert!(msg.contains("--pubwindow"), "{msg}"),
            other => panic!("--stream without a window must be a usage error, got {other:?}"),
        }
        match parse(&["--count", "5", "--stream", "--pubwindow", "1"]) {
            Err(CliError::Usage(msg)) => assert!(msg.contains("at least 2"), "{msg}"),
            other => panic!("--stream with window 1 must be a usage error, got {other:?}"),
        }
        let json = bench_json(&on, &BenchReport::default());
        assert!(json.contains("\"stream\":true"), "{json}");
    }

    #[test]
    fn fire_and_forget_is_publish_only_excludes_ack_pipelining_and_lands_in_the_json() {
        // AT-MOST-ONCE (QoS-0): default off; the bare flag (and its `--faf` alias) sets it; it is
        // refused outside publish mode and alongside the AWAITED-ack pipelining flags; and it is
        // echoed additively in the JSON object (schema version unchanged, the `--stream` precedent).
        let off = parse(&["--count", "5", "--mode", "publish"]).unwrap();
        assert!(!off.fire_and_forget, "fire-and-forget defaults off");
        let on = parse(&["--count", "5", "--mode", "publish", "--fire-and-forget"]).unwrap();
        assert!(on.fire_and_forget);
        let aliased = parse(&["--count", "5", "--mode", "publish", "--faf"]).unwrap();
        assert!(aliased.fire_and_forget, "`--faf` is the alias");
        // Publish-only: round-trip (the default) and subscribe are refused (no ack / no read-back).
        match parse(&["--count", "5", "--fire-and-forget"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("--mode publish"), "{m}"),
            other => panic!("fire-and-forget outside publish must be a usage error, got {other:?}"),
        }
        match parse(&["--count", "5", "--mode", "subscribe", "--fire-and-forget"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("produce-only"), "{m}"),
            other => panic!("fire-and-forget + subscribe must be a usage error, got {other:?}"),
        }
        // Mutually exclusive with the awaited-ack pipelining flags.
        match parse(&[
            "--count",
            "5",
            "--mode",
            "publish",
            "--fire-and-forget",
            "--stream",
            "--pubwindow",
            "8",
        ]) {
            Err(CliError::Usage(m)) => assert!(m.contains("mutually exclusive"), "{m}"),
            other => panic!("fire-and-forget + stream must be a usage error, got {other:?}"),
        }
        match parse(&[
            "--count",
            "5",
            "--mode",
            "publish",
            "--fire-and-forget",
            "--pubwindow",
            "8",
        ]) {
            Err(CliError::Usage(m)) => assert!(m.contains("pubwindow"), "{m}"),
            other => panic!("fire-and-forget + pubwindow>1 must be a usage error, got {other:?}"),
        }
        // Composes with the storage backend (memory here) and lands additively in the JSON.
        let mem = parse(&[
            "--count",
            "5",
            "--mode",
            "publish",
            "--fire-and-forget",
            "--storage",
            "memory",
        ])
        .unwrap();
        assert!(mem.fire_and_forget && mem.storage == StorageArg::Memory);
        let json = bench_json(&on, &BenchReport::default());
        assert!(json.contains("\"fire_and_forget\":true"), "{json}");
        assert!(
            json.contains("\"schema_version\":1"),
            "additive, version unchanged: {json}"
        );
    }

    #[test]
    fn consume_ack_defaults_to_batched_per_message_is_subscribe_only_and_lands_in_the_json() {
        // FAIR consume (#464): the SUBSCRIBE drain settles each fetched batch with one pipelined
        // `ack_many` by DEFAULT (the fair fetch+batch-ack throughput); `--per-message-ack` opts back
        // into the legacy one-ack-RPC-per-message drain (the ack-LATENCY ceiling). The flag is
        // subscribe-only (publish never consumes, round-trip uses a separate concurrent consumer) and
        // is echoed additively in the JSON object (schema version unchanged, the `--stream` precedent).
        let default_sub = parse(&["--count", "5", "--mode", "subscribe"]).unwrap();
        assert_eq!(
            default_sub.consume_ack,
            AckMode::Batched,
            "the fair batched-ack drain is the default"
        );
        let per_msg = parse(&["--count", "5", "--mode", "subscribe", "--per-message-ack"]).unwrap();
        assert_eq!(per_msg.consume_ack, AckMode::PerMessage);
        // The bare flag does not swallow the next flag.
        let trailing = parse(&[
            "--count",
            "5",
            "--mode",
            "subscribe",
            "--per-message-ack",
            "--no-fsync",
        ])
        .unwrap();
        assert!(
            trailing.no_fsync,
            "the flag after --per-message-ack must still parse"
        );
        // Subscribe-only: round-trip (the default) and publish are refused (the flag would mean
        // nothing — no consume drain there).
        match parse(&["--count", "5", "--per-message-ack"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("--mode subscribe"), "{m}"),
            other => {
                panic!("--per-message-ack outside subscribe must be a usage error, got {other:?}")
            }
        }
        match parse(&["--count", "5", "--mode", "publish", "--per-message-ack"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("consume"), "{m}"),
            other => panic!("--per-message-ack + publish must be a usage error, got {other:?}"),
        }
        // Both ack strategies land additively in the JSON; the schema version is unchanged.
        let json_default = bench_json(&default_sub, &BenchReport::default());
        assert!(
            json_default.contains("\"consume_ack\":\"batched\""),
            "{json_default}"
        );
        assert!(
            json_default.contains("\"schema_version\":1"),
            "additive, version unchanged: {json_default}"
        );
        let json_per_msg = bench_json(&per_msg, &BenchReport::default());
        assert!(
            json_per_msg.contains("\"consume_ack\":\"per-message\""),
            "{json_per_msg}"
        );
        assert!(
            json_per_msg.contains("\"schema_version\":1"),
            "additive, version unchanged: {json_per_msg}"
        );
    }

    #[test]
    fn consume_tier_defaults_to_work_streaming_is_subscribe_only_and_lands_in_the_json() {
        // The #554 consume-tier selector: the SUBSCRIBE drain runs the Tier-W work queue by DEFAULT;
        // `--consume-tier streaming` drives the Tier-S streaming consumer (the durable single-consumer
        // streaming-consume path benched head-to-head with NATS). Subscribe-only (publish never
        // consumes, round-trip uses a separate consumer), incompatible with `--per-message-ack` (a
        // streaming consumer commits a cursor, not per-message leases), and echoed additively in JSON.
        let default_sub = parse(&["--count", "5", "--mode", "subscribe"]).unwrap();
        assert_eq!(
            default_sub.consume_tier,
            ConsumeTier::Work,
            "the Tier-W work-queue drain is the default"
        );
        let streaming = parse(&[
            "--count",
            "5",
            "--mode",
            "subscribe",
            "--consume-tier",
            "streaming",
        ])
        .unwrap();
        assert_eq!(streaming.consume_tier, ConsumeTier::Streaming);
        // The `work` value is accepted explicitly too, and does not swallow the following flag.
        let explicit_work = parse(&[
            "--count",
            "5",
            "--mode",
            "subscribe",
            "--consume-tier",
            "work",
            "--no-fsync",
        ])
        .unwrap();
        assert_eq!(explicit_work.consume_tier, ConsumeTier::Work);
        assert!(
            explicit_work.no_fsync,
            "the flag after --consume-tier must still parse"
        );
        // An unknown tier value is a usage error.
        match parse(&[
            "--count",
            "5",
            "--mode",
            "subscribe",
            "--consume-tier",
            "nope",
        ]) {
            Err(CliError::Usage(m)) => assert!(m.contains("work` or `streaming"), "{m}"),
            other => panic!("a bad --consume-tier value must be a usage error, got {other:?}"),
        }
        // Subscribe-only: round-trip (the default) and publish are refused.
        match parse(&["--count", "5", "--consume-tier", "streaming"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("--mode subscribe"), "{m}"),
            other => {
                panic!("--consume-tier streaming outside subscribe must be a usage error, got {other:?}")
            }
        }
        // Streaming + --per-message-ack is rejected (lease-ack vs cursor-commit are different paths).
        match parse(&[
            "--count",
            "5",
            "--mode",
            "subscribe",
            "--consume-tier",
            "streaming",
            "--per-message-ack",
        ]) {
            Err(CliError::Usage(m)) => assert!(m.contains("streaming"), "{m}"),
            other => {
                panic!("--consume-tier streaming + --per-message-ack must be a usage error, got {other:?}")
            }
        }
        // Both tiers land additively in the JSON; the schema version is unchanged.
        let json_default = bench_json(&default_sub, &BenchReport::default());
        assert!(
            json_default.contains("\"consume_tier\":\"work\""),
            "{json_default}"
        );
        assert!(
            json_default.contains("\"schema_version\":1"),
            "additive, version unchanged: {json_default}"
        );
        let json_streaming = bench_json(&streaming, &BenchReport::default());
        assert!(
            json_streaming.contains("\"consume_tier\":\"streaming\""),
            "{json_streaming}"
        );
    }

    #[test]
    fn auto_pipeline_is_publish_only_excludes_the_other_paths_and_lands_in_the_json() {
        // The #508 auto-pipelining durable producer: default off; the bare `--autopipe` flag sets
        // it; it is refused outside publish mode and alongside `--stream` / `--fire-and-forget`;
        // and it is echoed additively in the JSON object (schema version unchanged).
        let off = parse(&["--count", "5", "--mode", "publish"]).unwrap();
        assert!(!off.auto_pipeline, "auto-pipeline defaults off");
        let on = parse(&["--count", "5", "--mode", "publish", "--autopipe"]).unwrap();
        assert!(on.auto_pipeline);
        // Bare flag does not swallow the next flag.
        let with_window = parse(&[
            "--count",
            "5",
            "--mode",
            "publish",
            "--autopipe",
            "--pubwindow",
            "32",
        ])
        .unwrap();
        assert!(with_window.auto_pipeline && with_window.pub_window == 32);
        // Publish-only: round-trip (the default) and subscribe are refused.
        match parse(&["--count", "5", "--autopipe"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("--mode publish"), "{m}"),
            other => panic!("autopipe outside publish must be a usage error, got {other:?}"),
        }
        match parse(&["--count", "5", "--mode", "subscribe", "--autopipe"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("produce-only"), "{m}"),
            other => panic!("autopipe + subscribe must be a usage error, got {other:?}"),
        }
        // Mutually exclusive with the other publish paths.
        match parse(&[
            "--count",
            "5",
            "--mode",
            "publish",
            "--autopipe",
            "--stream",
            "--pubwindow",
            "8",
        ]) {
            Err(CliError::Usage(m)) => assert!(m.contains("mutually exclusive"), "{m}"),
            other => panic!("autopipe + stream must be a usage error, got {other:?}"),
        }
        match parse(&[
            "--count",
            "5",
            "--mode",
            "publish",
            "--autopipe",
            "--fire-and-forget",
        ]) {
            Err(CliError::Usage(m)) => assert!(m.contains("mutually exclusive"), "{m}"),
            other => panic!("autopipe + fire-and-forget must be a usage error, got {other:?}"),
        }
        // Lands additively in the JSON, schema version unchanged.
        let json = bench_json(&on, &BenchReport::default());
        assert!(json.contains("\"auto_pipeline\":true"), "{json}");
        assert!(
            json.contains("\"schema_version\":1"),
            "additive, version unchanged: {json}"
        );
    }

    #[test]
    fn producers_default_to_one_are_publish_only_above_one_and_land_in_the_json() {
        // The #1040 multi-producer flag: default 1 (the historical single connection); `--producers
        // N` parses in publish mode, composes with every publish shape and backend, is refused
        // above 1 outside publish (a no-op flag is a footgun, the `--per-message-ack` precedent),
        // and lands ADDITIVELY in the JSON (schema version unchanged, the #19/#114 precedent).
        let cfg = parse(&["--count", "5", "--mode", "publish"]).unwrap();
        assert_eq!(cfg.producers, 1, "the single-connection default");
        let four = parse(&[
            "--count",
            "2000",
            "--mode",
            "publish",
            "--producers",
            "4",
            "--no-fsync",
        ])
        .unwrap();
        assert_eq!(four.producers, 4);
        assert!(
            four.no_fsync,
            "the flag after --producers must still parse (no double-advance)"
        );
        // 0 and garbage are usage errors naming the bound.
        match parse(&["--count", "5", "--mode", "publish", "--producers", "0"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("at least 1"), "{m}"),
            other => panic!("--producers 0 must be a usage error, got {other:?}"),
        }
        assert!(parse(&["--count", "5", "--mode", "publish", "--producers", "many"]).is_err());
        // Publish-only above 1: round-trip (the default mode) and subscribe are refused.
        match parse(&["--count", "5", "--producers", "4"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("--mode publish"), "{m}"),
            other => panic!("--producers > 1 + round-trip must be a usage error, got {other:?}"),
        }
        match parse(&["--count", "5", "--mode", "subscribe", "--producers", "2"]) {
            Err(CliError::Usage(m)) => assert!(m.contains("publish"), "{m}"),
            other => panic!("--producers > 1 + subscribe must be a usage error, got {other:?}"),
        }
        // The explicit single-connection default is accepted in any mode (the `--consume-tier
        // work` precedent: naming the default is never an error).
        let rt = parse(&["--count", "5", "--producers", "1"]).unwrap();
        assert_eq!(rt.producers, 1);
        // Composes with the publish shapes and backends the fleet runs per-connection.
        let shaped = parse(&[
            "--count",
            "2000",
            "--mode",
            "publish",
            "--producers",
            "8",
            "--stream",
            "--pubwindow",
            "64",
            "--storage",
            "memory",
        ])
        .unwrap();
        assert_eq!(shaped.producers, 8);
        assert!(shaped.stream && shaped.pub_window == 64);
        let faf = parse(&[
            "--count",
            "100",
            "--mode",
            "publish",
            "--producers",
            "2",
            "--faf",
        ])
        .unwrap();
        assert_eq!(faf.producers, 2);
        let autopipe = parse(&[
            "--count",
            "100",
            "--mode",
            "publish",
            "--producers",
            "2",
            "--autopipe",
        ])
        .unwrap();
        assert_eq!(autopipe.producers, 2);
        // ADDITIVE JSON: the field is ALWAYS present (1 on the historical run), schema version
        // unchanged, so a `--producers 1` object is the old object plus one additive field.
        let json = bench_json(&four, &BenchReport::default());
        assert!(json.contains("\"producers\":4"), "{json}");
        assert!(
            json.contains("\"schema_version\":1"),
            "additive, version unchanged: {json}"
        );
        let json = bench_json(&cfg, &BenchReport::default());
        assert!(json.contains("\"producers\":1"), "{json}");
    }

    #[test]
    fn multi_producer_human_view_names_the_fleet_and_the_unattributed_fsync_cost() {
        // #1040: the human view names the fleet size and states WHY the per-op fsync cost is not
        // attributed above one producer (concurrent connections share covering group-commit
        // fsyncs); the `--producers 1` view stays byte-identical (no fleet line at the default).
        let cfg = parse(&["--count", "2000", "--mode", "publish", "--producers", "4"]).unwrap();
        let report = BenchReport {
            produced: 2000,
            elapsed_secs: 1.0,
            msgs_per_sec: 2000.0,
            bytes_per_op: 256.0,
            fsync_measured: false,
            ..BenchReport::default()
        };
        let mut human = Vec::new();
        write_human(&cfg, &report, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("producers:      4"), "human: {human}");
        assert!(
            human.contains("share covering group-commit fsyncs"),
            "the fsync line states the multi-connection reason: {human}"
        );
        // The single-producer default prints NO fleet line and keeps the historical fsync wording.
        let one = parse(&["--count", "2000", "--mode", "publish"]).unwrap();
        let report = BenchReport {
            fsync_measured: true,
            fsync_cost_us: Some(900.0),
            ..BenchReport::default()
        };
        let mut human = Vec::new();
        write_human(&one, &report, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(!human.contains("producers:"), "human: {human}");
        assert!(human.contains("fsync cost:     900.0 us"), "human: {human}");
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
