// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Unix execution path for `ironbus bench` (#94): spin up an ISOLATED in-process broker (or
//! connect to a live one), drive the real #11 client over the real #6 produce path, measure the
//! latency tail and the honest round-trip fsync cost, then auto-delete the synthetic data directory
//! and report a cleanup failure with a non-zero exit.
//!
//! This is `#[cfg(unix)]` because the on-disk broker (`serve`) is Unix-only in v1 (the storage path
//! uses positioned IO the Windows path does not implement yet), exactly like `serve`/`peek`/`dump`.
//! The platform-neutral parsing, guards, JSON schema, payload generation, and percentiles live in
//! [`crate::bench`] and are unit-tested on every target.

use crate::bench::{
    fill_payload, percentiles_us, AckMode, BenchConfig, BenchReport, Bound, ConsumeTier, Mode,
    BENCH_NAMESPACE_PREFIX, ROUND_TRIP_TOKEN_LEN,
};
use crate::{
    materialized_config_line, open_disk_engine, open_memory_engine, CliError, DurabilityLevelArg,
    ServeConfig, StorageArg,
};
use ironbus_client::{Client, ClientConfig, ClientError, StreamConsumerConfig};
use ironbus_core::clock::Clock; // the monotonic seam the serve loop's liveness beacon (#95) reads
use ironbus_proto::message::{ConsumeTier as ProtoConsumeTier, PubBody};
use ironbus_server::actor::{spawn_actor_with_gather, DEFAULT_CHANNEL_BOUND};
use ironbus_server::server::serve;
use ironbus_storage::fs::{EphemeralFs, Filesystem, StdFs};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Executes the parsed `bench` invocation and returns the measured [`BenchReport`]. The rendering
/// is done by the cross-platform [`crate::bench::run`] caller, so this is pure measurement.
///
/// In ISOLATED mode (the default) it spawns its own broker over a fresh `ironbus-bench-<random>`
/// data directory under the temp dir, runs the load, then ALWAYS auto-deletes the directory: a
/// failure to clean up is reported and surfaced as an internal (70+) exit code, so a leftover never
/// goes unnoticed. In LIVE mode it connects to the configured address and never touches a data dir.
///
/// # Errors
/// Returns [`CliError::Unreachable`] if the broker cannot be reached, [`CliError::Internal`] for a
/// run failure or a cleanup failure (the cleanup failure maps to exit 70).
pub fn execute(cfg: &BenchConfig) -> Result<BenchReport, CliError> {
    match &cfg.live_addr {
        // LIVE mode: the operator acknowledged it; we never spawn or delete anything.
        Some(addr) => drive_load(cfg, addr),
        None => execute_isolated(cfg),
    }
}

/// The isolated path, dispatched on the broker's storage backend (#445, mirroring `cmd_serve`'s
/// static two-armed match): DISK spawns over a synthetic data dir with the auto-delete lifecycle;
/// MEMORY spawns over a fresh in-memory filesystem, so there is NO directory to create, lock, or
/// clean up (the whole #94 leftover-directory failure mode does not exist on this arm).
fn execute_isolated(cfg: &BenchConfig) -> Result<BenchReport, CliError> {
    let config = bench_serve_config(cfg);
    // The spawned broker is the REAL serve engine, so its config passes the REAL serve boot gates
    // (the #443 ephemeral consent + byte cap among them): if the serve rules tighten, bench
    // follows automatically instead of quietly spawning a config `serve` itself would refuse.
    crate::validate_serve_config(&config).map_err(|e| {
        CliError::Internal(format!(
            "bench: the spawned isolated broker's config failed the serve boot gates: {e}"
        ))
    })?;
    match cfg.storage {
        StorageArg::Disk => execute_isolated_disk(cfg, &config),
        StorageArg::Memory => {
            let broker = IsolatedBroker::spawn_memory(&config)?;
            log_spawned_config(&config, broker.addr(), None);
            let result = drive_load(cfg, broker.addr());
            broker.shutdown();
            result
        }
    }
}

/// The DISK isolated path: create a synthetic data dir, spawn an in-process broker over it, run
/// the load, tear the broker down, then auto-delete the directory (reporting a cleanup failure).
fn execute_isolated_disk(cfg: &BenchConfig, config: &ServeConfig) -> Result<BenchReport, CliError> {
    let data_dir = synthetic_data_dir(&cfg.group);
    // Start from a clean directory so a stale leftover from a crashed prior run cannot skew bytes.
    let _ = std::fs::remove_dir_all(&data_dir);

    // PRODUCTION-SAFETY: arm an RAII guard that removes the synthetic directory on ANY early exit,
    // so a broker spawn failure after the directory is created, or a panic inside the load loop,
    // cannot leak it. The normal path runs the explicit, failure-reporting cleanup below and then
    // disarms this guard, so the explicit cleanup stays authoritative for the exit code.
    let mut dir_guard = DataDirGuard::arm(data_dir.clone());

    let broker = IsolatedBroker::spawn_disk(&data_dir, config)?;
    log_spawned_config(config, broker.addr(), Some(&data_dir));
    let run_result = drive_load(cfg, broker.addr());
    // Tear the broker down BEFORE deleting the directory, so no writer races the cleanup.
    broker.shutdown();

    // Auto-delete the synthetic directory unconditionally, capturing any failure.
    let cleanup = std::fs::remove_dir_all(&data_dir);
    // The explicit cleanup above is now authoritative; the RAII net must not also fire.
    dir_guard.disarm();

    // The run result takes precedence: a run failure is reported even if cleanup also failed, but a
    // cleanup failure in that combined case is still surfaced on stderr so a leak is never silent.
    let report = match run_result {
        Ok(report) => report,
        Err(run_err) => {
            if let Err(e) = &cleanup {
                eprintln!(
                    "warning: failed to delete the synthetic bench directory {}: {e}",
                    data_dir.display()
                );
            }
            return Err(run_err);
        }
    };

    if let Err(e) = cleanup {
        // PRODUCTION-SAFETY: a leftover synthetic directory wastes space and must be seen. Report
        // it and exit non-zero (internal, 70+), per #94.
        return Err(crate::bench::cleanup_failed_error(
            &data_dir.display().to_string(),
            &e.to_string(),
        ));
    }

    Ok(report)
}

/// RAII safety net that removes the synthetic bench data directory when it drops, unless it was
/// explicitly [`disarmed`](Self::disarm). It exists so an early return (a broker spawn failure after
/// the directory was created) or a panic in the load loop cannot leak the directory; the normal path
/// performs an explicit, failure-reporting cleanup and then disarms this guard.
struct DataDirGuard {
    path: PathBuf,
    armed: bool,
}

impl DataDirGuard {
    fn arm(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DataDirGuard {
    fn drop(&mut self) {
        if self.armed {
            // Best effort: this only fires on an error or panic path whose exit code is already set
            // by the propagating error or the unwind, so there is nowhere better to route a failure.
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// The synthetic data-directory path: the temp dir plus the bench group name (already a random
/// `ironbus-bench-<suffix>`), so two concurrent runs never collide and the name is recognizable.
fn synthetic_data_dir(group: &str) -> PathBuf {
    // The group is `ironbus-bench-<suffix>`; reuse it verbatim as the dir name so the isolation
    // unit (dir + group) shares one recognizable random suffix.
    let name = if group.starts_with(BENCH_NAMESPACE_PREFIX) {
        group.to_string()
    } else {
        format!("{BENCH_NAMESPACE_PREFIX}{group}")
    };
    std::env::temp_dir().join(name)
}

/// An in-process isolated broker: the same `ironbus-server` engine + append actor + `serve` the
/// `ironbus` binary ships, bound to an ephemeral loopback port, torn down on [`Self::shutdown`].
/// No signal handler is installed (unlike `cmd_serve`): this is a child of the bench command, not
/// the whole process, so it is stopped by flipping the shutdown flag. GENERIC over the engine's
/// [`Filesystem`] (#445), exactly like `run_broker` in `main.rs`: the disk and memory bench
/// brokers share this whole body, monomorphized once per backend by `execute_isolated`'s static
/// dispatch, so the two backends can never drift in how bench hosts them.
struct IsolatedBroker<F: Filesystem + 'static> {
    addr: String,
    shutdown: Arc<AtomicBool>,
    serve_thread: Option<std::thread::JoinHandle<()>>,
    handle: ironbus_server::actor::EngineHandle<F, ironbus_server::clock::SystemClock>,
    actor: Option<
        std::thread::JoinHandle<
            ironbus_server::engine::Engine<F, ironbus_server::clock::SystemClock>,
        >,
    >,
}

impl IsolatedBroker<StdFs> {
    /// Spawns the DISK broker over `data_dir` on a loopback ephemeral port, from the prebuilt,
    /// already-validated bench `ServeConfig`.
    fn spawn_disk(
        data_dir: &Path,
        config: &ServeConfig,
    ) -> Result<IsolatedBroker<StdFs>, CliError> {
        let engine = open_disk_engine(data_dir, config, &[], &[])?;
        IsolatedBroker::from_engine(engine, config)
    }
}

impl IsolatedBroker<EphemeralFs> {
    /// Spawns the MEMORY broker (#445): the same engine over a fresh ephemeral filesystem via the
    /// shared `open_memory_engine`, so the bench broker is the REAL `serve --storage memory`
    /// engine path — including the #492 single-image `EphemeralFs` (no durable shadow), so the
    /// bench measures the production in-RAM backend, not the simulation one. No file is created and
    /// nothing needs cleanup afterwards.
    fn spawn_memory(config: &ServeConfig) -> Result<IsolatedBroker<EphemeralFs>, CliError> {
        let engine = open_memory_engine(config, &[], &[])?;
        IsolatedBroker::from_engine(engine, config)
    }
}

impl<F: Filesystem + 'static> IsolatedBroker<F> {
    /// Hosts an ALREADY-OPENED engine: actor spawn, ephemeral loopback bind, serve thread. The
    /// shared backend-independent body behind both spawn constructors. `F: Clone` because the serve
    /// thread (`server::serve`) drives `Session::process`, whose stream-addressed verbs (#588) reach
    /// `StreamSet::declare` (the per-stream log open clones the fs); every opened `Engine<F, _>`
    /// already carries `F: Clone` (`Engine::open` requires it), so this is no new restriction.
    fn from_engine(
        engine: ironbus_server::engine::Engine<F, ironbus_server::clock::SystemClock>,
        config: &ServeConfig,
    ) -> Result<IsolatedBroker<F>, CliError>
    where
        F: Clone,
    {
        // Honor the resolved group-commit gather (#454, #472), so the bench broker reflects the
        // SAME default as the real `serve` path (`run_broker` wires `config.commit_gather_us` the
        // same way). Without this the bench would always run the gather-off actor and never measure
        // the shipped default's effect on a concurrent publisher.
        let (handle, actor) =
            spawn_actor_with_gather(engine, DEFAULT_CHANNEL_BOUND, config.commit_gather_us);
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| CliError::Internal(format!("bench: cannot bind a loopback port: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| CliError::Internal(format!("bench: cannot read the bound address: {e}")))?
            .to_string();
        let shutdown = Arc::new(AtomicBool::new(false));
        let serve_thread = {
            let serve_handle = handle.clone();
            let serve_shutdown = Arc::clone(&shutdown);
            let max_connections = config.max_connections;
            std::thread::Builder::new()
                .name("ironbus-bench-serve".to_string())
                .spawn(move || {
                    // The bench broker has no health server, so the liveness beacon (#95) is unread;
                    // the serve loop still ticks it, so we hand it a throwaway beacon on a matching
                    // SystemClock.
                    let clock = ironbus_server::clock::SystemClock::new();
                    let beacon =
                        ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                    let _ = serve(
                        &listener,
                        &serve_handle,
                        &serve_shutdown,
                        max_connections,
                        &clock,
                        &beacon,
                    );
                })
                .map_err(|e| CliError::Internal(format!("bench: cannot spawn serve thread: {e}")))?
        };
        Ok(IsolatedBroker {
            addr,
            shutdown,
            serve_thread: Some(serve_thread),
            handle,
            actor: Some(actor),
        })
    }

    /// The loopback `host:port` the broker is listening on.
    fn addr(&self) -> &str {
        &self.addr
    }

    /// Stops the broker: flip the shutdown flag (the serve loop polls it within ~50 ms), drain the
    /// actor (flush the pending batch and checkpoint), and join both threads. Idempotent.
    fn shutdown(mut self) {
        self.stop();
    }

    /// The shared teardown used by both `shutdown` and `Drop`, so a panicking run never leaks the
    /// broker threads or an unflushed actor.
    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(t) = self.serve_thread.take() {
            let _ = t.join();
        }
        // Ask the actor to flush + checkpoint, then drop the handle so its channel closes and the
        // actor thread exits; join it. Best-effort: a teardown error never fails the bench result.
        let _ = self.handle.shutdown();
        if let Some(actor) = self.actor.take() {
            let _ = actor.join();
        }
    }
}

impl<F: Filesystem + 'static> Drop for IsolatedBroker<F> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The default `--max-total-bytes` cap bench gives its own MEMORY-backend broker (#445): the real
/// serve path refuses an in-RAM store without a byte bound (0 = unlimited would grow until the
/// host OOMs), and bench supplies a default rather than burdening the operator, because the
/// synthetic broker's data is disposable BY DESIGN. 256 MiB holds ~1M default-256-byte messages,
/// far beyond any sane bounded bench; a run that somehow fills it sheds at capacity (which
/// `produce_one` already tolerates as the overload workload) instead of eating the host's RAM.
const BENCH_MEMORY_CAP_BYTES: u64 = 256 * 1024 * 1024;

/// Builds the `ServeConfig` for the isolated bench broker: the compiled defaults, except the
/// checkpoint interval, which is `1` (durable cursor write per ack, honest fsync) normally and a
/// large batch under `--no-fsync` (spare flash, fsync cost not measured). `--no-fsync` (#1027)
/// ALSO relaxes the spawned broker's PRODUCE durability to `interval` (ack on the page-cache
/// write, a bounded-loss forced-fdatasync window — the honest "relaxed / page-cache" tier a real
/// `serve --durability-level interval` runs): before #1027 only the checkpoint interval was
/// raised, so the "page-cache dry run" silently still measured the per-ack `sync` fsync tier.
/// Under `--storage memory` (#445) it carries the memory backend plus the two boot-gate
/// requirements the real serve path enforces: the explicit ephemeral consent (bench's synthetic
/// broker and its data are disposable by design, so bench supplies the consent the way it already
/// owns the auto-delete of its synthetic disk dir) and the default in-RAM byte cap above.
fn bench_serve_config(cfg: &BenchConfig) -> ServeConfig {
    let mut config = ServeConfig::bench_default();
    config.checkpoint_interval = if cfg.no_fsync { 1_000_000 } else { 1 };
    if cfg.no_fsync {
        // The dry run's produce path must ALSO leave the per-ack fsync tier (#1027): `interval`
        // is the bounded-loss page-cache level (the default flush window still forces periodic
        // fdatasyncs, so the loss stays bounded exactly as a real relaxed broker's would). The
        // `sync` default is kept for every honest run, so `fsync_measured` claims stay true.
        config.durability_level = DurabilityLevelArg::Interval;
    }
    if cfg.storage == StorageArg::Memory {
        config.storage = StorageArg::Memory;
        config.ephemeral_loss_ack = true;
        config.max_total_bytes = BENCH_MEMORY_CAP_BYTES;
    }
    config
}

/// Writes the spawned isolated broker's MATERIALIZED-CONFIG line (#87) to stderr, exactly the
/// audit surface `serve` emits at startup (#1027): one structured `key=value` line with every
/// resolved knob, so an operator (or a probe) reads the EFFECTIVE durability tier the bench broker
/// really ran — `durability_level=interval` under `--no-fsync`, `durability_level=sync` otherwise —
/// straight off the run's stderr, never inferring it from the flag. stderr, not stdout, so the
/// `--json` single-object stdout contract is untouched.
fn log_spawned_config(config: &ServeConfig, addr: &str, data_dir: Option<&Path>) {
    eprintln!(
        "bench: {}",
        materialized_config_line(config, addr, data_dir)
    );
}

/// Drives the load against the broker at `addr` and returns the measured report. Dispatches on the
/// mode: publish (produce only), subscribe (drain only), or round-trip (produce + read back, the
/// honest end-to-end latency and fsync cost).
fn drive_load(cfg: &BenchConfig, addr: &str) -> Result<BenchReport, CliError> {
    match cfg.mode {
        Mode::Publish => run_publish(cfg, addr),
        Mode::Subscribe => run_subscribe(cfg, addr),
        Mode::RoundTrip => run_round_trip(cfg, addr),
    }
}

/// Connects a client to `addr`, mapping a connect failure to the frozen broker-unreachable code.
fn connect(addr: &str) -> Result<Client, CliError> {
    let client_cfg = ClientConfig::default();
    Client::connect_with(addr, &client_cfg)
        .map_err(|e| CliError::Unreachable(format!("bench: connecting to broker at {addr}: {e}")))
}

/// Connects a STREAMING (Tier-S) client to `addr` (#554): advertises Tier-S + `DeliverBatch` and a
/// streaming connection default in the `Connect` handshake, so the server may serve this connection
/// at Tier-S and a subscription marks its group streaming server-side. The `--consume-tier streaming`
/// drain rides this connection; if the server does not negotiate Tier-S the streaming fetch path
/// returns a server error the caller surfaces, so the bench cannot silently fall back to Tier-W.
fn connect_streaming(addr: &str) -> Result<Client, CliError> {
    let client_cfg = ClientConfig {
        understands_streaming: true,
        default_consume_tier: Some(ProtoConsumeTier::Streaming),
        understands_deliver_batch: true,
        ..ClientConfig::default()
    };
    Client::connect_with(addr, &client_cfg).map_err(|e| {
        CliError::Unreachable(format!(
            "bench: connecting streaming client to broker at {addr}: {e}"
        ))
    })
}

/// Whether the run should stop given how many ops are done and when it started.
fn should_stop(bound: &Bound, done: u64, started: Instant) -> bool {
    match bound {
        Bound::Count(n) => done >= *n,
        Bound::Duration(d) => started.elapsed() >= *d,
    }
}

/// Paces the producer to the optional target rate: if a rate is set, sleeps until the scheduled
/// send time of message `seq` relative to `started`. With no rate it is closed-loop (no sleep).
fn pace(rate_hz: Option<f64>, seq: u64, started: Instant) {
    if let Some(hz) = rate_hz {
        if hz > 0.0 {
            #[allow(clippy::cast_precision_loss)]
            let scheduled = seq as f64 / hz;
            let target = Duration::from_secs_f64(scheduled);
            let now = started.elapsed();
            if let Some(remaining) = target.checked_sub(now) {
                std::thread::sleep(remaining);
            }
        }
    }
}

/// The AUTO-PIPELINING DURABLE publish leg (#508), split from [`run_publish`]: drive
/// [`Client::pipelined_producer_with_window`], the default single-producer durable-throughput lever.
/// The handle buffers a window of at-least-once publishes and flushes them as ONE group-committed
/// batch, so a SINGLE producer keeps the window in flight and the broker collapses it under one
/// fsync — the gap the awaited per-publish [`Client::produce`] cannot close (it has one publish in
/// flight at a time). Every publish stays durable (ack-implies-durable); only WHEN the ack is
/// observed moves. The window is sized by `--pubwindow` (or [`DEFAULT_PIPELINE_WINDOW`] when it is
/// the unpipelined default of 1, so a bare `--autopipe` still pipelines).
///
/// Per-op time is attributed across each flushed window evenly (one fdatasync covers the window), so
/// the reported fsync cost honestly reflects the group-commit amortization, exactly as the
/// half-duplex `--pubwindow` path does.
fn run_publish_autopipe(cfg: &BenchConfig, addr: &str) -> Result<BenchReport, CliError> {
    let mut pub_client = connect(addr)?;
    // A bare `--autopipe` (pubwindow left at its unpipelined default of 1) still pipelines: use the
    // client's default window so the throughput lever actually engages.
    let window = if cfg.pub_window > 1 {
        cfg.pub_window
    } else {
        ironbus_client::DEFAULT_PIPELINE_WINDOW
    };
    let mut payload = vec![0u8; cfg.payload_bytes];
    let mut produced: u64 = 0;
    let mut fsync_samples: Vec<u64> = Vec::new();
    let started = Instant::now();
    let mut pipe = pub_client.pipelined_producer_with_window(window);
    // Time each flush across the publishes it made durable: a flush issues ONE write whose covering
    // group commit is one fdatasync, so dividing the flush's wall time across its publishes gives an
    // honest per-op durable cost (the same attribution the `--pubwindow` half-duplex path uses).
    let mut window_start = Instant::now();
    let mut window_count: u64 = 0;
    while !should_stop(&cfg.bound, produced, started) {
        fill_payload(
            &mut payload,
            cfg.payload_shape,
            produced,
            ROUND_TRIP_TOKEN_LEN,
        );
        stamp_seq(&mut payload, produced);
        let body = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: &payload,
        };
        window_count += 1;
        match pipe.produce(&body) {
            // A non-empty summary means this publish filled the window and triggered a flush: the
            // window's publishes are now durable. Attribute the flush's elapsed time across them.
            Ok(summary) if summary.acked > 0 => {
                attribute_window(&mut fsync_samples, &mut window_start, &mut window_count);
            }
            Ok(_) => {} // buffered only; its flush is timed when the window fills (or at finish).
            Err(e) if is_shed(&e) => {
                attribute_window(&mut fsync_samples, &mut window_start, &mut window_count);
            }
            Err(e) => return Err(classify(addr, "auto-pipelining a produce to", &e)),
        }
        produced += 1;
        pace(cfg.target_rate_hz, produced, started);
    }
    // Drain the buffered tail: its flush makes the remaining publishes durable.
    match pipe.finish() {
        Ok(_) => attribute_window(&mut fsync_samples, &mut window_start, &mut window_count),
        Err(e) if is_shed(&e) => {
            attribute_window(&mut fsync_samples, &mut window_start, &mut window_count);
        }
        Err(e) => return Err(classify(addr, "flushing the auto-pipelined tail to", &e)),
    }
    let elapsed = started.elapsed();
    // The flush attribution is amortized across the window, so no per-op ack RTT is claimed.
    Ok(finish_report(
        cfg,
        produced,
        produced,
        &[],
        &fsync_samples,
        elapsed,
        SampleAttribution {
            fsync_measured: cfg.fsync_is_measured(),
            acks_awaited: false,
        },
    ))
}

/// Attributes one flushed window's elapsed wall time evenly across the publishes it covered, pushing
/// one per-op sample per publish, then resets the window timer/counter for the next window. A
/// no-op when the window covered nothing (an empty flush).
fn attribute_window(samples: &mut Vec<u64>, window_start: &mut Instant, window_count: &mut u64) {
    if *window_count == 0 {
        *window_start = Instant::now();
        return;
    }
    let elapsed_ns = u64::try_from(window_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let per_msg = elapsed_ns / *window_count;
    for _ in 0..*window_count {
        samples.push(per_msg);
    }
    *window_count = 0;
    *window_start = Instant::now();
}

/// The FULL-DUPLEX publish leg (#458), split from [`run_publish`]: one `produce_stream` call
/// pumps the whole run, writer and ack-reader overlapped, in-flight capped at the window.
fn run_publish_stream(
    cfg: &BenchConfig,
    pub_client: &mut Client,
    addr: &str,
    started: Instant,
) -> Result<BenchReport, CliError> {
    // The FULL-DUPLEX sliding window (#458): one produce_stream call pumps the whole run,
    // writer and ack-reader overlapped, in-flight capped at the window. Payloads come from a
    // pool of `window` DISTINCT pre-filled buffers cycled by sequence: the pool slots cannot
    // be re-stamped per message (they may still be borrowed by the in-flight encoder), and
    // publish mode never reads payloads back, so the seq/send-time stamps the half-duplex
    // path embeds would be dead bytes here anyway. Entropy honesty matches the windowed
    // path's working set: `window` distinct realistic payloads in rotation.
    let mut pool: Vec<Vec<u8>> = vec![vec![0u8; cfg.payload_bytes]; cfg.pub_window];
    for (i, buf) in pool.iter_mut().enumerate() {
        fill_payload(buf, cfg.payload_shape, i as u64, ROUND_TRIP_TOKEN_LEN);
    }
    let pool = &pool;
    let bound = &cfg.bound;
    let mut seq: u64 = 0;
    let messages = std::iter::from_fn(move || {
        if should_stop(bound, seq, started) {
            return None;
        }
        let body = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: &pool[usize::try_from(seq).unwrap_or(0) % pool.len()],
        };
        seq += 1;
        Some(body)
    });
    let summary = pub_client
        .produce_stream(messages, cfg.pub_window)
        .map_err(|e| classify(addr, "streaming produces to", &e))?;
    let produced = summary.acked;
    let elapsed = started.elapsed();
    // No per-produce fsync attribution: the overlap makes a per-message share dishonest, so
    // the histogram stays empty, the report's fsync_measured flag is forced off, and no per-op
    // ack RTT is claimed either.
    Ok(finish_report(
        cfg,
        produced,
        produced,
        &[],
        &[],
        elapsed,
        SampleAttribution {
            fsync_measured: false,
            acks_awaited: false,
        },
    ))
}

/// The AT-MOST-ONCE publish leg (QoS-0, the #11 fast path), split from [`run_publish`]: drive
/// [`Client::produce_fire_and_forget`] as fast as the bound/rate allow. No `PubAck` is awaited (the
/// broker may even drop a send under its fire-and-forget token bucket by contract), so there is no
/// durable-write cost to attribute and no read-back latency: the report's fsync cost is forced
/// not-measured and the latency fields stay `None`, exactly like the memory backend. This is the
/// matched analog to a core fire-and-forget pub on a routing broker (e.g. NATS core `nats bench
/// pub`), which likewise writes without awaiting an ack.
fn run_publish_faf(cfg: &BenchConfig, addr: &str) -> Result<BenchReport, CliError> {
    let mut pub_client = connect(addr)?;
    // ONE realistic-shaped payload, filled once and reused for every send. The realistic fill is
    // independent of sequence (only the round-trip token region would vary by seq, and a
    // fire-and-forget send is never read back, so that region is dead bytes here), so a single
    // buffer is byte-equivalent to re-filling per message AND matches how a core-pub benchmark
    // drives its broker (a fixed payload). Filling once keeps the loop measuring the PURE
    // at-most-once send rate, not a per-message refill the peer does not pay either.
    let mut payload = vec![0u8; cfg.payload_bytes];
    fill_payload(&mut payload, cfg.payload_shape, 0, ROUND_TRIP_TOKEN_LEN);
    let body = PubBody {
        flags: 0,
        timestamp_ms: 0,
        key: b"",
        headers: b"",
        dedup: None,
        // `produce_fire_and_forget` forces this true on the wire regardless; set it here too so the
        // body and the call's contract never disagree.
        fire_and_forget: true,
        payload: &payload,
    };
    let mut produced: u64 = 0;
    let started = Instant::now();
    // COALESCING at-most-once producer (#11 fast path): each publish is framed into the producer's wire
    // buffer and flushed to the socket with ONE `write_all` at 32 KiB boundaries, instead of one write
    // syscall per message — the same coalescing a core pub client (e.g. NATS `nats bench pub`) performs.
    // This is what makes the QoS-0 send rate a fair head-to-head with a coalescing core pub rather than
    // a self-handicapped syscall-per-message loop.
    let mut faf_producer = pub_client.fire_and_forget_producer();
    while !should_stop(&cfg.bound, produced, started) {
        // No reply is read (the broker sends no PubAck for a fire-and-forget produce); TCP backpressure
        // is the only pacing when the broker falls behind. An IO/encode error is fatal (frozen codes).
        faf_producer
            .send(&body)
            .map_err(|e| classify(addr, "fire-and-forget producing to", &e))?;
        produced += 1;
        pace(cfg.target_rate_hz, produced, started);
    }
    // Push the final partial batch before stopping the clock so every counted message is on the wire.
    faf_producer
        .flush()
        .map_err(|e| classify(addr, "fire-and-forget producing to", &e))?;
    let elapsed = started.elapsed();
    // At-most-once: no ack and no read-back, so no latency, no durable-write cost to attribute
    // (the broker may even have shed sends under its token bucket), and certainly no ack RTT.
    // fsync is forced not-measured.
    Ok(finish_report(
        cfg,
        produced,
        produced,
        &[],
        &[],
        elapsed,
        SampleAttribution {
            fsync_measured: false,
            acks_awaited: false,
        },
    ))
}

/// PUBLISH mode: append at the bound/rate, measuring produce-side throughput and bytes/op. Latency
/// is not measured (no read-back), so the latency fields stay `None`.
fn run_publish(cfg: &BenchConfig, addr: &str) -> Result<BenchReport, CliError> {
    if cfg.fire_and_forget {
        return run_publish_faf(cfg, addr);
    }
    if cfg.auto_pipeline {
        return run_publish_autopipe(cfg, addr);
    }
    let mut pub_client = connect(addr)?;
    let mut payload = vec![0u8; cfg.payload_bytes];
    let mut produced: u64 = 0;
    let mut fsync_samples: Vec<u64> = Vec::new();
    let started = Instant::now();
    if cfg.stream && cfg.pub_window > 1 {
        return run_publish_stream(cfg, &mut pub_client, addr, started);
    }
    if cfg.pub_window > 1 {
        // The PIPELINED window (#450): fill W distinct payload buffers, write all W PUB frames
        // before awaiting any ack (Client::produce_window), and attribute the window's elapsed
        // time evenly across its messages, so the per-op fsync-cost sample reflects the
        // group-commit amortization honestly (one fdatasync covers the whole window).
        let mut buffers: Vec<Vec<u8>> = vec![vec![0u8; cfg.payload_bytes]; cfg.pub_window];
        while !should_stop(&cfg.bound, produced, started) {
            let want = match &cfg.bound {
                Bound::Count(n) => {
                    usize::try_from(n.saturating_sub(produced)).unwrap_or(usize::MAX)
                }
                Bound::Duration(_) => cfg.pub_window,
            }
            .min(cfg.pub_window);
            if want == 0 {
                break;
            }
            for (i, buf) in buffers.iter_mut().enumerate().take(want) {
                let seq = produced + i as u64;
                fill_payload(buf, cfg.payload_shape, seq, ROUND_TRIP_TOKEN_LEN);
                stamp_seq(buf, seq);
                stamp_send_time(buf, started);
            }
            let window: Vec<PubBody<'_>> = buffers
                .iter()
                .take(want)
                .map(|buf| PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: buf,
                })
                .collect();
            let call_start = Instant::now();
            match pub_client.produce_window(&window) {
                Ok(_) => {}
                Err(e) if is_shed(&e) => {}
                Err(e) => return Err(classify(addr, "producing a window to", &e)),
            }
            let elapsed_ns = u64::try_from(call_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let per_msg = elapsed_ns / want as u64;
            for _ in 0..want {
                fsync_samples.push(per_msg);
            }
            produced += want as u64;
            pace(cfg.target_rate_hz, produced, started);
        }
    } else {
        while !should_stop(&cfg.bound, produced, started) {
            fill_payload(
                &mut payload,
                cfg.payload_shape,
                produced,
                ROUND_TRIP_TOKEN_LEN,
            );
            stamp_seq(&mut payload, produced);
            let produce_ns = produce_one(&mut pub_client, addr, &mut payload, started)?;
            fsync_samples.push(produce_ns);
            produced += 1;
            pace(cfg.target_rate_hz, produced, started);
        }
    }
    let elapsed = started.elapsed();
    // Publish has no read-back, so no end-to-end latency; but the per-produce durable cost IS
    // measured (the produce call returns after the fdatasync), so the fsync cost is honest unless
    // --no-fsync batched the checkpoints. The ack RTT percentiles (#1024) are claimed only on the
    // plain awaited-per-produce path (`--pubwindow 1`), never from the windowed loop's amortized
    // per-op shares.
    Ok(finish_report(
        cfg,
        produced,
        produced,
        &[],
        &fsync_samples,
        elapsed,
        SampleAttribution {
            fsync_measured: cfg.fsync_is_measured(),
            acks_awaited: cfg.publish_acks_are_awaited(),
        },
    ))
}

/// SUBSCRIBE mode: pre-populate the queue (count is known) then drain it via the synthetic group,
/// measuring fetch/ack throughput. Records read-back latency from the embedded send time against a
/// single `started` shared by the preload and the drain, so the latency math is valid.
fn run_subscribe(cfg: &BenchConfig, addr: &str) -> Result<BenchReport, CliError> {
    // Determine how many to pre-load: the count bound, or a modest batch for a duration bound.
    let preload: u64 = match cfg.bound {
        Bound::Count(n) => n,
        Bound::Duration(_) => SUBSCRIBE_DURATION_PRELOAD,
    };
    let started = Instant::now();
    let mut producer = connect(addr)?;
    // Pre-load via a PIPELINED produce window (group-committed), not a serial per-message produce:
    // SUBSCRIBE measures the DRAIN rate, so the preload's write speed is irrelevant to the metric,
    // and a serial fdatasync-per-message preload is otherwise fsync-bound (~SD speed), making a
    // large preload take minutes for no measurement value. Each message still carries its `seq`
    // stamp. Chunked so the in-flight window stays bounded.
    let mut seq: u64 = 0;
    while seq < preload {
        let n = (preload - seq).min(PRELOAD_CHUNK);
        let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut b = vec![0u8; cfg.payload_bytes];
            fill_payload(&mut b, cfg.payload_shape, seq + i, ROUND_TRIP_TOKEN_LEN);
            stamp_seq(&mut b, seq + i);
            bufs.push(b);
        }
        let bodies: Vec<PubBody<'_>> = bufs
            .iter()
            .map(|b| PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b,
            })
            .collect();
        producer
            .produce_window(&bodies)
            .map_err(|e| classify(addr, "preloading the subscribe queue on", &e))?;
        seq += n;
    }
    drop(producer);

    // The measured drain phase: time it from here so the throughput reflects fetch/ack, not the
    // preload. The preload fsync cost is not the SUBSCRIBE metric (drain throughput is), so the
    // fsync histogram is empty for this mode.
    let drain_start = Instant::now();
    // TIER selector (#554): Tier-W is the per-message-lease work queue; Tier-S is the streaming
    // consumer-managed-offset path (the durable single-consumer streaming-consume head-to-head).
    let (recorded, latencies) = match cfg.consume_tier {
        ConsumeTier::Work => drain(cfg, addr, preload, started)?,
        ConsumeTier::Streaming => drain_streaming(cfg, addr, preload, started)?,
    };
    Ok(finish_report(
        cfg,
        preload,
        recorded,
        &latencies,
        &[],
        drain_start.elapsed(),
        SampleAttribution {
            fsync_measured: false,
            acks_awaited: false,
        },
    ))
}

/// ROUND-TRIP mode: a producer thread appends on the bound/rate while this thread fetches + acks and
/// records producer-to-consumer latency through the real #6 path, so the fsync cost is honest.
fn run_round_trip(cfg: &BenchConfig, addr: &str) -> Result<BenchReport, CliError> {
    let stop = Arc::new(AtomicBool::new(false));
    let started = Instant::now();

    // The producer runs on its own thread so the consumer can drain concurrently (the round trip).
    let producer_handle = {
        let cfg = cfg.clone();
        let addr = addr.to_string();
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("ironbus-bench-producer".to_string())
            .spawn(move || -> Result<(u64, Vec<u64>), CliError> {
                let mut pub_client = connect(&addr)?;
                let mut payload = vec![0u8; cfg.payload_bytes];
                let mut produced: u64 = 0;
                let mut fsync_samples: Vec<u64> = Vec::new();
                while !should_stop(&cfg.bound, produced, started) {
                    fill_payload(
                        &mut payload,
                        cfg.payload_shape,
                        produced,
                        ROUND_TRIP_TOKEN_LEN,
                    );
                    stamp_seq(&mut payload, produced);
                    fsync_samples.push(produce_one(&mut pub_client, &addr, &mut payload, started)?);
                    produced += 1;
                    pace(cfg.target_rate_hz, produced, started);
                }
                stop.store(true, Ordering::Release);
                Ok((produced, fsync_samples))
            })
            .map_err(|e| CliError::Internal(format!("bench: cannot spawn producer thread: {e}")))?
    };

    // The consumer drains and records until the producer is done AND the backlog is drained.
    let mut consumer = connect(addr)?;
    subscribe_group(&mut consumer, addr, &cfg.group)?;
    let mut latencies: Vec<u64> = Vec::new();
    let mut recorded: u64 = 0;
    loop {
        let fetched = fetch_batch(&mut consumer, addr, cfg.fetch_batch)?;
        let now = Instant::now();
        for m in &fetched.messages {
            if let Some(sent) = read_round_trip_time(&m.payload, started) {
                let latency_ns =
                    u64::try_from(now.duration_since(sent).as_nanos()).unwrap_or(u64::MAX);
                latencies.push(latency_ns);
                recorded += 1;
            }
            ack_one(&mut consumer, addr, m.offset, m.generation)?;
        }
        if fetched.messages.is_empty() && stop.load(Ordering::Acquire) {
            break;
        }
        if fetched.messages.is_empty() {
            std::thread::sleep(Duration::from_micros(200));
        }
    }
    let elapsed = started.elapsed();

    let (produced, fsync_samples) = match producer_handle.join() {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(CliError::Internal(
                "bench: producer thread panicked".to_string(),
            ))
        }
    };

    // The honest fsync cost is the median produce-call latency (ack-after-fsync, I2), measured only
    // when the durable path was exercised per produce, i.e. NOT in the --no-fsync dry run. The
    // producer leg awaits EVERY produce individually, so the same samples are honest produce-to-ack
    // RTTs (#1024) on any backend.
    Ok(finish_report(
        cfg,
        produced,
        recorded,
        &latencies,
        &fsync_samples,
        elapsed,
        SampleAttribution {
            fsync_measured: cfg.fsync_is_measured(),
            acks_awaited: true,
        },
    ))
}

/// Consecutive empty fetches that mean a count-bound drain is truly drained even below `expected`.
/// ~20ms at the 200us poll yield: long enough that the (already-finished) producer's records have
/// all arrived, short enough not to stall a normal full drain.
const DRAINED_GRACE_POLLS: u32 = 100;

/// Whether [`drain`] should stop. Pure so the termination logic is unit-tested without a broker.
///
/// Count bound: stop once the queue is drained (`empty_streak > 0`, the last fetch was empty) AND
/// either every expected record arrived (the normal full drain) OR the queue has stayed empty for
/// [`DRAINED_GRACE_POLLS`] (the rest were SHED under the broker's byte cap and will never arrive --
/// the producer already finished, so a sustained-empty queue cannot refill). Without the grace, a
/// shed/lossy preload hangs the drain forever waiting for `recorded >= expected`.
fn drain_should_stop(
    bound: Bound,
    recorded: u64,
    expected: u64,
    empty_streak: u32,
    drain_started: Instant,
) -> bool {
    match bound {
        Bound::Count(_) => {
            empty_streak > 0 && (recorded >= expected || empty_streak >= DRAINED_GRACE_POLLS)
        }
        Bound::Duration(d) => drain_started.elapsed() >= d,
    }
}

/// Drains all `expected` messages from the broker through the synthetic group, recording per-message
/// read-back latency (against the producer's `produce_started`), until the queue is empty after the
/// expected count is reached (count bound) or the drain duration elapses (duration bound).
///
/// The synthetic group is a COMPETING work-queue, so each lease is committed individually (cumulative
/// ack is broadcast-only). How those individual acks are ISSUED is the #464 fair-consume knob
/// ([`AckMode`]): by DEFAULT the drain settles each fetched batch with ONE pipelined `ack_many`
/// round-trip (the consume-side twin of the publish window), so the measured throughput reflects the
/// broker's real fetch + batch-ack rate — comparable to a NATS pull consumer or Redis `XREADGROUP`
/// whose clients batch their acks. Under `--per-message-ack` it falls back to one synchronous `ack`
/// per message (the historical drain), which is ack-RPC-LATENCY-bound, NOT fetch-bound. EITHER WAY
/// every fetched message is acked: the batched path settles the exact same leases, just amortized.
fn drain(
    cfg: &BenchConfig,
    addr: &str,
    expected: u64,
    produce_started: Instant,
) -> Result<(u64, Vec<u64>), CliError> {
    let mut consumer = connect(addr)?;
    subscribe_group(&mut consumer, addr, &cfg.group)?;
    let mut latencies: Vec<u64> = Vec::new();
    let mut recorded: u64 = 0;
    let mut empty_streak: u32 = 0;
    // Reused across iterations so the batched-ack path does not reallocate the ack vector per batch.
    let mut acks: Vec<(u64, u64)> = Vec::with_capacity(cfg.fetch_batch as usize);
    let drain_started = Instant::now();
    loop {
        // FAIR consume pull (#489): batch-pull the whole credit window in ONE round-trip (the NATS
        // pull-consumer twin), instead of one Flow round-trip per `fetch`, so the measured drain
        // reflects the broker's fetch throughput, not a per-fetch RPC. `no_wait` returns immediately
        // with whatever is ready (a single drain pass), exactly the closed-loop drain shape.
        let fetched = fetch_batch_pull(&mut consumer, addr, cfg.fetch_batch)?;
        let now = Instant::now();
        acks.clear();
        for m in &fetched.messages {
            if let Some(sent) = read_round_trip_time(&m.payload, produce_started) {
                // The read-back latency: time from the message's produce instant to its delivery.
                let latency_ns = u64::try_from(now.saturating_duration_since(sent).as_nanos())
                    .unwrap_or(u64::MAX);
                latencies.push(latency_ns);
            }
            recorded += 1;
            match cfg.consume_ack {
                // FAIR (#464): collect this batch's leases and settle them ALL in one pipelined
                // `ack_many` round-trip below, so the drain measures fetch + batch-ack throughput
                // (comparable to a NATS pull consumer / Redis XREADGROUP whose clients batch acks),
                // not the per-message ack RPC. Each lease is still acked individually by the broker
                // (correct for a COMPETING work-queue, where cumulative ack is broadcast-only).
                AckMode::Batched => acks.push((m.offset, m.generation)),
                // LEGACY per-message ack: one synchronous ack round-trip per delivered lease, the
                // historical ack-RPC-bound path kept available as an ack-LATENCY measurement.
                AckMode::PerMessage => ack_one(&mut consumer, addr, m.offset, m.generation)?,
            }
        }
        // Settle the whole batch with ONE pipelined round-trip (write all acks, then drain all
        // statuses). Bounded by the fetch credit, so the write-all-then-drain shape cannot deadlock
        // against the socket buffers. EVERY fetched message is acked: the batched path settles the
        // exact same leases the per-message path does, just amortized.
        if matches!(cfg.consume_ack, AckMode::Batched) && !acks.is_empty() {
            ack_many(&mut consumer, addr, &acks)?;
        }
        empty_streak = if fetched.messages.is_empty() {
            empty_streak.saturating_add(1)
        } else {
            0
        };
        if drain_should_stop(cfg.bound, recorded, expected, empty_streak, drain_started) {
            break;
        }
        if fetched.messages.is_empty() {
            // Caught up but not done: a tiny yield before the next poll.
            std::thread::sleep(Duration::from_micros(200));
        }
    }
    if recorded < expected {
        // The producer finished BEFORE the drain started, so a drained queue with fewer than
        // `expected` records means the broker shed the rest under its byte cap (memory mode, or a
        // disk drop policy) -- report it rather than hang waiting for records that will never come.
        eprintln!(
            "note: drained {recorded} of {expected} preloaded records; the broker shed \
             {} under its cap (the consume rate is over the {recorded} that survived)",
            expected - recorded
        );
    }
    Ok((recorded, latencies))
}

/// Drains the preloaded prefix via the TIER-S STREAMING consumer (#554): the batched-fetch +
/// bounded-read-ahead + periodic-cumulative-commit [`ironbus_client::StreamingConsumer`] default
/// (#662). This is the durable single-consumer streaming-consume path — the head-to-head with a NATS
/// `JetStream` pull consumer's batched-ack drain — NOT the per-message-lease work queue [`drain`]
/// measures. It returns the same `(recorded, latencies)` pair so the two tiers share the reporting
/// path; the consumer's `next_batch` does the windowed `StreamFetch` and commits the cursor
/// cumulatively every `commit_every_batches`, so the bench drives no per-message ack here (a
/// streaming consumer commits an offset, it does not settle leases).
fn drain_streaming(
    cfg: &BenchConfig,
    addr: &str,
    expected: u64,
    produce_started: Instant,
) -> Result<(u64, Vec<u64>), CliError> {
    let mut consumer_conn = connect_streaming(addr)?;
    subscribe_group(&mut consumer_conn, addr, &cfg.group)?;
    // The streaming window mirrors the Tier-W fetch credit (`--fetch-batch`), so the two tiers fetch
    // the same window size and the comparison is the TIER, not the window. Read-ahead ON is the #662
    // ergonomic default (the next window's StreamFetch is hidden behind processing the current one),
    // and the commit cadence is the client default (commit the cursor once every N windows).
    let stream_cfg = StreamConsumerConfig {
        max_records: cfg.fetch_batch,
        max_bytes: 0,
        read_ahead: true,
        ..StreamConsumerConfig::default()
    };
    let mut latencies: Vec<u64> = Vec::new();
    let mut recorded: u64 = 0;
    let mut consumer = consumer_conn.streaming_consumer_with(&cfg.group, &stream_cfg);
    let drain_started = Instant::now();
    let mut empty_streak: u32 = 0;
    loop {
        let batch = consumer
            .next_batch()
            .map_err(|e| classify(addr, "streaming-fetching from", &e))?;
        let now = Instant::now();
        for m in &batch.messages {
            if let Some(sent) = read_round_trip_time(&m.payload, produce_started) {
                let latency_ns = u64::try_from(now.saturating_duration_since(sent).as_nanos())
                    .unwrap_or(u64::MAX);
                latencies.push(latency_ns);
            }
            recorded += 1;
        }
        empty_streak = if batch.messages.is_empty() {
            empty_streak.saturating_add(1)
        } else {
            0
        };
        if drain_should_stop(cfg.bound, recorded, expected, empty_streak, drain_started) {
            break;
        }
        if batch.messages.is_empty() {
            std::thread::sleep(Duration::from_micros(200));
        }
    }
    // Flush the final cumulative commit (any window since the last periodic commit), so the consumed
    // span is durably checkpointed exactly as a real streaming consumer would leave it on shutdown.
    let _committed = consumer
        .finish()
        .map_err(|e| classify(addr, "committing the streaming cursor to", &e))?;
    if recorded < expected {
        eprintln!(
            "note: streaming-drained {recorded} of {expected} preloaded records; the broker shed \
             {} under its cap (the consume rate is over the {recorded} that survived)",
            expected - recorded
        );
    }
    Ok((recorded, latencies))
}

/// How the per-produce-call samples (`fsync_samples`) may honestly be attributed in the report.
/// The two flags are ORTHOGONAL: a plain awaited publish on the memory backend has an honest ack
/// RTT (`acks_awaited`) but no durable-write cost (`fsync_measured` off), while a `--pubwindow 8`
/// disk publish has an honest amortized fsync cost but NO per-op ack RTT.
#[derive(Clone, Copy)]
struct SampleAttribution {
    /// The per-op DURABLE path was exercised (disk backend, not the `--no-fsync` dry run), so the
    /// median sample is an honest per-op fsync cost ([`BenchConfig::fsync_is_measured`]).
    fsync_measured: bool,
    /// EVERY produce was individually awaited (plain `--pubwindow 1` publish, or the round-trip
    /// producer leg), so the samples are honest produce-to-ack RTTs REGARDLESS of storage backend
    /// (#1024). Off on the pipelined/fire-and-forget paths, whose per-op shares are amortized.
    acks_awaited: bool,
}

/// Assembles a [`BenchReport`] from the run tallies, the end-to-end LATENCY samples (read-back, in
/// the latency modes), and the per-produce-call samples (`fsync_samples`). The reported fsync cost
/// is the MEDIAN produce-call latency, not the round-trip p50: a `Pub` returns its `PubAck` only
/// after the covering group-commit `fdatasync` (invariant I2), so the produce-call median isolates
/// the durable-write cost from the queue-wait that inflates round-trip latency. It is reported only
/// when `fsync_measured` (not in the `--no-fsync` dry run, which batches cursor checkpoints). The
/// same samples yield the produce-to-ack RTT percentiles (#1024) — but only when `acks_awaited`
/// (every produce individually awaited), and then on ANY backend.
fn finish_report(
    cfg: &BenchConfig,
    produced: u64,
    recorded: u64,
    latencies: &[u64],
    fsync_samples: &[u64],
    elapsed: Duration,
    attribution: SampleAttribution,
) -> BenchReport {
    let elapsed_secs = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    // Throughput counts the messages the MEASURED side moved: recorded for a latency mode, produced
    // for publish-only.
    let moved = if cfg.mode.measures_latency() {
        recorded
    } else {
        produced
    };
    #[allow(clippy::cast_precision_loss)]
    let moved_f = moved as f64;
    #[allow(clippy::cast_precision_loss)]
    let payload_f = cfg.payload_bytes as f64;
    let msgs_per_sec = moved_f / elapsed_secs;
    let mb_per_sec = (moved_f * payload_f) / (1024.0 * 1024.0) / elapsed_secs;
    let bytes_per_op = if moved > 0 { payload_f } else { 0.0 };

    let mut report = BenchReport {
        produced,
        recorded,
        elapsed_secs,
        msgs_per_sec,
        mb_per_sec,
        bytes_per_op,
        fsync_measured: attribution.fsync_measured,
        ..BenchReport::default()
    };
    if let Some((p50, p99, p999, max)) = percentiles_us(latencies) {
        report.p50_us = Some(p50);
        report.p99_us = Some(p99);
        report.p999_us = Some(p999);
        report.max_us = Some(max);
    }
    // The produce-to-ack RTT percentiles (#1024): honest only when EVERY produce was individually
    // awaited (each sample is one full produce-call round trip), and then on any backend — an ack
    // RTT on the memory engine is a real RTT, it is just not a durable-write cost.
    if attribution.acks_awaited {
        if let Some((p50, p99, p999, max)) = percentiles_us(fsync_samples) {
            report.ack_p50_us = Some(p50);
            report.ack_p99_us = Some(p99);
            report.ack_p999_us = Some(p999);
            report.ack_max_us = Some(max);
        }
    }
    // The honest per-op fsync cost: the median produce-call latency, which an ack-after-fsync broker
    // (I2) cannot return before the durable write completes. Reported only when measured through the
    // per-produce durable path.
    if attribution.fsync_measured {
        if let Some((fsync_p50, _, _, _)) = percentiles_us(fsync_samples) {
            report.fsync_cost_us = Some(fsync_p50);
        }
    }
    report
}

/// Writes the sequence number into the token (bytes [8,16)), leaving the time slot (bytes [0,8))
/// for the produce-time stamp written by `produce_one`. The round-trip token is the 8-byte send
/// time then this 8-byte sequence; the consumer reads the time back to compute latency.
fn stamp_seq(payload: &mut [u8], seq: u64) {
    if payload.len() >= ROUND_TRIP_TOKEN_LEN {
        payload[8..16].copy_from_slice(&seq.to_le_bytes());
    }
}

/// Reads the send time back out of a delivered payload as an `Instant`, or `None` if the payload is
/// too short to carry the token (so a stray message never poisons the latency sample). The stored
/// value is nanoseconds since `started`; reconstruct the `Instant` by adding that to `started`.
fn read_round_trip_time(payload: &[u8], started: Instant) -> Option<Instant> {
    if payload.len() < ROUND_TRIP_TOKEN_LEN {
        return None;
    }
    let bytes = <[u8; 8]>::try_from(&payload[0..8]).ok()?;
    let offset_ns = u64::from_le_bytes(bytes);
    Some(started + Duration::from_nanos(offset_ns))
}

/// Produces one message, stamping the send-time token (nanos since the producer's `started`) into
/// the front of the payload just before the wire write, so the latency reflects the REAL send
/// instant (not the fill instant). Returns the produce-CALL latency in nanoseconds: a `Pub` returns
/// its `PubAck` only after the covering group-commit `fdatasync` completes (invariant I2), so this
/// is the honest per-op durable write cost, the basis of the reported fsync cost. Maps a fatal
/// client error to the frozen exit codes; a non-fatal capacity shed is tolerated (the overload
/// workload) and reported with the elapsed time so the shed path is still timed.
fn produce_one(
    client: &mut Client,
    addr: &str,
    payload: &mut [u8],
    started: Instant,
) -> Result<u64, CliError> {
    stamp_send_time(payload, started);
    let call_start = Instant::now();
    let result = client.produce(&PubBody {
        flags: 0,
        timestamp_ms: 0,
        key: b"",
        headers: b"",
        dedup: None,
        fire_and_forget: false,
        payload,
    });
    let latency_ns = u64::try_from(call_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    match result {
        Ok(_) => Ok(latency_ns),
        Err(e) if is_shed(&e) => Ok(latency_ns),
        Err(e) => Err(classify(addr, "producing to", &e)),
    }
}

/// Subscribes the consumer to the synthetic group, mapping a server rejection to an internal error.
fn subscribe_group(client: &mut Client, addr: &str, group: &str) -> Result<(), CliError> {
    client
        .subscribe(group)
        .map_err(|e| classify(addr, "subscribing to", &e))
}

/// Fetches up to `credit` messages, mapping a client error to the frozen exit codes. The per-fetch
/// (one Flow round-trip) pull used by the round-trip consumer, where the producer and consumer are
/// concurrent so a per-fetch poll is the natural shape.
fn fetch_batch(
    client: &mut Client,
    addr: &str,
    credit: u32,
) -> Result<ironbus_client::Fetch, CliError> {
    client
        .fetch(credit)
        .map_err(|e| classify(addr, "fetching from", &e))
}

/// Batch-pull up to `credit` records in ONE round-trip (#489), mapping a client error to the frozen
/// exit codes. Used by the SUBSCRIBE drain so the pull cost is amortized across the whole credit
/// window (the NATS pull-consumer twin) instead of one Flow round-trip per `fetch`. `no_wait` returns
/// immediately with whatever is ready — a single drain pass, the closed-loop drain shape — so the
/// drain's empty-queue termination logic is unchanged. No byte budget (`0`) and no deadline: the
/// record credit alone bounds the batch, exactly as the per-record `fetch` path is bounded.
fn fetch_batch_pull(
    client: &mut Client,
    addr: &str,
    credit: u32,
) -> Result<ironbus_client::Fetch, CliError> {
    client
        .fetch_batch(credit, 0, Duration::ZERO, true)
        .map_err(|e| classify(addr, "batch-fetching from", &e))
}

/// Acks one delivered message, mapping a client error to the frozen exit codes.
fn ack_one(client: &mut Client, addr: &str, offset: u64, generation: u64) -> Result<(), CliError> {
    client
        .ack(offset, generation)
        .map(|_| ())
        .map_err(|e| classify(addr, "acking to", &e))
}

/// Acks a whole fetched batch in ONE pipelined round-trip (#469), mapping a client error to the
/// frozen exit codes. The consume-side twin of `produce_window`: write every `(offset, generation)`
/// ack with one syscall, then drain one status per ack. Each lease is committed INDIVIDUALLY by the
/// broker, so this is correct for the COMPETING work-queue the bench drains (where cumulative ack is
/// broadcast-only). Caller keeps the batch bounded by the fetch credit so the write-all-then-drain
/// shape cannot deadlock against the socket buffers.
fn ack_many(client: &mut Client, addr: &str, acks: &[(u64, u64)]) -> Result<(), CliError> {
    client
        .ack_many(acks)
        .map(|_| ())
        .map_err(|e| classify(addr, "batch-acking to", &e))
}

/// Classifies a client error against the frozen exit-code scheme: a transport-level failure is
/// broker-unreachable (5); a broker error frame is internal (70). Mirrors `main.rs::classify`.
fn classify(addr: &str, doing: &str, e: &ClientError) -> CliError {
    let message = format!("bench: {doing} broker at {addr}: {e}");
    match e {
        ClientError::Io(_) | ClientError::Closed => CliError::Unreachable(message),
        _ => CliError::Internal(message),
    }
}

/// Whether a client error is the deliberate non-fatal #10 capacity shed, which the overload
/// workload tolerates rather than aborting. Mirrors the bench-crate harness `is_shed`.
fn is_shed(err: &ClientError) -> bool {
    matches!(err, ClientError::Server(m) if m.contains("at capacity"))
}

/// The number of messages a SUBSCRIBE run with a DURATION bound pre-loads before draining.
const SUBSCRIBE_DURATION_PRELOAD: u64 = 10_000;
/// Chunk size for the pipelined SUBSCRIBE preload (#19): a bounded in-flight window so a large
/// preload group-commits in batches rather than one unbounded window.
const PRELOAD_CHUNK: u64 = 1000;

/// Writes the send-time (nanos since `started`, little-endian) into the token's time slot
/// (bytes [0,8)). Called by `produce_one` at the real produce instant, so the recorded latency is
/// honest. A payload too short to carry the token leaves the latency unmeasured (skipped on read).
fn stamp_send_time(payload: &mut [u8], started: Instant) {
    if payload.len() >= ROUND_TRIP_TOKEN_LEN {
        let offset_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        payload[0..8].copy_from_slice(&offset_ns.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a bench arg list with the deterministic test suffix, mirroring `bench.rs`'s helper.
    fn cfg_of(args: &[&str]) -> BenchConfig {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        crate::bench::parse_bench(&owned, "deadbeef").expect("valid bench args")
    }

    /// 1000 per-produce samples of 1..=1000 us (in nanoseconds), so the expected percentiles are
    /// known exactly: max = 1000 us and p50 <= p99 <= p999 <= max.
    fn awaited_samples() -> Vec<u64> {
        (1..=1000u64).map(|us| us * 1_000).collect()
    }

    #[test]
    fn awaited_publish_samples_yield_ack_percentiles_on_disk_and_memory() {
        let samples = awaited_samples();
        // DISK, plain --pubwindow 1 publish: BOTH the #1024 ack RTT percentiles and the honest
        // fsync cost come from the same awaited per-produce samples, so the ack p50 must equal
        // the reported fsync cost exactly.
        let disk = cfg_of(&["--count", "1000", "--mode", "publish"]);
        let report = finish_report(
            &disk,
            1000,
            1000,
            &[],
            &samples,
            Duration::from_secs(1),
            SampleAttribution {
                fsync_measured: disk.fsync_is_measured(),
                acks_awaited: disk.publish_acks_are_awaited(),
            },
        );
        let p50 = report.ack_p50_us.expect("disk ack p50");
        let p99 = report.ack_p99_us.expect("disk ack p99");
        let p999 = report.ack_p999_us.expect("disk ack p999");
        let max = report.ack_max_us.expect("disk ack max");
        assert!(p50 <= p99 && p99 <= p999 && p999 <= max, "ordered tail");
        assert!((max - 1000.0).abs() < 1e-9, "max is the 1000 us sample");
        let fsync = report.fsync_cost_us.expect("disk fsync cost");
        assert!(
            (fsync - p50).abs() < 1e-9,
            "same samples, same median: fsync {fsync} vs ack p50 {p50}"
        );
        // MEMORY, same plain publish: the ack RTT is STILL honest (#1024, backend-agnostic), but
        // no fsync cost may be claimed (the in-memory engine issues no fsync).
        let memory = cfg_of(&[
            "--count",
            "1000",
            "--mode",
            "publish",
            "--storage",
            "memory",
        ]);
        let report = finish_report(
            &memory,
            1000,
            1000,
            &[],
            &samples,
            Duration::from_secs(1),
            SampleAttribution {
                fsync_measured: memory.fsync_is_measured(),
                acks_awaited: memory.publish_acks_are_awaited(),
            },
        );
        assert!(report.ack_p50_us.is_some(), "memory ack p50 is honest");
        assert!(report.ack_max_us.is_some(), "memory ack max is honest");
        assert!(!report.fsync_measured, "no fsync exists in memory mode");
        assert!(report.fsync_cost_us.is_none(), "so none may be claimed");
    }

    #[test]
    fn amortized_publish_never_claims_ack_percentiles() {
        // A windowed publish's per-op shares are amortized (one flush covers the window), so the
        // #1024 gate holds them out of the ack fields — even though the amortized fsync cost is
        // still honestly attributed on disk. This FAILS if the awaited-only gate is dropped.
        let cfg = cfg_of(&["--count", "1000", "--mode", "publish", "--pubwindow", "8"]);
        let samples = awaited_samples();
        let report = finish_report(
            &cfg,
            1000,
            1000,
            &[],
            &samples,
            Duration::from_secs(1),
            SampleAttribution {
                fsync_measured: cfg.fsync_is_measured(),
                acks_awaited: cfg.publish_acks_are_awaited(),
            },
        );
        assert!(report.ack_p50_us.is_none(), "amortized: no ack p50");
        assert!(report.ack_p99_us.is_none(), "amortized: no ack p99");
        assert!(report.ack_p999_us.is_none(), "amortized: no ack p999");
        assert!(report.ack_max_us.is_none(), "amortized: no ack max");
        assert!(
            report.fsync_cost_us.is_some(),
            "the amortized disk fsync cost is still reported"
        );
    }

    #[test]
    fn round_trip_producer_leg_populates_ack_percentiles() {
        // The round-trip producer leg awaits every produce (produce_one), so its samples carry the
        // #1024 ack percentiles alongside — and independent of — the e2e delivery percentiles.
        let cfg = cfg_of(&["--count", "1000", "--mode", "round-trip"]);
        let latencies: Vec<u64> = (1..=1000u64).map(|us| us * 5_000).collect(); // 5..5000 us e2e
        let samples = awaited_samples();
        let report = finish_report(
            &cfg,
            1000,
            1000,
            &latencies,
            &samples,
            Duration::from_secs(1),
            SampleAttribution {
                fsync_measured: cfg.fsync_is_measured(),
                acks_awaited: true,
            },
        );
        let ack_max = report.ack_max_us.expect("round-trip ack max");
        let e2e_max = report.max_us.expect("round-trip e2e max");
        assert!(report.ack_p50_us.is_some(), "round-trip ack p50");
        assert!(
            ack_max < e2e_max,
            "the ack RTT ({ack_max}) is the produce leg only, strictly below the e2e delivery \
             tail ({e2e_max}) here"
        );
    }

    #[test]
    fn no_fsync_spawns_an_interval_durability_broker_and_the_default_stays_sync() {
        // #1027 DISCRIMINATOR: `--no-fsync` must relax the spawned broker's PRODUCE durability to
        // `interval` (the bounded-loss page-cache tier) IN ADDITION to batching the cursor
        // checkpoints. This FAILS on the pre-#1027 code, where only the checkpoint interval moved
        // and the "page-cache dry run" silently measured the per-ack `sync` fsync tier.
        let dry = bench_serve_config(&cfg_of(&["--count", "10", "--no-fsync"]));
        assert_eq!(
            dry.durability_level,
            DurabilityLevelArg::Interval,
            "--no-fsync must materialize interval durability on the spawned broker"
        );
        assert_eq!(
            dry.checkpoint_interval, 1_000_000,
            "the checkpoint relaxation is kept alongside the durability relaxation"
        );
        // The relaxed level must still pass the REAL serve boot gates (interval needs at least one
        // positive flush trigger and is not `--async-loss-ack`-gated), or the spawn would refuse.
        crate::validate_serve_config(&dry).expect("the --no-fsync bench config boots");
        // And the audit surface says so: the materialized-config line the run logs names the tier.
        let line = materialized_config_line(&dry, "127.0.0.1:0", None);
        assert!(
            line.contains("durability_level=interval") && line.contains("power_loss_safe=false"),
            "the materialized-config line must name the interval tier: {line}"
        );
        // WITHOUT the flag the honest default is untouched: per-ack sync durability, per-ack
        // checkpoint, and the line says so.
        let honest = bench_serve_config(&cfg_of(&["--count", "10"]));
        assert_eq!(honest.durability_level, DurabilityLevelArg::Sync);
        assert_eq!(honest.checkpoint_interval, 1);
        let line = materialized_config_line(&honest, "127.0.0.1:0", None);
        assert!(
            line.contains("durability_level=sync") && line.contains("power_loss_safe=true"),
            "the default bench broker stays on the power-loss-safe sync tier: {line}"
        );
    }

    #[test]
    fn drain_stops_on_full_count_and_on_shed_but_not_before_caught_up() {
        let t = Instant::now();
        // Full drain: every expected record arrived and the queue is empty -> stop.
        assert!(drain_should_stop(Bound::Count(500), 500, 500, 1, t));
        // Still receiving (last fetch non-empty -> streak 0): keep going.
        assert!(!drain_should_stop(Bound::Count(500), 200, 500, 0, t));
        // Caught up but short of expected after only a brief empty: could be transient, keep waiting.
        assert!(!drain_should_stop(Bound::Count(500), 200, 500, 1, t));
        // Sustained-empty below expected (records were shed): stop instead of hanging forever.
        assert!(drain_should_stop(
            Bound::Count(500),
            200,
            500,
            DRAINED_GRACE_POLLS,
            t
        ));
    }

    use super::DataDirGuard;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn unique_dir(tag: &str) -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ironbus-bench-{tag}-{}-{n}", std::process::id()))
    }

    #[test]
    fn an_armed_guard_removes_the_dir_on_drop() {
        let dir = unique_dir("guard-armed");
        std::fs::create_dir_all(&dir).expect("create test dir");
        assert!(dir.exists());
        {
            let _guard = DataDirGuard::arm(dir.clone());
        }
        assert!(
            !dir.exists(),
            "an armed guard must remove the synthetic dir on drop (the spawn-failure / panic leak path)"
        );
    }

    #[test]
    fn a_disarmed_guard_leaves_the_dir() {
        let dir = unique_dir("guard-disarmed");
        std::fs::create_dir_all(&dir).expect("create test dir");
        {
            let mut guard = DataDirGuard::arm(dir.clone());
            guard.disarm();
        }
        assert!(
            dir.exists(),
            "a disarmed guard must NOT remove the dir; the explicit failure-reporting cleanup owns deletion"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
