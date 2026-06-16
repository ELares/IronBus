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
    fill_payload, percentiles_us, BenchConfig, BenchReport, Bound, Mode, BENCH_NAMESPACE_PREFIX,
    ROUND_TRIP_TOKEN_LEN,
};
use crate::{open_disk_engine, open_memory_engine, CliError, ServeConfig, StorageArg};
use ironbus_client::{Client, ClientConfig, ClientError};
use ironbus_core::clock::Clock; // the monotonic seam the serve loop's liveness beacon (#95) reads
use ironbus_proto::message::PubBody;
use ironbus_server::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
use ironbus_server::server::serve;
use ironbus_storage::fs::{Filesystem, InMemoryFs, StdFs};
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

impl IsolatedBroker<InMemoryFs> {
    /// Spawns the MEMORY broker (#445): the same engine over a fresh in-memory filesystem via the
    /// shared `open_memory_engine`, so the bench broker is the REAL `serve --storage memory`
    /// engine path. No file is created and nothing needs cleanup afterwards.
    fn spawn_memory(config: &ServeConfig) -> Result<IsolatedBroker<InMemoryFs>, CliError> {
        let engine = open_memory_engine(config, &[], &[])?;
        IsolatedBroker::from_engine(engine, config)
    }
}

impl<F: Filesystem + 'static> IsolatedBroker<F> {
    /// Hosts an ALREADY-OPENED engine: actor spawn, ephemeral loopback bind, serve thread. The
    /// shared backend-independent body behind both spawn constructors.
    fn from_engine(
        engine: ironbus_server::engine::Engine<F, ironbus_server::clock::SystemClock>,
        config: &ServeConfig,
    ) -> Result<IsolatedBroker<F>, CliError> {
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
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
/// large batch under `--no-fsync` (spare flash, fsync cost not measured). Under
/// `--storage memory` (#445) it carries the memory backend plus the two boot-gate requirements
/// the real serve path enforces: the explicit ephemeral consent (bench's synthetic broker and its
/// data are disposable by design, so bench supplies the consent the way it already owns the
/// auto-delete of its synthetic disk dir) and the default in-RAM byte cap above.
fn bench_serve_config(cfg: &BenchConfig) -> ServeConfig {
    let mut config = ServeConfig::bench_default();
    config.checkpoint_interval = if cfg.no_fsync { 1_000_000 } else { 1 };
    if cfg.storage == StorageArg::Memory {
        config.storage = StorageArg::Memory;
        config.ephemeral_loss_ack = true;
        config.max_total_bytes = BENCH_MEMORY_CAP_BYTES;
    }
    config
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
    // the histogram stays empty and the report's fsync_measured flag is forced off.
    Ok(finish_report(
        cfg,
        produced,
        produced,
        &[],
        &[],
        elapsed,
        false,
    ))
}

/// PUBLISH mode: append at the bound/rate, measuring produce-side throughput and bytes/op. Latency
/// is not measured (no read-back), so the latency fields stay `None`.
fn run_publish(cfg: &BenchConfig, addr: &str) -> Result<BenchReport, CliError> {
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
    // --no-fsync batched the checkpoints.
    Ok(finish_report(
        cfg,
        produced,
        produced,
        &[],
        &fsync_samples,
        elapsed,
        cfg.fsync_is_measured(),
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
    let (recorded, latencies) = drain(cfg, addr, preload, started)?;
    Ok(finish_report(
        cfg,
        preload,
        recorded,
        &latencies,
        &[],
        drain_start.elapsed(),
        false,
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
    // when the durable path was exercised per produce, i.e. NOT in the --no-fsync dry run.
    Ok(finish_report(
        cfg,
        produced,
        recorded,
        &latencies,
        &fsync_samples,
        elapsed,
        cfg.fsync_is_measured(),
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
    let drain_started = Instant::now();
    loop {
        let fetched = fetch_batch(&mut consumer, addr, cfg.fetch_batch)?;
        let now = Instant::now();
        for m in &fetched.messages {
            if let Some(sent) = read_round_trip_time(&m.payload, produce_started) {
                // The read-back latency: time from the message's produce instant to its delivery.
                let latency_ns = u64::try_from(now.saturating_duration_since(sent).as_nanos())
                    .unwrap_or(u64::MAX);
                latencies.push(latency_ns);
            }
            // Per-message ack: the synthetic group is a COMPETING work-queue, where each lease is
            // acked individually (cumulative ack is a broadcast-only primitive). This is the real
            // work-queue consume path; its drain throughput is therefore ack-RPC-bound, which the
            // corpus notes when comparing to peers whose clients batch their acks.
            ack_one(&mut consumer, addr, m.offset, m.generation)?;
            recorded += 1;
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

/// Assembles a [`BenchReport`] from the run tallies, the end-to-end LATENCY samples (read-back, in
/// the latency modes), and the per-produce-call samples (`fsync_samples`). The reported fsync cost
/// is the MEDIAN produce-call latency, not the round-trip p50: a `Pub` returns its `PubAck` only
/// after the covering group-commit `fdatasync` (invariant I2), so the produce-call median isolates
/// the durable-write cost from the queue-wait that inflates round-trip latency. It is reported only
/// when `fsync_measured` (not in the `--no-fsync` dry run, which batches cursor checkpoints).
fn finish_report(
    cfg: &BenchConfig,
    produced: u64,
    recorded: u64,
    latencies: &[u64],
    fsync_samples: &[u64],
    elapsed: Duration,
    fsync_measured: bool,
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
        fsync_measured,
        ..BenchReport::default()
    };
    if let Some((p50, p99, p999, max)) = percentiles_us(latencies) {
        report.p50_us = Some(p50);
        report.p99_us = Some(p99);
        report.p999_us = Some(p999);
        report.max_us = Some(max);
    }
    // The honest per-op fsync cost: the median produce-call latency, which an ack-after-fsync broker
    // (I2) cannot return before the durable write completes. Reported only when measured through the
    // per-produce durable path.
    if fsync_measured {
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

/// Fetches up to `credit` messages, mapping a client error to the frozen exit codes.
fn fetch_batch(
    client: &mut Client,
    addr: &str,
    credit: u32,
) -> Result<ironbus_client::Fetch, CliError> {
    client
        .fetch(credit)
        .map_err(|e| classify(addr, "fetching from", &e))
}

/// Acks one delivered message, mapping a client error to the frozen exit codes.
fn ack_one(client: &mut Client, addr: &str, offset: u64, generation: u64) -> Result<(), CliError> {
    client
        .ack(offset, generation)
        .map(|_| ())
        .map_err(|e| classify(addr, "acking to", &e))
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
