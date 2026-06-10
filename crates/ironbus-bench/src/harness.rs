// SPDX-License-Identifier: MIT OR Apache-2.0
//! The open-loop load generator and latency recorder: the coordinated-omission-free core.
//!
//! # Why open-loop, and why intended-send-time
//!
//! A CLOSED-loop generator (send a request, wait for its reply, then send the next) silently erases
//! the tail under overload: while the broker is stalled the generator simply waits, issues fewer
//! requests, and never records the latency the messages it DIDN'T send would have had. That is
//! coordinated omission, and it makes a wedged broker look fine. The parent SLO (#19) lives or dies
//! on the tail, so this harness is OPEN-loop: messages are scheduled at a constant target arrival
//! rate with Poisson (exponential) inter-arrival jitter, on a schedule fixed BEFORE the run.
//!
//! Each message's latency is measured from its INTENDED send time (the schedule), not from when the
//! sender actually got around to sending it (wrk2 style). The intended send time is embedded as a
//! token in the payload; the receiver reads it back and records `now - intended` against a single
//! monotonic-raw clock. So when the broker stalls and the sender backs up, the backlog of messages
//! that finally drain all carry their ORIGINAL (now-old) intended times, and the receiver records
//! the full stall in the tail. A stalled broker cannot hide.
//!
//! # Shape
//!
//! A dedicated SENDER thread drives one real #11 client, producing on schedule. A separate RECEIVER
//! thread drives a second real #11 client, fetching + acking continuously and recording each
//! message's end-to-end latency into an `HdrHistogram`. They are never coupled into a request/reply
//! loop. Both run against the SHIPPING `ironbus` binary over a real loopback socket.

use crate::clock::{now_nanos, Nanos};
use crate::probe::{dir_size_bytes, rss_bytes};
use hdrhistogram::Histogram;
use ironbus_client::{Client, ClientConfig};
use ironbus_proto::message::PubBody;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_distr::{Distribution, Exp};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The fixed-size token embedded at the front of every payload: the 8-byte intended-send-time
/// (monotonic-raw nanos, little-endian) then an 8-byte monotonically increasing sequence number.
/// The receiver reads these back to compute latency and to skip any payload it cannot trust.
const TOKEN_LEN: usize = 16;

/// The `HdrHistogram`'s lowest discernible value, 1 microsecond, in nanoseconds. Anything faster is
/// floored to this bucket; sub-microsecond resolution is not meaningful for an end-to-end network
/// round trip and would only inflate the histogram.
const HIST_LOW_NANOS: u64 = 1_000;

/// The `HdrHistogram`'s highest trackable value, 60 seconds, in nanoseconds. A latency above this is
/// saturated to the ceiling (and still counted), which is correct for a pathological stall: it lands
/// in the top bucket and lifts the tail, never silently dropped.
const HIST_HIGH_NANOS: u64 = 60_000_000_000;

/// Significant figures the `HdrHistogram` keeps (3 => ~0.1% bucket error), the issue's target.
const HIST_SIGFIG: u8 = 3;

/// The default deterministic RNG seed for the Poisson jitter, so a run is reproducible.
pub const DEFAULT_SEED: u64 = 0x1B05_C0FF_EE42_7711;

/// The entropy of the generated payload BODY (the bytes after the embedded token), #439.
///
/// The harness used to send ALL-ZEROS bodies. Since #430 wired the write path, the spawned broker
/// compresses with the shipped default `lz4`, and all-zeros is the PATHOLOGICAL BEST CASE for any
/// codec: every byte-budget and throughput number the harness recorded was best-case, not
/// representative. The default is now a compressible-but-realistic telemetry shape (the same shape
/// the `ironbus bench` CLI generates for `--payload-shape realistic`), with an incompressible
/// option for the codec's worst case. Both fills are deterministic, so runs stay reproducible.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PayloadEntropy {
    /// A repetitive, codec-friendly ASCII pattern resembling real structured edge telemetry (the
    /// DEFAULT). Compressible like real `key=value` sensor records, NOT degenerate like zeros.
    #[default]
    CompressibleRealistic,
    /// Deterministic pseudo-random bytes, re-seeded per message: incompressible, the codec's
    /// worst case (already-compressed or encrypted payloads). Opt-in.
    Incompressible,
}

impl PayloadEntropy {
    /// Parses the `--payload-entropy` value (the same vocabulary as the CLI bench's
    /// `--payload-shape`: `realistic` is the compressible default, `random` the incompressible
    /// probe).
    #[must_use]
    pub fn parse(value: &str) -> Option<PayloadEntropy> {
        match value {
            "realistic" | "real" => Some(PayloadEntropy::CompressibleRealistic),
            "random" | "noise" => Some(PayloadEntropy::Incompressible),
            _ => None,
        }
    }

    /// The stable string used in the provenance JSON and the reproduce command.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadEntropy::CompressibleRealistic => "realistic",
            PayloadEntropy::Incompressible => "random",
        }
    }
}

/// Configuration for one open-loop run.
#[derive(Clone, Debug)]
pub struct RunConfig {
    /// Target arrival rate, messages per second. The open-loop schedule is built to this rate; the
    /// broker's actual throughput may be lower under overload, which is exactly what the tail shows.
    pub target_rate_hz: f64,
    /// How long to generate load.
    pub duration: Duration,
    /// Total payload size in bytes (including the embedded token); floored to [`TOKEN_LEN`].
    pub payload_bytes: usize,
    /// The payload BODY entropy (#439): compressible-realistic by default, incompressible opt-in.
    pub payload_entropy: PayloadEntropy,
    /// How many messages the receiver requests per fetch (its credit window).
    pub fetch_batch: u32,
    /// Deterministic RNG seed for the Poisson jitter, so a run is reproducible.
    pub seed: u64,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            target_rate_hz: 5_000.0,
            duration: Duration::from_secs(5),
            payload_bytes: 256,
            payload_entropy: PayloadEntropy::default(),
            fetch_batch: 256,
            seed: DEFAULT_SEED,
        }
    }
}

/// An error running the harness.
#[derive(Debug)]
pub enum RunError {
    /// A client could not connect or a produce/fetch failed in a way the run cannot continue past.
    Client(String),
    /// The run config was invalid (a non-positive rate, a zero duration).
    BadConfig(&'static str),
    /// The `HdrHistogram` could not be constructed (the bounds are out of range).
    Histogram(String),
    /// A worker thread panicked (its join failed), which the run treats as fatal.
    WorkerPanicked,
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RunError::Client(e) => write!(f, "client error: {e}"),
            RunError::BadConfig(why) => write!(f, "bad run config: {why}"),
            RunError::Histogram(e) => write!(f, "histogram error: {e}"),
            RunError::WorkerPanicked => write!(f, "a harness worker thread panicked"),
        }
    }
}

impl std::error::Error for RunError {}

/// The latency percentiles a run reports, in microseconds (the SLO is stated in this unit).
#[derive(Clone, Copy, Debug)]
pub struct Percentiles {
    /// p50 (median) latency, microseconds.
    pub p50_us: f64,
    /// p99 latency, microseconds.
    pub p99_us: f64,
    /// p99.9 latency, microseconds.
    pub p999_us: f64,
    /// The single worst observed latency, microseconds (the max bucket).
    pub max_us: f64,
}

/// The full result of one open-loop run: throughput, the percentiles, the resource samples, and
/// the RAW `HdrHistogram` so the percentiles are recomputable and the run is mergeable with others.
#[derive(Clone)]
pub struct RunReport {
    /// The config the run executed.
    pub config: RunConfig,
    /// How many messages the receiver actually recorded end-to-end.
    pub recorded: u64,
    /// Achieved throughput, messages per second (recorded / wall-clock run seconds).
    pub msgs_per_sec: f64,
    /// Achieved throughput, megabytes per second (payload bytes delivered / run seconds).
    pub mb_per_sec: f64,
    /// The latency percentiles.
    pub percentiles: Percentiles,
    /// Steady-state RSS of the broker, bytes, the median of samples taken mid-run (`None` if the
    /// platform cannot read another process's RSS).
    pub steady_rss_bytes: Option<u64>,
    /// Total user payload bytes the sender PRODUCED (the denominator of write amplification).
    pub payload_bytes_produced: u64,
    /// On-disk bytes in the data dir at the end of the run (the numerator of write amplification).
    pub data_dir_bytes: u64,
    /// Write amplification: data-dir bytes per payload byte produced (`None` if nothing produced).
    pub write_amplification: Option<f64>,
    /// The RAW `HdrHistogram`, kept whole so percentiles recompute and runs merge across windows.
    pub histogram: Histogram<u64>,
}

impl RunReport {
    /// Whether the recorded sample is large enough to trust the high percentiles. A p99.9 needs at
    /// least ~1000 samples to be a real measured quantile rather than the single max.
    #[must_use]
    pub fn has_tail_resolution(&self) -> bool {
        self.recorded >= 1_000
    }
}

/// The receiver-side shared latency recorder. A `Mutex<Histogram>` is recorded into by the single
/// receiver thread; the `Arc` lets the run own it after the join. Recording is off the network hot
/// path's critical section (the lock is held only for the O(1) `record`), so it never throttles.
type SharedHist = Arc<Mutex<Histogram<u64>>>;

/// Runs one open-loop generation against the broker at `addr`, with `data_dir` for the resource
/// probes. Returns the full [`RunReport`] including the raw histogram.
///
/// `broker_pid` is the broker process id, sampled for steady-state RSS while the run is in flight.
///
/// # Errors
/// Returns a [`RunError`] on a bad config, a histogram construction failure, a fatal client error
/// in a worker, or a worker panic.
pub fn run_open_loop(
    addr: &str,
    data_dir: &Path,
    broker_pid: u32,
    config: &RunConfig,
) -> Result<RunReport, RunError> {
    if config.target_rate_hz <= 0.0 {
        return Err(RunError::BadConfig("target rate must be positive"));
    }
    if config.duration.is_zero() {
        return Err(RunError::BadConfig("duration must be non-zero"));
    }
    let payload_bytes = config.payload_bytes.max(TOKEN_LEN);

    let hist: SharedHist = Arc::new(Mutex::new(
        Histogram::new_with_bounds(HIST_LOW_NANOS, HIST_HIGH_NANOS, HIST_SIGFIG)
            .map_err(|e| RunError::Histogram(format!("{e:?}")))?,
    ));

    // The run is bounded by a stop flag plus the schedule: the sender stops emitting after the
    // duration, then the receiver drains the in-flight backlog and stops.
    let stop = Arc::new(AtomicBool::new(false));
    // The sender publishes the count it produced; the receiver knows when it has drained them all.
    let produced = Arc::new(AtomicU64::new(0));
    let sender_done = Arc::new(AtomicBool::new(false));

    // Build clients up front so a connect failure is reported before any thread starts.
    let cfg = ClientConfig::default();
    let mut sender =
        Client::connect_with(addr, &cfg).map_err(|e| RunError::Client(e.to_string()))?;
    let mut receiver =
        Client::connect_with(addr, &cfg).map_err(|e| RunError::Client(e.to_string()))?;

    let run_start = now_nanos();

    // --- The RESOURCE SAMPLER: median RSS over samples taken while the run is in flight. ---
    let rss_samples: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let sampler = std::thread::spawn({
        let stop = Arc::clone(&stop);
        let rss_samples = Arc::clone(&rss_samples);
        move || {
            while !stop.load(Ordering::Acquire) {
                if let Some(bytes) = rss_bytes(broker_pid) {
                    if let Ok(mut v) = rss_samples.lock() {
                        v.push(bytes);
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    });

    // --- The RECEIVER: fetch + ack continuously, record latency from the embedded intended time. ---
    let receiver_handle = std::thread::spawn({
        let hist = Arc::clone(&hist);
        let produced = Arc::clone(&produced);
        let sender_done = Arc::clone(&sender_done);
        let fetch_batch = config.fetch_batch;
        move || -> Result<u64, RunError> {
            receive_loop(&mut receiver, &hist, &produced, &sender_done, fetch_batch)
        }
    });

    // --- The SENDER: produce on the open-loop schedule, stamping each with its INTENDED time. ---
    // Run inline on this thread so the borrow of `sender` stays local and simple.
    let SendOutcome {
        sent,
        payload_produced,
        error: sender_err,
    } = send_loop(&mut sender, payload_bytes, run_start, config)?;

    // Tell the receiver how many were produced and that the sender is done, so it can stop once it
    // has drained the full backlog (which carries the old intended times under a stall).
    produced.store(sent, Ordering::Release);
    sender_done.store(true, Ordering::Release);

    // Join the receiver: it drains the in-flight backlog then stops. Then stop the sampler.
    let recorded = match receiver_handle.join() {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            stop.store(true, Ordering::Release);
            let _ = sampler.join();
            return Err(e);
        }
        Err(_) => {
            stop.store(true, Ordering::Release);
            let _ = sampler.join();
            return Err(RunError::WorkerPanicked);
        }
    };
    stop.store(true, Ordering::Release);
    sampler.join().map_err(|_| RunError::WorkerPanicked)?;

    if let Some(e) = sender_err {
        return Err(e);
    }

    let run_secs = nanos_to_secs(now_nanos().saturating_sub(run_start)).max(f64::MIN_POSITIVE);

    // Take the recorded histogram out of the Arc/Mutex for the report (the run owns it now).
    let histogram = Arc::try_unwrap(hist)
        .map_err(|_| RunError::WorkerPanicked)?
        .into_inner()
        .map_err(|_| RunError::WorkerPanicked)?;

    let percentiles = Percentiles {
        p50_us: nanos_to_us(histogram.value_at_quantile(0.50)),
        p99_us: nanos_to_us(histogram.value_at_quantile(0.99)),
        p999_us: nanos_to_us(histogram.value_at_quantile(0.999)),
        max_us: nanos_to_us(histogram.max()),
    };

    let steady_rss_bytes = rss_samples.lock().ok().and_then(|v| median(&v));

    let data_dir_bytes = dir_size_bytes(data_dir);
    let payload_bytes_produced = payload_produced;
    let write_amplification = (payload_bytes_produced > 0)
        .then(|| count_to_f64(data_dir_bytes) / count_to_f64(payload_bytes_produced));

    let payload_delivered = recorded.saturating_mul(payload_bytes as u64);
    let mb_per_sec = (count_to_f64(payload_delivered) / (1024.0 * 1024.0)) / run_secs;

    Ok(RunReport {
        config: config.clone(),
        recorded,
        msgs_per_sec: count_to_f64(recorded) / run_secs,
        mb_per_sec,
        percentiles,
        steady_rss_bytes,
        payload_bytes_produced,
        data_dir_bytes,
        write_amplification,
        histogram,
    })
}

/// The RECEIVER loop: fetch + ack continuously, recording each message's end-to-end latency from
/// its embedded INTENDED send time. Stops once the sender is done AND every produced message has
/// been drained, so a stall's drained backlog is fully recorded before the run ends.
fn receive_loop(
    receiver: &mut Client,
    hist: &SharedHist,
    produced: &AtomicU64,
    sender_done: &AtomicBool,
    fetch_batch: u32,
) -> Result<u64, RunError> {
    let mut recorded: u64 = 0;
    loop {
        let fetched = match receiver.fetch(fetch_batch) {
            Ok(f) => f,
            // The broker dropped the connection (a hard stall reset it, or it closed under load):
            // stop gracefully and report the samples already recorded rather than failing the run.
            Err(e) if is_connection_ended(&e) => break,
            Err(e) => return Err(RunError::Client(e.to_string())),
        };
        let now = now_nanos();
        for m in &fetched.messages {
            if let Some(intended) = read_token_time(&m.payload) {
                // Latency from the INTENDED send time, not the actual send: the wrk2
                // anti-coordinated-omission measurement. A clock that somehow read backward (it
                // should not) floors at zero rather than wrapping into a huge value. The value is
                // then clamped into the histogram's trackable range.
                let latency = now
                    .saturating_sub(intended)
                    .clamp(HIST_LOW_NANOS, HIST_HIGH_NANOS);
                if let Ok(mut h) = hist.lock() {
                    // record (not record_correct): the open-loop schedule already accounts for
                    // omission via the intended-time token, so a plain record of the true
                    // end-to-end latency is the honest value, with no synthetic backfill.
                    let _ = h.record(latency);
                }
                recorded += 1;
            }
            // Ack to advance the cursor and free credit, so delivery keeps flowing. A connection
            // ended here (the broker dropped us) ends the run gracefully with what we recorded.
            if let Err(e) = receiver.ack(m.offset, m.generation) {
                if is_connection_ended(&e) {
                    return Ok(recorded);
                }
                return Err(RunError::Client(e.to_string()));
            }
        }
        // An empty fetch while the sender is still running just means we are caught up; keep
        // polling. Stop only once the sender is done and everything it produced has been drained.
        if fetched.messages.is_empty() {
            if sender_done.load(Ordering::Acquire) && recorded >= produced.load(Ordering::Acquire) {
                break;
            }
            // Nothing to do this instant: a tiny yield avoids a busy spin on an idle socket.
            std::thread::sleep(Duration::from_micros(200));
        }
    }
    Ok(recorded)
}

/// What the sender produced.
struct SendOutcome {
    /// How many messages were accepted (the count the receiver must drain).
    sent: u64,
    /// Total user payload bytes produced (the write-amplification denominator).
    payload_produced: u64,
    /// A fatal client error that ended the loop early, if any.
    error: Option<RunError>,
}

/// The SENDER loop: produce on the open-loop schedule, stamping each payload with its INTENDED send
/// time. Exponential inter-arrivals at the target rate make a Poisson arrival process. If a prior
/// produce blocked (the broker stalled), the loop does NOT skip the missed schedule slots: it sends
/// them immediately, each still carrying its ORIGINAL intended time, so the backlog's latency lands
/// honestly in the tail. A non-fatal #10 capacity shed is tolerated (the overload workload); any
/// other error ends the loop and is returned.
fn send_loop(
    sender: &mut Client,
    payload_bytes: usize,
    run_start: Nanos,
    config: &RunConfig,
) -> Result<SendOutcome, RunError> {
    // The payload body is generated per the configured entropy (#439). The all-zeros body this
    // loop used to send was the pathological BEST CASE under the broker's lz4 codec (the spawned
    // `serve` is pinned to `--compression lz4`, the shipped default, see `broker.rs`), so every
    // recorded number was best-case rather than representative. The default body is now the
    // compressible-realistic telemetry shape; `Incompressible` re-fills per message for the
    // worst case. BASELINE CONTINUITY: this changes the default workload, so a recorded baseline
    // from before this change is not comparable with one after it; per the #439 review there are
    // NO archived baselines yet (the v0.1.0 baseline is still unrecorded), which is exactly why
    // the default is made honest NOW, before the first baseline freezes the old workload in.
    let mut payload = vec![0u8; payload_bytes];
    fill_payload_body(&mut payload, config.payload_entropy, 0);
    let mut rng = StdRng::seed_from_u64(config.seed);
    // The exponential's lambda is the rate (per second); its mean interval is 1/rate seconds.
    let exp =
        Exp::new(config.target_rate_hz).map_err(|_| RunError::BadConfig("rate not finite"))?;
    let run_deadline = run_start.saturating_add(nanos_from_duration(config.duration));
    let mut intended = run_start;
    let mut sent: u64 = 0;
    let mut payload_produced: u64 = 0;
    let mut error: Option<RunError> = None;

    while intended < run_deadline {
        let now = now_nanos();
        if intended > now {
            sleep_until(intended, now);
        }
        // An incompressible body is re-filled PER MESSAGE (seeded by the sequence number) so the
        // broker can never amortize repeated bytes across records; the realistic pattern is
        // seq-independent, already in the buffer from the one-time fill above.
        if config.payload_entropy == PayloadEntropy::Incompressible {
            fill_payload_body(&mut payload, PayloadEntropy::Incompressible, sent);
        }
        write_token(&mut payload, intended, sent);
        match sender.produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: &payload,
        }) {
            Ok(_) => {
                payload_produced = payload_produced.saturating_add(payload_bytes as u64);
                sent += 1;
            }
            Err(e) if is_shed(&e) => {
                // A non-fatal shed is part of the overload workload (the broker sheds, not OOMs):
                // keep pacing the schedule rather than aborting.
            }
            Err(e) if is_connection_ended(&e) => {
                // The broker dropped the connection (e.g. a hard stall that reset an in-flight
                // produce on thaw). End the send loop gracefully WITHOUT a fatal error: the receiver
                // still drains and records whatever was already produced, so the run reports the
                // measured tail instead of crashing. `error` stays None.
                break;
            }
            Err(e) => {
                error = Some(RunError::Client(e.to_string()));
                break;
            }
        }
        // Advance the schedule by one exponential interval (seconds -> nanos).
        let interval_secs = exp.sample(&mut rng);
        intended = intended.saturating_add(secs_to_nanos(interval_secs));
    }

    Ok(SendOutcome {
        sent,
        payload_produced,
        error,
    })
}

/// Fills the payload BODY (everything after the [`TOKEN_LEN`]-byte token, which the sender stamps
/// separately) with the chosen entropy (#439). MIRRORS the `ironbus bench` CLI's `fill_payload`
/// (`crates/ironbus-cli/src/bench.rs`) byte for byte, so the harness and the CLI bench measure the
/// SAME payload shapes; it cannot be imported because `ironbus-cli` ships only a binary target.
/// Both fills are deterministic for a given `seq`, so a run stays reproducible.
fn fill_payload_body(payload: &mut [u8], entropy: PayloadEntropy, seq: u64) {
    if payload.len() <= TOKEN_LEN {
        return;
    }
    let body = &mut payload[TOKEN_LEN..];
    match entropy {
        PayloadEntropy::CompressibleRealistic => {
            // A short, repeating ASCII record-like pattern: highly compressible, like the
            // structured key=value telemetry an edge sensor actually emits, but NOT the
            // degenerate all-zeros best case.
            const PATTERN: &[u8] = b"ts=000000 sensor=edge temp=21.5 occ=1 batt=98 rssi=-67; ";
            for (i, b) in body.iter_mut().enumerate() {
                *b = PATTERN[i % PATTERN.len()];
            }
        }
        PayloadEntropy::Incompressible => {
            // A tiny self-contained LCG (Numerical Recipes constants), seeded per message so the
            // fill is incompressible yet deterministic for a given seq.
            let mut state = seq.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            for b in body.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                // Keep the low 8 bits of a high-entropy word; the mask makes the narrowing
                // explicit and well-defined (not a truncating cast).
                *b = u8::try_from((state >> 33) & 0xff).unwrap_or(0);
            }
        }
    }
}

/// Writes the intended-send-time token (8-byte nanos LE, then 8-byte seq LE) into the front of
/// `payload`. The caller guarantees `payload.len() >= TOKEN_LEN`.
fn write_token(payload: &mut [u8], intended: Nanos, seq: u64) {
    payload[0..8].copy_from_slice(&intended.to_le_bytes());
    payload[8..16].copy_from_slice(&seq.to_le_bytes());
}

/// Reads the intended-send-time nanos back out of a delivered payload, or `None` if the payload is
/// too short to carry the token (so a stray message never poisons the histogram).
fn read_token_time(payload: &[u8]) -> Option<Nanos> {
    if payload.len() < TOKEN_LEN {
        return None;
    }
    let bytes = <[u8; 8]>::try_from(&payload[0..8]).ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Whether a client error is the deliberate, non-fatal #10 capacity shed ("at capacity"), which the
/// overload workload tolerates, versus a real transport or protocol failure, which is fatal.
fn is_shed(err: &ironbus_client::ClientError) -> bool {
    matches!(err, ironbus_client::ClientError::Server(m) if m.contains("at capacity"))
}

/// Whether a client error means the broker connection simply ENDED (reset, aborted, broken pipe,
/// truncated read, or closed), as opposed to a protocol or config fault. A load generator that is
/// dropped by the broker under load, or during the #111 injected-stall self-test (which SIGSTOPs the
/// broker mid-run, so an in-flight op can be reset on thaw), should report the samples it ALREADY
/// measured rather than crash: the loops treat a connection-ended error as a graceful early end of
/// the run, keeping the recorded tail (which already holds the stall's drained backlog).
fn is_connection_ended(err: &ironbus_client::ClientError) -> bool {
    match err {
        ironbus_client::ClientError::Closed => true,
        ironbus_client::ClientError::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

/// Sleeps until the monotonic-raw instant `target`, given the current reading `now < target`. Uses
/// a single `Duration` sleep (the OS timer resolution bounds the precision; for a sub-millisecond
/// pace the residual jitter is absorbed by the open-loop intended-time accounting, not lost).
fn sleep_until(target: Nanos, now: Nanos) {
    let remaining = target.saturating_sub(now);
    if remaining > 0 {
        std::thread::sleep(Duration::from_nanos(remaining));
    }
}

/// Converts a `Duration` to monotonic-raw nanos (saturating, so an absurd duration cannot wrap).
fn nanos_from_duration(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Converts a floating-point seconds interval to nanos, clamped to non-negative and finite. An
/// absurd interval saturates at `u64::MAX` rather than wrapping; a non-finite or negative one is 0.
fn secs_to_nanos(secs: f64) -> u64 {
    if secs.is_finite() && secs > 0.0 {
        let nanos = secs * 1e9;
        // Cap below 2^64 before the cast so the conversion never produces an unspecified value.
        if nanos >= u64_max_as_f64() {
            u64::MAX
        } else {
            // The value is finite, non-negative, and below u64::MAX, so the truncating cast is well
            // defined and the fractional nanosecond it drops is below the clock resolution.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                nanos as u64
            }
        }
    } else {
        0
    }
}

/// `u64::MAX` as the nearest `f64`, the saturation threshold for [`secs_to_nanos`].
fn u64_max_as_f64() -> f64 {
    // 2^64 exactly; any f64 at or above this would not fit a u64.
    18_446_744_073_709_551_616.0
}

/// Nanos to seconds as f64. The precision loss above 2^52 ns (~52 days) is irrelevant for a bench
/// run and only affects the least-significant digits of a reported rate.
#[allow(clippy::cast_precision_loss)]
fn nanos_to_secs(nanos: u64) -> f64 {
    nanos as f64 / 1e9
}

/// Nanos to microseconds as f64. The precision loss is below the histogram's bucket error for any
/// latency the harness reports.
#[allow(clippy::cast_precision_loss)]
fn nanos_to_us(nanos: u64) -> f64 {
    nanos as f64 / 1e3
}

/// A `u64` byte/count to `f64` for a ratio or rate, where the sub-ULP precision loss above 2^52 is
/// immaterial to the reported figure.
#[allow(clippy::cast_precision_loss)]
fn count_to_f64(n: u64) -> f64 {
    n as f64
}

/// The median of a sample set, or `None` if empty. Sorts a copy (samples are small, one per 20 ms).
fn median(samples: &[u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    Some(v[v.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_round_trips() {
        let mut payload = vec![0u8; 256];
        write_token(&mut payload, 123_456_789, 42);
        assert_eq!(read_token_time(&payload), Some(123_456_789));
    }

    #[test]
    fn the_token_survives_every_entropy_fill() {
        // The fill writes ONLY the body, so a token stamped before or after a fill is intact.
        for entropy in [
            PayloadEntropy::CompressibleRealistic,
            PayloadEntropy::Incompressible,
        ] {
            let mut payload = vec![0u8; 256];
            write_token(&mut payload, 123_456_789, 42);
            fill_payload_body(&mut payload, entropy, 42);
            assert_eq!(read_token_time(&payload), Some(123_456_789));
        }
    }

    #[test]
    fn the_default_body_is_compressible_realistic_and_not_zeros() {
        // The #439 fix has teeth: the DEFAULT body is the realistic pattern, which has few
        // distinct byte values per window (compressible) but is NOT the all-zeros degenerate
        // best case the harness used to send.
        assert_eq!(
            PayloadEntropy::default(),
            PayloadEntropy::CompressibleRealistic
        );
        let mut payload = vec![0u8; 256];
        fill_payload_body(&mut payload, PayloadEntropy::default(), 0);
        let body = &payload[TOKEN_LEN..];
        assert!(
            body.iter().any(|&b| b != 0),
            "the default body must not be all zeros"
        );
        let distinct_real = distinct_bytes(body);
        let mut rand_payload = vec![0u8; 256];
        fill_payload_body(&mut rand_payload, PayloadEntropy::Incompressible, 1);
        let distinct_rand = distinct_bytes(&rand_payload[TOKEN_LEN..]);
        assert!(
            distinct_real < distinct_rand,
            "realistic ({distinct_real}) must use fewer distinct bytes than random ({distinct_rand})"
        );
    }

    #[test]
    fn the_incompressible_fill_is_deterministic_per_seq_and_differs_across_seqs() {
        // Reproducibility: the same seq always yields the same bytes; different seqs differ, so
        // the broker can never amortize repeated bodies across records.
        let mut a = vec![0u8; 256];
        let mut b = vec![0u8; 256];
        let mut c = vec![0u8; 256];
        fill_payload_body(&mut a, PayloadEntropy::Incompressible, 7);
        fill_payload_body(&mut b, PayloadEntropy::Incompressible, 7);
        fill_payload_body(&mut c, PayloadEntropy::Incompressible, 8);
        assert_eq!(a, b, "same seq => same fill");
        assert_ne!(a, c, "different seq => different fill");
    }

    #[test]
    fn payload_entropy_parses_the_cli_vocabulary() {
        assert_eq!(
            PayloadEntropy::parse("realistic"),
            Some(PayloadEntropy::CompressibleRealistic)
        );
        assert_eq!(
            PayloadEntropy::parse("random"),
            Some(PayloadEntropy::Incompressible)
        );
        assert_eq!(PayloadEntropy::parse("zeros"), None);
        assert_eq!(PayloadEntropy::CompressibleRealistic.as_str(), "realistic");
        assert_eq!(PayloadEntropy::Incompressible.as_str(), "random");
    }

    /// Counts distinct byte values, the same compressibility proxy the CLI bench's tests use.
    fn distinct_bytes(bytes: &[u8]) -> usize {
        let mut seen = [false; 256];
        for &b in bytes {
            seen[b as usize] = true;
        }
        seen.iter().filter(|&&s| s).count()
    }

    #[test]
    fn a_short_payload_has_no_token() {
        assert_eq!(read_token_time(&[0u8; 4]), None);
    }

    #[test]
    fn median_of_an_even_set_picks_the_upper_middle() {
        assert_eq!(median(&[10, 20, 30, 40]), Some(30));
        assert_eq!(median(&[5]), Some(5));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn a_capacity_error_is_recognized_as_a_shed() {
        assert!(is_shed(&ironbus_client::ClientError::Server(
            "produce failed: at capacity".into()
        )));
        assert!(!is_shed(&ironbus_client::ClientError::Server(
            "some other error".into()
        )));
        assert!(!is_shed(&ironbus_client::ClientError::Closed));
    }

    // GOLDEN VECTORS shared verbatim with the twin generator's test (the same arrays appear in
    // crates/ironbus-cli/src/bench.rs): the two fills cannot import each other (ironbus-cli ships only a binary target),
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
    fn the_fill_matches_the_cli_bench_twin_golden_vectors() {
        let mut p = vec![0u8; TOKEN_LEN + 48];
        fill_payload_body(&mut p, PayloadEntropy::CompressibleRealistic, 7);
        assert_eq!(
            p[TOKEN_LEN..],
            GOLDEN_REALISTIC_48,
            "realistic fill drifted from the twin"
        );
        let mut p = vec![0u8; TOKEN_LEN + 48];
        fill_payload_body(&mut p, PayloadEntropy::Incompressible, 7);
        assert_eq!(
            p[TOKEN_LEN..],
            GOLDEN_LCG_SEQ7_48,
            "incompressible fill drifted from the twin"
        );
    }
}
