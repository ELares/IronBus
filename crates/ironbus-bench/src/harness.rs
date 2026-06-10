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
    // An all-zeros payload (only the 16-byte token at the front varies). Since #430 wired the
    // write path, the spawned `serve` (no `--compression` override, see `broker.rs`) compresses
    // with the DEFAULT `lz4` codec, and all-zeros is the BEST-CASE compressible workload: the
    // throughput and write-amplification numbers this harness reports are therefore NOT
    // representative for incompressible (already-compressed or encrypted) payloads. Deliberately
    // unchanged, for run-to-run comparability; measure an incompressible workload with
    // `--compression none` or a realistic corpus instead.
    let mut payload = vec![0u8; payload_bytes];
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
}
