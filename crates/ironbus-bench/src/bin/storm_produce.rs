// SPDX-License-Identifier: MIT OR Apache-2.0
//! Many-streams fsync-storm durable produce driver (#1192 S1, epic #1196; gates #1193).
//!
//! The signature differentiation cell: N concurrent producers, EACH publishing to its OWN named
//! stream on one LIVE broker, every publish an awaited at-least-once ack (`Client::publish_to`,
//! ack-implies-durable, single in-flight per producer — the per-message storm shape). This is the
//! workload where external audit evidence (Vanlightly 2023) showed Redpanda's fsync handling
//! collapsing at many producers/small batches, AND the workload where IronBus's own ceiling audit
//! (#1193) predicts K dirty named streams cost K serial `fdatasync` barriers per commit tick (the
//! #1040 pipelined flusher covers only the default log). The point of the cell is the honest
//! baseline on both sides, whatever it says.
//!
//! Drives a LIVE broker (started by the harness scenario script, `storm2.sh`) over a real socket
//! through the real client — never a privileged path. Each producer thread opens its OWN TCP
//! connection with the stream-addressing capability, declares `storm.<i>` (idempotent), aligns on
//! a barrier, then runs its closed produce loop recording every produce-to-ack RTT. Aggregate
//! throughput is total messages over the WHOLE-PHASE wall time (first thread's start to the last
//! thread's end — the #1040 multi-producer convention). Per-producer p50/p99 come from each
//! thread's own samples via the same nearest-rank quantile the matched Kafka-side driver
//! (`StormProducers.java`) uses, so the two instruments are method-identical.
//!
//! Emits ONE JSON object on stdout (`schema: storm-produce-v1`). Off the per-PR CI path; run on
//! demand by the harness:
//!
//! ```text
//! cargo run --release -p ironbus-bench --bin storm-produce -- \
//!     --addr 127.0.0.1:7777 --producers 32 --count 2000 --payload-bytes 128
//! ```

use ironbus_client::{Client, ClientConfig};
use ironbus_proto::message::PubBody;
use std::process::ExitCode;
use std::sync::{Arc, Barrier};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Parsed command-line options.
struct Opts {
    /// The LIVE broker to drive (the harness starts it; this driver never spawns one).
    addr: String,
    /// How many producers = how many named streams (`storm.0` .. `storm.{n-1}`).
    producers: usize,
    /// Messages per producer (the closed loop's bound).
    count: u64,
    /// Payload bytes per message.
    payload_bytes: usize,
    /// The named-stream prefix (`storm.` by default).
    stream_prefix: String,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            addr: "127.0.0.1:7777".to_string(),
            producers: 8,
            count: 1000,
            payload_bytes: 128,
            stream_prefix: "storm.".to_string(),
        }
    }
}

fn parse_args() -> Result<Opts, String> {
    let mut opts = Opts::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag `{}` needs a value", args[*i - 1]))
        };
        match args[i].as_str() {
            "--addr" => opts.addr = take(&mut i)?,
            "--producers" => {
                opts.producers = take(&mut i)?
                    .parse()
                    .map_err(|e| format!("--producers: {e}"))?;
            }
            "--count" => {
                opts.count = take(&mut i)?.parse().map_err(|e| format!("--count: {e}"))?;
            }
            "--payload-bytes" => {
                opts.payload_bytes = take(&mut i)?
                    .parse()
                    .map_err(|e| format!("--payload-bytes: {e}"))?;
            }
            "--stream-prefix" => opts.stream_prefix = take(&mut i)?,
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    if opts.producers == 0 || opts.count == 0 {
        return Err("--producers and --count must be at least 1".to_string());
    }
    Ok(opts)
}

/// Fills `payload` with the SAME compressible record-like ASCII pattern `ironbus bench
/// --payload-shape realistic` generates (`fill_payload` in the CLI crate, not a dependency of this
/// crate — the pattern is replicated so the storm cell's bytes match the matched-matrix rows).
fn fill_realistic(payload: &mut [u8]) {
    const PATTERN: &[u8] = b"ts=000000 sensor=edge temp=21.5 occ=1 batt=98 rssi=-67; ";
    for (i, b) in payload.iter_mut().enumerate() {
        *b = PATTERN[i % PATTERN.len()];
    }
}

/// Nearest-rank quantile over an ALREADY-SORTED ascending sample slice, in the sample's unit.
/// The same method as `StormProducers.java` (the Redpanda-side matched driver) so per-producer
/// percentiles are instrument-identical across brokers. Returns 0 for an empty slice (callers
/// never pass one; the produce loop records `count >= 1` samples).
fn nearest_rank(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // ceil(p*n)-1 clamped: the textbook nearest-rank index. n is a sample count (bounded by the
    // run's --count), far below 2^52, so the f64 round-trip is exact.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

/// One producer thread's result: its wall window (offsets from the shared epoch) and its sorted
/// ack-RTT samples in nanoseconds.
// The shared `_ns` postfix is the point: every field is a nanosecond quantity and the unit lives
// in the name (the same convention the harness's `*_us` JSON fields use).
#[allow(clippy::struct_field_names)]
struct ProducerResult {
    start_ns: u64,
    end_ns: u64,
    sorted_rtts_ns: Vec<u64>,
}

/// Runs one producer's closed loop: connect, declare `storm.<idx>`, wait the barrier, publish
/// `count` awaited messages recording each RTT.
fn run_producer(
    idx: usize,
    opts: &Opts,
    epoch: Instant,
    barrier: &Barrier,
) -> Result<ProducerResult, String> {
    let stream = format!("{}{idx}", opts.stream_prefix);
    let config = ClientConfig {
        understands_streams: true,
        ..ClientConfig::default()
    };
    let mut client = Client::connect_with(&opts.addr, &config)
        .map_err(|e| format!("producer {idx}: connect {}: {e}", opts.addr))?;
    if !client.streams_enabled() {
        return Err(format!(
            "producer {idx}: broker did not confirm stream addressing"
        ));
    }
    client
        .declare_stream(&stream)
        .map_err(|e| format!("producer {idx}: declare_stream({stream}): {e}"))?;

    let mut payload = vec![0u8; opts.payload_bytes];
    fill_realistic(&mut payload);
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let mut rtts_ns = Vec::with_capacity(usize::try_from(opts.count).unwrap_or(0));

    barrier.wait();
    let start_ns = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
    for _ in 0..opts.count {
        let body = PubBody {
            flags: 0,
            timestamp_ms,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: &payload,
        };
        let t0 = Instant::now();
        client
            .publish_to(&stream, &body)
            .map_err(|e| format!("producer {idx}: publish_to({stream}): {e}"))?;
        rtts_ns.push(u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    let end_ns = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
    rtts_ns.sort_unstable();
    Ok(ProducerResult {
        start_ns,
        end_ns,
        sorted_rtts_ns: rtts_ns,
    })
}

/// ns -> us with 0.01 us resolution, for the JSON output.
#[allow(clippy::cast_precision_loss)] // RTTs are far below 2^52 ns (52-bit-exact)
fn ns_to_us(ns: u64) -> f64 {
    (ns as f64 / 10.0).round() / 100.0
}

/// Median of an UNSORTED f64 slice (per-producer percentile summaries; small N).
fn median_f64(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    if values.is_empty() {
        return 0.0;
    }
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    }
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("storm-produce: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let opts = Arc::new(opts);
    let barrier = Arc::new(Barrier::new(opts.producers));
    let epoch = Instant::now();
    let mut handles = Vec::with_capacity(opts.producers);
    for idx in 0..opts.producers {
        let opts = Arc::clone(&opts);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            run_producer(idx, &opts, epoch, &barrier)
        }));
    }

    let mut results = Vec::with_capacity(opts.producers);
    for (idx, handle) in handles.into_iter().enumerate() {
        match handle.join() {
            Ok(Ok(r)) => results.push(r),
            Ok(Err(msg)) => {
                eprintln!("storm-produce: {msg}");
                return ExitCode::FAILURE;
            }
            Err(_) => {
                eprintln!("storm-produce: producer thread {idx} panicked");
                return ExitCode::FAILURE;
            }
        }
    }

    // Whole-phase wall: first thread's post-barrier start to the last thread's end (#1040).
    let wall_start = results.iter().map(|r| r.start_ns).min().unwrap_or(0);
    let wall_end = results.iter().map(|r| r.end_ns).max().unwrap_or(0);
    let wall_ns = wall_end.saturating_sub(wall_start).max(1);
    let total_msgs = opts.count.saturating_mul(opts.producers as u64);
    #[allow(clippy::cast_precision_loss)] // counts/ns far below 2^52
    let msgs_per_sec = total_msgs as f64 / (wall_ns as f64 / 1e9);

    // Pooled percentiles (all samples merged) + per-producer summaries.
    let mut pooled: Vec<u64> = results
        .iter()
        .flat_map(|r| r.sorted_rtts_ns.iter().copied())
        .collect();
    pooled.sort_unstable();
    let mut per_p50: Vec<f64> = Vec::with_capacity(results.len());
    let mut per_p99: Vec<f64> = Vec::with_capacity(results.len());
    let per_producer: Vec<serde_json::Value> = results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let p50 = ns_to_us(nearest_rank(&r.sorted_rtts_ns, 0.50));
            let p99 = ns_to_us(nearest_rank(&r.sorted_rtts_ns, 0.99));
            per_p50.push(p50);
            per_p99.push(p99);
            serde_json::json!({
                "stream": format!("{}{i}", opts.stream_prefix),
                "msgs": r.sorted_rtts_ns.len(),
                "p50_us": p50,
                "p99_us": p99,
            })
        })
        .collect();

    #[allow(clippy::cast_precision_loss)] // wall_ns far below 2^52
    let out = serde_json::json!({
        "schema": "storm-produce-v1",
        "producers": opts.producers,
        "streams": opts.producers,
        "count_per_producer": opts.count,
        "total_messages": total_msgs,
        "payload_bytes": opts.payload_bytes,
        "wall_s": (wall_ns as f64 / 1e9 * 1000.0).round() / 1000.0,
        "msgs_per_sec": (msgs_per_sec * 10.0).round() / 10.0,
        "ack_p50_us_pooled": ns_to_us(nearest_rank(&pooled, 0.50)),
        "ack_p99_us_pooled": ns_to_us(nearest_rank(&pooled, 0.99)),
        "ack_p999_us_pooled": ns_to_us(nearest_rank(&pooled, 0.999)),
        "per_producer_p50_us_median": median_f64(&mut per_p50),
        "per_producer_p99_us_median": median_f64(&mut per_p99),
        "per_producer": per_producer,
    });
    match serde_json::to_string(&out) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("storm-produce: JSON encode failed: {e}");
            ExitCode::FAILURE
        }
    }
}
