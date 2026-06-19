// SPDX-License-Identifier: MIT OR Apache-2.0
//! Single-consumer streaming-consume throughput: the BATCHED + read-ahead default vs the
//! per-message-fetch + per-message-commit path (#550, V2-M1).
//!
//! The first-principles claim behind [M1-I10] is that one fetch round-trip plus one cursor write per
//! RECORD is the dominant per-message cost of durable consume, and that amortizing the fetch and the
//! commit across a BATCH (plus hiding the next fetch's round-trip behind processing via bounded
//! read-ahead) is the ergonomic win that lets a single durable consumer keep up. This bench MEASURES
//! that delta over the SAME data on the SAME in-process broker the binary ships:
//!
//!   - BASELINE: the per-record streaming path — `stream_fetch(off, 1, ..)` for one record, then
//!     `stream_commit(off+1)` per record (one round-trip + one commit each). This is the self-handicap
//!     the issue calls out.
//!   - DEFAULT: the batched `StreamingConsumer` — fetch a window, periodic cumulative commit, bounded
//!     read-ahead ON (the #550 ergonomic default).
//!
//! Both drain the identical durable prefix through the REAL client over a real loopback socket; the
//! reported delta is the throughput multiple. This is the consume-side setup for the #554 NATS
//! comparison; it is NOT that comparison, and it is OFF the per-PR CI path (run on demand):
//!   cargo run -p ironbus-bench --bin stream-consume-bench --release -- --records 50000 --window 256
//!
//! It ALSO reports the #552 leg: the OLD fixed-64 per-consumer credit window vs the AUTO-TUNED window,
//! over the SAME data and loopback link, with a client window far above 64 so the SERVER credit window
//! binds. At the fixed 64 each fetch is capped at 64 records (the 64/RTT loopback floor #464/#532
//! found); with the auto-tune the per-consumer window grows from 64 toward the ceiling, so the
//! steady-state per-fetch size climbs and the floor lifts. The reported `floor lift` is that multiple.

// The in-process broker (`ironbus_bench::inproc`) is Unix-only, matching the shipped broker, so the
// whole bench body is `cfg(unix)`. On a non-Unix target the binary compiles to a no-op `main` that
// explains the platform requirement, so the crate still builds everywhere.

#[cfg(unix)]
use ironbus_bench::inproc::InProcBroker;
#[cfg(unix)]
use ironbus_client::{Client, ClientConfig, StreamConsumerConfig};
#[cfg(unix)]
use ironbus_proto::message::{ConsumeTier, PubBody};
use std::process::ExitCode;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
/// The streaming `ClientConfig`: advertises Tier-S + `DeliverBatch` and a streaming connection default,
/// so a SUB marks its group streaming server-side (the wiring the batched default rides on).
fn streaming_config() -> ClientConfig {
    ClientConfig {
        understands_streaming: true,
        default_consume_tier: Some(ConsumeTier::Streaming),
        understands_deliver_batch: true,
        ..ClientConfig::default()
    }
}

#[cfg(unix)]
/// Drains `records` via the batched streaming consumer with a LARGE client window (so the SERVER-side
/// per-consumer credit window — fixed 64 vs auto-tuned — is the binding constraint, not the client's
/// own batch cap). Returns the wall-clock elapsed. This is the #552 measurement: at a fixed 64 server
/// credit each fetch is capped at 64 records (64/RTT loopback floor); with the auto-tune the window
/// grows from 64 toward the ceiling, so the steady-state per-fetch size climbs and the floor lifts.
fn drain_streaming_window(
    addr: &str,
    records: u64,
    client_window: u32,
) -> Result<Duration, String> {
    let mut c = Client::connect_with(addr, &streaming_config())
        .map_err(|e| format!("window consumer connect: {e}"))?;
    c.subscribe("s").map_err(|e| format!("window sub: {e}"))?;
    let cfg = StreamConsumerConfig {
        // A client window far above 64, so the SERVER credit window is what bounds each fetch: at the
        // old fixed 64 the server caps every fetch at 64; with the auto-tune it grows past 64.
        max_records: client_window,
        max_bytes: 0,
        commit_every_batches: 8,
        start_offset: 0,
        read_ahead: true,
    };
    let start = Instant::now();
    let mut consumer = c.streaming_consumer_with("s", &cfg);
    let mut drained = 0u64;
    loop {
        let batch = consumer
            .next_batch()
            .map_err(|e| format!("window next_batch: {e}"))?;
        if batch.is_empty() {
            break;
        }
        drained += batch.messages.len() as u64;
        if drained >= records {
            break;
        }
    }
    consumer
        .finish()
        .map_err(|e| format!("window finish: {e}"))?;
    Ok(start.elapsed())
}

#[cfg(unix)]
/// Produces `records` payloads of `payload_bytes` each onto the default group, so both consume paths
/// read the SAME durable prefix.
fn seed(addr: &str, records: u64, payload_bytes: usize) -> Result<(), String> {
    let mut p = Client::connect(addr).map_err(|e| format!("producer connect: {e}"))?;
    let payload = vec![0xABu8; payload_bytes];
    // A pipelined producer so seeding a large prefix is not floored at one fsync per publish.
    let mut producer = p.pipelined_producer();
    for _ in 0..records {
        producer
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: &payload,
            })
            .map_err(|e| format!("seed produce: {e}"))?;
    }
    producer.finish().map_err(|e| format!("seed flush: {e}"))?;
    Ok(())
}

#[cfg(unix)]
/// Drains `records` via the PER-RECORD streaming path: one `stream_fetch` of a single record, then one
/// `stream_commit` per record. Returns the wall-clock elapsed. This is the self-handicapped baseline.
fn drain_per_record(addr: &str, records: u64) -> Result<Duration, String> {
    let mut c = Client::connect_with(addr, &streaming_config())
        .map_err(|e| format!("per-record consumer connect: {e}"))?;
    c.subscribe("s")
        .map_err(|e| format!("per-record sub: {e}"))?;
    let start = Instant::now();
    let mut offset = 0u64;
    let mut drained = 0u64;
    while drained < records {
        let batch = c
            .stream_fetch(offset, 1, 0)
            .map_err(|e| format!("per-record fetch: {e}"))?;
        if batch.messages.is_empty() {
            break;
        }
        for m in &batch.messages {
            // The work the caller would do per message is out of scope; we measure the fetch+commit
            // overhead the two paths differ in, so the per-record path commits after EACH record.
            offset = m.offset + 1;
            c.stream_commit("s", offset)
                .map_err(|e| format!("per-record commit: {e}"))?;
            drained += 1;
        }
    }
    Ok(start.elapsed())
}

#[cfg(unix)]
/// Drains `records` via the BATCHED + read-ahead `StreamingConsumer` default (#550): fetch a window,
/// periodic cumulative commit, bounded read-ahead ON. Returns the wall-clock elapsed.
fn drain_batched(
    addr: &str,
    records: u64,
    window: u32,
    commit_every: u32,
) -> Result<Duration, String> {
    let mut c = Client::connect_with(addr, &streaming_config())
        .map_err(|e| format!("batched consumer connect: {e}"))?;
    c.subscribe("s").map_err(|e| format!("batched sub: {e}"))?;
    let cfg = StreamConsumerConfig {
        max_records: window,
        max_bytes: 0,
        commit_every_batches: commit_every,
        start_offset: 0,
        read_ahead: true,
    };
    let start = Instant::now();
    let mut consumer = c.streaming_consumer_with("s", &cfg);
    let mut drained = 0u64;
    loop {
        let batch = consumer
            .next_batch()
            .map_err(|e| format!("batched next_batch: {e}"))?;
        if batch.is_empty() {
            break;
        }
        drained += batch.messages.len() as u64;
        if drained >= records {
            break;
        }
    }
    consumer
        .finish()
        .map_err(|e| format!("batched finish: {e}"))?;
    Ok(start.elapsed())
}

#[cfg(unix)]
#[allow(clippy::cast_precision_loss)]
fn throughput(records: u64, elapsed: Duration) -> f64 {
    records as f64 / elapsed.as_secs_f64()
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    // Minimal arg parsing (no clap in this crate): --records N --window N --commit-every N --payload N.
    let mut records: u64 = 20_000;
    let mut window: u32 = 256;
    let mut commit_every: u32 = 8;
    let mut payload: usize = 64;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut val = || {
            args.next()
                .ok_or_else(|| format!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            "--records" => records = val()?.parse().map_err(|e| format!("--records: {e}"))?,
            "--window" => window = val()?.parse().map_err(|e| format!("--window: {e}"))?,
            "--commit-every" => {
                commit_every = val()?.parse().map_err(|e| format!("--commit-every: {e}"))?;
            }
            "--payload" => payload = val()?.parse().map_err(|e| format!("--payload: {e}"))?,
            other => return Err(format!("unknown flag {other}")),
        }
    }

    let broker = InProcBroker::start()?;
    let addr = broker.addr().to_string();
    seed(&addr, records, payload)?;

    // Per-record baseline first (the self-handicap), then the batched default. Each drains the SAME
    // prefix from offset 0 over its OWN connection / streaming cursor, so the two are apples-to-apples.
    let per_record = drain_per_record(&addr, records)?;
    let batched = drain_batched(&addr, records, window, commit_every)?;

    let pr_tput = throughput(records, per_record);
    let b_tput = throughput(records, batched);
    let speedup = b_tput / pr_tput;

    println!("stream-consume-bench (#550): single-consumer streaming throughput, same data");
    println!("  records={records} payload={payload}B window={window} commit_every={commit_every}");
    println!(
        "  per-message  (fetch 1 + commit each): {pr_tput:>12.0} msg/s  ({:.3}s)",
        per_record.as_secs_f64()
    );
    println!(
        "  batched + read-ahead default        : {b_tput:>12.0} msg/s  ({:.3}s)",
        batched.as_secs_f64()
    );
    println!("  speedup (batched / per-message)     : {speedup:>12.2}x");

    // #552 PROOF: the OLD fixed-64 credit window vs the AUTO-TUNED window, over the SAME data and a
    // real loopback link, with a client window far above 64 so the SERVER credit window is the binding
    // constraint. At the fixed 64 each fetch is capped at 64 records (the 64/RTT loopback floor the
    // #464/#532 bench found); with the auto-tune the per-consumer window grows from 64 toward the
    // ceiling, so the steady-state per-fetch size climbs and the floor lifts. The two brokers are
    // separate in-process instances so neither's credit state leaks into the other.
    let client_window: u32 = 1024; // far above 64, so the SERVER credit (64 vs auto-tune) binds
    let old_broker = InProcBroker::start_with_credit(64)?;
    let old_addr = old_broker.addr().to_string();
    seed(&old_addr, records, payload)?;
    let old_64 = drain_streaming_window(&old_addr, records, client_window)?;

    // The auto-tune ceiling (2048, the production default): the window grows from the 64 floor toward
    // this, so the per-fetch size climbs well past 64.
    let auto_broker = InProcBroker::start_with_credit(2048)?;
    let auto_addr = auto_broker.addr().to_string();
    seed(&auto_addr, records, payload)?;
    let auto = drain_streaming_window(&auto_addr, records, client_window)?;

    let old_tput = throughput(records, old_64);
    let auto_tput = throughput(records, auto);
    let floor_lift = auto_tput / old_tput;
    println!();
    println!(
        "  #552 credit flow-control: single-consumer streaming throughput, client window {client_window}"
    );
    println!(
        "  OLD fixed-64 credit window           : {old_tput:>12.0} msg/s  ({:.3}s)  [64/RTT floor]",
        old_64.as_secs_f64()
    );
    println!(
        "  AUTO-TUNED window (grows 64 -> ceil) : {auto_tput:>12.0} msg/s  ({:.3}s)",
        auto.as_secs_f64()
    );
    println!("  floor lift (auto-tune / fixed-64)    : {floor_lift:>12.2}x");
    Ok(())
}

#[cfg(unix)]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stream-consume-bench error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!(
        "stream-consume-bench requires a Unix target (the in-process broker is Unix-only, matching \
         the shipped broker)."
    );
    ExitCode::FAILURE
}
