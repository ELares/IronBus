// SPDX-License-Identifier: MIT OR Apache-2.0
//! A minimal HTTP health endpoint for an operator or an orchestrator probe.
//!
//! Three routes on a loopback HTTP port (#16): `GET /healthz` is liveness (this loop is
//! running, so the process is up) and `GET /readyz` is readiness (the broker's durable log
//! writer is live, an active segment is open, so it can still accept writes; a writer frozen
//! by a fatal fsync or a failed segment roll answers `503`). Everything else is `404`, and a
//! non-`GET` is `405`.
//! `/readyz` takes the engine lock, so its latency tracks an in-flight produce fsync (a slow
//! disk shows up as readiness latency, which is the intent). The parser reads only the bounded
//! request line, blocks with read and write timeouts plus a total deadline, and closes after
//! one response, so a slow or hostile client cannot wedge the loop. `GET /metrics` exposes a
//! few engine gauges (committed offset, durable head, consumer lag, in-flight, writer health)
//! in Prometheus text format, including the `ironbus_fsync_seconds` produce-fsync latency
//! histogram, and the per-reason recovery-loss series `ironbus_recovery_loss_bytes` (#16).
//!
//! `GET /admin` (#99) is an OPT-IN, READ-ONLY introspection endpoint: a structured JSON snapshot
//! of operational state (broker-level durable head and counters, per-work-group committed offset,
//! lag, and in-flight depth, the DLQ state, and an echo of the effective config bounds), derived
//! entirely from the engine's existing read-only accessors. It is OFF by default and enabled only
//! when the operator passes `serve --enable-admin`; when disabled it is `404`, exactly like an
//! unknown path. It is UNAUTHENTICATED, sharing `/metrics`'s trust model (loopback or a trusted
//! network, the #105/#107 threat model), so it must NEVER expose a mutating action or secret
//! material. Mutating admin actions (consumer reset, DLQ redrive, force-reap) are out of scope and
//! deferred to a separate mutating-admin surface; this endpoint is strictly GET-only and read-only.

use crate::actor::EngineAccess;
use crate::engine::{Counters, EngineConfigSnapshot, GroupConsumerStat};
use crate::metrics::{LatencyHistogram, FSYNC_BUCKET_LE_SECONDS};
use crate::registry::{FixedHistogram, REGISTRY_BUCKET_LE_SECONDS};
use ironbus_core::clock::Clock;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::loss::ReasonCode;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How long to wait between non-blocking accept polls.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Per-connection read/write timeout (slowloris defense).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// The request line is bounded; a client that sends no newline within this many bytes is
/// rejected rather than buffered without limit.
const MAX_REQUEST_LINE: usize = 8 * 1024;

/// Serves the health endpoints over `listener` until `shutdown` is set. Connections are
/// handled inline (health traffic is low and loopback), each bounded by [`REQUEST_TIMEOUT`].
///
/// `admin_enabled` gates the opt-in read-only `/admin` introspection endpoint (#99): `false`
/// (the default an operator gets unless they pass `--enable-admin`) makes `/admin` answer `404`
/// exactly like any unknown path, so the surface is OFF unless deliberately turned on.
///
/// # Errors
/// Returns an IO error only from configuring the listener; per-connection IO errors are
/// contained so one bad client never ends the loop.
pub fn serve_health<F, C, E>(
    listener: &TcpListener,
    engine: &E,
    shutdown: &AtomicBool,
    admin_enabled: bool,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
{
    listener.set_nonblocking(true)?;
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // One bad client must not end the loop; contain its IO error.
                let _ = handle(stream, engine, admin_enabled);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            // A transient accept failure must not tear the listener down.
            Err(_) => std::thread::sleep(ACCEPT_POLL),
        }
    }
    Ok(())
}

fn handle<F, C, E>(mut stream: TcpStream, engine: &E, admin_enabled: bool) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
{
    // The accepted socket inherits the listener's non-blocking flag; reads must block for the
    // timeouts to apply (the wire handler does the same), else a request split across TCP
    // segments is dropped and the timeouts are a no-op.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    // Bound the TOTAL time to read the request line, not only each read: a client dribbling one
    // byte just inside each per-read window would otherwise hold this connection (and, since
    // the accept loop is inline, every other probe) for hours.
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let mut buf = vec![0u8; MAX_REQUEST_LINE];
    let mut len = 0;
    let newline = loop {
        if len == buf.len() {
            return respond(&mut stream, 414, "URI Too Long", "request line too long");
        }
        if std::time::Instant::now() >= deadline {
            return respond(
                &mut stream,
                408,
                "Request Timeout",
                "request line not received in time",
            );
        }
        let n = stream.read(&mut buf[len..])?;
        if n == 0 {
            return Ok(()); // the client closed before sending a request line
        }
        len += n;
        if let Some(pos) = buf[..len].iter().position(|&b| b == b'\n') {
            break pos;
        }
    };

    // Parse "METHOD PATH VERSION" (a leading CR is trimmed by split_whitespace).
    let line = String::from_utf8_lossy(&buf[..newline]);
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("");
    if method != "GET" {
        return respond(
            &mut stream,
            405,
            "Method Not Allowed",
            "only GET is supported",
        );
    }
    // Drop any query string.
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    match path {
        "/healthz" => respond(&mut stream, 200, "OK", "ok"),
        "/readyz" => {
            // Read the writer-health flag through the actor (the single owner). If the actor is gone
            // (a shutdown drain), the broker is not ready: surface 503 rather than hang.
            match engine.with(|e| e.is_healthy()) {
                Ok(true) => respond(&mut stream, 200, "OK", "ready"),
                Ok(false) => respond(&mut stream, 503, "Service Unavailable", "writer frozen"),
                Err(_) => respond(&mut stream, 503, "Service Unavailable", "shutting down"),
            }
        }
        "/metrics" => {
            // Build the whole metrics snapshot in ONE actor job so every field is from the same
            // instant (the actor is the single reader/writer). A gone actor yields 503.
            let snapshot = engine.with(|g| MetricsSnapshot {
                committed: g.committed_offset().get(),
                flushed: g.flushed_offset().get(),
                in_flight: g.in_flight(),
                healthy: g.is_healthy(),
                recovered_truncated: g.recovered_truncated_bytes(),
                quarantined: g.quarantined_bytes(),
                recovery_loss: {
                    let r = g.loss_report();
                    ReasonCode::ALL.map(|rc| r.bytes_skipped_for(rc))
                },
                recovery_loss_records: {
                    let r = g.loss_report();
                    ReasonCode::ALL.map(|rc| r.records_lost_for(rc))
                },
                // -1 is the unambiguous "none yet" sentinel (offsets are never negative).
                last_dead_lettered: g
                    .last_dead_lettered_offset()
                    .map_or(-1i64, |o| i64::try_from(o.get()).unwrap_or(i64::MAX)),
                dlq_records: g.dlq_records(),
                counters: g.counters(),
                fsync: g.fsync_histogram(),
                groups: g.group_consumer_stats(),
                // The bounded metric registry (#97) is rendered into a String inside the actor job
                // (it walks only the bounded series set and the fixed histograms, so the work is
                // O(number of series), independent of the record count or disk size), then the body
                // is assembled outside with the rest. The uptime series reads the live monotonic
                // clock seam here so it advances between scrapes.
                registry: registry_body(g.registry(), g.now_monotonic()),
            });
            match snapshot {
                Ok(snapshot) => respond(&mut stream, 200, "OK", &metrics_body(snapshot)),
                Err(_) => respond(&mut stream, 503, "Service Unavailable", "shutting down"),
            }
        }
        // The opt-in read-only introspection endpoint (#99). When disabled it is indistinguishable
        // from an unknown path (a 404), so the surface is invisible unless the operator turned it
        // on. The non-GET case was already rejected with 405 above, so this is GET-only.
        "/admin" if admin_enabled => match admin_snapshot(engine) {
            Ok(snapshot) => respond_json(&mut stream, 200, "OK", &admin_body(&snapshot)),
            Err(_) => respond(&mut stream, 503, "Service Unavailable", "shutting down"),
        },
        _ => respond(&mut stream, 404, "Not Found", "unknown endpoint"),
    }
}

/// Captures the read-only introspection state (#99) in ONE actor job, so every field is from the
/// same instant. Every value comes from an existing read-only accessor; this cannot mutate the
/// engine and carries no secret material.
///
/// # Errors
/// Returns [`ActorGone`](crate::actor::ActorGone) if the actor exited before the read.
fn admin_snapshot<F, C, E>(engine: &E) -> Result<AdminSnapshot, crate::actor::ActorGone>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
{
    engine.with(|g| AdminSnapshot {
        healthy: g.is_healthy(),
        flushed: g.flushed_offset().get(),
        committed: g.committed_offset().get(),
        earliest_retained: g.earliest_retained_offset().get(),
        durable_record_bytes: g.durable_record_bytes(),
        durable_record_count: g.durable_record_count(),
        segment_count: g.segment_count(),
        recovered_truncated_bytes: g.recovered_truncated_bytes(),
        // -1 is the unambiguous "none yet" sentinel (offsets are never negative), the same one
        // `/metrics` uses.
        last_dead_lettered: g
            .last_dead_lettered_offset()
            .map_or(-1i64, |o| i64::try_from(o.get()).unwrap_or(i64::MAX)),
        dlq_records: g.dlq_records(),
        counters: g.counters(),
        groups: g.group_consumer_stats(),
        config: g.config_snapshot(),
    })
}

/// A consistent snapshot of the metric inputs, read under one engine lock.
#[derive(Clone)]
struct MetricsSnapshot {
    committed: u64,
    flushed: u64,
    in_flight: usize,
    healthy: bool,
    recovered_truncated: u64,
    /// Bytes copied into the forensic quarantine store at the last recovery (#134).
    quarantined: u64,
    /// Bytes dropped at the last recovery, per [`ReasonCode`] in code order.
    recovery_loss: [u64; 5],
    /// Records dropped at the last recovery, per [`ReasonCode`] in code order.
    recovery_loss_records: [u64; 5],
    /// The most recent dead-letter offset, or -1 if none (the exposition sentinel).
    last_dead_lettered: i64,
    /// The number of records durably written to the DLQ sink (the dead-letter depth, #63).
    dlq_records: u64,
    counters: Counters,
    fsync: LatencyHistogram,
    /// Per-work-group consumer position, for the lag-by-cursor series (#15, #16).
    groups: Vec<GroupConsumerStat>,
    /// The pre-rendered bounded-metric-registry section (#97): the fixed-bucket fsync-duration and
    /// append-latency histograms, the capped per-consumer lag series, and the self-monitoring
    /// series. Rendered under the engine lock (it walks only the bounded series set), then spliced
    /// into the body.
    registry: String,
}

/// Renders the Prometheus text exposition body from an engine snapshot. Consumer lag is the
/// durable records produced but not yet committed (`flushed - committed`).
fn metrics_body(snapshot: MetricsSnapshot) -> String {
    let MetricsSnapshot {
        committed,
        flushed,
        in_flight,
        healthy,
        recovered_truncated,
        quarantined,
        recovery_loss,
        recovery_loss_records,
        last_dead_lettered,
        dlq_records,
        counters,
        fsync,
        groups,
        registry,
    } = snapshot;
    let lag = flushed.saturating_sub(committed);
    let mut body = format!(
        "# HELP ironbus_committed_offset The committed consumer cursor; every offset below it is acked.\n\
         # TYPE ironbus_committed_offset gauge\n\
         ironbus_committed_offset {committed}\n\
         # HELP ironbus_flushed_offset The durable log head; the offset of the next record to be written.\n\
         # TYPE ironbus_flushed_offset gauge\n\
         ironbus_flushed_offset {flushed}\n\
         # HELP ironbus_consumer_lag Durable records produced but not yet committed.\n\
         # TYPE ironbus_consumer_lag gauge\n\
         ironbus_consumer_lag {lag}\n\
         # HELP ironbus_in_flight Messages delivered (leased) but not yet acked.\n\
         # TYPE ironbus_in_flight gauge\n\
         ironbus_in_flight {in_flight}\n\
         # HELP ironbus_writer_healthy 1 if the durable log writer is live, 0 if frozen.\n\
         # TYPE ironbus_writer_healthy gauge\n\
         ironbus_writer_healthy {healthy_value}\n\
         # HELP ironbus_recovery_truncated_bytes Bytes dropped from a torn or unsynced tail at the last recovery (startup).\n\
         # TYPE ironbus_recovery_truncated_bytes gauge\n\
         ironbus_recovery_truncated_bytes {recovered_truncated}\n\
         # HELP ironbus_quarantine_bytes Corrupt bytes copied into the forensic quarantine store at the last recovery (capped, copy-not-move).\n\
         # TYPE ironbus_quarantine_bytes gauge\n\
         ironbus_quarantine_bytes {quarantined}\n\
         # HELP ironbus_last_dead_lettered_offset The log offset of the most recently dead-lettered message, or -1 if none.\n\
         # TYPE ironbus_last_dead_lettered_offset gauge\n\
         ironbus_last_dead_lettered_offset {last_dead_lettered}\n\
         # HELP ironbus_produced_total Messages appended by produce.\n\
         # TYPE ironbus_produced_total counter\n\
         ironbus_produced_total {produced}\n\
         # HELP ironbus_produced_bytes_total Logical message bytes appended by produce (key + headers + payload).\n\
         # TYPE ironbus_produced_bytes_total counter\n\
         ironbus_produced_bytes_total {produced_bytes}\n\
         # HELP ironbus_produce_rejected_total Produces rejected because the durable log was at its byte cap (the drop-new shed).\n\
         # TYPE ironbus_produce_rejected_total counter\n\
         ironbus_produce_rejected_total {produce_rejected}\n\
         # HELP ironbus_delivered_total Message deliveries handed out (a redelivery counts again).\n\
         # TYPE ironbus_delivered_total counter\n\
         ironbus_delivered_total {delivered}\n\
         # HELP ironbus_redelivered_total Deliveries that were a redelivery.\n\
         # TYPE ironbus_redelivered_total counter\n\
         ironbus_redelivered_total {redelivered}\n\
         # HELP ironbus_dead_lettered_total Messages dead-lettered past MaxDeliver.\n\
         # TYPE ironbus_dead_lettered_total counter\n\
         ironbus_dead_lettered_total {dead_lettered}\n\
         # HELP ironbus_dlq_records_total Records durably written to the dead-letter sink (the DLQ depth, survives restart).\n\
         # TYPE ironbus_dlq_records_total counter\n\
         ironbus_dlq_records_total {dlq_records}\n\
         # HELP ironbus_acks_total Commits via ack (a term commits through the same path).\n\
         # TYPE ironbus_acks_total counter\n\
         ironbus_acks_total {acks}\n\
         # HELP ironbus_segments_reaped_total Old sealed segments reclaimed by consumer-safe retention (size, age, or count).\n\
         # TYPE ironbus_segments_reaped_total counter\n\
         ironbus_segments_reaped_total {segments_reaped}\n\
         # HELP ironbus_segments_force_reaped_total Old sealed segments force-reaped by the disk-full drop-oldest policy (may drop a slow consumer's unconsumed records).\n\
         # TYPE ironbus_segments_force_reaped_total counter\n\
         ironbus_segments_force_reaped_total {segments_force_reaped}\n\
         # HELP ironbus_truncations_total Below-earliest truncation events served to a consumer because its records were force-reaped out from under it (the resilience skip signal).\n\
         # TYPE ironbus_truncations_total counter\n\
         ironbus_truncations_total {truncations}\n\
         # HELP ironbus_truncated_records_total Records skipped by below-earliest truncations (the record-count span of ironbus_truncations_total).\n\
         # TYPE ironbus_truncated_records_total counter\n\
         ironbus_truncated_records_total {truncated_records}\n",
        healthy_value = u8::from(healthy),
        produced = counters.produced,
        produced_bytes = counters.produced_bytes,
        produce_rejected = counters.produce_rejected,
        delivered = counters.delivered,
        redelivered = counters.redelivered,
        dead_lettered = counters.dead_lettered,
        acks = counters.acks,
        segments_reaped = counters.segments_reaped,
        segments_force_reaped = counters.segments_force_reaped,
        truncations = counters.truncations,
        truncated_records = counters.truncated_records,
    );
    body.push_str(&skip_loss_reconciliation_lines(&counters));
    body.push_str(&recovery_loss_lines(&recovery_loss));
    body.push_str(&recovery_loss_records_lines(&recovery_loss_records));
    body.push_str(&fsync_histogram_lines(&fsync));
    body.push_str(&group_consumer_lines(&groups, flushed));
    body.push_str(&registry);
    body
}

/// Renders the recovery-loss reconciliation surface (#307): the new `_total` repair counter
/// `ironbus_counter_checkpoint_repair_total` (incremented when a reconciliation on open raised a
/// recovery-loss value above its durable snapshot) plus the three reconciled gauges
/// `ironbus_records_skipped`, `ironbus_bytes_skipped`, and `ironbus_last_skip_offset`, each
/// reconciled across a restart to `max(snapshot, replay)` so it never resumes lower than before a
/// crash. Held in its own block (out of the main format above) so the repair counter's TYPE/HELP stay
/// contiguous and the renderer stays under the line cap.
fn skip_loss_reconciliation_lines(counters: &Counters) -> String {
    format!(
        "# HELP ironbus_counter_checkpoint_repair_total Reconciliations on open where checkpoint-plus-replay raised a recovery-loss counter above its durable snapshot (#307).\n\
         # TYPE ironbus_counter_checkpoint_repair_total counter\n\
         ironbus_counter_checkpoint_repair_total {repairs}\n\
         # HELP ironbus_records_skipped Records lost to recovery loss (the durable loss report total), reconciled across restart to max(snapshot, durable loss report) so it never resumes lower than before a crash (#307).\n\
         # TYPE ironbus_records_skipped gauge\n\
         ironbus_records_skipped {records_skipped}\n\
         # HELP ironbus_bytes_skipped Bytes lost to recovery loss, reconciled across restart to max(snapshot, durable loss report) so it never resumes lower than before a crash (#307).\n\
         # TYPE ironbus_bytes_skipped gauge\n\
         ironbus_bytes_skipped {bytes_skipped}\n\
         # HELP ironbus_last_skip_offset The highest log offset any skip/loss event reached, reconciled across restart to max(checkpoint, replay) (#307).\n\
         # TYPE ironbus_last_skip_offset gauge\n\
         ironbus_last_skip_offset {last_skip_offset}\n",
        repairs = counters.counter_checkpoint_repairs,
        records_skipped = counters.records_skipped,
        bytes_skipped = counters.bytes_skipped,
        last_skip_offset = counters.last_skip_offset,
    )
}

/// Renders the bounded metric registry section (#97): the fixed-bucket
/// `ironbus_fsync_duration_seconds` and `ironbus_append_duration_seconds` histograms, the capped
/// per-consumer `ironbus_consumer_lag_records{consumer}` series (plus the `__overflow__` fold and
/// `ironbus_consumer_labels_dropped_total`), and the self-monitoring series (`ironbus_build_info`,
/// `ironbus_start_time_seconds`, `ironbus_uptime_seconds`). It walks only the bounded series set and
/// the fixed histograms, so it is O(number of series), independent of the record count or disk size.
/// `now_monotonic` is the live clock-seam reading the uptime is derived from.
fn registry_body(registry: &crate::registry::MetricRegistry, now_monotonic: u64) -> String {
    let mut s = String::new();
    fixed_histogram_lines(
        &mut s,
        "ironbus_fsync_duration_seconds",
        "The fsync (durability barrier) latency on produce, over the fixed registry buckets.",
        registry.fsync_duration(),
    );
    fixed_histogram_lines(
        &mut s,
        "ironbus_append_duration_seconds",
        "The whole durable-append (append + fsync) latency on produce, over the fixed registry buckets.",
        registry.append_latency(),
    );
    consumer_lag_lines(&mut s, registry);
    self_monitoring_lines(&mut s, registry, now_monotonic);
    s
}

/// Renders one fixed-bucket [`FixedHistogram`] as a Prometheus histogram (`name`, cumulative `le`
/// buckets in seconds over [`REGISTRY_BUCKET_LE_SECONDS`], plus `+Inf`, `_sum`, and `_count`). The
/// sum is rendered in seconds with nanosecond precision without floating point.
fn fixed_histogram_lines(s: &mut String, name: &str, help: &str, h: &FixedHistogram) {
    let _ = writeln!(s, "# HELP {name} {help}");
    let _ = writeln!(s, "# TYPE {name} histogram");
    let cumulative = h.cumulative_buckets();
    for (le, count) in REGISTRY_BUCKET_LE_SECONDS.iter().zip(cumulative.iter()) {
        let _ = writeln!(s, "{name}_bucket{{le=\"{le}\"}} {count}");
    }
    let total = h.count();
    let nanos = h.sum_nanos();
    let _ = writeln!(s, "{name}_bucket{{le=\"+Inf\"}} {total}");
    let _ = writeln!(
        s,
        "{name}_sum {}.{:09}",
        nanos / 1_000_000_000,
        nanos % 1_000_000_000
    );
    let _ = writeln!(s, "{name}_count {total}");
}

/// Renders the capped per-consumer lag series `ironbus_consumer_lag_records{consumer=...}` (#97):
/// one gauge sample per distinct consumer, the `{consumer="__overflow__"}` fold for over-cap
/// consumers (only when a label has actually been dropped, so the line is absent on a healthy
/// broker), and the `ironbus_consumer_labels_dropped_total` counter. Lag is maintained
/// incrementally (`head - committed`) and never scanned on scrape.
fn consumer_lag_lines(s: &mut String, registry: &crate::registry::MetricRegistry) {
    let lag = registry.consumer_lag();
    s.push_str(
        "# HELP ironbus_consumer_lag_records Per-consumer durable records produced but not yet committed (maintained incrementally, capped cardinality).\n\
         # TYPE ironbus_consumer_lag_records gauge\n",
    );
    lag.for_each_series(|consumer, records| {
        let _ = writeln!(
            s,
            "ironbus_consumer_lag_records{{consumer=\"{}\"}} {records}",
            escape_label(consumer)
        );
    });
    // The overflow fold series is emitted only once a label has been dropped, so a healthy
    // broker's exposition does not carry it. The total folded lag stays visible here.
    if lag.has_overflow() {
        let _ = writeln!(
            s,
            "ironbus_consumer_lag_records{{consumer=\"{}\"}} {}",
            crate::registry::OVERFLOW_CONSUMER_LABEL,
            lag.overflow_lag()
        );
    }
    let _ = writeln!(
        s,
        "# HELP ironbus_consumer_labels_dropped_total Consumer lag labels refused a distinct series at the cardinality cap (folded into __overflow__)."
    );
    let _ = writeln!(s, "# TYPE ironbus_consumer_labels_dropped_total counter");
    let _ = writeln!(
        s,
        "ironbus_consumer_labels_dropped_total {}",
        lag.labels_dropped()
    );
}

/// Renders the self-monitoring series (#97): `ironbus_build_info` (the build version as a label,
/// value 1), `ironbus_start_time_seconds` (the broker start time as Unix seconds, captured once at
/// open), and `ironbus_uptime_seconds` (monotonic-derived from the clock seam, so it never
/// regresses on a wall-clock step).
fn self_monitoring_lines(
    s: &mut String,
    registry: &crate::registry::MetricRegistry,
    now_monotonic: u64,
) {
    let _ = writeln!(
        s,
        "# HELP ironbus_build_info The build version as a label; the value is always 1."
    );
    let _ = writeln!(s, "# TYPE ironbus_build_info gauge");
    let _ = writeln!(
        s,
        "ironbus_build_info{{version=\"{}\"}} 1",
        escape_label(registry.build_version())
    );
    let _ = writeln!(
        s,
        "# HELP ironbus_start_time_seconds The broker start time in Unix seconds."
    );
    let _ = writeln!(s, "# TYPE ironbus_start_time_seconds gauge");
    let _ = writeln!(
        s,
        "ironbus_start_time_seconds {}",
        registry.start_time_unix_seconds()
    );
    let _ = writeln!(
        s,
        "# HELP ironbus_uptime_seconds Seconds since the broker started (monotonic-derived)."
    );
    let _ = writeln!(s, "# TYPE ironbus_uptime_seconds gauge");
    let _ = writeln!(
        s,
        "ironbus_uptime_seconds {}",
        registry.uptime_seconds(now_monotonic)
    );
}

/// Escapes a work-group name for a Prometheus label value: backslash, double-quote, and
/// newline per the exposition format. Group names are graphic ASCII (no newlines), but the
/// escape is applied unconditionally so a future relaxation cannot break the exposition.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Renders the per-work-group consumer series (#15, #16): committed offset, lag, and
/// in-flight depth labeled by `group`, so an operator sees lag broken down by cursor. Lag is
/// the durable head minus the group's committed offset. The Prometheus text format requires
/// all samples of one metric family to be contiguous, so each metric is emitted as a whole
/// block (one HELP/TYPE then every group's sample), not interleaved per group.
fn group_consumer_lines(groups: &[GroupConsumerStat], flushed: u64) -> String {
    let mut s = String::from(
        "# HELP ironbus_group_committed_offset The committed offset of a work-group's cursor.\n\
         # TYPE ironbus_group_committed_offset gauge\n",
    );
    for stat in groups {
        let _ = writeln!(
            s,
            "ironbus_group_committed_offset{{group=\"{}\"}} {}",
            escape_label(&stat.group),
            stat.committed
        );
    }
    s.push_str(
        "# HELP ironbus_group_consumer_lag Durable records not yet committed by a work-group.\n\
         # TYPE ironbus_group_consumer_lag gauge\n",
    );
    for stat in groups {
        let lag = flushed.saturating_sub(stat.committed);
        let _ = writeln!(
            s,
            "ironbus_group_consumer_lag{{group=\"{}\"}} {lag}",
            escape_label(&stat.group)
        );
    }
    s.push_str(
        "# HELP ironbus_group_in_flight Messages leased but not yet acked in a work-group.\n\
         # TYPE ironbus_group_in_flight gauge\n",
    );
    for stat in groups {
        let _ = writeln!(
            s,
            "ironbus_group_in_flight{{group=\"{}\"}} {}",
            escape_label(&stat.group),
            stat.in_flight
        );
    }
    s
}

/// Renders the per-reason recovery-loss gauge `ironbus_recovery_loss_bytes{reason=...}` from the
/// last recovery's loss report: one line per reason in code order, zero where a reason did not
/// occur. The grand total equals `ironbus_recovery_truncated_bytes`.
fn recovery_loss_lines(by_reason: &[u64; 5]) -> String {
    let mut s = String::from(
        "# HELP ironbus_recovery_loss_bytes Bytes dropped at the last recovery, by reason.\n\
         # TYPE ironbus_recovery_loss_bytes gauge\n",
    );
    for (reason, bytes) in ReasonCode::ALL.iter().zip(by_reason.iter()) {
        let _ = writeln!(
            s,
            "ironbus_recovery_loss_bytes{{reason=\"{}\"}} {bytes}",
            reason.metric_label()
        );
    }
    s
}

/// Renders the per-reason recovery-loss gauge `ironbus_recovery_loss_records{reason=...}`
/// from the last recovery's loss report: the record-count complement of
/// `ironbus_recovery_loss_bytes`, so an operator sees not just how many bytes recovery
/// dropped but how many records, by reason. Zero where a reason did not occur.
fn recovery_loss_records_lines(by_reason: &[u64; 5]) -> String {
    let mut s = String::from(
        "# HELP ironbus_recovery_loss_records Records dropped at the last recovery, by reason.\n\
         # TYPE ironbus_recovery_loss_records gauge\n",
    );
    for (reason, records) in ReasonCode::ALL.iter().zip(by_reason.iter()) {
        let _ = writeln!(
            s,
            "ironbus_recovery_loss_records{{reason=\"{}\"}} {records}",
            reason.metric_label()
        );
    }
    s
}

/// Renders the `ironbus_fsync_seconds` Prometheus histogram (cumulative `le` buckets in
/// seconds, plus `_sum` and `_count`) from a [`LatencyHistogram`] snapshot.
fn fsync_histogram_lines(fsync: &LatencyHistogram) -> String {
    let cumulative = fsync.cumulative_buckets();
    let mut s = String::from(
        "# HELP ironbus_fsync_seconds The fsync (durability barrier) latency on produce.\n\
         # TYPE ironbus_fsync_seconds histogram\n",
    );
    for (le, count) in FSYNC_BUCKET_LE_SECONDS.iter().zip(cumulative.iter()) {
        let _ = writeln!(s, "ironbus_fsync_seconds_bucket{{le=\"{le}\"}} {count}");
    }
    let total = fsync.count();
    let nanos = fsync.sum_nanos();
    let _ = writeln!(s, "ironbus_fsync_seconds_bucket{{le=\"+Inf\"}} {total}");
    // Seconds with nanosecond precision, formatted without floating point.
    let _ = writeln!(
        s,
        "ironbus_fsync_seconds_sum {}.{:09}",
        nanos / 1_000_000_000,
        nanos % 1_000_000_000
    );
    let _ = writeln!(s, "ironbus_fsync_seconds_count {total}");
    s
}

/// A consistent snapshot of the read-only introspection state (#99), read under one engine lock so
/// every field is from the same instant. Every value comes from an existing read-only engine
/// accessor; nothing here can mutate the engine, and no secret material is carried.
struct AdminSnapshot {
    healthy: bool,
    flushed: u64,
    committed: u64,
    earliest_retained: u64,
    durable_record_bytes: u64,
    durable_record_count: u64,
    segment_count: usize,
    recovered_truncated_bytes: u64,
    /// The most recent dead-letter offset, or -1 if none (the same sentinel `/metrics` uses).
    last_dead_lettered: i64,
    dlq_records: u64,
    counters: Counters,
    /// Per-work-group consumer position, the default group `""` included.
    groups: Vec<GroupConsumerStat>,
    config: EngineConfigSnapshot,
}

/// The schema version of the `/admin` JSON body (#99). Pinned so a consumer can detect a
/// breaking shape change; a future incompatible change bumps it.
const ADMIN_SCHEMA_VERSION: u32 = 1;

/// Renders the `/admin` JSON snapshot (#99): a structured, read-only view of operational state.
/// Hand-rendered (no serde dependency, matching the hand-rendered Prometheus text) and strictly a
/// projection of [`AdminSnapshot`], so it can never mutate engine state. The top-level shape is
/// `{schema_version, broker, groups[], dlq, config}`. Lag is the durable head minus the group's
/// committed offset, the same derivation `/metrics` uses.
fn admin_body(snapshot: &AdminSnapshot) -> String {
    let mut s = String::new();
    let _ = write!(s, "{{\"schema_version\":{ADMIN_SCHEMA_VERSION},");
    admin_broker_section(&mut s, snapshot);
    admin_groups_section(&mut s, snapshot);
    admin_dlq_section(&mut s, snapshot);
    admin_config_section(&mut s, &snapshot.config);
    s.push('}');
    s
}

/// Appends the broker-level `"broker":{...}` object: durable head, committed cursor, retained span,
/// sizes, and the operational counters. Lag is the durable head minus the committed offset.
fn admin_broker_section(s: &mut String, snapshot: &AdminSnapshot) {
    let counters = &snapshot.counters;
    let _ = write!(
        s,
        "\"broker\":{{\
            \"healthy\":{healthy},\
            \"flushed_offset\":{flushed},\
            \"committed_offset\":{committed},\
            \"earliest_retained_offset\":{earliest_retained},\
            \"consumer_lag\":{lag},\
            \"durable_record_bytes\":{durable_record_bytes},\
            \"durable_record_count\":{durable_record_count},\
            \"segment_count\":{segment_count},\
            \"recovery_truncated_bytes\":{recovered_truncated_bytes},\
            \"produced\":{produced},\
            \"produced_bytes\":{produced_bytes},\
            \"produce_rejected\":{produce_rejected},\
            \"delivered\":{delivered},\
            \"redelivered\":{redelivered},\
            \"dead_lettered\":{dead_lettered},\
            \"acks\":{acks},\
            \"segments_reaped\":{segments_reaped},\
            \"segments_force_reaped\":{segments_force_reaped},\
            \"truncations\":{truncations},\
            \"truncated_records\":{truncated_records}\
        }},",
        healthy = snapshot.healthy,
        flushed = snapshot.flushed,
        committed = snapshot.committed,
        earliest_retained = snapshot.earliest_retained,
        lag = snapshot.flushed.saturating_sub(snapshot.committed),
        durable_record_bytes = snapshot.durable_record_bytes,
        durable_record_count = snapshot.durable_record_count,
        segment_count = snapshot.segment_count,
        recovered_truncated_bytes = snapshot.recovered_truncated_bytes,
        produced = counters.produced,
        produced_bytes = counters.produced_bytes,
        produce_rejected = counters.produce_rejected,
        delivered = counters.delivered,
        redelivered = counters.redelivered,
        dead_lettered = counters.dead_lettered,
        acks = counters.acks,
        segments_reaped = counters.segments_reaped,
        segments_force_reaped = counters.segments_force_reaped,
        truncations = counters.truncations,
        truncated_records = counters.truncated_records,
    );
}

/// Appends the per-work-group `"groups":[...]` array (the default group `""` included): committed
/// offset, lag, and in-flight depth per group. Lag is the durable head minus the group's committed.
fn admin_groups_section(s: &mut String, snapshot: &AdminSnapshot) {
    s.push_str("\"groups\":[");
    for (i, stat) in snapshot.groups.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"name\":\"{}\",\"committed_offset\":{},\"consumer_lag\":{},\"in_flight\":{}}}",
            escape_json(&stat.group),
            stat.committed,
            snapshot.flushed.saturating_sub(stat.committed),
            stat.in_flight,
        );
    }
    s.push_str("],");
}

/// Appends the `"dlq":{...}` object: the durable dead-letter depth and the last dead-lettered
/// offset (`-1` if nothing has been dead-lettered).
fn admin_dlq_section(s: &mut String, snapshot: &AdminSnapshot) {
    let _ = write!(
        s,
        "\"dlq\":{{\"records\":{},\"last_dead_lettered_offset\":{}}},",
        snapshot.dlq_records, snapshot.last_dead_lettered,
    );
}

/// Appends the `"config":{...}` echo of the effective bounds (no secret material), each `0` keeping
/// the codebase's off/unlimited convention.
fn admin_config_section(s: &mut String, config: &EngineConfigSnapshot) {
    let _ = write!(
        s,
        "\"config\":{{\
            \"max_total_bytes\":{max_total_bytes},\
            \"max_segment_bytes\":{max_segment_bytes},\
            \"max_retained_bytes\":{max_retained_bytes},\
            \"max_age_ms\":{max_age_ms},\
            \"max_messages\":{max_messages},\
            \"max_in_flight\":{max_in_flight},\
            \"consumer_credit\":{consumer_credit},\
            \"consumer_credit_bytes\":{consumer_credit_bytes},\
            \"max_deliver\":{max_deliver},\
            \"max_groups\":{max_groups},\
            \"group_idle_evict_nanos\":{group_idle_evict_nanos},\
            \"visibility_nanos\":{visibility_nanos},\
            \"hard_cap_nanos\":{hard_cap_nanos},\
            \"disk_full_policy\":\"{disk_full_policy}\"\
        }}",
        max_total_bytes = config.max_total_bytes,
        max_segment_bytes = config.max_segment_bytes,
        max_retained_bytes = config.max_retained_bytes,
        max_age_ms = config.max_age_ms,
        max_messages = config.max_messages,
        max_in_flight = config.max_in_flight,
        consumer_credit = config.consumer_credit,
        consumer_credit_bytes = config.consumer_credit_bytes,
        max_deliver = config.max_deliver,
        max_groups = config.max_groups,
        group_idle_evict_nanos = config.group_idle_evict_nanos,
        visibility_nanos = config.visibility_nanos,
        hard_cap_nanos = config.hard_cap_nanos,
        disk_full_policy = disk_full_policy_label(config.disk_full_policy),
    );
}

/// The stable JSON label for a [`crate::engine::DiskFullPolicy`], matching the `--disk-full-policy`
/// CLI spelling so the echoed value round-trips to the flag an operator would set.
fn disk_full_policy_label(policy: crate::engine::DiskFullPolicy) -> &'static str {
    // `DiskFullPolicy` is `#[non_exhaustive]` to downstream crates, but within this crate the
    // match is exhaustive, so a new variant is a compile error here (a deliberate prompt to give
    // it a stable JSON label) rather than silently rendering as "unknown".
    match policy {
        crate::engine::DiskFullPolicy::DropNew => "drop-new",
        crate::engine::DiskFullPolicy::DropOldest => "drop-oldest",
    }
}

/// Escapes a string for a JSON string value: the two structural characters (`\` and `"`) plus the
/// control characters JSON requires escaped. Work-group names are graphic ASCII (the engine
/// validates them), but the escape is applied unconditionally so a future relaxation cannot produce
/// malformed JSON.
fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            other => out.push(other),
        }
    }
    out
}

fn respond(stream: &mut TcpStream, code: u16, reason: &str, body: &str) -> std::io::Result<()> {
    respond_with(stream, code, reason, "text/plain; charset=utf-8", body)
}

/// Like [`respond`] but with the `application/json` content type, for the `/admin` endpoint (#99).
fn respond_json(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    respond_with(
        stream,
        code,
        reason,
        "application/json; charset=utf-8",
        body,
    )
}

fn respond_with(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::SharedEngine;
    use crate::clock::SystemClock;
    use crate::engine::{AckResult, DiskFullPolicy, Engine, EngineConfig, Poll};
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::{Append, LogConfig};
    use std::sync::{Arc, Mutex};

    fn start() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve_health(&listener, &shared, &shutdown, false).unwrap()
        });
        (addr, shutdown, handle, engine)
    }

    /// Sends one raw request and returns the full response text.
    fn request(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(raw.as_bytes()).unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn healthz_is_ok_and_readyz_is_ready_on_a_live_broker() {
        let (addr, shutdown, handle, _engine) = start();

        let h = request(addr, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 200 OK"), "{h}");
        assert!(h.ends_with("ok"), "{h}");

        let r = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(r.ends_with("ready"), "{r}");

        // A query string is stripped.
        let q = request(addr, "GET /healthz?probe=1 HTTP/1.1\r\n\r\n");
        assert!(q.starts_with("HTTP/1.1 200 OK"), "{q}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn unknown_path_is_404_and_non_get_is_405() {
        let (addr, shutdown, handle, _engine) = start();

        let nf = request(addr, "GET /nope HTTP/1.1\r\n\r\n");
        assert!(nf.starts_with("HTTP/1.1 404 Not Found"), "{nf}");

        let na = request(addr, "POST /healthz HTTP/1.1\r\n\r\n");
        assert!(na.starts_with("HTTP/1.1 405 Method Not Allowed"), "{na}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_exposes_engine_gauges() {
        let (addr, shutdown, handle, engine) = start();
        // Produce two durable records so the flushed head and the lag advance.
        {
            let mut g = engine.lock().unwrap();
            for payload in [&b"a"[..], b"b"] {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
            }
        }
        // Anchor each assertion to a full line so a future value like 20 cannot false-match 2.
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        assert!(m.contains("# TYPE ironbus_consumer_lag gauge"), "{m}");
        assert!(m.contains("\nironbus_flushed_offset 2\n"), "{m}");
        assert!(m.contains("\nironbus_committed_offset 0\n"), "{m}");
        assert!(m.contains("\nironbus_consumer_lag 2\n"), "{m}");
        assert!(m.contains("\nironbus_in_flight 0\n"), "{m}");
        assert!(m.contains("\nironbus_writer_healthy 1\n"), "{m}");
        assert!(m.contains("\nironbus_recovery_truncated_bytes 0\n"), "{m}");
        // The per-reason recovery-loss series is present, one line per reason, zero on a clean
        // start (no recovery loss).
        assert!(
            m.contains("# TYPE ironbus_recovery_loss_bytes gauge"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_recovery_loss_bytes{reason=\"torn_tail\"} 0\n"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_recovery_loss_bytes{reason=\"corrupt_record_body\"} 0\n"),
            "{m}"
        );
        // The record-count complement of the per-reason loss-bytes series, plus a clean
        // (no leading whitespace) TYPE line so a strict Prometheus parser accepts it.
        assert!(
            m.contains("\n# TYPE ironbus_recovery_loss_records gauge\n"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_recovery_loss_records{reason=\"torn_tail\"} 0\n"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_recovery_loss_records{reason=\"sequence_gap\"} 0\n"),
            "{m}"
        );
        // The loss-bytes TYPE line is also clean (no indentation regression).
        assert!(
            m.contains("\n# TYPE ironbus_recovery_loss_bytes gauge\n"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_last_dead_lettered_offset -1\n"),
            "{m}"
        );
        assert!(m.contains("\nironbus_produced_total 2\n"), "{m}");
        assert!(m.contains("\nironbus_produced_bytes_total 2\n"), "{m}");
        // The drop-new shed counter is present and zero on an uncapped, healthy broker.
        assert!(
            m.contains("# TYPE ironbus_produce_rejected_total counter"),
            "{m}"
        );
        assert!(m.contains("\nironbus_produce_rejected_total 0\n"), "{m}");
        assert!(m.contains("\nironbus_delivered_total 0\n"), "{m}");
        assert!(m.contains("\nironbus_dead_lettered_total 0\n"), "{m}");
        // The DLQ depth counter is present and zero on a broker that has never dead-lettered.
        assert!(
            m.contains("# TYPE ironbus_dlq_records_total counter"),
            "{m}"
        );
        assert!(m.contains("\nironbus_dlq_records_total 0\n"), "{m}");
        // The fsync histogram: two produces above, so count and the +Inf bucket are 2. The
        // bucket distribution is timing-dependent under the system clock, so it is not pinned.
        assert!(m.contains("# TYPE ironbus_fsync_seconds histogram"), "{m}");
        assert!(m.contains("\nironbus_fsync_seconds_count 2\n"), "{m}");
        assert!(
            m.contains("ironbus_fsync_seconds_bucket{le=\"+Inf\"} 2"),
            "{m}"
        );

        // Lease one message: in-flight reflects the outstanding lease.
        let token = {
            let mut g = engine.lock().unwrap();
            match g.poll_now().unwrap() {
                Poll::Message(d) => d.token,
                other => panic!("expected a message, got {other:?}"),
            }
        };
        let leased = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(leased.contains("\nironbus_in_flight 1\n"), "{leased}");
        assert!(leased.contains("\nironbus_delivered_total 1\n"), "{leased}");
        assert!(
            leased.contains("\nironbus_redelivered_total 0\n"),
            "{leased}"
        );

        // Ack it: the committed cursor advances and the lag shrinks.
        {
            let mut g = engine.lock().unwrap();
            assert_eq!(g.ack(&token), AckResult::Acked);
        }
        let acked = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(acked.contains("\nironbus_committed_offset 1\n"), "{acked}");
        assert!(acked.contains("\nironbus_consumer_lag 1\n"), "{acked}");
        assert!(acked.contains("\nironbus_in_flight 0\n"), "{acked}");
        assert!(acked.contains("\nironbus_acks_total 1\n"), "{acked}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_exposes_the_quarantine_gauge() {
        // The forensic quarantine gauge (#134): present and zero on a clean start, with a clean
        // (no leading whitespace) TYPE line so a strict Prometheus parser accepts it. It is a gauge,
        // not a `_total`, so it is excluded from the frozen resilience-counter set by construction
        // (the_resilience_counter_taxonomy_is_frozen stays green).
        let (addr, shutdown, handle, _engine) = start();
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        assert!(
            m.contains("\n# TYPE ironbus_quarantine_bytes gauge\n"),
            "{m}"
        );
        assert!(m.contains("\nironbus_quarantine_bytes 0\n"), "{m}");
        // It must NOT carry the `_total` counter suffix (that would pull it into the frozen set).
        assert!(!m.contains("ironbus_quarantine_bytes_total"), "{m}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_exposes_the_registry_series() {
        // The bounded metric registry (#97): the fixed-bucket histograms, the per-consumer lag
        // series maintained incrementally on produce/ack, and the self-monitoring series, all on
        // `/metrics`. A clean start is exercised first, then a produce + ack moves the default
        // consumer's lag.
        let (addr, shutdown, handle, engine) = start();

        let m0 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        // The new fixed-bucket histograms are present with the issue's exact 0.0005 s first bound
        // and the 5 s last bound (proving the #97 bucket set, distinct from the legacy
        // ironbus_fsync_seconds histogram which keeps its own bounds).
        assert!(
            m0.contains("# TYPE ironbus_fsync_duration_seconds histogram"),
            "{m0}"
        );
        assert!(
            m0.contains("ironbus_fsync_duration_seconds_bucket{le=\"0.0005\"}"),
            "{m0}"
        );
        assert!(
            m0.contains("ironbus_fsync_duration_seconds_bucket{le=\"5\"}"),
            "{m0}"
        );
        assert!(
            m0.contains("# TYPE ironbus_append_duration_seconds histogram"),
            "{m0}"
        );
        // The legacy fsync histogram still renders (no existing metric name was removed).
        assert!(
            m0.contains("# TYPE ironbus_fsync_seconds histogram"),
            "{m0}"
        );
        // The self-monitoring series are present. build_info carries the crate version label and
        // value 1; start_time and uptime are gauges.
        assert!(
            m0.contains(&format!(
                "ironbus_build_info{{version=\"{}\"}} 1",
                env!("CARGO_PKG_VERSION")
            )),
            "{m0}"
        );
        assert!(
            m0.contains("\n# TYPE ironbus_start_time_seconds gauge\n"),
            "{m0}"
        );
        assert!(
            m0.contains("\n# TYPE ironbus_uptime_seconds gauge\n"),
            "{m0}"
        );
        // The dropped-labels counter is present and zero (it is in the frozen taxonomy as a
        // `_total`), and no overflow series exists on a healthy broker.
        assert!(
            m0.contains("\nironbus_consumer_labels_dropped_total 0\n"),
            "{m0}"
        );
        assert!(!m0.contains("consumer=\"__overflow__\""), "{m0}");
        // The default consumer's lag series exists at 0 before any produce.
        assert!(
            m0.contains("# TYPE ironbus_consumer_lag_records gauge"),
            "{m0}"
        );
        assert!(
            m0.contains("ironbus_consumer_lag_records{consumer=\"\"} 0"),
            "{m0}"
        );

        // Produce two records: the head advances, so the default consumer lags 2 and the new
        // histograms record observations.
        {
            let mut g = engine.lock().unwrap();
            for payload in [&b"a"[..], b"b"] {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
            }
        }
        let m1 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m1.contains("ironbus_consumer_lag_records{consumer=\"\"} 2"),
            "{m1}"
        );
        assert!(
            m1.contains("\nironbus_fsync_duration_seconds_count 2\n"),
            "{m1}"
        );
        assert!(
            m1.contains("\nironbus_append_duration_seconds_count 2\n"),
            "{m1}"
        );

        // Lease and ack one: the default consumer commits one record, so its lag drops to 1
        // (maintained incrementally on ack, never scanned).
        let token = {
            let mut g = engine.lock().unwrap();
            match g.poll_now().unwrap() {
                Poll::Message(d) => d.token,
                other => panic!("expected a message, got {other:?}"),
            }
        };
        {
            let mut g = engine.lock().unwrap();
            assert_eq!(g.ack(&token), AckResult::Acked);
        }
        let m2 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m2.contains("ironbus_consumer_lag_records{consumer=\"\"} 1"),
            "{m2}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// Like [`start`] but with a hard durable-log byte cap, so the rejection path is exercised.
    fn start_with_cap(
        max_total_bytes: u64,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default().with_max_total_bytes(max_total_bytes),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve_health(&listener, &shared, &shutdown, false).unwrap()
        });
        (addr, shutdown, handle, engine)
    }

    #[test]
    fn metrics_renders_and_increments_produce_rejected() {
        let payload = &b"capacity-probe"[..];
        // Measure one record's framed durable bytes, then cap the broker at exactly one record
        // so the SECOND produce is rejected by the drop-new shed.
        let one = {
            let (_addr, sd, h, eng) = start();
            let bytes = {
                let mut g = eng.lock().unwrap();
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
                g.durable_record_bytes()
            };
            sd.store(true, Ordering::Release);
            h.join().unwrap();
            bytes
        };

        let (addr, shutdown, handle, engine) = start_with_cap(one);
        // First produce fits; the metric starts at zero.
        {
            let mut g = engine.lock().unwrap();
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
        }
        let m0 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m0.contains("\nironbus_produce_rejected_total 0\n"), "{m0}");

        // Two over-cap produces are rejected (the writer stays live), so the counter reads 2.
        {
            let mut g = engine.lock().unwrap();
            for _ in 0..2 {
                let err = g
                    .produce(&Append {
                        timestamp_ms: 0,
                        flags: RecordFlags::EMPTY,
                        key: b"",
                        headers: b"",
                        payload,
                    })
                    .unwrap_err();
                assert!(err.is_at_capacity(), "got {err:?}");
            }
            assert!(g.is_healthy(), "the shed never freezes the writer");
        }
        let m1 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m1.contains("\nironbus_produce_rejected_total 2\n"), "{m1}");
        // The successful produce was counted once and nothing more (the sheds did not inflate it).
        assert!(m1.contains("\nironbus_produced_total 1\n"), "{m1}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_renders_and_increments_dlq_records() {
        use ironbus_core::clock::ManualClock;
        // Build a broker over a manual clock so a redelivery's lease can be expired deterministically,
        // dead-letter one message into the durable DLQ sink, then serve /metrics over it (the metric
        // body is clock-agnostic). The DLQ depth counter must render and read 1.
        let clock = Arc::new(ManualClock::new());
        let engine = Engine::open(
            InMemoryFs::new(),
            Arc::clone(&clock),
            EngineConfig {
                log: LogConfig::default(),
                // Tiny visibility/cap so a redelivery is reclaimable a few ns later.
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(1, false, vec![]).unwrap(), // max_deliver = 1
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, Arc<ManualClock>> = Arc::new(Mutex::new(engine));
        {
            let mut g = shared.lock().unwrap();
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"poison",
            })
            .unwrap();
            // First delivery, expire, then the second poll dead-letters it into the DLQ.
            let _ = g.poll_now().unwrap();
            clock.advance_monotonic_nanos(40);
            assert!(matches!(g.poll_now().unwrap(), Poll::Parked { .. }));
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let shared = Arc::clone(&shared);
            move || serve_health(&listener, &shared, &shutdown, false).unwrap()
        });

        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m.contains("# TYPE ironbus_dlq_records_total counter"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_dlq_records_total 1\n"),
            "the DLQ depth counter should read 1 after one dead-letter: {m}"
        );
        // The in-band advisory counter also fired.
        assert!(m.contains("\nironbus_dead_lettered_total 1\n"), "{m}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// Like [`start`] but with a small segment cap (so produces roll) plus a consumer-safe
    /// size-retention bound, so the reaper path is exercised end to end.
    fn start_with_retention(
        max_retained_bytes: u64,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        start_with_bounds(max_retained_bytes, 0)
    }

    /// Like [`start_with_retention`] but configures the COUNT bound (size off), to exercise the
    /// shared reaped counter under the count retention mode.
    fn start_with_count_retention(
        max_messages: u64,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        start_with_bounds(0, max_messages)
    }

    /// A small-segment broker with the given size and count retention bounds (age off), wired to a
    /// health endpoint, so the reaper path is exercised end to end over either bound.
    fn start_with_bounds(
        max_retained_bytes: u64,
        max_messages: u64,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig {
                    max_segment_bytes: 160,
                    max_total_bytes: 0,
                    ..LogConfig::default()
                },
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 64,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes,
                max_age_ms: 0,
                max_messages,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve_health(&listener, &shared, &shutdown, false).unwrap()
        });
        (addr, shutdown, handle, engine)
    }

    #[test]
    fn metrics_renders_and_increments_segments_reaped() {
        // The retention reaped counter renders on /metrics and increments once retention reclaims
        // old, fully-consumed segments as the durable log grows past the bound (#13, #80).
        let payload = &[0xab_u8; 16][..];
        // Measure one record's framed durable bytes, then bound retention at a few records.
        let one = {
            let (_a, sd, h, eng) = start_with_retention(0);
            let bytes = {
                let mut g = eng.lock().unwrap();
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
                g.durable_record_bytes()
            };
            sd.store(true, Ordering::Release);
            h.join().unwrap();
            bytes
        };

        let (addr, shutdown, handle, engine) = start_with_retention(4 * one);
        // The counter is present and zero before anything is reaped.
        let m0 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m0.contains("# TYPE ironbus_segments_reaped_total counter"),
            "{m0}"
        );
        assert!(m0.contains("\nironbus_segments_reaped_total 0\n"), "{m0}");

        // Produce well past the bound, interleaving a full drain-and-ack after each produce so the
        // committed cursor tracks the head (a streaming workload). Retention runs on produce
        // against the committed floor, so old, now-consumed segments become reapable.
        {
            let mut g = engine.lock().unwrap();
            for _ in 0..30 {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
                loop {
                    match g.poll_now().unwrap() {
                        Poll::Message(d) => {
                            assert_eq!(g.ack(&d.token), AckResult::Acked);
                        }
                        Poll::Parked { .. } => {}
                        Poll::Truncated { .. } => panic!("unexpected truncation"),
                        Poll::Idle => break,
                    }
                }
            }
            assert!(
                g.counters().segments_reaped >= 1,
                "retention reaped at least one segment"
            );
        }
        let m1 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        // The counter incremented past zero (the exact value depends on the framing, so assert
        // it is non-zero by ruling out the zero line and confirming the family is present).
        assert!(
            m1.contains("# TYPE ironbus_segments_reaped_total counter"),
            "{m1}"
        );
        assert!(
            !m1.contains("\nironbus_segments_reaped_total 0\n"),
            "the reaped counter must have incremented past zero: {m1}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_reaped_counter_increments_under_the_count_bound() {
        // The shared reaped counter also increments when the COUNT retention mode (not size)
        // triggers the reap (refs #13, #80): the metric counts reaped segments regardless of bound.
        let payload = &[0xab_u8; 16][..];
        let (addr, shutdown, handle, engine) = start_with_count_retention(8);
        let m0 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m0.contains("\nironbus_segments_reaped_total 0\n"), "{m0}");

        // Produce well past the count bound, draining and acking after each produce so the
        // committed cursor tracks the head (a streaming workload). Count retention then reaps the
        // old, now-consumed segments.
        {
            let mut g = engine.lock().unwrap();
            for _ in 0..40 {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
                loop {
                    match g.poll_now().unwrap() {
                        Poll::Message(d) => assert_eq!(g.ack(&d.token), AckResult::Acked),
                        Poll::Parked { .. } => {}
                        Poll::Truncated { .. } => panic!("unexpected truncation"),
                        Poll::Idle => break,
                    }
                }
            }
            assert!(
                g.counters().segments_reaped >= 1,
                "count retention reaped at least one segment"
            );
        }
        let m1 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m1.contains("# TYPE ironbus_segments_reaped_total counter"),
            "{m1}"
        );
        assert!(
            !m1.contains("\nironbus_segments_reaped_total 0\n"),
            "the reaped counter must have incremented under the count bound: {m1}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// A small-segment broker with a durable-log byte cap and the disk-full DROP-OLDEST policy,
    /// wired to a health endpoint, so the forced-reap counter path is exercised end to end (#82).
    fn start_with_drop_oldest(
        max_total_bytes: u64,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig {
                    max_segment_bytes: 160,
                    max_total_bytes,
                    ..LogConfig::default()
                },
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 64,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                disk_full_policy: DiskFullPolicy::DropOldest,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve_health(&listener, &shared, &shutdown, false).unwrap()
        });
        (addr, shutdown, handle, engine)
    }

    #[test]
    fn metrics_renders_and_increments_segments_force_reaped() {
        // The force-reaped counter renders on /metrics and increments once the disk-full
        // drop-oldest policy force-reaps an oldest segment to make room for an over-cap produce
        // (#82). A stuck consumer (leases offset 0, never acks) pins the protect floor so the
        // consumer-safe reaper cannot reclaim; only the forced reap can.
        let payload = &[0xab_u8; 16][..];
        let one = {
            let (_a, sd, h, eng) = start_with_drop_oldest(0);
            let bytes = {
                let mut g = eng.lock().unwrap();
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
                g.durable_record_bytes()
            };
            sd.store(true, Ordering::Release);
            h.join().unwrap();
            bytes
        };

        let (addr, shutdown, handle, engine) = start_with_drop_oldest(4 * one);
        // The counter is present and zero before anything is force-reaped.
        let m0 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m0.contains("# TYPE ironbus_segments_force_reaped_total counter"),
            "{m0}"
        );
        assert!(
            m0.contains("\nironbus_segments_force_reaped_total 0\n"),
            "{m0}"
        );

        {
            let mut g = engine.lock().unwrap();
            // A stuck consumer leases offset 0 and never acks: the protect floor stays at 0.
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
            assert!(matches!(g.poll_now_in("stuck").unwrap(), Poll::Message(_)));
            // Produce well past the cap: every produce succeeds (drop-oldest force-reaps).
            for _ in 0..20 {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .expect("drop-oldest accepts the produce");
            }
            assert!(
                g.counters().segments_force_reaped >= 1,
                "the drop-oldest policy force-reaped at least one segment"
            );
        }
        let m1 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m1.contains("# TYPE ironbus_segments_force_reaped_total counter"),
            "{m1}"
        );
        assert!(
            !m1.contains("\nironbus_segments_force_reaped_total 0\n"),
            "the force-reaped counter must have incremented past zero: {m1}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_renders_and_increments_truncations() {
        // The below-earliest truncation counters render on /metrics and increment when a consumer's
        // cursor falls below the oldest retained record (its data was force-reaped out from under it
        // by the disk-full drop-oldest policy) and the engine surfaces a one-time Poll::Truncated
        // (#82, #84, #96). This is the resilience SKIP signal: a consumer losing a span must never be
        // silent.
        let payload = &[0xab_u8; 16][..];
        let one = {
            let (_a, sd, h, eng) = start_with_drop_oldest(0);
            let bytes = {
                let mut g = eng.lock().unwrap();
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
                g.durable_record_bytes()
            };
            sd.store(true, Ordering::Release);
            h.join().unwrap();
            bytes
        };

        let (addr, shutdown, handle, engine) = start_with_drop_oldest(4 * one);
        // Both truncation counters are present and zero before anything is truncated.
        let m0 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m0.contains("# TYPE ironbus_truncations_total counter"),
            "{m0}"
        );
        assert!(m0.contains("\nironbus_truncations_total 0\n"), "{m0}");
        assert!(
            m0.contains("# TYPE ironbus_truncated_records_total counter"),
            "{m0}"
        );
        assert!(m0.contains("\nironbus_truncated_records_total 0\n"), "{m0}");

        let skipped = {
            let mut g = engine.lock().unwrap();
            // The "slow" group leases offset 0 and never acks, pinning its cursor at 0. The
            // drop-oldest policy then force-reaps the oldest segments out from under it as the log
            // grows past the cap.
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
            assert!(matches!(g.poll_now_in("slow").unwrap(), Poll::Message(_)));
            for _ in 0..20 {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .expect("drop-oldest accepts the produce");
            }
            assert!(
                g.counters().segments_force_reaped >= 1,
                "the drop-oldest policy force-reaped at least one segment"
            );
            // The slow group's next poll is a one-time truncation: its cursor (0) is now below the
            // oldest retained record, so the engine resets it up and reports the skipped span.
            let skipped = match g.poll_now_in("slow").unwrap() {
                Poll::Truncated { skipped, .. } => skipped,
                other => panic!("expected a truncation, got {other:?}"),
            };
            assert!(skipped >= 1, "at least one record was skipped");
            // Exactly one truncation event was counted, spanning `skipped` records.
            assert_eq!(g.counters().truncations, 1, "one truncation event");
            assert_eq!(
                g.counters().truncated_records,
                skipped,
                "the record span matches the surfaced skip"
            );
            skipped
        };

        let m1 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m1.contains("\nironbus_truncations_total 1\n"), "{m1}");
        assert!(
            m1.contains(&format!("\nironbus_truncated_records_total {skipped}\n")),
            "the records counter equals the skipped span: {m1}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_render_the_reconciliation_counter_and_skip_loss_gauges() {
        // The checkpoint-plus-replay reconciliation surface (#307) renders on /metrics: the new
        // `_total` repair counter (with TYPE/HELP, so the frozen-taxonomy parser accepts it) and the
        // two reconciled gauges, all zero on a clean fresh broker (no crash, no skip/loss).
        let (addr, shutdown, handle, _engine) = start();
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        assert!(
            m.contains("# TYPE ironbus_counter_checkpoint_repair_total counter"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_counter_checkpoint_repair_total 0\n"),
            "the repair counter is present and zero on a clean broker: {m}"
        );
        // The reconciled gauges are gauges (NOT `_total`), so they are excluded from the frozen
        // counter set by construction, and zero with no skip/loss.
        assert!(
            m.contains("\n# TYPE ironbus_records_skipped gauge\n"),
            "{m}"
        );
        assert!(m.contains("\nironbus_records_skipped 0\n"), "{m}");
        assert!(m.contains("\n# TYPE ironbus_bytes_skipped gauge\n"), "{m}");
        assert!(m.contains("\nironbus_bytes_skipped 0\n"), "{m}");
        assert!(
            m.contains("\n# TYPE ironbus_last_skip_offset gauge\n"),
            "{m}"
        );
        assert!(m.contains("\nironbus_last_skip_offset 0\n"), "{m}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// The COMPLETE, FROZEN set of resilience-counter metric names `/metrics` renders (#96). Every
    /// name here is an `ironbus_*_total` counter whose increment marks one resilience event the
    /// taxonomy guarantees is never silent (a shed, drop, skip, dead-letter, or reclamation). This
    /// set is the observability CONTRACT: adding, removing, or renaming a resilience counter MUST be
    /// a deliberate, test-gated edit here, so the taxonomy can never silently drift. See
    /// `docs/METRICS.md` for the per-counter meaning.
    const FROZEN_RESILIENCE_COUNTERS: &[&str] = &[
        "ironbus_produced_total",
        "ironbus_produced_bytes_total",
        "ironbus_produce_rejected_total",
        "ironbus_delivered_total",
        "ironbus_redelivered_total",
        "ironbus_dead_lettered_total",
        "ironbus_dlq_records_total",
        "ironbus_acks_total",
        "ironbus_segments_reaped_total",
        "ironbus_segments_force_reaped_total",
        "ironbus_truncations_total",
        "ironbus_truncated_records_total",
        // The checkpoint-plus-replay reconciliation/repair counter (#307): a reconciliation on open
        // raised a recovery-loss counter above its durable snapshot (the snapshot alone would have
        // resumed too low across a hard crash). A lower-bound-recovery signal, never a silent drop,
        // so it belongs in the frozen taxonomy. The reconciled gauges (`ironbus_records_skipped`,
        // `ironbus_bytes_skipped`, `ironbus_last_skip_offset`) are NOT `_total`, so they are excluded
        // by construction.
        "ironbus_counter_checkpoint_repair_total",
        // The metric-registry cardinality-cap counter (#97): a consumer lag label refused a distinct
        // series at the 1024-series cap was folded into `__overflow__`. A cardinality-pressure
        // signal, never a silent drop, so it belongs in the frozen taxonomy. The histograms
        // (`_seconds`/`_bucket`/`_sum`/`_count`) and gauges (`_lag_records`, `_build_info`,
        // `_start_time_seconds`, `_uptime_seconds`) the registry also adds are NOT `_total`, so they
        // are excluded from this set by construction (the taxonomy test filters on `_total`).
        "ironbus_consumer_labels_dropped_total",
    ];

    #[test]
    fn the_resilience_counter_taxonomy_is_frozen() {
        // Render /metrics and extract the COMPLETE set of `ironbus_*_total` counter names it emits,
        // then assert it equals FROZEN_RESILIENCE_COUNTERS exactly. A counter added without updating
        // the frozen set (or removed/renamed without it) fails here, so the resilience taxonomy and
        // its documented contract can never silently drift (#96). Modeled on the frozen wire-tag
        // tests, which pin the on-the-wire numbers the same way.
        let (addr, shutdown, handle, _engine) = start();
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");

        // Collect every distinct counter name: a sample line `ironbus_x_total <value>` (no label,
        // no `_bucket`/`_sum`/`_count` histogram suffix), confined to the `_total` counter suffix so
        // the gauges and the fsync histogram are excluded by construction. Asserting against the
        // SAMPLE lines (not the HELP/TYPE lines) proves each counter is actually exposed, not just
        // documented.
        let mut rendered: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for line in m.lines() {
            // A counter SAMPLE line is `ironbus_<...>_total <value>` with no label set. Match ANY
            // unsigned value, not just `0`: a counter that happens to be non-zero on a fresh broker
            // must NOT silently escape the exact-set check (a `_total 0` filter would skip it). A
            // `# HELP`/`# TYPE` line (first token `#`) and a labeled line (name ends in `}`) are
            // excluded by the `ironbus_*_total` name shape.
            let Some((name, value)) = line.split_once(' ') else {
                continue;
            };
            if name.starts_with("ironbus_")
                && name.ends_with("_total")
                && !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_digit())
            {
                rendered.insert(name);
            }
        }
        let expected: std::collections::BTreeSet<&str> =
            FROZEN_RESILIENCE_COUNTERS.iter().copied().collect();
        assert_eq!(
            rendered, expected,
            "the rendered resilience-counter set drifted from the frozen taxonomy; \
             update FROZEN_RESILIENCE_COUNTERS and docs/METRICS.md deliberately. \
             rendered={rendered:?} expected={expected:?}"
        );

        // Each frozen counter also carries a `# TYPE ... counter` declaration, so the exposition is
        // valid Prometheus (a strict parser needs the type line), and a `# HELP` line documenting it.
        for name in FROZEN_RESILIENCE_COUNTERS {
            assert!(
                m.contains(&format!("# TYPE {name} counter")),
                "missing TYPE line for {name}: {m}"
            );
            assert!(
                m.contains(&format!("# HELP {name} ")),
                "missing HELP line for {name}: {m}"
            );
        }

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn group_label_escapes_special_chars() {
        // A group name may contain a quote or backslash (both graphic ASCII); the label
        // must escape them so the Prometheus exposition stays well-formed.
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("a\"b"), "a\\\"b");
        assert_eq!(escape_label("a\\b"), "a\\\\b");
    }

    #[test]
    fn metrics_expose_per_group_consumer_lag() {
        // Lag broken down by cursor (#15, #16): with consumer groups, /metrics carries a
        // per-group committed/lag/in-flight series, not just the default group.
        let (addr, shutdown, handle, engine) = start();
        {
            let mut g = engine.lock().unwrap();
            for payload in [&b"a"[..], &b"b"[..], &b"c"[..]] {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
            }
            // Group "orders" consumes and acks the first message: committed advances to 1.
            match g.poll_in("orders", 0).unwrap() {
                Poll::Message(d) => assert_eq!(g.ack_in("orders", &d.token), AckResult::Acked),
                other => panic!("expected a message, got {other:?}"),
            }
            // Group "billing" leases one but does not ack: 1 in-flight, committed stays 0.
            assert!(matches!(g.poll_in("billing", 0).unwrap(), Poll::Message(_)));
        }
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        assert!(m.contains("# TYPE ironbus_group_consumer_lag gauge"), "{m}");
        // The default group is always present.
        assert!(
            m.contains("ironbus_group_committed_offset{group=\"\"} 0"),
            "{m}"
        );
        // orders: committed 1, lag 3-1=2, no in-flight (it acked).
        assert!(
            m.contains("ironbus_group_committed_offset{group=\"orders\"} 1"),
            "{m}"
        );
        assert!(
            m.contains("ironbus_group_consumer_lag{group=\"orders\"} 2"),
            "{m}"
        );
        assert!(
            m.contains("ironbus_group_in_flight{group=\"orders\"} 0"),
            "{m}"
        );
        // billing: committed 0, lag 3, one in-flight lease.
        assert!(
            m.contains("ironbus_group_consumer_lag{group=\"billing\"} 3"),
            "{m}"
        );
        assert!(
            m.contains("ironbus_group_in_flight{group=\"billing\"} 1"),
            "{m}"
        );
        // The Prometheus text format requires a metric family to be contiguous: every
        // committed-offset sample must precede every lag sample, which must precede every
        // in-flight sample. A strict parser rejects an interleaved family.
        let last_committed = m.rfind("\nironbus_group_committed_offset{").unwrap();
        let first_lag = m.find("\nironbus_group_consumer_lag{").unwrap();
        let last_lag = m.rfind("\nironbus_group_consumer_lag{").unwrap();
        let first_in_flight = m.find("\nironbus_group_in_flight{").unwrap();
        assert!(
            last_committed < first_lag && last_lag < first_in_flight,
            "per-group metric families must be contiguous, not interleaved: {m}"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_request_split_across_tcp_segments_is_handled() {
        let (addr, shutdown, handle, _engine) = start();
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // Send the request line in two segments with a gap, so the server does two reads. With
        // the accepted socket left non-blocking, the second read would WouldBlock and drop the
        // connection; a blocking socket waits for the rest. This pins the set_nonblocking(false).
        c.write_all(b"GET /heal").unwrap();
        c.flush().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        c.write_all(b"thz HTTP/1.1\r\n\r\n").unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        let resp = String::from_utf8_lossy(&out);
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "split request handled: {resp}"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_bare_newline_request_line_does_not_panic() {
        let (addr, shutdown, handle, _engine) = start();
        // A malformed request (just a newline) yields 405 (empty method != GET), never a panic.
        let r = request(addr, "\r\n");
        assert!(r.starts_with("HTTP/1.1 405"), "{r}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// Like [`start`] but with the opt-in `/admin` endpoint ENABLED and a config with several
    /// NON-default, distinctive bounds, so the admin config echo can be asserted exactly (#99).
    fn start_with_admin() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default().with_max_total_bytes(1_000_000),
                lease: LeaseConfig {
                    visibility_nanos: 1234,
                    hard_cap_nanos: 5678,
                },
                delivery: DeliveryConfig::new(7, false, vec![]).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 4096,
                checkpoint_interval: 1024,
                max_retained_bytes: 2048,
                max_age_ms: 99,
                max_messages: 33,
                max_groups: 100,
                group_idle_evict_ms: 0,
                disk_full_policy: DiskFullPolicy::DropOldest,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            // admin_enabled = true: this harness exercises the opt-in introspection endpoint.
            move || serve_health(&listener, &shared, &shutdown, true).unwrap()
        });
        (addr, shutdown, handle, engine)
    }

    /// Splits a raw HTTP response into (status line, body), so a JSON body can be parsed apart
    /// from the headers.
    fn split_body(raw: &str) -> (&str, &str) {
        let mut parts = raw.splitn(2, "\r\n\r\n");
        let head = parts.next().unwrap_or("");
        let body = parts.next().unwrap_or("");
        let status = head.lines().next().unwrap_or("");
        (status, body)
    }

    #[test]
    fn admin_is_404_when_the_flag_is_off() {
        // The endpoint is opt-in: with admin disabled (the default `start` harness) `/admin` is
        // indistinguishable from any unknown path, a 404, so the surface is invisible.
        let (addr, shutdown, handle, _engine) = start();
        let r = request(addr, "GET /admin HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 404 Not Found"), "{r}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_rejects_a_non_get_method() {
        // The endpoint is GET-only: even with admin ENABLED a non-GET is rejected with 405
        // (the method check precedes the path match), so no verb can carry a mutation.
        let (addr, shutdown, handle, _engine) = start_with_admin();
        for verb in ["POST", "PUT", "DELETE", "PATCH"] {
            let r = request(addr, &format!("{verb} /admin HTTP/1.1\r\n\r\n"));
            assert!(
                r.starts_with("HTTP/1.1 405 Method Not Allowed"),
                "{verb}: {r}"
            );
        }
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_returns_a_json_snapshot_with_correct_values() {
        let (addr, shutdown, handle, engine) = start_with_admin();
        // Drive a known broker state: produce 3, group "orders" acks the first (committed 1),
        // group "billing" leases one without acking (1 in-flight, committed 0).
        {
            let mut g = engine.lock().unwrap();
            for payload in [&b"a"[..], &b"b"[..], &b"c"[..]] {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                })
                .unwrap();
            }
            match g.poll_in("orders", 0).unwrap() {
                Poll::Message(d) => assert_eq!(g.ack_in("orders", &d.token), AckResult::Acked),
                other => panic!("expected a message, got {other:?}"),
            }
            assert!(matches!(g.poll_in("billing", 0).unwrap(), Poll::Message(_)));
        }

        let r = request(addr, "GET /admin HTTP/1.1\r\n\r\n");
        let (status, body) = split_body(&r);
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(
            r.contains("Content-Type: application/json"),
            "the admin body is JSON: {r}"
        );

        // The body is well-formed, documented JSON: it parses, and the load-bearing fields carry
        // the values the known broker state produced. Asserting on substrings (not a JSON lib,
        // which the crate does not depend on) keeps the test dependency-free; each field is
        // anchored to its key so a value cannot false-match across fields.
        assert!(body.starts_with('{') && body.ends_with('}'), "{body}");
        assert!(body.contains("\"schema_version\":1"), "{body}");

        // Broker level: 3 produced, durable head 3, default-group committed 0, lag 3.
        assert!(body.contains("\"flushed_offset\":3"), "{body}");
        assert!(body.contains("\"committed_offset\":0"), "{body}");
        assert!(body.contains("\"consumer_lag\":3"), "{body}");
        assert!(body.contains("\"produced\":3"), "{body}");
        assert!(body.contains("\"delivered\":2"), "{body}");
        assert!(body.contains("\"acks\":1"), "{body}");
        assert!(body.contains("\"healthy\":true"), "{body}");
        assert!(body.contains("\"segment_count\":1"), "{body}");

        // Per-group: the default group (""), orders (committed 1, lag 2, in-flight 0), billing
        // (committed 0, lag 3, in-flight 1).
        assert!(
            body.contains("\"name\":\"\""),
            "default group present: {body}"
        );
        assert!(
            body.contains(
                "{\"name\":\"orders\",\"committed_offset\":1,\"consumer_lag\":2,\"in_flight\":0}"
            ),
            "{body}"
        );
        assert!(
            body.contains(
                "{\"name\":\"billing\",\"committed_offset\":0,\"consumer_lag\":3,\"in_flight\":1}"
            ),
            "{body}"
        );

        // DLQ: nothing dead-lettered yet, so depth 0 and the -1 sentinel.
        assert!(body.contains("\"records\":0"), "{body}");
        assert!(body.contains("\"last_dead_lettered_offset\":-1"), "{body}");

        // Config echo: the distinctive non-default bounds the harness configured.
        assert!(body.contains("\"max_total_bytes\":1000000"), "{body}");
        assert!(body.contains("\"max_retained_bytes\":2048"), "{body}");
        assert!(body.contains("\"max_age_ms\":99"), "{body}");
        assert!(body.contains("\"max_messages\":33"), "{body}");
        assert!(body.contains("\"max_in_flight\":16"), "{body}");
        assert!(body.contains("\"consumer_credit\":64"), "{body}");
        assert!(body.contains("\"consumer_credit_bytes\":4096"), "{body}");
        assert!(body.contains("\"max_deliver\":7"), "{body}");
        assert!(body.contains("\"max_groups\":100"), "{body}");
        assert!(body.contains("\"visibility_nanos\":1234"), "{body}");
        assert!(body.contains("\"hard_cap_nanos\":5678"), "{body}");
        assert!(
            body.contains("\"disk_full_policy\":\"drop-oldest\""),
            "{body}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_reports_the_dlq_state_after_a_dead_letter() {
        use ironbus_core::clock::ManualClock;
        // A broker that dead-letters one message reports the DLQ depth and last offset on /admin.
        let clock = Arc::new(ManualClock::new());
        let engine = Engine::open(
            InMemoryFs::new(),
            Arc::clone(&clock),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(1, false, vec![]).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: crate::engine::DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, Arc<ManualClock>> = Arc::new(Mutex::new(engine));
        {
            let mut g = shared.lock().unwrap();
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"poison",
            })
            .unwrap();
            let _ = g.poll_now().unwrap();
            clock.advance_monotonic_nanos(40);
            assert!(matches!(g.poll_now().unwrap(), Poll::Parked { .. }));
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let shared = Arc::clone(&shared);
            move || serve_health(&listener, &shared, &shutdown, true).unwrap()
        });

        let r = request(addr, "GET /admin HTTP/1.1\r\n\r\n");
        let (status, body) = split_body(&r);
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{r}");
        // One record dead-lettered into the durable sink: depth 1, last offset 0.
        assert!(body.contains("\"records\":1"), "{body}");
        assert!(body.contains("\"last_dead_lettered_offset\":0"), "{body}");
        assert!(body.contains("\"dead_lettered\":1"), "{body}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_group_name_is_json_escaped() {
        // A group name carrying a quote and a backslash is JSON-escaped so the body stays
        // well-formed (the engine validates names as graphic ASCII, but the escape is
        // unconditional for robustness, #99).
        assert_eq!(escape_json("plain"), "plain");
        assert_eq!(escape_json("a\"b"), "a\\\"b");
        assert_eq!(escape_json("a\\b"), "a\\\\b");
        assert_eq!(escape_json("a\tb"), "a\\tb");
    }
}
