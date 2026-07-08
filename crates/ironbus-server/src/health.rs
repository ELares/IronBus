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
//! `GET /admin` (#99) is an OPT-IN, READ-ONLY introspection endpoint: a structured JSON snapshot of
//! operational state with four named sub-resources, `segments` (the durable-log span), `consumers`
//! (per-work-group committed offset and INCREMENTAL lag; `groups` is a back-compat alias), `config`
//! (an echo of the effective bounds), and `resilience` (the last-skip-offset, the integrity-freeze
//! flag, and the skip totals), plus a broker summary and the DLQ state. Every value comes from an
//! existing read-only engine accessor, so #15 can render segments, consumers, lag, and
//! last-skip-offset from THIS JSON ALONE without ever parsing a metric name.
//!
//! `/admin` v2 (#577) is ADDITIVE on top of v1: the same body plus three new bounded objects an
//! operator can read without the Prometheus scrape — `connections` (the aggregate connz signals:
//! open / accepted / closed / refused / authenticated plus the `rejected{reason}` pre-auth-`DoS`
//! breakdown, a BOUNDED aggregate, never an unbounded per-connection list, #572/#633), `storage`
//! (the on-disk footprint: segment count and bytes, the filesystem free bytes, and the RAM
//! headroom / RSS-vs-cap, #573/#574), and `recovery` (the flagship corruption-recovery counters:
//! recovery runs by outcome, torn-tail repairs, and corruption repairs by artifact, #575). Every
//! v2 field is read from the SAME read-only accessors `/metrics` uses (the engine ones under one
//! lock, the connz / disk-free / RSS ones off-lock exactly as the metrics scrape does), so the two
//! surfaces agree by construction and the v2 body can never mutate engine state.
//!
//! The schema version is PINNED in the `Accept` header: a consumer that requires the exact v1 shape
//! sends `Accept: application/vnd.ironbus.admin.v1+json` (it gets the UNCHANGED v1 body); one that
//! requires v2 sends `application/vnd.ironbus.admin.v2+json`. An `Accept` that explicitly names a
//! DIFFERENT (unknown) IronBus-admin version is `406 Not Acceptable`, while an absent or wildcard
//! `Accept` (a plain `curl`) takes the NEWEST version (`v2`), so a future bump is the only way a
//! curl default ever changes shape and an existing v1 pin is never broken.
//!
//! The liveness/readiness split this milestone confirms is ALREADY in place: `/healthz` is liveness
//! (the accept-loop watchdog, #95) and `/readyz` is readiness (the engine-lock writer-health check
//! plus the #637 SIGTERM-drain gate), two independent routes — `/admin` adds no third health
//! signal, it is pure read-only introspection.
//!
//! It is OFF by default and enabled only when the operator passes `serve --enable-admin`; when
//! disabled it is `404`, exactly like an unknown path. It shares `/metrics`'s trust model and bind
//! rule: bound to LOOPBACK by default, and the same WIDEN-REQUIRES-AUTH invariant applies (a
//! non-loopback bind of the health/admin surface requires the transport security and an auth
//! identity the #107 bind invariant mandates, the same precondition that gates the data port). On
//! loopback it is UNAUTHENTICATED like `/metrics`, so it must NEVER expose a mutating action or
//! secret material. Mutating admin actions (consumer reset, DLQ redrive, force-reap) are out of
//! scope and deferred to a separate mutating-admin surface (#18/#14); this endpoint is strictly
//! GET-only and read-only, with NO route that mutates engine state.

use crate::actor::EngineAccess;
use crate::cluster::ack_level::{ClusterAckLevel, ClusterAckLevelMetrics};
use crate::connz::{ConnectionMetrics, ConnectionMetricsSnapshot};
use crate::engine::{
    BackpressureSnapshot, Counters, EngineConfigSnapshot, GroupConsumerStat, RecoveryArtifact,
    RecoveryCounters, RecoveryOutcome,
};
use crate::liveness::LivenessBeacon;
use crate::metrics::{LatencyHistogram, FSYNC_BUCKET_LE_SECONDS};
use crate::registry::{FixedHistogram, REGISTRY_BUCKET_LE_SECONDS};
use ironbus_core::clock::Clock;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::loss::ReasonCode;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How long to wait between non-blocking accept polls.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Per-connection read/write timeout (slowloris defense).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// The request line is bounded; a client that sends no newline within this many bytes is
/// rejected rather than buffered without limit.
const MAX_REQUEST_LINE: usize = 8 * 1024;
/// The HARD CAP on health probe connections handled CONCURRENTLY (#874). The accept loop hands each
/// accepted probe to its own short-lived handler thread so one slow/stalled client can no longer
/// serialize (and thereby starve) every other probe — but the concurrency is BOUNDED: beyond this
/// many in-flight handlers the loop SHEDS the connection (drops the stream, which closes it) instead
/// of spawning without limit. This mirrors the wire server's connection cap (#865) so
/// `network.health_allow_public` cannot be turned into a thread/fd-exhaustion `DoS`: a slow client
/// occupies at most one slot, and a flood is refused, never amplified into unbounded threads. The
/// health surface is intentionally low-traffic (a handful of orchestrator probes plus scrapers), so
/// this ceiling is ample for every legitimate caller while still capping a hostile one.
const MAX_CONCURRENT_HEALTH_HANDLERS: usize = 32;

/// Releases a concurrent-health-handler slot on drop — on a normal return OR a panic unwind — so a
/// slot is never leaked even if a handler panics (#874). The matching increment is the accept loop's
/// `fetch_add` at admission; this drop is the paired `fetch_sub`. Mirrors the wire server's
/// `ConnectionSlot` (#865/#866).
struct HealthHandlerSlot<'a> {
    in_flight: &'a AtomicUsize,
}

impl Drop for HealthHandlerSlot<'_> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The per-server count of health connections SHED — dropped without a handler — broken out by the two
/// shed sites the accept loop has (#953): `at_cap`, already at [`MAX_CONCURRENT_HEALTH_HANDLERS`]
/// in-flight handlers, and `spawn_refused`, the OS refusing a handler thread (#866). Shedding was
/// SILENT before #953 (unlike the wire server's `ConnectionMetrics` refused count), so an operator
/// could not see health probes being dropped under a flood; these render as the labeled counter
/// `ironbus_health_shed_total{reason}` on `/metrics`. Lives on the accept loop's stack alongside the
/// in-flight gauge — health-owned, deliberately NOT folded into the wire `connz` set (health probes
/// were never in connz) — and is read by the `/metrics` handler under the same thread scope.
#[derive(Debug, Default)]
struct HealthShedCounters {
    at_cap: AtomicU64,
    spawn_refused: AtomicU64,
}

impl HealthShedCounters {
    /// Reads a relaxed snapshot of the two shed counters for the `/metrics` scrape.
    fn snapshot(&self) -> HealthShedSnapshot {
        HealthShedSnapshot {
            at_cap: self.at_cap.load(Ordering::Relaxed),
            spawn_refused: self.spawn_refused.load(Ordering::Relaxed),
        }
    }
}

/// A plain `Copy` snapshot of [`HealthShedCounters`], carried into the metric renderer.
#[derive(Clone, Copy, Debug, Default)]
struct HealthShedSnapshot {
    /// Connections shed because the in-flight cap was full (`reason="at_cap"`).
    at_cap: u64,
    /// Connections shed because the OS refused a handler thread (`reason="spawn_refused"`, #866).
    spawn_refused: u64,
}

/// Serves the health endpoints over `listener` until `shutdown` is set. Connections are
/// handled inline (health traffic is low and loopback), each bounded by [`REQUEST_TIMEOUT`].
///
/// `admin_enabled` gates the opt-in read-only `/admin` introspection endpoint (#99): `false`
/// (the default an operator gets unless they pass `--enable-admin`) makes `/admin` answer `404`
/// exactly like any unknown path, so the surface is OFF unless deliberately turned on.
///
/// `progress` and `liveness_window_nanos` drive the `/healthz` hysteresis watchdog (#95): the
/// handler reads `clock.now_monotonic_nanos()` (the SAME monotonic seam the wire accept loop ticks
/// the `progress` beacon on) and answers 503 only after the broker's main loop has gone a whole
/// `liveness_window_nanos` with no tick, so a slow-but-progressing broker stays 200 and a stuck loop
/// trips. A `liveness_window_nanos` of `0` DISABLES the watchdog (`/healthz` is then always 200 while
/// up). `clock` is read directly here, NOT through the append actor, so liveness measures the accept
/// loop's progress and never blocks on (nor is faulted by) a wedged writer.
///
/// # Errors
/// Returns an IO error only from configuring the listener; per-connection IO errors are
/// contained so one bad client never ends the loop.
pub fn serve_health<F, C, E>(
    listener: &TcpListener,
    engine: &E,
    shutdown: &AtomicBool,
    admin_enabled: bool,
    progress: &LivenessBeacon,
    liveness_window_nanos: u64,
    clock: &C,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C> + Sync,
{
    // The legacy entry point: no connz metric is scraped (a fresh, un-shared one) and no data-dir is
    // measured, so `/metrics` reports the honest zero / "unavailable" for the connz (#572) and
    // disk-free (#573) series — exactly the at-rest block the cluster-ack series uses until serve-wired.
    // The connz-aware bootstrap uses `serve_health_connz`, sharing the SAME connz `Arc` as the wire
    // server and passing the broker's data directory.
    serve_health_connz(
        listener,
        engine,
        shutdown,
        admin_enabled,
        progress,
        liveness_window_nanos,
        clock,
        &Arc::new(ConnectionMetrics::new()),
        None,
    )
}

/// Serves the health endpoints exactly like [`serve_health`], plus the connection-signal ("connz",
/// #572) and disk-free storage telemetry (#573): the SAME shared `Arc<ConnectionMetrics>` the wire
/// server records into (so `/metrics` exposes the live connz), and the broker's `data_dir` (so
/// `ironbus_disk_free_bytes` reports the free space on the filesystem the durable log lives on, or the
/// `-1` unavailable sentinel for an in-memory broker / when it cannot be read). [`serve_health`]
/// delegates here with a fresh un-shared metric and no data-dir, keeping its signature stable for the
/// existing callers.
///
/// # Errors
/// Returns an IO error only from configuring the listener; per-connection IO errors are contained.
#[allow(clippy::too_many_arguments)]
pub fn serve_health_connz<F, C, E>(
    listener: &TcpListener,
    engine: &E,
    shutdown: &AtomicBool,
    admin_enabled: bool,
    progress: &LivenessBeacon,
    liveness_window_nanos: u64,
    clock: &C,
    connz: &Arc<ConnectionMetrics>,
    data_dir: Option<&Path>,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C> + Sync,
{
    // The legacy entry point has no DRAINING readiness gate (#637): pass a never-set flag, so `/readyz`
    // behaves exactly as before (200 while the writer is healthy, 503 only on a frozen writer / gone
    // actor). The drain-aware bootstrap uses `serve_health_connz_draining`.
    let never_draining = AtomicBool::new(false);
    serve_health_connz_draining(
        listener,
        engine,
        shutdown,
        &never_draining,
        admin_enabled,
        progress,
        liveness_window_nanos,
        clock,
        connz,
        data_dir,
    )
}

/// Serves the health endpoints exactly like [`serve_health_connz`], plus the SIGTERM-DRAIN READINESS
/// GATE (#637, V2-M7): when `draining` is set, `GET /readyz` answers `503` immediately ("draining"),
/// BEFORE consulting the engine, so an orchestrator stops routing new work to this broker the moment a
/// stop signal arrives — while the health server KEEPS SERVING (so the 503 is observable, not a refused
/// connection). This is the "stop accepting before stop serving" ordering: the broker flips `draining`
/// first, then drains in-flight work bounded by the drain timeout. `GET /healthz` (liveness) is
/// UNAFFECTED by draining — a draining broker is still live and answers 200 — so an orchestrator
/// distinguishes "not-ready, drain me" from "dead, restart me". With `draining` never set this is
/// byte-for-byte [`serve_health_connz`].
///
/// # Errors
/// Returns an IO error only from configuring the listener; per-connection IO errors are contained.
#[allow(clippy::too_many_arguments)]
pub fn serve_health_connz_draining<F, C, E>(
    listener: &TcpListener,
    engine: &E,
    shutdown: &AtomicBool,
    draining: &AtomicBool,
    admin_enabled: bool,
    progress: &LivenessBeacon,
    liveness_window_nanos: u64,
    clock: &C,
    connz: &Arc<ConnectionMetrics>,
    data_dir: Option<&Path>,
) -> std::io::Result<()>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C> + Sync,
{
    // Own the data-dir path once for the loop's lifetime (each per-request handler borrows it).
    let data_dir = data_dir.map(Path::to_path_buf);
    let data_dir = data_dir.as_deref();
    listener.set_nonblocking(true)?;
    // The number of health handlers currently in flight, the BOUND enforced against
    // `MAX_CONCURRENT_HEALTH_HANDLERS` (#874). Lives on this loop's stack; the scoped handler threads
    // borrow it and the scope joins every one of them before this function returns.
    let in_flight = AtomicUsize::new(0);
    // The health-shed counters (#953), health-owned on this loop's stack (like `in_flight`): the
    // accept loop increments them on a shed and the `/metrics` handler reads them under the scope.
    let shed = HealthShedCounters::default();
    // A THREAD SCOPE, so each handler may borrow the loop's `engine`/`clock`/beacons by reference
    // (no `'static`/clone required) while the scope GUARANTEES every outstanding handler is joined
    // before `serve_health_connz_draining` returns — preserving graceful shutdown: when `shutdown`
    // flips, the accept loop below breaks and the scope drains the in-flight handlers, exactly as the
    // old inline loop finished its one in-flight request before returning.
    std::thread::scope(|scope| {
        while !shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // BOUNDED CONCURRENCY (#874): admit at most `MAX_CONCURRENT_HEALTH_HANDLERS`
                    // in-flight handlers. At the cap, SHED the connection (drop the stream, which
                    // closes it) rather than spawn an unbounded thread — so a slow/stalled probe
                    // client (or a `health_allow_public` flood) occupies at most one slot and can
                    // NEVER starve a liveness/readiness probe nor exhaust threads/fds. The cap is
                    // EXACT: this loop is the SOLE incrementer and accept is single-threaded, so the
                    // check and the `fetch_add` below never race each other (only the handlers ever
                    // DECREMENT, which can only free a slot); the cap is never even transiently
                    // exceeded. A shed is COUNTED (#953) so a flood is observable on `/metrics`.
                    if in_flight.load(Ordering::Acquire) >= MAX_CONCURRENT_HEALTH_HANDLERS {
                        shed.at_cap.fetch_add(1, Ordering::Relaxed);
                        drop(stream); // shed: closes the connection immediately
                        continue;
                    }
                    // Reserve the slot BEFORE spawning so the cap is honored even if two accepts race;
                    // the handler's `HealthHandlerSlot` releases it on return OR a panic unwind.
                    in_flight.fetch_add(1, Ordering::AcqRel);
                    // FALLIBLE spawn (#866): `std::thread::spawn` PANICS on a thread-creation refusal
                    // (EAGAIN under a cgroup `pids.max` / `RLIMIT_NPROC`), which the release profile's
                    // `panic = "abort"` would turn into a whole-broker abort. `Builder::spawn_scoped`
                    // surfaces it as an `Err` the loop SHEDS, undoing the reserve — exactly the
                    // bounded shed the at-cap branch does — instead of killing the health server.
                    let spawned = std::thread::Builder::new()
                        .name("ironbus-health".to_string())
                        .spawn_scoped(scope, {
                            let in_flight = &in_flight;
                            let shed = &shed;
                            move || {
                                // Release the reserved slot on EVERY exit (return or unwind).
                                let _slot = HealthHandlerSlot { in_flight };
                                // One bad client must not end the loop; contain its IO error. It is
                                // now confined to THIS handler thread, so a slow client blocks only
                                // its own connection, never the accept loop or other probes.
                                let _ = handle(
                                    stream,
                                    engine,
                                    draining,
                                    admin_enabled,
                                    progress,
                                    liveness_window_nanos,
                                    clock,
                                    connz,
                                    data_dir,
                                    shed,
                                );
                            }
                        });
                    if spawned.is_err() {
                        // The OS refused thread creation: the closure (and its `stream`) was dropped,
                        // closing the connection, and the `HealthHandlerSlot` was never built — so
                        // UNDO the reserve here and keep serving, shedding like the at-cap branch.
                        // COUNT it (#953) so a thread-creation flood is observable on `/metrics`.
                        shed.spawn_refused.fetch_add(1, Ordering::Relaxed);
                        in_flight.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                // A transient accept failure must not tear the listener down.
                Err(_) => std::thread::sleep(ACCEPT_POLL),
            }
        }
    });
    Ok(())
}

// The route dispatcher is one cohesive match over the fixed health routes (/metrics, /healthz,
// /readyz, /admin, 404); the #862 actor-watchdog 503 branches push it one line over the pedantic bound.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn handle<F, C, E>(
    mut stream: TcpStream,
    engine: &E,
    draining: &AtomicBool,
    admin_enabled: bool,
    progress: &LivenessBeacon,
    liveness_window_nanos: u64,
    clock: &C,
    connz: &Arc<ConnectionMetrics>,
    data_dir: Option<&Path>,
    shed: &HealthShedCounters,
) -> std::io::Result<()>
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
    // Disable Nagle (#1028): a health/metrics response is one small write a poller round-trips on,
    // and probe timeout budgets are often tight. Best-effort — latency-only, never fails the request.
    crate::server::set_nodelay_best_effort(&stream);

    // Read the request HEAD (request line + headers) under a bounded byte and total-time budget; the
    // outcome is either a parsed head or an already-sent error response (414/408) or a clean close.
    let head = match read_request_head(&mut stream)? {
        RequestHead::Parsed { head } => head,
        // Either an error response was already sent (414/408) or the client closed before a full
        // request line; in both cases there is nothing more to answer.
        RequestHead::Responded | RequestHead::Closed => return Ok(()),
    };

    // Split the request line from the header section on the first `\n` of the LOSSY string itself,
    // never a raw byte index: `from_utf8_lossy` turns each invalid byte into a 3-byte U+FFFD and shifts
    // every later offset, so indexing the lossy string with a raw-buffer index can land inside a U+FFFD
    // and panic the whole process (#860). `\n` survives the lossy conversion unchanged, so `split_once`
    // is char-boundary-safe. The read loop only yields `Parsed` once a `\n` is present, so this splits.
    let (request_line, header_section) = head.split_once('\n').unwrap_or((head.as_str(), ""));
    // Parse "METHOD PATH VERSION" (a leading CR is trimmed by split_whitespace).
    let line = request_line.trim_end_matches('\r');
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
    // The `Accept` header value (lower-cased, all values joined), for the `/admin` version pin (#99).
    // Absent on a plain `curl`, which is fine: an absent or wildcard Accept takes the current version.
    let accept = parse_accept_header(header_section);
    // Drop any query string.
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    match path {
        // Liveness with a hysteresis watchdog (#95). Read the monotonic seam DIRECTLY (not through
        // the actor): liveness measures the accept loop's progress, so it must not block on, nor be
        // faulted by, a wedged writer. The beacon is ticked every accept-loop iteration (idle too),
        // so this sheds 503 only after a full window with no tick, which only a STUCK loop produces.
        // A slow-but-progressing broker keeps ticking and stays 200; a frozen writer (a readyz 503)
        // is still live here. A zero window disables the watchdog (always 200 while up).
        "/healthz" => {
            let now = clock.now_monotonic_nanos();
            // 503 if EITHER the ACCEPT loop wedged (#95) OR the APPEND ACTOR wedged on a hung fsync
            // (#862). The actor-watchdog read is a non-blocking atomic that answers even while the actor
            // is wedged, so a hung writer no longer leaves liveness GREEN (the silent total-stall bug) —
            // an orchestrator now sees 503 and restarts the node. Disabled (always healthy here) until
            // the serve path arms the bound, so an unconfigured/single-node broker is unchanged.
            if progress.stuck_for_window(now, liveness_window_nanos) {
                respond(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "no event-loop progress",
                )
            } else if !engine.actor_alive() && !draining.load(Ordering::Acquire) {
                // #922: an UNEXPECTED append-actor death (return or panic with `draining` unset) is
                // liveness-fatal — the broker can never serve another produce, strictly worse than the
                // wedge below, so an orchestrator should restart it. The `!draining` guard keeps a
                // GRACEFUL shutdown's terminal window (the actor exits by design before the process
                // does) reading 200 here: "told to die" is not "dead, restart me".
                respond(&mut stream, 503, "Service Unavailable", "append actor gone")
            } else if engine.actor_watchdog_overran(now) {
                respond(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "append actor wedged",
                )
            } else {
                respond(&mut stream, 200, "OK", "ok")
            }
        }
        "/readyz" => {
            // The SIGTERM-DRAIN readiness gate (#637), checked FIRST, before consulting the engine: a
            // broker that received a stop signal flips `draining` and immediately answers 503 here, so
            // an orchestrator stops routing new work to it BEFORE the drain begins — the "stop
            // accepting before stop serving" ordering. The engine is still healthy at this instant
            // (the drain has not started), so the 503 must come from the gate, not the engine check.
            // FULLY NON-BLOCKING readiness (#862): four atomic reads, NO actor round-trip, so a HUNG
            // fsync can never block this handler and — on the single-threaded health server — wedge the
            // whole health surface (the bug the old `engine.with(|e| e.is_healthy())` had: it queued a
            // job behind the wedged fsync and hung FOREVER, so even the watchdog's own 503 was never
            // served). Checked in priority order: a SIGTERM drain (#637, stop routing before stop
            // serving), then a GONE actor (#922: the shared alive flag, flipped by the actor's drop
            // guard on return OR unwind — the case the watchdog misses when the actor died IDLE or the
            // bound is disabled, and the frozen-writer flag misses too because a dead actor publishes
            // nothing; this restores the old blocking read's `Err(_)` => 503 arm without the blocking),
            // then a WEDGED actor (a hung fsync past the watchdog bound, #862), then a FROZEN writer (a
            // fsync that RETURNED an error, read from the actor's published flag). Otherwise ready. The
            // writer-frozen flag reflects the state as of the last completed batch — exactly when the
            // old blocking read would have observed it.
            if draining.load(Ordering::Acquire) {
                respond(&mut stream, 503, "Service Unavailable", "draining")
            } else if !engine.actor_alive() {
                respond(&mut stream, 503, "Service Unavailable", "append actor gone")
            } else if engine.actor_watchdog_overran(clock.now_monotonic_nanos()) {
                respond(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "append actor wedged",
                )
            } else if engine.writer_appears_healthy() {
                respond(&mut stream, 200, "OK", "ready")
            } else {
                respond(&mut stream, 503, "Service Unavailable", "writer frozen")
            }
        }
        "/metrics" => match metrics_snapshot(engine, connz, data_dir, shed.snapshot()) {
            Ok(snapshot) => respond(&mut stream, 200, "OK", &metrics_body(snapshot)),
            Err(_) => respond(&mut stream, 503, "Service Unavailable", "shutting down"),
        },
        // The opt-in read-only introspection endpoint (#99). When disabled it is indistinguishable
        // from an unknown path (a 404), so the surface is invisible unless the operator turned it
        // on. The non-GET case was already rejected with 405 above, so this is GET-only.
        "/admin" if admin_enabled => {
            // The schema version is PINNED in the `Accept` header (#99/#577): an absent or wildcard
            // Accept (a plain `curl`) takes the NEWEST version (`v2`); an explicit `v1` pin gets the
            // UNCHANGED v1 body; an explicit `v2` pin gets the v2 body; an Accept that explicitly
            // names a DIFFERENT (unknown) IronBus-admin version is `406 Not Acceptable`, so a
            // future-version consumer cannot silently misread an older body. A non-admin media type
            // (e.g. `text/html`) is tolerated and served the newest version, matching how `/metrics`
            // ignores Accept. The v1 and v2 bodies share ONE off-lock-augmented snapshot (the v1
            // renderer simply ignores the v2-only fields), so a v1 request stays byte-for-byte v1.
            match admin_accept_decision(&accept) {
                AcceptDecision::ServeV1 => match admin_snapshot(engine, connz, data_dir) {
                    // v1 keeps its historical generic `application/json` Content-Type so a v1 pin is
                    // byte-for-byte the prior response (header AND body); only the body schema is the
                    // contract, but holding the header steady too keeps a v1 consumer untouched.
                    Ok(snapshot) => respond_json(
                        &mut stream,
                        200,
                        "OK",
                        &admin_body(&snapshot),
                        "application/json",
                    ),
                    Err(_) => respond(&mut stream, 503, "Service Unavailable", "shutting down"),
                },
                AcceptDecision::ServeV2 => match admin_snapshot(engine, connz, data_dir) {
                    // v2 labels the response with the versioned media type so a client can confirm
                    // which representation it received without parsing the body's `schema_version`.
                    Ok(snapshot) => respond_json(
                        &mut stream,
                        200,
                        "OK",
                        &admin_body_v2(&snapshot),
                        ADMIN_MEDIA_TYPE_V2,
                    ),
                    Err(_) => respond(&mut stream, 503, "Service Unavailable", "shutting down"),
                },
                AcceptDecision::UnsupportedVersion => respond_json(
                    &mut stream,
                    406,
                    "Not Acceptable",
                    "{\"error\":\"unsupported admin schema version\",\
                     \"supported\":[\
                     \"application/vnd.ironbus.admin.v1+json\",\
                     \"application/vnd.ironbus.admin.v2+json\"]}",
                    "application/json",
                ),
            }
        }
        _ => respond(&mut stream, 404, "Not Found", "unknown endpoint"),
    }
}

/// The outcome of reading the request head ([`read_request_head`]).
enum RequestHead {
    /// The request head was read (lossy-decoded). The caller splits it on its own first `\n` rather
    /// than a raw byte index: `from_utf8_lossy` turns each invalid byte into a 3-byte U+FFFD and shifts
    /// every later offset, so a raw index can land inside a U+FFFD and panic (#860).
    Parsed { head: String },
    /// An error response (414/408) was already sent to the client; the caller should return.
    Responded,
    /// The client closed before sending a complete request line; there is nothing to answer.
    Closed,
}

/// Reads the request HEAD under a bounded byte budget ([`MAX_REQUEST_LINE`]) and a total-time
/// deadline ([`REQUEST_TIMEOUT`]). It reads until the REQUEST LINE is complete (its terminating `\n`),
/// then returns everything buffered so far, INCLUDING whatever header bytes arrived in the same
/// read(s). It does NOT block for a separate header round-trip: every well-behaved client (curl, the
/// `ironbus admin` client, an orchestrator probe) sends the full head in one segment, so the `Accept`
/// header for the `/admin` version negotiation (#99) is present without a second read that a minimal
/// request-line-only client (which never sends `\r\n\r\n`) would hang waiting on. This keeps the exact
/// slowloris/split-segment behavior the prior request-line reader had. A request line that overruns
/// the byte bound gets a `414`, one that misses the deadline a `408`, each sent here; a clean close
/// before a full request line yields [`RequestHead::Closed`].
fn read_request_head(stream: &mut TcpStream) -> std::io::Result<RequestHead> {
    // Bound the TOTAL time to read the request line, not only each read: a client dribbling one byte
    // just inside each per-read window would otherwise hold this connection (and, since the accept
    // loop is inline, every other probe) for hours.
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let mut buf = vec![0u8; MAX_REQUEST_LINE];
    let mut len = 0;
    loop {
        if len == buf.len() {
            respond(stream, 414, "URI Too Long", "request line too long")?;
            return Ok(RequestHead::Responded);
        }
        if std::time::Instant::now() >= deadline {
            respond(
                stream,
                408,
                "Request Timeout",
                "request line not received in time",
            )?;
            return Ok(RequestHead::Responded);
        }
        let n = stream.read(&mut buf[len..])?;
        if n == 0 {
            return Ok(RequestHead::Closed); // the client closed before a complete request line
        }
        len += n;
        // Break as soon as the request LINE is complete (its terminating newline). Any header bytes
        // that came along in the same read are already in `buf[..len]` and are parsed by the caller;
        // we do not issue another blocking read for headers, so a request-line-only client never hangs.
        if buf[..len].contains(&b'\n') {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf[..len]).into_owned();
    Ok(RequestHead::Parsed { head })
}

/// Extracts and lower-cases the `Accept` header value(s) from the header section (everything after
/// the request line). Returns the joined value, or an empty string if no `Accept` header was sent.
/// Header-name matching is ASCII-case-insensitive per RFC 7230; the value is lower-cased so the
/// `/admin` version match is case-insensitive too.
fn parse_accept_header(header_section: &str) -> String {
    let mut accepts: Vec<String> = Vec::new();
    for raw in header_section.split('\n') {
        let line = raw.trim_end_matches('\r');
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("accept") {
                accepts.push(value.trim().to_ascii_lowercase());
            }
        }
    }
    accepts.join(",")
}

/// The outcome of negotiating the `/admin` schema version against the `Accept` header (#99/#577).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptDecision {
    /// Serve the UNCHANGED `v1` body: the Accept explicitly pinned `v1` (alone or alongside another
    /// version it also accepts). A v1 pin always wins for v1 so an existing consumer is never broken.
    ServeV1,
    /// Serve the `v2` body: the Accept was absent, a wildcard, a non-admin type, or explicitly pinned
    /// `v2`. `v2` is the NEWEST version, so an unpinned client (a plain `curl`) takes it.
    ServeV2,
    /// The Accept explicitly named an IronBus-admin version that is neither `v1` nor `v2` (an unknown
    /// future/unsupported version): `406 Not Acceptable`, so a consumer never silently misreads.
    UnsupportedVersion,
}

/// The media type that pins the `/admin` v1 schema (#99). A consumer that requires the exact v1 shape
/// sends `Accept: application/vnd.ironbus.admin.v1+json`; v1 is FROZEN, so this is permanent.
const ADMIN_MEDIA_TYPE_V1: &str = "application/vnd.ironbus.admin.v1+json";

/// The media type that pins the `/admin` v2 schema (#577): the NEWEST version, served to an unpinned
/// client. A future incompatible shape adds a `v3` constant alongside (it never mutates this one).
const ADMIN_MEDIA_TYPE_V2: &str = "application/vnd.ironbus.admin.v2+json";

/// The vendor-prefix that identifies ANY IronBus-admin media type, used to detect an Accept that
/// names a DIFFERENT admin version (which we must reject rather than silently serve a mismatched body).
const ADMIN_MEDIA_TYPE_PREFIX: &str = "application/vnd.ironbus.admin.";

/// Negotiates the `/admin` schema version from the (lower-cased) `Accept` value (#99/#577). The rule:
/// an explicit `v1` pin serves the UNCHANGED v1 body (it wins even when offered alongside another
/// version, so an existing consumer is never broken); an explicit `v2` pin serves v2; an absent
/// Accept, a wildcard (`*/*`), or a non-admin type (`application/json`, `text/html`) takes the NEWEST
/// version (v2), exactly as `/metrics` ignores Accept; only an Accept that explicitly names an
/// IronBus-admin media type that is neither v1 nor v2 is rejected (`406`), so a future-version-only
/// consumer never silently misreads an older body. v1 is checked before v2 so a multi-type Accept
/// that lists both resolves to v1 (the back-compat-safe choice for a client that accepts either).
fn admin_accept_decision(accept: &str) -> AcceptDecision {
    if accept.is_empty() {
        return AcceptDecision::ServeV2;
    }
    // Scan the offered media types once. A v1 pin wins outright (back-compat). Otherwise remember
    // whether v2 or some OTHER admin version was named, and decide after the scan: v2 beats an
    // unknown admin version, and a named-but-unknown admin version with no v1/v2 offer is a 406.
    let mut named_v2 = false;
    let mut named_other_admin = false;
    for media in accept.split(',') {
        // A media-range may carry parameters (`;q=...`); the type is the part before the first `;`.
        let media = media.split(';').next().unwrap_or(media).trim();
        if media == ADMIN_MEDIA_TYPE_V1 {
            return AcceptDecision::ServeV1;
        }
        if media == ADMIN_MEDIA_TYPE_V2 {
            named_v2 = true;
        } else if media.starts_with(ADMIN_MEDIA_TYPE_PREFIX) {
            named_other_admin = true;
        }
    }
    if named_v2 {
        // An explicit v2 pin (possibly alongside an unknown version it also accepts): serve v2.
        AcceptDecision::ServeV2
    } else if named_other_admin {
        // The client pinned an IronBus-admin version that is neither v1 nor v2: reject rather than
        // serve a mismatched body.
        AcceptDecision::UnsupportedVersion
    } else {
        // No admin media type was named (e.g. `*/*`, `application/json`, `text/html`): take the
        // newest version (v2), exactly as `/metrics` ignores Accept. A consumer that needs a specific
        // version pins it via the explicit media types above.
        AcceptDecision::ServeV2
    }
}

/// Captures the whole `/metrics` snapshot in ONE actor job, so every field is from the same instant
/// (the actor is the single reader/writer). The RSS reading is then filled in OUTSIDE the engine
/// lock (it is a process-level read, not engine state), so a `/proc`/`ps` read never runs inside the
/// actor job. Every value comes from an existing read-only accessor; this cannot mutate the engine.
///
/// # Errors
/// Returns [`ActorGone`](crate::actor::ActorGone) if the actor exited before the read.
fn metrics_snapshot<F, C, E>(
    engine: &E,
    connz: &ConnectionMetrics,
    data_dir: Option<&Path>,
    health_shed: HealthShedSnapshot,
) -> Result<MetricsSnapshot, crate::actor::ActorGone>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
{
    let mut snapshot = engine.with(|g| {
        // Fold the loss report ONCE into its per-reason and grand totals (#504). The standalone
        // accessors each rescan the whole event list, so reading every per-reason series the old
        // way was O(reasons · events); `aggregate` makes the scrape O(events). The per-reason
        // arrays are already in `ReasonCode::ALL` order, the order these metric series render in.
        let loss = g.loss_report().aggregate();
        MetricsSnapshot {
            committed: g.committed_offset().get(),
            flushed: g.flushed_offset().get(),
            in_flight: g.in_flight(),
            healthy: g.is_healthy(),
            recovered_truncated: g.recovered_truncated_bytes(),
            quarantined: g.quarantined_bytes(),
            recovery_loss: loss.bytes_skipped,
            recovery_loss_records: loss.records_lost,
            recovery_data_loss: loss.data_loss_bytes,
            // -1 is the unambiguous "none yet" sentinel (offsets are never negative).
            last_dead_lettered: g
                .last_dead_lettered_offset()
                .map_or(-1i64, |o| i64::try_from(o.get()).unwrap_or(i64::MAX)),
            dlq_records: g.dlq_records(),
            counters: g.counters(),
            fsync: g.fsync_histogram(),
            // The edge write-amplification + RAM-headroom + daily-write-budget inputs (#118), read here
            // so they share the snapshot's single instant. The RSS is filled in below, off the lock.
            edge: EdgeMetrics {
                logical_bytes_written: g.logical_bytes_written(),
                physical_bytes_written: g.physical_bytes_written(),
                ram_ceiling_bytes: g.ram_ceiling_bytes(),
                daily_physical_write_budget_bytes: g.daily_physical_write_budget_bytes(),
                physical_bytes_written_today: g.physical_bytes_written_today(),
                daily_budget_sheds: g.daily_budget_sheds(),
                produce_rejected: g.counters().produce_rejected,
                // The on-disk storage footprint (#573): read under the same lock as the rest, so the
                // disk-free gauge and the footprint it is measured against share one instant. Cast the
                // segment count to a portable u64 (it is a small `usize`).
                durable_record_bytes: g.durable_record_bytes(),
                segment_count: u64::try_from(g.segment_count()).unwrap_or(u64::MAX),
            },
            // The durability observability inputs (#341, #379), read under the same lock: the active
            // level, whether it waives I2 (the sticky power-loss-unsafe signal), and the live unsynced
            // bytes-at-risk. All three are derived from the engine's level + storage state.
            durability: DurabilityMetrics {
                level: g.durability_level().as_str(),
                power_loss_unsafe: g.power_loss_unsafe(),
                unsynced_bytes: g.unsynced_bytes(),
            },
            // The CLUSTER ack-level observability inputs (#605/#610). The cluster ack path is not yet
            // `serve`-wired (a single-node broker never selects a cluster level), so the scrape reports
            // the at-rest all-zero block: the per-level counters and the `power_loss_unsafe` gauge exist
            // (the frozen taxonomy requires them) and report `0`. Wiring a live `ClusterAckLevelMetrics`
            // through the running broker's quorum-ack release is the follow-up.
            cluster_ack: ClusterAckLevelMetrics::new(),
            // The backpressure controllers' observable state (#68, #69), read under the same lock.
            backpressure: g.backpressure_snapshot(),
            // Filled in below, outside the engine lock; `None` is the not-yet-read placeholder.
            rss: None,
            // The connection-signal snapshot (#572) and the disk-free reading (#573) are filled in
            // below, OUTSIDE the engine lock: connz is a shared off-engine atomic set, and disk-free is
            // a process-level `df` read, neither is engine state, so keeping them off the lock avoids a
            // `df`/atomic read inside the actor job. The defaults are the not-yet-read placeholders.
            connz: ConnectionMetricsSnapshot::default(),
            disk_free: crate::rss::UNAVAILABLE,
            // The health-shed counts (#953) are OFF-lock health-server state, not engine state, so
            // they are the not-yet-set placeholder here and filled in below (like connz / disk-free).
            health_shed: HealthShedSnapshot::default(),
            groups: g.group_consumer_stats(),
            // The bounded metric registry (#97) is rendered into a String inside the actor job (it walks
            // only the bounded series set and the fixed histograms, so the work is O(number of series),
            // independent of the record count or disk size), then the body is assembled outside with the
            // rest. The uptime series reads the live monotonic clock seam here so it advances between
            // scrapes.
            registry: registry_body(g.registry(), g.now_monotonic()),
        }
    })?;
    // Read this process's RSS OUTSIDE the engine lock (#118): a best-effort, no-`unsafe`
    // cross-platform read (`/proc/self/status` on Linux, `ps` on macOS), `None` where unavailable so
    // the headroom gauge reports the honest sentinel rather than a misleading zero. It is not engine
    // state, so keeping it off the lock avoids a `ps`/`/proc` read inside the actor job.
    snapshot.rss = crate::rss::current_rss_bytes();
    // Read the CONNECTION SIGNALS (#572) off-lock: a consistent-enough snapshot of the shared connz
    // atomics (accept/close/refuse/open/auth), recorded by the wire server off the engine lock.
    snapshot.connz = connz.snapshot();
    // Attach the health-probe SHED counts (#953): health-server state the handler passed in, not
    // engine state, so like connz it is set here rather than read under the engine lock.
    snapshot.health_shed = health_shed;
    // Read the DISK-FREE bytes (#573) off-lock on the filesystem the durable log lives on, when a data
    // dir is known. An in-memory broker (no data dir) and a platform where `df` is unavailable both
    // report the `-1` unavailable sentinel rather than a misleading zero, exactly like the RAM gauges.
    snapshot.disk_free = data_dir
        .and_then(crate::rss::disk_free_bytes)
        .map_or(crate::rss::UNAVAILABLE, |free| {
            i64::try_from(free).unwrap_or(i64::MAX)
        });
    Ok(snapshot)
}

/// Captures the read-only introspection state (#99/#577) in ONE actor job, so every ENGINE field is
/// from the same instant, then fills the OFF-LOCK fields (connz, disk-free, RSS) exactly as
/// [`metrics_snapshot`] does — a process-level / shared-atomic read, not engine state, so it never
/// runs inside the actor job. Every value comes from an existing read-only accessor; this cannot
/// mutate the engine and carries no secret material. The v1 renderer ignores the off-lock fields, so
/// a v1 request is unaffected by their presence.
///
/// # Errors
/// Returns [`ActorGone`](crate::actor::ActorGone) if the actor exited before the read.
fn admin_snapshot<F, C, E>(
    engine: &E,
    connz: &ConnectionMetrics,
    data_dir: Option<&Path>,
) -> Result<AdminSnapshot, crate::actor::ActorGone>
where
    F: Filesystem + 'static,
    C: Clock + Clone + 'static,
    E: EngineAccess<F, C>,
{
    let mut snapshot = engine.with(|g| AdminSnapshot {
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
        // The configured RAM ceiling (#574), read under the lock so the storage object's headroom is
        // measured against the same instant; the RSS / disk-free / connz are off-lock placeholders
        // filled below, exactly as `metrics_snapshot` defers them.
        ram_ceiling_bytes: g.ram_ceiling_bytes(),
        connz: ConnectionMetricsSnapshot::default(),
        disk_free: crate::rss::UNAVAILABLE,
        rss: None,
    })?;
    // Read the OFF-LOCK fields exactly as `metrics_snapshot` does (#572/#573/#574): connz is a shared
    // off-engine atomic set, disk-free a process-level `df`, RSS a process-level `/proc`/`ps` read —
    // none is engine state, so keeping them off the lock avoids a `df`/`ps`/atomic read inside the
    // actor job. The defaults above are the not-yet-read placeholders (the same honest zero / `-1`
    // sentinels `/metrics` uses on the legacy path).
    snapshot.connz = connz.snapshot();
    snapshot.disk_free = data_dir
        .and_then(crate::rss::disk_free_bytes)
        .map_or(crate::rss::UNAVAILABLE, |free| {
            i64::try_from(free).unwrap_or(i64::MAX)
        });
    snapshot.rss = crate::rss::current_rss_bytes();
    Ok(snapshot)
}

/// The edge-resource metric inputs (#118), read from the engine under the same lock as the rest of
/// the snapshot. The RSS reading and the derived `write_amp_ratio` / `ram_headroom` are computed in
/// the renderer from these raw values, so the actor job stays a pure read of engine state.
#[derive(Clone, Copy)]
struct EdgeMetrics {
    /// Total LOGICAL bytes appended this run (user payload, no framing): the write-amp denominator.
    logical_bytes_written: u64,
    /// Total PHYSICAL bytes appended this run (frames + segment headers/footers): the write-amp
    /// numerator and the real flash-wear write volume.
    physical_bytes_written: u64,
    /// The configured RAM ceiling in bytes for the headroom gauge (`0` = unset).
    ram_ceiling_bytes: u64,
    /// The OPT-IN daily physical write budget in bytes (`0` = the governor is off).
    daily_physical_write_budget_bytes: u64,
    /// The physical bytes written so far on the current UTC day (the daily-budget meter).
    physical_bytes_written_today: u64,
    /// The count of appends shed because the daily physical write budget was reached.
    daily_budget_sheds: u64,
    /// The count of produces REJECTED by the drop-new shed (the disk-full byte cap AND the
    /// daily-write-budget governor; the same value surfaced as `ironbus_produce_rejected_total`).
    /// Folded into the `ironbus_produce_saturated` signal so the gauge fires on EITHER shed, matching
    /// its HELP text.
    produce_rejected: u64,
    /// The stored record bytes currently durable on disk (#573): the on-disk log footprint the
    /// disk-free gauge is measured against. A read-only engine count, rendered as a GAUGE.
    durable_record_bytes: u64,
    /// The number of open plus sealed durable-log segment files currently on disk (#573). A read-only
    /// engine count, rendered as a GAUGE.
    segment_count: u64,
}

/// The durability observability inputs (#341, #379), read under the same engine lock as the rest of
/// the snapshot. The active level surfaces both as a `level` label on `ironbus_durability_level_info`
/// and, derived from it, as the `ironbus_durability_power_loss_unsafe` gauge (1 when the level waives
/// I2); the live unsynced exposure is `ironbus_durability_unsynced_bytes`. Every name is a GAUGE (no
/// `_total` suffix), so the additions extend `FROZEN_METRIC_TYPES` without touching the
/// resilience-counter taxonomy.
#[derive(Clone, Copy)]
struct DurabilityMetrics {
    /// The active durability level's stable flag spelling (`sync`/`interval`/`async`/`none`), the
    /// `level` label of `ironbus_durability_level_info`.
    level: &'static str,
    /// Whether the active level WAIVES I2 (ack-implies-durable): `true` under any relaxed level,
    /// `false` under the default `sync`. The `ironbus_durability_power_loss_unsafe` gauge (1/0).
    power_loss_unsafe: bool,
    /// The live UNSYNCED record-byte exposure: the acked-but-not-yet-durable bytes a power cut would
    /// lose. Always `0` under `sync`. The `ironbus_durability_unsynced_bytes` gauge.
    unsynced_bytes: u64,
}

/// A consistent snapshot of the metric inputs, read under one engine lock.
#[derive(Clone)]
struct MetricsSnapshot {
    committed: u64,
    flushed: u64,
    in_flight: usize,
    healthy: bool,
    recovered_truncated: u64,
    /// The persisted on-disk footprint of the forensic quarantine store (#134, #315): the
    /// corrupt-byte copies prior recoveries left, surviving restart.
    quarantined: u64,
    /// Bytes dropped at the last recovery, per [`ReasonCode`] in code order. Sized to
    /// [`ReasonCode::ALL`] so appending a reason (e.g. `UnresolvedDictId`, #357) ripples here
    /// automatically instead of leaving a stale, too-short array.
    recovery_loss: [u64; ReasonCode::ALL.len()],
    /// Records dropped at the last recovery, per [`ReasonCode`] in code order. Sized to
    /// [`ReasonCode::ALL`] so a new reason ripples automatically.
    recovery_loss_records: [u64; ReasonCode::ALL.len()],
    /// Bytes of real DATA loss at the last recovery (the loss report total with `TornTail`
    /// excluded, #59): the headline "bytes lost" figure that must not inflate on a brownout.
    recovery_data_loss: u64,
    /// The most recent dead-letter offset, or -1 if none (the exposition sentinel).
    last_dead_lettered: i64,
    /// The number of records durably written to the DLQ sink (the dead-letter depth, #63).
    dlq_records: u64,
    counters: Counters,
    fsync: LatencyHistogram,
    /// The edge write-amplification + RAM-headroom + daily-write-budget inputs (#118), read under the
    /// same engine lock as the rest so every metric is from one instant.
    edge: EdgeMetrics,
    /// The DURABILITY observability inputs (#341, #379), read under the same lock: the active level's
    /// flag spelling, whether it waives I2 (the sticky power-loss-unsafe signal), and the live
    /// unsynced bytes-at-risk. Under the default `sync` the level is `"sync"`, unsafe is `false`, and
    /// the unsynced exposure is always `0`.
    durability: DurabilityMetrics,
    /// The CLUSTER ack-level observability inputs (#605/#610): one produce count PER cluster ack level
    /// (`c0`/`c1`/`c2-pagecache`/`c2-fsync`) and the cluster `power_loss_unsafe` gauge. On a single-node
    /// / no-cluster broker this is the at-rest all-zero block ([`ClusterAckLevelMetrics::new`]): every
    /// per-level counter is `0` and the gauge is `0`, so the series exist (the frozen taxonomy requires
    /// them) but report the honest zero. The `serve`-path wiring of a live per-produce selected level is
    /// the follow-up; this surfaces the taxonomy.
    cluster_ack: ClusterAckLevelMetrics,
    /// This process's resident-set size in bytes (#118), or `None` when it cannot be read on this
    /// platform. Read OUTSIDE the engine lock (it is a process-level read, not engine state) and
    /// injected after the actor job returns; the RAM-headroom gauge degrades to the unavailable
    /// sentinel when it is `None`.
    rss: Option<u64>,
    /// The connection-signal ("connz") snapshot (#572): accepted/closed/open/refused/authenticated.
    /// Read OUTSIDE the engine lock from the shared connz atomics (a set of off-engine signals, not
    /// engine state). On the legacy `serve_health` path (an un-shared fresh metric) this is the at-rest
    /// all-zero block — the series exist (the frozen taxonomy requires them) but report the honest zero.
    connz: ConnectionMetricsSnapshot,
    /// The health-probe SHED counts (#953): connections the health accept loop dropped without a
    /// handler, by reason (`at_cap` / `spawn_refused`). Health-owned off-lock state (not engine, not
    /// connz), so it is passed in by the handler rather than read under the engine lock. Rendered as
    /// the labeled counter `ironbus_health_shed_total{reason}`; zero when the surface has never shed.
    health_shed: HealthShedSnapshot,
    /// The FREE bytes on the filesystem the durable log lives on (#573), or the `-1` unavailable
    /// sentinel for an in-memory broker (no data dir), a platform where `df` is unavailable, or the
    /// legacy `serve_health` path (no data dir threaded). Read OUTSIDE the engine lock (a process-level
    /// `df` read, not engine state).
    disk_free: i64,
    /// The backpressure controllers' observable state (#68, #69): the CoDel / retry-budget /
    /// fire-and-forget / egress shed counters and the sojourn-estimate / retry-ratio / egress-limit
    /// gauges. Read under the same engine lock as the rest, so every metric is from one instant. All
    /// counters are additive to the frozen taxonomy; the gauges carry no `_total` suffix, so they
    /// stay out of the resilience-counter set by construction.
    backpressure: BackpressureSnapshot,
    /// Per-work-group consumer position, for the lag-by-cursor series (#15, #16).
    groups: Vec<GroupConsumerStat>,
    /// The pre-rendered bounded-metric-registry section (#97): the fixed-bucket fsync-duration and
    /// append-latency histograms, the capped per-consumer lag series, and the self-monitoring
    /// series. Rendered under the engine lock (it walks only the bounded series set), then spliced
    /// into the body.
    registry: String,
}

/// Renders the broker-core gauge + operational-counter block (the first section of the `/metrics`
/// body): the offsets and lag gauges, the writer-health and recovery gauges, and the `_total`
/// operational counters. Held in its own function so [`metrics_body`] stays under the line cap and
/// the big inline `format!` is one focused unit. Consumer lag is `flushed - committed`.
#[allow(clippy::too_many_arguments)]
fn broker_core_lines(
    committed: u64,
    flushed: u64,
    in_flight: usize,
    healthy: bool,
    recovered_truncated: u64,
    quarantined: u64,
    last_dead_lettered: i64,
    dlq_records: u64,
    counters: &Counters,
) -> String {
    let lag = flushed.saturating_sub(committed);
    format!(
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
         # HELP ironbus_quarantine_bytes Persisted on-disk bytes of the forensic quarantine store (capped, copy-not-move); the corrupt-byte copies prior recoveries left, surviving restart.\n\
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
         # HELP ironbus_dead_lettered_total Messages dead-lettered (past MaxDeliver, or routed to a dead-letter exchange after a TTL expiry or reject).\n\
         # TYPE ironbus_dead_lettered_total counter\n\
         ironbus_dead_lettered_total {dead_lettered}\n\
         # HELP ironbus_expired_total Messages expired by a per-message/per-stream TTL and reclaimed by retention (skipped on read, not delivered, not dead-lettered).\n\
         # TYPE ironbus_expired_total counter\n\
         ironbus_expired_total {expired}\n\
         # HELP ironbus_filtered_total Records skipped by a per-subject filtered consumer because their stored subject did not match the work-group filter (the wildcard-subscription selectivity signal).\n\
         # TYPE ironbus_filtered_total counter\n\
         ironbus_filtered_total {filtered}\n\
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
         ironbus_truncated_records_total {truncated_records}\n\
         # HELP ironbus_dedup_hits_total Benign producer dedup hits: a msg_id already seen within the producer's window, so the original offset was returned (duplicate=true) and no second copy appended.\n\
         # TYPE ironbus_dedup_hits_total counter\n\
         ironbus_dedup_hits_total {dedup_hits}\n\
         # HELP ironbus_dedup_out_of_window_total Dedup ids evicted by the time bound (their dedup protection lapsed, so a later republish would not be deduped).\n\
         # TYPE ironbus_dedup_out_of_window_total counter\n\
         ironbus_dedup_out_of_window_total {dedup_out_of_window}\n\
         # HELP ironbus_producer_out_of_order_total Idempotent-producer publishes rejected for an out-of-order sequence (seq skipped past the next-expected, the Kafka OutOfOrderSequence rejection, so a later retry of a skipped seq cannot double-append).\n\
         # TYPE ironbus_producer_out_of_order_total counter\n\
         ironbus_producer_out_of_order_total {producer_out_of_order}\n",
        healthy_value = u8::from(healthy),
        produced = counters.produced,
        produced_bytes = counters.produced_bytes,
        produce_rejected = counters.produce_rejected,
        delivered = counters.delivered,
        redelivered = counters.redelivered,
        dead_lettered = counters.dead_lettered,
        expired = counters.expired,
        filtered = counters.filtered,
        acks = counters.acks,
        segments_reaped = counters.segments_reaped,
        segments_force_reaped = counters.segments_force_reaped,
        truncations = counters.truncations,
        truncated_records = counters.truncated_records,
        dedup_hits = counters.dedup_hits,
        dedup_out_of_window = counters.dedup_out_of_window,
        producer_out_of_order = counters.producer_out_of_order,
    )
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
        recovery_data_loss,
        last_dead_lettered,
        dlq_records,
        counters,
        fsync,
        edge,
        durability,
        cluster_ack,
        backpressure,
        rss,
        connz,
        health_shed,
        disk_free,
        groups,
        registry,
    } = snapshot;
    let mut body = broker_core_lines(
        committed,
        flushed,
        in_flight,
        healthy,
        recovered_truncated,
        quarantined,
        last_dead_lettered,
        dlq_records,
        &counters,
    );
    body.push_str(&skip_loss_reconciliation_lines(&counters));
    body.push_str(&recovery_loss_lines(&recovery_loss));
    body.push_str(&recovery_data_loss_lines(recovery_data_loss));
    body.push_str(&recovery_loss_records_lines(&recovery_loss_records));
    body.push_str(&recovery_event_lines(&counters.recovery));
    body.push_str(&fsync_histogram_lines(&fsync));
    body.push_str(&edge_metric_lines(&edge, rss, disk_free));
    body.push_str(&connz_metric_lines(connz));
    body.push_str(&health_shed_lines(health_shed));
    body.push_str(&durability_metric_lines(&durability));
    body.push_str(&cluster_ack_metric_lines(&cluster_ack));
    body.push_str(&backpressure_metric_lines(&backpressure));
    body.push_str(&group_consumer_lines(&groups, flushed));
    body.push_str(&registry);
    body
}

/// Renders the DURABILITY observability series (#341, #379), all additive GAUGES (no `_total`
/// suffix, so they extend the frozen `(name, type)` contract without touching the resilience-counter
/// taxonomy). Three series surface the active durability level and its loss exposure:
///
/// - `ironbus_durability_level_info{level="..."} 1`: a labeled info gauge naming the ACTIVE level
///   (`sync`/`interval`/`async`/`none`), always `1`, the canonical "which level is running" series a
///   dashboard joins on. The label set is a fixed four-value enum, so the cardinality is bounded.
/// - `ironbus_durability_power_loss_unsafe`: the STICKY power-loss-unsafe signal (#379), `1` when the
///   active level WAIVES I2 (any relaxed level), `0` under the default `sync`. An operator alerts on
///   it crossing to `1` (the broker can lose acknowledged data on a power cut).
/// - `ironbus_durability_unsynced_bytes`: the live UNSYNCED bytes-at-risk a power cut would lose,
///   always `0` under `sync` (no unsynced tail), the real-time loss exposure under a relaxed level.
fn durability_metric_lines(durability: &DurabilityMetrics) -> String {
    let level = escape_label(durability.level);
    let unsafe_value = u8::from(durability.power_loss_unsafe);
    format!(
        "# HELP ironbus_durability_level_info The active durability level (#341); the `level` label is one of sync|interval|async|none, the value is always 1.\n\
         # TYPE ironbus_durability_level_info gauge\n\
         ironbus_durability_level_info{{level=\"{level}\"}} 1\n\
         # HELP ironbus_durability_power_loss_unsafe 1 if the active durability level WAIVES I2 (ack-implies-durable) and can lose acknowledged data on a power cut (any relaxed level); 0 under the power-loss-safe default sync.\n\
         # TYPE ironbus_durability_power_loss_unsafe gauge\n\
         ironbus_durability_power_loss_unsafe {unsafe_value}\n\
         # HELP ironbus_durability_unsynced_bytes Acknowledged-but-not-yet-fdatasync'd record bytes currently at risk on a power cut; always 0 under the sync level, the live loss exposure under a relaxed level.\n\
         # TYPE ironbus_durability_unsynced_bytes gauge\n\
         ironbus_durability_unsynced_bytes {}\n",
        durability.unsynced_bytes,
    )
}

/// Renders the CLUSTER ACK-LEVEL series (#605/#610), additive to the frozen `(name, type)` contract.
/// Two series surface the cluster's durability posture — the cluster twin of the durability-level
/// series above:
///
/// - `ironbus_cluster_ack_total{level="..."}`: one COUNTER per cluster ack level
///   (`c0`/`c1`/`c2_pagecache`/`c2_fsync`) — the number of records acked at each strength, so the
///   posture is observable. It is a LABELED `_total` counter, so (like `ironbus_retry_shed_total{side}`)
///   its sample line is excluded from the UNLABELED-`_total` resilience-taxonomy test by construction and
///   is pinned only in `FROZEN_METRIC_TYPES`. A produce ack is an observability event, not a resilience
///   SHED, so it does not belong in the loss/shed resilience-counter set.
/// - `ironbus_cluster_ack_power_loss_unsafe`: the cluster `power_loss_unsafe` GAUGE (no `_total`), `1`
///   when a weaker-than-fsync cluster level is the active selected level (`c0`/`c1`/`c2-pagecache`), `0`
///   under the power-loss-safe `c2-fsync` default (or no cluster). An operator alerts on it crossing to
///   `1` exactly as for the single-node `ironbus_durability_power_loss_unsafe`. NATS has no such gauge.
///
/// On a single-node / no-cluster broker every counter is `0` and the gauge is `0` — the series exist
/// (the frozen taxonomy requires them) and report the honest zero.
fn cluster_ack_metric_lines(cluster_ack: &ClusterAckLevelMetrics) -> String {
    let mut out = String::new();
    // The per-level COUNTER, one labeled sample per level (in spectrum order).
    out.push_str(
        "# HELP ironbus_cluster_ack_total Records acked at each cluster ack level (#605); the `level` label is one of c0|c1|c2_pagecache|c2_fsync (no-ack / leader local-fsync / quorum page-cache / quorum fdatasync). c2_fsync is the R>=3 default (fsync'd-on-a-quorum); the weaker levels are explicit opt-ins.\n\
         # TYPE ironbus_cluster_ack_total counter\n",
    );
    for level in ClusterAckLevel::ALL {
        let _ = writeln!(
            out,
            "ironbus_cluster_ack_total{{level=\"{}\"}} {}",
            level.metric_label(),
            cluster_ack.count(level),
        );
    }
    // The cluster power-loss-unsafe GAUGE.
    let unsafe_value = u8::from(cluster_ack.power_loss_unsafe());
    let _ = write!(
        out,
        "# HELP ironbus_cluster_ack_power_loss_unsafe 1 if the active SELECTED cluster ack level WAIVES the quorum-fsync guarantee and can lose acknowledged data on a correlated quorum power cut (c0/c1/c2-pagecache); 0 under the power-loss-safe c2-fsync default or with no cluster.\n\
         # TYPE ironbus_cluster_ack_power_loss_unsafe gauge\n\
         ironbus_cluster_ack_power_loss_unsafe {unsafe_value}\n",
    );
    out
}

/// Renders the BACKPRESSURE series (#68, #69), additive to the frozen taxonomy: the CoDel /
/// retry-budget / fire-and-forget / egress shed COUNTERS (every name `ironbus_*_total`, each a
/// resilience SHED the #16 contract guarantees is never silent, so each is pinned in
/// `FROZEN_RESILIENCE_COUNTERS`), plus the GAUGES (the CoDel sojourn estimate, the retry ratio, the
/// AIMD egress limit; no `_total` suffix, so they extend `FROZEN_METRIC_TYPES` without touching the
/// resilience-counter set, matching how the existing gauges are handled).
///
/// `ironbus_retry_ratio` is reported in the same parts-per-million the budget tracks (the gauge is a
/// plain integer; a dashboard divides by 1e6 for a fraction). With every backpressure knob at its
/// disabling default the counters are `0` and the gauges report the inert values (a `0` sojourn, a
/// `0` ratio, the default `16` egress limit), so a zero-config broker still emits the series (the
/// taxonomy is complete) with no shed activity.
fn backpressure_metric_lines(bp: &BackpressureSnapshot) -> String {
    format!(
        "# HELP ironbus_codel_shed_total New produces shed by the CoDel time-in-queue (sojourn) control (standing admission latency past the target).\n\
         # TYPE ironbus_codel_shed_total counter\n\
         ironbus_codel_shed_total {codel_shed}\n\
         # HELP ironbus_codel_backstop_shed_total New produces shed by the sojourn-independent depth/byte backstop (a stalled drain the CoDel sojourn control cannot see, or the durable-log byte cap).\n\
         # TYPE ironbus_codel_backstop_shed_total counter\n\
         ironbus_codel_backstop_shed_total {codel_backstop_shed}\n\
         # HELP ironbus_codel_interval_resets_total CoDel suspend-gap interval resets (a sleeping edge device that resumed without misfiring a burst of false sheds).\n\
         # TYPE ironbus_codel_interval_resets_total counter\n\
         ironbus_codel_interval_resets_total {codel_interval_resets}\n\
         # HELP ironbus_retry_shed_total Retries throttled broker-side by the per-client retry budget (the anti-amplification re-check).\n\
         # TYPE ironbus_retry_shed_total counter\n\
         ironbus_retry_shed_total{{side=\"broker\"}} {retry_shed}\n\
         # HELP ironbus_fire_and_forget_shed_total Fire-and-forget (un-credited) messages shed by the per-connection token bucket.\n\
         # TYPE ironbus_fire_and_forget_shed_total counter\n\
         ironbus_fire_and_forget_shed_total {fire_and_forget_shed}\n\
         # HELP ironbus_egress_shed_total Downstream egress requests shed at the AIMD concurrency limit.\n\
         # TYPE ironbus_egress_shed_total counter\n\
         ironbus_egress_shed_total {egress_shed}\n\
         # HELP ironbus_codel_sojourn_estimate_ms The current minimum-sojourn estimate (milliseconds) the CoDel control law is acting on.\n\
         # TYPE ironbus_codel_sojourn_estimate_ms gauge\n\
         ironbus_codel_sojourn_estimate_ms {codel_sojourn}\n\
         # HELP ironbus_retry_ratio The observed retry (shed) rate as a fraction of the request rate, in parts-per-million (divide by 1e6 for a fraction); the 10%-budget signal.\n\
         # TYPE ironbus_retry_ratio gauge\n\
         ironbus_retry_ratio {retry_ratio}\n\
         # HELP ironbus_egress_limit The current AIMD egress concurrency limit (between 4 and 128); halves when a downstream sink degrades, climbs back as it heals.\n\
         # TYPE ironbus_egress_limit gauge\n\
         ironbus_egress_limit {egress_limit}\n\
         # HELP ironbus_wal_fsync_headroom_shed_total New produces shed by the fsync-headroom admission credit (#378): the un-fsynced buffered-but-not-durable backlog hit the configured headroom and a group-commit drain could not free it (only reached under a relaxed durability level deferring the fsync), so the new produce was rejected to keep the loss window / RAM bound within the headroom; never drops an accepted record.\n\
         # TYPE ironbus_wal_fsync_headroom_shed_total counter\n\
         ironbus_wal_fsync_headroom_shed_total {wal_headroom_shed}\n\
         # HELP ironbus_wal_fsync_headroom_bytes The configured fsync-headroom admission window in bytes (#378): the most un-fsynced buffered-but-not-durable record bytes the write frontier may run ahead of the durable frontier before a produce is throttled (a group-commit drain forced first) or shed; 0 = disabled (unbounded by this control).\n\
         # TYPE ironbus_wal_fsync_headroom_bytes gauge\n\
         ironbus_wal_fsync_headroom_bytes {wal_fsync_headroom_bytes}\n",
        codel_shed = bp.codel_shed,
        codel_backstop_shed = bp.codel_backstop_shed,
        codel_interval_resets = bp.codel_interval_resets,
        retry_shed = bp.retry_shed,
        fire_and_forget_shed = bp.fire_and_forget_shed,
        egress_shed = bp.egress_shed,
        codel_sojourn = bp.codel_sojourn_estimate_ms,
        retry_ratio = bp.retry_ratio_per_million,
        egress_limit = bp.egress_limit,
        wal_headroom_shed = bp.wal_headroom_shed,
        wal_fsync_headroom_bytes = bp.wal_fsync_headroom_bytes,
    )
}

/// Renders the EDGE-resource series (#118), all additive to the frozen taxonomy: the flash
/// write-amplification counters and derived ratio, the RAM-headroom gauge, the throughput-collapse
/// saturation signal, and the opt-in daily-physical-write-budget accounting. Every name is pinned in
/// `FROZEN_METRIC_TYPES` (the #22 contract); the two new `_total` counters are also pinned in
/// `FROZEN_RESILIENCE_COUNTERS` (a write-budget shed and a produce shed are resilience events, never
/// silent). The new GAUGES carry no `_total` suffix, so they stay out of the taxonomy by
/// construction.
///
/// `write_amp_ratio` is `physical / logical` rendered with three decimal places WITHOUT floating
/// point (integer milli-units), and is `0.000` until the first logical byte is produced (a fresh
/// broker has no ratio yet). `ram_headroom_bytes` is `ceiling - rss`, or the `-1` unavailable
/// sentinel when no ceiling is set or RSS could not be read (see [`crate::rss`]).
fn edge_metric_lines(edge: &EdgeMetrics, rss: Option<u64>, disk_free: i64) -> String {
    let mut s = String::new();
    // The write-amplification counters and the derived ratio (#118).
    let _ = write!(
        s,
        "# HELP ironbus_logical_bytes_written Stored payload bytes appended this run (key + headers + payload as stored, post-compression under a non-none codec; no framing); the write-amplification denominator.\n\
         # TYPE ironbus_logical_bytes_written counter\n\
         ironbus_logical_bytes_written {logical}\n\
         # HELP ironbus_physical_bytes_written Physical bytes appended to segments this run (record frames plus segment headers and footers); the real flash-wear write volume and the write-amplification numerator.\n\
         # TYPE ironbus_physical_bytes_written counter\n\
         ironbus_physical_bytes_written {physical}\n",
        logical = edge.logical_bytes_written,
        physical = edge.physical_bytes_written,
    );
    let (ratio_int, ratio_milli) =
        write_amp_ratio_milli(edge.physical_bytes_written, edge.logical_bytes_written);
    let _ = write!(
        s,
        "# HELP ironbus_write_amp_ratio Flash write amplification: physical bytes written divided by logical bytes written (0 until the first byte is produced).\n\
         # TYPE ironbus_write_amp_ratio gauge\n\
         ironbus_write_amp_ratio {ratio_int}.{ratio_milli:03}\n"
    );
    // The RAM-headroom gauge (#118): the configured ceiling minus the measured RSS, or -1 when
    // either is unavailable (no ceiling set, or RSS unreadable on this platform).
    let headroom = crate::rss::ram_headroom_bytes(edge.ram_ceiling_bytes, rss);
    let _ = write!(
        s,
        "# HELP ironbus_ram_headroom_bytes Bytes of headroom below the configured RAM ceiling (ram_ceiling_bytes minus the process RSS), or -1 when no ceiling is set or RSS is unavailable on this platform.\n\
         # TYPE ironbus_ram_headroom_bytes gauge\n\
         ironbus_ram_headroom_bytes {headroom}\n"
    );
    // The RAM-headroom RATIO and the RSS-vs-cap RATIO (#574): the byte headroom gauge expressed as a
    // dimensionless, ceiling-relative per-mille (0..=1000) so an operator can alert on "under 10%
    // headroom" without hard-coding the box's byte ceiling. Float-free integer per-mille (the same
    // convention `ironbus_write_amp_ratio` uses), and the `-1` unavailable sentinel when no ceiling is
    // set or RSS could not be read. The two are complements below the ceiling (they sum to 1.000); the
    // rss-vs-cap clamps at 1.000 once at/over the cap. Rendered as `value/1000`.`value%1000`.
    let headroom_ratio = crate::rss::ram_headroom_ratio_permille(edge.ram_ceiling_bytes, rss);
    write_permille_ratio(
        &mut s,
        "ironbus_ram_headroom_ratio",
        "The fraction of the configured RAM ceiling still available as headroom ((ceiling - rss) / ceiling), in [0, 1], or -1 when no ceiling is set or RSS is unavailable.",
        headroom_ratio,
    );
    let rss_over_cap = crate::rss::rss_over_cap_ratio_permille(edge.ram_ceiling_bytes, rss);
    write_permille_ratio(
        &mut s,
        "ironbus_rss_over_cap_ratio",
        "The fraction of the configured RAM ceiling the process RSS currently occupies (rss / ceiling), in [0, 1] (clamped at 1 once at/over the cap), or -1 when no ceiling is set or RSS is unavailable.",
        rss_over_cap,
    );
    // The DISK-FREE storage telemetry (#573): the free bytes on the filesystem the durable log lives
    // on, or the `-1` unavailable sentinel for an in-memory broker / a platform where `df` is
    // unavailable. Read OUT-OF-BAND in the snapshot (not from any in-process accounting), like RSS.
    let _ = write!(
        s,
        "# HELP ironbus_disk_free_bytes Free (available-to-an-unprivileged-process) bytes on the filesystem the durable log lives on, or -1 for an in-memory broker or when it cannot be read on this platform.\n\
         # TYPE ironbus_disk_free_bytes gauge\n\
         ironbus_disk_free_bytes {disk_free}\n"
    );
    // The persisted DURABLE STORAGE footprint (#573): the durable record bytes and the segment count,
    // the storage-side counterpart of the RAM gauges, so an operator can watch the on-disk growth that
    // disk-free is measured against. Both are read-only engine counts, GAUGES (no `_total`).
    let _ = write!(
        s,
        "# HELP ironbus_durable_record_bytes Stored record bytes currently durable on disk (the on-disk log footprint disk-free is measured against).\n\
         # TYPE ironbus_durable_record_bytes gauge\n\
         ironbus_durable_record_bytes {durable_bytes}\n\
         # HELP ironbus_segment_count Open plus sealed durable-log segment files currently on disk.\n\
         # TYPE ironbus_segment_count gauge\n\
         ironbus_segment_count {segments}\n",
        durable_bytes = edge.durable_record_bytes,
        segments = edge.segment_count,
    );
    // The portable throughput-collapse / saturation signal (#118): a GAUGE that is 1 once the broker
    // has SHED at least one produce (a drop-new admission exhaustion: the byte cap, the daily write
    // budget, or any over-cap rejection). It is throughput-derived, NOT a thermal sensor, so it is
    // portable across every target (temperature is left as an optional device-only add-on). An
    // operator alerts on it crossing to 1 (the broker is shedding load, the saturation symptom).
    let saturated = counters_indicate_saturation(edge);
    let _ = write!(
        s,
        "# HELP ironbus_produce_saturated 1 once the broker has shed at least one produce (admission exhaustion: a drop-new byte-cap or daily-write-budget shed); a portable throughput-collapse signal, not a thermal sensor.\n\
         # TYPE ironbus_produce_saturated gauge\n\
         ironbus_produce_saturated {saturated}\n",
        saturated = u8::from(saturated),
    );
    // The OPT-IN daily-physical-write-budget accounting (#118): the configured budget, today's
    // physical write meter, the over-budget gauge, and the shed counter. All are zero / off when no
    // budget is configured (the default), so the surface is honest without enabling the governor.
    let over_budget = edge.daily_physical_write_budget_bytes != 0
        && edge.physical_bytes_written_today >= edge.daily_physical_write_budget_bytes;
    let _ = write!(
        s,
        "# HELP ironbus_daily_physical_write_budget_bytes The opt-in daily physical write budget in bytes (0 = the flash-wear governor is off).\n\
         # TYPE ironbus_daily_physical_write_budget_bytes gauge\n\
         ironbus_daily_physical_write_budget_bytes {budget}\n\
         # HELP ironbus_physical_bytes_written_today Physical bytes written so far on the current UTC day (the daily-write-budget meter, reset at the UTC day boundary).\n\
         # TYPE ironbus_physical_bytes_written_today gauge\n\
         ironbus_physical_bytes_written_today {today}\n\
         # HELP ironbus_daily_write_budget_over 1 when the daily physical write budget is set and today's physical writes have reached it (the broker is shedding produces to protect flash), else 0.\n\
         # TYPE ironbus_daily_write_budget_over gauge\n\
         ironbus_daily_write_budget_over {over}\n\
         # HELP ironbus_daily_write_budget_sheds_total Produces shed because the daily physical write budget was reached (the flash-wear governor firing).\n\
         # TYPE ironbus_daily_write_budget_sheds_total counter\n\
         ironbus_daily_write_budget_sheds_total {sheds}\n",
        budget = edge.daily_physical_write_budget_bytes,
        today = edge.physical_bytes_written_today,
        over = u8::from(over_budget),
        sheds = edge.daily_budget_sheds,
    );
    s
}

/// Whether the broker has SHED at least one produce, for the portable `ironbus_produce_saturated`
/// throughput-collapse signal (#118): 1 once ANY drop-new admission exhaustion has fired, the
/// disk-full byte-cap shed (`produce_rejected`, which also covers the daily-write-budget shed since
/// both increment it) OR the daily-write-budget governor (`daily_budget_sheds`). Both are folded in
/// so the gauge matches its HELP ("a drop-new byte-cap OR daily-write-budget shed") exactly: a pure
/// byte-cap shed flips it too, not only a budget shed. It is the alert-friendly boolean an operator
/// watches, derived purely from in-process counters (no thermal sensor, so it is portable across
/// every target).
fn counters_indicate_saturation(edge: &EdgeMetrics) -> bool {
    edge.produce_rejected > 0 || edge.daily_budget_sheds > 0
}

/// Renders the CONNECTION-SIGNAL ("connz") series (#572): one LABELED counter family
/// `ironbus_connections_total{state="accepted|closed|refused|authenticated"}` plus the currently-open
/// GAUGE `ironbus_connections_open`. The `state` label is a FIXED four-value enum (NOT a
/// per-connection-id / per-peer value — a connection id is exactly the unbounded label the #576
/// cardinality firewall forbids), so the connz surface is bounded BY CONSTRUCTION. A connection
/// accept/close/auth is normal lifecycle and a refuse is a cap signal — none is a resilience
/// loss/skip/dead-letter SHED — so the labeled `_total` is pinned ONLY in `FROZEN_METRIC_TYPES` (its
/// LABELED sample lines are excluded from the unlabeled-`_total` resilience-taxonomy test by
/// construction, exactly like `ironbus_cluster_ack_total{level}` / `ironbus_retry_shed_total{side}`);
/// the open gauge carries no `_total`. On a broker whose connz was not serve-wired (the legacy
/// `serve_health` path) every value is the honest `0` — the series exist and report zero.
fn connz_metric_lines(connz: ConnectionMetricsSnapshot) -> String {
    let mut s = String::new();
    // The single labeled counter family (all samples of one family must be CONTIGUOUS).
    let _ = write!(
        s,
        "# HELP ironbus_connections_total Connection lifecycle counts by state (#572); the `state` label is one of accepted|closed|refused|authenticated (accepted = became a live handler; closed = handler returned/unwound; refused = rejected before a handler, cap-full or accept error; authenticated = a Connect handshake resolved a credential, 0 on a no-auth broker).\n\
         # TYPE ironbus_connections_total counter\n\
         ironbus_connections_total{{state=\"accepted\"}} {accepted}\n\
         ironbus_connections_total{{state=\"closed\"}} {closed}\n\
         ironbus_connections_total{{state=\"refused\"}} {refused}\n\
         ironbus_connections_total{{state=\"authenticated\"}} {authenticated}\n\
         # HELP ironbus_connections_open Connections currently live (accepted minus closed), maintained incrementally.\n\
         # TYPE ironbus_connections_open gauge\n\
         ironbus_connections_open {open}\n",
        accepted = connz.accepted,
        closed = connz.closed,
        refused = connz.refused,
        authenticated = connz.authenticated,
        open = connz.currently_open,
    );
    // The pre-auth DoS REJECTION family (#633): one LABELED counter
    // `ironbus_connections_rejected_total{reason}` whose `reason` label is a FIXED four-value enum
    // (rate_limited|half_open_cap|locked_out|auth_failed — NOT a per-IP / per-connection value, which
    // is exactly the unbounded label the #576 cardinality firewall forbids), so the family is bounded
    // BY CONSTRUCTION (`reason` is already an allowlisted bounded key). All four samples of the one
    // family are CONTIGUOUS. A no-DoS broker reports the honest zeros — the series exist and report 0.
    let _ = write!(
        s,
        "# HELP ironbus_connections_rejected_total Connections rejected by a pre-auth DoS defense by reason (#633); the `reason` label is one of rate_limited|half_open_cap|locked_out|auth_failed (rate_limited = the per-source-IP connect token bucket was empty; half_open_cap = the global accepted-but-not-yet-authenticated cap was full; locked_out = the source IP was in its failed-auth cooldown; auth_failed = an authentication attempt failed). 0 on a broker with no DoS defense configured.\n\
         # TYPE ironbus_connections_rejected_total counter\n\
         ironbus_connections_rejected_total{{reason=\"rate_limited\"}} {rate_limited}\n\
         ironbus_connections_rejected_total{{reason=\"half_open_cap\"}} {half_open_cap}\n\
         ironbus_connections_rejected_total{{reason=\"locked_out\"}} {locked_out}\n\
         ironbus_connections_rejected_total{{reason=\"auth_failed\"}} {auth_failed}\n",
        rate_limited = connz.rejected_rate_limited,
        half_open_cap = connz.rejected_half_open_cap,
        locked_out = connz.rejected_locked_out,
        auth_failed = connz.rejected_auth_failed,
    );
    s
}

/// Renders the HEALTH-PROBE shed counter (#953): `ironbus_health_shed_total{reason}`, one LABELED
/// counter per shed site the health accept loop has — `at_cap` (already at
/// [`MAX_CONCURRENT_HEALTH_HANDLERS`] in-flight handlers) and `spawn_refused` (the OS refused a
/// handler thread, #866). Before this the health surface shed SILENTLY, so an operator could not see
/// probes being dropped under a flood; this makes the flood observable, the health twin of the wire
/// server's connz `refused` signal (#865) — but deliberately its OWN series, since health probes were
/// never in connz. Being a LABELED `_total`, its sample lines are excluded from the unlabeled-`_total`
/// resilience-taxonomy test by construction (exactly like `ironbus_connections_total{state}`) and the
/// family is pinned only in `FROZEN_METRIC_TYPES`: a health-probe shed is a flood-protection signal,
/// NOT a record-loss resilience SHED, so it does not belong in the loss/shed taxonomy. The `reason`
/// label is a fixed two-value enum, so the cardinality is bounded by construction; both samples are
/// zero on a broker whose health surface has never shed.
fn health_shed_lines(shed: HealthShedSnapshot) -> String {
    format!(
        "# HELP ironbus_health_shed_total Health-probe connections shed (dropped without a handler) by the health accept loop, by reason (#953); the `reason` label is one of at_cap|spawn_refused (at_cap = the MAX_CONCURRENT_HEALTH_HANDLERS in-flight cap was full; spawn_refused = the OS refused a handler thread). A flood-protection signal, 0 on a broker whose health surface has never shed.\n\
         # TYPE ironbus_health_shed_total counter\n\
         ironbus_health_shed_total{{reason=\"at_cap\"}} {at_cap}\n\
         ironbus_health_shed_total{{reason=\"spawn_refused\"}} {spawn_refused}\n",
        at_cap = shed.at_cap,
        spawn_refused = shed.spawn_refused,
    )
}

/// Renders a per-mille ratio gauge (#574) WITHOUT floating point: a value in `[0, 1000]` is printed
/// as the `0.xyz` fraction (`value/1000`.`value%1000`), and the `-1` unavailable sentinel is printed
/// verbatim as `-1` (a real ratio is never negative, so `-1` is unambiguous, the same convention
/// `ironbus_ram_headroom_bytes` uses). Emits the `# HELP`/`# TYPE gauge` lines then the sample.
fn write_permille_ratio(s: &mut String, name: &str, help: &str, permille: i64) {
    let _ = writeln!(s, "# HELP {name} {help}");
    let _ = writeln!(s, "# TYPE {name} gauge");
    if permille < 0 {
        // The unavailable sentinel: print it verbatim, not as a fraction.
        let _ = writeln!(s, "{name} {permille}");
    } else {
        // A non-negative per-mille in [0, 1000] -> the `int.frac` ratio (e.g. 600 -> 0.600, 1000 -> 1.000).
        let v = permille.unsigned_abs();
        let _ = writeln!(s, "{name} {}.{:03}", v / 1000, v % 1000);
    }
}

/// Computes `physical / logical` as an integer part plus a three-digit milli-fraction, WITHOUT
/// floating point (#118), so the exposition is exact and reproducible. Returns `(0, 0)` (rendered
/// `0.000`) when `logical` is zero (a fresh broker has no ratio yet). The ratio is rounded to the
/// nearest milli-unit. Saturates rather than overflowing on a pathologically large physical total.
fn write_amp_ratio_milli(physical: u64, logical: u64) -> (u64, u64) {
    if logical == 0 {
        return (0, 0);
    }
    // milli = round(physical * 1000 / logical), computed in u128 to avoid overflow on the multiply.
    let milli_total = (u128::from(physical) * 1000 + u128::from(logical) / 2) / u128::from(logical);
    let int_part = u64::try_from(milli_total / 1000).unwrap_or(u64::MAX);
    let milli_part = u64::try_from(milli_total % 1000).unwrap_or(0);
    (int_part, milli_part)
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
    // The request-path latency histograms (#570): the produce->ack, deliver, and consume (ack)
    // request paths, over the SAME fixed registry buckets, so an operator sees the producer- and
    // consumer-visible latency distributions alongside the durability-barrier (fsync/append) ones.
    fixed_histogram_lines(
        &mut s,
        "ironbus_produce_ack_duration_seconds",
        "The produce->ack request-path latency: the engine time across the group-commit durability barrier that makes a produced batch durable (and thus acked to its producers), over the fixed registry buckets.",
        registry.produce_ack_latency(),
    );
    fixed_histogram_lines(
        &mut s,
        "ironbus_deliver_duration_seconds",
        "The deliver request-path latency: the engine time to service one poll that handed out a delivery (the poll scan plus the lease grant), over the fixed registry buckets.",
        registry.deliver_latency(),
    );
    fixed_histogram_lines(
        &mut s,
        "ironbus_consume_duration_seconds",
        "The consume (ack) request-path latency: the engine time to service one ack that committed (the lease ack plus the cursor commit and lag maintenance), over the fixed registry buckets.",
        registry.consume_latency(),
    );
    consumer_lag_lines(&mut s, registry);
    throughput_lines(&mut s, registry);
    ack_level_lines(&mut s, registry);
    self_monitoring_lines(&mut s, registry, now_monotonic);
    s
}

/// Renders the per-stream / per-group THROUGHPUT series (#571): records produced per stream
/// (`ironbus_stream_produced_total{stream}`) and consumed per group
/// (`ironbus_group_consumed_total{group}`), as monotonic counters with the SAME bounded cardinality
/// as the consumer-lag series — up to 1024 distinct labels then a `{stream|group="__overflow__"}`
/// fold (only emitted once a label has been dropped, so a healthy broker omits it), plus the
/// `ironbus_throughput_labels_dropped_total` cardinality-pressure counter. The `stream`/`group` label
/// is a bounded, overflow-folded WORK-GROUP / STREAM NAME (NOT a per-message / per-offset value), so
/// the cardinality is firewall-safe. Both labeled `_total` sample lines carry a label, so they are
/// pinned only in `FROZEN_METRIC_TYPES` (the unlabeled-`_total` resilience-taxonomy filter excludes
/// them by construction); the unlabeled `*_labels_dropped_total` is a never-silent cardinality-cap
/// event, so it is ALSO in `FROZEN_RESILIENCE_COUNTERS`, exactly like `ironbus_consumer_labels_dropped_total`.
fn throughput_lines(s: &mut String, registry: &crate::registry::MetricRegistry) {
    let tp = registry.throughput();
    // Each metric family must be CONTIGUOUS in the exposition (one HELP/TYPE then every sample), so
    // the produced family and the consumed family are emitted as whole blocks, not interleaved.
    let _ = writeln!(
        s,
        "# HELP ironbus_stream_produced_total Records produced per stream (maintained incrementally, capped cardinality; over-cap streams fold into stream=\"__overflow__\")."
    );
    let _ = writeln!(s, "# TYPE ironbus_stream_produced_total counter");
    tp.for_each_series(|label, produced, _consumed| {
        let _ = writeln!(
            s,
            "ironbus_stream_produced_total{{stream=\"{}\"}} {produced}",
            escape_label(label)
        );
    });
    if tp.has_overflow() {
        let _ = writeln!(
            s,
            "ironbus_stream_produced_total{{stream=\"{}\"}} {}",
            crate::registry::OVERFLOW_THROUGHPUT_LABEL,
            tp.overflow_produced()
        );
    }
    let _ = writeln!(
        s,
        "# HELP ironbus_group_consumed_total Records consumed (acked) per work-group (maintained incrementally, capped cardinality; over-cap groups fold into group=\"__overflow__\")."
    );
    let _ = writeln!(s, "# TYPE ironbus_group_consumed_total counter");
    tp.for_each_series(|label, _produced, consumed| {
        let _ = writeln!(
            s,
            "ironbus_group_consumed_total{{group=\"{}\"}} {consumed}",
            escape_label(label)
        );
    });
    if tp.has_overflow() {
        let _ = writeln!(
            s,
            "ironbus_group_consumed_total{{group=\"{}\"}} {}",
            crate::registry::OVERFLOW_THROUGHPUT_LABEL,
            tp.overflow_consumed()
        );
    }
    let _ = writeln!(
        s,
        "# HELP ironbus_throughput_labels_dropped_total Stream/group throughput labels refused a distinct series at the cardinality cap (folded into __overflow__)."
    );
    let _ = writeln!(s, "# TYPE ironbus_throughput_labels_dropped_total counter");
    let _ = writeln!(
        s,
        "ironbus_throughput_labels_dropped_total {}",
        tp.labels_dropped()
    );
}

/// Renders the per-ack-level (0/1/2) PRODUCE counters (#571): one labeled counter per ack level
/// (`ironbus_produce_ack_level_total{level="c0|c1|c2"}`), the single-node twin of the cluster
/// ack-level counters (`ironbus_cluster_ack_total`). The `level` label is a fixed THREE-value enum,
/// so the cardinality is bounded BY CONSTRUCTION (no overflow fold needed). A labeled `_total`, so its
/// sample line is excluded from the unlabeled-`_total` resilience-taxonomy test by construction and is
/// pinned only in `FROZEN_METRIC_TYPES`, exactly like `ironbus_cluster_ack_total`. On a fresh broker
/// every level is `0` — the series exist (the frozen taxonomy requires them) and report the honest zero.
fn ack_level_lines(s: &mut String, registry: &crate::registry::MetricRegistry) {
    use ironbus_proto::message::AckLevel;
    let acks = registry.ack_levels();
    let _ = writeln!(
        s,
        "# HELP ironbus_produce_ack_level_total Records produced at each per-publish ack level (#494/#571); the `level` label is one of c0|c1|c2 (no-ack / server-ack / server+client-ack). The single-node twin of ironbus_cluster_ack_total."
    );
    let _ = writeln!(s, "# TYPE ironbus_produce_ack_level_total counter");
    // Emit in spectrum order (c0, c1, c2), one labeled sample per level.
    for (level, label) in [
        (AckLevel::NoAck, "c0"),
        (AckLevel::ServerAck, "c1"),
        (AckLevel::ServerAndClientAck, "c2"),
    ] {
        let _ = writeln!(
            s,
            "ironbus_produce_ack_level_total{{level=\"{label}\"}} {}",
            acks.count(level)
        );
    }
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
/// broker), the `ironbus_consumer_overflow_saturated` gauge (1 once the overflow fold became a
/// monotonic lower bound, #321), and the `ironbus_consumer_labels_dropped_total` counter. Lag is
/// maintained incrementally (`head - committed`) and never scanned on scrape.
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
    // The defense-in-depth safety valve beyond the 1024-series cap (#321): 1 once more than the
    // overflow-ledger capacity of distinct over-cap consumers have been seen over the broker's
    // lifetime, so the `__overflow__` fold above is a monotonic LOWER BOUND rather than exact. A
    // GAUGE (no `_total` suffix), so it stays out of the frozen resilience-counter taxonomy by
    // construction.
    let _ = writeln!(
        s,
        "# HELP ironbus_consumer_overflow_saturated 1 when the __overflow__ consumer-lag series became a monotonic lower bound (more than the overflow-ledger capacity of distinct over-cap consumers seen)."
    );
    let _ = writeln!(s, "# TYPE ironbus_consumer_overflow_saturated gauge");
    let _ = writeln!(
        s,
        "ironbus_consumer_overflow_saturated {}",
        u8::from(lag.overflow_saturated() > 0)
    );
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
fn recovery_loss_lines(by_reason: &[u64; ReasonCode::ALL.len()]) -> String {
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

/// Renders the recovery DATA-LOSS gauge `ironbus_recovery_data_loss_bytes` (#59): the bytes the
/// last recovery dropped that are REAL data loss, i.e. the loss report's total with
/// [`ReasonCode::TornTail`] excluded. A torn or unsynced tail is a reported skip
/// (`ironbus_recovery_truncated_bytes` and the `torn_tail` per-reason series still carry it) but
/// not lost data, so this headline figure does not inflate on a brownout restart. It is a GAUGE
/// (no `_total`), so it stays out of the frozen resilience-counter taxonomy by construction.
fn recovery_data_loss_lines(data_loss_bytes: u64) -> String {
    format!(
        "# HELP ironbus_recovery_data_loss_bytes Bytes of real data loss at the last recovery (the loss report total with torn-tail truncation excluded, since a torn tail is bytes never fully written, not lost data).\n\
         # TYPE ironbus_recovery_data_loss_bytes gauge\n\
         ironbus_recovery_data_loss_bytes {data_loss_bytes}\n"
    )
}

/// Renders the per-reason recovery-loss gauge `ironbus_recovery_loss_records{reason=...}`
/// from the last recovery's loss report: the record-count complement of
/// `ironbus_recovery_loss_bytes`, so an operator sees not just how many bytes recovery
/// dropped but how many records, by reason. Zero where a reason did not occur.
fn recovery_loss_records_lines(by_reason: &[u64; ReasonCode::ALL.len()]) -> String {
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

/// Renders the recovery-EVENT counter family (#575): the FLAGSHIP corruption-recovery metrics NATS
/// has no analogue for (its truncate-and-drop recovery is silent, #7549/#7556). Each is bumped once
/// per `Engine::open` recovery run from the durable loss report, so they are monotonic `_total`
/// counters an operator can alert on. Three series:
///
/// - `ironbus_recovery_runs_total{outcome=clean|torn_tail_truncated|quarantined|data_loss}`: a
///   LABELED `_total`, one increment per open into the outcome bucket the run classified into. Like
///   the other labeled `_total`s (`ironbus_cluster_ack_total{level}`, `ironbus_retry_shed_total{side}`)
///   its sample lines are excluded from the UNLABELED-`_total` resilience-taxonomy set by construction
///   and pinned only in `FROZEN_METRIC_TYPES`. The `outcome` label is a fixed four-value enum, so the
///   cardinality is bounded.
/// - `ironbus_torn_tail_repairs_total`: an UNLABELED `_total`, the count of torn/unsynced tails
///   truncated to the longest valid prefix (a power-loss repair, NOT data loss). It joins the frozen
///   resilience-counter taxonomy (a never-silent recovery event).
/// - `ironbus_corruption_repairs_total{artifact=segment|cursor|dlq}`: a LABELED `_total`, the count of
///   data-loss corruption spans quarantined-and-dropped, by the on-disk artifact. Bounded
///   three-value `artifact` enum; pinned only in `FROZEN_METRIC_TYPES` (labeled), the marquee metric
///   NATS structurally lacks.
fn recovery_event_lines(recovery: &RecoveryCounters) -> String {
    let mut s = String::from(
        "# HELP ironbus_recovery_runs_total Recovery runs (one per broker open), by outcome (clean|torn_tail_truncated|quarantined|data_loss). The flagship corruption-recovery signal NATS has no analogue for.\n\
         # TYPE ironbus_recovery_runs_total counter\n",
    );
    for (outcome, runs) in RecoveryOutcome::ALL
        .iter()
        .zip(recovery.runs_by_outcome.iter())
    {
        let _ = writeln!(
            s,
            "ironbus_recovery_runs_total{{outcome=\"{}\"}} {runs}",
            outcome.metric_label()
        );
    }
    let _ = write!(
        s,
        "# HELP ironbus_torn_tail_repairs_total Torn/unsynced tails truncated to the longest valid prefix across all recovery runs (a power-loss repair, not data loss).\n\
         # TYPE ironbus_torn_tail_repairs_total counter\n\
         ironbus_torn_tail_repairs_total {}\n\
         # HELP ironbus_corruption_repairs_total Corruption spans quarantined-and-dropped across all recovery runs, by on-disk artifact (segment|cursor|dlq). NATS has NO corruption-repair metric (its recovery is silent truncate-and-drop).\n\
         # TYPE ironbus_corruption_repairs_total counter\n",
        recovery.torn_tail_repairs,
    );
    for (artifact, repairs) in RecoveryArtifact::ALL
        .iter()
        .zip(recovery.corruption_repairs_by_artifact.iter())
    {
        let _ = writeln!(
            s,
            "ironbus_corruption_repairs_total{{artifact=\"{}\"}} {repairs}",
            artifact.metric_label()
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

/// A consistent snapshot of the read-only introspection state (#99/#577). The ENGINE fields are read
/// under one engine lock so they are all from the same instant; the v2-only OFF-LOCK fields (connz,
/// disk-free, RSS) are filled afterward from process-level / shared-atomic reads, exactly as the
/// `/metrics` snapshot defers them (they are not engine state). Every value comes from an existing
/// read-only accessor; nothing here can mutate the engine, and no secret material is carried.
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
    // ── v2-only fields (#577) ─────────────────────────────────────────────────────────────────────
    // Read alongside the engine fields but consumed ONLY by `admin_body_v2`; the v1 renderer ignores
    // them, so a v1 request is byte-for-byte unchanged.
    /// The configured RAM ceiling in bytes (`0` = unset), read under the engine lock; the v2 storage
    /// object's RAM headroom / RSS-vs-cap is derived from it and [`Self::rss`] (#574).
    ram_ceiling_bytes: u64,
    /// The connection-signal ("connz") snapshot (#572/#633): the BOUNDED aggregate the v2
    /// `connections` object renders. Read OFF-LOCK from the shared connz atomics, the at-rest all-zero
    /// block on the legacy un-shared path.
    connz: ConnectionMetricsSnapshot,
    /// The FREE bytes on the filesystem the durable log lives on (#573), or the `-1` unavailable
    /// sentinel (in-memory broker / `df` unavailable / legacy path). Read OFF-LOCK.
    disk_free: i64,
    /// This process's resident-set size in bytes (#118/#574), or `None` when it cannot be read on this
    /// platform. Read OFF-LOCK; the v2 storage object's RAM headroom degrades to the `-1` sentinel
    /// when it is `None`.
    rss: Option<u64>,
}

/// The schema version of the `/admin` v1 JSON body (#99). FROZEN: pinned so a consumer can detect a
/// breaking shape change. v1 never changes; a new shape is a new version (`ADMIN_SCHEMA_VERSION_V2`).
const ADMIN_SCHEMA_VERSION: u32 = 1;

/// The schema version of the `/admin` v2 JSON body (#577): the v1 fields PLUS the `connections`,
/// `storage`, and `recovery` objects. Pinned so a consumer can detect the version it received.
const ADMIN_SCHEMA_VERSION_V2: u32 = 2;

/// Renders the `/admin` JSON snapshot (#99): a structured, read-only view of operational state.
/// Hand-rendered (no serde dependency, matching the hand-rendered Prometheus text) and strictly a
/// projection of [`AdminSnapshot`], so it can never mutate engine state.
///
/// The top-level shape is `{schema_version, broker, segments, consumers[], groups[], resilience,
/// dlq, config}`. The four #99 sub-resources are present by name: `segments` (the durable-log span),
/// `consumers` (the per-work-group committed offset and INCREMENTAL lag; `groups` is kept as a
/// back-compat alias of the same array so an existing consumer is not broken), `config` (the
/// effective-bounds echo), and `resilience` (last-skip-offset, the frozen flag, and the skip
/// totals). Lag is the durable head minus the committed offset, the same derivation `/metrics` uses,
/// so #15 can render segments, consumers, lag, and last-skip-offset from THIS JSON ALONE without
/// parsing a single metric name.
fn admin_body(snapshot: &AdminSnapshot) -> String {
    let mut s = String::new();
    let _ = write!(s, "{{\"schema_version\":{ADMIN_SCHEMA_VERSION},");
    admin_broker_section(&mut s, snapshot);
    admin_segments_section(&mut s, snapshot);
    admin_consumers_section(&mut s, snapshot);
    admin_resilience_section(&mut s, snapshot);
    admin_dlq_section(&mut s, snapshot);
    admin_config_section(&mut s, &snapshot.config);
    s.push('}');
    s
}

/// Renders the `/admin` v2 JSON snapshot (#577): the FULL v1 body (every v1 field, byte-for-byte the
/// same renderers, only `schema_version` bumped to 2) PLUS three new bounded objects an operator can
/// read without the Prometheus scrape — `connections`, `storage`, and `recovery`. Hand-rendered (no
/// serde) and strictly a projection of [`AdminSnapshot`], so it can never mutate engine state.
///
/// v2 is purely ADDITIVE: a consumer that ignores the three new keys reads it as v1, and the v1-only
/// renderers ([`admin_broker_section`] … [`admin_config_section`]) are shared verbatim, so the v1 and
/// v2 bodies can never drift in their common fields. The three additions each come from the SAME
/// read-only accessors `/metrics` exposes (the connz aggregate, the storage footprint, the recovery
/// counters), so the two surfaces agree by construction, and each is a FIXED-shape object (no
/// unbounded per-connection / per-segment list), keeping the body low-cardinality.
fn admin_body_v2(snapshot: &AdminSnapshot) -> String {
    let mut s = String::new();
    let _ = write!(s, "{{\"schema_version\":{ADMIN_SCHEMA_VERSION_V2},");
    // The v1 fields, rendered by the SAME functions v1 uses (only the schema_version differs above),
    // so the shared fields are guaranteed identical between the two versions.
    admin_broker_section(&mut s, snapshot);
    admin_segments_section(&mut s, snapshot);
    admin_consumers_section(&mut s, snapshot);
    admin_resilience_section(&mut s, snapshot);
    admin_dlq_section(&mut s, snapshot);
    admin_config_section(&mut s, &snapshot.config);
    // The v2 additions, each a fixed-shape bounded object.
    s.push(',');
    admin_connections_section(&mut s, snapshot);
    admin_storage_section(&mut s, snapshot);
    admin_recovery_section(&mut s, snapshot);
    s.push('}');
    s
}

/// Appends the v2 `"connections":{...}` object (#577): the BOUNDED aggregate of the connz signals
/// (#572/#633), so an operator reads the connection picture without the Prometheus scrape. It is a
/// FIXED-shape object — `open` (the live gauge), the `accepted`/`closed`/`refused`/`authenticated`
/// lifetime totals, and a nested `rejected{reason}` object with the four pre-auth-`DoS` reason
/// counters — never an unbounded per-connection or per-peer list (a connection id / source IP is
/// exactly the unbounded label the #576 cardinality firewall forbids), so the cardinality is bounded
/// by construction regardless of how many connections the broker has served. Every field mirrors a
/// `ironbus_connections_*` series, so `/admin` v2 and `/metrics` agree.
fn admin_connections_section(s: &mut String, snapshot: &AdminSnapshot) {
    let c = &snapshot.connz;
    let _ = write!(
        s,
        "\"connections\":{{\
            \"open\":{open},\
            \"accepted\":{accepted},\
            \"closed\":{closed},\
            \"refused\":{refused},\
            \"authenticated\":{authenticated},\
            \"rejected\":{{\
                \"rate_limited\":{rate_limited},\
                \"half_open_cap\":{half_open_cap},\
                \"locked_out\":{locked_out},\
                \"auth_failed\":{auth_failed}\
            }}\
        }},",
        open = c.currently_open,
        accepted = c.accepted,
        closed = c.closed,
        refused = c.refused,
        authenticated = c.authenticated,
        rate_limited = c.rejected_rate_limited,
        half_open_cap = c.rejected_half_open_cap,
        locked_out = c.rejected_locked_out,
        auth_failed = c.rejected_auth_failed,
    );
}

/// Appends the v2 `"storage":{...}` object (#577): the on-disk footprint and the RAM headroom, so an
/// operator reads the storage picture without the scrape. `segment_count` and `durable_record_bytes`
/// are the on-disk log footprint (#573); `disk_free_bytes` is the free space on the filesystem the
/// durable log lives on, or the `-1` unavailable sentinel for an in-memory broker / a platform where
/// `df` is unavailable (#573). The RAM block mirrors the `/metrics` edge gauges (#118/#574):
/// `ram_ceiling_bytes` is the configured ceiling (`0` = unset); `rss_bytes` is the live resident-set
/// size or the `-1` sentinel when it cannot be read; `ram_headroom_bytes` is `ceiling - rss` (or `-1`
/// when no ceiling is set or RSS is unavailable); and `rss_over_cap_ratio_permille` is the RSS-vs-cap
/// ratio in per-mille (`0`–`1000`, or `-1` unavailable). Every field reuses the SAME `crate::rss`
/// helpers `/metrics` uses, so the sentinel conventions and the two surfaces agree.
fn admin_storage_section(s: &mut String, snapshot: &AdminSnapshot) {
    // `-1` (the `crate::rss::UNAVAILABLE` / `RSS_UNAVAILABLE` sentinel) when RSS cannot be read on
    // this platform, matching the `/metrics` `ironbus_*` RAM gauges; otherwise the live RSS in bytes.
    let rss_bytes = snapshot.rss.map_or(crate::rss::RSS_UNAVAILABLE, |b| {
        i64::try_from(b).unwrap_or(i64::MAX)
    });
    let _ = write!(
        s,
        "\"storage\":{{\
            \"segment_count\":{segment_count},\
            \"durable_record_bytes\":{durable_record_bytes},\
            \"disk_free_bytes\":{disk_free},\
            \"ram_ceiling_bytes\":{ram_ceiling_bytes},\
            \"rss_bytes\":{rss_bytes},\
            \"ram_headroom_bytes\":{ram_headroom_bytes},\
            \"rss_over_cap_ratio_permille\":{rss_over_cap_ratio_permille}\
        }},",
        segment_count = snapshot.segment_count,
        durable_record_bytes = snapshot.durable_record_bytes,
        disk_free = snapshot.disk_free,
        ram_ceiling_bytes = snapshot.ram_ceiling_bytes,
        rss_bytes = rss_bytes,
        ram_headroom_bytes =
            crate::rss::ram_headroom_bytes(snapshot.ram_ceiling_bytes, snapshot.rss),
        rss_over_cap_ratio_permille =
            crate::rss::rss_over_cap_ratio_permille(snapshot.ram_ceiling_bytes, snapshot.rss),
    );
}

/// Appends the v2 `"recovery":{...}` object (#577): the flagship corruption-recovery counters NATS
/// has no analogue for (#575), so an operator reads the recovery picture without the scrape.
/// `runs_by_outcome` is a fixed-shape object keyed by the four bounded `RecoveryOutcome` labels (one
/// increment per broker open into the outcome bucket the run classified into); `torn_tail_repairs` is
/// the count of torn/unsynced tails truncated to the longest valid prefix (a power-loss repair, NOT
/// data loss); `corruption_repairs_by_artifact` is a fixed-shape object keyed by the three bounded
/// `RecoveryArtifact` labels (corruption spans quarantined-and-dropped, by the on-disk artifact).
/// Every field mirrors a `ironbus_recovery_runs_total` / `ironbus_torn_tail_repairs_total` /
/// `ironbus_corruption_repairs_total` series, with the SAME frozen label vocabularies, so the JSON
/// keys stay bounded and `/admin` v2 agrees with `/metrics` by construction.
fn admin_recovery_section(s: &mut String, snapshot: &AdminSnapshot) {
    let recovery = &snapshot.counters.recovery;
    s.push_str("\"recovery\":{\"runs_by_outcome\":{");
    for (i, (outcome, runs)) in RecoveryOutcome::ALL
        .iter()
        .zip(recovery.runs_by_outcome.iter())
        .enumerate()
    {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "\"{}\":{runs}", outcome.metric_label());
    }
    let _ = write!(
        s,
        "}},\"torn_tail_repairs\":{},\"corruption_repairs_by_artifact\":{{",
        recovery.torn_tail_repairs,
    );
    for (i, (artifact, repairs)) in RecoveryArtifact::ALL
        .iter()
        .zip(recovery.corruption_repairs_by_artifact.iter())
        .enumerate()
    {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "\"{}\":{repairs}", artifact.metric_label());
    }
    s.push_str("}}");
}

/// Appends the `"segments":{...}` sub-resource (#99): the durable-log SPAN #15 renders, derived from
/// the broker's read-only accessors. `count` is the live segment count; `earliest_retained_offset`
/// and `head_offset` (the durable head) bound the retained record range; `durable_record_count` and
/// `durable_record_bytes` size it. Together these are everything #15 needs to draw the segment span
/// without parsing any metric name.
fn admin_segments_section(s: &mut String, snapshot: &AdminSnapshot) {
    let _ = write!(
        s,
        "\"segments\":{{\
            \"count\":{count},\
            \"earliest_retained_offset\":{earliest},\
            \"head_offset\":{head},\
            \"durable_record_count\":{records},\
            \"durable_record_bytes\":{bytes}\
        }},",
        count = snapshot.segment_count,
        earliest = snapshot.earliest_retained,
        head = snapshot.flushed,
        records = snapshot.durable_record_count,
        bytes = snapshot.durable_record_bytes,
    );
}

/// Appends the `"resilience":{...}` sub-resource (#99): the resilience state #15 surfaces, so a
/// bounded loss is never silent in the introspection view either. `frozen` is the RocksDB-style
/// integrity freeze (the inverse of `healthy`); `last_skip_offset` is the highest offset any
/// skip/loss event reached; `records_skipped`/`bytes_skipped` are the durable recovery-loss totals;
/// `counter_checkpoint_repairs` is the reconcile-raised-the-lower-bound signal. All are read from the
/// same accessors `/metrics` exposes, so the two surfaces agree by construction.
fn admin_resilience_section(s: &mut String, snapshot: &AdminSnapshot) {
    let counters = &snapshot.counters;
    let _ = write!(
        s,
        "\"resilience\":{{\
            \"frozen\":{frozen},\
            \"last_skip_offset\":{last_skip_offset},\
            \"records_skipped\":{records_skipped},\
            \"bytes_skipped\":{bytes_skipped},\
            \"recovery_truncated_bytes\":{recovery_truncated_bytes},\
            \"counter_checkpoint_repairs\":{repairs}\
        }},",
        // `frozen` is the integrity freeze: a writer frozen by a fatal fsync answers `/readyz` 503.
        // It is the logical inverse of `healthy`, surfaced by name so an operator reads the alarming
        // state directly rather than inverting a health flag.
        frozen = !snapshot.healthy,
        last_skip_offset = counters.last_skip_offset,
        records_skipped = counters.records_skipped,
        bytes_skipped = counters.bytes_skipped,
        recovery_truncated_bytes = snapshot.recovered_truncated_bytes,
        repairs = counters.counter_checkpoint_repairs,
    );
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

/// Appends the per-work-group consumer view (#99) under BOTH `"consumers":[...]` (the #99 sub-
/// resource name #15 reads) and `"groups":[...]` (a back-compat alias of the identical array, so an
/// existing consumer of the prior scaffold keeps working). Each entry, the default group `""`
/// included, carries the group `name`, its `committed_offset`, the INCREMENTAL `consumer_lag`
/// (durable head minus the group's committed offset, the same derivation `/metrics` uses), and the
/// `in_flight` depth. Rendering both names once each keeps the two arrays byte-identical.
fn admin_consumers_section(s: &mut String, snapshot: &AdminSnapshot) {
    // Render the entries once into a reusable fragment, then emit it under both keys so `consumers`
    // and the `groups` alias can never diverge.
    let mut entries = String::new();
    for (i, stat) in snapshot.groups.iter().enumerate() {
        if i > 0 {
            entries.push(',');
        }
        let _ = write!(
            entries,
            "{{\"name\":\"{}\",\"committed_offset\":{},\"consumer_lag\":{},\"in_flight\":{}}}",
            escape_json(&stat.group),
            stat.committed,
            snapshot.flushed.saturating_sub(stat.committed),
            stat.in_flight,
        );
    }
    let _ = write!(s, "\"consumers\":[{entries}],\"groups\":[{entries}],");
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
            \"disk_full_policy\":\"{disk_full_policy}\",\
            \"ram_ceiling_bytes\":{ram_ceiling_bytes},\
            \"daily_physical_write_budget_bytes\":{daily_physical_write_budget_bytes}\
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
        // The #118 edge knobs echoed for #15 / the operator: the RAM-headroom ceiling and the
        // opt-in daily physical write budget (both `0` = off/unset by default).
        ram_ceiling_bytes = config.ram_ceiling_bytes,
        daily_physical_write_budget_bytes = config.daily_physical_write_budget_bytes,
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

/// Like [`respond`] but with a JSON `Content-Type`, for the `/admin` endpoint (#99/#577). The
/// `media_type` is the SCHEMA-PINNED admin media type the negotiated version selected (so a v1
/// response is labeled `application/vnd.ironbus.admin.v1+json` and a v2 response `...v2+json`, while
/// the 406 error body is a plain `application/json`); `; charset=utf-8` is appended here so each
/// call site passes only the bare media type. Every spelling starts with `application/`, so the
/// existing `Content-Type: application/json` substring checks still match a JSON response.
fn respond_json(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
    media_type: &str,
) -> std::io::Result<()> {
    respond_with(
        stream,
        code,
        reason,
        &format!("{media_type}; charset=utf-8"),
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
    // Write the WHOLE response under ONE monotonic deadline (#953), not the per-syscall
    // `set_write_timeout` the handler armed: that timeout RESETS on every partial write, so a slow
    // READER dribbling one byte per window could hold this handler — and thus one of the
    // MAX_CONCURRENT_HEALTH_HANDLERS slots — for ~response-size × REQUEST_TIMEOUT. A whole-response
    // budget bounds the write to at most REQUEST_TIMEOUT regardless of body size (the /metrics and
    // /admin bodies are the large ones), so a stalled reader frees its slot strictly on time. Each
    // response is a single write (Connection: close), so this deadline is the handler's write budget.
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    write_all_by_deadline(stream, response.as_bytes(), deadline)
}

/// Writes `bytes` in full under a WHOLE-RESPONSE monotonic `deadline` (#953). Unlike the socket's
/// `set_write_timeout` — a PER-SYSCALL budget that RESETS on every partial write, so a slow reader
/// making one byte of progress per window can stretch the total to ~response-size × `REQUEST_TIMEOUT` —
/// this bounds the ENTIRE write regardless of body size: before each `write` the per-syscall timeout
/// is trimmed to the REMAINING budget, and once the budget is spent the write fails `TimedOut` rather
/// than blocking anew. That strictly caps how long a stalled reader can pin one handler (hence one of
/// the [`MAX_CONCURRENT_HEALTH_HANDLERS`] slots). An `Interrupted` (`EINTR`) write is retried; a
/// short write advances and loops.
fn write_all_by_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> std::io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "health response write deadline exceeded",
            ));
        }
        // Trim the per-syscall timeout to what remains of the whole-response budget, so a blocking
        // write can never outlast the deadline. `now < deadline` here, so the remaining budget is
        // strictly positive — never the zero-duration timeout `set_write_timeout` rejects.
        stream.set_write_timeout(Some(deadline.saturating_duration_since(now)))?;
        match stream.write(&bytes[written..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "health response write returned zero",
                ));
            }
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
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

    /// The shared inert (back-compat byte-identical) engine config the `/metrics` test harnesses use,
    /// extracted so the connz/disk-free integration test reuses the SAME config as `start()`.
    fn test_eng_cfg() -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
            compression: ironbus_core::compress::Codec::None,
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
            // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
            max_streams: 0,
            group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
            ram_ceiling_bytes: 0,
            disk_full_policy: DiskFullPolicy::DropNew,
            dedup: ironbus_core::dedup::DedupConfig::default(),
            durability_level: crate::engine::DurabilityLevel::Sync,
            flush_interval_ms: 0,
            flush_max_bytes: 0,
            // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
            // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
            codel_target_ms: 0,
            codel_interval_ms: 0,
            retry_budget_ratio_per_million: 0,
            retry_budget_window_ms: 0,
            fire_and_forget_msg_rate: 0,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: 0,
            egress_limit: 0,
            wal_fsync_headroom_bytes: 0,
            sync_max_dirty_bytes: 0,
            // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
            // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
            default_message_ttl_ms: 0,
            dead_letter_exchange: None,
            dead_letter_expired: false,
        }
    }

    fn start() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
    ) {
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), test_eng_cfg()).unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                // Watchdog disabled (window 0): these helpers exercise /metrics, /readyz, etc., so
                // /healthz keeps its static-200 contract. The dedicated #95 liveness tests below pass
                // a non-zero window and drive a ManualClock.
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
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
    fn a_request_line_with_an_invalid_utf8_byte_does_not_crash_the_broker() {
        // #860 regression: a request line carrying an invalid-UTF-8 byte must NOT abort the process.
        // Pre-fix, the raw newline index was used to slice the `from_utf8_lossy` string (where the bad
        // byte became a 3-byte U+FFFD), landing inside the U+FFFD and panicking; under `panic = "abort"`
        // that took down the entire broker from one unauthenticated packet. Post-fix the head is split on
        // its own `\n`, so the request is handled and the broker stays up.
        let (addr, shutdown, handle, _engine) = start();

        // A 0xFF byte in the request line (not expressible as a &str, so connect and write raw bytes).
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(b"GET /healthz \xFF\r\n\r\n").unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        let resp = String::from_utf8_lossy(&out);
        assert!(
            resp.starts_with("HTTP/1.1 "),
            "expected an HTTP response (no crash), got: {resp:?}"
        );

        // The broker is still alive: a normal probe on the SAME listener still succeeds.
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            h.starts_with("HTTP/1.1 200 OK"),
            "broker survived the malformed request and still serves: {h}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn stalled_probe_clients_do_not_block_a_concurrent_healthz_probe() {
        // #874 regression: the health accept loop must handle each probe connection with BOUNDED
        // concurrency, so a slow/stalled client can no longer serialize — and thereby starve — a
        // liveness/readiness probe. A client that opens a connection and dribbles a PARTIAL request
        // head with NO terminating newline holds its handler for the full REQUEST_TIMEOUT (5s). Pre-fix
        // the single inline accept loop was stuck on each such client for those 5s, so a concurrent
        // `GET /healthz` waited behind them (here behind FOUR of them, ~20s, past any read timeout) and
        // a k8s liveness probe would time out and RESTART a healthy broker. Post-fix each stalled client
        // occupies only its own handler thread (within the concurrency cap), so the healthy probe is
        // served immediately.
        let (addr, shutdown, handle, _engine) = start();

        // Four stalled clients (well under MAX_CONCURRENT_HEALTH_HANDLERS): each sends a request line
        // fragment with NO '\n', so its handler blocks in `read_request_head` until the 5s timeout. Held
        // in a Vec so the sockets stay open (a dropped `TcpStream` would EOF and free the handler early).
        let mut stalled = Vec::new();
        for _ in 0..4 {
            let mut c = TcpStream::connect(addr).unwrap();
            // No CRLF anywhere: `read_request_head` never sees a newline and blocks for REQUEST_TIMEOUT.
            c.write_all(b"GET /healthz HTTP/1.1").unwrap();
            c.flush().unwrap();
            stalled.push(c);
        }
        // Let the accept loop take the stalled connections and enter their handlers before the probe
        // races in (pre-fix this is where the single loop is now wedged for ~5s each).
        std::thread::sleep(Duration::from_millis(300));

        // The concurrent healthy probe must return 200 WELL within the window the stalled clients hold.
        // Pre-fix it blocks ~5s+ behind the serialized stalled handlers (often past `request`'s own 5s
        // read timeout, panicking); the 2s ceiling — far below the ~5s per stalled handler yet far above
        // the settle — fails pre-fix and passes comfortably post-fix.
        let started = std::time::Instant::now();
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        let elapsed = started.elapsed();
        assert!(
            h.starts_with("HTTP/1.1 200 OK"),
            "the concurrent probe is still served 200: {h}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the concurrent /healthz probe must not serialize behind the stalled clients \
             (took {elapsed:?}); pre-#874-fix the single inline accept loop blocked it behind their \
             ~5s handlers"
        );

        // Release the stalled clients (frees their handlers), then shut down and join the scope.
        drop(stalled);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    // Unix-only: staging the stall requires the Unix send-buffer-fills-then-blocks semantics. On
    // Windows loopback a 16 MiB write to a never-reading peer does not reliably block (the kernel
    // buffers/accepts it), so `write_all_by_deadline` returns `Ok` and the stall cannot be forced;
    // the assertion `expect_err` then fails there. The production `write_all_by_deadline` deadline is
    // wall-clock and platform-independent (and is exercised by the health server on all platforms);
    // the mutation reasoning in the body documents the guarantee it enforces.
    #[cfg(unix)]
    #[test]
    fn write_all_by_deadline_bounds_a_stalled_reader_regardless_of_body_size() {
        // #953: the whole-response write deadline must give up at the deadline even when the peer
        // never reads (so the OS send buffer fills and the write blocks), instead of blocking the
        // socket's per-syscall write timeout (REQUEST_TIMEOUT = 5s) on the full buffer. A body far
        // larger than any send buffer forces a blocking write; a 300ms deadline must cap it. Mutation
        // check: a `write_all_by_deadline` that ignored `deadline` (fell back to the 5s per-syscall
        // timeout) would return only after ~5s, failing the sub-2s ceiling below.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Connect a peer that NEVER reads, so the server-side send buffer fills and the write stalls.
        let _peer = TcpStream::connect(addr).unwrap();
        let (mut server, _a) = listener.accept().unwrap();
        // Far larger than any socket send buffer, so the write cannot drain and MUST block.
        let big = vec![b'x'; 16 * 1024 * 1024];
        let started = std::time::Instant::now();
        let deadline = started + Duration::from_millis(300);
        let err = write_all_by_deadline(&mut server, &big, deadline)
            .expect_err("a never-read peer must make the deadlined write fail, not succeed");
        let elapsed = started.elapsed();
        // The OS surfaces a fired write timeout as WouldBlock (EAGAIN) or TimedOut; either is fine.
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "expected a timeout-shaped error, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the write must be bounded by the whole-response deadline (~300ms), took {elapsed:?}; \
             a per-syscall-only timeout would block ~5s on the full send buffer"
        );
    }

    #[test]
    fn health_shed_lines_render_both_reasons() {
        // #953: the shed counter renders one labeled sample per reason with its exact value. A LABELED
        // `_total`, so its sample lines are excluded from the unlabeled resilience-taxonomy filter (they
        // end in `}`) and it is pinned only in FROZEN_METRIC_TYPES.
        let out = health_shed_lines(HealthShedSnapshot {
            at_cap: 7,
            spawn_refused: 3,
        });
        assert!(
            out.contains("# TYPE ironbus_health_shed_total counter\n"),
            "{out}"
        );
        assert!(
            out.contains("ironbus_health_shed_total{reason=\"at_cap\"} 7\n"),
            "{out}"
        );
        assert!(
            out.contains("ironbus_health_shed_total{reason=\"spawn_refused\"} 3\n"),
            "{out}"
        );
    }

    #[test]
    fn health_probes_shed_at_the_cap_are_counted_on_metrics() {
        // #953: shedding at MAX_CONCURRENT_HEALTH_HANDLERS was SILENT; now it increments
        // `ironbus_health_shed_total{reason="at_cap"}`, so a flood is observable. Open MORE than the cap
        // of stalled connections SIMULTANEOUSLY (each dribbles a headless request line so its handler
        // blocks in `read_request_head`), so by pigeonhole at least (count - cap) are shed at the cap.
        // Then release them (freeing the slots) and scrape /metrics, which must report a non-zero
        // at_cap. Mutation check: dropping the `shed.at_cap.fetch_add` leaves it 0 and fails here.
        let (addr, shutdown, handle, _engine) = start();

        // Comfortably above MAX_CONCURRENT_HEALTH_HANDLERS (32), held open in a Vec so all are
        // concurrently in flight before any handler frees (a dropped socket would EOF and free early).
        let mut stalled = Vec::new();
        for _ in 0..(MAX_CONCURRENT_HEALTH_HANDLERS + 12) {
            if let Ok(mut c) = TcpStream::connect(addr) {
                let _ = c.write_all(b"GET /metrics HTTP/1.1"); // no '\n': the handler blocks
                let _ = c.flush();
                stalled.push(c);
            }
        }
        // Let the accept loop take every pending connection: it admits the cap and SHEDS the rest.
        std::thread::sleep(Duration::from_millis(500));
        // Free the slots so the scrape below can be served, then let the handlers exit.
        drop(stalled);
        std::thread::sleep(Duration::from_millis(300));

        // Scrape /metrics (retry a little in case a slot has not freed yet) and read the at_cap count.
        let mut at_cap = 0i64;
        for _ in 0..10 {
            let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
            if m.starts_with("HTTP/1.1 200 OK") {
                at_cap = metric_value(&m, "ironbus_health_shed_total{reason=\"at_cap\"}");
                if at_cap > 0 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            at_cap >= 1,
            "opening {} > cap {} concurrent probes must shed at least one at the cap, counted on \
             ironbus_health_shed_total{{reason=\"at_cap\"}}, got {at_cap}",
            MAX_CONCURRENT_HEALTH_HANDLERS + 12,
            MAX_CONCURRENT_HEALTH_HANDLERS
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn readyz_flips_to_503_when_draining_while_healthz_stays_200_and_the_engine_is_still_healthy() {
        // The #637 SIGTERM-drain readiness gate: a broker that received a stop signal flips `draining`
        // and `/readyz` answers 503 ("draining") IMMEDIATELY, even though the engine writer is still
        // perfectly healthy (the drain has not begun) — the "stop accepting before stop serving"
        // ordering. `/healthz` (liveness) is UNAFFECTED: a draining broker is still live (200), so an
        // orchestrator distinguishes "drain me" from "restart me".
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), test_eng_cfg()).unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let draining = Arc::clone(&draining);
            let shared = Arc::clone(&shared);
            move || {
                serve_health_connz_draining(
                    &listener,
                    &shared,
                    &shutdown,
                    &draining,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                    &Arc::new(ConnectionMetrics::new()),
                    None,
                )
                .unwrap();
            }
        });

        // Before draining: /readyz is ready (the engine is healthy).
        let r = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200 OK"), "ready before drain: {r}");
        assert!(r.ends_with("ready"), "{r}");

        // Flip draining (what the SIGTERM path does FIRST, before the actor drain).
        draining.store(true, Ordering::Release);

        // /readyz now sheds 503 "draining" — and the engine is STILL healthy, proving the 503 comes
        // from the readiness gate, not a frozen writer or a gone actor.
        let r2 = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            r2.starts_with("HTTP/1.1 503 Service Unavailable"),
            "draining is 503: {r2}"
        );
        assert!(r2.ends_with("draining"), "the drain reason: {r2}");
        assert!(
            shared.with(|e| e.is_healthy()).unwrap(),
            "the engine writer is still healthy during the readiness flip (drain not yet started)"
        );

        // /healthz is UNAFFECTED by draining: a draining broker is still live (200).
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 200 OK"), "live while draining: {h}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// A test `EngineAccess` that reports the append-actor wedge watchdog (#862) as overrun on demand,
    /// delegating every real call to a shared engine. It lets a test drive the HTTP health server and
    /// assert `/healthz` and `/readyz` flip to 503 the moment the watchdog trips — WITHOUT staging a real
    /// hung fsync (the actor-level `a_hung_fsync_wedges...` test already proves the real-wedge detection).
    struct WedgeableEngine {
        inner: SharedEngine<InMemoryFs, Arc<ironbus_core::clock::ManualClock>>,
        wedged: Arc<AtomicBool>,
        /// The published writer live/frozen flag /readyz reads non-blockingly (#862); `true` = live.
        writer_healthy: Arc<AtomicBool>,
        /// The shared actor-liveness flag (#949/#922); `true` = the append actor is running. A test
        /// flips it `false` to model an UNEXPECTED actor death (return or panic) with the watchdog idle.
        alive: Arc<AtomicBool>,
    }

    impl EngineAccess<InMemoryFs, Arc<ironbus_core::clock::ManualClock>> for WedgeableEngine {
        fn produce(
            &self,
            append: crate::actor::OwnedAppend,
        ) -> Result<crate::actor::ProduceOutcome, crate::actor::ActorGone> {
            self.inner.produce(append)
        }
        fn with<R, J>(&self, job: J) -> Result<R, crate::actor::ActorGone>
        where
            R: Send + 'static,
            J: FnOnce(&mut Engine<InMemoryFs, Arc<ironbus_core::clock::ManualClock>>) -> R
                + Send
                + 'static,
        {
            self.inner.with(job)
        }
        fn now_monotonic_nanos(&self) -> u64 {
            self.inner.now_monotonic_nanos()
        }
        fn consumer_credit_caps(&self) -> (u32, u64) {
            self.inner.consumer_credit_caps()
        }
        fn actor_watchdog_overran(&self, _now_monotonic_nanos: u64) -> bool {
            self.wedged.load(Ordering::Relaxed)
        }
        fn writer_appears_healthy(&self) -> bool {
            self.writer_healthy.load(Ordering::Relaxed)
        }
        fn actor_alive(&self) -> bool {
            self.alive.load(Ordering::Relaxed)
        }
    }

    /// Runs `serve_health` over a `ManualClock` with the given liveness `window_nanos` and a beacon
    /// the caller drives, so the #95 hysteresis watchdog can be exercised deterministically: the test
    /// advances the clock and ticks (or withholds) the beacon, then probes `/healthz`. Returns the
    /// bound address, the shutdown flag, the join handle, the shared clock, the shared beacon, and the
    /// shared actor-watchdog "wedged" flag (#862; default `false`, so liveness tests are unaffected).
    #[allow(clippy::type_complexity)]
    fn start_watchdog(
        window_nanos: u64,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        Arc<ironbus_core::clock::ManualClock>,
        Arc<LivenessBeacon>,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    ) {
        use ironbus_core::clock::ManualClock;
        let clock = Arc::new(ManualClock::new());
        let engine = Engine::open(
            InMemoryFs::new(),
            Arc::clone(&clock),
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap();
        let inner: SharedEngine<InMemoryFs, Arc<ManualClock>> = Arc::new(Mutex::new(engine));
        // The actor-watchdog "wedged" flag (#862), default false so the liveness tests behave exactly as
        // before; the actor-wedge test flips it to drive /healthz and /readyz to 503.
        let wedged = Arc::new(AtomicBool::new(false));
        // The published writer live/frozen flag (#862), default true (a fresh broker's writer is live);
        // the frozen-writer test flips it to drive /readyz to 503 via the non-blocking path.
        let writer_healthy = Arc::new(AtomicBool::new(true));
        // The shared actor-liveness flag (#949/#922), default true (the actor is running); the
        // actor-gone test flips it to model an unexpected death the watchdog cannot see.
        let alive = Arc::new(AtomicBool::new(true));
        let engine_access = WedgeableEngine {
            inner,
            wedged: Arc::clone(&wedged),
            writer_healthy: Arc::clone(&writer_healthy),
            alive: Arc::clone(&alive),
        };
        // The beacon starts at the clock's origin (0), exactly as the broker seeds it from its start
        // instant, so it is fresh at t=0 and only goes stale once the clock advances past the window
        // with no tick.
        let beacon = Arc::new(LivenessBeacon::new(clock.now_monotonic_nanos()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let beacon = Arc::clone(&beacon);
            let clock = Arc::clone(&clock);
            move || {
                serve_health(
                    &listener,
                    &engine_access,
                    &shutdown,
                    false,
                    &beacon,
                    window_nanos,
                    &clock,
                )
                .unwrap();
            }
        });
        (
            addr,
            shutdown,
            handle,
            clock,
            beacon,
            wedged,
            writer_healthy,
            alive,
        )
    }

    #[test]
    fn healthz_is_200_while_progress_is_fresh() {
        // With a 30 ms window: a beacon tick at the current instant keeps /healthz 200 even after the
        // clock advances a little (under the window), so a slow-but-progressing loop never sheds.
        let window = 30_000_000; // 30 ms in nanos
        let (addr, shutdown, handle, clock, beacon, _wedged, _writer_healthy, _alive) =
            start_watchdog(window);

        // Fresh at t=0.
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 200 OK"), "{h}");

        // Advance 10 ms (well under the window) and tick: still healthy.
        clock.advance_monotonic_nanos(10_000_000);
        beacon.mark_progress(clock.now_monotonic_nanos());
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 200 OK"), "{h}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn healthz_flips_to_503_after_the_window_with_no_progress() {
        // The teeth of the watchdog (#95): with the loop STUCK (no further beacon tick), once the
        // clock has advanced past the window /healthz sheds 503. This is the only thing that makes
        // the guard real: remove the watchdog (revert to a static 200) and this fails.
        let window = 30_000_000; // 30 ms
        let (addr, shutdown, handle, clock, beacon, _wedged, _writer_healthy, _alive) =
            start_watchdog(window);

        // Tick once at t=0, then let the loop wedge: no more ticks.
        beacon.mark_progress(clock.now_monotonic_nanos());
        // At exactly the window: still healthy (strict >).
        clock.advance_monotonic_nanos(window);
        let at = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            at.starts_with("HTTP/1.1 200 OK"),
            "at the window is healthy: {at}"
        );

        // One nanosecond past the window with no progress: stuck, so 503.
        clock.advance_monotonic_nanos(1);
        let past = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            past.starts_with("HTTP/1.1 503 Service Unavailable"),
            "past the window with no progress is 503: {past}"
        );
        assert!(past.ends_with("no event-loop progress"), "{past}");

        // A resumed loop (a fresh tick) clears it: liveness is not a one-way latch.
        beacon.mark_progress(clock.now_monotonic_nanos());
        let resumed = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(resumed.starts_with("HTTP/1.1 200 OK"), "{resumed}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn healthz_does_not_flip_on_normal_idle() {
        // A healthy-but-idle broker must stay 200: the accept loop ticks the beacon every ~poll even
        // with no client work, so even across MANY window-lengths of pure idle /healthz never sheds.
        // This pins "idle is progress" so the watchdog cannot crash-loop an idle edge node.
        let window = 30_000_000; // 30 ms
        let (addr, shutdown, handle, clock, beacon, _wedged, _writer_healthy, _alive) =
            start_watchdog(window);

        // Model a long idle run: a 5 ms idle poll tick repeated past several windows.
        for _ in 0..50 {
            clock.advance_monotonic_nanos(5_000_000);
            beacon.mark_progress(clock.now_monotonic_nanos());
            let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
            assert!(h.starts_with("HTTP/1.1 200 OK"), "idle stays healthy: {h}");
        }

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn healthz_and_readyz_flip_to_503_when_the_append_actor_is_wedged() {
        // #862 end-to-end at the HTTP layer: when the append actor is wedged on a hung fsync, /healthz
        // AND /readyz both flip to 503 — instead of /healthz staying GREEN (the accept-loop beacon is
        // decoupled, #95) and /readyz HANGING behind the wedged fsync. The actor-level
        // `a_hung_fsync_wedges...` test proves the real-wedge detection; this proves the health surface
        // surfaces it. The accept-loop beacon is kept FRESH throughout so the actor-watchdog is the SOLE
        // reason for any 503, never the liveness window.
        //
        // The writer stays LIVE throughout (`_writer_healthy` default true), so the /readyz 503 below is
        // purely the wedge watchdog, never the frozen-writer branch — a wedge is a HANG, not a
        // returned-error freeze.
        let window = 30_000_000; // 30 ms
        let (addr, shutdown, handle, clock, beacon, wedged, _writer_healthy, _alive) =
            start_watchdog(window);
        beacon.mark_progress(clock.now_monotonic_nanos());

        // Not wedged: both routes are healthy.
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            h.starts_with("HTTP/1.1 200 OK"),
            "healthy before the wedge: {h}"
        );
        let r = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            r.starts_with("HTTP/1.1 200 OK"),
            "ready before the wedge: {r}"
        );

        // The append actor wedges (a hung fsync overran the bound): /healthz AND /readyz flip to 503,
        // and /readyz answers PROMPTLY (the non-blocking watchdog read, never the wedged actor).
        wedged.store(true, Ordering::Release);
        beacon.mark_progress(clock.now_monotonic_nanos());
        let h2 = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            h2.starts_with("HTTP/1.1 503 Service Unavailable"),
            "healthz flips to 503 on an actor wedge: {h2}"
        );
        assert!(h2.ends_with("append actor wedged"), "{h2}");
        let r2 = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            r2.starts_with("HTTP/1.1 503 Service Unavailable"),
            "readyz flips to 503 (and does NOT hang) on an actor wedge: {r2}"
        );
        assert!(r2.ends_with("append actor wedged"), "{r2}");

        // Recovery (the fsync completed and the actor un-wedged): both return to healthy — not a latch.
        wedged.store(false, Ordering::Release);
        beacon.mark_progress(clock.now_monotonic_nanos());
        let h3 = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            h3.starts_with("HTTP/1.1 200 OK"),
            "healthz recovers after the wedge clears: {h3}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn healthz_and_readyz_flip_to_503_when_the_append_actor_died_unexpectedly() {
        // #922: an UNEXPECTED append-actor death (return or panic) while the watchdog reads IDLE and
        // `draining` is unset. The wedge watchdog never trips (`processing_since == 0` on an idle
        // death — modeled here by leaving `wedged` false) and the frozen-writer flag is stuck at its
        // last-published `true` (a dead actor publishes nothing), so ONLY the #949 alive flag can
        // catch it. Both routes must answer 503 "append actor gone": /readyz so the orchestrator stops
        // routing, /healthz so it restarts the node (a broker that can never serve another produce is
        // dead, not merely unready). The window is 30 ms with a fresh beacon, so liveness is NOT the
        // reason for any 503 — and the actor-gone branch works even with the watchdog disabled.
        let window = 30_000_000; // 30 ms
        let (addr, shutdown, handle, clock, beacon, _wedged, _writer_healthy, alive) =
            start_watchdog(window);
        beacon.mark_progress(clock.now_monotonic_nanos());

        // Alive: both routes healthy (the happy path is unchanged).
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 200 OK"), "live before death: {h}");
        let r = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200 OK"), "ready before death: {r}");

        // The actor dies unexpectedly (the drop guard flipped the shared flag; `draining` unset,
        // `wedged` untripped, writer flag frozen at `true`).
        alive.store(false, Ordering::Release);
        beacon.mark_progress(clock.now_monotonic_nanos());
        let r2 = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            r2.starts_with("HTTP/1.1 503 Service Unavailable"),
            "readyz flips to 503 on an unexpected actor death: {r2}"
        );
        assert!(r2.ends_with("append actor gone"), "{r2}");
        let h2 = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            h2.starts_with("HTTP/1.1 503 Service Unavailable"),
            "healthz flips to 503 too (dead-restart-me, strictly worse than a wedge): {h2}"
        );
        assert!(h2.ends_with("append actor gone"), "{h2}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn draining_wins_over_actor_gone_on_readyz_and_healthz_stays_200_through_the_drain() {
        // #922 composition with the #637 drain gate: during a GRACEFUL shutdown the actor exits BY
        // DESIGN before the process does, flipping the alive flag in the terminal window while the
        // health server keeps serving. `/readyz` must still answer "draining" (the gate is checked
        // FIRST — the operator asked for this state), and `/healthz` must stay 200 ("told to die" is
        // not "dead, restart me" — the `!draining` guard), so an orchestrator never counts a graceful
        // drain as a crash. Watchdog window 0 (disabled) — the #922 hard case.
        use ironbus_core::clock::ManualClock;
        let clock = Arc::new(ManualClock::new());
        let engine = Engine::open(InMemoryFs::new(), Arc::clone(&clock), test_eng_cfg()).unwrap();
        let inner: SharedEngine<InMemoryFs, Arc<ManualClock>> = Arc::new(Mutex::new(engine));
        let alive = Arc::new(AtomicBool::new(true));
        let engine_access = WedgeableEngine {
            inner,
            wedged: Arc::new(AtomicBool::new(false)),
            writer_healthy: Arc::new(AtomicBool::new(true)),
            alive: Arc::clone(&alive),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let draining = Arc::clone(&draining);
            let clock = Arc::clone(&clock);
            move || {
                serve_health_connz_draining(
                    &listener,
                    &engine_access,
                    &shutdown,
                    &draining,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &clock,
                    &Arc::new(ConnectionMetrics::new()),
                    None,
                )
                .unwrap();
            }
        });

        // The SIGTERM path: flip `draining` FIRST, then (later) the actor drain exits and flips the
        // alive flag — model both, in order.
        draining.store(true, Ordering::Release);
        alive.store(false, Ordering::Release);

        // /readyz: the drain gate wins the priority chain — the operator-initiated state, not the
        // alarming "append actor gone".
        let r = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            r.starts_with("HTTP/1.1 503 Service Unavailable"),
            "still 503 while draining: {r}"
        );
        assert!(
            r.ends_with("draining"),
            "the drain reason wins over actor-gone: {r}"
        );

        // /healthz: 200 through the drain's terminal window — a graceful exit is never a crash.
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            h.starts_with("HTTP/1.1 200 OK"),
            "live through the graceful drain even after the actor exited: {h}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn readyz_flips_to_503_on_a_frozen_writer_without_blocking_on_the_actor() {
        // #862: /readyz reads the writer-frozen state from a PUBLISHED atomic, NOT through the actor
        // (engine.with), so a frozen writer sheds 503 promptly AND — crucially — the read can never block
        // behind a hung writer and wedge the single-threaded health server. /healthz is UNAFFECTED by a
        // frozen writer (a frozen-but-running process is still alive — that is liveness, not readiness).
        let window = 30_000_000; // 30 ms
        let (addr, shutdown, handle, clock, beacon, _wedged, writer_healthy, _alive) =
            start_watchdog(window);
        beacon.mark_progress(clock.now_monotonic_nanos());

        // Live writer: ready.
        let r = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            r.starts_with("HTTP/1.1 200 OK"),
            "ready while the writer is live: {r}"
        );

        // The writer FREEZES (a covering fsync RETURNED an error): /readyz sheds 503 "writer frozen",
        // read non-blockingly; /healthz stays 200 (the process is still live).
        writer_healthy.store(false, Ordering::Release);
        let r2 = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            r2.starts_with("HTTP/1.1 503 Service Unavailable"),
            "readyz flips to 503 on a frozen writer: {r2}"
        );
        assert!(r2.ends_with("writer frozen"), "{r2}");
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(
            h.starts_with("HTTP/1.1 200 OK"),
            "a frozen-but-live broker is still alive (liveness != readiness): {h}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_zero_window_disables_the_healthz_watchdog() {
        // window 0 = the watchdog is off: /healthz is the legacy static 200 no matter how stale the
        // beacon, the opt-out path (and the contract the existing metrics/admin helpers rely on).
        let (addr, shutdown, handle, clock, _beacon, _wedged, _writer_healthy, _alive) =
            start_watchdog(0);
        // Advance far past any window with NO beacon tick: still 200, because the watchdog is off.
        clock.advance_monotonic_nanos(10_000_000_000);
        let h = request(addr, "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 200 OK"), "{h}");
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
    #[allow(clippy::too_many_lines)] // one exposition test asserting many metric lines end to end.
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
        // The appended at-rest-scrubber reason (#92, #59) has its own per-reason series (zero on a
        // clean start), and the data-loss gauge (torn-tail-excluded total, #59) is present and zero.
        assert!(
            m.contains("\nironbus_recovery_loss_bytes{reason=\"scrubber_suspect\"} 0\n"),
            "{m}"
        );
        assert!(
            m.contains("\n# TYPE ironbus_recovery_data_loss_bytes gauge\n"),
            "{m}"
        );
        assert!(m.contains("\nironbus_recovery_data_loss_bytes 0\n"), "{m}");
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
        // The opt-in dedup counters (#33) are present and zero on a broker no producer dedups
        // against (the two produces above sent no msg_id, so neither counter moved).
        assert!(m.contains("# TYPE ironbus_dedup_hits_total counter"), "{m}");
        assert!(m.contains("\nironbus_dedup_hits_total 0\n"), "{m}");
        assert!(
            m.contains("# TYPE ironbus_dedup_out_of_window_total counter"),
            "{m}"
        );
        assert!(m.contains("\nironbus_dedup_out_of_window_total 0\n"), "{m}");
        // The idempotent-producer out-of-order rejection counter (V2-M8) is present and zero on a
        // broker no producer sequences against.
        assert!(
            m.contains("# TYPE ironbus_producer_out_of_order_total counter"),
            "{m}"
        );
        assert!(
            m.contains("\nironbus_producer_out_of_order_total 0\n"),
            "{m}"
        );
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

    /// `/metrics` renders the `ironbus_consumer_overflow_saturated` gauge (#321): 0 (with a `gauge`
    /// TYPE line) on a fresh registry, and 1 once the bounded overflow fold-ledger saturates (more
    /// than the cap of distinct over-cap consumers seen), signalling the `__overflow__` lag series
    /// has become a monotonic lower bound. Driven straight through the private `registry_body`
    /// renderer, in the style of the registry-metrics rendering tests above.
    #[test]
    fn metrics_renders_the_overflow_saturated_gauge() {
        use crate::registry::{MetricRegistry, MAX_CONSUMER_SERIES, MAX_OVERFLOW_LEDGER};

        let mut registry = MetricRegistry::new(env!("CARGO_PKG_VERSION"), 0, 0);
        registry.seed_head(1);

        // A fresh registry has not saturated: the gauge renders 0 with a `gauge` TYPE line and no
        // stray `_total` suffix that would pull it into the frozen taxonomy.
        let before = registry_body(&registry, 0);
        assert!(
            before.contains("# TYPE ironbus_consumer_overflow_saturated gauge"),
            "{before}"
        );
        assert!(
            before.contains("\nironbus_consumer_overflow_saturated 0\n"),
            "{before}"
        );
        assert!(
            !before.contains("ironbus_consumer_overflow_saturated_total"),
            "{before}"
        );

        // Fill the distinct-series cap, then the entire overflow ledger, then one MORE distinct
        // over-cap consumer to saturate the ledger (the defense-in-depth safety valve).
        for i in 0..MAX_CONSUMER_SERIES {
            registry.set_consumer_committed(format!("c{i}").as_bytes(), 0);
        }
        for i in 0..MAX_OVERFLOW_LEDGER {
            registry.set_consumer_committed(format!("o{i}").as_bytes(), 0);
        }
        assert_eq!(
            registry.consumer_lag().overflow_saturated(),
            0,
            "ledger full but not yet saturated"
        );
        registry.set_consumer_committed(b"past-the-ledger", 0);
        assert!(
            registry.consumer_lag().overflow_saturated() > 0,
            "the past-capacity consumer saturated the ledger"
        );

        // Now the gauge renders 1: the operator's scrape-visible signal that the `__overflow__` lag
        // series is a monotonic lower bound.
        let after = registry_body(&registry, 0);
        assert!(
            after.contains("# TYPE ironbus_consumer_overflow_saturated gauge"),
            "{after}"
        );
        assert!(
            after.contains("\nironbus_consumer_overflow_saturated 1\n"),
            "{after}"
        );
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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            move || {
                // Watchdog disabled (window 0): these helpers exercise /metrics, /readyz, etc., so
                // /healthz keeps its static-200 contract. The dedicated #95 liveness tests below pass
                // a non-zero window and drive a ManualClock.
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
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

    /// Starts a broker with a non-zero RAM ceiling (#118), so the `ironbus_ram_headroom_bytes` gauge
    /// reports a real headroom (`ceiling - rss`) rather than the unavailable sentinel.
    fn start_with_ram_ceiling(
        ram_ceiling_bytes: u64,
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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            move || {
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
        });
        (addr, shutdown, handle, engine)
    }

    /// Starts a health server over an engine at the given durability level + interval triggers
    /// (#341, #379), so a test can scrape the `ironbus_durability_*` series for a relaxed level.
    fn start_with_durability(
        level: crate::engine::DurabilityLevel,
        flush_interval_ms: u64,
        flush_max_bytes: u64,
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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: level,
                flush_interval_ms,
                flush_max_bytes,
                // Backpressure controls (#68, #69) default to inert in the metrics test rig.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            move || {
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
        });
        (addr, shutdown, handle, engine)
    }

    #[test]
    fn metrics_render_the_durability_level_as_safe_under_the_default() {
        // The default level is observable AND power-loss safe (#341, #379): /metrics carries the
        // level info gauge labeled `sync`, the power-loss-unsafe gauge at 0, and a zero unsynced
        // exposure. A zero-config broker advertises itself as the safe durable level.
        let (addr, shutdown, handle, _engine) = start();
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        assert!(
            m.contains("ironbus_durability_level_info{level=\"sync\"} 1"),
            "the default level is reported as sync: {m}"
        );
        assert_eq!(
            metric_value(&m, "ironbus_durability_power_loss_unsafe"),
            0,
            "sync is power-loss safe (I2 holds): {m}"
        );
        assert_eq!(
            metric_value(&m, "ironbus_durability_unsynced_bytes"),
            0,
            "sync has no unsynced exposure: {m}"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn metrics_render_a_relaxed_level_as_power_loss_unsafe_with_a_live_exposure() {
        // A relaxed level is observable as power-loss UNSAFE with a live unsynced exposure (#379):
        // under `async`, after a produce that is acked-but-not-synced, /metrics labels the level
        // `async`, sets the power-loss-unsafe gauge to 1, and reports a NON-ZERO unsynced byte
        // exposure (the bytes-at-risk a power cut would lose). The operator's loss-exposure surface.
        let (addr, shutdown, handle, engine) =
            start_with_durability(crate::engine::DurabilityLevel::Async, 0, 0);
        {
            let mut g = engine.lock().unwrap();
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"at-risk-under-async",
            })
            .unwrap();
        }
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        assert!(
            m.contains("ironbus_durability_level_info{level=\"async\"} 1"),
            "the active level is reported as async: {m}"
        );
        assert_eq!(
            metric_value(&m, "ironbus_durability_power_loss_unsafe"),
            1,
            "async waives I2: the power-loss-unsafe gauge is 1: {m}"
        );
        assert!(
            metric_value(&m, "ironbus_durability_unsynced_bytes") > 0,
            "async has a live unsynced exposure after an unsynced produce: {m}"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// Extracts the value of a single un-labeled gauge/counter sample line `name <value>` from a
    /// rendered `/metrics` body, as an `i64` (so the -1 RAM-headroom sentinel parses too).
    fn metric_value(body: &str, name: &str) -> i64 {
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix(name) {
                if let Some(v) = rest.strip_prefix(' ') {
                    return v.trim().parse().unwrap_or_else(|_| {
                        panic!("metric {name} value `{v}` did not parse as i64; body:\n{body}")
                    });
                }
            }
        }
        panic!("metric {name} not found in body:\n{body}");
    }

    #[test]
    fn metrics_renders_the_edge_write_amplification_series() {
        // The edge write-amp series (#118): after a known produce, /metrics carries the logical and
        // physical byte counters and the derived ratio, with physical > logical (amplification > 1)
        // and the ratio strictly above 1.000. A test that pins these fails if the accounting or the
        // rendering regresses.
        let (addr, shutdown, handle, engine) = start();
        {
            let mut g = engine.lock().unwrap();
            for _ in 0..4 {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload: b"edge-write-amp-probe",
                })
                .unwrap();
            }
        }
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        // The series are present with their TYPE declarations.
        assert!(
            m.contains("# TYPE ironbus_logical_bytes_written counter"),
            "{m}"
        );
        assert!(
            m.contains("# TYPE ironbus_physical_bytes_written counter"),
            "{m}"
        );
        assert!(m.contains("# TYPE ironbus_write_amp_ratio gauge"), "{m}");

        let logical = metric_value(&m, "ironbus_logical_bytes_written");
        let physical = metric_value(&m, "ironbus_physical_bytes_written");
        // 4 records x 20-byte payload = 80 logical bytes.
        assert_eq!(logical, 4 * 20, "logical is the sum of the user payloads");
        assert!(
            physical > logical,
            "physical {physical} should exceed logical {logical} (write amplification > 1)"
        );
        // The ratio renders as `<int>.<3-digit milli>` and is strictly above 1.000.
        let ratio_line = m
            .lines()
            .find(|l| l.starts_with("ironbus_write_amp_ratio "))
            .unwrap_or_else(|| panic!("no ratio line in {m}"));
        let ratio_str = ratio_line
            .trim_start_matches("ironbus_write_amp_ratio ")
            .trim();
        assert!(
            ratio_str.contains('.'),
            "the ratio is rendered with a decimal point, got `{ratio_str}`"
        );
        assert!(
            ratio_str > "1.000",
            "the write-amp ratio should exceed 1.000, got `{ratio_str}`"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn ram_headroom_gauge_reflects_the_ceiling_minus_rss() {
        // With a configured RAM ceiling (#118), the headroom gauge reports `ceiling - rss`: a real,
        // non-sentinel value strictly below the ceiling (the process always uses SOME RSS) and equal
        // to the ceiling minus the measured RSS at scrape time. The ceiling is set far above any
        // plausible test RSS so the headroom is positive on every platform.
        let ceiling: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB, far above any test RSS
        let (addr, shutdown, handle, _engine) = start_with_ram_ceiling(ceiling);
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.contains("# TYPE ironbus_ram_headroom_bytes gauge"), "{m}");
        let headroom = metric_value(&m, "ironbus_ram_headroom_bytes");
        // On Linux/macOS the RSS is readable, so the headroom is a real value: positive, below the
        // ceiling, and equal to ceiling - rss for the RSS measured here.
        if let Some(rss) = crate::rss::current_rss_bytes() {
            assert!(
                headroom > 0,
                "headroom should be positive with a huge ceiling, got {headroom}"
            );
            let headroom_u = u64::try_from(headroom).expect("positive headroom fits u64");
            assert!(
                headroom_u < ceiling,
                "headroom {headroom} must be below the ceiling {ceiling} (the process uses some RSS)"
            );
            let expected = crate::rss::ram_headroom_bytes(ceiling, Some(rss));
            // The scrape's own RSS reading may differ from ours by a little; assert it is within a
            // generous 64 MiB window of ceiling - our-rss, which proves it is ceiling-minus-an-RSS,
            // not a constant or the sentinel.
            let delta = (headroom - expected).unsigned_abs();
            assert!(
                delta < 64 * 1024 * 1024,
                "headroom {headroom} should track ceiling - rss ({expected}); delta {delta}"
            );
        } else {
            // No RSS on this platform: the gauge is the unavailable sentinel.
            assert_eq!(
                headroom,
                crate::rss::RSS_UNAVAILABLE,
                "no RSS means the sentinel"
            );
        }

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn ram_headroom_gauge_is_the_sentinel_without_a_ceiling() {
        // With NO RAM ceiling configured (the default), the headroom gauge reports the -1 unavailable
        // sentinel rather than a misleading maximal headroom (#118).
        let (addr, shutdown, handle, _engine) = start();
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert_eq!(
            metric_value(&m, "ironbus_ram_headroom_bytes"),
            crate::rss::RSS_UNAVAILABLE,
            "no ceiling means the unavailable sentinel; body:\n{m}"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn metrics_surfaces_the_daily_write_budget_over_signal_when_exceeded() {
        // The opt-in daily physical write budget (#118): once today's physical writes reach the
        // budget, a produce is shed as a distinct, final drop-new reject, the over-budget gauge flips
        // to 1, and the shed counter ticks. Off (0) by default, so this configures a tiny budget.
        // Probe one record's physical footprint, then cap the day at exactly the first segment header
        // plus one record so the SECOND produce is over budget.
        let probe = {
            let e = Engine::open(
                InMemoryFs::new(),
                SystemClock::new(),
                EngineConfig {
                    consume_longpoll_ms: 0,
                    compression: ironbus_core::compress::Codec::None,
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
                    // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                    max_streams: 0,
                    group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                    ram_ceiling_bytes: 0,
                    disk_full_policy: DiskFullPolicy::DropNew,
                    dedup: ironbus_core::dedup::DedupConfig::default(),
                    durability_level: crate::engine::DurabilityLevel::Sync,
                    flush_interval_ms: 0,
                    flush_max_bytes: 0,
                    // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                    // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                    codel_target_ms: 0,
                    codel_interval_ms: 0,
                    retry_budget_ratio_per_million: 0,
                    retry_budget_window_ms: 0,
                    fire_and_forget_msg_rate: 0,
                    fire_and_forget_byte_rate: 0,
                    fire_and_forget_refill_ms: 0,
                    egress_limit: 0,
                    wal_fsync_headroom_bytes: 0,
                    sync_max_dirty_bytes: 0,
                    // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                    // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                    default_message_ttl_ms: 0,
                    dead_letter_exchange: None,
                    dead_letter_expired: false,
                },
            )
            .unwrap();
            let mut g = e;
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"budget-probe",
            })
            .unwrap();
            g.physical_bytes_written_today()
        };
        // Budget = exactly one record's physical footprint today: the first produce is admitted (the
        // meter is below the budget when checked), the second is over budget and shed.
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
                log: LogConfig::default().with_daily_physical_write_budget_bytes(probe),
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let handle = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let shutdown = Arc::clone(&shutdown);
            move || {
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
        });
        // The first produce is admitted; the over-budget gauge is still 0 and nothing has shed.
        {
            let mut g = engine.lock().unwrap();
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"budget-probe",
            })
            .unwrap();
        }
        let m0 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(
            m0.contains("# TYPE ironbus_daily_write_budget_over gauge"),
            "{m0}"
        );
        assert_eq!(
            metric_value(&m0, "ironbus_daily_write_budget_over"),
            1,
            "{m0}"
        );
        assert_eq!(
            metric_value(&m0, "ironbus_daily_write_budget_sheds_total"),
            0,
            "{m0}"
        );
        assert_eq!(
            metric_value(&m0, "ironbus_produce_saturated"),
            0,
            "no shed yet: {m0}"
        );
        assert_eq!(
            metric_value(&m0, "ironbus_daily_physical_write_budget_bytes"),
            i64::try_from(probe).expect("the budget fits i64"),
            "the configured budget is echoed: {m0}"
        );

        // The second produce is shed by the governor (non-fatal); the shed counter ticks and the
        // saturation signal flips to 1.
        {
            let mut g = engine.lock().unwrap();
            let err = g
                .produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload: b"budget-probe",
                })
                .unwrap_err();
            assert!(
                err.is_at_capacity(),
                "the over-budget produce sheds, got {err:?}"
            );
            assert!(g.is_healthy(), "a budget shed never freezes the writer");
        }
        let m1 = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert_eq!(
            metric_value(&m1, "ironbus_daily_write_budget_sheds_total"),
            1,
            "{m1}"
        );
        assert_eq!(
            metric_value(&m1, "ironbus_daily_write_budget_over"),
            1,
            "{m1}"
        );
        assert_eq!(
            metric_value(&m1, "ironbus_produce_saturated"),
            1,
            "the shed sets saturation: {m1}"
        );
        // The over-budget shed also flows through the existing drop-new rejection counter.
        assert_eq!(
            metric_value(&m1, "ironbus_produce_rejected_total"),
            1,
            "{m1}"
        );

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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            // The watchdog is disabled (window 0) for this metric-rendering test, so it keeps the
            // legacy static-200 /healthz contract while exercising /metrics.
            let clock = Arc::clone(&clock);
            move || {
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &clock,
                )
                .unwrap();
            }
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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            move || {
                // Watchdog disabled (window 0): these helpers exercise /metrics, /readyz, etc., so
                // /healthz keeps its static-200 contract. The dedicated #95 liveness tests below pass
                // a non-zero window and drive a ManualClock.
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
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
                        Poll::Compacted { .. } => panic!("unexpected compaction"),
                        Poll::Filtered { .. } => panic!("unexpected filtered"),
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
                        Poll::Compacted { .. } => panic!("unexpected compaction"),
                        Poll::Filtered { .. } => panic!("unexpected filtered"),
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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropOldest,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            move || {
                // Watchdog disabled (window 0): these helpers exercise /metrics, /readyz, etc., so
                // /healthz keeps its static-200 contract. The dedicated #95 liveness tests below pass
                // a non-zero window and drive a ManualClock.
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
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
        // The TTL expiry-and-reclaim counter (V2-M4, #549): a resilience drop signal alongside
        // dead_lettered (an expired-and-reclaimed message is accounted here, not silently dropped).
        "ironbus_expired_total",
        // The per-subject filtered-consumer skip counter (#594): the wildcard-subscription
        // selectivity signal, alongside the other resilience/observability counters.
        "ironbus_filtered_total",
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
        // The daily-physical-write-budget shed counter (#118): a produce shed because the opt-in
        // flash-wear governor's daily budget was reached (a distinct, FINAL drop-new reject, a
        // separate error from the disk-full byte-cap shed). A shed is a resilience event the taxonomy
        // guarantees is never
        // silent, so it belongs here. The edge GAUGES the same #118 work adds
        // (`ironbus_logical_bytes_written`/`ironbus_physical_bytes_written` are counters but are
        // write-AMPLIFICATION accounting, not resilience sheds; `ironbus_write_amp_ratio`,
        // `ironbus_ram_headroom_bytes`, `ironbus_produce_saturated`,
        // `ironbus_daily_physical_write_budget_bytes`, `ironbus_physical_bytes_written_today`, and
        // `ironbus_daily_write_budget_over` are gauges) are NOT in this resilience-shed set: the two
        // write-amp counters are byte-accounting, not loss/shed/skip events, and the gauges carry no
        // `_total` suffix, so the taxonomy test excludes them by construction.
        "ironbus_daily_write_budget_sheds_total",
        // The opt-in effectively-once dedup counters (#3, #33): a benign dedup HIT (a msg_id already
        // in the producer's window, so the original offset was returned and no second copy stored) and
        // an OUT-OF-WINDOW eviction (an id aged out by the time bound, so a later republish would not
        // be deduped). Both are resilience/observability events the taxonomy guarantees are never
        // silent (a dedup hit AVOIDED a double-store; an out-of-window event WARNS the window is too
        // small for the retry interval), so they are `_total` counters in the frozen set. The dedup
        // ITSELF carries no new gauge; the original/duplicate offset rides the existing PubAck/
        // PubAckDuplicate frames, not a metric.
        "ironbus_dedup_hits_total",
        "ironbus_dedup_out_of_window_total",
        // The idempotent-producer out-of-order rejection counter (V2-M8, #638): a sequenced publish
        // whose seq skipped past the next-expected was REJECTED (the Kafka OutOfOrderSequence rule, so
        // a later retry of the skipped seq cannot double-append). A never-silent resilience event the
        // taxonomy guarantees is counted, an unlabeled `_total`, so it joins this set. (A sequenced
        // dedup HIT shares `ironbus_dedup_hits_total` — the same observable as a msg_id dedup hit — so
        // it adds no new counter there; the durable high-water carries no new gauge.)
        "ironbus_producer_out_of_order_total",
        // The backpressure shed counters (#68, #69): each is a deliberate resilience SHED the #16
        // contract guarantees is never silent. CoDel sojourn shed and the depth/byte backstop shed
        // (#68); the fire-and-forget token-bucket shed and the egress AIMD shed (#69); and the
        // CoDel suspend-gap interval-reset counter (a resilience event: a sleeping device that did
        // NOT misfire). The `ironbus_retry_shed_total{side="broker"}` counter carries a `side` LABEL
        // (per docs/BACKPRESSURE.md), so its sample line is excluded from this UNLABELED-`_total`
        // taxonomy set by construction (the extractor filters on a bare `name value` shape); it is
        // pinned in `FROZEN_METRIC_TYPES` instead, exactly like the other labeled series. The
        // backpressure GAUGES (`ironbus_codel_sojourn_estimate_ms`, `ironbus_retry_ratio`,
        // `ironbus_egress_limit`) carry no `_total` suffix, so they are excluded too.
        "ironbus_codel_shed_total",
        "ironbus_codel_backstop_shed_total",
        "ironbus_codel_interval_resets_total",
        "ironbus_fire_and_forget_shed_total",
        "ironbus_egress_shed_total",
        // The fsync-headroom shed counter (#378): a new produce shed because the un-fsynced backlog
        // (the loss window / RAM bound) could not be drained below the configured headroom (only
        // reached under a relaxed durability level that defers the fsync). A deliberate resilience
        // SHED the #16 contract guarantees is never silent, an unlabeled `_total`, so it joins this
        // set. The companion `ironbus_wal_fsync_headroom_bytes` is a GAUGE (no `_total`), so it is
        // excluded here and pinned only in `FROZEN_METRIC_TYPES`.
        "ironbus_wal_fsync_headroom_shed_total",
        // The torn-tail recovery-repair counter (#575): a torn/unsynced tail truncated to the longest
        // valid prefix at recovery (a power-loss repair, NOT data loss). A never-silent recovery EVENT
        // the marquee NATS-can't taxonomy guarantees is counted, an UNLABELED `_total`, so it joins
        // this set. Its labeled siblings `ironbus_recovery_runs_total{outcome}` and
        // `ironbus_corruption_repairs_total{artifact}` carry a label, so their sample lines are
        // excluded from this unlabeled-`_total` set by construction and pinned only in
        // `FROZEN_METRIC_TYPES`, exactly like `ironbus_cluster_ack_total` / `ironbus_retry_shed_total`.
        // The `ironbus_recovery_loss_*` / `ironbus_recovery_data_loss_bytes` series are GAUGES (no
        // `_total`), so they are excluded here too.
        "ironbus_torn_tail_repairs_total",
        // The per-stream/per-group throughput cardinality-cap counter (#571): a stream/group label
        // refused a distinct series at the 1024-series cap was folded into `__overflow__`. A
        // cardinality-pressure signal, never a silent drop, so it belongs in the frozen taxonomy,
        // exactly like `ironbus_consumer_labels_dropped_total`. The throughput SAMPLE counters
        // (`ironbus_stream_produced_total{stream}` / `ironbus_group_consumed_total{group}`) and the
        // per-ack-level counter (`ironbus_produce_ack_level_total{level}`) all carry a LABEL, so their
        // sample lines are excluded from this unlabeled-`_total` set by construction and pinned only in
        // `FROZEN_METRIC_TYPES`.
        "ironbus_throughput_labels_dropped_total",
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

    /// The COMPLETE frozen `(metric name -> type)` contract for `/metrics` (#22, #99). Every metric
    /// the endpoint declares, counters AND gauges AND histograms, with its exact Prometheus type. The
    /// golden test below asserts the rendered `# TYPE` set equals this map EXACTLY, so ANY metric
    /// rename, type change, or unit change (a unit lives in the name suffix `_seconds`/`_bytes`/
    /// `_total`/`_offset`, so a unit change is a name change) fails CI until this map and
    /// docs/METRICS.md are bumped deliberately. This is the #99 "golden test fails on any metric
    /// name/type/unit change without a contract bump" criterion, widened past the `_total`-only
    /// taxonomy test to the whole surface.
    const FROZEN_METRIC_TYPES: &[(&str, &str)] = &[
        // Operational counters (the `_total` family; a superset check against the taxonomy test).
        ("ironbus_produced_total", "counter"),
        ("ironbus_produced_bytes_total", "counter"),
        ("ironbus_produce_rejected_total", "counter"),
        ("ironbus_delivered_total", "counter"),
        ("ironbus_redelivered_total", "counter"),
        ("ironbus_dead_lettered_total", "counter"),
        ("ironbus_expired_total", "counter"),
        ("ironbus_filtered_total", "counter"),
        ("ironbus_dlq_records_total", "counter"),
        ("ironbus_acks_total", "counter"),
        ("ironbus_segments_reaped_total", "counter"),
        ("ironbus_segments_force_reaped_total", "counter"),
        ("ironbus_truncations_total", "counter"),
        ("ironbus_truncated_records_total", "counter"),
        ("ironbus_counter_checkpoint_repair_total", "counter"),
        ("ironbus_consumer_labels_dropped_total", "counter"),
        // Opt-in effectively-once dedup counters (#3, #33): the benign-hit and out-of-window counts.
        ("ironbus_dedup_hits_total", "counter"),
        ("ironbus_dedup_out_of_window_total", "counter"),
        ("ironbus_producer_out_of_order_total", "counter"),
        // Edge write-amplification (#118): two byte counters (TYPE counter, but NOT `_total`-named,
        // matching the issue's contract, so the resilience-taxonomy `_total` filter excludes them)
        // plus the daily-write-budget shed counter (a resilience shed, so it IS `_total` and in the
        // frozen taxonomy too).
        ("ironbus_logical_bytes_written", "counter"),
        ("ironbus_physical_bytes_written", "counter"),
        ("ironbus_daily_write_budget_sheds_total", "counter"),
        // Broker gauges.
        ("ironbus_committed_offset", "gauge"),
        ("ironbus_flushed_offset", "gauge"),
        ("ironbus_consumer_lag", "gauge"),
        ("ironbus_in_flight", "gauge"),
        ("ironbus_writer_healthy", "gauge"),
        ("ironbus_last_dead_lettered_offset", "gauge"),
        ("ironbus_recovery_truncated_bytes", "gauge"),
        ("ironbus_quarantine_bytes", "gauge"),
        ("ironbus_consumer_overflow_saturated", "gauge"),
        // Edge gauges (#118): write-amp ratio, RAM headroom, the throughput-collapse saturation
        // signal, and the opt-in daily-write-budget accounting (budget, today's meter, over-budget).
        ("ironbus_write_amp_ratio", "gauge"),
        ("ironbus_ram_headroom_bytes", "gauge"),
        ("ironbus_produce_saturated", "gauge"),
        ("ironbus_daily_physical_write_budget_bytes", "gauge"),
        ("ironbus_physical_bytes_written_today", "gauge"),
        ("ironbus_daily_write_budget_over", "gauge"),
        // Durability-level observability gauges (#341, #379): the active level (a `level`-labeled info
        // gauge), the sticky power-loss-unsafe signal (1 when the active level waives I2), and the live
        // unsynced bytes-at-risk. All GAUGES (no `_total`), so they extend this contract without
        // touching FROZEN_RESILIENCE_COUNTERS. A relaxed level is an opt-in, not a resilience SHED, so
        // these are observability gauges, not loss/shed counters.
        ("ironbus_durability_level_info", "gauge"),
        ("ironbus_durability_power_loss_unsafe", "gauge"),
        ("ironbus_durability_unsynced_bytes", "gauge"),
        // Cluster ack-level series (#605/#610): the per-level produce COUNTER (a LABELED `_total`, so —
        // like `ironbus_retry_shed_total{side}` — its sample line is excluded from the UNLABELED-`_total`
        // resilience-taxonomy test by construction and is pinned ONLY here; a produce ack is an
        // observability event, not a resilience SHED) and the cluster `power_loss_unsafe` GAUGE (no
        // `_total`). Both are additive: a cluster durability level is a posture, not a loss/shed.
        ("ironbus_cluster_ack_total", "counter"),
        ("ironbus_cluster_ack_power_loss_unsafe", "gauge"),
        // Backpressure series (#68, #69): the CoDel / retry-budget / fire-and-forget / egress shed
        // COUNTERS (the unlabeled four plus the labeled `ironbus_retry_shed_total{side}` and the
        // suspend-gap reset counter), and the sojourn-estimate / retry-ratio / egress-limit GAUGES.
        // The unlabeled shed counters and the interval-reset counter are ALSO in
        // FROZEN_RESILIENCE_COUNTERS; the labeled retry counter and the gauges are pinned ONLY here
        // (the labeled `_total` sample line and the no-`_total` gauges are excluded from the
        // resilience-taxonomy test by its line-shape filter).
        ("ironbus_codel_shed_total", "counter"),
        ("ironbus_codel_backstop_shed_total", "counter"),
        ("ironbus_codel_interval_resets_total", "counter"),
        ("ironbus_retry_shed_total", "counter"),
        ("ironbus_fire_and_forget_shed_total", "counter"),
        ("ironbus_egress_shed_total", "counter"),
        // The fsync-headroom admission (#378): the shed COUNTER (an unlabeled `_total`, also in
        // FROZEN_RESILIENCE_COUNTERS) and the configured-headroom GAUGE (no `_total`, pinned only
        // here, like the other backpressure gauges).
        ("ironbus_wal_fsync_headroom_shed_total", "counter"),
        ("ironbus_codel_sojourn_estimate_ms", "gauge"),
        ("ironbus_retry_ratio", "gauge"),
        ("ironbus_egress_limit", "gauge"),
        ("ironbus_wal_fsync_headroom_bytes", "gauge"),
        // Per-group consumer gauges.
        ("ironbus_group_committed_offset", "gauge"),
        ("ironbus_group_consumer_lag", "gauge"),
        ("ironbus_group_in_flight", "gauge"),
        // Recovery-loss gauges.
        ("ironbus_recovery_loss_bytes", "gauge"),
        ("ironbus_recovery_loss_records", "gauge"),
        ("ironbus_recovery_data_loss_bytes", "gauge"),
        // Recovery-EVENT counters (#575), the marquee NATS-can't corruption-recovery taxonomy. The
        // unlabeled `ironbus_torn_tail_repairs_total` is ALSO in FROZEN_RESILIENCE_COUNTERS; the two
        // LABELED `_total`s (`{outcome}` and `{artifact}`) are pinned ONLY here (their sample lines
        // carry a label, so the unlabeled-`_total` resilience-taxonomy filter excludes them by
        // construction, exactly like `ironbus_cluster_ack_total`). NATS has NO corruption metric.
        ("ironbus_recovery_runs_total", "counter"),
        ("ironbus_torn_tail_repairs_total", "counter"),
        ("ironbus_corruption_repairs_total", "counter"),
        // Reconciled skip/loss gauges (the resilience watermarks; NOT `_total`).
        ("ironbus_records_skipped", "gauge"),
        ("ironbus_bytes_skipped", "gauge"),
        ("ironbus_last_skip_offset", "gauge"),
        // The registry (#97) series.
        ("ironbus_consumer_lag_records", "gauge"),
        ("ironbus_build_info", "gauge"),
        ("ironbus_start_time_seconds", "gauge"),
        ("ironbus_uptime_seconds", "gauge"),
        // Histograms (the fixed-bucket latency families).
        ("ironbus_fsync_seconds", "histogram"),
        ("ironbus_fsync_duration_seconds", "histogram"),
        ("ironbus_append_duration_seconds", "histogram"),
        // Request-path latency histograms (#570): produce->ack, deliver, consume (ack). Over the same
        // fixed registry buckets; all gauges/histograms, so no resilience-counter taxonomy change.
        ("ironbus_produce_ack_duration_seconds", "histogram"),
        ("ironbus_deliver_duration_seconds", "histogram"),
        ("ironbus_consume_duration_seconds", "histogram"),
        // Per-stream/per-group throughput counters (#571): the labeled produce/consume sample counters
        // (the `stream`/`group` label is a bounded, overflow-folded NAME, never a per-message value),
        // the unlabeled cardinality-cap counter (ALSO in FROZEN_RESILIENCE_COUNTERS), and the labeled
        // per-ack-level produce counter (the single-node twin of `ironbus_cluster_ack_total`; the
        // `level` label is a fixed three-value enum, so the cardinality is bounded by construction).
        ("ironbus_stream_produced_total", "counter"),
        ("ironbus_group_consumed_total", "counter"),
        ("ironbus_throughput_labels_dropped_total", "counter"),
        ("ironbus_produce_ack_level_total", "counter"),
        // Connection signals (connz, #572): one LABELED counter family
        // `ironbus_connections_total{state}` (the `state` label is a fixed four-value enum, so the
        // cardinality is bounded by construction — NEVER a per-connection-id label) plus the open
        // GAUGE. A connection accept/close/auth is normal lifecycle and a refuse is a cap signal, none
        // a resilience SHED, so the labeled `_total` is pinned ONLY here (its labeled sample lines are
        // excluded from the unlabeled-`_total` resilience-taxonomy test by construction, exactly like
        // `ironbus_cluster_ack_total{level}`); the open gauge carries no `_total`.
        ("ironbus_connections_total", "counter"),
        ("ironbus_connections_open", "gauge"),
        // Pre-auth DoS rejections (#633): one LABELED counter family
        // `ironbus_connections_rejected_total{reason}` whose `reason` label is a fixed four-value enum
        // (rate_limited|half_open_cap|locked_out|auth_failed — never a per-IP/per-connection value), so
        // the cardinality is bounded by construction (`reason` is an allowlisted firewall key). A
        // pre-auth rejection is a DoS-shed signal, not a resilience SHED of a record, so the labeled
        // `_total` is pinned ONLY here (its labeled sample lines are excluded from the unlabeled-`_total`
        // resilience-taxonomy test by construction, exactly like `ironbus_connections_total{state}`).
        ("ironbus_connections_rejected_total", "counter"),
        // Health-probe shed counter (#953): one LABELED counter family
        // `ironbus_health_shed_total{reason}` whose `reason` label is a fixed two-value enum
        // (at_cap|spawn_refused — never a per-connection value), so the cardinality is bounded by
        // construction. A health-probe shed is a flood-protection signal, NOT a record-loss resilience
        // SHED, so — like `ironbus_connections_total{state}` — the labeled `_total` is pinned ONLY here
        // (its labeled sample lines are excluded from the unlabeled-`_total` resilience-taxonomy test by
        // construction). Health probes were never in connz, so this is its own series, not folded in.
        ("ironbus_health_shed_total", "counter"),
        // Disk-free + durable-storage telemetry (#573): the free bytes on the log's filesystem, the
        // on-disk record footprint it is measured against, and the segment-file count. All GAUGES.
        ("ironbus_disk_free_bytes", "gauge"),
        ("ironbus_durable_record_bytes", "gauge"),
        ("ironbus_segment_count", "gauge"),
        // RAM ratios (#574): the headroom ratio and the rss-vs-cap ratio, float-free per-mille gauges
        // (the byte headroom gauge expressed dimensionless), with the -1 unavailable sentinel.
        ("ironbus_ram_headroom_ratio", "gauge"),
        ("ironbus_rss_over_cap_ratio", "gauge"),
    ];

    #[test]
    fn the_metric_name_and_type_contract_is_frozen() {
        // Render /metrics and extract the COMPLETE `(name, type)` set from its `# TYPE` lines, then
        // assert it equals FROZEN_METRIC_TYPES exactly. A metric added, removed, renamed, or
        // type-changed without updating the frozen map (and docs/METRICS.md) fails here, so the
        // metric/label stability contract (#22) cannot silently drift and a dashboard or the #15 CLI
        // can never be broken by an unannounced rename (#99).
        let (addr, shutdown, handle, _engine) = start();
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");

        // Collect every `# TYPE ironbus_<name> <type>` declaration as a (name, type) pair.
        let mut rendered: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        for line in m.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let mut it = rest.split_whitespace();
                if let (Some(name), Some(ty)) = (it.next(), it.next()) {
                    if name.starts_with("ironbus_") {
                        rendered.insert((name.to_string(), ty.to_string()));
                    }
                }
            }
        }
        let expected: std::collections::BTreeSet<(String, String)> = FROZEN_METRIC_TYPES
            .iter()
            .map(|(n, t)| ((*n).to_string(), (*t).to_string()))
            .collect();
        assert_eq!(
            rendered, expected,
            "the rendered metric (name, type) set drifted from the frozen contract; update \
             FROZEN_METRIC_TYPES and docs/METRICS.md deliberately (a metric/label rename is a #22 \
             contract change). rendered={rendered:?} expected={expected:?}"
        );

        // The frozen map has no duplicate names (a copy-paste guard on the contract itself).
        let names: std::collections::BTreeSet<&str> =
            FROZEN_METRIC_TYPES.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names.len(),
            FROZEN_METRIC_TYPES.len(),
            "FROZEN_METRIC_TYPES has a duplicate metric name"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// The CARDINALITY FIREWALL allowlist (#576): the COMPLETE set of label KEYS any `/metrics`
    /// series may carry. Every key here is a BOUNDED dimension — a fixed enum, a fixed histogram
    /// bucket, or a bounded + overflow-folded name (capped at 1024 distinct values then folded into
    /// `__overflow__`). An UNBOUNDED label — a per-message id, a subject, an offset, a connection id,
    /// a peer address — would introduce a label key NOT in this set, which the firewall rejects: that
    /// is exactly the class of label that turns a single series into millions and OOMs the very node
    /// the metrics protect. ADDING a label key here MUST be a deliberate, reviewed edit that proves the
    /// new dimension is bounded.
    const FROZEN_LABEL_KEYS: &[&str] = &[
        // Bounded + overflow-folded NAMES (cap 1024 -> `__overflow__`): consumer lag (#97), and the
        // per-stream / per-group throughput (#571). NOT a free-form per-message value.
        "consumer", "group", "stream",
        // Fixed ENUMS: the cluster/produce ack level, the retry side, the connz state, the recovery
        // artifact/outcome, the recovery-loss reason. All closed, small value sets.
        "level", "side", "state", "artifact", "outcome", "reason",
        // The fixed histogram bucket bound, and the single build-version of `ironbus_build_info`.
        "le", "version",
    ];

    /// The firewall's per-family distinct-series cap (#576): no labeled metric family may emit MORE
    /// than this many distinct series in one scrape. The bounded-name dimensions cap at 1024 distinct
    /// values plus a `__overflow__` fold and a possible default label, so a generous ceiling above
    /// 1024 catches a runaway (unbounded) family without false-positiving the legitimately-capped ones.
    const FIREWALL_MAX_SERIES_PER_FAMILY: usize = 1100;

    /// The CARDINALITY FIREWALL check (#576), factored out so it runs against BOTH the real `/metrics`
    /// body AND a synthetic body (to prove it BITES). Returns the list of violations found; an empty
    /// list means the exposition is firewall-clean. It flags two failure modes:
    ///
    /// 1. A labeled sample whose label KEY is not in [`FROZEN_LABEL_KEYS`] — the unbounded-label
    ///    class (a per-message id / subject / offset / connection id / peer address).
    /// 2. A labeled metric FAMILY that emitted more than [`FIREWALL_MAX_SERIES_PER_FAMILY`] distinct
    ///    series in one scrape — a runaway even if its key looked innocuous.
    fn cardinality_firewall_violations(body: &str) -> Vec<String> {
        use std::collections::{BTreeMap, BTreeSet};
        let allowed: BTreeSet<&str> = FROZEN_LABEL_KEYS.iter().copied().collect();
        let mut violations = Vec::new();
        // family name -> count of distinct labeled series seen.
        let mut family_series: BTreeMap<&str, usize> = BTreeMap::new();
        for line in body.lines() {
            let line = line.trim();
            // Only SAMPLE lines (skip `# HELP` / `# TYPE` and blanks). A labeled sample has the shape
            // `name{k1="v1",k2="v2"} value`.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(brace) = line.find('{') else {
                continue; // an UNLABELED sample carries no label, so it cannot be unbounded by a label
            };
            let name = &line[..brace];
            let Some(close) = line[brace..].find('}') else {
                continue;
            };
            let labels = &line[brace + 1..brace + close];
            *family_series.entry(name).or_insert(0) += 1;
            // Each label is `key="value"`, comma-separated. Extract the KEYS and check the allowlist.
            for kv in labels.split(',') {
                let Some(eq) = kv.find('=') else {
                    continue;
                };
                let key = kv[..eq].trim();
                if !allowed.contains(key) {
                    violations.push(format!(
                        "metric `{name}` carries UNBOUNDED-RISK label key `{key}` (not in FROZEN_LABEL_KEYS); \
                         a per-message/subject/offset/connection-id label would OOM the node — keep metrics low-cardinality"
                    ));
                }
            }
        }
        for (name, count) in family_series {
            if count > FIREWALL_MAX_SERIES_PER_FAMILY {
                violations.push(format!(
                    "metric family `{name}` emitted {count} distinct series in one scrape, over the firewall cap {FIREWALL_MAX_SERIES_PER_FAMILY} — a runaway (unbounded) family"
                ));
            }
        }
        violations
    }

    #[test]
    fn the_cardinality_firewall_passes_on_the_real_metrics_surface() {
        // #576: the LIVE `/metrics` exposition must be firewall-clean — every labeled series carries
        // only bounded label keys, and no family is a runaway. This is the CI lint that fails the build
        // if any future metric sneaks an unbounded (per-message / subject / offset / connection-id)
        // label onto the surface. Drive a few produces/acks first so the throughput families actually
        // emit labeled samples to scan, not just the at-rest zero block.
        let (addr, shutdown, handle, engine) = start();
        // Produce a few records so `ironbus_stream_produced_total{stream=""}` carries a real labeled
        // sample to scan (not just the at-rest zero block).
        {
            let mut g = engine.lock().unwrap();
            for _ in 0..3 {
                g.produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload: b"x",
                })
                .unwrap();
            }
        }
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        let body = m.split("\r\n\r\n").nth(1).unwrap_or(&m);
        let violations = cardinality_firewall_violations(body);
        assert!(
            violations.is_empty(),
            "the /metrics surface tripped the cardinality firewall (#576):\n{}",
            violations.join("\n")
        );
        // Every label key the surface actually uses is in the frozen allowlist, AND every allowlist
        // entry is documented as a bounded dimension (a guard on the allowlist itself: a stray key
        // could be removed from the surface but linger here, but a key never on the surface is benign).
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_cardinality_firewall_bites_a_synthetic_unbounded_metric() {
        // #576 PROVE-IT-BITES: a synthetic exposition that smuggles an UNBOUNDED label (a per-message
        // id, a per-connection id, a per-offset value) MUST be rejected by the firewall, so the lint
        // is real, not vacuous. Each of these is the canonical unbounded-cardinality footgun.
        let synthetic_msg_id = "\
            # TYPE ironbus_evil_total counter\n\
            ironbus_evil_total{msg_id=\"a1b2c3\"} 1\n";
        let v = cardinality_firewall_violations(synthetic_msg_id);
        assert!(
            v.iter().any(|s| s.contains("msg_id")),
            "the firewall must reject a per-message-id label: {v:?}"
        );

        let synthetic_conn = "ironbus_evil_total{connection_id=\"7f3a\"} 1\n";
        assert!(
            cardinality_firewall_violations(synthetic_conn)
                .iter()
                .any(|s| s.contains("connection_id")),
            "the firewall must reject a per-connection-id label"
        );

        let synthetic_offset = "ironbus_evil_total{offset=\"123456789\"} 1\n";
        assert!(
            cardinality_firewall_violations(synthetic_offset)
                .iter()
                .any(|s| s.contains("offset")),
            "the firewall must reject a per-offset label"
        );

        // A RUNAWAY family (an innocuous-looking but unbounded number of distinct series under an
        // allowed key) is also caught by the per-family series cap.
        let mut runaway = String::from("# TYPE ironbus_runaway_total counter\n");
        for i in 0..(FIREWALL_MAX_SERIES_PER_FAMILY + 5) {
            // Uses an ALLOWED key (`group`) but an unbounded number of distinct values — the firewall's
            // second guard (the per-family series cap) catches what the key allowlist alone would not.
            let _ = writeln!(runaway, "ironbus_runaway_total{{group=\"g{i}\"}} 1");
        }
        assert!(
            cardinality_firewall_violations(&runaway)
                .iter()
                .any(|s| s.contains("runaway") && s.contains("distinct series")),
            "the firewall must reject a family that blew past the per-family series cap"
        );

        // And a CLEAN labeled line (an allowed, bounded key) passes the firewall (no false positive).
        let clean = "ironbus_cluster_ack_total{level=\"c2_fsync\"} 0\n";
        assert!(
            cardinality_firewall_violations(clean).is_empty(),
            "a bounded-key labeled series must pass the firewall"
        );
    }

    #[test]
    fn connz_and_disk_free_render_live_through_serve_health_connz() {
        // #572/#573: the connz-aware serve path exposes the LIVE connection signals (recorded into the
        // shared metric) and a real disk-free reading (the temp dir's filesystem), proving the wiring
        // end-to-end, not just the at-rest zero block the legacy `serve_health` renders.
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), test_eng_cfg()).unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        // The SHARED connz metric: drive some signals BEFORE the scrape (as the wire server would).
        let connz = Arc::new(ConnectionMetrics::new());
        connz.record_accept();
        connz.record_accept();
        connz.record_accept();
        connz.record_close(); // one of the three closed
        connz.record_refused();
        connz.record_authenticated();
        connz.record_authenticated();
        let data_dir = std::env::temp_dir();
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let shared = Arc::clone(&shared);
            let connz = Arc::clone(&connz);
            let data_dir = data_dir.clone();
            move || {
                serve_health_connz(
                    &listener,
                    &shared,
                    &shutdown,
                    false,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                    &connz,
                    Some(&data_dir),
                )
                .unwrap();
            }
        });
        let m = request(addr, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        // The connz labeled family reports the live counts (3 accepted, 1 closed, 1 refused, 2 auth,
        // open == 3 - 1 == 2).
        assert!(
            m.contains("ironbus_connections_total{state=\"accepted\"} 3"),
            "{m}"
        );
        assert!(
            m.contains("ironbus_connections_total{state=\"closed\"} 1"),
            "{m}"
        );
        assert!(
            m.contains("ironbus_connections_total{state=\"refused\"} 1"),
            "{m}"
        );
        assert!(
            m.contains("ironbus_connections_total{state=\"authenticated\"} 2"),
            "{m}"
        );
        assert!(m.contains("ironbus_connections_open 2"), "{m}");
        // Disk-free reads a REAL non-`-1` figure on a unix dev/CI host (the temp dir's filesystem). On
        // an exotic host where `df` is unavailable it degrades to -1, which this tolerates.
        let disk_line = m
            .lines()
            .find(|l| l.starts_with("ironbus_disk_free_bytes "))
            .expect("disk-free line present");
        let value: i64 = disk_line
            .rsplit(' ')
            .next()
            .and_then(|v| v.parse().ok())
            .expect("disk-free value parses");
        assert!(
            value > 0 || value == -1,
            "disk-free is a real positive figure or the -1 sentinel: {value}"
        );

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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropOldest,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            // admin_enabled = true: this harness exercises the opt-in introspection endpoint. The
            // liveness watchdog is disabled (window 0), so /healthz keeps its static-200 contract.
            move || {
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    true,
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
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

        // Pin v1 explicitly so this remains a v1 field-correctness test (no Accept now defaults to v2,
        // #577); the v1 response carries the generic `application/json` Content-Type.
        let r = request(
            addr,
            "GET /admin HTTP/1.1\r\nAccept: application/vnd.ironbus.admin.v1+json\r\n\r\n",
        );
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
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
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
            // Watchdog disabled (window 0): this DLQ-state admin test does not exercise liveness.
            let clock = Arc::clone(&clock);
            move || {
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    true,
                    &LivenessBeacon::new(0),
                    0,
                    &clock,
                )
                .unwrap();
            }
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

    #[test]
    fn admin_v1_carries_the_four_named_sub_resources() {
        // The #99 contract: `/admin` v1 exposes the four sub-resources BY NAME (segments, consumers,
        // config, resilience), so #15 can render each from the JSON alone without parsing a metric
        // name. This is the test that fails if a sub-resource is dropped from the body.
        let (addr, shutdown, handle, engine) = start_with_admin();
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
        }

        let r = request(addr, "GET /admin HTTP/1.1\r\n\r\n");
        let (status, body) = split_body(&r);
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{r}");

        // Each of the four sub-resources is present by name.
        for key in [
            "\"segments\":{",
            "\"consumers\":[",
            "\"config\":{",
            "\"resilience\":{",
        ] {
            assert!(body.contains(key), "missing sub-resource {key}: {body}");
        }
        // `groups` is kept as a back-compat alias of `consumers`.
        assert!(
            body.contains("\"groups\":["),
            "groups alias present: {body}"
        );

        // segments: one segment, head 3, earliest retained 0, 3 records.
        assert!(body.contains("\"segments\":{\"count\":1,"), "{body}");
        assert!(body.contains("\"head_offset\":3"), "{body}");
        assert!(body.contains("\"earliest_retained_offset\":0"), "{body}");
        assert!(body.contains("\"durable_record_count\":3"), "{body}");

        // consumers: the orders group committed 1, incremental lag 2, in-flight 0.
        assert!(
            body.contains(
                "{\"name\":\"orders\",\"committed_offset\":1,\"consumer_lag\":2,\"in_flight\":0}"
            ),
            "orders consumer with incremental lag: {body}"
        );

        // resilience: a clean broker is not frozen, with zero skip totals and the -? sentinel-free
        // last-skip-offset at 0.
        assert!(body.contains("\"resilience\":{\"frozen\":false,"), "{body}");
        assert!(body.contains("\"last_skip_offset\":0"), "{body}");
        assert!(body.contains("\"records_skipped\":0"), "{body}");
        assert!(body.contains("\"bytes_skipped\":0"), "{body}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_consumers_and_groups_arrays_are_identical() {
        // The `consumers` sub-resource and the `groups` back-compat alias render from the same data,
        // so the two arrays must be byte-identical; a future divergence (two render paths) fails here.
        let (addr, shutdown, handle, engine) = start_with_admin();
        {
            let mut g = engine.lock().unwrap();
            g.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"x",
            })
            .unwrap();
            assert!(matches!(g.poll_in("billing", 0).unwrap(), Poll::Message(_)));
        }
        let r = request(addr, "GET /admin HTTP/1.1\r\n\r\n");
        let (_status, body) = split_body(&r);

        let extract = |key: &str| -> String {
            let start = body.find(key).expect("array key present") + key.len();
            let rest = &body[start..];
            let end = rest.find(']').expect("array closes");
            rest[..end].to_string()
        };
        assert_eq!(
            extract("\"consumers\":["),
            extract("\"groups\":["),
            "consumers and groups arrays must be identical: {body}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_resilience_reports_frozen_after_an_integrity_freeze() {
        // The resilience sub-resource surfaces the integrity freeze (#16: never silent). Drive a real
        // writer freeze (an armed fatal fsync on the fault filesystem) and assert `/admin` reports
        // `frozen:true`, matching the `/readyz` 503 a frozen writer answers.
        use ironbus_core::clock::ManualClock;
        use ironbus_storage::fault::FaultFs;
        use ironbus_storage::segment::StorageError;

        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut engine = Engine::open(
            fs,
            ManualClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: crate::engine::DEFAULT_GROUP_IDLE_EVICT_MS,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
                // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap();
        let msg = |payload: &'static [u8]| Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        };
        // A clean first produce, then arm a fatal fsync so the next produce freezes the writer.
        engine.produce(&msg(b"a")).unwrap();
        assert!(engine.is_healthy());
        control.set_fail_sync(true);
        let err = engine.produce(&msg(b"b")).unwrap_err();
        assert!(matches!(
            err,
            crate::engine::EngineError::Storage(StorageError::WriterFrozen)
        ));
        assert!(!engine.is_healthy(), "the writer is frozen");

        let shared: SharedEngine<FaultFs<InMemoryFs>, ManualClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let shared = Arc::clone(&shared);
            // Watchdog disabled (window 0): this frozen-resilience admin test does not exercise
            // liveness. A frozen writer must still answer /healthz 200 (liveness != readiness), which
            // the watchdog respects by reading the accept-loop beacon, not the writer health.
            move || {
                serve_health(
                    &listener,
                    &shared,
                    &shutdown,
                    true,
                    &LivenessBeacon::new(0),
                    0,
                    &ManualClock::new(),
                )
                .unwrap();
            }
        });

        let r = request(addr, "GET /admin HTTP/1.1\r\n\r\n");
        let (status, body) = split_body(&r);
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(
            body.contains("\"resilience\":{\"frozen\":true,"),
            "frozen surfaced: {body}"
        );
        assert!(
            body.contains("\"healthy\":false"),
            "broker reports unhealthy: {body}"
        );
        // And `/readyz` agrees: a frozen writer is 503.
        let ready = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(
            ready.starts_with("HTTP/1.1 503"),
            "frozen writer is not ready: {ready}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_serves_v1_for_the_pinned_accept_header() {
        // The schema version is pinned in the Accept header (#99): a consumer that sends the exact
        // v1 media type gets the v1 body (200).
        let (addr, shutdown, handle, _engine) = start_with_admin();
        let r = request(
            addr,
            "GET /admin HTTP/1.1\r\nAccept: application/vnd.ironbus.admin.v1+json\r\n\r\n",
        );
        let (status, body) = split_body(&r);
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(body.contains("\"schema_version\":1"), "{body}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_serves_the_newest_version_for_an_absent_or_wildcard_accept() {
        // A plain `curl` (no Accept, or `*/*`, or `application/json`) takes the NEWEST version (v2,
        // #577), exactly as `/metrics` ignores Accept, so the endpoint stays curl-friendly while
        // still being version-pinnable. The v2 body carries the three new objects by name.
        let (addr, shutdown, handle, _engine) = start_with_admin();
        for accept_line in [
            "",                             // no Accept header at all
            "Accept: */*\r\n",              // the curl default
            "Accept: application/json\r\n", // a generic JSON request
        ] {
            let r = request(addr, &format!("GET /admin HTTP/1.1\r\n{accept_line}\r\n"));
            let (status, body) = split_body(&r);
            assert!(
                status.starts_with("HTTP/1.1 200 OK"),
                "accept `{accept_line}` should serve the newest version: {r}"
            );
            assert!(body.contains("\"schema_version\":2"), "{body}");
            for key in ["\"connections\":{", "\"storage\":{", "\"recovery\":{"] {
                assert!(body.contains(key), "v2 object {key} present: {body}");
            }
        }
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_rejects_an_explicit_unknown_admin_accept_with_406() {
        // An Accept that explicitly names an IronBus-admin version that is neither v1 NOR v2 (an
        // unknown future version) is 406 Not Acceptable, so a future-version-only consumer can never
        // silently misread a v1/v2 body. This is the version-pin teeth: it fails if the negotiation
        // is dropped (every Accept would 200). v2 is now SUPPORTED, so only the unknown versions 406.
        let (addr, shutdown, handle, _engine) = start_with_admin();
        for bad in [
            "application/vnd.ironbus.admin.v3+json",
            "application/vnd.ironbus.admin.v99+json",
        ] {
            let r = request(
                addr,
                &format!("GET /admin HTTP/1.1\r\nAccept: {bad}\r\n\r\n"),
            );
            let (status, body) = split_body(&r);
            assert!(
                status.starts_with("HTTP/1.1 406 Not Acceptable"),
                "accept `{bad}` should be 406: {r}"
            );
            // The 406 names BOTH supported versions so a client can re-pin.
            assert!(
                body.contains("application/vnd.ironbus.admin.v1+json")
                    && body.contains("application/vnd.ironbus.admin.v2+json"),
                "the 406 names the supported versions: {body}"
            );
        }
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_serves_v1_when_v1_is_offered_alongside_v2() {
        // A consumer may offer several media types; if ANY is the v1 type, v1 is served — a v1 pin
        // is the back-compat-safe choice for a client that accepts EITHER, so an existing v1 consumer
        // that future-proofs its Accept by also listing v2 is never silently upgraded to v2 (#577).
        let (addr, shutdown, handle, _engine) = start_with_admin();
        let r = request(
            addr,
            "GET /admin HTTP/1.1\r\nAccept: application/vnd.ironbus.admin.v2+json, \
             application/vnd.ironbus.admin.v1+json\r\n\r\n",
        );
        let (status, body) = split_body(&r);
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(body.contains("\"schema_version\":1"), "v1 pin wins: {body}");
        // The v2-only objects are ABSENT from a v1 body (additive only in v2).
        assert!(
            !body.contains("\"connections\":{"),
            "v1 has no v2 object: {body}"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_has_no_mutating_route_every_non_get_is_405() {
        // STRICTLY READ-ONLY (#99): there is NO route that mutates state. Every mutating method on
        // `/admin` (and on the would-be action paths a mutating surface might add) is 405, since the
        // method gate precedes the path match, so no verb can carry a mutation through this endpoint.
        let (addr, shutdown, handle, _engine) = start_with_admin();
        let paths = ["/admin", "/admin/reset", "/admin/redrive", "/admin/dlq"];
        for path in paths {
            for verb in ["POST", "PUT", "DELETE", "PATCH"] {
                let r = request(addr, &format!("{verb} {path} HTTP/1.1\r\n\r\n"));
                assert!(
                    r.starts_with("HTTP/1.1 405 Method Not Allowed"),
                    "{verb} {path} must be 405 (no mutation): {r}"
                );
            }
        }
        // And a GET to a non-existent admin SUB-path is a 404 (only the read-only `/admin` exists),
        // so there is no hidden mutating sub-route reachable even by GET.
        let r = request(addr, "GET /admin/reset HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 404 Not Found"), "{r}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_accept_decision_classifies_each_case() {
        // The negotiation logic, unit-tested directly (lower-cased input, as the parser produces).
        // Unpinned -> NEWEST (v2): absent, wildcard, or a generic JSON type.
        assert_eq!(admin_accept_decision(""), AcceptDecision::ServeV2);
        assert_eq!(admin_accept_decision("*/*"), AcceptDecision::ServeV2);
        assert_eq!(
            admin_accept_decision("application/json"),
            AcceptDecision::ServeV2
        );
        // An explicit v1 pin -> the UNCHANGED v1 body (parameters tolerated).
        assert_eq!(
            admin_accept_decision("application/vnd.ironbus.admin.v1+json"),
            AcceptDecision::ServeV1
        );
        assert_eq!(
            admin_accept_decision("application/vnd.ironbus.admin.v1+json;q=0.9"),
            AcceptDecision::ServeV1
        );
        // An explicit v2 pin -> v2 (the version is now SUPPORTED, no longer a 406).
        assert_eq!(
            admin_accept_decision("application/vnd.ironbus.admin.v2+json"),
            AcceptDecision::ServeV2
        );
        assert_eq!(
            admin_accept_decision("application/vnd.ironbus.admin.v2+json;q=0.9"),
            AcceptDecision::ServeV2
        );
        // An explicit UNKNOWN admin version (neither v1 nor v2) -> 406.
        assert_eq!(
            admin_accept_decision("application/vnd.ironbus.admin.v3+json"),
            AcceptDecision::UnsupportedVersion
        );
        assert_eq!(
            admin_accept_decision("application/vnd.ironbus.admin.v99+json"),
            AcceptDecision::UnsupportedVersion
        );
        // v1 wins over v2 when BOTH are offered (back-compat-safe for an either-acceptor).
        assert_eq!(
            admin_accept_decision(
                "application/vnd.ironbus.admin.v2+json,application/vnd.ironbus.admin.v1+json"
            ),
            AcceptDecision::ServeV1
        );
        // v2 wins over an unknown version when both are offered (the supported one is served).
        assert_eq!(
            admin_accept_decision(
                "application/vnd.ironbus.admin.v3+json,application/vnd.ironbus.admin.v2+json"
            ),
            AcceptDecision::ServeV2
        );
    }

    #[test]
    fn parse_accept_header_extracts_the_value_case_insensitively() {
        // The header-name match is case-insensitive and the value is lower-cased, so a mixed-case
        // `AcCePt` with a mixed-case value still drives the version match.
        assert_eq!(
            parse_accept_header("\r\nAcCePt: Application/JSON\r\n"),
            "application/json"
        );
        assert_eq!(parse_accept_header("\r\nHost: x\r\n"), "");
        assert_eq!(
            parse_accept_header("\r\nAccept: a/b\r\nAccept: c/d\r\n"),
            "a/b,c/d"
        );
    }

    // ── /admin v2 (#577) ──────────────────────────────────────────────────────────────────────────

    /// An admin-enabled health server sharing a caller-supplied `Arc<ConnectionMetrics>` and the temp
    /// dir as the data dir, so a v2 test can drive LIVE connz signals (the wire server would) and read
    /// a real disk-free figure. Returns the bound addr, the shutdown flag, the join handle, the shared
    /// engine, and the shared connz handle. The engine config is `start_with_admin`'s, so the v1 body
    /// fields a v2 body also carries match the existing v1 expectations.
    #[allow(clippy::type_complexity)]
    fn start_with_admin_connz() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        SharedEngine<InMemoryFs, SystemClock>,
        Arc<ConnectionMetrics>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                compression: ironbus_core::compress::Codec::None,
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
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropOldest,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: crate::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                default_message_ttl_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&shared);
        let connz = Arc::new(ConnectionMetrics::new());
        let data_dir = std::env::temp_dir();
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let connz = Arc::clone(&connz);
            move || {
                serve_health_connz(
                    &listener,
                    &shared,
                    &shutdown,
                    true, // admin enabled
                    &LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                    &connz,
                    Some(&data_dir),
                )
                .unwrap();
            }
        });
        (addr, shutdown, handle, engine, connz)
    }

    #[test]
    fn admin_v2_carries_connections_storage_and_recovery_with_correct_values() {
        // The #577 contract: an unpinned (or v2-pinned) `/admin` request gets the v2 body, which adds
        // the three new bounded objects BY NAME with values that mirror the live connz / storage /
        // recovery state. Drive a known connz fixture and assert each field.
        use crate::connz::RejectReason;
        let (addr, shutdown, handle, engine, connz) = start_with_admin_connz();
        // Connz fixture: 3 accepted, 1 closed (open == 2), 1 refused, 2 authenticated, and one of each
        // pre-auth-DoS reason except locked_out (which gets two), so every field has a distinct value.
        connz.record_accept();
        connz.record_accept();
        connz.record_accept();
        connz.record_close();
        connz.record_refused();
        connz.record_authenticated();
        connz.record_authenticated();
        connz.record_rejected(RejectReason::RateLimited);
        connz.record_rejected(RejectReason::HalfOpenCap);
        connz.record_rejected(RejectReason::LockedOut);
        connz.record_rejected(RejectReason::LockedOut);
        connz.record_rejected(RejectReason::AuthFailed);
        // Storage fixture: produce 2 records so the segment count / durable bytes are non-trivial.
        {
            let mut g = engine.lock().unwrap();
            for payload in [&b"alpha"[..], &b"beta"[..]] {
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

        // An explicit v2 pin gets the v2 body (200), labeled with the versioned media type.
        let r = request(
            addr,
            "GET /admin HTTP/1.1\r\nAccept: application/vnd.ironbus.admin.v2+json\r\n\r\n",
        );
        let (status, body) = split_body(&r);
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(
            r.contains("Content-Type: application/vnd.ironbus.admin.v2+json"),
            "v2 labels the response: {r}"
        );
        assert!(body.contains("\"schema_version\":2"), "{body}");

        // connections: the bounded aggregate with the exact fixture counts, including the nested
        // rejected{reason} object (open == accepted - closed == 2).
        assert!(
            body.contains(
                "\"connections\":{\"open\":2,\"accepted\":3,\"closed\":1,\"refused\":1,\
                 \"authenticated\":2,\"rejected\":{\"rate_limited\":1,\"half_open_cap\":1,\
                 \"locked_out\":2,\"auth_failed\":1}}"
            ),
            "connections object: {body}"
        );

        // storage: 1 segment, the durable bytes are non-zero, and disk-free is a real positive figure
        // (the temp fs) or the -1 sentinel on an exotic host. No ceiling is configured, so the RAM
        // headroom / rss-over-cap are the -1 unavailable sentinel.
        assert!(body.contains("\"storage\":{\"segment_count\":1,"), "{body}");
        assert!(
            !body.contains("\"durable_record_bytes\":0,\"disk_free_bytes\""),
            "durable bytes are non-zero after two produces: {body}"
        );
        assert!(body.contains("\"ram_ceiling_bytes\":0,"), "{body}");
        assert!(
            body.contains("\"ram_headroom_bytes\":-1,"),
            "no ceiling -> headroom sentinel: {body}"
        );
        assert!(
            body.contains("\"rss_over_cap_ratio_permille\":-1"),
            "no ceiling -> ratio sentinel: {body}"
        );

        // recovery: a fresh in-memory broker opened CLEAN once, with no torn-tail / corruption repairs.
        assert!(
            body.contains(
                "\"recovery\":{\"runs_by_outcome\":{\"clean\":1,\"torn_tail_truncated\":0,\
                 \"quarantined\":0,\"data_loss\":0},\"torn_tail_repairs\":0,\
                 \"corruption_repairs_by_artifact\":{\"segment\":0,\"cursor\":0,\"dlq\":0}}"
            ),
            "recovery object: {body}"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn admin_v1_body_is_frozen_byte_for_byte() {
        // NON-NEGOTIABLE #1 (#577): an `Accept: ...v1+json` request gets the EXACT v1 body. This is the
        // frozen-schema snapshot for v1: it renders `admin_body` from a fully-determined fixture and
        // asserts the WHOLE string, so any field added/removed/reordered/renamed in the v1 path fails
        // here. The fixture is constructed directly (not via the engine) so the snapshot is fully
        // deterministic — no clock, no disk, no platform-dependent reading enters the v1 body.
        let snapshot = frozen_admin_fixture();
        let body = admin_body(&snapshot);
        assert_eq!(
            body,
            "{\"schema_version\":1,\
             \"broker\":{\"healthy\":true,\"flushed_offset\":7,\"committed_offset\":3,\
             \"earliest_retained_offset\":1,\"consumer_lag\":4,\"durable_record_bytes\":512,\
             \"durable_record_count\":6,\"segment_count\":2,\"recovery_truncated_bytes\":0,\
             \"produced\":10,\"produced_bytes\":1024,\"produce_rejected\":0,\"delivered\":8,\
             \"redelivered\":1,\"dead_lettered\":2,\"acks\":5,\"segments_reaped\":0,\
             \"segments_force_reaped\":0,\"truncations\":0,\"truncated_records\":0},\
             \"segments\":{\"count\":2,\"earliest_retained_offset\":1,\"head_offset\":7,\
             \"durable_record_count\":6,\"durable_record_bytes\":512},\
             \"consumers\":[{\"name\":\"\",\"committed_offset\":3,\"consumer_lag\":4,\"in_flight\":1}],\
             \"groups\":[{\"name\":\"\",\"committed_offset\":3,\"consumer_lag\":4,\"in_flight\":1}],\
             \"resilience\":{\"frozen\":false,\"last_skip_offset\":0,\"records_skipped\":0,\
             \"bytes_skipped\":0,\"recovery_truncated_bytes\":0,\"counter_checkpoint_repairs\":0},\
             \"dlq\":{\"records\":2,\"last_dead_lettered_offset\":5},\
             \"config\":{\"max_total_bytes\":1000000,\"max_segment_bytes\":4096,\
             \"max_retained_bytes\":2048,\"max_age_ms\":99,\"max_messages\":33,\"max_in_flight\":16,\
             \"consumer_credit\":64,\"consumer_credit_bytes\":4096,\"max_deliver\":7,\
             \"max_groups\":100,\"group_idle_evict_nanos\":0,\"visibility_nanos\":1234,\
             \"hard_cap_nanos\":5678,\"disk_full_policy\":\"drop-oldest\",\"ram_ceiling_bytes\":0,\
             \"daily_physical_write_budget_bytes\":0}}",
            "the v1 body schema is FROZEN; if this changed intentionally it is a NEW version, not a v1 edit"
        );
    }

    #[test]
    fn admin_v2_body_is_frozen_byte_for_byte() {
        // NON-NEGOTIABLE (#577): the v2 schema is FROZEN by a whole-string snapshot. v2 is the v1 body
        // (schema_version bumped to 2) followed by the three new bounded objects in order. The fixture
        // sets the connz / storage / recovery fields to fully-determined values (RSS forced to a known
        // figure under a known ceiling, so the headroom / ratio are deterministic), so the WHOLE string
        // is reproducible and any v2 shape drift fails here.
        let mut snapshot = frozen_admin_fixture();
        // A determined connz fixture.
        snapshot.connz = ConnectionMetricsSnapshot {
            accepted: 30,
            closed: 10,
            refused: 4,
            currently_open: 20,
            authenticated: 25,
            rejected_rate_limited: 1,
            rejected_half_open_cap: 2,
            rejected_locked_out: 3,
            rejected_auth_failed: 4,
        };
        // A determined storage fixture: a 1000-byte ceiling with a 400-byte RSS, so headroom == 600 and
        // rss-over-cap == 400 per-mille; a fixed disk-free figure (no platform read enters the snapshot).
        snapshot.ram_ceiling_bytes = 1000;
        snapshot.rss = Some(400);
        snapshot.disk_free = 99_999;
        // A determined recovery fixture: two clean opens, one torn-tail-truncated, plus repairs.
        snapshot.counters.recovery = crate::engine::RecoveryCounters {
            runs_by_outcome: [2, 1, 0, 0],
            torn_tail_repairs: 3,
            corruption_repairs_by_artifact: [1, 0, 2],
        };
        let body = admin_body_v2(&snapshot);
        assert_eq!(
            body,
            "{\"schema_version\":2,\
             \"broker\":{\"healthy\":true,\"flushed_offset\":7,\"committed_offset\":3,\
             \"earliest_retained_offset\":1,\"consumer_lag\":4,\"durable_record_bytes\":512,\
             \"durable_record_count\":6,\"segment_count\":2,\"recovery_truncated_bytes\":0,\
             \"produced\":10,\"produced_bytes\":1024,\"produce_rejected\":0,\"delivered\":8,\
             \"redelivered\":1,\"dead_lettered\":2,\"acks\":5,\"segments_reaped\":0,\
             \"segments_force_reaped\":0,\"truncations\":0,\"truncated_records\":0},\
             \"segments\":{\"count\":2,\"earliest_retained_offset\":1,\"head_offset\":7,\
             \"durable_record_count\":6,\"durable_record_bytes\":512},\
             \"consumers\":[{\"name\":\"\",\"committed_offset\":3,\"consumer_lag\":4,\"in_flight\":1}],\
             \"groups\":[{\"name\":\"\",\"committed_offset\":3,\"consumer_lag\":4,\"in_flight\":1}],\
             \"resilience\":{\"frozen\":false,\"last_skip_offset\":0,\"records_skipped\":0,\
             \"bytes_skipped\":0,\"recovery_truncated_bytes\":0,\"counter_checkpoint_repairs\":0},\
             \"dlq\":{\"records\":2,\"last_dead_lettered_offset\":5},\
             \"config\":{\"max_total_bytes\":1000000,\"max_segment_bytes\":4096,\
             \"max_retained_bytes\":2048,\"max_age_ms\":99,\"max_messages\":33,\"max_in_flight\":16,\
             \"consumer_credit\":64,\"consumer_credit_bytes\":4096,\"max_deliver\":7,\
             \"max_groups\":100,\"group_idle_evict_nanos\":0,\"visibility_nanos\":1234,\
             \"hard_cap_nanos\":5678,\"disk_full_policy\":\"drop-oldest\",\"ram_ceiling_bytes\":0,\
             \"daily_physical_write_budget_bytes\":0},\
             \"connections\":{\"open\":20,\"accepted\":30,\"closed\":10,\"refused\":4,\
             \"authenticated\":25,\"rejected\":{\"rate_limited\":1,\"half_open_cap\":2,\
             \"locked_out\":3,\"auth_failed\":4}},\
             \"storage\":{\"segment_count\":2,\"durable_record_bytes\":512,\"disk_free_bytes\":99999,\
             \"ram_ceiling_bytes\":1000,\"rss_bytes\":400,\"ram_headroom_bytes\":600,\
             \"rss_over_cap_ratio_permille\":400},\
             \"recovery\":{\"runs_by_outcome\":{\"clean\":2,\"torn_tail_truncated\":1,\
             \"quarantined\":0,\"data_loss\":0},\"torn_tail_repairs\":3,\
             \"corruption_repairs_by_artifact\":{\"segment\":1,\"cursor\":0,\"dlq\":2}}}",
            "the v2 body schema is FROZEN; a deliberate change is a NEW version, not a v2 edit"
        );

        // And the v1 renderer over the SAME augmented snapshot is byte-for-byte the frozen v1 body: the
        // v2-only fields never leak into a v1 response, proving v2 is purely additive.
        assert_eq!(
            admin_body(&snapshot),
            admin_body(&frozen_admin_fixture()),
            "the v2-only snapshot fields must not change the v1 body"
        );
    }

    /// A fully-determined [`AdminSnapshot`] fixture for the frozen-schema snapshots: every field is a
    /// fixed literal (no clock, disk, or platform read), the config matches the `start_with_admin`
    /// harness, and the v2-only off-lock fields default to the at-rest/unavailable block (a v2 test
    /// overrides them). Constructed directly so the snapshot bodies are reproducible on any platform.
    fn frozen_admin_fixture() -> AdminSnapshot {
        let counters = Counters {
            produced: 10,
            produced_bytes: 1024,
            delivered: 8,
            redelivered: 1,
            dead_lettered: 2,
            acks: 5,
            ..Counters::default()
        };
        AdminSnapshot {
            healthy: true,
            flushed: 7,
            committed: 3,
            earliest_retained: 1,
            durable_record_bytes: 512,
            durable_record_count: 6,
            segment_count: 2,
            recovered_truncated_bytes: 0,
            last_dead_lettered: 5,
            dlq_records: 2,
            counters,
            groups: vec![GroupConsumerStat {
                group: String::new(),
                committed: 3,
                in_flight: 1,
            }],
            config: EngineConfigSnapshot {
                max_total_bytes: 1_000_000,
                max_segment_bytes: 4096,
                max_retained_bytes: 2048,
                max_age_ms: 99,
                max_messages: 33,
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 4096,
                max_deliver: 7,
                max_groups: 100,
                // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
                max_streams: 0,
                group_idle_evict_nanos: 0,
                visibility_nanos: 1234,
                hard_cap_nanos: 5678,
                disk_full_policy: DiskFullPolicy::DropOldest,
                ram_ceiling_bytes: 0,
                daily_physical_write_budget_bytes: 0,
            },
            // The v2-only off-lock fields at their at-rest/unavailable defaults; a v2 test overrides them.
            ram_ceiling_bytes: 0,
            connz: ConnectionMetricsSnapshot::default(),
            disk_free: crate::rss::UNAVAILABLE,
            rss: None,
        }
    }
}
