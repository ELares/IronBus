// SPDX-License-Identifier: MIT OR Apache-2.0
//! A blocking, thread-per-connection TCP server that drives [`Session`]s over the append actor.
//!
//! Edge boxes carry a bounded number of local connections, so a thread per connection over
//! blocking IO keeps the binary small (no async runtime) and the model simple. The engine is owned
//! by a single APPEND ACTOR (#177); connection handlers fan in over a bounded channel and SEND
//! commands instead of locking the engine, so no handler holds a lock across an fsync. A produce is
//! group-committed by the actor (one `fdatasync` per drained batch), which removes the per-produce
//! fsync and the head-of-line block: a stalled disk no longer blocks every connection. Pings (and
//! anything that needs no engine state) are answered by the handler WITHOUT the actor, so a stalled
//! produce fsync never blocks another connection's ping. Concurrency is bounded by a connection cap
//! so a connection flood cannot spawn unbounded threads.

use crate::actor::EngineHandle;
use crate::auth::AuthConfig;
use crate::connz::ConnectionMetrics;
use crate::session::Session;
use ironbus_core::clock::Clock;
use ironbus_core::keyshared::MemberId;
use ironbus_storage::fs::Filesystem;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How long the accept loop blocks before re-checking the shutdown flag.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Idle timeout on an accepted connection: a client must make progress (a ping suffices)
/// within this window or the connection is closed, bounding slow-client (slowloris) holds
/// on the connection cap.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Sets `TCP_NODELAY` on a broker-side socket, BEST-EFFORT (#1028).
///
/// The data plane and the cluster peer links are small-frame request-response traffic (per-message
/// acks, single-in-flight producers, fetch round-trips, raft heartbeats), exactly the pattern where
/// Nagle + delayed-ACK stacks an RTT-scale stall onto every small write on a real network. Every
/// serious broker (NATS, Kafka, Redis) disables Nagle on both ends, so IronBus does too — on every
/// accepted connection and every outbound peer link.
///
/// BEST-EFFORT because a failed `setsockopt` degrades LATENCY only, never correctness (the bytes
/// still flow, just possibly delayed by Nagle): it must never kill an otherwise-healthy connection.
/// The failure is surfaced at debug (it is environmental — an exotic stack or a socket already
/// closing — and bounded to once per connection, so it is not a log-volume vector).
pub(crate) fn set_nodelay_best_effort(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "TCP_NODELAY setsockopt failed; continuing without it");
    }
}

/// The per-connection byte stream: plaintext TCP, or — behind `--features tls` (ADR-0004, #766) — a
/// rustls-terminated TCP carrying a completed TLS 1.3 session. Read/Write flow through the (possibly
/// TLS) layer; the socket-option methods reach the underlying [`TcpStream`] so the #1045 non-blocking
/// read pipelining and the slowloris read/write timeouts apply exactly as on a plaintext connection.
///
/// The variant is chosen ONCE, in the handler thread, before [`connection_loop`] runs (see
/// [`TlsTermination::wrap`]); the loop is stream-agnostic from then on.
enum Wire {
    /// A plaintext TCP connection (the default, and every connection on a non-tls build).
    Plain(TcpStream),
    /// A TLS-terminated connection whose 1.3 handshake already completed. Boxed because
    /// `StreamOwned` is large (it embeds the whole `ServerConnection`), so the common `Plain` variant
    /// stays a bare fd-sized value.
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Wire {
    /// The underlying accepted TCP socket, for the socket-level options [`connection_loop`] manages
    /// directly (the #1045 per-read blocking toggle and the slowloris timeouts).
    fn socket(&self) -> &TcpStream {
        match self {
            Wire::Plain(s) => s,
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.get_ref(),
        }
    }

    /// Toggle blocking mode on the underlying socket (the #1045 pipelining trick). On a TLS wire this
    /// composes cleanly: a non-blocking read that finds no COMPLETE TLS record yet returns
    /// `WouldBlock` with any partial record retained inside rustls, so the next read resumes it — the
    /// loop's `WouldBlock` handling (drain a parked ack, retry) stays correct. The slowloris read/write
    /// timeouts are set on the raw socket in `handle_connection` before wrapping (they persist on the
    /// same fd inside the `Wire`), so they are not re-exposed here.
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.socket().set_nonblocking(nonblocking)
    }

    /// The mTLS identity (ADR-0004 increment 3, #766) derived from the VERIFIED peer certificate's SAN,
    /// or `None` on a plaintext wire, a server-auth-only TLS wire (the server did not request a client
    /// cert), or a non-tls build. When the server config required a client cert (mTLS), rustls has
    /// already verified the chain against the client-CA during the handshake, so the leaf here is
    /// trusted; its URI/DNS SAN maps to an auth identity via [`crate::auth::mtls_san_identity`]
    /// (URI-then-DNS). Threaded into the session as `peer_san`, so an `Mtls`-mechanism `Connect`
    /// authenticates on the certificate alone, with no bearer credential.
    #[cfg(feature = "tls")]
    fn peer_san(&self) -> Option<String> {
        let Wire::Tls(s) = self else {
            return None;
        };
        let leaf = s.conn.peer_certificates()?.first()?;
        let (uris, dns) = crate::tls::peer_cert_sans(leaf.as_ref());
        crate::auth::mtls_san_identity(&uris, &dns)
    }

    /// On a non-tls build there is no TLS layer to supply a verified peer certificate, so there is
    /// never an mTLS identity.
    #[cfg(not(feature = "tls"))]
    #[allow(clippy::unused_self)]
    fn peer_san(&self) -> Option<String> {
        None
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Wire::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Wire::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Wire::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            Wire::Tls(s) => s.flush(),
        }
    }
}

/// The server-side TLS terminator threaded through the serve loop (ADR-0004, #766). The DEFAULT (and
/// every value on a non-tls build) serves plaintext — the type merely keeps the serve signatures
/// identical across builds. Behind `--features tls`, [`TlsTermination::with_config`] carries a rustls
/// [`ServerConfig`](rustls::ServerConfig) and every accepted connection completes a TLS 1.3 handshake
/// (in the HANDLER thread, so a slow handshake never stalls the accept loop) before its session runs.
#[derive(Clone, Default)]
pub struct TlsTermination {
    #[cfg(feature = "tls")]
    config: Option<Arc<rustls::ServerConfig>>,
}

impl TlsTermination {
    /// A terminator that wraps every accepted connection in TLS using `config` (ADR-0004).
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_config(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            config: Some(config),
        }
    }

    /// Wrap a freshly-accepted socket into a [`Wire`], completing the TLS 1.3 handshake first when a
    /// config is present. Runs in the HANDLER thread (never the accept loop), so a slow or hostile
    /// handshake bounds only its own connection (under the already-set slowloris read timeout).
    #[cfg(feature = "tls")]
    fn wrap(&self, mut socket: TcpStream) -> std::io::Result<Wire> {
        match &self.config {
            Some(config) => {
                let mut conn = rustls::ServerConnection::new(Arc::clone(config))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                // Drive the handshake to completion on the BLOCKING socket, before any application
                // bytes and before the loop's non-blocking read trick — so `connection_loop` only ever
                // sees a completed TLS session. A handshake failure (a plaintext probe, an unverified
                // client cert once mTLS lands, an unsupported version) returns `Err` here and closes
                // the connection, exactly as a malformed first frame would on the plaintext path.
                conn.complete_io(&mut socket)?;
                Ok(Wire::Tls(Box::new(rustls::StreamOwned::new(conn, socket))))
            }
            None => Ok(Wire::Plain(socket)),
        }
    }

    /// On a non-tls build there is no crypto stack, so every connection is plaintext.
    #[cfg(not(feature = "tls"))]
    #[allow(clippy::unused_self)]
    fn wrap(&self, socket: TcpStream) -> std::io::Result<Wire> {
        Ok(Wire::Plain(socket))
    }
}

/// Decrements the active-connection count on drop, so the count is released on both a
/// normal handler return and a panic unwind. Also records the connection CLOSE on the shared connz
/// metric (#572), so the close is accounted on every exit path (normal return AND panic unwind),
/// exactly like the cap slot it releases.
struct ConnectionSlot {
    /// The connection-cap slot to release on drop.
    active: Arc<AtomicUsize>,
    /// The shared connz metric to record the close on (#572).
    connz: Arc<ConnectionMetrics>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        // The connection's life ended (handler returned or unwound): record the close off the engine
        // lock, the close half of the accept recorded at admission.
        self.connz.record_close();
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only fault injection for [`spawn_connection_handler`] (#866): the number of UPCOMING handler
    /// spawns to force-fail (as if the OS refused thread creation, EAGAIN), decremented per forced
    /// failure. A test arms it on the accept-loop thread to prove the loop SHEDS spawn failures and then
    /// RECOVERS — a later spawn succeeds and the connection is admitted — without leaking a cap slot.
    /// Thread-local (not a global), so it only affects the one serve loop a test arms it on and never
    /// leaks into another concurrently-running test's loop.
    static FAIL_NEXT_SPAWNS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Spawns the per-connection handler on a fresh, NAMED thread, returning the spawn result so the accept
/// loop can SHED a thread-creation failure gracefully (#866). `std::thread::spawn` PANICS when the OS
/// refuses thread creation (EAGAIN under a cgroup `pids.max`, `RLIMIT_NPROC`, or stack/address-space
/// exhaustion on a bounded-RAM edge box), and the release profile's `panic = "abort"` turns that panic
/// into a whole-process abort — one failed spawn would kill every live connection. `Builder::spawn`
/// surfaces the failure as an `Err` instead, so the caller drops the connection and keeps serving, the
/// same bounded shed the at-capacity and transient-accept-error branches already do.
fn spawn_connection_handler<H>(handler: H) -> std::io::Result<()>
where
    H: FnOnce() + Send + 'static,
{
    #[cfg(test)]
    {
        let remaining = FAIL_NEXT_SPAWNS.with(std::cell::Cell::get);
        if remaining > 0 {
            FAIL_NEXT_SPAWNS.with(|c| c.set(remaining - 1));
            return Err(std::io::Error::other(
                "forced thread-spawn failure (test fault injection, #866)",
            ));
        }
    }
    std::thread::Builder::new()
        .name("ironbus-conn".to_string())
        .spawn(handler)
        .map(|_join| ())
}

/// Serves connections on `listener` until `shutdown` is set, spawning one thread per
/// connection (up to `max_connections` concurrently; further connections are refused). Each
/// connection drives a [`Session`] against the shared engine.
///
/// `clock` is the monotonic clock seam this loop reads to tick the `progress` liveness beacon
/// (#95): the accept loop calls [`LivenessBeacon::mark_progress`](crate::liveness::LivenessBeacon::mark_progress)
/// on EVERY iteration, including the idle would-block poll, so `/healthz` can tell a stuck loop from
/// an idle one (idle still ticks). The clock is read directly, NOT through the append actor, so the
/// accept loop's own liveness signal never depends on the actor being alive.
///
/// # Errors
/// Propagates a fatal listener error. A transient (would-block) accept is retried; a
/// per-connection IO error closes only that connection.
pub fn serve<F, C>(
    listener: &TcpListener,
    engine: &EngineHandle<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
    clock: &C,
    progress: &crate::liveness::LivenessBeacon,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    // The no-auth overload: an accept loop with no configured identity table (the zero-config
    // loopback-dev broker, and every test/bench that drives the loop directly). The scope gate is
    // bypassed for the whole loop, byte-for-byte today's behavior. A fresh, un-scraped connz metric
    // is created here so the legacy entry points keep their signature (#572): a caller that wants the
    // connz signals on `/metrics` uses [`serve_with_auth_connz`] and shares the same `Arc` with the
    // health server.
    serve_with_auth_connz(
        listener,
        engine,
        shutdown,
        max_connections,
        clock,
        progress,
        None,
        &Arc::new(ConnectionMetrics::new()),
    )
}

/// Serves connections exactly like [`serve_with_auth`], but records connection signals (#572) into the
/// shared `connz` metric (accept / close / refuse here; the authed-flip is recorded by the session).
/// The broker bootstrap creates ONE `Arc<ConnectionMetrics>` and passes the SAME handle to both this
/// accept loop and the health server, so `/metrics` exposes the live connz. [`serve_with_auth`]
/// delegates here with a fresh, un-scraped metric, keeping its signature stable.
///
/// # Errors
/// Propagates a fatal listener error, exactly like [`serve`].
// One arg over the clippy default: the connz handle is additive to the existing 7-arg accept-loop
// signature (the SAME wire surface, plus connz), so the cohesive accept loop stays one function.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_auth_connz<F, C>(
    listener: &TcpListener,
    engine: &EngineHandle<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
    clock: &C,
    progress: &crate::liveness::LivenessBeacon,
    auth: Option<Arc<AuthConfig>>,
    connz: &Arc<ConnectionMetrics>,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    serve_inner(
        listener,
        engine,
        shutdown,
        max_connections,
        clock,
        progress,
        auth,
        connz,
        None,
        None,
        TlsTermination::default(),
    )
}

/// Serves connections exactly like [`serve_with_auth_connz`], plus the OPTIONAL pre-auth `DoS` defenses
/// (#633, V2-M7): a per-source-IP connect rate limit, a global half-open (accepted-not-yet-authed)
/// connection cap, and a failed-auth lockout, all bounded O(1) and clock-injected. When `preauth` is
/// `Some(_)`, every accept is checked against the guard BEFORE a handler thread spawns or a handshake
/// byte is read, so an unauthenticated flood is shed at the cheapest point and the rejection surfaces
/// on `ironbus_connections_rejected_total{reason}`. When `None`, the accept path is byte-for-byte the
/// historical one (no IP read, no map, no clock read). The broker bootstrap shares the SAME `connz`
/// `Arc` with the health server so `/metrics` exposes the live rejection counters.
///
/// # Errors
/// Propagates a fatal listener error, exactly like [`serve`].
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_auth_connz_preauth<F, C>(
    listener: &TcpListener,
    engine: &EngineHandle<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
    clock: &C,
    progress: &crate::liveness::LivenessBeacon,
    auth: Option<Arc<AuthConfig>>,
    connz: &Arc<ConnectionMetrics>,
    preauth: Option<Arc<crate::preauth::PreAuthGuard>>,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    serve_inner(
        listener,
        engine,
        shutdown,
        max_connections,
        clock,
        progress,
        auth,
        connz,
        preauth,
        None,
        TlsTermination::default(),
    )
}

/// Serves connections exactly like [`serve_with_auth_connz_preauth`], plus the OPTIONAL security
/// AUDIT-EVENT stream (#635, V2-M7): when `audit` is `Some(_)`, every connection's `Connect` handshake
/// emits the auth OUTCOME (success/failure) and every scope-gated verb a connection lacks emits a
/// DENIAL through the shared emitter, carrying the identity NAME and the mechanism/scope/verb tags,
/// NEVER a credential. The SAME emitter is cloned per connection so the audit sequence is one monotonic
/// space. When `None` (or an emitter over the `Null` sink), the accept path is byte-for-byte the
/// historical one. The broker bootstrap builds the single emitter and shares it here.
///
/// # Errors
/// Propagates a fatal listener error, exactly like [`serve`].
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_auth_connz_preauth_audit<F, C>(
    listener: &TcpListener,
    engine: &EngineHandle<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
    clock: &C,
    progress: &crate::liveness::LivenessBeacon,
    auth: Option<Arc<AuthConfig>>,
    connz: &Arc<ConnectionMetrics>,
    preauth: Option<Arc<crate::preauth::PreAuthGuard>>,
    audit: Option<crate::audit::AuditEmitter>,
    tls: TlsTermination,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    serve_inner(
        listener,
        engine,
        shutdown,
        max_connections,
        clock,
        progress,
        auth,
        connz,
        preauth,
        audit,
        tls,
    )
}

/// Serves connections exactly like [`serve`], with an OPTIONAL connection-scoped auth table (#631,
/// V2-M7). When `auth` is `Some(_)`, every connection's `Connect` handshake must authenticate against
/// the table and a verb is gated on the resolved scope set; when `None`, the broker has no identities
/// and the scope gate is bypassed (the zero-config loopback-dev path). The auth table is shared across
/// connections via a cheap `Arc` clone per accept — it is immutable for the broker's lifetime, read
/// off the actor's hot path (like the credit caps), so it never head-of-line-blocks a handshake.
///
/// # Errors
/// Propagates a fatal listener error, exactly like [`serve`].
// `auth` is taken BY VALUE because each accepted connection clones the `Arc` and MOVES the clone into
// its own `'static` handler thread, so the loop needs to own the `Option<Arc<_>>` to keep cloning it
// for the whole accept lifetime — a borrow could not outlive the spawned threads.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_with_auth<F, C>(
    listener: &TcpListener,
    engine: &EngineHandle<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
    clock: &C,
    progress: &crate::liveness::LivenessBeacon,
    auth: Option<Arc<AuthConfig>>,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    // The connz-less overload: a fresh, un-scraped metric keeps this entry point's signature stable
    // for the existing callers (#572). The connz-aware bootstrap uses `serve_with_auth_connz`. No
    // pre-auth `DoS` guard on this legacy path (#633): the connz-and-`DoS`-aware bootstrap uses
    // `serve_with_auth_connz_preauth`.
    serve_inner(
        listener,
        engine,
        shutdown,
        max_connections,
        clock,
        progress,
        auth,
        &Arc::new(ConnectionMetrics::new()),
        None,
        None,
        TlsTermination::default(),
    )
}

/// The shared accept loop for [`serve_with_auth`] and [`serve_with_auth_connz`]: identical behavior,
/// with the connection signals (#572) recorded into the shared `connz` metric on accept, refuse, and
/// (via the per-connection slot guard) close. The authed-flip is recorded by the session, which gets
/// the same `connz` handle.
// One arg over the clippy default: the connz handle is additive to the cohesive 7-arg accept loop.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn serve_inner<F, C>(
    listener: &TcpListener,
    engine: &EngineHandle<F, C>,
    shutdown: &AtomicBool,
    max_connections: usize,
    clock: &C,
    progress: &crate::liveness::LivenessBeacon,
    auth: Option<Arc<AuthConfig>>,
    connz: &Arc<ConnectionMetrics>,
    preauth: Option<Arc<crate::preauth::PreAuthGuard>>,
    audit: Option<crate::audit::AuditEmitter>,
    tls: TlsTermination,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    // A monotonic per-connection counter that mints a distinct key_shared member id (#64) for each
    // accepted connection, so two concurrently-live members never collide in the rendezvous hash.
    // It only needs to be unique among the live connections; wraparound after 2^64 connections is
    // unreachable in any real deployment.
    let next_member = Arc::new(AtomicU64::new(0));
    while !shutdown.load(Ordering::Acquire) {
        // Tick the liveness beacon at the TOP of every iteration, before the (possibly blocking)
        // accept. A connection accepted, a connection refused at the cap, AND the idle would-block
        // poll all reach this point, so the beacon advances whether or not there is work: a running
        // accept loop is liveness. Only a loop that has truly wedged (or crashed) stops ticking, and
        // only then does `/healthz` shed after the hysteresis window (#95).
        progress.mark_progress(clock.now_monotonic_nanos());
        match listener.accept() {
            Ok((stream, addr)) => {
                // PRE-AUTH `DoS` DEFENSES (#633), checked FIRST, before the connection cap and before any
                // broker work: an UNAUTHENTICATED attacker hits the O(1)-bounded per-IP rate limit, the
                // global half-open cap, and the failed-auth lockout here, so a flood is shed at the
                // cheapest possible point. On reject the stream is dropped (it closes) and the bounded
                // `rejected_total{reason}` counter is bumped by the guard; this is NOT a connz "refused"
                // (that is the connection-cap signal) — the rejection reason is its own metric. When no
                // `DoS` defense is configured (`preauth` is `None`) this is skipped entirely: the accept
                // path is byte-for-byte the historical one (no IP read, no map, no clock read). On
                // ACCEPT the guard returns a `HalfOpenSlot` the handler holds until the handshake
                // resolves, decrementing the half-open count on drop.
                let half_open_slot = match preauth.as_ref() {
                    Some(guard) => match guard.on_accept(addr.ip()) {
                        Ok(slot) => Some(slot),
                        Err(reason) => {
                            // The guard already recorded `rejected_total{reason}`. ALSO emit a
                            // structured audit event (#887): the accept loop refuses this connection
                            // before a handler thread spawns, so no session-side `AuthOutcome` can
                            // fire for it — without this, the dedicated audit transport (SIEM/forensics)
                            // goes blind exactly during a lockout/rate-limit window (the highest-signal
                            // part of an online credential-guessing attack), while attempts keep
                            // arriving. `source_ip` is a safe handle; `reason` is the same bounded tag
                            // as the metric. No-op on the no-audit serve path (byte-for-byte historical).
                            if let Some(audit) = audit.as_ref() {
                                audit.emit(&crate::audit::AuditEvent::PreAuthRejection {
                                    source_ip: addr.ip().to_string(),
                                    reason: reason.as_str(),
                                });
                            }
                            // Refuse this connection before it can consume a handler thread or a
                            // handshake byte.
                            drop(stream);
                            continue;
                        }
                    },
                    None => None,
                };
                if active.load(Ordering::Acquire) >= max_connections {
                    // At capacity: REFUSE by dropping the stream (it closes). Record the refusal on
                    // connz (#572): it never became a live handler, so it counts only as refused, not
                    // accepted/open. Off the engine lock, a single relaxed atomic. Dropping
                    // `half_open_slot` here releases the half-open slot the guard reserved (the
                    // connection never reached a handler), so the half-open count never leaks.
                    drop(half_open_slot);
                    connz.record_refused();
                    drop(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::AcqRel);
                // The source IP, captured for the per-IP failed-auth lockout (#633). It is passed to the
                // session for the auth-outcome callback ONLY; it is NEVER a metric label (the guard keeps
                // it internal), so the metric surface stays low-cardinality.
                let peer_ip = addr.ip();
                // Each handler gets its own cheap clone of the actor handle (a `SyncSender` clone);
                // they all fan into the same single actor, preserving the single-writer rule.
                let engine = engine.clone();
                // The cap slot the handler's `ConnectionSlot` releases on its drop (the matching
                // `fetch_sub` for the admission `fetch_add` above). The loop keeps the original `active`
                // handle to UNDO the pre-increment if the spawn itself fails (#866).
                let slot_active = Arc::clone(&active);
                let member_id = MemberId::new(next_member.fetch_add(1, Ordering::Relaxed));
                // A cheap `Arc` clone of the shared, immutable auth table (or `None` on a no-auth
                // broker), so the handler can pin the connection's scope set at `Connect` time.
                let auth = auth.clone();
                // A cheap `Arc` clone of the shared connz metric, so the handler records the ACCEPT (on
                // start) and its slot guard records the close, and the session records the authed-flip
                // (#572). The loop keeps the original `connz` handle to record a REFUSAL if the spawn fails.
                let connz_for_conn = Arc::clone(connz);
                // A cheap `Arc` clone of the pre-auth `DoS` guard (#633), so the session can report its
                // auth outcome (failure -> per-IP lockout; success -> clear the IP's failed window).
                let preauth_for_conn = preauth.clone();
                // A cheap `Clone` of the shared audit emitter (#635), so the session emits the auth
                // OUTCOME and any scope DENIAL through it (carrying the identity NAME, never a
                // credential). `None` is the no-audit serve path (byte-for-byte historical).
                let audit_for_conn = audit.clone();
                // A cheap `Clone` of the TLS terminator (ADR-0004, #766): a shared `Arc<ServerConfig>`
                // behind the `tls` feature, or a zero-sized plaintext marker otherwise. Each handler
                // completes its own TLS handshake off the accept loop.
                let tls_for_conn = tls.clone();
                // FALLIBLE spawn (#866): `std::thread::spawn` PANICS on a thread-creation refusal
                // (EAGAIN), which `panic = "abort"` turns into a whole-broker abort. `Builder::spawn`
                // surfaces it as an `Err` the loop sheds. The connz ACCEPT is recorded INSIDE the handler
                // (paired with the slot's close), so a connection that never gets a handler thread is a
                // pure REFUSAL — exactly like the at-capacity branch — never a phantom accept+close.
                let spawn_outcome = spawn_connection_handler(move || {
                    // The connection is now live: record the ACCEPT on connz (#572), the accept half the
                    // slot guard's drop matches with a close. Recorded HERE (handler start), not at
                    // admission, so a failed-to-spawn connection is shed as a refusal, never an accept.
                    // Two atomics with NO panic point before the slot below is constructed, so the accept
                    // is always paired with the slot's close on every exit (return OR unwind).
                    connz_for_conn.record_accept();
                    // The guard decrements the cap slot AND records the connz close on return OR a
                    // panic unwind, so a panicking handler can never leak a slot nor miss a close.
                    let _slot = ConnectionSlot {
                        active: slot_active,
                        connz: Arc::clone(&connz_for_conn),
                    };
                    // Hand the half-open slot (#633) to the session so it is released when the `Connect`
                    // HANDSHAKE RESOLVES (a well-formed Connect, success or failure), not at connection
                    // teardown — so the `--max-preauth-connections` cap measures connections still
                    // mid-handshake, NOT authenticated long-lived ones (#880). A slowloris that never
                    // sends a well-formed Connect keeps it until the read timeout closes the connection.
                    // `None` when the half-open cap is disabled (no slot to hand over).
                    let _ = handle_connection(
                        stream,
                        &tls_for_conn,
                        &engine,
                        member_id,
                        auth,
                        &connz_for_conn,
                        preauth_for_conn,
                        peer_ip,
                        audit_for_conn,
                        half_open_slot,
                    );
                });
                if spawn_outcome.is_err() {
                    // The OS refused thread creation (EAGAIN under a cgroup `pids.max`, `RLIMIT_NPROC`,
                    // or stack/address-space exhaustion): #866. The failed closure was dropped, which
                    // released the half-open slot and closed the stream; `record_accept` never ran (it is
                    // the closure's first line), so the `ConnectionSlot` was never built either. UNDO the
                    // admission cap pre-increment and record the REFUSAL — shedding exactly like the
                    // at-capacity branch — then keep serving, instead of aborting the whole broker.
                    active.fetch_sub(1, Ordering::AcqRel);
                    connz.record_refused();
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            // A transient accept failure (fd exhaustion, an aborted/interrupted connection) must not
            // tear down the whole listener: back off briefly and keep serving. Record it as a connz
            // REFUSAL (#572) — the connection never became a live handler, so it is a refused
            // connection, the same disposition as a cap refusal.
            Err(_) => {
                connz.record_refused();
                std::thread::sleep(ACCEPT_POLL);
            }
        }
    }
    Ok(())
}

/// Drives one connection: read bytes, run the session, write responses, until the client
/// closes or the session ends.
#[allow(clippy::too_many_arguments)]
fn handle_connection<F, C>(
    stream: TcpStream,
    tls: &TlsTermination,
    engine: &EngineHandle<F, C>,
    member_id: MemberId,
    auth: Option<Arc<AuthConfig>>,
    connz: &Arc<ConnectionMetrics>,
    preauth: Option<Arc<crate::preauth::PreAuthGuard>>,
    peer_ip: std::net::IpAddr,
    audit: Option<crate::audit::AuditEmitter>,
    half_open_slot: Option<crate::preauth::HalfOpenSlot>,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    stream.set_nonblocking(false)?; // the handler reads blocking (and the TLS handshake needs it)
                                    // Bound how long a stalled client can hold this slot (slowloris defense): a read or
                                    // write that makes no progress within the window errors out and closes the connection.
                                    // Set on the raw socket BEFORE the TLS handshake so a slow handshake is bounded too.
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    // Disable Nagle on the accepted data-plane connection (#1028): small-frame request-response
    // traffic (acks, single-in-flight produces) must not wait out delayed-ACK. Best-effort — a
    // failed setsockopt costs latency, never correctness, so it does not close the connection.
    set_nodelay_best_effort(&stream);
    // Terminate TLS if configured (ADR-0004, #766): completes the TLS 1.3 handshake on the blocking
    // socket HERE, in the handler thread, so a slow/hostile handshake bounds only this connection
    // (under the read timeout just set) and never stalls the accept loop. A handshake failure closes
    // the connection. On the default (plaintext) path `wrap` is a zero-cost `Wire::Plain`. From here
    // the loop is stream-agnostic.
    let mut wire = tls.wrap(stream)?;
    // The mTLS identity (ADR-0004 increment 3, #766): on an mTLS connection rustls has already verified
    // the client certificate against the client-CA during the handshake above, so this is the SAN of a
    // TRUSTED cert (or `None` on plaintext / server-auth-only TLS / a non-tls build). It is threaded
    // into the session as `peer_san` so an `Mtls`-mechanism `Connect` authenticates on the certificate
    // alone; a non-mTLS connection carries `None` and an mTLS-mechanism connect fails closed.
    let peer_san = wire.peer_san();
    // Pin the auth requirement onto the session: with a configured table the `Connect` handshake must
    // authenticate and verbs are scope-gated; with `None` the gate is bypassed (loopback-dev).
    // The connz handle (#572) is attached so a successful `Connect` records the authed-flip.
    let mut session = match auth {
        Some(cfg) => Session::with_member_id_and_auth(member_id, cfg, peer_san),
        None => Session::with_member_id(member_id),
    }
    .with_connz(Arc::clone(connz))
    // Seed the event-driven consume long-poll budget (push delivery) from the engine config via a
    // LOCAL handle read (no actor round-trip), exactly like the credit-cap negotiation. `0` (the
    // default) keeps the byte-identical empty-and-return consume path.
    .with_consume_longpoll_ms(engine.consume_longpoll_ms());
    // Attach the pre-auth `DoS` guard (#633) so the `Connect` handshake reports its auth outcome to the
    // per-IP failed-auth lockout (a failure feeds the lockout + bumps `rejected_total{auth_failed}`; a
    // success clears the IP's window). A no-op when no `DoS` defense is configured.
    if let Some(guard) = preauth {
        session = session.with_preauth(guard, peer_ip);
    }
    // Attach the security audit emitter (#635) so the `Connect` handshake emits the auth OUTCOME and
    // every scope-gated verb emits a DENIAL through it (identity NAME only, never a credential). A
    // no-op when no audit sink is configured (the byte-for-byte historical path).
    if let Some(emitter) = audit {
        session = session.with_audit(emitter);
    }
    // Hand the half-open (#633) slot to the session so it is released when the `Connect` handshake
    // RESOLVES (a well-formed Connect), not at connection teardown (#880) — so the cap measures
    // mid-handshake connections, not authenticated long-lived ones. `None` (no half-open cap wired) and
    // an inert slot are both harmless no-ops on drop.
    if let Some(slot) = half_open_slot {
        session = session.with_half_open_slot(slot);
    }
    // The read/dispatch loop, run to completion so the cleanup below ALWAYS executes on exit:
    // whether the client closed cleanly, a read/write timed out, or a malformed frame ended the
    // session, this connection must leave any key_shared group it joined (#64) and flush its cursor.
    let outcome = connection_loop(&mut wire, engine, &mut session);
    // Leave any key_shared group (#64) so this member's keys re-route to their new owners (its
    // in-flight records drain or expire, the drain-or-expire guard), then flush its work-group's
    // committed cursor so a clean reconnect resumes past acked messages. Both go through the actor
    // (the single writer). Best-effort: the checkpoint is a lagging optimization, and if the actor
    // is already gone (a shutdown drain races a disconnect) these are no-ops, never a hang. Routed
    // to the session's group (#60), default-group if unsubscribed.
    let _ = session.leave_current_key_shared(engine);
    // Deregister this connection's active subscription (#288) so a broadcast group's group-of-one
    // slot frees for the next subscriber on disconnect, not just on an explicit UNSUB. Best-effort,
    // like the key_shared leave: a no-op for an unsubscribed connection or a gone actor.
    //
    // This is a best-effort PLAIN call (not run from a Drop guard): a panic unwinding out of
    // `connection_loop` would skip it and leak the registration, leaving the broadcast slot stuck
    // `BroadcastGroupBusy`. That is the same panic-unwind exposure as the `leave_current_key_shared`
    // cleanup directly above; there is no panic source in those lib paths today, so it is not a
    // live bug, but a future panic-prone refactor of the loop must keep this on every exit path.
    let _ = session.leave_current_subscription(engine);
    // Drop this connection's Level-2 produce-confirm entries (#497): a producer that opened L2
    // produces then disconnected has nobody awaiting its `ProduceConfirm`s, so the engine's bounded
    // registry drops every pending AND ready entry for this member rather than letting them sit until
    // the TTL. Best-effort like the cleanups above: a gone actor is a no-op. This is the "producer
    // disconnect" failure mode of the bounded registry. GATED on `produced_l2` so an L0/L1-only or
    // pure-consumer connection never routes this through the actor (it has nothing to drop).
    if session.produced_l2() {
        let _ = engine.with(move |e| e.drop_l2_confirms(member_id));
    }
    // Drop this connection's back-check listener bindings + queued `TxnCheck`s (#640 part 2): a producer
    // that registered a transaction listener then disconnected leaves a stale route, so the engine clears
    // its `group -> member` bindings and any undrained checks. The in-doubt half messages it owned stay
    // Prepared and are re-routed once the producer reconnects + re-registers (or, after the bounded
    // attempt cap, safely rolled back). GATED on `registered_txn_listener` so a non-back-checking
    // connection never routes this through the actor. This is the back-check twin of the L2-confirm
    // "producer disconnect" cleanup above.
    if session.registered_txn_listener() {
        let _ = engine.with(move |e| e.drop_txn_listener(member_id));
    }
    // Drop any released-but-undrained CLUSTER produce-acks for this connection (#719): a producer that
    // parked a `C2-fsync` ack, had it quorum-released into its outbox, then disconnected before draining
    // it leaves nothing to flush, so the gate's outbox entry is cleared rather than leaked. Off-actor (a
    // gate outbox lock only) and a no-op on a single-node / no-cluster broker (no gate), so the
    // single-node disconnect path is byte-for-byte unchanged.
    engine.drop_client_acks(member_id);
    let group = session.subscription().to_string();
    // Flush the connection's durable cursor on clean disconnect, routed to its (stream, group) (#681):
    // a named-stream consumer's committed position is made durable to that stream's own checkpoint, the
    // default stream (`""`) stays byte-for-byte the historical `checkpoint_group`.
    let stream = session.stream().to_string();
    let _ = engine.with(move |e| {
        let _ = e.checkpoint_in_stream(&stream, &group);
    });
    outcome
}

/// The per-connection read/dispatch loop, factored out so [`handle_connection`] can run its
/// cleanup (`key_shared` leave, cursor flush) on EVERY exit path: a clean close, a read/write
/// error, or a session-ending malformed frame. Returns when the client closes or the session ends.
///
/// The `needed` hint from [`Session::process`] avoids the O(n^2) re-decode of a trickled near-cap
/// frame (#176): after a pass leaves a partial trailing frame needing `needed` bytes, the loop does
/// not re-run `process` until the buffer has reached that length, so each frame is decoded a constant
/// number of times no matter how the client drips it.
///
/// # Single-connection produce pipelining (#1045)
///
/// A `process` pass no longer BLOCK-awaits its parked produce window at the pass boundary; it releases
/// only the ready front prefix and PERSISTS the rest ([`Session::has_parked`]). That is what lets one
/// connection overlap the NEXT batch with the CURRENT batch's fdatasync (closing the single-connection
/// P2 ceiling) — but it makes the LOOP, not the pass, responsible for eventually delivering an
/// un-fsync'd ack. So the loop reads NON-BLOCKING exactly while the window is non-empty: a would-block
/// then means "no new bytes right now", and it BLOCK-drains the front parked ack
/// ([`Session::drain_one_parked_blocking`]) so a bounded-window client that pipelined W produces and is
/// waiting on their acks makes progress (no deadlock). A SATURATING producer keeps finding bytes on
/// every read, so it stays in the read+submit+release cycle and its fsyncs overlap; the drain-one path
/// is reached only when the socket momentarily empties. With an EMPTY window the loop reads BLOCKING
/// (with the slowloris read timeout), so an idle connection sleeps on the socket instead of spinning.
fn connection_loop<F, C>(
    stream: &mut Wire,
    engine: &EngineHandle<F, C>,
    session: &mut Session,
) -> std::io::Result<()>
where
    F: Filesystem + Clone + 'static,
    C: Clock + Clone + 'static,
{
    let mut inbuf: Vec<u8> = Vec::new();
    // The read chunk sizes one pass's worth of new frames (#450, #454): a `process` pass sees at most
    // one chunk of new frames. The old 4 KiB stack chunk capped a 512-produce window at ~13 records per
    // group commit on 256 B payloads (hive measured), paying ~40 fsyncs per window. 64 KiB lets a pass
    // carry hundreds of small frames. Since #1045 a pass no longer BLOCK-awaits its parked window at the
    // pass boundary (it releases the ready prefix and persists the rest), so the publisher pipeline
    // depth is no longer bounded to one chunk: batch N+1's read overlaps batch N's fsync, and the parked
    // window spans passes up to `MAX_PARKED_PRODUCES`. Heap-allocated and zero-initialized:
    // `alloc_zeroed` pages stay untouched (no RSS) until the kernel actually fills them, so an idle or
    // ping-only connection still costs about a page.
    let mut chunk = vec![0u8; 64 * 1024];
    // The minimum buffer length before re-running `process` is worth it: `0` means run on any new
    // byte; a larger value is the trailing partial frame's `needed` hint, so a near-cap frame
    // trickled byte-by-byte is decoded once it is whole, not once per byte (#176).
    let mut needed: usize = 0;
    // The response buffer, hoisted above the loop and reused across passes like `inbuf`/`chunk`
    // (#826 did the same for the deliver scratch). `Session::process` is APPEND-ONLY (it never
    // clears `out`), and every pass fully drains `out` via `write_all` before the next `clear()`,
    // so reuse is sound: no stale bytes ever survive into a later response. This drops one
    // alloc/free per response-producing pass and keeps a deliver-heavy consume pass's multi-frame
    // buffer warm instead of re-growing it from zero every poll. `Vec::new()` stays lazy, so an
    // idle/ping-only connection whose passes leave `out` empty never allocates.
    let mut out: Vec<u8> = Vec::new();
    loop {
        // Read NON-BLOCKING exactly while the session has an un-acked pipelined window to overlap or
        // drain (#1045); read BLOCKING (with the slowloris timeout) when the window is empty, so an
        // idle connection sleeps on the socket. Confine the non-blocking flag to the READ syscall only
        // and restore blocking immediately after: `set_nonblocking` is per-socket (it would make WRITES
        // non-blocking too, and a `write_all` that hit `WouldBlock` mid-frame would truncate an ack on
        // the wire), so every response is written back in blocking mode. The two `fcntl`s are amortized
        // over a whole 64 KiB read's worth of frames.
        let want_nonblocking = session.has_parked();
        if want_nonblocking {
            stream.set_nonblocking(true)?;
        }
        let read_result = stream.read(&mut chunk[..]);
        if want_nonblocking {
            stream.set_nonblocking(false)?;
        }
        match read_result {
            Ok(0) => {
                // The client closed the connection. Any still-parked acks belong on the wire before
                // the close (#1045): block-drain the whole remaining window and flush it, best-effort
                // (a gone actor / fatal here just ends the connection). Then return so
                // `handle_connection` runs its cleanup on this clean-EOF path.
                if session.has_parked() {
                    out.clear();
                    let _ = session.flush_all_parked_blocking(engine, &mut out);
                    let _ = stream.write_all(&out);
                }
                return Ok(());
            }
            Ok(n) => {
                inbuf.extend_from_slice(&chunk[..n]);
                // Skip the dispatch until the buffer can make progress on the known-partial trailing frame.
                if inbuf.len() < needed {
                    continue;
                }

                out.clear();
                let Ok(progress) = session.process(engine, &inbuf, &mut out) else {
                    // A malformed frame, a fatal engine error, or a gone actor: flush any queued response
                    // (which, on the closing path, already carries the block-drained window) and close (a
                    // length-prefixed stream cannot resync).
                    let _ = stream.write_all(&out);
                    return Ok(());
                };
                inbuf.drain(..progress.consumed);
                // Remember how many bytes the trailing partial frame needs before the next pass.
                needed = progress.needed;
                // LEVER 5 — WRITE BEFORE THE CHECKPOINT HOP (median latency): put the response BYTES on
                // the wire FIRST, then fire the checkpoint actor round-trip. The checkpoint is a lagging
                // at-least-once optimization — it only bounds how many already-processed messages a crash
                // REDELIVERS on restart, never correctness — so nothing in the response depends on it, and
                // the byte can safely hit the wire before it. Writing first removes one cross-thread actor
                // round-trip from directly in front of the client-visible response, shaving it off the
                // delivery/ack median (the hop still runs every committing pass, just AFTER the write).
                if !out.is_empty() {
                    stream.write_all(&out)?;
                }
                // Persist the session's work-group cursor on the configured interval so a crash
                // redelivers a bounded tail. ONLY when this pass actually advanced a committed cursor (an
                // ack/flow/unsub): a ping- or connect-only pass skips the checkpoint entirely, so it
                // never sends a command to the actor and therefore CANNOT be head-of-line-blocked by
                // another connection's stalled produce fsync (#177 invariant 4). Best-effort: a
                // checkpoint write failure only costs redelivery on restart, never correctness, so it
                // must not fail the connection. Routed to the session's group (#60); a gone actor is a
                // no-op, never a hang.
                if progress.committed_progress {
                    let group = session.subscription().to_string();
                    // Route the checkpoint to the session's (stream, group) (#681): a named-stream
                    // consumer persists its cursor to that stream's own `cursor-<hex(group)>.ckpt`, the
                    // default stream (`""`) stays byte-for-byte the historical `maybe_checkpoint_group`.
                    let stream = session.stream().to_string();
                    let _ = engine.with(move |e| {
                        let _ = e.maybe_checkpoint_in_stream(&stream, &group);
                    });
                }
            }
            // A NON-BLOCKING read found no new bytes while the window is non-empty (#1045): a
            // bounded-window client pipelined W produces and is waiting on their acks, so there is no
            // more input coming until it gets one. Block-await the FRONT parked ack (and any now-ready
            // siblings) and write it, so the client can send its next batch — this is what stops a
            // bounded-window producer from deadlocking under the non-blocking pass. A saturating
            // producer almost never lands here (its next batch is already in the socket buffer, so the
            // read takes the `Ok(n)` arm and its fsyncs overlap the reads). Gated on `want_nonblocking`
            // so a BLOCKING-mode read timeout (the slowloris window, nothing parked) is NOT mistaken for
            // this and instead closes the connection via the arm below.
            Err(ref e) if want_nonblocking && e.kind() == std::io::ErrorKind::WouldBlock => {
                out.clear();
                if session.drain_one_parked_blocking(engine, &mut out).is_err() {
                    let _ = stream.write_all(&out);
                    return Ok(());
                }
                if !out.is_empty() {
                    stream.write_all(&out)?;
                }
            }
            // A real IO error, or a BLOCKING-mode read timeout (the slowloris defense with nothing
            // parked): close the connection, exactly as the original blocking `read()?` did.
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::{spawn_actor, EngineHandle, DEFAULT_CHANNEL_BOUND};
    use crate::clock::SystemClock;
    use crate::engine::{DiskFullPolicy, Engine, EngineConfig, Poll};
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameType};
    use ironbus_proto::message::{decode_deliver, encode_ack, encode_pub, AckBody, AckOp, PubBody};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;

    fn config() -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
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
            max_open_streams: 0,
            max_metric_streams: crate::engine::DEFAULT_MAX_METRIC_STREAMS,
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
            // Compression OFF (#430): the server tests pin the historical byte-identical image.
            compression: ironbus_core::compress::Codec::None,
            // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
            // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
            default_message_ttl_ms: 0,
            dead_letter_exchange: None,
            dead_letter_expired: false,
        }
    }

    fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode_frame(ty, body, &mut v).unwrap();
        v
    }

    /// A `Write` over a shared `Vec<u8>` so a test reads back exactly what an audit emitter wrote
    /// (#887). Module-scoped so it does not trip the `items-after-statements` lint inside a test body.
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Reads from `stream` until one complete frame is available, returning its type and
    /// body. `buf` carries leftover bytes between calls so a read that delivers several
    /// frames at once is not lost.
    fn read_one_frame(stream: &mut impl Read, buf: &mut Vec<u8>) -> (FrameType, Vec<u8>) {
        let mut chunk = [0u8; 256];
        loop {
            if let Ok(FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            }) = decode_frame(buf)
            {
                let result = (FrameType::from_u8(type_tag).unwrap(), body.to_vec());
                buf.drain(..consumed);
                return result;
            }
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "connection closed before a full frame");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    // A long-lived (valid 2020..2100) self-signed P-256 server cert for "localhost" + its PKCS#8 key,
    // the same fixtures `tls::tests` use. Embedded (not rcgen-generated) because rcgen pulls the
    // deny.toml-banned `ring`; these drive the end-to-end TLS termination test below.
    #[cfg(feature = "tls")]
    const TLS_SERVER_CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBVzCB/aADAgECAhMjGIxpQAwb+081fMl2nX2WEMQ8MAoGCCqGSM49BAMCMB4x
HDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIwIBcNMjAwMTAxMDAwMDAwWhgP
MjEwMDAxMDEwMDAwMDBaMB4xHDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+AoxgwFjAU
BgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJ+smDY9Jybx
FoJDOjOor9Cb56IyQQ64ts0roLO5NVx9AiEAnB1pAliacK3UDfG6xKEig12h4tzf
UrjVOalNQ4uwFJg=
-----END CERTIFICATE-----
";
    #[cfg(feature = "tls")]
    const TLS_SERVER_KEY: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWd4kisc5NnK6Nv0I
RL0rrbnn9ozoIOti7I4eisF3CHWhRANCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+A
-----END PRIVATE KEY-----
";

    /// End-to-end TLS 1.3 TERMINATION (ADR-0004, #766): a rustls client completes a real handshake
    /// against a broker whose accept loop wraps every connection via [`TlsTermination::with_config`],
    /// then CONNECTs and PRODUCEs over the ENCRYPTED connection and gets its ack back. This exercises
    /// the whole accept → handshake → [`connection_loop`] → session → response path over TLS, and
    /// proves the #1045 non-blocking-read pipelining composes with the rustls record layer.
    #[cfg(feature = "tls")]
    #[test]
    fn a_rustls_client_produces_over_a_tls_terminated_connection() {
        let (handle, _actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let connz = Arc::new(ConnectionMetrics::new());

        let server_config =
            crate::tls::server_config_from_pem(TLS_SERVER_CERT, TLS_SERVER_KEY).unwrap();
        let tls = TlsTermination::with_config(Arc::new(server_config));

        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            let connz = Arc::clone(&connz);
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve_with_auth_connz_preauth_audit(
                    &listener, &engine, &shutdown, 16, &clock, &beacon, None, &connz, None, None,
                    tls,
                )
                .unwrap();
            }
        });

        // The client verifies the broker against the embedded cert (mandatory server verification),
        // completes a TLS 1.3 handshake, and exchanges framed requests over the encrypted stream.
        let client_config = crate::tls::client_config_from_pem(TLS_SERVER_CERT).unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);

        let mut buf = Vec::new();
        tls_stream
            .write_all(&frame(FrameType::Connect, b""))
            .unwrap();
        assert_eq!(read_one_frame(&mut tls_stream, &mut buf).0, FrameType::Info);
        // The negotiated transport is exactly TLS 1.3 (docs/TRANSPORT.md §1.1).
        assert_eq!(
            tls_stream.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "the terminated connection must be TLS 1.3"
        );

        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"produced-over-tls",
            },
            &mut pub_body,
        )
        .unwrap();
        tls_stream
            .write_all(&frame(FrameType::Pub, &pub_body))
            .unwrap();
        assert_eq!(
            read_one_frame(&mut tls_stream, &mut buf).0,
            FrameType::PubAck,
            "a produce over the TLS-terminated connection must be acked"
        );

        // Consume the produced message BACK over the same TLS connection: a Flow grant yields a
        // multi-frame Deliver + FlowEnd response, proving the response-write path (larger, multi-frame
        // payloads) flows correctly through the rustls record layer, not just a single small ack.
        tls_stream
            .write_all(&frame(FrameType::Flow, &1u32.to_le_bytes()))
            .unwrap();
        let (ty, body) = read_one_frame(&mut tls_stream, &mut buf);
        assert_eq!(ty, FrameType::Deliver, "a Flow grant must deliver over TLS");
        let delivered = decode_deliver(&body).unwrap();
        assert_eq!(
            delivered.payload, b"produced-over-tls",
            "the payload must round-trip byte-for-byte through TLS"
        );
        assert_eq!(
            read_one_frame(&mut tls_stream, &mut buf).0,
            FrameType::FlowEnd
        );

        // Stop the accept loop and join it; the detached handler drains when the client drops at scope end.
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
    }

    // The mTLS fixtures (ADR-0004 increment 3): a test client-CA, a client cert it signed carrying the
    // URI SAN `spiffe://ironbus/client-a`, and that client cert's key. Embedded (rcgen pulls banned ring).
    #[cfg(feature = "tls")]
    const MTLS_CLIENT_CA: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBeDCCAR6gAwIBAgIUD1qVcCqTnuzk5f2PPxzBVwN3GOYwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWaXJvbmJ1cy10ZXN0LWNsaWVudC1jYTAgFw03NTAxMDEwMDAw
MDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWaXJvbmJ1cy10ZXN0LWNs
aWVudC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDDYgFVNE0pzmAR9jf/e
HWGvwuFfXdWUQa9n2nxTYcncGE47i3G4Er2RKnsh6hEfzqliAnoG/DWQxUIJl4C2
euujMjAwMB0GA1UdDgQWBBQkZqZUZaw1BiRdd6FJjsPbMJq4lTAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCjFMv+V2ep2/pvafj0nCL+OOH1glKT
eImsLe+T6lqrpgIgENKsK8qL9U5HkY7evGZM+CZNPHezUtmVVeASiOLgQO8=
-----END CERTIFICATE-----
";
    #[cfg(feature = "tls")]
    const MTLS_CLIENT_CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBazCCARGgAwIBAgIUT0zI7FaMJw1UP1RjaEl5HqkYI38wCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWaXJvbmJ1cy10ZXN0LWNsaWVudC1jYTAgFw03NTAxMDEwMDAw
MDBaGA80MDk2MDEwMTAwMDAwMFowHjEcMBoGA1UEAwwTaXJvbmJ1cy10ZXN0LWNs
aWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLupvaJvcE6GZOK5O+tFZmO8
LjzvaLvPFMqSRGQbfiRb4Cfgl8zS/dHoenJQoUU0k/ftbV/UCuLsBuPqkjcN/jSj
KDAmMCQGA1UdEQQdMBuGGXNwaWZmZTovL2lyb25idXMvY2xpZW50LWEwCgYIKoZI
zj0EAwIDSAAwRQIhANh/YTa9XguQ8VPV3AQijNNqVY4wDvkGWBu5kMsrGvU0AiB1
kQXnPnAxy3Jc6Zs9blJsL8IrT0lre7UCig1h/UYE0g==
-----END CERTIFICATE-----
";
    #[cfg(feature = "tls")]
    const MTLS_CLIENT_KEY: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgip1PQegOaJTyITUh
WpS5ThUAVX2c3/+TzWk7kIP1nkyhRANCAAS7qb2ib3BOhmTiuTvrRWZjvC4872i7
zxTKkkRkG34kW+An4JfM0v3R6HpyUKFFNJP37W1f1Ari7Abj6pI3Df40
-----END PRIVATE KEY-----
";

    /// End-to-end mTLS (ADR-0004 increment 3, #766): the broker requires a client certificate chained
    /// to the client-CA. A client presenting a VERIFIED cert completes the handshake and connects; a
    /// client presenting NO cert is rejected at the TLS layer (before any `Connect`). This exercises the
    /// `WebPkiClientVerifier` server config + the mTLS handshake through the real serve/accept path.
    #[cfg(feature = "tls")]
    #[test]
    fn an_mtls_client_with_a_verified_cert_connects_and_one_without_a_cert_is_rejected() {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;

        let (handle, _actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let connz = Arc::new(ConnectionMetrics::new());

        // The server REQUIRES a client cert chained to MTLS_CLIENT_CA.
        let server_config = crate::tls::server_config_mtls_from_pem(
            TLS_SERVER_CERT,
            TLS_SERVER_KEY,
            MTLS_CLIENT_CA,
        )
        .unwrap();
        let tls = TlsTermination::with_config(Arc::new(server_config));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            let connz = Arc::clone(&connz);
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve_with_auth_connz_preauth_audit(
                    &listener, &engine, &shutdown, 16, &clock, &beacon, None, &connz, None, None,
                    tls,
                )
                .unwrap();
            }
        });

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut server_roots = rustls::RootCertStore::empty();
        server_roots
            .add(
                CertificateDer::pem_slice_iter(TLS_SERVER_CERT)
                    .next()
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();

        // POSITIVE: a client presenting the verified client cert completes the handshake and connects.
        {
            let client_cert = CertificateDer::pem_slice_iter(MTLS_CLIENT_CERT)
                .next()
                .unwrap()
                .unwrap();
            let client_key =
                rustls::pki_types::PrivateKeyDer::from_pem_slice(MTLS_CLIENT_KEY).unwrap();
            let client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(server_roots.clone())
                .with_client_auth_cert(vec![client_cert], client_key)
                .unwrap();
            let mut conn =
                rustls::ClientConnection::new(Arc::new(client_config), name.clone()).unwrap();
            let mut sock = TcpStream::connect(addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut s = rustls::Stream::new(&mut conn, &mut sock);
            let mut buf = Vec::new();
            s.write_all(&frame(FrameType::Connect, b"")).unwrap();
            assert_eq!(
                read_one_frame(&mut s, &mut buf).0,
                FrameType::Info,
                "an mTLS client with a verified cert connects"
            );
        }

        // NEGATIVE: a client presenting NO client cert is rejected at the mTLS layer (the server
        // demands one), so the handshake fails — no `Connect` is ever processed.
        {
            let client_config = crate::tls::client_config_from_pem(TLS_SERVER_CERT).unwrap();
            let mut conn =
                rustls::ClientConnection::new(Arc::new(client_config), name.clone()).unwrap();
            let mut sock = TcpStream::connect(addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut s = rustls::Stream::new(&mut conn, &mut sock);
            let rejected = s
                .write_all(&frame(FrameType::Connect, b""))
                .and_then(|()| {
                    let mut chunk = [0u8; 64];
                    s.read(&mut chunk).map(|_| ())
                })
                .is_err();
            assert!(
                rejected,
                "a client presenting no cert must be rejected at the mTLS layer"
            );
        }

        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
    }

    #[test]
    fn set_nodelay_best_effort_disables_nagle_on_a_live_socket() {
        // #1028: the shared helper every accepted data-plane connection and cluster peer link runs
        // through must actually flip TCP_NODELAY on (read back via getsockopt on BOTH ends of a live
        // loopback pair), and must be callable on either an accepted or a dialed socket.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dialed = TcpStream::connect(addr).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        set_nodelay_best_effort(&accepted);
        set_nodelay_best_effort(&dialed);
        assert!(
            accepted.nodelay().expect("read TCP_NODELAY back"),
            "the accepted socket must have TCP_NODELAY set"
        );
        assert!(
            dialed.nodelay().expect("read TCP_NODELAY back"),
            "the dialed socket must have TCP_NODELAY set"
        );
    }

    #[test]
    fn a_panicking_handler_releases_its_connection_slot() {
        // The drop-guard must release the slot AND record the connz close on a panic unwind, not just
        // a normal return, so a panicking handler can never permanently leak a connection-cap slot nor
        // miss a close (#572).
        let active = Arc::new(AtomicUsize::new(0));
        active.fetch_add(1, Ordering::AcqRel);
        let connz = Arc::new(ConnectionMetrics::new());
        // Mirror the accept the slot's close pairs with, so currently_open returns to 0 on the close.
        connz.record_accept();
        let a = Arc::clone(&active);
        let cz = Arc::clone(&connz);
        let handle = std::thread::spawn(move || {
            let _slot = ConnectionSlot {
                active: a,
                connz: cz,
            };
            panic!("simulate a handler panic");
        });
        assert!(handle.join().is_err(), "the handler panicked");
        assert_eq!(
            active.load(Ordering::Acquire),
            0,
            "the connection slot was released on unwind"
        );
        let s = connz.snapshot();
        assert_eq!(s.closed, 1, "the connz close was recorded on unwind");
        assert_eq!(s.currently_open, 0, "the live gauge returned to zero");
    }

    /// Opens an in-memory engine and spawns the append actor over it, returning a handle plus the
    /// actor's join handle (which yields the engine back on a clean exit so a test can inspect it).
    fn spawn_inmem() -> (
        EngineHandle<InMemoryFs, SystemClock>,
        std::thread::JoinHandle<Engine<InMemoryFs, SystemClock>>,
    ) {
        let engine = Engine::open(InMemoryFs::new(), SystemClock::new(), config()).unwrap();
        spawn_actor(engine, DEFAULT_CHANNEL_BOUND)
    }

    /// Drops the last handle held by the test and joins the actor, recovering the engine. The server
    /// thread holds its own clone of the handle, so the caller must have already joined the server
    /// (or dropped its handle) for the actor's command channel to disconnect and the actor to exit.
    fn recover_engine(
        handle: EngineHandle<InMemoryFs, SystemClock>,
        actor: std::thread::JoinHandle<Engine<InMemoryFs, SystemClock>>,
    ) -> Engine<InMemoryFs, SystemClock> {
        // An explicit shutdown drains the actor deterministically (flush + checkpoint), then the
        // join yields the owned engine.
        let _ = handle.shutdown();
        drop(handle);
        actor.join().unwrap()
    }

    #[test]
    fn produce_over_tcp_appends_to_the_engine() {
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));

        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });

        // Client: connect, handshake, publish, read the responses.
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = Vec::new();
        client.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut client, &mut buf).0, FrameType::Info);

        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"net",
            },
            &mut pub_body,
        )
        .unwrap();
        client.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
        let (ty, body) = read_one_frame(&mut client, &mut buf);
        assert_eq!(ty, FrameType::PubAck);
        assert_eq!(
            body,
            0u64.to_le_bytes(),
            "PubAck carries the assigned offset 0"
        );

        drop(client);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();

        // The message is durable in the engine and deliverable.
        let mut engine = recover_engine(handle, actor);
        match engine.poll(0).unwrap() {
            Poll::Message(d) => assert_eq!(d.record.payload.as_ref(), b"net"),
            other => panic!("expected the produced message, got {other:?}"),
        }
    }

    #[test]
    fn two_produces_on_one_connection_each_get_exactly_their_own_ack() {
        // #833 discriminator: `connection_loop` now REUSES one response buffer across passes and
        // `clear()`s it at the top of each pass. That is sound only because `Session::process` is
        // append-only and every pass fully drains `out` before the next `clear()`. If the reused
        // buffer were ever NOT cleared, a later pass would re-emit the PRIOR pass's frames as a
        // stale prefix: the second produce would read back the FIRST produce's PubAck(offset 0)
        // instead of its own PubAck(offset 1). We drive two produces down one connection and pin
        // each PubAck to its own offset, so any stale-prefix regression trips the offset asserts.
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));

        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = Vec::new();
        client.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut client, &mut buf).0, FrameType::Info);

        for expected_offset in 0u64..2 {
            let mut pub_body = Vec::new();
            encode_pub(
                &PubBody {
                    flags: 0,
                    timestamp_ms: 0,
                    key: b"k",
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: b"net",
                },
                &mut pub_body,
            )
            .unwrap();
            client.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
            let (ty, body) = read_one_frame(&mut client, &mut buf);
            assert_eq!(ty, FrameType::PubAck, "each pass emits exactly its own ack");
            assert_eq!(
                body,
                expected_offset.to_le_bytes(),
                "the reused response buffer carries no stale prefix from the prior pass"
            );
        }

        drop(client);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        let _ = recover_engine(handle, actor);
    }

    #[test]
    fn a_thread_spawn_failure_sheds_the_connection_and_the_broker_keeps_serving() {
        // #866: `std::thread::spawn` PANICS on a thread-creation refusal (EAGAIN), and the release
        // profile's `panic = "abort"` would turn that panic into a whole-broker crash. With the fallible
        // spawn, a spawn failure is SHED like an at-capacity refusal — the broker keeps serving, the cap
        // slot is NOT leaked, and the live gauge stays balanced. We force the first three handler spawns
        // to fail (the thread-local fault hook, armed on the accept-loop thread), then prove a fourth
        // connection still HANDSHAKES — which a leaked cap slot would have refused at the cap — and the
        // connz counters balance.
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let connz = Arc::new(ConnectionMetrics::new());
        // A cap of 2: if a spawn failure leaked the `active` slot, the third shed would pin `active` at
        // the cap and the fourth connection could never be admitted. With the slot correctly undone,
        // every shed frees its slot and the cap never fills.
        let max_connections = 2;
        let fail_first = 3u32;

        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            let connz = Arc::clone(&connz);
            move || {
                // Arm the fault on THIS (accept-loop) thread: the first `fail_first` handler spawns fail.
                FAIL_NEXT_SPAWNS.with(|c| c.set(fail_first));
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve_inner(
                    &listener,
                    &engine,
                    &shutdown,
                    max_connections,
                    &clock,
                    &beacon,
                    None,
                    &connz,
                    None,
                    None,
                    TlsTermination::default(),
                )
                .unwrap();
            }
        });

        // The first `fail_first` connections each hit the forced spawn failure: the server sheds before
        // any handler runs, so the client sees EOF (or a reset), never an `Info` frame. Reading to the
        // close also SYNCHRONIZES — it returns only once the loop has processed (and shed) that
        // connection, so the next connect is ordered after this one's failure was consumed.
        for i in 0..fail_first {
            let mut client = TcpStream::connect(addr).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut byte = [0u8; 1];
            match client.read(&mut byte) {
                // A clean EOF (`Ok(0)`) or a reset (`Err`) both mean the server shed the connection.
                Ok(0) | Err(_) => {}
                Ok(n) => {
                    panic!("spawn failure #{i} should shed, but got {n} byte(s) of handler data")
                }
            }
            drop(client);
        }

        // The countdown is now exhausted: the next spawn succeeds. If a prior shed had leaked the cap
        // slot, `active` would be pinned at `max_connections` and THIS connection would be refused at the
        // cap (EOF, no `Info`). Instead it handshakes — proving every shed freed its slot.
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = Vec::new();
        client.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(
            read_one_frame(&mut client, &mut buf).0,
            FrameType::Info,
            "after the spawn failures the loop still admits a connection (no leaked cap slot)"
        );
        drop(client);

        // Let the fourth connection's close propagate, then shut down and join. A clean join proves the
        // loop NEVER aborted on a spawn failure (an abort would have killed the test process).
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while connz.snapshot().closed < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();

        let s = connz.snapshot();
        assert_eq!(
            s.refused,
            u64::from(fail_first),
            "each spawn failure was shed as a refusal: {s:?}"
        );
        assert_eq!(
            s.accepted, 1,
            "only the post-recovery connection ever reached a handler, so only it was accepted: {s:?}"
        );
        assert_eq!(
            s.currently_open, 0,
            "the live gauge returned to zero — no accept/close leak: {s:?}"
        );

        let _ = recover_engine(handle, actor);
    }

    #[test]
    fn preauth_rate_limit_rejects_a_second_rapid_connection_and_emits_the_metric() {
        // #633 end-to-end: with a per-IP rate limit (burst 1, 1/s) and a NON-advancing injected clock,
        // the FIRST loopback connection is admitted (and handshakes), but the SECOND from the same IP
        // (127.0.0.1, the only source in a loopback test) finds an empty bucket and is REJECTED before a
        // handler — the server drops the stream, the client sees EOF, and connz records
        // `rejected_total{reason="rate_limited"}`. The clock never advances, so no token refills: the
        // assertion is deterministic, never a wall-clock flake.
        use crate::preauth::{PreAuthConfig, PreAuthGuard};
        use ironbus_core::clock::ManualClock;

        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let connz = Arc::new(ConnectionMetrics::new());
        // The guard's OWN injected clock (a ManualClock that never advances), independent of the serve
        // loop's SystemClock. Burst 1 / rate 1: one token, no refill while the clock is frozen.
        let guard = Arc::new(PreAuthGuard::new(
            PreAuthConfig {
                per_ip_rate_per_sec: 1,
                per_ip_burst: 1,
                half_open_cap: 0,
                lockout_threshold: 0,
                lockout_window_ms: 0,
                lockout_cooldown_ms: 0,
            },
            Arc::new(ManualClock::new()) as Arc<dyn ironbus_core::clock::Clock>,
            Arc::clone(&connz),
        ));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            let connz = Arc::clone(&connz);
            let guard = Arc::clone(&guard);
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve_with_auth_connz_preauth(
                    &listener,
                    &engine,
                    &shutdown,
                    16,
                    &clock,
                    &beacon,
                    None,
                    &connz,
                    Some(guard),
                )
                .unwrap();
            }
        });

        // FIRST connection: admitted, handshakes (spends the one token).
        let mut c1 = TcpStream::connect(addr).unwrap();
        c1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        c1.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut c1, &mut buf).0, FrameType::Info);

        // SECOND connection from the same loopback IP: the bucket is empty and the clock has not
        // advanced, so it is REJECTED. The server drops the stream; a write+read sees EOF/error (the
        // peer closed before any handshake). Poll connz for the rejection (bounded wait, no sleep race).
        let mut rejected = false;
        for _ in 0..50 {
            if let Ok(mut c2) = TcpStream::connect(addr) {
                c2.set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                let _ = c2.write_all(&frame(FrameType::Connect, b""));
                let mut b = [0u8; 16];
                // A rejected connection was dropped by the server: the read returns 0 (EOF) or errors.
                let n = c2.read(&mut b).unwrap_or(0);
                if n == 0 {
                    // Confirm via the metric (the authoritative signal), bounded-retry for the accept
                    // thread to record it.
                    for _ in 0..50 {
                        if connz.snapshot().rejected_rate_limited >= 1 {
                            rejected = true;
                            break;
                        }
                        std::thread::yield_now();
                    }
                }
            }
            if rejected {
                break;
            }
        }
        assert!(
            rejected,
            "a second rapid connection from the same IP must be rate-limited and counted: {:?}",
            connz.snapshot()
        );
        // The legitimate first connection was NOT rejected (it handshaked above) and is still open.
        assert_eq!(
            connz.snapshot().rejected_half_open_cap,
            0,
            "no half-open rejection (the cap is disabled here)"
        );

        drop(c1);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        let _ = recover_engine(handle, actor);
    }

    #[test]
    fn preauth_rejection_emits_an_audit_event_not_just_a_metric() {
        // #887 end-to-end: a pre-auth rejection at accept time must ALSO surface on the security AUDIT
        // stream, not only the `rejected_total{reason}` metric. With a per-IP rate limit (burst 1, 1/s)
        // and a NON-advancing injected clock, the FIRST loopback connection handshakes (spends the one
        // token) and the SECOND from the same IP is REFUSED before a handler thread — the accept loop
        // then emits `event=preauth_rejection reason=rate_limited`. Without the fix the audit stream is
        // blind here (the connection never reaches a session, so no `AuthOutcome` can fire): this test
        // fails on the old code. Deterministic — the guard clock never advances, so no token refills.
        use crate::audit::{AuditEmitter, AuditSink};
        use crate::preauth::{PreAuthConfig, PreAuthGuard};
        use ironbus_core::clock::ManualClock;
        use std::sync::Mutex;

        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let connz = Arc::new(ConnectionMetrics::new());
        let audit_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let audit = AuditEmitter::new(
            AuditSink::writer(Box::new(SharedBuf(Arc::clone(&audit_buf)))),
            Arc::new(ManualClock::new()) as Arc<dyn ironbus_core::clock::Clock>,
        );
        // Burst 1 / rate 1 with a frozen guard clock: one token, no refill.
        let guard = Arc::new(PreAuthGuard::new(
            PreAuthConfig {
                per_ip_rate_per_sec: 1,
                per_ip_burst: 1,
                half_open_cap: 0,
                lockout_threshold: 0,
                lockout_window_ms: 0,
                lockout_cooldown_ms: 0,
            },
            Arc::new(ManualClock::new()) as Arc<dyn ironbus_core::clock::Clock>,
            Arc::clone(&connz),
        ));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            let connz = Arc::clone(&connz);
            let guard = Arc::clone(&guard);
            let audit = audit.clone();
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve_with_auth_connz_preauth_audit(
                    &listener,
                    &engine,
                    &shutdown,
                    16,
                    &clock,
                    &beacon,
                    None,
                    &connz,
                    Some(guard),
                    Some(audit),
                    TlsTermination::default(),
                )
                .unwrap();
            }
        });

        // FIRST connection: admitted, handshakes (spends the one token).
        let mut c1 = TcpStream::connect(addr).unwrap();
        c1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        c1.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut c1, &mut buf).0, FrameType::Info);

        // SECOND connection from the same loopback IP: refused before a handler. Poll the AUDIT buffer
        // (the load-bearing #887 signal) for the structured rejection event, bounded-retry.
        let mut audited = false;
        for _ in 0..50 {
            if let Ok(mut c2) = TcpStream::connect(addr) {
                c2.set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                let _ = c2.write_all(&frame(FrameType::Connect, b""));
                let mut b = [0u8; 16];
                let n = c2.read(&mut b).unwrap_or(0);
                if n == 0 {
                    for _ in 0..50 {
                        let text = String::from_utf8(audit_buf.lock().unwrap().clone()).unwrap();
                        if text.contains("event=preauth_rejection")
                            && text.contains("reason=rate_limited")
                        {
                            audited = true;
                            break;
                        }
                        std::thread::yield_now();
                    }
                }
            }
            if audited {
                break;
            }
        }
        let text = String::from_utf8(audit_buf.lock().unwrap().clone()).unwrap();
        assert!(
            audited,
            "a pre-auth rejection must emit an audit event, not just a metric; audit stream was: {text:?}"
        );
        // The refused connection carried the safe source-IP handle (loopback here), never a credential.
        assert!(
            text.contains("source_ip=\"127.0.0.1\""),
            "the rejection event records the source IP handle: {text:?}"
        );

        drop(c1);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        let _ = recover_engine(handle, actor);
    }

    #[test]
    fn full_produce_fetch_ack_round_trip_over_tcp() {
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });

        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        c.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::Info);

        // Produce.
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"e2e",
            },
            &mut pub_body,
        )
        .unwrap();
        c.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::PubAck);

        // Fetch: a Deliver frame then the FlowEnd terminator.
        c.write_all(&frame(FrameType::Flow, &1u32.to_le_bytes()))
            .unwrap();
        let (ty, body) = read_one_frame(&mut c, &mut buf);
        assert_eq!(ty, FrameType::Deliver);
        let delivered = decode_deliver(&body).unwrap();
        assert_eq!(delivered.payload, b"e2e");
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::FlowEnd); // batch terminator

        // Ack it.
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: delivered.offset,
                generation: delivered.generation,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        c.write_all(&frame(FrameType::Ack, &ack_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::AckStatus);

        drop(c);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();

        // The message was committed: nothing left to deliver.
        let engine = recover_engine(handle, actor);
        assert_eq!(engine.committed_offset().get(), 1);
    }

    #[test]
    fn a_clean_disconnect_checkpoints_the_cursor() {
        // The default interval is 1024, so a single ack does NOT trigger maybe_checkpoint:
        // the committed cursor can only become durable here via the close-path checkpoint the
        // server forces when the client disconnects. Reopening then proves that path fired.
        let (handle, actor) = spawn_inmem();

        // Drive one connection through handle_connection directly so we can JOIN it: when it
        // returns, the EOF-triggered checkpoint is deterministically complete (no race).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn({
            let engine = handle.clone();
            move || {
                let (stream, peer) = listener.accept().unwrap();
                let connz = Arc::new(ConnectionMetrics::new());
                handle_connection(
                    stream,
                    &TlsTermination::default(),
                    &engine,
                    MemberId::new(0),
                    None,
                    &connz,
                    None,
                    peer.ip(),
                    None,
                    None,
                )
            }
        });

        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        c.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::Info);

        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"persist-me",
            },
            &mut pub_body,
        )
        .unwrap();
        c.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::PubAck);

        c.write_all(&frame(FrameType::Flow, &1u32.to_le_bytes()))
            .unwrap();
        let (ty, body) = read_one_frame(&mut c, &mut buf);
        assert_eq!(ty, FrameType::Deliver);
        let delivered = decode_deliver(&body).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::FlowEnd);

        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: delivered.offset,
                generation: delivered.generation,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        c.write_all(&frame(FrameType::Ack, &ack_body)).unwrap();
        assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::AckStatus);

        // Clean disconnect: handle_connection reads EOF, forces the checkpoint (through the actor),
        // and returns.
        drop(c);
        server.join().unwrap().unwrap();

        // Recover the engine's filesystem and reopen it: the committed cursor (1) was persisted by
        // the close path, so the engine resumes at 1 rather than redelivering the acked message.
        let engine = recover_engine(handle, actor);
        let fs = engine.into_filesystem();
        let reopened = Engine::open(fs, SystemClock::new(), config()).unwrap();
        assert_eq!(
            reopened.committed_offset().get(),
            1,
            "a clean disconnect must persist the committed cursor"
        );
    }

    #[test]
    fn a_malformed_frame_closes_the_connection() {
        let (handle, actor) = spawn_inmem();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = SystemClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // A zero-length frame prefix is a malformed envelope: the server closes the conn.
        client.write_all(&[0u8, 0, 0, 0]).unwrap();
        let mut chunk = [0u8; 16];
        // The server closes, so the read returns 0 (EOF).
        let n = client.read(&mut chunk).unwrap();
        assert_eq!(
            n, 0,
            "server should close the connection on a malformed frame"
        );

        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        let _ = recover_engine(handle, actor);
    }

    #[test]
    fn a_stalled_produce_fsync_does_not_block_another_connections_ping() {
        // The #177 acceptance test: a stalled produce `sync_data` on ONE producer's group must not
        // head-of-line-block another connection's ping. Pre-#177 every connection waited on the same
        // engine `Mutex`, which a produce held across its fsync, so a stalled disk froze pings too.
        // Now the engine is owned by the append actor and pings are answered by the connection handler
        // WITHOUT touching the actor, so a producer parked in the actor's group-commit fsync cannot
        // delay another connection's ping. We prove it with the fault fs's sync GATE (no wall-clock
        // sleep): producer A's produce parks mid-fsync, and meanwhile B's ping returns Pong.
        use ironbus_core::clock::ManualClock;
        use ironbus_proto::message::{encode_pub, PubBody};
        use ironbus_storage::fault::FaultFs;

        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || {
                // This engine runs on a ManualClock, so the serve loop's liveness beacon ticks on the
                // same clock type (`C`). The beacon/window are not exercised by this #177 test.
                let clock = ManualClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });

        // Connection A: connect, then publish. Close the sync gate FIRST so A's produce parks inside
        // the actor's group-commit fsync and never returns until we open the gate.
        control.close_sync_gate();
        let mut a = TcpStream::connect(addr).unwrap();
        a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut abuf = Vec::new();
        a.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut a, &mut abuf).0, FrameType::Info);
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: b"stalled",
            },
            &mut pub_body,
        )
        .unwrap();
        // A's produce blocks in the actor's fsync; A does NOT get a PubAck yet. Send it from a thread
        // (it would otherwise block this test thread waiting for the never-arriving PubAck).
        let a_producer = std::thread::spawn(move || {
            a.write_all(&frame(FrameType::Pub, &pub_body)).unwrap();
            // This read blocks until the gate opens and the PubAck finally arrives.
            let (ty, _) = read_one_frame(&mut a, &mut abuf);
            assert_eq!(
                ty,
                FrameType::PubAck,
                "A's produce eventually acks once durable"
            );
            a
        });

        // Wait until A's produce is actually parked inside the closed gate (no wall-clock sleep).
        control.wait_for_sync_gate_entered(1);

        // Connection B: while A's fsync is stalled, B's ping must be answered. This is the head-of-line
        // property: the ping never reaches the actor, so the stalled produce cannot block it.
        let mut b = TcpStream::connect(addr).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut bbuf = Vec::new();
        b.write_all(&frame(FrameType::Connect, b"")).unwrap();
        assert_eq!(read_one_frame(&mut b, &mut bbuf).0, FrameType::Info);
        b.write_all(&frame(FrameType::Ping, b"")).unwrap();
        assert_eq!(
            read_one_frame(&mut b, &mut bbuf).0,
            FrameType::Pong,
            "B's ping is answered while A's produce fsync is stalled (no head-of-line block)"
        );

        // Release the gate: A's produce now completes (its PubAck arrives) and its thread joins.
        control.open_sync_gate();
        let a = a_producer.join().unwrap();
        drop(a);
        drop(b);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        // Drain and stop the actor (it owns the fault-fs engine).
        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join();
    }

    #[test]
    fn a_bounded_window_client_is_unblocked_by_the_drain_one_path_1045() {
        // #1045 NO-DEADLOCK TEETH, over a REAL socket + the real `connection_loop`: a bounded-window
        // producer pipelines W produces in ONE write, then BLOCKS reading for their W acks before
        // sending anything more. Since a pass no longer block-awaits its parked window, the connection
        // loop must deliver those acks via its drain-one-when-would-block path — otherwise the client
        // deadlocks (it waits for acks that are parked; the server waits for bytes that will not come
        // until the client gets acks). We force exactly that shape with the fault-fs sync gate: the W
        // produces park behind a gated group-commit fsync, the loop reads non-blocking, hits WouldBlock,
        // and block-drains the front; once the gate opens all W acks arrive in FIFO order with NO
        // further client bytes.
        use ironbus_core::clock::ManualClock;
        use ironbus_proto::message::{encode_pub, PubBody};
        use ironbus_storage::fault::FaultFs;

        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            move || {
                let clock = ManualClock::new();
                let beacon = crate::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(&listener, &engine, &shutdown, 16, &clock, &beacon).unwrap();
            }
        });

        // Close the gate FIRST so the client's whole window parks behind a gated covering fsync.
        control.close_sync_gate();

        // The bounded-window client, on its own thread (so the test can open the gate once the server is
        // parked): connect, pipeline W PUBs in ONE write, then read W acks WITHOUT sending anything more.
        let w: u64 = 5;
        let client_thread = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new();
            c.write_all(&frame(FrameType::Connect, b"")).unwrap();
            assert_eq!(read_one_frame(&mut c, &mut buf).0, FrameType::Info);
            let mut batch = Vec::new();
            for i in 0..w {
                let payload = format!("m{i}");
                let mut body = Vec::new();
                encode_pub(
                    &PubBody {
                        flags: 0,
                        timestamp_ms: 0,
                        key: b"",
                        headers: b"",
                        dedup: None,
                        fire_and_forget: false,
                        payload: payload.as_bytes(),
                    },
                    &mut body,
                )
                .unwrap();
                batch.extend_from_slice(&frame(FrameType::Pub, &body));
            }
            // One write of the whole window, then STOP sending and wait for the acks.
            c.write_all(&batch).unwrap();
            let mut offsets = Vec::new();
            for _ in 0..w {
                let (ty, body) = read_one_frame(&mut c, &mut buf);
                assert_eq!(ty, FrameType::PubAck, "a bounded-window produce is acked");
                offsets.push(u64::from_le_bytes(body[..8].try_into().unwrap()));
            }
            (c, offsets)
        });

        // Wait until the server is parked inside the window's covering fsync: it read the W pubs, parked
        // them, hit WouldBlock on the empty socket, and called `drain_one_parked_blocking`, now blocked
        // on the gate. Then open the gate: the window commits and the drain-one path releases every ack.
        control.wait_for_sync_gate_entered(1);
        control.open_sync_gate();

        let (c, offsets) = client_thread.join().unwrap();
        assert_eq!(
            offsets,
            (0..w).collect::<Vec<_>>(),
            "all W acks delivered in FIFO order via the drain-one path — no deadlock"
        );

        drop(c);
        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join();
    }
}
