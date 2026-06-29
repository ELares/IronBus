// SPDX-License-Identifier: MIT OR Apache-2.0
//! Live cross-cluster SERVE-ACCEPT wiring: make a real `ironbus serve` broker ACCEPT inbound
//! cross-cluster pull / push connections and serve them over real `TcpStream`s (#728/#732/#733
//! follow-up).
//!
//! ## What was missing
//!
//! The geo mirror/source ([`geo`](super::geo), #728), the edge leaf-spoke ([`leaf`](super::leaf),
//! #732), and the gateway federation ([`federation`](super::federation), #733) each shipped the
//! SERVE LOGIC and proved it in unit + real-socket integration tests — the geo [`OriginServer`] reads
//! a stream's committed records off the off-actor read plane to answer a remote mirror's `MirrorPull`
//! (wire tag 40), and the leaf [`HubPushReceiver`] CRC-revalidates + appends a leaf's `LeafPush` (wire
//! tag 41) to the hub's own receive log. Their PULLER / CONNECTOR side is already wired into the live
//! broker (the CLI spawns the per-origin geo/leaf/federation pull threads). What none of them wired —
//! a deferral flagged identically across all three PRs — is the broker's main run ACCEPTING inbound
//! cross-cluster connections to SERVE them. This module is that accept loop.
//!
//! ## The shape (mirrors the intra-cluster [`DataPlaneRuntime`](super::serve::DataPlaneRuntime), #718)
//!
//! [`CrossClusterServeRuntime::start`] binds ONE dedicated cross-cluster serve listener and spawns a
//! listener thread; per accepted connection it spawns a reader thread that pulls bounded, fail-closed
//! frames off the wire and DISPATCHES each by its [`FrameType`]:
//!
//! * a [`FrameType::MirrorPull`] frame is served READ-ONLY through the geo [`OriginServer`] over the
//!   broker's `Arc`-shared, off-actor [`ReadPlane`](ironbus_storage::read_plane::ReadPlane) (#654) —
//!   the served stream's log is NEVER written; the committed CRC-framed bytes are shipped verbatim.
//!   This one path serves geo MIRRORS / SOURCES *and* federation own-origin streams (all three speak
//!   the SAME `MirrorPull` frame — no new wire frame).
//! * a [`FrameType::LeafPush`] frame is RECEIVED + applied through the leaf [`HubPushReceiver`], which
//!   CRC-revalidates each pushed record and appends it to the HUB's OWN receive log via its own single
//!   writer — never any served stream's log.
//!
//! ## Why a dedicated listener (the design choice)
//!
//! The intra-cluster data plane (#718) binds its OWN peer listener rather than multiplexing the client
//! wire; this module makes the SAME choice for the same reasons, and it is the simpler correct one: the
//! cross-cluster serve is GATED on cross-cluster config (so its listener exists only when configured —
//! the byte-identical-off-feature guarantee is a single `Option` check at the bind site), it is bounded
//! and isolated from the client produce/consume hot path (a flood of remote pullers cannot starve a
//! local client), and it reuses this module's own bounded codec end-to-end. A shared client-wire
//! demultiplex would entangle the cross-cluster accept with the latency-critical client accept loop for
//! no benefit.
//!
//! ## Single-node / no cross-cluster config = nothing spawned (the byte-identical guarantee)
//!
//! [`CrossClusterServeRuntime::start`] is called ONLY when a cross-cluster serve is configured (a geo /
//! federation served stream, or a leaf hub receive log). With none configured NOTHING here is
//! constructed — no listener, no thread, no frame ever decoded — and the broker (produce/consume hot
//! path + engine/session/actor/storage/core) is byte-for-byte today's. The gate lives at the CLI call
//! site on the SAME configs the puller side is gated on.
//!
//! ## Bounded, resilient, ~0 idle (the #726 discipline, re-applied)
//!
//! Many remote pullers / leaves may connect; each gets ONE bounded reader thread, and a slow / broken
//! remote drops only its own connection — it never blocks another connection or local traffic (the
//! shared read plane is read-only and lock-free; the hub receiver takes a short per-push lock only to
//! append). The listener binds NON-BLOCKING (so the accept loop polls the shutdown flag), but every
//! ACCEPTED stream is forced BLOCKING with [`set_nonblocking(false)`](std::net::TcpStream::set_nonblocking)
//! (the #726 `O_NONBLOCK`-inheritance fix — a BSD/macOS accepted stream inherits the listener's
//! non-blocking flag, which would make a blocking read return `WouldBlock` instantly and hot-spin) plus
//! a short read timeout, so an IDLE accepted connection genuinely PARKS on the read (waking only every
//! poll to re-check shutdown) and does ~0 work — never a busy-spin.
//!
//! ## SCOPE / FLAGGED
//!
//! * **Single served stream.** Like the intra-cluster `DEFAULT_PARTITION` scope (#693) and the geo /
//!   leaf / federation integration tests, a `MirrorPull` for ANY stream name is served from the
//!   broker's one default-stream read plane, and a `LeafPush` is applied to the one configured hub
//!   receive log. Mapping named streams to distinct served read planes / receive logs is the
//!   multi-partition follow-up (#693).
//! * **Auth / TLS is minimal (loopback / trusted).** The accept loop trusts the transport; per-puller
//!   authn/z + TLS for a cross-cluster link is the hardening follow-up (the same posture the geo /
//!   leaf / federation pull side and the data-plane peer transport ship today).
//! * **Two-OS-PROCESS `ironbus serve`-to-`ironbus serve` validation is the #636 t4g hardware run.** The
//!   accept loop is proven over a REAL loopback `TcpStream` IN-PROCESS (a client socket connects to the
//!   spawned listener and exercises the real accept + serve path); the multi-process run stalls on the
//!   macOS dev rig (the #726 `O_NONBLOCK` multi-process artifact — a property of the measuring machine,
//!   not the product; Linux / t4g accepted sockets do not inherit the flag).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::read_plane::ReadPlane;

use super::geo::{
    MirrorPullRequest, MirrorPullResponse, OriginServer, MAX_GEO_PULL_BYTES, MAX_ORIGIN_STREAM_LEN,
};
use super::leaf::{HubPushReceiver, LeafPushRequest, LeafPushResponse, MAX_LEAF_PUSH_BYTES};
use ironbus_core::clock::Clock;

/// How long the cross-cluster serve threads (the accept loop, a per-connection reader) sleep / block
/// between shutdown re-checks, so a `stop` is prompt and an idle loop never busy-spins. The same
/// cadence the intra-cluster [`DataPlaneRuntime`](super::serve::DataPlaneRuntime) and the geo / leaf
/// pull loops use.
const SERVE_ACCEPT_POLL: Duration = Duration::from_millis(100);

/// The hard upper bound on a single inbound cross-cluster frame. A `MirrorPull` request is tiny; a
/// `LeafPush` request carries up to [`MAX_LEAF_PUSH_BYTES`] of pushed record bytes (8 MiB) plus its
/// small header. This cap sits just above that and below the absolute envelope cap, so every valid
/// frame fits and a larger one is rejected pre-allocation by the bounded codec (the SIZE half of the
/// fail-closed discipline). Equals the geo/leaf links' own receive cap so the accept side bounds an
/// inbound frame identically to the per-protocol links.
const MAX_SERVE_FRAME_BYTES: u32 = {
    let geo = MAX_GEO_PULL_BYTES.saturating_add(1024);
    let leaf = MAX_LEAF_PUSH_BYTES.saturating_add(1024);
    if geo > leaf {
        geo
    } else {
        leaf
    }
};

/// What this broker SERVES to inbound cross-cluster connections. Constructed by the CLI from the geo /
/// federation served-stream config and the leaf hub config; ALL fields are gates — an empty config
/// (`is_empty`) means nothing is served and the runtime is never started (the byte-identical
/// off-feature guarantee).
///
/// In this single-stream slice (#693), `serve_pulls` toggles serving the broker's default-stream read
/// plane to any `MirrorPull` (geo mirror / source / federation own-origin) and `accept_leaf_pushes`
/// toggles accepting `LeafPush` frames into the one hub receive log. Mapping named streams to distinct
/// served planes / receive logs is the multi-partition follow-up.
pub struct CrossClusterServeConfig<F: Filesystem, C: Clock> {
    /// The `Arc`-shared, off-actor read plane the geo [`OriginServer`] serves a `MirrorPull` from
    /// (read-only — never a writer of the served log). `Some` when a geo / federation served stream is
    /// configured; `None` disables the `MirrorPull` serve path entirely.
    pub serve_plane: Option<Arc<ReadPlane<F>>>,
    /// The hub receive-log [`HubPushReceiver`] a `LeafPush` is applied to (its OWN single writer; never
    /// a served stream's log). `Some` when this broker is a leaf hub; `None` disables the `LeafPush`
    /// accept path entirely. Behind a `Mutex` so the per-connection readers serialize their appends
    /// through the receiver's one writer (the single-writer invariant across connections).
    pub hub_receiver: Option<Arc<Mutex<HubPushReceiver<F, C>>>>,
}

impl<F: Filesystem, C: Clock> CrossClusterServeConfig<F, C> {
    /// True when nothing is served — no geo / federation pull plane AND no leaf hub receive log. The
    /// CLI checks this BEFORE [`CrossClusterServeRuntime::start`]; an empty config never binds a
    /// listener, so the broker is byte-for-byte today's.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.serve_plane.is_none() && self.hub_receiver.is_none()
    }
}

/// A live cross-cluster serve-accept runtime: the listener + per-connection reader threads that ACCEPT
/// inbound `MirrorPull` / `LeafPush` connections and serve them, mirroring the intra-cluster
/// [`DataPlaneRuntime`](super::serve::DataPlaneRuntime) shape (#718).
///
/// Constructed ONLY when a cross-cluster serve is configured (see [`CrossClusterServeConfig::is_empty`]);
/// with none configured this is never built and nothing here runs — the byte-identical off-feature
/// guarantee.
pub struct CrossClusterServeRuntime {
    /// The shutdown flag the runtime OWNS; `stop` sets it and joins the listener (the per-connection
    /// readers are detached and exit on this flag or a closed link).
    shutdown: Arc<AtomicBool>,
    /// The accept-loop listener thread.
    listener: Option<JoinHandle<()>>,
}

impl CrossClusterServeRuntime {
    /// Bind the cross-cluster serve listener on `serve_addr` and spawn the accept loop. The bind is
    /// SYNCHRONOUS (a bind failure is reported before any thread spawns — no half-started runtime). The
    /// `config` carries the read plane to serve pulls from and / or the hub receiver to apply pushes to;
    /// at least one must be present (the caller checks [`CrossClusterServeConfig::is_empty`] first).
    ///
    /// # Errors
    /// An [`io::Error`] if the listener cannot bind its address. On an error NO thread is left running.
    ///
    /// # Panics
    /// Panics only if the OS refuses to spawn the listener thread — an unrecoverable
    /// resource-exhaustion condition at start, treated like a failed allocation. Once `start` returns
    /// `Ok`, the runtime never panics on the serve path.
    pub fn start<F, C>(
        serve_addr: SocketAddr,
        config: CrossClusterServeConfig<F, C>,
    ) -> io::Result<Self>
    where
        F: Filesystem + Send + Sync + 'static,
        C: Clock + Send + 'static,
    {
        // Bind BEFORE spawning, so a bind failure is synchronous (no half-started runtime). Non-blocking
        // so the accept loop can poll the shutdown flag (and back off, ~0 idle, when nothing connects).
        let listener = TcpListener::bind(serve_addr)?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_l = Arc::clone(&shutdown);
        let listener_handle = std::thread::Builder::new()
            .name("ib-xcluster-serve".to_string())
            .spawn(move || run_serve_listener(listener, config, &shutdown_l))
            .expect("spawn cross-cluster serve listener thread");

        Ok(Self {
            shutdown,
            listener: Some(listener_handle),
        })
    }

    /// Signal shutdown and join the listener thread. Idempotent. Called by the broker's serve teardown
    /// alongside the geo / leaf / federation plane stops.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.listener.take() {
            let _ = h.join();
        }
    }
}

impl Drop for CrossClusterServeRuntime {
    fn drop(&mut self) {
        // Best-effort: a caller that forgets `stop` (or a panic on the serve path) still signals the
        // threads to wind down rather than leaking them. The deterministic join is `stop`.
        self.shutdown.store(true, Ordering::Release);
    }
}

/// The cross-cluster serve LISTENER thread: accept inbound connections and spawn one reader per
/// connection. Reader threads are detached; they exit on a closed / broken link or shutdown. The accept
/// loop is non-blocking and polls the shutdown flag so a stop is prompt and an idle accept does ~0 work.
// A thread entry point: it OWNS the listener + the served config (cloned into each per-connection
// reader) for the thread's lifetime; a borrow would fight the 'static spawn bound.
#[allow(clippy::needless_pass_by_value)]
fn run_serve_listener<F, C>(
    listener: TcpListener,
    config: CrossClusterServeConfig<F, C>,
    shutdown: &Arc<AtomicBool>,
) where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // The listener is NON-BLOCKING so the accept loop can poll shutdown; on BSD/macOS an
                // accepted stream INHERITS the listener's `O_NONBLOCK`, which would make a blocking read
                // return `WouldBlock` instantly and hot-spin instead of parking on an idle link (the
                // #726 idle busy-spin). Restore BLOCKING mode so the read timeout takes effect and an
                // idle reader genuinely PARKS (waking every poll to re-check shutdown).
                let _ = stream.set_nonblocking(false);
                // A short read timeout so a reader's blocking read re-checks shutdown promptly and an
                // idle inbound link never wedges a stop.
                let _ = stream.set_read_timeout(Some(SERVE_ACCEPT_POLL));
                let serve_plane = config.serve_plane.clone();
                let hub_receiver = config.hub_receiver.clone();
                let sd = Arc::clone(shutdown);
                let _ = std::thread::Builder::new()
                    .name("ib-xcluster-read".to_string())
                    .spawn(move || {
                        run_serve_reader(stream, serve_plane.as_ref(), hub_receiver.as_ref(), &sd);
                    });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                sleep_interruptible(SERVE_ACCEPT_POLL, shutdown);
            }
            Err(_) => sleep_interruptible(SERVE_ACCEPT_POLL, shutdown),
        }
    }
}

/// A per-connection cross-cluster serve reader: pull bounded, fail-closed frames off the wire and
/// DISPATCH each by its [`FrameType`] — a `MirrorPull` is served READ-ONLY off the geo
/// [`OriginServer`] over the shared read plane; a `LeafPush` is CRC-revalidated + applied by the leaf
/// [`HubPushReceiver`] into the hub's own receive log. The response frame is written back on the SAME
/// link. A frame whose type is not configured to be served (e.g. a `LeafPush` on a broker that is not a
/// hub), an oversized / corrupt frame, or any IO error drops THIS link only — never a panic, an
/// over-allocation, or an effect on another connection.
fn run_serve_reader<F, C>(
    stream: TcpStream,
    serve_plane: Option<&Arc<ReadPlane<F>>>,
    hub_receiver: Option<&Arc<Mutex<HubPushReceiver<F, C>>>>,
    shutdown: &AtomicBool,
) where
    F: Filesystem,
    C: Clock,
{
    let mut conn = ServeConn::new(stream);
    // The geo OriginServer borrows the read plane; build it ONCE per connection (cheap — it just holds
    // the `&ReadPlane`). It is strictly read-only: serving a pull never mutates the served stream.
    let origin = serve_plane.map(|p| OriginServer::new(p));
    while !shutdown.load(Ordering::Acquire) {
        match conn.recv_frame() {
            Ok(Some((frame_type, body))) => {
                if handle_one(&mut conn, frame_type, &body, origin.as_ref(), hub_receiver).is_err()
                {
                    return;
                }
            }
            // A read timeout with no full frame buffered: re-poll (re-checking shutdown). This is the
            // IDLE path — the reader parked on the blocking read for up to the timeout, did ~0 work, and
            // now loops to re-check shutdown.
            Err(ServeConnError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            // A bounded framing / decode error (fail-closed): log the cause for the operator and end
            // this reader. A hostile / corrupt / oversized frame is contained to THIS dropped link.
            Err(ServeConnError::Frame(e)) => {
                tracing::debug!(error = %e, "cross-cluster serve: dropping a link on a framing error");
                return;
            }
            // The peer closed cleanly, or a non-timeout IO fault: end this reader (the listener accepts
            // the next connection).
            Ok(None) | Err(ServeConnError::Io(_)) => return,
        }
    }
}

/// Serve / apply ONE decoded cross-cluster frame, writing its response back on the connection. Returns
/// `Err(())` to signal the caller to drop the link (a write fault, a serve error, or a frame whose type
/// is not served by this broker); `Ok(())` to continue.
fn handle_one<F, C>(
    conn: &mut ServeConn,
    frame_type: Option<FrameType>,
    body: &[u8],
    origin: Option<&OriginServer<'_, F>>,
    hub_receiver: Option<&Arc<Mutex<HubPushReceiver<F, C>>>>,
) -> Result<(), ()>
where
    F: Filesystem,
    C: Clock,
{
    match frame_type {
        // A geo / federation MIRROR PULL: serve it READ-ONLY off the shared read plane. The committed
        // CRC-framed bytes are shipped verbatim; the served log is never written.
        Some(FrameType::MirrorPull) => {
            let Some(origin) = origin else {
                // A pull arrived but this broker serves no stream (not a geo / federation origin): drop
                // the link rather than answer for a stream we do not serve.
                return Err(());
            };
            let req = MirrorPullRequest::decode(body).map_err(|_| ())?;
            let resp = origin.serve_pull(&req).map_err(|_| ())?;
            conn.send_mirror_response(&resp).map_err(|_| ())
        }
        // A leaf LEAF PUSH: CRC-revalidate + apply to the hub's own receive log via its single writer.
        Some(FrameType::LeafPush) => {
            let Some(receiver) = hub_receiver else {
                // A push arrived but this broker is not a hub: drop the link.
                return Err(());
            };
            let req = LeafPushRequest::decode(body).map_err(|_| ())?;
            // Take the receiver lock ONLY to apply (append + fsync) this push; the socket read / write
            // is off the lock, so one slow connection cannot wedge another's append. Recover a poisoned
            // lock (the append is idempotent on the leaf's resume cursor).
            let ack = {
                let mut r = receiver
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match r.apply_push(&req) {
                    Ok(out) => LeafPushResponse {
                        accepted_through_leaf_offset: out.accepted_through_leaf_offset,
                    },
                    // A corrupt pushed frame fails closed: the hub kept the validated prefix and we ack
                    // exactly that far, so the leaf re-pushes from the corruption point (no false ack
                    // past durable data). Any other error drops the link.
                    Err(super::leaf::LeafError::CorruptFrame { at_leaf_offset, .. }) => {
                        LeafPushResponse {
                            accepted_through_leaf_offset: at_leaf_offset,
                        }
                    }
                    Err(_) => return Err(()),
                }
            };
            conn.send_leaf_response(ack).map_err(|_| ())
        }
        // Any other (or unknown) frame type on the cross-cluster serve link is unexpected: fail closed.
        _ => Err(()),
    }
}

/// A bounded, fail-closed framed reader / writer over one accepted cross-cluster `TcpStream`. It owns
/// the same `[len][type][body]` envelope the geo [`GeoLink`](super::geo::GeoLink) and leaf
/// [`LeafLink`](super::leaf::LeafLink) write, but DISPATCHES by the type tag rather than assuming one
/// protocol, so the single accept loop serves both a `MirrorPull` and a `LeafPush` connection. Every
/// inbound frame is size-capped ([`MAX_SERVE_FRAME_BYTES`]) BEFORE its body is read or decoded.
struct ServeConn {
    stream: TcpStream,
    /// Accumulated, not-yet-consumed inbound bytes (a partial frame may straddle reads).
    inbuf: Vec<u8>,
}

/// One decoded inbound frame off the cross-cluster serve wire: its interpreted [`FrameType`] (`None`
/// for an unrecognized tag, which the dispatcher fails closed on) plus its body bytes. Aliased so the
/// connection reader's return type stays readable.
type DecodedFrame = (Option<FrameType>, Vec<u8>);

/// A typed error from the cross-cluster serve connection: a bounded framing / IO failure. The reader
/// always surfaces one of these rather than panicking or over-allocating — a hostile remote is
/// contained to a dropped connection.
#[derive(Debug)]
enum ServeConnError {
    /// The frame envelope was malformed or exceeded the size cap (rejected pre-allocation).
    Frame(FrameError),
    /// An underlying IO error reading from / writing to the connection (including a read timeout,
    /// surfaced as `WouldBlock` / `TimedOut` so the caller can re-poll).
    Io(io::Error),
}

impl From<io::Error> for ServeConnError {
    fn from(e: io::Error) -> Self {
        ServeConnError::Io(e)
    }
}

impl ServeConn {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            inbuf: Vec::new(),
        }
    }

    /// Receive ONE cross-cluster frame, BLOCKING on the stream's read (the read timeout the accept loop
    /// set governs how long it blocks — so an idle link parks / backs off rather than busy-spins).
    /// Returns `Ok(Some((frame_type, body)))` for a complete frame (`frame_type` is `None` for an
    /// unrecognized tag, which the dispatcher fails closed on), `Ok(None)` when the peer closes cleanly,
    /// and `Err` on a bounded framing error or an IO fault (incl. a read timeout).
    fn recv_frame(&mut self) -> Result<Option<DecodedFrame>, ServeConnError> {
        // Heap chunk (matches the geo / leaf links + the intra-cluster `DataPlaneLink`): a 64 KiB stack
        // array trips the large-stack-array lint, and the read loop reuses the one buffer regardless.
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            if let Some(frame) = self.try_decode_one()? {
                return Ok(Some(frame));
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                // Clean EOF with no complete frame buffered = peer closed.
                return Ok(None);
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Decode one buffered frame if a complete one is present, consuming its bytes. Returns `Ok(None)`
    /// when more bytes are needed. Applies the size cap BEFORE allocation (the bounded codec).
    fn try_decode_one(&mut self) -> Result<Option<DecodedFrame>, ServeConnError> {
        match decode_frame_with_cap(&self.inbuf, MAX_SERVE_FRAME_BYTES) {
            Ok(FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            }) => {
                let frame_type = FrameType::from_u8(type_tag);
                let body = body.to_vec();
                self.inbuf.drain(..consumed);
                Ok(Some((frame_type, body)))
            }
            Ok(FrameDecode::Incomplete { .. }) => Ok(None),
            Err(e) => Err(ServeConnError::Frame(e)),
        }
    }

    /// Frame + write a `MirrorPull` RESPONSE back to the puller (the geo wire shape — tag 40, kind 1).
    fn send_mirror_response(&mut self, resp: &MirrorPullResponse) -> Result<(), ServeConnError> {
        let mut frame = Vec::new();
        encode_frame(FrameType::MirrorPull, &resp.encode(), &mut frame)
            .map_err(ServeConnError::Frame)?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Frame + write a `LeafPush` RESPONSE (the ack) back to the leaf (the leaf wire shape — tag 41,
    /// kind 1). Takes the small [`LeafPushResponse`] (one `u64`) by value — it is `Copy`.
    fn send_leaf_response(&mut self, resp: LeafPushResponse) -> Result<(), ServeConnError> {
        let mut frame = Vec::new();
        encode_frame(FrameType::LeafPush, &resp.encode(), &mut frame)
            .map_err(ServeConnError::Frame)?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }
}

/// Sleep for `dur` but wake early if shutdown is set, in small slices, so a stop is never delayed by a
/// full sleep. Mirrors the intra-cluster serve plane's `sleep_interruptible`.
fn sleep_interruptible(dur: Duration, shutdown: &AtomicBool) {
    let slice = Duration::from_millis(20);
    let mut left = dur;
    while left > Duration::ZERO && !shutdown.load(Ordering::Acquire) {
        let this = slice.min(left);
        std::thread::sleep(this);
        left = left.checked_sub(this).unwrap_or(Duration::ZERO);
    }
}

// A small compile-time assertion that the serve cap admits a maximal leaf push (the largest legitimate
// inbound frame) plus its header, and stays under the absolute envelope cap. Compared in `u64` so the
// `usize` stream-name cap widens (never a truncating `as u32`).
const _: () = {
    assert!(MAX_SERVE_FRAME_BYTES >= MAX_LEAF_PUSH_BYTES);
    assert!(MAX_SERVE_FRAME_BYTES as u64 >= MAX_ORIGIN_STREAM_LEN as u64);
    assert!(MAX_SERVE_FRAME_BYTES <= ironbus_proto::frame::MAX_FRAME_LEN);
};

#[cfg(all(test, unix))]
#[allow(
    // The real-socket accept-loop proofs are single coherent end-to-end scenarios whose length is
    // intrinsic (build a log, spawn the listener, dial it, drive the protocol, assert byte-identity).
    clippy::too_many_lines,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use crate::cluster::geo::{GeoFrame, GeoLink, MirrorApplier, OriginCursorStore};
    use crate::cluster::leaf::{LeafForwarder, LeafFrame, LeafLink, LeafPushCursor};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::{Offset, RecordFlags};
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use std::net::{Ipv4Addr, TcpStream};
    use std::time::Instant;

    /// The per-pull budgets the client uses (the geo plane's own pull max constants are private; a
    /// generous request makes a multi-round catch-up over the real socket).
    const PULL_MAX_RECORDS: u32 = 1024;
    const PULL_MAX_BYTES: u32 = 1024 * 1024;

    // ---- scaffolding (a real on-disk StdFs backend + real sockets, the geo/leaf test discipline) ----

    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    /// A real on-disk log with `n` records, fsync'd, leaked to `'static` so its read plane keeps
    /// observing it for the test's lifetime (in a real serve the engine's append actor owns it). Returns
    /// the leaked log + its sealed served-prefix end offset.
    fn leaked_log_with_served_end(
        dir: &std::path::Path,
        prefix: &str,
        n: u32,
    ) -> (&'static Log<StdFs, ManualClock>, u64) {
        let fs = StdFs::new(dir.to_path_buf());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).expect("log opens");
        for i in 0..n {
            log.append(&rec(format!("{prefix}-{i:03}").as_bytes()))
                .unwrap();
        }
        log.sync().unwrap();
        let leaked: &'static Log<StdFs, ManualClock> = Box::leak(Box::new(log));
        let served = sealed_served_end(leaked);
        (leaked, served)
    }

    /// The sealed-prefix end offset a read plane will serve (the geo test's helper, verbatim discipline).
    fn sealed_served_end(log: &Log<StdFs, ManualClock>) -> u64 {
        let plane = log.read_plane().unwrap();
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 100_000);
            let raw = plane
                .read_range_raw(Offset::new(next), 1_000, None)
                .unwrap();
            let adv = raw.run.next_offset.get();
            if adv > next {
                next = adv;
            } else {
                break;
            }
        }
        next
    }

    fn free_addr() -> SocketAddr {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    /// Scale a GENEROUS base wait by the observed host slowdown (#618): a local copy of the runtime
    /// test's `host_scaled` (max-of-3-probes + a 24x cap), so the timing waits stay truthful and
    /// flake-free on a contended CI runner WITHOUT weakening what they prove. On an unloaded host the
    /// factor is ~1 and the wait stays the base (the test exits early the instant its predicate holds).
    fn host_scaled(base: Duration) -> Duration {
        fn probe_busy_nanos() -> u128 {
            const ITERS: u64 = 2_000_000;
            let start = Instant::now();
            let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
            for i in 0..ITERS {
                acc = acc
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(i | 1);
                acc ^= acc >> 29;
            }
            std::hint::black_box(acc);
            start.elapsed().as_nanos().max(1)
        }
        const REFERENCE_BUSY_NANOS: u128 = 4_000_000;
        const MAX_SCALE: u32 = 24;
        let mut samples = [probe_busy_nanos(), probe_busy_nanos(), probe_busy_nanos()];
        samples.sort_unstable();
        let observed = samples[2];
        let factor = (observed / REFERENCE_BUSY_NANOS).clamp(1, u128::from(MAX_SCALE));
        let factor = u32::try_from(factor).unwrap_or(MAX_SCALE);
        base * factor
    }

    fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + host_scaled(timeout);
        while Instant::now() < deadline {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        pred()
    }

    fn open_mirror(dir: &std::path::Path) -> MirrorApplier<StdFs, ManualClock> {
        let log = Log::open(
            StdFs::new(dir.to_path_buf()),
            ManualClock::new(),
            small_config(),
        )
        .expect("mirror log opens");
        let cursors =
            OriginCursorStore::open(&StdFs::new(dir.to_path_buf())).expect("cursor store");
        MirrorApplier::new(log, cursors, true)
    }

    /// A `serve_plane`-only config (a geo / federation origin) over `origin`'s read plane.
    fn serve_only(
        origin: &'static Log<StdFs, ManualClock>,
    ) -> CrossClusterServeConfig<StdFs, ManualClock> {
        CrossClusterServeConfig {
            serve_plane: Some(Arc::new(origin.read_plane().expect("read plane"))),
            hub_receiver: None,
        }
    }

    // ---- THE REAL-SOCKET ACCEPT-LOOP PROOF: a MirrorPull is served byte-faithfully ----

    /// Spawn the NEW broker serve-ACCEPT runtime over a real loopback listener, dial it with a real
    /// `TcpStream`, send `MirrorPull` requests for a served stream, and prove the committed records come
    /// back BYTE-FAITHFULLY — the end-to-end accept-loop wiring over a real socket (in-process). This is
    /// the load-bearing proof: it exercises the real accept + dispatch + `serve_pull` path, not just the
    /// serve logic the geo unit tests already cover.
    #[test]
    fn a_real_socket_pull_serves_committed_records_byte_faithfully() {
        let _guard = crate::cluster::heavy_cluster_test_guard();
        let origin_dir = tempfile::tempdir().expect("origin dir");
        let mirror_dir = tempfile::tempdir().expect("mirror dir");
        let (origin, served) = leaked_log_with_served_end(origin_dir.path(), "o", 40);
        assert!(
            served > 0,
            "the origin has a non-empty sealed prefix to serve"
        );

        let addr = free_addr();
        let mut runtime =
            CrossClusterServeRuntime::start(addr, serve_only(origin)).expect("serve-accept binds");

        // A real client socket drives the geo MirrorPull protocol against the spawned accept loop.
        let key = format!("{addr}/");
        let mut app = open_mirror(mirror_dir.path());
        assert!(
            wait_until(Duration::from_secs(10), || {
                let Ok(stream) = TcpStream::connect(addr) else {
                    return false;
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                let mut link = GeoLink::new(stream);
                loop {
                    let req = app.pull_request(&key, "", PULL_MAX_RECORDS, PULL_MAX_BYTES);
                    if link.send_request(&req).is_err() {
                        break;
                    }
                    match link.recv() {
                        Ok(Some(GeoFrame::Response(resp))) => {
                            let out = app.apply_pull_response(&key, &resp).expect("apply");
                            if out.applied == 0 {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                app.cursor(&key) == served
            }),
            "the mirror pulled the whole sealed prefix over the real socket (cursor {} of {served})",
            app.cursor(&key)
        );

        // The mirror's records are byte-faithful to the origin's, in order — the accept loop served the
        // committed bytes verbatim off the read plane.
        let recs = app.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served, "every served record landed");
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("o-{i:03}").as_bytes());
        }

        runtime.stop();
    }

    // ---- THE REAL-SOCKET ACCEPT-LOOP PROOF: a LeafPush is accepted + applied ----

    /// Spawn the serve-ACCEPT runtime as a leaf HUB over a real loopback listener, dial it with a real
    /// `TcpStream`, send `LeafPush` frames forwarding a local stream, and prove the hub ACCEPTED + applied
    /// them byte-faithfully — the accept-loop wiring of the leaf hub side over a real socket.
    #[test]
    fn a_real_socket_leaf_push_is_accepted_and_applied() {
        let _guard = crate::cluster::heavy_cluster_test_guard();
        let leaf_dir = tempfile::tempdir().expect("leaf dir");
        let hub_dir = tempfile::tempdir().expect("hub dir");
        let cursor_dir = tempfile::tempdir().expect("cursor dir");
        let (leaf_log, served) = leaked_log_with_served_end(leaf_dir.path(), "L", 35);
        assert!(served > 0);

        // The hub receive log + receiver behind the accept loop.
        let hub_log = Log::open(
            StdFs::new(hub_dir.path().to_path_buf()),
            ManualClock::new(),
            small_config(),
        )
        .expect("hub log opens");
        let receiver = Arc::new(Mutex::new(HubPushReceiver::new(hub_log)));
        let config = CrossClusterServeConfig {
            serve_plane: None,
            hub_receiver: Some(Arc::clone(&receiver)),
        };

        let addr = free_addr();
        let mut runtime =
            CrossClusterServeRuntime::start(addr, config).expect("serve-accept binds");

        // A real client socket drives the leaf LeafPush protocol against the spawned accept loop: read
        // the leaf log's sealed bytes, push them up, advance the durable push cursor to the hub's ack.
        let key = format!("{addr}/orders");
        let mut cursor = LeafPushCursor::open(&StdFs::new(cursor_dir.path().to_path_buf()))
            .expect("push cursor");
        assert!(
            wait_until(Duration::from_secs(10), || {
                let Ok(stream) = TcpStream::connect(addr) else {
                    return false;
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                let mut link = LeafLink::new(stream);
                loop {
                    let plane = leaf_log.read_plane().unwrap();
                    let fwd = LeafForwarder::new(&plane);
                    let Ok(req) = fwd.next_push("orders", cursor.cursor(&key)) else {
                        break;
                    };
                    if req.record_count == 0 {
                        break;
                    }
                    if link.send_request(&req).is_err() {
                        break;
                    }
                    match link.recv() {
                        Ok(Some(LeafFrame::Response(ack))) => {
                            cursor
                                .commit(&key, ack.accepted_through_leaf_offset)
                                .unwrap();
                        }
                        _ => break,
                    }
                }
                cursor.cursor(&key) == served
            }),
            "the leaf wrote its local stream through to the hub over the real socket (cursor {} of {served})",
            cursor.cursor(&key)
        );

        // The hub holds the leaf's records, byte-faithful, in order — the accept loop received + applied
        // each push into the hub's own receive log.
        let r = receiver.lock().unwrap();
        let recs = r.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served);
        for (i, rr) in recs.iter().enumerate() {
            assert_eq!(rr.payload.as_ref(), format!("L-{i:03}").as_bytes());
        }
        drop(r);

        runtime.stop();
    }

    // ---- GATING: no cross-cluster config spawns nothing ----

    /// With NO cross-cluster serve configured, the config is `is_empty()` and the CLI never starts the
    /// runtime — so no listener binds and the broker is byte-for-byte today's. This asserts the gate the
    /// byte-identical guarantee rests on.
    #[test]
    fn no_cross_cluster_config_spawns_no_serve_listener() {
        let empty: CrossClusterServeConfig<StdFs, ManualClock> = CrossClusterServeConfig {
            serve_plane: None,
            hub_receiver: None,
        };
        assert!(
            empty.is_empty(),
            "an empty config reports is_empty so the runtime is never started"
        );

        // A configured-either-way config is NOT empty (the runtime WOULD start).
        let dir = tempfile::tempdir().expect("dir");
        let (origin, _) = leaked_log_with_served_end(dir.path(), "g", 2);
        assert!(
            !serve_only(origin).is_empty(),
            "a configured serve plane is not empty"
        );
    }

    // ---- IDLE: an idle accepted serve connection does ~0 work ----

    /// An accepted connection that sends NOTHING must do ~0 work: the reader parks on the blocking read
    /// (the read timeout the accept loop set), waking only to re-check shutdown — never a busy-spin (the
    /// #726 discipline, re-applied on the accept side). We prove it the way the geo idle test does:
    /// a held-open idle connection completes a stop PROMPTLY (a busy-spinning reader would peg a core and
    /// the listener bind / accept path would still tear down, but the SIGNAL of correctness here is that
    /// the runtime stops quickly while an idle connection is parked, and the connection never received an
    /// unsolicited byte).
    #[test]
    fn an_idle_accepted_serve_connection_does_no_work() {
        let _guard = crate::cluster::heavy_cluster_test_guard();
        let dir = tempfile::tempdir().expect("dir");
        let (origin, _) = leaked_log_with_served_end(dir.path(), "i", 4);

        let addr = free_addr();
        let mut runtime =
            CrossClusterServeRuntime::start(addr, serve_only(origin)).expect("serve-accept binds");

        // Dial and hold the connection OPEN without sending a request. The accept loop accepted it and
        // its reader is now PARKED on the blocking read (no frame to decode).
        let idle = TcpStream::connect(addr).expect("idle client dials");
        idle.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        // The server never speaks first: an idle reader sends ~0 unsolicited bytes. A short read returns
        // a timeout (WouldBlock/TimedOut) or 0 — never server-pushed data.
        let mut buf = [0u8; 64];
        match (&idle).read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!("idle serve connection pushed {n} unsolicited bytes"),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "expected an idle read timeout, got {e:?}"
            ),
        }

        // A stop completes PROMPTLY even while the idle connection is held open: the parked reader is
        // detached and the shutdown-aware listener joins fast (a busy-spinning accept/reader would still
        // join, but a wedged one would not — this bounds the teardown). Generously host-scaled.
        let start = Instant::now();
        runtime.stop();
        let elapsed = start.elapsed();
        assert!(
            elapsed < host_scaled(Duration::from_secs(5)),
            "stop with an idle connection held open completed promptly ({elapsed:?})"
        );
        drop(idle);
    }
}
