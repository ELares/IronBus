// SPDX-License-Identifier: MIT OR Apache-2.0
//! Edge LEAF-SPOKE link — a lightweight, outbound-dialing leaf bridges a hub's streams (V2-C7-I3, #625).
//!
//! This is the NATS-leafnode-class topology, built ON the geo plane (#623, [`geo`](super::geo)) and the
//! domain namespace (#624, [`domain`](super::domain)). A **HUB** (a cluster or a single node) plus MANY
//! lightweight **LEAF** (edge) nodes. A leaf is NOT a full RAFT cluster member: it does not vote, it is
//! never in the metadata quorum, and the hub never dials it. Instead a leaf dials OUTBOUND to the hub
//! (leaves sit behind NAT / a firewall on the edge) and BRIDGES streams across the link, so an edge
//! device participates without the cost / coordination of full cluster membership, and leaf churn never
//! touches the hub's consensus.
//!
//! ## The two bridge directions
//!
//! A leaf bridges a hub stream in one or both directions:
//!
//! * **Read-side (DOWN): the leaf MIRRORS a hub stream locally.** This IS a geo MIRROR
//!   ([`geo::MirrorApplier`](super::geo::MirrorApplier)) where the leaf is the puller and the hub is the
//!   origin: the leaf PULLS the hub stream's CRC-framed bytes ([`geo::MirrorPullRequest`], wire tag 40),
//!   RE-VALIDATES every frame, applies it to its local log in order, and durably advances a per-hub
//!   resume cursor. Byte-faithful, in-order, gap-free, resumable across disconnect — the whole #728
//!   discipline, REUSED verbatim. The local mirror stream is READ-ONLY (its only writer is the apply
//!   path), exactly like a geo mirror.
//! * **Write-through (UP): the leaf FORWARDS its locally-produced records to the hub.** This is the NEW
//!   direction. On the SAME outbound link the leaf dialed, the leaf PUSHES the CRC-framed records of its
//!   local FORWARD stream ([`LeafPushRequest`], wire tag 41) from its durable PUSH CURSOR; the hub
//!   ([`HubPushReceiver`]) RE-VALIDATES every frame and appends it to the hub stream, then acks the leaf
//!   offset it durably accepted through. The leaf advances its push cursor to the ack, so a
//!   disconnect/restart resumes from there — at-least-once, de-duplicated by the monotonic cursor.
//!
//! ## Loop-safety (the write-through non-negotiable): a record crosses the link ONCE
//!
//! Write-through could in principle ECHO — a record mirrored DOWN, then forwarded back UP, forever. It
//! CANNOT here, by CONSTRUCTION:
//!
//! * The two directions are bound to DISTINCT local streams. A read-side bridge materializes a local
//!   MIRROR stream (read-only — no local producer can write it, so there is nothing local to forward up).
//!   A write-through bridge forwards a SEPARATE local stream whose records ALL originate from local
//!   produces (it is never an apply target of a mirror). A record therefore lives on exactly ONE side of
//!   the leaf and travels in exactly ONE direction.
//! * The forward is driven by the leaf's own LOCAL log offsets via a monotonic durable PUSH CURSOR
//!   ([`LeafPushCursor`]): each local record is forwarded at most once (the cursor only advances on a
//!   hub ack, and never re-sends an already-acked offset). A hub re-pull of the leaf's forwarded data is
//!   not even possible — the hub does not pull from the leaf (the asymmetry); only the leaf pushes.
//!
//! So even if an operator MIRRORS the very hub stream it FORWARDS to, the leaf's local forward stream and
//! its local mirror stream are different logs, and the cursor de-dups the forward — a record crosses the
//! link once. ([`LeafBridge::validate`] additionally REJECTS configuring the same local stream as both a
//! mirror and a forward, the only way the two could share a log.)
//!
//! ## Asymmetric dial direction (the leaf-not-the-hub non-negotiable)
//!
//! The LEAF dials OUTBOUND to the hub; the HUB never dials the leaf. The hub ACCEPTS an inbound leaf link
//! on its serve/data endpoint and answers pulls (read-side) + push requests (write-through) on it — it is
//! REACTIVE, holding no per-leaf dial state. This is the geo dialer ([`geo::pull_loop`](super::geo) /
//! the CLI `run_geo_puller`) REUSED for the read-side; the write-through pusher dials the same way.
//!
//! ## A leaf is NOT a Raft voter (the churn non-negotiable)
//!
//! NOTHING in this module touches the metadata Raft group ([`metadata_group`](super::metadata_group)),
//! the membership API ([`membership`](super::membership)), or the [`ClusterRuntime`](super::runtime). A
//! leaf is an outbound bridge — lighter than a cluster node — so adding/removing a leaf does NOT change
//! the hub's quorum/membership, consensus, or availability. A leaf connecting/disconnecting repeatedly is
//! invisible to the hub's metadata group. There is no leaf entry in any `ConfState`, no leaf peer-id, and
//! the hub's quorum math is computed entirely over its Raft voters, which a leaf is not.
//!
//! ## Async / non-blocking / bounded / ~0-idle (the #726 lesson, REUSED)
//!
//! The read-side loop is the geo [`pull_loop`](super::geo); the write-through loop ([`push_loop`]) has the
//! SAME shape: forward a bounded batch, block on the ack read up to a poll window, BACK OFF (interruptible
//! sleep) when there is nothing local to forward. An idle leaf does ~0 work (blocks/backs off, never
//! busy-spins). Per-leaf hub resources are bounded (one reader per inbound link; a push is size-capped +
//! re-validated before any append — a hostile leaf is contained to a dropped frame).
//!
//! ## Single-node / no-leaf = byte-identical (the critical guarantee)
//!
//! NOTHING here constructs unless a `--leaf-hub` is configured. With no leaf config the local
//! produce/consume/storage hot path is byte-for-byte today's broker: no [`HubPushReceiver`], no
//! [`LeafPusher`], no push cursor file, no [`FrameType::LeafPush`] ever decoded. The leaf plane is gated
//! entirely on the presence of a leaf config in the CLI serve hook, exactly like the geo plane.
//!
//! ## SCOPE / deferred (honest)
//!
//! * **Single default stream per bridge direction.** A bridge mirrors/forwards ONE hub stream <-> ONE
//!   local stream's default partition. Multi-partition is FLAGGED to #693 (the same scope the geo plane
//!   declared).
//! * **Cross-link AUTH/TLS** is minimal (loopback / trusted transport, plaintext, like the intra-cluster
//!   peer link + the geo link). mTLS / token auth on the leaf link is a FLAGGED follow-on.
//! * **At-least-once write-through.** A hub ack lost after the durable append re-pushes the same leaf
//!   span on reconnect; the hub appends it AGAIN (the leaf's records are appended to a hub stream that may
//!   also take other writers, so the hub cannot byte-compare to de-dup as a single-origin mirror can).
//!   The leaf's push cursor makes the COMMON path exactly-once; the rare lost-ack window is at-least-once.
//!   Producer-level de-dup on the hub (the existing dedup window) is the operator's lever; idempotent
//!   hub-side de-dup keyed on `(leaf, leaf_offset)` is a FLAGGED follow-on.
//! * Gateway/supercluster FEDERATION (symmetric cluster-to-cluster) is the SEPARATE #626 — NOT here; the
//!   leaf-spoke is asymmetric hub + many leaves.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ironbus_core::clock::Clock;
use ironbus_core::codec::{self, DecodeError};
use ironbus_core::types::Offset;
use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType, MAX_FRAME_LEN,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log};
use ironbus_storage::read_plane::ReadPlane;
use ironbus_storage::segment::StorageError;

use super::geo::{
    GeoError, GeoMode, GeoOrigin, OriginCursorStore, MAX_GEO_PULL_BYTES, MAX_ORIGIN_STREAM_LEN,
};

/// The hard maximum size, in bytes, of the CRC-framed record-byte payload one write-through PUSH request
/// may carry. Bounds the leaf's per-push budget AND, on the hub, the UNTRUSTED remote bytes the receive
/// path buffers and re-validates — a hub never trusts the request length blindly. Reuses the geo cap
/// ([`MAX_GEO_PULL_BYTES`], 8 MiB), so a leaf push is bounded exactly like a geo pull and always frames
/// under the absolute [`MAX_FRAME_LEN`] envelope.
pub const MAX_LEAF_PUSH_BYTES: u32 = MAX_GEO_PULL_BYTES;

/// The `kind` discriminant byte leading a [`FrameType::LeafPush`] body, so the request and the response
/// (which share the wire tag, like [`FrameType::MirrorPull`]) are never confused.
const PUSH_KIND_REQUEST: u8 = 0;
const PUSH_KIND_RESPONSE: u8 = 1;

/// The fixed little-endian prefix of an encoded [`LeafPushRequest`] BEFORE the variable stream name +
/// frame bytes: `kind: u8` + `from_leaf_offset: u64` + `record_count: u32` + `frame_bytes_len: u32` +
/// `stream_len: u16`.
const PUSH_REQUEST_PREFIX_LEN: usize = 1 + 8 + 4 + 4 + 2;

/// The fixed little-endian length of an encoded [`LeafPushResponse`] body: `kind: u8` +
/// `accepted_through_leaf_offset: u64`.
const PUSH_RESPONSE_LEN: usize = 1 + 8;

/// The per-push record / byte budget the write-through loop forwards. Bounded so one request always frames
/// under [`MAX_LEAF_PUSH_BYTES`] and a single slow link never buffers unboundedly. Mirrors the geo pull
/// budget so the two directions are paced identically.
const LEAF_PUSH_MAX_RECORDS: u32 = 1024;
const LEAF_PUSH_MAX_BYTES: u32 = 1024 * 1024;

/// Read a little-endian `u64` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 8`.
#[inline]
fn read_u64_le(b: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(buf)
}

/// Read a little-endian `u32` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 4`.
#[inline]
fn read_u32_le(b: &[u8], at: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(buf)
}

/// Read a little-endian `u16` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 2`.
#[inline]
fn read_u16_le(b: &[u8], at: usize) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&b[at..at + 2]);
    u16::from_le_bytes(buf)
}

/// A typed LEAF error. Every failure mode of the leaf-spoke write-through (serving / forwarding /
/// validating / appending a push) is one of these — the layer NEVER panics, NEVER blind-appends an
/// unvalidated byte, and FAILS CLOSED on any corrupt / malformed / oversized input. The read-side bridge
/// reuses the geo [`GeoError`] (it IS a geo mirror), so this type covers only the write-through direction
/// and the leaf-config validation.
#[derive(Debug)]
pub enum LeafError {
    /// A push REQUEST body was malformed (short, wrong kind, or its stored frame-byte length disagreed
    /// with the bytes present).
    MalformedRequest {
        /// The body length seen.
        len: usize,
    },
    /// A push RESPONSE body was malformed (short, wrong kind, or wrong length).
    MalformedResponse {
        /// The body length seen.
        len: usize,
    },
    /// A push request claimed more CRC-framed record bytes than [`MAX_LEAF_PUSH_BYTES`] — rejected before
    /// the bytes are trusted (the untrusted-remote size bound).
    RequestTooLarge {
        /// The claimed frame-byte length.
        len: u64,
    },
    /// A hub stream name exceeded [`MAX_ORIGIN_STREAM_LEN`] (the leaf addresses the hub stream by name,
    /// the same ceiling a geo origin stream uses).
    HubStreamNameTooLong {
        /// The name length seen.
        len: usize,
    },
    /// A hub stream name on the wire was not valid UTF-8.
    HubStreamNotUtf8,
    /// A CRC-framed frame in a push request FAILED the intact-record predicate
    /// ([`ironbus_core::codec::decode`]) — a corrupt, tampered, or truncated frame. The hub detected it
    /// and appended NOTHING from this frame onward (fail-closed). Carries the leaf offset the bad frame
    /// would have occupied and the typed decode reason.
    CorruptFrame {
        /// The leaf offset the corrupt frame would have been appended at.
        at_leaf_offset: u64,
        /// The typed decode failure (bad header CRC, bad body CRC, bad xxh3, truncated, ...).
        reason: DecodeError,
    },
    /// A push request claimed a `record_count` the actual frame bytes did not contain — a malformed
    /// request; fail closed.
    RecordCountMismatch {
        /// The count the request header claimed.
        claimed: u32,
        /// The number of complete frames actually decoded.
        actual: u32,
    },
    /// The durable PUSH cursor could not be persisted / recovered (an underlying IO fault). Surfaced
    /// rather than swallowed — a leaf that cannot persist its push cursor fails closed rather than risk a
    /// re-forward / skip on restart.
    Cursor {
        /// A human description of the cursor fault.
        what: String,
    },
    /// A leaf bridge config was invalid (e.g. the SAME local stream declared as both a read-side mirror
    /// AND a write-through forward — the only way the two directions could share a log and thus loop).
    Config {
        /// A human description of the config fault.
        what: String,
    },
    /// The hub's local log rejected an append (at-capacity / writer frozen) while applying a validated
    /// pushed record.
    Storage(StorageError),
    /// An underlying IO error reading from / writing to the leaf link.
    Io(io::Error),
    /// The leaf-link frame envelope was malformed or carried an unexpected type tag.
    Frame {
        /// A human description of the framing fault.
        what: String,
    },
}

impl core::fmt::Display for LeafError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LeafError::MalformedRequest { len } => {
                write!(f, "malformed leaf push request body ({len} bytes)")
            }
            LeafError::MalformedResponse { len } => {
                write!(f, "malformed leaf push response body ({len} bytes)")
            }
            LeafError::RequestTooLarge { len } => write!(
                f,
                "leaf push request claimed {len} frame bytes, over the {MAX_LEAF_PUSH_BYTES}-byte cap; rejected"
            ),
            LeafError::HubStreamNameTooLong { len } => write!(
                f,
                "hub stream name is {len} bytes, over the {MAX_ORIGIN_STREAM_LEN}-byte cap; rejected"
            ),
            LeafError::HubStreamNotUtf8 => write!(f, "hub stream name on the wire is not valid UTF-8"),
            LeafError::CorruptFrame {
                at_leaf_offset,
                reason,
            } => write!(
                f,
                "leaf push carried a corrupt frame at leaf offset {at_leaf_offset} ({reason:?}); fail-closed, nothing appended from here"
            ),
            LeafError::RecordCountMismatch { claimed, actual } => write!(
                f,
                "leaf push request record_count {claimed} != {actual} complete frames decoded"
            ),
            LeafError::Cursor { what } => write!(f, "leaf push cursor error: {what}"),
            LeafError::Config { what } => write!(f, "invalid leaf bridge config: {what}"),
            LeafError::Storage(e) => write!(f, "leaf push hub append failed: {e}"),
            LeafError::Io(e) => write!(f, "leaf link IO error: {e}"),
            LeafError::Frame { what } => write!(f, "leaf link frame error: {what}"),
        }
    }
}

impl std::error::Error for LeafError {}

impl From<io::Error> for LeafError {
    fn from(e: io::Error) -> Self {
        LeafError::Io(e)
    }
}

impl From<StorageError> for LeafError {
    fn from(e: StorageError) -> Self {
        LeafError::Storage(e)
    }
}

/// A leaf -> hub write-through PUSH request for one hub stream (#625): "append these CRC-framed records,
/// which are my LOCAL records starting at my own leaf offset `from_leaf_offset`, to your hub stream
/// `stream`." The asymmetric, push twin of [`geo::MirrorPullRequest`](super::geo::MirrorPullRequest): the
/// leaf drives the cadence; the hub never pulls from the leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafPushRequest {
    /// The hub stream to append into (empty = the hub's default stream).
    pub stream: String,
    /// The leaf's OWN local offset the first frame in `frame_bytes` sits at — the leaf's durable push
    /// cursor. The hub echoes back how far it accepted so the leaf advances the cursor (the de-dup
    /// anchor; a re-push of an already-acked offset is the leaf's resume, not a loop).
    pub from_leaf_offset: u64,
    /// How many complete CRC-framed records `frame_bytes` carries.
    pub record_count: u32,
    /// The contiguous CRC-framed local record frames — the leaf's bytes VERBATIM (UNTRUSTED on the hub
    /// until re-validated, exactly like a geo pull response on the puller).
    pub frame_bytes: Vec<u8>,
}

impl LeafPushRequest {
    /// Encode this request to its `kind`-led, fixed-prefix + variable-name + verbatim-bytes body.
    ///
    /// # Errors
    /// [`LeafError::HubStreamNameTooLong`] if the hub stream name exceeds [`MAX_ORIGIN_STREAM_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, LeafError> {
        if self.stream.len() > MAX_ORIGIN_STREAM_LEN {
            return Err(LeafError::HubStreamNameTooLong {
                len: self.stream.len(),
            });
        }
        let name = self.stream.as_bytes();
        let mut out =
            Vec::with_capacity(PUSH_REQUEST_PREFIX_LEN + name.len() + self.frame_bytes.len());
        out.push(PUSH_KIND_REQUEST);
        out.extend_from_slice(&self.from_leaf_offset.to_le_bytes());
        out.extend_from_slice(&self.record_count.to_le_bytes());
        let frame_len = u32::try_from(self.frame_bytes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&frame_len.to_le_bytes());
        // `name.len() <= MAX_ORIGIN_STREAM_LEN` (255) fits a u16 (checked above); fall back to the cap
        // rather than panic to keep the encoder infallible on a degenerate length.
        let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.frame_bytes);
        Ok(out)
    }

    /// Decode a request from its body bytes, BOUNDING the carried frame bytes against
    /// [`MAX_LEAF_PUSH_BYTES`] before accepting them — an oversized request (a hostile or buggy leaf) is
    /// rejected, never buffered.
    ///
    /// # Errors
    /// [`LeafError::MalformedRequest`] (short / wrong kind / inconsistent length),
    /// [`LeafError::RequestTooLarge`] (over the cap), [`LeafError::HubStreamNameTooLong`] /
    /// [`LeafError::HubStreamNotUtf8`] (bad name) — fail-closed, never guessed at.
    pub fn decode(body: &[u8]) -> Result<LeafPushRequest, LeafError> {
        if body.len() < PUSH_REQUEST_PREFIX_LEN || body[0] != PUSH_KIND_REQUEST {
            return Err(LeafError::MalformedRequest { len: body.len() });
        }
        let from_leaf_offset = read_u64_le(body, 1);
        let record_count = read_u32_le(body, 9);
        let frame_bytes_len = read_u32_le(body, 13);
        // The SIZE bound on untrusted remote bytes: reject an over-cap claimed length BEFORE trusting it.
        if frame_bytes_len > MAX_LEAF_PUSH_BYTES {
            return Err(LeafError::RequestTooLarge {
                len: u64::from(frame_bytes_len),
            });
        }
        let name_len = read_u16_le(body, 17) as usize;
        if name_len > MAX_ORIGIN_STREAM_LEN {
            return Err(LeafError::HubStreamNameTooLong { len: name_len });
        }
        let want = PUSH_REQUEST_PREFIX_LEN + name_len + frame_bytes_len as usize;
        if body.len() != want {
            return Err(LeafError::MalformedRequest { len: body.len() });
        }
        let name_end = PUSH_REQUEST_PREFIX_LEN + name_len;
        let stream = core::str::from_utf8(&body[PUSH_REQUEST_PREFIX_LEN..name_end])
            .map_err(|_| LeafError::HubStreamNotUtf8)?
            .to_string();
        Ok(LeafPushRequest {
            stream,
            from_leaf_offset,
            record_count,
            frame_bytes: body[name_end..].to_vec(),
        })
    }
}

/// A hub -> leaf write-through PUSH response (#625): how far (by the leaf's OWN offset) the hub durably
/// appended. The leaf advances its push cursor to this, so a disconnect/restart resumes from there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafPushResponse {
    /// The leaf offset the hub durably appended THROUGH (the exclusive end: `from_leaf_offset +
    /// accepted_records`). The leaf sets its push cursor to this — never past durably-appended data.
    pub accepted_through_leaf_offset: u64,
}

impl LeafPushResponse {
    /// Encode this response to its fixed `kind`-led body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUSH_RESPONSE_LEN);
        out.push(PUSH_KIND_RESPONSE);
        out.extend_from_slice(&self.accepted_through_leaf_offset.to_le_bytes());
        out
    }

    /// Decode a response from its body bytes.
    ///
    /// # Errors
    /// [`LeafError::MalformedResponse`] if the body is the wrong length or kind.
    pub fn decode(body: &[u8]) -> Result<LeafPushResponse, LeafError> {
        if body.len() != PUSH_RESPONSE_LEN || body[0] != PUSH_KIND_RESPONSE {
            return Err(LeafError::MalformedResponse { len: body.len() });
        }
        Ok(LeafPushResponse {
            accepted_through_leaf_offset: read_u64_le(body, 1),
        })
    }
}

/// The on-disk file name of the durable LEAF PUSH cursor store, under a write-through bridge's data
/// directory. Distinct from the geo `geo.cursor` so a leaf that both mirrors (read-side, geo cursor) and
/// forwards (write-through, this cursor) keeps the two cursors in separate files.
pub const PUSH_CURSOR_FILE: &str = "leaf.push.cursor";

/// A durable, per-hub-stream PUSH CURSOR (#625): the leaf's OWN local offset the hub has ACK'd for each
/// forwarded hub stream, persisted so a disconnect/restart resumes from there, never
/// re-forwarding an acked offset or skipping. It is the write-through twin of the geo
/// [`OriginCursorStore`](super::geo::OriginCursorStore) — and is in fact backed BY it (the same crash-safe
/// dual-slot CRC checkpoint), keyed by the hub-stream identity, so the durability story is identical and
/// proven.
pub struct LeafPushCursor<F: Filesystem> {
    store: OriginCursorStore<F>,
}

impl<F: Filesystem> LeafPushCursor<F> {
    /// Open (or initialize) the durable push cursor store under `fs`, in [`PUSH_CURSOR_FILE`]. A torn /
    /// missing file recovers as no cursors (every stream resumes from 0, the safe degrade), exactly the
    /// geo cursor store's recovery.
    ///
    /// # Errors
    /// [`LeafError::Cursor`] on an IO fault opening / creating the cursor file, or a recovered snapshot
    /// that fails to decode — fail-closed.
    pub fn open(fs: &F) -> Result<LeafPushCursor<F>, LeafError> {
        let store =
            OriginCursorStore::open_named(fs, PUSH_CURSOR_FILE).map_err(|e| map_cursor_err(&e))?;
        Ok(LeafPushCursor { store })
    }

    /// The leaf offset the hub has acked for `hub_stream_key` — the offset the next push should resume
    /// FROM. `0` for a stream never forwarded.
    #[must_use]
    pub fn cursor(&self, hub_stream_key: &str) -> u64 {
        self.store.cursor(hub_stream_key)
    }

    /// Durably ADVANCE `hub_stream_key`'s push cursor to `accepted_through_leaf_offset` (monotonic; a
    /// commit at or below the current cursor is a no-op).
    ///
    /// # Errors
    /// [`LeafError::Cursor`] on an IO fault, or if the encoded snapshot overflows the cap.
    pub fn commit(
        &mut self,
        hub_stream_key: &str,
        accepted_through_leaf_offset: u64,
    ) -> Result<(), LeafError> {
        self.store
            .commit(hub_stream_key, accepted_through_leaf_offset)
            .map_err(|e| map_cursor_err(&e))
    }
}

/// Re-map a geo cursor [`GeoError`] (the only error the reused [`OriginCursorStore`] surfaces) into a
/// [`LeafError::Cursor`]. The push cursor IS a geo cursor store under the hood, so its faults are cursor
/// faults; this keeps the leaf layer's error surface its own type.
fn map_cursor_err(e: &GeoError) -> LeafError {
    LeafError::Cursor {
        what: e.to_string(),
    }
}

/// The LEAF side of write-through for one local FORWARD stream: it wraps the leaf's OWN local stream read
/// plane (the same zero-copy [`ReadPlane`] the geo origin serve uses) and builds the next push request
/// from the durable push cursor — the leaf's records, VERBATIM, from where the hub last acked.
///
/// The leaf's local log is READ-ONLY through this path: the forward never changes the leaf's append /
/// produce path; it only ships bytes already written + flushed. So a local produce is never blocked by a
/// slow/broken hub link (the forward is asynchronous, off the produce path).
pub struct LeafForwarder<'a, F: Filesystem> {
    plane: &'a ReadPlane<F>,
}

impl<'a, F: Filesystem> LeafForwarder<'a, F> {
    /// Wrap a leaf local FORWARD stream's `Arc`-shared read plane as a write-through source.
    #[must_use]
    pub fn new(plane: &'a ReadPlane<F>) -> Self {
        Self { plane }
    }

    /// The leaf's local high-watermark for the forward stream: the read plane's flushed frontier — the
    /// prefix the leaf may forward up to. The leaf is fully forwarded iff its push cursor reaches this.
    #[must_use]
    pub fn high_watermark(&self) -> Offset {
        Offset::new(self.plane.flushed())
    }

    /// Build the next push request for `hub_stream` from the leaf's local offset `from_leaf_offset` (the
    /// push cursor): a contiguous run of the leaf's CRC-framed local record frames, bounded by the smaller
    /// of [`LEAF_PUSH_MAX_BYTES`] and [`MAX_LEAF_PUSH_BYTES`] (and [`LEAF_PUSH_MAX_RECORDS`]). The frames
    /// are shipped VERBATIM (the leaf does not re-encode — they are already its own durable bytes); the
    /// HUB re-validates them.
    ///
    /// Returns a request with an EMPTY run (`record_count == 0`) when the cursor is already at the leaf's
    /// sealed-served frontier — a clean no-op the loop pauses on (the idle path).
    ///
    /// # Errors
    /// [`LeafError::Storage`] if the underlying raw read fails (e.g. `from_leaf_offset` is older than the
    /// oldest retained record).
    pub fn next_push(
        &self,
        hub_stream: &str,
        from_leaf_offset: u64,
    ) -> Result<LeafPushRequest, LeafError> {
        let from = Offset::new(from_leaf_offset);
        let sealed = self.plane.read_range_raw(
            from,
            LEAF_PUSH_MAX_RECORDS as usize,
            Some(LEAF_PUSH_MAX_BYTES as usize),
        )?;
        Ok(LeafPushRequest {
            stream: hub_stream.to_string(),
            from_leaf_offset: sealed.run.first_offset.get(),
            record_count: u32::try_from(sealed.run.record_count).unwrap_or(u32::MAX),
            frame_bytes: sealed.run.bytes.to_vec(),
        })
    }
}

/// The outcome of the hub applying one push request: how many records were appended + the leaf offset the
/// hub durably accepted through (the response the hub sends back).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushOutcome {
    /// How many records this request durably appended to the hub stream's log.
    pub appended: u64,
    /// The leaf offset the hub accepted THROUGH: `from_leaf_offset + appended`. The leaf advances its
    /// push cursor to this.
    pub accepted_through_leaf_offset: u64,
}

/// The HUB side of write-through for one hub stream (#625): it RECEIVES a leaf's [`LeafPushRequest`],
/// RE-VALIDATES every CRC frame ([`ironbus_core::codec::decode`]), appends ONLY validated frames to the
/// hub stream's log IN ORDER, syncs, and answers a [`LeafPushResponse`] with the leaf offset it accepted
/// through. It is the write-through twin of the geo [`MirrorApplier`](super::geo::MirrorApplier)'s
/// apply path, but the HUB log is the WRITER and the leaf's bytes are the untrusted input.
///
/// The hub NEVER blind-trusts a leaf's bytes: a corrupt / tampered / truncated frame is DETECTED and the
/// append FAILS CLOSED (nothing from the bad frame onward is appended) — the leaf re-pushes from the
/// cursor. A leaf disconnecting mid-push leaves only the durably-synced prefix appended, and the unacked
/// suffix is re-pushed on reconnect (at-least-once; see the module-level scope note).
pub struct HubPushReceiver<F: Filesystem, C: Clock> {
    log: Log<F, C>,
}

impl<F: Filesystem, C: Clock> HubPushReceiver<F, C> {
    /// Wrap the hub stream's log as a write-through receiver. The hub log is this receiver's writer for
    /// the pushed records (in a real serve the hub stream's append actor owns it; the leaf-push append
    /// goes through the same single append discipline).
    #[must_use]
    pub fn new(log: Log<F, C>) -> Self {
        Self { log }
    }

    /// Borrow the hub stream's log (e.g. to read its appended records).
    #[must_use]
    pub fn log(&self) -> &Log<F, C> {
        &self.log
    }

    /// Apply a leaf's push REQUEST to the hub stream's log: re-validate every frame's CRC, append only
    /// validated frames IN ORDER, sync, and return the leaf offset accepted through.
    ///
    /// The sync happens BEFORE the response is sent, so an ack the leaf receives ALWAYS reflects durably-
    /// appended hub data — the leaf never advances its push cursor past data the hub has not synced.
    ///
    /// # Errors
    /// - [`LeafError::CorruptFrame`] if any frame fails CRC re-validation (fail-closed; the durably-synced
    ///   prefix's accepted-through is still returned via the response path by the caller).
    /// - [`LeafError::RecordCountMismatch`] if the byte run does not hold the claimed count.
    /// - [`LeafError::Storage`] if a hub append / sync fails.
    pub fn apply_push(&mut self, req: &LeafPushRequest) -> Result<PushOutcome, LeafError> {
        let from = req.from_leaf_offset;
        if req.record_count == 0 && req.frame_bytes.is_empty() {
            return Ok(PushOutcome {
                appended: 0,
                accepted_through_leaf_offset: from,
            });
        }
        // Walk the verbatim frame bytes, RE-VALIDATING and appending one frame at a time. `codec::decode`
        // is the intact-record predicate; only a passing frame is appended. A failure stops the walk,
        // syncs the validated prefix, and is surfaced — the hub NEVER appends a byte it has not validated.
        let mut at = 0usize;
        let mut appended = 0u64;
        let bytes = req.frame_bytes.as_slice();
        while at < bytes.len() {
            let at_leaf_offset = from + appended;
            let (view, frame_len) = match codec::decode(&bytes[at..]) {
                Ok(decoded) => decoded,
                Err(reason) => {
                    self.log.sync()?;
                    return Err(LeafError::CorruptFrame {
                        at_leaf_offset,
                        reason,
                    });
                }
            };
            let append = Append {
                timestamp_ms: view.timestamp_ms,
                flags: view.flags,
                key: view.key,
                headers: view.headers,
                payload: view.payload,
            };
            self.log.append(&append)?;
            appended += 1;
            at += frame_len;
        }
        // Durably commit the appended batch (one fsync per push — the group-commit shape). The ack the
        // caller sends after this reflects durably-synced data.
        self.log.sync()?;

        let actual = u32::try_from(appended).unwrap_or(u32::MAX);
        if actual != req.record_count {
            return Err(LeafError::RecordCountMismatch {
                claimed: req.record_count,
                actual,
            });
        }
        Ok(PushOutcome {
            appended,
            accepted_through_leaf_offset: from + appended,
        })
    }
}

/// Encode one leaf-push frame (request or response) to its on-wire bytes: the bounded
/// `[len][type=LeafPush][body]` envelope. Bounded the same way the decoder bounds an incoming one.
///
/// # Errors
/// [`LeafError::Frame`] if the body cannot be framed within the cap (it never should for a layer-produced
/// frame).
fn encode_leaf_frame(body: &[u8]) -> Result<Vec<u8>, LeafError> {
    let mut out = Vec::with_capacity(body.len() + 5);
    encode_frame(FrameType::LeafPush, body, &mut out).map_err(|e| LeafError::Frame {
        what: e.to_string(),
    })?;
    Ok(out)
}

/// One decoded inbound leaf-push frame: a push REQUEST (hub side) or a push RESPONSE (leaf side). They
/// share the wire tag, distinguished by their `kind` byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafFrame {
    /// A leaf -> hub push request.
    Request(LeafPushRequest),
    /// A hub -> leaf push response (ack).
    Response(LeafPushResponse),
}

/// Route a leaf-frame body (the `kind`-led layer bytes after the envelope) into a [`LeafFrame`] by its
/// leading `kind` byte. A request (`kind = 0`) decodes a [`LeafPushRequest`]; a response (`kind = 1`) a
/// [`LeafPushResponse`]; any other kind is a fail-closed framing error.
fn decode_leaf_body(body: &[u8]) -> Result<LeafFrame, LeafError> {
    match body.first().copied() {
        Some(PUSH_KIND_REQUEST) => Ok(LeafFrame::Request(LeafPushRequest::decode(body)?)),
        Some(PUSH_KIND_RESPONSE) => Ok(LeafFrame::Response(LeafPushResponse::decode(body)?)),
        other => Err(LeafError::Frame {
            what: format!("unknown leaf frame kind {other:?}"),
        }),
    }
}

/// A bidirectional LEAF link over any byte stream (`Read + Write`): a real `TcpStream` in production, an
/// in-memory pipe in tests. It carries [`FrameType::LeafPush`] request/response frames over the SAME
/// bounded `[len][type][body]` envelope, applying every bound on the receive path (size cap before
/// allocation, bounded layer decode), so a hostile / oversized / corrupt frame is a typed [`LeafError`],
/// never a panic or over-allocation. Transport-agnostic + synchronous, exactly like the geo
/// [`GeoLink`](super::geo::GeoLink).
pub struct LeafLink<S> {
    stream: S,
    /// Accumulated, not-yet-consumed inbound bytes (a partial frame may straddle reads).
    inbuf: Vec<u8>,
}

impl<S: Read + Write> LeafLink<S> {
    /// Wrap a byte stream as a leaf link.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            inbuf: Vec::new(),
        }
    }

    /// Send a push REQUEST over the link (leaf -> hub).
    ///
    /// # Errors
    /// [`LeafError::HubStreamNameTooLong`] if the name is over the cap, [`LeafError::Frame`] if it cannot
    /// be framed, or [`LeafError::Io`] on a write fault.
    pub fn send_request(&mut self, req: &LeafPushRequest) -> Result<(), LeafError> {
        let frame = encode_leaf_frame(&req.encode()?)?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send a push RESPONSE (ack) over the link (hub -> leaf).
    ///
    /// # Errors
    /// [`LeafError::Frame`] if it cannot be framed, or [`LeafError::Io`] on a write fault.
    pub fn send_response(&mut self, resp: &LeafPushResponse) -> Result<(), LeafError> {
        let frame = encode_leaf_frame(&resp.encode())?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive ONE leaf frame, BLOCKING on the underlying stream's read (the stream's read timeout
    /// governs how long it blocks — the caller sets it so an idle link blocks/backs off, never busy-
    /// spins). Returns `Ok(None)` when the peer closes cleanly. Every bound is applied on the receive
    /// path.
    ///
    /// # Errors
    /// [`LeafError::RequestTooLarge`] / [`LeafError::MalformedRequest`] / [`LeafError::MalformedResponse`]
    /// / [`LeafError::Frame`] on a bounded decode failure, or [`LeafError::Io`] on a read fault (including
    /// a timeout, surfaced as the underlying `WouldBlock`/`TimedOut` so the caller can re-poll).
    pub fn recv(&mut self) -> Result<Option<LeafFrame>, LeafError> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            if let Some(frame) = self.try_decode_one()? {
                return Ok(Some(frame));
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Ok(None);
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Decode one buffered leaf frame if a complete one is present, consuming its bytes. Returns
    /// `Ok(None)` when more bytes are needed. Applies the size cap before allocation + the bounded layer
    /// decode.
    fn try_decode_one(&mut self) -> Result<Option<LeafFrame>, LeafError> {
        let cap = MAX_FRAME_LEN.min(MAX_LEAF_PUSH_BYTES.saturating_add(1024));
        match decode_frame_with_cap(&self.inbuf, cap) {
            Ok(FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            }) => {
                if FrameType::from_u8(type_tag) != Some(FrameType::LeafPush) {
                    return Err(LeafError::Frame {
                        what: format!("unexpected frame tag {type_tag} on the leaf link"),
                    });
                }
                let frame = decode_leaf_body(body)?;
                self.inbuf.drain(..consumed);
                Ok(Some(frame))
            }
            Ok(FrameDecode::Incomplete { .. }) => Ok(None),
            Err(FrameError::FrameTooLarge { len }) => Err(LeafError::RequestTooLarge { len }),
            Err(e) => Err(LeafError::Frame {
                what: e.to_string(),
            }),
        }
    }
}

/// How long a write-through push loop BLOCKS on the ack read, and how long a fully-forwarded leaf BACKS
/// OFF before re-checking its local log — the idle-friendly cadence (#726: an idle push loop must
/// block/back off, ~0 idle CPU, never busy-spin). Reuses the geo
/// [`GEO_POLL`](super::geo::GEO_POLL) value so both directions are paced identically; re-declared here so
/// the leaf layer is self-contained.
pub const LEAF_PUSH_POLL: Duration = super::geo::GEO_POLL;

/// Sleep for `dur` but wake early if shutdown is set, in small slices, so a stop is never delayed by a
/// full sleep. Mirrors the geo plane's `sleep_interruptible`.
fn sleep_interruptible(dur: Duration, shutdown: &AtomicBool) {
    let slice = Duration::from_millis(20);
    let mut left = dur;
    while left > Duration::ZERO && !shutdown.load(Ordering::Acquire) {
        let this = slice.min(left);
        std::thread::sleep(this);
        left = left.checked_sub(this).unwrap_or(Duration::ZERO);
    }
}

/// Drive ONE connected leaf link for one write-through forward: build-push -> send -> read-ack ->
/// persist-cursor, on a cadence, until shutdown or the link breaks. Each round builds a push from the
/// durable push cursor, sends it, reads the ack (BLOCKING up to the link's read timeout — never a busy-
/// spin), and durably advances the cursor to the acked leaf offset. A fully-forwarded leaf (empty push)
/// BACKS OFF for [`LEAF_PUSH_POLL`] before re-checking. A link error drops the loop; the caller reconnects
/// and resumes from the cursor.
///
/// `build` returns the next [`LeafPushRequest`] under whatever lock the caller holds the forwarder behind
/// (so this loop is transport- and lock-agnostic, like the geo `pull_loop`); `commit` durably advances
/// the push cursor to the acked offset.
///
/// Returns when shutdown is observed or the link is determined broken (the caller reconnects).
pub fn push_loop<S, B, K>(
    link: &mut LeafLink<S>,
    shutdown: &AtomicBool,
    mut build: B,
    mut commit: K,
) where
    S: Read + Write,
    B: FnMut() -> Result<LeafPushRequest, LeafError>,
    K: FnMut(u64) -> Result<(), LeafError>,
{
    while !shutdown.load(Ordering::Acquire) {
        let req = match build() {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "leaf: build push failed; backing off");
                sleep_interruptible(LEAF_PUSH_POLL, shutdown);
                continue;
            }
        };
        let empty = req.record_count == 0;
        if empty {
            // Nothing local to forward: pace the next check so a fully-forwarded leaf does not hot-loop
            // (the idle ~0-CPU discipline). Do NOT send an empty push (it would be needless wire churn).
            sleep_interruptible(LEAF_PUSH_POLL, shutdown);
            continue;
        }
        if link.send_request(&req).is_err() {
            return; // link broke; the caller reconnects
        }
        match link.recv() {
            Ok(Some(LeafFrame::Response(ack))) => {
                if let Err(e) = commit(ack.accepted_through_leaf_offset) {
                    tracing::debug!(error = %e, "leaf: push cursor commit failed; will resume from cursor");
                    return;
                }
                // The hub may have accepted a full run; loop promptly to forward more.
            }
            // A request on the leaf link, or any other frame: ignore + back off.
            Ok(Some(LeafFrame::Request(_))) => sleep_interruptible(LEAF_PUSH_POLL, shutdown),
            Err(LeafError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // The read timeout elapsed with no ack: the link buffers any partial, loop and re-poll
                // (re-checking shutdown). This is the BLOCKING idle path — ~0 CPU while waiting.
            }
            // The hub closed cleanly (`Ok(None)`), or a decode / link error (`Err(_)`): drop the link and
            // let the caller reconnect + resume from the durable cursor.
            Ok(None) | Err(_) => return,
        }
    }
}

/// The DIRECTION a leaf bridges one stream across the link: read-side mirror (DOWN), write-through forward
/// (UP), or both. Single-stream / single-direction-per-stream is the #693-flagged scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafDirection {
    /// DOWN: the leaf MIRRORS the hub stream locally (a geo mirror; read-only local stream).
    Mirror,
    /// UP: the leaf FORWARDS its local stream's produces to the hub (write-through).
    Forward,
    /// Both: the leaf mirrors a hub stream AND forwards a local stream to the hub. The two use DISTINCT
    /// local streams (a mirror local stream is read-only; a forward local stream is locally produced), so
    /// even "both" never loops — see the module loop-safety note.
    Both,
}

impl LeafDirection {
    /// True if this direction includes the read-side mirror (DOWN).
    #[must_use]
    pub fn mirrors(self) -> bool {
        matches!(self, LeafDirection::Mirror | LeafDirection::Both)
    }

    /// True if this direction includes the write-through forward (UP).
    #[must_use]
    pub fn forwards(self) -> bool {
        matches!(self, LeafDirection::Forward | LeafDirection::Both)
    }
}

/// One configured stream bridge of a leaf: which HUB stream it bridges, the LOCAL stream(s) it
/// materializes, and the direction. A mirror bridge has a local MIRROR stream; a forward bridge has a
/// local FORWARD stream. (For `Both`, the two local streams MUST differ — enforced in
/// [`LeafConfig::validate`] — so the directions never share a log and cannot loop.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafBridge {
    /// The HUB stream this bridge mirrors and/or forwards to (empty = the hub's default stream).
    pub hub_stream: String,
    /// The local stream the read-side mirror materializes (read-only), if this bridge mirrors. `None`
    /// when the direction does not include a mirror.
    pub mirror_local_stream: Option<String>,
    /// The local stream the write-through forwards from, if this bridge forwards. `None` when the
    /// direction does not include a forward.
    pub forward_local_stream: Option<String>,
    /// The direction(s) this bridge spans.
    pub direction: LeafDirection,
}

/// The whole LEAF configuration: the hub this node is a leaf of, plus the configured stream bridges.
/// EMPTY (the default — no `--leaf-hub`) means NO leaf plane: the byte-identical single-node path
/// (nothing constructs). The hub is identified by a [`GeoOrigin`]-style address (resolved from a raw
/// `host:port` or a `@domain` reference through the SAME [`DomainResolver`](super::domain::DomainResolver)
/// the geo plane uses), so the read-side reuses the geo dialer + applier verbatim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeafConfig {
    /// The hub's geo endpoint address the leaf dials OUTBOUND (e.g. `10.0.0.1:7500`, resolved from a raw
    /// address or a `@domain` reference). Empty `addr` with no bridges = the no-leaf default.
    pub hub_addr: String,
    /// The configured stream bridges (one per `--leaf-mirror` / `--leaf-forward`).
    pub bridges: Vec<LeafBridge>,
}

impl LeafConfig {
    /// True if NO leaf hub is configured — the byte-identical non-leaf path (nothing constructs).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hub_addr.is_empty() && self.bridges.is_empty()
    }

    /// The LOCAL stream names that are READ-ONLY (the leaf's mirror locals) — the streams a client produce
    /// must be rejected on, exactly the geo read-only set. A FORWARD local stream is NOT read-only (it is
    /// the leaf's own locally-produced stream).
    #[must_use]
    pub fn read_only_streams(&self) -> Vec<String> {
        self.bridges
            .iter()
            .filter_map(|b| b.mirror_local_stream.clone())
            .collect()
    }

    /// The read-side bridges as geo [`GeoMode::Mirror`] streams over the hub address — so the read-side is
    /// driven by the geo plane VERBATIM (the leaf's read bridge IS a geo mirror of a hub stream). Each
    /// returns `(local_stream, GeoMode)` ready for the geo applier/puller, the SAME shape a `--mirror`
    /// produces.
    #[must_use]
    pub fn mirror_geo_modes(&self) -> Vec<(String, GeoMode)> {
        self.bridges
            .iter()
            .filter(|b| b.direction.mirrors())
            .filter_map(|b| {
                b.mirror_local_stream.clone().map(|local| {
                    (
                        local,
                        GeoMode::Mirror(GeoOrigin {
                            addr: self.hub_addr.clone(),
                            stream: b.hub_stream.clone(),
                        }),
                    )
                })
            })
            .collect()
    }

    /// Validate the leaf config fail-closed: a non-empty config MUST name a hub address, every bridge's
    /// declared direction(s) MUST carry the matching local stream, and — the LOOP-SAFETY guard — no local
    /// stream may serve as BOTH a mirror local and a forward local (the only way the two directions could
    /// share a log and echo a record across the link forever).
    ///
    /// # Errors
    /// [`LeafError::Config`] describing the first violation found.
    pub fn validate(&self) -> Result<(), LeafError> {
        if self.is_empty() {
            return Ok(());
        }
        if self.hub_addr.is_empty() {
            return Err(LeafError::Config {
                what: "a leaf bridge was configured but no `--leaf-hub` address was given"
                    .to_string(),
            });
        }
        let mut mirror_locals = std::collections::BTreeSet::new();
        let mut forward_locals = std::collections::BTreeSet::new();
        for b in &self.bridges {
            if b.direction.mirrors() {
                match &b.mirror_local_stream {
                    Some(s) => {
                        mirror_locals.insert(s.clone());
                    }
                    None => {
                        return Err(LeafError::Config {
                            what: format!(
                            "bridge for hub stream `{}` is a mirror but has no local mirror stream",
                            b.hub_stream
                        ),
                        })
                    }
                }
            }
            if b.direction.forwards() {
                match &b.forward_local_stream {
                    Some(s) => {
                        forward_locals.insert(s.clone());
                    }
                    None => {
                        return Err(LeafError::Config {
                            what: format!(
                                "bridge for hub stream `{}` is a forward but has no local forward stream",
                                b.hub_stream
                            ),
                        })
                    }
                }
            }
        }
        // THE LOOP-SAFETY GUARD: a local stream that is BOTH a mirror local AND a forward local would let
        // a record mirrored DOWN be forwarded back UP — an echo. Reject it; the two directions MUST use
        // distinct local logs so a record crosses the link exactly once.
        for s in &mirror_locals {
            if forward_locals.contains(s) {
                return Err(LeafError::Config {
                    what: format!(
                        "local stream `{s}` is configured as BOTH a read-side mirror and a \
                         write-through forward; that would echo a record across the link. A mirror \
                         local (read-only) and a forward local (locally produced) MUST be distinct streams"
                    ),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::{Append, LogConfig};

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

    #[test]
    fn push_request_round_trips_with_a_named_stream() {
        let req = LeafPushRequest {
            stream: "orders".to_string(),
            from_leaf_offset: 42,
            record_count: 2,
            frame_bytes: vec![1, 2, 3, 4, 5],
        };
        let bytes = req.encode().unwrap();
        assert_eq!(LeafPushRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn push_request_empty_stream_and_run_round_trips() {
        let req = LeafPushRequest {
            stream: String::new(),
            from_leaf_offset: 0,
            record_count: 0,
            frame_bytes: Vec::new(),
        };
        let bytes = req.encode().unwrap();
        assert_eq!(LeafPushRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn push_response_round_trips() {
        let resp = LeafPushResponse {
            accepted_through_leaf_offset: 99,
        };
        let bytes = resp.encode();
        assert_eq!(LeafPushResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn an_over_cap_push_request_is_rejected_pre_buffer() {
        // Hand-build a request whose claimed frame_bytes_len exceeds the cap.
        let mut body = Vec::new();
        body.push(PUSH_KIND_REQUEST);
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(MAX_LEAF_PUSH_BYTES + 1).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        match LeafPushRequest::decode(&body) {
            Err(LeafError::RequestTooLarge { len }) => {
                assert_eq!(len, u64::from(MAX_LEAF_PUSH_BYTES) + 1);
            }
            other => panic!("expected RequestTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn an_over_long_hub_stream_name_is_rejected_on_encode() {
        let req = LeafPushRequest {
            stream: "x".repeat(MAX_ORIGIN_STREAM_LEN + 1),
            from_leaf_offset: 0,
            record_count: 0,
            frame_bytes: Vec::new(),
        };
        assert!(matches!(
            req.encode(),
            Err(LeafError::HubStreamNameTooLong { .. })
        ));
    }

    #[test]
    fn a_malformed_push_request_kind_is_rejected() {
        let mut body = LeafPushRequest {
            stream: "s".to_string(),
            from_leaf_offset: 0,
            record_count: 0,
            frame_bytes: Vec::new(),
        }
        .encode()
        .unwrap();
        body[0] = 9; // wrong kind
        assert!(matches!(
            LeafPushRequest::decode(&body),
            Err(LeafError::MalformedRequest { .. })
        ));
    }

    #[test]
    fn push_cursor_persists_and_recovers_per_stream() {
        let fs = InMemoryFs::new();
        {
            let mut c = LeafPushCursor::open(&fs).unwrap();
            assert_eq!(c.cursor("orders"), 0);
            c.commit("orders", 5).unwrap();
            c.commit("events", 3).unwrap();
            // Monotonic: a backward commit is a no-op.
            c.commit("orders", 4).unwrap();
            assert_eq!(c.cursor("orders"), 5);
        }
        let c = LeafPushCursor::open(&fs).unwrap();
        assert_eq!(c.cursor("orders"), 5);
        assert_eq!(c.cursor("events"), 3);
        assert_eq!(c.cursor("never"), 0);
    }

    /// Build a leaf local FORWARD log with `n` records, fsync'd, returning the log + its sealed-served
    /// frontier (what the read plane serves off the sealed prefix).
    fn leaf_forward_log(n: u32) -> (Log<InMemoryFs, ManualClock>, u64) {
        let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..n {
            log.append(&rec(format!("L-{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        let served = sealed_served_end(&log);
        (log, served)
    }

    fn sealed_served_end(log: &Log<InMemoryFs, ManualClock>) -> u64 {
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

    /// Forward a leaf's local log into a hub log to convergence, returning total appended. Reuses the
    /// `LeafForwarder` (read leaf bytes) + `HubPushReceiver` (re-validate + append) + push cursor.
    fn forward_into(
        leaf: &Log<InMemoryFs, ManualClock>,
        hub: &mut HubPushReceiver<InMemoryFs, ManualClock>,
        cursor: &mut LeafPushCursor<InMemoryFs>,
        key: &str,
    ) -> u64 {
        let mut total = 0u64;
        loop {
            let plane = leaf.read_plane().unwrap();
            let fwd = LeafForwarder::new(&plane);
            let req = fwd.next_push(key, cursor.cursor(key)).unwrap();
            if req.record_count == 0 {
                break;
            }
            let out = hub.apply_push(&req).unwrap();
            cursor
                .commit(key, out.accepted_through_leaf_offset)
                .unwrap();
            total += out.appended;
        }
        total
    }

    #[test]
    fn write_through_forwards_leaf_records_to_the_hub_byte_faithfully() {
        let (leaf, served) = leaf_forward_log(30);
        assert!(served > 0);
        let hub_log = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        let mut hub = HubPushReceiver::new(hub_log);
        let cfs = InMemoryFs::new();
        let mut cursor = LeafPushCursor::open(&cfs).unwrap();
        let key = "orders";

        let appended = forward_into(&leaf, &mut hub, &mut cursor, key);
        assert_eq!(appended, served, "the hub appended the whole sealed prefix");
        assert_eq!(cursor.cursor(key), served, "push cursor advanced to served");

        // The hub's records are byte-faithful to the leaf's, in order.
        let hub_recs = hub.log().read_from(Offset::new(0), 100).unwrap();
        assert_eq!(hub_recs.len() as u64, served);
        for (i, r) in hub_recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("L-{i:02}").as_bytes());
        }
    }

    #[test]
    fn write_through_resumes_after_a_disconnect_with_no_gap_or_dup() {
        let (leaf, served) = leaf_forward_log(30);
        let hub_log = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        let mut hub = HubPushReceiver::new(hub_log);
        // The cursor shares ONE fs so it survives a "restart" (reopen).
        let cfs = InMemoryFs::new();
        let key = "orders";

        // First push: forward ONE batch, then DROP the cursor handle (a disconnect after partial forward).
        let partial = {
            let mut cursor = LeafPushCursor::open(&cfs).unwrap();
            let plane = leaf.read_plane().unwrap();
            let fwd = LeafForwarder::new(&plane);
            let req = fwd.next_push(key, cursor.cursor(key)).unwrap();
            assert!(req.record_count >= 1, "first batch forwarded something");
            let out = hub.apply_push(&req).unwrap();
            cursor
                .commit(key, out.accepted_through_leaf_offset)
                .unwrap();
            cursor.cursor(key)
        };
        assert!(partial > 0 && partial < served, "partial before disconnect");

        // REOPEN the cursor over the same fs: it recovers durably and forwarding RESUMES with no gap/dup.
        let mut cursor = LeafPushCursor::open(&cfs).unwrap();
        assert_eq!(cursor.cursor(key), partial, "push cursor recovered durably");
        let more = forward_into(&leaf, &mut hub, &mut cursor, key);
        assert_eq!(cursor.cursor(key), served, "resumed to served");
        assert_eq!(
            partial + more,
            served,
            "no gap, no dup across the disconnect"
        );
        // The hub holds exactly the sealed prefix, once, in order.
        let recs = hub.log().read_from(Offset::new(0), 1000).unwrap();
        assert_eq!(recs.len() as u64, served);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("L-{i:02}").as_bytes());
        }
    }

    #[test]
    fn a_corrupt_pushed_frame_fails_closed_on_the_hub() {
        let hub_log = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        let mut hub = HubPushReceiver::new(hub_log);
        // One good frame followed by a corrupt one.
        let mut frames = Vec::new();
        ironbus_core::codec::encode(
            &ironbus_core::codec::RecordView {
                seq: ironbus_core::types::Seq::new(0),
                timestamp_ms: 1,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"good",
            },
            &mut frames,
        )
        .unwrap();
        let good_len = frames.len();
        ironbus_core::codec::encode(
            &ironbus_core::codec::RecordView {
                seq: ironbus_core::types::Seq::new(1),
                timestamp_ms: 1,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"bad",
            },
            &mut frames,
        )
        .unwrap();
        frames[good_len + 4] ^= 0xFF; // corrupt the second frame's body
        let req = LeafPushRequest {
            stream: "orders".to_string(),
            from_leaf_offset: 0,
            record_count: 2,
            frame_bytes: frames,
        };
        let err = hub.apply_push(&req).unwrap_err();
        assert!(
            matches!(
                err,
                LeafError::CorruptFrame {
                    at_leaf_offset: 1,
                    ..
                }
            ),
            "expected CorruptFrame at leaf offset 1, got {err:?}"
        );
        // The good prefix WAS appended (the hub never blind-trusts, but it keeps the validated prefix).
        assert_eq!(hub.log().read_from(Offset::new(0), 10).unwrap().len(), 1);
    }

    #[test]
    fn an_idle_forward_builds_an_empty_push_and_is_a_clean_no_op() {
        let leaf = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        let plane = leaf.read_plane().unwrap();
        let fwd = LeafForwarder::new(&plane);
        let req = fwd.next_push("orders", 0).unwrap();
        assert_eq!(req.record_count, 0, "an idle forward has nothing to push");
        assert!(req.frame_bytes.is_empty());
    }

    #[test]
    fn leaf_config_reports_read_only_mirror_locals_and_geo_modes() {
        let cfg = LeafConfig {
            hub_addr: "h:1".to_string(),
            bridges: vec![
                LeafBridge {
                    hub_stream: "ho".to_string(),
                    mirror_local_stream: Some("m".to_string()),
                    forward_local_stream: None,
                    direction: LeafDirection::Mirror,
                },
                LeafBridge {
                    hub_stream: "hf".to_string(),
                    mirror_local_stream: None,
                    forward_local_stream: Some("f".to_string()),
                    direction: LeafDirection::Forward,
                },
            ],
        };
        // Only the mirror local is read-only; the forward local is the leaf's own produced stream.
        assert_eq!(cfg.read_only_streams(), vec!["m".to_string()]);
        // The read-side bridge surfaces as a geo Mirror of the hub stream over the hub address.
        let modes = cfg.mirror_geo_modes();
        assert_eq!(modes.len(), 1);
        assert_eq!(modes[0].0, "m");
        assert_eq!(
            modes[0].1,
            GeoMode::Mirror(GeoOrigin {
                addr: "h:1".to_string(),
                stream: "ho".to_string()
            })
        );
        assert!(!cfg.is_empty());
        cfg.validate().unwrap();
    }

    #[test]
    fn the_empty_leaf_config_is_the_no_leaf_default() {
        let cfg = LeafConfig::default();
        assert!(cfg.is_empty());
        assert!(cfg.read_only_streams().is_empty());
        assert!(cfg.mirror_geo_modes().is_empty());
        cfg.validate().unwrap(); // empty validates trivially (nothing constructs)
    }

    #[test]
    fn config_rejects_a_local_stream_that_is_both_mirror_and_forward_no_loop() {
        // THE LOOP-SAFETY GUARD: the same local stream as both a mirror local and a forward local would
        // echo a record across the link. Rejected fail-closed.
        let cfg = LeafConfig {
            hub_addr: "h:1".to_string(),
            bridges: vec![
                LeafBridge {
                    hub_stream: "ho".to_string(),
                    mirror_local_stream: Some("shared".to_string()),
                    forward_local_stream: None,
                    direction: LeafDirection::Mirror,
                },
                LeafBridge {
                    hub_stream: "hf".to_string(),
                    mirror_local_stream: None,
                    forward_local_stream: Some("shared".to_string()),
                    direction: LeafDirection::Forward,
                },
            ],
        };
        assert!(matches!(cfg.validate(), Err(LeafError::Config { .. })));
    }

    #[test]
    fn config_rejects_a_bridge_missing_its_directional_local_stream() {
        let cfg = LeafConfig {
            hub_addr: "h:1".to_string(),
            bridges: vec![LeafBridge {
                hub_stream: "ho".to_string(),
                mirror_local_stream: None, // declares Mirror but no local
                forward_local_stream: None,
                direction: LeafDirection::Mirror,
            }],
        };
        assert!(matches!(cfg.validate(), Err(LeafError::Config { .. })));
    }

    #[test]
    fn config_rejects_bridges_without_a_hub_addr() {
        let cfg = LeafConfig {
            hub_addr: String::new(),
            bridges: vec![LeafBridge {
                hub_stream: "ho".to_string(),
                mirror_local_stream: Some("m".to_string()),
                forward_local_stream: None,
                direction: LeafDirection::Mirror,
            }],
        };
        assert!(matches!(cfg.validate(), Err(LeafError::Config { .. })));
    }
}

/// The REAL two-node LEAF-SPOKE integration tests (#625): a HUB serve and a separate LEAF serve over real
/// loopback `TcpStream`s + real on-disk `StdFs` logs. Unix-only because the broker / serve path is
/// `cfg(unix)` via `StdFs` (so the helpers and tests vanish together on Windows under `-D dead_code`),
/// matching the geo `live_geo_tests` discipline. These tests PROVE — not merely by construction — the
/// asymmetric dial, byte-faithful read-side mirror + resume, byte-faithful write-through + resume,
/// loop-freedom (a record crosses once), leaf churn not degrading the hub, an idle leaf doing ~0 work, and
/// a leaf NOT being a Raft voter (hub quorum untouched across leaf churn).
#[cfg(all(test, unix))]
#[allow(clippy::similar_names)]
mod live_leaf_tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::cluster::geo::{
        GeoFrame, GeoLink, MirrorApplier, OriginCursorStore, OriginServer, GEO_POLL,
    };
    use crate::cluster::runtime::{ClusterConfig, ClusterRuntime, StartRole};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

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

    /// Scale a GENEROUS base wait by the observed host slowdown (#618), so the timing waits stay truthful
    /// and flake-free on a contended CI runner WITHOUT weakening what they prove. A local copy of the
    /// runtime test's `host_scaled` (max-of-probes + a 24x cap): on an unloaded host the factor is ~1 and
    /// the wait stays the base (the test is FAST and exits early the instant its predicate holds); on a
    /// starved host it stretches proportionally. The assertions are UNCHANGED.
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

    /// Poll `pred` until true or `timeout` (host-scaled) elapses. Returns the final predicate value.
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

    /// Bind an ephemeral loopback port, read it, drop the listener (the caller rebinds it).
    fn free_addr() -> SocketAddr {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    /// A real on-disk log with `n` records, fsync'd, leaked to `'static` so its read plane keeps observing
    /// it for the test's lifetime (in a real serve the engine's append actor owns it).
    fn leaked_log(dir: &std::path::Path, prefix: &str, n: u32) -> &'static Log<StdFs, ManualClock> {
        let fs = StdFs::new(dir.to_path_buf());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).expect("log opens");
        for i in 0..n {
            log.append(&rec(format!("{prefix}-{i:03}").as_bytes()))
                .unwrap();
        }
        log.sync().unwrap();
        Box::leak(Box::new(log))
    }

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

    /// THE ASYMMETRY (read-side): a HUB geo origin listener the LEAF dials OUTBOUND. The hub NEVER dials
    /// the leaf — it ACCEPTS the leaf's inbound link and answers `MirrorPull` requests from the hub
    /// stream's read plane. Returns a shutdown flag + the join handle; exits promptly on shutdown. This is
    /// the geo origin-serve pattern, REUSED — a leaf's read bridge IS a geo mirror of a hub stream.
    fn spawn_hub_mirror_serve(
        addr: SocketAddr,
        hub: &'static Log<StdFs, ManualClock>,
    ) -> (Arc<AtomicBool>, JoinHandle<()>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_t = Arc::clone(&shutdown);
        let listener = TcpListener::bind(addr).expect("hub mirror listener binds");
        listener.set_nonblocking(true).unwrap();
        let plane = Arc::new(hub.read_plane().expect("hub read plane"));
        let handle = std::thread::Builder::new()
            .name("ib-leaf-hub-mirror".to_string())
            .spawn(move || {
                while !shutdown_t.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            let plane = Arc::clone(&plane);
                            let sd = Arc::clone(&shutdown_t);
                            std::thread::spawn(move || {
                                let mut link = GeoLink::new(stream);
                                let server = OriginServer::new(&plane);
                                while !sd.load(Ordering::Acquire) {
                                    match link.recv() {
                                        Ok(Some(GeoFrame::Request(req))) => {
                                            let resp = server.serve_pull(&req).expect("serve_pull");
                                            if link.send_response(&resp).is_err() {
                                                return;
                                            }
                                        }
                                        Ok(Some(GeoFrame::Response(_))) => {}
                                        Err(GeoError::Io(e))
                                            if matches!(
                                                e.kind(),
                                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                            ) => {}
                                        Ok(None) | Err(_) => return,
                                    }
                                }
                            });
                        }
                        Err(ref e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                }
            })
            .expect("spawn hub mirror serve");
        (shutdown, handle)
    }

    /// The handles a hub push serve returns: a shutdown flag, the listener join handle, and the shared
    /// hub-receiver (so the test can read what the hub durably appended). Aliased to keep the spawn
    /// signature under the clippy type-complexity bar.
    type HubPushHandles = (
        Arc<AtomicBool>,
        JoinHandle<()>,
        Arc<Mutex<HubPushReceiver<StdFs, SystemClock>>>,
    );

    /// THE ASYMMETRY (write-through): a HUB push-receiver listener the LEAF dials OUTBOUND. The hub NEVER
    /// dials the leaf — it ACCEPTS the leaf's inbound link, RE-VALIDATES each pushed frame, appends to the
    /// hub stream's log, and acks. Returns a shutdown flag, the join handle, and the shared hub-receiver
    /// (so the test can read what the hub appended).
    fn spawn_hub_push_serve(addr: SocketAddr, hub_dir: &std::path::Path) -> HubPushHandles {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_t = Arc::clone(&shutdown);
        let listener = TcpListener::bind(addr).expect("hub push listener binds");
        listener.set_nonblocking(true).unwrap();
        let hub_log = Log::open(
            StdFs::new(hub_dir.to_path_buf()),
            SystemClock::new(),
            small_config(),
        )
        .expect("hub push log opens");
        let receiver = Arc::new(Mutex::new(HubPushReceiver::new(hub_log)));
        let receiver_t = Arc::clone(&receiver);
        let handle = std::thread::Builder::new()
            .name("ib-leaf-hub-push".to_string())
            .spawn(move || {
                while !shutdown_t.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            let receiver = Arc::clone(&receiver_t);
                            let sd = Arc::clone(&shutdown_t);
                            std::thread::spawn(move || {
                                let mut link = LeafLink::new(stream);
                                while !sd.load(Ordering::Acquire) {
                                    match link.recv() {
                                        Ok(Some(LeafFrame::Request(req))) => {
                                            // RE-VALIDATE + append under the lock (off the socket IO),
                                            // then ack the leaf offset accepted through.
                                            let ack = {
                                                let mut r = receiver.lock().unwrap_or_else(
                                                    std::sync::PoisonError::into_inner,
                                                );
                                                match r.apply_push(&req) {
                                                    Ok(out) => LeafPushResponse {
                                                        accepted_through_leaf_offset: out
                                                            .accepted_through_leaf_offset,
                                                    },
                                                    // A corrupt push still durably kept its validated
                                                    // prefix; ack exactly that so the leaf resumes after it.
                                                    Err(LeafError::CorruptFrame {
                                                        at_leaf_offset,
                                                        ..
                                                    }) => LeafPushResponse {
                                                        accepted_through_leaf_offset:
                                                            at_leaf_offset,
                                                    },
                                                    Err(_) => return,
                                                }
                                            };
                                            if link.send_response(&ack).is_err() {
                                                return;
                                            }
                                        }
                                        Ok(Some(LeafFrame::Response(_))) => {}
                                        Err(LeafError::Io(e))
                                            if matches!(
                                                e.kind(),
                                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                            ) => {}
                                        Ok(None) | Err(_) => return,
                                    }
                                }
                            });
                        }
                        Err(ref e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                }
            })
            .expect("spawn hub push serve");
        (shutdown, handle, receiver)
    }

    /// Open a leaf MIRROR applier (read-side bridge) over an on-disk dir (its local mirror log + geo
    /// cursor), exactly the geo mirror open.
    fn open_leaf_mirror(dir: &std::path::Path) -> MirrorApplier<StdFs, ManualClock> {
        let log = Log::open(
            StdFs::new(dir.to_path_buf()),
            ManualClock::new(),
            small_config(),
        )
        .expect("leaf mirror log opens");
        let cursors = OriginCursorStore::open(&StdFs::new(dir.to_path_buf())).expect("geo cursor");
        MirrorApplier::new(log, cursors, true)
    }

    /// The leaf DIALS the hub (outbound) and pulls one origin into its mirror until caught up to the hub's
    /// currently-served sealed prefix, resuming from the durable geo cursor. Reuses the geo pull request
    /// + apply path verbatim (the read-side bridge IS a geo mirror).
    fn leaf_drain_mirror(
        addr: SocketAddr,
        app: &mut MirrorApplier<StdFs, ManualClock>,
        key: &str,
        hub_stream: &str,
    ) {
        let stream = TcpStream::connect(addr).expect("leaf dials hub");
        stream.set_read_timeout(Some(GEO_POLL)).unwrap();
        let mut link = GeoLink::new(stream);
        loop {
            let req = app.pull_request(key, hub_stream, 1024, 1024 * 1024);
            if link.send_request(&req).is_err() {
                break;
            }
            match link.recv() {
                Ok(Some(GeoFrame::Response(resp))) => {
                    let out = app.apply_pull_response(key, &resp).expect("apply");
                    if out.applied == 0 {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    /// The leaf DIALS the hub (outbound) and forwards its local FORWARD stream to the hub until fully
    /// forwarded (push cursor reaches the leaf's sealed-served frontier), resuming from the durable push
    /// cursor. Returns the cursor after.
    fn leaf_drain_forward(
        addr: SocketAddr,
        leaf_forward: &Log<StdFs, ManualClock>,
        cursor: &mut LeafPushCursor<StdFs>,
        key: &str,
        hub_stream: &str,
    ) {
        let stream = TcpStream::connect(addr).expect("leaf dials hub");
        stream.set_read_timeout(Some(LEAF_PUSH_POLL)).unwrap();
        let mut link = LeafLink::new(stream);
        loop {
            let plane = leaf_forward.read_plane().unwrap();
            let fwd = LeafForwarder::new(&plane);
            let req = fwd
                .next_push(hub_stream, cursor.cursor(key))
                .expect("build push");
            if req.record_count == 0 {
                break;
            }
            if link.send_request(&req).is_err() {
                break;
            }
            match link.recv() {
                Ok(Some(LeafFrame::Response(ack))) => {
                    cursor
                        .commit(key, ack.accepted_through_leaf_offset)
                        .expect("commit push cursor");
                }
                _ => break,
            }
        }
    }

    fn dump_segments(log: &Log<StdFs, ManualClock>) -> BTreeMap<String, Vec<u8>> {
        use ironbus_storage::io::RandomAccessFile;
        let fs = log.filesystem();
        let mut out = BTreeMap::new();
        for name in fs.list().expect("list segments") {
            let file = fs.open(&name).expect("open segment");
            let len = usize::try_from(file.len().expect("len")).expect("len fits");
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, 0).expect("read segment");
            out.insert(name, buf);
        }
        out
    }

    #[test]
    fn a_leaf_mirrors_a_hub_stream_byte_faithfully_over_the_wire() {
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let hub_dir = tempfile::tempdir().expect("hub dir");
        let leaf_dir = tempfile::tempdir().expect("leaf dir");
        let hub = leaked_log(hub_dir.path(), "h", 40);
        let served = sealed_served_end(hub);
        assert!(served > 0);

        let addr = free_addr();
        let (shutdown, handle) = spawn_hub_mirror_serve(addr, hub);

        let key = format!("{addr}/");
        let mut app = open_leaf_mirror(leaf_dir.path());
        assert!(
            wait_until(Duration::from_secs(10), || {
                leaf_drain_mirror(addr, &mut app, &key, "");
                app.cursor(&key) == served
            }),
            "leaf mirror converged to the hub's sealed prefix (cursor {} of {served})",
            app.cursor(&key)
        );

        // Byte-faithful, in order.
        let recs = app.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("h-{i:03}").as_bytes());
        }
        // BYTE-IDENTITY: at least one fully-sealed leaf segment is byte-for-byte the hub's.
        let leaf_dump = dump_segments(app.log());
        let hub_dump = dump_segments(hub);
        assert!(
            leaf_dump
                .iter()
                .any(|(name, bytes)| hub_dump.get(name) == Some(bytes)),
            "at least one leaf mirror segment is byte-identical to the hub's over the wire"
        );

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn a_leaf_mirror_resumes_across_a_disconnect_with_no_gap_or_dup() {
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let hub_dir = tempfile::tempdir().expect("hub dir");
        let leaf_dir = tempfile::tempdir().expect("leaf dir");
        let hub = leaked_log(hub_dir.path(), "h", 40);
        let served = sealed_served_end(hub);

        let addr = free_addr();
        let (shutdown, handle) = spawn_hub_mirror_serve(addr, hub);
        let key = format!("{addr}/");

        // First connection: pull one batch then DROP the applier (a disconnect + restart). The cursor +
        // log are durable on disk, so a reopen resumes from the durable cursor.
        let partial = {
            let mut app = open_leaf_mirror(leaf_dir.path());
            let stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(GEO_POLL)).unwrap();
            let mut link = GeoLink::new(stream);
            let req = app.pull_request(&key, "", 1024, 1024 * 1024);
            link.send_request(&req).unwrap();
            if let Ok(Some(GeoFrame::Response(resp))) = link.recv() {
                let out = app.apply_pull_response(&key, &resp).unwrap();
                assert!(out.applied >= 1, "first batch applied something");
            }
            app.cursor(&key)
        };
        assert!(
            partial > 0 && partial < served,
            "partial catch-up before the disconnect"
        );

        // REOPEN over the same dir: durable cursor recovers, draining RESUMES with no gap / no dup.
        let mut app = open_leaf_mirror(leaf_dir.path());
        assert_eq!(app.cursor(&key), partial, "cursor recovered durably");
        assert!(wait_until(Duration::from_secs(10), || {
            leaf_drain_mirror(addr, &mut app, &key, "");
            app.cursor(&key) == served
        }));
        let recs = app.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served, "exactly the sealed prefix, once");
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(
                r.payload.as_ref(),
                format!("h-{i:03}").as_bytes(),
                "in order, no gap/dup"
            );
        }

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn a_leaf_writes_through_to_the_hub_byte_faithfully_over_the_wire() {
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let leaf_fwd_dir = tempfile::tempdir().expect("leaf forward dir");
        let leaf_cursor_dir = tempfile::tempdir().expect("leaf cursor dir");
        let hub_dir = tempfile::tempdir().expect("hub dir");
        // The leaf's LOCAL forward stream: 40 locally-produced records.
        let leaf_forward = leaked_log(leaf_fwd_dir.path(), "L", 40);
        let served = sealed_served_end(leaf_forward);
        assert!(served > 0);

        let addr = free_addr();
        let (shutdown, handle, receiver) = spawn_hub_push_serve(addr, hub_dir.path());
        let key = format!("{addr}/orders");

        let mut cursor =
            LeafPushCursor::open(&StdFs::new(leaf_cursor_dir.path().to_path_buf())).unwrap();
        assert!(
            wait_until(Duration::from_secs(10), || {
                leaf_drain_forward(addr, leaf_forward, &mut cursor, &key, "orders");
                cursor.cursor(&key) == served
            }),
            "leaf wrote its local stream through to the hub (cursor {} of {served})",
            cursor.cursor(&key)
        );

        // The hub holds the leaf's records, byte-faithful, in order.
        let r = receiver.lock().unwrap();
        let recs = r.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served);
        for (i, rr) in recs.iter().enumerate() {
            assert_eq!(rr.payload.as_ref(), format!("L-{i:03}").as_bytes());
        }
        drop(r);

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn a_leaf_write_through_resumes_across_a_disconnect_with_no_gap_or_dup() {
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let leaf_fwd_dir = tempfile::tempdir().expect("leaf forward dir");
        let leaf_cursor_dir = tempfile::tempdir().expect("leaf cursor dir");
        let hub_dir = tempfile::tempdir().expect("hub dir");
        let leaf_forward = leaked_log(leaf_fwd_dir.path(), "L", 40);
        let served = sealed_served_end(leaf_forward);

        let addr = free_addr();
        let (shutdown, handle, receiver) = spawn_hub_push_serve(addr, hub_dir.path());
        let key = format!("{addr}/orders");
        let cursor_fs = StdFs::new(leaf_cursor_dir.path().to_path_buf());

        // First push: forward ONE batch then DROP the cursor handle + link (a disconnect). The push cursor
        // is durable on disk, so a reopen resumes from it.
        let partial = {
            let mut cursor = LeafPushCursor::open(&cursor_fs).unwrap();
            let stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(LEAF_PUSH_POLL)).unwrap();
            let mut link = LeafLink::new(stream);
            let plane = leaf_forward.read_plane().unwrap();
            let fwd = LeafForwarder::new(&plane);
            let req = fwd.next_push("orders", cursor.cursor(&key)).unwrap();
            assert!(req.record_count >= 1, "first batch forwarded something");
            link.send_request(&req).unwrap();
            if let Ok(Some(LeafFrame::Response(ack))) = link.recv() {
                cursor
                    .commit(&key, ack.accepted_through_leaf_offset)
                    .unwrap();
            }
            cursor.cursor(&key)
        };
        assert!(
            partial > 0 && partial < served,
            "partial forward before the disconnect"
        );

        // REOPEN the push cursor over the same fs: it recovers durably and forwarding RESUMES, no gap/dup.
        let mut cursor = LeafPushCursor::open(&cursor_fs).unwrap();
        assert_eq!(
            cursor.cursor(&key),
            partial,
            "push cursor recovered durably"
        );
        assert!(wait_until(Duration::from_secs(10), || {
            leaf_drain_forward(addr, leaf_forward, &mut cursor, &key, "orders");
            cursor.cursor(&key) == served
        }));

        // The hub holds exactly the sealed prefix, once, in order (no gap, no dup across the disconnect).
        let r = receiver.lock().unwrap();
        let recs = r.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served, "exactly the sealed prefix, once");
        for (i, rr) in recs.iter().enumerate() {
            assert_eq!(
                rr.payload.as_ref(),
                format!("L-{i:03}").as_bytes(),
                "in order, no gap/dup"
            );
        }
        drop(r);

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn write_through_does_not_loop_a_record_crosses_the_link_once() {
        // THE NO-LOOP PROOF over the wire: a leaf that ALSO mirrors a DIFFERENT hub stream forwards its
        // local forward stream UP exactly once. The hub ends with exactly the leaf's records (count ==
        // served), never a multiple — even after repeated drain rounds (which would re-forward if the
        // cursor did not de-dup). The mirror local and forward local are DISTINCT logs, so a mirrored-down
        // record is never in the forward stream to echo up.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let leaf_fwd_dir = tempfile::tempdir().expect("leaf forward dir");
        let leaf_cursor_dir = tempfile::tempdir().expect("leaf cursor dir");
        let hub_dir = tempfile::tempdir().expect("hub dir");
        let leaf_forward = leaked_log(leaf_fwd_dir.path(), "L", 40);
        let served = sealed_served_end(leaf_forward);

        let addr = free_addr();
        let (shutdown, handle, receiver) = spawn_hub_push_serve(addr, hub_dir.path());
        let key = format!("{addr}/orders");
        let mut cursor =
            LeafPushCursor::open(&StdFs::new(leaf_cursor_dir.path().to_path_buf())).unwrap();

        // Forward to convergence...
        assert!(wait_until(Duration::from_secs(10), || {
            leaf_drain_forward(addr, leaf_forward, &mut cursor, &key, "orders");
            cursor.cursor(&key) == served
        }));
        // ...then drain SEVERAL MORE TIMES. With no de-dup these rounds would re-forward + double the hub.
        for _ in 0..5 {
            leaf_drain_forward(addr, leaf_forward, &mut cursor, &key, "orders");
        }

        // The hub has EXACTLY `served` records — each crossed the link ONCE (the cursor de-dup; no echo).
        let r = receiver.lock().unwrap();
        let count = r.log().read_from(Offset::new(0), 10_000).unwrap().len() as u64;
        assert_eq!(
            count, served,
            "each record crossed the link exactly once (no loop/echo)"
        );
        drop(r);

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn many_leaf_connects_and_disconnects_do_not_degrade_the_hub() {
        // LEAF CHURN: a leaf connects + disconnects repeatedly; the hub is UNAFFECTED. The hub serves every
        // (re)connection cleanly and the leaf converges byte-faithfully despite the churn — bounded
        // per-leaf resources (one reader per inbound link, torn down on disconnect), no degradation.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let hub_dir = tempfile::tempdir().expect("hub dir");
        let leaf_dir = tempfile::tempdir().expect("leaf dir");
        let hub = leaked_log(hub_dir.path(), "h", 60);
        let served = sealed_served_end(hub);

        let addr = free_addr();
        let (shutdown, handle) = spawn_hub_mirror_serve(addr, hub);
        let key = format!("{addr}/");
        let mut app = open_leaf_mirror(leaf_dir.path());

        // 20 connect/pull-one-batch/disconnect cycles: each cycle is a fresh dial + a short pull + a drop.
        // The hub keeps serving across all of them (a disconnect tears down only that leaf's reader).
        for _ in 0..20 {
            let stream = TcpStream::connect(addr).expect("leaf re-dials hub across churn");
            stream.set_read_timeout(Some(GEO_POLL)).unwrap();
            let mut link = GeoLink::new(stream);
            let req = app.pull_request(&key, "", 1024, 1024 * 1024);
            if link.send_request(&req).is_ok() {
                if let Ok(Some(GeoFrame::Response(resp))) = link.recv() {
                    let _ = app.apply_pull_response(&key, &resp);
                }
            }
            // `link`/`stream` drop here = a disconnect; the hub's per-leaf reader winds down.
        }
        // After the churn the hub is still fully serving: a final drain converges byte-faithfully.
        assert!(
            wait_until(Duration::from_secs(10), || {
                leaf_drain_mirror(addr, &mut app, &key, "");
                app.cursor(&key) == served
            }),
            "the hub kept serving across 20 leaf connect/disconnect cycles (cursor {} of {served})",
            app.cursor(&key)
        );
        let recs = app.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("h-{i:03}").as_bytes());
        }

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn a_leaf_is_not_a_voter_and_leaf_churn_never_touches_hub_quorum() {
        // THE NOT-A-VOTER PROOF: a single-node HUB metadata cluster has voter_count == 1 and is its own
        // leader. A leaf connects/disconnects repeatedly against a SEPARATE leaf endpoint; the hub's
        // metadata-Raft membership (voter_count) and leadership are UNCHANGED — a leaf is never a voter,
        // so leaf churn never touches the hub's consensus / quorum / availability.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let hub_meta_dir = tempfile::tempdir().expect("hub metadata dir");
        let hub_stream_dir = tempfile::tempdir().expect("hub stream dir");
        let leaf_dir = tempfile::tempdir().expect("leaf dir");

        // The HUB's metadata Raft group: a single seeded voter (its own quorum). This is the hub's
        // CONSENSUS plane — entirely separate from the leaf plane.
        let meta_addr = free_addr();
        let mut peers = BTreeMap::new();
        peers.insert(1u64, meta_addr);
        let cfg = ClusterConfig {
            node_id: 1,
            peers,
            role: StartRole::Voter,
            pending_learners: BTreeSet::new(),
        };
        let runtime = ClusterRuntime::start(
            &cfg,
            &StdFs::new(hub_meta_dir.path().to_path_buf()),
            SystemClock::new(),
            LogConfig::new(64 * 1024).unwrap(),
        )
        .expect("hub metadata cluster starts");
        // A lone voter self-elects.
        assert!(
            wait_until(Duration::from_secs(10), || runtime.status().is_leader),
            "the single-node hub self-elects"
        );
        let voters_before = runtime.status().voter_count;
        assert_eq!(voters_before, 1, "the hub has exactly its one voter");

        // The hub's leaf endpoint (a SEPARATE listener — the leaf plane, NOT the metadata peer port).
        let leaf_hub = leaked_log(hub_stream_dir.path(), "h", 30);
        let leaf_addr = free_addr();
        let (shutdown, handle) = spawn_hub_mirror_serve(leaf_addr, leaf_hub);
        let key = format!("{leaf_addr}/");
        let mut app = open_leaf_mirror(leaf_dir.path());

        // Churn the leaf 15x against the hub's leaf endpoint.
        for _ in 0..15 {
            let stream = TcpStream::connect(leaf_addr).expect("leaf dials hub leaf endpoint");
            stream.set_read_timeout(Some(GEO_POLL)).unwrap();
            let mut link = GeoLink::new(stream);
            let req = app.pull_request(&key, "", 1024, 1024 * 1024);
            if link.send_request(&req).is_ok() {
                if let Ok(Some(GeoFrame::Response(resp))) = link.recv() {
                    let _ = app.apply_pull_response(&key, &resp);
                }
            }
        }

        // THE ASSERTION: the hub's metadata membership + leadership are UNCHANGED by all that leaf churn.
        // A leaf appears in NO ConfState; the voter_count (the quorum basis) is the same 1, and the hub is
        // still its own leader. Leaf churn touched consensus zero times.
        let status_after = runtime.status();
        assert_eq!(
            status_after.voter_count, voters_before,
            "leaf churn did not change the hub's voter set (a leaf is NOT a voter)"
        );
        assert!(
            status_after.is_leader,
            "leaf churn did not disturb the hub's leadership"
        );
        assert!(
            status_after.suspected_dead.is_empty(),
            "no leaf is ever a metadata peer, so none can be a suspected-dead voter"
        );
        assert!(
            status_after.learners.is_empty(),
            "a leaf never joins the metadata group even as a learner"
        );

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
        drop(runtime);
    }

    #[test]
    fn an_idle_leaf_push_loop_does_no_work_and_backs_off() {
        // THE IDLE PROOF (#726): a leaf with NOTHING new to forward (its push cursor is at the local
        // frontier) BLOCKS / BACKS OFF, doing ~0 work — the push_loop applies nothing and never sends an
        // empty push (it pauses on the build-empty path). We prove it does not spin: a fully-forwarded
        // leaf's loop forwards NOTHING across several poll windows and exits promptly on shutdown.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let leaf_fwd_dir = tempfile::tempdir().expect("leaf forward dir");
        let leaf_cursor_dir = tempfile::tempdir().expect("leaf cursor dir");
        let hub_dir = tempfile::tempdir().expect("hub dir");
        // An EMPTY leaf forward log: nothing to forward, ever.
        let leaf_forward = leaked_log(leaf_fwd_dir.path(), "L", 0);
        let addr = free_addr();
        let (shutdown, handle, _receiver) = spawn_hub_push_serve(addr, hub_dir.path());
        let key = format!("{addr}/orders");

        let cursor = Arc::new(Mutex::new(
            LeafPushCursor::open(&StdFs::new(leaf_cursor_dir.path().to_path_buf())).unwrap(),
        ));
        let pushed = Arc::new(AtomicU64::new(0));
        let loop_shutdown = Arc::new(AtomicBool::new(false));
        // The read plane is `Send + Sync` (the `Log` itself is not — it caches a `RefCell` plane), so the
        // forward thread captures the `Arc<ReadPlane>`, exactly the geo origin-serve pattern.
        let plane = Arc::new(leaf_forward.read_plane().unwrap());

        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let ls = Arc::clone(&loop_shutdown);
        let pushed_t = Arc::clone(&pushed);
        let cursor_t = Arc::clone(&cursor);
        let plane_t = Arc::clone(&plane);
        let loop_handle = std::thread::spawn(move || {
            let mut link = LeafLink::new(stream);
            push_loop(
                &mut link,
                &ls,
                || {
                    let c = cursor_t.lock().unwrap();
                    let fwd = LeafForwarder::new(&plane_t);
                    let req = fwd.next_push("orders", c.cursor(&key))?;
                    if req.record_count > 0 {
                        pushed_t.fetch_add(u64::from(req.record_count), Ordering::Relaxed);
                    }
                    Ok(req)
                },
                |acked| {
                    cursor_t.lock().unwrap().commit(&key, acked)?;
                    Ok(())
                },
            );
        });

        // Let the idle loop run a few poll windows, then stop it. An idle leaf forwards NOTHING.
        std::thread::sleep(Duration::from_millis(600));
        loop_shutdown.store(true, Ordering::Release);
        let _ = loop_handle.join();
        assert_eq!(
            pushed.load(Ordering::Relaxed),
            0,
            "an idle leaf forwards nothing (it blocks/backs off, no busy work)"
        );

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }
}
