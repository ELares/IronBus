// SPDX-License-Identifier: MIT OR Apache-2.0
//! ISR (in-sync replica) set + min-in-sync-replicas + quorum-FSYNC ack release (V2-C2-I2, #593).
//!
//! This is THE cluster durability differentiator. Where C2-I1 (#590, [`super::replication`]) made a
//! follower PULL the leader's CRC-framed log and re-validate it, this module turns that replication
//! into a DURABILITY GUARANTEE the producer can rely on: a produce at the cluster ack level
//! `C2-fsync` (the R>=3 default) releases its `PubAck` ONLY when the record's offset has been
//! `fdatasync`'d on a QUORUM of replicas — so **an IronBus R-ack means fsync'd-on-a-quorum BY
//! CONSTRUCTION**.
//!
//! This is the precise win over NATS R3 and Kafka `acks=all`, both of which ack on a quorum (or ISR)
//! PAGE-CACHE, not a quorum FSYNC (`ironbus-clustering-design.md` §3; the NATS `#7564` loss of
//! 131k/930k acked records on a power cut). IronBus already acks-after-its-OWN-fsync on the leader
//! (the single-node I2, `engine.rs` `DurabilityLevel::Sync`); this gates the release ADDITIONALLY on
//! a quorum of replicas having each returned `fdatasync` Ok for the covering offset.
//!
//! ## The three pieces (one log / partition)
//!
//! 1. **The follower reports its FSYNC'd offset, not its received offset.** [`AckReplicatedBody`] is a
//!    follower → leader report carrying `(follower_id, fsynced_offset)` over the bounded
//!    `[len][type=AckReplicated][body]` envelope (the new wire tag 37). `fsynced_offset` is the first
//!    offset the follower has NOT durably appended — i.e. it has `fdatasync`'d every offset strictly
//!    below it. Because [`super::replication::Follower::apply_fetch_response`] calls `Log::sync`
//!    (`fdatasync`) before it returns, a follower's `next_offset` after an apply IS an fsync'd
//!    frontier; this report ships exactly that. Reporting FSYNC'd (not merely received) is what makes
//!    quorum-fsync REAL — the leader never counts a replica that has the bytes only in page cache.
//! 2. **The leader computes the QUORUM-COMMIT offset.** [`IsrTracker`] tracks, per replica (the leader
//!    itself + each follower), the highest offset that replica has `fdatasync`'d. The
//!    quorum-commit offset is the highest offset that AT LEAST `min_isr` replicas (a quorum, e.g.
//!    `f+1` of `2f+1`) — drawn from the current ISR — have all fsync'd. That is the durably-replicated
//!    committed prefix.
//! 3. **The C2-fsync ack release is gated on the quorum-commit offset.** [`QuorumAckGate`] holds a
//!    produce's pending `PubAck` until the produce's offset `< quorum_commit` (i.e. `min_isr` replicas
//!    have fsync'd it). [`QuorumAckGate::release_up_to`] is driven whenever the quorum-commit offset
//!    advances and returns every pending ack now satisfied, in offset order.
//!
//! ## `min_isr` enforcement — the no-false-ack property (unavailable over unsafe)
//!
//! If the ISR shrinks below `min_isr` (too many followers evicted for lag, or down), a `C2-fsync`
//! produce CANNOT be quorum-committed — there are not enough in-sync, fsync'd replicas to satisfy the
//! quorum. The honest choice, and IronBus's choice, is to BLOCK / backpressure (the ack stays pending)
//! rather than FALSELY ack a record that is not fsync'd-on-a-quorum. This is the
//! unavailable-over-unsafe posture: an R-ack is never a lie. [`IsrTracker::quorum_commit`] returns
//! `None` when the ISR is below `min_isr`, and [`QuorumAckGate::release_up_to`] releases nothing in
//! that state, so the producer waits (or, at the caller's option, the produce is failed with an
//! explicit not-enough-replicas error) — it is never acked on a page-cache or sub-quorum basis.
//!
//! ## Replica-lag eviction (the `replica.lag.time.max.ms` analogue)
//!
//! A follower that falls too far behind the leader's tail is evicted from the ISR so a permanently
//! lagging or wedged replica can neither hold back the quorum-commit offset nor be counted toward a
//! quorum it is not actually keeping up with. [`IsrTracker`] evicts a follower whose fsync'd offset
//! lags the leader's high-watermark by more than [`IsrConfig::max_lag_records`] (an offset-distance
//! bound; the time-based `replica.lag.time.max.ms` shape is the same idea over the clock seam and is
//! noted as a follow-up). An evicted follower re-joins the ISR automatically once it has caught back
//! up to within the bound (it reports a fresh fsync'd offset that is in-bounds again).
//!
//! ## What this module deliberately does NOT do (deferred, flagged)
//!
//! * **The explicit cluster ack-level ENUM** (`C0` / `C1` / `C2-pagecache` / `C2-fsync`) and the
//!   opt-in page-cache level + per-level metrics are **C3** (#605 / #608). Here the ONE cluster ack
//!   level implemented is `C2-fsync` (the quorum-fsync gate); the existing single-node `0/1/2`
//!   produce-ack spectrum and the `DurabilityLevel` (`engine.rs`) are unchanged, and a local-only /
//!   weaker level remains available there. This module is the quorum-fsync MECHANISM the C3 enum will
//!   select.
//! * **Leader-epoch truncation on divergence** is **C2-I4** (#599); **divergence self-heal** is C4;
//!   **multi-partition fan-out** is later. This module is ONE log / partition and assumes the C2-I1
//!   contiguous-lineage follower.
//! * **`serve`-path wiring**: like [`super::replication`] and the C1 peer transport (#667), this is the
//!   TESTABLE ISR + quorum-ack LAYER (the report codec, the tracker, the gate, driven by an in-process
//!   3-node leader+2-follower harness). Wiring it into the running broker's produce-ack release is the
//!   follow-up.
//!
//! ## Single-node is byte-identical (the Edge-First non-negotiable)
//!
//! With no cluster (n=1, R<3) NONE of this engages: the produce ack stays the existing local-fsync ack
//! (`DurabilityLevel::Sync`, I2), byte-for-byte. The ISR / quorum path only constructs in a configured
//! cluster with `min_isr >= 2`. This module adds no state and no code to the single-node append path;
//! merely linking it changes nothing on disk or on the wire for a standalone broker.

use std::collections::BTreeMap;

use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType, MAX_FRAME_LEN,
};

use super::replication::ReplicationError;

/// The fixed little-endian byte length of an encoded [`AckReplicatedBody`]:
/// `follower_id: u64` + `fsynced_offset: u64`.
const ACK_REPLICATED_LEN: usize = 8 + 8;

/// Read a little-endian `u64` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 8`
/// (every call site length-checks the body first), so this is panic-free.
#[inline]
fn read_u64_le(b: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(buf)
}

/// A follower → leader durably-replicated-offset REPORT (#593): "I, `follower_id`, have `fdatasync`'d
/// every record up to (but NOT including) `fsynced_offset`." It rides the bounded
/// `[len][type=AckReplicated][body]` envelope (wire tag 37) — an additive, peer-only frame a client
/// never sends.
///
/// The reported offset is the follower's DURABLE (fsync'd) frontier, the
/// [`super::replication::ApplyOutcome::next_offset`] after the apply's `Log::sync` returned Ok — NOT
/// the bytes it has merely received. Reporting fsync'd (not received) is what makes the leader's
/// quorum-commit a quorum-FSYNC, the load-bearing durability distinction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckReplicatedBody {
    /// The reporting follower's cluster node id (the same `u64` node id space the runtime / metadata
    /// group use). The leader authenticates this against the known partition replica set before it is
    /// counted, exactly as the C1 transport authenticates a Raft message's `from`.
    pub follower_id: u64,
    /// The first offset the follower has NOT durably appended: it has `fdatasync`'d every offset
    /// strictly below this. Monotonic non-decreasing per follower (a follower's durable prefix never
    /// shrinks); the tracker takes the max so a stale / reordered report can never lower it.
    pub fsynced_offset: u64,
}

impl AckReplicatedBody {
    /// Encode this report to its fixed-layout little-endian body bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACK_REPLICATED_LEN);
        out.extend_from_slice(&self.follower_id.to_le_bytes());
        out.extend_from_slice(&self.fsynced_offset.to_le_bytes());
        out
    }

    /// Decode a report from its body bytes.
    ///
    /// # Errors
    /// Returns [`ReplicationError::MalformedRequest`] if `body` is not exactly [`ACK_REPLICATED_LEN`]
    /// bytes — a malformed / truncated / over-long report is rejected, never guessed at (the same
    /// fail-closed discipline as the fetch request/response codecs).
    pub fn decode(body: &[u8]) -> Result<AckReplicatedBody, ReplicationError> {
        if body.len() != ACK_REPLICATED_LEN {
            return Err(ReplicationError::MalformedRequest { len: body.len() });
        }
        Ok(AckReplicatedBody {
            follower_id: read_u64_le(body, 0),
            fsynced_offset: read_u64_le(body, 8),
        })
    }

    /// Frame this report into the bounded `[len][type=AckReplicated][body]` envelope, ready to write to
    /// a peer link.
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] if the (fixed, tiny) body somehow cannot be framed.
    pub fn to_frame(&self) -> Result<Vec<u8>, ReplicationError> {
        let mut out = Vec::with_capacity(ACK_REPLICATED_LEN + 5);
        encode_frame(FrameType::AckReplicated, &self.encode(), &mut out).map_err(|e| {
            ReplicationError::Frame {
                what: e.to_string(),
            }
        })?;
        Ok(out)
    }

    /// Decode exactly one [`AckReplicatedBody`] from the front of a framed byte buffer, returning the
    /// report and the number of bytes consumed, or `Ok(None)` if the buffer does not yet hold a
    /// complete frame.
    ///
    /// The frame length is bounded by the absolute envelope cap on the way in (a hostile length is
    /// rejected before any allocation), and the type tag must be [`FrameType::AckReplicated`].
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] on a framing fault or an unexpected type tag, or
    /// [`ReplicationError::MalformedRequest`] if the body is the wrong length.
    pub fn decode_frame(
        buf: &[u8],
    ) -> Result<Option<(AckReplicatedBody, usize)>, ReplicationError> {
        // The report body is fixed and tiny; cap the inbound frame tightly (still <= MAX_FRAME_LEN).
        let cap = u32::try_from(ACK_REPLICATED_LEN + 16)
            .unwrap_or(MAX_FRAME_LEN)
            .min(MAX_FRAME_LEN);
        match decode_frame_with_cap(buf, cap) {
            Ok(FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            }) => match FrameType::from_u8(type_tag) {
                Some(FrameType::AckReplicated) => {
                    Ok(Some((AckReplicatedBody::decode(body)?, consumed)))
                }
                _ => Err(ReplicationError::Frame {
                    what: format!(
                        "unexpected frame type tag {type_tag} for an AckReplicated report"
                    ),
                }),
            },
            Ok(FrameDecode::Incomplete { .. }) => Ok(None),
            Err(FrameError::FrameTooLarge { len }) => {
                Err(ReplicationError::ResponseTooLarge { len })
            }
            Err(e) => Err(ReplicationError::Frame {
                what: e.to_string(),
            }),
        }
    }
}

/// Configuration for the ISR + quorum-commit of ONE partition log.
///
/// The supported clustered shape is `R = 2f+1` replicas with `min_isr = f+1` (the quorum), the design
/// default for `R >= 3` (`ironbus-clustering-design.md` §3). `min_isr` MUST be `>= 2` for the cluster
/// quorum path to engage at all — a `min_isr` of `1` is the degenerate leader-only (single-node-shaped)
/// case where the quorum gate reduces to the local-fsync ack and no follower is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsrConfig {
    /// The minimum number of in-sync, fsync'd replicas (INCLUDING the leader) that must have
    /// `fdatasync`'d a record before its offset is quorum-committed and its `C2-fsync` ack may be
    /// released. For `R = 2f+1` this is the quorum `f+1`. If the ISR has fewer than this many members,
    /// NO offset can be quorum-committed (the no-false-ack property): the ack blocks rather than lies.
    pub min_isr: usize,
    /// The replica-lag eviction bound (the `replica.lag.time.max.ms` offset analogue): a follower whose
    /// fsync'd offset lags the leader's high-watermark by MORE than this many records is evicted from
    /// the ISR until it catches back up to within the bound. `0` disables lag eviction (a follower is
    /// only ever out of the ISR if it has never reported).
    pub max_lag_records: u64,
}

impl Default for IsrConfig {
    fn default() -> Self {
        // The R=3 / min_isr=2 (f+1 of 2f+1, f=1) default: the smallest cluster that tolerates one
        // failure with a quorum-fsync ack, and the design's R>=3 default. A generous default lag bound
        // (a follower may trail by up to 1024 records before eviction) keeps a briefly-slow follower in
        // the ISR rather than flapping it.
        Self {
            min_isr: 2,
            max_lag_records: 1024,
        }
    }
}

/// Whether a replica is currently IN the in-sync set or has been evicted for lag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsrMembership {
    /// The replica is in-sync: it has reported an fsync'd offset within the lag bound of the leader's
    /// high-watermark, so it counts toward the quorum.
    InSync,
    /// The replica has been EVICTED for lagging past [`IsrConfig::max_lag_records`]: it does NOT count
    /// toward the quorum until it catches back up. It is still tracked (its reports still arrive) so it
    /// can auto-rejoin.
    EvictedForLag,
}

/// The LEADER-side ISR tracker for one partition log: it owns the leader's own fsync'd frontier and
/// every follower's reported fsync'd frontier, derives the in-sync set under the lag bound, and
/// computes the quorum-commit offset.
///
/// "fsync'd offset" everywhere is a FIRST-NOT-DURABLE frontier: a replica at fsync'd offset `N` has
/// `fdatasync`'d records `0..N` (offsets `0..=N-1`). The leader's own frontier is its
/// `Log::flushed_offset` (the local I2 durable head); a follower's is the
/// [`AckReplicatedBody::fsynced_offset`] it last reported.
pub struct IsrTracker {
    config: IsrConfig,
    /// The leader's own cluster node id (always an implicit, never-evicted ISR member: a leader is
    /// trivially in sync with itself).
    leader_id: u64,
    /// The leader's own fsync'd frontier (its local durable head, `Log::flushed_offset`). Seeded at 0
    /// and raised by [`IsrTracker::observe_leader_fsync`] as the leader group-commits.
    leader_fsynced: u64,
    /// Each follower's last-reported fsync'd frontier, keyed by node id. Monotonic non-decreasing per
    /// follower (the tracker takes the max on each report).
    followers: BTreeMap<u64, u64>,
}

impl IsrTracker {
    /// Construct a tracker for one partition led by `leader_id`, with the given `replica_ids` as the
    /// configured follower set (the leader is added implicitly and need not appear in `replica_ids`).
    /// Every follower starts at fsync'd offset 0 and is considered NOT-yet-reporting until its first
    /// [`IsrTracker::observe_follower_report`].
    #[must_use]
    pub fn new(leader_id: u64, replica_ids: &[u64], config: IsrConfig) -> Self {
        let mut followers = BTreeMap::new();
        for &id in replica_ids {
            if id != leader_id {
                followers.insert(id, 0u64);
            }
        }
        Self {
            config,
            leader_id,
            leader_fsynced: 0,
            followers,
        }
    }

    /// The leader's own node id.
    #[must_use]
    pub fn leader_id(&self) -> u64 {
        self.leader_id
    }

    /// The configured `min_isr` (the quorum size, including the leader).
    #[must_use]
    pub fn min_isr(&self) -> usize {
        self.config.min_isr
    }

    /// Raise the leader's own fsync'd frontier to `flushed_offset` (its `Log::flushed_offset` after a
    /// local group-commit `fdatasync`). The leader is always an ISR member; this is the I2 local-fsync
    /// frontier that the cluster quorum builds on. Monotonic: a smaller value is ignored.
    pub fn observe_leader_fsync(&mut self, flushed_offset: u64) {
        self.leader_fsynced = self.leader_fsynced.max(flushed_offset);
    }

    /// Record a follower's [`AckReplicatedBody`] report (its durably-replicated, fsync'd frontier).
    /// The follower's tracked frontier is raised to the max of its current and the reported value, so a
    /// stale / reordered report can never lower a follower's frontier. An unknown `follower_id` (not in
    /// the configured replica set) is IGNORED and reported via the return value, so a stray / spoofed
    /// report is never counted toward the quorum.
    ///
    /// Returns `true` if the report was from a known follower and applied, `false` if the follower id
    /// was unknown (rejected). The caller (the leader's report-handling path) should already have
    /// authenticated the peer id against the partition replica set; this is the in-tracker
    /// belt-and-braces check.
    pub fn observe_follower_report(&mut self, report: &AckReplicatedBody) -> bool {
        match self.followers.get_mut(&report.follower_id) {
            Some(frontier) => {
                *frontier = (*frontier).max(report.fsynced_offset);
                true
            }
            None => false,
        }
    }

    /// The leader's high-watermark for the purpose of lag: its own fsync'd frontier (the tail a
    /// follower is measured against). A follower lagging this by more than the bound is evicted.
    #[must_use]
    pub fn leader_high_watermark(&self) -> u64 {
        self.leader_fsynced
    }

    /// The current ISR membership of `follower_id` under the lag bound, or `None` if `follower_id` is
    /// not a configured follower. A follower is [`IsrMembership::InSync`] iff its reported fsync'd
    /// frontier is within [`IsrConfig::max_lag_records`] of the leader's frontier (or lag eviction is
    /// disabled).
    #[must_use]
    pub fn membership(&self, follower_id: u64) -> Option<IsrMembership> {
        self.followers
            .get(&follower_id)
            .map(|&frontier| self.classify(frontier))
    }

    fn classify(&self, follower_fsynced: u64) -> IsrMembership {
        if self.config.max_lag_records == 0 {
            return IsrMembership::InSync;
        }
        let lag = self.leader_fsynced.saturating_sub(follower_fsynced);
        if lag > self.config.max_lag_records {
            IsrMembership::EvictedForLag
        } else {
            IsrMembership::InSync
        }
    }

    /// The current ISR size: the leader (always in-sync) plus every follower within the lag bound.
    #[must_use]
    pub fn isr_size(&self) -> usize {
        let in_sync_followers = self
            .followers
            .values()
            .filter(|&&f| matches!(self.classify(f), IsrMembership::InSync))
            .count();
        // The leader is always an ISR member of its own partition.
        1 + in_sync_followers
    }

    /// Whether the ISR currently meets `min_isr` (the quorum is satisfiable). When this is false, NO
    /// offset can be quorum-committed and a `C2-fsync` ack must block rather than be released (the
    /// no-false-ack property).
    #[must_use]
    pub fn meets_min_isr(&self) -> bool {
        self.isr_size() >= self.config.min_isr
    }

    /// The QUORUM-COMMIT offset: the highest offset that at least `min_isr` replicas (drawn from the
    /// current ISR — the leader plus the lag-bounded followers) have all `fdatasync`'d. Records below
    /// this offset are durably-replicated-on-a-quorum; a `C2-fsync` ack for such a record is honest.
    ///
    /// Returns `None` when the ISR is below `min_isr` — there is no quorum, so NOTHING is committed and
    /// the ack must block (unavailable over unsafe). This `None` is the no-false-ack guarantee in the
    /// type system: the gate literally cannot release an ack when the quorum is absent.
    ///
    /// # How it is computed
    /// Collect the fsync'd frontiers of the IN-SYNC replicas (the leader's own frontier, plus each
    /// in-sync follower's), sort descending, and take the `min_isr`-th largest. That offset is the
    /// largest value `>= min_isr` replicas have all reached: at least `min_isr` frontiers are `>=` it.
    /// This is the standard ISR / Kafka high-watermark computation, specialized to a min-ISR quorum and
    /// — crucially — over FSYNC'd frontiers, not page-cache frontiers.
    #[must_use]
    pub fn quorum_commit(&self) -> Option<u64> {
        if !self.meets_min_isr() {
            return None;
        }
        // The frontiers that count toward the quorum: the leader (always in-sync) + every in-sync
        // follower. An evicted (lagging) follower's frontier is NOT included, so a stuck replica cannot
        // be counted toward a quorum it is not actually keeping up with.
        let mut frontiers: Vec<u64> = Vec::with_capacity(1 + self.followers.len());
        frontiers.push(self.leader_fsynced);
        for &f in self.followers.values() {
            if matches!(self.classify(f), IsrMembership::InSync) {
                frontiers.push(f);
            }
        }
        // Defensive: meets_min_isr() already guarantees at least min_isr frontiers here.
        if frontiers.len() < self.config.min_isr {
            return None;
        }
        // Sort descending and take the min_isr-th largest: the highest offset that at least min_isr
        // replicas have all fsync'd.
        frontiers.sort_unstable_by(|a, b| b.cmp(a));
        Some(frontiers[self.config.min_isr - 1])
    }
}

/// A produce whose `C2-fsync` `PubAck` is being WITHHELD until its offset is quorum-committed
/// (`fdatasync`'d on `min_isr` replicas). The opaque `token` is whatever the caller needs to map the
/// release back to the awaiting producer connection / reply channel (e.g. the parked-reply key the
/// actor uses for the local-fsync I2 ack today).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingAck<T> {
    /// The log offset of the produced record. Its `C2-fsync` ack releases only once
    /// `offset < quorum_commit` (i.e. `min_isr` replicas have fsync'd offsets `0..=offset`).
    pub offset: u64,
    /// The caller's opaque routing token for the awaiting producer (returned verbatim on release).
    pub token: T,
}

/// The gate that holds `C2-fsync` `PubAck`s until they are quorum-committed, and releases them in
/// offset order as the quorum-commit offset advances.
///
/// The leader ALREADY acks-after-its-own-fsync for the single-node I2 (`engine.rs`); this gate adds
/// the cluster condition: a record's ack is released only once `min_isr` replicas — the leader plus a
/// quorum of in-sync followers — have each `fdatasync`'d it. So the released ack carries the strongest
/// possible promise: the record is fsync'd-on-a-quorum.
///
/// `T` is the caller's opaque routing token (see [`PendingAck`]). The gate stores pending acks in
/// offset order so release is a single front-to-back drain; it never reorders acks past one another.
pub struct QuorumAckGate<T> {
    /// Pending acks in strictly increasing offset order (produces are appended in offset order, so a
    /// push is always at the back). A `VecDeque` would also serve; a `Vec` drained from the front in
    /// order is simplest and the front-drain is amortized O(released).
    pending: Vec<PendingAck<T>>,
    /// The highest offset already released, so a re-drive at a non-advancing quorum-commit offset
    /// releases nothing twice. Starts at 0 (no offset released yet; offset 0's ack releases when
    /// `quorum_commit >= 1`).
    released_through: u64,
    /// The cap on `pending.len()` (#864): the most acks this gate may withhold before [`park`](Self::park)
    /// REFUSES a new one. `0` = unlimited (the single-node-shaped / test default). Under an unsatisfiable
    /// ISR (a follower down, below `min_isr`) nothing drains, so without a cap a pipelining producer grows
    /// `pending` without bound — OOM/abort. At the cap `park` returns `false` so the caller fails the
    /// produce with an explicit not-enough-replicas error rather than buffering unboundedly.
    cap: usize,
}

impl<T> Default for QuorumAckGate<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> QuorumAckGate<T> {
    /// A fresh gate with no pending acks and NO backlog cap (`0` = unlimited). Used by the
    /// single-node-shaped path and the gate's own tests; the clustered leader uses
    /// [`with_cap`](Self::with_cap) to bound the parked backlog (#864).
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(0)
    }

    /// A fresh gate that withholds at most `cap` acks before [`park`](Self::park) refuses (#864); `0` =
    /// unlimited. The clustered leader sets this so an unsatisfiable ISR cannot grow the parked backlog
    /// without bound.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            pending: Vec::new(),
            released_through: 0,
            cap,
        }
    }

    /// Park a produce's `C2-fsync` ack to be released once its offset is quorum-committed, returning
    /// `true` if it was parked and `false` if the gate is at its backlog cap (#864). The leader calls
    /// this AFTER its own local-fsync (the I2 ack-after-its-own-fsync still holds); the cluster gate
    /// withholds the wire `PubAck` until the quorum has also fsync'd. On a `false` return the caller MUST
    /// NOT treat the produce as parked — it fails the produce with an explicit not-enough-replicas error
    /// rather than buffer the reply unboundedly while the ISR is below `min_isr`.
    ///
    /// Offsets must be parked in non-decreasing order (the produce path assigns offsets monotonically);
    /// this is the produce path's natural order.
    #[must_use]
    pub fn park(&mut self, offset: u64, token: T) -> bool {
        if self.cap != 0 && self.pending.len() >= self.cap {
            return false;
        }
        self.pending.push(PendingAck { offset, token });
        true
    }

    /// The number of acks currently withheld (awaiting quorum-fsync). Zero means every produced ack has
    /// been released.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Drop every pending ack whose token satisfies `is_dead` — e.g. a disconnected producer's tokens
    /// (#871) — returning the count removed. The survivors keep their order (offsets stay
    /// non-decreasing), and `released_through` is untouched: a purged token simply never releases, so
    /// release semantics are unchanged. This frees the dropped acks' backlog-cap slots (#864/#869) so a
    /// new produce is no longer refused by dead-owner entries an unsatisfiable quorum will never drain.
    pub fn purge_where(&mut self, mut is_dead: impl FnMut(&T) -> bool) -> usize {
        let before = self.pending.len();
        self.pending.retain(|p| !is_dead(&p.token));
        before - self.pending.len()
    }

    /// Whether an ack for `offset` is still being withheld.
    #[must_use]
    pub fn is_pending(&self, offset: u64) -> bool {
        self.pending.iter().any(|p| p.offset == offset)
    }

    /// Release — in offset order — every pending ack whose record is now quorum-committed, given the
    /// tracker's current quorum-commit offset.
    ///
    /// A pending ack at `offset` is released iff `offset < quorum_commit` (the quorum-commit offset is
    /// a FIRST-NOT-COMMITTED frontier: `quorum_commit = N` means offsets `0..N` are fsync'd on a
    /// quorum). When `quorum_commit` is `None` — the ISR is below `min_isr` — NOTHING is released: the
    /// acks stay withheld (the no-false-ack property; the producer waits, unavailable over unsafe).
    ///
    /// Returns the released tokens in offset order. The caller maps each back to its producer
    /// connection and finally writes the wire `PubAck`.
    pub fn release_up_to(&mut self, quorum_commit: Option<u64>) -> Vec<T> {
        let Some(commit) = quorum_commit else {
            // No quorum: release nothing. THE durability guarantee — an ack is never released on a
            // sub-quorum / page-cache basis.
            return Vec::new();
        };
        // Re-driving with a non-advancing commit must release nothing new.
        let commit = commit.max(self.released_through);
        // Release the contiguous SUBMISSION-ORDER prefix of acks whose record is now quorum-committed
        // (`offset < commit`). This is a strict prefix drain on purpose: each producer connection's acks
        // are delivered in FIFO submission order (the client's `produce_window` correlates replies by
        // ARRIVAL POSITION, not by offset — broker-assigned offsets are unknown until the ack arrives),
        // so an ack may NEVER be released ahead of an earlier-submitted one on the same stream.
        //
        // A dedup-hit (#917) can park an OLD duplicate offset BELOW a higher already-parked offset, so
        // `pending` is not always non-decreasing; the prefix drain correctly holds such a duplicate
        // behind its FIFO-predecessor (releasing it would re-order that connection's ack stream and
        // corrupt the client's position-indexed results) — it releases once the blocking earlier ack
        // does, and a never-committing blocker withholds BOTH (the producer waits, unavailable over
        // unsafe) until `purge_owner` reclaims them on disconnect. An ack at `offset >= commit` is
        // committed iff `offset < commit`.
        let split = self
            .pending
            .iter()
            .position(|p| p.offset >= commit)
            .unwrap_or(self.pending.len());
        let released: Vec<T> = self.pending.drain(..split).map(|p| p.token).collect();
        self.released_through = commit;
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- the AckReplicated report codec -----

    #[test]
    fn ack_replicated_report_round_trips_through_its_codec() {
        let report = AckReplicatedBody {
            follower_id: 0xCAFE_F00D,
            fsynced_offset: 123_456,
        };
        assert_eq!(AckReplicatedBody::decode(&report.encode()).unwrap(), report);
    }

    #[test]
    fn ack_replicated_decode_rejects_a_wrong_length_body() {
        assert!(matches!(
            AckReplicatedBody::decode(&[0u8; 15]),
            Err(ReplicationError::MalformedRequest { len: 15 })
        ));
        assert!(matches!(
            AckReplicatedBody::decode(&[0u8; 17]),
            Err(ReplicationError::MalformedRequest { len: 17 })
        ));
    }

    #[test]
    fn ack_replicated_round_trips_through_the_frame_envelope() {
        let report = AckReplicatedBody {
            follower_id: 7,
            fsynced_offset: 42,
        };
        let framed = report.to_frame().unwrap();
        let (decoded, consumed) = AckReplicatedBody::decode_frame(&framed).unwrap().unwrap();
        assert_eq!(decoded, report);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn ack_replicated_decode_frame_is_incomplete_on_a_partial_buffer() {
        let report = AckReplicatedBody {
            follower_id: 1,
            fsynced_offset: 9,
        };
        let framed = report.to_frame().unwrap();
        // A strict prefix returns Ok(None) (incomplete), never a wrong report or a panic.
        assert!(AckReplicatedBody::decode_frame(&framed[..framed.len() - 1])
            .unwrap()
            .is_none());
    }

    #[test]
    fn ack_replicated_decode_frame_rejects_the_wrong_type_tag() {
        // A correctly-framed body but under a DIFFERENT type tag is rejected (a frame that is not an
        // AckReplicated report on this path).
        let mut framed = Vec::new();
        encode_frame(FrameType::Ping, &[0u8; ACK_REPLICATED_LEN], &mut framed).unwrap();
        assert!(matches!(
            AckReplicatedBody::decode_frame(&framed),
            Err(ReplicationError::Frame { .. })
        ));
    }

    // ----- the quorum-commit offset computation -----

    #[test]
    fn quorum_commit_is_the_min_isr_th_largest_fsynced_frontier() {
        // 3 replicas (leader=1, followers 2 and 3), min_isr=2 (f+1 of 2f+1, f=1).
        let mut isr = IsrTracker::new(1, &[2, 3], IsrConfig::default());
        // Leader has fsync'd through offset 10; follower 2 through 7; follower 3 through 4.
        isr.observe_leader_fsync(10);
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 7,
        });
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 3,
            fsynced_offset: 4,
        });
        // Frontiers sorted desc: [10, 7, 4]; min_isr=2 → the 2nd largest = 7. At least 2 replicas
        // (leader@10, follower2@7) have fsync'd everything below offset 7.
        assert_eq!(isr.quorum_commit(), Some(7));
    }

    #[test]
    fn quorum_commit_ignores_a_stale_or_reordered_report() {
        let mut isr = IsrTracker::new(1, &[2, 3], IsrConfig::default());
        isr.observe_leader_fsync(10);
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 8,
        });
        // A LATER report that REGRESSES follower 2's frontier (stale / reordered) must NOT lower it.
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 3,
        });
        assert_eq!(
            isr.quorum_commit(),
            Some(8),
            "a stale report can never lower a follower's fsync'd frontier"
        );
    }

    #[test]
    fn an_unknown_follower_report_is_rejected_and_not_counted() {
        let mut isr = IsrTracker::new(1, &[2, 3], IsrConfig::default());
        isr.observe_leader_fsync(10);
        // A report from a node id that is NOT a configured replica (a stray / spoofed report) is
        // rejected and never counted toward the quorum.
        let applied = isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 99,
            fsynced_offset: 9,
        });
        assert!(!applied, "an unknown follower id is rejected");
        // followers 2 and 3 are still at 0 → only the leader is ahead → quorum (2nd largest) is 0.
        assert_eq!(isr.quorum_commit(), Some(0));
    }

    // ----- THE no-false-ack property: below min_isr, nothing commits -----

    #[test]
    fn below_min_isr_there_is_no_quorum_commit() {
        // R=3, min_isr=2, but lag-evict both followers so the ISR is just the leader (size 1 < 2).
        let config = IsrConfig {
            min_isr: 2,
            max_lag_records: 5,
        };
        let mut isr = IsrTracker::new(1, &[2, 3], config);
        isr.observe_leader_fsync(100);
        // Both followers lag by 100 >> 5 → both evicted → ISR size 1.
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 1,
        });
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 3,
            fsynced_offset: 2,
        });
        assert_eq!(isr.isr_size(), 1);
        assert!(!isr.meets_min_isr());
        assert_eq!(
            isr.quorum_commit(),
            None,
            "below min_isr there is NO quorum-commit offset: an ack must block, never falsely fire"
        );
    }

    // ----- replica-lag eviction + auto-rejoin -----

    #[test]
    fn a_lagging_follower_is_evicted_then_rejoins_when_it_catches_up() {
        let config = IsrConfig {
            min_isr: 2,
            max_lag_records: 10,
        };
        let mut isr = IsrTracker::new(1, &[2, 3], config);
        isr.observe_leader_fsync(100);
        // Follower 2 keeps up (lag 100-95=5 <= 10) → in-sync. Follower 3 lags (100-50=50 > 10) →
        // evicted.
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 95,
        });
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 3,
            fsynced_offset: 50,
        });
        assert_eq!(isr.membership(2), Some(IsrMembership::InSync));
        assert_eq!(isr.membership(3), Some(IsrMembership::EvictedForLag));
        assert_eq!(isr.isr_size(), 2, "leader + follower 2");
        // The quorum-commit is the 2nd largest of the IN-SYNC frontiers [100, 95] = 95; follower 3's
        // stale 50 does NOT drag it down (an evicted replica cannot hold back the quorum).
        assert_eq!(isr.quorum_commit(), Some(95));

        // Follower 3 catches back up (lag 100-96=4 <= 10) → auto-rejoins the ISR.
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 3,
            fsynced_offset: 96,
        });
        assert_eq!(isr.membership(3), Some(IsrMembership::InSync));
        assert_eq!(isr.isr_size(), 3);
        // Now all three are in-sync: frontiers [100, 96, 95], 2nd largest = 96.
        assert_eq!(isr.quorum_commit(), Some(96));
    }

    #[test]
    fn lag_eviction_disabled_keeps_a_reporting_follower_in_sync() {
        let config = IsrConfig {
            min_isr: 2,
            max_lag_records: 0, // disabled
        };
        let mut isr = IsrTracker::new(1, &[2], config);
        isr.observe_leader_fsync(1_000_000);
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 1,
        });
        // Even an enormous lag keeps the follower in-sync when eviction is disabled.
        assert_eq!(isr.membership(2), Some(IsrMembership::InSync));
        assert_eq!(isr.isr_size(), 2);
    }

    // ----- the quorum-fsync ack-release gate -----

    #[test]
    fn the_gate_releases_an_ack_only_once_its_offset_is_quorum_committed() {
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();
        // Three produces parked at offsets 0, 1, 2 (the token here is just the offset for the test).
        let _ = gate.park(0, 0);
        let _ = gate.park(1, 1);
        let _ = gate.park(2, 2);
        assert_eq!(gate.pending_len(), 3);

        // Quorum-commit = 1 → offsets < 1 release → just offset 0.
        let released = gate.release_up_to(Some(1));
        assert_eq!(released, vec![0]);
        assert_eq!(gate.pending_len(), 2);

        // Re-driving at the SAME commit releases nothing new.
        assert!(gate.release_up_to(Some(1)).is_empty());

        // Quorum advances to 3 → offsets 1 and 2 release, in order.
        let released = gate.release_up_to(Some(3));
        assert_eq!(released, vec![1, 2]);
        assert_eq!(gate.pending_len(), 0);
    }

    #[test]
    fn the_gate_holds_an_out_of_order_duplicate_behind_its_fifo_predecessor() {
        // #917: a dedup-hit parks an OLD duplicate offset that can sit BELOW a higher already-parked
        // offset (a fresh produce pipelined between an original and its retry), so `pending` is no
        // longer non-decreasing. Each producer connection's acks are delivered in FIFO SUBMISSION
        // order (the client correlates replies by ARRIVAL POSITION, not by offset), so the duplicate
        // must be HELD behind the offset-6 ack submitted before it — releasing it early would re-order
        // that connection's ack stream and corrupt the client's position-indexed results.
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();
        // Token 100 = original at offset 5; token 6 = a fresh produce at offset 6; token 200 = the
        // dedup retry at offset 5, parked AFTER offset 6 (out of order).
        let _ = gate.park(5, 100);
        let _ = gate.park(6, 6);
        let _ = gate.park(5, 200);
        assert_eq!(gate.pending_len(), 3);

        // Quorum-commit = 6 → only the contiguous FIFO prefix releases: just the original offset-5 ack.
        // The out-of-order duplicate stays withheld behind the offset-6 ack (it cannot jump the queue).
        let released = gate.release_up_to(Some(6));
        assert_eq!(
            released,
            vec![100],
            "only the FIFO prefix releases; the duplicate waits behind its offset-6 predecessor"
        );
        assert_eq!(gate.pending_len(), 2);

        // When offset 6 commits (quorum 7), the offset-6 ack AND the duplicate behind it release, in
        // submission order — preserving the connection's FIFO ack stream. No double-release.
        assert_eq!(gate.release_up_to(Some(7)), vec![6, 200]);
        assert_eq!(gate.pending_len(), 0);
    }

    #[test]
    fn the_gate_releases_nothing_when_there_is_no_quorum() {
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();
        let _ = gate.park(0, 0);
        let _ = gate.park(1, 1);
        // No quorum (ISR below min_isr) → quorum_commit is None → NOTHING releases (no-false-ack).
        assert!(gate.release_up_to(None).is_empty());
        assert_eq!(
            gate.pending_len(),
            2,
            "the acks stay withheld, never falsely fired"
        );
    }

    #[test]
    fn a_capped_gate_refuses_a_park_past_its_backlog_cap() {
        // #864: a capped gate withholds at most `cap` acks; past it, `park` REFUSES (returns false) so the
        // caller fails the produce rather than buffering unboundedly while the ISR is below min_isr.
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::with_cap(2);
        assert!(gate.park(0, 0), "first park fits under the cap");
        assert!(gate.park(1, 1), "second park fills the cap");
        assert!(!gate.park(2, 2), "a third park is REFUSED at the cap");
        assert_eq!(
            gate.pending_len(),
            2,
            "the refused park allocated nothing past the cap"
        );

        // Draining below the cap re-admits parks (the backlog recovered when the quorum advanced).
        assert_eq!(gate.release_up_to(Some(1)), vec![0]);
        assert_eq!(gate.pending_len(), 1);
        assert!(
            gate.park(2, 2),
            "with a slot freed, a park is admitted again"
        );
        assert_eq!(gate.pending_len(), 2);
    }

    #[test]
    fn an_uncapped_gate_parks_without_bound() {
        // `new()` / `with_cap(0)` = unlimited (the single-node-shaped / test default): the cap only
        // engages for the clustered leader gate built with a non-zero cap.
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();
        for i in 0..1000u64 {
            assert!(gate.park(i, i), "an uncapped gate never refuses");
        }
        assert_eq!(gate.pending_len(), 1000);
    }
}

/// The in-process 3-NODE end-to-end quorum-fsync-ack test (the headline deliverable of #593): a real
/// leader log + two real follower logs, wired through the C2-I1 follower-fetch transport (#590) AND
/// the C2-I2 ISR / quorum-commit / ack-gate, asserting the durability win HOLDS over the actual
/// storage path — a `C2-fsync` `PubAck` is released ONLY after a QUORUM (2 of 3) has FSYNC'd the
/// record. This is the property that beats NATS R3 (quorum page-cache); here it is exercised against
/// genuine `fdatasync`-on-`Log::sync` frontiers, not mocks.
#[cfg(test)]
mod cluster_quorum_tests {
    use super::*;
    use crate::cluster::replication::{Follower, ReplicationLeader};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::{Offset, RecordFlags};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::{Append, Log, LogConfig};

    type TestLog = Log<InMemoryFs, ManualClock>;

    fn small_config() -> LogConfig {
        // A small segment cap so a handful of records rolls across segments (like the replication
        // tests), proving the quorum path works across segment boundaries, not just one active segment.
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn open_log() -> TestLog {
        Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).expect("log opens")
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

    /// Fetch ALL currently-committed records from the leader into `follower` (over the real C2-I1
    /// serve→apply path), `fdatasync`'ing them on the follower, and return the follower's new fsync'd
    /// frontier (its `next_offset` after the apply's `Log::sync`) — exactly what the follower would put
    /// in its [`AckReplicatedBody`] report.
    fn follower_catch_up_and_report_fsynced(
        leader_log: &TestLog,
        follower: &mut Follower<InMemoryFs, ManualClock>,
    ) -> u64 {
        let leader = ReplicationLeader::new(leader_log);
        let hw = leader.high_watermark().get();
        for _ in 0..(hw + 2) {
            if follower.next_fetch_offset().get() >= hw {
                break;
            }
            let req = follower.fetch_request(100, u32::MAX);
            let resp = leader.serve_fetch(&req).expect("leader serves fetch");
            // apply_fetch_response calls Log::sync (fdatasync) before returning, so the returned
            // next_offset is a DURABLE (fsync'd) frontier — that is what the report carries.
            follower
                .apply_fetch_response(&resp)
                .expect("follower applies + fsyncs the fetched batch");
        }
        follower.next_fetch_offset().get()
    }

    #[test]
    fn puback_releases_only_after_a_2_of_3_quorum_has_fdatasynced_the_record() {
        // ---- a real 3-node cluster: leader=1 + followers 2,3 ----
        let mut leader_log = open_log();
        let mut follower_2 = Follower::new(open_log());
        let mut follower_3 = Follower::new(open_log());

        // The leader is the ISR tracker owner; the produce-ack gate withholds C2-fsync PubAcks.
        let mut isr = IsrTracker::new(1, &[2, 3], IsrConfig::default());
        assert_eq!(isr.min_isr(), 2, "R=3 default min_isr = f+1 = 2");
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();

        // ---- the leader produces + LOCALLY fsyncs 5 records (the existing I2 ack-after-its-own-fsync) ----
        for i in 0..5u32 {
            leader_log.append(&rec(format!("r{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap(); // the leader's own group-commit fdatasync (I2)
        let leader_fsynced = leader_log.flushed_offset().get();
        assert_eq!(leader_fsynced, 5);
        isr.observe_leader_fsync(leader_fsynced);
        // Park each produce's C2-fsync ack (the leader has fsync'd locally; the CLUSTER gate still
        // withholds the wire PubAck until a quorum has fsync'd).
        for off in 0..5u64 {
            let _ = gate.park(off, off);
        }

        // ---- ONLY the leader has the records: ISR = {leader} (followers at 0, lag 5 < 1024 so they
        //      are technically in-sync-by-lag but their fsync'd frontier is 0) ----
        // The quorum-commit is the 2nd-largest fsync'd frontier of [5, 0, 0] = 0. So NOTHING below
        // offset 0 is committed → NO ack releases. THE assertion: an ack is NOT released when only the
        // leader holds the record.
        assert_eq!(isr.quorum_commit(), Some(0));
        let released = gate.release_up_to(isr.quorum_commit());
        assert!(
            released.is_empty(),
            "no PubAck may release while only the leader has fsync'd the records"
        );
        assert_eq!(gate.pending_len(), 5, "all 5 acks are still withheld");

        // ---- a SECOND replica (follower 2) fetches + fdatasyncs the records, then reports ----
        let f2_fsynced = follower_catch_up_and_report_fsynced(&leader_log, &mut follower_2);
        assert_eq!(f2_fsynced, 5, "follower 2 has fdatasync'd all 5 records");
        let applied = isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: f2_fsynced,
        });
        assert!(applied);

        // Now TWO replicas (leader@5, follower2@5) have fsync'd through offset 5 → quorum-commit (2nd
        // largest of [5, 5, 0]) = 5. Every produce at offset < 5 is fsync'd-on-a-quorum.
        assert_eq!(
            isr.quorum_commit(),
            Some(5),
            "with a 2-of-3 fsync quorum the commit offset advances to 5"
        );
        let released = gate.release_up_to(isr.quorum_commit());
        assert_eq!(
            released,
            vec![0, 1, 2, 3, 4],
            "all 5 PubAcks release IN ORDER once a 2nd replica has fdatasync'd the records"
        );
        assert_eq!(gate.pending_len(), 0, "every ack released exactly once");

        // ---- the THIRD replica catching up later is a clean no-op for already-released acks ----
        let f3_fsynced = follower_catch_up_and_report_fsynced(&leader_log, &mut follower_3);
        assert_eq!(f3_fsynced, 5);
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 3,
            fsynced_offset: f3_fsynced,
        });
        assert_eq!(isr.quorum_commit(), Some(5));
        assert!(
            gate.release_up_to(isr.quorum_commit()).is_empty(),
            "re-driving after the 3rd replica catches up releases nothing new"
        );

        // ---- and the records are byte-identical on all three replicas (the C2-I1 contract holds) ----
        let leader_recs = leader_log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(
            follower_2.log().read_from(Offset::ZERO, 100).unwrap(),
            leader_recs
        );
        assert_eq!(
            follower_3.log().read_from(Offset::ZERO, 100).unwrap(),
            leader_recs
        );
        assert_eq!(leader_recs.len(), 5);
    }

    #[test]
    fn below_min_isr_a_c2_fsync_produce_blocks_rather_than_falsely_acking() {
        // THE durability guarantee: when the ISR drops below min_isr, a C2-fsync produce CANNOT be
        // quorum-committed → its PubAck BLOCKS (stays withheld) rather than firing on a sub-quorum
        // basis. The honest unavailable-over-unsafe choice.
        let config = IsrConfig {
            min_isr: 2,
            max_lag_records: 3,
        };
        let mut leader_log = open_log();
        let mut isr = IsrTracker::new(1, &[2, 3], config);
        let mut gate: QuorumAckGate<u64> = QuorumAckGate::new();

        // The leader produces + locally fsyncs 10 records.
        for i in 0..10u32 {
            leader_log.append(&rec(format!("x{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap();
        isr.observe_leader_fsync(leader_log.flushed_offset().get());
        for off in 0..10u64 {
            let _ = gate.park(off, off);
        }

        // Both followers are far behind (fsync'd only offset 1, lag 9 >> 3) → BOTH evicted → ISR = 1.
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 1,
        });
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 3,
            fsynced_offset: 1,
        });
        assert_eq!(
            isr.isr_size(),
            1,
            "both lagging followers evicted → ISR is leader-only"
        );
        assert!(!isr.meets_min_isr());
        assert_eq!(
            isr.quorum_commit(),
            None,
            "below min_isr there is NO quorum-commit offset"
        );

        // The ack-gate releases NOTHING: the producer blocks (the records are durable on the leader,
        // but they are NOT fsync'd-on-a-quorum, so an R-ack would be a lie).
        let released = gate.release_up_to(isr.quorum_commit());
        assert!(released.is_empty());
        assert_eq!(
            gate.pending_len(),
            10,
            "no false ack below min_isr: all 10 acks stay withheld until a quorum is restored"
        );

        // Restore the ISR: a follower catches back up (fsync'd offset 8, lag 2 <= 3) → rejoins → quorum
        // restored → the now-quorum-committed acks release. The block was temporary + honest, never a
        // false ack.
        isr.observe_follower_report(&AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 8,
        });
        assert!(
            isr.meets_min_isr(),
            "the ISR is back at min_isr once a follower catches up"
        );
        assert_eq!(isr.quorum_commit(), Some(8));
        let released = gate.release_up_to(isr.quorum_commit());
        assert_eq!(
            released,
            (0..8).collect::<Vec<u64>>(),
            "once a quorum is restored, only the now-quorum-fsync'd acks release"
        );
        assert_eq!(
            gate.pending_len(),
            2,
            "offsets 8 and 9 are not yet quorum-fsync'd"
        );
    }

    #[test]
    fn single_node_ack_is_byte_identical_no_cluster_engages() {
        // The Edge-First non-negotiable: with no cluster, the ISR / quorum path NEVER engages and the
        // produce ack is the existing local-fsync ack (I2). A standalone log produced + synced the
        // ordinary way is byte-for-byte what it always was; constructing the cluster types does not
        // perturb it (they are a separate, opt-in layer). Two independent single-node logs with the
        // same input are byte-identical, with or without the ISR types linked.
        let mut a = open_log();
        let mut b = open_log();
        for i in 0..12u32 {
            let p = format!("plain-{i}");
            a.append(&rec(p.as_bytes())).unwrap();
            b.append(&rec(p.as_bytes())).unwrap();
        }
        a.sync().unwrap();
        b.sync().unwrap();
        // The single-node durable head is the plain local-fsync flushed offset — no quorum, no gate.
        assert_eq!(a.flushed_offset().get(), 12);
        assert_eq!(a.flushed_offset(), b.flushed_offset());
        // Constructing an ISR tracker / gate over the standalone node changes nothing: with no
        // followers and min_isr=1 the quorum-commit is just the leader's own fsync'd frontier — i.e.
        // the C2-fsync gate DEGENERATES to the local-fsync I2 ack (the n=1 byte-identical path).
        let mut isr = IsrTracker::new(
            1,
            &[],
            IsrConfig {
                min_isr: 1,
                max_lag_records: 0,
            },
        );
        isr.observe_leader_fsync(a.flushed_offset().get());
        assert_eq!(isr.isr_size(), 1);
        assert!(isr.meets_min_isr());
        assert_eq!(
            isr.quorum_commit(),
            Some(12),
            "n=1: the quorum-commit IS the leader's own local-fsync frontier (I2), byte-identical"
        );
    }
}
