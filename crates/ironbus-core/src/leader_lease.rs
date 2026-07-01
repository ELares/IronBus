// SPDX-License-Identifier: MIT OR Apache-2.0
//! The cluster leader epoch + a time-bounded leadership lease (V2-C1, #582).
//!
//! This is the cluster-wide generalization of [`lease.rs`](crate::lease)'s per-consumer
//! generation fencing. Where a [`LeaseToken`](crate::lease::LeaseToken) fences a stale
//! message holder by its `generation`, a [`LeaderEpoch`] fences a stale *leader* by its
//! epoch: Raft's Election Safety gives at most one leader per epoch (per term), so a
//! strictly-increasing epoch is a cluster-wide fencing token — a leader carrying an old
//! epoch cannot supersede one carrying a newer epoch.
//!
//! On top of the epoch sits a [`LeaderLease`]: a leader holds leadership for only a bounded
//! lease, measured on the **monotonic** clock (the I6 seam — never the wall clock, so an NTP
//! step or a backwards wall jump cannot extend or shorten a lease). Once the lease expires a
//! stale leader is fenced: it must stop acting (and, later in C6, stop serving local reads)
//! until it renews. This is the cluster analogue of a message lease's visibility deadline.
//!
//! The type is PURE and IO-free, exactly like [`lease.rs`](crate::lease) and
//! [`clock.rs`](crate::clock): the caller supplies the monotonic `now` (in nanoseconds, from
//! the [`Clock`](crate::clock::Clock) seam) on every call. It holds NO clock and does NO IO,
//! so it composes with the single-writer actor without coloring the data path and stays
//! inside `ironbus-core`'s IO-free guarantee. Ordering NEVER consults the wall clock.

use core::cmp::Ordering;

/// The cluster-wide leader epoch: a strictly-increasing fencing token, one per leadership.
///
/// It is exactly the Raft term surfaced as a fencing token. Election Safety ("at most one
/// leader can be elected in a given term") means at most one leader exists per epoch, so a
/// total order on epochs is a total order on leaderships: a write/commit stamped with an
/// older epoch is fenced by one stamped with a newer epoch. This generalizes the per-lease
/// `generation` of [`LeaseToken`](crate::lease::LeaseToken) from one consumer's message to
/// the whole cluster's leadership.
///
/// Epoch `0` is the genesis / "no leadership yet" sentinel: a fresh group that has never
/// elected a leader is at epoch 0, which is strictly below every real leadership epoch (Raft
/// terms start at 1 on the first election), so any real leader fences the genesis state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct LeaderEpoch(u64);

impl LeaderEpoch {
    /// The genesis epoch: no leadership has been established. Strictly below every real
    /// leadership epoch, so it is fenced by any elected leader.
    pub const GENESIS: LeaderEpoch = LeaderEpoch(0);

    /// Wraps a raw term/epoch value (the Raft term) as a [`LeaderEpoch`].
    #[must_use]
    pub const fn new(epoch: u64) -> LeaderEpoch {
        LeaderEpoch(epoch)
    }

    /// The raw epoch value (the Raft term).
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// True if this epoch is at or below `other` — i.e. a write stamped with `self` is
    /// FENCED by a leadership at `other`. A strictly-greater epoch is never fenced by a
    /// lesser one; equal epochs are the same leadership (Election Safety: one leader per
    /// epoch) and so are NOT superseded by each other.
    #[must_use]
    pub const fn is_fenced_by(self, other: LeaderEpoch) -> bool {
        self.0 < other.0
    }
}

impl From<u64> for LeaderEpoch {
    fn from(epoch: u64) -> LeaderEpoch {
        LeaderEpoch(epoch)
    }
}

/// The outcome of observing a (possibly-newer) leadership epoch against the current one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochObservation {
    /// The observed epoch is strictly newer: leadership advanced. The previous leader (and
    /// any write it had not yet committed) is now fenced.
    Advanced {
        /// The epoch that was current before this observation.
        previous: LeaderEpoch,
        /// The new, strictly-greater current epoch.
        current: LeaderEpoch,
    },
    /// The observed epoch equals the current one: the same leadership, no change.
    Unchanged,
    /// The observed epoch is strictly OLDER than the current one: a stale leader. It is
    /// fenced — its observation is rejected and the current epoch is left untouched.
    Stale {
        /// The current (newer) epoch that fences the stale observation.
        current: LeaderEpoch,
        /// The stale epoch that was observed and rejected.
        observed: LeaderEpoch,
    },
}

/// A time-bounded leadership lease, fenced by a [`LeaderEpoch`] and a MONOTONIC deadline.
///
/// A leader establishes a lease at the monotonic time it (re)affirms leadership; the lease
/// is valid for `lease_nanos` of monotonic time. While valid, the holder may act as leader
/// (commit metadata, later serve local reads in C6). Once `now` reaches the deadline the
/// lease is EXPIRED and the holder is fenced: it must renew (which it can only do while still
/// the Raft leader) before acting again. A leader that lost an election but has not yet
/// noticed (a partition, a pause) therefore stops acting once its lease lapses, bounding the
/// stale-leader window without consulting the wall clock.
///
/// This is the leadership analogue of a [`Lease`](crate::lease)'s visibility deadline: the
/// epoch is the cluster fencing token (the `generation`), and the monotonic deadline is the
/// visibility timeout. Like that table, the deadline is read from the monotonic clock and is
/// never derived from the wall clock, so an NTP step cannot move it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaderLease {
    epoch: LeaderEpoch,
    /// The monotonic time the current lease was granted (its budget is measured from here).
    granted_at: u64,
    /// The monotonic deadline at or past which the lease is expired.
    deadline: u64,
}

impl LeaderLease {
    /// Grants a fresh leadership lease at `epoch`, valid from monotonic time `now` for
    /// `lease_nanos`. The deadline saturates at `u64::MAX` so a huge window cannot wrap.
    ///
    /// A `lease_nanos` of zero yields an already-expired lease (the deadline equals `now`),
    /// which fences immediately; callers use a real, positive window (see [`DEFAULT_LEASE_MS`]).
    ///
    /// [`DEFAULT_LEASE_MS`]: LeaderLease::DEFAULT_LEASE_MS
    #[must_use]
    pub fn grant(epoch: LeaderEpoch, now: u64, lease_nanos: u64) -> LeaderLease {
        LeaderLease {
            epoch,
            granted_at: now,
            deadline: now.saturating_add(lease_nanos),
        }
    }

    /// The default leadership-lease window, 10 seconds. Comfortably longer than the Raft
    /// election timeout (so a stable leader renews well before its lease lapses) yet short
    /// enough to bound the stale-leader window. Callers pass an explicit window in
    /// nanoseconds; this is the suggested default expressed in milliseconds.
    pub const DEFAULT_LEASE_MS: u64 = 10_000;

    /// The leadership epoch (fencing token) this lease was granted under.
    #[must_use]
    pub const fn epoch(self) -> LeaderEpoch {
        self.epoch
    }

    /// The monotonic deadline at or past which the lease is expired.
    #[must_use]
    pub const fn deadline(self) -> u64 {
        self.deadline
    }

    /// True if the lease is still VALID at monotonic time `now`: `now` is strictly before the
    /// deadline. At or past the deadline the lease is expired and the holder is fenced. The
    /// deadline is exclusive, exactly like a message lease's visibility deadline.
    #[must_use]
    pub const fn is_valid(self, now: u64) -> bool {
        now < self.deadline
    }

    /// True if the lease has EXPIRED at monotonic time `now` (`now` is at or past the
    /// deadline). A stale leader whose lease has expired is fenced and must not act.
    #[must_use]
    pub const fn is_expired(self, now: u64) -> bool {
        !self.is_valid(now)
    }

    /// Renews the lease for another `lease_nanos` window from monotonic time `now`, but ONLY
    /// while it is still the SAME leadership (`epoch` matches) AND the current lease has not
    /// already expired. A leader renews its own lease on each heartbeat tick while it remains
    /// leader; once the lease lapses (or leadership changed epoch) renewal is refused and the
    /// caller must establish a NEW lease via [`grant`] under the new epoch.
    ///
    /// Returns `true` and extends the deadline on success; returns `false` (a no-op) if the
    /// epoch differs or the lease is already expired at `now`. Refusing to renew an expired
    /// lease keeps the fence one-directional: a leader that fell behind cannot silently
    /// resurrect a lapsed lease — it must win the next term and grant a fresh one.
    ///
    /// [`grant`]: LeaderLease::grant
    pub fn renew(&mut self, epoch: LeaderEpoch, now: u64, lease_nanos: u64) -> bool {
        if self.epoch != epoch || self.is_expired(now) {
            return false;
        }
        self.granted_at = now;
        self.deadline = now.saturating_add(lease_nanos);
        true
    }

    /// True if a write/commit stamped with `epoch` is FENCED by this lease's leadership at
    /// monotonic time `now`. A write is fenced when EITHER its epoch is older than the lease's
    /// epoch (a superseded leader) OR the lease itself has expired (even the current leader
    /// must stop acting once its lease lapses). Only a write under the SAME, still-VALID lease
    /// epoch is allowed through — the cluster analogue of [`LeaseTable::holds_active`].
    ///
    /// [`LeaseTable::holds_active`]: crate::lease::LeaseTable::holds_active
    #[must_use]
    pub const fn fences(self, epoch: LeaderEpoch, now: u64) -> bool {
        // Fenced if the writer's epoch is not the current leadership's, or if the lease lapsed.
        epoch.get() != self.epoch.get() || self.is_expired(now)
    }
}

/// Tracks the cluster leader epoch and the local leadership lease for one node, fencing stale
/// leaders. This is the per-node view the metadata group exposes to the rest of the broker so
/// later issues (C2 replication, C4 divergence, C6 local reads) can fence with the epoch and
/// the lease without reaching into raft-rs.
///
/// The epoch is the durable fencing token (it IS the Raft term, persisted in the metadata
/// log's `HardState`, so it survives a restart and is monotonic across leadership changes).
/// The lease is the volatile, monotonic-clock-bounded grant the LOCAL leader holds; it is not
/// persisted (a restart starts with no held lease, so a recovered node never acts as a stale
/// leader until it re-wins leadership and grants a fresh lease).
///
/// Pure and IO-free: the caller advances it with `(term, is_leader, now)` observations drawn
/// from the raft core and the monotonic clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeadershipTracker {
    epoch: LeaderEpoch,
    /// The local leadership lease, present only while this node is (or recently was) leader.
    lease: Option<LeaderLease>,
    /// The lease window granted/renewed on each successful observation, in monotonic nanos.
    lease_nanos: u64,
}

impl LeadershipTracker {
    /// A fresh tracker at the genesis epoch with no held lease, granting `lease_nanos`-wide
    /// leases.
    #[must_use]
    pub const fn new(lease_nanos: u64) -> LeadershipTracker {
        LeadershipTracker {
            epoch: LeaderEpoch::GENESIS,
            lease: None,
            lease_nanos,
        }
    }

    /// The current cluster leader epoch (the highest term this node has observed).
    #[must_use]
    pub const fn epoch(self) -> LeaderEpoch {
        self.epoch
    }

    /// The local leadership lease, if this node currently holds (or recently held) one.
    #[must_use]
    pub const fn lease(self) -> Option<LeaderLease> {
        self.lease
    }

    /// Records the raft core's current `(term, is_leader)` at monotonic time `now`, advancing
    /// the epoch monotonically and (re)granting or expiring the local lease.
    ///
    /// The epoch only ever moves FORWARD: a higher term advances it (and fences the prior
    /// leadership); an equal term is the same leadership; a LOWER term is a stale observation
    /// and is rejected without moving the epoch (the [`EpochObservation::Stale`] arm — the
    /// monotonicity guarantee).
    ///
    /// When this node IS the leader at the (advanced or unchanged) epoch, it grants a fresh
    /// lease (on an epoch advance) or renews the existing one (on an unchanged epoch) from
    /// `now`. When it is NOT the leader, any held lease is dropped — it stops acting as
    /// leader at once (it will also be fenced by its lease lapsing even if this observation
    /// is missed). Returns the [`EpochObservation`] so the caller can react to a leadership
    /// change.
    pub fn observe(&mut self, term: u64, is_leader: bool, now: u64) -> EpochObservation {
        let observed = LeaderEpoch::new(term);
        let outcome = match observed.cmp(&self.epoch) {
            Ordering::Greater => EpochObservation::Advanced {
                previous: self.epoch,
                current: observed,
            },
            Ordering::Equal => EpochObservation::Unchanged,
            Ordering::Less => {
                // A stale, lower term: fence it, do NOT regress the epoch or touch the lease.
                return EpochObservation::Stale {
                    current: self.epoch,
                    observed,
                };
            }
        };

        self.epoch = observed;

        if is_leader {
            // Renew the existing lease in place if it is the SAME epoch and still live; otherwise
            // (new epoch, no lease, or a lapsed one) grant a fresh lease under this epoch.
            let renewed = self
                .lease
                .as_mut()
                .is_some_and(|lease| lease.renew(observed, now, self.lease_nanos));
            if !renewed {
                self.lease = Some(LeaderLease::grant(observed, now, self.lease_nanos));
            }
        } else {
            // Not the leader: relinquish any held lease so this node stops acting at once.
            self.lease = None;
        }

        outcome
    }

    /// True if a write/commit stamped with `epoch` is FENCED at monotonic time `now`: either
    /// its epoch is below the current cluster epoch, or this node does not hold a still-valid
    /// lease under that epoch. A stale leader (old epoch, or a lapsed lease) cannot commit.
    #[must_use]
    pub fn fences(self, epoch: LeaderEpoch, now: u64) -> bool {
        // Below the known cluster epoch ⇒ fenced regardless of any lease.
        if epoch.is_fenced_by(self.epoch) {
            return true;
        }
        // At the current epoch: allowed ONLY if this node holds a valid lease under it.
        match self.lease {
            Some(lease) => lease.fences(epoch, now),
            None => true,
        }
    }

    /// True if this node may ACT as leader at monotonic time `now`: it holds a lease at the
    /// current epoch and that lease has not expired. Once the lease lapses this returns false
    /// even if the node still believes it is leader — the stale-leader fence.
    #[must_use]
    pub fn can_act_as_leader(self, now: u64) -> bool {
        matches!(self.lease, Some(lease) if lease.epoch() == self.epoch && lease.is_valid(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const LEASE: u64 = 1_000; // 1_000 ns lease window, so tests advance time in small integers.

    #[test]
    fn epoch_is_a_total_fencing_order() {
        let lo = LeaderEpoch::new(3);
        let hi = LeaderEpoch::new(4);
        assert!(
            lo.is_fenced_by(hi),
            "an older epoch is fenced by a newer one"
        );
        assert!(
            !hi.is_fenced_by(lo),
            "a newer epoch is never fenced by an older one"
        );
        assert!(!lo.is_fenced_by(lo), "the same epoch does not fence itself");
        assert!(
            LeaderEpoch::GENESIS.is_fenced_by(LeaderEpoch::new(1)),
            "genesis is fenced by the first real leadership"
        );
        assert_eq!(LeaderEpoch::GENESIS.get(), 0);
    }

    #[test]
    fn a_fresh_lease_is_valid_then_expires_on_the_monotonic_clock() {
        let lease = LeaderLease::grant(LeaderEpoch::new(1), 100, LEASE);
        assert_eq!(lease.deadline(), 1_100);
        assert!(lease.is_valid(100), "valid at grant time");
        assert!(lease.is_valid(1_099), "valid just before the deadline");
        assert!(!lease.is_valid(1_100), "the deadline is exclusive: expired");
        assert!(lease.is_expired(1_100));
        assert!(lease.is_expired(5_000), "stays expired");
    }

    #[test]
    fn a_zero_window_lease_is_born_expired() {
        let lease = LeaderLease::grant(LeaderEpoch::new(1), 42, 0);
        assert!(lease.is_expired(42), "a zero window fences immediately");
    }

    #[test]
    fn grant_deadline_saturates_and_never_wraps() {
        let lease = LeaderLease::grant(LeaderEpoch::new(1), u64::MAX - 1, u64::MAX);
        assert_eq!(
            lease.deadline(),
            u64::MAX,
            "saturates, never wraps backwards"
        );
        assert!(lease.is_valid(u64::MAX - 1));
    }

    #[test]
    fn renew_extends_only_the_same_live_epoch() {
        let mut lease = LeaderLease::grant(LeaderEpoch::new(2), 0, LEASE); // deadline 1_000
                                                                           // Renew at 500 under the same epoch: deadline pushed to 1_500.
        assert!(lease.renew(LeaderEpoch::new(2), 500, LEASE));
        assert_eq!(lease.deadline(), 1_500);
        // A different epoch cannot renew (it is a different leadership).
        assert!(!lease.renew(LeaderEpoch::new(3), 600, LEASE));
        assert_eq!(lease.deadline(), 1_500, "a foreign-epoch renew is a no-op");
        // Once expired, even the same epoch cannot renew: must grant fresh under a new term.
        assert!(!lease.renew(LeaderEpoch::new(2), 1_500, LEASE));
        assert!(lease.is_expired(1_500));
    }

    #[test]
    fn fences_a_stale_or_lapsed_writer() {
        let lease = LeaderLease::grant(LeaderEpoch::new(5), 0, LEASE); // valid [0, 1_000)
                                                                       // Same epoch, valid lease: NOT fenced.
        assert!(
            !lease.fences(LeaderEpoch::new(5), 500),
            "current leader within lease acts"
        );
        // Older epoch: fenced even while the lease is valid (a superseded leader).
        assert!(
            lease.fences(LeaderEpoch::new(4), 500),
            "an older epoch is fenced"
        );
        // Same epoch but the lease lapsed: fenced (even the current leader must stop).
        assert!(
            lease.fences(LeaderEpoch::new(5), 1_000),
            "a lapsed lease fences its own leader"
        );
    }

    // --- LeadershipTracker: the per-node epoch + lease seam the metadata group drives. ---

    #[test]
    fn epoch_is_strictly_monotonic_across_leadership_changes() {
        // The leader-epoch monotonicity property: across a sequence of (re)elections the epoch
        // only ever increases, never regresses — even if a stale, lower term is observed.
        let mut t = LeadershipTracker::new(LEASE);
        assert_eq!(t.epoch(), LeaderEpoch::GENESIS);

        // Term 1: this node wins. Epoch advances 0 -> 1.
        assert_eq!(
            t.observe(1, true, 0),
            EpochObservation::Advanced {
                previous: LeaderEpoch::GENESIS,
                current: LeaderEpoch::new(1),
            }
        );
        assert_eq!(t.epoch(), LeaderEpoch::new(1));

        // Term 2: leadership moves elsewhere (is_leader=false). Epoch advances 1 -> 2.
        assert_eq!(
            t.observe(2, false, 10),
            EpochObservation::Advanced {
                previous: LeaderEpoch::new(1),
                current: LeaderEpoch::new(2),
            }
        );
        assert_eq!(t.epoch(), LeaderEpoch::new(2));

        // A STALE observation of an old term 1 is fenced and does NOT regress the epoch.
        assert_eq!(
            t.observe(1, true, 20),
            EpochObservation::Stale {
                current: LeaderEpoch::new(2),
                observed: LeaderEpoch::new(1),
            }
        );
        assert_eq!(
            t.epoch(),
            LeaderEpoch::new(2),
            "a stale term never regresses the epoch"
        );

        // Re-observing the current term is Unchanged (the same leadership, Election Safety).
        assert_eq!(t.observe(2, false, 30), EpochObservation::Unchanged);
        assert_eq!(t.epoch(), LeaderEpoch::new(2));
    }

    #[test]
    fn at_most_one_leadership_acts_per_epoch_and_a_stale_leader_is_fenced() {
        // Election Safety surfaced as fencing: at any epoch only the holder of a VALID lease at
        // that epoch may act; a superseded (older-epoch) leader is always fenced.
        let mut leader = LeadershipTracker::new(LEASE);
        leader.observe(7, true, 0); // wins term 7, lease [0, 1_000)
        assert!(
            leader.can_act_as_leader(0),
            "the term-7 leader holds a valid lease"
        );
        // A write at the current epoch within the lease is allowed; an older-epoch write is fenced.
        assert!(
            !leader.fences(LeaderEpoch::new(7), 500),
            "the current leader's write commits"
        );
        assert!(
            leader.fences(LeaderEpoch::new(6), 500),
            "a stale term-6 write is fenced"
        );

        // Leadership advances to term 8 elsewhere: this node is no longer leader. It drops its
        // lease and can no longer act, and ANY write it would make is fenced by the new epoch.
        leader.observe(8, false, 100);
        assert!(
            !leader.can_act_as_leader(100),
            "a superseded node cannot act"
        );
        assert!(
            leader.fences(LeaderEpoch::new(7), 100),
            "its old-epoch write is fenced"
        );
    }

    #[test]
    fn a_post_expiry_stale_leader_is_fenced_on_the_monotonic_clock() {
        // The lease-expiry fence: a node that still BELIEVES it is leader (it never saw a newer
        // term — a partition) stops being able to act once its lease lapses on the monotonic
        // clock, with no wall-clock involvement and no newer epoch needed to fence it.
        let mut leader = LeadershipTracker::new(LEASE);
        leader.observe(3, true, 0); // lease [0, 1_000)
        assert!(leader.can_act_as_leader(500), "within the lease it may act");
        assert!(
            !leader.fences(LeaderEpoch::new(3), 500),
            "its write commits within the lease"
        );

        // The monotonic clock crosses the deadline with NO new observation (the partition): the
        // lease lapses, so the stale leader can no longer act and its write is now fenced.
        assert!(
            !leader.can_act_as_leader(1_000),
            "the lapsed lease fences the stale leader"
        );
        assert!(
            leader.fences(LeaderEpoch::new(3), 1_000),
            "a post-expiry write by the stale leader cannot commit"
        );
    }

    #[test]
    fn a_leader_renews_its_lease_across_ticks_and_keeps_acting() {
        // A stable leader re-observes the same term each heartbeat and renews its lease, so it
        // keeps acting indefinitely without the epoch changing — the steady-state path.
        let mut leader = LeadershipTracker::new(LEASE);
        leader.observe(4, true, 0); // lease [0, 1_000)
                                    // Renew at 800 (still leader, same term): lease extends to [800, 1_800).
        assert_eq!(leader.observe(4, true, 800), EpochObservation::Unchanged);
        assert!(
            leader.can_act_as_leader(1_500),
            "the renewed lease covers 1_500"
        );
        assert_eq!(
            leader.epoch(),
            LeaderEpoch::new(4),
            "renewal never changes the epoch"
        );
    }

    #[test]
    fn losing_leadership_drops_the_lease_at_once() {
        let mut node = LeadershipTracker::new(LEASE);
        node.observe(2, true, 0);
        assert!(node.lease().is_some());
        // Same term, but no longer the leader: the lease is dropped immediately (a step-down).
        node.observe(2, false, 100);
        assert!(
            node.lease().is_none(),
            "stepping down relinquishes the lease at once"
        );
        assert!(!node.can_act_as_leader(100));
    }

    #[test]
    fn the_n1_degenerate_case_grants_a_trivial_lease() {
        // n=1: the lone voter self-elects at term 1 and trivially holds the only lease at epoch
        // 1 — there is no other leadership to fence, so the lease/epoch are degenerate but
        // consistent (the single-node path is unchanged behaviorally; this is pure bookkeeping).
        let mut solo = LeadershipTracker::new(LEASE);
        solo.observe(1, true, 0);
        assert_eq!(solo.epoch(), LeaderEpoch::new(1));
        assert!(solo.can_act_as_leader(0));
        assert!(
            !solo.fences(LeaderEpoch::new(1), 0),
            "the lone leader is never fenced by itself"
        );
        // Re-tick keeps it the sole, unfenced leader.
        solo.observe(1, true, 1);
        assert!(solo.can_act_as_leader(1));
    }

    proptest! {
        /// Fold a RANDOM sequence of `(term, is_leader, now_delta)` observations into a single
        /// [`LeadershipTracker`], with `now` accumulated strictly non-decreasing (the monotonic
        /// clock seam), and after EVERY step assert the leader-epoch fencing invariants. Where
        /// the hand-rolled `#[test]`s above pin fixed interleavings, this drives the whole
        /// observation space (term up/equal/down × leadership flap × the renew-vs-grant and
        /// lease-expiry boundaries) — the cluster-level analogue of `lease.rs`'s proptest.
        #[test]
        fn folding_random_observations_upholds_the_leader_epoch_fences(
            steps in prop::collection::vec((0u8..8, any::<bool>(), 0u8..4), 0..64),
        ) {
            let mut t = LeadershipTracker::new(LEASE);
            let mut now: u64 = 0;

            for (term, is_leader, now_delta) in steps {
                let term = u64::from(term);
                now += u64::from(now_delta); // strictly non-decreasing monotonic time

                let prev_epoch = t.epoch();
                let prev_lease = t.lease();

                let outcome = t.observe(term, is_leader, now);

                // (1) Monotonicity: the epoch NEVER regresses across observations.
                prop_assert!(
                    t.epoch() >= prev_epoch,
                    "epoch regressed from {prev_epoch:?} to {:?}",
                    t.epoch()
                );

                if term < prev_epoch.get() {
                    // (2) A stale, lower-term observation is fenced: it returns `Stale` and leaves
                    // BOTH the epoch and the lease byte-identical to before the call.
                    prop_assert_eq!(
                        outcome,
                        EpochObservation::Stale {
                            current: prev_epoch,
                            observed: LeaderEpoch::new(term),
                        }
                    );
                    prop_assert_eq!(t.epoch(), prev_epoch, "a stale observation regressed the epoch");
                    prop_assert_eq!(t.lease(), prev_lease, "a stale observation mutated the lease");
                } else {
                    // A non-stale (>=) observation advances the epoch to exactly the observed term.
                    prop_assert_eq!(t.epoch(), LeaderEpoch::new(term));

                    // (5) A same-epoch step where this node is NOT the leader drops the lease, so
                    // it cannot act — the immediate step-down fence.
                    if !is_leader {
                        prop_assert_eq!(t.lease(), None, "a non-leader step must drop the lease");
                        prop_assert!(!t.can_act_as_leader(now));
                    }
                }

                // (3) Acting as leader IMPLIES a still-valid lease pinned to the current epoch.
                if t.can_act_as_leader(now) {
                    let lease = t.lease().expect("can_act_as_leader ⇒ a lease is held");
                    prop_assert_eq!(lease.epoch(), t.epoch());
                    prop_assert!(lease.is_valid(now));
                    // The exact complement of the fence: a valid lease-holder's write at its OWN
                    // current epoch must be allowed through (not fenced) — the acting path.
                    prop_assert!(
                        !t.fences(t.epoch(), now),
                        "a valid lease-holder's own-epoch write must not be fenced"
                    );
                }

                // (4) The fence: every epoch strictly BELOW the current one is fenced; and when
                // this node holds no valid lease, EVERY candidate epoch is fenced.
                let holds_valid_lease = t.can_act_as_leader(now);
                for e in 0..=t.epoch().get() + 2 {
                    let candidate = LeaderEpoch::new(e);
                    if e < t.epoch().get() {
                        prop_assert!(
                            t.fences(candidate, now),
                            "an older epoch {e} must be fenced at epoch {:?}",
                            t.epoch()
                        );
                    }
                    if !holds_valid_lease {
                        prop_assert!(
                            t.fences(candidate, now),
                            "with no valid lease, epoch {e} must be fenced"
                        );
                    }
                }
            }
        }
    }
}
