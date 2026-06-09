// SPDX-License-Identifier: MIT OR Apache-2.0
//! The lease lifecycle: SQS-style visibility-timeout delivery with generation fencing.
//!
//! A delivered message becomes in-flight for a visibility timeout. Only an explicit ack
//! removes it; if the timeout passes unacked, the next claim redelivers it (to a live
//! member). A `progress` call extends the deadline by one visibility window but never
//! past a hard cap measured from the start of the current delivery attempt, so a stuck
//! consumer cannot hold a message forever.
//!
//! Each grant stamps a strictly increasing generation token. ack and extend carry the
//! token they were issued under; an operation whose generation no longer matches the
//! current lease is fenced (a no-op). This is what makes cross-member reclaim race-free:
//! once a message is redelivered, the original holder's token is stale, so its late ack
//! cannot double-ack.
//!
//! The table is pure and IO-free: the caller supplies monotonic time (`now`, in
//! nanoseconds, from the clock seam) on each call. Across a restart the table is empty,
//! so every previously in-flight message is treated as expired and redelivered. Because
//! the table also resets its generation counter on a restart, fencing across a restart is
//! NOT self-sufficient here: the caller must invalidate pre-restart tokens through an
//! outer epoch (a server/connection generation), so a client cannot present a token
//! minted before the restart. The caller also bounds the table size through its
//! max-in-flight (no unbounded growth here), and drives expired leases through
//! claim/max-deliver so orphaned leases are eventually evicted.

use crate::types::Offset;
use std::collections::BTreeMap;

/// Visibility-timeout and hard-cap tunables, in nanoseconds of monotonic time.
///
/// A degenerate config is accepted but behaves as the clamp dictates: `hard_cap_nanos`
/// below `visibility_nanos` clamps every deadline to the (smaller) cap, and a zero
/// `visibility_nanos` or `hard_cap_nanos` makes a lease expire the instant it is granted
/// (continuous redelivery). Use the defaults unless you mean it.
#[derive(Clone, Copy, Debug)]
pub struct LeaseConfig {
    /// How long a delivered message stays in-flight before it may be redelivered.
    pub visibility_nanos: u64,
    /// The most a single delivery attempt's lease may be extended, from the attempt's
    /// start. `progress` never pushes the deadline past this. Should be at least
    /// `visibility_nanos`.
    pub hard_cap_nanos: u64,
}

impl LeaseConfig {
    /// The default visibility timeout, 30 seconds.
    pub const DEFAULT_VISIBILITY_MS: u64 = 30_000;
    /// The default hard cap, 5 minutes.
    pub const DEFAULT_HARD_CAP_MS: u64 = 300_000;

    /// Builds a config from millisecond values (converted to nanoseconds, saturating).
    #[must_use]
    pub fn from_millis(visibility_ms: u64, hard_cap_ms: u64) -> LeaseConfig {
        LeaseConfig {
            visibility_nanos: visibility_ms.saturating_mul(1_000_000),
            hard_cap_nanos: hard_cap_ms.saturating_mul(1_000_000),
        }
    }
}

impl Default for LeaseConfig {
    fn default() -> LeaseConfig {
        LeaseConfig::from_millis(
            LeaseConfig::DEFAULT_VISIBILITY_MS,
            LeaseConfig::DEFAULT_HARD_CAP_MS,
        )
    }
}

/// A fencing token issued with a lease grant. It is carried by ack and extend so a stale
/// operation (from a holder whose lease was already redelivered) can be rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseToken {
    /// The leased message's log offset.
    pub offset: Offset,
    /// The generation this lease was granted under.
    pub generation: u64,
}

#[derive(Clone, Copy, Debug)]
struct Lease {
    generation: u64,
    /// Monotonic time the current delivery attempt began (the hard cap is measured from
    /// here, and it resets on redelivery: each attempt gets its own extension budget).
    attempt_start: u64,
    deadline: u64,
    deliveries: u32,
}

/// The outcome of a [`LeaseTable::claim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// The lease was granted (a first delivery or a redelivery). `deliveries` is the
    /// attempt number, starting at 1; the caller consults it for the max-deliver / DLQ
    /// decision.
    Granted {
        /// The fencing token for this grant.
        token: LeaseToken,
        /// How many times this message has now been delivered.
        deliveries: u32,
    },
    /// The message is currently leased to a holder and its visibility has not expired.
    InFlight,
    /// The generation space is exhausted (after `u64::MAX` grants, unreachable in any
    /// real deployment). The table refuses to grant rather than reuse a generation, which
    /// would silently break fencing; this mirrors the loud-failure contract of
    /// [`Offset::checked_next`](crate::types::Offset::checked_next).
    Exhausted,
}

/// The outcome of a [`LeaseTable::ack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    /// The ack matched the current lease; the message is removed from the in-flight set.
    Acked,
    /// The token was stale (already acked, or redelivered under a newer generation); the
    /// ack is a no-op.
    Fenced,
}

/// The outcome of a [`LeaseTable::extend`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtendOutcome {
    /// The lease deadline was extended to the returned monotonic time.
    Extended(u64),
    /// The hard cap from the attempt start has been reached; the lease cannot be
    /// extended further and will expire.
    CapReached,
    /// The token was stale; the extend is a no-op.
    Fenced,
}

/// The outcome of a [`LeaseTable::nack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NackOutcome {
    /// The lease was requeued for redelivery at the returned monotonic deadline.
    Requeued {
        /// The monotonic time at which the message becomes reclaimable again.
        deadline: u64,
    },
    /// The token was stale; the nack is a no-op (the message already redelivered or was acked).
    Fenced,
    /// The generation space is exhausted; the nack is refused rather than reusing a token.
    Exhausted,
}

/// Tracks the in-flight leases for one work-group over a single log.
#[derive(Clone, Debug, Default)]
pub struct LeaseTable {
    config: LeaseConfig,
    leases: BTreeMap<u64, Lease>,
    next_generation: u64,
    /// The durable per-message attempt counts CARRIED across a restart (#358): `{offset ->
    /// attempt_count}` for offsets that were in flight (delivered but unacked) at the last
    /// checkpoint. The table is rebuilt empty on restart, so without this a redelivered message
    /// resets to attempt 1 and a poison record could redeliver past its `MaxDeliver` cap. When the
    /// FIRST post-restart [`LeaseTable::claim`] of such an offset grants, it resumes the lease's
    /// delivery count at `carried + 1` (this redelivery is the next attempt), then drops the entry,
    /// so the live lease owns the count from then on. Empty in steady state (every entry is consumed
    /// by the first redelivery), and bounded by the same `max_in_flight` window that bounds
    /// `leases`, so it never grows unbounded. Acked / committed-past offsets never redeliver (the
    /// cursor gates them), so a stale carried entry is simply never consumed; the snapshot is
    /// rebuilt from the live leases each checkpoint, so such an entry never persists.
    carried: BTreeMap<u64, u32>,
}

impl LeaseTable {
    /// A new, empty lease table.
    #[must_use]
    pub fn new(config: LeaseConfig) -> LeaseTable {
        LeaseTable {
            config,
            leases: BTreeMap::new(),
            next_generation: 0,
            carried: BTreeMap::new(),
        }
    }

    /// Seeds the durable per-message attempt counts CARRIED from a prior run (#358), so the next
    /// [`LeaseTable::claim`] of each offset resumes its delivery count instead of resetting to 1.
    /// Each `(offset, attempt)` says the message at `offset` had been delivered `attempt` times
    /// before the restart; the next claim grants it as attempt `attempt + 1` (the redelivery), so
    /// `MaxDeliver` routes it to the dead-letter queue after at least `MaxDeliver` attempts TOTAL
    /// across restarts (the count is durable on the checkpoint cadence, so a crash replays only the
    /// un-checkpointed tail, bounding it at `MaxDeliver` plus that tail; it never regresses below the
    /// durable floor, so a poison can no longer redeliver unboundedly across reboots). A zero `attempt` carries no information and is ignored (a fresh delivery is
    /// attempt 1 anyway). Called once on the durable-resume path at open, on a freshly-built (empty)
    /// table; the carried set is bounded by `max_in_flight`, the same window that bounds the leases.
    pub fn resume_attempts(&mut self, attempts: impl IntoIterator<Item = (u64, u32)>) {
        for (offset, attempt) in attempts {
            if attempt > 0 {
                self.carried.insert(offset, attempt);
            }
        }
    }

    /// The per-message attempt counts of the currently-in-flight leases, as `(offset, deliveries)`
    /// pairs in ascending-offset order (#358). This is the durable snapshot the server persists
    /// alongside the cursor checkpoint so the counts survive an unclean restart; it is bounded by
    /// `max_in_flight` (one pair per in-flight offset). Acked offsets have no lease, so they are
    /// absent: a clean ack clears the durable count. Pairs with `deliveries == 0` cannot occur (a
    /// granted lease is at least attempt 1).
    #[must_use]
    pub fn attempt_counts(&self) -> Vec<(u64, u32)> {
        self.leases
            .iter()
            .map(|(&off, lease)| (off, lease.deliveries))
            .collect()
    }

    /// The number of messages currently tracked as in-flight (granted but not yet acked,
    /// whether or not their visibility has expired).
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.leases.len()
    }

    /// Claims `offset` for delivery at monotonic time `now`. A free offset, or one whose
    /// lease has expired, is granted (a redelivery resets the attempt start and bumps the
    /// generation, fencing the previous holder, and increments the delivery count). An
    /// offset still actively leased returns [`Claim::InFlight`].
    pub fn claim(&mut self, offset: Offset, now: u64) -> Claim {
        let off = offset.get();
        if let Some(lease) = self.leases.get(&off) {
            if now < lease.deadline {
                return Claim::InFlight;
            }
        }
        let generation = self.next_generation;
        // Refuse rather than reuse a generation: a saturating counter would silently break
        // fencing, since a redelivery sharing the prior holder's generation double-acks.
        let Some(next_generation) = generation.checked_add(1) else {
            return Claim::Exhausted;
        };
        self.next_generation = next_generation;
        // The deadline never exceeds the hard cap from the attempt start, even when the
        // configured visibility window is larger than the cap, so the cap is a true bound.
        let deadline = now
            .saturating_add(self.config.visibility_nanos)
            .min(now.saturating_add(self.config.hard_cap_nanos));
        let deliveries = if let Some(lease) = self.leases.get_mut(&off) {
            // Redelivery: a new attempt under a fresh generation, fencing the prior holder.
            lease.generation = generation;
            lease.attempt_start = now;
            lease.deadline = deadline;
            lease.deliveries = lease.deliveries.saturating_add(1);
            lease.deliveries
        } else {
            // First claim of this offset in THIS table. If a durable attempt count was carried
            // across a restart (#358), this delivery resumes at `carried + 1` (the message had
            // been delivered `carried` times before the crash, and this redelivery is the next
            // attempt), so `MaxDeliver` counts across restarts. The entry is consumed here, so the
            // live lease owns the count from now on. Saturating-add keeps a pathological carried
            // value from wrapping; the count saturates at u32::MAX exactly as the in-memory path.
            let resumed = self
                .carried
                .remove(&off)
                .map_or(1, |prior| prior.saturating_add(1));
            self.leases.insert(
                off,
                Lease {
                    generation,
                    attempt_start: now,
                    deadline,
                    deliveries: resumed,
                },
            );
            resumed
        };
        Claim::Granted {
            token: LeaseToken { offset, generation },
            deliveries,
        }
    }

    /// Whether `offset` could be claimed at monotonic time `now`: it is free (no lease) or its
    /// current lease has expired (`now` is at or past the deadline), so the next [`claim`] would
    /// grant it rather than return [`Claim::InFlight`]. A non-mutating peek, unlike [`claim`]: the
    /// `key_shared` router (#64) consults the record's key to decide routing BEFORE committing a
    /// claim, so it needs to know an offset is claimable without consuming a generation on an
    /// offset it then declines to deliver.
    ///
    /// [`claim`]: LeaseTable::claim
    #[must_use]
    pub fn is_claimable(&self, offset: Offset, now: u64) -> bool {
        // Claimable unless a lease exists whose visibility window has NOT yet elapsed. Written as a
        // negated `matches!` (rather than `map_or(true, ..)` / the 1.82-only `is_none_or`) to stay
        // MSRV-1.78 clean without tripping a newer clippy's map-or-to-is-none-or suggestion.
        !matches!(self.leases.get(&offset.get()), Some(lease) if now < lease.deadline)
    }

    /// Acks the lease named by `token`, removing the message from the in-flight set. A
    /// token whose generation no longer matches (already acked, or redelivered) is
    /// fenced.
    pub fn ack(&mut self, token: &LeaseToken) -> AckOutcome {
        let off = token.offset.get();
        match self.leases.get(&off) {
            Some(lease) if lease.generation == token.generation => {
                self.leases.remove(&off);
                AckOutcome::Acked
            }
            _ => AckOutcome::Fenced,
        }
    }

    /// Extends the lease named by `token` by one visibility window from `now`, clamped to
    /// the hard cap from the attempt start. A stale token is fenced; a lease already at
    /// its cap returns [`ExtendOutcome::CapReached`].
    pub fn extend(&mut self, token: &LeaseToken, now: u64) -> ExtendOutcome {
        let off = token.offset.get();
        let visibility = self.config.visibility_nanos;
        let cap_nanos = self.config.hard_cap_nanos;
        match self.leases.get_mut(&off) {
            Some(lease) if lease.generation == token.generation => {
                let cap = lease.attempt_start.saturating_add(cap_nanos);
                if now >= cap {
                    ExtendOutcome::CapReached
                } else {
                    let deadline = now.saturating_add(visibility).min(cap);
                    lease.deadline = deadline;
                    ExtendOutcome::Extended(deadline)
                }
            }
            _ => ExtendOutcome::Fenced,
        }
    }

    /// The delivery count (attempt number, 1 for the first delivery) of the lease named by
    /// `token`, if the token still owns it. The server indexes the nack backoff schedule by
    /// this attempt number.
    #[must_use]
    pub fn deliveries(&self, token: &LeaseToken) -> Option<u32> {
        self.leases
            .get(&token.offset.get())
            .filter(|lease| lease.generation == token.generation)
            .map(|lease| lease.deliveries)
    }

    /// Whether `token` names a lease that is BOTH still owned by this exact generation AND not yet
    /// expired at monotonic time `now` (`now` is before its deadline). It is `false` once the lease
    /// was acked or redelivered under a newer generation (a generation mismatch), AND also once the
    /// lease's visibility window has elapsed (the deadline is at or before `now`), even though the
    /// generation still matches: an expired lease is reclaimable, so it no longer "actively" holds
    /// the message for its current holder. The per-consumer credit accounting (#65) uses this to
    /// free a consumer's slot the moment its lease expires, so the redelivery is recounted against
    /// whoever next claims it (which may be the same consumer). A no-op for an unknown offset.
    #[must_use]
    pub fn holds_active(&self, token: &LeaseToken, now: u64) -> bool {
        self.leases
            .get(&token.offset.get())
            .is_some_and(|lease| lease.generation == token.generation && now < lease.deadline)
    }

    /// Nacks the lease named by `token`: requeues the message for redelivery at `now` plus
    /// `delay_nanos`. The nacking holder is fenced with a fresh generation (so a later ack of
    /// the same token is rejected, which prevents a nack-then-ack from committing an
    /// unprocessed message), and the delivery count is kept so the next claim escalates it for
    /// the `MaxDeliver` decision. A stale token is a no-op.
    ///
    /// `delay_nanos` is a retry backoff, not an in-attempt visibility extension, so unlike
    /// `claim` and `extend` it is intentionally not clamped to the per-attempt hard cap: a
    /// nack ends the current attempt and schedules the next, which may legitimately fall
    /// further out than the visibility cap of a single attempt allows.
    pub fn nack(&mut self, token: &LeaseToken, now: u64, delay_nanos: u64) -> NackOutcome {
        let off = token.offset.get();
        // Confirm the token owns the current lease before consuming a generation.
        match self.leases.get(&off) {
            Some(lease) if lease.generation == token.generation => {}
            _ => return NackOutcome::Fenced,
        }
        let generation = self.next_generation;
        // Refuse rather than reuse a generation, exactly as `claim` does, so fencing holds.
        let Some(next_generation) = generation.checked_add(1) else {
            return NackOutcome::Exhausted;
        };
        self.next_generation = next_generation;
        let deadline = now.saturating_add(delay_nanos);
        if let Some(lease) = self.leases.get_mut(&off) {
            lease.generation = generation;
            lease.deadline = deadline;
        }
        NackOutcome::Requeued { deadline }
    }

    /// The delivery count (attempt number) of the lease at `offset` IF the next [`claim`] at `now`
    /// would be a REDELIVERY, else `None` (#402). A redelivery is what a claim produces when an
    /// existing lease has EXPIRED (its deadline is at or before `now`): the message was already
    /// delivered `deliveries` times and the next claim would be attempt `deliveries + 1`. Returns
    /// `None` for an offset with no lease (a FIRST delivery, never a redelivery to throttle) or one
    /// whose lease is still active (it is in-flight, not reclaimable). Used by the broker to decide
    /// whether to consult the retry budget BEFORE claiming, so a throttled redelivery is DEFERRED via
    /// [`defer_redelivery`] without consuming a generation or bumping the attempt count.
    ///
    /// [`claim`]: LeaseTable::claim
    /// [`defer_redelivery`]: LeaseTable::defer_redelivery
    #[must_use]
    pub fn pending_redelivery_attempt(&self, offset: Offset, now: u64) -> Option<u32> {
        match self.leases.get(&offset.get()) {
            Some(lease) if now >= lease.deadline => Some(lease.deliveries),
            _ => None,
        }
    }

    /// DEFERS a redelivery by re-arming an EXPIRED lease's deadline to `now + delay_nanos`, WITHOUT
    /// bumping the delivery count or the generation (#402): the retry-throttle SPACES OUT a redelivery
    /// storm rather than dropping any message, so an at-least-once message still redelivers later. It
    /// is a no-op (returns `false`) unless a lease at `offset` exists AND is expired at `now` (only an
    /// expired, reclaimable lease is a redelivery candidate); an active lease is left untouched. Unlike
    /// [`nack`], it does NOT consume a generation (no holder is being fenced: the prior attempt already
    /// expired) and does NOT change the attempt count, so the message's `MaxDeliver` budget is
    /// unaffected and only genuine deliveries count toward it. The deadline is NOT clamped to the
    /// per-attempt hard cap (like [`nack`], a deferral schedules the NEXT attempt, which may fall
    /// further out than one visibility window).
    ///
    /// [`nack`]: LeaseTable::nack
    pub fn defer_redelivery(&mut self, offset: Offset, now: u64, delay_nanos: u64) -> bool {
        match self.leases.get_mut(&offset.get()) {
            Some(lease) if now >= lease.deadline => {
                lease.deadline = now.saturating_add(delay_nanos);
                true
            }
            _ => false,
        }
    }

    /// The offsets whose visibility has expired at `now` (deadline at or before `now`),
    /// in ascending order. These are reclaimable: the janitor redelivers them by
    /// claiming them again.
    #[must_use]
    pub fn expired(&self, now: u64) -> Vec<Offset> {
        self.leases
            .iter()
            .filter(|(_, lease)| now >= lease.deadline)
            .map(|(&off, _)| Offset::new(off))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn off(n: u64) -> Offset {
        Offset::new(n)
    }

    fn cfg() -> LeaseConfig {
        // 30 ns visibility, 100 ns hard cap, so tests can advance time in small integers.
        LeaseConfig {
            visibility_nanos: 30,
            hard_cap_nanos: 100,
        }
    }

    fn token(claim: Claim) -> LeaseToken {
        match claim {
            Claim::Granted { token, .. } => token,
            other => panic!("expected a grant, got {other:?}"),
        }
    }

    #[test]
    fn a_nack_requeues_and_fences_the_holder() {
        let mut t = LeaseTable::new(cfg());
        let tok0 = token(t.claim(off(0), 0));
        // Nack at now=10 with a 5 ns delay: requeued to deadline 15.
        match t.nack(&tok0, 10, 5) {
            NackOutcome::Requeued { deadline } => assert_eq!(deadline, 15),
            other => panic!("expected Requeued, got {other:?}"),
        }
        // The nacking holder is fenced: its token can no longer ack.
        assert_eq!(t.ack(&tok0), AckOutcome::Fenced);
        // Reclaimable at the deadline; redelivery bumps the generation and the delivery count.
        assert_eq!(t.expired(15), vec![off(0)]);
        match t.claim(off(0), 15) {
            Claim::Granted {
                token: tok1,
                deliveries,
            } => {
                assert_eq!(deliveries, 2, "redelivery escalates the delivery count");
                assert_ne!(tok1.generation, tok0.generation);
            }
            other => panic!("expected Granted, got {other:?}"),
        }
    }

    #[test]
    fn a_stale_nack_is_fenced() {
        let mut t = LeaseTable::new(cfg());
        let tok0 = token(t.claim(off(0), 0));
        // Redeliver by re-claiming after expiry, so tok0 is now stale.
        let _ = t.claim(off(0), 1000);
        assert_eq!(t.nack(&tok0, 1000, 0), NackOutcome::Fenced);
    }

    #[test]
    fn pending_redelivery_attempt_only_for_an_expired_lease() {
        // The retry-throttle seam (#402): a redelivery candidate is an offset with an EXPIRED lease.
        let mut t = LeaseTable::new(cfg());
        // No lease yet: not a redelivery (a first claim, never throttled).
        assert_eq!(t.pending_redelivery_attempt(off(0), 0), None);
        let _tok0 = token(t.claim(off(0), 0));
        // Active lease (now < deadline 30): in-flight, not reclaimable, so not a redelivery candidate.
        assert_eq!(t.pending_redelivery_attempt(off(0), 10), None);
        // Past the deadline: the next claim would be attempt 2 (a redelivery), reporting the prior
        // attempt count (1).
        assert_eq!(t.pending_redelivery_attempt(off(0), 30), Some(1));
        assert_eq!(t.pending_redelivery_attempt(off(0), 1000), Some(1));
    }

    #[test]
    fn defer_redelivery_spaces_out_without_bumping_the_attempt_or_generation() {
        // THE no-data-loss core (#402): a deferral re-arms the deadline of an expired lease WITHOUT
        // bumping the delivery count or the generation, so the message redelivers LATER (spaced out)
        // and still counts only genuine deliveries toward MaxDeliver.
        let mut t = LeaseTable::new(cfg());
        let tok0 = token(t.claim(off(0), 0));
        // Expired at now=30. Defer by 100 ns: the deadline moves to 130, no claim consumed.
        assert!(
            t.defer_redelivery(off(0), 30, 100),
            "an expired lease defers"
        );
        // Not reclaimable until the deferred deadline; the original token is NOT fenced (no generation
        // was consumed), so the still-working holder could even ack it.
        assert_eq!(t.expired(30), Vec::<Offset>::new(), "deferred past now");
        assert_eq!(t.expired(129), Vec::<Offset>::new());
        assert_eq!(
            t.expired(130),
            vec![off(0)],
            "reclaimable at the deferred deadline"
        );
        // The delivery count was NOT bumped by the deferral: the next claim is attempt 2, exactly as
        // if the deferral had never happened (a deferral is not a delivery).
        match t.claim(off(0), 130) {
            Claim::Granted {
                token: tok1,
                deliveries,
            } => {
                assert_eq!(deliveries, 2, "the deferral did not count as a delivery");
                assert_ne!(tok1.generation, tok0.generation, "the claim still fences");
            }
            other => panic!("expected Granted, got {other:?}"),
        }
    }

    #[test]
    fn defer_redelivery_is_a_no_op_on_an_active_or_absent_lease() {
        // A deferral only touches an EXPIRED lease: an active lease (mid-attempt) and an absent offset
        // are left untouched, so the throttle never disturbs an in-flight delivery or a first claim.
        let mut t = LeaseTable::new(cfg());
        assert!(!t.defer_redelivery(off(0), 0, 100), "no lease: no-op");
        let tok0 = token(t.claim(off(0), 0));
        assert!(!t.defer_redelivery(off(0), 10, 100), "active lease: no-op");
        // The active lease still expires on its ORIGINAL schedule (deadline 30), untouched.
        assert!(t.holds_active(&tok0, 29));
        assert!(!t.holds_active(&tok0, 30));
    }

    #[test]
    fn deliveries_reports_the_attempt_for_a_live_token() {
        let mut t = LeaseTable::new(cfg());
        let tok0 = token(t.claim(off(0), 0));
        assert_eq!(t.deliveries(&tok0), Some(1));
        // Redeliver after expiry: attempt 2 under a fresh token; the old token is stale.
        let tok1 = token(t.claim(off(0), 1000));
        assert_eq!(t.deliveries(&tok1), Some(2));
        assert_eq!(t.deliveries(&tok0), None, "stale token has no live attempt");
        t.ack(&tok1);
        assert_eq!(t.deliveries(&tok1), None, "no lease after ack");
    }

    #[test]
    fn an_immediate_nack_is_reclaimable_at_once() {
        let mut t = LeaseTable::new(cfg());
        let tok0 = token(t.claim(off(0), 5));
        // delay 0: deadline becomes now, so it is expired immediately.
        assert_eq!(t.nack(&tok0, 5, 0), NackOutcome::Requeued { deadline: 5 });
        assert_eq!(t.expired(5), vec![off(0)]);
    }

    #[test]
    fn first_claim_grants_and_a_re_claim_while_active_is_in_flight() {
        let mut t = LeaseTable::new(cfg());
        let c = t.claim(off(7), 0);
        assert_eq!(
            c,
            Claim::Granted {
                token: LeaseToken {
                    offset: off(7),
                    generation: 0
                },
                deliveries: 1
            }
        );
        assert_eq!(t.in_flight(), 1);
        // Still within the visibility window: not deliverable to anyone else.
        assert_eq!(t.claim(off(7), 10), Claim::InFlight);
    }

    #[test]
    fn an_expired_lease_is_redelivered_with_a_new_generation_and_delivery_count() {
        let mut t = LeaseTable::new(cfg());
        let first = token(t.claim(off(7), 0));
        // Past the 30 ns visibility window.
        let second = t.claim(off(7), 40);
        assert_eq!(
            second,
            Claim::Granted {
                token: LeaseToken {
                    offset: off(7),
                    generation: 1
                },
                deliveries: 2
            }
        );
        assert_ne!(token(second).generation, first.generation);
    }

    #[test]
    fn holds_active_is_true_only_for_a_live_unexpired_owning_token() {
        // The per-consumer credit (#65) frees a slot when its lease is no longer ACTIVE:
        // holds_active must distinguish a live, unexpired, generation-matching lease (true) from an
        // expired one (false, even though the generation still matches), a superseded generation
        // (false), and an acked or unknown offset (false).
        let mut t = LeaseTable::new(cfg());
        let tok = token(t.claim(off(7), 0)); // deadline = 30
                                             // Live and unexpired within the window.
        assert!(t.holds_active(&tok, 10), "live and unexpired");
        assert!(t.holds_active(&tok, 29), "still before the deadline");
        // At and past the deadline: expired, so NOT active even though the generation matches.
        assert!(
            !t.holds_active(&tok, 30),
            "the deadline is exclusive: expired"
        );
        assert!(!t.holds_active(&tok, 40), "well past the deadline: expired");
        // Redeliver under a new generation: the old token is no longer active at any time.
        let tok2 = token(t.claim(off(7), 40)); // generation bumped, deadline = 70
        assert!(
            !t.holds_active(&tok, 50),
            "the old generation is superseded"
        );
        assert!(t.holds_active(&tok2, 50), "the new generation is active");
        // Ack the live lease: no lease remains, so holds_active is false.
        assert_eq!(t.ack(&tok2), AckOutcome::Acked);
        assert!(!t.holds_active(&tok2, 50), "no lease after ack");
        // An offset never leased is never active.
        assert!(!t.holds_active(&token_at(off(99), 0), 0), "unknown offset");
    }

    /// A bare token for an offset/generation, for `holds_active` negative cases (no claim needed).
    fn token_at(offset: Offset, generation: u64) -> LeaseToken {
        LeaseToken { offset, generation }
    }

    #[test]
    fn is_claimable_is_a_non_mutating_peek_of_claim() {
        // The key_shared router (#64) peeks claimability before reading a record's key, so
        // is_claimable must agree with what claim WOULD do, and must not consume a generation.
        let mut t = LeaseTable::new(cfg()); // visibility 30 -> deadline 30
        assert!(t.is_claimable(off(7), 0), "a free offset is claimable");
        let _ = t.claim(off(7), 0);
        assert!(
            !t.is_claimable(off(7), 10),
            "an active lease is not claimable"
        );
        assert!(!t.is_claimable(off(7), 29), "still within the window");
        assert!(
            t.is_claimable(off(7), 30),
            "claimable exactly at the deadline (claim would redeliver)"
        );
        // The peek did not mutate: the generation a real claim now gets is still 1, not bumped.
        match t.claim(off(7), 30) {
            Claim::Granted { token, deliveries } => {
                assert_eq!(token.generation, 1, "peeking never consumed a generation");
                assert_eq!(deliveries, 2);
            }
            other => panic!("expected a redelivery, got {other:?}"),
        }
    }

    #[test]
    fn ack_removes_the_lease_and_a_second_ack_is_fenced() {
        let mut t = LeaseTable::new(cfg());
        let tok = token(t.claim(off(7), 0));
        assert_eq!(t.ack(&tok), AckOutcome::Acked);
        assert_eq!(t.in_flight(), 0);
        assert_eq!(t.ack(&tok), AckOutcome::Fenced);
    }

    #[test]
    fn a_late_ack_after_redelivery_is_fenced_no_double_ack() {
        let mut t = LeaseTable::new(cfg());
        let original = token(t.claim(off(7), 0)); // member A, generation 0
        let redelivered = t.claim(off(7), 40); // member B, generation 1
                                               // A comes back and acks with its stale token: rejected.
        assert_eq!(t.ack(&original), AckOutcome::Fenced);
        // B's current token acks for real.
        assert_eq!(t.ack(&token(redelivered)), AckOutcome::Acked);
    }

    #[test]
    fn extend_defers_redelivery_but_never_past_the_hard_cap() {
        let mut t = LeaseTable::new(cfg());
        let tok = token(t.claim(off(7), 0)); // attempt_start 0, cap at 100
                                             // Extend at 20: new deadline 20 + 30 = 50.
        assert_eq!(t.extend(&tok, 20), ExtendOutcome::Extended(50));
        // Extend at 90: 90 + 30 = 120 would pass the cap, so it clamps to 100.
        assert_eq!(t.extend(&tok, 90), ExtendOutcome::Extended(100));
        // At or past the cap, no further extension.
        assert_eq!(t.extend(&tok, 100), ExtendOutcome::CapReached);
    }

    #[test]
    fn extend_with_a_stale_token_is_fenced() {
        let mut t = LeaseTable::new(cfg());
        let original = token(t.claim(off(7), 0));
        t.claim(off(7), 40); // redeliver, fencing `original`
        assert_eq!(t.extend(&original, 45), ExtendOutcome::Fenced);
    }

    #[test]
    fn expired_lists_only_past_deadline_leases_in_order() {
        let mut t = LeaseTable::new(cfg());
        t.claim(off(1), 0); // deadline 30
        t.claim(off(2), 100); // deadline 130
        t.claim(off(3), 0); // deadline 30
                            // At now=50: offsets 1 and 3 are expired, 2 is not.
        assert_eq!(t.expired(50), vec![off(1), off(3)]);
        assert_eq!(t.expired(0), Vec::<Offset>::new());
    }

    #[test]
    fn deliveries_increments_across_repeated_redeliveries() {
        let mut t = LeaseTable::new(cfg());
        let mut now = 0;
        for expected in 1..=4u32 {
            let c = t.claim(off(7), now);
            match c {
                Claim::Granted { deliveries, .. } => assert_eq!(deliveries, expected),
                other => panic!("should redeliver, got {other:?}"),
            }
            now += 40; // advance past each visibility window
        }
    }

    #[test]
    fn generation_exhaustion_refuses_to_grant_rather_than_reuse() {
        // At the generation ceiling, claim refuses instead of reusing a generation (which
        // would let a redelivery share the prior holder's token and double-ack).
        let mut t = LeaseTable::new(cfg());
        t.next_generation = u64::MAX;
        assert_eq!(t.claim(off(5), 0), Claim::Exhausted);
        assert_eq!(t.in_flight(), 0);
    }

    #[test]
    fn initial_grant_respects_the_hard_cap_even_when_visibility_is_larger() {
        let mut t = LeaseTable::new(LeaseConfig {
            visibility_nanos: 100,
            hard_cap_nanos: 30,
        });
        let tok = token(t.claim(off(7), 0));
        // The deadline is clamped to attempt_start + hard_cap = 30, not now + 100.
        assert!(t.expired(29).is_empty());
        assert_eq!(t.expired(30), vec![off(7)]);
        assert_eq!(t.extend(&tok, 10), ExtendOutcome::Extended(30));
        assert_eq!(t.extend(&tok, 30), ExtendOutcome::CapReached);
    }

    #[test]
    fn the_hard_cap_resets_per_delivery_attempt() {
        let mut t = LeaseTable::new(cfg()); // visibility 30, hard cap 100
        let tok1 = token(t.claim(off(7), 0)); // attempt 1: cap at 100
        assert_eq!(t.extend(&tok1, 90), ExtendOutcome::Extended(100));
        // Expire and redeliver at 200: attempt 2 gets a FRESH cap at 300.
        let tok2 = token(t.claim(off(7), 200));
        assert_eq!(t.extend(&tok2, 290), ExtendOutcome::Extended(300));
        assert_eq!(t.extend(&tok2, 300), ExtendOutcome::CapReached);
    }

    #[test]
    fn leases_for_different_offsets_are_independent() {
        let mut t = LeaseTable::new(cfg());
        let a = token(t.claim(off(1), 0));
        let b = token(t.claim(off(2), 0));
        assert_ne!(a.generation, b.generation);
        assert_eq!(t.ack(&a), AckOutcome::Acked);
        assert_eq!(t.in_flight(), 1); // b untouched
        assert_eq!(t.claim(off(2), 5), Claim::InFlight);
        assert_eq!(t.ack(&b), AckOutcome::Acked);
        assert_eq!(t.in_flight(), 0);
    }

    #[test]
    fn a_lease_is_reclaimable_exactly_at_its_deadline() {
        let mut t = LeaseTable::new(cfg()); // visibility 30 -> deadline 30
        t.claim(off(7), 0);
        assert_eq!(t.claim(off(7), 29), Claim::InFlight);
        match t.claim(off(7), 30) {
            Claim::Granted { deliveries, .. } => assert_eq!(deliveries, 2),
            other => panic!("at-deadline should redeliver, got {other:?}"),
        }
    }

    #[test]
    fn a_carried_attempt_count_resumes_the_delivery_count_across_a_restart() {
        // #358: a message delivered N-1 times before a restart resumes at attempt N, not 1, so a
        // fresh (restarted) table seeded with the carried count grants the next claim as N.
        let mut t = LeaseTable::new(cfg());
        // The message had been delivered 3 times before the crash.
        t.resume_attempts([(off(7).get(), 3)]);
        // The first claim after the restart is attempt 4 (the resumed count + 1), NOT 1.
        match t.claim(off(7), 0) {
            Claim::Granted { deliveries, .. } => assert_eq!(deliveries, 4, "resumes at attempt 4"),
            other => panic!("expected Granted, got {other:?}"),
        }
        // A different, un-carried offset still starts at attempt 1.
        match t.claim(off(8), 0) {
            Claim::Granted { deliveries, .. } => assert_eq!(deliveries, 1),
            other => panic!("expected Granted, got {other:?}"),
        }
        // The carried entry was consumed: a re-claim of 7 after expiry escalates from the live
        // lease (5), not from the carried value again.
        match t.claim(off(7), 1000) {
            Claim::Granted { deliveries, .. } => {
                assert_eq!(deliveries, 5, "escalates from the live lease");
            }
            other => panic!("expected Granted, got {other:?}"),
        }
    }

    #[test]
    fn attempt_counts_snapshots_the_live_leases_and_a_clean_ack_clears_it() {
        let mut t = LeaseTable::new(cfg());
        // Claim two offsets and redeliver one so its attempt count is 2.
        let _ = t.claim(off(1), 0);
        let tok2 = token(t.claim(off(2), 0));
        let _ = t.claim(off(2), 1000); // redeliver 2: now attempt 2 (tok2 is stale)
        let mut counts = t.attempt_counts();
        counts.sort_unstable();
        assert_eq!(counts, vec![(1, 1), (2, 2)]);
        // A clean ack of offset 1 removes its lease, so it drops out of the snapshot (the durable
        // count is cleared). tok2 is stale (offset 2 was redelivered), so re-fetch the live token.
        let live1 = LeaseToken {
            offset: off(1),
            generation: 0,
        };
        assert_eq!(t.ack(&live1), AckOutcome::Acked);
        let _ = tok2; // tok2 stays stale; we only assert offset 1 cleared.
        let counts = t.attempt_counts();
        assert_eq!(
            counts,
            vec![(2, 2)],
            "an acked offset clears its durable count"
        );
    }

    #[test]
    fn resume_attempts_ignores_a_zero_carried_count() {
        // A zero carried attempt carries no information (a fresh delivery is attempt 1 anyway), so
        // it must not be seeded; the next claim is attempt 1, the unchanged pre-#358 behavior.
        let mut t = LeaseTable::new(cfg());
        t.resume_attempts([(off(7).get(), 0)]);
        match t.claim(off(7), 0) {
            Claim::Granted { deliveries, .. } => assert_eq!(deliveries, 1),
            other => panic!("expected Granted, got {other:?}"),
        }
    }

    proptest! {
        /// However many times a message is redelivered, only the most recently issued
        /// token can ack: every earlier token is fenced. This is the no-double-ack
        /// guarantee under arbitrary redelivery depth.
        #[test]
        fn only_the_latest_token_ever_acks(n in 1usize..8) {
            let mut t = LeaseTable::new(cfg());
            let mut tokens = Vec::new();
            let mut now = 0u64;
            for _ in 0..n {
                if let Claim::Granted { token, .. } = t.claim(off(7), now) {
                    tokens.push(token);
                }
                now += 1000; // far past visibility, so each claim is a redelivery
            }
            prop_assert_eq!(tokens.len(), n);
            // Every stale token is fenced and leaves the lease in place.
            let (last, stale) = tokens.split_last().unwrap();
            for tok in stale {
                prop_assert_eq!(t.ack(tok), AckOutcome::Fenced);
            }
            prop_assert_eq!(t.in_flight(), 1);
            // The latest token acks exactly once.
            prop_assert_eq!(t.ack(last), AckOutcome::Acked);
            prop_assert_eq!(t.ack(last), AckOutcome::Fenced);
            prop_assert_eq!(t.in_flight(), 0);
        }
    }
}
