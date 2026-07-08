// SPDX-License-Identifier: MIT OR Apache-2.0
//! The commit-notify wakeup seam for event-driven consume long-poll (push delivery).
//!
//! An idle consumer that polls an empty group today returns an empty batch and is re-polled by the
//! client on a timer — a latency floor of one client poll interval per idle window. This seam lets a
//! consumer BLOCK briefly on the broker instead: it snapshots a generation counter, polls once, and if
//! it drew nothing it waits on a [`Condvar`] until the append actor signals that the DURABLE frontier
//! advanced (a record committed) OR the wait times out, then re-polls exactly once. The wake is a pure,
//! additive overlay on the unchanged consume path: it never reorders, leases, or emits anything; it
//! only decides WHEN the existing poll runs again.
//!
//! GRANULARITY IS GLOBAL for v1 (one counter per engine, not per stream/group): any commit wakes every
//! waiter. A spurious cross-stream wakeup simply re-polls empty and (if still within budget) waits
//! again, which is byte-for-byte what a timer-driven re-poll does today, so global granularity is
//! correct, only slightly less selective than a future per-stream refinement. The counter is a
//! monotonically-increasing generation, so a bump that lands BETWEEN a waiter's snapshot and its wait
//! can never be lost (the predicate `*seq == snapshot` is already false, so `wait_timeout_while`
//! returns without parking) — the standard lost-wakeup-safe condvar protocol.
//!
//! NAMED-STREAM SCOPE (v1): the actor bumps only on the DEFAULT/root log's `flushed_offset` advancing,
//! so a consumer long-polling a NAMED stream (#588 — its own per-stream log) gets NO early wakeup and
//! falls back to its budget timeout. That is correct (it re-polls and delivers on timeout, exactly the
//! pre-push-delivery behavior) and is the same per-stream-granularity refinement noted above.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// The bounded busy-poll window a [`wait_for_change`](CommitNotify::wait_for_change) spins BEFORE
/// parking on the condvar (#1100), in microseconds — the exact parallel of the produce path's
/// `REPLY_SPIN_MICROS` (#1032, `actor.rs`). On the no-pre-ack-fsync tiers (memory backend or a relaxed
/// `interval`/`async`/`none` level) a produce becomes poll-visible within tens of microseconds, but a
/// waiter that parks straight onto the condvar eats a park/unpark round-trip whose scheduler-jitter
/// tail is the push-delivery p999 delivery regression (#1100: ~15 ms p999 vs ~1 ms push-OFF). Busy
/// re-reading the SAME generation the wait predicate checks for this small window catches that wake
/// WITHOUT the round-trip in the common case; the condvar park still backstops the remaining budget,
/// so lost-wakeup safety is byte-for-byte the pure-park path. Sized (100 us) to cover the
/// commit->frontier->bump hop on those tiers while wasting at most this much CPU on a spin that draws
/// nothing before it parks exactly as the historical path did.
const WAIT_SPIN_MICROS: u64 = 100;

/// The engine-wide commit-notify wakeup counter (#push-delivery). ONE per append actor, shared (via
/// `Arc`) between the actor thread (which [`bump`](CommitNotify::bump)s it whenever the durable poll
/// frontier advances) and every consumer connection thread (which
/// [`wait_for_change`](CommitNotify::wait_for_change)es on it while idle-long-polling).
///
/// The `seq` is a generation counter, not the frontier offset itself: the actor need not know any
/// waiter's cursor, and over-bumping is harmless (a woken waiter that finds nothing re-waits), so the
/// actor bumps on ANY frontier advance. Under-bumping would only cost latency (the waiter falls back to
/// its timeout), never correctness.
pub struct CommitNotify {
    /// The monotic wakeup generation. Bumped under the lock on every durable-frontier advance; read
    /// (snapshotted) by a waiter before it polls, and compared inside the wait predicate.
    seq: Mutex<u64>,
    /// Signalled on every [`bump`](CommitNotify::bump) so a parked waiter re-checks the predicate.
    cv: Condvar,
}

impl CommitNotify {
    /// A fresh notify at generation 0, wrapped in an `Arc` so the actor and every connection share the
    /// one instance.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(CommitNotify {
            seq: Mutex::new(0),
            cv: Condvar::new(),
        })
    }

    /// The CURRENT wakeup generation, snapshotted by a waiter BEFORE it runs its poll batch so a bump
    /// that lands between the snapshot and the wait is not lost (the wait predicate observes the
    /// advanced counter and returns immediately).
    #[must_use]
    pub fn seq(&self) -> u64 {
        *self
            .seq
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Advance the generation and wake every parked waiter. Called by the append actor STRICTLY AFTER
    /// the durability work that advanced the poll-visible frontier (pure observation — it never
    /// reorders the actor's own statements). Over-bumping is harmless.
    pub fn bump(&self) {
        {
            let mut seq = self
                .seq
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *seq = seq.wrapping_add(1);
        }
        // Notify AFTER dropping the lock so a woken waiter does not immediately contend on it.
        self.cv.notify_all();
    }

    /// Block until the generation moves off `snapshot` (a commit happened) or `timeout` elapses,
    /// whichever comes first. Returns as soon as the predicate is false, so a bump racing the snapshot
    /// is never lost. A spurious condvar wake with an unchanged generation simply re-parks until the
    /// deadline — the caller re-polls at most once regardless.
    ///
    /// `spin` gates a bounded busy-poll BEFORE the condvar park (#1100), threaded from the caller as the
    /// produce path's spin discriminant (`!commit_syncs_before_ack()`, #1032/#1026): `true` on the
    /// no-pre-ack-fsync tiers where a commit is poll-visible within microseconds — there this catches
    /// the wake without the park/unpark round-trip that drove the p999 delivery tail — and `false` on
    /// the fsync-barrier `sync` tier where a commit is milliseconds away, so spinning would only burn a
    /// core and this is byte-for-byte the historical straight-to-park.
    pub fn wait_for_change(&self, snapshot: u64, timeout: Duration, spin: bool) {
        let start = Instant::now();
        // Bounded spin-before-park (#1100). This is a PURE optimization layered on the unchanged
        // condvar park below: the spin only re-reads `seq` — the SAME generation the wait predicate
        // checks — so a bump it MISSES is still caught by the predicate (which then returns without
        // parking), and a bump it SEES returns immediately with no park at all. Lost-wakeup safety is
        // therefore identical to the pure-park path; the spin can only ever SHORTEN the wait.
        if spin {
            let spin_deadline = start + Duration::from_micros(WAIT_SPIN_MICROS);
            loop {
                // Re-read the generation under the same lock the predicate uses. A move off `snapshot`
                // means a commit landed during the spin: return WITHOUT parking (the caller re-polls).
                if self.seq() != snapshot {
                    return;
                }
                if Instant::now() >= spin_deadline {
                    break;
                }
                std::hint::spin_loop();
            }
        }
        // Park for the REMAINING budget (the spin, if any, already burned `start.elapsed()`). The
        // condvar backstops every wake the spin did not catch: `wait_timeout_while` re-checks the
        // predicate on entry and on every (spurious or real) wake, so a generation that already
        // advanced past `snapshot` — including a bump that raced the snapshot or landed just after the
        // spin window — returns without parking. The returned guard/timeout result is not needed: the
        // caller re-polls unconditionally after this returns.
        let remaining = timeout.saturating_sub(start.elapsed());
        let guard = self
            .seq
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = self
            .cv
            .wait_timeout_while(guard, remaining, |seq| *seq == snapshot)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generation that ALREADY advanced past the snapshot returns at once on the spin path — the
    /// first spin re-read observes `seq != snapshot` and never touches the condvar. (The pure-park
    /// path returns immediately here too via the entry predicate; this pins the spin fast path.)
    #[test]
    fn spin_returns_immediately_when_the_generation_already_advanced() {
        let notify = CommitNotify::new();
        let snapshot = notify.seq();
        notify.bump(); // seq is now != snapshot BEFORE the wait
        let start = Instant::now();
        notify.wait_for_change(snapshot, Duration::from_secs(30), /* spin */ true);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a pre-advanced generation must return at once, not park to the 30 s budget; took {:?}",
            start.elapsed()
        );
    }

    /// A bump that lands DURING the wait is observed and returns far below the (huge) budget — the
    /// headline #1100 case: a commit racing an idle long-poll wakes it promptly (via the spin re-read
    /// in the common case, or the condvar backstop if the spin window elapsed first), never at the
    /// timeout. Runs on BOTH gate settings to prove the wake fires regardless of the spin tier.
    #[test]
    fn a_generation_change_during_the_wait_is_observed_well_below_the_budget() {
        for spin in [true, false] {
            let notify = CommitNotify::new();
            let snapshot = notify.seq();
            let bumper = Arc::clone(&notify);
            let jh = std::thread::spawn(move || {
                // Land the commit inside the wait, after it has begun (past the ~100 us spin window on
                // the spin path, so this also exercises the condvar backstop, not only the busy-poll).
                std::thread::sleep(Duration::from_millis(20));
                bumper.bump();
            });
            let start = Instant::now();
            notify.wait_for_change(snapshot, Duration::from_secs(30), spin);
            let elapsed = start.elapsed();
            jh.join().unwrap();
            assert!(
                elapsed < Duration::from_secs(5),
                "a bump during the wait (spin={spin}) must wake it well below the 30 s budget, \
                 not at the timeout; took {elapsed:?}"
            );
        }
    }

    /// With spin ENABLED but NO commit, the spin exhausts and the condvar park still backstops the
    /// full budget — the wait times out at ~`timeout`, it does not busy-spin-return early. Proves the
    /// spin never swallows the timeout contract (a broken fall-through would return in ~100 us).
    #[test]
    fn spin_still_backstops_on_the_condvar_and_times_out_without_a_commit() {
        let notify = CommitNotify::new();
        let snapshot = notify.seq();
        let budget = Duration::from_millis(120);
        let start = Instant::now();
        notify.wait_for_change(snapshot, budget, /* spin */ true);
        let elapsed = start.elapsed();
        // At least the budget minus the spin window (and a slack for coarse timer granularity): the
        // park must dominate, so this is FAR above the 100 us spin — proving the spin fell through to
        // the condvar rather than returning early.
        assert!(
            elapsed >= budget.saturating_sub(Duration::from_millis(20)),
            "with no commit the spin must fall into the condvar park and honor the budget; \
             took {elapsed:?} for a {budget:?} budget"
        );
    }
}
