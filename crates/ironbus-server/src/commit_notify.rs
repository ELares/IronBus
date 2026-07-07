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
use std::time::Duration;

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
    pub fn wait_for_change(&self, snapshot: u64, timeout: Duration) {
        let guard = self
            .seq
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // `wait_timeout_while` re-checks the predicate on every (spurious or real) wake and on entry,
        // so a generation that already advanced past `snapshot` returns without parking. The returned
        // guard/timeout result is not needed: the caller re-polls unconditionally after this returns.
        let _ = self
            .cv
            .wait_timeout_while(guard, timeout, |seq| *seq == snapshot)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}
