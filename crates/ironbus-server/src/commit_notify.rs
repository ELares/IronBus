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
//! GRANULARITY IS PER-STREAM (#1100 L2): the seam is NOT one global counter but a small registry of
//! per-stream [`StreamCell`]s, keyed by stream identity (`""` for the DEFAULT/root log, each named
//! stream #588 by its name). A commit on stream A bumps ONLY stream A's cell, so it wakes ONLY the
//! consumers waiting on A — not every idle consumer in the broker. This kills two L1 costs at once: the
//! `O(N-idle)` THUNDERING HERD (a single global `notify_all` woke every parked consumer on any commit,
//! each to re-poll empty and re-park); and the LOCK CONVOY on the one global `seq` mutex (every waiter
//! and the actor contended on it). A commit now touches exactly the committing stream's cell (its own
//! mutex + condvar), and consumers of unrelated streams never wake. It also lifts the L1 NAMED-STREAM
//! FLOOR: a named-stream commit bumps that stream's cell, so its long-poller wakes promptly instead of
//! always eating its full budget (L1 only observed the root log's frontier, so a named-stream consumer
//! never got an early wake).
//!
//! LOST-WAKEUP SAFETY IS PRESERVED PER STREAM. Each cell's generation is a monotonically-increasing
//! counter; a waiter snapshots ITS stream's generation BEFORE it polls, so a bump that lands BETWEEN
//! the snapshot and the wait can never be lost — the wait predicate observes the advanced counter and
//! returns without parking (the standard lost-wakeup-safe condvar protocol, now keyed to the
//! consumer's own stream). Over-bumping a stream is harmless (a woken waiter that still finds nothing
//! re-waits or times out); under-bumping only costs THAT stream's waiters a little latency.
//!
//! BROADCAST CORRECTNESS. The cell key is the STREAM (log), NOT the work-group or member: every
//! consumer of stream S — competing-group members AND broadcast subscribers alike — snapshots and
//! waits on the SAME cell for S, so one commit to S wakes ALL of them. Each then re-polls its own
//! group's cursor; a consumer whose group already drained simply re-waits (a harmless over-wake within
//! the stream, the same benign re-poll the global seam did, now scoped to the one stream).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The bounded busy-poll window a [`wait_for_change`](StreamCell::wait_for_change) spins BEFORE
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

/// ONE stream's wakeup cell (#1100 L2): the per-stream generation + condvar the append actor bumps
/// when THAT stream's durable poll frontier advances, and the consumers of THAT stream wait on. Shared
/// via `Arc` between the actor (which caches the handle and [`bump`](StreamCell::bump)s it) and every
/// connection long-polling the stream (which [`wait_for_change`](StreamCell::wait_for_change)es on it).
///
/// The generation is an [`AtomicU64`] so a waiter's spin-before-park re-check (#1100) reads it
/// LOCK-FREE — resolving L1's noted follow-up (L1 re-read the counter through the mutex) — while the
/// mutex/condvar back the park. It is written ONLY under `lock` (in [`bump`](StreamCell::bump)), which
/// is what keeps the condvar lost-wakeup protocol intact despite the lock-free read (see `bump`).
pub struct StreamCell {
    /// The monotonic wakeup generation for THIS stream. Read LOCK-FREE by the spin and the park
    /// predicate; incremented ONLY under `lock` (in `bump`). A `wrapping`/`fetch_add` bump between a
    /// waiter's snapshot and its wait can never be lost — the predicate observes `gen != snapshot`.
    gen: AtomicU64,
    /// The mutex the condvar pairs with. It guards NO data (the generation lives in `gen`); it exists
    /// solely to make a `bump`'s increment and a waiter's predicate-check mutually exclusive, which
    /// closes the lost-wakeup window: a bump can only land BEFORE a waiter checks the predicate (so the
    /// waiter sees the new generation and never parks) or AFTER the waiter has atomically parked (so
    /// the `notify_all` wakes it) — never in between, because both hold this lock around the
    /// increment / the predicate-and-park.
    lock: Mutex<()>,
    /// Signalled on every [`bump`](StreamCell::bump) of THIS cell, so ONLY this stream's parked
    /// waiters re-check their predicate.
    cv: Condvar,
}

impl StreamCell {
    /// A fresh cell at generation 0.
    fn new() -> Arc<StreamCell> {
        Arc::new(StreamCell {
            gen: AtomicU64::new(0),
            lock: Mutex::new(()),
            cv: Condvar::new(),
        })
    }

    /// The CURRENT wakeup generation of this stream (lock-free), snapshotted by a waiter BEFORE it runs
    /// its poll batch so a bump that lands between the snapshot and the wait is not lost (the wait
    /// predicate observes the advanced counter and returns immediately).
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.gen.load(Ordering::Acquire)
    }

    /// Advance THIS stream's generation and wake ITS parked waiters. Called by the append actor
    /// STRICTLY AFTER the durability work that advanced this stream's poll-visible frontier (pure
    /// observation — it never reorders the actor's own statements). Over-bumping is harmless.
    ///
    /// The increment runs UNDER `lock` even though `gen` is an atomic: that is the lost-wakeup
    /// invariant. A waiter checks its predicate (`gen == snapshot`) while holding `lock` and only then
    /// atomically parks (releasing `lock`); because this increment also holds `lock`, it cannot slip
    /// between that check and the park — so the waiter either sees the new generation (and never parks)
    /// or is already parked when `notify_all` fires. `notify_all` is issued AFTER dropping the lock so
    /// a woken waiter does not immediately contend on it.
    pub fn bump(&self) {
        {
            let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
            self.gen.fetch_add(1, Ordering::Release);
        }
        self.cv.notify_all();
    }

    /// Block until this stream's generation moves off `snapshot` (a commit to THIS stream happened) or
    /// `timeout` elapses, whichever comes first. Returns as soon as the predicate is false, so a bump
    /// racing the snapshot is never lost. A spurious condvar wake with an unchanged generation simply
    /// re-parks until the deadline — the caller re-polls at most once regardless. A commit to a
    /// DIFFERENT stream bumps a DIFFERENT cell and never wakes this wait.
    ///
    /// `spin` gates a bounded busy-poll BEFORE the condvar park (#1100), threaded from the caller as the
    /// produce path's spin discriminant (`!commit_syncs_before_ack()`, #1032/#1026): `true` on the
    /// no-pre-ack-fsync tiers where a commit is poll-visible within microseconds — there this catches
    /// the wake without the park/unpark round-trip that drove the p999 delivery tail — and `false` on
    /// the fsync-barrier `sync` tier where a commit is milliseconds away, so spinning would only burn a
    /// core and this is byte-for-byte the historical straight-to-park.
    pub fn wait_for_change(&self, snapshot: u64, timeout: Duration, spin: bool) {
        let start = Instant::now();
        // Bounded spin-before-park (#1100), now LOCK-FREE (#1100 L2 resolves L1's follow-up): the spin
        // re-reads `gen` with a plain atomic load — the SAME generation the wait predicate checks — so
        // a bump it MISSES is still caught by the predicate (which then returns without parking), and a
        // bump it SEES returns immediately with no park and no mutex at all. Lost-wakeup safety is
        // identical to the pure-park path; the spin can only ever SHORTEN the wait.
        if spin {
            let spin_deadline = start + Duration::from_micros(WAIT_SPIN_MICROS);
            loop {
                // A move off `snapshot` means a commit to THIS stream landed during the spin: return
                // WITHOUT parking (the caller re-polls).
                if self.gen.load(Ordering::Acquire) != snapshot {
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
        // predicate on entry and on every (spurious or real) wake, reading `gen` UNDER `lock` — the
        // same lock `bump` holds around its increment — so a generation that already advanced past
        // `snapshot` (a bump that raced the snapshot or landed just after the spin window) returns
        // without parking. The returned guard/timeout result is not needed: the caller re-polls
        // unconditionally after this returns.
        let remaining = timeout.saturating_sub(start.elapsed());
        let guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .cv
            .wait_timeout_while(guard, remaining, |()| {
                self.gen.load(Ordering::Acquire) == snapshot
            })
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// The engine-wide commit-notify registry (#push-delivery, per-stream since #1100 L2). ONE per append
/// actor, shared (via `Arc`) between the actor thread (which [`bump`](CommitNotify::bump)s a stream's
/// cell whenever THAT stream's durable poll frontier advances) and every consumer connection thread
/// (which [`wait_for_change`](CommitNotify::wait_for_change)es on its OWN stream's cell while idle
/// long-polling).
///
/// It is a get-or-insert map from stream identity to that stream's [`StreamCell`]. The registry mutex
/// is held ONLY for the brief `HashMap` lookup/insert — NEVER across a park, a poll, or a bump's
/// `notify_all` — so a commit on stream A and an idle waiter on stream B contend here for nanoseconds
/// at most and then operate on DISJOINT per-cell mutexes/condvars (the L1 global-condvar thundering
/// herd and lock convoy are both gone). Cells are never removed (bounded by `max_streams` + 1), so a
/// [`cell`](CommitNotify::cell) handle for a given stream is stable for the life of the actor.
pub struct CommitNotify {
    /// Per-stream wakeup cells, keyed by stream name: `""` for the DEFAULT/root stream, each NAMED
    /// stream (#588) by its validated name. Get-or-insert under this ONE mutex.
    cells: Mutex<HashMap<Arc<str>, Arc<StreamCell>>>,
}

impl CommitNotify {
    /// A fresh, empty registry, wrapped in an `Arc` so the actor and every connection share the one
    /// instance. Cells are materialized lazily on first use per stream.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(CommitNotify {
            cells: Mutex::new(HashMap::new()),
        })
    }

    /// Get-or-create the wakeup cell for `stream` (`""` = the default/root stream). A brief
    /// registry-lock lookup that inserts a fresh generation-0 cell the first time a stream is seen by
    /// EITHER a producer (the actor's bump) or a consumer (a wait). Returns an owned `Arc` so a caller
    /// can HOLD the handle — the actor caches it to bump without re-locking the registry each commit; a
    /// consumer holds it across one consume batch to snapshot then wait on the SAME cell. Because cells
    /// are never removed, repeated calls for the same stream return the same cell.
    #[must_use]
    pub fn cell(&self, stream: &str) -> Arc<StreamCell> {
        let mut cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cell) = cells.get(stream) {
            return Arc::clone(cell);
        }
        let cell = StreamCell::new();
        cells.insert(Arc::from(stream), Arc::clone(&cell));
        cell
    }

    /// The CURRENT wakeup generation of `stream`, a convenience over [`cell`](CommitNotify::cell) +
    /// [`StreamCell::seq`].
    #[must_use]
    pub fn seq(&self, stream: &str) -> u64 {
        self.cell(stream).seq()
    }

    /// Advance `stream`'s generation and wake ONLY that stream's parked waiters (the per-stream
    /// targeted wakeup). A convenience over [`cell`](CommitNotify::cell) + [`StreamCell::bump`]; the
    /// actor prefers caching the [`cell`](CommitNotify::cell) handle and bumping it directly to skip
    /// the registry lock on the steady path.
    pub fn bump(&self, stream: &str) {
        self.cell(stream).bump();
    }

    /// Block until `stream`'s generation moves off `snapshot` or `timeout` elapses. A convenience over
    /// [`cell`](CommitNotify::cell) + [`StreamCell::wait_for_change`]; waits on THAT stream's cell only,
    /// so a commit to a different stream never wakes this waiter.
    pub fn wait_for_change(&self, stream: &str, snapshot: u64, timeout: Duration, spin: bool) {
        self.cell(stream).wait_for_change(snapshot, timeout, spin);
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
        let snapshot = notify.seq("");
        notify.bump(""); // seq is now != snapshot BEFORE the wait
        let start = Instant::now();
        notify.wait_for_change("", snapshot, Duration::from_secs(30), /* spin */ true);
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
            let snapshot = notify.seq("");
            let bumper = Arc::clone(&notify);
            let jh = std::thread::spawn(move || {
                // Land the commit inside the wait, after it has begun (past the ~100 us spin window on
                // the spin path, so this also exercises the condvar backstop, not only the busy-poll).
                std::thread::sleep(Duration::from_millis(20));
                bumper.bump("");
            });
            let start = Instant::now();
            notify.wait_for_change("", snapshot, Duration::from_secs(30), spin);
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
        let snapshot = notify.seq("");
        let budget = Duration::from_millis(120);
        let start = Instant::now();
        notify.wait_for_change("", snapshot, budget, /* spin */ true);
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

    /// FAN-OUT ISOLATION (#1100 L2, the thundering-herd fix): a waiter on stream A is NOT woken by a
    /// commit to stream B — it waits on B's WHOLE budget and times out — yet a commit to A DOES wake
    /// it promptly. Proves a bump is scoped to the committing stream's cell, so an idle consumer on
    /// one stream is never disturbed by commits on unrelated streams (the O(N-idle) herd L2 kills).
    #[test]
    fn a_commit_to_another_stream_does_not_wake_a_waiter() {
        // Part 1: a commit to "B" must NOT wake a waiter on "A" — it must time out on its own budget.
        let notify = CommitNotify::new();
        let snapshot_a = notify.seq("a");
        let bumper = Arc::clone(&notify);
        let jh = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            bumper.bump("b"); // a DIFFERENT stream
        });
        let budget = Duration::from_millis(200);
        let start = Instant::now();
        notify.wait_for_change("a", snapshot_a, budget, /* spin */ false);
        let elapsed = start.elapsed();
        jh.join().unwrap();
        assert!(
            elapsed >= budget.saturating_sub(Duration::from_millis(20)),
            "a commit to stream B must NOT wake a waiter on stream A; it must wait out its budget, \
             but it returned after {elapsed:?} (budget {budget:?})"
        );

        // Part 2: a commit to "A" DOES wake the same-keyed waiter promptly (the cell works for A).
        let notify = CommitNotify::new();
        let snapshot_a = notify.seq("a");
        let bumper = Arc::clone(&notify);
        let jh = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            bumper.bump("a"); // the SAME stream
        });
        let start = Instant::now();
        notify.wait_for_change(
            "a",
            snapshot_a,
            Duration::from_secs(30),
            /* spin */ false,
        );
        let elapsed = start.elapsed();
        jh.join().unwrap();
        assert!(
            elapsed < Duration::from_secs(5),
            "a commit to stream A must wake its own waiter well below the budget; took {elapsed:?}"
        );
    }

    /// NAMED-STREAM EARLY WAKE (#1100 L2, the named-stream floor fix): a waiter on a NAMED stream wakes
    /// on a commit to THAT named stream — far below its budget — where L1 (which only bumped on the
    /// root log) would have stranded it until timeout. The named cell is just another key, so this is
    /// the same mechanism as the default stream, now reaching named-stream long-pollers.
    #[test]
    fn a_named_stream_waiter_wakes_on_its_own_commit() {
        let notify = CommitNotify::new();
        let snapshot = notify.seq("orders");
        let bumper = Arc::clone(&notify);
        let jh = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            bumper.bump("orders");
        });
        let start = Instant::now();
        notify.wait_for_change(
            "orders",
            snapshot,
            Duration::from_secs(30),
            /* spin */ true,
        );
        let elapsed = start.elapsed();
        jh.join().unwrap();
        assert!(
            elapsed < Duration::from_secs(5),
            "a named-stream waiter must wake on its own stream's commit, not eat the full budget; \
             took {elapsed:?}"
        );
    }

    /// BROADCAST CORRECTNESS (#1100 L2): TWO waiters on the SAME stream (the competing-group member +
    /// broadcast-subscriber case — the key is the stream, not the group) are BOTH woken by ONE commit
    /// to that stream. Each snapshots and waits on the same cell, so a single `notify_all` releases
    /// both well below the budget.
    #[test]
    fn two_waiters_on_the_same_stream_both_wake_on_one_commit() {
        let notify = CommitNotify::new();
        let snap1 = notify.seq("s");
        let snap2 = notify.seq("s");
        let n1 = Arc::clone(&notify);
        let n2 = Arc::clone(&notify);
        let w1 = std::thread::spawn(move || {
            let start = Instant::now();
            n1.wait_for_change("s", snap1, Duration::from_secs(30), /* spin */ false);
            start.elapsed()
        });
        let w2 = std::thread::spawn(move || {
            let start = Instant::now();
            n2.wait_for_change("s", snap2, Duration::from_secs(30), /* spin */ false);
            start.elapsed()
        });
        // Let both threads reach the park, then fire ONE commit to the shared stream.
        std::thread::sleep(Duration::from_millis(40));
        notify.bump("s");
        let e1 = w1.join().unwrap();
        let e2 = w2.join().unwrap();
        assert!(
            e1 < Duration::from_secs(5) && e2 < Duration::from_secs(5),
            "one commit to a shared stream must wake BOTH waiters; took {e1:?} and {e2:?}"
        );
    }
}
