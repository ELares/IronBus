// SPDX-License-Identifier: MIT OR Apache-2.0
//! The liveness watchdog (#95): a monotonic-clock progress beacon the broker's main accept loop
//! ticks, so `GET /healthz` can tell a STUCK event loop apart from a merely idle one.
//!
//! `/healthz` is liveness: it must answer 200 while the process is making progress and flip to 503
//! only when the event loop has wedged. The trap is a probe with no hysteresis: it restarts the node
//! the first time a slow `fsync` overruns one tick, and a healthy-but-idle broker (no work to do)
//! must never look stuck. The beacon solves both. The wire accept loop ([`crate::server::serve`])
//! calls [`LivenessBeacon::mark_progress`] on EVERY iteration, including the idle would-block poll,
//! so the timestamp advances even when no client is connected: idle is progress. `/healthz` then
//! compares `now_monotonic - last_progress` against a configurable HYSTERESIS WINDOW and only sheds
//! once the loop has gone a whole window with no tick at all, which only a genuinely stuck (or
//! crashed) accept loop produces. All timing is on the monotonic clock seam
//! ([`ironbus_core::clock::Clock::now_monotonic_nanos`]), never the wall clock, so an NTP step never
//! drives liveness.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A shared monotonic "last made progress" timestamp the broker's main loop ticks and `/healthz`
/// reads, the heart of the liveness hysteresis watchdog (#95).
///
/// The accept loop calls [`mark_progress`](LivenessBeacon::mark_progress) on every cycle (work or
/// idle); the health server calls [`stuck_for_window`](LivenessBeacon::stuck_for_window) per probe.
/// Both sides read the SAME monotonic clock seam, so the difference is a real elapsed-nanos measure
/// that never goes backwards on a wall-clock step. Cheap to share: one `AtomicU64`, relaxed ordering
/// (the value is an advisory heartbeat, not a synchronization point for any other state).
#[derive(Debug)]
pub struct LivenessBeacon {
    /// The monotonic-clock nanos of the most recent loop tick. Seeded to the broker's start time so
    /// a window has to actually elapse with no tick before `/healthz` can shed (it never starts
    /// "already stuck").
    last_progress_nanos: AtomicU64,
}

impl LivenessBeacon {
    /// Creates a beacon whose last-progress instant is `now_monotonic_nanos` (the broker's start
    /// time), so a freshly started broker is live until a whole window elapses with no tick.
    #[must_use]
    pub fn new(now_monotonic_nanos: u64) -> LivenessBeacon {
        LivenessBeacon {
            last_progress_nanos: AtomicU64::new(now_monotonic_nanos),
        }
    }

    /// Records that the main loop made progress at `now_monotonic_nanos`. Called once per accept-loop
    /// iteration (a connection accepted, a connection refused at the cap, OR the idle would-block
    /// poll), so the beacon advances even on a totally idle broker: a running loop is liveness,
    /// whether or not it has work. A single relaxed store on the hot path.
    pub fn mark_progress(&self, now_monotonic_nanos: u64) {
        self.last_progress_nanos
            .store(now_monotonic_nanos, Ordering::Relaxed);
    }

    /// The nanoseconds since the last recorded progress, given the current monotonic reading.
    /// Saturating, so a reordered read that observes a `now` below the stored value reports `0`
    /// (fresh) rather than a giant wrapped age.
    #[must_use]
    pub fn since_progress_nanos(&self, now_monotonic_nanos: u64) -> u64 {
        now_monotonic_nanos.saturating_sub(self.last_progress_nanos.load(Ordering::Relaxed))
    }

    /// Whether the loop has gone at least one full hysteresis `window_nanos` with no progress tick,
    /// i.e. whether `/healthz` should shed (return 503). A `window_nanos` of `0` DISABLES the
    /// watchdog: liveness then never sheds on staleness (it always returns false here), preserving
    /// the legacy static-200 behavior for an operator who opts out. The comparison is strict `>` so
    /// the exact-window boundary is still healthy; only past it is stuck.
    #[must_use]
    pub fn stuck_for_window(&self, now_monotonic_nanos: u64, window_nanos: u64) -> bool {
        window_nanos != 0 && self.since_progress_nanos(now_monotonic_nanos) > window_nanos
    }
}

/// A shared actor-progress watchdog (#862): the append actor stamps the monotonic instant it BEGINS
/// processing a command batch — which includes the covering durability `fdatasync` — and clears it
/// when the batch completes and it returns to idle. The health server reads it WITHOUT going through
/// the actor, so a HUNG fsync (a failing eMMC doing long internal retries, a stalled networked/overlay
/// FS, brownout-stuck flash on the edge target) that blocks the actor thread FOREVER is DETECTED:
/// `processing_since` stays put while the monotonic clock advances, and once the gap exceeds the
/// configured bound the broker reports UNHEALTHY (flipping `/healthz` AND `/readyz` to 503) so an
/// orchestrator restarts it — instead of liveness staying green while the whole produce path is wedged.
///
/// This is DISTINCT from [`LivenessBeacon`]: that watches the ACCEPT loop, which is deliberately
/// decoupled from the writer (#95) and keeps ticking even while the actor is wedged, so it cannot see a
/// hung writer. This watches the actor itself. Unlike the accept loop, the actor does NOT tick while
/// idle (it blocks awaiting a command), so a stale-since-last-tick model would false-trip on a quiet
/// broker; instead a `processing_since` of `0` means IDLE (never wedged), and a non-zero stamp older
/// than the bound means the in-flight batch has overrun — a genuine wedge, not idleness.
///
/// It also carries the writer's FROZEN state (#862) as a published flag, so the health server can answer
/// `/readyz` WITHOUT going through the actor at all. Previously `/readyz` read the frozen state via
/// `engine.with(|e| e.is_healthy())`, which queues a job behind the actor — and on a HUNG fsync that job
/// blocks FOREVER, wedging the single-threaded health server so even the watchdog's own 503 is never
/// served. Publishing the frozen flag here lets `/readyz` shed on `draining` / a wedge / a frozen writer
/// with three non-blocking atomic reads and NO actor round-trip, so it can never hang. Cheap to share:
/// two `AtomicU64` + one `AtomicBool`, relaxed ordering (advisory heartbeat, not a synchronization point).
#[derive(Debug)]
pub struct ActorWatchdog {
    /// The monotonic nanos the actor began the current batch, or `0` when idle (blocked awaiting a
    /// command). Stored as `max(1)` so a `now` of `0` (a fresh manual clock) is never mistaken for idle.
    processing_since: AtomicU64,
    /// The overrun bound in nanos: an in-flight batch older than this is WEDGED. `0` = the watchdog is
    /// DISABLED (it never trips), the default until a serve configures it via [`set_bound_nanos`].
    ///
    /// [`set_bound_nanos`]: ActorWatchdog::set_bound_nanos
    bound_nanos: AtomicU64,
    /// The writer's live/frozen state, PUBLISHED by the actor after each batch (`engine.is_healthy()`),
    /// so `/readyz` can read it non-blockingly instead of through the actor (#862). `true` = live (the
    /// default for a fresh broker that has run no batch yet); `false` once a covering fsync RETURNED an
    /// error and froze the writer.
    writer_healthy: AtomicBool,
}

impl ActorWatchdog {
    /// A fresh watchdog (idle, writer live) with the given overrun `bound_nanos` (`0` = disabled).
    #[must_use]
    pub fn new(bound_nanos: u64) -> ActorWatchdog {
        ActorWatchdog {
            processing_since: AtomicU64::new(0),
            bound_nanos: AtomicU64::new(bound_nanos),
            writer_healthy: AtomicBool::new(true),
        }
    }

    /// Sets the overrun bound in nanos; `0` disables the watchdog. Called once at serve start from the
    /// configured value, before any produce can wedge.
    pub fn set_bound_nanos(&self, bound_nanos: u64) {
        self.bound_nanos.store(bound_nanos, Ordering::Relaxed);
    }

    /// Records that the actor BEGAN a command batch at `now_monotonic_nanos` (it is about to append and
    /// run the covering fsync). One relaxed store on the actor's per-BATCH boundary, never per message.
    pub fn mark_busy(&self, now_monotonic_nanos: u64) {
        self.processing_since
            .store(now_monotonic_nanos.max(1), Ordering::Relaxed);
    }

    /// Records that the actor FINISHED a batch and is returning to idle (awaiting the next command).
    /// Clears the in-flight stamp so the watchdog cannot trip on an idle actor.
    pub fn mark_idle(&self) {
        self.processing_since.store(0, Ordering::Relaxed);
    }

    /// Whether the actor's current batch has been in flight longer than the configured bound — a hung
    /// fsync. `false` when idle (`processing_since == 0`), when no bound is configured (`bound == 0`),
    /// or within the bound. The comparison is strict `>` so the exact-bound boundary is still healthy.
    #[must_use]
    pub fn overran(&self, now_monotonic_nanos: u64) -> bool {
        let bound = self.bound_nanos.load(Ordering::Relaxed);
        if bound == 0 {
            return false;
        }
        let since = self.processing_since.load(Ordering::Relaxed);
        since != 0 && now_monotonic_nanos.saturating_sub(since) > bound
    }

    /// Publishes the writer's live/frozen state (`engine.is_healthy()`), called by the actor after each
    /// batch's covering commit (#862). One relaxed store on the per-batch boundary.
    pub fn publish_writer_healthy(&self, healthy: bool) {
        self.writer_healthy.store(healthy, Ordering::Relaxed);
    }

    /// The last-published writer live/frozen state, read non-blockingly by `/readyz` (#862) so it never
    /// has to round-trip through the actor (which a hung fsync would block forever). `true` = live.
    #[must_use]
    pub fn writer_healthy(&self) -> bool {
        self.writer_healthy.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_beacon_is_not_stuck() {
        // Seeded at the start instant: with no time elapsed it is fresh, and even after a full
        // window has notionally passed it stays fresh as long as progress is marked at `now`.
        let b = LivenessBeacon::new(1_000);
        assert_eq!(b.since_progress_nanos(1_000), 0);
        assert!(!b.stuck_for_window(1_000, 30));
        b.mark_progress(5_000);
        assert!(!b.stuck_for_window(5_000, 30));
    }

    #[test]
    fn it_flips_only_after_a_full_window_of_no_progress() {
        let b = LivenessBeacon::new(0);
        b.mark_progress(100);
        // Inside the window: still healthy. At exactly the window: still healthy (strict >). Past
        // the window with no further tick: stuck.
        assert!(!b.stuck_for_window(100 + 10, 30));
        assert!(!b.stuck_for_window(100 + 30, 30));
        assert!(b.stuck_for_window(100 + 31, 30));
        // A fresh tick clears it again: a loop that resumes is live once more (no flapping latch).
        b.mark_progress(200);
        assert!(!b.stuck_for_window(200 + 5, 30));
    }

    #[test]
    fn a_zero_window_disables_the_watchdog() {
        // window 0 = disabled: no matter how stale, liveness never sheds on staleness.
        let b = LivenessBeacon::new(0);
        b.mark_progress(1);
        assert!(!b.stuck_for_window(u64::MAX, 0));
        assert_eq!(b.since_progress_nanos(u64::MAX), u64::MAX - 1);
    }

    #[test]
    fn a_backwards_now_reads_as_fresh_not_wrapped() {
        // A read that observes a `now` below the stored progress (a benign relaxed reorder) saturates
        // to 0 rather than reporting a near-u64::MAX age that would false-trip the watchdog.
        let b = LivenessBeacon::new(10_000);
        assert_eq!(b.since_progress_nanos(9_000), 0);
        assert!(!b.stuck_for_window(9_000, 30));
    }

    #[test]
    fn idle_ticks_keep_it_live_across_many_windows() {
        // Model a long idle run: the accept loop ticks every ~50 ms (idle would-block poll). Each
        // tick advances the beacon, so even over many window-lengths of pure idle it never sheds.
        let b = LivenessBeacon::new(0);
        let window = 30_000_000; // 30 ms in nanos
        let mut now = 0u64;
        for _ in 0..1000 {
            now += 5_000_000; // a 5 ms idle poll tick
            b.mark_progress(now);
            assert!(!b.stuck_for_window(now, window), "idle is healthy at {now}");
        }
        // Now the loop wedges: no further tick. After a full window it sheds.
        assert!(b.stuck_for_window(now + window + 1, window));
    }

    #[test]
    fn an_idle_actor_watchdog_never_overruns() {
        // #862: a `processing_since` of 0 means the actor is idle (blocked awaiting a command), so the
        // watchdog must NOT trip no matter how much time passes — only an in-flight batch can wedge.
        let w = ActorWatchdog::new(30);
        assert!(!w.overran(0));
        assert!(!w.overran(u64::MAX), "an idle actor is never wedged");
        // A finished batch (mark_busy then mark_idle) returns to idle: never wedged afterward.
        w.mark_busy(100);
        w.mark_idle();
        assert!(!w.overran(100 + 1_000_000));
    }

    #[test]
    fn a_busy_actor_watchdog_overruns_only_past_the_bound() {
        // The actor begins a batch at t=100; within the bound it is healthy, at exactly the bound it is
        // still healthy (strict >), and past the bound the in-flight batch is WEDGED (a hung fsync).
        let w = ActorWatchdog::new(30);
        w.mark_busy(100);
        assert!(!w.overran(100 + 10));
        assert!(!w.overran(100 + 30));
        assert!(w.overran(100 + 31), "the in-flight batch overran the bound");
        // The actor completing the batch clears the wedge (no flapping latch): idle again.
        w.mark_idle();
        assert!(!w.overran(100 + 1_000));
    }

    #[test]
    fn a_zero_bound_disables_the_actor_watchdog() {
        // bound 0 = disabled: even a very old in-flight stamp never trips (the default until a serve
        // configures a bound). Setting a bound then engages it.
        let w = ActorWatchdog::new(0);
        w.mark_busy(1);
        assert!(!w.overran(u64::MAX));
        w.set_bound_nanos(30);
        assert!(w.overran(1 + 31));
        w.set_bound_nanos(0);
        assert!(!w.overran(u64::MAX), "re-disabling stops the watchdog");
    }

    #[test]
    fn a_busy_stamp_of_zero_is_not_mistaken_for_idle() {
        // A fresh manual clock can read `now == 0`; `mark_busy` stores `max(1)`, so a batch that began
        // at logical time 0 is still seen as busy (not idle) and can overrun.
        let w = ActorWatchdog::new(30);
        w.mark_busy(0);
        assert!(!w.overran(0));
        // The stamp is clamped to 1, so the overrun is at now > 1 + bound (= 31), not idle-forever.
        assert!(
            w.overran(32),
            "a batch begun at t=0 still overruns the bound"
        );
    }

    #[test]
    fn the_watchdog_publishes_and_reads_the_writer_frozen_state() {
        // #862: /readyz reads the writer live/frozen state from this published flag (non-blocking), NOT
        // through the actor — so a frozen (or hung) writer can never block the readiness check.
        let w = ActorWatchdog::new(0);
        assert!(
            w.writer_healthy(),
            "a fresh watchdog reports the writer live"
        );
        w.publish_writer_healthy(false);
        assert!(
            !w.writer_healthy(),
            "a frozen writer is published and read back"
        );
        w.publish_writer_healthy(true);
        assert!(
            w.writer_healthy(),
            "a live writer reads back live again (not a one-way latch here)"
        );
    }
}
