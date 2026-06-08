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

use core::sync::atomic::{AtomicU64, Ordering};

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
}
