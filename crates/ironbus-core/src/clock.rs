// SPDX-License-Identifier: MIT OR Apache-2.0
//! The clock seam: all time in IronBus flows through [`Clock`] so the engine is
//! deterministic under simulation.
//!
//! Engine logic must never read `SystemTime::now` or `Instant::now` directly; it
//! reads time from a [`Clock`]. Production wires a real system clock; tests and the
//! deterministic simulation wire a [`ManualClock`] they advance explicitly.

use core::sync::atomic::{AtomicU64, Ordering};

/// A source of time. Two independent clocks are exposed:
///
/// - a wall clock ([`Clock::now_unix_millis`]) for record timestamps, which can
///   jump or move backwards across a reboot or a time step, and
/// - a monotonic clock ([`Clock::now_monotonic_nanos`]) for measuring durations
///   (lease deadlines, queue sojourn), which never moves backwards within a run.
///
/// Implementations must be cheap to call and safe to share across threads.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch, from the wall clock.
    fn now_unix_millis(&self) -> u64;

    /// Nanoseconds from an arbitrary, monotonic origin. Only differences are
    /// meaningful; the absolute value carries no cross-run meaning.
    fn now_monotonic_nanos(&self) -> u64;
}

/// Sharing a clock behind an [`std::sync::Arc`] forwards to the inner clock, so several
/// owners (an engine and a test driving time, for instance) observe the same clock.
impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now_unix_millis(&self) -> u64 {
        (**self).now_unix_millis()
    }

    fn now_monotonic_nanos(&self) -> u64 {
        (**self).now_monotonic_nanos()
    }
}

/// A deterministic [`Clock`] whose time only changes when a test advances it.
///
/// Both clocks start at zero and never read the host clock, so they are the time
/// source for unit tests and the deterministic simulation. Time is held in two
/// independent atomics so the clock can be shared across threads; a single advance
/// is therefore not an atomic snapshot across both clocks, so a concurrent reader
/// may observe the wall and monotonic values from different advance points. The
/// single-threaded deterministic simulation never hits that interleaving.
#[derive(Debug, Default)]
pub struct ManualClock {
    unix_millis: AtomicU64,
    monotonic_nanos: AtomicU64,
}

impl ManualClock {
    /// Creates a clock with both times at zero.
    #[must_use]
    pub fn new() -> ManualClock {
        ManualClock::default()
    }

    /// Creates a clock with the wall clock at `unix_millis` and the monotonic clock
    /// at zero.
    #[must_use]
    pub fn at_unix_millis(unix_millis: u64) -> ManualClock {
        ManualClock {
            unix_millis: AtomicU64::new(unix_millis),
            monotonic_nanos: AtomicU64::new(0),
        }
    }

    /// Sets the wall clock to `unix_millis`. The wall clock may move backwards.
    pub fn set_unix_millis(&self, unix_millis: u64) {
        self.unix_millis.store(unix_millis, Ordering::SeqCst);
    }

    /// Advances the wall clock by `millis` and the monotonic clock by the matching
    /// nanoseconds, saturating at `u64::MAX` (a clock must never wrap backwards).
    ///
    /// This advances both clocks in lockstep with no skew. To model clock skew (an
    /// NTP step, a stalled wall clock, a backwards jump), drive
    /// [`set_unix_millis`](ManualClock::set_unix_millis) and
    /// [`advance_monotonic_nanos`](ManualClock::advance_monotonic_nanos) independently.
    pub fn advance_millis(&self, millis: u64) {
        saturating_add(&self.unix_millis, millis);
        saturating_add(&self.monotonic_nanos, millis.saturating_mul(1_000_000));
    }

    /// Advances only the monotonic clock by `nanos`, leaving the wall clock fixed.
    pub fn advance_monotonic_nanos(&self, nanos: u64) {
        saturating_add(&self.monotonic_nanos, nanos);
    }
}

/// Atomically adds `delta` to `a`, saturating at `u64::MAX`. The update closure
/// always returns `Some`, so `fetch_update` never fails; it only retries under
/// contention.
fn saturating_add(a: &AtomicU64, delta: u64) {
    let _ = a.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_add(delta))
    });
}

impl Clock for ManualClock {
    fn now_unix_millis(&self) -> u64 {
        self.unix_millis.load(Ordering::SeqCst)
    }

    fn now_monotonic_nanos(&self) -> u64 {
        self.monotonic_nanos.load(Ordering::SeqCst)
    }
}

/// Cloning snapshots both clocks at their current values; the clone is an INDEPENDENT clock
/// thereafter (advancing one does not advance the other). The engine clones its clock to give a
/// secondary durable store (the DLQ sink, #63) its own time source, and that sink only needs the
/// wall clock to stamp segment-creation timestamps, so an independent clone is correct. Tests that
/// must drive both from one place share an `Arc<ManualClock>` instead, whose `Clone` aliases the
/// SAME clock.
impl Clone for ManualClock {
    fn clone(&self) -> ManualClock {
        ManualClock {
            unix_millis: AtomicU64::new(self.unix_millis.load(Ordering::SeqCst)),
            monotonic_nanos: AtomicU64::new(self.monotonic_nanos.load(Ordering::SeqCst)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn arc_clock_forwards_and_shares_state() {
        let clock = Arc::new(ManualClock::new());
        let shared = Arc::clone(&clock);
        clock.set_unix_millis(1_000);
        clock.advance_monotonic_nanos(500);
        // The Arc forwards to the same inner clock, so the shared handle sees the advance.
        assert_eq!(shared.now_unix_millis(), 1_000);
        assert_eq!(shared.now_monotonic_nanos(), 500);
    }

    #[test]
    fn starts_at_zero() {
        let c = ManualClock::new();
        assert_eq!(c.now_unix_millis(), 0);
        assert_eq!(c.now_monotonic_nanos(), 0);
    }

    #[test]
    fn advance_moves_both_clocks() {
        let c = ManualClock::at_unix_millis(1000);
        assert_eq!(c.now_unix_millis(), 1000);
        c.advance_millis(5);
        assert_eq!(c.now_unix_millis(), 1005);
        assert_eq!(c.now_monotonic_nanos(), 5_000_000);
    }

    #[test]
    fn monotonic_advances_independently() {
        let c = ManualClock::new();
        c.advance_monotonic_nanos(42);
        assert_eq!(c.now_monotonic_nanos(), 42);
        assert_eq!(c.now_unix_millis(), 0);
    }

    #[test]
    fn wall_clock_can_move_backwards() {
        let c = ManualClock::at_unix_millis(1000);
        c.set_unix_millis(500);
        assert_eq!(c.now_unix_millis(), 500);
    }

    #[test]
    fn usable_as_trait_object() {
        let c = ManualClock::at_unix_millis(7);
        let dyn_clock: &dyn Clock = &c;
        assert_eq!(dyn_clock.now_unix_millis(), 7);
    }

    #[test]
    fn advance_saturates() {
        let c = ManualClock::new();
        c.advance_monotonic_nanos(u64::MAX);
        c.advance_millis(1); // would overflow monotonic; saturates instead
        assert_eq!(c.now_monotonic_nanos(), u64::MAX);
    }

    #[test]
    fn monotonic_never_decreases() {
        let c = ManualClock::new();
        let mut prev = c.now_monotonic_nanos();
        for d in [3u64, 0, 100, 1, u64::MAX, 5] {
            c.advance_monotonic_nanos(d);
            let now = c.now_monotonic_nanos();
            assert!(now >= prev);
            prev = now;
        }
    }

    #[test]
    fn wall_clock_advance_saturates() {
        let c = ManualClock::at_unix_millis(u64::MAX - 1);
        c.advance_millis(10);
        assert_eq!(c.now_unix_millis(), u64::MAX);
    }

    #[test]
    fn set_wall_does_not_touch_monotonic() {
        let c = ManualClock::new();
        c.advance_monotonic_nanos(123);
        c.set_unix_millis(999);
        assert_eq!(c.now_monotonic_nanos(), 123);
        assert_eq!(c.now_unix_millis(), 999);
    }

    #[test]
    fn concurrent_advances_are_all_counted() {
        let c = ManualClock::new();
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..1000 {
                        c.advance_monotonic_nanos(1);
                    }
                });
            }
        });
        assert_eq!(c.now_monotonic_nanos(), 4 * 1000);
    }
}
