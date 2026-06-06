// SPDX-License-Identifier: MIT OR Apache-2.0
//! The production clock: a real implementation of the [`Clock`] seam over the OS clock.
//!
//! `ironbus-core` is IO-free and so cannot read `SystemTime`/`Instant`; this lives in the
//! server, which does. The engine takes any `Clock`, so tests substitute a `ManualClock`
//! and production wires this.

use ironbus_core::clock::Clock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A clock backed by the operating system: wall time from `SystemTime`, monotonic time
/// from `Instant` relative to when the clock was created.
#[derive(Debug)]
pub struct SystemClock {
    monotonic_origin: Instant,
}

impl SystemClock {
    /// Creates a clock whose monotonic zero is now.
    #[must_use]
    pub fn new() -> SystemClock {
        SystemClock {
            monotonic_origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> SystemClock {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn now_unix_millis(&self) -> u64 {
        // Before the Unix epoch (a badly-set clock) is reported as 0 rather than panicking.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn now_monotonic_nanos(&self) -> u64 {
        // Saturates after ~584 years of uptime; never wraps or panics.
        u64::try_from(self.monotonic_origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_time_never_goes_backwards() {
        let clock = SystemClock::new();
        let a = clock.now_monotonic_nanos();
        let b = clock.now_monotonic_nanos();
        assert!(b >= a, "monotonic clock went backwards: {b} < {a}");
    }

    #[test]
    fn wall_time_is_after_2020() {
        // 2020-01-01 in ms; any sane host clock is well past this.
        let clock = SystemClock::new();
        assert!(clock.now_unix_millis() > 1_577_836_800_000);
    }
}
