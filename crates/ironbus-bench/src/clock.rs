// SPDX-License-Identifier: MIT OR Apache-2.0
//! A monotonic-raw nanosecond clock, the single timebase the open-loop harness measures against.
//!
//! End-to-end latency is the difference between a message's INTENDED send time (scheduled by the
//! open-loop arrival process, #111) and the moment the receiver observes it. Both readings come
//! from the SAME clock on the SAME host (the default co-located sender + receiver), so there is no
//! cross-host skew to subtract: the only requirement is a clock that never steps backward and is
//! not slewed by NTP, so a stalled broker shows up as real wall-time in the tail rather than being
//! quietly corrected away.
//!
//! On Unix we read `CLOCK_MONOTONIC_RAW` via `clock_gettime`. `MONOTONIC_RAW` (not plain
//! `MONOTONIC`) is deliberate: it is NOT adjusted by NTP frequency slewing, so a measured
//! microsecond is a true elapsed microsecond. The same `CLOCK_MONOTONIC_RAW` constant and
//! `clock_gettime` call are available on both Linux and macOS (Darwin, since 10.12), so one code
//! path serves both; there is no need for the macOS `clock_gettime_nsec_np` variant. On a
//! non-Unix target (only the harness binary, never the shipped broker, which is Unix-only) we fall
//! back to `std::time::Instant`, which is monotonic but may be NTP-slewed; the harness's default
//! and only supported measurement target is Unix, so this fallback exists merely to keep the crate
//! compiling everywhere.

/// A monotonic-raw timestamp in nanoseconds since an unspecified epoch.
///
/// Only DIFFERENCES between two `Nanos` from the same process are meaningful; the absolute value
/// is opaque. This is the send-time token embedded in each payload and read back at the receiver.
pub type Nanos = u64;

/// Reads the monotonic-raw clock, returning nanoseconds since an unspecified, fixed epoch.
///
/// The value only has meaning as a difference against another reading from the same process. It is
/// guaranteed non-decreasing across calls in one process.
#[cfg(unix)]
#[must_use]
pub fn now_nanos() -> Nanos {
    // SAFETY: `clock_gettime` is a plain libc call (a foreign function, not a memory-unsafe
    // operation): we pass a valid clock id and a pointer to a fully owned, stack-allocated
    // `timespec` it fills in. It cannot read or write past that struct. We do not even branch on
    // its return code beyond defaulting to zero, so a (practically impossible) failure degrades to
    // a constant reading rather than reading uninitialized memory: the struct is zero-initialized.
    #[allow(unsafe_code)]
    let ts = unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_MONOTONIC_RAW: monotonic and NOT NTP-slewed, on both Linux and macOS.
        // `addr_of_mut!` (not `&raw mut`) keeps this on the 1.78 MSRV; both yield a raw pointer
        // without forming an intermediate reference.
        libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, core::ptr::addr_of_mut!(ts));
        ts
    };
    // tv_sec and tv_nsec are non-negative for a monotonic clock; the casts are lossless on every
    // supported target (tv_sec fits u64 for any realistic uptime, tv_nsec is 0..1_000_000_000).
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nsec = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nsec)
}

/// The non-Unix fallback: `Instant`-derived nanoseconds against a process-lifetime epoch.
///
/// The harness's supported measurement target is Unix (the broker is Unix-only). This keeps the
/// crate building on other targets; `Instant` is monotonic but may be NTP-slewed, so it is not the
/// honest measurement clock the issue specifies.
#[cfg(not(unix))]
#[must_use]
pub fn now_nanos() -> Nanos {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = *EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// A human-readable name for the clock source actually compiled in, recorded in the provenance.
#[must_use]
pub fn source_name() -> &'static str {
    if cfg!(unix) {
        "CLOCK_MONOTONIC_RAW (clock_gettime)"
    } else {
        "std::time::Instant (non-Unix fallback, may be NTP-slewed)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_never_steps_backward() {
        let mut last = now_nanos();
        for _ in 0..10_000 {
            let next = now_nanos();
            assert!(
                next >= last,
                "monotonic clock stepped back: {next} < {last}"
            );
            last = next;
        }
    }

    #[test]
    fn the_clock_advances_over_a_real_sleep() {
        let start = now_nanos();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let elapsed = now_nanos().saturating_sub(start);
        // A 5 ms sleep must register at least ~1 ms of monotonic time (very generous lower bound to
        // stay non-flaky on a loaded CI runner), proving the clock is wall-time, not a counter.
        assert!(
            elapsed >= 1_000_000,
            "clock did not advance over a 5 ms sleep: {elapsed} ns"
        );
    }
}
