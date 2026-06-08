// SPDX-License-Identifier: MIT OR Apache-2.0
//! A best-effort, cross-platform read of THIS process's resident set size (RSS), behind a clean
//! abstraction and with NO `unsafe` (#118).
//!
//! The edge RAM-headroom gauge (`ironbus_ram_headroom_bytes`) needs the live RSS so an operator can
//! watch the broker's resident footprint against the configured RAM ceiling
//! ([`crate::engine::EngineConfig::ram_ceiling_bytes`]) and alert before the kernel OOM-kills the
//! process (#10 shed-not-OOM, #19 / #115 RAM budget). RSS is intentionally read out-of-band (not
//! derived from any in-process accounting), so it measures the REAL resident pages the kernel
//! charges the process, page-cache-mapped segments and allocator slack included, the same quantity
//! the bench harness samples (`ironbus-bench`'s `probe::rss_bytes`).
//!
//! ## Portability and honesty
//!
//! - **Linux**: `VmRSS` is parsed out of `/proc/self/status` (already reported in kB by the
//!   kernel). This is the canonical, no-`unsafe` reading and is what runs on the edge target.
//! - **macOS**: there is no `/proc`, so we shell out to `ps -o rss= -p <pid>` (kB), the portable
//!   way to read a process's RSS without an `unsafe` `task_info` / `proc_pidinfo` FFI call. It is
//!   used only by developers on macOS; the gauge degrades gracefully if `ps` is unavailable.
//! - **Anywhere else**: there is no portable reading, so [`current_rss_bytes`] returns `None` and
//!   the gauge reports the unavailable sentinel rather than a misleading zero.
//!
//! When RSS is unavailable the headroom gauge is honest about it: it reports the unavailable
//! sentinel ([`RSS_UNAVAILABLE`]) instead of pretending the process uses zero bytes (which would
//! make the headroom look maximal exactly when we cannot prove it). See [`ram_headroom_bytes`].

/// The value the `ironbus_ram_headroom_bytes` gauge reports when RSS cannot be read on this
/// platform: `-1`, the unambiguous "unavailable" sentinel (a real headroom is never negative, and
/// `0` would be indistinguishable from "exactly at the ceiling"). Mirrors the `-1`-means-none
/// convention `ironbus_last_dead_lettered_offset` already uses on `/metrics`.
pub const RSS_UNAVAILABLE: i64 = -1;

/// Reads THIS process's resident set size (RSS) in bytes, or `None` if it cannot be determined on
/// this platform (so the caller reports "unavailable" rather than a misleading zero).
///
/// Best-effort and side-effect-free beyond the read itself: a parse failure, an absent `/proc`, or
/// a missing `ps` all degrade to `None`. Never panics and never blocks the broker.
#[must_use]
pub fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        current_rss_bytes_linux()
    }
    #[cfg(target_os = "macos")]
    {
        current_rss_bytes_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Linux: parse `VmRSS:\t<n> kB` out of `/proc/self/status`. No `unsafe`, no FFI.
#[cfg(target_os = "linux")]
fn current_rss_bytes_linux() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// macOS: `ps -o rss= -p <pid>` prints the RSS in kB with no header. The no-`unsafe` portable read
/// (the alternative is an `unsafe` `proc_pidinfo` FFI call, which #118 asks us to avoid).
#[cfg(target_os = "macos")]
fn current_rss_bytes_macos() -> Option<u64> {
    let pid = std::process::id();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let kb: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(kb.saturating_mul(1024))
}

/// Computes the `ironbus_ram_headroom_bytes` value from the configured RAM `ceiling` and a measured
/// `rss`: the bytes of headroom remaining below the ceiling (saturating at `0` once RSS reaches or
/// exceeds the ceiling), or [`RSS_UNAVAILABLE`] when either input is unusable.
///
/// The gauge is `RSS_UNAVAILABLE` (`-1`) when:
/// - the RAM ceiling is `0` (UNSET, the default): no ceiling is configured, so "headroom below the
///   ceiling" is undefined. An operator opts in by setting `ram_ceiling_bytes`.
/// - RSS could not be read on this platform (`rss` is `None`): we will not report a misleading
///   maximal headroom when we cannot prove the resident footprint.
///
/// Otherwise it is `ceiling.saturating_sub(rss)` as an `i64` (a 64 MiB edge ceiling is far inside
/// the `i64` range), so headroom never goes negative and the at-or-over-ceiling case reads `0`.
#[must_use]
pub fn ram_headroom_bytes(ceiling: u64, rss: Option<u64>) -> i64 {
    match (ceiling, rss) {
        // No ceiling configured, or RSS unavailable: the headroom is undefined, report the sentinel.
        (0, _) | (_, None) => RSS_UNAVAILABLE,
        (ceiling, Some(rss)) => {
            let headroom = ceiling.saturating_sub(rss);
            i64::try_from(headroom).unwrap_or(i64::MAX)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_has_a_nonzero_rss_on_supported_platforms() {
        // On Linux and macOS we can always read our OWN RSS, and it is non-zero. On any other
        // platform the read is `None` (and the gauge degrades to the unavailable sentinel), which
        // this test tolerates rather than failing the build on an exotic target.
        if let Some(bytes) = current_rss_bytes() {
            assert!(bytes > 0, "our own RSS should be non-zero, got {bytes}");
        }
    }

    #[test]
    fn headroom_is_ceiling_minus_rss() {
        // A measured RSS below the ceiling yields the exact remaining headroom.
        assert_eq!(ram_headroom_bytes(100, Some(40)), 60);
        // At the ceiling the headroom is zero, not negative.
        assert_eq!(ram_headroom_bytes(100, Some(100)), 0);
        // Over the ceiling saturates at zero (never negative, which is the unavailable sentinel).
        assert_eq!(ram_headroom_bytes(100, Some(140)), 0);
    }

    #[test]
    fn headroom_is_unavailable_without_a_ceiling_or_an_rss() {
        // No ceiling configured (the default): the gauge is the unavailable sentinel.
        assert_eq!(ram_headroom_bytes(0, Some(40)), RSS_UNAVAILABLE);
        // RSS could not be read: the gauge is the unavailable sentinel, NOT a misleading max headroom.
        assert_eq!(ram_headroom_bytes(100, None), RSS_UNAVAILABLE);
        // Both unusable: still the sentinel.
        assert_eq!(ram_headroom_bytes(0, None), RSS_UNAVAILABLE);
    }
}
