// SPDX-License-Identifier: MIT OR Apache-2.0
//! Out-of-band probes sampled WHILE the run is in flight: the broker's steady-state resident set
//! (RSS) and the on-disk size of its data directory.
//!
//! These are sampled, not derived from the message stream, so they measure the real process under
//! real load: RSS proves the broker does not grow without bound under overload (#10 shed-not-OOM),
//! and the data-dir byte total against the payload bytes produced gives the WRITE AMPLIFICATION
//! (framing, headers, checkpoints, segment overhead per byte of user payload).

use std::path::Path;

/// Reads the resident set size (RSS), in bytes, of process `pid`. Returns `None` if it cannot be
/// determined on this platform (so the caller records "unavailable" rather than a wrong zero).
///
/// On Linux RSS is `VmRSS` from `/proc/<pid>/status` (pages already reported in kB). On macOS we
/// shell out to `ps -o rss=` (kB), the portable way to read another process's RSS without a private
/// task port. On any other platform there is no portable reading, so `None`.
#[must_use]
pub fn rss_bytes(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        rss_bytes_linux(pid)
    }
    #[cfg(target_os = "macos")]
    {
        rss_bytes_macos(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Linux: parse `VmRSS:\t<n> kB` out of `/proc/<pid>/status`.
#[cfg(target_os = "linux")]
fn rss_bytes_linux(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// macOS: `ps -o rss= -p <pid>` prints the RSS in kB with no header.
#[cfg(target_os = "macos")]
fn rss_bytes_macos(pid: u32) -> Option<u64> {
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

/// Sums the byte size of every regular file under `dir`, recursively: the durable footprint of the
/// data directory (segments, checkpoints, DLQ). Compared against the payload bytes produced, this
/// is the run's write amplification. A read error on any entry is skipped (the directory may be
/// mutated by the live broker mid-walk), so the sample is a best-effort point-in-time total.
#[must_use]
pub fn dir_size_bytes(dir: &Path) -> u64 {
    fn walk(dir: &Path, acc: &mut u64) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => walk(&path, acc),
                Ok(ft) if ft.is_file() => {
                    if let Ok(meta) = entry.metadata() {
                        *acc = acc.saturating_add(meta.len());
                    }
                }
                _ => {}
            }
        }
    }
    let mut acc = 0;
    walk(dir, &mut acc);
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_has_a_nonzero_rss() {
        // We can always read our OWN RSS on a supported platform; it is non-zero.
        if let Some(bytes) = rss_bytes(std::process::id()) {
            assert!(bytes > 0, "our own RSS should be non-zero, got {bytes}");
        }
    }

    #[test]
    fn dir_size_sums_files_recursively() {
        let dir =
            std::env::temp_dir().join(format!("ironbus-bench-dirsize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.bin"), [0u8; 100]).unwrap();
        std::fs::write(dir.join("sub").join("b.bin"), [0u8; 50]).unwrap();
        assert_eq!(dir_size_bytes(&dir), 150, "100 + 50 across one nested dir");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
