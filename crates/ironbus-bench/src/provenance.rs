// SPDX-License-Identifier: MIT OR Apache-2.0
//! The versioned provenance JSON emitted for EVERY run.
//!
//! A latency number is only useful if it is reproducible and attributable: which binary, on which
//! host, under which config, against which clock. The provenance record captures all of that plus
//! the RAW `HdrHistogram` (V2+DEFLATE, base64), so a downstream tool can recompute any percentile,
//! merge runs across windows, and re-run the exact command. The `schema_version` lets a consumer
//! reject a record shape it does not understand rather than silently misread it.

use crate::clock;
use crate::harness::RunReport;
use hdrhistogram::serialization::{Serializer, V2DeflateSerializer};
use serde::Serialize;
use std::time::Duration;

/// The provenance schema version. Bump on any breaking change to the JSON shape so a consumer can
/// gate on it.
pub const SCHEMA_VERSION: u32 = 1;

/// The full, serializable provenance record for one run.
#[derive(Serialize)]
pub struct Provenance {
    /// The provenance schema version (see [`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// The IronBus git SHA the broker was built from, or `"unknown"` if it could not be read.
    pub git_sha: String,
    /// Whether the working tree was dirty when built (`true` => the SHA does not fully describe it).
    pub git_dirty: bool,
    /// The Cargo profile and notable build flags the harness was compiled under.
    pub build: BuildInfo,
    /// The host the run executed on.
    pub host: HostInfo,
    /// The clock source the latency was measured against.
    pub clock_source: String,
    /// The run configuration, flattened to plain numbers.
    pub config: ConfigInfo,
    /// The headline results.
    pub results: ResultsInfo,
    /// The RAW histogram, base64 of the standard `HdrHistogram` V2+DEFLATE encoding, so percentiles
    /// recompute and runs merge. Decodable by any `HdrHistogram` library that reads the V2 format.
    pub histogram_v2_deflate_base64: String,
    /// A copy-pasteable command that reproduces this run.
    pub reproduce: String,
}

/// Build-time facts.
#[derive(Serialize)]
pub struct BuildInfo {
    /// `"release"` or `"debug"`.
    pub profile: &'static str,
    /// The rustc target triple the harness was built for.
    pub target: &'static str,
}

/// Host facts.
#[derive(Serialize)]
pub struct HostInfo {
    /// The OS family (`unix` / `windows`) as compiled.
    pub family: &'static str,
    /// The target OS (e.g. `linux`, `macos`).
    pub os: &'static str,
    /// The target architecture (e.g. `x86_64`, `aarch64`).
    pub arch: &'static str,
    /// The hostname, or `"unknown"` if it could not be read.
    pub hostname: String,
    /// Available parallelism (logical CPUs), or 0 if unavailable.
    pub logical_cpus: usize,
}

/// The run config as plain numbers (so the JSON does not depend on `Duration`'s serde shape).
#[derive(Serialize)]
pub struct ConfigInfo {
    /// Target arrival rate, messages per second.
    pub target_rate_hz: f64,
    /// Run duration in milliseconds.
    pub duration_ms: u64,
    /// Payload size in bytes.
    pub payload_bytes: usize,
    /// Receiver fetch batch (credit window).
    pub fetch_batch: u32,
    /// The deterministic RNG seed for the Poisson jitter.
    pub seed: u64,
}

/// The headline results, in the units the SLO is stated in.
#[derive(Serialize)]
pub struct ResultsInfo {
    /// Messages the receiver recorded end-to-end.
    pub recorded: u64,
    /// Achieved throughput, messages per second.
    pub msgs_per_sec: f64,
    /// Achieved throughput, megabytes per second.
    pub mb_per_sec: f64,
    /// p50 latency, microseconds.
    pub p50_us: f64,
    /// p99 latency, microseconds.
    pub p99_us: f64,
    /// p99.9 latency, microseconds.
    pub p999_us: f64,
    /// Max observed latency, microseconds.
    pub max_us: f64,
    /// Steady-state broker RSS, bytes (`null` if the platform could not read it).
    pub steady_rss_bytes: Option<u64>,
    /// Total user payload bytes produced.
    pub payload_bytes_produced: u64,
    /// On-disk data-dir bytes at run end.
    pub data_dir_bytes: u64,
    /// Write amplification (data-dir bytes / payload bytes produced), `null` if nothing produced.
    pub write_amplification: Option<f64>,
    /// Whether the recorded sample is large enough for a trustworthy p99.9.
    pub tail_resolution_ok: bool,
}

impl Provenance {
    /// Assembles the provenance for a finished run. `git_sha`/`git_dirty` come from the build (the
    /// binary's embedded values when available, else `"unknown"`/`false`). `reproduce` is the exact
    /// command line a reader can paste to re-run it.
    #[must_use]
    pub fn from_report(
        report: &RunReport,
        git_sha: String,
        git_dirty: bool,
        reproduce: String,
    ) -> Self {
        Provenance {
            schema_version: SCHEMA_VERSION,
            git_sha,
            git_dirty,
            build: BuildInfo {
                profile: if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                },
                target: env!("IRONBUS_BENCH_TARGET"),
            },
            host: HostInfo {
                family: if cfg!(unix) { "unix" } else { "windows" },
                os: std::env::consts::OS,
                arch: std::env::consts::ARCH,
                hostname: hostname(),
                logical_cpus: std::thread::available_parallelism()
                    .map_or(0, std::num::NonZeroUsize::get),
            },
            clock_source: clock::source_name().to_string(),
            config: ConfigInfo {
                target_rate_hz: report.config.target_rate_hz,
                duration_ms: duration_ms(report.config.duration),
                payload_bytes: report.config.payload_bytes,
                fetch_batch: report.config.fetch_batch,
                seed: report.config.seed,
            },
            results: ResultsInfo {
                recorded: report.recorded,
                msgs_per_sec: report.msgs_per_sec,
                mb_per_sec: report.mb_per_sec,
                p50_us: report.percentiles.p50_us,
                p99_us: report.percentiles.p99_us,
                p999_us: report.percentiles.p999_us,
                max_us: report.percentiles.max_us,
                steady_rss_bytes: report.steady_rss_bytes,
                payload_bytes_produced: report.payload_bytes_produced,
                data_dir_bytes: report.data_dir_bytes,
                write_amplification: report.write_amplification,
                tail_resolution_ok: report.has_tail_resolution(),
            },
            histogram_v2_deflate_base64: encode_histogram(report),
            reproduce,
        }
    }

    /// Serializes the provenance to pretty JSON.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] only if the record cannot be serialized, which cannot happen
    /// for this fully-owned, plain-data shape.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Encodes the run's raw histogram as base64 of the `HdrHistogram` V2+DEFLATE wire format. On the
/// (practically impossible) serializer error, returns an empty string rather than panicking, so a
/// run still emits a record; the headline percentiles in `results` are unaffected.
fn encode_histogram(report: &RunReport) -> String {
    let mut serializer = V2DeflateSerializer::new();
    let mut buf: Vec<u8> = Vec::new();
    match serializer.serialize(&report.histogram, &mut buf) {
        Ok(_) => base64_encode(&buf),
        Err(_) => String::new(),
    }
}

/// Minimal, dependency-free base64 (standard alphabet, with `=` padding). The histogram blob is the
/// only thing encoded and it is not on any hot path, so a tiny self-contained encoder is preferred
/// over pulling a base64 crate onto the dependency surface.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Reads the hostname, falling back to `"unknown"`. Uses `libc::gethostname` on Unix (no extra
/// dependency); on other platforms the harness is not the supported target, so `"unknown"`.
fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: `gethostname` is a foreign function (not a memory-unsafe operation): it writes at
        // most `buf.len()` bytes into our owned, stack-allocated buffer and we pass that exact
        // length, so it cannot overrun. We only read the bytes it actually wrote (up to the NUL).
        #[allow(unsafe_code)]
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
        if rc == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
        "unknown".to_string()
    }
    #[cfg(not(unix))]
    {
        "unknown".to_string()
    }
}

/// A `Duration` as whole milliseconds (saturating).
fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
