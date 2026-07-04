// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable-write io-mode selection and storage-substrate detection.
//!
//! The `direct` io-mode (the SAFE T1 tier) writes record bytes straight to the device with
//! `O_DIRECT` over pre-formatted `written` extents and KEEPS the durability barrier, so it is
//! correct on ANY substrate — the barrier is never dropped. Its performance WIN, though, only
//! materializes on network-durable block storage (EBS-class): the barrier there becomes
//! metadata-free and its residual cost is the substrate's true (near-zero on durable-on-ack)
//! flush. On a local SSD or laptop the O_DIRECT round-trip buys nothing.
//!
//! Hence three knobs (`--io-mode <buffered|direct|auto>`), resolved ONCE at boot after the data
//! dir exists:
//! * `buffered` (default): today's `StdFile` — buffered `pwrite` + `fdatasync`. Everywhere.
//! * `direct`: force the T1 O_DIRECT+kept-barrier file. Safe on any substrate; a loud WARN if the
//!   substrate is not confirmed network-durable (it is still safe, just maybe not faster). Linux
//!   only — a non-Linux host has no `O_DIRECT`, so `direct` degrades to `buffered` with a WARN.
//! * `auto`: enable `direct` ONLY where a probe positively confirms network-durable storage
//!   (the EBS-class signal); fail closed to `buffered` on anything uncertain, local-volatile, or
//!   non-Linux. `auto` never turns direct on speculatively.
//!
//! The detection walks the data dir's backing block device in `/sys` (Linux). The RISK-FREE
//! posture: any probe failure resolves to `Unknown`, and `auto`'s only reaction to `Unknown` is
//! to stay buffered — so a probe bug can never do worse than pick the safe default. The
//! classification + mode-mapping are pure functions ([`classify`], [`resolve`]) tested against
//! fixtures on every platform; only the thin `/sys` reader is Linux-only and best-effort.

use std::path::Path;

/// The io-mode a user asks for (`--io-mode`, `IRONBUS_IO_MODE`, `storage.io_mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoMode {
    /// The DEFAULT: buffered `pwrite` + `fdatasync` (today's `StdFile`), on every platform.
    Buffered,
    /// Force the T1 `O_DIRECT` direct-write file with the barrier kept.
    Direct,
    /// Enable `direct` only where the substrate probe confirms network-durable storage; else
    /// fall back to `buffered`.
    Auto,
}

impl IoMode {
    /// Parses the flag / env / config spelling, accepting `buffered`, `direct`, or `auto`.
    #[must_use]
    pub fn parse(value: &str) -> Option<IoMode> {
        match value {
            "buffered" => Some(IoMode::Buffered),
            "direct" => Some(IoMode::Direct),
            "auto" => Some(IoMode::Auto),
            _ => None,
        }
    }

    /// The canonical spelling, the inverse of [`IoMode::parse`] (for the materialized-config log
    /// and a resolvable default).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            IoMode::Buffered => "buffered",
            IoMode::Direct => "direct",
            IoMode::Auto => "auto",
        }
    }
}

/// The io-mode actually in force after resolution — the two file strategies the storage layer
/// can build. (`auto` and the substrate probe collapse into one of these before any fd opens.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedIoMode {
    /// Buffered `StdFile` (default). Byte-and-behavior identical to today.
    Buffered,
    /// The T1 `O_DIRECT` direct-write file with the durability barrier kept.
    Direct,
}

/// How the backing storage substrate classifies for the io-mode decision. The ONLY positive
/// class is [`SubstrateClass::NetworkDurable`] (an EBS-class device `auto` will enable direct on);
/// everything else is a conservative non-positive that keeps `auto` buffered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstrateClass {
    /// Confirmed network-durable block storage (the EBS allowlist): `auto` enables direct here.
    NetworkDurable,
    /// Confirmed local + volatile (an instance-store `NVMe` / ephemeral disk): `auto` stays
    /// buffered (direct would add an `O_DIRECT` round-trip for no durability win).
    LocalVolatile,
    /// Could not be positively classified (a generic disk, an unresolvable stacked device, a
    /// non-Linux host, or any probe failure). `auto` fails closed to buffered.
    Unknown,
}

/// The raw signals a `/sys` probe (or a test fixture) gathers about the data dir's backing block
/// device. Every field is optional/best-effort: an absent or unreadable signal is `None`/`false`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubstrateProbe {
    /// `/sys/block/<phys>/device/model`, trimmed (e.g. `Amazon Elastic Block Store`).
    pub model: Option<String>,
    /// `/sys/block/<phys>/queue/rotational` (`0` = non-rotational). A corroborator only.
    pub rotational: Option<bool>,
    /// `/sys/block/<phys>/queue/write_cache` (`write through` / `write back`). INCONCLUSIVE for the
    /// durability question on EBS (`write back` is a conservative flag on a durable-on-ack device),
    /// so it is recorded for the log but never disqualifies T1.
    pub write_cache: Option<String>,
    /// A device-mapper / MD / LVM / loop layer that the probe could NOT resolve to a backing
    /// physical device (e.g. a writeback dm-cache, or an unreadable `slaves/` tree). Forces
    /// [`SubstrateClass::Unknown`] — the stacked-device fail-closed.
    pub stacked_unresolved: bool,
}

/// The confirmed network-durable device models (substring match, case-insensitive). Kept
/// deliberately tiny and explicit: only devices whose durability-on-ack is documented.
const NETWORK_DURABLE_MODELS: &[&str] = &[
    "amazon elastic block store",
    "nvme amazon elastic block store",
];

/// Confirmed local + volatile device models (substring match): lost on stop/terminate, so never a
/// direct-mode win and explicitly rejected from `auto`.
const LOCAL_VOLATILE_MODELS: &[&str] = &["amazon ec2 nvme instance storage", "instance storage"];

/// Classifies a substrate probe. Pure and total — tested against `/sys` fixtures on every
/// platform. Fail-closed: an unresolved stacked device or an unrecognized model is
/// [`SubstrateClass::Unknown`], never an optimistic positive.
#[must_use]
pub fn classify(probe: &SubstrateProbe) -> SubstrateClass {
    // A stacked device we could not walk down to a physical backing store (a writeback dm-cache
    // hides the true durability behind the virtual node) is Unknown — the fail-closed hardening.
    if probe.stacked_unresolved {
        return SubstrateClass::Unknown;
    }
    if let Some(model) = &probe.model {
        let m = model.to_ascii_lowercase();
        // Local-volatile is checked FIRST so an instance-store device is never mistaken for durable.
        if LOCAL_VOLATILE_MODELS.iter().any(|k| m.contains(k)) {
            return SubstrateClass::LocalVolatile;
        }
        if NETWORK_DURABLE_MODELS.iter().any(|k| m.contains(k)) {
            return SubstrateClass::NetworkDurable;
        }
    }
    // No decisive model: do not guess network-durable from rotational/write_cache alone (neither is
    // decisive for the durability-on-ack question). Unknown — `auto` stays buffered.
    SubstrateClass::Unknown
}

/// A resolved io-mode plus the human-readable notes to log at boot (mirroring how the durability
/// level logs its choice). A `warn` note is a loud banner (a fall-back the operator should see);
/// an info note is the routine "here is what I picked and why".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoModeResolution {
    /// The io-mode actually in force.
    pub mode: ResolvedIoMode,
    /// Notes to log, in order.
    pub notes: Vec<IoModeNote>,
}

/// One boot-time note about the io-mode decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoModeNote {
    /// `true` = a loud WARN banner; `false` = an INFO line.
    pub warn: bool,
    /// The message.
    pub message: String,
}

impl IoModeResolution {
    fn info(mode: ResolvedIoMode, message: impl Into<String>) -> IoModeResolution {
        IoModeResolution {
            mode,
            notes: vec![IoModeNote {
                warn: false,
                message: message.into(),
            }],
        }
    }
    fn warn(mode: ResolvedIoMode, message: impl Into<String>) -> IoModeResolution {
        IoModeResolution {
            mode,
            notes: vec![IoModeNote {
                warn: true,
                message: message.into(),
            }],
        }
    }
}

/// Whether the host has ``O_DIRECT`` (Linux). The `direct`/`auto` modes are Linux-first; on any
/// other unix ``O_DIRECT`` does not exist, so the resolver degrades to buffered.
#[must_use]
pub const fn host_supports_direct() -> bool {
    cfg!(target_os = "linux")
}

/// Maps a requested [`IoMode`] + the substrate [`SubstrateClass`] + host ``O_DIRECT`` support to the
/// [`ResolvedIoMode`] in force, plus the notes to log. Pure — the whole decision matrix, tested
/// exhaustively without touching a real disk.
///
/// * `buffered` -> buffered, always, no note.
/// * `direct` -> direct on a host with ``O_DIRECT`` (INFO if network-durable is confirmed, WARN
///   otherwise — still safe, the barrier is kept); on a host without ``O_DIRECT`` -> buffered + WARN.
/// * `auto` -> direct ONLY on a confirmed [`SubstrateClass::NetworkDurable`] host with ``O_DIRECT``;
///   otherwise buffered (fail-closed) with an INFO explaining why.
#[must_use]
pub fn resolve(requested: IoMode, class: SubstrateClass, host_direct: bool) -> IoModeResolution {
    match requested {
        IoMode::Buffered => IoModeResolution {
            mode: ResolvedIoMode::Buffered,
            notes: Vec::new(),
        },
        IoMode::Direct => {
            if !host_direct {
                return IoModeResolution::warn(
                    ResolvedIoMode::Buffered,
                    "io-mode=direct requested but this host has no O_DIRECT (direct is Linux-only); \
                     falling back to buffered (fully durable, unchanged behavior)",
                );
            }
            match class {
                SubstrateClass::NetworkDurable => IoModeResolution::info(
                    ResolvedIoMode::Direct,
                    "io-mode=direct on confirmed network-durable storage: O_DIRECT writes over \
                     pre-formatted written extents, durability barrier KEPT (ack-implies-durable holds)",
                ),
                SubstrateClass::LocalVolatile => IoModeResolution::warn(
                    ResolvedIoMode::Direct,
                    "io-mode=direct on LOCAL-VOLATILE storage (instance-store/ephemeral): still \
                     durable (the barrier is kept), but likely NO throughput win here — direct mode \
                     targets network-durable block storage",
                ),
                SubstrateClass::Unknown => IoModeResolution::warn(
                    ResolvedIoMode::Direct,
                    "io-mode=direct on a substrate that could not be confirmed network-durable: \
                     enabling direct anyway — it is SAFE (the durability barrier is kept), it just \
                     may not be faster; pass --io-mode=buffered to opt out",
                ),
            }
        }
        IoMode::Auto => {
            if !host_direct {
                return IoModeResolution::info(
                    ResolvedIoMode::Buffered,
                    "io-mode=auto: no O_DIRECT on this host (Linux-only); using buffered",
                );
            }
            match class {
                SubstrateClass::NetworkDurable => IoModeResolution::info(
                    ResolvedIoMode::Direct,
                    "io-mode=auto detected network-durable storage: enabling direct (O_DIRECT + \
                     kept barrier)",
                ),
                SubstrateClass::LocalVolatile => IoModeResolution::info(
                    ResolvedIoMode::Buffered,
                    "io-mode=auto: local-volatile storage detected — using buffered (direct has no \
                     win here)",
                ),
                SubstrateClass::Unknown => IoModeResolution::info(
                    ResolvedIoMode::Buffered,
                    "io-mode=auto: could not confirm network-durable storage — failing closed to \
                     buffered (pass --io-mode=direct to force it; it is safe anywhere)",
                ),
            }
        }
    }
}

/// Resolves the io-mode for a real data directory: probes the backing substrate (Linux; a
/// best-effort, fail-closed `/sys` walk) and runs the pure [`resolve`]. Non-Linux hosts skip the
/// probe (there is no ``O_DIRECT`` to enable).
#[must_use]
pub fn resolve_for_dir(requested: IoMode, data_dir: &Path) -> IoModeResolution {
    // Buffered needs no probe (and the probe's only consumer is the direct/auto path).
    if requested == IoMode::Buffered {
        return resolve(requested, SubstrateClass::Unknown, host_supports_direct());
    }
    let class = classify(&probe_backing_substrate(data_dir));
    resolve(requested, class, host_supports_direct())
}

/// Gathers the backing-device signals for `data_dir`. Linux reads `/sys`; every other platform
/// (and every failure) yields a probe that classifies as [`SubstrateClass::Unknown`].
#[cfg(target_os = "linux")]
fn probe_backing_substrate(data_dir: &Path) -> SubstrateProbe {
    linux_probe::probe(data_dir).unwrap_or(SubstrateProbe {
        stacked_unresolved: true,
        ..SubstrateProbe::default()
    })
}

/// Non-Linux: no `/sys`, no ``O_DIRECT``. Return an Unknown-classifying probe; the resolver already
/// short-circuits a non-``O_DIRECT`` host to buffered regardless.
#[cfg(not(target_os = "linux"))]
fn probe_backing_substrate(_data_dir: &Path) -> SubstrateProbe {
    SubstrateProbe::default()
}

/// The Linux-only, best-effort `/sys` reader. Isolated so its untested-on-macOS surface is small
/// and every failure path returns `None` (→ Unknown → `auto` stays buffered), so a bug here can
/// never do worse than pick the safe default.
#[cfg(target_os = "linux")]
mod linux_probe {
    use super::SubstrateProbe;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// Probes the block device backing `data_dir`, walking a stacked (`dm`/`md`/`loop`) node down to
    /// its physical backing device before reading the model / rotational / `write_cache` signals.
    pub(super) fn probe(data_dir: &Path) -> Option<SubstrateProbe> {
        let dev = std::fs::metadata(data_dir).ok()?.dev();
        // `major`/`minor` are safe pure-arithmetic libc fns on Linux (no memory access).
        let (major, minor) = (libc::major(dev), libc::minor(dev));
        let sys_block = Path::new("/sys/dev/block").join(format!("{major}:{minor}"));
        // Canonicalize the symlink into /sys/devices/... so we can inspect the real node.
        let node = std::fs::canonicalize(&sys_block).ok()?;

        let mut probe = SubstrateProbe::default();
        // Resolve down to the physical device (strip a partition, descend a stacked node).
        let Some(phys) = resolve_physical(&node) else {
            probe.stacked_unresolved = true;
            return Some(probe);
        };

        probe.model = read_trimmed(&phys.join("device/model"));
        // The `rotational` file is "1" (rotational) or "0" (non-rotational); anything else -> None.
        probe.rotational = match read_trimmed(&phys.join("queue/rotational")).as_deref() {
            Some("0") => Some(false),
            Some("1") => Some(true),
            _ => None,
        };
        probe.write_cache = read_trimmed(&phys.join("queue/write_cache"));
        Some(probe)
    }

    /// Given a `/sys/devices/.../<node>` path, resolve to the physical device directory: strip a
    /// partition to its parent disk, and descend one `slaves/` level for a `dm`/`md`/`loop` node.
    /// Returns `None` (→ `stacked_unresolved`) if a stacked node cannot be walked down.
    fn resolve_physical(node: &Path) -> Option<std::path::PathBuf> {
        let name = node.file_name()?.to_str()?.to_string();
        // A partition has a `partition` file; its disk is the parent directory.
        if node.join("partition").exists() {
            if let Some(parent) = node.parent() {
                return resolve_physical(parent);
            }
        }
        // A stacked node (device-mapper/MD/loop) exposes its backing devices under `slaves/`.
        let is_stacked = name.starts_with("dm-")
            || name.starts_with("md")
            || name.starts_with("loop")
            || node.join("slaves").is_dir() && has_entries(&node.join("slaves"));
        if is_stacked {
            let slaves = node.join("slaves");
            let first = std::fs::read_dir(&slaves).ok()?.flatten().next()?;
            let backing = std::fs::canonicalize(first.path()).ok()?;
            return resolve_physical(&backing);
        }
        Some(node.to_path_buf())
    }

    fn has_entries(dir: &Path) -> bool {
        std::fs::read_dir(dir)
            .ok()
            .and_then(|mut d| d.next())
            .is_some()
    }

    fn read_trimmed(path: &Path) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_mode_parse_roundtrips() {
        for m in [IoMode::Buffered, IoMode::Direct, IoMode::Auto] {
            assert_eq!(IoMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(IoMode::parse("nonsense"), None);
        assert_eq!(IoMode::parse(""), None);
    }

    fn probe_model(model: &str) -> SubstrateProbe {
        SubstrateProbe {
            model: Some(model.to_string()),
            rotational: Some(false),
            write_cache: Some("write back".to_string()),
            stacked_unresolved: false,
        }
    }

    #[test]
    fn classify_confirms_ebs_as_network_durable() {
        // The primary positive signal: the EBS device model, even with a `write back` cache (which
        // is INCONCLUSIVE, not disqualifying, on a durable-on-ack device).
        assert_eq!(
            classify(&probe_model("Amazon Elastic Block Store")),
            SubstrateClass::NetworkDurable
        );
        assert_eq!(
            classify(&probe_model("nvme Amazon Elastic Block Store")),
            SubstrateClass::NetworkDurable
        );
    }

    #[test]
    fn classify_rejects_instance_store_as_local_volatile() {
        assert_eq!(
            classify(&probe_model("Amazon EC2 NVMe Instance Storage")),
            SubstrateClass::LocalVolatile
        );
    }

    #[test]
    fn classify_is_unknown_for_a_generic_or_absent_model() {
        assert_eq!(
            classify(&probe_model("Samsung SSD 990 PRO")),
            SubstrateClass::Unknown
        );
        assert_eq!(
            classify(&SubstrateProbe::default()),
            SubstrateClass::Unknown
        );
        // write_cache alone (write through / write back) is never decisive on its own.
        let mut p = SubstrateProbe {
            write_cache: Some("write through".to_string()),
            ..Default::default()
        };
        assert_eq!(classify(&p), SubstrateClass::Unknown);
        p.write_cache = Some("write back".to_string());
        assert_eq!(classify(&p), SubstrateClass::Unknown);
    }

    #[test]
    fn classify_fails_closed_on_an_unresolved_stacked_device() {
        // Even an EBS-looking model is Unknown if it sits behind a stacked node we could not walk
        // down (a writeback dm-cache could be hiding the true durability).
        let p = SubstrateProbe {
            model: Some("Amazon Elastic Block Store".to_string()),
            stacked_unresolved: true,
            ..Default::default()
        };
        assert_eq!(classify(&p), SubstrateClass::Unknown);
    }

    #[test]
    fn resolve_buffered_is_always_buffered_with_no_note() {
        for class in [
            SubstrateClass::NetworkDurable,
            SubstrateClass::LocalVolatile,
            SubstrateClass::Unknown,
        ] {
            for host in [true, false] {
                let r = resolve(IoMode::Buffered, class, host);
                assert_eq!(r.mode, ResolvedIoMode::Buffered);
                assert!(r.notes.is_empty());
            }
        }
    }

    #[test]
    fn resolve_direct_enables_direct_on_any_substrate_when_host_supports_it() {
        // T1 is safe everywhere, so explicit `direct` always enables direct on an O_DIRECT host —
        // INFO on confirmed network-durable, WARN otherwise (still safe).
        let net = resolve(IoMode::Direct, SubstrateClass::NetworkDurable, true);
        assert_eq!(net.mode, ResolvedIoMode::Direct);
        assert!(!net.notes[0].warn);

        for class in [SubstrateClass::LocalVolatile, SubstrateClass::Unknown] {
            let r = resolve(IoMode::Direct, class, true);
            assert_eq!(
                r.mode,
                ResolvedIoMode::Direct,
                "direct is safe on {class:?}"
            );
            assert!(r.notes[0].warn, "unconfirmed direct warns loudly");
        }
    }

    #[test]
    fn resolve_direct_without_o_direct_falls_back_to_buffered_loudly() {
        let r = resolve(IoMode::Direct, SubstrateClass::NetworkDurable, false);
        assert_eq!(r.mode, ResolvedIoMode::Buffered);
        assert!(r.notes[0].warn);
    }

    #[test]
    fn resolve_auto_enables_direct_only_on_confirmed_network_durable() {
        assert_eq!(
            resolve(IoMode::Auto, SubstrateClass::NetworkDurable, true).mode,
            ResolvedIoMode::Direct
        );
        // Fail-closed to buffered on everything else, including unknown and local-volatile.
        for class in [SubstrateClass::LocalVolatile, SubstrateClass::Unknown] {
            assert_eq!(
                resolve(IoMode::Auto, class, true).mode,
                ResolvedIoMode::Buffered,
                "auto fails closed on {class:?}"
            );
        }
        // And never on a non-O_DIRECT host.
        assert_eq!(
            resolve(IoMode::Auto, SubstrateClass::NetworkDurable, false).mode,
            ResolvedIoMode::Buffered
        );
    }

    #[test]
    fn resolve_for_dir_buffered_needs_no_probe() {
        // A missing directory must not matter for buffered (no probe path taken).
        let r = resolve_for_dir(IoMode::Buffered, Path::new("/nonexistent/does/not/matter"));
        assert_eq!(r.mode, ResolvedIoMode::Buffered);
    }

    #[test]
    fn resolve_for_dir_on_non_linux_is_buffered() {
        // On this build's host: direct/auto degrade to buffered unless it is Linux (where the probe
        // may still say buffered). The point: never a panic, always a resolution.
        let r = resolve_for_dir(IoMode::Auto, Path::new("."));
        if !host_supports_direct() {
            assert_eq!(r.mode, ResolvedIoMode::Buffered);
        }
        // direct on a non-linux host falls back to buffered with a warn.
        let d = resolve_for_dir(IoMode::Direct, Path::new("."));
        if !host_supports_direct() {
            assert_eq!(d.mode, ResolvedIoMode::Buffered);
            assert!(d.notes.iter().any(|n| n.warn));
        }
    }
}
