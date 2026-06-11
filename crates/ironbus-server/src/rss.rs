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

/// The flat per-process fixed-overhead floor the refuse-to-boot guard charges INDEPENDENT of the
/// tuning knobs: the binary's resident text/data, the runtime (the single mutex-guarded engine
/// state, the embedded health server, the allocator arenas), and the bounded metric registry
/// (`~161 KiB`, #97). `docs/RAM_BUDGET.md` term 5 calls ~4 MiB a conservative working figure for the
/// edge profile; the guard uses exactly that constant so the formula it refuses against is the one
/// the doc itemizes. It is an ESTIMATE, not a code-asserted bound, so the guard is deliberately
/// CONSERVATIVE (it charges the floor on TOP of the bounded buffers) and only ever refuses a config
/// whose bounded buffers ALONE already crowd the ceiling.
pub const FIXED_OVERHEAD_BYTES: u64 = 4 * 1024 * 1024;

/// The per-OS-thread RESIDENT stack the guard charges per connection (one connection is one OS thread
/// in the v1 thread-per-connection server, so this term scales with `max_connections`, as
/// `docs/RAM_BUDGET.md` term 5 notes). A thread's VIRTUAL stack is large (often 8 MiB) but only the
/// touched pages are resident; 64 KiB is a generous estimate of the RESIDENT portion under the
/// broker's shallow per-connection call depth. Keeping it to the resident estimate keeps term 5
/// aligned with the doc's ~4 MiB fixed-overhead figure for the 32-connection edge profile rather than
/// charging the unrealized virtual reservation.
pub const PER_CONNECTION_STACK_BYTES: u64 = 64 * 1024;

/// A generous per-lease byte estimate for the per-group cursor + lease state (`docs/RAM_BUDGET.md`
/// term 3): each `LeaseTable` entry is a small fixed struct plus the `BTreeMap` node overhead, and
/// the `AckCursor`'s acked-ahead range is bounded by the same window. ~64 bytes per lease covers
/// both with margin.
pub const PER_LEASE_BYTES: u64 = 64;

/// How many full byte IMAGES of the store the in-memory backend (#443) can hold at once, the
/// multiplier the #445 footprint proof charges per stored byte under `--storage memory`. The
/// in-memory `Filesystem` (`InMemoryFs` / `InMemoryFile` in `ironbus-storage`) keeps TWO byte
/// images per file: the `live` bytes plus the `durable` image a `sync_data` clones them into (the
/// power-loss simulation contract every conformance suite relies on). At steady state every stored
/// byte therefore exists twice in RSS, so the worst-case in-memory store footprint is
/// `2 * max_total_bytes`, not `max_total_bytes`. The directory-level `sync_dir` clone is only a
/// map of `Arc` pointers (no third byte image), so 2 is the honest multiplier, not a guess.
pub const IN_MEMORY_STORE_IMAGES: u64 = 2;

/// The configuration the refuse-to-boot RAM guard ([`fits_under_ram_ceiling`]) reasons about: the
/// bounded-buffer knobs from `docs/RAM_BUDGET.md` plus `max_connections` (a server-level cap that
/// bounds the in-flight set, the read buffers, and the thread stacks). Every field is a CONFIGURED
/// cap, so the guard's verdict is provable from the config ALONE, never a live RSS reading (RSS at
/// boot is near-zero and says nothing about the steady-state ceiling the caps imply).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamFootprintConfig {
    /// The RAM ceiling in bytes (`ram_ceiling_bytes`); `0` means UNSET, so the guard is a no-op.
    pub ram_ceiling_bytes: u64,
    /// `--max-connections`: bounds the in-flight set, the per-connection read buffers, and the OS
    /// thread stacks all at once (the strongest single RAM lever, `docs/RAM_BUDGET.md` term 2).
    pub max_connections: u64,
    /// `--consumer-credit`: the per-connection un-acked MESSAGE count cap. With no byte budget it is
    /// the only count bound on term 1, so the worst-case message size (a maximal frame) binds.
    pub consumer_credit: u64,
    /// `--consumer-credit-bytes`: the per-connection un-acked PAYLOAD-byte budget (`0` = UNLIMITED,
    /// the byte budget is OFF). The FIRM RAM bound on term 1 when set.
    pub consumer_credit_bytes: u64,
    /// `--max-groups`: the live work-group cap (`0` = UNLIMITED). Bounds term 3 with `max_in_flight`.
    pub max_groups: u64,
    /// `--max-in-flight`: the per-group delivery window. Bounds the per-group lease/cursor state.
    pub max_in_flight: u64,
    /// The STORE's RAM bound (#445): `--max-total-bytes` when the storage backend is the in-memory
    /// store (`--storage memory`, #443), and `0` when the store is on disk. On disk the store is
    /// file-backed (the active segment is ~0 in RSS, `docs/RAM_BUDGET.md` term 4), so it is not a
    /// RAM source and this stays `0`. In memory mode the store IS RAM: every stored byte lives in
    /// the process, up to the byte cap, and is charged at [`IN_MEMORY_STORE_IMAGES`] images (the
    /// live bytes plus the durable-image clone `sync_data` keeps). The caller passes the resolved
    /// `max_total_bytes` here; memory mode refuses an unlimited (`0`) cap upstream, so a `0` always
    /// means "the store is not in RAM", never "unbounded RAM store".
    pub in_memory_store_bytes: u64,
}

/// The worst-case STEADY-STATE bounded-buffer footprint (in bytes) the configured caps imply,
/// derived purely from [`RamFootprintConfig`] (no live RSS, no IO). This is the quantity the
/// refuse-to-boot guard (#115, #19, #10) compares against the ceiling: it is the sum of the
/// FIRMLY-BOUNDED RAM sources `docs/RAM_BUDGET.md` itemizes, each multiplied out to its CONFIGURED
/// cap, so a verdict of "does not fit" is a PROOF from the config that the buffers cannot stay under
/// the ceiling, NOT a live-RSS guess (RSS at boot is near-zero and meaningless as a steady-state
/// predictor).
///
/// The terms (cited to `docs/RAM_BUDGET.md`), and the deliberate honesty about what is and is not
/// counted:
///
/// - **Term 1, per-connection in-flight payloads (the dominant, firmly-bounded term).** Each
///   connection holds at most `consumer_credit_bytes` un-acked PAYLOAD bytes (the firm RAM bound,
///   #275): `max_connections * consumer_credit_bytes`. When `consumer_credit_bytes` is `0` (the byte
///   budget is OFF, only the MESSAGE count binds) there is NO byte-side bound on a connection's
///   in-flight RAM, so the only provable bound is `consumer_credit` maximal frames each
///   (`consumer_credit * MAX_FRAME_LEN`): a config with no byte budget therefore cannot be PROVEN to
///   fit a small ceiling and is correctly refused. This is exactly the term the task names
///   (`max_connections * consumer_credit_bytes` worst case) and the firm RAM-side bound
///   `docs/EDGE_CONSTRAINTS.md` lists for the RAM-ceiling row.
/// - **Term 3, per-group cursor + lease state.** `max_groups * max_in_flight * PER_LEASE_BYTES`.
/// - **Term 5, fixed overhead + thread stacks.** [`FIXED_OVERHEAD_BYTES`] plus
///   `max_connections * PER_CONNECTION_STACK_BYTES` (one OS thread per connection).
///
/// NOT counted here, and WHY (this is the honest boundary of what the guard can prove):
///
/// - **Term 2, the per-connection read buffer**, is bounded only by `max_connections * MAX_FRAME_LEN`
///   (`~514 MiB` at the edge-tiny `max_connections = 32`), NOT by any credit knob, because
///   `MAX_FRAME_LEN` is a protocol constant, not a `serve` knob. `docs/RAM_BUDGET.md` is explicit
///   that this adversarial ~514 MiB spike is realized only if every connection is SIMULTANEOUSLY
///   mid-assembly of a near-maximal frame (which an edge workload of small records never does) and
///   is NOT part of the steady-state budget that sums under 64 MiB; bounding it tightly needs an
///   on-the-wire record-size cap and is tracked as the read-buffer follow-up. Charging it here would
///   refuse EVERY edge config, including the worked edge-tiny one the doc proves fits, so the guard
///   deliberately excludes it and asserts the firmly-bounded steady-state sum the doc itemizes.
/// - **Term 4 (the store).** On DISK it is ~0 in RSS (the active segment is written straight to
///   file) and is not charged. Under `--storage memory` (#443) the store ITSELF is RAM, so the
///   #445 memory-backend fold charges it: `in_memory_store_bytes` (the resolved
///   `--max-total-bytes` cap, the most stored bytes the engine ever retains) times
///   [`IN_MEMORY_STORE_IMAGES`] (the live bytes PLUS the durable-image clone the in-memory
///   filesystem keeps per file at every `sync_data`). Disk mode passes `0` here, so the disk
///   verdict is bit-for-bit the historical one.
/// - **The dead-letter sink (the DLQ), a DELIBERATE memory-mode exclusion.** The DLQ's log is
///   byte-UNCAPPED by design (its `LogConfig.max_total_bytes` is `0`: a poison record is the
///   durable evidence of a dropped message and must never itself be shed), and under
///   `--storage memory` it lives on the SAME in-memory filesystem as the store, so dead-lettered
///   bytes are RAM this model does not charge. The store term above bounds the MAIN log only, and
///   the guard's proof holds for ACK-PROGRESSING workloads: a poison-heavy workload (consumers
///   that never ack, so records dead-letter after `max_deliver` attempts) grows RSS OUTSIDE this
///   modeled floor. Capping the DLQ would shed poison evidence, a different design decision; the
///   honest mitigation is operational, so pair memory mode with consumers that make ack progress,
///   watch `ironbus_dlq_records_total`, and tune `--max-deliver`.
/// - **Term 6 (dedup)** costs nothing until a producer opts in, so it is not charged.
///
/// Every multiply and add SATURATES, so an unbounded (`0` = off) cap that would overflow instead
/// saturates to [`u64::MAX`] and the config is correctly refused under any real ceiling.
#[must_use]
pub fn worst_case_buffer_bytes(config: &RamFootprintConfig) -> u64 {
    let max_record = u64::from(ironbus_proto::frame::MAX_FRAME_LEN);

    // Term 1: per-connection un-acked PAYLOAD bytes, the firm RAM bound. With a byte budget set it is
    // `consumer_credit_bytes` per connection; with it OFF (0 = unlimited) the message COUNT is the
    // only bound, so the provable worst case is `consumer_credit` maximal frames each (which a small
    // ceiling cannot fit, so the config is honestly refused rather than waved through).
    let per_conn_inflight = if config.consumer_credit_bytes == 0 {
        config.consumer_credit.saturating_mul(max_record)
    } else {
        config.consumer_credit_bytes
    };
    let term1 = config.max_connections.saturating_mul(per_conn_inflight);

    // Term 3: per-group cursor + lease state.
    let term3 = config
        .max_groups
        .saturating_mul(config.max_in_flight)
        .saturating_mul(PER_LEASE_BYTES);

    // Term 4, the IN-MEMORY store (#445): zero on disk (file-backed, ~0 RSS); under `--storage
    // memory` the byte cap times the two byte images (live + the durable clone) the in-memory
    // filesystem holds per file. See `IN_MEMORY_STORE_IMAGES` for why the multiplier is exactly 2.
    let term4_memory_store = config
        .in_memory_store_bytes
        .saturating_mul(IN_MEMORY_STORE_IMAGES);

    // Term 5: fixed overhead + one OS thread stack per connection.
    let term5 = FIXED_OVERHEAD_BYTES.saturating_add(
        config
            .max_connections
            .saturating_mul(PER_CONNECTION_STACK_BYTES),
    );

    term1
        .saturating_add(term3)
        .saturating_add(term4_memory_store)
        .saturating_add(term5)
}

/// The verdict of the refuse-to-boot RAM guard for a configuration ([`fits_under_ram_ceiling`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamCeilingVerdict {
    /// No ceiling is configured (`ram_ceiling_bytes == 0`): the guard does not apply, the broker
    /// boots, and `ironbus_ram_headroom_bytes` reports the unavailable sentinel.
    Disabled,
    /// A ceiling is set and the worst-case bounded-buffer footprint fits under it: the broker boots.
    Fits {
        /// The worst-case bounded-buffer footprint the configured caps imply.
        worst_case_bytes: u64,
        /// The configured ceiling.
        ceiling_bytes: u64,
    },
    /// A ceiling is set and the worst-case bounded-buffer footprint PROVABLY exceeds it: the broker
    /// REFUSES to boot. The overage is the bytes by which the worst case is over the ceiling.
    Exceeds {
        /// The worst-case bounded-buffer footprint the configured caps imply.
        worst_case_bytes: u64,
        /// The configured ceiling.
        ceiling_bytes: u64,
        /// `worst_case_bytes - ceiling_bytes`: the provable overage the operator must close.
        overage_bytes: u64,
    },
}

/// The refuse-to-boot RAM guard (#115, #19, #10): decides whether the configured caps can PROVABLY
/// fit the broker's worst-case bounded-buffer footprint under the configured RAM ceiling.
///
/// The decision is purely a function of the config (via [`worst_case_buffer_bytes`]), NEVER a live
/// RSS reading: RSS at boot is near-zero and meaningless as a steady-state predictor, so the guard
/// asserts only what is PROVABLE, that the configured caps either can or cannot sum under the
/// ceiling. A `ram_ceiling_bytes` of `0` (the default) disables the guard
/// ([`RamCeilingVerdict::Disabled`]); a set ceiling yields [`RamCeilingVerdict::Fits`] when the
/// worst case is at or under it and [`RamCeilingVerdict::Exceeds`] (the refuse-to-boot case) when it
/// is provably over.
#[must_use]
pub fn fits_under_ram_ceiling(config: &RamFootprintConfig) -> RamCeilingVerdict {
    if config.ram_ceiling_bytes == 0 {
        return RamCeilingVerdict::Disabled;
    }
    let worst_case_bytes = worst_case_buffer_bytes(config);
    let ceiling_bytes = config.ram_ceiling_bytes;
    if worst_case_bytes <= ceiling_bytes {
        RamCeilingVerdict::Fits {
            worst_case_bytes,
            ceiling_bytes,
        }
    } else {
        RamCeilingVerdict::Exceeds {
            worst_case_bytes,
            ceiling_bytes,
            overage_bytes: worst_case_bytes - ceiling_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The edge-tiny preset (`docs/EDGE_CONSTRAINTS.md` / `docs/RAM_BUDGET.md`): 32 connections,
    /// 8 / 256 KiB consumer credits, 64 groups, 256 in-flight, under a 64 MiB ceiling.
    fn edge_tiny_footprint() -> RamFootprintConfig {
        RamFootprintConfig {
            ram_ceiling_bytes: 64 * 1024 * 1024,
            max_connections: 32,
            consumer_credit: 8,
            consumer_credit_bytes: 256 * 1024,
            max_groups: 64,
            max_in_flight: 256,
            // The edge-tiny preset is the DISK backend: the store is file-backed, not charged.
            in_memory_store_bytes: 0,
        }
    }

    #[test]
    fn no_ceiling_disables_the_guard() {
        let mut cfg = edge_tiny_footprint();
        cfg.ram_ceiling_bytes = 0;
        assert_eq!(fits_under_ram_ceiling(&cfg), RamCeilingVerdict::Disabled);
    }

    #[test]
    fn edge_tiny_fits_under_its_64_mib_ceiling() {
        let cfg = edge_tiny_footprint();
        // The bounded-buffer worst case is term1 (in-flight payloads) + term2 (read buffers) + term3
        // (group state) + term5 (fixed + thread stacks). The byte budget binds term 1, max_connections
        // is small (32), so the whole worst case is well under 64 MiB.
        let worst = worst_case_buffer_bytes(&cfg);
        assert!(
            worst <= cfg.ram_ceiling_bytes,
            "edge-tiny worst case {worst} must fit under the 64 MiB ceiling"
        );
        match fits_under_ram_ceiling(&cfg) {
            RamCeilingVerdict::Fits {
                worst_case_bytes,
                ceiling_bytes,
            } => {
                assert_eq!(worst_case_bytes, worst);
                assert_eq!(ceiling_bytes, cfg.ram_ceiling_bytes);
            }
            other => panic!("edge-tiny must fit, got {other:?}"),
        }
    }

    #[test]
    fn a_blown_up_max_connections_override_is_refused() {
        // edge-tiny credits but a server-sized connection cap: 4096 * 256 KiB of in-flight bytes alone
        // is 1 GiB, far over the 64 MiB ceiling, so the guard refuses and names the overage.
        let mut cfg = edge_tiny_footprint();
        cfg.max_connections = 4096;
        match fits_under_ram_ceiling(&cfg) {
            RamCeilingVerdict::Exceeds {
                worst_case_bytes,
                ceiling_bytes,
                overage_bytes,
            } => {
                assert!(worst_case_bytes > ceiling_bytes);
                assert_eq!(overage_bytes, worst_case_bytes - ceiling_bytes);
                assert!(
                    worst_case_bytes > 64 * 1024 * 1024,
                    "4096 connections blow the 64 MiB ceiling, got {worst_case_bytes}"
                );
            }
            other => panic!("a 4096-connection edge-tiny override must be refused, got {other:?}"),
        }
    }

    #[test]
    fn an_unlimited_byte_budget_with_default_credit_is_refused_under_a_tiny_ceiling() {
        // consumer_credit_bytes = 0 (OFF) means the only term-1 bound is the message COUNT, so 64
        // credits * a ~16 MiB maximal frame each is ~1 GiB per connection: under a 64 MiB ceiling
        // this cannot be PROVEN to fit and is refused. This is the honest, conservative reading: a
        // config with no byte budget cannot promise to stay under a small ceiling.
        let cfg = RamFootprintConfig {
            ram_ceiling_bytes: 64 * 1024 * 1024,
            max_connections: 32,
            consumer_credit: 64,
            consumer_credit_bytes: 0,
            max_groups: 64,
            max_in_flight: 256,
            in_memory_store_bytes: 0,
        };
        assert!(matches!(
            fits_under_ram_ceiling(&cfg),
            RamCeilingVerdict::Exceeds { .. }
        ));
    }

    #[test]
    fn the_in_memory_store_is_charged_at_two_byte_images() {
        // THE #445 MEMORY-BACKEND FOLD: with the store in RAM, the worst case grows by EXACTLY
        // twice the store cap over the same config with a disk store. The expectation is a HARD
        // LITERAL 2, deliberately NOT `IN_MEMORY_STORE_IMAGES`: an expectation computed from the
        // constant is self-referential and would silently follow a drifted constant (a mutant
        // setting it to 1 passed the whole suite that way once). The 2 is derived from the
        // in-memory filesystem itself: `InMemoryFile` retains exactly TWO byte images per file,
        // `State.live` plus `State.durable` (the image `sync_data`'s `clone_from` refreshes),
        // and the directory-level `sync_dir` clone copies only a map of `Arc` POINTERS, never a
        // third byte image. That retained set is the steady state; `clone_from`'s realloc
        // transient can briefly exceed it mid-sync (see `IN_MEMORY_STORE_IMAGES`). This test
        // FAILS if the store term is dropped, the clone headroom is forgotten, or the constant
        // drifts off 2 in either direction.
        let disk = edge_tiny_footprint();
        let mem = RamFootprintConfig {
            in_memory_store_bytes: 8 * 1024 * 1024,
            ..disk
        };
        assert_eq!(
            worst_case_buffer_bytes(&mem),
            worst_case_buffer_bytes(&disk) + 2 * 8 * 1024 * 1024,
            "the in-memory store must be charged at live + durable-clone (exactly 2 images)"
        );
    }

    #[test]
    fn a_memory_store_past_the_ceiling_is_refused_where_the_disk_config_fits() {
        // The issue-#445 headline: edge-tiny knobs FIT under 64 MiB on disk, but the SAME knobs
        // with a 1 GiB in-RAM store provably cannot (2 GiB of store images alone), so the verdict
        // flips from Fits to Exceeds purely on the store fold.
        let disk = edge_tiny_footprint();
        assert!(matches!(
            fits_under_ram_ceiling(&disk),
            RamCeilingVerdict::Fits { .. }
        ));
        let mem = RamFootprintConfig {
            in_memory_store_bytes: 1024 * 1024 * 1024,
            ..disk
        };
        match fits_under_ram_ceiling(&mem) {
            RamCeilingVerdict::Exceeds {
                worst_case_bytes, ..
            } => assert!(
                // A hard literal 2, not the constant, so a drifted multiplier cannot satisfy a
                // bound computed from itself.
                worst_case_bytes >= 2 * 1024 * 1024 * 1024,
                "the store images dominate the worst case, got {worst_case_bytes}"
            ),
            other => {
                panic!("a 1 GiB in-RAM store under a 64 MiB ceiling must be refused, got {other:?}")
            }
        }
    }

    #[test]
    fn an_absurd_in_memory_store_saturates_rather_than_overflows() {
        // Belt and braces: a u64::MAX byte cap times the image multiplier saturates (the config is
        // then refused under any real ceiling), never wraps around to a small, spuriously-fitting
        // worst case.
        let cfg = RamFootprintConfig {
            in_memory_store_bytes: u64::MAX,
            ..edge_tiny_footprint()
        };
        assert_eq!(worst_case_buffer_bytes(&cfg), u64::MAX);
    }

    #[test]
    fn the_worst_case_is_monotonic_in_the_caps() {
        // Widening any single cap can only grow (never shrink) the provable worst case, so the guard
        // never spuriously LOOSENS as a config is made more demanding.
        let base = edge_tiny_footprint();
        let baseline = worst_case_buffer_bytes(&base);
        for wider in [
            RamFootprintConfig {
                max_connections: base.max_connections + 1,
                ..base
            },
            RamFootprintConfig {
                consumer_credit_bytes: base.consumer_credit_bytes + 1,
                ..base
            },
            RamFootprintConfig {
                max_groups: base.max_groups + 1,
                ..base
            },
            RamFootprintConfig {
                max_in_flight: base.max_in_flight + 1,
                ..base
            },
            RamFootprintConfig {
                in_memory_store_bytes: base.in_memory_store_bytes + 1,
                ..base
            },
        ] {
            assert!(
                worst_case_buffer_bytes(&wider) >= baseline,
                "widening a cap must not shrink the worst case"
            );
        }
    }

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
