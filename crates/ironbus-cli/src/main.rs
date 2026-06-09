// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ironbus`, the command-line interface: run a broker and talk to one.
//!
//! The single binary is both the broker and the client tooling (per #136). This initial
//! slice implements three of the frozen command map's verbs:
//! - `serve` starts an on-disk broker (Unix only in v1: storage uses positioned IO that the
//!   Windows path does not yet implement).
//! - `pub` connects to a broker, appends one message, and prints its durable offset.
//! - `sub` fetches up to a credit of messages, prints each, and optionally acks them.
//!
//! `pub` and `sub` are thin wrappers over `ironbus-client`, so they run anywhere. Argument
//! parsing is hand-rolled (no external dependency) for this small surface; the broader
//! command tree and the versioned `--json` contract from #91 are follow-ups. Every failure
//! is a typed [`CliError`] mapped to the frozen exit-code scheme: 0 clean, 1 usage,
//! 5 broker-unreachable, 70 internal (the not-found and corruption codes belong to the
//! offline verbs not yet implemented).

/// The `serve` data-directory lifecycle and the single-broker lock (#89). Unix-only, like `serve`
/// itself; the non-Unix `cmd_serve` stub errors out before any of it runs, so the module is gated.
#[cfg(unix)]
mod dirlock;

/// The `bench` load generator's platform-neutral surface (#94): arg parsing, the production-safety
/// and flash-endurance guards, the versioned `--json` schema, payload generation, and percentiles.
/// Cross-platform (and unit-tested on every target) so the guards are exercised everywhere.
mod bench;

/// The `bench` Unix execution path (#94): spin up an isolated in-process broker (or connect to a
/// live one), drive the real #11 client over the real #6 produce path, measure the latency tail and
/// the honest round-trip fsync cost, then auto-delete the synthetic data dir. Unix-only, like
/// `serve` (the on-disk broker is Unix-only in v1); the non-Unix `run_bench` stub errors out.
#[cfg(unix)]
mod bench_run;

/// Atomic in-place upgrade + rollback for the `ironbus` binary (#104). Unix-only (the atomic
/// `rename(2)` swap and the directory fsync are POSIX guarantees); the non-Unix `cmd_upgrade`,
/// `cmd_rollback`, and `cmd_record_start` stubs error out before any of it runs, so the module is
/// gated. The module itself is `#![cfg(unix)]`-gated internally.
#[cfg(unix)]
mod upgrade;

/// The read-only `/admin` introspection client (#15, #99): fetch the broker's `/admin` v1 JSON over
/// HTTP and render the segments / consumers+lag / last-skip-offset views FROM THAT JSON ALONE. Plain
/// HTTP over a TcpStream, so it is cross-platform (no Unix gate); it consumes a remote broker's
/// health server, it does not open the on-disk store.
mod admin;

/// The strictly READ-ONLY `top` status view (#93): a LIVE mode that polls the broker's `/admin` v1
/// JSON (reusing the `admin` client) and an OFFLINE mode that renders only the file-derived panels
/// from the on-disk store (with a mandatory offline banner). Hand-rolled rendering that degrades to
/// plain text off a TTY / under `NO_COLOR` / with `--once` and sleeps between polls (no busy-spin),
/// pulling no new dependency. The live half is cross-platform (an HTTP client); the offline half is
/// Unix-only in v1, like the on-disk store, via a cfg-gated snapshot builder.
mod top;

/// The TOML config-FILE layer (#85, #86, #382): the file IO half of the configuration system
/// (whole-read, parse with the pure-Rust `toml` crate, flatten, strict-validate the key set, and
/// expose the known keys as the FILE override layer the resolver slots between env and default).
/// Cross-platform: the file is read and validated on every target (the same usage/config exit
/// applies everywhere `serve` parses flags); only the on-disk broker run is Unix-only. The PURE
/// grammar and the coupled-set validator live in `ironbus_core::config`; this module is the IO.
mod config_file;

/// The immutable effective-config + atomic RELOAD engine (#380, #382, the no-auth part): the
/// `Arc<EffectiveConfig>` behind a single safe swap point, read via one refcount bump on the path
/// that needs it, and the re-read RELOAD that validates the whole candidate, rejects a cold-key
/// change atomically, and swaps ONLY on full success (a broken reload keeps the old config). The
/// MUTATING wire `CONFIG SET` verbs need the #106 auth and are NOT here (no unauthenticated remote
/// mutation surface); this is the safe SIGHUP/re-read reload path only.
mod config_reload;

use ironbus_client::{Client, ClientError};
use ironbus_core::clock::Clock;
use ironbus_proto::message::PubBody;
use ironbus_server::clock::SystemClock;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

// The offline mutating-admin reset target (#299). The enum is platform-independent (a plain choice
// of offset/earliest/latest), so it is imported unconditionally: the cross-platform flag parser,
// the unit tests, the Unix `cmd_admin_consumer_reset`, and its non-Unix stub all name it. The
// actual data-dir mutation (`reset_consumer`/`redrive_dlq`, which open the on-disk store) is
// Unix-only, alongside the rest of the storage path.
use ironbus_storage::admin::ResetTarget;

#[cfg(unix)]
use ironbus_core::delivery::DeliveryConfig;
#[cfg(unix)]
use ironbus_core::lease::LeaseConfig;
#[cfg(unix)]
use ironbus_server::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
#[cfg(unix)]
use ironbus_server::engine::{DiskFullPolicy, DurabilityLevel, Engine, EngineConfig};
#[cfg(unix)]
use ironbus_server::health::serve_health;
#[cfg(unix)]
use ironbus_server::server::serve;
#[cfg(unix)]
use ironbus_storage::dlq::{read_dlq_entries, DlqEntry};
#[cfg(unix)]
use ironbus_storage::fs::StdFs;
#[cfg(unix)]
use ironbus_storage::log::LogConfig;
#[cfg(unix)]
use ironbus_storage::loss::LossReport;
#[cfg(unix)]
use ironbus_storage::offline::OfflineReader;
#[cfg(unix)]
use ironbus_storage::segment::{OwnedRecord, StorageError};
#[cfg(unix)]
use std::net::TcpListener;
// The secure-bind guard (#95) resolves and classifies `--health-addr`; it runs on the Unix serve path
// and in the platform-independent unit tests, so its imports follow the same gate as the helpers.
#[cfg(any(unix, test))]
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::Arc;

/// The default broker address: loopback only, so a zero-config broker is never exposed off
/// the host without an explicit choice.
const DEFAULT_ADDR: &str = "127.0.0.1:7777";
/// The default fetch credit for `sub`.
const DEFAULT_FETCH: u32 = 10;
/// The default connection cap for `serve`.
const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// The default RAM ceiling for `serve` (#115, #19): `0` = UNSET (the refuse-to-boot RAM guard is OFF
/// and `ironbus_ram_headroom_bytes` reports the `-1` sentinel). The `balanced` and `throughput`
/// profiles inherit this `0`; only `edge-tiny` opts into a real ceiling ([`EDGE_TINY_RAM_CEILING`]).
const DEFAULT_RAM_CEILING_BYTES: u64 = 0;
/// The `edge-tiny` profile RAM ceiling (#115, #19, #115-residual): the 64 MiB resident budget
/// `docs/RAM_BUDGET.md` and `docs/EDGE_CONSTRAINTS.md` size the tiny edge node against. With the
/// edge-tiny knobs the worst-case bounded-buffer footprint is well under this (~15 MiB), so
/// `--profile edge-tiny` boots; a blown-up `--max-connections` (or another over-cap) override pushes
/// the provable worst case over 64 MiB and the refuse-to-boot guard rejects it.
const EDGE_TINY_RAM_CEILING: u64 = 64 * 1024 * 1024;
/// The default in-flight window for the `serve` engine.
/// The default max-ack-pending window for `serve`.
const DEFAULT_MAX_IN_FLIGHT: u32 = 1024;

/// The default per-CONSUMER (per-connection) in-flight credit for `serve` (#65), aliased to the
/// engine's [`ironbus_server::engine::DEFAULT_CONSUMER_CREDIT`] so the CLI default and the engine
/// default are a single source of truth and cannot drift. It is the most un-acked messages one
/// connection may hold at once, the consumer-side half of credit-based flow control; the effective
/// Flow bound is min(this, the per-group `--max-in-flight` window). Floored to 1 by the engine.
const DEFAULT_CONSUMER_CREDIT: u32 = ironbus_server::engine::DEFAULT_CONSUMER_CREDIT;

/// The default per-CONSUMER (per-connection) in-flight BYTE budget for `serve` (#275), aliased to
/// the engine's [`ironbus_server::engine::DEFAULT_CONSUMER_CREDIT_BYTES`] so the CLI default and the
/// engine default are a single source of truth and cannot drift. It is the most un-acked payload
/// bytes one connection may hold at once, the RAM-side companion to the message-count credit; the
/// effective Flow bound is min(message credit, byte budget) with a hard floor of one message. `0`
/// means unlimited (the byte budget is off, only the message credit binds).
const DEFAULT_CONSUMER_CREDIT_BYTES: u64 = ironbus_server::engine::DEFAULT_CONSUMER_CREDIT_BYTES;

/// The default segment size cap for `serve` (64 MiB, matching the storage default).
const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// The default durable-log total byte cap for `serve` (0 = unlimited, matching the storage
/// default): the spill-by-default behavior is unchanged until an operator opts in to the shed.
const DEFAULT_MAX_TOTAL_BYTES: u64 = 0;

/// The default consumer-safe size-retention bound for `serve` (0 = unlimited, retention OFF,
/// matching the engine default): the broker never reaps old sealed segments until an operator
/// opts in, so existing behavior is unchanged.
const DEFAULT_MAX_RETAINED_BYTES: u64 = 0;

/// The default consumer-safe AGE-retention bound for `serve`, in MILLISECONDS (0 = disabled,
/// matching the engine default): the broker never reaps a segment for age until an operator opts
/// in. Milliseconds (not a duration string) so the flag takes a bare integer.
const DEFAULT_MAX_AGE_MS: u64 = 0;

/// The default consumer-safe COUNT-retention bound for `serve`, in messages (0 = disabled,
/// matching the engine default): the broker never reaps a segment for count until an operator
/// opts in.
const DEFAULT_MAX_MESSAGES: u64 = 0;

/// The default cap on the number of live work-groups for `serve` (refs #240, #9, #10), aliased to
/// the engine's [`ironbus_server::engine::DEFAULT_MAX_GROUPS`] so the CLI default and the engine
/// default are a single source of truth and cannot drift. It bounds total consumer-state memory
/// once the wire can name groups, so an unauthenticated client cannot exhaust memory by naming
/// endless groups. `0` = unlimited (the cap is off); the default is non-zero (1024).
const DEFAULT_MAX_GROUPS: usize = ironbus_server::engine::DEFAULT_MAX_GROUPS;

/// The default idle window after which an idle, fully-caught-up, lease-free NAMED work-group is
/// evicted for `serve` (refs #277, #240), in MILLISECONDS, aliased to the engine's
/// [`ironbus_server::engine::DEFAULT_GROUP_IDLE_EVICT_MS`] so the CLI and engine default are a single
/// source of truth. `0` = DISABLED (never evict), the default: an operator opts in to reclaiming
/// idle named groups. Eviction never deletes a durable checkpoint, so a re-subscribe still resumes.
const DEFAULT_GROUP_IDLE_EVICT_MS: u64 = ironbus_server::engine::DEFAULT_GROUP_IDLE_EVICT_MS;

/// The default disk-full overflow policy for `serve` (`drop-new`, matching the engine default):
/// an over-cap produce is shed, the older accepted data preserved, so existing behavior is
/// unchanged. `drop-oldest` opts in to force-reaping the oldest sealed segment to make room.
const DEFAULT_DISK_FULL_POLICY: &str = "drop-new";

/// The default durability LEVEL for `serve` (`sync`, matching the engine default, #341, #379): an ack
/// is emitted only after the covering `fdatasync`, so I2 holds and an acknowledged record is never
/// lost on a power cut (ZERO acked loss). A zero-config broker stays power-loss safe; the relaxed
/// levels (`interval`/`async`/`none`) are strictly opt-in and weaken I2 by a documented loss window.
const DEFAULT_DURABILITY_LEVEL: &str = "sync";

/// The default compression codec for `serve` (#12, #387): `lz4`, the pure-Rust default codec per
/// [ADR-0003](../../../docs/adr/0003-default-compression-lz4-zstd-opt-in.md). The codec runtime,
/// its raw-store / never-expand guards, and its decoder resilience live in
/// `ironbus_core::compress`; an operator selects `none` to store every record raw (the historical
/// byte layout) or `lz4` to compress compressible records. The opt-in `zstd` codec (behind a
/// feature, with its level knob and trained dictionaries) is deferred per ADR-0003 and is not a
/// valid value on the default build.
const DEFAULT_COMPRESSION: &str = "lz4";

/// The default `--flush-interval-ms` for the `interval` durability level (#341), in MILLISECONDS: the
/// most time an acked-but-unsynced record may sit before the background flush forces an `fdatasync`,
/// so the worst-case loss window is bounded. Only consulted under `--durability-level interval`. 1000
/// ms (one second) is a conservative default window; an operator tunes it down for less exposure or up
/// for fewer syncs. The byte trigger ([`DEFAULT_FLUSH_MAX_BYTES`]) bounds it independently.
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1_000;

/// The default `--flush-max-bytes` for the `interval` durability level (#341): the most UNSYNCED
/// record bytes that may accumulate before the background flush forces an `fdatasync`. Only consulted
/// under `--durability-level interval`. 1 MiB caps the bytes-at-risk independently of the time window,
/// so a burst that fills the budget before the timer fires still bounds the loss. The EFFECTIVE bound
/// is the smaller of the time and byte triggers.
const DEFAULT_FLUSH_MAX_BYTES: u64 = 1024 * 1024;

/// The default CoDel TARGET (ms) for `serve` (#68), aliased to the engine's default so the CLI and
/// engine stay one source of truth. `0` = DISABLED (CoDel off, the default), so a zero-config broker
/// is unchanged; an operator opts in by setting a non-zero target.
const DEFAULT_CODEL_TARGET_MS: u64 = ironbus_server::engine::DEFAULT_CODEL_TARGET_MS;
/// The default CoDel INTERVAL (ms) for `serve` (#68), aliased to the engine default. Only consulted
/// when the target is non-zero.
const DEFAULT_CODEL_INTERVAL_MS: u64 = ironbus_server::engine::DEFAULT_CODEL_INTERVAL_MS;
/// The default per-client retry-budget ratio (parts per million) for `serve` (#69), aliased to the
/// engine default. `0` = DISABLED (the default).
const DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION: u64 =
    ironbus_server::engine::DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION;
/// The default per-client retry-budget window (ms) for `serve` (#69), aliased to the engine default.
const DEFAULT_RETRY_BUDGET_WINDOW_MS: u64 = ironbus_server::engine::DEFAULT_RETRY_BUDGET_WINDOW_MS;
/// The default fire-and-forget token-bucket message rate (msg/s) for `serve` (#69), aliased to the
/// engine default. `0` = DISABLED (the un-credited tier is ungoverned, as today).
const DEFAULT_FIRE_AND_FORGET_MSG_RATE: u64 =
    ironbus_server::engine::DEFAULT_FIRE_AND_FORGET_MSG_RATE;
/// The default fire-and-forget token-bucket byte rate (bytes/s) for `serve` (#69), aliased to the
/// engine default. `0` = disabled.
const DEFAULT_FIRE_AND_FORGET_BYTE_RATE: u64 =
    ironbus_server::engine::DEFAULT_FIRE_AND_FORGET_BYTE_RATE;
/// The default fire-and-forget token-bucket refill granularity (ms) for `serve` (#69), aliased to the
/// engine default (100 ms).
const DEFAULT_FIRE_AND_FORGET_REFILL_MS: u64 =
    ironbus_server::engine::DEFAULT_FIRE_AND_FORGET_REFILL_MS;
/// The default starting / static-floor egress concurrency limit for `serve` (#69), aliased to the
/// engine default (16); the AIMD bounds `[4, 128]` always apply.
const DEFAULT_EGRESS_LIMIT: u32 = ironbus_server::engine::DEFAULT_EGRESS_LIMIT;

/// The default fsync-headroom admission window in BYTES for `serve` (#378), aliased to the core
/// default (`0` = OFF). A zero-config broker is unchanged; a non-zero value is the opt-in tight RAM /
/// loss-window bound on the un-fsynced write frontier.
const DEFAULT_WAL_FSYNC_HEADROOM_BYTES: u64 =
    ironbus_core::backpressure::DEFAULT_WAL_FSYNC_HEADROOM_BYTES;

/// The default COUNT bound on each per-producer dedup window for `serve` (#3, #33), aliased to the
/// engine's [`ironbus_core::dedup::DEFAULT_MAX_IDS`] so the CLI and engine default are one source of
/// truth. Dedup is OFF by default and activates per-producer only when a publish carries a `msg_id`;
/// this only SIZES the window when it does (the most `(msg_id, offset)` entries one producer keeps).
const DEFAULT_DEDUP_MAX_IDS: usize = ironbus_core::dedup::DEFAULT_MAX_IDS;

/// The default TIME bound on each per-producer dedup window for `serve` (#3, #33), in MILLISECONDS:
/// the engine's [`ironbus_core::dedup::DEFAULT_WINDOW_NANOS`] (2 minutes) converted to ms, so the CLI
/// and engine default stay one source of truth. `0` disables the time bound (only the count bound
/// applies). Monotonic time, so an NTP step never mis-expires the window.
const DEFAULT_DEDUP_WINDOW_MS: u64 = ironbus_core::dedup::DEFAULT_WINDOW_NANOS / 1_000_000;

/// The default cap on the NUMBER of distinct per-producer dedup windows for `serve` (#33), aliased to
/// the engine's [`ironbus_core::dedup::DEFAULT_MAX_PRODUCERS`] so the CLI and engine default stay one
/// source of truth. The `producer_id` is wire-supplied, so this caps the TOTAL dedup memory: a fresh
/// `producer_id` over the cap evicts the least-recently-active window. Floored to 1 by the engine.
const DEFAULT_DEDUP_MAX_PRODUCERS: usize = ironbus_core::dedup::DEFAULT_MAX_PRODUCERS;

/// The disk-full overflow policy parsed from `serve --disk-full-policy` (#82). A platform-neutral,
/// `Copy` mirror of the engine's policy enum, so it lives in the (non-Unix-gated) `ServeConfig` and
/// is validated on every platform; the Unix on-disk path maps it to the engine's `DiskFullPolicy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiskFullPolicyArg {
    /// Shed an over-cap produce (the drop-new default).
    DropNew,
    /// Force-reap the oldest sealed segment to make room, then accept the over-cap produce.
    DropOldest,
}

impl DiskFullPolicyArg {
    /// Parses the `--disk-full-policy` flag value, accepting `drop-new` or `drop-oldest`.
    fn parse(value: &str) -> Option<DiskFullPolicyArg> {
        match value {
            "drop-new" => Some(DiskFullPolicyArg::DropNew),
            "drop-oldest" => Some(DiskFullPolicyArg::DropOldest),
            _ => None,
        }
    }

    /// The flag/log spelling of this policy, the inverse of [`DiskFullPolicyArg::parse`]. `DropNew`
    /// returns the [`DEFAULT_DISK_FULL_POLICY`] string so the default constant stays the single
    /// source of truth for that name; used to supply a profile's policy as a resolvable default and
    /// to render it in the materialized-config log.
    fn as_str(self) -> &'static str {
        match self {
            DiskFullPolicyArg::DropNew => DEFAULT_DISK_FULL_POLICY,
            DiskFullPolicyArg::DropOldest => "drop-oldest",
        }
    }
}

/// The durability LEVEL parsed from `serve --durability-level` (#341, #379). A platform-neutral,
/// `Copy` mirror of the engine's [`ironbus_server::engine::DurabilityLevel`], so it lives in the
/// (non-Unix-gated) [`ServeConfig`] and is parsed/validated on EVERY platform; the Unix on-disk path
/// maps it to the engine enum. The default is [`DurabilityLevelArg::Sync`], the only power-loss-safe
/// level (ack-implies-durable, I2, zero acked loss): an operator who passes no `--durability-level`
/// keeps the historical durable broker. The relaxed levels are strictly opt-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurabilityLevelArg {
    /// The DEFAULT, power-loss-safe level: ack only after the covering `fdatasync` (I2).
    Sync,
    /// OPT-IN, bounded-loss: ack on page-cache write, forced `fdatasync` on the flush window.
    Interval,
    /// OPT-IN, unbounded-until-next-sync loss: ack on page-cache write, opportunistic fsync only.
    /// Gated behind `--async-loss-ack`.
    Async,
    /// OPT-IN, the largest loss window: like `async` with no periodic fsync. Gated behind
    /// `--async-loss-ack`.
    None,
}

impl DurabilityLevelArg {
    /// Parses the `--durability-level` flag value, accepting `sync`, `interval`, `async`, or `none`.
    fn parse(value: &str) -> Option<DurabilityLevelArg> {
        match value {
            "sync" => Some(DurabilityLevelArg::Sync),
            "interval" => Some(DurabilityLevelArg::Interval),
            "async" => Some(DurabilityLevelArg::Async),
            "none" => Some(DurabilityLevelArg::None),
            _ => None,
        }
    }

    /// The flag/log spelling of this level, the inverse of [`DurabilityLevelArg::parse`]. `Sync`
    /// returns the [`DEFAULT_DURABILITY_LEVEL`] string so the default constant stays the single
    /// source of truth for that name; used as a resolvable default and in the materialized-config log.
    fn as_str(self) -> &'static str {
        match self {
            DurabilityLevelArg::Sync => DEFAULT_DURABILITY_LEVEL,
            DurabilityLevelArg::Interval => "interval",
            DurabilityLevelArg::Async => "async",
            DurabilityLevelArg::None => "none",
        }
    }

    /// Whether this level WAIVES I2 (ack no longer implies durable): true for every relaxed level,
    /// false for `sync`. Drives the loud startup warning and the materialized-config power-loss-safe
    /// flag.
    fn waives_i2(self) -> bool {
        !matches!(self, DurabilityLevelArg::Sync)
    }

    /// Whether selecting this level REQUIRES the explicit `--async-loss-ack` data-loss acknowledgement
    /// to boot (the none/async safety gate, #49/#379): the UNBOUNDED-loss levels `async` and `none`.
    /// `sync` needs no ack; `interval`'s loss is bounded by the operator-chosen window, so it is opt-in
    /// but not gated behind the data-loss flag.
    fn requires_loss_ack(self) -> bool {
        matches!(self, DurabilityLevelArg::Async | DurabilityLevelArg::None)
    }
}

/// The compression CODEC parsed from `serve --compression` (#12, #387). A platform-neutral, `Copy`
/// mirror of [`ironbus_core::compress::Codec`], so it lives in the (non-Unix-gated) [`ServeConfig`]
/// and is parsed/validated on EVERY platform; the Unix on-disk write path maps it to the codec
/// runtime's config. The default is [`CompressionArg::Lz4`] (the ADR-0003 pure-Rust default codec);
/// `none` stores every record raw (the historical byte layout, byte-for-byte). The opt-in `zstd`
/// codec is deferred per ADR-0003 and is not accepted on the default build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompressionArg {
    /// No compression: every record is stored raw, byte-for-byte the historical layout.
    None,
    /// LZ4 block compression via the pure-Rust `lz4_flex` codec (the ADR-0003 default).
    Lz4,
}

impl CompressionArg {
    /// Parses the `--compression` flag value, accepting `none` or `lz4`. `zstd` is intentionally
    /// REJECTED on the default build (it is the opt-in feature, deferred per ADR-0003), so an
    /// operator who asks for it gets a clear usage error rather than a silent fallback.
    fn parse(value: &str) -> Option<CompressionArg> {
        match value {
            "none" => Some(CompressionArg::None),
            "lz4" => Some(CompressionArg::Lz4),
            _ => None,
        }
    }

    /// The flag/log spelling of this codec, the inverse of [`CompressionArg::parse`]. `Lz4` returns
    /// the [`DEFAULT_COMPRESSION`] string so the default constant stays the single source of truth
    /// for that name; used to render it in the materialized-config log.
    fn as_str(self) -> &'static str {
        match self {
            CompressionArg::None => "none",
            CompressionArg::Lz4 => DEFAULT_COMPRESSION,
        }
    }
}

/// The schema version of the compiled-in named profiles (#87). It is BUMPED whenever any
/// profile's knob VALUES change, so that a profile content change is a visible, versioned event
/// rather than a silent fleet-wide behavior drift across an upgrade. It is recorded in the
/// materialized-config startup log next to the active profile, so an operator can read exactly
/// which profile schema a running broker was compiled against. A bump is a documented
/// breaking-change CHANGELOG entry (the `balanced` row is also the shipped default set, so a
/// change to it is a default change too). Starts at 1: the values frozen in `docs/CONFIG.md`
/// section 6.
const PROFILE_SCHEMA_VERSION: u32 = 1;

/// A compiled-in named tuning profile (#87): a coherent group of knob values applied FIRST, then
/// overridden by any explicit env var or flag (so the effective precedence is profile < env <
/// flag, [`docs/CONFIG.md`](../../../docs/CONFIG.md) section 2). Profiles are baked into the static
/// binary so an offline edge device selects one with no external fetch, and are VERSIONED by
/// [`PROFILE_SCHEMA_VERSION`] so a content change is never silent.
///
/// A profile NEVER sets `data_dir` or any network/TLS key (those are environment-specific): it sets
/// only the storage / backpressure / delivery tuning knobs in [`ProfilePreset`]. `balanced` is the
/// DEFAULT and is exactly the compiled-in `DEFAULT_*` constant set, so `serve` with no `--profile`
/// (and no env/flag override) behaves byte-identically to a broker that predates this flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    /// Small RAM ceiling and flash gentleness for an unattended, battery-less ARM box (the
    /// `EDGE_SEGMENT_BYTES` 8 MiB segment, tight per-connection credits, few connections/groups,
    /// `drop-new`). Cross-referenced byte-for-byte against the `tiny` table in
    /// `docs/EDGE_CONSTRAINTS.md`; its steady-state RAM sums well under the 64 MiB edge ceiling.
    EdgeTiny,
    /// THE default: exactly the shipped compiled-in `DEFAULT_*` constants, so a zero-config broker
    /// starts on `balanced`. NOT edge-safe (256 conns * 8 MiB is ~2 GiB worst case), which is
    /// precisely why `edge-tiny` exists.
    Balanced,
    /// Wide buffers for a multi-core hub: large 256 MiB segments, wide credits and in-flight window,
    /// more connections/groups, a deeper checkpoint interval, and `drop-oldest` so a burst prefers
    /// spill-then-reclaim over rejecting the producer.
    Throughput,
}

impl Profile {
    /// The DEFAULT profile when no `--profile` (and no `IRONBUS_PROFILE`) is given: `balanced`, the
    /// shipped compiled-in default set, so existing zero-config behavior is unchanged.
    const DEFAULT: Profile = Profile::Balanced;

    /// Parses the `--profile` / `IRONBUS_PROFILE` value into a [`Profile`]. An unknown name returns
    /// `None`; the caller turns that into a usage error (exit 1) naming the accepted values.
    fn parse(value: &str) -> Option<Profile> {
        match value {
            "edge-tiny" => Some(Profile::EdgeTiny),
            "balanced" => Some(Profile::Balanced),
            "throughput" => Some(Profile::Throughput),
            _ => None,
        }
    }

    /// The stable wire/log name of this profile, the inverse of [`Profile::parse`], used in the
    /// materialized-config log so an operator reads back exactly the selectable name.
    fn name(self) -> &'static str {
        match self {
            Profile::EdgeTiny => "edge-tiny",
            Profile::Balanced => "balanced",
            Profile::Throughput => "throughput",
        }
    }

    /// The compiled-in preset (the coherent knob values) for this profile. The values are the
    /// `docs/CONFIG.md` section 6 table, cross-checked against `docs/EDGE_CONSTRAINTS.md` for
    /// `edge-tiny`; a test asserts each field, so a drift between this code and the doc fails CI.
    fn preset(self) -> ProfilePreset {
        match self {
            Profile::EdgeTiny => EDGE_TINY_PRESET,
            Profile::Balanced => BALANCED_PRESET,
            Profile::Throughput => THROUGHPUT_PRESET,
        }
    }
}

/// The coherent group of tuning-knob values a named [`Profile`] sets (#87). Each field is the
/// per-knob DEFAULT that profile contributes; an explicit env var or flag for the same knob still
/// overrides it (profile < env < flag), because the resolver passes the preset value where it would
/// otherwise pass the compiled `DEFAULT_*` constant. A preset NEVER carries `data_dir` or any
/// network/TLS material: those are environment-specific and stay outside the profile surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProfilePreset {
    /// `storage.segment_size` (`--max-segment-bytes`).
    max_segment_bytes: u64,
    /// `backpressure.consumer_credit` (`--consumer-credit`).
    consumer_credit: u32,
    /// `backpressure.consumer_credit_bytes` (`--consumer-credit-bytes`).
    consumer_credit_bytes: u64,
    /// `backpressure.max_connections` (`--max-connections`).
    max_connections: usize,
    /// `backpressure.max_groups` (`--max-groups`).
    max_groups: usize,
    /// `backpressure.max_in_flight` (`--max-in-flight`).
    max_in_flight: u32,
    /// `backpressure.disk_full_policy` (`--disk-full-policy`).
    disk_full_policy: DiskFullPolicyArg,
    /// `delivery.checkpoint_interval` (`--checkpoint-interval`).
    checkpoint_interval: u64,
    /// `delivery.visibility_timeout_ms` (`--visibility-timeout-ms`).
    visibility_ms: u64,
    /// `delivery.max_deliver` (`--max-deliver`).
    max_deliver: u32,
    /// `resources.ram_ceiling_bytes` (`--ram-ceiling-bytes`): the refuse-to-boot RAM ceiling (#115).
    /// `0` = UNSET (the guard is off) for `balanced`/`throughput`; `edge-tiny` sets the 64 MiB ceiling.
    ram_ceiling_bytes: u64,
}

/// The `edge-tiny` preset: `docs/CONFIG.md` section 6, identical to the `tiny` table in
/// `docs/EDGE_CONSTRAINTS.md`. 8 MiB segments, 8 / 256 KiB consumer credits, 32 connections, 64
/// groups, 256 in-flight, `drop-new`, 1024 checkpoint, 30 s visibility, 5 max-deliver.
const EDGE_TINY_PRESET: ProfilePreset = ProfilePreset {
    max_segment_bytes: 8 * 1024 * 1024,
    consumer_credit: 8,
    consumer_credit_bytes: 256 * 1024,
    max_connections: 32,
    max_groups: 64,
    max_in_flight: 256,
    disk_full_policy: DiskFullPolicyArg::DropNew,
    checkpoint_interval: 1024,
    visibility_ms: 30_000,
    max_deliver: 5,
    // The 64 MiB tiny-edge RAM ceiling (#115): with the edge-tiny knobs above the worst-case
    // bounded-buffer footprint is ~15 MiB, so the refuse-to-boot guard lets edge-tiny boot, and a
    // blown-up cap override (e.g. a server-sized --max-connections) is provably refused.
    ram_ceiling_bytes: EDGE_TINY_RAM_CEILING,
};

/// The `balanced` preset: THE default, and EXACTLY the compiled-in `DEFAULT_*` constant set, so a
/// zero-config broker (no profile, env, or flag) is byte-identical to one that predates `--profile`.
/// Each field is written as the `DEFAULT_*` constant so the two cannot drift; a test asserts they
/// are equal. `docs/CONFIG.md` section 6: 64 MiB segments, 64 / 8 MiB credits, 256 connections,
/// 1024 groups, 1024 in-flight, `drop-new`, 1024 checkpoint, 30 s visibility, 5 max-deliver.
const BALANCED_PRESET: ProfilePreset = ProfilePreset {
    max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
    consumer_credit: DEFAULT_CONSUMER_CREDIT,
    consumer_credit_bytes: DEFAULT_CONSUMER_CREDIT_BYTES,
    max_connections: DEFAULT_MAX_CONNECTIONS,
    max_groups: DEFAULT_MAX_GROUPS,
    max_in_flight: DEFAULT_MAX_IN_FLIGHT,
    disk_full_policy: DiskFullPolicyArg::DropNew,
    checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
    visibility_ms: DEFAULT_VISIBILITY_MS,
    max_deliver: DEFAULT_MAX_DELIVER,
    // `balanced` leaves the RAM guard OFF (server-sized defaults are far over 64 MiB by design), so a
    // zero-config broker is byte-identical to one that predates `--ram-ceiling-bytes`.
    ram_ceiling_bytes: DEFAULT_RAM_CEILING_BYTES,
};

/// The `throughput` preset: `docs/CONFIG.md` section 6, wide buffers for a multi-core hub. 256 MiB
/// segments, 512 / 64 MiB credits, 1024 connections, 4096 groups, 8192 in-flight, `drop-oldest`,
/// 4096 checkpoint, 30 s visibility, 5 max-deliver. CONFIG.md fixes every value here, so no
/// throughput knob had to be chosen freely.
const THROUGHPUT_PRESET: ProfilePreset = ProfilePreset {
    max_segment_bytes: 256 * 1024 * 1024,
    consumer_credit: 512,
    consumer_credit_bytes: 64 * 1024 * 1024,
    max_connections: 1024,
    max_groups: 4096,
    max_in_flight: 8192,
    disk_full_policy: DiskFullPolicyArg::DropOldest,
    checkpoint_interval: 4096,
    visibility_ms: 30_000,
    max_deliver: 5,
    // `throughput` is a multi-core hub, not an edge node, so the RAM guard is OFF: its wide buffers
    // are intentionally over 64 MiB and an operator on a hub sizes RAM out of band.
    ram_ceiling_bytes: DEFAULT_RAM_CEILING_BYTES,
};

/// The smallest segment size cap `serve` accepts: below this, segments proliferate
/// pathologically (one record each), so reject it as a misconfiguration.
const MIN_MAX_SEGMENT_BYTES: u64 = 4096;

/// The default visibility timeout for `serve` (30 s, matching the lease default).
const DEFAULT_VISIBILITY_MS: u64 = 30_000;

/// The default `/healthz` liveness HYSTERESIS WINDOW for `serve` (#95), in milliseconds: `/healthz`
/// flips to 503 only after the broker's accept loop has gone this long with no progress tick, so a
/// slow-but-progressing fsync never fails liveness and an idle (but ticking) loop stays healthy. `0`
/// DISABLES the watchdog (`/healthz` is then a static 200 while up). 10 s matches the #95 spec.
const DEFAULT_HEALTH_LIVENESS_WINDOW_MS: u64 = 10_000;

/// The default lease hard cap for `serve` (5 minutes). The effective cap is the larger of
/// this and the visibility timeout, so it is never below one redelivery window. Used only by
/// the Unix on-disk broker, so it is cfg-gated to keep the non-Unix build free of a dead const.
#[cfg(unix)]
const DEFAULT_HARD_CAP_MS: u64 = 300_000;

/// The default max delivery attempts before a poison message is dead-lettered.
const DEFAULT_MAX_DELIVER: u32 = 5;
/// The default cursor-checkpoint interval for the `serve` engine: at most this many messages
/// are redelivered after an abrupt crash (a clean disconnect flushes the cursor sooner).
const DEFAULT_CHECKPOINT_INTERVAL: u64 = 1024;
/// The default escalating nack backoff schedule (nanoseconds), indexed by delivery attempt and
/// clamped to the last entry: 100 ms, 500 ms, 2 s, 10 s, 30 s. Applied when a nack carries no
/// explicit delay, so a flapping consumer backs off instead of hot-looping a retry.
#[cfg(unix)]
const DEFAULT_NACK_BACKOFF_NANOS: [u64; 5] = [
    100_000_000,
    500_000_000,
    2_000_000_000,
    10_000_000_000,
    30_000_000_000,
];

/// Frozen exit codes (subset in use for these verbs), per issue #91.
const EXIT_USAGE: u8 = 1;
const EXIT_UNREACHABLE: u8 = 5;
const EXIT_INTERNAL: u8 = 70;
/// The data directory (or path) an offline verb was pointed at does not exist.
const EXIT_NOT_FOUND: u8 = 2;
/// Handled corruption / a structured-but-degraded result: an inspection verb (`scrub`, or
/// `repair` reporting what it did) RAN TO COMPLETION and reported one or more real
/// data-loss spans (a corruption skip, reason other than the expected torn tail). The
/// command succeeded at its job; the non-zero code communicates the degraded finding, not a
/// failure. A clean run, AND a run whose only skip is an expected `TornTail` brownout
/// truncation, stays `0`. This is the exit-code-3 gate frozen in `docs/CLI_CONTRACT.md`,
/// reusing the loss report's data-loss-vs-torn-tail boundary (`ReasonCode::is_data_loss`).
const EXIT_HANDLED_CORRUPTION: u8 = 3;
/// An offline verb found the data directory structurally corrupt (a broken segment chain
/// or an undecodable header), distinct from a clean torn tail it can still read past. This
/// is the BLOCKED case (the command could not finish), distinct from exit 3 (the command
/// FINISHED and reported the damage).
const EXIT_CORRUPT: u8 = 4;

const USAGE: &str = "\
ironbus: a durable edge message queue.

USAGE:
    ironbus serve --data-dir <dir> [--config <path>] [--allow-unknown-config]
                  [--profile <edge-tiny|balanced|throughput>]
                  [--addr <host:port>] [--max-connections <n>]
                  [--checkpoint-interval <n>] [--max-deliver <n>] [--allow-unlimited-deliver]
                  [--backoff-ms <ms,ms,...>] [--max-in-flight <n>]
                  [--consumer-credit <n>] [--consumer-credit-bytes <n>]
                  [--max-segment-bytes <n>] [--max-total-bytes <bytes>]
                  [--max-retained-bytes <bytes>] [--max-age-ms <ms>] [--max-messages <n>]
                  [--max-groups <n>] [--group-idle-evict-ms <ms>]
                  [--disk-full-policy <drop-new|drop-oldest>]
                  [--key-shared-group <name>]... [--broadcast-group <name>]...
                  [--visibility-timeout-ms <n>] [--health-addr <host:port>] [--enable-admin]
    ironbus pub   [--addr <host:port>] [--key <key>] [<payload>]
    ironbus sub   [--addr <host:port>] [--group <name>] [--max <n>]
                  [--ack | --nack [--delay-ms <n>] | --term]
    ironbus cumulative-ack [--addr <host:port>] [--group <name>] --up-to <offset>
    ironbus admin --health-addr <host:port>
    ironbus admin consumer-reset --data-dir <dir> --group <name> --to <offset|earliest|latest> [--json]
    ironbus admin dlq-redrive --data-dir <dir> [--json]
    ironbus peek  --data-dir <dir> [--from-offset <n>] [--limit <n>] [--json]
    ironbus dump  --data-dir <dir> [--limit <n>] [--json] [--dlq]
                  [--raw] [--require-dict]
    ironbus scrub --data-dir <dir> [--json]
    ironbus repair --data-dir <dir> [--apply] [--json]
    ironbus top   (--addr <host:port> | --health-addr <host:port> | --data-dir <dir>)
                  [--interval <secs>] [--once] [--json] [--no-color]
    ironbus bench (--duration <secs> | --count <n>) [--mode <publish|subscribe|round-trip>]
                  [--rate <msg/s>] [--payload-bytes <n>] [--payload-shape <realistic|random>]
                  [--fetch-batch <n>] [--group <name>] [--no-fsync] [--json]
                  [--addr <host:port> --i-understand-this-is-live]
    ironbus upgrade --new-binary <path> --dest <path> [--max-failed-starts <n>]
    ironbus rollback --dest <path>
    ironbus record-start --dest <path> (--failed | --ok | --check)
    ironbus migrate --data-dir <dir> [--allow <to-version>]
    ironbus help
    ironbus version

Notes:
    The default address is 127.0.0.1:7777 (loopback only).
    --config <path> loads a TOML configuration FILE (#382). It slots BETWEEN env and default, so the
    precedence is flag > env > FILE > default: a file key beats the compiled default, but an env var
    or a flag still overrides it for one run. The file is whole-read, parsed, and STRICTLY validated
    before the broker opens: an unknown key is a fatal error with a did-you-mean suggestion (pass
    --allow-unknown-config to downgrade it to a warning, for a staged upgrade), a broken file fails
    with the path and line/column, and the coupled-set rules (e.g. retention requested but every
    limit 0) are checked as a whole. Durations use {ms,s,m,h,d} and byte sizes the binary
    {B,KiB,MiB,GiB,TiB} (decimal-SI MB/GB is rejected); the unit is required. With no --config the
    resolution is byte-for-byte the historical flag > env > default. See docs/CONFIG.md.
    --profile <edge-tiny|balanced|throughput> (default balanced) stamps a compiled-in, versioned
    set of coherent tuning knobs in one move, then any explicit env var or flag overrides an
    individual knob (precedence profile < env < flag). balanced is the shipped default set, so it
    is byte-identical to passing no profile; edge-tiny is the small-RAM, flash-gentle edge preset;
    throughput widens every buffer for a multi-core hub. An unknown profile name is a usage error.
    The active profile and its schema version are logged in the startup materialized-config line.
    --max-in-flight bounds the per-GROUP in-flight (max-ack-pending) window; --consumer-credit
    (default 64) bounds the per-CONNECTION un-acked set, so in a competing group one stuck
    consumer cannot consume a peer's budget. A fetch delivers min(requested, consumer credit,
    group window). --consumer-credit-bytes (default 8388608, 8 MiB; 0 = unlimited) is the parallel
    per-CONNECTION un-acked BYTE budget, so a large-payload consumer cannot blow the RAM ceiling
    despite a small message count: a fetch also stops once a connection's in-flight bytes reach the
    budget, with a hard floor of one message (a single over-budget message is still delivered so it
    never wedges the consumer).
    --max-deliver (default 5) caps delivery attempts before a poison message is dead-lettered.
    0 (and the maximum 4294967295) mean unlimited delivery, allowed ONLY with
    --allow-unlimited-deliver, which also prints a startup WARN: an unlimited cap lets a single
    poison payload redeliver forever and is never dead-lettered.
    --backoff-ms <ms,ms,...> sets the escalating per-attempt nack/redelivery delay schedule
    (e.g. 100,500,2000), indexed by attempt and clamped to the last entry; it applies when a nack
    carries no explicit delay. Omitted, a built-in default schedule is used; a single 0 disables
    backoff (retry as soon as the visibility timeout allows).
    Retention reaps whole old, fully-consumed sealed segments under three composable, consumer-safe
    bounds, each 0 = off (the default): --max-retained-bytes (durable record bytes),
    --max-age-ms (a segment whose newest record is older than this many milliseconds), and
    --max-messages (total record count). A segment is reaped if ANY enabled bound trips, oldest
    first, never below the slowest consumer's committed offset, never the active segment.
    --max-groups (default 1024, 0 = unlimited) caps the number of live work-groups, including the
    default group, so once the wire can name groups a client cannot exhaust memory by naming
    endless groups. A new named group past the cap is rejected; the default group is never counted.
    --group-idle-evict-ms (default 0 = disabled) evicts an idle NAMED work-group from memory after
    it has been idle this many milliseconds, reclaiming its slot against --max-groups. Only a
    fully-caught-up (committed at the head, no acked-ahead set), lease-free, non-key-shared named
    group is evicted; the default group is never evicted and a group that is behind is never evicted,
    so a consumer's committed position is never lost. The durable per-group checkpoint is kept, so a
    re-subscribe resumes where it left off. The sweep is clock-driven (run on produce and poll, no
    background thread). An explicit unsub of a now-idle named group reclaims it immediately.
    --disk-full-policy (default drop-new) sets what an over-cap produce does once --max-total-bytes
    is hit: drop-new sheds it (preserving older data); drop-oldest force-reaps the oldest sealed
    segment to make room then accepts it, so a slow consumer whose records are reaped gets a
    one-time truncation notice and resumes at the oldest record still present.
    --key-shared-group <name> (repeatable, default none) runs the named competing group in
    key_shared ordering: a record's key routes to one live member, so same-key records keep their
    order while the group drains in parallel across keys. A group not named here stays plain
    competing distribution (the default), unaffected.
    --broadcast-group <name> (repeatable, default none) marks the named group BROADCAST: a
    group-of-one that sees every record in order, so it accepts the cumulative-ack verb
    (ack-all-up-to-offset). A broadcast group is mutually exclusive with key_shared. A group not
    named here stays plain competing distribution and rejects cumulative ack.
    cumulative-ack commits a BROADCAST group's cursor up to (exclusive) --up-to in one move, the
    safe broadcast half of the ack-all-up-to-offset verb. The server rejects it for a competing or
    key_shared group, and rejects an --up-to past the durable head or below the earliest retained
    offset; a re-ack at or below the current commit is an idempotent no-op success.
    --enable-admin (default off) turns on the read-only /admin introspection endpoint on the health
    server (so it needs --health-addr): a JSON snapshot of broker counters, per-group lag/in-flight,
    DLQ state, and the effective config bounds, for debugging. It is READ-ONLY (GET only, no path
    mutates state) and UNAUTHENTICATED, sharing /metrics's trust model, so run it only on loopback or
    a trusted network. Off, /admin is a 404 like any unknown path.
    admin --health-addr <host:port> fetches that read-only /admin v1 JSON from a RUNNING broker and
    prints the segments span, per-consumer committed offset and lag, and the resilience
    last-skip-offset, all from the /admin document alone (it never parses a metric name). It sends
    the version-pinning Accept header, so a schema mismatch is a clear error, not a misrender. The
    broker must have been started with --enable-admin; otherwise /admin is a 404 and admin says so.
    admin consumer-reset and admin dlq-redrive are OFFLINE mutating admin verbs (#299): they operate
    on a STOPPED broker's --data-dir, taking the same exclusive data-dir lock serve holds, so they
    refuse (exit 5) if a broker is running and can never race a live writer. consumer-reset rewrites
    a work-group's durable cursor checkpoint to --to <offset|earliest|latest> (clamped to the durable
    range; an out-of-range explicit offset is rejected, exit 1) using the broker's exact crash-safe
    dual-slot checkpoint, so the broker resumes the group from there on its next start. dlq-redrive
    re-injects the dead-lettered records from the durable DLQ sink back onto the main log (append and
    fsync the records, then advance a durable redrive watermark), crash-safely and idempotently (a
    re-run after a completed redrive re-injects nothing). The MUTATING WIRE admin verbs (the same
    actions on a LIVE broker) and force-reap (reaping stuck leases on a running broker) need
    connection-scoped auth and are deferred to the authed admin surface (#380/#106).
    pub reads the payload from the argument, or from stdin if omitted (an empty input
    publishes an empty message, which is a valid record).
    sub prints one line per message; at most one disposition applies to the batch:
    --ack commits, --nack requeues (after --delay-ms), --term drops without dead-lettering.
    peek and dump decode a stopped broker's data directory with no server running; they
    read only up to the durable high-water mark and mark, never hide, any torn or corrupt
    tail. peek shows a window (default 10 records); dump streams every record, one per line
    (NDJSON with --json). Both bound memory to one segment at a time.
    dump --dlq instead streams the durable dead-letter SINK (the dlq/ subdirectory): one line
    per poison record showing dlq_offset, source_offset, group, attempt, ts_ms, and the
    key/payload sizes (NDJSON with --json). It is read-only and never mutates the directory;
    an empty or never-poisoned broker shows nothing.
    dump --raw shows the on-disk frame and --require-dict fails strictly (exit 3) on a record
    whose dictionary is missing. On-disk compression (#12) is not yet implemented (the codec is
    always none), so today every record decodes plainly: --raw renders the same field set and
    --require-dict never trips. The flags are the committed surface for when #12 lands.
    scrub is an offline, strictly READ-ONLY full integrity scan of the data dir (no broker): it
    reports every corruption, torn-tail, or checksum issue it finds (the plan) and marks, never
    hides, what recovery would quarantine. It exits 0 if clean (a torn-tail-only result stays 0,
    matching recovery's data-loss boundary), 3 if it found and reported real data-loss corruption,
    2 if the data dir is missing, 4 if the chain is structurally corrupt and could not be read.
    repair defaults to the SAME read-only plan as scrub (print what it WOULD do, change nothing).
    --apply performs the repair: it takes the EXCLUSIVE data-dir lock first (exit 5 if a broker
    holds it), QUARANTINES (copies to quarantine/, never deletes) any corrupt span, truncates to
    the longest valid prefix exactly as recovery does, and preserves the data dir's uid/gid/mode.
    It is recovery made explicit and offline; it never makes the data less recoverable than
    recovery already would.
    top is a strictly READ-ONLY status view with two explicit modes. LIVE
    (--addr/--health-addr <host:port>) polls the broker's read-only /admin v1 JSON every --interval
    seconds (default 1, minimum 1) and renders the #16 counters: durable head, per-group lag and
    in-flight, the DLQ, the resilience counters, and the cumulative throughput counters; a down
    broker exits 5. OFFLINE (--data-dir <dir>) renders ONLY the file-derived panels (segments,
    durable head, the loss report, and the quarantine span) with NO broker, behind a MANDATORY
    banner that names it the offline file-derived view, so a missing volatile panel is never misread
    as a real zero. Exactly one mode is required (both or neither is a usage error). top never
    mutates anything: it only reads, and any action is PRINTED, never run. --once emits one snapshot
    and exits (for tests and scripting). Output degrades gracefully: a TTY with color (NO_COLOR
    unset, --no-color absent) and a refreshing run redraw in place with simple ANSI escapes; a piped
    or non-TTY stdout, NO_COLOR, --no-color, or --once print a PLAIN escape-free snapshot, so
    `ironbus top | cat` and a CI run produce clean text. --json emits a single versioned
    ironbus.cli.top.v1 object (the mode is tagged, so a script tells live from offline). The refresh
    SLEEPS between polls and never busy-spins. Offline mode is Unix-only in v1 (the on-disk store).
    bench is a load generator that reports throughput, p50/p99/p999 latency, fsync cost, and
    bytes/op over the real wire and produce path. By DEFAULT it is PRODUCTION-SAFE: it spawns its
    own ISOLATED broker over a fresh ironbus-bench-<random> data directory and reads through a fresh
    ironbus-bench-<random> consumer group, then auto-deletes the directory (a cleanup failure is
    reported and exits 70). It REFUSES to target an existing broker (--addr) or join a non-bench
    consumer group (--group) unless --i-understand-this-is-live is passed, so it can never corrupt
    real data or steal a real group's messages. To protect edge flash, exactly one of --duration
    <secs> or --count <n> is REQUIRED (no unbounded default), and --no-fsync is a dry run that
    batches the bench broker's cursor checkpoints (the fsync cost is then reported as not measured).
    round-trip mode (the default) measures producer-to-consumer latency through the real durable
    path, so the fsync-cost number is honest. Payloads are realistic (compressible, codec-friendly)
    by default; --payload-shape random uses incompressible noise. --json emits a single versioned
    object with explicitly-named latency-histogram fields (latency_p50_us, latency_p99_us,
    latency_p999_us, latency_max_us).
    Every serve setting can also be supplied via an environment variable IRONBUS_<FLAG>, the flag
    name uppercased with dashes as underscores (--max-total-bytes -> IRONBUS_MAX_TOTAL_BYTES,
    --data-dir -> IRONBUS_DATA_DIR, --addr -> IRONBUS_ADDR). Precedence is flag > env > default: an
    explicit flag overrides the env var, which overrides the compiled default. A bad env value (e.g.
    non-numeric where a number is expected) is a usage error naming the env var. See docs/CLI.md.
    On serve, the --data-dir is created (parents too, mode 0700) if absent and verified writable; a
    path that exists but is not a directory, or a read-only mount, is a fatal error naming the path.
    serve takes an exclusive lock on the data dir, so a second broker on the same data dir fails
    fast rather than corrupting the log with concurrent writers.
    upgrade swaps an ALREADY-VERIFIED new binary (--new-binary) over the live one (--dest) WITHOUT
    overwriting it in place: it stages the new bytes to a sibling temp on the same filesystem,
    fsyncs, retains the prior binary as <dest>.prev (one-command rollback), then renames atomically
    (POSIX), so a power cut mid-upgrade leaves either the old or the new binary, never a truncated
    one. The fail-closed download/verify is scripts/install.sh; upgrade is the post-verify swap.
    --max-failed-starts (default 3) is the N the systemd unit consults for fall-back.
    rollback restores <dest>.prev over --dest (the same atomic swap) and clears the start counter.
    record-start --failed/--ok/--check drives the consecutive-failed-start counter the systemd unit
    uses to fall back after N failures. --failed bumps it by one (the SINGLE increment source: the
    unit runs it as ExecStopPost on a non-clean exit); --ok clears it (the unit runs it once the
    broker is confirmed up, so a genuine failed start never clears it); --check only CONSULTS the
    counter without changing it (the unit runs it as ExecStartPre and rolls back if it reports the
    threshold is reached and a .prev exists), so a consult never itself bumps the counter and a
    healthy node that loses power uncleanly cannot accumulate toward a spurious rollback. See
    docs/DISTRIBUTION.md for the exact unit wiring.
    migrate gates an on-disk format bump so it is NEVER silent: within a major version the data dir
    opens with no migration (migrate reports 'no migration needed' and exits 0); a future format
    bump requires an explicit --allow <to-version> and is refused without it, exit 1. ironbus
    --version emits the build version (and the release embeds commit/provenance, see RELEASING.md).
    Exit codes: 0 clean, 1 usage, 2 not found, 3 handled corruption (scrub/repair finished and
    reported real data loss), 4 corrupt data (blocked: the chain could not be read), 5 broker
    unreachable, 70 internal.";

/// A command-line failure, mapped to a frozen exit code by [`main`].
#[derive(Debug)]
enum CliError {
    /// Bad or missing arguments (exit 1).
    Usage(String),
    /// The broker could not be reached (exit 5).
    Unreachable(String),
    /// An internal or runtime failure, including an unsupported platform (exit 70).
    Internal(String),
    /// An offline verb's data directory does not exist (exit 2). Constructed only on Unix,
    /// where the offline verbs run; documented in the exit-code scheme on every platform.
    #[cfg_attr(not(unix), allow(dead_code))]
    NotFound(String),
    /// An offline verb's data directory is structurally corrupt (exit 4). Constructed only
    /// on Unix, where the offline verbs run; documented on every platform.
    #[cfg_attr(not(unix), allow(dead_code))]
    Corrupt(String),
    /// Handled corruption (exit 3): an inspection verb (`scrub`/`repair`) ran to completion
    /// and reported one or more real data-loss spans. The command SUCCEEDED at its job; the
    /// non-zero code is the degraded finding, not a failure. The structured result has already
    /// been written to stdout (human or `--json`) before this is returned; the message is the
    /// informational summary, not an alarm. Constructed only on Unix, where the verbs run;
    /// documented on every platform.
    #[cfg_attr(not(unix), allow(dead_code))]
    HandledCorruption(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Unreachable(_) => EXIT_UNREACHABLE,
            CliError::Internal(_) => EXIT_INTERNAL,
            CliError::NotFound(_) => EXIT_NOT_FOUND,
            CliError::HandledCorruption(_) => EXIT_HANDLED_CORRUPTION,
            CliError::Corrupt(_) => EXIT_CORRUPT,
        }
    }
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CliError::Usage(m)
            | CliError::Unreachable(m)
            | CliError::Internal(m)
            | CliError::NotFound(m)
            | CliError::HandledCorruption(m)
            | CliError::Corrupt(m) => write!(f, "{m}"),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Internal(format!("io error: {e}"))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match run(&args, &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            if let CliError::Usage(_) = e {
                eprintln!("\n{USAGE}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// Parses `args` (without the program name) and dispatches the subcommand, writing normal
/// output to `out`.
///
/// # Errors
/// Returns a [`CliError`] for a usage problem, an unreachable broker, or a runtime failure.
fn run(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| CliError::Usage("no subcommand given".to_string()))?;
    match cmd.as_str() {
        "pub" => run_pub(rest, out),
        "sub" => run_sub(rest, out),
        "cumulative-ack" => run_cumulative_ack(rest, out),
        "serve" => run_serve(rest, out),
        "admin" => run_admin(rest, out),
        "peek" => run_peek(rest, out),
        "dump" => run_dump(rest, out),
        "scrub" => run_scrub(rest, out),
        "repair" => run_repair(rest, out),
        "top" => top::run_top(rest, out),
        "bench" => run_bench(rest, out),
        "upgrade" => run_upgrade(rest, out),
        "rollback" => run_rollback(rest, out),
        "record-start" => run_record_start(rest, out),
        "migrate" => run_migrate(rest, out),
        "help" | "--help" | "-h" => {
            writeln!(out, "{USAGE}")?;
            Ok(())
        }
        // A single deterministic version line. `--version`/`-V`/`version` all print the same
        // `ironbus <semver>` and exit 0, so an operator (and the CI cross-build smoke, #100) can
        // identify the build with no broker, no data dir, and no socket. The version is the
        // workspace package version compiled in via Cargo's `CARGO_PKG_VERSION`, so it tracks the
        // crate version automatically and cannot drift from the manifest.
        "version" | "--version" | "-V" => {
            writeln!(out, "ironbus {}", env!("CARGO_PKG_VERSION"))?;
            Ok(())
        }
        other => Err(CliError::Usage(format!("unknown subcommand `{other}`"))),
    }
}

/// Returns the value following `flag` at `args[*i]`, advancing `*i` past both tokens.
fn take_value(flag: &str, args: &[String], i: &mut usize) -> Result<String, CliError> {
    let value = args
        .get(*i + 1)
        .ok_or_else(|| CliError::Usage(format!("`{flag}` needs a value")))?
        .clone();
    *i += 2;
    Ok(value)
}

/// Like [`take_value`] but parses the value as a number, mapping a non-numeric value to the same
/// `` `{flag}` needs a number, got `{raw}` `` usage error every numeric `serve` flag returns. This
/// collapses the per-flag parse boilerplate to one call so the flag parser stays compact.
fn take_number<T>(flag: &str, args: &[String], i: &mut usize) -> Result<T, CliError>
where
    T: std::str::FromStr,
{
    let raw = take_value(flag, args, i)?;
    raw.parse::<T>()
        .map_err(|_| CliError::Usage(format!("`{flag}` needs a number, got `{raw}`")))
}

/// Like [`take_number`] but parses a comma-separated LIST of `u64` values (e.g. `100,500,2000`),
/// for the `--backoff-ms` schedule (#63). Whitespace around a value is tolerated; an empty list,
/// an empty element (a stray comma), or a non-numeric element is a usage error, so a typo is
/// caught before the broker opens rather than silently dropping a stage of the schedule.
fn take_number_list(flag: &str, args: &[String], i: &mut usize) -> Result<Vec<u64>, CliError> {
    let raw = take_value(flag, args, i)?;
    // Shared with the env-var path (`IRONBUS_BACKOFF_MS`, #89) via `parse_u64_list`, so the flag and
    // the env var accept exactly the same grammar and emit the same error shape (naming the source).
    parse_u64_list(flag, &raw)
}

/// Classifies a client error against the frozen exit-code scheme. A connection-level failure
/// (the broker is down, or dropped us mid-request) is broker-unreachable (5); a broker that
/// answered but spoke a wrong-shape or error frame is an internal/protocol fault (70). Used
/// at every client call site so "broker down" is exit 5 whether it was down before the dial
/// or died one request into the exchange.
fn classify(addr: &str, doing: &str, e: &ClientError) -> CliError {
    let message = format!("{doing} broker at {addr}: {e}");
    match e {
        ClientError::Io(_) | ClientError::Closed => CliError::Unreachable(message),
        _ => CliError::Internal(message),
    }
}

fn connect(addr: &str) -> Result<Client, CliError> {
    Client::connect(addr).map_err(|e| classify(addr, "connecting to", &e))
}

fn run_pub(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut key = String::new();
    let mut payload_arg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => addr = take_value("--addr", args, &mut i)?,
            "--key" => key = take_value("--key", args, &mut i)?,
            "--" => {
                // End of options: every remaining token is the payload (at most one), so a
                // payload that begins with `--` can still be published from the argument form.
                i += 1;
                while i < args.len() {
                    if payload_arg.is_some() {
                        return Err(CliError::Usage(
                            "pub takes at most one payload argument".to_string(),
                        ));
                    }
                    payload_arg = Some(args[i].clone());
                    i += 1;
                }
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for pub")))
            }
            _ => {
                if payload_arg.is_some() {
                    return Err(CliError::Usage(
                        "pub takes at most one payload argument".to_string(),
                    ));
                }
                payload_arg = Some(args[i].clone());
                i += 1;
            }
        }
    }
    // Payload from the argument, or from stdin if the argument is omitted.
    let payload = if let Some(p) = payload_arg {
        p.into_bytes()
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };
    cmd_pub(&addr, key.as_bytes(), &payload, out)
}

fn cmd_pub(addr: &str, key: &[u8], payload: &[u8], out: &mut impl Write) -> Result<(), CliError> {
    let mut client = connect(addr)?;
    let timestamp_ms = SystemClock::new().now_unix_millis();
    let offset = client
        .produce(&PubBody {
            flags: 0,
            timestamp_ms,
            key,
            headers: b"",
            dedup: None,
            payload,
        })
        .map_err(|e| classify(addr, "publishing to", &e))?;
    writeln!(out, "{offset}")?;
    Ok(())
}

/// What `sub` does with each fetched message.
#[derive(Clone, Copy)]
enum Disposition {
    /// Print only; the message stays in flight and redelivers after the visibility timeout.
    Peek,
    /// Commit each message (`--ack`).
    Ack,
    /// Requeue each message for redelivery; `None` uses the broker's backoff schedule (`--nack`).
    Nack { delay_ms: Option<u64> },
    /// Drop each message without dead-lettering (`--term`).
    Term,
}

/// The chosen `sub` disposition verb (before the nack delay is known). A typed slot keeps the
/// build-the-`Disposition` match exhaustive and compiler-checked, so a verb can never be
/// silently dropped to a peek by a typo.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DispositionKind {
    Ack,
    Nack,
    Term,
}

/// Records a chosen `sub` disposition, rejecting a second one (the three are exclusive).
fn set_dispose(slot: &mut Option<DispositionKind>, kind: DispositionKind) -> Result<(), CliError> {
    if slot.is_some() {
        return Err(CliError::Usage(
            "sub takes at most one of `--ack`, `--nack`, `--term`".to_string(),
        ));
    }
    *slot = Some(kind);
    Ok(())
}

fn run_sub(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut group = String::new();
    let mut max = DEFAULT_FETCH;
    let mut dispose: Option<DispositionKind> = None;
    let mut delay_ms: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => addr = take_value("--addr", args, &mut i)?,
            "--group" => group = take_value("--group", args, &mut i)?,
            "--max" => {
                let raw = take_value("--max", args, &mut i)?;
                max = raw
                    .parse::<u32>()
                    .map_err(|_| CliError::Usage(format!("`--max` needs a number, got `{raw}`")))?;
            }
            "--ack" => {
                set_dispose(&mut dispose, DispositionKind::Ack)?;
                i += 1;
            }
            "--nack" => {
                set_dispose(&mut dispose, DispositionKind::Nack)?;
                i += 1;
            }
            "--term" => {
                set_dispose(&mut dispose, DispositionKind::Term)?;
                i += 1;
            }
            "--delay-ms" => {
                let raw = take_value("--delay-ms", args, &mut i)?;
                delay_ms = Some(raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--delay-ms` needs a number, got `{raw}`"))
                })?);
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for sub")))
            }
            other => {
                return Err(CliError::Usage(format!(
                    "sub takes no positional arguments, got `{other}`"
                )))
            }
        }
    }
    if delay_ms.is_some() && dispose != Some(DispositionKind::Nack) {
        return Err(CliError::Usage(
            "`--delay-ms` is only valid with `--nack`".to_string(),
        ));
    }
    let disposition = match dispose {
        Some(DispositionKind::Ack) => Disposition::Ack,
        Some(DispositionKind::Nack) => Disposition::Nack { delay_ms },
        Some(DispositionKind::Term) => Disposition::Term,
        None => Disposition::Peek,
    };
    cmd_sub(&addr, &group, max, disposition, out)
}

fn cmd_sub(
    addr: &str,
    group: &str,
    max: u32,
    disposition: Disposition,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut client = connect(addr)?;
    // Join the named work-group before fetching (#9); an empty name keeps the default group.
    if !group.is_empty() {
        client
            .subscribe(group)
            .map_err(|e| classify(addr, "subscribing to", &e))?;
    }
    // Re-fetch until `max` is reached or a batch comes back empty. The per-consumer credit (#65)
    // caps a single Flow at the in-flight window, so a larger `--max` can only drain when each
    // batch is committed past: Ack and Term advance the cursor, freeing credit so the next fetch
    // serves new records. Peek and Nack do not advance (Peek keeps the records leased, Nack
    // requeues them), so re-fetching would only re-serve the same batch (under Nack, an immediate
    // redelivery storm); for those we take a single window-bounded batch and stop.
    let drains = matches!(disposition, Disposition::Ack | Disposition::Term);
    let mut total: u32 = 0;
    loop {
        let want = max - total;
        if want == 0 {
            break;
        }
        let fetched = client
            .fetch(want)
            .map_err(|e| classify(addr, "fetching from", &e))?;
        let got = u32::try_from(fetched.messages.len()).unwrap_or(u32::MAX);
        for m in &fetched.messages {
            writeln!(
                out,
                "#{} gen={} key={} payload={}",
                m.offset,
                m.generation,
                String::from_utf8_lossy(&m.key),
                String::from_utf8_lossy(&m.payload),
            )?;
            match disposition {
                Disposition::Peek => {}
                Disposition::Ack => {
                    let ok = client
                        .ack(m.offset, m.generation)
                        .map_err(|e| classify(addr, "acking to", &e))?;
                    writeln!(out, "  ack {}", if ok { "committed" } else { "fenced" })?;
                }
                Disposition::Nack { delay_ms } => {
                    let ok = client
                        .nack(m.offset, m.generation, delay_ms)
                        .map_err(|e| classify(addr, "nacking to", &e))?;
                    writeln!(out, "  nack {}", if ok { "requeued" } else { "fenced" })?;
                }
                Disposition::Term => {
                    let ok = client
                        .term(m.offset, m.generation)
                        .map_err(|e| classify(addr, "terminating on", &e))?;
                    writeln!(out, "  term {}", if ok { "dropped" } else { "fenced" })?;
                }
            }
        }
        // Surface any in-band dead-letter advisories: offsets the broker dropped as poison
        // (over MaxDeliver) and skipped from delivery (#63), so a consumer is not left silently
        // never seeing them.
        for dl in &fetched.dead_letters {
            let reason = if dl.reason == 0 {
                "max-deliver"
            } else {
                "reserved"
            };
            writeln!(out, "dead-letter offset={} reason={reason}", dl.offset)?;
        }
        // Surface any truncation advisories: the broker reset this cursor below the oldest retained
        // record because the disk-full drop-oldest policy reaped its records (#82, #84), so the
        // consumer learns it lost a span and where delivery resumed rather than silently skipping.
        for t in &fetched.truncations {
            writeln!(
                out,
                "truncated: resumed at offset {}, skipped {} record(s)",
                t.earliest_retained, t.skipped
            )?;
        }
        total = total.saturating_add(got);
        if got == 0 || !drains {
            break;
        }
    }
    writeln!(out, "fetched {total} message(s)")?;
    Ok(())
}

/// Parses and runs `cumulative-ack`: send a BROADCAST cumulative ack (ack-all-up-to-offset, #288)
/// for a group, committing its cursor up to the exclusive `--up-to` offset in one move.
///
/// # Errors
/// Returns [`CliError::Usage`] for a bad flag or a missing `--up-to`, [`CliError::Unreachable`] if
/// the broker is down, or [`CliError::Internal`] if the broker rejects the verb (the group is not a
/// broadcast consumer, or `--up-to` is outside the retained window).
fn run_cumulative_ack(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut group = String::new();
    let mut up_to: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => addr = take_value("--addr", args, &mut i)?,
            "--group" => group = take_value("--group", args, &mut i)?,
            "--up-to" => up_to = Some(take_number("--up-to", args, &mut i)?),
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for cumulative-ack"
                )))
            }
            other => {
                return Err(CliError::Usage(format!(
                    "cumulative-ack takes no positional arguments, got `{other}`"
                )))
            }
        }
    }
    let up_to = up_to
        .ok_or_else(|| CliError::Usage("cumulative-ack requires `--up-to <offset>`".to_string()))?;
    cmd_cumulative_ack(&addr, &group, up_to, out)
}

fn cmd_cumulative_ack(
    addr: &str,
    group: &str,
    up_to: u64,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut client = connect(addr)?;
    client
        .cumulative_ack(group, up_to)
        .map_err(|e| classify(addr, "cumulative-acking to", &e))?;
    let named = if group.is_empty() {
        "default group".to_string()
    } else {
        format!("group `{group}`")
    };
    writeln!(out, "cumulative ack committed {named} up to offset {up_to}")?;
    Ok(())
}

/// An injectable environment-variable lookup (#89): maps an env-var NAME to its value, or `None`
/// if it is unset. A `serve` setting reads its `IRONBUS_<FLAG>` var through this seam rather than
/// touching `std::env` directly, so a test can drive the env layer deterministically with a fixed
/// map (no global, racy process-environment mutation) while production passes a closure over the
/// real [`std::env::var`]. The precedence is flag > env > default: an explicit CLI flag overrides
/// the env var, which overrides the compiled default.
type EnvFn<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// Reads the `IRONBUS_<flag>` env var for `flag` (e.g. `--data-dir` -> `IRONBUS_DATA_DIR`) through
/// the injected `env` seam, returning the raw string if set. The mapping is the flag name minus its
/// leading `--`, uppercased, with `-` -> `_`, prefixed `IRONBUS_`; documented in `docs/CLI.md`.
fn env_var_name(flag: &str) -> String {
    let base = flag
        .trim_start_matches('-')
        .replace('-', "_")
        .to_uppercase();
    format!("IRONBUS_{base}")
}

/// Resolves a STRING setting with the flag > env > default precedence: the explicit CLI `flag`
/// value if given, else the `IRONBUS_<flag>` env var if set, else `default`.
fn resolve_string(flag: &str, cli: Option<String>, env: &EnvFn<'_>, default: &str) -> String {
    cli.or_else(|| env(&env_var_name(flag)))
        .unwrap_or_else(|| default.to_string())
}

/// Resolves an OPTIONAL string setting (one with no compiled default, e.g. `--data-dir`,
/// `--health-addr`): the explicit CLI value if given, else the env var if set, else `None`.
fn resolve_opt_string(flag: &str, cli: Option<String>, env: &EnvFn<'_>) -> Option<String> {
    cli.or_else(|| env(&env_var_name(flag)))
}

/// Resolves a NUMERIC setting with the flag > env > default precedence. If the CLI flag was given
/// its already-parsed value wins; otherwise the `IRONBUS_<flag>` env var is parsed, and a
/// non-numeric env value is a usage error NAMING THE ENV VAR (e.g. ``IRONBUS_MAX_TOTAL_BYTES needs
/// a number, got `x` ``), exactly as a bad flag value names the flag; absent the env var, `default`.
fn resolve_number<T>(flag: &str, cli: Option<T>, env: &EnvFn<'_>, default: T) -> Result<T, CliError>
where
    T: std::str::FromStr,
{
    if let Some(value) = cli {
        return Ok(value);
    }
    let name = env_var_name(flag);
    match env(&name) {
        Some(raw) => raw
            .parse::<T>()
            .map_err(|_| CliError::Usage(format!("`{name}` needs a number, got `{raw}`"))),
        None => Ok(default),
    }
}

/// Resolves a comma-separated `u64` LIST setting (`--backoff-ms`) with flag > env > default. The
/// CLI list wins if given; else the `IRONBUS_BACKOFF_MS` env var is parsed with the same grammar as
/// the flag (comma-separated, whitespace-tolerant), a bad element a usage error naming the env var;
/// absent the env var, the empty list (meaning "use the built-in default schedule").
fn resolve_number_list(
    flag: &str,
    cli: Option<Vec<u64>>,
    env: &EnvFn<'_>,
) -> Result<Vec<u64>, CliError> {
    if let Some(list) = cli {
        return Ok(list);
    }
    let name = env_var_name(flag);
    match env(&name) {
        Some(raw) => parse_u64_list(&name, &raw),
        None => Ok(Vec::new()),
    }
}

/// Parses a comma-separated `u64` list (the shared `--backoff-ms` grammar), naming `source` (a flag
/// or an env var) in the error. Whitespace around an element is tolerated; an empty element (a
/// stray comma) or a non-numeric element is a usage error.
fn parse_u64_list(source: &str, raw: &str) -> Result<Vec<u64>, CliError> {
    let mut values = Vec::new();
    for part in raw.split(',') {
        let value = part.trim().parse::<u64>().map_err(|_| {
            CliError::Usage(format!(
                "`{source}` needs a comma-separated list of numbers, got `{raw}`"
            ))
        })?;
        values.push(value);
    }
    if values.is_empty() {
        return Err(CliError::Usage(format!(
            "`{source}` needs at least one number"
        )));
    }
    Ok(values)
}

/// Resolves a BOOLEAN flag with flag > env > default(false). The flag is set on the command line
/// (no value), else the `IRONBUS_<flag>` env var is read: `1`/`true` (case-insensitive) enables it,
/// `0`/`false` disables it, any other value is a usage error naming the env var; absent, `false`.
fn resolve_bool(flag: &str, cli_set: bool, env: &EnvFn<'_>) -> Result<bool, CliError> {
    if cli_set {
        return Ok(true);
    }
    let name = env_var_name(flag);
    match env(&name) {
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" => Ok(true),
            "0" | "false" => Ok(false),
            other => Err(CliError::Usage(format!(
                "`{name}` must be `true`/`1` or `false`/`0`, got `{other}`"
            ))),
        },
        None => Ok(false),
    }
}

/// The fully-parsed `serve` invocation: the assembled tuning config plus the connection-level
/// arguments (the bind address, the optional data dir and health address, the declared
/// `key_shared` groups, and the declared broadcast groups) that are not part of [`ServeConfig`].
#[derive(Debug)]
struct ParsedServe {
    addr: String,
    data_dir: Option<String>,
    config: ServeConfig,
    key_shared_groups: Vec<String>,
    /// The work-group names declared BROADCAST (#288): each is a group-of-one that sees every
    /// record in order, marked broadcast at open so it accepts the cumulative-ack verb. CLI-only
    /// (no env mapping), repeatable like `--key-shared-group`.
    broadcast_groups: Vec<String>,
    health_addr: Option<String>,
    /// Non-fatal config-FILE warnings (#86, #382): unknown keys downgraded by
    /// `--allow-unknown-config`, plus the coupled-set warnings (a no-op `drop-oldest`). Surfaced to
    /// the log stream by `cmd_serve`; empty with no `--config`.
    config_warnings: Vec<String>,
    /// True when the config FILE explicitly set any retention key (#86, #382): drives the
    /// coupled-set "retention requested but every limit is 0" check, which fires only on an explicit
    /// request. False with no `--config`.
    retention_requested: bool,
    /// The `--config` path (#382), threaded to `cmd_serve` so the immutable-config + reload handle
    /// can RE-READ the file on a reload (the safe re-read trigger). `None` with no `--config`.
    config_path: Option<String>,
    /// The `--allow-unknown-config` flag (#86), threaded to `cmd_serve` so a re-read reload applies
    /// the SAME unknown-key policy as the startup load. False with no `--config`.
    allow_unknown_config: bool,
}

fn run_serve(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    // Production reads the real process environment through the injected seam; tests drive
    // `parse_serve_flags_with_env` with a fixed map so the env layer is deterministic (#89).
    let env = |name: &str| std::env::var(name).ok();
    let parsed = parse_serve_flags_with_env(args, &env)?;
    finish_serve(
        &parsed.addr,
        parsed.data_dir.as_deref(),
        &parsed.config,
        &parsed.key_shared_groups,
        &parsed.broadcast_groups,
        parsed.health_addr.as_deref(),
        &parsed.config_warnings,
        ReloadSource {
            config_path: parsed.config_path.as_deref(),
            allow_unknown_config: parsed.allow_unknown_config,
        },
        out,
    )
}

/// The inputs a re-read RELOAD needs (#382): the `--config` path to re-read and the unknown-key
/// policy to re-apply. Bundled into one struct so `finish_serve`/`cmd_serve` carry a single reload
/// concern rather than two more positional arguments. `config_path = None` means no `--config`, so
/// no reload source exists and the handle is read-only at startup.
#[derive(Clone, Copy)]
struct ReloadSource<'a> {
    /// The `--config` path to re-read on a reload, or `None` for no config file.
    config_path: Option<&'a str>,
    /// The `--allow-unknown-config` policy to re-apply on a reload.
    allow_unknown_config: bool,
}

/// Parses the `serve` flag list into a [`ParsedServe`]. Split out of [`run_serve`] so the
/// flag-parsing loop is one self-contained concern (and stays under the per-function line bound).
/// The `serve` flags as EXPLICITLY GIVEN on the command line: each settable knob is `Some` only if
/// its flag appeared, `None` otherwise, so the env/default layer ([`parse_serve_flags_with_env`])
/// can fill the unset slots with flag > env > default precedence (#89). The repeatable
/// `--key-shared-group` is a plain `Vec` (CLI-only, no env mapping); the booleans are `true` only if
/// their bare flag appeared.
// Each bool mirrors a distinct bare CLI flag (--allow-unlimited-deliver, --enable-admin,
// --health-allow-public, --async-loss-ack); they are independent knobs, not a state enum, so a
// struct of flag mirrors is the right shape (the same reasoning as ServeConfig below).
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct ServeFlags {
    addr: Option<String>,
    data_dir: Option<String>,
    /// The `--config <path>` TOML config FILE (#85, #382). `None` = no file, so resolution is the
    /// historical flag > env > default; when set, the file is read/parsed/validated and slots
    /// BETWEEN env and default (flag > env > FILE > default). CLI-only (no `IRONBUS_CONFIG` env, so
    /// the file location is never itself a file-resolved knob).
    config: Option<String>,
    /// The `--allow-unknown-config` escape hatch (#86): downgrade an unknown config-FILE key from a
    /// fatal error to a warning, for a staged upgrade. A bare boolean flag; default OFF (strict
    /// reject-unknown). CLI-only.
    allow_unknown_config: bool,
    /// The compiled-in named profile (#87) selected by `--profile` / `IRONBUS_PROFILE`. `None`
    /// resolves to the default profile (`balanced`). The profile is applied as the per-knob default,
    /// so an explicit env var or flag for any individual knob still overrides it (profile < env <
    /// flag). An unknown name is a usage error.
    profile: Option<String>,
    max_connections: Option<usize>,
    checkpoint_interval: Option<u64>,
    max_deliver: Option<u32>,
    allow_unlimited_deliver: bool,
    backoff_ms: Option<Vec<u64>>,
    max_in_flight: Option<u32>,
    consumer_credit: Option<u32>,
    consumer_credit_bytes: Option<u64>,
    max_segment_bytes: Option<u64>,
    max_total_bytes: Option<u64>,
    max_retained_bytes: Option<u64>,
    max_age_ms: Option<u64>,
    max_messages: Option<u64>,
    /// OPT-IN key compaction (#337): `--compact` turns it on (off by default). A bare boolean flag
    /// like `allow_unlimited_deliver`.
    compact: bool,
    max_groups: Option<usize>,
    group_idle_evict_ms: Option<u64>,
    /// The refuse-to-boot RAM ceiling in bytes (#115); `None` falls back to the profile preset (`0`
    /// = off for `balanced`/`throughput`, 64 MiB for `edge-tiny`). When set, the broker refuses to
    /// start if the worst-case bounded-buffer footprint provably exceeds it.
    ram_ceiling_bytes: Option<u64>,
    /// The COUNT bound on each per-producer dedup window (#33); `None` falls back to the default.
    dedup_max_ids: Option<usize>,
    /// The TIME bound on each per-producer dedup window in ms (#33); `None` falls back to the default.
    dedup_window_ms: Option<u64>,
    /// The cap on the NUMBER of distinct per-producer dedup windows (#33); `None` falls back to the
    /// default. Bounds the TOTAL dedup memory under a flood of distinct `producer_id`s.
    dedup_max_producers: Option<usize>,
    /// The durability LEVEL (#341, #379) selected by `--durability-level` / `IRONBUS_DURABILITY_LEVEL`.
    /// `None` resolves to the default `sync` (ack-implies-durable, I2, zero acked loss). An unknown
    /// name is a usage error.
    durability_level: Option<String>,
    /// The compression CODEC (#12, #387) selected by `--compression` / `IRONBUS_COMPRESSION`. `None`
    /// resolves to the default `lz4` (the ADR-0003 pure-Rust default codec). `none` stores every
    /// record raw; `zstd` is rejected on the default build. An unknown name is a usage error.
    compression: Option<String>,
    /// The `interval` level's TIME window in ms (#341); `None` falls back to the default.
    flush_interval_ms: Option<u64>,
    /// The `interval` level's unsynced-byte budget (#341); `None` falls back to the default.
    flush_max_bytes: Option<u64>,
    /// The explicit data-loss acknowledgement for `async`/`none` (#49, #379): the `--async-loss-ack`
    /// bare flag. `true` only if it appeared; without it, an `async`/`none` level refuses to boot.
    async_loss_ack: bool,
    disk_full_policy: Option<String>,
    visibility_ms: Option<u64>,
    enable_admin: bool,
    /// Turn ON the OTLP span export (#99, #352): the `--enable-otlp-export` bare flag. OFF by
    /// default. Honored only when the broker is built with the non-default `otlp` feature; on the
    /// default build, setting it logs a clear "built without otlp" diagnostic and export stays off.
    enable_otlp_export: bool,
    /// The OTLP collector endpoint (#352): `--otlp-endpoint <url>`, e.g. `http://127.0.0.1:4317`
    /// (plaintext gRPC). `None` falls back to the default endpoint when export is on. Read only when
    /// export is on AND the `otlp` feature is built in.
    otlp_endpoint: Option<String>,
    health_addr: Option<String>,
    /// The `/healthz` liveness hysteresis window in ms (#95); `None` falls back to the default.
    health_liveness_window_ms: Option<u64>,
    /// The fail-closed acknowledgement for a NON-LOOPBACK `--health-addr` (#95): the metrics/health
    /// surface is unauthenticated and unencrypted (TLS/#107 and auth/#106 are not wired), so a
    /// non-loopback bind refuses to start unless the operator sets this. A bare boolean flag.
    health_allow_public: bool,
    /// The CoDel TARGET in ms (#68); `None` falls back to the default (`0` = CoDel disabled).
    codel_target_ms: Option<u64>,
    /// The CoDel INTERVAL in ms (#68); `None` falls back to the default (100 ms).
    codel_interval_ms: Option<u64>,
    /// The per-client retry-budget ratio in parts-per-million (#69); `None` -> default (`0` = off).
    retry_budget_ratio_per_million: Option<u64>,
    /// The per-client retry-budget window in ms (#69); `None` -> default (60 s).
    retry_budget_window_ms: Option<u64>,
    /// The fire-and-forget token-bucket message rate in msg/s (#69); `None` -> default (`0` = off).
    fire_and_forget_msg_rate: Option<u64>,
    /// The fire-and-forget token-bucket byte rate in bytes/s (#69); `None` -> default (`0` = off).
    fire_and_forget_byte_rate: Option<u64>,
    /// The fire-and-forget token-bucket refill granularity in ms (#69); `None` -> default (100 ms).
    fire_and_forget_refill_ms: Option<u64>,
    /// The starting / static-floor egress concurrency limit (#69); `None` -> default (16).
    egress_limit: Option<u32>,
    /// The fsync-headroom admission window in BYTES (#378); `None` -> default (`0` = off).
    wal_fsync_headroom_bytes: Option<u64>,
    key_shared_groups: Vec<String>,
    broadcast_groups: Vec<String>,
}

/// Collects the `serve` arg list into [`ServeFlags`], each knob `Some` only if its flag appeared.
/// The env/default resolution is a separate pass so the precedence (flag > env > default) lives in
/// one place and the parse error for a bad FLAG value still names the flag (#89).
// One flat arm per `serve` flag: a single linear concern (the arg loop) that reads better unbroken
// than split across helpers, so the line count is allowed past the default ceiling.
#[allow(clippy::too_many_lines)]
fn collect_serve_flags(args: &[String]) -> Result<ServeFlags, CliError> {
    let mut f = ServeFlags::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => f.addr = Some(take_value("--addr", args, &mut i)?),
            "--data-dir" => f.data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--config" => f.config = Some(take_value("--config", args, &mut i)?),
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins.
            "--allow-unknown-config" => {
                f.allow_unknown_config = true;
                i += 1;
            }
            "--profile" => f.profile = Some(take_value("--profile", args, &mut i)?),
            "--max-connections" => {
                f.max_connections = Some(take_number("--max-connections", args, &mut i)?);
            }
            "--checkpoint-interval" => {
                f.checkpoint_interval = Some(take_number("--checkpoint-interval", args, &mut i)?);
            }
            "--max-deliver" => f.max_deliver = Some(take_number("--max-deliver", args, &mut i)?),
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins.
            "--allow-unlimited-deliver" => {
                f.allow_unlimited_deliver = true;
                i += 1;
            }
            // OPT-IN key compaction (#337), off by default: a bare boolean flag.
            "--compact" => {
                f.compact = true;
                i += 1;
            }
            "--backoff-ms" => {
                f.backoff_ms = Some(take_number_list("--backoff-ms", args, &mut i)?);
            }
            "--max-in-flight" => {
                f.max_in_flight = Some(take_number("--max-in-flight", args, &mut i)?);
            }
            "--consumer-credit" => {
                f.consumer_credit = Some(take_number("--consumer-credit", args, &mut i)?);
            }
            "--consumer-credit-bytes" => {
                f.consumer_credit_bytes =
                    Some(take_number("--consumer-credit-bytes", args, &mut i)?);
            }
            "--max-segment-bytes" => {
                f.max_segment_bytes = Some(take_number("--max-segment-bytes", args, &mut i)?);
            }
            "--max-total-bytes" => {
                f.max_total_bytes = Some(take_number("--max-total-bytes", args, &mut i)?);
            }
            "--max-retained-bytes" => {
                f.max_retained_bytes = Some(take_number("--max-retained-bytes", args, &mut i)?);
            }
            "--max-age-ms" => f.max_age_ms = Some(take_number("--max-age-ms", args, &mut i)?),
            "--max-messages" => {
                f.max_messages = Some(take_number("--max-messages", args, &mut i)?);
            }
            "--max-groups" => f.max_groups = Some(take_number("--max-groups", args, &mut i)?),
            "--group-idle-evict-ms" => {
                f.group_idle_evict_ms = Some(take_number("--group-idle-evict-ms", args, &mut i)?);
            }
            "--ram-ceiling-bytes" => {
                f.ram_ceiling_bytes = Some(take_number("--ram-ceiling-bytes", args, &mut i)?);
            }
            "--dedup-max-ids" => {
                f.dedup_max_ids = Some(take_number("--dedup-max-ids", args, &mut i)?);
            }
            "--dedup-window-ms" => {
                f.dedup_window_ms = Some(take_number("--dedup-window-ms", args, &mut i)?);
            }
            "--dedup-max-producers" => {
                f.dedup_max_producers = Some(take_number("--dedup-max-producers", args, &mut i)?);
            }
            "--disk-full-policy" => {
                f.disk_full_policy = Some(take_value("--disk-full-policy", args, &mut i)?);
            }
            "--durability-level" => {
                f.durability_level = Some(take_value("--durability-level", args, &mut i)?);
            }
            "--compression" => {
                f.compression = Some(take_value("--compression", args, &mut i)?);
            }
            "--flush-interval-ms" => {
                f.flush_interval_ms = Some(take_number("--flush-interval-ms", args, &mut i)?);
            }
            "--flush-max-bytes" => {
                f.flush_max_bytes = Some(take_number("--flush-max-bytes", args, &mut i)?);
            }
            // The backpressure controls (#68, #69). Each is opt-in: the resolver supplies the
            // disabling default when the flag is absent.
            "--codel-target-ms" => {
                f.codel_target_ms = Some(take_number("--codel-target-ms", args, &mut i)?);
            }
            "--codel-interval-ms" => {
                f.codel_interval_ms = Some(take_number("--codel-interval-ms", args, &mut i)?);
            }
            "--retry-budget-ratio-ppm" => {
                f.retry_budget_ratio_per_million =
                    Some(take_number("--retry-budget-ratio-ppm", args, &mut i)?);
            }
            "--retry-budget-window-ms" => {
                f.retry_budget_window_ms =
                    Some(take_number("--retry-budget-window-ms", args, &mut i)?);
            }
            "--fire-and-forget-msg-rate" => {
                f.fire_and_forget_msg_rate =
                    Some(take_number("--fire-and-forget-msg-rate", args, &mut i)?);
            }
            "--fire-and-forget-byte-rate" => {
                f.fire_and_forget_byte_rate =
                    Some(take_number("--fire-and-forget-byte-rate", args, &mut i)?);
            }
            "--fire-and-forget-refill-ms" => {
                f.fire_and_forget_refill_ms =
                    Some(take_number("--fire-and-forget-refill-ms", args, &mut i)?);
            }
            "--egress-limit" => {
                f.egress_limit = Some(take_number("--egress-limit", args, &mut i)?);
            }
            "--wal-fsync-headroom-bytes" => {
                f.wal_fsync_headroom_bytes =
                    Some(take_number("--wal-fsync-headroom-bytes", args, &mut i)?);
            }
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins. The
            // explicit data-loss acknowledgement that gates the unbounded-loss durability levels.
            "--async-loss-ack" => {
                f.async_loss_ack = true;
                i += 1;
            }
            "--key-shared-group" => {
                f.key_shared_groups
                    .push(take_value("--key-shared-group", args, &mut i)?);
            }
            "--broadcast-group" => {
                f.broadcast_groups
                    .push(take_value("--broadcast-group", args, &mut i)?);
            }
            "--visibility-timeout-ms" => {
                f.visibility_ms = Some(take_number("--visibility-timeout-ms", args, &mut i)?);
            }
            "--health-addr" => f.health_addr = Some(take_value("--health-addr", args, &mut i)?),
            "--health-liveness-window-ms" => {
                f.health_liveness_window_ms =
                    Some(take_number("--health-liveness-window-ms", args, &mut i)?);
            }
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins.
            "--health-allow-public" => {
                f.health_allow_public = true;
                i += 1;
            }
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins.
            "--enable-admin" => {
                f.enable_admin = true;
                i += 1;
            }
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins. Turns on
            // OTLP span export (#352); honored only on an `otlp`-featured build.
            "--enable-otlp-export" => {
                f.enable_otlp_export = true;
                i += 1;
            }
            "--otlp-endpoint" => {
                f.otlp_endpoint = Some(take_value("--otlp-endpoint", args, &mut i)?);
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for serve")))
            }
            other => {
                return Err(CliError::Usage(format!(
                    "serve takes no positional arguments, got `{other}`"
                )))
            }
        }
    }
    Ok(f)
}

/// Parses the `serve` flag list with NO env layer, resolving every unset knob to its compiled
/// default. The convenience entry for unit tests that assert flag parsing and defaults; production
/// goes through [`parse_serve_flags_with_env`] with the real process environment (#89).
#[cfg(test)]
fn parse_serve_flags(args: &[String]) -> Result<ParsedServe, CliError> {
    parse_serve_flags_with_env(args, &|_| None)
}

/// The whole-file reader the production `serve` path uses to load `--config`: a plain
/// read-to-string. Mapped to a typed reader-error string so the file layer's
/// [`config_file::ConfigFileError::Read`] names the path and the IO failure. Tests inject an
/// in-memory reader instead, so the file-precedence and strict-validation tests are deterministic.
fn fs_config_reader(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

/// Parses the `serve` flag list into a [`ParsedServe`], resolving each knob with the
/// `flag > env > FILE > default` precedence (#85, #89, #382): an explicit CLI flag wins, else the
/// `IRONBUS_<flag>` env var, else the `--config` TOML FILE value, else the compiled default. Reads
/// the config file (when `--config` is set) through the real filesystem; the
/// [`parse_serve_flags_with_env_and_reader`] variant takes an injected reader for deterministic
/// tests of the file layer.
///
/// # Errors
/// A [`CliError::Usage`] for a bad flag/env value, a broken/invalid config file, or a coupled-set
/// violation.
fn parse_serve_flags_with_env(args: &[String], env: &EnvFn<'_>) -> Result<ParsedServe, CliError> {
    parse_serve_flags_with_env_and_reader(args, env, &fs_config_reader)
}

/// Parses the `serve` flag list with an injected config-file reader, resolving each knob with the
/// flag > env > FILE > default precedence (#85, #89, #382): an explicit CLI flag wins, else the
/// `IRONBUS_<flag>` env var read through the injected `env` seam, else the `--config` TOML FILE
/// value (read through `read`), else the compiled default. A bad value at any layer is a usage
/// error NAMING ITS SOURCE, exactly like a bad flag. Split into a flag-collection pass
/// ([`collect_serve_flags`]) and this resolution pass so the precedence lives in one place.
///
/// The FILE layer is inserted by COMPOSING the env seam: a combined `env-then-file` closure returns
/// the env value if set, else the file value, so the existing `flag > env > default` resolvers gain
/// the file layer with NO change to their relative order (a flag still beats env, env still beats
/// the file, the file still beats the default). With no `--config`, no file is read and the
/// resolution is byte-for-byte the historical flag > env > default.
///
/// # Errors
/// A [`CliError::Usage`] for a bad flag/env value, a broken/invalid config file (with path +
/// line/column), an unknown config key (unless `--allow-unknown-config`), or a coupled-set violation.
// One `resolve_*` call per knob: a single linear concern (resolve every flag against env/file/
// default) that reads better as one flat block than split across helpers, so the line count is
// allowed past the default ceiling, like `collect_serve_flags`.
#[allow(clippy::too_many_lines)]
fn parse_serve_flags_with_env_and_reader(
    args: &[String],
    env: &EnvFn<'_>,
    read: &dyn Fn(&str) -> Result<String, String>,
) -> Result<ParsedServe, CliError> {
    let f = collect_serve_flags(args)?;
    // Load the `--config` FILE layer (#85, #382), if any. It is read, parsed, and strictly
    // validated BEFORE any knob resolves; a broken/invalid file is a fatal usage error here, so the
    // broker never half-applies a config. With no `--config`, `file_layer` is `None` and the
    // resolution below is the historical flag > env > default, byte-for-byte.
    let file_layer = match &f.config {
        Some(path) => Some(
            config_file::load_config_file(path, f.allow_unknown_config, read)
                .map_err(|e| CliError::Usage(e.to_string()))?,
        ),
        None => None,
    };
    // The combined env-then-file seam: env BEATS the file (env is the higher layer), so look env up
    // first and fall back to the file value. The existing `resolve_*` helpers consult THIS, so the
    // precedence becomes flag > env > FILE > default with no change to their internal logic.
    let combined = |name: &str| -> Option<String> {
        env(name).or_else(|| file_layer.as_ref().and_then(|fl| fl.lookup_env_name(name)))
    };
    let env: &EnvFn<'_> = &combined;
    // The named profile (#87) is resolved FIRST (flag > env), then its preset supplies the per-knob
    // DEFAULT for every knob below, so an explicit env var or flag for any knob still wins: the
    // effective precedence is profile < env < flag. No `--profile` (and no `IRONBUS_PROFILE`)
    // resolves to `balanced`, whose preset IS the compiled `DEFAULT_*` set, so zero-config behavior
    // is byte-identical to a broker that predates this flag. An unknown name is a usage error naming
    // its source and the accepted values.
    let profile_from_flag = f.profile.is_some();
    let profile = match resolve_opt_string("--profile", f.profile, env) {
        Some(raw) => Profile::parse(&raw).ok_or_else(|| {
            let source = if profile_from_flag {
                "--profile".to_string()
            } else {
                env_var_name("--profile")
            };
            CliError::Usage(format!(
                "`{source}` must be `edge-tiny`, `balanced`, or `throughput`, got `{raw}`"
            ))
        })?,
        None => Profile::DEFAULT,
    };
    let preset = profile.preset();
    // The disk-full policy is an enum string, so it resolves like a string but is then parsed: name
    // the source (the flag if it was explicit, else the env var) in a bad-value error so the
    // operator knows where it came from. The profile preset supplies the DEFAULT when neither flag
    // nor env set it, so e.g. `throughput` defaults to `drop-oldest` (still overridable).
    let policy_from_flag = f.disk_full_policy.is_some();
    let disk_full_policy_arg = resolve_string(
        "--disk-full-policy",
        f.disk_full_policy,
        env,
        preset.disk_full_policy.as_str(),
    );
    let disk_full_policy = DiskFullPolicyArg::parse(&disk_full_policy_arg).ok_or_else(|| {
        let source = if policy_from_flag {
            "--disk-full-policy".to_string()
        } else {
            env_var_name("--disk-full-policy")
        };
        CliError::Usage(format!(
            "`{source}` must be `drop-new` or `drop-oldest`, got `{disk_full_policy_arg}`"
        ))
    })?;
    // The durability LEVEL (#341, #379) resolves like the disk-full policy: an enum string with
    // flag > env > default (`sync`) precedence, parsed after resolution so a bad value names its
    // source (the flag if explicit, else the env var). The default `sync` keeps the historical
    // power-loss-safe broker; the relaxed levels are strictly opt-in.
    let level_from_flag = f.durability_level.is_some();
    let durability_level_arg = resolve_string(
        "--durability-level",
        f.durability_level,
        env,
        DEFAULT_DURABILITY_LEVEL,
    );
    let durability_level = DurabilityLevelArg::parse(&durability_level_arg).ok_or_else(|| {
        let source = if level_from_flag {
            "--durability-level".to_string()
        } else {
            env_var_name("--durability-level")
        };
        CliError::Usage(format!(
            "`{source}` must be `sync`, `interval`, `async`, or `none`, got `{durability_level_arg}`"
        ))
    })?;
    // The compression CODEC (#12, #387) resolves like the disk-full policy: an enum string with
    // flag > env > default (`lz4`) precedence, parsed after resolution so a bad value names its
    // source (the flag if explicit, else the env var). `zstd` is rejected here on the default build
    // (it is the deferred opt-in feature), so an operator asking for it gets a clear usage error.
    let compression_from_flag = f.compression.is_some();
    let compression_arg = resolve_string("--compression", f.compression, env, DEFAULT_COMPRESSION);
    let compression = CompressionArg::parse(&compression_arg).ok_or_else(|| {
        let source = if compression_from_flag {
            "--compression".to_string()
        } else {
            env_var_name("--compression")
        };
        CliError::Usage(format!(
            "`{source}` must be `none` or `lz4` (zstd is a deferred opt-in feature, not available \
             on this build), got `{compression_arg}`"
        ))
    })?;
    let mut parsed = ParsedServe {
        addr: resolve_string("--addr", f.addr, env, DEFAULT_ADDR),
        data_dir: resolve_opt_string("--data-dir", f.data_dir, env),
        config: ServeConfig {
            // The active profile and its schema version are carried into the materialized config so
            // `cmd_serve` can log them; the per-knob values below take the PRESET as their default,
            // overridable by env/flag (profile < env < flag).
            profile,
            profile_schema_version: PROFILE_SCHEMA_VERSION,
            max_connections: resolve_number(
                "--max-connections",
                f.max_connections,
                env,
                preset.max_connections,
            )?,
            checkpoint_interval: resolve_number(
                "--checkpoint-interval",
                f.checkpoint_interval,
                env,
                preset.checkpoint_interval,
            )?,
            max_deliver: resolve_number("--max-deliver", f.max_deliver, env, preset.max_deliver)?,
            allow_unlimited_deliver: resolve_bool(
                "--allow-unlimited-deliver",
                f.allow_unlimited_deliver,
                env,
            )?,
            backoff_ms: resolve_number_list("--backoff-ms", f.backoff_ms, env)?,
            max_in_flight: resolve_number(
                "--max-in-flight",
                f.max_in_flight,
                env,
                preset.max_in_flight,
            )?,
            consumer_credit: resolve_number(
                "--consumer-credit",
                f.consumer_credit,
                env,
                preset.consumer_credit,
            )?,
            consumer_credit_bytes: resolve_number(
                "--consumer-credit-bytes",
                f.consumer_credit_bytes,
                env,
                preset.consumer_credit_bytes,
            )?,
            max_segment_bytes: resolve_number(
                "--max-segment-bytes",
                f.max_segment_bytes,
                env,
                preset.max_segment_bytes,
            )?,
            max_total_bytes: resolve_number(
                "--max-total-bytes",
                f.max_total_bytes,
                env,
                DEFAULT_MAX_TOTAL_BYTES,
            )?,
            max_retained_bytes: resolve_number(
                "--max-retained-bytes",
                f.max_retained_bytes,
                env,
                DEFAULT_MAX_RETAINED_BYTES,
            )?,
            max_age_ms: resolve_number("--max-age-ms", f.max_age_ms, env, DEFAULT_MAX_AGE_MS)?,
            max_messages: resolve_number(
                "--max-messages",
                f.max_messages,
                env,
                DEFAULT_MAX_MESSAGES,
            )?,
            // OPT-IN key compaction (#337), OFF by default: not a profile preset (it is a per-topic
            // changelog policy), so it resolves from the `--compact` flag / `IRONBUS_COMPACT` env only.
            compact: resolve_bool("--compact", f.compact, env)?,
            max_groups: resolve_number("--max-groups", f.max_groups, env, preset.max_groups)?,
            group_idle_evict_ms: resolve_number(
                "--group-idle-evict-ms",
                f.group_idle_evict_ms,
                env,
                DEFAULT_GROUP_IDLE_EVICT_MS,
            )?,
            // The refuse-to-boot RAM ceiling (#115): the profile preset supplies the default (0 = off
            // for balanced/throughput, 64 MiB for edge-tiny), still overridable by env/flag, so an
            // operator can set the ceiling to the device/cgroup limit or override the edge-tiny one.
            ram_ceiling_bytes: resolve_number(
                "--ram-ceiling-bytes",
                f.ram_ceiling_bytes,
                env,
                preset.ram_ceiling_bytes,
            )?,
            disk_full_policy,
            visibility_ms: resolve_number(
                "--visibility-timeout-ms",
                f.visibility_ms,
                env,
                preset.visibility_ms,
            )?,
            enable_admin: resolve_bool("--enable-admin", f.enable_admin, env)?,
            // OTLP span export (#352): off by default; the endpoint has no compiled default (falls
            // back in the server crate when on). flag > env > default, exactly like the other knobs.
            enable_otlp_export: resolve_bool("--enable-otlp-export", f.enable_otlp_export, env)?,
            otlp_endpoint: resolve_opt_string("--otlp-endpoint", f.otlp_endpoint, env),
            health_liveness_window_ms: resolve_number(
                "--health-liveness-window-ms",
                f.health_liveness_window_ms,
                env,
                DEFAULT_HEALTH_LIVENESS_WINDOW_MS,
            )?,
            health_allow_public: resolve_bool("--health-allow-public", f.health_allow_public, env)?,
            dedup_max_ids: resolve_number(
                "--dedup-max-ids",
                f.dedup_max_ids,
                env,
                DEFAULT_DEDUP_MAX_IDS,
            )?,
            dedup_window_ms: resolve_number(
                "--dedup-window-ms",
                f.dedup_window_ms,
                env,
                DEFAULT_DEDUP_WINDOW_MS,
            )?,
            dedup_max_producers: resolve_number(
                "--dedup-max-producers",
                f.dedup_max_producers,
                env,
                DEFAULT_DEDUP_MAX_PRODUCERS,
            )?,
            // The durability level and its interval triggers (#341, #379). The level is resolved
            // above (flag > env > default `sync`); the interval triggers take their defaults when not
            // set, overridable by env/flag. `async`/`none` are gated behind `--async-loss-ack` in
            // `validate_serve_config`, never reachable by accident.
            durability_level,
            // The compression codec (#12, #387); default `lz4` per ADR-0003, `none` stores raw.
            compression,
            flush_interval_ms: resolve_number(
                "--flush-interval-ms",
                f.flush_interval_ms,
                env,
                DEFAULT_FLUSH_INTERVAL_MS,
            )?,
            flush_max_bytes: resolve_number(
                "--flush-max-bytes",
                f.flush_max_bytes,
                env,
                DEFAULT_FLUSH_MAX_BYTES,
            )?,
            async_loss_ack: resolve_bool("--async-loss-ack", f.async_loss_ack, env)?,
            // The backpressure controls (#68, #69). Every knob DEFAULTS to its disabling value, so a
            // zero-config broker behaves exactly as today; an operator opts in per knob. CoDel and the
            // retry budget and the fire-and-forget bucket default OFF; the egress limiter defaults to
            // its floor (16) and is always bounded to [4, 128].
            codel_target_ms: resolve_number(
                "--codel-target-ms",
                f.codel_target_ms,
                env,
                DEFAULT_CODEL_TARGET_MS,
            )?,
            codel_interval_ms: resolve_number(
                "--codel-interval-ms",
                f.codel_interval_ms,
                env,
                DEFAULT_CODEL_INTERVAL_MS,
            )?,
            retry_budget_ratio_per_million: resolve_number(
                "--retry-budget-ratio-ppm",
                f.retry_budget_ratio_per_million,
                env,
                DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION,
            )?,
            retry_budget_window_ms: resolve_number(
                "--retry-budget-window-ms",
                f.retry_budget_window_ms,
                env,
                DEFAULT_RETRY_BUDGET_WINDOW_MS,
            )?,
            fire_and_forget_msg_rate: resolve_number(
                "--fire-and-forget-msg-rate",
                f.fire_and_forget_msg_rate,
                env,
                DEFAULT_FIRE_AND_FORGET_MSG_RATE,
            )?,
            fire_and_forget_byte_rate: resolve_number(
                "--fire-and-forget-byte-rate",
                f.fire_and_forget_byte_rate,
                env,
                DEFAULT_FIRE_AND_FORGET_BYTE_RATE,
            )?,
            fire_and_forget_refill_ms: resolve_number(
                "--fire-and-forget-refill-ms",
                f.fire_and_forget_refill_ms,
                env,
                DEFAULT_FIRE_AND_FORGET_REFILL_MS,
            )?,
            egress_limit: resolve_number(
                "--egress-limit",
                f.egress_limit,
                env,
                DEFAULT_EGRESS_LIMIT,
            )?,
            // The fsync-headroom admission window (#378), flag > env > default `0` (OFF), so a
            // zero-config broker is unchanged; a non-zero value bounds the un-fsynced write frontier.
            wal_fsync_headroom_bytes: resolve_number(
                "--wal-fsync-headroom-bytes",
                f.wal_fsync_headroom_bytes,
                env,
                DEFAULT_WAL_FSYNC_HEADROOM_BYTES,
            )?,
        },
        key_shared_groups: f.key_shared_groups,
        broadcast_groups: f.broadcast_groups,
        health_addr: resolve_opt_string("--health-addr", f.health_addr, env),
        // Seeded below from the file layer (warnings + the explicit-retention-request flag);
        // empty/false with no `--config`, so the zero-config path carries nothing new.
        config_warnings: Vec::new(),
        retention_requested: false,
        config_path: f.config.clone(),
        allow_unknown_config: f.allow_unknown_config,
    };
    // Fold in the FILE layer's non-fatal warnings and its explicit-retention-request flag, then run
    // the WHOLE-config coupled-set validation as a UNIT (#86, #382, docs/CONFIG.md section 4): every
    // cross-key rule, collected at once. A fatal violation is a usage error here (the broker never
    // half-applies a config); the warnings are surfaced by `cmd_serve`. The per-flag range checks
    // (validate_serve_config) still run later in finish_serve; this adds the cross-key set.
    if let Some(fl) = &file_layer {
        parsed.config_warnings.extend(fl.warnings().iter().cloned());
        parsed.retention_requested = fl.retention_requested();
    }
    let verdict = coupled_set_verdict(&parsed.config, parsed.retention_requested);
    if let Some(first) = verdict.errors.first() {
        return Err(CliError::Usage(format!("config error: {first}")));
    }
    parsed
        .config_warnings
        .extend(verdict.warnings.iter().cloned());
    Ok(parsed)
}

/// Builds the IO-free [`ironbus_core::config::ResolvedConfig`] view from the assembled
/// [`ServeConfig`] and runs the whole-config coupled-set validation (#86, #382). The max-record /
/// frame-overhead floor uses the compiled record-format constants (the largest record the broker
/// accepts and the per-record header), so the segment-fit rule is checked against the real format.
/// `retention_requested` is true only when the operator EXPLICITLY asked for retention (set a
/// retention key in the config FILE), so the "retention requested but all off" rule fires only then.
fn coupled_set_verdict(
    config: &ServeConfig,
    retention_requested: bool,
) -> ironbus_core::config::ConfigVerdict {
    ironbus_core::config::validate_coupled_sets(&resolved_view(config, retention_requested))
}

/// Builds the IO-free [`ironbus_core::config::ResolvedConfig`] cross-key view from the assembled
/// [`ServeConfig`], the neutral struct both the coupled-set validator and the reload engine read.
/// The max-record / frame-overhead floor uses the compiled record-format constants, so the
/// segment-fit rule is checked against the real on-disk format.
fn resolved_view(
    config: &ServeConfig,
    retention_requested: bool,
) -> ironbus_core::config::ResolvedConfig {
    ironbus_core::config::ResolvedConfig {
        segment_bytes: config.max_segment_bytes,
        // `max_record_bytes = 0`: there is no configurable per-record CAP knob today (the shipped
        // storage writes an oversized record to its OWN segment, so a segment is NOT required to
        // exceed the 16 MiB record-format ceiling, which would wrongly reject the valid 8 MiB
        // `edge-tiny` segment). The segment-fit coupled-set rule is wired in the core validator and
        // fires the moment a `storage.max_record_bytes` knob lands; until then `0` skips it and the
        // shipped `>= MIN_MAX_SEGMENT_BYTES` floor (checked in `validate_serve_config`) is the bound.
        max_record_bytes: 0,
        frame_overhead: ironbus_core::format::RECORD_HEADER_LEN as u64,
        durability_level: map_durability_level(config.durability_level),
        flush_interval_ms: config.flush_interval_ms,
        flush_max_bytes: config.flush_max_bytes,
        async_loss_ack: config.async_loss_ack,
        max_retained_bytes: config.max_retained_bytes,
        max_age_ms: config.max_age_ms,
        max_messages: config.max_messages,
        retention_requested,
        max_total_bytes: config.max_total_bytes,
        disk_full_policy_drop_oldest: matches!(
            config.disk_full_policy,
            DiskFullPolicyArg::DropOldest
        ),
        // The durability none/async gate and the interval-trigger check are the shipped
        // `validate_durability`'s job (it runs first in `validate_serve_config` with the canonical
        // operator messages), so the coupled-set validator does NOT re-run them here.
        enforce_durability_gate: false,
    }
}

/// Builds the immutable [`config_reload::EffectiveConfig`] snapshot the [`config_reload::ConfigHandle`]
/// holds: the resolved cross-key view plus the COLD keys (`docs/CONFIG.md` section 3) whose change a
/// live reload must reject atomically. The COLD keys are the layout-affecting / open-time-immutable
/// ones: the segment size and the data dir (both COLD, changing them live could strand segments).
fn build_effective_config(
    config: &ServeConfig,
    data_dir: &Path,
    retention_requested: bool,
) -> config_reload::EffectiveConfig {
    // The COLD-key values, keyed off the classified `config_reload::COLD_KEYS` set so the two
    // never drift: each cold key's current value, for the reload's cold-key-change comparison.
    let cold_keys = config_reload::COLD_KEYS
        .iter()
        .map(|(key, _class)| {
            let value = match *key {
                "storage.segment_size" => config.max_segment_bytes.to_string(),
                "storage.data_dir" => data_dir.display().to_string(),
                // Unreachable: COLD_KEYS lists only the two above; a new cold key must add its arm.
                other => {
                    debug_assert!(false, "unhandled cold key `{other}`");
                    String::new()
                }
            };
            (*key, value)
        })
        .collect();
    config_reload::EffectiveConfig {
        cold_keys,
        resolved: resolved_view(config, retention_requested),
    }
}

/// Re-reads the `--config` file and attempts an atomic RELOAD (#380, #382): it builds a candidate
/// immutable config from the freshly re-read file (the COLD keys and the cross-key view), then asks
/// the handle to validate it fully, reject a cold-key change atomically, and swap ONLY on success.
/// A broken or unreadable re-read, or a cold-key change, leaves the running config UNCHANGED; the
/// outcome is logged to the broker's startup output. Auth-free: it re-reads a LOCAL file and swaps
/// only the in-process pointer (never an unauthenticated remote mutation).
///
/// The candidate's reloadable fields take the re-read FILE value where the file sets them, else the
/// currently-running value, so re-reading an UNEDITED file is a no-op `Applied` (the candidate
/// equals current), while an edited COLD key (e.g. `storage.segment_size`) is caught and rejected.
#[cfg(unix)]
fn reload_effective_config(
    handle: &config_reload::ConfigHandle,
    path: &str,
    allow_unknown: bool,
    current: &ServeConfig,
    data_dir: &Path,
    out: &mut impl Write,
) {
    let layer = match config_file::load_config_file(path, allow_unknown, &fs_config_reader) {
        Ok(layer) => layer,
        Err(e) => {
            // A broken/unreadable re-read keeps the running config; log and return (no swap).
            let _ = writeln!(out, "WARN: config reload rejected (re-read failed): {e}");
            return;
        }
    };
    // The candidate segment size: the re-read file value (parsed by the env-name layer back to a
    // plain integer) if the file set it, else the currently-running value. The same single source
    // the startup resolver used, so an unedited file yields the identical value (a no-op reload).
    let candidate_segment = layer
        .lookup_env_name("IRONBUS_MAX_SEGMENT_BYTES")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(current.max_segment_bytes);
    let mut candidate = build_effective_config(current, data_dir, layer.retention_requested());
    candidate.resolved.segment_bytes = candidate_segment;
    candidate.cold_keys = vec![
        ("storage.segment_size", candidate_segment.to_string()),
        ("storage.data_dir", data_dir.display().to_string()),
    ];
    let outcome = handle.reload_from(candidate);
    debug_assert!(
        outcome.applied(),
        "re-reading the unedited startup config must be a no-op Applied reload",
    );
    match outcome {
        config_reload::ReloadOutcome::Applied { warnings } => {
            let _ = writeln!(out, "config reload applied (re-read {path})");
            for w in warnings {
                let _ = writeln!(out, "WARN: config reload: {w}");
            }
        }
        config_reload::ReloadOutcome::Rejected { reasons } => {
            for r in reasons {
                let _ = writeln!(out, "WARN: config reload rejected (config unchanged): {r}");
            }
        }
    }
}

/// Maps the CLI's durability-arg enum onto the IO-free core's [`ironbus_core::config::DurabilityLevel`]
/// the coupled-set validator reasons about, so the cross-key durability checks live in the pure core.
fn map_durability_level(level: DurabilityLevelArg) -> ironbus_core::config::DurabilityLevel {
    match level {
        DurabilityLevelArg::Sync => ironbus_core::config::DurabilityLevel::Sync,
        DurabilityLevelArg::Interval => ironbus_core::config::DurabilityLevel::Interval,
        DurabilityLevelArg::Async => ironbus_core::config::DurabilityLevel::Async,
        DurabilityLevelArg::None => ironbus_core::config::DurabilityLevel::None,
    }
}

/// Resolves the required `--data-dir`, validates the assembled config, and dispatches to the
/// platform `cmd_serve`. Split out of `run_serve` so the flag-parsing loop stays a single concern.
#[allow(clippy::too_many_arguments)] // each input (addr, data dir, config, groups, health, the
                                     // config-file warnings, out) is a distinct concern; bundling
                                     // them into a struct would only move the noise, not remove it.
fn finish_serve(
    addr: &str,
    data_dir: Option<&str>,
    config: &ServeConfig,
    key_shared_groups: &[String],
    broadcast_groups: &[String],
    health_addr: Option<&str>,
    config_warnings: &[String],
    reload: ReloadSource<'_>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("serve requires `--data-dir <dir>`".to_string()))?;
    validate_serve_config(config)?;
    cmd_serve(
        addr,
        Path::new(data_dir),
        config,
        key_shared_groups,
        broadcast_groups,
        health_addr,
        config_warnings,
        reload,
        out,
    )
}

/// Rejects an out-of-range `serve` tuning value with a usage error before the broker opens.
fn validate_serve_config(config: &ServeConfig) -> Result<(), CliError> {
    if config.max_connections == 0 {
        // A zero cap binds and looks healthy but refuses every connection: reject it.
        return Err(CliError::Usage(
            "`--max-connections` must be at least 1".to_string(),
        ));
    }
    if (config.max_deliver == 0 || config.max_deliver == u32::MAX)
        && !config.allow_unlimited_deliver
    {
        // Both 0 and u32::MAX mean unlimited delivery (the lease counter saturates at the max,
        // so a poison message loops forever). Unlimited is reachable but must be DELIBERATE: it is
        // allowed only behind `--allow-unlimited-deliver` (which also emits a startup WARN, see
        // `cmd_serve`), else it is a usage error before the broker opens (#63).
        return Err(CliError::Usage(
            "`--max-deliver` must be at least 1 and below 4294967295 (0 and that maximum both \
             mean unlimited delivery; pass `--allow-unlimited-deliver` to enable it deliberately)"
                .to_string(),
        ));
    }
    if config.max_in_flight == 0 {
        // A zero window delivers nothing; the engine rejects it, so catch it as a usage error.
        return Err(CliError::Usage(
            "`--max-in-flight` must be at least 1".to_string(),
        ));
    }
    if config.consumer_credit == 0 {
        // A zero per-consumer credit would deliver nothing to any connection (#65). The engine
        // floors it to 1, but reject it loudly here so a typo is caught before the broker opens
        // rather than silently behaving as a credit of 1.
        return Err(CliError::Usage(
            "`--consumer-credit` must be at least 1".to_string(),
        ));
    }
    if config.max_segment_bytes < MIN_MAX_SEGMENT_BYTES {
        return Err(CliError::Usage(format!(
            "`--max-segment-bytes` must be at least {MIN_MAX_SEGMENT_BYTES} (smaller caps make \
             segments proliferate one record at a time)"
        )));
    }
    if config.visibility_ms == 0 {
        // A zero visibility timeout makes every delivered message instantly redeliverable,
        // a hot redelivery loop; require a positive window.
        return Err(CliError::Usage(
            "`--visibility-timeout-ms` must be at least 1".to_string(),
        ));
    }
    validate_durability(config)?;
    validate_ram_ceiling(config)?;
    Ok(())
}

/// The FAIL-CLOSED durability safety gate (#49, #341, #379): the none/async data-loss acknowledgement
/// and the `interval`-window sanity check, both BEFORE the broker opens.
///
/// - The unbounded-loss levels (`async`, `none`) WAIVE I2 with no loss ceiling, so they REFUSE TO
///   BOOT unless `--async-loss-ack` (the explicit `i-accept-acknowledged-data-loss` acknowledgement)
///   is set. This is the #49/#379 none-safety gate: a relaxed durability that loses acked data is
///   never reachable by a bare flag, only by an operator who explicitly accepted the loss. `sync` (the
///   default) and `interval` (bounded loss) need no acknowledgement.
/// - The `interval` level must have at least ONE positive trigger (`--flush-interval-ms` or
///   `--flush-max-bytes`): with both at `0` the window would never force a sync, silently degrading
///   `interval` to the unbounded `async` behavior WITHOUT the data-loss acknowledgement, which would
///   defeat the bound the operator chose. Rejected here so a misconfigured `interval` cannot become an
///   unannounced unbounded-loss broker.
///
/// # Errors
/// [`CliError::Usage`] (exit 1, before any listener opens) for a gated level without the
/// acknowledgement, or an `interval` level with no positive trigger.
fn validate_durability(config: &ServeConfig) -> Result<(), CliError> {
    if config.durability_level.requires_loss_ack() && !config.async_loss_ack {
        // Fail closed: an unbounded-loss level needs the explicit acknowledgement. The error names
        // the level, the waived invariant, the worst-case loss, and the flag to set, so the operator
        // knows exactly what they are turning off and how to confirm it.
        return Err(CliError::Usage(format!(
            "refusing to start with `--durability-level {level}`: it WAIVES I2 (ack-implies-durable) \
             with an UNBOUNDED loss window (every record acked since the last segment roll or clean \
             shutdown can be lost on a power cut). This is contrary to IronBus's power-loss-safe \
             default (`sync`). To enable it deliberately, pass `--async-loss-ack` to acknowledge that \
             acknowledged data can be lost (a loud startup warning is then logged on every boot). The \
             safe default needs no acknowledgement; `interval` carries a BOUNDED, operator-chosen loss \
             window and is not gated by this flag.",
            level = config.durability_level.as_str()
        )));
    }
    if config.durability_level == DurabilityLevelArg::Interval
        && config.flush_interval_ms == 0
        && config.flush_max_bytes == 0
    {
        // Both triggers off would make the window never fire, silently turning `interval` into the
        // unbounded `async` behavior without the data-loss acknowledgement. Require at least one.
        return Err(CliError::Usage(
            "`--durability-level interval` needs at least one positive flush trigger: set \
             `--flush-interval-ms` (a time window) and/or `--flush-max-bytes` (an unsynced-byte \
             budget) above 0, so the worst-case loss stays bounded. With both at 0 the window would \
             never force an fdatasync, silently degrading `interval` to the unbounded `async` \
             behavior."
                .to_string(),
        ));
    }
    Ok(())
}

/// The REFUSE-TO-BOOT RAM guard (#115, #19, #10): when `--ram-ceiling-bytes` is set (non-zero), the
/// broker refuses to start if the WORST-CASE bounded-buffer footprint the configured caps imply
/// PROVABLY exceeds the ceiling. The verdict is a pure function of the config (no live RSS, which at
/// boot is near-zero and meaningless as a steady-state predictor): it sums the bounded RAM sources
/// `docs/RAM_BUDGET.md` itemizes, each at its CONFIGURED cap, so a refusal is a proof from the config
/// that the caps cannot fit, not a guess. The error names the worst case, the ceiling, the overage,
/// and the knobs that drive it, so an operator knows exactly which cap to lower. `0` (the default for
/// `balanced`/`throughput`) disables the guard; `edge-tiny`'s 64 MiB ceiling fits (~15 MiB worst
/// case) but a blown-up cap override (e.g. a server-sized `--max-connections`) is refused here.
fn validate_ram_ceiling(config: &ServeConfig) -> Result<(), CliError> {
    // `usize` -> `u64` is lossless on every supported (32/64-bit) target; the saturating fallback is
    // belt-and-braces so a hypothetical >u64 platform could only ever make the worst case LARGER (more
    // likely to refuse), never spuriously fit.
    let footprint = ironbus_server::rss::RamFootprintConfig {
        ram_ceiling_bytes: config.ram_ceiling_bytes,
        max_connections: u64::try_from(config.max_connections).unwrap_or(u64::MAX),
        consumer_credit: u64::from(config.consumer_credit),
        consumer_credit_bytes: config.consumer_credit_bytes,
        max_groups: u64::try_from(config.max_groups).unwrap_or(u64::MAX),
        max_in_flight: u64::from(config.max_in_flight),
    };
    match ironbus_server::rss::fits_under_ram_ceiling(&footprint) {
        ironbus_server::rss::RamCeilingVerdict::Disabled
        | ironbus_server::rss::RamCeilingVerdict::Fits { .. } => Ok(()),
        ironbus_server::rss::RamCeilingVerdict::Exceeds {
            worst_case_bytes,
            ceiling_bytes,
            overage_bytes,
        } => Err(CliError::Usage(format!(
            "`--ram-ceiling-bytes` {ceiling_bytes} is below the worst-case bounded-buffer footprint \
             {worst_case_bytes} the configured caps imply (over by {overage_bytes} bytes): the \
             broker cannot prove it stays under the ceiling, so it refuses to boot. Lower \
             `--max-connections` ({max_connections}), `--consumer-credit-bytes` \
             ({consumer_credit_bytes}; 0 = unlimited, which cannot fit a small ceiling), \
             `--consumer-credit` ({consumer_credit}), `--max-groups` ({max_groups}), or \
             `--max-in-flight` ({max_in_flight}), or raise the ceiling. See docs/RAM_BUDGET.md for \
             the worst-case formula.",
            max_connections = config.max_connections,
            consumer_credit_bytes = config.consumer_credit_bytes,
            consumer_credit = config.consumer_credit,
            max_groups = config.max_groups,
            max_in_flight = config.max_in_flight,
        ))),
    }
}

/// The broker tuning knobs parsed from the `serve` flags.
// Not `Copy`: `backoff_ms` is a `Vec`. The config is moved (never re-used after the move) through
// `finish_serve`/`cmd_serve`, so `Clone` suffices. `Debug` lets a test assert on a `ParsedServe`.
// The four bools mirror four independent operator opt-ins (--allow-unlimited-deliver, --enable-admin,
// --health-allow-public, --async-loss-ack); each is a distinct safety/feature toggle, not a packed
// state, so a flat config of toggles is the right shape rather than an enum.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
struct ServeConfig {
    /// The compiled-in named profile (#87) the knobs below were resolved against, applied first and
    /// then overridden by any explicit env var or flag (profile < env < flag). Default `balanced`
    /// (the shipped `DEFAULT_*` set). Carried here only so the materialized-config startup log can
    /// report which profile is active; it does not re-influence the already-resolved knobs.
    profile: Profile,
    /// The [`PROFILE_SCHEMA_VERSION`] the broker was compiled against (#87), recorded in the
    /// materialized-config log so a profile content change across an upgrade is a visible, versioned
    /// event rather than a silent fleet-wide drift.
    profile_schema_version: u32,
    max_connections: usize,
    checkpoint_interval: u64,
    max_deliver: u32,
    /// Allow `--max-deliver 0` (unlimited delivery, refs #63). A poison message under an unlimited
    /// cap redelivers forever, so it is opt-in: without this flag a zero (or `u32::MAX`) cap is a
    /// usage error; with it, the broker starts and emits a startup WARN.
    allow_unlimited_deliver: bool,
    /// The escalating per-attempt nack backoff schedule in MILLISECONDS (refs #63), indexed by
    /// delivery attempt and clamped to the last entry. Applied when a nack carries no explicit
    /// delay, so a flapping consumer backs off instead of hot-looping a retry. Empty means use the
    /// built-in [`DEFAULT_NACK_BACKOFF_NANOS`] schedule; a single `0` disables backoff (retry as
    /// soon as the visibility timeout allows).
    backoff_ms: Vec<u64>,
    max_in_flight: u32,
    /// Per-CONSUMER (per-connection) standing in-flight credit (#65): the most un-acked messages one
    /// connection may hold at once, the consumer-side half of credit-based flow control. The
    /// effective Flow bound is min(this, the per-group `max_in_flight` window). Default 64 (NOT
    /// 65535), floored to 1 by the engine.
    consumer_credit: u32,
    /// Per-CONSUMER (per-connection) standing in-flight BYTE budget (#275): the most un-acked
    /// payload bytes one connection may hold at once, the RAM-side companion to `consumer_credit`.
    /// The effective Flow bound is min(message credit, byte budget) with a hard floor of one message
    /// (a single over-budget message is still delivered so it never wedges the consumer). Default
    /// 8 MiB; `0` = unlimited (the byte budget is off, only the message credit binds).
    consumer_credit_bytes: u64,
    max_segment_bytes: u64,
    /// Hard durable-log total byte cap, the drop-new shed backstop (#10). `0` means unlimited
    /// (the cap is off), which is the default and preserves the spill-by-default behavior.
    max_total_bytes: u64,
    /// Consumer-safe size-retention bound (#13, #80): the broker reaps old fully-consumed sealed
    /// segments while the durable log is over this many RECORD bytes. `0` means unlimited
    /// (retention off), the default, so existing behavior is unchanged.
    max_retained_bytes: u64,
    /// Consumer-safe AGE-retention bound (#13, #80), in MILLISECONDS: the broker reaps an old
    /// fully-consumed sealed segment whose newest record is older than this. `0` = disabled, the
    /// default. Milliseconds (not a duration string) so the flag is a bare integer.
    max_age_ms: u64,
    /// Consumer-safe COUNT-retention bound (#13, #80): the broker reaps old fully-consumed sealed
    /// segments while the log's total record count is over this many messages. `0` = disabled,
    /// the default.
    max_messages: u64,
    /// OPT-IN key-based log compaction (#337), OFF by default. When `true` the broker enables the
    /// off-hot-path compactor: after each produce-path reaper run it runs one rate-limited pass over
    /// a run of adjacent dirty SEALED segments, rewriting the survivors (the latest record per key,
    /// keeping their ORIGINAL sparse offsets) into a fresh v2 compacted segment. It is for
    /// changelog / state-snapshot topics where only the latest value per key matters, and it costs
    /// CPU + flash, so a general durable queue leaves it OFF (the default). It never touches the
    /// active segment, so it never blocks an append. See `docs/COMPACTION.md`.
    compact: bool,
    /// The cap on the number of live work-groups, including the default (refs #240, #9, #10):
    /// bounds consumer-state memory once the wire can name groups, so an unauthenticated client
    /// cannot exhaust memory by naming endless groups. `0` = unlimited (the cap is off); the
    /// default is non-zero (1024). A new named group past the cap is rejected by the engine.
    max_groups: usize,
    /// The idle window after which an idle, fully-caught-up, lease-free NAMED work-group is evicted
    /// from memory (refs #277, #240), in MILLISECONDS: the lifecycle reclaim that complements the
    /// `max_groups` cap. `0` = DISABLED (never evict), the default; a non-zero value opts in. The
    /// durable per-group checkpoint is never deleted, so a re-subscribe resumes; only fully-caught-up
    /// groups are evicted, so a consumer's committed position is never lost.
    group_idle_evict_ms: u64,
    /// The refuse-to-boot RAM ceiling in BYTES (#115, #19, #10), wired into
    /// [`EngineConfig::ram_ceiling_bytes`]. `0` = UNSET (the default for `balanced`/`throughput`):
    /// the guard is off and `ironbus_ram_headroom_bytes` reports the `-1` sentinel. When set
    /// (`edge-tiny` sets 64 MiB), the broker refuses to start if the WORST-CASE bounded-buffer
    /// footprint the configured caps imply (`max_connections` * the per-connection in-flight + read
    /// buffers, plus the per-group state and the fixed overhead; see
    /// `ironbus_server::rss::worst_case_buffer_bytes`) PROVABLY exceeds it, and the headroom gauge
    /// reports a real `ceiling - RSS` value.
    ram_ceiling_bytes: u64,
    /// The disk-full overflow policy (#82): `DropNew` (the default) sheds an over-cap produce,
    /// `DropOldest` force-reaps the oldest sealed segment to make room then accepts it. Honored only
    /// when `max_total_bytes` is set; with no cap, no produce is ever over-cap.
    disk_full_policy: DiskFullPolicyArg,
    visibility_ms: u64,
    /// Enable the OPT-IN read-only `/admin` introspection endpoint on the health server (#99). OFF
    /// by default: only with `--enable-admin` (and only when `--health-addr` is set) does `/admin`
    /// serve a JSON operational snapshot; otherwise it is a 404 like any unknown path. It is
    /// READ-ONLY and UNAUTHENTICATED, sharing `/metrics`'s trust model (loopback or a trusted
    /// network, the #105/#107 threat model), so it must run only where `/metrics` is already
    /// trusted. It exposes no mutating action and no secret material.
    enable_admin: bool,
    /// Turn ON OTLP span export (#99, #352). OFF by default. When set AND the broker is built with
    /// the non-default `otlp` feature, the bounded span queue drains into the concrete
    /// opentelemetry-otlp gRPC exporter shipping to [`Self::otlp_endpoint`]. On the DEFAULT build (no
    /// `otlp` feature), setting this logs a clear "built without otlp" diagnostic and export stays
    /// off, so the flag is harmless on the shipped binary. Platform-neutral (validated on every
    /// platform); only the Unix serve path wires the exporter.
    enable_otlp_export: bool,
    /// The OTLP collector endpoint (#352): where the span exporter ships when export is on, e.g.
    /// `http://127.0.0.1:4317` (plaintext gRPC, the default OTLP/gRPC port). `None` falls back to the
    /// in-crate default endpoint. Read only when export is on AND the `otlp` feature is built in;
    /// inert otherwise.
    otlp_endpoint: Option<String>,
    /// The `/healthz` liveness hysteresis window in MILLISECONDS (#95): the broker's accept loop ticks
    /// a monotonic-clock progress beacon every iteration (idle too), and `/healthz` answers 503 only
    /// after this long with no tick, so a slow-but-progressing fsync never fails liveness and a
    /// healthy idle loop stays 200. `0` = the watchdog is DISABLED (a static-200 `/healthz` while up).
    /// Default 10 s (`DEFAULT_HEALTH_LIVENESS_WINDOW_MS`).
    health_liveness_window_ms: u64,
    /// Acknowledge a NON-LOOPBACK `--health-addr` bind (#95), fail-closed default. The health surface
    /// (`/metrics`, `/healthz`, `/readyz`, optional `/admin`) is UNAUTHENTICATED and UNENCRYPTED: TLS
    /// (#107) and an auth identity (#106) are specified but NOT yet wired, so per the #107 bind
    /// invariant a non-loopback health bind refuses to start unless the operator deliberately opts in
    /// here, at which point the broker logs a loud warning. Loopback binds ignore this flag and never
    /// warn. There is NO override for the wire-protocol `--addr` bind; this is the health surface only.
    health_allow_public: bool,
    /// The COUNT bound on each per-producer effectively-once dedup window (#3, #33): the most
    /// `(msg_id, offset)` entries one producer's window keeps before evicting the oldest. Dedup is OFF
    /// by default and activates per-producer ONLY when a publish carries a `msg_id`; this only sizes
    /// the window when it does. Default 100k (`DEFAULT_DEDUP_MAX_IDS`); floored to 1 by the engine.
    dedup_max_ids: usize,
    /// The TIME bound on each per-producer dedup window (#3, #33), in MILLISECONDS of monotonic time:
    /// an entry older than this is evicted regardless of the count bound. Default 2 min
    /// (`DEFAULT_DEDUP_WINDOW_MS`); `0` disables the time bound (only the count bound applies).
    dedup_window_ms: u64,
    /// The cap on the NUMBER of distinct per-producer dedup windows (#33): the `producer_id` is
    /// wire-supplied and attacker-chosen, so this bounds the TOTAL dedup memory. A fresh
    /// `producer_id` over the cap evicts the least-recently-active window (an approximate LRU), so a
    /// flood of distinct ids cannot grow RAM without bound. Default 4096
    /// (`DEFAULT_DEDUP_MAX_PRODUCERS`); floored to 1 by the engine.
    dedup_max_producers: usize,
    /// The DURABILITY LEVEL (#341, #379): how an ack relates to the covering `fdatasync`. Default
    /// [`DurabilityLevelArg::Sync`] (ack only after the covering fdatasync, I2, ZERO acked loss on a
    /// power cut), so a zero-config broker is power-loss safe. The relaxed levels weaken I2 by a
    /// documented loss window and are strictly opt-in; the unbounded-loss ones (`async`/`none`) refuse
    /// to boot without `async_loss_ack` (the none/async safety gate). Platform-neutral so it is
    /// validated on every platform; the Unix on-disk path maps it to the engine enum.
    durability_level: DurabilityLevelArg,
    /// The COMPRESSION CODEC (#12, #387): which codec the on-disk compression runtime
    /// (`ironbus_core::compress`) compresses NEW writes with. Default [`CompressionArg::Lz4`] (the
    /// ADR-0003 pure-Rust default codec); [`CompressionArg::None`] stores every record raw,
    /// byte-for-byte the historical layout. The runtime's raw-store / never-expand guards and its
    /// decoder resilience (the decompressed-size cap, unknown-codec POISON) are codec-independent.
    /// Platform-neutral so it is parsed/validated on every platform; the Unix on-disk path maps it to
    /// the codec runtime's config. The opt-in `zstd` codec (and its level knob) is deferred per
    /// ADR-0003 and not accepted on the default build.
    compression: CompressionArg,
    /// The `interval` level's TIME window in MILLISECONDS (#341): the most time an acked-but-unsynced
    /// record may sit before a forced `fdatasync`, bounding the worst-case loss. Only consulted under
    /// `durability_level == interval`. Default 1 s (`DEFAULT_FLUSH_INTERVAL_MS`); `0` disables the time
    /// trigger (the byte budget alone forces the sync), but the validation requires at least one
    /// positive trigger so an `interval` broker always has a bound.
    flush_interval_ms: u64,
    /// The `interval` level's BYTE budget (#341): the most UNSYNCED record bytes that may accumulate
    /// before a forced `fdatasync`. Only consulted under `durability_level == interval`. Default 1 MiB
    /// (`DEFAULT_FLUSH_MAX_BYTES`); `0` disables the byte trigger (the time window alone forces the
    /// sync). The EFFECTIVE worst-case loss bound is the smaller of the time and byte triggers.
    flush_max_bytes: u64,
    /// The explicit DATA-LOSS ACKNOWLEDGEMENT for the unbounded-loss levels (#49, #379): the
    /// `--async-loss-ack` (a.k.a. `i-accept-acknowledged-data-loss`) bare flag. `async` and `none`
    /// WAIVE I2 with an unbounded loss window, so they REFUSE TO BOOT unless this is set (the
    /// fail-closed none/async safety gate). `sync` and `interval` ignore it. When a gated level boots
    /// with the ack, the broker logs a LOUD startup warning that I2 is waived and the worst-case loss
    /// for the active level.
    async_loss_ack: bool,
    /// The CoDel time-in-queue (sojourn) shedding TARGET in MILLISECONDS (#68): the acceptable
    /// standing produce-admission latency before the load-shed begins. `0` = DISABLED (the default),
    /// so a zero-config broker behaves exactly as today (byte-cap shed + consumer credit only). When
    /// set, the RFC 8289 recommended 5 ms is the doc value, and the engine CLAMPS it to `[1 ms, 1 s]`
    /// (never rejected). A sustained admission sojourn above it for `codel_interval_ms` sheds NEW
    /// produces with the typed "shed under load" signal, never dropping an accepted record.
    codel_target_ms: u64,
    /// The CoDel INTERVAL in MILLISECONDS (#68): the window the admission sojourn must stay above
    /// `codel_target_ms` before shedding, clamped to `[20 ms, 10 s]`. Only consulted when
    /// `codel_target_ms` is non-zero. Default 100 ms (the RFC 8289 value).
    codel_interval_ms: u64,
    /// The per-client retry-budget RATIO in PARTS PER MILLION (#69): the fraction of a client's
    /// request rate its retries may occupy before the broker-side throttle sheds them. `0` = DISABLED
    /// (the default). The doc budget is 10% (`100000`).
    retry_budget_ratio_per_million: u64,
    /// The per-client retry-budget sliding WINDOW in MILLISECONDS (#69), only consulted when the
    /// ratio is non-zero. Default 60 s.
    retry_budget_window_ms: u64,
    /// The fire-and-forget (un-credited) token-bucket MESSAGE rate in msg/s (#69): caps the
    /// QoS-0-equivalent tier so it cannot bypass the consumer-credit brake. `0` = DISABLED (the tier
    /// is ungoverned, as today). The doc default is 5000.
    fire_and_forget_msg_rate: u64,
    /// The fire-and-forget token-bucket BYTE rate in bytes/s (#69). `0` = disabled. Doc default
    /// 5 MiB/s.
    fire_and_forget_byte_rate: u64,
    /// The fire-and-forget token-bucket refill granularity in MILLISECONDS (#69): sizes the burst
    /// ceiling. Default 100 ms.
    fire_and_forget_refill_ms: u64,
    /// The starting / static-floor EGRESS concurrency limit for the AIMD downstream limiter (#69),
    /// adapted within `[4, 128]`. `0` is treated as the doc default floor (16) by the limiter.
    egress_limit: u32,
    /// The fsync-HEADROOM admission window in BYTES (#378): the most un-fsynced (buffered-but-not-
    /// durable) record bytes the BUFFERED write frontier may run ahead of the DURABLE frontier before
    /// a new produce is throttled (a group-commit drain forced first) or shed. `0` = DISABLED (the
    /// default), so a zero-config broker is unchanged; a non-zero value is the opt-in tight RAM /
    /// loss-window bound on the un-fsynced backlog. Under `sync` it throttles (drain-then-admit, never
    /// loses); under a relaxed durability level it caps the loss window by shedding new produces once
    /// the un-fsynced backlog fills. Reuses the engine's `unsynced_bytes()` frontier (#341).
    wal_fsync_headroom_bytes: u64,
}

// Only the Unix `bench` execution path constructs a default `ServeConfig` (the isolated broker); on
// a non-Unix target the `bench` run is stubbed out, so gate the constructor to avoid a dead-code
// warning under `-D warnings`.
#[cfg(unix)]
impl ServeConfig {
    /// The compiled-default `ServeConfig`, every knob at its built-in default. The `bench` (#94)
    /// isolated in-process broker starts from this and then sets only its checkpoint interval, so
    /// the bench broker matches the shipped `serve` defaults in every other respect. Defined once
    /// here so it cannot drift from the per-flag default constants.
    fn bench_default() -> ServeConfig {
        ServeConfig {
            // The bench broker is the shipped default set, i.e. the `balanced` profile.
            profile: Profile::Balanced,
            profile_schema_version: PROFILE_SCHEMA_VERSION,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            max_deliver: DEFAULT_MAX_DELIVER,
            allow_unlimited_deliver: false,
            backoff_ms: Vec::new(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            consumer_credit: DEFAULT_CONSUMER_CREDIT,
            consumer_credit_bytes: DEFAULT_CONSUMER_CREDIT_BYTES,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_age_ms: DEFAULT_MAX_AGE_MS,
            max_messages: DEFAULT_MAX_MESSAGES,
            // Key compaction (#337) is OFF by default.
            compact: false,
            max_groups: DEFAULT_MAX_GROUPS,
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
            ram_ceiling_bytes: DEFAULT_RAM_CEILING_BYTES,
            disk_full_policy: DiskFullPolicyArg::DropNew,
            visibility_ms: DEFAULT_VISIBILITY_MS,
            enable_admin: false,
            enable_otlp_export: false,
            otlp_endpoint: None,
            health_liveness_window_ms: DEFAULT_HEALTH_LIVENESS_WINDOW_MS,
            health_allow_public: false,
            dedup_max_ids: DEFAULT_DEDUP_MAX_IDS,
            dedup_window_ms: DEFAULT_DEDUP_WINDOW_MS,
            dedup_max_producers: DEFAULT_DEDUP_MAX_PRODUCERS,
            // The bench broker runs the default durable level (#341): ack-implies-durable, the same
            // power-loss-safe guarantee the shipped `serve` default carries.
            durability_level: DurabilityLevelArg::Sync,
            // The bench broker runs the default compression codec (#387): lz4 per ADR-0003.
            compression: CompressionArg::Lz4,
            flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
            flush_max_bytes: DEFAULT_FLUSH_MAX_BYTES,
            async_loss_ack: false,
            // Backpressure controls (#68, #69) default to inert in this config builder.
            codel_target_ms: 0,
            codel_interval_ms: DEFAULT_CODEL_INTERVAL_MS,
            retry_budget_ratio_per_million: 0,
            retry_budget_window_ms: DEFAULT_RETRY_BUDGET_WINDOW_MS,
            fire_and_forget_msg_rate: 0,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: DEFAULT_FIRE_AND_FORGET_REFILL_MS,
            egress_limit: DEFAULT_EGRESS_LIMIT,
            wal_fsync_headroom_bytes: DEFAULT_WAL_FSYNC_HEADROOM_BYTES,
        }
    }
}

/// Maps a data-dir lifecycle/lock failure (#89) onto the frozen CLI exit-code scheme. A
/// non-directory path is an operator MISCONFIGURATION (usage, exit 1); an unwritable mount, a
/// lock-IO fault, and the "another broker already running" contention are RUNTIME faults that fail
/// the broker start (internal, exit 70). All carry the typed message naming the data dir.
#[cfg(unix)]
fn map_dir_error(e: &dirlock::DirError) -> CliError {
    match e {
        dirlock::DirError::NotADirectory(_) => CliError::Usage(e.to_string()),
        dirlock::DirError::NotWritable(..)
        | dirlock::DirError::AlreadyLocked(_)
        | dirlock::DirError::LockIo(..) => CliError::Internal(e.to_string()),
    }
}

/// Resolves a `--health-addr` to its socket addresses and classifies the bind as loopback or not, the
/// fail-closed SECURE-BIND guard for the health surface (#95, the #107 bind invariant).
///
/// Resolution is on the RESOLVED address, never the literal string: a hostname that resolves to a
/// routable IP is non-loopback, and the wildcards `0.0.0.0` / `::` are non-loopback (they expose every
/// interface). A bind is loopback only when EVERY resolved address is loopback (`127.0.0.0/8` or
/// `::1`), so a name that maps to both `127.0.0.1` and a routable IP is treated as non-loopback.
///
/// Returns the resolved addresses to bind, plus whether the bind is loopback. An address that resolves
/// to nothing is a usage error. The CALLER applies the policy: a non-loopback bind without
/// `--health-allow-public` is refused (the health surface is unauthenticated and unencrypted today),
/// and with the ack it binds after a loud warning.
///
/// # Errors
/// [`CliError::Usage`] if the address cannot be resolved (an unresolvable host or a malformed
/// `host:port`), so a typo fails closed rather than silently binding nothing.
// Used on the Unix serve path and exercised by the (platform-independent) unit tests; gated so a
// non-Unix non-test build, where `serve` is stubbed out, does not carry it as dead code under
// `-D warnings`.
#[cfg(any(unix, test))]
fn resolve_and_classify_health_bind(haddr: &str) -> Result<(Vec<SocketAddr>, bool), CliError> {
    let resolved: Vec<SocketAddr> = haddr
        .to_socket_addrs()
        .map_err(|e| {
            CliError::Usage(format!(
                "`--health-addr` value `{haddr}` could not be resolved to an address: {e}"
            ))
        })?
        .collect();
    if resolved.is_empty() {
        return Err(CliError::Usage(format!(
            "`--health-addr` value `{haddr}` resolved to no address"
        )));
    }
    // Loopback ONLY if every resolved address is loopback; the wildcard `0.0.0.0`/`::` is unspecified
    // (not loopback), so it is correctly classified non-loopback by `is_loopback()`.
    let loopback = resolved.iter().all(|a| a.ip().is_loopback());
    Ok((resolved, loopback))
}

/// The fatal usage error for a non-loopback `--health-addr` bind without the `--health-allow-public`
/// acknowledgement (#95): the health surface is UNAUTHENTICATED and UNENCRYPTED (TLS #107 and auth
/// #106 are specified but not wired), so per the #107 bind invariant the broker refuses to start and
/// names the address, says which protections are missing, and points at the safe options. Fail-closed
/// (exit 1, before any listener opens): there is no window where an unprotected non-loopback health
/// socket accepts a connection.
#[cfg(any(unix, test))]
fn health_non_loopback_refusal(haddr: &str) -> CliError {
    CliError::Usage(format!(
        "refusing to bind non-loopback health address `{haddr}`: the health surface (/metrics, \
         /healthz, /readyz, /admin) is UNAUTHENTICATED and UNENCRYPTED (TLS #107 and an auth \
         identity #106 are not yet implemented), so exposing it off loopback would leak topology \
         and offsets and invite a scrape-amplification DoS. Bind a loopback address (the default is \
         a 127.0.0.1 health port) and scrape it over a localhost tunnel, OR pass \
         --health-allow-public to acknowledge that the metrics endpoint is unauthenticated and bind \
         it anyway (a loud startup warning is logged). This acknowledgement covers the health \
         surface only; the wire-protocol --addr bind has no such override."
    ))
}

/// The outcome of the secure-bind guard for a `--health-addr` that WAS set (#95): the resolved
/// addresses to bind, and whether to emit the loud unauthenticated-surface warning (true only for an
/// acknowledged non-loopback bind). A non-loopback bind without the acknowledgement does not produce
/// this; it is a fatal [`CliError::Usage`] from [`health_bind_decision`].
#[cfg(any(unix, test))]
#[derive(Debug)]
struct HealthBindDecision {
    /// The resolved socket addresses to bind, exactly what the guard classified.
    addrs: Vec<SocketAddr>,
    /// Whether to log the loud "unauthenticated network health surface" warning at startup (an
    /// acknowledged non-loopback bind), so the operator who opted in always sees it.
    warn_public: bool,
}

/// Applies the fail-closed SECURE-BIND policy (#95) to a set `--health-addr`: resolve and classify it,
/// then REFUSE a non-loopback bind unless `allow_public` was set. The single decision seam `cmd_serve`
/// uses, so the policy (loopback binds silently, non-loopback needs the ack and then warns) is in one
/// testable place: a unit test drives every branch, so removing the guard fails a test.
///
/// # Errors
/// [`CliError::Usage`] if the address does not resolve, or if it is non-loopback and `allow_public`
/// is `false` (the fail-closed refusal naming the address and the missing protections).
#[cfg(any(unix, test))]
fn health_bind_decision(haddr: &str, allow_public: bool) -> Result<HealthBindDecision, CliError> {
    let (addrs, loopback) = resolve_and_classify_health_bind(haddr)?;
    if loopback {
        // Loopback MAY run unauthenticated, silently: the trust boundary is the host itself.
        return Ok(HealthBindDecision {
            addrs,
            warn_public: false,
        });
    }
    if !allow_public {
        // Non-loopback with no acknowledgement: fail closed, before any side effect.
        return Err(health_non_loopback_refusal(haddr));
    }
    // Acknowledged non-loopback: bind it, but warn loudly on every startup.
    Ok(HealthBindDecision {
        addrs,
        warn_public: true,
    })
}

/// Builds the MATERIALIZED-CONFIG line (#87): one structured `key=value` line carrying the active
/// profile, the [`PROFILE_SCHEMA_VERSION`], and EVERY resolved tuning knob, so an operator can see
/// exactly what a broker is running and a profile content change is auditable across an upgrade. It
/// is the EFFECTIVE config after the full profile < env < flag resolution, not the raw flags. Pure
/// and platform-independent (it touches no IO) so a unit test asserts its contents directly and on
/// every platform; `cmd_serve` writes it once at startup. `data_dir` is included but NEVER any
/// secret material (the broker carries none today; the redacting newtype is the #89/#109 residual).
fn materialized_config_line(config: &ServeConfig, addr: &str, data_dir: &Path) -> String {
    let policy = config.disk_full_policy.as_str();
    // The durability level (#341, #379) and its loss exposure: an operator reads the active level,
    // whether it is power-loss safe (I2 holds only under `sync`), and the interval triggers straight
    // off the startup log, the same surface the `ironbus_durability_*` gauges expose on `/metrics`.
    let durability_level = config.durability_level.as_str();
    let power_loss_safe = !config.durability_level.waives_i2();
    // The compression codec (#12, #387) the on-disk codec runtime compresses new writes with; an
    // operator reads the active codec straight off the startup log. `none` is the historical
    // raw-store behavior.
    let compression = config.compression.as_str();
    format!(
        "materialized-config profile={} profile_schema_version={} addr={addr} \
         data_dir={data_dir} max_connections={} max_segment_bytes={} max_total_bytes={} \
         consumer_credit={} consumer_credit_bytes={} max_in_flight={} max_groups={} \
         group_idle_evict_ms={} checkpoint_interval={} max_deliver={} \
         allow_unlimited_deliver={} disk_full_policy={policy} visibility_timeout_ms={} \
         max_retained_bytes={} max_age_ms={} max_messages={} health_liveness_window_ms={} \
         enable_admin={} ram_ceiling_bytes={} durability_level={durability_level} \
         power_loss_safe={power_loss_safe} compression={compression} flush_interval_ms={} \
         flush_max_bytes={} async_loss_ack={} wal_fsync_headroom_bytes={}",
        config.profile.name(),
        config.profile_schema_version,
        config.max_connections,
        config.max_segment_bytes,
        config.max_total_bytes,
        config.consumer_credit,
        config.consumer_credit_bytes,
        config.max_in_flight,
        config.max_groups,
        config.group_idle_evict_ms,
        config.checkpoint_interval,
        config.max_deliver,
        config.allow_unlimited_deliver,
        config.visibility_ms,
        config.max_retained_bytes,
        config.max_age_ms,
        config.max_messages,
        config.health_liveness_window_ms,
        config.enable_admin,
        config.ram_ceiling_bytes,
        config.flush_interval_ms,
        config.flush_max_bytes,
        config.async_loss_ack,
        config.wal_fsync_headroom_bytes,
        data_dir = data_dir.display(),
    )
}

/// A one-line, human-readable description of the WORST-CASE acknowledged loss the active durability
/// level can take on a power cut (#341, #379), for the loud I2-waived startup warning. `sync` returns
/// the zero-loss statement; each relaxed level returns its documented bound (with the `interval`
/// window's configured triggers spelled out). Pure and platform-neutral (it reads only the config),
/// so it is testable on every platform and shared by the warning. The single source of truth for the
/// per-level loss wording, kept in step with `docs/DURABILITY.md` and the engine's
/// `DurabilityLevel::worst_case_loss_description`.
// Used on the Unix serve path (the loud I2-waived warning in `cmd_serve`) and by the
// platform-independent unit tests; gated so a non-Unix non-test build, where `serve` is stubbed out
// and never emits the warning, does not carry it as dead code under `-D warnings` (the recurring
// #288/#99 Windows footgun: a fn read only on cfg(unix) trips the Windows `never used` lint).
#[cfg(any(unix, test))]
fn durability_loss_description(config: &ServeConfig) -> String {
    match config.durability_level {
        DurabilityLevelArg::Sync => {
            "zero (an ack is emitted only after the covering fdatasync; I2 holds)".to_string()
        }
        DurabilityLevelArg::Interval => format!(
            "bounded by the flush window: at most the records acked since the last fdatasync, forced \
             every {} ms or {} unsynced bytes, whichever comes first",
            config.flush_interval_ms, config.flush_max_bytes
        ),
        DurabilityLevelArg::Async => "every record acked since the last fdatasync, with no time or \
             byte ceiling (bounded only by the OS dirty-writeback window); a segment roll or a clean \
             shutdown is the only barrier"
            .to_string(),
        DurabilityLevelArg::None => "every record acked since the last segment roll or clean \
             shutdown (no periodic fsync at all): the largest loss window"
            .to_string(),
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
// each input (addr, data dir, config, the declared groups,
// health addr, the config-file warnings, the reload source,
// out) is a distinct concern; a bundling struct would only
// move the noise.
#[allow(clippy::too_many_lines)] // the serve setup is one linear startup sequence (bind, lock, open
                                 // the engine, install the immutable-config handle + reload, the
                                 // health server, the accept loop, the graceful drain); splitting it
                                 // further would scatter a single concern across helpers.
fn cmd_serve(
    addr: &str,
    data_dir: &Path,
    config: &ServeConfig,
    key_shared_groups: &[String],
    broadcast_groups: &[String],
    health_addr: Option<&str>,
    config_warnings: &[String],
    reload: ReloadSource<'_>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    // Install the structured-tracing subscriber with the JSON log layer (#16, #99) before any broker
    // work, so startup events are structured too. OTLP span export (#352) stays OFF by runtime default
    // and, on this default build, is COMPILED OUT entirely (the `otlp` feature is off), so the only
    // steady-state cost is the JSON log formatting. When `--enable-otlp-export` is set AND the broker
    // was built with the `otlp` feature, the concrete exporter ships spans to `--otlp-endpoint`; when
    // the feature is OFF, setting the flag logs a clear "built without otlp" diagnostic and export
    // stays off (the seam is absent). The returned bounded span queue is the drop-and-count export
    // buffer; with export off it simply stays empty.
    if config.enable_otlp_export && !ironbus_server::obs::otlp_compiled_in() {
        writeln!(
            out,
            "WARN: --enable-otlp-export was set but this broker was built WITHOUT the `otlp` \
             feature; OTLP span export is disabled (rebuild with --features otlp to enable it)"
        )?;
    }
    let _span_queue = ironbus_server::obs::init_tracing(&ironbus_server::obs::TracingConfig {
        otlp_export_enabled: config.enable_otlp_export,
        otlp_endpoint: config.otlp_endpoint.clone(),
        ..ironbus_server::obs::TracingConfig::default()
    });

    // SECURE-BIND guard (#95, the #107 bind invariant), FAIL-CLOSED and FIRST: resolve and classify
    // `--health-addr` before ANY broker side effect (no data dir touched, no lock taken, no listener
    // opened), so a non-loopback health bind without the --health-allow-public acknowledgement
    // refuses to start cleanly with no partial state. Loopback binds (and the no-health-addr case)
    // pass through. The resolved addresses are reused below so what binds is exactly what was checked.
    let health_bind: Option<HealthBindDecision> = match health_addr {
        Some(haddr) => Some(health_bind_decision(haddr, config.health_allow_public)?),
        None => None,
    };

    // Data-dir lifecycle then the single-broker lock (#89), BEFORE the engine opens. `prepare`
    // creates the dir (0700) if absent, rejects a non-directory path, and proves it writable; the
    // lock makes a SECOND `serve` on the same data dir fail fast rather than corrupt the log with
    // concurrent writers. The `DirLock` is held in `_dir_lock` for the whole serve lifetime and is
    // released by the OS when it drops on return (and unconditionally on process exit).
    dirlock::prepare_data_dir(data_dir).map_err(|e| map_dir_error(&e))?;
    let _dir_lock = dirlock::DirLock::acquire(data_dir).map_err(|e| map_dir_error(&e))?;
    let engine = open_disk_engine(data_dir, config, key_shared_groups, broadcast_groups)?;
    // The engine is owned by the append actor (#177); connection handlers and the health server reach
    // it only through the bounded-channel handle, so no handler holds a lock across an fsync. The
    // actor's join handle yields the engine back on its clean exit (a Shutdown drain), which is how
    // the graceful-shutdown cursor flush (#195) completes before the process exits 0.
    let (shared, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
    let listener = TcpListener::bind(addr)
        .map_err(|e| CliError::Internal(format!("cannot bind {addr}: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| CliError::Internal(format!("cannot read local address: {e}")))?;
    writeln!(
        out,
        "ironbus listening on {local}, data dir {}",
        data_dir.display()
    )?;
    // The materialized-config dump (#87): ONE structured line with the active profile, the profile
    // schema version, and every resolved knob, so an operator sees exactly the effective config the
    // broker is running. This is diagnostic startup LOGGING, so it goes to STDERR (the log stream),
    // never the stdout startup-protocol stream: a consumer that reads the "listening on" line and
    // then stops reading stdout (a common supervisor pattern, and exactly what the migrate seed test
    // does) would otherwise make serve take a SIGPIPE on this write and die on Linux. Writing to
    // stderr and ignoring a write error keeps the broker alive and puts config logging where it
    // belongs.
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        materialized_config_line(config, &local.to_string(), data_dir)
    );
    // The config-FILE non-fatal warnings (#86, #382): a downgraded unknown key
    // (`--allow-unknown-config`) and the coupled-set warnings (a no-op `drop-oldest` with no byte
    // cap). On stderr (the log stream), same as the materialized-config line, so an operator sees a
    // setting that has no effect or a typo that was tolerated. Empty with no `--config`.
    for warning in config_warnings {
        let _ = writeln!(std::io::stderr(), "WARN: config: {warning}");
    }
    // The immutable effective-config + atomic reload handle (#380, #382): the resolved config is
    // installed into ONE immutable `Arc<EffectiveConfig>` behind a single safe swap point, read here
    // via one refcount bump (the single atomic pointer load on the path that needs it, never a
    // per-message re-parse). `_config_handle` is held for the serve lifetime; a re-read RELOAD
    // (`reload_from`) validates a whole candidate, rejects a cold-key change atomically, and swaps
    // ONLY on full success (a broken reload keeps this config). The SIGHUP wire is the #195
    // disentanglement residual (SIGHUP is currently bound to graceful-stop via ctrlc's `termination`
    // feature, so re-binding it to reload would silently change `kill -HUP` semantics); the engine
    // and the safe re-read trigger ship here, the authed mutating wire CONFIG verbs are the #106
    // residual (no unauthenticated remote mutation surface).
    // `retention_requested` is `false` here: the coupled-set "retention requested but all off" check
    // already ran (and passed) at parse time, so the installed snapshot needs no re-detection of the
    // request; a reload re-derives it from the re-read file.
    let config_handle =
        config_reload::ConfigHandle::new(build_effective_config(config, data_dir, false));
    debug_assert_eq!(
        config_handle.current().resolved.segment_bytes,
        config.max_segment_bytes,
        "the installed immutable config reads back the resolved segment size",
    );
    // The safe, auth-free RELOAD trigger (#380, #382): re-read the `--config` file, re-resolve and
    // fully validate the candidate, reject a cold-key change ATOMICALLY, and swap the immutable
    // `Arc<EffectiveConfig>` in ONE store ONLY on success (a broken reload keeps the running config).
    // Run once at startup right after the engine opens, as a re-read self-check: it proves the
    // file still parses identically just after the broker took the data-dir lock (catching a
    // mid-start operator edit, a TOCTOU window), and it is the exact path a future SIGHUP wire calls.
    // The reload mutates only the in-process config pointer on a LOCALLY-read file, never on an
    // unauthenticated remote request (the mutating wire CONFIG verbs are the #106 auth residual).
    if let Some(path) = reload.config_path {
        reload_effective_config(
            &config_handle,
            path,
            reload.allow_unknown_config,
            config,
            data_dir,
            out,
        );
    }
    if config.durability_level.waives_i2() {
        // The LOUD I2-WAIVED warning (#341, #379): a relaxed durability level is active, so an ack no
        // longer implies the record is durable. State exactly which invariant is waived and the
        // worst-case acknowledged loss for the active level, on EVERY startup, so an operator who
        // opted into a power-loss-unsafe broker always sees it. The unbounded-loss levels reached this
        // point only because `--async-loss-ack` was set (the gate in `validate_serve_config`), so this
        // is the deliberate, acknowledged warning, never a silent downgrade.
        writeln!(
            out,
            "WARN: --durability-level {level}: I2 (ack-implies-durable) is WAIVED; this broker is NOT \
             power-loss safe. An ack no longer implies the record is durable. Worst-case acknowledged \
             loss on a power cut: {loss}. Only `--durability-level sync` (the default) loses zero \
             acknowledged data on a power loss.",
            level = config.durability_level.as_str(),
            loss = durability_loss_description(config),
        )?;
    }
    if config.allow_unlimited_deliver && (config.max_deliver == 0 || config.max_deliver == u32::MAX)
    {
        // Unlimited delivery is opt-in but LOUD (#63): a single poison payload can redeliver
        // forever, so the operator who chose it sees it on every startup.
        writeln!(
            out,
            "WARN: --max-deliver is unlimited (--allow-unlimited-deliver): a poison message can \
             redeliver forever and is never dead-lettered"
        )?;
    }
    // The shared shutdown flag the serve loop polls. The wire serve uses a non-blocking accept that
    // re-checks this flag every ~50 ms (its ACCEPT_POLL), so flipping it breaks the accept loop
    // within a bounded time rather than only after the next connection. A SIGINT/SIGTERM/SIGHUP
    // handler flips it for a graceful stop (#195); the broker then stops accepting and, on exit
    // below, flushes every group's committed cursor so a restart does not redeliver acked messages.
    // Durability across an ABRUPT termination still holds (every ack is fsynced first); this handler
    // additionally makes a CLEAN operator stop non-redelivering by flushing the lagging cursor.
    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    // The monotonic clock the liveness watchdog (#95) measures against. ONE clock instance is shared
    // (cloned, so every clone reports from the SAME monotonic origin) between the wire accept loop
    // that ticks the beacon and the health server that reads it, so their difference is a real
    // elapsed-nanos measure. The beacon is seeded at the broker's start instant, so a fresh broker is
    // live until a whole window elapses with no tick.
    let health_clock = SystemClock::new();
    let progress = Arc::new(ironbus_server::liveness::LivenessBeacon::new(
        health_clock.now_monotonic_nanos(),
    ));

    // Start the health endpoints (if `--health-addr` was set), warning about an enabled-but-unreachable
    // admin endpoint and an acknowledged public bind. The secure-bind guard already classified and
    // (where required) refused the bind at the top of this function, so `health_bind` here is safe.
    let health_handle = start_health_server(
        config,
        health_addr,
        health_bind,
        &shared,
        &shutdown,
        &progress,
        &health_clock,
        out,
    )?;

    // The wire accept loop ticks the liveness beacon (#95) on its OWN clock clone (same origin), so
    // `/healthz` measures the accept loop's progress. The clone keeps the original `health_clock`
    // available above for the health server's own reads.
    let result = serve(
        &listener,
        &shared,
        &shutdown,
        config.max_connections,
        &health_clock.clone(),
        &progress,
    )
    .map_err(|e| CliError::Internal(format!("serve loop failed: {e}")));
    // The wire serve returns only when shutdown is set (a signal, or a fatal listener error that
    // ends the loop), so flip it for the health thread too.
    shutdown.store(true, Ordering::Release);
    if let Some(h) = health_handle {
        let _ = h.join();
    }
    result?;
    // Graceful-shutdown drain (#195): the serve loop has stopped accepting and every connection
    // handler has been signalled to wind down. Ask the append actor to flush its pending produce
    // batch (the one covering fsync) and force a final checkpoint of EVERY live work-group's
    // committed cursor, so a restart after this clean stop resumes past the acked messages rather
    // than redelivering up to `--checkpoint-interval` of them AND no acked-but-not-durable record is
    // lost. A long-lived consumer still connected at the signal does not get to run its own
    // close-path flush (its handler thread is detached, not joined), so this actor-side drain is what
    // makes the clean stop non-redelivering. It runs on a normal serve exit only; a serve error
    // returned above. Dropping our handle plus the shutdown command disconnects the actor's channel,
    // so it exits and the join completes.
    let drain = shared
        .shutdown()
        .map_err(|_| CliError::Internal("the append actor exited before shutdown".to_string()))?;
    drain.map_err(|e| CliError::Internal(format!("flushing cursors on shutdown: {e}")))?;
    drop(shared);
    let _ = actor.join();
    Ok(())
}

/// Starts the health-endpoint server thread when `--health-addr` was set, returning its join handle
/// (or `None` if no health address). Split out of [`cmd_serve`] so the bind, the startup warnings, and
/// the liveness-watchdog wiring (#95) live in one place and `cmd_serve` stays under the line bound.
///
/// `health_bind` is the secure-bind guard's already-classified decision: the bind was resolved and an
/// unacknowledged non-loopback bind was refused at the top of `cmd_serve`, so this only emits the loud
/// acknowledged-public warning (when `warn_public`) and binds the resolved addresses. It also warns
/// when `--enable-admin` was set without a health address (the admin endpoint then has nowhere to run).
///
/// # Errors
/// [`CliError::Internal`] if the health listener cannot bind or its local address cannot be read.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)] // the wiring inputs (config, bind, engine, shutdown, beacon,
                                     // clock, out) are each a distinct concern; bundling them into a
                                     // struct would only move the noise, not remove it.
fn start_health_server(
    config: &ServeConfig,
    health_addr: Option<&str>,
    health_bind: Option<HealthBindDecision>,
    shared: &ironbus_server::actor::EngineHandle<StdFs, SystemClock>,
    shutdown: &Arc<AtomicBool>,
    progress: &Arc<ironbus_server::liveness::LivenessBeacon>,
    health_clock: &SystemClock,
    out: &mut impl Write,
) -> Result<Option<std::thread::JoinHandle<()>>, CliError> {
    // The opt-in read-only `/admin` introspection endpoint (#99) needs the health server, which only
    // runs when `--health-addr` is set. A `--enable-admin` with no health address can never take
    // effect, so warn loudly rather than silently no-op.
    if config.enable_admin && health_addr.is_none() {
        writeln!(
            out,
            "WARN: --enable-admin has no effect without --health-addr (the /admin endpoint is \
             served by the health server)"
        )?;
    }
    let (Some(haddr), Some(decision)) = (health_addr, health_bind) else {
        return Ok(None);
    };
    if decision.warn_public {
        // Acknowledged non-loopback: bind it, but loudly, on every startup, so the operator who opted
        // into an unauthenticated network metrics surface always sees it.
        writeln!(
            out,
            "WARN: --health-allow-public: binding the UNAUTHENTICATED, UNENCRYPTED health surface to \
             non-loopback {haddr} (/metrics, /healthz, /readyz exposed to the network; TLS #107 and \
             auth #106 are not yet implemented). Restrict it at the network layer."
        )?;
    }
    // Bind the RESOLVED addresses (what the guard classified), not re-resolve the literal string, so
    // what is bound is exactly what was checked.
    let health_listener = TcpListener::bind(decision.addrs.as_slice())
        .map_err(|e| CliError::Internal(format!("cannot bind health {haddr}: {e}")))?;
    let health_local = health_listener
        .local_addr()
        .map_err(|e| CliError::Internal(format!("cannot read health address: {e}")))?;
    // The admin route is only advertised when opted in, so the default startup line is unchanged for
    // an operator who has not enabled it.
    if config.enable_admin {
        writeln!(
            out,
            "ironbus health endpoints on {health_local} (/healthz, /readyz, /metrics, \
             /admin [read-only, unauthenticated])"
        )?;
    } else {
        writeln!(
            out,
            "ironbus health endpoints on {health_local} (/healthz, /readyz, /metrics)"
        )?;
    }
    let engine = shared.clone();
    let shutdown = Arc::clone(shutdown);
    let admin_enabled = config.enable_admin;
    // The liveness watchdog window in nanos (#95); the config knob is in ms, `0` = disabled.
    let liveness_window_nanos = config.health_liveness_window_ms.saturating_mul(1_000_000);
    let progress = Arc::clone(progress);
    let health_clock = health_clock.clone();
    Ok(Some(std::thread::spawn(move || {
        let _ = serve_health(
            &health_listener,
            &engine,
            &shutdown,
            admin_enabled,
            &progress,
            liveness_window_nanos,
            &health_clock,
        );
    })))
}

/// Installs the process-wide signal handler that flips `shutdown` on SIGINT, SIGTERM, or SIGHUP, so
/// `serve` performs a graceful stop (#195): the serve loop's next poll observes the flag, stops
/// accepting, and the broker flushes its cursors before exiting 0. The `ironbus` binary runs exactly
/// one subcommand per process, so this is installed at most once per process. `try_set_handler` (not
/// `set_handler`) is used so the install is fallible-not-panicking: a `MultipleHandlers` error (a
/// handler already present, which the single-subcommand binary never produces but a future caller
/// might) is surfaced as an internal error rather than a panic, keeping the no-panic library bar.
/// `ctrlc` catches SIGINT; its `termination` feature (enabled in `Cargo.toml`) adds SIGTERM and
/// SIGHUP, so the one handler covers all three signals an operator stop might deliver.
#[cfg(unix)]
fn install_signal_handler(shutdown: &Arc<AtomicBool>) -> Result<(), CliError> {
    let flag = Arc::clone(shutdown);
    ctrlc::try_set_handler(move || {
        // Async-signal context: a single atomic store, nothing else. The serve loop polls this flag
        // on its next accept cycle and unwinds the accept-stop, cursor-flush, exit-0 path itself.
        flag.store(true, Ordering::Release);
    })
    .map_err(|e| CliError::Internal(format!("cannot install the shutdown signal handler: {e}")))
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)] // mirrors the Unix cmd_serve signature exactly; bundling the
                                     // distinct inputs into a struct would only move the noise.
fn cmd_serve(
    addr: &str,
    data_dir: &Path,
    config: &ServeConfig,
    key_shared_groups: &[String],
    broadcast_groups: &[String],
    health_addr: Option<&str>,
    config_warnings: &[String],
    reload: ReloadSource<'_>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    // The #87 materialized-config line, `Profile::name`, and `DiskFullPolicyArg::as_str` are reached
    // only from the Unix serve path, so build (and discard) the line here too: a function/method read
    // only on cfg(unix) trips the Windows `-D warnings` `never used` lint, invisible to a macOS
    // reviewer (the recurring #288/#99 footgun). This also consumes `profile`, `disk_full_policy`,
    // and the other knobs the line reads.
    let _ = materialized_config_line(config, addr, data_dir);
    // The immutable effective-config + reload ENGINE (#380, #382) is exercised only on the Unix serve
    // path (read at startup, then a re-read RELOAD), so the non-Unix stub must reference its WHOLE
    // surface too or the Windows `-D warnings` build trips dead-code on `reload_from` / `ReloadOutcome`
    // / `is_cold` / `class_of` / `cold_keys`, invisible to a macOS reviewer (the recurring #288/#99
    // footgun). Build the handle, read it, and drive one no-op reload (the candidate equals current,
    // so it is a no-op `Applied`); the stub errors out below before any real serving.
    let config_handle =
        config_reload::ConfigHandle::new(build_effective_config(config, data_dir, false));
    let _ = config_handle.current().resolved.segment_bytes;
    let candidate = build_effective_config(config, data_dir, false);
    let outcome = config_handle.reload_from(candidate);
    debug_assert!(
        outcome.applied(),
        "a no-op reload (candidate == current) is Applied",
    );
    if let config_reload::ReloadOutcome::Applied { warnings } = outcome {
        let _ = warnings.len();
    }
    let _ = (
        addr,
        data_dir,
        config.max_connections,
        config.checkpoint_interval,
        config.max_deliver,
        config.allow_unlimited_deliver,
        &config.backoff_ms,
        config.max_in_flight,
        config.consumer_credit,
        config.consumer_credit_bytes,
        config.max_segment_bytes,
        config.max_total_bytes,
        config.max_retained_bytes,
        config.max_age_ms,
        config.max_messages,
        // The #337 key-compaction opt-in is read only on the Unix serve path (it enables the
        // engine's off-hot-path compactor), so the non-Unix stub must consume it too or the Windows
        // `-D warnings` build trips field-never-read, invisible to a macOS reviewer (the recurring
        // #288/#99 footgun).
        config.compact,
        config.max_groups,
        config.group_idle_evict_ms,
        // The #115 refuse-to-boot RAM ceiling is read only on the Unix serve path (it wires the
        // engine's ram_ceiling_bytes and drives the boot guard), so the non-Unix stub must consume it
        // too or the Windows `-D warnings` build trips field-never-read, invisible to a macOS reviewer
        // (the recurring #288/#99 footgun).
        config.ram_ceiling_bytes,
        config.enable_admin,
        // The #352 OTLP export knobs are read only on the Unix serve path (they build the
        // TracingConfig the exporter wires), so the non-Unix stub must consume them too or the
        // Windows `-D warnings` build trips field-never-read, invisible to a macOS reviewer (the
        // recurring #288/#99 footgun). `otlp_endpoint` is borrowed (it is an owned Option).
        config.enable_otlp_export,
        &config.otlp_endpoint,
        // The #95 health knobs are read only on the Unix serve path, so the non-Unix stub must
        // consume them too or the Windows `-D warnings` build trips field-never-read, invisible to a
        // macOS reviewer (the recurring #288/#99 footgun).
        config.health_liveness_window_ms,
        config.health_allow_public,
        config.visibility_ms,
        // The #33 dedup knobs are read only on the Unix serve path (they size the engine's dedup
        // window), so the non-Unix stub must consume them too or the Windows `-D warnings` build trips
        // field-never-read, invisible to a macOS reviewer (the recurring #288/#99 footgun).
        config.dedup_max_ids,
        config.dedup_window_ms,
        config.dedup_max_producers,
        // The #341/#379 durability knobs are read only on the Unix serve path (they wire the engine's
        // durability_level / interval triggers and drive the none/async safety gate + the loud
        // I2-waived warning), so the non-Unix stub must consume them too or the Windows `-D warnings`
        // build trips field-never-read, invisible to a macOS reviewer (the recurring #288/#99 footgun).
        config.durability_level,
        // The #12/#387 compression codec is read only on the Unix serve path (it wires the codec
        // runtime's config and the materialized-config line), so the non-Unix stub must consume it
        // too or the Windows `-D warnings` build trips field-never-read, invisible to a macOS
        // reviewer (the recurring #288/#99 footgun).
        config.compression,
        config.flush_interval_ms,
        config.flush_max_bytes,
        config.async_loss_ack,
        // The #68/#69 backpressure knobs are read only on the Unix serve path (they wire the engine's
        // CoDel / retry-budget / fire-and-forget / egress controls), so the non-Unix stub must consume
        // them too or the Windows `-D warnings` build trips field-never-read, invisible to a macOS
        // reviewer (the recurring #288/#99 footgun).
        config.codel_target_ms,
        config.codel_interval_ms,
        config.retry_budget_ratio_per_million,
        config.retry_budget_window_ms,
        config.fire_and_forget_msg_rate,
        config.fire_and_forget_byte_rate,
        config.fire_and_forget_refill_ms,
        config.egress_limit,
        // The #378 fsync-headroom knob is read only on the Unix serve path (it wires the engine's
        // wal_fsync_headroom_bytes), so the non-Unix stub must consume it too or the Windows
        // `-D warnings` build trips field-never-read, invisible to a macOS reviewer (the recurring
        // #288/#99 footgun).
        config.wal_fsync_headroom_bytes,
        key_shared_groups,
        // Read the broadcast groups under cfg(not(unix)) too: a field/param read only on cfg(unix)
        // breaks the Windows `-D warnings` build invisibly to a macOS reviewer (#288 note).
        broadcast_groups,
        // The config-FILE warnings (#382) are emitted only on the Unix serve path, so the non-Unix
        // stub must consume the param too or the Windows `-D warnings` build trips unused-variable,
        // invisible to a macOS reviewer (the recurring #288/#99 footgun).
        config_warnings,
        // The reload source (#382, the `--config` path + unknown-key policy) is read only on the
        // Unix serve path's re-read reload, so consume it here too for the same #288 reason.
        reload.config_path,
        reload.allow_unknown_config,
        health_addr,
        out,
    );
    Err(CliError::Internal(
        "ironbus serve requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// Opens (creating the directory if absent) the on-disk broker engine rooted at `data_dir`.
/// `key_shared_groups` (#64) are declared server-side: each is put into `key_shared` ordering when
/// a consumer first subscribes; an empty slice leaves every group plain competing (the default).
/// `broadcast_groups` (#288) are marked BROADCAST at open (a group-of-one that sees every record in
/// order), so each accepts the cumulative-ack verb; an empty slice leaves every group competing.
#[cfg(unix)]
fn open_disk_engine(
    data_dir: &Path,
    config: &ServeConfig,
    key_shared_groups: &[String],
    broadcast_groups: &[String],
) -> Result<Engine<StdFs, SystemClock>, CliError> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| CliError::Internal(format!("cannot create {}: {e}", data_dir.display())))?;
    let fs = StdFs::new(data_dir.to_path_buf());
    // An explicit --backoff-ms wins; an empty schedule (the flag was not passed) uses the built-in
    // default. Each stage is milliseconds on the wire, nanoseconds in the engine; saturate rather
    // than overflow on an absurd value.
    let backoff_nanos: Vec<u64> = if config.backoff_ms.is_empty() {
        DEFAULT_NACK_BACKOFF_NANOS.to_vec()
    } else {
        config
            .backoff_ms
            .iter()
            .map(|ms| ms.saturating_mul(1_000_000))
            .collect()
    };
    let delivery = DeliveryConfig::new(
        config.max_deliver,
        config.allow_unlimited_deliver,
        backoff_nanos,
    )
    .map_err(|e| CliError::Internal(format!("delivery config: {e:?}")))?;
    let visibility_ms = config.visibility_ms;
    let engine = Engine::open(
        fs,
        SystemClock::new(),
        EngineConfig {
            // Both caps are honored: `new` validates and sets the segment cap, the builder
            // layers on the durable-log total byte cap (the drop-new shed; `0` = unlimited).
            log: LogConfig::new(config.max_segment_bytes)
                .map_err(|e| CliError::Internal(format!("log config: {e}")))?
                .with_max_total_bytes(config.max_total_bytes),
            lease: LeaseConfig::from_millis(visibility_ms, visibility_ms.max(DEFAULT_HARD_CAP_MS)),
            delivery,
            max_in_flight: config.max_in_flight,
            // The per-CONSUMER (per-connection) standing in-flight credit (#65): the most un-acked
            // messages one connection may hold, the consumer-side half of credit-based flow control.
            // The effective Flow bound is min(this, the per-group max_in_flight window). Floored to
            // 1 by the engine. Default 64 (NOT 65535), memory-justified by Little's Law (#19).
            consumer_credit: config.consumer_credit,
            // The per-CONSUMER (per-connection) in-flight BYTE budget (#275): the RAM-side companion
            // to the message-count credit. The effective Flow bound is min(message credit, byte
            // budget) with a hard floor of one message. Default 8 MiB; `0` = unlimited (off).
            consumer_credit_bytes: config.consumer_credit_bytes,
            checkpoint_interval: config.checkpoint_interval,
            // Consumer-safe retention (#13, #80), each `0` = disabled (off), the default. Size in
            // record bytes, age in milliseconds (against the engine clock), count in messages; the
            // bounds compose, so a segment is reaped if ANY enabled bound trips.
            max_retained_bytes: config.max_retained_bytes,
            max_age_ms: config.max_age_ms,
            max_messages: config.max_messages,
            // The work-group cap (refs #240, #9, #10): bounds consumer-state memory once the wire
            // can name groups. `0` = unlimited (off); the default is non-zero (1024). A new named
            // group past the cap is rejected by the engine before it allocates.
            max_groups: config.max_groups,
            // Idle named-group eviction (refs #277, #240): the lifecycle reclaim that completes the
            // #240 cap. `0` = disabled (off, the default), a non-zero value is the idle window in ms
            // after which a fully-caught-up, lease-free named group is reclaimed. Never deletes a
            // durable checkpoint, so a re-subscribe resumes; only caught-up groups are evicted, so a
            // consumer's committed position is never lost.
            group_idle_evict_ms: config.group_idle_evict_ms,
            // The refuse-to-boot RAM ceiling (#115, #19), wired from `--ram-ceiling-bytes` (or the
            // profile preset: 0 = off for balanced/throughput, 64 MiB for edge-tiny). `0` leaves the
            // guard off and `ironbus_ram_headroom_bytes` at the `-1` sentinel; a set ceiling makes the
            // gauge report a real `ceiling - RSS` value AND is enforced before this point by
            // `validate_serve_config` (which refuses to boot when the worst-case bounded-buffer
            // footprint provably exceeds it).
            ram_ceiling_bytes: config.ram_ceiling_bytes,
            // The disk-full overflow policy (#82): drop-new (default) sheds, drop-oldest force-reaps
            // the oldest sealed segment then accepts. Honored only when `max_total_bytes` is set.
            disk_full_policy: match config.disk_full_policy {
                DiskFullPolicyArg::DropNew => DiskFullPolicy::DropNew,
                DiskFullPolicyArg::DropOldest => DiskFullPolicy::DropOldest,
            },
            // The OPT-IN effectively-once dedup window (#3, #33): the dual count + time bound on each
            // per-producer dedup ring, plus the cap on the NUMBER of distinct producer windows.
            // Dedup is OFF by default and activates per-producer only when a publish carries a
            // `msg_id`; these flags only SIZE the window when it does. `--dedup-max-ids` is the count
            // bound (default 100k), `--dedup-window-ms` the time bound in ms (default 2 min), and
            // `--dedup-max-producers` (default 4096) caps the producer windows so a flood of
            // attacker-chosen `producer_id`s cannot grow RAM without bound (LRU eviction).
            dedup: ironbus_core::dedup::DedupConfig {
                max_ids: config.dedup_max_ids,
                window_nanos: config.dedup_window_ms.saturating_mul(1_000_000),
                max_producers: config.dedup_max_producers,
            },
            // The DURABILITY LEVEL (#341, #379), wired from `--durability-level`. Default `sync`
            // (ack only after the covering fdatasync, I2, zero acked loss): a zero-config broker is
            // byte-for-byte the historical durable broker. The relaxed levels are strictly opt-in and
            // weaken I2 by a documented loss window; `async`/`none` are already gated behind the
            // explicit `--async-loss-ack` acknowledgement by `validate_serve_config`, so an engine can
            // only reach a loss-bearing level once the operator accepted the loss. The `interval`
            // triggers (time/bytes) only matter under `interval`.
            durability_level: match config.durability_level {
                DurabilityLevelArg::Sync => DurabilityLevel::Sync,
                DurabilityLevelArg::Interval => DurabilityLevel::Interval,
                DurabilityLevelArg::Async => DurabilityLevel::Async,
                DurabilityLevelArg::None => DurabilityLevel::None,
            },
            flush_interval_ms: config.flush_interval_ms,
            flush_max_bytes: config.flush_max_bytes,
            // The backpressure controls (#68, #69), wired from the serve flags. Every knob defaults
            // to its disabling value (CoDel off, retry budget off, fire-and-forget ungoverned, egress
            // at its floor), so a zero-config broker is byte-for-byte the historical broker. The
            // engine CLAMPS the CoDel values and bounds the egress limiter, never rejecting a value.
            codel_target_ms: config.codel_target_ms,
            codel_interval_ms: config.codel_interval_ms,
            retry_budget_ratio_per_million: config.retry_budget_ratio_per_million,
            retry_budget_window_ms: config.retry_budget_window_ms,
            fire_and_forget_msg_rate: config.fire_and_forget_msg_rate,
            fire_and_forget_byte_rate: config.fire_and_forget_byte_rate,
            fire_and_forget_refill_ms: config.fire_and_forget_refill_ms,
            egress_limit: config.egress_limit,
            // The fsync-headroom admission window (#378), wired from `--wal-fsync-headroom-bytes`.
            // Default `0` = OFF (the un-fsynced frontier is bounded only by the group-commit
            // drain under `sync` / the interval window under a relaxed level), so a zero-config
            // broker is unchanged; a non-zero value is the opt-in tight RAM / loss-window bound.
            wal_fsync_headroom_bytes: config.wal_fsync_headroom_bytes,
        },
    )
    .map_err(|e| CliError::Internal(format!("opening broker at {}: {e}", data_dir.display())))?;
    let mut engine = engine;
    // Enable OPT-IN key compaction (#337) when `--compact` was passed (OFF by default). It runs the
    // off-hot-path compactor after each produce-path reaper run; it never touches the active segment,
    // so it cannot block an append. A broker without `--compact` is byte-for-byte unchanged.
    if config.compact {
        engine.set_compaction_config(ironbus_storage::compaction::CompactionConfig::enabled());
    }
    // Declare the key_shared groups (#64) server-side: a configured group enters key_shared mode
    // when a consumer first subscribes. An empty slice is a no-op, so every group stays competing.
    engine.set_configured_key_shared_groups(key_shared_groups.iter().cloned());
    // Mark the declared broadcast groups (#288): each is a group-of-one that sees every record in
    // order, marked at open so it accepts the cumulative-ack verb. A bad name or the group cap is a
    // fatal misconfiguration here (the broker should not start with an unhonored broadcast group).
    // An empty slice is a no-op, so every group stays plain competing.
    for group in broadcast_groups {
        engine
            .set_broadcast_in(group, true)
            .map_err(|e| CliError::Usage(format!("--broadcast-group `{group}`: {e}")))?;
    }
    Ok(engine)
}

/// The default number of records `peek` shows when `--limit` is not given.
const DEFAULT_PEEK_LIMIT: u64 = 10;

/// Parses and runs `admin`: fetch a RUNNING broker's read-only `/admin` v1 JSON over HTTP and render
/// the segments, consumers (with incremental lag), and last-skip-offset views FROM THAT JSON ALONE
/// (#15, #99). This is the consumer that demonstrates the `/admin` contract is self-sufficient: the
/// human diagnostics never parse a metric name. `--health-addr <host:port>` is required (the health
/// server is off by default, so there is no implicit default to dial); the endpoint must have been
/// started with `--enable-admin`.
///
/// # Errors
/// [`CliError::Usage`] for a missing/extra flag; [`CliError::Unreachable`] if the health server
/// cannot be reached; [`CliError::Internal`] if the response is not a usable admin v1 body (e.g.
/// `/admin` is not enabled, or the broker serves a different schema version).
fn run_admin(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    // The MUTATING offline admin subverbs (#299) are dispatched by a leading subcommand word, ahead
    // of the read-only `/admin` introspection (which takes only flags). The mutating WIRE verbs (an
    // online consumer-reset/dlq-redrive on a LIVE broker) and FORCE-REAP are DEFERRED to the authed
    // admin surface (#380/#106): a mutating surface over the wire needs connection-scoped auth, so
    // only the auth-free OFFLINE (broker-stopped, data-dir) subset ships here.
    match args.first().map(String::as_str) {
        Some("consumer-reset") => return run_admin_consumer_reset(&args[1..], out),
        Some("dlq-redrive") => return run_admin_dlq_redrive(&args[1..], out),
        Some("force-reap") => {
            return Err(CliError::Usage(
                "admin force-reap reaps stuck leases on a LIVE broker, an online authenticated \
                 operation deferred to the authed admin surface (#380); there are no live leases \
                 to reap offline"
                    .to_string(),
            ));
        }
        _ => {}
    }
    // No mutating subverb: the read-only `/admin` introspection (#15, #99), which takes only flags.
    let mut health_addr: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--health-addr" | "--addr" => {
                health_addr = Some(take_value("--health-addr", args, &mut i)?);
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for admin")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "admin takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let health_addr = health_addr.ok_or_else(|| {
        CliError::Usage(
            "admin needs --health-addr <host:port> (the broker's --health-addr, with --enable-admin)"
                .to_string(),
        )
    })?;
    cmd_admin(&health_addr, out)
}

/// Parses and runs `admin consumer-reset` (#299): the OFFLINE consumer reset. It rewrites a
/// work-group's durable cursor checkpoint to a chosen offset (`--to <offset|earliest|latest>`),
/// clamped to the durable range `[earliest_retained, head]`, reusing the broker's exact dual-slot
/// CRC checkpoint + `AckCursor` snapshot codecs. The broker MUST be STOPPED: this takes the same
/// exclusive data-dir lock `serve` holds and refuses (exit 5) if a broker is running, so a reset
/// can never race a live writer. An out-of-range explicit offset is rejected (exit 1).
///
/// # Errors
/// [`CliError::Usage`] for a bad flag, a missing `--data-dir`/`--group`/`--to`, or an out-of-range
/// target; [`CliError::NotFound`] (exit 2) if the data dir is absent; [`CliError::Unreachable`]
/// (exit 5) if a broker holds the lock; [`CliError::Corrupt`] (exit 4) if the chain is unreadable;
/// [`CliError::Internal`] (exit 70) on an IO fault.
fn run_admin_consumer_reset(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut group: Option<String> = None;
    let mut to: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--group" => group = Some(take_value("--group", args, &mut i)?),
            "--to" => to = Some(take_value("--to", args, &mut i)?),
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for admin consumer-reset"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "admin consumer-reset takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir = data_dir.ok_or_else(|| {
        CliError::Usage("admin consumer-reset requires `--data-dir <dir>`".to_string())
    })?;
    // The group is REQUIRED but may be the empty string (the default group): an operator must name
    // the group explicitly so a reset is never applied to the wrong cursor by omission. Pass
    // `--group ""` for the default group.
    let group = group.ok_or_else(|| {
        CliError::Usage(
            "admin consumer-reset requires `--group <name>` (use --group \"\" for the default group)"
                .to_string(),
        )
    })?;
    let to = to.ok_or_else(|| {
        CliError::Usage("admin consumer-reset requires `--to <offset|earliest|latest>`".to_string())
    })?;
    let target = parse_reset_target(&to)?;
    cmd_admin_consumer_reset(Path::new(&data_dir), &group, target, json, out)
}

/// Parses an `admin consumer-reset --to` value: a bare unsigned offset, or the `earliest`/`latest`
/// keywords (case-insensitive), into a storage [`ResetTarget`]. A non-numeric, non-keyword value is
/// a usage error naming the offending input. Platform-independent (pure string parsing into a plain
/// enum); only the data-dir mutation it feeds is Unix-gated.
fn parse_reset_target(raw: &str) -> Result<ResetTarget, CliError> {
    match raw.to_ascii_lowercase().as_str() {
        "earliest" => Ok(ResetTarget::Earliest),
        "latest" => Ok(ResetTarget::Latest),
        _ => raw.parse::<u64>().map(ResetTarget::Offset).map_err(|_| {
            CliError::Usage(format!(
                "`--to` needs an offset, `earliest`, or `latest`, got `{raw}`"
            ))
        }),
    }
}

/// Parses and runs `admin dlq-redrive` (#299): the OFFLINE DLQ redrive. It re-injects the
/// dead-lettered records from the durable DLQ sink (`dlq/`) back onto the main log, crash-safely
/// (append+fsync the records, then advance a durable redrive watermark) and idempotently (a re-run
/// after a completed redrive re-injects nothing). The broker MUST be STOPPED: it takes the
/// exclusive data-dir lock and refuses (exit 5) if a broker is running.
///
/// # Errors
/// [`CliError::Usage`] for a bad flag or a missing `--data-dir`; [`CliError::NotFound`] (exit 2)
/// if the data dir is absent; [`CliError::Unreachable`] (exit 5) if a broker holds the lock;
/// [`CliError::Corrupt`] (exit 4) if the chain is unreadable; [`CliError::Internal`] (exit 70) on
/// an IO fault.
fn run_admin_dlq_redrive(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for admin dlq-redrive"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "admin dlq-redrive takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir = data_dir.ok_or_else(|| {
        CliError::Usage("admin dlq-redrive requires `--data-dir <dir>`".to_string())
    })?;
    cmd_admin_dlq_redrive(Path::new(&data_dir), json, out)
}

/// Fetches and renders the `/admin` v1 view (#15, #99). Kept apart from [`run_admin`] (the flag
/// parser) so the fetch-parse-render pipeline is callable directly.
fn cmd_admin(health_addr: &str, out: &mut impl Write) -> Result<(), CliError> {
    let body = admin::fetch_admin(health_addr).map_err(|e| match e {
        admin::AdminError::Unreachable(m) => CliError::Unreachable(m),
        admin::AdminError::Protocol(m) => CliError::Internal(m),
    })?;
    let view = admin::parse_admin_v1(&body).map_err(|e| CliError::Internal(e.to_string()))?;
    write!(out, "{}", admin::render_admin_view(&view))?;
    Ok(())
}

/// Parses and runs `peek`: show a bounded window of durable records from a data directory, with
/// no server running.
///
/// # Errors
/// Returns a [`CliError`] for a usage problem, a missing directory (not found), a corrupt
/// segment chain (corrupt), or an IO failure (internal).
fn run_peek(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut from_offset: u64 = 0;
    let mut limit: u64 = DEFAULT_PEEK_LIMIT;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--from-offset" | "--offset" => {
                let raw = take_value("--from-offset", args, &mut i)?;
                from_offset = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--from-offset` needs a number, got `{raw}`"))
                })?;
            }
            "--limit" => {
                let raw = take_value("--limit", args, &mut i)?;
                limit = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--limit` needs a number, got `{raw}`"))
                })?;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for peek")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "peek takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("peek requires `--data-dir <dir>`".to_string()))?;
    cmd_inspect(Path::new(&data_dir), from_offset, Some(limit), json, out)
}

/// Parses and runs `dump`: stream every durable record from a data directory, one per line
/// (NDJSON with `--json`), with no server running, honoring `--limit`.
///
/// # Errors
/// As [`run_peek`].
fn run_dump(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut limit: Option<u64> = None;
    let mut json = false;
    let mut dlq = false;
    let mut raw = false;
    let mut require_dict = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--limit" => {
                let raw = take_value("--limit", args, &mut i)?;
                limit = Some(raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--limit` needs a number, got `{raw}`"))
                })?);
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--dlq" => {
                dlq = true;
                i += 1;
            }
            // The committed compression-inspection surface (#92), gated on on-disk compression
            // (#12). Today the codec is always `none`, so `--raw` (show the on-disk frame) renders
            // the same field set as the decoded form, and `--require-dict` (fail strictly on a
            // missing dictionary) never trips because no record carries a dictionary id. The flags
            // are accepted now so a script written against the frozen surface keeps working once
            // #12 lands; they are documented as gated, not faked.
            "--raw" => {
                raw = true;
                i += 1;
            }
            "--require-dict" => {
                require_dict = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for dump")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "dump takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("dump requires `--data-dir <dir>`".to_string()))?;
    // `--raw` and `--require-dict` are meaningless against the DLQ sink (it has no compressed
    // frames either), so reject the combination as a usage error rather than silently ignore it.
    if dlq && (raw || require_dict) {
        return Err(CliError::Usage(
            "`--raw`/`--require-dict` are not valid with `--dlq`".to_string(),
        ));
    }
    if dlq {
        return cmd_inspect_dlq(Path::new(&data_dir), limit, json, out);
    }
    // `raw`/`require_dict` are inert until #12 (codec is always `none`); they are threaded through
    // so the dispatch records the frozen surface without faking compression.
    let _ = (raw, require_dict);
    cmd_inspect(Path::new(&data_dir), 0, limit, json, out)
}

/// Parses and runs `scrub` (#92): a strictly READ-ONLY offline full integrity scan of the data dir,
/// sharing the recovery decode path. It reports every corruption/torn-tail/checksum issue it finds
/// (the plan) and marks, never hides, what recovery would quarantine; it NEVER writes.
///
/// # Errors
/// [`CliError::Usage`] for a bad flag or a missing `--data-dir`; [`CliError::NotFound`] (exit 2) if
/// the data dir is absent; [`CliError::Corrupt`] (exit 4) if the chain is structurally unreadable;
/// [`CliError::HandledCorruption`] (exit 3) if it found and reported real data-loss corruption (a
/// torn-tail-only result stays exit 0).
fn run_scrub(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for scrub")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "scrub takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("scrub requires `--data-dir <dir>`".to_string()))?;
    cmd_scrub(Path::new(&data_dir), json, out)
}

/// Parses and runs `repair` (#92): defaults to the SAME read-only plan as `scrub` (print what it
/// WOULD do, change nothing). `--apply` performs the repair under the exclusive data-dir lock:
/// quarantine-not-delete any corrupt span, truncate to the longest valid prefix exactly as recovery
/// does, preserving the data dir's uid/gid/mode. Unix-only (the on-disk storage is Unix-only in v1).
///
/// # Errors
/// [`CliError::Usage`] for a bad flag or a missing `--data-dir`; [`CliError::NotFound`] (exit 2) if
/// the data dir is absent; [`CliError::Unreachable`] (exit 5) if a broker holds the data-dir lock;
/// [`CliError::Corrupt`] (exit 4) if the chain is structurally unreadable; [`CliError::Internal`]
/// (exit 70) on an IO fault; [`CliError::HandledCorruption`] (exit 3) if it found and reported (plan)
/// or quarantined (`--apply`) real data-loss corruption (a torn-tail-only result stays exit 0).
fn run_repair(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut json = false;
    let mut apply = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--json" => {
                json = true;
                i += 1;
            }
            "--apply" => {
                apply = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for repair")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "repair takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir = data_dir
        .ok_or_else(|| CliError::Usage("repair requires `--data-dir <dir>`".to_string()))?;
    cmd_repair(Path::new(&data_dir), apply, json, out)
}

/// Parses and runs `bench` (#94): the publish / subscribe / round-trip load generator with the
/// production-safety and flash-endurance guards. Parsing (and the guards) are platform-neutral; the
/// load run is Unix-only (the on-disk broker is Unix-only in v1), so the run is dispatched through a
/// cfg-gated `cmd_bench`.
///
/// # Errors
/// Returns [`CliError::Usage`] for a bad flag, a missing required bound, an unacknowledged live
/// target, or an unacknowledged non-bench group; [`CliError::Unreachable`] if a live broker is
/// down; or [`CliError::Internal`] for a run failure or a synthetic-directory cleanup failure.
fn run_bench(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    // A fresh random suffix names the isolated synthetic data dir and consumer group, so two
    // concurrent bench runs never collide and the name is recognizable as bench-owned. Parsing and
    // rendering are cross-platform; the load run inside `bench::run` is the Unix-only seam (it errors
    // on a non-Unix host), so the renderers always have a live caller and the Windows build stays
    // warning-clean under `-D warnings` (the #99/#288 cfg(not(unix)) field-read footgun, avoided by
    // keeping the renderers' caller cross-platform rather than gating the whole module out).
    let config = bench::parse_bench(args, &random_suffix())?;
    bench::run(&config, out)
}

/// A short random-ish hex suffix for the synthetic bench namespace. Combines the process id, a
/// monotonic clock reading, and a per-call atomic counter, mixed with a small hash, so two runs in
/// the same process and two processes never collide on the temp-dir/group name. This is a
/// uniqueness aid for an isolated namespace, not a security primitive, so no `rand` dependency is
/// pulled onto the shipped binary's graph.
fn random_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = u64::from(std::process::id());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    let seq = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    // A cheap splitmix64-style mix so the suffix looks random and a coarse clock plus a small pid
    // still spread out.
    let mut x = pid
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(nanos)
        .wrapping_add(seq.wrapping_mul(0xBF58_476D_1CE4_E5B9));
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    format!("{x:016x}")
}

/// Parses and runs `upgrade`: atomically swap an already-verified new binary over the live one,
/// retaining the prior binary as `<dest>.prev` (#104). The download/verify is the fail-closed
/// `scripts/install.sh`; this verb is the post-verify atomic swap, so it never weakens
/// verify-before-install. Unix-only (atomic `rename(2)`); the non-Unix `cmd_upgrade` stub errors.
///
/// # Errors
/// [`CliError::Usage`] for a missing `--new-binary`/`--dest` or a bad flag; [`CliError::Internal`]
/// on an IO fault during the swap.
fn run_upgrade(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut new_binary: Option<String> = None;
    let mut dest: Option<String> = None;
    let mut max_failed_starts: Option<u32> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--new-binary" => new_binary = Some(take_value("--new-binary", args, &mut i)?),
            "--dest" => dest = Some(take_value("--dest", args, &mut i)?),
            "--max-failed-starts" => {
                max_failed_starts = Some(take_number("--max-failed-starts", args, &mut i)?);
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for upgrade"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "upgrade takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let new_binary = new_binary
        .ok_or_else(|| CliError::Usage("upgrade requires `--new-binary <path>`".to_string()))?;
    let dest =
        dest.ok_or_else(|| CliError::Usage("upgrade requires `--dest <path>`".to_string()))?;
    cmd_upgrade(
        Path::new(&new_binary),
        Path::new(&dest),
        max_failed_starts,
        out,
    )
}

/// Parses and runs `rollback`: restore `<dest>.prev` over the live binary (#104), the one-command
/// rollback to the last known-good bytes. Unix-only; the non-Unix `cmd_rollback` stub errors.
///
/// # Errors
/// [`CliError::Usage`] for a missing `--dest`; [`CliError::Internal`] if there is no `.prev` to
/// restore or on an IO fault during the swap.
fn run_rollback(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut dest: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dest" => dest = Some(take_value("--dest", args, &mut i)?),
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for rollback"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "rollback takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let dest =
        dest.ok_or_else(|| CliError::Usage("rollback requires `--dest <path>`".to_string()))?;
    cmd_rollback(Path::new(&dest), out)
}

/// The action `record-start` performs on the consecutive-failed-start counter (#104). Exactly one is
/// chosen per invocation; the systemd unit drives all three at the three lifecycle points.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RecordStartMode {
    /// Bump the counter by one (`ExecStopPost` on a non-clean exit: the SINGLE increment source).
    Failed,
    /// Clear the counter (`ExecStartPost` once the broker is confirmed up: a healthy start).
    Ok,
    /// Consult the counter WITHOUT changing it (`ExecStartPre`: report whether to roll back). A
    /// consult never bumps, so a healthy node losing power uncleanly cannot accumulate a rollback.
    Check,
}

/// Parses and runs `record-start`: drive the consecutive-failed-start counter the systemd unit uses
/// to fall back after N failures (#104). `--failed` bumps it, `--ok` clears it, `--check` only
/// consults it (no mutation). Exactly one mode is required. Unix-only.
///
/// # Errors
/// [`CliError::Usage`] for a missing `--dest` or anything other than exactly one of
/// `--failed`/`--ok`/`--check`; [`CliError::Internal`] on an IO fault updating the counter.
fn run_record_start(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut dest: Option<String> = None;
    let mut failed = false;
    let mut ok = false;
    let mut check = false;
    let mut max_failed_starts: Option<u32> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dest" => dest = Some(take_value("--dest", args, &mut i)?),
            "--failed" => {
                failed = true;
                i += 1;
            }
            "--ok" => {
                ok = true;
                i += 1;
            }
            "--check" => {
                check = true;
                i += 1;
            }
            "--max-failed-starts" => {
                max_failed_starts = Some(take_number("--max-failed-starts", args, &mut i)?);
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for record-start"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "record-start takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let dest =
        dest.ok_or_else(|| CliError::Usage("record-start requires `--dest <path>`".to_string()))?;
    let mode = match (failed, ok, check) {
        (true, false, false) => RecordStartMode::Failed,
        (false, true, false) => RecordStartMode::Ok,
        (false, false, true) => RecordStartMode::Check,
        _ => {
            return Err(CliError::Usage(
                "record-start requires exactly one of `--failed`, `--ok`, or `--check`".to_string(),
            ));
        }
    };
    cmd_record_start(Path::new(&dest), mode, max_failed_starts, out)
}

/// Parses and runs `migrate`: gate an on-disk format bump so it is NEVER silent (#104, #132). Within
/// a major version the data dir opens with no migration; a future format bump is refused without an
/// explicit `--allow <to-version>`. Unix-only (it reads the on-disk segments); the non-Unix
/// `cmd_migrate` stub errors.
///
/// # Errors
/// [`CliError::Usage`] for a missing `--data-dir`, a bad `--allow` value, or a refused silent bump;
/// [`CliError::NotFound`] if the data dir is absent; [`CliError::Corrupt`] / [`CliError::Internal`]
/// per the offline read.
fn run_migrate(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut allow: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--allow" => allow = Some(take_number("--allow", args, &mut i)?),
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for migrate"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "migrate takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir = data_dir
        .ok_or_else(|| CliError::Usage("migrate requires `--data-dir <dir>`".to_string()))?;
    cmd_migrate(Path::new(&data_dir), allow, out)
}

/// Decodes a data directory offline and writes its durable records (from `from_offset`, at most
/// `limit` of them) to `out`, then a final note for any torn or corrupt tail recovery would
/// skip, so the holes are shown, not hidden. Shared by `peek` (a bounded window) and `dump`
/// (the whole log). Memory is bounded to one segment at a time; a per-record streaming reader
/// for a multi-GB segment within a fixed RAM ceiling is tracked in #92.
#[cfg(unix)]
fn cmd_inspect(
    data_dir: &Path,
    from_offset: u64,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reader = OfflineReader::open(StdFs::new(data_dir.to_path_buf()))
        .map_err(|e| map_offline_err(data_dir, &e))?;
    let mut shown: u64 = 0;
    'segments: for &id in reader.segment_ids() {
        if limit.is_some_and(|max| shown >= max) {
            break;
        }
        let records = reader
            .read_segment(id)
            .map_err(|e| map_offline_err(data_dir, &e))?;
        for record in &records {
            if record.offset.get() < from_offset {
                continue;
            }
            if limit.is_some_and(|max| shown >= max) {
                break 'segments;
            }
            write_record(record, json, out)?;
            shown += 1;
        }
    }
    write_loss(reader.loss_report(), json, out)?;
    Ok(())
}

/// Writes one record as a human line or a single NDJSON object. `crc` is always `ok` because
/// the offline reader only yields records that passed their CRC; `codec` is always `none`
/// until on-disk compression (#12) lands.
#[cfg(unix)]
fn write_record(record: &OwnedRecord, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    if json {
        writeln!(
            out,
            "{{\"offset\":{},\"ts_ms\":{},\"bytes\":{},\"key_bytes\":{},\"crc\":\"ok\",\"codec\":\"none\"}}",
            record.offset.get(),
            record.timestamp_ms,
            record.payload.len(),
            record.key.len(),
        )?;
    } else {
        writeln!(
            out,
            "offset={} ts_ms={} bytes={} key_bytes={} crc=ok codec=none",
            record.offset.get(),
            record.timestamp_ms,
            record.payload.len(),
            record.key.len(),
        )?;
    }
    Ok(())
}

/// Writes a final summary of any torn or corrupt tail the durable prefix dropped (marking the
/// holes, not hiding them). Nothing is written for a clean directory, so a clean `dump --json`
/// stays pure record NDJSON.
#[cfg(unix)]
fn write_loss(report: &LossReport, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    if report.is_empty() {
        return Ok(());
    }
    if json {
        write!(
            out,
            "{{\"loss\":{{\"bytes\":{},\"events\":[",
            report.total_bytes_skipped()
        )?;
        for (n, e) in report.events.iter().enumerate() {
            if n > 0 {
                write!(out, ",")?;
            }
            write!(
                out,
                "{{\"segment\":{},\"start\":{},\"end\":{},\"reason\":\"{}\"}}",
                e.segment_id,
                e.byte_offset_start,
                e.byte_offset_end,
                e.reason_code.metric_label(),
            )?;
        }
        writeln!(out, "]}}}}")?;
    } else {
        writeln!(
            out,
            "note: {} byte(s) past the durable head are torn or corrupt and were not shown ({} event(s))",
            report.total_bytes_skipped(),
            report.events.len(),
        )?;
        for e in &report.events {
            writeln!(
                out,
                "  segment {} bytes [{}, {}) reason={}",
                e.segment_id,
                e.byte_offset_start,
                e.byte_offset_end,
                e.reason_code.metric_label(),
            )?;
        }
    }
    Ok(())
}

/// Decodes a stopped broker's DURABLE DEAD-LETTER SINK (the `dlq/` subdirectory) offline and writes
/// its dead-letter records (at most `limit` of them) to `out`, READ-ONLY, never mutating the
/// directory (#63). Each line shows the DLQ position, the source offset, the original timestamp, the
/// group, the attempt, and the key/payload lengths. An ABSENT or empty DLQ shows nothing (a clean,
/// never-poisoned broker), which is not an error. Reuses the same offline reader as `dump`, so the
/// frozen offline exit codes apply (a missing DATA directory is still not-found).
#[cfg(unix)]
fn cmd_inspect_dlq(
    data_dir: &Path,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    // A missing DATA directory is not-found (exit 2), matching plain `dump`; an absent `dlq/`
    // subdirectory inside an existing data directory is simply an empty DLQ (shown as nothing).
    if !data_dir.is_dir() {
        return Err(CliError::NotFound(format!(
            "no data directory at {}",
            data_dir.display()
        )));
    }
    let entries = read_dlq_entries(&StdFs::new(data_dir.to_path_buf()))
        .map_err(|e| map_offline_err(data_dir, &e))?;
    // `--limit` caps how many records are shown; `usize::MAX` (no limit) shows them all.
    let cap = limit.map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
    for entry in entries.iter().take(cap) {
        write_dlq_entry(entry, json, out)?;
    }
    Ok(())
}

/// Writes one DLQ entry as a human line or a single NDJSON object. Like `write_record`, this
/// reports only sizes (not the raw key/payload bytes), so a binary payload never corrupts the
/// terminal or the NDJSON stream.
#[cfg(unix)]
fn write_dlq_entry(entry: &DlqEntry, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    if json {
        writeln!(
            out,
            "{{\"dlq_offset\":{},\"source_offset\":{},\"group\":\"{}\",\"attempt\":{},\"ts_ms\":{},\"bytes\":{},\"key_bytes\":{}}}",
            entry.dlq_offset.get(),
            entry.source_offset,
            escape_json(&entry.group),
            entry.attempt,
            entry.timestamp_ms,
            entry.payload.len(),
            entry.key.len(),
        )?;
    } else {
        writeln!(
            out,
            "dlq_offset={} source_offset={} group={:?} attempt={} ts_ms={} bytes={} key_bytes={}",
            entry.dlq_offset.get(),
            entry.source_offset,
            entry.group,
            entry.attempt,
            entry.timestamp_ms,
            entry.payload.len(),
            entry.key.len(),
        )?;
    }
    Ok(())
}

/// Escapes a string for embedding in a JSON string literal (backslash, double-quote, and the
/// control characters the format requires). Group names are graphic ASCII today, but the escape is
/// unconditional so a future relaxation cannot produce invalid NDJSON.
#[cfg(unix)]
fn escape_json(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // A writeln/write into a String never fails, so the result is discarded.
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Maps an offline-reader storage error to the frozen offline exit-code scheme: a missing data
/// directory is not-found (2), a broken segment chain or an undecodable header is corruption
/// (4), and anything else is an internal failure (70).
#[cfg(unix)]
fn map_offline_err(data_dir: &Path, e: &StorageError) -> CliError {
    let at = data_dir.display();
    match e {
        StorageError::Io(io) if io.kind() == io::ErrorKind::NotFound => {
            CliError::NotFound(format!("no data directory at {at}"))
        }
        StorageError::Io(io) => CliError::Internal(format!("reading {at}: {io}")),
        StorageError::Record(_)
        | StorageError::Segment(_)
        | StorageError::FooterSegmentMismatch { .. }
        | StorageError::UnsealedPredecessor { .. }
        | StorageError::SegmentIdMismatch { .. }
        | StorageError::SegmentChainBroken { .. } => {
            CliError::Corrupt(format!("corrupt data directory at {at}: {e}"))
        }
        other => CliError::Internal(format!("reading {at}: {other}")),
    }
}

/// The current schema version of the `scrub` `--json` result object (`ironbus.cli.scrub.vN`),
/// per [`docs/CLI_CONTRACT.md`]. A new OPTIONAL field is additive (no bump); a field
/// rename/removal/type-change bumps this. Registered in `docs/compat/versions.md`.
#[cfg(unix)]
const SCRUB_SCHEMA_VERSION: u32 = 1;
/// The current schema version of the `repair` `--json` result object (`ironbus.cli.repair.vN`),
/// per [`docs/CLI_CONTRACT.md`]. Same bump rule as [`SCRUB_SCHEMA_VERSION`].
#[cfg(unix)]
const REPAIR_SCHEMA_VERSION: u32 = 1;

/// Runs `scrub` (#92): a strictly READ-ONLY offline full integrity scan of the data dir, sharing the
/// recovery decode path ([`OfflineReader`]). It opens the directory read-only (which NEVER mutates
/// it: no truncation, no roll, no segment creation), computes the loss report exactly as recovery
/// would, renders the plan (human or `--json` `ironbus.cli.scrub.v1`), and maps the outcome to the
/// frozen exit scheme.
///
/// Exit mapping (the exit-code-3 gate, `docs/CLI_CONTRACT.md`):
/// - `0`: the directory is clean, OR its only skip is an expected `TornTail` brownout truncation (a
///   reported skip that is NOT data loss, per [`ReasonCode::is_data_loss`]).
/// - `3` ([`CliError::HandledCorruption`]): the scan FINISHED and found one or more real data-loss
///   spans (a corruption skip). The plan is on stdout; the code communicates the degraded finding.
/// - `2` ([`CliError::NotFound`]): the data dir is missing.
/// - `4` ([`CliError::Corrupt`]): the chain is structurally unreadable (BLOCKED, distinct from 3).
///
/// It is strictly read-only: the only storage call is [`OfflineReader::open`], which the storage
/// crate documents (and a test here proves) never writes.
#[cfg(unix)]
fn cmd_scrub(data_dir: &Path, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    let reader = OfflineReader::open(StdFs::new(data_dir.to_path_buf()))
        .map_err(|e| map_offline_err(data_dir, &e))?;
    let report = reader.loss_report();
    let plan = ScrubPlan::from_report(report, reader.segment_ids().len());
    write_scrub_result(data_dir, &plan, json, out)?;
    // Exit 3 ONLY for real data loss; a torn-tail-only result stays exit 0 (the loss-report
    // data-loss boundary, the same one recovery and the quarantine store use). The structured
    // result has already been written above, so the non-zero return only carries the exit code.
    if plan.data_loss_bytes > 0 {
        return Err(CliError::HandledCorruption(plan.summary("scrub", false)));
    }
    Ok(())
}

/// Runs `repair` (#92). Without `--apply` it is `scrub` re-labeled: the SAME read-only plan (open
/// read-only, compute the loss report, print what it WOULD do, change nothing). With `--apply` it
/// performs the repair, which is recovery made explicit and offline:
///
/// 1. Acquire the EXCLUSIVE data-dir lock ([`dirlock::DirLock`], the same lock `serve` holds). If a
///    broker holds it, fail fast with exit 5 ([`CliError::Unreachable`]) and change nothing, so
///    `--apply` can never race a live writer and corrupt the MANIFEST.
/// 2. Run recovery via [`Log::open`], which QUARANTINES (copies to `quarantine/`, never deletes) any
///    corrupt span BEFORE truncating it, truncates the active segment to the longest valid prefix,
///    and uses the atomic write-temp+fsync+rename + dir-fsync discipline for every file it rewrites.
///    It NEVER edits a sealed segment in place and NEVER makes the data less recoverable than
///    recovery already would (it IS recovery). The data dir's uid/gid/mode are preserved because
///    recovery only truncates EXISTING files in place; it never recreates the directory.
///
/// The exit mapping matches [`cmd_scrub`]; additionally an apply that races a broker is exit 5, and
/// an IO fault during apply is exit 70.
#[cfg(unix)]
fn cmd_repair(
    data_dir: &Path,
    apply: bool,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    if !apply {
        // Read-only by default: the plan, computed exactly as scrub computes it, changing nothing.
        let reader = OfflineReader::open(StdFs::new(data_dir.to_path_buf()))
            .map_err(|e| map_offline_err(data_dir, &e))?;
        let plan = ScrubPlan::from_report(reader.loss_report(), reader.segment_ids().len());
        write_repair_result(data_dir, &plan, false, json, out)?;
        if plan.data_loss_bytes > 0 {
            return Err(CliError::HandledCorruption(plan.summary("repair", false)));
        }
        return Ok(());
    }

    // `--apply`: take the EXCLUSIVE lock FIRST, so a running broker (which holds it) blocks us with a
    // fail-fast exit 5 rather than letting two writers touch one log. `prepare_data_dir` rejects a
    // non-directory path and a missing dir maps to not-found (exit 2), matching scrub. The lock is
    // released by close(2) when `_lock` drops at the end of this function (or on any early return).
    if !data_dir.exists() {
        return Err(CliError::NotFound(format!(
            "no data directory at {}",
            data_dir.display()
        )));
    }
    dirlock::prepare_data_dir(data_dir).map_err(|e| map_dir_error(&e))?;
    let _lock = dirlock::DirLock::acquire(data_dir).map_err(|e| match e {
        // A broker holding the lock is the fail-fast contention case the issue maps to exit 5
        // (unreachable): repair refuses to touch a live broker's data dir. This is the ONE place
        // `AlreadyLocked` is exit 5 rather than `serve`'s exit-70 double-open guard.
        dirlock::DirError::AlreadyLocked(_) => CliError::Unreachable(format!(
            "cannot repair {}: a broker holds its exclusive lock (stop the broker first)",
            data_dir.display()
        )),
        other => map_dir_error(&other),
    })?;

    // Recovery made explicit: `Log::open` quarantines each corrupt span (copy, not move), truncates
    // to the longest valid prefix with the atomic fsync discipline, and preserves the directory in
    // place. The default config is the documented recovery baseline (64 MiB segment cap, the default
    // quarantine budget); repair never makes the data LESS recoverable than this. A structural fault
    // maps to exit 4 (blocked), an I3 cap breach the same (recovery itself would refuse), an IO
    // fault to exit 70.
    let recovered = ironbus_storage::log::Log::open(
        StdFs::new(data_dir.to_path_buf()),
        SystemClock::new(),
        LogConfig::default(),
    )
    .map_err(|e| map_offline_err(data_dir, &e))?;
    let plan = ScrubPlan::from_report(recovered.loss_report(), recovered.segment_count());
    // Drop the recovered log (releasing its file handles) BEFORE reporting, so nothing dangles.
    drop(recovered);
    write_repair_result(data_dir, &plan, true, json, out)?;
    if plan.data_loss_bytes > 0 {
        return Err(CliError::HandledCorruption(plan.summary("repair", true)));
    }
    Ok(())
}

/// The structured plan a `scrub`/`repair` run produces: the segment count it scanned, and the loss
/// the durable prefix dropped, split into the data-loss total (corruption, the exit-3 trigger) and
/// the torn-tail total (a reported skip that is NOT data loss). Built from the recovery
/// [`LossReport`] so the offline plan and the broker's next-start recovery agree on every span.
#[cfg(unix)]
struct ScrubPlan {
    /// How many segments the scan walked.
    segments: usize,
    /// The number of skip spans the report carries (corruption + torn tail).
    skipped_spans: usize,
    /// The total bytes of real DATA loss (the exit-3 trigger): the sum over events whose reason
    /// [`ReasonCode::is_data_loss`], i.e. every reason EXCEPT `TornTail`.
    data_loss_bytes: u64,
    /// The total bytes of torn/unsynced tail skipped (a reported skip, NOT data loss).
    torn_tail_bytes: u64,
    /// The number of spans that are real data loss (corruption skips).
    data_loss_spans: usize,
    /// The per-event spans, copied so the renderer does not borrow the report.
    events: Vec<ScrubEvent>,
}

/// One loss span in a [`ScrubPlan`], flattened from a [`ironbus_storage::loss::LossEvent`] for
/// rendering (the segment, the byte span, the reason label, and whether it counts as data loss).
#[cfg(unix)]
struct ScrubEvent {
    segment_id: u64,
    start: u64,
    end: u64,
    reason: &'static str,
    is_data_loss: bool,
}

#[cfg(unix)]
impl ScrubPlan {
    /// Builds the plan from a recovery [`LossReport`] and the scanned segment count, classifying
    /// each span by [`ReasonCode::is_data_loss`] so a torn-tail-only report yields
    /// `data_loss_bytes == 0` (exit 0) while any corruption span trips the exit-3 total.
    fn from_report(report: &LossReport, segments: usize) -> ScrubPlan {
        let events: Vec<ScrubEvent> = report
            .events
            .iter()
            .map(|e| ScrubEvent {
                segment_id: e.segment_id,
                start: e.byte_offset_start,
                end: e.byte_offset_end,
                reason: e.reason_code.metric_label(),
                is_data_loss: e.reason_code.is_data_loss(),
            })
            .collect();
        let data_loss_spans = events.iter().filter(|e| e.is_data_loss).count();
        ScrubPlan {
            segments,
            skipped_spans: report.events.len(),
            data_loss_bytes: report.data_loss_bytes(),
            torn_tail_bytes: report
                .total_bytes_skipped()
                .saturating_sub(report.data_loss_bytes()),
            data_loss_spans,
            events,
        }
    }

    /// `true` if the scan found nothing to report (a clean directory).
    fn is_clean(&self) -> bool {
        self.skipped_spans == 0
    }

    /// A one-line informational summary for the [`CliError::HandledCorruption`] message (exit 3) and
    /// the human stdout line. `applied` distinguishes a repair that quarantined-and-truncated from a
    /// scrub/plan that only reported.
    fn summary(&self, command: &str, applied: bool) -> String {
        let verb = if applied {
            "quarantined"
        } else {
            "would quarantine"
        };
        format!(
            "{command} {verb} {} corrupt span(s), {} byte(s) of data loss ({} torn-tail byte(s) excluded)",
            self.data_loss_spans, self.data_loss_bytes, self.torn_tail_bytes,
        )
    }
}

/// Writes the `scrub` result: the human plan (or the `ironbus.cli.scrub.v1` `--json` object). The
/// JSON object is emitted on EVERY exit path (clean exit 0 AND the exit-3 data-loss path), per the
/// `--json` contract, carrying the `exit_code` it is about to return.
#[cfg(unix)]
fn write_scrub_result(
    data_dir: &Path,
    plan: &ScrubPlan,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let exit_code = if plan.data_loss_bytes > 0 {
        EXIT_HANDLED_CORRUPTION
    } else {
        0
    };
    if json {
        write_plan_json(
            out,
            "ironbus.cli.scrub",
            SCRUB_SCHEMA_VERSION,
            data_dir,
            plan,
            None,
            exit_code,
        )
    } else {
        write_plan_human(out, "scrub", data_dir, plan, None)
    }
}

/// Writes the `repair` result: the human plan (or the `ironbus.cli.repair.v1` `--json` object),
/// labeling whether `--apply` mutated the directory. `applied=false` is the read-only plan (what it
/// WOULD do); `applied=true` reports what it DID (quarantined and truncated under the lock).
#[cfg(unix)]
fn write_repair_result(
    data_dir: &Path,
    plan: &ScrubPlan,
    applied: bool,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let exit_code = if plan.data_loss_bytes > 0 {
        EXIT_HANDLED_CORRUPTION
    } else {
        0
    };
    if json {
        write_plan_json(
            out,
            "ironbus.cli.repair",
            REPAIR_SCHEMA_VERSION,
            data_dir,
            plan,
            Some(applied),
            exit_code,
        )
    } else {
        write_plan_human(out, "repair", data_dir, plan, Some(applied))
    }
}

/// Renders a scrub/repair plan as a human report: a header line (clean or a damage count), then one
/// indented line per span, then for `repair` an applied/plan line. Wording is NOT a stability
/// contract (only `--json` is); a script should pass `--json` and key off `schema`.
#[cfg(unix)]
fn write_plan_human(
    out: &mut impl Write,
    command: &str,
    data_dir: &Path,
    plan: &ScrubPlan,
    applied: Option<bool>,
) -> Result<(), CliError> {
    if plan.is_clean() {
        writeln!(
            out,
            "{command}: {} is clean ({} segment(s) scanned, no corruption or torn tail)",
            data_dir.display(),
            plan.segments,
        )?;
        if let Some(false) = applied {
            writeln!(
                out,
                "  nothing to repair (read-only plan; pass --apply to act)"
            )?;
        }
        return Ok(());
    }
    writeln!(
        out,
        "{command}: {} segment(s) scanned, {} skip span(s): {} byte(s) of data loss, {} torn-tail byte(s) (not data loss)",
        plan.segments, plan.skipped_spans, plan.data_loss_bytes, plan.torn_tail_bytes,
    )?;
    for e in &plan.events {
        let kind = if e.is_data_loss {
            "data-loss"
        } else {
            "torn-tail (no data loss)"
        };
        writeln!(
            out,
            "  segment {} bytes [{}, {}) reason={} {kind}",
            e.segment_id, e.start, e.end, e.reason,
        )?;
    }
    match applied {
        None => {}
        Some(true) => {
            writeln!(
                out,
                "  applied: quarantined the corrupt span(s) to quarantine/ and truncated to the longest valid prefix",
            )?;
        }
        Some(false) => {
            writeln!(
                out,
                "  read-only plan: --apply would quarantine the corrupt span(s) to quarantine/ and truncate to the longest valid prefix (nothing changed)",
            )?;
        }
    }
    Ok(())
}

/// Renders a scrub/repair plan as the single versioned `--json` result object
/// (`ironbus.cli.<command>.vN`). It carries the `schema`, the source `data_dir`, the segment count,
/// the skip/data-loss/torn-tail tallies, the per-span `events` array (the same field names as the
/// `ironbus.loss-report.v1` events so the CLI and recovery agree), the `exit_code` it is about to
/// return, and `ok` (true only on a clean exit-0 run). `repair` additionally carries `applied`.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn write_plan_json(
    out: &mut impl Write,
    schema_command: &str,
    schema_version: u32,
    data_dir: &Path,
    plan: &ScrubPlan,
    applied: Option<bool>,
    exit_code: u8,
) -> Result<(), CliError> {
    write!(
        out,
        "{{\"schema\":\"{schema_command}.v{schema_version}\",\"data_dir\":\"{}\",\"segments\":{},\"skipped_spans\":{},\"data_loss_spans\":{},\"data_loss_bytes\":{},\"torn_tail_bytes\":{},",
        escape_json(&data_dir.display().to_string()),
        plan.segments,
        plan.skipped_spans,
        plan.data_loss_spans,
        plan.data_loss_bytes,
        plan.torn_tail_bytes,
    )?;
    if let Some(applied) = applied {
        write!(out, "\"applied\":{applied},")?;
    }
    write!(out, "\"events\":[")?;
    for (n, e) in plan.events.iter().enumerate() {
        if n > 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"segment\":{},\"start\":{},\"end\":{},\"reason\":\"{}\",\"data_loss\":{}}}",
            e.segment_id, e.start, e.end, e.reason, e.is_data_loss,
        )?;
    }
    let ok = exit_code == 0;
    writeln!(out, "],\"ok\":{ok},\"exit_code\":{exit_code}}}")?;
    Ok(())
}

/// `scrub`/`repair` require Unix in v1 (the on-disk storage uses positioned IO the Windows path does
/// not yet implement), matching `serve`/`peek`/`dump`. The non-Unix stub consumes every parameter so
/// the Windows `-D warnings` build stays clean (the #99/#288 cfg(not(unix)) field-read footgun).
#[cfg(not(unix))]
fn cmd_scrub(data_dir: &Path, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    let _ = (data_dir, json, out);
    Err(CliError::Internal(
        "ironbus scrub requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// `repair` requires Unix in v1, for the same reason as `scrub` (and the exclusive `flock(2)` lock
/// and atomic `rename(2)` recovery discipline are POSIX). The stub consumes every parameter.
#[cfg(not(unix))]
fn cmd_repair(
    data_dir: &Path,
    apply: bool,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (data_dir, apply, json, out);
    Err(CliError::Internal(
        "ironbus repair requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// The current schema version of the `admin consumer-reset` `--json` result object
/// (`ironbus.cli.admin-consumer-reset.vN`), per [`docs/CLI_CONTRACT.md`]. Append-only: a new
/// OPTIONAL field is additive (no bump); a rename/removal/type-change bumps this. Registered in
/// `docs/compat/versions.md`.
#[cfg(unix)]
const ADMIN_CONSUMER_RESET_SCHEMA_VERSION: u32 = 1;
/// The current schema version of the `admin dlq-redrive` `--json` result object
/// (`ironbus.cli.admin-dlq-redrive.vN`). Same bump rule.
#[cfg(unix)]
const ADMIN_DLQ_REDRIVE_SCHEMA_VERSION: u32 = 1;

/// Maps a storage [`ironbus_storage::admin::AdminError`] onto the frozen CLI exit-code scheme: an
/// out-of-range reset target is a usage error (exit 1, the operator asked for an offset that does
/// not exist), and a storage fault is classified exactly as the read-only offline verbs classify it
/// (missing dir -> 2, corrupt chain -> 4, IO fault -> 70).
#[cfg(unix)]
fn map_admin_err(data_dir: &Path, e: ironbus_storage::admin::AdminError) -> CliError {
    use ironbus_storage::admin::AdminError;
    match e {
        AdminError::OutOfRange { .. } | AdminError::InvalidGroup(_) => {
            CliError::Usage(e.to_string())
        }
        AdminError::Storage(s) => map_offline_err(data_dir, &s),
    }
}

/// Takes the exclusive data-dir lock the way `repair --apply` does, so an offline mutating admin
/// verb (#299) can never race a LIVE broker: a running broker holds the lock, so this fails fast
/// with exit 5 and changes nothing (the broker-stopped contract). A missing dir is exit 2, a
/// non-directory or unwritable path the usual `map_dir_error` mapping. Returns the held lock, kept
/// alive for the caller's mutation and released by `close(2)` on drop.
#[cfg(unix)]
fn lock_stopped_broker(data_dir: &Path, verb: &str) -> Result<dirlock::DirLock, CliError> {
    if !data_dir.exists() {
        return Err(CliError::NotFound(format!(
            "no data directory at {}",
            data_dir.display()
        )));
    }
    dirlock::prepare_data_dir(data_dir).map_err(|e| map_dir_error(&e))?;
    dirlock::DirLock::acquire(data_dir).map_err(|e| match e {
        dirlock::DirError::AlreadyLocked(_) => CliError::Unreachable(format!(
            "cannot {verb} {}: a broker holds its exclusive lock (stop the broker first)",
            data_dir.display()
        )),
        other => map_dir_error(&other),
    })
}

/// Runs `admin consumer-reset` (#299): the OFFLINE consumer reset, under the exclusive data-dir
/// lock. Rewrites the group's durable cursor checkpoint to the resolved, range-clamped offset using
/// the broker's exact codecs, then writes the versioned result (human or
/// `ironbus.cli.admin-consumer-reset.v1`).
#[cfg(unix)]
fn cmd_admin_consumer_reset(
    data_dir: &Path,
    group: &str,
    target: ResetTarget,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    // Take the lock FIRST so a running broker blocks us (exit 5) before any read or write.
    let _lock = lock_stopped_broker(data_dir, "reset the consumer of")?;
    let (outcome, _fs) =
        ironbus_storage::admin::reset_consumer(StdFs::new(data_dir.to_path_buf()), group, target)
            .map_err(|e| map_admin_err(data_dir, e))?;
    write_consumer_reset_result(data_dir, group, &outcome, json, out)
}

/// Writes the `admin consumer-reset` result: the human line or the versioned
/// `ironbus.cli.admin-consumer-reset.v1` `--json` object. Emitted on the success path (exit 0); a
/// rejected target or a storage fault returned earlier as a typed error.
#[cfg(unix)]
fn write_consumer_reset_result(
    data_dir: &Path,
    group: &str,
    outcome: &ironbus_storage::admin::ResetOutcome,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    if json {
        write!(
            out,
            "{{\"schema\":\"ironbus.cli.admin-consumer-reset.v{ADMIN_CONSUMER_RESET_SCHEMA_VERSION}\",\"data_dir\":\"{}\",\"group\":\"{}\",\"committed\":{},",
            escape_json(&data_dir.display().to_string()),
            escape_json(group),
            outcome.committed,
        )?;
        match outcome.previous_committed {
            Some(p) => write!(out, "\"previous_committed\":{p},")?,
            None => write!(out, "\"previous_committed\":null,")?,
        }
        writeln!(
            out,
            "\"earliest_retained\":{},\"head\":{},\"ok\":true,\"exit_code\":0}}",
            outcome.earliest_retained, outcome.head,
        )?;
    } else {
        let group_label = if group.is_empty() {
            "(default)".to_string()
        } else {
            format!("{group:?}")
        };
        let from = outcome
            .previous_committed
            .map_or_else(|| "(none)".to_string(), |p| p.to_string());
        writeln!(
            out,
            "admin consumer-reset: group {group_label} cursor {from} -> {} (durable range [{}, {}])",
            outcome.committed, outcome.earliest_retained, outcome.head,
        )?;
    }
    Ok(())
}

/// Runs `admin dlq-redrive` (#299): the OFFLINE DLQ redrive, under the exclusive data-dir lock.
/// Re-injects the un-redriven DLQ records onto the main log crash-safely and idempotently, then
/// writes the versioned result (human or `ironbus.cli.admin-dlq-redrive.v1`).
#[cfg(unix)]
fn cmd_admin_dlq_redrive(
    data_dir: &Path,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _lock = lock_stopped_broker(data_dir, "redrive the DLQ of")?;
    let (outcome, _fs) = ironbus_storage::admin::redrive_dlq(
        StdFs::new(data_dir.to_path_buf()),
        SystemClock::new(),
        LogConfig::default(),
    )
    .map_err(|e| map_admin_err(data_dir, e))?;
    write_dlq_redrive_result(data_dir, &outcome, json, out)
}

/// Writes the `admin dlq-redrive` result: the human line or the versioned
/// `ironbus.cli.admin-dlq-redrive.v1` `--json` object (exit 0 on success, including the idempotent
/// zero-redriven re-run).
#[cfg(unix)]
fn write_dlq_redrive_result(
    data_dir: &Path,
    outcome: &ironbus_storage::admin::RedriveOutcome,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    if json {
        writeln!(
            out,
            "{{\"schema\":\"ironbus.cli.admin-dlq-redrive.v{ADMIN_DLQ_REDRIVE_SCHEMA_VERSION}\",\"data_dir\":\"{}\",\"redriven\":{},\"dlq_records\":{},\"already_redriven\":{},\"ok\":true,\"exit_code\":0}}",
            escape_json(&data_dir.display().to_string()),
            outcome.redriven,
            outcome.dlq_records,
            outcome.already_redriven,
        )?;
    } else {
        writeln!(
            out,
            "admin dlq-redrive: re-injected {} of {} DLQ record(s) onto the main log ({} already redriven)",
            outcome.redriven, outcome.dlq_records, outcome.already_redriven,
        )?;
    }
    Ok(())
}

/// `admin consumer-reset` requires Unix in v1 (the on-disk storage and the exclusive `flock(2)`
/// lock are POSIX), like `scrub`/`repair`. The stub consumes every parameter so the Windows
/// `-D warnings` build stays clean.
#[cfg(not(unix))]
fn cmd_admin_consumer_reset(
    data_dir: &Path,
    group: &str,
    target: ResetTarget,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (data_dir, group, target, json, out);
    Err(CliError::Internal(
        "ironbus admin consumer-reset requires a Unix host in v1: on-disk storage is Unix-only"
            .to_string(),
    ))
}

/// `admin dlq-redrive` requires Unix in v1, for the same reason as `admin consumer-reset`. The stub
/// consumes every parameter.
#[cfg(not(unix))]
fn cmd_admin_dlq_redrive(
    data_dir: &Path,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (data_dir, json, out);
    Err(CliError::Internal(
        "ironbus admin dlq-redrive requires a Unix host in v1: on-disk storage is Unix-only"
            .to_string(),
    ))
}

/// Maps an upgrade/rollback error to the frozen exit-code scheme: a missing rollback copy is a
/// usage error (1; the operator asked to roll back where nothing was upgraded), an IO fault is
/// internal (70).
#[cfg(unix)]
fn map_upgrade_err(e: &upgrade::UpgradeError) -> CliError {
    match e {
        // Both refusals (no rollback copy, or a copy recorded as known-bad) are usage-level: the
        // verb declined to act and left the binary in a safe state, it did not fault (exit 1).
        upgrade::UpgradeError::NoPrev(_) | upgrade::UpgradeError::PrevIsKnownBad(_) => {
            CliError::Usage(e.to_string())
        }
        upgrade::UpgradeError::Io(..) => CliError::Internal(e.to_string()),
    }
}

/// Atomically swaps the already-verified `new_binary` over `dest`, retaining the prior binary as
/// `<dest>.prev` (#104). Never overwrites the live binary in place: it stages to a sibling temp,
/// fsyncs, retains the prior bytes, then renames atomically (POSIX). The caller has ALREADY verified
/// `new_binary` (the fail-closed `scripts/install.sh`), so this never weakens verify-before-install.
#[cfg(unix)]
fn cmd_upgrade(
    new_binary: &Path,
    dest: &Path,
    max_failed_starts: Option<u32>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    if !new_binary.exists() {
        return Err(CliError::Usage(format!(
            "no new binary at {} (run the fail-closed scripts/install.sh to download and verify it \
             first; upgrade only performs the post-verify atomic swap)",
            new_binary.display()
        )));
    }
    let had_prior = dest.exists();
    upgrade::atomic_swap_with_prev(new_binary, dest).map_err(|e| map_upgrade_err(&e))?;
    // A new binary is a fresh start budget: clear any stale failed-start count so a prior version's
    // failures do not trip the fall-back for this one.
    upgrade::record_successful_start(dest)
        .map_err(|e| CliError::Internal(format!("resetting the start counter: {e}")))?;
    let n = max_failed_starts.unwrap_or(upgrade::DEFAULT_MAX_FAILED_STARTS);
    if had_prior {
        writeln!(
            out,
            "upgraded {} (prior binary retained as {} for rollback; falls back after {n} failed \
             starts)",
            dest.display(),
            upgrade::prev_path(dest).display()
        )?;
    } else {
        writeln!(
            out,
            "installed {} (fresh install, no prior binary to retain)",
            dest.display()
        )?;
    }
    Ok(())
}

/// Restores `<dest>.prev` over the live binary (#104): the one-command rollback to the last
/// known-good bytes, via the same atomic swap, also clearing the start-attempt counter.
#[cfg(unix)]
fn cmd_rollback(dest: &Path, out: &mut impl Write) -> Result<(), CliError> {
    upgrade::rollback_to_prev(dest).map_err(|e| map_upgrade_err(&e))?;
    writeln!(
        out,
        "rolled back {} to the retained previous binary (start counter cleared)",
        dest.display()
    )?;
    Ok(())
}

/// Drives the consecutive-failed-start counter the systemd unit uses to fall back after N failures
/// (#104). The three modes are the three lifecycle points the unit wires, and they keep the count
/// honest so a HEALTHY node never rolls back on power loss:
///
/// - [`RecordStartMode::Failed`] (`ExecStopPost` on a non-clean exit) is the SINGLE place the counter
///   is bumped, so one crash cycle increments by exactly one.
/// - [`RecordStartMode::Ok`] (`ExecStartPost`, run only once the broker is confirmed up) clears it,
///   so a genuine successful start resets the budget.
/// - [`RecordStartMode::Check`] (`ExecStartPre`) only CONSULTS the count and reports whether to roll
///   back; it never mutates the counter, so consulting on every boot (including after an unclean
///   power loss of a healthy binary) cannot itself accumulate toward a spurious rollback.
///
/// `Check`/`Failed` report whether [`upgrade::should_fall_back`] holds (the count has reached N AND a
/// `<dest>.prev` exists); the unit greps the "fall-back threshold reached" line and runs `rollback`.
/// The decision (`should_fall_back`) is pure and unit-tested in the `upgrade` module.
#[cfg(unix)]
fn cmd_record_start(
    dest: &Path,
    mode: RecordStartMode,
    max_failed_starts: Option<u32>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let n = max_failed_starts.unwrap_or(upgrade::DEFAULT_MAX_FAILED_STARTS);
    match mode {
        RecordStartMode::Failed => {
            let count = upgrade::record_failed_start(dest, n)
                .map_err(|e| CliError::Internal(format!("recording a failed start: {e}")))?;
            report_fall_back(dest, count, n, out)?;
        }
        RecordStartMode::Check => {
            // Consult only: read the current count, never write it.
            let count = upgrade::read_failed_starts(dest);
            report_fall_back(dest, count, n, out)?;
        }
        RecordStartMode::Ok => {
            upgrade::record_successful_start(dest)
                .map_err(|e| CliError::Internal(format!("clearing the start counter: {e}")))?;
            writeln!(out, "healthy start: start counter cleared")?;
        }
    }
    Ok(())
}

/// Reports whether the node should fall back at the given `count` (the shared `--failed`/`--check`
/// output): the "fall-back threshold reached" line the systemd unit greps when `should_fall_back`
/// holds, otherwise a no-op line. Writes only; never touches the counter.
#[cfg(unix)]
fn report_fall_back(dest: &Path, count: u32, n: u32, out: &mut impl Write) -> Result<(), CliError> {
    if upgrade::should_fall_back(dest, count, n) {
        writeln!(
            out,
            "failed start {count}/{n}: fall-back threshold reached and a rollback copy exists; \
             run `ironbus rollback --dest {}`",
            dest.display()
        )?;
    } else {
        writeln!(out, "failed start {count}/{n}: no fall-back yet")?;
    }
    Ok(())
}

/// Gates an on-disk format bump so it is NEVER silent (#104, #132). Reads the data dir's on-disk
/// format version (the first segment header's version byte, read RAW so a future version is
/// detectable even though this build's decoder would reject it), and:
///
/// - An EMPTY/absent-segments data dir (or one already at this build's [`FORMAT_VERSION`]) needs no
///   migration: it opens as-is within the major version. Reports "no migration needed", exits 0.
/// - A data dir at a DIFFERENT format version is a format bump. Without an explicit `--allow
///   <to-version>` naming this build's version it is REFUSED (a usage error), so an upgrade can
///   never silently reinterpret on-disk bytes under a layout it does not know. With a matching
///   `--allow` it still cannot migrate (no in-place migration path exists in v1), so it reports the
///   honest state and the operator's options rather than faking a migration.
#[cfg(unix)]
fn cmd_migrate(data_dir: &Path, allow: Option<u8>, out: &mut impl Write) -> Result<(), CliError> {
    use ironbus_core::format::FORMAT_VERSION;
    if !data_dir.exists() {
        return Err(CliError::NotFound(format!(
            "no data directory at {}",
            data_dir.display()
        )));
    }
    let on_disk = read_on_disk_format_version(data_dir)?;
    let current = FORMAT_VERSION;
    match on_disk {
        None => {
            writeln!(
                out,
                "no migration needed: {} holds no segments yet (a fresh data dir opens at format v{current})",
                data_dir.display()
            )?;
            Ok(())
        }
        Some(v) if v == current => {
            writeln!(
                out,
                "no migration needed: {} is on-disk format v{v}, the current major (opens with no migration)",
                data_dir.display()
            )?;
            Ok(())
        }
        Some(v) => {
            // A different on-disk format version: a bump that must NEVER be silent.
            match allow {
                Some(to) if to == current => Err(CliError::Usage(format!(
                    "{} is on-disk format v{v}, but this build writes format v{current}, and no \
                     in-place migration path from v{v} to v{current} exists yet. A format bump \
                     within a major version is forward/backward compatible (see \
                     docs/COMPATIBILITY.md); a major bump needs a dedicated migrator, not an \
                     in-place reinterpretation. Refusing rather than corrupting the log.",
                    data_dir.display()
                ))),
                _ => Err(CliError::Usage(format!(
                    "REFUSING a silent format bump: {} is on-disk format v{v} but this build writes \
                     format v{current}. Re-run with `--allow {current}` to acknowledge the bump \
                     explicitly (it is still gated; an on-disk format change is never applied \
                     silently, see docs/COMPATIBILITY.md).",
                    data_dir.display()
                ))),
            }
        }
    }
}

/// Reads the on-disk format version stamped in the data dir's first segment header, RAW (the
/// version byte at [`ironbus_core::format::segment_header_offsets::VERSION`]), so a FUTURE version
/// is detectable even though this build's `SegmentHeader::decode` would reject it. Returns `None`
/// for a data dir with no segments yet (a fresh dir needs no migration).
#[cfg(unix)]
fn read_on_disk_format_version(data_dir: &Path) -> Result<Option<u8>, CliError> {
    use ironbus_core::format::{segment_header_offsets, SEGMENT_HEADER_LEN};
    use ironbus_storage::fs::Filesystem;
    use ironbus_storage::io::RandomAccessFile;
    use ironbus_storage::naming::{segment_file_name, segment_ids};
    let fs = StdFs::new(data_dir.to_path_buf());
    let ids = segment_ids(&fs)
        .map_err(|e| CliError::Internal(format!("listing {}: {e}", data_dir.display())))?;
    let Some(&first) = ids.first() else {
        return Ok(None);
    };
    let name = segment_file_name(first);
    let file = fs
        .open(&name)
        .map_err(|e| CliError::Internal(format!("opening {name}: {e}")))?;
    let mut header = [0u8; SEGMENT_HEADER_LEN];
    file.read_exact_at(&mut header, 0).map_err(|e| {
        CliError::Corrupt(format!(
            "{} is too short to hold a segment header: {e}",
            data_dir.display()
        ))
    })?;
    Ok(Some(header[segment_header_offsets::VERSION]))
}

/// `peek` / `dump` require Unix in v1 (the on-disk storage uses positioned IO the Windows path
/// does not yet implement), matching `serve`.
#[cfg(not(unix))]
fn cmd_inspect(
    data_dir: &Path,
    from_offset: u64,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (data_dir, from_offset, limit, json, out);
    Err(CliError::Internal(
        "ironbus peek/dump require a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// `dump --dlq` requires Unix in v1 for the same reason as `dump` (the on-disk storage uses
/// positioned IO the Windows path does not yet implement).
#[cfg(not(unix))]
fn cmd_inspect_dlq(
    data_dir: &Path,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (data_dir, limit, json, out);
    Err(CliError::Internal(
        "ironbus dump --dlq requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// `upgrade` requires Unix in v1: the atomic `rename(2)` swap and the directory fsync are POSIX
/// guarantees. The non-Unix stub consumes every parameter (so the Windows `-D warnings` build is
/// clean, per the #288 footgun note) and errors before any swap.
#[cfg(not(unix))]
fn cmd_upgrade(
    new_binary: &Path,
    dest: &Path,
    max_failed_starts: Option<u32>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (new_binary, dest, max_failed_starts, out);
    Err(CliError::Internal(
        "ironbus upgrade requires a Unix host in v1: the atomic rename(2) swap is POSIX-only"
            .to_string(),
    ))
}

/// `rollback` requires Unix in v1, for the same reason as `upgrade` (the atomic `rename(2)` swap).
#[cfg(not(unix))]
fn cmd_rollback(dest: &Path, out: &mut impl Write) -> Result<(), CliError> {
    let _ = (dest, out);
    Err(CliError::Internal(
        "ironbus rollback requires a Unix host in v1: the atomic rename(2) swap is POSIX-only"
            .to_string(),
    ))
}

/// `record-start` requires Unix in v1 (it is the systemd fall-back helper, and `serve` is Unix-only).
#[cfg(not(unix))]
fn cmd_record_start(
    dest: &Path,
    mode: RecordStartMode,
    max_failed_starts: Option<u32>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (dest, mode, max_failed_starts, out);
    Err(CliError::Internal(
        "ironbus record-start requires a Unix host in v1 (the systemd fall-back helper)"
            .to_string(),
    ))
}

/// `migrate` requires Unix in v1 (it reads the on-disk segments, which use positioned IO the Windows
/// path does not yet implement, matching `peek`/`dump`).
#[cfg(not(unix))]
fn cmd_migrate(data_dir: &Path, allow: Option<u8>, out: &mut impl Write) -> Result<(), CliError> {
    let _ = (data_dir, allow, out);
    Err(CliError::Internal(
        "ironbus migrate requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    #[cfg(unix)]
    use ironbus_core::types::RecordFlags;
    use ironbus_server::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
    use ironbus_server::engine::{DiskFullPolicy, Engine, EngineConfig};
    use ironbus_server::server::serve;
    use ironbus_storage::fs::InMemoryFs;
    #[cfg(unix)]
    use ironbus_storage::log::Append;
    use ironbus_storage::log::LogConfig;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Spawns the append actor over `engine` and a wire server bound to an ephemeral port, returning
    /// the address, the shutdown flag, the server join handle, and the actor join handle (so the test
    /// can recover the engine after a clean stop). The actor owns the engine; the server reaches it
    /// through the handle.
    #[allow(clippy::type_complexity)]
    fn serve_engine<F, C>(
        engine: Engine<F, C>,
        max_connections: usize,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        std::thread::JoinHandle<Engine<F, C>>,
    )
    where
        F: ironbus_storage::fs::Filesystem + 'static,
        C: ironbus_core::clock::Clock + Clone + Default + 'static,
    {
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                // These wire-only helpers do not start a health server, so the liveness beacon (#95)
                // is unread; the serve loop still ticks it, so give it a fresh beacon on a default
                // clock of the matching type.
                let clock = C::default();
                let beacon =
                    ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                serve(
                    &listener,
                    &handle,
                    &shutdown,
                    max_connections,
                    &clock,
                    &beacon,
                )
                .unwrap();
            }
        });
        (addr, shutdown, server, actor)
    }

    /// Recovers the engine from the actor after the server has been stopped: the server thread has
    /// already dropped its handle, so an explicit shutdown drains the actor and the join yields the
    /// owned engine.
    fn recover_engine<F, C>(actor: std::thread::JoinHandle<Engine<F, C>>) -> Engine<F, C>
    where
        F: ironbus_storage::fs::Filesystem + 'static,
        C: ironbus_core::clock::Clock + Clone + 'static,
    {
        actor.join().unwrap()
    }

    /// A [`ServeConfig`] for a disk-engine test: the given in-flight window and checkpoint
    /// interval, every other knob the production default (retention and the total cap both off).
    #[cfg(unix)]
    fn test_serve_config(max_in_flight: u32, checkpoint_interval: u64) -> ServeConfig {
        ServeConfig {
            profile: Profile::Balanced,
            profile_schema_version: PROFILE_SCHEMA_VERSION,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            checkpoint_interval,
            max_deliver: DEFAULT_MAX_DELIVER,
            allow_unlimited_deliver: false,
            backoff_ms: Vec::new(),
            max_in_flight,
            consumer_credit: DEFAULT_CONSUMER_CREDIT,
            consumer_credit_bytes: DEFAULT_CONSUMER_CREDIT_BYTES,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_age_ms: DEFAULT_MAX_AGE_MS,
            max_messages: DEFAULT_MAX_MESSAGES,
            // Key compaction (#337) is OFF by default.
            compact: false,
            max_groups: DEFAULT_MAX_GROUPS,
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
            ram_ceiling_bytes: DEFAULT_RAM_CEILING_BYTES,
            disk_full_policy: DiskFullPolicyArg::DropNew,
            visibility_ms: DEFAULT_VISIBILITY_MS,
            enable_admin: false,
            enable_otlp_export: false,
            otlp_endpoint: None,
            health_liveness_window_ms: DEFAULT_HEALTH_LIVENESS_WINDOW_MS,
            health_allow_public: false,
            dedup_max_ids: DEFAULT_DEDUP_MAX_IDS,
            dedup_window_ms: DEFAULT_DEDUP_WINDOW_MS,
            dedup_max_producers: DEFAULT_DEDUP_MAX_PRODUCERS,
            // The default durable level (#341): a test config that does not opt in stays power-loss
            // safe (ack-implies-durable), so an unrelated test never accidentally relaxes durability.
            durability_level: DurabilityLevelArg::Sync,
            // The default compression codec (#387): lz4 per ADR-0003.
            compression: CompressionArg::Lz4,
            flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
            flush_max_bytes: DEFAULT_FLUSH_MAX_BYTES,
            async_loss_ack: false,
            // Backpressure controls (#68, #69) default to inert in this config builder.
            codel_target_ms: 0,
            codel_interval_ms: DEFAULT_CODEL_INTERVAL_MS,
            retry_budget_ratio_per_million: 0,
            retry_budget_window_ms: DEFAULT_RETRY_BUDGET_WINDOW_MS,
            fire_and_forget_msg_rate: 0,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: DEFAULT_FIRE_AND_FORGET_REFILL_MS,
            egress_limit: DEFAULT_EGRESS_LIMIT,
            wal_fsync_headroom_bytes: DEFAULT_WAL_FSYNC_HEADROOM_BYTES,
        }
    }

    /// Builds a `serve` arg vector from string slices, the convenience the profile/precedence tests
    /// use to drive the hand-rolled parser.
    fn serve_args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    // ---- #382 TOML config-FILE layer + flag > env > FILE > default precedence ----

    /// Parses `serve` flags with an injected env map AND an injected config-file reader, so the
    /// file-precedence and strict-validation tests are deterministic (no real filesystem).
    fn parse_with_env_and_file(
        args: &[String],
        env: &std::collections::HashMap<String, String>,
        file: &'static str,
    ) -> Result<ParsedServe, CliError> {
        let env_fn = |name: &str| env.get(name).cloned();
        let read = move |_path: &str| Ok(file.to_string());
        parse_serve_flags_with_env_and_reader(args, &env_fn, &read)
    }

    #[test]
    fn a_config_file_sets_a_knob_below_the_default() {
        // THE FILE > default teeth: with no flag and no env, the FILE value wins over the compiled
        // default. The file sets a 32 MiB segment; the default is 64 MiB.
        let env = std::collections::HashMap::new();
        let doc = "[storage]\nsegment_size = \"32MiB\"\n";
        let parsed =
            parse_with_env_and_file(&serve_args(&["--config", "/x.toml"]), &env, doc).unwrap();
        assert_eq!(
            parsed.config.max_segment_bytes,
            32 * 1024 * 1024,
            "FILE beats default"
        );
    }

    #[test]
    fn env_overrides_the_config_file() {
        // THE env > FILE teeth: an env var beats the FILE value for the same knob.
        let mut env = std::collections::HashMap::new();
        env.insert(
            "IRONBUS_MAX_SEGMENT_BYTES".to_string(),
            (16 * 1024 * 1024).to_string(),
        );
        let doc = "[storage]\nsegment_size = \"32MiB\"\n";
        let parsed =
            parse_with_env_and_file(&serve_args(&["--config", "/x.toml"]), &env, doc).unwrap();
        assert_eq!(
            parsed.config.max_segment_bytes,
            16 * 1024 * 1024,
            "env beats FILE"
        );
    }

    #[test]
    fn a_flag_overrides_both_env_and_the_config_file() {
        // THE flag > env > FILE teeth: the flag wins over BOTH the env var and the FILE value.
        let mut env = std::collections::HashMap::new();
        env.insert(
            "IRONBUS_MAX_SEGMENT_BYTES".to_string(),
            (16 * 1024 * 1024).to_string(),
        );
        let doc = "[storage]\nsegment_size = \"32MiB\"\n";
        let parsed = parse_with_env_and_file(
            &serve_args(&[
                "--config",
                "/x.toml",
                "--max-segment-bytes",
                &(8 * 1024 * 1024).to_string(),
            ]),
            &env,
            doc,
        )
        .unwrap();
        assert_eq!(
            parsed.config.max_segment_bytes,
            8 * 1024 * 1024,
            "flag beats env and FILE"
        );
    }

    #[test]
    fn the_no_config_default_path_is_unchanged() {
        // THE critical invariant: with NO `--config`, resolution is byte-for-byte the historical
        // flag > env > default. A zero-config broker is exactly the `balanced` default set.
        let parsed = parse_serve_flags(&serve_args(&[])).unwrap();
        assert_eq!(parsed.config.max_segment_bytes, DEFAULT_MAX_SEGMENT_BYTES);
        assert_eq!(parsed.config.consumer_credit, DEFAULT_CONSUMER_CREDIT);
        assert!(parsed.config_warnings.is_empty(), "no file, no warnings");
        assert!(parsed.config_path.is_none());
    }

    #[test]
    fn a_broken_config_file_is_a_usage_error_with_the_path_and_location() {
        let env = std::collections::HashMap::new();
        let doc = "[storage\nsegment_size = \"32MiB\"\n"; // missing ]
        let err =
            parse_with_env_and_file(&serve_args(&["--config", "/etc/ironbus.toml"]), &env, doc)
                .unwrap_err();
        match err {
            CliError::Usage(m) => {
                assert!(m.contains("/etc/ironbus.toml"), "names the path: {m}");
                assert!(m.contains("line"), "names a location: {m}");
            }
            other => panic!("a broken file is a usage error, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_config_key_is_a_usage_error_with_a_suggestion() {
        let env = std::collections::HashMap::new();
        let doc = "[storage]\nsegmnet_size = \"32MiB\"\n";
        let err =
            parse_with_env_and_file(&serve_args(&["--config", "/x.toml"]), &env, doc).unwrap_err();
        match err {
            CliError::Usage(m) => {
                assert!(m.contains("segmnet_size"), "echoes the bad key: {m}");
                assert!(
                    m.contains("storage.segment_size"),
                    "suggests the right key: {m}"
                );
            }
            other => panic!("an unknown key is a usage error, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_config_key_is_a_warning_under_allow_unknown_config() {
        let env = std::collections::HashMap::new();
        let doc = "[storage]\nsegmnet_size = \"32MiB\"\n";
        let parsed = parse_with_env_and_file(
            &serve_args(&["--config", "/x.toml", "--allow-unknown-config"]),
            &env,
            doc,
        )
        .unwrap();
        assert!(
            parsed
                .config_warnings
                .iter()
                .any(|w| w.contains("segmnet_size")),
            "the downgraded key is a warning: {:?}",
            parsed.config_warnings
        );
        // The unknown key did NOT change the segment size (it stays the default).
        assert_eq!(parsed.config.max_segment_bytes, DEFAULT_MAX_SEGMENT_BYTES);
    }

    #[test]
    fn a_coupled_set_violation_in_the_file_is_a_usage_error() {
        // retention requested (a retention key is set) but every limit resolves to 0 is rejected.
        let env = std::collections::HashMap::new();
        let doc = "[retention]\nmax_retained_bytes = 0\n";
        let err =
            parse_with_env_and_file(&serve_args(&["--config", "/x.toml"]), &env, doc).unwrap_err();
        match err {
            CliError::Usage(m) => assert!(
                m.contains("retention requested but every limit is 0"),
                "names the coupled-set violation: {m}"
            ),
            other => panic!("a coupled-set violation is a usage error, got {other:?}"),
        }
    }

    #[test]
    fn a_drop_oldest_with_no_cap_is_a_config_warning_not_a_failure() {
        // A no-op `drop-oldest` (no byte cap) is a WARNING, not a fatal error: the broker still
        // resolves, and the warning is surfaced.
        let env = std::collections::HashMap::new();
        let doc = "[backpressure]\ndisk_full_policy = \"drop-oldest\"\n";
        let parsed =
            parse_with_env_and_file(&serve_args(&["--config", "/x.toml"]), &env, doc).unwrap();
        assert!(
            parsed
                .config_warnings
                .iter()
                .any(|w| w.contains("has no effect")),
            "the no-op policy is a warning: {:?}",
            parsed.config_warnings
        );
    }

    #[test]
    fn a_unitless_duration_in_the_file_is_a_usage_error() {
        let env = std::collections::HashMap::new();
        let doc = "[delivery]\nvisibility_timeout_ms = \"45\"\n";
        let err =
            parse_with_env_and_file(&serve_args(&["--config", "/x.toml"]), &env, doc).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{err:?}");
        assert_eq!(
            err.exit_code(),
            EXIT_USAGE,
            "a bad config is a clean usage exit, never a panic"
        );
    }

    // ---- #87 compiled-in profiles + materialized-config logging ----

    #[test]
    fn edge_tiny_profile_resolves_to_its_exact_values() {
        // Every `edge-tiny` knob is the `docs/CONFIG.md` section 6 / `docs/EDGE_CONSTRAINTS.md`
        // value, asserted exactly so a drift between the code and the doc fails this test.
        let parsed = parse_serve_flags(&serve_args(&["--profile", "edge-tiny"])).unwrap();
        let c = &parsed.config;
        assert_eq!(c.profile, Profile::EdgeTiny);
        assert_eq!(c.profile_schema_version, PROFILE_SCHEMA_VERSION);
        assert_eq!(c.max_segment_bytes, 8 * 1024 * 1024, "8 MiB segments");
        assert_eq!(c.consumer_credit, 8);
        assert_eq!(c.consumer_credit_bytes, 256 * 1024, "256 KiB");
        assert_eq!(c.max_connections, 32);
        assert_eq!(c.max_groups, 64);
        assert_eq!(c.max_in_flight, 256);
        assert_eq!(c.disk_full_policy, DiskFullPolicyArg::DropNew);
        assert_eq!(c.checkpoint_interval, 1024);
        assert_eq!(c.visibility_ms, 30_000);
        assert_eq!(c.max_deliver, 5);
    }

    #[test]
    fn balanced_profile_resolves_to_its_exact_values() {
        // `balanced` is the default set; assert it is exactly the compiled `DEFAULT_*` constants
        // (the source of truth the `BALANCED_PRESET` is written against).
        let parsed = parse_serve_flags(&serve_args(&["--profile", "balanced"])).unwrap();
        let c = &parsed.config;
        assert_eq!(c.profile, Profile::Balanced);
        assert_eq!(c.max_segment_bytes, DEFAULT_MAX_SEGMENT_BYTES);
        assert_eq!(c.consumer_credit, DEFAULT_CONSUMER_CREDIT);
        assert_eq!(c.consumer_credit_bytes, DEFAULT_CONSUMER_CREDIT_BYTES);
        assert_eq!(c.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(c.max_groups, DEFAULT_MAX_GROUPS);
        assert_eq!(c.max_in_flight, DEFAULT_MAX_IN_FLIGHT);
        assert_eq!(c.disk_full_policy, DiskFullPolicyArg::DropNew);
        assert_eq!(c.checkpoint_interval, DEFAULT_CHECKPOINT_INTERVAL);
        assert_eq!(c.visibility_ms, DEFAULT_VISIBILITY_MS);
        assert_eq!(c.max_deliver, DEFAULT_MAX_DELIVER);
    }

    #[test]
    fn throughput_profile_resolves_to_its_exact_values() {
        // Every `throughput` knob is the `docs/CONFIG.md` section 6 value, asserted exactly.
        let parsed = parse_serve_flags(&serve_args(&["--profile", "throughput"])).unwrap();
        let c = &parsed.config;
        assert_eq!(c.profile, Profile::Throughput);
        assert_eq!(c.max_segment_bytes, 256 * 1024 * 1024, "256 MiB segments");
        assert_eq!(c.consumer_credit, 512);
        assert_eq!(c.consumer_credit_bytes, 64 * 1024 * 1024, "64 MiB");
        assert_eq!(c.max_connections, 1024);
        assert_eq!(c.max_groups, 4096);
        assert_eq!(c.max_in_flight, 8192);
        assert_eq!(c.disk_full_policy, DiskFullPolicyArg::DropOldest);
        assert_eq!(c.checkpoint_interval, 4096);
        assert_eq!(c.visibility_ms, 30_000);
        assert_eq!(c.max_deliver, 5);
    }

    #[test]
    fn default_profile_is_byte_identical_to_the_compiled_defaults() {
        // No `--profile` MUST resolve to exactly the same config as `--profile balanced`, which is
        // the shipped default set: existing zero-config behavior is unchanged. Compare every knob.
        let none = parse_serve_flags(&serve_args(&[])).unwrap().config;
        let balanced = parse_serve_flags(&serve_args(&["--profile", "balanced"]))
            .unwrap()
            .config;
        assert_eq!(
            none.profile,
            Profile::Balanced,
            "default profile is balanced"
        );
        assert_eq!(none.max_segment_bytes, balanced.max_segment_bytes);
        assert_eq!(none.consumer_credit, balanced.consumer_credit);
        assert_eq!(none.consumer_credit_bytes, balanced.consumer_credit_bytes);
        assert_eq!(none.max_connections, balanced.max_connections);
        assert_eq!(none.max_groups, balanced.max_groups);
        assert_eq!(none.max_in_flight, balanced.max_in_flight);
        assert_eq!(none.disk_full_policy, balanced.disk_full_policy);
        assert_eq!(none.checkpoint_interval, balanced.checkpoint_interval);
        assert_eq!(none.visibility_ms, balanced.visibility_ms);
        assert_eq!(none.max_deliver, balanced.max_deliver);
        // And each is the raw compiled default, the other anchor of the zero-config guarantee.
        assert_eq!(none.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(none.max_segment_bytes, DEFAULT_MAX_SEGMENT_BYTES);
        assert_eq!(none.consumer_credit, DEFAULT_CONSUMER_CREDIT);
    }

    #[test]
    fn an_explicit_flag_overrides_the_profile() {
        // Precedence proof, the override half: `--profile edge-tiny` sets max_connections to 32,
        // then an explicit `--max-connections 64` MUST win (profile < flag).
        let parsed = parse_serve_flags(&serve_args(&[
            "--profile",
            "edge-tiny",
            "--max-connections",
            "64",
        ]))
        .unwrap();
        assert_eq!(parsed.config.profile, Profile::EdgeTiny);
        assert_eq!(
            parsed.config.max_connections, 64,
            "the flag wins over the profile"
        );
        // The non-overridden edge-tiny knobs are untouched, so the override is surgical.
        assert_eq!(parsed.config.consumer_credit, 8);
        assert_eq!(parsed.config.max_segment_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn an_env_var_overrides_the_profile_and_a_flag_overrides_the_env_var() {
        // Full precedence proof: profile < env < flag, on one knob set at all three layers.
        // edge-tiny -> max_connections 32; env -> 50; flag -> 64. The flag must win, and with the
        // flag removed the env (50) must win over the profile (32).
        let env_map = |name: &str| -> Option<String> {
            if name == "IRONBUS_MAX_CONNECTIONS" {
                Some("50".to_string())
            } else {
                None
            }
        };
        let with_flag = parse_serve_flags_with_env(
            &serve_args(&["--profile", "edge-tiny", "--max-connections", "64"]),
            &env_map,
        )
        .unwrap();
        assert_eq!(
            with_flag.config.max_connections, 64,
            "flag beats env beats profile"
        );
        let env_over_profile =
            parse_serve_flags_with_env(&serve_args(&["--profile", "edge-tiny"]), &env_map).unwrap();
        assert_eq!(
            env_over_profile.config.max_connections, 50,
            "env beats profile when no flag is given"
        );
    }

    #[test]
    fn the_profile_itself_is_selectable_via_env() {
        // `IRONBUS_PROFILE` selects the profile (env layer), and an explicit `--profile` flag still
        // wins over it. With only the env var, edge-tiny is selected.
        let env_map = |name: &str| -> Option<String> {
            if name == "IRONBUS_PROFILE" {
                Some("edge-tiny".to_string())
            } else {
                None
            }
        };
        let from_env = parse_serve_flags_with_env(&serve_args(&[]), &env_map).unwrap();
        assert_eq!(from_env.config.profile, Profile::EdgeTiny);
        assert_eq!(from_env.config.max_connections, 32);
        let flag_wins =
            parse_serve_flags_with_env(&serve_args(&["--profile", "throughput"]), &env_map)
                .unwrap();
        assert_eq!(
            flag_wins.config.profile,
            Profile::Throughput,
            "the flag beats the env profile"
        );
    }

    #[test]
    fn an_unknown_profile_is_a_usage_error() {
        let e = parse_serve_flags(&serve_args(&["--profile", "tiny"])).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        // The error names the accepted values so the operator can fix it.
        let msg = format!("{e:?}");
        assert!(
            msg.contains("edge-tiny"),
            "names the accepted profiles: {msg}"
        );
    }

    #[test]
    fn the_profile_never_overrides_a_knob_it_does_not_set() {
        // A profile sets only its tuning knobs; retention and the total-byte cap are NOT in the
        // preset, so even `throughput` leaves them at their compiled defaults (off).
        let c = parse_serve_flags(&serve_args(&["--profile", "throughput"]))
            .unwrap()
            .config;
        assert_eq!(c.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert_eq!(c.max_retained_bytes, DEFAULT_MAX_RETAINED_BYTES);
        assert_eq!(c.max_age_ms, DEFAULT_MAX_AGE_MS);
        assert_eq!(c.max_messages, DEFAULT_MAX_MESSAGES);
        assert_eq!(c.group_idle_evict_ms, DEFAULT_GROUP_IDLE_EVICT_MS);
    }

    #[test]
    fn the_materialized_config_line_carries_the_profile_version_and_resolved_knobs() {
        // The materialized-config dump must contain the active profile, the profile schema version,
        // and the resolved knob values, so an operator can read exactly what is running. Resolve an
        // edge-tiny profile with one flag override and assert the line reflects the EFFECTIVE config.
        let config = parse_serve_flags(&serve_args(&[
            "--profile",
            "edge-tiny",
            "--max-connections",
            "64",
        ]))
        .unwrap()
        .config;
        let line =
            materialized_config_line(&config, "127.0.0.1:7777", Path::new("/var/lib/ironbus"));
        assert!(
            line.contains("materialized-config"),
            "is the dump line: {line}"
        );
        assert!(
            line.contains("profile=edge-tiny"),
            "the active profile: {line}"
        );
        assert!(
            line.contains(&format!("profile_schema_version={PROFILE_SCHEMA_VERSION}")),
            "the schema version: {line}"
        );
        // The resolved (overridden) value, not the profile's 32.
        assert!(
            line.contains("max_connections=64"),
            "the resolved override: {line}"
        );
        // A profile-supplied value carried through.
        assert!(
            line.contains("consumer_credit=8"),
            "the profile value: {line}"
        );
        assert!(
            line.contains("consumer_credit_bytes=262144"),
            "256 KiB: {line}"
        );
        assert!(
            line.contains("disk_full_policy=drop-new"),
            "the policy: {line}"
        );
        // The edge-tiny RAM ceiling (#115) carried through: 64 MiB, the refuse-to-boot guard's bound.
        assert!(
            line.contains("ram_ceiling_bytes=67108864"),
            "the edge-tiny 64 MiB RAM ceiling: {line}"
        );
        assert!(line.contains("addr=127.0.0.1:7777"), "the addr: {line}");
        assert!(
            line.contains("data_dir=/var/lib/ironbus"),
            "the data dir: {line}"
        );
        // One single line (no embedded newline), so it is one structured log record.
        assert!(!line.contains('\n'), "a single line: {line}");
    }

    #[test]
    fn the_three_presets_are_distinct_and_balanced_equals_the_default_set() {
        // Guard the table: the three presets differ from each other, and `balanced` IS the default
        // set. A copy-paste that made two profiles identical, or that drifted balanced from the
        // defaults, fails here.
        assert_ne!(EDGE_TINY_PRESET, BALANCED_PRESET);
        assert_ne!(BALANCED_PRESET, THROUGHPUT_PRESET);
        assert_ne!(EDGE_TINY_PRESET, THROUGHPUT_PRESET);
        assert_eq!(Profile::Balanced.preset(), BALANCED_PRESET);
        assert_eq!(BALANCED_PRESET.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(BALANCED_PRESET.max_segment_bytes, DEFAULT_MAX_SEGMENT_BYTES);
        // The RAM ceiling (#115): only edge-tiny opts into the 64 MiB refuse-to-boot guard; the
        // server-sized balanced/throughput presets leave it OFF (0).
        assert_eq!(EDGE_TINY_PRESET.ram_ceiling_bytes, EDGE_TINY_RAM_CEILING);
        assert_eq!(EDGE_TINY_PRESET.ram_ceiling_bytes, 64 * 1024 * 1024);
        assert_eq!(BALANCED_PRESET.ram_ceiling_bytes, 0);
        assert_eq!(THROUGHPUT_PRESET.ram_ceiling_bytes, 0);
    }

    /// Builds a real on-disk data directory with `n` durable records via the engine, for
    /// the offline `peek` / `dump` verbs to read back.
    #[cfg(unix)]
    fn make_data_dir(tag: &str, n: usize) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ironbus-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut engine = open_disk_engine(&dir, &test_serve_config(64, 1), &[], &[]).unwrap();
        for i in 0..n {
            let payload = format!("msg-{i}");
            engine
                .produce(&Append {
                    timestamp_ms: 100 + u64::try_from(i).unwrap(),
                    flags: RecordFlags::EMPTY,
                    key: b"k",
                    headers: b"",
                    payload: payload.as_bytes(),
                })
                .unwrap();
        }
        drop(engine);
        dir
    }

    // --- offline mutating admin verbs (#299) ---

    /// A reset/redrive run over `args`, capturing stdout and the exit code, for the admin tests.
    #[cfg(unix)]
    fn run_admin_verb(args: &[&str]) -> (String, u8) {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut buf = Vec::new();
        match run(&owned, &mut buf) {
            Ok(()) => (String::from_utf8(buf).unwrap(), 0),
            Err(e) => (String::from_utf8(buf).unwrap(), e.exit_code()),
        }
    }

    /// Reads a group's durable committed offset back from its cursor checkpoint, proving the broker
    /// (or an `OfflineReader`) resumes from where the reset wrote it.
    #[cfg(unix)]
    fn read_committed_offset(dir: &std::path::Path, group: &str) -> Option<u64> {
        use ironbus_core::cursor::AckCursor;
        use ironbus_storage::checkpoint::Checkpoint;
        use ironbus_storage::fs::Filesystem;
        use ironbus_storage::naming::cursor_checkpoint_name;
        let fs = StdFs::new(dir.to_path_buf());
        let name = cursor_checkpoint_name(group);
        if !fs.exists(&name).unwrap() {
            return None;
        }
        let (_, recovered) = Checkpoint::open(fs.open(&name).unwrap()).unwrap();
        let payload = recovered?;
        Some(
            AckCursor::decode_snapshot(&payload)
                .unwrap()
                .committed()
                .get(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn admin_consumer_reset_rewrites_the_cursor_and_emits_the_versioned_json() {
        let dir = make_data_dir("admin-reset", 10);
        let (out, code) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "orders",
            "--to",
            "4",
            "--json",
        ]);
        assert_eq!(code, 0, "{out}");
        assert!(
            out.contains("\"schema\":\"ironbus.cli.admin-consumer-reset.v1\""),
            "carries the versioned schema: {out}"
        );
        assert!(out.contains("\"committed\":4"), "{out}");
        assert!(out.contains("\"head\":10"), "{out}");
        assert!(out.contains("\"ok\":true,\"exit_code\":0"), "{out}");
        // The cursor the broker resumes from is now exactly 4.
        assert_eq!(read_committed_offset(&dir, "orders"), Some(4));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_broker_resumes_a_named_group_from_the_reset_offset() {
        // The teeth: after an offline reset of a NAMED group, the REAL engine rediscovers the group
        // at open and resumes it from the rewritten cursor (clamped to the durable range). This
        // proves the reset wrote a cursor the broker reads natively, not just bytes we can decode.
        let dir = make_data_dir("admin-reset-resume", 12);
        let (_o, code) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "orders",
            "--to",
            "7",
        ]);
        assert_eq!(code, 0);

        let engine = open_disk_engine(&dir, &test_serve_config(64, 1), &[], &[]).unwrap();
        assert_eq!(
            engine.committed_offset_in("orders"),
            ironbus_core::types::Offset::new(7),
            "the broker resumes the named group from the reset offset"
        );
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn admin_consumer_reset_earliest_and_latest_hit_the_range_ends() {
        let dir = make_data_dir("admin-reset-ends", 6);
        let (_o, c1) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "g",
            "--to",
            "latest",
        ]);
        assert_eq!(c1, 0);
        assert_eq!(
            read_committed_offset(&dir, "g"),
            Some(6),
            "latest is the head"
        );
        let (_o, c2) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "g",
            "--to",
            "earliest",
        ]);
        assert_eq!(c2, 0);
        assert_eq!(
            read_committed_offset(&dir, "g"),
            Some(0),
            "earliest is offset 0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn admin_consumer_reset_out_of_range_is_a_usage_error_and_writes_nothing() {
        let dir = make_data_dir("admin-reset-oor", 5);
        let (out, code) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "g",
            "--to",
            "99",
            "--json",
        ]);
        assert_eq!(code, EXIT_USAGE, "out-of-range is a usage error: {out}");
        // A rejected reset wrote no cursor file (no stdout JSON either, since it failed before write).
        assert_eq!(
            read_committed_offset(&dir, "g"),
            None,
            "no cursor was written"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn admin_consumer_reset_rejects_a_group_name_the_broker_would_skip() {
        // A non-graphic group name (here, a space) is one the engine's group discovery would skip,
        // so the reset refuses it as a usage error rather than writing an ignored cursor.
        let dir = make_data_dir("admin-reset-badgroup", 4);
        let (out, code) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "bad name",
            "--to",
            "0",
        ]);
        assert_eq!(code, EXIT_USAGE, "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn admin_consumer_reset_refuses_a_running_broker() {
        // A broker holds the exclusive data-dir lock: the offline reset must fail fast with exit 5
        // (unreachable / stop-the-broker-first), never touching the cursor.
        let dir = make_data_dir("admin-reset-locked", 5);
        dirlock::prepare_data_dir(&dir).unwrap();
        let held = dirlock::DirLock::acquire(&dir).unwrap();
        let (out, code) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "g",
            "--to",
            "2",
        ]);
        assert_eq!(
            code, EXIT_UNREACHABLE,
            "a running broker blocks the reset: {out}"
        );
        assert_eq!(
            read_committed_offset(&dir, "g"),
            None,
            "the cursor was not touched"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn admin_consumer_reset_missing_data_dir_is_not_found() {
        let dir = std::env::temp_dir().join(format!(
            "ironbus-cli-admin-reset-absent-{}-xyz",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let (_o, code) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "g",
            "--to",
            "0",
        ]);
        assert_eq!(code, EXIT_NOT_FOUND);
    }

    #[cfg(unix)]
    #[test]
    fn admin_consumer_reset_requires_group_and_to() {
        let dir = make_data_dir("admin-reset-args", 3);
        // Missing --group.
        let (_o, c1) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--to",
            "0",
        ]);
        assert_eq!(c1, EXIT_USAGE);
        // Missing --to.
        let (_o, c2) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "g",
        ]);
        assert_eq!(c2, EXIT_USAGE);
        // A bad --to value.
        let (_o, c3) = run_admin_verb(&[
            "admin",
            "consumer-reset",
            "--data-dir",
            dir.to_str().unwrap(),
            "--group",
            "g",
            "--to",
            "banana",
        ]);
        assert_eq!(c3, EXIT_USAGE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dead-letters `poison` records into the data directory's DLQ sink (the broker's exact sink),
    /// so the redrive verb has poison to re-inject.
    #[cfg(unix)]
    fn seed_dlq(dir: &std::path::Path, poison: u64) {
        use ironbus_core::types::{Offset, Seq};
        use ironbus_storage::dlq::DlqSink;
        use ironbus_storage::segment::OwnedRecord;
        let fs = StdFs::new(dir.to_path_buf());
        let mut sink = DlqSink::open(&fs, SystemClock::new(), LogConfig::default()).unwrap();
        for i in 0..poison {
            let src = OwnedRecord {
                offset: Offset::new(500 + i),
                seq: Seq::new(500 + i),
                timestamp_ms: 7000 + i,
                flags: RecordFlags::EMPTY,
                key: b"pk".to_vec(),
                headers: b"".to_vec(),
                payload: format!("poison-{i}").into_bytes(),
            };
            sink.append_poison("orders", &src, 6).unwrap();
        }
    }

    /// Counts the durable main-log records in the data directory (offline), for the redrive assertions.
    #[cfg(unix)]
    fn main_log_len(dir: &std::path::Path) -> u64 {
        let reader = OfflineReader::open(StdFs::new(dir.to_path_buf())).unwrap();
        let mut n = 0u64;
        for &id in reader.segment_ids() {
            n += reader.read_segment(id).unwrap().len() as u64;
        }
        n
    }

    #[cfg(unix)]
    #[test]
    fn admin_dlq_redrive_re_injects_and_is_idempotent() {
        let dir = make_data_dir("admin-redrive", 3);
        seed_dlq(&dir, 4);
        let before = main_log_len(&dir);

        let (out, code) = run_admin_verb(&[
            "admin",
            "dlq-redrive",
            "--data-dir",
            dir.to_str().unwrap(),
            "--json",
        ]);
        assert_eq!(code, 0, "{out}");
        assert!(
            out.contains("\"schema\":\"ironbus.cli.admin-dlq-redrive.v1\""),
            "versioned schema: {out}"
        );
        assert!(out.contains("\"redriven\":4"), "{out}");
        assert!(out.contains("\"dlq_records\":4"), "{out}");
        assert!(out.contains("\"already_redriven\":0"), "{out}");
        assert_eq!(
            main_log_len(&dir),
            before + 4,
            "the 4 poison records re-injected"
        );

        // A re-run after a completed redrive re-injects NOTHING (idempotent, no duplicates).
        let (out2, code2) = run_admin_verb(&[
            "admin",
            "dlq-redrive",
            "--data-dir",
            dir.to_str().unwrap(),
            "--json",
        ]);
        assert_eq!(code2, 0, "{out2}");
        assert!(
            out2.contains("\"redriven\":0"),
            "a re-run redrives nothing: {out2}"
        );
        assert!(out2.contains("\"already_redriven\":4"), "{out2}");
        assert_eq!(
            main_log_len(&dir),
            before + 4,
            "no duplicates on the re-run"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn admin_dlq_redrive_refuses_a_running_broker() {
        let dir = make_data_dir("admin-redrive-locked", 2);
        seed_dlq(&dir, 2);
        let before = main_log_len(&dir);
        dirlock::prepare_data_dir(&dir).unwrap();
        let held = dirlock::DirLock::acquire(&dir).unwrap();
        let (out, code) =
            run_admin_verb(&["admin", "dlq-redrive", "--data-dir", dir.to_str().unwrap()]);
        assert_eq!(
            code, EXIT_UNREACHABLE,
            "a running broker blocks redrive: {out}"
        );
        drop(held);
        assert_eq!(main_log_len(&dir), before, "the main log was not touched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn admin_force_reap_is_deferred_to_the_authed_surface() {
        // force-reap reaps stuck leases on a LIVE broker (online + auth); it is a clean usage error
        // here, naming the deferral, never a silent no-op.
        let (out, code) = run_admin_verb(&["admin", "force-reap", "--data-dir", "/tmp/whatever"]);
        assert_eq!(code, EXIT_USAGE);
        let _ = out;
    }

    #[cfg(unix)]
    #[test]
    fn serve_with_an_empty_broadcast_group_is_a_clean_usage_error() {
        // `serve --broadcast-group ""` names the DEFAULT/empty group, which can never be a broadcast
        // group (#288): the active-subscriber cap that makes a broadcast group a group-of-one binds
        // only a NAMED group, so the default group would be an uncapped broadcast group, the residual
        // silent-loss bypass. The configure-time path must surface this as a clean startup USAGE
        // error, NOT a panic. `open_disk_engine` maps the engine's typed reject to `CliError::Usage`.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "ironbus-cli-bcast-empty-{}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let broadcast_groups = vec![String::new()];
        let err = open_disk_engine(&dir, &test_serve_config(64, 1), &[], &broadcast_groups)
            .err()
            .expect("an empty --broadcast-group must be refused, not opened");
        match err {
            CliError::Usage(msg) => {
                assert!(
                    msg.contains("--broadcast-group") && msg.contains("named group only"),
                    "the usage error names the cause: {msg}"
                );
            }
            other => panic!("expected a clean Usage error, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn peek_shows_a_window_of_records() {
        let dir = make_data_dir("peek", 5);
        let mut buf = Vec::new();
        run_peek(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--limit".to_string(),
                "3".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "--limit honored: {text}");
        assert!(lines[0].contains("offset=0"), "{text}");
        assert!(lines[2].contains("offset=2"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn peek_honors_from_offset() {
        let dir = make_data_dir("peekoff", 5);
        let mut buf = Vec::new();
        run_peek(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--from-offset".to_string(),
                "3".to_string(),
                "--limit".to_string(),
                "10".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "offsets 3 and 4 only: {text}");
        assert!(lines[0].contains("offset=3"), "{text}");
        assert!(lines[1].contains("offset=4"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn dump_streams_all_records_as_ndjson() {
        let dir = make_data_dir("dump", 4);
        let mut buf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--json".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "one NDJSON line per record: {text}");
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.starts_with('{') && line.ends_with('}'),
                "ndjson: {line}"
            );
            assert!(line.contains(&format!("\"offset\":{i}")), "{line}");
            assert!(line.contains("\"crc\":\"ok\""), "{line}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn dump_marks_a_torn_tail_rather_than_hiding_it() {
        let dir = make_data_dir("torn", 4);
        // Tear three bytes off the active segment so its last record no longer parses.
        let seg = dir.join("seg-0000000000000000.log");
        let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        let len = f.metadata().unwrap().len();
        f.set_len(len - 3).unwrap();
        f.sync_all().unwrap();
        let mut buf = Vec::new();
        run_dump(
            &["--data-dir".to_string(), dir.display().to_string()],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("offset=2"),
            "the durable prefix is shown: {text}"
        );
        assert!(
            !text.contains("offset=3"),
            "the torn record is not shown: {text}"
        );
        assert!(
            text.contains("note:") && text.contains("torn"),
            "the hole is marked, not hidden: {text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_data_dir_is_not_found() {
        let dir =
            std::env::temp_dir().join(format!("ironbus-cli-absent-{}-xyz", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut buf = Vec::new();
        let e = run_peek(
            &["--data-dir".to_string(), dir.display().to_string()],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_NOT_FOUND, "{e}");
    }

    #[test]
    fn peek_requires_a_data_dir() {
        let mut buf = Vec::new();
        let e = run_peek(&[], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
    }

    #[test]
    fn dump_requires_a_data_dir() {
        let mut buf = Vec::new();
        let e = run_dump(&[], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
    }

    /// Builds a real on-disk data directory that has dead-lettered exactly one poison message into
    /// its durable DLQ sink, by driving an engine over a manual clock so a redelivery expires
    /// deterministically. Returns the data directory path.
    #[cfg(unix)]
    fn make_dlq_data_dir(tag: &str) -> std::path::PathBuf {
        use ironbus_core::clock::ManualClock;
        let dir = std::env::temp_dir().join(format!("ironbus-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut e = Engine::open(
            StdFs::new(dir.clone()),
            Arc::clone(&clock),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(1, false, Vec::new()).unwrap(), // max_deliver = 1
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: ironbus_server::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert in this test EngineConfig.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
            },
        )
        .unwrap();
        e.produce(&Append {
            timestamp_ms: 777,
            flags: RecordFlags::EMPTY,
            key: b"kk",
            headers: b"",
            payload: b"poison-payload",
        })
        .unwrap();
        let _ = e.poll_now().unwrap(); // delivery 1
        clock.advance_monotonic_nanos(40);
        match e.poll_now().unwrap() {
            ironbus_server::engine::Poll::Parked { .. } => {}
            other => panic!("expected the poison to be parked, got {other:?}"),
        }
        drop(e);
        dir
    }

    #[cfg(unix)]
    #[test]
    fn dump_dlq_shows_the_dead_letter_records_read_only() {
        let dir = make_dlq_data_dir("dumpdlq");
        // Snapshot the directory tree before the read, to prove the inspector never mutates it.
        let before = dir_snapshot(&dir);
        let mut buf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--dlq".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one dead-letter record: {text}");
        assert!(lines[0].contains("source_offset=0"), "{text}");
        assert!(lines[0].contains("attempt=2"), "{text}");
        assert!(lines[0].contains("ts_ms=777"), "{text}");
        assert!(lines[0].contains("bytes=14"), "the payload length: {text}");
        assert!(lines[0].contains("key_bytes=2"), "{text}");

        // The --json form is one NDJSON object with the same fields.
        let mut jbuf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--dlq".to_string(),
                "--json".to_string(),
            ],
            &mut jbuf,
        )
        .unwrap();
        let jtext = String::from_utf8(jbuf).unwrap();
        assert!(jtext.contains("\"source_offset\":0"), "{jtext}");
        assert!(jtext.contains("\"attempt\":2"), "{jtext}");
        assert!(jtext.contains("\"ts_ms\":777"), "{jtext}");

        // Read-only: the directory tree is byte-for-byte unchanged after both reads.
        let after = dir_snapshot(&dir);
        assert_eq!(
            before, after,
            "dump --dlq must not mutate the data directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dump_dlq_on_a_never_poisoned_dir_shows_nothing_and_does_not_create_the_subdir() {
        let dir = make_data_dir("dumpdlqempty", 3);
        let mut buf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--dlq".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        assert!(buf.is_empty(), "an empty DLQ shows nothing");
        // The read-only inspector must not have created the dlq/ subdirectory.
        assert!(
            !dir.join("dlq").exists(),
            "dump --dlq must not create the dlq/ subdirectory on a poison-free directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dump_dlq_on_a_missing_dir_is_not_found() {
        let missing =
            std::env::temp_dir().join(format!("ironbus-cli-nodir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        let mut buf = Vec::new();
        let e = run_dump(
            &[
                "--data-dir".to_string(),
                missing.display().to_string(),
                "--dlq".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_NOT_FOUND);
    }

    /// A sorted snapshot of `(relative path, bytes)` for every regular file under `dir`, used to
    /// prove a read-only inspector never mutates the directory.
    #[cfg(unix)]
    fn dir_snapshot(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    walk(base, &path, out);
                } else {
                    let rel = path.strip_prefix(base).unwrap().to_path_buf();
                    out.push((rel, std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    // ---- scrub / repair (#92) -------------------------------------------------------------

    /// Plants a real `CorruptRecordBody` (data-loss) span in `dir`'s active segment by flipping the
    /// LAST byte of the file (inside the last record's frame). The file length is unchanged, so the
    /// last frame parses structurally but fails its body CRC: recovery stops at it and drops
    /// `[lastframe, EOF)` as one `corrupt_record_body` event (data loss), exactly as the storage
    /// recovery test does. The first `n-1` records stay intact.
    #[cfg(unix)]
    fn plant_corrupt_body(dir: &Path) {
        let seg = dir.join("seg-0000000000000000.log");
        let mut bytes = std::fs::read(&seg).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&seg, &bytes).unwrap();
    }

    /// Reads the `mode & 0o777` of a path (Unix), so a test can prove repair preserved it.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn scrub_on_a_clean_dir_exits_0_and_reports_clean() {
        let dir = make_data_dir("scrubclean", 5);
        let mut buf = Vec::new();
        // A clean directory: scrub returns Ok (exit 0) and the human report says "clean".
        cmd_scrub(&dir, false, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("is clean"), "clean report: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn scrub_on_a_planted_corruption_exits_3_and_reports_the_exact_span() {
        let dir = make_data_dir("scrubcorrupt", 5);
        // Record the span the body corruption will drop, by reading the file length before AND after
        // (the corrupt body drops `[lastframe, EOF)`; EOF is the physical length, unchanged).
        let seg = dir.join("seg-0000000000000000.log");
        let physical_len = std::fs::metadata(&seg).unwrap().len();
        plant_corrupt_body(&dir);
        let mut buf = Vec::new();
        let e = cmd_scrub(&dir, false, &mut buf).unwrap_err();
        // Exit 3: handled corruption (the scan finished and found real data loss).
        assert_eq!(e.exit_code(), EXIT_HANDLED_CORRUPTION, "{e}");
        let text = String::from_utf8(buf).unwrap();
        // The exact span is reported: segment 0, a corrupt_record_body reason ending at EOF, marked
        // as data-loss.
        assert!(
            text.contains("segment 0 bytes ["),
            "names the segment+span: {text}"
        );
        assert!(
            text.contains(&format!(", {physical_len})")),
            "the span ends at the physical EOF {physical_len}: {text}"
        );
        assert!(text.contains("reason=corrupt_record_body"), "{text}");
        assert!(text.contains("data-loss"), "{text}");
        assert!(
            !text.contains("torn-tail (no data loss)"),
            "a body-CRC failure is data loss, not a torn tail: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn scrub_on_a_torn_tail_only_dir_exits_0() {
        let dir = make_data_dir("scrubtorn", 4);
        // Tear three bytes off the active segment: a TORN TAIL (the last frame's declared length now
        // runs past EOF), which is a reported skip but NOT data loss, so scrub stays exit 0.
        let seg = dir.join("seg-0000000000000000.log");
        let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        let len = f.metadata().unwrap().len();
        f.set_len(len - 3).unwrap();
        f.sync_all().unwrap();
        let mut buf = Vec::new();
        // Ok (exit 0): a torn-tail-only result is clean per the data-loss boundary.
        cmd_scrub(&dir, false, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("torn_tail"),
            "the torn tail is still REPORTED: {text}"
        );
        assert!(
            text.contains("torn-tail (no data loss)"),
            "marked as not-data-loss: {text}"
        );
        assert!(
            text.contains("0 byte(s) of data loss"),
            "zero data-loss bytes: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn scrub_is_strictly_read_only() {
        let dir = make_data_dir("scrubro", 5);
        plant_corrupt_body(&dir);
        // Snapshot the whole directory tree, run scrub (which finds data loss), and prove every byte
        // is unchanged: scrub never writes, not even to quarantine.
        let before = dir_snapshot(&dir);
        let mut buf = Vec::new();
        let _ = cmd_scrub(&dir, false, &mut buf); // exit 3; the result is irrelevant here
        let after = dir_snapshot(&dir);
        assert_eq!(before, after, "scrub must not mutate the data directory");
        assert!(
            !dir.join("quarantine").exists(),
            "scrub never creates the quarantine/ subdir (it is read-only)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn scrub_json_carries_the_versioned_schema_and_exit_code() {
        let dir = make_data_dir("scrubjson", 5);
        plant_corrupt_body(&dir);
        let mut buf = Vec::new();
        let _ = cmd_scrub(&dir, true, &mut buf);
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("\"schema\":\"ironbus.cli.scrub.v1\""),
            "versioned schema: {text}"
        );
        assert!(
            text.contains("\"exit_code\":3"),
            "carries exit_code 3: {text}"
        );
        assert!(
            text.contains("\"ok\":false"),
            "ok=false on data loss: {text}"
        );
        assert!(text.contains("\"data_loss_bytes\":"), "{text}");
        assert!(
            text.contains("\"reason\":\"corrupt_record_body\""),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn scrub_on_a_missing_dir_is_not_found() {
        let dir =
            std::env::temp_dir().join(format!("ironbus-cli-scrubabsent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut buf = Vec::new();
        let e = cmd_scrub(&dir, false, &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_NOT_FOUND, "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn repair_without_apply_changes_nothing() {
        let dir = make_data_dir("repairplan", 5);
        plant_corrupt_body(&dir);
        let before = dir_snapshot(&dir);
        let mut buf = Vec::new();
        // The read-only plan reports the same data loss as scrub and returns exit 3, but mutates
        // NOTHING: no quarantine, no truncation.
        let e = cmd_repair(&dir, false, false, &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_HANDLED_CORRUPTION, "{e}");
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("read-only plan"), "labels the plan: {text}");
        assert!(text.contains("nothing changed"), "{text}");
        let after = dir_snapshot(&dir);
        assert_eq!(
            before, after,
            "repair without --apply must not mutate the dir"
        );
        assert!(
            !dir.join("quarantine").exists(),
            "no quarantine without --apply"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn repair_apply_quarantines_truncates_and_preserves_mode() {
        let dir = make_data_dir("repairapply", 6);
        let seg = dir.join("seg-0000000000000000.log");
        // Set a deliberate, non-default mode on the data dir so the preservation check has teeth.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        }
        let dir_mode_before = mode_of(&dir);
        let len_before = std::fs::metadata(&seg).unwrap().len();
        plant_corrupt_body(&dir);
        let mut buf = Vec::new();
        let e = cmd_repair(&dir, true, false, &mut buf).unwrap_err();
        // Exit 3: it quarantined real data loss.
        assert_eq!(e.exit_code(), EXIT_HANDLED_CORRUPTION, "{e}");
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("applied: quarantined"),
            "reports what it did: {text}"
        );

        // QUARANTINE-not-delete: the corrupt span was COPIED to quarantine/, a forensic blob exists.
        let qdir = dir.join("quarantine");
        assert!(qdir.is_dir(), "quarantine/ was created: {text}");
        let blobs: Vec<_> = std::fs::read_dir(&qdir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("q-") && n.ends_with(".bin")
            })
            .collect();
        assert_eq!(blobs.len(), 1, "exactly one forensic blob");
        assert!(
            blobs[0]
                .file_name()
                .to_string_lossy()
                .contains("corrupt_record_body"),
            "the blob names the reason: {:?}",
            blobs[0].file_name()
        );

        // TRUNCATED to the longest valid prefix: the active segment is now SHORTER than before
        // (the corrupt last frame is gone).
        let len_after = std::fs::metadata(&seg).unwrap().len();
        assert!(
            len_after < len_before,
            "the segment was truncated to the valid prefix: {len_after} < {len_before}"
        );

        // PRESERVED mode: recovery only truncates files in place, never recreates the dir.
        assert_eq!(
            mode_of(&dir),
            dir_mode_before,
            "the data dir mode is preserved"
        );
        assert_eq!(mode_of(&dir), 0o750, "the explicit 0750 survives");

        // RECOVERY AGREEMENT: re-running scrub on the repaired dir is now CLEAN (exit 0), proving the
        // repair left a consistent prefix the broker's next start would accept unchanged.
        let mut buf2 = Vec::new();
        cmd_scrub(&dir, false, &mut buf2).unwrap();
        assert!(
            String::from_utf8(buf2).unwrap().contains("is clean"),
            "the repaired dir scrubs clean"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn repair_apply_exits_5_when_the_lock_is_held() {
        let dir = make_data_dir("repairlocked", 4);
        plant_corrupt_body(&dir);
        // Simulate a running broker by holding the exclusive data-dir lock ourselves.
        dirlock::prepare_data_dir(&dir).unwrap();
        let held = dirlock::DirLock::acquire(&dir).unwrap();
        let before = dir_snapshot(&dir);
        let mut buf = Vec::new();
        let e = cmd_repair(&dir, true, false, &mut buf).unwrap_err();
        // Exit 5 (unreachable): repair refuses to touch a live broker's data dir, and changes
        // nothing (the lock blocked it before recovery ran).
        assert_eq!(e.exit_code(), EXIT_UNREACHABLE, "{e}");
        let after = dir_snapshot(&dir);
        assert_eq!(
            before, after,
            "a lock-blocked repair --apply mutates nothing"
        );
        assert!(
            !dir.join("quarantine").exists(),
            "no quarantine when lock-blocked"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn repair_apply_on_a_clean_dir_exits_0() {
        let dir = make_data_dir("repaircleanapply", 5);
        // A clean dir: --apply takes the lock, runs recovery (which truncates nothing), and exits 0.
        let mut buf = Vec::new();
        cmd_repair(&dir, true, false, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("is clean"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dump_accepts_raw_and_require_dict_flags_inertly_today() {
        // The #12-gated flags are accepted now: with the codec always `none` they do not change the
        // output (no record carries a dictionary, so --require-dict never trips) and --raw renders
        // the same field set. This pins the frozen flag surface without faking compression.
        let dir = make_data_dir("dumpraw", 3);
        let mut buf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--raw".to_string(),
                "--require-dict".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.lines().count(), 3, "all three records dump: {text}");
        assert!(text.contains("codec=none"), "{text}");
        // --raw/--require-dict are rejected against the DLQ sink (no compressed frames there either).
        let mut bad = Vec::new();
        let e = run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--dlq".to_string(),
                "--raw".to_string(),
            ],
            &mut bad,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Starts an in-process broker over an in-memory filesystem (cross-platform), returning
    /// the bound address, a shutdown flag, and the serve thread handle.
    fn start_inmem_server() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, Vec::new()).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: ironbus_server::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert in this test EngineConfig.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
            },
        )
        .unwrap();
        // The actor join handle is detached here (these wire-only tests do not inspect the engine):
        // when the server thread drops its handle on stop, the actor's channel disconnects and it
        // drains and exits on its own.
        let (addr, shutdown, handle, _actor) = serve_engine(engine, 16);
        (addr, shutdown, handle)
    }

    #[test]
    fn pub_then_sub_with_ack_round_trip() {
        let (addr, shutdown, handle) = start_inmem_server();
        let a = addr.to_string();

        let mut published = Vec::new();
        cmd_pub(&a, b"the-key", b"hello-cli", &mut published).unwrap();
        assert_eq!(String::from_utf8(published).unwrap(), "0\n");

        let mut consumed = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Ack, &mut consumed).unwrap();
        let text = String::from_utf8(consumed).unwrap();
        assert!(text.contains("#0 gen="), "missing offset line: {text}");
        assert!(text.contains("key=the-key"), "missing key: {text}");
        assert!(
            text.contains("payload=hello-cli"),
            "missing payload: {text}"
        );
        assert!(text.contains("ack committed"), "missing ack: {text}");
        assert!(
            text.contains("fetched 1 message(s)"),
            "missing count: {text}"
        );

        // Acked: a second sub sees nothing.
        let mut again = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Peek, &mut again).unwrap();
        assert_eq!(String::from_utf8(again).unwrap(), "fetched 0 message(s)\n");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// Builds an in-memory engine with one group marked BROADCAST (#288), for the cumulative-ack
    /// CLI test: the group accepts the verb, so `cmd_cumulative_ack` drives the real engine path.
    fn engine_with_broadcast_group(group: &str) -> Engine<InMemoryFs, SystemClock> {
        let mut engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, Vec::new()).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: ironbus_server::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert in this test EngineConfig.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
            },
        )
        .unwrap();
        engine.set_broadcast_in(group, true).unwrap();
        engine
    }

    #[test]
    fn cumulative_ack_subcommand_drives_the_engine_path() {
        // The `cumulative-ack` subcommand (#288) commits a broadcast group's cursor up to --up-to,
        // and the server rejects it for a competing group. Drives the real engine over the wire.
        let (addr, shutdown, handle, actor) =
            serve_engine(engine_with_broadcast_group("bcast"), 16);
        let a = addr.to_string();
        // Produce four records so up_to == 3 is within the durable head.
        for _ in 0..4 {
            let mut published = Vec::new();
            cmd_pub(&a, b"", b"x", &mut published).unwrap();
        }
        // Cumulative ack the broadcast group up to 3: succeeds and prints the committed line.
        let mut out = Vec::new();
        run_cumulative_ack(
            &[
                "--addr".to_string(),
                a.clone(),
                "--group".to_string(),
                "bcast".to_string(),
                "--up-to".to_string(),
                "3".to_string(),
            ],
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cumulative ack committed group `bcast` up to offset 3"),
            "cumulative-ack output: {text}"
        );
        // A competing group (the default, not broadcast) is rejected: the verb maps the server Err
        // to an internal CliError, so the call fails (the safety trap holds through the CLI too).
        let mut out = Vec::new();
        let err = run_cumulative_ack(
            &[
                "--addr".to_string(),
                a.clone(),
                "--up-to".to_string(),
                "2".to_string(),
            ],
            &mut out,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("competing work-group"),
            "expected a work-group rejection, got: {err}"
        );
        // A missing --up-to is a usage error before any connection.
        let mut out = Vec::new();
        let usage = run_cumulative_ack(&["--group".to_string(), "bcast".to_string()], &mut out)
            .unwrap_err();
        assert!(matches!(usage, CliError::Usage(_)), "got {usage:?}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
        let _ = recover_engine(actor);
    }

    #[test]
    fn sub_with_a_group_fetches_from_that_group() {
        let (addr, shutdown, handle) = start_inmem_server();
        let a = addr.to_string();
        let mut published = Vec::new();
        cmd_pub(&a, b"", b"grouped", &mut published).unwrap();
        // A named group fetches and acks the message.
        let mut consumed = Vec::new();
        cmd_sub(&a, "team-a", 10, Disposition::Ack, &mut consumed).unwrap();
        let text = String::from_utf8(consumed).unwrap();
        assert!(text.contains("payload=grouped"), "group fetch: {text}");
        assert!(text.contains("ack committed"), "{text}");
        // A different group has an independent cursor, so it still sees the message.
        let mut other = Vec::new();
        cmd_sub(&a, "team-b", 10, Disposition::Peek, &mut other).unwrap();
        assert!(
            String::from_utf8(other)
                .unwrap()
                .contains("payload=grouped"),
            "a second group independently sees the message"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn sub_on_an_empty_queue_reports_zero() {
        let (addr, shutdown, handle) = start_inmem_server();
        let mut buf = Vec::new();
        cmd_sub(&addr.to_string(), "", 5, Disposition::Ack, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "fetched 0 message(s)\n");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn run_dispatches_help_without_a_server() {
        let mut buf = Vec::new();
        run(&["help".to_string()], &mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("USAGE:"));
    }

    #[test]
    fn run_dispatches_version_without_a_server() {
        // `version`, `--version`, and `-V` are the same deterministic, broker-free, socket-free
        // line `ironbus <crate-version>`, exit 0. This is exactly what the #100 cross-build smoke
        // executes on each target, so assert the program name and the compiled crate version.
        for form in ["version", "--version", "-V"] {
            let mut buf = Vec::new();
            run(&[form.to_string()], &mut buf).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert_eq!(out, format!("ironbus {}\n", env!("CARGO_PKG_VERSION")));
        }
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        let mut buf = Vec::new();
        let e = run(&["frobnicate".to_string()], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("frobnicate")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn no_subcommand_is_a_usage_error() {
        let mut buf = Vec::new();
        assert_eq!(run(&[], &mut buf).unwrap_err().exit_code(), EXIT_USAGE);
    }

    #[test]
    fn bad_max_is_a_usage_error_before_connecting() {
        // A parse error must surface (exit 1) without ever dialing a broker.
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--max".to_string(),
                "not-a-number".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_flag_value_is_a_usage_error() {
        let mut buf = Vec::new();
        let e = run(&["pub".to_string(), "--key".to_string()], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--key")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_requires_a_data_dir() {
        let mut buf = Vec::new();
        let e = run(&["serve".to_string()], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--data-dir")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_deliver() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-deliver".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-deliver"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_max_deliver() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-md0-never-created".to_string(),
                "--max-deliver".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least 1"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_an_unlimited_max_deliver() {
        // u32::MAX is also "unlimited" (the lease counter saturates), so it is a usage error,
        // not an internal error, just like 0.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mdmax-never-created".to_string(),
                "--max-deliver".to_string(),
                u32::MAX.to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("unlimited"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    // A platform-independent baseline `ServeConfig` for the validation-level tests (the engine and
    // socket are never opened, so it needs no Unix gate). Defaults mirror the production defaults.
    fn validation_config() -> ServeConfig {
        ServeConfig {
            profile: Profile::Balanced,
            profile_schema_version: PROFILE_SCHEMA_VERSION,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            max_deliver: DEFAULT_MAX_DELIVER,
            allow_unlimited_deliver: false,
            backoff_ms: Vec::new(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            consumer_credit: DEFAULT_CONSUMER_CREDIT,
            consumer_credit_bytes: DEFAULT_CONSUMER_CREDIT_BYTES,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_age_ms: DEFAULT_MAX_AGE_MS,
            max_messages: DEFAULT_MAX_MESSAGES,
            // Key compaction (#337) is OFF by default.
            compact: false,
            max_groups: DEFAULT_MAX_GROUPS,
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
            ram_ceiling_bytes: DEFAULT_RAM_CEILING_BYTES,
            disk_full_policy: DiskFullPolicyArg::DropNew,
            visibility_ms: DEFAULT_VISIBILITY_MS,
            enable_admin: false,
            enable_otlp_export: false,
            otlp_endpoint: None,
            health_liveness_window_ms: DEFAULT_HEALTH_LIVENESS_WINDOW_MS,
            health_allow_public: false,
            dedup_max_ids: DEFAULT_DEDUP_MAX_IDS,
            dedup_window_ms: DEFAULT_DEDUP_WINDOW_MS,
            dedup_max_producers: DEFAULT_DEDUP_MAX_PRODUCERS,
            // The default durable level (#341): a test config that does not opt in stays power-loss
            // safe (ack-implies-durable), so an unrelated test never accidentally relaxes durability.
            durability_level: DurabilityLevelArg::Sync,
            // The default compression codec (#387): lz4 per ADR-0003.
            compression: CompressionArg::Lz4,
            flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
            flush_max_bytes: DEFAULT_FLUSH_MAX_BYTES,
            async_loss_ack: false,
            // Backpressure controls (#68, #69) default to inert in this config builder.
            codel_target_ms: 0,
            codel_interval_ms: DEFAULT_CODEL_INTERVAL_MS,
            retry_budget_ratio_per_million: 0,
            retry_budget_window_ms: DEFAULT_RETRY_BUDGET_WINDOW_MS,
            fire_and_forget_msg_rate: 0,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: DEFAULT_FIRE_AND_FORGET_REFILL_MS,
            egress_limit: DEFAULT_EGRESS_LIMIT,
            wal_fsync_headroom_bytes: DEFAULT_WAL_FSYNC_HEADROOM_BYTES,
        }
    }

    #[test]
    fn validate_rejects_unlimited_max_deliver_without_the_opt_in() {
        // 0 and u32::MAX both mean unlimited; without --allow-unlimited-deliver each is a usage
        // error, and the message points the operator at the opt-in flag (#63).
        for max in [0, u32::MAX] {
            let cfg = ServeConfig {
                max_deliver: max,
                allow_unlimited_deliver: false,
                ..validation_config()
            };
            match validate_serve_config(&cfg) {
                Err(CliError::Usage(m)) => {
                    assert!(m.contains("--allow-unlimited-deliver"), "{m}");
                }
                other => panic!("expected a usage error for max_deliver={max}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_accepts_unlimited_max_deliver_with_the_opt_in() {
        // The same unlimited caps are accepted once the operator opts in (#63). The accompanying
        // startup WARN is emitted by cmd_serve; validation only stops rejecting.
        for max in [0, u32::MAX] {
            let cfg = ServeConfig {
                max_deliver: max,
                allow_unlimited_deliver: true,
                ..validation_config()
            };
            assert!(
                validate_serve_config(&cfg).is_ok(),
                "unlimited max_deliver={max} should be accepted with the opt-in"
            );
        }
    }

    #[test]
    fn validate_accepts_a_config_with_no_ram_ceiling() {
        // The default ceiling is 0 (unset): the refuse-to-boot guard is OFF, so the server-sized
        // balanced defaults (far over 64 MiB by design) validate cleanly.
        let cfg = validation_config();
        assert_eq!(cfg.ram_ceiling_bytes, 0);
        assert!(validate_serve_config(&cfg).is_ok());
    }

    #[test]
    fn validate_accepts_edge_tiny_caps_under_the_64_mib_ceiling() {
        // The edge-tiny knobs (32 conns, 256 KiB byte budget, 64 groups, 256 in-flight) under the
        // 64 MiB ceiling: the worst-case bounded-buffer footprint (~15 MiB) fits, so the broker boots.
        let cfg = ServeConfig {
            max_connections: 32,
            consumer_credit: 8,
            consumer_credit_bytes: 256 * 1024,
            max_groups: 64,
            max_in_flight: 256,
            ram_ceiling_bytes: EDGE_TINY_RAM_CEILING,
            ..validation_config()
        };
        assert!(
            validate_serve_config(&cfg).is_ok(),
            "edge-tiny caps fit under the 64 MiB ceiling, so the broker must boot"
        );
    }

    #[test]
    fn validate_refuses_to_boot_when_a_blown_up_cap_exceeds_the_ceiling() {
        // The edge-tiny ceiling but a server-sized --max-connections override: 4096 * 256 KiB of
        // in-flight bytes alone is 1 GiB, provably over 64 MiB, so the guard refuses to boot (exit 1)
        // and the usage message names the overage and the knob to lower.
        let cfg = ServeConfig {
            max_connections: 4096,
            consumer_credit: 8,
            consumer_credit_bytes: 256 * 1024,
            max_groups: 64,
            max_in_flight: 256,
            ram_ceiling_bytes: EDGE_TINY_RAM_CEILING,
            ..validation_config()
        };
        match validate_serve_config(&cfg) {
            Err(CliError::Usage(m)) => {
                assert!(m.contains("--ram-ceiling-bytes"), "{m}");
                assert!(m.contains("refuses to boot"), "{m}");
                assert!(m.contains("over by"), "names the overage: {m}");
                assert!(
                    m.contains("--max-connections"),
                    "names the knob to lower: {m}"
                );
                // A usage error maps to the frozen exit code 1.
                assert_eq!(CliError::Usage(m).exit_code(), EXIT_USAGE);
            }
            other => panic!("a 4096-connection edge-tiny override must be refused, got {other:?}"),
        }
    }

    #[test]
    fn validate_refuses_an_unlimited_byte_budget_under_a_tiny_ceiling() {
        // consumer_credit_bytes = 0 (OFF) means the only term-1 bound is the message COUNT, so the
        // worst case is consumer_credit maximal frames per connection: under a 64 MiB ceiling this
        // cannot be PROVEN to fit and is refused (the honest, conservative reading).
        let cfg = ServeConfig {
            max_connections: 32,
            consumer_credit: DEFAULT_CONSUMER_CREDIT,
            consumer_credit_bytes: 0,
            ram_ceiling_bytes: EDGE_TINY_RAM_CEILING,
            ..validation_config()
        };
        match validate_serve_config(&cfg) {
            Err(CliError::Usage(m)) => assert!(m.contains("--ram-ceiling-bytes"), "{m}"),
            other => panic!(
                "an unlimited byte budget under a tiny ceiling must be refused, got {other:?}"
            ),
        }
    }

    // ---- #341 / #379 relaxed durability levels: CLI gate, parsing, observability ----

    #[test]
    fn the_default_durability_level_is_sync_and_power_loss_safe() {
        // THE TEETH for the safe default at the CLI: a zero-config `serve` resolves to `sync`, which
        // is power-loss safe and needs no acknowledgement. An operator who changes nothing keeps I2.
        let cfg = parse_serve_flags(&serve_args(&[])).unwrap().config;
        assert_eq!(cfg.durability_level, DurabilityLevelArg::Sync);
        assert!(
            !cfg.durability_level.waives_i2(),
            "the default sync level is power-loss safe"
        );
        assert!(
            validate_serve_config(&cfg).is_ok(),
            "the default needs no data-loss acknowledgement"
        );
    }

    #[test]
    fn serve_parses_every_durability_level() {
        // Each level spelling round-trips through the flag, and `sync`/`interval` need no ack while
        // `async`/`none` are gated (asserted separately).
        for (flag, level) in [
            ("sync", DurabilityLevelArg::Sync),
            ("interval", DurabilityLevelArg::Interval),
            ("async", DurabilityLevelArg::Async),
            ("none", DurabilityLevelArg::None),
        ] {
            let cfg = parse_serve_flags(&serve_args(&["--durability-level", flag]))
                .unwrap()
                .config;
            assert_eq!(cfg.durability_level, level, "{flag} parses to {level:?}");
        }
        // An unknown level is a usage error naming the accepted values.
        match parse_serve_flags(&serve_args(&["--durability-level", "bogus"])) {
            Err(CliError::Usage(m)) => {
                assert!(m.contains("sync"), "names the accepted values: {m}");
                assert!(m.contains("`bogus`"), "echoes the bad value: {m}");
            }
            other => panic!("a bad durability level must be a usage error, got {other:?}"),
        }
    }

    #[test]
    fn serve_compression_default_is_lz4_and_parses_each_codec() {
        // The compression codec (#12, #387): the default is `lz4` (ADR-0003), and both accepted
        // spellings round-trip through the flag.
        let cfg = parse_serve_flags(&serve_args(&[])).unwrap().config;
        assert_eq!(cfg.compression, CompressionArg::Lz4, "default codec is lz4");
        for (flag, codec) in [("none", CompressionArg::None), ("lz4", CompressionArg::Lz4)] {
            let cfg = parse_serve_flags(&serve_args(&["--compression", flag]))
                .unwrap()
                .config;
            assert_eq!(cfg.compression, codec, "{flag} parses to {codec:?}");
        }
        // `zstd` is REJECTED on the default build (it is the deferred opt-in feature): a usage error
        // naming the accepted values and the deferral, not a silent fallback.
        match parse_serve_flags(&serve_args(&["--compression", "zstd"])) {
            Err(CliError::Usage(m)) => {
                assert!(
                    m.contains("`none`") && m.contains("`lz4`"),
                    "names accepted values: {m}"
                );
                assert!(m.contains("zstd"), "explains the zstd deferral: {m}");
            }
            other => panic!("zstd must be a usage error on the default build, got {other:?}"),
        }
        // Any other unknown codec is a usage error too.
        match parse_serve_flags(&serve_args(&["--compression", "bogus"])) {
            Err(CliError::Usage(m)) => assert!(m.contains("`bogus`"), "echoes the bad value: {m}"),
            other => panic!("a bad compression codec must be a usage error, got {other:?}"),
        }
        // The materialized-config line carries the active codec.
        let line = materialized_config_line(
            &parse_serve_flags(&serve_args(&["--compression", "none"]))
                .unwrap()
                .config,
            "127.0.0.1:7700",
            Path::new("/tmp/d"),
        );
        assert!(
            line.contains("compression=none"),
            "config line carries the codec: {line}"
        );
    }

    #[test]
    fn async_and_none_refuse_to_boot_without_the_data_loss_acknowledgement() {
        // THE none/async SAFETY GATE (#49, #379): the unbounded-loss levels refuse to start without
        // `--async-loss-ack`, fail-closed (exit 1), with a message that names the level, the waived
        // invariant, and the flag to set. A loss-bearing durability is never reachable by accident.
        for level in ["async", "none"] {
            let cfg = parse_serve_flags(&serve_args(&["--durability-level", level]))
                .unwrap()
                .config;
            match validate_serve_config(&cfg) {
                Err(CliError::Usage(m)) => {
                    assert!(m.contains(level), "names the level: {m}");
                    assert!(m.contains("I2"), "names the waived invariant: {m}");
                    assert!(
                        m.contains("--async-loss-ack"),
                        "names the acknowledgement flag: {m}"
                    );
                    assert_eq!(CliError::Usage(m).exit_code(), EXIT_USAGE);
                }
                other => panic!("{level} without the ack must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn async_and_none_boot_with_the_data_loss_acknowledgement() {
        // With the explicit `--async-loss-ack`, the gated levels are accepted (the loud I2-waived
        // warning is emitted by cmd_serve at startup; validation only stops rejecting once the
        // operator has acknowledged the loss).
        for level in ["async", "none"] {
            let cfg = parse_serve_flags(&serve_args(&[
                "--durability-level",
                level,
                "--async-loss-ack",
            ]))
            .unwrap()
            .config;
            assert!(cfg.async_loss_ack, "the ack flag parsed");
            assert!(
                validate_serve_config(&cfg).is_ok(),
                "{level} with --async-loss-ack must be accepted"
            );
            assert!(
                cfg.durability_level.waives_i2(),
                "{level} still waives I2 (the warning fires), it is just acknowledged"
            );
        }
    }

    #[test]
    fn interval_needs_at_least_one_positive_flush_trigger() {
        // `interval` with BOTH triggers at 0 would silently become the unbounded `async` behavior
        // without the data-loss acknowledgement: rejected as a usage error so the bound the operator
        // chose is never silently lost. `interval` needs no `--async-loss-ack` (its loss is bounded).
        let cfg = parse_serve_flags(&serve_args(&[
            "--durability-level",
            "interval",
            "--flush-interval-ms",
            "0",
            "--flush-max-bytes",
            "0",
        ]))
        .unwrap()
        .config;
        match validate_serve_config(&cfg) {
            Err(CliError::Usage(m)) => {
                assert!(m.contains("interval"), "names the level: {m}");
                assert!(
                    m.contains("--flush-interval-ms") && m.contains("--flush-max-bytes"),
                    "names both triggers: {m}"
                );
            }
            other => panic!("interval with no trigger must be refused, got {other:?}"),
        }
        // With a positive trigger it boots (and needs no acknowledgement: its loss is bounded).
        let ok = parse_serve_flags(&serve_args(&[
            "--durability-level",
            "interval",
            "--flush-interval-ms",
            "500",
        ]))
        .unwrap()
        .config;
        assert!(
            validate_serve_config(&ok).is_ok(),
            "interval with a positive trigger and no ack must boot"
        );
    }

    #[test]
    fn the_materialized_config_line_carries_the_durability_level_and_loss_exposure() {
        // The OBSERVABILITY surface at startup (#341, #379): the materialized-config line carries the
        // active level, whether it is power-loss safe, and the interval triggers, so an operator reads
        // the durability posture straight off the startup log.
        let safe = parse_serve_flags(&serve_args(&[])).unwrap().config;
        let line = materialized_config_line(&safe, "127.0.0.1:7777", Path::new("/var/lib/ironbus"));
        assert!(line.contains("durability_level=sync"), "{line}");
        assert!(line.contains("power_loss_safe=true"), "{line}");

        let relaxed = parse_serve_flags(&serve_args(&[
            "--durability-level",
            "async",
            "--async-loss-ack",
        ]))
        .unwrap()
        .config;
        let line2 =
            materialized_config_line(&relaxed, "127.0.0.1:7777", Path::new("/var/lib/ironbus"));
        assert!(line2.contains("durability_level=async"), "{line2}");
        assert!(line2.contains("power_loss_safe=false"), "{line2}");
        assert!(line2.contains("async_loss_ack=true"), "{line2}");
    }

    #[test]
    fn the_per_level_worst_case_loss_description_matches_the_level() {
        // The loud-warning loss wording (#341): `sync` states zero loss; each relaxed level states its
        // documented bound, with the `interval` window's triggers spelled out. Pins the operator-facing
        // wording so a doc/code drift is caught.
        let sync = parse_serve_flags(&serve_args(&[])).unwrap().config;
        assert!(durability_loss_description(&sync).contains("zero"));
        let interval = parse_serve_flags(&serve_args(&[
            "--durability-level",
            "interval",
            "--flush-interval-ms",
            "750",
            "--flush-max-bytes",
            "2048",
        ]))
        .unwrap()
        .config;
        let d = durability_loss_description(&interval);
        assert!(d.contains("750 ms"), "spells out the time window: {d}");
        assert!(
            d.contains("2048 unsynced bytes"),
            "spells out the budget: {d}"
        );
        let none = parse_serve_flags(&serve_args(&[
            "--durability-level",
            "none",
            "--async-loss-ack",
        ]))
        .unwrap()
        .config;
        assert!(
            durability_loss_description(&none).contains("largest loss window"),
            "none states the largest window"
        );
    }

    #[test]
    fn serve_parses_the_ram_ceiling_bytes_flag() {
        // The flag takes a value and feeds the guard: a tiny ceiling with the (huge) balanced defaults
        // is refused to boot, proving the flag parsed and reached the guard rather than being an
        // unknown flag or a no-op.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-ram-ceiling-test".to_string(),
                "--ram-ceiling-bytes".to_string(),
                "1048576".to_string(), // 1 MiB: the balanced server defaults cannot fit.
            ],
            &mut buf,
        )
        .unwrap_err();
        match e {
            CliError::Usage(m) => assert!(
                m.contains("--ram-ceiling-bytes") && m.contains("refuses to boot"),
                "the flag parsed and the guard refused the over-ceiling default config: {m}"
            ),
            other => panic!("expected the ram-ceiling refuse-to-boot usage error, got {other:?}"),
        }
    }

    #[test]
    fn the_delivery_config_rejects_unlimited_without_the_opt_in() {
        // The core DeliveryConfig is the typed-error layer the CLI relies on (#63): unlimited
        // without the flag is the typed ConfigError, not a panic.
        use ironbus_core::delivery::ConfigError;
        assert_eq!(
            DeliveryConfig::new(0, false, Vec::new()).unwrap_err(),
            ConfigError::UnlimitedDeliverNotAllowed
        );
        // With the opt-in it builds.
        assert!(DeliveryConfig::new(0, true, Vec::new()).is_ok());
    }

    #[test]
    fn serve_parses_the_allow_unlimited_deliver_flag() {
        // The flag is a bare boolean (no value). Parsing must NOT reject it as an unknown flag; the
        // config then fails on the missing --data-dir, proving the flag itself parsed cleanly.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-deliver".to_string(),
                "0".to_string(),
                "--allow-unlimited-deliver".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        // It got past flag parsing and config validation (unlimited is now allowed) to the
        // data-dir requirement, so the flag both parsed and lifted the unlimited rejection.
        match e {
            CliError::Usage(m) => assert!(m.contains("--data-dir"), "{m}"),
            other => panic!("expected the data-dir usage error, got {other:?}"),
        }
    }

    #[test]
    fn take_number_list_parses_a_comma_separated_schedule() {
        let args = vec!["--backoff-ms".to_string(), "100, 500 ,2000".to_string()];
        let mut i = 0;
        let list = take_number_list("--backoff-ms", &args, &mut i).unwrap();
        assert_eq!(list, vec![100, 500, 2000]);
        assert_eq!(i, 2, "advances past the flag and its value");
        // A single value is a one-element schedule.
        let args = vec!["--backoff-ms".to_string(), "0".to_string()];
        let mut i = 0;
        assert_eq!(
            take_number_list("--backoff-ms", &args, &mut i).unwrap(),
            vec![0]
        );
    }

    #[test]
    fn take_number_list_rejects_a_bad_element() {
        // A non-numeric element or a stray comma (empty element) is a usage error, so a typo is
        // caught before the broker opens.
        for raw in ["100,nope,2000", "100,,200", ""] {
            let args = vec!["--backoff-ms".to_string(), raw.to_string()];
            let mut i = 0;
            match take_number_list("--backoff-ms", &args, &mut i) {
                Err(CliError::Usage(m)) => assert!(m.contains("--backoff-ms"), "{m}"),
                other => panic!("expected a usage error for `{raw}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn serve_rejects_a_bad_backoff_ms() {
        // End to end through the flag parser: a malformed --backoff-ms is a usage error (exit 1).
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--backoff-ms".to_string(),
                "100,bad,2000".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--backoff-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_in_flight() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-in-flight".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-in-flight"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_max_in_flight() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mif0-never-created".to_string(),
                "--max-in-flight".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least 1"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_consumer_credit() {
        // #65: a zero per-consumer credit would deliver nothing to any connection; reject it as a
        // usage error before the broker opens (the engine also floors it to 1, but a typo is caught
        // here loudly rather than silently behaving as 1).
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-cc0-never-created".to_string(),
                "--consumer-credit".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--consumer-credit"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_segment_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-segment-bytes".to_string(),
                "big".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-segment-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_total_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-total-bytes".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-total-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_a_zero_max_total_bytes_meaning_unlimited() {
        // 0 is the default (unlimited) and an explicit 0 must parse the same, then fail only on
        // the unrelated unreachable bind path proves it was accepted, not rejected as usage.
        // Here we point at a never-created data dir with a valid wire addr; the flag parsing and
        // validation pass (no usage error), so the failure is internal/bind, never EXIT_USAGE.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mtb0-never-served".to_string(),
                "--max-total-bytes".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --max-total-bytes 0 (unlimited) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mtb0-never-served");
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_retained_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-retained-bytes".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-retained-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_a_max_retained_bytes_value() {
        // A valid --max-retained-bytes parses and validates (no usage error); the only failure is
        // the unrelated bind on an unreachable addr, proving the flag was accepted, not rejected.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mrb-never-served".to_string(),
                "--max-retained-bytes".to_string(),
                "4096".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "a valid --max-retained-bytes parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mrb-never-served");
    }

    #[test]
    fn usage_lists_the_max_retained_bytes_flag() {
        // The new retention flag is documented in the USAGE string, so `ironbus help` surfaces it.
        assert!(
            USAGE.contains("--max-retained-bytes"),
            "USAGE must document the retention flag"
        );
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_age_ms() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-age-ms".to_string(),
                "soon".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-age-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_messages() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-messages".to_string(),
                "many".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-messages"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_max_age_ms_and_max_messages_values() {
        // Both new retention flags parse and validate (no usage error); the only failure is the
        // unrelated bind on an unreachable addr, proving the flags were accepted, not rejected.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-age-count-never-served".to_string(),
                "--max-age-ms".to_string(),
                "60000".to_string(),
                "--max-messages".to_string(),
                "100000".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "valid --max-age-ms and --max-messages parse and validate: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-age-count-never-served");
    }

    #[test]
    fn usage_lists_the_age_and_count_retention_flags() {
        // Both new retention flags are documented in the USAGE string, so `ironbus help` surfaces
        // them alongside the byte bound.
        assert!(
            USAGE.contains("--max-age-ms"),
            "USAGE must document --max-age-ms"
        );
        assert!(
            USAGE.contains("--max-messages"),
            "USAGE must document --max-messages"
        );
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_groups() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-groups".to_string(),
                "many".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-groups"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_a_max_groups_value() {
        // A valid --max-groups parses and validates (no usage error); the only failure is the
        // unrelated bind on an unreachable addr, proving the flag was accepted, not rejected.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mg-never-served".to_string(),
                "--max-groups".to_string(),
                "16".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "a valid --max-groups parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mg-never-served");
    }

    #[test]
    fn serve_accepts_a_zero_max_groups_meaning_unlimited() {
        // `0` = unlimited (the cap is off), matching the `0` = off convention of the other bounds.
        // An explicit 0 must parse the same as the default, so the only failure is the unrelated
        // bind path, never EXIT_USAGE.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mg0-never-served".to_string(),
                "--max-groups".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --max-groups 0 (unlimited) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mg0-never-served");
    }

    #[test]
    fn usage_lists_the_max_groups_flag() {
        assert!(
            USAGE.contains("--max-groups"),
            "USAGE must document --max-groups"
        );
    }

    // ----- Idle named-group eviction flag (#277) -----

    #[test]
    fn serve_parses_the_group_idle_evict_ms_flag() {
        // The --group-idle-evict-ms flag (#277) parses its value into the ServeConfig, so the engine
        // receives the configured idle window.
        let parsed = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/ironbus-cli-gie-never-served".to_string(),
            "--group-idle-evict-ms".to_string(),
            "60000".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.config.group_idle_evict_ms, 60000);
    }

    #[test]
    fn the_group_idle_evict_ms_default_is_disabled() {
        // The default is 0 (disabled / never evict), matching the engine default and the `0` = off
        // convention of the other bounds, so an unconfigured broker never reclaims named groups.
        let parsed = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/ironbus-cli-gie-default-never-served".to_string(),
        ])
        .unwrap();
        assert_eq!(
            parsed.config.group_idle_evict_ms,
            DEFAULT_GROUP_IDLE_EVICT_MS
        );
        assert_eq!(DEFAULT_GROUP_IDLE_EVICT_MS, 0);
    }

    #[test]
    fn serve_accepts_a_zero_group_idle_evict_ms_meaning_disabled() {
        // An explicit 0 (disabled) parses the same as the default, so the only failure is the
        // unrelated bind path, never EXIT_USAGE.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-gie0-never-served".to_string(),
                "--group-idle-evict-ms".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --group-idle-evict-ms 0 (disabled) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-gie0-never-served");
    }

    #[test]
    fn serve_rejects_a_non_numeric_group_idle_evict_ms() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--group-idle-evict-ms".to_string(),
                "soon".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--group-idle-evict-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_lists_the_group_idle_evict_ms_flag() {
        assert!(
            USAGE.contains("--group-idle-evict-ms"),
            "USAGE must document --group-idle-evict-ms"
        );
    }

    // ----- Per-consumer BYTE budget flag (#275) -----

    #[test]
    fn serve_parses_the_consumer_credit_bytes_flag() {
        // The --consumer-credit-bytes flag (#275) parses its value into the ServeConfig, so the
        // engine receives the configured byte budget.
        let parsed = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/ironbus-cli-ccb-never-served".to_string(),
            "--consumer-credit-bytes".to_string(),
            "65536".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.config.consumer_credit_bytes, 65536);
    }

    #[test]
    fn the_consumer_credit_bytes_default_is_eight_mib() {
        // Omitted, the flag defaults to 8 MiB, aliased to the engine default so the two never drift.
        let parsed = parse_serve_flags(&["--data-dir".to_string(), "/tmp/x".to_string()]).unwrap();
        assert_eq!(
            parsed.config.consumer_credit_bytes,
            DEFAULT_CONSUMER_CREDIT_BYTES
        );
        assert_eq!(DEFAULT_CONSUMER_CREDIT_BYTES, 8 * 1024 * 1024);
    }

    // ----- Env-var mapping with flag > env > default precedence (#89) -----

    /// Builds an injected env lookup from a fixed list of (name, value) pairs, so the env layer is
    /// driven DETERMINISTICALLY without touching (and racing on) the real process environment.
    fn fixed_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn the_env_var_name_mapping_is_ironbus_uppercase_underscored() {
        // `--max-total-bytes` -> `IRONBUS_MAX_TOTAL_BYTES`, `--data-dir` -> `IRONBUS_DATA_DIR`,
        // `--addr` -> `IRONBUS_ADDR`: leading dashes stripped, `-` -> `_`, uppercased, `IRONBUS_`.
        assert_eq!(env_var_name("--max-total-bytes"), "IRONBUS_MAX_TOTAL_BYTES");
        assert_eq!(env_var_name("--data-dir"), "IRONBUS_DATA_DIR");
        assert_eq!(env_var_name("--addr"), "IRONBUS_ADDR");
        assert_eq!(env_var_name("--enable-admin"), "IRONBUS_ENABLE_ADMIN");
    }

    #[test]
    fn env_var_sets_a_value_when_no_flag_is_given() {
        // No `--max-total-bytes` flag, but `IRONBUS_MAX_TOTAL_BYTES` set: the env value applies.
        let env = fixed_env(&[
            ("IRONBUS_MAX_TOTAL_BYTES", "4096"),
            ("IRONBUS_DATA_DIR", "/tmp/ironbus-env-dd"),
            ("IRONBUS_ADDR", "127.0.0.1:9999"),
        ]);
        let parsed = parse_serve_flags_with_env(&[], &env).expect("env-only serve config resolves");
        assert_eq!(parsed.config.max_total_bytes, 4096, "env value applied");
        assert_eq!(parsed.data_dir.as_deref(), Some("/tmp/ironbus-env-dd"));
        assert_eq!(parsed.addr, "127.0.0.1:9999");
    }

    #[test]
    fn an_explicit_flag_overrides_the_env_var() {
        // The flag wins over the env var (flag > env): `--max-total-bytes 100` beats the env's 4096.
        let env = fixed_env(&[
            ("IRONBUS_MAX_TOTAL_BYTES", "4096"),
            ("IRONBUS_ADDR", "127.0.0.1:9999"),
        ]);
        let parsed = parse_serve_flags_with_env(
            &[
                "--max-total-bytes".to_string(),
                "100".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1234".to_string(),
            ],
            &env,
        )
        .unwrap();
        assert_eq!(parsed.config.max_total_bytes, 100, "the flag overrides env");
        assert_eq!(parsed.addr, "127.0.0.1:1234", "the flag overrides env");
    }

    #[test]
    fn the_default_applies_when_neither_flag_nor_env_is_given() {
        // Neither a flag nor an env var: the compiled default (flag > env > default).
        let env = fixed_env(&[]);
        let parsed = parse_serve_flags_with_env(&[], &env).unwrap();
        assert_eq!(parsed.config.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert_eq!(parsed.addr, DEFAULT_ADDR);
        assert_eq!(
            parsed.data_dir, None,
            "no data dir from flag, env, or default"
        );
    }

    #[test]
    fn the_wal_fsync_headroom_resolves_flag_over_env_over_default_and_logs_it() {
        // The #378 knob follows the standard flag > env > default precedence, defaults to OFF, and is
        // surfaced on the materialized-config startup line so an operator sees the active bound.
        // Default: OFF (0), a zero-config broker is unchanged.
        let parsed = parse_serve_flags(&serve_args(&[])).unwrap();
        assert_eq!(
            parsed.config.wal_fsync_headroom_bytes, DEFAULT_WAL_FSYNC_HEADROOM_BYTES,
            "the default headroom is the compiled default (0 = off)"
        );
        assert_eq!(
            parsed.config.wal_fsync_headroom_bytes, 0,
            "the compiled default is off"
        );

        // Env var sets it when no flag is given.
        let env = fixed_env(&[("IRONBUS_WAL_FSYNC_HEADROOM_BYTES", "65536")]);
        let from_env = parse_serve_flags_with_env(&serve_args(&[]), &env).unwrap();
        assert_eq!(
            from_env.config.wal_fsync_headroom_bytes, 65536,
            "the env var applies when no flag is given"
        );

        // The flag overrides the env var.
        let from_flag =
            parse_serve_flags_with_env(&serve_args(&["--wal-fsync-headroom-bytes", "4096"]), &env)
                .unwrap();
        assert_eq!(
            from_flag.config.wal_fsync_headroom_bytes, 4096,
            "the flag overrides the env var (flag > env)"
        );

        // The materialized-config startup line carries the resolved value.
        let line = materialized_config_line(
            &from_flag.config,
            "127.0.0.1:7777",
            Path::new("/var/lib/ironbus"),
        );
        assert!(
            line.contains("wal_fsync_headroom_bytes=4096"),
            "the materialized-config line surfaces the resolved headroom: {line}"
        );
    }

    #[test]
    fn an_invalid_env_value_is_a_typed_error_naming_the_env_var() {
        // A non-numeric env value where a number is expected is a usage error that NAMES THE ENV VAR
        // (not the flag), exactly as a bad flag value names the flag.
        let env = fixed_env(&[("IRONBUS_MAX_TOTAL_BYTES", "not-a-number")]);
        let e = parse_serve_flags_with_env(&[], &env).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => {
                assert!(
                    m.contains("IRONBUS_MAX_TOTAL_BYTES"),
                    "names the env var: {m}"
                );
                assert!(m.contains("not-a-number"), "echoes the bad value: {m}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn an_env_supplied_bool_and_list_resolve_through_the_seam() {
        // The boolean (`IRONBUS_ENABLE_ADMIN`) and the comma-separated list (`IRONBUS_BACKOFF_MS`)
        // resolve through the env seam with the same grammar as their flags.
        let env = fixed_env(&[
            ("IRONBUS_ENABLE_ADMIN", "true"),
            ("IRONBUS_BACKOFF_MS", "100, 500 ,2000"),
        ]);
        let parsed = parse_serve_flags_with_env(&[], &env).unwrap();
        assert!(
            parsed.config.enable_admin,
            "env-supplied bool enabled admin"
        );
        assert_eq!(
            parsed.config.backoff_ms,
            vec![100, 500, 2000],
            "env list parsed"
        );
        // An invalid bool value names the env var.
        let bad = parse_serve_flags_with_env(&[], &fixed_env(&[("IRONBUS_ENABLE_ADMIN", "maybe")]))
            .unwrap_err();
        match bad {
            CliError::Usage(m) => assert!(m.contains("IRONBUS_ENABLE_ADMIN"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn an_env_supplied_disk_full_policy_resolves_and_a_bad_one_names_the_env_var() {
        let parsed = parse_serve_flags_with_env(
            &[],
            &fixed_env(&[("IRONBUS_DISK_FULL_POLICY", "drop-oldest")]),
        )
        .unwrap();
        assert_eq!(
            parsed.config.disk_full_policy,
            DiskFullPolicyArg::DropOldest
        );
        let bad = parse_serve_flags_with_env(
            &[],
            &fixed_env(&[("IRONBUS_DISK_FULL_POLICY", "drop-everything")]),
        )
        .unwrap_err();
        match bad {
            CliError::Usage(m) => assert!(m.contains("IRONBUS_DISK_FULL_POLICY"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_and_cli_docs_document_the_env_var_mapping() {
        // The env-var surface is documented in the usage banner and in docs/CLI.md (#89).
        assert!(
            USAGE.contains("IRONBUS_"),
            "USAGE must document the env-var mapping"
        );
    }

    // ----- data_dir lifecycle and the single-broker lock on serve (#89) -----

    #[cfg(unix)]
    #[test]
    fn serve_creates_a_missing_data_dir() {
        // serve creates the data dir (and parents) if absent. We point it at an UNBINDABLE address so
        // the call errors at the bind step (after the dir is prepared), proving creation happened
        // without leaving a broker running.
        let dir = std::env::temp_dir().join(format!(
            "ironbus-cli-serve-mkdir-{}/nested/leaf",
            std::process::id()
        ));
        let base =
            std::env::temp_dir().join(format!("ironbus-cli-serve-mkdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        assert!(!dir.exists());
        let mut buf = Vec::new();
        // Port 0 binds fine, so use a host the OS refuses to bind to force a post-prepare error.
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--addr".to_string(),
                "240.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        // It got past the data-dir lifecycle (the dir now exists) and failed later (bind).
        assert!(
            dir.is_dir(),
            "serve created the missing data dir and parents: {e}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn serve_on_a_non_directory_data_dir_is_a_usage_error() {
        // A --data-dir that exists but is a regular file is a typed usage error naming the path,
        // before the broker opens.
        let base =
            std::env::temp_dir().join(format!("ironbus-cli-serve-nondir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                file.display().to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE, "{e}");
        match &e {
            CliError::Usage(m) => assert!(m.contains("not a directory"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn serve_fails_fast_when_the_data_dir_is_already_locked() {
        // Hold the single-broker lock, then attempt a serve on the same data dir: it must fail fast
        // with the typed "already running" error (a non-zero exit), NOT double-open and corrupt.
        let dir =
            std::env::temp_dir().join(format!("ironbus-cli-serve-locked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dirlock::prepare_data_dir(&dir).unwrap();
        let held = dirlock::DirLock::acquire(&dir).unwrap();
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--addr".to_string(),
                "127.0.0.1:0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(e.exit_code(), 0, "a contended serve exits non-zero: {e}");
        let msg = e.to_string();
        assert!(
            msg.contains("already running"),
            "the typed single-broker error: {msg}"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serve_enable_admin_is_off_by_default_and_set_by_the_flag() {
        // The read-only /admin endpoint (#99) is opt-in: absent the flag it is off.
        let off = parse_serve_flags(&["--data-dir".to_string(), "/tmp/x".to_string()]).unwrap();
        assert!(!off.config.enable_admin, "admin is off by default");
        // `--enable-admin` is a bare boolean (no value): it sets the flag and the loop advances one
        // token, so a following flag still parses.
        let on = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/x".to_string(),
            "--enable-admin".to_string(),
            "--max-in-flight".to_string(),
            "8".to_string(),
        ])
        .unwrap();
        assert!(on.config.enable_admin, "admin is on with --enable-admin");
        assert_eq!(on.config.max_in_flight, 8, "the trailing flag still parses");
    }

    #[test]
    fn serve_otlp_export_is_off_by_default_and_set_by_the_flags() {
        // OTLP span export (#352) is opt-in: absent the flags it is off with no endpoint.
        let off = parse_serve_flags(&["--data-dir".to_string(), "/tmp/x".to_string()]).unwrap();
        assert!(!off.config.enable_otlp_export, "export is off by default");
        assert!(off.config.otlp_endpoint.is_none(), "no endpoint by default");
        // `--enable-otlp-export` is a bare boolean (advances one token); `--otlp-endpoint` takes a
        // value. Both parse, and a trailing flag after the bare flag still parses.
        let on = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/x".to_string(),
            "--enable-otlp-export".to_string(),
            "--otlp-endpoint".to_string(),
            "http://collector:4317".to_string(),
            "--max-in-flight".to_string(),
            "8".to_string(),
        ])
        .unwrap();
        assert!(on.config.enable_otlp_export, "export is on with the flag");
        assert_eq!(
            on.config.otlp_endpoint.as_deref(),
            Some("http://collector:4317"),
            "the endpoint is parsed"
        );
        assert_eq!(on.config.max_in_flight, 8, "the trailing flag still parses");
    }

    #[test]
    fn health_bind_classifies_loopback_and_non_loopback() {
        // The #95 secure-bind classification is on the RESOLVED address. Loopback literals classify
        // loopback; the wildcard and a routable literal classify non-loopback.
        let (_a, loopback) = resolve_and_classify_health_bind("127.0.0.1:9095").unwrap();
        assert!(loopback, "127.0.0.1 is loopback");
        let (_a, loopback) = resolve_and_classify_health_bind("127.0.0.5:9095").unwrap();
        assert!(loopback, "all of 127.0.0.0/8 is loopback");
        let (_a, loopback) = resolve_and_classify_health_bind("[::1]:9095").unwrap();
        assert!(loopback, "::1 is loopback");
        // The unspecified wildcard exposes every interface, so it is NOT loopback.
        let (_a, loopback) = resolve_and_classify_health_bind("0.0.0.0:9095").unwrap();
        assert!(!loopback, "0.0.0.0 (every interface) is non-loopback");
        let (_a, loopback) = resolve_and_classify_health_bind("[::]:9095").unwrap();
        assert!(!loopback, ":: (every interface) is non-loopback");
        // A routable literal IP is non-loopback (a documentation-range address, never dialed).
        let (_a, loopback) = resolve_and_classify_health_bind("192.0.2.1:9095").unwrap();
        assert!(!loopback, "a routable IP is non-loopback");
    }

    #[test]
    fn health_bind_rejects_an_unresolvable_address() {
        // A malformed or unresolvable --health-addr fails closed with a usage error naming the value,
        // never silently binds nothing. `.invalid` is the reserved never-resolves TLD (RFC 6761).
        let e = resolve_and_classify_health_bind("no-such-host.invalid:9095").unwrap_err();
        assert!(matches!(e, CliError::Usage(_)), "got {e:?}");
        let e = resolve_and_classify_health_bind("not-a-host-port").unwrap_err();
        assert!(matches!(e, CliError::Usage(_)), "got {e:?}");
    }

    #[test]
    fn health_bind_decision_is_fail_closed_for_a_non_loopback_bind() {
        // The teeth of the secure-bind guard (#95): a NON-LOOPBACK bind WITHOUT the acknowledgement
        // is refused (the broker would never start). Remove the guard and this fails.
        let e = health_bind_decision("0.0.0.0:9095", false).unwrap_err();
        match e {
            CliError::Usage(m) => {
                assert!(m.contains("0.0.0.0:9095"), "names the address: {m}");
                assert!(
                    m.contains("UNAUTHENTICATED"),
                    "explains the missing auth: {m}"
                );
                assert!(
                    m.contains("--health-allow-public"),
                    "names the ack flag: {m}"
                );
            }
            other => panic!("expected a usage refusal, got {other:?}"),
        }
        // A hostname that resolves to a non-loopback IP is caught the same way (classification is on
        // the resolved address, not the literal string).
        assert!(
            matches!(
                health_bind_decision("192.0.2.7:9095", false),
                Err(CliError::Usage(_))
            ),
            "a routable address with no ack is refused"
        );
    }

    #[test]
    fn health_bind_decision_loopback_binds_silently_and_ack_binds_with_a_warning() {
        // Loopback MAY run unauthenticated with NO warning (the trust boundary is the host).
        let d = health_bind_decision("127.0.0.1:0", false).unwrap();
        assert!(!d.warn_public, "loopback never warns");
        assert!(
            !d.addrs.is_empty(),
            "loopback resolves to an address to bind"
        );
        // The ack flag has no effect on a loopback bind (still silent).
        let d = health_bind_decision("127.0.0.1:0", true).unwrap();
        assert!(!d.warn_public, "loopback stays silent even with the ack");
        // A NON-LOOPBACK bind WITH the acknowledgement starts, and flags the loud warning.
        let d = health_bind_decision("0.0.0.0:0", true).unwrap();
        assert!(
            d.warn_public,
            "an acknowledged non-loopback bind warns loudly"
        );
        assert!(!d.addrs.is_empty(), "it resolves an address to bind");
    }

    #[test]
    fn serve_parses_the_health_liveness_window_and_allow_public_flags() {
        // The #95 knobs: the liveness window (ms) and the bare allow-public ack flag parse into the
        // ServeConfig with the documented defaults absent the flags.
        let def = parse_serve_flags(&["--data-dir".to_string(), "/tmp/x".to_string()]).unwrap();
        assert_eq!(
            def.config.health_liveness_window_ms, DEFAULT_HEALTH_LIVENESS_WINDOW_MS,
            "the liveness window defaults to 10 s"
        );
        assert!(
            !def.config.health_allow_public,
            "the public-bind ack is off by default (fail-closed)"
        );
        let set = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/x".to_string(),
            "--health-liveness-window-ms".to_string(),
            "0".to_string(),
            "--health-allow-public".to_string(),
            "--max-in-flight".to_string(),
            "8".to_string(),
        ])
        .unwrap();
        assert_eq!(
            set.config.health_liveness_window_ms, 0,
            "0 disables the watchdog"
        );
        assert!(
            set.config.health_allow_public,
            "the bare ack flag sets true"
        );
        assert_eq!(
            set.config.max_in_flight, 8,
            "the trailing flag still parses"
        );
    }

    #[test]
    fn serve_rejects_a_non_numeric_health_liveness_window() {
        // A bad --health-liveness-window-ms value is a usage error naming the flag, like every other
        // numeric serve flag (it never silently falls back to a default).
        let e = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/x".to_string(),
            "--health-liveness-window-ms".to_string(),
            "soon".to_string(),
        ])
        .unwrap_err();
        match e {
            CliError::Usage(m) => assert!(m.contains("--health-liveness-window-ms"), "{m}"),
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    // The guard runs inside the Unix `cmd_serve` (the non-Unix `cmd_serve` is a stub that errors
    // before it), so this end-to-end refusal test is Unix-only, like the other `serve` runtime tests.
    #[cfg(unix)]
    #[test]
    fn serve_refuses_a_non_loopback_health_addr_without_the_ack() {
        // END TO END through `run`: a non-loopback --health-addr with no acknowledgement fails to
        // start with a usage error (exit 1) and binds nothing. The data dir is never served.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-health-public-never-served".to_string(),
                "--health-addr".to_string(),
                "0.0.0.0:9099".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE, "the refusal is exit 1");
        match e {
            CliError::Usage(m) => {
                assert!(
                    m.contains("0.0.0.0:9099"),
                    "names the offending address: {m}"
                );
                assert!(
                    m.contains("--health-allow-public"),
                    "names the ack flag: {m}"
                );
            }
            other => panic!("expected a fail-closed usage error, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_a_zero_consumer_credit_bytes_meaning_unlimited() {
        // `0` = unlimited (the byte budget is off), matching the `0` = off convention of the other
        // byte bounds. Unlike --consumer-credit (where 0 is a usage error), a 0 byte budget is a
        // valid, meaningful value (only the message credit binds), so it must parse and validate.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-ccb0-never-served".to_string(),
                "--consumer-credit-bytes".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --consumer-credit-bytes 0 (unlimited) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-ccb0-never-served");
    }

    #[test]
    fn serve_rejects_a_non_numeric_consumer_credit_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--consumer-credit-bytes".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--consumer-credit-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_lists_the_consumer_credit_bytes_flag() {
        assert!(
            USAGE.contains("--consumer-credit-bytes"),
            "USAGE must document --consumer-credit-bytes"
        );
    }

    #[test]
    fn serve_accepts_repeated_key_shared_group_flags() {
        // The repeatable --key-shared-group flag (#64) parses and validates; the only failure is
        // the unrelated bind on an unreachable addr, proving the flag was accepted.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-ksg-never-served".to_string(),
                "--key-shared-group".to_string(),
                "orders".to_string(),
                "--key-shared-group".to_string(),
                "events".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "repeated --key-shared-group flags parse and validate: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-ksg-never-served");
    }

    #[test]
    fn serve_rejects_a_key_shared_group_without_a_value() {
        let mut buf = Vec::new();
        let e = run(
            &["serve".to_string(), "--key-shared-group".to_string()],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--key-shared-group"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_lists_the_key_shared_group_flag() {
        assert!(
            USAGE.contains("--key-shared-group"),
            "USAGE must document --key-shared-group"
        );
    }

    #[test]
    fn serve_rejects_a_tiny_max_segment_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-msb-never-created".to_string(),
                "--max-segment-bytes".to_string(),
                "100".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_visibility_timeout() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--visibility-timeout-ms".to_string(),
                "soon".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--visibility-timeout-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_visibility_timeout() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-vt0-never-created".to_string(),
                "--visibility-timeout-ms".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least 1"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn an_unreachable_broker_maps_to_exit_five() {
        // Port 1 on loopback refuses immediately, so this does not hang on the connect timeout.
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_UNREACHABLE, "{e}");
        assert!(matches!(e, CliError::Unreachable(_)));
    }

    #[test]
    fn sub_rejects_two_dispositions() {
        let mut buf = Vec::new();
        let e = run(
            &["sub".to_string(), "--ack".to_string(), "--nack".to_string()],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        assert!(matches!(e, CliError::Usage(_)));
    }

    #[test]
    fn delay_ms_requires_nack() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--ack".to_string(),
                "--delay-ms".to_string(),
                "5".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        assert!(matches!(e, CliError::Usage(m) if m.contains("--delay-ms")));
    }

    #[test]
    fn nack_delay_is_order_independent() {
        // `--delay-ms` before `--nack` must be accepted (the validation runs after the parse
        // loop). With no broker it then fails to connect (exit 5), proving the flags parsed
        // rather than tripping a usage error (exit 1).
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
                "--delay-ms".to_string(),
                "7".to_string(),
                "--nack".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(
            e.exit_code(),
            EXIT_UNREACHABLE,
            "parsed then failed to connect: {e}"
        );
    }

    #[test]
    fn sub_nack_requeues_and_sub_term_drops() {
        let (addr, shutdown, handle) = start_inmem_server();
        let a = addr.to_string();

        // Nack: the message is requeued and redelivers on the next fetch (the default 30s
        // visibility means the redelivery is the nack's doing, not a timeout).
        cmd_pub(&a, b"", b"retry", &mut Vec::new()).unwrap();
        let mut nout = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Nack { delay_ms: None }, &mut nout).unwrap();
        assert!(String::from_utf8(nout).unwrap().contains("nack requeued"));
        let mut aout = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Ack, &mut aout).unwrap();
        let atext = String::from_utf8(aout).unwrap();
        assert!(atext.contains("payload=retry"), "redelivered: {atext}");
        assert!(atext.contains("ack committed"), "acked: {atext}");

        // Term: the message is dropped (committed past) and a re-fetch is empty.
        cmd_pub(&a, b"", b"drop", &mut Vec::new()).unwrap();
        let mut tout = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Term, &mut tout).unwrap();
        assert!(String::from_utf8(tout).unwrap().contains("term dropped"));
        let mut eout = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Peek, &mut eout).unwrap();
        assert_eq!(String::from_utf8(eout).unwrap(), "fetched 0 message(s)\n");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_poison_message_is_dead_lettered_after_exceeding_max_deliver() {
        // The golden-path poison case end to end over the wire: a short visibility timeout
        // (so the redelivery is fast) and max_deliver = 1. The first peek leases the message
        // (delivery 1); after the timeout the next fetch is delivery 2, which exceeds the cap,
        // so the engine dead-letters it (parked, not redelivered) and records the drop with
        // its offset. This is platform-agnostic (in-memory fs) but uses the real clock for the
        // visibility timeout, with a 10x sleep margin so it is not flaky.
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::from_millis(50, 300_000),
                delivery: DeliveryConfig::new(1, false, Vec::new()).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: ironbus_server::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert in this test EngineConfig.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
            },
        )
        .unwrap();
        let (addr, shutdown, handle, actor) = serve_engine(engine, 16);
        let a = addr.to_string();

        cmd_pub(&a, b"", b"poison", &mut Vec::new()).unwrap();

        // Delivery 1: peeked (leased), not acked.
        let mut first = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Peek, &mut first).unwrap();
        assert!(
            String::from_utf8(first).unwrap().contains("payload=poison"),
            "the first delivery is served"
        );

        // Past the visibility timeout, delivery 2 exceeds max_deliver = 1: dead-lettered, so
        // the re-fetch is empty.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut second = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Peek, &mut second).unwrap();
        assert_eq!(
            String::from_utf8(second).unwrap(),
            "dead-letter offset=0 reason=max-deliver\nfetched 0 message(s)\n",
            "the consumer is told the poison message was dead-lettered via the in-band advisory \
             (#63); it is not redelivered"
        );

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
        // The engine recorded the drop and its offset (the resilience signal). Recover it from the
        // actor after the clean stop and inspect it directly.
        let g = recover_engine(actor);
        assert_eq!(g.counters().dead_lettered, 1, "exactly one dead-letter");
        assert!(
            g.last_dead_lettered_offset().is_some_and(|o| o.get() == 0),
            "the dead-lettered offset is reported"
        );
    }

    #[test]
    fn the_in_flight_window_bounds_each_delivery_batch() {
        // Backpressure / no unbounded in-flight (#133 overload): with max_in_flight = 2, each
        // fetch delivers at most 2 messages even with a credit of 10 and 4 produced. The
        // window, not the credit, is the cap; acks free slots for the next batch.
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::from_millis(30_000, 300_000),
                delivery: DeliveryConfig::new(5, false, Vec::new()).unwrap(),
                max_in_flight: 2,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: ironbus_server::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert in this test EngineConfig.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
            },
        )
        .unwrap();
        let (addr, shutdown, handle, _actor) = serve_engine(engine, 16);
        let a = addr.to_string();

        for (i, payload) in [&b"a"[..], b"b", b"c", b"d"].into_iter().enumerate() {
            let mut out = Vec::new();
            cmd_pub(&a, b"", payload, &mut out).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), format!("{i}\n"));
        }

        // Observe the per-batch window at the Flow layer: `cmd_sub --ack` deliberately drains
        // across batches up to `--max` (#65 SHOULD-FIX), so a single CLI call no longer exposes one
        // window-bounded batch. Drive the protocol directly to assert each fetch is capped at the
        // in-flight window of 2, not the credit of 10.
        let mut client = Client::connect(&a).unwrap();

        // First fetch: capped at the window of 2 despite a credit of 10 and 4 available.
        let batch1 = client.fetch(10).unwrap();
        assert_eq!(
            batch1.messages.len(),
            2,
            "the in-flight window caps the batch at 2, not the credit of 10"
        );
        assert_eq!(batch1.messages[0].payload.as_slice(), b"a");
        assert_eq!(batch1.messages[1].payload.as_slice(), b"b");
        for m in &batch1.messages {
            assert!(client.ack(m.offset, m.generation).unwrap(), "ack committed");
        }

        // The acks freed the window; the next fetch delivers the next two.
        let batch2 = client.fetch(10).unwrap();
        assert_eq!(
            batch2.messages.len(),
            2,
            "the next batch is also capped at 2"
        );
        assert_eq!(batch2.messages[0].payload.as_slice(), b"c");
        assert_eq!(batch2.messages[1].payload.as_slice(), b"d");
        for m in &batch2.messages {
            assert!(client.ack(m.offset, m.generation).unwrap(), "ack committed");
        }

        // All four committed: the stream is drained.
        let batch3 = client.fetch(10).unwrap();
        assert!(batch3.messages.is_empty(), "the stream is drained");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn serve_on_disk_round_trips_and_survives_a_restart() {
        // Exercise the CLI-specific disk wiring (create dir, StdFs, Engine::open), a full
        // publish/fetch/ack round-trip over a real directory, and durability across a restart.
        let dir = std::env::temp_dir().join(format!("ironbus-cli-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let engine = open_disk_engine(&dir, &test_serve_config(64, 1), &[], &[]).unwrap();
        let (addr, shutdown, handle, actor) = serve_engine(engine, 16);

        let a = addr.to_string();
        let mut published = Vec::new();
        cmd_pub(&a, b"k", b"on-disk", &mut published).unwrap();
        assert_eq!(String::from_utf8(published).unwrap(), "0\n");

        let mut consumed = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Ack, &mut consumed).unwrap();
        let text = String::from_utf8(consumed).unwrap();
        assert!(text.contains("payload=on-disk"), "missing payload: {text}");
        assert!(text.contains("ack committed"), "missing ack: {text}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
        // Recover and DROP the engine before reopening the same dir, so the actor has drained every
        // queued checkpoint (the ack at checkpoint_interval = 1 and the close-path flush) and the
        // StdFs file handles are released. This makes the restart deterministic.
        drop(recover_engine(actor));

        // Restart: reopen the SAME data dir. With checkpoint_interval = 1, the server persisted the
        // committed cursor when it acked offset 0, so a clean restart RESUMES past the acked message
        // (it does not redeliver), and the durable log continues at offset 1 rather than overwriting
        // offset 0.
        let reopened = open_disk_engine(&dir, &test_serve_config(64, 1), &[], &[]).unwrap();
        let (addr2, shutdown2, handle2, actor2) = serve_engine(reopened, 16);
        let a2 = addr2.to_string();

        let mut after_restart = Vec::new();
        cmd_sub(&a2, "", 10, Disposition::Peek, &mut after_restart).unwrap();
        assert_eq!(
            String::from_utf8(after_restart).unwrap(),
            "fetched 0 message(s)\n",
            "acked message redelivered after restart: cursor was not checkpointed"
        );

        let mut next = Vec::new();
        cmd_pub(&a2, b"k", b"after-restart", &mut next).unwrap();
        assert_eq!(
            String::from_utf8(next).unwrap(),
            "1\n",
            "log did not persist offset 0 across restart"
        );

        shutdown2.store(true, Ordering::Release);
        handle2.join().unwrap();
        drop(recover_engine(actor2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_restart_redelivers_only_the_uncommitted_tail() {
        // Durability across a restart with a PARTIAL ack: produce three messages, ack only the
        // first, then restart on the same data dir. The acked message stays committed (never
        // redelivers), and the uncommitted tail (offsets 1 and 2) redelivers. The core
        // no-acked-write-lost / uncommitted-tail-redelivers invariant, end to end over the wire.
        let dir = std::env::temp_dir().join(format!("ironbus-cli-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let engine = open_disk_engine(&dir, &test_serve_config(64, 1), &[], &[]).unwrap();
        let (addr, shutdown, handle, actor) = serve_engine(engine, 16);
        let a = addr.to_string();
        for (i, payload) in [&b"m0"[..], b"m1", b"m2"].into_iter().enumerate() {
            let mut out = Vec::new();
            cmd_pub(&a, b"", payload, &mut out).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), format!("{i}\n"));
        }
        // A credit of 1 leases and acks exactly the first message (offset 0); the cursor is
        // checkpointed (checkpoint_interval = 1, plus the clean disconnect).
        let mut acked = Vec::new();
        cmd_sub(&a, "", 1, Disposition::Ack, &mut acked).unwrap();
        let acked = String::from_utf8(acked).unwrap();
        assert!(
            acked.contains("payload=m0"),
            "acked the first message: {acked}"
        );
        assert!(acked.contains("ack committed"), "committed: {acked}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
        // Drain the actor and release the StdFs handles before reopening the same dir.
        drop(recover_engine(actor));

        // Restart on the same dir: only the uncommitted tail (offsets 1 and 2) redelivers.
        let reopened = open_disk_engine(&dir, &test_serve_config(64, 1), &[], &[]).unwrap();
        let (addr2, shutdown2, handle2, actor2) = serve_engine(reopened, 16);
        let a2 = addr2.to_string();
        let mut tail = Vec::new();
        cmd_sub(&a2, "", 10, Disposition::Peek, &mut tail).unwrap();
        let tail = String::from_utf8(tail).unwrap();
        assert!(
            tail.contains("fetched 2 message(s)"),
            "the two uncommitted messages redeliver: {tail}"
        );
        assert!(
            tail.contains("payload=m1") && tail.contains("payload=m2"),
            "the tail content redelivers: {tail}"
        );
        assert!(
            !tail.contains("payload=m0"),
            "the acked message must not redeliver after a restart: {tail}"
        );

        shutdown2.store(true, Ordering::Release);
        handle2.join().unwrap();
        drop(recover_engine(actor2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
