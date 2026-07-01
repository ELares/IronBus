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

/// The value the disk-free and ratio gauges report when the quantity cannot be computed on this
/// platform (or no ceiling is configured): `-1`, the same unambiguous "unavailable" sentinel
/// [`RSS_UNAVAILABLE`] uses. A real free-byte count or ratio is never negative, so `-1` is
/// unambiguous and consistent with the existing `ironbus_ram_headroom_bytes` / `_last_dead_lettered`
/// convention on `/metrics`.
pub const UNAVAILABLE: i64 = -1;

/// Reads the FREE (available-to-an-unprivileged-process) bytes on the filesystem that holds `path`,
/// or `None` if it cannot be determined on this platform (so the caller reports "unavailable" rather
/// than a misleading zero).
///
/// Implemented without `unsafe` and without a new dependency by shelling out to the POSIX
/// `df -k -P <path>` (the portable, header-stable form), exactly as [`current_rss_bytes`] shells to
/// `ps` on macOS: it parses the "Available" 1024-byte-block column and multiplies to bytes. It is
/// available on Linux and macOS (the edge target and the dev host); anywhere `df` is absent or
/// unparseable it degrades to `None`. Best-effort and side-effect-free beyond the read; never panics
/// and never blocks the broker. Read OUT-OF-BAND (not from any in-process accounting), like RSS.
#[must_use]
pub fn disk_free_bytes(path: &std::path::Path) -> Option<u64> {
    // `df -P` (POSIX mode) guarantees a stable single header line then one data line per filesystem;
    // `-k` pins the block size to 1024 bytes so the "Available" column is portable across Linux and
    // macOS (which otherwise default to different block sizes). Pass the path so we measure the
    // filesystem the data dir actually lives on, not the cwd's.
    let out = std::process::Command::new("df")
        .args(["-k", "-P"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // The data line is the LAST non-empty line (a long device name can wrap onto two lines in some
    // `df` variants, but `-P` forbids that wrap, so the single data line is the last one). Columns:
    // Filesystem, 1024-blocks, Used, Available, Capacity, Mounted-on. "Available" is index 3.
    let data = text.lines().rfind(|l| !l.trim().is_empty())?;
    let available_kib: u64 = data.split_whitespace().nth(3)?.parse().ok()?;
    Some(available_kib.saturating_mul(1024))
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

/// The number of parts-per-thousand the `ironbus_ram_headroom_ratio` gauge reports as: a fraction in
/// `[0, 1]` rendered as an integer in `[0, 1000]` (per-mille), so the ratio is exposed WITHOUT
/// floating point (the same float-free integer-milli convention `ironbus_write_amp_ratio` uses). The
/// renderer prints `value / 1000`.`value % 1000` as the `0.xyz` ratio.
pub const RATIO_SCALE: u64 = 1000;

/// Computes the RAM headroom RATIO in per-mille (#574): the fraction of the configured RAM `ceiling`
/// that is still HEADROOM (`(ceiling - rss) / ceiling`), as an integer in `[0, RATIO_SCALE]`, or
/// [`UNAVAILABLE`] (`-1`) when the ceiling is unset (`0`) or RSS could not be read. It is the
/// headroom-bytes gauge expressed as a dimensionless, ceiling-relative ratio so an operator can
/// alert on "under 10% headroom" without hard-coding the box's byte ceiling. Computed in `u128` to
/// avoid overflow on the scale multiply, rounded to the nearest per-mille; `1000` = all headroom (RSS
/// near zero), `0` = at or over the ceiling. Pairs with [`rss_over_cap_ratio`].
#[must_use]
pub fn ram_headroom_ratio_permille(ceiling: u64, rss: Option<u64>) -> i64 {
    match (ceiling, rss) {
        (0, _) | (_, None) => UNAVAILABLE,
        (ceiling, Some(rss)) => {
            let headroom = ceiling.saturating_sub(rss);
            // round(headroom * 1000 / ceiling), in u128 so the multiply cannot overflow.
            let permille = (u128::from(headroom) * u128::from(RATIO_SCALE)
                + u128::from(ceiling) / 2)
                / u128::from(ceiling);
            i64::try_from(permille).unwrap_or(i64::from(u32::try_from(RATIO_SCALE).unwrap_or(1000)))
        }
    }
}

/// Computes the RSS-vs-cap RATIO in per-mille (#574): the fraction of the configured RAM `ceiling`
/// the process RSS currently OCCUPIES (`rss / ceiling`), as an integer in `[0, RATIO_SCALE]` (and
/// CLAMPED at `RATIO_SCALE` once RSS is at or over the ceiling, so an over-ceiling process reads a
/// full `1000` rather than wrapping), or [`UNAVAILABLE`] (`-1`) when the ceiling is unset or RSS is
/// unreadable. It is the complement of [`ram_headroom_ratio_permille`] (the two sum to `RATIO_SCALE`
/// below the ceiling) and the rss-vs-cap signal the issue asks for: `0` = empty, `1000` = at/over the
/// cap. Computed in `u128` to avoid overflow on the scale multiply.
#[must_use]
pub fn rss_over_cap_ratio_permille(ceiling: u64, rss: Option<u64>) -> i64 {
    match (ceiling, rss) {
        (0, _) | (_, None) => UNAVAILABLE,
        (ceiling, Some(rss)) => {
            let permille = (u128::from(rss) * u128::from(RATIO_SCALE) + u128::from(ceiling) / 2)
                / u128::from(ceiling);
            let clamped = permille.min(u128::from(RATIO_SCALE));
            i64::try_from(clamped).unwrap_or(i64::from(u32::try_from(RATIO_SCALE).unwrap_or(1000)))
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

/// How many full byte IMAGES of the store the in-memory PRODUCTION backend retains at steady state,
/// the multiplier the #445 footprint proof charges per stored byte under `--storage memory`. After
/// #492, production `--storage memory` uses the single-image `EphemeralFile` / `EphemeralFs`
/// (`ironbus-storage`): ONE `live` byte image and NO `durable` clone — an ephemeral store makes no
/// power-loss promise, so it needs no second image — and the directory-level `sync_dir` clone copies
/// only a map of `Arc` pointers (no byte image). Every stored byte therefore exists ONCE in RSS, so
/// the worst-case in-memory store footprint is `1 * max_total_bytes`, not `2 * max_total_bytes`.
///
/// The 2x `live` + `durable` image survives ONLY in the `InMemoryFile` power-loss SIMULATION the
/// conformance suites rely on. That is a TEST backend, never a production boot path, so the
/// refuse-to-boot guard does not charge for it. (Pre-#492 the guard charged 2x here, which now
/// over-refuses a valid 1x config on a RAM-tight edge box — see #520.) The guard stays conservative:
/// it never under-charges the real production backend.
pub const IN_MEMORY_STORE_IMAGES: u64 = 1;

/// The per-window-entry RAM the opt-in dedup registry charges in the refuse-to-boot proof
/// (`docs/RAM_BUDGET.md` term 6, #878). Each remembered id is stored TWICE — once as the `HashMap`
/// index key and once in the `VecDeque` eviction order (`ProducerWindow` in `ironbus_core::dedup` does
/// `index.insert(msg_id.to_vec(), …)` AND `order.push_back((msg_id.to_vec(), …))`, two independent heap
/// copies, no `Arc` sharing). The charge is `2 *`
/// [`MAX_MSG_ID_LEN`](ironbus_core::dedup::MAX_MSG_ID_LEN) (both maximal-id copies, 512 B) plus 192 B of
/// header + capacity slack, which is a true UPPER bound on the real worst case (~658 B for a maximal
/// id): the `HashMap` buckets (key `Vec` 24 + value tuple 16 + control ≈ 41 B/bucket, up to ~2x at
/// hashbrown's <=7/8 load factor ≈ 82 B/entry) PLUS the `VecDeque` slots (32 B each, and because
/// `record` pushes BEFORE `evict_overflow` a power-of-two `dedup_max_ids` momentarily holds `max_ids+1`
/// and never shrinks the doubled capacity ≈ 64 B/entry). The guard charges this per `dedup_max_ids`
/// slot, so the proof holds regardless of the actual id lengths a producer sends.
pub const DEDUP_ENTRY_BYTES: u64 = 2 * ironbus_core::dedup::MAX_MSG_ID_LEN as u64 + 192;

/// The per-producer fixed key RAM the dedup proof charges (`docs/RAM_BUDGET.md` term 6, #878): the
/// `producer_id` key is stored up to THREE times — the `producers` map key plus the approximate-LRU
/// `BinaryHeap`, which rebuilds at 2x so it can hold two copies of a key — plus the empty
/// `ProducerWindow` struct + collection headers. `3 *`
/// [`MAX_MSG_ID_LEN`](ironbus_core::dedup::MAX_MSG_ID_LEN) (768 B) plus 384 B of headers/slack upper-
/// bounds the real ~1100 B. This is the small `max_producers`-scaled keys term (~few MiB at the shipped
/// default cap, ~tens of KiB at edge-tiny), dominated by the per-entry term above.
pub const DEDUP_PRODUCER_KEY_BYTES: u64 = 3 * ironbus_core::dedup::MAX_MSG_ID_LEN as u64 + 384;

/// The upper bound on ONE prepared transactional half message's RESIDENT bytes, the per-slot charge of
/// the refuse-to-boot guard's txn term (`docs/RAM_BUDGET.md` term 7, #909). A prepared half message
/// (`ironbus_storage::txn::HalfMessage`) buffers the original record VERBATIM — its `key` + `headers` +
/// `payload` (plus the small `txn_id` + `stream` + struct/`HashMap`-entry overhead) — and the whole
/// original record is bounded by the protocol frame cap, so one buffered half message is at most
/// [`MAX_FRAME_LEN`](ironbus_proto::frame::MAX_FRAME_LEN) resident. This mirrors term 1, which likewise
/// bounds one in-flight payload at a maximal frame; the `MAX_FRAME_LEN` headroom over a 16 MiB record
/// body (its `+64 KiB`) absorbs the `txn_id` / `stream` / struct overhead, so the constant is a true
/// UPPER bound. The guard charges it per `max_prepared` slot, so the proof holds whatever sizes a producer
/// prepares.
// `u64::from` is not yet const-callable, so a widening `as` cast is the only option in a `const`; it is
// lossless (u32 -> u64) so the `cast_lossless` pedantic lint is a false positive here.
#[allow(clippy::cast_lossless)]
pub const PREPARED_HALF_MESSAGE_BYTES: u64 = ironbus_proto::frame::MAX_FRAME_LEN as u64;

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
    /// the process, up to the byte cap, and is charged at [`IN_MEMORY_STORE_IMAGES`] (a single
    /// `live` image after #492; the production `EphemeralFile` backend keeps no durable clone). The
    /// caller passes the resolved
    /// `max_total_bytes` here; memory mode refuses an unlimited (`0`) cap upstream, so a `0` always
    /// means "the store is not in RAM", never "unbounded RAM store".
    pub in_memory_store_bytes: u64,
    /// `--dedup-max-producers`: the cap on concurrently-tracked opt-in dedup windows (#33). With
    /// `producer_id` wire-supplied and attacker-chosen, the window COUNT is bounded only by this cap,
    /// not the connection count, so the dedup term (6) must charge it (#878).
    pub dedup_max_producers: u64,
    /// `--dedup-max-ids`: the per-producer dedup window depth (the count of remembered `msg_id`s).
    /// Bounds the per-window RAM at `dedup_max_ids` * [`DEDUP_ENTRY_BYTES`].
    pub dedup_max_ids: u64,
    /// `--max-prepared`: the cap on concurrently-PREPARED transactional half messages (#909). Each
    /// prepared half message buffers a full producer-controlled record VERBATIM in RAM, and the
    /// `txn_id` is wire-supplied and attacker-chosen, so a `TxnPrepare` flood can pin up to this many
    /// maximal records — bounded ONLY by this cap, not the connection count. The guard MUST charge it
    /// (term 7), exactly as it charges the dedup cap (#878) and `consumer_credit`, which likewise cost
    /// nothing until used. `0` is floored to 1 by the engine, so a `0` here charges one slot.
    pub max_prepared: u64,
    /// `--max-prepared-bytes`: the OPTIONAL exact resident-byte budget for the prepared half messages
    /// (#909 follow-up, #958). `0` = OFF (only the count cap `max_prepared` binds, so term 7 charges the
    /// worst case `max_prepared * PREPARED_HALF_MESSAGE_BYTES`). When SET, the engine's per-prepare byte
    /// accounting refuses any prepare that would push the resident sum past this budget, so it is the
    /// FIRM byte bound on term 7 — exactly as `consumer_credit_bytes` is the firm byte bound on term 1
    /// (a maximal-frame count charge otherwise). Lets an operator tune the prepared-payload RAM ceiling
    /// precisely instead of paying a full maximal frame per slot.
    pub max_prepared_bytes: u64,
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
///
///   The #552 credit AUTO-TUNE does NOT loosen this term and keeps the guard TRUTHFUL: the per-consumer
///   count window auto-tunes UPWARD toward `consumer_credit` (its ceiling), but `consumer_credit` IS
///   the worst-case in-flight count this term already charges, so the auto-tune can never push a
///   connection's in-flight past the value the guard assumes. With the byte budget SET, term 1 is
///   byte-bound (`consumer_credit_bytes`) regardless of how high the count auto-tunes — the count grows
///   strictly UNDER the firm byte cap. With the byte budget OFF, the term charges the full ceiling
///   (`consumer_credit * MAX_FRAME_LEN`), so raising the ceiling to a Kafka-class default makes a
///   no-byte-budget config HONESTLY refuse under a small ceiling rather than silently grow its
///   worst-case RAM. Either way the guard's term remains an upper bound on the true in-flight RAM (it
///   is drift-tested below: `the_worst_case_is_monotonic_in_the_caps` and the byte-budget-off refusal).
/// - **Term 3, per-group cursor + lease state.** `max_groups * max_in_flight * PER_LEASE_BYTES`.
/// - **Term 5, fixed overhead + thread stacks.** [`FIXED_OVERHEAD_BYTES`] plus
///   `max_connections * PER_CONNECTION_STACK_BYTES` (one OS thread per connection).
/// - **Term 6, the opt-in per-producer dedup windows (#878).** `dedup_max_producers` *
///   `dedup_max_ids` * [`DEDUP_ENTRY_BYTES`], plus `dedup_max_producers` * [`DEDUP_PRODUCER_KEY_BYTES`]
///   of keys. `producer_id` is wire-supplied and attacker-chosen, so the window
///   COUNT is bounded only by `dedup_max_producers`, NOT the connection count — a publishing client
///   spraying distinct `producer_id`+`msg_id` grows this without a per-connection limit. It costs
///   nothing until a producer opts in, but the guard's proof is "the CAPS cannot exceed the ceiling",
///   so the configured caps are charged exactly as `consumer_credit` is (which also costs nothing
///   until a consumer connects). At the shipped defaults (`4096 * 100_000 * ~704 ~= 269 GiB`) this
///   refuses any small ceiling, so an edge profile MUST lower `--dedup-max-ids`/`--dedup-max-producers`
///   (the `edge-tiny` preset does).
/// - **Term 7, the prepared transactional half messages (#909).** `max_prepared` *
///   [`PREPARED_HALF_MESSAGE_BYTES`]. The txn 2PC store buffers the FULL payload of every
///   prepared-but-unresolved half message in RAM (`ironbus_storage::txn`'s `prepared_payloads`), keyed
///   by the wire-supplied, attacker-chosen `txn_id`, so a `TxnPrepare` flood can pin up to `max_prepared`
///   maximal records — the SAME un-summed, config-capped, attacker-bounded RAM source as the dedup
///   windows (term 6). It is bounded only by `max_prepared`, NOT the connection count, so the guard
///   charges the cap exactly as it charges the dedup cap. At the shipped default (`65_536 * ~16 MiB` ≈
///   1 TiB) this refuses any small ceiling, so an edge profile MUST lower `--max-prepared` (the
///   `edge-tiny` preset does, to a handful of slots, since each slot is a full maximal frame). The
///   engine HONORS the lowered cap (`Engine::set_txn_max_prepared` retunes the txn table), so the
///   charge is a true bound, not a paper one. With the OPTIONAL exact byte budget set
///   (`--max-prepared-bytes`, #958) the engine's per-prepare byte accounting instead holds the resident
///   sum under that budget, so term 7 charges `max_prepared_bytes` directly — the firm byte bound, the
///   txn sibling of term 1's `consumer_credit_bytes`, letting an operator tune the ceiling precisely
///   rather than paying a full maximal frame per slot.
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
///   [`IN_MEMORY_STORE_IMAGES`] (after #492, a single `live` image — the production `EphemeralFile`
///   backend keeps no durable clone). Disk mode passes `0` here, so the disk
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
    // memory` the byte cap times the SINGLE byte image the production `EphemeralFile` backend holds
    // (#492 — one `live` image, no durable clone). See `IN_MEMORY_STORE_IMAGES`.
    let term4_memory_store = config
        .in_memory_store_bytes
        .saturating_mul(IN_MEMORY_STORE_IMAGES);

    // Term 5: fixed overhead + one OS thread stack per connection.
    let term5 = FIXED_OVERHEAD_BYTES.saturating_add(
        config
            .max_connections
            .saturating_mul(PER_CONNECTION_STACK_BYTES),
    );

    // Term 6, the OPT-IN per-producer dedup windows (`docs/RAM_BUDGET.md` section 6, #878): the worst
    // case is every one of `dedup_max_producers` windows full to `dedup_max_ids` entries of a maximal
    // id, plus the per-producer `producer_id` key. `producer_id` is wire-supplied and attacker-chosen,
    // so the window COUNT is bounded only by the configured cap, not the connection count — the guard
    // MUST charge the cap (this is exactly the `consumer_credit` precedent: charged at its configured
    // cap though it too costs nothing until a consumer connects). Saturating, so an unbounded knob
    // refuses rather than wraps.
    let term6_dedup = config
        .dedup_max_producers
        .saturating_mul(config.dedup_max_ids)
        .saturating_mul(DEDUP_ENTRY_BYTES)
        .saturating_add(
            config
                .dedup_max_producers
                .saturating_mul(DEDUP_PRODUCER_KEY_BYTES),
        );

    // Term 7, the PREPARED transactional half messages (`docs/RAM_BUDGET.md` section 8, #909): the txn
    // 2PC store buffers up to `max_prepared` full half-message records in RAM, keyed by the wire-supplied
    // `txn_id`, so the worst case is every slot holding a maximal record. Bounded only by the configured
    // cap (not the connection count), so the guard charges the cap — the txn sibling of term 6. The
    // engine honors the lowered cap via `Engine::set_txn_max_prepared`, so this is a real bound.
    // Saturating, so an absurd cap refuses rather than wraps. `.max(1)` mirrors the engine's floor
    // (`Engine::set_txn_max_prepared` clamps to >= 1), so a configured `0` still charges the one slot
    // the engine will actually admit — matching the `max_prepared` doc.
    // With the exact byte budget SET (#958), the engine's per-prepare accounting holds the resident sum
    // under `max_prepared_bytes`, so that is the FIRM byte bound and term 7 charges it directly — the
    // txn sibling of term 1's `consumer_credit_bytes`. With it OFF (`0`) only the count cap binds, so the
    // provable worst case is every slot a maximal frame (`max_prepared * PREPARED_HALF_MESSAGE_BYTES`).
    let term7_prepared = if config.max_prepared_bytes == 0 {
        config
            .max_prepared
            .max(1)
            .saturating_mul(PREPARED_HALF_MESSAGE_BYTES)
    } else {
        config.max_prepared_bytes
    };

    term1
        .saturating_add(term3)
        .saturating_add(term4_memory_store)
        .saturating_add(term5)
        .saturating_add(term6_dedup)
        .saturating_add(term7_prepared)
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
            // The edge-tiny preset LOWERS the dedup caps (#878) so term 6 is bounded well under the
            // 64 MiB ceiling: 64 * 256 * ~704 ~= 11 MiB (the shipped 4096 * 100_000 defaults would be
            // ~269 GiB and refuse here).
            dedup_max_producers: 64,
            dedup_max_ids: 256,
            // The edge-tiny preset LOWERS the prepared cap (#909): each prepared half message is a full
            // maximal frame (~16 MiB), so with ~26 MiB already spent on the other terms, only a couple of
            // prepared slots fit under 64 MiB. 2 slots is ~32 MiB — the whole worst case lands just under
            // the ceiling. The shipped default (65_536) would imply ~1 TiB and refuse here.
            max_prepared: 2,
            // The exact byte budget is OFF (#958): edge-tiny fits via the lowered count cap alone.
            max_prepared_bytes: 0,
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
            dedup_max_producers: 64,
            dedup_max_ids: 1024,
            max_prepared: 2,
            max_prepared_bytes: 0,
        };
        assert!(matches!(
            fits_under_ram_ceiling(&cfg),
            RamCeilingVerdict::Exceeds { .. }
        ));
    }

    #[test]
    fn the_count_term_charges_the_full_autotune_ceiling_when_the_byte_budget_is_off() {
        // #552 GUARD-TRUTHFULNESS DRIFT TEST. The per-consumer count window auto-tunes UPWARD toward
        // `consumer_credit` (its ceiling), so with the byte budget OFF the worst-case in-flight count IS
        // that ceiling — the guard MUST charge `consumer_credit * MAX_FRAME_LEN` per connection, not the
        // old fixed 64. This pins term 1 to the auto-tune ceiling so a future change that grows the
        // ceiling without growing the guard's charge (a silent RAM-bound regression) FAILS here.
        let max_record = u64::from(ironbus_proto::frame::MAX_FRAME_LEN);
        let ceiling = u64::from(ironbus_core::backpressure::DEFAULT_CREDIT_CEILING);
        let cfg = RamFootprintConfig {
            ram_ceiling_bytes: 0, // not testing the verdict, only the worst-case term
            max_connections: 4,
            consumer_credit: ceiling,
            consumer_credit_bytes: 0, // byte budget OFF -> the COUNT ceiling binds term 1
            max_groups: 0,
            max_in_flight: 0,
            in_memory_store_bytes: 0,
            dedup_max_producers: 0, // dedup off: this test isolates the term-1 count charge
            dedup_max_ids: 0,
            max_prepared: 0, // prepared cap off (floored to 1 elsewhere): isolate the term-1 charge
            max_prepared_bytes: 0, // byte budget OFF: isolate the term-1 charge
        };
        let worst = worst_case_buffer_bytes(&cfg);
        // Term 1 alone is `max_connections * consumer_credit * MAX_FRAME_LEN`; the whole worst case is
        // at least that (the other terms are non-negative). The lower bound is a HARD product of the
        // ceiling, so it follows the constant rather than being computed from the function under test.
        let term1 = 4u64.saturating_mul(ceiling).saturating_mul(max_record);
        assert!(
            worst >= term1,
            "the count-bound worst case must charge the full auto-tune ceiling \
             ({ceiling} msgs/conn * {max_record}B), got worst={worst} < term1={term1}"
        );
    }

    #[test]
    fn the_byte_budget_binds_term_one_independent_of_the_autotune_ceiling() {
        // #552 FIRM-BYTE-BOUND DRIFT TEST. With the byte budget SET, term 1 is `consumer_credit_bytes`
        // per connection NO MATTER how high the count auto-tunes: two configs that differ ONLY in the
        // count ceiling (low fixed 64 vs the high auto-tune ceiling) but share the same byte budget have
        // the IDENTICAL worst case. This is the guarantee that the count auto-tunes UNDER the firm byte
        // cap and can never blow RAM by growing the count.
        let low_count = RamFootprintConfig {
            ram_ceiling_bytes: 0,
            max_connections: 8,
            consumer_credit: 64,
            consumer_credit_bytes: 8 * 1024 * 1024, // byte budget SET -> the firm bound binds term 1
            max_groups: 16,
            max_in_flight: 256,
            in_memory_store_bytes: 0,
            dedup_max_producers: 64,
            dedup_max_ids: 1024,
            max_prepared: 2,
            max_prepared_bytes: 0,
        };
        let high_count = RamFootprintConfig {
            consumer_credit: u64::from(ironbus_core::backpressure::DEFAULT_CREDIT_CEILING),
            ..low_count
        };
        assert_eq!(
            worst_case_buffer_bytes(&low_count),
            worst_case_buffer_bytes(&high_count),
            "with a byte budget set, the count ceiling must not change the worst case (byte budget is \
             the firm RAM bound; the count auto-tunes UNDER it)"
        );
    }

    #[test]
    fn the_in_memory_store_is_charged_at_one_byte_image() {
        // THE #445 MEMORY-BACKEND FOLD, post-#492: with the store in RAM via the production
        // single-image `EphemeralFile` backend, the worst case grows by EXACTLY the store cap over
        // the same config with a disk store. The expectation is a HARD LITERAL 1, deliberately NOT
        // `IN_MEMORY_STORE_IMAGES`: an expectation computed from the constant is self-referential
        // and would silently follow a drifted constant. The 1 is derived from the production backend
        // itself: `EphemeralFile` retains ONE byte image per file (`State.live`), with NO `durable`
        // clone (an ephemeral store makes no power-loss promise), and the directory-level `sync_dir`
        // clone copies only a map of `Arc` POINTERS, never a byte image. (The 2x `live` + `durable`
        // image lives only in the `InMemoryFile` SIMULATION, which is not a production boot path; see
        // #520.) This test FAILS if the store term is dropped or the constant drifts off 1 in either
        // direction.
        let disk = edge_tiny_footprint();
        let mem = RamFootprintConfig {
            in_memory_store_bytes: 8 * 1024 * 1024,
            ..disk
        };
        assert_eq!(
            worst_case_buffer_bytes(&mem),
            worst_case_buffer_bytes(&disk) + 8 * 1024 * 1024,
            "the in-memory store must be charged at the single live image (exactly 1 image)"
        );
    }

    #[test]
    fn a_memory_store_past_the_ceiling_is_refused_where_the_disk_config_fits() {
        // The issue-#445 headline: edge-tiny knobs FIT under 64 MiB on disk, but the SAME knobs
        // with a 1 GiB in-RAM store provably cannot (1 GiB of store image alone, post-#492), so the
        // verdict flips from Fits to Exceeds purely on the store fold.
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
                // A hard literal 1, not the constant, so a drifted multiplier cannot satisfy a
                // bound computed from itself.
                worst_case_bytes >= 1024 * 1024 * 1024,
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
        // #878: a dedup cap bump must STRICTLY grow the worst case — this PINS that term 6 is actually
        // summed. A `>= baseline` check would pass even if term 6 were dropped (the mutant would equal
        // the baseline), so the dedup mutants assert strict `>`. `base` has both dedup caps non-zero, so
        // each bump's delta (max_producers * ENTRY, or max_ids * ENTRY + KEY) is strictly positive.
        assert!(
            worst_case_buffer_bytes(&RamFootprintConfig {
                dedup_max_producers: base.dedup_max_producers + 1,
                ..base
            }) > baseline,
            "a dedup_max_producers bump must STRICTLY grow the worst case (term 6 is charged)"
        );
        assert!(
            worst_case_buffer_bytes(&RamFootprintConfig {
                dedup_max_ids: base.dedup_max_ids + 1,
                ..base
            }) > baseline,
            "a dedup_max_ids bump must STRICTLY grow the worst case (term 6 is charged)"
        );
        // #909: a prepared-cap bump must STRICTLY grow the worst case — this PINS that term 7 is summed.
        // A `>= baseline` check would pass even if term 7 were dropped (the mutant would equal the
        // baseline), so this asserts strict `>`. The delta is exactly one `PREPARED_HALF_MESSAGE_BYTES`.
        assert!(
            worst_case_buffer_bytes(&RamFootprintConfig {
                max_prepared: base.max_prepared + 1,
                ..base
            }) > baseline,
            "a max_prepared bump must STRICTLY grow the worst case (term 7 is charged)"
        );
    }

    #[test]
    fn the_prepared_cap_is_charged_at_one_maximal_frame_per_slot() {
        // #909 EXACT-CHARGE DRIFT TEST. Term 7 charges EXACTLY one maximal frame per prepared slot, so
        // bumping `max_prepared` by N grows the worst case by N * PREPARED_HALF_MESSAGE_BYTES. The delta
        // is asserted against a HARD product of the frame constant (not the function under test), so a
        // dropped or drifted term-7 multiplier fails here.
        let base = edge_tiny_footprint();
        let bumped = RamFootprintConfig {
            max_prepared: base.max_prepared + 3,
            ..base
        };
        assert_eq!(
            worst_case_buffer_bytes(&bumped),
            worst_case_buffer_bytes(&base) + 3 * PREPARED_HALF_MESSAGE_BYTES,
            "each prepared slot must be charged exactly one maximal frame (term 7)"
        );
        // The per-slot charge is a full protocol frame, not a token estimate: a half message buffers the
        // whole record verbatim.
        assert_eq!(
            PREPARED_HALF_MESSAGE_BYTES,
            u64::from(ironbus_proto::frame::MAX_FRAME_LEN)
        );
    }

    #[test]
    fn the_shipped_default_prepared_cap_is_refused_under_a_tiny_ceiling() {
        // #909: the shipped-default prepared cap (65_536 half messages) implies ~1 TiB of buffered
        // half-message payloads in the worst case, which CANNOT fit a 64 MiB edge ceiling. Pre-#909 the
        // guard did not charge the prepared payloads, so an edge-tiny box booted under 64 MiB yet a
        // `TxnPrepare` flood of distinct txn_ids could pin up to 65_536 maximal records in RAM and OOM it
        // — the same defect class as the #878 dedup gap. The guard now charges term 7 and PROVABLY
        // refuses unless `--max-prepared` is lowered.
        let cfg = RamFootprintConfig {
            max_prepared: u64::try_from(ironbus_core::txn::DEFAULT_MAX_PREPARED).unwrap(),
            ..edge_tiny_footprint()
        };
        match fits_under_ram_ceiling(&cfg) {
            RamCeilingVerdict::Exceeds {
                worst_case_bytes, ..
            } => assert!(
                // A hard literal floor, not a self-referential bound: 65_536 * 16 MiB is ~1 TiB, far over
                // the 64 MiB ceiling.
                worst_case_bytes >= 512 * 1024 * 1024 * 1024,
                "the default prepared cap implies ~1 TiB, got {worst_case_bytes}"
            ),
            other => panic!(
                "the shipped default prepared cap under a 64 MiB ceiling must be refused, got {other:?}"
            ),
        }
    }

    #[test]
    fn the_edge_tiny_prepared_cap_fits_but_a_blown_override_is_refused() {
        // #909 headline: the edge-tiny prepared cap (a handful of slots) FITS under 64 MiB, but blowing
        // `--max-prepared` back up (even to a modest 8 slots ≈ 128 MiB of half messages) provably cannot,
        // so the verdict flips from Fits to Exceeds purely on term 7.
        let fits = edge_tiny_footprint();
        assert!(matches!(
            fits_under_ram_ceiling(&fits),
            RamCeilingVerdict::Fits { .. }
        ));
        let blown = RamFootprintConfig {
            max_prepared: 8,
            ..fits
        };
        match fits_under_ram_ceiling(&blown) {
            RamCeilingVerdict::Exceeds {
                worst_case_bytes, ..
            } => assert!(
                worst_case_bytes >= 8 * u64::from(ironbus_proto::frame::MAX_FRAME_LEN),
                "8 prepared slots is ~128 MiB of half messages, got {worst_case_bytes}"
            ),
            other => panic!(
                "a blown --max-prepared under a 64 MiB ceiling must be refused, got {other:?}"
            ),
        }
    }

    #[test]
    fn the_exact_byte_budget_binds_term_seven_independent_of_the_count_cap() {
        // #958 FIRM-BYTE-BOUND DRIFT TEST (the txn sibling of the term-1 `consumer_credit_bytes` test
        // above). With the exact byte budget SET, term 7 is `max_prepared_bytes` NO MATTER how high the
        // count cap is: two configs that differ ONLY in `max_prepared` but share the byte budget have the
        // IDENTICAL worst case, because the engine's per-prepare accounting holds the resident sum under
        // the byte budget. This pins the byte-budget branch so a change that reverts term 7 to the
        // count charge (a silent ceiling loosening) FAILS here.
        let low_count = RamFootprintConfig {
            max_prepared_bytes: 8 * 1024 * 1024,
            ..edge_tiny_footprint()
        };
        let high_count = RamFootprintConfig {
            max_prepared: u64::try_from(ironbus_core::txn::DEFAULT_MAX_PREPARED).unwrap(),
            ..low_count
        };
        assert_eq!(
            worst_case_buffer_bytes(&low_count),
            worst_case_buffer_bytes(&high_count),
            "with a byte budget set, the count cap must not change the worst case (the byte budget is \
             the firm term-7 RAM bound)"
        );
        // And the byte budget is ACTUALLY charged: with it set, term 7 is exactly the budget, strictly
        // smaller than the count charge the same slots would otherwise cost (2 * a maximal frame).
        let count_charged = RamFootprintConfig {
            max_prepared_bytes: 0,
            ..low_count
        };
        assert!(
            worst_case_buffer_bytes(&low_count) < worst_case_buffer_bytes(&count_charged),
            "the exact byte budget (8 MiB) must charge less than 2 maximal frames of count charge"
        );
    }

    #[test]
    fn an_absurd_prepared_cap_saturates_rather_than_overflows() {
        // Belt and braces (mirrors the store-cap saturation test): a u64::MAX prepared cap times the
        // per-slot frame charge saturates to u64::MAX (the config is then refused under any real
        // ceiling), never wraps to a small, spuriously-fitting worst case.
        let cfg = RamFootprintConfig {
            max_prepared: u64::MAX,
            ..edge_tiny_footprint()
        };
        assert_eq!(worst_case_buffer_bytes(&cfg), u64::MAX);
    }

    #[test]
    fn the_shipped_default_dedup_caps_are_refused_under_a_tiny_ceiling() {
        // #878: the shipped-default dedup caps (4096 producers * 100_000 ids) imply ~269 GiB of dedup
        // windows in the worst case, which CANNOT fit a 64 MiB edge ceiling. Pre-#878 the guard did
        // not charge dedup, so an edge-tiny box booted under 64 MiB yet a publishing client spraying
        // distinct producer_id+msg_id could grow dedup RAM past the ceiling and OOM it. The guard now
        // charges term 6 and PROVABLY refuses unless the dedup caps are lowered.
        let cfg = RamFootprintConfig {
            dedup_max_producers: 4096,
            dedup_max_ids: 100_000,
            ..edge_tiny_footprint()
        };
        match fits_under_ram_ceiling(&cfg) {
            RamCeilingVerdict::Exceeds {
                worst_case_bytes, ..
            } => assert!(
                // A hard literal floor, not a self-referential bound: 4096 * 100_000 * 256 (just the
                // msg_id bytes) is already ~100 GiB, far over the 64 MiB ceiling.
                worst_case_bytes >= 100 * 1024 * 1024 * 1024,
                "the default dedup caps imply ~269 GiB, got {worst_case_bytes}"
            ),
            other => panic!(
                "the shipped default dedup caps under a 64 MiB ceiling must be refused, got {other:?}"
            ),
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

    #[test]
    fn the_headroom_ratio_is_per_mille_of_the_ceiling() {
        // 40 of 100 bytes resident -> 60% headroom -> 600 per-mille.
        assert_eq!(ram_headroom_ratio_permille(100, Some(40)), 600);
        // At the ceiling: zero headroom.
        assert_eq!(ram_headroom_ratio_permille(100, Some(100)), 0);
        // Over the ceiling: still zero (saturating sub), never negative-but-the-sentinel.
        assert_eq!(ram_headroom_ratio_permille(100, Some(140)), 0);
        // Empty: full headroom is the scale.
        assert_eq!(
            ram_headroom_ratio_permille(100, Some(0)),
            i64::try_from(RATIO_SCALE).unwrap()
        );
    }

    #[test]
    fn the_rss_over_cap_ratio_is_the_complement_and_clamps() {
        // 40 of 100 resident -> 40% of cap occupied -> 400 per-mille; complements the headroom 600.
        assert_eq!(rss_over_cap_ratio_permille(100, Some(40)), 400);
        assert_eq!(
            rss_over_cap_ratio_permille(100, Some(40)) + ram_headroom_ratio_permille(100, Some(40)),
            i64::try_from(RATIO_SCALE).unwrap(),
            "headroom and rss-over-cap ratios sum to the scale below the ceiling"
        );
        // Over the ceiling clamps at the scale (a full 1000), never wraps.
        assert_eq!(
            rss_over_cap_ratio_permille(100, Some(250)),
            i64::try_from(RATIO_SCALE).unwrap()
        );
    }

    #[test]
    fn both_ratios_are_unavailable_without_a_ceiling_or_an_rss() {
        assert_eq!(ram_headroom_ratio_permille(0, Some(40)), UNAVAILABLE);
        assert_eq!(ram_headroom_ratio_permille(100, None), UNAVAILABLE);
        assert_eq!(rss_over_cap_ratio_permille(0, Some(40)), UNAVAILABLE);
        assert_eq!(rss_over_cap_ratio_permille(100, None), UNAVAILABLE);
    }

    #[test]
    #[cfg(all(test, unix))]
    fn disk_free_reads_a_nonzero_available_on_a_real_fs() {
        // On a unix dev/edge host `df` reads the temp dir's filesystem and reports a non-zero free
        // figure. Anywhere `df` is unavailable or unparseable this degrades to `None`, which the
        // test tolerates rather than failing the build on an exotic environment.
        let dir = std::env::temp_dir();
        if let Some(free) = disk_free_bytes(&dir) {
            assert!(
                free > 0,
                "the temp filesystem should report some free space"
            );
        }
    }
}
