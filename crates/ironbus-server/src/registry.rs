// SPDX-License-Identifier: MIT OR Apache-2.0
//! The bounded, allocation-free metric registry (#97).
//!
//! This makes leaving metrics on permanently affordable on a few-hundred-MB ARM box: the
//! per-message APPEND hot path never allocates and the registry READ side a scrape walks
//! (`for_each_series`, the cumulative-bucket reads, the overflow/uptime reads) never allocates
//! either, the registry has a HARD memory ceiling (a fixed sub-100 core-series cost plus 1024
//! consumer series times a fixed per-series cost, plus the bounded overflow fold-ledger), and
//! per-consumer lag is cheap to update (the append path that runs on every produce is
//! O(1): it bumps one shared head counter; the commit path for an existing consumer is O(1) via a
//! label->slot side-index, falling back to a bounded over-cap fold) and O(number of series) to
//! scrape, all independent of the record count or disk size. Crucially NOTHING here ever walks the
//! durable log or the disk.
//!
//! NOTE the Prometheus TEXT EXPOSITION the `/metrics` endpoint returns is built by
//! [`crate::health`] into a `String` and so DOES allocate that body (an inherent, already-bounded
//! cost of the text format); the allocation-free guarantee here is precisely the per-message
//! append path and the registry read side that feeds the body, not the text serialization itself.
//!
//! The pieces:
//!
//! - [`FixedHistogram`]: a histogram over a FIXED COMPILE-TIME bucket set in seconds
//!   ([`REGISTRY_BUCKET_BOUNDS_NANOS`]), reused for `ironbus_fsync_duration_seconds` and the
//!   append-latency histogram. The buckets are NOT runtime-configurable (a `const`), so the
//!   per-histogram memory is fixed at compile time.
//! - [`ConsumerLagRegistry`]: per-consumer lag (`ironbus_consumer_lag_records{consumer}`)
//!   maintained INCREMENTALLY (the durable head advances on append, the per-consumer commit
//!   floor advances on commit) and never scanned on scrape. A HARD CAP of
//!   [`MAX_CONSUMER_SERIES`] distinct series: past the cap a new consumer is REFUSED its own
//!   series, its lag folds into `{consumer="__overflow__"}`, and `ironbus_consumer_labels_dropped_total`
//!   increments, so an unbounded consumer cardinality can never OOM the very node the metrics
//!   protect, while the total lag stays visible.
//! - [`MetricRegistry`]: the owner of the histograms and the lag registry, plus the
//!   self-monitoring series `ironbus_build_info`, `ironbus_start_time_seconds`, and
//!   `ironbus_uptime_seconds` (the last two derived from the injected clock seam, never a raw
//!   `SystemTime::now`/`Instant::now`).
//!
//! It is IO-free and clock-seam-clean, so it could live in `ironbus-core`; it lives in
//! `ironbus-server` next to the engine and the `/metrics` rendering it feeds, alongside the
//! existing [`crate::metrics`] histogram.

use ironbus_proto::message::AckLevel;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// The cross-thread, bounded CLUSTER-follower divergence telemetry (#873 Phase 1): a fixed set of
/// process-lifetime monotonic counters the data-plane FOLLOWER fetch threads bump and the metrics
/// scrape reads. It is a separate `Arc`-shared atomic block (the SAME shape the connz / health-shed
/// signals use) rather than a field of [`MetricRegistry`], because the follower fetch loops run on
/// their own data-plane threads with no access to the single-threaded engine-owned registry — a
/// lock-free atomic counter is the only sound bridge from those threads to the scrape.
///
/// It is BOUNDED by construction: a FIXED, tiny set of `u64` counters with NO per-partition / per-label
/// cardinality (a divergence event names its partition + offsets in the operator WARN LOG, not in a
/// metric label), so no adversarial or buggy input can grow this block. Nothing here ever touches the
/// durable log, the wire format, or any behavior — it is pure observation.
#[derive(Debug, Default)]
pub struct FollowerDivergenceMetrics {
    /// `ironbus_follower_uncommitted_tail_suspected_total`: the number of times a follower fetch loop
    /// SUSPECTED (detection only — never acted) that it holds an fsynced UNCOMMITTED tail above its own
    /// quorum-committed floor that the incoming leader lineage excludes (the #873 silent post-failover
    /// stitch hazard). Incremented at most ONCE per divergent fetch-link session (the follower loop
    /// latches it), so a wedged follower that empty-no-op loops does not inflate the counter — it stays
    /// a bounded, once-per-episode operator signal, not a per-poll spam.
    uncommitted_tail_suspected: AtomicU64,
}

impl FollowerDivergenceMetrics {
    /// Records one SUSPECTED uncommitted-tail divergence episode (#873 Phase 1). Lock-free; callable
    /// from any data-plane follower thread.
    pub fn record_uncommitted_tail_suspected(&self) {
        self.uncommitted_tail_suspected
            .fetch_add(1, Ordering::Relaxed);
    }

    /// The cumulative count of suspected uncommitted-tail divergence episodes
    /// (`ironbus_follower_uncommitted_tail_suspected_total`).
    #[must_use]
    pub fn uncommitted_tail_suspected_total(&self) -> u64 {
        self.uncommitted_tail_suspected.load(Ordering::Relaxed)
    }
}

/// The frozen registry-histogram bucket upper bounds, in NANOSECONDS, ascending, matching the
/// fixed second-valued set the issue pins: `{0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05,
/// 0.1, 0.2, 0.5, 1, 2, 5}`. An implicit `+Inf` bucket follows. These are a compile-time
/// constant, NOT runtime-configurable: a runtime-tunable bucket set would unbound the
/// per-series memory, so the bucket count (and thus the per-histogram cost) is fixed here.
pub const REGISTRY_BUCKET_BOUNDS_NANOS: [u64; 13] = [
    500_000,       // 0.0005 s (500 us)
    1_000_000,     // 0.001 s (1 ms)
    2_000_000,     // 0.002 s
    5_000_000,     // 0.005 s
    10_000_000,    // 0.01 s
    20_000_000,    // 0.02 s
    50_000_000,    // 0.05 s
    100_000_000,   // 0.1 s
    200_000_000,   // 0.2 s
    500_000_000,   // 0.5 s
    1_000_000_000, // 1 s
    2_000_000_000, // 2 s
    5_000_000_000, // 5 s
];

/// The Prometheus `le` labels (seconds) matching [`REGISTRY_BUCKET_BOUNDS_NANOS`], one per bound.
/// The implicit final `+Inf` bucket is rendered separately.
pub const REGISTRY_BUCKET_LE_SECONDS: [&str; 13] = [
    "0.0005", "0.001", "0.002", "0.005", "0.01", "0.02", "0.05", "0.1", "0.2", "0.5", "1", "2", "5",
];

/// The number of stored bucket slots: one per bound plus the trailing `+Inf` bucket.
pub const REGISTRY_BUCKET_SLOTS: usize = REGISTRY_BUCKET_BOUNDS_NANOS.len() + 1;

/// A histogram over the FIXED [`REGISTRY_BUCKET_BOUNDS_NANOS`] bucket set, observed in
/// nanoseconds. `observe` is allocation-free (it only indexes a fixed array and adds), and the
/// stored size is a compile-time constant, so a registry of these has a fixed memory ceiling.
///
/// The bucket counts are stored NON-cumulatively and made cumulative only at exposition time, so
/// an observation touches exactly one slot.
#[derive(Clone, Copy, Debug)]
pub struct FixedHistogram {
    /// Per-bucket observation counts (length = bounds + 1 for the `+Inf` bucket).
    counts: [u64; REGISTRY_BUCKET_SLOTS],
    /// The running sum of all observed nanoseconds (saturating).
    sum_nanos: u64,
    /// The total number of observations.
    count: u64,
}

impl Default for FixedHistogram {
    fn default() -> FixedHistogram {
        FixedHistogram {
            counts: [0; REGISTRY_BUCKET_SLOTS],
            sum_nanos: 0,
            count: 0,
        }
    }
}

impl FixedHistogram {
    /// Records one observation of `nanos` nanoseconds (the `le` bound is inclusive). Allocation-free:
    /// it finds the bucket by a linear scan of the fixed bounds and bumps one `u64` slot, the running
    /// sum, and the count.
    pub fn observe(&mut self, nanos: u64) {
        let idx = REGISTRY_BUCKET_BOUNDS_NANOS
            .iter()
            .position(|&bound| nanos <= bound)
            .unwrap_or(REGISTRY_BUCKET_BOUNDS_NANOS.len());
        // `idx` is in `0..=REGISTRY_BUCKET_BOUNDS_NANOS.len()`, always a valid `counts` index
        // (length is `+1`), so this never panics; use `get_mut` so a future bounds change cannot
        // introduce an index-panic in a lib path.
        if let Some(slot) = self.counts.get_mut(idx) {
            *slot += 1;
        }
        self.sum_nanos = self.sum_nanos.saturating_add(nanos);
        self.count += 1;
    }

    /// The total number of observations (the histogram `_count`).
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The running sum of observed nanoseconds (the `_sum`, before the seconds conversion).
    #[must_use]
    pub fn sum_nanos(&self) -> u64 {
        self.sum_nanos
    }

    /// The CUMULATIVE bucket counts, one per [`REGISTRY_BUCKET_BOUNDS_NANOS`] bound (each includes
    /// every lower bucket), as a Prometheus histogram requires. The `+Inf` bucket equals
    /// [`FixedHistogram::count`]. Returned by value (a fixed-size array, on the stack), so the
    /// scrape rendering allocates nothing for it.
    #[must_use]
    pub fn cumulative_buckets(&self) -> [u64; REGISTRY_BUCKET_BOUNDS_NANOS.len()] {
        let mut cumulative = [0u64; REGISTRY_BUCKET_BOUNDS_NANOS.len()];
        let mut running = 0u64;
        for (i, slot) in cumulative.iter_mut().enumerate() {
            running = running.saturating_add(self.counts.get(i).copied().unwrap_or(0));
            *slot = running;
        }
        cumulative
    }
}

/// The HARD CAP on the number of distinct consumer lag series the registry will hold (#97). Past
/// this, a new consumer is refused its own series and folds into `{consumer="__overflow__"}`,
/// bounding the registry's consumer-series memory at a fixed `MAX_CONSUMER_SERIES x per-series
/// cost`. An unbounded consumer cardinality would OOM the very node metrics protect, so the cap is
/// mandatory.
pub const MAX_CONSUMER_SERIES: usize = 1024;

/// The capacity of the BOUNDED overflow fold-ledger (#97): the number of DISTINCT over-cap
/// consumers whose commit floor is tracked individually so a re-commit UPDATES that consumer's
/// contribution (subtract its old floor, add the new) instead of accumulating. This is what makes
/// the fold idempotent under the engine's per-ack `set_committed`: an already-folded consumer that
/// acks again does not double-count. It is a fixed, small capacity (so the ledger's memory is part
/// of the registry's hard ceiling, NOT an unbounded per-consumer map). Distinct over-cap consumers
/// past this ledger capacity fall back to the documented coarse saturation behavior (see
/// [`ConsumerLagRegistry`]). Sized to match [`MAX_CONSUMER_SERIES`] so the common case (a finite,
/// even large, set of over-cap consumers) is tracked exactly.
pub const MAX_OVERFLOW_LEDGER: usize = MAX_CONSUMER_SERIES;

/// The synthetic consumer label every over-cap consumer's lag folds into, so the TOTAL lag stays
/// visible even once distinct labels are refused.
pub const OVERFLOW_CONSUMER_LABEL: &str = "__overflow__";

/// The maximum stored length of a consumer label, in bytes. A consumer name is a work-group name,
/// which the engine validates as bounded graphic ASCII; storing it INLINE (no heap `String`) is
/// what keeps the per-series cost fixed and the hot path allocation-free. A name longer than this
/// is truncated for the stored key (its lag still folds into the matching truncated series), so an
/// over-long label can never grow the per-series cost.
pub const MAX_CONSUMER_LABEL_BYTES: usize = 64;

/// One consumer's lag series: the inline (heap-free) label plus the two incrementally-maintained
/// counts whose difference is the lag. Fixed size, so an array of these has a fixed memory cost.
#[derive(Clone, Copy)]
struct ConsumerSeries {
    /// The consumer label, stored inline as a fixed byte buffer (no heap allocation).
    label: [u8; MAX_CONSUMER_LABEL_BYTES],
    /// The used length of `label` (`0..=MAX_CONSUMER_LABEL_BYTES`). A FIXED-WIDTH `u16` (not a
    /// platform-sized `usize`), so the per-series size is identical on 32-bit and 64-bit targets and
    /// the memory-ceiling test is portable. `MAX_CONSUMER_LABEL_BYTES` (64) fits a `u16` easily.
    label_len: u16,
    /// Whether this slot is occupied.
    used: bool,
    /// The records this consumer has COMMITTED (its commit floor as a record count). Lag is the
    /// shared durable head minus this, both maintained incrementally, so the lag is never computed
    /// by scanning the log or the disk.
    committed: u64,
}

impl ConsumerSeries {
    const EMPTY: ConsumerSeries = ConsumerSeries {
        label: [0u8; MAX_CONSUMER_LABEL_BYTES],
        label_len: 0,
        used: false,
        committed: 0,
    };

    /// Whether this occupied slot's label equals `name` (compared on the stored, possibly truncated,
    /// bytes). Comparing the truncated key is deliberate: two names that share the first
    /// [`MAX_CONSUMER_LABEL_BYTES`] bytes fold into one series, which is acceptable for a label that
    /// long and keeps the key allocation-free.
    fn label_matches(&self, name: &[u8]) -> bool {
        let stored = self.label.get(..usize::from(self.label_len)).unwrap_or(&[]);
        let key = stored_key(name);
        stored == key
    }

    /// The rendered label as a `&str`. The stored bytes are a prefix of a validated graphic-ASCII
    /// work-group name, so they are valid UTF-8; a defensive `from_utf8` failure renders as empty
    /// rather than panicking in a lib path.
    fn label_str(&self) -> &str {
        let stored = self.label.get(..usize::from(self.label_len)).unwrap_or(&[]);
        core::str::from_utf8(stored).unwrap_or("")
    }
}

/// The stored (possibly truncated) key bytes for `name`: at most [`MAX_CONSUMER_LABEL_BYTES`]
/// bytes, so an over-long label can never grow the inline buffer.
fn stored_key(name: &[u8]) -> &[u8] {
    name.get(..MAX_CONSUMER_LABEL_BYTES.min(name.len()))
        .unwrap_or(name)
}

/// Copies `name`'s (possibly truncated) stored key into `slot`'s inline label buffer and marks it
/// used. Allocation-free (a fixed-size `copy_from_slice` into the preallocated buffer). Shared by
/// the distinct-series claim and the overflow-ledger insert so the inline-label store is identical
/// in both, keeping the per-slot cost fixed and the hot path heap-free.
fn store_label(slot: &mut ConsumerSeries, name: &[u8]) {
    let key = stored_key(name);
    let n = key.len().min(MAX_CONSUMER_LABEL_BYTES);
    if let Some(dst) = slot.label.get_mut(..n) {
        if let Some(src) = key.get(..n) {
            dst.copy_from_slice(src);
        }
    }
    // `n <= MAX_CONSUMER_LABEL_BYTES` (64), so it always fits a `u16`; the `unwrap_or` is a
    // never-taken fallback that keeps the conversion panic-free in a lib path.
    slot.label_len = u16::try_from(n).unwrap_or(u16::MAX);
    slot.used = true;
}

/// The per-consumer lag registry (#97): the durable head as a record count, a fixed array of up to
/// [`MAX_CONSUMER_SERIES`] consumer series, the bounded `__overflow__` fold ledger for refused
/// labels, and the dropped-labels counter. Lag for one consumer is `head - committed`, both
/// maintained incrementally; a scrape only walks the bounded series array, never the log.
///
/// # The overflow fold is IDEMPOTENT over a bounded ledger
///
/// The engine calls `set_committed` on EVERY ack (and on dead-letter commit, truncation reset, and
/// once per group at open), so the same consumer commits many times over its life. For an over-cap
/// consumer (one refused a distinct series), a naive fold that just summed every commit into a
/// running total would double-count on each re-commit: `overflow_consumers` would stop equalling
/// the number of DISTINCT folded consumers (so the overflow lag would RISE as a folded consumer made
/// progress), and `labels_dropped` would grow per ack instead of per distinct refused label.
///
/// To make the fold idempotent WITHOUT an unbounded per-consumer map, an over-cap consumer's last
/// committed floor is tracked in a BOUNDED ledger of [`MAX_OVERFLOW_LEDGER`] inline entries: a
/// re-commit looks the consumer up and UPDATES its contribution in place (subtract its old floor,
/// add the new), so `overflow_committed` always equals the sum of the DISTINCT folded consumers'
/// current floors, `overflow_consumers` and `labels_dropped` bump only on the FIRST insert of a
/// distinct label, and the overflow lag never grows as a folded consumer advances. The ledger is a
/// fixed, small slice of the registry's hard ceiling, NOT an unbounded map.
///
/// If even that bounded ledger saturates (more DISTINCT over-cap consumers than [`MAX_OVERFLOW_LEDGER`]
/// over the registry's whole life), a brand-new distinct over-cap consumer that cannot be tracked
/// individually falls back to a documented COARSE behavior: it bumps `labels_dropped` once and the
/// monotonic `overflow_saturated` counter, but its lag is NOT folded into `overflow_lag` (it cannot
/// be tracked idempotently without a slot, and folding it un-trackably would let the lag grow-wrong
/// on its re-commits). The reported overflow lag is then a documented LOWER BOUND on the true folded
/// lag, still monotonic and never grows-wrong; `overflow_saturated > 0` is the signal that the
/// reported overflow lag is a floor rather than exact.
pub struct ConsumerLagRegistry {
    /// The durable log head as a RECORD COUNT (the number of records produced). Advances by one on
    /// every append; every consumer's lag is this minus its commit floor.
    head: u64,
    /// The fixed-capacity consumer series array, as a boxed slice of exactly [`MAX_CONSUMER_SERIES`]
    /// slots, allocated ONCE at construction on the heap (so the 1024-slot array never lives on a
    /// stack frame nor inline in the engine struct). A new consumer takes the first free slot; past
    /// capacity it folds into the overflow ledger.
    series: Box<[ConsumerSeries]>,
    /// The number of occupied slots in `series`.
    len: usize,
    /// A side-index from a consumer's stored (possibly truncated) label key to its slot in `series`,
    /// so `set_committed` resolves an existing consumer's slot in O(1) instead of a linear
    /// label-compare over up to [`MAX_CONSUMER_SERIES`] slots on EVERY actor-path ack (#486). The key
    /// is the SAME truncated key the slot stores (see [`stored_key`]), so a lookup and the slot's
    /// inline label always agree. It holds one entry per occupied distinct series, never more than
    /// [`MAX_CONSUMER_SERIES`], and is preallocated at that cap in [`ConsumerLagRegistry::default`] so
    /// a slot claim never resizes it on the commit path. It is kept consistent with the slot array at
    /// the single place a slot is claimed: an insert maps the new key to its slot. (There is no slot
    /// eviction or recycle today — `len`/`used` only ever advance — but if a slot is ever recycled to
    /// a new label, this map MUST be updated in the same place, or a stale key would resolve to the
    /// wrong slot.) It is NOT part of the fixed `size_of` memory ceiling the way the boxed arrays are,
    /// but its heap is bounded by the same [`MAX_CONSUMER_SERIES`] cap (a fixed-cardinality index), so
    /// it cannot grow without bound.
    slot_index: HashMap<Box<[u8]>, usize>,
    /// The BOUNDED overflow fold-ledger: up to [`MAX_OVERFLOW_LEDGER`] inline entries, one per
    /// DISTINCT over-cap consumer, each storing that consumer's last committed floor so a re-commit
    /// updates its contribution in place (subtract old, add new) instead of accumulating. Allocated
    /// ONCE at construction (a boxed slice, like `series`), so the ledger is part of the fixed memory
    /// ceiling and never an unbounded map.
    overflow_ledger: Box<[ConsumerSeries]>,
    /// The number of occupied slots in `overflow_ledger` (the count of DISTINCT folded consumers
    /// tracked individually). `overflow_lag = head x overflow_ledger_len - overflow_committed`.
    overflow_ledger_len: usize,
    /// The summed commit floor of every DISTINCT consumer currently tracked in `overflow_ledger`.
    /// Maintained by subtract-old/add-new on each re-commit, so it stays exact (never accumulates)
    /// as folded consumers make progress. See [`ConsumerLagRegistry::overflow_lag`].
    overflow_committed: u64,
    /// `overflow_saturated`: the number of DISTINCT over-cap consumers that could not be tracked
    /// individually because the bounded ledger was full. Monotonic. When non-zero, `overflow_lag` is
    /// a documented LOWER BOUND (these consumers' lag is not folded in, to keep the fold idempotent
    /// without an unbounded map). In the common case (finite over-cap cardinality under the ledger
    /// capacity) this stays zero and the overflow lag is exact.
    overflow_saturated: u64,
    /// `ironbus_consumer_labels_dropped_total`: the number of DISTINCT consumer labels refused a
    /// series because the cap was reached. Bumps only on the FIRST fold of a distinct label (a
    /// ledger insert OR a saturation), NEVER per ack, so a folded consumer re-committing does not
    /// inflate it. A monotonic counter (an operator's cardinality-pressure signal).
    labels_dropped: u64,
}

impl Default for ConsumerLagRegistry {
    fn default() -> ConsumerLagRegistry {
        ConsumerLagRegistry {
            head: 0,
            // Allocated directly on the heap as a boxed slice (no transient stack array), ONCE at
            // construction (off the hot path). `vec!` fills exactly MAX_CONSUMER_SERIES Copy slots.
            series: vec![ConsumerSeries::EMPTY; MAX_CONSUMER_SERIES].into_boxed_slice(),
            len: 0,
            // The label->slot side-index (#486), preallocated at the same cap as `series` ONCE at
            // construction (off the hot path) so a slot claim on the commit path never resizes it. It
            // holds at most one entry per distinct series, so its heap stays bounded by the cap.
            slot_index: HashMap::with_capacity(MAX_CONSUMER_SERIES),
            // The bounded overflow fold-ledger, allocated ONCE at construction the same way, so the
            // fold is idempotent over a fixed-capacity structure (no unbounded per-consumer map).
            overflow_ledger: vec![ConsumerSeries::EMPTY; MAX_OVERFLOW_LEDGER].into_boxed_slice(),
            overflow_ledger_len: 0,
            overflow_committed: 0,
            overflow_saturated: 0,
            labels_dropped: 0,
        }
    }
}

impl ConsumerLagRegistry {
    /// Records that `count` records were appended (the durable head advanced). O(1) and
    /// allocation-free: it only advances the shared head, so every consumer's lag (head minus its
    /// commit floor) rises without touching any per-series slot. This is why an append stays O(1)
    /// regardless of the number of consumer series.
    pub fn record_appended(&mut self, count: u64) {
        self.head = self.head.saturating_add(count);
    }

    /// Sets consumer `name`'s committed record floor to `committed` (the commit path). For an existing
    /// consumer this is O(1): the label->slot side-index resolves its slot directly (#486), instead of
    /// the old linear label-compare over up to [`MAX_CONSUMER_SERIES`] slots on every actor-path ack.
    /// A brand-new consumer claims a free slot and records its key->slot mapping, or (at the cap) folds
    /// into the overflow series, incrementing the dropped-labels counter. Never walks the log. The
    /// existing-consumer re-commit path is allocation-free (a borrowed-key lookup); the once-per-new-
    /// consumer claim records the mapping off the steady-state path. The stored floor is monotonic
    /// non-decreasing (a commit never moves a cursor backwards), so a stale lower value is ignored.
    pub fn set_committed(&mut self, name: &[u8], committed: u64) {
        // An existing series: advance its floor (monotonic). Resolved in O(1) via the label->slot
        // side-index (#486) instead of a linear label-compare over up to MAX_CONSUMER_SERIES slots on
        // every actor-path ack; the index key is the SAME truncated `stored_key` the slot holds, so a
        // hit always points at the matching occupied slot. Never the log. This lookup borrows the key
        // (no `Box`/`Vec` is built), so the steady-state re-commit path stays allocation-free.
        let key = stored_key(name);
        if let Some(&idx) = self.slot_index.get(key) {
            if let Some(slot) = self.series.get_mut(idx) {
                slot.committed = slot.committed.max(committed);
                return;
            }
        }
        // A new consumer with a free slot: claim it and record its key->slot mapping so the next
        // commit resolves it in O(1). The insert (which may allocate the boxed key) happens ONCE per
        // distinct consumer, off the steady-state ack path; the map is preallocated at the cap, so the
        // insert never resizes it.
        if self.len < MAX_CONSUMER_SERIES {
            if let Some(slot) = self.series.get_mut(self.len) {
                store_label(slot, name);
                slot.committed = committed;
                self.slot_index.insert(Box::from(key), self.len);
                self.len += 1;
                return;
            }
        }
        // The cap is reached: refuse a new distinct series and fold this consumer into the bounded
        // overflow ledger. This MUST be idempotent: the engine calls `set_committed` on every ack,
        // so the same over-cap consumer arrives here repeatedly; a naive `+= committed` would
        // double-count (the BLOCKER this fix closes). Instead, track each distinct over-cap
        // consumer's floor in the ledger and UPDATE in place on a re-commit.
        self.fold_into_overflow(name, committed);
    }

    /// Folds an over-cap consumer's commit floor into the bounded overflow ledger IDEMPOTENTLY
    /// (#97). Allocation-free, and a bounded in-memory scan of at most [`MAX_OVERFLOW_LEDGER`] inline
    /// entries:
    ///
    /// - An already-tracked consumer: advance its stored floor monotonically (`.max`) and apply the
    ///   delta to `overflow_committed` (subtract its old floor, add its new), so a re-commit UPDATES
    ///   its contribution instead of accumulating. `labels_dropped`/`overflow_ledger_len` do NOT
    ///   change (it was already counted on its first fold).
    /// - A brand-new distinct over-cap consumer with ledger room: claim a ledger slot, store its
    ///   floor, add it to `overflow_committed`, and bump `overflow_ledger_len` and `labels_dropped`
    ///   ONCE.
    /// - A brand-new distinct over-cap consumer with NO ledger room (saturation): bump
    ///   `labels_dropped` and `overflow_saturated` once; its lag is NOT folded into
    ///   `overflow_committed`/`overflow_lag` (it cannot be tracked idempotently without a slot, and
    ///   an un-trackable fold would grow-wrong on its re-commits). The overflow lag is then a
    ///   documented LOWER BOUND. A saturating consumer that re-commits cannot be distinguished from
    ///   a new one without a slot, so it may bump these counters again; this is the explicit,
    ///   monotonic, never-grows-wrong coarse fallback for the (rare) past-ledger-capacity case, and
    ///   `overflow_saturated > 0` flags it.
    fn fold_into_overflow(&mut self, name: &[u8], committed: u64) {
        // An already-tracked over-cap consumer: update its contribution in place. Monotonic floor
        // (a commit never moves a cursor backwards), so a stale lower value is ignored.
        for slot in self
            .overflow_ledger
            .iter_mut()
            .take(self.overflow_ledger_len)
        {
            if slot.used && slot.label_matches(name) {
                let new_floor = slot.committed.max(committed);
                // Apply only the forward delta to the running sum, so `overflow_committed` stays the
                // exact sum of the tracked floors (never an accumulation across re-commits).
                let delta = new_floor.saturating_sub(slot.committed);
                self.overflow_committed = self.overflow_committed.saturating_add(delta);
                slot.committed = new_floor;
                return;
            }
        }
        // A brand-new distinct over-cap consumer with ledger room: claim a slot and count it ONCE.
        if self.overflow_ledger_len < MAX_OVERFLOW_LEDGER {
            if let Some(slot) = self.overflow_ledger.get_mut(self.overflow_ledger_len) {
                store_label(slot, name);
                slot.committed = committed;
                self.overflow_ledger_len += 1;
                self.overflow_committed = self.overflow_committed.saturating_add(committed);
                self.labels_dropped = self.labels_dropped.saturating_add(1);
                return;
            }
        }
        // The ledger is saturated: a distinct over-cap consumer beyond the ledger capacity. Count it
        // (a distinct refused label) and flag saturation, but do NOT fold its lag, keeping the
        // overflow lag a monotonic, never-grows-wrong LOWER BOUND.
        self.overflow_saturated = self.overflow_saturated.saturating_add(1);
        self.labels_dropped = self.labels_dropped.saturating_add(1);
    }

    /// The durable head as a record count (the value every consumer's lag is measured against).
    #[must_use]
    pub fn head(&self) -> u64 {
        self.head
    }

    /// `ironbus_consumer_labels_dropped_total`: the count of DISTINCT consumer labels refused a
    /// series at the cap. Counts each distinct over-cap label ONCE (on its first fold), never per
    /// ack, so a folded consumer re-committing does not inflate it.
    #[must_use]
    pub fn labels_dropped(&self) -> u64 {
        self.labels_dropped
    }

    /// The lag of the overflow (folded) series: the sum over every DISTINCT folded consumer of
    /// `head - committed_i`, which equals `head x overflow_ledger_len - overflow_committed`
    /// (saturating, so a stale floor above the head never underflows). Because `overflow_committed`
    /// is the EXACT sum of the tracked consumers' current floors (maintained by subtract-old/add-new
    /// on every re-commit, never accumulated), this does NOT rise as a folded consumer makes
    /// progress: a folded consumer committing a higher offset lowers its own `head - committed_i`
    /// term, exactly as a distinct series would. If the bounded ledger saturated
    /// ([`ConsumerLagRegistry::overflow_saturated`] `> 0`), this is a documented monotonic LOWER
    /// BOUND (the un-tracked, past-capacity consumers' lag is not folded in).
    #[must_use]
    pub fn overflow_lag(&self) -> u64 {
        // `overflow_ledger_len` is at most MAX_OVERFLOW_LEDGER (1024), so it always fits a `u64`; the
        // `unwrap_or` is a never-taken fallback that keeps the conversion panic-free in a lib path.
        let tracked = u64::try_from(self.overflow_ledger_len).unwrap_or(u64::MAX);
        self.head
            .saturating_mul(tracked)
            .saturating_sub(self.overflow_committed)
    }

    /// `overflow_saturated`: the number of DISTINCT over-cap consumers that could not be tracked in
    /// the bounded fold-ledger because it was full. When `> 0`, [`ConsumerLagRegistry::overflow_lag`]
    /// is a documented monotonic LOWER BOUND rather than the exact folded lag. Zero in the common
    /// case (over-cap cardinality within the ledger capacity).
    #[must_use]
    pub fn overflow_saturated(&self) -> u64 {
        self.overflow_saturated
    }

    /// Whether the overflow series is in use (at least one consumer was folded, whether tracked in
    /// the ledger or refused at saturation), so the scrape only emits the `__overflow__` line once a
    /// label has actually been dropped.
    #[must_use]
    pub fn has_overflow(&self) -> bool {
        self.overflow_ledger_len > 0 || self.overflow_saturated > 0
    }

    /// Invokes `f(label, lag)` for each occupied DISTINCT consumer series, lag = `head - committed`
    /// (saturating). O(number of series), allocation-free, and never walks the log: the lag is the
    /// difference of two incrementally-maintained counts. The overflow series is emitted by the
    /// caller via [`ConsumerLagRegistry::overflow_lag`] so the borrow stays simple.
    pub fn for_each_series<F: FnMut(&str, u64)>(&self, mut f: F) {
        for slot in self.series.iter().take(self.len) {
            if slot.used {
                let lag = self.head.saturating_sub(slot.committed);
                f(slot.label_str(), lag);
            }
        }
    }

    /// The number of occupied distinct consumer series (for the memory-ceiling test and operators).
    #[must_use]
    pub fn series_len(&self) -> usize {
        self.len
    }
}

/// One per-label throughput series (#571): the inline (heap-free) label plus the two monotonic
/// counts — records PRODUCED to this stream and records CONSUMED (acked) by this group. Fixed size,
/// so an array of these has a fixed memory cost, exactly like [`ConsumerSeries`].
#[derive(Clone, Copy)]
struct ThroughputSeries {
    /// The stream/group label, stored inline as a fixed byte buffer (no heap allocation).
    label: [u8; MAX_CONSUMER_LABEL_BYTES],
    /// The used length of `label` (a fixed-width `u16` for a portable per-series size).
    label_len: u16,
    /// Whether this slot is occupied.
    used: bool,
    /// Records produced to this stream (monotonic).
    produced: u64,
    /// Records consumed (acked) by this group (monotonic).
    consumed: u64,
}

impl ThroughputSeries {
    const EMPTY: ThroughputSeries = ThroughputSeries {
        label: [0u8; MAX_CONSUMER_LABEL_BYTES],
        label_len: 0,
        used: false,
        produced: 0,
        consumed: 0,
    };

    /// Copies `name`'s (possibly truncated) stored key into the inline label buffer and marks used.
    /// Allocation-free (a fixed-size `copy_from_slice` into the preallocated buffer).
    fn store_label(&mut self, name: &[u8]) {
        let key = stored_key(name);
        let n = key.len().min(MAX_CONSUMER_LABEL_BYTES);
        if let (Some(dst), Some(src)) = (self.label.get_mut(..n), key.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.label_len = u16::try_from(n).unwrap_or(u16::MAX);
        self.used = true;
    }

    /// The rendered label as a `&str` (the stored bytes are a prefix of a validated graphic-ASCII
    /// name, so valid UTF-8; a defensive failure renders empty rather than panicking in a lib path).
    fn label_str(&self) -> &str {
        let stored = self.label.get(..usize::from(self.label_len)).unwrap_or(&[]);
        core::str::from_utf8(stored).unwrap_or("")
    }
}

/// The synthetic label every over-cap throughput series folds into, so the TOTAL produced/consumed
/// stays visible even once distinct stream/group labels are refused at the cap (#571). Distinct from
/// [`OVERFLOW_CONSUMER_LABEL`] only in NAME meaning (it labels a `stream`/`group`, not a `consumer`);
/// reusing the `__overflow__` spelling keeps the over-cap fold convention uniform across the surface.
pub const OVERFLOW_THROUGHPUT_LABEL: &str = "__overflow__";

/// The per-stream / per-group THROUGHPUT registry (#571): records produced per stream and records
/// consumed (acked) per group, as monotonic counters keyed by the stream/group LABEL, with the SAME
/// hard cardinality bound as [`ConsumerLagRegistry`] — up to [`MAX_CONSUMER_SERIES`] distinct labels,
/// then a new label is REFUSED its own series and its counts fold into `{stream|group="__overflow__"}`,
/// so an unbounded stream/group cardinality can never OOM the node the metrics protect while the TOTAL
/// throughput stays visible.
///
/// Unlike the lag registry's FLOOR semantics (where a re-commit must update-in-place to stay
/// idempotent), throughput is a pure MONOTONIC COUNTER: each record adds a delta of one. So the
/// over-cap fold is the trivial idempotent case — an over-cap label's increments simply add into the
/// shared overflow counters; there is no per-overflow-label ledger to keep, because there is no floor
/// to reconcile. `labels_dropped` counts each DISTINCT refused label once (on its first fold), an
/// operator's cardinality-pressure signal, exactly like the lag registry's.
///
/// Allocation-free on the steady-state record path (an existing label resolves O(1) via the
/// label->slot side-index, like the lag registry's #486 index); the once-per-new-label claim records
/// the mapping off the hot path. Never walks the log or the disk.
pub struct ThroughputRegistry {
    /// The fixed-capacity series array (a boxed slice of exactly [`MAX_CONSUMER_SERIES`] slots),
    /// allocated ONCE at construction. A new label takes the first free slot; past the cap it folds.
    series: Box<[ThroughputSeries]>,
    /// The number of occupied slots in `series`.
    len: usize,
    /// A label->slot side-index so a record for an existing label resolves O(1), preallocated at the
    /// cap so a claim never resizes it on the hot path. One entry per occupied primary series, plus
    /// one per distinct over-cap label tracked in the bounded overflow ledger (mapped to its ledger
    /// slot via [`OVERFLOW_INDEX_BASE`](ThroughputRegistry::OVERFLOW_INDEX_BASE)), so a re-record of a
    /// folded label resolves O(1) too.
    slot_index: HashMap<Box<[u8]>, usize>,
    /// The BOUNDED overflow fold-ledger (mirrors [`ConsumerLagRegistry`]'s, #97): up to
    /// [`MAX_OVERFLOW_LEDGER`] inline entries, one per DISTINCT over-cap label, so a re-record of a
    /// folded label adds into ITS slot and `labels_dropped` counts each distinct label ONCE on its
    /// first fold. Allocated once; part of the fixed memory ceiling, NOT an unbounded per-label map.
    overflow_ledger: Box<[ThroughputSeries]>,
    /// The number of occupied slots in `overflow_ledger` (the count of DISTINCT folded labels).
    overflow_ledger_len: usize,
    /// `*_labels_dropped_total`: the number of DISTINCT labels refused a primary series at the cap.
    /// Bumps only on the FIRST fold of a distinct label, NEVER per record, so a folded label recording
    /// again does not inflate it. A monotonic cardinality-pressure signal.
    labels_dropped: u64,
}

impl Default for ThroughputRegistry {
    fn default() -> ThroughputRegistry {
        ThroughputRegistry {
            series: vec![ThroughputSeries::EMPTY; MAX_CONSUMER_SERIES].into_boxed_slice(),
            len: 0,
            // Sized for the primary cap PLUS the overflow ledger cap, so neither a primary claim nor an
            // overflow-ledger insert resizes the index on the record path.
            slot_index: HashMap::with_capacity(MAX_CONSUMER_SERIES + MAX_OVERFLOW_LEDGER),
            overflow_ledger: vec![ThroughputSeries::EMPTY; MAX_OVERFLOW_LEDGER].into_boxed_slice(),
            overflow_ledger_len: 0,
            labels_dropped: 0,
        }
    }
}

impl ThroughputRegistry {
    /// The `slot_index` value offset that distinguishes an OVERFLOW-LEDGER slot from a primary-series
    /// slot: a stored value `>= OVERFLOW_INDEX_BASE` is `OVERFLOW_INDEX_BASE + ledger_slot`. Sized at
    /// the primary cap, so the two index spaces never collide.
    const OVERFLOW_INDEX_BASE: usize = MAX_CONSUMER_SERIES;

    /// Resolves (or claims, or folds) the series for `name` and applies `apply` to its counts.
    /// O(1) and allocation-free for an EXISTING label — a primary series OR an already-folded over-cap
    /// label (the side-index resolves either, then a borrowed mutation). A brand-new label claims a
    /// free primary slot, then a bounded overflow-ledger slot at the cap (the only allocations, once
    /// per distinct label, off the steady-state path); `labels_dropped` counts each DISTINCT refused
    /// label ONCE. The closure receives `(&mut produced, &mut consumed)`.
    fn record(&mut self, name: &[u8], apply: impl Fn(&mut u64, &mut u64)) {
        let key = stored_key(name);
        // An EXISTING label — a primary series OR an already-folded over-cap label — resolves O(1).
        if let Some(&idx) = self.slot_index.get(key) {
            if idx >= Self::OVERFLOW_INDEX_BASE {
                if let Some(slot) = self
                    .overflow_ledger
                    .get_mut(idx - Self::OVERFLOW_INDEX_BASE)
                {
                    apply(&mut slot.produced, &mut slot.consumed);
                    return;
                }
            } else if let Some(slot) = self.series.get_mut(idx) {
                apply(&mut slot.produced, &mut slot.consumed);
                return;
            }
        }
        // A brand-new label with a free primary slot: claim it and record its key->slot mapping.
        if self.len < MAX_CONSUMER_SERIES {
            if let Some(slot) = self.series.get_mut(self.len) {
                slot.store_label(name);
                apply(&mut slot.produced, &mut slot.consumed);
                self.slot_index.insert(Box::from(key), self.len);
                self.len += 1;
                return;
            }
        }
        // The primary cap is reached: a brand-new DISTINCT over-cap label folds into the bounded
        // overflow ledger (counted ONCE), so a re-record of it resolves O(1) above next time.
        if self.overflow_ledger_len < MAX_OVERFLOW_LEDGER {
            if let Some(slot) = self.overflow_ledger.get_mut(self.overflow_ledger_len) {
                slot.store_label(name);
                apply(&mut slot.produced, &mut slot.consumed);
                self.slot_index.insert(
                    Box::from(key),
                    Self::OVERFLOW_INDEX_BASE + self.overflow_ledger_len,
                );
                self.overflow_ledger_len += 1;
                self.labels_dropped = self.labels_dropped.saturating_add(1);
                return;
            }
        }
        // Even the bounded ledger is saturated (more distinct over-cap labels than its capacity over
        // the broker's life): count the distinct drop, but do NOT fold its counts (it cannot be tracked
        // without a slot, and an untracked fold could not be resolved O(1) on a re-record). The
        // reported overflow totals are then a documented LOWER BOUND; `labels_dropped` still flags the
        // pressure. The same coarse, monotonic, never-grows-wrong fallback the lag registry uses.
        self.labels_dropped = self.labels_dropped.saturating_add(1);
    }

    /// Records one record PRODUCED to the stream `name` (#571). Allocation-free for an existing label.
    pub fn record_produced(&mut self, name: &[u8]) {
        self.record(name, |produced, _| *produced = produced.saturating_add(1));
    }

    /// Records one record CONSUMED (acked) by the group `name` (#571). Allocation-free for an existing
    /// label.
    pub fn record_consumed(&mut self, name: &[u8]) {
        self.record(name, |_, consumed| *consumed = consumed.saturating_add(1));
    }

    /// Invokes `f(label, produced, consumed)` for each occupied DISTINCT primary series. O(number of
    /// series), allocation-free; the overflow fold is emitted by the caller via the accessors below.
    pub fn for_each_series<F: FnMut(&str, u64, u64)>(&self, mut f: F) {
        for slot in self.series.iter().take(self.len) {
            if slot.used {
                f(slot.label_str(), slot.produced, slot.consumed);
            }
        }
    }

    /// Whether the overflow fold is in use (at least one label refused a primary series at the cap).
    #[must_use]
    pub fn has_overflow(&self) -> bool {
        self.overflow_ledger_len > 0 || self.labels_dropped > 0
    }

    /// The folded produced count of every over-cap stream label (`{stream="__overflow__"}`): the sum
    /// over the bounded ledger. A documented LOWER BOUND if the ledger ever saturated.
    #[must_use]
    pub fn overflow_produced(&self) -> u64 {
        self.overflow_ledger
            .iter()
            .take(self.overflow_ledger_len)
            .fold(0u64, |acc, s| acc.saturating_add(s.produced))
    }

    /// The folded consumed count of every over-cap group label (`{group="__overflow__"}`): the sum
    /// over the bounded ledger. A documented LOWER BOUND if the ledger ever saturated.
    #[must_use]
    pub fn overflow_consumed(&self) -> u64 {
        self.overflow_ledger
            .iter()
            .take(self.overflow_ledger_len)
            .fold(0u64, |acc, s| acc.saturating_add(s.consumed))
    }

    /// The count of DISTINCT stream/group labels refused a primary series at the cap (a
    /// cardinality-pressure signal, the `*_labels_dropped_total` counter). Counts each distinct label
    /// once (on its first fold), never per record.
    #[must_use]
    pub fn labels_dropped(&self) -> u64 {
        self.labels_dropped
    }

    /// The number of occupied distinct primary series (for the memory-ceiling test and operators).
    #[must_use]
    pub fn series_len(&self) -> usize {
        self.len
    }
}

/// The per-ack-level (Level 0/1/2) produce counters (#571): a FIXED three-slot array indexed by
/// [`AckLevel::as_u8`], so the cardinality is bounded BY CONSTRUCTION (a closed three-value enum, no
/// overflow fold needed). Each slot is the count of records accepted at that ack level
/// (`c0` no-ack / `c1` server-ack / `c2` server+client-ack), the single-node twin of the cluster
/// ack-level counters. Allocation-free; a plain array bump under the engine lock.
#[derive(Clone, Copy, Default)]
pub struct AckLevelCounters {
    /// Indexed by [`AckLevel::as_u8`] (`0`=`NoAck`, `1`=`ServerAck`, `2`=`ServerAndClientAck`).
    counts: [u64; 3],
}

impl AckLevelCounters {
    /// Records one record accepted at ack level `level`. Allocation-free (a fixed-index array bump).
    pub fn record(&mut self, level: AckLevel) {
        let idx = usize::from(level.as_u8());
        if let Some(slot) = self.counts.get_mut(idx) {
            *slot = slot.saturating_add(1);
        }
    }

    /// The count of records accepted at ack level `level`.
    #[must_use]
    pub fn count(&self, level: AckLevel) -> u64 {
        self.counts
            .get(usize::from(level.as_u8()))
            .copied()
            .unwrap_or(0)
    }
}

/// The owner of the bounded metric registry (#97): the two fixed-bucket histograms
/// (`ironbus_fsync_duration_seconds` and the append-latency histogram), the per-consumer lag
/// registry, and the self-monitoring series. Constructed once at engine open with the build
/// version and the open-time wall/monotonic instants read from the injected clock seam, so the
/// uptime and start-time series never call a raw `SystemTime::now`/`Instant::now`.
pub struct MetricRegistry {
    /// `ironbus_fsync_duration_seconds`: the produce-time fsync (durability barrier) latency, over
    /// the fixed registry buckets.
    fsync_duration: FixedHistogram,
    /// The append-latency histogram (the cost of one durable append), over the SAME fixed buckets.
    append_latency: FixedHistogram,
    /// `ironbus_produce_ack_duration_seconds` (#570): the produce->ACK request-path latency — the
    /// engine time from a group-commit batch starting its durability barrier to the records being
    /// durable (acked). Observed once per real-fsync batch (group commit amortizes one barrier over
    /// the batch), over the SAME fixed buckets, so an operator sees the producer-visible ack latency
    /// distribution distinct from the bare fsync syscall cost.
    produce_ack_latency: FixedHistogram,
    /// `ironbus_deliver_duration_seconds` (#570): the deliver request-path latency — the engine time
    /// to service one poll that handed out a delivery (the poll scan + lease grant), over the SAME
    /// fixed buckets. A poll that delivered nothing records nothing.
    deliver_latency: FixedHistogram,
    /// `ironbus_consume_duration_seconds` (#570): the consume (ack) request-path latency — the engine
    /// time to service one ack that committed (the lease ack + cursor commit + lag maintenance), over
    /// the SAME fixed buckets. A fenced/no-op ack records nothing.
    consume_latency: FixedHistogram,
    /// The per-consumer lag registry (incremental, capped at [`MAX_CONSUMER_SERIES`]).
    consumer_lag: ConsumerLagRegistry,
    /// The per-stream/per-group THROUGHPUT registry (#571): records produced per stream and consumed
    /// per group, bounded at [`MAX_CONSUMER_SERIES`] distinct labels with an `__overflow__` fold.
    throughput: ThroughputRegistry,
    /// The per-ack-level (0/1/2) produce counters (#571): a fixed three-slot array, bounded by the
    /// closed [`AckLevel`] enum (no overflow fold needed).
    ack_levels: AckLevelCounters,
    /// The build version string (`CARGO_PKG_VERSION`), the `version` label of `ironbus_build_info`.
    /// A `&'static str`, so the self-info series carries no heap allocation.
    build_version: &'static str,
    /// The broker's start time as Unix SECONDS, read ONCE from the clock seam at open. Exposed as
    /// the constant gauge `ironbus_start_time_seconds`.
    start_time_unix_seconds: u64,
    /// The clock-seam monotonic instant (nanoseconds) at open, the origin `ironbus_uptime_seconds`
    /// is measured from. Monotonic-derived (never wall-clock), so uptime never goes backwards on an
    /// NTP step.
    start_monotonic_nanos: u64,
}

impl MetricRegistry {
    /// Builds the registry, capturing the build version and the open-time wall/monotonic instants
    /// from the clock seam. `start_time_unix_seconds` and `start_monotonic_nanos` come from the
    /// caller's [`ironbus_core::clock::Clock`] read, never a raw `now()`.
    #[must_use]
    pub fn new(
        build_version: &'static str,
        start_time_unix_seconds: u64,
        start_monotonic_nanos: u64,
    ) -> MetricRegistry {
        MetricRegistry {
            fsync_duration: FixedHistogram::default(),
            append_latency: FixedHistogram::default(),
            produce_ack_latency: FixedHistogram::default(),
            deliver_latency: FixedHistogram::default(),
            consume_latency: FixedHistogram::default(),
            consumer_lag: ConsumerLagRegistry::default(),
            throughput: ThroughputRegistry::default(),
            ack_levels: AckLevelCounters::default(),
            build_version,
            start_time_unix_seconds,
            start_monotonic_nanos,
        }
    }

    /// Records one fsync (durability barrier) latency observation, in nanoseconds. Allocation-free
    /// hot-path call.
    pub fn observe_fsync_nanos(&mut self, nanos: u64) {
        self.fsync_duration.observe(nanos);
    }

    /// Records one append-latency observation, in nanoseconds. Allocation-free hot-path call.
    pub fn observe_append_nanos(&mut self, nanos: u64) {
        self.append_latency.observe(nanos);
    }

    /// Records one produce->ack request-path latency observation (#570), in nanoseconds.
    /// Allocation-free hot-path call.
    pub fn observe_produce_ack_nanos(&mut self, nanos: u64) {
        self.produce_ack_latency.observe(nanos);
    }

    /// Records one deliver request-path latency observation (#570), in nanoseconds. Allocation-free
    /// hot-path call; called only when a poll actually delivered.
    pub fn observe_deliver_nanos(&mut self, nanos: u64) {
        self.deliver_latency.observe(nanos);
    }

    /// Records one consume (ack) request-path latency observation (#570), in nanoseconds.
    /// Allocation-free hot-path call; called only when an ack actually committed.
    pub fn observe_consume_nanos(&mut self, nanos: u64) {
        self.consume_latency.observe(nanos);
    }

    /// Records that one record was appended (the durable head advanced by one). Allocation-free and
    /// O(1) regardless of the number of consumer series.
    pub fn record_appended(&mut self) {
        self.consumer_lag.record_appended(1);
    }

    /// Seeds the durable head to `records` at open (#97), so a recovered (non-empty) log starts the
    /// consumer-lag series at the correct produced-record count rather than zero. Called ONCE from
    /// [`crate::engine::Engine::open`]; the per-record `record_appended` is the steady-state path.
    pub fn seed_head(&mut self, records: u64) {
        self.consumer_lag.record_appended(records);
    }

    /// Sets consumer `name`'s committed record floor (the commit path). Allocation-free for an
    /// existing or overflow consumer; a brand-new consumer claims a fixed series slot or folds into
    /// the overflow series at the cap. See [`ConsumerLagRegistry::set_committed`].
    pub fn set_consumer_committed(&mut self, name: &[u8], committed: u64) {
        self.consumer_lag.set_committed(name, committed);
    }

    /// Records one record PRODUCED to stream `name` (#571). Allocation-free for an existing label; a
    /// brand-new stream claims a bounded series slot (or folds into `__overflow__` at the cap).
    pub fn record_stream_produced(&mut self, name: &[u8]) {
        self.throughput.record_produced(name);
    }

    /// Records one record CONSUMED (acked) by group `name` (#571). Allocation-free for an existing
    /// label; a brand-new group claims a bounded series slot (or folds into `__overflow__` at the cap).
    pub fn record_group_consumed(&mut self, name: &[u8]) {
        self.throughput.record_consumed(name);
    }

    /// Records one record accepted at ack level `level` (#571). Allocation-free (a fixed-index bump).
    pub fn record_ack_level(&mut self, level: AckLevel) {
        self.ack_levels.record(level);
    }

    /// The fsync-duration histogram (`ironbus_fsync_duration_seconds`).
    #[must_use]
    pub fn fsync_duration(&self) -> &FixedHistogram {
        &self.fsync_duration
    }

    /// The append-latency histogram.
    #[must_use]
    pub fn append_latency(&self) -> &FixedHistogram {
        &self.append_latency
    }

    /// The produce->ack request-path latency histogram (`ironbus_produce_ack_duration_seconds`, #570).
    #[must_use]
    pub fn produce_ack_latency(&self) -> &FixedHistogram {
        &self.produce_ack_latency
    }

    /// The deliver request-path latency histogram (`ironbus_deliver_duration_seconds`, #570).
    #[must_use]
    pub fn deliver_latency(&self) -> &FixedHistogram {
        &self.deliver_latency
    }

    /// The consume (ack) request-path latency histogram (`ironbus_consume_duration_seconds`, #570).
    #[must_use]
    pub fn consume_latency(&self) -> &FixedHistogram {
        &self.consume_latency
    }

    /// The per-consumer lag registry (for the scrape rendering and the cap/overflow tests).
    #[must_use]
    pub fn consumer_lag(&self) -> &ConsumerLagRegistry {
        &self.consumer_lag
    }

    /// The per-stream/per-group throughput registry (#571), for the scrape rendering and the
    /// cap/overflow tests.
    #[must_use]
    pub fn throughput(&self) -> &ThroughputRegistry {
        &self.throughput
    }

    /// The per-ack-level (0/1/2) produce counters (#571), for the scrape rendering.
    #[must_use]
    pub fn ack_levels(&self) -> &AckLevelCounters {
        &self.ack_levels
    }

    /// The build version string (the `version` label of `ironbus_build_info`).
    #[must_use]
    pub fn build_version(&self) -> &'static str {
        self.build_version
    }

    /// The broker start time as Unix seconds (`ironbus_start_time_seconds`), captured once at open.
    #[must_use]
    pub fn start_time_unix_seconds(&self) -> u64 {
        self.start_time_unix_seconds
    }

    /// The uptime in WHOLE SECONDS derived from the monotonic clock seam: `now_monotonic_nanos`
    /// minus the open-time monotonic origin, in seconds. Monotonic-derived so it never regresses on
    /// a wall-clock step. Pass the engine's current `now_monotonic_nanos` reading (from the clock
    /// seam); this function does no `now()` of its own.
    #[must_use]
    pub fn uptime_seconds(&self, now_monotonic_nanos: u64) -> u64 {
        now_monotonic_nanos.saturating_sub(self.start_monotonic_nanos) / 1_000_000_000
    }
}

/// The fixed registry-memory ceiling, in bytes, asserted by a test and signed off against the
/// edge RAM budget. It is the sum of the consumer-lag series array and its bounded overflow
/// fold-ledger, the per-stream/per-group throughput series array and ITS bounded overflow ledger
/// (#571), and the fixed core-series state (the histograms plus the small scalars). It is INDEPENDENT
/// of the record count, the disk size, and the number of live consumers/streams/groups, because ALL
/// FOUR series arrays are preallocated at their fixed caps.
///
/// The exact value is asserted in the tests below against `size_of` so a struct-layout change that
/// inflates the per-series cost is caught; the documented ceiling in `docs/METRICS.md` and the
/// `docs/RAM_BUDGET.md` sign-off cite this same derivation.
#[must_use]
pub fn registry_memory_ceiling_bytes() -> usize {
    // The boxed consumer-series array: the capped, dominant term.
    let consumer_series = MAX_CONSUMER_SERIES * core::mem::size_of::<ConsumerSeries>();
    // The bounded overflow fold-ledger: a second capped array of the SAME inline `ConsumerSeries`
    // entry, preallocated at its cap, so the overflow fold stays idempotent without an unbounded
    // per-consumer map. It is part of the hard ceiling, not an open-ended term.
    let overflow_ledger = MAX_OVERFLOW_LEDGER * core::mem::size_of::<ConsumerSeries>();
    // The per-stream/per-group throughput arrays (#571): a primary series array plus a bounded
    // overflow fold-ledger, BOTH capped and preallocated at the SAME cardinality cap, so they are part
    // of the hard ceiling, not open-ended terms.
    let throughput_series = MAX_CONSUMER_SERIES * core::mem::size_of::<ThroughputSeries>();
    let throughput_overflow = MAX_OVERFLOW_LEDGER * core::mem::size_of::<ThroughputSeries>();
    // The fixed core state held inline in MetricRegistry (the two histograms plus the scalar
    // self-info and lag-registry bookkeeping). This is the fixed sub-100-series core cost.
    let core = core::mem::size_of::<MetricRegistry>();
    consumer_series + overflow_ledger + throughput_series + throughput_overflow + core
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};

    #[test]
    fn follower_divergence_counter_starts_zero_and_increments_once_per_episode() {
        // #873 Phase 1: the bounded suspected-uncommitted-tail counter is monotonic and starts at zero.
        let m = FollowerDivergenceMetrics::default();
        assert_eq!(
            m.uncommitted_tail_suspected_total(),
            0,
            "a fresh telemetry block reports the honest zero"
        );
        m.record_uncommitted_tail_suspected();
        assert_eq!(
            m.uncommitted_tail_suspected_total(),
            1,
            "recording a suspected episode increments the counter (mutation check)"
        );
        m.record_uncommitted_tail_suspected();
        m.record_uncommitted_tail_suspected();
        assert_eq!(m.uncommitted_tail_suspected_total(), 3);
    }

    // -- The allocation-counting global allocator (scoped so it never makes unrelated tests flaky).
    //
    // A `#[global_allocator]` is process-wide, so a naive process-wide counter would be perturbed by
    // every OTHER test thread allocating in parallel. The arming and the count are therefore
    // THREAD-LOCAL: the allocator only counts an allocation made on a thread that armed itself, and
    // each counting test arms only its OWN thread, tightly around the hot-path call. A parallel test
    // on another thread is never counted, so the measurement is deterministic under parallel
    // `cargo test` with no global lock. The allocator is a transparent pass-through to the system
    // allocator otherwise.

    thread_local! {
        static COUNTING_ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static ALLOC_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Records one allocation against THIS thread's counter, but only while this thread is armed.
    /// `try_with` is used so an allocation during thread-local teardown (when the TLS is already
    /// destroyed) is silently ignored rather than panicking inside the allocator.
    fn note_alloc() {
        let armed = COUNTING_ARMED
            .try_with(std::cell::Cell::get)
            .unwrap_or(false);
        if armed {
            let _ = ALLOC_COUNT.try_with(|c| c.set(c.get().saturating_add(1)));
        }
    }

    struct CountingAllocator;

    // SAFETY: forwards every call unchanged to the system allocator; it only ADDS a thread-local
    // counter bump when this thread is armed, which does not affect the allocation itself. The
    // returned pointers and layouts are exactly the system allocator's, so the `GlobalAlloc`
    // contract is upheld. This is a test-only allocator (the whole module is `#[cfg(test)]`), so
    // `unsafe_code` is opted in here per the workspace lint policy.
    #[allow(unsafe_code)]
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note_alloc();
            System.alloc(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout);
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            note_alloc();
            System.realloc(ptr, layout, new_size)
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    /// Runs `f` with THIS thread's counter armed and returns the number of allocations it made. The
    /// window is as tight as possible (arm, call, disarm); only this thread's allocations are
    /// counted, so it is robust under parallel `cargo test` without any global lock.
    fn count_allocs<F: FnOnce()>(f: F) -> usize {
        ALLOC_COUNT.with(|c| c.set(0));
        COUNTING_ARMED.with(|c| c.set(true));
        f();
        COUNTING_ARMED.with(|c| c.set(false));
        ALLOC_COUNT.with(std::cell::Cell::get)
    }

    #[test]
    #[allow(clippy::cast_precision_loss)] // exact small integers; the f64 round-trip is lossless here
    fn the_le_labels_match_the_nanosecond_bounds() {
        assert_eq!(
            REGISTRY_BUCKET_LE_SECONDS.len(),
            REGISTRY_BUCKET_BOUNDS_NANOS.len()
        );
        for (le, &nanos) in REGISTRY_BUCKET_LE_SECONDS
            .iter()
            .zip(&REGISTRY_BUCKET_BOUNDS_NANOS)
        {
            let parsed: f64 = le.parse().unwrap();
            let expected = nanos as f64 / 1e9;
            assert!((parsed - expected).abs() < 1e-12, "le {le} != {nanos} ns");
        }
    }

    #[test]
    #[allow(clippy::cast_precision_loss)] // exact small integers; the f64 round-trip is lossless here
    fn the_bucket_set_is_exactly_the_fixed_issue_97_set() {
        // The issue pins the second-valued set exactly; a reorder or an off-by-one bound is caught.
        let expected_seconds = [
            0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0,
        ];
        assert_eq!(REGISTRY_BUCKET_BOUNDS_NANOS.len(), expected_seconds.len());
        for (&nanos, &secs) in REGISTRY_BUCKET_BOUNDS_NANOS.iter().zip(&expected_seconds) {
            let as_secs = nanos as f64 / 1e9;
            assert!((as_secs - secs).abs() < 1e-12, "{nanos} ns != {secs} s");
        }
    }

    #[test]
    fn histogram_places_each_observation_in_its_bucket() {
        let mut h = FixedHistogram::default();
        h.observe(400_000); // <= 0.0005 s -> bucket 0
        h.observe(500_000); // == 0.0005 s -> bucket 0 (le inclusive)
        h.observe(1_500_000); // <= 0.002 s -> bucket 2
        h.observe(9_000_000_000); // > 5 s -> +Inf only
        assert_eq!(h.count(), 4);
        assert_eq!(h.sum_nanos(), 400_000 + 500_000 + 1_500_000 + 9_000_000_000);
        let c = h.cumulative_buckets();
        assert_eq!(c[0], 2, "two at or below 0.0005 s");
        assert_eq!(c[1], 2, "nothing new at 0.001 s");
        assert_eq!(
            c[2], 3,
            "the 0.0015 s observation lands at the 0.002 s bound"
        );
        assert_eq!(
            c[REGISTRY_BUCKET_BOUNDS_NANOS.len() - 1],
            3,
            "the 9 s observation is excluded from the 5 s bucket (only +Inf)"
        );
    }

    #[test]
    fn consumer_lag_is_head_minus_committed_and_incremental() {
        let mut r = ConsumerLagRegistry::default();
        // Append 5 records: the head advances, so a fresh consumer at floor 0 lags 5.
        r.record_appended(5);
        r.set_committed(b"orders", 0);
        let mut seen = Vec::new();
        r.for_each_series(|label, lag| seen.push((label.to_string(), lag)));
        assert_eq!(seen, vec![("orders".to_string(), 5)]);
        // Commit 3 records: lag drops to 2, with NO rescan of any log (only the floor moved).
        r.set_committed(b"orders", 3);
        seen.clear();
        r.for_each_series(|label, lag| seen.push((label.to_string(), lag)));
        assert_eq!(seen, vec![("orders".to_string(), 2)]);
        // A second consumer is an independent series.
        r.set_committed(b"billing", 1);
        seen.clear();
        r.for_each_series(|label, lag| seen.push((label.to_string(), lag)));
        assert!(seen.contains(&("billing".to_string(), 4)), "{seen:?}");
        assert_eq!(r.series_len(), 2);
    }

    #[test]
    fn the_commit_floor_is_monotonic() {
        let mut r = ConsumerLagRegistry::default();
        r.record_appended(10);
        r.set_committed(b"g", 7);
        // A stale lower commit is ignored (a cursor never moves backwards).
        r.set_committed(b"g", 3);
        let mut lag = None;
        r.for_each_series(|_, l| lag = Some(l));
        assert_eq!(lag, Some(3), "floor stays at 7, so lag = 10 - 7 = 3");
    }

    #[test]
    fn the_1024th_plus_consumer_folds_into_overflow_and_counts_drops() {
        let mut r = ConsumerLagRegistry::default();
        r.record_appended(100);
        // Fill exactly the cap with distinct series, each committed at 0 (lag 100).
        for i in 0..MAX_CONSUMER_SERIES {
            r.set_committed(format!("c{i}").as_bytes(), 0);
        }
        assert_eq!(r.series_len(), MAX_CONSUMER_SERIES);
        assert_eq!(r.labels_dropped(), 0, "nothing dropped at exactly the cap");
        assert!(!r.has_overflow());
        // The 1025th and 1026th consumers are refused a distinct series and fold into __overflow__.
        r.set_committed(b"overflow-a", 10); // lag 90
        r.set_committed(b"overflow-b", 30); // lag 70
        assert_eq!(
            r.series_len(),
            MAX_CONSUMER_SERIES,
            "no new distinct series"
        );
        assert_eq!(r.labels_dropped(), 2, "two labels dropped");
        assert!(r.has_overflow());
        // Total folded lag stays visible and correct: 90 + 70 = 160.
        assert_eq!(r.overflow_lag(), 160);
    }

    #[test]
    fn an_over_cap_consumer_recommitting_does_not_double_count_or_grow_lag() {
        // The BLOCKER regression (#97): the engine calls `set_committed` on EVERY ack, so an
        // over-cap (folded) consumer arrives here many times over its life. The fold MUST be
        // idempotent: re-committing the SAME folded consumer must NOT inflate `labels_dropped`
        // (which counts DISTINCT refused labels) and must NOT make the overflow lag rise as the
        // consumer makes progress. The old code did `overflow_committed += committed` /
        // `overflow_consumers += 1` / `labels_dropped += 1` on every commit, so this test fails
        // against it and passes after the bounded fold-ledger fix.
        let mut r = ConsumerLagRegistry::default();
        r.record_appended(100);
        // Fill exactly the cap with distinct series so the next consumer is forced into the fold.
        for i in 0..MAX_CONSUMER_SERIES {
            r.set_committed(format!("c{i}").as_bytes(), 0);
        }
        assert_eq!(r.labels_dropped(), 0);
        assert!(!r.has_overflow());

        // The worked example from the issue: head = 100, ONE over-cap consumer.
        // First commit at offset 10 -> its lag is 100 - 10 = 90.
        r.set_committed(b"over-cap", 10);
        assert_eq!(r.labels_dropped(), 1, "exactly one DISTINCT label refused");
        assert_eq!(
            r.overflow_saturated(),
            0,
            "the ledger has room, no saturation"
        );
        assert_eq!(
            r.overflow_lag(),
            90,
            "first fold: head 100 - committed 10 = 90"
        );

        // The SAME consumer commits again, advancing to offset 50 (it made progress). The old code
        // computed 100*2 - 60 = 140 here (lag RISING as the consumer caught up); the fix updates the
        // single tracked floor in place, so the lag is the true 100 - 50 = 50 and DROPS, and the
        // distinct-label counter stays at 1 (not 2).
        r.set_committed(b"over-cap", 50);
        assert_eq!(
            r.labels_dropped(),
            1,
            "a re-commit of an already-folded consumer must NOT count a new dropped label"
        );
        assert_eq!(
            r.overflow_lag(),
            50,
            "the overflow lag must be the consumer's true lag (100 - 50), not rise to 140"
        );

        // A stale lower re-commit is ignored (monotonic floor), so the lag does not jump back up.
        r.set_committed(b"over-cap", 20);
        assert_eq!(r.overflow_lag(), 50, "a stale lower commit is ignored");

        // A SECOND distinct over-cap consumer is a new dropped label and adds its own lag term.
        r.set_committed(b"over-cap-2", 30); // lag 70
        assert_eq!(
            r.labels_dropped(),
            2,
            "a second DISTINCT label is counted once"
        );
        // Total folded lag = (100 - 50) + (100 - 30) = 50 + 70 = 120, exact (no saturation).
        assert_eq!(r.overflow_lag(), 120);
        // And re-committing the second consumer many times does not inflate either metric.
        for off in 31..=60 {
            r.set_committed(b"over-cap-2", off);
        }
        assert_eq!(
            r.labels_dropped(),
            2,
            "many re-commits, still two distinct labels"
        );
        // over-cap is at 50, over-cap-2 advanced to 60: (100 - 50) + (100 - 60) = 50 + 40 = 90.
        assert_eq!(
            r.overflow_lag(),
            90,
            "the folded lag tracks each consumer's true progress, never accumulating"
        );
    }

    #[test]
    fn the_overflow_ledger_saturation_is_a_monotonic_lower_bound() {
        // Past the ledger capacity, a brand-new distinct over-cap consumer cannot be tracked
        // individually. The documented coarse fallback: it bumps `labels_dropped` and the
        // `overflow_saturated` flag, but its lag is NOT folded in, so the reported overflow lag is a
        // monotonic LOWER BOUND. The ledger-tracked consumers' lag stays exact and never grows-wrong.
        let mut r = ConsumerLagRegistry::default();
        r.record_appended(1000);
        // Fill the distinct-series cap.
        for i in 0..MAX_CONSUMER_SERIES {
            r.set_committed(format!("c{i}").as_bytes(), 0);
        }
        // Fill the ENTIRE overflow ledger with distinct over-cap consumers, each at floor 0.
        for i in 0..MAX_OVERFLOW_LEDGER {
            r.set_committed(format!("o{i}").as_bytes(), 0);
        }
        assert_eq!(r.overflow_saturated(), 0, "ledger not yet saturated");
        let lag_at_ledger_full = r.overflow_lag();
        let ledger_cap = u64::try_from(MAX_OVERFLOW_LEDGER).unwrap();
        assert_eq!(
            r.labels_dropped(),
            ledger_cap,
            "one distinct label per ledgered over-cap consumer"
        );
        // One MORE distinct over-cap consumer: the ledger is full, so it saturates.
        r.set_committed(b"past-the-ledger", 0);
        assert_eq!(
            r.overflow_saturated(),
            1,
            "the past-capacity consumer saturated"
        );
        assert_eq!(
            r.labels_dropped(),
            ledger_cap + 1,
            "the saturating consumer is still counted as a distinct refused label"
        );
        // The reported lag is a LOWER BOUND: it does not grow-wrong (it stays at the ledgered total,
        // not the old buggy head*consumers - committed which would have ballooned).
        assert_eq!(
            r.overflow_lag(),
            lag_at_ledger_full,
            "a saturating consumer is not folded into the lag, which stays a monotonic lower bound"
        );
        // A ledgered consumer making progress still LOWERS the (lower-bound) lag, never raises it.
        r.set_committed(b"o0", 500);
        assert!(
            r.overflow_lag() < lag_at_ledger_full,
            "a tracked consumer's progress lowers the overflow lag"
        );
    }

    #[test]
    fn the_overflow_fold_path_does_not_allocate() {
        // The engine drives the fold on every ack, so the fold (claim + re-commit update) must be
        // allocation-free just like the under-cap commit path.
        let mut reg = MetricRegistry::new("0.0.0", 0, 0);
        reg.record_appended();
        // Fill the distinct-series cap OUTSIDE the counted window.
        for i in 0..MAX_CONSUMER_SERIES {
            reg.set_consumer_committed(format!("c{i}").as_bytes(), 0);
        }
        // Pre-fold one over-cap consumer OUTSIDE the window (its first fold claims a ledger slot).
        reg.set_consumer_committed(b"folded", 0);
        let allocs = count_allocs(|| {
            // Re-commit the already-folded consumer many times: the steady-state engine ack path.
            for i in 0..1000u64 {
                reg.set_consumer_committed(b"folded", i);
            }
        });
        assert_eq!(
            allocs, 0,
            "the overflow re-commit path allocated {allocs} times"
        );
    }

    #[test]
    fn an_over_long_label_is_truncated_not_grown() {
        let mut r = ConsumerLagRegistry::default();
        r.record_appended(1);
        let long = "x".repeat(MAX_CONSUMER_LABEL_BYTES * 2);
        r.set_committed(long.as_bytes(), 0);
        let mut label_len = None;
        r.for_each_series(|label, _| label_len = Some(label.len()));
        assert_eq!(label_len, Some(MAX_CONSUMER_LABEL_BYTES));
    }

    #[test]
    fn uptime_is_monotonic_derived() {
        let reg = MetricRegistry::new("9.9.9", 1_700_000_000, 5_000_000_000);
        // 8 s after the open-time monotonic origin (5 s).
        assert_eq!(reg.uptime_seconds(13_000_000_000), 8);
        // A monotonic reading before the origin (cannot happen for a real clock) saturates to 0.
        assert_eq!(reg.uptime_seconds(1_000_000_000), 0);
        assert_eq!(reg.start_time_unix_seconds(), 1_700_000_000);
        assert_eq!(reg.build_version(), "9.9.9");
    }

    #[test]
    fn the_registry_memory_ceiling_is_fixed_and_bounded() {
        // The ceiling is independent of how many consumers are live: a registry with zero, one, and
        // the full cap of consumers all report the SAME ceiling, because the series array is
        // preallocated at the cap.
        let ceiling = registry_memory_ceiling_bytes();
        // The per-series cost is fixed at compile time (the inline label buffer plus the small
        // committed/len/used bookkeeping, all fixed-width so it is identical on 32-bit and 64-bit
        // targets). It is bounded by the label buffer plus two machine words, so a layout change
        // that inflated it (e.g. a heap `String` label, which would shrink the struct to a pointer
        // but add unbounded heap) is caught by the bound below.
        let per_series = core::mem::size_of::<ConsumerSeries>();
        assert!(
            per_series >= MAX_CONSUMER_LABEL_BYTES,
            "the inline label buffer must be stored, not heaped: per_series {per_series}"
        );
        assert!(
            per_series <= MAX_CONSUMER_LABEL_BYTES + 16,
            "per-series cost drifted above label[64] + two words: {per_series}"
        );
        // The throughput series (#571) is a parallel capped array (a per-stream/per-group counter
        // payload instead of a lag floor), also preallocated at the cap with its own bounded overflow
        // ledger, all fixed-width so it is identical across targets.
        let per_throughput = core::mem::size_of::<ThroughputSeries>();
        assert!(
            per_throughput >= MAX_CONSUMER_LABEL_BYTES,
            "the inline throughput label buffer must be stored, not heaped: {per_throughput}"
        );
        assert!(
            per_throughput <= MAX_CONSUMER_LABEL_BYTES + 24,
            "per-throughput-series cost drifted above label[64] + three words: {per_throughput}"
        );
        // The overflow fold-ledgers are SECOND capped arrays of the same per-entry cost, also
        // preallocated at their caps, so they too are fixed terms independent of live-label count. The
        // ceiling is exactly the four capped arrays (lag series + lag overflow + throughput series +
        // throughput overflow) plus the fixed core.
        assert_eq!(
            ceiling,
            MAX_CONSUMER_SERIES * per_series
                + MAX_OVERFLOW_LEDGER * per_series
                + MAX_CONSUMER_SERIES * per_throughput
                + MAX_OVERFLOW_LEDGER * per_throughput
                + core::mem::size_of::<MetricRegistry>()
        );
        // The signed-off ceiling: the four capped series arrays (the lag series + its overflow ledger,
        // the throughput series + its overflow ledger) are the dominant terms and together are well
        // under 512 KiB, so the whole registry is a small fixed slice of the 64 MiB edge RAM budget,
        // INDEPENDENT of record count or disk size. (~80-88 bytes/series x 1024 x 4 arrays ~= 340 KiB.)
        assert!(
            ceiling < 512 * 1024,
            "registry ceiling {ceiling} bytes exceeded the documented 512 KiB sign-off"
        );
        // The core (non-consumer-series) state is a fixed sub-100-series cost: a handful of
        // histograms and scalars, well under 1 KiB.
        assert!(
            core::mem::size_of::<MetricRegistry>() < 1024,
            "core registry state is not the fixed small term it is documented as"
        );
    }

    #[test]
    fn the_append_and_commit_hot_path_does_not_allocate() {
        // Build the registry and pre-touch its consumer series OUTSIDE the counted window (claiming a
        // series slot copies the label into the preallocated array; the test asserts the STEADY-STATE
        // hot path, where the series already exists, allocates nothing).
        let mut reg = MetricRegistry::new("0.0.0", 0, 0);
        reg.set_consumer_committed(b"orders", 0);
        reg.set_consumer_committed(b"billing", 0);
        // The steady-state append + commit + observe hot path: advance the head, observe both
        // histograms, and move two existing consumers' commit floors. None of this may allocate.
        let allocs = count_allocs(|| {
            for i in 0..1000u64 {
                reg.record_appended();
                reg.observe_fsync_nanos(123_456);
                reg.observe_append_nanos(7_890);
                reg.set_consumer_committed(b"orders", i);
                reg.set_consumer_committed(b"billing", i / 2);
            }
        });
        assert_eq!(
            allocs, 0,
            "the append/commit hot path allocated {allocs} times"
        );
    }

    #[test]
    fn the_throughput_and_ack_level_record_paths_are_allocation_free() {
        // #571: the per-stream produce / per-group consume counters and the per-ack-level counters
        // must be allocation-free on the STEADY-STATE hot path (an existing label), so leaving them on
        // is affordable on the edge box, exactly like the lag registry. Pre-touch the labels OUTSIDE
        // the counted window (claiming a series slot copies the label into the preallocated array).
        let mut reg = MetricRegistry::new("0.0.0", 0, 0);
        reg.record_stream_produced(b""); // the default stream
        reg.record_group_consumed(b"orders");
        let allocs = count_allocs(|| {
            for _ in 0..1000u64 {
                reg.record_stream_produced(b"");
                reg.record_group_consumed(b"orders");
                reg.record_ack_level(AckLevel::NoAck);
                reg.record_ack_level(AckLevel::ServerAck);
                reg.record_ack_level(AckLevel::ServerAndClientAck);
            }
        });
        assert_eq!(
            allocs, 0,
            "the throughput/ack-level record path allocated {allocs} times"
        );
        // The counts landed where expected (1 pre-touch + 1000 in-window).
        let tp = reg.throughput();
        tp.for_each_series(|label, produced, consumed| match label {
            "" => assert_eq!(produced, 1001),
            "orders" => assert_eq!(consumed, 1001),
            other => panic!("unexpected throughput label {other:?}"),
        });
        assert_eq!(reg.ack_levels().count(AckLevel::NoAck), 1000);
        assert_eq!(reg.ack_levels().count(AckLevel::ServerAck), 1000);
        assert_eq!(reg.ack_levels().count(AckLevel::ServerAndClientAck), 1000);
    }

    #[test]
    fn the_throughput_registry_caps_cardinality_and_folds_overflow() {
        // #571: past MAX_CONSUMER_SERIES distinct labels, a new label is REFUSED its own series and its
        // counts FOLD into `__overflow__`, bounding the series memory (the cardinality firewall the
        // registry enforces). `labels_dropped` counts each DISTINCT refused label once.
        let mut reg = MetricRegistry::new("0.0.0", 0, 0);
        // Fill exactly to the cap with distinct stream labels, each produced once.
        for i in 0..MAX_CONSUMER_SERIES {
            reg.record_stream_produced(format!("stream-{i}").as_bytes());
        }
        let tp = reg.throughput();
        assert_eq!(tp.series_len(), MAX_CONSUMER_SERIES);
        assert!(!tp.has_overflow(), "at the cap exactly, no overflow yet");
        assert_eq!(tp.labels_dropped(), 0);
        // Two MORE distinct over-cap labels, each produced twice: both fold, and the fold sums their
        // counts (a pure monotonic add is trivially idempotent — no floor to reconcile).
        reg.record_stream_produced(b"over-a");
        reg.record_stream_produced(b"over-a");
        reg.record_stream_produced(b"over-b");
        reg.record_stream_produced(b"over-b");
        let tp = reg.throughput();
        assert!(tp.has_overflow());
        assert_eq!(
            tp.overflow_produced(),
            4,
            "both over-cap labels' produces fold into __overflow__"
        );
        assert_eq!(
            tp.labels_dropped(),
            2,
            "each DISTINCT refused label is counted once, never per record"
        );
        assert_eq!(
            tp.series_len(),
            MAX_CONSUMER_SERIES,
            "the series array never grows past the cap"
        );
    }

    #[test]
    fn the_throughput_overflow_label_is_invisible_until_a_label_is_dropped() {
        // #571: a healthy broker (under the cap) emits NO `__overflow__` throughput series, so the
        // overflow line only appears once cardinality pressure forced a fold.
        let mut reg = MetricRegistry::new("0.0.0", 0, 0);
        reg.record_stream_produced(b"orders");
        reg.record_group_consumed(b"orders");
        assert!(!reg.throughput().has_overflow());
    }

    #[test]
    fn the_request_path_latency_histograms_observe_and_are_allocation_free() {
        // #570: the produce->ack / deliver / consume request-path histograms record into the SAME
        // fixed bucket set, and their observe is allocation-free just like fsync/append (so leaving
        // the request-path latency metrics on is affordable on the edge box).
        let mut reg = MetricRegistry::new("0.0.0", 0, 0);
        let allocs = count_allocs(|| {
            for _ in 0..1000u64 {
                reg.observe_produce_ack_nanos(250_000); // <= 0.0005 s bucket 0
                reg.observe_deliver_nanos(1_500_000); // <= 0.002 s bucket 2
                reg.observe_consume_nanos(9_000_000_000); // > 5 s -> +Inf only
            }
        });
        assert_eq!(
            allocs, 0,
            "the latency observe path allocated {allocs} times"
        );
        assert_eq!(reg.produce_ack_latency().count(), 1000);
        assert_eq!(reg.deliver_latency().count(), 1000);
        assert_eq!(reg.consume_latency().count(), 1000);
        // Each landed in its expected cumulative bucket.
        assert_eq!(reg.produce_ack_latency().cumulative_buckets()[0], 1000);
        assert_eq!(reg.deliver_latency().cumulative_buckets()[2], 1000);
        assert_eq!(
            reg.consume_latency().cumulative_buckets()[REGISTRY_BUCKET_BOUNDS_NANOS.len() - 1],
            0,
            "a > 5 s observation is only in +Inf, not the 5 s bucket"
        );
    }

    #[test]
    fn the_scrape_walk_does_not_allocate() {
        // A scrape walks the bounded series set and reads the histograms; the WALK itself (the
        // for_each_series visit plus the cumulative-bucket reads) must allocate nothing. (The
        // string formatting the real /metrics body does is a separate, already-bounded concern; this
        // pins that the registry's read side is allocation-free.)
        let mut reg = MetricRegistry::new("0.0.0", 0, 0);
        reg.record_appended();
        for i in 0..500u64 {
            reg.set_consumer_committed(format!("c{i}").as_bytes(), 0);
        }
        let allocs = count_allocs(|| {
            let mut total = 0u64;
            reg.consumer_lag()
                .for_each_series(|_, lag| total = total.saturating_add(lag));
            let _ = reg.fsync_duration().cumulative_buckets();
            let _ = reg.append_latency().cumulative_buckets();
            let _ = reg.consumer_lag().overflow_lag();
            let _ = reg.uptime_seconds(1_000_000_000);
            // Defeat any dead-code elision of the walk.
            assert!(total >= 500);
        });
        assert_eq!(allocs, 0, "the scrape walk allocated {allocs} times");
    }
}
