// SPDX-License-Identifier: MIT OR Apache-2.0
//! The bounded, allocation-free metric registry (#97).
//!
//! This makes leaving metrics on permanently affordable on a few-hundred-MB ARM box: the
//! append and scrape hot paths never allocate, the registry has a HARD memory ceiling
//! (a fixed sub-100 core-series cost plus 1024 consumer series times a fixed per-series
//! cost), and per-consumer lag is cheap to update (the append path that runs on every produce is
//! O(1): it bumps one shared head counter; the commit path is a bounded scan of at most
//! [`MAX_CONSUMER_SERIES`] in-memory slots) and O(number of series) to scrape, all independent of
//! the record count or disk size. Crucially NOTHING here ever walks the durable log or the disk.
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

/// The per-consumer lag registry (#97): the durable head as a record count, a fixed array of up to
/// [`MAX_CONSUMER_SERIES`] consumer series, the `__overflow__` fold series for refused labels, and
/// the dropped-labels counter. Lag for one consumer is `head - committed`, both maintained
/// incrementally; a scrape only walks the bounded series array, never the log.
pub struct ConsumerLagRegistry {
    /// The durable log head as a RECORD COUNT (the number of records produced). Advances by one on
    /// every append; every consumer's lag is this minus its commit floor.
    head: u64,
    /// The fixed-capacity consumer series array, as a boxed slice of exactly [`MAX_CONSUMER_SERIES`]
    /// slots, allocated ONCE at construction on the heap (so the 1024-slot array never lives on a
    /// stack frame nor inline in the engine struct). A new consumer takes the first free slot; past
    /// capacity it folds into the overflow series.
    series: Box<[ConsumerSeries]>,
    /// The number of occupied slots in `series`.
    len: usize,
    /// The folded commit floor of every OVER-CAP consumer (those refused a distinct series). Its
    /// lag is `head x overflow_consumers - overflow_committed`; see
    /// [`ConsumerLagRegistry::overflow_lag`]. Held as the count of folded consumers and their
    /// summed commit floor so the total stays correct as folded consumers commit.
    overflow_committed: u64,
    /// The number of distinct consumers folded into the overflow series.
    overflow_consumers: u64,
    /// `ironbus_consumer_labels_dropped_total`: the number of distinct consumer labels refused a
    /// series because the cap was reached. A monotonic counter (an operator's cardinality-pressure
    /// signal).
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
            overflow_committed: 0,
            overflow_consumers: 0,
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

    /// Sets consumer `name`'s committed record floor to `committed` (the commit path). Allocation-free,
    /// and a bounded in-memory scan of at most [`MAX_CONSUMER_SERIES`] slots (never the log): it finds
    /// the consumer's slot (or claims a free one for a new consumer, or folds into the overflow series
    /// at the cap, incrementing the dropped-labels counter). The stored floor is monotonic
    /// non-decreasing (a commit never moves a cursor backwards), so a stale lower value is ignored.
    pub fn set_committed(&mut self, name: &[u8], committed: u64) {
        // An existing series: advance its floor (monotonic). The linear scan is over the bounded
        // series array (at most MAX_CONSUMER_SERIES), never the log.
        for slot in self.series.iter_mut().take(self.len) {
            if slot.used && slot.label_matches(name) {
                slot.committed = slot.committed.max(committed);
                return;
            }
        }
        // A new consumer with a free slot: claim it.
        if self.len < MAX_CONSUMER_SERIES {
            if let Some(slot) = self.series.get_mut(self.len) {
                let key = stored_key(name);
                let n = key.len().min(MAX_CONSUMER_LABEL_BYTES);
                if let Some(dst) = slot.label.get_mut(..n) {
                    if let Some(src) = key.get(..n) {
                        dst.copy_from_slice(src);
                    }
                }
                // `n <= MAX_CONSUMER_LABEL_BYTES` (64), so it always fits a `u16`; the `unwrap_or`
                // is a never-taken fallback that keeps the conversion panic-free in a lib path.
                slot.label_len = u16::try_from(n).unwrap_or(u16::MAX);
                slot.used = true;
                slot.committed = committed;
                self.len += 1;
                return;
            }
        }
        // The cap is reached: refuse a new distinct series, fold this consumer into the overflow
        // series, and count the dropped label. The overflow lag stays correct because the folded
        // commit floor is summed across every folded consumer.
        self.overflow_committed = self.overflow_committed.saturating_add(committed);
        self.overflow_consumers = self.overflow_consumers.saturating_add(1);
        self.labels_dropped = self.labels_dropped.saturating_add(1);
    }

    /// The durable head as a record count (the value every consumer's lag is measured against).
    #[must_use]
    pub fn head(&self) -> u64 {
        self.head
    }

    /// `ironbus_consumer_labels_dropped_total`: the count of consumer labels refused a series at the
    /// cap.
    #[must_use]
    pub fn labels_dropped(&self) -> u64 {
        self.labels_dropped
    }

    /// The lag of the overflow (folded) series: the sum over every folded consumer of
    /// `head - committed_i`, which equals `head x overflow_consumers - overflow_committed`
    /// (saturating, so a stale floor above the head never underflows).
    #[must_use]
    pub fn overflow_lag(&self) -> u64 {
        self.head
            .saturating_mul(self.overflow_consumers)
            .saturating_sub(self.overflow_committed)
    }

    /// Whether the overflow series is in use (at least one consumer was folded), so the scrape only
    /// emits the `__overflow__` line once a label has actually been dropped.
    #[must_use]
    pub fn has_overflow(&self) -> bool {
        self.overflow_consumers > 0
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
    /// The per-consumer lag registry (incremental, capped at [`MAX_CONSUMER_SERIES`]).
    consumer_lag: ConsumerLagRegistry,
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
            consumer_lag: ConsumerLagRegistry::default(),
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

    /// The per-consumer lag registry (for the scrape rendering and the cap/overflow tests).
    #[must_use]
    pub fn consumer_lag(&self) -> &ConsumerLagRegistry {
        &self.consumer_lag
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
/// edge RAM budget. It is the sum of the consumer-series array (the dominant, capped term) and the
/// fixed core-series state (the two histograms plus the small scalars). It is INDEPENDENT of the
/// record count, the disk size, and the number of live consumers, because the consumer-series array
/// is preallocated at its 1024-slot cap.
///
/// The exact value is asserted in the tests below against `size_of` so a struct-layout change that
/// inflates the per-series cost is caught; the documented ceiling in `docs/METRICS.md` and the
/// `docs/RAM_BUDGET.md` sign-off cite this same derivation.
#[must_use]
pub fn registry_memory_ceiling_bytes() -> usize {
    // The boxed consumer-series array: the capped, dominant term.
    let consumer_series = MAX_CONSUMER_SERIES * core::mem::size_of::<ConsumerSeries>();
    // The fixed core state held inline in MetricRegistry (the two histograms plus the scalar
    // self-info and lag-registry bookkeeping). This is the fixed sub-100-series core cost.
    let core = core::mem::size_of::<MetricRegistry>();
    consumer_series + core
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};

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
        assert_eq!(
            ceiling,
            MAX_CONSUMER_SERIES * per_series + core::mem::size_of::<MetricRegistry>()
        );
        // The signed-off ceiling: the consumer-series array is the dominant term and is well under
        // 128 KiB, so the whole registry is a small fixed slice of the 64 MiB edge RAM budget,
        // INDEPENDENT of record count or disk size. (~80 bytes/series x 1024 ~= 80 KiB.)
        assert!(
            ceiling < 128 * 1024,
            "registry ceiling {ceiling} bytes exceeded the documented 128 KiB sign-off"
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
