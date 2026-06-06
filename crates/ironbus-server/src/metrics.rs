// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-bucket latency histograms for the operator metrics, allocation-free on the hot path.
//!
//! [`LatencyHistogram`] records observations (nanoseconds) into a frozen set of buckets and
//! tracks the running sum and count, so `/metrics` can expose a Prometheus histogram without
//! allocating per observation. The fsync (durability barrier) latency on produce is the first
//! consumer; the bounds straddle a fast on-disk fdatasync (~100 us) and a slow, contended edge
//! SD card (~1 s).

/// The frozen fsync-latency bucket upper bounds, in nanoseconds, ascending. An implicit
/// `+Inf` bucket follows.
pub const FSYNC_BUCKET_BOUNDS_NANOS: [u64; 9] = [
    100_000,       // 100 us
    500_000,       // 500 us
    1_000_000,     // 1 ms
    5_000_000,     // 5 ms
    10_000_000,    // 10 ms
    50_000_000,    // 50 ms
    100_000_000,   // 100 ms
    500_000_000,   // 500 ms
    1_000_000_000, // 1 s
];

/// The Prometheus `le` labels (seconds) matching [`FSYNC_BUCKET_BOUNDS_NANOS`], one per bound.
pub const FSYNC_BUCKET_LE_SECONDS: [&str; 9] = [
    "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1",
];

/// A fixed-bucket histogram of latencies in nanoseconds. `observe` is allocation-free; the
/// bucket counts are stored non-cumulatively and made cumulative only at exposition time.
#[derive(Clone, Copy, Debug)]
pub struct LatencyHistogram {
    /// Per-bucket observation counts (length = bounds + 1 for the `+Inf` bucket).
    counts: [u64; FSYNC_BUCKET_BOUNDS_NANOS.len() + 1],
    /// The running sum of all observed nanoseconds.
    sum_nanos: u64,
    /// The total number of observations.
    count: u64,
}

impl Default for LatencyHistogram {
    fn default() -> LatencyHistogram {
        LatencyHistogram {
            counts: [0; FSYNC_BUCKET_BOUNDS_NANOS.len() + 1],
            sum_nanos: 0,
            count: 0,
        }
    }
}

impl LatencyHistogram {
    /// Records one observation of `nanos` nanoseconds (the `le` bound is inclusive).
    pub fn observe(&mut self, nanos: u64) {
        let idx = FSYNC_BUCKET_BOUNDS_NANOS
            .iter()
            .position(|&bound| nanos <= bound)
            .unwrap_or(FSYNC_BUCKET_BOUNDS_NANOS.len());
        self.counts[idx] += 1;
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

    /// The CUMULATIVE bucket counts, one per [`FSYNC_BUCKET_BOUNDS_NANOS`] bound (each includes
    /// every lower bucket), as a Prometheus histogram requires. The `+Inf` bucket equals
    /// [`LatencyHistogram::count`].
    #[must_use]
    pub fn cumulative_buckets(&self) -> [u64; FSYNC_BUCKET_BOUNDS_NANOS.len()] {
        let mut cumulative = [0u64; FSYNC_BUCKET_BOUNDS_NANOS.len()];
        let mut running = 0u64;
        for (i, slot) in cumulative.iter_mut().enumerate() {
            running += self.counts[i];
            *slot = running;
        }
        cumulative
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_histogram_is_all_zero() {
        let h = LatencyHistogram::default();
        assert_eq!(h.count(), 0);
        assert_eq!(h.sum_nanos(), 0);
        assert_eq!(h.cumulative_buckets(), [0; FSYNC_BUCKET_BOUNDS_NANOS.len()]);
    }

    #[test]
    fn observe_places_each_value_in_its_bucket_and_sums() {
        let mut h = LatencyHistogram::default();
        h.observe(50_000); // <= 100 us -> bucket 0
        h.observe(100_000); // == 100 us -> bucket 0 (le is inclusive)
        h.observe(750_000); // <= 1 ms -> bucket 2
        h.observe(2_000_000_000); // > 1 s -> +Inf only
        assert_eq!(h.count(), 4);
        assert_eq!(h.sum_nanos(), 50_000 + 100_000 + 750_000 + 2_000_000_000);
        let c = h.cumulative_buckets();
        assert_eq!(c[0], 2, "two observations at or below 100 us");
        assert_eq!(c[1], 2, "nothing new at 500 us");
        assert_eq!(c[2], 3, "the 750 us observation lands at the 1 ms bound");
        assert_eq!(
            c[FSYNC_BUCKET_BOUNDS_NANOS.len() - 1],
            3,
            "the 2 s observation is excluded from the 1 s bucket (only in +Inf)"
        );
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn the_le_labels_match_the_nanosecond_bounds() {
        assert_eq!(
            FSYNC_BUCKET_LE_SECONDS.len(),
            FSYNC_BUCKET_BOUNDS_NANOS.len()
        );
        for (le, &nanos) in FSYNC_BUCKET_LE_SECONDS
            .iter()
            .zip(&FSYNC_BUCKET_BOUNDS_NANOS)
        {
            let expected = nanos as f64 / 1e9;
            let parsed: f64 = le.parse().unwrap();
            assert!((parsed - expected).abs() < 1e-12, "le {le} != {nanos} ns");
        }
    }
}
