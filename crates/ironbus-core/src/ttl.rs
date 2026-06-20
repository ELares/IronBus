// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-message and per-stream message TTL: the pure, IO-free deadline policy (V2-M4, #549).
//!
//! A TTL turns a duration ("expire 30s after this record was produced") into a durable, absolute
//! [`Deadline`] that a reader can check against the clock seam. The decision layer lives here, pure
//! and allocation-free; applying it (skipping an expired record on read, reclaiming it at reap,
//! routing it to a dead-letter exchange) is the storage/server's job.
//!
//! ## Why the deadline is wall-clock-anchored, not raw-monotonic
//! IronBus exposes two clocks through the I6 seam ([`crate::clock::Clock`]): a monotonic clock for
//! RUNTIME durations (lease deadlines, queue sojourn) that resets its origin every process start,
//! and a wall clock for record timestamps that is durable across a restart. A per-message TTL must
//! survive a restart — a 1-hour TTL on a record produced before a reboot must still expire an hour
//! after it was produced — so its deadline is anchored to the record's DURABLE producer
//! `timestamp_ms` (`timestamp_ms + ttl_ms`) and checked against the wall clock, exactly as the
//! existing per-stream max-age retention already ages out old segments. Both reads go through the
//! clock SEAM (never a raw `SystemTime::now`), so a [`ManualClock`](crate::clock::ManualClock) test
//! drives expiry deterministically with no wall-clock flake: "expiry is a deadline checked against
//! the seam, not a host-clock read." The monotonic seam still governs every NON-durable deadline;
//! it cannot anchor a durable one because its origin is meaningless across runs.
//!
//! ## Granularity (the honest bound)
//! Expiry is enforced at TWO bounded points, never an unbounded per-message timer:
//! - ON READ: an expired record is SKIPPED (never delivered) — checked once, O(1), at deliver time.
//! - AT REAP: an expired record's BYTES are reclaimed by the existing whole-segment retention reap
//!   ([`reap`](../../ironbus_storage/log/struct.Log.html#method.reap)), at SEGMENT granularity. A
//!   record stays on disk (invisible, skipped on read) until its whole segment ages/sizes/counts
//!   out, exactly like a compaction-superseded record. There is NO per-message timer wheel.

/// A per-message time-to-live: a duration after the record's producer timestamp, in milliseconds.
///
/// `Ttl(0)` is reserved as "no TTL" so an absent/zero TTL is byte-identical to today (the record
/// never expires); a real TTL is always `>= 1` ms. Construct with [`Ttl::from_millis`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Ttl(u64);

impl Ttl {
    /// The "no TTL" sentinel: a record with this TTL never expires (today's behavior).
    pub const NONE: Ttl = Ttl(0);

    /// Wraps a duration in milliseconds as a [`Ttl`]. A `0` is [`Ttl::NONE`] (never expires).
    #[must_use]
    pub const fn from_millis(millis: u64) -> Ttl {
        Ttl(millis)
    }

    /// The TTL duration in milliseconds (`0` means [`Ttl::NONE`], never expires).
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Whether this is the "never expires" sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// The absolute expiry [`Deadline`] for a record produced at wall-clock `timestamp_ms`, or
    /// `None` for [`Ttl::NONE`] (no deadline, never expires). The deadline saturates at `u64::MAX`
    /// so a TTL near the end of the clock space never wraps backwards into an immediate expiry.
    #[must_use]
    pub const fn deadline_from(self, timestamp_ms: u64) -> Option<Deadline> {
        if self.0 == 0 {
            None
        } else {
            Some(Deadline(timestamp_ms.saturating_add(self.0)))
        }
    }

    /// Picks the EFFECTIVE TTL under lower-wins precedence (#549): the smaller of a per-message TTL
    /// and a per-stream default max-age, treating [`Ttl::NONE`] as "no bound" (`+infinity`), so the
    /// tighter of the two wins and either alone applies when the other is absent. With both absent
    /// the result is [`Ttl::NONE`] (never expires).
    #[must_use]
    pub const fn lower_of(per_message: Ttl, per_stream: Ttl) -> Ttl {
        match (per_message.0, per_stream.0) {
            (0, 0) => Ttl::NONE,
            (0, s) => Ttl(s),
            (m, 0) => Ttl(m),
            (m, s) if m <= s => Ttl(m),
            (_, s) => Ttl(s),
        }
    }
}

/// An absolute expiry instant: wall-clock milliseconds since the Unix epoch, past which a record is
/// expired. Derived from a [`Ttl`] and the record's durable producer `timestamp_ms` via
/// [`Ttl::deadline_from`], so it survives a restart (a runtime monotonic instant could not).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Deadline(u64);

impl Deadline {
    /// Wraps an absolute Unix-millis instant as a [`Deadline`].
    #[must_use]
    pub const fn at_unix_millis(unix_millis: u64) -> Deadline {
        Deadline(unix_millis)
    }

    /// The absolute deadline as Unix milliseconds.
    #[must_use]
    pub const fn as_unix_millis(self) -> u64 {
        self.0
    }

    /// Whether this deadline has PASSED at wall-clock `now_unix_millis` (read from the clock seam).
    ///
    /// A record is expired the instant the wall clock reaches OR exceeds its deadline (`now >=
    /// deadline`), matching the existing age-retention bound's `<` over `max_timestamp_ms +
    /// max_age_ms < now` once rearranged. A record produced exactly `ttl` ms ago is expired.
    #[must_use]
    pub const fn is_expired_at(self, now_unix_millis: u64) -> bool {
        now_unix_millis >= self.0
    }
}

/// Whether a record produced at `timestamp_ms` with `ttl` is expired at wall-clock `now_unix_millis`.
///
/// A convenience over [`Ttl::deadline_from`] + [`Deadline::is_expired_at`]: [`Ttl::NONE`] is never
/// expired (returns `false`), so a no-TTL record is byte-identically unaffected.
#[must_use]
pub const fn is_expired(ttl: Ttl, timestamp_ms: u64, now_unix_millis: u64) -> bool {
    match ttl.deadline_from(timestamp_ms) {
        Some(deadline) => deadline.is_expired_at(now_unix_millis),
        None => false,
    }
}

/// The 4-byte magic that opens a per-message TTL header prefix inside a record's `headers` blob.
/// A `headers` blob that does NOT begin with this carries no per-message TTL, so a record produced
/// without a TTL is byte-identical to today (the prefix is simply absent).
pub const TTL_HEADER_MAGIC: [u8; 4] = *b"TTL1";

/// The fixed size of the per-message TTL header prefix: `magic`(4) + `ttl_ms`(8).
pub const TTL_HEADER_LEN: usize = 4 + 8;

/// Prepends a per-message TTL header to `original_headers`, producing the `headers` blob to store.
///
/// The layout (little-endian) is `[magic(4)][ttl_ms(8)]` followed by the original headers verbatim,
/// so a reader strips the fixed prefix to recover BOTH the TTL and the original headers. A
/// [`Ttl::NONE`] adds NO prefix (returns the original headers unchanged), keeping a no-TTL produce
/// byte-identical to today. The original headers are never inspected, so any blob is preserved.
#[must_use]
pub fn encode_ttl_headers(ttl: Ttl, original_headers: &[u8]) -> Vec<u8> {
    if ttl.is_none() {
        return original_headers.to_vec();
    }
    let mut out = Vec::with_capacity(TTL_HEADER_LEN + original_headers.len());
    out.extend_from_slice(&TTL_HEADER_MAGIC);
    out.extend_from_slice(&ttl.as_millis().to_le_bytes());
    out.extend_from_slice(original_headers);
    out
}

/// Splits a stored `headers` blob into its per-message [`Ttl`] (if a TTL prefix is present) and the
/// ORIGINAL headers. A blob that does not begin with [`TTL_HEADER_MAGIC`], or one too short to hold
/// the fixed prefix, carries no TTL: it is returned whole as the original headers with [`Ttl::NONE`]
/// (so a foreign or older record reads exactly as today). The original headers are borrowed from the
/// input, never copied, so the hot read path stays allocation-free.
#[must_use]
pub fn decode_ttl_headers(headers: &[u8]) -> (Ttl, &[u8]) {
    if headers.len() < TTL_HEADER_LEN || headers[0..4] != TTL_HEADER_MAGIC {
        return (Ttl::NONE, headers);
    }
    // The 8 TTL bytes follow the 4-byte magic; the slice is known long enough by the length guard.
    let mut ms = [0u8; 8];
    ms.copy_from_slice(&headers[4..TTL_HEADER_LEN]);
    (
        Ttl::from_millis(u64::from_le_bytes(ms)),
        &headers[TTL_HEADER_LEN..],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_never_expires() {
        assert!(Ttl::NONE.is_none());
        assert_eq!(Ttl::NONE.deadline_from(0), None);
        assert_eq!(Ttl::NONE.deadline_from(u64::MAX), None);
        // No TTL = never expires, regardless of how far the clock advances.
        assert!(!is_expired(Ttl::NONE, 0, u64::MAX));
    }

    #[test]
    fn from_zero_is_none() {
        assert_eq!(Ttl::from_millis(0), Ttl::NONE);
        assert!(Ttl::from_millis(0).is_none());
    }

    #[test]
    fn deadline_is_timestamp_plus_ttl() {
        let ttl = Ttl::from_millis(1_000);
        assert_eq!(
            ttl.deadline_from(100),
            Some(Deadline::at_unix_millis(1_100))
        );
        assert_eq!(ttl.as_millis(), 1_000);
    }

    #[test]
    fn deadline_saturates_at_the_clock_ceiling() {
        let ttl = Ttl::from_millis(10);
        assert_eq!(
            ttl.deadline_from(u64::MAX),
            Some(Deadline::at_unix_millis(u64::MAX)),
            "a TTL near the end of the clock space saturates, never wraps to an early expiry"
        );
        assert!(!is_expired(ttl, u64::MAX, u64::MAX - 1));
    }

    #[test]
    fn expiry_is_at_or_past_the_deadline() {
        let ttl = Ttl::from_millis(1_000);
        // Produced at 100, so the deadline is 1_100.
        assert!(!is_expired(ttl, 100, 1_099), "before the deadline: live");
        assert!(is_expired(ttl, 100, 1_100), "at the deadline: expired");
        assert!(is_expired(ttl, 100, 1_101), "past the deadline: expired");
    }

    #[test]
    fn lower_of_is_lower_wins_with_none_as_infinity() {
        let m = Ttl::from_millis(500);
        let s = Ttl::from_millis(1_000);
        // The tighter (smaller) of two real TTLs wins, regardless of order.
        assert_eq!(Ttl::lower_of(m, s), m);
        assert_eq!(Ttl::lower_of(s, m), m);
        // Either alone applies when the other is absent (NONE = +infinity).
        assert_eq!(Ttl::lower_of(m, Ttl::NONE), m);
        assert_eq!(Ttl::lower_of(Ttl::NONE, s), s);
        // Both absent: never expires.
        assert_eq!(Ttl::lower_of(Ttl::NONE, Ttl::NONE), Ttl::NONE);
        // Equal TTLs: that value.
        assert_eq!(Ttl::lower_of(m, m), m);
    }

    #[test]
    fn deadline_is_expired_at_boundary() {
        let d = Deadline::at_unix_millis(50);
        assert!(!d.is_expired_at(49));
        assert!(d.is_expired_at(50));
        assert!(d.is_expired_at(51));
        assert_eq!(d.as_unix_millis(), 50);
    }

    #[test]
    fn ttl_headers_round_trip() {
        let ttl = Ttl::from_millis(30_000);
        let blob = encode_ttl_headers(ttl, b"user-headers");
        assert_eq!(&blob[0..4], &TTL_HEADER_MAGIC);
        let (decoded, original) = decode_ttl_headers(&blob);
        assert_eq!(decoded, ttl);
        assert_eq!(original, b"user-headers");
    }

    #[test]
    fn no_ttl_header_is_byte_identical() {
        // A NONE TTL adds no prefix at all: the stored blob IS the original headers.
        let blob = encode_ttl_headers(Ttl::NONE, b"user-headers");
        assert_eq!(blob, b"user-headers");
        // Decoding a blob with no TTL prefix returns it whole with NONE.
        let (decoded, original) = decode_ttl_headers(b"user-headers");
        assert_eq!(decoded, Ttl::NONE);
        assert_eq!(original, b"user-headers");
    }

    #[test]
    fn decode_tolerates_a_foreign_or_short_blob() {
        // A blob shorter than the fixed prefix carries no TTL.
        let (ttl, original) = decode_ttl_headers(b"TTL");
        assert_eq!(ttl, Ttl::NONE);
        assert_eq!(original, b"TTL");
        // Wrong magic of the right length carries no TTL and is returned whole.
        let (ttl, original) = decode_ttl_headers(b"XXXX12345678extra");
        assert_eq!(ttl, Ttl::NONE);
        assert_eq!(original, b"XXXX12345678extra");
    }

    #[test]
    fn empty_original_headers_round_trip() {
        let blob = encode_ttl_headers(Ttl::from_millis(5), b"");
        let (ttl, original) = decode_ttl_headers(&blob);
        assert_eq!(ttl, Ttl::from_millis(5));
        assert!(original.is_empty());
    }
}
