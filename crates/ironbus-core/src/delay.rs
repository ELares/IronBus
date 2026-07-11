// SPDX-License-Identifier: MIT OR Apache-2.0
//! Arbitrary-timestamp SCHEDULED/DELAYED messages: the pure, IO-free due-time policy (V2-M4, #555).
//!
//! A delayed message is INVISIBLE to queue consumers until its due-time, then delivered normally.
//! IronBus adopts the `RocketMQ` 5.x ARBITRARY-delay design (any due-time, not fixed delay levels),
//! made CLOCK-SKEW-SAFE by two first-principles decisions:
//!
//! 1. **The broker's clock anchors the due-time, never the producer's.** The wire carries the
//!    producer's request as a RELATIVE duration (`DLY1` + `delay_ms`, a duration is skew-free by
//!    construction), and the broker RESOLVES it against ITS OWN wall-clock seam at append time into
//!    an absolute stored due-instant (`DUE1` + `due_unix_ms`). A producer with a skewed clock can
//!    request a wrong-length delay, but it can never place a record's due-time before the broker
//!    observed its append, and it can never perturb another record's due-time.
//! 2. **Release order among due records is LOG SEQUENCE, never a wall-clock sort.** The delivery
//!    scan HOLDS at the earliest un-due record (it never advances the group cursor past it), so
//!    records release strictly in append order — FIFO-with-delays. A later-sequence record with an
//!    earlier due-time waits for the earlier-sequence record ahead of it (the honest head-of-line
//!    property of the v1 design; an out-of-order-release due-index sidecar is a possible follow-up).
//!    Ordering is therefore decided by the one total order the log already has, and NO wall-clock
//!    comparison between two records' timestamps ever decides which delivers first.
//!
//! ## Header carriage (the TTL1 precedent, #549)
//! The due-time rides inside the record's `headers` blob as a fixed 12-byte magic-prefixed block,
//! exactly like the per-message TTL prefix ([`crate::ttl::TTL_HEADER_MAGIC`]) — no record-format
//! change, no new frame field, and a record without the prefix is byte-identical to today. The
//! canonical composition order when BOTH prefixes are present is `TTL1` FIRST, then `DLY1`/`DUE1`,
//! then the original headers (encode delay first, then TTL around it); the decoders here accept the
//! block at position 0 or immediately after a leading TTL block.
//!
//! ## Two magics, one block shape
//! - [`DELAY_HEADER_MAGIC`] (`DLY1`): the WIRE REQUEST — `delay_ms`, a duration RELATIVE to the
//!   broker's append instant. Producers attach this; it never reaches storage.
//! - [`DUE_HEADER_MAGIC`] (`DUE1`): the STORED RESOLUTION — `due_unix_ms`, ABSOLUTE broker-wall
//!   Unix milliseconds. ONLY the broker mints `DUE1`: the produce chokepoints rewrite `DLY1 ->
//!   DUE1` in place (same length), and a WIRE headers blob carrying a raw `DUE1` is REJECTED
//!   fail-closed ([`DelayHeaderError::DueInjected`]) — accepting it would bypass both the
//!   max-delay bound and the broker-clock anchor (a producer could self-schedule `u64::MAX`,
//!   stalling every group on the stream forever). Replication/mirror/DLQ paths copy already-minted
//!   stored frames verbatim BELOW the resolution seam, so every replica holds the SAME resolved
//!   due-instant and re-resolution is impossible.
//!
//! Anchoring to the broker wall clock (not the runtime monotonic clock) is what makes the due-time
//! DURABLE: a record due in an hour, produced before a reboot, is still due at the same wall instant
//! after it — the same argument as the TTL deadline ([`crate::ttl`]). Both reads go through the
//! clock SEAM ([`crate::clock::Clock::now_unix_millis`]), never a raw `SystemTime::now`, so a
//! [`ManualClock`](crate::clock::ManualClock) drives due-ness deterministically in tests.
//!
//! ## Scope (delivery-visibility gate, not a re-ordering engine)
//! The gate applies to QUEUE delivery (the work-group claim/deliver scans). A Tier-S / streaming
//! reader is a LOG reader (replay semantics): it sees a delayed record immediately, with its `DUE1`
//! block intact in the delivered headers for application-level handling — the same stance as
//! retention and compaction, which are also log-level views. TTL composes lower-wins as usual: a
//! record whose TTL deadline passes before its due-time EXPIRES un-delivered (the TTL clock starts
//! at the record's producer `timestamp_ms`, unchanged by the delay).

/// A requested delivery delay: a duration in milliseconds RELATIVE to the broker's append instant.
///
/// `Delay(0)` is reserved as "no delay" so an absent/zero delay is byte-identical to today (the
/// record is immediately visible); a real delay is always `>= 1` ms. Construct with
/// [`Delay::from_millis`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Delay(u64);

impl Delay {
    /// The "no delay" sentinel: a record with this delay is immediately visible (today's behavior).
    pub const NONE: Delay = Delay(0);

    /// Wraps a duration in milliseconds as a [`Delay`]. A `0` is [`Delay::NONE`] (no delay).
    #[must_use]
    pub const fn from_millis(millis: u64) -> Delay {
        Delay(millis)
    }

    /// The requested delay in milliseconds (`0` means [`Delay::NONE`], no delay).
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Whether this is the "no delay" sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// A rejected delay request (#555): the requested delay exceeds the broker's configured maximum.
/// An unbounded delay would pin retention arbitrarily far into the future, so the bound is
/// enforced fail-closed at the produce boundary (the publish is REFUSED, never silently clamped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelayTooLong {
    /// The delay the producer requested, in milliseconds.
    pub requested_ms: u64,
    /// The broker's configured maximum delay, in milliseconds.
    pub max_ms: u64,
}

/// A rejected delayed-delivery header at the produce boundary (#555): the two fail-closed refusals
/// [`resolve_delay_headers`] can return. Both refuse the publish with nothing appended; neither is
/// ever a silent clamp or a silent pass-through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelayHeaderError {
    /// The `DLY1` request's delay exceeds the broker's configured maximum ([`DelayTooLong`]): an
    /// unbounded schedule would pin retention arbitrarily far into the future.
    TooLong(DelayTooLong),
    /// The wire headers carried a raw `DUE1` block — a BROKER-MINTED stored form the wire must
    /// never carry (#555 injection hardening). Only the broker's resolution seam mints `DUE1`; a
    /// producer-supplied absolute due-instant would bypass BOTH the `max_delay_ms` bound (the block
    /// is not a `DLY1` request, so the bound is never consulted — `due_unix_ms = u64::MAX` would
    /// head-of-line-stall every group on the stream forever and pin retention unboundedly) AND the
    /// broker-clock anchoring (the whole clock-skew-safety design). Rejected fail-closed: a wire
    /// produce must carry a `DLY1` relative request, never a `DUE1`. Legitimate already-minted
    /// `DUE1` records (DLQ moves/redrive, replication followers, geo mirror-apply) re-inject via
    /// verbatim `Log::append`-level copies BELOW this seam and are untouched by this rejection.
    DueInjected {
        /// The absolute due-instant the wire tried to smuggle in, in Unix milliseconds.
        due_unix_ms: u64,
    },
}

/// The 4-byte magic that opens a WIRE-REQUEST delay prefix inside a publish's `headers` blob:
/// `delay_ms`, a duration RELATIVE to the broker's append instant. A producer attaches this; the
/// broker resolves it to a [`DUE_HEADER_MAGIC`] block (same length, in place) before storing, so
/// `DLY1` never reaches disk through a broker produce path. A `headers` blob that does not begin
/// with this (directly or after a leading TTL block) carries no delay request.
pub const DELAY_HEADER_MAGIC: [u8; 4] = *b"DLY1";

/// The 4-byte magic that opens a STORED, broker-RESOLVED due-time prefix inside a record's
/// `headers` blob: `due_unix_ms`, ABSOLUTE broker-wall Unix milliseconds assigned by the broker's
/// clock seam at append time. The delivery scan compares this against the wall seam to decide
/// visibility; release ORDER among due records is log sequence (the scan holds at the earliest
/// un-due record).
pub const DUE_HEADER_MAGIC: [u8; 4] = *b"DUE1";

/// The fixed size of a delay/due header prefix: `magic`(4) + `millis`(8). The wire request and the
/// stored resolution share this length, so the broker's `DLY1 -> DUE1` rewrite is an in-place patch
/// that never moves the original headers.
pub const DELAY_HEADER_LEN: usize = 4 + 8;

/// The byte offset at which a delay/due block may sit inside `headers`: `0`, or — when the blob
/// opens with a per-message TTL block (#549, the canonical `TTL1`-first composition) — immediately
/// after that TTL block. Returns `0` when no TTL block leads the blob.
fn delay_block_offset(headers: &[u8]) -> usize {
    use crate::ttl::{TTL_HEADER_LEN, TTL_HEADER_MAGIC};
    if headers.len() >= TTL_HEADER_LEN && headers[0..4] == TTL_HEADER_MAGIC {
        TTL_HEADER_LEN
    } else {
        0
    }
}

/// Reads the 8-byte little-endian millis field of the delay/due block at `at`, if `headers` holds a
/// full block opened by `magic` there.
fn block_millis(headers: &[u8], at: usize, magic: [u8; 4]) -> Option<u64> {
    let block = headers.get(at..at + DELAY_HEADER_LEN)?;
    if block[0..4] != magic {
        return None;
    }
    let mut ms = [0u8; 8];
    ms.copy_from_slice(&block[4..DELAY_HEADER_LEN]);
    Some(u64::from_le_bytes(ms))
}

/// Prepends a WIRE-REQUEST delay header to `original_headers`, producing the `headers` blob a
/// producer publishes. The layout (little-endian) is `[DLY1(4)][delay_ms(8)]` followed by the
/// original headers verbatim. A [`Delay::NONE`] adds NO prefix (returns the original unchanged), so
/// a no-delay produce is byte-identical to today. To compose with a per-message TTL, apply THIS
/// first and then [`crate::ttl::encode_ttl_headers`] around the result (canonical order: `TTL1`
/// outermost, then `DLY1`).
#[must_use]
pub fn encode_delay_headers(delay: Delay, original_headers: &[u8]) -> Vec<u8> {
    if delay.is_none() {
        return original_headers.to_vec();
    }
    let mut out = Vec::with_capacity(DELAY_HEADER_LEN + original_headers.len());
    out.extend_from_slice(&DELAY_HEADER_MAGIC);
    out.extend_from_slice(&delay.as_millis().to_le_bytes());
    out.extend_from_slice(original_headers);
    out
}

/// RESOLVES a wire-request delay in `headers` against the BROKER's wall clock at append time
/// (#555): the clock-skew-safety chokepoint every WIRE produce path funnels through. Its callers
/// are exactly the two produce chokepoints (the engine's default-stream and named-stream seams);
/// every legitimate already-resolved record (a DLQ move/redrive, a replication follower, a geo
/// mirror-apply) re-injects via verbatim `Log::append`-level frame copies BELOW this seam and never
/// reaches it — which is what makes the `DUE1` rejection below sound.
///
/// - No `DLY1` and no `DUE1` block (directly or after a leading TTL block): returns `Ok(None)` —
///   the untouched non-delayed fast path, zero allocation.
/// - A `DLY1` block whose `delay_ms` exceeds `max_delay_ms` (when `max_delay_ms > 0`; `0` means
///   unbounded): returns `Err(DelayHeaderError::TooLong)` — the fail-closed produce rejection, so
///   an unbounded schedule can never pin retention. The bound is on the REQUESTED duration, so a
///   skewed producer cannot dodge it.
/// - A raw `DUE1` block: returns `Err(DelayHeaderError::DueInjected)` — fail-closed. `DUE1` is the
///   BROKER-MINTED stored form; accepting it from the wire would bypass both the `max_delay_ms`
///   bound and the broker-clock anchoring (a producer could self-schedule `due_unix_ms = u64::MAX`,
///   head-of-line-stalling every group on the stream forever and pinning retention unboundedly).
///   A wire produce must carry a `DLY1` relative request, never a `DUE1`.
/// - An accepted `DLY1`: returns `Ok(Some(patched))`, a copy of `headers` with the block rewritten
///   IN PLACE (same length) to `[DUE1(4)][due_unix_ms(8)]`, where `due_unix_ms = now_unix_ms +
///   delay_ms` (saturating, so a delay near the clock ceiling never wraps into the past). A
///   `delay_ms` of `0` resolves to "due now" (immediately visible), preserving the request shape
///   without a special case.
///
/// `now_unix_ms` MUST come from the broker's clock seam ([`crate::clock::Clock::now_unix_millis`]),
/// never from any producer-supplied field: the record's `timestamp_ms` is producer-controlled on
/// the wire, so anchoring to it would let a skewed producer shift its own visibility instant.
///
/// # Errors
/// [`DelayHeaderError::TooLong`] when the requested delay exceeds a non-zero `max_delay_ms`;
/// [`DelayHeaderError::DueInjected`] when the wire headers carry a broker-only `DUE1` block.
pub fn resolve_delay_headers(
    headers: &[u8],
    now_unix_ms: u64,
    max_delay_ms: u64,
) -> Result<Option<Vec<u8>>, DelayHeaderError> {
    let at = delay_block_offset(headers);
    let Some(delay_ms) = block_millis(headers, at, DELAY_HEADER_MAGIC) else {
        // Not a delay REQUEST. A raw broker-only `DUE1` here is a wire INJECTION (the bypass of
        // both the max-delay bound and the broker-clock anchor): reject fail-closed. Anything else
        // is the untouched non-delayed fast path.
        if let Some(due_unix_ms) = block_millis(headers, at, DUE_HEADER_MAGIC) {
            return Err(DelayHeaderError::DueInjected { due_unix_ms });
        }
        return Ok(None);
    };
    if max_delay_ms != 0 && delay_ms > max_delay_ms {
        return Err(DelayHeaderError::TooLong(DelayTooLong {
            requested_ms: delay_ms,
            max_ms: max_delay_ms,
        }));
    }
    let due_unix_ms = now_unix_ms.saturating_add(delay_ms);
    let mut patched = headers.to_vec();
    patched[at..at + 4].copy_from_slice(&DUE_HEADER_MAGIC);
    patched[at + 4..at + DELAY_HEADER_LEN].copy_from_slice(&due_unix_ms.to_le_bytes());
    Ok(Some(patched))
}

/// The STORED broker-resolved due-instant of a record, read from its `headers` blob: absolute
/// broker-wall Unix milliseconds, or `None` for a record with no `DUE1` block (immediately visible,
/// today's behavior — the non-delayed fast path is one 4-byte compare). Accepts the block at
/// position 0 or immediately after a leading TTL block (the canonical composition).
#[must_use]
pub fn decode_due_headers(headers: &[u8]) -> Option<u64> {
    block_millis(headers, delay_block_offset(headers), DUE_HEADER_MAGIC)
}

/// Whether a record with stored `headers` is still UN-DUE (invisible to queue delivery) at
/// wall-clock `now_unix_ms` from the clock seam.
///
/// A record is due the instant the wall clock reaches OR exceeds its due-instant (`now >= due`),
/// the same at-the-boundary convention as TTL expiry ([`crate::ttl::Deadline::is_expired_at`]); a
/// record with no `DUE1` block is never un-due. The delivery scan HOLDS at (never advances the
/// group cursor past) the first un-due record, so due records release in log-sequence order.
#[must_use]
pub fn is_undue(headers: &[u8], now_unix_ms: u64) -> bool {
    match decode_due_headers(headers) {
        Some(due_unix_ms) => now_unix_ms < due_unix_ms,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ttl::{encode_ttl_headers, Ttl};

    #[test]
    fn none_encodes_no_prefix() {
        assert!(Delay::NONE.is_none());
        assert_eq!(Delay::from_millis(0), Delay::NONE);
        let blob = encode_delay_headers(Delay::NONE, b"user-headers");
        assert_eq!(blob, b"user-headers");
    }

    #[test]
    fn resolve_rewrites_the_request_to_an_absolute_broker_due_instant() {
        let blob = encode_delay_headers(Delay::from_millis(500), b"user-headers");
        assert_eq!(&blob[0..4], &DELAY_HEADER_MAGIC);
        let patched = resolve_delay_headers(&blob, 10_000, 0).unwrap().unwrap();
        // Same length, magic flipped to DUE1, millis now the ABSOLUTE broker instant, original
        // headers untouched.
        assert_eq!(patched.len(), blob.len());
        assert_eq!(&patched[0..4], &DUE_HEADER_MAGIC);
        assert_eq!(decode_due_headers(&patched), Some(10_500));
        assert_eq!(&patched[DELAY_HEADER_LEN..], b"user-headers");
    }

    #[test]
    fn a_wire_due1_block_is_rejected_never_passed_through() {
        // The #555 injection hardening: `DUE1` is BROKER-MINTED — a wire blob carrying one would
        // bypass both the max-delay bound (it is not a `DLY1` request, so the bound is never
        // consulted) and the broker-clock anchor. It is rejected fail-closed at ANY bound setting,
        // including unbounded (`max = 0`): the anchor bypass is independent of the bound.
        let mut blob = Vec::new();
        blob.extend_from_slice(&DUE_HEADER_MAGIC);
        blob.extend_from_slice(&u64::MAX.to_le_bytes());
        blob.extend_from_slice(b"orig");
        for max in [0u64, 500] {
            assert_eq!(
                resolve_delay_headers(&blob, 10_000, max),
                Err(DelayHeaderError::DueInjected {
                    due_unix_ms: u64::MAX
                }),
                "a raw wire DUE1 is rejected (max = {max})"
            );
        }
        // The same injection hidden behind a canonical leading TTL block is also caught.
        let ttl_wrapped = encode_ttl_headers(Ttl::from_millis(9_000), &blob);
        assert_eq!(
            resolve_delay_headers(&ttl_wrapped, 10_000, 0),
            Err(DelayHeaderError::DueInjected {
                due_unix_ms: u64::MAX
            })
        );
        // A block too short to be a full DUE1 is NOT an injection (opaque user bytes, the same
        // tolerance the TTL decode has): passed through untouched.
        assert_eq!(resolve_delay_headers(b"DUE1", 10_000, 0).unwrap(), None);
    }

    #[test]
    fn a_broker_minted_due1_is_honored_by_the_read_path() {
        // The read seam is unchanged by the injection rejection: a broker-RESOLVED blob (minted by
        // this module's own rewrite — the only legitimate source) still decodes and gates
        // visibility. Internal re-injection paths (DLQ moves/redrive, replication, mirror-apply)
        // copy such frames verbatim below the resolution seam, so they never re-enter
        // `resolve_delay_headers` — pinned at the engine level by the DLQ-copy test.
        let blob = encode_delay_headers(Delay::from_millis(500), b"h");
        let patched = resolve_delay_headers(&blob, 10_000, 0).unwrap().unwrap();
        assert_eq!(decode_due_headers(&patched), Some(10_500));
        assert!(is_undue(&patched, 10_499));
        assert!(!is_undue(&patched, 10_500));
    }

    #[test]
    fn resolve_leaves_a_plain_blob_untouched() {
        assert_eq!(resolve_delay_headers(b"", 5, 0).unwrap(), None);
        assert_eq!(resolve_delay_headers(b"user-headers", 5, 0).unwrap(), None);
        // Too short to hold a block, even though it starts with the magic.
        assert_eq!(resolve_delay_headers(b"DLY1", 5, 0).unwrap(), None);
        // Wrong magic of the right length.
        assert_eq!(
            resolve_delay_headers(b"XXXX12345678extra", 5, 0).unwrap(),
            None
        );
    }

    #[test]
    fn resolve_rejects_a_delay_over_the_configured_max() {
        let blob = encode_delay_headers(Delay::from_millis(501), b"");
        assert_eq!(
            resolve_delay_headers(&blob, 0, 500),
            Err(DelayHeaderError::TooLong(DelayTooLong {
                requested_ms: 501,
                max_ms: 500,
            }))
        );
        // Exactly at the max is accepted (the bound is inclusive).
        let at_max = encode_delay_headers(Delay::from_millis(500), b"");
        assert!(resolve_delay_headers(&at_max, 0, 500).unwrap().is_some());
        // A zero max is UNBOUNDED (consistent with the other `0 = no constraint` knobs).
        assert!(resolve_delay_headers(&blob, 0, 0).unwrap().is_some());
    }

    #[test]
    fn resolve_saturates_at_the_clock_ceiling() {
        let blob = encode_delay_headers(Delay::from_millis(10), b"");
        let patched = resolve_delay_headers(&blob, u64::MAX - 3, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_due_headers(&patched),
            Some(u64::MAX),
            "a delay near the end of the clock space saturates, never wraps into the past"
        );
    }

    #[test]
    fn undue_is_strictly_before_the_due_instant() {
        let blob = encode_delay_headers(Delay::from_millis(100), b"");
        let patched = resolve_delay_headers(&blob, 1_000, 0).unwrap().unwrap();
        assert!(is_undue(&patched, 1_099), "before the due instant: held");
        assert!(!is_undue(&patched, 1_100), "at the due instant: due");
        assert!(!is_undue(&patched, 1_101), "past the due instant: due");
        // A record with no DUE1 block is never un-due.
        assert!(!is_undue(b"user-headers", 0));
        // An UNRESOLVED wire request is not a stored due-time: never un-due on read. (A broker
        // produce path always resolves; this pins the strictness for a hand-rolled blob.)
        assert!(!is_undue(&blob, 0));
    }

    #[test]
    fn composes_after_a_leading_ttl_block() {
        // Canonical order: TTL1 outermost, then DLY1, then the original headers.
        let inner = encode_delay_headers(Delay::from_millis(250), b"orig");
        let blob = encode_ttl_headers(Ttl::from_millis(9_000), &inner);
        // The TTL decode still sees its block at position 0...
        let (ttl, rest) = crate::ttl::decode_ttl_headers(&blob);
        assert_eq!(ttl, Ttl::from_millis(9_000));
        assert_eq!(&rest[0..4], &DELAY_HEADER_MAGIC);
        // ...and the delay resolves in place AFTER it, leaving the TTL block untouched.
        let patched = resolve_delay_headers(&blob, 2_000, 0).unwrap().unwrap();
        let (ttl, rest) = crate::ttl::decode_ttl_headers(&patched);
        assert_eq!(ttl, Ttl::from_millis(9_000));
        assert_eq!(&rest[0..4], &DUE_HEADER_MAGIC);
        assert_eq!(decode_due_headers(&patched), Some(2_250));
        assert!(is_undue(&patched, 2_249));
        assert!(!is_undue(&patched, 2_250));
    }

    #[test]
    fn a_zero_delay_request_resolves_to_due_now() {
        // A producer may send delay 0 explicitly; it resolves to "due at the append instant"
        // (immediately visible), preserving the request shape without a special case.
        let mut blob = Vec::new();
        blob.extend_from_slice(&DELAY_HEADER_MAGIC);
        blob.extend_from_slice(&0u64.to_le_bytes());
        let patched = resolve_delay_headers(&blob, 777, 0).unwrap().unwrap();
        assert_eq!(decode_due_headers(&patched), Some(777));
        assert!(!is_undue(&patched, 777));
    }

    #[test]
    fn empty_original_headers_round_trip() {
        let blob = encode_delay_headers(Delay::from_millis(5), b"");
        assert_eq!(blob.len(), DELAY_HEADER_LEN);
        let patched = resolve_delay_headers(&blob, 100, 0).unwrap().unwrap();
        assert_eq!(decode_due_headers(&patched), Some(105));
    }
}
