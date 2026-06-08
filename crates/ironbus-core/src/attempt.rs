// SPDX-License-Identifier: MIT OR Apache-2.0
//! The durable per-message attempt-count snapshot: how a poison message's `MaxDeliver`
//! count survives an unclean restart (#358).
//!
//! The per-message delivery-attempt count lives in the [`LeaseTable`](crate::lease::LeaseTable)
//! as each in-flight lease's `deliveries`. That table is rebuilt empty on restart, so without a
//! durable record a redelivered message resets to attempt 1, and a poison record on an
//! edge device that reboots often could redeliver past its `MaxDeliver` cap and NEVER reach the
//! dead-letter queue. This module is the IO-free codec that makes the count durable: a compact,
//! CRC-protected snapshot of the `{offset -> attempt_count}` pairs of the currently-in-flight
//! (delivered but unacked) entries, which the server persists alongside the cursor checkpoint and
//! reloads at open so the lease table resumes each redelivery at its true attempt number.
//!
//! The snapshot is bounded by the same `max_in_flight` window that bounds the lease table itself
//! (one pair per in-flight offset), so it never grows unbounded. It reuses the cursor snapshot's
//! durability discipline: a 1-byte [`SNAPSHOT_VERSION`], the run count, the pairs, then a trailing
//! crc32c over everything before it. A torn or corrupt snapshot is rejected with a typed
//! [`AttemptSnapshotError`] so the caller can fall back to no carried counts (every in-flight
//! message resumes at attempt 1, the pre-#358 behavior) rather than trust bad state.

/// The on-disk snapshot format version for an attempt-count map (see [`encode_attempt_snapshot`]).
const SNAPSHOT_VERSION: u8 = 1;

/// The minimum length in bytes of an [`encode_attempt_snapshot`] output: the fixed header (a
/// 1-byte version plus the 4-byte pair count) and the trailing 4-byte crc32c, with no pairs. A
/// payload shorter than this cannot be a snapshot.
pub const ATTEMPT_SNAPSHOT_MIN_LEN: usize = 1 + 4 + 4;

/// The bytes one `(offset: u64, attempt: u32)` pair occupies in a snapshot.
const PAIR_LEN: usize = 8 + 4;

/// Reads a little-endian `u64` at `pos`; the caller has bounds-checked the slice length.
fn read_u64(buf: &[u8], pos: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[pos..pos + 8]);
    u64::from_le_bytes(b)
}

/// Reads a little-endian `u32` at `pos`; the caller has bounds-checked the slice length.
fn read_u32(buf: &[u8], pos: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[pos..pos + 4]);
    u32::from_le_bytes(b)
}

/// Encodes a durable snapshot of the in-flight attempt counts (#358): a 1-byte version, the pair
/// count, the `(offset, attempt)` pairs in ascending-offset order, then a trailing crc32c over
/// everything before it. The pairs MUST be sorted by offset and have distinct offsets (the lease
/// table keys by offset, so it always is); a zero `attempt` carries no information (a fresh
/// delivery resumes at 1 anyway), so the caller should omit it, but the codec does not reject it.
///
/// The bytes are appended to `out` (the storage layer frames the snapshot after other bytes), so
/// the caller may pass a non-empty buffer; the appended suffix decodes on its own.
pub fn encode_attempt_snapshot(pairs: &[(u64, u32)], out: &mut Vec<u8>) {
    let start = out.len();
    out.push(SNAPSHOT_VERSION);
    // The pair count is bounded by max_in_flight (a u32 knob), so it always fits a u32; saturate
    // rather than panic if a future caller ever exceeds it (decode then reads only what fits).
    let count = u32::try_from(pairs.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for &(offset, attempt) in pairs {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&attempt.to_le_bytes());
    }
    let crc = crc32c::crc32c(&out[start..]);
    out.extend_from_slice(&crc.to_le_bytes());
}

/// Decodes a snapshot produced by [`encode_attempt_snapshot`], validating the version, the
/// declared pair count against the length, the checksum, and that the pairs are strictly sorted by
/// offset (so a corrupt or torn snapshot is rejected rather than silently misread). Returns the
/// `(offset, attempt)` pairs in ascending-offset order.
///
/// # Errors
/// Returns [`AttemptSnapshotError`] for a short, mis-sized, wrong-version, count-mismatched,
/// bad-checksum, or out-of-order snapshot. A rejected snapshot never yields a half-built map.
pub fn decode_attempt_snapshot(input: &[u8]) -> Result<Vec<(u64, u32)>, AttemptSnapshotError> {
    if input.len() < ATTEMPT_SNAPSHOT_MIN_LEN {
        return Err(AttemptSnapshotError::Truncated);
    }
    let version = input[0];
    if version != SNAPSHOT_VERSION {
        return Err(AttemptSnapshotError::UnsupportedVersion(version));
    }
    let pairs_bytes = input.len() - ATTEMPT_SNAPSHOT_MIN_LEN;
    if pairs_bytes % PAIR_LEN != 0 {
        return Err(AttemptSnapshotError::BadLength { len: input.len() });
    }
    let declared = read_u32(input, 1);
    // The declared count must match the bytes actually present, so a count field that disagrees
    // with the length (a torn or tampered snapshot) is rejected rather than over- or under-read.
    if u64::from(declared) != (pairs_bytes / PAIR_LEN) as u64 {
        return Err(AttemptSnapshotError::CountMismatch {
            declared,
            actual: (pairs_bytes / PAIR_LEN) as u64,
        });
    }
    let crc_at = input.len() - 4;
    let stored = read_u32(input, crc_at);
    if crc32c::crc32c(&input[..crc_at]) != stored {
        return Err(AttemptSnapshotError::BadCrc);
    }
    let mut pairs = Vec::with_capacity(pairs_bytes / PAIR_LEN);
    let mut pos = ATTEMPT_SNAPSHOT_MIN_LEN - 4; // first pair starts right after the header
    let mut prev: Option<u64> = None;
    while pos < crc_at {
        let offset = read_u64(input, pos);
        let attempt = read_u32(input, pos + 8);
        if let Some(p) = prev {
            if offset <= p {
                return Err(AttemptSnapshotError::NotSorted {
                    offset,
                    prev_offset: p,
                });
            }
        }
        prev = Some(offset);
        pairs.push((offset, attempt));
        pos += PAIR_LEN;
    }
    Ok(pairs)
}

/// A failure decoding an attempt-count snapshot (see [`decode_attempt_snapshot`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptSnapshotError {
    /// The snapshot is shorter than the fixed header plus checksum.
    Truncated,
    /// The snapshot length is not a fixed header plus a whole number of `(u64, u32)` pairs.
    BadLength {
        /// The rejected length.
        len: usize,
    },
    /// The snapshot's version byte is one this build does not understand.
    UnsupportedVersion(u8),
    /// The declared pair count did not match the bytes actually present.
    CountMismatch {
        /// The count the snapshot's header declared.
        declared: u32,
        /// The number of whole pairs the snapshot body actually held.
        actual: u64,
    },
    /// The trailing crc32c did not match the body (a torn or corrupt snapshot).
    BadCrc,
    /// The decoded pairs were not strictly sorted by ascending, distinct offset.
    NotSorted {
        /// The offending offset.
        offset: u64,
        /// The offset of the preceding pair (which `offset` failed to exceed).
        prev_offset: u64,
    },
}

impl core::fmt::Display for AttemptSnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AttemptSnapshotError::Truncated => {
                write!(f, "attempt snapshot is too short for its header")
            }
            AttemptSnapshotError::BadLength { len } => {
                write!(
                    f,
                    "attempt snapshot length {len} is not a header plus whole pairs"
                )
            }
            AttemptSnapshotError::UnsupportedVersion(v) => {
                write!(f, "attempt snapshot version {v} is not supported")
            }
            AttemptSnapshotError::CountMismatch { declared, actual } => write!(
                f,
                "attempt snapshot declared {declared} pairs but holds {actual}"
            ),
            AttemptSnapshotError::BadCrc => write!(f, "attempt snapshot checksum did not match"),
            AttemptSnapshotError::NotSorted {
                offset,
                prev_offset,
            } => write!(
                f,
                "attempt snapshot offset {offset} is not strictly above the previous {prev_offset}"
            ),
        }
    }
}

impl std::error::Error for AttemptSnapshotError {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_snapshot_round_trips() {
        let mut buf = Vec::new();
        encode_attempt_snapshot(&[], &mut buf);
        // version (1) + count (4) + crc (4), no pairs.
        assert_eq!(buf.len(), ATTEMPT_SNAPSHOT_MIN_LEN);
        assert_eq!(decode_attempt_snapshot(&buf).unwrap(), Vec::new());
    }

    #[test]
    fn pairs_round_trip_in_order() {
        let pairs = vec![(2u64, 3u32), (5, 1), (9, 7)];
        let mut buf = Vec::new();
        encode_attempt_snapshot(&pairs, &mut buf);
        assert_eq!(buf.len(), ATTEMPT_SNAPSHOT_MIN_LEN + PAIR_LEN * 3);
        assert_eq!(decode_attempt_snapshot(&buf).unwrap(), pairs);
    }

    #[test]
    fn encode_appends_to_a_prefixed_buffer() {
        // The storage layer frames the snapshot after other bytes, so the suffix must decode alone.
        let pairs = vec![(1u64, 4u32)];
        let mut buf = vec![0xAA, 0xBB];
        let start = buf.len();
        encode_attempt_snapshot(&pairs, &mut buf);
        assert_eq!(decode_attempt_snapshot(&buf[start..]).unwrap(), pairs);
        assert_eq!(&buf[..start], &[0xAA, 0xBB]);
    }

    #[test]
    fn decode_rejects_a_truncated_snapshot() {
        for len in 0..ATTEMPT_SNAPSHOT_MIN_LEN {
            let buf = vec![0u8; len];
            assert_eq!(
                decode_attempt_snapshot(&buf),
                Err(AttemptSnapshotError::Truncated)
            );
        }
    }

    #[test]
    fn decode_rejects_an_unsupported_version() {
        let mut buf = Vec::new();
        encode_attempt_snapshot(&[(1, 1)], &mut buf);
        buf[0] = SNAPSHOT_VERSION + 1;
        // Re-checksum so the only fault is the version byte (not merely caught by the crc).
        let crc_at = buf.len() - 4;
        let crc = crc32c::crc32c(&buf[..crc_at]);
        buf[crc_at..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            decode_attempt_snapshot(&buf),
            Err(AttemptSnapshotError::UnsupportedVersion(
                SNAPSHOT_VERSION + 1
            ))
        );
    }

    #[test]
    fn decode_rejects_a_mis_sized_snapshot() {
        let mut buf = Vec::new();
        encode_attempt_snapshot(&[(1, 1)], &mut buf);
        for extra in 1..PAIR_LEN {
            let mut bad = buf.clone();
            bad.splice(5..5, vec![0u8; extra]); // junk between the header and the pairs
            assert_eq!(
                decode_attempt_snapshot(&bad),
                Err(AttemptSnapshotError::BadLength { len: bad.len() })
            );
        }
    }

    #[test]
    fn decode_rejects_a_count_mismatch() {
        // A crc-correct body whose declared count disagrees with the actual pairs is rejected.
        let pairs = vec![(2u64, 3u32), (5, 1)];
        let mut buf = Vec::new();
        encode_attempt_snapshot(&pairs, &mut buf);
        // Overwrite the count field to a wrong value, then re-checksum.
        buf[1..5].copy_from_slice(&7u32.to_le_bytes());
        let crc_at = buf.len() - 4;
        let crc = crc32c::crc32c(&buf[..crc_at]);
        buf[crc_at..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            decode_attempt_snapshot(&buf),
            Err(AttemptSnapshotError::CountMismatch {
                declared: 7,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_rejects_a_corrupt_checksum() {
        let mut buf = Vec::new();
        encode_attempt_snapshot(&[(2, 3), (5, 1)], &mut buf);
        buf[5] ^= 0x01; // flip a byte inside the first pair
        assert_eq!(
            decode_attempt_snapshot(&buf),
            Err(AttemptSnapshotError::BadCrc)
        );
    }

    #[test]
    fn decode_rejects_out_of_order_pairs() {
        // A crc-correct body whose offsets are not strictly ascending is a corrupt snapshot.
        let mut buf = vec![SNAPSHOT_VERSION];
        buf.extend_from_slice(&2u32.to_le_bytes());
        // Two pairs with a descending offset.
        buf.extend_from_slice(&5u64.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&5u64.to_le_bytes()); // equal, not strictly above
        buf.extend_from_slice(&1u32.to_le_bytes());
        let crc = crc32c::crc32c(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            decode_attempt_snapshot(&buf),
            Err(AttemptSnapshotError::NotSorted { .. })
        ));
    }

    proptest! {
        /// Encode then decode is the identity for any sorted-distinct pair set, the checksum
        /// accepts the snapshot's own bytes, and the framing length is exact.
        #[test]
        fn snapshot_codec_round_trips(
            raw in prop::collection::vec((0u64..10_000, 1u32..1_000), 0..64),
        ) {
            // Dedup and sort by offset so the input satisfies the codec's sorted-distinct contract.
            let mut map = std::collections::BTreeMap::new();
            for (o, a) in raw {
                map.insert(o, a);
            }
            let pairs: Vec<(u64, u32)> = map.into_iter().collect();
            let mut buf = Vec::new();
            encode_attempt_snapshot(&pairs, &mut buf);
            prop_assert_eq!(buf.len(), ATTEMPT_SNAPSHOT_MIN_LEN + PAIR_LEN * pairs.len());
            let decoded = decode_attempt_snapshot(&buf).expect("own snapshot decodes");
            prop_assert_eq!(decoded, pairs);
        }

        /// crc32c detects every single-bit error in a snapshot this small, so flipping any one bit
        /// is always rejected: no silently corrupted attempt map is ever restored.
        #[test]
        fn snapshot_codec_detects_single_bit_flips(
            raw in prop::collection::vec((0u64..1000, 1u32..1000), 0..32),
            idx in 0usize..4096,
            bit in 0u8..8,
        ) {
            let mut map = std::collections::BTreeMap::new();
            for (o, a) in raw {
                map.insert(o, a);
            }
            let pairs: Vec<(u64, u32)> = map.into_iter().collect();
            let mut buf = Vec::new();
            encode_attempt_snapshot(&pairs, &mut buf);
            let i = idx % buf.len();
            buf[i] ^= 1u8 << bit;
            prop_assert!(
                decode_attempt_snapshot(&buf).is_err(),
                "a flip of byte {} bit {} must be detected", i, bit
            );
        }
    }
}
