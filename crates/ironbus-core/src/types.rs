// SPDX-License-Identifier: MIT OR Apache-2.0
//! Foundational value types shared across IronBus.
//!
//! These are small, `Copy` newtypes that give the log's identifiers distinct,
//! hard-to-confuse types. They carry no IO and no allocation.

use core::fmt;

/// A monotonically increasing position in the durable log.
///
/// Offsets are assigned by the single append actor and never reused or reordered
/// within the lifetime of a queue. The zero offset is the first record.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Offset(u64);

impl Offset {
    /// The first offset in a log.
    pub const ZERO: Offset = Offset(0);

    /// Wraps a raw `u64` as an [`Offset`].
    #[must_use]
    pub const fn new(value: u64) -> Offset {
        Offset(value)
    }

    /// Returns the raw `u64` value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next offset, or `None` if the offset space is exhausted.
    ///
    /// Because offsets are monotonic and never reused, the caller must treat
    /// `None` as a hard, loud failure (the log cannot mint another id) rather than
    /// reusing this value. A real deployment never approaches `u64::MAX`.
    #[must_use]
    pub const fn checked_next(self) -> Option<Offset> {
        match self.0.checked_add(1) {
            Some(n) => Some(Offset(n)),
            None => None,
        }
    }
}

impl fmt::Debug for Offset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Offset({})", self.0)
    }
}

impl fmt::Display for Offset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A per-record sequence number, unique and monotonic within a single segment.
///
/// A record's sequence must fall in `[base_seq, base_seq + record_count)` for the
/// segment that holds it; a value outside that range marks the record as stale or
/// torn during recovery.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Seq(u64);

impl Seq {
    /// Wraps a raw `u64` as a [`Seq`].
    #[must_use]
    pub const fn new(value: u64) -> Seq {
        Seq(value)
    }

    /// Returns the raw `u64` value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next sequence number, or `None` if the space is exhausted.
    ///
    /// As with [`Offset::checked_next`], `None` is a hard failure: a sequence
    /// number is never reused.
    #[must_use]
    pub const fn checked_next(self) -> Option<Seq> {
        match self.0.checked_add(1) {
            Some(n) => Some(Seq(n)),
            None => None,
        }
    }
}

impl fmt::Debug for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seq({})", self.0)
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The per-record flag bits stored in the record header `flags` byte.
///
/// Unknown bits are preserved on read so that a future writer can introduce new
/// flags without older readers corrupting them. A reader can detect unknown bits
/// with [`RecordFlags::unknown_bits`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RecordFlags(u8);

impl RecordFlags {
    /// The record payload is compressed (see the compression design).
    pub const COMPRESSED: RecordFlags = RecordFlags(0b0000_0001);
    /// The record carries a routing or ordering key.
    pub const HAS_KEY: RecordFlags = RecordFlags(0b0000_0010);
    /// The record carries a second xxh3-64 checksum field immediately before its
    /// trailer (set by the codec when the stored body reaches `XXH3_PAYLOAD_THRESHOLD`).
    pub const HAS_XXH3: RecordFlags = RecordFlags(0b0000_0100);
    /// The record carries a stored SUBJECT (#594): an optional length-prefixed field placed
    /// immediately after the header and before the body, with its own CRC32C. The codec derives
    /// the bit from a non-empty subject (like `HAS_KEY` from the key), so it always agrees with
    /// whether the subject field is present. Additive: a record without it is byte-for-byte the
    /// pre-subject layout.
    pub const HAS_SUBJECT: RecordFlags = RecordFlags(0b0000_1000);

    /// An empty flag set.
    pub const EMPTY: RecordFlags = RecordFlags(0);

    /// The union of every flag this version understands. A writer must never emit
    /// a bit outside this mask.
    pub const KNOWN: RecordFlags =
        RecordFlags(Self::COMPRESSED.0 | Self::HAS_KEY.0 | Self::HAS_XXH3.0 | Self::HAS_SUBJECT.0);

    /// Builds a flag set from its raw byte.
    #[must_use]
    pub const fn from_bits(bits: u8) -> RecordFlags {
        RecordFlags(bits)
    }

    /// Returns the raw flag byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns `true` if every bit in `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: RecordFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns a new flag set with the bits in `other` added.
    #[must_use]
    pub const fn with(self, other: RecordFlags) -> RecordFlags {
        RecordFlags(self.0 | other.0)
    }

    /// Returns the subset of bits that this version does not recognize.
    ///
    /// An empty result means every set bit is known. A reader uses this to decide
    /// whether a record was written by a newer format than it fully understands.
    #[must_use]
    pub const fn unknown_bits(self) -> RecordFlags {
        RecordFlags(self.0 & !Self::KNOWN.0)
    }
}

impl fmt::Debug for RecordFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordFlags(0b{:08b})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_roundtrip_and_order() {
        assert_eq!(Offset::ZERO.get(), 0);
        assert_eq!(Offset::new(42).get(), 42);
        assert_eq!(Offset::new(42).checked_next(), Some(Offset::new(43)));
        assert!(Offset::new(1) < Offset::new(2));
        assert_eq!(Offset::new(u64::MAX).checked_next(), None);
    }

    #[test]
    fn seq_roundtrip() {
        assert_eq!(Seq::new(7).get(), 7);
        assert_eq!(Seq::new(7).checked_next(), Some(Seq::new(8)));
        assert_eq!(Seq::new(u64::MAX).checked_next(), None);
    }

    #[test]
    fn flags_set_and_query() {
        let f = RecordFlags::EMPTY
            .with(RecordFlags::COMPRESSED)
            .with(RecordFlags::HAS_KEY);
        assert!(f.contains(RecordFlags::COMPRESSED));
        assert!(f.contains(RecordFlags::HAS_KEY));
        assert_eq!(f.bits(), 0b11);
        assert!(!RecordFlags::COMPRESSED.contains(RecordFlags::HAS_KEY));
    }

    #[test]
    fn flags_unknown_bits_detected_and_preserved() {
        assert_eq!(RecordFlags::KNOWN.bits(), 0b1111);
        // The xxh3 and subject presence bits are recognized flags, not unknown bits.
        assert!(RecordFlags::KNOWN.contains(RecordFlags::HAS_XXH3));
        assert!(RecordFlags::KNOWN.contains(RecordFlags::HAS_SUBJECT));
        assert_eq!(RecordFlags::HAS_XXH3.unknown_bits(), RecordFlags::EMPTY);
        assert_eq!(RecordFlags::HAS_SUBJECT.unknown_bits(), RecordFlags::EMPTY);
        // A known-only set has no unknown bits.
        assert_eq!(RecordFlags::KNOWN.unknown_bits(), RecordFlags::EMPTY);
        // An unknown high bit is both preserved and reported.
        let future = RecordFlags::from_bits(0b1000_0010);
        assert_eq!(future.bits(), 0b1000_0010);
        assert_eq!(future.unknown_bits(), RecordFlags::from_bits(0b1000_0000));
    }

    #[test]
    fn display_is_numeric() {
        assert_eq!(Offset::new(9).to_string(), "9");
        assert_eq!(Seq::new(9).to_string(), "9");
    }
}
