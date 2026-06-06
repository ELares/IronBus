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

    /// Returns the next offset, saturating at `u64::MAX`.
    ///
    /// A real deployment never approaches `u64::MAX`, so saturation is a defensive
    /// guard rather than an expected path.
    #[must_use]
    pub const fn next(self) -> Offset {
        Offset(self.0.saturating_add(1))
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

    /// Returns the next sequence number, saturating at `u64::MAX`.
    #[must_use]
    pub const fn next(self) -> Seq {
        Seq(self.0.saturating_add(1))
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
/// flags without older readers corrupting them.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct RecordFlags(u8);

impl RecordFlags {
    /// The record payload is compressed (see the compression design).
    pub const COMPRESSED: RecordFlags = RecordFlags(0b0000_0001);
    /// The record carries a routing or ordering key.
    pub const HAS_KEY: RecordFlags = RecordFlags(0b0000_0010);

    /// An empty flag set.
    pub const EMPTY: RecordFlags = RecordFlags(0);

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
        assert_eq!(Offset::new(42).next(), Offset::new(43));
        assert!(Offset::new(1) < Offset::new(2));
        assert_eq!(Offset::new(u64::MAX).next(), Offset::new(u64::MAX));
    }

    #[test]
    fn seq_roundtrip() {
        assert_eq!(Seq::new(7).get(), 7);
        assert_eq!(Seq::new(7).next(), Seq::new(8));
        assert_eq!(Seq::new(u64::MAX).next(), Seq::new(u64::MAX));
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
        // Unknown bits are preserved.
        assert_eq!(RecordFlags::from_bits(0b1000_0000).bits(), 0b1000_0000);
    }

    #[test]
    fn display_is_numeric() {
        assert_eq!(Offset::new(9).to_string(), "9");
        assert_eq!(Seq::new(9).to_string(), "9");
    }
}
