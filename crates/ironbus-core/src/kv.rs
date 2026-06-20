// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure, IO-free value types for the KV bucket (V2-M5, #556 + #558).
//!
//! A KV bucket is a key-compacted stream/log: `bucket -> stream`, `key -> record key`,
//! `value -> record body`, and crucially `revision -> the record's log offset`. The whole
//! storage and engine integration lives ABOVE this crate (`ironbus-storage::kv`), because it
//! touches a [`Log`](crate). This module holds only the pure types that the storage layer and
//! a future wire/CLI share: the [`Revision`] newtype, the typed [`CasMismatch`] a failed
//! compare-and-swap returns, and the [`KvError`] surface. They carry no IO, no allocation
//! beyond an owned key/value the caller already holds, and no clock — exactly the IO-free
//! contract this crate enforces.
//!
//! ## Why a revision is an offset
//!
//! Every keyed record a bucket appends gets a monotonic log offset (the single writer assigns
//! it, never reused, never reordered). That offset IS the key's revision: it totally orders
//! every write to the bucket, so "the key's current revision" is unambiguous and a
//! compare-and-swap against an expected revision is a single integer compare. On a single node
//! this makes CAS LINEARIZABLE by construction (one writer, one total order), which is the beat
//! over NATS's KV CAS that can read a STALE follower before serializing through the stream
//! leader.

use core::fmt;

/// A KV key's revision: the log offset of the record that set the key's CURRENT value.
///
/// A revision is monotonic per key (a later write to the same key always has a strictly greater
/// revision, because the single writer assigns strictly increasing offsets) and totally ordered
/// across the whole bucket (it IS an offset in the one log). [`Revision::NONE`] is the sentinel
/// for "this key does not exist yet" — the expected revision a caller passes to create a key
/// only if it is absent (the create-if-not-exists CAS).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Revision(u64);

impl Revision {
    /// The sentinel revision meaning "the key does not exist" — the expected revision for a
    /// create-if-absent compare-and-swap, and the current revision a [`CasMismatch`] reports for
    /// a key that is not present. Distinct from `Revision(0)`, which is a REAL revision (the very
    /// first record in the log lives at offset `0`); a key's existence is carried by the head
    /// index, never inferred from a zero revision, so `NONE` is the dedicated absent marker that
    /// a real offset can never collide with (it is `u64::MAX`, an offset a real log never reaches).
    pub const NONE: Revision = Revision(u64::MAX);

    /// Wraps a raw log offset as a [`Revision`].
    #[must_use]
    pub const fn new(value: u64) -> Revision {
        Revision(value)
    }

    /// The raw `u64` (the underlying log offset).
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether this revision is the [`Revision::NONE`] absent sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == Revision::NONE.0
    }
}

impl fmt::Debug for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            write!(f, "Revision(NONE)")
        } else {
            write!(f, "Revision({})", self.0)
        }
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// The typed outcome of a FAILED linearizable compare-and-swap ([`put_if`](crate)): the
/// expected revision the caller supplied did NOT match the key's current revision, so the put
/// was REJECTED and NOTHING was written. Carries the key's ACTUAL current revision so the
/// caller can re-read and retry against the real value (the read-modify-write loop a CAS exists
/// to support).
///
/// This is NOT an IO error and NOT data loss: it is the normal "you lost the race / your view
/// was stale" signal, which on a single-writer log is observed atomically (the check-and-append
/// is serialized through the one writer, so the reported `current` is the value that won).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CasMismatch {
    /// The revision the caller EXPECTED the key to be at (what they passed to `put_if`).
    pub expected: Revision,
    /// The key's ACTUAL current revision at the instant the writer evaluated the CAS — the value
    /// that won. [`Revision::NONE`] if the key does not currently exist (so the caller learns
    /// the key was deleted or never created). The caller re-reads against this and retries.
    pub current: Revision,
}

impl fmt::Display for CasMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CAS mismatch: expected revision {}, current revision {}",
            self.expected, self.current
        )
    }
}

impl std::error::Error for CasMismatch {}

/// The maximum KV key length in bytes (a bucket key maps 1:1 to a record's compaction key, so it
/// inherits the record key's bound). Held here as the pure, shared constant so the storage layer
/// and a future wire/CLI agree on one limit; an over-length key fails closed at the boundary with
/// [`KvError::KeyTooLong`] rather than reaching the log.
pub const MAX_KV_KEY_LEN: usize = 1024;

/// An error from a KV-bucket operation that is independent of the storage layer's own IO errors:
/// the pure validation and semantic failures the bucket can decide WITHOUT touching the disk.
///
/// A storage/IO failure (a frozen writer, a capacity shed, a sync failure) surfaces as the
/// storage layer's own error type, NOT here — this crate is IO-free and never names a
/// [`std::io::Error`]. The storage `KvBucket` composes the two so a caller handles them with one
/// `?` at that layer; the pure failures live here so they are testable without a filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvError {
    /// An empty key was supplied. A KV key is the record's COMPACTION key, and a keyless record is
    /// NEVER compacted away (it is always a survivor), so an empty key would never collapse to a
    /// single value per key — it would accumulate forever. A bucket therefore REFUSES an empty key
    /// fail-closed at the boundary rather than silently writing an un-compactable record.
    EmptyKey,
    /// A key longer than [`MAX_KV_KEY_LEN`]. Carries the offending length so the caller can report
    /// the exact overage.
    KeyTooLong {
        /// The rejected key's length in bytes.
        len: usize,
    },
    /// A compare-and-swap was rejected because the expected revision did not match the key's
    /// current revision. Carries the [`CasMismatch`] (expected + actual current revision). This is
    /// the ONLY non-IO failure a `put_if` adds over a plain `put`.
    Cas(CasMismatch),
}

impl fmt::Display for KvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KvError::EmptyKey => write!(f, "a KV key must be non-empty"),
            KvError::KeyTooLong { len } => {
                write!(
                    f,
                    "KV key length {len} exceeds the maximum {MAX_KV_KEY_LEN}"
                )
            }
            KvError::Cas(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for KvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KvError::Cas(m) => Some(m),
            KvError::EmptyKey | KvError::KeyTooLong { .. } => None,
        }
    }
}

impl From<CasMismatch> for KvError {
    fn from(m: CasMismatch) -> Self {
        KvError::Cas(m)
    }
}

/// Validates a KV key against the pure boundary rules (non-empty, within [`MAX_KV_KEY_LEN`]),
/// returning the typed [`KvError`] on violation. This is the IO-free check the storage layer runs
/// BEFORE it ever touches the log, so a bad key fails closed at the edge.
///
/// # Errors
/// Returns [`KvError::EmptyKey`] for an empty key or [`KvError::KeyTooLong`] for an over-length one.
pub fn validate_key(key: &[u8]) -> Result<(), KvError> {
    if key.is_empty() {
        return Err(KvError::EmptyKey);
    }
    if key.len() > MAX_KV_KEY_LEN {
        return Err(KvError::KeyTooLong { len: key.len() });
    }
    Ok(())
}

/// Whether a stored record body encodes a TOMBSTONE (a delete) under the empty-payload convention
/// the compaction machinery already uses (`docs/COMPACTION.md`): a keyed record whose payload is
/// empty means "this key is deleted." The KV bucket REUSES that exact convention so a delete and a
/// compaction tombstone are the SAME on-disk record — no new flag bit, no second format. This is a
/// pure helper so the read-side index rebuild and a future reader agree on the predicate.
#[must_use]
pub fn is_tombstone_value(value: &[u8]) -> bool {
    value.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_none_is_distinct_from_zero() {
        assert!(Revision::NONE.is_none());
        assert!(!Revision::new(0).is_none());
        assert_ne!(Revision::NONE, Revision::new(0));
        // A real offset never reaches u64::MAX, so NONE can never collide with a real revision.
        assert_eq!(Revision::NONE.get(), u64::MAX);
    }

    #[test]
    fn revision_roundtrip_and_order() {
        assert_eq!(Revision::new(42).get(), 42);
        assert!(Revision::new(1) < Revision::new(2));
        assert_eq!(Revision::default(), Revision::new(0));
    }

    #[test]
    fn revision_display_marks_none() {
        assert_eq!(Revision::new(9).to_string(), "9");
        assert_eq!(Revision::NONE.to_string(), "NONE");
        assert_eq!(format!("{:?}", Revision::NONE), "Revision(NONE)");
        assert_eq!(format!("{:?}", Revision::new(3)), "Revision(3)");
    }

    #[test]
    fn cas_mismatch_carries_both_revisions() {
        let m = CasMismatch {
            expected: Revision::new(5),
            current: Revision::new(9),
        };
        assert_eq!(m.expected, Revision::new(5));
        assert_eq!(m.current, Revision::new(9));
        assert!(m.to_string().contains("expected revision 5"));
        assert!(m.to_string().contains("current revision 9"));
    }

    #[test]
    fn key_validation_rules() {
        assert_eq!(validate_key(b""), Err(KvError::EmptyKey));
        assert!(validate_key(b"k").is_ok());
        assert!(validate_key(&vec![b'k'; MAX_KV_KEY_LEN]).is_ok());
        assert_eq!(
            validate_key(&vec![b'k'; MAX_KV_KEY_LEN + 1]),
            Err(KvError::KeyTooLong {
                len: MAX_KV_KEY_LEN + 1
            })
        );
    }

    #[test]
    fn tombstone_predicate_is_empty_payload() {
        assert!(is_tombstone_value(b""));
        assert!(!is_tombstone_value(b"v"));
    }

    #[test]
    fn cas_mismatch_converts_into_kv_error() {
        let m = CasMismatch {
            expected: Revision::new(1),
            current: Revision::NONE,
        };
        let e: KvError = m.into();
        assert_eq!(e, KvError::Cas(m));
    }
}
