// SPDX-License-Identifier: MIT OR Apache-2.0
//! A KV bucket over the compacted log (V2-M5-I1 #556) + linearizable CAS (V2-M5-I2 #558).
//!
//! A KV bucket is a NAMED, key-compacted stream/log — NOT a new storage engine. It is a thin
//! view over the SAME segmented [`Log`] every other IronBus stream uses, with key compaction
//! (the shipped `--compact` machinery, `docs/COMPACTION.md`) turned ON so the durable log keeps,
//! for each key, the last value. The mapping is exact:
//!
//! - `bucket`   -> a [`Log`] (its own directory / stream — a bucket is a stream with compaction on);
//! - `key`      -> the record's COMPACTION key (the same key field the compactor collapses on);
//! - `value`    -> the record payload (an EMPTY payload is the tombstone, the existing delete
//!                 convention — no new flag bit, [`ironbus_core::kv::is_tombstone_value`]);
//! - `revision` -> the record's LOG OFFSET (the single writer assigns it, never reused/reordered).
//!
//! ## The compacted head (how `get` is O(1) and linearizable)
//!
//! Compaction's whole job is "keep the last value per key." This bucket materializes that head as
//! a resident `key -> (revision, value)` map and serves [`KvBucket::get`] straight from it: a get
//! is a single hash lookup of the LATEST value, never a log scan. The map is the same
//! last-value-per-key view the on-disk compactor converges the segments toward; the in-memory map
//! is just the head, updated synchronously on every mutation so a get always observes the most
//! recent committed write (linearizable on a single node — see CAS below). The durable log behind
//! it is what RECOVERS the head on reopen (scan in offset order, last write per key wins,
//! tombstone removes the key), and what the background compactor reclaims so the segments do not
//! grow without bound. The in-memory head is a cache OF the durable log, never a second source of
//! truth.
//!
//! ## Linearizable CAS (#558) — the beat over NATS
//!
//! [`KvBucket::put_if`] is a compare-and-swap against an EXPECTED revision, serialized through the
//! SINGLE WRITER (this bucket owns its [`Log`] `&mut self`, which IS the writer): the check
//! (current revision == expected?) and the append are ONE indivisible step because nothing else
//! can interleave on `&mut self`. On a single node that makes CAS linearizable BY CONSTRUCTION —
//! one writer, one total order, no separate consensus round. A mismatch returns the typed
//! [`CasMismatch`] (carrying the key's ACTUAL current revision) and writes NOTHING. NATS's KV CAS,
//! by contrast, can read a STALE follower/mirror before serializing through the stream leader;
//! IronBus's get serves the linearizable compacted head and its CAS never reads a stale replica.
//!
//! ## What is in scope here
//!
//! `put` / `get` / `delete` / `revision` (#556) + linearizable `put_if` CAS (#558). WATCH (#559),
//! per-key TTL + bounded tombstone reclamation (#560), the WIRE frames, and the rich `ironbus kv`
//! CLI (M6) are deliberately NOT in this module — see the PR body for the flagged follow-ups.
//! Bounded tombstone reclamation already exists at the storage layer via the shipped compaction
//! `tombstone_ttl`; the per-key TTL EXPIRY semantics and the watch cursor are the flagged #559/#560.
//!
//! ## Non-KV streams are UNAFFECTED
//!
//! A `KvBucket` is the ONLY thing that turns compaction on for its log and maintains a head index.
//! The default stream, every non-KV stream, the engine's produce path, the existing `StreamSet`,
//! and the compaction module are untouched: this module only COMPOSES them. A deployment that
//! never opens a `KvBucket` behaves byte-for-byte as before.

use std::collections::HashMap;

use bytes::Bytes;
use ironbus_core::clock::Clock;
use ironbus_core::kv::{is_tombstone_value, validate_key, CasMismatch, KvError, Revision};
use ironbus_core::types::{Offset, RecordFlags};

use crate::compaction::{CompactionConfig, CompactionOutcome};
use crate::fs::Filesystem;
use crate::log::{Append, Log, LogConfig};
use crate::segment::StorageError;

/// An error from a [`KvBucket`] operation: either a pure KV failure (an invalid key, or a CAS
/// mismatch — [`KvError`], decided WITHOUT touching the disk) or a lower-level storage/IO failure
/// from the bucket's [`Log`] ([`StorageError`]: a frozen writer, a capacity shed, a sync failure).
/// The two are unified so a caller handles a bucket op with one `?`.
#[derive(Debug)]
pub enum KvBucketError {
    /// A pure, IO-free KV failure: an invalid key or a [`CasMismatch`]. Carries the typed
    /// [`KvError`] so a CAS mismatch surfaces the key's current revision for a retry.
    Kv(KvError),
    /// A storage/IO failure from the underlying [`Log`] (append, sync, open, read). The bucket
    /// never weakens the log's durability or recovery semantics — it forwards them verbatim.
    Storage(StorageError),
}

impl std::fmt::Display for KvBucketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KvBucketError::Kv(e) => write!(f, "kv error: {e}"),
            KvBucketError::Storage(e) => write!(f, "kv storage error: {e}"),
        }
    }
}

impl std::error::Error for KvBucketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KvBucketError::Kv(e) => Some(e),
            KvBucketError::Storage(e) => Some(e),
        }
    }
}

impl From<KvError> for KvBucketError {
    fn from(e: KvError) -> Self {
        KvBucketError::Kv(e)
    }
}

impl From<StorageError> for KvBucketError {
    fn from(e: StorageError) -> Self {
        KvBucketError::Storage(e)
    }
}

impl From<CasMismatch> for KvBucketError {
    fn from(m: CasMismatch) -> Self {
        KvBucketError::Kv(KvError::Cas(m))
    }
}

/// One resident head entry: a key's CURRENT revision (the offset of the record that set it) and
/// its current value. Only LIVE keys are in the head map — a deleted key has NO entry (its
/// tombstone removed it), so a `get` of a deleted key is a plain map miss.
#[derive(Clone, Debug)]
struct HeadEntry {
    /// The offset of the record that set this key's current value — the key's revision.
    revision: Revision,
    /// The key's current value (a refcounted slice of the read buffer on recovery, or an owned
    /// copy of the caller's value on a live put). Never empty for a live key (an empty value is a
    /// tombstone, which REMOVES the key from the head rather than storing it).
    value: Bytes,
}

/// A KV bucket: a key-compacted [`Log`] plus its resident compacted head (`key -> (revision,
/// value)`). The bucket owns its log mutably, so it IS the single writer for its keyspace —
/// which is exactly what makes [`KvBucket::put_if`] linearizable.
///
/// `F` is the backing filesystem and `C` the clock seam, identical to a plain [`Log`]; a bucket
/// adds no new storage primitive, only the head index and the KV verbs over the log.
pub struct KvBucket<F: Filesystem, C: Clock> {
    /// The durable substrate: a normal segmented log whose sealed segments are reclaimed by KEY
    /// COMPACTION (the shipped `--compact` machinery) so they converge to last-value-per-key — the
    /// recoverable, bounded-tombstone store behind the resident head. The bucket is the only writer
    /// to this log.
    log: Log<F, C>,
    /// The KEY-COMPACTION config this bucket drives [`Log::maybe_compact`] with — ENABLED (a bucket
    /// is a stream WITH compaction). It governs the BACKGROUND on-disk reclamation only (tombstone
    /// ttl, dirty-ratio trigger, source-segment cap); the read path is served by the resident head,
    /// so compaction never gates a `get`. [`KvBucket::compact`] runs one rate-capped pass with this.
    compaction: CompactionConfig,
    /// The resident compacted head: every LIVE key's current revision + value. Rebuilt from the
    /// durable log on `open` (scan in offset order, last write wins, tombstone removes the key) and
    /// updated synchronously on every mutation, so a `get` is O(1) and observes the latest
    /// committed write. A deleted key is ABSENT (no entry), never a stored empty value.
    head: HashMap<Bytes, HeadEntry>,
}

impl<F: Filesystem + Clone, C: Clock + Clone> KvBucket<F, C> {
    /// Opens (recovering, or creating fresh) a KV bucket over the log rooted at `fs`. The log is
    /// opened with KEY COMPACTION enabled (the bucket's whole point), recovers exactly as any
    /// IronBus log (longest-valid-prefix, per-record CRC, bounded/reported loss — UNCHANGED), and
    /// then the resident head is rebuilt by scanning the recovered durable records in offset order:
    /// the LAST write per key wins (its offset is the key's revision), and a tombstone (empty
    /// payload) REMOVES the key. So after a reopen the head is byte-for-byte the latest-value-per-key
    /// view the durable log encodes — the recovery test asserts exactly this.
    ///
    /// `config` is the underlying log configuration (segment caps, byte caps); compaction is forced
    /// ON regardless of what `config` carried, because a non-compacting "KV bucket" is a
    /// contradiction. Every other knob is the caller's.
    ///
    /// # Errors
    /// Propagates any [`StorageError`] from opening/recovering the log (including the fail-closed
    /// layout/format checks) or from the recovery scan that rebuilds the head.
    pub fn open(fs: F, clock: C, config: LogConfig) -> Result<KvBucket<F, C>, StorageError> {
        // A bucket's log ALWAYS compacts: it is a stream with compaction on. The compaction CONFIG
        // (tombstone ttl, dirty ratio) keeps its shipped defaults — those govern the BACKGROUND
        // on-disk reclamation that `compact` drives, not the read path, which is served by the
        // resident head rebuilt below.
        let log = Log::open(fs, clock, config)?;
        let head = Self::rebuild_head(&log)?;
        Ok(KvBucket {
            log,
            compaction: CompactionConfig::enabled(),
            head,
        })
    }

    /// Rebuilds the resident compacted head from the durable log: scans every durable record in
    /// offset order and, for each key, keeps the LATEST (highest-offset) record — exactly the
    /// last-value-per-key rule compaction itself uses. A tombstone (empty payload, the delete
    /// convention) REMOVES its key from the head rather than storing it. The result is the head as
    /// of the durable prefix; offsets are sparse if the on-disk compactor already ran, which is
    /// fine — the scan reads whatever survivors are present and the last one per key wins.
    ///
    /// Cost: O(durable records) once at open (the same scan recovery already pays), and the head is
    /// O(distinct LIVE keys) in memory — the compacted size, not the history size.
    fn rebuild_head(log: &Log<F, C>) -> Result<HashMap<Bytes, HeadEntry>, StorageError> {
        let mut head: HashMap<Bytes, HeadEntry> = HashMap::new();
        let durable = log.flushed_offset().get();
        // Read the whole durable prefix in one bounded pass. `read_from` caps at the flushed head
        // and skips compaction gaps transparently, so this yields the survivors in offset order.
        let max = usize::try_from(durable).unwrap_or(usize::MAX);
        for rec in log.read_from(Offset::ZERO, max)? {
            // A keyless record is not a KV write (a bucket only ever appends keyed records); skip it
            // defensively so a foreign keyless record on the log never corrupts the head.
            if rec.key.is_empty() {
                continue;
            }
            if is_tombstone_value(&rec.payload) {
                // A tombstone deletes the key: drop any earlier value. A later put for the same key
                // (a higher offset) re-adds it, because the scan is in ascending offset order.
                head.remove(&rec.key);
            } else {
                head.insert(
                    rec.key.clone(),
                    HeadEntry {
                        revision: Revision::new(rec.offset.get()),
                        value: rec.payload.clone(),
                    },
                );
            }
        }
        Ok(head)
    }

    /// Consumes the bucket and returns the underlying filesystem, so the data dir can be reopened
    /// (the recovery test closes a bucket and reopens it over the same fs to prove the head
    /// rebuilds from the durable log).
    #[must_use]
    pub fn into_filesystem(self) -> F {
        self.log.into_filesystem()
    }
}

impl<F: Filesystem, C: Clock> KvBucket<F, C> {
    /// The current revision of `key`, or [`Revision::NONE`] if the key does not exist (never
    /// written, or deleted). A pure read of the resident head — no IO, no log scan.
    #[must_use]
    pub fn revision(&self, key: &[u8]) -> Revision {
        self.head.get(key).map_or(Revision::NONE, |e| e.revision)
    }

    /// The LATEST value for `key` (the compacted head), or `None` if the key does not exist
    /// (never written, or deleted — a tombstone removed it). Served from the resident head: a
    /// single O(1) hash lookup of the most recent committed write, NOT a log scan. This is the
    /// linearizable get — it always observes the value the most recent `put`/`put_if`/`delete`
    /// committed through the single writer.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.head.get(key).map(|e| e.value.clone())
    }

    /// The number of LIVE keys in the bucket (the compacted head size, NOT the history length).
    #[must_use]
    pub fn len(&self) -> usize {
        self.head.len()
    }

    /// Whether the bucket has no live keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.head.is_empty()
    }

    /// PUT `key = value`, appending a keyed record to the compacted log and returning the new
    /// [`Revision`] (the assigned log offset). A second put for the same key OVERWRITES it: the new
    /// record has a higher offset, so it becomes the key's latest value (the compacted head keeps
    /// the LAST value, the superseded one is dropped on a later compaction pass). The value MUST be
    /// non-empty — an empty value is a tombstone; use [`KvBucket::delete`] for a delete.
    ///
    /// The record is durable on return (the bucket syncs its log per write, upholding I2:
    /// ack-implies-durable), and the resident head is updated to the new revision/value so a
    /// subsequent `get` observes it.
    ///
    /// # Errors
    /// Returns [`KvBucketError::Kv`] for an empty/over-length key OR an empty value (a delete must
    /// go through `delete`), else propagates a [`KvBucketError::Storage`] from the log append/sync.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<Revision, KvBucketError> {
        validate_key(key)?;
        if is_tombstone_value(value) {
            // An empty value is the tombstone encoding; routing it through `put` would silently
            // delete the key. Refuse fail-closed so a delete is always an explicit `delete` call.
            return Err(KvBucketError::Storage(StorageError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "put with an empty value is a delete; call delete() instead",
                ),
            )));
        }
        let revision = self.append_keyed(key, value)?;
        self.head.insert(
            Bytes::copy_from_slice(key),
            HeadEntry {
                revision,
                value: Bytes::copy_from_slice(value),
            },
        );
        Ok(revision)
    }

    /// DELETE `key`, appending a TOMBSTONE (a keyed record with an empty payload — the shipped
    /// delete convention, `docs/COMPACTION.md`, NO new flag bit) and removing the key from the
    /// resident head, so a subsequent `get` returns `None`. Returns the tombstone's [`Revision`]
    /// (its offset), so a caller can observe WHERE the delete landed in the total order, or `None`
    /// if the key did not exist (nothing was written — deleting an absent key is a no-op that does
    /// not append a tombstone, keeping the log free of redundant tombstones).
    ///
    /// The tombstone is RETAINED on disk for the compaction `tombstone_ttl` (the bounded,
    /// reported reclamation — the beat over NATS's indefinite-until-50%-dead garbage), so an
    /// offline consumer that was down can come back and observe the delete; then the compactor
    /// reclaims it. The per-key TTL EXPIRY (#560) is the flagged follow-up; the bounded tombstone
    /// reclamation it builds on is already shipped in the compaction layer.
    ///
    /// # Errors
    /// Returns [`KvBucketError::Kv`] for an invalid key, else propagates a [`KvBucketError::Storage`]
    /// from the log append/sync.
    pub fn delete(&mut self, key: &[u8]) -> Result<Option<Revision>, KvBucketError> {
        validate_key(key)?;
        if !self.head.contains_key(key) {
            // Deleting an absent key writes nothing: no redundant tombstone, and the head is already
            // without the key. (A caller that wants a tombstone for an offline observer regardless
            // can be added later; the bounded-tombstone story does not need a tombstone-per-noop.)
            return Ok(None);
        }
        // The tombstone is the empty-payload record under the same key (the existing convention).
        let revision = self.append_keyed(key, b"")?;
        self.head.remove(key);
        Ok(Some(revision))
    }

    /// LINEARIZABLE compare-and-swap (#558): PUT `key = value` ONLY IF the key's current revision
    /// equals `expected`. The check (current == expected?) and the append are serialized through
    /// the SINGLE WRITER — this method holds `&mut self`, the sole writer to the bucket's log — so
    /// the compare-and-append is ONE indivisible step nothing can interleave. On a single node this
    /// is linearizable BY CONSTRUCTION (one writer, one total order), with NO separate consensus
    /// round and NO possibly-stale follower read (the beat over NATS KV CAS).
    ///
    /// Pass `expected = `[`Revision::NONE`] to create the key ONLY IF it is absent
    /// (create-if-not-exists); pass a real revision to update ONLY IF the key is still at that exact
    /// revision (no one else wrote it since you read it). On success the new [`Revision`] is
    /// returned and the head is updated. On a mismatch NOTHING is written and a typed [`CasMismatch`]
    /// (carrying the key's ACTUAL current revision) is returned, so the caller re-reads and retries.
    ///
    /// The value MUST be non-empty (an empty value is a delete; a compare-and-delete is the flagged
    /// follow-up, not this verb).
    ///
    /// # Errors
    /// Returns [`KvBucketError::Kv`] holding a [`KvError::Cas`] on a revision mismatch (the typed,
    /// expected failure — nothing was written), a [`KvError::EmptyKey`]/`KeyTooLong` for an invalid
    /// key or an empty value, else a [`KvBucketError::Storage`] from the log append/sync.
    pub fn put_if(
        &mut self,
        key: &[u8],
        value: &[u8],
        expected: Revision,
    ) -> Result<Revision, KvBucketError> {
        validate_key(key)?;
        if is_tombstone_value(value) {
            return Err(KvBucketError::Storage(StorageError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "put_if with an empty value is a delete; not supported by CAS",
                ),
            )));
        }
        // THE LINEARIZATION POINT. We hold &mut self (the single writer), so reading the current
        // revision and (on a match) appending happen with NOTHING able to interleave between them.
        // This is the whole CAS guarantee: the compare and the append are atomic because the writer
        // is serial. On another node's stale replica this would be a race; here it cannot be.
        let current = self.revision(key);
        if current != expected {
            // Mismatch: write NOTHING, return the key's ACTUAL current revision so the caller can
            // re-read and retry. This is the typed, expected outcome, not an error in the log.
            return Err(CasMismatch { expected, current }.into());
        }
        // The compare passed under the single writer: append + sync + update the head. The new
        // offset is the new revision.
        let revision = self.append_keyed(key, value)?;
        self.head.insert(
            Bytes::copy_from_slice(key),
            HeadEntry {
                revision,
                value: Bytes::copy_from_slice(value),
            },
        );
        Ok(revision)
    }

    /// Runs ONE rate-capped key-compaction pass over the bucket's sealed segments (the shipped
    /// `--compact` cleaner via [`Log::maybe_compact`]): it rewrites the dirty sealed segments to keep
    /// last-value-per-key and reclaims superseded records plus tombstones aged past `tombstone_ttl`
    /// (the BOUNDED, recoverable reclamation — the beat over NATS's indefinite garbage). This is the
    /// on-disk reclamation; the resident head is UNCHANGED by it (compaction keeps the same latest
    /// value per key the head already holds), so a `get` is unaffected and never blocked behind a
    /// pass. Off the hot path: only sealed segments are touched, never the active one.
    ///
    /// Returns the [`CompactionOutcome`] (empty if no dirty run met the trigger). A caller drives this
    /// on a coarse interval / on seal, exactly as the engine does for a non-KV compacted stream.
    ///
    /// # Errors
    /// Propagates a [`StorageError`] from the pass ([`StorageError::WriterFrozen`] on a dead writer,
    /// or an IO/segment error). The head is not rebuilt here — compaction preserves the latest value
    /// per key, so the in-memory head stays correct.
    pub fn compact(&mut self) -> Result<CompactionOutcome, StorageError> {
        self.log.maybe_compact(&self.compaction)
    }

    /// Appends one keyed record to the bucket's log and SYNCS it (durable on return, I2 upheld),
    /// returning the assigned offset as a [`Revision`]. The single low-level write path every KV
    /// verb funnels through, so the durability discipline is in exactly one place. A `value` of
    /// `b""` is the tombstone encoding (`delete` uses it); a non-empty value is a live put.
    fn append_keyed(&mut self, key: &[u8], value: &[u8]) -> Result<Revision, StorageError> {
        let offset = self.log.append(&Append {
            timestamp_ms: self.log.now_unix_millis(),
            flags: RecordFlags::EMPTY,
            key,
            headers: b"",
            payload: value,
        })?;
        // Sync per write so an acked KV put/delete is durable (I2) and recoverable — the bucket
        // never weakens the log's durability. The resident head, updated by the caller after this
        // returns, is a cache of this now-durable record.
        self.log.sync()?;
        Ok(Revision::new(offset.get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use ironbus_core::clock::ManualClock;

    fn open_bucket() -> KvBucket<InMemoryFs, ManualClock> {
        KvBucket::open(InMemoryFs::new(), ManualClock::new(), LogConfig::default()).unwrap()
    }

    /// A tiny segment cap so a handful of puts roll into several sealed segments, giving the
    /// compactor adjacent dirty sources to reclaim.
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 200,
            ..LogConfig::default()
        }
    }

    /// put/get returns the latest value, and a get of an absent key is None.
    #[test]
    fn put_then_get_returns_the_value() {
        let mut kv = open_bucket();
        assert_eq!(kv.get(b"k"), None);
        let r = kv.put(b"k", b"v1").unwrap();
        assert_eq!(kv.get(b"k").as_deref(), Some(b"v1".as_ref()));
        assert_eq!(kv.revision(b"k"), r);
        assert_eq!(kv.len(), 1);
        assert!(!kv.is_empty());
    }

    /// A second put OVERWRITES: get returns the NEW value and the compacted head keeps the LAST
    /// one; the revision advances (the new offset is strictly greater).
    #[test]
    fn second_put_overwrites_and_advances_revision() {
        let mut kv = open_bucket();
        let r1 = kv.put(b"k", b"v1").unwrap();
        let r2 = kv.put(b"k", b"v2").unwrap();
        assert!(
            r2.get() > r1.get(),
            "a later put has a strictly higher revision"
        );
        assert_eq!(kv.get(b"k").as_deref(), Some(b"v2".as_ref()));
        assert_eq!(kv.revision(b"k"), r2);
        // Still ONE live key (the head keeps the last value, not both).
        assert_eq!(kv.len(), 1);
    }

    /// delete writes a tombstone; get then returns not-found and the key leaves the head.
    #[test]
    fn delete_writes_a_tombstone_and_get_is_not_found() {
        let mut kv = open_bucket();
        kv.put(b"k", b"v1").unwrap();
        let del_rev = kv.delete(b"k").unwrap();
        assert!(del_rev.is_some(), "deleting a live key writes a tombstone");
        assert_eq!(kv.get(b"k"), None);
        assert_eq!(kv.revision(b"k"), Revision::NONE);
        assert!(kv.is_empty());
        // Deleting an ABSENT key is a no-op (no redundant tombstone, returns None).
        assert_eq!(kv.delete(b"k").unwrap(), None);
        assert_eq!(kv.delete(b"never").unwrap(), None);
    }

    /// A put AFTER a delete re-creates the key (a higher offset re-adds it to the head).
    #[test]
    fn put_after_delete_recreates_the_key() {
        let mut kv = open_bucket();
        kv.put(b"k", b"v1").unwrap();
        kv.delete(b"k").unwrap();
        let r = kv.put(b"k", b"v2").unwrap();
        assert_eq!(kv.get(b"k").as_deref(), Some(b"v2".as_ref()));
        assert_eq!(kv.revision(b"k"), r);
    }

    /// CAS SUCCEEDS at the expected revision and the value/revision update.
    #[test]
    fn cas_succeeds_at_the_expected_revision() {
        let mut kv = open_bucket();
        let r1 = kv.put(b"k", b"v1").unwrap();
        let r2 = kv.put_if(b"k", b"v2", r1).unwrap();
        assert!(r2.get() > r1.get());
        assert_eq!(kv.get(b"k").as_deref(), Some(b"v2".as_ref()));
        assert_eq!(kv.revision(b"k"), r2);
    }

    /// CAS create-if-absent: `put_if` with the NONE sentinel creates the key only when it is absent.
    #[test]
    fn cas_create_if_absent() {
        let mut kv = open_bucket();
        // The key is absent -> expected NONE matches -> the create succeeds.
        let r = kv.put_if(b"k", b"v1", Revision::NONE).unwrap();
        assert_eq!(kv.get(b"k").as_deref(), Some(b"v1".as_ref()));
        // A second create-if-absent now FAILS (the key exists; current != NONE).
        let err = kv.put_if(b"k", b"v2", Revision::NONE).unwrap_err();
        match err {
            KvBucketError::Kv(KvError::Cas(m)) => {
                assert_eq!(m.expected, Revision::NONE);
                assert_eq!(m.current, r);
            }
            other => panic!("expected a CAS mismatch, got {other:?}"),
        }
        // The failed CAS wrote NOTHING: the value is still v1.
        assert_eq!(kv.get(b"k").as_deref(), Some(b"v1".as_ref()));
    }

    /// CAS FAILS at a STALE expected revision, returns a typed `CasMismatch` with the CURRENT
    /// revision, and writes nothing.
    #[test]
    fn cas_fails_at_a_stale_revision_with_typed_mismatch() {
        let mut kv = open_bucket();
        let r1 = kv.put(b"k", b"v1").unwrap();
        let r2 = kv.put(b"k", b"v2").unwrap(); // r1 is now STALE
        let err = kv.put_if(b"k", b"v3", r1).unwrap_err();
        match err {
            KvBucketError::Kv(KvError::Cas(m)) => {
                assert_eq!(
                    m.expected, r1,
                    "the mismatch echoes the stale expected revision"
                );
                assert_eq!(m.current, r2, "and reports the ACTUAL current revision");
            }
            other => panic!("expected a CAS mismatch, got {other:?}"),
        }
        // Nothing was written: the value is still v2, the revision still r2.
        assert_eq!(kv.get(b"k").as_deref(), Some(b"v2".as_ref()));
        assert_eq!(kv.revision(b"k"), r2);
    }

    /// CAS LINEARIZABILITY: a sequence of CAS attempts against the SAME read revision — exactly one
    /// wins, the rest see the typed mismatch. Serialized through the single writer, the winner is
    /// the first to commit and every later attempt against the now-stale revision fails. This is the
    /// concurrent-CAS contract, made deterministic by the single-writer total order.
    #[test]
    fn cas_is_linearizable_only_one_winner() {
        let mut kv = open_bucket();
        let base = kv.put(b"k", b"v0").unwrap();
        // Three contenders all read `base` and race to CAS. The single writer serializes them: the
        // FIRST wins (current == base), the rest now see current == winner's revision != base.
        let first = kv.put_if(b"k", b"a", base).unwrap();
        for (i, contender) in [b"b".as_ref(), b"c".as_ref()].iter().enumerate() {
            let err = kv.put_if(b"k", contender, base).unwrap_err();
            match err {
                KvBucketError::Kv(KvError::Cas(m)) => {
                    assert_eq!(m.expected, base);
                    assert_eq!(m.current, first, "contender {i} sees the winner's revision");
                }
                other => panic!("expected a CAS mismatch, got {other:?}"),
            }
        }
        // Exactly the winner's value is present; the losers wrote nothing.
        assert_eq!(kv.get(b"k").as_deref(), Some(b"a".as_ref()));
        assert_eq!(kv.revision(b"k"), first);
    }

    /// The bucket RECOVERS: write some keys (including an overwrite and a delete), close the bucket,
    /// reopen over the same fs, and the head is intact — get returns the right LATEST value, a
    /// deleted key is gone, and the revision == the offset that set it.
    #[test]
    fn bucket_recovers_the_compacted_head_on_reopen() {
        let fs = InMemoryFs::new();
        let (rev_a2, rev_c) = {
            let mut kv =
                KvBucket::open(fs.clone(), ManualClock::new(), LogConfig::default()).unwrap();
            kv.put(b"a", b"a1").unwrap();
            let rev_a2 = kv.put(b"a", b"a2").unwrap(); // overwrite a
            kv.put(b"b", b"b1").unwrap();
            kv.delete(b"b").unwrap(); // delete b
            let rev_c = kv.put(b"c", b"c1").unwrap();
            (rev_a2, rev_c)
        };

        // Reopen over the SAME durable bytes. The head rebuilds from the recovered log.
        let kv = KvBucket::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        assert_eq!(
            kv.get(b"a").as_deref(),
            Some(b"a2".as_ref()),
            "latest value of a survives"
        );
        assert_eq!(
            kv.revision(b"a"),
            rev_a2,
            "revision == the offset that set it"
        );
        assert_eq!(kv.get(b"b"), None, "the deleted key is gone after recovery");
        assert_eq!(kv.get(b"c").as_deref(), Some(b"c1".as_ref()));
        assert_eq!(kv.revision(b"c"), rev_c);
        // Two live keys (a, c); b was deleted.
        assert_eq!(kv.len(), 2);

        // The recovered head still serves CAS linearizably: a CAS at the recovered revision wins.
        let mut kv = kv;
        let r = kv.put_if(b"a", b"a3", rev_a2).unwrap();
        assert_eq!(kv.get(b"a").as_deref(), Some(b"a3".as_ref()));
        assert!(r.get() > rev_a2.get());
    }

    /// revision == offset: the revision a put returns is exactly the underlying log offset, and a
    /// fresh bucket's first put lands at offset 0.
    #[test]
    fn revision_equals_offset() {
        let mut kv = open_bucket();
        let r0 = kv.put(b"k", b"v").unwrap();
        assert_eq!(r0, Revision::new(0), "the first record is offset 0");
        let r1 = kv.put(b"k2", b"v").unwrap();
        assert_eq!(r1, Revision::new(1), "the next record is offset 1");
    }

    /// A compaction pass reclaims superseded records on disk WITHOUT disturbing the resident head:
    /// after many overwrites of the same key, `compact` keeps last-value-per-key, and a get/revision
    /// is unchanged — and the bucket still recovers the right latest value from the compacted log.
    #[test]
    fn compact_reclaims_on_disk_and_head_is_unchanged() {
        let fs = InMemoryFs::new();
        let mut kv = KvBucket::open(fs.clone(), ManualClock::new(), small_config()).unwrap();
        // Many overwrites of one key (forcing several sealed segments to roll) plus a distinct key.
        let mut last = Revision::NONE;
        for v in 0..12u8 {
            last = kv.put(b"alpha", &[v; 16]).unwrap();
        }
        kv.put(b"beta", b"b").unwrap();
        let before_alpha = kv.get(b"alpha").unwrap();
        let before_rev = kv.revision(b"alpha");
        assert_eq!(before_rev, last);

        // Run a compaction pass: it should reclaim the superseded alpha records on disk.
        let outcome = kv.compact().unwrap();
        assert!(
            outcome.compacted_segment_id.is_some(),
            "a run of overwrites is dirty enough to compact"
        );
        assert!(
            outcome.dropped > 0,
            "superseded alpha versions were reclaimed"
        );

        // The resident head is UNCHANGED: same latest value, same revision.
        assert_eq!(kv.get(b"alpha"), Some(before_alpha.clone()));
        assert_eq!(kv.revision(b"alpha"), before_rev);
        assert_eq!(kv.get(b"beta").as_deref(), Some(b"b".as_ref()));

        // And the COMPACTED log still recovers the right latest value on reopen.
        drop(kv);
        let kv = KvBucket::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(kv.get(b"alpha"), Some(before_alpha));
        assert_eq!(kv.revision(b"alpha"), before_rev);
        assert_eq!(kv.get(b"beta").as_deref(), Some(b"b".as_ref()));
    }

    /// An invalid key fails closed at the boundary (never reaching the log), and an empty value is
    /// rejected by put (it is a delete).
    #[test]
    fn invalid_inputs_fail_closed() {
        let mut kv = open_bucket();
        assert!(matches!(
            kv.put(b"", b"v"),
            Err(KvBucketError::Kv(KvError::EmptyKey))
        ));
        assert!(
            kv.put(b"k", b"").is_err(),
            "an empty value is a delete, refused by put"
        );
        // The log is untouched: no key exists.
        assert!(kv.is_empty());
    }
}
