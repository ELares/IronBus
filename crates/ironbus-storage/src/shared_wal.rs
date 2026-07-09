// SPDX-License-Identifier: MIT OR Apache-2.0
//! A `SharedWal`: ONE shared commit log holding MANY named streams' records, interleaved and tagged,
//! demultiplexed per-stream on read and recovery (#597, V2-M2-I13 — the shared-WAL fallback for high
//! stream counts).
//!
//! ## Why (first principles)
//!
//! A [`crate::streamset::StreamSet`] gives every named stream its OWN [`Log`] — its own segment set
//! and open file descriptor(s). That is the resilience-isolation default (I2): a torn segment in one
//! stream cannot touch a sibling. But each per-stream log costs at least one open active segment
//! (an fd + its write buffer), so beyond roughly a core's worth of streams the fd/buffer overhead
//! dominates even with the #565 hot-set LRU bounding the OPEN set (a stream is still a directory + a
//! segment file, and churning the LRU re-pays open/recover per touch). The shared-WAL fallback is the
//! explicit density-over-isolation tradeoff: MANY streams write to ONE commit log (RocketMQ's
//! CommitLog model), tagged by stream, with a DERIVED per-stream index that keeps the single
//! interleaved log per-stream-addressable. `N` streams then cost ONE segment set and ONE fd, not `N`.
//!
//! ## The demux key (the stored stream tag)
//!
//! Every record appended for stream `S` is framed with `S`'s validated name as its stored STREAM TAG
//! ([`ironbus_core::codec::encode_with_stream_tag`], gated by the additive
//! [`RecordFlags::HAS_STREAM_TAG`] bit, CRC-covered independently of the body). The tag is the demux
//! key: it is what lets a shared, interleaved log be split back into per-stream record sequences on
//! read and recovery. Because the tag rides its own CRC'd frame field, a corrupted tag is a
//! fail-closed reject ([`DecodeError::BadStreamTagCrc`]), never a silent cross-stream mis-delivery.
//!
//! ## The derived per-stream index (rebuilt from the log)
//!
//! [`SharedWal`] keeps a DERIVED index `stream -> [shared-log offsets]`: for each stream, the ordered
//! list of shared-log offsets whose record carries that stream's tag, in stream order. It is
//! append-maintained on write and REBUILT FROM THE LOG on [`SharedWal::open`] by scanning the shared
//! commit log once and demultiplexing each record's tag (RocketMQ's ConsumeQueue, rebuilt from the
//! CommitLog). The index is a pure function of the log's durable bytes, so recovery reconstructs it
//! exactly; it is not a second durable format to keep consistent.
//!
//! ## Reads demultiplex by the index, and VERIFY the tag (invariant 1)
//!
//! A consumer of stream `S` reads by a STREAM-RELATIVE position over `S`'s index (0, 1, 2, …); each
//! position maps to a shared-log offset the reader fetches and decodes. The decode re-reads the
//! stored tag and asserts it equals `S` before the record is returned — belt-and-suspenders on top of
//! the authoritative index — so a record written for stream `A` can NEVER be delivered to a consumer
//! of stream `B` even if the index were somehow wrong. A read never returns a not-yet-durable record
//! (it stops at the shared log's flushed head).
//!
//! ## Recovery (invariant 2)
//!
//! [`SharedWal::open`] opens the shared log with the SAME longest-valid-prefix recovery a single
//! [`Log`] gets (a torn tail is truncated fail-closed, its loss bounded and reported), then rebuilds
//! the per-stream index from the surviving durable bytes. Each stream's committed record sequence is
//! therefore reconstructed with no lost/duplicated/reordered records per stream: shared-log offsets
//! are stable and the demux scan is deterministic, so a per-stream cursor (a stream-relative position,
//! #681) resumes exactly where it left off across a restart.
//!
//! ## The reduced contract vs. the per-stream default (the honest tradeoff)
//!
//! This mode DELIBERATELY trades away per-stream resilience isolation for density:
//! - **Resilience isolation is SHARED, not per-stream.** A torn tail on the ONE commit log truncates
//!   whichever streams had records in the torn region (bounded/reported over the shared bytes),
//!   whereas per-stream logs contain a torn segment's blast radius to one stream. This is the I2
//!   tradeoff the issue names explicitly.
//! - **Retention (#566) is a GLOBAL commit-log reap, not per-stream.** The interleaved records cannot
//!   be reaped for one stream independently; RocketMQ reaps the whole CommitLog by time/size and trims
//!   the derived indexes. Wiring that reap is a documented follow-up (see the PR); this core keeps the
//!   shared log append-only.
//! - **Subjects (#594) are not stored in shared mode** (the stored subject and the stream tag share
//!   the fixed post-header frame slot and are mutually exclusive). Per-subject filtering within a
//!   shared-WAL stream is a documented follow-up.
//! - **The DLQ (#1110) still composes per stream**: the dead-letter sink is a SEPARATE per-stream log
//!   keyed by [`StreamId`], orthogonal to whether the SOURCE is a per-stream log or the shared WAL, so
//!   a poisoned record's forensic copy still lands in its stream's DLQ unchanged.
//!
//! ## Scope boundary (what this module is NOT)
//!
//! This is the shared-WAL STORAGE PRIMITIVE only: tagged interleaved append, per-stream demux read,
//! and index-rebuilding recovery over ONE commit log. Wiring it into the engine's
//! `produce_in_stream`/`poll_in_stream`/`ack_in_stream` and recovery paths in place of the per-stream
//! [`StreamSet`] — plus the global-reap retention and per-subject filtering above — is the deferred
//! follow-up surfaced in the PR (like #693's deferred cooperative rebalance). The default per-stream
//! mode is byte-for-byte untouched.

use crate::fs::Filesystem;
use crate::layout::SHARED_WAL_SUBDIR;
use crate::log::{Append, Log, LogConfig};
use crate::loss::LossReport;
use crate::segment::{OwnedRecord, StorageError};
use crate::streamset::{StreamError, StreamId};
use bytes::Bytes;
use ironbus_core::clock::Clock;
use ironbus_core::codec;
use ironbus_core::types::Offset;
use std::collections::BTreeMap;

/// How a broker stores its NAMED streams — the storage-mode selector (#597), a tunable an operator
/// sets on `EngineConfig`. The SAFE default is [`StorageMode::PerStreamLogs`] (today's behavior,
/// byte-for-byte), so the shared-WAL fallback is strictly OPT-IN and an existing deployment is
/// unchanged. The choice is a tradeoff, not a one-way door: per-stream logs give per-stream resilience
/// isolation; the shared WAL gives density at high stream counts (see [`SharedWal`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum StorageMode {
    /// Each NAMED stream is its OWN [`Log`] under `streams/<hex(name)>/` (a
    /// [`crate::streamset::StreamSet`]) — the DEFAULT. Per-stream resilience isolation (a torn segment
    /// in one stream cannot touch a sibling), at the cost of one open segment/fd per resident stream
    /// (bounded by the #565 hot-set LRU). This is today's behavior, unchanged.
    #[default]
    PerStreamLogs,
    /// MANY named streams share ONE [`SharedWal`] commit log (records interleaved and tagged, #597) —
    /// the high-stream-count density fallback. `N` streams cost one segment set / fd instead of `N`,
    /// trading away per-stream resilience isolation (a torn tail is shared) and independent per-stream
    /// retention (a global commit-log reap) for that density. Opt-in.
    SharedWal,
}

/// The result of [`SharedWal::open`]: the opened shared WAL paired with its recovery summary. Named so
/// the two-element tuple does not trip `type_complexity` and reads as one value at the call site.
pub type OpenedSharedWal<F, C> = (SharedWal<F, C>, SharedWalRecovery);

/// The recovery summary of a [`SharedWal::open`]: how the ONE shared commit log recovered (its bounded
/// reported loss) plus the per-stream record counts the demux scan reconstructed. Unlike the
/// per-stream [`crate::streamset::StreamRecovery`], the loss here is SHARED (one commit log, one
/// longest-valid-prefix recovery) — the density-over-isolation tradeoff made explicit.
#[derive(Clone, Debug)]
pub struct SharedWalRecovery {
    /// The bytes recovery truncated from the shared log's torn/unsynced active-segment tail (the
    /// silent loss, made explicit). Zero for a clean recovery.
    pub recovered_truncated_bytes: u64,
    /// The structured, versioned loss report from the shared log's recovery: every byte span recovery
    /// skipped (torn tail or corrupt body), bounded and reported. Empty for a clean recovery. This is
    /// the SHARED report (one commit log), not per stream.
    pub loss_report: LossReport,
    /// The number of durable records the demux scan reconstructed per stream, keyed by [`StreamId`] in
    /// deterministic order. A stream declared but never written durably is absent (it left no bytes).
    pub stream_record_counts: BTreeMap<StreamId, usize>,
    /// The count of durable records whose stored tag was ABSENT or not a valid stream name (deep
    /// corruption that nonetheless passed the frame CRCs, or a foreign writer). Such a record is
    /// delivered to NO stream — isolation-friendly, never mis-delivered — and reported here.
    pub undecodable_tag_records: u64,
}

/// ONE shared commit log holding MANY named streams' records, interleaved and TAGGED by stream, with a
/// DERIVED per-stream index that demultiplexes the single log back into per-stream record sequences on
/// read and recovery (#597). See the module docs for the design, the demux-key/CRC guarantees, and the
/// reduced-contract tradeoff vs the per-stream [`crate::streamset::StreamSet`] default.
///
/// `F` is the backing filesystem and `C` the clock seam, exactly as for a single [`Log`]. The shared
/// commit log lives under the reserved [`SHARED_WAL_SUBDIR`] of the data directory.
pub struct SharedWal<F: Filesystem, C: Clock> {
    /// The single shared commit log holding every stream's records, interleaved and tagged. ONE
    /// segment set + fd(s) for ALL streams — the density win.
    log: Log<F, C>,
    /// The DERIVED per-stream index: for each stream, the ordered shared-log offsets of its records,
    /// in stream order (ascending, since shared-log offsets are monotonic and a stream's records are
    /// appended in order). Rebuilt from the log on [`SharedWal::open`], append-maintained on write. A
    /// `BTreeMap` keeps iteration deterministic and the per-stream lookup O(log streams).
    index: BTreeMap<StreamId, Vec<Offset>>,
}

impl<F: Filesystem, C: Clock> std::fmt::Debug for SharedWal<F, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedWal")
            .field("stream_count", &self.index.len())
            .field("segment_count", &self.log.segment_count())
            .field("next_offset", &self.log.next_offset())
            .finish_non_exhaustive()
    }
}

/// The chunk size (in records) of the recovery demux scan: read this many raw frames per positioned
/// read while rebuilding the per-stream index, so recovery is O(records) with a bounded per-read
/// buffer rather than one syscall per record or one buffer for the whole log.
const RECOVERY_SCAN_CHUNK: usize = 1024;

impl<F: Filesystem + Clone, C: Clock + Clone> SharedWal<F, C> {
    /// Opens (recovering, or creating fresh) the shared WAL rooted at `fs`: opens the ONE shared commit
    /// log under [`SHARED_WAL_SUBDIR`] with the standard longest-valid-prefix recovery, then REBUILDS
    /// the per-stream index by scanning that log once and demultiplexing each record's stored tag.
    ///
    /// The returned [`SharedWalRecovery`] carries the shared log's bounded/reported loss and the
    /// per-stream record counts the scan reconstructed. A torn tail is truncated fail-closed (its loss
    /// reported); every surviving durable record is placed under its stream's index by its tag, so each
    /// stream's committed sequence is reconstructed exactly (invariant 2).
    ///
    /// # Errors
    /// Propagates a [`StorageError`] from creating the `shared-wal/` subdir, opening/recovering the
    /// shared log, or reading it during the demux scan.
    pub fn open(
        fs: &F,
        clock: C,
        config: LogConfig,
    ) -> Result<OpenedSharedWal<F, C>, StorageError> {
        let shared_fs = fs.subdir(SHARED_WAL_SUBDIR).map_err(StorageError::Io)?;
        let log = Log::open(shared_fs, clock, config)?;
        let mut wal = SharedWal {
            log,
            index: BTreeMap::new(),
        };
        let undecodable = wal.rebuild_index()?;
        let recovery = SharedWalRecovery {
            recovered_truncated_bytes: wal.log.recovered_truncated_bytes(),
            loss_report: wal.log.loss_report().clone(),
            stream_record_counts: wal
                .index
                .iter()
                .map(|(id, offs)| (id.clone(), offs.len()))
                .collect(),
            undecodable_tag_records: undecodable,
        };
        Ok((wal, recovery))
    }

    /// Scans the shared commit log from offset 0 to its durable head, demultiplexing each record's
    /// stored tag into the per-stream index. Returns the count of records whose tag was absent or not a
    /// valid stream name (undecodable — placed under no stream). The scan reads at most
    /// [`RECOVERY_SCAN_CHUNK`] raw frames per positioned read, so peak memory is one chunk, not the
    /// whole log. Only the DURABLE prefix (below the flushed head) is scanned, which is exactly the
    /// longest valid prefix the shared log's own recovery already established.
    fn rebuild_index(&mut self) -> Result<u64, StorageError> {
        self.index.clear();
        let mut undecodable = 0u64;
        let flushed = self.log.flushed_offset().get();
        let mut cursor = 0u64;
        while cursor < flushed {
            let (run, next) =
                self.log
                    .read_range_raw(Offset::new(cursor), RECOVERY_SCAN_CHUNK, None)?;
            if run.record_count == 0 {
                // No contiguous raw run at `cursor` (e.g. a compacted region routed to the materialize
                // path). The shared WAL is append-only in this core (retention is a deferred global
                // reap), so this is not expected; advance to the suggested tail if it makes progress,
                // else stop — fail-safe, never an infinite loop.
                match next {
                    Some(n) if n.get() > cursor => {
                        cursor = n.get();
                        continue;
                    }
                    _ => break,
                }
            }
            let bytes: &[u8] = &run.bytes;
            let base = run.first_offset.get();
            let mut pos = 0usize;
            // Frames in a contiguous raw run occupy dense offsets `base + i`; `pos` walks the variable
            // frame lengths within the buffer. (`i` indexes the record; `pos` is not a simple counter.)
            for i in 0..run.record_count {
                // The raw run carries only header-CRC-validated frames; the full decode here also
                // verifies the body and tag CRCs. Within the durable prefix every frame is intact (the
                // log's recovery kept only fully-valid frames), so a decode error is a fail-closed bug,
                // surfaced rather than silently skipped.
                let (_view, tag, consumed) =
                    codec::decode_with_stream_tag(&bytes[pos..]).map_err(StorageError::Record)?;
                if let Some(id) = tag_to_stream_id(tag) {
                    self.index
                        .entry(id)
                        .or_default()
                        .push(Offset::new(base + i));
                } else {
                    undecodable += 1;
                }
                pos += consumed;
            }
            cursor = run.next_offset.get();
        }
        Ok(undecodable)
    }

    /// Declares NAMED stream `id` so it can be appended to and read: registers an index entry. Unlike a
    /// per-stream [`Log`], this creates NO new files or fds — a stream in shared mode is just a tag and
    /// an index slot, which is the whole density point. Re-declaring an existing stream is idempotent.
    /// Returns whether the stream was NEWLY declared (`true`) versus already present (`false`).
    ///
    /// # Errors
    /// Returns [`StreamError::InvalidName`] for the DEFAULT stream (`""`): the default stream is the
    /// engine's root log and is never routed into the shared WAL (it has no non-empty tag to demux by),
    /// so declaring it here is rejected at the boundary.
    pub fn declare(&mut self, id: &StreamId) -> Result<bool, StreamError> {
        if id.is_default() {
            return Err(StreamError::InvalidName {
                name: id.name().to_string(),
            });
        }
        if self.index.contains_key(id) {
            Ok(false)
        } else {
            self.index.insert(id.clone(), Vec::new());
            Ok(true)
        }
    }

    /// Routes one append to stream `id` in the SHARED commit log: frames the record with `id`'s name as
    /// its stored stream tag (the demux key), appends it, and records the assigned shared-log offset in
    /// `id`'s index. Returns the STREAM-RELATIVE position the record took in `id`'s sequence (0 for the
    /// first record of the stream), which is the offset a consumer resumes from. The record is durable
    /// only after a subsequent [`SharedWal::sync`].
    ///
    /// # Errors
    /// Returns [`StorageError::Io`] wrapping `NotFound` if `id` is not declared (declare it first, so a
    /// typo'd id fails closed rather than silently minting a stream), or `InvalidInput` for the default
    /// stream; else propagates the shared log's [`Log::append_with_stream_tag`] error unchanged.
    pub fn append_to(&mut self, id: &StreamId, record: &Append<'_>) -> Result<u64, StorageError> {
        if id.is_default() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the default stream is not routable into the shared WAL (it is the root log)",
            )));
        }
        if !self.index.contains_key(id) {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stream {:?} is not declared in the shared WAL", id.name()),
            )));
        }
        let offset = self
            .log
            .append_with_stream_tag(record, id.name().as_bytes())?;
        // `id` was confirmed present above and `declare`/`close` (the only index mutators) do not run
        // during this call, so the entry is still present; map the impossible `None` to a typed error
        // rather than an unwrap, so this method carries no panic path.
        let entry = self.index.get_mut(id).ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stream {:?} vanished from the shared-WAL index", id.name()),
            ))
        })?;
        let stream_pos = entry.len() as u64;
        entry.push(offset);
        Ok(stream_pos)
    }

    /// Reads up to `max` of stream `id`'s records starting at STREAM-RELATIVE position `from_stream_pos`
    /// (0 = the stream's first record), demultiplexed from the shared commit log via `id`'s index. Each
    /// returned record is fully CRC-validated AND its stored tag is verified to equal `id` before it is
    /// returned (invariant 1: a sibling stream's record can never be delivered here). A record that is
    /// not yet durable (at or past the shared log's flushed head) is not returned; because a stream's
    /// index offsets are ascending, the read stops at the first non-durable one.
    ///
    /// # Errors
    /// Returns [`StorageError::Io`] wrapping `NotFound` if `id` is not declared; [`StorageError`] from
    /// the underlying positioned read; or `InvalidData` if an indexed offset's record does not carry
    /// `id`'s tag (a fail-closed demux-integrity guard that should be unreachable).
    pub fn read_stream(
        &self,
        id: &StreamId,
        from_stream_pos: u64,
        max: usize,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        let offsets = self.index.get(id).ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stream {:?} is not declared in the shared WAL", id.name()),
            ))
        })?;
        let start = usize::try_from(from_stream_pos).unwrap_or(usize::MAX);
        let flushed = self.log.flushed_offset().get();
        let mut out = Vec::new();
        for &offset in offsets.iter().skip(start) {
            if out.len() >= max {
                break;
            }
            // A stream's index offsets are ascending, so the first non-durable one ends the readable
            // run (every later offset is also non-durable). This is the per-stream durable-head gate.
            if offset.get() >= flushed {
                break;
            }
            out.push(self.read_one_demuxed(id, offset)?);
        }
        Ok(out)
    }

    /// Reads and demultiplexes the single record at shared-log `offset`, verifying its stored tag
    /// equals `id`'s name before materializing it. The verification is the belt-and-suspenders guard
    /// for invariant 1: even if the index were wrong, a record tagged for another stream is refused
    /// here rather than mis-delivered.
    fn read_one_demuxed(&self, id: &StreamId, offset: Offset) -> Result<OwnedRecord, StorageError> {
        let (run, _next) = self.log.read_range_raw(offset, 1, None)?;
        if run.record_count == 0 {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("shared-WAL index offset {offset} is not readable in the commit log"),
            )));
        }
        let (view, tag, _consumed) =
            codec::decode_with_stream_tag(&run.bytes).map_err(StorageError::Record)?;
        if tag != id.name().as_bytes() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "shared-WAL demux violation: offset {offset} indexed under stream {:?} but its \
                     stored tag is {:?}",
                    id.name(),
                    String::from_utf8_lossy(tag),
                ),
            )));
        }
        // The blobs are refcounted slices of the shared read buffer the view borrows (zero-copy). A
        // shared-WAL record carries a tag, never a subject, so `subject` is empty.
        Ok(OwnedRecord {
            offset,
            seq: view.seq,
            timestamp_ms: view.timestamp_ms,
            flags: view.flags,
            key: run.bytes.slice_ref(view.key),
            headers: run.bytes.slice_ref(view.headers),
            payload: run.bytes.slice_ref(view.payload),
            subject: Bytes::new(),
        })
    }

    /// Makes every appended record durable (ONE `fdatasync` on the shared commit log, for ALL streams —
    /// the density win extends to commits). Returns the new durable head.
    ///
    /// # Errors
    /// Propagates the shared log's [`Log::sync`] error (which freezes the writer on a barrier failure).
    pub fn sync(&mut self) -> Result<Offset, StorageError> {
        self.log.sync()?;
        Ok(self.log.synced_offset())
    }

    /// The number of declared streams (index entries).
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.index.len()
    }

    /// Whether stream `id` is declared.
    #[must_use]
    pub fn is_declared(&self, id: &StreamId) -> bool {
        self.index.contains_key(id)
    }

    /// The declared stream ids, in deterministic (name) order.
    #[must_use]
    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.index.keys().cloned().collect()
    }

    /// The number of records currently indexed for stream `id` (its stream-relative length, including
    /// not-yet-synced appends), or `0` if `id` is not declared.
    #[must_use]
    pub fn stream_len(&self, id: &StreamId) -> usize {
        self.index.get(id).map_or(0, Vec::len)
    }

    /// The number of on-disk segment FILES the shared commit log holds — the density quantity: ONE
    /// segment set serves ALL streams, so this stays small (typically 1) as the stream count grows,
    /// where `N` per-stream logs would cost at least `N` segment files (one per stream subdir).
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.log.segment_count()
    }

    /// The shared commit log's next (append) offset — the total number of records ever appended across
    /// all streams.
    #[must_use]
    pub fn next_offset(&self) -> Offset {
        self.log.next_offset()
    }

    /// The shared commit log's durable head ([`Log::synced_offset`]).
    #[must_use]
    pub fn synced_offset(&self) -> Offset {
        self.log.synced_offset()
    }

    /// Borrows the shared commit log (read-only), for inspection/metrics. Reads should go through
    /// [`SharedWal::read_stream`], which demultiplexes by stream; this is the raw, undemuxed log.
    #[must_use]
    pub fn shared_log(&self) -> &Log<F, C> {
        &self.log
    }
}

/// Maps a stored stream tag (raw bytes from a decoded frame) back to a [`StreamId`], or `None` if the
/// tag is not valid UTF-8 or not a valid stream name. `None` routes the record to no stream (counted
/// as undecodable), never to the wrong one — the fail-safe for a corrupt-but-CRC-valid or foreign tag.
fn tag_to_stream_id(tag: &[u8]) -> Option<StreamId> {
    let name = std::str::from_utf8(tag).ok()?;
    StreamId::named(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::FaultFs;
    use crate::fs::InMemoryFs;
    use crate::io::RandomAccessFile;
    use crate::naming::{segment_file_name, stream_subdir_name};
    use crate::streamset::StreamSet;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;

    fn cfg() -> LogConfig {
        LogConfig::default()
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    fn open(fs: &InMemoryFs) -> OpenedSharedWal<InMemoryFs, ManualClock> {
        SharedWal::open(fs, ManualClock::new(), cfg()).unwrap()
    }

    fn named(name: &str) -> StreamId {
        StreamId::named(name).unwrap()
    }

    /// N streams write to ONE shared WAL; each consumer reads ONLY its own stream's records, in order,
    /// and a record written for stream A is NEVER delivered to a consumer of stream B (the headline
    /// tag-demux correctness invariant, #1).
    #[test]
    fn each_consumer_reads_only_its_own_streams_records_in_order() {
        let fs = InMemoryFs::new();
        let (mut wal, _) = open(&fs);
        let a = named("alpha");
        let b = named("beta");
        let c = named("gamma");
        for id in [&a, &b, &c] {
            assert!(wal.declare(id).unwrap());
        }
        // Interleave appends across the three streams so their records are truly intermixed in the one
        // shared commit log.
        wal.append_to(&a, &rec(b"a0")).unwrap();
        wal.append_to(&b, &rec(b"b0")).unwrap();
        wal.append_to(&a, &rec(b"a1")).unwrap();
        wal.append_to(&c, &rec(b"c0")).unwrap();
        wal.append_to(&b, &rec(b"b1")).unwrap();
        wal.append_to(&a, &rec(b"a2")).unwrap();
        wal.sync().unwrap();

        // Each stream reads back EXACTLY its own records, in append order — nothing from a sibling.
        let ra = wal.read_stream(&a, 0, 100).unwrap();
        assert_eq!(
            ra.iter().map(|r| r.payload.to_vec()).collect::<Vec<_>>(),
            vec![b"a0".to_vec(), b"a1".to_vec(), b"a2".to_vec()]
        );
        let rb = wal.read_stream(&b, 0, 100).unwrap();
        assert_eq!(
            rb.iter().map(|r| r.payload.to_vec()).collect::<Vec<_>>(),
            vec![b"b0".to_vec(), b"b1".to_vec()]
        );
        let rc = wal.read_stream(&c, 0, 100).unwrap();
        assert_eq!(
            rc.iter().map(|r| r.payload.to_vec()).collect::<Vec<_>>(),
            vec![b"c0".to_vec()]
        );
        // Cross-stream isolation stated directly: no record of A appears in B's or C's read, ever.
        for r in rb.iter().chain(rc.iter()) {
            assert!(!r.payload.starts_with(b"a"), "an A record leaked to B/C");
        }
    }

    /// A stream-relative read RESUMES from a cursor position and returns the correct suffix (the
    /// per-stream durable cursor, #681, composes: the same offset space, one stream at a time).
    #[test]
    fn stream_relative_read_resumes_from_a_cursor_position() {
        let fs = InMemoryFs::new();
        let (mut wal, _) = open(&fs);
        let a = named("alpha");
        let b = named("beta");
        wal.declare(&a).unwrap();
        wal.declare(&b).unwrap();
        for i in 0..5u8 {
            wal.append_to(&a, &rec(&[b'a', b'0' + i])).unwrap();
            wal.append_to(&b, &rec(&[b'b', b'0' + i])).unwrap();
        }
        wal.sync().unwrap();
        // Resume A from position 2: the next records are a2, a3, a4 (never a B record).
        let tail = wal.read_stream(&a, 2, 100).unwrap();
        assert_eq!(
            tail.iter().map(|r| r.payload.to_vec()).collect::<Vec<_>>(),
            vec![b"a2".to_vec(), b"a3".to_vec(), b"a4".to_vec()]
        );
        // A bounded read honors `max`.
        let two = wal.read_stream(&b, 1, 2).unwrap();
        assert_eq!(
            two.iter().map(|r| r.payload.to_vec()).collect::<Vec<_>>(),
            vec![b"b1".to_vec(), b"b2".to_vec()]
        );
    }

    /// Restarting the shared WAL reconstructs EACH stream's committed record sequence correctly, from
    /// the shared log alone — the derived index is rebuilt by demultiplexing tags (invariant 2).
    #[test]
    fn recovery_rebuilds_each_streams_cursor_from_the_shared_log() {
        let fs = InMemoryFs::new();
        let a = named("alpha");
        let b = named("beta");
        let c = named("gamma");
        {
            let (mut wal, _) = open(&fs);
            for id in [&a, &b, &c] {
                wal.declare(id).unwrap();
            }
            // Different counts per stream so a mis-assembled demux would surface as the wrong sequence.
            for i in 0..2u8 {
                wal.append_to(&a, &rec(format!("a{i}").as_bytes())).unwrap();
            }
            for i in 0..4u8 {
                wal.append_to(&b, &rec(format!("b{i}").as_bytes())).unwrap();
            }
            wal.append_to(&c, &rec(b"c0")).unwrap();
            wal.sync().unwrap();
        }
        // Reopen over the same durable image: the index is rebuilt from the shared log's tags.
        let (wal, recovery) = open(&fs);
        assert!(recovery.loss_report.is_empty(), "clean recovery");
        assert_eq!(recovery.undecodable_tag_records, 0);
        assert_eq!(recovery.stream_record_counts[&a], 2);
        assert_eq!(recovery.stream_record_counts[&b], 4);
        assert_eq!(recovery.stream_record_counts[&c], 1);
        // And each stream reads back exactly its own records, in order, after the restart.
        assert_eq!(
            wal.read_stream(&a, 0, 100)
                .unwrap()
                .iter()
                .map(|r| r.payload.to_vec())
                .collect::<Vec<_>>(),
            vec![b"a0".to_vec(), b"a1".to_vec()]
        );
        assert_eq!(
            wal.read_stream(&b, 0, 100)
                .unwrap()
                .iter()
                .map(|r| r.payload.to_vec())
                .collect::<Vec<_>>(),
            vec![
                b"b0".to_vec(),
                b"b1".to_vec(),
                b"b2".to_vec(),
                b"b3".to_vec()
            ]
        );
        assert_eq!(
            wal.read_stream(&c, 0, 100).unwrap()[0].payload.as_ref(),
            b"c0"
        );
    }

    /// THE DENSITY WIN, measured: MANY streams in shared mode cost ONE segment set / a HANDFUL of
    /// files, where an equivalent per-stream [`StreamSet`] costs one subtree PER stream. We count the
    /// actual on-disk files on both sides.
    #[test]
    fn shared_wal_uses_far_fewer_files_than_per_stream_logs() {
        const N: usize = 40;

        // Shared WAL: one record per stream to N streams, all in the ONE commit log.
        let shared_fs = InMemoryFs::new();
        {
            let (mut wal, _) = open(&shared_fs);
            for i in 0..N {
                let id = named(&format!("s{i}"));
                wal.declare(&id).unwrap();
                wal.append_to(&id, &rec(b"one")).unwrap();
            }
            wal.sync().unwrap();
            // ONE shared segment set (a single active segment for these tiny records) serves all N.
            assert_eq!(
                wal.segment_count(),
                1,
                "all {N} streams share one active segment"
            );
            assert_eq!(wal.stream_count(), N);
        }
        // Count the shared WAL's segment files under shared-wal/.
        let shared_seg_files = shared_fs
            .subdir(SHARED_WAL_SUBDIR)
            .unwrap()
            .list()
            .unwrap()
            .into_iter()
            .filter(|f| f.starts_with("seg-"))
            .count();

        // Per-stream StreamSet: the same N streams, each its own log under streams/<hex>/.
        let per_stream_fs = InMemoryFs::new();
        {
            let (mut set, _) = StreamSet::open(&per_stream_fs, ManualClock::new(), cfg()).unwrap();
            for i in 0..N {
                let id = named(&format!("s{i}"));
                set.declare(&id).unwrap();
                set.append_to(&id, &rec(b"one")).unwrap();
            }
            set.sync_all().unwrap();
        }
        // Count the per-stream segment files: at least one per stream subdir.
        let streams_fs = per_stream_fs.subdir("streams").unwrap();
        let mut per_stream_seg_files = 0usize;
        for i in 0..N {
            let sub = streams_fs
                .subdir(&stream_subdir_name(&format!("s{i}")))
                .unwrap();
            per_stream_seg_files += sub
                .list()
                .unwrap()
                .into_iter()
                .filter(|f| f.starts_with("seg-"))
                .count();
        }

        assert!(
            per_stream_seg_files >= N,
            "per-stream logs cost at least one segment file per stream (got {per_stream_seg_files})"
        );
        assert!(
            shared_seg_files < per_stream_seg_files,
            "shared WAL uses fewer segment files ({shared_seg_files}) than per-stream logs \
             ({per_stream_seg_files})"
        );
        assert_eq!(
            shared_seg_files, 1,
            "one shared segment file for all {N} streams"
        );
    }

    /// A torn tail on the shared commit log is truncated fail-closed (its loss reported), and the
    /// surviving durable prefix per stream is reconstructed correctly — the shared, not per-stream,
    /// isolation contract, made explicit.
    #[test]
    fn a_torn_shared_tail_fails_closed_and_recovers_the_valid_prefix() {
        let fs = InMemoryFs::new();
        let a = named("alpha");
        let b = named("beta");
        {
            let (mut wal, _) = open(&fs);
            wal.declare(&a).unwrap();
            wal.declare(&b).unwrap();
            wal.append_to(&a, &rec(b"a0")).unwrap();
            wal.append_to(&b, &rec(b"b0")).unwrap();
            wal.append_to(&a, &rec(b"a1")).unwrap();
            wal.sync().unwrap();
        }
        // Tear 3 bytes off the END of the shared commit log's active segment 0.
        let shared = fs.subdir(SHARED_WAL_SUBDIR).unwrap();
        let seg = shared.open(&segment_file_name(0)).unwrap();
        let torn = seg.len().unwrap() - 3;
        seg.set_len(torn).unwrap();
        seg.sync_data().unwrap();

        // Reopen: the torn last record is truncated, loss is reported, and the valid prefix survives.
        let (wal, recovery) = open(&fs);
        assert!(
            recovery.recovered_truncated_bytes > 0,
            "the torn tail was truncated"
        );
        assert!(!recovery.loss_report.is_empty(), "the loss is reported");
        // a0 and b0 survived (a1 was the torn last record).
        assert_eq!(
            wal.read_stream(&a, 0, 100).unwrap()[0].payload.as_ref(),
            b"a0"
        );
        assert_eq!(wal.stream_len(&a), 1, "a1 was lost with the torn tail");
        assert_eq!(
            wal.read_stream(&b, 0, 100).unwrap()[0].payload.as_ref(),
            b"b0"
        );
    }

    /// Reads never return a not-yet-durable record: appended-but-unsynced records are invisible until
    /// a `sync`, and a fresh open reconstructs only what was durable.
    #[test]
    fn reads_stop_at_the_durable_head() {
        let fs = InMemoryFs::new();
        let (mut wal, _) = open(&fs);
        let a = named("alpha");
        wal.declare(&a).unwrap();
        wal.append_to(&a, &rec(b"a0")).unwrap();
        wal.append_to(&a, &rec(b"a1")).unwrap();
        // Before sync: the index knows 2 records, but neither is durable, so the read is empty.
        assert_eq!(wal.stream_len(&a), 2);
        assert!(wal.read_stream(&a, 0, 100).unwrap().is_empty());
        wal.sync().unwrap();
        assert_eq!(wal.read_stream(&a, 0, 100).unwrap().len(), 2);
    }

    /// The default stream is never routable into the shared WAL (it is the engine's root log): declare
    /// and append both reject it, and an undeclared stream fails closed rather than silently minting.
    #[test]
    fn default_stream_rejected_and_undeclared_fails_closed() {
        let fs = InMemoryFs::new();
        let (mut wal, _) = open(&fs);
        assert!(wal.declare(&StreamId::default_stream()).is_err());
        assert!(wal
            .append_to(&StreamId::default_stream(), &rec(b"x"))
            .is_err());
        // An undeclared named stream is a typed error on append and read (no silent new stream).
        let ghost = named("ghost");
        assert!(wal.append_to(&ghost, &rec(b"x")).is_err());
        assert!(wal.read_stream(&ghost, 0, 1).is_err());
    }

    /// The shared WAL syncs ALL streams with ONE fdatasync (the density win on commits): dirtying many
    /// streams and committing costs a single barrier, not one per stream.
    #[test]
    fn one_fdatasync_commits_every_stream() {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let (mut wal, _) = SharedWal::open(&fs, ManualClock::new(), cfg()).unwrap();
        let ids: Vec<StreamId> = (0..8).map(|i| named(&format!("s{i}"))).collect();
        for id in &ids {
            wal.declare(id).unwrap();
        }
        for id in &ids {
            wal.append_to(id, &rec(b"r")).unwrap();
        }
        let before = control.sync_count();
        wal.sync().unwrap();
        assert_eq!(
            control.sync_count() - before,
            1,
            "one fdatasync commits all {} streams",
            ids.len()
        );
    }
}
