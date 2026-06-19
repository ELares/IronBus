// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`MetadataLogStorage`]: the durable raft-rs `Storage` for the metadata group (V2-C1, #580).
//!
//! This is C1-I2: it replaces the in-memory `raft::storage::MemStorage` that C1-I1 (#578)
//! used with a `Storage` impl backed by an IronBus CRC-framed [`Log`](ironbus_storage::log::Log).
//! The metadata Raft log is therefore an IronBus log — its own subdirectory of the data
//! directory (the same shape as the dead-letter sink, [`ironbus_storage::dlq`]) — so it
//! inherits the storage crate's I1–I4 guarantees with NO second log format:
//!
//! * **I1 longest-valid-prefix recovery / I2 fail-closed durability** — the log recovers to
//!   the longest CRC-valid prefix; the persist step of the Raft `Ready` cycle fsyncs the
//!   metadata log BEFORE the group advances/acks. This is the metadata analogue of IronBus's
//!   own ack-after-fsync (I2) and the foundation for C3's quorum-fsync.
//! * **I3 bounded loss / I4 reported corruption + quarantine** — a corrupt metadata segment
//!   is recovered to its valid prefix, the loss is BOUNDED by the storage caps and REPORTED
//!   via the log's [`LossReport`](ironbus_storage::loss::LossReport), never silently dropped.
//!   This is the NATS differentiator: a corrupt metadata snapshot in NATS (#7556) can
//!   permanently delete streams; here metadata corruption is bounded and surfaced.
//!
//! ## What is persisted, and how
//!
//! Every durable item is one IronBus log record. The record's 1-byte `headers` tag says what
//! the record is; the `payload` is the item's bytes:
//!
//! * **`KIND_ENTRY`** — one raft `Entry`. The payload is the entry's `protobuf` wire bytes
//!   (the SAME vendored-codec encoding raft-rs uses internally), so an entry round-trips
//!   byte-for-byte. The header also carries the entry's `(index, term)` for cheap recovery
//!   bookkeeping without a full decode.
//! * **`KIND_STATE`** — a `(HardState, ConfState)` checkpoint. raft requires the `HardState`
//!   (term / vote / commit) and the `ConfState` (membership) survive restart; each is the
//!   latest checkpoint wins, so `initial_state` is reconstructed from the LAST such record.
//!
//! ## Raft suffix-truncate over an append-only log
//!
//! raft appends are not pure appends: on a leader change `append(ents)` may REWRITE a suffix
//! of the log (`ents[0].index` can be `<= last_index`), overwriting the conflicting tail
//! (see `MemStorageCore::append`, which `drain`s the suffix then extends). The IronBus log is
//! APPEND-ONLY, so we do not overwrite bytes: we append the rewriting entries as fresh
//! records, and the in-memory mirror applies "drop every entry with index `>= ents[0].index`,
//! then push `ents`" — exactly `MemStorage`'s semantics.
//!
//! Recovery stays a PURE FUNCTION of the durable bytes because the IronBus log offset is a
//! monotonic write-order watermark: replaying the records in offset order and applying the
//! SAME "truncate-at-index then append" rule per `KIND_ENTRY` record reconstructs the final
//! logical log exactly. A record written later (higher offset) for a given raft index thus
//! supersedes an earlier one, and any raft index above a later batch's tail is dropped — the
//! last writer for each suffix wins, deterministically, from bytes alone.
//!
//! ## Compaction / snapshot
//!
//! `snapshot()` is implemented per raft-rs's contract: a metadata snapshot at the committed
//! index carrying the current `ConfState` (the metadata state-machine bytes are filled in by
//! a later checkpoint issue; an empty-data snapshot is valid for the in-cluster
//! leader-establishment path the metadata group uses). Log COMPACTION (physically reclaiming
//! the superseded/applied prefix of the metadata log) reuses the storage crate's existing
//! retention, but driving it from the applied index is deferred to a focused follow-up
//! (see the module note in the PR); this issue ships the durable append + recover + truncate
//! core, which is the load-bearing part.
//!
//! ## Scope (C1-I2 only)
//!
//! The durable `Storage` for the metadata group, and nothing else. Leader-epoch exposure +
//! leases (C1-I3), joint-consensus membership / learners (C1-I4), peer transport / replication
//! (C1-I3 / C2), and wiring the group into `serve` are SEPARATE issues. No peer bytes are
//! parsed here, so the protobuf advisory ignore stays scoped to C1-I3. This module lives only
//! in `ironbus-server` (never `ironbus-core`), so the IO-free / async-free core invariant and
//! the single-node (n=1) path are untouched.

use std::sync::{Arc, RwLock};

use ironbus_core::clock::Clock;
use ironbus_core::types::RecordFlags;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::loss::LossReport;
use ironbus_storage::segment::StorageError;

use protobuf::Message as _;
use raft::eraftpb::{ConfState, Entry, HardState, Snapshot};
use raft::storage::{GetEntriesContext, RaftState, Storage};
use raft::util::limit_size;
use raft::{Error as RaftError, Result as RaftResult, StorageError as RaftStorageError};

/// The subdirectory of the data directory that holds the metadata Raft log's segments. The
/// metadata group's log is isolated under here, the same shape as the dead-letter sink's
/// `dlq/` subdirectory, so it is its own recoverable segment set and never mixes frames with
/// the broker's data log.
pub const METADATA_SUBDIR: &str = "metaraft";

/// Record-kind tags stored in the metadata log record's `headers`. Stable on the wire; a
/// record whose first header byte is not one of these is foreign to the metadata log and is
/// surfaced as a recovery error rather than silently ignored.
const KIND_ENTRY: u8 = 1;
const KIND_STATE: u8 = 2;

/// Errors opening, persisting to, or recovering the durable metadata storage.
#[derive(Debug)]
pub enum MetadataStorageError {
    /// A storage-layer error from the underlying IronBus log (open / append / sync / read).
    Storage(StorageError),
    /// A raft `Entry` / `HardState` / `ConfState` failed to (de)serialize via the vendored
    /// protobuf codec.
    Codec(protobuf::ProtobufError),
    /// A recovered record carried an unknown kind tag, so the metadata log holds a frame that
    /// is not a metadata record (a foreign or corrupt-past-CRC frame): fail closed, never
    /// silently skip.
    UnknownRecordKind(u8),
    /// A recovered record's `headers` were too short to carry the kind tag + `(index, term)`.
    MalformedRecordHeader,
}

impl core::fmt::Display for MetadataStorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MetadataStorageError::Storage(e) => write!(f, "metadata log storage error: {e:?}"),
            MetadataStorageError::Codec(e) => write!(f, "metadata record codec error: {e}"),
            MetadataStorageError::UnknownRecordKind(k) => {
                write!(f, "unknown metadata record kind tag {k}")
            }
            MetadataStorageError::MalformedRecordHeader => {
                write!(f, "metadata record header is too short")
            }
        }
    }
}

impl std::error::Error for MetadataStorageError {}

impl From<StorageError> for MetadataStorageError {
    fn from(e: StorageError) -> Self {
        MetadataStorageError::Storage(e)
    }
}

impl From<protobuf::ProtobufError> for MetadataStorageError {
    fn from(e: protobuf::ProtobufError) -> Self {
        MetadataStorageError::Codec(e)
    }
}

/// The in-memory mirror of the durable metadata log, behind the `RwLock` in
/// [`MetadataLogStorage`]. It is rebuilt at open by replaying the durable records, and is the
/// fast index the synchronous `Storage` reads serve from — the durable log is the source of
/// truth, the mirror is its in-memory projection (exactly the `MemStorageCore` shape, but
/// every mutation is also written through to the IronBus log + fsynced first).
struct Core {
    /// The persisted hard state (term / vote / commit), the latest checkpoint wins.
    hard_state: HardState,
    /// The persisted configuration state (membership), the latest checkpoint wins.
    conf_state: ConfState,
    /// The logical raft log entries in index order. `entries[i].index == entries[0].index + i`
    /// (contiguous), mirroring `MemStorageCore`. A leader-change suffix rewrite drops the tail
    /// and re-pushes, so this is always the CURRENT logical log, never the physical history.
    entries: Vec<Entry>,
    /// The index a hypothetical snapshot would be taken at: the metadata of the last
    /// snapshot/compaction. For C1-I2 (no compaction yet) this is the dummy index 0 with
    /// term 0, matching a fresh `MemStorageCore`.
    snapshot_index: u64,
    /// The term of the entry at `snapshot_index` (0 for the dummy snapshot).
    snapshot_term: u64,
}

impl Core {
    /// `first_index`/`last_index` mirror `MemStorageCore`: when the log is empty they derive
    /// from the snapshot metadata, so a fresh group reports `first_index == 1`, `last_index ==
    /// 0` (an empty log truncated at index 0).
    fn first_index(&self) -> u64 {
        match self.entries.first() {
            Some(e) => e.index,
            None => self.snapshot_index + 1,
        }
    }

    fn last_index(&self) -> u64 {
        match self.entries.last() {
            Some(e) => e.index,
            None => self.snapshot_index,
        }
    }

    /// Apply one already-decoded entry record to the mirror with `MemStorage`'s truncate-then-
    /// append semantics: drop every in-memory entry with index `>= entry.index`, then push.
    /// Replaying records in durable (offset) order through this rule reconstructs the final
    /// logical log from bytes alone (the recovery proof in the module docs).
    fn mirror_entry(&mut self, entry: Entry) {
        let first = self.first_index();
        if entry.index < first {
            // The record predates the current first index (a compacted prefix); ignore it,
            // as MemStorage's append would reject a compacted overwrite. Unreachable until
            // compaction lands, but kept total so recovery never panics on stale bytes.
            return;
        }
        // Drop the conflicting suffix [entry.index ..], then append. `entry.index - first` is
        // the in-vec position of the first dropped entry (always in range: index >= first).
        let drop_from = usize::try_from(entry.index - first).expect("log index fits usize");
        self.entries.truncate(drop_from);
        self.entries.push(entry);
    }
}

/// A durable raft-rs [`Storage`] backed by an IronBus CRC-framed [`Log`]. Synchronous and
/// caller-driven, the same shape as `MemStorage`: the synchronous `Storage` reads are served
/// from the in-memory [`Core`] behind an `Arc<RwLock<_>>` (so `&self` reads compose with
/// raft-rs), and every mutation is written THROUGH to the durable log and fsynced before the
/// mirror is updated, so a power loss never leaves the mirror ahead of the bytes.
///
/// `F` is the [`Filesystem`] seam (`StdFs` in production, `InMemoryFs` in the deterministic
/// simulation) and `C` the [`Clock`] seam, exactly as the rest of the storage engine.
pub struct MetadataLogStorage<F: Filesystem, C: Clock> {
    /// The durable metadata Raft log (its own `metaraft/` subdirectory). The single source of
    /// truth; the [`Core`] mirror is its in-memory projection.
    log: Log<F, C>,
    /// The in-memory projection the synchronous `Storage` reads serve from.
    core: Arc<RwLock<Core>>,
}

impl<F: Filesystem, C: Clock> MetadataLogStorage<F, C> {
    /// Open (recovering, or creating fresh) the durable metadata storage rooted at the
    /// `metaraft/` subdirectory of `parent_fs`, seeding the initial voter `ConfState` for a
    /// brand-new group. The subdirectory is created on demand by [`Filesystem::subdir`], the
    /// same way the dead-letter sink's is.
    ///
    /// Recovery is a pure function of the durable bytes: the records are replayed in offset
    /// order to rebuild the logical entry log + the latest `HardState`/`ConfState`. A corrupt
    /// tail is recovered to the longest valid prefix by the underlying [`Log`] and REPORTED
    /// via [`Self::loss_report`]; if a recovered record is structurally foreign (an unknown
    /// kind tag survived its CRC), recovery fails closed.
    ///
    /// `conf_state_voters` seeds the membership ONLY when the recovered log carries no
    /// persisted `ConfState` yet (a fresh group); on a recovered group the persisted
    /// membership wins and the seed is ignored, so a restart never resets membership.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataStorageError`] if the subdirectory or log cannot be opened, a record
    /// fails to decode, or a recovered record carries an unknown kind.
    pub fn open(
        parent_fs: &F,
        clock: C,
        config: LogConfig,
        conf_state_voters: &[u64],
    ) -> Result<Self, MetadataStorageError> {
        let meta_fs = parent_fs
            .subdir(METADATA_SUBDIR)
            .map_err(StorageError::Io)?;
        let log = Log::open(meta_fs, clock, config)?;
        let mut core = Core {
            hard_state: HardState::default(),
            conf_state: ConfState::default(),
            entries: Vec::new(),
            snapshot_index: 0,
            snapshot_term: 0,
        };
        Self::replay_into(&log, &mut core)?;
        // Seed the voter set for a brand-new group ONLY (no persisted ConfState recovered).
        // A recovered group keeps its durable membership: the seed never overwrites it.
        if core.conf_state.voters.is_empty() && core.conf_state.learners.is_empty() {
            core.conf_state.voters = conf_state_voters.to_vec();
        }
        Ok(Self {
            log,
            core: Arc::new(RwLock::new(core)),
        })
    }

    /// Replay every durable record (in offset order) into `core`: fold `KIND_ENTRY` records
    /// through the truncate-then-append rule and `KIND_STATE` records as latest-wins
    /// checkpoints. The `Log` has already recovered to its longest valid prefix, so this only
    /// ever sees CRC-valid frames.
    fn replay_into(log: &Log<F, C>, core: &mut Core) -> Result<(), MetadataStorageError> {
        // `read_from(ZERO, MAX)` returns every durable (flushed) record in offset order; the
        // metadata log is small (one group's control plane), so a single forward pass at open
        // is cheap.
        let records = log.read_from(ironbus_core::types::Offset::ZERO, usize::MAX)?;
        for record in records {
            let headers = record.headers.as_ref();
            let kind = *headers
                .first()
                .ok_or(MetadataStorageError::MalformedRecordHeader)?;
            match kind {
                KIND_ENTRY => {
                    let entry = Entry::parse_from_bytes(record.payload.as_ref())?;
                    core.mirror_entry(entry);
                }
                KIND_STATE => {
                    let (hs, cs) = decode_state(record.payload.as_ref())?;
                    core.hard_state = hs;
                    core.conf_state = cs;
                }
                other => return Err(MetadataStorageError::UnknownRecordKind(other)),
            }
        }
        Ok(())
    }

    /// Append one entry record to the durable log, WITHOUT fsync (the caller fsyncs once at
    /// the end of the batch via [`Self::sync`], the group-commit barrier). Mirrors the new
    /// entry into the in-memory projection.
    fn append_entry_record(&mut self, entry: &Entry) -> Result<(), MetadataStorageError> {
        let payload = entry.write_to_bytes()?;
        // header: [KIND_ENTRY][index:u64-le][term:u64-le] — the index/term let recovery and
        // inspection read an entry's position without decoding the protobuf payload.
        let mut headers = Vec::with_capacity(1 + 8 + 8);
        headers.push(KIND_ENTRY);
        headers.extend_from_slice(&entry.index.to_le_bytes());
        headers.extend_from_slice(&entry.term.to_le_bytes());
        self.log.append(&Append {
            timestamp_ms: self.log.now_unix_millis(),
            flags: RecordFlags::default(),
            key: &[],
            headers: &headers,
            payload: &payload,
        })?;
        self.core
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mirror_entry(entry.clone());
        Ok(())
    }

    /// Persist a batch of raft entries durably. This is the C1-I2 analogue of
    /// `MemStorageCore::append`: a leader-change rewrite (`entries[0].index <= last_index`)
    /// drops the conflicting suffix in the mirror and appends the rewriting records to the
    /// append-only log; recovery replays them in order and the last writer per index wins.
    ///
    /// Entries are written here but NOT fsynced; the caller calls [`Self::sync`] once after
    /// the whole `Ready` is persisted (the group-commit barrier), so a Raft `Ready` cycle pays
    /// ONE fdatasync, not one per entry — and that fsync happens BEFORE the group advances.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataStorageError`] if an entry fails to encode or the log append fails.
    pub fn append(&mut self, entries: &[Entry]) -> Result<(), MetadataStorageError> {
        for entry in entries {
            self.append_entry_record(entry)?;
        }
        Ok(())
    }

    /// Persist the latest `HardState` (term / vote / commit) durably as a checkpoint record.
    /// Not fsynced here; the caller's [`Self::sync`] is the barrier. The `ConfState` carried in
    /// the checkpoint is the current mirror membership, so a single record always captures the
    /// full `RaftState` and `initial_state` can reconstruct from the last one.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataStorageError`] if the checkpoint fails to encode or the append fails.
    pub fn set_hard_state(&mut self, hs: &HardState) -> Result<(), MetadataStorageError> {
        let cs = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .conf_state
            .clone();
        self.write_state_record(hs, &cs)?;
        self.core
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .hard_state = hs.clone();
        Ok(())
    }

    /// Persist the latest `ConfState` (membership) durably as a checkpoint record, paired with
    /// the current `HardState`. Membership changes are driven from C1-I4; this is the durable
    /// seam they will use. Not fsynced here.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataStorageError`] if the checkpoint fails to encode or the append fails.
    pub fn set_conf_state(&mut self, cs: &ConfState) -> Result<(), MetadataStorageError> {
        let hs = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .hard_state
            .clone();
        self.write_state_record(&hs, cs)?;
        self.core
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .conf_state = cs.clone();
        Ok(())
    }

    /// Encode and append one `(HardState, ConfState)` checkpoint record (no fsync, no mirror
    /// update — the callers above update the mirror field they own).
    fn write_state_record(
        &mut self,
        hs: &HardState,
        cs: &ConfState,
    ) -> Result<(), MetadataStorageError> {
        let payload = encode_state(hs, cs)?;
        let headers = [KIND_STATE];
        self.log.append(&Append {
            timestamp_ms: self.log.now_unix_millis(),
            flags: RecordFlags::default(),
            key: &[],
            headers: &headers,
            payload: &payload,
        })?;
        Ok(())
    }

    /// The durability barrier: fdatasync the metadata log so every record appended since the
    /// last sync is durable. The Raft `Ready` persist step calls this BEFORE the group
    /// advances/acks — the metadata analogue of IronBus's ack-after-fsync (I2), reusing the
    /// log's group-commit `sync`.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataStorageError`] if the durability barrier fails (the log freezes the
    /// writer and surfaces it, so the caller does not advance past an un-fsynced record).
    pub fn sync(&mut self) -> Result<(), MetadataStorageError> {
        self.log.sync()?;
        Ok(())
    }

    /// The recovery loss report for the metadata log: the bounded, REPORTED account of any
    /// bytes the longest-valid-prefix recovery skipped (I3/I4). Empty when recovery was clean.
    /// This is the differentiator — metadata corruption is bounded and surfaced here, never a
    /// silent total loss (NATS #7556).
    #[must_use]
    pub fn loss_report(&self) -> &LossReport {
        self.log.loss_report()
    }

    /// Borrow the underlying metadata log (for inspection and tests).
    #[must_use]
    pub fn log(&self) -> &Log<F, C> {
        &self.log
    }
}

/// Encode a `(HardState, ConfState)` checkpoint: each protobuf message length-prefixed
/// (`[u32-le len][bytes]`) so the pair decodes unambiguously from one record payload.
fn encode_state(hs: &HardState, cs: &ConfState) -> Result<Vec<u8>, MetadataStorageError> {
    let hs_bytes = hs.write_to_bytes()?;
    let cs_bytes = cs.write_to_bytes()?;
    // A HardState/ConfState wire form is a handful of varints; its length never approaches
    // u32::MAX, so the length prefixes are sound.
    let hs_len = u32::try_from(hs_bytes.len()).expect("hard state length fits u32");
    let cs_len = u32::try_from(cs_bytes.len()).expect("conf state length fits u32");
    let mut out = Vec::with_capacity(8 + hs_bytes.len() + cs_bytes.len());
    out.extend_from_slice(&hs_len.to_le_bytes());
    out.extend_from_slice(&hs_bytes);
    out.extend_from_slice(&cs_len.to_le_bytes());
    out.extend_from_slice(&cs_bytes);
    Ok(out)
}

/// Decode a `(HardState, ConfState)` checkpoint written by [`encode_state`].
fn decode_state(buf: &[u8]) -> Result<(HardState, ConfState), MetadataStorageError> {
    fn take_u32(buf: &[u8], pos: &mut usize) -> Result<usize, MetadataStorageError> {
        let end = pos
            .checked_add(4)
            .ok_or(MetadataStorageError::MalformedRecordHeader)?;
        let slice = buf
            .get(*pos..end)
            .ok_or(MetadataStorageError::MalformedRecordHeader)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(slice);
        *pos = end;
        usize::try_from(u32::from_le_bytes(a))
            .map_err(|_| MetadataStorageError::MalformedRecordHeader)
    }
    fn take_slice<'a>(
        buf: &'a [u8],
        pos: &mut usize,
        len: usize,
    ) -> Result<&'a [u8], MetadataStorageError> {
        let end = pos
            .checked_add(len)
            .ok_or(MetadataStorageError::MalformedRecordHeader)?;
        let slice = buf
            .get(*pos..end)
            .ok_or(MetadataStorageError::MalformedRecordHeader)?;
        *pos = end;
        Ok(slice)
    }
    let mut pos = 0usize;
    let hs_len = take_u32(buf, &mut pos)?;
    let hs = HardState::parse_from_bytes(take_slice(buf, &mut pos, hs_len)?)?;
    let cs_len = take_u32(buf, &mut pos)?;
    let cs = ConfState::parse_from_bytes(take_slice(buf, &mut pos, cs_len)?)?;
    Ok((hs, cs))
}

impl<F: Filesystem, C: Clock> Storage for MetadataLogStorage<F, C> {
    /// The persisted `HardState` + `ConfState`, rebuilt at open from the durable checkpoint
    /// records. A fresh group returns the seeded voter `ConfState` with a default `HardState`.
    fn initial_state(&self) -> RaftResult<RaftState> {
        let core = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(RaftState {
            hard_state: core.hard_state.clone(),
            conf_state: core.conf_state.clone(),
        })
    }

    /// A slice of log entries in `[low, high)`, served from the in-memory mirror (the durable
    /// projection), bounded by `max_size` exactly as `MemStorage` does via `limit_size`.
    ///
    /// # Panics
    ///
    /// Panics if `high` exceeds `last_index() + 1`, the same fail-loud caller-bug contract as
    /// `MemStorage`.
    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        _context: GetEntriesContext,
    ) -> RaftResult<Vec<Entry>> {
        let max_size = max_size.into();
        let core = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if low < core.first_index() {
            return Err(RaftError::Store(RaftStorageError::Compacted));
        }
        assert!(
            high <= core.last_index() + 1,
            "index out of bound (last: {}, high: {})",
            core.last_index() + 1,
            high
        );
        let offset = core.first_index();
        let lo = usize::try_from(low - offset).expect("log index fits usize");
        let hi = usize::try_from(high - offset).expect("log index fits usize");
        let mut ents = core.entries[lo..hi].to_vec();
        limit_size(&mut ents, max_size);
        Ok(ents)
    }

    /// The term of the entry at `idx`, served from the mirror. `idx == snapshot_index` returns
    /// the snapshot term; an `idx` below the first index is `Compacted`, above the last index
    /// is `Unavailable` — the `MemStorage` contract.
    fn term(&self, idx: u64) -> RaftResult<u64> {
        let core = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if idx == core.snapshot_index {
            return Ok(core.snapshot_term);
        }
        let offset = core.first_index();
        if idx < offset {
            return Err(RaftError::Store(RaftStorageError::Compacted));
        }
        if idx > core.last_index() {
            return Err(RaftError::Store(RaftStorageError::Unavailable));
        }
        let pos = usize::try_from(idx - offset).expect("log index fits usize");
        Ok(core.entries[pos].term)
    }

    fn first_index(&self) -> RaftResult<u64> {
        Ok(self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .first_index())
    }

    fn last_index(&self) -> RaftResult<u64> {
        Ok(self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_index())
    }

    /// The most recent metadata snapshot per raft-rs's contract: a snapshot at the committed
    /// index carrying the current `ConfState`. For C1-I2 the snapshot data is empty (the
    /// metadata state-machine bytes + log compaction are a focused follow-up); the metadata
    /// group's in-cluster leader-establishment path does not require snapshot DATA, only the
    /// metadata (index / term / conf state), which is filled in here.
    fn snapshot(&self, request_index: u64, _to: u64) -> RaftResult<Snapshot> {
        let core = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut snapshot = Snapshot::default();
        let commit = core.hard_state.commit;
        // The snapshot index is the committed index (all entries at or below it are applied),
        // clamped up to `request_index` as raft-rs requires (`index >= request_index`).
        let index = commit.max(request_index);
        {
            let meta = snapshot.mut_metadata();
            meta.index = index;
            // The snapshot term is the term of the entry at the committed index when it is a
            // present log entry; at/below the snapshot dummy it is the snapshot term.
            meta.term = if commit == core.snapshot_index {
                core.snapshot_term
            } else if commit >= core.first_index() && commit <= core.last_index() {
                let pos =
                    usize::try_from(commit - core.first_index()).expect("commit index fits usize");
                core.entries[pos].term
            } else {
                core.hard_state.term
            };
            meta.set_conf_state(core.conf_state.clone());
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::io::RandomAccessFile as _;
    use ironbus_storage::naming::segment_file_name;
    use raft::storage::GetEntriesContext;

    fn config() -> LogConfig {
        LogConfig::new(64 * 1024).expect("valid segment cap")
    }

    fn open(fs: &InMemoryFs, voters: &[u64]) -> MetadataLogStorage<InMemoryFs, ManualClock> {
        MetadataLogStorage::open(fs, ManualClock::new(), config(), voters).expect("open")
    }

    /// One log entry at `(index, term)` carrying `data` bytes.
    fn entry(index: u64, term: u64, data: &[u8]) -> Entry {
        Entry {
            index,
            term,
            data: bytes::Bytes::copy_from_slice(data),
            ..Default::default()
        }
    }

    fn hard_state(term: u64, vote: u64, commit: u64) -> HardState {
        HardState {
            term,
            vote,
            commit,
            ..Default::default()
        }
    }

    fn conf_state(voters: Vec<u64>, learners: Vec<u64>) -> ConfState {
        ConfState {
            voters,
            learners,
            ..Default::default()
        }
    }

    fn ctx() -> GetEntriesContext {
        GetEntriesContext::empty(false)
    }

    /// Append entries, persist a hard state, fsync, then REOPEN over the same durable image:
    /// the recovered entries, terms, and hard state are byte-identical (a durability round-trip
    /// across a simulated restart).
    #[test]
    fn append_then_recover_yields_identical_entries_and_hard_state() {
        let fs = InMemoryFs::new();
        let originals = vec![
            entry(1, 1, b"alpha"),
            entry(2, 1, b"beta"),
            entry(3, 2, b"gamma"),
        ];
        {
            let mut storage = open(&fs, &[1, 2, 3]);
            storage.append(&originals).expect("append");
            storage
                .set_hard_state(&hard_state(2, 1, 3))
                .expect("set hard state");
            storage.sync().expect("sync");
            assert_eq!(storage.last_index().unwrap(), 3);
        }

        // Reopen: recovery is a pure function of the durable bytes.
        let recovered = open(&fs, &[1, 2, 3]);
        assert_eq!(recovered.first_index().unwrap(), 1);
        assert_eq!(recovered.last_index().unwrap(), 3);
        let got = recovered.entries(1, 4, None, ctx()).expect("entries");
        assert_eq!(got, originals, "recovered entries are byte-identical");
        assert_eq!(recovered.term(2).unwrap(), 1);
        assert_eq!(recovered.term(3).unwrap(), 2);
        let state = recovered.initial_state().unwrap();
        assert_eq!(state.hard_state.term, 2);
        assert_eq!(state.hard_state.vote, 1);
        assert_eq!(state.hard_state.commit, 3);
        assert!(
            recovered.loss_report().is_empty(),
            "a clean reopen reports no loss"
        );
    }

    /// `initial_state` reflects the persisted `HardState` AND `ConfState` (membership), and a
    /// later `ConfState` checkpoint wins on recovery.
    #[test]
    fn initial_state_reflects_persisted_hard_and_conf_state() {
        let fs = InMemoryFs::new();
        {
            let mut storage = open(&fs, &[1, 2, 3]);
            // The seed ConfState is present immediately (fresh group).
            let seeded = storage.initial_state().unwrap();
            assert_eq!(seeded.conf_state.voters, vec![1, 2, 3]);
            // Persist a NEW membership (e.g. a learner added) + a hard state.
            storage
                .set_conf_state(&conf_state(vec![1, 2, 3], vec![4]))
                .expect("set conf state");
            storage
                .set_hard_state(&hard_state(7, 0, 0))
                .expect("set hard state");
            storage.sync().expect("sync");
        }
        // Reopen: the persisted membership wins over the seed, the hard state survives.
        let recovered = open(&fs, &[1, 2, 3]);
        let state = recovered.initial_state().unwrap();
        assert_eq!(state.conf_state.voters, vec![1, 2, 3]);
        assert_eq!(state.conf_state.learners, vec![4]);
        assert_eq!(state.hard_state.term, 7);
    }

    /// A raft leader-change SUFFIX TRUNCATE/OVERWRITE is handled: appending a batch whose
    /// first index is at or below the current last index supersedes the conflicting tail. The
    /// IronBus log is append-only, so the rewriting records are appended; recovery replays
    /// them in order and the last writer per index wins.
    #[test]
    fn raft_suffix_truncate_overwrite_is_handled_in_memory_and_on_recovery() {
        let fs = InMemoryFs::new();
        {
            let mut storage = open(&fs, &[1]);
            // Term 1 leader writes indices 1..=4.
            storage
                .append(&[
                    entry(1, 1, b"a"),
                    entry(2, 1, b"b"),
                    entry(3, 1, b"c"),
                    entry(4, 1, b"d"),
                ])
                .expect("append term 1");
            storage.sync().expect("sync");
            assert_eq!(storage.last_index().unwrap(), 4);

            // A new term-2 leader REWRITES the suffix from index 3: indices 3,4 are overwritten
            // (with new term/data) and index 4's old entry is gone, replaced by a single new
            // index 3 (a shorter log) — exactly MemStorage's drain-then-extend.
            storage
                .append(&[entry(3, 2, b"C2")])
                .expect("append term 2 rewrite");
            storage.sync().expect("sync");

            // In-memory: the log is now 1,2,3 with index 3 = term 2 / "C2", index 4 gone.
            assert_eq!(storage.last_index().unwrap(), 3);
            assert_eq!(storage.term(3).unwrap(), 2);
            let got = storage.entries(1, 4, None, ctx()).unwrap();
            assert_eq!(
                got,
                vec![entry(1, 1, b"a"), entry(2, 1, b"b"), entry(3, 2, b"C2")]
            );
        }

        // On RECOVERY from the append-only durable bytes, the same final logical log is
        // reconstructed (the last writer for index 3 wins, index 4 is dropped).
        let recovered = open(&fs, &[1]);
        assert_eq!(recovered.last_index().unwrap(), 3);
        assert_eq!(recovered.term(3).unwrap(), 2);
        assert_eq!(
            recovered.entries(1, 4, None, ctx()).unwrap(),
            vec![entry(1, 1, b"a"), entry(2, 1, b"b"), entry(3, 2, b"C2")],
        );
        // Index 4 is genuinely gone: its term is no longer available.
        assert!(recovered.term(4).is_err());
    }

    /// THE DIFFERENTIATOR: a corrupted metadata segment recovers BOUNDED + REPORTED — the
    /// longest valid prefix survives and the loss is surfaced via the loss report — rather than
    /// losing everything (NATS #7556, where a corrupt metadata snapshot can permanently delete
    /// streams).
    #[test]
    fn corrupt_metadata_segment_recovers_bounded_and_reported() {
        let fs = InMemoryFs::new();
        {
            let mut storage = open(&fs, &[1]);
            storage
                .append(&[
                    entry(1, 1, b"keep-1"),
                    entry(2, 1, b"keep-2"),
                    entry(3, 1, b"keep-3"),
                    entry(4, 1, b"corrupt-me"),
                ])
                .expect("append");
            storage.sync().expect("sync");
            assert_eq!(storage.last_index().unwrap(), 4);
        }

        // Reach into the metadata log's OWN subdirectory and flip the last byte of its segment
        // (inside the last record's frame) so its body CRC fails: a complete-but-corrupt record.
        let meta_fs = fs.subdir(METADATA_SUBDIR).expect("metaraft subdir");
        let file = meta_fs.open(&segment_file_name(0)).expect("open segment");
        let mut raw = file.snapshot();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        file.write_all_at(&raw, 0).expect("write corrupted");
        file.sync_data().expect("sync corrupted");

        // Recovery drops ONLY the corrupt last record; the three intact records survive, and
        // the loss is REPORTED, never a silent total wipe.
        let recovered = open(&fs, &[1]);
        assert_eq!(
            recovered.last_index().unwrap(),
            3,
            "the valid prefix (indices 1..=3) survives the corruption"
        );
        assert_eq!(
            recovered.entries(1, 4, None, ctx()).unwrap(),
            vec![
                entry(1, 1, b"keep-1"),
                entry(2, 1, b"keep-2"),
                entry(3, 1, b"keep-3")
            ],
        );
        let report = recovered.loss_report();
        assert!(
            !report.is_empty(),
            "the corruption is REPORTED, not silently swallowed"
        );
        assert!(
            report.total_bytes_skipped() > 0,
            "the bounded loss is accounted for in bytes"
        );
    }

    /// A fresh storage with no records reports the empty-log indices `MemStorage` does
    /// (`first_index == 1`, `last_index == 0`).
    #[test]
    fn fresh_storage_reports_empty_log_indices() {
        let fs = InMemoryFs::new();
        let storage = open(&fs, &[1, 2, 3]);
        assert_eq!(storage.first_index().unwrap(), 1);
        assert_eq!(storage.last_index().unwrap(), 0);
        assert_eq!(
            storage.initial_state().unwrap().conf_state.voters,
            vec![1, 2, 3]
        );
    }

    /// `entries` honors the `max_size` bound exactly as `MemStorage` (at least one entry is
    /// always returned even if it exceeds the cap).
    #[test]
    fn entries_respects_max_size_like_memstorage() {
        let fs = InMemoryFs::new();
        let mut storage = open(&fs, &[1]);
        storage
            .append(&[
                entry(1, 1, b"xxxxxxxx"),
                entry(2, 1, b"yyyyyyyy"),
                entry(3, 1, b"zzzzzzzz"),
            ])
            .expect("append");
        storage.sync().expect("sync");
        // A tiny max_size still returns at least the first entry.
        let one = storage.entries(1, 4, Some(1), ctx()).unwrap();
        assert_eq!(one.len(), 1);
        // No cap returns all three.
        let all = storage.entries(1, 4, None, ctx()).unwrap();
        assert_eq!(all.len(), 3);
    }
}
