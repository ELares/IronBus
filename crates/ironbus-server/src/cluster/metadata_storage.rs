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
//! ## Compaction / snapshot (#660)
//!
//! `snapshot()` serves a raft-rs snapshot at the committed index carrying the current `ConfState`
//! AND the serialized metadata state-machine bytes (in `Snapshot.data`), so a far-behind learner
//! receives a complete point-in-time cut instead of the whole log. The snapshot is persisted
//! durably to a DUAL-SLOT CRC checkpoint
//! ([`MetadataSnapshotCheckpoint`](ironbus_storage::checkpoint::MetadataSnapshotCheckpoint)) in the
//! `metaraft/` subdirectory — the same crash-safe discipline as the cursor/attempts/producer-seq
//! checkpoints — and the in-memory mirror is COMPACTED (its log prefix at or below the snapshot
//! index is dropped) and the underlying log's now-superseded prefix segments are physically
//! reclaimed. The crash-safe ORDER is non-negotiable: the snapshot is fsynced to its checkpoint
//! BEFORE the log prefix is dropped, so a crash mid-compaction leaves either {prior snapshot + full
//! log} or {new snapshot + (truncated) log} — never a gap where neither holds the committed state.
//!
//! On RECOVERY the snapshot checkpoint is read FIRST (installing its state-machine bytes, index,
//! term, and `ConfState`), then the log records are replayed: any `KIND_ENTRY` record at or below
//! the snapshot index is ignored (the existing `mirror_entry` compacted-prefix guard), so only the
//! TAIL above the snapshot folds on top. A node restored from {snapshot + tail} therefore holds the
//! EXACT committed metadata state it would by replaying the full log (#660 non-negotiable 1).
//! A torn or missing snapshot checkpoint recovers as "no snapshot" and the node simply replays the
//! full retained log (the pre-#660 path), so the snapshot is never load-bearing for correctness on
//! its own — it is an optimization layered over the already-correct durable log.
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
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::checkpoint::MetadataSnapshotCheckpoint;
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

/// The filename of the dual-slot CRC metadata-snapshot checkpoint (#660), inside the `metaraft/`
/// subdirectory alongside the log segments. Holds the most recent durable raft `Snapshot` (its
/// index/term/`ConfState` + the metadata state-machine bytes); recovery reads it before replaying
/// the log so the retained tail folds onto the snapshot.
const SNAPSHOT_CHECKPOINT: &str = "snapshot.ckpt";

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
    /// The index the last snapshot/compaction was taken at: the metadata of the last snapshot. A
    /// fresh group (no compaction yet) is the dummy index 0 with term 0, matching a fresh
    /// `MemStorageCore`. After a compaction at index N this is N and `entries.first().index` is
    /// `N + 1` (or the log is empty and `first_index() == N + 1`).
    snapshot_index: u64,
    /// The term of the entry at `snapshot_index` (0 for the dummy snapshot).
    snapshot_term: u64,
    /// The serialized metadata STATE-MACHINE bytes of the last installed/created snapshot (#660):
    /// the `Snapshot.data` payload [`MetadataStateMachine::snapshot`](crate::cluster::state_machine::MetadataStateMachine::snapshot)
    /// produced at `snapshot_index`. Empty for the dummy (pre-compaction) snapshot. Served back in
    /// [`Storage::snapshot`] so a far-behind learner receives the committed state, not just the
    /// metadata. The group fills this in via [`MetadataLogStorage::install_snapshot_state`] when it
    /// creates a snapshot from its applied state machine, and `apply_snapshot` sets it from a
    /// received snapshot.
    snapshot_data: Vec<u8>,
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

    /// Install a received snapshot into the mirror — the raft-rs `MemStorageCore::apply_snapshot`
    /// contract (#660): adopt the snapshot's `(index, term)` as the new snapshot metadata, set the
    /// hard-state commit to the snapshot index and raise the term, REPLACE the `ConfState` with the
    /// snapshot's, store the snapshot DATA, and CLEAR the log (every entry the snapshot subsumes is
    /// gone; the tail above it arrives by replication). Returns the snapshot index so the caller
    /// can compute the log offset to physically reclaim.
    ///
    /// Refuses (returns `false`) a STALE snapshot whose index is below our current first index — we
    /// already hold that state and a newer tail, so installing it would REGRESS committed state
    /// (the `SnapshotOutOfDate` guard). The caller surfaces this fail-closed.
    fn apply_snapshot(&mut self, index: u64, term: u64, conf_state: ConfState, data: Vec<u8>) -> bool {
        if self.first_index() > index {
            return false; // stale snapshot: we already have this and more.
        }
        self.snapshot_index = index;
        self.snapshot_term = term;
        self.snapshot_data = data;
        self.hard_state.term = self.hard_state.term.max(term);
        self.hard_state.commit = index;
        self.conf_state = conf_state;
        self.entries.clear();
        true
    }

    /// Compact the mirror's log PREFIX up to (but not including) `compact_index` — the raft-rs
    /// `MemStorageCore::compact` contract (#660): drop every in-memory entry strictly below
    /// `compact_index`, and record `(compact_index - 1, its term)` as the new snapshot metadata so
    /// `first_index()`/`term()` stay correct against the compacted log. `compact_index` must be at
    /// or below the COMMITTED + applied frontier (the caller enforces this); a no-op if it is at or
    /// below the current first index.
    ///
    /// The new snapshot's term is the term of the entry at `compact_index - 1` (the last entry the
    /// snapshot subsumes), read from the mirror BEFORE the prefix is dropped, so a later `term()`
    /// query at the snapshot index returns the right term.
    fn compact(&mut self, compact_index: u64) {
        let first = self.first_index();
        if compact_index <= first {
            return; // nothing below the current first index to drop.
        }
        // The snapshot index is one below the new first index; its term is the term of that entry.
        let new_snapshot_index = compact_index - 1;
        // `new_snapshot_index` is in [first, last]; locate it in the mirror to read its term.
        let pos = usize::try_from(new_snapshot_index - first).expect("compact index fits usize");
        self.snapshot_term = self.entries[pos].term;
        self.snapshot_index = new_snapshot_index;
        // Drop entries [first ..= new_snapshot_index] — i.e. the first `pos + 1` entries.
        self.entries.drain(..=pos);
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
    /// The dual-slot CRC checkpoint that durably holds the most recent metadata snapshot (#660),
    /// in the `metaraft/` subdirectory alongside the log. Written (fsync) BEFORE the log prefix is
    /// compacted, so a crash mid-compaction is always recoverable.
    snapshot_checkpoint: MetadataSnapshotCheckpoint<F::File>,
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
            snapshot_data: Vec::new(),
        };

        // RECOVER THE SNAPSHOT FIRST (#660), so the log replay below folds only the TAIL above the
        // snapshot index onto it. The checkpoint is opened (creating it if absent) through the
        // metadata log's OWN filesystem (the `metaraft/` subdir), the same create-then-dir-sync
        // discipline the engine uses for its cursor/attempts/producer-seq checkpoints. A torn or
        // missing snapshot recovers as None, so the node falls back to a full-log replay — the
        // snapshot is never load-bearing for correctness on its own.
        let snapshot_checkpoint = {
            let fs = log.filesystem();
            let file = if fs.exists(SNAPSHOT_CHECKPOINT).map_err(StorageError::Io)? {
                fs.open(SNAPSHOT_CHECKPOINT).map_err(StorageError::Io)?
            } else {
                let file = fs.create_new(SNAPSHOT_CHECKPOINT).map_err(StorageError::Io)?;
                fs.sync_dir().map_err(StorageError::Io)?; // the new file's dir entry must be durable
                file
            };
            let (checkpoint, recovered) = MetadataSnapshotCheckpoint::open(file)?;
            if let Some(bytes) = recovered {
                let snapshot = Snapshot::parse_from_bytes(&bytes)?;
                install_snapshot_into_core(&mut core, &snapshot);
            }
            checkpoint
        };

        Self::replay_into(&log, &mut core)?;
        // Seed the voter set for a brand-new group ONLY (no persisted ConfState recovered AND no
        // snapshot installed one). A recovered group — log OR snapshot — keeps its durable
        // membership: the seed never overwrites it.
        if core.conf_state.voters.is_empty() && core.conf_state.learners.is_empty() {
            core.conf_state.voters = conf_state_voters.to_vec();
        }
        Ok(Self {
            log,
            core: Arc::new(RwLock::new(core)),
            snapshot_checkpoint,
        })
    }

    /// Replay every durable record (in offset order) into `core`: fold `KIND_ENTRY` records
    /// through the truncate-then-append rule and `KIND_STATE` records as latest-wins
    /// checkpoints. The `Log` has already recovered to its longest valid prefix, so this only
    /// ever sees CRC-valid frames.
    fn replay_into(log: &Log<F, C>, core: &mut Core) -> Result<(), MetadataStorageError> {
        // Read every durable (flushed) record in offset order, starting at the EARLIEST retained
        // offset (which rises past 0 once compaction has reaped prefix segments — reading from a
        // reaped offset is `OffsetOutOfRange`). The metadata log is small (one group's control
        // plane), so a single forward pass at open is cheap.
        let records = log.read_from(log.earliest_offset(), usize::MAX)?;
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
                    // Latest STATE record wins — EXCEPT it can never REGRESS the commit/term below
                    // an installed snapshot (#660). A snapshot is persisted before the log prefix is
                    // compacted, so a crash can leave a snapshot whose committed frontier is AHEAD of
                    // the newest surviving STATE record; the snapshot's frontier is the floor (the
                    // committed bar only ever rises), so a recovered node never re-admits a
                    // below-snapshot commit. ConfState always takes the latest STATE record's value
                    // (a tail conf-change is newer than the snapshot's membership).
                    core.hard_state.term = hs.term.max(core.hard_state.term);
                    core.hard_state.commit = hs.commit.max(core.hard_state.commit);
                    core.hard_state.vote = hs.vote;
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

    /// The index of the last snapshot/compaction (the dummy index 0 before any compaction). Every
    /// log entry at or below this is subsumed by the durable snapshot; the retained log is the tail
    /// above it. The group reads this to know whether it has caught the snapshot up to its applied
    /// state.
    #[must_use]
    pub fn snapshot_index(&self) -> u64 {
        self.core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot_index
    }

    /// CREATE + persist a metadata snapshot at `index` carrying the serialized state-machine
    /// `data`, then COMPACT the log up to it (#660). This is the leader/driver-cadence path: the
    /// caller passes the bytes of its applied [`MetadataStateMachine::snapshot`](crate::cluster::state_machine::MetadataStateMachine::snapshot)
    /// at the committed+applied `index` (and that index's `term`).
    ///
    /// The crash-safe order is NON-NEGOTIABLE (#660 non-negotiable 3):
    /// 1. Build the raft `Snapshot` (index/term/`ConfState`/data) and write it to the dual-slot CRC
    ///    checkpoint, which fsyncs it — the snapshot is DURABLE before anything is dropped.
    /// 2. COMPACT the in-memory mirror (drop the entry prefix at or below `index`, record the new
    ///    snapshot metadata).
    /// 3. Physically RECLAIM the now-superseded durable log segments below the snapshot boundary
    ///    (best-effort space reclamation; recovery is correct even if this is skipped, since the
    ///    snapshot checkpoint subsumes the prefix and the `mirror_entry` guard ignores pre-snapshot
    ///    records on replay).
    ///
    /// A crash between (1) and (3) leaves the durable snapshot + a possibly-un-truncated log; on
    /// recovery the snapshot installs and the log tail folds on top — no committed state is lost and
    /// no torn state is observable. `index` MUST be at or below the committed + applied frontier
    /// (the caller enforces this); a snapshot at or below the current snapshot index is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataStorageError`] if the snapshot fails to encode, the checkpoint write
    /// (fsync) fails, or the physical reclamation read/reap fails.
    pub fn create_snapshot_and_compact(
        &mut self,
        index: u64,
        term: u64,
        data: &[u8],
    ) -> Result<(), MetadataStorageError> {
        {
            let core = self
                .core
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // No-op if we already have a snapshot at or above this index (never regress).
            if index <= core.snapshot_index {
                return Ok(());
            }
        }
        let conf_state = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .conf_state
            .clone();

        // (1) Build + DURABLY persist the snapshot BEFORE dropping any log prefix.
        let mut snapshot = Snapshot::default();
        snapshot.data = bytes::Bytes::copy_from_slice(data);
        {
            let meta = snapshot.mut_metadata();
            meta.index = index;
            meta.term = term;
            meta.set_conf_state(conf_state);
        }
        let snapshot_bytes = snapshot.write_to_bytes()?;
        self.snapshot_checkpoint.write(&snapshot_bytes)?;

        // (2) Compact the in-memory mirror up to (and including) `index`. Store the snapshot data
        // so a later `snapshot()` serves it. The mirror's compact records the new snapshot metadata
        // (index/term) read from the entry it subsumes.
        {
            let mut core = self
                .core
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            core.compact(index + 1);
            core.snapshot_data = data.to_vec();
        }

        // (3) Physically reclaim the superseded durable log prefix (best-effort).
        self.reclaim_log_prefix(index)?;
        Ok(())
    }

    /// Durably INSTALL a snapshot RECEIVED from the leader over the wire (#660): persist it to the
    /// crash-safe checkpoint (fsync) BEFORE installing it into the mirror, then install it (adopting
    /// its index/term/`ConfState`/data and clearing the log) and reclaim the superseded log prefix.
    /// Returns `true` if the snapshot was installed, `false` if it was STALE (its index is at or
    /// below our current first index — we already hold that state + a newer tail), which the caller
    /// surfaces fail-closed.
    ///
    /// This is the receiving half of snapshot-based catch-up: a far-behind learner/follower that
    /// raft-rs hands a snapshot in its `Ready` installs it here, then applies the replicated tail on
    /// top — no gap, no dup, no replay of pre-snapshot entries (#660 non-negotiable 4).
    ///
    /// # Errors
    ///
    /// Returns [`MetadataStorageError`] if the snapshot fails to encode, the checkpoint write
    /// (fsync) fails, or the physical reclamation fails.
    pub fn install_received_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<bool, MetadataStorageError> {
        let index = snapshot.get_metadata().index;
        {
            let core = self
                .core
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if core.first_index() > index {
                return Ok(false); // stale: we already have this and a newer tail.
            }
        }
        // DURABLY persist the received snapshot BEFORE installing it (fsync via the checkpoint).
        let snapshot_bytes = snapshot.write_to_bytes()?;
        self.snapshot_checkpoint.write(&snapshot_bytes)?;
        // Install into the mirror (clears the log, adopts the snapshot's state).
        let installed = {
            let mut core = self
                .core
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            install_snapshot_into_core(&mut core, snapshot);
            true
        };
        // Reclaim the now-superseded durable log prefix (the whole log is below the snapshot here).
        self.reclaim_log_prefix(index)?;
        Ok(installed)
    }

    /// Physically reclaim whole durable log SEGMENTS whose records are entirely superseded by a
    /// snapshot at raft `snapshot_index` — BOUNDED, best-effort space reclamation (#660
    /// non-negotiable 6). It scans the durable log once to find the lowest IronBus log OFFSET of any
    /// record that must be RETAINED (an `KIND_ENTRY` whose raft index is strictly above
    /// `snapshot_index`, or — conservatively — the newest `KIND_STATE` record, whichever is lower),
    /// then reaps every sealed segment that lies entirely below that floor. A segment containing any
    /// retained tail record is NEVER reaped, so the retained tail always survives; the active
    /// segment is never reaped. Recovery stays correct whether or not this runs (the snapshot
    /// checkpoint subsumes the prefix), so any reap error is surfaced but the compaction itself has
    /// already succeeded durably.
    fn reclaim_log_prefix(&mut self, snapshot_index: u64) -> Result<(), MetadataStorageError> {
        // Find the protect floor: the lowest IronBus offset of a record that must be RETAINED.
        // Anything strictly below this floor is fully superseded and may be reaped.
        let records = self
            .log
            .read_from(Offset::ZERO, usize::MAX)?;
        let mut protect_floor: Option<u64> = None;
        for record in &records {
            let headers = record.headers.as_ref();
            let Some(&kind) = headers.first() else {
                continue;
            };
            let retain = match kind {
                // An ENTRY record is retained iff its raft index is strictly above the snapshot.
                // The (index, term) are in the header right after the kind byte (LE u64 each).
                KIND_ENTRY => entry_index_from_header(headers).is_some_and(|idx| idx > snapshot_index),
                // Conservatively retain ALL state records: the latest one is load-bearing and the
                // checkpoint-record bytes are tiny, so never reap a segment holding one. (After the
                // snapshot the group rewrites a fresh STATE record on its next ready cycle, so old
                // ones drain out of the active segment naturally over time.)
                KIND_STATE => true,
                _ => true,
            };
            if retain {
                let off = record.offset.get();
                protect_floor = Some(protect_floor.map_or(off, |f| f.min(off)));
            }
        }
        // If nothing must be retained (every record is below the snapshot), protect floor is the
        // log's next offset — everything is reapable. Otherwise reap strictly below the floor.
        let floor = protect_floor.unwrap_or_else(|| self.log.next_offset().get());
        // Reap whole sealed segments fully below the floor. The byte bound is set to 1 so the
        // size predicate is always satisfied; the protect floor is what actually bounds the reap to
        // fully-superseded segments (a segment is only dropped when the NEXT segment's base is at or
        // below the floor, i.e. every record in the dropped segment is below the floor — retained
        // tail records are never reaped). The active segment is never reaped.
        self.log.reap_to_size(1, floor)?;
        Ok(())
    }
}

/// Read an `KIND_ENTRY` record's raft index from its header without decoding the protobuf payload.
/// The header is `[KIND_ENTRY][index:u64-le][term:u64-le]`; returns `None` if it is too short.
fn entry_index_from_header(headers: &[u8]) -> Option<u64> {
    // [0] is the kind byte; [1..9] is the LE index.
    let idx_bytes = headers.get(1..9)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(idx_bytes);
    Some(u64::from_le_bytes(a))
}

/// Install a recovered/received raft `Snapshot` into a [`Core`] (#660): adopt its `(index, term)`,
/// `ConfState`, and DATA, set the hard-state commit/term, and clear the log. Shared by recovery
/// (reading the checkpoint at open) and the live received-snapshot path. The snapshot's `data` is
/// the serialized metadata state-machine bytes the group restores from.
fn install_snapshot_into_core(core: &mut Core, snapshot: &Snapshot) {
    let meta = snapshot.get_metadata();
    core.apply_snapshot(
        meta.index,
        meta.term,
        meta.get_conf_state().clone(),
        snapshot.data.to_vec(),
    );
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

    /// Serve a metadata snapshot per raft-rs's contract (#660): a snapshot at a committed index,
    /// carrying the `ConfState` AND the serialized metadata state-machine bytes in `Snapshot.data`,
    /// so a far-behind learner/follower that raft-rs decides to catch up via snapshot receives the
    /// COMMITTED STATE (not just the metadata). raft-rs requires the returned snapshot index be
    /// `>= request_index`.
    ///
    /// We serve the DURABLY-CREATED snapshot (at `snapshot_index`, with its `snapshot_data`) when it
    /// covers `request_index` — that snapshot's data is the exact point-in-time state machine cut.
    /// When we do NOT yet have a data-bearing snapshot fresh enough for `request_index` (e.g. the
    /// group hasn't created one at or above it yet), we return
    /// [`SnapshotTemporarilyUnavailable`](raft::StorageError::SnapshotTemporarilyUnavailable), which
    /// raft-rs handles by retrying later — by then the driver's snapshot cadence has created one. So
    /// we never serve a snapshot whose DATA does not match its metadata (no torn/empty-data snapshot
    /// is ever sent to a follower).
    fn snapshot(&self, request_index: u64, _to: u64) -> RaftResult<Snapshot> {
        let core = self
            .core
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // If we have a durable data-bearing snapshot at or above the requested index, serve it
        // verbatim (its data is the consistent cut at `snapshot_index`).
        if core.snapshot_index >= request_index && core.snapshot_index > 0 {
            let mut snapshot = Snapshot::default();
            snapshot.data = bytes::Bytes::copy_from_slice(&core.snapshot_data);
            let meta = snapshot.mut_metadata();
            meta.index = core.snapshot_index;
            meta.term = core.snapshot_term;
            meta.set_conf_state(core.conf_state.clone());
            return Ok(snapshot);
        }
        // Otherwise we have no fresh-enough DATA-bearing snapshot to serve; ask raft-rs to retry,
        // by which point the driver's snapshot cadence will have created one covering this index.
        // (raft-rs treats this as transient, not an error.)
        Err(RaftError::Store(
            RaftStorageError::SnapshotTemporarilyUnavailable,
        ))
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

    // --- #660: snapshot create + compaction + crash-safety + snapshot install. ---

    /// A small metadata-state-machine snapshot blob (its exact bytes are opaque to the storage —
    /// the storage carries them as `Snapshot.data`).
    fn sm_bytes(tag: &str) -> Vec<u8> {
        format!("SM-STATE@{tag}").into_bytes()
    }

    /// Append many entries, snapshot + compact at an index, and confirm the durable log is
    /// BOUNDED (its `first_index` rises past the snapshot, the on-disk record count drops) AND the
    /// retained tail above the snapshot is intact — the committed-state-preserved + bounded
    /// invariants at the storage layer (#660 non-negotiables 1 + 6).
    #[test]
    fn snapshot_then_compact_truncates_the_log_and_keeps_the_tail() {
        // A small segment cap so many entries roll into several sealed segments (so reaping can
        // actually reclaim whole segments below the snapshot boundary).
        let fs = InMemoryFs::new();
        let mut storage =
            MetadataLogStorage::open(&fs, ManualClock::new(), LogConfig::new(512).unwrap(), &[1])
                .expect("open");
        // 20 entries at term 1.
        let entries: Vec<Entry> = (1..=20).map(|i| entry(i, 1, b"payload-bytes")).collect();
        storage.append(&entries).expect("append");
        storage.set_hard_state(&hard_state(1, 1, 20)).expect("hs");
        storage.sync().expect("sync");
        assert_eq!(storage.first_index().unwrap(), 1);
        assert_eq!(storage.last_index().unwrap(), 20);
        let records_before = storage.log().durable_record_count();

        // Snapshot + compact at index 15 (committed + applied).
        storage
            .create_snapshot_and_compact(15, 1, &sm_bytes("idx15"))
            .expect("snapshot+compact");

        // The log is now BOUNDED: first_index rose past the snapshot, last_index is unchanged, and
        // the durable on-disk record count dropped (whole prefix segments were reaped).
        assert_eq!(storage.snapshot_index(), 15);
        assert_eq!(
            storage.first_index().unwrap(),
            16,
            "first index rose to snapshot_index + 1"
        );
        assert_eq!(storage.last_index().unwrap(), 20, "the tail is retained");
        assert!(
            storage.log().durable_record_count() < records_before,
            "compaction reclaimed durable records ({} < {})",
            storage.log().durable_record_count(),
            records_before
        );
        // The retained tail entries (16..=20) are intact and a below-first read is Compacted.
        let tail = storage.entries(16, 21, None, ctx()).expect("tail");
        assert_eq!(tail.len(), 5);
        assert_eq!(tail[0].index, 16);
        assert!(
            storage.entries(10, 16, None, ctx()).is_err(),
            "a read below the compacted first index is rejected"
        );
        // term() at the snapshot index returns the snapshot term, not a panic.
        assert_eq!(storage.term(15).unwrap(), 1);
    }

    /// THE COMMITTED-STATE-PRESERVED RECOVERY TEST (#660 non-negotiable 1): after a snapshot +
    /// compaction, REOPEN over the same durable image and confirm the recovered storage installs
    /// the snapshot (its data + index/term/`ConfState`) and folds the retained tail on top — the
    /// recovered state equals the full pre-compaction state (snapshot+tail == full-replay).
    #[test]
    fn recovery_from_snapshot_plus_tail_equals_the_full_state() {
        let fs = InMemoryFs::new();
        {
            let mut storage = MetadataLogStorage::open(
                &fs,
                ManualClock::new(),
                LogConfig::new(512).unwrap(),
                &[1, 2, 3],
            )
            .expect("open");
            let entries: Vec<Entry> = (1..=12).map(|i| entry(i, 2, b"e")).collect();
            storage.append(&entries).expect("append");
            storage.set_hard_state(&hard_state(2, 1, 12)).expect("hs");
            storage.sync().expect("sync");
            // Snapshot at 8, keeping the tail 9..=12.
            storage
                .create_snapshot_and_compact(8, 2, &sm_bytes("idx8"))
                .expect("snapshot+compact");
        }

        // Reopen: recovery reads the snapshot checkpoint FIRST, then replays only the tail.
        let recovered = open(&fs, &[1, 2, 3]);
        assert_eq!(
            recovered.snapshot_index(),
            8,
            "the durable snapshot is recovered"
        );
        assert_eq!(
            recovered.first_index().unwrap(),
            9,
            "first index is snapshot_index + 1"
        );
        assert_eq!(recovered.last_index().unwrap(), 12, "the tail recovered");
        // The hard state commit survived (the snapshot's index is the floor, the tail STATE record
        // raised it to 12).
        let state = recovered.initial_state().unwrap();
        assert_eq!(state.hard_state.commit, 12);
        // The snapshot served back carries the SM data + index/term, ready for a learner.
        let snap = recovered.snapshot(8, 1).expect("snapshot");
        assert_eq!(snap.get_metadata().index, 8);
        assert_eq!(snap.get_metadata().term, 2);
        assert_eq!(snap.data.as_ref(), sm_bytes("idx8").as_slice());
        // The tail entries are intact.
        assert_eq!(recovered.entries(9, 13, None, ctx()).unwrap().len(), 4);
    }

    /// THE CRASH-SAFETY TEST (#660 non-negotiable 3): simulate a crash AFTER the snapshot was
    /// persisted to its checkpoint but BEFORE the log prefix was reaped (the un-truncated-log case)
    /// — recovery must still recover the correct committed state with NO loss and NO torn state. We
    /// reproduce it by persisting a snapshot checkpoint over a FULL (un-compacted) log and reopening.
    #[test]
    fn crash_after_snapshot_persist_before_log_truncation_recovers_correctly() {
        let fs = InMemoryFs::new();
        {
            let mut storage = MetadataLogStorage::open(
                &fs,
                ManualClock::new(),
                LogConfig::new(64 * 1024).unwrap(), // single segment: nothing to reap
                &[1],
            )
            .expect("open");
            let entries: Vec<Entry> = (1..=10).map(|i| entry(i, 3, b"e")).collect();
            storage.append(&entries).expect("append");
            storage.set_hard_state(&hard_state(3, 1, 10)).expect("hs");
            storage.sync().expect("sync");
            // Snapshot + compact at 6. With one segment the reap is a no-op, so the FULL log
            // survives on disk alongside the durable snapshot — exactly the crash-mid-compaction
            // window (snapshot persisted, log not yet physically truncated).
            storage
                .create_snapshot_and_compact(6, 3, &sm_bytes("idx6"))
                .expect("snapshot+compact");
            // The on-disk log still holds all 10 records (single segment, not reaped).
            assert_eq!(storage.log().durable_record_count() >= 10, true);
        }

        // Reopen: the snapshot installs (index 6), and the log replay's pre-snapshot entries (1..=6)
        // are IGNORED by the mirror_entry compacted-prefix guard, while the tail (7..=10) folds on
        // top. No loss, no torn state, no duplicate replay of pre-snapshot entries.
        let recovered = open(&fs, &[1]);
        assert_eq!(recovered.snapshot_index(), 6);
        assert_eq!(
            recovered.first_index().unwrap(),
            7,
            "the compacted-prefix guard dropped the pre-snapshot entries on replay"
        );
        assert_eq!(recovered.last_index().unwrap(), 10, "the tail is intact");
        assert_eq!(recovered.term(6).unwrap(), 3, "snapshot term recovered");
        assert_eq!(recovered.entries(7, 11, None, ctx()).unwrap().len(), 4);
        let snap = recovered.snapshot(6, 1).expect("snapshot");
        assert_eq!(snap.data.as_ref(), sm_bytes("idx6").as_slice());
    }

    /// A crash BEFORE the snapshot was persisted (no snapshot checkpoint) recovers via a FULL log
    /// replay — the pre-#660 path, proving the snapshot is never load-bearing on its own.
    #[test]
    fn crash_before_snapshot_persist_recovers_via_full_log_replay() {
        let fs = InMemoryFs::new();
        {
            let mut storage = open(&fs, &[1]);
            let entries: Vec<Entry> = (1..=5).map(|i| entry(i, 1, b"e")).collect();
            storage.append(&entries).expect("append");
            storage.set_hard_state(&hard_state(1, 1, 5)).expect("hs");
            storage.sync().expect("sync");
            // NO snapshot created (the crash is before any compaction).
        }
        let recovered = open(&fs, &[1]);
        assert_eq!(recovered.snapshot_index(), 0, "no snapshot");
        assert_eq!(recovered.first_index().unwrap(), 1, "full log replayed");
        assert_eq!(recovered.last_index().unwrap(), 5);
    }

    /// A torn snapshot checkpoint (corrupted both slots) recovers as "no snapshot" and falls back
    /// to the full log replay — never a torn install (#660 non-negotiable 3, the torn case).
    #[test]
    fn a_torn_snapshot_checkpoint_falls_back_to_the_full_log() {
        let fs = InMemoryFs::new();
        {
            let mut storage = MetadataLogStorage::open(
                &fs,
                ManualClock::new(),
                LogConfig::new(64 * 1024).unwrap(),
                &[1],
            )
            .expect("open");
            let entries: Vec<Entry> = (1..=8).map(|i| entry(i, 1, b"e")).collect();
            storage.append(&entries).expect("append");
            storage.set_hard_state(&hard_state(1, 1, 8)).expect("hs");
            storage.sync().expect("sync");
            storage
                .create_snapshot_and_compact(5, 1, &sm_bytes("idx5"))
                .expect("snapshot+compact");
        }
        // Corrupt the snapshot checkpoint file in the metaraft/ subdir (flip bytes across BOTH
        // slots so neither validates) — a torn snapshot.
        let meta_fs = fs.subdir(METADATA_SUBDIR).expect("metaraft subdir");
        let file = meta_fs.open(SNAPSHOT_CHECKPOINT).expect("open snapshot ckpt");
        let mut raw = file.snapshot();
        for b in raw.iter_mut() {
            *b ^= 0xff;
        }
        file.write_all_at(&raw, 0).expect("write corrupted");
        file.sync_data().expect("sync corrupted");

        // Recovery ignores the torn snapshot and replays the FULL log (single segment was never
        // reaped), so all 8 entries come back — no loss, no torn install.
        let recovered = open(&fs, &[1]);
        assert_eq!(recovered.snapshot_index(), 0, "torn snapshot ignored");
        assert_eq!(recovered.first_index().unwrap(), 1, "full log replayed");
        assert_eq!(recovered.last_index().unwrap(), 8);
    }

    /// Installing a RECEIVED snapshot (the learner/follower catch-up half) adopts its
    /// index/term/`ConfState`/data, clears the log, and persists it durably — then the retained tail
    /// can be appended on top (#660 non-negotiable 4).
    #[test]
    fn install_received_snapshot_adopts_state_and_survives_reopen() {
        let fs = InMemoryFs::new();
        {
            let mut storage = open(&fs, &[1]);
            // A snapshot arriving from a leader at index 30, term 5.
            let mut snapshot = Snapshot::default();
            snapshot.data = bytes::Bytes::copy_from_slice(&sm_bytes("recv30"));
            {
                let meta = snapshot.mut_metadata();
                meta.index = 30;
                meta.term = 5;
                meta.set_conf_state(conf_state(vec![1, 2, 3], vec![4]));
            }
            let installed = storage.install_received_snapshot(&snapshot).expect("install");
            assert!(installed);
            assert_eq!(storage.snapshot_index(), 30);
            assert_eq!(
                storage.first_index().unwrap(),
                31,
                "first index is snapshot index + 1 after install"
            );
            // The tail above the snapshot replicates next: append 31, 32.
            storage
                .append(&[entry(31, 5, b"t1"), entry(32, 5, b"t2")])
                .expect("append tail");
            storage.set_hard_state(&hard_state(5, 0, 32)).expect("hs");
            storage.sync().expect("sync");
            assert_eq!(storage.last_index().unwrap(), 32);
        }
        // Reopen: the installed snapshot + the tail survive.
        let recovered = open(&fs, &[1]);
        assert_eq!(recovered.snapshot_index(), 30);
        assert_eq!(recovered.first_index().unwrap(), 31);
        assert_eq!(recovered.last_index().unwrap(), 32);
        let state = recovered.initial_state().unwrap();
        assert_eq!(state.conf_state.voters, vec![1, 2, 3]);
        assert_eq!(state.conf_state.learners, vec![4]);
        let snap = recovered.snapshot(30, 1).expect("snapshot");
        assert_eq!(snap.data.as_ref(), sm_bytes("recv30").as_slice());
    }

    /// A STALE received snapshot (index below our current first index — we already hold that and a
    /// newer tail) is REFUSED, never regressing committed state (#660 non-negotiable 1,
    /// fail-closed): the `first_index() > index` `SnapshotOutOfDate` guard, matching MemStorage.
    #[test]
    fn a_stale_received_snapshot_is_refused() {
        let fs = InMemoryFs::new();
        let mut storage = open(&fs, &[1]);
        // First install a snapshot at index 10, so our first index is 11.
        let mut newer = Snapshot::default();
        newer.data = bytes::Bytes::copy_from_slice(&sm_bytes("idx10"));
        {
            let meta = newer.mut_metadata();
            meta.index = 10;
            meta.term = 2;
            meta.set_conf_state(conf_state(vec![1], vec![]));
        }
        assert!(storage.install_received_snapshot(&newer).expect("install newer"));
        assert_eq!(storage.first_index().unwrap(), 11);

        // A LATER-arriving snapshot at index 5 is stale: it is below our first index (11).
        let mut stale = Snapshot::default();
        {
            let meta = stale.mut_metadata();
            meta.index = 5;
            meta.term = 1;
            meta.set_conf_state(conf_state(vec![1], vec![]));
        }
        let installed = storage
            .install_received_snapshot(&stale)
            .expect("install call");
        assert!(!installed, "a stale snapshot is refused");
        // The newer snapshot is untouched (no regression).
        assert_eq!(storage.snapshot_index(), 10);
        assert_eq!(storage.first_index().unwrap(), 11);
    }

    /// `snapshot()` returns `SnapshotTemporarilyUnavailable` when no data-bearing snapshot fresh
    /// enough for the request exists, so a torn/empty-data snapshot is never sent to a follower.
    #[test]
    fn snapshot_is_unavailable_until_one_is_created() {
        let fs = InMemoryFs::new();
        let mut storage = open(&fs, &[1]);
        storage
            .append(&[entry(1, 1, b"a"), entry(2, 1, b"b")])
            .expect("append");
        storage.set_hard_state(&hard_state(1, 1, 2)).expect("hs");
        storage.sync().expect("sync");
        // No snapshot created yet: a request is transiently unavailable.
        assert!(matches!(
            storage.snapshot(1, 0),
            Err(RaftError::Store(
                RaftStorageError::SnapshotTemporarilyUnavailable
            ))
        ));
        // After creating one at index 2, the request is served with data.
        storage
            .create_snapshot_and_compact(2, 1, &sm_bytes("idx2"))
            .expect("snapshot+compact");
        let snap = storage.snapshot(1, 0).expect("snapshot now available");
        assert_eq!(snap.get_metadata().index, 2);
        assert_eq!(snap.data.as_ref(), sm_bytes("idx2").as_slice());
    }
}
