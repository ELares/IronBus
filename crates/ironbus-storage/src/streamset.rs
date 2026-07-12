// SPDX-License-Identifier: MIT OR Apache-2.0
//! A `StreamSet`: N independently-opened, independently-recovered IronBus logs over one filesystem
//! (#563, V2-M2 the multiple-streams core).
//!
//! The single-log broker is, in v2 terms, a broker with exactly ONE stream: the DEFAULT stream `""`,
//! which IS today's root log (the `seg-<hex>.log` segments at the data-dir root). This module
//! generalizes that to N streams without touching the default stream's bytes: the default stream
//! stays the root log, byte for byte, and each NAMED stream is its own independent [`Log`] under
//! `streams/<hex(name)>/`. A deployment that declares no named stream is therefore unchanged on disk
//! and in behavior — `streams/` is never even created.
//!
//! ## The DLQ-subdir pattern, generalized
//!
//! [`crate::dlq::DlqSink`] proved the pattern this module generalizes: a fully independent
//! [`Log`] rooted at a subdirectory of the same [`Filesystem`] (`Log::open(parent_fs.subdir("dlq"),
//! …)`), using the exact same framed, CRC32C'd, recoverable segment format and the same recovery
//! path as the main log, with no second format to maintain. The DLQ is ONE such subdir-log; a
//! `StreamSet` is N of them, one per named stream under the reserved `streams/` subtree (whose name
//! #670 reserved and versioned via the layout marker), keyed by a validated [`StreamId`].
//!
//! ## Per-stream resilience isolation (the headline property)
//!
//! Because each stream is an independent [`Log`] over its OWN segment set, each stream recovers
//! independently: it gets the existing longest-valid-prefix recovery, per-record CRC, and a bounded,
//! reported [`LossReport`] over ITS OWN durable bytes (recovery is a pure function of a stream's
//! durable bytes — I1-I4). A torn or corrupt segment in stream X recovers X to X's own valid prefix
//! and X's own loss report, and CANNOT shorten or corrupt a sibling stream's recovery or the default
//! stream's: a single bad segment contains its blast radius to one stream rather than poisoning all
//! traffic. This is the resilience win the shared-WAL fallback (M2-I13) deliberately trades away for
//! density, and the property [`StreamSet::open`]'s test suite asserts directly.
//!
//! ## Per-record cost stays FLAT as streams grow
//!
//! A `StreamSet` adds NO per-record structure: the resident index is per-stream and O(Σ segments) of
//! that stream (the same resident index a single [`Log`] already keeps), so total resident index is
//! O(Σ segments across all streams) — never O(Σ records). Opening stream X touches only X's
//! directory; it never reads or rebuilds stream Y. Appending to X is exactly a single-`Log` append on
//! X. Adding a stream therefore costs one directory + its segments, never a per-record tax on the
//! others.
//!
//! ## The cross-stream `CommitCoordinator` (M2-I3, #564) — group-commit ACROSS streams
//!
//! Per-stream logs create a Big-O hazard the naive [`StreamSet::sync_all`] embodies: it calls
//! `log.sync()` per stream, and each `Log::sync` is `flush_pending` + `fdatasync`. Driven once per
//! produced record that touches a new stream, that is one `fdatasync` PER stream PER commit, making
//! the fsync cost O(streams) and destroying the durable-produce throughput win the single-log
//! group-commit earned (where ONE `Log::sync` = ONE `write_all_at` + ONE `fdatasync` amortizes the
//! barrier across a whole batch of buffered appends).
//!
//! [`StreamSet::commit_tick`] restores the amortization by generalizing that single-log group-commit
//! ACROSS streams. In ONE tick it:
//!   1. picks only the DIRTIED streams ([`Log::has_unsynced_records`] — a stream with appended,
//!      not-yet-durable records); a CLEAN/COLD stream is skipped entirely and costs nothing;
//!   2. for each dirtied stream, [`Log::flush_no_sync`] drains its `pending` buffer to the page
//!      cache (independent per fd, cheap, no fsync);
//!   3. for each dirtied stream, [`Log::sync_data_only`] issues the covering `fdatasync` on its fd;
//!   4. for each dirtied stream whose fdatasync SUCCEEDED,
//!      [`Log::advance_synced_offset_after_external_sync`] advances its durable head and releases
//!      its parked producer acks — together, in the same tick, no extra actor round-trips.
//!
//! ### The HONEST cost framing (the load-bearing claim)
//!
//! A tick touching K dirtied streams issues exactly K `fdatasync` calls. This is NOT one syscall:
//! `fdatasync` operates on a single fd and the kernel CANNOT batch a durability barrier across
//! different fds, so K dirtied streams genuinely cost K barriers — we do not pretend otherwise. The
//! win is AMORTIZATION, not syscall-count magic: those K barriers are issued with ZERO extra actor
//! wakeups/round-trips (one flush pass, one fsync pass, one ack-release pass), and ONLY dirtied
//! streams are synced (cold streams cost nothing). So for a FIXED total record rate spread over a
//! bounded hot set of streams, the K barriers per tick are amortized across ALL the records the tick
//! commits — the per-RECORD fsync cost stays O(1/batch), exactly as today's single-log group-commit
//! amortizes its one `fdatasync` across a batch of records. The fsync COUNT is
//! O(dirtied-streams-per-tick); the per-RECORD cost is O(1/batch). When only the default stream `""`
//! is dirtied, a tick is ONE flush + ONE fdatasync + ONE durable-head advance — byte-for-byte and
//! behavior-for-behavior today's single-log group-commit.
//!
//! ### Per-stream I2 + isolation preserved
//!
//! Each stream's producer ack is released ONLY after THAT stream's covering `fdatasync` returns
//! (I2, ack-implies-durable, per stream): a stream's durable head advances in step (4) only on the
//! success path of its own step-(3) barrier. No cross-stream ordering is promised, and none is
//! needed — each stream's `synced_offset` advances independently. A failed `fdatasync` on stream X
//! FREEZES stream X (the writer-freeze discipline, [`Log::sync_data_only`]) WITHOUT advancing X's
//! durable head (its acks stay parked) and WITHOUT bricking a sibling: the tick records X's freeze
//! and continues the barrier for every other dirtied stream. Recovery stays a pure function of each
//! stream's durable bytes (longest-valid-prefix per stream); the on-disk format is untouched.
//!
//! ### The DLQ stays independent (scope)
//!
//! The DLQ ([`crate::dlq::DlqSink`]) is a second independent log that fsyncs itself in-band inside
//! `append_poison` (the poison record must be durable BEFORE the source cursor commits — a
//! crash-safety contract). The coordinator does NOT fold the DLQ into the cross-stream barrier:
//! the DLQ is not a member of the `StreamSet`, and its bespoke append-then-self-sync ordering is
//! preserved unchanged (not regressed). Folding it in would require a deferred-sync append path on
//! `DlqSink` while preserving that ordering — out of scope for #564.
//!
//! ## Scope boundary (what this module is NOT)
//!
//! This is the StreamSet storage primitive ONLY: multi-`Log` open / recover / declare / route-by-id,
//! PLUS the cross-stream group-commit [`StreamSet::commit_tick`] (M2-I3, #564 — see below).
//! It deliberately does NOT do:
//! - the `max_open_streams` hot-set / fd LRU bound — M2-I4 (#565). Here every declared stream's
//!   [`Log`] is kept resident.
//! - per-stream retention/compaction — M2-I5.
//! - the WIRE frames (`StreamDeclare`/`PubTo`/`SubTo`) — M2-I10. A `StreamSet` is a storage/engine
//!   internal API; the wire protocol is untouched.
//! - partitions — M2-I11.

use crate::fs::Filesystem;
use crate::layout::STREAMS_SUBDIR;
use crate::log::{
    par_recover_open, par_sync_data_only, Append, AtRestCrypto, Log, LogConfig,
    RECOVERY_OPEN_MAX_WORKERS,
};
use crate::loss::LossReport;
use crate::naming::{
    is_valid_stream_name, parse_stream_subdir_name, stream_subdir_name, MAX_STREAM_NAME_LEN,
};
use crate::segment::{OwnedRecord, StorageError};
use ironbus_core::clock::Clock;
use ironbus_core::types::Offset;
use std::collections::BTreeMap;

/// A validated stream identifier: either the DEFAULT stream (the empty name `""`, today's root log)
/// or a NAMED stream (1 to [`MAX_STREAM_NAME_LEN`] graphic-ASCII bytes). The newtype makes an invalid
/// name unrepresentable past construction, so every API that takes a `StreamId` is already validated
/// — the routing layer (and the later wire wiring, M2-I10) cannot smuggle a path-unsafe or
/// over-length name into the filesystem.
///
/// Construct via [`StreamId::default_stream`] (the root log) or [`StreamId::named`] (validated).
/// Equality and ordering are by the underlying name, so a `StreamId` keys the [`StreamSet`]'s
/// `BTreeMap` directly (deterministic iteration, default stream first since `"" < any non-empty`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(String);

impl StreamId {
    /// The DEFAULT stream: the empty name `""`, which addresses today's ROOT log (the data-dir's
    /// `seg-<hex>.log` segments), NOT a `streams/` child. Routing the default stream preserves the
    /// single-log broker's behavior exactly.
    #[must_use]
    pub fn default_stream() -> StreamId {
        StreamId(String::new())
    }

    /// Constructs a NAMED stream id, validating the name against [`is_valid_stream_name`] (1 to
    /// [`MAX_STREAM_NAME_LEN`] graphic-ASCII bytes — the SAME rule a work-group name obeys). The
    /// empty name is rejected here: the default stream is constructed via [`StreamId::default_stream`],
    /// never by passing `""` to a "named" constructor, so the two are never confused.
    ///
    /// # Errors
    /// Returns [`StreamError::InvalidName`] (carrying the rejected name) for an empty, over-length,
    /// or non-graphic-ASCII name, so a bad name fails closed at the boundary rather than reaching the
    /// filesystem.
    pub fn named(name: &str) -> Result<StreamId, StreamError> {
        if is_valid_stream_name(name) {
            Ok(StreamId(name.to_string()))
        } else {
            Err(StreamError::InvalidName {
                name: name.to_string(),
            })
        }
    }

    /// The stream's name: `""` for the default stream, else the validated named-stream name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }

    /// Whether this is the DEFAULT stream (the root log).
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.0.is_empty()
    }
}

/// An error from a [`StreamSet`] operation that is not itself a lower-level [`StorageError`]: today,
/// only an invalid stream name (the validation boundary). A storage/IO failure from opening,
/// recovering, appending, reading, or syncing a stream's [`Log`] surfaces as [`StorageError`]
/// directly via the `From` impl below, so callers handle the two with one `?`.
#[derive(Debug)]
pub enum StreamError {
    /// A named stream's name was empty, longer than [`MAX_STREAM_NAME_LEN`], or contained a
    /// non-graphic-ASCII byte (the same rule a work-group name obeys). Carries the rejected name.
    InvalidName {
        /// The rejected stream name.
        name: String,
    },
    /// A lower-level storage or IO error from a stream's [`Log`] (open, recover, append, read, sync,
    /// or the `streams/` subdir creation/enumeration).
    Storage(StorageError),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::InvalidName { name } => write!(
                f,
                "invalid stream name {name:?} (the default stream is \"\", otherwise 1 to {MAX_STREAM_NAME_LEN} graphic-ASCII bytes)"
            ),
            StreamError::Storage(e) => write!(f, "stream storage error: {e}"),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StreamError::Storage(e) => Some(e),
            StreamError::InvalidName { .. } => None,
        }
    }
}

impl From<StorageError> for StreamError {
    fn from(e: StorageError) -> Self {
        StreamError::Storage(e)
    }
}

/// The result of [`StreamSet::open`]: the opened set, paired with each stream's INDEPENDENT recovery
/// summary (keyed by id, default stream included). Named so the two-element tuple does not trip the
/// `type_complexity` lint and reads as one value at the call site.
pub type OpenedStreamSet<F, C> = (StreamSet<F, C>, BTreeMap<StreamId, StreamRecovery>);

/// A per-stream recovery summary: how the stream recovered (its bounded, reported loss), produced by
/// [`StreamSet::open`] for every stream it opened. Because each stream recovers independently, every
/// stream has its OWN summary; a torn stream's non-empty loss never appears under a sibling's id.
#[derive(Clone, Debug)]
pub struct StreamRecovery {
    /// The bytes recovery truncated from this stream's torn/unsynced active-segment tail (the silent
    /// loss, made explicit). Zero for a clean recovery.
    pub recovered_truncated_bytes: u64,
    /// The structured, versioned loss report from THIS stream's recovery: every byte span recovery
    /// skipped (torn tail or corrupt body), bounded and reported. Empty for a clean recovery. A
    /// torn/corrupt sibling's events are NEVER in this stream's report (the isolation property).
    pub loss_report: LossReport,
}

/// The result of one [`StreamSet::commit_tick`]: which streams the tick synced, how many `fdatasync`
/// barriers it issued, and which (if any) streams FROZE on their barrier. The HONEST cost framing
/// reads straight off this: `fdatasyncs_issued == synced.len() + froze.len()` is the fsync COUNT for
/// the tick (one barrier attempted per DIRTIED stream — `fsync` cannot be batched across fds), and
/// it is O(dirtied streams in the tick), NOT O(messages): a tick committing many records per dirtied
/// stream amortizes its K barriers across all of them, so the per-RECORD fsync cost is O(1/batch).
/// Cold (clean) streams are absent from every field — they cost nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitOutcome {
    /// The dirtied streams whose covering `fdatasync` SUCCEEDED this tick, each paired with its new
    /// durable head ([`Log::synced_offset`]) — the offset up to which THAT stream's parked producer
    /// acks may now be released (per-stream I2). Deterministic (default-stream-first) order.
    pub synced: Vec<(StreamId, Offset)>,
    /// The dirtied streams whose `fdatasync` FAILED this tick: each is now FROZEN read-only (the
    /// writer-freeze discipline), its durable head was NOT advanced, and its parked acks were NOT
    /// released. A frozen stream does not brick its siblings — the rest of the tick still committed.
    /// Empty on a fully-successful tick.
    pub froze: Vec<StreamId>,
    /// The number of `fdatasync` barriers this tick ISSUED — one per DIRTIED stream (success or
    /// freeze), i.e. `synced.len() + froze.len()`. This is the tick's fsync COUNT, the
    /// O(dirtied-streams) quantity; a clean tick (nothing dirtied) issues zero.
    pub fdatasyncs_issued: usize,
}

/// N independently-opened, independently-recovered IronBus [`Log`]s over one [`Filesystem`], keyed by
/// [`StreamId`]: the DEFAULT stream `""` is today's ROOT log (byte-identical), and each NAMED stream
/// is an independent [`Log`] under `streams/<hex(name)>/` (the DLQ subdir pattern, generalized). See
/// the module docs for the design and the scope boundary.
///
/// `F` is the backing filesystem and `C` the clock seam, exactly as for a single [`Log`]; the
/// default stream and every named stream share the SAME `F` instance's directory tree and the same
/// `C`, so they observe one consistent power-loss image.
pub struct StreamSet<F: Filesystem, C: Clock> {
    /// Every open stream's log, keyed by id. The default stream `""` is ALWAYS present (it is the
    /// root log, opened at construction); named streams are added by [`StreamSet::declare`] and
    /// rediscovered at [`StreamSet::open`]. A `BTreeMap` keeps iteration deterministic (default
    /// first) and the per-stream lookup O(log streams) — never O(records).
    streams: BTreeMap<StreamId, Log<F, C>>,
    /// The clock seam, cloned into each newly-declared stream's [`Log`] so a stream opened later in
    /// the process's life shares the same time source as the rest. Held so [`StreamSet::declare`] can
    /// open a fresh stream without the caller re-supplying it.
    clock: C,
    /// The log configuration applied to EVERY stream's [`Log`] (segment cap, byte caps, quarantine
    /// budget, daily write budget). Per-stream config overrides are a future concern (per-stream
    /// retention is M2-I5); here one config governs all streams, matching the single-log broker.
    config: LogConfig,
    /// The at-rest AEAD encryption context (#780 phase 2) applied to EVERY stream's [`Log`] — the
    /// default stream AND every named stream — so a named stream is encrypted exactly like the default
    /// one, using the SAME key. [`AtRestCrypto::default`] (no key) is the plaintext default, byte-for-
    /// byte unchanged. Held so [`StreamSet::declare`] can open a fresh named stream encrypted without
    /// the caller re-supplying the key.
    at_rest: AtRestCrypto,
    /// The access-ordered list of OPEN NAMED streams for the `max_open_streams` hot-set LRU (M2-I4,
    /// #565): the FRONT is the least-recently-used named stream (the next eviction victim) and the
    /// BACK is the most-recently-used. The DEFAULT stream `""` is NEVER a member (it is the root log
    /// and is never evicted). Kept in lockstep with the named entries of `streams`: [`StreamSet::open`]
    /// seeds it from the recovered named streams, [`StreamSet::declare`] pushes a newly-opened stream
    /// to the MRU end, [`StreamSet::touch`] promotes an accessed stream to the MRU end, and
    /// [`StreamSet::close`] removes an evicted stream. So `lru.len() == self.len() - 1` (the open named
    /// count) always. The engine reads [`StreamSet::lru_victim`] to pick the stream to evict when
    /// opening one more would exceed the cap; the CAP itself is engine policy (an `EngineConfig` knob),
    /// so a bare `StreamSet` (cap unset) simply never evicts and this list is pure bookkeeping.
    lru: Vec<StreamId>,
}

impl<F: Filesystem, C: Clock> std::fmt::Debug for StreamSet<F, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSet")
            .field("stream_count", &self.streams.len())
            .field(
                "stream_ids",
                &self.streams.keys().map(StreamId::name).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl<F: Filesystem + Clone, C: Clock + Clone> StreamSet<F, C> {
    /// Opens (recovering, or creating fresh) the whole stream set rooted at `fs`: the DEFAULT stream
    /// `""` (the root log) plus every NAMED stream already present under `streams/`. Each stream is
    /// opened as an INDEPENDENT [`Log`] (the default at the data-dir root, each named one at
    /// `streams/<hex(name)>/`), so each gets its own longest-valid-prefix recovery, per-record CRC,
    /// bounded/reported [`LossReport`], and the #670 layout-marker check (the default stream's
    /// `Log::open` performs the marker check at the root, exactly as today).
    ///
    /// Recovery is INDEPENDENT per stream: the returned map carries each stream's own
    /// [`StreamRecovery`], and a torn/corrupt stream recovers to ITS OWN valid prefix without
    /// shortening or corrupting any sibling's recovery (the resilience-isolation property). A foreign
    /// directory under `streams/` (one whose name is not a canonical hex-encoded stream name) is
    /// SKIPPED, never opened as a stream, exactly as a foreign file is skipped by segment recovery.
    ///
    /// Total recovery work is O(Σ records across all streams) — each stream's recovery is its
    /// existing single-log recovery, run once. The named streams are opened in PARALLEL across a
    /// bounded worker set ([`par_recover_open`], #822): each stream is a byte-isolated subtree, so a
    /// torn segment in one cannot touch a sibling or the root, and the index-aligned results are
    /// folded into the `BTreeMap` in key order — so the recovered map, every [`StreamRecovery`], and
    /// the first error surfaced are byte-for-byte identical to a strictly serial open. The DEFAULT
    /// stream is opened FIRST, serially (its #670 marker check fail-closes the whole boot before any
    /// named-stream work), exactly as before.
    ///
    /// A data dir with no `streams/` subtree (the common single-log deployment) opens with ONLY the
    /// default stream and never materializes `streams/`, so its on-disk shape is unchanged.
    ///
    /// # Errors
    /// Propagates a [`StorageError`] from opening/recovering any stream (including the
    /// fail-closed `IncompatibleLayoutVersion` from the default stream's #670 marker check) or from
    /// enumerating `streams/`.
    pub fn open(
        fs: &F,
        clock: C,
        config: LogConfig,
    ) -> Result<OpenedStreamSet<F, C>, StorageError> {
        Self::open_inner(fs, clock, config, AtRestCrypto::default())
    }

    /// Opens (recovering, or creating fresh) the whole stream set with LIVE at-rest AEAD encryption
    /// (#780 phase 2): a configured `crypto`/`keyring` encrypts (and decrypts on read) EVERY stream's
    /// log — the default stream and every named stream — with the SAME key. Passing
    /// `AtRestCrypto::default()` is byte-for-byte [`StreamSet::open`].
    ///
    /// # Errors
    /// As [`StreamSet::open`], plus the fail-closed at-rest guards of [`Log::open_encrypted`] on a
    /// per-stream config mismatch.
    #[cfg(feature = "encryption")]
    pub fn open_encrypted(
        fs: &F,
        clock: C,
        config: LogConfig,
        crypto: Option<std::sync::Arc<crate::crypto::SegmentCrypto>>,
        keyring: Option<std::sync::Arc<crate::crypto::KeyRing>>,
    ) -> Result<OpenedStreamSet<F, C>, StorageError> {
        Self::open_inner(fs, clock, config, AtRestCrypto::new(crypto, keyring))
    }

    /// Opens the whole stream set with a pre-built [`AtRestCrypto`] context (#780 phase 3, the serve
    /// hookup): the seam the ENGINE uses to open EVERY stream's log with the SAME opaque, always-compiled
    /// at-rest context it also threads to the root [`Log::open_with_at_rest`], WITHOUT naming the
    /// feature-gated `SegmentCrypto`/`KeyRing` types. `AtRestCrypto::default()` is byte-for-byte
    /// [`StreamSet::open`]; a configured context encrypts (and decrypts on read) the default stream and
    /// every named stream with the same key.
    ///
    /// # Errors
    /// As [`StreamSet::open`], plus the fail-closed at-rest guards of [`Log::open_with_at_rest`] on a
    /// per-stream config mismatch.
    pub fn open_with_at_rest(
        fs: &F,
        clock: C,
        config: LogConfig,
        at_rest: AtRestCrypto,
    ) -> Result<OpenedStreamSet<F, C>, StorageError> {
        Self::open_inner(fs, clock, config, at_rest)
    }

    /// The shared body behind [`StreamSet::open`] and [`StreamSet::open_encrypted`]: opens every
    /// stream's log with the SAME at-rest context.
    fn open_inner(
        fs: &F,
        clock: C,
        config: LogConfig,
        at_rest: AtRestCrypto,
    ) -> Result<OpenedStreamSet<F, C>, StorageError> {
        let mut streams = BTreeMap::new();
        let mut recoveries = BTreeMap::new();

        // 1) The DEFAULT stream "" = today's ROOT log, opened at the data-dir root. This is the
        //    EXISTING single-log open: it performs the #670 layout-marker check and the
        //    longest-valid-prefix recovery over the root segments, byte for byte as before (when no key
        //    is configured). The StreamSet adds NOTHING to this path, so a deployment with no named
        //    stream is unchanged.
        let root = Log::open_with_at_rest(fs.clone(), clock.clone(), config, at_rest.clone())?;
        recoveries.insert(StreamId::default_stream(), recovery_of(&root));
        streams.insert(StreamId::default_stream(), root);

        // 2) Each NAMED stream already on disk under `streams/`. Probe WITHOUT creating the subtree
        //    (so a single-log dir never grows a `streams/`): only if `streams/` exists do we
        //    enumerate it. Each child directory whose name is a canonical hex-encoded stream name is
        //    opened as an INDEPENDENT Log at `streams/<dir>/`; a foreign directory is skipped.
        if fs.subdir_exists(STREAMS_SUBDIR).map_err(StorageError::Io)? {
            let streams_fs = fs.subdir(STREAMS_SUBDIR).map_err(StorageError::Io)?;
            // Enumerate the named-stream subtrees SERIALLY (cheap dir listing + name parse), skipping
            // any stray/foreign directory (not a canonical hex stream name) exactly as before — it
            // never opens as a stream and never shadows a real one. `list_subdirs` is already sorted,
            // so `named` is in a deterministic order.
            let named: Vec<(StreamId, String)> = streams_fs
                .list_subdirs()
                .map_err(StorageError::Io)?
                .into_iter()
                .filter_map(|dir| parse_stream_subdir_name(&dir).map(|name| (StreamId(name), dir)))
                .collect();
            // Open every named stream's INDEPENDENT log at streams/<dir>/ in PARALLEL across a
            // bounded worker set (#822). Each open recovers over its own durable bytes alone: a torn
            // segment here cannot touch the root log or a sibling. Results are index-aligned to
            // `named`; the fold below inserts them into the BTreeMap in key order, so the recovered
            // map + summaries are byte-for-byte the serial-open result.
            let at_rest_ref = &at_rest;
            let opened = par_recover_open(&named, RECOVERY_OPEN_MAX_WORKERS, |(_, dir)| {
                // A named stream is opened with the SAME at-rest crypto as the default stream (#780).
                let log = Log::open_with_at_rest(
                    streams_fs.subdir(dir).map_err(StorageError::Io)?,
                    clock.clone(),
                    config,
                    at_rest_ref.clone(),
                )?;
                let recovery = recovery_of(&log);
                Ok::<_, StorageError>((recovery, log))
            });
            // Fold in `named` order: `?` surfaces the FIRST failing stream's error exactly as the
            // serial loop did (which stopped at the first failing dir in the same order).
            for (result, (id, _dir)) in opened.into_iter().zip(named.iter()) {
                let (recovery, log) = result?;
                recoveries.insert(id.clone(), recovery);
                streams.insert(id.clone(), log);
            }
        }

        // Seed the hot-set LRU (#565) from the recovered NAMED streams in deterministic (BTreeMap key)
        // order — the default stream `""` is excluded (it is never evicted). A freshly recovered stream
        // has no runtime access history, so key order is the arbitrary-but-reproducible initial LRU
        // order; the engine's boot-time evict-to-cap (if the recovered named count exceeds the cap)
        // therefore evicts the lowest-keyed streams first, deterministically.
        let lru: Vec<StreamId> = streams
            .keys()
            .filter(|id| !id.is_default())
            .cloned()
            .collect();

        Ok((
            StreamSet {
                streams,
                clock,
                config,
                at_rest,
                lru,
            },
            recoveries,
        ))
    }
}

impl<F: Filesystem, C: Clock> StreamSet<F, C> {
    /// Opens ONLY the DEFAULT stream's slot — the inert `""` re-open of the (already-recovered) root
    /// log — WITHOUT scanning or opening anything under `streams/` (#597, shared-WAL wiring). This is
    /// the substrate the ENGINE uses in [`crate::shared_wal::StorageMode::SharedWal`] mode, where the
    /// named streams live in the ONE shared commit log and the `streams/<hex(name)>/` subdirectories
    /// hold ONLY per-stream consumer METADATA (cursor / attempts checkpoints and the per-stream
    /// `dlq/` sink) with NO segments: opening a per-stream [`Log`] there would materialize an empty
    /// segment file per stream (defeating the density point) AND create a second, empty-looking read
    /// surface shadowing the shared WAL's real records. With only the `""` slot, every named-stream
    /// query on this set answers "not open" (`get` -> `None`, `is_open` -> `false`,
    /// `open_named_count` -> `0`), which is exactly the fail-safe answer for the engine's untouched
    /// per-stream-mode code paths — the shared-mode branches never consult this set for a named
    /// stream. The default stream's contract is unchanged: the engine still serves `""` from its own
    /// root [`Log`]; this slot is the same inert re-open [`StreamSet::open`] performs.
    ///
    /// # Errors
    /// Propagates a [`StorageError`] from re-opening the root log.
    pub fn open_default_only(fs: &F, clock: C, config: LogConfig) -> Result<Self, StorageError>
    where
        F: Clone,
        C: Clone,
    {
        let mut streams = BTreeMap::new();
        // The inert `""` re-open uses today's plaintext path: the shared-WAL substrate this backs is
        // fail-closed under at-rest encryption (a mixed shared-WAL + encryption mode is phase 3), so a
        // default-only stream set carries no at-rest key.
        let root = Log::open(fs.clone(), clock.clone(), config)?;
        streams.insert(StreamId::default_stream(), root);
        Ok(StreamSet {
            streams,
            clock,
            config,
            at_rest: AtRestCrypto::default(),
            lru: Vec::new(),
        })
    }
}

// `declare` (open-or-reopen a single named stream's log) needs only the CLOCK to be `Clone` (it clones
// the clock seam into the new `Log`) — NOT the filesystem, since [`Filesystem::subdir`] borrows `&self`
// and [`Log::open`] takes an owned subdir handle. Splitting it out of the `F: Clone` block above is what
// lets the ENGINE'S CONSUME/ACK paths (which are generic over an `F` that need not be `Clone`) REOPEN a
// stream the hot-set LRU evicted (#565): a lazy reopen is exactly a `declare`, so it must be reachable
// without the `F: Clone` bound that only [`StreamSet::open`]'s parallel cold-open needs.
impl<F: Filesystem, C: Clock + Clone> StreamSet<F, C> {
    /// Declares (creating its `streams/<hex(name)>/` directory + a fresh [`Log`] on first use, or
    /// returning the already-open one) the NAMED stream `id`, so it can be appended to and read. The
    /// default stream is always already open (it is the root log), so declaring it is a no-op that
    /// simply confirms it is present.
    ///
    /// On first declaration of a named stream this materializes `streams/` (and `streams/<hex>/`) on
    /// disk via [`Filesystem::subdir`] and opens a fresh independent [`Log`] there. Re-declaring an
    /// open stream is idempotent: it does not reopen or disturb the existing log. Returns whether the
    /// stream was NEWLY OPENED (`true`) versus already open (`false`).
    ///
    /// This is ALSO the hot-set LRU REOPEN path (#565): a stream the LRU evicted (its log closed, its
    /// on-disk `streams/<hex>/` subtree intact) is reopened here by exactly the same [`Log::open`] that
    /// a first declaration runs, which recovers its durable records from disk — so a reopen is
    /// behaviorally a per-stream restart. A newly-opened stream is pushed to the MRU end of the hot-set
    /// LRU (it is the most-recently-touched stream by definition).
    ///
    /// # Errors
    /// Propagates a [`StorageError`] from creating the subdir or opening the stream's log.
    pub fn declare(&mut self, id: &StreamId) -> Result<bool, StorageError> {
        if self.streams.contains_key(id) {
            return Ok(false);
        }
        // The default stream is inserted at open and can never be missing here, so any id not present
        // is a named stream: create streams/<hex(name)>/ and open a fresh independent log there.
        debug_assert!(!id.is_default(), "the default stream is always open");
        let root = self.root_fs();
        let subtree = root.subdir(STREAMS_SUBDIR).map_err(StorageError::Io)?;
        let this_stream_dir = subtree
            .subdir(&stream_subdir_name(id.name()))
            .map_err(StorageError::Io)?;
        // A named stream's log is opened (and, on the LRU reopen path, recovered) with the SAME at-rest
        // crypto as the default stream (#780), so a lazily-declared/reopened named stream is encrypted
        // exactly like every other stream — no plaintext leak on a fresh or reopened named stream.
        let log = Log::open_with_at_rest(
            this_stream_dir,
            self.clock.clone(),
            self.config,
            self.at_rest.clone(),
        )?;
        self.streams.insert(id.clone(), log);
        // A newly-opened (or reopened) named stream is the most-recently-used by definition: push it to
        // the MRU end of the hot-set LRU so it is the LAST to be evicted (#565). `declare` returns early
        // above when the stream is already open, so this never double-inserts an id.
        self.lru.push(id.clone());
        Ok(true)
    }

    /// Borrows the root filesystem (the default stream's), the parent of the `streams/` subtree, so a
    /// newly-declared named stream is rooted under the same data directory as every other stream. The
    /// default stream is always present, so this never panics.
    fn root_fs(&self) -> &F {
        self.streams
            .get(&StreamId::default_stream())
            .expect("the default stream is always open")
            .filesystem()
    }
}

impl<F: Filesystem, C: Clock> StreamSet<F, C> {
    /// Borrows a stream's log by id for reads/inspection, or `None` if the stream is not open (a
    /// named stream that was never [`declare`](StreamSet::declare)d). The default stream is always
    /// open. This is the route-by-id read path: a consume targeting a specific stream resolves its
    /// log here.
    #[must_use]
    pub fn get(&self, id: &StreamId) -> Option<&Log<F, C>> {
        self.streams.get(id)
    }

    /// Mutably borrows a stream's log by id for appends, or `None` if the stream is not open. The
    /// default stream is always open. This is the route-by-id WRITE path: a publish targeting a
    /// specific stream resolves its log here and appends to it. The append is exactly a single-`Log`
    /// append — appending to stream X never touches stream Y, so per-record cost stays flat as
    /// streams grow.
    pub fn get_mut(&mut self, id: &StreamId) -> Option<&mut Log<F, C>> {
        self.streams.get_mut(id)
    }

    /// Routes one append to stream `id`, returning the assigned [`Offset`], or
    /// [`StreamError::InvalidName`]-free `Err` of [`StorageError`]/unopened. A convenience over
    /// [`get_mut`](StreamSet::get_mut) + [`Log::append`] that names the routing intent: a publish to
    /// a specific stream. The record is durable only after a subsequent [`sync_stream`](StreamSet::sync_stream).
    ///
    /// # Errors
    /// Returns [`StorageError::Io`] wrapping a `NotFound` if `id` is not an open stream (declare it
    /// first), else propagates the underlying [`Log::append`] [`StorageError`] (capacity sheds,
    /// writer-frozen, etc.) unchanged.
    pub fn append_to(
        &mut self,
        id: &StreamId,
        record: &Append<'_>,
    ) -> Result<Offset, StorageError> {
        match self.streams.get_mut(id) {
            Some(log) => log.append(record),
            None => Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stream {:?} is not open (declare it first)", id.name()),
            ))),
        }
    }

    /// The subject-storing twin of [`append_to`](StreamSet::append_to) (#594-B): routes one append to
    /// stream `id` ALSO persisting `subject` as the record's optional subject field, so a per-subject
    /// filtered consumer on a NAMED stream can match it. An EMPTY `subject` is byte-for-byte
    /// [`append_to`](StreamSet::append_to) (the subject rides its own frame field with its own CRC and
    /// never enters the body-compression path). The caller validated the subject grammar at the wire
    /// boundary.
    ///
    /// # Errors
    /// Returns [`StorageError::Io`] wrapping a `NotFound` if `id` is not an open stream (declare it
    /// first), else propagates the underlying [`Log::append_with_subject`] [`StorageError`] unchanged.
    pub fn append_to_with_subject(
        &mut self,
        id: &StreamId,
        record: &Append<'_>,
        subject: &[u8],
    ) -> Result<Offset, StorageError> {
        match self.streams.get_mut(id) {
            Some(log) => log.append_with_subject(record, subject),
            None => Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stream {:?} is not open (declare it first)", id.name()),
            ))),
        }
    }

    /// Reads up to `max_records` records (and at most `max_bytes` encoded frame bytes, if set) from
    /// stream `id` starting at `start`, routing the read to that stream's log. Returns an empty vec
    /// for an unopened stream is NOT done — an unopened stream is an error, so a typo'd id is not
    /// silently an empty read.
    ///
    /// # Errors
    /// Returns [`StorageError::Io`] wrapping `NotFound` if `id` is not an open stream, else
    /// propagates the underlying [`Log::read_range`] error.
    pub fn read_range(
        &self,
        id: &StreamId,
        start: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        match self.streams.get(id) {
            Some(log) => log.read_range(start, max_records, max_bytes),
            None => Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stream {:?} is not open (declare it first)", id.name()),
            ))),
        }
    }

    /// Makes stream `id`'s appended records durable (fsync), independently of every other stream.
    ///
    /// NOTE the scope boundary: this syncs ONE stream's log on its own. The cross-stream group-commit
    /// that batches a single `fdatasync` across many streams is M2-I3 (#564); until then each stream
    /// syncs independently, which is CORRECT (every acked record is durable) but not yet
    /// fsync-optimal. Correctness first.
    ///
    /// # Errors
    /// Returns `NotFound` for an unopened stream, else propagates [`Log::sync`].
    pub fn sync_stream(&mut self, id: &StreamId) -> Result<(), StorageError> {
        match self.streams.get_mut(id) {
            Some(log) => log.sync(),
            None => Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stream {:?} is not open (declare it first)", id.name()),
            ))),
        }
    }

    /// Syncs EVERY open stream's log, each independently (see [`sync_stream`](StreamSet::sync_stream)
    /// for the M2-I3 group-commit boundary). Stops and returns on the first stream's sync error, so a
    /// failure is surfaced rather than swallowed; streams already synced stay durable.
    ///
    /// # Errors
    /// Propagates the first stream's [`Log::sync`] error.
    pub fn sync_all(&mut self) -> Result<(), StorageError> {
        for log in self.streams.values_mut() {
            log.sync()?;
        }
        Ok(())
    }

    /// THE CROSS-STREAM GROUP-COMMIT (M2-I3, #564). Runs ONE commit tick over the whole set: a single
    /// batched durability barrier that makes every DIRTIED stream's appended records durable and
    /// releases their parked producer acks together, while a clean/cold stream costs nothing. This is
    /// today's single-log group-commit (`flush_pending` then ONE `fdatasync` amortized over a batch of
    /// appends), GENERALIZED across the per-stream logs so per-stream isolation does NOT cost the
    /// durable-produce throughput win.
    ///
    /// The tick has three passes over the dirtied streams (those with appended, not-yet-durable
    /// records — [`Log::has_unsynced_records`]):
    ///   1. **flush**: [`Log::flush_no_sync`] drains each dirtied stream's `pending` buffer to the
    ///      page cache (independent per fd, cheap, no fsync);
    ///   2. **barrier**: [`crate::log::par_sync_data_only`] issues the covering `fdatasync` on each
    ///      dirtied stream's fd — K dirtied streams = K barriers (the kernel cannot batch `fdatasync`
    ///      across different fds; this is honest, see [`CommitOutcome`]). Because each stream is an
    ///      INDEPENDENT fd, the K barriers are FANNED OUT concurrently across a bounded scoped-worker
    ///      set and JOINED before any ack releases, so the tick's barrier phase costs max(barrier)
    ///      not sum(barrier) (#823);
    ///   3. **release**: for each stream whose barrier SUCCEEDED,
    ///      [`Log::advance_synced_offset_after_external_sync`] advances its durable head and the
    ///      returned [`CommitOutcome::synced`] reports the offset up to which its acks may release.
    ///
    /// ### Cost (the load-bearing claim)
    /// The fsync COUNT is `O(dirtied streams this tick)` ([`CommitOutcome::fdatasyncs_issued`]), NOT
    /// `O(messages)`: a tick that commits many records across a bounded hot set of streams amortizes
    /// its K barriers over ALL those records, so the per-RECORD fsync cost stays `O(1/batch)` — the
    /// exact amortization the single-log group-commit already gives, now spanning streams. A tick that
    /// dirties only the default stream `""` is ONE flush + ONE fdatasync + ONE advance: byte- and
    /// behavior-identical to today's single-log group-commit.
    ///
    /// ### I2 + isolation
    /// Each stream's acks release ONLY after ITS OWN covering `fdatasync` (per-stream I2): a stream
    /// appears in [`CommitOutcome::synced`] only on the success path of its own barrier. A failed
    /// `fdatasync` FREEZES that one stream (recorded in [`CommitOutcome::froze`]; its durable head is
    /// NOT advanced, its acks stay parked) and the tick CONTINUES for every sibling — one bad fd does
    /// not brick the batch. No cross-stream ordering is promised or needed.
    ///
    /// This never returns `Err`: a per-stream barrier failure is reported in
    /// [`CommitOutcome::froze`], not raised, because one frozen stream must not abort a sibling's
    /// commit. (Contrast [`StreamSet::sync_all`], which stops on the first error — that is the
    /// pre-#564 correctness-first path and is kept for callers that want fail-fast.)
    #[must_use]
    pub fn commit_tick(&mut self) -> CommitOutcome {
        // Snapshot the DIRTIED stream ids up front (default-first, deterministic BTreeMap key order).
        // A clean/cold stream — or a frozen one — is never touched, so a tick's cost scales with the
        // hot set, not the total stream count. The ordinal of each id in this Vec is the tag the
        // barrier fan-out reassembles by, so the release pass stays in this deterministic order.
        let dirtied: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(_, log)| log.has_unsynced_records())
            .map(|(id, _)| id.clone())
            .collect();

        let mut outcome = CommitOutcome {
            synced: Vec::with_capacity(dirtied.len()),
            froze: Vec::new(),
            fdatasyncs_issued: 0,
        };
        // Every froze ordinal (from a PASS-1 flush freeze OR a PASS-2 barrier freeze) lands here and
        // is sorted into the deterministic dirtied order at the end, byte-identical to the serial loop.
        let mut froze_ord: Vec<usize> = Vec::new();

        // PASS 1 (serial, cheap): flush each dirtied stream's pending bytes to the page cache (no
        // fsync). A flush failure is the fatal frozen-writer class, identical to a failed barrier:
        // record the freeze and do NOT advance the durable head. A stream that flushes OK hands its
        // disjoint `&mut Log` to the barrier fan-out (tagged by its ordinal in `dirtied`). Every
        // dirtied stream owes exactly one barrier, counted here whether it flush-froze or reaches
        // PASS 2 (identical count to the serial loop).
        //
        // We resolve the `&mut Log` handles by draining the whole map with `iter_mut` and matching
        // each entry against `dirtied` by ordinal, so the handles are disjoint (`get_mut` in a loop
        // cannot yield K simultaneous `&mut`). `dirtied` is in the same key order as `iter_mut`, so a
        // single forward walk aligns them.
        let mut barriers: Vec<(usize, &mut Log<F, C>)> = Vec::with_capacity(dirtied.len());
        {
            let mut next = 0usize;
            for (id, log) in &mut self.streams {
                if next >= dirtied.len() {
                    break;
                }
                if *id != dirtied[next] {
                    continue; // a clean stream between two dirtied ones
                }
                let ord = next;
                next += 1;
                outcome.fdatasyncs_issued += 1;
                if log.flush_no_sync().is_err() {
                    froze_ord.push(ord);
                    continue;
                }
                barriers.push((ord, log));
            }
        }

        // PASS 2 (fan-out): issue the K covering fdatasyncs CONCURRENTLY across a bounded scoped-worker
        // set, then JOIN every barrier before ANY ack is released. Each stream is its own fd/`Log`
        // (disjoint `&mut`), so the barriers are independent and the tick's barrier phase now costs
        // max(barrier) instead of sum(barrier) (#823). DURABILITY: `par_sync_data_only` returns only
        // after EVERY barrier has completed, and PASS 3 advances a stream's durable head ONLY on its
        // `Ok(())` result — a failed fd freezes ONLY its own commits, never a sibling's, and no ack
        // releases until after this join.
        let mut barrier_results = par_sync_data_only(barriers);
        // Reassemble in the deterministic dirtied order (the fan-out returns completion order).
        barrier_results.sort_unstable_by_key(|(ord, _)| *ord);

        // PASS 3 (serial, deterministic): for each stream whose barrier returned, advance its durable
        // head and report its ack-release offset (per-stream I2 — acks release only now, after its own
        // fdatasync); a stream whose barrier failed freezes (acks stay parked).
        for (ord, result) in barrier_results {
            let id = &dirtied[ord];
            if result.is_ok() {
                if let Some(log) = self.streams.get_mut(id) {
                    log.advance_synced_offset_after_external_sync();
                    outcome.synced.push((id.clone(), log.synced_offset()));
                }
            } else {
                froze_ord.push(ord);
            }
        }

        froze_ord.sort_unstable();
        outcome.froze = froze_ord
            .into_iter()
            .map(|ord| dirtied[ord].clone())
            .collect();
        outcome
    }

    /// The ids of every open stream, in deterministic (default-first) order. The default stream `""`
    /// is always included.
    #[must_use]
    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.streams.keys().cloned().collect()
    }

    /// Visit each NAMED stream's durable head (`flushed_offset`), calling `f(name, head)` in
    /// deterministic (name) order and SKIPPING the inert default `""` slot (whose authoritative head
    /// lives on the engine's root [`Log`], not this set's default entry). Allocation-free — no
    /// intermediate `Vec` — so the append actor's per-stream commit-notify frontier scan (push
    /// delivery, #1100 L2) costs one atomic head read per open named stream and nothing when none
    /// exist.
    pub fn for_each_named_frontier<G: FnMut(&str, u64)>(&self, mut f: G) {
        for (id, log) in &self.streams {
            if id.is_default() {
                continue;
            }
            f(id.name(), log.flushed_offset().get());
        }
    }

    /// The number of open streams, including the always-present default stream (so this is `>= 1`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether the set has no streams. Always `false` (the default stream is always open); provided
    /// so a `len`-bearing type carries the conventional companion and clippy is satisfied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Whether stream `id` is currently open.
    #[must_use]
    pub fn is_open(&self, id: &StreamId) -> bool {
        self.streams.contains_key(id)
    }

    // ======================= M2-I4 (#565): the max_open_streams hot-set LRU =======================
    //
    // These methods maintain the OPEN-set access order and close/evict a stream's log on demand. The
    // CAP is engine policy (`EngineConfig::max_open_streams`), and eviction's flush-of-durable-state
    // (the per-stream cursor #681, the DLQ #1110, the attempt counts) lives in the engine (it owns that
    // state). The `StreamSet` owns only the MECHANISM here: the LRU order, the victim pick, and the
    // log close (fd + segment-buffer release). A reopen is a `declare` (above), which recovers the
    // stream from disk — so an evict/reopen cycle is behaviorally a per-stream restart.

    /// Promotes OPEN named stream `id` to the MOST-recently-used end of the hot-set LRU (#565), so it
    /// is the LAST to be evicted. Called on every access (produce / consume / ack) of a named stream.
    /// A no-op for the default stream (never in the LRU) or an id that is not currently open (nothing
    /// to promote — a reopen re-adds it at the MRU end via [`StreamSet::declare`]). O(open named
    /// streams), which is bounded by the cap.
    pub fn touch(&mut self, id: &StreamId) {
        if id.is_default() || !self.streams.contains_key(id) {
            return;
        }
        if let Some(pos) = self.lru.iter().position(|x| x == id) {
            // Already tracked: move it from wherever it is to the MRU (back) end. `remove` is O(n) but
            // n is bounded by the open cap, and this keeps the vector a true recency order.
            let existing = self.lru.remove(pos);
            self.lru.push(existing);
        } else {
            // Open but somehow untracked (defensive — every open goes through `declare`, which tracks
            // it): record it at the MRU end so the invariant `lru == open named set` self-heals.
            self.lru.push(id.clone());
        }
    }

    /// The LEAST-recently-used OPEN named stream — the next eviction victim — or `None` when no named
    /// stream is open (#565). The default stream is never a candidate (it is not in the LRU). The
    /// engine calls this when opening one more stream would exceed `max_open_streams`, evicts the
    /// returned victim (flushing its durable state and closing its log), and repeats until under cap.
    #[must_use]
    pub fn lru_victim(&self) -> Option<StreamId> {
        self.lru.first().cloned()
    }

    /// The number of OPEN NAMED streams, EXCLUDING the always-present default stream (#565): the
    /// quantity the `max_open_streams` cap bounds. Equal to `self.len() - 1` (the default is always
    /// open) and to `self.lru.len()` (the LRU tracks exactly the open named streams).
    #[must_use]
    pub fn open_named_count(&self) -> usize {
        self.streams.len().saturating_sub(1)
    }

    /// CLOSES (evicts from the open set) NAMED stream `id`: drops its [`Log`] — releasing the file
    /// descriptor and the in-memory segment/pending buffers — and removes it from the hot-set LRU
    /// (#565). Its ON-DISK `streams/<hex>/` subtree is left fully intact, so a later [`StreamSet::declare`]
    /// REOPENS and recovers it from disk exactly like a per-stream restart. Returns whether a stream
    /// was actually closed (`false` if `id` was not open).
    ///
    /// The caller MUST have already made the stream's records durable ([`StreamSet::sync_stream`]) and
    /// checkpointed any engine-side per-stream state (cursor / DLQ / attempts) BEFORE calling this —
    /// dropping the `Log` discards its unflushed `pending` buffer, so an un-synced tail would be lost.
    /// The default stream is NEVER closable (it is the root log): a request to close it is a no-op
    /// `false`, so the default stream can never be evicted.
    pub fn close(&mut self, id: &StreamId) -> bool {
        if id.is_default() {
            return false;
        }
        if let Some(pos) = self.lru.iter().position(|x| x == id) {
            self.lru.remove(pos);
        }
        self.streams.remove(id).is_some()
    }
}

/// Captures a freshly-opened log's recovery outcome (the truncated-tail bytes and the structured loss
/// report) into an owned [`StreamRecovery`], so the per-stream recovery summary outlives the borrow
/// of the log it came from.
fn recovery_of<F: Filesystem, C: Clock>(log: &Log<F, C>) -> StreamRecovery {
    StreamRecovery {
        recovered_truncated_bytes: log.recovered_truncated_bytes(),
        loss_report: log.loss_report().clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use crate::io::RandomAccessFile;
    use crate::naming::{segment_file_name, segment_ids, stream_subdir_name};
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

    fn open(fs: &InMemoryFs) -> OpenedStreamSet<InMemoryFs, ManualClock> {
        StreamSet::open(fs, ManualClock::new(), cfg()).unwrap()
    }

    /// A fresh data dir opens with ONLY the default stream "", and produces the EXACT same on-disk
    /// image (the root `seg-*.log`, no `streams/`) as today's single-log path — byte for byte.
    #[test]
    fn fresh_dir_has_only_the_default_stream_byte_identical_to_a_single_log() {
        // The single-log baseline: a bare Log over a fresh fs, a couple of records, synced.
        let baseline_fs = InMemoryFs::new();
        {
            let mut log = Log::open(baseline_fs.clone(), ManualClock::new(), cfg()).unwrap();
            log.append(&rec(b"a")).unwrap();
            log.append(&rec(b"b")).unwrap();
            log.sync().unwrap();
        }

        // The StreamSet path: same fresh fs, declare NO named stream, write the same records to the
        // DEFAULT stream, sync.
        let set_fs = InMemoryFs::new();
        {
            let (mut set, recoveries) = open(&set_fs);
            // Exactly one stream — the default — and it recovered clean.
            assert_eq!(set.stream_ids(), vec![StreamId::default_stream()]);
            assert_eq!(set.len(), 1);
            assert!(recoveries[&StreamId::default_stream()]
                .loss_report
                .is_empty());
            let def = StreamId::default_stream();
            set.append_to(&def, &rec(b"a")).unwrap();
            set.append_to(&def, &rec(b"b")).unwrap();
            set.sync_stream(&def).unwrap();
        }

        // No `streams/` subtree was ever materialized: the on-disk shape is unchanged.
        assert!(!set_fs.subdir_exists(STREAMS_SUBDIR).unwrap());
        // The root segment files are byte-for-byte identical between the two paths.
        let baseline_ids = segment_ids(&baseline_fs).unwrap();
        let set_ids = segment_ids(&set_fs).unwrap();
        assert_eq!(baseline_ids, set_ids);
        for id in set_ids {
            let b = baseline_fs.open(&segment_file_name(id)).unwrap().snapshot();
            let s = set_fs.open(&segment_file_name(id)).unwrap().snapshot();
            assert_eq!(
                b, s,
                "segment {id} differs between single-log and StreamSet"
            );
        }
        // And the layout marker is the same single byte image the single-log path writes (#670).
        assert!(baseline_fs.exists("layout.meta").unwrap());
        assert!(set_fs.exists("layout.meta").unwrap());
    }

    /// Declaring a named stream creates `streams/<hex(name)>/` and the stream is independently
    /// appendable and readable; the default stream keeps its own data.
    #[test]
    fn declare_named_stream_creates_subdir_and_is_independently_usable() {
        let fs = InMemoryFs::new();
        let (mut set, _) = open(&fs);
        let def = StreamId::default_stream();
        let orders = StreamId::named("orders").unwrap();

        // First declaration creates it; a second is idempotent.
        assert!(set.declare(&orders).unwrap());
        assert!(!set.declare(&orders).unwrap());
        // The on-disk directory is streams/<hex("orders")>/.
        assert!(fs.subdir_exists(STREAMS_SUBDIR).unwrap());
        let streams_fs = fs.subdir(STREAMS_SUBDIR).unwrap();
        assert_eq!(
            streams_fs.list_subdirs().unwrap(),
            vec![stream_subdir_name("orders")]
        );

        // Independent data: write different records to each stream.
        set.append_to(&def, &rec(b"default-0")).unwrap();
        set.append_to(&orders, &rec(b"orders-0")).unwrap();
        set.append_to(&orders, &rec(b"orders-1")).unwrap();
        set.sync_all().unwrap();

        // Each stream reads back its OWN records, at its own offsets (both start at 0).
        let d = set.read_range(&def, Offset::ZERO, 100, None).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(&*d[0].payload, b"default-0");
        let o = set.read_range(&orders, Offset::ZERO, 100, None).unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!(&*o[0].payload, b"orders-0");
        assert_eq!(&*o[1].payload, b"orders-1");
    }

    /// `append_to_with_subject` persists the record's subject field on a NAMED stream and it round-trips
    /// through a reopen (#594-B); an EMPTY subject is byte-for-byte the subject-less `append_to`.
    #[test]
    fn append_to_with_subject_round_trips_on_a_named_stream_and_survives_reopen() {
        let fs = InMemoryFs::new();
        let orders = StreamId::named("orders").unwrap();
        {
            let (mut set, _) = open(&fs);
            set.declare(&orders).unwrap();
            // A subject-bearing append, a subject-less one (empty subject == append_to), another subject.
            set.append_to_with_subject(&orders, &rec(b"A"), b"orders.a")
                .unwrap();
            set.append_to_with_subject(&orders, &rec(b"P"), b"")
                .unwrap();
            set.append_to_with_subject(&orders, &rec(b"B"), b"orders.b")
                .unwrap();
            set.sync_all().unwrap();
        }
        // Reopen and read back: the stored subject rides the frame and recovers with the record.
        let (set, _) = open(&fs);
        let o = set.read_range(&orders, Offset::ZERO, 100, None).unwrap();
        assert_eq!(o.len(), 3);
        assert_eq!(
            (&*o[0].payload, &*o[0].subject),
            (&b"A"[..], &b"orders.a"[..])
        );
        assert_eq!(
            (&*o[1].payload, &*o[1].subject),
            (&b"P"[..], &b""[..]),
            "an empty subject stores a subject-less record"
        );
        assert_eq!(
            (&*o[2].payload, &*o[2].subject),
            (&b"B"[..], &b"orders.b"[..])
        );
    }

    /// Reopening recovers EVERY stream independently with its own durable data.
    #[test]
    fn reopen_recovers_all_streams_independently_with_their_own_data() {
        let fs = InMemoryFs::new();
        let def = StreamId::default_stream();
        let a = StreamId::named("alpha").unwrap();
        let b = StreamId::named("beta").unwrap();
        {
            let (mut set, _) = open(&fs);
            set.declare(&a).unwrap();
            set.declare(&b).unwrap();
            set.append_to(&def, &rec(b"d0")).unwrap();
            set.append_to(&a, &rec(b"a0")).unwrap();
            set.append_to(&a, &rec(b"a1")).unwrap();
            set.append_to(&b, &rec(b"b0")).unwrap();
            set.sync_all().unwrap();
        }

        // Reopen: all three streams are rediscovered (the two named from streams/, the default at the
        // root), each recovers clean, and each holds exactly its own records.
        let (set, recoveries) = open(&fs);
        assert_eq!(set.stream_ids(), vec![def.clone(), a.clone(), b.clone()]);
        for id in [&def, &a, &b] {
            assert!(
                recoveries[id].loss_report.is_empty(),
                "{} recovered clean",
                id.name()
            );
        }
        assert_eq!(
            set.read_range(&def, Offset::ZERO, 100, None).unwrap().len(),
            1
        );
        let ar = set.read_range(&a, Offset::ZERO, 100, None).unwrap();
        assert_eq!(ar.len(), 2);
        assert_eq!(&*ar[0].payload, b"a0");
        assert_eq!(
            set.read_range(&b, Offset::ZERO, 100, None).unwrap().len(),
            1
        );
    }

    /// THE HEADLINE TEST — resilience isolation: corrupting a named stream's segment recovers THAT
    /// stream bounded/reported to its valid prefix, and leaves the default stream AND a sibling
    /// stream completely UNAFFECTED.
    #[test]
    fn corrupt_one_named_stream_is_isolated_from_the_default_and_siblings() {
        let fs = InMemoryFs::new();
        let def = StreamId::default_stream();
        let victim = StreamId::named("victim").unwrap();
        let sibling = StreamId::named("sibling").unwrap();
        {
            let (mut set, _) = open(&fs);
            set.declare(&victim).unwrap();
            set.declare(&sibling).unwrap();
            // The default + the sibling each get clean, durable data.
            set.append_to(&def, &rec(b"default-keep")).unwrap();
            set.append_to(&sibling, &rec(b"sibling-keep-0")).unwrap();
            set.append_to(&sibling, &rec(b"sibling-keep-1")).unwrap();
            // The victim gets several records; we will tear its tail.
            for i in 0..4u8 {
                set.append_to(&victim, &rec(&[b'v', i])).unwrap();
            }
            set.sync_all().unwrap();
        }

        // Tear three bytes off the END of the VICTIM stream's segment 0 only (its independent log
        // lives at streams/<hex("victim")>/seg-...0.log). This is the same torn-tail idiom the
        // single-log recovery tests use, applied to one stream's directory.
        let victim_fs = fs
            .subdir(STREAMS_SUBDIR)
            .unwrap()
            .subdir(&stream_subdir_name("victim"))
            .unwrap();
        let seg = victim_fs.open(&segment_file_name(0)).unwrap();
        let torn_len = seg.len().unwrap() - 3;
        seg.set_len(torn_len).unwrap();
        seg.sync_data().unwrap();

        // Reopen the whole set. The victim recovers to its OWN valid prefix and reports its OWN loss;
        // the default and the sibling are byte-clean and fully present.
        let (set, recoveries) = open(&fs);

        // VICTIM: bounded + reported loss, recovered to its valid prefix (3 of its 4 records survive).
        let vrec = &recoveries[&victim];
        assert!(
            vrec.recovered_truncated_bytes > 0,
            "the victim's torn tail was truncated"
        );
        assert!(
            !vrec.loss_report.is_empty(),
            "the victim's loss is reported"
        );
        assert_eq!(vrec.loss_report.events.len(), 1);
        assert_eq!(
            vrec.loss_report.events[0].reason_code,
            crate::loss::ReasonCode::TornTail
        );
        let vread = set.read_range(&victim, Offset::ZERO, 100, None).unwrap();
        assert_eq!(vread.len(), 3, "the victim recovered its 3 intact records");

        // DEFAULT: completely unaffected — clean recovery, all data present.
        let drec = &recoveries[&def];
        assert_eq!(
            drec.recovered_truncated_bytes, 0,
            "the default stream lost nothing"
        );
        assert!(
            drec.loss_report.is_empty(),
            "the default stream reports no loss"
        );
        let dread = set.read_range(&def, Offset::ZERO, 100, None).unwrap();
        assert_eq!(dread.len(), 1);
        assert_eq!(&*dread[0].payload, b"default-keep");

        // SIBLING: completely unaffected — clean recovery, both records present. The victim's
        // corruption could NOT shorten or corrupt the sibling's recovery.
        let srec = &recoveries[&sibling];
        assert_eq!(
            srec.recovered_truncated_bytes, 0,
            "the sibling stream lost nothing"
        );
        assert!(
            srec.loss_report.is_empty(),
            "the sibling stream reports no loss"
        );
        let sread = set.read_range(&sibling, Offset::ZERO, 100, None).unwrap();
        assert_eq!(sread.len(), 2);
        assert_eq!(&*sread[0].payload, b"sibling-keep-0");
        assert_eq!(&*sread[1].payload, b"sibling-keep-1");
    }

    /// A foreign directory under `streams/` (not a canonical hex-encoded stream name) is SKIPPED at
    /// open, never opened as a stream — exactly as a foreign file is skipped by segment recovery.
    #[test]
    fn a_foreign_streams_subdir_is_skipped_not_opened() {
        let fs = InMemoryFs::new();
        // Materialize streams/ with one real stream and one foreign directory (a non-hex name).
        {
            let (mut set, _) = open(&fs);
            let real = StreamId::named("real").unwrap();
            set.declare(&real).unwrap();
            set.append_to(&real, &rec(b"x")).unwrap();
            set.sync_all().unwrap();
        }
        // Plant a foreign directory under streams/ by creating a file inside it (the flat in-mem fs
        // materializes a dir lazily as a key appears). "NOT-HEX" is not a canonical hex name.
        let streams_fs = fs.subdir(STREAMS_SUBDIR).unwrap();
        let foreign = streams_fs.subdir("NOT-HEX").unwrap();
        foreign.create_new("junk.txt").unwrap();
        foreign.sync_dir().unwrap();

        // Reopen: only the real stream is opened; the foreign dir is skipped.
        let (set, _) = open(&fs);
        assert_eq!(
            set.stream_ids(),
            vec![StreamId::default_stream(), StreamId::named("real").unwrap()]
        );
    }

    /// Opening N streams adds NO per-record structure: per-record cost stays flat. We assert the
    /// structural invariant directly — the resident index is per-stream (each stream is a plain
    /// `Log`), so the only thing that grows with N is the number of logs, not any per-record table.
    #[test]
    fn per_record_cost_is_flat_as_streams_grow() {
        let fs = InMemoryFs::new();
        let (mut set, _) = open(&fs);
        // Declare many streams; append one record to each. The set is a BTreeMap of independent Logs;
        // there is no shared per-record structure to grow. The proof is structural (the type holds
        // only `BTreeMap<StreamId, Log>` + the clock + the config), reinforced here by showing each
        // stream's append is independent and self-contained.
        for i in 0..50u32 {
            let id = StreamId::named(&format!("s{i}")).unwrap();
            set.declare(&id).unwrap();
            set.append_to(&id, &rec(b"one")).unwrap();
        }
        set.sync_all().unwrap();
        // 50 named + 1 default. Each holds exactly its own single record; opening stream X never
        // touched stream Y's data.
        assert_eq!(set.len(), 51);
        for i in 0..50u32 {
            let id = StreamId::named(&format!("s{i}")).unwrap();
            assert_eq!(
                set.read_range(&id, Offset::ZERO, 100, None).unwrap().len(),
                1
            );
        }
    }

    /// Naming validation rejects bad stream names at the `StreamId` boundary, so a path-unsafe or
    /// over-length name can never reach the filesystem.
    #[test]
    fn naming_validation_rejects_bad_stream_names() {
        // The empty name is the DEFAULT stream, not a named one: `named("")` is rejected.
        assert!(matches!(
            StreamId::named(""),
            Err(StreamError::InvalidName { .. })
        ));
        // Over-length and non-graphic-ASCII are rejected.
        assert!(StreamId::named(&"x".repeat(MAX_STREAM_NAME_LEN + 1)).is_err());
        assert!(StreamId::named("has space").is_err());
        assert!(StreamId::named("café").is_err());
        // Valid names construct.
        assert!(StreamId::named("orders").is_ok());
        assert!(StreamId::named("a/b").is_ok()); // graphic ASCII; hex-encoded on disk
        assert!(StreamId::named(&"x".repeat(MAX_STREAM_NAME_LEN)).is_ok());
        assert_eq!(StreamId::default_stream().name(), "");
        assert!(StreamId::default_stream().is_default());
    }

    /// Routing to an unopened named stream is a typed `NotFound` error, not a silent empty read/write,
    /// so a typo'd id fails closed.
    #[test]
    fn routing_to_an_unopened_stream_is_an_error_not_a_silent_noop() {
        let fs = InMemoryFs::new();
        let (mut set, _) = open(&fs);
        let ghost = StreamId::named("never-declared").unwrap();
        assert!(!set.is_open(&ghost));
        assert!(set.append_to(&ghost, &rec(b"x")).is_err());
        assert!(set.read_range(&ghost, Offset::ZERO, 1, None).is_err());
        assert!(set.sync_stream(&ghost).is_err());
        // The default stream is always open and routable.
        assert!(set.is_open(&StreamId::default_stream()));
    }

    // ============================ M2-I3 (#564): the CommitCoordinator ============================
    //
    // These tests exercise `StreamSet::commit_tick` — the cross-stream group-commit — over a counting
    // fault filesystem so we can assert the HONEST fsync-count claim directly (a tick over K dirtied
    // streams issues exactly K fdatasyncs, and a cold stream issues none), plus per-stream I2, the
    // single-dirtied-stream byte/behaviour identity with today's single-log group-commit, the
    // freeze-one-stream-not-siblings isolation, and per-stream recovery after a coordinated commit.

    use crate::fault::{FaultControl, FaultFs};

    /// Opens a `StreamSet` over a counting [`FaultFs`], returning the set, its recoveries, and the
    /// [`FaultControl`] so a test can read `sync_count()` (every `sync_data`/`sync_all`) and arm a
    /// sync failure. The control is cloned out before the fs is moved into the set.
    fn open_faulty(
        inner: InMemoryFs,
    ) -> (
        StreamSet<FaultFs<InMemoryFs>, ManualClock>,
        BTreeMap<StreamId, StreamRecovery>,
        FaultControl,
    ) {
        let (fs, control) = FaultFs::new(inner);
        let (set, recoveries) = StreamSet::open(&fs, ManualClock::new(), cfg()).unwrap();
        (set, recoveries, control)
    }

    /// THE HONEST FSYNC-COUNT TEST: a commit tick over K DIRTIED streams issues EXACTLY K fdatasyncs,
    /// and COLD (clean) streams are not synced — so the fsync count is O(dirtied streams per tick),
    /// not O(streams) and not O(messages). We assert the count off the counting fs directly.
    #[test]
    fn commit_tick_syncs_exactly_the_dirtied_streams_cold_streams_cost_nothing() {
        let (mut set, _, control) = open_faulty(InMemoryFs::new());
        let def = StreamId::default_stream();
        let a = StreamId::named("a").unwrap();
        let b = StreamId::named("b").unwrap();
        let c = StreamId::named("c").unwrap();
        for id in [&a, &b, &c] {
            set.declare(id).unwrap();
        }

        // Dirty 3 of the 4 streams (default, a, b); leave c COLD (no append). Many records per dirtied
        // stream — the amortization is over records, the fsync count is over dirtied streams.
        for _ in 0..10 {
            set.append_to(&def, &rec(b"d")).unwrap();
            set.append_to(&a, &rec(b"a")).unwrap();
            set.append_to(&b, &rec(b"b")).unwrap();
        }

        // One tick. No segment rolls happen for these tiny records (one open segment per stream), so
        // every `sync_data`/`sync_all` the counter sees is a coordinator barrier.
        let syncs_before = control.sync_count();
        let outcome = set.commit_tick();
        let barriers = control.sync_count() - syncs_before;

        // EXACTLY 3 fdatasyncs for the 3 dirtied streams — the cold stream `c` cost nothing.
        assert_eq!(
            barriers, 3,
            "one fdatasync per DIRTIED stream, cold stream not synced"
        );
        assert_eq!(outcome.fdatasyncs_issued, 3);
        assert_eq!(outcome.synced.len(), 3);
        assert!(outcome.froze.is_empty());
        // The synced set is exactly {default, a, b}, deterministic (default-first); c is absent.
        let synced_ids: Vec<&StreamId> = outcome.synced.iter().map(|(id, _)| id).collect();
        assert_eq!(synced_ids, vec![&def, &a, &b]);
        assert!(!synced_ids.contains(&&c));

        // A SECOND tick with nothing newly dirtied issues ZERO fdatasyncs (all caught up + cold c).
        let syncs_before = control.sync_count();
        let outcome2 = set.commit_tick();
        assert_eq!(
            control.sync_count() - syncs_before,
            0,
            "a tick with no dirtied stream issues no barrier"
        );
        assert_eq!(outcome2.fdatasyncs_issued, 0);
        assert!(outcome2.synced.is_empty());

        // 30 records were committed across the 3 dirtied streams for 3 barriers: ~0.1 fsync/record.
        // Doubling the per-stream record count would NOT change the barrier count — O(1/batch).
    }

    /// #823: with K>1 streams dirtied in ONE tick the K covering fdatasyncs are FANNED OUT
    /// concurrently across a bounded scoped-worker set, yet the outcome stays byte-identical to the
    /// old serial barrier loop. Under a total fsync fault EVERY dirtied fd's barrier fails on its own
    /// (per-stream freeze isolation survives the fan-out), the froze set is reported in the
    /// deterministic default-first order (NOT thread-completion order), and — the paramount durability
    /// invariant — NO stream's durable head advanced and NO ack released, because every barrier is
    /// JOINED before the release pass runs.
    #[test]
    fn fanned_out_barrier_freeze_is_deterministic_and_acks_nothing() {
        let (mut set, _, control) = open_faulty(InMemoryFs::new());
        let def = StreamId::default_stream();
        let a = StreamId::named("a").unwrap();
        let b = StreamId::named("b").unwrap();
        let c = StreamId::named("c").unwrap();
        for id in [&a, &b, &c] {
            set.declare(id).unwrap();
        }
        // Dirty all 4 streams (default, a, b, c), several records each — K = 4 barriers in one tick.
        for _ in 0..4 {
            for id in [&def, &a, &b, &c] {
                set.append_to(id, &rec(b"r")).unwrap();
            }
        }
        // Each dirtied stream's durable head BEFORE the tick (trails its append head).
        let before: BTreeMap<StreamId, Offset> = [&def, &a, &b, &c]
            .iter()
            .map(|id| ((*id).clone(), set.get(id).unwrap().synced_offset()))
            .collect();

        control.set_fail_sync(true);
        let outcome = set.commit_tick();
        control.set_fail_sync(false);

        assert_eq!(outcome.fdatasyncs_issued, 4);
        assert!(
            outcome.synced.is_empty(),
            "no commit acked when its covering fdatasync failed"
        );
        // The froze set is the deterministic default-first (BTreeMap key) order, not completion order.
        assert_eq!(
            outcome.froze,
            vec![def.clone(), a.clone(), b.clone(), c.clone()],
            "froze reported in deterministic default-first order"
        );
        // Each dirtied fd froze on its OWN barrier fault; none advanced its durable head (the release
        // pass ran only after the join, so a failed barrier released no ack).
        for id in [&def, &a, &b, &c] {
            let log = set.get(id).unwrap();
            assert_eq!(
                log.synced_offset(),
                before[id],
                "a frozen stream's durable head must NOT advance"
            );
            assert!(
                !log.is_writable(),
                "each dirtied fd froze on its own barrier"
            );
        }
    }

    /// PER-STREAM I2: each stream's durable head ([`Log::synced_offset`]) advances only after ITS OWN
    /// covering fdatasync, and the tick reports per-stream the offset up to which acks may release.
    /// Before the tick a dirtied stream's durable head trails its append head; after, it equals it.
    #[test]
    fn commit_tick_advances_each_streams_durable_head_only_after_its_sync() {
        let (mut set, _, _control) = open_faulty(InMemoryFs::new());
        let def = StreamId::default_stream();
        let a = StreamId::named("a").unwrap();
        set.declare(&a).unwrap();

        set.append_to(&def, &rec(b"d0")).unwrap();
        set.append_to(&def, &rec(b"d1")).unwrap();
        set.append_to(&a, &rec(b"a0")).unwrap();

        // Pre-tick: appended but NOT durable — each durable head trails its next-append head.
        assert_ne!(
            set.get(&def).unwrap().synced_offset(),
            set.get(&def).unwrap().next_offset()
        );
        assert_ne!(
            set.get(&a).unwrap().synced_offset(),
            set.get(&a).unwrap().next_offset()
        );

        let outcome = set.commit_tick();

        // Post-tick: each dirtied stream's durable head caught up to its append head (acks releasable
        // up to that offset), and the outcome reports each stream's release offset = its next_offset.
        for id in [&def, &a] {
            let log = set.get(id).unwrap();
            assert_eq!(
                log.synced_offset(),
                log.next_offset(),
                "{}'s durable head advanced after its own fsync",
                id.name()
            );
        }
        // Default committed 2 records (next_offset == 2), stream a committed 1 (next_offset == 1).
        let released: BTreeMap<&str, Offset> = outcome
            .synced
            .iter()
            .map(|(id, off)| (id.name(), *off))
            .collect();
        assert_eq!(released[""], set.get(&def).unwrap().next_offset());
        assert_eq!(released["a"], set.get(&a).unwrap().next_offset());
        assert_eq!(released[""].get(), 2);
        assert_eq!(released["a"].get(), 1);
    }

    /// SINGLE-DIRTIED-STREAM == TODAY'S SINGLE-LOG GROUP-COMMIT, byte- and behaviour-identical. A tick
    /// that dirties only the default stream `""` issues ONE fdatasync (exactly today's `Log::sync`),
    /// produces the same on-disk image, and the same durable head, as a bare single `Log::sync`.
    #[test]
    fn single_dirtied_stream_tick_is_byte_identical_to_a_single_log_sync() {
        // We hold a handle to the underlying InMemoryFs (Clone shares the backing store) for each
        // side so we can read raw segment snapshots, while the Log/StreamSet run over a counting
        // FaultFs wrapping that same store.
        // Baseline: a bare single Log, two records, ONE sync. Count its barriers over a counting fs.
        let base_inner = InMemoryFs::new();
        {
            let (base_fs, base_ctl) = FaultFs::new(base_inner.clone());
            let mut log = Log::open(base_fs, ManualClock::new(), cfg()).unwrap();
            log.append(&rec(b"x")).unwrap();
            log.append(&rec(b"y")).unwrap();
            let before = base_ctl.sync_count();
            log.sync().unwrap();
            assert_eq!(
                base_ctl.sync_count() - before,
                1,
                "a single Log::sync is ONE fdatasync"
            );
        }

        // Coordinator: a fresh set, the SAME two records to the DEFAULT stream only, ONE commit_tick.
        let set_inner = InMemoryFs::new();
        let (set_fs, set_ctl) = FaultFs::new(set_inner.clone());
        let mut set = {
            let (s, _) = StreamSet::open(&set_fs, ManualClock::new(), cfg()).unwrap();
            s
        };
        let def = StreamId::default_stream();
        set.append_to(&def, &rec(b"x")).unwrap();
        set.append_to(&def, &rec(b"y")).unwrap();
        let before = set_ctl.sync_count();
        let outcome = set.commit_tick();
        // ONE fdatasync — identical to the single-log group-commit.
        assert_eq!(
            set_ctl.sync_count() - before,
            1,
            "a single-dirtied-stream tick is ONE fdatasync"
        );
        assert_eq!(outcome.fdatasyncs_issued, 1);
        assert_eq!(outcome.synced.len(), 1);
        assert_eq!(outcome.synced[0].0, def);

        // No `streams/` was materialized (default = root log), and the root segment bytes match the
        // single-log baseline byte-for-byte (read through the underlying InMemoryFs handles).
        assert!(!set_inner.subdir_exists(STREAMS_SUBDIR).unwrap());
        let base_ids = segment_ids(&base_inner).unwrap();
        let set_ids = segment_ids(&set_inner).unwrap();
        assert_eq!(base_ids, set_ids);
        for id in set_ids {
            let b = base_inner.open(&segment_file_name(id)).unwrap().snapshot();
            let s = set_inner.open(&segment_file_name(id)).unwrap().snapshot();
            assert_eq!(
                b, s,
                "segment {id} differs between single-log sync and single-stream tick"
            );
        }
    }

    /// FAILED FSYNC FREEZES ONE STREAM, SIBLINGS HEALTHY. A barrier failure freezes the dirtied
    /// stream (recorded in `froze`, its durable head NOT advanced, its acks NOT released), and a
    /// later tick still commits a sibling — the freeze did not brick the set.
    #[test]
    fn failed_fsync_freezes_one_stream_and_leaves_siblings_healthy() {
        let (mut set, _, control) = open_faulty(InMemoryFs::new());
        let victim = StreamId::named("victim").unwrap();
        let sibling = StreamId::named("sibling").unwrap();
        set.declare(&victim).unwrap();
        set.declare(&sibling).unwrap();

        // Tick 1: dirty ONLY the victim, fail every fsync. The victim's barrier fails -> it freezes.
        set.append_to(&victim, &rec(b"v0")).unwrap();
        control.set_fail_sync(true);
        let outcome = set.commit_tick();
        control.set_fail_sync(false);

        // The victim froze: in `froze`, not `synced`; its durable head did NOT advance; not writable.
        assert_eq!(outcome.froze, vec![victim.clone()]);
        assert!(outcome.synced.is_empty());
        assert_eq!(
            outcome.fdatasyncs_issued, 1,
            "the one dirtied stream's barrier was attempted"
        );
        assert!(
            !set.get(&victim).unwrap().is_writable(),
            "the victim is frozen read-only"
        );
        // Its acks stayed PARKED: durable head still trails the append head (nothing acked-as-durable).
        assert_ne!(
            set.get(&victim).unwrap().synced_offset(),
            set.get(&victim).unwrap().next_offset()
        );

        // Tick 2: the sibling is healthy and commits fine; the frozen victim is simply skipped (a
        // frozen writer reports no unsynced records, so it owes no barrier).
        set.append_to(&sibling, &rec(b"s0")).unwrap();
        let before = control.sync_count();
        let outcome2 = set.commit_tick();
        assert_eq!(
            control.sync_count() - before,
            1,
            "only the healthy sibling is synced; the frozen victim is skipped"
        );
        assert_eq!(outcome2.synced.len(), 1);
        assert_eq!(outcome2.synced[0].0, sibling);
        assert!(outcome2.froze.is_empty());
        // The sibling is fully durable; the victim is still frozen but cannot be appended to.
        assert_eq!(
            set.get(&sibling).unwrap().synced_offset(),
            set.get(&sibling).unwrap().next_offset()
        );
        assert!(
            set.append_to(&victim, &rec(b"v1")).is_err(),
            "a frozen stream rejects appends"
        );
    }

    /// RECOVERY PER STREAM AFTER A COORDINATED COMMIT: every stream committed in one tick recovers,
    /// on reopen, to its own durable prefix (longest-valid-prefix per stream), independently.
    #[test]
    fn recovery_per_stream_after_a_coordinated_commit_is_correct() {
        let inner = InMemoryFs::new();
        let def = StreamId::default_stream();
        let a = StreamId::named("alpha").unwrap();
        let b = StreamId::named("beta").unwrap();
        {
            let (fs, _control) = FaultFs::new(inner.clone());
            let (mut set, _) = StreamSet::open(&fs, ManualClock::new(), cfg()).unwrap();
            set.declare(&a).unwrap();
            set.declare(&b).unwrap();
            set.append_to(&def, &rec(b"d0")).unwrap();
            set.append_to(&a, &rec(b"a0")).unwrap();
            set.append_to(&a, &rec(b"a1")).unwrap();
            set.append_to(&b, &rec(b"b0")).unwrap();
            // One coordinated commit makes all three durable together.
            let outcome = set.commit_tick();
            assert_eq!(outcome.synced.len(), 3);
            assert!(outcome.froze.is_empty());
        }

        // Reopen over the same durable image: each stream recovers clean to exactly its own records.
        let (set, recoveries) = StreamSet::open(&inner, ManualClock::new(), cfg()).unwrap();
        for id in [&def, &a, &b] {
            assert!(
                recoveries[id].loss_report.is_empty(),
                "{} recovered clean",
                id.name()
            );
        }
        assert_eq!(
            set.read_range(&def, Offset::ZERO, 100, None).unwrap().len(),
            1
        );
        let ar = set.read_range(&a, Offset::ZERO, 100, None).unwrap();
        assert_eq!(ar.len(), 2);
        assert_eq!(&*ar[0].payload, b"a0");
        assert_eq!(&*ar[1].payload, b"a1");
        assert_eq!(
            set.read_range(&b, Offset::ZERO, 100, None).unwrap().len(),
            1
        );
    }

    /// A no-op tick (a fresh set, nothing appended) issues zero barriers and an empty outcome — the
    /// `Default` outcome — so a coordinator driven on an idle pass costs nothing.
    #[test]
    fn an_idle_tick_is_a_zero_cost_noop() {
        let (mut set, _, control) = open_faulty(InMemoryFs::new());
        let before = control.sync_count();
        let outcome = set.commit_tick();
        assert_eq!(control.sync_count() - before, 0);
        assert_eq!(outcome, CommitOutcome::default());
    }

    /// #822: with MANY named streams (well past the outer worker cap), the PARALLEL open recovers
    /// every stream's own data, in a DETERMINISTIC id order, byte-for-byte identical across repeated
    /// cold opens — the parallel path's reassembly must be reproducible, never dependent on which
    /// worker won which stream. This exercises the bounded outer pool (streams > workers) end to end.
    #[test]
    fn many_named_streams_recover_in_parallel_deterministically() {
        let fs = InMemoryFs::new();
        let def = StreamId::default_stream();
        // 24 named streams > RECOVERY_OPEN_MAX_WORKERS (8), so the outer pool genuinely steals work.
        let ids: Vec<StreamId> = (0..24)
            .map(|i| StreamId::named(&format!("stream-{i:03}")).unwrap())
            .collect();
        {
            let (mut set, _) = open(&fs);
            for id in &ids {
                set.declare(id).unwrap();
            }
            set.append_to(&def, &rec(b"default")).unwrap();
            // Each named stream i gets exactly i+1 records tagged with its index, so a mis-assembled
            // (worker-order) recovery would surface as a stream holding the WRONG records.
            for (i, id) in ids.iter().enumerate() {
                for r in 0..=i {
                    set.append_to(id, &rec(format!("s{i:03}-r{r}").as_bytes()))
                        .unwrap();
                }
            }
            set.sync_all().unwrap();
        }

        // Two independent cold opens must agree exactly (reproducibility of the parallel path).
        let (set_a, rec_a) = open(&fs);
        let (set_b, rec_b) = open(&fs);

        // Deterministic id order: default first, then the named streams in sorted order.
        let mut expected_order = vec![def.clone()];
        expected_order.extend(ids.iter().cloned());
        expected_order.sort();
        assert_eq!(set_a.stream_ids(), expected_order);
        assert_eq!(set_b.stream_ids(), set_a.stream_ids());

        for (i, id) in ids.iter().enumerate() {
            // Same recovery summary from both opens (clean, no loss).
            assert!(rec_a[id].loss_report.is_empty(), "{} clean", id.name());
            assert_eq!(
                rec_a[id].recovered_truncated_bytes,
                rec_b[id].recovered_truncated_bytes
            );
            // Each stream holds exactly its OWN records — not a sibling's.
            let read = set_a.read_range(id, Offset::ZERO, 1000, None).unwrap();
            assert_eq!(read.len(), i + 1, "{} has its own record count", id.name());
            assert_eq!(&*read[0].payload, format!("s{i:03}-r0").as_bytes());
            // Byte-identical read from the second open.
            let read_b = set_b.read_range(id, Offset::ZERO, 1000, None).unwrap();
            assert_eq!(read.len(), read_b.len());
            assert_eq!(&*read[i].payload, &*read_b[i].payload);
        }
    }

    // ======================= M2-I4 (#565): the max_open_streams hot-set LRU =======================

    /// `declare` tracks each newly-opened named stream at the MRU end and the default stream is NEVER
    /// in the LRU, so `lru_victim` returns the first-declared named stream and `open_named_count`
    /// excludes the default.
    #[test]
    fn declare_tracks_the_open_set_and_default_is_never_a_victim() {
        let fs = InMemoryFs::new();
        let (mut set, _) = open(&fs);
        // No named stream open yet: nothing to evict, and the default is not counted.
        assert_eq!(set.open_named_count(), 0);
        assert_eq!(set.lru_victim(), None);

        let a = StreamId::named("a").unwrap();
        let b = StreamId::named("b").unwrap();
        let c = StreamId::named("c").unwrap();
        for id in [&a, &b, &c] {
            set.declare(id).unwrap();
        }
        assert_eq!(set.open_named_count(), 3);
        // Declared a, b, c in order -> a is the LRU (first-declared), the eviction victim.
        assert_eq!(set.lru_victim(), Some(a.clone()));
    }

    /// `touch` promotes an accessed stream to the MRU end, so a recently-touched stream is NOT the next
    /// victim — the LRU reorders on access.
    #[test]
    fn touch_reorders_the_lru_so_a_hot_stream_is_not_evicted_next() {
        let fs = InMemoryFs::new();
        let (mut set, _) = open(&fs);
        let a = StreamId::named("a").unwrap();
        let b = StreamId::named("b").unwrap();
        let c = StreamId::named("c").unwrap();
        for id in [&a, &b, &c] {
            set.declare(id).unwrap();
        }
        // Order is [a, b, c]; a is LRU. Touch a -> order becomes [b, c, a], so b is now the victim.
        assert_eq!(set.lru_victim(), Some(a.clone()));
        set.touch(&a);
        assert_eq!(set.lru_victim(), Some(b.clone()));
        // Touch b -> [c, a, b], c is the victim.
        set.touch(&b);
        assert_eq!(set.lru_victim(), Some(c.clone()));
        // Touching the default stream is a no-op (it is never in the LRU).
        set.touch(&StreamId::default_stream());
        assert_eq!(set.lru_victim(), Some(c.clone()));
    }

    /// `close` releases a named stream's log + LRU slot but leaves its on-disk subtree intact, so a
    /// later `declare` REOPENS it recovering its durable records — an evict/reopen cycle is a per-stream
    /// restart, losing no committed data. The default stream is never closable.
    #[test]
    fn close_then_reopen_recovers_the_streams_durable_records() {
        let fs = InMemoryFs::new();
        let a = StreamId::named("a").unwrap();
        {
            let (mut set, _) = open(&fs);
            set.declare(&a).unwrap();
            set.append_to(&a, &rec(b"a0")).unwrap();
            set.append_to(&a, &rec(b"a1")).unwrap();
            set.sync_all().unwrap();

            // Close (evict) a: it leaves the open set + LRU, but its bytes stay on disk.
            assert!(set.close(&a));
            assert!(!set.is_open(&a));
            assert_eq!(set.open_named_count(), 0);
            assert_eq!(set.lru_victim(), None);
            // The default stream is never closable.
            assert!(!set.close(&StreamId::default_stream()));
            assert!(set.is_open(&StreamId::default_stream()));

            // Reopen a via declare: `Log::open` recovers its two durable records from disk.
            assert!(set.declare(&a).unwrap());
            assert!(set.is_open(&a));
            let read = set.read_range(&a, Offset::ZERO, 100, None).unwrap();
            assert_eq!(
                read.len(),
                2,
                "the reopened stream recovered its durable records"
            );
            assert_eq!(&*read[0].payload, b"a0");
            assert_eq!(&*read[1].payload, b"a1");
            // Reopen re-tracked it at the MRU end (it is the only named stream, so it is the victim).
            assert_eq!(set.lru_victim(), Some(a.clone()));
        }
    }

    // At-rest AEAD encryption of a StreamSet (#780 phase 2): the SAME key encrypts the default stream
    // AND every named stream (single-node). Behind the `encryption` feature.
    #[cfg(feature = "encryption")]
    mod at_rest {
        use super::*;
        use crate::crypto::{AeadKey, AeadSuite, KeyRing, SegmentCrypto};
        use std::sync::Arc;

        const SUITE: AeadSuite = AeadSuite::ChaCha20Poly1305;
        const KEY_ID: u64 = 1;

        fn ekey(seed: u8) -> AeadKey {
            AeadKey::from_bytes([seed; crate::crypto::KEY_LEN])
        }
        fn open_enc(fs: &InMemoryFs) -> StreamSet<InMemoryFs, ManualClock> {
            let crypto = Arc::new(SegmentCrypto::new(SUITE, KEY_ID, ekey(0xA1)));
            let mut ring = KeyRing::new();
            ring.insert(KEY_ID, ekey(0xA1));
            StreamSet::open_encrypted(
                fs,
                ManualClock::new(),
                cfg(),
                Some(crypto),
                Some(Arc::new(ring)),
            )
            .unwrap()
            .0
        }
        fn contains(hay: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
        }

        #[test]
        fn default_and_named_streams_are_encrypted_on_disk_and_read_back_plaintext() {
            const MARK_D: &[u8] = b"DEFAULT-STREAM-SECRET";
            const MARK_N: &[u8] = b"NAMED-STREAM-SECRET";
            let fs = InMemoryFs::new();
            let orders = StreamId::named("orders").unwrap();
            {
                let mut set = open_enc(&fs);
                let def = StreamId::default_stream();
                set.append_to(&def, &rec(MARK_D)).unwrap();
                assert!(set.declare(&orders).unwrap());
                set.append_to(&orders, &rec(MARK_N)).unwrap();
                set.sync_stream(&def).unwrap();
                set.sync_stream(&orders).unwrap();

                // Consume: both streams read back DECRYPTED plaintext.
                assert_eq!(
                    &set.read_range(&def, Offset::ZERO, 10, None).unwrap()[0].payload[..],
                    MARK_D
                );
                assert_eq!(
                    &set.read_range(&orders, Offset::ZERO, 10, None).unwrap()[0].payload[..],
                    MARK_N
                );
            }

            // On disk: BOTH the default (root) segment AND the named-stream segment are CIPHERTEXT.
            let root_seg = fs.open(&segment_file_name(0)).unwrap().snapshot();
            assert!(
                !contains(&root_seg, MARK_D),
                "the default stream segment must be ciphertext"
            );
            let named_fs = fs
                .subdir(STREAMS_SUBDIR)
                .unwrap()
                .subdir(&stream_subdir_name(orders.name()))
                .unwrap();
            let named_seg = named_fs.open(&segment_file_name(0)).unwrap().snapshot();
            assert!(
                !contains(&named_seg, MARK_N),
                "the named stream segment must be ciphertext"
            );

            // Reopen: recovery of BOTH encrypted streams, then read everything back as plaintext.
            let set2 = open_enc(&fs);
            assert_eq!(
                &set2
                    .read_range(&StreamId::default_stream(), Offset::ZERO, 10, None)
                    .unwrap()[0]
                    .payload[..],
                MARK_D
            );
            assert_eq!(
                &set2.read_range(&orders, Offset::ZERO, 10, None).unwrap()[0].payload[..],
                MARK_N
            );
        }
    }
}
