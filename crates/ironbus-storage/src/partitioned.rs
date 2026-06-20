// SPDX-License-Identifier: MIT OR Apache-2.0
//! A `PartitionedStream`: ONE stream optionally subdivided into `P` independent sub-logs
//! (partitions) — the parallel-consume scaling lever (#591, V2-M2 M2-I11).
//!
//! ## What a partition is, and why
//!
//! A stream is, by default, ONE log with total order (every record in one durable sequence). M2-I2's
//! [`crate::streamset::StreamSet`] generalized "one broker = one log" to "one broker = N independent
//! streams, each its own log". This module generalizes the OTHER axis: "one stream = ONE log" becomes
//! "one stream = `P` independent sub-logs (partitions)", where `P = 1` (the default) is exactly
//! today's single log.
//!
//! Partitions are the multi-consumer SCALING lever. A single total-order log can be consumed by at
//! most one ordered reader at a time (order is global); `P` partitions each carry their own
//! INDEPENDENT order, so `P` consumers can drain `P` partitions in PARALLEL, each preserving
//! per-partition order — exactly Kafka's model (per-partition order, NO total order across
//! partitions). Because each partition is a full [`Log`], its per-partition cursor/poll/lease state
//! composes directly with the lock-free read plane (#539, M1-I3): `P` partitions ⇒ `P`-way parallel
//! reads with no cross-partition contention.
//!
//! ## Generalizing the `StreamSet` subdir pattern (the on-disk shape)
//!
//! This reuses the `StreamSet` idea — an independent [`Log`] per subdirectory of one [`Filesystem`],
//! same framed/CRC'd/recoverable segment format, same recovery path — applied to the partitions of
//! ONE stream:
//!
//! - `P = 1` (the DEFAULT): the stream's ONE partition IS the stream's own log AT ITS ROOT, with NO
//!   `p-*/` subdir. For the default stream `""` that root is the data-dir root (today's `seg-*.log`);
//!   for a named stream it is `streams/<hex(name)>/`. So a single-partition stream is BYTE-FOR-BYTE a
//!   non-partitioned stream on disk — the default costs nothing and changes nothing.
//! - `P > 1`: each partition `i` is an INDEPENDENT [`Log`] under `<stream-root>/p-<08x(i)>/`. The
//!   stream root holds only the `P` partition subdirs (no segments of its own).
//!
//! Routing the single-partition case to the stream root (not a `p-00000000/` subdir) is what makes
//! `P = 1` preserve today's bytes; a partitioned stream (`P > 1`) is a NEW on-disk shape, only ever
//! created when a stream explicitly declares `P > 1`.
//!
//! ## Produce routing (`key -> partition`)
//!
//! A publish picks a partition with [`ironbus_core::partition`]:
//! - a record with a KEY routes by the STABLE hash `xxh3_64(key) % P` ([`PartitionedStream::append_keyed`]),
//!   so every record sharing a key lands in the SAME partition and keeps its order there (the per-key
//!   order guarantee). The hash is the same `xxh3_64` `keyshared` uses, so there is one key-hash
//!   contract.
//! - a KEYLESS record spreads by round-robin / sticky over the partitions
//!   ([`PartitionedStream::append_keyless`]), since it has no per-key order to preserve.
//!
//! Either way the chosen partition's sub-log gets a plain single-[`Log`] append — appending to
//! partition `i` never touches partition `j`, so per-record cost stays flat as `P` grows.
//!
//! ## Consume: per-partition cursor/poll/lease ⇒ P-way parallel
//!
//! Each partition is its OWN [`Log`], so each has its OWN read position, poll, and (at the engine
//! layer) lease/work-group state — there is NO shared cursor across partitions. A competing group over
//! a `P`-partition stream can therefore have its consumers each drain a DIFFERENT partition
//! independently and in parallel (the parallel-consume win). This module lands the per-partition
//! STORAGE + read state so consume CAN scale to `P`; the actual partition→consumer ASSIGNMENT and
//! rebalance-on-join/leave is a later issue (M5.3-class) — see the scope boundary below.
//!
//! ## Per-partition resilience isolation (inherited I1–I4)
//!
//! Every partition is an independent [`Log`] over its OWN segment set, so each recovers independently:
//! longest-valid-prefix recovery, per-record CRC, and a bounded/reported [`LossReport`] over ITS OWN
//! durable bytes (I1–I4). A torn or corrupt segment in partition `i` recovers `i` to `i`'s own valid
//! prefix and `i`'s own loss report, and CANNOT shorten or corrupt a sibling partition — exactly the
//! per-stream isolation [`StreamSet`] gives across streams, now ALSO across the partitions within one
//! stream. The headline test [`tests::corrupt_one_partition_is_isolated_from_its_siblings`] asserts
//! this directly.
//!
//! ## The cross-partition `CommitCoordinator` (composes with #564)
//!
//! Per-partition logs would naively cost one `fdatasync` PER partition PER commit. As across streams
//! (M2-I3, #564), [`PartitionedStream::commit_tick`] restores group-commit ACROSS partitions: in one
//! tick it flushes every DIRTIED partition to the page cache, issues one `fdatasync` per dirtied
//! partition, and releases every parked ack together — the fsync COUNT is O(dirtied partitions/tick),
//! the per-RECORD cost stays O(1/batch). A `P = 1` stream's tick is ONE flush + ONE fdatasync + ONE
//! advance — byte- and behaviour-identical to today's single-log group-commit. The tick returns a
//! [`PartitionCommitOutcome`] that mirrors the cross-stream [`crate::streamset::CommitOutcome`], so a
//! broker's outer commit loop can fold a partitioned stream's tick into the same barrier it runs
//! across streams.
//!
//! ## Total order preserved
//!
//! `P = 1` (the default) is full total order — one partition, one cursor, today's single log. A stream
//! that needs total order simply stays single-partition; partitioning is OPT-IN per stream.
//!
//! ## Scope boundary (what this module is NOT)
//!
//! This is the partitioned-storage + key→partition produce-routing + per-partition consume-STATE
//! primitive ONLY. It deliberately does NOT do:
//! - the partition → consumer ASSIGNMENT and rebalance-on-join/leave (which consumer drains which
//!   partition, and how that re-balances when a consumer joins or leaves) — that is a later,
//!   M5.3-class issue. Here every partition's independent read state EXISTS so consume CAN scale to
//!   `P`; who is assigned to it is out of scope.
//! - the WIRE frame to DECLARE a partition count / address a partition — additive, minimal, and left
//!   to the wire wiring (it can reuse `StreamDeclare` with a partition-count field). A
//!   `PartitionedStream` is a storage/engine internal API.
//! - cross-partition transactions (a record atomic across partitions) — explicitly NOT a goal;
//!   per-partition order is the contract, like Kafka.
//! - the engine produce/consume wiring (threading a `PartitionedStream` through the server's
//!   produce/consume path) — a follow-up, same as `StreamSet`'s engine wiring was tracked separately
//!   from the `StreamSet` storage primitive.

use crate::fs::Filesystem;
use crate::log::{Append, Log, LogConfig};
use crate::loss::LossReport;
use crate::naming::partition_subdir_name;
use crate::segment::{OwnedRecord, StorageError};
use ironbus_core::clock::Clock;
use ironbus_core::partition::{
    partition_for_key, PartitionCount, PartitionIndex, PartitionSelector,
};
use ironbus_core::types::Offset;

/// A per-partition recovery summary: how partition `i` recovered (its bounded, reported loss),
/// produced by [`PartitionedStream::open`] for every partition. Because each partition recovers
/// independently, each has its OWN summary; a torn partition's non-empty loss never appears under a
/// sibling's index. Mirrors [`crate::streamset::StreamRecovery`], at the partition granularity.
#[derive(Clone, Debug)]
pub struct PartitionRecovery {
    /// The partition this summary is for (`0..P`).
    pub partition: PartitionIndex,
    /// The bytes recovery truncated from this partition's torn/unsynced active-segment tail (the
    /// silent loss, made explicit). Zero for a clean recovery.
    pub recovered_truncated_bytes: u64,
    /// The structured, versioned loss report from THIS partition's recovery: every byte span recovery
    /// skipped (torn tail or corrupt body), bounded and reported. Empty for a clean recovery. A
    /// torn/corrupt sibling partition's events are NEVER in this partition's report (the isolation
    /// property).
    pub loss_report: LossReport,
}

/// The result of [`PartitionedStream::open`]: the opened stream, paired with each partition's
/// INDEPENDENT recovery summary (indexed by partition, `0..P`). Named so the two-element tuple does
/// not trip the `type_complexity` lint and reads as one value at the call site.
pub type OpenedPartitionedStream<F, C> = (PartitionedStream<F, C>, Vec<PartitionRecovery>);

/// The result of one [`PartitionedStream::commit_tick`]: which partitions the tick synced, how many
/// `fdatasync` barriers it issued, and which (if any) FROZE on their barrier. The cross-PARTITION
/// analogue of [`crate::streamset::CommitOutcome`] (the cross-STREAM coordinator), with the SAME
/// honest cost framing: `fdatasyncs_issued == synced.len() + froze.len()` is the fsync COUNT for the
/// tick (one barrier per DIRTIED partition — `fdatasync` cannot be batched across fds), O(dirtied
/// partitions), NOT O(messages). Cold (clean) partitions are absent from every field.
///
/// A partition is identified by its [`PartitionIndex`] (not a `StreamId`): a partitioned stream is ONE
/// stream, so the row identity is the partition within it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartitionCommitOutcome {
    /// The dirtied partitions whose covering `fdatasync` SUCCEEDED this tick, each paired with its new
    /// durable head ([`Log::synced_offset`]) — the per-partition offset up to which THAT partition's
    /// parked producer acks may now release (per-partition I2). Index order.
    pub synced: Vec<(PartitionIndex, Offset)>,
    /// The dirtied partitions whose `fdatasync` FAILED this tick: each is now FROZEN read-only, its
    /// durable head was NOT advanced, and its parked acks were NOT released. A frozen partition does
    /// not brick its siblings — the rest of the tick still committed. Empty on a fully-successful tick.
    pub froze: Vec<PartitionIndex>,
    /// The number of `fdatasync` barriers this tick ISSUED — one per DIRTIED partition (success or
    /// freeze), i.e. `synced.len() + froze.len()`. The tick's fsync COUNT (the O(dirtied partitions)
    /// quantity); a clean tick (nothing dirtied) issues zero.
    pub fdatasyncs_issued: usize,
}

/// One stream stored as `P` independent, independently-recovered [`Log`]s (partitions) over one
/// [`Filesystem`] subtree, keyed by [`PartitionIndex`]: `P = 1` (the default) is the stream's ONE log
/// at its root (byte-identical to a non-partitioned stream), and `P > 1` is `P` independent [`Log`]s
/// under `p-<08x(i)>/` (the `StreamSet` subdir pattern, at the partition granularity). See the module
/// docs for the design and the scope boundary.
///
/// `F` is the backing filesystem and `C` the clock seam, exactly as for a single [`Log`]; every
/// partition shares the SAME `F` subtree and the same `C`, so they observe one consistent power-loss
/// image. The `root` filesystem is the STREAM'S root (the data-dir root for the default stream,
/// `streams/<hex(name)>/` for a named stream) — this type is agnostic to which stream it is, and the
/// caller (the `StreamSet` / engine wiring) supplies the right root.
pub struct PartitionedStream<F: Filesystem, C: Clock> {
    /// The stream's `P` partition logs, in index order `0..P`. For `P = 1` this is exactly one log,
    /// which is the stream's OWN root log (no `p-*/` subdir). For `P > 1` element `i` is the log at
    /// `p-<08x(i)>/`. Indexed by [`PartitionIndex::as_usize`], always in bounds (routing only ever
    /// produces an index `< P`).
    partitions: Vec<Log<F, C>>,
    /// The declared partition count `P` (`>= 1`), the invariant that `partitions.len() == P` upholds.
    count: PartitionCount,
    /// The round-robin / sticky selector for KEYLESS appends to THIS stream. (A real broker keeps a
    /// selector per producer CONNECTION; this owned one is the stream's default for the keyless path
    /// and for tests. Each call spreads keyless records across the partitions.)
    keyless_selector: PartitionSelector,
}

impl<F: Filesystem, C: Clock> std::fmt::Debug for PartitionedStream<F, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartitionedStream")
            .field("partition_count", &self.count.get())
            .finish_non_exhaustive()
    }
}

impl<F: Filesystem + Clone, C: Clock + Clone> PartitionedStream<F, C> {
    /// Opens (recovering, or creating fresh) a stream with `count` partitions rooted at `root`.
    ///
    /// `root` is the STREAM'S root filesystem: the data-dir root for the default stream, or
    /// `streams/<hex(name)>/` for a named stream (the caller supplies it). With:
    /// - `count == 1` (the DEFAULT): the one partition IS the stream's own log opened DIRECTLY at
    ///   `root` (no `p-*/` subdir), so this is byte-for-byte the existing single-log open — including
    ///   the #670 layout-marker check that `Log::open` performs at the root. A single-partition stream
    ///   therefore never materializes a `p-*/` subdir and is unchanged on disk.
    /// - `count > 1`: each partition `i` is opened as an INDEPENDENT [`Log`] at `root/p-<08x(i)>/`. A
    ///   partition directory is created on first open if absent (a fresh partitioned stream), or
    ///   recovered if present (a reopen). Each partition's recovery is over its OWN durable bytes
    ///   alone: a torn segment in one partition cannot touch a sibling.
    ///
    /// Recovery is INDEPENDENT per partition: the returned `Vec<PartitionRecovery>` carries each
    /// partition's own summary, and a torn/corrupt partition recovers to ITS OWN valid prefix without
    /// shortening or corrupting any sibling (the resilience-isolation property). Total recovery work is
    /// O(Σ records across all partitions) — each partition's recovery is its existing single-log
    /// recovery, run once.
    ///
    /// # Errors
    /// Propagates a [`StorageError`] from opening/recovering any partition (including the fail-closed
    /// `IncompatibleLayoutVersion` from a partition's #670 marker check) or from creating a partition
    /// subdir.
    pub fn open(
        root: &F,
        clock: C,
        config: LogConfig,
        count: PartitionCount,
    ) -> Result<OpenedPartitionedStream<F, C>, StorageError> {
        let mut partitions = Vec::with_capacity(count.get() as usize);
        let mut recoveries = Vec::with_capacity(count.get() as usize);

        if count.is_single() {
            // P = 1: the one partition IS the stream's own root log. This is the EXISTING single-log
            // open at `root` — same #670 marker check, same longest-valid-prefix recovery — so a
            // single-partition stream is byte-for-byte a non-partitioned stream. No `p-*/` subdir.
            let log = Log::open(root.clone(), clock, config)?;
            recoveries.push(recovery_of(PartitionIndex::ZERO, &log));
            partitions.push(log);
        } else {
            // P > 1: each partition i is an INDEPENDENT log at root/p-<08x(i)>/. The partition subdir
            // is created on first open (Filesystem::subdir creates it) and recovered on reopen. Open
            // them in index order so `partitions[i]` is partition i.
            for i in 0..count.get() {
                let dir = partition_subdir_name(i);
                let part_fs = root.subdir(&dir).map_err(StorageError::Io)?;
                let log = Log::open(part_fs, clock.clone(), config)?;
                let idx = PartitionIndex::new(i);
                recoveries.push(recovery_of(idx, &log));
                partitions.push(log);
            }
        }

        Ok((
            PartitionedStream {
                partitions,
                count,
                keyless_selector: PartitionSelector::new(),
            },
            recoveries,
        ))
    }
}

impl<F: Filesystem, C: Clock> PartitionedStream<F, C> {
    /// The stream's partition count `P` (`>= 1`).
    #[must_use]
    pub fn count(&self) -> PartitionCount {
        self.count
    }

    /// Whether this is a single-partition (total-order) stream (`P = 1`) — the default. A
    /// single-partition stream is today's single log: one cursor, full total order, unchanged on disk.
    #[must_use]
    pub fn is_single(&self) -> bool {
        self.count.is_single()
    }

    /// The partition a record carrying `key` would route to, WITHOUT appending — the stable hash
    /// `xxh3_64(key) % P` for a non-empty key. The same key always returns the same partition for a
    /// fixed `P` (the per-key-order property). For an EMPTY key use [`append_keyless`] /
    /// [`next_keyless_partition`] instead (a keyless record has no stable home; it round-robins).
    #[must_use]
    pub fn partition_for_key(&self, key: &[u8]) -> PartitionIndex {
        partition_for_key(key, self.count)
    }

    /// Borrows partition `idx`'s log for reads/inspection (its independent cursor/poll substrate), or
    /// `None` if `idx >= P`. Partition 0 always exists. This is the per-partition READ path: a consume
    /// targeting a specific partition resolves its log here, independently of every other partition —
    /// the per-partition state that lets `P` consumers read `P` partitions in parallel.
    #[must_use]
    pub fn partition(&self, idx: PartitionIndex) -> Option<&Log<F, C>> {
        self.partitions.get(idx.as_usize())
    }

    /// Mutably borrows partition `idx`'s log (for appends), or `None` if `idx >= P`. The append is
    /// exactly a single-[`Log`] append — appending to partition `i` never touches partition `j`, so
    /// per-record cost stays flat as `P` grows.
    pub fn partition_mut(&mut self, idx: PartitionIndex) -> Option<&mut Log<F, C>> {
        self.partitions.get_mut(idx.as_usize())
    }

    /// Routes a KEYED publish to its partition by the stable hash `xxh3_64(key) % P` and appends
    /// there, returning the partition it landed in and the [`Offset`] within that partition. Every
    /// record sharing `record.key` lands in the SAME partition and keeps its order there (per-key
    /// order). `record.key` MUST be non-empty for the per-key routing to mean anything; an empty key
    /// degenerates to partition 0 here (use [`append_keyless`] to spread a keyless record).
    ///
    /// The record is durable only after a subsequent [`commit_tick`](PartitionedStream::commit_tick)
    /// (or [`sync_all`](PartitionedStream::sync_all)).
    ///
    /// # Errors
    /// Propagates the chosen partition's [`Log::append`] error (capacity sheds, writer-frozen, etc.).
    pub fn append_keyed(
        &mut self,
        record: &Append<'_>,
    ) -> Result<(PartitionIndex, Offset), StorageError> {
        let idx = partition_for_key(record.key, self.count);
        let offset = self.partitions[idx.as_usize()].append(record)?;
        Ok((idx, offset))
    }

    /// Routes a KEYLESS publish across the partitions by round-robin (advancing the stream's selector)
    /// and appends there, returning the partition it landed in and the [`Offset`] within it. A keyless
    /// record has no per-key order to preserve, so it spreads for parallelism. Successive keyless
    /// appends cycle through the partitions.
    ///
    /// The record is durable only after a subsequent [`commit_tick`](PartitionedStream::commit_tick).
    ///
    /// # Errors
    /// Propagates the chosen partition's [`Log::append`] error.
    pub fn append_keyless(
        &mut self,
        record: &Append<'_>,
    ) -> Result<(PartitionIndex, Offset), StorageError> {
        let idx = self.keyless_selector.next(self.count);
        let offset = self.partitions[idx.as_usize()].append(record)?;
        Ok((idx, offset))
    }

    /// The partition the NEXT keyless append would use (round-robin), advancing the stream's selector
    /// WITHOUT appending. Exposed for a caller that wants to pick the keyless partition and append
    /// itself; the keyless spread is identical to [`append_keyless`].
    pub fn next_keyless_partition(&mut self) -> PartitionIndex {
        self.keyless_selector.next(self.count)
    }

    /// Routes ONE publish to its partition applying the keyed-vs-keyless split in one place (the
    /// single per-record entry point): a non-empty `record.key` routes by the stable hash, an empty
    /// key spreads by round-robin. Returns the partition and the [`Offset`] within it.
    ///
    /// # Errors
    /// Propagates the chosen partition's [`Log::append`] error.
    pub fn append(
        &mut self,
        record: &Append<'_>,
    ) -> Result<(PartitionIndex, Offset), StorageError> {
        if record.key.is_empty() {
            self.append_keyless(record)
        } else {
            self.append_keyed(record)
        }
    }

    /// Reads up to `max_records` records (and at most `max_bytes` encoded frame bytes, if set) from
    /// PARTITION `idx` starting at `start`, routing the read to that partition's log. Each partition
    /// has its own offset space (every partition starts at offset 0), so `start` is a per-partition
    /// position.
    ///
    /// # Errors
    /// Returns [`StorageError::Io`] wrapping `NotFound` if `idx >= P`, else propagates the underlying
    /// [`Log::read_range`] error.
    pub fn read_range(
        &self,
        idx: PartitionIndex,
        start: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        match self.partitions.get(idx.as_usize()) {
            Some(log) => log.read_range(start, max_records, max_bytes),
            None => Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "partition {} is out of range (stream has {} partitions)",
                    idx.get(),
                    self.count.get()
                ),
            ))),
        }
    }

    /// Makes EVERY partition's appended records durable (fsync), each independently. The
    /// correctness-first path (stops on the first partition's error); see
    /// [`commit_tick`](PartitionedStream::commit_tick) for the batched cross-partition group-commit.
    ///
    /// # Errors
    /// Propagates the first partition's [`Log::sync`] error.
    pub fn sync_all(&mut self) -> Result<(), StorageError> {
        for log in &mut self.partitions {
            log.sync()?;
        }
        Ok(())
    }

    /// THE CROSS-PARTITION GROUP-COMMIT — one commit tick over all `P` partitions: a single batched
    /// durability barrier that makes every DIRTIED partition's appended records durable and releases
    /// their parked producer acks together, while a clean/cold partition costs nothing. This is the
    /// cross-stream [`crate::streamset::StreamSet::commit_tick`] (M2-I3, #564) at the PARTITION
    /// granularity, so a partitioned stream's commit folds into the same group-commit discipline.
    ///
    /// The tick has three passes over the DIRTIED partitions ([`Log::has_unsynced_records`]):
    ///   1. **flush** — [`Log::flush_no_sync`] drains each dirtied partition's `pending` to the page
    ///      cache (cheap, no fsync);
    ///   2. **barrier** — [`Log::sync_data_only`] issues the covering `fdatasync` on each dirtied
    ///      partition's fd (K dirtied partitions = K barriers; the kernel cannot batch `fdatasync`
    ///      across fds);
    ///   3. **release** — for each partition whose barrier SUCCEEDED,
    ///      [`Log::advance_synced_offset_after_external_sync`] advances its durable head, reported in
    ///      [`PartitionCommitOutcome::synced`].
    ///
    /// The [`PartitionCommitOutcome`] mirrors the cross-stream [`crate::streamset::CommitOutcome`],
    /// keyed by [`PartitionIndex`] (a partitioned stream is ONE stream). The fsync COUNT is O(dirtied
    /// partitions this tick), the per-RECORD cost O(1/batch). A `P = 1` stream's tick is ONE flush +
    /// ONE fdatasync + ONE advance — byte/behaviour-identical to today's single-log group-commit.
    ///
    /// ### I2 + isolation
    /// Each partition's acks release ONLY after ITS OWN covering `fdatasync` (per-partition I2). A
    /// failed `fdatasync` FREEZES that one partition (recorded in [`PartitionCommitOutcome::froze`];
    /// durable head NOT advanced, acks stay parked) and the tick CONTINUES for every sibling — one bad
    /// fd does not brick the stream. This never returns `Err`: a per-partition barrier failure is
    /// reported, not raised, so one frozen partition does not abort a sibling's commit.
    #[must_use]
    pub fn commit_tick(&mut self) -> PartitionCommitOutcome {
        // Pick the DIRTIED partitions up front (index order, deterministic). A clean/cold partition —
        // or a frozen one — is never touched, so a tick's cost scales with the dirtied set, not P.
        let dirtied: Vec<usize> = self
            .partitions
            .iter()
            .enumerate()
            .filter(|(_, log)| log.has_unsynced_records())
            .map(|(i, _)| i)
            .collect();

        let mut outcome = PartitionCommitOutcome {
            synced: Vec::with_capacity(dirtied.len()),
            froze: Vec::new(),
            fdatasyncs_issued: 0,
        };

        for i in dirtied {
            let log = &mut self.partitions[i];
            // `i` came from enumerating `self.partitions`, whose length is `P <= u32::MAX`, so the
            // conversion is exact; the non-panicking `unwrap_or` fallback is unreachable (it keeps
            // `commit_tick` panic-free, so `missing_panics_doc` stays satisfied).
            let idx = PartitionIndex::new(u32::try_from(i).unwrap_or(u32::MAX));

            // PASS 1 — flush this partition's pending bytes to the page cache (no fsync). A flush
            // failure is the fatal frozen-writer class, identical to a failed barrier: record the
            // freeze, do NOT advance the durable head, and continue with the siblings.
            if log.flush_no_sync().is_err() {
                outcome.fdatasyncs_issued += 1; // the barrier this partition owed, frozen pre-sync
                outcome.froze.push(idx);
                continue;
            }

            // PASS 2 — the covering fdatasync on THIS partition's fd. K dirtied partitions => K
            // barriers (fdatasync cannot be batched across fds). One barrier per dirtied partition is
            // counted whether it succeeds or freezes the writer.
            outcome.fdatasyncs_issued += 1;
            if log.sync_data_only().is_err() {
                // The barrier failed: this one partition is now frozen read-only, its acks stay PARKED
                // (I2 upheld). Siblings continue.
                outcome.froze.push(idx);
                continue;
            }

            // PASS 3 — the barrier returned: advance THIS partition's durable head and report the
            // offset up to which its parked acks may release. Per-partition I2.
            log.advance_synced_offset_after_external_sync();
            outcome.synced.push((idx, log.synced_offset()));
        }

        outcome
    }
}

/// Captures a freshly-opened partition log's recovery outcome into an owned [`PartitionRecovery`], so
/// the per-partition recovery summary outlives the borrow of the log it came from.
fn recovery_of<F: Filesystem, C: Clock>(
    partition: PartitionIndex,
    log: &Log<F, C>,
) -> PartitionRecovery {
    PartitionRecovery {
        partition,
        recovered_truncated_bytes: log.recovered_truncated_bytes(),
        loss_report: log.loss_report().clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{FaultControl, FaultFs};
    use crate::fs::InMemoryFs;
    use crate::io::RandomAccessFile;
    use crate::naming::{parse_partition_subdir_name, segment_file_name, segment_ids};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;

    fn cfg() -> LogConfig {
        LogConfig::default()
    }

    fn keyed<'a>(key: &'a [u8], payload: &'a [u8]) -> Append<'a> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key,
            headers: b"",
            payload,
        }
    }

    fn keyless(payload: &[u8]) -> Append<'_> {
        keyed(b"", payload)
    }

    fn count(p: u32) -> PartitionCount {
        PartitionCount::new(p).unwrap()
    }

    fn open(fs: &InMemoryFs, p: u32) -> OpenedPartitionedStream<InMemoryFs, ManualClock> {
        PartitionedStream::open(fs, ManualClock::new(), cfg(), count(p)).unwrap()
    }

    /// P = 1 (the DEFAULT) is BYTE-FOR-BYTE today's single log: a single-partition stream writes the
    /// same root `seg-*.log`, never a `p-*/` subdir, identical to a bare `Log`.
    #[test]
    fn single_partition_is_byte_identical_to_a_single_log() {
        // Baseline: a bare Log over a fresh fs, two records, synced.
        let baseline_fs = InMemoryFs::new();
        {
            let mut log = Log::open(baseline_fs.clone(), ManualClock::new(), cfg()).unwrap();
            log.append(&keyed(b"k", b"a")).unwrap();
            log.append(&keyed(b"k", b"b")).unwrap();
            log.sync().unwrap();
        }

        // PartitionedStream P=1: same fresh fs, the same records, one commit.
        let part_fs = InMemoryFs::new();
        {
            let (mut stream, recoveries) = open(&part_fs, 1);
            assert_eq!(stream.count(), PartitionCount::ONE);
            assert!(stream.is_single());
            assert_eq!(recoveries.len(), 1);
            assert!(recoveries[0].loss_report.is_empty());
            // Both records route to partition 0 (P=1 collapses every key there).
            assert_eq!(
                stream.append_keyed(&keyed(b"k", b"a")).unwrap().0,
                PartitionIndex::ZERO
            );
            assert_eq!(
                stream.append_keyed(&keyed(b"k", b"b")).unwrap().0,
                PartitionIndex::ZERO
            );
            stream.sync_all().unwrap();
        }

        // No `p-*/` subdir was ever materialized: the on-disk shape is unchanged. The root segment
        // files are byte-for-byte identical to the single-log baseline.
        assert!(part_fs.list_subdirs().unwrap().is_empty());
        let baseline_ids = segment_ids(&baseline_fs).unwrap();
        let part_ids = segment_ids(&part_fs).unwrap();
        assert_eq!(baseline_ids, part_ids);
        for id in part_ids {
            let b = baseline_fs.open(&segment_file_name(id)).unwrap().snapshot();
            let s = part_fs.open(&segment_file_name(id)).unwrap().snapshot();
            assert_eq!(
                b, s,
                "segment {id} differs between single-log and P=1 stream"
            );
        }
        // And the layout marker is the same single-log image (#670).
        assert!(baseline_fs.exists("layout.meta").unwrap());
        assert!(part_fs.exists("layout.meta").unwrap());
    }

    /// A P>1 stream stores P INDEPENDENT sub-logs, one per `p-<08x(i)>/` subdir.
    #[test]
    fn multi_partition_stores_p_independent_sublogs() {
        let fs = InMemoryFs::new();
        let (mut stream, recoveries) = open(&fs, 4);
        assert_eq!(stream.count().get(), 4);
        assert!(!stream.is_single());
        assert_eq!(recoveries.len(), 4);

        // The four partition subdirs exist, named p-00000000 .. p-00000003, in index order.
        let subdirs = fs.list_subdirs().unwrap();
        assert_eq!(
            subdirs,
            vec![
                partition_subdir_name(0),
                partition_subdir_name(1),
                partition_subdir_name(2),
                partition_subdir_name(3),
            ]
        );

        // Write a record to EACH partition directly (by index) and read it back from that partition's
        // own offset space (every partition starts at offset 0). The loop var is `u8` so the payload
        // byte is a widening `u32::from`, never a truncating cast.
        for i in 0..4u8 {
            let idx = PartitionIndex::new(u32::from(i));
            stream
                .partition_mut(idx)
                .unwrap()
                .append(&keyless(&[b'p', i]))
                .unwrap();
        }
        stream.sync_all().unwrap();
        for i in 0..4u8 {
            let idx = PartitionIndex::new(u32::from(i));
            let r = stream.read_range(idx, Offset::ZERO, 100, None).unwrap();
            assert_eq!(r.len(), 1, "partition {i} holds exactly its own record");
            assert_eq!(&*r[0].payload, &[b'p', i][..]);
        }
        // Each partition's seg lives under its own subdir; the stream root holds NO segments of its
        // own (only the partition subdirs + the layout marker the first partition's open wrote).
        assert!(
            segment_ids(&fs).unwrap().is_empty(),
            "stream root has no segments of its own"
        );
    }

    /// KEY -> PARTITION IS STABLE: the same key always routes to the same partition, and records
    /// sharing a key all land in ONE partition (per-key order preserved within that partition).
    #[test]
    fn keyed_routing_is_stable_and_preserves_per_key_order_within_a_partition() {
        let fs = InMemoryFs::new();
        let (mut stream, _) = open(&fs, 8);

        // The home partition of a key is stable across repeated lookups.
        let home = stream.partition_for_key(b"order-42");
        for _ in 0..20 {
            assert_eq!(stream.partition_for_key(b"order-42"), home);
        }

        // Append several records for the SAME key: every one lands in `home`, in order.
        for n in 0..5u8 {
            let (idx, off) = stream.append_keyed(&keyed(b"order-42", &[n])).unwrap();
            assert_eq!(
                idx, home,
                "every record for the key lands in its home partition"
            );
            assert_eq!(off.get(), u64::from(n), "in-order within the partition");
        }
        // A DIFFERENT key may go to a different partition, but is itself stable.
        let other_home = stream.partition_for_key(b"order-99");
        assert_eq!(stream.partition_for_key(b"order-99"), other_home);

        stream.sync_all().unwrap();
        // `home` holds exactly the 5 same-key records, IN ORDER (per-key order within the partition).
        let recs = stream.read_range(home, Offset::ZERO, 100, None).unwrap();
        let mine: Vec<&[u8]> = recs
            .iter()
            .filter(|r| &*r.key == b"order-42")
            .map(|r| &*r.payload)
            .collect();
        assert_eq!(
            mine,
            vec![&[0u8][..], &[1][..], &[2][..], &[3][..], &[4][..]]
        );
    }

    /// KEYLESS records round-robin / sticky across partitions (no per-key order to preserve, spread
    /// for parallelism).
    #[test]
    fn keyless_records_round_robin_across_partitions() {
        let fs = InMemoryFs::new();
        let (mut stream, _) = open(&fs, 4);
        // Eight keyless appends cycle 0,1,2,3,0,1,2,3.
        let landed: Vec<u32> = (0..8)
            .map(|n| stream.append_keyless(&keyless(&[n])).unwrap().0.get())
            .collect();
        assert_eq!(landed, vec![0, 1, 2, 3, 0, 1, 2, 3]);
        stream.sync_all().unwrap();
        // Each partition got exactly two keyless records.
        for i in 0..4u32 {
            let r = stream
                .read_range(PartitionIndex::new(i), Offset::ZERO, 100, None)
                .unwrap();
            assert_eq!(
                r.len(),
                2,
                "partition {i} got its even share of keyless records"
            );
        }
    }

    /// PER-PARTITION INDEPENDENT CURSOR/CONSUME: a read on partition 0 is independent of partition 1
    /// (its own offset space + position), so P partitions are consumed in PARALLEL with no shared
    /// cursor. We assert independence by reading the two partitions at different positions.
    #[test]
    fn per_partition_consume_is_independent_p_way_parallel() {
        let fs = InMemoryFs::new();
        let (mut stream, _) = open(&fs, 2);
        let p0 = PartitionIndex::new(0);
        let p1 = PartitionIndex::new(1);
        // Partition 0 gets 3 records, partition 1 gets 1 — each its OWN offset space starting at 0.
        for n in 0..3u8 {
            stream
                .partition_mut(p0)
                .unwrap()
                .append(&keyless(&[b'a', n]))
                .unwrap();
        }
        stream
            .partition_mut(p1)
            .unwrap()
            .append(&keyless(b"b0"))
            .unwrap();
        stream.sync_all().unwrap();

        // A "consumer" on partition 0 reads from offset 1 (its own position); a consumer on partition
        // 1 reads from offset 0 — the two positions are completely independent (no shared cursor).
        let c0 = stream.read_range(p0, Offset::new(1), 100, None).unwrap();
        assert_eq!(
            c0.len(),
            2,
            "partition-0 reader resumes at its own offset 1"
        );
        assert_eq!(&*c0[0].payload, b"a\x01");
        let c1 = stream.read_range(p1, Offset::ZERO, 100, None).unwrap();
        assert_eq!(
            c1.len(),
            1,
            "partition-1 reader is unaffected by partition 0's position"
        );
        assert_eq!(&*c1[0].payload, b"b0");
        // Reading partition 0 again from 0 STILL returns all 3 — partition 1's read did not move it.
        assert_eq!(
            stream
                .read_range(p0, Offset::ZERO, 100, None)
                .unwrap()
                .len(),
            3
        );
        // An out-of-range partition is a typed error (P partitions, index P is out of range).
        assert!(stream
            .read_range(PartitionIndex::new(2), Offset::ZERO, 1, None)
            .is_err());
    }

    /// PER-PARTITION RECOVERY ISOLATION (the headline): corrupting one partition's segment recovers
    /// THAT partition bounded/reported to its valid prefix, and leaves its sibling partitions
    /// completely UNAFFECTED.
    #[test]
    fn corrupt_one_partition_is_isolated_from_its_siblings() {
        let fs = InMemoryFs::new();
        // Route distinct keys until we have a key whose home is partition 1 (the victim) and at least
        // one key home to a sibling, so we can fill specific partitions.
        {
            let (mut stream, _) = open(&fs, 3);
            // Fill partition 0 (sibling) and partition 2 (sibling) with clean data by index.
            stream
                .partition_mut(PartitionIndex::new(0))
                .unwrap()
                .append(&keyless(b"s0-keep"))
                .unwrap();
            stream
                .partition_mut(PartitionIndex::new(2))
                .unwrap()
                .append(&keyless(b"s2-keep-0"))
                .unwrap();
            stream
                .partition_mut(PartitionIndex::new(2))
                .unwrap()
                .append(&keyless(b"s2-keep-1"))
                .unwrap();
            // Fill the VICTIM partition 1 with several records; we will tear its tail.
            for n in 0..4u8 {
                stream
                    .partition_mut(PartitionIndex::new(1))
                    .unwrap()
                    .append(&keyless(&[b'v', n]))
                    .unwrap();
            }
            stream.sync_all().unwrap();
        }

        // Tear three bytes off the END of the VICTIM partition's segment 0 (its log lives at
        // root/p-00000001/seg-...0.log).
        let victim_fs = fs.subdir(&partition_subdir_name(1)).unwrap();
        let seg = victim_fs.open(&segment_file_name(0)).unwrap();
        let torn_len = seg.len().unwrap() - 3;
        seg.set_len(torn_len).unwrap();
        seg.sync_data().unwrap();

        // Reopen. The victim recovers to its OWN valid prefix + reports its OWN loss; the siblings are
        // byte-clean and fully present.
        let (stream, recoveries) = open(&fs, 3);
        // recoveries is index-ordered: [p0, p1(victim), p2].
        let v = &recoveries[1];
        assert_eq!(v.partition, PartitionIndex::new(1));
        assert!(
            v.recovered_truncated_bytes > 0,
            "the victim's torn tail was truncated"
        );
        assert!(!v.loss_report.is_empty(), "the victim's loss is reported");
        assert_eq!(v.loss_report.events.len(), 1);
        assert_eq!(
            v.loss_report.events[0].reason_code,
            crate::loss::ReasonCode::TornTail
        );
        let vread = stream
            .read_range(PartitionIndex::new(1), Offset::ZERO, 100, None)
            .unwrap();
        assert_eq!(vread.len(), 3, "the victim recovered its 3 intact records");

        // SIBLING partition 0: untouched — clean recovery, its record present.
        assert_eq!(recoveries[0].recovered_truncated_bytes, 0);
        assert!(
            recoveries[0].loss_report.is_empty(),
            "sibling p0 reports no loss"
        );
        assert_eq!(
            stream
                .read_range(PartitionIndex::new(0), Offset::ZERO, 100, None)
                .unwrap()
                .len(),
            1
        );
        // SIBLING partition 2: untouched — both records present.
        assert_eq!(recoveries[2].recovered_truncated_bytes, 0);
        assert!(
            recoveries[2].loss_report.is_empty(),
            "sibling p2 reports no loss"
        );
        assert_eq!(
            stream
                .read_range(PartitionIndex::new(2), Offset::ZERO, 100, None)
                .unwrap()
                .len(),
            2
        );
    }

    /// Reopening recovers EVERY partition independently with its own durable data.
    #[test]
    fn reopen_recovers_all_partitions_independently() {
        let fs = InMemoryFs::new();
        {
            let (mut stream, _) = open(&fs, 3);
            stream
                .partition_mut(PartitionIndex::new(0))
                .unwrap()
                .append(&keyless(b"p0"))
                .unwrap();
            stream
                .partition_mut(PartitionIndex::new(1))
                .unwrap()
                .append(&keyless(b"p1a"))
                .unwrap();
            stream
                .partition_mut(PartitionIndex::new(1))
                .unwrap()
                .append(&keyless(b"p1b"))
                .unwrap();
            stream
                .partition_mut(PartitionIndex::new(2))
                .unwrap()
                .append(&keyless(b"p2"))
                .unwrap();
            stream.sync_all().unwrap();
        }
        let (stream, recoveries) = open(&fs, 3);
        for r in &recoveries {
            assert!(
                r.loss_report.is_empty(),
                "partition {:?} recovered clean",
                r.partition
            );
        }
        assert_eq!(
            stream
                .read_range(PartitionIndex::new(0), Offset::ZERO, 100, None)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            stream
                .read_range(PartitionIndex::new(1), Offset::ZERO, 100, None)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            stream
                .read_range(PartitionIndex::new(2), Offset::ZERO, 100, None)
                .unwrap()
                .len(),
            1
        );
    }

    /// THE COMMIT COORDINATOR COMMITS MULTIPLE PARTITIONS IN ONE TICK, issuing exactly one fdatasync
    /// per DIRTIED partition (cold partitions cost nothing), over a counting fault fs.
    #[test]
    fn commit_tick_commits_multiple_partitions_in_one_tick() {
        let (fs, control): (FaultFs<InMemoryFs>, FaultControl) = FaultFs::new(InMemoryFs::new());
        let (mut stream, _) =
            PartitionedStream::open(&fs, ManualClock::new(), cfg(), count(4)).unwrap();

        // Dirty 3 of the 4 partitions (0,1,2); leave partition 3 COLD. Many records per dirtied
        // partition — the amortization is over records, the fsync count is over dirtied partitions.
        for _ in 0..10 {
            for i in 0..3u32 {
                stream
                    .partition_mut(PartitionIndex::new(i))
                    .unwrap()
                    .append(&keyless(b"r"))
                    .unwrap();
            }
        }

        let before = control.sync_count();
        let outcome = stream.commit_tick();
        let barriers = control.sync_count() - before;

        // EXACTLY 3 fdatasyncs for the 3 dirtied partitions — the cold partition 3 cost nothing.
        assert_eq!(
            barriers, 3,
            "one fdatasync per DIRTIED partition; cold partition not synced"
        );
        assert_eq!(outcome.fdatasyncs_issued, 3);
        assert_eq!(outcome.synced.len(), 3);
        assert!(outcome.froze.is_empty());
        // Each dirtied partition's durable head caught up to its append head.
        for i in 0..3u32 {
            let log = stream.partition(PartitionIndex::new(i)).unwrap();
            assert_eq!(
                log.synced_offset(),
                log.next_offset(),
                "partition {i} durable head advanced"
            );
        }

        // A second tick with nothing newly dirtied issues ZERO barriers.
        let before = control.sync_count();
        let outcome2 = stream.commit_tick();
        assert_eq!(
            control.sync_count() - before,
            0,
            "an all-clean tick issues no barrier"
        );
        assert!(outcome2.synced.is_empty());
    }

    /// A single-partition (P=1) commit tick is ONE fdatasync — byte/behaviour-identical to a single
    /// `Log::sync`, the total-order path.
    #[test]
    fn single_partition_commit_tick_is_one_fdatasync() {
        let (fs, control): (FaultFs<InMemoryFs>, FaultControl) = FaultFs::new(InMemoryFs::new());
        let (mut stream, _) =
            PartitionedStream::open(&fs, ManualClock::new(), cfg(), PartitionCount::ONE).unwrap();
        stream.append_keyed(&keyed(b"k", b"x")).unwrap();
        stream.append_keyed(&keyed(b"k", b"y")).unwrap();
        let before = control.sync_count();
        let outcome = stream.commit_tick();
        assert_eq!(
            control.sync_count() - before,
            1,
            "a single-partition tick is ONE fdatasync"
        );
        assert_eq!(outcome.fdatasyncs_issued, 1);
        assert_eq!(outcome.synced.len(), 1);
    }

    /// A FAILED fsync FREEZES one partition, leaving its siblings healthy — the freeze did not brick
    /// the stream.
    #[test]
    fn failed_fsync_freezes_one_partition_and_leaves_siblings_healthy() {
        let (fs, control): (FaultFs<InMemoryFs>, FaultControl) = FaultFs::new(InMemoryFs::new());
        let (mut stream, _) =
            PartitionedStream::open(&fs, ManualClock::new(), cfg(), count(2)).unwrap();

        // Tick 1: dirty ONLY partition 0, fail every fsync -> partition 0 freezes.
        stream
            .partition_mut(PartitionIndex::new(0))
            .unwrap()
            .append(&keyless(b"v0"))
            .unwrap();
        control.set_fail_sync(true);
        let outcome = stream.commit_tick();
        control.set_fail_sync(false);
        assert_eq!(outcome.froze.len(), 1);
        assert!(outcome.synced.is_empty());
        assert_eq!(outcome.fdatasyncs_issued, 1);
        assert!(
            !stream
                .partition(PartitionIndex::new(0))
                .unwrap()
                .is_writable(),
            "p0 frozen read-only"
        );

        // Tick 2: the sibling partition 1 commits fine; the frozen partition 0 is skipped.
        stream
            .partition_mut(PartitionIndex::new(1))
            .unwrap()
            .append(&keyless(b"s0"))
            .unwrap();
        let before = control.sync_count();
        let outcome2 = stream.commit_tick();
        assert_eq!(
            control.sync_count() - before,
            1,
            "only the healthy sibling is synced"
        );
        assert_eq!(outcome2.synced.len(), 1);
        assert!(outcome2.froze.is_empty());
        // p0 is still frozen and rejects appends; p1 is fully durable.
        assert!(stream
            .partition_mut(PartitionIndex::new(0))
            .unwrap()
            .append(&keyless(b"v1"))
            .is_err());
        let p1 = stream.partition(PartitionIndex::new(1)).unwrap();
        assert_eq!(p1.synced_offset(), p1.next_offset());
    }

    /// A foreign directory under a P>1 stream's root (not a canonical `p-*/` name) is left alone at
    /// open (the stream opens exactly its `P` partitions; a stray dir is neither opened nor consulted).
    #[test]
    fn a_foreign_subdir_under_a_partitioned_stream_is_not_opened_as_a_partition() {
        let fs = InMemoryFs::new();
        {
            let (mut stream, _) = open(&fs, 2);
            stream
                .partition_mut(PartitionIndex::new(0))
                .unwrap()
                .append(&keyless(b"x"))
                .unwrap();
            stream.sync_all().unwrap();
        }
        // Plant a foreign directory under the stream root.
        let foreign = fs.subdir("NOT-A-PARTITION").unwrap();
        foreign.create_new("junk.txt").unwrap();
        foreign.sync_dir().unwrap();
        // Reopen with the same P=2: exactly two partitions open, the foreign dir is irrelevant.
        let (stream, recoveries) = open(&fs, 2);
        assert_eq!(stream.count().get(), 2);
        assert_eq!(recoveries.len(), 2);
        assert_eq!(
            stream
                .read_range(PartitionIndex::new(0), Offset::ZERO, 100, None)
                .unwrap()
                .len(),
            1
        );
        // The foreign dir's name is not a canonical partition name.
        assert_eq!(parse_partition_subdir_name("NOT-A-PARTITION"), None);
    }
}
