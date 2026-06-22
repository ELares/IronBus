// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline mutating admin operations on a STOPPED broker's data directory (#299): the parts of the
//! mutating admin surface that are SAFE WITHOUT auth because they have no network surface.
//!
//! Issue #299 tracks a mutating admin surface (consumer reset, DLQ redrive, force-reap). A mutating
//! surface OVER THE WIRE must be auth-gated (an unauthenticated remote data-destruction endpoint is
//! an RCE-class hole); that authed wire surface is deferred to #380 / #106. This module is the
//! AUTH-FREE subset: operations an operator who already has filesystem access runs against the data
//! directory while the broker is STOPPED. There is no remote surface to authenticate, so the safety
//! boundary is "the broker is stopped and the operator owns the bytes", enforced by the CLI taking
//! the same exclusive data-dir lock `serve` holds before calling in here.
//!
//! Two operations live here:
//!
//! - [`reset_consumer`]: rewrite a work-group's durable cursor checkpoint to a chosen offset,
//!   clamped to the durable range `[earliest_retained, head]`. It reuses the EXACT codecs the
//!   broker writes: the dual-slot CRC [`Checkpoint`](crate::checkpoint::Checkpoint) and the
//!   [`AckCursor`] snapshot, so the file is byte-for-byte one the broker's recovery resumes from,
//!   not a new variant. An out-of-range target is rejected before any write.
//!
//! - [`redrive_dlq`]: re-inject the dead-lettered records from the durable DLQ sink (`dlq/`) back
//!   onto the MAIN log, so a poison batch an operator has fixed can be reprocessed. The records are
//!   appended-and-fsynced to the main log FIRST (the broker's append+sync discipline), and only
//!   THEN is a durable redrive watermark advanced; the watermark makes a completed redrive
//!   idempotent (a re-run re-injects nothing), and the ordering means a crash mid-redrive leaves a
//!   fully recoverable log (it may re-inject a suffix on the next run, at-least-once, never corrupt).
//!
//! Force-reap (reaping stuck LEASES on a LIVE broker) is inherently online: offline there are no
//! live leases to reap, and on a live broker it needs the running engine plus auth, so it is
//! deferred to the authed admin surface (#380).
//!
//! Every operation is crash-safe via the reused atomic discipline (the dual-slot checkpoint, the
//! log's write-temp+fsync+rename segment writes): a crash mid-operation leaves a recoverable data
//! directory, never a corrupt log. The CLI maps the typed [`AdminError`] onto the frozen exit-code
//! scheme.

use crate::checkpoint::Checkpoint;
use crate::dlq::{read_dlq_entries, DlqEntry};
use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use crate::layout::STREAMS_SUBDIR;
use crate::log::{Append, Log, LogConfig};
use crate::naming::{
    cursor_checkpoint_name, cursor_checkpoint_names, is_valid_stream_name,
    parse_stream_subdir_name, stream_subdir_name,
};
use crate::offline::OfflineReader;
use crate::segment::StorageError;
use crate::streamset::{StreamId, StreamSet};
use ironbus_core::clock::Clock;
use ironbus_core::cursor::AckCursor;
use ironbus_core::types::{Offset, RecordFlags};

/// The durable file recording how far the offline DLQ redrive (#299) has progressed: the count of
/// leading DLQ records already re-injected onto the main log. Stored in the SAME dual-slot CRC
/// [`Checkpoint`] the broker uses for cursors, so it inherits the identical crash-safe two-slot
/// torn-write tolerance with no new on-disk format. Its absence means "nothing redriven yet". It
/// never begins with `cursor` or `attempts`, so it is inert to cursor/attempt recovery, and it is
/// not a segment file, so the log ignores it.
const REDRIVE_CHECKPOINT: &str = "dlq-redrive.ckpt";

/// A target offset for an offline consumer reset: an explicit offset, the earliest retained record,
/// or the durable head. `Earliest` and `Latest` resolve against the live durable range so an
/// operator need not know the exact numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetTarget {
    /// Reset to this explicit committed offset (the next offset to deliver). Rejected if outside
    /// the durable range `[earliest_retained, head]`.
    Offset(u64),
    /// Reset to the earliest retained offset (redeliver every record still on disk).
    Earliest,
    /// Reset to the durable head (skip everything; the group is fully caught up).
    Latest,
}

/// The outcome of a successful [`reset_consumer`]: what the cursor was rewritten to, plus the
/// durable range it was clamped against, so the caller can report exactly what happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetOutcome {
    /// The committed offset the cursor checkpoint now holds (the resolved, clamped target).
    pub committed: u64,
    /// The previous committed offset the durable cursor held, or `None` if the group had no durable
    /// cursor before (a fresh reset of a never-checkpointed group).
    pub previous_committed: Option<u64>,
    /// The earliest retained offset the target was clamped against (the low end of the range).
    pub earliest_retained: u64,
    /// The durable head the target was clamped against (the high end of the range).
    pub head: u64,
}

/// The outcome of a successful [`redrive_dlq`]: how many records it re-injected this run and the
/// DLQ depth, so a re-run reports zero re-injected (idempotent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedriveOutcome {
    /// The number of DLQ records re-injected onto the main log on THIS run (0 on an idempotent
    /// re-run after a completed redrive).
    pub redriven: u64,
    /// The total number of DLQ records the sink holds.
    pub dlq_records: u64,
    /// The number of DLQ records already redriven before this run (the watermark on entry).
    pub already_redriven: u64,
}

/// A failure of an offline admin operation (#299), kept typed so the CLI maps it onto the frozen
/// exit-code scheme with no stringly-typed leakage.
#[derive(Debug)]
pub enum AdminError {
    /// A consumer reset target is outside the durable range `[earliest_retained, head]`, so the
    /// reset is refused rather than writing a cursor the broker could not resume from. Carries the
    /// requested offset and the range, so the operator sees exactly why.
    OutOfRange {
        /// The requested target offset.
        requested: u64,
        /// The earliest retained offset (the low end of the valid range).
        earliest_retained: u64,
        /// The durable head (the high end of the valid range, inclusive for a reset).
        head: u64,
    },
    /// The group name is one the broker would never resume: a reset to it would write a cursor the
    /// engine's group discovery skips, so it is refused rather than silently no-op. A name must be
    /// the empty default group, or 1 to [`MAX_GROUP_NAME_LEN`] graphic-ASCII bytes (the engine's
    /// `validate_group_name` rule). Carries the rejected name.
    InvalidGroup(String),
    /// A storage error reading or writing the data directory (the cursor checkpoint, the DLQ sink,
    /// or the main log). Carries the underlying [`StorageError`] so the CLI classifies a missing
    /// directory, a corrupt chain, or an IO fault exactly as the read-only verbs do.
    Storage(StorageError),
}

impl core::fmt::Display for AdminError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdminError::OutOfRange {
                requested,
                earliest_retained,
                head,
            } => write!(
                f,
                "reset target {requested} is outside the durable range [{earliest_retained}, {head}]"
            ),
            AdminError::InvalidGroup(name) => write!(
                f,
                "invalid work-group name {name:?} (the default group is \"\", otherwise 1 to {MAX_GROUP_NAME_LEN} graphic-ASCII bytes)"
            ),
            AdminError::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AdminError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AdminError::Storage(e) => Some(e),
            AdminError::OutOfRange { .. } | AdminError::InvalidGroup(_) => None,
        }
    }
}

/// The maximum work-group name length the broker accepts (the engine's `MAX_GROUP_NAME_LEN`,
/// mirrored here so the offline reset rejects exactly the names the broker's group discovery would
/// skip). Kept a small const rather than a server dependency so `ironbus-storage` stays free of
/// `ironbus-server`; a divergence would only make the offline verb stricter or looser than the
/// engine, which a test in the CLI (the broker resumes the reset group) guards against.
const MAX_GROUP_NAME_LEN: usize = 128;

/// Validates a work-group name against the broker's rule: the empty default group is always valid;
/// any other name must be 1 to [`MAX_GROUP_NAME_LEN`] graphic-ASCII bytes. A name the engine would
/// reject is refused here so a reset never writes a cursor the broker silently ignores.
fn validate_group(group: &str) -> Result<(), AdminError> {
    if group.is_empty() {
        return Ok(());
    }
    let len = group.len();
    if len > MAX_GROUP_NAME_LEN || !group.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(AdminError::InvalidGroup(group.to_string()));
    }
    Ok(())
}

impl From<StorageError> for AdminError {
    fn from(e: StorageError) -> AdminError {
        AdminError::Storage(e)
    }
}

/// Resolves a [`ResetTarget`] against the durable range and validates it. `Earliest` and `Latest`
/// resolve to the range ends (always valid). An explicit `Offset` outside `[earliest_retained,
/// head]` is REJECTED (not clamped): an operator who asks for a specific offset that does not exist
/// has made a mistake the tool surfaces, rather than silently snapping to a different offset.
fn resolve_target(
    target: ResetTarget,
    earliest_retained: u64,
    head: u64,
) -> Result<u64, AdminError> {
    match target {
        ResetTarget::Earliest => Ok(earliest_retained),
        ResetTarget::Latest => Ok(head),
        ResetTarget::Offset(o) => {
            if o < earliest_retained || o > head {
                Err(AdminError::OutOfRange {
                    requested: o,
                    earliest_retained,
                    head,
                })
            } else {
                Ok(o)
            }
        }
    }
}

/// Reads a group's CURRENT durable committed offset from its cursor checkpoint, or `None` if the
/// group has no durable cursor yet. Reuses the broker's exact decode path (the dual-slot
/// [`Checkpoint`] plus the [`AckCursor`] snapshot), so the "before" value the reset reports is the
/// one the broker would itself recover.
fn read_committed<F: Filesystem>(fs: &F, group: &str) -> Result<Option<u64>, StorageError> {
    let name = cursor_checkpoint_name(group);
    if !fs.exists(&name)? {
        return Ok(None);
    }
    let (_, recovered) = Checkpoint::open(fs.open(&name)?)?;
    let Some(payload) = recovered else {
        return Ok(None);
    };
    // The current format is the full snapshot; a payload too short to be a snapshot is the legacy
    // committed-only format (its leading 8 little-endian bytes the committed offset), matching the
    // broker's `resume_cursor_from_snapshot`. Either way we only need the committed watermark.
    if payload.len() >= AckCursor::SNAPSHOT_MIN_LEN {
        if let Ok(cursor) = AckCursor::decode_snapshot(&payload) {
            return Ok(Some(cursor.committed().get()));
        }
    }
    let committed = payload
        .get(..8)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map_or(0, u64::from_le_bytes);
    Ok(Some(committed))
}

/// One work-group's cursor as the read-only `ironbus verify` fsck sees it (#601): the group name, its
/// durable committed offset (decoded with the broker's exact codec), and whether that offset is valid
/// against the durable range `[earliest_retained, durable_head]`. A cursor below `earliest_retained`
/// (its records were reaped out from under it) or above `durable_head` (it points past the end of the
/// log) is a cursor-vs-log MISMATCH the broker would clamp on next start; verify only REPORTS it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorStatus {
    /// The work-group name (the empty string is the default group).
    pub group: String,
    /// The durable committed offset the cursor decoded to.
    pub committed: u64,
    /// `true` when `committed` is within `[earliest_retained, durable_head]`; `false` is a mismatch.
    pub in_range: bool,
}

/// Inspects every durable consumer cursor in a STOPPED broker's data directory READ-ONLY (#601, the
/// `ironbus verify` cursor pass), reporting each group's committed offset and whether it is valid
/// against the durable range `[earliest_retained, durable_head]`. It opens an [`OfflineReader`] (which
/// never mutates) to learn the range, enumerates the cursor checkpoints with
/// [`cursor_checkpoint_names`], and decodes each with the broker's exact codec (the same one
/// [`reset_consumer`] reports the "before" value with). It NEVER writes — it is the detect-and-report
/// twin of `reset_consumer`, so an `ironbus verify` run leaves every cursor byte-for-byte unchanged.
///
/// A cursor whose checkpoint is present but undecodable (both slots torn) is skipped, not reported as
/// a mismatch: a torn cursor reverts to its prior durable slot on the broker's next open exactly as
/// the checkpoint contract guarantees, so it is not a log inconsistency. Returns the statuses sorted
/// by cursor file name (matching `cursor_checkpoint_names`). Takes the filesystem BY VALUE (mirroring
/// [`OfflineReader::open`] and [`reset_consumer`]) and returns it, so the caller can reuse the handle.
///
/// # Errors
/// [`StorageError`] for a missing/corrupt data directory or an IO fault (the same classification the
/// other offline readers use).
pub fn inspect_cursors<F: Filesystem>(fs: F) -> Result<(Vec<CursorStatus>, F), StorageError> {
    // The durable range to validate each cursor against, learned read-only (no mutation). The
    // OfflineReader hands the filesystem back so the cursor decode below reuses the same handle.
    let reader = OfflineReader::open(fs)?;
    let earliest = reader.earliest_retained().get();
    let head = reader.durable_head().get();
    let fs = reader.into_filesystem();

    let mut statuses = Vec::new();
    for (group, _file) in cursor_checkpoint_names(&fs)? {
        // Decode the committed watermark with the broker's exact codec. A cursor whose both slots are
        // torn (no recovered payload) is skipped: the checkpoint reverts it cleanly on next open, so
        // it is not a log inconsistency to flag.
        if let Some(committed) = read_committed(&fs, &group)? {
            let in_range = committed >= earliest && committed <= head;
            statuses.push(CursorStatus {
                group,
                committed,
                in_range,
            });
        }
    }
    Ok((statuses, fs))
}

/// Rewrites a work-group's durable cursor checkpoint to a chosen offset, clamped to the durable
/// range `[earliest_retained, head]` (#299, the offline consumer reset). The broker must be STOPPED;
/// the caller holds the exclusive data-dir lock so this never races a live writer.
///
/// The write reuses the BROKER'S EXACT codecs: the rewritten cursor is the
/// `AckCursor::resume(target)` snapshot (committed watermark, no acked-ahead set, since a reset
/// makes the group resume cleanly from the chosen offset) stored through the dual-slot CRC
/// [`Checkpoint`]. The checkpoint's two-slot discipline is crash-safe: a crash mid-write reverts to
/// the prior durable slot, never a torn cursor. The cursor file is created (and its directory
/// fsynced) on first use exactly as the broker creates it.
///
/// `target` resolves against the live durable range; an explicit out-of-range offset is REJECTED
/// (it would make the broker resume past the head or inside a reaped hole). On success the broker's
/// next start (or an [`OfflineReader`]) resumes the group from the rewritten offset. Takes the
/// filesystem BY VALUE (mirroring [`OfflineReader::open`]) and returns it, so the caller can reuse
/// the handle.
///
/// # Errors
/// [`AdminError::OutOfRange`] if an explicit target is outside the durable range;
/// [`AdminError::Storage`] for a missing/corrupt data directory or an IO fault.
pub fn reset_consumer<F: Filesystem>(
    fs: F,
    group: &str,
    target: ResetTarget,
) -> Result<(ResetOutcome, F), AdminError> {
    // Reject a name the broker would never resume BEFORE any IO, so a reset never writes a cursor
    // the engine's group discovery silently skips (the empty default group is always valid).
    validate_group(group)?;
    // Open the data directory read-only to learn the durable range. This validates the chain (a
    // corrupt directory surfaces the same typed error the read-only verbs return) WITHOUT mutating
    // anything, then hands the filesystem back for the checkpoint write.
    let reader = OfflineReader::open(fs)?;
    let earliest_retained = reader.earliest_retained().get();
    let head = reader.durable_head().get();
    let fs = reader.into_filesystem();

    let committed = resolve_target(target, earliest_retained, head)?;
    let previous_committed = read_committed(&fs, group)?;

    // Build the cursor payload EXACTLY as the broker would for a clean resume at `committed`: an
    // AckCursor with that watermark and no acked-ahead set, snapshot-encoded. This is the same byte
    // sequence `Engine::checkpoint_cursor` writes, so the broker's recovery reads it natively.
    let cursor = AckCursor::resume(Offset::new(committed));
    let mut payload = Vec::new();
    cursor.encode_snapshot(&mut payload);

    // Open (creating + dir-syncing on first use) the cursor checkpoint and write through the
    // dual-slot CRC checkpoint, exactly as `Engine::write_group_checkpoint` does.
    write_cursor_checkpoint(&fs, group, &payload)?;

    Ok((
        ResetOutcome {
            committed,
            previous_committed,
            earliest_retained,
            head,
        },
        fs,
    ))
}

/// Writes `payload` to a work-group's cursor checkpoint via the dual-slot CRC [`Checkpoint`],
/// creating the file (and fsyncing the directory) on first use. This mirrors the broker's
/// `write_group_checkpoint` open-and-write sequence so the file is the one the broker resumes from.
fn write_cursor_checkpoint<F: Filesystem>(
    fs: &F,
    group: &str,
    payload: &[u8],
) -> Result<(), StorageError> {
    let name = cursor_checkpoint_name(group);
    let file = if fs.exists(&name)? {
        fs.open(&name)?
    } else {
        let f = fs.create_new(&name)?;
        // The new file's directory entry must be durable before its contents, exactly as the broker
        // orders it, so a power loss right after creation cannot lose the file.
        fs.sync_dir()?;
        f
    };
    let (mut cp, _) = Checkpoint::open(file)?;
    cp.write(payload)?;
    Ok(())
}

/// Re-injects the dead-lettered records from the durable DLQ sink (`dlq/`) back onto the MAIN log
/// (#299, the offline DLQ redrive), so a poison batch an operator has fixed can be reprocessed. The
/// broker must be STOPPED; the caller holds the exclusive data-dir lock. Takes the filesystem BY
/// VALUE (the main log must own it) and returns it.
///
/// Crash-safe, idempotent ordering:
/// 1. Read the DLQ entries (read-only) and the durable redrive watermark (how many DLQ records a
///    prior run already re-injected). Only the un-redriven suffix is considered.
/// 2. Append each un-redriven record's ORIGINAL payload/key/headers/timestamp to the main log via
///    the same `Log::append` the broker uses, then `Log::sync` ONCE so every re-injected record is
///    durable (fsynced) before the watermark moves.
/// 3. Advance the durable redrive watermark to the DLQ depth through the dual-slot CRC checkpoint.
///
/// The watermark is what makes a COMPLETED redrive idempotent: a re-run sees the watermark already
/// at the DLQ depth and re-injects nothing. The ordering (records durable BEFORE the watermark
/// advances) means a crash between steps 2 and 3 leaves the records re-injected but the watermark
/// not advanced, so the next run re-injects that suffix again. That is at-least-once (a duplicate
/// of the just-redriven suffix), never a corrupt log and never a lost record: the main log and the
/// DLQ sink are both intact and recoverable at every instant. The DLQ sink is PRESERVED (the
/// records stay for inspection); redrive copies forward, it does not delete the sink.
///
/// # Errors
/// [`AdminError::Storage`] for a missing/corrupt data directory or an IO fault. An absent or empty
/// DLQ is not an error (it redrives zero records).
pub fn redrive_dlq<F: Filesystem, C: Clock>(
    fs: F,
    clock: C,
    config: LogConfig,
) -> Result<(RedriveOutcome, F), AdminError> {
    // Read the DLQ entries read-only (an absent `dlq/` is an empty list, not an error). They come
    // back in DLQ-offset order, which is dead-letter order.
    let entries: Vec<DlqEntry> = read_dlq_entries(&fs)?;
    let dlq_records = entries.len() as u64;

    // The durable redrive watermark: how many leading DLQ records a prior run already re-injected.
    let already_redriven = read_redrive_watermark(&fs)?;
    // Clamp the watermark to the current DLQ length (defensive: the sink only grows, but a clamp
    // keeps the slice index sound even if the watermark were ever ahead).
    let start = usize::try_from(already_redriven)
        .unwrap_or(usize::MAX)
        .min(entries.len());
    if start == entries.len() {
        // Nothing new to redrive: a completed redrive re-run is a no-op (idempotent).
        return Ok((
            RedriveOutcome {
                redriven: 0,
                dlq_records,
                already_redriven,
            },
            fs,
        ));
    }

    // Open the MAIN log (this recovers the active tail exactly as the broker's recovery does; the
    // caller holds the lock, so this is the only writer). Append each pending record's ORIGINAL
    // content; the DLQ entry already carries the original key/headers/payload/timestamp verbatim.
    let mut log = Log::open(fs, clock, config)?;
    let mut redriven = 0u64;
    for entry in &entries[start..] {
        log.append(&Append {
            timestamp_ms: entry.timestamp_ms,
            // The payload is the original VERBATIM (the sink never decodes it), so a compressed
            // original is still compressed here: the COMPRESSED flag MUST be carried back or the
            // consumer would get a compressed stream labeled uncompressed. The main-log append
            // re-derives HAS_KEY (from the key) and HAS_XXH3 (from the size), so only the content
            // flag (COMPRESSED) is preserved from the stored DLQ record.
            flags: RecordFlags::from_bits(
                entry.original_flags.bits() & RecordFlags::COMPRESSED.bits(),
            ),
            key: &entry.key,
            headers: &entry.headers,
            payload: &entry.payload,
        })?;
        redriven += 1;
    }
    // Make every re-injected record durable BEFORE advancing the watermark: this ordering is the
    // crash-safety contract (records durable first, then the idempotency watermark).
    log.sync()?;
    let fs = log.into_filesystem();

    // Advance the durable redrive watermark to the full DLQ depth, so a re-run re-injects nothing.
    write_redrive_watermark(&fs, dlq_records)?;

    Ok((
        RedriveOutcome {
            redriven,
            dlq_records,
            already_redriven,
        },
        fs,
    ))
}

/// Reads the durable redrive watermark (the count of DLQ records already re-injected), or `0` if
/// the redrive checkpoint is absent (nothing redriven yet) or its slot is torn (the dual-slot
/// checkpoint discards a torn slot, so the value is the last fully-written one, never a torn one).
fn read_redrive_watermark<F: Filesystem>(fs: &F) -> Result<u64, StorageError> {
    if !fs.exists(REDRIVE_CHECKPOINT)? {
        return Ok(0);
    }
    let (_, recovered) = Checkpoint::open(fs.open(REDRIVE_CHECKPOINT)?)?;
    let value = recovered
        .as_deref()
        .and_then(|p| p.get(..8))
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map_or(0, u64::from_le_bytes);
    Ok(value)
}

/// Writes the redrive watermark (the count of DLQ records re-injected, little-endian) through the
/// dual-slot CRC [`Checkpoint`], creating the file (and fsyncing the directory) on first use. The
/// payload is a bare 8-byte count, well under the slot's `MAX_PAYLOAD`.
fn write_redrive_watermark<F: Filesystem>(fs: &F, watermark: u64) -> Result<(), StorageError> {
    let file = if fs.exists(REDRIVE_CHECKPOINT)? {
        fs.open(REDRIVE_CHECKPOINT)?
    } else {
        let f = fs.create_new(REDRIVE_CHECKPOINT)?;
        fs.sync_dir()?;
        f
    };
    let (mut cp, _) = Checkpoint::open(file)?;
    cp.write(&watermark.to_le_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Group + stream lifecycle management (#586): the offline subset of the nats-CLI
// `consumer`/`stream` management verbs an operator runs against a STOPPED broker's
// data directory. Every op reuses the same broker-stopped, data-dir-owned safety
// boundary as `reset_consumer`/`redrive_dlq` (the CLI holds the exclusive lock).
// ---------------------------------------------------------------------------

/// The outcome of dropping a work-group's durable state offline (#586, `group purge`/`group rm`):
/// whether a cursor checkpoint was actually removed, so the CLI reports "removed" vs "no such
/// group" (the not-found path is the caller's, mapped to exit 2). `purge` and `rm` perform the SAME
/// durable mutation today — a work-group's only durable footprint is its cursor checkpoint — so they
/// share this outcome; they differ only in the CLI's wording/intent (`purge` = drop progress, `rm` =
/// forget the group), and a future per-group durable attribute would extend `rm` without changing
/// `purge`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupDropOutcome {
    /// `true` when a durable cursor checkpoint existed and was removed; `false` when the group had no
    /// durable footprint (the caller surfaces this as not-found so a typo is never a silent success).
    pub existed: bool,
}

/// Removes a work-group's durable cursor checkpoint from a STOPPED broker's data directory (#586,
/// `group purge`/`group rm`). The broker must be STOPPED and the caller holds the exclusive data-dir
/// lock, exactly as [`reset_consumer`]. The group name is validated against the broker's rule FIRST
/// (an invalid name is refused before any IO), so this never deletes a foreign file.
///
/// The cursor checkpoint (`cursor.ckpt` for the default group, `cursor-<hex(name)>.ckpt` for a named
/// one) is a work-group's ONLY durable footprint today, so removing it is the complete drop: the
/// broker's next start sees no cursor for the group and treats it as fresh (it resumes from the
/// log's earliest retained offset on first poll, exactly as a never-seen group). The removal is
/// directory-fsynced so it is crash-durable (a power loss after this returns never resurrects the
/// cursor). `existed == false` means there was nothing to remove (the group had no durable cursor);
/// the caller decides whether that is not-found.
///
/// # Errors
/// [`AdminError::InvalidGroup`] for a name the broker would never resume; [`AdminError::Storage`]
/// for an IO fault removing the checkpoint or fsyncing the directory.
pub fn drop_group<F: Filesystem>(fs: &F, group: &str) -> Result<GroupDropOutcome, AdminError> {
    // Reject a name the broker would never resume BEFORE any IO, so a drop never targets a foreign
    // file (the empty default group is always valid). This mirrors `reset_consumer`'s ordering.
    validate_group(group)?;
    let name = cursor_checkpoint_name(group);
    if !fs.exists(&name).map_err(StorageError::Io)? {
        return Ok(GroupDropOutcome { existed: false });
    }
    fs.remove(&name).map_err(StorageError::Io)?;
    // Make the removal crash-durable: a power loss after this returns must not resurrect the cursor
    // (the same fsync-the-directory discipline a create uses, applied to a remove).
    fs.sync_dir().map_err(StorageError::Io)?;
    Ok(GroupDropOutcome { existed: true })
}

/// One named work-group's lag against the durable log (#586, `group info`/`group ls`): its committed
/// offset and the durable range, so the CLI renders the lag (`durable_head - committed`) and whether
/// the cursor is valid (in range). This is the lag-oriented twin of [`CursorStatus`] (which carries
/// only the in-range bit); it is built from the SAME read-only [`inspect_cursors`] pass plus the
/// durable head, so the two never disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupLag {
    /// The work-group name (the empty string is the default group).
    pub group: String,
    /// The durable committed offset the cursor decoded to (the next offset the group would deliver).
    pub committed: u64,
    /// `true` when `committed` is within `[earliest_retained, durable_head]`; `false` is a cursor-vs-log
    /// mismatch (a reaped-out-from-under or past-the-head cursor) the broker would clamp on next start.
    pub in_range: bool,
    /// The number of durable records the group has not yet committed (`durable_head - committed`),
    /// saturating at 0 for an out-of-range-ahead cursor so the lag is never a wild underflow.
    pub lag: u64,
}

/// Lists every work-group's lag against the durable log READ-ONLY (#586, `group ls`/`group info`),
/// reusing [`inspect_cursors`] for the per-group committed offset + in-range bit and the durable
/// head for the lag. It MUTATES NOTHING (the inspect pass is the read-only verify twin of
/// [`reset_consumer`]). Takes the filesystem BY VALUE (mirroring [`inspect_cursors`]) and returns it.
///
/// # Errors
/// [`StorageError`] for a missing/corrupt data directory or an IO fault (the same classification the
/// other offline readers use).
pub fn list_group_lag<F: Filesystem>(fs: F) -> Result<(Vec<GroupLag>, F), StorageError> {
    // The durable head the lag is measured against, learned read-only. `inspect_cursors` validates
    // the chain and hands the filesystem back, so the two passes see one consistent durable image.
    let reader = OfflineReader::open(fs)?;
    let head = reader.durable_head().get();
    let fs = reader.into_filesystem();

    let (statuses, fs) = inspect_cursors(fs)?;
    let lags = statuses
        .into_iter()
        .map(|c| GroupLag {
            lag: head.saturating_sub(c.committed),
            group: c.group,
            committed: c.committed,
            in_range: c.in_range,
        })
        .collect();
    Ok((lags, fs))
}

/// One stream's durable summary (#586, `stream ls`/`stream info`): its name (the empty string is the
/// default stream — today's root log), the durable range it spans, the record count, and whether its
/// recovery reported any loss. Built from the SAME per-stream [`OfflineReader`] the read-only verbs
/// use, so a stream summary and a per-stream verify never disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamSummary {
    /// The stream name: `""` for the default stream (the root log), else the named-stream name.
    pub stream: String,
    /// The oldest retained offset (the low end of the durable range).
    pub earliest_retained: u64,
    /// The durable head (the offset just past the last durable record).
    pub durable_head: u64,
    /// The number of durable records the stream retains (`durable_head - earliest_retained`).
    pub records: u64,
    /// `true` when the stream's recovery reported one or more loss spans (a torn/corrupt active
    /// tail). A clean stream is `false`. This is a read-only signal; the summary never repairs.
    pub has_loss: bool,
}

/// Opens a read-only [`OfflineReader`] over ONE stream's log: the data-dir root for the default
/// stream `""`, or `streams/<hex(name)>/` for a named one. The default-vs-named split mirrors
/// [`StreamSet::open`] exactly, so the offline summary reads the same bytes the broker recovers.
///
/// For a NAMED stream the subdir is probed with `subdir_exists` FIRST and a `NotFound` IO error is
/// returned if it is absent — `subdir` would otherwise CREATE the directory on demand, turning a
/// `stream info ghost` into a silent "empty stream" (and materializing a phantom). Probing keeps a
/// summary of a non-existent stream a clean not-found (exit 2) without any side effect.
fn open_stream_reader<F: Filesystem + Clone>(
    fs: &F,
    stream: &str,
) -> Result<OfflineReader<F>, StorageError> {
    if stream.is_empty() {
        OfflineReader::open(fs.clone())
    } else {
        OfflineReader::open(open_named_stream_subdir(fs, stream)?)
    }
}

/// Opens a NAMED stream's `streams/<hex(name)>/` directory filesystem, probing for it WITHOUT
/// creating it: an absent `streams/` or an absent stream subdir is a clean `NotFound` IO error, NOT
/// a silently-materialized empty stream. Shared by the read-only summary path and the destructive
/// purge path so both fail-close identically on a non-existent stream. The default stream `""` is
/// the root log and never lives under `streams/`; callers handle it separately.
fn open_named_stream_subdir<F: Filesystem + Clone>(
    fs: &F,
    stream: &str,
) -> Result<F, StorageError> {
    let absent = || {
        StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no stream {stream:?}"),
        ))
    };
    if !fs.subdir_exists(STREAMS_SUBDIR).map_err(StorageError::Io)? {
        return Err(absent());
    }
    let streams_root = fs.subdir(STREAMS_SUBDIR).map_err(StorageError::Io)?;
    let dir = stream_subdir_name(stream);
    if !streams_root.subdir_exists(&dir).map_err(StorageError::Io)? {
        return Err(absent());
    }
    streams_root.subdir(&dir).map_err(StorageError::Io)
}

/// Summarizes one stream's durable state READ-ONLY (#586, `stream info`): opens the stream's log via
/// [`open_stream_reader`] and reports its range, record count, and loss bit, MUTATING NOTHING. The
/// default stream `""` summarizes the root log; a named stream summarizes `streams/<hex(name)>/`.
///
/// # Errors
/// [`StorageError`] for a missing/corrupt stream log or an IO fault (the same classification the
/// other offline readers use). A NAMED stream whose subdir does not exist surfaces as the
/// reader's not-found (the CLI maps it to exit 2).
pub fn stream_summary<F: Filesystem + Clone>(
    fs: &F,
    stream: &str,
) -> Result<StreamSummary, StorageError> {
    let reader = open_stream_reader(fs, stream)?;
    let earliest_retained = reader.earliest_retained().get();
    let durable_head = reader.durable_head().get();
    Ok(StreamSummary {
        stream: stream.to_string(),
        earliest_retained,
        durable_head,
        records: durable_head.saturating_sub(earliest_retained),
        has_loss: !reader.loss_report().is_empty(),
    })
}

/// Lists every stream's durable summary READ-ONLY (#586, `stream ls`): the DEFAULT stream `""`
/// (always present — it is the root log) plus every NAMED stream under `streams/`, each summarized by
/// [`stream_summary`]. MUTATES NOTHING. A foreign directory under `streams/` (one whose name is not a
/// canonical hex-encoded stream name) is SKIPPED, exactly as [`StreamSet::open`] skips it. The
/// summaries are sorted default-first then by name (the deterministic `StreamId` order).
///
/// # Errors
/// [`StorageError`] for a missing/corrupt data directory, a corrupt stream log, or an IO fault.
pub fn list_streams<F: Filesystem + Clone>(fs: &F) -> Result<Vec<StreamSummary>, StorageError> {
    // The default stream is always present (the root log); summarize it first.
    let mut out = vec![stream_summary(fs, "")?];

    // Each NAMED stream already on disk under `streams/`, probed WITHOUT creating the subtree (so a
    // single-log dir is never grown), enumerated and parsed exactly as `StreamSet::open` does.
    if fs.subdir_exists(STREAMS_SUBDIR).map_err(StorageError::Io)? {
        let streams_fs = fs.subdir(STREAMS_SUBDIR).map_err(StorageError::Io)?;
        let mut names: Vec<String> = streams_fs
            .list_subdirs()
            .map_err(StorageError::Io)?
            .iter()
            .filter_map(|dir| parse_stream_subdir_name(dir))
            .collect();
        // Deterministic by name (the default is already first); a foreign dir was filtered above.
        names.sort();
        for name in names {
            out.push(stream_summary(fs, &name)?);
        }
    }
    Ok(out)
}

/// Creates a NAMED stream's durable log under `streams/<hex(name)>/` (#586, `stream create`), so a
/// subject-addressed or id-routed publish has a log to land in once the broker starts. Reuses
/// [`StreamSet::declare`] (declare-on-first-use, the EXACT path the engine's declare-on-produce and
/// declare-on-bind take), so the created stream is byte-identical to one the broker would create.
/// The broker must be STOPPED and the caller holds the exclusive data-dir lock. Returns `true` when
/// the stream was newly created, `false` when it already existed (idempotent).
///
/// The DEFAULT stream `""` cannot be "created": it is the root log and always exists, so passing it
/// is an [`AdminError::InvalidGroup`]-shaped name rejection here via [`StreamId::named`] (the empty
/// name is not a valid NAMED stream).
///
/// # Errors
/// [`StorageError`] for an invalid name (surfaced through the stream-id validation as an IO
/// `InvalidInput`) or an IO fault creating the subdir/segment. The CLI validates the name up front
/// for a clean usage error, so a bad name never reaches here in practice.
pub fn create_stream<F: Filesystem + Clone, C: Clock + Clone>(
    fs: &F,
    clock: C,
    config: LogConfig,
    stream: &str,
) -> Result<bool, StorageError> {
    let id = StreamId::named(stream).map_err(|_| {
        StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid stream name {stream:?}"),
        ))
    })?;
    // Open the whole stream set (recovering the default + any existing named streams), then declare
    // the target. `declare` is idempotent and materializes `streams/<hex>/` on first use, exactly as
    // the broker does. The set is dropped after; only the durable directory persists.
    let (mut set, _recoveries) = StreamSet::open(fs, clock, config)?;
    set.declare(&id)
}

/// The outcome of a DESTRUCTIVE offline stream op (#586, `stream purge`/`stream rm`): how many
/// durable records were dropped and how many segment files were removed, so the CLI reports exactly
/// what was destroyed. `purge` empties the stream (drops its records, keeping the stream's directory
/// so it stays a declared, ready stream); `rm` does the same removal of records (a named stream's
/// only durable content is its segments), and the CLI's `rm` wording reflects forgetting the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPurgeOutcome {
    /// The number of durable records the stream held before the purge (`durable_head -
    /// earliest_retained`), i.e. how many records this op dropped.
    pub records: u64,
    /// The number of segment files removed from the stream's log.
    pub segments_removed: u64,
}

/// Drops every durable record of a NAMED stream by removing its segment files (#586, `stream
/// purge`/`stream rm`), under the exclusive data-dir lock on a STOPPED broker. DESTRUCTIVE: the
/// records are gone after this (the caller gates it behind an explicit `--force`/`--yes` and a
/// count-of-what-will-be-deleted message). Returns the record + segment counts so the CLI reports
/// exactly what was destroyed.
///
/// The op opens the stream's log read-only FIRST (via [`open_stream_reader`]) to learn the record
/// count and the segment ids — this also VALIDATES the chain, so a corrupt stream surfaces the same
/// typed error the read-only verbs return BEFORE any deletion (fail-closed: a stream that does not
/// open cleanly is never half-deleted). Then each segment file is removed and the directory is
/// fsynced ONCE, so the empty stream is crash-durable. The stream's `streams/<hex>/` directory is
/// PRESERVED (an empty directory), so the stream stays declared and ready to receive again — exactly
/// the `purge` semantics (empty, not forgotten). The DEFAULT stream `""` cannot be purged here (it is
/// the root log shared with the default group's durable state); the caller refuses it up front.
///
/// # Errors
/// [`StorageError`] for an invalid name, a missing/corrupt stream log (fail-closed: refused before
/// any deletion), or an IO fault removing a segment or fsyncing.
pub fn purge_stream<F: Filesystem + Clone>(
    fs: &F,
    stream: &str,
) -> Result<StreamPurgeOutcome, StorageError> {
    // Refuse an invalid name and the default stream BEFORE any IO (the default stream is not a
    // `streams/` child and shares the root log; purging it is out of scope for this op).
    if !is_valid_stream_name(stream) {
        return Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid stream name {stream:?}"),
        )));
    }
    // Probe + open the stream subdir WITHOUT creating it: a missing stream is a not-found
    // (fail-closed), never a phantom empty stream materialized as a side effect of a destructive op.
    // Then open the stream's log read-only FIRST: this validates the chain (a corrupt stream is
    // refused here, before any deletion — fail-closed) and yields the record count + segment ids.
    let dir_fs = open_named_stream_subdir(fs, stream)?;
    let reader = OfflineReader::open(dir_fs)?;
    let records = reader
        .durable_head()
        .get()
        .saturating_sub(reader.earliest_retained().get());
    let segment_ids: Vec<u64> = reader.segment_ids().to_vec();
    let dir_fs = reader.into_filesystem();

    // Remove each segment file, then fsync the directory ONCE so the now-empty stream is crash-durable.
    let mut segments_removed = 0u64;
    for id in &segment_ids {
        dir_fs
            .remove(&crate::naming::segment_file_name(*id))
            .map_err(StorageError::Io)?;
        segments_removed += 1;
    }
    if segments_removed > 0 {
        dir_fs.sync_dir().map_err(StorageError::Io)?;
    }
    Ok(StreamPurgeOutcome {
        records,
        segments_removed,
    })
}

// ---------------------------------------------------------------------------
// Point-consistent backup / restore (V2-M6 #607): a single snapshot of the
// data dir — the log + the consumer cursors + the DLQ together — captured at
// ONE logical point (the broker STOPPED, the CLI holding the exclusive lock),
// and a fail-closed restore that materializes a data dir a restored verify
// passes. Reuses the broker-stopped, data-dir-owned safety boundary as the
// other offline admin ops (the CLI holds the exclusive lock around these).
// ---------------------------------------------------------------------------

/// The name of the manifest file at the root of a backup directory tree. It records the backup
/// FORMAT version, a CRC32C + length of every captured file, and the captured durable offsets, so a
/// restore can validate the backup is complete and uncorrupted before materializing a byte of it.
/// Deliberately NOT a `seg-*.log`/`cursor*.ckpt`/`layout.meta` name, so it is inert to log recovery.
pub const BACKUP_MANIFEST_FILE: &str = "MANIFEST";

/// The subdirectory of a backup tree that holds the faithful copy of the source data directory. The
/// manifest sits at the backup root; the captured tree lives under here, so the manifest and the data
/// never share a namespace (a manifest can never be mistaken for a captured file, or vice versa).
pub const BACKUP_DATA_SUBDIR: &str = "data";

/// The magic prefix of the manifest payload (IronBus `BacKuP`), distinguishing a real IronBus backup
/// manifest from an unrelated file a foreign tool might leave: a restore refuses a `MANIFEST` whose
/// payload does not start with this, fail-closed, rather than materializing an arbitrary tree.
const BACKUP_MAGIC: &str = "IBBKP";

/// The backup FORMAT version this build writes and understands. It versions the BACKUP artifact
/// layout (the manifest grammar + the `data/` tree), distinct from both the per-segment
/// `FORMAT_VERSION` and the data-dir `LAYOUT_VERSION` it captures. A restore of a backup whose format
/// version is GREATER than this is refused fail-closed (a newer backup is never half-interpreted by an
/// older binary), exactly as an unknown layout marker is refused.
pub const BACKUP_FORMAT_VERSION: u32 = 1;

/// The CLI-layer single-broker lock file (`LOCK`, #89): an `flock(2)` advisory lock the broker/CLI
/// holds, NOT storage state. It is EXCLUDED from a backup (capturing it would let a restore carry a
/// foreign lock token into a fresh dir) and is never required for `verify`/recovery, so its absence
/// from a restored dir is correct. Named here so the snapshot skips exactly it at the data-dir root.
const LOCK_FILE_NAME: &str = "LOCK";

/// A failure of a backup or restore operation (#607), kept typed so the CLI maps it onto the frozen
/// exit-code scheme. Distinct from [`AdminError`] because restore adds validation-failure cases
/// (a corrupt, incomplete, or wrong-version backup) that are neither an out-of-range reset nor a
/// plain storage fault: they are fail-closed REJECTIONS of an untrustworthy backup.
#[derive(Debug)]
pub enum BackupError {
    /// The backup's `MANIFEST` is absent, unreadable, or not a well-formed IronBus backup manifest
    /// (wrong magic or malformed grammar). The backup is rejected fail-closed; nothing is restored.
    /// Carries a human reason.
    InvalidManifest(String),
    /// The backup declares a FORMAT version this build does not understand (greater than
    /// [`BACKUP_FORMAT_VERSION`]). Refused fail-closed — a newer backup is never half-interpreted by
    /// an older binary. Carries the found version and the supported version.
    IncompatibleVersion {
        /// The backup-format version found in the manifest.
        found: u32,
        /// The backup-format version this build supports (the maximum it can restore).
        supported: u32,
    },
    /// A captured file is missing from the backup tree, or its bytes do not match the manifest's
    /// CRC32C/length (a truncated or corrupted backup). Refused fail-closed BEFORE any byte is
    /// written to the target dir, so a corrupt backup never yields a partial restore. Carries the
    /// offending relative path and a reason.
    CorruptBackup(String),
    /// The target data directory is NON-EMPTY and `--force` was not given, so the restore refuses to
    /// clobber it. Carries the count of existing entries so the CLI can report what it would have
    /// overwritten.
    TargetNotEmpty(usize),
    /// A storage/IO error reading the source dir, reading the backup, or writing the target. Carries
    /// the underlying [`StorageError`] so the CLI classifies it exactly as the other offline verbs do.
    Storage(StorageError),
}

impl core::fmt::Display for BackupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BackupError::InvalidManifest(m) => write!(f, "invalid backup manifest: {m}"),
            BackupError::IncompatibleVersion { found, supported } => write!(
                f,
                "backup format version {found} is newer than this build supports ({supported})"
            ),
            BackupError::CorruptBackup(m) => write!(f, "corrupt or incomplete backup: {m}"),
            BackupError::TargetNotEmpty(n) => write!(
                f,
                "target data directory is not empty ({n} existing entr{}); pass --force to overwrite",
                if *n == 1 { "y" } else { "ies" }
            ),
            BackupError::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BackupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BackupError::Storage(e) => Some(e),
            BackupError::InvalidManifest(_)
            | BackupError::IncompatibleVersion { .. }
            | BackupError::CorruptBackup(_)
            | BackupError::TargetNotEmpty(_) => None,
        }
    }
}

impl From<StorageError> for BackupError {
    fn from(e: StorageError) -> BackupError {
        BackupError::Storage(e)
    }
}

/// A convenience: lift a bare `io::Error` into a [`BackupError::Storage`] wrapping [`StorageError::Io`].
fn io_err(e: std::io::Error) -> BackupError {
    BackupError::Storage(StorageError::Io(e))
}

/// One captured file recorded in the manifest: its path RELATIVE to the captured `data/` root (with
/// `/` separators, so a nested `dlq/seg-...log` is one entry), the CRC32C of its bytes, and its byte
/// length. The restore re-reads each file from the backup and checks both against this before writing
/// anything to the target, so a truncated or bit-rotted backup is rejected fail-closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupFileEntry {
    /// The file's path relative to the captured `data/` root, `/`-separated (e.g. `seg-0000…0.log`
    /// or `dlq/seg-0000…0.log`). Path-safe by construction: every component is a real on-disk name.
    pub rel_path: String,
    /// The CRC32C of the file's bytes, the integrity check the restore re-computes and compares.
    pub crc32c: u32,
    /// The file's length in bytes, checked alongside the CRC (a length mismatch is a truncation).
    pub len: u64,
}

/// The outcome of a successful [`snapshot_data_dir`]: how many files (and bytes) were captured, and
/// the durable offsets recorded for the consistency self-check, so the CLI reports exactly what the
/// point-consistent snapshot covered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupOutcome {
    /// The number of files captured across the whole tree (root + every subdir).
    pub files: usize,
    /// The total bytes captured (the sum of every file's length).
    pub bytes: u64,
    /// The durable head of the default-stream log at capture time (the high end of the durable range).
    pub durable_head: u64,
    /// The earliest retained offset of the default-stream log at capture time.
    pub earliest_retained: u64,
    /// The number of consumer cursor checkpoints captured (one per work-group with durable state).
    pub cursors: usize,
    /// The number of durable DLQ records captured (the DLQ depth at the snapshot point).
    pub dlq_records: usize,
}

/// The outcome of a successful [`restore_data_dir`]: how many files (and bytes) were materialized,
/// plus the durable offsets the manifest recorded (so the CLI can report the restored point and a
/// caller can cross-check it against a post-restore `verify`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// The number of files materialized into the target data dir.
    pub files: usize,
    /// The total bytes materialized.
    pub bytes: u64,
    /// The durable head the manifest recorded at capture time (the restored log head).
    pub durable_head: u64,
    /// The earliest retained offset the manifest recorded at capture time.
    pub earliest_retained: u64,
    /// The number of consumer cursors the manifest recorded.
    pub cursors: usize,
    /// The number of DLQ records the manifest recorded.
    pub dlq_records: usize,
}

/// Recursively lists every file in a filesystem subtree as `(rel_path, bytes)` pairs, `/`-separated
/// relative to the subtree root, skipping the CLI `LOCK` file AT THE ROOT ONLY (a deeper `LOCK` is a
/// real captured byte, though no IronBus subtree writes one). Deterministic: files then subdirs, each
/// in the backend's sorted order, so two snapshots of the same bytes produce byte-identical manifests.
///
/// This is the heart of the FAITHFUL round trip: it copies EVERY file the data dir holds — segments,
/// cursor checkpoints, `counters.ckpt`, `layout.meta`, the `dlq-redrive.ckpt` watermark, the `dlq/`
/// subtree, any `streams/<hex>/` subtree, the `quarantine/` forensic store — by enumeration, so the
/// backup is the data dir's committed content with no per-artifact special-casing to drift.
fn collect_tree<F: Filesystem>(
    fs: &F,
    prefix: &str,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), BackupError> {
    let at_root = prefix.is_empty();
    for name in fs.list().map_err(io_err)? {
        // The CLI lock is transient, not storage state, and a restored dir must not carry a foreign
        // lock token: skip it at the root (the only place the broker/CLI writes it).
        if at_root && name == LOCK_FILE_NAME {
            continue;
        }
        let file = fs.open(&name).map_err(io_err)?;
        let len = usize::try_from(file.len().map_err(io_err)?).map_err(|_| {
            BackupError::Storage(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file too large to capture in one buffer",
            )))
        })?;
        let mut bytes = vec![0u8; len];
        file.read_exact_at(&mut bytes, 0).map_err(io_err)?;
        let rel = if at_root {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        out.push((rel, bytes));
    }
    for dir in fs.list_subdirs().map_err(io_err)? {
        let child = fs.subdir(&dir).map_err(io_err)?;
        let child_prefix = if at_root {
            dir.clone()
        } else {
            format!("{prefix}/{dir}")
        };
        collect_tree(&child, &child_prefix, out)?;
    }
    Ok(())
}

/// Captures the consistency self-check fields (the durable range, the cursor count, the DLQ depth)
/// from a STOPPED data dir, the same read-only reads `verify` performs. Because the broker is stopped
/// and the caller holds the exclusive lock, these are settled values: the snapshot they describe is a
/// single consistent point (no cursor can be past this head, no DLQ entry can dangle). Returns the
/// four fields; on a freshly-empty or unopenable-as-a-log dir the durable range is `(0, 0)` (an empty
/// log is a valid point).
fn capture_consistency_fields<F: Filesystem + Clone>(
    fs: &F,
) -> Result<(u64, u64, usize, usize), BackupError> {
    // The default-stream durable range, read-only. An empty/fresh dir opens as an empty log (range
    // 0..0); a structurally-corrupt dir surfaces its typed error here, refusing to back up a dir that
    // does not even open (fail-closed: a backup of an unreadable dir would be useless).
    let reader = OfflineReader::open(fs.clone())?;
    let earliest_retained = reader.earliest_retained().get();
    let durable_head = reader.durable_head().get();
    drop(reader);
    let cursors = cursor_checkpoint_names(fs).map_err(io_err)?.len();
    let dlq_records = read_dlq_entries(fs)?.len();
    Ok((earliest_retained, durable_head, cursors, dlq_records))
}

/// Serializes the manifest payload: a magic + version header, the captured durable offsets / cursor /
/// DLQ counts (the consistency self-check), then one line per captured file (`crc32c len rel_path`).
/// A line-oriented, std-only grammar (no serde, no new dep) whose every field is ASCII; the `rel_path`
/// is the last field so a `/` in it (a nested file) is unambiguous (the first two fields never contain
/// a space). The reader splits the first two fields off and takes the rest verbatim as the path.
fn encode_manifest(
    files: &[BackupFileEntry],
    earliest_retained: u64,
    durable_head: u64,
    cursors: usize,
    dlq_records: usize,
) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut s = String::new();
    // Header: magic + format version, then the self-check fields. A writeln into a String is infallible.
    let _ = writeln!(s, "{BACKUP_MAGIC} {BACKUP_FORMAT_VERSION}");
    let _ = writeln!(
        s,
        "range {earliest_retained} {durable_head} cursors {cursors} dlq {dlq_records}"
    );
    let _ = writeln!(s, "files {}", files.len());
    for e in files {
        // `crc len rel_path`: the two numeric fields are space-free, so the path (which may contain a
        // `/`) is the unambiguous remainder of the line. A path never contains a newline (a filesystem
        // name component cannot), so one entry is exactly one line.
        let _ = writeln!(s, "{} {} {}", e.crc32c, e.len, e.rel_path);
    }
    s.into_bytes()
}

/// The decoded manifest: the format version, the four self-check fields, and the per-file entries.
struct DecodedManifest {
    version: u32,
    earliest_retained: u64,
    durable_head: u64,
    cursors: usize,
    dlq_records: usize,
    files: Vec<BackupFileEntry>,
}

/// Parses a manifest payload, returning a typed [`BackupError`] for anything that is not a well-formed
/// IronBus backup manifest (wrong magic, a malformed header, a bad file line, or a file-count
/// mismatch). It does NOT yet check the format version against this build's support — the caller does
/// that — so this is a pure grammar check that fail-closes on any structural problem.
fn decode_manifest(payload: &[u8]) -> Result<DecodedManifest, BackupError> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| BackupError::InvalidManifest("manifest is not valid UTF-8".to_string()))?;
    let mut lines = text.lines();

    // Header line: `IBBKP <version>`.
    let header = lines
        .next()
        .ok_or_else(|| BackupError::InvalidManifest("empty manifest".to_string()))?;
    let mut hp = header.split(' ');
    if hp.next() != Some(BACKUP_MAGIC) {
        return Err(BackupError::InvalidManifest(
            "missing IronBus backup magic".to_string(),
        ));
    }
    let version: u32 = hp
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| BackupError::InvalidManifest("malformed format version".to_string()))?;

    // Self-check line: `range <earliest> <head> cursors <n> dlq <n>`.
    let range_line = lines
        .next()
        .ok_or_else(|| BackupError::InvalidManifest("missing range line".to_string()))?;
    // `range <earliest> <head> cursors <n> dlq <n>` — 7 space-delimited tokens.
    let rp: Vec<&str> = range_line.split(' ').collect();
    let bad_range = || BackupError::InvalidManifest("malformed range line".to_string());
    if rp.len() != 7 || rp[0] != "range" || rp[3] != "cursors" || rp[5] != "dlq" {
        return Err(bad_range());
    }
    let earliest_retained: u64 = rp[1].parse().map_err(|_| bad_range())?;
    let durable_head: u64 = rp[2].parse().map_err(|_| bad_range())?;
    let cursors: usize = rp[4].parse().map_err(|_| bad_range())?;
    let dlq_records: usize = rp[6].parse().map_err(|_| bad_range())?;

    // File-count line: `files <n>`.
    let files_line = lines
        .next()
        .ok_or_else(|| BackupError::InvalidManifest("missing files line".to_string()))?;
    let declared: usize = files_line
        .strip_prefix("files ")
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| BackupError::InvalidManifest("malformed files line".to_string()))?;

    // One entry per remaining line: `<crc> <len> <rel_path>`.
    let mut files = Vec::with_capacity(declared);
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let crc32c: u32 = parts
            .next()
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| BackupError::InvalidManifest("malformed file CRC".to_string()))?;
        let len: u64 = parts
            .next()
            .and_then(|l| l.parse().ok())
            .ok_or_else(|| BackupError::InvalidManifest("malformed file length".to_string()))?;
        let rel_path = parts
            .next()
            .ok_or_else(|| BackupError::InvalidManifest("missing file path".to_string()))?
            .to_string();
        files.push(BackupFileEntry {
            rel_path,
            crc32c,
            len,
        });
    }
    if files.len() != declared {
        return Err(BackupError::InvalidManifest(format!(
            "manifest declares {declared} files but lists {}",
            files.len()
        )));
    }
    Ok(DecodedManifest {
        version,
        earliest_retained,
        durable_head,
        cursors,
        dlq_records,
        files,
    })
}

/// Writes `bytes` to a fresh file `name` under `fs`, creating it, fsyncing its content, and fsyncing
/// the directory so the new entry is crash-durable — the same write-then-dir-sync discipline the
/// segment/checkpoint writers use. `create_new` is used so a restore can never silently clobber a file
/// (the caller has already proven the target is empty or forced an explicit clear).
fn write_durable_file<F: Filesystem>(fs: &F, name: &str, bytes: &[u8]) -> Result<(), BackupError> {
    let file = fs.create_new(name).map_err(io_err)?;
    if !bytes.is_empty() {
        file.write_all_at(bytes, 0).map_err(io_err)?;
    }
    file.sync_all().map_err(io_err)?;
    fs.sync_dir().map_err(io_err)?;
    Ok(())
}

/// Walks a `/`-separated relative path to its parent directory filesystem, creating each intermediate
/// subdir on the way (mirroring the source tree's shape under the backup or restore root), and returns
/// `(parent_fs, leaf_name)`. A single-component path returns `(root.clone(), path)`. Every component is
/// a real on-disk name, so `subdir` (which rejects `.`/`..`/`/`) is safe.
fn descend_to_parent<F: Filesystem + Clone>(
    root: &F,
    rel_path: &str,
) -> Result<(F, String), BackupError> {
    let mut components: Vec<&str> = rel_path.split('/').collect();
    let leaf = components
        .pop()
        .ok_or_else(|| BackupError::CorruptBackup(format!("empty path {rel_path:?}")))?
        .to_string();
    let mut cur = root.clone();
    for comp in components {
        cur = cur.subdir(comp).map_err(io_err)?;
    }
    Ok((cur, leaf))
}

/// Takes a POINT-CONSISTENT snapshot of a STOPPED broker's data directory (#607): the log + the
/// consumer cursors + the DLQ (and every other durable artifact) captured together at ONE logical
/// point. The broker MUST be STOPPED and the caller MUST hold the exclusive data-dir lock — that is
/// what makes the on-disk state a consistent point (the writer's checkpoints are settled), so the
/// capture reads all artifacts under one quiescent image and a restore of it cannot reintroduce
/// divergence (a cursor past the head, a dangling DLQ ref).
///
/// `src` is the data-dir filesystem; `dst` is the (empty) backup-tree filesystem. The backup is a
/// DIRECTORY TREE (no tar, no new dep): the source tree is copied verbatim under `dst`'s
/// [`BACKUP_DATA_SUBDIR`] (`data/`), and a [`BACKUP_MANIFEST_FILE`] (`MANIFEST`) at `dst`'s root
/// records the format version, a CRC32C + length of every captured file, and the captured durable
/// offsets / cursor / DLQ counts (the consistency self-check a restore re-validates). The CLI `LOCK`
/// file is excluded (it is a transient advisory lock, not storage state).
///
/// # Errors
/// [`BackupError::Storage`] for an IO fault or a structurally-unreadable source (a dir that does not
/// even open as a log is refused — a backup of an unreadable dir is useless).
pub fn snapshot_data_dir<S, D>(src: &S, dst: &D) -> Result<BackupOutcome, BackupError>
where
    S: Filesystem + Clone,
    D: Filesystem + Clone,
{
    // The consistency self-check fields, read under the quiescent (stopped + locked) image. These also
    // validate the source opens as a log: a corrupt source is refused here before anything is written.
    let (earliest_retained, durable_head, cursors, dlq_records) = capture_consistency_fields(src)?;

    // Enumerate every file in the source tree (root + subdirs), reading its bytes. Excludes the LOCK
    // file at the root. This is the faithful copy: every committed artifact, by enumeration.
    let mut captured: Vec<(String, Vec<u8>)> = Vec::new();
    collect_tree(src, "", &mut captured)?;

    // Materialize the `data/` subtree under the backup root, computing each file's CRC32C + length for
    // the manifest as we write it. `subdir` creates `data/` on first use.
    let data_root = dst.subdir(BACKUP_DATA_SUBDIR).map_err(io_err)?;
    let mut entries = Vec::with_capacity(captured.len());
    let mut total_bytes = 0u64;
    for (rel, bytes) in &captured {
        let (parent, leaf) = descend_to_parent(&data_root, rel)?;
        write_durable_file(&parent, &leaf, bytes)?;
        entries.push(BackupFileEntry {
            rel_path: rel.clone(),
            crc32c: crc32c::crc32c(bytes),
            len: bytes.len() as u64,
        });
        total_bytes += bytes.len() as u64;
    }

    // Write the manifest LAST (after every captured file is durable), so a crash mid-backup leaves a
    // backup with no manifest — which a restore rejects as invalid (fail-closed), never a manifest
    // that promises files not yet on disk.
    let manifest = encode_manifest(
        &entries,
        earliest_retained,
        durable_head,
        cursors,
        dlq_records,
    );
    write_durable_file(dst, BACKUP_MANIFEST_FILE, &manifest)?;

    Ok(BackupOutcome {
        files: entries.len(),
        bytes: total_bytes,
        durable_head,
        earliest_retained,
        cursors,
        dlq_records,
    })
}

/// Validates a backup and MATERIALIZES a data directory from it (#607), fail-closed. The backup is
/// validated WHOLE before a single byte is written to `dst`: the manifest must be a well-formed
/// IronBus backup manifest of a supported format version, and EVERY listed file must be present in the
/// backup with bytes whose CRC32C + length match the manifest. A corrupt, truncated, incomplete, or
/// wrong-version backup is REJECTED (a typed [`BackupError`]) with NOTHING written, so a restore is
/// never partial.
///
/// `backup` is the backup-tree filesystem; `dst` is the target data-dir filesystem. The target must be
/// EMPTY unless `force` is set: a restore refuses to clobber a non-empty data dir without an explicit
/// `--force` ([`BackupError::TargetNotEmpty`]). With `force`, an existing target is CLEARED first (its
/// files and subtrees removed) so the restored tree is exactly the backup's, never a merge.
///
/// After this returns the target holds a byte-faithful copy of the captured data dir, so it PASSES
/// `verify` (point-consistent: every cursor ≤ the log head, every DLQ entry resolvable) and a broker
/// resumes from the restored cursors exactly as it would from the source.
///
/// # Errors
/// [`BackupError::InvalidManifest`] / [`BackupError::IncompatibleVersion`] / [`BackupError::CorruptBackup`]
/// for an untrustworthy backup (fail-closed, nothing written); [`BackupError::TargetNotEmpty`] if the
/// target is non-empty without `force`; [`BackupError::Storage`] for an IO fault.
pub fn restore_data_dir<B, D>(
    backup: &B,
    dst: &D,
    force: bool,
) -> Result<RestoreOutcome, BackupError>
where
    B: Filesystem + Clone,
    D: Filesystem + Clone,
{
    // 1) Read + validate the manifest. A missing/unreadable/foreign manifest is refused fail-closed.
    if !backup.exists(BACKUP_MANIFEST_FILE).map_err(io_err)? {
        return Err(BackupError::InvalidManifest(
            "no MANIFEST at the backup root".to_string(),
        ));
    }
    let manifest_file = backup.open(BACKUP_MANIFEST_FILE).map_err(io_err)?;
    let mlen = usize::try_from(manifest_file.len().map_err(io_err)?)
        .map_err(|_| BackupError::InvalidManifest("manifest too large".to_string()))?;
    let mut mbytes = vec![0u8; mlen];
    manifest_file
        .read_exact_at(&mut mbytes, 0)
        .map_err(io_err)?;
    let manifest = decode_manifest(&mbytes)?;
    if manifest.version > BACKUP_FORMAT_VERSION {
        return Err(BackupError::IncompatibleVersion {
            found: manifest.version,
            supported: BACKUP_FORMAT_VERSION,
        });
    }

    // 2) Re-read every captured file from the backup tree and check its CRC32C + length against the
    //    manifest. This is done WHOLE, into memory, BEFORE any write to the target, so a corrupt or
    //    truncated backup is rejected with the target untouched (fail-closed: never a partial restore).
    let data_root = if backup.subdir_exists(BACKUP_DATA_SUBDIR).map_err(io_err)? {
        backup.subdir(BACKUP_DATA_SUBDIR).map_err(io_err)?
    } else if manifest.files.is_empty() {
        // A manifest of an empty data dir lists no files; the `data/` subdir may be absent. Use the
        // backup root as a (file-less) data root: the loop below runs zero times.
        backup.clone()
    } else {
        return Err(BackupError::CorruptBackup(
            "manifest lists files but the backup has no data/ subtree".to_string(),
        ));
    };
    let mut validated: Vec<(String, Vec<u8>)> = Vec::with_capacity(manifest.files.len());
    let mut total_bytes = 0u64;
    for entry in &manifest.files {
        let (parent, leaf) = descend_to_parent(&data_root, &entry.rel_path)?;
        if !parent.exists(&leaf).map_err(io_err)? {
            return Err(BackupError::CorruptBackup(format!(
                "file {} listed in the manifest is missing from the backup",
                entry.rel_path
            )));
        }
        let file = parent.open(&leaf).map_err(io_err)?;
        let actual_len = file.len().map_err(io_err)?;
        if actual_len != entry.len {
            return Err(BackupError::CorruptBackup(format!(
                "file {} has length {actual_len}, manifest says {}",
                entry.rel_path, entry.len
            )));
        }
        let mut bytes = vec![
            0u8;
            usize::try_from(actual_len).map_err(|_| io_err(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "file too large")
            ))?
        ];
        file.read_exact_at(&mut bytes, 0).map_err(io_err)?;
        let actual_crc = crc32c::crc32c(&bytes);
        if actual_crc != entry.crc32c {
            return Err(BackupError::CorruptBackup(format!(
                "file {} failed CRC check (got {actual_crc:#010x}, manifest {:#010x})",
                entry.rel_path, entry.crc32c
            )));
        }
        total_bytes += actual_len;
        validated.push((entry.rel_path.clone(), bytes));
    }

    // 3) Guard the target: it must be EMPTY unless `force`. The LOCK file (which the CLI created when
    //    it took the restore lock on the target) does NOT count as content. With `force`, clear the
    //    target so the restored tree is exactly the backup's.
    let existing = non_lock_entries(dst)?;
    if !existing.is_empty() {
        if !force {
            return Err(BackupError::TargetNotEmpty(existing.len()));
        }
        clear_dir(dst)?;
    }

    // 4) Materialize the validated bytes into the target. Every file is fsynced and its directory
    //    dir-synced, so the restored dir is crash-durable. Because every byte was validated in step 2,
    //    this phase only writes known-good content.
    for (rel, bytes) in &validated {
        let (parent, leaf) = descend_to_parent(dst, rel)?;
        write_durable_file(&parent, &leaf, bytes)?;
    }

    Ok(RestoreOutcome {
        files: validated.len(),
        bytes: total_bytes,
        durable_head: manifest.durable_head,
        earliest_retained: manifest.earliest_retained,
        cursors: manifest.cursors,
        dlq_records: manifest.dlq_records,
    })
}

/// Lists a data dir's entries (files + subdirs) at the ROOT, EXCLUDING the CLI `LOCK` file — the
/// content a restore's emptiness check considers. The lock is the CLI's own advisory-lock file (it
/// holds the restore lock on the target), not data; an otherwise-empty dir that holds only `LOCK` is
/// "empty" for the purpose of a clobber check.
fn non_lock_entries<F: Filesystem>(fs: &F) -> Result<Vec<String>, BackupError> {
    let mut out: Vec<String> = fs
        .list()
        .map_err(io_err)?
        .into_iter()
        .filter(|n| n != LOCK_FILE_NAME)
        .collect();
    out.extend(fs.list_subdirs().map_err(io_err)?);
    Ok(out)
}

/// Recursively removes every file and subtree under `fs`, EXCEPT the root `LOCK` file (the CLI's own
/// restore lock, which must stay held). Used by `--force` to clear a non-empty target so the restored
/// tree is exactly the backup's, never a merge of old and new. Subdir contents are removed first, then
/// the (now-empty) subdir's files; the directory entry is dir-synced so the clear is crash-durable.
fn clear_dir<F: Filesystem + Clone>(fs: &F) -> Result<(), BackupError> {
    for dir in fs.list_subdirs().map_err(io_err)? {
        let child = fs.subdir(&dir).map_err(io_err)?;
        clear_dir(&child)?;
    }
    for name in fs.list().map_err(io_err)? {
        if name == LOCK_FILE_NAME {
            continue;
        }
        fs.remove(&name).map_err(io_err)?;
    }
    fs.sync_dir().map_err(io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlq::DlqSink;
    use crate::fs::InMemoryFs;
    use crate::naming::segment_file_name;
    use crate::segment::{OwnedRecord, SegmentReader};
    use bytes::Bytes;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::Seq;

    fn cfg() -> LogConfig {
        LogConfig::default()
    }

    /// Appends `n` records to a fresh main log and returns the filesystem holding it, synced.
    fn log_with(n: u64) -> InMemoryFs {
        let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), cfg()).unwrap();
        for i in 0..n {
            log.append(&Append {
                timestamp_ms: i,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[u8::try_from(i % 256).unwrap(); 8],
            })
            .unwrap();
        }
        log.sync().unwrap();
        log.into_filesystem()
    }

    /// Reads back every durable main-log record across the directory, in order.
    fn main_records(fs: &InMemoryFs) -> Vec<OwnedRecord> {
        let reader = OfflineReader::open(fs.clone()).unwrap();
        let mut out = Vec::new();
        for &id in reader.segment_ids() {
            out.extend(reader.read_segment(id).unwrap());
        }
        out
    }

    fn source_record(offset: u64, key: &[u8], headers: &[u8], payload: &[u8]) -> OwnedRecord {
        OwnedRecord {
            offset: Offset::new(offset),
            seq: Seq::new(offset),
            timestamp_ms: 1000 + offset,
            flags: RecordFlags::EMPTY,
            key: Bytes::copy_from_slice(key),
            headers: Bytes::copy_from_slice(headers),
            payload: Bytes::copy_from_slice(payload),
        }
    }

    // --- consumer reset ---

    #[test]
    fn reset_to_an_explicit_offset_rewrites_the_cursor_the_broker_resumes_from() {
        let fs = log_with(10);
        let (outcome, fs) = reset_consumer(fs, "orders", ResetTarget::Offset(4)).unwrap();
        assert_eq!(outcome.committed, 4);
        assert_eq!(outcome.previous_committed, None);
        assert_eq!(outcome.earliest_retained, 0);
        assert_eq!(outcome.head, 10);

        // The written file is exactly a broker cursor checkpoint: dual-slot CRC checkpoint wrapping
        // an AckCursor snapshot whose committed watermark is 4.
        let name = cursor_checkpoint_name("orders");
        let (_, recovered) = Checkpoint::open(fs.open(&name).unwrap()).unwrap();
        let payload = recovered.expect("a cursor was written");
        let cursor = AckCursor::decode_snapshot(&payload).expect("the broker codec decodes it");
        assert_eq!(cursor.committed(), Offset::new(4));
        assert!(
            cursor.ahead_ranges().is_empty(),
            "a reset has no acked-ahead set"
        );
    }

    #[test]
    fn reset_earliest_and_latest_resolve_to_the_range_ends() {
        let fs = log_with(7);
        let (earliest, fs) = reset_consumer(fs, "g", ResetTarget::Earliest).unwrap();
        assert_eq!(earliest.committed, 0);
        let (latest, fs) = reset_consumer(fs, "g", ResetTarget::Latest).unwrap();
        assert_eq!(latest.committed, 7, "latest is the durable head");
        // The second reset reports the first as the previous committed value.
        assert_eq!(latest.previous_committed, Some(0));
        let _ = fs;
    }

    #[test]
    fn reset_to_the_head_is_in_range_and_accepted() {
        // The head is INCLUSIVE for a reset (commit-past-everything == caught up).
        let fs = log_with(5);
        let (outcome, _) = reset_consumer(fs, "g", ResetTarget::Offset(5)).unwrap();
        assert_eq!(outcome.committed, 5);
    }

    #[test]
    fn reset_past_the_head_is_rejected_out_of_range() {
        let fs = log_with(5);
        let err = reset_consumer(fs, "g", ResetTarget::Offset(6)).unwrap_err();
        match err {
            AdminError::OutOfRange {
                requested,
                earliest_retained,
                head,
            } => {
                assert_eq!((requested, earliest_retained, head), (6, 0, 5));
            }
            other => panic!("expected OutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn inspect_cursors_reports_in_range_and_out_of_range_read_only() {
        // The read-only `ironbus verify` cursor pass: it enumerates every cursor, decodes the
        // committed watermark with the broker's codec, and flags one out of the durable range.
        let fs = log_with(5); // durable range [0, 5]
                              // A VALID cursor (in range) via the real reset path.
        let (_, fs) = reset_consumer(fs, "good", ResetTarget::Offset(3)).unwrap();
        // An OUT-OF-RANGE cursor: write a committed offset past the head directly (bypassing the
        // clamp), the cursor-vs-log mismatch verify must catch.
        let name = cursor_checkpoint_name("bad");
        let file = fs.create_new(&name).unwrap();
        fs.sync_dir().unwrap();
        let (mut ckpt, _) = Checkpoint::open(file).unwrap();
        let mut payload = Vec::new();
        AckCursor::resume(Offset::new(99)).encode_snapshot(&mut payload);
        ckpt.write(&payload).unwrap();

        // Snapshot the cursor files to prove inspect_cursors mutates nothing.
        let good_before = fs.open(&cursor_checkpoint_name("good")).unwrap();
        let bad_before = fs.open(&name).unwrap();
        let good_bytes_before = read_all(&good_before);
        let bad_bytes_before = read_all(&bad_before);

        let (statuses, fs) = inspect_cursors(fs).unwrap();
        let good = statuses.iter().find(|c| c.group == "good").unwrap();
        let bad = statuses.iter().find(|c| c.group == "bad").unwrap();
        assert_eq!((good.committed, good.in_range), (3, true));
        assert_eq!(
            (bad.committed, bad.in_range),
            (99, false),
            "a cursor past the head is an out-of-range mismatch"
        );

        // READ-ONLY: the cursor files are byte-for-byte unchanged.
        assert_eq!(
            read_all(&fs.open(&cursor_checkpoint_name("good")).unwrap()),
            good_bytes_before
        );
        assert_eq!(read_all(&fs.open(&name).unwrap()), bad_bytes_before);
    }

    /// Reads a whole file's bytes (a test helper for the read-only assertions above).
    fn read_all<R: crate::io::RandomAccessFile>(f: &R) -> Vec<u8> {
        let len = f.len().unwrap();
        let mut buf = vec![0u8; usize::try_from(len).unwrap()];
        f.read_exact_at(&mut buf, 0).unwrap();
        buf
    }

    #[test]
    fn reset_to_an_invalid_group_name_is_rejected_before_any_write() {
        // A name the broker would never resume (non-graphic byte) is refused, so the reset never
        // writes a cursor the engine's group discovery silently skips. The empty default group and
        // a normal name are accepted.
        let fs = log_with(5);
        let bad = "bad name"; // a space is not graphic ASCII
        match reset_consumer(fs.clone(), bad, ResetTarget::Offset(0)).unwrap_err() {
            AdminError::InvalidGroup(n) => assert_eq!(n, bad),
            other => panic!("expected InvalidGroup, got {other:?}"),
        }
        // Nothing was written for the rejected name.
        assert!(!fs.exists(&cursor_checkpoint_name(bad)).unwrap());
        // The default (empty) group and a graphic-ASCII name are valid.
        reset_consumer(fs.clone(), "", ResetTarget::Offset(0)).unwrap();
        reset_consumer(fs, "orders", ResetTarget::Offset(0)).unwrap();
    }

    #[test]
    fn reset_rewrites_an_existing_cursor_and_reports_the_previous_value() {
        let fs = log_with(20);
        let (first, fs) = reset_consumer(fs, "orders", ResetTarget::Offset(15)).unwrap();
        assert_eq!(first.committed, 15);
        assert_eq!(first.previous_committed, None);
        // A second reset (e.g. rewinding) reports the prior committed offset and rewrites the same
        // file, exercising the open-existing (not create) path.
        let (second, fs) = reset_consumer(fs, "orders", ResetTarget::Offset(3)).unwrap();
        assert_eq!(second.committed, 3);
        assert_eq!(second.previous_committed, Some(15));

        let name = cursor_checkpoint_name("orders");
        let (_, recovered) = Checkpoint::open(fs.open(&name).unwrap()).unwrap();
        let cursor = AckCursor::decode_snapshot(&recovered.unwrap()).unwrap();
        assert_eq!(cursor.committed(), Offset::new(3), "the latest write wins");
    }

    #[test]
    fn a_reset_to_an_invalid_offset_does_not_write_anything() {
        // A rejected reset must change nothing: no cursor file appears for the group.
        let fs = log_with(5);
        let name = cursor_checkpoint_name("g");
        assert!(!fs.exists(&name).unwrap());
        let _ = reset_consumer(fs.clone(), "g", ResetTarget::Offset(99)).unwrap_err();
        assert!(
            !fs.exists(&name).unwrap(),
            "a rejected reset wrote no cursor file"
        );
    }

    // --- DLQ redrive ---

    /// Builds a data directory whose DLQ sink holds `poison` dead-lettered records (with a small
    /// existing main log), returning the filesystem.
    fn dir_with_dlq(main: u64, poison: u64) -> InMemoryFs {
        let fs = log_with(main);
        let mut sink = DlqSink::open(&fs, ManualClock::new(), cfg()).unwrap();
        for i in 0..poison {
            let src = source_record(100 + i, b"k", b"hdr", format!("poison-{i}").as_bytes());
            sink.append_poison("orders", &src, 6).unwrap();
        }
        fs
    }

    #[test]
    fn redrive_re_injects_every_poison_record_onto_the_main_log() {
        let fs = dir_with_dlq(3, 4);
        let before = main_records(&fs).len() as u64;
        let (outcome, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        assert_eq!(outcome.redriven, 4);
        assert_eq!(outcome.dlq_records, 4);
        assert_eq!(outcome.already_redriven, 0);
        // The four poison payloads now appear at the tail of the main log.
        let after = main_records(&fs);
        assert_eq!(after.len() as u64, before + 4);
        let tail: Vec<Vec<u8>> = after[after.len() - 4..]
            .iter()
            .map(|r| r.payload.to_vec())
            .collect();
        assert_eq!(
            tail,
            (0..4)
                .map(|i| format!("poison-{i}").into_bytes())
                .collect::<Vec<_>>()
        );
        // The DLQ sink is preserved (redrive copies forward, it does not delete the sink).
        assert_eq!(read_dlq_entries(&fs).unwrap().len(), 4);
    }

    #[test]
    fn redrive_preserves_the_compressed_flag_so_a_consumer_can_decompress() {
        // A compressed source record (the default lz4 codec, #387) is stored in the DLQ with its
        // payload VERBATIM (still compressed) plus the COMPRESSED flag. Redrive must carry COMPRESSED
        // back, or a consumer would receive a compressed stream labeled uncompressed (garbage).
        let fs = log_with(2);
        let mut sink = DlqSink::open(&fs, ManualClock::new(), cfg()).unwrap();
        let compressed_payload = b"\x04\x00\x00\x00lz4-stream-bytes".to_vec();
        let src = OwnedRecord {
            offset: Offset::new(100),
            seq: Seq::new(100),
            timestamp_ms: 1100,
            flags: RecordFlags::COMPRESSED.with(RecordFlags::HAS_KEY),
            key: Bytes::from_static(b"k"),
            headers: Bytes::from_static(b"hdr"),
            payload: Bytes::from(compressed_payload.clone()),
        };
        sink.append_poison("orders", &src, 6).unwrap();

        // The DLQ entry must carry the original COMPRESSED bit (it is not decoded by the sink).
        let entries = read_dlq_entries(&fs).unwrap();
        assert!(
            entries[0].original_flags.contains(RecordFlags::COMPRESSED),
            "the DLQ entry carries the original COMPRESSED flag"
        );

        let (outcome, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        assert_eq!(outcome.redriven, 1);
        let tail = main_records(&fs).pop().unwrap();
        assert!(
            tail.flags.contains(RecordFlags::COMPRESSED),
            "the redriven record keeps COMPRESSED so the consumer can decompress it"
        );
        assert_eq!(
            tail.payload, compressed_payload,
            "the compressed payload is preserved verbatim across the redrive"
        );
    }

    #[test]
    fn redrive_is_idempotent_on_a_re_run_no_duplicates() {
        let fs = dir_with_dlq(2, 3);
        let (first, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        assert_eq!(first.redriven, 3);
        let after_first = main_records(&fs).len() as u64;

        // A second redrive after the first completed re-injects NOTHING (the watermark covers the
        // whole DLQ), so the main log does not grow.
        let (second, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        assert_eq!(second.redriven, 0, "a completed redrive re-run is a no-op");
        assert_eq!(second.already_redriven, 3);
        assert_eq!(main_records(&fs).len() as u64, after_first, "no duplicates");
    }

    #[test]
    fn redrive_picks_up_new_poison_records_after_a_prior_redrive() {
        // Redrive 2, then dead-letter 2 more, then redrive again: only the 2 new ones re-inject.
        let fs = dir_with_dlq(1, 2);
        let (first, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        assert_eq!(first.redriven, 2);
        let mid = main_records(&fs).len() as u64;

        let mut sink = DlqSink::open(&fs, ManualClock::new(), cfg()).unwrap();
        for i in 0..2u64 {
            let src = source_record(200 + i, b"k2", b"", format!("late-{i}").as_bytes());
            sink.append_poison("orders", &src, 6).unwrap();
        }
        drop(sink);

        let (second, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        assert_eq!(second.redriven, 2, "only the 2 newly-added poison records");
        assert_eq!(second.already_redriven, 2);
        assert_eq!(main_records(&fs).len() as u64, mid + 2);
    }

    #[test]
    fn redrive_with_an_empty_or_absent_dlq_is_a_no_op() {
        // No DLQ subdir ever materialized: redrive does nothing and is not an error.
        let fs = log_with(3);
        let (outcome, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        assert_eq!(outcome.redriven, 0);
        assert_eq!(outcome.dlq_records, 0);
        // The probe must not have materialized a dlq/ subdir.
        assert!(!fs.subdir_exists("dlq").unwrap());
    }

    #[test]
    fn a_crash_before_the_watermark_advances_leaves_a_recoverable_log_and_re_redrives() {
        // Simulate the crash window between "records fsynced to the main log" and "watermark
        // advanced": the records are durable but the redrive checkpoint never moved. The next run
        // must re-inject them (at-least-once), and the log must be fully recoverable throughout.
        let fs = dir_with_dlq(2, 3);

        // Step A: re-inject the records onto the main log and fsync, but do NOT advance the
        // watermark (exactly the state a crash at the ordering point leaves).
        let entries = read_dlq_entries(&fs).unwrap();
        let mut log = Log::open(fs.clone(), ManualClock::new(), cfg()).unwrap();
        for e in &entries {
            log.append(&Append {
                timestamp_ms: e.timestamp_ms,
                flags: RecordFlags::EMPTY,
                key: &e.key,
                headers: &e.headers,
                payload: &e.payload,
            })
            .unwrap();
        }
        log.sync().unwrap();
        let crashed = log.into_filesystem();

        // The log is recoverable (a clean reopen succeeds and sees the re-injected records).
        let reopened = OfflineReader::open(crashed.clone()).unwrap();
        assert!(
            reopened.loss_report().is_empty(),
            "no corruption after the crash"
        );

        // The watermark is still 0 (never advanced), so a fresh redrive re-injects all 3 again.
        assert_eq!(read_redrive_watermark(&crashed).unwrap(), 0);
        let before = main_records(&crashed).len() as u64;
        let (outcome, after_fs) = redrive_dlq(crashed, ManualClock::new(), cfg()).unwrap();
        assert_eq!(
            outcome.redriven, 3,
            "a crash before the watermark advanced re-redrives (at-least-once)"
        );
        assert_eq!(main_records(&after_fs).len() as u64, before + 3);
    }

    #[test]
    fn the_main_log_stays_a_valid_segment_chain_after_redrive() {
        // After a redrive the active segment is still a well-formed, CRC-valid segment the recovery
        // reader accepts with no loss, proving the re-injection used the log's own append path.
        let fs = dir_with_dlq(4, 5);
        let (_, fs) = redrive_dlq(fs, ManualClock::new(), cfg()).unwrap();
        let reader = OfflineReader::open(fs.clone()).unwrap();
        assert!(reader.loss_report().is_empty());
        for &id in reader.segment_ids() {
            // Each segment scans cleanly through the recovery decode path.
            SegmentReader::open(fs.open(&segment_file_name(id)).unwrap())
                .unwrap()
                .scan()
                .unwrap();
        }
    }

    // --- group + stream management (#586) ---

    /// Declares a named stream on `fs` and appends `n` records to it, returning the filesystem. Uses
    /// the real `StreamSet` declare+append path, so the on-disk shape is exactly the broker's.
    fn fs_with_named_stream(fs: InMemoryFs, stream: &str, n: u64) -> InMemoryFs {
        let (mut set, _) = StreamSet::open(&fs, ManualClock::new(), cfg()).unwrap();
        let id = StreamId::named(stream).unwrap();
        set.declare(&id).unwrap();
        let log = set.get_mut(&id).unwrap();
        for i in 0..n {
            log.append(&Append {
                timestamp_ms: i,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[u8::try_from(i % 256).unwrap(); 8],
            })
            .unwrap();
        }
        log.sync().unwrap();
        fs
    }

    #[test]
    fn drop_group_removes_an_existing_cursor_and_reports_existed() {
        // A group with a durable cursor: drop_group removes the checkpoint and reports existed=true;
        // a re-drop reports existed=false (idempotent, the not-found signal the CLI maps to exit 2).
        let fs = log_with(10);
        let (_, fs) = reset_consumer(fs, "orders", ResetTarget::Offset(4)).unwrap();
        assert!(fs.exists(&cursor_checkpoint_name("orders")).unwrap());

        let first = drop_group(&fs, "orders").unwrap();
        assert!(first.existed, "an existing cursor is removed");
        assert!(
            !fs.exists(&cursor_checkpoint_name("orders")).unwrap(),
            "the cursor file is gone after a drop"
        );

        let second = drop_group(&fs, "orders").unwrap();
        assert!(!second.existed, "a re-drop is not-found (idempotent)");
    }

    #[test]
    fn drop_group_on_a_never_seen_group_reports_not_existed() {
        let fs = log_with(3);
        let outcome = drop_group(&fs, "ghost").unwrap();
        assert!(!outcome.existed, "no durable footprint -> not-found");
        assert!(!fs.exists(&cursor_checkpoint_name("ghost")).unwrap());
    }

    #[test]
    fn drop_group_rejects_an_invalid_name_before_any_io() {
        let fs = log_with(3);
        match drop_group(&fs, "bad name").unwrap_err() {
            AdminError::InvalidGroup(n) => assert_eq!(n, "bad name"),
            other => panic!("expected InvalidGroup, got {other:?}"),
        }
    }

    #[test]
    fn list_group_lag_reports_committed_in_range_and_lag() {
        // Two groups at different offsets over a log with durable head 10; lag = head - committed.
        let fs = log_with(10);
        let (_, fs) = reset_consumer(fs, "fast", ResetTarget::Offset(8)).unwrap();
        let (_, fs) = reset_consumer(fs, "slow", ResetTarget::Offset(2)).unwrap();
        let (lags, _fs) = list_group_lag(fs).unwrap();
        let fast = lags.iter().find(|g| g.group == "fast").unwrap();
        let slow = lags.iter().find(|g| g.group == "slow").unwrap();
        assert_eq!((fast.committed, fast.lag, fast.in_range), (8, 2, true));
        assert_eq!((slow.committed, slow.lag, slow.in_range), (2, 8, true));
    }

    #[test]
    fn list_streams_reports_the_default_and_named_streams() {
        // The default stream is always present (the root log); a named stream is summarized too.
        let fs = log_with(6); // root log: 6 records
        let fs = fs_with_named_stream(fs, "orders", 4);
        let summaries = list_streams(&fs).unwrap();
        let default = summaries.iter().find(|s| s.stream.is_empty()).unwrap();
        let orders = summaries.iter().find(|s| s.stream == "orders").unwrap();
        assert_eq!(default.records, 6, "the root log holds 6 records");
        assert!(!default.has_loss);
        assert_eq!(orders.records, 4, "the named stream holds 4 records");
        assert!(!orders.has_loss);
        // The default stream sorts first (the deterministic StreamId order).
        assert!(summaries[0].stream.is_empty());
    }

    #[test]
    fn stream_summary_of_a_missing_named_stream_is_not_found_without_materializing_it() {
        // A `stream info ghost` over a dir with no such stream is a clean not-found, and it must NOT
        // create a phantom `streams/<hex(ghost)>/` as a side effect (the probe-before-open contract).
        let fs = log_with(3);
        let err = stream_summary(&fs, "ghost").unwrap_err();
        match err {
            StorageError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected a not-found IO error, got {other:?}"),
        }
        // No phantom stream materialized.
        assert!(
            !fs.subdir_exists(STREAMS_SUBDIR).unwrap(),
            "a not-found summary never creates the streams/ subtree"
        );
    }

    #[test]
    fn create_stream_materializes_a_named_stream_idempotently() {
        let fs = log_with(2);
        let created = create_stream(&fs, ManualClock::new(), cfg(), "events").unwrap();
        assert!(created, "the stream is newly created");
        assert!(fs.subdir_exists(STREAMS_SUBDIR).unwrap());
        // It now appears in the listing as an empty stream.
        let summaries = list_streams(&fs).unwrap();
        let events = summaries.iter().find(|s| s.stream == "events").unwrap();
        assert_eq!(events.records, 0);
        // A re-create is idempotent (returns false, no error).
        let again = create_stream(&fs, ManualClock::new(), cfg(), "events").unwrap();
        assert!(!again, "a re-create is idempotent");
    }

    #[test]
    fn create_stream_rejects_the_default_and_invalid_names() {
        let fs = log_with(1);
        // The empty (default) name is not a valid NAMED stream.
        assert!(create_stream(&fs, ManualClock::new(), cfg(), "").is_err());
        // A non-graphic name is rejected.
        assert!(create_stream(&fs, ManualClock::new(), cfg(), "bad name").is_err());
    }

    #[test]
    fn purge_stream_drops_every_record_and_reports_the_counts() {
        let fs = log_with(2);
        let fs = fs_with_named_stream(fs, "orders", 5);
        // Before: the stream holds 5 records.
        assert_eq!(stream_summary(&fs, "orders").unwrap().records, 5);

        let outcome = purge_stream(&fs, "orders").unwrap();
        assert_eq!(outcome.records, 5, "5 records were dropped");
        assert!(
            outcome.segments_removed >= 1,
            "at least one segment removed"
        );

        // After: the stream's directory is preserved (still declared) but empty.
        let after = stream_summary(&fs, "orders").unwrap();
        assert_eq!(after.records, 0, "the stream is empty after a purge");
        assert!(
            fs.subdir(STREAMS_SUBDIR)
                .unwrap()
                .subdir_exists(&stream_subdir_name("orders"))
                .unwrap(),
            "the stream directory is preserved (purge empties, it does not forget)"
        );
        // The root log is untouched (blast-radius isolation).
        assert_eq!(stream_summary(&fs, "").unwrap().records, 2);
    }

    #[test]
    fn purge_stream_refuses_the_default_and_invalid_names() {
        let fs = log_with(4);
        // The default stream cannot be purged here (it is the root log).
        assert!(purge_stream(&fs, "").is_err());
        // An invalid name is refused before any IO.
        assert!(purge_stream(&fs, "bad name").is_err());
        // The root log is untouched after the refusals.
        assert_eq!(stream_summary(&fs, "").unwrap().records, 4);
    }

    // --- backup / restore (#607) ---

    /// Reads back every cursor's committed offset as a sorted `(group, committed)` map, for comparing a
    /// source dir and its restored copy.
    fn cursor_map(fs: &InMemoryFs) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = inspect_cursors(fs.clone())
            .unwrap()
            .0
            .into_iter()
            .map(|c| (c.group, c.committed))
            .collect();
        out.sort();
        out
    }

    /// The complete sorted list of `(rel_path, bytes)` across a data dir's whole tree (root + subdirs),
    /// excluding the LOCK file, so two dirs can be compared byte-for-byte. Reuses the snapshot walker.
    fn tree_image(fs: &InMemoryFs) -> Vec<(String, Vec<u8>)> {
        let mut v = Vec::new();
        collect_tree(fs, "", &mut v).unwrap();
        v.sort();
        v
    }

    /// Builds a rich source data dir: a main log, named-stream logs, several work-group cursors (one
    /// reset to mid-log), and a populated DLQ — so a round-trip exercises every artifact class.
    fn rich_source(main: u64, poison: u64) -> InMemoryFs {
        let fs = dir_with_dlq(main, poison);
        // A couple of named streams (the `streams/<hex>/` subtree).
        create_stream(&fs, ManualClock::new(), cfg(), "orders").unwrap();
        create_stream(&fs, ManualClock::new(), cfg(), "events").unwrap();
        // Several cursors, including the default group and a mid-log reset (an in-range cursor).
        let (_, fs) = reset_consumer(fs, "", ResetTarget::Offset(1)).unwrap();
        let (_, fs) = reset_consumer(fs, "g1", ResetTarget::Offset(main.min(2))).unwrap();
        let (_, fs) = reset_consumer(fs, "g2", ResetTarget::Latest).unwrap();
        fs
    }

    #[test]
    fn snapshot_then_restore_round_trips_the_whole_data_dir_byte_for_byte() {
        let src = rich_source(6, 3);
        let src_tree = tree_image(&src);
        let src_cursors = cursor_map(&src);
        let src_main = main_records(&src);
        let src_dlq = read_dlq_entries(&src).unwrap().len();

        // Backup into a fresh tree, then restore into a fresh (empty) data dir.
        let backup = InMemoryFs::new();
        let bout = snapshot_data_dir(&src, &backup).unwrap();
        assert!(bout.files > 0);
        assert_eq!(bout.cursors, src_cursors.len());
        assert_eq!(bout.dlq_records, src_dlq);

        let restored = InMemoryFs::new();
        let rout = restore_data_dir(&backup, &restored, false).unwrap();
        assert_eq!(rout.files, bout.files);
        assert_eq!(rout.bytes, bout.bytes);
        assert_eq!(rout.durable_head, bout.durable_head);
        assert_eq!(rout.cursors, bout.cursors);
        assert_eq!(rout.dlq_records, bout.dlq_records);

        // FAITHFUL: the restored tree is byte-for-byte the source, and the high-level views match.
        assert_eq!(tree_image(&restored), src_tree, "byte-faithful tree");
        assert_eq!(cursor_map(&restored), src_cursors, "cursors match");
        assert_eq!(
            read_dlq_entries(&restored).unwrap().len(),
            src_dlq,
            "DLQ matches"
        );
        assert_eq!(
            main_records(&restored).len(),
            src_main.len(),
            "main log records match"
        );
    }

    #[test]
    fn restored_dir_is_point_consistent_every_cursor_within_the_durable_range() {
        // The consistency oracle (the same range check `ironbus verify` runs): after a restore, every
        // cursor is within [earliest_retained, durable_head] and the DLQ depth is intact — by
        // construction, since the source was captured at one quiescent point.
        let src = rich_source(8, 2);
        let backup = InMemoryFs::new();
        snapshot_data_dir(&src, &backup).unwrap();
        let restored = InMemoryFs::new();
        restore_data_dir(&backup, &restored, false).unwrap();

        let reader = OfflineReader::open(restored.clone()).unwrap();
        let earliest = reader.earliest_retained().get();
        let head = reader.durable_head().get();
        drop(reader);
        for (group, committed) in cursor_map(&restored) {
            assert!(
                committed >= earliest && committed <= head,
                "cursor {group:?} committed {committed} must be within [{earliest}, {head}]"
            );
        }
    }

    #[test]
    fn restore_refuses_a_non_empty_target_without_force_then_overwrites_with_force() {
        let src = rich_source(4, 1);
        let backup = InMemoryFs::new();
        snapshot_data_dir(&src, &backup).unwrap();

        // A target that already holds a (different) data dir: restore without force is refused.
        let target = log_with(99);
        let before = tree_image(&target);
        match restore_data_dir(&backup, &target, false).unwrap_err() {
            BackupError::TargetNotEmpty(n) => assert!(n > 0),
            other => panic!("expected TargetNotEmpty, got {other:?}"),
        }
        // The refused restore wrote NOTHING (the target is byte-for-byte unchanged).
        assert_eq!(tree_image(&target), before, "a refused restore is a no-op");

        // With --force the target is cleared and replaced by exactly the backup's tree.
        restore_data_dir(&backup, &target, true).unwrap();
        let src_tree = {
            let fresh = InMemoryFs::new();
            restore_data_dir(&backup, &fresh, false).unwrap();
            tree_image(&fresh)
        };
        assert_eq!(
            tree_image(&target),
            src_tree,
            "force overwrote with the backup"
        );
    }

    #[test]
    fn restore_rejects_a_corrupt_truncated_or_wrong_version_backup_fail_closed() {
        let src = rich_source(5, 2);

        // (a) A flipped byte in a captured file fails the CRC check, with the target untouched.
        let backup = InMemoryFs::new();
        snapshot_data_dir(&src, &backup).unwrap();
        let data = backup.subdir(BACKUP_DATA_SUBDIR).unwrap();
        let a_seg = data
            .list()
            .unwrap()
            .into_iter()
            .find(|n| n.starts_with("seg-"))
            .unwrap();
        let f = data.open(&a_seg).unwrap();
        let mut b = vec![0u8; usize::try_from(f.len().unwrap()).unwrap()];
        f.read_exact_at(&mut b, 0).unwrap();
        b[0] ^= 0xff;
        f.write_all_at(&b, 0).unwrap();
        let target = InMemoryFs::new();
        assert!(matches!(
            restore_data_dir(&backup, &target, false).unwrap_err(),
            BackupError::CorruptBackup(_)
        ));
        assert!(
            non_lock_entries(&target).unwrap().is_empty(),
            "no partial restore"
        );

        // (b) A missing captured file is a corrupt backup.
        let backup2 = InMemoryFs::new();
        snapshot_data_dir(&src, &backup2).unwrap();
        let data2 = backup2.subdir(BACKUP_DATA_SUBDIR).unwrap();
        let some = data2
            .list()
            .unwrap()
            .into_iter()
            .find(|n| n.starts_with("seg-"))
            .unwrap();
        data2.remove(&some).unwrap();
        let t2 = InMemoryFs::new();
        assert!(matches!(
            restore_data_dir(&backup2, &t2, false).unwrap_err(),
            BackupError::CorruptBackup(_)
        ));
        assert!(non_lock_entries(&t2).unwrap().is_empty());

        // (c) A missing manifest is an invalid backup.
        let backup3 = InMemoryFs::new();
        snapshot_data_dir(&src, &backup3).unwrap();
        backup3.remove(BACKUP_MANIFEST_FILE).unwrap();
        let t3 = InMemoryFs::new();
        assert!(matches!(
            restore_data_dir(&backup3, &t3, false).unwrap_err(),
            BackupError::InvalidManifest(_)
        ));

        // (d) A future format version is refused fail-closed.
        let backup4 = InMemoryFs::new();
        snapshot_data_dir(&src, &backup4).unwrap();
        let mf = backup4.open(BACKUP_MANIFEST_FILE).unwrap();
        let mut mb = vec![0u8; usize::try_from(mf.len().unwrap()).unwrap()];
        mf.read_exact_at(&mut mb, 0).unwrap();
        // Rewrite the version field (the second whitespace-delimited token of line 1) to a future value.
        let text = String::from_utf8(mb).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines[0] = format!("{BACKUP_MAGIC} {}", BACKUP_FORMAT_VERSION + 1);
        let rewritten = format!("{}\n", lines.join("\n")).into_bytes();
        mf.set_len(0).unwrap();
        mf.write_all_at(&rewritten, 0).unwrap();
        let t4 = InMemoryFs::new();
        assert!(matches!(
            restore_data_dir(&backup4, &t4, false).unwrap_err(),
            BackupError::IncompatibleVersion { found, supported }
                if found == BACKUP_FORMAT_VERSION + 1 && supported == BACKUP_FORMAT_VERSION
        ));
    }

    #[test]
    fn snapshot_excludes_the_lock_file_and_an_empty_dir_round_trips() {
        // A LOCK file at the root (the CLI's advisory lock) is NOT captured: a restored dir carries no
        // foreign lock token.
        let src = log_with(3);
        src.create_new("LOCK").unwrap();
        src.sync_dir().unwrap();
        let backup = InMemoryFs::new();
        let out = snapshot_data_dir(&src, &backup).unwrap();
        let data = backup.subdir(BACKUP_DATA_SUBDIR).unwrap();
        assert!(
            !data.exists("LOCK").unwrap(),
            "LOCK is excluded from the backup"
        );
        let restored = InMemoryFs::new();
        restore_data_dir(&backup, &restored, false).unwrap();
        assert!(
            !restored.exists("LOCK").unwrap(),
            "no LOCK in the restored dir"
        );
        assert_eq!(out.files, restored.list().unwrap().len());

        // A brand-new (never-opened) data dir backs up and restores cleanly (an empty log is a valid
        // consistent point: range 0..0, no cursors, no DLQ).
        let empty_src = InMemoryFs::new();
        let empty_backup = InMemoryFs::new();
        let eout = snapshot_data_dir(&empty_src, &empty_backup).unwrap();
        assert_eq!(
            (eout.durable_head, eout.cursors, eout.dlq_records),
            (0, 0, 0)
        );
        let empty_restored = InMemoryFs::new();
        restore_data_dir(&empty_backup, &empty_restored, false).unwrap();
        // The restored empty dir opens as an empty log.
        let r = OfflineReader::open(empty_restored).unwrap();
        assert_eq!(r.durable_head().get(), 0);
    }

    #[test]
    fn a_redrive_after_restore_continues_correctly_from_the_restored_state() {
        // Proves the restored DLQ + log are usable: a redrive of the restored dir re-injects exactly
        // the captured poison records onto the restored log, as it would have on the source.
        let src = dir_with_dlq(4, 3);
        let backup = InMemoryFs::new();
        snapshot_data_dir(&src, &backup).unwrap();
        let restored = InMemoryFs::new();
        restore_data_dir(&backup, &restored, false).unwrap();

        let before = main_records(&restored).len() as u64;
        let (outcome, restored) = redrive_dlq(restored, ManualClock::new(), cfg()).unwrap();
        assert_eq!(
            outcome.redriven, 3,
            "the restored DLQ redrives its 3 records"
        );
        assert_eq!(main_records(&restored).len() as u64, before + 3);
    }
}
