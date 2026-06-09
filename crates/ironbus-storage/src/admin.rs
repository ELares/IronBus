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
use crate::log::{Append, Log, LogConfig};
use crate::naming::cursor_checkpoint_name;
use crate::offline::OfflineReader;
use crate::segment::StorageError;
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
            // The original record's flags are not separately carried by the DLQ entry; the log
            // re-derives HAS_KEY from the key, and a redriven record is a fresh main-log record, so
            // EMPTY flags (plus the derived key flag) is correct. COMPRESSED is not reconstructed
            // here because the DLQ entry holds the DECODED original payload.
            flags: RecordFlags::EMPTY,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlq::DlqSink;
    use crate::fs::InMemoryFs;
    use crate::naming::segment_file_name;
    use crate::segment::{OwnedRecord, SegmentReader};
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
            key: key.to_vec(),
            headers: headers.to_vec(),
            payload: payload.to_vec(),
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
            .map(|r| r.payload.clone())
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
}
