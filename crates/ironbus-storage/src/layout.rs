// SPDX-License-Identifier: MIT OR Apache-2.0
//! The data-directory LAYOUT version marker (#562, V2-M2 foundation).
//!
//! This versions the on-disk DIRECTORY STRUCTURE of a data directory: where the streams,
//! cursors, and dead-letter subtree live. It is DISTINCT from the per-segment/record
//! `FORMAT_VERSION` (`ironbus_core::format`), which versions the record and segment
//! ENCODING. A single data directory therefore carries two orthogonal version axes: the
//! encoding of each frame, and the shape of the directory that holds the frames.
//!
//! ## Why
//!
//! V2-M2 introduces N streams, which changes the on-disk shape: named streams will live in
//! a `streams/<name>/` subtree (generalizing the existing `dlq/` subdir pattern), with the
//! default stream `""` remaining today's root log. Introducing a new directory shape is a
//! breaking change to the layout contract, so it must be a VERSIONED, recoverable migration
//! rather than a silent reinterpretation. This marker reserves that future: it declares the
//! layout version up front so a newer layout is detected and refused by an older binary
//! (fail-closed), exactly as an unknown `FORMAT_VERSION` is refused, instead of being
//! misread.
//!
//! ## Layout version 1 (today)
//!
//! - The root log IS the default stream `""`: `seg-<hex>.log` segments, `cursor.ckpt` /
//!   `cursor-<hex>.ckpt`, `counters.ckpt`, and the `quarantine/` forensic subdir at the
//!   data-dir root.
//! - The `dlq/` subdirectory holds the dead-letter sink (a second segmented [`crate::log::Log`]).
//! - The `streams/` subtree is RESERVED for M2-I2 (per-stream logs) and is NOT created here.
//!
//! An existing single-log deployment IS, byte for byte, a layout-v1 directory: the marker
//! only records that fact, it changes no segment, cursor, or DLQ byte.
//!
//! ## Durability and recovery (a pure function of durable bytes)
//!
//! The marker is stored in `layout.meta`, a [`crate::checkpoint::SlotCheckpoint`]: a
//! two-slot, CRC32C-protected, alternating-write, fsync'd file. Recovery is the same pure
//! function of durable bytes the rest of the store obeys:
//!
//! - **Absent** (a pre-marker data dir, before this build): treated as layout v1 and the
//!   marker is WRITTEN. A safe, idempotent upgrade: an existing single-log deployment is
//!   already byte-for-byte layout v1, so recording v1 reinterprets nothing.
//! - **Present and v1**: opened unchanged.
//! - **Present and a FUTURE/unknown version** (a marker that fully decodes — magic and CRC
//!   valid — but declares a version this build does not understand): FAIL CLOSED with
//!   [`StorageError::IncompatibleLayoutVersion`]. A newer layout is never silently
//!   reinterpreted by an older binary.
//! - **Torn or corrupt** (a slot whose CRC fails, or a payload whose magic is wrong): the
//!   checkpoint's dual-slot discipline reverts to the other durable slot; if neither slot is
//!   valid the marker recovers as ABSENT and is re-upgraded to v1. A bad marker therefore
//!   NEVER bricks an otherwise-valid data dir — it costs at most a re-write of the v1 marker,
//!   and it never fabricates a future version (only a fully-valid, CRC-checked future marker
//!   triggers the fail-closed reject). This mirrors how a torn cursor checkpoint regresses to
//!   its prior durable value rather than inventing one.

use crate::checkpoint::Checkpoint;
use crate::fs::Filesystem;
use crate::segment::StorageError;

/// The on-disk data-directory LAYOUT version this build writes and understands. Version 1 is
/// today's layout: the root log is the default stream `""`, with the `dlq/` subdir and the
/// `streams/` subtree (the latter reserved, created by M2-I2, not here).
///
/// Bumped only by a future layout change (e.g. moving named streams under `streams/<name>/`),
/// at which point a v1 reader refuses the new value rather than guessing — the same exact-match,
/// fail-closed discipline as `FORMAT_VERSION`.
pub const LAYOUT_VERSION: u32 = 1;

/// The reserved data-dir subtree for per-stream logs (M2-I2). NOT created by this module; named
/// here so the name is reserved by the layout contract and a single source of truth exists once
/// M2-I2 materializes it.
pub const STREAMS_SUBDIR: &str = "streams";

/// The reserved data-dir subtree for PARTITIONED streams (M2-I11b, #693): each partitioned stream is
/// a [`crate::partitioned::PartitionedStream`] rooted at `pstreams/<hex(name)>/`, whose `P` sub-logs
/// live under `pstreams/<hex(name)>/p-<08x(i)>/`. It is a SEPARATE subtree from [`STREAMS_SUBDIR`] so
/// the single-log [`crate::streamset::StreamSet`] (which scans only `streams/`) never mistakes a
/// partitioned stream's root for a plain named-stream log. NOT created until a stream declares `P > 1`,
/// so a deployment that never partitions never materializes `pstreams/` (its disk image is unchanged).
pub const PARTITIONED_STREAMS_SUBDIR: &str = "pstreams";

/// The reserved data-dir subtree for the SHARED WAL (M2-I13, #597 — the shared-WAL fallback for high
/// stream counts): ONE [`crate::shared_wal::SharedWal`] commit log holding every shared-mode named
/// stream's records interleaved and tagged, rooted at `shared-wal/`. It is a SEPARATE subtree from
/// [`STREAMS_SUBDIR`] and [`PARTITIONED_STREAMS_SUBDIR`] so a shared-WAL commit log is never mistaken
/// for a plain named-stream log (per-stream scanners read only `streams/`, and the shared-WAL scanner
/// reads only here). ADDITIVE: created only when shared-WAL storage mode is selected, so a default
/// per-stream-log deployment never materializes `shared-wal/` and its on-disk image is unchanged. A
/// v1 reader that predates this subtree simply ignores it (it is not `streams/` and not the root log).
pub const SHARED_WAL_SUBDIR: &str = "shared-wal";

/// The on-disk file name of the layout marker. It deliberately does NOT match the `seg-<hex>.log`
/// or `cursor*.ckpt` naming, so segment enumeration ([`crate::naming::segment_ids`]) and cursor
/// discovery skip it as a foreign file.
const LAYOUT_MARKER_FILE: &str = "layout.meta";

/// The magic prefix of the marker payload (IronBus Data-Dir), distinguishing a real layout marker
/// from an unrelated `layout.meta` a foreign tool might leave: a CRC-valid slot whose magic does
/// not match is treated as absent, never as a versioned marker.
const LAYOUT_MAGIC: [u8; 4] = *b"IBDD";

/// The decoded marker payload: magic (4) + layout version (4, little-endian `u32`). The CRC, slot
/// framing, and dual-slot torn-write tolerance are provided by the [`Checkpoint`] this rides in, so
/// this struct only encodes the meaningful fields.
const MARKER_PAYLOAD_LEN: usize = 8;

/// Encodes the marker payload for `version` (magic, then the version little-endian).
fn encode_marker(version: u32) -> [u8; MARKER_PAYLOAD_LEN] {
    let mut buf = [0u8; MARKER_PAYLOAD_LEN];
    buf[0..4].copy_from_slice(&LAYOUT_MAGIC);
    buf[4..8].copy_from_slice(&version.to_le_bytes());
    buf
}

/// Decodes a marker payload to its layout version, returning `None` if the payload is not a
/// well-formed layout marker (wrong length or wrong magic). A `None` here is treated by the caller
/// exactly like an absent marker, so a foreign or future-FIELD-LAYOUT payload never masquerades as
/// a known version.
fn decode_marker(payload: &[u8]) -> Option<u32> {
    if payload.len() != MARKER_PAYLOAD_LEN {
        return None;
    }
    if payload[0..4] != LAYOUT_MAGIC {
        return None;
    }
    Some(u32::from_le_bytes(payload[4..8].try_into().ok()?))
}

/// Checks (and, on a pre-marker dir, best-effort upgrades) the data-directory layout marker,
/// returning the layout version now in effect.
///
/// The ONLY hard failure is a successfully-read, fully-valid marker that declares a version GREATER
/// than [`LAYOUT_VERSION`]: that is the fail-closed reject ([`StorageError::IncompatibleLayoutVersion`]),
/// because an older binary must never reinterpret a newer layout. Every other case resolves to a
/// version with NO error: a present v1 marker returns 1; an ABSENT, torn, corrupt, or foreign marker
/// is treated as layout v1 (an existing single-log dir is byte-for-byte layout v1) and the v1 marker
/// is written BEST-EFFORT.
///
/// "Best-effort" is deliberate and matches the `counters.ckpt` discipline: the marker is a layout
/// CONTRACT, not correctness state, so a filesystem that cannot persist it (read-only, out of space,
/// an injected write fault) must NOT block opening an otherwise-valid data dir. The write is simply
/// retried on the next open. Persisting the marker therefore never fails `Log::open`; only READING a
/// valid future marker does.
///
/// This must be called by [`crate::log::Log::open`] BEFORE any recovery so a future layout is
/// refused before its (unknown-shaped) contents are interpreted. It touches only `layout.meta`, so
/// it never reads or writes a segment, cursor, or DLQ byte: an existing data dir's segments open
/// exactly as before.
///
/// It deliberately does NOT issue its own `sync_dir`: the marker's CONTENT is made durable by
/// `Checkpoint::write`'s `sync_all`, and its directory entry's durability piggybacks on the next
/// `sync_dir` the open path already performs (the fresh log's `start_segment`, or a later
/// produce/seal). A separate `sync_dir` would add a gratuitous fsync to every open and a spurious
/// failure boundary that a best-effort marker must not introduce.
///
/// # Errors
/// Returns [`StorageError::IncompatibleLayoutVersion`] (and ONLY that) when a valid marker declares
/// a future version. An IO error reading or writing the marker is swallowed (best-effort), resolving
/// to layout v1.
pub fn open_or_upgrade<F: Filesystem>(fs: &F) -> Result<u32, StorageError> {
    // 1) READ first. Only a fully-valid marker (slot CRC OK, magic OK) declaring a FUTURE version is
    //    the fail-closed reject; this is the one outcome that propagates an error. A read IO error
    //    (e.g. an injected fault) is treated as "no readable marker": best-effort, fall through to v1.
    if let Some(version) = read_marker_version(fs) {
        if version > LAYOUT_VERSION {
            return Err(StorageError::IncompatibleLayoutVersion {
                found: version,
                supported: LAYOUT_VERSION,
            });
        }
        // A known version (today only v1; a below-current version is reserved for a future explicit
        // migration step, unreachable now) is accepted as-is, no rewrite.
        return Ok(version);
    }

    // 2) Absent / torn / corrupt / foreign / unreadable: this IS layout v1. Write the v1 marker
    //    BEST-EFFORT (a single-log dir is already byte-for-byte v1, so this records a fact and
    //    reinterprets nothing); a write failure is swallowed and retried on the next open.
    let _ = write_v1_marker(fs);
    Ok(LAYOUT_VERSION)
}

/// The read-only outcome of inspecting the data-directory layout marker (#601, the `ironbus verify`
/// fsck). Unlike [`open_or_upgrade`] this NEVER writes the marker on an absent/torn directory, so it
/// is safe for the read-only verify path; it still fail-closes the same way on a future version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutMarker {
    /// A fully-valid, CRC-checked marker present on disk, declaring this version (today only `1`).
    Present(u32),
    /// No valid marker on disk (absent, torn, corrupt, or foreign). Treated as layout v1 by
    /// recovery, which would WRITE the v1 marker best-effort; verify only REPORTS this without
    /// writing, so the directory is left byte-for-byte unchanged.
    AbsentTreatedAsV1,
}

/// Inspects the data-directory layout marker READ-ONLY, the verify-path twin of [`open_or_upgrade`]
/// that NEVER writes (#601). It applies the SAME fail-closed reject as recovery — a fully-valid
/// marker declaring a version greater than [`LAYOUT_VERSION`] returns
/// [`StorageError::IncompatibleLayoutVersion`] — but on an absent/torn/corrupt marker it returns
/// [`LayoutMarker::AbsentTreatedAsV1`] instead of writing the v1 marker, so an `ironbus verify` run
/// changes no bytes. `verify` reports a present-but-future marker as a structural block, exactly as
/// the broker would refuse to open it.
///
/// # Errors
/// Returns [`StorageError::IncompatibleLayoutVersion`] (and ONLY that) when a valid marker declares a
/// future version. A read IO error is swallowed (best-effort), resolving to
/// [`LayoutMarker::AbsentTreatedAsV1`], exactly as `open_or_upgrade` treats an unreadable marker.
pub fn check_layout_marker<F: Filesystem>(fs: &F) -> Result<LayoutMarker, StorageError> {
    match read_marker_version(fs) {
        Some(version) if version > LAYOUT_VERSION => Err(StorageError::IncompatibleLayoutVersion {
            found: version,
            supported: LAYOUT_VERSION,
        }),
        Some(version) => Ok(LayoutMarker::Present(version)),
        None => Ok(LayoutMarker::AbsentTreatedAsV1),
    }
}

/// Reads the layout version from `layout.meta`, returning `None` if it is absent, unreadable, torn,
/// corrupt, or foreign (any case that should be treated as "no valid marker", i.e. layout v1). A
/// `Some(version)` is a fully-valid, CRC-checked marker payload (the caller decides whether that
/// version is acceptable). This is read-only and never an error: a bad marker is a `None`, never a
/// propagated failure, so it can never by itself brick a valid data dir.
fn read_marker_version<F: Filesystem>(fs: &F) -> Option<u32> {
    if !fs.exists(LAYOUT_MARKER_FILE).ok()? {
        return None;
    }
    let file = fs.open(LAYOUT_MARKER_FILE).ok()?;
    let (_checkpoint, recovered) = Checkpoint::open(file).ok()?;
    decode_marker(recovered.as_deref()?)
}

/// Best-effort durable write of the v1 marker, creating `layout.meta` if absent. Returns an IO error
/// to the caller, which swallows it: a filesystem that cannot persist the marker still opens the log.
fn write_v1_marker<F: Filesystem>(fs: &F) -> Result<(), StorageError> {
    let file = if fs.exists(LAYOUT_MARKER_FILE).map_err(StorageError::Io)? {
        fs.open(LAYOUT_MARKER_FILE).map_err(StorageError::Io)?
    } else {
        fs.create_new(LAYOUT_MARKER_FILE)
            .map_err(StorageError::Io)?
    };
    let (mut checkpoint, _recovered) = Checkpoint::open(file)?;
    checkpoint.write(&encode_marker(LAYOUT_VERSION))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::FaultFs;
    use crate::fs::InMemoryFs;
    use crate::io::RandomAccessFile;
    use crate::naming::{parse_segment_file_name, segment_file_name, segment_ids};

    /// A fresh data dir gains a durable v1 marker on first open.
    #[test]
    fn fresh_dir_writes_v1_marker() {
        let fs = InMemoryFs::new();
        assert!(!fs.exists(LAYOUT_MARKER_FILE).unwrap());
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
        assert!(fs.exists(LAYOUT_MARKER_FILE).unwrap());
        // The marker is durable across a reopen and stays v1 (idempotent, no second write needed).
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
    }

    /// An existing pre-marker data dir (segments present, no marker) auto-upgrades to v1 and leaves
    /// every segment file untouched.
    #[test]
    fn pre_marker_dir_auto_upgrades_to_v1_leaving_segments_untouched() {
        let fs = InMemoryFs::new();
        // Simulate a pre-marker single-log deployment: a couple of segment files, no marker.
        for id in [0u64, 1] {
            let f = fs.create_new(&segment_file_name(id)).unwrap();
            f.write_all_at(b"segment-bytes", 0).unwrap();
            f.sync_all().unwrap();
        }
        fs.sync_dir().unwrap();
        let before = fs.open(&segment_file_name(0)).unwrap();
        let mut before_bytes = vec![0u8; b"segment-bytes".len()];
        before.read_exact_at(&mut before_bytes, 0).unwrap();

        assert!(!fs.exists(LAYOUT_MARKER_FILE).unwrap());
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
        assert!(fs.exists(LAYOUT_MARKER_FILE).unwrap());

        // Segments are byte-for-byte unchanged.
        let after = fs.open(&segment_file_name(0)).unwrap();
        let mut after_bytes = vec![0u8; b"segment-bytes".len()];
        after.read_exact_at(&mut after_bytes, 0).unwrap();
        assert_eq!(before_bytes, after_bytes);
        // Still exactly the two segments (the marker is not a segment and is not enumerated).
        assert_eq!(segment_ids(&fs).unwrap(), vec![0, 1]);
    }

    /// A valid marker declaring a FUTURE version is rejected (fail-closed), never reinterpreted.
    #[test]
    fn future_version_is_rejected() {
        let fs = InMemoryFs::new();
        // Write a well-formed marker for a version this build does not understand.
        let file = fs.create_new(LAYOUT_MARKER_FILE).unwrap();
        file.sync_all().unwrap();
        fs.sync_dir().unwrap();
        let (mut cp, _) = Checkpoint::open(file).unwrap();
        cp.write(&encode_marker(LAYOUT_VERSION + 1)).unwrap();

        let err = open_or_upgrade(&fs).unwrap_err();
        match err {
            StorageError::IncompatibleLayoutVersion { found, supported } => {
                assert_eq!(found, LAYOUT_VERSION + 1);
                assert_eq!(supported, LAYOUT_VERSION);
            }
            other => panic!("expected IncompatibleLayoutVersion, got {other:?}"),
        }
        // A far-future version is rejected the same way.
        let file = fs.open(LAYOUT_MARKER_FILE).unwrap();
        let (mut cp, _) = Checkpoint::open(file).unwrap();
        cp.write(&encode_marker(9999)).unwrap();
        assert!(matches!(
            open_or_upgrade(&fs).unwrap_err(),
            StorageError::IncompatibleLayoutVersion { found: 9999, .. }
        ));
    }

    /// A corrupted marker (its single durable slot's CRC fails) does NOT brick the dir: it recovers
    /// as absent and is re-upgraded to v1, bounded to a single marker rewrite.
    #[test]
    fn corrupt_marker_recovers_bounded_to_v1_without_bricking() {
        let fs = InMemoryFs::new();
        // Establish a v1 marker, then corrupt EVERY byte-region of the file so neither slot's CRC
        // can validate. The dir's (here, empty) segments must still open fine afterwards.
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
        let file = fs.open(LAYOUT_MARKER_FILE).unwrap();
        let len = usize::try_from(file.len().unwrap()).unwrap();
        let mut bytes = vec![0u8; len];
        file.read_exact_at(&mut bytes, 0).unwrap();
        for b in &mut bytes {
            *b ^= 0xff;
        }
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_all().unwrap();

        // Re-upgrade is idempotent and succeeds (no error, no brick): the marker is rewritten v1.
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
        // And it is durable + valid again on the next open.
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
    }

    /// The read-only `check_layout_marker` (the `ironbus verify` path) reports an ABSENT marker as
    /// `AbsentTreatedAsV1` WITHOUT writing it, unlike `open_or_upgrade` which upgrades on disk.
    #[test]
    fn check_layout_marker_is_read_only_on_an_absent_marker() {
        let fs = InMemoryFs::new();
        assert!(!fs.exists(LAYOUT_MARKER_FILE).unwrap());
        assert_eq!(
            check_layout_marker(&fs).unwrap(),
            LayoutMarker::AbsentTreatedAsV1
        );
        // CRUCIAL: it did NOT write the marker (verify never mutates), unlike open_or_upgrade.
        assert!(
            !fs.exists(LAYOUT_MARKER_FILE).unwrap(),
            "check_layout_marker must not write the marker"
        );
    }

    /// `check_layout_marker` reports a PRESENT, valid marker as `Present(version)`.
    #[test]
    fn check_layout_marker_reports_a_present_version() {
        let fs = InMemoryFs::new();
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1); // write a real v1 marker
        assert_eq!(
            check_layout_marker(&fs).unwrap(),
            LayoutMarker::Present(LAYOUT_VERSION)
        );
    }

    /// `check_layout_marker` fail-closes on a valid FUTURE marker exactly as `open_or_upgrade` does
    /// (so verify surfaces the same structural block the broker would refuse to open), but it still
    /// never writes.
    #[test]
    fn check_layout_marker_fail_closes_on_a_future_version() {
        let fs = InMemoryFs::new();
        let file = fs.create_new(LAYOUT_MARKER_FILE).unwrap();
        file.sync_all().unwrap();
        fs.sync_dir().unwrap();
        let (mut cp, _) = Checkpoint::open(file).unwrap();
        cp.write(&encode_marker(LAYOUT_VERSION + 1)).unwrap();
        assert!(matches!(
            check_layout_marker(&fs).unwrap_err(),
            StorageError::IncompatibleLayoutVersion {
                found,
                supported,
            } if found == LAYOUT_VERSION + 1 && supported == LAYOUT_VERSION
        ));
    }

    /// Persisting the marker is BEST-EFFORT: a filesystem whose every write fails still resolves to
    /// layout v1 with NO error, so a write-erroring (e.g. read-only or full) backing store never
    /// blocks opening an otherwise-valid data dir. Only READING a valid future marker fails closed.
    #[test]
    fn a_marker_write_failure_does_not_fail_the_upgrade() {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        control.set_fail_write(true);
        // Absent marker + every write failing: still v1, no propagated error.
        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
    }

    /// A valid FUTURE marker still fails closed even when writes are failing: the reject is a READ
    /// outcome and does not depend on being able to persist anything.
    #[test]
    fn a_future_marker_is_rejected_even_when_writes_fail() {
        let inner = InMemoryFs::new();
        // Lay down a valid future-version marker on the inner disk.
        {
            let file = inner.create_new(LAYOUT_MARKER_FILE).unwrap();
            file.sync_all().unwrap();
            inner.sync_dir().unwrap();
            let (mut cp, _) = Checkpoint::open(file).unwrap();
            cp.write(&encode_marker(LAYOUT_VERSION + 1)).unwrap();
        }
        let (fs, control) = FaultFs::new(inner);
        control.set_fail_write(true);
        assert!(matches!(
            open_or_upgrade(&fs).unwrap_err(),
            StorageError::IncompatibleLayoutVersion { .. }
        ));
    }

    /// A foreign `layout.meta` whose payload is the wrong shape (valid CRC, wrong magic) is treated
    /// as absent and overwritten with the v1 marker, not mistaken for a versioned marker.
    #[test]
    fn foreign_payload_is_treated_as_absent() {
        let fs = InMemoryFs::new();
        let file = fs.create_new(LAYOUT_MARKER_FILE).unwrap();
        file.sync_all().unwrap();
        fs.sync_dir().unwrap();
        let (mut cp, _) = Checkpoint::open(file).unwrap();
        cp.write(b"not-a-layout-marker").unwrap(); // wrong magic, wrong length

        assert_eq!(open_or_upgrade(&fs).unwrap(), 1);
        // Now a real v1 marker is in place.
        let file = fs.open(LAYOUT_MARKER_FILE).unwrap();
        let (_, recovered) = Checkpoint::open(file).unwrap();
        assert_eq!(decode_marker(recovered.as_deref().unwrap()), Some(1));
    }

    /// The marker round-trips its version and the encode/decode are inverses for v1.
    #[test]
    fn marker_encode_decode_round_trips() {
        assert_eq!(decode_marker(&encode_marker(1)), Some(1));
        assert_eq!(decode_marker(&encode_marker(2)), Some(2));
        assert_eq!(decode_marker(&encode_marker(u32::MAX)), Some(u32::MAX));
        // Wrong length and wrong magic both decode to None (treated as absent).
        assert_eq!(decode_marker(b"short"), None);
        assert_eq!(decode_marker(b"XXXX\x01\x00\x00\x00"), None);
    }

    /// The marker file name is never mistaken for a segment, so it is invisible to enumeration.
    #[test]
    fn marker_file_is_not_a_segment_name() {
        assert_eq!(parse_segment_file_name(LAYOUT_MARKER_FILE), None);
    }
}
