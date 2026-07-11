// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tiered storage (#643, V2-M10, phase 1): offloading cold SEALED segments to an object store behind
//! the read/recovery abstraction. These drive a `Log` directly (the through-actor read path is where
//! restore-on-access lives) and assert the load-bearing DATA-INTEGRITY invariants:
//!
//! - offload removes the local file, records the segment REMOTE in the durable manifest, and uploads
//!   the object;
//! - a read of an offloaded segment transparently fetches + re-verifies + serves it, byte-exact;
//! - a RESTART recovers an offloaded segment as PRESENT (manifest spliced), never a torn gap, and it
//!   is still readable;
//! - the crash windows recover correctly (upload-before-manifest => still fully local; manifest-
//!   before-delete => consistent, served, no double-count);
//! - a retention reap of an offloaded segment DELETES the remote object (no orphan);
//! - a cold-store `get` failure / a corrupt fetched object is a TYPED fail-closed error, never a
//!   silent gap or garbage;
//! - with offload DISABLED the on-disk image is byte-for-byte unchanged (no manifest file).

// A test helper filters `seg-*.log` files by suffix; the file-extension lint is not meaningful here.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::sync::Arc;

use ironbus_core::clock::ManualClock;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::cold::{cold_object_name, ColdStorageConfig, ColdStore, FsColdStore};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::{Append, Log, LogConfig, RetentionBounds};
use ironbus_storage::segment::StorageError;

type TestLog = Log<InMemoryFs, ManualClock>;

/// Small segments so a modest workload rolls across many sealed segments.
fn config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 256,
        ..LogConfig::default()
    }
}

/// Appends `n` records (each an 8-byte payload = its index), fsyncing each, so the workload rolls and
/// seals several segments. Generic over the filesystem so the fault-injection test can drive it too.
fn append_n<F: Filesystem>(log: &mut Log<F, ManualClock>, n: u64) {
    for i in 0..n {
        let payload = i.to_le_bytes();
        log.append(&Append {
            timestamp_ms: 1_700_000_000_000 + i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        })
        .unwrap();
        log.sync().unwrap();
    }
}

/// Reads every record as `(offset, payload)` for a byte-exact before/after comparison.
fn read_all<F: Filesystem>(log: &Log<F, ManualClock>) -> Vec<(u64, Vec<u8>)> {
    log.read_from(Offset::ZERO, 100_000)
        .unwrap()
        .into_iter()
        .map(|r| (r.offset.get(), r.payload.to_vec()))
        .collect()
}

/// The number of local `seg-<id>.log` files present.
fn local_segment_count(fs: &InMemoryFs) -> usize {
    fs.list()
        .unwrap()
        .into_iter()
        .filter(|n| n.starts_with("seg-") && n.ends_with(".log"))
        .count()
}

/// Opens a log over `data_fs` with a cold store over `cold_fs` attached (offload enabled, keeping the
/// single newest sealed segment local).
fn open_with_cold(data_fs: &InMemoryFs, cold_fs: &InMemoryFs) -> TestLog {
    let mut log = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
    let store: Arc<dyn ColdStore> = Arc::new(FsColdStore::new(cold_fs.clone()));
    log.set_cold_store(store, ColdStorageConfig::enabled(1));
    log
}

#[test]
fn offload_removes_local_records_remote_and_uploads_then_reads_transparently() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let mut log = open_with_cold(&data_fs, &cold_fs);
    append_n(&mut log, 60);

    let baseline = read_all(&log);
    let local_before = local_segment_count(&data_fs);
    assert!(
        local_before >= 3,
        "workload should have rolled several segments"
    );

    let offloaded = log.offload_cold_segments().unwrap();
    assert!(offloaded > 0, "at least one cold segment should offload");
    assert_eq!(log.cold_offloaded_count(), usize::try_from(offloaded).unwrap());

    // Segment 0 (the oldest) is offloaded: local file GONE, manifest REMOTE, object PRESENT.
    assert!(log.is_segment_remote(0));
    assert!(
        !data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap(),
        "the offloaded segment's local file must be deleted"
    );
    assert!(
        cold_fs.exists(&cold_object_name(0)).unwrap(),
        "the offloaded segment's object must be in the cold store"
    );
    assert!(
        local_segment_count(&data_fs) < local_before,
        "local files freed"
    );

    // A read spanning the offloaded prefix transparently fetches + serves it, byte-exact.
    let after = read_all(&log);
    assert_eq!(after, baseline, "offloaded records read back byte-exact");
    // The offloaded segment's local file is re-materialized (restore-on-access), but still REMOTE.
    assert!(log.is_segment_remote(0));
}

#[test]
fn offloaded_segment_survives_restart_as_present_and_is_readable() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let baseline;
    let count;
    {
        let mut log = open_with_cold(&data_fs, &cold_fs);
        append_n(&mut log, 60);
        baseline = read_all(&log);
        count = log.durable_record_count();
        let offloaded = log.offload_cold_segments().unwrap();
        assert!(offloaded > 0);
        // Prove the local file is really gone before the restart.
        assert!(!data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap());
    }

    // RESTART: reopen over the same durable disk. Recovery reads the manifest and splices the
    // offloaded prefix back as PRESENT (no SegmentChainBroken on the absent files).
    let mut log2 = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
    assert!(
        log2.is_segment_remote(0),
        "offloaded segment recovers REMOTE"
    );
    assert!(log2.cold_offloaded_count() > 0);
    assert_eq!(
        log2.durable_record_count(),
        count,
        "offloaded records still count toward retention totals after restart"
    );

    // Re-attach the backend (the operator re-configures it) and read: the offloaded segment fetches.
    let store: Arc<dyn ColdStore> = Arc::new(FsColdStore::new(cold_fs.clone()));
    log2.set_cold_store(store, ColdStorageConfig::enabled(1));
    assert_eq!(
        read_all(&log2),
        baseline,
        "readable byte-exact after restart"
    );
}

#[test]
fn read_of_offloaded_segment_without_backend_fails_closed() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    {
        let mut log = open_with_cold(&data_fs, &cold_fs);
        append_n(&mut log, 60);
        log.offload_cold_segments().unwrap();
    }
    // Restart WITHOUT re-attaching the cold store: a read of the offloaded segment must fail closed
    // (typed, never a silent empty read), so the operator learns the backend must be re-configured.
    let log2 = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
    let err = log2.read_from(Offset::ZERO, 100_000).unwrap_err();
    assert!(
        matches!(err, StorageError::ColdStoreUnavailable { .. }),
        "expected ColdStoreUnavailable, got {err:?}"
    );
    assert!(err.is_cold_read_failure());
}

#[test]
fn get_failure_is_a_typed_error_not_a_silent_gap() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let mut log = open_with_cold(&data_fs, &cold_fs);
    append_n(&mut log, 60);
    log.offload_cold_segments().unwrap();
    // Delete the offloaded object out-of-band (simulate object loss / a transport miss). The local
    // file is already gone, so the read must fetch — and fail closed.
    cold_fs.remove(&cold_object_name(0)).unwrap();
    let err = log.read_from(Offset::ZERO, 100_000).unwrap_err();
    assert!(
        matches!(err, StorageError::ColdFetch { segment_id: 0, .. }),
        "expected ColdFetch for segment 0, got {err:?}"
    );
    assert!(err.is_cold_read_failure());
}

#[test]
fn corrupt_fetched_object_fails_closed_not_delivered() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let mut log = open_with_cold(&data_fs, &cold_fs);
    append_n(&mut log, 60);
    log.offload_cold_segments().unwrap();
    // Corrupt the offloaded object's bytes (flip the middle byte): the CRC re-verification on fetch
    // must reject it, and the poisoned bytes must never be materialized as a local segment.
    let obj = cold_fs.open(&cold_object_name(0)).unwrap();
    let len = obj.len().unwrap();
    let mut buf = vec![0u8; usize::try_from(len).unwrap()];
    obj.read_exact_at(&mut buf, 0).unwrap();
    let mid = buf.len() / 2;
    buf[mid] ^= 0xff;
    obj.write_all_at(&buf, 0).unwrap();
    obj.sync_all().unwrap();

    let err = log.read_from(Offset::ZERO, 100_000).unwrap_err();
    assert!(
        matches!(err, StorageError::ColdCorrupt { segment_id: 0 }),
        "expected ColdCorrupt for segment 0, got {err:?}"
    );
    // Fail-closed: the corrupt segment's local file was NOT re-materialized.
    assert!(!data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap());
}

#[test]
fn crash_after_upload_before_manifest_recovers_fully_local() {
    // Simulate a crash between the object upload and the manifest commit by making the manifest's
    // fsync FAIL: `offload_one_segment` returns before deleting the local file, and the in-memory
    // manifest map rolls back — so the segment stays FULLY LOCAL (no loss).
    use ironbus_storage::fault::FaultFs;
    let (data_fs, control) = FaultFs::new(InMemoryFs::new());
    let cold_fs = InMemoryFs::new();
    let mut log = Log::open(data_fs, ManualClock::new(), config()).unwrap();
    let store: Arc<dyn ColdStore> = Arc::new(FsColdStore::new(cold_fs.clone()));
    log.set_cold_store(store, ColdStorageConfig::enabled(1));
    append_n(&mut log, 60);
    let baseline = read_all(&log);

    control.set_fail_sync(true); // the manifest checkpoint write fsync will fail
    let err = log.offload_cold_segments().unwrap_err();
    // The offload did not commit: no segment is recorded REMOTE.
    assert!(
        !log.is_segment_remote(0),
        "manifest must not record a REMOTE it could not fsync"
    );
    // With the fault cleared, the segment is still fully local and reads unchanged.
    control.set_fail_sync(false);
    assert_eq!(
        read_all(&log),
        baseline,
        "no loss: the segment stayed local"
    );
    let _ = err;
}

#[test]
fn crash_after_manifest_before_delete_recovers_consistently() {
    // Offload normally (deletes the local file), then RE-CREATE the local file to model a crash
    // AFTER the manifest commit but BEFORE the durable local delete. Recovery must treat this
    // consistently (no ColdManifestCorrupt, no double-count) and still read byte-exact.
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let baseline;
    let count;
    let crashed_id;
    {
        let mut log = open_with_cold(&data_fs, &cold_fs);
        append_n(&mut log, 60);
        baseline = read_all(&log);
        count = log.durable_record_count();
        let offloaded = log.offload_cold_segments().unwrap();
        // The real "after manifest, before delete" window happens on the segment CURRENTLY being
        // offloaded (offload is oldest-first): every older segment is already fully remote (deleted),
        // and THIS one has its manifest entry committed but its local unlink not yet durable. That is
        // the HIGHEST offloaded id — the one adjacent to the still-local chain.
        crashed_id = offloaded - 1;
        assert!(!data_fs
            .exists(&format!("seg-{crashed_id:016x}.log"))
            .unwrap());
    }
    // Model the surviving local file: copy its object bytes back to the local segment path.
    let obj_bytes = {
        let f = cold_fs.open(&cold_object_name(crashed_id)).unwrap();
        let len = f.len().unwrap();
        let mut b = vec![0u8; usize::try_from(len).unwrap()];
        f.read_exact_at(&mut b, 0).unwrap();
        b
    };
    let seg = data_fs
        .create_new(&format!("seg-{crashed_id:016x}.log"))
        .unwrap();
    seg.write_all_at(&obj_bytes, 0).unwrap();
    seg.sync_all().unwrap();
    data_fs.sync_dir().unwrap();

    // Reopen: the crashed segment is BOTH manifest-REMOTE and locally present. Recovery keeps it in
    // the local chain (not double-spliced), still flagged REMOTE, and reads byte-exact.
    let log2 = open_with_cold(&data_fs, &cold_fs);
    assert_eq!(
        log2.durable_record_count(),
        count,
        "the both-local-and-remote segment is counted exactly once"
    );
    assert!(log2.is_segment_remote(crashed_id));
    assert!(
        log2.is_segment_remote(0),
        "older segments are still fully remote"
    );
    assert_eq!(read_all(&log2), baseline, "readable byte-exact");
}

#[test]
fn retention_reap_of_an_offloaded_segment_deletes_the_remote_object() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let mut log = open_with_cold(&data_fs, &cold_fs);
    append_n(&mut log, 60);
    log.offload_cold_segments().unwrap();
    assert!(log.is_segment_remote(0));
    assert!(cold_fs.exists(&cold_object_name(0)).unwrap());
    let offloaded_before = log.cold_offloaded_count();

    // A tight byte cap reaps the oldest segments, offloaded ones included. `protect_below_offset` is
    // the log head, so no consumer blocks the reap.
    let bounds = RetentionBounds {
        max_bytes: 128,
        max_age_ms: 0,
        max_messages: 0,
    };
    let protect = log.next_offset().get();
    log.reap(bounds, protect).unwrap();

    // The offloaded segment 0 was reaped: its manifest entry AND its remote object are gone (no
    // orphan leak), and it is no longer recorded REMOTE.
    assert!(!log.is_segment_remote(0));
    assert!(
        !cold_fs.exists(&cold_object_name(0)).unwrap(),
        "reaping an offloaded segment must delete the remote object (no orphan)"
    );
    assert!(
        log.cold_offloaded_count() < offloaded_before,
        "the reaped segment's manifest entry is removed"
    );
}

#[test]
fn disabled_offload_is_byte_identical_and_writes_no_manifest() {
    // Two identical workloads: one with a cold store attached but DISABLED, one with no cold tier at
    // all. The on-disk image must be byte-for-byte identical, and no `cold-manifest.ckpt` appears.
    fn image(fs: &InMemoryFs) -> Vec<(String, Vec<u8>)> {
        let mut img: Vec<(String, Vec<u8>)> = fs
            .list()
            .unwrap()
            .into_iter()
            .map(|n| (n.clone(), fs.open(&n).unwrap().snapshot()))
            .collect();
        img.sort();
        img
    }

    let plain_fs = InMemoryFs::new();
    {
        let mut log = Log::open(plain_fs.clone(), ManualClock::new(), config()).unwrap();
        append_n(&mut log, 60);
    }

    let disabled_fs = InMemoryFs::new();
    {
        let cold_fs = InMemoryFs::new();
        let mut log = Log::open(disabled_fs.clone(), ManualClock::new(), config()).unwrap();
        // A backend is attached but the policy is DISABLED (the default): offload is a no-op.
        let store: Arc<dyn ColdStore> = Arc::new(FsColdStore::new(cold_fs.clone()));
        log.set_cold_store(store, ColdStorageConfig::default());
        append_n(&mut log, 60);
        assert_eq!(
            log.offload_cold_segments().unwrap(),
            0,
            "disabled offload is a no-op"
        );
        assert_eq!(log.cold_offloaded_count(), 0);
        // No manifest file was created.
        assert!(!disabled_fs.exists("cold-manifest.ckpt").unwrap());
    }

    assert_eq!(
        image(&plain_fs),
        image(&disabled_fs),
        "a disabled cold tier changes no on-disk byte"
    );
}
