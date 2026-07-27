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
//! - with offload DISABLED the on-disk image is byte-for-byte unchanged (no manifest file);
//! - a restore-on-access CACHE file NEVER breaks the next restart (a partial/non-adjacent restore
//!   must not create a phantom gap) and is NEVER trusted torn (verified against the manifest);
//! - an offload error (a cold-store outage) leaves the segment LOCAL and retries — never a loss.

// A test helper filters `seg-*.log` files by suffix; the file-extension lint is not meaningful here.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::sync::Arc;

use ironbus_core::clock::ManualClock;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::cold::{
    cold_object_name, ColdStorageConfig, ColdStore, ColdStoreError, FsColdStore,
    COLD_MANIFEST_DAMAGED_FILE, COLD_MANIFEST_FILE,
};
use ironbus_storage::fault::FaultFs;
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
    assert_eq!(
        log.cold_offloaded_count(),
        usize::try_from(offloaded).unwrap()
    );

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

/// The exact recovery repro (#1152 review): offload a prefix, restore ONLY the segment covering
/// `restore_at` via a single-record low-offset read (a normal lagging consumer), then RESTART. The
/// restored `seg-<id>.log` for a still-REMOTE id must NOT anchor the chain scan (it is "absent until
/// verified"), so the log opens cleanly with no phantom `SegmentChainBroken` gap, and every record
/// reads back byte-exact (the still-remote segments re-fetched).
fn restore_then_restart_reads_clean(restore_at: u64) {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let baseline;
    {
        let mut log = open_with_cold(&data_fs, &cold_fs);
        append_n(&mut log, 60);
        baseline = read_all(&log);
        let offloaded = log.offload_cold_segments().unwrap();
        assert!(
            offloaded > 1,
            "need several offloaded segments so a partial restore leaves a gap"
        );
        // Restore ONLY the segment covering `restore_at`: a single-record read materializes just it.
        let _ = log.read_from(Offset::new(restore_at), 1).unwrap();
    }
    // RESTART: recovery must EXCLUDE the restored-but-still-REMOTE cache file from the contiguity
    // scan. Before the fix this panicked with `SegmentChainBroken` (a phantom gap).
    let log2 = open_with_cold(&data_fs, &cold_fs);
    assert_eq!(
        read_all(&log2),
        baseline,
        "all records readable after a partial-restore restart (remote re-fetched)"
    );
}

#[test]
fn restart_after_restoring_the_oldest_offloaded_segment_opens_clean() {
    // seg-0 restored, segs 1..k still remote, local tail newest => a definite non-adjacent gap.
    restore_then_restart_reads_clean(0);
}

#[test]
fn restart_after_restoring_a_middle_offloaded_segment_opens_clean() {
    // A middle offloaded offset: restores a middle segment, leaving remote holes on BOTH sides.
    restore_then_restart_reads_clean(20);
}

#[test]
fn restart_after_restoring_the_whole_prefix_opens_clean() {
    // The originally-passing contiguous case (a full replay restores everything): still reopens.
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let baseline;
    {
        let mut log = open_with_cold(&data_fs, &cold_fs);
        append_n(&mut log, 60);
        baseline = read_all(&log);
        assert!(log.offload_cold_segments().unwrap() > 1);
        let _ = read_all(&log); // restore the ENTIRE prefix (contiguous)
    }
    let log2 = open_with_cold(&data_fs, &cold_fs);
    assert_eq!(read_all(&log2), baseline);
}

#[test]
fn a_torn_restored_cache_file_is_purged_at_open_and_refetched_never_served() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let baseline;
    {
        let mut log = open_with_cold(&data_fs, &cold_fs);
        append_n(&mut log, 60);
        baseline = read_all(&log);
        log.offload_cold_segments().unwrap();
        assert!(log.is_segment_remote(0));
        assert!(!data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap());
    }
    // Plant a TORN cache file for the REMOTE seg-0 (garbage that does not match the manifest), as a
    // crash mid-restore under the no-atomic-rename fs seam would leave in a PRIOR run.
    let seg0 = data_fs
        .create_new(&format!("seg-{:016x}.log", 0u64))
        .unwrap();
    seg0.write_all_at(b"garbage that is not a valid segment", 0)
        .unwrap();
    seg0.sync_all().unwrap();
    data_fs.sync_dir().unwrap();

    // RESTART: recovery PURGES the torn cache for the REMOTE id (so it never anchors the chain scan
    // or trips the compaction probe), opens cleanly, and a read RE-FETCHES the authoritative bytes —
    // the torn cache is never served as authoritative.
    let log2 = open_with_cold(&data_fs, &cold_fs);
    assert_eq!(
        read_all(&log2),
        baseline,
        "torn cache purged at open + re-fetched, never served as authoritative"
    );
    // The re-fetched cache is now the correct, manifest-matching bytes.
    assert!(log2.is_segment_remote(0));
}

#[test]
fn offload_error_leaves_the_segment_local_and_retries() {
    // Non-blocker #2 (storage contract): a cold-store PUT outage must never lose data — the segment
    // stays LOCAL (nothing recorded REMOTE, no local file deleted) and offload retries next tick. The
    // engine wraps this best-effort (warn + `ironbus_cold_offload_errors_total` + continue), so a
    // produce is never failed by a tiering hiccup.
    let data_fs = InMemoryFs::new();
    let (cold_fault, cold_ctl) = FaultFs::new(InMemoryFs::new());
    let mut log = Log::open(data_fs, ManualClock::new(), config()).unwrap();
    let store: Arc<dyn ColdStore> = Arc::new(FsColdStore::new(cold_fault));
    log.set_cold_store(store, ColdStorageConfig::enabled(1));
    append_n(&mut log, 60);
    let baseline = read_all(&log);

    cold_ctl.set_fail_write(true); // the cold-store PUT fails
    let err = log.offload_cold_segments().unwrap_err();
    assert!(
        err.is_cold_read_failure(),
        "a put outage surfaces a cold-read error: {err:?}"
    );
    assert_eq!(
        log.cold_offloaded_count(),
        0,
        "nothing offloaded under a put outage"
    );
    assert!(!log.is_segment_remote(0));
    assert_eq!(
        read_all(&log),
        baseline,
        "no loss: every record still local + readable"
    );

    cold_ctl.set_fail_write(false); // backend recovers
    assert!(
        log.offload_cold_segments().unwrap() > 0,
        "the next tick retries and succeeds"
    );
    assert!(log.is_segment_remote(0));
    assert_eq!(
        read_all(&log),
        baseline,
        "readable after a successful retry"
    );
}

/// A `ColdStore` whose `delete` always fails, so a reap's best-effort object delete behaves exactly
/// as a crash at that step (the manifest entry is already durably gone, the object survives): the
/// #1153 crash-state builder. `list` keeps the trait default (`None`), so the crash state stays
/// inert while it is built.
#[derive(Debug)]
struct RefusingDeleteStore {
    inner: FsColdStore<InMemoryFs>,
}

impl ColdStore for RefusingDeleteStore {
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ColdStoreError> {
        self.inner.put(key, bytes)
    }
    fn get(&self, key: &str) -> Result<Vec<u8>, ColdStoreError> {
        self.inner.get(key)
    }
    fn delete(&self, _key: &str) -> Result<(), ColdStoreError> {
        Err(ColdStoreError::Io(std::io::Error::other(
            "injected: the process crashed before the reap's object delete",
        )))
    }
    fn exists(&self, key: &str) -> Result<bool, ColdStoreError> {
        self.inner.exists(key)
    }
}

/// #1153 (the follow-up #1152 deferred): a reap of a REMOTE segment durably removes its manifest
/// entry FIRST, then best-effort deletes the cold object and any restore-cache file. A crash in
/// between leaves a surviving `seg-<id>.log` for the now-reaped id BELOW the still-remote prefix —
/// pre-#1153 an unbootable `SegmentChainBroken` local-chain gap (no loss, but manual cleanup) —
/// plus a leaked cold object. The startup orphan sweep must: boot the broker on exactly this state,
/// serve every retained record intact, sweep the leaked object once a backend attaches, NEVER touch
/// an object the manifest still records REMOTE, and re-run idempotently.
#[test]
fn reap_crash_orphan_cache_is_swept_at_open_and_the_leaked_object_on_attach() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let expected_tail;
    let earliest;
    {
        // Build the EXACT crash state through the public API: offload the cold prefix, restore a
        // cache file for segment 0 by reading it, then reap it with the object delete refused (the
        // store) and the cache-file unlink refused (a single-shot armed fault) — byte-for-byte the
        // mid-reap crash window after the DURABLE manifest-entry removal.
        let (fault_fs, control) = FaultFs::new(data_fs.clone());
        let mut log = Log::open(fault_fs, ManualClock::new(), config()).unwrap();
        log.set_cold_store(
            Arc::new(RefusingDeleteStore {
                inner: FsColdStore::new(cold_fs.clone()),
            }),
            ColdStorageConfig::enabled(1),
        );
        append_n(&mut log, 60);
        let offloaded = log.offload_cold_segments().unwrap();
        assert!(
            offloaded >= 2,
            "a still-remote prefix must remain above the reaped id"
        );
        let _ = log.read_from(Offset::ZERO, 1).unwrap(); // restore-on-access caches seg 0
        assert!(data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap());
        control.fail_remove_on(1); // the cache-file unlink "crashes"
        log.reap_oldest_forced()
            .unwrap()
            .expect("one segment reaped");
        assert!(
            !log.is_segment_remote(0),
            "the manifest entry removal committed"
        );
        earliest = log.earliest_offset();
        expected_tail = log
            .read_from(earliest, 100_000)
            .unwrap()
            .into_iter()
            .map(|r| (r.offset.get(), r.payload.to_vec()))
            .collect::<Vec<_>>();
    }
    // The crash state: the orphan cache below the still-remote prefix + the leaked object.
    assert!(data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap());
    assert!(cold_fs.exists(&cold_object_name(0)).unwrap());

    // RESTART: pre-#1153 this open hard-failed `SegmentChainBroken` on the orphan's gap. The sweep
    // (before the chain-continuity check) clears the provably-reaped orphan and the broker boots.
    let log2 = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
    assert!(
        !data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap(),
        "the orphaned restore-cache file was swept at open"
    );
    assert_eq!(log2.earliest_offset(), earliest);
    let remote_ids: Vec<u64> = (0..64).filter(|&id| log2.is_segment_remote(id)).collect();
    assert!(!remote_ids.is_empty() && !remote_ids.contains(&0));
    drop(log2);

    // IDEMPOTENT: a further reopen of the already-swept directory changes nothing and boots.
    let before = data_fs.list().unwrap();
    let mut log3 = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
    assert_eq!(
        data_fs.list().unwrap(),
        before,
        "the re-run sweep is a no-op"
    );
    assert_eq!(log3.earliest_offset(), earliest);

    // Attaching the backend sweeps the LEAKED object (provably reaped: durably absent from the
    // manifest, below the still-remote prefix) and NEVER a manifest-REMOTE object.
    log3.set_cold_store(
        Arc::new(FsColdStore::new(cold_fs.clone())),
        ColdStorageConfig::enabled(1),
    );
    assert!(
        !cold_fs.exists(&cold_object_name(0)).unwrap(),
        "the leaked object for the reaped id is swept on attach"
    );
    for &id in &remote_ids {
        assert!(
            cold_fs.exists(&cold_object_name(id)).unwrap(),
            "object {id} is still REMOTE and must survive"
        );
    }
    // Every retained record reads back intact.
    let tail: Vec<(u64, Vec<u8>)> = log3
        .read_from(earliest, 100_000)
        .unwrap()
        .into_iter()
        .map(|r| (r.offset.get(), r.payload.to_vec()))
        .collect();
    assert_eq!(
        tail, expected_tail,
        "all remaining data is durable and intact"
    );
}

/// The PR #1188 review CRITICAL, exact repro through the public API: offload a cold prefix,
/// overwrite `cold-manifest.ckpt` with `0xFF` (external dual-slot damage — both slots
/// nonzero-sequence, both CRC-bad), reopen (the broker still BOOTS: the manifest recovers as
/// EMPTY, the #1142 availability discipline), attach the store — and every cold object (the SOLE
/// durable copies of the offloaded records) must SURVIVE. Pre-fix, the attach-time orphan-object
/// sweep took the empty-manifest floor fallback (the oldest LOCAL slot id, above every
/// formerly-remote id) and hard-deleted them all. The damaged recovery is now durably recorded in
/// the `cold-manifest.damaged` sentinel, and both startup sweeps refuse to run until an operator
/// reconciles the cold store and deletes it.
#[test]
fn a_damaged_cold_manifest_never_lets_the_attach_sweep_destroy_the_sole_copies() {
    let data_fs = InMemoryFs::new();
    let cold_fs = InMemoryFs::new();
    let offloaded;
    {
        let mut log = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
        log.set_cold_store(
            Arc::new(FsColdStore::new(cold_fs.clone())),
            ColdStorageConfig::enabled(1),
        );
        append_n(&mut log, 60);
        offloaded = log.offload_cold_segments().unwrap();
        assert!(offloaded >= 2, "need a real offloaded prefix");
    }
    for id in 0..offloaded {
        assert!(cold_fs.exists(&cold_object_name(id)).unwrap());
    }
    // The external damage: 0xFF over BOTH dual-slot checkpoint slots.
    let ckpt = data_fs.open(COLD_MANIFEST_FILE).unwrap();
    let len = usize::try_from(ckpt.len().unwrap()).unwrap();
    ckpt.write_all_at(&vec![0xFF; len], 0).unwrap();
    ckpt.sync_all().unwrap();

    // RESTART: boots (availability over consistency), durably records the damage.
    let mut log = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
    assert!(
        data_fs.exists(COLD_MANIFEST_DAMAGED_FILE).unwrap(),
        "the damaged recovery is durably recorded in the sentinel"
    );

    // ATTACH: the orphan-object sweep must REFUSE — every sole-copy object survives.
    log.set_cold_store(
        Arc::new(FsColdStore::new(cold_fs.clone())),
        ColdStorageConfig::enabled(1),
    );
    for id in 0..offloaded {
        assert!(
            cold_fs.exists(&cold_object_name(id)).unwrap(),
            "sole copy of object {id} must SURVIVE the damaged-manifest attach"
        );
    }
}
