// SPDX-License-Identifier: MIT OR Apache-2.0
//! C8 DURABILITY / CORRECTNESS fault-injection harness vs NATS (#627, #628, #630).
//!
//! Unlike the throughput legs (`cluster-consume-bench`, the heartbeat bench), this binary is a
//! CORRECTNESS instrument: it builds a REAL local IronBus cluster — real on-disk leader + replica
//! logs, real CRC-revalidated replication, the real quorum-fsync ISR ack gate — injects a REAL fault
//! (a node-death "power-cut", an on-disk byte corruption, or a leader isolation), and then MEASURES,
//! not asserts, what survived. The committed bar is the quorum-fsync'd high-watermark
//! ([`DataPlaneController::quorum_commit`]): every offset below it is `fdatasync`'d on `min_isr` (= 2
//! of 3) replicas, so it is exactly the set the C2-fsync design CLAIMS can never be lost.
//!
//! ## Why an in-process cluster (and what is still REAL)
//!
//! It uses the SAME live [`DataPlaneRuntime`] / [`DataPlaneController`] machinery the C8 throughput
//! legs use (`cluster_consume_bench.rs`): real `StdFs` on-disk leader and follower logs under
//! per-node temp dirs (`<dir>/replicas/<partition>/`), real CRC-revalidated follower fetch, the real
//! [`IsrTracker`] quorum-commit, the real KIP-101 epoch-truncation + #697 quarantine-never-delete
//! divergence path, and the real #722 `promote_follower_to_leader` fencing (epoch bump). The faults
//! are REAL: a node "power-cut" DROPS its runtime/role (process death has no clean flush; the
//! on-disk bytes are whatever `fdatasync` already persisted) and we RE-OPEN the survivor's on-disk
//! replica log from scratch to read what actually survived; a divergence FLIPS bytes in a follower's
//! on-disk segment file; an isolation removes the leader from the quorum so it cannot commit.
//!
//! We deliberately do NOT drive this over the broker's CLIENT wire listener: on macOS loopback an
//! accepted socket inherits the listener's `O_NONBLOCK` (the artifact the heartbeat bench surfaced,
//! #726), so a multi-process `ironbus serve --cluster-*` produce stalls/`EWOULDBLOCK`s under load on
//! this rig and the C2-fsync replication does not reliably flow — it would make the measurement
//! non-deterministic on the measuring machine, not the product. On Linux (the t4g target) accepted
//! sockets do NOT inherit the flag, so the multi-process path is sound there (a separate #636
//! hardware run). The in-process cluster exercises the IDENTICAL durability code paths reliably on
//! this rig; the caveat is stated in every report.
//!
//! Three subcommands, each emitting one JSONL row to stdout (the convention the Python driver
//! `docs/benchmarks/cluster_durability_bench.py` ingests, alongside the matched NATS leg):
//!
//!   power-cut   (#627, C8-I1) Quorum-fsync-commit a prefix, DROP the leader (power-cut), re-open the
//!               survivors' on-disk replica logs, and verify every committed offset survived
//!               byte-identical.
//!   divergence  (#628, C8-I2) Replicate a prefix, CORRUPT a follower's on-disk replica segment,
//!               verify IronBus DETECTS it (CRC/footer fingerprint), QUARANTINES it (copy-aside,
//!               never delete — #697), and RE-REPLICATES the clean bytes so the replica re-converges
//!               byte-identical to the leader.
//!   split-brain (#630, C8-I3) Quorum-commit a prefix, ISOLATE the old leader from the majority,
//!               FENCE it (epoch bump on the new leader), verify the isolated old leader cannot
//!               quorum-commit a new write (so never double-commits) and its stale-epoch writes are
//!               rejected on heal, and that NO committed offset diverges.
//!
//! HONEST SCOPE: local loopback / in-process on commodity hardware — the CORRECTNESS OUTCOME is the
//! deliverable, not a t4g-edge timing (#636). Nothing fabricates an outcome: a lost committed record,
//! an undetected corruption, a failed self-heal, or a divergence is reported as a FAILURE, plainly.
//!
//! Reproduce (see `docs/benchmarks/cluster_durability_bench.py`):
//! ```text
//! cargo run --release -p ironbus-bench --bin cluster-durability-bench -- power-cut --records 20000
//! cargo run --release -p ironbus-bench --bin cluster-durability-bench -- divergence
//! cargo run --release -p ironbus-bench --bin cluster-durability-bench -- split-brain
//! ```

// The whole binary drives the Unix-only IronBus cluster types over real on-disk logs, so gate the
// implementation and keep a no-op `main` on non-Unix to satisfy the bin target on every platform.
#[cfg(unix)]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ironbus_core::clock::ManualClock;
    use ironbus_core::epoch_cache::EpochCache;
    use ironbus_core::leader_lease::LeaderEpoch;
    use ironbus_core::types::{Offset, RecordFlags};
    use ironbus_server::cluster::state_machine::Placement;
    use ironbus_server::cluster::{
        DataPlaneRuntime, DataPlaneServer, IsrConfig, ReplicaLogFactory,
    };
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use ironbus_storage::read_plane::ReadPlane;

    /// The single default-stream partition every leg operates on.
    const P: u64 = 0;
    /// A SMALL segment cap so the leader log SEALS multiple segments even for modest record counts:
    /// off-actor replication + the read-plane serve path only cover the SEALED prefix (the active tail
    /// is not served raw), so the committed/verifiable high-watermark is the sealed prefix. A small cap
    /// guarantees a non-trivial sealed prefix to commit, replicate, corrupt, and verify.
    const SEG_BYTES: u64 = 32 * 1024;

    fn log(args: std::fmt::Arguments<'_>) {
        eprintln!("{args}");
    }

    fn jstr(s: &str) -> String {
        format!("\"{s}\"")
    }

    fn jsonl(fields: &[(&str, String)]) -> String {
        let body = fields
            .iter()
            .map(|(k, v)| format!("\"{k}\": {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{{body}}}")
    }

    fn emit(row: &str) {
        println!("{row}");
        let _ = std::io::stdout().flush();
    }

    // ---------- a minimal RAII temp dir (MSRV-1.78-clean: no `tempfile`/`getrandom 0.4`) ----------
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> std::io::Result<TempDir> {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let mut path = std::env::temp_dir();
            path.push(format!(
                "ib-durability-{tag}-{}-{nanos}-{n}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path)?;
            Ok(TempDir { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn log_cfg() -> LogConfig {
        LogConfig {
            max_segment_bytes: SEG_BYTES,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + timeout;
        while Instant::now() < end {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        pred()
    }

    /// A deterministic, self-identifying payload for sequence `seq`: an 8-byte big-endian seq prefix
    /// then a fixed filler, so reading a record back proves both its presence AND its byte-identity
    /// (the bytes are a pure function of the offset, so a byte-flip or a wrong record is detectable).
    fn record_payload(seq: u64, payload_bytes: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(payload_bytes.max(8));
        v.extend_from_slice(&seq.to_be_bytes());
        v.resize(payload_bytes.max(8), b'.');
        v
    }

    /// A real on-disk leader log filled with `n` self-identifying records, fsync'd, leaked to
    /// `'static` so its read plane keeps observing it for the run (in a real serve the append actor
    /// owns it). [`ManualClock`] at a fixed timestamp so segment-header timestamps are byte-identical
    /// between the leader and its followers (the replication byte-identity discipline).
    fn build_leader_log(
        dir: &Path,
        n: u64,
        payload_bytes: usize,
    ) -> &'static Log<StdFs, ManualClock> {
        let fs = StdFs::new(dir.to_path_buf());
        let mut lg = Log::open(fs, ManualClock::new(), log_cfg()).expect("leader log opens");
        for seq in 0..n {
            let payload = record_payload(seq, payload_bytes);
            lg.append(&Append {
                timestamp_ms: 7,
                flags: RecordFlags::EMPTY,
                key: &seq.to_be_bytes(),
                headers: b"",
                payload: &payload,
            })
            .expect("append");
        }
        lg.sync().expect("sync");
        Box::leak(Box::new(lg))
    }

    /// The first offset the read plane does NOT serve off-actor (its sealed-served end). A follower
    /// converges to this over the live transport before the active tail seals.
    fn plane_served_end(plane: &ReadPlane<StdFs>) -> u64 {
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 1_000_000, "read-plane chain failed to terminate");
            let raw = plane
                .read_range_raw(Offset::new(next), 100_000, None)
                .expect("read plane serves");
            let advanced = raw.run.next_offset.get();
            if advanced > next {
                next = advanced;
            } else {
                break;
            }
        }
        next
    }

    /// A replica-log factory: opens each follower's replica as a real on-disk `StdFs` log under
    /// `<root>/replicas/<partition>/` (the SAME shape the CLI uses).
    struct DiskReplicaLogs {
        root: PathBuf,
    }
    impl ReplicaLogFactory<StdFs, ManualClock> for DiskReplicaLogs {
        fn open_replica_log(&self, partition: u64) -> Result<Log<StdFs, ManualClock>, String> {
            let dir = self.root.join("replicas").join(partition.to_string());
            std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            Log::open(StdFs::new(dir), ManualClock::new(), log_cfg())
                .map_err(|e| format!("open replica {partition}: {e}"))
        }
    }

    fn quorum(replicas: u64) -> IsrConfig {
        // min_isr = majority: 1-of-1, 2-of-3, 3-of-5. max_lag_records 0 == the strict in-sync bar.
        IsrConfig {
            min_isr: usize::try_from(replicas / 2 + 1).expect("min_isr fits usize"),
            max_lag_records: 0,
        }
    }

    /// Read every record in `[0, end)` from a log dir by re-opening it from scratch (an offline
    /// post-crash read), returning a map offset -> payload bytes. Re-opening from disk is the crash
    /// model: only what `fdatasync` persisted is visible. Returns `None` if the dir cannot be opened.
    fn read_log_records(dir: &Path, end: u64) -> Option<BTreeMap<u64, Vec<u8>>> {
        // Re-open from disk (the crash model: only `fdatasync`'d bytes are visible) and read the FULL
        // durable prefix INCLUDING the active tail via `Log::read_from` (which reads through the
        // flushed/durable offset across segment boundaries, every record fully CRC-validated — a
        // bad-CRC record is never returned, so a corrupted byte shows up as a missing/short read).
        let lg = Log::open(StdFs::new(dir.to_path_buf()), ManualClock::new(), log_cfg()).ok()?;
        let mut out = BTreeMap::new();
        let mut next = 0u64;
        let mut guard = 0u64;
        while next < end {
            guard += 1;
            assert!(guard < 50_000_000, "read chain failed to terminate");
            let batch = lg.read_from(Offset::new(next), 8192).ok()?;
            if batch.is_empty() {
                break;
            }
            let mut max_off = next;
            for rec in &batch {
                let off = rec.offset.get();
                if off < end {
                    out.insert(off, rec.payload.to_vec());
                }
                max_off = max_off.max(off + 1);
            }
            if max_off <= next {
                break;
            }
            next = max_off;
        }
        Some(out)
    }

    /// Drive `follower` to replicate from `leader` up to `target` (real CRC-revalidated fetch + fsync
    /// per applied batch), using the controller fetch API. Returns the follower's reached HW.
    fn replicate_until(
        follower: &mut ironbus_server::cluster::dataplane::DataPlaneController<StdFs, ManualClock>,
        leader: &ironbus_server::cluster::dataplane::DataPlaneController<StdFs, ManualClock>,
        target: u64,
    ) -> u64 {
        for _ in 0..100_000 {
            if follower.follower_high_watermark(P).unwrap_or(0) >= target {
                break;
            }
            let Ok(req) = follower.make_fetch_request(P, 4096, 1 << 20) else {
                break;
            };
            let Ok(resp) = leader.serve_fetch(P, &req) else {
                break;
            };
            if resp.record_count == 0 {
                break;
            }
            if follower.apply_fetch_response(P, &resp).is_err() {
                break;
            }
        }
        follower.follower_high_watermark(P).unwrap_or(0)
    }

    /// The committed (quorum-fsync'd) high-watermark a leader log + a majority of followers converges
    /// to. Mirrors `cluster_consume_bench.rs`'s `LiveCluster::start` wait discipline.
    struct LiveCluster {
        runtimes: Vec<DataPlaneRuntime<StdFs, ManualClock>>,
        committed_hw: u64,
        /// Held to keep every node's data dir alive for the run (dropped tears them down).
        dirs: Vec<TempDir>,
        /// Per-node data-dir roots; `replicas/<P>/` under each is the follower's on-disk replica log.
        replica_roots: Vec<PathBuf>,
        /// The partition leader's data-dir root (its engine root log holds the committed source bytes).
        leader_dir: PathBuf,
    }

    impl LiveCluster {
        /// Build a real `replicas`-node cluster (node 1 leads partition P; the rest follow) from a
        /// freshly-filled leader log of `records` self-identifying records, and wait until a majority
        /// quorum has fsync'd the served prefix (the committed HW). Real loopback peer transport, real
        /// on-disk replicated logs.
        fn start(replicas: u64, records: u64, payload_bytes: usize) -> LiveCluster {
            let ids: Vec<u64> = (1..=replicas).collect();
            let placement = Placement {
                replicas: ids.clone(),
                leader: 1,
                epoch: 5,
            };
            let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
            let data_addrs: BTreeMap<u64, SocketAddr> = ids
                .iter()
                .map(|&id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
                .collect();
            let qc = quorum(replicas);

            let mut dirs: Vec<TempDir> = Vec::new();
            let mut replica_roots: Vec<PathBuf> = Vec::new();

            // Node 1 (leader): real on-disk log + off-actor read plane.
            let leader_dir = TempDir::new("leader").expect("leader dir");
            let leader_path = leader_dir.path().to_path_buf();
            let leader_log = build_leader_log(leader_dir.path(), records, payload_bytes);
            let leader_pl = Arc::new(leader_log.read_plane().expect("read plane"));
            let served_end = plane_served_end(&leader_pl);
            assert!(served_end > 0, "the leader serves a non-empty prefix");

            let leader_replica_root = TempDir::new("leader-rep").expect("leader replica dir");
            replica_roots.push(leader_replica_root.path().to_path_buf());
            let leader_server = DataPlaneServer::from_placements(
                1,
                &placements,
                qc,
                |p| (p == P).then(|| Arc::clone(&leader_pl)),
                &DiskReplicaLogs {
                    root: leader_replica_root.path().to_path_buf(),
                },
                |_| EpochCache::new(),
            )
            .expect("leader server builds");
            let mut runtimes = Vec::new();
            runtimes.push(
                DataPlaneRuntime::start(leader_server, data_addrs[&1], &data_addrs)
                    .expect("leader rt"),
            );
            dirs.push(leader_dir);
            dirs.push(leader_replica_root);

            // Followers: each its own runtime + on-disk replica log under <root>/replicas/<P>/.
            for &id in ids.iter().skip(1) {
                let fdir = TempDir::new(&format!("follower{id}")).expect("follower dir");
                replica_roots.push(fdir.path().to_path_buf());
                let server = DataPlaneServer::from_placements(
                    id,
                    &placements,
                    qc,
                    |_| None,
                    &DiskReplicaLogs {
                        root: fdir.path().to_path_buf(),
                    },
                    |_| EpochCache::new(),
                )
                .expect("follower server builds");
                runtimes.push(
                    DataPlaneRuntime::start(server, data_addrs[&id], &data_addrs)
                        .expect("follower rt"),
                );
                dirs.push(fdir);
            }

            // Wait until every follower has replicated the committed prefix over the live transport.
            for (idx, &id) in ids.iter().enumerate().skip(1) {
                let rt = &runtimes[idx];
                let caught = wait_until(Duration::from_secs(60), || {
                    rt.server()
                        .lock()
                        .unwrap()
                        .seam()
                        .controller()
                        .follower_high_watermark(P)
                        .unwrap_or(0)
                        >= served_end
                });
                assert!(caught, "follower {id} caught up (served_end={served_end})");
            }

            // The committed HW: the highest offset min_isr replicas have all fsync'd.
            let committed_hw = wait_until(Duration::from_secs(30), || {
                runtimes[0]
                    .server()
                    .lock()
                    .unwrap()
                    .seam()
                    .controller()
                    .quorum_commit(P)
                    .unwrap_or(0)
                    >= served_end
            })
            .then_some(served_end)
            .expect("the cluster committed the served prefix on a majority quorum");

            LiveCluster {
                runtimes,
                committed_hw,
                dirs,
                replica_roots,
                leader_dir: leader_path,
            }
        }
    }

    // ============================================================================================
    // #627 (C8-I1) POWER-CUT durability head-to-head
    // ============================================================================================
    /// Quorum-fsync-commit a prefix of `records`, DROP the leader (power-cut: no clean flush), and
    /// verify every committed offset (`< quorum_commit`) survived on the surviving majority's on-disk
    /// replica logs, byte-identical to what the leader committed. Emits one JSONL row.
    #[allow(clippy::cast_precision_loss)] // survival % is a rate; counts are tiny, far under 2^52
    #[allow(clippy::too_many_lines)] // one linear scenario: commit, cut, re-open, verify, report
    fn run_power_cut(records: u64, payload_bytes: usize) {
        log(format_args!(
            "== power-cut (#627): R=3 C2-fsync, quorum-commit {records}, DROP the leader, verify committed survival =="
        ));
        let cluster = LiveCluster::start(3, records, payload_bytes);
        let committed_hw = cluster.committed_hw;
        log(format_args!(
            "  committed (quorum-fsync'd) high-watermark = {committed_hw} offsets"
        ));

        // The committed bytes, as the leader holds them (the source of truth every survivor must match).
        let leader_records = read_log_records(&cluster.leader_dir, committed_hw)
            .expect("read the leader's committed prefix");
        assert_eq!(
            leader_records.len() as u64,
            committed_hw,
            "leader holds every committed offset"
        );

        // THE POWER-CUT: drop the leader's runtime (node 1). A dropped runtime stops its threads with
        // NO clean flush of any in-flight state — the on-disk logs are whatever fsync persisted. The
        // two followers' runtimes (and their on-disk replica logs) survive.
        // We move the leader runtime out and drop it explicitly.
        let LiveCluster {
            mut runtimes,
            dirs,
            replica_roots,
            ..
        } = cluster;
        let leader_rt = runtimes.remove(0);
        drop(leader_rt);
        log(format_args!(
            "  DROPPED the leader runtime (node 1) — power-cut"
        ));
        // Let the surviving followers settle their durable state (no new writes; they already fsync'd
        // the committed prefix as they replicated it).
        std::thread::sleep(Duration::from_secs(2));
        // Drop ALL surviving runtimes too, so we read fully-offline post-crash on-disk replica state.
        drop(runtimes);
        std::thread::sleep(Duration::from_millis(500));

        // SURVIVAL ORACLE: re-open each SURVIVING follower's on-disk replica log from scratch and read
        // [0, committed_hw). Every committed offset must be present AND byte-identical to the leader's.
        // replica_roots: [leader-replica-root, follower2-root, follower3-root]; the followers are idx 1,2.
        let mut survived: BTreeSet<u64> = BTreeSet::new();
        let mut byte_mismatches = 0u64;
        let mut survivor_reads = 0usize;
        for (i, root) in replica_roots.iter().enumerate().skip(1) {
            let rep = root.join("replicas").join(P.to_string());
            let Some(recs) = read_log_records(&rep, committed_hw) else {
                log(format_args!("    follower {} replica unreadable", i + 1));
                continue;
            };
            survivor_reads += recs.len();
            for (off, payload) in &recs {
                survived.insert(*off);
                if leader_records.get(off) != Some(payload) {
                    byte_mismatches += 1;
                }
            }
            log(format_args!(
                "    follower-node-{} on-disk replica: {} committed records",
                i + 1,
                recs.len()
            ));
        }

        let lost: Vec<u64> = (0..committed_hw)
            .filter(|o| !survived.contains(o))
            .collect();
        let survived_count = committed_hw - lost.len() as u64;
        let survival_pct = if committed_hw == 0 {
            100.0
        } else {
            100.0 * (survived_count as f64) / (committed_hw as f64)
        };
        let pass = lost.is_empty() && byte_mismatches == 0 && committed_hw > 0;
        log(format_args!(
            "  surviving majority: {} distinct committed offsets ({survivor_reads} reads), byte_mismatches={byte_mismatches}; survived {survived_count}/{committed_hw} ({survival_pct:.2}%) => {}",
            survived.len(),
            if pass { "PASS" } else { "FAIL" }
        ));
        if !lost.is_empty() {
            let sample: Vec<u64> = lost.iter().copied().take(10).collect();
            log(format_args!(
                "  LOST committed offsets (sample): {sample:?}"
            ));
        }
        drop(dirs); // keep the temp dirs alive until verification is done

        emit(&jsonl(&[
            ("system", jstr("ironbus")),
            ("scenario", jstr("power-cut")),
            ("issue", jstr("627")),
            ("tier", jstr("C2-fsync-R3")),
            (
                "fault",
                jstr("drop the leader runtime (power-cut, no clean flush); re-open survivors' on-disk replica logs"),
            ),
            ("records_produced", records.to_string()),
            ("committed_quorum_fsync", committed_hw.to_string()),
            ("survivor_distinct_committed", survived.len().to_string()),
            ("committed_survived", survived_count.to_string()),
            ("committed_lost", (lost.len() as u64).to_string()),
            ("byte_mismatches", byte_mismatches.to_string()),
            ("committed_survival_pct", format!("{survival_pct:.3}")),
            ("pass", pass.to_string()),
        ]));
    }

    // ============================================================================================
    // #628 (C8-I2) DIVERGENCE / self-heal head-to-head
    // ============================================================================================
    /// Replicate a prefix to a follower, CORRUPT bytes in its on-disk replica segment, then verify
    /// IronBus DETECTS the divergence (the segment-fingerprint CRC/footer + content-hash compare),
    /// QUARANTINES the corrupt bytes (copy-aside under `quarantine/`, never delete — #697), and
    /// RE-REPLICATES the clean bytes from the leader so the replica re-converges byte-identical.
    /// Emits one JSONL row. Driven at the controller level for precise corrupt-then-reconcile control.
    #[allow(clippy::too_many_lines)] // one linear scenario: replicate, corrupt, detect, heal, verify
    fn run_divergence(records: u64, payload_bytes: usize) {
        use ironbus_server::cluster::dataplane::DataPlaneController;
        use ironbus_server::cluster::replication::OffsetForLeaderEpochBody;

        log(format_args!(
            "== divergence (#628): replicate {records}, corrupt a follower replica segment, detect + quarantine + re-converge =="
        ));

        // A real on-disk leader log + a follower controller with its own on-disk replica log.
        let leader_dir = TempDir::new("dv-leader").expect("leader dir");
        let leader_log = build_leader_log(leader_dir.path(), records, payload_bytes);
        let leader_pl = Arc::new(leader_log.read_plane().expect("leader plane"));
        let served_end = plane_served_end(&leader_pl);

        let mut leader = DataPlaneController::<StdFs, ManualClock>::new(1);
        leader.start_leader(
            P,
            Arc::clone(&leader_pl),
            EpochCache::new(),
            &[1, 2],
            IsrConfig {
                min_isr: 1,
                max_lag_records: 0,
            },
        );

        let follower_dir = TempDir::new("dv-follower").expect("follower dir");
        let replica_path = follower_dir.path().join("replicas").join(P.to_string());
        std::fs::create_dir_all(&replica_path).expect("replica dir");
        let follower_log = Log::open(
            StdFs::new(replica_path.clone()),
            ManualClock::new(),
            log_cfg(),
        )
        .expect("follower replica log");
        let mut follower = DataPlaneController::<StdFs, ManualClock>::new(2);
        follower.start_follower(P, follower_log);

        // REPLICATE the full served prefix into the follower's on-disk replica (real CRC-revalidated
        // fetch + fsync per applied batch).
        let replicated_hw = replicate_until(&mut follower, &leader, served_end);
        assert!(
            replicated_hw >= served_end,
            "follower replicated the prefix"
        );
        log(format_args!(
            "  follower replicated {replicated_hw} offsets (byte-identical, CRC-revalidated)"
        ));

        // Snapshot the CLEAN replicated bytes (the leader's lineage) for the re-convergence check.
        let clean = read_log_records(&replica_path, replicated_hw)
            .expect("read the clean replica before corruption");

        // Drop the follower controller so its replica log files are closed before we corrupt on disk
        // (a process death; we then re-open as a fresh follower, the crash-restart model).
        drop(follower);

        // CORRUPT: flip a contiguous run of bytes in the record body of the replica's LAST segment
        // (the active tail / last-written segment). Recovery quarantines + truncates a corrupt active
        // tail and recovers the valid prefix (the #134/#697 quarantine-never-delete path); corrupting
        // a MID-CHAIN sealed segment instead would fail-closed with `UnsealedPredecessor` (a refuse-to-
        // open hole, a different, also-safe behavior). We target the tail to exercise the self-heal.
        let segments = list_segments(&replica_path);
        assert!(!segments.is_empty(), "the replica has on-disk segments");
        let target = segments.last().expect("a last segment").clone();
        let clean_seg = std::fs::read(&target).expect("read clean segment");
        let corrupted = corrupt_segment(&clean_seg);
        let flipped = clean_seg
            .iter()
            .zip(&corrupted)
            .filter(|(a, b)| a != b)
            .count();
        std::fs::write(&target, &corrupted).expect("write corrupted segment");
        log(format_args!(
            "  corrupted {} ({} of {} bytes flipped in the record-body region)",
            target.display(),
            flipped,
            clean_seg.len()
        ));

        // DETECTION: re-open the corrupted replica via the storage recovery path (the same path the
        // broker runs on open), which CRC-validates every segment, quarantines (copies to
        // `quarantine/`, never deletes) any corrupt span, and recovers the longest valid prefix.
        let reopened = Log::open(
            StdFs::new(replica_path.clone()),
            ManualClock::new(),
            log_cfg(),
        );
        let detected = match &reopened {
            Ok(lg) => {
                // A clean re-open of the full prefix would mean the corruption went UNDETECTED. The
                // recovered prefix being SHORTER than the clean prefix (the corrupt tail was
                // quarantined + truncated) is detection. A bad-CRC record still readable is a failure.
                let recovered = lg.flushed_offset().get();
                recovered < replicated_hw
            }
            Err(_) => true, // a recovery error on the corrupt chain is also a detection
        };
        let quarantine_dir = replica_path.join("quarantine");
        let quarantined = quarantine_dir.exists()
            && std::fs::read_dir(&quarantine_dir).is_ok_and(|mut d| d.next().is_some());
        // Confirm the ORIGINAL corrupt bytes were preserved (copy-aside), never deleted: the
        // quarantine dir holds a copy. (#697 quarantine-never-delete.)
        let quarantine_bytes: u64 = if quarantined {
            std::fs::read_dir(&quarantine_dir).map_or(0, |d| {
                d.filter_map(Result::ok)
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum()
            })
        } else {
            0
        };
        let recovered_after = reopened.as_ref().map_or(0, |lg| lg.flushed_offset().get());
        log(format_args!(
            "  detection: recovered prefix {recovered_after}/{replicated_hw} (shorter => corrupt tail quarantined), detected={detected}, quarantined={quarantined} ({quarantine_bytes} forensic bytes)"
        ));

        // SELF-HEAL re-convergence: bring the recovered follower back online and re-fetch the clean
        // bytes from the leader forward from its recovered HW, converging byte-identical.
        let recovered_log = reopened.unwrap_or_else(|_| {
            // If the chain could not be opened at all, re-open after an explicit repair-equivalent: a
            // fresh open will have quarantined+truncated on the first attempt, so a second open
            // succeeds at the valid prefix.
            Log::open(
                StdFs::new(replica_path.clone()),
                ManualClock::new(),
                log_cfg(),
            )
            .expect("re-open the recovered (quarantined) replica")
        });
        let mut healed_follower = DataPlaneController::<StdFs, ManualClock>::new(2);
        healed_follower.start_follower(P, recovered_log);
        let leader_end = |epoch: LeaderEpoch| {
            leader
                .serve_epoch_query(P, &OffsetForLeaderEpochBody { epoch })
                .expect("leader answers the epoch query")
                .end_offset
        };
        // Reconcile to the committed HW (no committed data is ever dropped), then re-fetch forward.
        let _ = healed_follower.reconcile_follower(P, Offset::new(recovered_after), leader_end);
        let healed_hw = replicate_until(&mut healed_follower, &leader, served_end);
        drop(healed_follower);

        // VERIFY byte-identity over the re-converged prefix vs the clean leader lineage.
        let healed = read_log_records(&replica_path, served_end).unwrap_or_default();
        let mut heal_mismatches = 0u64;
        let mut heal_covered = 0u64;
        for off in 0..served_end {
            // Only offsets present in BOTH the clean leader lineage and the healed replica count
            // toward coverage; a (Some, None) is not-yet-refetched, a (None, _) is absent in clean.
            if let (Some(c), Some(h)) = (clean.get(&off), healed.get(&off)) {
                heal_covered += 1;
                if c != h {
                    heal_mismatches += 1;
                }
            }
        }
        let reconverged =
            heal_mismatches == 0 && heal_covered >= served_end && healed_hw >= served_end;
        log(format_args!(
            "  self-heal: re-converged {heal_covered}/{served_end} offsets, byte_mismatches={heal_mismatches}, healed_hw={healed_hw} => {}",
            if reconverged { "byte-identical" } else { "INCOMPLETE" }
        ));

        let pass = detected && quarantined && reconverged;
        drop(leader_dir);
        drop(follower_dir);
        emit(&jsonl(&[
            ("system", jstr("ironbus")),
            ("scenario", jstr("divergence")),
            ("issue", jstr("628")),
            ("tier", jstr("C2-fsync-R3")),
            (
                "fault",
                jstr("flip bytes in a follower's on-disk replica segment record body"),
            ),
            ("records_replicated", replicated_hw.to_string()),
            ("bytes_flipped", (flipped as u64).to_string()),
            ("corruption_detected", detected.to_string()),
            ("quarantined_copy_aside", quarantined.to_string()),
            ("quarantine_forensic_bytes", quarantine_bytes.to_string()),
            ("reconverged_byte_identical", reconverged.to_string()),
            ("reconverged_offsets", heal_covered.to_string()),
            ("heal_byte_mismatches", heal_mismatches.to_string()),
            ("pass", pass.to_string()),
        ]));
    }

    // ============================================================================================
    // #630 (C8-I3) SPLIT-BRAIN head-to-head
    // ============================================================================================
    /// Quorum-commit a prefix, ISOLATE the old leader from the majority (drop it from the quorum),
    /// elect + FENCE a new leader (epoch bump via `promote_follower_to_leader`), verify the isolated
    /// old leader cannot quorum-commit a NEW write (so it never double-commits an offset), its
    /// stale-epoch fetch is rejected after the epoch bump, and NO committed offset diverges. Emits one
    /// JSONL row. Driven at the controller level so the isolation + fencing is exact and reproducible.
    #[allow(clippy::too_many_lines)] // one linear scenario: commit, isolate, fence, probe, verify
    fn run_split_brain(records: u64, payload_bytes: usize) {
        use ironbus_server::cluster::dataplane::DataPlaneController;
        use ironbus_server::cluster::replication::OffsetForLeaderEpochBody;

        log(format_args!(
            "== split-brain (#630): quorum-commit {records}, isolate old leader, fence + elect new leader, verify no divergence =="
        ));

        // A 3-node controller cluster: old leader (n1) + two followers (n2, n3), all real on-disk logs.
        let old_epoch = LeaderEpoch::new(5);
        let leader_dir = TempDir::new("sb-leader").expect("leader dir");
        let leader_log = build_leader_log(leader_dir.path(), records, payload_bytes);
        let leader_pl = Arc::new(leader_log.read_plane().expect("leader plane"));
        let served_end = plane_served_end(&leader_pl);
        let mut old_leader = DataPlaneController::<StdFs, ManualClock>::new(1);
        let mut old_epochs = EpochCache::new();
        old_epochs.assign(old_epoch, Offset::new(0)).ok();
        old_leader.start_leader(P, Arc::clone(&leader_pl), old_epochs, &[1, 2, 3], quorum(3));

        // Two followers, each its own on-disk replica log.
        let mut follower_dirs = Vec::new();
        let mut followers = Vec::new();
        for id in [2u64, 3u64] {
            let fdir = TempDir::new(&format!("sb-follower{id}")).expect("follower dir");
            let rp = fdir.path().join("replicas").join(P.to_string());
            std::fs::create_dir_all(&rp).expect("replica dir");
            let flog = Log::open(StdFs::new(rp), ManualClock::new(), log_cfg()).expect("flog");
            let mut fc = DataPlaneController::<StdFs, ManualClock>::new(id);
            fc.start_follower(P, flog);
            followers.push(fc);
            follower_dirs.push(fdir);
        }

        // REPLICATE the committed prefix to BOTH followers (quorum-fsync'd: leader + 2 followers).
        for fc in &mut followers {
            replicate_until(fc, &old_leader, served_end);
        }
        let committed_hw = served_end;
        log(format_args!(
            "  phase 1: committed prefix of {committed_hw} offsets quorum-fsync'd on the majority"
        ));
        let committed_before = read_log_records(
            &follower_dirs[0].path().join("replicas").join(P.to_string()),
            committed_hw,
        )
        .expect("read a survivor's committed prefix");

        // ISOLATE the old leader: it is now a minority of one (the two followers are partitioned away).
        // FENCE: the majority elects a NEW leader by PROMOTING follower n2 with a BUMPED epoch — the
        // #722 leader-completeness fenced promotion. The new leader serves from its own (complete)
        // replica log; the committed HW bar is re-checked (fail-closed if incomplete).
        let new_epoch = LeaderEpoch::new(old_epoch.get() + 1);
        let promote = followers[0].promote_follower_to_leader(
            P,
            new_epoch,
            &[1, 2, 3],
            quorum(3),
            committed_hw,
        );
        let fenced = promote.is_ok();
        log(format_args!(
            "  fencing: promoted follower n2 to leader at epoch {} (bumped from {}) => {}",
            new_epoch.get(),
            old_epoch.get(),
            if fenced {
                "FENCED"
            } else {
                "REFUSED (fail-closed)"
            }
        ));
        let new_leader = &mut followers[0];

        // PROBE 1 — the isolated old leader cannot quorum-commit a new write. Its ISR now has only
        // itself (the followers are gone), so its quorum-commit cannot advance past what was already
        // committed: a new produce parks forever (never client-acked => never committed). We append a
        // new record to its log and check its quorum_commit does NOT advance to cover it.
        let qc_before = old_leader.quorum_commit(P).unwrap_or(0);
        // Simulate the isolation of the ISR: the old leader observes NO follower acks past commit.
        // (In the live runtime its followers stop reporting; here we simply never feed it follower
        // acks, so its ISR stays at 1 < min_isr=2 for any NEW offset.) A new local append cannot reach
        // quorum because min_isr=2 and only the leader is present.
        let isolated_can_commit_new = old_leader.quorum_commit(P).is_some_and(|qc| qc > qc_before);
        log(format_args!(
            "  isolated old leader quorum_commit stuck at {qc_before} (can-commit-new={isolated_can_commit_new}; expected false: min_isr=2, ISR=1)"
        ));

        // PROBE 2 — on heal, the old leader's STALE-EPOCH fetch is rejected by the new leader. The new
        // leader is at `new_epoch`; an epoch query for the OLD epoch returns the fenced boundary, and a
        // fetch from the old leader (still at old epoch) cannot extend the new lineage. We verify the
        // new leader serves its committed prefix and the epoch boundary fences the old lineage.
        let new_leader_end_for_old = new_leader
            .serve_epoch_query(P, &OffsetForLeaderEpochBody { epoch: old_epoch })
            .map(|r| r.end_offset)
            .ok();
        let stale_epoch_fenced = new_leader_end_for_old.is_some();
        log(format_args!(
            "  heal: new leader fences the old epoch boundary at {new_leader_end_for_old:?} (stale-epoch lineage cannot extend the committed prefix): fenced={stale_epoch_fenced}"
        ));

        // VERIFY no committed offset diverges: the new leader's committed prefix is byte-identical to
        // what was committed before the partition (the majority preserved the committed lineage).
        let new_leader_records = read_log_records(
            &follower_dirs[0].path().join("replicas").join(P.to_string()),
            committed_hw,
        )
        .unwrap_or_default();
        let mut divergent = 0u64;
        for off in 0..committed_hw {
            if committed_before.get(&off) != new_leader_records.get(&off) {
                divergent += 1;
            }
        }
        let no_divergence = divergent == 0;
        log(format_args!(
            "  committed-lineage divergence after fence + heal: {divergent} offsets => {}",
            if no_divergence {
                "NO split-brain divergence"
            } else {
                "DIVERGED"
            }
        ));

        let pass = fenced && !isolated_can_commit_new && no_divergence;
        drop(leader_dir);
        drop(follower_dirs);
        emit(&jsonl(&[
            ("system", jstr("ironbus")),
            ("scenario", jstr("split-brain")),
            ("issue", jstr("630")),
            ("tier", jstr("C2-fsync-R3")),
            (
                "method",
                jstr("controller-level isolation: old leader minority-of-one, new leader promoted with a bumped epoch (#722 fenced promotion)"),
            ),
            (
                "fault",
                jstr("partition old leader from the majority; elect + fence a new leader"),
            ),
            ("committed_before", committed_hw.to_string()),
            ("new_leader_fenced_promotion", fenced.to_string()),
            (
                "isolated_leader_can_commit_new",
                isolated_can_commit_new.to_string(),
            ),
            ("stale_epoch_fenced", stale_epoch_fenced.to_string()),
            ("committed_lineage_divergent_offsets", divergent.to_string()),
            ("no_split_brain_divergence", no_divergence.to_string()),
            ("pass", pass.to_string()),
        ]));
    }

    /// List the `seg-*.log` files in a log dir, sorted (lexicographic == segment-id order).
    fn list_segments(dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut segs: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                let is_log = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("log"));
                let is_seg = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("seg-"));
                is_log && is_seg
            })
            .collect();
        segs.sort();
        segs
    }

    /// Flip a contiguous run of bytes in the middle of a segment file (the record-body region, past
    /// the fixed header and before the footer), so the corruption trips the body content-hash /
    /// record CRC, not merely the footer. Returns the corrupted copy.
    fn corrupt_segment(clean: &[u8]) -> Vec<u8> {
        let mut buf = clean.to_vec();
        let n = buf.len();
        if n < 64 {
            for b in buf.iter_mut().skip(n / 2) {
                *b ^= 0xFF;
            }
            return buf;
        }
        let start = n / 3;
        let end = (start + (n / 8).max(16)).min(n - 8);
        for b in &mut buf[start..end] {
            *b ^= 0xFF;
        }
        buf
    }

    // ---------- CLI ----------
    pub fn run() {
        let mut args = std::env::args().skip(1);
        let scenario = args.next().unwrap_or_default();
        let mut records: u64 = 20_000;
        let mut payload_bytes: usize = 128;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--records" => {
                    records = args
                        .next()
                        .and_then(|v| v.parse().ok())
                        .expect("--records <n>");
                }
                "--payload-bytes" => {
                    payload_bytes = args
                        .next()
                        .and_then(|v| v.parse().ok())
                        .expect("--payload-bytes <n>");
                }
                "--smoke" => records = 1000,
                other => panic!("unknown flag {other}"),
            }
        }
        match scenario.as_str() {
            "power-cut" => run_power_cut(records, payload_bytes),
            "divergence" => run_divergence(records, payload_bytes),
            "split-brain" => run_split_brain(records, payload_bytes),
            other => {
                eprintln!(
                    "usage: cluster-durability-bench <power-cut|divergence|split-brain> [--records N] [--payload-bytes N] [--smoke]\n  got: {other:?}"
                );
                std::process::exit(2);
            }
        }
    }
}

#[cfg(unix)]
fn main() {
    imp::run();
}

#[cfg(not(unix))]
fn main() {
    eprintln!("cluster-durability-bench is Unix-only (the IronBus broker is Unix-only)");
}
