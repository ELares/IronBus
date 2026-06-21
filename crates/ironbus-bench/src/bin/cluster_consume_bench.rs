// SPDX-License-Identifier: MIT OR Apache-2.0
//! Clustered-consume APPORTIONED-READ throughput vs replica count (V2-C8-I5, #634).
//!
//! THE C8 headline. The #723 read-consistency tiers let a follower serve a COMMITTED read
//! (`<=` the safe high-watermark) LOCALLY from its own replicated, page-cache-resident copy of the
//! partition log — CRAQ "clean" reads, the leader serves a 0-RTT linearizable lease read. So a
//! consumer FLEET reading committed data can fan its reads across all `R` replicas instead of
//! hammering one leader, and aggregate consume throughput should scale with `R`.
//!
//! This binary MEASURES that scaling on a REAL local cluster: it builds a real on-disk leader log
//! with a committed prefix, spins up a real [`DataPlaneRuntime`] cluster over loopback TCP
//! (`R` in {1, 3, 5}), waits until every follower has replicated the committed prefix, then runs a
//! consumer fleet of `C` reader threads that DRAIN the committed prefix, apportioned round-robin
//! across the `R` replicas. Each reader serves bytes through the SAME off-actor zero-copy
//! [`ReadPlane`](ironbus_storage::read_plane::ReadPlane) machinery the wire fetch uses:
//! [`DataPlaneController::serve_leader_local_read`] on the leader and
//! [`DataPlaneController::serve_follower_read`] (`ReadTier::FollowerCommitted`) on a follower.
//!
//! It emits one JSONL row per `(replicas, run)` to stdout (and a per-replica-count summary to
//! stderr), the same JSONL-rows convention as `consume_bench.py`. The Python driver
//! `docs/benchmarks/cluster_consume_bench.py` runs this for `R` in {1,3,5}, runs the matched NATS
//! clustered-consume leg, and assembles the report.
//!
//! ## What this measures, exactly (the honest scope)
//!
//! It measures the IronBus FOLLOWER-READ SERVE PATH: the `DataPlaneController` serve methods that
//! return committed zero-copy byte runs off the off-actor read plane — the mechanism that makes
//! apportioned reads scale. The #723 tiers are NOT yet threaded into the per-connection wire
//! session (`session.rs`); the live `ironbus` consumer still fetches from its connected node's
//! local path. So this drives the controller serve API in-process over the REAL live runtime
//! (real loopback peer transport, real on-disk replicated logs, real CRC-revalidated replication),
//! NOT the wire-protocol session. The NATS leg, by contrast, is end-to-end over the wire. The
//! report labels this asymmetry; do not read the absolute ratio as a wire-to-wire number — read the
//! IronBus SCALING SHAPE (throughput vs `R`) and the order-of-magnitude.
//!
//! Reproduce (see `docs/benchmarks/cluster_consume_bench.py`):
//! ```text
//! cargo run --release -p ironbus-bench --bin cluster-consume-bench -- \
//!     --replicas 3 --consumers 6 --records 50000 --payload-bytes 256 --warmup-ms 1000 \
//!     --measure-ms 3000 --runs 5
//! ```

// The whole binary is the cluster harness; the cluster types are Unix-only (the broker is
// Unix-only), so gate the entire module and keep a no-op `main` on non-Unix to satisfy the bin
// target on every platform.
#[cfg(unix)]
mod imp {
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::{Offset, RecordFlags};
    use ironbus_server::cluster::read_consistency::ReadTier;
    use ironbus_server::cluster::state_machine::Placement;
    use ironbus_server::cluster::{
        DataPlaneRuntime, DataPlaneServer, FollowerReadOutcome, IsrConfig, ReplicaLogFactory,
    };
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use ironbus_storage::read_plane::ReadPlane;

    const P: u64 = 0;

    /// CLI-parsed knobs.
    struct Args {
        replicas: u64,
        consumers: u64,
        records: u32,
        payload_bytes: usize,
        warmup_ms: u64,
        measure_ms: u64,
        runs: u32,
        seg_bytes: u64,
    }

    fn parse_args() -> Args {
        let mut a = Args {
            replicas: 3,
            consumers: 6,
            records: 50_000,
            payload_bytes: 256,
            warmup_ms: 1000,
            measure_ms: 3000,
            runs: 5,
            seg_bytes: 1024 * 1024,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut val = || it.next().expect("flag needs a value");
            match flag.as_str() {
                "--replicas" => a.replicas = val().parse().expect("u64"),
                "--consumers" => a.consumers = val().parse().expect("u64"),
                "--records" => a.records = val().parse().expect("u32"),
                "--payload-bytes" => a.payload_bytes = val().parse().expect("usize"),
                "--warmup-ms" => a.warmup_ms = val().parse().expect("u64"),
                "--measure-ms" => a.measure_ms = val().parse().expect("u64"),
                "--runs" => a.runs = val().parse().expect("u32"),
                "--seg-bytes" => a.seg_bytes = val().parse().expect("u64"),
                other => panic!("unknown flag {other}"),
            }
        }
        assert!(
            a.replicas == 1 || a.replicas == 3 || a.replicas == 5,
            "--replicas must be 1, 3, or 5 (a supported quorum size)"
        );
        assert!(a.consumers >= 1, "--consumers must be >= 1");
        a
    }

    fn log_cfg(seg_bytes: u64) -> LogConfig {
        LogConfig {
            max_segment_bytes: seg_bytes,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    /// A real on-disk leader log filled with `n` records of `payload_bytes` each, fsync'd, leaked to
    /// `'static` so its read plane keeps observing it for the run's lifetime (in a real serve the
    /// engine's append actor owns it). [`ManualClock`] at zero so the segment-header timestamps are
    /// byte-identical between the leader and its followers (the replication byte-identity discipline).
    fn build_leader_log(
        dir: &std::path::Path,
        n: u32,
        payload_bytes: usize,
        seg_bytes: u64,
    ) -> &'static Log<StdFs, ManualClock> {
        let fs = StdFs::new(dir.to_path_buf());
        let mut log =
            Log::open(fs, ManualClock::new(), log_cfg(seg_bytes)).expect("leader log opens");
        let payload = vec![b'x'; payload_bytes];
        for _ in 0..n {
            log.append(&Append {
                timestamp_ms: 7,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &payload,
            })
            .expect("append");
        }
        log.sync().expect("sync");
        Box::leak(Box::new(log))
    }

    /// The first offset the read plane does NOT serve off-actor (its sealed-served end) — the bar a
    /// follower converges to over the live transport before the active tail seals.
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

    /// A replica-log factory: opens each follower's replica as a real on-disk `StdFs` log under a
    /// per-node temp dir (the same `<data_dir>/replicas/<partition>` shape the CLI uses).
    struct DiskReplicaLogs {
        root: std::path::PathBuf,
        seg_bytes: u64,
    }
    impl ReplicaLogFactory<StdFs, ManualClock> for DiskReplicaLogs {
        fn open_replica_log(&self, partition: u64) -> Result<Log<StdFs, ManualClock>, String> {
            let dir = self.root.join("replicas").join(partition.to_string());
            std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            Log::open(StdFs::new(dir), ManualClock::new(), log_cfg(self.seg_bytes))
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

    /// A minimal RAII temp directory — a local stand-in for the `tempfile` crate so the bench's
    /// dependency tree stays MSRV-1.78-clean (`tempfile`'s transitive `getrandom 0.4` requires the
    /// `edition2024` Cargo feature, unstable on 1.78). Creates a process-unique dir under the system
    /// temp dir and removes it on drop, same lifecycle as `tempfile::TempDir`.
    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> std::io::Result<TempDir> {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let mut path = std::env::temp_dir();
            path.push(format!(
                "ironbus-cluster-bench-{}-{nanos}-{n}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path)?;
            Ok(TempDir { path })
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// One live cluster of `replicas` nodes (node 1 leads partition `P`; the rest follow), built from
    /// a freshly-filled leader log. Holds the runtimes so they stay up for the run, plus the
    /// committed bar the readers must not cross.
    struct LiveCluster {
        runtimes: Vec<DataPlaneRuntime<StdFs, ManualClock>>,
        committed_hw: u64,
        _dirs: Vec<TempDir>,
    }

    impl LiveCluster {
        fn start(replicas: u64, records: u32, payload_bytes: usize, seg_bytes: u64) -> LiveCluster {
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

            // Node 1 (leader): real on-disk log + off-actor read plane.
            let leader_dir = TempDir::new().expect("leader dir");
            let leader_log = build_leader_log(leader_dir.path(), records, payload_bytes, seg_bytes);
            let leader_pl = Arc::new(leader_log.read_plane().expect("read plane"));
            let served_end = plane_served_end(&leader_pl);
            assert!(
                served_end > 0,
                "the leader serves a non-empty committed prefix"
            );

            let leader_replica_root = TempDir::new().expect("leader replica dir");
            let leader_server = DataPlaneServer::from_placements(
                1,
                &placements,
                qc,
                |p| (p == P).then(|| Arc::clone(&leader_pl)),
                &DiskReplicaLogs {
                    root: leader_replica_root.path().to_path_buf(),
                    seg_bytes,
                },
                |_| ironbus_core::epoch_cache::EpochCache::new(),
            )
            .expect("leader server builds");
            let mut runtimes = Vec::new();
            runtimes.push(
                DataPlaneRuntime::start(leader_server, data_addrs[&1], &data_addrs)
                    .expect("leader rt"),
            );
            dirs.push(leader_dir);
            dirs.push(leader_replica_root);

            // The followers (nodes 2..=replicas): each its own runtime + on-disk replica log, dialing
            // the leader's data-plane address and applying CRC-revalidated bytes.
            for &id in ids.iter().skip(1) {
                let fdir = TempDir::new().expect("follower dir");
                let server = DataPlaneServer::from_placements(
                    id,
                    &placements,
                    qc,
                    |_| None,
                    &DiskReplicaLogs {
                        root: fdir.path().to_path_buf(),
                        seg_bytes,
                    },
                    |_| ironbus_core::epoch_cache::EpochCache::new(),
                )
                .expect("follower server builds");
                runtimes.push(
                    DataPlaneRuntime::start(server, data_addrs[&id], &data_addrs)
                        .expect("follower rt"),
                );
                dirs.push(fdir);
            }

            // Wait until EVERY follower has replicated the committed prefix over the live transport
            // (so a follower read actually has the bytes to serve — never an empty fan-out).
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
                assert!(
                    caught,
                    "follower {id} caught up to the committed prefix (served_end={served_end})"
                );
            }

            // The committed HW: with a majority quorum holding the served prefix, the leader's
            // quorum-commit covers it (the highest offset min_isr replicas have all fsync'd) — the
            // exact safe bar a follower read is fenced by. For R=1 the leader IS the quorum.
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
                _dirs: dirs,
            }
        }

        /// Drain the committed prefix ONCE from replica `node_idx` (0 == leader), summing the records
        /// served. Reads chained raw runs `[0, committed_hw)` through the controller serve path — the
        /// SAME off-actor zero-copy read plane the wire fetch uses. Returns the record count drained.
        fn drain_once(&self, node_idx: usize) -> u64 {
            let srv = self.runtimes[node_idx].server().lock().unwrap();
            let ctrl = srv.seam().controller();
            let mut from = Offset::ZERO;
            let mut served = 0u64;
            let mut guard = 0u64;
            loop {
                guard += 1;
                assert!(guard < 10_000_000, "drain chain failed to terminate");
                let count = if node_idx == 0 {
                    // The leader: a 0-RTT linearizable lease-local read (lease valid in this harness).
                    let run = ctrl
                        .serve_leader_local_read(P, true, from, usize::MAX, None)
                        .expect("leader serves a local read");
                    let next = run.run.next_offset.get();
                    let c = run.run.record_count;
                    if c == 0 || next <= from.get() {
                        served += c;
                        break;
                    }
                    from = Offset::new(next);
                    c
                } else {
                    // A follower: a CRAQ committed-local read, fenced by the committed HW.
                    let outcome = ctrl
                        .serve_follower_read(
                            P,
                            ReadTier::FollowerCommitted,
                            Some(self.committed_hw),
                            from,
                            usize::MAX,
                            None,
                        )
                        .expect("follower serves a committed read locally");
                    let run = match outcome {
                        FollowerReadOutcome::Served(r) => r,
                        FollowerReadOutcome::ConfirmWithLeader { .. } => {
                            panic!("a clean committed read serves locally, not a confirm")
                        }
                    };
                    let next = run.run.next_offset.get();
                    let c = run.run.record_count;
                    if c == 0 || next <= from.get() {
                        served += c;
                        break;
                    }
                    from = Offset::new(next);
                    c
                };
                served += count;
                if from.get() >= self.committed_hw {
                    break;
                }
            }
            served
        }
    }

    /// Run ONE measurement: `consumers` reader threads, each pinned to a replica round-robin, drain
    /// the committed prefix in a tight loop for `warmup_ms + measure_ms`; only records drained during
    /// the measurement window are counted. Returns (records/sec aggregate, total records measured).
    // The throughput divide is f64 by intent (a rate); record counts well under 2^52 lose no precision.
    #[allow(clippy::cast_precision_loss)]
    fn measure(cluster: &Arc<LiveCluster>, consumers: u64, warmup_ms: u64, measure_ms: u64) -> f64 {
        let replicas = cluster.runtimes.len() as u64;
        let stop = Arc::new(AtomicBool::new(false));
        let measure_on = Arc::new(AtomicBool::new(false));
        let total = Arc::new(AtomicU64::new(0));
        // Barrier: all readers + the controller line up before the clock starts.
        let barrier = Arc::new(Barrier::new(
            usize::try_from(consumers).expect("consumers fits usize") + 1,
        ));

        let mut handles = Vec::new();
        for c in 0..consumers {
            // round-robin apportion across replicas
            let node_idx = usize::try_from(c % replicas).expect("node index fits usize");
            let cluster = Arc::clone(cluster);
            let stop = Arc::clone(&stop);
            let measure_on = Arc::clone(&measure_on);
            let total = Arc::clone(&total);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut local = 0u64;
                barrier.wait();
                while !stop.load(Ordering::Relaxed) {
                    let drained = cluster.drain_once(node_idx);
                    if measure_on.load(Ordering::Relaxed) {
                        local += drained;
                    }
                }
                total.fetch_add(local, Ordering::Relaxed);
            }));
        }

        barrier.wait();
        // Warmup (drains happen but are not counted), then flip the measurement window on.
        std::thread::sleep(Duration::from_millis(warmup_ms));
        measure_on.store(true, Ordering::Relaxed);
        let t0 = Instant::now();
        std::thread::sleep(Duration::from_millis(measure_ms));
        measure_on.store(false, Ordering::Relaxed);
        let elapsed = t0.elapsed().as_secs_f64();
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().expect("reader thread");
        }
        let measured = total.load(Ordering::Relaxed);
        measured as f64 / elapsed
    }

    fn log(args: std::fmt::Arguments<'_>) {
        eprintln!("{args}");
    }

    // The run-count -> f64 for mean/stdev: the run count is tiny, no precision is lost.
    #[allow(clippy::cast_precision_loss)]
    pub fn run() {
        let a = parse_args();
        log(format_args!(
            "== cluster consume scaling: R={} consumers={} records={} payload={}B warmup={}ms measure={}ms runs={} ==",
            a.replicas, a.consumers, a.records, a.payload_bytes, a.warmup_ms, a.measure_ms, a.runs
        ));
        let cluster = Arc::new(LiveCluster::start(
            a.replicas,
            a.records,
            a.payload_bytes,
            a.seg_bytes,
        ));
        log(format_args!(
            "  cluster up: {} nodes, committed_hw={} records",
            a.replicas, cluster.committed_hw
        ));

        let mut rates = Vec::new();
        for run in 0..a.runs {
            let rate = measure(&cluster, a.consumers, a.warmup_ms, a.measure_ms);
            rates.push(rate);
            // One JSONL row per run on stdout (the harness convention).
            println!(
                "{{\"system\": \"ironbus\", \"tier\": \"cluster-follower-read\", \"replicas\": {}, \"consumers\": {}, \"payload\": {}, \"records\": {}, \"run\": {}, \"mode\": \"consume\", \"throughput\": {:.3}}}",
                a.replicas, a.consumers, a.payload_bytes, a.records, run, rate
            );
            log(format_args!("  run {run}: {rate:.0} records/s"));
        }
        let n = rates.len() as f64;
        let mean = rates.iter().sum::<f64>() / n;
        let var = rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / n;
        let stdev = var.sqrt();
        log(format_args!(
            "  R={} -> mean {mean:.0} records/s (stdev {stdev:.0}, n={})",
            a.replicas, a.runs
        ));
    }
}

#[cfg(unix)]
fn main() {
    imp::run();
}

#[cfg(not(unix))]
fn main() {
    eprintln!("cluster-consume-bench is Unix-only (the IronBus broker is Unix-only)");
}
