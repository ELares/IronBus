# t4g 3-node edge fit — run plan (#636)

The cluster benchmark harnesses (`cluster_consume_bench.py`, `cluster_heartbeat_bench.py`,
`cluster_durability_bench.py` + the Rust `cluster-consume-bench` / `cluster-durability-bench` bins)
are complete and run today on local loopback. The one remaining clustering validation is the
**edge-hardware fit on real AWS Graviton (t4g)** — and the apples-to-apples **wire-to-wire**
clustered-consume number vs NATS. This must run on Linux/t4g, **not** the macOS dev machine:
multi-process `ironbus serve` stalls on macOS loopback because an accepted socket inherits the
listener's `O_NONBLOCK` (the artifact fixed in #726); **Linux accepted sockets do not inherit it**,
so the multi-process path that the in-process tests prove works natively on t4g.

## What #636 answers
1. **Edge fit:** does a 3-node IronBus cluster fit + perform within a t4g.small/medium resource
   budget (CPU, RAM, disk, idle cost)?
2. **Wire-to-wire consume vs NATS:** the #634 leg measured the IronBus *scaling shape* (O(R)) via
   the in-process serve path; on t4g, run a real wire client fleet across the replicas (now that the
   client follower-read routing #735 + the serve-accept #734 are wired) to get the apples-to-apples
   throughput ratio vs a NATS R3 cluster.
3. **Durability/failover under real power-loss + real network** (vs the local fault-injection in #727).

## Prereqs
- AWS account; 1–3 `t4g.small` or `t4g.medium` instances (Amazon Linux 2023 / Ubuntu arm64).
- `ironbus` built for `aarch64-unknown-linux-gnu` (the repo already targets musl static-link in CI —
  use that artifact or `cargo build --release --target aarch64-unknown-linux-gnu`).
- `nats-server` (arm64) for the comparison legs.
- Python 3 (the harness drivers).

## Step 1 — single t4g, 3 loopback nodes (fastest signal)
Run the existing harnesses **unchanged** on one t4g instance (they spin up 3 loopback nodes):
```
# on the t4g instance, repo checked out, ironbus + nats-server on PATH
python3 docs/benchmarks/cluster_heartbeat_bench.py    # idle CPU/net per node, vs NATS
python3 docs/benchmarks/cluster_consume_bench.py      # O(R) consume scaling, vs NATS
python3 docs/benchmarks/cluster_durability_bench.py   # power-cut / self-heal / split-brain, vs NATS
```
Collect the emitted `*-rows.jsonl` + `*-report.md`. This gives the **t4g per-node + scaling +
durability** numbers and validates the edge fit. Compare against the M1-Pro local-loopback numbers
already in this directory (the *shape* should match; absolute numbers reflect t4g).

## Step 2 — 3 separate t4g instances, real network (the wire-to-wire number)
Run one node per instance so the data plane crosses a real NIC:
```
# node 1 (leader), node 2, node 3 — each on its own t4g, repo checked out.
# Non-loopback binds need the explicit plaintext opt-ins on this private benchmark network: the
# client wire (--addr 0.0.0.0) takes --insecure-plaintext-wire (+ an --auth-config identity), and
# the peer wire (--cluster-peer) takes --insecure-plaintext-peers (#629 / #1067).
ironbus serve --addr 0.0.0.0:7000 --data-dir /var/ib --storage disk --insecure-plaintext-peers \
  --cluster-id 1 --cluster-peer 1=<node1-ip>:7100 --cluster-peer 2=<node2-ip>:7100 --cluster-peer 3=<node3-ip>:7100 \
  --cluster-peer-client 1=<node1-ip>:7000 --cluster-peer-client 2=<node2-ip>:7000 --cluster-peer-client 3=<node3-ip>:7000
# (node 2/3 symmetric with their own --cluster-id; cluster data plane = --addr +1, cross-cluster serve = --addr +2)
```
Then point a **wire client fleet** at the cluster: produce to the leader (NOT_LEADER redirect #735
auto-routes if a client hits a follower, using the `--cluster-peer-client` hints from #740), and run
a consumer fleet that fans committed reads across the 3 replicas (follower-read routing #723/#735).
Measure aggregate consume throughput vs a NATS R3 cluster on the same 3 instances. **This produces
the apples-to-apples wire-to-wire ratio that the #634 report flagged as pending.**

## Step 3 — real power-cut / partition (optional, strengthens #727)
On the 3-instance setup: `aws ec2 stop-instances` (or pull the leader) mid-write under C2-fsync R3 and
verify every client-acked record survives on the survivors + the cluster auto-fails-over (#722); use
a security-group rule to partition the leader and verify epoch-fencing (no split-brain). This is the
real-hardware version of the local fault injection in #727.

## Acceptance
- A 3-node cluster runs on t4g within the instance's resource budget (record CPU%, RSS, disk, idle).
- The t4g numbers confirm/refine the local-loopback findings (idle ≈ NATS; consume scales ~O(R);
  power-cut tie; self-heal win; split-brain safe).
- Step 2 yields the **wire-to-wire** clustered-consume-vs-NATS ratio (closes the #634 asterisk).
- Commit the collected `*-rows.jsonl` + `*-report.md` (date- + instance-stamped) under this directory.

## Honest notes
- All existing cluster-bench numbers are **M1-Pro local loopback** — the *shape* + relative ratios are
  defensible; the **absolute edge numbers are this run**.
- Keep the reporting auditor-defensible: p50/p90/p99 over ≥5 runs, machine/instance spec, NATS
  durability tier labeled (C2-fsync R3 vs NATS R3 file), report ties as ties — same standard as the
  existing reports. Never fabricate a number.
