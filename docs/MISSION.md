# IronBus mission: the durable log broker — single node or clustered — that beats NATS on every front

> Status: MISSION + ROADMAP. This document states the GOAL and tracks progress to it. It is scrupulously
> explicit, in three tiers: what is **measured today**, what is **shipped and wired (with scope edges)**,
> and what is **still target**. Read the honesty tables in [§2](#2-honesty-measured-today-shipped-and-wired-and-still-target)
> before reading any superlative as a present-tense claim. "Better on every front" is the destination;
> clustering, multi-stream, and the single-consumer consume win have since shipped (§2b), each marked at
> its true status below.

---

## 1. The mission

**IronBus is the durable log broker — single node OR clustered — that is feature-rich and decisively
better than NATS on every front.** It pairs Kafka-class consume speed (zero-copy delivery,
consumer-managed offsets) with SQS-class per-message semantics (visibility leases, per-message
dead-letter, generation fencing) that Kafka and Redpanda structurally lack — on top of **bounded,
reported, fail-closed corruption recovery that NATS cannot do** — and a **real multi-node cluster with
NATS-cluster feature parity and better**.

**Clustering is first-class, not a post-1.0 afterthought.** IronBus is designed to be a genuine
multi-node cluster (real leader/follower replication, NATS-cluster parity *and* better on durability,
recovery, and scaling cost) that **degrades to a zero-config single node**. The single-node binary is a
strict subset of the cluster: with one node there is no quorum math, no heartbeats, and the durability
contract is exactly today's single-node `fsync`-before-ack. With three nodes you add one small consensus
group plus pull-replication whose background cost tracks **nodes and traffic, never asset count** — the
inverse of the design that limits NATS today.

We have no installed customer base, so we are free to rearchitect. Every feature is justified by Big-O
and first principles; every milestone ships under PR + fresh-eyes review + CI-green + an on-device
benchmark versus NATS JetStream **and** Core (and a multi-node rig for the cluster work).

The single-node tenets are unchanged and remain the tie-breaker order:
**Resilient > Simple > Edge First > HyperScale > Cross Platform** (see [the tenets in the README](../README.md#the-five-tenets)).
The cluster preserves them: the cluster ack default is `fsync`'d-on-a-quorum (it does not weaken the
single-node durability contract, it extends it), and the cluster recovery invariants
([CI1–CI4](#cluster-recovery-invariants-ci1ci4)) extend the single-node bounded-and-reported-loss
discipline ([I1–I6](../docs/INVARIANTS.md#shared-invariants-i1-to-i8)) across replicas.

---

## 2. Honesty: measured today, shipped and wired, and still target

This is the most important section. It splits every capability three ways: a measured win (§2a),
shipped-and-wired with a stated scope edge (§2b), or still target (§2c). A superlative in §1 is the
destination until the capability reaches §2a.

### 2a. Achieved and measured today (single node)

These are real, on-device, measured wins — the foundation the mission builds on.

| Capability | Status | The measured / mechanical fact |
| --- | --- | --- |
| Durable produce throughput | **ACHIEVED, measured on-device** | Durable pipelined produce measured at **~80x NATS JetStream at `sync_interval=always`** (matched-durability label) on the reference edge device — `fsync`-before-ack, group-committed. See [docs/PERF_LEDGER.md](../docs/PERF_LEDGER.md#round-5-458-the-half-duplex-window-was-the-leg-4-gap-full-duplex-produce_stream--928ks-all-five-legs-cleared). |
| Single-consumer durable consume | **ACHIEVED, measured** | The Tier-S streaming consumer (consumer-managed offsets, a resident sparse byte index, zero-copy `DeliverBatch`) measures **~6–8x NATS JetStream pull** across the 20k→200k sweep on t4g.large ([docs/PERF_LEDGER.md](../docs/PERF_LEDGER.md), 2026-06-19). This used to be the one axis we lost; the [V2-M1](#v2-roadmap-the-single-node-milestones) fix landed and the win is now unconditional. |
| In-memory (RAM) throughput | **ACHIEVED, measured** | In-memory stream measured **~3.3x** NATS JetStream in-memory at matched workload (PERF_LEDGER round 5). |
| Corruption recovery | **ACHIEVED** | Bounded, reported, fail-closed: longest-valid-prefix recovery, stop-at-first-bad-frame, per-event caps (≤1 segment or 64 MiB, ≤1% of durable bytes), quarantine-by-copy, typed loss report — see [docs/RECOVERY.md](../docs/RECOVERY.md#1-the-recovery-model-ratified) and [I3](../docs/INVARIANTS.md#i3-bounded-reported-loss). NATS truncate-and-drops are unbounded and silent. |
| Native Prometheus metrics | **ACHIEVED** | `/metrics` is built in (NATS needs a sidecar). |
| Multi-consumer durable consume | **ACHIEVED** | Competing / key-shared / broadcast work-groups over one ordered log. |
| Single static binary, kernel-only deps | **ACHIEVED** | One musl binary, broker + CLI, no JVM, no ZooKeeper, no external dependency. |

### 2b. Shipped and wired (functionally complete; broader verification in progress)

These are built, wired end-to-end (engine → wire frames → CLI) and covered by tests. They do not yet carry the full CI-gated head-to-head benchmark that the §2a rows do, and each has a stated scope edge — but "not built" is no longer true for any of them.

| Capability | Status | What ships, and the scope edge |
| --- | --- | --- |
| Multi-stream + subjects + wildcards | **SHIPPED, wired** | N named streams + subject routing + `*` / `>` wildcards are wired end-to-end (`streamset.rs` → engine → `StreamDeclare` / `PubTo` / `SubTo` / `BindSubject` / `PubSubject` frames → the `ironbus stream` CLI); an unbound subject is a typed fail-closed reject. Scope edge: **partitions** are built in storage but not yet wired through the engine ([V2-M2](#v2-roadmap-the-single-node-milestones), #693), and named-stream consume parity (DLQ / key-shared / Tier-S / metrics) is in progress (#681). |
| Multi-node clustering + replication | **SHIPPED, wired** | A real cluster runs behind `ironbus serve --cluster-id / --cluster-peer`: a KRaft-style metadata Raft group (tikv/raft-rs), per-partition leader-serve + ISR follower-fetch on a data-plane port, the `C2-fsync` quorum-`fdatasync` ack default (the wire `PubAck` is withheld until quorum-fsync), leader-epoch fencing, footer/CRC divergence self-heal, follower reads, and async geo / leaf / federation. [V2-C1 through V2-C7](#v2-roadmap-the-clustering-milestones) are merged. Scope edge: replication today covers the single default log (partition 0); **multi-partition** replication awaits the M2 partition wiring (#693), and the cluster benchmarks are not yet CI-gated (#636, [V2-C8](#v2-roadmap-the-clustering-milestones)). |
| Reliability: idempotent producer + transactional messaging | **SHIPPED, wired** | Idempotent producer (PID + epoch + sequence; Fresh / Duplicate / Fenced / OutOfOrder), effectively-once proven across restart AND a long offline gap; RocketMQ-style transactional half-messages (`TxnPrepare` through `TxnListen` frames, crash-safe commit + broker back-check) with end-to-end client tests ([V2-M8](#v2-roadmap-the-single-node-milestones)). |
| Observability + recovery-as-feature | **SHIPPED, wired** | `ironbus verify` (offline fsck), `repair` (`--apply` under a data-dir lock), `backup` / `restore`, latency histograms (`ironbus_*_seconds_bucket`), and recovery-event counters from the live loss report ([V2-M6](#v2-roadmap-the-single-node-milestones)). Scope edge: OpenTelemetry tracing is the one M6 piece not built (#770). |
| Security: auth + pre-auth DoS + graceful drain | **SHIPPED, wired** | Three auth mechanisms (bearer token, Argon2id password, mTLS) × three independent scopes, pre-auth DoS defenses (per-IP rate limit, half-open cap, failed-auth lockout), graceful drain + SIGTERM readiness-flip, and a secret-free audit stream, wired into the accept loop ([V2-M7](#v2-roadmap-the-single-node-milestones)). Scope edge: the **mTLS** mechanism is inert (fails closed) until the TLS transport lands — see §2c. |

### 2c. Still target — not built

Genuinely not shipped, marked as such everywhere they appear:

| Roadmap item | Status | Note |
| --- | --- | --- |
| Partitions through the engine + multi-partition replication | **TARGET** | The partition math is built in storage but not wired to the engine / wire / CLI; cluster replication covers the default log until it lands. [V2-M2](#v2-roadmap-the-single-node-milestones), #693. |
| Routing richness — priorities / delayed / request-reply | **TARGET** | Per-message TTL enforcement exists in the engine (operator surface open, #710) and reason-tagged dead-lettering ships; optional priorities (#553), scheduled / delayed messages (#555), and request-reply RPC (#764) are not built. [V2-M4](#v2-roadmap-the-single-node-milestones). |
| TLS 1.3 + mTLS transport | **TARGET — the wire is plaintext today** | No TLS stack is linked; `--tls-*` material is reserved and **refused at startup** (#766). Until it lands, run on loopback or use `--insecure-plaintext-wire` with auth on a trusted network. [V2-M7](#v2-roadmap-the-single-node-milestones). |
| Tiered storage | **TARGET (post-1.0)** | Offload cold sealed segments to an object-storage backend behind the cursor abstraction. [V2-M10](#v2-roadmap-the-single-node-milestones), #643. Distinct from an object store (a non-goal). |
| Clustering benchmarks, CI-gated | **TARGET** | The cluster code ships; the head-to-head-vs-NATS cluster benchmarks are not yet CI-gated, and the t4g 3-node edge-fit run is open (#636). [V2-C8](#v2-roadmap-the-clustering-milestones). |

**Rule:** every capability is marked at its true status — a measured win (§2a), shipped-and-wired with a stated scope edge (§2b), or still target (§2c). A superlative in §1 is the destination, not a present-tense claim, until it reaches §2a.

---

## 3. Strategic scorecard

Verified against the `nats-server` source, the Jepsen NATS 2.12.1 report, Antithesis, and ~35 GitHub
issues. This is a competitive map, not a claim that the gaps are closed.

### Already winning (achieved, measured)

- **Durable produce** — ~80x NATS `sync_interval=always`, pipelined, on-device (PERF_LEDGER round 5).
- **Single-consumer durable consume** — ~6–8x NATS JetStream pull, the Tier-S streaming tier (PERF_LEDGER 2026-06-19). The axis we used to lose is now an unconditional win.
- **In-memory RAM** — ~3.3x NATS JetStream in-memory; more memory-efficient.
- **Corruption recovery** — bounded / reported / fail-closed, vs NATS unbounded / silent / unrecoverable.
- **Native Prometheus** — built in, vs NATS needing a sidecar.
- **Multi-consumer consume** — work-groups over one ordered log.

### Shipped and wired (feature parity reached; scope edges in §2b)

- **Multi-stream + subjects + wildcards** — wired end-to-end; partitions are the remaining M2 gap (#693).
- **Multi-node clustering** — metadata Raft + per-partition ISR replication + `C2-fsync` quorum acks + follower reads + divergence self-heal + geo, behind `--cluster-id / --cluster-peer`; default-log replication today, multi-partition (#693) and CI-gated benches (#636) pending.
- **Reliability** — idempotent producer + transactional messaging (M8), effectively-once across restart + offline gap.
- **Observability** — verify / repair / backup / restore + latency histograms + recovery counters (M6).
- **Security** — 3-mechanism auth × 3 scopes + pre-auth DoS + graceful drain (M7); the TLS transport is the gap.

### Still target (not built)

- Partitions through the engine + multi-partition replication → V2-M2 (#693).
- Routing priorities / delayed / request-reply → V2-M4 (#553 / #555 / #764).
- TLS 1.3 + mTLS transport — the wire is plaintext today → V2-M7 (#766).
- Tiered storage → V2-M10 (#643).
- CI-gated cluster benchmarks → V2-C8 (#636).

### Non-goals (deliberately not built)

- **KV store** and **object store** are non-goals: IronBus stays a pure message bus and does not grow into adjacent datastore categories (a KV store like the NATS JetStream KV, or an object store). These were formerly the V2-M5 and V2-M9 roadmap slots, now retired. Tiered storage (V2-M10) is unaffected: offloading cold sealed log segments to an object-storage backend is core log infrastructure, not an object-store product.

---

## 4. The NATS-shortfall ammunition (verified)

Every claim below cites a primary source. These are the documented failures the IronBus design is built
to beat — not by assertion, but by construction (see §5–§6 and the cluster milestones).

- **`ack` ≠ durable.** NATS defers `fsync` (default `sync_interval` 2 minutes); an `ack` does not mean
  the data is on disk. [#7564](https://github.com/nats-io/nats-server/issues/7564) (open, defended "by
  design"): a simulated power failure **lost 131,418 of 930,005 acknowledged writes**.
- **Truncate-and-drop recovery — unbounded and silent.**
  [#7549](https://github.com/nats-io/nats-server/issues/7549): a single-bit `.blk` error loses 20k–287k
  acked records **even with `sync_interval: always` on R5**.
  [#7556](https://github.com/nats-io/nats-server/issues/7556): a single-bit error on a **minority** can
  cause nodes to **permanently delete the entire stream directory**, and the cluster never recovers
  quorum. [#6752](https://github.com/nats-io/nats-server/issues/6752): KV corrupts within days, requiring
  a manual recreate.
- **Raft-per-asset scaling.** Each replicated stream and consumer is its own Raft group (N+M+1 groups),
  so background heartbeat traffic scales with **asset count** (a ~2000-HA-asset/server ceiling), and the
  meta group is a single point of failure ([#4502](https://github.com/nats-io/nats-server/issues/4502)).
- **Replica drift that never self-heals.** [#5576](https://github.com/nats-io/nats-server/issues/5576):
  a replica can return "with a stream containing no data at all while reporting it as current";
  `errFirstSequenceMismatch` is defined but not acted on.
- **Filtered-consumer throughput cliff.** [#7014](https://github.com/nats-io/nats-server/issues/7014): a
  filtered consumer can hit a ~99% throughput cliff.
- **Jepsen NATS 2.12.1.** A corrupt node **"managed to become the leader of the cluster despite its
  corrupt state"** and then deleted the stream; the run **lost 679,153 of 1,367,069 total acknowledged
  writes (≈ 49.7%)**. ([jepsen.io/analyses/nats-2.12.1](https://jepsen.io/analyses/nats-2.12.1).)

> Provenance note: "1,367,069" is the *total* acked writes, and "679,153" is the *lost* subset (≈ 49.7%),
> not two separate losses. "N+M+1 groups" / "heartbeat scales with asset count" are faithful
> characterizations of NATS's per-asset Raft structure, not verbatim NATS phrases.

---

## 5. The recommended cluster architecture (in brief)

IronBus clusters as a **KRaft-style single metadata-Raft group** (one small 3- or 5-voter quorum owns
membership, partition placement, leadership/epoch, and config — and nothing on the hot data path) plus
**Kafka-ISR-style per-partition pull replication of the existing CRC-framed log** (followers fetch the
leader's already-framed segment byte ranges and re-validate each frame; partitions are *not* Raft groups,
so there is no per-partition heartbeat). The **default cluster ack (`C2-fsync`) means the record is
`fdatasync`'d on a quorum of replicas by construction** — strictly stronger than NATS R3 (quorum
page-cache) and Kafka `acks=all` (which trades `fsync` for replication) — affordable because IronBus
group-commits one `fdatasync` per batch on both leader and followers. Divergence self-heals: replicas
cross-check the segment **footer `(record_count, last_seq)` + per-segment CRCs** IronBus already computes,
fenced by a per-partition **leader epoch**, so silent drift and minority-corruption-deletes become
bounded, reported, automatically repaired events. **This is explicitly NOT Raft-per-asset** (NATS's group
explosion + heartbeat storm + meta-SPOF + never-self-healing drift), and it degrades to a zero-config
single node at n=1.

The cluster **preserves the single-node durability/recovery/edge/flash-wear guarantees**: `C2-fsync`
keeps `ack`-implies-durable; followers append the same large sequential CRC-framed segments (no extra
write amplification, no in-place rewrites); and the cluster recovery invariants below extend I1–I3 across
replicas.

### Cluster recovery invariants (CI1–CI4)

- **CI1 — cluster durable prefix.** The committed prefix is identical on every in-sync replica up to the
  high-watermark; divergence above it is truncated by epoch, never committed.
- **CI2 — cluster ack implies quorum-fsync.** A `C2-fsync` ack ⇒ the record is `fdatasync`'d on a quorum
  (the cluster extension of I2).
- **CI3 — bounded, reported, repaired divergence.** Any cross-replica divergence is detected (footer/CRC),
  bounded by the I3 caps, reported as a typed event, and either auto-repaired from the quorum or fails
  closed — never silently served, never deletes data, never loses quorum from a minority fault.
- **CI4 — epoch monotonicity / no stale-leader commit.** Leadership epochs are monotonic and
  majority-assigned; a stale or corrupt replica cannot commit or win re-election (the leader-completeness
  restriction). This is the construction that prevents the Jepsen corrupt-node-wins-election failure.

---

## 6. V2 roadmap and status ledger

Each milestone below is one line of SCOPE. Authoritative completion status is in §2 (measured /
shipped-and-wired / still target): several have shipped — M1 (consume), M2 (streams + subjects + wildcards),
M6, M7 (auth), M8, and the cluster C1 through C7 — so the bullets describe what each milestone covers, not
that it is unbuilt.

### V2 roadmap the single-node milestones

- **V2-M1 — Consume: beat NATS (SHIPPED — now ~6–8x, see §2a).** Resident byte index + lock-free read plane +
  zero-copy delivery + a streaming consumer-managed-offset tier, keeping the lease-rich work-queue tier.
- **V2-M2 — Multi-stream + subjects + wildcards (P0, biggest feature gap).** N independent logs +
  subject routing + partitions on one node, fail-closed on unbound subjects, flat per-record cost.
- **V2-M3 — Per-message-ack hardening.** Bound + persist the acked-ahead set; durable per-message
  delivery-count so the max-deliver→DLQ rule always fires.
- **V2-M4 — Routing & queue richness.** Per-message/stream TTL, dead-letter exchanges, optional
  priorities, scheduled/delayed messages.
- **V2-M6 — Observability + rich CLI + recovery-as-feature.** Latency histograms, recovery-event
  counters, an `ironbus verify` offline fsck, a first-class `repair`, backup/restore.
- **V2-M7 — Security & DoS hardening.** TLS 1.3 fail-closed bind, three-mechanism auth × three scopes,
  pre-auth DoS defenses, graceful drain.
- **V2-M8 — Reliability semantics.** Idempotent producer (PID + epoch + sequence), effectively-once
  survival across restart + long offline gap.
- **V2-M10 — Tiered storage (post-1.0).** Offload cold sealed segments to object storage behind the
  cursor abstraction.
- **V2-M11 — (folded into the clustering milestones below).** The thin "replication done right" is
  replaced by the first-class V2-C set.
- **V2-M12 — Prove the wins: head-to-head benchmarks vs NATS.** Corruption-recovery, write-amplification,
  durable produce + consume, and effectively-once survival, all CI-gated.

### V2 roadmap the clustering milestones

Clustering is first-class. Each milestone below is one line. **V2-C1 through V2-C7 have shipped and are
wired** (see §2b, behind `--cluster-id / --cluster-peer`); the remaining cluster milestone is V2-C8
(CI-gating the head-to-head-vs-NATS cluster benchmarks, #636). The default-log scope edge in §2b applies.

- **V2-C1 — Metadata consensus (the one Raft group).** An embedded metadata-Raft (1/3/5 voters) over an
  IronBus log holding membership/placement/leadership-epoch/config; joint-consensus membership + learners
  + peer-id validation; the n=1 zero-config degeneracy is byte-for-byte today's broker.
- **V2-C2 — Per-partition data replication (leader + ISR pull).** Followers fetch CRC-framed segment
  ranges and re-validate each frame; an in-sync-replica set with `min_isr`; high-watermark = the
  contiguous committed prefix; leader-epoch truncation on divergence; group-commit on leader and follower.
- **V2-C3 — Cluster ack levels (the durability win).** A `C0/C1/C2-pagecache/C2-fsync` spectrum;
  `C2-fsync` (quorum `fdatasync`) is the R≥3 default; `C2-pagecache` is an explicit, loud opt-in; per-level
  metrics.
- **V2-C4 — Divergence detection + self-heal (the recovery differentiator).** Footer/CRC cross-replica
  compare; automatic re-sync from the quorum; minority-corruption quarantine + repair (never delete);
  leader-completeness election restriction; the CI1–CI4 checkers.
- **V2-C5 — Membership / placement / rebalance (no meta-SPOF).** Replica placement across nodes/failure
  domains, cooperative learner back-fill on join, leaderless-node failover with no data move,
  re-replication rate-limited under the existing backpressure.
- **V2-C6 — Follower / stale reads (consume scales with replicas).** Leader-lease local linearizable
  reads, CRAQ-style apportioned follower reads, zero-copy follower delivery.
- **V2-C7 — Cross-cluster / geo (async, additive).** Async mirror + source, cluster-id/domain namespace,
  edge leaf-spoke links, gateway/supercluster federation.
- **V2-C8 — Clustering benchmarks vs NATS (CI-gated proof).** Quorum power-cut durability, divergence
  self-heal, split-brain, heartbeat-cost scaling, clustered consume throughput, and a 3-node edge-fit
  proof — each reproducing a documented NATS failure and showing IronBus's by-construction win.

---

## 7. Cross-references

- The tenets and the current shipped scope: [README.md](../README.md).
- The single-node durability contract the cluster extends: [docs/DURABILITY.md](../docs/DURABILITY.md).
- The recovery model the cluster invariants extend: [docs/RECOVERY.md](../docs/RECOVERY.md).
- The shared invariants I1–I6: [docs/INVARIANTS.md](../docs/INVARIANTS.md).
- The edge constraints the cluster must not regress: [docs/EDGE_CONSTRAINTS.md](../docs/EDGE_CONSTRAINTS.md).
- The log-is-WAL model the followers replicate verbatim: [docs/WAL.md](../docs/WAL.md).
- The measured produce/consume numbers cited here: [docs/PERF_LEDGER.md](../docs/PERF_LEDGER.md).
- The prior-art take/leave that grounds the architecture choices: [docs/PRIOR_ART.md](../docs/PRIOR_ART.md).
