<p align="center">
  <img src="docs/assets/ironbus-logo.png" alt="IronBus logo" width="360">
</p>

# IronBus

**A single durable, crash-safe message queue for the edge, in one static Rust binary.**

> Status: active development, with most of the mission shipped. The single-node broker, multi-stream + subjects + wildcards, a real multi-node cluster (C1–C7), idempotent + transactional produce, three-mechanism auth, and the observability + recovery tooling are all built, wired, and CI-gated. The remaining gaps are tracked per item: partitions through the engine ([#693](https://github.com/ELares/IronBus/issues/693)), the TLS transport ([#766](https://github.com/ELares/IronBus/issues/766)), and routing richness ([#553](https://github.com/ELares/IronBus/issues/553), [#555](https://github.com/ELares/IronBus/issues/555), [#764](https://github.com/ELares/IronBus/issues/764)). Code lands one small, reviewed, CI-gated PR at a time. Start at the [vision EPIC (#1)](https://github.com/ELares/IronBus/issues/1).
>
> **Where this is going:** the v2 mission is for IronBus to be feature-rich and decisively better than NATS on every front, **single node or clustered**, with clustering a first-class goal (not post-1.0) — and most of it has shipped. Read **[docs/MISSION.md](docs/MISSION.md)** — it is scrupulously explicit, in three tiers, about what is measured today, what is shipped and wired (with scope edges), and what is still target.

IronBus is one durable, ordered queue (think a single AWS SQS queue) that lives on the device, survives power loss and corrupt files on its own, and fans out to many consumers. It ships as a single static binary you can drop onto a Raspberry Pi. It takes the best small, composable ideas from MQTT, NATS, Kafka, Pulsar, Redpanda, RocksDB, Redis Streams, and SQS, and leaves behind the operational weight and the silent durability footguns that do not survive a battery-less edge node. The single-node durable broker, multi-stream + subjects + wildcards, and a real multi-node cluster all run today; the remaining v2 items (partitions, TLS, routing richness) are tracked with a per-capability status in [docs/MISSION.md](docs/MISSION.md). A KV store and an object store are non-goals: IronBus stays a pure message bus.

---

## Why IronBus exists

Every existing broker is wrong for a resilient durable-log edge workload in a different way, and each wrongness maps to one of our tenets:

- **Kafka** defaults to NOT calling `fsync` per write and leans on replication for durability. On an edge box that loses power, the page-cache loss window is real, and replicas usually share the same power rail, so the independent-failure assumption is false. It also drags in a JVM.
- **NATS Core** is beautifully simple but has no persistence. JetStream adds durability but a heavier surface.
- **MQTT** is edge-friendly and simple, but it is a protocol, not a durable, replayable log.
- **SQS** is the delivery model we want (visibility-timeout leases, dead-letter queues, dedup), but it is a managed cloud service, the opposite of embeddable and edge-first.
- **RocksDB, Pulsar, Redpanda, Redis Streams** each solved one piece beautifully (a checksummed log, segment-centric storage, a single self-contained binary, lease-based consumer groups), but none is the whole thing.

None of them is a single static cross-platform binary that self-heals against corrupt files with bounded, reported loss. IronBus exists to be exactly that intersection.

---

## The five tenets

We rank the tenets, and when two conflict we resolve in this order: **Resilient > Simple > Edge First > HyperScale > Cross Platform.**

| Tenet | What it means in practice |
| --- | --- |
| **Simple** | One logical queue, one binary, one config file with safe defaults, a tiny length-framed binary wire protocol whose stored records you can decode with the built-in `ironbus peek` and `ironbus dump` commands. Install to first message in under a minute (see the [Quick start](#quick-start-from-install-to-many-producers-and-consumers)). No ZooKeeper, no JVM, no external dependencies. |
| **Resilient** | Every acknowledged durable write survives power loss. Startup always recovers a consistent prefix. A torn tail or a poison record or segment is skipped, never fatal, with loss bounded and reported as a number. |
| **HyperScale** | High per-core throughput on edge hardware (not horizontal scale-out): a bounded ring-buffer core with structural backpressure, group-commit `fdatasync`, and zero-copy fan-out. Measured head-to-head against Redpanda on real durable hardware in the [Benchmarks](#benchmarks) section — not asserted. |
| **Edge First** | RAM ceilings, flash-wear budgets, and brownout behavior are first-class configuration, not afterthoughts. The queue spills to disk and sheds load rather than blocking producers or running out of memory. |
| **Cross Platform** | One static musl binary per architecture (aarch64, armv7, x86_64), kernel-only dependency, reproducible builds, embedded SBOM. |

---

## What IronBus is, and is not

**IronBus v1 IS:**

- A single durable, totally ordered, append-only log per instance (one queue), consumed by many consumers.
- At-least-once delivery with SQS-style visibility-timeout leases, redelivery, a max-deliver limit, and a dead-letter queue.
- Local-first and embeddable, durable on one node by calling `fdatasync` before it acknowledges a write.
- Self-healing: it detects corruption, skips poison records and quarantines unreadable segments, resynchronizes to the next valid record, and reports exactly what was lost.
- A single static binary that is both the broker and the CLI.

**Most of the v2 mission has shipped; the remaining items are the v2 roadmap, all tracked with an
explicit status in [docs/MISSION.md](docs/MISSION.md) §2.** The mission is for IronBus to be feature-rich
and decisively better than NATS on every front, single node **or clustered**. Single node is the
zero-config default the cluster degrades to, not the ceiling:

- **Multi-stream + subjects + wildcards ship today; partitions are the remaining gap.** Named streams,
  subject routing, and `*` / `>` wildcards are wired end-to-end (an unbound subject is a typed fail-closed
  reject); partitions are built in storage but not yet wired through the engine (V2-M2, #693). A KV store
  and an object store are non-goals: IronBus stays a pure message bus.
- **A real multi-node cluster ships today; clustering is first-class.** Beyond the zero-config single node
  (`fdatasync` before ack), a genuine cluster runs behind `--cluster-id / --cluster-peer`: a metadata Raft
  group, per-partition ISR pull replication, a `fsync`'d-on-a-quorum ack default, leader-epoch fencing, and
  footer / CRC divergence self-heal that **preserve** every durability / recovery / edge / flash-wear
  guarantee below; the cluster recovery invariants (CI1–CI4) extend the single-node
  bounded-and-reported-loss discipline across replicas. Scope edge: replication covers the default log
  today (multi-partition awaits #693) and the cluster benchmarks are not yet CI-gated (#636).

**IronBus is explicitly NOT (these are durable non-goals):**

- Not exactly-once. At-least-once is the contract, with an optional fire-and-forget fast path. No exactly-once handshake. Effectively-once is available via the opt-in [idempotent producer](#idempotent-producer-effectively-once).
- Not a key/value store. A KV store (the NATS JetStream KV analog) is a different product category; IronBus stays a pure message bus.
- Not an object store. Chunked object storage is out of scope. (Tiered storage of cold log segments to an object-storage backend is core log infrastructure and stays on the roadmap, which is distinct from being an object store.)
- Not a Kafka wire-protocol clone, and not a Windows product in v1 (Windows fsync and path semantics differ enough to threaten the durability guarantee).

---

## Benchmarks

Performance ([#19](https://github.com/ELares/IronBus/issues/19)) is measured, not asserted, on the substrate that actually decides a durable broker: **real network-attached durable storage**, where a `fdatasync` ack means the bytes survived power loss. IronBus is benchmarked head-to-head against **Redpanda v26.1.12** on real AWS **t4g / EBS** hardware, cross-checked in a matched Linux VM. Everything below is **3-run medians** with each broker pinned to a matched, labeled durability tier; full methodology, per-broker configs, and harnesses live under **[docs/benchmarks/](docs/benchmarks/)**.

### Matched-conditions: IronBus vs Redpanda, both inside one Linux VM

Redpanda is Linux-only, so to rank it fairly against IronBus this study puts **both brokers inside the same Linux VM** — same kernel, same ext4-on-virtio disk, same guest loopback, same real `fdatasync` (~200–300 µs) — the identical substrate for both. Full methodology, every cell, and the harness: **[docs/benchmarks/REDPANDA_MATCHED_2026_07.md](docs/benchmarks/REDPANDA_MATCHED_2026_07.md)**.

The single-connection matrix there has IronBus winning P3/1 KiB, both consume rows, and both durable-latency rows (L1 ~7×, real sub-millisecond fsync-ack vs Redpanda's tool-quantized 2 ms), tying P1, and trailing on **P2 group-commit produce** — the gap that motivated the **pipelined sync tier** ([#1040](https://github.com/ELares/IronBus/issues/1040): `fdatasync` decoupled from and overlapped with the append path, self-clocking group commit). That single-connection P2 gap is the IronBus **client**, not its broker: the session drains its parked-produce window each pass, so one connection cannot fill the pipeline — while Redpanda's Kafka client already pipelines 5-in-flight on one connection.

Given each broker the client concurrency that saturates it (IronBus `bench --producers N`; Redpanda N parallel perf clients), the durable-produce result inverts:

| P2 durable produce | IronBus peak | Redpanda peak | IronBus advantage |
| --- | ---: | ---: | :-- |
| 128 B | **1.68 M** (8 conns) | 1.51 M (4 clients) | **1.11×** |
| 1 KiB | **657 k** (8 conns) | 300 k (4 clients) | **2.19×** |

**Redpanda does not scale with more clients** (its single raft group is saturated by one 5-in-flight client — throughput peaks at 4 and drops at 8); **IronBus scales up and passes Redpanda's peak on both sizes** (1.44×/2.46× at matched 8 clients). The single-connection row remains the honest exception, addressed by the session-side per-connection reorder ring ([#1045](https://github.com/ELares/IronBus/issues/1045)) — reported here unhidden.

### Real hardware: AWS t4g / EBS — the authoritative durable numbers

The VM's virtio `fdatasync` is real but cheap (~200–300 µs); the toughest test of a group-commit engine is a barrier expensive enough that the only way to sustain throughput is to coalesce and overlap many records per sync. So the matched study was **re-run on a single AWS t4g.large** Graviton node with both brokers writing an **EBS gp3** volume (real `fdatasync` ~2.8 ms, ~10× the VM's virtio flush). The result **reproduces and sharpens** the VM verdict: on the expensive real sync, Redpanda peaks at *one* client and falls monotonically, while IronBus climbs to **256 k @128 B / 62 k @1 KiB** — beating Redpanda's peak **1.21× / 1.67×** (2.25× / 2.46× at matched 8 clients). The pricier the durability barrier, the wider IronBus's group-commit margin. See §7 of the study doc.

A subsequent configurable **io-mode** ([#1054](https://github.com/ELares/IronBus/issues/1054); `serve --io-mode auto`, which auto-detects EBS as network-durable) closes the *single-connection* rows too. On EBS the residual `fdatasync` cost is pure extent-metadata journaling, so an `O_DIRECT` write plus a now-free barrier (~1 µs, the full fsync guarantee kept) turns single-connection sync-per-message from a loss into a **1.7–2.5× win**, single-connection group-commit at 1 KiB into a **3.7× win** (128 B lands at par), and drops durable-ack **median** latency to ~1 ms so IronBus now leads L1 at the median as well as the ~100× tail. `buffered` stays the default; `auto`/`direct` are the network-durable opt-in.

The single-connection medians on that substrate, with `--io-mode auto` (3-run medians, same box class and Redpanda build, `write_caching=false`):

| Row (durability label) | Size | IronBus (`--io-mode auto`) | Redpanda | Result |
| --- | --- | ---: | ---: | :-- |
| **P1** sync-per-message (fsync before **every** ack) | 128 B | **898** | 520 | IronBus **1.7×** |
| | 1 KiB | **897** | 364 | IronBus **2.5×** |
| **P2** single-conn group-commit (`pubwindow=4096`) | 128 B | 130,035 | 140,805 | par (0.92×) |
| | 1 KiB | **125,163** | 33,763 | IronBus **3.7×** |
| **L1** durable ack, p50 / p99 µs (lower is better) | 128 B | **1,039 / 3,155** | 2,000 / 317,000 | IronBus **1.9× / ~100×** |
| | 1 KiB | **1,045 / 3,172** | 2,000 / 301,000 | IronBus **1.9× / ~95×** |

On this real durable substrate IronBus **wins or ties every row**; the single non-win is P2/128 B single-connection, at par (within the study's ~8 % cell spread). Redpanda's L1 p50 is throttled-tool-quantized to whole milliseconds, but its ~300 ms p99 tail is real. Full medians and the harness are in **[§7 of the study doc](docs/benchmarks/REDPANDA_MATCHED_2026_07.md)**.

### Performance targets

The measured table above does not retire the SLO discipline: the provisional marquee **target** (a floor, not a measurement) remains 256-byte messages, a single consumer, durable group-commit `fdatasync`, sustaining at least 60,000 messages per second with p99 latency under 6 ms **on a Raspberry Pi 4**. Every published SLO is a measured floor (the on-device p99 minus a 20 percent margin), recorded with an HdrHistogram against a single monotonic clock, and gated against regression on a rolling baseline. See [docs/SLO.md](docs/SLO.md) and [docs/PERF_LEDGER.md](docs/PERF_LEDGER.md) for the on-device (t4g / edge) measured history, including the ~80x-NATS durable-produce and ~6–8x consume results from the on-device history.

---

## Quick start: from install to many producers and consumers

IronBus is one static binary that is **both the broker and the CLI**. Below is the whole loop: install it, start the broker on your edge device, then point producers and consumers at it. The local examples use the default address `127.0.0.1:7777`, so you can drop `--addr` when everything runs on the same box.

> Security heads-up: the wire protocol is **not yet encrypted** — TLS is designed but not implemented ([#766](https://github.com/ELares/IronBus/issues/766)), so the wire is plaintext. Authentication **is** implemented (bearer token or Argon2id password, with publish / subscribe / admin scopes), but until TLS lands keep the broker bound to loopback or a trusted LAN behind a firewall or an SSH / WireGuard tunnel. Do not expose it to the open internet.

### 1. Install

**The seamless path (recommended).** One line auto-detects your CPU arch, downloads the matching static `musl` binary from the latest release, and verifies its checksum before installing (fail-closed, no skip-verify override):

```sh
curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh | sh
```

Prefer to grab the binary yourself? Download the static `musl` binary for your CPU from the [latest release](https://github.com/ELares/IronBus/releases/latest), `chmod +x`, and run it (no runtime dependencies, not even a libc to install):

| Edge CPU | Asset |
| --- | --- |
| arm64 / Raspberry Pi 4 / 5 (64-bit) | `ironbus-linux-arm64` |
| armv7 / Raspberry Pi (32-bit) | `ironbus-linux-armv7` |
| x86_64 / amd64 | `ironbus-linux-amd64` |

Every push to main publishes a fresh `YYYY.MMDD.N` build (calendar-versioned, the three static binaries plus a consolidated `SHA256SUMS` and a Sigstore provenance attestation), so `releases/latest` and the installer always resolve to the newest build. See [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) for every channel.

**Prefer a container?** Every build also publishes a multi-arch (amd64 / arm64 / armv7) distroless image to `ghcr.io/elares/ironbus`, so you can pull and run without installing anything (mind the loopback / security note above):

```sh
docker pull ghcr.io/elares/ironbus:latest
docker run --rm -v ironbus-data:/var/lib/ironbus -p 127.0.0.1:7777:7777 \
  ghcr.io/elares/ironbus:latest serve --data-dir /var/lib/ironbus
```

**Build from source** (the developer / alternative path, on any host with a Rust toolchain):

```sh
git clone https://github.com/ELares/IronBus.git
cd IronBus
cargo build --release
# the single binary is now at target/release/ironbus
```

For an **edge device** without network access to the release, cross-compile the one static `musl` binary and copy it over:

```sh
rustup target add aarch64-unknown-linux-musl   # or armv7-unknown-linux-musleabihf, x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/ironbus pi@edge-device:/usr/local/bin/ironbus
```

### 2. Start the broker on the edge

The only required flag is `--data-dir` (the durable log, the consumer cursors, and the dead-letter sink all live there). Use the `edge-tiny` profile for a small-RAM, flash-gentle node:

```sh
ironbus serve --data-dir /var/lib/ironbus --profile edge-tiny
```

- `--profile edge-tiny` selects the small-RAM preset (8 MiB segments, tiny credits, 32 connections) plus a **64 MiB RAM ceiling that refuses to boot if the configured caps cannot fit**, so the broker can never surprise you by growing past its budget. `balanced` (the default) and `throughput` are the other two presets; any env var or flag still overrides an individual knob, and `--config <file>` slots a strictly-validated TOML file into the precedence chain (see the [config feature](#config-file-profiles-and-hot-reload) and [docs/CONFIG.md](docs/CONFIG.md)).
- By default the broker binds **loopback only** (`127.0.0.1:7777`) and acknowledges a write **only after `fdatasync`**, so a power cut loses zero acknowledged messages. To let producers and consumers on **other machines** reach it, bind the device's address (mind the security note above):

  ```sh
  ironbus serve --data-dir /var/lib/ironbus --profile edge-tiny --addr 0.0.0.0:7777
  ```

- Optional health and metrics: add `--health-addr 127.0.0.1:9090` to expose `GET /healthz`, `/readyz`, and `/metrics`.
- `Ctrl-C` (or `SIGINT` / `SIGTERM`) stops gracefully: it flushes every consumer cursor and exits cleanly, and a restart resumes from the durable log. `SIGHUP` (or `systemctl reload`) re-reads `--config` and applies the live-reloadable subset (the consumer-safe retention bounds + the disk-full policy) without stopping the broker (#380); a change to a restart-required key is reported but needs a restart. Mind that the unit ships `Restart=on-failure`: a clean stop (`SIGTERM`) stays down until you `systemctl start ironbus` again. For an always-on node, run it under systemd (the `.deb` ships a ready unit, so `sudo systemctl enable --now ironbus` is all you need once it is installed).

### 3. Producers: one, or many

Each stream is **one durable, totally ordered log** (a single-stream broker is the default). Any number of producers append to it; the order is the order the broker fsynced them.

```sh
# Publish one message. It prints the durable offset once the record is fsynced
# (a printed offset means the message is on disk).
ironbus pub 'hello edge'

# Attach a key (keys drive key-shared ordering on the consumer side).
ironbus pub --key sensor-12 '{"temp":21.4}'

# Take the payload from a pipeline (stdin) instead of an argument.
read_sensor | ironbus pub --key sensor-12
```

**Many producers** is just running `ironbus pub` from as many processes or hosts as you like; each opens its own connection and the broker serializes them all into the single ordered log. A quick local burst:

```sh
for i in $(seq 1 1000); do ironbus pub "event-$i"; done
```

(For a long-lived, high-rate producer, link the [`ironbus-client` Rust crate](#client-sdks) or the [Go SDK](#go) instead of forking a process per message.)

### 4. Consumers: one, or many

A consumer joins a named **work-group**, fetches messages, and disposes of each: `--ack` (commit, never redelivered), `--nack` (redeliver later), or `--term` (drop). Delivery is at-least-once, so an un-acked message redelivers after its visibility timeout.

```sh
# Read up to 10 from the "orders" group and commit them.
ironbus sub --group orders --max 10 --ack
```

Each message prints as `#<offset> gen=<token> key=<key> payload=<payload>`, followed by `fetched <n> message(s)`. Omit the disposition to **peek** (print without committing; the messages redeliver after the timeout):

```sh
ironbus sub --group orders --max 5
```

**Many consumers** is where the work-group model matters — see [Work-groups](#work-groups-competing--key-shared--broadcast) in the feature tour for the three patterns (competing, key-shared, broadcast).

### 5. Inspect the data directly (no running broker)

Because the durable log is just files, you can decode it with the broker stopped:

```sh
ironbus peek  --data-dir /var/lib/ironbus   # a bounded window of durable records
ironbus dump  --data-dir /var/lib/ironbus   # every durable record
ironbus scrub --data-dir /var/lib/ironbus   # read-only integrity scan that reports any corruption
```

For every flag, default, and exit code, see the [CLI reference (docs/CLI.md)](docs/CLI.md); for a longer narrative walkthrough see [docs/USAGE.md](docs/USAGE.md).

---

## Feature tour

Everything below is **shipped and wired** — every command in this tour was verified against the current binary. Each subsection names its scope edge where one exists. (What is *not* built is consolidated in [What is NOT shipped](#what-is-not-shipped-the-roadmap-and-the-non-goals).)

### The durable ordered log

One crash-safe append-only log per instance — `fdatasync` before ack, so a printed offset means the record is on disk — consumed by many consumers at-least-once.

```sh
ironbus serve --data-dir /var/lib/ironbus
ironbus pub 'hello edge'
ironbus sub --group orders --max 10 --ack
```

### Durability levels

The operator picks the ack/durability tradeoff per broker. `sync` (fsync-before-ack, zero acked loss) is the default; the relaxed levels (`interval`, `async`, `none`) are strictly opt-in and gated behind an explicit `--async-loss-ack` consent flag so a config typo can never silently weaken the contract. See [docs/DURABILITY.md](docs/DURABILITY.md).

```sh
ironbus serve --data-dir /var/lib/ironbus --durability-level sync
```

### Multi-stream, subjects, and wildcards

N named independent logs plus subject routing with `*` / `>` wildcards, wired end-to-end (engine → wire frames → CLI). An unbound subject is a typed, fail-closed reject — never a silent drop. Scope edge: named-stream consume parity (DLQ / key-shared / Tier-S / metrics on named streams) is in progress ([#681](https://github.com/ELares/IronBus/issues/681)).

```sh
ironbus stream create events --data-dir /var/lib/ironbus
ironbus stream bind 'sensors.>' events --data-dir /var/lib/ironbus
ironbus stream ls --data-dir /var/lib/ironbus
```

### Work-groups: competing / key-shared / broadcast

SQS-style competing consumers by default, per-key ordered fan-out (`--key-shared-group`), or a group-of-one broadcast tap (`--broadcast-group`) — all three over one ordered log with durable cursors, pickable per group at serve time.

```sh
ironbus serve --data-dir /var/lib/ironbus --key-shared-group orders --broadcast-group audit
# competing (default): run N of these and each gets a disjoint slice
ironbus sub --group workers --max 100 --ack
# broadcast: observe everything, then commit the cursor in one move
ironbus sub --group audit --max 100
ironbus cumulative-ack --group audit --up-to 5000
```

### Tier-S streaming consume (consumer-managed offsets)

The Kafka-style high-throughput consume tier: zero-copy `DeliverBatch` delivery over a resident sparse byte index, with consumer-managed offsets and cumulative commits — the 1.65 M msg/s row in the [benchmarks](#benchmarks) (4.2x NATS). The lease-rich work-queue tier (Tier-W) stays the default for per-message semantics.

```sh
ironbus bench --count 100000 --mode subscribe --consume-tier streaming
```

### Idempotent producer (effectively-once)

PID + epoch + sequence dedup (`Fresh` / `Duplicate` / `Fenced` / `OutOfOrder`) that survives a broker restart and an arbitrarily long offline gap. Off by default; opt-in per producer.

```sh
ironbus serve --data-dir /var/lib/ironbus --dedup-window-ms 120000 --dedup-max-ids 100000
```

```rust
// Rust: produce_dedup returns the typed ack (Fresh / Duplicate / Fenced / OutOfOrder).
let ack = client.produce_dedup(&message)?;
```

### Transactional half-messages

RocketMQ-style two-phase produce: prepare a half message (invisible to consumers), run your local transaction, then commit or roll back — with a crash-safe broker back-check (`TxnCheck`) so a producer that dies mid-transaction never wedges the log. Client-driven via the Rust API (`prepare` / `commit` / `rollback` / `transact`, plus `register_transaction_listener` for the back-check).

```rust
let txn = client.prepare("events", &message)?;
// ... local work ...
let offset = client.commit(&txn)?;   // or client.rollback(&txn)?
```

### Fire-and-forget fast path

An optional un-acked produce path with its own rate/byte budget, for telemetry-style throughput where at-most-once is acceptable.

```sh
ironbus bench --count 100000 --mode publish --fire-and-forget
```

### Multi-node clustering and replication

See the dedicated [Clustering](#clustering) section — a metadata Raft group, ISR pull replication, quorum-fsync acks, and divergence self-heal, behind two flags.

### Security: authentication, pre-auth DoS defenses, graceful drain

See the dedicated [Security](#security) section.

### Observability: Prometheus, health, live views

Built-in `/metrics` (no sidecar — NATS needs one), split `/healthz` + `/readyz` liveness/readiness, latency histograms and recovery counters, a live TUI, operator reports, and an optional read-only `/admin` snapshot.

```sh
ironbus serve --data-dir /var/lib/ironbus --health-addr 127.0.0.1:9090 --enable-admin
ironbus top --health-addr 127.0.0.1:9090
ironbus report groups --health-addr 127.0.0.1:9090
ironbus server check --health-addr 127.0.0.1:9090   # Nagios-style one-liner, frozen exit codes
```

Scope edge: OpenTelemetry tracing is the one observability piece not built ([#770](https://github.com/ELares/IronBus/issues/770)).

### Recovery as a feature: verify / repair / backup / restore

The recovery tooling NATS lacks: an offline fsck (`verify`), an explicit mutating repair (quarantine-by-copy + longest-valid-prefix truncate, under the exclusive data-dir lock, `--apply --force` required), and point-consistent backup/restore with a CRC'd manifest and fail-closed validation.

```sh
ironbus verify  --data-dir /var/lib/ironbus
ironbus repair  --data-dir /var/lib/ironbus                 # read-only plan
ironbus repair  --data-dir /var/lib/ironbus --apply --force # the actual repair
ironbus backup  --data-dir /var/lib/ironbus --out /backups/ib-2026-07-01
ironbus restore --from /backups/ib-2026-07-01 --data-dir /var/lib/ironbus
```

### Bounded, reported, fail-closed corruption recovery

Longest-valid-prefix startup recovery, stop-at-first-bad-frame, per-event loss caps (≤1 segment or 64 MiB, ≤1% of durable bytes), quarantine-by-copy, and a typed LossReport (log line + report file + Prometheus counter). Exceeding a cap freezes the log read-only rather than guessing. See [Resilience](#resilience-designed-for-failure-first).

```sh
ironbus scrub --data-dir /var/lib/ironbus   # read-only: report what recovery would do
```

### Dead-letter queue + crash-safe redrive

Poison messages past `--max-deliver` (default 5) are dead-lettered into a durable DLQ sink you can inspect and idempotently re-inject onto the main log — a feature NATS lacks.

```sh
ironbus dlq ls --data-dir /var/lib/ironbus
ironbus dlq peek --limit 20 --data-dir /var/lib/ironbus
ironbus dlq redrive --data-dir /var/lib/ironbus
```

### Backpressure and credit-based flow control

An auto-tuning per-connection credit window (message count + byte budget), per-group max-in-flight, CoDel sojourn control, and spill-to-disk-then-shed — producers are never blocked by default. See [docs/BACKPRESSURE.md](docs/BACKPRESSURE.md).

```sh
ironbus serve --data-dir /var/lib/ironbus --consumer-credit 2048 --consumer-credit-bytes 8388608 --max-in-flight 1024
```

### Retention: size / age / count

Three composable, consumer-safe bounds (each 0 = off) reap whole old **fully-consumed sealed** segments — never below the slowest consumer's committed offset, never the active segment. (Flag values are raw numbers; the config file additionally accepts `KiB`/`MiB`/`GiB` units.)

```sh
ironbus serve --data-dir /var/lib/ironbus \
  --max-retained-bytes 1073741824 --max-age-ms 604800000 --max-messages 1000000
```

### Compression: lz4 by default, zstd opt-in

Per-record, self-describing lz4 compression on the default path (pure Rust `lz4_flex`), transparent to every client — deliveries are decompressed before hand-off. zstd + trained dictionaries are an **opt-in build feature** (`--features zstd`) only, never on the default path (ADR-0003).

```sh
ironbus serve --data-dir /var/lib/ironbus --compression lz4   # the default, shown explicitly
```

### In-memory (ephemeral) storage backend

The same engine over an in-memory filesystem — no files, no fsync, explicitly no restart durability — for hot-path fan-out and test rigs. It refuses to boot without the explicit loss consent **and** a RAM cap (`0 = unlimited` would OOM the device, so it is rejected).

```sh
ironbus serve --storage memory --ephemeral-loss-ack --max-total-bytes 268435456
```

### Checkpoints

Crash-safe dual-slot consumer-cursor checkpointing at a configurable interval, so work-groups resume exactly where they committed after a restart or power cut.

```sh
ironbus serve --data-dir /var/lib/ironbus --checkpoint-interval 1000
```

### Offline data inspection: peek / dump

Decode the durable log and the DLQ straight from the data directory, with no broker running, bounded to one segment of memory at a time. `dump --raw` shows the on-disk frame, compression descriptor included.

```sh
ironbus peek --data-dir /var/lib/ironbus --limit 20
ironbus dump --data-dir /var/lib/ironbus --json     # NDJSON, one record per line
ironbus dump --data-dir /var/lib/ironbus --dlq      # the dead-letter sink
```

### Group and stream management + offline consumer reset

Offline management verbs over a stopped broker's data dir (they take the same exclusive lock `serve` holds, so they can never race a live writer): list/inspect/reset/purge/rm work-groups and streams, rewrite a durable cursor, redrive the DLQ. Destructive verbs refuse without `--force`.

```sh
ironbus group ls --data-dir /var/lib/ironbus
ironbus group reset orders --data-dir /var/lib/ironbus --to earliest
ironbus admin consumer-reset --data-dir /var/lib/ironbus --group orders --to latest
```

### Config file, profiles, and hot reload

A strictly-validated TOML config (`--config`; an unknown key is a **fatal error with a did-you-mean suggestion**), versioned `edge-tiny` / `balanced` / `throughput` profiles, `flag > env > file > default` precedence, and SIGHUP live-reload of the consumer-safe subset. Durations and byte sizes in the file carry required units (`8MiB`, `500ms`). See [docs/CONFIG.md](docs/CONFIG.md).

```sh
ironbus serve --data-dir /var/lib/ironbus --config /etc/ironbus/ironbus.toml --profile edge-tiny
```

### CLI ergonomics: contexts, JSON envelope, completion, cheat sheet

Named connection profiles (address + token + data-dir; the token file must be `chmod 0600` — a group- or world-readable secret is refused), a **frozen** machine-readable `ironbus.cli.v1` `--json` envelope with frozen exit codes (0 clean, 1 usage, 2 not found, 3 handled corruption, 4 corrupt data, 5 broker unreachable, 70 internal), shell completion, and a cheat sheet.

```sh
ironbus context create edge --addr 10.0.0.1:7777 --token-file /etc/ironbus/token --use
ironbus --json verify --data-dir /var/lib/ironbus
ironbus completion zsh
ironbus cheat
```

### Zero-downtime upgrade / rollback / migrate

An atomic staged binary swap (a power cut mid-upgrade leaves the old or the new binary, never a truncated one) with one-command rollback, a systemd-consulted failed-start counter, and a never-silent on-disk format migration gate.

```sh
ironbus upgrade --new-binary ./ironbus-new --dest /usr/local/bin/ironbus
ironbus rollback --dest /usr/local/bin/ironbus
ironbus migrate --data-dir /var/lib/ironbus
```

### Load generator: bench

A production-safe benchmark: by default it spawns its own **isolated** broker over a fresh throwaway data dir (it refuses to target a live broker without an explicit consent flag) and reports throughput, p50/p99/p999 latency, produce-ack RTT percentiles, and fsync cost. This is the driver the [benchmark studies](docs/benchmarks/) used.

```sh
ironbus bench --duration 30 --mode round-trip --payload-bytes 256 --pubwindow 64 --json
```

---

## Client SDKs

The wire protocol is a small, versioned, length-framed binary protocol ([docs/TRANSPORT.md](docs/TRANSPORT.md)); the official clients speak it natively — no HTTP, no protobuf.

**New to the clients?** [docs/CLIENT_SDKS.md](docs/CLIENT_SDKS.md) is the full getting-started walkthrough for both languages — connect, every produce/consume shape, transactions, subjects, auth, cluster redirects, and a capability matrix across the Rust (sync/async) and Go clients.

### Rust

Two first-party crates in this workspace, sharing every wire codec and type: [`ironbus-client`](crates/ironbus-client/) (blocking, minimal, edge-first) and [`ironbus-client-async`](crates/ironbus-client-async/) (its tokio twin — same API surface, `.await`ed). Broker-side lz4 compression is transparent in both; auth rides `ClientConfig::credential` (`AuthCredential` bearer/password). Runnable examples live in [`crates/ironbus-client/examples/`](https://github.com/ELares/IronBus/tree/main/crates/ironbus-client/examples).

```rust
use ironbus_client::Client;
use ironbus_proto::message::PubBody;

let mut client = Client::connect("127.0.0.1:7777")?;

// Produce: the returned offset means the record is fsync'd durable.
let offset = client.produce(&PubBody {
    flags: 0,
    timestamp_ms: 0,
    key: b"sensor-12",
    headers: b"",
    dedup: None,
    fire_and_forget: false,
    payload: br#"{"temp":21.4}"#,
})?;

// Consume: join a work-group, fetch a batch, ack each message.
client.subscribe("workers")?;
let fetched = client.fetch(10)?;
for m in &fetched.messages {
    client.ack(m.offset, m.generation)?;
}

// Named streams + Tier-S streaming consume (consumer-managed offsets).
client.declare_stream("events")?;
let mut consumer = client.streaming_consumer("replay");
let batch = consumer.next_batch()?;
```

The async twin is the same call surface with `.await`:

```rust
use ironbus_client_async::AsyncClient;
use ironbus_client_async::proto::PubBody;

let mut client = AsyncClient::connect("127.0.0.1:7777").await?;
let offset = client
    .produce(&PubBody {
        flags: 0,
        timestamp_ms: 0,
        key: b"key",
        headers: b"",
        dedup: None,
        fire_and_forget: false,
        payload: b"hello",
    })
    .await?;
client.subscribe("workers").await?;
let fetched = client.fetch(10).await?;
for m in &fetched.messages {
    client.ack(m.offset, m.generation).await?;
}
```

Both clients are one-connection, request-response FIFO: drive concurrency with one client per thread/task. `produce_to_leader` handles the cluster `NotLeader` redirect transparently.

### Go

The official Go SDK lives at [`sdk/go`](https://github.com/ELares/IronBus/tree/main/sdk/go) (module `github.com/ELares/IronBus/sdk/go`, [#1021](https://github.com/ELares/IronBus/issues/1021)): the same versioned wire, byte-identical framing, transparent lz4 deliveries, bearer/password auth, contexts on every call. Like the Rust clients, a `*Client` owns one connection and is used from one goroutine. Runnable examples live in [`sdk/go/examples/`](https://github.com/ELares/IronBus/tree/main/sdk/go/examples).

```go
import (
	"context"

	ironbus "github.com/ELares/IronBus/sdk/go"
)

ctx := context.Background()
client, err := ironbus.Connect(ctx, ironbus.Config{Addr: "127.0.0.1:7777"})
if err != nil { /* ... */ }
defer client.Close()

// Produce: the returned offset means the record is fsync'd durable (server ack).
offset, err := client.Produce(ctx, &ironbus.Message{
	Key:     []byte("sensor-12"),
	Payload: []byte(`{"temp":21.4}`),
})
_ = offset

// Consume: join a work-group, fetch a batch, ack each by (offset, generation).
if err := client.Subscribe(ctx, "workers"); err != nil { /* ... */ }
res, err := client.Fetch(ctx, ironbus.FetchOptions{MaxRecords: 10})
for _, m := range res.Messages {
	// handle m.Payload ...
	_, _ = client.Ack(ctx, m.Offset, m.Generation)
}
```

---

## Clustering

A real multi-node cluster ships today, behind two flags — and it degrades to the zero-config single node at n=1:

```sh
# on each of three nodes (adjust --cluster-id and the addresses):
ironbus serve --data-dir /var/lib/ironbus --cluster-id 1 \
  --cluster-peer 1=10.0.0.1:7900 --cluster-peer 2=10.0.0.2:7900 --cluster-peer 3=10.0.0.3:7900
```

What runs behind those flags (V2-C1 through V2-C7, all merged — see [docs/MISSION.md](docs/MISSION.md) §2b):

- **One KRaft-style metadata Raft group** (tikv/raft-rs) owns membership, placement, leadership epochs, and config — and nothing on the hot data path. This is explicitly **not** Raft-per-asset: no per-stream heartbeat storm, no ~2000-asset ceiling, no meta single point of failure.
- **Kafka-ISR-style per-partition pull replication** of the existing CRC-framed log: followers fetch the leader's already-framed segment byte ranges and re-validate every frame.
- **The default cluster ack is `C2-fsync`**: the wire `PubAck` is withheld until the record is `fdatasync`'d on a **quorum** — strictly stronger than NATS R3 (quorum page-cache) and Kafka `acks=all` (which trades fsync for replication), affordable because IronBus group-commits one `fdatasync` per batch on leader and followers alike.
- **Leader-epoch fencing + footer/CRC divergence self-heal**: silent replica drift and minority-corruption faults become bounded, reported, automatically repaired events (the cluster recovery invariants CI1–CI4 extend the single-node I1–I3 discipline). A produce to a non-leader returns a typed `NotLeader` redirect with a leader hint; the clients follow it.
- **Follower reads** (consume scales with replicas) and **async geo**: mirror/source links, leaf-spoke edge links, gateway federation.

Scope edges, stated plainly: replication covers the single default log today (multi-partition replication awaits the #693 partition wiring), and the cluster benchmarks are not yet CI-gated ([#636](https://github.com/ELares/IronBus/issues/636)) — the [benchmark table](#benchmarks) above is single-node only.

---

## Security

Security ([#18](https://github.com/ELares/IronBus/issues/18)) is shaped for devices on untrusted networks. What ships today, and what does not:

- **Authentication ships and is enforced**: three mechanisms (bearer token, username + Argon2id password, and mTLS — the latter wired but **inert/fails-closed** until the TLS transport lands) × three independent scopes (**publish, subscribe, admin**), configured via `--auth-config` and managed with `ironbus passwd`:

  ```sh
  ironbus passwd --auth-config /etc/ironbus/auth.toml --user alice --scopes publish,subscribe
  ironbus serve --data-dir /var/lib/ironbus --auth-config /etc/ironbus/auth.toml \
    --addr 0.0.0.0:7777 --insecure-plaintext-wire
  ```

- **TLS 1.3 is the designed transport, but it is NOT yet implemented ([#766](https://github.com/ELares/IronBus/issues/766)): the wire is plaintext today.** No TLS stack is linked, and any `--tls-*` material is reserved and refused at startup (the broker will not boot with it set). A **non-loopback bind is therefore an explicit decision**: `--insecure-plaintext-wire` is the loud opt-in for running auth-on-plaintext beyond loopback — for TLS-terminated-upstream, service-mesh, or VPN/WireGuard patterns. Without it, keep the broker on loopback or behind a tunnel.
- **Encryption at rest is designed but NOT yet built** ([#780](https://github.com/ELares/IronBus/issues/780)) — no AEAD provider is linked; the on-disk format reserves a nonce and an at-rest flag for AES-256-GCM / ChaCha20-Poly1305, but data on disk is unencrypted today.
- **Fail-closed secret handling**: IronBus refuses to start (and `passwd`/`context` refuse to read) if a secret-bearing file is group- or world-readable — `chmod 0600` your token and password files.
- **Pre-auth DoS defenses**: half-open connection caps, per-source connection rate limits, and failed-auth lockout, so a handshake flood cannot exhaust a small device; plus graceful drain (SIGTERM flips readiness, lets in-flight work finish) and a secret-free audit stream.

---

## Resilience: designed for failure first

Resilience is the top tenet, so failure is planned, not patched. Every subsystem carries a failure-mode and mitigation matrix, aggregated into a [consolidated FMEA (#129)](https://github.com/ELares/IronBus/issues/129); the invariants every subsystem must uphold are tracked in [shared invariants and glossary (#131)](https://github.com/ELares/IronBus/issues/131):

- No acknowledged write is ever lost below its configured durability level.
- Recovery never reads past a torn or partially written tail record.
- Loss from a corruption skip is bounded (at most one segment or 64 MiB per event, at most 1 percent of durable bytes per recovery) and is always reported, never silent and never partial within a record.
- The log preserves a single total durable order.

Concretely, IronBus treats a failed `fsync` as fatal and freezes the writer read-only (the PostgreSQL fsyncgate lesson), checksums every record so a flipped bit on an SD card is caught on read, quarantines unreadable segments by copy rather than move into a capped store, and resynchronizes to the next valid record boundary so one bad region does not poison the rest of the log. And recovery is not only automatic — it is a **first-class operator feature**: `verify` (offline fsck), `repair` (explicit, locked, plan-first), `backup` / `restore` (point-consistent, manifest-validated), and `scrub` (read-only scan) make every recovery path inspectable and drivable on demand (see the [feature tour](#recovery-as-a-feature-verify--repair--backup--restore)).

These claims are not taken on faith. Verification ([#21](https://github.com/ELares/IronBus/issues/21)) is built around a bespoke, in-tree deterministic simulation (a single seeded PRNG threaded through every IO, clock, and scheduling decision) so a power cut can be replayed bit for bit. Five crash classes are hard release gates: `kill -9`, simulated power cut with write reordering, a one-shot `fsync` error, and block-layer fault injection for dropped writes and per-block read errors. Every pull request runs a 256-seed sweep, the record and segment parsers are continuously fuzzed, a tiered corpus of deliberately corrupted files is asserted on, and a sim-versus-real conformance gate on a reference edge device keeps the simulation honest.

---

## The CLI

The same binary that runs the broker is the CLI, in the spirit of the NATS CLI but with a real view into the stored data. The shipped verbs, grouped:

- **Interact**: `pub`, `sub`, `cumulative-ack`, and `bench` (the production-safe load generator).
- **Observe**: `top` (live TUI or offline file-derived view), `report groups|streams|storage|recovery|connections`, `server info|healthz|ready|check`, and the read-only `admin` snapshot.
- **Recover**: `verify`, `repair`, `backup`, `restore`, `scrub` — the [recovery-as-a-feature](#recovery-as-a-feature-verify--repair--backup--restore) set.
- **Inspect offline**: `peek`, `dump` (`--json`, `--dlq`, `--raw`), straight from the data directory with no broker running.
- **Manage**: `group ls|info|reset|purge|rm`, `stream ls|info|create|bind|purge|rm`, `dlq ls|peek|redrive`, `admin consumer-reset|dlq-redrive`, `passwd`.
- **Operate**: `upgrade`, `rollback`, `record-start`, `migrate`.
- **Ergonomics**: `context` (named connection profiles), `completion`, `cheat`, and the global `--json` flag — one frozen `ironbus.cli.v1` envelope per command, with frozen exit codes, safe to script against forever.

Every command speaks human-readable output by default and `--json` for machines. The full contract is [docs/CLI.md](docs/CLI.md) and [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md).

---

## How it works

The data path is deliberately short. A producer sends a record. A single append actor frames and checksums it, appends it to the active log segment, group-commits an `fdatasync`, and only then acknowledges. The active segment **is** the write-ahead log: there is no separate WAL file to keep in sync. Sealed segments are served to many consumers through a derived offset index that is rebuilt from the log on startup. Every record on disk carries a CRC32C, so corruption is always caught, and every recovery path is bounded and reported.

```
producer ─▶ wire protocol ─▶ ring buffer + credit-based backpressure
                                   │  single append actor, monotonic u64 offsets
                                   ▼
              active log segment, CRC32C framed  (this IS the WAL)
                                   │  group-commit fdatasync, then ack
                                   ▼
              sealed segments  +  derived offset / time index
                                   │
   many consumers ◀─ leases, acks, redelivery, DLQ ─▶ dead-letter queue
                                   │
   corruption found ─▶ skip record / quarantine segment ─▶ bounded, reported loss
```

### Subsystems (each is a design issue)

| Area | Issue | What it covers |
| --- | --- | --- |
| Queue semantics | [#3](https://github.com/ELares/IronBus/issues/3) | Single ordered log, many consumers, at-least-once, ordering guarantees, opt-in dedup |
| Storage engine | [#4](https://github.com/ELares/IronBus/issues/4) | Append-only segmented log (the active segment is the WAL), derived indexes, directory layout |
| Record format | [#5](https://github.com/ELares/IronBus/issues/5) | On-disk byte framing, CRC32C, record-aligned layout, torn-write detection, versioning |
| Durability | [#6](https://github.com/ELares/IronBus/issues/6) | `fsync` strategy, group commit, ack contract, power-loss guarantees |
| Crash recovery | [#7](https://github.com/ELares/IronBus/issues/7) | Startup replay, torn-tail truncation, index rebuild, longest-valid-prefix |
| Corruption skip | [#8](https://github.com/ELares/IronBus/issues/8) | Detect, skip, quarantine, resync, bounded and reported loss |
| Consumer model | [#9](https://github.com/ELares/IronBus/issues/9) | Cursors, groups, acks, redelivery, visibility timeout, dead-letter queue |
| Backpressure | [#10](https://github.com/ELares/IronBus/issues/10) | Credit-based flow control, spill-to-disk, overflow policy, load shedding |
| Wire protocol | [#11](https://github.com/ELares/IronBus/issues/11) | Length-framed binary protocol, verbs, capability negotiation |
| Compression | [#12](https://github.com/ELares/IronBus/issues/12) | lz4_flex default (pure Rust), per-record self-describing descriptor; zstd and trained dictionaries opt-in behind the `zstd` feature, never on the default path (#139, ADR-0003) |
| Retention | [#13](https://github.com/ELares/IronBus/issues/13) | Time, size, and count retention, whole-segment deletion, lifecycle |
| Configuration | [#14](https://github.com/ELares/IronBus/issues/14) | Layered config, hot reload, profiles, safe zero-config defaults |
| CLI | [#15](https://github.com/ELares/IronBus/issues/15) | pub, sub, bench, offline data inspection, scrub, live TUI, management verbs |
| Observability | [#16](https://github.com/ELares/IronBus/issues/16) | Prometheus metrics, tracing, health, structured introspection |
| Build and distribution | [#17](https://github.com/ELares/IronBus/issues/17) | Single static binary, cross-compilation, packaging, supply chain |
| Security | [#18](https://github.com/ELares/IronBus/issues/18) | AuthN and authZ, TLS, encryption at rest, edge threat model |
| Performance | [#19](https://github.com/ELares/IronBus/issues/19) | SLO targets, benchmark methodology, regression gating |
| Edge constraints | [#20](https://github.com/ELares/IronBus/issues/20) | Flash wear, RAM ceilings, fsync cost, brownout behavior |
| Verification | [#21](https://github.com/ELares/IronBus/issues/21) | Crash injection, fuzzing, property tests, deterministic simulation |
| Governance | [#22](https://github.com/ELares/IronBus/issues/22) | License, repo structure, RFC process, versioning |

---

## Key decisions already committed

A fresh-eyes second pass over every issue resolved over one hundred design questions across the 22 subsystem issues. The headline decisions that define the product:

| Question | Decision |
| --- | --- |
| Logical scope | Multi-stream + subjects + wildcards over one node today; partitions are the remaining v2 item (#693, see [docs/MISSION.md](docs/MISSION.md)). A KV store and an object store are non-goals (IronBus stays a pure message bus). |
| Delivery contract | At-least-once, pull-based in v1. SQS-style visibility-timeout leases (default 30s, hard cap 5 minutes), persisted redelivery count, default max-deliver 5, then dead-letter queue. |
| Ordering | Total durable order of the log. Per-group at-least-once, not per-group strict in-order delivery. Exactly-once is a non-goal. |
| Storage model | Log-is-WAL: a publish is one framed, checksummed, record-aligned append to the active segment, and that append is the durable record. No separate WAL file. The offset index is derived and rebuildable. |
| Durability default | Group-committed `fdatasync` of the active log before ack. The commit thread syncs whatever appends arrived during the previous sync (cap 1 MiB, no proactive linger by default). Levels (`--durability-level`): `sync` (default, ack-after-`fdatasync`, I2, zero acked loss), `interval` (bounded by the flush window), `async`/`none` (relaxed, gated behind `--async-loss-ack`). |
| Checksum | CRC32C (Castagnoli) on every record, using the hardware instruction with a software fallback. Payloads over 64 KiB carry a second independent xxh3-64 checksum. CRC32C gates resync. |
| Record and segment sizes | Default max record 16 MiB (hard cap, configurable up to 1 GiB), 64 MiB segments (8 MiB on the edge profile). A record never spans two segments. |
| Backpressure | Credit-based pull (auto-tuning window, default ceiling 2048 messages / 8 MiB in-flight per connection). Durable topics spill to disk then shed (drop_new past the spill cap, always reported); telemetry topics drop_oldest. `block` is opt-in only, never a default. CoDel sojourn control plus a hard depth backstop. |
| Dedup | Off by default. Opt-in per-producer window (100,000 ids or 2 minutes). An optional stable producer-id and epoch persists the high-watermark so dedup survives a restart and an arbitrarily long offline gap. |
| Bounded loss report | After any skip, report (records_lost, bytes_lost, segments_affected) plus the offset range and a reason enum, via a log line, a recovery report file, and a Prometheus counter. Loss is capped at one segment or 64 MiB per event and 1 percent of durable bytes per recovery; exceeding either freezes the log read-only and alerts. |
| Runtime | tokio (multi-threaded), with the durability commit on a dedicated thread. io_uring is a deferred, feature-flagged, Linux 5.10 and newer optimization, never the foundation, to protect the Cross Platform tenet. |
| Targets | First-class: aarch64, x86_64, armv7 musl static binaries, kernel floor Linux 4.19. Best-effort, CI-built: macOS. Windows is a non-goal for v1. |
| Replication | A real multi-node cluster ships today (metadata Raft + leader/follower ISR pull replication, `fsync`'d-on-a-quorum ack default, leader-epoch fencing, divergence self-heal) behind `--cluster-id / --cluster-peer`, preserving the single-node durability/recovery/edge guarantees. Default-log replication today; multi-partition awaits #693 and the cluster benchmarks are not yet CI-gated (#636) — see [docs/MISSION.md](docs/MISSION.md). |
| License | Dual `MIT OR Apache-2.0` across the whole workspace. |
| MSRV | Rust 1.78, may rise only in a minor release, new floor always at least 6 months old. |

The full, immutable record of these decisions lives in the [ADR index (#130)](https://github.com/ELares/IronBus/issues/130) and as ADR files as they are ratified.

---

## What is NOT shipped: the roadmap, and the non-goals

The honesty section, mirroring [docs/MISSION.md](docs/MISSION.md) §2c — everything here is genuinely not built and is marked as such everywhere it appears:

| Not built yet | Tracking | Note |
| --- | --- | --- |
| Partitions through the engine | [#693](https://github.com/ELares/IronBus/issues/693) | Partition math exists in storage only; not wired through engine/wire/CLI. Cluster replication covers the single default log until this lands. |
| TLS 1.3 / mTLS transport | [#766](https://github.com/ELares/IronBus/issues/766) | The wire is plaintext today; `--tls-*` material is refused at startup; the mTLS auth mechanism is inert (fails closed) until this lands. |
| Encryption at rest | [#780](https://github.com/ELares/IronBus/issues/780) | No AEAD provider linked; the on-disk format reserves the fields. |
| Priorities / delayed messages / request-reply RPC | [#553](https://github.com/ELares/IronBus/issues/553) / [#555](https://github.com/ELares/IronBus/issues/555) / [#764](https://github.com/ELares/IronBus/issues/764) | The V2-M4 routing-richness set. (Per-message TTL enforcement exists in the engine; its operator surface is open, [#710](https://github.com/ELares/IronBus/issues/710).) |
| OpenTelemetry tracing | [#770](https://github.com/ELares/IronBus/issues/770) | The one observability gap — metrics, health, histograms, and recovery counters did ship. |
| Named-stream consume parity | [#681](https://github.com/ELares/IronBus/issues/681) | DLQ / key-shared / Tier-S / metrics on **named** streams — in progress; the default log has it all. |
| Tiered storage (post-1.0) | [#643](https://github.com/ELares/IronBus/issues/643) | Offloading cold sealed segments to object storage — core log infrastructure, distinct from an object store. |
| CI-gated cluster benchmarks | [#636](https://github.com/ELares/IronBus/issues/636) | The cluster code ships; the head-to-head cluster benches and the 3-node edge-fit run are open. |

And the **permanent non-goals**, deliberately never built: exactly-once (at-least-once is the contract; effectively-once via the idempotent producer), a KV store, an object store, a Kafka wire-protocol clone, and Windows in v1. zstd stays an opt-in build feature, never the default codec.

---

## How this repository is organized

The design came first and still anchors the code: issues [#3](https://github.com/ELares/IronBus/issues/3)–[#22](https://github.com/ELares/IronBus/issues/22) are the 20 vetted subsystem designs, [#1](https://github.com/ELares/IronBus/issues/1) is the vision EPIC and index, and [#2](https://github.com/ELares/IronBus/issues/2) is the comparative prior-art analysis. The implementation now lives in a small Rust workspace built from those designs:

- `crates/ironbus-core` — I/O-free types and logic; `crates/ironbus-storage` — the segmented log; `crates/ironbus-proto` — the frozen wire codecs; `crates/ironbus-server` — the broker; `crates/ironbus-client` / `crates/ironbus-client-async` — the Rust clients; `crates/ironbus-cli` — the CLI; `crates/ironbus-bench` — bench internals; `sdk/go` — the Go SDK.
- `docs/` — the contracts (durability, recovery, invariants, config, CLI, transport, mission) plus [docs/benchmarks/](docs/benchmarks/) for the measured studies; `fuzz/` — the fuzz targets; `scripts/ci/` — the CI gates (including the docs link-integrity checks).
- Meta issues tie it together: [consolidated FMEA (#129)](https://github.com/ELares/IronBus/issues/129), [ADR index (#130)](https://github.com/ELares/IronBus/issues/130), [invariants and glossary (#131)](https://github.com/ELares/IronBus/issues/131), [compatibility and versioning policy (#132)](https://github.com/ELares/IronBus/issues/132), and the [golden-path acceptance scenario (#133)](https://github.com/ELares/IronBus/issues/133).

Browse by [milestone](https://github.com/ELares/IronBus/milestones) or by [label](https://github.com/ELares/IronBus/labels) (for example `area:storage`, `area:recovery`, `area:backpressure`, or `sub-issue`).

---

## Project status and how to get involved

The architecture was vetted in the design issues before code began, and the implementation is now broad: the durable single-node broker, multi-stream + subjects + wildcards, the multi-node cluster, idempotent + transactional produce, auth, and the full observability/recovery tooling are merged, each landed as a small, reviewed, CI-gated pull request. The best ways to help right now: challenge the design decisions (every decision states the alternative it rejected and why, so disagreement is easy to ground), reproduce the [benchmarks](#benchmarks) (the harness is in the repo), and kick the tires on the [feature tour](#feature-tour) against your own edge hardware.

Releases are reproducible, signed (cosign keyless plus an offline signature), and shipped with an embedded SBOM and a fail-closed verifying installer. Contribution, security, and code-of-conduct policies are defined in the [governance issue (#22)](https://github.com/ELares/IronBus/issues/22) and [CONTRIBUTING.md](CONTRIBUTING.md), including a Developer Certificate of Origin sign-off, a Contributor Covenant code of conduct, and private security disclosure through GitHub Security Advisories.

---

## License

IronBus is dual-licensed under your choice of [MIT](https://opensource.org/license/mit) or [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), as decided in the [governance issue (#22)](https://github.com/ELares/IronBus/issues/22). See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
