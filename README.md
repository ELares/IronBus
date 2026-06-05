# IronBus

**A single durable, crash-safe message queue for the edge, in one static Rust binary.**

> Status: planning and design. This repository is intentionally code-free. The entire product is being designed in the open, as GitHub issues, before a single line of product code is committed. Start at the [vision EPIC (#1)](https://github.com/ELares/IronBus/issues/1).

IronBus is one durable, ordered queue (think a single AWS SQS queue) that lives on the device, survives power loss and corrupt files on its own, and fans out to many consumers. It ships as a single static binary you can drop onto a Raspberry Pi. It takes the best small, composable ideas from MQTT, NATS, Kafka, Pulsar, Redpanda, RocksDB, Redis Streams, and SQS, and leaves behind the operational weight and the silent durability footguns that do not survive a battery-less edge node.

---

## Why IronBus exists

Every existing broker is wrong for a resilient single-topic edge workload in a different way, and each wrongness maps to one of our tenets:

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
| **Simple** | One logical queue, one binary, one config file with safe defaults, a tiny length-framed wire protocol you can drive with netcat. Install to first message in under a minute. No ZooKeeper, no JVM, no external dependencies. |
| **Resilient** | Every acknowledged durable write survives power loss. Startup always recovers a consistent prefix. A torn tail or a poison record or segment is skipped, never fatal, with loss bounded and reported as a number. |
| **HyperScale** | High per-core throughput on edge hardware (not horizontal scale-out): a bounded ring-buffer core with structural backpressure, group-commit `fdatasync`, and zero-copy fan-out, sustaining tens of thousands of small messages per second per core. |
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

**IronBus v1 is explicitly NOT (these are committed non-goals):**

- Not multi-topic, not partitions, not subjects, and not a routing fabric. Multiple independent queues are achieved by running multiple instances. Multi-topic-in-one-log is deferred to a later version.
- Not replicated. v1 is single-node durable. No quorum, no leader election. Replication is reserved for a post-1.0 milestone and the version scheme leaves room for it.
- Not exactly-once. At-least-once is the contract, with an optional fire-and-forget fast path. No exactly-once handshake.
- Not a Kafka wire-protocol clone, and not a Windows product in v1 (Windows fsync and path semantics differ enough to threaten the durability guarantee).

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
| Compression | [#12](https://github.com/ELares/IronBus/issues/12) | zstd default, per-batch, lz4 fallback, dictionaries deferred to a later milestone |
| Retention | [#13](https://github.com/ELares/IronBus/issues/13) | Time, size, and count retention, whole-segment deletion, lifecycle |
| Configuration | [#14](https://github.com/ELares/IronBus/issues/14) | Layered config, hot reload, profiles, safe zero-config defaults |
| CLI | [#15](https://github.com/ELares/IronBus/issues/15) | pub, sub, bench, info, lag, offline data inspection, scrub, live TUI |
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
| Logical scope | One durable ordered queue per instance. No partitions or subjects in v1. |
| Delivery contract | At-least-once, pull-based in v1. SQS-style visibility-timeout leases (default 30s, hard cap 5 minutes), persisted redelivery count, default max-deliver 5, then dead-letter queue. |
| Ordering | Total durable order of the log. Per-group at-least-once, not per-group strict in-order delivery. Exactly-once is a non-goal. |
| Storage model | Log-is-WAL: a publish is one framed, checksummed, record-aligned append to the active segment, and that append is the durable record. No separate WAL file. The offset index is derived and rebuildable. |
| Durability default | Group-committed `fdatasync` of the active log before ack. The commit thread syncs whatever appends arrived during the previous sync (cap 1 MiB, no proactive linger by default). Modes: `fdatasync` (default), `interval`, and `none` (gated behind an explicit data-loss acknowledgement). |
| Checksum | CRC32C (Castagnoli) on every record, using the hardware instruction with a software fallback. Payloads over 64 KiB carry a second independent xxh3-64 checksum. CRC32C gates resync. |
| Record and segment sizes | Default max record 16 MiB (hard cap, configurable up to 1 GiB), 64 MiB segments (8 MiB on the edge profile). A record never spans two segments. |
| Backpressure | Credit-based pull (default 64 messages or 8 MiB in-flight per consumer). Durable topics spill to disk then shed (drop_new past the spill cap, always reported); telemetry topics drop_oldest. `block` is opt-in only, never a default. CoDel sojourn control plus a hard depth backstop. |
| Dedup | Off by default. Opt-in per-producer window (100,000 ids or 2 minutes). An optional stable producer-id and epoch persists the high-watermark so dedup can survive a restart and an arbitrarily long offline gap. |
| Bounded loss report | After any skip, report (records_lost, bytes_lost, segments_affected) plus the offset range and a reason enum, via a log line, a recovery report file, and a Prometheus counter. Loss is capped at one segment or 64 MiB per event and 1 percent of durable bytes per recovery; exceeding either freezes the log read-only and alerts. |
| Runtime | tokio (multi-threaded), with the durability commit on a dedicated thread. io_uring is a deferred, feature-flagged, Linux 5.10 and newer optimization, never the foundation, to protect the Cross Platform tenet. |
| Targets | First-class: aarch64, x86_64, armv7 musl static binaries, kernel floor Linux 4.19. Best-effort, CI-built: macOS. Windows is a non-goal for v1. |
| Replication | Out of scope for v1. Single-node durable only. |
| License | Dual `MIT OR Apache-2.0` across the whole workspace. |
| MSRV | Rust 1.78, may rise only in a minor release, new floor always at least 6 months old. |

The full, immutable record of these decisions will live in an [ADR index (#130)](https://github.com/ELares/IronBus/issues/130) and as `rfcs/NNNN-slug.md` files once the code-free phase ends.

---

## Resilience: designed for failure first

Resilience is the top tenet, so failure is planned, not patched. Every issue carries a failure-mode and mitigation matrix, and they are aggregated into a [consolidated FMEA (#129)](https://github.com/ELares/IronBus/issues/129). The invariants every subsystem must uphold are tracked in [shared invariants and glossary (#131)](https://github.com/ELares/IronBus/issues/131):

- No acknowledged write is ever lost below its configured durability level.
- Recovery never reads past a torn or partially written tail record.
- Loss from a corruption skip is bounded (at most one segment or 64 MiB per event, at most 1 percent of durable bytes per recovery) and is always reported, never silent and never partial within a record.
- The log preserves a single total durable order.

Concretely, IronBus treats a failed `fsync` as fatal and freezes the writer read-only (the PostgreSQL fsyncgate lesson), checksums every record so a flipped bit on an SD card is caught on read, quarantines unreadable segments by copy rather than move into a capped store, and resynchronizes to the next valid record boundary so one bad region does not poison the rest of the log.

These claims are not taken on faith. Verification ([#21](https://github.com/ELares/IronBus/issues/21)) is built around a bespoke, in-tree deterministic simulation (a single seeded PRNG threaded through every IO, clock, and scheduling decision) so a power cut can be replayed bit for bit. Five crash classes are hard release gates: `kill -9`, simulated power cut with write reordering, a one-shot `fsync` error, and block-layer fault injection for dropped writes and per-block read errors. Every pull request runs a 256-seed sweep, the record and segment parsers are continuously fuzzed, a tiered corpus of deliberately corrupted files is asserted on, and a sim-versus-real conformance gate on a reference edge device keeps the simulation honest.

---

## Secure by default

Security ([#18](https://github.com/ELares/IronBus/issues/18)) is shaped for devices on untrusted networks:

- **TLS 1.3 only**, and it is mandatory on any non-loopback bind. Plaintext is allowed solely on the loopback interface. There is no insecure-network opt-in flag at all. The binary carries its own modern TLS stack, so the oldest target platform still gets TLS 1.3.
- **Three explicit scopes**: publish, subscribe, admin. Auth is by bearer token, username and password (Argon2id, edge-tuned), or mTLS, which is the recommended mechanism for untrusted LANs.
- **Safe by default**: IronBus refuses to start if a secret-bearing file is group or world readable, and ships bounded pre-auth defenses (half-open connection caps, per-source connection rate limits, failed-auth backoff) so a handshake flood cannot exhaust a small device.
- Optional **encryption at rest** with AES-256-GCM or ChaCha20-Poly1305, selected by runtime CPU feature detection.

---

## The CLI you actually want

The same binary that runs the broker is the CLI, in the spirit of the NATS CLI but with a real view into the stored data:

- `pub` and `sub` for quick interaction, `bench` for load generation.
- `info`, `consumer ls`, and `lag` for live state.
- `peek` and `dump` to decode and display stored records straight from the data directory, even with no server running.
- `repair` and `scrub` to drive corruption recovery on demand.
- `top`, a live TUI showing throughput, lag, fsync latency, backpressure, and corruption events.

Every command speaks human-readable output by default and `--json` for scripting.

---

## Performance targets

Performance ([#19](https://github.com/ELares/IronBus/issues/19)) is measured, not asserted. The provisional marquee target is 256-byte messages, a single consumer, durable group-commit `fdatasync`, sustaining at least 60,000 messages per second with p99 latency under 6 ms on a Raspberry Pi 4. Every published SLO is a measured floor (the on-device p99 minus a 20 percent margin), recorded with an HdrHistogram against a single monotonic clock, and gated against regression on a rolling baseline.

---

## Roadmap

Work is grouped into three milestones. The design issues come first because no code is written until the design is vetted.

- **M0: Vision and Scope.** The problem, the tenets, the committed scope and non-goals, the prior-art evidence base, the invariants, and the ADR index.
- **M1: Architecture Specification.** Vetted specs for every core subsystem: semantics, storage, record format, durability, recovery, corruption skip, consumers, backpressure, protocol, compression, retention, configuration, and the CLI.
- **M2: Prototype-Ready Design.** The cross-cutting concerns that gate coding: observability, build and distribution, security, performance, edge constraints, verification, governance, and the end-to-end golden-path acceptance scenario.

---

## How this repository is organized

This is a documentation-first project. The backlog is the design.

- **[#1](https://github.com/ELares/IronBus/issues/1)** is the vision EPIC and the index of everything.
- **[#2](https://github.com/ELares/IronBus/issues/2)** is the comparative prior-art analysis (what we borrow and reject).
- **[#3](https://github.com/ELares/IronBus/issues/3) through [#22](https://github.com/ELares/IronBus/issues/22)** are the 20 subsystem design issues.
- Each design issue carries a fresh-eyes review comment (resolved decisions, gaps, and a failure-mode matrix) and is broken into smaller `[TASK]` sub-issues with a tracked checklist in its body.
- **Meta issues** tie it together: [consolidated FMEA (#129)](https://github.com/ELares/IronBus/issues/129), [ADR index (#130)](https://github.com/ELares/IronBus/issues/130), [invariants and glossary (#131)](https://github.com/ELares/IronBus/issues/131), [compatibility and versioning policy (#132)](https://github.com/ELares/IronBus/issues/132), and the [golden-path acceptance scenario (#133)](https://github.com/ELares/IronBus/issues/133).

Browse by [milestone](https://github.com/ELares/IronBus/milestones) or by [label](https://github.com/ELares/IronBus/labels) (for example `area:storage`, `area:recovery`, `area:backpressure`, or `sub-issue`).

---

## Project status and how to get involved

IronBus is in the planning and documentation phase. There is no code yet, by design, so that the architecture is vetted before it is built. The best way to help right now is to read the design issues and challenge the decisions: every decision states the alternative it rejected and why, so disagreement is easy to ground.

The planned shape of the codebase (to be ratified by the first RFC, not yet committed) is a small Rust workspace: `ironbus-core` (I/O-free types and logic), `ironbus-storage`, `ironbus-proto`, `ironbus-server`, `ironbus-client`, and `ironbus-cli`. Releases are planned to be reproducible, signed (cosign keyless plus an offline signature), and shipped with an embedded SBOM and a fail-closed verifying installer. Contribution, security, and code-of-conduct policies are defined in the [governance issue (#22)](https://github.com/ELares/IronBus/issues/22), including a Developer Certificate of Origin sign-off, a Contributor Covenant code of conduct, and private security disclosure through GitHub Security Advisories.

---

## License

IronBus will be dual-licensed under your choice of [MIT](https://opensource.org/license/mit) or [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), as decided in the [governance issue (#22)](https://github.com/ELares/IronBus/issues/22). The license files will be added with the first code.
