# IronBus design diagrams

This directory holds the architecture and design diagrams for IronBus, rendered as PDFs. They are a visual companion to the design issues; the GitHub issues remain the canonical, authoritative design record. Each diagram is committed both as a Graphviz source (`.dot`) and a rendered `.pdf`, so anyone can regenerate them.

For the byte-level data-model reference (the on-disk, wire, config, runtime, and report contracts derived from and cross-checked against the source), see [CONTRACTS.md](CONTRACTS.md).

Regenerate all PDFs:

```sh
cd docs/diagrams
for f in *.dot; do dot -Tpdf "$f" -o "${f%.dot}.pdf"; done
```

## Diagrams

| # | Diagram | What it shows | Primary issues |
| --- | --- | --- | --- |
| 01 | [System architecture](diagrams/01-architecture.pdf) | The broker, clients, and on-disk data directory, and how a record flows from producer to durable log to consumers | #1, #4 |
| 02 | [Publish data path](diagrams/02-publish-path.pdf) | The eight steps of a publish and the durability boundary (ack only after the covering fdatasync) | #6 |
| 03 | [Crash recovery flow](diagrams/03-recovery-flow.pdf) | Longest-valid-prefix startup recovery, torn-tail truncation, corruption skip, and the bounded-loss freeze | #7, #8 |
| 04 | [On-disk record and segment layout](diagrams/04-record-layout.pdf) | The frozen v1 byte format: record frame (36-byte header), trailer, segment header and footer | #5 |
| 05 | [Consumer delivery state machine](diagrams/05-consumer-state-machine.pdf) | Message states under at-least-once leases: available, in-flight, acked, redelivery, DLQ, parked | #9 |
| 06 | [WAL and segment lifecycle](diagrams/06-wal-segment-lifecycle.pdf) | How the log-is-WAL files are sealed, retained, and retired, and which background actor owns each step | #135, #4, #7, #13, #10 |
| 07 | [CLI command tree](diagrams/07-cli-command-tree.pdf) | The full command surface of the single binary, color-coded by online versus offline | #136, #15 |
| 08 | [Contract models](diagrams/08-contract-models-er.pdf) | The on-disk, wire, config, runtime, and report schemas and their relationships | #137, #5, #11 |

## Reference docs

- [CLI reference map](CLI.md): the exhaustive command-surface map of the `ironbus` binary, every subcommand, every flag (type, default, unit), every exit code, and online versus offline, each default cited to the `main.rs` constant. The complementary flag-and-exit-code table to the prose guide in [USAGE.md](USAGE.md) (#136).
- [Invariants and glossary](INVARIANTS.md): the shared invariants every subsystem must hold (I1 to I8), the resilience invariant checkers, and the canonical glossary of load-bearing terms, each cross-checked against the code (#131).
- [Metrics and the resilience-observability contract](METRICS.md): the normative catalog of every `/metrics` counter and gauge, and the contract that every shed, drop, skip, dead-letter, truncation, force-reap, and recovery-loss event increments a stable-named, documented counter so no resilience event is ever silent and the taxonomy can never silently drift, pinned by a frozen-taxonomy test (#96, #16).
- [Contract models](CONTRACTS.md): the on-disk, wire, config, runtime, and report byte-level schemas, derived from and cross-checked against the source (#137).
- [The `ironbus.loss-report.v1` schema](schemas/loss-report.v1.md): the versioned, externally-frozen recovery loss-report schema (every `LossReport`/`LossEvent` field and type, the stable `ReasonCode` integer values and JSON names, the bounded-loss caps, and the golden tests that freeze the JSON shape so a field rename or reason-code renumber is a CI failure), cross-referenced from CONTRACTS.md (#120, #21).
- [The WAL under load and the on-disk file lifecycle](WAL.md): how the active-segment-is-the-WAL model absorbs a high write rate (segment roll, the O(1) running totals, the shed/drop-oldest overflow policy), the on-disk file classes and their lifecycle (active and sealed `.log`, the cursor checkpoints, the `dlq/` sink), recovery under a crash mid-write, the knobs, and what #135 specifies but the code does not yet implement (#135).
- [Threat model and security posture](THREAT_MODEL.md): the enumerated edge threat model, the implemented DoS and resource-exhaustion mitigations cited to the code, and an honest statement of the current no-auth / no-TLS / no-at-rest-encryption posture versus the specified controls (#106 to #109), each cross-checked against the source (#105).
- [Compatibility and versioning](COMPATIBILITY.md): the on-disk-format and wire-protocol compatibility rules, each citing the code mechanism that enforces it (the frozen-tag tests, typed unknown-tag handling, the version and checksum_algo refuse-on-unknown, the unknown-flag-bit preservation, the never-recycle id rule, reaped-prefix recovery), the version registry and SemVer/MSRV policy state, and a clearly-marked list of the negotiation and migration features that are specified but absent, cross-checked against the source (#132, #126).
- [Architecture decision records](adr/README.md) and the [ADR index](adr/INDEX.md): the numbered in-tree decision records (log-is-WAL, segments never recycled, lz4_flex default) plus a flat catalog of every resolved design decision with its status and owning issue, marking which decisions still lack a numbered ADR file (#130, #125).
- [Design risk register](RISK_REGISTER.md): the adversarial flaw-hunt over the shipped design, a register of failure modes by category (durability, concurrency, resource-exhaustion/DoS, recovery, observability, security, operational, performance), each marked MITIGATED with the cited mechanism and test, FIXED with the real merged fix, or OPEN with its tracking issue; includes the record of real defects the review process caught (the #240 recovery cursor-drop, the #283 empty-key over-serialization, the #279 macro-bench crash, the #289 serve-flag parse loop, the #96 uncounted truncation, the #301 Windows build break) and the honest open-risk list (no auth #106 / TLS #107 / at-rest encryption #108, the single-Mutex head-of-line block, non-durable counters #98, no loom #122). The post-implementation complement to the design-time hunt in #138 (#138).
- [Edge tuning: the hardware constraint to knob mapping](EDGE_TUNING.md): the operator-facing table that maps each edge hardware constraint (limited RAM and the 64 MiB ceiling, flash wear / slow storage, limited CPU, intermittent power) to the specific shipped `serve` knob(s) that honor it, with a recommended edge value and the reasoning, every value cited to a real flag in CLI.md. States honestly that these are RECOMMENDED MANUAL settings, not an auto-selected profile (there is no `--profile` flag; `EDGE_SEGMENT_BYTES` is unwired, you get 8 MiB only via `--max-segment-bytes 8388608`), and cross-references the #115 RAM-budget and #87 profile-selection follow-ups. Cross-references CLI.md, WAL.md, SLO.md, and THREAT_MODEL.md; docs only (#117, #19).
- [Service-level objectives](SLO.md): the SLO target table (throughput msg/s and MB/s, p50/p99/p99.9 latency, steady-state RAM ceiling, write amplification) tied to the metrics the macro-bench harness (`crates/ironbus-bench/`, #111) actually emits, with each target quoted from the README or #19 / #110 and marked honestly as a STATED TARGET, not yet ratified against a measured baseline, plus the ratification process (run #111 on the reference device, archive the provenance, version the table) and a not-yet-measured disclaimer; the live coordinated-omission self-test is `#[ignore]`d on shared CI (#284) so no measured baseline is committed (#110, #19).

## Notes

- The diagrams reflect the frozen v1 model: log-is-WAL (the active segment is the write-ahead log), single durable queue, at-least-once delivery with visibility-timeout leases, and bounded, reported loss on corruption.
- Where a design decision is still open (for example v2 segment recycling), the diagram marks it as deferred rather than implying it is settled. The open decisions are tracked in the coherence audit issue (#139).
