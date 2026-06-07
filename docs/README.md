# IronBus design diagrams

This directory holds the architecture and design diagrams for IronBus, rendered as PDFs. They are a visual companion to the design issues; the GitHub issues remain the canonical, authoritative design record. Each diagram is committed both as a Graphviz source (`.dot`) and a rendered `.pdf`, so anyone can regenerate them.

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

- [Invariants and glossary](INVARIANTS.md): the shared invariants every subsystem must hold (I1 to I8), the resilience invariant checkers, and the canonical glossary of load-bearing terms, each cross-checked against the code (#131).

## Notes

- The diagrams reflect the frozen v1 model: log-is-WAL (the active segment is the write-ahead log), single durable queue, at-least-once delivery with visibility-timeout leases, and bounded, reported loss on corruption.
- Where a design decision is still open (for example v2 segment recycling), the diagram marks it as deferred rather than implying it is settled. The open decisions are tracked in the coherence audit issue (#139).
