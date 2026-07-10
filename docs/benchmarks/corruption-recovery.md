<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Corruption-recovery head-to-head: IronBus vs NATS JetStream

The [#644](https://github.com/ELares/IronBus/issues/644) (V2-M12) benchmark: **demonstrate,
not assert**, the recovery differentiator by injecting the same four classes of on-disk
corruption into both brokers' file stores and recording what each one actually does. The four
classes reproduce failure modes reported against the NATS JetStream file store by its own
users and by Jepsen: a single-bit flip in a stored block
([nats-server #7549](https://github.com/nats-io/nats-server/issues/7549)), a >= 32 MB record
under a limit that allows it
([nats-server #6797](https://github.com/nats-io/nats-server/issues/6797)), a torn tail (the
power-cut partial write), and a stale index that references a missing message block
([nats-server #5412](https://github.com/nats-io/nats-server/issues/5412); the cluster-wide
snapshot-corruption escalation is
[nats-server #7556](https://github.com/nats-io/nats-server/issues/7556)).

Every result below is **measured**, both sides, on the same host. Wins, losses, and
non-reproductions are all recorded; the honest-notes section is part of the result.

## Harnesses (how to re-run)

- **IronBus legs** — a repeatable integration test over the real `ironbus` binary
  (durable disk mode, fsync-per-ack, the zero-config default):
  `cargo test -p ironbus-cli --test corruption_recovery`
  ([`crates/ironbus-cli/tests/corruption_recovery.rs`](../../crates/ironbus-cli/tests/corruption_recovery.rs)).
  It runs in the normal CI suite, so the behaviors in this table are asserted on every run.
- **NATS legs** — a scripted, observation-only harness (downloads the pinned nats-server +
  natscli for the host arch, runs each scenario against a fresh JetStream file store, prints
  `OBSERV:` lines): `bash docs/benchmarks/corruption_recovery_nats.sh`
  ([`corruption_recovery_nats.sh`](corruption_recovery_nats.sh)).

## Methodology and versions

- **Environment:** Linux container (aarch64), single node, loopback. This is a
  correctness/behavior benchmark: no throughput numbers are read from it.
- **Versions:** IronBus at this commit (debug build, defaults: `durability_level=sync`,
  `power_loss_safe=true`, `compression=lz4`, `--checkpoint-interval 1`) vs
  **nats-server v2.14.3** driven by **natscli 0.4.0** (JetStream file storage, `replicas=1`,
  `sync_interval: always`, fresh store per scenario). 2026-07-10.
- **Injection is identical in kind on both sides:** write an acknowledged corpus, stop the
  broker cleanly, damage the store files directly (flip one bit / truncate the tail / delete a
  block while keeping the index / corrupt the checkpoint), restart, then measure state,
  readback, and reporting.
- **Grading, four properties per leg:**
  - **bounded** — the loss (if any) is a contiguous, capped span, never the whole stream;
  - **reported** — a structured, quantified loss report (reason + span), not a generic log line;
  - **no silent misread** — bytes that fail verification are never served as truth;
  - **served** — surviving records remain consumable and the log continues.

## Results

| # | Scenario | IronBus (measured) | NATS 2.14.3 (measured) |
| --- | --- | --- | --- |
| 1a | Single-bit flip, active (unsealed) segment | Recovery stops at the flipped record: the span from that record to the written tail (577 bytes in the run) is truncated, **reported** as a `corrupt_record_body` loss event with exact byte offsets — offline `verify`/`dump --json` and the online `/metrics` series agree **byte for byte** — and the poisoned span is copied to `quarantine/` for forensics. Records 0..=9 served byte-exact; the flipped record is never delivered; appends continue at the truncated head. | Stream still reports **300 messages** after restart; the consumer receives **299** — stream seq 150 is **silently skipped**: no error to the consumer, no server log line at all, and the stream's own message count is not even updated. An acknowledged write is gone with zero reporting. |
| 1b | Single-bit flip, sealed (middle-of-log) segment | **Fail-closed refusal**: `serve` exits with `storage error: predecessor segment 0 is not sealed`; `verify`/`dump` refuse the directory as structural corruption (exit 4); **every on-disk byte is preserved** (measured: the store differs from the pre-flip image by exactly the injected bit). No record is served from an unverifiable chain; the operator restores from a replica/backup with evidence intact. | Same behavior as 1a — the node starts and serves around the damage silently (the Jepsen runs in #7549 lost 20k–287k acknowledged records this way on 2.12.1, cluster-wide, with R5 replication). |
| 2 | >= 32 MB record (limit allows it) | **Refused up front**, before any byte is stored: the publish fails with `frame length 33554446 exceeds the 16842752-byte cap` (16 MiB record cap, enforced at frame encode and decode). Broker unharmed; the next publish lands at the contiguous next offset; `verify` clean. An in-cap large record (8 MiB, incompressible) is stored durably and **round-trips byte-exact across a restart**. | The acked path is **fixed on 2.14.3 in this shape**: a JetStream publish of 32 MiB under `max_payload: 64MB` now fails clean with `message too large (10077)` (#6797 reproduced accept-then-corrupt on 2.10/2.11; the issue is still open upstream). The **unacked core publish** captured by the stream is **silently dropped**: the client reports success, the stream stores nothing. |
| 3 | Torn tail (partial trailing write) | The 14 torn bytes are truncated and **reported exactly**: a `torn_tail` loss event with the byte span; `ironbus_recovery_truncated_bytes` equals the offline report (14 == 14). All 100% of acked records served byte-exact; the log continues at the truncated head. | The torn record is dropped and the stream restarts: 100 -> **99 messages**, 99 readable. Reporting is two generic warnings (`Stream state outdated, last block has additional entries, will rebuild`) — **no quantified loss span**; the count just changes. |
| 4 | Stale index / corrupt checkpoint | The **log is the source of truth; the checkpoint is derived**. Whole `cursor.ckpt` corrupted (both CRC slots): broker starts, cursor resets to the log start, all 10 records **redeliver at-least-once, zero data loss**, and the group is caught up after the drain. Single-bit flip (dual-slot discipline): the cursor is the intact newest slot or regresses to the previous durable one — measured **never ahead of the durable ack floor**, never torn, consumer never wedged. | The **index is the source of truth**: `could not locate msg block 1` -> the stream is restored to **`messages: 0`** (`first_seq: 51, last_seq: 50`) — **all 50 acknowledged messages silently deleted** (one generic WRN); the durable consumer's 30 pending messages vanish (`num_pending: 0`). The #5412 permanent consumer wedge itself is fixed on 2.14.3 (new publishes flow and are delivered). |

### Property grades

| # | Scenario | IronBus: bounded / reported / no-misread / served | NATS 2.14.3: bounded / reported / no-misread / served |
| --- | --- | --- | --- |
| 1a | Bit flip, active segment | yes / yes (exact span, 3 agreeing surfaces) / yes / yes | yes (1 msg) / **no** (zero reporting, count still 300) / yes (dropped, not misread) / yes |
| 1b | Bit flip, sealed segment | yes (nothing lost) / yes (precise structural error) / yes / **no — refuses to start** (integrity over availability) | yes (this run) / **no** / yes / yes (but #7549: silent loss of acked middle-of-log spans at scale) |
| 2 | >= 32 MB record | yes (nothing stored) / yes (explicit cap error) / yes / yes (log continues; in-cap 8 MiB round-trips) | acked path: refused clean (fixed in this shape); unacked path: **silent drop** (no / no / yes / yes) |
| 3 | Torn tail | yes / yes (exact bytes; counter == report) / yes / yes (100% of acked records) | yes (1 msg) / **partial** (generic warnings, no quantities) / yes / yes (99%) |
| 4 | Stale index / checkpoint | yes (zero loss) / yes / yes / yes (at-least-once redelivery, never wedged, never ahead of the ack floor) | **no — the whole stream empties** / **no** (one generic WRN) / yes / partial (consumer unwedged on 2.14.3, but 50 acked + 30 pending messages silently gone) |

## Honest notes

- **NATS #6797 (>= 32 MB) is not reproducible on 2.14.3 in its reported shape**: the
  JetStream-acknowledged publish now fails clean with `message too large (10077)` even though
  `max_payload` allows it (the reports were against 2.10/2.11; the upstream issue is still
  open). What remains on 2.14.3 is the unacked core-publish variant: stream capture silently
  drops the message while the client sees success. Recorded as measured, not spun.
- **NATS #5412's consumer wedge is fixed on 2.14.3**: the restored stream keeps its sequence
  space (`first_seq: 51, last_seq: 50` rather than the old `last_seq: 0`), so consumers accept
  new messages. The data-loss half of that issue is unchanged: one missing block referenced by
  `index.db` still silently empties the whole stream.
- **NATS #7549/#7556 at their full Jepsen scale are cluster findings** (R5 replication losing
  acked records; snapshot corruption deleting streams cluster-wide). This harness measures the
  single-node storage-engine behavior underneath them; the single-node observation (silent
  skip, no reporting) is consistent with the cluster reports.
- **IronBus scenario 1b is a deliberate availability trade**: a CRC failure inside a *sealed,
  middle-of-log* segment refuses the whole open rather than serving a chain it cannot verify;
  `repair --apply --force` also refuses (structural, exit 4). On a single node the recovery
  path is a replica or backup. A guided single-node repair for mid-chain corruption
  (quarantine + truncate from the damaged record, like the active-segment path) is a possible
  follow-up — the current stance is documented in `docs/RECOVERY.md`.
- The bit-flip legs place the flip in a **record body**. Flips in other structures (segment
  header, footer, checkpoint) hit different reason codes on IronBus (`corrupt_segment_header`,
  the dual-slot checkpoint discipline of scenario 4) and are covered by the storage crate's
  corruption-corpus tests; the NATS script does not sweep those variants.
- IronBus ran a **debug build** (this is a behavior benchmark, not a throughput one); NATS ran
  its release binary. Payload sizes and corpus counts differ per scenario and are stated in the
  harnesses; both sides of each scenario use the same corpus and the same injected damage.
