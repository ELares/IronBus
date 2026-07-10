<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Effectively-once survival head-to-head: IronBus vs NATS JetStream

The [#647](https://github.com/ELares/IronBus/issues/647) (V2-M12) benchmark: **demonstrate,
not assert**, the effectively-once survival differentiator built in
[#639](https://github.com/ELares/IronBus/issues/639) (M8-I2) by injecting the two things a
time-bounded dedup window is vulnerable to — a **broker restart** and a **producer-offline gap
longer than the window** — and measuring, on both brokers, whether a producer's retry of an
already-acknowledged publish is deduplicated or double-appended.

Every result below is **measured**, both sides, on the same host, with duplicate counts as the
ground truth. Wins, losses, and behaviors that differ from folklore are all recorded; the
honest-notes section is part of the result.

## Harnesses (how to re-run)

- **IronBus legs** — a repeatable integration test over the real `ironbus` binary (durable
  disk mode, fsync-per-ack, the zero-config default):
  `cargo test -p ironbus-cli --test effectively_once`
  ([`crates/ironbus-cli/tests/effectively_once.rs`](../../crates/ironbus-cli/tests/effectively_once.rs)).
  It runs in the normal CI suite, so the behaviors in this table are asserted on every run.
- **NATS legs** — a scripted, observation-only harness (downloads the pinned nats-server +
  natscli for the host arch, runs each scenario against a fresh JetStream file store, prints
  `OBSERV:` lines): `bash docs/benchmarks/effectively_once_nats.sh`
  ([`effectively_once_nats.sh`](effectively_once_nats.sh)).

## Methodology and versions

- **Environment:** Linux container (aarch64), single node, loopback. This is a
  correctness/behavior benchmark: no throughput numbers are read from it.
- **Versions:** IronBus at this commit (debug build, defaults: `durability_level=sync`,
  `power_loss_safe=true`, `--checkpoint-interval 1`) vs **nats-server v2.14.3** driven by
  **natscli 0.4.0** (JetStream file storage, `replicas=1`, `sync_interval: always`, fresh
  store per scenario). 2026-07-10.
- **The retry shape is identical on both sides:** publish an acknowledged corpus of messages
  each carrying a stable idempotency identity (IronBus: the `PubDedup` block — `producer_id` +
  `epoch` + `msg_id`, with the sequenced legs also carrying the per-producer monotonic `seq`;
  NATS: the `Nats-Msg-Id` header on an acknowledged JetStream publish), inject the scenario's
  restart and/or gap, then **re-publish the exact same identities** — a producer retrying
  after its acks were lost in transit. The measured result is how many retries were appended
  a second time.
- **Shortened windows (the standard methodology):** the gap scenarios run against
  deliberately shortened windows — `duplicates: 5s` on the NATS stream (config
  `duplicate_window`, default 2 minutes) and `--dedup-window-ms 3000` on IronBus's `msg_id`
  window (same 2-minute default) — and the producer sleeps past them (8 s / 4.5 s). Waiting
  out the real defaults would measure the same lapse, only slower. The restart scenarios keep
  the default windows so the restart is isolated from the time bound. IronBus's **sequence**
  path has no time parameter to shorten — its wall-clock independence is the thing measured.
- **Both IronBus dedup paths are measured**, including the one that loses: the time-bounded
  `msg_id` window (the same primitive class as `Nats-Msg-Id`) and the durable
  idempotent-producer sequence (the differentiator under test).

## Results

Duplicate counts are `duplicates appended / retries sent`. **0 = effectively-once held.**

| # | Scenario | IronBus (measured) | NATS 2.14.3 (measured) |
| --- | --- | --- | --- |
| 1 | Retry after a broker **restart** (window still open) | **Sequence path: 0/10 duplicates.** The graceful-shutdown flush persisted the `(producer_id, epoch, last_seq, last_offset)` high-water to `producer-seq.ckpt`; every cross-restart retry answered `duplicate = true` (10 counted `ironbus_dedup_hits_total`), nothing appended, and the log carries each record exactly once. `msg_id` window path: **1/1 duplicated** — the window is in-memory and does not survive a restart (measured, recorded honestly; see the notes). | **0/10 duplicates** — measured on both a clean (SIGTERM) restart and a `kill -9` restart. On 2.14.3 the file store **rebuilds the duplicate-tracking state from the stored message headers** still inside the window, so a restart alone does NOT lapse it. Recorded as measured, against the folklore. |
| 2 | Retry after a **producer-offline gap** longer than the window (no restart) | **Sequence path: 0/5 duplicates** — the high-water is sequence state, not wall-clock, so the gap is irrelevant by construction. `msg_id` window path: **1/1 duplicated** after the gap, and the lapse is **operator-visible** (`ironbus_dedup_out_of_window_total` fired), never silent. | **10/10 duplicated** — every retry past the `duplicate_window` was accepted as an ordinary new message (stream count 10 -> 20). The window is the whole defense: once wall-clock passes it, the same `Nats-Msg-Id` reads fresh. |
| 3 | **Combined**: restart PLUS a gap past the window | **Sequence path: 0/5 duplicates** across a `kill -9` (no shutdown flush) plus the gap: the ack-driven checkpoint tick had already persisted the high-water, and it is time-independent. `msg_id` window path: **1/1 duplicated** (state gone and time lapsed). | **10/10 duplicated** (stream count 10 -> 20) — the rebuilt-on-restart tracking state only covers messages still inside the window, so the gap lapses it exactly as with no restart. |
| 4 | The **honest bound** of the IronBus sequence path: `kill -9` before ANY durability point | **3/3 duplicated** — an unclean kill before any ack-driven checkpoint tick, graceful shutdown, or txn-commit flush loses the un-persisted high-water, and the retries re-append (the documented at-least-once degrade). The bound is **checkpoint lag**, never wall-clock. | — (no durable dedup path to bound; the window scenarios above are the whole contract) |

## The dedup contracts, as measured

- **NATS `Nats-Msg-Id`:** one primitive — a per-stream duplicate-tracking window bounded by
  wall-clock (`duplicate_window`, default 2 minutes). On 2.14.3 with file storage it **does
  survive restarts** (clean and `kill -9`): the tracking state is rebuilt from stored message
  headers still inside the window. What it cannot survive is **time**: any retry arriving
  after the window — a producer offline past 2 minutes, a long partition, a queued redelivery
  — is appended again, indistinguishable from a fresh publish. Widening the window widens the
  per-message tracking state it implies; the bound stays wall-clock.
- **IronBus `msg_id` window (#33):** the same primitive class, deliberately: per-producer,
  bounded by a count (default 100k ids) AND a monotonic time window (default 2 minutes,
  `--dedup-window-ms`), epoch-fenced. Held **in memory only** — it does not survive a restart
  (on that one axis it is weaker than NATS's file-store window, measured in scenario 1 and
  stated here rather than hidden). A lapse is counted (`ironbus_dedup_out_of_window_total`),
  never silent. This is the content-keyed convenience path, not the survival contract.
- **IronBus idempotent-producer sequence (V2-M8, #638/#639):** the survival contract. The
  broker keeps one `(epoch, last_seq, last_offset)` high-water per `producer_id` — O(1) per
  producer, not O(messages) — persisted to `producer-seq.ckpt` (dual-slot, CRC-protected) on
  the ack-driven cursor-checkpoint cadence, the graceful-shutdown flush, and inline at txn
  commit. A retry (`seq <= last_seq`) is deduplicated to exactly-once-append **across
  restarts and arbitrarily long gaps** — the bound is sequence state, never wall-clock. Its
  real limits, measured or stated: (a) an unclean kill loses high-waters newer than the last
  durability point (scenario 4: at-least-once for exactly those retries, never a wrong
  offset); (b) the registry tracks at most 4096 producers (attacker-chosen ids are
  LRU-evicted; an evicted producer degrades to at-least-once); (c) a retry of an *older* seq
  is answered with the *high-water* offset, honoring "already durable, do not re-append"
  rather than per-seq offset recall; (d) a sequence *gap* (`seq > last + 1`) is rejected
  (`OutOfOrder`, the Kafka semantics), never silently accepted.

## Honest notes

- **The headline claim needed qualifying, and the measurement did it.** The M8-I2 framing
  ("NATS's dedup is volatile and lapses on restart") is **not what 2.14.3 does on file
  storage**: scenarios 1/1b measured 0/10 duplicates across both clean and `kill -9`
  restarts. What lapses NATS's dedup is the **wall-clock window itself** (scenarios 2 and 3:
  10/10 duplicated). The IronBus differentiator is therefore precisely: *dedup bounded by
  sequence state instead of wall-clock*, plus the measured restart survival — not a claim
  that NATS forgets on restart.
- **IronBus's own `msg_id` window is the volatile one across restarts** (scenario 1: 1/1
  duplicated where NATS's file-store window held). The doc says so because the measurement
  did. A producer that needs survival uses the sequence path; the window path is for
  content-keyed dedup inside a session.
- **Scenario 4 is a deliberate leg, not a failure:** it measures the sequence path's real
  durability bound (checkpoint lag under an unclean kill with zero durability points) so this
  page states the actual contract instead of claiming infinity. In a running pipeline the
  high-water persists on every ack-driven checkpoint tick (`--checkpoint-interval 1` in the
  harness), on every graceful shutdown, and inline at txn commit.
- **The shortened windows are methodology, not a thumb on the scale:** both sides' gap legs
  shorten their window (5 s NATS, 3 s IronBus) and wait past it; the 2-minute defaults lapse
  identically, only slower. The IronBus sequence path's 0-duplicate results are
  wall-clock-independent and hold for any gap length by construction.
- IronBus ran a **debug build** (this is a behavior benchmark, not a throughput one); NATS
  ran its release binary. Corpus sizes are stated in the harnesses; both sides of each
  scenario retry the same identities they published.
