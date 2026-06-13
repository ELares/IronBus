# IronBus design risk register

This is the design risk register for IronBus: an adversarial flaw-hunt over the
shipped design, derived from the issues, the code, the merged PRs, and the
project's development history (#138). The original META issue #138 is the
design-time hunt that ran *before* coding (the R1 to R13 contradictions in the
frozen design). This document is the complementary *post-implementation* register:
the failure modes the shipped engine faces, what is mitigated in the code today,
the real defects the adversarial-review process caught and fixed, and the risks
that honestly remain open.

The code, the README, and the issues are canonical. Every entry marked MITIGATED
cites a mechanism and a test verified against the source; every FIXED DEFECT is a
real merged fix checked against the CHANGELOG, the issue, or the merged PR; every
OPEN risk names its tracking issue. This register does not overstate the safety
posture: IronBus is a trusted-network, single-node, log-is-WAL broker, and the
open section is deliberately blunt about what is not there yet.

Cross-references (this document does not duplicate them):

- [THREAT_MODEL.md](THREAT_MODEL.md): the enumerated edge threat model, the DoS
  and resource-exhaustion mitigations, and the honest no-auth / no-TLS /
  no-at-rest-encryption posture (#105).
- [INVARIANTS.md](INVARIANTS.md): the shared invariants I1 to I8, the resilience
  invariant checkers, and the glossary (#131).
- [WAL.md](WAL.md): the active-segment-is-the-WAL model under load, the file
  lifecycle, and the single-writer caveat (#135).
- [CONTRACTS.md](CONTRACTS.md): the byte-level on-disk, wire, config, runtime, and
  report schemas (#137).
- [METRICS.md](METRICS.md) and
  [schemas/loss-report.v1.md](schemas/loss-report.v1.md): the frozen
  resilience-counter taxonomy and the versioned loss-report schema (#96, #120).

Categories used below: durability, concurrency, resource-exhaustion/DoS,
recovery, observability, security, operational, performance.

## How to read an entry

Each risk has an id, a short title, a category, the failure mode it describes, its
current status (MITIGATED with the mechanism and test, FIXED with the merged fix,
or OPEN with the tracking issue), and a residual-risk note: what is still true
even after the mitigation, or what the open risk costs until it lands.

---

## Section 1: risks mitigated in the shipped code

Each of these was a credible failure mode that the engine now defends against, with
the defending mechanism and a test cited to the source.

### RR-01 Unbounded per-consumer occupancy (RAM exhaustion)

- **Category:** resource-exhaustion/DoS.
- **Failure mode:** a single consumer (or a malicious one) fetches without acking
  and pins unbounded in-flight messages, blowing the broker's RAM ceiling and
  starving peers in the same competing group.
- **Mitigation:** two composed per-connection budgets. The message-count credit
  (`EngineConfig.consumer_credit`, default 64, `serve --consumer-credit`) caps the
  un-acked message count per connection (#65). The byte budget
  (`EngineConfig.consumer_credit_bytes`, default 8 MiB, `serve
  --consumer-credit-bytes`) caps the un-acked payload bytes, so the effective
  per-Flow credit is `min(message credits, byte credits)` with a hard floor of one
  message so a single over-budget record never wedges the consumer (#275). Both
  are derived from the connection-scoped `leased` set, so the accounting cannot
  drift. Tested at every layer (engine passthrough, session credit-cap /
  restore-on-ack/nack/term / isolation / redelivery accounting, end-to-end over a
  real server, CLI flag validation).
- **Residual risk:** the credit is server-side only; the wire-advertised /
  negotiated credit in the Connect/Info handshake is not built (see RR-21, #292),
  so a client cannot learn the broker's ceiling and must discover it by being
  capped. Per-member in-flight depth is not yet on `/metrics`.

### RR-02 Unbounded named-group memory

- **Category:** resource-exhaustion/DoS.
- **Failure mode:** the wire can name work-groups (the `Sub` frame body is the
  group name), so a client that subscribes to an unbounded set of distinct named
  groups makes the broker allocate a per-group `AckCursor` + `LeaseTable`
  indefinitely.
- **Mitigation:** a live-group cap plus name validation
  (`EngineConfig.max_groups`, default 1024, `serve --max-groups`) rejects a new
  NAMED group past the cap with the typed `EngineError::TooManyGroups` before
  allocating; the default group `""` is exempt and uncounted; names are validated
  (1 to 128 graphic-ASCII bytes) with `EngineError::InvalidGroupName` (#240). Idle
  named-group eviction (`EngineConfig.group_idle_evict_ms`, `0` = disabled,
  `serve --group-idle-evict-ms`) reclaims a slot from a fully-caught-up,
  lease-free, idle named group, durably checkpointing it at the head before
  dropping it so re-subscribe resumes and redelivers nothing acked (#277).
- **Residual risk:** #240 itself is still OPEN as a META task (the cap shipped;
  the broader lifecycle bookkeeping it tracks is iterative). Eviction is off by
  default (`0`), so the steady-state defense against group accumulation is the cap,
  not the reaper, unless an operator opts in.

### RR-03 Disk exhaustion

- **Category:** resource-exhaustion/DoS, durability.
- **Failure mode:** unbounded log growth fills the device, after which any further
  write fails and the node is wedged.
- **Mitigation:** a layered disk-bounding model. The durable-byte cap
  (`LogConfig.max_total_bytes`, `serve --max-total-bytes`, `0` = unlimited)
  rejects a produce before any write with the non-fatal `StorageError::AtCapacity`
  (the drop-new shed), counted as `ironbus_produce_rejected_total` (#10). The
  consumer-safe retention reaper deletes whole old sealed segments under a byte,
  age, or count bound (`--max-retained-bytes` / `--max-age-ms` / `--max-messages`,
  each `0` = off), never the active segment and never below the slowest consumer's
  committed offset, counted as `ironbus_segments_reaped_total` (#13). The opt-in
  drop-oldest policy (`--disk-full-policy drop-oldest`) force-reaps the oldest
  sealed segment to accept the produce, surfacing exactly one `Poll::Truncated`
  to a consumer whose cursor fell below earliest-retained, counted as
  `ironbus_segments_force_reaped_total` (#82). Tested at the storage, engine,
  `/metrics`, and golden-path levels (including #133 step 8 over the real binary).
- **Residual risk:** the caps are per-log and opt-in (`0` = unlimited is the
  default). The DLQ sink, the cursor checkpoints, and the data log are not jointly
  budgeted against device free space by a single high-water enforcer (this was R7
  in the design hunt; the joint budget is not built). The DLQ never reaps by
  design, so a poison storm grows it without bound.

### RR-04 Poison-message redelivery loops

- **Category:** operational, durability.
- **Failure mode:** a message that fails processing is nacked and redelivered
  forever, blocking the group and burning redelivery work.
- **Mitigation:** MaxDeliver to a durable DLQ. A record over `max_deliver` is
  moved to a durable, segmented DLQ sink under `dlq/` by a crash-atomic,
  exactly-once move (append + fsync the poison record, THEN commit the source
  cursor past it; a crash in the window redelivers and re-poisons, and the
  per-group dead-lettered high-water mark rebuilt at open suppresses the
  duplicate), idempotent on `(group, source offset, attempt)`, counted as
  `ironbus_dlq_records_total` (#63). Unlimited delivery (`max_deliver` 0 or
  `u32::MAX`) is allowed only behind `serve --allow-unlimited-deliver` plus a
  startup WARN. Engine tests:
  `a_poisoned_message_is_durably_written_to_the_dlq_and_committed_past`,
  `the_no_poison_path_never_creates_or_touches_the_dlq`,
  `counters_track_a_dead_letter`.
- **Residual risk:** the DLQ sink never reaps, so a high poison rate grows it
  unboundedly (feeds RR-03). The DLQ idempotency check in the engine keys on
  `(group, source_offset)` rather than the full `(group, offset, attempt)` tuple
  (noted in INVARIANTS.md). The broadcast-consumer cumulative-ack path is deferred
  (#288).

### RR-05 Silent corruption loss

- **Category:** durability, recovery.
- **Failure mode:** an on-disk bit-flip in a record is read back as valid and
  delivered, or silently drops acked data without any signal.
- **Mitigation:** per-record CRC32C (header and body), verified first so a body
  corruption is reported as `BadBodyCrc`, plus an independent xxh3-64 over the same
  body byte range for records whose stored body reaches 64 KiB
  (`RecordFlags::HAS_XXH3`, a mismatch is the distinct typed `DecodeError::BadXxh3`)
  (#146). Recovery fails closed on the I3 bounded-loss caps: `Log::open` computes
  the per-event cap (one segment or 64 MiB) and the global cap (1% of durable
  bytes, floored at the per-event cap) and refuses to open if the loss report
  exceeds them (`log.rs` `check_caps`), rather than accept unbounded silent loss
  (#120). The deterministic corruption corpus
  (`crates/ironbus-storage/tests/corruption_corpus.rs`) drives the real recovery
  path over one precise mutation per case and an exhaustive single-bit-flip sweep
  (`single_bit_flip_sweep_over_every_offset_never_panics`), asserting a concrete
  typed outcome and a valid prefix every time, never a panic and never a read past
  the torn tail; no real recovery bug was found, so the corpus is a permanent
  regression net (#123).
- **Residual risk:** the bounded-loss cap is "1% of durable bytes per recovery"
  (R6 in the design hunt): on a large log that 1% is large, and a corrupt segment
  *header* can cost a whole segment as one event. The heavier block-layer fault
  injection (dm-flakey / dm-dust) and the ALICE crash-prefix conformance run are
  hardware-dependent and deferred (#123 follow-up). The offline reader
  (`OfflineReader`) deliberately does NOT fail closed (it is a read-only inspector,
  not the recovery path).

### RR-06 Torn tail on crash

- **Category:** recovery, durability.
- **Failure mode:** a power cut mid-append leaves a partial record (torn header,
  body, or trailer) at the tail; reading it as a record corrupts state or panics.
- **Mitigation:** recovery truncates the torn or unsynced active-segment tail back
  to the last intact, fully-synced record (`Log::open`), and reports the dropped
  bytes via `recovered_truncated_bytes()` (the silent-loss signal is surfaced, not
  hidden) (#7). The `InMemoryFile` model distinguishes `fdatasync` (`sync_data`)
  from `fsync` (`sync_all`) so a length-shrink truncation is durable only after
  `sync_all`, matching the conservative real-disk contract recovery follows.
  Crash-recovery test: `a_torn_write_during_append_is_truncated_by_recovery`.
- **Residual risk:** the zero-fill end-of-data rule interacts with preallocation
  (R13 in the design hunt); preallocation and recycling are not implemented, so the
  shipped model is size-rolled segments without that specific interaction, but the
  rule remains a latent hazard if preallocation lands.

### RR-07 Lost acks on graceful stop

- **Category:** durability, operational.
- **Failure mode:** an operator stops the broker (SIGTERM) and the lagging
  in-memory cursor is lost, so acked messages redeliver to a still-connected
  consumer on restart.
- **Mitigation:** SIGINT / SIGTERM flip the serve loop's shutdown flag,
  stop accepting connections, flush EVERY work-group's committed cursor
  (`Engine::checkpoint_all_groups`), and exit 0, so a restart after a clean stop
  does not redeliver acked messages (#195). The handler (`ctrlc`) does a single
  async-signal-safe atomic store; the existing non-blocking accept observes it
  within ~50 ms. A gating Unix integration test produces/consumes/acks under the
  production checkpoint interval, sends SIGTERM, asserts exit 0, restarts, and
  asserts no redelivery.
- **Residual risk:** un-acked in-flight messages still redeliver after a graceful
  stop (correct at-least-once); the optional in-flight drain is not implemented.

### RR-08 Connection floods, slowloris, and oversized frames

- **Category:** resource-exhaustion/DoS, security.
- **Failure mode:** an attacker on the trusted network opens unbounded
  connections, holds them open without progressing (slowloris), or declares a huge
  frame length to force a giant allocation.
- **Mitigation:** a connection cap (`max_connections`, `serve --max-connections`)
  refuses connections past the bound; a 30 s `CONNECTION_TIMEOUT` read/write
  deadline bounds slowloris holds (`server.rs`); and `MAX_FRAME_LEN` (16 MiB + 64
  KiB) caps the declared frame length so an oversized declaration is the typed
  `FrameTooLarge`, never an allocation (`frame.rs`). These are the implemented DoS
  controls catalogued in [THREAT_MODEL.md](THREAT_MODEL.md) (#105).
- **Residual risk:** these are reachability defenses, not authentication: any peer
  that can reach the port has full produce/consume access (see RR-19). The
  connection cap is global, not per-source, so one source can exhaust the budget.

### RR-09 Silent resilience events

- **Category:** observability.
- **Failure mode:** a shed, drop, skip, dead-letter, truncation, force-reap, or
  recovery-loss happens silently, so an operator cannot see the node losing or
  shedding data.
- **Mitigation:** the frozen resilience-counter taxonomy: every such event
  increments a stable-named, documented `ironbus_*_total` counter on `/metrics`
  and `/admin`, pinned by `the_resilience_counter_taxonomy_is_frozen` so adding,
  removing, or renaming a resilience counter is a test-gated change and the
  taxonomy cannot silently drift (#96). [METRICS.md](METRICS.md) is the normative
  per-counter catalog (including the deliberately-uncounted dispositions and their
  rationale). The recovery loss report is a versioned, externally-frozen schema
  (`ironbus.loss-report.v1`, golden-tested) (#120).
- **Residual risk:** the counters are in-memory and reset to zero on restart (they
  are not durable; see RR-22, #98), so a crash erases the running tallies; only the
  durable evidence (the DLQ, the truncated-bytes accessor, the on-disk log) is
  authoritative across a restart.

---

## Section 2: real defects found and fixed during development

This is the highest-signal section: a record of the adversarial-review process
catching real bugs before release. Each is a real merged fix, verified against the
CHANGELOG, the issue, or the merged PR (none invented).

### RR-10 Lowering --max-groups silently dropped durable cursors on recovery

- **Category:** durability, recovery.
- **Risk it represented:** the named-group cap (#240) was applied to the open-time
  resume scan as well as to new-group creation. Lowering `--max-groups` below the
  count of groups already on disk would have capped the resume scan, resetting the
  excess groups to offset 0 and redelivering the entire already-acked log to them.
  A config tweak between restarts could silently lose every group's committed
  position.
- **Mitigation now in place:** recovery loads EVERY durable named group
  unconditionally; the cap gates only the new-creation allocation path
  (`poll_in`), never the open-time resume (`engine.rs`, comments at the recovery
  path; test `lowering_the_group_cap_still_recovers_every_durable_group` asserts
  the default plus three recovered groups survive a cap of 2). Verified against the
  CHANGELOG #240 entry and the source.
- **Residual risk:** none for the recovery path; the cap correctly bounds only new
  creation.

### RR-11 key_shared empty-key over-serialization

- **Category:** performance, concurrency.
- **Risk it represented:** in the first cut of key_shared routing the per-key
  serialization gate was applied to the empty key `b""`, throttling ALL
  empty-keyed traffic to one in-flight record across the whole group, which
  contradicts the "empty key = plain competing, drains in parallel" contract and
  would have collapsed throughput for the common unkeyed case.
- **Mitigation now in place:** `decide` bypasses the gate for the empty key (the
  lease layer alone bounds it per offset) and `mark_in_flight` is a no-op for it;
  empty-keyed records keep plain competing distribution. Fixed during PR review
  (commit "Let empty keys drain in parallel under key_shared (#64 review)"); core
  test `empty_keys_drain_in_parallel_and_are_not_serialized`
  (`crates/ironbus-core/src/keyshared.rs`) and an engine test that polls two
  empty-keyed records with no ack between (which the old gate failed). Verified
  against the merged PR #283 review thread and the source.
- **Residual risk:** none for the empty-key path. Wire-negotiated `key_ordering`
  and per-member in-flight depth on `/metrics` remain follow-ups.

### RR-12 Macro-bench crashed on a dropped connection under a hard stall

- **Category:** observability, operational (tooling).
- **Risk it represented:** the open-loop macro-bench harness (#111) crashed when
  the broker dropped its connection under a hard injected stall (a `SIGSTOP` that
  reset an in-flight connection), so the SLO instrument itself could not measure
  the very overload it exists to measure, masking a stall as a harness crash.
- **Mitigation now in place:** the harness tolerates a dropped broker connection,
  reporting the samples already measured rather than crashing, distinguishing a
  tolerated `ConnectionReset` / `BrokenPipe` under overload from a real transport
  failure (`crates/ironbus-bench/src/harness.rs`). Fixed in PR #279 (commit "Make
  the macro-bench harness tolerate a dropped broker connection (#111)") and
  recorded in the CHANGELOG. Verified against the merged PR commits and the source.
- **Residual risk:** the harness is a measurement tool, not a shipped path; its
  coordinated-omission self-test is now a reliable deterministic gate (the legacy
  live `SIGSTOP` proof stays behind `--ignored`; see RR-20, #284).

### RR-13 serve-flag parse infinite loop on a value-less flag

- **Category:** operational.
- **Risk it represented:** the boolean `serve --allow-unlimited-deliver` flag
  takes no value; the first cut advanced the parse index by zero for it, so the
  flag loop spun forever and `ironbus serve` hung at startup the moment the flag
  was passed.
- **Mitigation now in place:** a value-less flag advances the parse index by ONE
  (`crates/ironbus-cli/src/main.rs`, the `--allow-unlimited-deliver` arm with the
  comment "A bare boolean flag (no value): advance ONE token, not two, or the loop
  spins"); covered by the parse test `serve_parses_the_allow_unlimited_deliver_flag`.
  Stated explicitly in the PR #289 body ("the first cut advanced by zero and spun
  the flag loop forever. Fixed and covered by the parse test"). Verified against
  the merged PR body and the source.
- **Residual risk:** none for this flag; the boolean-flag arm now advances
  correctly.

### RR-14 Below-earliest truncation served to a consumer was uncounted

- **Category:** observability.
- **Risk it represented:** when drop-oldest force-reaping marched past a stuck
  consumer's cursor, the resulting below-earliest truncation served to that
  consumer (the `Poll::Truncated` skip signal) incremented no counter, so a node
  could silently skip records out from under a lagging consumer with no `/metrics`
  evidence, violating the "no resilience event is silent" contract.
- **Mitigation now in place:** two counters were added at the `Poll::Truncated`
  site: `ironbus_truncations_total` (events) and `ironbus_truncated_records_total`
  (the record-count span), rendered on `/metrics` and `/admin`
  (`crates/ironbus-server/src/health.rs`), and locked in by the frozen-taxonomy
  test. The audit found every OTHER resilience event was already counted; this was
  the one gap. Fixed in #96. Verified against the CHANGELOG #96 entry and the
  source.
- **Residual risk:** the counters are in-memory and reset on restart (RR-22).

### RR-15 Windows dead-code build break from a unix-only serve field

- **Category:** operational.
- **Risk it represented:** the `/admin` work (#99) added a `config.enable_admin`
  field read only on the Unix serve path, so the non-unix `cmd_serve` stub left it
  unread and `ironbus-cli` failed to compile warning-clean on Windows under
  `-D warnings` (a portability / CI build break, not a runtime bug since `serve`
  is Unix-only).
- **Mitigation now in place:** the non-unix `cmd_serve` stub now consumes
  `config.enable_admin`, so the crate compiles clean on Windows under `-D warnings`;
  no behavior change (`serve` stays Unix-only). Fixed in PR #301 (CHANGELOG "Build
  fix" entry, refs #99). Verified against the merged PR and the CHANGELOG.
- **Residual risk:** none; the stub consumes the field.

---

## Section 3: open / unmitigated risks

Honest accounting of what is not defended yet. Each names its tracking issue.

### RR-16 No authentication

- **Category:** security.
- **Failure mode:** the `Connect` / `Info` handshake carries no credential, so any
  peer that can reach the port has full produce and consume access. Reachability is
  authorization.
- **Status:** OPEN, tracking #106. The connection-scoped authentication and
  three-scope authorization model is specified but not built. See
  [THREAT_MODEL.md](THREAT_MODEL.md) (no-auth posture) and CONTRACTS.md (the
  handshake fields are specified-but-absent).
- **Residual risk:** IronBus must be deployed only on a trusted network /
  localhost; the connection cap and slowloris timeout (RR-08) bound DoS but not
  access.

### RR-17 No TLS

- **Category:** security.
- **Failure mode:** the wire is plaintext (no TLS crate in any `Cargo.toml`), so a
  network observer reads and can tamper with every record in flight.
- **Status:** OPEN, tracking #107. TLS 1.3 transport, the localhost-default bind
  invariant, and the pre-auth DoS defenses are specified but not built.
- **Residual risk:** confidentiality and integrity in transit depend entirely on
  the network being trusted.

### RR-18 No at-rest encryption

- **Category:** security.
- **Failure mode:** the log and the DLQ are plaintext on disk, so device theft or
  filesystem access exposes every stored record.
- **Status:** OPEN, tracking #108. Optional at-rest AEAD encryption and its
  interaction with the checksums and recovery is specified but not built.
- **Residual risk:** at-rest confidentiality depends on device-level controls
  (disk encryption, physical security).

### RR-19 Single-Mutex append path head-of-line blocking

- **Category:** performance, concurrency.
- **Failure mode:** the single logical writer (invariant I8) is realized by sharing
  the `Engine` behind a `Mutex` (`SharedEngine` in `server.rs`); the
  thread-per-connection model serializes every produce through that lock, and a
  produce holds the lock across its `fdatasync`. A single slow fsync (an SD/eMMC
  garbage-collection pause is routinely hundreds of ms) head-of-line-blocks EVERY
  connection, not just the producer that triggered it (this was R2 in the design
  hunt).
- **Status:** FIXED (#177). The `Engine` is now owned by a single append-actor
  thread (`actor.rs`); connection handlers fan in over a bounded `sync_channel` and
  send commands instead of locking the engine, so NO handler holds a lock across an
  fsync. The actor group-commits a drained batch of produces with ONE `fdatasync`
  and acks the batch only after it (amortizing the fsync), and pings are answered in
  the handler without touching the actor, so a stalled produce fsync no longer
  head-of-line-blocks other connections' pings. An acceptance test stalls a
  producer's `sync_data` (a sync-gating fault fs) and proves another connection's
  ping still returns; another proves a batch issues one `fdatasync`, not N. I2,
  single durable order, no-deadlock (a closed channel is a typed `ActorGone`), and
  the #195 graceful-shutdown drain are preserved.
- **Residual risk:** a stalled fsync still blocks WORK that needs durable engine
  state (a producer behind it in the same group, and the actor's serial cursor
  commits), since the single-writer rule keeps those serial; the bounded channel
  applies backpressure rather than unbounded buffering. Tail-sync latency on worn
  flash is still unmeasured.

### RR-20 Macro-bench injected-stall self-test flaky on shared CI

- **Category:** observability (tooling).
- **Failure mode:** the headline coordinated-omission self-test originally
  `SIGSTOP`ped the broker mid-run and asserted the tail moves; it was reliable on
  a stable host but flaky on GitHub's shared runners, where the OS freeze did not
  reliably manifest in the tail (a runner-scheduling artifact, not a harness-logic
  bug), so it could not gate per-PR CI and was `#[ignore]`d.
- **Status:** RESOLVED by #284. The proof is now a deterministic in-process
  freeze: the self-test runs the broker in-process (the same `ironbus-server`
  engine + actor + `serve`) over a `FaultFs` and freezes it by closing the sync
  gate, which parks the group-commit `fdatasync` on a condvar, so the freeze
  always lands in the tail with no OS dependence. It is de-`#[ignore]`d, gates
  every PR, and was verified non-flaky over 20 consecutive runs. The legacy live
  `SIGSTOP` proof is kept behind `--ignored` and does not gate CI.
- **Residual risk:** the SLO table is still aspirational because no measured
  on-device baseline has been archived; [SLO.md](SLO.md) marks every target as a
  STATED TARGET, not yet ratified. The honesty gate itself (no coordinated
  omission) is now enforced per PR.

### RR-21 No wire-advertised credit or version / capability negotiation

- **Category:** operational, performance.
- **Failure mode:** the per-consumer credit and byte budget are server-side only
  and are not carried in the (empty) Connect/Info handshake, so a client cannot
  learn the broker's ceiling and discovers it only by being capped. There is also
  no `wire_protocol_version` and no capability negotiation: the handshake is empty.
- **Status:** OPEN, tracking #292 (wire-advertised / negotiated per-consumer
  credit) and #132 (the on-disk and wire compatibility / versioning policy, the
  META; the version registry and negotiation are specified-but-absent). See
  [COMPATIBILITY.md](COMPATIBILITY.md).
- **Residual risk:** clients and brokers cannot negotiate; a future wire change
  has no handshake to negotiate over, so compatibility rests on the frozen-tag
  append-only discipline (which IS enforced) rather than negotiation.

### RR-22 Resilience counters are not durable

- **Category:** observability.
- **Failure mode:** the `ironbus_*_total` resilience counters are in-memory and
  reset to zero on every restart, so a crash erases the running tallies of sheds,
  drops, skips, dead-letters, truncations, force-reaps, and recovery loss. An
  operator scraping `/metrics` sees post-restart counts, not lifetime totals; the
  monotonicity a counter implies is broken across a restart.
- **Status:** OPEN, tracking #98 (resilience-counter durability: checkpoint plus
  replay reconciliation with a monotonicity contract). Verified OPEN at the time of
  writing; not yet merged.
- **Residual risk:** lifetime resilience accounting must come from the durable
  evidence (the DLQ depth, `recovered_truncated_bytes`, the on-disk log), not the
  counters, until #98 lands. Prometheus `rate()` over a restart sees a counter
  reset and treats it correctly, but absolute lifetime totals are lost.

### RR-23 No loom coverage

- **Category:** concurrency.
- **Failure mode:** the concurrent handoffs (the append-actor command/reply
  channels, the cursor, refcounts) are not proven under a concurrency model checker,
  so a subtle memory-ordering or interleaving bug could hide.
- **Status:** OPEN, tracking #122. No `loom` model exists in the tree (noted in
  [INVARIANTS.md](INVARIANTS.md)). The honest reason: there are still no hand-rolled
  lock-free structures. The #177 append actor (RR-19) fans connection handlers into a
  single owner over a std `sync_channel` (a vetted bounded queue, not a custom
  lock-free structure) with per-command reply channels, so the handoffs are still
  ordinary std primitives loom would not exercise differently from std's own tests;
  loom becomes load-bearing only if a hand-rolled lock-free path is ever introduced.
- **Residual risk:** low today (coarse locking is simple to reason about), rising
  the moment a lock-free path is introduced.

### RR-24 Unbounded dedup producer map (distinct-`producer_id` RAM exhaustion)

- **Category:** resource-exhaustion/DoS.
- **Failure mode:** the opt-in dedup registry
  (`crates/ironbus-core/src/dedup.rs`) keyed its per-producer window map on the
  wire-supplied, attacker-chosen `producer_id` and NEVER reaped it: no cap, no
  LRU, no idle eviction. A peer (when dedup is enabled) sending an unbounded
  stream of distinct `producer_id`s grew broker RAM without bound, and a single
  `producer_id` could be up to the 64 KiB wire field maximum. The per-window
  bounds (count + time) bounded each window but not the NUMBER of windows, so the
  RAM_BUDGET claim that the term was "bounded by the connection count" was false.
- **Mitigation:** a hard cap on the number of tracked windows
  (`DedupConfig::max_producers`, default 4096, `serve --dedup-max-producers`,
  floored to 1) with LRU eviction: a fresh `producer_id` over the cap evicts the
  least-recently-active window (`DedupRegistry::make_room_for`), and fully
  time-expired windows are reaped opportunistically first, so the TOTAL dedup
  memory is the closed formula `max_producers * max_ids * per_entry`. Evicting a
  window only drops dedup state for the least-active producer, which falls back to
  at-least-once (already the contract for an aged/evicted id). The `producer_id`
  and `msg_id` are each capped at 256 bytes (`MAX_PRODUCER_ID_LEN` /
  `MAX_MSG_ID_LEN`), enforced as a typed, connection-preserving rejection at the
  wire boundary in `Session::handle_pub`. Tested in `dedup.rs`
  (`the_producer_count_is_hard_bounded_under_a_flood_of_distinct_producer_ids`,
  `an_evicted_producers_later_duplicate_is_treated_as_fresh`,
  `an_active_producer_is_not_evicted_while_idle_ones_exist`,
  `a_fully_time_expired_window_is_reaped_so_it_does_not_pin_a_slot`) and in
  `session.rs` (`an_oversized_producer_id_is_rejected_at_the_wire_boundary`).
- **Residual risk:** the cap is a per-producer-window count, not a measured RAM
  high-water; an operator who opts into dedup on a tight node must still size
  `--dedup-max-producers` and `--dedup-max-ids` against the documented worst case
  (RAM_BUDGET.md), since the shipped defaults target a server, not a 64 MiB edge
  box. The window is session-scoped (lost on restart), so it never grows across
  restarts.

---

## Summary of counts

Mitigated (Section 1): 9 risks. Fixed defects (Section 2): 7 real merged fixes
(RR-24 the latest, the dedup producer-map bound found in adversarial review).
Open / unmitigated (Section 3): 8 risks.

By category (mitigated vs open, defects counted under their category):

| Category | Mitigated | Fixed defect | Open |
| --- | --- | --- | --- |
| durability | RR-03, RR-05, RR-06, RR-07 | RR-10 | |
| concurrency | | RR-11, RR-19 | RR-23 |
| resource-exhaustion/DoS | RR-01, RR-02, RR-03, RR-08 | RR-24 | |
| recovery | RR-05, RR-06 | RR-10 | |
| observability | RR-09 | RR-12, RR-14 | RR-20, RR-22 |
| security | RR-08 | | RR-16, RR-17, RR-18 |
| operational | RR-04, RR-07 | RR-13, RR-15 | RR-21 |
| performance | | RR-11, RR-19 | RR-21 |

(Some risks span more than one category and appear in each; the headline counts
above are by section.)

## Provenance

Every "mitigated" cites a mechanism and a test verified against the source at the
time of writing. Every "fixed defect" was checked against the CHANGELOG, the
closed issue, or the merged PR (RR-10 #240 / CHANGELOG; RR-11 PR #283 review
thread; RR-12 PR #279 commits; RR-13 PR #289 body; RR-14 #96 / CHANGELOG; RR-15
PR #301 / CHANGELOG; RR-19 #177 / CHANGELOG). Every "open" names a tracking issue
confirmed open against the issue tracker (#106, #107, #108, #98, #122, #132, #284,
#292). The design-time hunt that preceded coding is the META issue #138; of the
open architectural items it raised, the single-writer head-of-line block is now
fixed (RR-19, #177), and the joint disk budget and the bounded-loss cap on a large
log remain open (RR-03 and RR-05).
