# IronBus consolidated FMEA

This is the consolidated **Failure Mode and Effects Analysis** for IronBus: the
single operator-facing and reviewer-facing table that aggregates every per-issue
failure mode (enumerated across the parent design issues #1 through #22 and their
task children) into one place, de-duplicated, on one severity scale, each keyed to
the issues it originates in, the real metric or log or exit-code that detects it,
the mitigation decision and the issue that resolved it, and the test or gate that
proves it is handled (#129).

Every per-issue digest scattered a "Failure considerations" list across 22 issues,
so no one could see the whole risk surface, de-duplicate the recurring cross-issue
modes (power-loss-before-fsync, fsyncgate, clock regression, edge OOM, retry storm,
operator-unsafe-default, each appearing in five or more issues), or map each mode to
the test that proves it. This document owns that aggregation. The code, the issues,
and [METRICS.md](METRICS.md) are canonical: every detection signal below is a real
metric, gauge, typed error, or exit code cross-checked against METRICS.md and the
source, and every test owner is a real test, corpus, gate, or honestly marked
"device-only" / "not yet covered" cross-checked against the test tree.

## How this relates to RISK_REGISTER.md (and how it does not duplicate it)

[RISK_REGISTER.md](RISK_REGISTER.md) is the **design-time** adversarial flaw-hunt
(#138): a category-organized prose register (RR-01..RR-23) of failure modes, the
mechanism mitigating each, the real defects the review process caught and fixed,
and the honest open risks. It is keyed by **category** (durability, concurrency,
resource-exhaustion, recovery, observability, security, operational, performance)
and reads as narrative.

This FMEA is the **operator-facing** complement and is a **different shape**: a
flat, per-issue-aggregated table keyed by **origin issue + test owner**, with one
row per de-duplicated failure mode, one severity scale across all of them, and a
named detection signal and test owner for every row. Where the risk register
explains *why* a risk exists and *whether* the design defends it, this FMEA gives
an operator the one-line answer to "what breaks, how would I see it, and what test
proves it is handled". Each row cross-links to its RR entry where one exists, so the
two documents reference rather than duplicate each other. RISK_REGISTER.md owns the
prose; FMEA.md owns the at-a-glance table and the CI coverage gate (below).

## Severity scale (one scale, used for every row)

| Severity | Meaning |
|----------|---------|
| **Critical** | Can lose, corrupt, or silently drop an **acknowledged** record, or wedge the node so it cannot recover, if the mitigation fails. A Critical row MUST have a green #21 verification gate before a tagged release (per #22). |
| **High** | Can lose **unacknowledged** data, shed accepted-but-not-yet-durable load, deny service, or exhaust a bounded edge resource (RAM, disk, file descriptors), but never silently loses an acknowledged record. |
| **Medium** | Degrades correctness of a derived or advisory quantity (ordering metadata, a counter, retention timing) without losing record data. |
| **Low** | Operational or tooling friction (a build break, a flaky self-test, a missing observability nicety) with no data or availability effect. |

"#21 verification gate" means the verification-strategy artifact (#21): the crash
class in `crates/ironbus-storage/tests/crash_recovery.rs`, the corruption corpus in
`crates/ironbus-storage/tests/corruption_corpus.rs`, the conformance corpus and
recovery sweep (`conformance_corpus.rs` / `conformance_recovery.rs`), the loom
concurrency models (`tools/loom-tests/`, the nightly `loom` job), the golden-path
acceptance run (`crates/ironbus-cli/tests/acceptance.rs`, the CI
`golden-path acceptance gate (#133)` job), or the macro-bench injected-stall proof
(`crates/ironbus-bench/tests/injected_stall.rs`).

## The consolidated FMEA table

One row per de-duplicated failure mode. A mode that several issues raised is a
SINGLE row whose "Origin issues" column lists every issue that raised it (the
de-dup is explicit). The detection signal names a real metric / gauge / typed error
/ exit code from METRICS.md or the source; the test owner names a real test or gate,
or honestly says "device-only" or "not yet covered".

| ID | Failure mode | Origin issues | Severity | Detection signal | Mitigation (+ resolving issue) | Test owner |
|----|--------------|---------------|----------|------------------|--------------------------------|------------|
| F1 | **Power loss before the covering fdatasync reaches stable storage**, between a producer ack and durability. | #1, #6, #20, #48 | Critical | The recovery loss report (`ironbus.loss-report.v1`); `ironbus_recovery_loss_records{reason=torn_tail}` and `ironbus_recovery_truncated_bytes` at startup. | Ack ONLY after the `fdatasync` covering the record returns (I2, ack-implies-durable); group commit amortizes the sync but never acks before it, so acknowledged loss on power loss is zero (#6, #48, #177). See RR-06. | `crash_recovery.rs`: `power_loss_at_every_boundary_no_roll` / `_with_rolling`, `a_torn_write_during_append_is_truncated_by_recovery`; the I2 property `an_ack_is_sent_only_after_the_covering_fsync_completes_i2` (`actor.rs`); acceptance steps 6-7. |
| F2 | **fsyncgate: `fdatasync` returns EIO once**, a naive retry then "succeeds", but the kernel already dropped the dirty page clean, so the data is silently gone. | #6, #20, #21, #48 | Critical | `ironbus_writer_healthy` flips to `0` (the integrity-freeze gauge); `Log::sync` returns the typed `WriterFrozen`; no `PubAck` is sent. | HALT the writer to a read-only frozen state on a sync error; NEVER retry-and-trust a failed sync. Ack is withheld, the active segment is dropped (#6, #48). See RR-19 / DURABILITY.md "fsyncgate". | `crash_recovery.rs`: `fatal_fsync_freeze_loses_no_acked_record`, `fatal_fsync_freeze_during_a_roll_loses_no_acked_record`, the seeded sweep `a_sync_fault_at_any_point_loses_no_acked_record`. |
| F3 | **Torn tail after a brownout**: a partial record (torn header, body, or trailer) at the active-segment tail; reading it as a record corrupts state or panics. | #5, #7, #8, #43 | Critical | `ironbus_recovery_truncated_bytes` and `ironbus_recovery_loss_records{reason=torn_tail}`; `recovered_truncated_bytes()`. | Longest-valid-prefix recovery truncates the torn or unsynced tail back to the last intact, fully-synced record and REPORTS the dropped bytes (never hidden); a torn tail is labeled not-data-loss (#7, #43). See RR-06. | `crash_recovery.rs`: `tail_truncation_drops_the_partial_record`; `corruption_corpus.rs`: `torn_tail_partial_record_header` / `_body` / `_trailer`; acceptance step 7. |
| F4 | **Corruption-skip / poison record**: an on-disk bit-flip in a checksum-valid-looking record (or its body) is read back, or a corrupt record stalls recovery. | #5, #8, #56, #146 | Critical | `ironbus_recovery_loss_records{reason=corrupt_record_header\|corrupt_record_body}`; the typed `DecodeError::BadBodyCrc` / `BadXxh3`; `ironbus_quarantine_bytes` (the forensic copy). | Per-record CRC32C (header + body), plus an independent xxh3-64 over the same body range at/above 64 KiB; stop-at-first-bad-frame drops `[bad, EOF)` as ONE bounded+reported corruption event; the corrupt span is copied (not moved) to `quarantine/` (#8, #146, #134). See RR-05. | `corruption_corpus.rs`: `flipped_record_header_crc`, `flipped_record_body_crc`, `flipped_xxh3_field_on_over_threshold_record`, `mid_log_*_corruption_stops_at_the_first_bad_record`; `quarantine_recovery.rs`: `a_corrupt_segment_is_copied_to_quarantine_while_recovery_recovers_the_prefix`. |
| F5 | **Bounded-loss cap breach turns reported loss into unbounded silent loss**: recovery would drop more than the per-event or global cap allows. | #7, #8, #21, #120 | Critical | The typed `StorageError::ExcessiveRecoveryLoss`; `Log::open` refuses to open (fail-closed, non-zero exit), rather than accept the loss. | I3 bounded-loss caps (per-event = one segment or 64 MiB; global = 1% of durable bytes, floored at the per-event cap) computed in `check_caps`; exceeding either FAILS CLOSED instead of silently accepting (#120, #8). See RR-05 and loss-report.v1.md. | `corruption_corpus.rs`: `all_zeros_whole_segment_fails_closed`; `crash_recovery.rs`: `recovery_fails_closed_when_a_fault_strikes_the_roll_forward`; loss-report golden `golden_loss_report_v1_serialization_is_frozen` (`loss.rs`). |
| F6 | **Disk full / unbounded log growth** fills the device; further writes fail and the node wedges. | #10, #13, #20 | High | `ironbus_produce_rejected_total`; the typed `StorageError::AtCapacity` surfaced to the producer as a stable `at capacity` reply, connection stays open. | Drop-new shed: a durable-byte cap (`--max-total-bytes`) rejects an over-cap produce BEFORE any write; the consumer-safe retention reaper frees whole old sealed segments under byte/age/count bounds, never below the slowest consumer (#10, #13). See RR-03. | `golden_path.rs`: `golden_path_overload_spills_then_sheds_at_the_byte_cap`; acceptance step 5; storage/engine reap + at-capacity unit tests. |
| F7 | **Drop-oldest force-reap skips data out from under a lagging consumer** (a below-earliest truncation). | #13, #82, #96 | High | `ironbus_segments_force_reaped_total` (the loss-bearing reclamation) and the consumer-side `ironbus_truncations_total` / `ironbus_truncated_records_total`; one-time `Poll::Truncated`. | Opt-in `--disk-full-policy drop-oldest` force-reaps to accept the produce, surfacing exactly ONE `Poll::Truncated` skip to a consumer below earliest-retained, counted so the skip is never silent (#82, #96). See RR-03 / RR-14. | `golden_path.rs`: `golden_path_drop_oldest_truncates_a_stuck_consumer`; acceptance step 8; the frozen-taxonomy test pins both counters. |
| F8 | **Poison-message redelivery loop**: a message that always fails processing is nacked and redelivered forever, blocking the group. | #9, #63 | High | `ironbus_dead_lettered_total`, `ironbus_dlq_records_total` (durable DLQ depth), `ironbus_last_dead_lettered_offset`. | MaxDeliver to a durable, segmented DLQ via a crash-atomic exactly-once move (append+fsync the poison record, THEN commit the source cursor past it); idempotent on `(group, source offset)` (#63). Unlimited deliver only behind `--allow-unlimited-deliver` + a startup WARN. See RR-04. | Engine tests `a_poisoned_message_is_durably_written_to_the_dlq_and_committed_past`, `the_no_poison_path_never_creates_or_touches_the_dlq`, `counters_track_a_dead_letter`. |
| F9 | **Clock regression / boot-at-epoch**: a backward wall-clock jump or RTC-less boot-at-epoch corrupts lease, dedup, or retention-age math, or makes a metric go backwards. | #3, #9, #13, #20 | Medium | `ironbus_uptime_seconds` (monotonic-derived, never regresses on an NTP step); a backward jump only makes the age reaper MORE conservative (no premature delete). | The broker-assigned monotonic `seq` / log offset is the SOLE ordering authority and never consults the wall clock (I6); the wall-clock `timestamp` is advisory; age retention is fail-safe under a backward jump; uptime derives from the injected monotonic clock seam (#20, EDGE_CONSTRAINTS.md, #3). | `crash_recovery.rs`: `recovery_is_a_pure_function_of_the_durable_bytes` (timestamp never participates); the monotonic-clock seam unit tests; acceptance fan-out step (one durable order). |
| F10 | **Edge OOM / RAM-ceiling breach**: uncounted buffers push RSS past the device RAM ceiling and the kernel OOM-kills the broker. | #20, #10, #19, #115 | High | No boot guard or runtime RSS check is enforced today; the **closest live signal** is `ironbus_ram_headroom_bytes` (`ram_ceiling_bytes` minus RSS, `-1` when unset) and `ironbus_produce_saturated`. | Per-source RAM is BOUNDED by config (per-connection in-flight by `consumer_credit`/`consumer_credit_bytes`; read buffers by `MAX_FRAME_LEN`/`max_connections`; per-group state by `max_groups`/`max_in_flight`; the active segment is written straight to disk so `max_segment_bytes` bounds DISK not RSS). The 64 MiB `tiny` budget sums under the ceiling (#115, #20). **Honest gap:** the ceiling is NOT enforced (no refuse-to-boot RSS guard) and the shipped defaults are not edge-safe; that guard is the #115 / #17 follow-up. See RR-01 and RAM_BUDGET.md. | RAM_BUDGET.md is the source-derived budget; `ironbus_ram_headroom_bytes` is exercised by the #118 edge-metrics tests. The refuse-to-boot RSS guard is **not yet covered** (follow-up #115). |
| F11 | **Retry storm / thundering herd**: client retries multiply load under overload into a sustained collapse. | #10, #11, #69 | High | The structured `retry_after_ms` (0 = retry-now, `0xFFFFFFFF` = do-not-retry/shed) and `shed` wire fields are SPECIFIED in BACKPRESSURE.md; no live retry-budget metric exists yet. | A per-client 10% retry budget over a 60 s window (client-side + broker-rechecked), plus a `retry_after_ms` / do-not-retry signal and an egress AIMD limiter proven not to amplify (#69, #11). **Honest gap:** SPECIFIED, not built; IronBus ships only drop-new/drop-oldest + per-consumer credit today. See BACKPRESSURE.md. | **Not yet covered** (the retry budget, the wire fields, the limiter are the #69/#11 implementation residual). The macro-bench injected-stall proof (`injected_stall.rs`) covers the related overload-tail-visibility property. |
| F12 | **Operator ships an unsafe default** (durability relaxed, an over-budget profile, unlimited redelivery, drop-oldest on a durable topic) without an explicit acknowledgement. | #1, #6, #14, #20 | High | A startup WARN on `--allow-unlimited-deliver`; the materialized-config startup log line (active profile + every resolved knob); a usage error on an unknown `--profile`. | Safe-by-default: the only durability level shipped is `sync` (ack-implies-durable); the relaxed `interval`/`async`/`none` levels are SPECIFIED-NOT-IMPLEMENTED and gated behind an explicit data-loss acknowledgement; unlimited deliver requires the explicit flag + WARN; the config validator rejects coupled-set violations whole-config-before-apply (#14, #6). **Honest gap:** the file/profile validator's full coupled-set rejection is the #85/#86 residual. See RR-13 and CONFIG.md. | `main.rs` parse test `serve_parses_the_allow_unlimited_deliver_flag` (the flag is honored, not a parse hang, RR-13); the #87 profile selection + materialized-config tests. Full coupled-set validation is **not yet covered** (#86). |
| F13 | **Dedup memory exhaustion**: an attacker floods distinct `producer_id`/`msg_id` values, growing the dedup window without bound. | #33, #3 | High | The dedup ring is bounded; a flood is rejected at the wire boundary (typed). No silent growth: `ironbus_dedup_hits_total` / `ironbus_dedup_out_of_window_total`. | Total dedup memory is hard-bounded: distinct producer windows capped (`--dedup-max-producers`, default 4096, LRU) with opportunistic reaping of time-expired windows; `producer_id`/`msg_id` each capped at 256 bytes (typed rejection); bound is `max_producers * max_ids * per_entry` (#33). | The `ironbus-core` dedup-ring tests (count + time-window eviction, LRU producer eviction, the per-id byte cap); the frozen-taxonomy / metric-name golden tests pin the two counters. |
| F14 | **Unbounded named-group memory**: the wire names work-groups, so a client subscribing to unbounded distinct names makes the broker allocate per-group cursor + lease state indefinitely. | #9, #240 | High | The typed `EngineError::TooManyGroups` (rejected before allocation) and `EngineError::InvalidGroupName`. | A live-group cap (`--max-groups`, default 1024) rejects a new NAMED group past the cap before allocating; names validated (1-128 graphic-ASCII bytes); the default group is exempt; idle named-group eviction reclaims a caught-up, lease-free slot with a durable head checkpoint (#240, #277). See RR-02. | Engine tests for the cap reject + name validation + `lowering_the_group_cap_still_recovers_every_durable_group` (RR-10); the idle-eviction loss-free tests. |
| F15 | **Unbounded per-consumer occupancy**: one consumer fetches without acking and pins unbounded in-flight messages, blowing the RAM ceiling and starving peers. | #9, #10, #65 | High | `ironbus_in_flight` / `ironbus_group_in_flight{group}`; the per-connection credit ceiling caps a stuck consumer to its own slots. | Two composed per-connection budgets: message-count credit (`--consumer-credit`, default 64) and byte budget (`--consumer-credit-bytes`, default 8 MiB), effective credit = `min(...)` with a one-message floor; derived from the connection-scoped `leased` set so accounting cannot drift (#65, #275). See RR-01. | Session credit-cap / restore-on-ack/nack/term / isolation / redelivery-accounting tests; the end-to-end over-a-real-server credit test; CLI flag-validation tests. |
| F16 | **Connection flood / slowloris / oversized frame**: an unauthenticated peer opens unbounded connections, holds them open without progress, or declares a huge frame length to force a giant allocation. | #16, #18, #10 | High | Connections past the cap are dropped; a slowloris hits the 30 s `CONNECTION_TIMEOUT`; an oversized length is the typed `FrameTooLarge` BEFORE allocation. | A connection cap (`--max-connections`, default 256, slot released on panic), a 30 s read/write deadline, and `MAX_FRAME_LEN` (16 MiB + 64 KiB) validated before any body allocation (#105). **Honest gap:** the cap and timeout are TOTAL, not per-source; per-source limits are #107. See RR-08 and THREAT_MODEL.md (T7). | `frame.rs` `FrameTooLarge` / `EmptyFrame` decode tests; server connection-cap / `ConnectionSlot` drop-guard tests; the health-endpoint 8 KiB / 5 s bound tests. |
| F17 | **Broadcast cumulative-ack silent drop**: two subscribers on one broadcast group hold competing in-flight leases and a cumulative ack commits past (silently drops) a peer's unacked message. | #9, #63, #288 | Critical | The typed `EngineError::BroadcastGroupBusy` (a second concurrent SUB rejected) and `EngineError::BroadcastGroupNotNamed` (the default group cannot be a broadcast group). | A broadcast group accepts AT MOST ONE active subscriber; `set_broadcast_in` refuses to flip a group carrying competing in-flight state; the slot frees on UNSUB / switch / disconnect; `--broadcast-group ""` is a clean usage error (#288, #63). See RR-04 (broadcast path). | The #288 regression tests reproducing both exploits and the valid single-consumer case; the over-the-wire disconnect-frees-the-slot test; the engine + CLI default-group reject tests. |
| F18 | **Single-Mutex append head-of-line block**: a single slow fsync (an SD/eMMC GC pause of hundreds of ms) blocks EVERY connection, not just the producer that triggered it. | #1, #4, #17 | High | `ironbus_fsync_seconds` / `ironbus_fsync_duration_seconds` (the durability-barrier latency histogram); a stalled produce no longer blocks another connection's ping. | The `Engine` is owned by a single append-actor thread; handlers fan in over a bounded `sync_channel` and never hold a lock across an fsync; the actor group-commits a drained batch with ONE `fdatasync`; pings are answered without touching the actor (#177). **Residual:** a stalled fsync still blocks WORK needing durable state (single-writer rule). See RR-19. | The acceptance tests that stall a producer's `sync_data` and prove another connection's ping still returns, and that a batch issues one `fdatasync` not N (`actor.rs`); the I2 property `..._i2`. |
| F19 | **No auth / no TLS on a non-loopback bind** exposes produce/consume/ack and `/metrics` to any reachable peer, and plaintext on the wire to any observer. | #16, #18, #106, #107 | High | None enforced today: nothing refuses a non-loopback bind. The default bind is `127.0.0.1:7777` (a default, NOT an enforced invariant). | **Honest gap (OPEN):** connection-scoped auth + three-scope authz (#106) and TLS 1.3 + a fail-closed non-loopback bind invariant (#107) are SPECIFIED, not built. Today IronBus is a trusted-network / localhost broker; the connection cap + slowloris timeout (F16) bound DoS but NOT access. See RR-16 / RR-17, THREAT_MODEL.md (T2-T4), AUTHENTICATION.md, TRANSPORT.md. | **Not yet covered in code** (#106, #107). Acceptance step 2 proves the health endpoints come up bound to loopback (the default), not that a non-loopback bind is refused. |
| F20 | **Metrics cardinality OOM**: an unbounded set of distinct consumer labels makes the metric registry allocate without bound (OOMing the very node metrics protect). | #16, #97 | High | `ironbus_consumer_labels_dropped_total` (distinct labels refused, once each); the over-cap lag folds into `ironbus_consumer_lag_records{consumer="__overflow__"}` so total lag stays visible. | A hard 1024-distinct-series cap + an idempotent overflow fold; the registry has a fixed memory ceiling (~161 KiB) independent of record count, disk size, and live-consumer count (#97). | The registry tests: `the_registry_memory_ceiling_is_fixed_and_bounded`, `the_append_and_commit_hot_path_does_not_allocate`, `the_scrape_walk_does_not_allocate`; the frozen-taxonomy test pins the counter. |
| F21 | **Resilience counters lost on crash**: the in-memory `ironbus_*_total` counters reset to zero on restart, so a crash erases the running tallies and breaks the monotonicity a counter implies. | #16, #98 | Medium | `ironbus_counter_checkpoint_repair_total` (a reconciliation that raised a recovery-loss value above its snapshot, the post-crash lower-bound recovery firing). | Counters snapshot to a CRC'd `counters.ckpt` on the checkpoint cadence + graceful-shutdown flush and seed from it at startup (a `kill -9` loses at most the post-snapshot increments: a monotonic lower bound). The recovery-loss family (`ironbus_records_skipped`, `ironbus_bytes_skipped`, the recovery-head of `ironbus_last_skip_offset`) is strengthened to a strict cross-restart monotonic max(snapshot, replay) (#98, #307). See RR-22. | The counter-checkpoint snapshot + restart-seed tests and the #307 checkpoint-plus-replay reconciliation tests (the `max(snapshot, replay)` raise, the corrupt-`counters.ckpt`-never-blocks-recovery path). |
| F22 | **Sequence gap / recycled stale frame**: a checksum-valid record carries an out-of-order sequence (a recycled or mixed-up frame) and recovery would replay garbage. | #5, #8, #44 | Critical | `ironbus_recovery_loss_records{reason=sequence_gap}`; recovery abandons the segment at that record. | Recovery's intact-record predicate includes sequence continuity; a checksum-valid but out-of-order frame ends the valid prefix as a `SequenceGap` (code 5) reported loss; segment ids are NEVER recycled in v1 so this is a defense, not an expected steady-state event (#44, #8, ADR-0002). See RR-05 / RECOVERY.md decision table. | `crash_recovery.rs`: `recovery_rejects_a_synthesized_sequence_gap`; `corruption_corpus.rs`: `recycled_frame_with_a_stale_sequence`. |
| F23 | **Segment chain gap / corrupt segment header**: a missing segment in the chain, or an unreadable segment header, would silently truncate or misread the log. | #5, #8, #42 | Critical | `ironbus_recovery_loss_records{reason=corrupt_segment_header}`; a corrupt active-segment header fails closed; a chain gap ends the valid prefix. | The segment-header per-segment floor and the chain-continuity check end the valid prefix at a missing/unreadable segment; a corrupt header costs at most one segment as one bounded event under the I3 caps; a corrupt ACTIVE-segment header fails closed (#42, #8). See RR-05 / RECOVERY.md. | `corruption_corpus.rs`: `segment_chain_gap`, `unsealed_non_final_predecessor`, `flipped_segment_header_crc`, `truncated_short_segment_header`, `unsupported_segment_header_version` / `_checksum_algo`. |
| F24 | **Concurrency interleaving bug** in the append-actor handoff, the commit index, or the segment/connection refcount (a memory-ordering or interleaving hazard a stress test would miss). | #21, #122 | Medium | None at runtime (a latent correctness bug). The model checker is the detector. | The concurrent handoffs use ordinary std primitives (a `sync_channel`, per-command reply channels), not hand-rolled lock-free structures, so the surface is small; loom exhaustively permutes the three concurrency seams. **Residual:** loom becomes load-bearing only if a hand-rolled lock-free path is introduced (#122). See RR-23. | `tools/loom-tests/tests/loom_concurrency.rs` (the nightly `loom` job): `commit_index_observe_never_sees_an_index_without_its_data`, `wal_handoff_delivers_each_item_exactly_once_in_fifo_order`, `wal_handoff_two_producers_lose_no_item_under_a_full_channel`, `refcount_drops_exactly_once_after_the_last_reference_releases`. |

## Coverage gaps with no test owner (honest follow-ups)

These rows have a real mitigation DESIGNED but no shipped test that proves it,
called out so a reviewer does not mistake a specified control for a verified one:

- **F10 (edge OOM):** the refuse-to-boot RSS guard and the auto edge profile are
  not built; only the per-source byte/count BOUNDS are enforced and the RAM budget
  is a source-derived accounting, not a runtime gate. Follow-up: #115, #17.
- **F11 (retry storm):** the retry budget, the `retry_after_ms` / `shed` wire
  fields, and the egress AIMD limiter are SPECIFIED only. Follow-up: #69, #11.
- **F12 (unsafe default):** the full coupled-set config-validation rejection is not
  the shipped `flag > env > default` resolver's behavior yet. Follow-up: #86.
- **F19 (no auth / no TLS):** the entire auth + TLS + fail-closed-bind surface is
  OPEN. Follow-up: #106, #107.

## How the CI coverage check works (the #129 mechanized criterion)

`scripts/ci/fmea-coverage.sh` is the deterministic coverage gate. It holds a
**curated list of required failure-mode IDs** (`F1`..`Fn`), and for each one a set
of **anchor keywords** that MUST appear in this document. The script asserts that:

1. every required `Fn` ID appears as a table-row ID in `docs/FMEA.md`, and
2. each required mode's anchor keywords are present (so a row cannot be gutted to a
   placeholder while keeping its ID), and
3. the IDs are contiguous (`F1..Fn` with no gap), so a row cannot be silently
   dropped from the middle.

Deleting a row, renumbering it, or emptying its mitigation text fails the gate. The
check is pure POSIX `sh` (shellcheck-clean), needs no toolchain, and is wired into
CI as the `fmea-coverage` job (and runnable locally as
`sh scripts/ci/fmea-coverage.sh`).

### Extending it when a new failure mode is added

When a new per-issue failure mode is enumerated:

1. Add a new contiguous row to the table above (the next `Fn`), with all required
   columns, a real detection signal cross-checked against METRICS.md, and a real
   test owner (or an honest "not yet covered" + a follow-up issue).
2. Add the new ID and its anchor keyword(s) to the `REQUIRED` list at the top of
   `scripts/ci/fmea-coverage.sh` (the list is a single, commented, easy-to-edit
   block).
3. Run `sh scripts/ci/fmea-coverage.sh` locally to confirm it passes.

The gate is intentionally a curated keyword list rather than a scrape of every
issue body: it is low-false-positive (it never fails for a reason unrelated to this
table), deterministic (no network, no `gh`, no git history), and forces a deliberate
edit here whenever the risk surface changes, which is exactly the #129 contract that
"a new failure mode added to any issue must appear here".

## Provenance

Every detection signal above is a metric, gauge, typed error, or exit code present
in [METRICS.md](METRICS.md), the loss-report schema, or the source at the time of
writing; no metric or test was invented. Every test owner is a real test or gate in
the tree (`crates/ironbus-storage/tests/crash_recovery.rs`,
`crates/ironbus-storage/tests/corruption_corpus.rs`,
`crates/ironbus-storage/tests/quarantine_recovery.rs`,
`crates/ironbus-cli/tests/golden_path.rs`,
`crates/ironbus-cli/tests/acceptance.rs`,
`crates/ironbus-bench/tests/injected_stall.rs`,
`tools/loom-tests/tests/loom_concurrency.rs`, and the engine / session / registry
unit tests) or an honest "device-only" / "not yet covered" with the follow-up
issue named. The de-duplicated cross-issue modes (F1 power-loss, F2 fsyncgate, F9
clock regression, F10 edge OOM, F11 retry storm, F12 unsafe default) are each a
SINGLE row whose origin-issues column lists every issue that raised them. The
design-time category register is [RISK_REGISTER.md](RISK_REGISTER.md) (#138); this
operator-facing per-issue aggregation is #129.
