<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus CLI reference map

This is the exhaustive command-surface reference for the `ironbus` binary: every
subcommand, every flag with its type, default, and unit, every exit code, and which
verbs run **online** (connect to a broker) versus **offline** (read a data directory
directly). It is derived from and cross-checked against the CLI source,
[`crates/ironbus-cli/src/main.rs`](../crates/ironbus-cli/src/main.rs); the code is
canonical, so every default below cites the `DEFAULT_*` constant it comes from.

This document is the flag-and-exit-code map. For the worked examples, the narrative
walkthrough (durability, restart-and-resume, consumer groups, health endpoints), and the
end-to-end demo, see the prose guide [`USAGE.md`](USAGE.md). The two are complementary:
USAGE.md tells you how to use the binary, this file is the complete table of what every
flag and code does.

> Scope: this map covers the command surface that the binary SHIPS today. The frozen
> design in issue #136 specifies a larger verb tree (`tap`, `wire`, `info`, `consumer`,
> `segments`, `dlq`, `retention`, `config`, `recovery report`, `completions`) and a
> versioned `--json` schema contract; those verbs are NOT implemented in the current binary
> and are deliberately absent here. The `scrub` and `repair` verbs (#92) and their
> versioned `--json` schemas (`ironbus.cli.scrub.v1` / `ironbus.cli.repair.v1`), the
> `top` verb (#93) with its `ironbus.cli.top.v1` `--json` schema, and the OFFLINE mutating
> `admin consumer-reset` / `admin dlq-redrive` verbs (#299) with their
> `ironbus.cli.admin-consumer-reset.v1` / `ironbus.cli.admin-dlq-redrive.v1` schemas, ARE
> implemented and documented below (the MUTATING WIRE admin verbs and `force-reap` remain
> deferred to the authed admin surface #380/#106). This reference enumerates only what
> `main.rs` actually parses and runs.

## Command summary

| Subcommand | Mode | Platform | What it does |
|------------|------|----------|--------------|
| `serve` | online (runs the broker) | Unix only in v1 | Open the on-disk log under `--data-dir` (or, with the opt-in `--storage memory`, an ephemeral in-memory log, #443) and serve the wire protocol on `--addr`. |
| `pub` | online (connects) | any | Append one message and print its durable offset. |
| `sub` | online (connects) | any | Fetch up to a credit of messages, print each, optionally dispose of the batch. |
| `cumulative-ack` | online (connects) | any | Commit a BROADCAST group's cursor up to (exclusive) `--up-to` in one move (ack-all-up-to-offset, #288). |
| `peek` | offline (reads `--data-dir`) | Unix only in v1 | Show a bounded window of durable records from a stopped broker's data directory. |
| `dump` | offline (reads `--data-dir`) | Unix only in v1 | Stream every durable record (or, with `--dlq`, the dead-letter sink). |
| `scrub` | offline (reads `--data-dir`) | Unix only in v1 | Strictly read-only full integrity scan: report every corruption / torn-tail / checksum issue (the plan). Never writes. |
| `repair` | offline (reads `--data-dir`) | Unix only in v1 | Default the same read-only plan as `scrub`; `--apply` quarantines and truncates under the exclusive lock (recovery made explicit). |
| `admin consumer-reset` | OFFLINE MUTATING (reads + rewrites `--data-dir`) | Unix only in v1 | Rewrite a work-group's durable cursor checkpoint to `--to <offset\|earliest\|latest>`, clamped to the durable range, under the exclusive lock (broker stopped). An out-of-range explicit offset is rejected. (#299) |
| `admin dlq-redrive` | OFFLINE MUTATING (reads + rewrites `--data-dir`) | Unix only in v1 | Re-inject the dead-lettered records from the durable DLQ sink back onto the main log, crash-safely and idempotently, under the exclusive lock (broker stopped). (#299) |
| `top` | LIVE (polls `/admin`) any; OFFLINE (reads `--data-dir`) Unix only in v1 | Strictly read-only status view. LIVE polls the broker's `/admin` v1 JSON; OFFLINE renders only the file-derived panels behind a mandatory banner. |
| `help` / `--help` / `-h` | neither | any | Print the usage banner. |
| `version` / `--version` / `-V` | neither | any | Print a single `ironbus <version>` line. |

A subcommand is required; an unknown subcommand or a missing one is a usage error
(exit 1). `serve`, `peek`, `dump`, `scrub`, and `repair` are Unix only in v1 because the
on-disk storage uses positioned IO the Windows path does not yet implement; on a non-Unix
host they fail with exit 70. `pub` and `sub` are thin wrappers over `ironbus-client` and run
anywhere.

## Online versus offline

- **Online** verbs (`serve`, `pub`, `sub`) speak the length-framed TCP wire protocol on
  `--addr` (default `127.0.0.1:7777`, loopback only). `pub` and `sub` connect to a
  running broker; `serve` IS the broker. If the broker cannot be reached, an online verb
  exits 5 (unreachable).
- **Offline** verbs (`peek`, `dump`, `scrub`, `repair`) decode the on-disk data directory
  directly with NO server running, via the storage crate's `OfflineReader` (and, for
  `repair --apply`, `Log::open`). They read only up to the durable high-water mark and stop
  at the first torn or bad-CRC record (the same boundary recovery uses), marking, never
  hiding, any tail they skipped. `peek`/`dump`/`scrub` never mutate the directory; only
  `repair --apply` writes, and only under the exclusive data-dir lock. There is no online
  fallback for the offline verbs: they are pure offline readers (or, for `repair --apply`,
  an offline recovery).
- **Dual-mode**: `top` is BOTH. Its LIVE mode is an `/admin` HTTP client (any platform); its
  OFFLINE mode is a pure file-derived reader (Unix only in v1). Which mode runs is chosen by the
  flag (`--addr`/`--health-addr` vs `--data-dir`), and a mandatory banner names the active mode so
  the two are never confused.

### Memory-mode brokers and the offline verbs (#443, #444)

A broker run with `serve --storage memory` keeps NO on-disk state: when it exits (cleanly or by
crash), it leaves NO data directory behind, so there is nothing for `peek`, `dump`, `scrub`,
`repair`, `admin consumer-reset`, `admin dlq-redrive`, `migrate`, or `top --data-dir` to inspect,
ever. The LIVE surfaces are the ONLY introspection story for a memory-mode broker: `/healthz`,
`/readyz`, `/metrics`, `/admin` (with `--enable-admin`), and `ironbus top --addr` all work
unchanged while it runs, and nothing works after it stops. The offline mutating verbs have no
memory-mode counterpart either: there is no stopped-broker state to reset or redrive (an
operator who needs a post-mortem or an offline mutation needs the disk backend, on tmpfs if
flash wear is the concern; see [`EDGE_TUNING.md`](EDGE_TUNING.md)).

`--storage` itself is a `serve`-only flag. Every offline verb's strict parser rejects it as an
unknown flag (a usage error, exit 1, before touching the filesystem), so `peek --storage memory`
can never be mistaken for a working invocation; this rejection is pinned by a test. The offline
verbs also read no `IRONBUS_*` environment variables, so an `IRONBUS_STORAGE=memory` in a unit
env file cannot leak into them. The residual confusion case is honest and unchanged: pointing an offline
verb's `--data-dir` at a directory that does not exist (for example, because the broker that
"owned" it was a memory broker and never created one) is the ordinary exit 2 not-found.

## `serve` (online; Unix only in v1)

Starts the broker: opens (creating if absent) the durable log under `--data-dir`, binds
the wire protocol on `--addr`, optionally binds the health endpoints on `--health-addr`,
and runs until signalled. SIGINT or SIGTERM triggers a graceful stop: the serve
loop stops accepting, flushes every work-group's committed cursor, and exits 0. SIGHUP is
the runtime config-reload trigger (#380, refs #88): it re-reads the `--config` file and
applies the live-reloadable subset (the consumer-safe retention bounds and the disk-full
policy) to the running broker without dropping connections; a restart-required key change is
reported on stderr but not applied live, and a cold-key change is rejected. With no `--config`
set, SIGHUP is a logged no-op. SIGHUP keeps the broker running — it never stops it.

`--data-dir` is REQUIRED under the default `--storage disk`; omitting it is a usage error.
Under the opt-in `--storage memory` (#443) the rule inverts: `--data-dir` must be ABSENT
(see the memory-mode notes below). `serve` takes no positional arguments. All numeric flags
reject a non-numeric value as a usage error before the broker opens.

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--data-dir <dir>` | path | required (no default) | path | The directory holding the segmented log, the cursor checkpoints, and the `dlq/` sink. |
| `--config <path>` | path | none (no file) | path | Load a TOML configuration FILE (#382). It slots BETWEEN env and default, so the precedence is **flag > env > FILE > default**: a file key beats the compiled default, but an env var or a flag still overrides it. The file is whole-read, parsed (the pure-Rust `toml` crate), and STRICTLY validated before the broker opens: an unknown key is a fatal usage error with a did-you-mean (downgradable with `--allow-unknown-config`), a broken file fails with the path + line/column, durations use `{ms,s,m,h,d}` and byte sizes the binary `{B,KiB,MiB,GiB,TiB}` (unit required, decimal-SI rejected), and the coupled-set rules are checked as a whole. The frozen sections are `[durability]`, `[storage]`, `[retention]`, `[backpressure]`, `[delivery]`, `[network]`, the bare `profile` key, and the reserved-but-tolerated `[observability]`/`[auth]`/`[compression]`. With no `--config` the resolution is byte-for-byte the historical flag > env > default. The schema is `docs/CONFIG.md`. |
| `--allow-unknown-config` | bool flag | off | n/a | Downgrade an UNKNOWN config-FILE key from a fatal error to a warning (for a staged upgrade). The unknown key is logged and ignored, never wired into a knob. Has no effect without `--config`. |
| `--profile <edge-tiny\|balanced\|throughput>` | enum | `balanced` (the compiled `DEFAULT_*` set, `PROFILE_SCHEMA_VERSION`) | n/a | Select a compiled-in, versioned tuning PROFILE (#87): a coherent group of knobs (`--max-segment-bytes`, `--consumer-credit`, `--consumer-credit-bytes`, `--max-connections`, `--max-groups`, `--max-in-flight`, `--disk-full-policy`, `--checkpoint-interval`, `--visibility-timeout-ms`, `--max-deliver`) set in one move. Applied FIRST, then any explicit env var or flag overrides an individual knob, so the precedence is **profile < env < flag**. `balanced` IS the shipped default set (so it is byte-identical to passing no profile); `edge-tiny` is the small-RAM, flash-gentle edge preset (8 MiB segments, 8 / 256 KiB credits, 32 connections, `drop-new`); `throughput` widens every buffer for a multi-core hub (256 MiB segments, 512 / 64 MiB credits, 1024 connections, `drop-oldest`). A profile NEVER sets `--data-dir` or any network/TLS key. An unknown name is a usage error. The exact per-profile values are frozen in `docs/CONFIG.md` section 6. |
| `--addr <host:port>` | string | `127.0.0.1:7777` (`DEFAULT_ADDR`) | host:port | The wire-protocol listen address (loopback only by default). |
| `--max-connections <n>` | usize | `256` (`DEFAULT_MAX_CONNECTIONS`) | count | Connection cap, so a flood cannot spawn unbounded threads. Must be at least 1. |
| `--checkpoint-interval <n>` | u64 | `1024` (`DEFAULT_CHECKPOINT_INTERVAL`) | messages | At most this many messages may be redelivered after an abrupt crash; the cursor also flushes on a clean disconnect. |
| `--max-deliver <n>` | u32 | `5` (`DEFAULT_MAX_DELIVER`) | attempts | Delivery attempts before a poison message is dead-lettered. `0` and `4294967295` both mean unlimited, allowed ONLY with `--allow-unlimited-deliver`, else a usage error. |
| `--allow-unlimited-deliver` | flag (no value) | off (false) | n/a | Permit `--max-deliver 0` (or the u32 max), unlimited delivery. Prints a startup WARN: a poison payload can then redeliver forever and is never dead-lettered. |
| `--backoff-ms <ms,ms,...>` | comma-separated u64 list | built-in schedule `100,500,2000,10000,30000` (`DEFAULT_NACK_BACKOFF_NANOS`) | milliseconds | Escalating per-attempt nack/redelivery delay, indexed by attempt and clamped to the last entry, applied when a nack carries no explicit delay. A single `0` disables backoff (retry as soon as the visibility timeout allows). An empty list or a non-numeric element is a usage error. |
| `--max-in-flight <n>` | u32 | `1024` (`DEFAULT_MAX_IN_FLIGHT`) | messages | The per-GROUP max-ack-pending window: at most this many messages leased above the committed cursor at once. Must be at least 1. |
| `--consumer-credit <n>` | u32 | `64` (`DEFAULT_CONSUMER_CREDIT`, aliased to `ironbus_server::engine::DEFAULT_CONSUMER_CREDIT`) | messages | The per-CONNECTION un-acked credit. A fetch delivers `min(requested, consumer credit, group window)`, so one stuck consumer cannot drain a peer's budget. Must be at least 1. |
| `--consumer-credit-bytes <n>` | u64 | `8388608` (8 MiB, `DEFAULT_CONSUMER_CREDIT_BYTES`, aliased to `ironbus_server::engine::DEFAULT_CONSUMER_CREDIT_BYTES`); `0` = unlimited | bytes | The per-CONNECTION un-acked BYTE budget (key + headers + payload), so a large-payload consumer cannot blow the RAM ceiling despite a small message count. Effective credit per fetch is `min(message credit, byte budget)`. NOT floored: a single message larger than the whole budget is still delivered when nothing is in flight (so it never wedges), but is otherwise blocked. |
| `--max-segment-bytes <n>` | u64 | `67108864` (64 MiB, `DEFAULT_MAX_SEGMENT_BYTES`) | bytes | The soft per-segment size cap. Must be at least `4096` (`MIN_MAX_SEGMENT_BYTES`); smaller caps make segments proliferate one record at a time. |
| `--max-total-bytes <bytes>` | u64 | `0` = unlimited (`DEFAULT_MAX_TOTAL_BYTES`) | bytes | The hard durable-log byte cap (the drop-new shed backstop). At or over it, a produce is rejected. |
| `--max-retained-bytes <bytes>` | u64 | `0` = off (`DEFAULT_MAX_RETAINED_BYTES`) | bytes | Size-based retention: reap whole old fully-consumed sealed segments while the durable log exceeds this many record bytes. |
| `--max-age-ms <ms>` | u64 | `0` = off (`DEFAULT_MAX_AGE_MS`) | milliseconds | Age-based retention: reap a fully-consumed sealed segment whose newest record is older than this. |
| `--max-messages <n>` | u64 | `0` = off (`DEFAULT_MAX_MESSAGES`) | messages | Count-based retention: reap oldest fully-consumed sealed segments while the total durable record count exceeds this bound. |
| `--max-groups <n>` | usize | `1024` (`DEFAULT_MAX_GROUPS`, aliased to `ironbus_server::engine::DEFAULT_MAX_GROUPS`); `0` = unlimited | count | Cap on live work-groups. A new NAMED group past the cap is rejected; the default group is exempt and never counted. |
| `--ram-ceiling-bytes <n>` | u64 | `0` = unset (`DEFAULT_RAM_CEILING_BYTES`; the `edge-tiny` profile sets `67108864` = 64 MiB) | bytes | The refuse-to-boot RAM ceiling (#115, #19). `0` leaves the guard OFF and `ironbus_ram_headroom_bytes` reports the `-1` sentinel. When set, the broker REFUSES to start (usage error, exit 1, naming the overage) if the WORST-CASE bounded-buffer footprint the configured caps imply provably exceeds it, and the `ironbus_ram_headroom_bytes` gauge reports a real `ceiling - RSS` headroom. The worst case is provable from the CONFIG (`max_connections * consumer_credit_bytes` in-flight payloads, plus the per-group cursor/lease state and a fixed overhead), NOT a boot-time RSS reading (RSS at boot is near-zero and meaningless). See `docs/RAM_BUDGET.md` for the formula. |
| `--disk-full-policy <drop-new\|drop-oldest>` | enum | `drop-new` (`DEFAULT_DISK_FULL_POLICY`) | n/a | What an over-cap produce does once `--max-total-bytes` is hit. `drop-new` sheds it (preserving older data); `drop-oldest` force-reaps the oldest sealed segment to make room then accepts it. Any other value is a usage error. |
| `--durability-level <sync\|interval\|async\|none>` | enum | `sync` (`DEFAULT_DURABILITY_LEVEL`) | n/a | The DURABILITY LEVEL (#341, #379): how an ack relates to the covering `fdatasync`. `sync` (the default) acks ONLY after the covering `fdatasync` returns, so I2 holds and a power cut loses ZERO acknowledged records. The relaxed levels are STRICTLY OPT-IN and weaken I2: `interval` acks on the page-cache write and forces a sync on the flush window (bounded loss = the smaller of `--flush-interval-ms` and `--flush-max-bytes`); `async` acks on the page-cache write and syncs only opportunistically (a segment roll or clean shutdown), unbounded loss until then; `none` adds no periodic fsync at all (the largest loss window). `async` and `none` REFUSE to boot without `--async-loss-ack`. Any relaxed level logs a loud startup WARN that I2 is waived and the worst-case loss. Any other value is a usage error. |
| `--flush-interval-ms <n>` | u64 | `1000` (`DEFAULT_FLUSH_INTERVAL_MS`) | milliseconds | The `interval` level's TIME window: the most MONOTONIC-clock time an acked-but-unsynced record may sit before a forced `fdatasync`. `0` disables the time trigger (the byte budget alone forces the sync). Only consulted under `--durability-level interval`. |
| `--flush-max-bytes <n>` | u64 | `1048576` (1 MiB, `DEFAULT_FLUSH_MAX_BYTES`) | bytes | The `interval` level's BYTE budget: the most UNSYNCED record bytes that may accumulate before a forced `fdatasync`. `0` disables the byte trigger (the time window alone forces the sync). The EFFECTIVE worst-case loss bound is the smaller of the time and byte triggers. Only consulted under `--durability-level interval`. |
| `--async-loss-ack` | flag (no value) | off (false) | n/a | The explicit DATA-LOSS ACKNOWLEDGEMENT (#49, #379) that the unbounded-loss levels (`async`, `none`) require to boot: an `i-accept-acknowledged-data-loss`-style confirmation. Without it, `--durability-level async`/`none` is a fail-closed usage error (exit 1). `sync` and `interval` ignore it (`sync` is safe; `interval`'s loss is bounded by the operator-chosen window). |
| `--storage <disk\|memory>` | enum | `disk` (`DEFAULT_STORAGE`) | n/a | The storage BACKEND (#443). `disk` (the default) is the durable on-disk store rooted at `--data-dir`, byte-for-byte the historical broker. `memory` runs the SAME engine over an in-memory filesystem: NO files, NO fsync, and explicitly NO power-loss or restart durability (a clean stop or crash loses every acked message; a supervisor restart revives an EMPTY broker), for hot-path fan-out, spill-to-RAM buffering, and test rigs where flash wear or fsync latency is the binding constraint. `memory` REFUSES to boot without the dedicated `--ephemeral-loss-ack` consent flag (`--async-loss-ack` does NOT cover it: a relaxed fsync schedule on a durable store is a different loss contract), without an explicit `--max-total-bytes` above 0 (the RAM bound; the cap meters STORED, post-compression bytes), and with an explicit `--data-dir` (the broker keeps no on-disk state). The startup banner states the ephemeral contract and the materialized-config line says `storage=memory`. RAM-boundedness caveat: the dead-letter sink is deliberately byte-UNCAPPED (poison evidence is never shed) and in memory mode it also lives in RAM, OUTSIDE the `--max-total-bytes` cap and the #115 guard's modeled floor, so the footprint is bounded for ack-progressing workloads; pair memory mode with consumers that ack, monitor `ironbus_dlq_records_total`, and tune `--max-deliver` (see `docs/RAM_BUDGET.md`). Any other value is a usage error. The fuller memory-mode operational surface is #444. |
| `--ephemeral-loss-ack` | flag (no value) | off (false) | n/a | The explicit EPHEMERAL-LOSS ACKNOWLEDGEMENT (#443) that `--storage memory` requires to boot: consent that a clean stop or crash loses EVERY acknowledged message. Distinct from `--async-loss-ack` (which consents to a relaxed fsync schedule on a DURABLE store); neither flag satisfies the other's gate. The env form is `IRONBUS_EPHEMERAL_LOSS_ACK` per the `IRONBUS_<FLAG>` grammar. Scripting note: detect an ephemeral broker by the `storage=memory` field on the materialized-config line, never by `data_dir=none` alone (a disk broker started with a literal relative directory named `none` emits the same `data_dir` token). |
| `--key-shared-group <name>` | string, REPEATABLE | none (empty) | n/a | Run the named competing group in `key_shared` ordering: a record's key routes to one live member, so same-key records keep order while the group drains in parallel across keys. Pass once per group; a group not named stays plain competing. |
| `--broadcast-group <name>` | string, REPEATABLE | none (empty) | n/a | Mark a NAMED group BROADCAST (#288): a group-of-one that sees every record in order, so it accepts the `cumulative-ack` verb. The group MUST be named: the DEFAULT/empty group (`--broadcast-group ""`) cannot be a broadcast group (its consumers never SUB a name, so the group-of-one subscriber cap could not bind it) and is rejected as a startup usage error. Mutually exclusive with `key_shared`. A broadcast group is enforced as a true group-of-one: it accepts AT MOST ONE active subscriber (a second concurrent SUB is rejected). Pass once per group; a group not named stays plain competing and rejects cumulative ack. An empty/bad name or the group cap is a startup usage error. |
| `--visibility-timeout-ms <n>` | u64 | `30000` (`DEFAULT_VISIBILITY_MS`) | milliseconds | How long a delivered message stays in flight before it may redeliver. Must be at least 1. The lease hard cap is the larger of 5 minutes (`DEFAULT_HARD_CAP_MS = 300000`) and this. |
| `--health-addr <host:port>` | string | off (not set) | host:port | If set, also serve `GET /healthz`, `/readyz`, and `/metrics` (and `/admin` with `--enable-admin`) on this HTTP port. Loopback by default; a non-loopback bind requires `--health-allow-public` (see below). |
| `--health-allow-public` | flag (no value) | off (false) | n/a | Acknowledge a NON-LOOPBACK `--health-addr` bind (#95). The health surface is UNAUTHENTICATED and UNENCRYPTED (TLS #107 and auth #106 are not yet implemented), so by default a non-loopback bind refuses to start; this flag binds it anyway with a loud startup WARN. Loopback binds ignore this flag. Covers the health surface only; the wire `--addr` bind has no such override. |
| `--health-liveness-window-ms <n>` | u64 | `10000` (10 s, `DEFAULT_HEALTH_LIVENESS_WINDOW_MS`); `0` = disabled | milliseconds | The `/healthz` liveness HYSTERESIS WINDOW (#95): `/healthz` returns 503 only after the broker's accept loop has gone this long with no monotonic-clock progress tick, so a slow-but-progressing fsync never fails liveness and a healthy idle node stays 200. `0` disables the watchdog (static-200 `/healthz` while up). |
| `--enable-otlp-export` | flag (no value) | off (false) | n/a | Turn ON OTLP span export (#99, #352). Honored only when the broker is built with the non-default `otlp` Cargo feature; the DEFAULT shipped binary links no opentelemetry, so setting this on a default build logs a clear `WARN: ... built WITHOUT the otlp feature` line and export stays off. When built with `otlp` and set, a drain thread ships the bounded span queue to `--otlp-endpoint` over plaintext gRPC (no TLS), dropping-and-counting under backpressure so a slow collector never blocks a produce. |
| `--otlp-endpoint <url>` | string | `http://127.0.0.1:4317` (when export is on) | OTLP/gRPC URL | The OTLP collector endpoint the span exporter ships to (#352), e.g. `http://127.0.0.1:4317` (plaintext gRPC, the standard OTLP/gRPC port). Read only when `--enable-otlp-export` is set AND the `otlp` feature is built in. |
| `--codel-target-ms <n>` | u64 | `0` (DISABLED, `DEFAULT_CODEL_TARGET_MS`) | milliseconds | The CoDel time-in-queue (sojourn) shedding TARGET (#68): the acceptable standing produce-admission latency before the load-shed begins. `0` (the default) DISABLES CoDel, so a zero-config broker is unchanged (byte-cap shed + consumer credit only). A non-zero value opts in (the RFC 8289 recommended value is 5 ms) and the engine CLAMPS it to `[1 ms, 1 s]`, never rejecting it. A sustained admission sojourn above it for one `--codel-interval-ms` window sheds NEW produces with a typed "shed under load" signal; it NEVER drops an already-accepted record (I2 holds). |
| `--codel-interval-ms <n>` | u64 | `100` (`DEFAULT_CODEL_INTERVAL_MS`) | milliseconds | The CoDel INTERVAL (#68): the window the admission sojourn must stay above `--codel-target-ms` before shedding, and the base drop spacing. Clamped to `[20 ms, 10 s]`. Only consulted when `--codel-target-ms` is non-zero. |
| `--retry-budget-ratio-ppm <n>` | u64 | `0` (DISABLED) | parts per million | The per-client retry-budget RATIO (#69): the fraction of a client's request rate its retries may occupy before the broker-side throttle sheds them (the Google SRE accept-based adaptive throttle, the anti-amplification re-check). `0` (the default) DISABLES the budget (no retry is throttled). The doc budget is 10% (`100000`). |
| `--retry-budget-window-ms <n>` | u64 | `60000` (60 s) | milliseconds | The per-client retry-budget sliding WINDOW (#69): the window the request/accept counts are tracked over. Only consulted when `--retry-budget-ratio-ppm` is non-zero. |
| `--fire-and-forget-msg-rate <n>` | u64 | `0` (DISABLED) | messages/second | The fire-and-forget (un-credited) admission token bucket's MESSAGE rate (#69): caps the QoS-0-equivalent tier so it cannot bypass the consumer-credit brake or starve credited traffic. `0` (with the byte rate) DISABLES the bucket (the tier is ungoverned, as today). The doc default is `5000`. |
| `--fire-and-forget-byte-rate <n>` | u64 | `0` (DISABLED) | bytes/second | The fire-and-forget token bucket's BYTE rate (#69). `0` (with the message rate) disables the bucket. The doc default is `5242880` (5 MiB/s). |
| `--fire-and-forget-refill-ms <n>` | u64 | `100` | milliseconds | The fire-and-forget token bucket's refill granularity (#69): sizes the burst ceiling (`rate * refill_ms / 1000`). |
| `--egress-limit <n>` | u32 | `16` (`DEFAULT_EGRESS_LIMIT`) | count | The starting / static-floor EGRESS concurrency limit for the AIMD downstream limiter (#69): in-flight requests to a downstream sink, adapted up additively (+1 on a clean window) and down multiplicatively (x0.5 on a timeout / 429 / 503), bounded to `[4, 128]`. `0` is treated as the default floor (16). |
| `--wal-fsync-headroom-bytes <n>` | u64 | `0` (DISABLED, `DEFAULT_WAL_FSYNC_HEADROOM_BYTES`) | bytes | The fsync-HEADROOM admission credit (#378): the most un-fsynced (buffered-but-not-durable) record bytes the BUFFERED write frontier may run ahead of the DURABLE frontier. `0` (the default) DISABLES it (a zero-config broker is unchanged). When set, a new produce that would push the un-fsynced backlog past the headroom first forces a group-commit drain; under `--durability-level sync` the drain frees the headroom and the produce is admitted (THROTTLE, never loses), under a relaxed level the drain defers the fsync so the produce is SHED with a typed `wal fsync headroom exhausted` signal (bounding the loss window). It NEVER drops an already-accepted record (I2 holds) and never wedges on an oversized produce. Reuses the engine's `unsynced_bytes()` frontier (#341). |

### `serve` validation (each a usage error, exit 1)

- `--profile` must be `edge-tiny`, `balanced`, or `throughput`; any other value is a usage error
  naming the accepted profiles.
- `--max-connections` must be at least 1.
- `--max-deliver` must be at least 1 and below 4294967295 (both `0` and the u32 max mean
  unlimited; pass `--allow-unlimited-deliver` to enable it deliberately).
- `--max-in-flight` must be at least 1.
- `--consumer-credit` must be at least 1.
- `--max-segment-bytes` must be at least 4096.
- `--visibility-timeout-ms` must be at least 1.
- `--disk-full-policy` must be `drop-new` or `drop-oldest`.
- `--durability-level` must be `sync`, `interval`, `async`, or `none`. `async` and `none` REFUSE to
  boot without `--async-loss-ack` (the unbounded-loss safety gate, #49/#379): a fail-closed usage
  error naming the level, the waived I2 invariant, the worst-case loss, and the flag to set.
  `--durability-level interval` with BOTH `--flush-interval-ms` and `--flush-max-bytes` at `0` is a
  usage error (it would silently degrade to the unbounded `async` behavior without the
  acknowledgement); set at least one positive trigger.
- `--ram-ceiling-bytes`, when set (non-zero), must be at or above the WORST-CASE bounded-buffer
  footprint the configured caps imply, or the broker REFUSES to boot with a usage error that names
  the worst case, the ceiling, the overage, and the knobs to lower (`--max-connections`,
  `--consumer-credit-bytes`, `--consumer-credit`, `--max-groups`, `--max-in-flight`). `0` (the
  default for `balanced`/`throughput`) disables the guard; `edge-tiny`'s 64 MiB ceiling fits its
  caps (a blown-up override is what trips it). The check is provable from the config, never a live
  RSS reading. See `docs/RAM_BUDGET.md`.
- `--health-addr` that resolves to a NON-LOOPBACK address (including the wildcards `0.0.0.0` /
  `::`, or a hostname that resolves to a routable IP) is REFUSED unless `--health-allow-public` is
  also set: the health surface is unauthenticated and unencrypted, so a fail-closed startup error
  (naming the address) is the default rather than an accidental public metrics endpoint (#95). The
  classification is on the resolved address. A `--health-addr` that resolves to nothing is also a
  usage error.
- `--storage` must be `disk` or `memory`; an unknown value is a usage error naming its source (the
  flag, or the `IRONBUS_STORAGE` env var). `--storage memory` (#443) REFUSES to boot without the
  dedicated `--ephemeral-loss-ack` consent, with `--max-total-bytes` at `0` (unlimited), or with
  an explicit `--data-dir` (from the flag, the `IRONBUS_DATA_DIR` env var, or the
  `storage.data_dir` config-file key). All three refusals are fail-closed usage errors (exit 1)
  before any listener opens; the interplay of every other knob with memory mode is below.

### Memory mode (`--storage memory`): flag and config interplay (#443, #444)

The memory backend runs the SAME engine over an in-memory filesystem, so almost every knob keeps
its exact disk-mode meaning; the few that touch the filesystem boundary are decided explicitly
here. Each row below is a pinned decision, not an accident:

- `--data-dir` / `IRONBUS_DATA_DIR` / `storage.data_dir` (config file): REFUSED (usage error,
  exit 1). The broker keeps no on-disk state, so a given path would only LOOK durable. The
  config-file key flows through the same env mapping and is refused identically (pinned by a
  test).
- `--max-total-bytes`: REQUIRED above `0`. On disk an unbounded log fills the SD card; in RAM it
  OOMs the device, so the cap (which meters STORED, post-compression bytes) is the RAM bound and
  `0` = unlimited is refused.
- `--max-segment-bytes` (`storage.segment_size`): LEGAL, identical semantics. Segments roll in
  RAM exactly as they roll on disk; the active-segment working set it bounds is the same memory
  either way.
- `--max-retained-bytes` / `--max-age-ms` / `--max-messages` (retention): LEGAL, identical
  semantics, and MORE load-bearing, not less: a reaped sealed segment frees RAM instead of disk,
  which is what keeps a long-running memory broker under its byte cap.
- `--disk-full-policy`: LEGAL, identical semantics despite the name: at the byte cap `drop-new`
  sheds the produce and `drop-oldest` force-reaps the oldest sealed in-RAM segment to admit it.
- `--checkpoint-interval` (and the per-group cursor checkpoints): LEGAL and MEANINGFUL. Group
  cursors, attempts counts, and redelivery semantics hold within the process lifetime, and the
  checkpoint machinery runs against the in-memory filesystem unchanged (deliberately NOT
  special-cased: it is the same code path the engine tests exercise). What changes is the
  payoff: a checkpoint write costs RAM bandwidth instead of flash wear, and no checkpoint
  survives the process, so the flag tunes nothing an operator can observe across a restart.
- `--compact` (#337): LEGAL, allowed and documented rather than refused. Compaction rewrites
  sealed segments in RAM exactly as on disk; for a keyed changelog topic it genuinely RECLAIMS
  RAM under the byte cap, so refusing it would remove a real tool. For a non-keyed workload it
  is pointless (it only spends CPU), which is exactly as true on disk.
- `--durability-level` / `--flush-interval-ms` / `--flush-max-bytes` / `--async-loss-ack`: LEGAL
  but VACUOUS. There is no fsync on the in-memory filesystem, so every level yields the same
  RAM-only loss contract; the gates are still enforced uniformly (`async`/`none` still demand
  `--async-loss-ack`), because backend-conditional validation would let a script that flips
  `--storage` silently change what it is consenting to. Leave the default `sync`.
- `--ram-ceiling-bytes` (#115): COMPOSES UNCHANGED. The refuse-to-boot guard bounds the
  bounded-buffer footprint; note it does NOT count stored records (that is `--max-total-bytes`,
  which in memory mode is additional resident RAM, so size the two together).
- Everything else (`--addr`, connection/credit/group caps, delivery, dedup, backpressure,
  health/admin, `--compression`, `--profile`, `--config`): unchanged; none of it touches the
  filesystem boundary.

Memory mode skips the data-dir lifecycle below entirely: no directory is created, probed, or
locked. The single-broker exclusive lock exists to stop two brokers writing one directory; each
memory broker owns a private in-memory filesystem, so the only exclusivity that applies is the
`--addr` bind itself. After exit there is nothing to inspect offline (see "Memory-mode brokers
and the offline verbs" above).

### Environment-variable mapping and precedence (#89)

Every `serve` setting can also be supplied via an environment variable, so the same key
surface works as a foreground binary, a systemd unit, or a container with no config file.
The variable name is `IRONBUS_<FLAG>`: the flag name minus its leading `--`, uppercased,
with each `-` replaced by `_`. The **precedence is flag > env > FILE > default**: an
explicit command-line flag overrides the env var, which overrides the `--config` TOML FILE
value (#382), which overrides the compiled default. The compiled default for each knob is
supplied by the active `--profile` (#87), which is itself applied below the file, env, and
flag layers, so the full chain is **profile < FILE < env < flag** (the profile sets a
knob's starting value, then the file, an env var, or a flag for that same knob overrides
it). With no `--profile`, the default profile is `balanced`, whose values ARE the compiled
`DEFAULT_*` constants; with no `--config`, the file layer is absent, so the historical
`flag > env > default` behavior is byte-for-byte unchanged.

| Flag | Environment variable |
|------|----------------------|
| `--addr` | `IRONBUS_ADDR` |
| `--data-dir` | `IRONBUS_DATA_DIR` |
| `--profile` | `IRONBUS_PROFILE` (`edge-tiny`/`balanced`/`throughput`) |
| `--max-connections` | `IRONBUS_MAX_CONNECTIONS` |
| `--checkpoint-interval` | `IRONBUS_CHECKPOINT_INTERVAL` |
| `--max-deliver` | `IRONBUS_MAX_DELIVER` |
| `--allow-unlimited-deliver` | `IRONBUS_ALLOW_UNLIMITED_DELIVER` (`true`/`1` or `false`/`0`) |
| `--backoff-ms` | `IRONBUS_BACKOFF_MS` (comma-separated, e.g. `100,500,2000`) |
| `--max-in-flight` | `IRONBUS_MAX_IN_FLIGHT` |
| `--consumer-credit` | `IRONBUS_CONSUMER_CREDIT` |
| `--consumer-credit-bytes` | `IRONBUS_CONSUMER_CREDIT_BYTES` |
| `--max-segment-bytes` | `IRONBUS_MAX_SEGMENT_BYTES` |
| `--max-total-bytes` | `IRONBUS_MAX_TOTAL_BYTES` |
| `--max-retained-bytes` | `IRONBUS_MAX_RETAINED_BYTES` |
| `--max-age-ms` | `IRONBUS_MAX_AGE_MS` |
| `--max-messages` | `IRONBUS_MAX_MESSAGES` |
| `--max-groups` | `IRONBUS_MAX_GROUPS` |
| `--group-idle-evict-ms` | `IRONBUS_GROUP_IDLE_EVICT_MS` |
| `--ram-ceiling-bytes` | `IRONBUS_RAM_CEILING_BYTES` |
| `--disk-full-policy` | `IRONBUS_DISK_FULL_POLICY` |
| `--durability-level` | `IRONBUS_DURABILITY_LEVEL` |
| `--flush-interval-ms` | `IRONBUS_FLUSH_INTERVAL_MS` |
| `--flush-max-bytes` | `IRONBUS_FLUSH_MAX_BYTES` |
| `--async-loss-ack` | `IRONBUS_ASYNC_LOSS_ACK` |
| `--storage` | `IRONBUS_STORAGE` (`disk`/`memory`, #443) |
| `--ephemeral-loss-ack` | `IRONBUS_EPHEMERAL_LOSS_ACK` (`true`/`1` or `false`/`0`) |
| `--wal-fsync-headroom-bytes` | `IRONBUS_WAL_FSYNC_HEADROOM_BYTES` |
| `--visibility-timeout-ms` | `IRONBUS_VISIBILITY_TIMEOUT_MS` |
| `--health-addr` | `IRONBUS_HEALTH_ADDR` |
| `--health-allow-public` | `IRONBUS_HEALTH_ALLOW_PUBLIC` (`true`/`1` or `false`/`0`) |
| `--health-liveness-window-ms` | `IRONBUS_HEALTH_LIVENESS_WINDOW_MS` |
| `--enable-admin` | `IRONBUS_ENABLE_ADMIN` (`true`/`1` or `false`/`0`) |
| `--enable-otlp-export` | `IRONBUS_ENABLE_OTLP_EXPORT` (`true`/`1` or `false`/`0`) |
| `--otlp-endpoint` | `IRONBUS_OTLP_ENDPOINT` |

A bad env value (e.g. non-numeric where a number is expected, or an unknown
`IRONBUS_DISK_FULL_POLICY`) is a usage error (exit 1) that **names the env var**, exactly
as a bad flag value names the flag. The repeatable `--key-shared-group` is command-line
only (no single-var mapping, since a list with a per-group meaning does not flatten to one
scalar). The compiled-in named PROFILES and the `--profile` selector are implemented
(#87, see `--profile` above); the TOML config FILE (`--config`), its strict typed-key /
literal-grammar / coupled-set validation, and the immutable-config atomic re-read RELOAD
engine are implemented (#382, see `--config` above and `docs/CONFIG.md`). The reload engine
runs as a startup self-check when `--config` is set, and SIGHUP is now the runtime trigger
(#380, refs #88): it re-reads `--config` and applies the live-reloadable subset (the retention
bounds + the disk-full policy) to the running broker, with restart-required keys reported but
not applied live, so applying those requires restarting the broker. The other remaining residual is the MUTATING
wire `CONFIG SET`/`SAVE` admin verbs, which need the #106 connection-scoped auth (there is
no unauthenticated remote config mutation).

### `serve` data_dir lifecycle and the single-broker lock (#89)

On `serve`, before the broker opens:

- The `--data-dir` is **created (parents too, mode `0700`) if absent**, so a freshly
  flashed device provisions its queue with no manual `mkdir`.
- A path that **exists but is not a directory** (e.g. a regular file) is a usage error
  (exit 1) naming the path.
- The directory is **probe-write-and-fsync verified writable**; a read-only or unwritable
  mount is a fatal error (exit 70) naming the path, rather than a silent loss of durability.
- `serve` then takes an **exclusive advisory lock** (`flock(LOCK_EX|LOCK_NB)`) on a `LOCK`
  file in the data dir. A second `serve` on the SAME data dir **fails fast** (exit 70,
  "another ironbus broker is already running on `<dir>`") instead of opening a second writer
  to the one log, which would interleave appends and corrupt it. The lock is released by the
  OS when the process exits (clean shutdown or crash), so it never goes stale.

### `serve` output

On a successful bind it prints (to stdout):

```
ironbus listening on <addr>, data dir <dir>
```

or, under `--storage memory` (#443), the backend instead of a path that does not exist:

```
ironbus listening on <addr>, storage memory (ephemeral)
```

followed on EVERY memory-mode boot by the ephemeral-contract banner (its own line, mirroring
the loud I2-waived durability warning):

```
WARN: --storage memory: this broker is EPHEMERAL. Records live only in this process's RAM: NO files, NO fsync, NO power-loss or restart durability. ...
```

It then prints the MATERIALIZED-CONFIG line (#87): one structured `key=value` line carrying
the active profile, the profile schema version, and every resolved tuning knob, so an
operator can see exactly what the broker is running (and a profile content change is
auditable across an upgrade):

```
materialized-config profile=<name> profile_schema_version=<n> addr=<addr> data_dir=<dir> max_connections=<n> max_segment_bytes=<n> ... enable_admin=<bool> ram_ceiling_bytes=<n>
```

The line ends with an ADDITIVE trailing `storage=` field (#443): `storage=disk` on the default
backend, `storage=memory` with `data_dir=none` in memory mode. A script detects an ephemeral
broker by `storage=memory`, never by `data_dir=none` alone (a disk broker started with a literal
relative directory named `none` emits the same `data_dir` token).

If `--health-addr` is set, it also prints:

```
ironbus health endpoints on <addr> (/healthz, /readyz, /metrics)
```

If unlimited delivery is enabled, it prints the startup warning:

```
WARN: --max-deliver is unlimited (--allow-unlimited-deliver): a poison message can redeliver forever and is never dead-lettered
```

If a NON-LOOPBACK health bind was acknowledged with `--health-allow-public`, it prints a loud
startup warning on every start (the surface is unauthenticated and unencrypted):

```
WARN: --health-allow-public: binding the UNAUTHENTICATED, UNENCRYPTED health surface to non-loopback <addr> ...
```

A non-loopback `--health-addr` WITHOUT `--health-allow-public` does not start: it prints a
fail-closed usage error naming the address and exits 1.

### `/healthz` liveness vs `/readyz` readiness (#95)

`/healthz` is LIVENESS: it answers 200 while the broker's accept loop is making progress and flips
to 503 only after `--health-liveness-window-ms` (default 10 s) of no progress, on a monotonic clock
so a wall-clock step never drives it. A slow-but-progressing fsync keeps `/healthz` 200, an idle node
stays 200 (idle is progress), and a writer frozen by a fatal fsync still returns `/healthz` 200
(liveness is not readiness). `/readyz` is READINESS: it answers 503 while the durable-log writer is
frozen or the broker is shutting down, and 200 once it accepts writes.

## `pub` (online; any platform)

Connects to the broker, appends one message, and prints its assigned durable offset (the
offset is printed only after the record is fsynced, so a printed offset means the message
is durable). The payload comes from the single positional argument, or from stdin if the
argument is omitted (an empty input publishes an empty message, a valid record).

| Flag / argument | Value type | Default | Meaning |
|-----------------|-----------|---------|---------|
| `--addr <host:port>` | string | `127.0.0.1:7777` (`DEFAULT_ADDR`) | The broker address to connect to. |
| `--key <key>` | string | empty | The record key (its bytes). |
| `--` | separator | n/a | End of options: the remaining token is the payload, so a payload beginning with `--` can still be published. |
| `<payload>` | positional (at most one) | from stdin if omitted | The message payload. A second positional argument is a usage error. |

Output: the assigned durable offset, one line, base-10:

```
0
```

## `sub` (online; any platform)

Connects to the broker, joins the named work-group (or the default group if `--group` is
omitted), fetches up to `--max` messages, prints one line per message, and applies at
most one disposition to the batch. `sub` takes no positional arguments.

For the cursor-advancing dispositions (`--ack`, `--term`) `sub` re-fetches across batches
until `--max` is reached or a batch is empty, so a `--max` larger than the per-connection
credit drains as slots free. For peek (no disposition) and `--nack`, it takes a single
window-bounded batch and stops (re-fetching would only re-serve the same records).

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--addr <host:port>` | string | `127.0.0.1:7777` (`DEFAULT_ADDR`) | host:port | The broker address. |
| `--group <name>` | string | empty (default group) | n/a | Consume as this named work-group; an empty name keeps the default cursor. |
| `--max <n>` | u32 | `10` (`DEFAULT_FETCH`) | messages | The total number of messages to fetch. |
| `--ack` | flag (no value) | (peek) | n/a | Disposition: commit each message; it never redelivers. |
| `--nack` | flag (no value) | (peek) | n/a | Disposition: requeue each message for redelivery (after `--delay-ms`, else the broker's backoff schedule). |
| `--term` | flag (no value) | (peek) | n/a | Disposition: drop each message without dead-lettering. |
| `--delay-ms <n>` | u64 | none (broker schedule) | milliseconds | Defer a `--nack` redelivery by this many milliseconds. Only valid with `--nack`; otherwise a usage error. |

At most one of `--ack` / `--nack` / `--term` may be given (a second is a usage error); if
none is given the disposition is peek (print only, the messages stay leased and redeliver
after the visibility timeout).

### `sub` output

One line per message, then a per-message disposition line (except for peek), then a final
count:

```
#<offset> gen=<generation> key=<key> payload=<payload>
```

where `gen` is the lease fencing token (carried back on the acknowledgement). The
disposition line is one of:

| Disposition | Line on success | Line when fenced (stale token) |
|-------------|-----------------|-------------------------------|
| `--ack` | `  ack committed` | `  ack fenced` |
| `--nack` | `  nack requeued` | `  nack fenced` |
| `--term` | `  term dropped` | `  term fenced` |

In-band advisories may also appear within a batch:

- Dead-letter: `dead-letter offset=<n> reason=max-deliver` (reason is `max-deliver` for
  reason code 0, otherwise `reserved`), for an offset the broker parked as poison.
- Truncation: `truncated: resumed at offset <n>, skipped <k> record(s)`, when the
  drop-oldest policy reaped a stuck consumer's records and its cursor was reset.

The final line is always:

```
fetched <n> message(s)
```

## `cumulative-ack` (online; any platform)

Sends a BROADCAST cumulative ack (ack-all-up-to-offset, #288), committing a broadcast
group's single cursor up to the EXCLUSIVE `--up-to` offset in one move. This is the safe
broadcast half of the `JetStream` `AckAll` verb: a broadcast group is a group-of-one that
sees every record in order, so committing past `--up-to` drops nothing. The server
HARD-REJECTS the verb for a competing or `key_shared` work-group (the cumulative-ack safety
trap), and rejects an `--up-to` past the durable head or below the earliest-retained offset;
a re-ack at or below the current commit is an idempotent no-op success.

A group is marked broadcast server-side with `serve --broadcast-group <name>`. The group must
be NAMED: the default/empty group cannot be a broadcast group (`--broadcast-group ""` is a
startup usage error), because its consumers never SUB a name and so the group-of-one
subscriber cap could never bind them.

| Flag | Type | Default | Notes |
|------|------|---------|-------|
| `--addr <host:port>` | string | `127.0.0.1:7777` | The broker to connect to. |
| `--group <name>` | string | empty (default group) | The broadcast group to cumulative-ack. |
| `--up-to <offset>` | u64 | required | The EXCLUSIVE offset to commit the cursor up to (every offset strictly below it is acked). |

On success it prints one line:

```
cumulative ack committed group `<name>` up to offset <up_to>
```

(or `default group` for an empty `--group`). A server rejection (the group is not broadcast,
or `--up-to` is outside the retained window) is mapped to an internal error (exit 70) with
the broker's typed reason; an unreachable broker is exit 5; a missing `--up-to` is a usage
error (exit 1).

## `peek` (offline; Unix only in v1)

Shows a bounded window of durable records from a stopped broker's data directory, with no
server running. `--data-dir` is REQUIRED. Takes no positional arguments.

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--data-dir <dir>` | path | required | path | The data directory to read. |
| `--from-offset <n>` (alias `--offset <n>`) | u64 | `0` | offset | Start showing records at this offset; earlier records are skipped. |
| `--limit <n>` | u64 | `10` (`DEFAULT_PEEK_LIMIT`) | records | The maximum number of records to show. |
| `--json` | flag (no value) | off (human text) | n/a | Emit one JSON object per record (NDJSON) instead of the human line. |

## `dump` (offline; Unix only in v1)

Streams every durable record from a data directory, one per line, with no server running.
With `--dlq` it instead streams the durable dead-letter SINK (the `dlq/` subdirectory),
read-only. `--data-dir` is REQUIRED. Takes no positional arguments.

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--data-dir <dir>` | path | required | path | The data directory to read. |
| `--limit <n>` | u64 | none (all records) | records | The maximum number of records to show. Omitted, every record is streamed. |
| `--json` | flag (no value) | off (human text) | n/a | Emit NDJSON instead of the human line. |
| `--dlq` | flag (no value) | off | n/a | Stream the dead-letter sink (`dlq/`) instead of the main log. An absent or empty `dlq/` shows nothing. |
| `--raw` | flag (no value) | off | n/a | Show the on-disk frame rather than the decoded logical message: for a compressed record (#430), `bytes` is the STORED (descriptor + stream) length and no decode is attempted; for a raw-stored record it renders the same field set as the decoded form. Rejected with `--dlq`. |
| `--require-dict` | flag (no value) | off | n/a | Fail strictly (exit 3) on a record whose compression dictionary is missing, instead of degrading to `decoded:false`. The `lz4` path never references a dictionary (its `dict_id` is always 0), so this only trips on a `zstd`-build dictionary record whose sidecar is absent. Rejected with `--dlq`. |

Note: `dump` has NO `--from-offset`; it always starts at offset 0. Only `peek` accepts
`--from-offset`/`--offset`.

`--raw` and `--require-dict` are the committed #136 surface, LIVE since the write path was
wired (#430). A compressed record decodes by default (`codec` names the real stored codec,
`bytes` is the original payload length, `decoded:true`); one that cannot be decoded degrades
structurally (`decoded:false` plus a `reason`, `missing-dict:<id>` for an unresolved
dictionary) unless `--require-dict` makes the missing dictionary strict (exit 3). `--raw`
shows the stored frame instead and never decodes. A raw-stored record (sub-threshold,
incompressible, or a `--compression none` broker) renders the historical field set
unchanged under every flag combination.

## `scrub` (offline; Unix only in v1)

Strictly READ-ONLY full integrity scan of the data directory with no server running, sharing
the recovery decode path (the storage crate's `OfflineReader`). It reports every corruption,
torn-tail, or checksum issue it finds (the plan), marking, never hiding, what recovery would
quarantine, and NEVER writes. `--data-dir` is REQUIRED. Takes no positional arguments.

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--data-dir <dir>` | path | required | path | The data directory to scan. |
| `--json` | flag (no value) | off (human text) | n/a | Emit the versioned `ironbus.cli.scrub.v1` result object instead of the human report. |

Exit codes (the exit-code-3 gate, see [`CLI_CONTRACT.md`](CLI_CONTRACT.md)):

- `0`: the directory is clean, OR its only skip is an expected torn-tail brownout truncation
  (a reported skip that is NOT data loss, per `ReasonCode::is_data_loss`).
- `3`: the scan FINISHED and found one or more real data-loss spans (a corruption skip,
  reason other than `torn_tail`). The plan is on stdout; the code is the degraded finding.
- `2`: the data directory does not exist.
- `4`: the directory is structurally corrupt and could not be read (a broken segment chain or
  an undecodable header). This is the BLOCKED case, distinct from `3` (FINISHED-and-reported).

### `scrub` output shapes

Human form, a clean directory:

```
scrub: <dir> is clean (<n> segment(s) scanned, no corruption or torn tail)
```

Human form, a damaged directory (one indented line per skip span):

```
scrub: <n> segment(s) scanned, <k> skip span(s): <d> byte(s) of data loss, <t> torn-tail byte(s) (not data loss)
  segment <id> bytes [<start>, <end>) reason=<reason> data-loss
  segment <id> bytes [<start>, <end>) reason=torn_tail torn-tail (no data loss)
```

`--json` form (the single versioned result object, `ironbus.cli.scrub.v1`):

```json
{"schema":"ironbus.cli.scrub.v1","data_dir":"<dir>","segments":<n>,"skipped_spans":<k>,"data_loss_spans":<d>,"data_loss_bytes":<db>,"torn_tail_bytes":<tb>,"events":[{"segment":<id>,"start":<s>,"end":<e>,"reason":"<reason>","data_loss":<bool>}],"ok":<bool>,"exit_code":<code>}
```

The result object is emitted on EVERY exit path (a clean `exit_code:0` AND the `exit_code:3`
data-loss path), carrying `ok` (true only on a clean run) and the `exit_code` it returns. The
`events[]` field names (`segment`/`start`/`end`/`reason`) match the `ironbus.loss-report.v1`
events, so the CLI plan and the broker's recovery loss report agree on every span.

## `repair` (offline; Unix only in v1)

Defaults to the SAME read-only plan as `scrub` (print what it WOULD do, change nothing).
`--apply` performs the repair, which is recovery made explicit and offline. `--data-dir` is
REQUIRED. Takes no positional arguments.

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--data-dir <dir>` | path | required | path | The data directory to repair. |
| `--apply` | flag (no value) | off (read-only plan) | n/a | Perform the repair: take the exclusive lock, quarantine the corrupt span(s), truncate to the longest valid prefix. Omitted, nothing is written. |
| `--json` | flag (no value) | off (human text) | n/a | Emit the versioned `ironbus.cli.repair.v1` result object instead of the human report. |

Without `--apply`, `repair` is `scrub` re-labeled: it opens the directory read-only, computes
the same plan, prints what `--apply` WOULD do, and changes nothing.

With `--apply`, `repair`:

1. Takes the EXCLUSIVE data-dir lock (`flock(LOCK_EX|LOCK_NB)` on the `LOCK` file, the same
   lock `serve` holds) FIRST. If a broker holds it, `repair --apply` FAILS FAST with exit `5`
   and changes nothing, so it can never race a live writer and corrupt the data.
2. Runs recovery (`Log::open`): it QUARANTINES (copies to `quarantine/`, never deletes) any
   corrupt span BEFORE truncating it, truncates the active segment to the longest valid
   prefix, and uses the atomic write-then-fsync-then-rename + directory-fsync discipline for
   any file it rewrites. It NEVER edits a sealed segment in place and NEVER makes the data
   less recoverable than recovery already would (it IS recovery). The data directory's
   uid/gid/mode are preserved because recovery only truncates existing files in place; it
   never recreates the directory.

Exit codes match `scrub` (`0` clean / torn-tail-only, `3` handled data loss, `2` not found,
`4` structurally corrupt/blocked), plus: `--apply` against a broker that holds the lock is
exit `5`, and an IO fault during apply is exit `70`.

### `repair` output shapes

Human form mirrors `scrub`, with a trailing line stating whether `--apply` acted:

```
  read-only plan: --apply would quarantine the corrupt span(s) to quarantine/ and truncate to the longest valid prefix (nothing changed)
```

or, with `--apply`:

```
  applied: quarantined the corrupt span(s) to quarantine/ and truncated to the longest valid prefix
```

`--json` form (the single versioned result object, `ironbus.cli.repair.v1`) is the `scrub`
object plus an `applied` boolean:

```json
{"schema":"ironbus.cli.repair.v1","data_dir":"<dir>","segments":<n>,"skipped_spans":<k>,"data_loss_spans":<d>,"data_loss_bytes":<db>,"torn_tail_bytes":<tb>,"applied":<bool>,"events":[...],"ok":<bool>,"exit_code":<code>}
```

## `admin consumer-reset` / `admin dlq-redrive` (offline MUTATING; Unix only in v1)

The OFFLINE, AUTH-FREE subset of the mutating admin surface (#299). Both operate on a STOPPED
broker's `--data-dir`: they take the SAME exclusive data-dir lock `serve` holds, so a running
broker blocks them with exit `5` ("stop the broker first") and they can never race a live writer.
This is the broker-stopped contract: the safety boundary is "the broker is stopped and the operator
owns the bytes on disk", which needs no authentication because there is no network surface. The
MUTATING WIRE forms (the same actions on a LIVE broker) and `admin force-reap` (reaping stuck leases
on a running broker, which has no offline meaning) need connection-scoped auth and are DEFERRED to
the authed admin surface ([#380](https://github.com/ELares/IronBus/issues/380) /
[#106](https://github.com/ELares/IronBus/issues/106)); `admin force-reap` is a clean usage error
here, naming the deferral. The mutation reuses the broker's EXACT on-disk codecs (the dual-slot CRC
checkpoint and the `AckCursor` snapshot for the cursor; the segmented log's append+fsync for the
redrive), so a crash mid-operation leaves a recoverable data directory, never a corrupt log.

### `admin consumer-reset`

Rewrites a work-group's durable cursor checkpoint to a chosen offset, so the broker resumes the
group from there on its next start (re-reading or skipping records as the operator intends).

| Flag | Type | Default | Values | Meaning |
|------|------|---------|--------|---------|
| `--data-dir <dir>` | path | required | path | The stopped broker's data directory. |
| `--group <name>` | string | required | any name (`""` = the default group) | The work-group whose cursor is rewritten. Required even for the default group, so a reset is never applied to the wrong cursor by omission. |
| `--to <target>` | string | required | a `u64` offset, or `earliest` / `latest` | The committed offset to rewrite to. `earliest` is the oldest retained offset; `latest` is the durable head. |
| `--json` | flag | off (human text) | n/a | Emit the versioned `ironbus.cli.admin-consumer-reset.v1` result object. |

The target is clamped to the durable range `[earliest_retained, head]`: `earliest`/`latest` resolve
to the range ends; an explicit `--to <offset>` OUTSIDE the range is REJECTED with exit `1` (rather
than silently snapped), so an operator who names an offset that does not exist sees the mistake. The
rewritten cursor is the `AckCursor::resume(target)` snapshot (the committed watermark, no
acked-ahead set) written through the same crash-safe dual-slot CRC checkpoint the broker writes, to
`cursor.ckpt` (the default group) or `cursor-<hex(name)>.ckpt` (a named group).

Exit codes: `0` success, `1` usage (bad flag, missing `--data-dir`/`--group`/`--to`, or an
out-of-range explicit offset), `2` data dir not found, `4` structurally corrupt/blocked, `5` a
broker holds the lock, `70` IO fault.

Human form:

```
admin consumer-reset: group "orders" cursor 12 -> 4 (durable range [0, 10])
```

`--json` form (the single versioned result object, `ironbus.cli.admin-consumer-reset.v1`):

```json
{"schema":"ironbus.cli.admin-consumer-reset.v1","data_dir":"<dir>","group":"<name>","committed":<n>,"previous_committed":<n|null>,"earliest_retained":<e>,"head":<h>,"ok":true,"exit_code":0}
```

### `admin dlq-redrive`

Re-injects the dead-lettered records from the durable DLQ sink (`dlq/`) back onto the MAIN log, so a
poison batch an operator has fixed can be reprocessed.

| Flag | Type | Default | Values | Meaning |
|------|------|---------|--------|---------|
| `--data-dir <dir>` | path | required | path | The stopped broker's data directory. |
| `--json` | flag | off (human text) | n/a | Emit the versioned `ironbus.cli.admin-dlq-redrive.v1` result object. |

Crash-safe, idempotent ordering: the un-redriven DLQ records' ORIGINAL key/headers/payload/timestamp
are appended to the main log via the log's own append path and fsynced FIRST, then a durable redrive
watermark (a dual-slot CRC `dlq-redrive.ckpt`, the count of DLQ records already re-injected) is
advanced. The watermark makes a COMPLETED redrive idempotent: a re-run sees the watermark at the DLQ
depth and re-injects nothing (no duplicates). A crash BETWEEN the fsync and the watermark advance
leaves the records re-injected but the watermark not advanced, so the next run re-injects that suffix
again (at-least-once); the main log and the DLQ sink are intact and recoverable at every instant. The
DLQ sink is PRESERVED (redrive copies forward; it does not delete the sink). An absent or empty DLQ
redrives zero records and is not an error.

Exit codes: `0` success (including the idempotent zero-redriven re-run), `2` data dir not found, `4`
structurally corrupt/blocked, `5` a broker holds the lock, `70` IO fault.

Human form:

```
admin dlq-redrive: re-injected 4 of 4 DLQ record(s) onto the main log (0 already redriven)
```

`--json` form (the single versioned result object, `ironbus.cli.admin-dlq-redrive.v1`):

```json
{"schema":"ironbus.cli.admin-dlq-redrive.v1","data_dir":"<dir>","redriven":<n>,"dlq_records":<total>,"already_redriven":<prior>,"ok":true,"exit_code":0}
```

## `top` (LIVE: any platform; OFFLINE: Unix only in v1)

A strictly READ-ONLY status view with two explicit modes and graceful text degradation (#93).
It pulls NO new dependency: the rendering is hand-rolled, the live half reuses the same
dependency-free `/admin` v1 client and JSON extractors as `admin`, and the in-place TTY redraw is
a couple of bare ANSI escapes gated behind a TTY-and-`NO_COLOR` check (`std::io::IsTerminal`).

- **LIVE mode** (`--addr` or `--health-addr <host:port>`) polls the broker's read-only `/admin` v1
  JSON every `--interval` seconds and renders the #16 counters: the durable head and committed
  cursor, the per-group lag and in-flight depth, the DLQ depth and last dead-lettered offset, the
  resilience counters (frozen, last-skip-offset, records/bytes skipped), and the cumulative
  throughput counters (produced, delivered, redelivered, acks). Each panel names its `/admin`
  source. The broker must have been started with `--health-addr` AND `--enable-admin`. A down
  broker exits 5.
- **OFFLINE mode** (`--data-dir <dir>`) renders ONLY the file-derived panels the offline reader can
  compute with NO broker: the segment count and durable head, the loss report (events, bytes,
  records estimate), and the quarantine span (blob count and bytes). It is shown behind a MANDATORY
  banner that names it the offline file-derived view, and it explicitly states the volatile live
  panels (throughput, fsync latency, in-flight) are NOT available offline, so a missing panel is
  never misread as a real zero.

Exactly one mode is required; both or neither is a usage error (exit 1). `top` NEVER mutates
anything: live mode only issues `GET /admin`, offline mode only reads the data directory (the same
read-only `OfflineReader` that backs `peek`/`dump`) and lists `quarantine/`. Any operator action is
PRINTED as the exact subcommand to run, never executed.

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--addr <host:port>` / `--health-addr <host:port>` | string | none | host:port | LIVE mode: the broker's `/admin` HTTP endpoint (its `--health-addr`). Both spellings are accepted. |
| `--data-dir <dir>` | path | none | path | OFFLINE mode: the stopped broker's data directory. |
| `--interval <secs>` | u64 | `1` (`DEFAULT_TOP_INTERVAL_SECS`) | seconds | The refresh interval. Minimum 1; `0` would busy-spin and is a usage error. The poll SLEEPS this long between snapshots, so a slow-poll on a constrained link costs no CPU. |
| `--once` | flag | off | n/a | Emit ONE snapshot and exit 0 (for tests and scripting). Always plain text. |
| `--json` | flag | off | n/a | Emit a single versioned `ironbus.cli.top.v1` object instead of the human view. The `mode` field is tagged `live` or `offline`. |
| `--no-color` | flag | off | n/a | Suppress color even on a TTY. `NO_COLOR` (any non-empty value) does the same. |

### `top` degradation

When stdout is a TTY AND `NO_COLOR` is unset AND `--no-color` is absent AND this is a refreshing
(not `--once`) run, `top` does an in-place redraw: it clears the screen and homes the cursor with
two simple ANSI escapes and colors the mode banner. In every other case (a piped or non-TTY
stdout, `NO_COLOR`, `--no-color`, or `--once`) it prints a PLAIN snapshot with NO escape sequences,
so `ironbus top --once | cat` and a CI run produce clean text, not escape-sequence garbage. The
mode banner is ALWAYS present (only its styling degrades), so the live-vs-offline distinction is
never lost.

### `top` output shapes

LIVE human form (each panel names its `/admin` source):

```
ironbus top -- LIVE (broker /admin v1 at 127.0.0.1:PORT)
broker: frozen=false durable_head=3 committed=0 retained_from=0 [source: /admin broker, segments]
log: segments=1 records=3 bytes=12 [source: /admin segments]
throughput: produced=3 produced_bytes=6 delivered=0 redelivered=0 acks=0 [source: /admin broker counters #16]
dlq: records=0 last_dead_lettered_offset=-1 dead_lettered=0 [source: /admin dlq, broker]
resilience: frozen=false last_skip_offset=0 records_skipped=0 bytes_skipped=0 [source: /admin resilience]
consumers (per-group lag + in-flight) [source: /admin consumers]:
  (default): committed=0 lag=3 in_flight=0
note: top is read-only. ...
```

OFFLINE human form (the mandatory banner, the file-derived panels only):

```
ironbus top -- OFFLINE file-derived view of <dir> (NO broker)
note: OFFLINE. These panels are derived from files on disk with no running broker; the live
      volatile panels (throughput, fsync latency, in-flight depth) are NOT available offline.
log: segments=1 durable_head=4 [source: offline reader]
loss: events=0 bytes=0 records_estimate=0 [source: offline loss report]
quarantine: blobs=0 bytes=0 [source: quarantine/ subdirectory]
note: top is read-only. ...
```

`--json` form (the single versioned object, `ironbus.cli.top.v1`); `mode` tells the two apart:

```json
{"schema":"ironbus.cli.top.v1","mode":"live","source":"<addr>","frozen":<bool>,"durable_head":<n>,"committed":<n>,"earliest_retained":<n>,"segment_count":<n>,"durable_record_count":<n>,"durable_record_bytes":<n>,"produced":<n>,"produced_bytes":<n>,"delivered":<n>,"redelivered":<n>,"acks":<n>,"dead_lettered":<n>,"dlq_records":<n>,"dlq_last_dead_lettered_offset":<i>,"last_skip_offset":<n>,"records_skipped":<n>,"bytes_skipped":<n>,"consumers":[{"name":"<g>","committed_offset":<n>,"consumer_lag":<n>,"in_flight":<n>}]}
```

```json
{"schema":"ironbus.cli.top.v1","mode":"offline","source":"<dir>","segment_count":<n>,"durable_head":<n>,"loss_events":<n>,"loss_bytes":<n>,"loss_records_estimate":<n>,"quarantine_blobs":<n>,"quarantine_bytes":<n>}
```

### Offline output shapes (`peek` and `dump`)

A normal record, human form:

```
offset=<n> ts_ms=<ms> bytes=<payload-len> key_bytes=<key-len> crc=ok codec=none
```

The same record, `--json` form (NDJSON, one object per line):

```json
{"offset":<n>,"ts_ms":<ms>,"bytes":<payload-len>,"key_bytes":<key-len>,"crc":"ok","codec":"none"}
```

`crc` is always `ok` (the offline reader only yields records that passed their CRC) and
`codec` names the real stored codec (`none` for a raw-stored record, `lz4` for a compressed
one, #430). Only sizes are printed, never
the raw key or payload bytes, so a binary payload never corrupts the stream.

A torn or corrupt tail is MARKED, never hidden, after the records. Human form:

```
note: <bytes> byte(s) past the durable head are torn or corrupt and were not shown (<m> event(s))
  segment <id> bytes [<start>, <end>) reason=<reason>
```

`--json` form (a single trailing object; nothing is written for a clean directory):

```json
{"loss":{"bytes":<bytes>,"events":[{"segment":<id>,"start":<s>,"end":<e>,"reason":"<reason>"}]}}
```

### Dead-letter output shapes (`dump --dlq`)

One line per poison record. Human form:

```
dlq_offset=<n> source_offset=<n> group="<name>" attempt=<a> ts_ms=<ms> bytes=<payload-len> key_bytes=<key-len>
```

`--json` form (one object per line, group name JSON-escaped):

```json
{"dlq_offset":<n>,"source_offset":<n>,"group":"<name>","attempt":<a>,"ts_ms":<ms>,"bytes":<payload-len>,"key_bytes":<key-len>}
```

## Exit codes

One fixed scheme across every verb, so a script can branch on the code without parsing
output. The values come from the `EXIT_*` constants in `main.rs`, and `main` maps each
`CliError` variant to one of them.

| Code | Constant / source | Meaning |
|------|-------------------|---------|
| `0` | `ExitCode::SUCCESS` | Clean: the command completed (a `peek`/`dump`/`scrub`/`repair` that marked a torn tail still exits 0; the loss is reported, not an error). |
| `1` | `EXIT_USAGE` (`CliError::Usage`) | Usage or argument error: an unknown subcommand or flag, a missing required value, a bad numeric value, a missing `--data-dir`, an out-of-range `serve` knob, a second disposition or payload. The usage banner is also printed to stderr. |
| `2` | `EXIT_NOT_FOUND` (`CliError::NotFound`) | Operational not-found: an offline verb's `--data-dir` does not exist (`peek` / `dump`, including `dump --dlq`; `scrub` / `repair`). |
| `3` | `EXIT_HANDLED_CORRUPTION` (`CliError::HandledCorruption`) | Handled corruption / structured-but-degraded: an inspection verb (`scrub`, or `repair` reporting its plan or what it applied) RAN TO COMPLETION and reported one or more real data-loss spans (a corruption skip, reason other than `torn_tail`). The command succeeded at its job; the code is the degraded finding, not a failure. A clean run, AND a run whose only skip is an expected `torn_tail` brownout truncation, stays `0` (the loss-report data-loss boundary, `ReasonCode::is_data_loss`). |
| `4` | `EXIT_CORRUPT` (`CliError::Corrupt`) | Corrupt data, BLOCKED: an offline verb found the data directory structurally corrupt (a broken segment chain, an undecodable header, a footer/segment-id mismatch) and could not finish, distinct from a clean torn TAIL it can read past (exit 0) and from a handled corruption skip it finished reporting (exit 3). The load-bearing distinction: `4` is "I gave up", `3` is "I finished and here is the damage". |
| `5` | `EXIT_UNREACHABLE` (`CliError::Unreachable`) | Broker unreachable: an online verb could not reach the broker, or the broker dropped the connection mid-request (a connection-level IO error or a closed socket); also `repair --apply` when a broker holds the exclusive data-dir lock (it refuses to touch a live broker's data dir). |
| `70` | `EXIT_INTERNAL` (`CliError::Internal`) | Internal or runtime failure: an IO error, a broker that answered with a wrong-shape or error frame, or an unsupported platform (`serve`/`peek`/`dump`/`scrub`/`repair` on non-Unix). |

All seven codes above are mapped in `main.rs`. Other codes the issue #136 design reserves
are NOT emitted by the current binary.

## Notes and cross-references

- The default address is `127.0.0.1:7777`, loopback only, so a zero-config broker is
  never exposed off the host without an explicit `--addr`.
- For the durability model, restart-and-resume semantics, consumer-group behavior, the
  health/metrics endpoints, and worked examples, see [`USAGE.md`](USAGE.md). USAGE.md's
  `serve` flag table is a curated subset; THIS file is the complete flag map (USAGE.md
  omits `--allow-unlimited-deliver`, `--backoff-ms`, `--consumer-credit`, `--max-groups`,
  `--disk-full-policy`, `--key-shared-group`, and `--broadcast-group`).
- The on-disk and wire byte layouts referenced by the offline output shapes are specified
  in [`CONTRACTS.md`](CONTRACTS.md).
| `--pubwindow <n>` | int | `1` | n/a | The pipelined publish window (#450): up to `n` un-acked PUBs in flight per produce call via the client's `produce_window`, so the broker's group commit covers the window with ONE `fdatasync` instead of `n`. Acks keep their unchanged fsynced-durable meaning; only WHEN the publisher awaits changes. `1` is the historical one-awaited-ack-per-publish path; `0` is a usage error. Reported additively as `pubwindow` in the `--json` output. |
| `--per-message-ack` | flag (no value) | off (BATCHED-ack drain) | n/a | The fair-consume opt-out (#464): the `--mode subscribe` drain settles each fetched batch with one pipelined `ack_many` round-trip by DEFAULT (the consume-side twin of `--pubwindow`), so the measured throughput reflects the broker's real fetch + batch-ack rate — comparable to a NATS pull consumer or Redis `XREADGROUP` whose clients batch their acks. This flag opts back into the legacy one-synchronous-`ack`-per-message drain, a legitimate ack-RPC-LATENCY measurement (it is ack-RPC-bound, NOT fetch-bound), but NOT a fair throughput head-to-head. EITHER way every fetched message is acked (each lease individually — the competing-work-queue contract; cumulative ack is broadcast-only); only WHEN the acks flush differs. Subscribe-only (publish never consumes, round-trip uses a separate concurrent consumer), so it is a usage error in another mode. Reported additively as `consume_ack` (`batched`/`per-message`) in the `--json` output (schema version unchanged). |
