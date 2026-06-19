<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# The configuration system: precedence, the typed knob table, coupled-set validation, the TOML format, and the named profiles

This is the normative configuration-system specification for IronBus, the
[#14](https://github.com/ELares/IronBus/issues/14) DESIGN deliverable. It freezes
the layered precedence model, enumerates every configuration knob with its type,
default, units, valid range and reload class, specifies the coupled-set
validation rules, justifies the TOML file format, and defines the three named
profiles with their exact values.

IronBus resolves its configuration from `serve` command-line flags, `IRONBUS_*`
environment variables, and a `--config <path>` TOML FILE, on the precedence
`flag > env > FILE > default` (the `data_dir` lifecycle and the env mapping are
specified in [CLI.md](CLI.md)). The TOML config FILE, the named PROFILES, the
strict typed-key + literal-grammar + coupled-set validation, and the
immutable-config atomic re-read RELOAD engine are all now IMPLEMENTED (#87,
#382); the reload engine runs as a validate-whole-then-swap startup self-check
AND on a runtime trigger: SIGHUP re-reads the `--config` file and applies the
live-reloadable subset (the retention bounds + the disk-full policy) to the
running broker, restart-required keys reported but not applied live (#380). The other remaining residual is the MUTATING wire
`CONFIG SET`/`SAVE` admin verbs, which need the #106 connection-scoped auth
(there is no unauthenticated remote config mutation surface). Each layer is tagged with the issue that owns it, and the
boundary between what ships and what is still specified is drawn explicitly
throughout, so this document never claims an unwired layer exists.

Every knob name, default, and validation rule below is cross-checked against the
real code: the `serve` flags and `DEFAULT_*`/`MIN_*` constants in
[`crates/ironbus-cli/src/main.rs`](../crates/ironbus-cli/src/main.rs), the
`EngineConfig` fields in
[`crates/ironbus-server/src/engine.rs`](../crates/ironbus-server/src/engine.rs),
and the nested `LogConfig` / `LeaseConfig` / `DeliveryConfig` in
[`crates/ironbus-storage/src/log.rs`](../crates/ironbus-storage/src/log.rs),
[`crates/ironbus-core/src/lease.rs`](../crates/ironbus-core/src/lease.rs), and
[`crates/ironbus-core/src/delivery.rs`](../crates/ironbus-core/src/delivery.rs).
Where a knob is named in the #14 design but is NOT a real field yet, it is
labelled **SPECIFIED-NOT-YET-A-FIELD** and points at its owning issue, so the
table never invents a field. The byte-level config-model reference is in
[CONTRACTS.md](CONTRACTS.md); the operator-facing manual-flag runbook is in
[CLI.md](CLI.md) and [EDGE_TUNING.md](EDGE_TUNING.md); this document is the
design-level specification that ties them together and adds the file, profile,
and reload layers #14 owns.

Throughout, MiB = 1024 * 1024 bytes, KiB = 1024 bytes, and a duration in `ms` is
milliseconds.

## Contents

1. [What is SPECIFICATION and what is an IMPLEMENTATION RESIDUAL](#1-what-is-specification-and-what-is-an-implementation-residual)
2. [The precedence model, with a worked multi-layer example](#2-the-precedence-model-with-a-worked-multi-layer-example)
3. [The full typed knob table](#3-the-full-typed-knob-table)
4. [Coupled-set validation rules](#4-coupled-set-validation-rules)
5. [The config-file format decision: TOML](#5-the-config-file-format-decision-toml)
6. [The three named profiles](#6-the-three-named-profiles)
7. [Implementation residuals and their owning issues](#7-implementation-residuals-and-their-owning-issues)

---

## 1. What is SPECIFICATION and what is an IMPLEMENTATION RESIDUAL

Read this first, because it frames every table below.

| Layer / feature | Status | Owner |
| --- | --- | --- |
| Compiled-in defaults (the `DEFAULT_*` constants) | SHIPPED | [CLI.md](CLI.md), `main.rs` |
| Environment-variable mapping (`IRONBUS_<FLAG>`) | SHIPPED (#89) | [CLI.md](CLI.md), `main.rs` |
| Command-line flags (`serve --...`) | SHIPPED | [CLI.md](CLI.md), `main.rs` |
| `flag > env > default` precedence between the shipped layers | SHIPPED (#89) | [CLI.md](CLI.md) |
| `data_dir` create-if-absent + probe-write + fatal-if-unwritable, single-broker lock | SHIPPED (#89) | [CLI.md](CLI.md) |
| The TOML config FILE and its parser (`serve --config <path>`) | SHIPPED (#382) | [#85](https://github.com/ELares/IronBus/issues/85), `config_file.rs` |
| The named PROFILES (`edge-tiny` / `balanced` / `throughput`), the `--profile` flag, and the materialized-config log | SHIPPED (#87) | [#87](https://github.com/ELares/IronBus/issues/87), `main.rs` |
| The immutable `Arc<EffectiveConfig>` + the atomic validate-whole-then-swap re-read RELOAD engine | SHIPPED ([#382](https://github.com/ELares/IronBus/issues/382)/[#380](https://github.com/ELares/IronBus/issues/380)): startup self-check + SIGHUP runtime re-read applying the live subset (retention + disk-full); mutating wire verbs await #106 | [#88](https://github.com/ELares/IronBus/issues/88), `config_reload.rs` |
| The MUTATING wire admin `CONFIG SET`/`SAVE` verbs (need auth) | **SPECIFIED here, NOT implemented** | [#380](https://github.com/ELares/IronBus/issues/380) (needs auth) |
| Secret redaction in config dumps | **SPECIFIED, NOT implemented** (env mapping IS shipped) | [#89](https://github.com/ELares/IronBus/issues/89) |
| The typed key table, the literal grammar parser, and coupled-set validation | SHIPPED (#382) | [#86](https://github.com/ELares/IronBus/issues/86), `ironbus-core::config` |

The honest one-line summary: the same knob surface is reachable via flags, env
vars, AND a `--config` TOML FILE on the SHIPPED `flag > env > FILE > default`
precedence; the strict typed-key validation, the shared literal grammar, the
coupled-set validators, and the immutable-config + atomic re-read RELOAD engine are
wired (#382), the reload engine running as a startup self-check AND on a runtime
trigger (SIGHUP re-reads `--config` and applies the live subset — the retention bounds
+ the disk-full policy — restart-required keys reported but not applied live, #380).
The remaining residual is the MUTATING
wire `CONFIG SET`/`SAVE` admin verbs, which need the #106 connection-scoped auth
(no unauthenticated remote config mutation). [CONTRACTS.md](CONTRACTS.md) records the same boundary from the
byte-model side (the TOML config FILE is IMPLEMENTED, #382, and the mutating
wire `CONFIG SET`/`SAVE` verbs are the deferred residual).

---

## 2. The precedence model, with a worked multi-layer example

### The layered precedence chain

The effective configuration is resolved into ONE immutable struct at startup, by
walking five layers from lowest precedence to highest. The highest layer that
SETS a given key wins; a layer that does not set a key leaves the lower layer's
value untouched. Resolving once at startup means there is no per-message config
lookup on the hot path (an Edge First requirement: the effective config is a
small `EngineConfig` read once, never re-consulted per produce).

```
lowest precedence
  1. compiled-in defaults      the DEFAULT_* constants in main.rs / engine.rs
  2. a named compiled-in profile   profile = "edge-tiny" | "balanced" | "throughput"
  3. the config file (TOML)        --config /etc/ironbus.toml
  4. environment variables         IRONBUS_<FLAG>=...
  5. command-line flags            serve --<flag> ...
highest precedence
```

Note the placement deliberately: the SHIPPED behavior is `flag > env > default`
(stated exactly that way in [CLI.md](CLI.md)). This document does not contradict
that. It slots the two NEW layers BETWEEN the default and the env layers:

- A **named profile** (layer 2) is applied FIRST, on top of the compiled-in
  defaults, then any explicit key OVERRIDES it. A profile is a coherent starting
  point, never a lock: it sets a coherent group of knobs in one move, and any
  file key, env var, or flag still overrides an individual member. This is the
  profile-then-override semantics #14 requires.
- The **config file** (layer 3) sits ABOVE the profile and defaults but BELOW
  env vars and flags, so an operator can ship a reviewed `/etc/ironbus.toml` and
  still override a single key for one run via an env var (the natural container /
  systemd injection point) or a flag (the natural ad-hoc point), without editing
  the file.

The shipped pair therefore stays exactly as CLI.md documents it (flag beats env
beats the compiled default); this design only inserts the profile and file
layers, which are both below env and flag, so adding them never changes the
relative order of the two layers that ship today.

A sixth, runtime layer is named in the #14 design (a `CONFIG SET` admin path that
is the highest precedence of all, volatile and in-memory). It is part of the
hot-reload residual owned by [#88](https://github.com/ELares/IronBus/issues/88)
and is described in [section 4](#4-coupled-set-validation-rules) and
[section 7](#7-implementation-residuals-and-their-owning-issues); it is NOT a
shipped layer and is not part of the startup chain above.

### The worked multi-layer example: one knob set at three layers

Take the per-segment size cap, the real field
`LogConfig::max_segment_bytes` / flag `--max-segment-bytes`
(`DEFAULT_MAX_SEGMENT_BYTES` = `67108864`, 64 MiB). Suppose an operator runs an
edge gateway and sets this same knob at three layers:

| Layer | Value set | How |
| --- | --- | --- |
| 1. compiled-in default | `67108864` (64 MiB) | `DEFAULT_MAX_SEGMENT_BYTES` in `main.rs` |
| 2. profile | `8388608` (8 MiB) | `profile = "edge-tiny"` sets `storage.segment_size` |
| 3. config file | `33554432` (32 MiB) | `[storage] segment_size = "32MiB"` in `/etc/ironbus.toml` |
| 4. environment | (not set) | -- |
| 5. command-line flag | `16777216` (16 MiB) | `serve --max-segment-bytes 16777216` |

The resolution walks bottom-up: the default 64 MiB is overwritten by the
profile's 8 MiB, which is overwritten by the file's 32 MiB, which is overwritten
by the flag's 16 MiB. The env layer set nothing, so it is transparent.

**Effective value: `16777216` (16 MiB), from the command-line flag, the highest
layer that set the key.**

If the flag were removed, the file's 32 MiB would win; remove the file key too
and the profile's 8 MiB wins; remove the profile and the compiled-in 64 MiB
default is what `ironbus serve` with no arguments uses. This is the
zero-config-starts-on-`balanced` guarantee from the other direction: with no
profile, no file, no env var, and no flag, every knob takes its compiled-in
default, and that compiled-in default set IS the `balanced` profile (see
[section 6](#6-the-three-named-profiles)).

The same example, restricted to the TWO layers that ship today, is exactly the
CLI.md behavior: with `IRONBUS_MAX_SEGMENT_BYTES=33554432` in the environment and
`--max-segment-bytes 16777216` on the command line, the flag's 16 MiB wins
(`flag > env`); drop the flag and the env's 32 MiB wins (`env > default`). The
profile and file rows above are the SPECIFIED layers #87 and #85 insert below
the env layer.

---

## 3. The full typed knob table

Every configuration knob, with its type, default, units, valid range, and a
HOT / COLD / COUPLED reload class. Every SHIPPED knob's name and default is the
real one, cited to its constant; a knob that is named in the #14 design but is
not a field yet is **SPECIFIED-NOT-YET-A-FIELD** with its owning issue.

Reload-class legend (the live-reload semantics owned by
[#88](https://github.com/ELares/IronBus/issues/88)):

- **COLD**: changing it requires a restart. Layout-affecting or
  open-time-immutable keys (segment size, data dir) are COLD because changing
  them live could strand segments; this is a Resilient-first choice, stated in
  the #14 second-pass resolution.
- **HOT**: safe to change at runtime; a reload applies it to the running broker
  without a restart.
- **COUPLED**: must be validated (and changed) as a SET with its partners; a
  reload that touches one member re-validates the whole set before any member is
  applied (see [section 4](#4-coupled-set-validation-rules)).

The reload engine ships (#382): the immutable `Arc<EffectiveConfig>` and the atomic
re-read RELOAD enforce the COLD/HOT distinction in the class column below (a COLD-key
change across a reload is rejected atomically, leaving the running config unchanged).
The engine runs as a validate-whole-then-swap startup self-check AND on a runtime
trigger: SIGHUP re-reads `--config` and applies the live-reloadable subset (the
retention bounds + the disk-full policy) to the running broker, with restart-required
keys reported but not applied live ([#380](https://github.com/ELares/IronBus/issues/380)).
Also still deferred are the MUTATING wire `CONFIG SET`/`SAVE` admin verbs, which need the #106 auth.

### Storage (`[storage]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `segment_size` | `--max-segment-bytes` / `IRONBUS_MAX_SEGMENT_BYTES` | u64 | `67108864` (64 MiB, `DEFAULT_MAX_SEGMENT_BYTES`) | bytes | `>= 4096` (`MIN_MAX_SEGMENT_BYTES`) | COLD (coupled with `segment_roll`) |
| `data_dir` | `--data-dir` / `IRONBUS_DATA_DIR` | path | required (no default) | path | a writable directory; created 0700 if absent, probe-write verified (#89) | COLD |
| `max_total_bytes` | `--max-total-bytes` / `IRONBUS_MAX_TOTAL_BYTES` | u64 | `0` = unlimited (`DEFAULT_MAX_TOTAL_BYTES`) | bytes | `0` (off) or any u64 | HOT |
| `segment_roll` | SPECIFIED-NOT-YET-A-FIELD | duration | `0` = size-only (specified) | duration (`{ms,s,m,h,d}`) | `0` (off) or a positive duration | COLD (coupled with `segment_size`) |
| (no file key: flag/env ONLY) | `--storage` / `IRONBUS_STORAGE` | enum | `disk` (`DEFAULT_STORAGE`) | -- | `disk \| memory` (#443) | COLD (the backend is an open-time decision) |
| (no file key: flag/env ONLY) | `--ephemeral-loss-ack` / `IRONBUS_EPHEMERAL_LOSS_ACK` | bool | `false` | -- | `true` to permit `--storage memory` | COLD (coupled with the backend) |

The storage BACKEND selector and its ephemeral-loss consent (#443) are deliberately
flag/env ONLY, with no `[storage]` file key: the backend decides whether a data
directory exists at all, and a consent that waives durability should be visible in
the unit file or on the command line, not buried in a config file the unit merely
points at (the same reasoning that keeps the repeatable group flags command-line
only). Under `--storage memory` the `data_dir` row above INVERTS: the key (file,
env, or flag form) must be ABSENT and is refused at boot as a usage error, because
an in-memory broker keeps no on-disk state and a configured path would only LOOK
durable. `memory` also requires `max_total_bytes` above `0` (in RAM the byte cap is
the OOM guard, so `0` = unlimited is refused). Every other key in this document
keeps its meaning under the memory backend; the per-knob interplay table is in
[CLI.md](CLI.md).

`segment_roll` is the co-equal TIME roll trigger flagged in the #139 coherence
pass: the merged storage design (#4/#5/WAL.md) has a 1h time-based segment roll
in addition to the size cap, but the locked `[storage]` table and the shipped
`serve` flags expose only `segment_size`. It is added to the locked section list
here (COLD, COUPLED with `segment_size`) so the time roll is representable; the
field and flag are the #4/#87 implementation residual.

#### `max_total_bytes` is a RECORD-region cap, not a disk/RAM budget (#493)

`max_total_bytes` caps ONLY the framed **record region** — the sum, across every
segment, of `valid_end - SEGMENT_HEADER_LEN` (the same quantity recovery sums as
`durable_bytes` and retention reaps against). It deliberately does NOT count the
per-segment framing, the in-memory image, or a disk backend's preallocation, so the
**true resident footprint is always larger than the configured cap**. An operator
sizing a memory or disk budget MUST apply the multiplier below rather than assume
`bytes_resident == max_total_bytes`.

Why the cap basis stays the record region (and is not switched to a physical meter):
retention/reap decrement the record-region total in O(1), so it is the one basis a
reap can relieve. `ironbus_physical_bytes_written` is a write-AMPLIFICATION counter
that **never decreases on a reap**, so capping on it would tighten after every reap
and eventually wedge the writer; and the resident terms below are backend- and
config-specific (the production in-memory image is now 1x the record region after
#492; disk preallocation depends on `segment_size`), so no single basis can honestly
fold them in. The cap basis is therefore left untouched and the overhead is published
here.

Per-backend multiplier (record region → resident bytes):

| Term | Adds | Worst case (tiny records) |
| --- | --- | --- |
| Per-record framing | 44 B/record (36 B header + 8 B trailer) already INSIDE the record region | dominates at small payloads: a 1 B record frames to ~45 B → ~`1.85x` of payload |
| Per-segment header/footer | 64 B/segment + 32 B/sealed segment | small unless `segment_size` is tiny (many segments) |
| In-memory image (`--storage memory`) | **1x** the record region after #492 — production `--storage memory` runs the single-`Vec` `EphemeralFile`/`EphemeralFs` backend (no `live`+`durable` copy); the historical **2x** in-RAM copy now exists ONLY in the `InMemoryFile` crash-recovery simulation | ~`1x` of the resident framed bytes (the boot RAM guard still charges 2x conservatively — see RAM_BUDGET.md) |
| Per-segment index cache (memory + disk) | a few entries per segment | small |
| Disk preallocation (`--storage disk`) | the ACTIVE segment is preallocated to `segment_size` (default 64 MiB) | up to one `segment_size` of apparent disk use beyond the resident framed bytes |

**Honest live estimate.** The framed resident bytes (record region + every live
segment's header + every sealed segment's footer, reap-tracked) are exposed
programmatically by `Log::resident_bytes_estimate()`. It excludes the in-memory
image multiplier and disk preallocation on purpose (both are backend/config
specific — add them from the table above). Practical sizing:

- **Disk budget** ≈ `resident_bytes_estimate()` + `segment_size` (the active
  segment's preallocation). To hold `max_total_bytes` of record bytes, provision at
  least `max_total_bytes + (segment_count × 96 B framing) + segment_size`.
- **Memory budget** (`--storage memory`) ≈ `resident_bytes_estimate()` × the image
  multiplier, which is **1x** after #492 (production runs the single-`Vec`
  `EphemeralFile`/`EphemeralFs` backend, with no `live`+`durable` copy). The boot
  RAM guard still charges 2x conservatively (see RAM_BUDGET.md), so a config that the
  guard refuses still leaves headroom in practice. `max_total_bytes` is REQUIRED
  above `0` for the memory backend precisely because it is the OOM guard — size it as
  `desired_RAM / image_multiplier`, then subtract the segment-framing overhead.

### Durability (`[durability]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `durability_level` | `--durability-level` / `IRONBUS_DURABILITY_LEVEL` | enum | `sync` (`DEFAULT_DURABILITY_LEVEL`) | -- | `sync \| interval \| async \| none` | COLD (coupled with the flush knobs and `async_loss_ack`) |
| `flush_interval_ms` | `--flush-interval-ms` / `IRONBUS_FLUSH_INTERVAL_MS` | u64 | `1000` (`DEFAULT_FLUSH_INTERVAL_MS`) | ms | `>= 0` (`0` disables the time trigger) | COLD (coupled with `durability_level`) |
| `flush_max_bytes` | `--flush-max-bytes` / `IRONBUS_FLUSH_MAX_BYTES` | size | `1048576` (1 MiB, `DEFAULT_FLUSH_MAX_BYTES`) | bytes | `>= 0` (`0` disables the byte trigger) | COLD (coupled with `durability_level`) |
| (no file key: flag/env ONLY) | `--commit-gather-us` / `IRONBUS_COMMIT_GATHER_US` | u64 | `200` (`DEFAULT_COMMIT_GATHER_US`) | us | `0..=1000000` (`0` disables the gather) | COLD (an actor-spawn decision) (#454, #472) |
| `async_loss_ack` | `--async-loss-ack` / `IRONBUS_ASYNC_LOSS_ACK` | bool | `false` | -- | `true` to enable `async` / `none` | COLD (coupled with `durability_level`) |

The durability `durability_level` enum is now IMPLEMENTED (#341, #379). The DEFAULT
is **`sync`** (ack-after-`fdatasync`, invariant I2, ZERO acked loss on a power cut):
an operator who changes nothing keeps the power-loss-safe broker. The relaxed
levels are STRICTLY OPT-IN: `interval` (ack on the page-cache write, bounded loss =
the smaller of `flush_interval_ms` and `flush_max_bytes`), `async` (ack on the
page-cache write, opportunistic fsync only, unbounded until the next sync), and
`none` (no periodic fsync, the largest window). The unbounded-loss levels
(`async`, `none`) REFUSE to boot without `async_loss_ack = true` (the explicit
data-loss acknowledgement, the none/async safety gate); an `interval` with BOTH
flush triggers at `0` is also refused (it would silently degrade to `async`). When
any relaxed level is active the broker logs a loud startup WARN that I2 is waived
and the worst-case loss, and surfaces the level + loss exposure on `/metrics`
(`ironbus_durability_level_info`, `ironbus_durability_power_loss_unsafe`,
`ironbus_durability_unsynced_bytes`). [DURABILITY.md](DURABILITY.md) is the
authority for the per-level ack and loss contract; this document specs the keys.

> Naming note: an earlier #14 second-pass draft named the level enum `fdatasync`
> with `group_commit_max_delay_ms` / `group_commit_max_bytes` linger knobs. The
> shipped enum is `sync | interval | async | none` (matching the
> README/DURABILITY.md and the implemented `--durability-level` flag, #341/#379),
> and the interval window's triggers are `flush_interval_ms` / `flush_max_bytes`.
> The group-commit batcher's amortization remains hardwired (the #177 append actor
> drains a batch into one barrier); the flush knobs tune the `interval` window, not
> the group-commit batch boundary.

The batch-knob names are the #6-frozen `group_commit_max_delay_ms` /
`group_commit_max_bytes` (NOT the #14 draft's `fsync_interval_ms` /
`fsync_max_batch`), with the 1 MiB BYTE-cap semantics, default 0 ms linger. The
group-commit batcher is the #177 append actor; it amortizes one `fdatasync` over
a drained batch but still acks each record only after the covering sync returns,
so these knobs tune the COST of durability, never the GUARANTEE. They are
SPECIFIED-NOT-YET-A-FIELD: the append actor's batching is hardwired today, not a
configurable bound.

### Backpressure controls (`[backpressure]`, #68 / #69)

These knobs are now IMPLEMENTED (#336). Every one DEFAULTS to its disabling value,
so a broker that changes nothing behaves EXACTLY as today (the byte-cap drop-new /
drop-oldest overflow policy and the per-consumer credit window are the only
backpressure). They are the load-based complement to the byte cap; see
[BACKPRESSURE.md](BACKPRESSURE.md) for the control laws and the proofs-of-intent.

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `codel_target_ms` | `--codel-target-ms` / `IRONBUS_CODEL_TARGET_MS` | u64 | `0` = off (`DEFAULT_CODEL_TARGET_MS`) | ms | `0` (off) or CLAMPED to `[1, 1000]` | COLD |
| `codel_interval_ms` | `--codel-interval-ms` / `IRONBUS_CODEL_INTERVAL_MS` | u64 | `100` (`DEFAULT_CODEL_INTERVAL_MS`) | ms | CLAMPED to `[20, 10000]` | COLD |
| `retry_budget_ratio_per_million` | `--retry-budget-ratio-ppm` / `IRONBUS_RETRY_BUDGET_RATIO_PPM` | u64 | `0` = off | ppm | `0` (off) or `<= 1000000` | COLD |
| `retry_budget_window_ms` | `--retry-budget-window-ms` / `IRONBUS_RETRY_BUDGET_WINDOW_MS` | u64 | `60000` (60 s) | ms | `> 0` | COLD |
| `fire_and_forget_msg_rate` | `--fire-and-forget-msg-rate` / `IRONBUS_FIRE_AND_FORGET_MSG_RATE` | u64 | `0` = off | msg/s | `0` (off) or any u64 | COLD |
| `fire_and_forget_byte_rate` | `--fire-and-forget-byte-rate` / `IRONBUS_FIRE_AND_FORGET_BYTE_RATE` | u64 | `0` = off | bytes/s | `0` (off) or any u64 | COLD |
| `fire_and_forget_refill_ms` | `--fire-and-forget-refill-ms` / `IRONBUS_FIRE_AND_FORGET_REFILL_MS` | u64 | `100` | ms | `> 0` | COLD |
| `egress_limit` | `--egress-limit` / `IRONBUS_EGRESS_LIMIT` | u32 | `16` (`DEFAULT_EGRESS_LIMIT`) | count | AIMD-bounded to `[4, 128]` | COLD |
| `wal_fsync_headroom_bytes` | `--wal-fsync-headroom-bytes` / `IRONBUS_WAL_FSYNC_HEADROOM_BYTES` | u64 | `0` = OFF (`DEFAULT_WAL_FSYNC_HEADROOM_BYTES`) | bytes | `0` (unbounded) or any byte count | COLD |

A CoDel value outside its clamp is SILENTLY CLAMPED to the nearest bound (never a
startup error), per the "no per-device tuning" and "cannot refuse to start over a
CoDel value" criteria (#14). The CoDel TARGET and INTERVAL ship at the RFC 8289
recommended 5 ms / 100 ms when enabled, but CoDel is OFF by default (`target = 0`),
so an operator opts in. A CoDel shed rejects a NEW produce with a typed "shed under
load" signal and NEVER drops an already-accepted record (I2 holds). The retry
budget and the fire-and-forget bucket are accounting / admission controls that are
off by default; the egress AIMD limiter is always bounded to `[4, 128]` and starts
at its floor (16). Each control is observable on `/metrics`
(`ironbus_codel_shed_total`, `ironbus_codel_backstop_shed_total`,
`ironbus_codel_interval_resets_total`, `ironbus_retry_shed_total`,
`ironbus_fire_and_forget_shed_total`, `ironbus_egress_shed_total`, and the gauges
`ironbus_codel_sojourn_estimate_ms`, `ironbus_retry_ratio`, `ironbus_egress_limit`).
The fsync-headroom admission credit (`wal_fsync_headroom_bytes`, #378) bounds the
un-fsynced write backlog: under `sync` it throttles the group-commit backlog (a RAM
guard, never loses), under a relaxed durability level it caps the loss window in bytes
by shedding new produces. Off by default; observable as
`ironbus_wal_fsync_headroom_shed_total` and `ironbus_wal_fsync_headroom_bytes`.

> Wire-signal residual (#11): the machine-actionable `retry_after_ms` / `shed`
> fields on the rejection frame are owned by the frozen-protocol extension (#11) and
> are NOT in the protocol yet. Until #11 lands, a CoDel / retry shed rides the
> existing bare `Err` frame (a distinct, self-announcing message), exactly as
> BACKPRESSURE.md specifies; the structured hint is the part that waits on #11.

### Retention (`[retention]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `max_retained_bytes` | `--max-retained-bytes` / `IRONBUS_MAX_RETAINED_BYTES` | u64 | `0` = off (`DEFAULT_MAX_RETAINED_BYTES`) | bytes | `0` (off) or any u64 | HOT |
| `max_age_ms` | `--max-age-ms` / `IRONBUS_MAX_AGE_MS` | u64 | `0` = off (`DEFAULT_MAX_AGE_MS`) | ms | `0` (off) or any u64 | HOT |
| `max_messages` | `--max-messages` / `IRONBUS_MAX_MESSAGES` | u64 | `0` = off (`DEFAULT_MAX_MESSAGES`) | messages | `0` (off) or any u64 | HOT |

The three retention bounds COMPOSE: a sealed segment is reaped if ANY enabled
bound trips, and retention NEVER deletes a segment a consumer still needs (it
protects below the minimum committed offset across every group). All three
default to `0` (off), so an unconfigured broker is unbounded by retention and
bounded only by `max_total_bytes` and `disk_full_policy`.

### Backpressure / flow control (`[backpressure]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `disk_full_policy` | `--disk-full-policy` / `IRONBUS_DISK_FULL_POLICY` | enum | `drop-new` (`DEFAULT_DISK_FULL_POLICY`) | -- | `drop-new \| drop-oldest` | HOT |
| `consumer_credit` | `--consumer-credit` / `IRONBUS_CONSUMER_CREDIT` | u32 | `64` (`DEFAULT_CONSUMER_CREDIT`) | messages | `>= 1` (`0` floored to 1 at open) | HOT |
| `consumer_credit_bytes` | `--consumer-credit-bytes` / `IRONBUS_CONSUMER_CREDIT_BYTES` | u64 | `8388608` (8 MiB, `DEFAULT_CONSUMER_CREDIT_BYTES`) | bytes | `0` = unlimited or any u64 | HOT |
| `max_in_flight` | `--max-in-flight` / `IRONBUS_MAX_IN_FLIGHT` | u32 | `1024` (`DEFAULT_MAX_IN_FLIGHT`) | messages | `>= 1` (`0` rejected: `ZeroMaxInFlight`) | COLD |
| `max_connections` | `--max-connections` / `IRONBUS_MAX_CONNECTIONS` | usize | `256` (`DEFAULT_MAX_CONNECTIONS`) | count | `>= 1` | COLD |
| `max_groups` | `--max-groups` / `IRONBUS_MAX_GROUPS` | usize | `1024` (`DEFAULT_MAX_GROUPS`) | count | `0` = unlimited or any usize | COLD |
| `group_idle_evict_ms` | `--group-idle-evict-ms` / `IRONBUS_GROUP_IDLE_EVICT_MS` | u64 | `0` = disabled (`DEFAULT_GROUP_IDLE_EVICT_MS`) | ms | `0` (off) or any u64 | HOT |
| `ram_ceiling_bytes` | `--ram-ceiling-bytes` / `IRONBUS_RAM_CEILING_BYTES` | u64 | `0` = unset (`DEFAULT_RAM_CEILING_BYTES`; `edge-tiny` sets `67108864` = 64 MiB) | bytes | `0` (off) or `>=` the worst-case bounded-buffer footprint | COLD |
| `codel_target_ms` | SPECIFIED-NOT-YET-A-FIELD | u64 | `5` (CoDel TARGET) | ms | `[1 ms, 1 s]` (clamped) | HOT |
| `codel_interval_ms` | SPECIFIED-NOT-YET-A-FIELD | u64 | `100` (CoDel INTERVAL) | ms | `[20 ms, 10 s]` (clamped) | HOT |

The shipped overflow control is `disk_full_policy` plus the two per-consumer
credits; the CoDel sojourn-shedding TARGET/INTERVAL keys are SPECIFIED in
[BACKPRESSURE.md](BACKPRESSURE.md) but not wired (the #68/#10 residual). The
`block` overflow policy from the #14 draft is opt-in-only per the README and is
deliberately NOT a shipped value; only `drop-new` and `drop-oldest` ship (the
`DiskFullPolicy` enum is `#[non_exhaustive]` so a later `block` is additive).

### Delivery and leases (`[delivery]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `max_deliver` | `--max-deliver` / `IRONBUS_MAX_DELIVER` | u32 | `5` (`DEFAULT_MAX_DELIVER`) | attempts | `>= 1` and `< u32::MAX`; `0`/`u32::MAX` (unlimited) only with the opt-in | HOT |
| `allow_unlimited_deliver` | `--allow-unlimited-deliver` / `IRONBUS_ALLOW_UNLIMITED_DELIVER` | bool | `false` | -- | `true`/`1` or `false`/`0` | COLD (coupled with `max_deliver`) |
| `backoff_ms` | `--backoff-ms` / `IRONBUS_BACKOFF_MS` | list[u64] | `100,500,2000,10000,30000` (`DEFAULT_NACK_BACKOFF_NANOS`) | ms list | non-empty list of u64; a single `0` disables backoff | HOT |
| `visibility_timeout_ms` | `--visibility-timeout-ms` / `IRONBUS_VISIBILITY_TIMEOUT_MS` | u64 | `30000` (30 s, `DEFAULT_VISIBILITY_MS`) | ms | `>= 1` | HOT |
| `checkpoint_interval` | `--checkpoint-interval` / `IRONBUS_CHECKPOINT_INTERVAL` | u64 | `1024` (`DEFAULT_CHECKPOINT_INTERVAL`) | messages | any u64 (`0` treated as 1) | HOT |

The lease HARD cap is not an independent knob: it is derived as
`max(DEFAULT_HARD_CAP_MS = 300000, visibility_timeout_ms)`
(`LeaseConfig::from_millis(visibility_ms, visibility_ms.max(DEFAULT_HARD_CAP_MS))`
in `main.rs`), so it is never below one redelivery window. The repeatable
`--key-shared-group` and `--broadcast-group` are command-line ONLY (a list with a
per-group meaning does not flatten to one scalar env var), as CLI.md states.

### Network (`[network]`, `[network.tls]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `listen` | `--addr` / `IRONBUS_ADDR` | host:port | `127.0.0.1:7777` (`DEFAULT_ADDR`) | -- | a bindable `host:port` | COLD |
| `health_addr` | `--health-addr` / `IRONBUS_HEALTH_ADDR` | host:port | off (not set) | -- | a `host:port`; non-loopback requires `health_allow_public` (#95) | COLD |
| `health_allow_public` | `--health-allow-public` / `IRONBUS_HEALTH_ALLOW_PUBLIC` | bool | `false` (off) | -- | `true`/`1` or `false`/`0` | COLD |
| `health_liveness_window_ms` | `--health-liveness-window-ms` / `IRONBUS_HEALTH_LIVENESS_WINDOW_MS` | u64 | `10000` (10 s) | ms | `0` = disabled, else any positive window | COLD |
| `enable_admin` | `--enable-admin` / `IRONBUS_ENABLE_ADMIN` | bool | `false` (off) | -- | `true`/`1` or `false`/`0` | COLD |
| `tls.enabled` | SPECIFIED-NOT-YET-A-FIELD | bool | `false` | -- | bool; `cert_path`/`key_path` required when true | COLD |
| `tls.cert_path` / `tls.key_path` | SPECIFIED-NOT-YET-A-FIELD | path | none | path | a readable file, mode `& 0o077 == 0` | COLD |

TLS and the pre-auth DoS keys are SPECIFIED in [TRANSPORT.md](TRANSPORT.md) (the
#107 residual), not wired; the broker's WIRE bind today is loopback plaintext by
default. The fail-closed bind invariant IS enforced for the HEALTH surface (#95):
a non-loopback `health_addr` refuses to start unless `health_allow_public`
acknowledges the unauthenticated/unencrypted surface (then it binds with a loud
warning), since TLS/auth are not yet wired there either. `enable_admin` ships (it
gates the read-only `/admin` introspection endpoint) but the mutating `CONFIG`
verbs do not (#88).

### Observability (`[observability]`) and auth (`[auth]`)

Per the #139 coherence resolution, the locked, fatal-on-unknown top-level section
list is EXPANDED to include `[observability]` (#16) and `[auth]` (#18, with the
at-rest encryption keys under `[storage]` or `[network.tls]`), so the
fatal-on-unknown-key rule does not refuse to start a broker that carries its own
observability or security config. These sections are entirely
**SPECIFIED-NOT-YET-A-FIELD**: their keys are owned by [METRICS.md](METRICS.md) /
#16 (observability) and [AUTHENTICATION.md](AUTHENTICATION.md) /
[SECRETS.md](SECRETS.md) / [AT_REST_ENCRYPTION.md](AT_REST_ENCRYPTION.md) / #18
(auth and at-rest), and are listed here only to FREEZE the section names as part
of the #14 stability contract. #14 remains the single schema owner; #16 and #18
add their keys UNDER these reserved sections rather than restructuring config
under the existing tables.

### Frozen section names (the stability contract)

The top-level TOML sections are FROZEN as a stability contract: `[durability]`,
`[storage]`, `[retention]`, `[backpressure]`, `[network]` (with `[network.tls]`),
`[delivery]`, `[observability]`, and `[auth]`. A future rename ships the new name
WITH the old name as a deprecated alias, never a silent break. Unknown top-level
sections and unknown keys are REJECTED fatally by default (with an edit-distance
did-you-mean), because warn-and-ignore is how a typo silently disables durability
or retention; an opt-in `--allow-unknown-config` escape hatch downgrades it to a
warning for staged upgrades. This reject-by-default + frozen-sections rule is the #14
resolved decision; it is IMPLEMENTED (#382) by the #85/#86 parser in
`crates/ironbus-core/src/config.rs` (the did-you-mean uses edit distance) and
`crates/ironbus-cli/src/config_file.rs`.

---

## 4. Coupled-set validation rules

The config layer is the ONLY layer that sees every knob at once, so it OWNS
coupled-set validation, importing pure validator functions from the subsystem
issues (#6 durability, #13 retention, #10 backpressure, #12 compression). The
governing rule, stated once and applied everywhere:

> **The WHOLE effective config is validated as a unit BEFORE any value is
> applied.** A config is read-whole, then validated (per-key range checks AND
> every coupled-set check), then atomically installed (`Arc<Config>` swap). If
> ANY check fails, NOTHING is applied: at startup the broker refuses to start
> (fatal, naming the offending key and constraint); at hot reload the running
> config is left exactly unchanged. The hot path therefore never sees a
> half-applied or partially-validated config.

The per-flag range validation `serve` performs (each a usage error, exit 1, naming
the flag, per CLI.md) still ships: `--max-deliver` in `[1, u32::MAX)` unless opted in,
`--max-in-flight >= 1`, `--max-connections >= 1`, `--consumer-credit >= 1`,
`--max-segment-bytes >= 4096`, `--visibility-timeout-ms >= 1`, `--disk-full-policy` in
`{drop-new, drop-oldest}`. The COUPLED-SET checks below are now IMPLEMENTED (#382) in
the IO-free `crates/ironbus-core/src/config.rs` (`validate_coupled_sets`), run as a UNIT
over the whole resolved config before the broker opens (the durability none/async gate
keeps its shipped CLI-side home in `validate_durability`). The not-yet-a-field rows
(`max_record_bytes`, the compression set) are wired in the validator and fire the moment
their knob lands.

### Coupled set 1: segment size vs the record-size ceiling vs the RAM ceiling

`storage.segment_size` is coupled to the maximum record size and (on the edge) to
the RAM ceiling. A segment must be large enough to hold more than one record, so
a record never spans two segments (an INVARIANTS.md invariant). The SHIPPED check
is the floor `segment_size >= MIN_MAX_SEGMENT_BYTES` (4096 at the CLI layer);
`LogConfig::new` rejects a smaller value. The coupled check the #86 validator adds
is `segment_size >= max_record_bytes + header + footer`.

```
config error: storage.segment_size = 2048 is below the minimum 4096
  (smaller caps fragment the log into one-record segments)
config error: storage.segment_size = 16MiB cannot hold a max-size record:
  it must be at least max_record_bytes (16MiB) + frame overhead
```

### Coupled set 2: the consumer message credit vs the byte budget (RAM ceiling)

`backpressure.consumer_credit` (messages) and `consumer_credit_bytes` (bytes) are
a coupled RAM bound: the effective per-fetch delivery is
`min(message credit, byte budget)` with a hard floor of ONE message (a single
message larger than the whole byte budget is still delivered so it never wedges,
but nothing further is sent until bytes free). On an edge profile, the product
`max_connections * consumer_credit_bytes` is the worst-case in-flight RAM, and is
validated against the configured RAM ceiling (`ram_ceiling_bytes`).

When `ram_ceiling_bytes` is set (the `edge-tiny` profile sets 64 MiB; an operator
may set it on any profile), this is now ENFORCED by a refuse-to-boot guard (#115):
the broker computes the worst-case bounded-buffer footprint from the config and
refuses to start, with a usage error (exit 1) naming the overage, when it provably
exceeds the ceiling.

```
config error: --ram-ceiling-bytes 67108864 is below the worst-case bounded-buffer
  footprint the configured caps imply (over by N bytes): lower max_connections or
  consumer_credit_bytes (0 = unlimited cannot fit a small ceiling), or raise the
  ceiling. See docs/RAM_BUDGET.md for the worst-case formula.
```

(The verdict is PROVABLE from the config, never a boot-time RSS reading: RSS at
boot is near-zero and meaningless as a steady-state predictor. With a ceiling set
the `ironbus_ram_headroom_bytes` gauge also reports a real `ceiling - RSS` value
instead of the `-1` unset sentinel. See [RAM_BUDGET.md](RAM_BUDGET.md).)

### Coupled set 3: durability level vs the none-gate

`durability.level` is coupled to an explicit loss-acknowledgement gate. The safe
`fdatasync` level needs no gate. The relaxed `interval` and `none` levels (which
trade durability for throughput, contrary to the Edge First safe default) MUST
NOT be reachable by accident: selecting one requires an explicit
acknowledgement key (`durability.accept_data_loss = true`), and `interval`
additionally requires a positive `group_commit_max_delay_ms` linger window
(`none` with a 0 ms window would be a no-op). The whole `[durability]` set
(`level` + the linger knobs + the gate) is validated together.

```
config error: durability.level = "none" requires durability.accept_data_loss = true
  (the relaxed levels weaken the ack-implies-durable guarantee; opt in explicitly)
config error: durability.level = "interval" requires group_commit_max_delay_ms > 0
  (an interval level with a 0 ms flush window degenerates to per-record fdatasync)
```

### Coupled set 4: retention policy vs its limits

The retention bounds (`max_retained_bytes`, `max_age_ms`, `max_messages`) compose
(any enabled bound reaps), so the coupled check is that AT LEAST ONE bound is
enabled when a retention policy is requested, and that an enabled bound is
non-degenerate. With all three `0` (the default), retention is simply OFF and that
is valid; the check fires only when the operator asks for retention but leaves
every limit at `0`.

```
config error: retention requested but every limit is 0 (max_retained_bytes,
  max_age_ms, max_messages all disabled); enable at least one bound
```

### Coupled set 5: the disk-full byte cap vs the policy

`backpressure.disk_full_policy` only takes effect when `storage.max_total_bytes`
is set (with no cap, no produce is ever over-cap, so neither policy triggers).
Selecting `drop-oldest` with no cap is therefore a no-op the validator WARNS on,
so an operator who expected force-reap behavior learns the cap is missing.

```
config warning: backpressure.disk_full_policy = "drop-oldest" has no effect:
  storage.max_total_bytes is unset (0 = unlimited), so no produce is ever over-cap
```

### Coupled set 6: compression codec vs dictionary id

`compression.dictionary_id` is meaningful only when a codec is selected; a
non-zero dictionary id with `codec = "none"` is a misconfiguration. The codec
RUNTIME and the `serve --compression <none|lz4>` flag shipped (#387, default
`lz4`) and the serve write path is WIRED to the runtime (#430): records with a
compressible payload of 64 bytes or more are stored compressed behind the
`COMPRESSED` record flag, exactly what the materialized-config line echoes.
The `[compression]` FILE keys remain SPECIFIED-NOT-YET-A-FIELD (the section is
reserved and tolerated), owned by #12; the validator is named here for
completeness of the coupled-set surface #14 requires.

```
config error: compression.dictionary_id = 7 set but compression.codec = "none"
  (a dictionary id is only valid with a compressing codec)
```

---

## 5. The config-file format decision: TOML

IronBus's config FILE format is TOML. The decision and its rationale:

| Format | Verdict | Why |
| --- | --- | --- |
| **TOML** | **CHOSEN** | Typed scalars (int, bool, string, and the duration/size literal strings the knob surface needs); explicit `[section]` tables map one-to-one to the subsystem grouping; comments are allowed, which matters for an operator-facing file; hand-editable and unambiguous; a single mature pure-Rust parser keeps the static binary self-contained, cross-platform, and minimal-dependency. |
| YAML | rejected | Significant whitespace is a footgun (a mis-indented key silently changes scope); type coercion surprises (`no` becomes the boolean `false`, an unquoted version becomes a float); a heavier parser pulls more dependency surface, against the minimal-dep, single-static-binary posture. |
| JSON | rejected | No comments and no trailing commas make it hostile to a hand-edited operator file; trivial to emit machine-side but the config file is operator-facing first. |
| Flat `key value` (Redis style) | rejected | Dead simple to parse but has no structure for the grouped subsystems (`[durability]`, `[storage]`, ...) and no nesting for `[network.tls]`; the knob surface is naturally sectioned, so a flat format loses the grouping the stability contract freezes. |

The minimal-dependency point is load-bearing for IronBus specifically: the single
static musl binary embeds the parser, so config validation runs entirely
in-process with no network and no external schema service. A freshly flashed edge
device validates its own config offline.

### The frozen section structure (incorporating the #139 resolutions)

The illustrative file below shows the FROZEN section structure, the reconciled
key names, and the durability-literal reconciliation. The parser is now in the tree
(#382): `serve --config <path>` accepts exactly this format (the durability `level`
token is `sync | interval | async | none`, the implemented enum, not the old
`fdatasync` draft name shown in the older comment below).

The keys below are the ACCEPTED set (the implemented #382 typed-key table); a key not
in it is rejected with a did-you-mean unless `--allow-unknown-config` is passed.
SPECIFIED-NOT-YET-A-FIELD keys (`storage.segment_roll`, `durability.group_commit_*`,
`network.tls.*`, the compression set) are NOT yet accepted and are omitted from the
accepted example so a copied file validates; they land with their owning issues. The
reserved `[observability]`/`[auth]`/`[compression]` sections are TOLERATED (any key
under them is ignored, never rejected), so a broker carrying that config still starts.

```toml
# the ACCEPTED file format (#382): serve --config <path> reads this with the precedence
# flag > env > FILE > default. Durations use {ms,s,m,h,d}; byte sizes the binary
# {B,KiB,MiB,GiB,TiB}; the unit is required (decimal-SI MB/GB is rejected).

profile = "balanced"               # applies a coherent preset, then keys below override it

[durability]
level = "sync"                     # sync (default, ack-after-fdatasync, I2) | interval | async | none;
                                   # async/none require async_loss_ack = true (the loss gate)
flush_interval_ms = "1s"           # the interval-level time trigger (a duration literal)
flush_max_bytes = "1MiB"           # the interval-level unsynced-byte trigger
async_loss_ack = false             # the explicit data-loss acknowledgement for async/none

[storage]
segment_size = "64MiB"             # --max-segment-bytes; COLD (a reload may not change it)
data_dir = "/var/lib/ironbus"      # --data-dir; created 0700 if absent (#89); COLD
max_total_bytes = "0B"             # 0 = unlimited (a plain integer 0 is also accepted)

# [retention] is OFF by default (every bound 0); enable AT LEAST ONE bound when you add the
# section, else the coupled-set validator rejects "retention requested but every limit is 0".
# Example of an enabled retention policy (uncomment and size for the device):
# [retention]
# max_retained_bytes = "1GiB"        # any one enabled bound reaps; reaping never crosses a consumer

[backpressure]
disk_full_policy = "drop-new"      # drop-new | drop-oldest (block is opt-in-only, not shipped)
consumer_credit = 64               # per-connection message credit
consumer_credit_bytes = "8MiB"     # 8 MiB per-connection byte budget (0 = unlimited)
max_in_flight = 1024               # per-group window
max_connections = 256
max_groups = 1024                  # 0 = unlimited
ram_ceiling_bytes = "0B"           # 0 = off (edge-tiny sets 64 MiB); refuse-to-boot RAM guard (#115)

[delivery]
max_deliver = 5                    # 0/u32::MAX (unlimited) only with allow_unlimited_deliver
allow_unlimited_deliver = false
backoff_ms = [100, 500, 2000, 10000, 30000]
visibility_timeout_ms = "30s"      # a duration literal
checkpoint_interval = 1024

[network]
listen = "127.0.0.1:7777"          # loopback only by default
enable_admin = false

[observability]                    # reserved section (#139): any key here is tolerated (owned by #16)
[auth]                             # reserved section (#139): any key here is tolerated (owned by #18)
```

The #139 reconciliations encoded above:

- the durability literal is `fdatasync` (not `sync` / `batch` / `fsync-batch`),
  matching the README and the syscall;
- the batch knobs are `group_commit_max_delay_ms` / `group_commit_max_bytes`
  (the #6-frozen names and the 1 MiB byte semantics), NOT the draft's
  `fsync_interval_ms` / `fsync_max_batch` record-count knobs;
- the missing co-equal time roll `storage.segment_roll` is added;
- `[observability]` and `[auth]` are added to the frozen, fatal-on-unknown
  section list so #16/#18 config does not fail startup.

### The env-var and flag mapping for the same keys

Every key above is also reachable via its `serve` flag and its `IRONBUS_<FLAG>`
env var (the env mapping is SHIPPED, #89): the flag name minus its leading `--`,
uppercased, with each `-` replaced by `_`. The exact mapping table is in
[CLI.md](CLI.md). Arrays (`backoff_ms`) are comma-separated in env/flag form
(`IRONBUS_BACKOFF_MS=100,500,2000`); the literal grammar for durations and sizes
in the FILE is the #86 shared parser (durations `int + {ms,s,m,h,d}`, sizes
`int + binary {B,KiB,MiB,GiB,TiB}`, unit required, decimal SI rejected,
overflow-checked).

---

## 6. The three named profiles

A profile sets a coherent group of knobs in ONE move, then any explicit key
overrides it (applied-first-then-overridden, [section 2](#2-the-precedence-model-with-a-worked-multi-layer-example)).
A profile NEVER sets `data_dir` or TLS material. Profiles are compiled-in and
versioned (a profile's content change is a breaking change, logged via the
materialized-config dump). Profile SELECTION (the `--profile` flag and the
`IRONBUS_PROFILE` env var) is SHIPPED ([#87](https://github.com/ELares/IronBus/issues/87)):
the values below are the compiled-in presets the flag selects, applied first and then
overridden by any explicit env var or flag (precedence profile < env < flag), and the
active profile plus the `profile_schema_version` are emitted in the startup
materialized-config log line. The individual flag/env values are still reachable by hand;
`--profile` stamps a coherent set in one move.

The values below are real, currently-accepted flag values. The `edge-tiny`
column is cross-referenced byte-for-byte against the `tiny` profile table in
[EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md) and the worked budget in
[RAM_BUDGET.md](RAM_BUDGET.md), kept identical so the two docs never drift.

| Knob (flag) | `edge-tiny` | `balanced` (the default) | `throughput` |
| --- | --- | --- | --- |
| `segment_size` (`--max-segment-bytes`) | `8388608` (8 MiB) | `67108864` (64 MiB) | `268435456` (256 MiB) |
| `consumer_credit` (`--consumer-credit`) | `8` | `64` | `512` |
| `consumer_credit_bytes` (`--consumer-credit-bytes`) | `262144` (256 KiB) | `8388608` (8 MiB) | `67108864` (64 MiB) |
| `max_connections` (`--max-connections`) | `32` | `256` | `1024` |
| `max_groups` (`--max-groups`) | `64` | `1024` | `4096` |
| `max_in_flight` (`--max-in-flight`) | `256` | `1024` | `8192` |
| `ram_ceiling_bytes` (`--ram-ceiling-bytes`) | `67108864` (64 MiB) | `0` (off) | `0` (off) |
| `disk_full_policy` (`--disk-full-policy`) | `drop-new` | `drop-new` | `drop-oldest` |
| `checkpoint_interval` (`--checkpoint-interval`) | `1024` | `1024` | `4096` |
| `visibility_timeout_ms` (`--visibility-timeout-ms`) | `30000` | `30000` | `30000` |
| `max_deliver` (`--max-deliver`) | `5` | `5` | `5` |
| `durability.level` (the compiled default; no profile relaxes it, `--durability-level` is the only way, #341/#379) | `fdatasync` (= `sync`) | `fdatasync` (= `sync`) | `fdatasync` (= `sync`) |
| `segment_roll` (SPECIFIED-NOT-YET-A-FIELD) | `1h` | `1h` | `1h` |
| retention (`--max-*`) | enable at least one, device-sized | off by default (`0`) | off by default (`0`) |

One-line rationale each:

- **`edge-tiny`** favors a small RAM ceiling and flash gentleness on an
  unattended, battery-less ARM box: small 8 MiB segments (erase-block-friendly,
  never recycled), tight per-connection credits (8 messages / 256 KiB), few
  connections and groups, and `drop-new` to avoid the extra force-reap writes of
  `drop-oldest`. Its steady-state RAM sums to ~9 MiB, well under the 64 MiB edge
  ceiling (the per-term arithmetic is in [RAM_BUDGET.md](RAM_BUDGET.md) and
  [EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md)). The 8 MiB segment is the
  `EDGE_SEGMENT_BYTES` value. It also sets `ram_ceiling_bytes = 64 MiB`, which arms
  the refuse-to-boot RAM guard (#115): its own caps fit (the worst-case
  bounded-buffer footprint is well under 64 MiB), so it boots, but a blown-up cap
  override (e.g. a server-sized `--max-connections`) is provably refused.
- **`balanced`** is THE default, and is exactly the set of compiled-in
  `DEFAULT_*` constants in `main.rs` (64 MiB segments, 64 / 8 MiB consumer
  credits, 256 connections, 1024 groups, 1024 in-flight, `drop-new`, 1024
  checkpoint, 30 s visibility, 5 max-deliver). This is what `ironbus serve` with
  no profile, no file, no env var, and no flag runs, which is the
  zero-config-starts-on-`balanced` acceptance guarantee. (RAM_BUDGET.md notes
  these server-sized defaults are NOT edge-safe: 256 conns x 8 MiB is ~2 GiB
  worst case, which is exactly why `edge-tiny` exists.)
- **`throughput`** widens every buffer for a multi-core hub: large 256 MiB
  segments, wide consumer credits (512 messages / 64 MiB) and a wide 8192
  in-flight window, more connections and groups, a deeper checkpoint interval,
  and `drop-oldest` so a burst prefers spill-to-disk-then-reclaim over rejecting
  the producer.

The `balanced` row IS the shipped default set (each value is the real `DEFAULT_*`
constant), so `balanced` is the compiled-in default; selecting `edge-tiny` /
`throughput` by name (the `--profile` flag) is now SHIPPED (#87, the
`EDGE_TINY_PRESET` / `BALANCED_PRESET` / `THROUGHPUT_PRESET` constants in `main.rs`,
carrying `PROFILE_SCHEMA_VERSION`). The `edge-tiny` and `throughput` VALUES are also
reachable by passing the individual flags or `IRONBUS_*` env vars.

---

## 7. Implementation residuals and their owning issues

This document is the schema SPECIFICATION; most of its layers are now IMPLEMENTED.
The implementation status and the issues that own each layer:

- **[#85](https://github.com/ELares/IronBus/issues/85): the precedence resolver
  and the TOML config-file parser. SHIPPED (#382).** `serve --config <path>`
  whole-reads, parses (the pure-Rust `toml` crate), flattens, strictly validates,
  and slots the file between env and default (`flag > env > FILE > default`), in
  `crates/ironbus-cli/src/config_file.rs`. The atomic `Arc<EffectiveConfig>` load
  and the re-read RELOAD swap ship in `config_reload.rs`. The crash-safe SAVE
  (temp + fsync + rename + dir-fsync, comment-preserving) ties to the mutating
  admin surface and is the remaining #380/#106 residual.
- **[#86](https://github.com/ELares/IronBus/issues/86): the typed key table, the
  literal-grammar parser, and strict validation with coupled-set checks. SHIPPED
  (#382).** The shared duration/size literal grammar (unit-required, decimal-SI
  rejected, overflow-checked), the reject-unknown-key-with-did-you-mean rule (and
  `--allow-unknown-config`), and the coupled-set validators in
  [section 4](#4-coupled-set-validation-rules) live in the IO-free
  `crates/ironbus-core/src/config.rs`; the per-flag range checks still ship too.
- **[#87](https://github.com/ELares/IronBus/issues/87): the compiled-in versioned
  profiles and materialized-config logging. SHIPPED.** The `--profile` /
  `IRONBUS_PROFILE` selector, the `edge-tiny` / `balanced` / `throughput` named
  presets, the `PROFILE_SCHEMA_VERSION` versioning, and the materialized-config
  startup log line are implemented in `main.rs`. A profile content change is a
  documented breaking change (a `PROFILE_SCHEMA_VERSION` bump and a CHANGELOG entry).
- **[#88](https://github.com/ELares/IronBus/issues/88)/[#380](https://github.com/ELares/IronBus/issues/380):
  the hot/cold/coupled reload engine and the runtime admin `CONFIG` verbs. PARTLY
  SHIPPED (#382).** The immutable `Arc<EffectiveConfig>` (read via one atomic
  pointer load), the cold/hot key classification, and the atomic re-read RELOAD
  (validate the whole config, reject a cold-key change atomically, swap only on
  success) ship in `config_reload.rs`; the engine runs as a startup self-check
  AND on a runtime trigger: SIGHUP re-reads `--config` and applies the live-reloadable
  subset (the retention bounds + the disk-full policy) to the running broker, restart-required
  keys reported but not applied live ([#380](https://github.com/ELares/IronBus/issues/380)). The read-only
  `/admin` introspection endpoint (`--enable-admin`) ships. The MUTATING
  `CONFIG SET/SAVE` verbs change runtime state and need the
  [#106](https://github.com/ELares/IronBus/issues/106) connection-scoped auth, so
  they are DEFERRED (no unauthenticated remote config mutation surface).
- **[#89](https://github.com/ELares/IronBus/issues/89): the env mapping,
  `data_dir` lifecycle, and secret redaction.** The env mapping and the
  `data_dir` create-if-absent / probe-write / single-broker-lock lifecycle are
  SHIPPED (see [CLI.md](CLI.md)). Secret redaction in config dumps (the redacting
  newtype, the never-leak-a-secret test) is the remaining #89 / #109 residual.

No contradiction with merged docs was found: every shipped default, knob name,
and validation rule above matches `main.rs` / `engine.rs` / `log.rs` /
`lease.rs` / `delivery.rs` and the config-model table in
[CONTRACTS.md](CONTRACTS.md), the `edge-tiny` values match
[EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md) and [RAM_BUDGET.md](RAM_BUDGET.md), and
the durability literal and group-commit key names match
[DURABILITY.md](DURABILITY.md) and the #6/#139 reconciliations.

## Cross-references

- [CLI.md](CLI.md): the SHIPPED `serve` flag-and-default reference, the env-var
  mapping table, the `flag > env > default` precedence, and the `data_dir`
  lifecycle (each default cited to its `main.rs` constant).
- [CONTRACTS.md](CONTRACTS.md): the byte-level config-model reference
  (`EngineConfig` and the nested configs) and the explicit
  no-TOML-document-today boundary.
- [DURABILITY.md](DURABILITY.md): the authority for the one shipped `fdatasync`
  level and the specified-not-wired relaxed levels.
- [EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md) and [RAM_BUDGET.md](RAM_BUDGET.md):
  the `edge-tiny` / `tiny` profile values and the under-64-MiB RAM budget the
  profile realizes.
- [BACKPRESSURE.md](BACKPRESSURE.md): the CoDel and overflow-policy keys.
- [TRANSPORT.md](TRANSPORT.md), [AUTHENTICATION.md](AUTHENTICATION.md),
  [SECRETS.md](SECRETS.md), [AT_REST_ENCRYPTION.md](AT_REST_ENCRYPTION.md): the
  `[network.tls]`, `[auth]`, and at-rest keys (the #107/#106/#109/#108
  residuals).
- Issues: [#14](https://github.com/ELares/IronBus/issues/14) (this design),
  [#85](https://github.com/ELares/IronBus/issues/85) (parser + resolver),
  [#86](https://github.com/ELares/IronBus/issues/86) (key table + validation),
  [#87](https://github.com/ELares/IronBus/issues/87) (profiles),
  [#88](https://github.com/ELares/IronBus/issues/88) (reload + admin),
  [#89](https://github.com/ELares/IronBus/issues/89) (env mapping + data_dir +
  redaction), and the
  [#139](https://github.com/ELares/IronBus/issues/139) coherence resolutions.
