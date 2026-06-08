<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# The configuration system: precedence, the typed knob table, coupled-set validation, the TOML format, and the named profiles

This is the normative configuration-system specification for IronBus, the
[#14](https://github.com/ELares/IronBus/issues/14) DESIGN deliverable. It freezes
the layered precedence model, enumerates every configuration knob with its type,
default, units, valid range and reload class, specifies the coupled-set
validation rules, justifies the TOML file format, and defines the three named
profiles with their exact values.

It is a SPECIFICATION, not a feature claim. IronBus today resolves its
configuration from `serve` command-line flags and `IRONBUS_*` environment
variables ONLY: the precedence between those two layers and the `data_dir`
lifecycle are SHIPPED and specified in [CLI.md](CLI.md); the TOML config FILE,
the named PROFILES, and HOT RELOAD are SPECIFIED here but NOT YET IMPLEMENTED.
Each unimplemented layer is tagged with the issue that owns its implementation
residual, and the boundary between what ships and what is specified is drawn
explicitly throughout, so this document never claims an unwired layer exists.

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
| The TOML config FILE and its parser | **SPECIFIED here, NOT implemented** | [#85](https://github.com/ELares/IronBus/issues/85) |
| The named PROFILES (`edge-tiny` / `balanced` / `throughput`) and a `--profile` flag | **SPECIFIED here, NOT implemented** | [#87](https://github.com/ELares/IronBus/issues/87) |
| HOT RELOAD and the runtime admin `CONFIG` verbs | **SPECIFIED here, NOT implemented** | [#88](https://github.com/ELares/IronBus/issues/88) |
| Secret redaction in config dumps | **SPECIFIED, NOT implemented** (env mapping IS shipped) | [#89](https://github.com/ELares/IronBus/issues/89) |
| The typed key table, the literal grammar parser, and coupled-set validation | **SPECIFIED here; partial validation SHIPPED as per-flag range checks** | [#86](https://github.com/ELares/IronBus/issues/86) |

The honest one-line summary: the same knob surface is reachable TODAY via flags
and env vars on the SHIPPED two-layer precedence; the FILE, PROFILE, and RELOAD
layers in this document are the design IronBus is built toward, owned by #85,
#87, and #88. Nothing below should be read as claiming the file, profile, or
reload layers are wired. [CONTRACTS.md](CONTRACTS.md) states the same boundary
from the byte-model side ("There is NO TOML config document in the
implementation today").

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

Because no reload engine ships yet, the reload class is a SPECIFICATION of the
intended #88 behavior, not a property the binary enforces today; today every knob
is effectively COLD (set once at `serve` start). The class column is what #88
must implement.

### Storage (`[storage]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `segment_size` | `--max-segment-bytes` / `IRONBUS_MAX_SEGMENT_BYTES` | u64 | `67108864` (64 MiB, `DEFAULT_MAX_SEGMENT_BYTES`) | bytes | `>= 4096` (`MIN_MAX_SEGMENT_BYTES`) | COLD (coupled with `segment_roll`) |
| `data_dir` | `--data-dir` / `IRONBUS_DATA_DIR` | path | required (no default) | path | a writable directory; created 0700 if absent, probe-write verified (#89) | COLD |
| `max_total_bytes` | `--max-total-bytes` / `IRONBUS_MAX_TOTAL_BYTES` | u64 | `0` = unlimited (`DEFAULT_MAX_TOTAL_BYTES`) | bytes | `0` (off) or any u64 | HOT |
| `segment_roll` | SPECIFIED-NOT-YET-A-FIELD | duration | `0` = size-only (specified) | duration (`{ms,s,m,h,d}`) | `0` (off) or a positive duration | COLD (coupled with `segment_size`) |

`segment_roll` is the co-equal TIME roll trigger flagged in the #139 coherence
pass: the merged storage design (#4/#5/WAL.md) has a 1h time-based segment roll
in addition to the size cap, but the locked `[storage]` table and the shipped
`serve` flags expose only `segment_size`. It is added to the locked section list
here (COLD, COUPLED with `segment_size`) so the time roll is representable; the
field and flag are the #4/#87 implementation residual.

### Durability (`[durability]`)

| Knob (file key) | Flag / env | Type | Default | Units | Valid range | Reload |
| --- | --- | --- | --- | --- | --- | --- |
| `level` | SPECIFIED-NOT-YET-A-FIELD | enum | `fdatasync` | -- | `fdatasync` (shipped) `\| interval \| none` (specified, not wired) | COLD (coupled with the linger knobs) |
| `group_commit_max_delay_ms` | SPECIFIED-NOT-YET-A-FIELD | u64 | `0` (no linger) | ms | `0` or a positive bound | COLD (coupled with `level`) |
| `group_commit_max_bytes` | SPECIFIED-NOT-YET-A-FIELD | size | `1048576` (1 MiB cap) | bytes | a positive byte cap | COLD (coupled with `level`) |

The durability `level` enum literal is reconciled per the #14 second-pass and
#139 decisions: the single shipped level is named **`fdatasync`** (matching the
README and the actual syscall), NOT `sync` / `batch` / `fsync-batch`. v1 ships
exactly ONE level, `fdatasync` (ack-after-`fdatasync`, invariant I2), and it
CANNOT be weakened from the command line; the relaxed `interval` and `none`
levels are SPECIFIED but deliberately not wired, off by default, and require an
explicit data-loss acknowledgement before they can weaken I2. This is the
authority in [DURABILITY.md](DURABILITY.md); this document does not re-spec the
durability mechanism, only its config keys.

The batch-knob names are the #6-frozen `group_commit_max_delay_ms` /
`group_commit_max_bytes` (NOT the #14 draft's `fsync_interval_ms` /
`fsync_max_batch`), with the 1 MiB BYTE-cap semantics, default 0 ms linger. The
group-commit batcher is the #177 append actor; it amortizes one `fdatasync` over
a drained batch but still acks each record only after the covering sync returns,
so these knobs tune the COST of durability, never the GUARANTEE. They are
SPECIFIED-NOT-YET-A-FIELD: the append actor's batching is hardwired today, not a
configurable bound.

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
| `health_addr` | `--health-addr` / `IRONBUS_HEALTH_ADDR` | host:port | off (not set) | -- | a loopback `host:port` | COLD |
| `enable_admin` | `--enable-admin` / `IRONBUS_ENABLE_ADMIN` | bool | `false` (off) | -- | `true`/`1` or `false`/`0` | COLD |
| `tls.enabled` | SPECIFIED-NOT-YET-A-FIELD | bool | `false` | -- | bool; `cert_path`/`key_path` required when true | COLD |
| `tls.cert_path` / `tls.key_path` | SPECIFIED-NOT-YET-A-FIELD | path | none | path | a readable file, mode `& 0o077 == 0` | COLD |

TLS, the bind invariant, and the pre-auth DoS keys are SPECIFIED in
[TRANSPORT.md](TRANSPORT.md) (the #107 residual), not wired; the broker today is
loopback plaintext by default. `enable_admin` ships (it gates the read-only
`/admin` introspection endpoint) but the mutating `CONFIG` verbs do not (#88).

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
or retention; an opt-in `--allow-unknown-config` escape hatch is reserved for
staged upgrades. This reject-by-default + frozen-sections rule is the #14
resolved decision; it is SPECIFIED here and owned by the #85/#86 parser.

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

Today, the SHIPPED slice of this is the per-flag range validation `serve` already
performs (each a usage error, exit 1, naming the flag, per CLI.md): `--max-deliver`
in `[1, u32::MAX)` unless opted in, `--max-in-flight >= 1`, `--max-connections >= 1`,
`--consumer-credit >= 1`, `--max-segment-bytes >= 4096`, `--visibility-timeout-ms >= 1`,
`--disk-full-policy` in `{drop-new, drop-oldest}`. The COUPLED-SET checks below
are the #86 residual: they are SPECIFIED here with their error messages and are
not all wired yet.

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
validated against the documented RAM ceiling.

```
config error: backpressure.max_connections (256) * consumer_credit_bytes (8MiB)
  = 2GiB worst-case in-flight, over the 64MiB edge RAM ceiling;
  lower max_connections or consumer_credit_bytes, or select profile = "edge-tiny"
```

(The 64 MiB ceiling is a documented target met BY CONFIGURATION, not enforced by
a boot guard today: see [RAM_BUDGET.md](RAM_BUDGET.md). The boot-guard residual is
#115.)

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
non-zero dictionary id with `codec = "none"` is a misconfiguration. On-disk
compression is not landed (`codec` reads `none` today), so this whole set is
SPECIFIED-NOT-YET-A-FIELD, owned by #12; the validator is named here for
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
key names, and the durability-literal reconciliation. It is illustrative of the
SPECIFIED format; there is no TOML parser in the tree yet.

```toml
# illustrative: the SPECIFIED file format. There is no TOML parser yet (#85);
# configuration today is serve flags + IRONBUS_* env vars only.

profile = "balanced"               # applies a coherent preset, then keys below override it

[durability]
level = "fdatasync"                # the ONE shipped level (ack-after-fdatasync, I2);
                                   # interval | none are SPECIFIED, not wired, and gated
group_commit_max_delay_ms = 0      # #6-frozen linger window (0 = no linger)
group_commit_max_bytes = 1048576   # #6-frozen 1 MiB group-commit byte cap

[storage]
segment_size = "64MiB"             # --max-segment-bytes; COLD
segment_roll = "1h"                # co-equal time roll (SPECIFIED-NOT-YET-A-FIELD, #4/#87)
data_dir = "/var/lib/ironbus"      # --data-dir; created 0700 if absent (#89)
max_total_bytes = 0                # 0 = unlimited

[retention]
max_retained_bytes = 0             # 0 = off; any one enabled bound reaps
max_age_ms = 0
max_messages = 0

[backpressure]
disk_full_policy = "drop-new"      # drop-new | drop-oldest (block is opt-in-only, not shipped)
consumer_credit = 64               # per-connection message credit
consumer_credit_bytes = 8388608    # 8 MiB per-connection byte budget (0 = unlimited)
max_in_flight = 1024               # per-group window
max_connections = 256
max_groups = 1024                  # 0 = unlimited

[delivery]
max_deliver = 5                    # 0/u32::MAX (unlimited) only with allow_unlimited_deliver
backoff_ms = [100, 500, 2000, 10000, 30000]
visibility_timeout_ms = 30000
checkpoint_interval = 1024

[network]
listen = "127.0.0.1:7777"          # loopback only by default
enable_admin = false

[network.tls]
enabled = false                    # SPECIFIED, not wired (#107); cert_path/key_path when true

[observability]                    # reserved section (#139); keys owned by #16
[auth]                             # reserved section (#139); keys owned by #18 (+ at-rest)
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
materialized-config dump). Profile SELECTION (a `--profile` flag) is the
[#87](https://github.com/ELares/IronBus/issues/87) implementation residual; this
section SPECIFIES the values. Today these are the individual flag/env values an
operator passes by hand.

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
| `disk_full_policy` (`--disk-full-policy`) | `drop-new` | `drop-new` | `drop-oldest` |
| `checkpoint_interval` (`--checkpoint-interval`) | `1024` | `1024` | `4096` |
| `visibility_timeout_ms` (`--visibility-timeout-ms`) | `30000` | `30000` | `30000` |
| `max_deliver` (`--max-deliver`) | `5` | `5` | `5` |
| `durability.level` (always on, not a flag today) | `fdatasync` | `fdatasync` | `fdatasync` |
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
  `EDGE_SEGMENT_BYTES` value.
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
constant), so `balanced` is implemented today as the compiled-in defaults; only
the SELECTION of `edge-tiny` / `throughput` by name (the `--profile` flag) is the
#87 residual. The `edge-tiny` and `throughput` VALUES are reachable today by
passing the individual flags or `IRONBUS_*` env vars.

---

## 7. Implementation residuals and their owning issues

This document is SPECIFICATION. The IMPLEMENTATION residuals it specifies, and
the issues that own them:

- **[#85](https://github.com/ELares/IronBus/issues/85): the precedence resolver,
  the TOML config-file parser, and atomic load/reload.** There is no `toml`
  dependency and no config-file layer in the tree today; configuration is
  populated from `serve` flags and `IRONBUS_*` env vars only. Adding the parser
  (whole-read, then validate, then atomic `Arc<Config>` swap; crash-safe SAVE via
  temp + fsync + rename + dir-fsync) is the #85 residual. The two SHIPPED layers
  (env, flag) and their `flag > env > default` precedence are already wired (#89,
  [CLI.md](CLI.md)).
- **[#86](https://github.com/ELares/IronBus/issues/86): the typed key table, the
  literal-grammar parser, and strict validation with coupled-set checks.** The
  per-flag range checks ship; the shared duration/size literal grammar, the
  reject-unknown-key-with-did-you-mean rule, and the coupled-set validators in
  [section 4](#4-coupled-set-validation-rules) are the #86 residual.
- **[#87](https://github.com/ELares/IronBus/issues/87): the compiled-in versioned
  profiles and materialized-config logging.** The `--profile` selection flag, the
  `edge-tiny` / `throughput` named presets, profile versioning, and the
  materialized-config dump are the #87 residual. The `balanced` profile is the
  shipped default set; the other two profiles' VALUES are reachable via
  individual flags today.
- **[#88](https://github.com/ELares/IronBus/issues/88): the hot/cold/coupled
  reload engine and the runtime admin `CONFIG` verbs.** The reload classes in
  [section 3](#3-the-full-typed-knob-table) are SPECIFICATION; no reload engine
  ships, so every knob is effectively COLD (set once at `serve` start). The
  `CONFIG GET/SET/LIST/DIFF/RELOAD/SAVE` admin surface (SET volatile and
  highest-precedence, SAVE explicit and atomic) is the #88 residual. The
  read-only `/admin` introspection endpoint (`--enable-admin`) ships; the
  mutating verbs do not.
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
