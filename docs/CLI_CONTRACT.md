<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus CLI machine-output contract

This is the normative, frozen DESIGN spec for the scriptable surface of the `ironbus`
binary: the versioned `--json` schema contract, the global flags and how they interact
with the per-command online/offline classification, and the exit-code-3 corruption gate.
It completes the M1 command-map design issue [#136](https://github.com/ELares/IronBus/issues/136)
by freezing the three pieces the shipped reference deliberately left open: a stable,
versioned machine-output format, the mode-forcing global flags, and a non-zero exit code
for a structured-but-degraded result.

> Scope. This document specifies a CONTRACT (the JSON shape, the flag semantics, the
> exit-code meaning). It is **specified, not yet implemented**: the current binary parses
> only the surface enumerated in [`CLI.md`](CLI.md) and maps only the six exit codes
> `0/1/2/4/5/70`. The verb IMPLEMENTATIONS that emit these schemas (`scrub`/`repair`
> [#92](https://github.com/ELares/IronBus/issues/92), `top`
> [#93](https://github.com/ELares/IronBus/issues/93), `consumer lag`, `segments`,
> `dlq`, `retention`, `info`, `tap`, `wire`, `bench`, `config`, `recovery report`,
> `completions`) are tracked under the children of
> [#15](https://github.com/ELares/IronBus/issues/15). This doc is the COMMAND-MAP and
> `--json`/flags/exit-code DESIGN, not the verb impls.

## Where this fits

Three documents describe the CLI, in order of abstraction:

- [`USAGE.md`](USAGE.md): the prose walkthrough (how to use the binary, worked examples).
- [`CLI.md`](CLI.md): the exhaustive map of the surface that SHIPS TODAY, every flag with
  its type/default/unit cited to a `main.rs` constant, and the six exit codes the binary
  emits. Canonical for what is implemented.
- This file: the frozen CONTRACT for the DESIGNED machine surface (the versioned `--json`
  schema, the global flags, the exit-code-3 gate). Canonical for what scripts may rely on
  once the verbs land.

The full verb/noun tree, color-coded online/offline/offline-only, is frozen in the diagram
[`diagrams/07-cli-command-tree.dot`](diagrams/07-cli-command-tree.dot) (rendered
`07-cli-command-tree.pdf`). This file does NOT restate the tree; it cites it. Where this
file names a command's mode (online, offline, offline-only) it MUST agree with that
diagram and with the per-command tables in [`CLI.md`](CLI.md); a divergence is a bug in
this file.

The schema-version bump rule below is the SAME rule the version registry
[`compat/versions.md`](compat/versions.md) (#126) applies to every other versioned
id-space, and the same rule the `ironbus.loss-report.v1` schema
([`schemas/loss-report.v1.md`](schemas/loss-report.v1.md), #120) already follows. The CLI
`--json` schemas are registered there as a new id-space family when the verbs land; this
doc is their normative definition.

## 1. The versioned `--json` schema contract

`--json` is a COMMITTED, versioned contract. Human-readable text (the default) carries NO
stability guarantee: columns, ordering, and wording may change between releases, as
[`CLI.md`](CLI.md) already states. A consumer that wants stability MUST pass `--json` and
key off the `schema` field.

### 1.1 Every object carries a `schema` field

Every JSON object the CLI emits under `--json`, whether a single result object or one line
of a stream, carries a top-level string field:

```
"schema": "ironbus.cli.<command>.vN"
```

`<command>` is the dotted command path with spaces replaced by dots (`serve-status`,
`pub-result`, `sub-record`, `dump-record`, `consumer.lag`, `segments.verify`,
`scrub-result`, `repair-plan`, `dlq.ls`, `retention.info`, `recovery.report`). `N` is an
integer schema version starting at `1`. The `schema` string is the FULL discriminator: a
consumer matches on the exact string and never parses the version out of band.

The shipped offline output that exists today (the `peek`/`dump` per-record line and the
trailing loss object documented in [`CLI.md`](CLI.md)) is the v0 PRECURSOR of this
contract: it has the right field set but does NOT yet carry the `schema` envelope. Adding
the `schema` field (and the header object for the streaming verbs, see 1.3) is the change
that promotes those objects to `ironbus.cli.dump-record.v1` / `ironbus.cli.peek-record.v1`.
Because adding a field is backward compatible (see 1.5), a consumer reading today's
schema-less line keeps working; the promotion is additive.

### 1.2 A result object is emitted EVEN ON A NON-ZERO EXIT

Under `--json`, every command emits a terminal result/summary object, and it does so on
EVERY exit path including a non-zero one. A health check or pipeline that runs an `ironbus`
command under `--json` is GUARANTEED a parseable object on stdout describing the outcome,
so it never has to scrape stderr or infer failure from an empty stream. The result object
carries the exit code it is about to return in its `exit_code` field, so a consumer reading
only stdout learns the code without inspecting `$?`.

The one exception is exit `1` (a usage/argument error): a malformed invocation is rejected
by the argument parser BEFORE any command runs, so there is no command context to emit a
schema for. Exit `1` prints the usage banner to stderr and emits no JSON, exactly as the
shipped binary does. Every other code (`0`, `2`, `3`, `4`, `5`, `70`) emits a result
object under `--json`.

### 1.3 Streaming verbs emit NDJSON: a header object, then record objects

The streaming verbs (`sub`, `dump`, `peek`, `tap`, `top --json`) emit
[NDJSON](https://ndjson.org/) ([archived 2026-05-08](https://web.archive.org/web/20260508182020/https://ndjson.org/)): one JSON object per line, no enclosing array. The first line
is a HEADER object that describes the stream; each following line is one RECORD object;
the LAST line is the terminal result/summary object (1.2). So a streaming `--json` run is:

```
{"schema":"ironbus.cli.<command>.header.vN", ...}     <- header, exactly one, first
{"schema":"ironbus.cli.<command>-record.vN", ...}     <- zero or more records
{"schema":"ironbus.cli.<command>-record.vN", ...}
{"schema":"ironbus.cli.<command>.result.vN", ...}     <- summary, exactly one, last
```

The header lets a consumer set up before the first record (it carries the source, the
bounds, and the stream's record schema name) and lets a stream that yields zero records
still announce itself. The header, record, and result schemas version INDEPENDENTLY (each
is its own id-space line in the registry), so a record-field addition does not force a
header bump.

Non-streaming verbs (`serve`'s status line, `pub`, `consumer lag`, `segments verify`,
`scrub`, `repair`, `info`, `retention info`, `recovery report`) emit a SINGLE result
object and no header.

### 1.4 Encoding conventions (consistent with #16)

These match the metric-encoding contract in [`METRICS.md`](METRICS.md) (#16) and the shaped
output already in [`CLI.md`](CLI.md), so the CLI and the metrics endpoint never disagree on
units:

- Durations are in the field's named unit suffix: `_ms` is milliseconds, `_us` is
  microseconds, `_s` is seconds. A field with no unit suffix that is a duration is an
  error; always suffix.
- Sizes are bytes (`_bytes`).
- Offsets and sequences are base-10 unsigned 64-bit integers, emitted as JSON numbers.
  (Offsets stay within 2^53 in practice; a consumer that needs the full u64 range reads
  the same value from the metrics endpoint, which is string-safe.)
- Timestamps are `ts_ms`, milliseconds since the Unix epoch, the record's STORED timestamp,
  never a CLI-side clock read (lag-age is computed from the stored timestamp, never a
  cross-clock comparison, per [`CLI.md`](CLI.md) and #16).
- Raw key and payload BYTES are NEVER emitted; only their byte lengths (`key_bytes`,
  `bytes`), so a binary payload never corrupts the stream (the rule already in
  [`CLI.md`](CLI.md)'s offline output shapes). A verb that must surface bytes (a future
  `dump --decode`) emits them base64 in an explicitly-named field, never raw.

### 1.5 The schema-version bump rule (additive vs breaking, per #126)

The CLI `--json` schemas follow the EXACT append-only-vs-breaking discipline the version
registry [`compat/versions.md`](compat/versions.md) (#126) defines for every id-space, and
that the `ironbus.loss-report.v1` schema (#120) already lives by:

- **Additive (no bump).** Adding a NEW OPTIONAL field to an object is backward compatible
  and does NOT bump `N`. A consumer that does not know the field ignores it; a consumer
  that needs it treats its absence as "older producer". A field is only safe to add this
  way if its ABSENCE is a valid, meaningful state (so a new field is born optional, never
  required mid-version).
- **Breaking (bump `N`).** Removing a field, renaming a field, changing a field's type, or
  changing a field's MEANING is a breaking change. It bumps `N` (e.g.
  `ironbus.cli.sub-record.v1` to `...v2`) and is gated by the project's SemVer policy
  (#22/#126): a breaking schema bump cannot ride a patch release.
- **Registered.** Each `ironbus.cli.<command>.vN` schema is a row in the version registry's
  table when its verb lands, with its current `N`, the code symbol that serializes it, the
  append-only-vs-breaking rule (this section), and its owner issue under #15. The registry's
  REFUSE/POISON/NEGOTIATE classification places the CLI schemas under "a consumer reads only
  its known `N`": a consumer that sees a HIGHER `N` than it knows treats the object as a
  forward-incompatible producer and fails closed, exactly as the loss-report `schema_version`
  rule does.

This is the same rule applied to a different surface: the loss-report freezes a wire schema
for recovery; the CLI freezes a wire schema for the operator tooling. Both are golden-pinned
once their emitters exist (the loss-report already is; the CLI schemas are pinned by the
verb-impl PRs under #15).

### 1.6 Concrete JSON shapes (frozen)

The shapes below are the v1 frozen forms. Field types follow 1.4. Each is annotated with
its command's mode (it MUST match the command tree and [`CLI.md`](CLI.md)).

#### `serve-status` (online; the `serve` startup result)

The structured form of the human banner `serve` prints on a successful bind. A single
result object (not streaming):

```json
{
  "schema": "ironbus.cli.serve-status.v1",
  "addr": "127.0.0.1:7777",
  "data_dir": "/var/lib/ironbus",
  "health_addr": null,
  "max_connections": 256,
  "durability": "sync",
  "unlimited_deliver": false,
  "exit_code": 0
}
```

`health_addr` is `null` when `--health-addr` is unset (an optional field whose null is
meaningful, so a later non-null is additive). `durability` echoes the level
([`DURABILITY.md`](DURABILITY.md): v1 ships only `sync`). `exit_code` is `0` on a clean
bind; a bind that fails (e.g. the single-broker lock is held) returns the structured error
object (below) with the relevant non-zero code.

#### `pub-result` (online; the `pub` result)

The structured form of the durable-offset line `pub` prints. The offset is present only
after the record is fsynced, so its presence means the message is durable:

```json
{
  "schema": "ironbus.cli.pub-result.v1",
  "offset": 42,
  "key_bytes": 0,
  "bytes": 128,
  "durable": true,
  "exit_code": 0
}
```

On an unreachable broker `pub` emits the error object with `exit_code: 5` and no `offset`
(nothing was durably written), so a consumer keys on `durable`/`offset` presence, never on
a sentinel offset.

#### `sub-record` (online; one record in the `sub` stream)

`sub` is streaming, so it emits a header, then one `sub-record` per delivered message, then
a `sub-result` summary. The record:

```json
{
  "schema": "ironbus.cli.sub-record.v1",
  "offset": 42,
  "gen": 7,
  "key_bytes": 4,
  "bytes": 128,
  "ts_ms": 1733512345678,
  "codec": "none",
  "disposition": "ack",
  "ack_status": "committed"
}
```

`gen` is the lease fencing token (carried on the acknowledgement, matching the human
`gen=` field in [`CLI.md`](CLI.md)). `disposition` is one of `peek`/`ack`/`nack`/`term`;
`ack_status` is `committed`/`requeued`/`dropped`/`fenced` and is absent for a peek (an
additive-absence field). In-band advisories (`dead-letter`, `truncated`) are their own
schema'd objects interleaved in the stream, never folded into a record. The `sub` header
and the `sub-result` summary (delivered count, exit code) bracket the stream.

#### `dump-record` (offline; one record in the `dump`/`peek` stream)

`dump` and `peek` are offline streams; their record object is the schema'd promotion of the
line already in [`CLI.md`](CLI.md):

```json
{
  "schema": "ironbus.cli.dump-record.v1",
  "offset": 42,
  "ts_ms": 1733512345678,
  "bytes": 128,
  "key_bytes": 4,
  "crc": "ok",
  "codec": "none",
  "decoded": true
}
```

`crc` is `ok` (the offline reader only yields records that passed CRC) and `codec` is
`none` until on-disk compression lands, matching [`CLI.md`](CLI.md). `decoded` is `true`
normally; for a compressed record whose dictionary is missing it is `false` with a
`reason` field (`"missing-dict:<id>"`), per the #136 body and
[`DICTIONARY_LIFECYCLE.md`](DICTIONARY_LIFECYCLE.md) (a missing dictionary is a
structured-degraded record, NOT a failure, unless `--require-dict` is set). `peek` uses the
same record under `ironbus.cli.peek-record.v1`. The stream's trailing loss object (the
torn/corrupt tail) is its own schema, the promotion of [`CLI.md`](CLI.md)'s
`{"loss":{...}}` object to `ironbus.cli.dump.loss.v1`, carrying the same
`bytes`/`events[]` shape as the `ironbus.loss-report.v1` events (segment id, start, end,
reason), so the CLI loss object and the recovery loss report agree on every field name.

#### `admin-consumer-reset` (offline MUTATING; the `admin consumer-reset` result, #299)

The single result object of the OFFLINE consumer reset. The verb operates on a STOPPED
broker's `--data-dir` under the exclusive data-dir lock, so it is never a wire surface and
needs no auth (the MUTATING WIRE form is deferred to the authed admin surface #380/#106).

```json
{
  "schema": "ironbus.cli.admin-consumer-reset.v1",
  "data_dir": "<dir>",
  "group": "<name>",
  "committed": 4,
  "previous_committed": 12,
  "earliest_retained": 0,
  "head": 10,
  "ok": true,
  "exit_code": 0
}
```

`committed` is the resolved, range-clamped offset the cursor was rewritten to;
`previous_committed` is the prior durable committed offset, or `null` if the group had no
durable cursor before. `earliest_retained`/`head` are the durable range the target was
clamped against. An explicit `--to <offset>` outside `[earliest_retained, head]` is REJECTED
(exit `1`, the `ironbus.cli.result.v1` envelope, not this object); `earliest`/`latest`
resolve to the range ends.

#### `admin-dlq-redrive` (offline MUTATING; the `admin dlq-redrive` result, #299)

The single result object of the OFFLINE DLQ redrive (re-inject the dead-lettered records onto
the main log, crash-safely and idempotently, under the exclusive lock).

```json
{
  "schema": "ironbus.cli.admin-dlq-redrive.v1",
  "data_dir": "<dir>",
  "redriven": 4,
  "dlq_records": 4,
  "already_redriven": 0,
  "ok": true,
  "exit_code": 0
}
```

`redriven` is how many DLQ records this run re-injected (0 on an idempotent re-run after a
completed redrive); `dlq_records` is the DLQ depth; `already_redriven` is the durable redrive
watermark on entry. The crash-safe ordering (records fsynced, THEN the watermark advanced) and
the at-least-once re-redrive on a crash before the watermark advance are described in
[`CLI.md`](CLI.md).

#### The error/result object (every command; emitted on a non-zero exit)

The terminal object on ANY non-zero exit path (except usage exit `1`, see 1.2). It is the
structured failure a health check parses:

```json
{
  "schema": "ironbus.cli.result.v1",
  "command": "scrub",
  "ok": false,
  "exit_code": 3,
  "error": {
    "kind": "corruption-handled",
    "message": "scrub completed: 2 corrupt span(s) skipped, 65536 byte(s)",
    "detail": {
      "skipped_spans": 2,
      "skipped_bytes": 65536,
      "max_lag_exceeded": false
    }
  }
}
```

`kind` is a stable enum string mapped one-to-one to the exit code: `corruption-handled`
(exit `3`), `not-found` (exit `2`), `corrupt` (exit `4`), `unreachable` (exit `5`),
`internal` (exit `70`). `ok` is `false` for any non-zero `exit_code` and `true` for `0`;
on a CLEAN run (`exit_code: 0`) the same `ironbus.cli.result.v1` envelope is emitted with
`ok: true` and `error: null`, so a consumer reads one object shape regardless of outcome.
`detail` is an open, additive object whose keys depend on `command` (a `scrub`/`peek`/
`dump` carries skip counts; a `consumer lag` carries the lag tuple and the `--max-lag`
breach). Adding a `detail` key is additive (1.5).

## 2. The global flags

Five flags apply to EVERY subcommand. The first four are already frozen in the command
tree's legend and [`CLI.md`](CLI.md); this section adds the mode-forcing semantics of
`--offline`/`--online` and pins `--config`.

| Flag | Value | Default | Applies to |
|------|-------|---------|------------|
| `--data-dir <path>` | path | `serve` requires it; offline verbs require it | the on-disk log directory (the source of truth for offline verbs) |
| `--config <path>` | path | unset (defaults from #14 resolution) | the TOML config file (#14); a verb-relevant subset of its keys seeds defaults, flag > env > config > compiled default |
| `--addr <host:port>` | host:port | `127.0.0.1:7777` (`DEFAULT_ADDR`) | the broker socket for online verbs |
| `--json` | flag | off (human text) | the versioned machine output (section 1) |
| `--offline` / `--online` | flag (mutually exclusive) | unset (auto-classify) | FORCE the mode (this section) |

### 2.1 `--config <path>`

`--config` points at the TOML config file (#14). Its precedence sits one rung below the
environment variables documented in [`CLI.md`](CLI.md)'s env-mapping table: the order is
**flag > env > config-file > compiled default**. A config-file value is read only for the
keys a given command honors (a `serve` reads the broker bounds; an offline verb reads at
most the data-dir resolution), so `--config` never injects an irrelevant key into a
command. A missing `--config` path that was explicitly passed is a usage error (exit `1`,
naming the path); an UNSET `--config` falls back to the #14 default-resolution chain and is
not an error. The broader profile and hot-reload machinery is a #14 follow-up; `--config`
here is the file-path flag and its precedence rung only.

### 2.2 `--offline` and `--online` force the mode

Each leaf in the command tree
([`diagrams/07-cli-command-tree.dot`](diagrams/07-cli-command-tree.dot)) is tagged ONLINE
(blue: it speaks the wire protocol on `--addr`), OFFLINE-CAPABLE (green: it can read the
data dir directly but can also consult a broker), or OFFLINE-ONLY (tan: it ONLY reads the
data dir and never connects). A command that can run EITHER way (an offline-capable green
leaf, e.g. `info`, `peek`, `dump`, `consumer lag`) auto-classifies: it runs offline when
`--data-dir` is reachable and no broker holds the lock, online when `--addr` answers.
`--offline` and `--online` FORCE the mode and make a mismatch a hard failure instead of a
silent fallback:

- `--offline` forces the data-dir path. On an ONLINE-ONLY command (a blue leaf:
  `serve`, `pub`, `sub`, `tap`, `bench`, `consumer reset/purge/pause/resume`,
  `dlq redrive/purge`, `retention reap`, `config get/set/reload`) `--offline` is a USAGE
  ERROR (exit `1`): the command has no offline implementation, so silently doing nothing
  would be worse than rejecting. The rejection names the command and the conflict.
- `--online` forces the broker path. On an OFFLINE-ONLY command (a tan leaf: `wire`,
  `segments ls/verify`, `scrub`, `repair`, `config check/print/schema`,
  `recovery report`, `version`, `completions`) `--online` is a USAGE ERROR (exit `1`): the
  command reads bytes the broker does not serve (sealed-segment CRCs, the on-disk config
  file, the captured frame dump), so there is nothing to force online.
- On an OFFLINE-CAPABLE (green) command, `--offline`/`--online` simply PIN the
  auto-classification to one side and fail (exit `2` if the forced side is unreachable: no
  data dir for `--offline`, no broker for `--online`) rather than falling back to the other.
- `--offline` and `--online` together are a usage error (exit `1`); they are mutually
  exclusive.

This is the symmetric rule the #136 acceptance criteria require: "an offline-only command
rejects `--online` and vice versa." The mode each flag forces, and which leaves are
online/offline-capable/offline-only, is the SAME tagging as the command-tree diagram; this
table does not introduce a new classification, it states the flag interaction over the
existing one.

> Note (#299): the MUTATING consumer-reset and DLQ-redrive actions ship today only in their
> OFFLINE-ONLY forms, `admin consumer-reset` and `admin dlq-redrive`, which read and rewrite a
> STOPPED broker's `--data-dir` under the exclusive lock (and so are tan/offline-only: they refuse
> a running broker, never connect, and reject `--online`). The blue `consumer reset` / `dlq
> redrive` WIRE leaves above (and `force-reap` on a live broker) remain DEFERRED to the authed admin
> surface (#380/#106): a mutating action over the wire needs connection-scoped auth, so it cannot
> share the unauthenticated trust model and is intentionally not shipped here.

### 2.3 `--data-dir`, `--addr`, `--json`

These keep their [`CLI.md`](CLI.md) meaning unchanged. `--data-dir` is the offline source
of truth and is required by `serve` and the offline verbs. `--addr` is the broker socket
for online verbs (loopback default, never exposed without an explicit `--addr`). `--json`
selects the section-1 contract. `--log-level` (in the diagram legend) tunes diagnostic
verbosity and never changes a command's output contract or exit code.

## 3. The exit-code-3 gate

[`CLI.md`](CLI.md) freezes the SHIPPED exit-code scheme from the `EXIT_*` constants in
`main.rs`: `0` clean, `1` usage, `2` not-found, `4` corrupt-blocked, `5` unreachable,
`70+` internal. The value `3` is currently UNUSED by the binary. This section reserves it.

### 3.1 What exit `3` means

Exit `3` is **handled corruption / a structured-but-degraded result**: the command RAN TO
COMPLETION and produced a structured result, but that result reports a degraded condition
the operator should alert on. It is the code that lets an alert fire WITHOUT the command
itself having failed. Two conditions return `3`:

1. A read-only inspection (`scrub`, `peek`, `dump`, `segments verify`) completed and
   reported one or more SKIPPED records: it read past a torn or corrupt span, marked it
   (never hid it), and finished. The data it could read is in the stream; the skipped span
   is in the trailing loss object and counted in the result object's `detail`.
2. A `--max-lag` threshold was exceeded (3.3): the lag query succeeded and returned a real
   number, but the number breaches the operator's threshold.

In both cases the command SUCCEEDED at its job (it scrubbed, it dumped, it measured); the
non-zero code communicates the DEGRADED FINDING, not a command failure. Under `--json` the
terminal `ironbus.cli.result.v1` object carries `exit_code: 3`, `ok: false`, and
`kind: "corruption-handled"` (1.6), so a health check gets the structured detail alongside
the code.

### 3.2 Why `3` does not collide with the existing scheme

The shipped scheme has a deliberate hole at `3`, and the new meaning is DISTINCT from each
neighbor, so nothing is overloaded:

| Code | Meaning | How `3` differs |
|------|---------|-----------------|
| `0` | clean; the command completed with nothing to report (a `peek`/`dump` over a CLEAN dir, or a lag UNDER `--max-lag`, exits `0`) | `3` means it completed but found a degraded condition to report |
| `1` | usage/argument error (the parser rejects before any command runs) | `3` is a RAN-TO-COMPLETION outcome, never an argument problem |
| `2` | operational not-found (no such data-dir, consumer, or cursor) | `3` means the target WAS found and read; a degraded span or lag was reported |
| `4` | corruption that BLOCKED completion (could not read the segment chain/header; the command could not finish) | `3` means corruption was HANDLED and the command FINISHED; `4` means it could not. This is the load-bearing distinction: `4` is "I gave up", `3` is "I finished and here is the damage" |
| `5` | broker unreachable for an online verb | `3` is independent of reachability; an offline `scrub` never touches the broker |
| `70+` | internal/runtime failure (IO error, wrong-shape frame, unsupported platform) | `3` is an expected, structured outcome, not an internal fault |

The existing `0` (a `peek`/`dump` that marked a torn tail still exits `0`) is the key
boundary to honor: TODAY, a marked torn tail is exit `0` because the binary has no `3`. The
DESIGN refines that for the inspection verbs (`scrub`/`peek`/`dump`/`segments verify`): once
`3` exists, a run that SKIPPED a span (a real corruption skip, reason other than the
expected `TornTail`) exits `3`, while a clean run, AND a run whose only skip is an expected
`TornTail` brownout truncation, stays `0`. This mirrors the loss-report's own
data-loss-vs-reported-skip boundary ([`schemas/loss-report.v1.md`](schemas/loss-report.v1.md),
`ReasonCode::is_data_loss`): a `TornTail` is a REPORTED SKIP but NOT data loss, so it does
NOT trip the alert code; every other reason IS data loss and trips `3`. This keeps `3`
consistent with the recovery scheme rather than inventing a second corruption taxonomy.
No existing code changes meaning; `3` fills the reserved hole.

### 3.3 Which commands honor `--max-lag`

`--max-lag` is the threshold flag that drives the lag half of exit `3`. It is honored ONLY
by `consumer lag` (the green offline-capable leaf that reports a consumer group's lag). Per
the #136 open decision, `--max-lag` accepts the RECORDS threshold as its primary form:
`--max-lag <records>` exits `3` when the group's lag-records (the sort key) exceeds the
threshold. The records form is frozen; a future bytes/age tuple
(`--max-lag records=...,bytes=...,age=...`) is an ADDITIVE extension (a new optional form,
no exit-code change), so the design does not foreclose it but commits only the records
form now. `consumer lag` reports records, bytes, and age in every mode (lag-age from the
stored record timestamp, never a cross-clock comparison, per [`CLI.md`](CLI.md) and #16);
`--max-lag` gates the exit code on the records figure.

A command WITHOUT `--max-lag` never returns `3` for a lag reason; only the corruption-skip
condition (3.1 item 1) can return `3` for the inspection verbs. No other command honors
`--max-lag`.

## 4. What this doc does NOT do (verb-impl residuals under #15)

This document completes the COMMAND-MAP and the `--json`/flags/exit-code DESIGN. It does
NOT implement any verb. The implementations that EMIT these schemas, honor these flags, and
return these codes are tracked under the children of
[#15](https://github.com/ELares/IronBus/issues/15):

- `scrub`/`repair` (the read-only corruption survey and the quarantine/truncate plan):
  [#92](https://github.com/ELares/IronBus/issues/92).
- `top` (the live/offline TUI, read-only, degrades to text):
  [#93](https://github.com/ELares/IronBus/issues/93).
- `admin consumer-reset` / `admin dlq-redrive` (the OFFLINE, broker-stopped subset of the mutating
  admin surface): [#299](https://github.com/ELares/IronBus/issues/299). The MUTATING WIRE forms and
  `force-reap` (a live-broker operation) stay deferred to the authed admin surface
  [#380](https://github.com/ELares/IronBus/issues/380) / [#106](https://github.com/ELares/IronBus/issues/106),
  since a mutating action over the wire needs connection-scoped auth.
- `consumer` group (`ls`/`info`/`lag`/`reset`/`purge`/`pause`/`resume`), `segments`
  (`ls`/`verify`), `dlq` (`ls`/`redrive`/`purge`), `retention` (`info`/`reap`), `info`,
  `tap`, `wire`, `bench`, `config` (`check`/`print`/`schema`/`get`/`set`/`reload`),
  `recovery report`, `completions`: their own children of #15, each landing its verb plus
  the golden test that pins its `ironbus.cli.<command>.vN` schema.

When a verb lands, its PR registers its schema row in [`compat/versions.md`](compat/versions.md)
(1.5), golden-pins the JSON shape, and wires the flag/exit-code behavior this doc freezes.
Until then, the shipped surface is exactly the six verbs and six exit codes in
[`CLI.md`](CLI.md), and this contract is SPECIFIED, not implemented.

## Cross-references

- [`CLI.md`](CLI.md): the shipped surface, the six exit codes, the offline output shapes
  this contract promotes to v1 schemas.
- [`diagrams/07-cli-command-tree.dot`](diagrams/07-cli-command-tree.dot): the frozen
  verb/noun tree with the online/offline/offline-only tagging this doc's global-flag rules
  build on.
- [`compat/versions.md`](compat/versions.md) (#126): the version registry and the
  append-only-vs-breaking bump rule the `--json` schemas follow.
- [`schemas/loss-report.v1.md`](schemas/loss-report.v1.md) (#120): the recovery loss
  schema whose data-loss-vs-reported-skip boundary the exit-`3` gate reuses, and whose
  event fields the CLI loss object mirrors.
- [`METRICS.md`](METRICS.md) (#16): the encoding contract (units, no raw bytes) the
  `--json` output shares.
- [`DICTIONARY_LIFECYCLE.md`](DICTIONARY_LIFECYCLE.md) (#78): the missing-dictionary
  `decoded:false` degraded-record path `dump` honors.
- [`USAGE.md`](USAGE.md): the prose CLI walkthrough.
