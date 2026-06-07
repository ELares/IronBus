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
> design in issue #136 specifies a larger verb tree (`tap`, `wire`, `bench`, `info`,
> `consumer`, `segments`, `scrub`, `repair`, `dlq`, `retention`, `top`, `config`,
> `recovery report`, `completions`) and a versioned `--json` schema contract;
> those are NOT implemented in the current binary and are deliberately absent here. This
> reference enumerates only what `main.rs` actually parses and runs.

## Command summary

| Subcommand | Mode | Platform | What it does |
|------------|------|----------|--------------|
| `serve` | online (runs the broker) | Unix only in v1 | Open the on-disk log under `--data-dir` and serve the wire protocol on `--addr`. |
| `pub` | online (connects) | any | Append one message and print its durable offset. |
| `sub` | online (connects) | any | Fetch up to a credit of messages, print each, optionally dispose of the batch. |
| `peek` | offline (reads `--data-dir`) | Unix only in v1 | Show a bounded window of durable records from a stopped broker's data directory. |
| `dump` | offline (reads `--data-dir`) | Unix only in v1 | Stream every durable record (or, with `--dlq`, the dead-letter sink). |
| `help` / `--help` / `-h` | neither | any | Print the usage banner. |
| `version` / `--version` / `-V` | neither | any | Print a single `ironbus <version>` line. |

A subcommand is required; an unknown subcommand or a missing one is a usage error
(exit 1). `serve`, `peek`, and `dump` are Unix only in v1 because the on-disk storage
uses positioned IO the Windows path does not yet implement; on a non-Unix host they fail
with exit 70. `pub` and `sub` are thin wrappers over `ironbus-client` and run anywhere.

## Online versus offline

- **Online** verbs (`serve`, `pub`, `sub`) speak the length-framed TCP wire protocol on
  `--addr` (default `127.0.0.1:7777`, loopback only). `pub` and `sub` connect to a
  running broker; `serve` IS the broker. If the broker cannot be reached, an online verb
  exits 5 (unreachable).
- **Offline** verbs (`peek`, `dump`) decode the on-disk data directory directly with NO
  server running, via the storage crate's `OfflineReader`. They read only up to the
  durable high-water mark and stop at the first torn or bad-CRC record (the same boundary
  recovery uses), marking, never hiding, any tail they skipped. They never mutate the
  directory. There is no online fallback for `peek`/`dump`: they are pure offline readers.

## `serve` (online; Unix only in v1)

Starts the broker: opens (creating if absent) the durable log under `--data-dir`, binds
the wire protocol on `--addr`, optionally binds the health endpoints on `--health-addr`,
and runs until signalled. SIGINT, SIGTERM, or SIGHUP triggers a graceful stop: the serve
loop stops accepting, flushes every work-group's committed cursor, and exits 0.

`--data-dir` is REQUIRED; omitting it is a usage error. `serve` takes no positional
arguments. All numeric flags reject a non-numeric value as a usage error before the
broker opens.

| Flag | Value type | Default | Unit | Meaning |
|------|-----------|---------|------|---------|
| `--data-dir <dir>` | path | required (no default) | path | The directory holding the segmented log, the cursor checkpoints, and the `dlq/` sink. |
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
| `--disk-full-policy <drop-new\|drop-oldest>` | enum | `drop-new` (`DEFAULT_DISK_FULL_POLICY`) | n/a | What an over-cap produce does once `--max-total-bytes` is hit. `drop-new` sheds it (preserving older data); `drop-oldest` force-reaps the oldest sealed segment to make room then accepts it. Any other value is a usage error. |
| `--key-shared-group <name>` | string, REPEATABLE | none (empty) | n/a | Run the named competing group in `key_shared` ordering: a record's key routes to one live member, so same-key records keep order while the group drains in parallel across keys. Pass once per group; a group not named stays plain competing. |
| `--visibility-timeout-ms <n>` | u64 | `30000` (`DEFAULT_VISIBILITY_MS`) | milliseconds | How long a delivered message stays in flight before it may redeliver. Must be at least 1. The lease hard cap is the larger of 5 minutes (`DEFAULT_HARD_CAP_MS = 300000`) and this. |
| `--health-addr <host:port>` | string | off (not set) | host:port | If set, also serve `GET /healthz`, `/readyz`, and `/metrics` on this loopback HTTP port. |

### `serve` validation (each a usage error, exit 1)

- `--max-connections` must be at least 1.
- `--max-deliver` must be at least 1 and below 4294967295 (both `0` and the u32 max mean
  unlimited; pass `--allow-unlimited-deliver` to enable it deliberately).
- `--max-in-flight` must be at least 1.
- `--consumer-credit` must be at least 1.
- `--max-segment-bytes` must be at least 4096.
- `--visibility-timeout-ms` must be at least 1.
- `--disk-full-policy` must be `drop-new` or `drop-oldest`.

### Environment-variable mapping and precedence (#89)

Every `serve` setting can also be supplied via an environment variable, so the same key
surface works as a foreground binary, a systemd unit, or a container with no config file.
The variable name is `IRONBUS_<FLAG>`: the flag name minus its leading `--`, uppercased,
with each `-` replaced by `_`. The **precedence is flag > env > default**: an explicit
command-line flag overrides the env var, which overrides the compiled default.

| Flag | Environment variable |
|------|----------------------|
| `--addr` | `IRONBUS_ADDR` |
| `--data-dir` | `IRONBUS_DATA_DIR` |
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
| `--disk-full-policy` | `IRONBUS_DISK_FULL_POLICY` |
| `--visibility-timeout-ms` | `IRONBUS_VISIBILITY_TIMEOUT_MS` |
| `--health-addr` | `IRONBUS_HEALTH_ADDR` |
| `--enable-admin` | `IRONBUS_ENABLE_ADMIN` (`true`/`1` or `false`/`0`) |

A bad env value (e.g. non-numeric where a number is expected, or an unknown
`IRONBUS_DISK_FULL_POLICY`) is a usage error (exit 1) that **names the env var**, exactly
as a bad flag value names the flag. The repeatable `--key-shared-group` is command-line
only (no single-var mapping, since a list with a per-group meaning does not flatten to one
scalar). The broader TOML config file, profiles, and hot reload are SEPARATE follow-ups
(#85/#87/#88) and not yet implemented.

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

If `--health-addr` is set, it also prints:

```
ironbus health endpoints on <addr> (/healthz, /readyz, /metrics)
```

If unlimited delivery is enabled, it prints the startup warning:

```
WARN: --max-deliver is unlimited (--allow-unlimited-deliver): a poison message can redeliver forever and is never dead-lettered
```

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

Note: `dump` has NO `--from-offset`; it always starts at offset 0. Only `peek` accepts
`--from-offset`/`--offset`.

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
`codec` is always `none` until on-disk compression lands. Only sizes are printed, never
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
| `0` | `ExitCode::SUCCESS` | Clean: the command completed (a `peek`/`dump` that marked a torn tail still exits 0; the loss is reported, not an error). |
| `1` | `EXIT_USAGE` (`CliError::Usage`) | Usage or argument error: an unknown subcommand or flag, a missing required value, a bad numeric value, a missing `--data-dir`, an out-of-range `serve` knob, a second disposition or payload. The usage banner is also printed to stderr. |
| `2` | `EXIT_NOT_FOUND` (`CliError::NotFound`) | Operational not-found: an offline verb's `--data-dir` does not exist (`peek` / `dump`, including `dump --dlq`). |
| `4` | `EXIT_CORRUPT` (`CliError::Corrupt`) | Corrupt data: an offline verb found the data directory structurally corrupt (a broken segment chain, an undecodable header, a footer/segment-id mismatch), distinct from a clean torn TAIL it can read past (which is exit 0 with a loss note). |
| `5` | `EXIT_UNREACHABLE` (`CliError::Unreachable`) | Broker unreachable: an online verb could not reach the broker, or the broker dropped the connection mid-request (a connection-level IO error or a closed socket). |
| `70` | `EXIT_INTERNAL` (`CliError::Internal`) | Internal or runtime failure: an IO error, a broker that answered with a wrong-shape or error frame, or an unsupported platform (`serve`/`peek`/`dump` on non-Unix). |

Codes `3` (handled corruption) and other codes the issue #136 design reserves are NOT
emitted by the current binary; only the six above are mapped in `main.rs`.

## Notes and cross-references

- The default address is `127.0.0.1:7777`, loopback only, so a zero-config broker is
  never exposed off the host without an explicit `--addr`.
- For the durability model, restart-and-resume semantics, consumer-group behavior, the
  health/metrics endpoints, and worked examples, see [`USAGE.md`](USAGE.md). USAGE.md's
  `serve` flag table is a curated subset; THIS file is the complete flag map (USAGE.md
  omits `--allow-unlimited-deliver`, `--backoff-ms`, `--consumer-credit`, `--max-groups`,
  `--disk-full-policy`, and `--key-shared-group`).
- The on-disk and wire byte layouts referenced by the offline output shapes are specified
  in [`CONTRACTS.md`](CONTRACTS.md).
