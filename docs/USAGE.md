<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus usage guide

This guide covers running the `ironbus` binary as it exists today: a single durable
queue, a producer and consumer over a small length-framed TCP protocol, and loopback
health and metrics endpoints. It documents the implemented subset; the design backlog
lives in the GitHub issues, and the README holds the broader vision.

## Install (a released binary)

The quickest path on an edge device is the fail-closed installer, which downloads the static musl
binary that matches the host's architecture from a GitHub Release and verifies its SHA256 against
the release `SHA256SUMS` BEFORE installing it. It refuses to install on any download error, a
missing or mismatched checksum, or an unsupported platform, and it never `eval`s downloaded
content. It has no skip-verification override.

```sh
# Latest release, auto-detected arch:
curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh | sh

# Pin a version, pick an install dir, and also verify the Sigstore provenance:
curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh \
  | sh -s -- --version v0.1.0 --bin-dir "$HOME/.local/bin" --verify-provenance
```

See [RELEASING.md](../RELEASING.md) for the full installer flags, the release assets
(`ironbus-<triple>`, `SHA256SUMS`, the SBOM, and the build-provenance attestation), and the manual
`sha256sum -c` / `gh attestation verify` verification commands.

## Build (from source)

IronBus is a Rust workspace. Build the `ironbus` binary from source:

```sh
cargo build --release -p ironbus-cli
# the binary lands at target/release/ironbus
```

CI also cross-compiles a static musl binary for `x86_64`, `aarch64`, and `armv7` on
every change (see the `musl build` jobs), so an edge deployment can ship one static
file with no runtime dependencies.

The untrusted-byte parsers (the record-frame decoder, the wire-frame decoder, the cursor
snapshot decoder, and the segment scanner) are continuously fuzzed by a cargo-fuzz harness
under `fuzz/`; a nightly CI job soaks every target under AddressSanitizer. See
[`fuzz/README.md`](../fuzz/README.md) to run a soak locally.

> The broker (`ironbus serve`) is Unix only in v1: its on-disk storage uses positioned
> IO that the Windows path does not yet implement. `pub` and `sub` are cross platform.

## Run a broker

```sh
ironbus serve --data-dir /var/lib/ironbus
```

`serve` opens (creating if absent) the durable log under `--data-dir`, binds the wire
protocol on `--addr` (default `127.0.0.1:7777`, loopback only), and runs until the
process is signalled. A produce is synchronously durable: the offset is returned only
after the record is fsynced, so an abrupt termination never loses an acknowledged
publish. The consumer cursor is a separate, lagging checkpoint (see "Restart and
resume" below), so it is NOT fsynced on every ack.

| Flag | Default | Meaning |
|------|---------|---------|
| `--data-dir <dir>` | required | The directory holding the segmented log and the cursor checkpoint. |
| `--addr <host:port>` | `127.0.0.1:7777` | The wire-protocol listen address. |
| `--max-connections <n>` | `256` | Connection cap; a flood cannot spawn unbounded threads. Must be at least 1. |
| `--checkpoint-interval <n>` | `1024` | At most this many messages may be redelivered after an abrupt crash; the cursor is also flushed on a clean disconnect. A lower value persists the consumer cursor more eagerly at the cost of more checkpoint writes. |
| `--max-deliver <n>` | `5` | Delivery attempts a message gets before it is dead-lettered (parked). Must be at least 1. |
| `--allow-unlimited-deliver` | off | Value-less opt-in that permits `--max-deliver 0` (unlimited delivery, never dead-lettered), with a startup WARN. Without it, an unlimited `--max-deliver` is rejected as a usage error. |
| `--backoff-ms <a,b,c>` | `100,500,2000,10000,30000` | A comma-separated per-attempt nack/redelivery backoff schedule in milliseconds, indexed by attempt and clamped to the last entry, applied when a nack carries no explicit `--delay-ms`. A single `0` disables backoff. |
| `--max-in-flight <n>` | `1024` | The per-group max-ack-pending window: at most this many messages may be leased above the committed cursor at once. Must be at least 1. |
| `--consumer-credit <n>` | `64` | The per-connection un-acked message credit: the most messages one connection may hold un-acked at once. The effective per-fetch credit is the smaller of this and the per-group `--max-in-flight` window. Must be at least 1. |
| `--consumer-credit-bytes <n>` | `8388608` (8 MiB) | The per-connection un-acked byte budget (key plus headers plus payload), the RAM-side companion to `--consumer-credit`; `0` means unlimited. A single message larger than the whole budget is still delivered when nothing is in flight, so it never wedges. |
| `--max-segment-bytes <n>` | `67108864` | The soft per-segment size cap (64 MiB). Must be at least 4096 (smaller caps proliferate segments). |
| `--max-total-bytes <bytes>` | `0` (unlimited) | The hard durable-log byte cap. At or over it, a produce is rejected (drop-new shed) with an `at capacity` error. See "Bounding disk use" below. |
| `--max-retained-bytes <bytes>` | `0` (off) | Size-based retention: reclaim whole old SEALED segments, once every group has committed past them, while the durable log exceeds this many record bytes. See "Bounding disk use" below. |
| `--max-age-ms <ms>` | `0` (off) | Time-based retention: reclaim a fully-consumed sealed segment once its newest record is older than this many milliseconds. See "Bounding disk use" below. |
| `--max-messages <n>` | `0` (off) | Count-based retention: reclaim oldest fully-consumed sealed segments once the total durable record count exceeds this bound. See "Bounding disk use" below. |
| `--max-groups <n>` | `1024` | Cap on the number of live work-groups; a new named group past the cap is rejected (the default group is exempt and never counted). `0` means unlimited. |
| `--disk-full-policy <drop-new\|drop-oldest>` | `drop-new` | What an over-cap produce does once `--max-total-bytes` is hit: `drop-new` sheds it (preserving older data); `drop-oldest` force-reaps the oldest sealed segment to make room, then accepts it. |
| `--key-shared-group <name>` | none | Repeatable: declares a named competing group that runs in `key_shared` ordering, so a record's key routes to one live member and same-key records keep their order while the group drains in parallel across keys. Pass once per group. |
| `--broadcast-group <name>` | none | Repeatable: marks a NAMED group BROADCAST (a group-of-one that sees every record in order), so it accepts the `cumulative-ack` verb. The group must be named: the default/empty group cannot be broadcast (`--broadcast-group ""` is a startup usage error). Mutually exclusive with `key_shared`. Pass once per group. |
| `--visibility-timeout-ms <n>` | `30000` | How long a delivered message stays in flight before it may redeliver. Must be at least 1. The lease hard cap is the larger of 5 minutes and this. |
| `--dedup-max-ids <n>` | `100000` | The count bound on each per-producer effectively-once dedup window: the most `(msg_id, offset)` entries one producer keeps before the oldest is evicted. Dedup is OFF until a producer opts in by sending a `msg_id`; this only sizes the window when it does. Floored to 1. See "Effectively-once dedup" below. |
| `--dedup-window-ms <ms>` | `120000` (2 min) | The time bound on each per-producer dedup window, in milliseconds of monotonic time: an entry older than this is evicted regardless of the count bound. `0` disables the time bound (only the count bound applies). |
| `--dedup-max-producers <n>` | `4096` | The cap on the NUMBER of distinct per-producer dedup windows. The `producer_id` is wire-supplied, so this bounds the TOTAL dedup memory: a fresh `producer_id` over the cap evicts the least-recently-active window (an approximate LRU), so a flood of distinct ids cannot grow RAM without bound. Floored to 1. |
| `--health-addr <host:port>` | off | If set, also serve the health and metrics HTTP endpoints on this loopback port. |

For the exhaustive flag map (value types, every default cited to its `main.rs` constant, and
the validation rules), see the complete CLI reference in [`CLI.md`](CLI.md).

### Durability across platforms

A produce is acknowledged only after its record clears a true write-barrier to the
storage device, so an acknowledged offset means the bytes will survive a power cut. How
that barrier is issued depends on the platform, and IronBus relies on the standard
library to issue the right one:

| Platform | Durable-sync barrier |
|----------|----------------------|
| Linux (the production target: static musl on ext4 or f2fs) | `fdatasync(2)` / `fsync(2)`, true device write-barriers. |
| macOS and iOS (developer and CI targets) | `fcntl(fd, F_FULLFSYNC)`, which flushes the drive's volatile write cache to permanent storage. A plain `fsync(2)` on Darwin does NOT issue that flush, so the standard library uses `F_FULLFSYNC` for both `sync_data` and `sync_all`, and IronBus relies on exactly that. |
| Windows | Not a v1 broker target; `pub` and `sub` run, but `serve` does not. |

IronBus does not silently downgrade the barrier. If a filesystem cannot honour
`F_FULLFSYNC`, the sync surfaces an error, the log writer freezes (`/readyz` reports
`503`), and the broker stops acknowledging rather than letting an ack outrun a real
flush. Production durability targets Linux musl; macOS is supported for development and
CI, where the `F_FULLFSYNC` barrier still applies.

### Bounding disk use

By default the durable log spills to disk without bound: it grows as fast as producers
publish, and nothing is reclaimed. Four `serve` flags bound that growth. They are off by
default (each defaults to `0`), so an existing `serve` is unchanged until an operator opts
in. The model is spill, then shed, with retention draining behind it:

- The log spills to disk by default (no cap).
- `--max-total-bytes <bytes>` is the hard byte cap (the drop-new shed). When the durable
  log is at or over it, a produce is rejected before any write: nothing is appended, no
  offset advances, and the producer is told promptly with an `at capacity` error rather
  than a silent drop or a hang. The writer stays live, so a later produce succeeds once
  retention frees space. `0` (the default) means unlimited.
- Retention reclaims space as consumers drain. The three retention bounds are
  `--max-retained-bytes <bytes>` (reclaim while the log exceeds this many durable record
  bytes), `--max-age-ms <ms>` (reclaim a segment whose newest record is older than this
  many milliseconds), and `--max-messages <n>` (reclaim while the total durable record
  count exceeds this bound). Each is `0` = off by default; they compose, so a segment is
  reclaimed if ANY enabled bound trips.

Retention is consumer-safe: it never deletes a record a group still needs. The reclaim
unit is a whole sealed segment, never a partial one and never the active segment. A
segment is reclaimed oldest first, and only once every consumer group has committed past
it, so the slowest group's records are never reaped. There is no disk-full drop-oldest
policy: when the cap is full, IronBus sheds the new produce, it does not delete old
acknowledged records.

The two relevant metrics on `/metrics` are `ironbus_produce_rejected_total` (produces shed
by the byte cap) and `ironbus_segments_reaped_total` (segments reclaimed by retention).

## Produce

```sh
ironbus pub --addr 127.0.0.1:7777 --key orders "hello"
# prints the assigned durable offset, e.g. 0
echo "from stdin" | ironbus pub
```

`pub` connects, appends one message, and prints its assigned durable offset. The
payload comes from the argument, or from stdin if the argument is omitted (an empty
input publishes an empty message, which is a valid record). The offset is returned only
after the record is fsynced, so a printed offset means the message is durable.

### Effectively-once dedup (opt-in, #33)

A producer can request effectively-once delivery by attaching a `msg_id` to a publish
(via the client library's `produce_dedup`; the `pub` CLI sends no `msg_id`, so it never
dedups, and behavior is unchanged). When a `msg_id` is present the broker keeps a bounded
per-producer window of `(msg_id -> offset)` and:

- A `msg_id` it has NOT seen within the window is a fresh produce: it is appended and
  acked with the assigned offset (`duplicate = false`).
- A `msg_id` it HAS seen within the window is a BENIGN dedup hit: the broker returns the
  ORIGINAL offset with `duplicate = true` and `rc = 0` (NEVER an error) and appends no
  second copy, so an idempotent retry over a lossy link does not loop or double-store.

The window is bounded by BOTH a count (`--dedup-max-ids`, default 100k) AND a time bound
(`--dedup-window-ms`, default 2 min, on the MONOTONIC clock, so an NTP step never
mis-expires it), whichever is hit first. A republish OUTSIDE the window creates a new
offset and is delivered again, so consumers must stay idempotent regardless. Dedup keys on
`msg_id` ONLY, never the body. A producer may also carry a stable `producer_id` and a
monotonic `epoch`: a HIGHER epoch fences an older zombie session reusing the same
`producer_id`. Dedup is SESSION-scoped (in-memory) and lost on broker restart by default.
The `ironbus_dedup_hits_total` and `ironbus_dedup_out_of_window_total` metrics expose the
hit and out-of-window rates.

The TOTAL dedup memory is hard-bounded: the number of distinct producer windows is capped at
`--dedup-max-producers` (default 4096) with least-recently-active LRU eviction (a flood of
distinct, attacker-chosen `producer_id`s cannot grow RAM without bound), and the `producer_id`
and `msg_id` are each capped at 256 bytes (an oversized id is rejected with a typed error, the
connection stays open). The worst-case bound is `max_producers * max_ids * per_entry`; see
[RAM_BUDGET.md](RAM_BUDGET.md) for the arithmetic and the edge-safe knob values.

## Consume

```sh
ironbus sub --addr 127.0.0.1:7777 --max 10 --ack
```

`sub` fetches up to `--max` messages (default 10) and prints one line per message:

```
#0 gen=0 key=orders payload=hello
  ack committed
fetched 1 message(s)
```

The `gen` is the lease fencing token; it must be carried back on the acknowledgement.
Pass `--group <name>` to consume as a named work-group instead of the default cursor
(see "Consumer groups" below).
At most one disposition applies to the whole fetched batch:

| Disposition | Effect |
|-------------|--------|
| (none) | Peek: print only, do not commit. The messages stay leased and redeliver after the visibility timeout (30 seconds; not flag-configurable). A peek still claims a lease, so it counts as a delivery attempt: repeatedly peeking without acking eventually parks the message at `MaxDeliver`. |
| `--ack` | Commit each message; it never redelivers. |
| `--nack [--delay-ms <n>]` | Requeue each message for redelivery. With `--delay-ms`, defer by that many milliseconds; without it, the broker applies its escalating backoff schedule (100 ms, 500 ms, 2 s, 10 s, 30 s by attempt). |
| `--term` | Drop each message without dead-lettering (an intentional discard). |

The wire protocol also supports `progress` (extend a lease while a consumer is still
working) and a keepalive `ping`, but those are library-only and not yet surfaced as
`sub` flags.

Acknowledgement is at-least-once: a message is redelivered until it is acked or termed,
and a stale token (the message already redelivered) is fenced, so a late ack cannot
commit an already-reprocessed message. A message that fails past the delivery cap
(`MaxDeliver`, default 5) is parked and surfaced on the metrics endpoint rather than
looping forever.

When the broker parks an offset as poison during a fetch, `sub` prints an in-band
advisory line so the consumer is not left silently never seeing it:

```
dead-letter offset=7 reason=max-deliver
```

The advisory is emitted alongside the deliveries in the same batch (the credit caps the
total of deliveries plus advisories), so a consumer that polls a queue learns exactly
which offsets were dropped past `MaxDeliver`.

## Restart and resume

The durable log always survives a restart, so a fresh publish after restarting on the
same `--data-dir` continues at the next offset (the message bytes were fsynced at
produce time).

The consumer cursor is a lagging checkpoint, not a per-ack fsync. It becomes durable
when a consumer's connection closes cleanly (the disconnect flushes it) or after
`--checkpoint-interval` cumulative commits (default 1024). So a clean restart resumes
past acked messages, but an ABRUPT crash (a power cut or a kill) can redeliver up to
`--checkpoint-interval` recently-acked messages. This is safe at-least-once (a duplicate,
never a loss), and `--checkpoint-interval` is exactly the knob that trades that redelivery
window against checkpoint write amplification; a lower value (even `1`) persists the
cursor more eagerly.

Signalling the broker is NOT an abrupt stop: `serve` installs a SIGINT/SIGTERM/SIGHUP
handler that does a graceful shutdown. It stops accepting connections, flushes every
work-group's committed cursor, and exits 0, so a restart after a clean operator stop does
not redeliver already-acked messages even from a long-lived consumer that was still
connected. The graceful stop flushes the cursor only: there is no in-flight drain, so any
message that was leased but not yet acked when the signal arrived still redelivers after
the restart, which is the correct at-least-once behavior. The everyday `pub`/`sub` flow
also resumes cleanly because each short-lived `sub` connection closes and flushes its
cursor on disconnect.

## Consumer groups

The single durable log fans out to many named work-groups. Pass `--group <name>` to
`sub` to consume as that group; an empty (omitted) name keeps the default group, so
existing callers are unchanged.

```sh
# A broadcast consumer: its own group, so it sees every message.
ironbus sub --addr 127.0.0.1:7777 --group analytics --max 10 --ack

# A competing group: several members share one group name, so each message goes to
# exactly one member. Run more than one of these to split the work.
ironbus sub --addr 127.0.0.1:7777 --group workers --max 10 --ack
```

Each group has its own committed cursor and its own in-flight lease set over the shared
log, and every group advances independently: a broadcast group (used by one consumer)
sees every message, while a competing group (shared by several members) hands each
message to exactly one member. Group names are 1 to 128 graphic-ASCII bytes; the broker
enforces the shape and a per-broker group cap on the first fetch and surfaces a bad name
as an error.

Per-group cursors are durable: each named group checkpoints to its own
`cursor-<hex(name)>.ckpt` file under `--data-dir` (the default group keeps `cursor.ckpt`),
so a group resumes past its acked messages after a restart instead of redelivering the
whole log from offset 0. The same `--checkpoint-interval` and clean-disconnect flush rules
from "Restart and resume" apply per group.

### Cumulative ack for a broadcast group

A group declared BROADCAST (a group-of-one that sees every record in order) can commit its
cursor up to an offset in ONE move with the `cumulative-ack` verb (ack-all-up-to-offset),
instead of acking each message. Mark the group broadcast at `serve` time, then commit:

```sh
ironbus serve --data-dir /var/lib/ironbus --broadcast-group analytics &
# ... produce and consume on the analytics group ...
# Commit the analytics cursor up to (exclusive) offset 100 in one call:
ironbus cumulative-ack --group analytics --up-to 100
```

`--up-to` is EXCLUSIVE (every offset strictly below it is acked). The broker validates it
against the durable head and the earliest-retained offset and rejects an out-of-range value;
a re-ack at or below the current commit is an idempotent no-op success. This verb is offered
ONLY for a broadcast group: a competing or `key_shared` group is hard-rejected (committing a
shared cursor past peers' still-in-flight messages would silently drop them).

A broadcast group is enforced as a true group-of-one: it accepts AT MOST ONE active
subscriber at a time, so a cumulative ack only ever commits past that single consumer's own
in-flight leases. A second concurrent SUB to a broadcast group is rejected, and marking a
group broadcast is refused if it already carries competing in-flight state. The slot frees on
UNSUB or disconnect, so a replacement consumer can take over.

`--broadcast-group` marks a NAMED group only: the default/empty group cannot be a broadcast
group (`--broadcast-group ""` is a startup usage error). The group-of-one subscriber cap binds
a named group's subscribers, but the default group's consumers reach it on the implicit default
subscription and never SUB a name, so the cap could never bind them; an uncapped broadcast group
would reopen the silent-drop path, so it is refused outright.

## Offline inspection

`peek` and `dump` decode a stopped broker's data directory with no server running, so you
can inspect what is durably stored without starting (or interfering with) the broker. They
read only up to the durable high-water mark and never mutate the directory.

```sh
# A bounded window of records (default 10), optionally from an offset.
ironbus peek --data-dir /var/lib/ironbus --from-offset 0 --limit 10

# Every record, one per line (NDJSON with --json).
ironbus dump --data-dir /var/lib/ironbus --json
```

Each record line carries the offset, the timestamp, the payload byte length, the key byte
length, the CRC status (always `ok`, since the reader only yields records that passed their
checksum), and the codec (always `none` until on-disk compression lands):

```
offset=0 ts_ms=100 bytes=5 key_bytes=6 crc=ok codec=none
```

| Verb | Flags | Shows |
|------|-------|-------|
| `peek` | `--data-dir <dir>` (required), `--from-offset <n>`, `--limit <n>`, `--json` | A bounded window of records (default 10), from `--from-offset`. |
| `dump` | `--data-dir <dir>` (required), `--limit <n>`, `--json` | Every record, one per line (NDJSON with `--json`). |

Both mark, never hide, a torn or corrupt tail: a trailing note (a `{"loss":...}` object in
`--json` mode) reports the dropped byte span and the reason, so the holes are shown rather
than silently skipped. A clean directory prints no note. Both bound memory to one segment
at a time. The offline verbs are Unix only in v1, like `serve`.

## Health and metrics

Start the broker with `--health-addr` to expose three loopback HTTP endpoints:

```sh
ironbus serve --data-dir /var/lib/ironbus --health-addr 127.0.0.1:9090
```

| Endpoint | Meaning |
|----------|---------|
| `GET /healthz` | Liveness: `200 ok` whenever the process is up. |
| `GET /readyz` | Readiness: `200 ready`, or `503` if the durable log writer has frozen. |
| `GET /metrics` | Prometheus text exposition format. |

`/metrics` exposes the headline gauges and counters:

```
ironbus_committed_offset      the committed consumer cursor
ironbus_flushed_offset        the durable log head
ironbus_consumer_lag          flushed minus committed (the headline lag signal)
ironbus_in_flight             leased but not yet acked
ironbus_writer_healthy        1 live, 0 frozen
ironbus_recovery_truncated_bytes  bytes dropped from a torn tail at the last recovery
ironbus_last_dead_lettered_offset offset of the most recent dead-letter (-1 if none)
ironbus_fsync_seconds          histogram of the produce fsync (durability barrier) latency
ironbus_produced_total        messages appended
ironbus_delivered_total       deliveries handed out (a redelivery counts again)
ironbus_redelivered_total     deliveries that were a redelivery
ironbus_dead_lettered_total   messages parked past MaxDeliver (the drop signal)
ironbus_acks_total            commits via ack (a term commits through the same path)
ironbus_produce_rejected_total produces shed by the durable-log byte cap (see "Bounding disk use")
ironbus_segments_reaped_total segments reclaimed by consumer-safe retention
ironbus_segments_force_reaped_total segments force-reaped by the disk-full drop-oldest policy
ironbus_truncations_total      below-earliest truncations served to a consumer (the skip signal)
ironbus_truncated_records_total records skipped by those truncations
ironbus_dedup_hits_total       benign opt-in dedup hits (a msg_id retry returned the original offset, no second copy)
ironbus_dedup_out_of_window_total dedup ids that aged out of the window (size the window if non-zero)
```

Every resilience event the broker sheds, drops, skips, dead-letters, truncates,
force-reaps, or loses on recovery increments a stable-named counter, so no
resilience event is ever silent. The full per-counter catalog, the
shed-vs-drop-vs-skip-vs-dead-letter taxonomy, and the frozen-taxonomy contract
are in [METRICS.md](METRICS.md).

## A complete example

```sh
# Terminal 1: run a broker with health endpoints.
ironbus serve --data-dir /tmp/ironbus-demo --addr 127.0.0.1:7777 --health-addr 127.0.0.1:9090

# Terminal 2: produce, consume, and observe.
ironbus pub --addr 127.0.0.1:7777 "first"     # prints 0
ironbus pub --addr 127.0.0.1:7777 "second"    # prints 1
ironbus sub --addr 127.0.0.1:7777 --max 10 --ack
curl -s http://127.0.0.1:9090/metrics | grep ironbus_consumer_lag
```

## Semantics contract and conformance vectors

IronBus pins its observable queue behavior as a STABLE contract so a client can rely on it and a
second implementation can be checked against it. Two pieces make it concrete.

STABLE error/signal codes. Every observable rejection or signal has a frozen, normative code (e.g.
`ERR_CUMULATIVE_ACK_NOT_ALLOWED` for a cumulative ack on a competing group, `ERR_ACK_NOT_OWNED` for
an ack on a lease you do not own, `OFFSET_TRIMMED` for a read below the retention horizon,
`ERR_PRODUCER_FENCED` for a stale producer epoch, `DUPLICATE` for a benign dedup hit). The full
table is in [CONTRACTS.md](CONTRACTS.md). The codes never change spelling, so you can branch on them.

The conformance vector suite (`crates/ironbus-server/tests/vectors/semantics.json`). This is a
language-agnostic, checked-in data file of input-sequence to observable-output cases covering
ordering, at-least-once redelivery, dedup hit and eviction, ack rejection with the named codes, key
routing, broadcast cursors, and trim. It is the executable spec: a Rust harness runs every vector
against the real engine and asserts the outputs match exactly, driven by an injected logical clock
(no real sleeps), so the suite is deterministic. The same vectors can drive an external client
harness over the wire to certify another implementation. See [CONTRACTS.md](CONTRACTS.md) for the
vector schema and the harness contract.

## Exit codes

Every verb follows one fixed scheme, so a script can branch on the code without parsing
output:

| Code | Meaning |
|------|---------|
| `0` | Clean. |
| `1` | Usage error (bad or missing arguments). |
| `2` | Not found: an offline verb's `--data-dir` does not exist (`peek` / `dump`). |
| `4` | Corrupt: an offline verb found the data directory structurally corrupt, distinct from a clean torn tail it can read past (`peek` / `dump`). |
| `5` | Broker unreachable. |
| `70` | Internal error (including an unsupported platform). |
