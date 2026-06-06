<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus usage guide

This guide covers running the `ironbus` binary as it exists today: a single durable
queue, a producer and consumer over a small length-framed TCP protocol, and loopback
health and metrics endpoints. It documents the implemented subset; the design backlog
lives in the GitHub issues, and the README holds the broader vision.

## Build

IronBus is a Rust workspace. Build the `ironbus` binary from source:

```sh
cargo build --release -p ironbus-cli
# the binary lands at target/release/ironbus
```

CI also cross-compiles a static musl binary for `x86_64`, `aarch64`, and `armv7` on
every change (see the `musl build` jobs), so an edge deployment can ship one static
file with no runtime dependencies.

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
| `--max-in-flight <n>` | `1024` | The max-ack-pending window: at most this many messages may be leased above the committed cursor at once. Must be at least 1. |
| `--max-segment-bytes <n>` | `67108864` | The soft per-segment size cap (64 MiB). Must be at least 4096 (smaller caps proliferate segments). |
| `--visibility-timeout-ms <n>` | `30000` | How long a delivered message stays in flight before it may redeliver. Must be at least 1. The lease hard cap is the larger of 5 minutes and this. |
| `--health-addr <host:port>` | off | If set, also serve the health and metrics HTTP endpoints on this loopback port. |

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

## Restart and resume

The durable log always survives a restart, so a fresh publish after restarting on the
same `--data-dir` continues at the next offset (the message bytes were fsynced at
produce time).

The consumer cursor is a lagging checkpoint, not a per-ack fsync. It becomes durable
when a consumer's connection closes cleanly (the disconnect flushes it) or after
`--checkpoint-interval` cumulative commits (default 1024). So a clean restart resumes
past acked messages, but an abrupt stop can redeliver up to `--checkpoint-interval`
recently-acked messages. Note there is no graceful-shutdown drain yet, so signalling the
broker (SIGTERM/SIGINT) IS an abrupt stop. This is safe at-least-once (a duplicate, never
a loss), and `--checkpoint-interval` is exactly the knob that trades that redelivery
window against checkpoint write amplification; a lower value (even `1`) persists the
cursor more eagerly. The everyday `pub`/`sub` flow resumes cleanly because each
short-lived `sub` connection closes and flushes the cursor; a long-lived consumer that is
still connected when the broker is signalled gets the redelivery behavior instead.

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
```

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

## Exit codes

`pub`, `sub`, and `serve` follow a fixed scheme: `0` clean, `1` usage error, `5` broker
unreachable, `70` internal. A script can branch on these without parsing output.
