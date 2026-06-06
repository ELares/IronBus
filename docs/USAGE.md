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
process is signalled. Durability holds across an abrupt termination because every ack
is fsynced before it returns.

| Flag | Default | Meaning |
|------|---------|---------|
| `--data-dir <dir>` | required | The directory holding the segmented log and the cursor checkpoint. |
| `--addr <host:port>` | `127.0.0.1:7777` | The wire-protocol listen address. |
| `--max-connections <n>` | `256` | Connection cap; a flood cannot spawn unbounded threads. Must be at least 1. |
| `--checkpoint-interval <n>` | `1024` | At most this many messages may be redelivered after an abrupt crash; the cursor is also flushed on a clean disconnect. A lower value persists the consumer cursor more eagerly at the cost of more checkpoint writes. |
| `--health-addr <host:port>` | off | If set, also serve the health and metrics HTTP endpoints on this loopback port. |

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
| (none) | Peek: print only. The messages stay in flight and redeliver after the visibility timeout. |
| `--ack` | Commit each message; it never redelivers. |
| `--nack [--delay-ms <n>]` | Requeue each message for redelivery. With `--delay-ms`, defer by that many milliseconds; without it, the broker applies its escalating backoff schedule (100 ms, 500 ms, 2 s, 10 s, 30 s by attempt). |
| `--term` | Drop each message without dead-lettering (an intentional discard). |

Acknowledgement is at-least-once: a message is redelivered until it is acked or termed,
and a stale token (the message already redelivered) is fenced, so a late ack cannot
commit an already-reprocessed message. A message that fails past the delivery cap
(`MaxDeliver`, default 5) is parked and surfaced on the metrics endpoint rather than
looping forever.

## Restart and resume

The broker persists the consumer cursor, so restarting on the same `--data-dir` resumes
past the messages that were already acked rather than redelivering the whole log. The
durable log itself always survives, so a fresh publish after a restart continues at the
next offset.

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
