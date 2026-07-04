<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Client SDKs — getting started

IronBus ships first-party clients that speak the wire protocol
([docs/TRANSPORT.md](TRANSPORT.md)) natively — no HTTP, no protobuf:

| Language | Crate / module | Model |
| --- | --- | --- |
| **Rust (blocking)** | [`ironbus-client`](../crates/ironbus-client/) | one TCP connection, request/response |
| **Rust (async)** | [`ironbus-client-async`](../crates/ironbus-client-async/) | the tokio twin — same surface, `.await`ed |
| **Go** | [`sdk/go`](../sdk/go/) (`github.com/ELares/IronBus/sdk/go`) | one connection, `context`-driven |

Every client shares the same connection contract: **request/response, FIFO, one
in-flight call per connection.** Scale out with more connections, not by sharing
one. A connection that errors mid-reply is terminally broken by design (retrying
would read the previous request's reply) — drop it and reconnect.

This guide walks the common tasks. Every snippet has a runnable counterpart under
[`crates/ironbus-client/examples/`](../crates/ironbus-client/examples/),
[`crates/ironbus-client-async/examples/`](../crates/ironbus-client-async/examples/),
and [`sdk/go/examples/`](../sdk/go/examples/) — see [Examples](#examples).

## Install

**Rust** (first-party workspace crates; add by git until a crates.io release):

```toml
[dependencies]
ironbus-client = { git = "https://github.com/ELares/IronBus" }
# or the async twin:
ironbus-client-async = { git = "https://github.com/ELares/IronBus" }
```

**Go**:

```sh
go get github.com/ELares/IronBus/sdk/go
```

You also need a broker. From this repo:

```sh
cargo run -p ironbus-cli --release -- serve --data-dir /tmp/ironbus-demo --addr 127.0.0.1:7777
```

## Connect

Capabilities (credit, gap markers, streaming tier, named streams, auth) are
negotiated once in the handshake; the client adopts what the server confirms.

```rust
// Rust (blocking) — defaults, or connect_with(&ClientConfig) to set capabilities.
use ironbus_client::Client;
let mut client = Client::connect("127.0.0.1:7777")?;
```

```rust
// Rust (async)
use ironbus_client_async::AsyncClient;
let mut client = AsyncClient::connect("127.0.0.1:7777").await?;
```

```go
// Go — Config always carries the address (and any capabilities/credential).
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
client, err := ironbus.Connect(ctx, ironbus.Config{Addr: "127.0.0.1:7777"})
if err != nil { /* ... */ }
defer client.Close()
```

## Produce

Every durable ack means the record is **fsync-durable** on the broker (subject to
the broker's `--durability-level`). Pick the shape by your latency/throughput need:

| Shape | Rust | Go | When |
| --- | --- | --- | --- |
| Awaited durable | `produce` | `Produce` | one record, simplest; ~one fsync per record |
| **Pipelined durable** | `pipelined_producer[_with_window]`, `produce_window` | *(not yet)* | high single-producer throughput: a window shares one group-commit fsync |
| Fire-and-forget (QoS 0) | `produce_fire_and_forget` | `ProduceFireAndForget` | max speed, loss acceptable |
| Idempotent (dedup) | `produce_dedup` | `ProduceDedup` | safe retries: a repeated `MsgID` returns the original offset |

```rust
// Rust: awaited durable produce. The offset is durable on return.
use ironbus_client::proto::PubBody;
let offset = client.produce(&PubBody {
    flags: 0, timestamp_ms: 0, key: b"sensor-12", headers: b"",
    dedup: None, fire_and_forget: false, payload: br#"{"temp":21.4}"#,
})?;
```

```rust
// Rust: high-throughput single producer. The window is buffered and flushed as
// ONE group-committed batch, so a single connection sustains far more than the
// awaited path (which has one record in flight). Tune the window for your workload.
let mut producer = client.pipelined_producer_with_window(1024);
for i in 0..10_000u32 {
    let payload = format!("event-{i}");
    producer.produce(&PubBody {
        flags: 0, timestamp_ms: 0, key: b"", headers: b"",
        dedup: None, fire_and_forget: false, payload: payload.as_bytes(),
    })?;
}
let summary = producer.finish()?; // every acked record is durable
```

```go
// Go: awaited durable produce.
offset, err := client.Produce(ctx, &ironbus.Message{Key: []byte("sensor-12"), Payload: []byte(`{"temp":21.4}`)})
```

> **Throughput note (Go):** the Go SDK currently produces one awaited record at a
> time. Windowed/pipelined produce — the mechanism behind IronBus's durable
> group-commit throughput numbers — is a tracked follow-up. Use multiple
> connections to scale Go producers today.

## Consume

Two consume models over the same log:

### Work-group (competing, at-least-once)

Subscribe to a named group; each record is **leased** to one consumer as an
`(offset, generation)` fencing token. Settle every lease exactly one way:

- **ack** — done; the group commits past it.
- **nack** — failed here, redeliver (optionally after a delay); after
  `max_deliver` attempts the record is dead-lettered (poison quarantine).
- **term** — intentional drop; commit past it without dead-lettering.

An unsettled lease redelivers after the visibility timeout, so a crashed consumer
loses nothing. `ack` returning `false` means the lease was *fenced* (it already
redelivered elsewhere) — process idempotently.

```rust
// Rust
client.subscribe("workers")?;
let batch = client.fetch(64)?;
for m in &batch.messages {
    // ... process m.payload ...
    let committed = client.ack(m.offset, m.generation)?;
    if !committed { /* fenced: someone else owns it now */ }
}
for dl in &batch.dead_letters { eprintln!("poison at offset {}", dl.offset); }
```

```go
// Go
if err := client.Subscribe(ctx, "workers"); err != nil { /* ... */ }
res, err := client.Fetch(ctx, ironbus.FetchOptions{MaxRecords: 64, Expires: 2 * time.Second})
for _, m := range res.Messages {
    committed, err := client.Ack(ctx, m.Offset, m.Generation)
    _ = committed // false == fenced
    _ = err
}
```

### Streaming (Tier-S, ordered replay — Rust)

A single ordered reader that pulls the log in **windows** by offset and commits
its cursor **cumulatively** (not per record) — the shape a throughput drain or a
replay wants. Requires negotiating the streaming tier at connect.

```rust
use ironbus_client::{Client, ClientConfig};
use ironbus_client::proto::ConsumeTier;

let cfg = ClientConfig { understands_streaming: true,
    default_consume_tier: Some(ConsumeTier::Streaming), ..ClientConfig::default() };
let mut client = Client::connect_with("127.0.0.1:7777", &cfg)?;
client.subscribe("replay")?;                 // marks the group streaming

let mut stream = client.streaming_consumer("replay");
loop {
    let batch = stream.next_batch()?;        // advances + periodically commits the cursor
    if batch.is_empty() { break; }
    for m in &batch.messages { /* ... process ... */ }
}
let committed = stream.finish()?;            // flush the final commit
```

The Go SDK's MVP is work-group consume only; Tier-S is a tracked follow-up.

## Transactions (2PC half-messages — Rust)

Solve the dual-write problem ("update my DB **and** publish, atomically").
`transact` durably buffers an invisible half message, runs your closure, then
**commits** it (visible, exactly once) on `Ok` or **rolls it back** (discarded) on
`Err`. No consumer ever sees a record whose local transaction did not commit.

```rust
use ironbus_client::TxnId;
let txn = TxnId::new(b"order-4711".to_vec());
let offset = client.transact(&txn, "", &message, || {
    charge_customer()?;   // your local transaction; Ok commits, Err rolls back
    Ok::<(), MyError>(())
})?;
```

## Subjects (NATS-style routing — Rust & Go)

Bind a subject **pattern** (`*` = one token, `>` = trailing tokens) to a named
stream, then publish/subscribe by subject. Resolution is fail-closed: an unbound
subject is rejected, not silently dropped.

```rust
client.bind_subject("orders.*.created", "orders")?; // Rust
client.publish_subject("orders.eu.created", &message)?;
```

```go
_ = client.BindSubject(ctx, "orders.*.created", "orders") // Go
_, _ = client.ProduceSubject(ctx, "orders.eu.created", &ironbus.Message{Payload: p})
```

## Authentication

An auth-enabled broker requires a credential in the handshake. Secrets are
**redacted** when the config/credential is logged.

```rust
// Rust
use ironbus_client::{AuthCredential, AuthMechanism, ClientConfig};
let cfg = ClientConfig {
    credential: Some(AuthCredential { mechanism: AuthMechanism::Bearer, material: token.into_bytes() }),
    ..ClientConfig::default()
};
let mut client = Client::connect_with("127.0.0.1:7777", &cfg)?;
```

```go
// Go
bearer, _ := ironbus.Bearer(token)                       // or ironbus.Password(user, pass)
client, err := ironbus.Connect(ctx, ironbus.Config{Addr: addr, Credential: bearer})
```

See [docs/AUTHENTICATION.md](AUTHENTICATION.md) for broker-side setup and scopes.

## Errors and clusters

Errors are typed. The one worth handling explicitly is the cluster redirect:
producing against a follower returns **not-leader** with the current leader's
address hint. The Rust client's `produce_to_leader` chases the hint for you;
otherwise match the error and reconnect.

```rust
// Rust: the one-call path (bounded redirects). On a single node it is just produce().
let offset = client.produce_to_leader(&message, &config, 3)?;

// ...or handle it yourself:
match client.produce(&message) {
    Err(ironbus_client::ClientError::NotLeader { leader_hint: Some(addr) }) => {
        client = Client::connect_with(addr.as_str(), &config)?; // retry there
    }
    other => { other?; }
}
```

```go
// Go: match the typed error and reconnect to the hint (see examples/cluster_notleader).
var nl *ironbus.NotLeaderError
if errors.As(err, &nl) && nl.LeaderHint != "" { /* reconnect to nl.LeaderHint */ }
```

Because a connection is terminally broken after a mid-reply error, the reconnect
pattern is: on `Io`/`Closed`/`NotLeader`, build a **fresh** client and resume from
your last known-durable offset (produces are at-least-once; make consumers
idempotent).

## Capability matrix

What each client supports today. The Rust blocking client is the reference
superset; the async twin and the Go MVP are subsets with tracked follow-ups.

| Capability | Rust (sync) | Rust (async) | Go |
| --- | :---: | :---: | :---: |
| Awaited durable produce | ✅ | ✅ | ✅ |
| Fire-and-forget (QoS 0) | ✅ | ✅ | ✅ |
| Idempotent produce (dedup) | ✅ | ✅ | ✅ |
| Pipelined / windowed produce | ✅ | `produce_window` | ⏳ |
| Work-group consume (ack/nack/term) | ✅ | ✅ | ✅ |
| Cumulative ack (broadcast) | ✅ | ✅ | ✅ |
| Batched ack (`ack_many`) | ✅ | ✅ | ⏳ |
| Streaming consume (Tier-S) | ✅ | ✅ | ⏳ |
| Named streams | ✅ | ✅ | ✅ |
| Subjects (bind/pub/sub) | ✅ | ⏳ | ✅ |
| Transactions (2PC) | ✅ | prepare/commit/rollback | ⏳ |
| Auth (bearer / password) | ✅ | ✅ | ✅ |
| Not-leader redirect helper | ✅ | ⏳ | typed error (manual) |
| TLS | ⏳ | ⏳ | ⏳ |

✅ supported · ⏳ tracked follow-up. TLS is not built in any client yet (see the
[roadmap](../README.md#what-is-not-shipped-the-roadmap-and-the-non-goals)).

## Examples

Each runs against a live broker (`ironbus serve --data-dir /tmp/ironbus-demo`):

| Topic | Rust (blocking) | Rust (async) | Go |
| --- | --- | --- | --- |
| Produce (awaited / QoS0 / dedup / pipelined) | `produce` | `produce_async` | `produce` |
| Work-group consume + ack | `consume_ack_group` | `consume_async` | `consume_ack_group` |
| Streaming consume (Tier-S) | `streaming_consumer` | `streaming_consumer_async` | — |
| Transactions (2PC) | `transactions` | — | — |
| Named streams | `streams` | — | `streams` |
| Subjects + wildcards | `subjects_wildcard` | — | `subjects_wildcard` |
| Cluster not-leader redirect | `not_leader` | — | `cluster_notleader` |
| Authentication | `auth` | — | `auth` |

Run them with, e.g., `cargo run -p ironbus-client --example produce` or
`go run ./examples/produce` (from `sdk/go`).
