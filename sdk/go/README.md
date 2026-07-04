# IronBus Go SDK

The official Go client for [IronBus](../../README.md) (issue #1021): a minimal,
wire-exact client over the frozen versioned protocol.

```go
import ironbus "github.com/ELares/IronBus/sdk/go"

client, err := ironbus.Connect(ctx, ironbus.Config{Addr: "127.0.0.1:7777"})
offset, err := client.Produce(ctx, &ironbus.Message{Payload: []byte("hello")})

err = client.Subscribe(ctx, "workers")
res, err := client.Fetch(ctx, ironbus.FetchOptions{MaxRecords: 64})
for _, m := range res.Messages {
    _, _ = client.Ack(ctx, m.Offset, m.Generation)
}
```

## Scope (MVP)

- Connect/Info handshake with capability negotiation (credit / credit-bytes /
  gap-marker / default ack level), Bearer + Password auth with redacting
  `String()`/`GoString()` on the credential.
- Produce: awaited (level 1), fire-and-forget (level 0), level-2 wire bits,
  opt-in dedup (duplicate returns the original offset).
- Tier-W consume: `Subscribe` + batch `Fetch` (tag 23) on the default stream,
  `Ack`/`Nack`/`Term`/`Progress` with offset+generation fencing,
  `CumulativeAck` for broadcast groups, DeadLetter / Truncated / GapMarker
  advisory decode, transparent broker-side lz4 BLOCK decompression (per-record
  8 MiB cap before allocation plus an aggregate fetch-window ceiling).
- Named streams: `DeclareStream` / `QueryStream` / `ProduceTo` /
  `SubscribeTo`; subjects incl. `*`/`>` wildcard BIND patterns:
  `BindSubject` / `ProduceSubject` / `SubscribeSubject`. A named-stream or
  subject binding is drained with the per-record Flow verb (tag 10)
  transparently — the broker's batch Fetch verb polls the default stream only.
- Cluster `NotLeader` (tag 42) decoded into the typed
  `NotLeaderError{LeaderHint}`.

Deliberately OFF (capabilities not advertised, so the broker never sends the
frames): Tier-S streaming (`StreamFetch`/`StreamCommit`), raw-framed
`DeliverBatch` (tag 26), transactions (tags 44-49), TLS/mTLS, the zstd codec.

## Concurrency model

A `Client` owns ONE TCP connection driven request-response FIFO, mirroring the
reference clients: it is NOT goroutine-safe. Use one `Client` per goroutine.
Context deadlines map onto the socket's read/write deadlines (cleared after
each call); the read path is cancellation-safe (scratch-then-extend), so a
deadline mid-frame never desyncs the framing. A deadline (or cancellation)
that fires while a reply is pending is TERMINAL for the connection, matching
the Rust reference client: the FIFO is still owed that reply, so a timed-out
`Client` must be discarded and a new one dialed.

## Wire conformance

`internal/wire/testdata/golden_vectors.json` is the language-neutral
golden-frame corpus exported by the NORMATIVE Rust encoders. `go test ./...`
decodes every vector and re-encodes it byte-identically. Regenerate after a
(deliberate, reviewed) wire change:

```sh
IRONBUS_EXPORT_GO_VECTORS="$PWD/sdk/go/internal/wire/testdata" \
  cargo test -p ironbus-proto --test export_go_vectors
```

## Live integration tests

Env-gated OFF in CI (no release binary there; see
`.github/workflows/go-sdk.yml`). Locally:

```sh
cargo build --release
cd sdk/go && IRONBUS_LIVE=1 go test ./...
```

`IRONBUS_BIN` overrides the broker binary path.

## Examples

Each example runs against a live broker
(`ironbus serve --data-dir /tmp/ironbus-demo`):

- `examples/produce`: awaited, fire-and-forget, and dedup produces.
- `examples/consume_ack_group`: the work-group fetch/ack loop.
- `examples/streams`: named-stream declare / query / produce / consume.
- `examples/subjects_wildcard`: wildcard subject binding + subject pub/sub.
- `examples/cluster_notleader`: following the typed NotLeader redirect (a
  single-node broker never emits it; run against a cluster node to see the
  redirect).
- `examples/auth`: connecting with a bearer or username+password credential
  (secret redacted when logged; safe to run against a no-auth broker, which
  ignores it).

The only dependency is `github.com/pierrec/lz4/v4` (the broker compresses
stored payloads transparently, so the SDK must decode lz4 blocks).
