# Tiered storage — offloading cold segments to object storage (#643, V2-M10)

IronBus tiers **cold, sealed, immutable log segments** out to a cheap, high-capacity backing store,
reclaiming local disk while keeping every record readable. This is the Kafka KIP-405 / Pulsar /
Redpanda tiered-storage class: an immutable sealed segment (its footer written, no in-place mutation
ever races) is the natural tiering unit.

Tiered storage is **OFF by default**. A broker that never enables it writes zero new bytes, touches no
new files, and pulls none of the object-storage dependencies into its build.

## The two backends

Offload/fetch/recover/reap is driven through one tiny `ColdStore` seam (`put`/`get`/`delete`/`exists`
over an opaque object key). The backing store is chosen by config; the crash-safety, manifest, and
retention logic is **backend-agnostic and identical** for either:

| Backend | Selector | Feature | Use |
| --- | --- | --- | --- |
| `FsColdStore` | default | (always built, pure Rust) | A local directory / NFS mount. Phase 1 (#1152). |
| `S3ColdStore` | `S3ColdStoreConfig` | `s3` (off by default) | Amazon S3 / S3-compatible (MinIO, Ceph, Cloudflare R2, LocalStack). Phase 2 (#643). |

`S3ColdStore` is a small, **purpose-built** S3 client — not a general object-storage crate. The four
`ColdStore` verbs are four S3 requests (`PUT` upload, `GET` download, `DELETE`, `HEAD`), none of which
needs an XML response body, so a non-2xx is a typed error read from the **status line**, never a parsed
error document. The log's offload/fetch/recover/reap machinery is **unchanged**; only the trait
implementation differs. See [`crates/ironbus-storage/src/cold.rs`](../crates/ironbus-storage/src/cold.rs).

### Why hand-rolled (ADR-0004)

The S3 backend deliberately does **not** use a general object-storage crate. The mature options
(`object_store`, the AWS SDK) have a hard dependency on `ring`, which ADR-0004 bans in favour of
**aws-lc-rs as IronBus's sole crypto provider**. Instead, `S3ColdStore` is built from crates **already
in the tree** for the TLS stack:

- **AWS Signature Version 4** request signing over **aws-lc-rs** (HMAC-SHA256 + SHA-256) — no `ring`.
- **HTTPS** over the same **rustls + aws-lc-rs**, TLS 1.3-only stack the `tls` feature ships.
- **HTTP/1.1** over `hyper` + `hyper-util`; no XML parser.

So the `s3` feature adds **zero new crates**, links **no `ring`** and **no XML parser**, keeps the
default graph clean, and needs **no `cargo deny` / MSRV exceptions**.

## Building with the S3 backend

```sh
cargo build -p ironbus-storage --features s3
```

The default broker graph pulls **none** of the S3/HTTP/TLS deps (`cargo tree -p ironbus-storage -e
normal` is clean), and `ring` is absent from the whole all-features tree.

## Configuration

`S3ColdStoreConfig` selects and parameterizes the S3 backend:

| Field | Meaning |
| --- | --- |
| `bucket` | The S3 bucket the log's cold objects live in. |
| `prefix` | An object-key prefix within the bucket (the engine gives each log its own prefix so keys never collide across logs). May be empty. |
| `region` | The AWS region (e.g. `us-east-1`) — part of the SigV4 scope and the default endpoint host. |
| `endpoint` | An explicit endpoint URL for an S3-**compatible** store (`https://s3.example.com`, `http://127.0.0.1:9000`). Omit for real AWS S3 (`s3.<region>.amazonaws.com`). |
| `path_style` | Path-style (`/<bucket>/<key>`) vs virtual-hosted (`<bucket>.<host>/<key>`). `true` for most S3-compatible stores + LocalStack; AWS accepts either. |
| `access_key_id` / `secret_access_key` / `session_token` | Static SigV4 credentials. The secret + session token are redacted in `Debug`. |
| `ca_pem` | The trust-anchor (CA) PEM used to verify the endpoint's certificate over HTTPS. **Required** for an `https` endpoint; ignored for a plaintext `http` endpoint. |

**Credentials (phase 2):** static keys from config/environment
(`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / optional `AWS_SESSION_TOKEN`). IAM instance-profile /
ECS-task-role / STS auto-resolution is a documented follow-up. Automatic loading of bundled/OS trust
roots (so `ca_pem` is optional for real AWS) is likewise a follow-up.

Constructed with `S3ColdStore::new(config)`, then installed on the log with the same
`set_cold_storage(store, ColdStorageConfig)` seam the default `FsColdStore` uses. `ColdStorageConfig`
(the policy — `enabled` and `keep_recent_segments`) is orthogonal to the backend choice.

## The durability contract (where a bug is permanent data loss)

The load-bearing invariant is **upload → fsync-manifest-REMOTE → then delete the local file**: a local
segment is never unlinked before **both** its remote copy and its durable manifest entry exist. Every
crash window in between recovers to either fully-local or fully-remote-and-recorded — never a gap. See
[`RECOVERY.md`](RECOVERY.md) for the full crash-window analysis.

For the S3 backend this rests on one mapping: **a 2xx response to a `PUT` means the object is durable in
S3 before `Ok` is returned** (S3 acknowledges a PUT only once the object is durably stored and replicated
across Availability Zones, with read-after-write consistency) — exactly the "durable before the manifest
records REMOTE" guarantee `FsColdStore`'s `fsync` provides. A `GET` returns the raw object bytes, which
the caller re-verifies (segment header + footer + CRC32C, pinned in the manifest entry) before trusting
them, so a corrupt store fails closed. `DELETE` is idempotent (a 404 is treated as success, so a retried
reap is safe) — but a `403`/`5xx` is surfaced as a typed error, never masked as a completed reap.

## The async/sync bridge

The S3 client is async; the `ColdStore` trait is sync, to match the log's **single-writer append
actor** (a plain synchronous thread that owns `&mut Log`). Each `ColdStore` method bridges with
`block_on` over one tokio **current-thread** runtime owned by the backend. The actor is never itself
inside a tokio runtime, so `block_on` can never re-enter/deadlock a running one; it serializes every
cold-store call, so the runtime is never contended.

## Testing

SigV4 correctness is proven in CI **without network**: the SigV4 signer is tested against **AWS's
published test vectors** (the "deriving the signing key" example and the `get-vanilla` request from the
AWS SigV4 test suite) in `cold.rs`, matching AWS byte-for-byte. The
`ColdStore` contract + the full log-driven offload/fetch/reap lifecycle are tested against an in-process
**mock S3 server** (`tests/cold_s3.rs`) that also validates every request carries a well-formed SigV4
`Authorization` header. No real S3, no network, no extra dependency.

### Testing against a real S3 (manual)

#### Against LocalStack or MinIO (S3-compatible, local)

```sh
# 1. Start a local S3-compatible endpoint, e.g. MinIO on :9000; create a bucket `ironbus-cold`.
# 2. Point the backend at it via S3ColdStoreConfig:
#      bucket:            "ironbus-cold"
#      endpoint:          Some("http://127.0.0.1:9000")   # plaintext dev endpoint (no ca_pem)
#      region:            "us-east-1"
#      path_style:        true
#      access_key_id:     "minioadmin"
#      secret_access_key: "minioadmin"
# 3. Enable tiering, produce enough to roll several sealed segments, trigger the retention tick, then
#    confirm the cold objects appear under the bucket/prefix and a fetch-on-read serves them byte-exact
#    after the local files are reclaimed.
```

#### Against real AWS S3

```sh
# Provide static credentials + the CA trust anchor for HTTPS:
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# S3ColdStoreConfig {
#   bucket: "your-bucket", region: "us-east-1", prefix: "ironbus/log-0",
#   endpoint: None,                 # => https://s3.us-east-1.amazonaws.com
#   path_style: false,              # virtual-hosted (AWS default)
#   ca_pem: Some(<the Amazon root CA chain, or the system CA bundle bytes>),
#   .. }
```

## Observability

Offload runs best-effort on the retention tick and never fails a produce: a cold-store outage or a full
manifest is surfaced on the `ironbus_cold_offload_errors_total{reason}` counter (plus a `warn!`) and
retried on the next tick. See [`METRICS.md`](METRICS.md).

## Phase 2 scope vs deferred

**Phase 2 (this change):** the `S3ColdStore` backend (SigV4 over aws-lc-rs; HTTPS over rustls +
aws-lc-rs; PUT/GET/DELETE/HEAD) + `S3ColdStoreConfig` + the async/sync bridge, behind the `s3` feature;
the SigV4 test-vector proof + the full `ColdStore` contract + a log-driven offload/fetch/reap test.

**Deferred (backend-agnostic follow-ups):** operator-facing CLI/serve wiring to select+configure the
backend; IAM/ECS/STS credential auto-resolution; automatic OS/bundled TLS trust roots (so `ca_pem` is
optional); connection pooling; a local restore cache with eviction; offload of compacted (v2) segments;
async/background off-actor offload/prefetch; a startup orphan-object sweep. None touch the backend's
signing or wire format.
