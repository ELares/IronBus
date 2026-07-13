# ironbus-iceberg-sink

Materialize an IronBus topic as an **Apache Iceberg** table (Parquet data files + Iceberg v2
metadata) in object storage, so Snowflake, Databricks, Spark, Trino and DuckDB can query the bus's
data as an open table — without a bespoke Flink/Spark ETL job. (#793, phase 1.)

This is a **standalone companion binary**. It is a plain consumer that reads the bus over the wire
and writes the table entirely outside the broker.

## The broker stays a pure message bus

This connector is its **own, separate Cargo workspace**, deliberately **excluded** from the root
IronBus workspace (see the root `Cargo.toml` `exclude` list, alongside `tools/loom-tests`). That is a
hard dependency-isolation constraint: the heavy analytics stack it pulls (Apache Arrow, Parquet, the
`iceberg` metadata layer, Thrift, Avro, tokio, opendal) must **never** unify into the broker's
dependency graph or its `cargo-auditable` SBOM. Because Cargo resolves features per-lockfile, only a
separate, excluded workspace with its own `Cargo.lock` guarantees that `cargo build` / `cargo tree`
of the broker stays Arrow/Parquet/Thrift-free. The sink path-depends on `ironbus-client` (a pure-Rust
leaf) to consume, exactly like any external consumer.

The broker-native "topics are tables" path (an in-broker query engine / Pulsar-SQL / Trino-style
surface) is an explicitly **declined non-goal**, alongside the already-declined KV and object-store
non-goals. Iceberg here is *output materialization* by an external consumer, not the broker becoming
a lakehouse.

## Usage

```sh
# Run a broker
ironbus serve --data-dir /var/lib/ironbus

# Drain the topic into an Iceberg table and exit (one-shot / batch)
ironbus-iceberg-sink --addr 127.0.0.1:7777 --output /data/lake/orders

# Or follow the topic continuously
ironbus-iceberg-sink --addr 127.0.0.1:7777 --stream orders --group lake-orders \
    --output /data/lake/orders --follow
```

Flags: `--addr`, `--stream` (empty = the default stream), `--group`, `--output` (the table
directory), `--batch-max-records`, `--batch-max-bytes`, `--start-offset` (for a brand-new table),
`--follow`, `--poll-interval-ms`, `--manifest-compaction-threshold` (compact once the current
snapshot references this many manifests; `0` disables — default 16) and `--snapshot-retention-count`
(snapshots to keep; the current snapshot is always kept — default 10).

## Bounded metadata growth (manifest compaction + expire-snapshots)

Every append carries the full manifest set forward and adds a snapshot, so a naively long-lived table
would write O(N²) manifest-list bytes over N commits and grow an unbounded snapshot log. Once the
current snapshot accumulates `--manifest-compaction-threshold` manifests, the sink rewrites them into
one compacted manifest (a spec `replace` snapshot over the **same** data files — no row is added or
dropped) and expires snapshots outside `--snapshot-retention-count`, bounding both. This is
correctness-preserving: the compaction commit uses the **identical** crash-safe fsync discipline as an
append and is published atomically by the `version-hint.text` swap, and the durable resume watermark is
carried onto the replace snapshot so a cold restart resumes exactly where it left off. Stale
manifest/manifest-list files are reclaimed **only after** the new metadata is durably committed
(delete-after-commit), and only if **no** retained snapshot references them; data files are never
deleted (this append-only sink keeps them all live). A crash at any point leaves a valid table — at
worst a few harmless orphan files, never a dangling pointer.

## Table schema

Each bus record maps to one row of a flat, unpartitioned Iceberg v2 table:

| column         | type          | field-id | notes                                   |
| -------------- | ------------- | -------- | --------------------------------------- |
| `offset`       | `long`        | 1        | the bus log offset (ordering + dedup)   |
| `timestamp_ms` | `long`        | 2        | producer timestamp, ms since epoch      |
| `flags`        | `int`         | 3        | stored record flags                     |
| `key`          | `binary`      | 4        | routing/ordering key (empty if none)    |
| `headers`      | `binary`      | 5        | headers blob (empty if none)            |
| `payload`      | `binary`      | 6        | the message payload, opaque bytes       |

`offset` is a SQL reserved word in some engines — quote it (`"offset"`) in queries.

The payload is materialized as **opaque binary**: this is the useful bus *envelope*, not a
single-column dump. Decoding the payload into typed, per-schema columns is gated on the
schema-encoding story (**#762**) and is a follow-up; until then downstream engines decode `payload`
themselves.

## Correctness: at-least-once in, exactly-once in the table

* **The table's own state is the resume + dedup authority.** Every snapshot records
  `ironbus.next-offset` (the exclusive high offset the table now covers) in its summary. On startup
  the sink reads it back and consumes strictly from there, so it never re-materializes an offset the
  table already holds.
* **The Iceberg commit is an atomic pointer swap.** A batch writes the Parquet data file, the
  manifest, the manifest list and the new `v{N}.metadata.json` (all fsynced), then atomically renames
  `version-hint.text` to `N`. A crash *before* the rename leaves the new files orphaned and the table
  valid at the previous version (the batch simply re-materializes on resume); a crash *after* it has
  already advanced the watermark, so the broker cursor (committed last) redelivering that batch is
  dropped by the dedup filter. Either way, no duplicate and no dropped row.
* The broker consumer-group cursor is advanced after each commit so retention can progress, but it is
  only advisory — the table watermark is authoritative.

## Iceberg metadata approach

A minimal Iceberg table is Parquet data files plus an Avro manifest chain (manifest → manifest list →
`metadata.json`). The Avro manifest schemas carry ~30 fields each keyed by exact Iceberg field-ids;
one wrong id silently yields a table an engine refuses to read. Rather than hand-encode that, this
uses the `iceberg` crate's own spec writers (`ManifestWriter`, `ManifestListWriter`,
`TableMetadataBuilder`) — spec-correct by construction — while keeping full control of the two things
a catalog would otherwise own: the file **layout** and the durable **current-metadata pointer**
(`version-hint.text`). That is the plain Hadoop/`version-hint` convention DuckDB, Spark and Trino
read, and it makes the sink resumable without an external catalog. Parquet data files are written
directly with the Arrow writer.

## Verifying the table is queryable (DuckDB)

```sql
INSTALL iceberg; LOAD iceberg;
SELECT count(*), min("offset"), max("offset") FROM iceberg_scan('/data/lake/orders');
```

The integration test (`tests/integration.rs`, gated on `IRONBUS_BIN`) additionally scans the table
through its real Iceberg reference chain (`version-hint` → `metadata.json` → manifest list →
manifests → Parquet) and asserts contiguous offsets across a restart with no duplicates.

## Phase 1 vs. deferred

**Phase 1 (this crate):** a working, DuckDB-verified end-to-end sink — consume → Parquet → valid
Iceberg v2 table — against a **local-directory** object store, with resumable, dup-safe append.

**Follow-ups:** S3/GCS object-store backends; a REST-catalog endpoint; typed payload columns via the
schema-encoding story (#762); partitioning (e.g. by time); schema evolution; **data-file** compaction
(bin-packing the small per-batch Parquet files — manifest compaction + snapshot expiry already ship,
see above); Parquet compression tuning; multi-topic fan-out.
