# ADR index

A flat catalog of the architecture decisions resolved in the IronBus design, each
with its id, title, status, owning issue, and a one-line summary. It is the
queryable companion to the numbered ADR files: those files own the rationale, the
owning GitHub issues and the top-level `README.md` own the decision, and this index
just lists every decision in one place so a reader can find it without walking 22
issues. Issue [#130](https://github.com/ELares/IronBus/issues/130) owns this index.

## What stays canonical

This index does not own any decision. The frozen decisions live on their owning
GitHub issues, the headline ones are summarized in the top-level `README.md` under
"Key decisions already committed", and the byte-level and invariant detail lives in
[`docs/CONTRACTS.md`](../CONTRACTS.md) and [`docs/INVARIANTS.md`](../INVARIANTS.md).
Where this index and a source disagree, the code, the README, and the owning issue
win, in that order, and this index is corrected. This index does NOT duplicate the
contract tables or the invariant statements; it points at them.

## How to read the status column

- **Accepted**: the decision is in force and reflected in the owning issue, the
  README, or the code.
- **Proposed / Open**: the decision is written down but not fully resolved or not
  fully implemented; the owning issue is still open on it.
- **Superseded**: a later decision replaced it; the row names the replacement.

An entry whose **ADR** column is a numbered file (`0001` and up) has a record under
this directory. An entry marked **ADR file pending** has its decision frozen in the
code and the issue, but no numbered ADR file has been written for it yet; the
decision is no less binding, it just has not been transcribed into an `NNNN-slug.md`
record. Do not cite a pending row as if a file exists.

> A note on numbering. The seed rows in the #130 issue body (ADR-0007, 0011, 0019,
> 0024, ...) and their `CONFLICTED` statuses predate the resolution pass. Those
> cross-issue conflicts (the WAL architecture, the checksum stack, segment
> recycling, the compression default) were resolved in
> [#139](https://github.com/ELares/IronBus/issues/139), and the committed ADR files
> use a fresh sequential numbering starting at 0001. This index catalogs the ACTUAL
> committed state, not the stale seed ids, so a reader is never pointed at a number
> that does not exist.

---

## Numbered ADRs (records exist under `docs/adr/`)

| ADR | Title | Status | Owning issue | Summary |
| --- | --- | --- | --- | --- |
| [0001](0001-log-is-wal.md) | The active segment is the write-ahead log | Accepted | [#4](https://github.com/ELares/IronBus/issues/4), [#6](https://github.com/ELares/IronBus/issues/6) | There is no separate WAL file; a publish is one framed, CRC32C'd, record-aligned append to the active segment, fdatasync'd, and the offset index is derived and rebuilt on startup. |
| [0002](0002-segments-never-recycled-in-v1.md) | v1 never recycles a segment id | Accepted | [#18](https://github.com/ELares/IronBus/issues/18), resolved in [#139](https://github.com/ELares/IronBus/issues/139) | A new segment always takes a fresh id strictly greater than any used before, so the at-rest AEAD nonce can derive from `segment_id` without nonce reuse under a fixed key. |
| [0003](0003-default-compression-lz4-zstd-opt-in.md) | lz4_flex is the default codec, zstd is opt-in | Accepted | [#12](https://github.com/ELares/IronBus/issues/12), resolved in [#139](https://github.com/ELares/IronBus/issues/139) | The default compression codec is pure-Rust `lz4_flex`; zstd (vendored-C `zstd-sys`) is opt-in only behind a feature, never on the default path, keeping the default static musl binary C-free. |

---

## Frozen decisions recorded in code / issues (ADR file pending)

These decisions are resolved and frozen in the code and on their owning issues, but
no numbered ADR file has been written for them yet. They are catalogued here so the
index is complete; each names where it is canonical so a maintainer can promote it
to a numbered record. The byte layouts are in
[`docs/CONTRACTS.md`](../CONTRACTS.md) and the invariants in
[`docs/INVARIANTS.md`](../INVARIANTS.md); this table does not repeat them.

### Decisions resolved in the #139 coherence pass

| Title | Status | Owning issue | Summary |
| --- | --- | --- | --- |
| Default compression codec and C-FFI posture | Accepted (file pending) | [#12](https://github.com/ELares/IronBus/issues/12) / [#17](https://github.com/ELares/IronBus/issues/17), resolved in [#139](https://github.com/ELares/IronBus/issues/139) | Same decision as ADR-0003, viewed from the supply-chain side: the default binary path carries no vendored-C crate; enforced in `deny.toml`. (ADR-0003 records the codec half; the C-FFI-allowlist half, #102, has no file.) |
| LossReport serde posture | Accepted (file pending) | [#120](https://github.com/ELares/IronBus/issues/120), via [#223](https://github.com/ELares/IronBus/issues/223) | `LossReport` derives `serde::{Serialize, Deserialize}` in prod; `serde_json` is a dev-only dependency so the static edge binary stays small. Source: `crates/ironbus-storage/src/loss.rs`. |
| Log-is-WAL single append path (durability coherence) | Accepted (recorded by ADR-0001) | [#6](https://github.com/ELares/IronBus/issues/6), [#4](https://github.com/ELares/IronBus/issues/4), restated in [#139](https://github.com/ELares/IronBus/issues/139) | The #139 root-drift-1 fix re-anchored the durability clause to the active segment (no separate WAL file, no async feed, no WAL checkpoint). ADR-0001 is the file. |
| Single resync predicate | Accepted (file pending) | [#5](https://github.com/ELares/IronBus/issues/5), confirmation count [#8](https://github.com/ELares/IronBus/issues/8), via [#139](https://github.com/ELares/IronBus/issues/139) | Resync is magic match AND header CRC32C valid AND seq continuity within the segment, owned by #5; #8 adds the two-consecutive-record confirmation on top. See `docs/CONTRACTS.md` (record models) and `docs/INVARIANTS.md` (I1). |
| No segment recycling vs at-rest nonce | Accepted (recorded by ADR-0002) | [#5](https://github.com/ELares/IronBus/issues/5) / [#18](https://github.com/ELares/IronBus/issues/18), resolved in [#139](https://github.com/ELares/IronBus/issues/139) | Same decision as ADR-0002; #4's recycle-up-to-2 and #20's generation-tag guard were dropped. ADR-0002 is the file. |
| Config locked tables include `[observability]` and `[auth]` | Proposed / Open | [#14](https://github.com/ELares/IronBus/issues/14), recorded in [#139](https://github.com/ELares/IronBus/issues/139) | A forward decision: when config (#14) is built, the fatal-on-unknown table set gains `[observability]` and `[auth]` plus at-rest keys. NOT yet implemented (there is no TOML config in code today; see `docs/CONTRACTS.md` config section). |
| Wire protocol is binary-only (no netcat / text mode) | Accepted (file pending) | [#11](https://github.com/ELares/IronBus/issues/11), confirmed in [#139](https://github.com/ELares/IronBus/issues/139) | The README points at `ironbus tap` / `ironbus wire` for inspection, not netcat; binary length-framed is the only wire format. See `docs/CONTRACTS.md` (wire frames). |

### Frozen wire and on-disk format decisions (canonical in `docs/CONTRACTS.md`)

| Title | Status | Owning issue | Summary |
| --- | --- | --- | --- |
| Frame envelope `[len:u32][type:u8]` | Accepted (file pending) | [#11](https://github.com/ELares/IronBus/issues/11) | The wire envelope is a little-endian u32 length (counting the type byte plus body) then a one-byte type tag; no varints anywhere. Source: `crates/ironbus-proto/src/frame.rs`. |
| Frozen frame tag set (Connect 1 .. Truncated 18) | Accepted (file pending) | [#11](https://github.com/ELares/IronBus/issues/11) | The frame type tags start at 1 and are contiguous through `Truncated` (18); pinned by `type_tags_have_their_exact_frozen_wire_values`. See `docs/CONTRACTS.md` (FrameType tags). |
| Distinct response frames per verb | Accepted | [#179](https://github.com/ELares/IronBus/issues/179) (CLOSED) | `PubAck` (14), `AckStatus` (15), and `FlowEnd` (16) replace an overloaded generic `Ok`, so a reply is self-describing and request pipelining is possible. `Ok` (11) is retained as a reserved body-less success. |
| 36-byte record header / 8-byte trailer | Accepted (file pending) | [#5](https://github.com/ELares/IronBus/issues/5) | The on-disk record is a fixed 36-byte header (magic `0x4942`, `header_crc` over `[0,32)`) then body then an 8-byte trailer (`body_crc`, `total_len`); offsets are frozen. See `docs/CONTRACTS.md` (RecordHeader / RecordTrailer). |
| xxh3-64 large-payload checksum in the frame | Accepted | [#146](https://github.com/ELares/IronBus/issues/146) (CLOSED) | A record whose stored body reaches `XXH3_PAYLOAD_THRESHOLD` (64 KiB) carries an 8-byte xxh3-64 immediately before the trailer, flagged by `HAS_XXH3`. CRC32C is still verified first and gates resync; an xxh3 mismatch is the distinct `BadXxh3`. |

### Durability and recovery decisions (canonical in `docs/INVARIANTS.md`)

| Title | Status | Owning issue | Summary |
| --- | --- | --- | --- |
| fdatasync-before-ack durability default | Accepted (file pending) | [#6](https://github.com/ELares/IronBus/issues/6) | The default durability level group-commits an `fdatasync` of the active segment before any ack; a failed fsync freezes the writer read-only rather than acking. See `docs/INVARIANTS.md` (I2). The opt-in `none` / `interval` modes are specified but NOT implemented. |
| Torn-tail truncation on recovery | Accepted (file pending) | [#7](https://github.com/ELares/IronBus/issues/7) | Recovery takes the longest valid prefix and truncates a torn or partially written tail, reporting the dropped span as a `TornTail` loss event; it never reads past the durable head. See `docs/INVARIANTS.md` (I1). |
| Bounded-loss recovery caps and checkers | Proposed / Open | [#120](https://github.com/ELares/IronBus/issues/120) (OPEN) | A corruption skip is capped (one segment or 64 MiB per event, 1% of durable bytes per recovery) and always reported; exceeding a cap fails the open. The I1 to I4 checkers and the versioned `LossReport` schema landed (#223 to #226), but #120's full harness wiring and checker-numbering alignment stay open. See `docs/INVARIANTS.md` (I3 and the resilience checkers). |
| Visibility-timeout lease + DLQ model | Accepted (file pending) | [#9](https://github.com/ELares/IronBus/issues/9), DLQ sink [#63](https://github.com/ELares/IronBus/issues/63) | At-least-once delivery with a visibility-timeout lease (default 30 s, hard cap 5 min), generation fencing against double-ack, `max_deliver` (default 5) then an exactly-once move to a durable DLQ sink keyed by `(group, source_offset)`. See `docs/INVARIANTS.md` (always-on invariants) and `docs/CONTRACTS.md` (DLQ model). |

### Dependency, default, and bound decisions

| Title | Status | Owning issue | Summary |
| --- | --- | --- | --- |
| Graceful-shutdown + reload signal handling via `signal-hook` | Accepted | [#195](https://github.com/ELares/IronBus/issues/195) (CLOSED), [#380](https://github.com/ELares/IronBus/issues/380) | SIGINT/SIGTERM checkpoint every group's cursor before exit; SIGHUP re-reads `--config` and applies the live-reloadable subset (a runtime reload, #380), never a stop. Uses `signal-hook` (per-signal, so the stop signals and SIGHUP are distinguished — superseding the earlier `ctrlc`, whose `termination` feature could not tell them apart) over a hand-rolled `unsafe` sigaction Miri cannot exercise; it pulls `signal-hook-registry`/`libc`, allowlisted in `deny.toml`. Recorded in `crates/ironbus-cli/Cargo.toml`. |
| Per-consumer in-flight credit (auto-tuning count window) | Accepted (file pending), issue OPEN | [#65](https://github.com/ELares/IronBus/issues/65) (OPEN), [#552](https://github.com/ELares/IronBus/issues/552) | Each connection holds at most `consumer_credit` un-acked messages, floored to 1, no unbounded opt-out; effective bound is the min of this and the per-group window. The message-count window now AUTO-TUNES (#552): `DEFAULT_CONSUMER_CREDIT` = 2048 is the CEILING the window grows toward from a 64 floor as the consumer keeps draining (halving under backpressure), RAM-bounded by the firm `consumer_credit_bytes` budget; an explicit `--consumer-credit <= 64` pins the historical fixed window. The message-count half is implemented (#274); the per-consumer BYTE budget and wire-negotiated credit are deferred (#275), so #65 stays open. |
| Named work-group cap default 1024 | Accepted (file pending), issue OPEN | [#240](https://github.com/ELares/IronBus/issues/240) (OPEN) | `max_groups` (`DEFAULT_MAX_GROUPS` = 1024, `0` = unlimited) rejects a new named group past the cap with `TooManyGroups`; names are validated (1 to 128 graphic-ASCII bytes); the default group `""` is exempt. The cap and validation landed (#278); idle-group eviction / `Unsub` lifecycle is deferred (#277), so #240 stays open. |

---

## Promoting a pending row to a numbered ADR

To turn a pending row into a record: copy `template.md` to the next free
`NNNN-slug.md`, fill in the context, decision, and consequences, cite the owning
issue, and replace the "ADR file pending" mark in this index with the new number.
The number, once assigned, is never reused. See [`README.md`](README.md) for the
full process.

A machine-readable `adr.yaml` that this table renders from (mirroring the #2
claims.yaml pattern named in #130) is not yet in the tree; it is a follow-up to this
prose index and is tracked under #130.
