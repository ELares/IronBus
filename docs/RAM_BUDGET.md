# The tiny-profile RAM budget

This document derives the broker's resident-memory (RSS) budget from the
source, accounts for every RAM source and the configuration knob that bounds
it, and gives a worked edge configuration whose steady-state total fits under
the 64 MiB ceiling the README asserts for the `tiny` edge profile
([#20](https://github.com/ELares/IronBus/issues/20),
[#115](https://github.com/ELares/IronBus/issues/115)).

It complements [CLI.md](CLI.md) (the flag reference, every default cited to its
`main.rs` constant), [EDGE_TUNING.md](EDGE_TUNING.md) (the edge-knob tuning
guide), [THREAT_MODEL.md](THREAT_MODEL.md) (the resource-exhaustion DoS
mitigations these same knobs provide), and [SLO.md](SLO.md) (the steady-state
RAM SLO row, measured by the macro-bench harness).

## Honest summary up front

Read this before the arithmetic, because it changes how you should read it:

- **A RAM ceiling is now ENFORCED by a refuse-to-boot guard (#115).** When
  `ram_ceiling_bytes` is set (the `--ram-ceiling-bytes` serve flag; the
  `edge-tiny` profile sets it to 64 MiB), the broker computes the WORST-CASE
  bounded-buffer footprint the configured caps imply (the formula below) and
  REFUSES to start, with a usage error (exit 1) naming the overage and the knobs
  to lower, when that worst case provably exceeds the ceiling. The verdict is
  PROVABLE from the config, NOT a live boot-time RSS reading: RSS at boot is
  near-zero and meaningless as a steady-state predictor, so the guard asserts only
  what the caps prove (the bounded-buffer sum either can or cannot fit), never a
  guess. With a ceiling set, the `ironbus_ram_headroom_bytes` gauge also reports a
  real `ceiling - RSS` headroom instead of the `-1` unset sentinel. The
  default is `0` = UNSET (the guard is off for `balanced`/`throughput`), so a
  zero-config broker is unchanged. The implementation is in
  `ironbus_server::rss::worst_case_buffer_bytes` / `fits_under_ram_ceiling` and the
  CLI `validate_ram_ceiling`. The only OTHER RSS-aware code is the macro-bench probe
  (`crates/ironbus-bench/src/probe.rs`, `rss_bytes`), which *measures* steady-state
  RSS during a benchmark run; the precise on-device RSS-under-ceiling measurement
  stays a device residual (a shared CI runner's RSS is not meaningful), so the guard
  asserts the provable-from-config fit, not the live RSS magnitude.
- **The default knob values are NOT edge-safe.** Shipped as-is, the
  per-connection and per-connection-times-`max_connections` worst cases are far
  over 64 MiB (the arithmetic is below: the consumer byte budget alone is
  ~2 GiB worst case, ~32x over). The defaults target a server, not a 64 MiB
  edge node. You MUST lower them for the edge; the worked config below does.
- **There is no mmap in storage.** Segments are read and written through
  positional file IO (`write_all_at` / `read_at`), not a memory map, so there
  are no uncounted mapped pages. The #115 design sketch's `mmap_max_bytes=0`
  knob is therefore a no-op (there is nothing to set it on), so the guard does
  not model an mmap term: term 4 (the active segment) is ~0 in RSS.

The itemized per-buffer budget, the refuse-to-boot guard, and the auto edge
profile that [#115](https://github.com/ELares/IronBus/issues/115) specifies are
now SHIPPED (the guard above, plus `--profile edge-tiny`,
[#87](https://github.com/ELares/IronBus/issues/87)); the per-topic RAM floor (a
multi-queue concept) and the tighter read-buffer bound remain follow-ups under
[#20](https://github.com/ELares/IronBus/issues/20) and
[#117](https://github.com/ELares/IronBus/issues/117). What follows is the
honest accounting against the code as it ships, so an operator can also do the
sizing by hand when no ceiling is set.

Throughout, MiB = 1024 * 1024 bytes and KiB = 1024 bytes.

## The RAM sources and their bounding knobs

There are seven process-RSS sources (one of which is the fixed overhead). Each is
bounded by a specific knob or a per-segment constant, cited to the code.

### 1. Per-connection in-flight messages (the dominant term)

Every delivered-but-not-yet-acked message is held in RAM in the session's
`leased` set until it is acked, nacked, termed, or its lease expires
(`crates/ironbus-server/src/session.rs`). Two per-connection knobs bound this,
and the effective bound is the smaller of the two:

- `consumer_credit` (`--consumer-credit`, default **2048** = the auto-tune
  CEILING, `DEFAULT_CONSUMER_CREDIT` in `crates/ironbus-server/src/engine.rs`):
  the max count of un-acked messages a connection may hold. The window AUTO-TUNES
  from a 64 floor toward this 2048 ceiling as the consumer keeps draining, halving
  under backpressure (#552); the ceiling is the WORST-CASE count this budget must
  charge. The firm `consumer_credit_bytes` budget below is what keeps the higher
  ceiling RAM-safe — the count grows strictly UNDER it. An explicit
  `--consumer-credit <= 64` pins the historical fixed window
  ([#65](https://github.com/ELares/IronBus/issues/65),
  [#552](https://github.com/ELares/IronBus/issues/552)).
- `consumer_credit_bytes` (`--consumer-credit-bytes`, default **8 MiB**,
  `DEFAULT_CONSUMER_CREDIT_BYTES` in `engine.rs`; `0` = unlimited): the max
  un-acked PAYLOAD bytes (key + headers + payload) a connection may hold
  ([#275](https://github.com/ELares/IronBus/issues/275)). The byte total is
  *derived* from the `leased` set's per-entry sizes
  (`Session::in_flight_bytes`), never a separate counter, so it cannot drift
  from true ownership.

A Flow delivers at most `min(message credits remaining, byte credits
remaining)`, with a hard floor of ONE message so a single over-budget message
never wedges the consumer (`Session::handle_flow`). So the worst-case in-flight
RAM for ONE connection is:

```
per_conn = min(consumer_credit * max_record_size,  consumer_credit_bytes)
           + (one floor-of-one over-budget message, at most max_record_size)
```

and the broker-wide worst case multiplies by `max_connections`
(`--max-connections`, default **256**, `DEFAULT_MAX_CONNECTIONS` in
`crates/ironbus-cli/src/main.rs`), the only knob that bounds the connection
count (the accept loop refuses past it, `serve` / `ConnectionSlot` in
`crates/ironbus-server/src/server.rs`).

**KEY FINDING: the defaults are not edge-safe.** With the shipped defaults and
the 8 MiB byte budget binding (it binds long before the 2048-message count
ceiling * a 16 MiB record — the byte budget is the firm RAM bound the count
auto-tunes under):

```
per_conn worst case  = consumer_credit_bytes = 8 MiB
broker-wide          = 8 MiB * max_connections
                     = 8 MiB * 256
                     = 2048 MiB = 2 GiB
```

That is ~32x over the 64 MiB ceiling. The defaults are tuned for a server with
RAM to spare, not a 64 MiB edge node. This single term is why the defaults must
be lowered for the edge.

### 2. Per-connection read buffer

Each connection thread owns one inbound frame-assembly buffer (`inbuf` in
`handle_connection`, `crates/ironbus-server/src/server.rs`) that accumulates
bytes off the socket and is drained per fully-decoded frame. It cannot grow
without bound: the frame decoder rejects any frame whose length prefix exceeds
`MAX_FRAME_LEN` (**16 MiB + 64 KiB**, `crates/ironbus-proto/src/frame.rs`)
BEFORE allocating the body (`decode_frame_with_cap`), so a connection's read
buffer holds at most one almost-complete maximal frame plus a 4 KiB read chunk:

```
per_conn_read = MAX_FRAME_LEN + 4 KiB ~= 16 MiB + 68 KiB
```

The ONLY lever on this term is `max_connections`: there is no per-connection
read-buffer cap knob. That makes `max_connections` the strongest argument for
an auto RAM-guard, because at the default 256 the read buffers ALONE bound at
`256 * ~16 MiB ~= 4 GiB` worst case (only ever realized by 256 connections each
mid-delivery of a near-maximal frame, but it is the true ceiling). Lowering
`max_connections` is the single knob that bounds both this term and term 1.

### 3. Per-group state

Each live work-group holds an `AckCursor` (`crates/ironbus-core/src/cursor.rs`)
and a `LeaseTable` (`crates/ironbus-core/src/lease.rs`,
a `BTreeMap<u64, Lease>`). Both are bounded by the per-group in-flight window
`max_in_flight` (`--max-in-flight`, default **1024**, `DEFAULT_MAX_IN_FLIGHT`
in `main.rs`): the delivery window is `committed + max_in_flight`
(`Engine::poll`), so the `LeaseTable` holds at most `max_in_flight` `Lease`
entries (each a small fixed struct: generation, attempt_start, deadline,
deliveries) and the `AckCursor`'s acked-ahead `Vec` is bounded by the same
window.

The durable per-message attempt counter (#358) adds nothing unbounded. At rest
the attempt counts live INSIDE the `LeaseTable`'s `Lease` entries (the existing
`deliveries` field above), so they cost no extra RAM. The only added structure is
the `carried: BTreeMap<u64, u32>` map seeded at open from the durable
`attempts.ckpt` / `attempts-<hex>.ckpt` snapshot: it holds at most one
`(offset, attempt)` entry per in-flight offset, so it is bounded by the SAME
`max_in_flight` window, and each entry is consumed (dropped) by the first
redelivery after the restart, so it is empty in steady state. The on-disk snapshot
is likewise bounded: at most `max_in_flight` 12-byte pairs per group, capped to the
`ATTEMPTS_PAYLOAD` = 32 KiB checkpoint slot (the leading pairs that fit are kept;
the rare overflow tail only resets those offsets to attempt 1, never a leak).

The number of live groups is bounded by `max_groups` (`--max-groups`, default
**1024**, `DEFAULT_MAX_GROUPS` in `engine.rs`; the default group `""` is exempt
and never counted): a new named group past the cap is rejected with
`EngineError::TooManyGroups` before allocating anything
(`Engine::poll_in`). So:

```
group_state <= max_groups * max_in_flight * sizeof(Lease + cursor-range entry)
```

Each lease entry is on the order of tens of bytes (4 x u64-ish fields plus the
`BTreeMap` node overhead); call it ~64 bytes for a generous estimate including
the map node. This term is small compared to term 1 unless both `max_groups`
and `max_in_flight` are large.

### 4. Active segment and page cache (mostly NOT process RSS)

The log keeps one active segment open for append. Crucially, the active segment
is written STRAIGHT TO FILE, not buffered in RAM: `SegmentWriter::append`
encodes one record into a short-lived per-record scratch `Vec` and immediately
does `self.file.write_all_at(&buf, self.write_pos)`
(`crates/ironbus-storage/src/segment.rs`); there is no in-RAM accumulation of
the segment. Therefore `max_segment_bytes` (`--max-segment-bytes`, default
**64 MiB**, `DEFAULT_MAX_SEGMENT_BYTES`) and `max_total_bytes`
(`--max-total-bytes`, default `0` = unlimited) bound DISK, not process RSS. The
per-append scratch buffer is bounded by one record (<= `MAX_FRAME_LEN`) and is
freed immediately.

What the OS keeps in the PAGE CACHE for the segment files is a separate matter:
it is reclaimable kernel memory the OS drops under pressure, it is shared, and
it is not the broker's private RSS. It can show up in coarse "used memory"
tools but does not count against the broker's resident heap the way terms 1 to
3 do. The read path (`Log::read_from`) materializes at most one record at a
time into a batch `Vec` (`Engine::poll` reads `read_from(off, 1)`), so a
delivery never pulls a credit-sized batch into RAM at once; the in-flight RAM
is accounted in term 1 (the session's `leased` set), not here.

### 5. Fixed overhead

A floor independent of load:

- The static binary's resident text/data. The release build is size-optimized
  (`opt-level = "s"`, fat LTO, one codegen unit, `panic = "abort"`,
  `strip = true` in the workspace `Cargo.toml`,
  [#101](https://github.com/ELares/IronBus/issues/101)). The README ships it as
  "a single static binary you can drop onto a Raspberry Pi"; the historical
  draft cites it on the order of ~500 KiB. NOTE: this exact figure is NOT
  asserted anywhere in the source as a constant or test, so treat ~500 KiB as
  an order-of-magnitude placeholder, not a verified bound. Only a fraction is
  resident at any moment.
- Runtime: the engine's single `Mutex`-guarded state, the metrics counters, the
  embedded health/metrics server, per-connection thread stacks (one OS thread
  per connection, so this scales with `max_connections` too), and allocator
  arenas.
- The **bounded metric registry** (#97, `crates/ironbus-server/src/registry.rs`):
  a hard, fixed ceiling of `1024 consumer series x 80 bytes/series ~= 80 KiB`
  for the per-consumer lag table, plus an equally-capped bounded overflow
  fold-ledger (`1024 entries x 80 bytes ~= 80 KiB`) that keeps the `__overflow__`
  fold idempotent across the broker's per-ack commits, plus a fixed sub-1 KiB
  core (the two fixed-bucket histograms and the self-monitoring scalars). The
  per-series (and per-ledger-entry) cost is fixed-width and inline (a 64-byte
  label buffer plus fixed-width bookkeeping, identical on 32-bit and 64-bit), and
  both arrays are preallocated at their caps, so the whole registry is **~161 KiB
  INDEPENDENT of the record count, the disk size, and the number of live
  consumers**. That is well under 0.3% of the 64 MiB ceiling, so leaving the full
  metric surface on permanently is affordable. The cap is what makes this
  bounded: an unbounded consumer cardinality would otherwise grow these terms
  without limit, so a new consumer past the cap is refused its own series and
  folded into `__overflow__` (its lag still visible) rather than allocating, and
  the fold-ledger that makes that fold idempotent is itself capped. A test
  (`the_registry_memory_ceiling_is_fixed_and_bounded`) asserts the ceiling, and
  [METRICS.md](METRICS.md) carries the full derivation. This is the registry
  sign-off the #19 / #115 budget requires.

Call the fixed overhead ~4 MiB as a conservative working figure for the edge
profile (binary resident pages + runtime + a small allocator slack). This is an
estimate, not a measured or code-asserted bound.

### 6. Per-producer dedup window (opt-in, #33)

The opt-in effectively-once dedup registry
(`crates/ironbus-core/src/dedup.rs`) costs NOTHING until a producer opts in by
sending a `msg_id`; a no-dedup workload allocates zero here. When a producer
does opt in, it gets one bounded window: a `(msg_id -> offset)` ring indexed
twice (a FIFO order `VecDeque` and an O(1) lookup `HashMap`), bounded by BOTH a
count (`--dedup-max-ids`, default **100,000**, `DedupConfig::max_ids`, floored
to 1) AND a monotonic time bound (`--dedup-window-ms`, default **2 min**,
`DedupConfig::window_nanos`), evicting on whichever is hit first. So the
per-producer worst case is:

```
per_producer_dedup <= dedup_max_ids * (2 * msg_id_len + ~2 * (Vec/HashMap entry overhead))
```

Each entry stores the `msg_id` (`Vec<u8>`, bounded by `MAX_MSG_ID_LEN` = **256
bytes**, enforced as a typed rejection at the wire boundary in
`Session::handle_pub`) TWICE — once as the `HashMap` index key and once in the
order `VecDeque` (two independent heap copies, no `Arc` sharing) — plus a `u64`
offset and a `u64` insertion instant. So the per-entry worst case is `2 *
msg_id_len + ~2 * overhead`, i.e. with a maximal 256-byte id about **~704 bytes**.
For a generous estimate at the default count cap that is `100_000 * ~704 ~= 67 MiB`
PER opted-in producer with worst-case ids (or `100_000 * (2*32 + ~64) ~= 12 MiB`
with modest 32-byte ids). This term is therefore SIZED BY the count bound, so an
edge profile that opts into dedup must either lower `--dedup-max-ids` or rely on
the time bound to keep the live window small. The refuse-to-boot guard now CHARGES
this term at the configured caps (`DEDUP_ENTRY_BYTES ~= 704`, #878), so a bounded
ceiling refuses unless the dedup caps fit.

**The TOTAL is hard-bounded too.** The `producer_id` is wire-supplied and
attacker-chosen, so the NUMBER of distinct producer windows is NOT bounded by
the connection count (one connection can present an unbounded stream of distinct
`producer_id`s). It is bounded by `--dedup-max-producers` (default **4,096**,
`DedupConfig::max_producers`, floored to 1): a fresh `producer_id` over the cap
evicts the LEAST-RECENTLY-ACTIVE producer window (an approximate LRU keyed on
each window's last-touch monotonic instant), and fully time-expired windows are
reaped opportunistically first, so an idle producer does not pin a slot until the
LRU forces it. Evicting a window only drops dedup state for the least-active
producer, which then falls back to at-least-once for that producer (already the
contract for an aged/evicted id), so eviction is safe. The `producer_id` itself
is bounded by `MAX_PRODUCER_ID_LEN` = **256 bytes** (the same typed wire-boundary
rejection), so a single id cannot be the 64 KiB wire field maximum. The TOTAL
dedup memory is therefore:

```
total_dedup <= max_producers * max_ids * (2 * msg_id_len + ~2 * entry overhead)
             + max_producers * (3 * producer_id_len + ~2 * overhead)
```

At the SHIPPED defaults with the worst-case 256-byte ids, the absolute ceiling is
`4_096 * 100_000 * ~704 bytes ~= 269 GiB` (plus a few MiB of keys), which is the
honest worst case the count knobs must be lowered against for a 64 MiB edge node,
NOT a steady-state figure — and which the refuse-to-boot guard now CHARGES (#878),
so the shipped defaults provably refuse any small ceiling. The `edge-tiny` preset
therefore lowers the caps to `--dedup-max-producers 64` / `--dedup-max-ids 256`
(`64 * 256 * ~704 ~= 11 MiB`), which fits its 64 MiB ceiling. The point is that the
bound is a CLOSED formula in the three knobs, independent of how many distinct
`producer_id`s an attacker sends. The structure
is pure and IO-free (the monotonic `now` comes through the clock seam), and it
is SESSION-scoped: lost on broker restart by default, so it never grows across
restarts.

A defensive default for a 64 MiB edge box is to LOWER `--dedup-max-ids` (e.g. to
a few thousand) AND `--dedup-max-producers` (e.g. to a few hundred) when enabling
dedup, sizing the count bound to the realistic in-flight retry depth and the
producer fan-in rather than the shipped defaults; the 2-minute time bound then
caps how long any id lingers regardless.

### 7. Resident per-segment seek index (the consume read plane)

The consume read path keeps a small RESIDENT, in-memory seek index per OPEN segment
so `Log::read_from` can SEEK to a record's frame instead of re-scanning the whole
segment on every delivery
([#483](https://github.com/ELares/IronBus/issues/483),
[#537](https://github.com/ELares/IronBus/issues/537);
`crates/ironbus-storage/src/log.rs`, `SegmentIndex` / `CompactedIndex`). It is
SPARSE — Kafka's `.index` design — holding ONE `(offset, byte position)` anchor per
`SEGMENT_INDEX_STRIDE_BYTES` (**4 KiB**) of frame data, NOT one per record, so its
RAM is `O(region_bytes / stride)` **independent of the record count**:

```
per_segment_index = (max_segment_bytes / 4096) anchors x 16 bytes/anchor
edge-tiny (max_segment_bytes = 8 MiB):
                  = (8 MiB / 4 KiB) x 16 B = 2048 x 16 B = 32 KiB per resident segment
```

This matters because the index is built per OPEN segment and held while it is read,
so a slow or replaying consumer (or a follower read) can pin SEVERAL sealed segments
resident at once. A DENSE one-entry-per-record index — the pre-#537 shape — would
have cost one `u64` per record: a fully-packed 8 MiB edge segment of 36-byte frames
is ~233k records ~= **1.86 MiB** of index PER segment, scaling with the record count
and the read working set, and was UNACCOUNTED here. The sparse index replaces that
with a flat ~32 KiB/segment that does not grow as small records pack in; the read
seeks to the nearest anchor and forward-scans at most one stride (~114 minimum-size
frames), a bounded constant. Even pinning, say, 16 resident segments is ~512 KiB —
under 1% of the 64 MiB ceiling.

It is RESIDENT-ONLY and never persisted: built on first read (or seeded as the
active segment appends), EVICTED the instant a segment is retired (reap, force-reap,
compaction install), and rebuilt from the durable frames on reopen, so it adds no
on-disk format and no recovery surface. The refuse-to-boot guard does not model this
term (it is small, bounded, and not a configured buffer cap), but the per-segment
bound above lets an operator add it to a hand sizing when many segments are pinned by
a replaying consumer.

## A worked tiny-profile configuration that fits under 64 MiB

Choose edge-safe knob values so the steady-state total provably sums under the
ceiling. These are the values you would pass to `serve` (or set via the
`IRONBUS_*` env vars):

| Knob | Flag | Edge value | What it bounds |
| --- | --- | --- | --- |
| Consumer credit | `--consumer-credit` | `8` | un-acked messages per connection |
| Consumer byte budget | `--consumer-credit-bytes` | `262144` (256 KiB) | un-acked bytes per connection |
| Max connections | `--max-connections` | `32` | concurrent connections (bounds terms 1, 2, and thread stacks) |
| Max groups | `--max-groups` | `64` | live work-groups |
| Max in-flight | `--max-in-flight` | `256` | per-group delivery window |
| Max segment bytes | `--max-segment-bytes` | `8388608` (8 MiB) | DISK per segment (not RSS) |
| Dedup window depth | `--dedup-max-ids` | `256` | remembered `msg_id`s per producer (term 6) |
| Dedup producer cap | `--dedup-max-producers` | `64` | concurrently-tracked dedup windows (term 6) |

Assume a representative edge record of ~16 KiB (key + headers + payload). Then:

**Term 1, per-connection in-flight (steady state).** The byte budget binds:
`min(consumer_credit * 16 KiB, consumer_credit_bytes)
= min(8 * 16 KiB, 256 KiB) = min(128 KiB, 256 KiB) = 128 KiB` per connection
(here the message credit binds first; the byte budget is the harder backstop
for larger records). Broker-wide:

```
term1 = 128 KiB * max_connections = 128 KiB * 32 = 4096 KiB = 4 MiB
```

**Term 3, per-group state.** `max_groups * max_in_flight * ~64 bytes
= 64 * 256 * 64 bytes = 1,048,576 bytes = 1 MiB`.

**Term 4, active segment in RSS.** ~0 (written straight to file; only a
one-record scratch buffer, <= one ~16 KiB record, is transiently resident).

**Term 5, fixed overhead.** ~4 MiB (binary resident + runtime + 32 thread
stacks; estimate).

**Term 6, the opt-in dedup windows (#878).** Charged by the guard at the configured
caps regardless of whether a producer opts in at runtime (the proof is from the
config): `dedup_max_producers * dedup_max_ids * ~704 bytes = 64 * 256 * ~704 ~= 11
MiB` (plus a few KiB of producer keys).

**Steady-state total (the bounded-buffer worst case the guard sums):**

```
term1 (in-flight)      4 MiB
term3 (group state)    1 MiB
term4 (active segment) ~0
term5 (fixed)         ~4 MiB
term6 (dedup caps)    ~11 MiB
---------------------------
total                 ~20 MiB   <<  64 MiB ceiling
```

The worst case lands well under the ceiling, leaving generous headroom. (A no-dedup
workload allocates zero of term 6 at runtime, but the guard still charges the CAP, so
the caps must fit — they do here.)

### The worst-case read-buffer caveat

Term 2 (per-connection read buffers) is the one term not bounded by the credit
knobs, only by `max_connections`. Its worst case under this config is:

```
term2 worst = max_connections * (MAX_FRAME_LEN + 4 KiB)
            = 32 * (16 MiB + 64 KiB + 4 KiB)
            ~= 32 * 16.07 MiB
            ~= 514 MiB
```

This is the honest ceiling, but it is only reached if all 32 connections are
SIMULTANEOUSLY mid-assembly of a near-16-MiB frame, which an edge workload of
~16 KiB records never does (a 16 KiB frame is fully read and drained in one or
two 4 KiB chunks). To make this term provably small you must ALSO cap the
on-the-wire record size, which today means lowering `MAX_FRAME_LEN`'s effective
cap is not a `serve` knob; the practical lever remains `max_connections`. With
`max_connections = 32` and edge-sized records the realized read-buffer
residency is on the order of `32 * ~32 KiB ~= 1 MiB`, well within budget; the
~514 MiB figure is the adversarial worst case, and bounding it tightly is part
of the auto RAM-guard follow-up
([#20](https://github.com/ELares/IronBus/issues/20) /
[#117](https://github.com/ELares/IronBus/issues/117)).

### Worst case with the byte budget binding

If every connection holds its full byte budget of un-acked messages, term 1's
worst case is `consumer_credit_bytes * max_connections
= 256 KiB * 32 = 8 MiB`, plus the floor-of-one overshoot of at most one record
per connection (`32 * 16 KiB = 512 KiB`). Even fully saturated, term 1 stays
~8.5 MiB, so the steady-state budget is robust; the read buffers (term 2) are
the only term that can spike, and only under an adversarial maximal-frame load.

## The refuse-to-boot RAM guard: the worst-case formula it enforces

When `ram_ceiling_bytes` is set (`--ram-ceiling-bytes`; `edge-tiny` sets 64 MiB),
the broker REFUSES to start if the worst-case bounded-buffer footprint the
configured caps imply provably exceeds the ceiling. The footprint is a CLOSED
formula in the config (no live RSS), summing the FIRMLY-BOUNDED terms above:

```
worst_case = term1 + term3 + term4mem + term5 + term6

term1 (per-connection in-flight payloads, the firm RAM bound)
     = max_connections * per_conn_inflight
  where per_conn_inflight = consumer_credit_bytes              if it is set, else
                            consumer_credit * MAX_FRAME_LEN     if it is 0 (UNLIMITED)
term3 (per-group cursor + lease state)
     = max_groups * max_in_flight * PER_LEASE_BYTES (~64 bytes)
term4mem (the store, ONLY under --storage memory; 0 on disk)
     = IN_MEMORY_STORE_IMAGES (1, post-#492) * max_total_bytes
term5 (fixed overhead + one OS-thread stack per connection)
     = FIXED_OVERHEAD_BYTES (~4 MiB)
     + max_connections * PER_CONNECTION_STACK_BYTES (~64 KiB resident)
term6 (the opt-in per-producer dedup windows, #878)
     = dedup_max_producers * dedup_max_ids * DEDUP_ENTRY_BYTES (~704 bytes:
       each id stored TWICE — HashMap key + VecDeque slot — plus headers/slack)
     + dedup_max_producers * DEDUP_PRODUCER_KEY_BYTES (~1152 bytes)
  producer_id is wire-supplied, so the window COUNT is bounded only by the caps,
  NOT the connection count; at the shipped 4096 * 100_000 defaults this is ~269 GiB,
  so a bounded ceiling MUST lower the dedup caps (the edge-tiny preset does).
```

THE MEMORY-BACKEND STORE FOLD (#445, refs #443): on DISK the store is term 4 of
the budget above, ~0 in RSS (written straight to file), so the guard does not
charge it and the disk verdict is the historical one bit-for-bit. Under
`--storage memory` the store ITSELF is RAM: the engine retains up to
`--max-total-bytes` of stored bytes. Production `--storage memory` now runs the
single-`Vec` `EphemeralFile`/`EphemeralFs` backend (#492): ONE byte image per file,
no `live`+`durable` copy, and an O(1) no-op `sync_*`, so the true production
retained set is **~1x** `max_total_bytes`. The 2x `live`+`durable` byte image now
exists ONLY in the `InMemoryFile` crash-recovery SIMULATION (the deterministic
power-loss models), which production never runs. Post-#492 the boot guard charges
`1 * max_total_bytes` (`IN_MEMORY_STORE_IMAGES = 1`) — matching the single-image
ephemeral backend, so it no longer over-refuses a valid 1x config on a RAM-tight edge
box — and refuses a ceiling below that floor. Memory mode already refuses an unlimited (`0`)
byte cap at boot, so the store term is always finite there. The live framed resident
bytes are also available programmatically via `Log::resident_bytes_estimate()`
(#493). Two honesty caveats on `term4mem`:

- **The 2x charge is the boot guard's conservative bound, not the production
  retained set.** Production runs the 1x `EphemeralFs` backend (#492), so the guard's
  `2 * max_total_bytes` now over-charges by one image. The 2x retained set survives
  only in the `InMemoryFile` simulation, where the durable image is refreshed by
  `clone_from` inside `sync_data` and the simulated set is exactly two images per
  file at steady state (a `clone_from` realloc can briefly exceed it mid-sync). The
  guard tracks that simulation constant rather than the ephemeral 1x, on the safe
  side of the ceiling.
- **The dead-letter sink (the DLQ) is DELIBERATELY excluded.** The DLQ's log is
  byte-UNCAPPED by design (a poison record is the durable evidence of a dropped
  message and must never itself be shed), and in memory mode it lives on the
  SAME in-memory filesystem as the store, so `term4mem` bounds the MAIN log
  only. The guard's proof therefore holds for ACK-PROGRESSING workloads; a
  poison-heavy workload (consumers that never ack, so records dead-letter after
  `--max-deliver` attempts, default 5) grows RSS OUTSIDE the modeled floor.
  Capping the DLQ would shed poison evidence, a different design decision.
  Operationally: pair memory mode with consumers that make ack progress,
  monitor `ironbus_dlq_records_total`, and tune `--max-deliver`.

WHY this is PROVABLE-FROM-CONFIG and not a boot RSS guess: every term is a
CONFIGURED cap multiplied to its maximum, so the sum is the largest the bounded
buffers can ever be under that config. RSS at boot is near-zero (no connections,
no in-flight), so it predicts nothing about the steady-state ceiling the caps
imply; the guard therefore asserts only what the caps prove. A
`consumer_credit_bytes` of `0` (the byte budget OFF) has NO byte-side bound, so the
only provable bound is the message COUNT times a maximal frame, which a small
ceiling cannot fit, so such a config is honestly refused rather than waved through.

WHAT THE GUARD DELIBERATELY DOES NOT CHARGE, and why: **term 2, the per-connection
read buffer**, is bounded only by `max_connections * MAX_FRAME_LEN` (~514 MiB at
`max_connections = 32`), NOT by any credit knob, because `MAX_FRAME_LEN` is a
protocol constant, not a `serve` knob. As the worst-case-read-buffer caveat above
explains, that ~514 MiB is the ADVERSARIAL spike, realized only if every connection
is simultaneously mid-assembly of a near-maximal frame, and is explicitly NOT part
of the steady-state budget that sums under 64 MiB; bounding it tightly needs an
on-the-wire record-size cap (the read-buffer follow-up). Charging it would refuse
EVERY edge config, including the worked `edge-tiny` one this doc proves fits, so the
guard sums the firmly-bounded steady-state terms (1, 3, 5, and the config-capped
term 6, #878) the budget itemizes. For the `edge-tiny` profile the worst case is
~26 MiB (8 MiB term1 + ~1 MiB term3 + ~6 MiB term5 + ~11 MiB term6 from its LOWERED
`dedup_max_producers = 64` / `dedup_max_ids = 256` caps), well under 64 MiB, so it
boots; a blown-up `--max-connections` (or a `0` byte budget, or restoring the default
dedup caps whose ~269 GiB worst case the guard charges) pushes it over and is refused.

## What enforces this, and what does not

| Mechanism | Status in code |
| --- | --- |
| `consumer_credit` message cap | ENFORCED (`Session::handle_flow`, #65) |
| `consumer_credit_bytes` byte budget | ENFORCED (`Session::in_flight_bytes`, #275) |
| `max_connections` connection cap | ENFORCED (`serve` accept loop, #105) |
| `max_groups` group cap | ENFORCED (`EngineError::TooManyGroups`, #240) |
| `max_in_flight` per-group window | ENFORCED (`Engine::poll` window) |
| `MAX_FRAME_LEN` frame cap | ENFORCED before allocation (frame.rs) |
| `dedup_max_producers` producer-window cap | ENFORCED (LRU eviction, `DedupRegistry::make_room_for`, #33) |
| `MAX_PRODUCER_ID_LEN` / `MAX_MSG_ID_LEN` id caps | ENFORCED (typed wire-boundary rejection, `Session::handle_pub`, #33) |
| RAM ceiling refuse-to-boot guard | ENFORCED when `ram_ceiling_bytes` is set (`fits_under_ram_ceiling`, CLI `validate_ram_ceiling`, #115); `ram_headroom_bytes` then reports a real value |
| Edge `tiny` profile (`--profile edge-tiny`) | SHIPPED (#87); also sets `ram_ceiling_bytes = 64 MiB` to arm the guard |
| `mmap_max_bytes` | N/A (no mmap in storage; the `=0` tiny knob is a no-op) |
| Per-topic RAM floor + reject-on-no-budget | NOT PRESENT (single queue today) |

The refuse-to-boot guard and the edge profile are now implemented
([#115](https://github.com/ELares/IronBus/issues/115),
[#87](https://github.com/ELares/IronBus/issues/87)); the per-topic RAM floor (a
multi-queue concept) and the tighter read-buffer bound remain open
([#20](https://github.com/ELares/IronBus/issues/20) /
[#117](https://github.com/ELares/IronBus/issues/117)). For a 64 MiB node, run
`--profile edge-tiny` (which sets both the edge-safe knobs and the 64 MiB ceiling)
rather than the shipped server defaults; the guard then refuses any override that
would not fit.
