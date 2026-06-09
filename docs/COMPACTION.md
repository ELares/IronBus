# Optional key-based log compaction (the no-manifest design)

This document is the spec for IronBus's optional, opt-in, Kafka-style KEY-BASED log
compaction (#83, parent #13). It is now IMPLEMENTED (#337): the cleaner, the v2 compacted
segment format, the atomic swap, the fail-closed `version=2` bump, the overlapping-range
recovery, and the sparse-offset read path are all in the source. The implementation lives in
`crates/ironbus-storage/src/compaction.rs` (the cleaner and the trigger), the v2 format consts
and the `CompactionMeta` block in `crates/ironbus-core/src/{format,segment}.rs`, the
compacted-segment writer/reader and the overlapping-range recovery in
`crates/ironbus-storage/src/{segment,log}.rs`, and the off-hot-path wiring plus the
sparse-offset poll in `crates/ironbus-server/src/engine.rs`. It is OFF by default
(`serve --compact` / `Engine::set_compaction_config`). This doc remains the
behavior-and-contract reference; the byte layouts are in [CONTRACTS.md](CONTRACTS.md) and the
registry rows in [compat/versions.md](compat/versions.md).

It is a behavior-and-format document, not a byte-layout reference. For the exact on-disk
record, segment, and footer byte layouts see [CONTRACTS.md](CONTRACTS.md); for the file
lifecycle (active vs sealed segments, the reaper, recovery) see [WAL.md](WAL.md); for the
shared invariants (I1 to I8) see [INVARIANTS.md](INVARIANTS.md). The two frozen storage
decisions this builds on are [ADR 0001 (the active segment is the WAL)](adr/0001-log-is-wal.md)
and [ADR 0002 (v1 never recycles a segment id)](adr/0002-segments-never-recycled-in-v1.md).

Two honesty headers up front:

- **This is opt-in and edge-hostile.** Compaction is OFF by default because it costs the
  one resource an edge core cannot spare: CPU (it re-reads, key-indexes, and rewrites
  sealed segments) and flash write endurance (it rewrites survivor bytes). It is for
  changelog / state-snapshot topics where the latest value per key is the only thing that
  matters, not for a general durable queue. When enabled it is rate-limited and yields to
  the append path so it never starves a produce.
- **The issue says "atomic MANIFEST swap"; IronBus has NO manifest.** The #83 text and
  #135's sketch both assume a manifest the compactor edits. IronBus deliberately has none:
  recovery discovers segments by listing the directory and parsing self-describing file
  names (`naming.rs`: "the directory of self-describing files is the authority, no manifest
  required"). This document ADAPTS the compaction design to that model. The single atomic
  commit point is the durable appearance of the new compacted segment file, not a manifest
  entry swap. The bulk of this spec is that reconciliation, below.

---

## What compaction does

A compacted topic keeps, for each key, AT LEAST the last value, plus a bounded retention of
tombstones (null-value deletes). The cleaner reads N adjacent dirty SEALED segments, builds
a key-to-latest-offset map over them, and rewrites only the SURVIVORS (the latest record per
key, plus any tombstone still inside its `tombstone_ttl`) into a fresh segment. Every survivor
keeps its ORIGINAL log offset and original sequence; nothing is reordered, no offset is
rewritten or reused. The result is a sparse offset range: the survivors are the same records
they always were, just with the superseded records between them removed, leaving permanent
gaps.

This is the exact opposite of the reaper. The [reaper](WAL.md#retention-deleting-whole-sealed-segments)
deletes WHOLE sealed segments by age / size / count, cheaply, never looking inside. The
compactor looks inside, keeps a per-key subset, and is expensive. They compose
(see [`compact_and_delete`](#compact_and_delete-the-reaper-runs-first)).

### Survivor selection (the acceptance core)

Over the N source segments, scanned in offset order:

- **At least the last value per key.** For each distinct key, the record with the HIGHEST
  offset wins; every earlier record for that key is superseded and dropped. "At least"
  because the boundary rules below can retain more, never fewer.
- **A keyless record is never compacted away.** A record with `key_len == 0` (the
  `HAS_KEY` flag false, derived from `key_len`, per [CONTRACTS.md](CONTRACTS.md)) has no
  compaction key and is ALWAYS a survivor. Compaction is meaningful only for keyed topics;
  a keyless record on a compacted topic is carried through verbatim. (Whether to even admit
  keyless records on a compacted topic is an operator policy, not a compaction-correctness
  question; the compactor's job is to never silently drop one.)
- **Tombstones (null-value deletes) honored for `tombstone_ttl`.** A tombstone is a record
  whose value (payload) is empty for a key: it means "this key is deleted." It supersedes
  every earlier value for its key, exactly like any newer record. It is RETAINED (kept as a
  survivor) until it is older than `tombstone_ttl` (default 24h), measured against the engine
  clock seam (never the host wall clock, so the deterministic simulation drives it, per I6).
  Retaining it that long lets an OFFLINE consumer that was down come back and observe the
  delete rather than silently never seeing the key vanish. Once a tombstone has aged past
  `tombstone_ttl` AND it is still the latest record for its key, the cleaner may drop it on a
  later pass, finally reclaiming the key. A tombstone is encoded as the empty payload, NOT a
  new flag bit, so the #5 record header is untouched (the existing `payload_len == 0` carries
  it; an explicit tombstone flag bit is a possible future refinement, called out under
  [Open questions](#open-questions)).

### What compaction must NEVER do (the hard guarantees)

- **Never reorder records.** Survivors are written in ascending offset order. The single
  total order (I7-style, by offset) is preserved.
- **Never rewrite or reuse an offset.** A survivor keeps its original offset and original
  per-segment sequence verbatim. This preserves I5 (offset monotonic, never reused) at the
  record level: compaction removes offsets, it never invents or shifts one.
- **Never compact the active segment.** Only SEALED segments are ever inputs. The active
  segment is the WAL; it is being appended to and is never an input or output of a clean.
  This is the same structural rule that makes the active segment provably non-deletable
  (WAL.md), reused here.
- **Never lose a key's last value to a crash.** The originals stay authoritative until the
  single atomic commit point (below); a crash before it leaves the originals; a crash after
  it leaves the compacted segment. There is no in-place mutation, so there is no window in
  which a half-written clean is the only copy.

---

## The new compacted segment, without a manifest

Compaction's only structural novelty over the existing model is that ONE segment file can be
authoritative for an offset RANGE that the originals also cover, until the originals are gone.
A manifest is the usual way to record "this file now owns offsets [a, b)". IronBus has none,
so the new segment must DECLARE its own coverage in its self-describing metadata (a COMPACTED
marker in the header plus a covered-range block in the footer region, below), and recovery
must resolve an overlap deterministically from the files alone.

### A compaction marker in the header, the covered range in a v2 footer block

A compacted segment is a normal segment (the [SegmentHeader](CONTRACTS.md) / record-frame /
[SegmentFooter](CONTRACTS.md) format is unchanged in SHAPE) with two additional facts it
records, in two different places chosen so each fact lives where it fits and is
CRC-protected:

- a **compaction marker** in the header (this segment is the output of a clean, not a fresh
  roll), and
- the **covered range**, in a dedicated v2 compaction-metadata block appended after the sealed
  footer (not in the header): the covered offset span
  `[covered_base_offset, covered_end_offset)` and the parallel covered SEQUENCE span
  `[covered_base_seq, covered_end_seq)` of the ORIGINAL source segments this compacted segment
  supersedes (both spans are needed because recovery checks offset AND sequence continuity, see
  the chain check below), plus the highest covered source segment id so recovery can name
  exactly which original files this one replaces.

**Why the covered range does NOT go in the header reserved bytes.** The earlier sketch put
the covered range in the header's 16-byte reserved region `[44, 60)`. That region is NOT
free: [AT_REST_ENCRYPTION.md](AT_REST_ENCRYPTION.md) already assigns `[44, 60)` to the at-rest
`aead_suite` u8 plus a `key_id` (the rest reserved-zero), and a compacted segment can ALSO be
encrypted (this spec re-encrypts every survivor under the new segment id below, so a compacted
segment is a normal candidate for at-rest encryption). A segment that is BOTH compacted AND
encrypted cannot put both the at-rest fields and the covered range in the same 16 bytes.
Worse, the covered range is more than two fields: `covered_base_offset` is its OWN field (see
the next subsection, not an alias of `base_offset`), and the parallel `base_seq` continuity
forces a covered SEQUENCE span too, so even the offset-only covered range (3 `u64`s = 24 bytes)
does not fit a 16-byte region at all, and the full covered range is larger still. So
`[44, 60)` stays owned by at-rest encryption, and the covered range moves out of the header
entirely.

**Where the covered range lives: a v2 compaction-metadata block in the footer region.** A
compacted segment is born SEALED (it is never the active segment), so it always carries a
[SegmentFooter](CONTRACTS.md), written once at seal time. The version=2 format defines a
compaction-metadata block that a compacted segment writes immediately AFTER the standard
32-byte footer, as the file's final bytes, CRC-protected on its own:

| offset (from block start) | field | type | notes |
|---|---|---|---|
| `[0, 8)`   | `covered_base_offset` | u64 | the source set's TRUE starting offset (see below) |
| `[8, 16)`  | `covered_end_offset`  | u64 | one past the highest covered SOURCE offset |
| `[16, 24)` | `covered_base_seq`    | u64 | the source set's TRUE starting sequence (parallel to `covered_base_offset`) |
| `[24, 32)` | `covered_end_seq`     | u64 | one past the highest covered SOURCE sequence |
| `[32, 40)` | `highest_covered_source_id` | u64 | the highest segment id this clean supersedes (the recovery tie-break) |
| `[40, 44)` | `block_crc` | u32 | CRC32C over `[0, 40)` of this block |

The block is 44 bytes, written and fsynced as part of the same seal that writes the footer, so
it is durable at the same instant the footer is (the footer and this block are one contiguous
trailing write). It is self-validating exactly like the footer: a reader of a `version` = 2
segment reads the trailing block, checks `block_crc`, and rejects a torn or mismatched block
the same way a torn footer is rejected, so a half-written compacted segment never parses as a
valid compacted segment (it falls into the crash-before-commit case below). The standard
32-byte footer is UNCHANGED in layout (segment id, last seq, record count, its own
`footer_crc` over `[0, 28)`); v2 only appends the 44-byte block after it. Nothing in the
header reserved region `[44, 60)` is touched, so a compacted-AND-encrypted segment has room
for BOTH: the at-rest `aead_suite` + `key_id` in the header `[44, 60)`, and the covered range
in the footer-region block.

**The only header change is one flag bit.** The header's `flags` u16 at `[10, 12)` (inside the
CRC-covered bytes `[0, 60)`) gains ONE bit, `COMPACTED` (a distinct bit from the at-rest
`SEGMENT_ENCRYPTED` bit, so the two never collide and a segment may set both). The header
reserved bytes `[44, 60)` are NOT used by compaction. The CRC at `[60, 64)` still covers the
flag bit for free.

- **Honesty: this is a format change, and it is gated by the format version.** A v1 reader
  treats `flags` as "preserved but not interpreted" and would not even look for a trailing
  compaction-metadata block. A v1 reader that encountered a COMPACTED segment would IGNORE the
  marker and the covered range and try to stitch the segment into the contiguous chain as if
  it were ordinary, which (because survivors are sparse) would fail the chain check or, worse,
  deliver a wrong view. So a compactor-writing broker MUST stamp the segment header `version`
  = 2 (a format-version bump) on compacted segments AND stamp the same `version` = 2 in the
  footer (the footer carries its own `version` byte, per [CONTRACTS.md](CONTRACTS.md), so the
  trailing block is version-gated there too), and a v1 reader MUST refuse a `version` it does
  not know (it already does: "a v1 reader rejects any other value" for `checksum_algo`, and
  `version` is refuse-on-unknown per [COMPATIBILITY.md](COMPATIBILITY.md)). This is the
  correct, fail-closed outcome: an old reader refuses a compacted log rather than silently
  misreading it. The format-version bump, the COMPACTED flag bit, and the v2
  compaction-metadata block are coordinated with the frozen #5 header / #5 footer and
  [ADR 0001](adr/0001-log-is-wal.md); they must be registered as the v2 on-disk delta in
  [COMPATIBILITY.md](COMPATIBILITY.md) and the byte layouts added to
  [CONTRACTS.md](CONTRACTS.md) when implemented.

### `covered_base_offset` is the source set's TRUE start, its own field

`covered_base_offset` is NOT `base_offset` (the lowest survivor's offset). They differ exactly
when the first source segment's LEADING records are all superseded: the lowest survivor's
offset is then strictly greater than the source set's true starting offset. If recovery used
`base_offset` as the covered start, the span `[predecessor_end, lowest_survivor_offset)` would
be left UNCOVERED, a gap that the chain-continuity check (below) would reject. So
`covered_base_offset` is defined as the source set's TRUE starting offset, the lowest covered
SOURCE offset (equivalently, the predecessor segment's end / where this compacted segment must
abut its predecessor in the chain), independent of which survivor happens to be lowest. It is
its own field in the compaction-metadata block, carried explicitly, never derived from
`base_offset`. `covered_end_offset` is symmetric: one past the highest covered SOURCE offset
(which, because the last source record is always a survivor of its own key unless tombstoned,
typically coincides with the last survivor's offset + 1, but is recorded as the source span,
not inferred). `highest_covered_source_id` is the highest segment id in the source set, used
only as the deterministic tie-break in recovery rule 3 below.

### Why the covered range, not a manifest, is enough

Recovery already discovers every `seg-<id>.log`, parses its self-describing header, and
stitches a chain by `base_offset`. A compacted segment self-describes BOTH its own survivor
records (header) AND the original offset/sequence span it stands in for (the v2 footer block).
That is exactly the information a manifest entry would have carried ("offsets [a, b) now live
in file X"), only it lives in the file that owns the range rather than in a separate mutable
index. The directory remains the single authority; we have added self-describing facts to one
file, which is the existing design philosophy, not a new structure.

---

## The atomic swap, without a manifest

The clean is a write-new-then-retire-originals sequence whose SINGLE commit point is the
durable appearance of the new compacted segment. The originals stay authoritative until that
instant; afterwards they are redundant and removed with the existing rename-then-unlink reaper
discipline so an open reader drains rather than reading freed bytes.

The compactor's new segment id is a FRESH id strictly greater than any id ever used (ADR 0002:
ids are never recycled, the at-rest AEAD nonce depends on it). So a compacted segment that
covers a LOW original offset range nonetheless carries a HIGH segment id. The id no longer
sorts with its offset range (the one place the "id order equals offset order" assumption is
deliberately broken), which the recovery resolution below accounts for explicitly.

### The sequence

1. **Select.** Pick N adjacent dirty sealed source segments whose combined dirty ratio is at
   or over `min_dirty_ratio` (default 0.5: at least half the records are superseded, so the
   rewrite pays for itself). Never the active segment.
2. **Build the key map.** Scan the N segments in offset order (streaming, one record at a
   time, peak memory one record plus the key map; the key map is the cost line that bounds how
   many segments N can be on an edge core). Record, per key, the highest-offset survivor; track
   tombstones and their ages.
3. **Write the new segment.** Create `seg-<fresh-id>.log`, write its header (`version` = 2,
   COMPACTED flag set; `base_offset` = the lowest survivor's offset, as for any segment; the
   header reserved bytes `[44, 60)` left for at-rest encryption), then the survivors in
   ascending offset order with their ORIGINAL offsets and sequences, then the
   [SegmentFooter](CONTRACTS.md) (`version` = 2), then the 44-byte v2 compaction-metadata block
   (`covered_base_offset`, `covered_end_offset`, `covered_base_seq`, `covered_end_seq`,
   `highest_covered_source_id`, `block_crc`) as the file's final bytes. `fsync` the file, then `fsync` the parent directory so the new
   file's directory entry is durable. THIS DIRECTORY FSYNC IS THE ATOMIC COMMIT POINT: before
   it, the new segment may not survive a power loss and the originals are authoritative; after
   it, the compacted segment is durably present and authoritative for its covered range. The
   footer and the trailing block are one contiguous final write, so they become durable
   together; a crash that leaves a torn block (failing `block_crc`) is indistinguishable from a
   crash before the commit, and recovery treats it as such.
4. **Retire the originals.** For each covered source segment, `rename` it out of the way (to a
   transient name a reader will not pick up, e.g. a `.compacting` suffix that
   `parse_segment_file_name` rejects, so it instantly leaves the recoverable set) then
   `unlink` it, then `fsync` the parent directory. Rename-then-unlink, not a bare unlink, so a
   reader still holding an open handle to an original drains its bytes (the file stays on disk
   until the handle closes) and never reads freed data. A reader that has not yet opened the
   original simply will not find it (the rename removed it from the namespace), and falls
   through to the compacted segment.

A produce can interleave at every step: the cleaner yields to the append actor (below), and
because the cleaner only ever touches SEALED segments and writes a NEW file, an append to the
ACTIVE segment never races a clean for the same bytes.

### Crash recovery: longest-valid-prefix, no compaction-specific repair

The acceptance criterion is that a crash before OR after the swap recovers via the existing
longest-valid-prefix recovery with NO compaction-specific repair step. It does, because the
two crash windows each leave the directory in a state ordinary recovery already resolves, plus
two small, generic resolution rules:

- **Crash BEFORE the commit point (step 3 not durably complete).** The new compacted segment
  is either absent or a torn/partial file. The originals are all still present and still
  authoritative. Recovery: the originals form the normal contiguous chain and recover exactly
  as today. The orphan new segment is DISCARDED: it is a COMPACTED segment whose covered range
  is ALREADY fully present as original segments, so it is redundant; recovery unlinks it (the
  generic "an authoritative-elsewhere compacted segment is dropped" rule). If it was torn
  (header not even fully written), it never parsed as a segment at all. Either way: no special
  repair, the originals win.
- **Crash AFTER the commit point but during retire (step 4 partway).** The compacted segment
  is durably present; SOME originals are gone, some remain (renamed-aside or not yet
  unlinked). Recovery: the compacted segment is authoritative for its covered range. Any
  original still present whose offset range is FULLY covered by a durable compacted segment is
  UNREFERENCED and recovery unlinks it (the generic "an original superseded by a durable
  compacted segment is removed" rule), and any leftover `.compacting`-suffixed transient is
  removed (it parses as no segment, so it is foreign and skipped, then garbage-collected). The
  compacted segment plus any not-yet-covered originals form the chain.

Both rules are generic file-set reconciliations driven entirely by the segment's
self-describing metadata (the COMPACTED flag in the header and the covered range in the v2
footer block), not a replay of a compaction journal. There is no
manifest to be torn, so there is no torn-manifest recovery case. The recovery loss caps (I3,
bounded reported loss) are unaffected: a discarded orphan compacted segment is not a loss (its
data is fully present in the originals), and an unlinked superseded original is not a loss (its
surviving records are present in the compacted segment); neither path emits a `LossReport`
event, because no durable record was actually lost.

### Determining overlap deterministically without a manifest

When two files cover the same offset (a compacted segment and an as-yet-unretired original),
recovery must pick ONE deterministically. The rule, in order:

1. **Group the discovered segments into ordinary and compacted** (by the COMPACTED flag).
2. **A compacted segment is authoritative over every original whose offset range it fully
   covers.** Concretely: an ordinary segment whose `[base_offset, base_offset + record_count)`
   is fully inside some compacted segment's `[covered_base_offset, covered_end_offset)` is
   superseded; recovery drops it.
3. **Two compacted segments never partially overlap.** A clean always covers a contiguous run
   of WHOLE source segments, and the next clean's source set starts at the previous clean's
   covered end (or a later offset), so covered ranges are disjoint and abut. If a future crash
   somehow leaves two compacted segments with overlapping covered ranges, the one with the
   HIGHER segment id (the later clean, by ADR 0002 monotonicity) wins and the lower is dropped
   as superseded. This is the single tie-break, and it is total because ids are monotonic and
   never reused.
4. **After dropping superseded originals, the surviving set (compacted segments plus
   uncompacted originals) must stitch into one offset-contiguous-at-the-segment-boundary
   chain.** Note the chain is contiguous at SEGMENT boundaries (each segment's covered or
   actual range abuts the next), even though offsets WITHIN a compacted segment are sparse.
   This is the one place the recovery chain check must change: today
   `scan_recover_chain` requires BOTH `base_offset == next_base_offset` AND
   `base_seq == next_base_seq` exactly (it advances `next_base_seq = base_seq + record_count`
   in lockstep with the offset half) and every non-final segment sealed; with compaction the
   predecessor's offset "end" is its `covered_end_offset` (for a compacted segment) or
   `base_offset + record_count` (for an ordinary one), and a compacted segment's record
   offsets are not dense. The offset continuity check becomes "the next segment's
   covered/actual base equals the previous segment's covered/actual end," which reduces to the
   current check for an all-ordinary log.
   - **The `base_seq` half must change in parallel.** Survivors keep their ORIGINAL, now-sparse
     sequences, exactly as they keep their original offsets, so a compacted segment's record
     count is smaller than its covered sequence span and `next_base_seq = base_seq +
     record_count` no longer lands on the next segment's `base_seq`. The compaction-metadata
     block therefore also pins the covered SEQUENCE span so recovery can advance the sequence
     expectation by the covered span (not the survivor count) across a compacted segment, the
     same way it advances the offset expectation by `covered_end_offset`. Concretely the v2
     block carries `covered_base_seq` and `covered_end_seq` (the source set's true starting and
     one-past-ending sequence) alongside the offset span, and the chain-continuity check
     compares the next segment's covered/actual base sequence to the previous segment's
     covered/actual end sequence. For an all-ordinary log both halves reduce to today's exact
     `base_offset`/`base_seq` checks.

Because each step is a pure function of the self-describing headers in the directory, recovery
is still deterministic and still a pure function of the durable bytes (I4). The id is no
longer a proxy for offset order (a compacted segment has a high id but a low covered range), so
recovery sorts the resolution by COVERED/ACTUAL OFFSET RANGE, not by id, and uses the id only
for the monotonic tie-break in rule 3.

---

## Sparse offsets at the reader (coordinating with #9 and #59)

Compaction makes the durable log SPARSE: between two survivors there is a permanent hole where
superseded records used to be. This is a real change to a contract the current read path
assumes, and the spec is honest about it.

- **The current read path assumes dense offsets.** `Engine::poll` walks offsets one by one
  (`offset += 1`) and `Log::read_from(off, 1)` expects a record at every offset below the
  flushed head (the `MissingRecord` "unreachable" arm). The offline reader asserts "offsets are
  contiguous." A compacted log violates all three: a compacted-away offset has no record. So
  sparse-offset tolerance is a NEW requirement compaction introduces, not an existing
  property.
- **The reader skips a compaction gap; it is NOT a loss.** When the reader reaches an offset
  that was compacted away, it ADVANCES to the next present offset rather than stalling or
  reporting `MissingRecord`. The index (the in-memory sorted `SegmentSlot` list plus the
  per-segment record positions) must let a read FIND the next present offset at or after a
  target, so the read path seeks forward over a gap in O(log n) rather than probing every
  absent offset. Inside a compacted segment, the records are physically contiguous (the gaps
  are between original offsets, not in the file), so a sequential scan of the compacted segment
  naturally yields the survivors in order; the gap only appears when mapping file position to
  logical offset.
- **The gap marker is the #59 sparse-offset contract, with a DISTINCT, non-loss reason.** #59
  already defines sparse, stable offsets with an explicit gap marker delivered to the #9
  consumer (a skip range `[lost_offset_start, lost_offset_end)` with a reason code). Compaction
  reuses that machinery for the consumer-visible gap, BUT the reason is a new, deliberate one:
  a compaction gap is NOT data loss (the superseded values were intentionally removed and a
  newer value for the key exists), unlike the recovery loss reasons
  (`TornTail`, `CorruptRecordHeader`, `CorruptRecordBody`, `CorruptSegmentHeader`,
  `SequenceGap`, per `loss.rs`) which ARE loss-or-truncation and EACH emit a `LossEvent` with
  a non-zero `bytes_skipped` that the loss-bytes counters sum (including `TornTail`, the
  expected power-loss truncation, which is reported, not excluded). So compaction adds a
  `Compacted` skip reason that is NOT a recovery loss reason at all: it never produces a
  `LossEvent` or `LossReport` and so never touches the loss-bytes counters, because no durable
  record was lost. It is purely a consumer-facing #59 SkipEvent reason, and a consumer that
  wants the latest-value-per-key view can simply ignore a `Compacted` gap marker entirely.
  This must be agreed with #9 and #59 when implemented; the honest statement is that compaction
  turns "every offset below the head has a record" from an invariant into "every offset below
  the head has a record OR a recorded compaction gap."
- **A consumer cursor is unaffected by a gap.** The committed cursor is a watermark over
  ACKED offsets; a compacted-away offset is treated as already-satisfied (there is nothing to
  deliver), so the cursor advances past the gap exactly as if those offsets had been acked.
  This is distinct from the below-earliest TRUNCATION signal (`Poll::Truncated`, WAL.md), which
  fires when a reaper deletes records UNDER a cursor; a compaction gap is above-or-at the
  cursor and is a normal forward skip, not a truncation. The engine surfaces the forward skip as
  the distinct `Poll::Compacted { from, to }` (#411), which the session maps to
  `GapMarker(reason = COMPACTED)` for a gap-marker-capable consumer and swallows silently for a
  non-capable one. The two signals stay separate.

---

## `compact_and_delete`: the reaper runs first

A compacted topic can ALSO have age / size / count retention (`compact_and_delete`, the Kafka
`cleanup.policy=compact,delete`). The order is fixed and load-bearing: the cheap age/size/count
REAPER runs FIRST, then the compactor. Two reasons:

- **Never compact a segment we are about to delete.** If the reaper is going to drop the oldest
  sealed segments wholesale (they aged out, or the byte/count cap is over), spending CPU and
  flash to compact them first is pure waste. Reaping first means the compactor only ever sees
  segments that survived retention.
- **The reaper is whole-segment and consumer-safe; the compactor is intra-segment.** The
  [reaper](WAL.md#retention-deleting-whole-sealed-segments) deletes whole sealed segments below
  the slowest-consumer protect floor. Running it first keeps that simple, cheap, consumer-safe
  path unchanged and unblocked by the expensive compactor.

So `compact_and_delete` is: run `Engine::reap_for_retention` (the existing produce-path reaper)
to completion, THEN, if compaction is enabled and a dirty run meets `min_dirty_ratio`, run one
rate-limited compaction pass. Pure `compact` (no delete) skips the reaper step. Pure `delete`
(no compact) is exactly today's behavior.

---

## The cleaner is rate-limited, yields to appends, and is OFF by default

On a single edge core an unthrottled cleaner would starve the append path (it does CPU-bound
key-mapping and flash-bound rewriting). The cleaner is therefore:

- **OFF by default.** No compaction runs unless an operator opts a topic in. The default
  durable-queue behavior (append, seal, reap whole segments) is unchanged. (IronBus has one
  durable log per broker today, so "compacted topic" is a per-broker policy until multi-topic
  lands; the opt-in is a `serve` flag plus the `min_dirty_ratio` / `tombstone_ttl` knobs.)
- **Rate-limited.** A compaction pass does a BOUNDED amount of work (at most N source segments,
  N small enough that the key map fits the edge RAM budget per
  [RAM_BUDGET.md](RAM_BUDGET.md)), then stops and re-checks `min_dirty_ratio` before another
  pass. There is no continuous background grind; a pass is event-driven (on a seal that pushes a
  dirty run over the ratio) plus a coarse interval, both rate-capped.
- **Yields to the append path.** The append actor (the single writer, WAL.md) always wins. The
  cleaner runs OUTSIDE the append actor's critical section (it reads sealed segments, which the
  actor never touches, and writes a new file, never the active one), and its directory fsyncs
  are scheduled so they never sit in front of a produce's covering fdatasync. A produce is never
  blocked behind a compaction fsync; if the cleaner and a produce contend for the disk, the
  produce's durability barrier takes priority and the cleaner backs off. The bounded
  `sync_channel` to the append actor (WAL.md) is the backpressure seam: the cleaner submits its
  work without ever holding a lock the actor needs.

---

## Honest limits and what is deliberately deferred

- **Implemented (#337, #411).** The COMPACTED header flag, the v2 compaction-metadata footer block,
  the covered-range recovery rules, the sparse-offset read/skip path (a reader and the engine
  poll skip a compacted hole), the `Compacted` gap-reason CODE (`gap_reason::COMPACTED = 2`), the
  cleaner, AND (since #411) the consumer-facing EMISSION of `GapMarker(reason = COMPACTED)` when a
  gap-marker-capable consumer reads across a compacted hole are all built. The engine surfaces the
  skip as a `Poll::Compacted { from, to }` (the interior, sparse-offset twin of the below-earliest
  `Poll::Truncated`), and the session maps it to a `GapMarker` with the exact `[from, to)` span and
  `reason = COMPACTED` for a gap-marker-capable consumer; a NON-capable consumer keeps the silent
  cursor-advance (a compacted hole is not a loss, so it gets no frame and never the legacy
  `Truncated`), so the wire format is unchanged and only the already-defined reason is now emitted.
  What is still deliberately DEFERRED as a safe follow-up (the core is complete): the advanced
  `min_dirty_ratio` BYTE accounting (count is shipped; bytes is the better flash-cost proxy, an open
  question below), a standalone `ironbus compact` CLI verb (the off-hot-path engine pass and the
  `serve --compact` knob are shipped), and the explicit TOMBSTONE flag bit (the empty-payload
  convention is shipped). None of those affect the crash-safety or the format, which are complete
  and correct.
- **It costs CPU and flash; it is for changelog topics only.** Stated up front; restated here.
  A general durable queue should leave it OFF.
- **It forces a format-version bump.** A broker that has ever written a compacted segment
  produces a v2-header log that a v1-only reader correctly REFUSES (fail-closed) rather than
  misreads. This is a real compatibility consequence, owned by [COMPATIBILITY.md](COMPATIBILITY.md).
- **The id no longer tracks offset order for compacted segments.** A compacted segment has a
  high id but a low covered range; recovery resolves by covered/actual offset range and uses the
  id only as the monotonic tie-break. ADR 0002 (never recycle) is preserved and is in fact
  relied on for that tie-break.
- **A compacted segment can also be encrypted; the two specs partition the header cleanly.** A
  compacted segment is a normal candidate for at-rest encryption, and the two features do not
  collide: at-rest encryption owns the header reserved bytes `[44, 60)` (`aead_suite` + `key_id`)
  and the `SEGMENT_ENCRYPTED` flag bit; compaction owns a DIFFERENT flag bit (`COMPACTED`) and
  the v2 compaction-metadata block in the footer region, and touches none of `[44, 60)`. So a
  compacted-AND-encrypted segment has room for BOTH sets of fields. And the at-rest AEAD nonce
  (segment-id || record counter, per [AT_REST_ENCRYPTION.md](AT_REST_ENCRYPTION.md)) stays
  unique for the rewritten survivors: because the compacted segment gets a FRESH never-recycled
  id (ADR 0002), each survivor is re-encrypted under the new segment's id, not its old one, so
  no nonce is reused. This header partition and the nonce interaction are pinned in the
  encryption spec when both are implemented.

### Open questions

- Whether to add an explicit TOMBSTONE record flag bit (vs the implicit empty-payload
  convention), which would let the reader recognize a delete without inspecting the payload
  length. Deferred; the empty-payload convention is enough for the compactor and keeps the #5
  header untouched at the record level (only the segment header gains the COMPACTED flag).
- The exact `min_dirty_ratio` accounting (dirty = superseded record count, or superseded
  bytes). Bytes is the better flash-cost proxy; pinned at implementation.
- Whether a single broker grows multi-topic before compaction ships (compaction is most useful
  per-topic). Until then it is a per-broker opt-in.

---

## Where this is verified

- Survivor selection (last-value-per-key, tombstone TTL, keyless carry-through, no reorder, no
  offset rewrite): `crates/ironbus-storage/src/compaction.rs` unit tests
  (`compaction_keeps_latest_per_key_at_original_offsets_drops_superseded`,
  `a_tombstone_within_ttl_is_kept_then_dropped_when_aged_out`).
- Crash-before / crash-after the commit point recovering via longest-valid-prefix with no
  special repair: `crates/ironbus-storage/tests/compaction_crash.rs`, injecting a `sync_dir`
  failure at the directory fsync (the commit point) and mid-retire via the fault fs, asserting
  the originals win before (`crash_before_the_commit_point_keeps_the_originals`) and the
  compacted segment wins after (`crash_after_the_commit_during_retire_keeps_the_compacted_set`),
  with no `LossReport` event either way, and that before-vs-after recover IDENTICALLY
  (`recovery_is_identical_whether_the_crash_was_before_or_after_a_full_retire`).
- The v2 fail-closed bump: a v1-only reader REFUSES a compacted segment on disk
  (`a_v1_only_reader_fails_closed_on_a_compacted_segment_on_disk`, plus the core
  `a_v1_only_reader_fails_closed_on_a_compacted_header`). A v1 segment is byte-identical
  (`a_non_compacted_header_is_byte_identical_to_v1`).
- Open readers never read freed data during retire: the in-memory disk keeps an open handle's
  inode alive after the unlink-then-dir-fsync (the same discipline the reaper already uses), so a
  drained read never reads freed bytes.
- Sparse-offset read / skip-the-gap (never a recovery `LossEvent`, so never in the loss-bytes
  counters): the storage read path skips an absent offset, and the engine poll advances the cursor
  past a compacted hole (`compaction_off_by_default_and_opt_in_skips_holes_on_poll` in
  `crates/ironbus-server/src/engine.rs`, which now also asserts the poll surfaces a
  `Poll::Compacted { from, to }` for each hole).
- Consumer-facing COMPACTED emission (#411): a gap-marker-capable consumer reading ACROSS a
  compacted hole receives EXACTLY ONE `GapMarker(reason = COMPACTED)` with the exact `[from, to)`
  span, never a `Truncated` and never a loss
  (`a_gap_marker_consumer_reading_across_a_compacted_hole_gets_one_compacted_marker` in
  `crates/ironbus-server/src/session.rs`); a NON-capable consumer reading the SAME compacted log
  advances SILENTLY with no marker and no error
  (`a_non_capable_consumer_reading_across_a_compacted_hole_advances_silently`). The reason is correct
  by construction: the interior compacted hole is the distinct `Poll::Compacted` (above
  `earliest_retained`, segment present), structurally separate from the below-earliest trim that
  returns `Poll::Truncated`. The wire format is UNCHANGED: only the already-defined
  `gap_reason::COMPACTED` is now emitted.
- The cleaner off by default and off the hot path: the same engine test asserts a produce that
  triggers a compaction pass returns its offset normally (the append is never blocked), and that
  no v2 segment is written until an operator opts in.
