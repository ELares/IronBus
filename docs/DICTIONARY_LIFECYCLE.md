# Trained per-type dictionary lifecycle (the self-contained-distribution design)

This document is the lifecycle spec for IronBus's trained per-message-type compression
dictionaries (#78, parent #12). It is now IMPLEMENTED behind the OPT-IN `zstd` Cargo feature
(#357). The on-disk compression runtime for the default `lz4` codec landed first (#387,
`crates/ironbus-core/src/compress.rs`): the self-describing descriptor carries the `dict_id`
field (§8), the `DictResolver` SEAM (§3, §4) is in place, and an unresolved `dict_id` is the
bounded POISON class routed to #8 as `ReasonCode::UnresolvedDictId` (§5,
`crates/ironbus-storage/src/loss.rs`). The zstd-specific machinery is now IMPLEMENTED behind
the opt-in `zstd` feature per [ADR 0003](adr/0003-default-compression-lz4-zstd-opt-in.md): the
zstd codec id 2 (`ironbus_core::compress`, with the same decompression-bomb cap and
corrupt-never-panics resilience as `lz4`), the `ZDICT` training call + the content-addressed
`dict_id` (`ironbus_core::dict`, §1, §2), the sidecar-IO write/read + the content-validated
resolver (`ironbus_storage::dict_store`, §3, §4), the measured before/after ratio (§7), and the
`ironbus dict` train/install/ls CLI. On the DEFAULT (non-zstd) build none of this is compiled:
every frame is written with `dict_id = 0` (no dictionary), and a record carrying the zstd codec
id is read as UNKNOWN-codec POISON, never a crash, so the default binary stays pure Rust and
byte-for-byte unchanged. The `include_bytes!` build-time embed of an active set (§3b) is the
one remaining residual: the runtime sidecar (the primary, binary-independent copy) and the
resolver's embedded-set seam (`CachingDictResolver::add_embedded`) are implemented; wiring a
`build.rs` to compile `dicts/active/` into the binary is a follow-up.

It is a lifecycle-and-format document, not a byte-layout reference. For the exact on-disk
record, segment, and footer byte layouts see [CONTRACTS.md](CONTRACTS.md) and the
[record-layout diagram](diagrams/04-record-layout.pdf); for the recovery loss-report schema
this design routes an unresolved dictionary through see
[schemas/loss-report.v1.md](schemas/loss-report.v1.md); for the corruption / quarantine path
see [INVARIANTS.md](INVARIANTS.md) (I3 bounded-and-reported loss); for the single-binary embed
story see [DISTRIBUTION.md](DISTRIBUTION.md). The two frozen decisions this builds on are
[ADR 0003 (lz4_flex is the default codec, zstd is opt-in)](adr/0003-default-compression-lz4-zstd-opt-in.md)
and the frozen `ironbus.loss-report.v1` reason-code vocabulary.

## Three honesty headers up front

- **Deferred from v1 on purpose, and ADDITIVE.** #78 is deliberately deferred: a
  referenced-but-absent dictionary is permanently undecodable data, so dictionaries land
  ONLY once the distribution story below is real. The v1 frame already RESERVES the dict_id
  INTERPRETATION behind the COMPRESSED flag (Section 8): the dict_id is not a physical reserved
  header field, it is a value carried only inside a compressed payload's descriptor, which v1
  never writes. So this is additive with NO wire-format break and NO on-disk format break. A v1 reader and a future dictionary-aware reader interpret a v1 frame identically.
- **This spec is NOT the `ZDICT` implementation.** IronBus runs a deliberately minimal
  dependency graph: per [ADR 0003](adr/0003-default-compression-lz4-zstd-opt-in.md) the
  default codec is pure-Rust `lz4_flex` and zstd (`zstd-sys`, vendored C) is opt-in only,
  behind an explicit feature, never on the default path. Trained dictionaries are a zstd
  feature, so the whole of this design is gated behind that opt-in zstd feature. Adding the
  `ZDICT` training API (the C `ZDICT_trainFromBuffer`) is an IMPLEMENTATION-phase decision and
  is explicitly OUT OF SCOPE here. This document specifies the lifecycle around that call so
  the call itself is the only residual.
- **lz4_flex does not consume a trained dictionary.** Trained dictionaries are a zstd
  capability. On the default pure-Rust path (lz4_flex) a frame is written with `dict_id = 0`
  (no dictionary). A dictionary-bearing frame is therefore always a zstd frame, only produced
  when the operator has opted into the zstd feature AND configured a dictionary.

---

## 1. Training: the `ironbus dict train` subcommand

Training is an OFFLINE operator action run with the same single static binary as the broker
and the rest of the CLI (#15), so an operator needs no extra tool. It is a new subcommand
under a `dict` group, alongside the future `dict ls` / `dict show`:

```sh
ironbus dict train \
  --type sensor.telemetry.v1 \
  --samples /var/lib/ironbus/dict-samples/sensor.telemetry.v1/ \
  --target-dict-bytes 112640 \
  --out /var/lib/ironbus/dicts/
```

### Inputs (the per-type sample corpus)

- `--type <message-type>`: the message-type identity the dictionary is trained FOR. A
  dictionary is per message type, because the cross-record redundancy a dictionary captures
  (shared keys, shared schema, shared field names and units) lives WITHIN one type, not
  across unlike types. The type string is metadata for the operator and the report; it is NOT
  embedded in the dict_id (the dict_id is content-addressed, Section 2).
- `--samples <dir>`: a directory of raw, UNCOMPRESSED sample records of that one type, one
  record per file (or an NDJSON/length-prefixed corpus the trainer splits). The records are
  REAL telemetry captured from the topic, not synthetic, so the dictionary learns the actual
  payload distribution. A future `ironbus dict sample --type <t> --topic <t> --count N` verb
  can collect this corpus from a live or on-disk topic via the offline reader (#15); for v1 of
  this design the corpus is operator-supplied.
- Sample-count bounds (enforced by the trainer, fail-closed):
  - `MIN_SAMPLES = 1000`. `ZDICT_trainFromBuffer` is documented to need roughly a few thousand
    samples to produce a useful dictionary; below the floor the trainer REFUSES with a usage
    error rather than emitting a weak dictionary. The floor is a documented safe default,
    tunable via `--min-samples` for an operator who knowingly accepts a smaller corpus.
  - `TARGET_SAMPLES = 10000` (the recommended corpus size the operator flow aims for; advisory,
    surfaced as a warning below it, not a hard floor).
  - The trainer also requires the corpus to span at least `MIN_DISTINCT_BYTES` of total sample
    bytes, so 1000 identical records do not pass the count floor while carrying no diversity.

### Output (the dictionary bytes)

- `--target-dict-bytes <n>`: the requested dictionary size, default `112640` (110 KiB, zstd's
  own `ZDICT` default). The dictionary is a single opaque blob of bytes: a zstd dictionary is
  a prebuilt set of entropy tables plus a synthetic "past" the compressor seeds its window
  with, which is exactly why it works from the first few hundred bytes where an unprimed LZ77
  window finds nothing.
- The trainer writes the dictionary to `--out <dir>` as `dicts/<dict_id>.zstd` (Section 3),
  where `<dict_id>` is the content-hash id computed in Section 2. It also prints a structured
  `--json` record (type, dict_id, dict_bytes, sample_count, sample_bytes) for the operator's
  records; the type-to-dict_id mapping is the operator's to keep (there is NO central registry,
  Section 2).

### The operator flow (end to end)

1. Capture a per-type sample corpus from real telemetry (operator-supplied, or via a future
   `dict sample`).
2. Run `ironbus dict train --type <t> --samples <dir>`; the trainer validates the corpus
   against the count and diversity floors, runs the training, computes the content-hash
   dict_id, and CHECKS FOR A COLLISION against the dictionaries already in `--out` (Section 2).
3. The trainer emits `dicts/<dict_id>.zstd` and the JSON summary.
4. The operator configures the broker to USE that dict_id for that message type via the #14
   compression-dictionary config surface (the `[compression.dictionary]` block #12 sketched).
   The broker embeds the active set at build time (Section 3) and writes the sidecar at
   runtime (Section 3).

**IMPLEMENTED (#357, opt-in `zstd` feature):** the `ZDICT_trainFromBuffer` call is
`ironbus_core::dict::train_dictionary` (via the `zstd` crate's `zdict_builder` feature),
enforcing the `MIN_SAMPLES` / `TARGET_SAMPLES` / `MIN_DISTINCT_BYTES` floors fail-closed; the
operator surface is `ironbus dict train --type <t> --samples <dir>` (with `--out`,
`--target-dict-bytes`, `--min-samples`, `--json`), which emits `dicts/<dict_id>.zstd` and a
`--json` summary including the measured ratio (§7).

## 2. dict_id: a content-addressed, collision-checked, registry-free id

### The exact hash

`dict_id = (truncate to u32) of BLAKE3-256(dictionary_bytes)`, taking the FIRST 4 bytes of the
32-byte BLAKE3 digest interpreted as a little-endian `u32`. BLAKE3 is the named algorithm; the
truncation is "first 4 bytes of the digest, little-endian". The hash is over the EXACT
dictionary blob the trainer emits (the bytes that land in `dicts/<dict_id>.zstd`), so the id
is a function of the content alone.

Rationale for the choice:
- BLAKE3 is a fast, pure-Rust, modern cryptographic hash with no C FFI, so it does not violate
  the [ADR 0003](adr/0003-default-compression-lz4-zstd-opt-in.md) pure-Rust-default posture
  even on the default build (the hash runs at TRAIN time and at the dict_id-derivation step,
  not in the hot compress path). Using a cryptographic hash (not a CRC) means a same-prefix
  collision cannot be engineered cheaply, which matters because the id is the immutability
  guarantee. BLAKE3 is NOT in the dependency graph today (the only hashes present are the
  CRC32C/xxhash used on the data path), so the implementation adds it as a new crate with its own
  `deny.toml` justification entry; its `CC0-1.0 OR Apache-2.0` license is accepted via the
  Apache-2.0 arm of the permissive allowlist.
- The truncation to u32 matches the dict_id WIDTH the v1 frame reserves (Section 8) and the
  `u32 dict_id` field #12 sketched. The truncation is what makes a collision POSSIBLE (a 32-bit
  space over a 256-bit hash), which is exactly why the train-time collision check below is
  mandatory.

### What happens on a collision at train time

The trainer holds the dict_id space honest. Before writing `dicts/<dict_id>.zstd`, it derives
the candidate dict_id and checks the output directory (and any operator-supplied active set
passed with `--known-dicts`):

- If the candidate derives dict_id 0, the trainer REFUSES it (0 is permanently the
  no-dictionary sentinel, Section 8) and the operator re-trains with a trivially different
  corpus, exactly as for a collision below. This is a ~1 in 2^32 event, but it is a HARD rule so
  a trained dictionary can never claim the no-dictionary id.
- If NO file `dicts/<dict_id>.zstd` exists, the id is free: write it.
- If a file `dicts/<dict_id>.zstd` exists AND its bytes are BYTE-IDENTICAL to the candidate,
  the trainer produced the same dictionary again (a deterministic re-train of the same corpus):
  it is a no-op, the existing file stands, and the same dict_id is reported. This is not a
  collision; it is the content-addressing working.
- If a file `dicts/<dict_id>.zstd` exists but its bytes DIFFER from the candidate, that is a
  true 32-bit truncation collision: two DIFFERENT dictionaries hashed to the same truncated id.
  The trainer REFUSES, fail-closed, with a non-zero exit and a typed error naming the colliding
  dict_id, and writes NOTHING. The operator's documented recovery is to re-run the training (a
  trivially different corpus, for example one more or one fewer sample, yields a different blob
  and therefore a different full BLAKE3 digest and almost certainly a different truncated id).
  A 32-bit collision over distinct trained dictionaries is astronomically unlikely in practice
  (a fleet would need on the order of 2^16 distinct dictionaries before a birthday collision is
  even probable), so this path is a guard, not an expected event, but it is a HARD guard so a
  collision can never silently reinterpret old data.

### Why content-addressing makes reuse structurally impossible

The dict_id is DERIVED from the dictionary bytes, not ASSIGNED by an allocator. Two
consequences follow mechanically:

- A given dictionary always has the SAME dict_id, everywhere, with no coordination. No central
  registry, no allocation server, no shared counter, which is the right answer for an edge
  fleet of intermittently connected nodes that cannot reach a registry.
- A given dict_id can only ever name ONE dictionary (modulo the refused 32-bit collision
  above). You cannot "reuse" dict_id 7 for a new dictionary, because a new dictionary has
  different bytes and therefore a different content hash and therefore a different dict_id. The
  only way to get the same dict_id is to have the identical bytes, which IS the same
  dictionary. Reuse is not forbidden by policy; it is impossible by construction. This is the
  same never-reuse property the at-rest nonce design depends on for segment ids
  ([ADR 0002](adr/0002-segments-never-recycled-in-v1.md)), achieved here by content-addressing
  rather than a monotonic counter.

## 3. Distribution: self-contained, never strands an offline reader

A dictionary is REQUIRED to decompress a frame that references it, so a missing dictionary is
permanently undecodable data. The distribution design makes a dictionary travel WITH the data
it is needed for, by two redundant mechanisms.

### 3a. The per-segment on-disk sidecar (the primary, binary-independent copy)

When the producing node writes a segment that contains ANY record referencing dict_id D, it
writes the dictionary blob as a sidecar file alongside the segments:

```
<data_dir>/
  seg-0000000000000000.log         # the segment (the authority)
  seg-0000000000000000.index       # derived sparse index (non-authoritative)
  seg-0000000000000000.tindex      # derived sparse time index
  dicts/
    <dict_id>.zstd                 # the dictionary blob, content-named (Section 2)
```

- The sidecar lives in a `dicts/` SUBDIRECTORY of the data directory, exactly parallel to the
  `quarantine/` subdirectory (see [quarantine store](schemas/loss-report.v1.md)). Recovery
  enumerates the live log with the flat directory walk that lists only `seg-*.log` files and
  never descends into a subdirectory, so a `dicts/` blob is structurally invisible to the live
  recovery walk and can never be mistaken for a segment.
- The sidecar is content-named `<dict_id>.zstd`, so the file name IS the integrity check: a
  reader resolving dict_id D re-derives the content hash of `dicts/<dict_id>.zstd` and confirms
  it equals D before trusting the bytes. A corrupt or wrong dictionary blob fails the
  content-hash check and is treated as ABSENT (the resolution falls through to the embedded set,
  Section 4), never silently misused.
- The blob is written ONCE per data directory and shared by every segment that references it
  (it is content-addressed, so the same dictionary is the same file). It is written durably
  (fsync the blob, then fsync the `dicts/` directory) BEFORE the first segment that references
  it is acked, so a referenced dictionary is always on disk before the data that needs it. The
  blob is never mutated (Section 6), so this write is write-once.
- "Self-contained" is the load-bearing property: whoever holds the segment files holds the
  `dicts/` sidecars too, so the data is decodable by that holder ALONE, with no network, no
  registry, and no dependency on which binary version is installed. This is what survives a
  binary downgrade (Section 4).

### 3b. The embedded active set (the secondary, build-time copy)

The CURRENTLY ACTIVE dictionaries (the small set the broker is configured to compress NEW
writes with) are ALSO embedded in the static binary at build time, per the single-binary story
(#17). The mechanism is Rust's `include_bytes!`: the build compiles each active dictionary blob
in `dicts/active/<dict_id>.zstd` into a `&'static [u8]` keyed by its dict_id, so the running
binary carries the active set in its own image with zero runtime IO and zero external file
dependency.

- This keeps the #17 promise that an offline device is never stranded: even a freshly imaged
  node with an empty data directory can decode a frame written with an active dictionary,
  because the dictionary is IN the binary.
- The embedded set is deliberately SMALL (only the active dictionaries the broker compresses
  with), so it costs little binary size, which is a first-class metric on a flash-scarce edge
  node (#17, #20). Retired dictionaries are NOT embedded (they live on as sidecars next to the
  old data they decode, Section 6); only the active set rides in the binary.
- Because the embedded set is fixed at BUILD time, a downgraded binary carries the active set
  of the OLDER build, which may not include a dictionary a newer producer used. That gap is
  exactly why the sidecar is resolved first (Section 4).

**IMPLEMENTED (#357, opt-in `zstd` feature):** the runtime sidecar write/read IO is
`ironbus_storage::dict_store::DictSidecarStore` (write-once, content-named, fsync-blob-then-
dir-sync durability ordering, content-hash-on-read integrity check that treats a mismatched or
absent blob as ABSENT). The `build.rs` + `include_bytes!` embed of the active set (§3b) is the
one remaining follow-up; the resolver already accepts an embedded set via
`CachingDictResolver::add_embedded`, so wiring the build-time compile-in is additive.

## 4. Resolution order: on-disk sidecar FIRST, then the embedded set

A reader resolving a frame's dict_id D follows a fixed order:

1. **On-disk sidecar first.** Look for `dicts/<D>.zstd` in the data directory. If present AND
   its content hash re-derives to D (the integrity check from Section 3a), use it. Done.
2. **Embedded set second.** Otherwise, look up D in the binary's embedded active set. If
   present, use it. Done.
3. **Unresolved.** If D is in neither, the dict_id is UNRESOLVED, which is bounded poison via
   Section 5.

### Why sidecar-first survives a binary downgrade

The producing node always writes the sidecar (Section 3a), so the sidecar is the copy that
TRAVELS WITH THE DATA and is independent of which binary reads it. The embedded set is fixed at
the reader binary's build time, so it can be STALE relative to the data: a node downgraded to an
older binary carries that older build's active set, which may LACK a dictionary a newer producer
already used to write segments on this very disk.

By resolving the on-disk sidecar first, the reader uses the dictionary that was written
ALONGSIDE the data, regardless of the reader binary's age. The older binary, missing dict_id D
from its embedded set, still finds `dicts/<D>.zstd` on disk (the newer producer wrote it there)
and decodes correctly. Embedded-first would do the opposite: a downgraded binary would fail to
find D in its stale embedded set and fall to the unresolved path even though the correct
dictionary is sitting on disk a directory away. Sidecar-first is therefore the order that makes
"a downgrade never strands readable data" true. It also means the sidecar is authoritative for
the dictionary's CONTENT: if the embedded and sidecar copies ever disagreed (they cannot, both
are content-named by the same hash), the disk copy that matches the on-disk data wins.

## 5. Unresolved dict_id = bounded poison via #8 (the reported-loss class)

An unresolved dict_id (Section 4 step 3) is NEVER a silent drop and NEVER a crash. It is routed
through the #8 corruption / quarantine path as a BOUNDED, REPORTED loss, exactly like any other
record IronBus cannot interpret. The affected record (or the smallest unit that contains it) is
skipped, the gap is reported with offset range and byte count, and a forensic copy is captured
in the quarantine store, so an operator sees precisely what was lost and can supply the missing
dictionary later.

### The distinguishing property: framing is intact, decode is impossible

This is a DIFFERENT failure class from the existing ReasonCodes 1 through 6. Those are corruption
or ordering failures: a bad record header CRC, a bad body CRC, a bad segment header, an
out-of-order sequence. An unresolved-dict_id frame is the opposite: the record header CRC, the
body CRC, and the xxh3 (if present) ALL PASS, because the dict_id and the compressed payload are
inside the checksum-covered body and are byte-perfect on disk. The bytes are not corrupt; they
are simply not decodable WITHOUT a dictionary this reader does not hold. It is the same shape as
the at-rest-encryption "unknown key-id" loss class
([AT_REST_ENCRYPTION.md](AT_REST_ENCRYPTION.md)): intact ciphertext, absent key. Folding it into
a corruption reason like `CorruptRecordBody` would be a lie (the body is not corrupt) and would
mislead an operator into hunting bit-rot when the real fix is to ship a dictionary.

### The ReasonCode decision: a NEW append-only reason

This design specifies a NEW reason code, appended to the frozen `ironbus.loss-report.v1`
vocabulary:

| code | JSON name           | metric label          | meaning |
|------|---------------------|-----------------------|---------|
| `7`  | `UnresolvedDictId`  | `unresolved_dict_id`  | a checksum-VALID record referenced a compression dict_id that the reader could resolve from neither the on-disk `dicts/` sidecar nor the embedded active set, so the record could not be decompressed and was skipped as bounded, reported loss. Distinct from a corrupt body (codes 2/3): the framing and CRCs are intact; only the dictionary is absent. It IS data loss (`is_data_loss() == true`). |

Why a NEW reason rather than reusing an existing one:
- Reusing `CorruptRecordBody` (3) would misreport an absent-dictionary event as bit-rot,
  defeating the whole "reported loss names exactly what was lost" contract (#8) and sending the
  operator after the wrong root cause.
- The existing reasons 1 through 6 are checksum/framing failures (1 through 4), an ordering break
  (5, SequenceGap, whose own CRCs pass), or scrubber-detected bit-rot (6); none describes "intact
  frame, valid CRCs, absent decode input". An honest
  report needs its own reason, so an operator (and a dashboard) can tell "ship the missing
  dictionary" apart from "this disk is rotting".

Why this is SAFE against the frozen-schema rule:
- It is APPEND-ONLY. Code 7 is a NEW number, a NEW name, and a NEW label. Codes 1 through 6 are
  byte-identical: not renamed, not reordered, not renumbered. This is exactly the move the
  schema already made for code 6 (`ScrubberSuspect`), which was appended without a version bump.
- It does NOT bump `schema_version`. Per the loss-report versioning policy, adding a new
  `ReasonCode` variant does not bump the version: a `v1` reader that predates code 7 still reads
  a code-7 event's numeric span (`bytes_skipped`, the offset range, the record estimate) and
  just renders the reason as an unknown name. So a deployed reader is never broken by this
  addition. `schema_version` stays at `1`.
- It counts as data loss, like every reason except `TornTail`, so it flows into
  `ironbus_recovery_data_loss_bytes` and `quarantine::is_corruption_skip` keeps the forensic
  copy, the same boundary every other corruption skip uses.

**IMPLEMENTED (#357, #387):** `ReasonCode::UnresolvedDictId` (code 7, label `unresolved_dict_id`,
`is_data_loss() == true`) is appended to `crates/ironbus-storage/src/loss.rs`, the golden
vocabulary test (`golden_reason_code_vocabulary_is_frozen`) and the stability test
(`reason_codes_are_stable_and_distinct`) are extended, and `schema_version` stays `1` (codes 1
through 6 are byte-identical). The decode path emits it: `ironbus_core::compress::decompress_payload`
returns `PoisonUnresolvedDict` for a non-zero `dict_id` the `DictResolver` cannot resolve, and
`ReasonCode::for_decompress_error` maps that to `UnresolvedDictId` for the #8 quarantine flow. The
DEFERRED residual is only the actual dictionary RESOLUTION against real sidecar/embedded bytes (the
zstd-feature side); the default build's `NoDictionaries` resolver makes every non-zero `dict_id`
correctly unresolved.

## 6. Immutability and rotation

Dictionaries are APPEND-ONLY, the same discipline the loss-report vocabulary and the segment-id
space follow:

- A dictionary blob, once written as `dicts/<dict_id>.zstd`, is NEVER mutated in place. Its
  content-addressed name (Section 2) makes mutation meaningless: changing the bytes changes the
  content hash, so the result is a DIFFERENT file with a DIFFERENT dict_id, not an edit of the
  existing one.
- ROTATION means training a NEW dictionary and writing a NEW dict_id, then pointing new writes
  at it (and embedding it in the next build's active set). The OLD dict_id keeps naming the OLD
  dictionary, whose blob stays on disk as a sidecar next to the old segments that reference it.
- Therefore OLD DATA STAYS READABLE FOREVER: a segment written under dict_id 7 still resolves
  dict_id 7 from its sidecar (Section 4 step 1) long after the active dictionary has rotated to
  dict_id 42, and even after dict_id 7 has been DROPPED from the embedded active set in newer
  builds (because the sidecar, not the embedded set, is authoritative for old data). Rotation
  never invalidates a single previously-written record.
- A retired dictionary's sidecar is reclaimed only when the LAST segment referencing it is
  reaped by the normal retention/compaction lifecycle (#13, [WAL.md](WAL.md)). The dictionary
  outlives the data it serves and is collected with it, never before.

## 7. The before/after ratio methodology

The #78 acceptance criterion is a DOCUMENTED before/after compression-ratio win (dictionary vs
no-dictionary, per-batch) on REAL telemetry. The MEASURED NUMBER is a residual (it depends on a
real corpus on real hardware); this section specifies the METHOD so the number, when produced,
is honest and reproducible.

- **Unit and codec held constant.** Both arms compress the SAME real per-type telemetry corpus,
  in the SAME per-batch unit (the #12 default unit), with the SAME zstd level. The ONLY variable
  is the dictionary: arm A compresses each batch with NO dictionary (`dict_id = 0`); arm B
  compresses each batch with the trained per-type dictionary (`dict_id = D`). Changing only the
  one variable is what makes the ratio attributable to the dictionary and nothing else.
- **Real telemetry, not synthetic noise.** The corpus is REAL captured records of the message
  type, the same realistic-payload discipline `ironbus bench` already enforces (it measures on
  #12-encoded real payloads by default, not incompressible noise, see #94). Synthetic random
  payloads would show a near-zero or negative dictionary win and prove nothing.
- **The reported ratio.** For each arm, `ratio = sum(uncompressed batch bytes) / sum(compressed
  batch bytes)` over the whole corpus, plus the per-batch distribution (so a single lucky batch
  does not dominate). The headline is `ratio_B / ratio_A`, the dictionary's multiplicative win,
  with both absolute ratios reported so the baseline is visible. The expected shape is the #12
  finding (a few-hundred-byte JSON record going from roughly 2.8x without a dictionary to nearly
  7x with one), but the SPEC commits only to the METHOD; the realized number is the residual.
- **Where it is measured.** The measurement rides the existing benchmark surfaces rather than a
  new one: `ironbus bench` already reports the realized ratio on #12-encoded payloads (#94), so
  the before/after is two bench runs differing only in the dictionary config, on the same corpus
  and device. When the comparison is run against peer systems or as a tracked regression, it
  uses the #114 baseline rig's matched-workload discipline (same device, same message size, same
  durability label) so the ratio is compared apples-to-apples and a regression gate can watch it.
- **On-device, per #19.** Like every edge performance number, the canonical ratio is taken on
  the reference ARM device under the run discipline (#113), not faked host-side, because the
  whole point is the realized edge flash and uplink saving.

**IMPLEMENTED (#357, opt-in `zstd` feature):** the two-arm measurement is wired into
`ironbus dict train`, which reports `ratio_no_dict`, `ratio_with_dict`, and `ratio_gain`
(`ratio_with_dict / ratio_no_dict`) over the training corpus at a fixed zstd level (the §7
one-variable method); the `--json` summary carries the numbers. The CANONICAL on-device edge
number on a real per-type corpus (per #19/#113) is the one remaining residual: the method,
the formula, and the tooling are implemented; the archived device number is the follow-up.

## 8. The v1 frame's dict_id reservation (proof this is additive)

This design changes NO wire format and NO on-disk format, because the v1 frame already RESERVES
the dict_id space. The reservation is concrete:

- **Where the compressed marker lives.** The on-disk record header (36 bytes) carries a `flags`
  byte whose bit 0 is `COMPRESSED` (`RecordFlags::COMPRESSED = 0b0000_0001` in
  `crates/ironbus-core/src/types.rs`). When `COMPRESSED` is set, the record's payload is a
  compressed object whose SELF-DESCRIBING codec descriptor (the codec id and the `u32 dict_id`,
  the descriptor #12 sketched) prefixes the compressed bytes inside the checksum-covered body.
  The dict_id therefore lives in the compressed payload's descriptor, not in a separate header
  field, so adding it consumes no new header bytes and shifts no existing field.
- **Width.** The reserved dict_id is a `u32` (4 bytes, little-endian), matching the `u32 dict_id`
  in the #12 batch-header sketch and the truncation width in Section 2.
- **Default / unset meaning.** `dict_id = 0` means NO DICTIONARY. The record-layout diagram
  states this directly: the payload is "optionally zstd, dict_id=0 in v1"
  ([04-record-layout.dot](diagrams/04-record-layout.dot)). The trainer never emits dict_id 0 as a
  trained id: 0 is permanently the no-dictionary sentinel (a content hash that truncates to 0 is
  re-derived, the trivial probability of which is handled by the train-time collision/re-roll
  path in Section 2), so a `dict_id = 0` frame is unambiguously "no dictionary, decode without
  one".
- **Why this is provably additive.** The compression runtime is implemented at the SAME
  `FORMAT_VERSION = 1` because the descriptor lives INSIDE the payload, inside the CRC-covered
  body, so no header byte moves, no field width changes, and the format-registry digest (the
  `pub const` layout in `format.rs`) is unchanged (#387). A record stored RAW (the `lz4` codec's
  raw-store / never-expand fallback, or `--compression none`) leaves the `COMPRESSED` bit CLEAR
  and writes no descriptor, so it is BYTE-FOR-BYTE the pre-compression layout: every existing
  record and conformance vector reads identically. A frame that DOES set `COMPRESSED` is a frame
  written by this `lz4`-codec runtime (always `dict_id = 0` on the default path) or a future
  zstd-feature writer (which may set a non-zero `dict_id`); the unknown-flag-bit preservation rule
  (`RecordFlags::unknown_bits`, types.rs) means an older reader preserves bits it does not
  recognize rather than corrupting them, and a reader without the codec routes an unknown codec id
  or an unresolved `dict_id` to the bounded POISON class (§5) rather than crashing. The addition is
  a new INTERPRETATION of a state the v1 format already reserved, which is the definition of
  additive.

---

## Acceptance-criteria map (#78)

| #78 acceptance criterion | Status |
|--------------------------|--------|
| CLI trains a dictionary from collected samples and emits a content-hash dict_id | IMPLEMENTED (Sections 1, 2, #357): `ironbus dict train` -> `ironbus_core::dict::train_dictionary` (ZDICT) + `truncate_u32(BLAKE3-256)` dict_id |
| A frame written with a dictionary is decodable using only the on-disk sidecar (binary-independent) | IMPLEMENTED (Sections 3a, 4, #357): `ironbus_storage::dict_store::DictSidecarStore` + `CachingDictResolver` (sidecar-first, content-validated) |
| The same frame is decodable from the embedded set when the sidecar is absent | IMPLEMENTED-SEAM (Sections 3b, 4, #357): the resolver serves an embedded set via `CachingDictResolver::add_embedded`; the `build.rs`/`include_bytes!` compile-in is the one follow-up |
| An unresolved dict_id is quarantined via #8, not crashed or silently dropped | IMPLEMENTED (Section 5, #357/#387): `PoisonUnresolvedDict` -> `ReasonCode::UnresolvedDictId` -> #8 |
| Dictionaries are immutable; a re-train yields a new dict_id and leaves old data readable | IMPLEMENTED (Sections 2, 6, #357): content-addressed dict_id + write-once sidecar store make reuse impossible by construction |
| A documented before/after ratio on real telemetry shows the dictionary win over no-dictionary per-batch | METHOD + TOOLING IMPLEMENTED (Section 7, #357): `ironbus dict train` reports `ratio_no_dict`/`ratio_with_dict`/`ratio_gain`; the archived on-device number is the residual |

## Cross-references

- Parent compression design: [#12](https://github.com/ELares/IronBus/issues/12).
- Decoder resilience / quarantine: [INVARIANTS.md](INVARIANTS.md),
  [schemas/loss-report.v1.md](schemas/loss-report.v1.md), [#8](https://github.com/ELares/IronBus/issues/8).
- Single-binary embed and distribution: [DISTRIBUTION.md](DISTRIBUTION.md),
  [#17](https://github.com/ELares/IronBus/issues/17).
- CLI surface (the `dict` subcommand home): [CLI.md](CLI.md), [#15](https://github.com/ELares/IronBus/issues/15).
- Bench / baseline rig for the ratio method: [SLO.md](SLO.md),
  [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md), #94, #114.
- The codec / pure-Rust-default decision: [ADR 0003](adr/0003-default-compression-lz4-zstd-opt-in.md).
- The never-reuse precedent: [ADR 0002](adr/0002-segments-never-recycled-in-v1.md).

The `lz4`-codec runtime, the `dict_id` descriptor field, the `DictResolver` seam, and the
`UnresolvedDictId` reason emission are now in source (#387/#357). The remaining implementation
follow-up (the zstd `ZDICT` training, the sidecar IO, the `include_bytes!` embed, and the measured
before/after ratio), all behind the opt-in zstd feature, is tracked separately.
