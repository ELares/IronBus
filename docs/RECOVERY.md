# The recovery model: longest valid prefix and stop at first bad frame

This document is the authority for IronBus's RECOVERY MODEL: how `Log::open`
turns a crashed-or-corrupted on-disk data directory back into a consistent,
durable log; the exact predicate that decides whether a frame is intact; the
exhaustive decision table over every recovery situation; the decidable boundary
between a torn tail and mid-log corruption; the one safe recovery behavior v1
ships; and the older draft mechanisms it deliberately supersedes.

It RATIFIES the architecture that is already merged and tested. It is derived
from and cross-checked against the source. Where the older draft criteria in
[#43](https://github.com/ELares/IronBus/issues/43),
[#53](https://github.com/ELares/IronBus/issues/53),
[#57](https://github.com/ELares/IronBus/issues/57), and
[#58](https://github.com/ELares/IronBus/issues/58) diverge from the shipped
code, the CODE wins and the divergence is flagged inline. Those drafts describe a
byte-by-byte two-record resync with a mid-log skip-and-resume; IronBus does NOT
do that, and section 5 records exactly why.

For the shared invariants (I1 to I8) and the canonical glossary see
[INVARIANTS.md](INVARIANTS.md); for the durability contract see
[DURABILITY.md](DURABILITY.md); for the byte-level on-disk layouts see
[CONTRACTS.md](CONTRACTS.md); for the WAL-is-the-log model and the file lifecycle
see [WAL.md](WAL.md); for the loss-report schema see
[the `ironbus.loss-report.v1` schema](schemas/loss-report.v1.md); for the
compatibility rules see [COMPATIBILITY.md](COMPATIBILITY.md).

## The one honest headline

IronBus recovery is STOP AT FIRST BAD FRAME, equivalently LONGEST VALID PREFIX.
It is NOT a byte-by-byte resync that skips a corrupt record and resumes on a
later record.

> Recovery validates frames forward from the durable floor. The FIRST frame that
> is not intact ENDS the valid prefix. Everything from that frame to the end of
> the segment is dropped as ONE bounded, typed, reported loss event. Recovery
> never scans forward looking for the next valid magic, never resyncs onto a
> later frame, and never resurrects bytes past the first bad frame.

This is the safe choice for an edge log whose records are tiny and whose
on-device flash fails in contiguous spans. The draft "find the next valid record
boundary and resume" mechanism is intentionally absent (section 5): under the #5
frozen format, a record magic alone is not a resync authority, so resyncing onto
a later magic is exactly the unsafe move the format was frozen to prevent.

The whole model rests on three properties that are already proven in the merged
tests:

1. A torn or unsynced tail (the common power-loss case) is TRUNCATED to the last
   intact record and is NOT counted as data loss (it was never acked data).
2. A mid-log corrupt frame STOPS the prefix at that frame and drops the rest of
   the segment as one reported corruption loss event that DOES count as data
   loss.
3. A checksum-valid frame whose sequence is out of order is a HARD, fail-closed
   error (`RecoveredSequenceMismatch`), never silently accepted and never
   truncated past.

---

## 1. The recovery model, ratified

### 1.1 The durable floor and always-forward validation

Recovery never trusts a stored summary over the bytes. It establishes a
conservative DURABLE FLOOR and then validates strictly FORWARD from it, accepting
only what the bytes themselves prove.

- **Segment header is the per-segment floor.** Each segment is opened by
  validating its 64-byte header (magic, version `== 1`, `checksum_algo`, and the
  header CRC over bytes `[0, 60)`). A segment whose header does not validate is
  not partially recovered; the whole segment fails closed (section 3.4). The
  validated header's `base_offset` / `base_seq` are the floor the records are
  validated against. See `SegmentReader::open` and `SegmentHeader::decode`.

- **The footer is a CANDIDATE, never an authority on its own.** The trailing
  32 bytes are decoded as a footer CANDIDATE and trusted as a seal ONLY when the
  body independently agrees: the record region must decode cleanly up to exactly
  the footer start, and the footer's `record_count` and `last_seq` must match the
  recovered records. A footer that disagrees with the body (a torn sealed tail,
  or 32 trailing bytes that merely look like a footer, coincidentally or forged
  through record payload) is NOT trusted, and the segment is recovered as
  unsealed. Only a body-consistent footer that names a DIFFERENT `segment_id` is
  a hard error (a recycled or mixed-up file). See `SegmentReader::scan` /
  `scan_recovery`, tests `footer_disagreeing_with_body_is_not_trusted`,
  `footer_overlapping_record_data_is_not_trusted`,
  `corrupt_footer_crc_still_recovers_records`.

- **The checkpoint is a conservative floor, never a ceiling.** The per-group ack
  cursor checkpoint (`cursor.ckpt`, two slots, alternate-by-parity, higher-seq
  valid-CRC slot wins) regresses to the prior durable value on a torn write
  rather than reading a torn or invented one. It bounds delivery state from
  below; it can never advance recovery past a record the log bytes do not prove
  durable. See `crates/ironbus-storage/src/checkpoint.rs` and the checkpoint
  model in [CONTRACTS.md](CONTRACTS.md).

Recovery is a PURE FUNCTION of the durable bytes (invariant I4): recovering twice
from the same image yields identical records, consulting no wall clock and no
ambient state.

### 1.2 The intact-record predicate

A record frame is INTACT (a valid frame) if and only if ALL of the following
hold, checked in this order. This is the single predicate every recovery decision
turns on. It is the same predicate stated in [CONTRACTS.md](CONTRACTS.md) under
"Relationships and limits" and implemented in
`crates/ironbus-core/src/codec.rs` (`decode` and the length-only `decoded_len`):

1. `magic` equals `RECORD_MAGIC` (`0x4942`).
2. `version` equals the v1 `FORMAT_VERSION` (`1`).
3. `header_crc` (CRC32C over header bytes `[0, 32)`) matches.
4. The trailing `total_len` (the second u32 of the 8-byte trailer) equals the
   total frame length computed from the header fields. This is the length
   SENTINEL: the frame self-describes its length, and the on-disk length field
   must agree with the computed one or the frame is rejected (`BadLength`).
5. `body_crc` (CRC32C over the body) matches.
6. If the `HAS_XXH3` flag is set (stored body at or above
   `XXH3_PAYLOAD_THRESHOLD` = 64 KiB), the optional 8-byte xxh3-64 over the same
   body range matches.

CRC32C is the resync-gating checksum: it is verified BEFORE the xxh3-64, so a
corruption the CRC catches is always reported as a body-CRC failure, never as an
xxh3 failure. The derived bits (`HAS_KEY`, `HAS_XXH3`) must agree with the stored
lengths or the frame is malformed. A frame that fails any clause is NOT intact;
recovery stops at it (the kind of failure picks the reason code, section 2).

`timestamp` NEVER participates in this predicate, and NEVER participates in
ordering or classification. Producer timestamps are advisory data, not
monotonic, and a clock regression is not corruption. Recovery reconstructs the
per-segment MAX timestamp (not the last) purely for the age-retention reaper,
never for any decision. This is invariant I6 (ordering never consults the wall
clock); see `scan_body_streaming` in `crates/ironbus-storage/src/segment.rs` and
I6 in [INVARIANTS.md](INVARIANTS.md).

### 1.3 Longest valid prefix and stop at first bad frame

Recovery walks records forward from the segment header end, one frame at a time
(a streaming scan whose peak memory is the largest single record, not the whole
region, #156). It maintains `valid_end`, the byte offset just past the last
intact record. Two outcomes end the walk:

- **Torn tail (not data loss).** The bytes after the last intact record cannot
  form a whole intact record because they were never fully written: fewer bytes
  than a record header remain, or the header is intact but the declared frame
  runs past the region end (a partial body or trailer). Recovery TRUNCATES the
  active segment to `valid_end`, reports a `TornTail` loss over `[valid_end, EOF)`
  that is EXCLUDED from the data-loss total, and resumes appending at `valid_end`.
  This is the longest-valid-prefix recovery, labeled NOT data loss because no
  acked record is ever in the truncated tail (invariant I2, see
  [DURABILITY.md](DURABILITY.md)).

- **Mid-log corruption (data loss, bounded and reported).** A frame's structure
  is intact enough to read but its checksum or sentinel fails (a flipped header
  byte, a flipped body byte, a bad length sentinel, a bad xxh3). Recovery STOPS
  at that frame and drops the entire span `[bad_frame_start, EOF)` of the segment
  as ONE typed loss event that DOES count as data loss. It does NOT scan forward
  for a later valid frame and does NOT resume mid-segment (section 5).

Either way, the dropped span is recorded as a structured `LossEvent` (segment id,
start and end byte offsets, bytes skipped, a lower-bound record-loss estimate of
at least 1, and a `ReasonCode`) in a versioned `LossReport`, so no skip or
truncation is ever silent. The loss is never partial WITHIN a record: a frame
either passes its checksums whole or ends the prefix. See `Log::recover` in
`crates/ironbus-storage/src/log.rs` and the schema in
`crates/ironbus-storage/src/loss.rs`.

### 1.4 The I3 bounded-loss caps (fail closed)

Recovery refuses to accept UNBOUNDED silent loss. Before returning, it checks the
loss report against the I3 caps:

- **Per-event cap:** one segment or 64 MiB (`PER_EVENT_BYTE_CAP`), whichever is
  smaller. No single dropped span may exceed it.
- **Global cap:** 1% of durable bytes, FLOORED at the per-event cap so a normal
  torn tail on a tiny log is always in bounds.

If either cap is exceeded, `Log::open` returns
`StorageError::ExcessiveRecoveryLoss(CapViolation)` and FAILS the open rather than
silently dropping more than the caps allow. The torn-tail span counts toward the
total-skip cap but is excluded from the DATA-loss accounting. See the I3 block of
`Log::recover`, `LossReport::check_caps` in `loss.rs`, the I3 checker
`check_bounded_loss` in `crates/ironbus-storage/src/invariants.rs`, and I3 in
[INVARIANTS.md](INVARIANTS.md). Tests:
`recovery_fails_closed_when_loss_exceeds_the_per_event_cap`,
`check_caps_rejects_a_single_oversized_event`,
`check_caps_rejects_a_cascade_over_the_global_cap`.

### 1.5 The fault schedule is SEEDED and replayable (#384)

The crash classes above are exercised two complementary ways, both fully
deterministic:

- **The ARMING model** (`crates/ironbus-storage/src/fault.rs`): a test arms ONE
  specific fault (a failed fsync, a torn write, a checksum flip, a short read, a
  `sync_dir` publish failure) at a chosen boundary. The point gates in
  `crash_recovery.rs` use this to pin a named crash situation to a named outcome.
- **The SEEDED model** (`crates/ironbus-storage/src/sim.rs`): a single seeded
  in-tree PRNG (`SplitMix64`, ~15 lines, no external RNG crate) drives EVERY fault
  decision (which op class faults, and which fault), so a whole crash workload is a
  pure function of one `u64` seed. A `FaultSchedule` records the fault/op EVENT
  TRACE, so a run is fully replayable: re-running with the printed seed reproduces
  the identical trace and the identical recovery.

Two gates in `crates/ironbus-storage/tests/seeded_faults.rs` give the seeded model
teeth: the SAME-SEED determinism gate runs one workload under one seed twice and
asserts an identical event trace AND an identical recovered-log hash (stronger than
the disk-image equality the `determinism.rs` gate already checks), while asserting a
DIFFERENT seed varies the schedule (so the gate is not vacuous); and a per-PR
fixed-256-seed recovery sweep drives faults through the crash + recovery path and
asserts I1 to I4 hold under a few-second budget, PRINTING the seed of any failing
case so it replays exactly (`cargo test`, deterministic, no flaky cron). A
recovery-side arm injects a fault DURING recovery and requires the invariants hold
on success or a clean typed error (never a panic).

Out of scope for #384, still open: the broader ASYNC-SCHEDULER seam (#119, #151)
that would also seed the ORDERING/interleaving of concurrent operations, and the
cfg-guarded sim-mode lint deny-list (reject `now()` / real-thread-spawn /
unordered-map iteration in sim mode). This PR scopes to the highest-value parts: the
seeded FAULT schedule, the same-seed gate, and the seed sweep.

---

## 2. The exhaustive decision table (#43 core deliverable)

One row per recovery situation, mapping the observable on-disk condition to the
single action recovery takes, the resulting `LossReport` reason code (or none),
whether the span counts as DATA loss, and the owning code symbol or test. The
predicate (section 1.2) is the same for every row; the rows differ only in WHICH
clause failed and WHERE.

| # | Observable condition | Action | Reason code | Data loss? | Owning code symbol / test |
|---|---|---|---|---|---|
| 1 | Clean sealed segment: body decodes intact up to the footer, footer body-consistent and same `segment_id` | Trust the seal; all records recovered, segment sealed | none | no | `SegmentReader::scan_recovery` footer branch; `seal_then_scan_reads_footer_and_records` |
| 2 | Clean active segment: body decodes intact to EOF, no footer | All records recovered; resume appending at `valid_end` | none | no | `scan_body_streaming` clean path; `write_then_scan_roundtrip`, `scan_recovery_agrees_with_scan_across_shapes` |
| 3 | Short/truncated final record: fewer than a record header remains after the last intact record | Truncate to `valid_end`; longest valid prefix | `TornTail` | no | `scan_body_streaming` `remaining < RECORD_HEADER_LEN`; `torn_tail_partial_record_header` |
| 4 | Over-running `total_len` at EOF: header intact but declared frame runs past the region (partial body or trailer) | Truncate to `valid_end` | `TornTail` | no | `scan_body_streaming` `total > remaining`; `torn_tail_partial_record_body`, `torn_tail_partial_record_trailer` |
| 5 | Zero-filled tail with fewer than a header left, or a sub-header sliver | Truncate to `valid_end` | `TornTail` | no | `scan_body_streaming` short-remaining branch; see also row 6 caveat |
| 6 | Zero-filled tail that still spans a full header (zero word is not a valid magic) | Stop at the zero region; drop `[zero_start, EOF)` | `CorruptRecordHeader` | yes | `decoded_len` `BadMagic`; `all_zeros_record_region` (NOTE: differs from the draft, see below) |
| 7 | Bad record `magic` mid-log | Stop at that frame; drop `[frame, EOF)` | `CorruptRecordHeader` | yes | `decoded_len` `BadMagic`; `bad_record_magic` |
| 8 | Unsupported record `version` mid-log | Stop at that frame; drop `[frame, EOF)` | `CorruptRecordHeader` | yes | `decoded_len` `UnsupportedVersion`; `unsupported_record_version` |
| 9 | Bad `header_crc` mid-log (valid magic, flipped header byte) | Stop at that frame; drop `[frame, EOF)` | `CorruptRecordHeader` | yes | `decoded_len` `BadHeaderCrc`; `flipped_record_header_crc`, `planted_false_magic_in_a_header_is_rejected_at_the_header_crc` |
| 10 | Bad `body_crc` mid-log (header intact, flipped body byte) | Stop at that frame; drop `[frame, EOF)` | `CorruptRecordBody` | yes | `decode` `BadBodyCrc`; `flipped_record_body_crc`, `planted_false_magic_mid_log_is_rejected_at_the_checksum` |
| 11 | Bad `total_len` sentinel mid-log (length field disagrees with computed total) | Stop at that frame; drop `[frame, EOF)` | `CorruptRecordBody` | yes | `decode` `BadLength`; covered by the body-validation path in `scan_body_streaming` (`codec::decode` rejects) |
| 12 | Bad xxh3-64 on an over-threshold record (CRC32C passes, xxh3 flipped) | Stop at that frame; drop `[frame, EOF)` | `CorruptRecordBody` | yes | `decode` `BadXxh3`; `flipped_xxh3_field_on_over_threshold_record` |
| 13 | Bad segment header CRC (or bad magic / unsupported version / unsupported `checksum_algo`) | Fail the whole segment closed; no partial recovery | none in `LossReport` (typed `StorageError`); the reserved report reason is `CorruptSegmentHeader` | n/a (open fails) | `SegmentReader::open` -> `SegmentHeader::decode`; `flipped_segment_header_crc`, `unsupported_segment_header_version`, `unsupported_segment_header_checksum_algo`, `all_zeros_whole_segment_fails_closed` |
| 14 | Segment file shorter than a 64-byte header | Fail closed, typed structural error | none (typed `SegmentError::Truncated`) | n/a (open fails) | `SegmentReader::open` length guard; `short_file_is_typed_truncation_not_io`, `truncated_short_segment_header` |
| 15 | Valid frame whose `seq != base_seq + index` mid-log (recycled / mixed-up frame) | Fail the whole recovery closed; never accepted, never truncated past | none (hard `StorageError`) | n/a (open fails) | `scan_body_streaming` seq check -> `RecoveredSequenceMismatch`; `scan_recovery_reports_a_recycled_frame_with_a_bad_seq`, `recycled_frame_with_a_stale_sequence` |
| 16 | Body-consistent footer that names a DIFFERENT `segment_id` | Fail closed (recycled / mixed file) | none (typed `FooterSegmentMismatch`) | n/a (open fails) | `scan_recovery` footer branch; `footer_from_wrong_segment_is_rejected`, `footer_header_segment_id_mismatch` |
| 17 | Footer present but disagrees with the body (lying count, overlapping record data, or torn footer CRC) | Distrust the seal; recover the valid prefix as UNSEALED | `TornTail` only if trailing non-record bytes remain, else none | no | `scan_recovery` candidate rejection; `footer_disagreeing_with_body_is_not_trusted`, `footer_overlapping_record_data_is_not_trusted`, `corrupt_footer_crc_still_recovers_records`, `truncated_footer_recovers_records_unsealed` |
| 18 | Non-final segment in the chain is unsealed (two appendable segments) | Fail closed | none (typed `UnsealedPredecessor`) | n/a (open fails) | `scan_recover_chain`; `unsealed_non_final_predecessor` |
| 19 | Segment base offset/seq does not continue from its predecessor (gap or overlap) | Fail closed | none (typed `SegmentChainBroken`) | n/a (open fails) | `scan_recover_chain`; `segment_chain_gap` |
| 20 | Recovery would drop more than the I3 caps allow (one oversize event, or a cascade over 1% of durable bytes) | Fail the open closed; freeze rather than accept unbounded silent loss | n/a (the report is built, then `check_caps` rejects it) | n/a (open fails) | I3 block of `Log::recover` -> `ExcessiveRecoveryLoss`; `recovery_fails_closed_when_loss_exceeds_the_per_event_cap` |

Notes that keep the table honest against the merged code:

- **Row 6 differs from the draft.** The #43 / #53 drafts assert that a zero-fill
  or all-0xFF run to EOF is ALWAYS a torn tail. In the shipped code a zero region
  that still spans a full record header is read as a frame and rejected at the
  magic check, so it is reported as `CorruptRecordHeader` (code 2), NOT
  `TornTail` (code 1). See `all_zeros_record_region`. This is conservative and
  correct (a zeroed previously-durable region is corruption, not an unwritten
  tail), but it is a real divergence from the draft wording and is recorded as
  such, not smoothed over. A genuinely torn (sub-header) zero sliver still
  classifies as `TornTail` (row 5).
- **Rows 13 to 20 are not `LossReport` rows.** A segment-level or chain-level
  fault fails `Log::open` with a typed `StorageError` and never produces a
  `LossReport`; recovery never silently serves a structurally inconsistent log.
  `CorruptSegmentHeader` (reason code 4) and `SequenceGap` (reason code 5) are
  DEFINED in the frozen `ReasonCode` vocabulary but are NEVER produced by
  recovery today (see section 5 and the `loss.rs` frozen-vocabulary test). They
  are reserved so the metrics taxonomy is frozen up front.
- Every row maps to a code symbol AND, where one exists, a named test. The only
  rows without a dedicated single-purpose test are row 11 (the `BadLength`
  sentinel mismatch, exercised through the general `codec::decode` rejection path
  and the single-bit-flip sweep rather than a hand-built fixture) and the
  reserved-but-unproduced reasons noted above; no row is left unmapped.

---

## 3. Torn tail versus mid-log, and active-segment handling (#53 / #58)

### 3.1 The decidable classification

The boundary is a DETERMINISTIC function of the durable bytes at the stop offset,
not a heuristic and not a forward scan. When forward validation stops at offset
`O` in a segment, the classification is decided ENTIRELY by why the frame at `O`
failed the intact predicate:

- It is a TORN TAIL when the bytes at `O` cannot form a whole record because they
  were never fully written: fewer than `RECORD_HEADER_LEN` bytes remain, or the
  header is intact but the declared `total_len` runs past the region end. Action:
  truncate to `O`, report `TornTail`, exclude from data loss, resume. (Rows 3 to
  5.)
- It is MID-LOG CORRUPTION when the bytes at `O` ARE a whole frame's worth but a
  checksum or sentinel fails: a bad magic over a full-header span, a bad
  `header_crc`, a bad `body_crc`, a bad length sentinel, or a bad xxh3. Action:
  stop at `O`, drop `[O, EOF)` as one reported `CorruptRecordHeader` or
  `CorruptRecordBody` event, count it as data loss. (Rows 6 to 12.)

The classification is decidable from the local frame at `O` alone because the #5
format makes a frame self-describing (magic, version, CRC-protected header, length
sentinel, body CRC). Recovery does not need to look at what follows `O` to
classify: stop-at-first-bad-frame means a later valid frame can never RECLASSIFY
an earlier failure, which is exactly the property that lets the boundary be a pure
function of the durable bytes rather than a scan result.

### 3.2 The handoff to the quarantine path

A mid-log corruption (data-loss) span is handed to the forensic QUARANTINE store
(#134) BEFORE it is truncated away, as a COPY (never a move): the corrupt bytes
are captured under the `quarantine/` subdirectory for offline analysis. A torn
tail is NOT quarantined (it is not corrupt data). The split is the single
predicate `quarantine::is_corruption_skip(reason)`, which is `reason != TornTail`,
the SAME boundary `ReasonCode::is_data_loss` uses, so the data-loss total and the
forensic store always agree on what "corruption" means. The capture is
best-effort and never blocks or fails recovery, and it is capped (oldest blobs
evicted first). See `crates/ironbus-storage/src/quarantine.rs`
(`is_corruption_skip`, `quarantine_corrupt_span`) and the quarantine block of
`Log::recover`.

This is the merged realization of the #53 / #58 "handoff to corruption-skip /
quarantine". Note the DIVERGENCE from the draft: the handoff is a copy-then-drop
for forensics, NOT a skip-and-resume that advances past the gap to a later resync
offset. Recovery drops `[O, EOF)` whole; it does not pass a resume offset back to
keep reading the segment (section 5).

### 3.3 Active-segment handling

The highest-id segment is the active one unless it is sealed:

- **Sealed highest segment (crash after sealing, before the next was created):**
  recovery ROLLS FORWARD. The sealed segment's record bytes join the sealed
  total, and a FRESH segment with `last_id + 1` is created continuing the offset
  and sequence space, so appends start in a clean segment. See the
  `scan.footer.is_some()` branch of `Log::recover` and
  `recovery_resumes_an_empty_active_segment_after_a_completed_roll`.
- **Unsealed highest segment (the normal active case):** recovery
  TRUNCATES-AND-RESUMES. Any torn or unsynced tail is dropped to `valid_end`
  (with its loss event and quarantine copy), the file is truncated and
  `sync_all`'d, and the writer RESUMES at `valid_end` via `SegmentWriter::resume`
  with the recovered record count, last sequence, and max timestamp. See the
  `else` branch of `Log::recover`.

### 3.4 Corrupt active-segment header

If the active (highest) segment's HEADER is itself unreadable (bad magic,
unsupported version, bad header CRC, or a file too short to hold a header),
recovery does NOT partially recover it and does NOT silently open a fresh
segment around it. It FAILS `Log::open` CLOSED with a typed `StorageError`
(rows 13 to 14). This is a deliberate DIVERGENCE from the #58 draft, which
proposed quarantining a corrupt active-segment header and opening a fresh new-id
segment to avoid a producer wedge. In the shipped model a corrupt segment header
is a structural fault that fails closed rather than risk inventing a new active
segment over an unverified one; the "open a fresh segment" automatic-repair is
not implemented. An operator-driven recovery (move the bad file aside) is the
intended path, and the fail-closed behavior is pinned by
`flipped_segment_header_crc`, `unsupported_segment_header_version`, and
`all_zeros_whole_segment_fails_closed`.

---

## 4. Recovery modes (#58): v1 ships exactly one

IronBus v1 ships ONE hardcoded, safe recovery behavior. There is no recovery-mode
config knob. The single behavior is:

- Longest valid prefix on a torn tail (truncate, resume, no data loss).
- Stop at first bad frame on mid-log corruption (drop `[bad, EOF)`, report,
  quarantine, count as data loss).
- Fail closed on a cap breach (I3), on an out-of-order sequence
  (`RecoveredSequenceMismatch`), and on any segment-level or chain-level fault.

This is consistent with the one-durability-level stance in
[DURABILITY.md](DURABILITY.md): IronBus exposes exactly one safe default and does
not let the command line weaken it.

The #58 draft proposed THREE modes selectable via #14: `resync` (default),
`strict` (fail-closed, exit nonzero, loud banner), and `salvage` (skip-any, no
resync gate), with a one-time loud startup banner and the active mode surfaced
via #15. NONE of those modes exist today and they are NOT claimed here.

What IS worth noting honestly:

- The shipped single behavior already absorbs the SAFE half of the draft `strict`
  mode: a cap breach, an out-of-order sequence, or a segment-level fault already
  fails the open closed with a typed error, which is the loud, fail-closed
  outcome `strict` aimed at (it simply is not separately selectable, because it is
  the default).
- A `salvage` (skip-any) mode would REQUIRE the forward-resync primitive that #5
  deliberately froze out (section 5), so it cannot be added as a config knob
  without first reopening that format decision.

A future selectable strict-versus-default recovery mode is therefore a possible
[#14](https://github.com/ELares/IronBus/issues/14) config knob, recorded here as a
candidate, NOT as shipped. If it is ever added it would expose the EXISTING
fail-closed behavior under a name and surface the active mode via #15; it would
not add a new unsafe salvage path.

---

## 5. Superseded mechanisms (#57): no two-record resync, no scan window, no poison set

The #57 / #53 / #43 drafts specified a forward RESYNC primitive to find the next
valid record boundary after a corrupt record and RESUME reading the segment:

- a byte-by-byte scan from the end of the corrupt record,
- requiring TWO consecutive CRC-valid records before accepting a resync boundary,
- a configurable SCAN WINDOW (default 8 MiB) clamped to the segment end,
- an in-memory POISON SET keyed by offset so repeated hot reads short-circuit,
- returning `(resync_offset, lost_start, lost_end, lost_bytes)` to keep reading.

ALL of these are SUPERSEDED by stop-at-first-bad-frame and are NOT implemented,
deliberately:

- **The format authority rationale (#5).** The frozen v1 format and #5 froze the
  rule do-not-use-magic-alone-for-resync: a 2-byte record magic
  (`RECORD_MAGIC = 0x4942`) appears all over ordinary payload bytes, so a scanner
  that locks onto the next magic can resync onto garbage. The two-record gate was
  the draft's mitigation, but stop-at-first-bad-frame removes the need for it
  entirely by never resyncing in the first place. This is proven by
  `planted_false_magic_mid_log_is_rejected_at_the_checksum`: a real
  `RECORD_MAGIC` plus a plausible version byte is PLANTED inside a middle record's
  body, and recovery still stops at the FIRST bad frame (the now-corrupt middle
  record) and drops to EOF as one event, NEVER resyncing onto the planted magic
  deeper in the file. The header variant
  `planted_false_magic_in_a_header_is_rejected_at_the_header_crc` shows a valid
  magic is necessary but not sufficient: the header CRC still rejects it.
- **A mid-log corruption is NOT skipped and resumed.** Because recovery drops
  `[bad_frame, EOF)` whole, a corrupt frame in the middle of a segment costs the
  rest of that segment, not just the one record. This is the safe trade for an
  edge log (contiguous flash failure, tiny records): it guarantees the recovered
  prefix is genuinely a prefix of the durable order, with no invented frame
  boundary able to resurrect dropped bytes. The cost (losing the segment tail past
  the first bad frame) is bounded and reported (I3) and quarantined for forensics.
- **No scan window, no poison set.** With no forward scan there is no O(window)
  cost to cap and no per-read re-scan to memoize, so the 8 MiB window and the
  poison-set memoization have no implementation to attach to. They are recorded
  here as superseded, not deferred.

The net effect: where the draft would skip one record and resume on the next
valid frame, IronBus ends the valid prefix at the first bad frame. The decision
table (section 2) is exhaustive over this model; there is no "resync" action in
it because there is no resync in the code.

---

## 6. Cross-references and consistency

- The intact-record predicate (section 1.2) is identical to the one in
  [CONTRACTS.md](CONTRACTS.md) ("A record is intact only when ...") and is the
  `codec::decode` / `codec::decoded_len` implementation.
- The torn-tail-is-not-data-loss rule (section 1.3) and the I3 caps
  (section 1.4) are the I1 / I3 invariants in [INVARIANTS.md](INVARIANTS.md) and
  the loss schema in
  [the `ironbus.loss-report.v1` schema](schemas/loss-report.v1.md).
- The longest-valid-prefix-on-power-loss guarantee (section 1.3) is the recovery
  half of the I2 ack-implies-durable contract in [DURABILITY.md](DURABILITY.md).
- The active-segment roll-forward and truncate-and-resume (section 3.3) are the
  recovery entries of the WAL file lifecycle in [WAL.md](WAL.md).
- The frozen, never-recycled `segment_id` rule that makes a recycled-frame
  sequence mismatch a hard error (row 15) is the compatibility rule in
  [COMPATIBILITY.md](COMPATIBILITY.md).

### Divergences from the older drafts, recorded not invented

| Draft expectation | Shipped reality | Where |
|---|---|---|
| Byte-by-byte two-record resync after a corrupt record, then resume | Stop at first bad frame; drop `[bad, EOF)` whole, no resume | Section 5, `planted_false_magic_mid_log_is_rejected_at_the_checksum` |
| 8 MiB scan window + poison-set memoization | Not implemented; no forward scan exists to bound or memoize | Section 5 |
| Three recovery modes (resync / strict / salvage) via #14 | One hardcoded safe behavior; fail-closed already covers the safe half of `strict` | Section 4 |
| Corrupt active-segment header: quarantine and open a fresh new-id segment | Fail `Log::open` closed with a typed error; no automatic fresh-segment repair | Section 3.4 |
| Zero-fill / 0xFF to EOF always a torn tail | A full-header-spanning zero region is `CorruptRecordHeader`; only a sub-header sliver is `TornTail` | Row 6, `all_zeros_record_region` |
| `SequenceGap` reason emitted for an out-of-order frame | An out-of-order frame is the hard `RecoveredSequenceMismatch` error; `SequenceGap` is reserved but never produced | Row 15, section 5, `loss.rs` frozen vocabulary |

No contradiction with the merged code was found that is left unresolved: every
divergence above is a case where the shipped code is SAFER or simpler than the
draft, and this document ratifies the shipped behavior as the authority.
