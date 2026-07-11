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

## 6. Compaction: resolving an overlapping offset range (#337)

Optional key-based compaction (`docs/COMPACTION.md`) is the one feature that lets ONE segment
file (a `version=2` COMPACTED segment) be authoritative for an offset RANGE that the originals
also cover, until the originals are retired. A crash mid-swap can therefore leave the directory
holding BOTH the compacted segment and the originals it replaced. Recovery resolves the overlap
DETERMINISTICALLY from the files alone, with NO manifest and NO compaction-specific repair beyond
two generic file-set reconciliations. This runs only when a compacted segment is present
(`Log::recover_with_compaction`); an all-ordinary directory takes the unchanged v1 path
(section 1), so a log that has never been compacted recovers exactly as before.

The resolution, in order:

1. **Classify** each segment as ordinary or compacted (the COMPACTED header flag). A
   compacted-flagged segment whose trailing footer or 44-byte covered-range block is torn or
   CRC-mismatched did NOT reach its commit point (the directory fsync): it is a crash-before-commit
   orphan, discarded (unlinked). A half-written compacted segment thus never parses as a valid one.
2. **A committed compacted segment is authoritative** over every ordinary segment whose
   `[base_offset, base_offset + record_count)` is fully inside its covered range
   `[covered_base_offset, covered_end_offset)` (read from the v2 block): those superseded originals
   are unlinked (the crash-after-commit-during-retire case). Their surviving records are present in
   the compacted segment, so this is NOT a loss.
3. **Two compacted segments never partially overlap** by construction (a clean covers a contiguous
   run of whole source segments). If a crash somehow left two with overlapping covered ranges, the
   HIGHER segment id (the later clean, by ADR 0002 monotonicity) wins and the lower is unlinked.
4. **The surviving set stitches a contiguous-at-the-segment-boundary chain**, sorted by
   COVERED/ACTUAL offset range (NOT by id, since a compacted id no longer tracks its range). The
   continuity check advances the offset AND sequence expectation by the COVERED SPAN across a
   compacted segment (the survivors are sparse, so the survivor count does not), which reduces to
   the v1 exact `base_offset`/`base_seq` check for an all-ordinary log.

Each step is a pure function of the self-describing durable bytes (I4), so recovery stays
deterministic. NEITHER reconciliation emits a `LossReport` event (no durable record is actually
lost), the I3 caps and the I1 to I4 invariants hold, and the durable head never regresses. This is
verified in `crates/ironbus-storage/tests/compaction_crash.rs` (crash before/after the commit,
overlap resolution, the before-vs-after identical-recovery gate, and the fail-closed v2 refusal).

---

## 7. Cross-references and consistency

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

---

## 8. The operator runbook: recovery-as-a-feature (`verify` -> `repair` -> metric)

Sections 1 to 7 ratify the recovery MODEL. This section is the OPERATOR story: the
two first-class CLI commands and the metric that turn "a segment went bad" into a
bounded, knowable, reported recovery — the marquee **IronBus can, NATS can't**
differentiator. NATS's only documented corruption-recovery path is
restore-from-backup (its official DR docs state no in-place fix exists), its
truncate-and-drop recovery is silent and unbounded (#7549/#7556), and it exposes
**no corruption metric at all**. IronBus makes recovery a command, a metric, and a
bounded loss envelope.

### 8.1 The two commands

Both are OFFLINE store tools: they run against a STOPPED broker's `--data-dir` with
no server and do not touch the broker runtime. They share the recovery decode path
(section 1.2), so the offline view and the broker's next-start recovery agree on
every byte.

- **`ironbus verify --data-dir <dir> [--json]`** — the READ-ONLY fsck (the
  `fsck --dry-run` NATS lacks). It CRC-validates every segment of the log (the
  longest-valid-prefix scan of section 1.3, in read-only mode), then ALSO validates
  the layout marker (section 1.1 / #670), every consumer cursor against the durable
  range `[earliest_retained, durable_head]`, and the DLQ, and reports the forensic
  `quarantine/` footprint. It **MUTATES NOTHING**: a torn tail or corruption is
  DETECTED and REPORTED — never truncated, never quarantined, never a cursor
  rewritten. It is built entirely from the read-only `OfflineReader`,
  `check_layout_marker` (which, unlike recovery's `open_or_upgrade`, never writes the
  v1 marker), `inspect_cursors`, `read_dlq_entries`, and `quarantine::persisted_bytes`.
  Exit codes (the frozen scheme): **0** clean (a torn-tail-only result stays 0, the
  data-loss boundary of section 1.3), **3** it found and reported real data-loss
  corruption OR a cursor-vs-log mismatch, **2** the data dir is missing, **4** the
  chain is structurally unreadable (or a future layout marker blocks the open,
  section 1.1). `--json` emits a single `ironbus.cli.verify.v1` object with the
  segment `events` (segment id + byte span + reason + `data_loss`), the `cursors`
  array, `dlq_records`, `quarantine_bytes`, `layout_version`, and the `exit_code`.

- **`ironbus repair --data-dir <dir> [--apply --force] [--json]`** — the MUTATING
  command, recovery made explicit and offline. With NO flags it is the read-only
  PLAN (the same plan `verify`/`scrub` print: what it WOULD do, changing nothing).
  `--apply` performs the repair and **REQUIRES `--force`** (the confirmation gate: a
  bare `repair --apply` is refused with exit 1, checked before any lock or recovery,
  so `repair` never silently destroys). `--apply --force` takes the EXCLUSIVE
  data-dir lock first (exit 5 if a broker holds it — it never races a live writer),
  then runs recovery via `Log::open`, which:
  1. **QUARANTINES (copy-then-drop, NEVER delete)** each corrupt span to the capped
     `quarantine/` store BEFORE truncating it (section 3.2). The forensic bytes
     survive; nothing is ever deleted.
  2. **Truncates to the longest valid prefix** exactly as recovery does (section
     1.3), preserving every committed record and the data dir's uid/gid/mode.
  It NEVER makes the data less recoverable than the broker's own next-start recovery
  would. The bounded loss is REPORTED (the `LossReport`, human or
  `ironbus.cli.repair.v1`).

`verify` is the read-only twin of `repair`: run `verify` to SEE the problem, run
`repair --apply --force` to FIX it. After a repair, `verify` is clean (the repaired
prefix is consistent), proving the repair left a log the broker accepts unchanged.

### 8.2 The metric the recovery fires

When the BROKER itself recovers at startup (`Engine::open`), it counts the recovery
as an EVENT (#575) — the flagship metric NATS has no analogue for. Each is bumped
once per open from the durable loss reports of EVERY recovery path that open ran
(#1130: the root log, each named per-stream recovery, the shared WAL's recovery,
and every partition sub-log recovery) and is monotonic across a `kill -9`:

- `ironbus_recovery_runs_total{outcome="clean|torn_tail_truncated|quarantined|data_loss"}`
  — one increment per recovery run, in the bucket of the WORST loss observed
  across all the paths. The `fraction-of-opens-that-needed-a-repair` signal.
  `data_loss` fires for quarantine-UNCAPTURED loss — today, the shared WAL's
  undecodable-tag records (counted on the `ironbus_shared_wal_undecodable_records`
  last-open gauge).
- `ironbus_torn_tail_repairs_total` — torn/unsynced tails truncated to the longest
  valid prefix (power-loss repairs, NOT data loss), across every log the open
  recovers.
- `ironbus_corruption_repairs_total{artifact="segment|cursor|dlq"}` — corruption
  spans quarantined-and-dropped, by artifact. **This is the metric NATS structurally
  lacks**: a non-zero `{artifact="segment"}` is the alertable "real bytes were lost
  (and forensically preserved) at recovery" signal.

These join the existing recovery-loss GAUGES (`ironbus_recovery_data_loss_bytes`,
`ironbus_recovery_loss_bytes{reason}`, `ironbus_quarantine_bytes`) that report the
LAST recovery's loss. See [METRICS.md](METRICS.md) for the full taxonomy; the names
are pinned in the frozen-taxonomy test, so they can never silently drift.

### 8.3 Why the loss is BOUNDED (the knowable envelope)

The whole point: an operator can state the loss envelope BEFORE running anything,
because recovery is capped (the I3 caps, section 1.4). A single dropped span can
never exceed one segment or 64 MiB (`PER_EVENT_BYTE_CAP`), and the total can never
exceed 1% of durable bytes (floored at the per-event cap). If recovery WOULD exceed
the caps it FAILS CLOSED (`ExcessiveRecoveryLoss`) rather than silently dropping
more — so the loss is either within the published bound or the open is refused. The
`quarantine/` store is likewise capped (oldest blobs evicted first), so the forensic
footprint is bounded too. `verify` reports the exact span (segment + `[start, end)`
byte offsets) and `ironbus_recovery_data_loss_bytes` / `ironbus_corruption_repairs_total`
report the totals, so "how much did I lose and why is it bounded" is answerable from
the CLI and the metric together.

### 8.4 The runbook: a segment went bad

1. **Stop the broker** (the offline tools take the exclusive data-dir lock; a live
   broker blocks `repair --apply` with exit 5).
2. **`ironbus verify --data-dir <dir> --json`** — see WHAT is wrong, WHERE (segment +
   byte offset), and HOW MUCH is lost (bounded by the I3 caps). Exit 3 means a
   data-loss corruption or a cursor mismatch; exit 0 means clean or torn-tail-only.
   This mutates nothing, so it is always safe to run.
3. **`ironbus repair --data-dir <dir>`** (no flags) — review the read-only PLAN: what
   `--apply` WOULD quarantine and truncate, changing nothing.
4. **`ironbus repair --data-dir <dir> --apply --force`** — perform the bounded,
   reported repair: quarantine the corrupt span (copy-then-drop, forensics
   preserved), truncate to the longest valid prefix (committed data preserved).
5. **`ironbus verify --data-dir <dir>`** — confirm the dir is now clean.
6. **Restart the broker.** Its `Engine::open` recovery is a no-op on the
   already-repaired dir (an empty loss report), and `ironbus_recovery_runs_total{outcome="clean"}`
   ticks. Watch `ironbus_corruption_repairs_total{artifact="segment"}` and
   `ironbus_recovery_data_loss_bytes` for the historical record of what was lost.

The **NATS contrast**: at step 2 NATS has no `fsck` to run (the only recovery path is
restore-from-backup); at step 4 its in-place recovery is a silent, unbounded
truncate-and-drop with no quarantine forensics; at step 6 it has no corruption metric
to alert on. IronBus's recovery is a command, a bounded envelope, and a metric.

### 8.5 Backup and restore: a point-consistent snapshot (#607)

`verify`/`repair` recover a damaged dir IN PLACE; `backup`/`restore` capture and
re-materialize a WHOLE dir. Both are OFFLINE store tools (stopped broker, exclusive
lock), and a RESTORED dir passes `verify` (section 8.1) — `verify` is the consistency
oracle for a restore exactly as it is for a repair.

- **`ironbus backup --data-dir <dir> --out <backup> [--json]`** — a **point-consistent**
  snapshot of the log + the consumer cursors + the DLQ (and every other durable
  artifact: `counters.ckpt`, `layout.meta`, the `dlq-redrive.ckpt` watermark, any
  `streams/<name>/` subtree, the `quarantine/` store, and — when tiered storage (#643)
  is enabled — the `cold-manifest.ckpt` that records which sealed segments are offloaded
  REMOTE) captured at ONE logical point. It
  takes the **EXCLUSIVE data-dir lock** first (exit **5** if a broker is running — a
  running broker's data dir is not a consistent point), and because the broker is
  stopped and the lock is held, the on-disk checkpoints are SETTLED: capturing all three
  artifacts under that quiescent image yields a snapshot a restore cannot make divergent
  (no cursor past the head, no DLQ entry referencing a record the log no longer has). The
  backup is a **directory tree** (no tar dependency): a `MANIFEST` at the backup root
  (format version + a CRC32C/length of every captured file + the captured durable offsets
  / cursor / DLQ counts, the consistency self-check) plus a `data/` subtree that is a
  faithful copy of the data dir captured by recursive ENUMERATION (so there is no
  per-artifact special case to drift). The CLI `LOCK` file is EXCLUDED (a transient
  advisory lock, not storage state). The manifest is written LAST, so a crash mid-backup
  leaves a backup with no manifest — which a restore rejects (fail-closed), never one that
  promises files not on disk. `--json` emits a single `ironbus.cli.backup.v1` object.

- **`ironbus restore --from <backup> --data-dir <dir> [--force] [--json]`** — validate the
  backup and materialize the target, **fail-closed**. The backup is validated WHOLE before
  a single byte is written: the `MANIFEST` must be a well-formed IronBus backup manifest of
  a SUPPORTED format version (a future version is refused, exactly as a future layout marker
  is, section 1.1), and EVERY listed file must be present with bytes whose CRC32C + length
  match the manifest. A corrupt, truncated, incomplete, or wrong-version backup is REJECTED
  (nonzero exit) with **NOTHING written to the target** — never a partial restore. It
  **REFUSES to clobber a NON-EMPTY `--data-dir` without `--force`** (with `--force` the
  target is cleared first, so the restored tree is exactly the backup's, never a merge), and
  it takes the exclusive lock on the target (exit 5 if a broker holds it). After a restore
  the target holds a byte-faithful copy of the captured dir, so it **passes `verify`** (every
  cursor ≤ the log head, every DLQ entry resolvable) and a broker resumes from the restored
  cursors exactly as it would from the source. `--json` emits `ironbus.cli.restore.v1`.

The point-consistency argument, restated: a backup is consistent BY CONSTRUCTION because it
is taken at a single quiescent point (stopped broker + exclusive lock + settled checkpoints),
and `verify` is the proof — a round trip (fill → backup → restore to a fresh dir → `verify`)
is clean, with the restored cursors/DLQ/log-head equal to the source. The **NATS contrast**:
a NATS snapshot has no offline whole-store consistency proof of cursors-vs-log-vs-DLQ; here
the manifest self-check plus the `verify` oracle make "this backup restores to a consistent
dir" a checkable property, not a hope.

### 8.6 The runbook: the writer froze

A **frozen writer** is a deliberate fail-stop, not a crash. When a covering `fsync` (or the
append behind it) returns a **fatal** storage error — EIO from a failing device, a read-only
remount, a filesystem fault, or the volume filling at the OS layer — the append actor stops
writing rather than keep acknowledging produces it can no longer make durable. That preserves
**I2 (an ack implies the record is durable)**: IronBus would rather refuse than lie. The freeze
is **terminal for the process** — `begin_async_commit` errors on a frozen writer, so batch N+1
can never become durable behind it, and the writer **cannot self-thaw**. Recovery is a
**restart onto healthy storage**, not a wait.

**How you learn about it (there is no freeze log line — detection is a metric + `/readyz`):**

- The `IronbusWriterFrozen` alert fires: `ironbus_writer_healthy == 0` (the **act-now** alert
  table under [MONITORING.md](MONITORING.md) → Alerts).
- `/readyz` returns **503 `writer frozen`**, so a load balancer pulls the broker out of
  rotation (`/healthz` may still be 200 if the event loop is otherwise ticking — readyz is the
  authoritative freeze signal, see [health.rs](../crates/ironbus-server/src/health.rs)).
- In-flight and subsequent produces are **fataled/refused** with a `WriterFrozen` error; a
  Level-1+ producer sees the failed ack rather than a false success.

**The runbook:**

1. **Confirm it is a freeze, then find the storage fault.** `ironbus_writer_healthy == 0` +
   `/readyz` 503 `writer frozen` is the freeze. The freeze is the SYMPTOM; the cause is under
   the mount. Check the kernel log (`dmesg` / journal) for `EIO` / device errors, the mount
   state (a read-only remount after an fs error is common), device health (SMART), and free
   space at the fs layer (`df` — a fatal ENOSPC differs from IronBus's own bounded disk-cap
   shedding, which does NOT freeze the writer).
2. **Fix the underlying storage.** Remount read-write after clearing the fs error, free or
   extend the volume, or replace/repair the failing device — or move the data-dir onto a
   healthy volume (a restore, step 4b).
3. **Restart the broker.** The writer state is process-local, so a restart is what thaws it.
   `Engine::open` runs its normal recovery over the data-dir on start; if the fatal write left
   a torn tail, that recovery truncates it to the longest valid prefix (committed data
   preserved) — a clean restart. `ironbus_writer_healthy` returns to `1`, `/readyz` to `200`,
   and produces are accepted again.
4. **If the restart's recovery reports corruption or the volume is gone:**
   - a. Corruption beyond a torn tail → follow the **segment runbook (section 8.4)**
     (`verify` → `repair --apply --force` → `verify`) before restarting.
   - b. The volume is lost → **restore from backup (section 8.5)** onto a healthy volume, then
     start; the restored dir passes `verify` by construction.
5. **Verify recovery.** `ironbus_writer_healthy == 1`, `/readyz` 200, a test produce is acked.
   The freeze left no silent loss: nothing was acked that is not durable (that is the whole
   point of the fail-stop), so there is no data-loss ledger to reconcile — unlike a crash,
   where you would check `ironbus_recovery_data_loss_bytes` (section 8.1).

The **NATS contrast**: a JetStream write that cannot fsync has no equivalent terminal
fail-stop with a dedicated liveness gauge and a readyz gate — the failure surfaces as errors
without a single "the writer is frozen, stop trusting acks" signal to alert and page on. Here
the freeze is one gauge (`ironbus_writer_healthy`), one readyz state (`writer frozen`), and one
bounded recovery (fix storage → restart), so "acked ⇒ durable" holds across the fault instead
of degrading silently.

---

## 9. Transactional messages (2PC): the half-message commit point and its durability scope (#640)

A transactional half message (`prepare` → `commit`/`rollback`, the two-phase-commit
core in #640) buffers a payload INVISIBLE to consumers under a producer-supplied
`txn_id`, then either makes it visible at one durable commit point or discards it.
The buffered half lives in the `txn/` subtree (its own log, never the real stream),
so a consumer never sees a Prepared payload, and the `txn/` subtree is not even
materialized until the first `prepare` (a non-transactional broker is byte-for-byte
unchanged). This section ratifies the COMMIT-POINT crash ordering and — because the
"SHIP-WITH-DOC" review turned on exactly this — states the THREE durability-scope
caveats that keep the exactly-once claim honest. The engine code is
`Engine::txn_commit` / `commit_real_append` / `flush_txn_commit_dedup` and the clamp
`seed_producer_seq_from_recovered` in `crates/ironbus-server/src/engine.rs`; the
on-disk op-marker fsync is `TxnStore::append_op` in
`crates/ironbus-storage/src/txn.rs`.

### 9.1 The commit-point ordering

A fresh commit (or a crash-recovery redrive of a Prepared txn) runs four ordered
steps, designed so the real append is exactly-once across a crash:

- **A** — WRITE the buffered payload to the real stream, no fsync (assigns the
  offset, records the txn-id seq high-water IN MEMORY), DEDUPED by the durable
  txn-id producer-seq (#639) so a redrive re-write is a duplicate at the original
  offset.
- **A2** — fsync the producer-seq CHECKPOINT (`producer-seq.ckpt`), making the
  dedup identity durable BEFORE the record.
- **A3** — the COMMIT-BATCH covering fsync, making the real record durable.
- **B** — append + fsync the COMMITTED op-marker (the COMMIT POINT, carrying the
  real offset).

The crash windows map onto the longest-valid-prefix model of sections 1–3:

| Crash window | On reopen | Outcome |
|---|---|---|
| after `prepare`, before A | txn replays as Prepared (only the half record is durable) | a later commit is a FRESH resolve; still invisible |
| after A3, before B | txn replays as Prepared (no op-marker), payload still buffered | recovery re-commits; A re-writes the SAME payload under the SAME txn-id seq, which the durable high-water (made durable in A2) recognizes as a DUPLICATE at the original offset → exactly once |
| between A2 and A3 | high-water durable, real record LOST in the torn tail | recovery's `seed_producer_seq_from_recovered` CLAMPS a high-water whose offset is at/past the durable head and DROPS it, so the redrive re-writes FRESH at the real head → no double (the first write was lost), no loss (the redrive lands it) |
| after B | txn replays as Committed | no replay work; a retried commit is a benign idempotent no-op returning the recorded offset |

A2 is ordered BEFORE A3 specifically so the between-A2-and-A3 window degrades to the
CLAMP (drop a phantom high-water), not to a double-append. This is the recovery half
of the I2 ack-implies-durable contract (section 1.3 / [DURABILITY.md](DURABILITY.md)),
specialized to the 2PC commit point.

### 9.2 The three durability-scope caveats (post-review, stated honestly)

**(a) Exactly-once is SCOPED to `DurabilityLevel::Sync` (the default).** The
default-stream exactly-once / no-committed-empty guarantee rests on A3 (the real
record's covering fsync) happening BEFORE B (the op-marker, which ALWAYS
force-fsyncs). Under a RELAXED durability level (`interval`/`async`/`none`) A3 is a
no-fsync `flush_no_sync` while the op-marker B still force-fsyncs — so a power cut can
leave the lifecycle state Committed (B durable) while the unsynced real record is lost
(committed-but-empty). This is consistent with the relaxed-level acked-loss waiver
(I2 is already waived there, [DURABILITY.md](DURABILITY.md)), but it is a NEW
asymmetry: the lifecycle marker is durable while its record is not. Use `sync` (the
default) for the no-committed-empty guarantee.

**(b) Named-stream commit redrive is at-least-once on crash.** Only the DEFAULT stream
carries the durable txn-id seq dedup. A NAMED (non-default) target stream is
exactly-once in NORMAL operation, but a crash-recovery redrive (a Prepared replay
re-appending) can DUPLICATE at a new offset (never loss, never a double-append in
normal operation). Closing this is a flagged follow-up: thread the engine producer-seq
dedup through `StreamSet::append_to` with a per-stream-namespaced high-water.

**(c) The dedup high-water can age out.** The txn-id dedup high-water shares the
bounded (LRU, ~4096-entry) `producer-seq.ckpt` slot. A VERY late default-stream
redrive whose high-water was EVICTED by newer producers before it runs degrades to
at-least-once (safe — never loss, never a flipped outcome). An IMMEDIATE
crash-recovery redrive is unaffected: the txn pseudo-ids were just written and sort to
the front of the LRU, so they are still present when recovery replays the Prepared txn.

All three caveats are SAFE failure modes (at-least-once or a refused conflict, never a
silent loss and never a flipped commit/rollback outcome). They are pinned in the engine
doc comments (the module-level crash-safety argument and the `txn_commit` /
`commit_real_append` doc) and exercised by the engine txn tests (the clamp branch by
`crash_between_a2_and_a3_clamps_the_phantom_high_water_and_redrives_fresh`).

### 9.3 Transaction-id choice across reconnects (auto-minted vs caller-supplied)

The `txn_id` is the broker's IDEMPOTENCY KEY (it anchors the lifecycle, the dedup
high-water, and the commit/rollback resolution). The client offers two ways to
choose it (`crates/ironbus-client/src/lib.rs`):

- **Auto-minted** (`Client::prepare`): `<local_addr>#<seq>` — the connection's local
  socket address plus a monotonic per-connection counter. Unique WITHIN a connection
  and across concurrently-open connections (distinct local addresses), but NOT durable
  across a reconnect: an EPHEMERAL local port REUSED by a later connection whose
  counter has reset to 0 can re-mint an id a still-prepared txn already holds. Because
  the id is the idempotency key, this surfaces as a broker ERROR (a spent /
  still-prepared id is refused) — NEVER a silent merge of two distinct half messages.
- **Caller-supplied** (`Client::prepare_with_id`): a stable id you control (a UUID, a
  snowflake, a content hash). This is the DURABLE choice for a transaction that must
  survive a reconnect, or that derives its identity from the producer's own local
  transaction — it makes the cross-connection idempotency explicit instead of relying
  on the per-connection mint.

For transactions that span a reconnect, prefer `prepare_with_id` with a stable id.

### 9.4 The broker back-check: resolving a producer-crashed in-doubt txn (#640 part 2)

Part 1 leaves one hole: if a producer sends a half message (`prepare`) then
CRASHES before `commit`/`rollback`, the half message is stuck `Prepared`
(invisible, undelivered) forever. The **back-check** closes it. The broker
periodically scans for `Prepared` half messages older than a timeout and asks the
producer "what is the state of transaction X?"; the producer's registered
transaction-state listener answers `Commit` / `Rollback` / `Unknown`, and the
broker resolves accordingly. If the producer is unreachable after a bounded number
of attempts, the broker applies a SAFE TERMINAL default. The engine code is
`Engine::txn_back_check_tick` / `resolve_txn_check` / `register_txn_listener` and
the `TxnBackCheck` router in `crates/ironbus-server/src/engine.rs`; the pure
schedule is `ironbus_core::txn::BackCheckBook`; the durable bookkeeping is the
`TXNB` op-record + `TxnStore::append_back_check` in
`crates/ironbus-storage/src/txn.rs`.

**The scan loop.** A cheap periodic task (riding the producer's serve passes, the
same per-pass seam as the Level-2 `ProduceConfirm` drain, gated on the connection
having registered a listener) queries `BackCheckBook::due(now)` — every enrolled
`Prepared` txn whose next-eligible instant has passed, capped at a global per-pass
batch (no storm). For each due txn it records the attempt durably FIRST, then
pushes a `TxnCheck` to the producer's live listener; after the bounded
`max_back_check_attempts` with no resolution it applies the SAFE TERMINAL default
= **Rollback/discard** (never deliver a message whose outcome is unknowable). The
scan is a no-op (zero work) when no txn is in-doubt, so a broker that does not use
transactions is byte-for-byte unchanged.

**The new frames + tags.** `TxnCheck` (tag 47, broker→producer, "state of txn X?",
reusing the frozen `TxnResolveBody` shape), `TxnCheckResult` (tag 48,
producer→broker, `txn_id` + a `Commit`/`Rollback`/`Unknown` decision byte), and
`TxnListen` (tag 49, producer→broker, the listener-group registration). All
version-tagged, length-framed, cap-before-alloc, and pinned by byte-freeze
snapshot tests. An unrecognized decision byte folds to the SAFE `Unknown`.

**Durable bookkeeping + recovery.** The back-check schedule + attempt count are
persisted as a new `TXNB` op-record (CRC32C'd, version-tagged, frozen) so they
SURVIVE a broker restart. On replay the attempt count is restored EXACTLY (it is
the terminal-default gate), while the `next_eligible` instant is REBASED against
the live monotonic clock — a persisted absolute monotonic instant is meaningless
across a reboot (the monotonic origin resets), so a recovered txn is promptly
re-eligible with its count preserved and the scan resumes. A `TXNB` record whose
txn later resolved is superseded by the commit/rolled-back op-marker on replay
(never re-enrolled).

**Re-enroll on open — no orphan across a restart-before-first-attempt.** The
`TXNB` record is written only on the FIRST back-check ATTEMPT, so a txn that was
`prepare`d and then survived a restart WITHIN the first timeout window (no attempt
fired yet, no `TXNB` record) would, if the book were rebuilt only from `TXNB`
records, come back `Prepared` but NOT enrolled — never scanned, never
back-checked, never terminal-defaulted: stuck `Prepared` (invisible, undelivered)
FOREVER, the exact orphan this feature exists to clean up. So replay RE-ENROLLS
**every** still-`Prepared` txn into the back-check book, driven off the lifecycle
table's `all_prepared()` (NOT the `TXNB` records): a txn that had a `TXNB` record
keeps its persisted attempt count exactly; a txn with none enrolls FRESH at 0
attempts. The re-enroll is idempotent (a resolved txn is absent from
`all_prepared()`, so it is never re-enrolled) and runs only when there ARE prepared
txns on open, so a non-transactional broker is byte-for-byte unchanged. The code is
the `all_prepared()`-driven loop in `TxnStore::replay`
(`crates/ironbus-storage/src/txn.rs`), proven by
`a_prepared_txn_with_no_back_record_is_re_enrolled_on_replay` (storage) and
`a_prepare_then_restart_before_any_attempt_is_re_enrolled_and_terminal_defaults`
(engine, end-to-end through the terminal default).

**The concrete commit-loss window (the DEFAULT schedule).** A producer that does
not answer a back-check — i.e. does not reconnect and re-register its listener in
time — within roughly `timeout + (max_attempts − 1) × retry` will have its
commit-intent half message terminal-**ROLLED BACK** (discarded, never delivered,
all-or-nothing — never torn). At the production defaults (`timeout` 30 s, `retry`
15 s, `max_attempts` 5) that window is ≈ 30 + 4×15 = **90 s**: after ~90 s of an
unanswered in-doubt txn, the broker safely discards it. Discard is the safe default
— the broker NEVER delivers a message whose outcome it cannot confirm. **Operators
with long local transactions** (a producer that may legitimately take longer than
this to commit/recover) MUST raise `timeout` / `max_attempts` (and/or `retry`) via
`Engine::set_back_check_config` so a slow-but-alive producer is not rolled back out
from under a commit it was about to make.

**Routing to the (re)connected producer.** The broker only writes a producer's
socket from that producer's own pass (thread-per-connection), so the back-check
push rides the producer's listener loop exactly like the L2 confirm drain. The
per-connection `MemberId` changes across a reconnect, so routing is keyed by a
STABLE producer-chosen listener GROUP: a producer registers it via `TxnListen`
(re-registering after a reconnect re-points the route to its new connection); each
half message records its owning group at `prepare`; the scan routes a `TxnCheck`
to whatever connection currently holds that group's listener. THE HEADLINE CASE:
a producer prepares, disconnects before resolve (crash), reconnects and
re-registers its listener, the scan back-checks it, the listener replies `Commit`
→ the half is committed EXACTLY ONCE via the part-1 path (proven by
`the_headline_crash_reconnect_back_check_commit_delivers_exactly_once` in
`engine.rs` and `the_headline_back_check_resolves_a_crashed_producers_half_over_the_wire`
end-to-end in `ironbus-client`).

**Resolution reuses part 1 (the inherited exactly-once + immutability).** A
back-check `Commit` goes through the SAME idempotent `Engine::txn_commit` path
(default-stream exactly-once preserved); a `Rollback` through the same
`txn_rollback`; the back-check NEVER introduces a new commit path. So part 1's
`AlreadyResolved` rule covers every race:

| Race | Outcome |
|---|---|
| producer answers `Commit` twice | the second is a benign idempotent no-op (returns the recorded offset); no second delivery |
| producer answers `Commit` AFTER the terminal `Rollback` already fired | REFUSED (`AlreadyResolved { RolledBack }`) — never a flip, never a double-resolve |
| a duplicate `TxnCheckResult` | a no-op (the txn is already resolved/forgotten) |
| the producer never returns | after `max_back_check_attempts` → terminal `Rollback` (discarded, never delivered) |

**The terminal-default safety net + its limits.** The terminal default is
ALWAYS `Rollback` (discard), never `Commit`: a half message whose outcome is
unknowable is never delivered. It fires through the same idempotent `txn_rollback`,
so a producer's later `Commit` is the refused-flip above, not a double-resolve. A
half message prepared by a producer that NEVER registered a listener is not
routable (the broker cannot reach it), but is still enrolled — the bounded attempt
cap still advances on each scan and the terminal `Rollback` still safely discards
it, so a listener-less producer's crashed half is never stuck forever (it is just
never given the chance to commit it, which is the correct conservative default).
The routing GROUP is the unit of identity: two producers that (mis)register the
SAME group share a listener route, so a deployment must give each producer a
distinct stable group (e.g. its durable producer id).

**Ownership of a back-check answer (the resolve gate).** A `TxnCheckResult` answer
may resolve an in-doubt (`Prepared`) txn ONLY when the answering connection OWNS
the txn's listener group: it must have a REGISTERED listener (a non-empty group via
`TxnListen`) AND that group must EQUAL the group recorded as the txn's owner at
`prepare`. Otherwise the answer is REFUSED (`ERR_TXN_CHECK_UNAUTHORIZED`,
`EngineError::TxnCheckUnauthorized`) and the txn is left exactly as it was —
`Prepared`, on its back-check schedule — so a LEGITIMATE owner's answer can still
arrive; the answering connection is NOT torn down (it is a typed refusal, never a
flip, never a panic). Without this gate, ANY `Publish` connection could
commit/discard ANY producer's in-doubt txn with one forged
`TxnCheckResult{txn_id, decision}` — a cross-producer data-integrity hole. The
headline reconnect case is unaffected: a producer that prepared under group "B",
crashed, reconnected and re-registered `TxnListen{group:"B"}` answers for its own
txn → owner "B" == its group "B" → ALLOWED; a different connection (group "A" or
none) answering for "B"'s txn → REFUSED. A txn that is already resolved (or was
never seen) has nothing in-doubt to protect, so it bypasses the gate straight into
the part-1 idempotent path (a duplicate answer is a benign no-op, a flip is the
inherited `AlreadyResolved` refusal). The gate is a pure in-memory map lookup
keyed off the already-recorded `txn_owner`, so it adds NO hot-path cost to
non-transactional traffic. Code: `Engine::resolve_txn_check` in
`crates/ironbus-server/src/engine.rs` (gated on `TxnBackCheck::owner_group`), proven
by `a_forged_back_check_answer_from_a_non_owner_is_refused_and_leaves_the_txn_prepared`
and `the_owner_group_can_resolve_its_own_back_checked_txn`.

**The listener group is capability-bearing (the auth-layer residual).** The
group-MATCH gate above proves OWNERSHIP, not IDENTITY: a malicious client that
already KNOWS a victim's group name could register that group via `TxnListen` and
then answer (hijack) for the victim's txns. This is the SAME class as "any client
on a no-auth broker can do anything" — the broker's transport, not the back-check,
is the trust boundary. So the listener group must be treated as a **capability**:
when auth is enabled, a deployment SHOULD bind the listener group to the
authenticated principal (reject a `TxnListen` for a group the principal is not
entitled to), and the standing requirement that **two producers must never share a
group** (each uses a distinct stable group, e.g. its durable producer id) is what
keeps ownership unambiguous. The group-MATCH gate is the in-scope fix here; binding
the group to an authenticated principal is the auth-layer follow-up, out of scope
for the no-auth back-check core.
