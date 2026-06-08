# IronBus optional at-rest AEAD encryption

**Status: specified, not yet implemented; tracked by #108.** This document is the
normative design for optional authenticated encryption of segment payloads at
rest. None of it is wired into the binary today. The log and the dead-letter
queue are plaintext on disk right now, exactly as [THREAT_MODEL.md](THREAT_MODEL.md)
states (no auth, no TLS, no at-rest encryption), and the record flag bits
defined today are `COMPRESSED`, `HAS_KEY`, and `HAS_XXH3` (the `KNOWN` set per
[CONTRACTS.md](CONTRACTS.md)); no encryption bit is allocated yet (see
[INVARIANTS.md](INVARIANTS.md), I7). This spec is the child of the security epic
#18 and the sibling of the auth spec ([AUTHENTICATION.md](AUTHENTICATION.md),
#106), the TLS transport spec ([TRANSPORT.md](TRANSPORT.md), #107), and the
secret-handling spec (#109).

This is the device-theft mitigation (threat row T1 in THREAT_MODEL.md), with its
honest limit stated plainly: a key co-located with a stolen device defeats it.

Where this spec constrains an existing surface it cites the issue that owns it,
and it does not imply that surface changes shape. The byte coordinates it adds
sit inside fields the on-disk format already reserves, so the #4 record framing,
the #5 checksum scope, the #6 publish path, and the segment-rolling contract are
all preserved. This document is the authority for the at-rest encryption
contract; the README "encryption at rest" bullet and the THREAT_MODEL
"specified controls not yet implemented" row are summaries that point here. Where
they differ, this document is canonical.

---

## Scope of v1

At-rest encryption is **optional** and **off by default**. A broker that is not
configured with a key writes the existing plaintext v1 format unchanged, byte for
byte, so enabling encryption is a deliberate operator action and a never-encrypted
deployment is never penalized.

In scope for v1:

- Exactly **two** AEAD suites, chosen once at startup by CPU feature detection and
  **recorded in the segment header** so every read is unambiguous: AES-256-GCM
  where the runtime reports a hardware AES implementation (aarch64 crypto
  extensions, x86 AES-NI), and ChaCha20-Poly1305 as the portable constant-time
  fallback everywhere else.
- A **deterministic 96-bit nonce** derived from the segment id and a per-segment
  record counter, so nonce reuse is structurally impossible without trusting an
  RNG that may be weak at early boot.
- **In-place** encryption of the record body within the existing record frame, so
  the #6 publish path and the segment-rolling lifecycle are unchanged and the #5
  checksum is computed over ciphertext.
- A **key-id** (never the key) in the segment header, with **new-segments-only**
  rotation and a defined key-source priority via the #14 config system.
- A **distinct, reported** error class for an unknown key-id or an AEAD tag
  mismatch, routed through the bounded-and-reported recovery-loss path (#8),
  separate from a plain #5 checksum corruption.

Out of scope for v1, deferred and not flagged behind an option (the format and
config simply do not offer them, so an operator cannot select a mode that does not
exist):

- Re-encrypting existing history on rotation. Rotation is new-segments-only;
  sealed segments keep the key-id they were written under.
- Per-record or per-tenant keys. v1 is one active write key per broker, plus any
  number of read-only prior keys for rotation.
- Encrypting the consumer-cursor checkpoints, the counters checkpoint, the
  quarantine store, or the segment header and footer themselves. v1 encrypts
  record payload bodies only; the framing and recovery metadata stay in the clear
  so recovery can run without the key (see "What is and is not encrypted").
- Key escrow, a network key server, or a hardware-token PIN flow. Key material is
  sourced locally per "Key sourcing".

---

## What is and is not encrypted

The unit of encryption is the **record body** as defined by #4: the `key`,
`headers`, and `payload` bytes in wire order, the same contiguous range the #5
`body_crc` already covers (see [CONTRACTS.md](CONTRACTS.md), the RecordTrailer and
the xxh3-64 field). Everything outside that range stays in the clear so recovery,
retention, and offset lookups work without the key:

| On-disk bytes | Encrypted in v1? | Why |
|---|---|---|
| Record body (`key` + `headers` + `payload`) | **Yes** | the confidential message content; this is the asset T1 protects |
| Record header (magic, version, flags, lengths, sequence, `header_crc`) | No | recovery must read the length and sequence to walk the log without the key |
| Record trailer (`body_crc`, `total_len`) and the optional xxh3-64 | No | the checksums gate resync and bound-loss recovery without the key (see "Checksums over ciphertext") |
| Segment header and footer | No | they carry the AEAD suite, key-id, and segment id the reader needs to even attempt a decrypt |
| Cursor / counters checkpoints, DLQ metadata, quarantine blobs | No (v1) | deferred; the DLQ preserves the original record verbatim, so a DLQ'd ciphertext body stays ciphertext, but the DLQ metadata is plaintext |

Encrypting the body but not the lengths is a deliberate, disclosed trade. An
offline attacker still learns the per-record body length, the record count, the
sequence numbers, and the timing (`created_unix_ms`) of a sealed segment. v1
treats message **content** confidentiality as the goal and **does not** claim to
hide message size or count. An operator who needs size-hiding must pad at the
producer; v1 does not pad.

---

## AEAD suite selection and the segment-header record

### The two suites

| Suite | Selected when | Key | Nonce | Tag |
|---|---|---|---|---|
| `AES_256_GCM` | the runtime reports hardware AES (aarch64 crypto extensions, x86 AES-NI) | 256-bit | 96-bit | 128-bit |
| `CHACHA20_POLY1305` | otherwise (the portable constant-time fallback) | 256-bit | 96-bit | 128-bit |

Both are 256-bit-key, 96-bit-nonce, 128-bit-tag AEADs, so the key material and the
nonce construction below are identical across suites; only the primitive differs.
AES-256-GCM is selected **only** where the CPU exposes a constant-time hardware AES
path, because a software AES-GCM is both slow and a timing-side-channel risk on a
small device. ChaCha20-Poly1305 is constant-time in portable software and is the
default everywhere hardware AES is not reported, so an edge target with no AES
extensions still gets a safe, fast AEAD.

### Detection is at startup, the choice is recorded

The suite is chosen **once, at broker startup**, by CPU feature detection (the same
detection the platform runtime exposes; on x86 this is the AES-NI bit, on aarch64
the AES crypto-extension bit). The detection result is not re-evaluated per record
or per segment. The chosen suite is then **written into the header of every
segment the broker seals**, so a reader never has to guess and never depends on the
reader's own CPU matching the writer's. A segment written under AES-256-GCM on an
AES-NI host is read back correctly on a ChaCha-only host, because the reader honors
the recorded suite, not its own detection.

This closes the otherwise-silent ambiguity where a different host (or a
different binary build) would decrypt with the wrong primitive and surface as a tag
mismatch. The suite is data, not inference.

### Segment-header coordination with #4 / #5 (no framing drift)

The encryption metadata reuses fields the v1 segment header **already reserves**,
so the 64-byte `SegmentHeader` keeps its frozen offsets and CRC scope (see
CONTRACTS.md, "SegmentHeader (on-disk, 64 bytes)"). Today bytes `[44, 60)` are
reserved-zero and the `flags` u16 at `[10, 12)` is reserved-and-preserved. v1
at-rest encryption uses them as follows, and changes no other offset:

| Field | Existing v1 meaning | At-rest-encryption use |
|---|---|---|
| `flags` u16 `[10, 12)` | reserved, preserved, not interpreted | one bit becomes `SEGMENT_ENCRYPTED`; the rest stay reserved-zero |
| reserved `[44, 60)` (16 bytes) | zero | `aead_suite` u8, then a `key_id` (a fixed-width identifier, never the key), the rest reserved-zero |
| `header_crc` u32 `[60, 64)` | CRC32C over `[0, 60)` | unchanged: it already covers the `flags` and reserved bytes, so the suite and key-id are CRC-protected for free |

The reserved bytes `[44, 60)` are owned by at-rest encryption alone. Optional
key-based compaction ([COMPACTION.md](COMPACTION.md)) does NOT use `[44, 60)`: it
puts its covered-range metadata in a CRC-protected v2 compaction-metadata block in
the footer region and uses only a separate `COMPACTED` flag bit, so a segment that
is both compacted and encrypted carries the `aead_suite` + `key_id` here AND the
covered range in its footer block without collision.

Because `header_crc` already covers `[0, 60)`, the suite byte and the key-id are
integrity-protected the moment they are written, with no new checksum and no
offset move. A future, encryption-aware reader that meets an `aead_suite` VALUE
it does not understand refuses with an unsupported-format error, the same
refuse-on-unknown discipline the v1 `version` and `checksum_algo` VALUES already
use (per [COMPATIBILITY.md](COMPATIBILITY.md)). A genuinely old, pre-encryption
reader is protected by a different mechanism, because unknown segment-header and
record flag BITS are preserve-and-ignore (not refuse-on-unknown), so the
`SEGMENT_ENCRYPTED` bit alone would not stop it. Instead the 16-byte AEAD tag
inflates each record's on-disk length beyond what its plaintext `key_len` /
`hdr_len` / `payload_len` fields declare, so the existing `codec::decode`
total-length self-check rejects the frame as `BadLength` and recovery classifies
it as record corruption. Either path is a hard rejection, never a silent
plaintext read. A reader that finds `SEGMENT_ENCRYPTED` clear reads the body as
plaintext exactly as today.

A corresponding record-level `ENCRYPTED` flag bit is reserved in the record `flags`
byte (today only `COMPRESSED`, `HAS_KEY`, `HAS_XXH3` are defined, per CONTRACTS.md;
the byte has reserved space). Per-segment uniformity is the v1 rule: every record
in an encrypted segment is encrypted under that segment's suite and key-id, so the
record bit and the segment flag always agree, and a decode that finds them
disagreeing is a `BadLength`-class rejection, consistent with how decode already
rejects a `HAS_KEY` or `HAS_XXH3` flag that disagrees with the lengths.

When `COMPRESSED` and `ENCRYPTED` are both set, the order is **compress then
encrypt**: the body is compressed first and the ciphertext is the AEAD of the
compressed bytes, so the encryption sees high-entropy input and the checksum and
the AEAD both cover the final on-disk ciphertext. (Compression itself, #12 / #139,
is also specified-not-implemented; this only fixes the ordering for when both
land.)

---

## Deterministic nonce and the no-reuse argument

The 96-bit AEAD nonce is **deterministic**, not random:

```
nonce[96] = segment_id[64] || record_counter[32]
```

- `segment_id` is the same monotonic 64-bit identifier already in the segment
  header (`[12, 20)`), and IronBus **never recycles a segment id** (ADR 0002, the
  never-recycle id rule, cross-checked in COMPATIBILITY.md). So the high 64 bits
  are unique per segment for the life of the log.
- `record_counter` is a **per-segment** monotonic 32-bit counter that starts at 0
  for the first record in a segment and increments by one per record. It is not
  stored per record; it is derived deterministically from the record's position in
  the segment during both write and recovery (the same position the recovery
  scanner already walks), so it costs no extra on-disk bytes.

### Why reuse is structurally impossible

GCM (and ChaCha20-Poly1305) nonce reuse under a fixed key is catastrophic: it
leaks the XOR of two plaintexts and, for GCM, can forge the authentication tag. v1
prevents it **structurally**, without trusting any RNG:

1. **Within a segment**, `record_counter` is strictly increasing and never repeats,
   so two records in the same segment never share a nonce.
2. **Across segments**, `segment_id` is unique and never recycled, so the high 64
   bits differ, so no two records in two different segments share a nonce, even at
   the same `record_counter`.
3. **Across a key**, because rotation is new-segments-only and each new segment
   gets a fresh, never-recycled `segment_id`, the (segment_id, counter) space
   under any one key is collision-free by construction.

A 32-bit per-segment counter caps a single segment at 2^32 records before the
counter would wrap. This bound is airtight regardless of the configured
`max_segment_bytes`: a segment's own `record_count` is a `u32`, and
`SegmentWriter::append` refuses with `SegmentFull` at `record_count == u32::MAX`,
so a segment can never hold more than `u32::MAX` records no matter how large the
byte budget is set. The default 64 MiB (8 MiB edge) segment holds far fewer
(around 1.5M records at 64 MiB), so the counter never approaches the wrap point
within a real segment. The roll to a new segment, which the #6 / segment-rolling
contract already triggers on size, is itself the guarantee that the counter is
reset only alongside a fresh `segment_id`.

The decisive property: **this construction needs no randomness at all.** It does
not draw a nonce from an RNG, so it cannot be defeated by a low-entropy early-boot
`/dev/urandom` on a freshly provisioned edge device. The classic random-96-bit-GCM-nonce
birthday-bound reuse risk (and the early-boot-entropy risk that makes it worse on
embedded hardware) is removed by construction rather than mitigated by hoping the
RNG is good.

The nonce is reproducible by any reader from data already on disk (the segment id
in the header and the record's ordinal position), so it is **not stored** per
record and adds no framing bytes.

---

## In-place encryption within the existing frame (the #6 contract unchanged)

Encryption happens **in place** inside the existing record body, so the publish
path (#6) and the segment-rolling contract keep their exact shape:

1. The producer's body (`key` + `headers` + `payload`, after the optional
   compress step) is the AEAD **plaintext**.
2. The writer computes the deterministic nonce from the active segment's id and the
   record's per-segment counter, encrypts the body with the active suite and key,
   and writes the resulting **ciphertext** (same length as the plaintext, since GCM
   and ChaCha20-Poly1305 are stream-cipher AEADs) plus the 128-bit **tag** into the
   record frame.
3. The tag is appended to the body region (immediately after the ciphertext,
   before the optional xxh3-64 and the trailer) and is counted in `total_len`, so
   `total_len` stays the single source of truth for the frame length. An encrypted
   record's body is therefore `plaintext_len + 16` bytes; the `key_len`,
   `hdr_len`, and `payload_len` header fields continue to describe the
   **plaintext** lengths, and the 16-byte tag is the only size delta, flagged by
   `ENCRYPTED` exactly as the 8-byte xxh3-64 is flagged by `HAS_XXH3`.
4. The append, the fdatasync-before-ack durability boundary, the offset
   assignment, and the segment roll are **byte-for-byte the same control flow** as
   the plaintext path. Encryption is a transform of the body bytes between "the
   producer handed us a body" and "we frame and append it"; it does not move the
   durability boundary, does not change when an ack is returned, and does not change
   when a segment rolls. The #6 eight-step publish path (CONTRACTS.md, the publish
   diagram) is unchanged; only the bytes written into the body differ.

Because the ciphertext is the same length as the plaintext plus a fixed 16-byte
tag, the segment-size accounting and the roll trigger see a small, constant,
predictable per-record delta and nothing else. There is no chunking, no separate
encryption stream, and no second file.

---

## Checksums over ciphertext (#5), and the read/verify order (I7)

The #5 checksums are computed over the **ciphertext**, not the plaintext:

- `body_crc` (CRC32C) covers the on-disk body byte range, which for an encrypted
  record is the **ciphertext plus the tag**, exactly the bytes written. The xxh3-64
  (for records at or above the 64 KiB threshold) covers the same on-disk range.
- This is the only choice that keeps corruption detection working **without the
  key**: recovery can verify the CRC, detect bit-rot or a torn tail, and bound loss
  on a segment it cannot decrypt, because the CRC is over the literal bytes on
  disk.

The verify order on read realizes the I7 "integrity before transform" invariant
([INVARIANTS.md](INVARIANTS.md), I7), whose decrypt half is exactly this spec:

```
1. verify header CRC32C        (frame structure intact)
2. verify body CRC32C          (on-disk ciphertext bytes intact)   <- #5, key-free
3. verify xxh3-64 if present   (independent large-record check)    <- #5, key-free
4. AEAD-decrypt + verify tag   (authenticity + confidentiality)    <- #108, needs key
```

CRC first means a bit-flip in the stored ciphertext is caught and classified as
ordinary corruption (a #5 `CorruptRecordBody`, the existing reason code) **before**
the broker ever attempts a decrypt, so a corrupted ciphertext never masquerades as
a key problem. Only after the CRC passes does the broker attempt the AEAD decrypt;
a tag failure at that point is therefore **not** bit-rot (the CRC already vouched
for the bytes) but a genuine authenticity failure (wrong key, rotated key, or a
forgery), and is reported as its own distinct class (next section).

Note the honest layering: a CRC is not a cryptographic integrity check (it never
was, see THREAT_MODEL.md, T-file), but the **AEAD tag is**. Once encryption is on,
the tag, not the CRC, is the cryptographic authenticity guarantee on the body; the
CRC remains the cheap, key-free resync and bit-rot gate that bounds recovery loss.
The two layers do different jobs and v1 keeps both.

---

## Key-id in the header; rotation is new-segments-only

The segment header stores a **`key_id`** (a stable, fixed-width identifier for the
key, for example a short label or a truncated hash of the key, decided in #14),
**never the key itself**. The key bytes never touch the log. On read, the broker
looks up the loaded key whose id matches the segment's `key_id` and uses it to
decrypt every record in that segment.

Rotation is **new-segments-only**; history is **never re-encrypted**:

- Rotating the active write key means: load the new key, mark it the write key, and
  from the next sealed segment onward the header records the new `key_id`. Already-sealed
  segments keep the `key_id` they were written under and are **not** rewritten.
- A broker therefore must keep the **old keys loadable** as long as it retains
  segments written under them. The set of loaded keys is "the current write key
  plus every prior key whose segments are still on disk." Once retention (#13)
  reaps the last segment written under an old key, that key may be dropped.
- This makes rotation O(1) and crash-safe: there is no bulk re-encryption pass to
  interrupt, and a rotation that is interrupted mid-way simply leaves some sealed
  segments on the old key and the active one on the new key, which is the normal,
  well-defined state.

The honest cost of new-segments-only rotation is recorded plainly: rotating the key
does **not** retroactively protect already-written data against a key that was
already compromised. If an old key is believed compromised, the protection is to
reap the segments under it (retention) and accept that anything an attacker already
copied under that key is exposed. Rotation limits the **future** blast radius of a
key; it cannot un-expose the past.

### Key sourcing (priority, defined via #14)

Key material is sourced locally, by the #14 configuration system, in this priority
order. The first source that yields a key wins; a configured-but-unreadable source
is a fatal startup error, not a silent fall-through to a weaker source:

1. **TEE-sealed key, where a trusted execution environment is present.** The
   strongest local custody: the key is sealed to the device's TEE and unsealed only
   in the secure world, so it is not readable from a cold disk image alone. Used
   automatically where the platform exposes it.
2. **Raw key file** (a 32-byte key in a file referenced by #14). The file is
   subject to the same fail-closed permission check as every other secret-bearing
   file (#109): the broker refuses to start if it is group- or world-readable.
3. **Argon2id-derived from a passphrase.** A passphrase is stretched with Argon2id
   at the edge-tuned parameters the auth spec already fixes (m = 19 MiB, t = 2,
   p = 1, per AUTHENTICATION.md), with a stored, non-secret salt, into the 256-bit
   key. This lets an operator key a device from a memorized passphrase without a
   key file, at the documented cost that the passphrase strength is now the key
   strength.

The priority is fixed so the **strongest available** custody is used without an
operator having to remember to ask for it, and so a misconfiguration cannot
silently downgrade from a TEE-sealed key to a passphrase. Exactly one key is the
active write key at a time; the others (prior write keys) are loaded read-only for
rotation. The full #14 key-config schema (the config keys, their names, and the
loader precedence resolver) is owned by #14 and #109; this spec fixes only the
priority and the never-store-the-key rule.

---

## Distinct reported failure classes via #8 (not silent)

The single most dangerous failure this spec must prevent is a **wrong or rotated
key yielding undecryptable data behind a passing checksum** that looks like a clean
read or like silent loss. v1 makes it loud. Two new failure classes are defined,
each **distinct** from a plain #5 checksum corruption and each routed through the
bounded-and-reported recovery-loss path (#8, the `LossReport` / `LossEvent` /
`ReasonCode` vocabulary in [schemas/loss-report.v1.md](schemas/loss-report.v1.md)):

- **Unknown key-id.** A segment whose header `key_id` matches **no loaded key**.
  The broker cannot decrypt that segment's records at all. This is reported as its
  own `ReasonCode` (a new appended variant, for example `UnknownKeyId`), not as a
  checksum corruption, because the bytes are fine and the only problem is a missing
  key. An operator reading the loss report sees "you are missing key X for segment
  S," which is an actionable key-management error, not "your disk is corrupt."
- **AEAD tag mismatch.** A segment's `key_id` matches a loaded key, the CRC over
  the ciphertext passed, but the **AEAD tag fails**. This means the bytes are
  intact (CRC vouched for them) yet do not authenticate under the named key: a
  wrong key bound to that id, a key/id mismatch, or a forgery. Reported as its own
  `ReasonCode` (a new appended variant, for example `AeadTagMismatch`), again
  distinct from `CorruptRecordBody`.

Both are appended to the frozen `ReasonCode` vocabulary following the append-only
rule (a new reason gets a new number, name, and metric label; existing reasons,
the v1 set `TornTail` / `CorruptRecordHeader` / `CorruptRecordBody` /
`CorruptSegmentHeader` / `SequenceGap`, are never renumbered or renamed, and adding
a variant does not bump `LossReport::SCHEMA_VERSION`, per the loss-report schema's
versioning policy). They flow through the same bounded-loss machinery as every
other recovery loss: each is a counted `LossEvent` with a byte span, subject to the
I3 per-event and global loss caps, so a flood of undecryptable segments **fails
closed** with `ExcessiveRecoveryLoss` rather than silently dropping unbounded data
(the same #8 / #120 bounded-and-reported-loss guarantee that already covers
corruption).

The separation is the point. A reviewer or operator can tell apart, at a glance and
from a stable machine-readable code:

| Symptom | Reason class | What it means |
|---|---|---|
| Bytes changed on disk | `CorruptRecordBody` (#5, existing) | bit-rot / torn write; the key is irrelevant |
| Header names a key you do not have | `UnknownKeyId` (#108, new) | a key-management gap; load the key, the data is fine |
| Bytes intact, tag fails under the named key | `AeadTagMismatch` (#108, new) | wrong/rotated key or forgery; do NOT treat as corruption |

A wrong or rotated key therefore can **never** look like a passing read, like a
silent skip, or like ordinary corruption: it is always a named, counted, reported
event with its own reason code. This is the explicit answer to the issue's
"critical failure" concern.

---

## The honest limit: a co-located key defeats at-rest encryption

At-rest encryption defends exactly one threat: an attacker who obtains the **disk
or its image** (T1, physical device theft, offline read) **without** the key. It
does **not** defend against an attacker who obtains the key along with the disk.

If the encryption key is stored on, or alongside, the same device that is
physically stolen, the encryption is defeated: the thief has both the ciphertext
and the key. A raw key file on the same disk, a passphrase written on the device, a
key in an environment file in the same image, all reduce at-rest encryption to a
speed bump. This is an **accepted residual risk** of any device-resident key,
already recorded in THREAT_MODEL.md ("At-rest encryption does not defend a
co-located key (T1)"), and it is why the key-sourcing priority above prefers a
**TEE-sealed** key where one exists: a key sealed to the device's secure world is
not readable from a cold disk image alone, which is the one local custody that
meaningfully resists device theft. Where there is no TEE, the operator must keep
the key off the device (a removable key, a passphrase the operator carries) for the
encryption to mean anything against theft.

Stated bluntly so no reader takes false comfort: **at-rest encryption with a
co-located plaintext key protects against a stolen disk, not a stolen device.**

---

## Interaction summary (which contracts this spec touches)

| Contract | Interaction | Net effect |
|---|---|---|
| #4 record / segment layout | adds the `ENCRYPTED` record flag bit (reserved space exists), the `SEGMENT_ENCRYPTED` segment flag bit, and `aead_suite` + `key_id` in the segment header's reserved `[44, 60)` bytes | no offset moves; frozen header CRC already covers the new fields |
| #5 checksums | CRC32C and xxh3-64 are computed over the on-disk **ciphertext + tag** | corruption detection works without the key; verify order is CRC then decrypt (I7) |
| #6 publish path | encryption is an in-place body transform before framing | the eight-step path and the fdatasync-before-ack durability boundary are unchanged |
| #7 recovery / #8 bounded reported loss | unknown key-id and tag mismatch are new appended `ReasonCode`s routed through the loss report under the I3 caps | distinct from corruption; fail-closed, never silent |
| #13 retention | a key may be dropped once the last segment under it is reaped | rotation is new-segments-only; old keys live as long as their segments |
| #14 config | key sourcing (TEE-sealed > raw key file > Argon2id passphrase), fail-closed | priority fixed here; the config-key schema is owned by #14 / #109 |
| #109 secret handling | the key file is subject to the fail-closed permission refuse-to-start check | a group/world-readable key file aborts startup |

---

## Specified, not implemented

Nothing in this document exists in the binary today. There is no AEAD crate in any
`Cargo.toml`, no encryption record-flag bit defined (only `COMPRESSED`,
`HAS_KEY`, `HAS_XXH3`), no `aead_suite` or `key_id` written to any segment header,
no `UnknownKeyId` or `AeadTagMismatch` reason code, and no key loader. The segment
header's reserved bytes and the record `flags` byte's reserved space are exactly
that today: reserved and zero. This is the design these will implement, tracked by
#108 under the security epic #18.
