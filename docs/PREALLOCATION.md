# Cross-platform segment preallocation, and why v1 never recycles a segment

This document specifies how IronBus preallocates the active segment to its full roll
size in a portable way, and resolves the open question of whether sealed-then-deleted
segments are recycled. The preallocation primitive is now IMPLEMENTED (#330): the IO seam
carries a `RandomAccessFile::preallocate(len)` method, `start_segment` preallocates each
new active segment to the roll size best-effort, and the production `StdFile` reserves
real blocks per OS (Linux `fallocate` with `FALLOC_FL_KEEP_SIZE`, macOS
`fcntl(F_PREALLOCATE)`), falling back to today's grow-on-append on a filesystem that
supports neither. The recycling question is RESOLVED, not deferred: in v1 a segment is
never recycled, for the at-rest-encryption nonce reason recorded in
[ADR 0002](adr/0002-segments-never-recycled-in-v1.md).

It complements [WAL.md](WAL.md) (the file lifecycle and the fsync model) and
[CONTRACTS.md](CONTRACTS.md) (the frozen 64-byte segment header). The IO seam it builds
on is `crates/ironbus-storage/src/io.rs` (`RandomAccessFile`) and
`crates/ironbus-storage/src/fs.rs` (`Filesystem`).

The tagline promises CROSS PLATFORM. The shipped durability primitives already meet that
bar on Linux and macOS (the production targets), but the #135 draft assumed Linux
`fallocate` for preallocation, which neither builds on macOS or Windows nor maps to one
syscall across them. This spec closes that portability hole by defining a thin
four-primitive shim instead of a single Linux-only call.

---

## The four-primitive shim

IronBus storage already reaches the filesystem only through two seams, never through raw
syscalls: per-file IO through `RandomAccessFile` (`io.rs`) and the data directory through
`Filesystem` (`fs.rs`). Portable durability is the property that the small set of
primitives those seams expose each have a correct per-OS implementation. Three of the
four already exist in the seam; preallocation is the one this spec adds.

| # | Primitive | Seam method (today) | Status |
|---|---|---|---|
| a | **preallocate** | `RandomAccessFile::preallocate(len)` | IMPLEMENTED (`io.rs`, #330) |
| b | **file-datasync** (fdatasync) | `RandomAccessFile::sync_data` | IMPLEMENTED (`io.rs`) |
| c | **directory-sync** | `Filesystem::sync_dir` (free `io::sync_dir` on Unix) | IMPLEMENTED (`fs.rs`, `io.rs`) |
| d | **sealed-read-map** (positioned reads of an immutable sealed segment) | `RandomAccessFile::read_at` / `read_exact_at` | IMPLEMENTED (`io.rs`) |

Primitives (b), (c), and (d) are unchanged by this spec and are documented where they
live: the fdatasync-versus-fsync metadata contract and the macOS `F_FULLFSYNC` barrier in
`io.rs` and [WAL.md](WAL.md), the directory-entry durability model in `fs.rs`. This
document specifies (a) and how it slots onto the seam without disturbing the other three.

### Why a sealed-read-map primitive, not mmap

"Sealed-read-map" is the *logical* primitive a consumer needs: random positioned reads of
an immutable, already-sealed segment, served lock-free while the single writer appends to
a different (active) file. In v1 that primitive is the positioned `pread` path
(`read_at`), NOT a memory map: there is no mmap in storage (confirmed in RAM_BUDGET.md), so
a segment read costs a syscall, not an address-space mapping. The primitive is named for
its contract (positioned reads of a sealed file) so a future mmap-backed implementation
could satisfy the same contract on a platform where that wins, without the rest of the
engine knowing. v1 satisfies it with `pread`/`ReadFile`-positioned IO on every target.

---

## Preallocation: specified behavior

### Default ON, the active segment, to full roll size

Preallocation is **default ON**. When a new active segment is created (`Log::open` for the
first segment, `Log::start_segment` on every roll), the file is preallocated to the
configured roll size (`LogConfig::max_segment_bytes`, default 64 MiB; 8 MiB at the edge
size) BEFORE the first record is appended. The file's *logical length* still grows with
appends as today (the write position is the append cursor, not the preallocated end); what
preallocation changes is that the *physical blocks* backing those bytes are reserved up
front, in one call, rather than block by block as each append extends the file.

A knob to disable it for filesystems or operators that prefer not to (`preallocate`,
default `true`) is a forward config key (there is no TOML config in code yet; see
CONTRACTS.md), coordinated with #14 like the other storage knobs. The IMPLEMENTED v1
wiring is unconditional-but-best-effort: `start_segment` always attempts the reservation
and SWALLOWS any failure, falling back to grow-on-append, so disabling the optimization is
already the natural behavior on any filesystem that cannot reserve. Exposing the explicit
`preallocate = false` knob (to skip the attempt entirely) rides the same #14 config plumbing
as the other storage knobs and is deferred to it.

### The wear and latency rationale (Edge First)

Preallocating the active segment to full roll size buys two things that matter most on an
edge node:

- **Contiguity.** One up-front reservation lets the filesystem place the segment as one
  contiguous (or near-contiguous) extent instead of growing it a block at a time as
  appends arrive. A contiguous file reduces fragmentation and keeps sequential append and
  sequential recovery scan fast on the slow flash an edge device runs on.
- **One fewer fdatasync cost per commit.** When a file grows, its *length* is metadata. On
  the grow-on-append path, the commit `fdatasync` (the I2 ack-implies-durable barrier in
  INVARIANTS.md) must also persist that the file got longer, an inode-metadata update on
  most filesystems. Preallocating the blocks up front means the steady-state append writes
  into already-allocated space, so the per-commit `fdatasync` flushes record DATA without
  also forcing an inode-metadata write on every commit. Fewer metadata writes is directly
  less flash wear and lower, more predictable commit latency, which is the Edge First
  tenet: trade a single larger up-front allocation for steadier, cheaper steady-state
  commits.

This is the same reasoning that makes the log-is-WAL single-file design (ADR 0001) win on
flash: minimize write amplification on a device that is already wearing.

### ENOSPC at roll is a fail-fast event, not a mid-stream surprise

Reserving the whole roll size up front means a disk that cannot hold another full segment
fails at SEGMENT CREATION, deterministically, instead of partway through filling the
segment when an append happens to land on the first unbacked block. This is a feature: the
out-of-space condition surfaces at the roll boundary, where the engine already has a clean
overflow path, not as a surprise mid-append.

An `ENOSPC` (or any allocation failure) from the preallocate call at roll is routed to the
existing disk-full / overflow handling, NOT a new code path:

- It is reported as the same non-fatal `StorageError::AtCapacity` the byte-cap overflow
  uses (WAL.md, "Overflow"), so the engine's `disk_full_policy` (#10) decides: `DropNew`
  sheds the produce and tells the producer promptly via `AtCapacity` with the
  `produce_rejected` counter; `DropOldest` runs the reaper / `reap_oldest_forced` to free
  a whole sealed segment (#13) and retries the roll. The writer stays live; a later roll
  succeeds once retention frees space.
- The active segment is never half-preallocated into an inconsistent state: a failed
  preallocate at roll leaves the new segment uncreated (or removed on the failure path),
  so recovery sees the prior sealed chain plus a still-appendable active segment, exactly
  the state it already handles.

This is precisely the "ENOSPC during preallocation becomes a fail-fast-at-roll event,
which #10 and #13 handle cleanly rather than a mid-stream surprise" property the issue
calls for, and it reuses the shipped overflow path rather than inventing one.

### The zero-fill end-of-data interaction (a recorded hazard)

Preallocation interacts with the recovery end-of-data rule, tracked as R13 in the design
risk hunt (RISK_REGISTER.md, RR-06 residual risk). The shipped torn-tail recovery finds
the active segment's end of data by scanning records forward and stopping at the first
non-record bytes; preallocated tail blocks read back as zeros. A future implementation
MUST ensure the recovery scan distinguishes "preallocated-but-unwritten zero tail" from
"a real record," which the existing framing already does (a zero region is not a valid
record header: the magic and `header_crc` fail), so recovery truncates the unwritten tail
exactly as it truncates a torn one. This spec records the requirement; the
implementing PR carries the recovery-scan test that pins it on a preallocated file.

---

## Per-OS implementation and durability notes

Preallocate has a different syscall on each target, which is the whole reason for a shim
rather than a raw `fallocate`. Each maps to the same logical contract: reserve `len`
backing blocks for the file without changing the bytes a reader sees, then make that
reservation effective for the steady-state appends that follow.

The implemented form uses the KEEP-SIZE variant on every OS: it reserves blocks WITHOUT
advancing the file's logical length. This is load-bearing, and is a refinement of the
earlier draft (which paired the reservation with an `ftruncate`/`posix_fallocate`
size-grow): the append cursor is the logical end of data, and both recovery's torn-tail
scan and the offline `dump`/`scrub` tools find the end of data from `file.len()`. If
preallocation grew the logical length to the full roll size, every reader would see a
multi-MiB zero tail and (correctly, but needlessly, and breaking the offline-tool output)
report it as a zero window. Keeping the size means the logical length still grows only
with appends, which land in the already-reserved blocks. So the macOS `ftruncate` pairing
is dropped, and Linux uses `FALLOC_FL_KEEP_SIZE`.

| OS | Primitive | Reserves real blocks? | Durability note |
|---|---|---|---|
| **Linux** (production, musl) | `fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, len)` | Yes | `fallocate` reserves real extents and `FALLOC_FL_KEEP_SIZE` leaves the logical size unchanged; the steady-state append then writes into allocated blocks, so the commit `fdatasync` need not also persist a length-grow. On a filesystem that does not support allocation (`EOPNOTSUPP`/`ENOSYS`, rare on ext4/f2fs/xfs, the edge targets) it falls back to no-prealloc (grow-on-append). A genuine `ENOSPC` is surfaced (not swallowed) at the seam. The block reservation itself is not the durability barrier: the I2 commit `fdatasync` still is. |
| **macOS** (developer, CI) | `fcntl(fd, F_PREALLOCATE)` with `F_ALLOCATECONTIG` then `F_ALLOCATEALL` (NO `ftruncate`) | Yes (contiguous if possible) | `F_PREALLOCATE` reserves blocks and does NOT advance the file's logical size, which is exactly the keep-size reservation wanted, so no `ftruncate` pairing is used. On macOS the durability barrier is `F_FULLFSYNC`, which `std` already issues for both `sync_data` and `sync_all` (see `io.rs`); preallocation does not change that, it only removes the per-commit length-grow. If `F_PREALLOCATE` returns `ENOTSUP`, it falls back to no-prealloc (grow-on-append); any other error is surfaced. |
| **Windows** (v1 non-goal; flagged for #17) | `SetFilePointerEx(fd, len)` then `SetEndOfFile(fd)` to set the size; optionally `SetFileValidData` to mark the range valid without zeroing | Size set; blocks valid only with `SetFileValidData` | `SetFilePointerEx` + `SetEndOfFile` set the file size but leave the range as a zeroing-on-first-write valid-data region, so the wear/latency benefit is partial unless `SetFileValidData` is used. **`SetFileValidData` requires the `SE_MANAGE_VOLUME_NAME` privilege** and exposes previously-deleted disk contents in the unwritten range, so it is a deliberate, privileged opt-in, never the default. Without it, Windows preallocation sets the size (avoiding repeated grows) but the OS still zeroes-on-write; the durability barrier on Windows is `FlushFileBuffers`. Windows is a v1 NON-GOAL (the production targets are Linux musl and macOS; `io.rs` ships only the trait and `InMemoryFile` off Unix), so this row is the SPECIFIED Windows mapping for when the build matrix (#17) adds it, not shipped code. |

The common fallback ladder on every OS is: **keep-size block reservation, then no-prealloc
(grow-on-append)** when the filesystem reports it cannot allocate. The implementation drops
the intermediate set-size / zero-fill rungs the draft listed precisely because they would
advance the logical length (the very thing the keep-size form avoids), so they are not
correct keep-size rungs. Both surviving rungs are correct for durability; the lower rung
only gives up the wear/latency benefit, never the ack-implies-durable guarantee (which is
always the commit `fdatasync`, independent of preallocation). Falling back to
grow-on-append is exactly the shipped v1 behavior, so a platform that supports no
keep-size reservation primitive (any non-Linux, non-Apple Unix, or an unsupported
filesystem) degrades to today's code, not to an unsafe one.

---

## How it maps onto the existing IO seam

The preallocate primitive slots onto `RandomAccessFile` (`io.rs`), the same seam
`sync_data` / `read_at` / `set_len` already use, so an implementation drops in without new
plumbing:

- The trait method is `fn preallocate(&self, len: u64) -> io::Result<()>` with a DEFAULT
  no-op body, so adding it is non-breaking and IO-free-safe for the simulation. The default
  is a literal no-op (`Ok(())`): a backend with no reservation primitive degrades to
  grow-on-append, which is correct. The in-memory `InMemoryFile` overrides it to TRACK the
  requested reservation (a high-water `preallocated_to`) WITHOUT changing its bytes or its
  logical length, mirroring the real keep-size reservation. This is deliberate over a
  `set_len`-extend: a set-len would zero-fill the in-memory image to `len` and diverge the
  deterministic disk image (the determinism and crash-recovery sweeps assert byte-identical
  images and exact truncated-tail counts), whereas a tracked reservation keeps a
  preallocated active segment byte-identical to a grow-on-append one while still letting a
  test assert the roll-size reservation was requested.
- The production `StdFile` (Unix) overrides it with the per-OS syscall above. `StdFile`
  already exposes `from_file` for "a preallocated or handed-off descriptor" (`io.rs`), so
  the preallocation can also be done at create time and handed in; the trait method is the
  in-place form used on roll.
- The directory-level `Filesystem` seam (`fs.rs`) is UNCHANGED: preallocation is a
  per-file concern, and `create_new` + `sync_dir` already give the crash-safe create
  ordering (file `sync_all`, then directory `sync_dir`, then ack) that a preallocated
  segment also uses. Preallocate runs after `create_new` and before the first append, on
  the file handle `create_new` returns.

The deterministic simulation exercises the preallocate path (a preallocated active segment,
appends into it, a power loss, a recovery scan that recovers the longest valid prefix and
drops the unwritten tail) with no new fault model: because the in-memory backend tracks the
reservation without changing bytes, a preallocated segment IS a grow-on-append one to the
simulation, so the existing determinism, crash-recovery, and invariant sweeps cover it, and
the implementing PR adds the explicit `start_segment`-preallocates-the-roll-size,
empty-segment-recovers-as-empty, partial-segment-recovers-longest-prefix, and
preallocate-failure-is-non-fatal tests.

> Implementation note (#330): the trait method ships with a no-op default body, so adding it
> is non-breaking and keeps `ironbus-core` IO-free (the primitive lives in `ironbus-storage`,
> not core). The one place `unsafe` appears is the thin per-OS libc FFI wrapper for
> `fallocate`/`fcntl(F_PREALLOCATE)` in `StdFile`, each call carrying a `// SAFETY:` argument
> (a plain syscall over a valid owned fd and a fully-owned struct, no memory aliasing), under
> the workspace `unsafe_code = "warn"` + `#[allow(unsafe_code)]` convention the existing
> `clock.rs`/`broker.rs` libc calls already use. `libc` (a pure-Rust binding, no vendored C)
> is reused, not added: it is already in the workspace tree and on the `deny.toml`
> pure-Rust-syscall allow-list. No panic on a library path; no `ironbus-storage` test regresses.

---

## Recycling: resolved, not deferred

The #40 / #135 draft proposed recycling up to 2 sealed-then-deleted segment files: zero
them, rename them, and reuse them as future active segments, each stamped with a
monotonically increasing GENERATION in the segment header so a crash could never replay a
prior life's trailing bytes through the recovery scan (#7). **That proposal is SUPERSEDED
in v1 by [ADR 0002](adr/0002-segments-never-recycled-in-v1.md).** v1 NEVER recycles a
segment.

### Why recycling is unsafe under at-rest encryption

The reason is the at-rest AEAD nonce, not the recovery replay the draft worried about.
IronBus offers optional encryption at rest (#108,
[AT_REST_ENCRYPTION.md](AT_REST_ENCRYPTION.md)) with AES-256-GCM or
ChaCha20-Poly1305, both 96-bit-nonce AEADs. The nonce is DETERMINISTIC:

```
nonce[96] = segment_id[64] || record_counter[32]
```

The high 64 bits ARE the `segment_id`. The whole no-reuse argument (AT_REST_ENCRYPTION.md,
"Deterministic nonce and the no-reuse argument") rests on `segment_id` being unique and
never recycled: across segments the high 64 bits differ, so no two records under a fixed
key ever share a nonce. Recycling a `segment_id` under a fixed key would reuse a nonce,
which is **catastrophic** for both GCM and ChaCha20-Poly1305 (it leaks the keystream XOR
of two messages and, for GCM, the authentication subkey). A monotonic GENERATION stamp in
the header does NOT fix this: the nonce is built from `segment_id` alone, so two different
lives of the same `segment_id` collide on the nonce regardless of any generation field.

### The v1 resolution

- **v1 never recycles a `segment_id`.** A new active segment always gets a fresh id
  strictly greater than any id ever used, across rolls and across a restart (ADR 0002),
  pinned by the storage test
  `segment_ids_increase_monotonically_and_are_never_recycled` in
  `crates/ironbus-storage/src/log.rs`. A reaped segment leaves a hole at the bottom of the
  id space; the id is gone for good.
- **No generation stamp is added to the #5 segment header.** The frozen 64-byte
  `SegmentHeader` (CONTRACTS.md) has no `generation` field and gains none: the draft's
  `generation` was the recycle-safety guard, and with recycling forbidden it is
  unnecessary. The header's reserved bytes `[44, 60)` and one `flags` bit are already
  spoken for by at-rest encryption (`aead_suite`, `key_id`, the `SEGMENT_ENCRYPTED` bit;
  AT_REST_ENCRYPTION.md), so NOT spending header space on an unnecessary generation field
  is also the right framing-stability call. The #5 header offsets and CRC scope stay
  frozen.
- **The stale-bytes-replay guard the draft wanted from a generation stamp is already
  provided** by per-segment framing: a recycled file's prior-life trailing bytes can never
  be replayed because there is no recycled file. A torn or unwritten tail (including a
  preallocated zero tail) is rejected by the record magic + `header_crc` + sequence
  continuity check and truncated by recovery (#7), so the #7 stale-bytes hazard is closed
  by the never-recycle rule plus the existing torn-tail truncation, with no generation
  field needed.

### Recycling is a v2 concern, gated behind a nonce-safety decision

Recycling has no current motivation (the id space is 64 bits; at any realistic edge roll
rate it never exhausts). If a future v2 ever wants it, ADR 0002 requires it to FIRST solve
the nonce reuse it would otherwise create, and it would supersede ADR 0002. Two viable v2
escape hatches exist, and either makes recycling nonce-safe:

- **A per-life random nonce PREFIX in the header.** Store a per-segment random salt in the
  header and fold it into the nonce derivation, so two lives of the same `segment_id` get
  different nonces. This needs header space (a new field, hence a format-version bump) and
  a careful argument that the salt has enough entropy on an edge device whose early-boot
  RNG may be weak, which is the exact early-boot-entropy risk the current DETERMINISTIC
  nonce was chosen to avoid (AT_REST_ENCRYPTION.md). So this hatch trades the deterministic
  no-reuse guarantee for one that depends on RNG quality, a real cost to weigh.
- **A key rotation on recycle.** Rotation is already new-segments-only
  (AT_REST_ENCRYPTION.md, "Key-id in the header; rotation is new-segments-only"), so a
  recycled segment written under a NEW `key_id` reuses the `(segment_id, counter)` nonce
  space safely, because nonce uniqueness is required only PER KEY. This reuses the shipped
  rotation machinery and keeps the deterministic nonce, at the cost of forcing a key
  rotation cadence on the recycle cadence.

This document does not pick between them: per ADR 0002 that is a v2 decision, made only if
recycling ever earns its keep, and it would be its own ADR superseding 0002. The honest v1
position is simply: **no recycling, no generation field, fresh monotonic ids forever.**

The segment-lifecycle diagram (`docs/diagrams/06-wal-segment-lifecycle.dot`) already marks
the `RECYCLED` state "deferred, OPEN DECISION / v2 option," consistent with this
resolution.

---

## Build-matrix implications, flagged to #17

The four-primitive shim has a direct bearing on the cross-platform build and distribution
matrix (#17), which must be flagged so the portability promise is tested, not assumed:

- **Conditional compilation, per OS.** The preallocate implementation is `#[cfg]`-gated
  per target (`target_os = "linux"`, `target_vendor = "apple"`, `target_os = "windows"`),
  exactly as `io.rs` already gates `StdFile` behind `#[cfg(unix)]`. A target with no
  preallocate syscall compiles to the no-op-or-fallback default, so the workspace builds on
  every target in the matrix; nothing is left to fail to link on macOS or Windows the way a
  raw `fallocate` reference would.
- **musl, not glibc, on Linux.** The production Linux target is `*-unknown-linux-musl`
  (static binaries, the #100 / #17 musl cross-build). `fallocate` / `posix_fallocate` are
  available under musl; the implementing PR must verify the chosen call links and runs
  under the musl cross toolchain and the qemu smoke (#100), not only under the developer's
  glibc.
- **Windows is a v1 non-goal but must keep BUILDING.** As with the existing
  `cfg(not(unix))` stubs (the `cmd_serve` Windows build fix in the CHANGELOG), any new
  field or call this design introduces must have a Windows-compiling form (the default
  trait body suffices), so `-D warnings` stays green on the Windows CI lane even though
  `serve` and `StdFile` are Unix-only. The SPECIFIED Windows preallocation mapping above is
  for when #17 promotes Windows from non-goal to a built target.
- **The durability barrier per OS is already in the matrix.** `sync_data` / `sync_all` map
  to `fdatasync` / `fsync` on Linux and to `F_FULLFSYNC` on macOS (`io.rs`); preallocation
  does not change which barrier is issued, so the existing per-OS durability test
  (`apple_durable_sync_takes_the_full_fsync_barrier_path`) still covers the commit barrier.
  #17 adds the per-OS preallocate smoke alongside it.

---

## Status summary

| Item | Status |
|---|---|
| The four-primitive shim (preallocate, file-datasync, directory-sync, sealed-read-map) | (a)(b)(c)(d) all IMPLEMENTED in the seam (a = `RandomAccessFile::preallocate`, #330) |
| Preallocation always-on best-effort, active segment, full roll size, wear/latency rationale | IMPLEMENTED (`start_segment`, #330); an explicit disable knob is deferred to #14 config |
| ENOSPC at roll | A keep-size `ENOSPC` is surfaced at the seam; v1 wiring SWALLOWS it in `start_segment` and falls back to grow-on-append (the doc's route-to-`AtCapacity` refinement is a forward improvement, not required for correctness) |
| Per-OS preallocate (Linux `fallocate` + `FALLOC_FL_KEEP_SIZE`, macOS `fcntl(F_PREALLOCATE)`; Windows `SetEndOfFile`/`SetFileValidData` still SPECIFIED for #17) | IMPLEMENTED for Linux + macOS; other Unix and Windows degrade to the no-op default |
| Segment recycling | RESOLVED: v1 NEVER recycles (ADR 0002); no generation stamp; recycling is a v2 nonce-safety decision |
| Build-matrix implications | FLAGGED to #17 |

See also: [WAL.md](WAL.md), [CONTRACTS.md](CONTRACTS.md),
[AT_REST_ENCRYPTION.md](AT_REST_ENCRYPTION.md),
[ADR 0002](adr/0002-segments-never-recycled-in-v1.md),
[ADR 0001](adr/0001-log-is-wal.md), [RISK_REGISTER.md](RISK_REGISTER.md).
