# Changelog

All notable changes to IronBus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow Semantic Versioning once it reaches a tagged release.

## [Unreleased]

### Added
- `ironbus-storage::naming`: segment file naming (`seg-<16-hex-digit-id>.log`, fixed width so lexicographic order equals segment-id order), a strict canonical parser that is the exact inverse of the name function (proptest round-trip both ways), and `segment_ids`, which enumerates a data directory in ascending segment-id order while skipping foreign files. The directory of self-describing files is the discovery authority, no manifest required.
- `ironbus-storage::fs`: a `Filesystem` seam (open, create-new, list, remove, exists, sync-dir) over one flat data directory of segment files, with an `InMemoryFs` that models directory-entry durability (a created-but-not-dir-synced file vanishes on power loss; a removal that was not dir-synced is undone) and a Unix `StdFs` that rejects names escaping the data directory. This is the substrate for the multi-segment log and recovery.
- `ironbus-storage::segment`: `SegmentWriter` (append records, sync, seal with footer) and `SegmentReader` (validate header, scan records, recover the valid prefix on a torn or corrupt tail), wiring the record and segment codecs to the `RandomAccessFile` seam. Tests cover round-trip, seal/scan, empty sealed segments, torn-tail recovery, power-loss (only synced records survive), and rejection of a footer bound to a different segment.
- Cargo workspace skeleton with six crates: `ironbus-core`, `ironbus-storage`,
  `ironbus-proto`, `ironbus-server`, `ironbus-client`, and `ironbus-cli` (binary
  `ironbus`). `ironbus-core` is IO-free.
- Workspace lints (clippy all + pedantic, `unsafe_code` warn) applied to every crate.
- Continuous integration: rustfmt, clippy (deny warnings), test matrix on Linux,
  macOS, and Windows, an MSRV 1.78 build, and a lint that keeps `ironbus-core` IO-free.
- Dual `MIT OR Apache-2.0` license files.
- `ironbus-storage::io`: the `RandomAccessFile` trait (positioned reads/writes, `sync_data`, `len`, `set_len`) and an `InMemoryFile` (sync-counting, snapshot-able) so storage goes through a seam the deterministic simulation can substitute.
- `ironbus-storage::io::StdFile`: production `RandomAccessFile` over an OS file using cursor-free positioned IO (pread/pwrite), plus `sync_dir` for crash-durable segment creation (Unix targets; Windows is a v1 non-goal).
- `ironbus-core::segment`: encode and decode of the frozen 64-byte segment header and 32-byte sealed footer, both CRC32C-protected, with a typed `SegmentError` and proptest round-trip plus corruption tests. Shared little-endian read helpers factored into `crate::raw`.
- `ironbus-core::clock`: the `Clock` trait (wall and monotonic time) and a deterministic `ManualClock`, so engine logic never reads the host clock directly and the simulation controls time.
- `ironbus-core::codec`: record-frame encode and decode with CRC32C header and body checksums, typed `EncodeError`/`DecodeError`, and proptest round-trip plus single-bit-flip corruption-detection tests. The optional xxh3-64 large-payload checksum is deferred (frame layout pending).
- `ironbus-core`: frozen v1 on-disk format constants and field offsets (record header, trailer, segment header and footer), and the `Offset`, `Seq`, and `RecordFlags` value types, with unit tests pinning the layout.
- Supply-chain CI gate (`cargo-deny`) with a permissive-license allowlist, and SPDX license headers on every Rust source enforced by CI.
