# Changelog

All notable changes to IronBus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow Semantic Versioning once it reaches a tagged release.

## [Unreleased]

### Added
- Cargo workspace skeleton with six crates: `ironbus-core`, `ironbus-storage`,
  `ironbus-proto`, `ironbus-server`, `ironbus-client`, and `ironbus-cli` (binary
  `ironbus`). `ironbus-core` is IO-free.
- Workspace lints (clippy all + pedantic, `unsafe_code` warn) applied to every crate.
- Continuous integration: rustfmt, clippy (deny warnings), test matrix on Linux,
  macOS, and Windows, an MSRV 1.78 build, and a lint that keeps `ironbus-core` IO-free.
- Dual `MIT OR Apache-2.0` license files.
- `ironbus-core::clock`: the `Clock` trait (wall and monotonic time) and a deterministic `ManualClock`, so engine logic never reads the host clock directly and the simulation controls time.
- `ironbus-core::codec`: record-frame encode and decode with CRC32C header and body checksums, typed `EncodeError`/`DecodeError`, and proptest round-trip plus single-bit-flip corruption-detection tests. The optional xxh3-64 large-payload checksum is deferred (frame layout pending).
- `ironbus-core`: frozen v1 on-disk format constants and field offsets (record header, trailer, segment header and footer), and the `Offset`, `Seq`, and `RecordFlags` value types, with unit tests pinning the layout.
- Supply-chain CI gate (`cargo-deny`) with a permissive-license allowlist, and SPDX license headers on every Rust source enforced by CI.
