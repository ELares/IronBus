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
