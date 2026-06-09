# 0003. lz4_flex is the default compression codec, zstd is opt-in only

- **Status**: Accepted; the `lz4_flex` default-codec runtime is IMPLEMENTED (#387,
  `crates/ironbus-core/src/compress.rs`). The opt-in `zstd` codec (and its trained-dictionary
  ZDICT training) remains deferred, never on the default path.
- **Owning issue**: [#12](https://github.com/ELares/IronBus/issues/12) (compression), decided in #139

## Context

The compression issue (#12) originally leaned toward zstd as the default codec
with an lz4 fallback. But the best zstd crate (`zstd`, via `zstd-sys`) links
vendored C. A vendored-C dependency on the default path conflicts with the
project's static-binary and supply-chain posture (#17): it complicates the musl
cross-builds, widens the audited surface, and pulls a C toolchain onto the
default build. The #139 decision pass resolved this in favor of a pure-Rust
default.

## Decision

The default compression codec is `lz4_flex`, which is pure Rust. zstd (via
`zstd-sys`, vendored C) is opt-in only, behind an explicit feature, and is never
on the default path. The default build pulls no vendored-C crate.

This is recorded and enforced in `deny.toml`, whose `[bans]` comment reads: "Per
#139, the default path is pure Rust: no vendored-C crate is allowed on it. The
default compression codec is lz4_flex (pure Rust); zstd (zstd-sys, vendored C) is
opt-in only, behind an explicit feature, never on the default path. A C-FFI
allowlist is enforced here once any such opt-in dependency is introduced
(tracked in #102)." This refines the older README issue-table phrasing for #12,
which still reads "zstd default, lz4 fallback"; the #139 decision in `deny.toml`
is the resolved position.

## Consequences

- The default binary stays pure Rust, which keeps the musl static cross-builds
  simple and the supply-chain audit (cargo-deny, the SBOM) free of vendored C on
  the default path.
- Operators who want zstd's higher ratio opt in explicitly via a feature and
  accept the vendored-C dependency; cargo-deny gates it through a C-FFI allowlist
  (#102). IMPLEMENTED in #357: the opt-in `zstd` Cargo feature of `ironbus-core`
  (threaded up to `ironbus-storage` and `ironbus-cli`) adds the zstd codec (id 2)
  and the trained-dictionary lifecycle. The `zstd-sys` vendored-C crate is built
  VENDORED + STATIC (the `pkg-config` feature is OFF, so it compiles the bundled
  `zstd.1.5.7` C rather than linking a system libzstd, the #77 musl requirement)
  and is the sole, explicitly allowed C-FFI in `deny.toml`. The DEFAULT build,
  its SBOM, and the `scripts/ci/cffi-ban.sh` gate (which scope to the default
  `ironbus-cli` graph) carry ZERO zstd and stay byte-for-byte unchanged; the
  opt-in path is covered by the `zstd-feature` CI job.
- The README issue-table row for #12 is now historical on the default-codec
  point and should be read against this ADR and the #139 decision.
