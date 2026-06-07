# 0003. lz4_flex is the default compression codec, zstd is opt-in only

- **Status**: Accepted
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
  accept the vendored-C dependency; cargo-deny will gate it through a C-FFI
  allowlist (#102) once that dependency is actually introduced.
- The README issue-table row for #12 is now historical on the default-codec
  point and should be read against this ADR and the #139 decision.
