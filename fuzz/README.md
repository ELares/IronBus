# IronBus fuzz targets

Coverage-guided fuzzing of every parser that reads untrusted or possibly corrupt bytes
(issues [#21](https://github.com/ELares/IronBus/issues/21),
[#123](https://github.com/ELares/IronBus/issues/123)). The crate's property tests already
round-trip structured inputs; these targets drive the raw decoders with libFuzzer's
mutated byte strings under AddressSanitizer, so an out-of-bounds read or a panic on a
hostile or brownout-corrupted input surfaces as a crash rather than in production.

The contract every target asserts is the same one the proptests assume: on **any** input
the parser only returns a typed error or a valid view, it never panics and never reads out
of bounds.

## Targets

| Target | Parser | Why it matters |
| --- | --- | --- |
| `record_codec` | `ironbus_core::codec::decode` / `decoded_len` | The record-frame decoder runs on the recovery and delivery paths. |
| `frame_decode` | `ironbus_proto::frame::decode_frame` | The length-framed wire decoder reads bytes straight off a client socket. |
| `cursor_snapshot` | `ironbus_core::cursor::AckCursor::decode_snapshot` | A torn or hostile durable checkpoint payload must not crash recovery. |
| `segment_scan` | `ironbus_storage::segment::SegmentReader` scan and recovery | The most security-critical parser: it runs on every startup over on-disk bytes a power cut may have corrupted. |
| `connect_auth_section` | `ironbus_proto::message::parse_connect_auth` | The auth section of the `Connect` body, parsed on a NOT-YET-AUTHENTICATED connection — the most hostile input position (a panic here under `panic = "abort"` is an unauthenticated remote kill). |
| `password_material` | `ironbus_proto::message::unpack_password_material` | Splits attacker-supplied credential bytes before the Argon2id verify, on the same pre-auth path. |

The table above is representative, not exhaustive — CI derives the full target set from
`fuzz_targets/*.rs` at run time (see [CI](#ci)), so adding a target here never requires
touching a hardcoded list and can never silently orphan a parser.

## Running locally

The crate is detached from the main workspace (it has its own empty `[workspace]` table) so
the stable, merge-blocking workspace is never built with the nightly sanitizer toolchain.
cargo-fuzz needs a nightly toolchain:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# Soak one target (Ctrl-C to stop), or bound it with -max_total_time=<seconds>. Seed it from
# the committed regression corpus so it replays every known crasher first.
cargo +nightly fuzz run record_codec --target x86_64-unknown-linux-gnu \
    corpus-regression/record_codec -- -max_total_time=60

# Build every target without running, to check they still compile.
cargo +nightly fuzz build --target x86_64-unknown-linux-gnu
```

`--target x86_64-unknown-linux-gnu` is REQUIRED. cargo-fuzz infers its default `--target`
from its own binary triple, and CI binstalls the musl-static cargo-fuzz build, so without
the flag the fuzz targets build for `x86_64-unknown-linux-musl`, which is incompatible with
AddressSanitizer. Pass it on every `fuzz run` / `fuzz build` (locally too, on a musl host).

## The committed regression corpus (#385)

`fuzz/corpus-regression/<target>/<sha256>` is a small, committed, content-addressed set of
permanent seeds: the frozen [#45](https://github.com/ELares/IronBus/issues/45) conformance
vectors plus crafted hostile inputs (overlong length fields, truncated frames, all-ones
headers), one directory per target, each file named by the SHA-256 of its own bytes. Unlike
the volatile working `corpus/` (which cargo-fuzz rewrites every run and `.gitignore`
excludes), this directory is TRACKED, so a once-found crash stays a permanent seed.

Regenerate it deterministically (and assert it is current) with:

```sh
sh fuzz/seed-regression-corpus.sh           # (re)write the committed corpus
sh fuzz/seed-regression-corpus.sh --check    # assert the committed corpus is up to date (CI)
```

## Minimize and promote

When a soak finds a crasher (dropped under `fuzz/artifacts/<target>/`), minimize it and
promote the minimized input into the regression corpus, where its content-addressed name
makes the promotion idempotent:

```sh
cd fuzz
cargo +nightly fuzz tmin <target> --target x86_64-unknown-linux-gnu <crash-file>
# tmin writes the minimized input; copy it in under its content hash:
cp <minimized-file> "corpus-regression/<target>/$(sha256sum <minimized-file> | cut -d' ' -f1)"
```

Commit the new seed. From then on the per-PR replay (below) guards it on every PR.

## CI

- **Per-PR (light, deterministic):** the `test` job runs
  `crates/ironbus-server/tests/fuzz_regression_replay.rs`, which drives every committed
  regression seed through the same decoder its libFuzzer target calls and asserts no panic.
  It needs no sanitizer and no nightly, so it runs on every PR on all three OSes and is
  non-flaky. The `fuzz-corpus` job asserts the committed corpus is up to date, and the
  `fuzz-smoke` job replays the corpus under ASan and short-fuzzes each target for a few
  seconds (`--target x86_64-unknown-linux-gnu`), so a shallow new crasher is caught on the PR.
- **Nightly (deep):** the `fuzz` job soaks every target under ASan (180 s/target today,
  rising toward 30 min/target), seeded by the regression corpus. A crash fails the job and
  uploads the input (90-day retention) for triage and promotion.
- **"Every target" is structural, not aspirational:** both the nightly soak and the per-PR
  `fuzz-smoke` DERIVE their target list from `fuzz_targets/*.rs` at run time — there is no
  hardcoded list to forget to update (a hardcoded list once silently orphaned 8 of 21 targets
  from every lane). A new target is smoke-tested on the PR that adds it and soaked the same
  night; a target file missing its `Cargo.toml` `[[bin]]` entry fails both lanes loudly. A
  target with no committed regression corpus yet fuzzes from scratch until seeds are promoted.
- **Coverage regression:** the nightly `coverage` job emits the workspace line-coverage
  percentage and retains `lcov.info`. The "coverage-below-last-release" gate (compare to the
  last released tag's archived coverage, fail on an un-tolerated drop) was ARMED at `v0.1.0`
  (#1068): the `coverage-regression-gate` step reads
  `docs/benchmarks/baselines/v0.1.0/coverage-baseline.json` and enforces
  `current >= line_coverage_pct - tolerance_pct`, mirroring the #114 perf gate's baseline shape.
  The baseline's `line_coverage_pct` is recorded by the maintainer from the first post-tag
  nightly percentage (it is `null`/PENDING-no-op until then; see the baseline README).

The build outputs, the discovered working corpora, and the crash artifacts are git-ignored;
the regression corpus and `Cargo.lock` are committed so a soak is reproducible.
