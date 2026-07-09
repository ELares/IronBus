# Releasing IronBus

IronBus ships as a single static `musl` binary for three edge triples, through two release
channels:

- **Rolling, calendar-versioned** releases, published AUTOMATICALLY on EVERY push to main by the
  `Rolling release` workflow (`.github/workflows/rolling-release.yml`). The version is `YYMM.1DD.1{Build}`
  (the UTC date plus a per-day build number, e.g. `2607.108.11` then `2607.108.12`, resetting the
  next day). Each rolling build publishes the three static musl binaries, their per-binary
  `.sha256`, a consolidated `SHA256SUMS`, and a Sigstore build-provenance attestation, as a NORMAL
  release, so `releases/latest` (and the `curl | sh` installer's default) always points at the
  newest rolling build. The version is stamped into the binary via `IRONBUS_BUILD_VERSION` (read by
  `option_env!` in the `version` verb, forwarded into the cross container by `Cross.toml`), so
  `ironbus version` reports the published calendar version without touching `Cargo.lock`. There is
  NO changelog gate and no `.deb`/container on this channel (rolling builds are continuous, not
  curated). Skip a build by putting `[skip release]` in the head commit message.
- **Formal, tagged** releases, cut by the maintainer by pushing a `v*` tag, built by the `Release`
  workflow (`.github/workflows/release.yml`). This is the curated channel described below: it adds
  the `.deb` per triple, the distroless container, the CycloneDX SBOM, and the changelog gate.

The build path on both channels reuses the same `cross` static-link setup the CI `musl build` jobs
prove on every PR (and the SBOM path is exercised per-PR by the CI `sbom` job), so neither release
runs unproven steps.

## Cut a release

Cutting a release is one command to prepare the tree, one reviewed PR, and one tag push. The
`prepare-release.sh` script does the mechanical prep; the `Release` workflow does the build +
publish. Nothing is published until you push the tag.

```sh
# 1. Prepare the tree (edits only — no commit, no tag, no push):
scripts/prepare-release.sh 0.2.0
```

`scripts/prepare-release.sh <X.Y.Z>` (validates the version is semver; idempotent):

1. bumps `[workspace.package] version` in the top-level `Cargo.toml`,
2. bumps the internal path-dependency `version = "..."` pins in every crate manifest so cargo's
   published-version requirement stays in lockstep,
3. reconciles `Cargo.lock` (`cargo update --workspace`; a deterministic in-place patch if `cargo` is
   not on `PATH`),
4. rolls `CHANGELOG.md`: moves `## [Unreleased]` under a new `## [vX.Y.Z]` heading with a
   `_Released <date>._` sub-line, and inserts a fresh empty `## [Unreleased]`. The version heading is
   kept EXACTLY `## [vX.Y.Z]` (no in-heading date) so the #128 changelog gate and the release-notes
   extractor both match it; the date lives on the sub-line,
5. scaffolds `docs/benchmarks/baselines/vX.Y.Z/` from the previous release's baselines (retagged, the
   coverage number reset to the pending `null`), and
6. prints the remaining steps.

Then, still by hand (the two owner decisions the script cannot make for you):

- **Fill in the changelog** under `## [vX.Y.Z]` if it is empty. The release workflow's
  `changelog Unreleased is non-empty` gate (#128) runs first and FAILS the whole release if the
  section has no content, so a release can never ship without an audit-trail entry.
- **Re-anchor the baselines** if you have fresh numbers — the scaffolded perf runs are carried over
  from the previous tag for you to replace, and the coverage number is reset to the pending `null`
  (see [Regression-gate baselines](#regression-gate-baselines-perf--coverage) below and the
  scaffolded `docs/benchmarks/baselines/vX.Y.Z/README.md`). Also point the perf gate's `--baseline`
  in `ci.yml` at the new tag's file.

```sh
# 2. Commit on a branch, open the release PR (CI green, reviewed, merged):
git switch -c chore/release-v0.2.0
git add -A
git commit -s -m "chore(release): prepare v0.2.0"    # -s: DCO sign-off, per CONTRIBUTING.md
gh pr create --fill

# 3. After the PR merges, tag the merge commit and push the tag — this triggers the release:
git tag -s v0.2.0 -m "v0.2.0"                          # signed tag (or -a for annotated)
git push origin v0.2.0
```

Pushing the `v*` tag triggers the `Release` workflow (`.github/workflows/release.yml`), which:

1. asserts the tag version equals the `[workspace.package]` version (`version-gate`, via
   `scripts/ci/assert-tag-version.sh`) and the changelog section is non-empty (`changelog-gate`,
   #128) — either failing loudly BEFORE any binary is built;
2. cross-builds the three static musl binaries (the same `cross` matrix the CI `musl build` jobs
   prove on every PR), packages a `.deb` per triple, and builds/pushes the distroless container;
3. publishes the GitHub Release with the SHA256SUMS, both SBOMs, and the Sigstore attestation, using
   release notes **extracted from the `## [vX.Y.Z]` CHANGELOG section** (`scripts/ci/release-notes.sh`).
   If that section exceeds GitHub's 125000-char body limit, the notes are truncated at a line
   boundary with a link to the full `CHANGELOG.md` at the tag.

The `Release` workflow can also be run from the Actions tab (`workflow_dispatch`) against an existing
tag. Re-running it for a tag that already has a published release fails at the `gh release create`
step (it does not clobber); delete the existing release first (`gh release delete vX.Y.Z`) to rebuild
it.

> **crates.io.** IronBus does NOT publish its library crates to crates.io — it ships a single binary
> over the four channels below, `docs/CLIENT_SDKS.md` pins the Rust crates "by git until a crates.io
> release", and `[patch.crates-io] raft-proto` redirects a dependency to a vendored build-script-free
> codec that a real `cargo publish` would not carry. The release workflow documents the enable path
> (a `CRATES_IO_TOKEN` secret + a `cargo publish` job in dependency order) inline, next to the
> `create the GitHub Release` step, for when that decision is made.

## Regression-gate baselines (perf + coverage)

Two CI regression gates compare each build against the LAST RELEASED TAG's archived baseline, so a
release must archive its baselines for the gates to enforce. They were dormant (no-op) until the
first tag because there was nothing to compare against; `v0.1.0` armed them (#1068). Each release
archives its own `docs/benchmarks/baselines/vX.Y.Z/` directory and the gates point at the newest.

- **Perf regression gate** (`regression-gate` job in `.github/workflows/ci.yml`, #114). Archive
  `docs/benchmarks/baselines/vX.Y.Z/perf-baseline.json` in the
  `ironbus_bench::regression::Baseline` schema (`{ "tag", "runs": [RunPoint...] }`) — the per-device
  reference macro-bench medians (#111). The job passes it via `--baseline`; the gate then FAILS on an
  un-ratified rolling-median regression (throughput -10%, p99 +15%, p99.9 +25%). The live per-device
  numbers are a documented device residual (see [BASELINE_RIG.md](docs/BASELINE_RIG.md)); the checked-in
  history fixture stands in for the current run so the job validates the GATE wiring, not live runs.
  Update `--baseline` in `ci.yml` to point at the newest tag's file each release.
- **Coverage regression gate** (`coverage` job in `.github/workflows/nightly.yml`, #385). Archive
  `docs/benchmarks/baselines/vX.Y.Z/coverage-baseline.json`
  (`{ "tag", "line_coverage_pct", "tolerance_pct" }`). The nightly `coverage-regression-gate` step
  reads it and FAILS on `current < line_coverage_pct - tolerance_pct`. **Record the number** from the
  first post-tag nightly run: the `coverage` lane prints the workspace line-coverage percentage
  (`cargo llvm-cov --workspace --all-features`) to the job log + step summary and retains `lcov.info`
  for 90 days — copy that percentage into `line_coverage_pct` (it is `null` until you do, which the
  step reports as a documented PENDING no-op rather than a failure).

## What the release produces

For each of the three build targets `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and
`armv7-unknown-linux-musleabihf`, the published binary asset carries a friendly CPU-arch name
(`ironbus-linux-amd64`, `ironbus-linux-arm64`, `ironbus-linux-armv7` respectively); the
`unknown`-vendored triple stays the internal cargo/cross build target only:

- `ironbus-linux-<arch>`: the static `musl` binary (no `PT_INTERP`, no `NEEDED` libs; asserted in the
  job). It has no runtime dependency even though the friendly name drops `musl`.
- `ironbus-linux-<arch>.sha256`: its SHA256 checksum.
- `ironbus-linux-<arch>.deb`: the Debian package built from that verified binary (no recompile),
  self-checked with `dpkg-deb -c` in the `package-deb` job. The `.deb` now mirrors the friendly
  binary asset name (`ironbus-linux-amd64.deb`, `ironbus-linux-arm64.deb`, `ironbus-linux-armv7.deb`),
  so it carries no `unknown`-vendored triple either; the triple stays the cargo `--target` only.

Plus, once per release:

- `SHA256SUMS`: one consolidated checksum file over all three binaries, the three `.deb` packages,
  AND the CycloneDX SBOM, the file the installer verifies against. The job self-checks it
  (`sha256sum -c SHA256SUMS`) before it ships.
- The distroless container image (built by the `container` job from the verified binary; published to
  ghcr.io only when registry publishing is opted in, see docs/DISTRIBUTION.md).
- `ironbus.sbom.json`: the `cargo-auditable` dependency manifest (the graph is target
  independent for this pure-Rust workspace), extracted with `rust-audit-info`.
- `ironbus.cyclonedx.json`: a `syft`-generated CycloneDX (JSON) SBOM of the released binary, the
  standalone, tool-recoverable manifest a scanner consumes (#367). It is emitted by the SHA-pinned
  `anchore/sbom-action` over the SAME native binary the cargo-auditable step builds, so it covers
  the identical pure-Rust dependency set as `ironbus.sbom.json`. The two are complementary: the
  cargo-auditable one is the in-binary provenance embedded in the shipped artifact (recovered with
  `rust-audit-info`, round-trip-gated against `Cargo.lock` per #102); the CycloneDX one is the
  scannable release asset every SBOM/vuln tool reads natively (`syft`/`grype`, below). syft is a CI
  tool only; it is NOT a crate dependency and adds nothing to the shipped graph.
- A keyless Sigstore build-provenance attestation for every binary, the `SHA256SUMS`, the
  cargo-auditable SBOM, and the CycloneDX SBOM, stored in the repository's attestations.

A `v0.x` (or `v0.0.0`) tag is published as a GitHub **prerelease**, since the project is pre-1.0
and not yet a stability promise (see SECURITY.md); a `v1+` tag publishes a full release.

## Install (the fail-closed installer)

`scripts/install.sh` is a `curl | sh`-style installer that detects the host architecture, maps it
to a friendly asset suffix, downloads the matching `ironbus-linux-<arch>` binary (e.g.
`ironbus-linux-arm64`) AND the release `SHA256SUMS`, and verifies the binary's SHA256 against
`SHA256SUMS` BEFORE installing. It is **fail-closed**: any
download error, a missing or mismatched checksum, a malformed `SHA256SUMS`, or an unsupported
platform aborts with a non-zero exit and installs nothing. It never `eval`s or `sh`-pipes any
downloaded content. There is no insecure / skip-verification override.

```sh
# Latest release, auto-detected arch, default install dir:
curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh | sh

# Pin a version, choose an install dir, and additionally verify the Sigstore provenance:
curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh \
  | sh -s -- --version v0.1.0 --bin-dir "$HOME/.local/bin" --verify-provenance
```

`--verify-provenance` additionally runs `gh attestation verify` (it needs the `gh` CLI and Rekor
reachability) and is itself fail-closed: if requested and verification fails, nothing is installed.
The checksum verification (`verify_checksum`) is factored into a shell function and gated by a
tamper-rejection test (`crates/ironbus-cli/tests/installer_verify.rs`) that proves a tampered
binary, an unlisted asset, an empty or malformed `SHA256SUMS`, and a missing binary are all
rejected, while a matching binary is accepted.

## Distribution channels

IronBus ships over four channels, each fail-closed verified before it places a binary, all carrying
the same reproducible static binary. They are documented in full in
[docs/DISTRIBUTION.md](docs/DISTRIBUTION.md):

1. The fail-closed `curl | sh` installer (`scripts/install.sh`), below.
2. A Debian `.deb` package (`cargo deb`, metadata in `crates/ironbus-cli/Cargo.toml`), built per
   triple by the `package-deb` release job from the verified static binary (no recompile). It bundles
   the binary, a systemd unit (running the broker as the unprivileged `ironbus` user, wiring the
   atomic-upgrade fall-back), and a default config conffile.
3. A distroless container image (`gcr.io/distroless/static:nonroot`, `Dockerfile`/`Dockerfile.release`)
   built by the `container` release job from the verified binary; running as non-root with the
   WAL/segment dir as a required writable volume. Registry publishing is opt-in (see DISTRIBUTION.md).
4. The checksummed GitHub Releases (the binaries, the `.deb` packages, the consolidated `SHA256SUMS`,
   the cargo-auditable SBOM, the syft CycloneDX SBOM, and the build-provenance attestation), below.

The lifecycle on a deployed node (atomic in-place upgrade, one-command rollback, fall-back after N
failed starts, and the explicit `migrate` format gate) is also in
[docs/DISTRIBUTION.md](docs/DISTRIBUTION.md).

## Verify a downloaded binary

```sh
# Integrity (one file for all three binaries, or the per-binary .sha256):
sha256sum -c SHA256SUMS                              # checks every listed asset present locally
sha256sum -c ironbus-linux-amd64.sha256

# Provenance (it was built by this repo's Release workflow, signed via Sigstore, no key needed):
gh attestation verify ironbus-linux-amd64 --repo ELares/IronBus

# Dependency manifest (the embedded or attached SBOM):
rust-audit-info ironbus.sbom.json
```

## Scan the CycloneDX SBOM (syft / grype)

`ironbus.cyclonedx.json` is the scannable release artifact: any CycloneDX-aware tool reads it
directly, no extraction step. After downloading it (and, optionally, verifying it against
`SHA256SUMS` and its provenance attestation as above):

```sh
# Read the manifest back / re-emit it in another format (syft converts between SBOM formats):
syft convert ironbus.cyclonedx.json -o cyclonedx-json    # or spdx-json, syft-table, ...

# Vulnerability-scan the SBOM with grype (no rebuild, no network fetch of the binary):
grype sbom:ironbus.cyclonedx.json

# Equivalently, scan the downloaded binary directly (syft/grype generate the SBOM on the fly):
grype ./ironbus-linux-amd64
```

The CycloneDX SBOM and the embedded `cargo-auditable` SBOM (`ironbus.sbom.json`) describe the SAME
dependency set by construction (both derive from the one native release build): the cargo-auditable
one is the in-binary provenance you recover from a deployed binary with `rust-audit-info` (and the
#102 round-trip gate proves matches `Cargo.lock`), while the CycloneDX one is the standalone asset
the `syft`/`grype` ecosystem scans without unpacking the binary.

> Note (separate tuning decision, not changed here): #367 also raises whether `deny.toml`'s
> `[advisories] unmaintained = "all"` should become a documented warn-then-deny grace window rather
> than a hard deny on every unmaintained advisory. That is a cargo-deny policy preference, distinct
> from attaching the SBOM, and is intentionally left unchanged in this change; revisit it on its own
> so a policy loosening is a deliberate, reviewed decision.

## Reproducibility

The shipped binary is meant to be bit-for-bit reproducible: an operator can rebuild a tag from
source and confirm, byte for byte, exactly what is on a device. That is mechanized, not asserted.

### The release profile

`[profile.release]` in the workspace `Cargo.toml` sets `opt-level = "s"` (size; `"z"` is gated on
a #19 throughput check, not yet taken), `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, and
`strip = true`. Single-codegen-unit and fat LTO are load-bearing for determinism as well as size:
parallel codegen units are scheduled nondeterministically. `panic = "abort"` is binding, not a
size tweak: the handlers are panic-free by construction (see #7), so there is no unwinding path to
preserve. `strip = true` removes the symbol table.

### Determinism inputs (the reproducible invocation)

`strip` does not remove the absolute build paths the compiler bakes into rodata (`panic!`/`assert!`
location strings, `#[track_caller]` callsites, `file!()`), so a build still depends on WHERE it ran
unless those paths are remapped. The reproducible release build pins every determinism input:

- `--remap-path-prefix` for the workspace and the cargo cache, so the checkout directory and
  `$HOME` drop out of the binary. Set in the invocation below because both values
  (`$PWD`, `$CARGO_HOME`) are only known at build time; cargo does not expand environment
  variables inside `.cargo/config.toml`, so they cannot be committed there portably.
- `CARGO_INCREMENTAL = 0`, pinned in `.cargo/config.toml`'s `[env]` (its value does not depend on
  the build location). Incremental codegen reorders output and is not bit-reproducible.
- `codegen-units = 1`, in `[profile.release]` (above): parallel codegen is nondeterministic.
- `SOURCE_DATE_EPOCH`, set to the release tag's commit date, so any embedded build timestamp is
  the commit's, not the wall clock of the runner.
- `--locked`, so the build uses the committed `Cargo.lock` and not a freshly resolved graph.
- A fixed toolchain. The CI/release jobs pin `dtolnay/rust-toolchain` to a commit SHA (#142); a
  manual rebuild must use the same `rustc` version (printed in the release notes) to match bytes.
- Embed the `cargo-auditable` SBOM BEFORE `strip` runs, so the embedded dependency manifest is
  present and the strip pass is the last mutation. With `strip = true` in the profile, build the
  binary with `cargo auditable build` so the SBOM is embedded during the same codegen.

The exact release invocation (what the #103 workflow runs, and what a manual rebuild reproduces):

```sh
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export RUSTFLAGS="--remap-path-prefix=$PWD=/ironbus --remap-path-prefix=$CARGO_HOME=/cargo"
cargo auditable build --release --locked -p ironbus-cli \
  --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/ironbus
```

(Verified locally that the remap drops every embedded absolute path with no size change.)

### Size delta

Applying the profile shrank the native `ironbus` release binary from 703 KiB to 410 KiB (41%
smaller) on the original measurement; the determinism inputs are byte-rewrites only and do not
change the size. The musl edge targets are the shipped artifacts and are size-checked per
architecture by the #100 cross-build matrix.

### The byte-identical gate

Reproducibility is mechanized as a merge-blocking CI gate (the `byte-identical reproducibility gate`
job in `.github/workflows/ci.yml`, #101). On every PR it builds the SAME commit TWICE with the
reproducible invocation above (`SOURCE_DATE_EPOCH` from the commit date, `CARGO_INCREMENTAL=0`,
`--locked`, the `--remap-path-prefix` pair) for `x86_64-unknown-linux-musl`, runs a `cargo clean`
between the two builds so the second is a genuine fresh compile, and asserts the two binaries have
an IDENTICAL SHA256. A mismatch fails the gate.

It is a SINGLE-RUNNER, TWO-BUILD comparison by design. The two builds run back to back on one
runner, so the toolchain (`rustc`, libc, sysroot) is held fixed and a mismatch is a real determinism
regression in this tree. Building on two DIFFERENT runners and diffing was rejected: a differing
runner toolchain would fail the gate for a reason that is NOT a determinism regression in our
sources. The release workflow can still rebuild on a clean runner to cross-check, but the per-PR
gate is the deterministic single-runner comparison.

Verified before the gate was added: `cargo build --release --locked` with this invocation is
byte-identical across both an incremental rebuild and a full `cargo clean` rebuild.

#### diffoscope triage

If the gate ever fails, rebuild the two binaries with the invocation above and localize the
differing bytes:

```sh
diffoscope /tmp/ironbus-build1 target/x86_64-unknown-linux-musl/release/ironbus
```

The usual culprits are a new embedded absolute path (extend the `--remap-path-prefix` set), a build
timestamp that ignores `SOURCE_DATE_EPOCH`, or parallel codegen creeping in (`codegen-units` must
stay `1`). The static cross-build matrix is #100; release signing is #103.
