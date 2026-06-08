# Releasing IronBus

IronBus ships as a single static `musl` binary for three edge triples. A release is cut by
pushing a version tag; the `Release` workflow (`.github/workflows/release.yml`) builds, signs,
and publishes the artifacts. The build path reuses the same `cross` static-link setup the CI
`musl build` jobs prove on every PR, and the SBOM path is exercised per-PR by the CI `sbom` job,
so a tagged release does not run unproven steps.

## Cut a release

The release workflow has a `changelog Unreleased is non-empty` gate (#128) that runs first and
FAILS the whole release if `## [Unreleased]` in `CHANGELOG.md` has no content, so a release can
never ship without an audit-trail entry. Tag a release only after the entries are present.

1. Land all changes for the release via the normal PR flow (CI green, self-reviewed, merged).
2. Move the `## [Unreleased]` section of `CHANGELOG.md` under a new `## [vX.Y.Z]` heading and
   bump the workspace `version` in the top-level `Cargo.toml`, in a final PR.
3. After it merges, tag the merge commit and push the tag:

   ```sh
   git tag -s vX.Y.Z -m "vX.Y.Z"   # signed tag (or -a for annotated)
   git push origin vX.Y.Z
   ```

   The `Release` workflow can also be run from the Actions tab (`workflow_dispatch`) against an
   existing tag.

   Re-running the workflow for a tag that already has a published release fails at the
   `gh release create` step (it does not clobber); delete the existing release first
   (`gh release delete vX.Y.Z`) to rebuild it.

## What the release produces

For each of `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and
`armv7-unknown-linux-musleabihf`:

- `ironbus-<triple>`: the static binary (no `PT_INTERP`, no `NEEDED` libs; asserted in the job).
- `ironbus-<triple>.sha256`: its SHA256 checksum.
- `ironbus-<triple>.deb`: the Debian package built from that verified binary (no recompile),
  self-checked with `dpkg-deb -c` in the `package-deb` job.

Plus, once per release:

- `SHA256SUMS`: one consolidated checksum file over all three binaries AND the three `.deb` packages,
  the file the installer verifies against. The job self-checks it (`sha256sum -c SHA256SUMS`) before
  it ships.
- The distroless container image (built by the `container` job from the verified binary; published to
  ghcr.io only when registry publishing is opted in, see docs/DISTRIBUTION.md).
- `ironbus.sbom.json`: the `cargo-auditable` dependency manifest (the graph is target
  independent for this pure-Rust workspace), extracted with `rust-audit-info`.
- A keyless Sigstore build-provenance attestation for every binary, the `SHA256SUMS`, and the
  SBOM, stored in the repository's attestations.

A `v0.x` (or `v0.0.0`) tag is published as a GitHub **prerelease**, since the project is pre-1.0
and not yet a stability promise (see SECURITY.md); a `v1+` tag publishes a full release.

## Install (the fail-closed installer)

`scripts/install.sh` is a `curl | sh`-style installer that detects the host architecture, maps it
to a musl triple, downloads the matching `ironbus-<triple>` binary AND the release `SHA256SUMS`,
and verifies the binary's SHA256 against `SHA256SUMS` BEFORE installing. It is **fail-closed**: any
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
   the SBOM, and the build-provenance attestation), below.

The lifecycle on a deployed node (atomic in-place upgrade, one-command rollback, fall-back after N
failed starts, and the explicit `migrate` format gate) is also in
[docs/DISTRIBUTION.md](docs/DISTRIBUTION.md).

## Verify a downloaded binary

```sh
# Integrity (one file for all three binaries, or the per-binary .sha256):
sha256sum -c SHA256SUMS                              # checks every listed asset present locally
sha256sum -c ironbus-x86_64-unknown-linux-musl.sha256

# Provenance (it was built by this repo's Release workflow, signed via Sigstore, no key needed):
gh attestation verify ironbus-x86_64-unknown-linux-musl --repo ELares/IronBus

# Dependency manifest (the embedded or attached SBOM):
rust-audit-info ironbus.sbom.json
```

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
