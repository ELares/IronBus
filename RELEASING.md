# Releasing IronBus

IronBus ships as a single static `musl` binary for three edge triples. A release is cut by
pushing a version tag; the `Release` workflow (`.github/workflows/release.yml`) builds, signs,
and publishes the artifacts. The build path reuses the same `cross` static-link setup the CI
`musl build` jobs prove on every PR, and the SBOM path is exercised per-PR by the CI `sbom` job,
so a tagged release does not run unproven steps.

## Cut a release

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

Plus, once per release:

- `ironbus.sbom.json`: the `cargo-auditable` dependency manifest (the graph is target
  independent for this pure-Rust workspace), extracted with `rust-audit-info`.
- A keyless Sigstore build-provenance attestation for every binary and the SBOM, stored in the
  repository's attestations.

## Verify a downloaded binary

```sh
# Integrity:
sha256sum -c ironbus-x86_64-unknown-linux-musl.sha256

# Provenance (it was built by this repo's Release workflow, signed via Sigstore, no key needed):
gh attestation verify ironbus-x86_64-unknown-linux-musl --repo ELares/IronBus

# Dependency manifest (the embedded or attached SBOM):
rust-audit-info ironbus.sbom.json
```

## Reproducibility

The release profile (`[profile.release]` in `Cargo.toml`) sets `panic = "abort"`, fat LTO, one
codegen unit, and `strip = true`. A fully byte-reproducible two-runner gate
(`SOURCE_DATE_EPOCH`, `--remap-path-prefix`) is tracked under #101.
