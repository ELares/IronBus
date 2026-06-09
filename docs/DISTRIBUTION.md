# Distribution channels and lifecycle

How IronBus ships and how a deployed broker is upgraded and rolled back safely (#104, parent #17).

IronBus is one static `musl` binary that is both the broker and the client tooling. Every channel
below ships the SAME reproducible binary (see [RELEASING.md](../RELEASING.md)); the difference is
only the packaging. There are four channels, each fail-closed verified before it places a binary:

1. The fail-closed `curl | sh` installer (`scripts/install.sh`).
2. A Debian `.deb` package (cargo-deb).
3. A distroless container image (`gcr.io/distroless/static`).
4. The checksummed GitHub Releases (the raw binaries + `SHA256SUMS` + SBOM + provenance).

There are two release CHANNELS the GitHub Releases come from:

- A **rolling, calendar-versioned** release published AUTOMATICALLY on EVERY push to main
  (`.github/workflows/rolling-release.yml`), versioned `YYYY.MMDD.N` (the UTC date plus a per-day
  build number). Each rolling build ships the three static musl binaries, their per-binary
  `.sha256`, a consolidated `SHA256SUMS`, and a keyless Sigstore build-provenance attestation. It is
  a NORMAL release, so GitHub's `releases/latest` (and therefore the `curl | sh` installer's default
  and the installer's `--version latest`) resolves to the newest rolling build. This is the
  continuous channel that makes "install" mean "grab the binary for your arch from the latest
  release". It carries NO changelog gate (rolling builds are continuous, not curated) and does not
  attach the `.deb`. It DOES publish the distroless container image: every rolling build pushes a
  multi-arch (amd64/arm64/armv7) image to `ghcr.io/elares/ironbus`, tagged `:latest` and
  `:YYYY.MMDD.N`, so the registry image is the live, continuously-published one (#334).
- A **formal, tagged** release cut on a `v*` tag by the maintainer (`.github/workflows/release.yml`).
  This is the curated channel: it adds the `.deb` per triple, the syft CycloneDX SBOM, and a
  changelog gate (an empty `## [Unreleased]` FAILS the release before any binary is built), and it
  pushes the same multi-arch container image to `ghcr.io/elares/ironbus` (tagged `:vX.Y.Z`, plus
  `:latest` for a non-prerelease). A 0.x tag is published as a prerelease, so it does not move
  `releases/latest` or the image `:latest`.

Plus the lifecycle on an unattended edge node: an atomic in-place [upgrade](#in-place-upgrade-and-rollback)
that never overwrites the live binary, one-command rollback, fall-back after N failed starts, and an
explicit [`migrate` gate](#on-disk-format-compatibility-and-the-migrate-gate) so an on-disk format
bump is never silent.

## 1. The fail-closed installer

`scripts/install.sh` detects the host architecture, maps it to a friendly asset suffix, downloads the
matching `ironbus-linux-<arch>` binary (e.g. `ironbus-linux-arm64`) AND the release `SHA256SUMS`, and
verifies the SHA256 BEFORE installing. The asset is a static `musl` binary with no runtime dependency
even though the friendly name drops `musl`; the `unknown`-vendored triple stays the internal build
target only. It
is fail-closed: any download error, a missing or mismatched checksum, a malformed `SHA256SUMS`, or an
unsupported platform aborts with a non-zero exit and installs nothing. It never `eval`s or `sh`-pipes
downloaded content, and there is no skip-verification override. On an upgrade it retains the prior
binary as `ironbus.prev` (an atomic same-directory move) before the atomic swap, so a rollback copy
always exists. Full usage is in [RELEASING.md](../RELEASING.md#install-the-fail-closed-installer).

```sh
curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh | sh
```

## 2. The Debian `.deb` package

Built with [`cargo deb`](https://github.com/kornelski/cargo-deb) ([archived 2026-06-05](https://web.archive.org/web/20260605144432/https://github.com/kornelski/cargo-deb)) from the verified static binary; the
metadata lives in `[package.metadata.deb]` in `crates/ironbus-cli/Cargo.toml`. cargo-deb is a
build-time tool only: it is NOT a runtime or compile dependency of any shipped crate, so it adds
nothing to the binary's dependency graph and leaves the `cargo-deny` supply-chain gate untouched.

The package installs:

- `/usr/bin/ironbus`, the static binary (mode 0755).
- `/lib/systemd/system/ironbus.service`, a systemd unit running the broker as the unprivileged
  `ironbus` system user (created by the postinst) against `/var/lib/ironbus`.
- `/etc/ironbus/ironbus.env`, the default config (a dpkg conffile, so local edits survive upgrades).

The published `.deb` asset carries the same friendly CPU-arch name as the binary,
`ironbus-linux-<arch>.deb` (`ironbus-linux-amd64.deb`, `ironbus-linux-arm64.deb`,
`ironbus-linux-armv7.deb`), so it too drops the `unknown`-vendored triple; the triple stays the cargo
`--target` only. The unit is installed but NOT enabled or started automatically; enable it
deliberately:

```sh
sudo dpkg -i ironbus-linux-<arch>.deb
sudo systemctl enable --now ironbus
```

The CI/release path builds the verified static musl binary first, then packages it WITHOUT a rebuild
so the `.deb` ships the exact reproducible release bytes:

```sh
# (after the static musl binary is built and verified into target/<triple>/release/ironbus)
cargo deb -p ironbus-cli --no-build --no-strip --target <triple>
```

`.rpm` is deferred behind the same spec: the `assets` map that drives the `.deb` also drives an
[nfpm](https://nfpm.goreleaser.com/) ([archived 2026-04-13](https://web.archive.org/web/20260413200705/https://nfpm.goreleaser.com/)) config, and an `.rpm` job is added once a dnf/yum fleet exists.

### Fall-back-after-N wiring (the systemd unit)

The packaged unit (`packaging/systemd/ironbus.service`) wires the atomic-upgrade fall-back with a
consecutive-failed-start counter (a file next to the binary). Each lifecycle hook has ONE job, so the
count means "consecutive genuinely-failed starts" and a HEALTHY broker is never spuriously rolled back
(e.g. by repeated unclean power losses):

- `ExecStartPre` runs `ironbus record-start --dest <bin> --check`: it only CONSULTS the counter (never
  bumps it) and, once it has reached N (default 3) AND an `ironbus.prev` exists, runs
  `ironbus rollback --dest <bin>` to restore the last known-good binary before this start.
- `ExecStartPost` runs `ironbus record-start --dest <bin> --ok` AFTER a short readiness grace window
  (`IRONBUS_STARTUP_GRACE_SEC`, default 10s), CLEARING the budget. For a `Type=simple` service, a
  binary that crashes during the window has its `ExecStartPost` killed before the `--ok`, so a genuine
  failed start never clears the counter; a binary that stays up past the window is a real successful
  start and resets it to 0.
- `ExecStopPost` runs `ironbus record-start --dest <bin> --failed` ONLY on a non-clean exit. This is
  the SINGLE place the counter is incremented, so one crash cycle bumps it by exactly 1 (no
  double-count) and a deliberate `systemctl stop` (a clean exit) leaves it untouched.

So a node that cannot start a freshly-upgraded binary heals itself to the prior bytes after N genuine
consecutive failed starts, while an unclean power loss of a working broker never accumulates toward a
rollback (the consult-only `ExecStartPre` does not bump, and `ExecStartPost --ok` cleared the budget
on the last healthy start). `StartLimitIntervalSec=0` disables systemd's start-rate limiter so the
fall-back-after-N logic, not the rate limiter, governs restarts. N is `--max-failed-starts`
(default 3).

## 3. The distroless container image

`Dockerfile` builds a multi-stage image whose runtime stage is `gcr.io/distroless/static:nonroot`.
distroless static provides exactly what a static musl binary needs and nothing else: CA certificates
(for the future TLS uplink, #107), tzdata, an `/etc/passwd` `nonroot` user, and NO shell, package
manager, or libc. The image runs as the non-root `nonroot` user (uid 65532), never root.

A `FROM scratch` variant is RESERVED, not used: scratch carries no CA certs, no tzdata, and no passwd
entry, so a binary that does TLS or non-root execution would silently break on it. We default to
distroless to avoid that footgun; scratch is only viable once there is provably no TLS or tz
dependency.

### Required writable volume

The broker's WAL/segment directory (`IRONBUS_DATA_DIR`, default `/var/lib/ironbus`) MUST be a
writable volume mount owned by the nonroot uid (65532). The image itself is read-only; without the
mount the broker cannot open its data dir.

```sh
docker build -t ironbus:dev .
docker run --rm \
  -v ironbus-data:/var/lib/ironbus \
  -e IRONBUS_ADDR=0.0.0.0:7777 -p 7777:7777 \
  ironbus:dev
```

### Published image: `ghcr.io/elares/ironbus` (#334)

The image IS published to GitHub Container Registry. **Every rolling build** (every push to main,
`.github/workflows/rolling-release.yml`) builds the distroless image FROM the three already-verified
release binaries (no recompile) and pushes a `linux/amd64` + `linux/arm64` + `linux/arm/v7`
multi-arch manifest to `ghcr.io/elares/ironbus`, tagged with the calendar version AND `:latest`:

- `ghcr.io/elares/ironbus:latest` always tracks the newest rolling build.
- `ghcr.io/elares/ironbus:YYYY.MMDD.N` pins a specific rolling build.

The formal `v*` channel (`.github/workflows/release.yml`) pushes the same multi-arch manifest on a
tag, tagged `:vX.Y.Z` plus `:latest` (a 0.x prerelease pushes only the version tag, never moving
`:latest`). Both channels build with `Dockerfile.release`, a COPY-only image that copies the binary
that passed the `SHA256SUMS` check straight in, so the verify-before-package property holds and no
QEMU is needed (no foreign code runs during the build). The push uses the workflow's built-in
`GITHUB_TOKEN` with `packages: write` (ghcr.io is the repo's own registry), so no external or
org-level secret is required.

Pull and run (the image is multi-arch, so `docker` selects the layer for your CPU automatically):

```sh
docker pull ghcr.io/elares/ironbus:latest
docker run --rm \
  -v ironbus-data:/var/lib/ironbus \
  -p 127.0.0.1:7777:7777 \
  ghcr.io/elares/ironbus:latest serve --data-dir /var/lib/ironbus
```

The data dir MUST be a writable volume owned by the nonroot uid (65532); the image itself is
read-only (see [Required writable volume](#required-writable-volume)). The wire protocol is not yet
encrypted or authenticated, so the example binds the host port to loopback (`127.0.0.1:7777:7777`);
expose it to other machines only behind a firewall or an SSH / WireGuard tunnel, never to the open
internet.

**Package visibility (a one-time maintainer action).** The FIRST push CREATES the
`ghcr.io/elares/ironbus` package, which GitHub defaults to **private** (visible only to the repo).
An anonymous `docker pull` needs the package set to **public**, which is a one-time package-settings
toggle the maintainer makes in the GitHub UI (the package's *Package settings -> Danger Zone ->
Change visibility*) or via the API. The workflow push itself works with `GITHUB_TOKEN` regardless of
visibility; only the public anonymous pull depends on this toggle.

To build the image by hand from a verified binary (the single-arch path, e.g. for a local smoke):

```sh
docker build -f Dockerfile.release \
  --build-arg IRONBUS_BIN=dist/ironbus-linux-amd64 \
  -t ghcr.io/elares/ironbus:local .
```

## 4. Checksummed GitHub Releases

Each release publishes, for the three edge CPUs, a friendly-named static binary
(`ironbus-linux-amd64` for x86_64/amd64, `ironbus-linux-arm64` for arm64 / Raspberry Pi 4-5 64-bit,
`ironbus-linux-armv7` for armv7 / 32-bit Pi), a per-binary `.sha256`, one consolidated `SHA256SUMS`,
and a keyless Sigstore build-provenance attestation over the binaries and `SHA256SUMS`. Each binary is
a static `musl` build with no runtime dependency (the friendly name drops `musl`; the
`unknown`-vendored triple is only the internal cargo build target). This is the source of truth the
installer, the `.deb`, and the container all consume. The installer auto-detects the host arch and
picks the matching asset. Verify integrity with `sha256sum -c SHA256SUMS` and provenance with
`gh attestation verify <binary> --repo ELares/IronBus`.

These releases come from the two channels above: the **rolling** channel (automatic on every main
push, `YYYY.MMDD.N`, the three binaries + `SHA256SUMS` + provenance) and the **formal** `v*` channel
(which additionally attaches the cargo-auditable and CycloneDX SBOMs, the `.deb` packages, and rides
the changelog gate). The `curl | sh` installer and the `releases/latest` default both resolve to the
newest rolling build. Details in [RELEASING.md](../RELEASING.md#what-the-release-produces).

## In-place upgrade and rollback

A running broker is a binary with an open WAL, so an upgrade is a lifecycle operation, not a one-shot
install. The `ironbus upgrade` verb (and the installer's `install_binary`/shell twin) enforce two
properties:

- **The live binary is never overwritten in place.** The new bytes are written to a sibling temp file
  ON THE SAME FILESYSTEM, fsynced, the current binary is retained as `<dest>.prev` via an atomic
  same-directory rename, then the new file is `rename(2)`d over the destination. `rename` is atomic
  on POSIX, so **a power cut mid-upgrade leaves either the old binary (rename not yet applied) or the
  new binary fully on disk, never a truncated one.** The fsync before the rename guarantees the new
  bytes are durable before the rename publishes them.
- **A node that cannot start the new binary falls back to `ironbus.prev` after N failed starts**
  (default N = 3). The systemd unit records each failed start and, at the threshold, runs
  `ironbus rollback` to restore the prior known-good bytes. See the
  [unit wiring](#fall-back-after-n-wiring-the-systemd-unit).
- **The rollback is re-entrant under a power cut (#348).** A two-rename swap has a sub-microsecond
  window between the renames where `ironbus.prev` momentarily holds the bytes that were at the
  destination (the just-failed binary). A power cut there, or after the swap but before the
  failed-start counter is cleared, could otherwise let a re-entered `--check` promote those known-bad
  bytes. Two protections close it: (1) `rollback` restores `ironbus.prev` over the destination
  WITHOUT first moving the destination onto `.prev`, so the last known-good bytes in `.prev` are
  preserved for the whole rollback and a re-entry converges to the good binary; (2) when the counter
  reaches the cap, the failing binary's content fingerprint is recorded (durably, alongside the
  counter) as a known-bad guard, and `rollback` REFUSES to promote `ironbus.prev` if its fingerprint
  matches the recorded known-bad one. The guard is cleared only after a rollback restores the bytes
  and resets the counter (so a crash before that keeps the re-entry deterministic), and a genuine
  healthy start (`record-start --ok`) clears it too. These live entirely in the verbs; no unit change
  is needed.

The download-and-verify step is NOT re-implemented in `upgrade`: it stays in the fail-closed
`scripts/install.sh` (the single source of verify-before-install). `ironbus upgrade` is the
post-verify atomic swap, so it never weakens the fail-closed posture: any download/verify happens
BEFORE the swap.

```sh
# Verify and download the new binary with the fail-closed installer to a staging path, then swap it
# in atomically (retaining the prior binary as /usr/bin/ironbus.prev):
ironbus upgrade --new-binary /tmp/ironbus.new --dest /usr/bin/ironbus

# One-command rollback to the retained previous binary:
ironbus rollback --dest /usr/bin/ironbus
```

## On-disk format compatibility and the `migrate` gate

On-disk WAL/segment formats are forward/backward compatible WITHIN a major version (#4, #5): the
record header, segment header, and segment footer each carry a single `FORMAT_VERSION` byte (= 1
today), unknown record-flag bits are preserved, and the reserved header bytes give a future version
room to add fields without disturbing older readers. A v1 reader reads only v1 and refuses any other
version loudly rather than guessing a layout it does not know (see
[COMPATIBILITY.md](COMPATIBILITY.md)).

A format bump across a major version is gated behind the explicit `ironbus migrate` subcommand and is
NEVER silent:

- Within a major version (the data dir's stamped format equals this build's), `migrate` reports
  "no migration needed" and the data dir opens with no migration.
- A data dir whose stamped on-disk format version differs from this build's is REFUSED with a usage
  error unless the operator passes `--allow <to-version>` to acknowledge the bump explicitly. Even
  with `--allow`, this v1 build has no in-place migrator, so it reports the honest state rather than
  reinterpreting bytes under a layout it does not know.

```sh
ironbus migrate --data-dir /var/lib/ironbus
```

## Build provenance

`ironbus --version` emits the build version. The reproducible release embeds the exact commit and
build provenance (a keyless Sigstore build-provenance attestation over every artifact, verifiable
with `gh attestation verify`, plus a cargo-auditable SBOM embedded in the binary); see
[RELEASING.md](../RELEASING.md#reproducibility) and [SECURITY.md](../SECURITY.md).
