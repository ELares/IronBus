#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# IronBus fail-closed installer (#103).
#
# Downloads the static `ironbus` binary that matches this host's architecture from a GitHub Release,
# verifies its SHA256 against the release's signed `SHA256SUMS`, and installs it. The release assets
# carry friendly CPU-arch names (`ironbus-linux-amd64` / `-arm64` / `-armv7`); they are static musl
# builds with no runtime dependency (not even a libc). It is
# FAIL-CLOSED: it NEVER places a binary it has not verified. Any download failure, a missing or
# mismatched checksum, or an unsupported platform aborts with a non-zero exit and installs nothing.
# It does not `eval` or `sh`-pipe any downloaded content; the only thing fetched is the binary and
# the checksum file, and the binary is only ever executed by the operator after install.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh | sh
#   # or, pinning a version and verifying provenance:
#   sh install.sh --version v0.1.0 --verify-provenance --bin-dir "$HOME/.local/bin"
#
# Flags:
#   --version <tag>        Release tag to install (default: latest). Pin this for reproducibility.
#   --bin-dir <dir>        Install directory (default: /usr/local/bin, or $HOME/.local/bin if the
#                          default is not writable).
#   --target <arch>        Force the asset arch suffix (linux-amd64 / linux-arm64 / linux-armv7)
#                          instead of auto-detecting from `uname -m`.
#   --verify-provenance    Additionally verify the keyless Sigstore build-provenance attestation
#                          with `gh attestation verify`. FAIL-CLOSED: if requested and `gh` is
#                          absent or verification fails, the install aborts. (Without this flag the
#                          SHA256 check is always enforced; provenance is opt-in because it needs
#                          the `gh` CLI and Rekor reachability, which an edge device may lack.)
#   --help                 Show this help.
#
# This installer is intentionally fail-closed and has NO insecure / skip-verification override.

set -eu

REPO="ELares/IronBus"

# ---------------------------------------------------------------------------------------------
# Pure helpers. These are sourced (not executed) by the test harness, so they must have no side
# effects at definition time and must not read the network. `main` at the bottom only runs when
# the script is executed directly, never when sourced.
# ---------------------------------------------------------------------------------------------

log() { printf 'ironbus-install: %s\n' "$*" >&2; }
die() { printf 'ironbus-install: error: %s\n' "$*" >&2; exit 1; }

# Map `uname -m` to the FRIENDLY release asset suffix (the published asset is `ironbus-<suffix>`,
# e.g. `ironbus-linux-arm64`). These static binaries are the `unknown`-vendored musl build targets
# internally, but ship under obvious CPU-arch names. Unknown -> empty (caller treats it as
# unsupported).
detect_target() {
    arch="${1:-$(uname -m)}"
    case "$arch" in
        x86_64 | amd64) printf '%s' "linux-amd64" ;;
        aarch64 | arm64) printf '%s' "linux-arm64" ;;
        armv7l | armv7 | armhf) printf '%s' "linux-armv7" ;;
        *) printf '' ;;
    esac
}

# Compute the SHA256 of a file as a bare lowercase hex digest, using whichever tool is present.
# Prints nothing and returns non-zero if no checksum tool exists (caller fails closed on empty).
sha256_of() {
    file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{ print $1 }'
    else
        return 1
    fi
}

# FAIL-CLOSED checksum verification. This is the security-critical core and is unit-tested over
# fixtures (see crates/ironbus-cli/tests/installer_verify.rs).
#
#   verify_checksum <binary_file> <asset_name> <SHA256SUMS_file>
#
# Returns 0 ONLY when <asset_name> has an entry in <SHA256SUMS_file> AND the actual SHA256 of
# <binary_file> equals that entry. Returns non-zero (and never 0) on: a missing/empty checksum
# file, no entry for the asset, a malformed entry, no checksum tool, or any digest mismatch. It
# treats every ambiguous or error condition as a verification FAILURE, never a pass.
verify_checksum() {
    bin_file="$1"
    asset_name="$2"
    sums_file="$3"

    [ -f "$bin_file" ] || { log "binary not found: $bin_file"; return 1; }
    [ -s "$sums_file" ] || { log "checksum file missing or empty: $sums_file"; return 1; }

    # Pull the expected digest for exactly this asset. `sha256sum` lines are "<hex>  <name>"
    # (two spaces) or "<hex> *<name>"; match the asset as a whole final field so a substring or a
    # differently-named asset cannot satisfy the check. Take only the first match's first field.
    expected="$(awk -v want="$asset_name" '
        { name = $2; sub(/^\*/, "", name); if (name == want) { print $1; exit } }
    ' "$sums_file")"

    if [ -z "$expected" ]; then
        log "no checksum entry for $asset_name in $sums_file"
        return 1
    fi
    # A SHA256 is 64 lowercase hex chars; reject anything else rather than trusting a junk line.
    case "$expected" in
        *[!0-9a-f]* | "") log "malformed checksum for $asset_name"; return 1 ;;
    esac
    if [ "${#expected}" -ne 64 ]; then
        log "malformed checksum length for $asset_name"
        return 1
    fi

    actual="$(sha256_of "$bin_file")" || { log "no sha256 tool (need sha256sum or shasum)"; return 1; }
    if [ -z "$actual" ]; then
        log "could not compute sha256 of $bin_file"
        return 1
    fi

    if [ "$actual" != "$expected" ]; then
        log "CHECKSUM MISMATCH for $asset_name"
        log "  expected: $expected"
        log "  actual:   $actual"
        return 1
    fi
    return 0
}

# Download <url> to <dest>, failing on any HTTP or transport error. Uses curl or wget; never
# pipes the body to a shell. Returns non-zero on failure so the caller can fail closed.
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        # -f: fail on HTTP >= 400; -S: show errors; -L: follow redirects; -o: to file.
        curl -fSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        die "need curl or wget to download $url"
    fi
}

# Atomically install the already-verified binary <src> at <dest>, retaining any prior binary as
# `<dest>.prev` for rollback (#133 step 10). This is pure (no network) and is unit-tested in
# isolation (see crates/ironbus-cli/tests/installer_verify.rs), so it must stay side-effect-free at
# definition time and be POSIX-sh portable.
#
#   install_binary <src> <dest>
#
# CONTRACT (the caller has ALREADY passed fail-closed verification before calling this, so this
# function never weakens verify-before-install):
#   - Stages <src> next to <dest> as a sibling temp, chmods it 0755, so a reader never sees a
#     partial file and an interrupted install never leaves a truncated binary at <dest>.
#   - UPGRADE (a file already exists at <dest>): retains the CURRENT <dest> as `<dest>.prev` (an
#     atomic same-directory `mv`, so the prior binary is never half-moved) BEFORE swapping the new
#     binary into place, so an operator can roll back to the prior known-good bytes.
#   - FRESH install (nothing at <dest>): retains nothing, so no spurious `.prev` is created.
# Returns non-zero (without installing) on any IO error.
install_binary() {
    src="$1"
    dest="$2"
    tmp_dest="${dest}.tmp.$$"
    cp "$src" "$tmp_dest" || { log "could not stage the binary next to $dest"; return 1; }
    chmod 0755 "$tmp_dest" || { log "could not chmod the staged binary"; rm -f "$tmp_dest"; return 1; }

    if [ -e "$dest" ]; then
        prev_dest="${dest}.prev"
        if ! mv -f "$dest" "$prev_dest"; then
            log "could not retain the previous binary as $prev_dest"
            rm -f "$tmp_dest"
            return 1
        fi
        log "retained the previous binary as $prev_dest (rollback copy)"
    fi

    mv -f "$tmp_dest" "$dest" || { log "could not install to $dest"; return 1; }
    return 0
}

# Build the release asset base URL for a tag (or the /latest/download redirect).
asset_base_url() {
    version="$1"
    if [ "$version" = "latest" ]; then
        printf 'https://github.com/%s/releases/latest/download' "$REPO"
    else
        printf 'https://github.com/%s/releases/download/%s' "$REPO" "$version"
    fi
}

# ---------------------------------------------------------------------------------------------
# Orchestration. Only runs when the script is executed, not when sourced for testing.
# ---------------------------------------------------------------------------------------------

main() {
    version="latest"
    bin_dir=""
    force_target=""
    verify_provenance="0"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version) version="${2:?--version needs a value}"; shift 2 ;;
            --version=*) version="${1#--version=}"; shift ;;
            --bin-dir) bin_dir="${2:?--bin-dir needs a value}"; shift 2 ;;
            --bin-dir=*) bin_dir="${1#--bin-dir=}"; shift ;;
            --target) force_target="${2:?--target needs a value}"; shift 2 ;;
            --target=*) force_target="${1#--target=}"; shift ;;
            --verify-provenance) verify_provenance="1"; shift ;;
            --help | -h)
                sed -n '2,40p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
                exit 0
                ;;
            *) die "unknown argument: $1 (try --help)" ;;
        esac
    done

    target="$force_target"
    [ -n "$target" ] || target="$(detect_target)"
    [ -n "$target" ] || die "unsupported platform: $(uname -m) (supported: x86_64, aarch64, armv7)"

    asset="ironbus-${target}"
    base="$(asset_base_url "$version")"
    log "installing $asset ($version) from github.com/$REPO"

    workdir="$(mktemp -d "${TMPDIR:-/tmp}/ironbus-install.XXXXXX")" || die "could not create a temp dir"
    # Clean up the scratch dir on any exit; a half-downloaded, unverified binary never survives.
    trap 'rm -rf "$workdir"' EXIT INT TERM

    log "downloading the binary and SHA256SUMS"
    download "${base}/${asset}" "${workdir}/${asset}" || die "download failed: ${base}/${asset}"
    download "${base}/SHA256SUMS" "${workdir}/SHA256SUMS" || die "download failed: ${base}/SHA256SUMS"

    log "verifying SHA256 against SHA256SUMS"
    verify_checksum "${workdir}/${asset}" "$asset" "${workdir}/SHA256SUMS" \
        || die "checksum verification FAILED; refusing to install $asset"
    log "checksum OK"

    if [ "$verify_provenance" = "1" ]; then
        command -v gh >/dev/null 2>&1 \
            || die "--verify-provenance requested but the gh CLI is not installed (fail-closed)"
        log "verifying the Sigstore build-provenance attestation with gh"
        gh attestation verify "${workdir}/${asset}" --repo "$REPO" \
            || die "provenance verification FAILED; refusing to install $asset (fail-closed)"
        log "provenance OK"
    fi

    # Choose the install dir: the explicit --bin-dir, else /usr/local/bin, else ~/.local/bin.
    if [ -z "$bin_dir" ]; then
        if [ -w /usr/local/bin ] 2>/dev/null; then
            bin_dir="/usr/local/bin"
        else
            bin_dir="${HOME}/.local/bin"
        fi
    fi
    mkdir -p "$bin_dir" || die "could not create install dir: $bin_dir"

    dest="${bin_dir}/ironbus"
    # Install atomically, retaining any prior binary as `ironbus.prev` for rollback (#133 step 10).
    # This runs ONLY after the fail-closed checksum (and optional provenance) verification above has
    # passed, so it never weakens verify-before-install: the new binary is fully verified before the
    # `.prev` retention or the swap touch the install dir.
    install_binary "${workdir}/${asset}" "$dest" || die "could not install to $dest"

    log "installed verified ironbus to $dest"
    case ":${PATH}:" in
        *":${bin_dir}:"*) : ;;
        *) log "note: $bin_dir is not on your PATH; add it to run 'ironbus' directly" ;;
    esac
    log "done. run: $dest --version"
}

# Run main only when executed directly. A harness that sources this file to unit-test the helpers
# (e.g. crates/ironbus-cli/tests/installer_verify.rs) sets IRONBUS_INSTALL_SH_SOURCED=1 first, so
# the functions above are defined and callable with no network access and no install side effects.
# `$0` is not a reliable "am I sourced" signal under POSIX `sh`/`dash` (it stays the script path on
# a `. ./install.sh`), so the explicit sentinel is the portable guard.
if [ "${IRONBUS_INSTALL_SH_SOURCED:-0}" != "1" ]; then
    main "$@"
fi
