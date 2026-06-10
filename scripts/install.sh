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
# Environment:
#   IRONBUS_INSTALL_DEST   FULL destination path for the binary (e.g. /usr/bin/ironbus), not a
#                          directory. When set it bypasses the default /usr/local/bin vs
#                          ~/.local/bin selection AND --bin-dir, and flows through the same atomic
#                          install (same-version no-op, ironbus.prev retention). Pair it with the
#                          packaged systemd unit, whose ExecStart runs /usr/bin/ironbus. Validated
#                          FAIL-CLOSED: a relative path, a directory, or a missing or unwritable
#                          parent directory aborts with a clear error and installs nothing.
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

# Classify the available `wget` from the FIRST LINE of `wget --version` (run under LC_ALL=C so
# the banner is never translated). Prints one of: gnu-wget-1 | wget2 | unknown. BusyBox and other
# minimal builds reject `--version` with a usage error; that classifies as `unknown`.
#
# Why every flavor below is REFUSED by `download` (#423): NO known wget can be trusted to pin the
# URL scheme across redirects for a NON-RECURSIVE single-file download, and SHA256SUMS travels
# over the same channel as the binary, so one plaintext hop lets a network-position attacker
# defeat the checksum gate entirely. Empirical record (2026-06-10):
#
#   - GNU wget 1.x: `--https-only` is honored ONLY in recursive mode (in wget's source,
#     opt.https_only is consulted only by download_child in src/recur.c). Verified on GNU Wget
#     1.25.0: `wget --https-only --secure-protocol=TLSv1_2 -nv -O out URL` (a) fetched a plain
#     http:// URL over plaintext with exit 0, and (b) followed an https-to-plain-http 302 and
#     fetched the body with exit 0. The flags are accepted and silently do nothing here.
#   - GNU wget2: tested on wget2 2.2.1 (GnuTLS build) and DISPROVEN, so it is refused too:
#     (a) `--https-only` does not apply to the command-line URL (a plain http:// URL downloads
#     over plaintext, exit 0); (b) its refusal of an https-to-http redirect EXITS 0 with no
#     output file, so a caller gets no failure signal; (c) `--https-enforce=hard` rewrites http
#     to https but silently FALLS BACK TO PLAINTEXT when the TLS connect fails (verified against
#     an http-only host: a plain `GET / HTTP/1.1` on the wire, exit 0, while reporting the URL
#     as https://); (d) combining `--https-only --https-enforce=hard` (either order) disables
#     the upgrade entirely and fetches the plain http:// URL over plaintext again. Unproven (here
#     disproven) enforcement is not trusted.
#   - BusyBox / anything unrecognized: no HTTPS-enforcement flags at all; never enforceable.
wget_flavor() {
    # Some builds (BusyBox) exit non-zero on --version; the text still prints, tolerate it.
    wget_version="$(LC_ALL=C wget --version 2>&1)" || true
    # Keep only the first line, with no external tool: the test harness calls these helpers on a
    # PATH that resolves nothing but stub tools (so no `head`).
    wget_nl='
'
    wget_version="${wget_version%%"${wget_nl}"*}"
    case "$wget_version" in
        "GNU Wget 1."*) printf '%s' 'gnu-wget-1' ;;
        "GNU Wget2"*) printf '%s' 'wget2' ;;
        *) printf '%s' 'unknown' ;;
    esac
}

# Download <url> to <dest> over HTTPS only; never pipes the body to a shell. Decision table:
#
#   curl (preferred)   used, with `--proto '=https' --tlsv1.2` pinning the scheme on every hop
#                      and the TLS floor; returns non-zero on any HTTP or transport error so the
#                      caller can fail closed.
#   wget, any flavor   REFUSED: `download` exits via `die` before any fetch is attempted. GNU
#                      wget 1.x only honors --https-only recursively, wget2's enforcement was
#                      empirically disproven, and BusyBox has no enforcement flags at all (see
#                      wget_flavor above for the full evidence). A flavor-specific error names
#                      the reason and the remedies.
#   neither            exits via `die`.
#
# The wget and no-tool branches deliberately `die` (exit) rather than return non-zero: no call
# site invokes download in a subshell, and exiting is the strongest fail-closed signal, so a
# future caller cannot ignore the status and proceed downgradable (#423).
download() {
    url="$1"
    dest="$2"
    remedy="install curl, or download it manually over HTTPS and verify it against SHA256SUMS"
    if command -v curl >/dev/null 2>&1; then
        # -f: fail on HTTP >= 400; -S: show errors; -L: follow redirects; -o: to file.
        curl -fSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        case "$(wget_flavor)" in
            gnu-wget-1)
                die "GNU wget 1.x cannot enforce HTTPS for a single-file download (--https-only is honored only in recursive mode, so a plain-http URL or an https-to-http redirect is fetched anyway; verified on GNU Wget 1.25.0); refusing to download $url with it; $remedy"
                ;;
            wget2)
                die "wget2 is not trusted to enforce HTTPS (tested on wget2 2.2.1: --https-only skips the command-line URL, its redirect refusal exits 0, and --https-enforce=hard falls back to plaintext when TLS fails); refusing to download $url with it; $remedy"
                ;;
            *)
                die "the available wget (BusyBox or an unrecognized build) cannot enforce HTTPS; refusing to download $url with it; $remedy"
                ;;
        esac
    else
        die "need curl to download $url (wget is refused: no flavor provably enforces HTTPS for a single-file download)"
    fi
}

# Atomically install the already-verified binary <src> at <dest>, retaining any prior binary as
# `<dest>.prev` for rollback (#133 step 10). This is pure (no network) and is unit-tested in
# isolation (see crates/ironbus-cli/tests/installer_verify.rs), so it must stay side-effect-free at
# definition time and be POSIX-sh portable.
#
#   install_binary <src> <dest> [version-label]
#
# CONTRACT (the caller has ALREADY passed fail-closed verification before calling this, so this
# function never weakens verify-before-install):
#   - SAME-VERSION re-run (<dest> exists and its SHA256 equals <src>'s): a no-op SUCCESS (#422).
#     Neither <dest> nor `<dest>.prev` is touched, so an idempotent re-provision (config management
#     re-running the installer for the version already live) can never clobber the rollback copy
#     with bytes identical to the live binary. Sets ironbus_install_skipped=1 for the caller.
#   - Stages <src> next to <dest> as a sibling temp, chmods it 0755, so a reader never sees a
#     partial file and an interrupted install never leaves a truncated binary at <dest>.
#   - UPGRADE (a file already exists at <dest>): STAGES the CURRENT <dest> bytes to a sibling temp
#     by COPY, never by moving the live binary (#421), and commits that staged copy over
#     `<dest>.prev` (one atomic same-directory `mv`) only AFTER the final swap has succeeded. So a
#     failed final swap leaves <dest> AND any pre-existing `<dest>.prev` exactly as they were: a
#     pre-existing good rollback copy is never replaced with bytes identical to the live binary by
#     an install that did not land. DELIBERATE TRADE: a crash between the final swap and the
#     `.prev` commit leaves `.prev` one version stale, an OLDER known-good binary, which is safer
#     than committing first and leaving `.prev` byte-identical to the possibly-bad binary just
#     installed. The live binary stays in place throughout, so there is never a window where
#     <dest> does not exist for a supervised restart to land in.
#   - Exactly ONE operation changes <dest>: the final atomic `mv`. If it fails, the live binary
#     AND any existing `.prev` are UNTOUCHED (the retention only STAGED a copy; nothing committed),
#     so every failure path leaves the host with the binary it already had (or, on a fresh install,
#     still nothing), never with neither the old binary nor the new one.
#   - FAIL-CLOSED ON AN UNREADABLE <dest>: the retention READS the live binary (`cp -p`), so an
#     existing-but-unreadable <dest> now fails the install closed (a deliberate behavior change:
#     the older `mv`-based retention needed no read permission). A live binary the installer
#     cannot read for retention is not upgraded over.
#   - SYMLINK at <dest>: a same-bytes re-run skips and leaves the symlink in place. With differing
#     bytes, `<dest>.prev` receives a regular-file COPY of the symlink TARGET's bytes, and the
#     final `mv` replaces the symlink ITSELF with a regular file (the old target file is left on
#     disk, no longer referenced from <dest>).
#   - FRESH install (nothing at <dest>): retains nothing, so no spurious `.prev` is created.
# Returns non-zero (live binary and any existing `.prev` untouched) on any IO error before or at
# the final swap. If the swap succeeded but the `.prev` commit then fails, the install itself
# stands (the host runs the new, verified binary) and the old `.prev`, one version stale, is kept;
# that is reported as a warning, not a failure.
install_binary() {
    src="$1"
    dest="$2"
    version_label="${3:-}"
    ironbus_install_skipped=0

    # SAME-VERSION GUARD (#422): if the destination already holds EXACTLY the bytes we are about
    # to install, this run is an idempotent re-provision, not an upgrade. Skip BOTH the `.prev`
    # retention and the swap: retaining here would overwrite the only rollback copy with bytes
    # identical to the live binary, leaving nothing to roll back to. If no sha256 tool exists the
    # comparison cannot run; fall through and install normally (never skip on an ambiguous answer).
    if [ -f "$dest" ]; then
        new_sum="$(sha256_of "$src")" || new_sum=""
        cur_sum="$(sha256_of "$dest")" || cur_sum=""
        if [ -n "$new_sum" ] && [ "$new_sum" = "$cur_sum" ]; then
            # Only a pinned tag (v*) reads naturally inline; "latest" (or any other channel word)
            # is parenthesized so the line never claims a literal version named "latest".
            case "$version_label" in
                "") log "ironbus already installed at $dest, nothing to do" ;;
                v*) log "ironbus $version_label already installed at $dest, nothing to do" ;;
                *) log "ironbus ($version_label) already installed at $dest, nothing to do" ;;
            esac
            ironbus_install_skipped=1
            return 0
        fi
    fi

    tmp_dest="${dest}.tmp.$$"
    cp "$src" "$tmp_dest" || { log "could not stage the binary next to $dest"; rm -f "$tmp_dest"; return 1; }
    chmod 0755 "$tmp_dest" || { log "could not chmod the staged binary"; rm -f "$tmp_dest"; return 1; }

    prev_dest="${dest}.prev"
    prev_tmp="${prev_dest}.tmp.$$"
    prev_staged=0
    if [ -e "$dest" ]; then
        # ROLLBACK RETENTION (#421), STAGED ONLY: `cp -p` the CURRENT binary's bytes to a sibling
        # temp WITHOUT unlinking or moving the live binary, and WITHOUT touching `<dest>.prev` yet.
        # The staged copy is committed over `.prev` only AFTER the final swap succeeds, so a failed
        # swap can never have replaced a pre-existing good `.prev` with bytes identical to the live
        # binary. (The pre-fix `mv <dest> <dest>.prev` retention opened a window where <dest> did
        # not exist and a failed final swap stranded the host with NO binary at <dest>.)
        if ! cp -p "$dest" "$prev_tmp"; then
            log "could not stage the previous binary for retention as $prev_dest"
            rm -f "$tmp_dest" "$prev_tmp"
            return 1
        fi
        prev_staged=1
    fi

    # SINGLE ATOMIC SWAP (#421): this `mv` is the ONLY operation that changes <dest>. On success a
    # reader sees the old binary or the new one, never a missing or partial file. On failure the
    # live binary is UNTOUCHED (the retention above only STAGED a copy) and any pre-existing
    # `.prev` is UNTOUCHED too (nothing has committed over it); discard both temps and report.
    if ! mv -f "$tmp_dest" "$dest"; then
        log "could not install to $dest (the existing binary and rollback copy, if any, are untouched)"
        rm -f "$tmp_dest" "$prev_tmp"
        return 1
    fi

    if [ "$prev_staged" = "1" ]; then
        # COMMIT THE RETENTION only now that the new binary is live: one atomic same-directory `mv`
        # replaces `.prev` with the staged copy of the just-replaced binary. A crash between the
        # swap above and this commit leaves `.prev` one version stale (an OLDER known-good), the
        # deliberate trade documented in the contract. If the commit itself fails, the completed
        # install stands and the old `.prev` (if any) is kept; warn rather than fail the install.
        if mv -f "$prev_tmp" "$prev_dest"; then
            log "retained the previous binary as $prev_dest (rollback copy)"
        else
            log "warning: could not commit the rollback copy to $prev_dest (keeping the existing one, if any; it is one version stale)"
            rm -f "$prev_tmp"
        fi
    fi
    return 0
}

# Resolve the FINAL install destination for the verified binary (#433), honoring the
# IRONBUS_INSTALL_DEST environment override. Sets `ironbus_resolved_dest` for the caller (a global,
# like install_binary's `ironbus_install_skipped`, so a validation failure can `die` in the
# caller's own shell rather than inside a command-substitution subshell whose exit a careless
# caller could ignore). Sourced by the test harness, so it must stay POSIX-sh portable and
# side-effect-free at definition time.
#
#   resolve_install_dest [bin_dir]
#
#   - IRONBUS_INSTALL_DEST set (non-empty): it is the FULL destination path of the binary itself
#     (e.g. /usr/bin/ironbus, pairing the script with the packaged systemd unit's ExecStart), NOT
#     a directory to put it in. It bypasses the default /usr/local/bin vs ~/.local/bin selection
#     AND --bin-dir, and flows through install_binary unchanged, so the same-version no-op guard
#     (#422) and the `<dest>.prev` rollback retention (#421) operate on the override path exactly
#     as on a default one. FAIL-CLOSED validation, each failure dying with an error that names the
#     problem:
#       * a relative path is refused (a destination that depends on the caller's cwd is an
#         accident waiting to happen, never an intent);
#       * a path that IS a directory (or ends in `/`) is refused: the override names the binary
#         file itself;
#       * a parent directory that does not exist or is not writable is refused: the installer
#         creates only the DEFAULT install dir, never an override's parents, and a non-writable
#         parent would otherwise surface later as a less actionable staging error.
#   - Otherwise: the explicit --bin-dir, else /usr/local/bin when writable, else ~/.local/bin (the
#     pre-#433 default selection, unchanged), with the chosen dir created via `mkdir -p` and the
#     binary named `ironbus` inside it.
resolve_install_dest() {
    rid_bin_dir="${1:-}"
    if [ -n "${IRONBUS_INSTALL_DEST:-}" ]; then
        rid_dest="$IRONBUS_INSTALL_DEST"
        case "$rid_dest" in
            /*) : ;;
            *) die "IRONBUS_INSTALL_DEST must be an absolute path to the binary (got the relative path: $rid_dest)" ;;
        esac
        case "$rid_dest" in
            */) die "IRONBUS_INSTALL_DEST must name the binary file itself, not a directory (got: $rid_dest; try ${rid_dest}ironbus)" ;;
        esac
        if [ -d "$rid_dest" ]; then
            die "IRONBUS_INSTALL_DEST is a directory, not a binary path: $rid_dest (set it to the full file path, e.g. ${rid_dest}/ironbus)"
        fi
        rid_parent="${rid_dest%/*}"
        [ -n "$rid_parent" ] || rid_parent="/"
        if [ ! -d "$rid_parent" ]; then
            die "IRONBUS_INSTALL_DEST parent directory does not exist: $rid_parent (create it first; the installer only creates the default install dir, never an override's parents)"
        fi
        if [ ! -w "$rid_parent" ]; then
            die "IRONBUS_INSTALL_DEST parent directory is not writable: $rid_parent (re-run with enough privilege to write it)"
        fi
        ironbus_resolved_dest="$rid_dest"
        return 0
    fi
    if [ -z "$rid_bin_dir" ]; then
        if [ -w /usr/local/bin ] 2>/dev/null; then
            rid_bin_dir="/usr/local/bin"
        else
            rid_bin_dir="${HOME}/.local/bin"
        fi
    fi
    mkdir -p "$rid_bin_dir" || die "could not create install dir: $rid_bin_dir"
    ironbus_resolved_dest="${rid_bin_dir}/ironbus"
}

# Parse the ExecStart binary path from systemd unit text on STDIN and print it (or nothing).
# Shell builtins ONLY (`read`, `case`, parameter expansion): the test harness calls the unit
# detection on a PATH that resolves nothing but stub tools, so no grep/awk/sed/head may be used
# here. Mirrors systemd's own override semantics: a later `ExecStart=` line wins (a drop-in
# override appears after the base unit in `systemctl cat` output) and an empty `ExecStart=` resets.
# The value is the first word after `ExecStart=`, with systemd's `+` full-privilege Exec prefix
# stripped (the only prefix this repo's unit uses; see packaging/systemd/ironbus.service, #420).
unit_execstart_from_stdin() {
    uefs_bin=""
    uefs_tab="$(printf '\t')"
    while IFS= read -r uefs_line; do
        case "$uefs_line" in
            ExecStart=*)
                uefs_val="${uefs_line#ExecStart=}"
                uefs_val="${uefs_val#+}"
                # First word: cut at the first space or tab (systemd separates argv with either).
                uefs_val="${uefs_val%% *}"
                uefs_val="${uefs_val%%"$uefs_tab"*}"
                uefs_bin="$uefs_val"
                ;;
        esac
    done
    printf '%s' "$uefs_bin"
}

# Detect the path of the binary the host's `ironbus` systemd unit actually runs (#433). Prints the
# unit's ExecStart binary path on stdout, or nothing when no unit can be found. CHEAP and
# POSIX-safe by construction: every external tool is guarded with `command -v`, the parsing uses
# only shell builtins (see unit_execstart_from_stdin), and every probe failure degrades to "no
# unit found" rather than an error, so a non-systemd host (or a restricted PATH) just gets no
# warning, never a broken install. Sources, in order:
#   1. `systemctl cat ironbus` when systemctl exists: the authoritative view, including drop-in
#      overrides.
#   2. Otherwise (no systemctl, or it knows no such unit) the unit files the .deb or an operator
#      would place, first readable one wins: /etc/systemd/system/ironbus.service, then
#      /lib/systemd/system/ironbus.service, read with shell redirection (no `cat` needed).
unit_exec_binary() {
    if command -v systemctl >/dev/null 2>&1; then
        ueb_text="$(systemctl cat ironbus 2>/dev/null)" || ueb_text=""
        if [ -n "$ueb_text" ]; then
            printf '%s\n' "$ueb_text" | unit_execstart_from_stdin
            return 0
        fi
    fi
    for ueb_file in /etc/systemd/system/ironbus.service /lib/systemd/system/ironbus.service; do
        if [ -r "$ueb_file" ]; then
            unit_execstart_from_stdin <"$ueb_file"
            return 0
        fi
    done
    return 0
}

# After the destination is chosen (override or default), warn LOUDLY when the host's ironbus
# systemd unit runs a DIFFERENT binary path than that destination (#433). A WARNING, never a
# failure: the install itself is correct, so the exit-0 path continues. Without this, an operator
# following the README one-liner next to the packaged unit gets a silent version split: the
# packaged unit hardcodes ExecStart=/usr/bin/ironbus (and IRONBUS_BIN=/usr/bin/ironbus for the
# whole fall-back-after-N machinery) while the script defaults to /usr/local/bin, so the service
# keeps running the unit's binary, PATH usually shadows it interactively, and the unit's
# rollback/record-start state never sees script-side upgrades. Finding NO unit binary (no
# systemctl and no unit file, i.e. a non-systemd host) prints nothing.
#
#   warn_if_unit_binary_differs <dest>
warn_if_unit_binary_differs() {
    wub_dest="$1"
    wub_unit_bin="$(unit_exec_binary)"
    if [ -z "$wub_unit_bin" ] || [ "$wub_unit_bin" = "$wub_dest" ]; then
        return 0
    fi
    log "##############################################################################"
    log "WARNING: the ironbus systemd unit runs a DIFFERENT binary than this install"
    log "         destination; the two paths WILL hold different versions over time."
    log ""
    log "  install destination:        $wub_dest"
    log "  systemd unit (ExecStart):   $wub_unit_bin"
    log ""
    log "The service keeps executing $wub_unit_bin; this install does not"
    log "change what the unit runs. The shell may also resolve 'ironbus' to the"
    log "install destination first on PATH, so the interactive CLI and the running"
    log "broker can be two different versions indefinitely, and the unit's"
    log "fall-back/rollback machinery (ironbus.prev next to ITS binary) never sees"
    log "upgrades installed here."
    log ""
    log "To upgrade the binary the unit actually runs, re-run the installer with:"
    log "  IRONBUS_INSTALL_DEST=$wub_unit_bin"
    log "##############################################################################"
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
    # Set late (after the install dir is chosen) but initialized here so the EXIT trap below can
    # reference it under `set -u` before that point.
    dest=""

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
                sed -n '2,42p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
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
    # Also remove install_binary's two sibling staging temps if an interrupt lands mid-install
    # ($dest is empty until the install dir is chosen below, so this is a no-op before then; the
    # temps never hold the only copy of anything, so removing them is always safe).
    trap 'rm -rf "$workdir"; if [ -n "$dest" ]; then rm -f "${dest}.tmp.$$" "${dest}.prev.tmp.$$"; fi' EXIT INT TERM

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

    # Choose the destination (#433): the IRONBUS_INSTALL_DEST override (the FULL binary path,
    # validated fail-closed in resolve_install_dest), else the explicit --bin-dir, else
    # /usr/local/bin, else ~/.local/bin.
    resolve_install_dest "$bin_dir"
    dest="$ironbus_resolved_dest"
    bin_dir="${dest%/*}"
    [ -n "$bin_dir" ] || bin_dir="/"
    if [ -n "${IRONBUS_INSTALL_DEST:-}" ]; then
        log "IRONBUS_INSTALL_DEST override in effect: installing to $dest"
    fi

    # UNIT-AWARENESS (#433): if this host's ironbus systemd unit runs a DIFFERENT binary path than
    # the destination just chosen, say so LOUDLY before installing (a warning, never a failure:
    # the packaged unit hardcodes ExecStart=/usr/bin/ironbus while the script defaults to
    # /usr/local/bin, so an operator following the README one-liner next to the .deb unit would
    # otherwise upgrade a binary the service never executes). Deliberately BEFORE install_binary,
    # so the warning also prints on the same-version no-op path below: the mismatch is about
    # WHERE the binary lives, not about whether bytes moved this run.
    warn_if_unit_binary_differs "$dest"
    # Install atomically, retaining any prior binary as `ironbus.prev` for rollback (#133 step 10).
    # This runs ONLY after the fail-closed checksum (and optional provenance) verification above has
    # passed, so it never weakens verify-before-install: the new binary is fully verified before the
    # `.prev` retention or the swap touch the install dir.
    install_binary "${workdir}/${asset}" "$dest" "$version" || die "could not install to $dest"

    # Idempotent same-version re-run (#422): the verified bytes are already live at $dest; nothing
    # was changed and the existing rollback copy (if any) is preserved. install_binary already
    # printed the "nothing to do" line; report success and stop here.
    if [ "${ironbus_install_skipped:-0}" = "1" ]; then
        exit 0
    fi

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
