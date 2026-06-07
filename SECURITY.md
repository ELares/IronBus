# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue,
pull request, or discussion for a suspected vulnerability, since that can expose
edge fleets before a fix exists.

Use GitHub's private vulnerability reporting for this repository (the "Report a
vulnerability" button under the Security tab), or email security@ironbus.dev.
Include the affected version or commit, the conditions that trigger the issue,
and the impact you observed. We will work with you on coordinated disclosure and
credit you when the fix ships, unless you ask us not to.

## Supported versions

IronBus is pre-1.0 and under active development. Only the latest release is
supported. Fixes land on the main line and ship in the next release; we do not
backport to older pre-1.0 versions.

## What counts as a security issue

Beyond the usual classes (authentication and authorization bypass, memory
safety, denial of service, information disclosure), durability and
corruption-safety defects are treated as security-relevant. IronBus exists to
keep acknowledged data safe across power loss and corrupt files, so a bug that
loses an acknowledged write, reads past a torn tail, silently drops data, or
breaks the bounded-and-reported loss guarantee is handled with the same urgency
as a classic vulnerability.

## Verifying release binaries

Release binaries carry a keyless Sigstore build-provenance attestation, so you
can confirm an artifact was built by this repository's Release workflow without
trusting any local key. Each binary also ships with a SHA256 checksum. See
[RELEASING.md](RELEASING.md) for the exact verification commands
(`sha256sum -c` for integrity and `gh attestation verify` for provenance).
