# IronBus secret handling, redaction, security audit events, and crypto SBOM posture

**Status: specified, not yet implemented; tracked by #109.** This document is the
normative design for how IronBus sources its secrets, protects them in memory and
on disk, keeps them out of every log and diagnostic, the structured security audit
events that make an attack on an unattended box visible, and the crypto dependency
posture that keeps the single binary auditable. None of it is wired into the binary
today: there is no auth and no TLS in the broker yet (the honest current posture is
in [THREAT_MODEL.md](THREAT_MODEL.md)), so there is no secret to source, redact, or
audit in the running code. The three load-bearing mechanisms this spec defines, the
**redacting newtype**, the **fail-closed secret-file permission check** at boot, and
the **security audit-event emitter**, are specified here, not yet in the binary.

This spec is the child of the security epic #18 and the sibling of the auth spec
(#106, [AUTHENTICATION.md](AUTHENTICATION.md)), the TLS spec (#107,
[TRANSPORT.md](TRANSPORT.md)), and the at-rest encryption spec (#108). It closes the
operator-footgun (a secret in a config file or a log line) and the supply-chain
surface (an unaudited crypto dependency) that the auth and transport specs assume but
do not themselves define.

Where this spec constrains a surface owned by another issue it cites that issue and
states the constraint, never claiming the surface already carries it: the #14
configuration system (where secrets are sourced), the #15 admin / diagnostic surface
(which must redact), the #16 observability / export contract (where the audit events
flow, see [METRICS.md](METRICS.md)), and the #17 release / SBOM machinery (where the
crypto surface must fit, see [RELEASING.md](../RELEASING.md)).

This document is the authority for the secret-handling contract. The README "Secure
by default" bullet ("IronBus refuses to start if a secret-bearing file is group or
world readable") and the THREAT_MODEL "specified controls not yet implemented" row
for #109 are summaries that point here; where they differ, this document is canonical.

---

## What counts as a secret

A **secret** is any byte string whose disclosure breaks a security boundary. The
complete v1 set, each owned by a sibling spec, is:

- **Bearer-token hashes** and **password (Argon2id PHC) hashes** from the #106
  identity table. The stored form is already a one-way hash, not the plaintext
  credential, but the hash is still a secret: it is the exact value a constant-time
  compare checks against, so leaking it enables an offline guessing attack and, for a
  bearer token stored as a raw SHA-256, a direct presentation attack. It is treated as
  a secret, not as public metadata.
- **The TLS private key** (#107). The most sensitive on-box material: disclosure lets
  any party impersonate the broker and decrypt recorded sessions.
- **The at-rest encryption key** (#108). Disclosure defeats at-rest encryption
  entirely (and a key co-located with a stolen disk is an accepted residual risk; see
  THREAT_MODEL T1).

Identity **names**, scope sets, SAN match strings, file paths, and the Argon2id
*parameters* (m, t, p, encoded in the PHC string) are **not** secrets: they are the
safe handles this spec routes through logs and audit events in place of the
credential. The rule is stated once and applied everywhere below: the **name is
safe, the credential is not.**

---

## Secret sourcing (constrains #14)

Secrets are **never inline in config.** No TOML key, no CLI flag, and no environment
variable ever carries a plaintext secret value. A secret is sourced by reference,
exactly two ways, both owned by the #14 configuration system:

- **From a file**, by path: the config names a path and the broker reads the secret
  bytes from it at startup (for example a `tls_key_file`, an `at_rest_key_file`, or a
  file holding the identity table's hash list).
- **From an environment variable**, by name: the config names an environment variable
  and the broker reads the secret from the process environment at startup (for example
  a container secret mounted as an env var by the orchestrator).

The config carries the **reference** (a path or an env-var name), never the value.
The hashed-credential lists in the #106 identity table (token SHA-256 digests,
Argon2id PHC strings, accepted SAN identities) live in a credential-bearing file that
is sourced this way and is subject to the permission check below. This is the
mechanism the auth spec already cites as "the #109 fail-closed secret-file-permission
rule"; this document defines it.

A reference that resolves to no value (a missing file, an unset env var, an empty
file) when the configuration requires that secret is a **fatal startup error**, not a
silent fall-through to no-secret. The broker fails closed: it does not start a
listener that needs a key it could not load.

### The fail-closed permission check (StrictModes)

At startup, before opening any listener, the broker **stats every secret-bearing
file** it was told to source and **refuses to start** (fail closed) if the file is
unsafe. The check matches OpenSSH `StrictModes`:

- **Group- or world-readable / writable is fatal.** A file whose mode has any bit in
  `0o077` set (`mode & 0o077 != 0`) is rejected: a secret a group or the world can
  read is not a secret. The required mode is owner-only (`0o600` for a file, `0o700`
  for a directory that holds secret files).
- **Wrong owner is fatal.** A secret file not owned by the user the broker runs as
  (and whose containing directory is not owned by that user or root) is rejected. This
  catches the wrong-owner-but-tight-permissions case: a `0o600` file owned by another
  user is still readable by that user and is refused. This is the case the issue calls
  out explicitly, and it is why the check is owner-and-mode, not mode alone.

On rejection the broker exits non-zero with an error that names the offending file's
**path and the failing condition** (the path is safe to log; see
[Redaction](#the-redacting-newtype)) and **never reads or logs the file contents.**
The refusal itself is a security audit event (`secret_permission_refusal`, below), so
a fail-closed boot is observable, not just a dead process.

**On a non-POSIX platform** (Windows), POSIX mode bits and Unix ownership do not
exist, so the mode/owner check is **skipped with a logged notice** stating that the
host filesystem permission model could not be enforced and that the operator owns
securing the file via the platform's own ACLs. The notice is emitted once at startup;
it is not a fatal error (the broker still starts), and it is itself the
identity-config-reload-adjacent kind of safe, secret-free log line this spec mandates.
In practice `serve` is Unix-only in v1 (see [CLI.md](CLI.md)), so the POSIX path is
the only one that runs the broker; the Windows skip-with-notice keeps the contract
total across platforms.

This boot check is **specified, not yet in the binary.** The closest shipped behavior
is the `serve` data-dir lifecycle, which creates the data dir with mode `0o700` and
probe-writes it (see CLI.md, "data_dir lifecycle"); the StrictModes check over secret
files is the new, unimplemented part.

---

## The redacting newtype

Every secret type is wrapped in a single **redacting newtype** so that a secret can
never be printed by accident. Redaction is by construction, not by discipline: a
reviewer or a test cannot rely on every call site remembering to redact, so the type
itself forecloses the leak.

- **`Debug` and `Display` emit a fixed placeholder**, never the wrapped bytes. The
  placeholder is a constant such as `<redacted>` (or `Secret(<redacted>)` for `Debug`,
  carrying the wrapper's type name but never its value), identical for every secret so
  the placeholder itself leaks nothing (not even the length). A struct holding a secret
  field derives `Debug` and the field prints as the placeholder, so a `{:?}` of a whole
  config, session, or error struct cannot spill a secret.
- **The raw bytes are reachable only through one explicit accessor** (an
  `expose_secret()`-style method), so every read of the underlying material is a
  greppable, review-visible call. There is no `Deref` to the inner bytes and no public
  field; the *only* ways to obtain the secret are construction and the named accessor.
- **The wrapper does not implement `Serialize`** (or implements it as the placeholder),
  so a secret cannot be serialized into a JSON diagnostic, a #15 dump, or an audit
  event by including its struct.
- **Key material is zeroed after use where the language allows** (see
  [Zeroization](#zeroization)).

This is the `secrecy`/`zeroize` newtype pattern stated as an IronBus invariant. The
exact crate choice (a vetted `secrecy`-style wrapper versus a hand-rolled newtype) is
deferred to the implementation PR; whichever lands, it must satisfy the redaction unit
test below and add no non-permissive or vendored-C dependency (see
[Crypto dependency surface](#crypto-dependency-surface-constrains-17)).

### One security-event emitter takes the name, never the credential

Every security event is routed through **one emitter**. The emitter's signature takes
the identity **name** (safe) and the structured fields below; it has **no parameter
that is a credential** and no way to pass one. There is no second logging path for a
security event: a call site cannot bypass the emitter and `log!` a credential, because
the credential is wrapped in the redacting newtype and the newtype renders as the
placeholder anyway. The emitter is the single choke point where the name-is-safe /
credential-is-not rule is enforced, and it is the only producer of the audit-event
schema below.

### The redaction unit test (mandatory)

A unit test asserts that **known secrets never appear in any log, error, or #15
dump.** The test is the review-catchable boundary the failure analysis names. It:

- Constructs each secret type (a token hash, a password PHC hash, a TLS private key, an
  at-rest key) wrapping a **known sentinel byte pattern**.
- Formats every surface that could leak: `Debug` and `Display` of the secret and of
  every struct that holds one (config, session, identity table, error types), every
  error message the auth and boot paths produce, the serialized form of any
  diagnostic, and the rendered #15 `dump` / `/admin` snapshot.
- Asserts the **sentinel pattern is absent** from every produced string, and that the
  fixed placeholder **is** present where a secret field was rendered (so the test fails
  both if a secret leaks and if a field that should redact was silently dropped instead
  of redacted).

Modeled on the frozen-taxonomy and frozen-tag tests already in the tree
([METRICS.md](METRICS.md), the resilience-counter freeze), this test makes a
redaction regression a CI failure rather than a review-only catch.

---

## Zeroization

Secret material is **zeroed after use where the language allows.** Rust gives no
absolute guarantee (a value can be copied by an optimizer or paged to swap before it is
cleared), so this is "best effort, by construction," stated honestly:

- The redacting newtype implements `Drop` to overwrite its bytes with zeros on drop,
  using a non-elidable write (the `zeroize` crate's `Zeroizing`, or `Drop` plus a
  volatile/compiler-fence write) so the optimizer cannot remove the clear as dead.
- Transient secret material (a presented password before hashing, a decrypted key
  buffer) is held in the same wrapper or in a `Zeroizing` buffer so it is cleared as
  soon as it leaves scope, not left in a freed allocation for the next allocator
  customer to read.
- The honest limits are recorded, not hidden: zeroization does not defend against a
  core dump, swap to unencrypted disk, a debugger on a live process, or a copy the
  compiler made before the clear. It narrows the window in which a freed secret sits in
  reusable memory; it is not a substitute for the permission check or for not having
  the secret on the box at all.

---

## Security audit events (exported via #16)

An attack on an **unattended** edge box is invisible without an audit trail, so the
audit-event requirement is part of the security boundary, not an add-on. IronBus
defines a **structured, secret-free** security audit event schema, emitted by the one
emitter above and **exported via the #16 observability contract**
([METRICS.md](METRICS.md)), so a security event is never silent, the same "no silent
event" philosophy the resilience counters already hold.

### The "no silent security event" alignment with #16

[METRICS.md](METRICS.md) freezes the rule that every resilience event (shed, drop,
skip, dead-letter, truncation, force-reap, recovery-loss) increments a stable-named,
documented counter so no resilience event is silent. This spec extends that philosophy
to security: every authn outcome, authz denial, rate-limit/lockout trip, secret-permission
refusal, and identity reload is a **named, structured audit event**. Like the
resilience counters, the event names form a **frozen set** a test pins, so adding,
removing, or renaming a security event is a deliberate, test-gated change, never an
accidental drift. The events carry **no payload bytes and no credential**, exactly as
the #16 metrics endpoint carries no secret material and no message payload (METRICS.md,
the loopback/trusted-network trust model). An audit event whose only safe identifier is
a name uses the name; it never uses a credential, an offset, or a message id as a
label (the `reason`-label discipline METRICS.md applies to recovery loss).

The transport of the events (a structured log stream, a counter family on `/metrics`,
or both) is owned by #16; this spec freezes the **schema and the field set**, not the
final wire spelling. A counter family (for example an `ironbus_authn_failures_total`
keyed by mechanism, or an `ironbus_authz_denials_total`) plugs into the existing
frozen-taxonomy contract; the per-event structured record (with the sequence number and
wall clock below) is the audit-log form. Both are secret-free.

### Common envelope: monotonic sequence plus wall-clock

Every audit event carries, in addition to its event-specific fields:

- A **monotonic sequence number**: a per-process `u64` that increments by one for every
  emitted audit event and **never** decreases, sourced from an atomic counter, not the
  clock. This is the authoritative ordering: it survives a clock jump (NTP step, manual
  set, suspend/resume) that would reorder or collide wall-clock timestamps. It mirrors
  the I6 discipline already in the tree (ordering never consults the wall clock; see
  [INVARIANTS.md](INVARIANTS.md)).
- A **wall-clock timestamp** (milliseconds since the Unix epoch): the human- and
  SIEM-facing "when," recorded for correlation with other systems but explicitly **not**
  trusted for ordering. When the two disagree (a later sequence with an earlier
  wall-clock), the sequence wins and the disagreement is itself the evidence of a clock
  jump.

This pair is the load-bearing answer to "ordering survives clock jumps": the sequence
orders, the wall clock contextualizes.

### The event set

Each event is structured, secret-free, and carries the common envelope. The set is
frozen (a test pins it):

| Event | Fields (all secret-free) | When |
| --- | --- | --- |
| **Authn outcome** | identity name (or the literal `<unknown>` for a failed lookup so an unknown-username probe does not echo attacker-supplied bytes), mechanism (`bearer` / `password` / `mtls`), outcome (`success` / `failure`) | Every connect-time authentication attempt (#106). The mechanism and outcome are recorded; the presented credential never is. |
| **Authz denial** | identity name, requested scope (`publish` / `subscribe` / `admin`), verb | A connection authenticated but lacked the scope for the verb it attempted (#106). The uniform Authorization Violation on the wire carries no oracle (AUTHENTICATION.md); the audit event, on the trusted side, may distinguish authn failure from authz denial for the operator without ever telling the client which. |
| **Rate-limit trip** | source identifier (IP), limit name | A per-source connection rate limit or half-open cap fired (#107, the pre-auth DoS defenses). |
| **Lockout trip** | identity name or source identifier, the failed-attempt count, the applied delay | The failed-auth lockout escalated its accept delay at the N=5 threshold (#107). |
| **Secret-permission refusal at boot** | file path, failing condition (`group_world_readable` / `wrong_owner` / `missing` / `unreadable`) | The StrictModes check above refused to start. Emitted before exit so a fail-closed boot is observable. The path is safe; the contents are never read. |
| **Identity config-reload** | the change summary (counts of identities added / removed / changed, by name, never by credential) | The #14 identity table was reloaded (when hot reload lands; today config is read once at startup). A rotation that adds or removes a credential is auditable by name. |

No event carries a token, a password, a key, a hash, or any message payload. The
identity **name** is the only identifier; an event whose subject has no name uses a
non-secret handle (a source IP for a pre-auth flood, the file path for a boot refusal).

These events are **specified, not implemented**: there is no audit emitter and no
security event in the binary today (there is no auth to succeed or fail). The schema
here is what #16 exports once the auth (#106) and transport (#107) paths that generate
the events land.

---

## #15 diagnostics must redact (constrains #15)

The #15 admin / data-introspection surface (the offline `dump` / `peek` readers in
[CLI.md](CLI.md), the `/admin` operational snapshot in
[AUTHENTICATION.md](AUTHENTICATION.md), and any future `info` / `consumer ls`)
**must redact stored credentials.** The constraint is already half-satisfied by
construction and half specified:

- **Already true by construction:** the offline `dump` / `peek` readers print only
  **sizes**, never the raw key or payload bytes (CLI.md, "Offline output shapes":
  "Only sizes are printed, never the raw key or payload bytes"), and the `/admin`
  snapshot exposes only stored offsets and operational state (durable head, cursors,
  lag, per-group state, DLQ depth, and the config echo), never key or payload bytes
  (AUTHENTICATION.md, the `admin`-gated stored-data introspection), and it predates any
  secret being loadable. So no message-payload secret leaks through a dump today.
- **Specified for when credentials exist:** once the #106 identity table is loaded into
  the broker, any diagnostic that echoes configuration (the `/admin` config echo, a
  future `config` dump) **must render every credential field as the redacting newtype's
  placeholder**, never the stored hash or key. Because the credentials are held in the
  redacting newtype, a diagnostic that serializes the config struct gets the placeholder
  for free; the spec's requirement is that no diagnostic add a bespoke path that reaches
  past the wrapper to print the raw value. The redaction unit test above includes the
  rendered #15 surfaces in its leak assertion, so a diagnostic that leaks a credential
  is a CI failure.

---

## Crypto dependency surface (constrains #17)

The crypto the security epic needs is a **small, enumerable** set of vetted,
pure-Rust, permissively-licensed crates, chosen so the whole surface fits the
`cargo-auditable` SBOM embedded in the #17 binary (see [RELEASING.md](../RELEASING.md))
and is gated by `cargo-deny` advisories (`deny.toml`). The surface, by sibling spec:

| Need | Crate (specified) | Owner | License posture |
| --- | --- | --- | --- |
| TLS 1.3 transport | `rustls` (with `ring` or `aws-lc-rs` as its crypto provider) | #107 | rustls is Apache-2.0 / MIT / ISC; the provider is permissive (ISC-style / Apache-2.0). Both fit the `deny.toml` allow-list. |
| At-rest AEAD (AES-256-GCM, ChaCha20-Poly1305) | the RustCrypto AEAD crates (`aes-gcm`, `chacha20poly1305`, over the `aead` trait) | #108 | MIT / Apache-2.0, pure Rust, already covered by the allow-list. |
| Password hashing | `argon2` (RustCrypto), at the m=19 MiB / t=2 / p=1 edge profile | #106 | MIT / Apache-2.0, pure Rust. |
| Token hashing | `sha2` (RustCrypto), SHA-256 for bearer-token storage | #106 | MIT / Apache-2.0, pure Rust. |
| Constant-time compare | `subtle` (RustCrypto), the non-short-circuiting equality the token and hash compares use | #106 | MIT, pure Rust. |
| Zeroization | `zeroize` (and a `secrecy`-style wrapper, see [the newtype](#the-redacting-newtype)) | #109 | Apache-2.0 / MIT, pure Rust. |

### How it fits the #17 SBOM and cargo-deny gate

- **It is in the SBOM.** The #17 release embeds a `cargo-auditable` dependency manifest
  in the binary (`ironbus.sbom.json`, extracted with `rust-audit-info`; see
  RELEASING.md, "What the release produces"). Every crate above, being a normal Cargo
  dependency of a shipped crate, is recorded in that manifest, so the crypto surface is
  enumerable from the shipped binary itself, with no separate artifact to trust. The
  SBOM is embedded **before** `strip` runs (RELEASING.md, "Determinism inputs"), so the
  manifest is present in the released bytes.
- **It is advisory-gated.** `deny.toml` sets `[advisories] yanked = "deny"` and
  `unmaintained = "all"`, so a yanked or unmaintained crypto crate fails the
  per-PR `cargo-deny` check; the CI `sbom` job exercises the SBOM path on every PR
  (RELEASING.md), so a tagged release runs no unproven step. A new RUSTSEC advisory
  against `rustls`, an AEAD crate, or `argon2` therefore breaks CI until it is updated
  or explicitly, auditably waived.
- **It is license-clean.** `deny.toml`'s `[licenses] allow` list is permissive-only
  (MIT, Apache-2.0, BSD, ISC, and the few others enumerated there). Every crate above is
  MIT or Apache-2.0 (or ISC for the TLS provider), so the crypto surface adds no license
  exception. The `ring`/`aws-lc-rs` provider contains vendored assembly/C for the
  primitives; this is the one place the #139 "pure-Rust default-data-path" rule is
  knowingly relaxed, and only for the TLS provider off the record path, exactly as the
  `deny.toml` C-FFI allowlist note (#102) anticipates. The decision of provider
  (`ring` vs `aws-lc-rs`, or rustls with a pure-Rust provider) is owned by #107; this
  spec records that whichever lands must stay on the allow-list or extend it
  deliberately.
- **It is minimal.** The list above is the **whole** crypto surface. The server crate
  has no third-party runtime dependency beyond the workspace crates today
  (THREAT_MODEL T9); these crates are the bounded, audited addition the security epic
  introduces, not an open-ended graph.

The exact crate **versions** are pinned by the committed `Cargo.lock` and the `--locked`
release build (RELEASING.md); this spec freezes the **surface** (which crates, why,
and the SBOM/deny gating), not the version numbers, which the lockfile owns.

---

## Specified but not implemented (honest status)

None of the following exists in the binary today. Do not assume any of it. There is no
auth and no TLS yet, so there is no secret to source, no audit event to emit, and no
crypto crate in the shipped graph.

| Item | Status | Owner |
| --- | --- | --- |
| Secret sourcing from file / env reference, never inline | Specified, not implemented | #109, #14 |
| Fail-closed StrictModes secret-file permission check at boot (mode `& 0o077`, wrong-owner); non-POSIX skip-with-notice | Specified, not implemented | #109 |
| The redacting newtype (fixed `Debug`/`Display` placeholder, single accessor, no `Serialize`) over all secret types | Specified, not implemented | #109 |
| The redaction unit test (known sentinel never appears in any log / error / #15 dump) | Specified, not implemented | #109 |
| Zeroization of secret material after use (best-effort, `Drop`/`zeroize`) | Specified, not implemented | #109 |
| The one security-event emitter (takes the name, never the credential) | Specified, not implemented | #109, #16 |
| The structured, secret-free audit-event schema (sequence + wall clock) exported via #16 | Specified, not implemented | #109, #16 |
| The frozen security-event set test | Specified, not implemented | #109, #16 |
| #15 diagnostics redacting stored credentials (the new credential path) | Specified, not implemented | #109, #15 |
| The crypto dependency surface (rustls + AEAD + argon2 + sha2 + subtle + zeroize) in the SBOM and under cargo-deny | Specified; the SBOM/deny machinery exists (#17), the crypto crates land with #106/#107/#108 | #109, #17, #106, #107, #108 |

---

## Cross-references

- [THREAT_MODEL.md](THREAT_MODEL.md): the current no-auth / no-TLS / no-at-rest posture
  and the "specified controls not yet implemented" row for #109 that points here; the
  T9 supply-chain residual risk this spec's crypto-SBOM posture narrows.
- [AUTHENTICATION.md](AUTHENTICATION.md): the #106 identity table whose token and
  password hashes this spec wraps and sources, and the "subject to the #109 fail-closed
  secret-file-permission rule" hook this document defines.
- [TRANSPORT.md](TRANSPORT.md): the #107 TLS private key this spec wraps, and the
  pre-auth rate-limit / lockout trips that emit audit events.
- [METRICS.md](METRICS.md): the #16 observability contract and the "no silent event"
  philosophy the security audit events extend; the frozen-taxonomy and `reason`-label
  discipline the audit-event set mirrors.
- [CLI.md](CLI.md): the #15 `dump` / `peek` / `/admin` diagnostics that must redact,
  and the `serve` data-dir lifecycle whose `0o700` create the StrictModes check extends
  to secret files.
- [RELEASING.md](../RELEASING.md): the #17 `cargo-auditable` SBOM and `cargo-deny`
  advisory/license gate the crypto surface fits.
- [INVARIANTS.md](INVARIANTS.md): I6 (ordering never consults the wall clock), the
  discipline the monotonic audit sequence number honors.
- The README "Secure by default" section and the security epic #18.
