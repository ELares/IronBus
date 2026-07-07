# Transport security, the bind invariant, and pre-auth DoS defenses

This document is the normative specification for IronBus transport security: the
TLS 1.3 layer that protects the wire, the bind invariant that keeps an
unconfigured node off the network, and the pre-authentication denial-of-service
defenses that bound a handshake or connection flood before any credential is
checked. It is the network-boundary half of the security epic (#18); the
credential model it leans on (auth identities, the three authorization scopes) is
specified separately in #106.

> **Status (updated ADR-0004 / #766, TLS increments 1–2b): SERVER-SIDE TLS 1.3
> TERMINATION now SHIPS behind the non-default `tls` Cargo feature.** A broker
> built `--features tls` and given `--tls-cert` + `--tls-key` terminates a real
> TLS 1.3 handshake (rustls + the owner-ratified `aws-lc-rs` provider, ADR-0004),
> so a non-loopback bind is genuinely encrypted — no `--insecure-plaintext-wire`
> opt-in required. The FAIL-CLOSED BIND INVARIANT (section 2) stays enforced with
> the same honest rule: no config may imply encryption it does not deliver. The
> matrix is now feature-aware:
>
> - **The default loopback bind stays zero-config** (no TLS, no auth, no flag) —
>   byte-for-byte the historical dev path.
> - **`--features tls` build, `--tls-cert` + `--tls-key`: HONORED.** The wire is
>   TLS 1.3-encrypted; a non-loopback bind is allowed with no plaintext opt-in.
>   Exactly ONE of the pair is incomplete material and is REFUSED fail-closed; the
>   private key is `StrictModes`-checked (owner-only) before it is read.
> - **DEFAULT (non-`tls`) build, any `--tls-cert`/`--tls-key` (flag OR
>   `IRONBUS_TLS_*` env): REFUSED** at startup with a typed usage error naming the
>   flag — that build links no TLS stack, so a cert cannot encrypt and must never
>   imply encryption. (Refused on any bind, even loopback.) Rebuild `--features
>   tls`, terminate TLS upstream, or pass `--insecure-plaintext-wire`.
> - **`--tls-client-ca` (mTLS) is REFUSED on EVERY build** until the mTLS increment
>   (#766) verifies client certificates — honoring it now would imply mutual
>   authentication IronBus does not yet perform.
> - **A non-loopback `--addr` with no TLS and no opt-in is REFUSED** (no silent
>   plaintext): use TLS, bind loopback + terminate TLS upstream, or pass
>   `--insecure-plaintext-wire`.
> - **`--insecure-plaintext-wire` WITH an auth identity ALLOWS a non-loopback
>   plaintext bind** — the explicit, audited opt-in for the legitimate
>   TLS-terminated-upstream pattern (a mesh / proxy / VPN encrypts the wire; the
>   broker terminates plaintext + auth behind it) — and always emits a LOUD startup
>   WARNING that the broker wire is plaintext.
> - **`--insecure-plaintext-wire` WITHOUT auth is REFUSED** — never plaintext AND
>   anonymous off loopback.
>
> The precondition is checked pre-listen on the resolved address, so there is no
> window where an unprotected non-loopback socket accepts a connection. The
> connection-scoped auth model and the three-scope authorization (#631,
> [AUTHENTICATION.md](AUTHENTICATION.md)) ship with it (bearer/password verify on
> audited pure-Rust RustCrypto primitives). What REMAINS flagged: **mTLS**
> (`--tls-client-ca` client-certificate verification → identity mapping) and
> **client-side TLS** (the IronBus CLI/SDK verifying and connecting to a TLS broker,
> #957) are the next TLS increments; the crypto-provider supply-chain decision that
> once blocked all of this is RESOLVED (aws-lc-rs behind the `tls` feature,
> ADR-0004, a documented `deny.toml` C-FFI exception like `zstd-sys`; the default
> and `edge-min` builds stay byte-for-byte pure-Rust). The
> pre-auth DoS knobs (section 3) are parsed, validated, and surfaced with safe
> defaults, but their accept-loop *enforcement* (the per-IP token bucket + half-open
> cap + `connections_rejected_total{reason}`) is the next PR. The at-rest
> encryption (#108) and the audit-event export stream (#109/#635) remain
> specified-only. See [THREAT_MODEL.md](THREAT_MODEL.md) for the honest posture.
> Where this document constrains the handshake it cites #11 (the wire protocol and
> client API), where it adds a setting it cites #14 (the configuration system),
> and where it closes a threat it cites #105 (the threat model).

The single rule this document exists to enforce comes first, so no reader walks
away thinking IronBus can be put on a hostile network with a config that only
*looks* secure:

> **No config may imply encryption that is not delivered, and no non-loopback
> wire is ever silently plaintext.** A `--features tls` broker with `--tls-cert` +
> `--tls-key` DELIVERS TLS 1.3 encryption, so its non-loopback bind is genuinely
> secure. A build WITHOUT the `tls` feature cannot encrypt the wire, so a `--tls-*`
> cert is REFUSED there rather than accepted as a false promise of encryption. In
> either build a non-loopback plaintext bind is REFUSED unless the operator
> EXPLICITLY passes `--insecure-plaintext-wire` together with an auth identity, the
> honest, loudly-warned opt-in for a plaintext wire with TLS terminated upstream. A
> plaintext wire is never anonymous off loopback, and the broker refuses to start —
> before the listener opens, with an actionable error — in every other case.
> Zero-config plaintext exists only on the loopback interface, where the trust
> boundary is the host itself.

---

## Scope and non-goals

In scope:

- The TLS 1.3 transport: version floor and ceiling, the permitted cipher suites,
  where the TLS stack lives, and the client and server certificate-verification
  rules.
- The bind invariant: the default address, the precondition for any non-loopback
  bind, where and when it is validated, and what failure looks like.
- The pre-auth DoS defenses: a half-open (pre-auth) connection cap, a
  per-source-IP connection rate limit, and a failed-auth lockout, each with a
  safe default, each exposed as a #14 key, each on by default for a non-loopback
  bind and exempt on loopback.

Out of scope (specified elsewhere, cross-referenced where they touch this layer):

- The credential model: bearer token, username and password, and mTLS identities,
  and the publish / subscribe / admin scopes, are #106. This document treats "an
  auth identity is configured" as a precondition and specifies what happens at the
  transport boundary; it does not specify how a credential is shaped or checked.
- At-rest encryption of the data directory is #108.
- Secret-file handling, redaction, and audit events are #109.
- The wire framing and the `Connect` / `Info` handshake bodies are #11; this
  document constrains *when* TLS wraps that handshake and *when* a connection is
  counted as pre-auth, not the frame layout.

---

## 1. TLS 1.3 transport

### 1.1 Version: TLS 1.3 only, no fallback

IronBus speaks **TLS 1.3 and nothing older**. The minimum and maximum protocol
version are both pinned to TLS 1.3. There is no TLS 1.2 fallback, no
version-negotiation down-step, and no configuration knob that re-enables an
older version. A peer that cannot do TLS 1.3 cannot connect; the handshake
fails closed.

The rationale is that IronBus targets edge devices that may sit on untrusted
networks for years, and a downgrade path is an attack surface (a network
attacker who can strip the TLS 1.3 offer to force a weaker 1.2 suite). Pinning
the floor and the ceiling to the same version removes that path entirely. TLS
1.3 also removes the legacy cipher and key-exchange baggage (static RSA, CBC,
renegotiation) that the older downgrade attacks lived in.

### 1.2 Cipher suites: the TLS 1.3 AEAD set only

The permitted cipher suites are exactly the three TLS 1.3 AEAD suites:

| Suite | AEAD | Notes |
| --- | --- | --- |
| `TLS_AES_256_GCM_SHA384` | AES-256-GCM | Preferred where AES hardware (AES-NI / ARMv8 crypto) is present. |
| `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 | Preferred on a device with no AES hardware acceleration; constant-time in software. |
| `TLS_AES_128_GCM_SHA256` | AES-128-GCM | Permitted; a lighter AES-GCM option. |

There are no non-AEAD suites because TLS 1.3 defines none; this table is the full
1.3 suite set, stated explicitly so the spec is closed rather than "whatever the
library defaults to". Suite ordering is a server preference and SHOULD prefer the
ChaCha20-Poly1305 suite when the host reports no AES acceleration, so an edge
device without AES-NI does not pay the software-AES cost; this is a performance
preference, not a security ranking (all three are AEAD and acceptable). The
key-exchange groups are the TLS 1.3 ECDHE groups (X25519 preferred); static key
exchange does not exist in 1.3, so forward secrecy is structural.

### 1.3 The TLS stack is bundled in the binary

IronBus carries its own modern TLS implementation (rustls, with a vendored or
statically linked crypto provider) inside the binary. TLS capability is a
property of IronBus, not of the host OS: the broker does not link the platform's
system TLS (OpenSSL, SChannel, Secure Transport) and does not depend on a
system-installed library or trust store being present or current. The oldest,
most stripped-down target platform still gets TLS 1.3, and the TLS version and
suite set are the same on every platform because they come from the bundled
stack, not the host.

The trade-off, recorded honestly: a bundled TLS stack means a TLS-relevant
advisory is patched by shipping a new IronBus binary, not by a host `apt
upgrade`. The release machinery (provenance, SBOM, `cargo-deny` advisory gate;
see [THREAT_MODEL.md](THREAT_MODEL.md), T9) is what makes that update path
auditable.

### 1.4 Certificate verification: mandatory on clients, mTLS optional

- **Server-certificate verification is mandatory on every client.** A client
  verifies the broker's certificate chain against a configured trust anchor (a CA
  bundle or a pinned certificate) and verifies the expected name. There is no
  "accept any certificate" / `insecure-skip-verify` flag, on the client or the
  broker. A client that cannot verify the server fails the handshake; it does not
  fall back to an unverified connection. This is what defeats the active MITM
  (THREAT_MODEL.md, T3): an in-path attacker cannot present a substitute
  certificate the client will accept.
- **mTLS is the optional strongest mode**, and the recommended one for an
  untrusted LAN. When the broker is configured to require client certificates,
  the TLS handshake itself carries the client identity: the broker verifies the
  client certificate against its configured client-CA trust anchor during the
  handshake, before the application-level `Connect` is processed. A client
  certificate that does not verify terminates the connection at the TLS layer. The
  mapping from a verified client certificate to an authorization scope is the auth
  model (#106); this document specifies only that mTLS, when enabled, is enforced
  at the handshake and that a verified client certificate satisfies the
  "configured auth identity" precondition of the bind invariant (section 2).
- **Server-only TLS (no client certificate) is still a full TLS deployment.** The
  wire is encrypted and the server is authenticated; the *client* is then
  authenticated by one of the other #106 credential mechanisms (bearer token or
  password) carried inside the now-encrypted `Connect`. mTLS raises that to
  cryptographic mutual authentication at the transport layer.

TLS material (the server certificate and private key, and for mTLS the client-CA
trust anchor) is supplied through #14 configuration keys. The exact key names,
file formats, and the fail-closed file-permission rules for the private key are
specified with the rest of the secret-handling surface in #109 and #14; this
document requires only that "TLS material is configured" be a checkable
precondition at startup (section 2). Loading TLS material follows the
secret-file-permission rule (refuse to start on a group- or world-readable key
file) defined in #109.

---

## 2. The bind invariant

### 2.1 Default bind is loopback

The default wire-protocol bind address is `127.0.0.1:7777` (loopback), and the
optional health endpoint, when enabled, defaults to a loopback address as well
(see [CLI.md](CLI.md), `--addr` / `--health-addr`). An operator who runs the
broker with no network configuration gets a localhost broker, reachable only from
the same host. This is the existing default today; what #107 adds is that the
default is no longer the *only* thing keeping the broker off the network.

A bind is **loopback** if every address it resolves to is in the IPv4 loopback
block `127.0.0.0/8` or is the IPv6 loopback `::1`. A bind is **non-loopback**
otherwise, which includes the unspecified wildcard addresses `0.0.0.0` and `::`
(binding the wildcard exposes the broker on every interface and is treated as
non-loopback). The classification is made on the resolved bind address, not on
the literal string the operator typed, so a hostname that resolves to a routable
address is non-loopback.

### 2.2 The precondition: the honest non-loopback matrix (refuse until native TLS)

The intended end-state is that a non-loopback bind requires BOTH TLS material AND
an auth identity. But the native TLS 1.3 handshake is **not yet implemented**
(#107: there is no allowed pure-Rust crypto provider on the `deny.toml` allowlist,
so rustls cannot run a handshake). A `--tls-*` cert therefore **cannot encrypt the
wire in this build**, and accepting one would falsely imply encryption that is not
delivered — the single defect this posture removes. Until #107 lands, the
non-loopback matrix is:

1. **Any `--tls-*` material set** (`--tls-cert`, `--tls-key`, or
   `--tls-client-ca`, by flag OR `IRONBUS_TLS_*` env) → **REFUSED** with a typed
   usage error naming the flag. Reserved/not-yet-honored: a cert cannot encrypt
   today, so it must never be accepted as a promise of encryption. This is checked
   FIRST and on **any** bind — even loopback — so a stray cert never creates a
   false impression of safety anywhere. (The loopback zero-config path is
   unaffected because it passes no `--tls-*`.)
2. **Non-loopback, no opt-in** → **REFUSED**. There is no silent plaintext: bind a
   loopback address and terminate TLS upstream, pass `--insecure-plaintext-wire`,
   or wait for native TLS (#107).
3. **Non-loopback, `--insecure-plaintext-wire`, WITH an auth identity** →
   **ALLOWED** as an explicit plaintext opt-in. This is the legitimate
   TLS-terminated-upstream pattern: a mesh / proxy / VPN encrypts the wire and the
   broker terminates plaintext + auth behind it. A **loud startup WARNING** is
   always emitted stating the broker wire is plaintext. An auth identity (#106: a
   bearer token, a username and password) is still required, so the wire is
   authenticated, never anonymous.
4. **Non-loopback, `--insecure-plaintext-wire`, NO auth identity** → **REFUSED**.
   The opt-in accepts a plaintext WIRE, never anonymous network access; plaintext
   AND anonymous off loopback is the worst case and is refused by construction.
5. **Loopback** → **ALLOWED** with zero config (no TLS, no auth, no opt-in).

The accidental-public-broker mistake the first draft allowed (bind a routable
address, no TLS, no auth) and the misleading-cert mistake (a `--tls-cert` that
implied encryption while the wire was served plaintext) are exactly the states
this matrix makes unreachable. When native TLS lands (#107), the `--tls-*` path is
re-enabled to actually encrypt and rejoins this decision (restoring the intended
TLS-material-AND-auth precondition, with `--tls-client-ca` again satisfying both
halves for mTLS).

### 2.3 Validated at startup, before the listener opens, fail-closed

The matrix is evaluated **during startup configuration validation, before the
broker binds the listening socket**. The ordering is normative: the broker first
refuses any `--tls-*` material (reserved/not-yet-honored), then resolves and
classifies the bind address, and for a non-loopback bind confirms the explicit
`--insecure-plaintext-wire` opt-in and at least one auth identity are present, and
only then opens the listener. In every refusing case the broker **exits non-zero
with an actionable error and never opens a network listener**. No partial state is
exposed: there is no window where a non-loopback socket is accepting connections
before the check runs.

The error messages are actionable: each names the offending flag or bind address
and points at the honest way forward. Representative forms:

```
error: --tls-cert is not yet honored: the TLS 1.3 handshake is the flagged
  follow-up #107 (no allowed pure-Rust crypto provider is on the deny.toml
  allowlist yet), so a TLS cert CANNOT encrypt the wire in this build — accepting
  it would falsely imply encryption that is not delivered. To bind a non-loopback
  address today, terminate TLS upstream (mesh / proxy / VPN) and bind a loopback
  address, or pass --insecure-plaintext-wire to explicitly accept a plaintext wire
  WITH auth, or wait for native TLS (#107).
```

```
error: non-loopback bind `0.0.0.0:7777` refused: the TLS 1.3 handshake is not yet
  implemented (#107), so the wire cannot be encrypted; bind a loopback address and
  terminate TLS upstream, pass --insecure-plaintext-wire to explicitly accept a
  plaintext wire with auth, or wait for native TLS. There is NO --tls-* path today.
  To run with zero config, bind a loopback address (the default 127.0.0.1:7777).
```

```
error: --insecure-plaintext-wire on non-loopback `0.0.0.0:7777` requires an auth
  identity: the opt-in accepts a PLAINTEXT wire (with TLS terminated upstream), but
  NEVER anonymous network access. Set --auth-config <identity-table> so network
  clients are authenticated.
```

(The flag names are the #14 / #106 keys; the `--tls-*` spellings are reserved now
and re-enabled when native TLS lands.)

### 2.4 No override into network-anonymous; the only plaintext opt-in is explicit, authenticated, and loud

There is **no flag, env var, or config key that allows a non-loopback bind with
anonymous clients**, and **none that makes a `--tls-*` cert imply encryption the
build cannot deliver**. The design deliberately omits an `--insecure` /
`--allow-anonymous`-style escape hatch for *anonymous* network access, because
such a flag is the single most common way a "secure by default" system ends up
exposed in production (someone sets it once to get past an error and never removes
it).

There is exactly **one** opt-in, and it is intentionally narrow: a
**plaintext WIRE** (never plaintext + anonymous) via `--insecure-plaintext-wire`
**with an auth identity**. It exists because the native TLS 1.3 handshake is not
yet wired (#107), so without it a non-loopback bind would be impossible even for
the legitimate, common deployment where a mesh / proxy / VPN already encrypts the
wire and the broker terminates plaintext + auth behind it. Three properties keep
it honest: (a) it never permits anonymous access — an auth identity is still
required; (b) it is `insecure`-named and emits a LOUD startup warning every boot,
so it cannot be set-and-forgotten silently; and (c) it is the *only* way to bind
non-loopback, so an operator cannot stumble onto plaintext by misconfiguring TLS —
a `--tls-*` cert is refused outright, never silently downgraded to plaintext.

Zero-config plaintext otherwise exists only on loopback. A loopback bind MAY run
without TLS, without auth, and without the opt-in, silently (no warning), because
the trust boundary there is the host itself: a peer that can reach `127.0.0.1` is
already on the box, and local tooling and the same-host CLI (#15) must work with
zero configuration. The moment the bind is non-loopback, the section 2.2 matrix
applies with no further exception.

---

## 3. Pre-authentication DoS defenses

These defenses bound resource consumption by a client that has connected but not
yet authenticated, so a flood of half-open or rapidly-reconnecting connections
cannot exhaust a small edge device before any credential check happens. They
extend the existing global connection cap and slowloris timeout
([THREAT_MODEL.md](THREAT_MODEL.md), T7), which are total-not-per-source and so do
not by themselves stop a single noisy source from consuming the whole budget.

**On by default for a non-loopback bind; exempt on loopback.** All three defenses
below are active by default whenever the bind is non-loopback, and are not applied
to a loopback bind. The loopback exemption mirrors the bind invariant's trust
model: local same-host use (#15, the CLI, local tooling, tests) must never be
throttled or locked out, and a flood from `127.0.0.1` is a local actor with bigger
options than reconnecting in a loop. Each defense is a #14 key with a safe default,
so an operator can tune or, for a trusted segment, disable it, but the safe value
is the default and requires no configuration to be protected.

A connection is **pre-auth** (half-open, in the sense used here) from the moment
it is accepted until it has successfully authenticated (completed the TLS
handshake where required, and presented an accepted credential per #106) or has
been closed. The caps and limits below count pre-auth connections; once a
connection authenticates it leaves the pre-auth accounting and is governed by the
normal per-connection resource bounds (the global connection cap, per-consumer
credit, frame cap; see THREAT_MODEL.md).

### 3.1 Half-open (pre-auth) connection cap

A bound on the number of connections that are accepted but **not yet
authenticated** at any instant. Past the cap, a newly accepted connection is
closed immediately rather than admitted to the pre-auth pool. This caps the
memory and descriptor cost of a handshake flood: an attacker who opens many
connections and never finishes authenticating cannot pile up unbounded pre-auth
state, and cannot starve the global connection cap with half-open connections,
because the pre-auth pool is bounded independently of the (larger) total
connection cap.

- **Default: 128** pre-auth connections.
- It is distinct from and smaller than the global `--max-connections` cap
  (default 256): the global cap bounds *all* connections, this bounds the
  *unauthenticated* subset, so authenticated long-lived clients cannot be denied a
  slot by a pile of half-open ones.
- A connection leaves the pre-auth count the instant it authenticates or closes,
  so a steady stream of clients that authenticate promptly never approaches the
  cap; only connections that linger unauthenticated occupy it.

### 3.2 Per-source-IP connection rate limit

A token-bucket rate limit on **new connections accepted from a single source IP**.
A source that opens connections faster than the configured rate has its excess
connection attempts dropped (the connection is closed right after accept, before
any pre-auth work), while other sources are unaffected. This is the per-source
control the global cap lacks: it stops one address from churning connections to
drive failed-auth attempts or to occupy the pre-auth pool, without penalizing the
rest of the network.

- **Default: 10 connections per second** per source IP, token-bucket (so a short
  burst above the steady rate is tolerated up to the bucket depth, then the rate
  binds).
- The limit is keyed on the source IP, not the (IP, port) pair, so opening many
  source ports from one host does not multiply the budget.
- Long-lived IronBus connections reconnect rarely, so a steady-state legitimate
  client sits far below 10/sec; the default is conservative on purpose (see the
  tuning note below).

### 3.3 Failed-auth lockout with a fixed escalating accept delay

After a source IP accumulates **N failed authentication attempts**, the broker
locks that source out: it closes the connection on the failed attempt and applies
an **escalating delay before it will accept the next connection from that
source**. This blunts a reconnect-and-retry credential-guessing loop
([THREAT_MODEL.md](THREAT_MODEL.md), T6): each wrong guess costs the attacker an
increasing, enforced wait, so the guess rate collapses, while a legitimate client
that mistypes a credential a few times pays only a small, bounded delay.

- **Default threshold: N = 5** failed attempts from a source before the lockout
  engages.
- The delay **escalates** with continued failures from the same source (for
  example a bounded backoff schedule), so a persistent guesser is slowed more than
  a one-off fat-finger, up to a cap, and the lockout decays once the source stops
  failing, so a legitimate client is not permanently banned by a transient
  misconfiguration.

**Constant-time guarantee (load-bearing).** The escalating delay is implemented as
a **fixed delay applied at accept / connection-admission time**, NOT as a
verify-time difference. The credential comparison itself stays **constant-time**:
the broker does not return faster on a wrong credential than on a right one and
does not add the penalty *inside* the compare, so the lockout adds no timing
side-channel to the auth check. The penalty is a separate, deliberate sleep on the
*next accept* from that source, decided by the failure count for that source, not
by which byte of the credential mismatched. An attacker measuring response time
learns the source is rate-limited (which is intended and observable anyway), not
anything about the credential. The constant-time compare is part of the #106 auth
design; this document's requirement is that the lockout MUST NOT reintroduce a
timing oracle by piggy-backing the delay onto the compare.

### 3.4 The three defenses as #14 config keys

Each limit is a #14 configuration key with a safe default, following the existing
`serve` flag and `IRONBUS_<FLAG>` env-var convention (see [CLI.md](CLI.md), the
`serve` flag table and the environment-variable mapping). The flag and env-var
names below are the proposed surface; their exact spelling is fixed with the rest
of the TLS and auth keys in #14.

| Setting | Proposed flag | Proposed env var | Default | Unit | Mitigates (THREAT_MODEL.md) |
| --- | --- | --- | --- | --- | --- |
| Half-open (pre-auth) connection cap | `--max-preauth-connections <n>` | `IRONBUS_MAX_PREAUTH_CONNECTIONS` | `128` | count | T7 (handshake flood / half-open pile-up) |
| Per-source-IP connection rate | `--preauth-rate-per-ip <n>` | `IRONBUS_PREAUTH_RATE_PER_IP` | `10` | connections/sec (token-bucket) | T7 (single-source connection flood) |
| Failed-auth lockout threshold | `--auth-failure-lockout <n>` | `IRONBUS_AUTH_FAILURE_LOCKOUT` | `5` | failures | T6 (credential brute force by reconnect) |

Notes on the keys:

- Each default is the safe value; a non-loopback bind is protected with no
  configuration. On a loopback bind the keys are inert (the defenses are exempt
  there, section 3), matching the loopback exemption of the bind invariant.
- The defaults are deliberately conservative, since IronBus connections are
  long-lived and reconnect rarely; a legitimate client sits far below the rate
  limit and never trips the lockout, while the loopback exemption means local
  same-host use (#15) is never throttled. An operator on a known-friendly segment
  MAY raise the rate or the threshold; the design does not provide a way to take a
  *network* bind below the safe floor into "no pre-auth defenses", only to tune the
  numbers.
- The per-source state these defenses keep (the per-IP token bucket and
  failure-count map) is itself bounded so the defense cannot become a DoS vector:
  the tracking table is capped and evicts idle entries, so an attacker spraying
  many spoofed source IPs cannot force unbounded tracker memory. The eviction
  bound is sized with the rest of the #14 keys.

---

## 4. Threat-model traceability

This section ties each defense to the threat row it closes, so a later
implementation PR can show its mitigation lands against a specific threat and a
reviewer can confirm coverage at a glance. The rows are in
[THREAT_MODEL.md](THREAT_MODEL.md); #107 is the issue that, when implemented,
moves them from "not mitigated today" to mitigated.

| THREAT_MODEL.md row | Threat | How this spec closes it |
| --- | --- | --- |
| T2 | Untrusted-LAN passive eavesdrop | TLS 1.3 AEAD encryption of the wire (section 1.1, 1.2). |
| T3 | Untrusted-LAN active MITM | TLS 1.3 plus mandatory server-certificate verification on clients (section 1.4), with mTLS as the strongest mode. |
| T6 | Credential brute force by reconnect | Failed-auth lockout with a fixed escalating accept delay (section 3.3); the delay is constant-time-safe. |
| T7 | Pre-auth handshake / connection flood (DoS) | The half-open (pre-auth) connection cap (section 3.1) and the per-source-IP connection rate limit (section 3.2) add the per-source and half-open bounds the existing global cap lacks. |
| (bind note) | Accidental public broker (network bind, no TLS or auth) | The fail-closed bind invariant (section 2): a non-loopback bind without TLS and an auth identity is refused before the listener opens, with no override. |

The pre-auth-DoS row, T7, is the central one: THREAT_MODEL.md records that the
shipped connection cap and timeouts are *total, not per-source*, and explicitly
defers per-source rate limiting and the half-open cap to #107. Sections 3.1 and
3.2 are that deferred work, specified. T7 stays partially mitigated (the global
cap and slowloris timeout already exist) until #107 lands the per-source and
half-open bounds on top.

When #107 is implemented, THREAT_MODEL.md should be updated to move T2, T3, the
per-source half of T7, and the bind note from "not mitigated today" to mitigated,
and to add the new pre-auth keys to its secure-defaults catalog. That edit is part
of the implementation work, not this spec.

---

## 5. Failure considerations and accepted trade-offs

Recorded honestly, so the implementation accounts for them:

- **Over-aggressive rate limits could lock out a legitimate long-lived client.**
  Mitigated by conservative defaults (connections are long-lived and reconnect
  rarely, so a real client sits far below 10/sec and 5 failures), by the loopback
  exemption (local #15 use is never throttled), and by the failed-auth lockout
  decaying once a source stops failing rather than being a permanent ban.
- **A bundled TLS stack ties TLS patching to an IronBus release**, not a host
  library update (section 1.3). Accepted: the trade is a uniform, host-independent
  TLS 1.3 floor on every platform, and the auditable release path (provenance,
  SBOM, advisory gate) is what keeps the update trustworthy.
- **The fixed-delay lockout must not become a timing oracle.** Section 3.3 makes
  this explicit: the delay is at accept time, decided by the per-source failure
  count, never inside the credential compare, so the compare stays constant-time.
  An implementation that put the penalty in the verify path would reintroduce
  exactly the side-channel it is meant to avoid.
- **The per-source tracking tables are themselves a resource**, so they are
  bounded and idle-evicting (section 3.4), preventing a spoofed-source-IP spray
  from turning the defense into a memory-exhaustion vector.
- **No override into network-plaintext is a deliberate ergonomic cost.** An
  operator who genuinely wants a plaintext network bind cannot have one; the
  supported answers are a loopback bind, a local tunnel terminated on loopback, or
  configuring TLS and auth. This is the intended friction (section 2.4): the
  absence of an escape hatch is the feature.

---

## Cross-references

- [THREAT_MODEL.md](THREAT_MODEL.md): the enumerated edge threat model and the
  current (no-TLS, no-auth) posture; the T7 pre-auth-DoS row this spec extends,
  and the T2 / T3 / T6 rows it closes (#105).
- [CLI.md](CLI.md): the canonical `serve` flag map, the `IRONBUS_<FLAG>` env-var
  convention, and the existing `--addr` / `--max-connections` defaults the new
  keys sit beside (#136).
- [INVARIANTS.md](INVARIANTS.md): the shared subsystem invariants; the bind
  invariant (section 2) is a startup-validation rule in that family (#131).
- #11: the wire protocol and client API the TLS layer wraps and the handshake the
  pre-auth accounting measures.
- #14: the configuration system that carries the TLS material keys and the three
  pre-auth-defense keys, with the flag > env > default precedence.
- #106: the connection-scoped authentication and three-scope authorization model;
  the "auth identity" the bind invariant requires and the constant-time credential
  compare the lockout must not disturb.
- #18: the security epic this transport layer is part of.
