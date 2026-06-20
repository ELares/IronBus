# IronBus connection-scoped authentication and the three-scope authorization model

**Status (updated #631, V2-M7): IMPLEMENTED.** The connection-scoped
authentication and three-scope authorization model in this document is now wired
into the broker. On an auth-required broker (an `--auth-config` identity table or
an mTLS client-CA is configured) the `Connect` handshake authenticates against the
identity table, the resolved scope set is pinned to the connection for its
lifetime, and every scope-gated verb is checked against it with NO implication
between scopes (`admin` does NOT grant `publish` or `subscribe`); every failure is
the single uniform "Authorization Violation" with no oracle. Bearer (SHA-256 +
constant-time compare) and username/password (Argon2id) verify on audited
pure-Rust RustCrypto primitives. The credential rides an additive, backward-
compatible section of the `Connect` body, so a no-auth (loopback-dev) broker is
byte-for-byte unchanged. The mTLS mechanism's SAN-to-identity mapping is
implemented and enforced; it becomes reachable once the TLS layer (the FLAGGED
follow-up, [TRANSPORT.md](TRANSPORT.md) section 1) supplies a verified peer
certificate — until then an mTLS-mechanism connect fails closed (no verified
cert), never a default-scope grant. The fail-closed bind invariant (a non-loopback
bind requires both TLS material and an auth identity, validated pre-listen) ships
with this. The honest posture is recorded in
[THREAT_MODEL.md](THREAT_MODEL.md). This spec is tracked by #106/#631 and is the
core auth contract every verb is gated by; it is the child of the security epic
#18 and the sibling of the TLS spec (#107), the at-rest encryption spec (#108),
and the secret-handling spec (#109).

Where this spec constrains an existing surface it cites the issue that owns it: the
#11 CONNECT handshake (the wire frames it extends), the #14 configuration system
(the keys it adds), and the #15 diagnostics surface (the commands it gates). It
never claims those surfaces already carry auth; they do not.

This document is the authority for the auth contract. The README "Secure by
default" bullets and the THREAT_MODEL "specified controls not yet implemented"
table are summaries that point here; where they differ, this document is canonical.

---

## Scope of v1

IronBus v1 specifies exactly **three** authentication mechanisms and exactly
**three** authorization scopes. Nothing else is in scope for v1.

- **Three mechanisms:** bearer token, username and password, and mTLS. NATS-style
  nkey and JWT account authentication is deliberately out of scope for v1. It is
  deferred, not flagged behind an option; the wire and config simply do not offer
  it, so an operator cannot select a mechanism that does not exist.
- **Three scopes:** `publish`, `subscribe`, `admin`. Each is granted explicitly per
  identity. **No scope implies another.** In particular `admin` does NOT imply
  `publish` or `subscribe`.

Authentication answers "who is this connection". Authorization answers "what may
this identity do". They are separate steps: a connection that authenticates
successfully but holds no scope for the verb it attempts is rejected exactly the
same way as a connection that fails authentication (see
[The uniform Authorization Violation](#the-uniform-authorization-violation)).

---

## Connection-scoped authentication

Authentication is established **once**, in the #11 CONNECT handshake, and is
**bound to the connection for its entire lifetime.** There is no re-authentication
verb, no credential refresh on the wire, and no way to change identity or scope on
a live connection. To assume a different identity, a client opens a new connection.

This is the MQTT session-scoped lesson stated as an invariant: the identity and the
authorized scope set are pinned at connect time and never consulted from
mutable per-message state thereafter. A verb is authorized against the connection's
pinned scope set, never against anything the client sends in the verb frame, so a
client cannot escalate by asserting a scope or identity in a later frame.

### Handshake placement (constrains #11)

Today the `Connect` frame (tag 1) and the `Info` reply (tag 2) carry **empty
bodies** (see [CONTRACTS.md](CONTRACTS.md), "FrameType tags", and
[COMPATIBILITY.md](COMPATIBILITY.md)). This spec gives `Connect` a body that
carries the credential and gives the server an authenticated/anonymous decision
before any other verb is accepted. The exact byte layout of the populated
`Connect`/`Info` bodies is a wire-format change owned by #11 and is frozen there,
not here; this document specifies the **semantics** the bytes must encode, not the
offsets.

The handshake sequence this spec requires:

1. The transport is established. On a non-loopback bind that means TLS 1.3 is
   already negotiated (#107); the auth credential is never sent over a plaintext
   non-loopback transport. The mTLS mechanism is part of that TLS handshake (see
   [mTLS](#mtls-san-based-identity)); the other two mechanisms present their
   credential in the `Connect` body inside the established TLS session.
2. The client sends `Connect` carrying its mechanism selector and credential
   material (for bearer token and username/password) or nothing beyond the selector
   (for mTLS, where the credential is the peer certificate already presented at the
   TLS layer).
3. The server authenticates the credential, resolves the connection to a single
   configured **identity**, and pins that identity's **scope set** to the
   connection.
4. On success the server replies `Info`. On any failure (unknown mechanism, bad
   credential, a verifying mTLS cert that matches no configured identity) the server
   replies with the single uniform `Err` "Authorization Violation" (tag 12) and
   closes the connection. There is no partial-auth state and no anonymous fallback
   on a configured-auth broker.

A connection that has not completed a successful `Connect` may send nothing but
`Connect`; any other verb before a successful handshake is an Authorization
Violation. This matches the existing dispatch rule that a verb sent before
`connected` is refused, tightened so that "connected" now means "authenticated".

---

## The three authentication mechanisms

### Bearer token

A bearer token is a high-entropy opaque secret presented in the `Connect` body. The
holder of the token is the identity; possession is proof.

- **Entropy.** A token MUST be at least 256 bits (32 bytes) of cryptographically
  random data. The broker does not mint tokens; the operator generates them out of
  band and configures their hashes (see [Rotation](#additive-credential-set-rotation)).
- **Storage.** The broker stores **only the SHA-256 of the token**, never the token
  itself. The configured value (#14 key, below) is the hex SHA-256 digest. A leaked
  config file therefore leaks digests, not usable tokens.
- **Comparison.** Verification hashes the presented token with SHA-256 and compares
  the digest to each configured digest using a **constant-time comparison** (a fixed
  32-byte compare that does not short-circuit on the first differing byte). This is
  mandatory: a byte-by-byte early-exit compare is a timing oracle that leaks the
  digest prefix and is a defect, not an option.
- **No reversible storage and no plaintext at rest.** Because only the digest is
  stored and the compare is over digests, the broker never holds a token in a form
  an attacker reading the config could replay.

SHA-256 (not a slow KDF) is correct here precisely because the token is full-entropy
random: there is no low-entropy secret to grind, so a password hash would add cost
with no security benefit. Username/password is the opposite case (below).

### Username and password

A human-memorable, therefore low-entropy, credential: a username string plus a
password presented in the `Connect` body.

- **Hashing.** The broker stores an **Argon2id** hash of each password, never the
  password. The edge profile parameters are **m = 19 MiB (memory cost), t = 2
  (iterations / time cost), p = 1 (parallelism)**. These are the OWASP-recommended
  Argon2id minimum and are chosen to be survivable on a small edge device while
  still making an offline guessing attack expensive. The salt is per-credential and
  stored in the standard PHC-string encoding alongside the hash, so the configured
  value is a self-describing Argon2id PHC string (it carries its own m, t, p, and
  salt).
- **Verification.** On `Connect`, the broker derives the Argon2id hash of the
  presented password using the parameters and salt encoded in the stored PHC string
  and compares. The verification itself is constant-time with respect to the stored
  hash bytes.
- **Why Argon2id and not SHA-256 here.** A password is low-entropy and guessable; a
  fast hash (SHA-256) would let an attacker who obtains the config grind billions of
  guesses per second. Argon2id's memory hardness makes that grinding expensive even
  on a GPU. The token case is reversed (full entropy, so a fast hash is correct):
  the mechanism dictates the hash, never operator preference.

### mTLS (SAN-based identity)

Mutual TLS: the client presents a certificate during the TLS 1.3 handshake (#107),
the broker verifies the chain to a configured trust anchor (CA), and the
**certificate's identity selects the configured scope set.**

- **Chain verification first.** The certificate MUST verify to a configured CA. A
  cert that does not chain-verify is rejected at the TLS layer; it never reaches
  identity resolution.
- **Identity is the SAN, by a fixed rule.** The identity is taken from the Subject
  Alternative Name extension using this exact precedence:
  1. the **first URI SAN**, if any URI SAN is present;
  2. otherwise the **first DNS SAN**.
- **CN is excluded.** The certificate **Common Name is NEVER used** as an identity,
  not even as a fallback when no SAN is present. CN-as-identity is a well-known
  source of impersonation bugs (CN is unstructured and was never meant to be an
  authorization principal). A certificate that verifies but carries no URI SAN and
  no DNS SAN has no usable identity and is rejected.
- **No default scope for a verifying cert.** A certificate that chain-verifies but
  whose resolved SAN identity matches **no configured identity** is **REJECTED**, not
  granted a default or empty scope and not allowed to connect anonymously. This is
  the load-bearing rule that closes the authz-bypass where "the cert verified, so let
  it in with some baseline access". Verification proves the cert is trusted; it does
  NOT prove the holder is authorized. Only an explicit SAN-to-identity match in the
  configured identity table grants any scope.

The SAN-to-identity match is exact-string against the configured identity name.
There is no wildcard, regex, or substring matching of SANs in v1.

---

## The three authorization scopes

Authorization is exactly three scopes, granted explicitly per identity. The scope
set pinned at connect time is the complete authority of the connection.

| Scope | Grants | Does NOT grant |
| --- | --- | --- |
| `publish` | Produce records (the `Pub` verb). | Consuming, acking, or any admin action. |
| `subscribe` | Subscribe and consume: `Sub`, `Unsub`, `Flow`, and the full ack vocabulary (`Ack`/`Nack`/`Term`/`Progress`, all carried as the `Ack` frame's op). | Producing, or any admin action. |
| `admin` | The admin-gated verbs and diagnostics (below). | Producing or consuming. **`admin` does NOT imply `publish` or `subscribe`.** |

**No scope implies another.** An identity that should both produce and consume is
granted `publish` and `subscribe` explicitly. An operator identity that should also
administer is granted all three. There is no "superuser" bit and no implication
chain; `admin` is the narrowest possible grant for administration, deliberately so,
to keep the blast radius of a leaked admin credential to administration alone.

### Verb-to-scope mapping (constrains the #11 verb set)

The frozen #11 verb set (see [CONTRACTS.md](CONTRACTS.md), "FrameType tags") maps to
scopes as follows. Server-to-client frames (`Info`, `Pong`, `Deliver`, `PubAck`,
`AckStatus`, `FlowEnd`, `DeadLetter`, `Truncated`, `Err`, `Ok`) are responses, not
client requests, so they are not scope-gated (`Pong` is the server reply to a
client `Ping`).

| Client verb (tag) | Required scope |
| --- | --- |
| `Connect` (1) | none (it IS the authentication step) |
| `Ping` (3) | none (liveness; carries no data and exposes no state) |
| `Pub` (5) | `publish` |
| `Sub` (6) | `subscribe` |
| `Unsub` (7) | `subscribe` |
| `Ack` (8), including the Nack/Term/Progress ops | `subscribe` |
| `Flow` (10) | `subscribe` |

A verb whose pinned scope set lacks the required scope is an Authorization
Violation, indistinguishable on the wire from an authentication failure.

### The admin-gated verb and diagnostic list

`admin` gates **anything that exposes stored data or mutates retention, identities,
or consumer state.** No produce/consume path is in the admin set, and no admin
action is reachable from `publish` or `subscribe`.

Today the only diagnostics surface that exists in the binary is the read-only
`/admin` HTTP endpoint on the embedded health server (off by default behind
`serve --enable-admin`), which is currently **UNAUTHENTICATED** and shares the
loopback/trusted-network trust model of `/metrics` (#99, #105). This spec brings
that surface, and the larger #15 / #136 diagnostic command tree, under the `admin`
scope when connection-scoped auth is enabled. The following require `admin`:

- **Stored-data introspection.** The read-only `/admin` operational snapshot
  (durable head, cursors, lag, per-group state, DLQ depth, the config echo). It
  exposes stored offsets and operational state, so it is `admin`-gated. The liveness
  probes `GET /healthz` and `GET /readyz` carry no stored data and stay ungated; the
  `GET /metrics` exposure decision is owned by #107 (the endpoint hardening issue)
  and is cross-referenced, not redefined here.
- **DLQ and stored-record inspection over the wire.** Any future verb or #15/#136
  diagnostic that reads stored records or the dead-letter sink to a client (the
  online analogues of the offline `peek`/`dump`/`dump --dlq` readers) requires
  `admin`, because it discloses message contents and metadata that `subscribe`'s
  normal delivery flow would not otherwise reveal out of order.
- **Mutating admin actions.** Consumer-cursor reset, DLQ redrive, and force-reap
  (the mutating-admin surface deferred to #299) require `admin`. These mutate
  retention and consumer state.
- **Identity and credential management, if ever exposed online.** Any future verb
  that lists, adds, or removes identities or credential hashes requires `admin`.
  (v1 rotation is config-and-deploy, not an online verb; see below.)

The **offline** CLI readers (`peek`, `dump`, `dump --dlq`) read the data directory
directly with the broker stopped (#15, #136); they are governed by filesystem
permissions, not by a connection scope, because there is no connection. This spec
does not change that. It governs only what is reachable over an authenticated
connection or the embedded HTTP server.

---

## Additive credential-set rotation

Credential validity is an **additive set**, not a single value with an expiry
clock. There is **no server-side expiry timer** and no credential-lifetime field on
the wire or in config.

- Each mechanism's configured credential is a **list**, not a scalar: a list of
  bearer-token SHA-256 digests per identity, a list of Argon2id PHC strings per
  username, a list of accepted SAN identities. A presented credential authenticates
  if it matches **any** member of the relevant set.
- **Rotation is two deploys, with no clock dependence:**
  1. Add the new credential to the set and deploy. Both old and new are now valid.
     Clients migrate to the new credential at their own pace.
  2. Once every client uses the new credential, remove the old one from the set and
     deploy. The old credential is now rejected.
- **Revocation of a leaked credential** is the second deploy run immediately: add the
  replacement (if the identity is still needed), then remove the leaked entry. The
  containment is purely set-membership; it does not wait for any timer to lapse, and
  it is deterministic (the credential is rejected the instant the deploy lands, not
  "eventually").

This is the deliberate v1 trade: no expiry timer means no surprise mass-expiry
outage on an edge fleet with skewed clocks, and no dependence on a correct wall
clock for a security property (in the same clock-seam spirit as invariant I6,
where ordering never consults the wall clock; see [INVARIANTS.md](INVARIANTS.md), I6).
Short-lived / auto-expiring credentials (and any nkey/JWT lifetime semantics) are
explicitly out of v1 scope and are the natural follow-up if a time-bounded
credential is later required.

---

## The uniform Authorization Violation

Every authentication and authorization failure produces **one** on-the-wire result:
the `Err` frame (tag 12) carrying a single fixed message, **"Authorization
Violation"**, followed by the broker closing the connection. The `Err` body is a
plain UTF-8 message with no numeric code (see [CONTRACTS.md](CONTRACTS.md), "Error"),
which fits this design exactly: there is no code field to leak a sub-reason.

The following all map to the identical response, with **no oracle** distinguishing
them:

- an unknown or unsupported authentication mechanism;
- a bad bearer token (no digest match);
- a bad username or password (no Argon2id match, including an unknown username);
- an mTLS cert that verifies but matches no configured identity;
- a successfully authenticated connection attempting a verb its pinned scope set
  does not grant.

The reasons this is uniform:

- **No bad-credential vs insufficient-scope oracle.** If "wrong password" and "valid
  password, wrong scope" returned different errors, an attacker could confirm a valid
  credential by probing a verb. The uniform error denies that signal.
- **No username-enumeration oracle.** "Unknown username" and "known username, wrong
  password" are the same response, so an attacker cannot enumerate valid usernames.
- **No timing oracle.** Combined with the constant-time token compare and the
  constant-time Argon2id verification, the failure path does not leak which check
  failed through its response content, its error code (there is none), or its timing.

The broker MAY record the distinct internal reason in its own audit log for the
operator (the audit-event surface is owned by #109); the distinction never crosses
the wire to the client.

---

## Failure considerations and the two sharp risks

This design is shaped around the two specific failures the auth contract must not
have, called out in #106:

1. **A timing oracle in bearer-token comparison.** Mitigated by the mandatory
   constant-time 32-byte digest compare and the uniform Authorization Violation, so
   neither the compare's timing nor the response content reveals the stored digest.
2. **An authz bypass where a verifying cert gets a default scope.** Mitigated by
   requiring an explicit SAN-to-identity match: chain verification grants no scope,
   only an exact match in the configured identity table does, and a verifying cert
   with no match is rejected outright.

A leaked credential is contained by the additive set with no clock dependence: the
operator adds the replacement, deploys, then removes the leaked entry and deploys,
and the leaked credential is rejected the instant the second deploy lands.

---

## Configuration surface (constrains #14)

The credential and scope configuration is owned by the #14 configuration system;
this spec states the keys it must provide and their semantics, not their final TOML
spelling (which #14 freezes). All of these are **specified, not implemented.**

- An **identity table**: a set of named identities, each with an explicit scope set
  drawn from `{publish, subscribe, admin}` and a credential binding for one of the
  three mechanisms.
- Per identity, an **additive credential list** for its mechanism: bearer-token
  SHA-256 hex digests (e.g. a `token_hashes = [...]` list), or Argon2id PHC strings
  for username/password, or accepted SAN identities for mTLS.
- A **trust anchor** (CA bundle path) for mTLS chain verification (shared with the
  #107 TLS configuration).
- The whole credential-bearing configuration is subject to the #109 fail-closed
  secret-file-permission rule: the broker refuses to start if a file carrying
  credential material is group- or world-readable.

No configuration key carries a credential expiry time, by design (see
[Additive credential-set rotation](#additive-credential-set-rotation)).

---

## Specified but not implemented (honest status)

None of the following exists in the binary today. Do not assume any of it.

| Item | Status | Owner |
| --- | --- | --- |
| Populated `Connect`/`Info` handshake bodies carrying the mechanism + credential | Specified here, frozen in #11 | #11, #106 |
| Bearer token (SHA-256 storage, constant-time compare) | Specified, not implemented | #106 |
| Username/password (Argon2id m=19 MiB, t=2, p=1) | Specified, not implemented | #106 |
| mTLS SAN identity (URI-then-DNS, CN excluded, no-match rejected) | Specified, not implemented | #106, #107 |
| The three scopes (publish/subscribe/admin, no implication) | Specified, not implemented | #106 |
| Admin scope on `/admin`, the #15/#136 diagnostics, and mutating admin (#299) | Specified, not implemented | #106, #15, #99, #299 |
| Additive credential-set rotation (no expiry timer) | Specified, not implemented | #106 |
| Uniform Authorization Violation `Err` (no oracle) | Specified, not implemented | #106 |
| TLS 1.3 transport that carries the credential on a non-loopback bind | Specified | #107 |
| Failed-auth backoff and per-source pre-auth DoS defenses | Specified | #107 |
| Secret-file fail-closed permissions; security audit events | Specified | #109 |

---

## Cross-references

- [THREAT_MODEL.md](THREAT_MODEL.md): the current no-auth posture (T4, T5, T6, T8)
  this spec closes, and the specified-controls table that points here.
- [CONTRACTS.md](CONTRACTS.md): the frozen `Connect`/`Info`/`Err` frames and the verb
  tag set this spec gates.
- [COMPATIBILITY.md](COMPATIBILITY.md): the empty-handshake / no-negotiation status
  the populated `Connect` body (#11) changes.
- [INVARIANTS.md](INVARIANTS.md): I6 (ordering never consults the wall clock),
  whose clock-seam discipline the no-expiry-timer rotation honors.
- [CLI.md](CLI.md): the `serve --enable-admin` flag and the `/admin`, `/healthz`,
  `/readyz`, `/metrics` endpoints this spec scope-gates.
- The README "Secure by default" section and the security epic #18.
