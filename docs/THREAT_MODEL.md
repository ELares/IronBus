# IronBus edge threat model and security posture

This document enumerates the edge threat model for IronBus and states the
**current** security posture honestly, derived from and cross-checked against the
actual source (`crates/ironbus-server`, `crates/ironbus-proto`,
`crates/ironbus-storage`) and the README. Both the code and the README are
canonical; where they disagree, this document follows the code and says so.

The single most important fact comes first, so no reader takes a false sense of
security away from the rest of the document:

> **IronBus today has no authentication, no TLS, and no at-rest encryption
> wired into the binary.** Any client that can open a TCP connection to the
> broker port can produce, consume, and acknowledge messages, and all wire
> traffic is plaintext. IronBus is a trusted-network / localhost broker today.
> Do not expose it to a hostile network until connection-scoped auth (#106) and
> TLS (#107) land.

The controls the README describes under "Secure by default" (TLS 1.3 mandatory
on a non-loopback bind, three authorization scopes, bearer-token / password /
mTLS auth, optional AEAD at-rest encryption, fail-closed secret-file
permissions) are the **specified** design of the security epic (#18). They are
not yet implemented. This document separates what is implemented and verified in
the code from what is specified-but-unimplemented, and never claims a control
exists if it does not.

For the vulnerability-disclosure process, see [SECURITY.md](../SECURITY.md);
this document does not duplicate it.

---

## Assets (what is protected)

These are the things an attacker would want to read, forge, destroy, or exhaust.

- **The durable log.** The append-only, log-is-WAL record store under the data
  directory: every acknowledged message. Loss or corruption of an acknowledged
  write is the worst outcome IronBus can produce, so durability defects are
  treated as security issues (see SECURITY.md, "What counts as a security
  issue").
- **Consumer cursors.** The per-group committed offset and in-flight lease
  state. Forging or rewinding a cursor causes redelivery or silent skipping of
  records.
- **The dead-letter queue (DLQ).** The durable `dlq/` sink holding poison
  messages (records past `MaxDeliver`), each preserving the original record
  verbatim plus its dead-letter metadata.
- **In-process and on-disk state generally.** Process memory and file
  descriptors on a small edge device are finite; exhausting them is a
  denial-of-service against every other tenant of the box.

---

## Trust boundaries

Each boundary is a place where data crosses from a less-trusted to a
more-trusted domain and must be validated.

- **The TCP wire (`--addr`, default `127.0.0.1:7777`).** Where a client's bytes
  enter the broker. The accept loop, the frame decoder, and the per-connection
  `Session` all sit on this boundary. There is no cryptographic boundary here
  today: the bytes are plaintext and the sender is unauthenticated.
- **The data directory on disk.** Where recovery reads bytes the broker itself
  may not have written in this run (a prior process, a power cut that left a torn
  tail, or an attacker with filesystem access). Recovery treats these bytes as
  untrusted: every record is CRC-validated before it is trusted.
- **The health / metrics endpoints (`--health-addr`).** A separate optional HTTP
  listener exposing `GET /healthz`, `GET /readyz`, and `GET /metrics`. The
  metrics surface broker gauges (offsets, lag, in-flight, fsync latency,
  recovery loss). It carries no message payloads, but it is an
  information-disclosure and DoS surface like any unauthenticated endpoint.

A note on the loopback assumption: the broker default address is
`127.0.0.1:7777` and the health module is documented as a "loopback HTTP port".
**The bind address is not constrained to loopback in code.** Both
`cmd_serve` and the health listener call `TcpListener::bind(addr)` directly on
whatever host:port the operator passes
(`crates/ironbus-cli/src/main.rs`, `cmd_serve`), so an operator can bind
`0.0.0.0` today and there is no TLS-or-auth gate that refuses it. The "localhost
default bind invariant" that the README implies is the *default*, not an
enforced invariant; enforcing it is specified in #107.

---

## Threat table (STRIDE-flavored)

One row per concrete edge threat, with the current detection and mitigation in
the code, and the accepted residual risk. A "not mitigated today" entry names
the tracking issue and is honest that the control is specified but absent.

| # | Threat | Current detection / mitigation (cited) | Residual risk today |
| --- | --- | --- | --- |
| T1 | **Physical device theft** (disk read offline) | None. The log and DLQ are plaintext on disk; there is no at-rest encryption. | Full data exposure on a stolen disk. At-rest AEAD is specified in #108 but unimplemented. Even once it lands, a key co-located with the stolen disk defeats it (accepted residual risk, see below). |
| T2 | **Untrusted-LAN passive eavesdrop** | None. The wire is plaintext; there is no TLS in the binary (no TLS crate in any `Cargo.toml`). | Full payload and metadata disclosure to anyone on-path. Not mitigated today; tracked in #107. |
| T3 | **Untrusted-LAN active MITM** (forge / tamper / replay) | None. No transport integrity, no peer authentication. Any in-path party can inject or rewrite frames. | Full message forgery and tampering. Not mitigated today; tracked in #107 (TLS 1.3) and #106 (auth). |
| T4 | **Unauthenticated client produces / consumes / forges** | **None for authorization.** The `Connect` handshake carries no credential: `dispatch` sets `connected = true` and replies with an empty `Info` body, with no negotiated state (`crates/ironbus-server/src/session.rs`). The `Connect`/`Info` bodies are empty; there is no auth or capability negotiation. The only same-connection guard implemented is *connection-scoped lease ownership* (#175): an ack/nack whose `(offset, generation)` was not delivered to this session is fenced without touching the engine (`handle_ack`), so one connection cannot ack another's in-flight message. That is a correctness fence, not authentication. | Any client that can reach the port has full produce/consume access. Not mitigated today; tracked in #106 (connection-scoped auth and the three-scope model). |
| T5 | **Stolen bearer token** | N/A. No auth exists, so there is no token to steal yet. | Once auth lands (#106), a leaked token grants its scope until revoked. Recorded here so the auth design (#106) accounts for revocation and short-lived credentials. |
| T6 | **Credential brute force by reconnect** | N/A today (no credential to guess). | A reconnect-and-retry guessing loop. Failed-auth backoff is specified in #107 but does not exist yet. |
| T7 | **Pre-authentication handshake / connection flood (DoS)** | **Partially mitigated.** A hard connection cap bounds concurrent connections: the accept loop refuses a new connection once `active >= max_connections` by dropping the stream, and the slot is released even on a panic unwind via a drop guard (`crates/ironbus-server/src/server.rs`, `serve` / `ConnectionSlot`); default 256 (`DEFAULT_MAX_CONNECTIONS`). A slowloris client is bounded by a 30-second read/write timeout (`CONNECTION_TIMEOUT`) that closes a connection making no progress. The frame decoder validates the length prefix against `MAX_FRAME_LEN` (16 MiB + 64 KiB) *before any allocation*, so a hostile length cannot force a large reservation (`decode_frame_with_cap` in `crates/ironbus-proto/src/frame.rs`). The health endpoint bounds its request line at 8 KiB and its per-connection time at a 5-second timeout (`crates/ironbus-server/src/health.rs`). | The connection cap and timeouts are *total*, not per-source: there is no per-IP connection rate limit or half-open cap, so a single source can still consume the global cap. Per-source rate limiting and failed-auth backoff are specified in #107. The cap bounds resource exhaustion but, with no auth, does not stop an authorized-by-reachability flood of valid produces. The per-source half-open cap, per-source connection rate limit, and failed-auth lockout that close this gap are specified in [TRANSPORT.md](TRANSPORT.md) (#107). |
| T8 | **Malicious admin-scope misuse** | N/A. There are no authorization scopes implemented; every reachable client has full access (see T4). | The blast radius of a single reachable client is "everything". Scope separation (publish / subscribe / admin) is specified in #106. |
| T9 | **Supply-chain crate compromise** | Release binaries carry a keyless Sigstore build-provenance attestation and a SHA256 checksum (see SECURITY.md); CI pins every GitHub Actions `uses:` to a full commit SHA; `cargo-deny` (`deny.toml`) gates licenses and advisories. The server crate has no third-party runtime dependencies beyond the workspace crates. | A compromised upstream crate or a malicious transitive dependency. Mitigated by a minimal dependency surface, license/advisory gating, and verifiable provenance, but not eliminated. Accepted residual risk. |

### Wire-level threats, enumerated per the task

The rows below restate the on-the-wire threats with the exact implemented
mitigation (or its honest absence), since these are the ones a reader most needs
when deciding where to deploy the broker.

- **An unauthenticated client on the network (produce / consume / forge).**
  *Not mitigated today.* See T4. The handshake authenticates nothing; reachability
  is access. Tracked in #106.
- **Resource exhaustion via unbounded group names.**
  *Mitigated.* A new named work-group is created only if its name validates and the
  per-engine group cap allows it: `validate_group_name` requires 1 to 128
  graphic-ASCII bytes (no spaces, control bytes, or non-ASCII), and `poll_in`
  rejects a new group past `max_groups` (default 1024, `0` = unlimited) with the
  typed `EngineError::TooManyGroups` *before allocating anything*
  (`crates/ironbus-server/src/engine.rs`). This bounds the per-name and total
  consumer-state memory an attacker can force by naming arbitrary groups over the
  wire (#240).
- **Resource exhaustion via unbounded connections.**
  *Mitigated.* The connection cap (`max_connections`, default 256) refuses
  connections past the cap (`serve` in `server.rs`). See T7.
- **Resource exhaustion via oversized frames.**
  *Mitigated.* `decode_frame_with_cap` rejects a frame whose length prefix exceeds
  the effective cap (`min(max_len, MAX_FRAME_LEN)`, absolute cap 16 MiB + 64 KiB)
  with `FrameError::FrameTooLarge` *before* allocating the body buffer
  (`crates/ironbus-proto/src/frame.rs`). A zero-length prefix is a malformed
  envelope that closes the connection (`EmptyFrame`).
- **Resource exhaustion via in-flight set (one consumer starving peers).**
  *Mitigated.* Per-consumer credit (#65): each connection holds at most
  `consumer_credit` un-acked messages (default 64), derived from the
  connection-scoped `leased` set, so a stuck consumer pins only its own slots and
  cannot consume a peer's budget in a competing group
  (`crates/ironbus-server/src/session.rs`, the `Session::credit_ceiling` /
  `leased` accounting).
- **Resource exhaustion via disk.**
  *Mitigated (bounded, not unlimited).* The durable-log byte cap
  (`LogConfig::max_total_bytes`, `0` = unlimited default) sheds an over-cap produce
  with the non-fatal `StorageError::AtCapacity` (drop-new), surfaced to the
  producer as a stable `at capacity` reply, the connection staying open
  (`handle_pub` in `session.rs`, #10). The consumer-safe retention reaper deletes
  whole old fully-consumed sealed segments under size / age / count bounds, never
  below the slowest consumer's committed offset and never the active segment
  (`crates/ironbus-server/src/engine.rs`, `Log::reap`, #13 / #80). The opt-in
  drop-oldest policy force-reaps the oldest segment to bound disk under sustained
  overload (#82). These bound disk growth; they do not authenticate the producer
  driving it.
- **A malicious or corrupt on-disk file.**
  *Mitigated for integrity (fail-closed), not for confidentiality or
  authenticity.* Every record's body is CRC32C-protected (plus an independent
  xxh3-64 over the same byte range for records at or above the 64 KiB threshold,
  #146), and the checkpoint file is CRC32C-protected with two alternating slots so
  a torn write reverts to the prior durable value rather than a torn one
  (`crates/ironbus-storage/src/checkpoint.rs`). Recovery scans the longest valid
  prefix and truncates a torn tail. Crucially, recovery is **bounded-loss
  fail-closed**: if recovery would drop more than the bounded-loss caps allow
  (per-event cap = one segment or 64 MiB, whichever is smaller; global cap = 1% of
  durable bytes, floored at the per-event cap), it returns
  `StorageError::ExcessiveRecoveryLoss` instead of silently accepting unbounded
  loss (`crates/ironbus-storage/src/log.rs`, the `check_caps` gate, I3 / #120).
  A CRC is *not* a cryptographic integrity check: an attacker with write access to
  the data directory can craft a record that passes CRC. The CRC defends against
  bit-rot and torn writes, not a malicious file author.
- **A slowloris client.**
  *Mitigated.* The 30-second `CONNECTION_TIMEOUT` read/write timeout closes a
  connection that makes no progress, bounding the slow-client hold on a
  connection-cap slot (`server.rs`); the health endpoint uses a 5-second timeout
  and an 8 KiB request-line bound (`health.rs`).
- **Eavesdropping / tampering on the wire.**
  *Not mitigated today.* Plaintext, no transport integrity. See T2 and T3.
  Tracked in #107.

---

## Secure-defaults catalog

Each default below is something IronBus does today, mapped to the threat row it
addresses. Defaults that the README lists but the code does not yet enforce are
shown in the *specified* table further down, not here, so this catalog only
contains controls that actually run.

| Default (implemented) | Where | Mitigates |
| --- | --- | --- |
| Bind defaults to `127.0.0.1:7777` (loopback) | `DEFAULT_ADDR`, `crates/ironbus-cli/src/main.rs` | T2, T3, T4 (default keeps the broker off the LAN; not enforced, see note) |
| Connection cap (default 256), slot released on panic | `serve` / `ConnectionSlot`, `server.rs` | T7 (connection flood) |
| 30s idle read/write timeout on every connection | `CONNECTION_TIMEOUT`, `server.rs` | T7 (slowloris) |
| Frame length validated before allocation, hard 16 MiB + 64 KiB cap | `decode_frame_with_cap`, `frame.rs` | T7 (oversized-frame DoS) |
| Named-group cap (default 1024) + name validation (1 to 128 graphic-ASCII) | `validate_group_name` / `poll_in`, `engine.rs` | T7 (group-name memory exhaustion, #240) |
| Per-consumer credit (default 64) bounds one connection's in-flight set | `Session` credit / `leased`, `session.rs` | T7 (one consumer starving peers, #65) |
| Durable-log byte cap + drop-new shed; consumer-safe retention reaper | `Log` byte cap / `Log::reap`, `engine.rs` | T7 (disk exhaustion, #10 / #13) |
| Record body CRC32C (+ xxh3-64 for large records); CRC'd dual-slot checkpoint | `codec` / `checkpoint.rs` | T-file (bit-rot / torn write integrity) |
| Bounded-loss fail-closed recovery (refuse to exceed the loss cap) | `check_caps`, `log.rs` | T-file (unbounded silent loss, I3 / #120) |
| Health request line bounded at 8 KiB, 5s per-connection timeout, one response then close | `health.rs` | T7 (health-endpoint slowloris) |
| Release provenance (Sigstore attestation + SHA256), SHA-pinned CI actions, `cargo-deny` gate | SECURITY.md / `deny.toml` / CI | T9 (supply chain) |

---

## Accepted residual risks (recorded explicitly, not buried)

- **At-rest encryption does not defend a co-located key (T1).** Even once at-rest
  AEAD lands (#108), if the encryption key is stored on or alongside the same disk
  that is physically stolen, the encryption is defeated. This is an accepted
  residual risk of any device-resident key, recorded here so #108 must address key
  custody explicitly (a co-located key is not a mitigation for device theft).
- **A CRC is not a cryptographic integrity check (T-file).** It detects accidental
  corruption and torn writes, not a malicious file author with write access to the
  data directory. Filesystem access to the data directory is, today, full access
  to the data.
- **The connection cap and timeouts are global, not per-source (T7).** A single
  source can still consume the whole connection budget; per-source rate limiting is
  specified in #107.
- **Supply-chain compromise is reduced, not eliminated (T9).** Provenance and a
  minimal dependency surface lower the probability and aid detection; they do not
  make a malicious upstream crate impossible.

---

## Current security posture

**IronBus is a trusted-network / localhost broker today.** It is safe to run
where every party that can reach the broker port is already trusted: a single
host (loopback), or a private, trusted network segment with no hostile clients.

It must **not** be exposed to a hostile or shared network. There is no
authentication, so reachability is full access (produce, consume, ack); there is
no TLS, so all traffic is plaintext and tamperable; and there is no at-rest
encryption, so the data directory is readable by anyone with filesystem access.

The DoS and resource-exhaustion bounds that *are* implemented (connection cap,
slowloris timeout, frame cap, group cap, per-consumer credit, disk cap and
retention, bounded-loss recovery) make the broker robust against accidental and
some adversarial overload, but they do not substitute for authentication or
transport security. Do not treat them as a reason to expose the port.

Operationally, until #106 and #107 land:

- Keep the broker on loopback (`127.0.0.1`, the default) or a trusted segment.
- Do not pass a non-loopback `--addr` or `--health-addr` on an untrusted network
  (nothing in the code stops you; the responsibility is the operator's).
- Treat the data directory as plaintext: protect it with filesystem permissions
  and disk-level encryption supplied by the host.

---

## Specified controls not yet implemented

Each specified control below maps to its tracking issue. None of these exist in
the binary today; do not assume any of them.

| Specified control | Status | Tracking issue |
| --- | --- | --- |
| Connection-scoped authentication; three authorization scopes (publish / subscribe / admin), specified in [AUTHENTICATION.md](AUTHENTICATION.md) | Specified, not implemented | #106 |
| TLS 1.3 transport; localhost-default bind enforced as an invariant; pre-auth DoS defenses (per-source rate limits, half-open caps, failed-auth backoff). Specified in [TRANSPORT.md](TRANSPORT.md). | Specified, not implemented | #107 |
| Optional at-rest AEAD encryption (AES-256-GCM / ChaCha20-Poly1305) and its interaction with checksums and recovery | Specified, not implemented | #108 |
| Secret handling and redaction, security audit events, crypto SBOM posture, fail-closed on unsafe secret-file permissions. Specified in [SECRETS.md](SECRETS.md). | Specified, not implemented | #109 |
| Security epic that ties the above together and the edge threat model this document realizes | Design parent | #18 |

The mapping is intentionally bidirectional: every "not mitigated today" row in
the threat table names the issue that will mitigate it, and every issue here
traces back to the threat rows it closes, so a later security PR can show its
mitigation lands against a specific threat and a reviewer can see at a glance
which threats are still open.
