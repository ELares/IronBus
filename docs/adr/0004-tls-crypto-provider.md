# 0004. The TLS 1.3 crypto provider — a scoped, feature-gated aws-lc-rs allowance

- **Status**: Proposed (owner decision required — this ADR exists to make that decision, not to pre-empt it)
- **Owning issue**: [#766](https://github.com/ELares/IronBus/issues/766) (crypto-provider decision + TLS 1.3/mTLS), [#957](https://github.com/ELares/IronBus/issues/957) (client TLS), [#107](https://github.com/ELares/IronBus/issues/107) (transport spec)

## Context

The wire is **plaintext today**. `docs/TRANSPORT.md` specifies TLS 1.3-only + optional mTLS, `--tls-*`
material is parsed but **refused at startup** (fail-closed), and mTLS identity-mapping is wired but
inert until the handshake lands. The 2026-07-06 production-readiness audit graded this the single
disqualifying gap for public trust: no deployment across a trust boundary is possible, and bearer
tokens / passwords transit cleartext on any non-loopback bind. NATS, Kafka, and Redpanda all ship
TLS; a durable broker without it cannot be marketed as trustworthy on an untrusted network.

The implementation is **blocked on one supply-chain decision**, not on TLS code. `rustls` (the
chosen pure-Rust TLS stack, `docs/TRANSPORT.md`) needs a *crypto provider* for the AEAD, key
exchange, and signature primitives. The three real options each conflict with a project value:

1. **`ring`** — vendored C/assembly. On the `deny.toml` bans list (#102 C-FFI ban). Unmaintained-ish.
2. **`aws-lc-rs`** (rustls's current default provider, `aws-lc-sys` underneath) — vendored AWS-LC C,
   FIPS-capable, the best-audited option, fast (AES-NI / ARMv8 crypto). `aws-lc-sys` is on the
   `deny.toml` bans list.
3. **A pure-Rust RustCrypto provider** (`rustls-rustcrypto` or a hand-wired `CryptoProvider` over the
   RustCrypto AEAD/`x25519-dalek`/`*-rs` primitives) — no C. But `rustls-rustcrypto` is **pre-1.0 /
   alpha**, its constant-time and side-channel properties are less scrutinized than aws-lc/ring, and
   staking a durability broker's *security* claim on an immature provider is its own trust risk.

The relevant tenets pull in opposite directions: **Resilient / trustworthy** (the top tenet) wants
audited, production-grade crypto for the security boundary; **Cross Platform / single-static-binary /
pure-Rust supply chain** (#102, #139) wants no vendored C. There is no option that satisfies both.

**Precedent that resolves the tension.** The project has already made this exact trade once, and the
maintainer approved it: **zstd** (`zstd-sys`, vendored C) is allowed **behind the non-default `zstd`
Cargo feature** (ADR-0003, #357). `deny.toml` carries the documented, scoped exception; the default
and `edge-min` builds stay byte-for-byte pure-Rust; `cffi-ban.sh` structurally guards that the
default graph can never acquire the C-FFI silently. That is the template: an optional, non-default,
loudly-documented C dependency is acceptable when (a) the default build stays pure-Rust and (b) the
value is worth more than purity *for that feature*.

## Decision

**Ship TLS behind a non-default `tls` Cargo feature whose crypto provider is `aws-lc-rs`, added to
`deny.toml` as a documented, feature-scoped C-FFI exception exactly like `zstd-sys`.** The default
and `edge-min` builds link no TLS stack and no new C (unchanged, pure-Rust, byte-for-byte); a
`--features tls` build carries `rustls` + `aws-lc-rs` and enables the TLS 1.3 / mTLS transport; the
fail-closed bind invariant and `--insecure-plaintext-wire` opt-in are unchanged for the default
build.

Rationale for preferring aws-lc-rs over the pure-Rust provider: TLS is a **security** boundary where
"audited, constant-time, FIPS-capable" outranks "pure Rust", the RustCrypto rustls provider is not
yet mature enough to stake production trust on, and aws-lc-rs is rustls's own default — the
best-supported, least-surprising path. The zstd precedent already establishes that a feature-scoped C
dependency is compatible with the project's supply-chain posture, so this is an *application* of an
approved policy, not a new one.

> **This ADR is Proposed, not Accepted.** Adding `aws-lc-sys` reverses a `deny.toml` ban and softens
> the "pure Rust in every build" reading of the static-binary posture for the TLS-enabled build. That
> is a values decision reserved to the owner. The three options and their consequences are laid out
> so the decision can be made deliberately; the recommendation is aws-lc-rs.

## Consequences

**If accepted (aws-lc-rs, feature-scoped):**
- The default / `edge-min` builds are unchanged and pure-Rust; only `--features tls` pulls `rustls` +
  `aws-lc-rs`. `deny.toml` gets a `zstd-sys`-style documented allowance for `aws-lc-sys`; `cffi-ban.sh`
  is extended to prove the default graph still carries no TLS C-FFI.
- musl static builds: `aws-lc-sys` compiles its bundled C with `cc` (like `zstd-sys`), so the `tls`
  feature needs a C toolchain in that CI lane (the zstd lane already proves this works); the DEFAULT
  musl static binary is untouched.
- Implementation unblocks: the `--tls-*` flags stop refusing, the mTLS identity mapping activates, the
  client crates gain a `ClientConfig` TLS field (#957), and `docs/TRANSPORT.md` / MISSION.md move TLS
  from TARGET to shipped-behind-a-feature. THREAT_MODEL T3 (cleartext wire) is mitigated for `tls`
  builds; the default build's honest posture (loopback or `--insecure-plaintext-wire` + auth on a
  trusted network) is documented, not silently implied safe.
- Obligation: the peer/cluster wire (#1067) must also gain TLS/auth — this ADR covers the client wire;
  the peer wire is tracked separately.

**If rejected in favor of the pure-Rust RustCrypto provider:**
- No `deny.toml` change; every build stays pure-Rust. But the project ships production TLS on an
  alpha-grade provider, which must be disclosed honestly (a weaker security claim than "audited
  crypto"), and the provider's maturity becomes a maintenance risk. Revisit when a pure-Rust rustls
  provider reaches a production-audited 1.0.

**If deferred (status quo):**
- The wire stays plaintext; the documented posture remains loopback / upstream-TLS-termination
  (sidecar or load balancer terminates TLS, IronBus runs `--insecure-plaintext-wire` + auth on a
  trusted network). This is a legitimate v1 stance for meshed/internal deployments but leaves the
  public-trust gap open and the "beats NATS on every front" claim false on transport security.

Whichever is chosen, the outcome is recorded on #766, this ADR flips to Accepted (or Superseded), and
the `deny.toml` / `docs/TRANSPORT.md` / MISSION.md text is reconciled to it in the same change.
