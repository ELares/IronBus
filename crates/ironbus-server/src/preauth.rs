// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pre-auth DoS defenses (#633, V2-M7): the O(1)-bounded resource limits an UNAUTHENTICATED attacker
//! hits BEFORE the broker does any real work.
//!
//! The auth contract (`docs/AUTHENTICATION.md`) closes the *credential* side; this module closes the
//! *resource* side, so a flood of connections from an attacker that never authenticates cannot
//! exhaust the broker. Three independent defenses, each checked at accept time, BEFORE a handler
//! thread is spawned or a single handshake byte is read:
//!
//! 1. **Per-source-IP connect rate limit** — a token bucket per source IP. The per-IP state lives in
//!    a BOUNDED map with eviction (never an unbounded per-IP map: the very thing a spoofed-source
//!    flood would use to OOM the node), so the limiter's own memory is O(cap), not O(distinct IPs
//!    seen).
//! 2. **Half-open connection cap** — a single global counter of connections accepted-but-not-yet-
//!    authenticated. Over the cap, a new connection is refused. An RAII [`HalfOpenSlot`] decrements
//!    it when the handshake resolves (success, failure, or disconnect), so a stalled or slowloris
//!    half-open client can hold at most one slot and the count can never leak.
//! 3. **Failed-auth lockout** — after N failed auth attempts from an IP within a window, the IP is
//!    locked out for a cooldown. This blunts online credential-guessing and the per-connection cost
//!    of repeatedly running the (deliberately expensive) Argon2id verify.
//!
//! All three surface a rejection on the connz `ironbus_connections_rejected_total{reason}` family
//! ([`crate::connz::RejectReason`]), a bounded (four-value-enum `reason`) low-cardinality counter.
//!
//! # Determinism / clock seam
//!
//! Every time-dependent decision (token-bucket refill, lockout window/cooldown) reads the injected
//! [`Clock`]'s MONOTONIC nanos, never the wall clock — so a window is immune to an NTP step or a
//! backwards wall-clock jump (the I6 clock-seam discipline), and a test drives it with a
//! `ManualClock` for flake-free assertions.
//!
//! # Byte-identical when not configured
//!
//! A [`PreAuthGuard`] is built ONLY when at least one defense is configured. The accept loop holds an
//! `Option<PreAuthGuard>`; `None` is the historical path, byte-for-byte: no map, no atomic, no clock
//! read, zero added cost. Each individual defense is independently optional (a `0`/absent knob
//! disables just that one), so an operator can run, e.g., the half-open cap without the rate limit.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ironbus_core::clock::Clock;

use crate::connz::{ConnectionMetrics, RejectReason};

/// The hard ceiling on the number of distinct source IPs the per-IP limiter tracks at once (#633).
/// The per-IP state map is bounded to this many entries; when full, inserting a new IP first EVICTS
/// the least-recently-seen entry, so a flood of distinct (possibly spoofed) source IPs can never grow
/// the limiter's memory without bound — its footprint is O(this), not O(distinct IPs ever seen). The
/// trade is that a sufficiently wide source-IP flood can churn the table and let an evicted attacker's
/// bucket/lockout reset; that is acceptable because the GLOBAL half-open cap still bounds the total
/// concurrent unauthenticated work regardless of how many IPs are in flight.
pub const MAX_TRACKED_IPS: usize = 4096;

/// The configuration for the pre-auth DoS defenses (#633). Built from the operator's serve flags. A
/// field left at its disabling value (`per_ip_rate_per_sec == 0`, `half_open_cap == 0`,
/// `lockout_threshold == 0`) turns OFF just that one defense; if ALL are disabled the broker builds
/// NO [`PreAuthGuard`] (the byte-identical historical accept path).
#[derive(Clone, Copy, Debug)]
pub struct PreAuthConfig {
    /// The sustained per-source-IP new-connection rate, in connections per second (the token-bucket
    /// refill rate). `0` disables the per-IP rate limit.
    pub per_ip_rate_per_sec: u32,
    /// The per-source-IP burst capacity (the token-bucket size): how many connections one IP may make
    /// instantaneously before it is throttled to the sustained rate. Clamped to at least 1 when the
    /// rate limit is on, so a legitimate client's first connection is never rejected.
    pub per_ip_burst: u32,
    /// The global cap on connections accepted-but-not-yet-authenticated (half-open). `0` disables the
    /// half-open cap.
    pub half_open_cap: u32,
    /// The number of failed auth attempts from one IP within [`lockout_window_ms`] that triggers a
    /// lockout. `0` disables the failed-auth lockout.
    pub lockout_threshold: u32,
    /// The sliding window, in milliseconds, over which failed auth attempts are counted toward the
    /// [`lockout_threshold`].
    pub lockout_window_ms: u64,
    /// The lockout cooldown, in milliseconds: once locked out, an IP's new connections are refused
    /// for this long before it may try again.
    pub lockout_cooldown_ms: u64,
}

impl PreAuthConfig {
    /// Whether ANY defense is enabled. The broker builds a [`PreAuthGuard`] only when this is `true`;
    /// otherwise the accept loop runs the byte-identical historical path with `None`.
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.per_ip_rate_per_sec > 0 || self.half_open_cap > 0 || self.lockout_threshold > 0
    }
}

/// The per-source-IP limiter state (#633): the token bucket plus the failed-auth lockout bookkeeping.
/// Held in the bounded map keyed by `IpAddr`. All times are MONOTONIC nanos from the injected clock.
#[derive(Clone, Copy, Debug)]
struct IpState {
    /// The token-bucket level, in MILLI-tokens (1000 = one whole connection token), so the refill is
    /// integer-exact without floating point: refill adds `rate_per_sec * elapsed_ns / 1_000_000`
    /// milli-tokens. A whole connection costs 1000 milli-tokens.
    tokens_milli: u64,
    /// The monotonic-nanos timestamp the bucket was last refilled (so the next refill adds exactly the
    /// tokens that accrued since).
    last_refill_ns: u64,
    /// The count of failed auth attempts in the current window.
    failed_count: u32,
    /// The monotonic-nanos timestamp the current failed-auth window started; the window resets (and
    /// `failed_count` restarts at 1) once `lockout_window_ms` has elapsed since it.
    window_start_ns: u64,
    /// `Some(until_ns)` while this IP is locked out: new connections are refused until the monotonic
    /// clock passes `until_ns`. `None` when not locked out.
    locked_until_ns: Option<u64>,
    /// The last monotonic-nanos timestamp this IP was touched, used to pick the eviction victim (the
    /// least-recently-seen entry) when the bounded map is full.
    last_seen_ns: u64,
}

impl IpState {
    /// A fresh entry with a FULL bucket (so a new IP's first connection is always allowed) seen at
    /// `now_ns`.
    fn new(burst_milli: u64, now_ns: u64) -> IpState {
        IpState {
            tokens_milli: burst_milli,
            last_refill_ns: now_ns,
            failed_count: 0,
            window_start_ns: now_ns,
            locked_until_ns: None,
            last_seen_ns: now_ns,
        }
    }

    /// Refills the bucket for the time elapsed since the last refill, capped at the burst size. Pure
    /// integer math (milli-tokens), so there is no float and no drift.
    fn refill(&mut self, rate_per_sec: u64, burst_milli: u64, now_ns: u64) {
        let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);
        // milli-tokens accrued = rate_per_sec (tokens/s) * 1000 (milli/token) * elapsed_s
        //                      = rate_per_sec * 1000 * elapsed_ns / 1e9
        //                      = rate_per_sec * elapsed_ns / 1_000_000
        let accrued = rate_per_sec
            .saturating_mul(elapsed_ns)
            .saturating_div(1_000_000);
        if accrued > 0 {
            self.tokens_milli = self.tokens_milli.saturating_add(accrued).min(burst_milli);
            self.last_refill_ns = now_ns;
        }
        // If no whole milli-token accrued yet, DO NOT advance last_refill_ns: that would discard the
        // sub-granularity fraction and starve a low rate. The next call sees the full elapsed window.
    }
}

/// One whole connection token, in milli-tokens.
const ONE_TOKEN_MILLI: u64 = 1000;

/// The pre-auth DoS guard (#633): the per-IP rate limiter (bounded map), the global half-open cap, and
/// the failed-auth lockout, all clock-injected. Shared by the accept loop (`Arc`); cheap to clone.
///
/// The per-IP map is behind a `Mutex` — taken ONLY at accept time and at an auth outcome, never on the
/// record hot path — so it is off the engine's single-writer lock entirely. The half-open count is a
/// lock-free `AtomicUsize`. The guard records every rejection on the shared connz metric.
pub struct PreAuthGuard {
    cfg: PreAuthConfig,
    /// The bounded per-IP limiter state. Capped at [`MAX_TRACKED_IPS`] with least-recently-seen
    /// eviction, so its memory is O(cap), never O(distinct IPs).
    ips: Mutex<BTreeMap<IpAddr, IpState>>,
    /// The live count of half-open (accepted-but-not-yet-authed) connections. Lock-free.
    half_open: AtomicUsize,
    /// The injected clock (monotonic nanos drive every window); never the wall clock.
    clock: Arc<dyn Clock>,
    /// The shared connz metric a rejection is recorded on (`rejected_total{reason}`).
    connz: Arc<ConnectionMetrics>,
}

impl std::fmt::Debug for PreAuthGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn Clock` is not `Debug`; render the config + live counts, never the clock or any secret
        // (there is none here — only counts and a bounded config).
        f.debug_struct("PreAuthGuard")
            .field("cfg", &self.cfg)
            .field(
                "tracked_ips",
                &self.ips.lock().map(|m| m.len()).unwrap_or(0),
            )
            .field("half_open", &self.half_open.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl PreAuthGuard {
    /// Builds a guard for the configured defenses. The caller builds one ONLY when
    /// [`PreAuthConfig::any_enabled`] is `true`; a fully-disabled config would build a guard that
    /// admits everything, which is pointless (the accept loop uses `None` instead for the byte-
    /// identical path).
    #[must_use]
    pub fn new(
        cfg: PreAuthConfig,
        clock: Arc<dyn Clock>,
        connz: Arc<ConnectionMetrics>,
    ) -> PreAuthGuard {
        PreAuthGuard {
            cfg,
            ips: Mutex::new(BTreeMap::new()),
            half_open: AtomicUsize::new(0),
            clock,
            connz,
        }
    }

    /// The per-IP burst capacity in milli-tokens (at least one whole token when the rate limit is on,
    /// so a legitimate first connection is never rejected).
    fn burst_milli(&self) -> u64 {
        u64::from(self.cfg.per_ip_burst.max(1)).saturating_mul(ONE_TOKEN_MILLI)
    }

    /// Decides whether to ACCEPT a new connection from `ip`, applying every enabled defense in order:
    /// lockout first (a locked-out IP is refused before any other work), then the per-IP rate limit,
    /// then the global half-open cap. On accept, the half-open count is incremented and an RAII
    /// [`HalfOpenSlot`] is returned that decrements it on drop (handshake done, failed, or
    /// disconnected). On refuse, the bounded [`RejectReason`] is recorded on connz and returned.
    ///
    /// This is the SINGLE choke point the accept loop calls BEFORE spawning a handler or reading a
    /// byte, so an unauthenticated attacker hits an O(1)-bounded limit before any broker work. The map
    /// lock is held only for this short decision, off the engine lock.
    ///
    /// # Errors
    /// The [`RejectReason`] the connection was refused for (`locked_out` / `rate_limited` /
    /// `half_open_cap`). The corresponding `rejected_total{reason}` counter is bumped before return.
    pub fn on_accept(&self, ip: IpAddr) -> Result<HalfOpenSlot<'_>, RejectReason> {
        let now_ns = self.clock.now_monotonic_nanos();

        // Defenses 1 & 2 (lockout, rate limit) consult the per-IP map. Take the lock once.
        if self.cfg.lockout_threshold > 0 || self.cfg.per_ip_rate_per_sec > 0 {
            let mut ips = self.ips.lock().expect("preauth ip map poisoned");
            let burst_milli = self.burst_milli();
            let entry = Self::entry_mut(&mut ips, ip, burst_milli, now_ns);
            entry.last_seen_ns = now_ns;

            // 1. LOCKOUT: a locked-out IP is refused outright until its cooldown lapses (monotonic).
            if self.cfg.lockout_threshold > 0 {
                if let Some(until) = entry.locked_until_ns {
                    if now_ns < until {
                        drop(ips);
                        self.connz.record_rejected(RejectReason::LockedOut);
                        return Err(RejectReason::LockedOut);
                    }
                    // Cooldown lapsed: clear the lockout and reset the window so the IP starts fresh.
                    entry.locked_until_ns = None;
                    entry.failed_count = 0;
                    entry.window_start_ns = now_ns;
                }
            }

            // 2. PER-IP RATE LIMIT: refill, then spend one token. An empty bucket is a refuse.
            if self.cfg.per_ip_rate_per_sec > 0 {
                entry.refill(u64::from(self.cfg.per_ip_rate_per_sec), burst_milli, now_ns);
                if entry.tokens_milli < ONE_TOKEN_MILLI {
                    drop(ips);
                    self.connz.record_rejected(RejectReason::RateLimited);
                    return Err(RejectReason::RateLimited);
                }
                entry.tokens_milli -= ONE_TOKEN_MILLI;
            }
            // Lock dropped here.
        }

        // 3. HALF-OPEN CAP: a lock-free CAS that admits only if the live half-open count is under the
        // cap, so the increment and the check are one atomic step (no accept can slip past the cap
        // under a concurrent flood).
        if self.cfg.half_open_cap > 0 {
            let cap = self.cfg.half_open_cap as usize;
            let mut cur = self.half_open.load(Ordering::Acquire);
            loop {
                if cur >= cap {
                    self.connz.record_rejected(RejectReason::HalfOpenCap);
                    return Err(RejectReason::HalfOpenCap);
                }
                match self.half_open.compare_exchange_weak(
                    cur,
                    cur + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => cur = observed,
                }
            }
            return Ok(HalfOpenSlot {
                half_open: Some(&self.half_open),
            });
        }

        // The half-open cap is disabled: nothing to decrement, so the slot is inert.
        Ok(HalfOpenSlot { half_open: None })
    }

    /// Records one FAILED authentication attempt from `ip` (#633): increments the windowed failed
    /// count and, if it reaches the threshold within the window, locks the IP out for the cooldown.
    /// Also bumps `rejected_total{reason="auth_failed"}`. Called by the handler when the `Connect`
    /// handshake fails to resolve a credential. No-op map touch when the lockout defense is disabled
    /// (the counter is still bumped, so the operator sees auth failures regardless).
    pub fn on_auth_failure(&self, ip: IpAddr) {
        self.connz.record_rejected(RejectReason::AuthFailed);
        if self.cfg.lockout_threshold == 0 {
            return;
        }
        let now_ns = self.clock.now_monotonic_nanos();
        let window_ns = self.cfg.lockout_window_ms.saturating_mul(1_000_000);
        let cooldown_ns = self.cfg.lockout_cooldown_ms.saturating_mul(1_000_000);
        let burst_milli = self.burst_milli();
        let mut ips = self.ips.lock().expect("preauth ip map poisoned");
        let entry = Self::entry_mut(&mut ips, ip, burst_milli, now_ns);
        entry.last_seen_ns = now_ns;
        // Slide the window: if the current window has elapsed, restart it at this failure.
        if now_ns.saturating_sub(entry.window_start_ns) > window_ns {
            entry.window_start_ns = now_ns;
            entry.failed_count = 0;
        }
        entry.failed_count = entry.failed_count.saturating_add(1);
        if entry.failed_count >= self.cfg.lockout_threshold {
            entry.locked_until_ns = Some(now_ns.saturating_add(cooldown_ns));
        }
    }

    /// Records a SUCCESSFUL authentication from `ip` (#633): clears its failed-auth window so an
    /// occasional fat-fingered password before a correct one never accumulates toward a lockout.
    /// No-op when the lockout defense is disabled.
    pub fn on_auth_success(&self, ip: IpAddr) {
        if self.cfg.lockout_threshold == 0 {
            return;
        }
        let now_ns = self.clock.now_monotonic_nanos();
        let mut ips = self.ips.lock().expect("preauth ip map poisoned");
        if let Some(entry) = ips.get_mut(&ip) {
            entry.failed_count = 0;
            entry.window_start_ns = now_ns;
            entry.locked_until_ns = None;
            entry.last_seen_ns = now_ns;
        }
    }

    /// Looks up (or inserts, with eviction) the per-IP entry. When the map is at [`MAX_TRACKED_IPS`]
    /// and `ip` is NOT already present, the least-recently-seen entry is evicted first, so the map's
    /// memory is bounded O(cap) regardless of how many distinct IPs are ever seen. Returns a mutable
    /// reference to the (existing or freshly inserted) entry.
    fn entry_mut<'a>(
        ips: &'a mut BTreeMap<IpAddr, IpState>,
        ip: IpAddr,
        burst_milli: u64,
        now_ns: u64,
    ) -> &'a mut IpState {
        if !ips.contains_key(&ip) && ips.len() >= MAX_TRACKED_IPS {
            // Evict the least-recently-seen entry (O(n) scan over a BOUNDED n = cap, so still O(1) in
            // the size of the input — the table can never grow past the cap). A bounded linear scan on
            // the (rare) full-table insert is the cost of keeping the map allocation-bounded without a
            // second index; it is off the engine lock and gated behind the cap.
            if let Some((&victim, _)) = ips.iter().min_by_key(|(_, s)| s.last_seen_ns) {
                ips.remove(&victim);
            }
        }
        ips.entry(ip)
            .or_insert_with(|| IpState::new(burst_milli, now_ns))
    }

    /// The current count of tracked source IPs (for the bounded-map test). Always `<= MAX_TRACKED_IPS`.
    #[cfg(test)]
    fn tracked_ip_count(&self) -> usize {
        self.ips.lock().expect("preauth ip map poisoned").len()
    }

    /// The current half-open count (for tests).
    #[cfg(test)]
    fn half_open_count(&self) -> usize {
        self.half_open.load(Ordering::Acquire)
    }
}

/// An RAII slot for one half-open (accepted-but-not-yet-authed) connection (#633). Held by the
/// connection handler for the whole handshake window; on drop (handshake resolved — success, failure,
/// or disconnect) it decrements the global half-open count, so a stalled/slowloris half-open client
/// holds at most one slot and the count can never leak. When the half-open cap is disabled the slot is
/// inert (`half_open: None`), so a no-cap broker pays nothing.
#[derive(Debug)]
pub struct HalfOpenSlot<'a> {
    half_open: Option<&'a AtomicUsize>,
}

impl Drop for HalfOpenSlot<'_> {
    fn drop(&mut self) {
        if let Some(counter) = self.half_open {
            // Saturating decrement: a slot is created exactly once per admitted accept and dropped
            // exactly once, so this never underflows in practice; saturate defensively.
            let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn guard(cfg: PreAuthConfig) -> (PreAuthGuard, Arc<ManualClock>, Arc<ConnectionMetrics>) {
        let clock = Arc::new(ManualClock::new());
        let connz = Arc::new(ConnectionMetrics::new());
        let g = PreAuthGuard::new(cfg, clock.clone() as Arc<dyn Clock>, connz.clone());
        (g, clock, connz)
    }

    fn rate_only(rate: u32, burst: u32) -> PreAuthConfig {
        PreAuthConfig {
            per_ip_rate_per_sec: rate,
            per_ip_burst: burst,
            half_open_cap: 0,
            lockout_threshold: 0,
            lockout_window_ms: 0,
            lockout_cooldown_ms: 0,
        }
    }

    #[test]
    fn any_enabled_is_false_only_when_every_knob_is_off() {
        let off = PreAuthConfig {
            per_ip_rate_per_sec: 0,
            per_ip_burst: 0,
            half_open_cap: 0,
            lockout_threshold: 0,
            lockout_window_ms: 0,
            lockout_cooldown_ms: 0,
        };
        assert!(!off.any_enabled());
        assert!(rate_only(1, 1).any_enabled());
        assert!(PreAuthConfig {
            half_open_cap: 1,
            ..off
        }
        .any_enabled());
        assert!(PreAuthConfig {
            lockout_threshold: 1,
            ..off
        }
        .any_enabled());
    }

    #[test]
    fn per_ip_rate_limit_triggers_and_emits_rate_limited_and_refills_over_time() {
        // burst 2, 1/s: two instant connections allowed, the third refused; after 1s one refills.
        let (g, clock, connz) = guard(rate_only(1, 2));
        assert!(g.on_accept(ip(1)).is_ok(), "first within burst");
        assert!(g.on_accept(ip(1)).is_ok(), "second within burst");
        // Third with an empty bucket is refused with the bounded reason.
        assert_eq!(g.on_accept(ip(1)).unwrap_err(), RejectReason::RateLimited);
        assert_eq!(connz.snapshot().rejected_rate_limited, 1);
        // Determinism: advance the INJECTED clock by 1s -> exactly one token refills.
        clock.advance_monotonic_nanos(1_000_000_000);
        assert!(g.on_accept(ip(1)).is_ok(), "one token refilled after 1s");
        // Now empty again.
        assert_eq!(g.on_accept(ip(1)).unwrap_err(), RejectReason::RateLimited);
        assert_eq!(connz.snapshot().rejected_rate_limited, 2);
    }

    #[test]
    fn rate_limit_is_per_ip_a_flood_from_one_ip_does_not_throttle_another() {
        let (g, _clock, _connz) = guard(rate_only(1, 1));
        assert!(g.on_accept(ip(1)).is_ok());
        // ip(1) is now empty, but a DIFFERENT IP has its own full bucket.
        assert_eq!(g.on_accept(ip(1)).unwrap_err(), RejectReason::RateLimited);
        assert!(
            g.on_accept(ip(2)).is_ok(),
            "a legit second client must not be throttled by the first's flood"
        );
    }

    #[test]
    fn half_open_cap_triggers_and_a_dropped_slot_frees_capacity() {
        let cfg = PreAuthConfig {
            half_open_cap: 2,
            ..rate_only(0, 0)
        };
        let (g, _clock, connz) = guard(cfg);
        let s1 = g.on_accept(ip(1)).unwrap();
        let s2 = g.on_accept(ip(2)).unwrap();
        assert_eq!(g.half_open_count(), 2);
        // Over the cap: refused with the bounded reason.
        assert_eq!(g.on_accept(ip(3)).unwrap_err(), RejectReason::HalfOpenCap);
        assert_eq!(connz.snapshot().rejected_half_open_cap, 1);
        // Dropping a slot (handshake resolved/disconnected) frees one.
        drop(s1);
        assert_eq!(g.half_open_count(), 1);
        let s3 = g.on_accept(ip(3)).unwrap();
        assert_eq!(g.half_open_count(), 2);
        drop(s2);
        drop(s3);
        assert_eq!(g.half_open_count(), 0, "every slot drop decremented");
    }

    #[test]
    fn lockout_after_n_failures_within_the_window_and_cooldown_lapses_deterministically() {
        let cfg = PreAuthConfig {
            lockout_threshold: 3,
            lockout_window_ms: 10_000,
            lockout_cooldown_ms: 30_000,
            ..rate_only(0, 0)
        };
        let (g, clock, connz) = guard(cfg);
        // Three failures within the window -> locked out.
        g.on_auth_failure(ip(1));
        g.on_auth_failure(ip(1));
        g.on_auth_failure(ip(1));
        assert_eq!(connz.snapshot().rejected_auth_failed, 3);
        // A new connection from the locked IP is now refused.
        assert_eq!(g.on_accept(ip(1)).unwrap_err(), RejectReason::LockedOut);
        assert_eq!(connz.snapshot().rejected_locked_out, 1);
        // Still locked just before the cooldown lapses.
        clock.advance_monotonic_nanos(29_000_000_000);
        assert_eq!(g.on_accept(ip(1)).unwrap_err(), RejectReason::LockedOut);
        // After the cooldown, the IP may connect again (deterministic, clock-driven).
        clock.advance_monotonic_nanos(2_000_000_000);
        assert!(g.on_accept(ip(1)).is_ok(), "cooldown lapsed -> admitted");
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate_to_a_lockout() {
        let cfg = PreAuthConfig {
            lockout_threshold: 3,
            lockout_window_ms: 1_000,
            lockout_cooldown_ms: 30_000,
            ..rate_only(0, 0)
        };
        let (g, clock, _connz) = guard(cfg);
        g.on_auth_failure(ip(1));
        // Two seconds later (past the 1s window) the count restarts; two failures never reach 3.
        clock.advance_monotonic_nanos(2_000_000_000);
        g.on_auth_failure(ip(1));
        g.on_auth_failure(ip(1));
        assert!(
            g.on_accept(ip(1)).is_ok(),
            "spread-out failures must not lock out"
        );
    }

    #[test]
    fn a_successful_auth_clears_the_failed_window() {
        let cfg = PreAuthConfig {
            lockout_threshold: 3,
            lockout_window_ms: 10_000,
            lockout_cooldown_ms: 30_000,
            ..rate_only(0, 0)
        };
        let (g, _clock, _connz) = guard(cfg);
        g.on_auth_failure(ip(1));
        g.on_auth_failure(ip(1));
        g.on_auth_success(ip(1)); // clears the two prior failures
        g.on_auth_failure(ip(1));
        g.on_auth_failure(ip(1));
        assert!(
            g.on_accept(ip(1)).is_ok(),
            "a success between failures must reset the count, so 2+2 never locks"
        );
    }

    #[test]
    fn the_per_ip_map_is_bounded_and_evicts_under_a_distinct_ip_flood() {
        // A flood of MANY distinct source IPs must NOT grow the map without bound — it is capped at
        // MAX_TRACKED_IPS with least-recently-seen eviction. (Uses a small synthetic flood; the cap
        // itself is asserted to hold.)
        let (g, clock, _connz) = guard(rate_only(1, 1));
        // Touch far more distinct IPs than the cap would be if it were tiny; assert the map never
        // exceeds the cap. We advance the clock per IP so last_seen ordering is well-defined.
        for i in 0..(MAX_TRACKED_IPS as u64 + 50) {
            let addr = IpAddr::V4(Ipv4Addr::new(
                (i >> 24) as u8,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
            ));
            clock.advance_monotonic_nanos(1);
            let _ = g.on_accept(addr);
            assert!(
                g.tracked_ip_count() <= MAX_TRACKED_IPS,
                "the per-IP map must never exceed MAX_TRACKED_IPS (bounded, with eviction)"
            );
        }
        assert_eq!(
            g.tracked_ip_count(),
            MAX_TRACKED_IPS,
            "the map fills to exactly the cap and then only evicts"
        );
    }

    #[test]
    fn a_legit_authed_client_under_normal_load_is_never_rejected() {
        // A generous burst + sane rate: a normal client making a handful of connections, well under
        // any limit, is always admitted (no false positive on the legitimate path).
        let cfg = PreAuthConfig {
            per_ip_rate_per_sec: 10,
            per_ip_burst: 20,
            half_open_cap: 100,
            lockout_threshold: 5,
            lockout_window_ms: 10_000,
            lockout_cooldown_ms: 30_000,
        };
        let (g, clock, connz) = guard(cfg);
        for _ in 0..5 {
            let slot = g.on_accept(ip(7)).expect("a legit client is admitted");
            g.on_auth_success(ip(7)); // it authenticates fine
            drop(slot); // handshake done, half-open slot freed
            clock.advance_monotonic_nanos(200_000_000); // 5/s, well under the 10/s rate
        }
        let s = connz.snapshot();
        assert_eq!(s.rejected_rate_limited, 0);
        assert_eq!(s.rejected_half_open_cap, 0);
        assert_eq!(s.rejected_locked_out, 0);
        assert_eq!(s.rejected_auth_failed, 0);
    }
}
