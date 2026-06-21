// SPDX-License-Identifier: MIT OR Apache-2.0
//! Re-replication rate-limit under CoDel-style backpressure (#619, C5-I4).
//!
//! When a replica must re-replicate a LARGE BACKLOG — a freshly-joined learner back-filling (#724),
//! a recovered / repaired / divergent replica catching up (#697), or a failover successor — the
//! catch-up FETCH must be RATE-LIMITED under controlled-delay backpressure so it does NOT saturate
//! the network link or starve live produce / consume / replication traffic. Kafka replication can
//! saturate a broker on a big catch-up; this is the principled, controlled-delay alternative:
//! graceful re-replication that PROTECTS live traffic and still converges.
//!
//! This module owns ONLY the math and the state machine for that decision. It performs no IO, spawns
//! no thread, and reads no clock: every time-based method takes the current MONOTONIC time in
//! nanoseconds, which the serve loop reads from its monotonic source (a `std::time::Instant` delta in
//! production, an injected nanosecond stream in tests). That keeps the controller deterministic and
//! unit-testable without the wall clock, exactly the discipline
//! [`ironbus_core::backpressure::Codel`] already follows — which this REUSES rather than reinventing.
//!
//! ## The algorithm
//!
//! The follower fetch loop ([`crate::cluster::serve`]) drives this per partition:
//!
//! 1. **Catch-up detection.** A fetch is "re-replicating" iff the follower is FAR behind — its
//!    `backlog = leader_high_watermark - follower_next_offset` exceeds
//!    [`CATCHUP_BACKLOG_THRESHOLD`]. At or below the threshold the follower is steady-state TAILING
//!    near the high-watermark, and [`Decision`] is always [`Decision::full_rate`] (no throttle at
//!    all), so ordinary live replication is byte-for-byte unaffected.
//!
//! 2. **Controlled-delay signal.** While re-replicating, the loop measures each catch-up fetch's
//!    NETWORK round-trip (request-sent → response-received, EXCLUDING the local apply / fsync) and
//!    feeds it to the wrapped [`Codel`] as the queue SOJOURN. The network leg — not the
//!    host-disk-jitter-dominated total service time — is what stretches when the LINK is saturated,
//!    which is exactly the contention this rate-limit protects against. The throttle then subtracts the
//!    minimum-observed network leg as the uncontended BASELINE and feeds CoDel the STANDING (excess)
//!    delay, so it is portable across fast / slow links without per-host tuning. Per RFC 8289, when the
//!    standing delay stays above [`Codel::target_ms`] for a full [`Codel::interval_ms`], CoDel signals
//!    contention; a near-baseline delay clears it. The delay rises precisely when the link is contended
//!    by live traffic, so CoDel reads the contention WITHOUT any cross-thread coordination.
//!
//! 3. **Budget shaping + yield.** The decision returns a [`FetchBudget`] (the `max_records` /
//!    `max_bytes` for the NEXT catch-up fetch) and a `yield_for` inter-fetch backoff:
//!    - **healthy** → the FULL catch-up budget and no backoff (fast convergence when the link is
//!      idle);
//!    - **contended** → the budget multiplicatively SHRINKS toward a floor and an inter-fetch
//!      backoff is imposed, so the catch-up's share of the link drops and live traffic keeps
//!      headroom. The shrink/grow reuses the AIMD asymmetry (grow steadily, back off fast) the
//!      broker's credit auto-tune already uses, via [`AimdLimiter`].
//!
//! ## The four non-negotiables, by construction
//!
//! - **Correctness unchanged.** This only ever changes the `max_records` / `max_bytes` REQUEST
//!   budget and adds an inter-fetch sleep. WHAT is applied is untouched: the follower still
//!   re-validates every frame's CRC, appends contiguously in order, and fails closed on a gap /
//!   corruption (`crate::cluster::replication::Follower::apply_fetch_response`). A smaller budget is
//!   simply more, smaller fetches — the same bytes, the same order.
//! - **Live traffic protected.** The throttled budget shrinks toward [`MIN_CATCHUP_RECORDS`] /
//!   [`MIN_CATCHUP_BYTES`] (a small fraction of the full budget) and a backoff is imposed, so a
//!   catch-up under contention can occupy at most a small, BOUNDED share of the link — live
//!   produce / consume / replication always has headroom.
//! - **Bounded, never starved.** The budget floor is `>= 1` record and a non-zero byte budget, and
//!   the backoff is capped at [`MAX_BACKOFF_MS`]; the throttle only SLOWS the catch-up, it can never
//!   stop it. Each non-empty fetch still advances the follower's frontier, so the catch-up always
//!   makes forward progress and converges to the high-watermark in bounded time.
//! - **Idle cost ~0.** A caught-up or throttled-waiting follower BLOCKS (the loop's
//!   `sleep_interruptible`), it never busy-spins (the #726 discipline). This type holds no thread and
//!   does no work between calls.

use ironbus_core::backpressure::{AimdLimiter, Codel};

/// The backlog (in records) above which a follower is treated as RE-REPLICATING (catching up) rather
/// than steady-state tailing, so the rate-limit engages. `backlog = leader_high_watermark -
/// follower_next_offset`.
///
/// Chosen as the FULL catch-up record budget ([`FULL_CATCHUP_RECORDS`]): below one full fetch's worth
/// the follower can converge in a single round, so there is nothing to rate-limit (it is effectively
/// tailing); above it the catch-up is multi-round and is the firehose worth shaping. This keeps the
/// steady-state path (a follower within one fetch of the head) completely untouched — exactly the
/// "near the HW fetches normally" requirement.
pub const CATCHUP_BACKLOG_THRESHOLD: u64 = FULL_CATCHUP_RECORDS as u64;

/// The FULL (un-throttled) catch-up record budget per fetch — the historical
/// `serve::FETCH_MAX_RECORDS`. A healthy (uncontended) catch-up requests this many records per fetch,
/// for fast convergence.
pub const FULL_CATCHUP_RECORDS: u32 = 1024;

/// The FULL (un-throttled) catch-up byte budget per fetch — the historical `serve::FETCH_MAX_BYTES`
/// (1 MiB). The leader bounds a response to at most this (and to `MAX_REPL_FETCH_BYTES`), so a single
/// fetch is always size-bounded.
pub const FULL_CATCHUP_BYTES: u32 = 1024 * 1024;

/// The FLOOR on the throttled catch-up RECORD budget: the throttle never shrinks a fetch below this,
/// so the catch-up always makes forward progress (it is bounded, never starved). Small enough that a
/// throttled catch-up occupies only a thin slice of the link, large enough to still advance.
pub const MIN_CATCHUP_RECORDS: u32 = 32;

/// The FLOOR on the throttled catch-up BYTE budget (64 KiB): paired with [`MIN_CATCHUP_RECORDS`] so a
/// throttled fetch is small but never zero — convergence is guaranteed.
pub const MIN_CATCHUP_BYTES: u32 = 64 * 1024;

/// The longest inter-fetch backoff the throttle imposes under sustained contention, in milliseconds.
/// Bounding the backoff is what guarantees the catch-up cannot be starved indefinitely: even under
/// permanent contention the follower issues a (small) fetch at least every [`MAX_BACKOFF_MS`], so it
/// always converges in bounded time.
pub const MAX_BACKOFF_MS: u64 = 200;

/// The default CoDel TARGET for the re-replication throttle, in milliseconds: the acceptable STANDING
/// (above-baseline) per-fetch delay. The controller feeds CoDel the per-fetch QUEUEING delay — the
/// service delay MINUS the minimum-observed (uncontended) baseline (see [`ReReplicationThrottle`]) —
/// so the TARGET is the excess delay a contended link adds, NOT the absolute fetch+apply+fsync time
/// (which varies wildly by host / disk and would otherwise trip the throttle on its OWN baseline
/// work).
///
/// Set at 50 ms (well above RFC 8289's 5 ms produce-queue default) deliberately: a catch-up fetch's
/// baseline service time is dominated by a local `fsync`, whose normal per-fetch JITTER on a busy host
/// (scheduling, page-cache flush, a loaded disk) is routinely tens of milliseconds — that jitter is
/// NOT link contention and must not throttle. A genuine link-saturation event (a 1 MiB catch-up fetch
/// queued behind live produce / consume / replication on a busy link) adds HUNDREDS of milliseconds of
/// standing delay, far above this target. 50 ms cleanly separates the two: the throttle ignores fsync
/// jitter and fires on real link saturation. (CoDel additionally requires the delay to stay above
/// target for a full [`DEFAULT_REREPL_CODEL_INTERVAL_MS`] before arming, so a single jitter spike never
/// throttles.)
pub const DEFAULT_REREPL_CODEL_TARGET_MS: u64 = 50;

/// The default CoDel INTERVAL for the re-replication throttle, in milliseconds: the window the service
/// delay must stay above TARGET before the throttle engages (so a single slow fetch does not
/// over-react). RFC 8289 default (100 ms).
pub const DEFAULT_REREPL_CODEL_INTERVAL_MS: u64 = 100;

/// The decision the throttle returns for the next catch-up fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The budget (record + byte caps) to request in the next fetch.
    pub budget: FetchBudget,
    /// The inter-fetch backoff to sleep BEFORE issuing the next catch-up fetch, in milliseconds. `0`
    /// while healthy (no yield) or while not re-replicating. Bounded by [`MAX_BACKOFF_MS`]. The serve
    /// loop sleeps this via its interruptible sleep, so a throttled-waiting follower BLOCKS (idle cost
    /// ~0), never busy-spins.
    pub yield_for_ms: u64,
    /// Whether this fetch is being RATE-LIMITED (the follower is far behind AND the controller is in
    /// the contended state). Purely informational (a gauge / a test signal); the loop acts on
    /// `budget` + `yield_for_ms`.
    pub throttled: bool,
}

impl Decision {
    /// The full-rate decision: the un-throttled catch-up budget, no backoff. Used when the follower is
    /// NOT re-replicating (within [`CATCHUP_BACKLOG_THRESHOLD`] of the head — steady-state tailing) or
    /// when the link is healthy.
    #[must_use]
    pub fn full_rate() -> Decision {
        Decision {
            budget: FetchBudget {
                max_records: FULL_CATCHUP_RECORDS,
                max_bytes: FULL_CATCHUP_BYTES,
            },
            yield_for_ms: 0,
            throttled: false,
        }
    }
}

/// The record + byte budget for one fetch request (the `max_records` / `max_bytes` of a
/// `FetchRecordsBody`). Shrinking this is how the throttle reduces a catch-up's link share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchBudget {
    /// The maximum records to request in the next fetch.
    pub max_records: u32,
    /// The maximum CRC-framed record bytes to request in the next fetch.
    pub max_bytes: u32,
}

/// The CoDel-style adaptive throttle on ONE partition's re-replication (catch-up) fetch.
///
/// It composes the pure [`Codel`] controller (the contention SIGNAL, from the per-fetch STANDING
/// delay) with an [`AimdLimiter`] (the budget SHAPE: grow steadily, back off fast). The serve loop
/// calls [`Self::observe_fetch`] after each catch-up fetch with how long it took, then
/// [`Self::decide`] before the next one with the current backlog; the returned [`Decision`] carries
/// the next budget + any backoff.
///
/// ## Why a BASELINE-RELATIVE sojourn
///
/// The absolute per-fetch network round-trip varies by orders of magnitude across links: a fast
/// LAN is sub-millisecond, a slow WAN / cellular edge link tens of milliseconds. So a fixed
/// absolute target would either never fire (too high) or fire on the catch-up's OWN baseline
/// round-trip with no contention at all (too low). True CoDel sheds on the STANDING
/// queue delay: the delay ABOVE the no-load minimum. So this tracks the MINIMUM observed round-trip
/// as the uncontended baseline and feeds CoDel the EXCESS (`round_trip - baseline`). On an idle
/// link the excess is ~0 (no throttle, full-rate catch-up); when live traffic contends the link the
/// per-fetch round-trip rises above the baseline and the excess crosses the target to engage the
/// throttle. The baseline only ever ratchets DOWN (a faster-than-ever fetch lowers it), so a transient
/// fast fetch cannot mask sustained contention.
///
/// Disabled (a `0` CoDel target or interval) makes [`Self::decide`] always return
/// [`Decision::full_rate`] for a catch-up — the historical un-throttled behavior — so a broker that
/// turns the throttle off is byte-for-byte as before. The throttle is NEVER constructed off-cluster
/// (it lives only on the follower fetch path), so the single-node hot path is untouched.
#[derive(Clone, Copy, Debug)]
pub struct ReReplicationThrottle {
    /// The controlled-delay contention signal over the per-fetch STANDING (above-baseline) delay.
    codel: Codel,
    /// The catch-up RECORD budget as an AIMD window in `[MIN_CATCHUP_RECORDS, FULL_CATCHUP_RECORDS]`:
    /// `keep_up` (a healthy fetch) grows it back toward full additively, `back_off` (a CoDel shed)
    /// halves it toward the floor. The byte budget is derived proportionally from this so the two
    /// dimensions move together.
    records: AimdLimiter,
    /// The MINIMUM observed per-fetch service delay (nanoseconds) — the uncontended baseline the
    /// standing delay is measured above. `None` until the first fetch is observed. Only ratchets down,
    /// so contention (a delay above this floor) is what drives the CoDel signal, never the absolute
    /// host/disk service time.
    baseline_nanos: Option<u64>,
    /// The most recent decision's "throttled" state, for the observability gauge / a test signal.
    throttled: bool,
}

impl ReReplicationThrottle {
    /// Build a throttle from a CoDel TARGET / INTERVAL in MILLISECONDS. A `0` for either disables the
    /// controller (every catch-up runs full-rate). The record budget starts at the FULL budget (an
    /// idle link converges at full rate immediately) and adapts down under contention.
    #[must_use]
    pub fn from_millis(codel_target_ms: u64, codel_interval_ms: u64) -> ReReplicationThrottle {
        ReReplicationThrottle {
            codel: Codel::from_millis(codel_target_ms, codel_interval_ms),
            // The AIMD step is `+1` (additive increase per healthy fetch); the floor / ceiling are the
            // throttled / full record budgets. Start at the ceiling: a fresh follower on an idle link
            // converges full-rate from the first fetch.
            records: AimdLimiter::new(
                FULL_CATCHUP_RECORDS,
                MIN_CATCHUP_RECORDS,
                FULL_CATCHUP_RECORDS,
            ),
            baseline_nanos: None,
            throttled: false,
        }
    }

    /// The default re-replication throttle: CoDel target [`DEFAULT_REREPL_CODEL_TARGET_MS`] (5 ms),
    /// interval [`DEFAULT_REREPL_CODEL_INTERVAL_MS`] (100 ms).
    #[must_use]
    pub fn default_throttle() -> ReReplicationThrottle {
        ReReplicationThrottle::from_millis(
            DEFAULT_REREPL_CODEL_TARGET_MS,
            DEFAULT_REREPL_CODEL_INTERVAL_MS,
        )
    }

    /// Whether the throttle is ENABLED (a non-zero CoDel target + interval). A disabled throttle
    /// always returns [`Decision::full_rate`].
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.codel.is_enabled()
    }

    /// Whether the last [`Self::decide`] rate-limited the fetch (for the gauge / tests).
    #[must_use]
    pub fn is_throttled(&self) -> bool {
        self.throttled
    }

    /// The current catch-up RECORD budget the controller would request (for the gauge / tests).
    #[must_use]
    pub fn current_records_budget(&self) -> u32 {
        self.records.limit()
    }

    /// The current CoDel sojourn estimate in milliseconds (the per-fetch service delay the control law
    /// is acting on), for the gauge.
    #[must_use]
    pub fn sojourn_estimate_ms(&self) -> u64 {
        self.codel.sojourn_estimate_ms()
    }

    /// Feed the controller ONE catch-up fetch's SERVICE DELAY (`service_nanos`, the wall-clock the
    /// fetch round-trip + the local apply took, clamped `>= 0` by the caller) measured at monotonic
    /// time `now_nanos`. The controller tracks the MINIMUM observed service delay as the uncontended
    /// BASELINE and feeds CoDel the STANDING delay (`service_nanos - baseline`), so the throttle reads
    /// CONTENTION (the delay a busy link adds), not the host/disk baseline. A standing delay above the
    /// CoDel target sustained for the interval SHRINKS the budget (the link is contended — yield); a
    /// near-baseline delay GROWS it back toward full (the link is idle — converge fast).
    ///
    /// Only catch-up (re-replicating) fetches should be fed here; a steady-state tailing fetch does
    /// not drive the throttle (the loop fetches full-rate there).
    pub fn observe_fetch(&mut self, service_nanos: u64, now_nanos: u64) {
        if !self.codel.is_enabled() {
            return;
        }
        // Ratchet the uncontended baseline DOWN to the fastest fetch ever seen, then measure this
        // fetch's STANDING delay above it. The baseline only falls, so sustained contention (every
        // fetch slower than the no-load floor) keeps the standing delay high.
        let baseline = match self.baseline_nanos {
            Some(b) => b.min(service_nanos),
            None => service_nanos,
        };
        self.baseline_nanos = Some(baseline);
        let standing_nanos = service_nanos.saturating_sub(baseline);
        // CoDel `sojourn` returns true when THIS sample should be "shed" — here, the contention
        // signal to BACK OFF the catch-up budget. A healthy sample returns false and GROWS it.
        if self.codel.sojourn(standing_nanos, now_nanos) {
            self.records.on_failure(); // multiplicative shrink toward the floor
        } else {
            self.records.on_success(); // additive grow back toward full
        }
    }

    /// Signal that the catch-up drained (the follower reached the high-watermark or this fetch came
    /// back empty), so the contention window is cleared — the next catch-up starts fresh rather than
    /// carrying a stale dropping state. Mirrors [`Codel::on_empty`].
    pub fn on_caught_up(&mut self, now_nanos: u64) {
        self.codel.on_empty(now_nanos);
    }

    /// The decision for the NEXT fetch, given the follower's current `backlog` (records the leader's
    /// high-watermark is ahead of the follower's next offset) at monotonic time `now_nanos`.
    ///
    /// - `backlog <= CATCHUP_BACKLOG_THRESHOLD` (steady-state tailing, or disabled) →
    ///   [`Decision::full_rate`]: the follower is near the head; fetch normally (no rate-limit at all,
    ///   so ordinary live replication is unaffected).
    /// - `backlog > CATCHUP_BACKLOG_THRESHOLD` (re-replicating) → the SHAPED budget: the current AIMD
    ///   record budget (shrunk under contention, grown when healthy), a proportionally-derived byte
    ///   budget, and an inter-fetch backoff that scales with how throttled the budget is (so a deeply
    ///   throttled catch-up yields more of the link). The backoff is capped at [`MAX_BACKOFF_MS`], so
    ///   the catch-up is never starved.
    pub fn decide(&mut self, backlog: u64, now_nanos: u64) -> Decision {
        if !self.codel.is_enabled() || backlog <= CATCHUP_BACKLOG_THRESHOLD {
            // Not re-replicating (or the throttle is off): full-rate, and the contention window is
            // cleared so a later catch-up starts fresh.
            if backlog <= CATCHUP_BACKLOG_THRESHOLD {
                self.codel.on_empty(now_nanos);
            }
            self.throttled = false;
            return Decision::full_rate();
        }

        let records = self.records.limit();
        // Derive the byte budget proportionally to the record budget's position in its range, so the
        // two dimensions throttle together. At the full record budget the byte budget is full; at the
        // floor it is the byte floor; in between it interpolates.
        let max_bytes = scale_bytes(records);
        // The fetch is throttled iff the budget has been shrunk below full (the controller is in the
        // contended state).
        let throttled = records < FULL_CATCHUP_RECORDS;
        self.throttled = throttled;
        // The inter-fetch backoff: zero while at full budget (healthy — converge fast), scaling up to
        // MAX_BACKOFF_MS as the budget approaches the floor (deeply contended — yield the link to live
        // traffic). Linear in how far the budget has shrunk.
        let yield_for_ms = if throttled { backoff_ms(records) } else { 0 };
        Decision {
            budget: FetchBudget {
                max_records: records,
                max_bytes,
            },
            yield_for_ms,
            throttled,
        }
    }
}

/// Derive the catch-up BYTE budget from the current RECORD budget, interpolating linearly between the
/// byte floor (at the record floor) and the full byte budget (at the full record budget), so the two
/// budget dimensions shrink and grow together. Saturating / floored so the result is always within
/// `[MIN_CATCHUP_BYTES, FULL_CATCHUP_BYTES]`.
fn scale_bytes(records: u32) -> u32 {
    if records >= FULL_CATCHUP_RECORDS {
        return FULL_CATCHUP_BYTES;
    }
    if records <= MIN_CATCHUP_RECORDS {
        return MIN_CATCHUP_BYTES;
    }
    // position in [0, 1] of records within [MIN_CATCHUP_RECORDS, FULL_CATCHUP_RECORDS], in u64 math.
    let span_records = u64::from(FULL_CATCHUP_RECORDS - MIN_CATCHUP_RECORDS);
    let above_floor = u64::from(records - MIN_CATCHUP_RECORDS);
    let span_bytes = u64::from(FULL_CATCHUP_BYTES - MIN_CATCHUP_BYTES);
    // bytes = MIN + span_bytes * above_floor / span_records; span_records is non-zero here
    // (FULL_CATCHUP_RECORDS > MIN_CATCHUP_RECORDS by construction).
    let extra = span_bytes.saturating_mul(above_floor) / span_records;
    let bytes = u64::from(MIN_CATCHUP_BYTES).saturating_add(extra);
    // The result is within [MIN_CATCHUP_BYTES, FULL_CATCHUP_BYTES] by construction; clamp defensively.
    u32::try_from(bytes.min(u64::from(FULL_CATCHUP_BYTES))).unwrap_or(FULL_CATCHUP_BYTES)
}

/// The inter-fetch backoff in milliseconds for a throttled catch-up at the given RECORD budget. Zero
/// at the full budget, scaling LINEARLY up to [`MAX_BACKOFF_MS`] as the budget approaches the floor —
/// so a deeply throttled catch-up yields more of the link to live traffic, but the backoff is always
/// capped (the catch-up is never starved). The caller only calls this when `records <
/// FULL_CATCHUP_RECORDS` (throttled).
fn backoff_ms(records: u32) -> u64 {
    let records = records.clamp(MIN_CATCHUP_RECORDS, FULL_CATCHUP_RECORDS);
    let span_records = u64::from(FULL_CATCHUP_RECORDS - MIN_CATCHUP_RECORDS);
    // How far below full the budget has shrunk, in [0, span_records].
    let below_full = u64::from(FULL_CATCHUP_RECORDS - records);
    // backoff = MAX_BACKOFF_MS * below_full / span_records, in [0, MAX_BACKOFF_MS]. span_records is
    // non-zero by construction.
    (MAX_BACKOFF_MS.saturating_mul(below_full) / span_records).min(MAX_BACKOFF_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    // ---- catch-up detection: steady-state tailing is never throttled ----

    #[test]
    fn a_follower_within_one_fetch_of_the_head_is_never_throttled() {
        let mut t = ReReplicationThrottle::default_throttle();
        // Backlog at/under the threshold: steady-state tailing. Even after a contention episode, a
        // near-the-head fetch is full-rate (the throttle is catch-up-only).
        let d = t.decide(CATCHUP_BACKLOG_THRESHOLD, 0);
        assert_eq!(d, Decision::full_rate());
        assert!(!d.throttled);
        let d = t.decide(0, MS);
        assert_eq!(d, Decision::full_rate());
        let d = t.decide(1, 2 * MS);
        assert_eq!(d, Decision::full_rate());
    }

    #[test]
    fn a_disabled_throttle_always_runs_full_rate_even_far_behind() {
        let mut t = ReReplicationThrottle::from_millis(0, 100); // disabled
        assert!(!t.is_enabled());
        // Feed sustained huge service delays: a disabled throttle never shrinks.
        let mut now = 0u64;
        for _ in 0..1000 {
            now += MS;
            t.observe_fetch(50 * MS, now);
        }
        let d = t.decide(10_000_000, now);
        assert_eq!(
            d,
            Decision::full_rate(),
            "a disabled throttle is the historical un-throttled catch-up"
        );
    }

    // ---- the CoDel contention signal: far behind + contention => throttle ----

    #[test]
    fn a_far_behind_follower_under_sustained_contention_throttles_the_budget() {
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        let backlog = 10_000_000u64; // far behind: re-replicating.
                                     // Establish a low uncontended baseline (a fast idle-link fetch, ~0.5 ms).
        now += MS;
        t.observe_fetch(MS / 2, now);
        // Healthy at first: full budget.
        let d = t.decide(backlog, now);
        assert!(!d.throttled, "starts un-throttled");
        assert_eq!(d.budget.max_records, FULL_CATCHUP_RECORDS);
        // Sustained per-fetch service delay well ABOVE the baseline+target (150 ms standing >> 50 ms
        // target) for several intervals: CoDel signals contention, the budget shrinks, a backoff is
        // imposed.
        for _ in 0..400 {
            now += MS;
            t.observe_fetch(150 * MS, now);
        }
        let d = t.decide(backlog, now);
        assert!(
            d.throttled,
            "sustained contention while far behind throttles"
        );
        assert!(
            d.budget.max_records < FULL_CATCHUP_RECORDS,
            "the record budget shrank: {}",
            d.budget.max_records
        );
        assert!(
            d.budget.max_records >= MIN_CATCHUP_RECORDS,
            "but never below the floor (bounded, never starved): {}",
            d.budget.max_records
        );
        assert!(
            d.yield_for_ms > 0,
            "a backoff yields the link to live traffic"
        );
        assert!(d.yield_for_ms <= MAX_BACKOFF_MS, "the backoff is capped");
        assert!(
            d.budget.max_bytes < FULL_CATCHUP_BYTES && d.budget.max_bytes >= MIN_CATCHUP_BYTES,
            "the byte budget shrinks with the record budget, floored: {}",
            d.budget.max_bytes
        );
    }

    #[test]
    fn a_healthy_link_keeps_the_full_catchup_budget_even_far_behind() {
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        let backlog = 10_000_000u64;
        // Service delays well UNDER the 5 ms target: a fast, idle link. Never throttles.
        for _ in 0..1000 {
            now += MS;
            t.observe_fetch(MS, now); // 1 ms << 5 ms target
            let d = t.decide(backlog, now);
            assert!(!d.throttled, "a healthy link converges full-rate");
            assert_eq!(d.budget.max_records, FULL_CATCHUP_RECORDS);
            assert_eq!(d.yield_for_ms, 0, "no backoff while healthy");
        }
    }

    #[test]
    fn the_throttle_recovers_to_full_rate_when_contention_clears() {
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        let backlog = 10_000_000u64;
        // Establish a low uncontended baseline.
        now += MS;
        t.observe_fetch(MS / 2, now);
        // Drive into the throttled state with a high standing delay above the baseline.
        for _ in 0..400 {
            now += MS;
            t.observe_fetch(150 * MS, now);
        }
        assert!(
            t.decide(backlog, now).throttled,
            "throttled under contention"
        );
        // Contention clears: near-baseline fetches grow the budget back toward full (additive
        // recovery).
        for _ in 0..5000 {
            now += MS;
            t.observe_fetch(MS / 2, now);
        }
        let d = t.decide(backlog, now);
        assert!(!d.throttled, "recovered to full rate once the link is idle");
        assert_eq!(d.budget.max_records, FULL_CATCHUP_RECORDS);
        assert_eq!(d.yield_for_ms, 0);
    }

    // ---- bounded, never starved: the floor + capped backoff guarantee progress ----

    #[test]
    fn under_permanent_contention_the_budget_floors_and_never_reaches_zero() {
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        let backlog = 10_000_000u64;
        // Establish a low uncontended baseline, then permanent heavy contention above it: many CoDel
        // sheds, the budget halves repeatedly toward the floor.
        now += MS;
        t.observe_fetch(MS / 2, now);
        for _ in 0..100_000 {
            now += MS;
            t.observe_fetch(300 * MS, now);
        }
        let d = t.decide(backlog, now);
        assert!(
            d.budget.max_records < FULL_CATCHUP_RECORDS,
            "permanent contention drove the budget below full: {}",
            d.budget.max_records
        );
        assert!(
            d.budget.max_records >= MIN_CATCHUP_RECORDS,
            "the record budget never collapses below the floor (>= 1 record, so forward progress is \
             guaranteed): {}",
            d.budget.max_records
        );
        assert!(
            d.budget.max_bytes >= MIN_CATCHUP_BYTES,
            "the byte budget never collapses to zero (it floors at MIN_CATCHUP_BYTES): {}",
            d.budget.max_bytes
        );
        assert!(
            d.yield_for_ms <= MAX_BACKOFF_MS,
            "the backoff is always capped, so a fetch is issued at least every MAX_BACKOFF_MS"
        );
    }

    #[test]
    fn a_constant_high_delay_is_not_contention_and_does_not_throttle() {
        // The baseline-relative core: a SLOW but STEADY link (every fetch 90 ms — a slow disk, not a
        // contended one) has zero STANDING delay above its own baseline, so it is NOT throttled. Only a
        // delay that RISES above the established baseline (real contention) throttles. This is what
        // makes the throttle portable across fast/slow hosts without per-host tuning.
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        let backlog = 10_000_000u64;
        for _ in 0..1000 {
            now += MS;
            t.observe_fetch(90 * MS, now); // constant 90 ms: slow but uncontended.
            let d = t.decide(backlog, now);
            assert!(
                !d.throttled,
                "a constant (uncontended) delay must not throttle: budget {}",
                d.budget.max_records
            );
        }
        assert_eq!(t.current_records_budget(), FULL_CATCHUP_RECORDS);
    }

    // ---- live traffic protected: the throttled catch-up's link share is bounded ----

    #[test]
    fn under_contention_the_catchup_link_share_is_bounded_so_live_traffic_keeps_headroom() {
        // The live-traffic-protection invariant, deterministically: under sustained contention the
        // per-fetch budget shrinks toward the floor AND a per-fetch backoff is imposed, so the catch-up
        // can occupy at most a small, BOUNDED share of the link — leaving headroom for live traffic.
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        let backlog = 10_000_000u64;
        // Low baseline, then sustained contention.
        now += MS;
        t.observe_fetch(MS / 2, now);
        for _ in 0..2000 {
            now += MS;
            t.observe_fetch(200 * MS, now);
        }
        let d = t.decide(backlog, now);
        assert!(d.throttled, "sustained contention throttles");
        // The catch-up's per-fetch budget is at most a small FRACTION of the full budget: the throttle
        // caps its link share so live traffic always has the rest. (At the deep-contention end the
        // budget is near the floor — a tiny slice.)
        assert!(
            d.budget.max_records <= FULL_CATCHUP_RECORDS / 4,
            "the throttled budget is capped to a small share of the link: {} of {}",
            d.budget.max_records,
            FULL_CATCHUP_RECORDS
        );
        // AND it yields the link between fetches (a non-trivial backoff), so even the small fetches do
        // not occupy the link back-to-back.
        assert!(
            d.yield_for_ms > 0 && d.yield_for_ms <= MAX_BACKOFF_MS,
            "a bounded inter-fetch backoff yields the link: {} ms",
            d.yield_for_ms
        );
    }

    // ---- convergence: a throttled catch-up still drains a backlog in bounded time ----

    #[test]
    fn a_throttled_catchup_still_drains_a_backlog_to_zero_no_starvation() {
        // Simulate the serve loop's catch-up under PERMANENT contention: each round, the follower
        // fetches `budget.max_records` (capped by the remaining backlog), advances, and the throttle
        // shrinks the budget. Prove the backlog still reaches ZERO in a BOUNDED number of rounds — the
        // throttle slows the catch-up but never starves it (the floor + capped backoff guarantee
        // forward progress).
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        let mut backlog: u64 = 200_000; // a big backlog (~200x the full per-fetch budget).
                                        // Establish a low baseline so the contention below is a real standing delay.
        now += MS;
        t.observe_fetch(MS / 2, now);
        let mut rounds = 0u64;
        while backlog > 0 {
            rounds += 1;
            assert!(
                rounds < 100_000,
                "the throttled catch-up must converge in bounded rounds (no livelock): backlog={backlog}"
            );
            let d = t.decide(backlog, now);
            // The fetch pulls min(budget, backlog) records — always at least one (the floor), so the
            // backlog strictly decreases every round (forward progress, no deadlock).
            let pulled = u64::from(d.budget.max_records).min(backlog).max(1);
            assert!(pulled >= 1, "every fetch advances by at least one record");
            backlog -= pulled.min(backlog);
            // Permanent contention: every fetch is slow above the baseline.
            now += MS;
            t.observe_fetch(200 * MS, now);
        }
        assert_eq!(
            backlog, 0,
            "the throttled catch-up converged to the high-watermark"
        );
        // It DID throttle along the way (the budget was driven below full), proving the convergence was
        // through the rate-limited path, not because the throttle was inert.
        assert!(
            t.current_records_budget() < FULL_CATCHUP_RECORDS,
            "the catch-up converged WHILE rate-limited (budget {} < full)",
            t.current_records_budget()
        );
    }

    // ---- pure budget-shaping helpers ----

    #[test]
    fn scale_bytes_spans_the_floor_to_full_range_monotonically() {
        assert_eq!(scale_bytes(FULL_CATCHUP_RECORDS), FULL_CATCHUP_BYTES);
        assert_eq!(scale_bytes(MIN_CATCHUP_RECORDS), MIN_CATCHUP_BYTES);
        assert_eq!(
            scale_bytes(0),
            MIN_CATCHUP_BYTES,
            "below floor clamps to floor"
        );
        assert_eq!(
            scale_bytes(FULL_CATCHUP_RECORDS + 1),
            FULL_CATCHUP_BYTES,
            "above full clamps to full"
        );
        // Monotonic non-decreasing across the range.
        let mut prev = 0u32;
        let mut r = MIN_CATCHUP_RECORDS;
        while r <= FULL_CATCHUP_RECORDS {
            let b = scale_bytes(r);
            assert!(b >= prev, "scale_bytes is monotonic: {b} < {prev} at {r}");
            assert!(
                (MIN_CATCHUP_BYTES..=FULL_CATCHUP_BYTES).contains(&b),
                "in range at {r}: {b}"
            );
            prev = b;
            r += 32;
        }
    }

    #[test]
    fn backoff_is_zero_at_full_budget_and_capped_at_the_floor() {
        assert_eq!(
            backoff_ms(FULL_CATCHUP_RECORDS),
            0,
            "no backoff at full budget"
        );
        assert_eq!(
            backoff_ms(MIN_CATCHUP_RECORDS),
            MAX_BACKOFF_MS,
            "max backoff at the floor"
        );
        // Monotonic non-increasing in the budget (more throttled => more backoff), always capped.
        let mut prev = MAX_BACKOFF_MS + 1;
        let mut r = MIN_CATCHUP_RECORDS;
        while r <= FULL_CATCHUP_RECORDS {
            let b = backoff_ms(r);
            assert!(b <= prev, "backoff is non-increasing in budget");
            assert!(b <= MAX_BACKOFF_MS, "backoff is always capped");
            prev = b;
            r += 32;
        }
    }

    #[test]
    fn on_caught_up_clears_the_contention_window() {
        let mut t = ReReplicationThrottle::default_throttle();
        let mut now = 0u64;
        // Establish a low uncontended baseline.
        now += MS;
        t.observe_fetch(MS / 2, now);
        // Open the above-target window most of the way (but not yet armed): 50 ms < 100 ms interval.
        for _ in 0..50 {
            now += MS;
            t.observe_fetch(150 * MS, now);
        }
        // The follower caught up: clear the window.
        now += MS;
        t.on_caught_up(now);
        // A fresh sub-interval contention burst must NOT immediately throttle (the window was reset).
        for _ in 0..50 {
            now += MS;
            t.observe_fetch(150 * MS, now);
        }
        assert!(
            t.current_records_budget() == FULL_CATCHUP_RECORDS,
            "after on_caught_up a sub-interval burst does not shrink the budget: {}",
            t.current_records_budget()
        );
    }

    // ---- determinism: the same injected stream makes the same decisions ----

    #[test]
    fn the_decision_is_deterministic_under_an_injected_clock() {
        let run = || {
            let mut t = ReReplicationThrottle::default_throttle();
            let mut now = 0u64;
            let backlog = 5_000_000u64;
            let mut budgets = Vec::new();
            for i in 0..500 {
                now += MS;
                // A deterministic mixed delay pattern: alternating high (contended)/low (idle).
                let delay = if i % 3 == 0 { 200 * MS } else { 2 * MS };
                t.observe_fetch(delay, now);
                budgets.push(t.decide(backlog, now).budget.max_records);
            }
            budgets
        };
        assert_eq!(
            run(),
            run(),
            "identical injected streams => identical decisions"
        );
    }
}
