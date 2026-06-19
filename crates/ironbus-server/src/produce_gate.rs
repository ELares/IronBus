// SPDX-License-Identifier: MIT OR Apache-2.0
//! The connection-thread produce fast-reject gate (#476, fixes #465).
//!
//! ## The bug (#465)
//!
//! Every produce-side load-shed decision — the CoDel controlled-delay shed, the fsync-headroom shed,
//! and the durable-log byte-cap [`AtCapacity`](crate::actor::ProduceOutcome::AtCapacity) shed — runs
//! on the SINGLE append-actor thread, AFTER the connection handler's blocking send into the bounded
//! actor channel (`EngineHandle::produce_submit` → `tx.send`, bound
//! [`DEFAULT_CHANNEL_BOUND`](crate::actor::DEFAULT_CHANNEL_BOUND)). When the broker is saturated the
//! channel fills, so the client BLOCKS on `send` and cannot reach the cheap shed: backpressure
//! front-runs the load-shed. A produce that should have been a prompt, immediate `AtCapacity`
//! rejection instead stalls behind the full channel until the actor drains — the #465 symptom
//! (pre-loading a `--storage memory` broker past its byte cap "did not return"; the client waited
//! on an ack it could not get).
//!
//! ## The fix (#476)
//!
//! A connection-thread **fast-reject pre-check** that runs BEFORE the blocking `tx.send`. It reads an
//! O(1) relaxed-atomic snapshot of the engine's durable-byte-cap state (this gate) and, when it is
//! SURE the actor would shed the produce with `AtCapacity`, replies `AtCapacity` IMMEDIATELY without
//! enqueuing and without blocking. The authoritative actor-side byte-cap check
//! ([`Engine::append_no_sync`](crate::engine::Engine) → `Log::append`) is UNCHANGED and remains the
//! source of truth (it must, for I2 / single-total-order correctness); this gate is purely a
//! fast-reject FILTER in front of it, exactly the same seam shape as the off-actor consume path.
//!
//! ## Conservatism (the load-bearing property): NO false rejects
//!
//! A false reject — fast-rejecting a produce the actor would have ACCEPTED — is lost throughput / a
//! dropped good message, so it is forbidden. This gate fast-rejects ONLY when it is certain the actor
//! would shed. The guarantee rests on three facts, all of which hold because the bytes value and the
//! overflow policy are mutated EXCLUSIVELY on the append-actor thread (see `actor::run_actor` and the
//! `engine.with(...)` config-reload path, which both run on that one thread, serialized):
//!
//! 1. **The authoritative predicate is monotone-safe to snapshot.** The actor sheds `AtCapacity`
//!    exactly when `cap != 0 && durable_record_bytes >= cap && durable_record_bytes > 0`
//!    (`Log::append`). The cap (`max_total_bytes`) is NOT live-reloadable (it is layout/contract-bound
//!    and requires a restart), so it is fixed for the engine's life and can be snapshotted once. The
//!    only quantity that moves is `durable_record_bytes`, and it changes ONLY on the actor thread:
//!    it GROWS on an append (inside `commit_batch`) and SHRINKS only on a reap (also inside
//!    `commit_batch`, or on a config-reload reap — both on the actor).
//!
//! 2. **A stale snapshot under drop-new can only be too LOW, never falsely too high.** The actor
//!    refreshes this gate's bytes value right AFTER every `commit_batch` (the one place bytes change).
//!    Between that refresh and the actor next processing a produce, NOTHING lowers the real bytes (a
//!    reap only runs during a `commit_batch`, which is when/after the pre-checked produce is itself
//!    processed). So if the snapshot reads "at/over cap," the real value is still at/over cap when the
//!    actor checks it — the fast-reject matches the authoritative outcome. A snapshot that lags LOW
//!    (e.g. a not-yet-published recent append) merely makes the gate fall through to the actor, which
//!    is always safe.
//!
//! 3. **Drop-oldest never fast-rejects.** Under [`DiskFullPolicy::DropOldest`](crate::engine) an
//!    over-cap produce is ACCEPTED after a force-reap, so an over-cap snapshot does NOT imply a shed.
//!    The policy is live-reloadable (on the actor), so to stay conservative across a flip the actor
//!    publishes a SENTINEL (`bytes = 0`, which always reads as under-cap) whenever the policy is
//!    drop-oldest, and re-publishes the real bytes only while it is drop-new. A flip to drop-oldest
//!    therefore disables the gate before any produce is accepted under the new policy; a flip back to
//!    drop-new starting from the `0` sentinel only ever UNDER-reports (falls through to the actor)
//!    until the next commit refreshes it. Either direction is safe.
//!
//! The net effect: the gate can fast-reject a produce the actor would have rejected (the #465 fix),
//! and can NEVER fast-reject a produce the actor would have accepted (no false rejects). When it is
//! not sure, it returns `false` and the produce takes the normal, fully-authoritative actor path.

use core::sync::atomic::{AtomicU64, Ordering};

/// A shared, relaxed-atomic snapshot of the durable-log byte-cap shed state the connection thread
/// reads to fast-reject an at-or-over-cap produce BEFORE the blocking actor-channel send (#476).
///
/// One `AtomicU64`, relaxed ordering (the value is an advisory fast-reject hint, not a synchronization
/// point for any other state — the actor's own check stays authoritative). The configured cap is held
/// as a plain field because it never changes after open (`max_total_bytes` is not live-reloadable).
///
/// `bytes` carries the live `durable_record_bytes` the actor publishes after each commit WHILE the
/// overflow policy is drop-new, and the sentinel `0` whenever the policy is drop-oldest (so the gate
/// disengages under drop-oldest, which accepts over-cap produces). See the module docs for the full
/// no-false-reject argument.
#[derive(Debug)]
pub struct ProduceCapGate {
    /// The configured durable-log byte cap (`LogConfig::max_total_bytes`). `0` means the cap is OFF
    /// (unlimited): the gate then never fast-rejects, exactly matching the actor, which never sheds
    /// `AtCapacity` with no cap. Fixed for the engine's life (not live-reloadable).
    cap: u64,
    /// The most recently published shed-eligible `durable_record_bytes`, or the `0` sentinel under
    /// drop-oldest. Read relaxed by the connection thread, stored relaxed by the actor thread.
    bytes: AtomicU64,
    /// A MONOTONIC running total of fast-rejects performed on the connection thread (#476), so a
    /// fast-reject is never a SILENT shed. The connection thread bumps it (relaxed `fetch_add`) every
    /// time [`ProduceCapGate::would_shed`] short-circuits a produce; the actor reads it once per batch
    /// and folds the DELTA since its last read into the engine's authoritative shed counters
    /// (`Engine::record_fast_reject_sheds`), so `ironbus_produce_rejected_total` counts a fast-reject
    /// exactly like an in-actor `AtCapacity` shed. Monotonic + delta-reconciled, so the count is
    /// exact under any number of concurrent connection threads with no lock and no double-count.
    fast_rejects: AtomicU64,
    /// The fast-reject high-water mark the ACTOR has already folded into the engine's authoritative
    /// shed counters (#476). Touched ONLY by the actor thread (in `take_unreconciled_fast_rejects`),
    /// so it needs no compare-and-swap: the actor reads `fast_rejects - reconciled` as the new delta,
    /// then advances `reconciled` to the value it just observed. An `AtomicU64` (not a plain field)
    /// only because the gate is shared behind an `Arc`.
    reconciled: AtomicU64,
    /// A MONOTONIC running total of LEVEL-0 (no-ack / fire-and-forget) produces fast-rejected at the
    /// connection thread by the SAME byte-cap pre-check (#495, generalizing #476). Kept SEPARATE from
    /// `fast_rejects` because an over-cap L0 shed is a fire-and-forget DROP (the client accepted loss,
    /// no ack), so the actor folds this delta into `ironbus_fire_and_forget_shed_total` (NOT
    /// `produce_rejected`, which counts the Level-1 at-least-once rejections the producers actually
    /// saw). The connection thread bumps it (relaxed `fetch_add`) every time
    /// [`ProduceCapGate::would_shed`] short-circuits an L0 produce; the actor reads the delta once per
    /// batch and folds it, so an L0 cap-shed is never a silent drop. Monotonic + delta-reconciled, so
    /// the count is exact under any number of concurrent connection threads with no lock.
    l0_shed: AtomicU64,
    /// The L0-shed high-water mark the ACTOR has already folded into
    /// `ironbus_fire_and_forget_shed_total` (#495). Touched ONLY by the actor thread (in
    /// [`ProduceCapGate::take_unreconciled_l0_sheds`]), so it needs no compare-and-swap, exactly like
    /// `reconciled` does for `fast_rejects`.
    l0_reconciled: AtomicU64,
}

impl ProduceCapGate {
    /// Creates a gate for a log whose byte cap is `cap` (`0` = unlimited / cap off). Seeded with
    /// `bytes = 0` (under cap), so a freshly opened broker never fast-rejects until the actor has
    /// published a real over-cap reading — the conservative starting point.
    #[must_use]
    pub fn new(cap: u64) -> ProduceCapGate {
        ProduceCapGate {
            cap,
            bytes: AtomicU64::new(0),
            fast_rejects: AtomicU64::new(0),
            reconciled: AtomicU64::new(0),
            l0_shed: AtomicU64::new(0),
            l0_reconciled: AtomicU64::new(0),
        }
    }

    /// Publishes the current shed-eligible durable byte total (the actor thread calls this).
    ///
    /// Pass the engine's live `durable_record_bytes` WHILE the overflow policy is drop-new, or the
    /// sentinel `0` whenever it is drop-oldest (so the gate disengages under a policy that accepts
    /// over-cap produces). A single relaxed store; called once per `commit_batch` and once per policy
    /// reload, never on the per-message connection hot path. See [`ProduceCapGate::publish_drop_new`]
    /// and [`ProduceCapGate::disengage`] for the two intent-named wrappers the actor uses.
    pub fn publish(&self, shed_eligible_bytes: u64) {
        self.bytes.store(shed_eligible_bytes, Ordering::Relaxed);
    }

    /// Publishes `durable_record_bytes` as the shed-eligible total: the actor calls this after a
    /// commit WHILE the overflow policy is drop-new (the only policy under which an over-cap produce
    /// is actually shed). A thin, intent-named wrapper over [`ProduceCapGate::publish`].
    pub fn publish_drop_new(&self, durable_record_bytes: u64) {
        self.publish(durable_record_bytes);
    }

    /// Disengages the gate (publishes the `0` sentinel): the actor calls this whenever the overflow
    /// policy is drop-oldest, under which an over-cap produce is ACCEPTED after a force-reap, so the
    /// connection-thread fast-reject must never fire. A thin, intent-named wrapper over
    /// [`ProduceCapGate::publish`].
    pub fn disengage(&self) {
        self.publish(0);
    }

    /// The connection-thread fast-reject decision: returns `true` ONLY when the gate is SURE the
    /// actor would shed this produce with `AtCapacity`, so the caller may reply `AtCapacity`
    /// immediately WITHOUT enqueuing onto the (possibly full, blocking) actor channel — the #476 fix.
    ///
    /// Mirrors the authoritative `Log::append` predicate EXACTLY (`cap != 0 && bytes >= cap &&
    /// bytes > 0`) over the last-published snapshot. Because the snapshot can only lag LOW under
    /// drop-new and is forced to the under-cap sentinel under drop-oldest (see the module docs), a
    /// `true` here implies the actor would also shed — never a false reject. A `false` means "not
    /// sure / would succeed," and the produce falls through to the normal authoritative actor path.
    #[must_use]
    pub fn would_shed(&self) -> bool {
        let cap = self.cap;
        if cap == 0 {
            // No cap configured: the actor never sheds `AtCapacity`, so the gate never fires.
            return false;
        }
        let bytes = self.bytes.load(Ordering::Relaxed);
        // The at-or-over check, identical to `Log::append`: `bytes > 0` keeps the empty-log rule (an
        // oversized first record is always written, never wedged out by a fast-reject).
        bytes >= cap && bytes > 0
    }

    /// Records that the connection thread just fast-rejected a produce (#476): bumps the monotonic
    /// fast-reject total so the actor can later count the shed in the engine's authoritative
    /// `produce_rejected` (a fast-reject is never silent). A single relaxed `fetch_add` on the produce
    /// fast-path; the caller invokes it exactly once per [`ProduceCapGate::would_shed`] that fired.
    pub fn record_fast_reject(&self) {
        self.fast_rejects.fetch_add(1, Ordering::Relaxed);
    }

    /// The MONOTONIC running total of fast-rejects performed on the connection thread (#476). A single
    /// relaxed load. Exposed for tests/observability; the actor uses
    /// [`ProduceCapGate::take_unreconciled_fast_rejects`] to fold the delta into the engine counters.
    #[must_use]
    pub fn fast_reject_total(&self) -> u64 {
        self.fast_rejects.load(Ordering::Relaxed)
    }

    /// Returns the number of fast-rejects performed since the LAST call and advances the reconciled
    /// high-water mark (#476). Called ONLY by the actor thread, once per batch, so it needs no CAS:
    /// it reads the connection threads' monotonic total, subtracts what it has already folded, and
    /// records the new high-water mark. The returned delta is then folded into the engine's
    /// authoritative shed counters (`Engine::record_fast_reject_sheds`), so every fast-reject is
    /// counted exactly once and a fast-reject is never a silent shed. `saturating_sub` guards the
    /// (impossible-under-the-single-actor-invariant) case of a reordered read seeing a total below the
    /// high-water mark: it then reports `0` rather than a wrapped delta.
    pub fn take_unreconciled_fast_rejects(&self) -> u64 {
        let total = self.fast_rejects.load(Ordering::Relaxed);
        let already = self.reconciled.load(Ordering::Relaxed);
        let delta = total.saturating_sub(already);
        if delta != 0 {
            self.reconciled.store(total, Ordering::Relaxed);
        }
        delta
    }

    /// Records that the connection thread just fast-rejected a LEVEL-0 (no-ack / fire-and-forget)
    /// produce by the byte-cap pre-check (#495): bumps the monotonic L0-shed total so the actor can
    /// later fold it into `ironbus_fire_and_forget_shed_total` (an over-cap L0 shed is a fire-and-forget
    /// drop, never silent). A single relaxed `fetch_add` on the L0 fast path; the caller invokes it
    /// exactly once per [`ProduceCapGate::would_shed`] that fired for an L0 produce. SEPARATE from
    /// [`ProduceCapGate::record_fast_reject`] so an L0 shed is counted as a fire-and-forget drop, not a
    /// Level-1 `produce_rejected` rejection.
    pub fn record_l0_shed(&self) {
        self.l0_shed.fetch_add(1, Ordering::Relaxed);
    }

    /// The MONOTONIC running total of Level-0 produces fast-rejected on the connection thread (#495). A
    /// single relaxed load. Exposed for tests/observability; the actor uses
    /// [`ProduceCapGate::take_unreconciled_l0_sheds`] to fold the delta into the engine counter.
    #[must_use]
    pub fn l0_shed_total(&self) -> u64 {
        self.l0_shed.load(Ordering::Relaxed)
    }

    /// Returns the number of Level-0 cap-sheds performed since the LAST call and advances the
    /// L0-reconciled high-water mark (#495). Called ONLY by the actor thread, once per batch, so it
    /// needs no CAS: it reads the connection threads' monotonic L0 total, subtracts what it has already
    /// folded, and records the new high-water mark. The returned delta is folded into
    /// `ironbus_fire_and_forget_shed_total` (`Engine::record_fire_and_forget_sheds`), so an L0 cap-shed
    /// is counted exactly once and never silent. `saturating_sub` guards the
    /// (impossible-under-the-single-actor-invariant) reordered read, reporting `0` rather than wrapping.
    pub fn take_unreconciled_l0_sheds(&self) -> u64 {
        let total = self.l0_shed.load(Ordering::Relaxed);
        let already = self.l0_reconciled.load(Ordering::Relaxed);
        let delta = total.saturating_sub(already);
        if delta != 0 {
            self.l0_reconciled.store(total, Ordering::Relaxed);
        }
        delta
    }

    /// The configured cap (`0` = unlimited). Exposed for tests and observability.
    #[must_use]
    pub fn cap(&self) -> u64 {
        self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_cap_never_fast_rejects() {
        // cap == 0 is the default (unlimited): the actor never sheds `AtCapacity`, so neither does the
        // gate, no matter how large the published byte total grows.
        let gate = ProduceCapGate::new(0);
        assert!(!gate.would_shed());
        gate.publish_drop_new(u64::MAX);
        assert!(!gate.would_shed(), "no cap => never fast-reject");
    }

    #[test]
    fn a_fresh_gate_is_under_cap() {
        // Seeded at 0 bytes: a freshly opened broker is under cap and never fast-rejects until the
        // actor publishes a real over-cap reading (the conservative starting point).
        let gate = ProduceCapGate::new(1_000);
        assert!(!gate.would_shed());
    }

    #[test]
    fn it_fast_rejects_only_at_or_over_cap() {
        // Mirrors `Log::append` exactly: under cap => fall through; AT cap or OVER => fast-reject.
        let gate = ProduceCapGate::new(1_000);
        gate.publish_drop_new(999);
        assert!(!gate.would_shed(), "below cap is not a shed");
        gate.publish_drop_new(1_000);
        assert!(gate.would_shed(), "at cap sheds (at-or-over)");
        gate.publish_drop_new(2_500);
        assert!(gate.would_shed(), "over cap sheds");
        // A reap drops it back under the cap: the gate disengages again, so a later produce is not
        // falsely rejected.
        gate.publish_drop_new(500);
        assert!(
            !gate.would_shed(),
            "a reap back under cap re-opens the gate"
        );
    }

    #[test]
    fn the_empty_log_rule_is_preserved() {
        // `bytes == 0` is never a shed even when the cap is tiny: the empty-log first record is always
        // written (an oversized first record is not wedged out), exactly as `Log::append`'s
        // `total > 0` clause guarantees.
        let gate = ProduceCapGate::new(1);
        assert!(!gate.would_shed(), "empty log: first record always written");
        gate.publish_drop_new(0);
        assert!(!gate.would_shed());
    }

    #[test]
    fn drop_oldest_disengages_the_gate() {
        // Under drop-oldest an over-cap produce is ACCEPTED after a force-reap, so the actor publishes
        // the `0` sentinel via `disengage()` and the gate must never fire even though the real byte
        // total is over cap.
        let gate = ProduceCapGate::new(1_000);
        gate.publish_drop_new(5_000); // would fast-reject under drop-new
        assert!(gate.would_shed());
        gate.disengage(); // a flip to drop-oldest
        assert!(
            !gate.would_shed(),
            "drop-oldest accepts over-cap; the gate must disengage (no false reject)"
        );
    }

    #[test]
    fn fast_rejects_are_counted_and_reconciled_as_exact_deltas() {
        // A fast-reject is never a SILENT shed: each `record_fast_reject` bumps the monotonic total,
        // and the actor's `take_unreconciled_fast_rejects` hands back EXACTLY the new ones since the
        // last reconcile (so the engine's `produce_rejected` ends up equal to the rejections the
        // producers actually saw — no under- or double-count).
        let gate = ProduceCapGate::new(1_000);
        assert_eq!(gate.fast_reject_total(), 0);
        assert_eq!(
            gate.take_unreconciled_fast_rejects(),
            0,
            "nothing to fold yet"
        );

        gate.record_fast_reject();
        gate.record_fast_reject();
        gate.record_fast_reject();
        assert_eq!(gate.fast_reject_total(), 3);
        // The actor folds all 3 at once.
        assert_eq!(gate.take_unreconciled_fast_rejects(), 3);
        // A second reconcile with no new fast-rejects folds nothing (no double-count).
        assert_eq!(gate.take_unreconciled_fast_rejects(), 0);

        // More fast-rejects accrue; only the NEW ones are folded next time.
        gate.record_fast_reject();
        gate.record_fast_reject();
        assert_eq!(gate.fast_reject_total(), 5, "the total stays monotonic");
        assert_eq!(
            gate.take_unreconciled_fast_rejects(),
            2,
            "only the 2 new ones"
        );
        assert_eq!(gate.take_unreconciled_fast_rejects(), 0);
    }

    #[test]
    fn l0_sheds_are_counted_and_reconciled_separately_from_l1_fast_rejects() {
        // A LEVEL-0 (no-ack) cap-shed is a fire-and-forget DROP, so it is tallied on its OWN counter
        // and folded into `fire_and_forget_shed`, NEVER mixed into the Level-1 `produce_rejected`
        // fast-reject total (#495). The two counters move independently and reconcile as exact deltas.
        let gate = ProduceCapGate::new(1_000);
        assert_eq!(gate.l0_shed_total(), 0);
        assert_eq!(gate.fast_reject_total(), 0);

        // Two L0 sheds and one L1 fast-reject: each lands on its own counter.
        gate.record_l0_shed();
        gate.record_l0_shed();
        gate.record_fast_reject();
        assert_eq!(gate.l0_shed_total(), 2, "L0 sheds on the L0 counter only");
        assert_eq!(
            gate.fast_reject_total(),
            1,
            "L1 fast-rejects unaffected by L0"
        );

        // Each reconciles its own delta; folding one never consumes the other.
        assert_eq!(gate.take_unreconciled_l0_sheds(), 2);
        assert_eq!(gate.take_unreconciled_fast_rejects(), 1);
        assert_eq!(gate.take_unreconciled_l0_sheds(), 0, "no double-count");
        assert_eq!(gate.take_unreconciled_fast_rejects(), 0, "no double-count");

        // Only the NEW L0 sheds fold next time.
        gate.record_l0_shed();
        assert_eq!(gate.take_unreconciled_l0_sheds(), 1, "only the new L0 shed");
        assert_eq!(gate.take_unreconciled_l0_sheds(), 0);
    }

    #[test]
    fn cap_is_reported() {
        assert_eq!(ProduceCapGate::new(4_096).cap(), 4_096);
        assert_eq!(ProduceCapGate::new(0).cap(), 0);
    }
}
