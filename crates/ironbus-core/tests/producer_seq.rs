// SPDX-License-Identifier: MIT OR Apache-2.0
//! Model-based property tests for the broker-side effectively-once state machine
//! (`ProducerSeqRegistry::check` / `record`, #842, V2-M8; KIP-98).
//!
//! The in-crate `#[cfg(test)]` module for `producer_seq` is thorough but entirely example-based:
//! one retry, one gap, one epoch bump each. Dedup bugs hide in the INTERLEAVING space — a retry of
//! an older sequence after several advances, a stale-epoch replay landing between a fresh check and
//! its record, an epoch bump that should (or should not) reset `last_seq`. This test drives a random
//! op stream over a SINGLE producer against a reference model and asserts, per step, that the
//! registry's decision and its published high-water agree with the model. A double-append, a false
//! accept of a gap, a wrong duplicate offset, or a missed fence is a silent durability/exactly-once
//! defect — the worst class for this primitive — so the model is the discriminating oracle.
//!
//! Layered like the trie/resolve-cache tests (#568/#569):
//!
//! 1. A GOLDEN sequence pins fresh -> retry -> gap -> bump -> stale on a hand-picked interleaving.
//! 2. A PROPTEST model oracle interleaves `Advance` / `Retry` / `Gap` / `BumpEpoch` / `StaleReplay`
//!    and asserts, on every step, decision-and-high-water == model.

use ironbus_core::producer_seq::{ProducerSeqRegistry, SeqConfig, SeqDecision};
use ironbus_core::types::Offset;

/// The single producer every op targets. Keeping it to one producer keeps the model's `(epoch,
/// last_seq, last_offset)` a scalar and makes the dedup invariant the WHOLE assertion.
const PID: &[u8] = b"producer";

/// A registry sized far above the op count so eviction NEVER fires: this test isolates the dedup
/// state machine; eviction has its own example tests in the crate module.
fn registry() -> ProducerSeqRegistry {
    ProducerSeqRegistry::new(SeqConfig {
        max_producers: 4096,
    })
}

// ---------------------------------------------------------------------------
// 1. Golden interleaving: fresh -> retry(old) -> gap -> bump(reset) -> stale.
// ---------------------------------------------------------------------------

#[test]
fn golden_interleaving_matches_the_hand_model() {
    let mut r = registry();

    // Two fresh appends at epoch 3, offsets 100 then 101 (strictly increasing).
    assert_eq!(r.check(PID, 3, 0, 0), SeqDecision::Fresh);
    r.record(PID, 3, 0, Offset::new(100), 0);
    assert_eq!(r.check(PID, 3, 1, 1), SeqDecision::Fresh);
    r.record(PID, 3, 1, Offset::new(101), 1);

    // A retry of the OLDER seq 0 (not the high-water) is still a duplicate at the HIGH-WATER
    // offset 101 — we hold only the last offset — and never advances.
    assert_eq!(
        r.check(PID, 3, 0, 2),
        SeqDecision::Duplicate {
            offset: Offset::new(101)
        }
    );
    assert_eq!(r.high_water(PID), Some((3, Some(1), Offset::new(101))));

    // A gap (seq 3, expected 2) is rejected and leaves the high-water untouched.
    assert_eq!(
        r.check(PID, 3, 3, 3),
        SeqDecision::OutOfOrder { expected: 2 }
    );
    assert_eq!(r.high_water(PID), Some((3, Some(1), Offset::new(101))));

    // An epoch bump to 5 RESETS the sequence space: check reports Fresh and the high-water's
    // last_seq is None until the record lands.
    assert_eq!(r.check(PID, 5, 0, 4), SeqDecision::Fresh);
    assert_eq!(r.high_water(PID), Some((5, None, Offset::new(101))));
    r.record(PID, 5, 0, Offset::new(200), 4);
    assert_eq!(r.high_water(PID), Some((5, Some(0), Offset::new(200))));

    // A stale-epoch replay (epoch 4 < 5) is fenced with the current epoch and changes nothing.
    assert_eq!(
        r.check(PID, 4, 9, 5),
        SeqDecision::Fenced { current_epoch: 5 }
    );
    assert_eq!(r.high_water(PID), Some((5, Some(0), Offset::new(200))));
}

// ---------------------------------------------------------------------------
// 2. Model-based proptest over a random op stream.
// ---------------------------------------------------------------------------

use proptest::prelude::*;

/// One op in the randomized stream. Parameters are RAW draws reduced against the live model at
/// apply time (e.g. a retry seq is taken modulo `last + 1`), so every op is always well-formed.
#[derive(Clone, Debug)]
enum Op {
    /// Check the next expected sequence; on Fresh, record it at a strictly increasing offset.
    Advance,
    /// Retry an already-recorded sequence (raw draw reduced into `0..=last`): must be a Duplicate
    /// at the model's last offset and must not advance the high-water.
    Retry(u64),
    /// Present a gap `last + g` with `g >= 2`: must be OutOfOrder{expected: last + 1}, no advance.
    Gap(u64),
    /// Bump the epoch by `1..=3`: check under the new epoch must be Fresh and must reset `last_seq`.
    BumpEpoch(u64),
    /// Replay under a strictly-older epoch (raw draws for how-far-back and the seq): must be Fenced.
    StaleReplay(u64, u64),
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => Just(Op::Advance),
        4 => any::<u64>().prop_map(Op::Retry),
        3 => (2u64..=6).prop_map(Op::Gap),
        3 => (1u64..=3).prop_map(Op::BumpEpoch),
        3 => (any::<u64>(), any::<u64>()).prop_map(|(b, s)| Op::StaleReplay(b, s)),
    ]
}

/// The reference model: the last-accepted `(epoch, last_seq, last_offset)` for the one producer,
/// plus a monotonic offset mint and a monotonic clock. `last_seq` is `None` only before the first
/// record at the current epoch.
struct Model {
    epoch: u64,
    last_seq: Option<u64>,
    last_offset: Offset,
    next_offset: u64,
    now: u64,
}

proptest! {
    /// THE model property: over an arbitrary interleaving of advances, retries, gaps, epoch bumps,
    /// and stale replays, the registry's `check` decision on every step equals the model's, and its
    /// published `high_water` equals the model's `(epoch, last_seq, last_offset)` triple. This pins,
    /// simultaneously, all five invariants #842 calls out:
    ///   * every recorded Fresh gets a strictly increasing offset;
    ///   * a retry of a recorded seq is Duplicate{offset == model.last_offset} and never advances;
    ///   * high_water's last_seq is monotonic non-decreasing within an epoch and resets to None on a
    ///     strictly higher epoch;
    ///   * any epoch strictly below the model epoch is Fenced{current_epoch};
    ///   * seq > last + 1 is OutOfOrder{expected: last + 1}.
    #[test]
    fn check_and_record_match_the_model_over_random_streams(
        ops in proptest::collection::vec(arb_op(), 1..=64),
    ) {
        let mut r = registry();
        let mut m = Model {
            epoch: 0,
            last_seq: None,
            last_offset: Offset::new(0),
            next_offset: 1,
            now: 0,
        };
        // Whether the producer has been established (first Advance/BumpEpoch). Before that the
        // producer is untracked and high_water is None; after it, last_seq is always Some.
        let mut established = false;
        // The previous established high-water, for the explicit monotonic-within-epoch check.
        let mut prev_hw: Option<(u64, u64)> = None;

        for op in ops {
            m.now += 1;
            match op {
                Op::Advance => {
                    let seq = m.last_seq.map_or(0, |last| last + 1);
                    prop_assert_eq!(r.check(PID, m.epoch, seq, m.now), SeqDecision::Fresh);
                    let offset = Offset::new(m.next_offset);
                    // Strictly increasing offset assignment (vs the previous high-water offset).
                    if established {
                        prop_assert!(offset.get() > m.last_offset.get());
                    }
                    r.record(PID, m.epoch, seq, offset, m.now);
                    m.last_seq = Some(seq);
                    m.last_offset = offset;
                    m.next_offset += 1;
                    established = true;
                }
                Op::Retry(raw) => {
                    let Some(last) = m.last_seq else { continue };
                    let past = raw % (last + 1); // in 0..=last
                    prop_assert_eq!(
                        r.check(PID, m.epoch, past, m.now),
                        SeqDecision::Duplicate { offset: m.last_offset }
                    );
                    // A retry never advances the high-water.
                    prop_assert_eq!(
                        r.high_water(PID),
                        Some((m.epoch, Some(last), m.last_offset))
                    );
                }
                Op::Gap(g) => {
                    let Some(last) = m.last_seq else { continue };
                    let seq = last + g; // g >= 2, so seq >= last + 2 > last + 1
                    prop_assert_eq!(
                        r.check(PID, m.epoch, seq, m.now),
                        SeqDecision::OutOfOrder { expected: last + 1 }
                    );
                    // A rejected gap never advances the high-water.
                    prop_assert_eq!(
                        r.high_water(PID),
                        Some((m.epoch, Some(last), m.last_offset))
                    );
                }
                Op::BumpEpoch(delta) => {
                    let new_epoch = m.epoch + delta;
                    prop_assert_eq!(r.check(PID, new_epoch, 0, m.now), SeqDecision::Fresh);
                    // The bump RESET the sequence space: last_seq is None until the record lands.
                    prop_assert_eq!(r.high_water(PID), Some((new_epoch, None, m.last_offset)));
                    let offset = Offset::new(m.next_offset);
                    r.record(PID, new_epoch, 0, offset, m.now);
                    m.epoch = new_epoch;
                    m.last_seq = Some(0);
                    m.last_offset = offset;
                    m.next_offset += 1;
                    established = true;
                }
                Op::StaleReplay(back, seq) => {
                    if m.epoch == 0 {
                        continue; // no epoch strictly below 0 exists
                    }
                    let stale = m.epoch - (back % m.epoch + 1); // in 0..m.epoch
                    prop_assert_eq!(
                        r.check(PID, stale, seq, m.now),
                        SeqDecision::Fenced { current_epoch: m.epoch }
                    );
                    // A fenced zombie changes nothing.
                    prop_assert_eq!(
                        r.high_water(PID),
                        Some((m.epoch, m.last_seq, m.last_offset))
                    );
                }
            }

            // After every op, the registry's published high-water equals the model's triple.
            if established {
                let hw = r.high_water(PID).expect("established producer is tracked");
                prop_assert_eq!(hw, (m.epoch, m.last_seq, m.last_offset));

                // Explicit monotonicity: within an epoch last_seq is non-decreasing; a strictly
                // higher epoch is the ONLY way the epoch moves.
                let last = m.last_seq.expect("established => last_seq is Some");
                if let Some((prev_epoch, prev_seq)) = prev_hw {
                    if hw.0 == prev_epoch {
                        prop_assert!(last >= prev_seq, "last_seq regressed within an epoch");
                    } else {
                        prop_assert!(hw.0 > prev_epoch, "epoch must only increase");
                    }
                }
                prev_hw = Some((hw.0, last));
            }
        }
    }
}
