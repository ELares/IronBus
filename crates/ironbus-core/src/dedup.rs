// SPDX-License-Identifier: MIT OR Apache-2.0
//! The opt-in effectively-once dedup window (#3, #33): a producer-supplied `msg_id`
//! deduplicated within a bounded per-producer window.
//!
//! Dedup is OFF by default and activates per-producer ONLY when a publish carries a
//! `msg_id`; a publish with no `msg_id` never touches this structure, so the historical
//! behavior is byte-for-byte unchanged. When active, the broker keeps, per producer, a
//! ring of `(msg_id -> offset)` bounded by BOTH a count (default
//! [`DEFAULT_MAX_IDS`]) AND a monotonic time window (default [`DEFAULT_WINDOW_NANOS`]),
//! evicting on whichever bound is hit first. A `msg_id` seen again within the window is a
//! BENIGN dedup hit: the broker returns the ORIGINAL offset with `duplicate = true` and a
//! success status, NEVER an error, so an idempotent retry over a lossy edge link does not
//! loop. A republish OUTSIDE the window (the id aged or was evicted out) is treated as a
//! genuinely new produce and is delivered again; consumers stay idempotent regardless.
//!
//! Keying is `msg_id` ONLY, never the body, matching `JetStream` and SQS FIFO.
//!
//! ## Epoch fencing
//!
//! A producer may carry a stable `producer_id` plus a monotonic `epoch`. A HIGHER epoch
//! FENCES an older one: when a producer's known epoch advances, the older window is reset
//! (a new session supersedes a zombie), and a produce that presents a STALE epoch (below
//! the known one) is fenced and rejected, so a zombie session reusing an old `producer_id`
//! cannot replay stale ids. The default producer (an empty `producer_id`) carries epoch 0
//! and is never fenced, so a plain `msg_id`-only producer with no identity still dedups.
//!
//! ## Time and IO
//!
//! The structure is PURE and IO-free, like [`crate::lease::LeaseTable`]: the caller
//! supplies monotonic time (`now`, in nanoseconds, from the clock seam) on each call, so
//! an NTP wall-clock step can never mis-expire the window (I6). Across a broker restart the
//! registry is empty, so session-scoped dedup is lost on restart (the documented default);
//! an optional persistent `producer_id` high-water in the WAL that survives restart is a
//! deferred follow-up (the in-memory structure here is the window the spec sizes).
//!
//! ## Memory
//!
//! Each live producer holds at most [`DedupConfig::max_ids`] entries; each entry is a
//! `Vec<u8>` `msg_id` plus a `u64` offset plus a `u64` insertion instant, indexed twice (a
//! FIFO order queue and a lookup map). The per-producer worst case is bounded by `max_ids`
//! and the `msg_id` length cap; see `docs/RAM_BUDGET.md`.

use crate::types::Offset;
use std::collections::HashMap;
use std::collections::VecDeque;

/// The default count bound on a per-producer dedup window: at most this many `(msg_id,
/// offset)` entries are retained before the oldest is evicted (#33). Sized so a fast
/// producer's recent ids are remembered for retries without unbounded growth.
pub const DEFAULT_MAX_IDS: usize = 100_000;

/// The default time bound on a per-producer dedup window, in NANOSECONDS of monotonic time:
/// an entry older than this is evicted regardless of the count bound (#33). Two minutes,
/// the spec default: long enough to cover an edge-link retry, short enough to bound memory.
pub const DEFAULT_WINDOW_NANOS: u64 = 120 * 1_000_000_000;

/// The hard cap on a `msg_id`'s length in bytes. A `msg_id` is producer-chosen (a UUID, a
/// sequence string, a content hash); this bounds the per-entry memory and rejects a hostile
/// oversized id before it is stored. Generous for any real idempotency key.
pub const MAX_MSG_ID_LEN: usize = 256;

/// The dedup window tunables: the dual count + time bound (#33). A `0` `max_ids` is NOT a
/// way to disable the count bound (a zero count bound would remember nothing and so dedup
/// nothing); the engine floors it to 1. A `0` `window_nanos` DOES disable the TIME bound
/// (only the count bound applies), matching the `0` = off convention used elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DedupConfig {
    /// The count bound: the most `(msg_id, offset)` entries one producer's window retains
    /// before evicting the oldest. Floored to 1 by [`DedupRegistry::new`] (a zero count
    /// bound would remember nothing).
    pub max_ids: usize,
    /// The time bound in NANOSECONDS of monotonic time: an entry older than this is evicted
    /// on the next touch of the producer's window, independent of the count bound. `0`
    /// disables the time bound (only the count bound applies).
    pub window_nanos: u64,
}

impl Default for DedupConfig {
    /// The spec defaults: [`DEFAULT_MAX_IDS`] ids OR [`DEFAULT_WINDOW_NANOS`] (2 min),
    /// whichever is hit first.
    fn default() -> DedupConfig {
        DedupConfig {
            max_ids: DEFAULT_MAX_IDS,
            window_nanos: DEFAULT_WINDOW_NANOS,
        }
    }
}

/// The outcome of a [`DedupRegistry::check`]: whether a produce is fresh (append it), a
/// dedup hit (return the original offset, do NOT append), or fenced by a stale epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DedupDecision {
    /// A fresh produce: this `msg_id` is not in the producer's live window (it is new, or it
    /// aged/evicted out). The caller appends the record, then calls
    /// [`DedupRegistry::record`] with the assigned offset once it is durable. `out_of_window`
    /// is `true` when entries were evicted by the TIME bound while servicing this check (the
    /// republish-past-the-window risk signal), `false` for a plain new id.
    Fresh {
        /// Whether servicing this check evicted at least one entry by the TIME bound, i.e. an
        /// id's dedup protection lapsed (the out-of-window-republish observability signal).
        out_of_window: bool,
    },
    /// A BENIGN dedup hit: this `msg_id` is already in the producer's live window at this
    /// offset. The caller returns the original `offset` with `duplicate = true` and a success
    /// status (NEVER an error) and does NOT append a second copy.
    Duplicate {
        /// The original durable offset the first copy was assigned.
        offset: Offset,
    },
    /// The produce presented a STALE epoch (below the producer's known high-water): a zombie
    /// session reusing an old `producer_id`. The caller REJECTS the produce (it is fenced),
    /// appending nothing.
    Fenced {
        /// The producer's current (newer) known epoch that fenced this produce.
        current_epoch: u64,
    },
}

/// One producer's bounded dedup window: a FIFO order queue plus an O(1) lookup map, both
/// over the same `(msg_id -> offset)` entries, with the producer's epoch high-water.
#[derive(Debug)]
struct ProducerWindow {
    /// The producer's known epoch high-water. A produce below this is fenced; a produce
    /// above it resets the window and advances this.
    epoch: u64,
    /// FIFO insertion order, oldest at the front, for the count + time eviction. Each entry
    /// is `(msg_id, insertion_instant_nanos)`; the offset lives in `index`.
    order: VecDeque<(Vec<u8>, u64)>,
    /// O(1) lookup from `msg_id` to its `(offset, insertion_instant_nanos)`.
    index: HashMap<Vec<u8>, (Offset, u64)>,
}

impl ProducerWindow {
    fn new(epoch: u64) -> ProducerWindow {
        ProducerWindow {
            epoch,
            order: VecDeque::new(),
            index: HashMap::new(),
        }
    }

    /// Drops every entry older than the time bound (front of the FIFO), returning whether any
    /// were dropped. A `0` `window_nanos` disables the time bound. `now` is monotonic, so
    /// `now.saturating_sub(inserted)` never underflows.
    fn evict_expired(&mut self, window_nanos: u64, now: u64) -> bool {
        if window_nanos == 0 {
            return false;
        }
        let mut evicted = false;
        while let Some((msg_id, inserted)) = self.order.front() {
            if now.saturating_sub(*inserted) < window_nanos {
                break;
            }
            // The lookup map may already hold a NEWER insertion for the same id (a re-add after
            // an eviction); only remove the map entry if it still points at THIS aged instant,
            // so a live newer entry is never dropped.
            if self
                .index
                .get(msg_id)
                .is_some_and(|(_, idx_inserted)| *idx_inserted == *inserted)
            {
                self.index.remove(msg_id);
            }
            self.order.pop_front();
            evicted = true;
        }
        evicted
    }

    /// Drops oldest entries until the count bound holds. Mirrors `evict_expired`'s
    /// stale-map-entry guard.
    fn evict_overflow(&mut self, max_ids: usize) {
        while self.order.len() > max_ids {
            let Some((msg_id, inserted)) = self.order.pop_front() else {
                break;
            };
            if self
                .index
                .get(&msg_id)
                .is_some_and(|(_, idx_inserted)| *idx_inserted == inserted)
            {
                self.index.remove(&msg_id);
            }
        }
    }
}

/// The per-producer dedup registry: the broker-side owner of every live producer window
/// (#33). Held by the engine and consulted on the produce path; pure and IO-free (the
/// caller supplies monotonic `now`). The number of distinct live producers is bounded by
/// the caller's connection count and the natural churn of the windows; each window is
/// bounded by [`DedupConfig::max_ids`].
#[derive(Debug)]
pub struct DedupRegistry {
    config: DedupConfig,
    producers: HashMap<Vec<u8>, ProducerWindow>,
}

impl DedupRegistry {
    /// Creates an empty registry with `config`. The count bound is floored to 1 (a zero count
    /// bound would remember no id and dedup nothing).
    #[must_use]
    pub fn new(config: DedupConfig) -> DedupRegistry {
        DedupRegistry {
            config: DedupConfig {
                max_ids: config.max_ids.max(1),
                window_nanos: config.window_nanos,
            },
            producers: HashMap::new(),
        }
    }

    /// The active config (count and time bound), with the count floor applied.
    #[must_use]
    pub fn config(&self) -> DedupConfig {
        self.config
    }

    /// The number of live producer windows (for tests and introspection).
    #[must_use]
    pub fn producer_count(&self) -> usize {
        self.producers.len()
    }

    /// Decides what a produce carrying `producer_id` / `epoch` / `msg_id` should do, at
    /// monotonic instant `now`, WITHOUT mutating the stored `(msg_id -> offset)` mapping for a
    /// fresh produce (the caller calls [`DedupRegistry::record`] only once the append is
    /// durable). It DOES advance the producer's epoch and evict expired/overflow entries (pure
    /// window maintenance), and it returns:
    ///
    /// - [`DedupDecision::Fenced`] if `epoch` is below the producer's known high-water (a stale
    ///   zombie produce): reject it.
    /// - [`DedupDecision::Duplicate`] if `msg_id` is already in the producer's live window:
    ///   return the original offset with `duplicate = true`.
    /// - [`DedupDecision::Fresh`] otherwise: append, then `record` the assigned offset. Its
    ///   `out_of_window` flag is set when the maintenance evicted an entry by the TIME bound.
    ///
    /// A NEWER `epoch` than the known high-water RESETS the producer's window (a new session
    /// fences the old one's ids) before the lookup, so a fresh epoch never dedups against a
    /// prior epoch's ids.
    pub fn check(
        &mut self,
        producer_id: &[u8],
        epoch: u64,
        msg_id: &[u8],
        now: u64,
    ) -> DedupDecision {
        let max_ids = self.config.max_ids;
        let window_nanos = self.config.window_nanos;
        let window = self
            .producers
            .entry(producer_id.to_vec())
            .or_insert_with(|| ProducerWindow::new(epoch));

        // Epoch fencing: a stale epoch is rejected; a newer epoch supersedes the old session.
        if epoch < window.epoch {
            return DedupDecision::Fenced {
                current_epoch: window.epoch,
            };
        }
        if epoch > window.epoch {
            window.epoch = epoch;
            window.order.clear();
            window.index.clear();
        }

        // Window maintenance: time bound first (its eviction is the out-of-window signal), then
        // the count bound. Both run before the lookup so an aged id reads as a miss (fresh).
        let out_of_window = window.evict_expired(window_nanos, now);
        window.evict_overflow(max_ids);

        match window.index.get(msg_id) {
            Some((offset, _)) => DedupDecision::Duplicate { offset: *offset },
            None => DedupDecision::Fresh { out_of_window },
        }
    }

    /// Records that `msg_id` from `producer_id` was appended at `offset` at monotonic instant
    /// `now`, after a [`DedupDecision::Fresh`] check and the covering durable commit. A
    /// subsequent [`DedupRegistry::check`] for the same `msg_id` within the window then returns
    /// [`DedupDecision::Duplicate`] with this `offset`.
    ///
    /// Idempotent on a repeat call for an id already at the head: it refreshes the entry rather
    /// than double-inserting. The count and time bounds are re-applied so the window stays
    /// bounded even if `record` is called without an intervening `check`.
    pub fn record(&mut self, producer_id: &[u8], msg_id: &[u8], offset: Offset, now: u64) {
        let max_ids = self.config.max_ids;
        let window_nanos = self.config.window_nanos;
        let window = self
            .producers
            .entry(producer_id.to_vec())
            .or_insert_with(|| ProducerWindow::new(0));
        // A re-record of a live id updates the map in place; the stale order-queue entry is
        // skipped at eviction time by the instant guard, so it never double-removes a live id.
        window.index.insert(msg_id.to_vec(), (offset, now));
        window.order.push_back((msg_id.to_vec(), now));
        window.evict_expired(window_nanos, now);
        window.evict_overflow(max_ids);
    }

    /// The number of live entries in `producer_id`'s window (for tests).
    #[must_use]
    pub fn window_len(&self, producer_id: &[u8]) -> usize {
        self.producers.get(producer_id).map_or(0, |w| w.index.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> DedupRegistry {
        DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 1_000,
        })
    }

    #[test]
    fn a_new_msg_id_is_fresh_then_a_repeat_is_a_duplicate() {
        let mut r = reg();
        assert_eq!(
            r.check(b"", 0, b"m1", 0),
            DedupDecision::Fresh {
                out_of_window: false
            }
        );
        r.record(b"", b"m1", Offset::new(7), 0);
        assert_eq!(
            r.check(b"", 0, b"m1", 10),
            DedupDecision::Duplicate {
                offset: Offset::new(7)
            }
        );
    }

    #[test]
    fn a_distinct_msg_id_is_always_fresh() {
        let mut r = reg();
        r.record(b"", b"m1", Offset::new(1), 0);
        assert_eq!(
            r.check(b"", 0, b"m2", 0),
            DedupDecision::Fresh {
                out_of_window: false
            }
        );
    }

    #[test]
    fn the_count_bound_evicts_the_oldest_so_it_reads_fresh_again() {
        let mut r = reg(); // max_ids = 4
        for i in 0..4u64 {
            let id = format!("m{i}");
            r.record(b"", id.as_bytes(), Offset::new(i), 0);
        }
        // m0 is still present (exactly at the cap).
        assert_eq!(
            r.check(b"", 0, b"m0", 0),
            DedupDecision::Duplicate {
                offset: Offset::new(0)
            }
        );
        // A fifth id evicts the oldest (m0).
        r.record(b"", b"m4", Offset::new(4), 0);
        assert_eq!(
            r.check(b"", 0, b"m0", 0),
            DedupDecision::Fresh {
                out_of_window: false
            }
        );
        // m1..m4 are still live.
        assert_eq!(
            r.check(b"", 0, b"m4", 0),
            DedupDecision::Duplicate {
                offset: Offset::new(4)
            }
        );
    }

    #[test]
    fn the_time_bound_evicts_an_aged_id_and_flags_out_of_window() {
        let mut r = reg(); // window_nanos = 1_000
        r.record(b"", b"m1", Offset::new(1), 0);
        // Within the window: still a duplicate.
        assert_eq!(
            r.check(b"", 0, b"m1", 999),
            DedupDecision::Duplicate {
                offset: Offset::new(1)
            }
        );
        // Past the window: the aged id is evicted and the check reads fresh, flagged
        // out-of-window (its dedup protection lapsed).
        assert_eq!(
            r.check(b"", 0, b"m1", 1_000),
            DedupDecision::Fresh {
                out_of_window: true
            }
        );
    }

    #[test]
    fn a_zero_window_disables_the_time_bound() {
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 8,
            window_nanos: 0,
        });
        r.record(b"", b"m1", Offset::new(1), 0);
        // Even far in the future the id is a duplicate (only the count bound applies).
        assert_eq!(
            r.check(b"", 0, b"m1", u64::MAX),
            DedupDecision::Duplicate {
                offset: Offset::new(1)
            }
        );
    }

    #[test]
    fn the_count_bound_is_floored_to_one() {
        let r = DedupRegistry::new(DedupConfig {
            max_ids: 0,
            window_nanos: 0,
        });
        assert_eq!(r.config().max_ids, 1);
    }

    #[test]
    fn a_stale_epoch_is_fenced() {
        let mut r = reg();
        // Establish epoch 5 for this producer.
        assert!(matches!(
            r.check(b"p1", 5, b"m1", 0),
            DedupDecision::Fresh { .. }
        ));
        r.record(b"p1", b"m1", Offset::new(1), 0);
        // A produce at the OLD epoch 4 is fenced.
        assert_eq!(
            r.check(b"p1", 4, b"m2", 0),
            DedupDecision::Fenced { current_epoch: 5 }
        );
    }

    #[test]
    fn a_newer_epoch_resets_the_window() {
        let mut r = reg();
        r.check(b"p1", 1, b"m1", 0);
        r.record(b"p1", b"m1", Offset::new(1), 0);
        assert_eq!(
            r.check(b"p1", 1, b"m1", 0),
            DedupDecision::Duplicate {
                offset: Offset::new(1)
            }
        );
        // A newer epoch supersedes: the old window is cleared, so m1 reads fresh again.
        assert_eq!(
            r.check(b"p1", 2, b"m1", 0),
            DedupDecision::Fresh {
                out_of_window: false
            }
        );
    }

    #[test]
    fn distinct_producers_have_independent_windows() {
        let mut r = reg();
        r.check(b"p1", 0, b"shared", 0);
        r.record(b"p1", b"shared", Offset::new(1), 0);
        // The same msg_id from a DIFFERENT producer is fresh (keying is per-producer).
        assert_eq!(
            r.check(b"p2", 0, b"shared", 0),
            DedupDecision::Fresh {
                out_of_window: false
            }
        );
        assert_eq!(r.producer_count(), 2);
    }

    #[test]
    fn re_recording_a_live_id_does_not_grow_the_window_unboundedly() {
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 100,
            window_nanos: 0,
        });
        for t in 0..50u64 {
            r.record(b"", b"same", Offset::new(t), t);
        }
        // The map holds exactly one entry for the id despite 50 records.
        assert_eq!(r.window_len(b""), 1);
        assert_eq!(
            r.check(b"", 0, b"same", 50),
            DedupDecision::Duplicate {
                offset: Offset::new(49)
            }
        );
    }
}
