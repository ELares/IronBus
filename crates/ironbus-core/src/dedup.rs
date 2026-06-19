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
//! and the `msg_id` length cap.
//!
//! The TOTAL memory is hard-bounded too (#33). The `producer_id` is wire-supplied and
//! attacker-chosen, so the NUMBER of distinct producer windows must be capped or a peer that
//! sends endless distinct `producer_id`s grows broker RAM without bound. The registry caps the
//! count of tracked windows at [`DedupConfig::max_producers`] (default
//! [`DEFAULT_MAX_PRODUCERS`]) and, when a fresh `producer_id` would exceed the cap, evicts the
//! LEAST-RECENTLY-ACTIVE window (an approximate LRU keyed on each window's last-touch monotonic
//! instant). The victim is found in O(log P) amortized via a last-touch min-heap with lazy
//! invalidation, NOT an O(P) scan over every window — the scan would otherwise fire on every fresh
//! `producer_id`, precisely the producer-flood the cap defends against (#478). Evicting a window
//! only loses dedup state for the least-active producer, which then
//! falls back to at-least-once for that producer (already the contract for an aged/evicted id),
//! so eviction is safe. Fully time-expired windows are reaped opportunistically first, so an
//! idle producer does not pin a slot until the LRU cap forces it. The TOTAL worst case is thus
//! `max_producers * max_ids * per_entry`, with each `producer_id` itself bounded by
//! [`MAX_PRODUCER_ID_LEN`]; see `docs/RAM_BUDGET.md`.

use crate::types::Offset;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
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

/// The hard cap on a `producer_id`'s length in bytes. The `producer_id` is wire-supplied and
/// attacker-chosen, and it is the KEY of the producer-window map; without a cap a single id could
/// be up to the wire `u16` field limit (64 KiB), so this bounds the per-window key memory and
/// rejects a hostile oversized id at the engine boundary before it is stored (a typed rejection,
/// never a panic). Generous for any real producer identity (a UUID, a hostname, a session token).
pub const MAX_PRODUCER_ID_LEN: usize = 256;

/// The default cap on the NUMBER of distinct producer windows the registry tracks at once (#33).
/// The `producer_id` is attacker-chosen, so the count of windows must be bounded or a peer sending
/// endless distinct `producer_id`s grows broker RAM without bound. When a fresh `producer_id` would
/// exceed this cap, the least-recently-active window is evicted (an approximate LRU). Sized so a
/// realistic fan-in of producers all keep their windows, while a flood is hard-bounded.
pub const DEFAULT_MAX_PRODUCERS: usize = 4096;

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
    /// The cap on the NUMBER of distinct producer windows tracked at once (the TOTAL-memory
    /// bound, #33): the `producer_id` is attacker-chosen, so the count of windows must be capped
    /// or a flood of distinct ids grows RAM without bound. A fresh `producer_id` over this cap
    /// evicts the least-recently-active window (an approximate LRU). Floored to 1 by
    /// [`DedupRegistry::new`] (a zero producer bound would track nothing). Default
    /// [`DEFAULT_MAX_PRODUCERS`].
    pub max_producers: usize,
}

impl Default for DedupConfig {
    /// The spec defaults: [`DEFAULT_MAX_IDS`] ids OR [`DEFAULT_WINDOW_NANOS`] (2 min),
    /// whichever is hit first, across at most [`DEFAULT_MAX_PRODUCERS`] distinct producers.
    fn default() -> DedupConfig {
        DedupConfig {
            max_ids: DEFAULT_MAX_IDS,
            window_nanos: DEFAULT_WINDOW_NANOS,
            max_producers: DEFAULT_MAX_PRODUCERS,
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
    /// The monotonic instant this window was last touched (checked or recorded), the LRU recency
    /// key for the [`DedupConfig::max_producers`] cap: when a fresh `producer_id` would exceed the
    /// cap, the window with the smallest `last_touch` is evicted. Updated on every `check`/`record`
    /// for the producer, so an actively-used window is never the eviction victim while idle ones
    /// exist.
    last_touch: u64,
}

impl ProducerWindow {
    fn new(epoch: u64, now: u64) -> ProducerWindow {
        ProducerWindow {
            epoch,
            order: VecDeque::new(),
            index: HashMap::new(),
            last_touch: now,
        }
    }

    /// Whether the window holds no live entries (fully empty or fully time-expired), so it pins no
    /// dedup state and can be reaped without losing any protection.
    fn is_empty(&self) -> bool {
        self.index.is_empty()
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
/// caller supplies monotonic `now`). The number of distinct live producer windows is HARD-bounded
/// by [`DedupConfig::max_producers`] with LRU eviction (a flood of attacker-chosen `producer_id`s
/// cannot grow it without bound); each window is bounded by [`DedupConfig::max_ids`] and the time
/// bound, so the TOTAL memory is `max_producers * max_ids * per_entry`.
#[derive(Debug)]
pub struct DedupRegistry {
    config: DedupConfig,
    producers: HashMap<Vec<u8>, ProducerWindow>,
    /// The LRU recency index for the [`DedupConfig::max_producers`] cap: a MIN-heap (via
    /// [`Reverse`]) over `(last_touch, producer_id)`, so the smallest `last_touch` is at the top.
    /// Picking the eviction victim is then O(log P) instead of an O(P) scan over every window on
    /// every fresh `producer_id` (the producer-flood path the cap defends, #478).
    ///
    /// Recency is LAZILY invalidated: a window's `last_touch` is mutated in place on every
    /// touch (so a producer can have several stale heap entries), and a producer can be removed
    /// (evicted/reaped) while a heap entry survives. A heap entry `(touch, pid)` is the true LRU
    /// victim ONLY when `pid` is still tracked AND its current `last_touch == touch`; any entry
    /// failing that is stale and discarded on pop. Every touch and every insert pushes a fresh
    /// `(last_touch, pid)`, so the freshest entry for a live producer always reflects its real
    /// recency, and the heap size is reaped back to the live-window count whenever it grows past
    /// twice the producer count (so stale entries cannot accumulate without bound).
    lru: BinaryHeap<Reverse<(u64, Vec<u8>)>>,
}

impl DedupRegistry {
    /// Creates an empty registry with `config`. The count bound and the producer-count bound are
    /// each floored to 1 (a zero count bound would remember no id and dedup nothing; a zero
    /// producer bound would track no producer).
    #[must_use]
    pub fn new(config: DedupConfig) -> DedupRegistry {
        DedupRegistry {
            config: DedupConfig {
                max_ids: config.max_ids.max(1),
                window_nanos: config.window_nanos,
                max_producers: config.max_producers.max(1),
            },
            producers: HashMap::new(),
            lru: BinaryHeap::new(),
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

    /// Reaps every producer window that aged FULLY empty under the time bound, so an idle producer
    /// does not pin a slot against the [`DedupConfig::max_producers`] cap until the LRU forces it.
    /// A no-op when the time bound is disabled (`window_nanos == 0`, ids never age out). `now` is
    /// monotonic, so the per-window `evict_expired` never underflows. Returns nothing; it only
    /// shrinks the map.
    fn reap_empty_windows(&mut self, now: u64) {
        let window_nanos = self.config.window_nanos;
        if window_nanos == 0 {
            return;
        }
        self.producers.retain(|_, window| {
            window.evict_expired(window_nanos, now);
            !window.is_empty()
        });
    }

    /// Ensures there is room for ONE MORE producer window before inserting `producer_id`, enforcing
    /// the [`DedupConfig::max_producers`] TOTAL-memory cap (#33). If `producer_id` is already
    /// tracked, this is a no-op (a re-touch never needs a slot). Otherwise, if the map is at the
    /// cap, it first reaps fully time-expired windows (free room without losing any live state),
    /// then, if still at the cap, evicts the LEAST-RECENTLY-active window (the smallest
    /// `last_touch`) so the new producer fits. Evicting a window only drops dedup state for the
    /// least-active producer, which falls back to at-least-once (already the contract), so this is
    /// safe. Pure: no IO, no panic.
    ///
    /// The victim is found via the [`DedupRegistry::lru`] min-heap in O(log P) amortized rather than
    /// an O(P) scan over every window (#478): pop the smallest `(last_touch, pid)`, skipping any
    /// STALE entry (a `pid` no longer tracked, or whose current `last_touch` has since advanced past
    /// this entry's), until a live entry surfaces — that producer is the true LRU and is removed.
    /// Each window has exactly one heap entry per distinct `last_touch` it ever held, so the total
    /// pops across a flood are bounded by the touches that produced them; eviction is thus amortized
    /// O(log P).
    fn make_room_for(&mut self, producer_id: &[u8], now: u64) {
        if self.producers.contains_key(producer_id) {
            return;
        }
        let cap = self.config.max_producers;
        if self.producers.len() < cap {
            return;
        }
        // First try to free a slot for nothing by reaping fully time-expired (now-empty) windows.
        self.reap_empty_windows(now);
        // If reaping was not enough (or the time bound is off), evict the least-recently-active
        // window. Pop the heap until a non-stale entry surfaces: an entry is the live LRU victim
        // only when its `pid` is still tracked AND its window's current `last_touch` still equals
        // the heap entry's recorded touch (otherwise the producer was re-touched or already removed,
        // and a fresher entry for it — if any — sits deeper in the heap).
        while self.producers.len() >= cap {
            let Some(Reverse((touch, pid))) = self.lru.pop() else {
                // The heap drained without finding a victim (every entry was stale). This is
                // unreachable while `producers` is non-empty, because every live window pushed at
                // least one entry for its current `last_touch`; the loop guard guarantees a live
                // producer exists, so the break is purely defensive (no panic, no scan fallback).
                break;
            };
            if self
                .producers
                .get(&pid)
                .is_some_and(|w| w.last_touch == touch)
            {
                self.producers.remove(&pid);
            }
        }
    }

    /// Records on the LRU heap that `producer_id`'s window was touched at monotonic instant `now`,
    /// pushing a fresh `(now, producer_id)` entry so the O(log P) victim search sees the new recency.
    /// The caller sets the window's own `last_touch` field; this only maintains the heap index.
    /// Periodically rebuilds the heap of stale entries (when it grows past twice the live-window
    /// count) so lazy invalidation cannot let stale entries accumulate without bound.
    fn touch_lru(&mut self, producer_id: &[u8], now: u64) {
        self.lru.push(Reverse((now, producer_id.to_vec())));
        // Bound the heap: stale entries (superseded touches, removed producers) accumulate one per
        // touch. When the heap exceeds twice the live-window count, rebuild it from the current
        // windows so its size returns to exactly the producer count. Amortized O(1) per touch (the
        // rebuild is O(P) but only fires after Θ(P) touches have piled up).
        if self.lru.len() > self.producers.len().saturating_mul(2) {
            self.lru = self
                .producers
                .iter()
                .map(|(pid, w)| Reverse((w.last_touch, pid.clone())))
                .collect();
        }
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
        // Enforce the producer-count cap BEFORE inserting a (possibly new) window, so the registry
        // never holds more than `max_producers` windows: a flood of distinct attacker-chosen
        // `producer_id`s evicts the least-recently-active window rather than growing without bound.
        self.make_room_for(producer_id, now);
        // Ensure the window is present and touch the recency clock: this window is the
        // most-recently-active, so it is not the LRU eviction victim while idle windows exist. The
        // borrow ends here so `touch_lru` (which reads `self.producers` to bound the heap) sees the
        // window already inserted.
        self.producers
            .entry(producer_id.to_vec())
            .or_insert_with(|| ProducerWindow::new(epoch, now))
            .last_touch = now;
        // Mirror the touch onto the LRU heap, keeping the O(log P) victim search in sync.
        self.touch_lru(producer_id, now);
        // Re-borrow the now-present window for the rest of the call (the closure never runs).
        let window = self
            .producers
            .entry(producer_id.to_vec())
            .or_insert_with(|| ProducerWindow::new(epoch, now));

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
        // Enforce the producer-count cap before a (possibly new) window is inserted: `record` for a
        // never-checked producer would otherwise grow the map past the cap.
        self.make_room_for(producer_id, now);
        // Ensure the window is present and touch the recency clock; the borrow ends so `touch_lru`
        // sees the inserted window when it bounds the heap (see `check`).
        self.producers
            .entry(producer_id.to_vec())
            .or_insert_with(|| ProducerWindow::new(0, now))
            .last_touch = now;
        self.touch_lru(producer_id, now);
        let window = self
            .producers
            .entry(producer_id.to_vec())
            .or_insert_with(|| ProducerWindow::new(0, now));
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
            ..DedupConfig::default()
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
            ..DedupConfig::default()
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
            ..DedupConfig::default()
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
            ..DedupConfig::default()
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

    #[test]
    fn the_producer_count_is_floored_to_one() {
        let r = DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 0,
            max_producers: 0,
        });
        assert_eq!(r.config().max_producers, 1);
    }

    #[test]
    fn the_producer_count_is_hard_bounded_under_a_flood_of_distinct_producer_ids() {
        // The #33 memory-exhaustion regression: a peer driving MANY distinct producer_ids must NOT
        // grow the registry without bound. With the LRU producer cap the count stays <= the cap no
        // matter how many distinct ids arrive. This test FAILS on the pre-fix (unbounded) code,
        // where producer_count would equal the number of distinct ids driven.
        let max_producers = 16;
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 0, // time bound off, so only the LRU cap can bound the producer count
            max_producers,
        });
        // Drive 10x the cap of distinct producer_ids, each recording one id.
        for i in 0..(max_producers as u64 * 10) {
            let pid = format!("producer-{i}");
            assert!(matches!(
                r.check(pid.as_bytes(), 0, b"m", i),
                DedupDecision::Fresh { .. }
            ));
            r.record(pid.as_bytes(), b"m", Offset::new(i), i);
            // The registry is HARD-bounded at every step, never past the cap.
            assert!(
                r.producer_count() <= max_producers,
                "producer_count {} exceeded the cap {max_producers}",
                r.producer_count()
            );
        }
        assert_eq!(
            r.producer_count(),
            max_producers,
            "the registry holds exactly the cap of windows after the flood"
        );
    }

    #[test]
    fn an_evicted_producers_later_duplicate_is_treated_as_fresh() {
        // LRU-eviction safety: once a producer's window is evicted to honor the cap, a later repeat
        // of its id is a genuinely-FRESH produce (at-least-once fallback), NEVER a false dedup hit
        // against stale state. The earliest producer is the LRU victim under the flood.
        let max_producers = 4;
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 0,
            max_producers,
        });
        // The victim records an id at t=0, making it the least-recently-active.
        r.check(b"victim", 0, b"id", 0);
        r.record(b"victim", b"id", Offset::new(7), 0);
        assert_eq!(
            r.check(b"victim", 0, b"id", 1),
            DedupDecision::Duplicate {
                offset: Offset::new(7)
            },
            "the victim's id is a duplicate while its window is still live"
        );
        // Fill the cap with NEWER producers, each more-recently-active than the victim, forcing the
        // victim out by LRU.
        for i in 0..max_producers as u64 {
            let pid = format!("newer-{i}");
            let t = 10 + i;
            r.check(pid.as_bytes(), 0, b"x", t);
            r.record(pid.as_bytes(), b"x", Offset::new(100 + i), t);
        }
        assert_eq!(r.producer_count(), max_producers);
        // The victim's window was evicted, so its id now reads FRESH (no false dedup, at-least-once).
        assert_eq!(
            r.check(b"victim", 0, b"id", 100),
            DedupDecision::Fresh {
                out_of_window: false
            },
            "an evicted producer's id falls back to at-least-once, never a stale false dedup"
        );
    }

    #[test]
    fn an_active_producer_is_not_evicted_while_idle_ones_exist() {
        // LRU correctness: a continuously-active producer must survive the cap pressure; the IDLE
        // producers are the eviction victims, not the hot one.
        let max_producers = 4;
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 0,
            max_producers,
        });
        // "hot" records an id early, then is re-touched LAST so it is the most-recently-active.
        r.check(b"hot", 0, b"keep", 0);
        r.record(b"hot", b"keep", Offset::new(42), 0);
        // Fill the rest of the cap with idle producers (touched once, never again).
        for i in 0..(max_producers as u64 - 1) {
            let pid = format!("idle-{i}");
            let t = 1 + i;
            r.check(pid.as_bytes(), 0, b"x", t);
            r.record(pid.as_bytes(), b"x", Offset::new(200 + i), t);
        }
        assert_eq!(r.producer_count(), max_producers);
        // Re-touch hot so it is the most recently active, then drive a flood of NEW producers. Each
        // new one evicts the least-recently-active, which is always an idle producer, never hot.
        r.check(b"hot", 0, b"keep", 1_000);
        for i in 0..(max_producers as u64 * 4) {
            let pid = format!("flood-{i}");
            let t = 1_001 + i;
            r.check(pid.as_bytes(), 0, b"y", t);
            r.record(pid.as_bytes(), b"y", Offset::new(300 + i), t);
            // Re-touch hot each round so it stays the freshest and is never the victim.
            r.check(b"hot", 0, b"keep", t + 1);
        }
        // hot survived: its id is still a live duplicate at its original offset.
        assert_eq!(
            r.check(b"hot", 0, b"keep", 100_000),
            DedupDecision::Duplicate {
                offset: Offset::new(42)
            },
            "the continuously-active producer is never the LRU victim"
        );
    }

    #[test]
    fn a_re_touched_window_is_not_the_lru_victim_despite_a_stale_heap_entry() {
        // Heap lazy-invalidation correctness (#478): when a window is re-touched, its OLD
        // (smaller-last_touch) heap entry is left behind as a stale entry. The victim search MUST
        // discard that stale entry (current last_touch no longer matches it) and never evict a
        // re-touched window while a genuinely older one exists.
        let max_producers = 3;
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 0,
            max_producers,
        });
        // "early" is touched first at t=0 (leaving a stale heap entry there), then RE-touched at a
        // large t so it is actually the most-recently-active.
        r.check(b"early", 0, b"e", 0);
        r.record(b"early", b"e", Offset::new(1), 0);
        // "mid" is the genuinely least-recently-active window (touched once at t=5, never again).
        r.check(b"mid", 0, b"m", 5);
        r.record(b"mid", b"m", Offset::new(2), 5);
        // "late" fills the cap at t=10.
        r.check(b"late", 0, b"l", 10);
        r.record(b"late", b"l", Offset::new(3), 10);
        assert_eq!(r.producer_count(), max_producers);
        // Re-touch "early" at t=100: its stale (0, "early") heap entry remains, but its real
        // last_touch is now 100 — the freshest of all three.
        r.check(b"early", 0, b"e", 100);
        // A new producer forces one eviction. The victim must be "mid" (smallest live last_touch),
        // NOT "early" (whose stale heap entry has the smallest touch but is invalid).
        r.check(b"intruder", 0, b"x", 200);
        r.record(b"intruder", b"x", Offset::new(4), 200);
        assert_eq!(r.producer_count(), max_producers);
        // "early" survived (re-touched), "late" survived, "mid" was evicted.
        assert_eq!(
            r.check(b"early", 0, b"e", 300),
            DedupDecision::Duplicate {
                offset: Offset::new(1)
            },
            "the re-touched window must survive despite its stale heap entry"
        );
        assert_eq!(
            r.check(b"mid", 0, b"m", 301),
            DedupDecision::Fresh {
                out_of_window: false
            },
            "the genuinely least-recently-active window was the eviction victim"
        );
    }

    #[test]
    fn heavy_re_touching_keeps_the_lru_heap_bounded_and_eviction_correct() {
        // Heap-bound correctness (#478): re-touching the same hot producer many times piles up
        // stale heap entries. The periodic rebuild must keep the heap from growing without bound
        // AND must not corrupt the LRU victim choice. Drive thousands of re-touches of one hot
        // producer interleaved with a flood of fresh ones; the count stays capped and the hot
        // producer is never evicted.
        let max_producers = 8;
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 0,
            max_producers,
        });
        r.check(b"hot", 0, b"h", 0);
        r.record(b"hot", b"h", Offset::new(42), 0);
        for i in 0..1_000u64 {
            // Re-touch hot repeatedly (each push is a soon-to-be-stale heap entry).
            r.check(b"hot", 0, b"h", 1_000 + i * 3);
            // Flood a fresh producer that must evict some OTHER (idle) window, never hot.
            let pid = format!("flood-{i}");
            r.check(pid.as_bytes(), 0, b"y", 1_001 + i * 3);
            r.record(pid.as_bytes(), b"y", Offset::new(1_000 + i), 1_001 + i * 3);
            assert!(
                r.producer_count() <= max_producers,
                "count {} exceeded cap {max_producers}",
                r.producer_count()
            );
        }
        // hot survived every round (continuously the freshest), and the cap held throughout.
        assert_eq!(r.producer_count(), max_producers);
        assert_eq!(
            r.check(b"hot", 0, b"h", 1_000_000),
            DedupDecision::Duplicate {
                offset: Offset::new(42)
            },
            "the continuously-hot producer is never evicted despite a flood of stale heap entries"
        );
    }

    #[test]
    fn a_fully_time_expired_window_is_reaped_so_it_does_not_pin_a_slot() {
        // Empty-window reaping: an idle producer whose entries all aged out under the time bound is
        // reaped opportunistically when the cap is reached, freeing a slot WITHOUT evicting a live
        // window. Here the cap is 2: one expired idle window and one fresh window, then a third
        // producer reaps the expired one rather than evicting the fresh one.
        let mut r = DedupRegistry::new(DedupConfig {
            max_ids: 4,
            window_nanos: 1_000,
            max_producers: 2,
        });
        // p_old records at t=0; it will fully age out by t=2000.
        r.check(b"p_old", 0, b"a", 0);
        r.record(b"p_old", b"a", Offset::new(1), 0);
        // p_live records recently so it must NOT be reaped or evicted.
        r.check(b"p_live", 0, b"b", 1_900);
        r.record(b"p_live", b"b", Offset::new(2), 1_900);
        assert_eq!(r.producer_count(), 2);
        // A third producer at t=2000: p_old's only entry has aged out (>= 1000 ns old), so the
        // empty-window reap drops p_old and the new producer fits without evicting p_live.
        r.check(b"p_new", 0, b"c", 2_000);
        r.record(b"p_new", b"c", Offset::new(3), 2_000);
        assert_eq!(r.producer_count(), 2, "still at the cap");
        // p_live survived the reap (it was not expired), so its id is still a live duplicate.
        assert_eq!(
            r.check(b"p_live", 0, b"b", 2_001),
            DedupDecision::Duplicate {
                offset: Offset::new(2)
            },
            "the live window survived; only the fully-expired idle one was reaped"
        );
    }
}
