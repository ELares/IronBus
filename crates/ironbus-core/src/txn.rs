// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IO-free transactional half-message 2PC state machine (V2-M8, #640 part 1/2).
//!
//! This is the `RocketMQ` transactional-message model adapted to IronBus: a producer sends a
//! **half (prepared) message** that the broker stores durably but keeps INVISIBLE to consumers,
//! runs its local transaction, then sends **commit** (the half message becomes visible — it is
//! appended to the real target stream) or **rollback** (the half message is discarded, never
//! delivered). This module is the PURE lifecycle: `Prepared -> {Committed, RolledBack}`, with the
//! legal transitions, the idempotency rules, and the cheap "unresolved-prepared" query the part-2
//! broker back-check will scan. It holds NO payload bytes and does NO IO; the durable half-log and
//! the real-stream append live in `ironbus-storage` / `ironbus-server` above this.
//!
//! ## The lifecycle and its legal transitions
//!
//! A transaction id (producer-supplied, see [`MAX_TXN_ID_LEN`]) moves through exactly:
//!
//! ```text
//!                 commit                       (terminal)
//!   Prepared ───────────────▶ Committed
//!      │                         ▲
//!      │ rollback                │  re-commit  = NO-OP (returns the prior Committed outcome)
//!      ▼                         │  re-rollback of a Committed = REFUSED (already committed)
//!   RolledBack ◀────────────────┘
//!   (terminal)   re-rollback = NO-OP (returns the prior RolledBack outcome)
//!                commit of a RolledBack = REFUSED (already rolled back)
//! ```
//!
//! - **Idempotent resolve.** Re-committing an already-Committed txn, or re-rolling-back an
//!   already-RolledBack txn, is a NO-OP that returns the PRIOR outcome (so a retried commit over a
//!   lossy link does not error and does not double-resolve). This mirrors the
//!   [`crate::dedup`] / [`crate::producer_seq`] "a retry is a benign duplicate, never an error"
//!   discipline.
//! - **Never silently flipped.** A commit AFTER a rollback, or a rollback AFTER a commit, is
//!   REFUSED ([`TxnError::AlreadyResolved`]) — the terminal outcome is immutable. A resolved txn is
//!   never re-opened.
//! - **Prepare is idempotent too.** Re-preparing a still-Prepared id is a NO-OP (the half message
//!   is already durable); preparing an id that is already RESOLVED is REFUSED (its slot is spent).
//!
//! ## The unresolved-prepared query (part 2's back-check seam)
//!
//! Each prepared txn records the monotonic instant it was prepared (injected by the caller — this
//! module reads NO clock). [`TxnTable::unresolved_before`] returns every txn still `Prepared` whose
//! prepare instant is at or before a cutoff, in prepare order, so part 2's back-check can cheaply
//! find "prepared but unresolved for longer than T" without scanning resolved entries. Resolved
//! txns are kept only as a bounded tombstone set for idempotency (see the memory note); the
//! unresolved set is a separate, directly-indexed structure so the scan is O(unresolved), never
//! O(all-txns-ever).
//!
//! ## Memory
//!
//! The table holds one small entry per LIVE (unresolved) txn plus a bounded tombstone of recently
//! resolved txn ids (so a retried commit/rollback after the real resolve is still recognized as a
//! benign duplicate rather than read as a fresh prepare). The `txn_id` is wire-supplied and
//! attacker-chosen, so BOTH sets are hard-capped ([`TxnConfig::max_prepared`],
//! [`TxnConfig::max_resolved_tombstones`]) with the same approximate-LRU eviction the dedup/seq
//! registries use: a flood of distinct ids evicts the least-recently-touched entry rather than
//! growing without bound. Evicting a resolved tombstone only means a (very late) retry of THAT
//! commit/rollback is no longer recognized as a duplicate — the durable op-log in storage remains
//! the source of truth, so this is a safe degrade, not a correctness loss.
//!
//! ## IO and time
//!
//! PURE and IO-free, exactly like [`crate::dedup`], [`crate::producer_seq`], and
//! [`crate::lease::LeaseTable`]: the caller supplies the monotonic `now` (for the prepare instant
//! and LRU recency), and the durable half-log / op-log replay that rebuilds this table on restart
//! lives in the storage layer. The CI `ironbus-core is IO-free` gate enforces the no-IO rule.

use crate::dedup::MAX_PRODUCER_ID_LEN;
use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::collections::BinaryHeap;
use std::collections::HashMap;

/// The hard cap on a transaction id's length in bytes. The `txn_id` is producer-chosen (a UUID, a
/// snowflake, a content hash) and wire-supplied, so this bounds the per-entry key memory and lets
/// the engine reject a hostile oversized id at the boundary before it is stored. Sized identically
/// to [`MAX_PRODUCER_ID_LEN`] (256), generous for any real transaction identity.
pub const MAX_TXN_ID_LEN: usize = MAX_PRODUCER_ID_LEN;

/// The default cap on the number of concurrently-PREPARED (unresolved) transactions tracked. The
/// `txn_id` is attacker-chosen, so the count of live half messages must be bounded or a peer that
/// prepares endless distinct ids without resolving them grows broker RAM (and the durable half-log)
/// without bound. A prepare over this cap is REFUSED ([`TxnError::TooManyPrepared`]) rather than
/// silently evicting a live half message — a still-Prepared txn holds a durable, undelivered
/// payload that must NOT be dropped, so the safe action under pressure is to refuse the new prepare,
/// not to forget an existing one. Generous for any realistic in-flight transaction fan-in.
pub const DEFAULT_MAX_PREPARED: usize = 65_536;

/// The default cap on the number of recently-RESOLVED txn-id tombstones retained for idempotency.
/// A resolved tombstone lets a retried commit/rollback (arriving after the real resolve) be
/// recognized as a benign duplicate. Bounded with approximate-LRU eviction: evicting the
/// least-recently-resolved tombstone only means a (very late) retry of THAT resolve is no longer
/// deduped in memory, which the durable op-log still covers — a safe degrade.
pub const DEFAULT_MAX_RESOLVED_TOMBSTONES: usize = 65_536;

/// Tunables for a [`TxnTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxnConfig {
    /// The cap on concurrently-PREPARED (unresolved) transactions: a prepare over this cap is
    /// refused (never evicting a live, undelivered half message). Floored to 1 by [`TxnTable::new`].
    pub max_prepared: usize,
    /// The cap on recently-RESOLVED txn-id tombstones kept for idempotency: a fresh resolve over
    /// this cap evicts the least-recently-resolved tombstone (approximate LRU). Floored to 1 by
    /// [`TxnTable::new`].
    pub max_resolved_tombstones: usize,
}

impl Default for TxnConfig {
    fn default() -> TxnConfig {
        TxnConfig {
            max_prepared: DEFAULT_MAX_PREPARED,
            max_resolved_tombstones: DEFAULT_MAX_RESOLVED_TOMBSTONES,
        }
    }
}

/// The terminal outcome a resolved transaction settled on. A `Prepared` txn has no outcome yet; a
/// resolved one is exactly one of these, immutably.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnOutcome {
    /// The half message was COMMITTED: it is (to be) appended to the real target stream and becomes
    /// visible to consumers. The durable op-log carries a committed marker.
    Committed,
    /// The half message was ROLLED BACK: it is discarded and NEVER delivered. The durable op-log
    /// carries a rolled-back marker.
    RolledBack,
}

/// The current lifecycle state of a tracked transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnState {
    /// The half message is durably stored but unresolved and INVISIBLE to consumers.
    Prepared,
    /// The transaction has reached a terminal outcome (committed or rolled back), immutably.
    Resolved(TxnOutcome),
}

/// What a [`TxnTable::prepare`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareDecision {
    /// A FRESH prepare: this id was not tracked, so the caller must durably buffer the half message
    /// and write a prepared marker. The table now holds it as `Prepared`.
    Prepared,
    /// A re-prepare of a still-`Prepared` id: a benign DUPLICATE (the half message is already
    /// durable). The caller re-acks WITHOUT buffering a second copy. Idempotent prepare.
    AlreadyPrepared,
}

/// What a [`TxnTable::commit`] / [`TxnTable::rollback`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveDecision {
    /// A FRESH resolve of a `Prepared` txn to the requested outcome: the caller appends the buffered
    /// payload to the real stream (for a commit) and writes the op-marker (for both). The table now
    /// holds the txn as `Resolved(outcome)`.
    Resolved,
    /// A re-resolve of a txn ALREADY at the SAME outcome: a benign DUPLICATE (a retried
    /// commit-of-committed or rollback-of-rolledback). The caller re-acks the PRIOR outcome WITHOUT
    /// re-appending or re-marking. Idempotent resolve.
    AlreadyResolved,
}

/// A failure resolving or preparing a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnError {
    /// A commit/rollback (or re-prepare) named a txn id the table has never seen (no prepared half
    /// message, no resolved tombstone). The caller rejects it: there is nothing to resolve.
    UnknownTxn,
    /// A commit was requested for a txn already rolled back, or a rollback for one already
    /// committed: the terminal outcome is immutable, so the conflicting resolve is REFUSED, never
    /// silently flipped. Carries the prior (binding) outcome so the caller can report it.
    AlreadyResolved {
        /// The terminal outcome the txn is already bound to (which the conflicting verb contradicts).
        outcome: TxnOutcome,
    },
    /// A prepare named an id that is already RESOLVED (its slot is spent): re-using a resolved txn
    /// id for a new half message is refused, so a committed/rolled-back id can never be reopened.
    /// Carries the prior outcome.
    TxnIdSpent {
        /// The terminal outcome the spent id resolved to.
        outcome: TxnOutcome,
    },
    /// A prepare would exceed [`TxnConfig::max_prepared`] concurrently-prepared transactions. A live
    /// half message is NEVER evicted to make room (it holds an undelivered durable payload), so the
    /// new prepare is refused instead. The producer retries after some in-flight txns resolve.
    TooManyPrepared {
        /// The configured cap on concurrently-prepared transactions.
        cap: usize,
    },
    /// The supplied `txn_id` exceeds [`MAX_TXN_ID_LEN`]. Rejected at the boundary before it is stored.
    TxnIdTooLong {
        /// The rejected id length.
        len: usize,
    },
}

impl core::fmt::Display for TxnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TxnError::UnknownTxn => {
                write!(f, "unknown transaction id (nothing prepared to resolve)")
            }
            TxnError::AlreadyResolved { outcome } => {
                write!(
                    f,
                    "transaction already resolved as {outcome:?}, will not flip"
                )
            }
            TxnError::TxnIdSpent { outcome } => {
                write!(
                    f,
                    "transaction id already spent (resolved {outcome:?}), cannot re-prepare"
                )
            }
            TxnError::TooManyPrepared { cap } => {
                write!(
                    f,
                    "too many prepared transactions (cap {cap}); retry after some resolve"
                )
            }
            TxnError::TxnIdTooLong { len } => {
                write!(
                    f,
                    "transaction id length {len} exceeds the {MAX_TXN_ID_LEN}-byte cap"
                )
            }
        }
    }
}

impl std::error::Error for TxnError {}

/// One tracked transaction's lifecycle bookkeeping (NO payload — that lives in the durable
/// half-log). For a `Prepared` txn the `prepared_at` is its prepare instant (the back-check key);
/// for a resolved tombstone it is the resolve instant (the LRU recency key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TxnEntry {
    state: TxnState,
    /// The monotonic instant this entry was last (re)stamped: the PREPARE instant while `Prepared`
    /// (the [`TxnTable::unresolved_before`] scan key), the RESOLVE instant once resolved (the
    /// tombstone-LRU recency key). Caller-injected; this module reads no clock.
    instant: u64,
}

/// The pure transactional-half-message lifecycle table (V2-M8, #640 part 1): the broker-side owner
/// of every in-flight and recently-resolved transaction's STATE (not its payload). Held by the
/// engine, consulted on the txn produce/resolve path, rebuilt on restart by replaying the durable
/// half-log + op-log. Pure and IO-free; the caller supplies monotonic `now`.
///
/// Two structures keep the back-check scan cheap and the memory bounded:
/// - `prepared`: every CURRENTLY-`Prepared` txn, keyed by id, plus a prepare-ordered index so
///   [`TxnTable::unresolved_before`] is O(unresolved) and never walks resolved entries.
/// - `resolved`: a bounded LRU tombstone of recently-resolved txn ids (id -> outcome), for
///   idempotent re-resolve / spent-id detection without retaining every txn forever.
#[derive(Debug)]
pub struct TxnTable {
    config: TxnConfig,
    /// Currently-`Prepared` (unresolved) transactions: `txn_id -> TxnEntry{Prepared, prepared_at}`.
    prepared: HashMap<Vec<u8>, TxnEntry>,
    /// A prepare-ordered index over the `prepared` set: a sorted set of `(prepared_at, txn_id)` so
    /// the back-check can enumerate the oldest unresolved txns in O(result) via a range scan, without
    /// touching resolved entries. Kept in lockstep with `prepared` (entry inserted on prepare,
    /// removed on resolve), so it never holds a stale or resolved id.
    prepared_by_age: BTreeSet<(u64, Vec<u8>)>,
    /// A bounded LRU tombstone of recently-RESOLVED txn ids and their terminal outcome, for
    /// idempotent re-resolve and spent-id rejection. `txn_id -> TxnEntry{Resolved(outcome),
    /// resolved_at}`.
    resolved: HashMap<Vec<u8>, TxnEntry>,
    /// The LRU recency index for the `resolved` tombstone cap: a MIN-heap over `(resolved_at,
    /// txn_id)`, the same lazily-invalidated approximate-LRU the dedup/producer-seq registries use
    /// (a stale entry — a removed id, or one whose `instant` advanced — is discarded on pop), reaped
    /// back to the live tombstone count when it grows past twice that count.
    resolved_lru: BinaryHeap<Reverse<(u64, Vec<u8>)>>,
}

impl TxnTable {
    /// Creates an empty table with `config`. Both caps are floored to 1.
    #[must_use]
    pub fn new(config: TxnConfig) -> TxnTable {
        TxnTable {
            config: TxnConfig {
                max_prepared: config.max_prepared.max(1),
                max_resolved_tombstones: config.max_resolved_tombstones.max(1),
            },
            prepared: HashMap::new(),
            prepared_by_age: BTreeSet::new(),
            resolved: HashMap::new(),
            resolved_lru: BinaryHeap::new(),
        }
    }

    /// The active config (with the floors applied).
    #[must_use]
    pub fn config(&self) -> TxnConfig {
        self.config
    }

    /// The number of currently-`Prepared` (unresolved) transactions.
    #[must_use]
    pub fn prepared_count(&self) -> usize {
        self.prepared.len()
    }

    /// The number of recently-resolved tombstones currently retained.
    #[must_use]
    pub fn resolved_tombstone_count(&self) -> usize {
        self.resolved.len()
    }

    /// The current lifecycle state of `txn_id`, or `None` if untracked (never prepared, or its
    /// resolved tombstone was evicted under the cap). For tests, observability, and the engine's
    /// ack-shaping.
    #[must_use]
    pub fn state(&self, txn_id: &[u8]) -> Option<TxnState> {
        if let Some(e) = self.prepared.get(txn_id) {
            return Some(e.state);
        }
        self.resolved.get(txn_id).map(|e| e.state)
    }

    /// Validates the id length at the boundary, the one structural reject shared by every verb.
    fn check_id_len(txn_id: &[u8]) -> Result<(), TxnError> {
        if txn_id.len() > MAX_TXN_ID_LEN {
            return Err(TxnError::TxnIdTooLong { len: txn_id.len() });
        }
        Ok(())
    }

    /// Decides what a PREPARE (half-message produce) of `txn_id` at monotonic instant `now` should
    /// do, WITHOUT mutating the durable store (the caller buffers the half message and writes the
    /// prepared marker only on a [`PrepareDecision::Prepared`]). On a fresh prepare the table records
    /// the txn as `Prepared` at `now`.
    ///
    /// # Errors
    /// - [`TxnError::TxnIdTooLong`] if the id exceeds [`MAX_TXN_ID_LEN`].
    /// - [`TxnError::TxnIdSpent`] if the id is already RESOLVED (its slot is spent; never reopened).
    /// - [`TxnError::TooManyPrepared`] if accepting it would exceed [`TxnConfig::max_prepared`]
    ///   (a live half message is never evicted to make room — the prepare is refused instead).
    pub fn prepare(&mut self, txn_id: &[u8], now: u64) -> Result<PrepareDecision, TxnError> {
        Self::check_id_len(txn_id)?;
        // A re-prepare of a still-prepared id is a benign duplicate: the half message is already
        // durable, so the caller re-acks without buffering a second copy.
        if self.prepared.contains_key(txn_id) {
            return Ok(PrepareDecision::AlreadyPrepared);
        }
        // A prepare of an already-RESOLVED id is refused: a committed/rolled-back txn id is spent and
        // is never reopened (so a stale producer cannot resurrect a settled txn).
        if let Some(e) = self.resolved.get(txn_id) {
            if let TxnState::Resolved(outcome) = e.state {
                return Err(TxnError::TxnIdSpent { outcome });
            }
        }
        // A fresh prepare must fit under the concurrently-prepared cap. A live half message is NEVER
        // evicted to make room (it holds an undelivered durable payload), so we REFUSE rather than
        // evict — the opposite of the dedup/seq registries, which may safely evict a stale window.
        if self.prepared.len() >= self.config.max_prepared {
            return Err(TxnError::TooManyPrepared {
                cap: self.config.max_prepared,
            });
        }
        self.prepared.insert(
            txn_id.to_vec(),
            TxnEntry {
                state: TxnState::Prepared,
                instant: now,
            },
        );
        self.prepared_by_age.insert((now, txn_id.to_vec()));
        Ok(PrepareDecision::Prepared)
    }

    /// Decides what a COMMIT of `txn_id` at monotonic instant `now` should do. Shared core with
    /// [`TxnTable::rollback`] via [`TxnTable::resolve`].
    ///
    /// # Errors
    /// See [`TxnTable::resolve`].
    pub fn commit(&mut self, txn_id: &[u8], now: u64) -> Result<ResolveDecision, TxnError> {
        self.resolve(txn_id, TxnOutcome::Committed, now)
    }

    /// Decides what a ROLLBACK of `txn_id` at monotonic instant `now` should do. Shared core with
    /// [`TxnTable::commit`] via [`TxnTable::resolve`].
    ///
    /// # Errors
    /// See [`TxnTable::resolve`].
    pub fn rollback(&mut self, txn_id: &[u8], now: u64) -> Result<ResolveDecision, TxnError> {
        self.resolve(txn_id, TxnOutcome::RolledBack, now)
    }

    /// The shared resolve core: move `txn_id` to the terminal `outcome` at monotonic instant `now`,
    /// WITHOUT doing IO (the caller appends the buffered payload to the real stream for a commit and
    /// writes the op-marker only on a [`ResolveDecision::Resolved`]). On a fresh resolve the txn moves
    /// from `Prepared` to `Resolved(outcome)`: it leaves the prepared set + age index and enters the
    /// bounded resolved tombstone.
    ///
    /// # Errors
    /// - [`TxnError::TxnIdTooLong`] if the id exceeds [`MAX_TXN_ID_LEN`].
    /// - [`TxnError::UnknownTxn`] if no prepared half message and no resolved tombstone exist for the
    ///   id (nothing to resolve).
    /// - [`TxnError::AlreadyResolved`] if the txn is already resolved to the OTHER outcome (a commit
    ///   of a rolled-back txn, or vice versa): the terminal outcome is immutable, so the conflicting
    ///   verb is refused, never silently flipped.
    ///
    /// A re-resolve to the SAME outcome (a retried commit-of-committed / rollback-of-rolledback) is a
    /// benign [`ResolveDecision::AlreadyResolved`], NOT an error.
    pub fn resolve(
        &mut self,
        txn_id: &[u8],
        outcome: TxnOutcome,
        now: u64,
    ) -> Result<ResolveDecision, TxnError> {
        Self::check_id_len(txn_id)?;
        // Fast path: the txn is currently Prepared — this is the fresh, durable resolve.
        if let Some(entry) = self.prepared.get(txn_id) {
            let prepared_at = entry.instant;
            // Move out of the prepared set and its age index (kept in lockstep).
            self.prepared.remove(txn_id);
            self.prepared_by_age.remove(&(prepared_at, txn_id.to_vec()));
            self.insert_resolved_tombstone(txn_id, outcome, now);
            return Ok(ResolveDecision::Resolved);
        }
        // The txn is not prepared: it is either a resolved tombstone (idempotent re-resolve or a
        // conflicting flip) or genuinely unknown.
        match self.resolved.get(txn_id).map(|e| e.state) {
            Some(TxnState::Resolved(prior)) => {
                if prior == outcome {
                    // A retried commit-of-committed / rollback-of-rolledback: benign duplicate,
                    // returns the prior outcome, no IO. We deliberately do NOT bump the tombstone's
                    // LRU recency here: a resolved txn's tombstone ages out by its RESOLVE time, not
                    // by how often a late retry pokes it, matching the durable op-log's view.
                    Ok(ResolveDecision::AlreadyResolved)
                } else {
                    // A commit after rollback, or rollback after commit: refused, never flipped.
                    Err(TxnError::AlreadyResolved { outcome: prior })
                }
            }
            // No resolved tombstone either. (A resolved entry is always `Resolved(_)`, so the
            // `Some(Prepared)` case is unreachable; it folds in here, all reading as unknown.)
            Some(TxnState::Prepared) | None => Err(TxnError::UnknownTxn),
        }
    }

    /// Inserts a resolved tombstone for `txn_id -> outcome` at `now`, enforcing the
    /// [`TxnConfig::max_resolved_tombstones`] cap with approximate-LRU eviction (the same lazily
    /// invalidated min-heap the dedup/producer-seq registries use). Evicting a tombstone only drops
    /// the in-memory idempotency hint for a very-late retry of THAT resolve (the durable op-log still
    /// covers it), so eviction is safe.
    fn insert_resolved_tombstone(&mut self, txn_id: &[u8], outcome: TxnOutcome, now: u64) {
        // Make room for one more tombstone if the id is new and we are at the cap.
        if !self.resolved.contains_key(txn_id)
            && self.resolved.len() >= self.config.max_resolved_tombstones
        {
            while self.resolved.len() >= self.config.max_resolved_tombstones {
                let Some(Reverse((touch, id))) = self.resolved_lru.pop() else {
                    // Unreachable while `resolved` is non-empty (every tombstone pushed an LRU entry);
                    // purely defensive (no panic, no scan fallback).
                    break;
                };
                if self.resolved.get(&id).is_some_and(|e| e.instant == touch) {
                    self.resolved.remove(&id);
                }
            }
        }
        self.resolved.insert(
            txn_id.to_vec(),
            TxnEntry {
                state: TxnState::Resolved(outcome),
                instant: now,
            },
        );
        self.touch_resolved_lru(txn_id, now);
    }

    /// Records on the resolved-LRU heap that `txn_id`'s tombstone was (re)stamped at `now`, and
    /// periodically rebuilds the heap (when it grows past twice the live tombstone count) so lazily
    /// invalidated stale entries cannot accumulate without bound — amortized O(1) per resolve.
    fn touch_resolved_lru(&mut self, txn_id: &[u8], now: u64) {
        self.resolved_lru.push(Reverse((now, txn_id.to_vec())));
        if self.resolved_lru.len() > self.resolved.len().saturating_mul(2) {
            self.resolved_lru = self
                .resolved
                .iter()
                .map(|(id, e)| Reverse((e.instant, id.clone())))
                .collect();
        }
    }

    /// Every currently-`Prepared` (unresolved) txn whose prepare instant is at or before `cutoff`, in
    /// ascending `(prepared_at, txn_id)` order — the part-2 broker back-check seam (#640 part 2 will
    /// scan "prepared but unresolved for longer than T" by passing `cutoff = now - T`). O(result) via
    /// the prepare-ordered index, never a walk over resolved entries. Each item is
    /// `(txn_id, prepared_at)`.
    #[must_use]
    pub fn unresolved_before(&self, cutoff: u64) -> Vec<(Vec<u8>, u64)> {
        // The index is keyed `(prepared_at, txn_id)`; a range up to `(cutoff, max-id)` inclusive
        // selects exactly the txns prepared at or before `cutoff`. `u64::MAX`-bounded by the
        // half-open upper key `(cutoff + 1, [])`, guarding `cutoff == u64::MAX`.
        match cutoff.checked_add(1) {
            Some(next) => self
                .prepared_by_age
                .range(..(next, Vec::new()))
                .map(|(at, id)| (id.clone(), *at))
                .collect(),
            None => self
                .prepared_by_age
                .iter()
                .map(|(at, id)| (id.clone(), *at))
                .collect(),
        }
    }

    /// Every currently-`Prepared` txn id, in ascending `(prepared_at, txn_id)` order, for a durable
    /// snapshot or a full back-check sweep. Equivalent to [`TxnTable::unresolved_before`] with no
    /// cutoff.
    #[must_use]
    pub fn all_prepared(&self) -> Vec<(Vec<u8>, u64)> {
        self.prepared_by_age
            .iter()
            .map(|(at, id)| (id.clone(), *at))
            .collect()
    }

    /// Restores one txn's state from a durable replay (the storage layer's half-log + op-log replay
    /// at open). A `Prepared` restore re-enters the unresolved set + age index at `instant`; a
    /// `Resolved` restore re-enters the tombstone at `instant`. A restore is trusted recovered state:
    /// it never errors, never refuses, and (for a `Prepared` restore) is NOT subject to the
    /// `max_prepared` cap — the durable log is authoritative, so recovery rebuilds exactly what was
    /// durable. A later `Resolved` restore for an id first seen `Prepared` (the op-log replayed after
    /// the half-log) correctly supersedes it (the prepared entry is cleared first).
    pub fn restore(&mut self, txn_id: &[u8], state: TxnState, instant: u64) {
        // If this id is currently held Prepared (from an earlier half-log replay) and we are now
        // restoring a resolution, clear the prepared entry + age index first so the two sets stay
        // disjoint and the txn ends up only in the tombstone.
        if let Some(prev) = self.prepared.remove(txn_id) {
            self.prepared_by_age
                .remove(&(prev.instant, txn_id.to_vec()));
        }
        match state {
            TxnState::Prepared => {
                self.prepared.insert(
                    txn_id.to_vec(),
                    TxnEntry {
                        state: TxnState::Prepared,
                        instant,
                    },
                );
                self.prepared_by_age.insert((instant, txn_id.to_vec()));
            }
            TxnState::Resolved(outcome) => {
                // A resolved restore supersedes any prepared restore for the same id and is NOT
                // bounded by the tombstone cap (recovery rebuilds the durable truth); the cap applies
                // only to live resolves. Insert directly and seed the LRU.
                self.resolved.insert(
                    txn_id.to_vec(),
                    TxnEntry {
                        state: TxnState::Resolved(outcome),
                        instant,
                    },
                );
                self.touch_resolved_lru(txn_id, instant);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> TxnTable {
        TxnTable::new(TxnConfig::default())
    }

    #[test]
    fn a_fresh_prepare_then_commit_round_trips() {
        let mut t = table();
        assert_eq!(t.prepare(b"tx1", 10), Ok(PrepareDecision::Prepared));
        assert_eq!(t.state(b"tx1"), Some(TxnState::Prepared));
        assert_eq!(t.prepared_count(), 1);
        assert_eq!(t.commit(b"tx1", 20), Ok(ResolveDecision::Resolved));
        assert_eq!(
            t.state(b"tx1"),
            Some(TxnState::Resolved(TxnOutcome::Committed))
        );
        // It left the prepared set, entered the tombstone.
        assert_eq!(t.prepared_count(), 0);
        assert_eq!(t.resolved_tombstone_count(), 1);
    }

    #[test]
    fn a_fresh_prepare_then_rollback_round_trips() {
        let mut t = table();
        assert_eq!(t.prepare(b"tx1", 10), Ok(PrepareDecision::Prepared));
        assert_eq!(t.rollback(b"tx1", 20), Ok(ResolveDecision::Resolved));
        assert_eq!(
            t.state(b"tx1"),
            Some(TxnState::Resolved(TxnOutcome::RolledBack))
        );
        assert_eq!(t.prepared_count(), 0);
    }

    #[test]
    fn re_preparing_a_still_prepared_id_is_a_benign_duplicate() {
        let mut t = table();
        assert_eq!(t.prepare(b"tx1", 10), Ok(PrepareDecision::Prepared));
        // A retried prepare of the same id: duplicate, NOT a second half message.
        assert_eq!(t.prepare(b"tx1", 11), Ok(PrepareDecision::AlreadyPrepared));
        assert_eq!(t.prepared_count(), 1, "no second prepared entry");
    }

    #[test]
    fn re_committing_a_committed_txn_is_a_benign_duplicate_not_an_error() {
        let mut t = table();
        t.prepare(b"tx1", 10).unwrap();
        assert_eq!(t.commit(b"tx1", 20), Ok(ResolveDecision::Resolved));
        // The headline idempotency rule: a retried commit returns AlreadyResolved, never an error,
        // and never re-appends.
        assert_eq!(t.commit(b"tx1", 21), Ok(ResolveDecision::AlreadyResolved));
        assert_eq!(t.commit(b"tx1", 22), Ok(ResolveDecision::AlreadyResolved));
    }

    #[test]
    fn re_rolling_back_a_rolledback_txn_is_a_benign_duplicate() {
        let mut t = table();
        t.prepare(b"tx1", 10).unwrap();
        assert_eq!(t.rollback(b"tx1", 20), Ok(ResolveDecision::Resolved));
        assert_eq!(t.rollback(b"tx1", 21), Ok(ResolveDecision::AlreadyResolved));
    }

    #[test]
    fn commit_after_rollback_is_refused_not_flipped() {
        let mut t = table();
        t.prepare(b"tx1", 10).unwrap();
        t.rollback(b"tx1", 20).unwrap();
        // The load-bearing safety rule: a commit of a rolled-back txn is REFUSED, the outcome is not
        // silently flipped.
        assert_eq!(
            t.commit(b"tx1", 30),
            Err(TxnError::AlreadyResolved {
                outcome: TxnOutcome::RolledBack
            })
        );
        // And the txn stays rolled back.
        assert_eq!(
            t.state(b"tx1"),
            Some(TxnState::Resolved(TxnOutcome::RolledBack))
        );
    }

    #[test]
    fn rollback_after_commit_is_refused_not_flipped() {
        let mut t = table();
        t.prepare(b"tx1", 10).unwrap();
        t.commit(b"tx1", 20).unwrap();
        assert_eq!(
            t.rollback(b"tx1", 30),
            Err(TxnError::AlreadyResolved {
                outcome: TxnOutcome::Committed
            })
        );
        assert_eq!(
            t.state(b"tx1"),
            Some(TxnState::Resolved(TxnOutcome::Committed))
        );
    }

    #[test]
    fn committing_or_rolling_back_an_unknown_txn_is_rejected() {
        let mut t = table();
        assert_eq!(t.commit(b"ghost", 10), Err(TxnError::UnknownTxn));
        assert_eq!(t.rollback(b"ghost", 10), Err(TxnError::UnknownTxn));
    }

    #[test]
    fn re_preparing_a_resolved_id_is_refused_as_spent() {
        let mut t = table();
        t.prepare(b"tx1", 10).unwrap();
        t.commit(b"tx1", 20).unwrap();
        // The id's slot is spent: re-using it for a new half message is refused (no resurrection).
        assert_eq!(
            t.prepare(b"tx1", 30),
            Err(TxnError::TxnIdSpent {
                outcome: TxnOutcome::Committed
            })
        );
    }

    #[test]
    fn an_oversized_txn_id_is_rejected_at_the_boundary() {
        let mut t = table();
        let too_long = vec![b'x'; MAX_TXN_ID_LEN + 1];
        assert_eq!(
            t.prepare(&too_long, 10),
            Err(TxnError::TxnIdTooLong {
                len: MAX_TXN_ID_LEN + 1
            })
        );
        assert_eq!(
            t.commit(&too_long, 10),
            Err(TxnError::TxnIdTooLong {
                len: MAX_TXN_ID_LEN + 1
            })
        );
        // Exactly at the cap is accepted.
        let at_cap = vec![b'x'; MAX_TXN_ID_LEN];
        assert_eq!(t.prepare(&at_cap, 10), Ok(PrepareDecision::Prepared));
    }

    #[test]
    fn distinct_txns_are_independent() {
        let mut t = table();
        t.prepare(b"a", 10).unwrap();
        t.prepare(b"b", 11).unwrap();
        t.commit(b"a", 20).unwrap();
        // Resolving a never touches b.
        assert_eq!(
            t.state(b"a"),
            Some(TxnState::Resolved(TxnOutcome::Committed))
        );
        assert_eq!(t.state(b"b"), Some(TxnState::Prepared));
        assert_eq!(t.prepared_count(), 1);
    }

    #[test]
    fn unresolved_before_returns_only_old_prepared_txns_in_age_order() {
        let mut t = table();
        t.prepare(b"old1", 10).unwrap();
        t.prepare(b"old2", 20).unwrap();
        t.prepare(b"new1", 100).unwrap();
        // Resolve one so it must NOT appear in the unresolved scan.
        t.commit(b"old2", 25).unwrap();
        // Everything prepared at or before 50: old1 (10) only (old2 resolved, new1 too new).
        let stale = t.unresolved_before(50);
        assert_eq!(stale, vec![(b"old1".to_vec(), 10)]);
        // At or before 100 picks up new1 too, in age order.
        let all = t.unresolved_before(100);
        assert_eq!(all, vec![(b"old1".to_vec(), 10), (b"new1".to_vec(), 100)]);
        // all_prepared agrees with no cutoff.
        assert_eq!(t.all_prepared(), all);
    }

    #[test]
    fn unresolved_before_handles_the_u64_max_cutoff() {
        let mut t = table();
        t.prepare(b"a", u64::MAX).unwrap();
        // A cutoff of u64::MAX must include a txn prepared at u64::MAX (no overflow).
        assert_eq!(
            t.unresolved_before(u64::MAX),
            vec![(b"a".to_vec(), u64::MAX)]
        );
    }

    #[test]
    fn the_prepared_set_is_hard_capped_and_refuses_rather_than_evicts() {
        // A live half message is never evicted: a prepare over the cap is refused, so an
        // undelivered durable payload is never silently dropped.
        let cap = 4;
        let mut t = TxnTable::new(TxnConfig {
            max_prepared: cap,
            ..TxnConfig::default()
        });
        for i in 0..cap as u64 {
            let id = format!("tx-{i}");
            assert_eq!(t.prepare(id.as_bytes(), i), Ok(PrepareDecision::Prepared));
        }
        assert_eq!(t.prepared_count(), cap);
        // The next prepare is refused (NOT an eviction of an existing half message).
        assert_eq!(
            t.prepare(b"overflow", 100),
            Err(TxnError::TooManyPrepared { cap })
        );
        // Every original half message survives.
        assert_eq!(t.prepared_count(), cap);
        // Resolving one frees a slot, so a subsequent prepare fits.
        t.commit(b"tx-0", 200).unwrap();
        assert_eq!(t.prepare(b"overflow", 201), Ok(PrepareDecision::Prepared));
    }

    #[test]
    fn the_resolved_tombstone_set_is_lru_bounded_under_a_flood() {
        // The resolved tombstones are bounded: a flood of resolved txns evicts the oldest tombstone,
        // never growing without bound. (Eviction only loses the in-memory idempotency hint for a
        // very-late retry; the durable op-log still covers it.)
        let max = 8;
        let mut t = TxnTable::new(TxnConfig {
            max_prepared: 1_000,
            max_resolved_tombstones: max,
        });
        for i in 0..(max as u64 * 10) {
            let id = format!("tx-{i}");
            t.prepare(id.as_bytes(), i).unwrap();
            t.commit(id.as_bytes(), i + 1).unwrap();
            assert!(
                t.resolved_tombstone_count() <= max,
                "tombstone count exceeded the cap"
            );
        }
        assert_eq!(t.resolved_tombstone_count(), max);
        // The prepared set is empty (all resolved).
        assert_eq!(t.prepared_count(), 0);
    }

    #[test]
    fn an_evicted_tombstone_makes_a_late_retry_read_as_unknown_not_a_false_resolve() {
        let max = 2;
        let mut t = TxnTable::new(TxnConfig {
            max_prepared: 1_000,
            max_resolved_tombstones: max,
        });
        // Resolve the victim first (oldest tombstone).
        t.prepare(b"victim", 0).unwrap();
        t.commit(b"victim", 1).unwrap();
        // Flood newer resolved txns, each more recent, forcing the victim's tombstone out.
        for i in 0..max as u64 {
            let id = format!("new-{i}");
            t.prepare(id.as_bytes(), 10 + i).unwrap();
            t.commit(id.as_bytes(), 11 + i).unwrap();
        }
        assert_eq!(t.resolved_tombstone_count(), max);
        // The victim's tombstone is gone, so its state is now unknown (a late commit retry reads as
        // UnknownTxn — a safe at-least-once degrade the durable op-log covers, never a false flip).
        assert_eq!(t.state(b"victim"), None);
        assert_eq!(t.commit(b"victim", 100), Err(TxnError::UnknownTxn));
    }

    #[test]
    fn restore_rebuilds_prepared_and_resolved_state() {
        let mut t = table();
        // Replay a half-log: two prepared txns.
        t.restore(b"p1", TxnState::Prepared, 10);
        t.restore(b"p2", TxnState::Prepared, 20);
        // Replay the op-log: p1 committed (supersedes its prepared restore).
        t.restore(b"p1", TxnState::Resolved(TxnOutcome::Committed), 30);
        // p1 is now resolved (left the prepared set), p2 stays prepared.
        assert_eq!(
            t.state(b"p1"),
            Some(TxnState::Resolved(TxnOutcome::Committed))
        );
        assert_eq!(t.state(b"p2"), Some(TxnState::Prepared));
        assert_eq!(t.prepared_count(), 1);
        // The back-check sees only the still-prepared p2.
        assert_eq!(t.unresolved_before(u64::MAX), vec![(b"p2".to_vec(), 20)]);
        // A retried commit of the restored-committed p1 is a benign duplicate (cross-restart idem).
        assert_eq!(t.commit(b"p1", 40), Ok(ResolveDecision::AlreadyResolved));
        // p2 can still be freshly resolved.
        assert_eq!(t.rollback(b"p2", 50), Ok(ResolveDecision::Resolved));
    }

    #[test]
    fn restore_then_resolve_a_prepared_txn_is_a_fresh_resolve() {
        // The crash-after-prepare case: only the half-log replayed (no op-marker), so the txn comes
        // back Prepared and a later commit is a FRESH resolve (not a duplicate).
        let mut t = table();
        t.restore(b"tx1", TxnState::Prepared, 10);
        assert_eq!(t.state(b"tx1"), Some(TxnState::Prepared));
        assert_eq!(t.commit(b"tx1", 20), Ok(ResolveDecision::Resolved));
    }

    #[test]
    fn the_caps_are_floored_to_one() {
        let t = TxnTable::new(TxnConfig {
            max_prepared: 0,
            max_resolved_tombstones: 0,
        });
        assert_eq!(t.config().max_prepared, 1);
        assert_eq!(t.config().max_resolved_tombstones, 1);
    }

    #[test]
    fn heavy_resolve_keeps_the_lru_heap_bounded() {
        // Many resolves pile up LRU entries; the periodic rebuild keeps the heap from growing without
        // bound and keeps eviction correct (the count stays capped throughout).
        let max = 8;
        let mut t = TxnTable::new(TxnConfig {
            max_prepared: 1_000,
            max_resolved_tombstones: max,
        });
        for i in 0..2_000u64 {
            let id = format!("tx-{i}");
            t.prepare(id.as_bytes(), i * 2).unwrap();
            t.commit(id.as_bytes(), i * 2 + 1).unwrap();
            assert!(t.resolved_tombstone_count() <= max);
        }
        assert_eq!(t.resolved_tombstone_count(), max);
    }
}
