// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Kafka-style idempotent producer: a `(producer_id, epoch, monotonic sequence)` that
//! deduplicates a RETRIED publish to exactly-once-append and survives a producer restart, a
//! broker restart, AND a long offline gap (V2-M8, #638/#639; KIP-98).
//!
//! ## Why this is distinct from the [`crate::dedup`] window
//!
//! The existing [`crate::dedup`] window is keyed on a producer-chosen `msg_id` and bounded by a
//! count AND a monotonic TIME window: an id republished after the window aged out reads FRESH and
//! is appended again (the documented, at-least-once fallback for an aged id). That is exactly the
//! NATS `Nats-Msg-Id` model — a time-bounded ring that silently lapses on a long gap. It is the
//! right primitive for content-keyed dedup, but it is NOT effectively-once across a long gap.
//!
//! This module is the EFFECTIVELY-ONCE primitive: a producer establishes a `(producer_id, epoch)`
//! identity and stamps each publish with a per-producer MONOTONIC `sequence`. The broker tracks
//! ONLY the LAST-ACCEPTED `(epoch, sequence, offset)` per producer — O(1) state per producer, NOT
//! O(messages) and NOT time-bounded — so dedup never lapses with the clock:
//!
//! - `seq == last_accepted + 1` is the next expected publish: FRESH, append it, advance the
//!   high-water.
//! - `seq <= last_accepted` is a RETRY of an already-accepted publish: a DUPLICATE; return the
//!   ORIGINAL offset (the last-accepted offset when `seq == last_accepted`, else a benign
//!   "already past" duplicate) and append NOTHING. A retry is deduped to exactly-once-append.
//! - `seq > last_accepted + 1` is an OUT-OF-ORDER / GAP sequence — a silent reorder that, if
//!   accepted, would corrupt the idempotence guarantee (a later retry of the skipped seq would
//!   read FRESH). It is REJECTED with [`SeqDecision::OutOfOrder`] (the Kafka `OutOfOrderSequence`
//!   semantics), never silently accepted.
//!
//! ## Epoch fencing (zombie producers)
//!
//! Each producer carries a monotonic `epoch` established at registration. A HIGHER epoch FENCES an
//! older one: a restarted producer comes back with `epoch + 1`, which RESETS the sequence
//! high-water (the new session's sequence space starts fresh from the broker's view) and
//! SUPERSEDES the old session. A produce that presents a STALE epoch (below the broker's known
//! high-water) is a ZOMBIE — an old session that lost its lease but kept writing — and is FENCED
//! ([`SeqDecision::Fenced`]), so a zombie can never double-write behind a restarted producer.
//!
//! ## Durability (the beat over NATS)
//!
//! The per-producer `(epoch, last_seq, last_offset)` high-water is SMALL and BOUNDED (one triple
//! per active producer), so the whole table snapshots into a CRC-protected checkpoint via
//! [`encode_seq_snapshot`] / [`decode_seq_snapshot`] (the same dual-slot, regress-never-corrupt
//! discipline the cursor and attempt-count checkpoints use). On a broker restart the table is
//! REBUILT from the checkpoint, so a replayed retry across the restart is STILL deduped — and
//! because the bound is sequence state, not wall-clock, a LONG offline gap never drops it. That is
//! precisely where NATS's time-bounded `Nats-Msg-Id` window forgets and re-appends.
//!
//! ## Memory
//!
//! The table is O(active producers): one fixed-size triple per `producer_id`, with the
//! `producer_id` itself bounded by [`crate::dedup::MAX_PRODUCER_ID_LEN`]. The `producer_id` is
//! wire-supplied and attacker-chosen, so the NUMBER of tracked producers is HARD-capped at
//! [`SeqConfig::max_producers`] with approximate-LRU eviction (the same O(log P) last-touch
//! min-heap with lazy invalidation the dedup registry uses, #478): a flood of distinct ids evicts
//! the least-recently-active producer rather than growing without bound. Evicting a producer only
//! drops its high-water, which then falls back to at-least-once for that producer (a later publish
//! reads FRESH) — the same safe fallback an evicted dedup window has. A long-dead producer is
//! thereby RECLAIMED under cap pressure; nothing pins a slot forever.
//!
//! ## IO and time
//!
//! This module is PURE and IO-free, like [`crate::dedup`] and [`crate::lease::LeaseTable`]: the
//! caller supplies a monotonic `now` (for the LRU recency only — the dedup decision itself is
//! wall-clock-INDEPENDENT, the whole point) and persists the snapshot in the storage/server layer.

use crate::types::Offset;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::HashMap;

/// The default cap on the NUMBER of distinct idempotent producers tracked at once. The
/// `producer_id` is attacker-chosen, so the count of tracked high-waters must be bounded or a peer
/// sending endless distinct ids grows broker RAM without bound. A fresh `producer_id` over this cap
/// evicts the least-recently-active producer (an approximate LRU). Sized to mirror
/// [`crate::dedup::DEFAULT_MAX_PRODUCERS`]: a realistic fan-in of idempotent producers all keep
/// their high-water, while a flood is hard-bounded.
pub const DEFAULT_MAX_SEQ_PRODUCERS: usize = 4096;

/// Tunables for a [`ProducerSeqRegistry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqConfig {
    /// The cap on the NUMBER of distinct producer high-waters tracked at once (the total-memory
    /// bound): the `producer_id` is attacker-chosen, so the count must be capped or a flood of
    /// distinct ids grows RAM without bound. A fresh `producer_id` over this cap evicts the
    /// least-recently-active producer (an approximate LRU). Floored to 1 by [`ProducerSeqRegistry::new`].
    pub max_producers: usize,
}

impl Default for SeqConfig {
    fn default() -> SeqConfig {
        SeqConfig {
            max_producers: DEFAULT_MAX_SEQ_PRODUCERS,
        }
    }
}

/// One durable producer high-water entry: `(producer_id, epoch, last_seq, last_offset)`. The unit of
/// the [`encode_seq_snapshot`] / [`decode_seq_snapshot`] codec and [`ProducerSeqRegistry::snapshot_pairs`].
pub type SeqHighWater = (Vec<u8>, u64, u64, Offset);

/// The outcome of a [`ProducerSeqRegistry::check`]: what a sequenced produce should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqDecision {
    /// The next expected sequence (`seq == last_accepted + 1`, or the first sequence for a new
    /// producer/epoch): a FRESH produce. The caller appends the record, then calls
    /// [`ProducerSeqRegistry::record`] with the assigned offset once it is durable.
    Fresh,
    /// A RETRY of an already-accepted publish (`seq <= last_accepted`): a DUPLICATE. The caller
    /// returns `offset` (the original durable offset when `seq == last_accepted`, the high-water's
    /// offset otherwise) with `duplicate = true` and a SUCCESS status, NEVER an error — so an
    /// idempotent retry over a lossy edge link does not loop — and appends NOTHING.
    Duplicate {
        /// The durable offset to return for this benign retry (the producer's last-accepted offset).
        offset: Offset,
    },
    /// An OUT-OF-ORDER / GAP sequence (`seq > last_accepted + 1`): the producer skipped one or more
    /// sequences. Accepting it would corrupt idempotence (a later retry of a skipped seq would read
    /// FRESH and double-append), so it is REJECTED — the Kafka `OutOfOrderSequence` semantics. The
    /// caller rejects the produce and appends nothing.
    OutOfOrder {
        /// The sequence the broker expected next (`last_accepted + 1`), so the producer can resync.
        expected: u64,
    },
    /// The produce presented a STALE epoch (below the producer's known high-water): a ZOMBIE session
    /// reusing an old `producer_id`. The caller REJECTS the produce (it is fenced), appending nothing.
    Fenced {
        /// The producer's current (newer) known epoch that fenced this produce.
        current_epoch: u64,
    },
}

/// One producer's idempotence high-water: the last-accepted `(epoch, sequence, offset)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProducerSeq {
    /// The producer's known epoch high-water. A produce below this is fenced; a produce above it
    /// resets the sequence space and advances this.
    epoch: u64,
    /// The last sequence ACCEPTED (appended) for this `(producer, epoch)`. `None` means the
    /// producer/epoch is known but no publish has yet been accepted, so the FIRST sequence is fresh.
    last_seq: Option<u64>,
    /// The durable offset the last-accepted sequence was appended at. Returned for a benign retry
    /// of that sequence. Meaningless while `last_seq` is `None`.
    last_offset: Offset,
    /// The monotonic instant this producer was last touched, the LRU recency key for the
    /// [`SeqConfig::max_producers`] cap (the same approximate-LRU the dedup registry uses).
    last_touch: u64,
}

/// The per-producer idempotence registry: the broker-side owner of every active producer's
/// `(epoch, last_seq, last_offset)` high-water (V2-M8). Held by the engine and consulted on the
/// produce path; pure and IO-free. The number of distinct producers is HARD-bounded by
/// [`SeqConfig::max_producers`] with LRU eviction, and each producer holds ONE fixed-size triple,
/// so the total memory is O(producers), NOT O(messages) and NOT time-bounded.
#[derive(Debug)]
pub struct ProducerSeqRegistry {
    config: SeqConfig,
    producers: HashMap<Vec<u8>, ProducerSeq>,
    /// The LRU recency index for the [`SeqConfig::max_producers`] cap: a MIN-heap over
    /// `(last_touch, producer_id)`, so the least-recently-active producer is at the top. Lazily
    /// invalidated exactly as [`crate::dedup::DedupRegistry`]'s heap (a stale entry — a removed
    /// producer, or one whose `last_touch` has since advanced — is discarded on pop), and reaped
    /// back to the live-producer count when it grows past twice that count, so stale entries cannot
    /// accumulate without bound and the victim search stays O(log P) amortized (#478).
    lru: BinaryHeap<Reverse<(u64, Vec<u8>)>>,
}

impl ProducerSeqRegistry {
    /// Creates an empty registry with `config`. The producer-count bound is floored to 1.
    #[must_use]
    pub fn new(config: SeqConfig) -> ProducerSeqRegistry {
        ProducerSeqRegistry {
            config: SeqConfig {
                max_producers: config.max_producers.max(1),
            },
            producers: HashMap::new(),
            lru: BinaryHeap::new(),
        }
    }

    /// The active config (with the count floor applied).
    #[must_use]
    pub fn config(&self) -> SeqConfig {
        self.config
    }

    /// The number of tracked producers (for tests and introspection).
    #[must_use]
    pub fn producer_count(&self) -> usize {
        self.producers.len()
    }

    /// The last-accepted `(epoch, last_seq, last_offset)` for `producer_id`, or `None` if untracked.
    /// `last_seq` is `None` when the producer/epoch is known but no publish has been accepted yet.
    /// Used by the durable-snapshot builder to enumerate the high-waters.
    #[must_use]
    pub fn high_water(&self, producer_id: &[u8]) -> Option<(u64, Option<u64>, Offset)> {
        self.producers
            .get(producer_id)
            .map(|p| (p.epoch, p.last_seq, p.last_offset))
    }

    /// Ensures there is room for ONE MORE producer before inserting `producer_id`, enforcing the
    /// [`SeqConfig::max_producers`] cap. A no-op if `producer_id` is already tracked. Otherwise, if
    /// at the cap, evicts the least-recently-active producer via the O(log P) min-heap (skipping
    /// stale entries) so the new producer fits. Evicting a producer only drops its high-water, which
    /// then falls back to at-least-once (a later publish reads fresh) — the same safe fallback the
    /// dedup registry's eviction has. Pure: no IO, no panic.
    fn make_room_for(&mut self, producer_id: &[u8]) {
        if self.producers.contains_key(producer_id) {
            return;
        }
        let cap = self.config.max_producers;
        if self.producers.len() < cap {
            return;
        }
        while self.producers.len() >= cap {
            let Some(Reverse((touch, pid))) = self.lru.pop() else {
                // Unreachable while `producers` is non-empty (every live producer pushed an entry
                // for its current `last_touch`); purely defensive (no panic, no scan fallback).
                break;
            };
            if self
                .producers
                .get(&pid)
                .is_some_and(|p| p.last_touch == touch)
            {
                self.producers.remove(&pid);
            }
        }
    }

    /// Records on the LRU heap that `producer_id` was touched at monotonic instant `now`, pushing a
    /// fresh `(now, producer_id)` entry so the victim search sees the new recency. Periodically
    /// rebuilds the heap (when it grows past twice the live-producer count) so lazily-invalidated
    /// stale entries cannot accumulate without bound — amortized O(1) per touch.
    fn touch_lru(&mut self, producer_id: &[u8], now: u64) {
        self.lru.push(Reverse((now, producer_id.to_vec())));
        if self.lru.len() > self.producers.len().saturating_mul(2) {
            self.lru = self
                .producers
                .iter()
                .map(|(pid, p)| Reverse((p.last_touch, pid.clone())))
                .collect();
        }
    }

    /// Decides what a sequenced produce carrying `producer_id` / `epoch` / `seq` should do, at
    /// monotonic instant `now` (used for LRU recency ONLY — the decision is wall-clock-independent),
    /// WITHOUT advancing the high-water for a fresh produce (the caller calls
    /// [`ProducerSeqRegistry::record`] only once the append is durable). It DOES advance the
    /// producer's epoch on a newer epoch (resetting the sequence space). Returns:
    ///
    /// - [`SeqDecision::Fenced`] if `epoch` is below the producer's known high-water (a zombie).
    /// - [`SeqDecision::Fresh`] for the next expected sequence (`last + 1`, or the first sequence of
    ///   a new producer/epoch).
    /// - [`SeqDecision::Duplicate`] for a retry (`seq <= last_accepted`): the last-accepted offset.
    /// - [`SeqDecision::OutOfOrder`] for a gap (`seq > last_accepted + 1`).
    ///
    /// A NEWER `epoch` RESETS the sequence high-water before the decision, so a restarted producer's
    /// first sequence under the new epoch reads fresh (its `last_seq` is cleared).
    pub fn check(&mut self, producer_id: &[u8], epoch: u64, seq: u64, now: u64) -> SeqDecision {
        self.make_room_for(producer_id);
        let entry = self
            .producers
            .entry(producer_id.to_vec())
            .or_insert(ProducerSeq {
                epoch,
                last_seq: None,
                last_offset: Offset::new(0),
                last_touch: now,
            });
        entry.last_touch = now;

        // Epoch fencing: a stale epoch is a zombie; a newer epoch supersedes (resets the sequence).
        if epoch < entry.epoch {
            let current_epoch = entry.epoch;
            self.touch_lru(producer_id, now);
            return SeqDecision::Fenced { current_epoch };
        }
        if epoch > entry.epoch {
            entry.epoch = epoch;
            entry.last_seq = None;
        }

        let decision = match entry.last_seq {
            // No publish accepted yet at this epoch: any sequence is the FIRST one, so it is fresh.
            // (Kafka starts at sequence 0; the first sequence a producer/epoch presents establishes
            // its base, so we do not require it to be exactly 0 — a resumed producer may continue
            // its own counter. The high-water is then this seq once it is recorded.)
            None => SeqDecision::Fresh,
            Some(last) => {
                if seq <= last {
                    // A retry of an already-accepted sequence: a benign duplicate at the
                    // last-accepted offset. (We hold ONLY the last offset, not every prior offset,
                    // so a retry of an OLDER sequence returns the high-water offset; the contract is
                    // "this publish is already durable, do not re-append", which holds.)
                    SeqDecision::Duplicate {
                        offset: entry.last_offset,
                    }
                } else if seq == last + 1 {
                    SeqDecision::Fresh
                } else {
                    // seq > last + 1: a gap. Rejected, never silently accepted.
                    SeqDecision::OutOfOrder { expected: last + 1 }
                }
            }
        };
        self.touch_lru(producer_id, now);
        decision
    }

    /// Records that `producer_id`'s sequence `seq` (at `epoch`) was appended at `offset`, at
    /// monotonic instant `now`, after a [`SeqDecision::Fresh`] check and the covering durable
    /// commit. The high-water advances to `(epoch, seq, offset)` ONLY if this is a forward move (a
    /// stale or duplicate record never regresses it), so a re-`record` of an already-accepted
    /// sequence is idempotent.
    pub fn record(&mut self, producer_id: &[u8], epoch: u64, seq: u64, offset: Offset, now: u64) {
        self.make_room_for(producer_id);
        let entry = self
            .producers
            .entry(producer_id.to_vec())
            .or_insert(ProducerSeq {
                epoch,
                last_seq: None,
                last_offset: offset,
                last_touch: now,
            });
        entry.last_touch = now;
        // A newer epoch supersedes; a stale epoch never regresses the high-water.
        if epoch > entry.epoch {
            entry.epoch = epoch;
            entry.last_seq = None;
        } else if epoch < entry.epoch {
            self.touch_lru(producer_id, now);
            return;
        }
        // Advance only on a forward sequence (the recorded fresh seq is `last + 1`, or the first).
        // `is_none_or` is stable only from 1.82; the workspace MSRV is 1.78, so spell it out.
        let advance = match entry.last_seq {
            None => true,
            Some(last) => seq > last,
        };
        if advance {
            entry.last_seq = Some(seq);
            entry.last_offset = offset;
        }
        self.touch_lru(producer_id, now);
    }

    /// Restores one producer's high-water from a durable snapshot (used at broker open). Sets
    /// `(epoch, last_seq, last_offset)` directly; the LRU clock is seeded to `now`. A restore never
    /// fences (it is trusted recovered state), so a producer that comes back AT its recovered epoch
    /// and continues its sequence is deduped EXACTLY as before the restart — the durability beat.
    pub fn restore(
        &mut self,
        producer_id: &[u8],
        epoch: u64,
        last_seq: u64,
        last_offset: Offset,
        now: u64,
    ) {
        self.make_room_for(producer_id);
        self.producers.insert(
            producer_id.to_vec(),
            ProducerSeq {
                epoch,
                last_seq: Some(last_seq),
                last_offset,
                last_touch: now,
            },
        );
        self.touch_lru(producer_id, now);
    }

    /// Every tracked producer's `(producer_id, epoch, last_seq, last_offset)` with a recorded
    /// sequence, sorted by `producer_id`, for the durable snapshot. A producer whose `last_seq` is
    /// still `None` (registered but never accepted a publish) carries no high-water and is omitted —
    /// its first publish after a restart is fresh anyway.
    #[must_use]
    pub fn snapshot_pairs(&self) -> Vec<SeqHighWater> {
        let mut out: Vec<SeqHighWater> = self
            .producers
            .iter()
            .filter_map(|(pid, p)| p.last_seq.map(|s| (pid.clone(), p.epoch, s, p.last_offset)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

/// The on-disk snapshot format version for a producer-sequence high-water map.
const SNAPSHOT_VERSION: u8 = 1;

/// The minimum length of an [`encode_seq_snapshot`] output: a 1-byte version, a 4-byte entry count,
/// and a trailing 4-byte crc32c, with no entries. A payload shorter than this cannot be a snapshot.
pub const SEQ_SNAPSHOT_MIN_LEN: usize = 1 + 4 + 4;

/// Encodes a durable snapshot of the producer-sequence high-waters: a 1-byte version, the entry
/// count, then each `(producer_id, epoch, last_seq, last_offset)` as `u16-len producer_id`, `u64
/// epoch`, `u64 last_seq`, `u64 last_offset`, then a trailing crc32c over everything before it. The
/// entries MUST be sorted by `producer_id` and distinct (the registry's [`ProducerSeqRegistry::snapshot_pairs`]
/// guarantees it). Appended to `out`, so the storage layer may frame it after other bytes.
///
/// The triple is the WHOLE durable state: one fixed-size high-water per producer, so the snapshot is
/// O(producers) — never O(messages). Each `producer_id` is bounded by
/// [`crate::dedup::MAX_PRODUCER_ID_LEN`], so a single entry is bounded too.
pub fn encode_seq_snapshot(entries: &[SeqHighWater], out: &mut Vec<u8>) {
    let start = out.len();
    out.push(SNAPSHOT_VERSION);
    let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for (pid, epoch, last_seq, last_offset) in entries {
        // The producer_id is bounded by MAX_PRODUCER_ID_LEN at the wire boundary, so its length
        // always fits a u16; saturate rather than panic if a future caller ever exceeds it.
        let plen = u16::try_from(pid.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(&pid[..plen as usize]);
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(&last_seq.to_le_bytes());
        out.extend_from_slice(&last_offset.get().to_le_bytes());
    }
    let crc = crc32c::crc32c(&out[start..]);
    out.extend_from_slice(&crc.to_le_bytes());
}

/// Decodes a snapshot produced by [`encode_seq_snapshot`], validating the version, the declared
/// count against the bytes, the checksum, and that the `producer_id`s are strictly sorted and
/// distinct (so a corrupt or torn snapshot is rejected rather than silently misread). Returns the
/// `(producer_id, epoch, last_seq, last_offset)` entries in ascending-`producer_id` order.
///
/// # Errors
/// Returns [`SeqSnapshotError`] for a short, mis-sized, wrong-version, count-mismatched,
/// bad-checksum, or out-of-order snapshot. A rejected snapshot never yields a half-built map, so the
/// caller falls back to no carried high-waters (every producer resumes at-least-once, the safe
/// degrade) rather than trust bad state.
pub fn decode_seq_snapshot(input: &[u8]) -> Result<Vec<SeqHighWater>, SeqSnapshotError> {
    if input.len() < SEQ_SNAPSHOT_MIN_LEN {
        return Err(SeqSnapshotError::Truncated);
    }
    let version = input[0];
    if version != SNAPSHOT_VERSION {
        return Err(SeqSnapshotError::UnsupportedVersion(version));
    }
    let crc_at = input.len() - 4;
    let mut crc_bytes = [0u8; 4];
    crc_bytes.copy_from_slice(&input[crc_at..]);
    let stored = u32::from_le_bytes(crc_bytes);
    if crc32c::crc32c(&input[..crc_at]) != stored {
        return Err(SeqSnapshotError::BadCrc);
    }
    let mut declared_bytes = [0u8; 4];
    declared_bytes.copy_from_slice(&input[1..5]);
    let declared = u32::from_le_bytes(declared_bytes);

    let mut entries = Vec::new();
    let mut pos = SEQ_SNAPSHOT_MIN_LEN - 4; // first entry starts right after the header
    let mut prev: Option<Vec<u8>> = None;
    while pos < crc_at {
        // Each entry: u16 plen, plen bytes, 3 * u64.
        if pos + 2 > crc_at {
            return Err(SeqSnapshotError::BadLength { len: input.len() });
        }
        let mut plen_bytes = [0u8; 2];
        plen_bytes.copy_from_slice(&input[pos..pos + 2]);
        let plen = u16::from_le_bytes(plen_bytes) as usize;
        pos += 2;
        let entry_tail = pos + plen + 24; // producer_id + 3 u64
        if entry_tail > crc_at {
            return Err(SeqSnapshotError::BadLength { len: input.len() });
        }
        let pid = input[pos..pos + plen].to_vec();
        pos += plen;
        let epoch = read_u64(input, pos);
        let last_seq = read_u64(input, pos + 8);
        let last_offset = read_u64(input, pos + 16);
        pos += 24;
        if let Some(p) = &prev {
            if pid <= *p {
                return Err(SeqSnapshotError::NotSorted);
            }
        }
        prev = Some(pid.clone());
        entries.push((pid, epoch, last_seq, Offset::new(last_offset)));
    }
    if u64::from(declared) != entries.len() as u64 {
        return Err(SeqSnapshotError::CountMismatch {
            declared,
            actual: entries.len() as u64,
        });
    }
    Ok(entries)
}

/// Reads a little-endian `u64` at `pos`; the caller has bounds-checked the slice length.
fn read_u64(buf: &[u8], pos: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[pos..pos + 8]);
    u64::from_le_bytes(b)
}

/// A failure decoding a producer-sequence snapshot (see [`decode_seq_snapshot`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqSnapshotError {
    /// The snapshot is shorter than the fixed header plus checksum.
    Truncated,
    /// An entry ran past the snapshot body (a torn or tampered length).
    BadLength {
        /// The rejected total length.
        len: usize,
    },
    /// The snapshot's version byte is one this build does not understand.
    UnsupportedVersion(u8),
    /// The declared entry count did not match the entries actually present.
    CountMismatch {
        /// The count the snapshot's header declared.
        declared: u32,
        /// The number of whole entries the body actually held.
        actual: u64,
    },
    /// The trailing crc32c did not match the body (a torn or corrupt snapshot).
    BadCrc,
    /// The decoded `producer_id`s were not strictly sorted and distinct.
    NotSorted,
}

impl core::fmt::Display for SeqSnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SeqSnapshotError::Truncated => write!(f, "producer-seq snapshot is too short"),
            SeqSnapshotError::BadLength { len } => {
                write!(f, "producer-seq snapshot length {len} is malformed")
            }
            SeqSnapshotError::UnsupportedVersion(v) => {
                write!(f, "producer-seq snapshot version {v} is not supported")
            }
            SeqSnapshotError::CountMismatch { declared, actual } => write!(
                f,
                "producer-seq snapshot declared {declared} entries but holds {actual}"
            ),
            SeqSnapshotError::BadCrc => write!(f, "producer-seq snapshot checksum did not match"),
            SeqSnapshotError::NotSorted => {
                write!(
                    f,
                    "producer-seq snapshot producer_ids are not strictly sorted"
                )
            }
        }
    }
}

impl std::error::Error for SeqSnapshotError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> ProducerSeqRegistry {
        ProducerSeqRegistry::new(SeqConfig::default())
    }

    #[test]
    fn the_first_sequence_is_fresh_then_a_retry_is_a_duplicate() {
        let mut r = reg();
        // seq 0 for a fresh producer is the first publish: fresh.
        assert_eq!(r.check(b"p", 0, 0, 0), SeqDecision::Fresh);
        r.record(b"p", 0, 0, Offset::new(10), 0);
        // The exact same publish retried: a benign duplicate at the original offset.
        assert_eq!(
            r.check(b"p", 0, 0, 1),
            SeqDecision::Duplicate {
                offset: Offset::new(10)
            }
        );
        // seq 1 is the next expected: fresh.
        assert_eq!(r.check(b"p", 0, 1, 2), SeqDecision::Fresh);
    }

    #[test]
    fn a_retried_publish_deduplicates_to_one_append() {
        // The headline guarantee: a retry returns the original offset and appends nothing.
        let mut r = reg();
        assert_eq!(r.check(b"p", 0, 5, 0), SeqDecision::Fresh);
        r.record(b"p", 0, 5, Offset::new(42), 0);
        // Retry the same seq twice more: both are duplicates at the SAME offset (one append only).
        assert_eq!(
            r.check(b"p", 0, 5, 1),
            SeqDecision::Duplicate {
                offset: Offset::new(42)
            }
        );
        assert_eq!(
            r.check(b"p", 0, 5, 2),
            SeqDecision::Duplicate {
                offset: Offset::new(42)
            }
        );
    }

    #[test]
    fn an_out_of_order_gap_is_rejected() {
        let mut r = reg();
        assert_eq!(r.check(b"p", 0, 0, 0), SeqDecision::Fresh);
        r.record(b"p", 0, 0, Offset::new(1), 0);
        // Skipping to seq 2 (gap: expected 1) is rejected, not silently accepted.
        assert_eq!(
            r.check(b"p", 0, 2, 1),
            SeqDecision::OutOfOrder { expected: 1 }
        );
        // The high-water is unchanged, so the in-order seq 1 still reads fresh (no corruption).
        assert_eq!(r.check(b"p", 0, 1, 2), SeqDecision::Fresh);
    }

    #[test]
    fn a_stale_epoch_is_fenced_while_the_new_epoch_writes() {
        let mut r = reg();
        // Epoch 5 establishes and writes.
        assert_eq!(r.check(b"p", 5, 0, 0), SeqDecision::Fresh);
        r.record(b"p", 5, 0, Offset::new(1), 0);
        // A zombie at the OLD epoch 4 is fenced.
        assert_eq!(
            r.check(b"p", 4, 1, 1),
            SeqDecision::Fenced { current_epoch: 5 }
        );
        // The new epoch 6 supersedes and resets the sequence space: its seq 0 is fresh.
        assert_eq!(r.check(b"p", 6, 0, 2), SeqDecision::Fresh);
        r.record(b"p", 6, 0, Offset::new(2), 2);
        // The old epoch is still fenced after the bump.
        assert_eq!(
            r.check(b"p", 5, 1, 3),
            SeqDecision::Fenced { current_epoch: 6 }
        );
    }

    #[test]
    fn a_restarted_producer_higher_epoch_resets_the_sequence_and_dedups_fresh() {
        let mut r = reg();
        for s in 0..3u64 {
            assert_eq!(r.check(b"p", 1, s, s), SeqDecision::Fresh);
            r.record(b"p", 1, s, Offset::new(s), s);
        }
        // The producer restarts with epoch 2; seq 0 under the new epoch is fresh (not deduped
        // against epoch 1's seq 0), so a restarted producer never falsely dedups.
        assert_eq!(r.check(b"p", 2, 0, 10), SeqDecision::Fresh);
    }

    #[test]
    fn distinct_producers_are_independent() {
        let mut r = reg();
        r.check(b"a", 0, 0, 0);
        r.record(b"a", 0, 0, Offset::new(1), 0);
        // The same seq from a different producer is fresh (per-producer keying).
        assert_eq!(r.check(b"b", 0, 0, 0), SeqDecision::Fresh);
        assert_eq!(r.producer_count(), 2);
    }

    #[test]
    fn the_state_is_bounded_o_producers_under_a_flood() {
        // The headline memory bound: a flood of distinct producer_ids never grows past the cap.
        let max = 16;
        let mut r = ProducerSeqRegistry::new(SeqConfig { max_producers: max });
        for i in 0..(max as u64 * 10) {
            let pid = format!("p-{i}");
            assert_eq!(r.check(pid.as_bytes(), 0, 0, i), SeqDecision::Fresh);
            r.record(pid.as_bytes(), 0, 0, Offset::new(i), i);
            assert!(r.producer_count() <= max, "exceeded cap");
        }
        assert_eq!(r.producer_count(), max);
    }

    #[test]
    fn an_evicted_dead_producer_falls_back_to_fresh_not_a_false_dedup() {
        let max = 4;
        let mut r = ProducerSeqRegistry::new(SeqConfig { max_producers: max });
        // The victim writes at t=0, the least-recently-active.
        r.check(b"victim", 0, 0, 0);
        r.record(b"victim", 0, 0, Offset::new(7), 0);
        // Flood newer producers, each more recent, forcing the victim out by LRU.
        for i in 0..max as u64 {
            let pid = format!("new-{i}");
            r.check(pid.as_bytes(), 0, 0, 10 + i);
            r.record(pid.as_bytes(), 0, 0, Offset::new(100 + i), 10 + i);
        }
        assert_eq!(r.producer_count(), max);
        // The reclaimed victim's seq now reads FRESH (at-least-once), never a stale false dedup.
        assert_eq!(r.check(b"victim", 0, 0, 100), SeqDecision::Fresh);
    }

    #[test]
    fn an_active_producer_is_not_evicted_while_idle_ones_exist() {
        let max = 4;
        let mut r = ProducerSeqRegistry::new(SeqConfig { max_producers: max });
        r.check(b"hot", 0, 0, 0);
        r.record(b"hot", 0, 0, Offset::new(42), 0);
        for i in 0..(max as u64 - 1) {
            let pid = format!("idle-{i}");
            r.check(pid.as_bytes(), 0, 0, 1 + i);
            r.record(pid.as_bytes(), 0, 0, Offset::new(200 + i), 1 + i);
        }
        r.check(b"hot", 0, 1, 1_000);
        r.record(b"hot", 0, 1, Offset::new(43), 1_000);
        for i in 0..(max as u64 * 4) {
            let pid = format!("flood-{i}");
            let t = 1_001 + i;
            r.check(pid.as_bytes(), 0, 0, t);
            r.record(pid.as_bytes(), 0, 0, Offset::new(300 + i), t);
            r.check(b"hot", 0, 2 + i, t + 1);
            r.record(b"hot", 0, 2 + i, Offset::new(50 + i), t + 1);
        }
        // hot survived: a retry of its last seq is still a duplicate at its last offset.
        let last = 2 + (max as u64 * 4 - 1);
        assert!(matches!(
            r.check(b"hot", 0, last, 1_000_000),
            SeqDecision::Duplicate { .. }
        ));
    }

    #[test]
    fn record_is_idempotent_and_never_regresses() {
        let mut r = reg();
        r.check(b"p", 0, 0, 0);
        r.record(b"p", 0, 0, Offset::new(5), 0);
        r.check(b"p", 0, 1, 1);
        r.record(b"p", 0, 1, Offset::new(6), 1);
        // Re-recording an OLDER seq never regresses the high-water.
        r.record(b"p", 0, 0, Offset::new(99), 2);
        assert_eq!(
            r.check(b"p", 0, 1, 3),
            SeqDecision::Duplicate {
                offset: Offset::new(6)
            }
        );
        assert_eq!(r.check(b"p", 0, 2, 4), SeqDecision::Fresh);
    }

    #[test]
    fn restore_reestablishes_the_high_water_for_cross_restart_dedup() {
        // The durability beat in the pure layer: restore the high-water, then a replayed retry is
        // STILL deduped (no time bound to lapse).
        let mut r = reg();
        r.restore(b"p", 3, 7, Offset::new(70), 0);
        // A retry of seq 7 at the recovered epoch is a duplicate at the recovered offset.
        assert_eq!(
            r.check(b"p", 3, 7, 1_000),
            SeqDecision::Duplicate {
                offset: Offset::new(70)
            }
        );
        // The next sequence is fresh; an older one is a duplicate; a gap is rejected.
        assert_eq!(r.check(b"p", 3, 8, 1_001), SeqDecision::Fresh);
        assert_eq!(
            r.check(b"p", 3, 9, 1_002),
            SeqDecision::OutOfOrder { expected: 8 }
        );
    }

    #[test]
    fn snapshot_round_trips_through_the_registry() {
        let mut r = reg();
        for (pid, seq, off) in [(&b"a"[..], 2u64, 20u64), (b"b", 5, 50)] {
            r.check(pid, 1, seq, 0);
            r.record(pid, 1, seq, Offset::new(off), 0);
        }
        let pairs = r.snapshot_pairs();
        let mut buf = Vec::new();
        encode_seq_snapshot(&pairs, &mut buf);
        let decoded = decode_seq_snapshot(&buf).unwrap();
        assert_eq!(decoded, pairs);

        // Restore into a fresh registry and confirm cross-restart dedup.
        let mut r2 = reg();
        for (pid, epoch, last_seq, last_offset) in &decoded {
            r2.restore(pid, *epoch, *last_seq, *last_offset, 0);
        }
        assert_eq!(
            r2.check(b"a", 1, 2, 1),
            SeqDecision::Duplicate {
                offset: Offset::new(20)
            }
        );
        assert_eq!(r2.check(b"b", 1, 6, 1), SeqDecision::Fresh);
    }

    #[test]
    fn empty_snapshot_round_trips() {
        let mut buf = Vec::new();
        encode_seq_snapshot(&[], &mut buf);
        assert_eq!(buf.len(), SEQ_SNAPSHOT_MIN_LEN);
        assert_eq!(decode_seq_snapshot(&buf).unwrap(), Vec::new());
    }

    #[test]
    fn decode_rejects_a_truncated_snapshot() {
        for len in 0..SEQ_SNAPSHOT_MIN_LEN {
            assert_eq!(
                decode_seq_snapshot(&vec![0u8; len]),
                Err(SeqSnapshotError::Truncated)
            );
        }
    }

    #[test]
    fn decode_rejects_an_unsupported_version() {
        let mut buf = Vec::new();
        encode_seq_snapshot(&[(b"p".to_vec(), 1, 2, Offset::new(3))], &mut buf);
        buf[0] = SNAPSHOT_VERSION + 1;
        let crc_at = buf.len() - 4;
        let crc = crc32c::crc32c(&buf[..crc_at]);
        buf[crc_at..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            decode_seq_snapshot(&buf),
            Err(SeqSnapshotError::UnsupportedVersion(SNAPSHOT_VERSION + 1))
        );
    }

    #[test]
    fn decode_rejects_a_corrupt_checksum() {
        let mut buf = Vec::new();
        encode_seq_snapshot(&[(b"p".to_vec(), 1, 2, Offset::new(3))], &mut buf);
        buf[6] ^= 0x01;
        assert_eq!(decode_seq_snapshot(&buf), Err(SeqSnapshotError::BadCrc));
    }

    #[test]
    fn decode_rejects_out_of_order_producer_ids() {
        // Two entries with descending producer_ids, crc-correct: rejected.
        let mut buf = vec![SNAPSHOT_VERSION];
        buf.extend_from_slice(&2u32.to_le_bytes());
        for pid in [b"b", b"a"] {
            buf.extend_from_slice(&1u16.to_le_bytes());
            buf.extend_from_slice(pid);
            buf.extend_from_slice(&1u64.to_le_bytes());
            buf.extend_from_slice(&1u64.to_le_bytes());
            buf.extend_from_slice(&1u64.to_le_bytes());
        }
        let crc = crc32c::crc32c(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(decode_seq_snapshot(&buf), Err(SeqSnapshotError::NotSorted));
    }

    #[test]
    fn decode_rejects_a_count_mismatch() {
        let mut buf = Vec::new();
        encode_seq_snapshot(
            &[
                (b"a".to_vec(), 1, 1, Offset::new(1)),
                (b"b".to_vec(), 1, 1, Offset::new(2)),
            ],
            &mut buf,
        );
        buf[1..5].copy_from_slice(&9u32.to_le_bytes());
        let crc_at = buf.len() - 4;
        let crc = crc32c::crc32c(&buf[..crc_at]);
        buf[crc_at..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            decode_seq_snapshot(&buf),
            Err(SeqSnapshotError::CountMismatch {
                declared: 9,
                actual: 2
            })
        );
    }
}
