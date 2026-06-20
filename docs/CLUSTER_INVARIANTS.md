# IronBus cluster recovery invariants (CI1 to CI4)

The cluster-wide analogue of the single-node invariants in
[INVARIANTS.md](INVARIANTS.md). Where the single-node I1 to I8 hold for ONE
replica's durable log, the cluster invariants CI1 to CI4 ratify what a CLUSTER
of replicas must guarantee about a committed record once replication, the
quorum-fsync ack, divergence self-heal, and leader-completeness are in play. This
is the written, falsifiable cluster durability contract — the thing NATS leaves
unspecified, and the thing the Jepsen NATS analysis showed it does not hold.

These invariants are the V2-C4 (`[C4-I5]`, #615) ratification of the cluster
recovery semantics that the C2/C3/C4 milestones build. They are derived from and
cross-checked against the actual code: each invariant has a PURE-FUNCTION CHECKER
in `crates/ironbus-core/src/cluster_invariants.rs`, kept IO-free in `ironbus-core`
exactly like the single-node resilience checkers in
`crates/ironbus-storage/src/invariants.rs`. Where this doc and the implementation
diverge, the CODE wins and the divergence is flagged inline.

A note on numbering. CI1 to CI4 are a SEPARATE, independently-numbered set from
the shared I1 to I8 and from the resilience checkers I1 to I4 in
[INVARIANTS.md](INVARIANTS.md). They are the cluster contract every replica is
written against. Each CIn EXTENDS a single-node invariant cluster-wide, and the
mapping is given per invariant below.

---

## CI1: cluster durable prefix

**Statement.** The committed prefix — every offset strictly below the cluster
high-watermark (HW) — is IDENTICAL on every in-sync replica. Two in-sync replicas
never disagree on a committed record. Divergence is allowed ONLY above the HW
(uncommitted), where leader-epoch truncation removes the divergent suffix; it is
never committed.

**Why it holds.** A follower pulls the leader's CRC-framed segment bytes verbatim
and re-validates every frame with the same intact-record predicate recovery uses,
so an in-sync replica's committed bytes are byte-identical to the leader's. The HW
advances only over the quorum-committed prefix (CI2), so a record below the HW has
been replicated and fsync'd on a quorum of identical copies. A follower that
replicated a divergent suffix from an old leader truncates it to the divergence
point of the correct lineage (leader-epoch truncation, KIP-101) before it can be
committed.

**Extends.** I1 (durable prefix) — the single-node longest-valid-prefix, lifted to
"identical committed prefix across in-sync replicas."

**Checker.** `check_cluster_durable_prefix(replicas, committed_hw)` — over each
in-sync replica's per-offset committed fingerprints, asserts every replica matches
the reference replica on every offset below `committed_hw`. The negative fixture: a
replica that holds a different record at a committed offset (or is short of the HW)
is rejected.

---

## CI2: cluster ack implies quorum-fsync

**Statement.** A released `C2-fsync` ack at offset `o` implies that at least
`min_isr` replicas (a quorum, e.g. `f + 1` of `2f + 1`) have each `fdatasync`'d
every offset `<= o`. An ack is NEVER released on a sub-quorum or page-cache basis.

**Why it holds.** The leader's quorum-fsync ack gate (`isr::QuorumAckGate`, #691)
withholds a `C2-fsync` `PubAck` until the produce's offset is below the
quorum-commit offset — the highest offset at least `min_isr` ISR replicas have all
reported `fdatasync`'d (followers report their FSYNC'd frontier, not their received
frontier). Below `min_isr` the quorum-commit offset is `None` and the gate releases
nothing: the ack blocks rather than lies (unavailable over unsafe, the no-false-ack
property). This is the decisive win over NATS R3 / Kafka `acks=all`, which ack on a
quorum PAGE-CACHE, not a quorum FSYNC.

**Extends.** I2 (ack implies durable, conditioned on `durability_level=sync`) — the
single-node fsync-before-ack, lifted to "fsync-on-a-quorum-before-ack."

**Checker.** `check_quorum_fsync_ack(acks, min_isr)` — over the released acks and
the count of replicas that had fsync'd each, asserts none was released below
`min_isr`. The negative fixture: an ack released with only one fsync'd replica under
a quorum of two is rejected (the page-cache / sub-quorum ack NATS permits).

---

## CI3: bounded, reported, repaired divergence

**Statement.** Any cross-replica divergence is DETECTED, BOUNDED (within the I3
caps), REPORTED (a typed event), and either auto-repaired from the quorum or failed
closed. It is NEVER silently served, NEVER deletes data, and NEVER repaired past the
cap without failing closed.

**Why it holds.** Replicas advertise a per-segment fingerprint (the footer triple
`(record_count, last_seq, footer_CRC)` plus an xxh3-64 content hash);
`divergence::compare_fingerprints` detects a mismatch in O(segments) and emits a
typed `DivergenceReport` (a clean cluster detects nothing — no false positive). On a
detection the divergent suffix is truncated (clamped at or above the committed HW,
so committed data is never dropped) and the clean CRC-validated bytes are re-fetched
from the quorum, bounded by the I3 caps and reported as a `ResyncReport`; over the
cap it fails closed. A minority-corrupt segment is quarantined (copy-then-drop into
the forensic store, never deleted) and re-synced from the clean majority, so the
partition stays available. This fixes the two NATS failures with no fix today: the
silent-drift class (`#5576`) and the minority-corruption-deletes-the-stream class
(`#7556`).

**Extends.** I3 (bounded, reported loss) — the single-node corruption-skip
contract, lifted so the "loss" is REPAIRED from a peer (or failed closed) instead of
merely reported, and a minority fault can never delete data or lose quorum.

**Checker.** `check_divergence_handled(handlings)` — over each detected divergence
and its outcome, asserts the outcome is one of the valid ones (repaired within the
cap, failed closed over the cap, or quarantined + re-synced). The negative fixtures:
a silently-served divergence, a deleted divergence, and a repair past the cap that
did not fail closed are each rejected.

---

## CI4: epoch monotonicity / no stale-leader-commit

**Statement.** Leadership epochs are monotonic: across the committed log, a later
offset never carries an older leader epoch, and no record is ever committed under an
epoch strictly below the cluster-known epoch. A stale leader cannot commit, and a
stale or corrupt replica cannot win re-election (the leader-completeness restriction).

**Why it holds.** The metadata Raft group assigns each partition a monotonic leader
epoch (the Raft term, #668); the epoch only moves forward (a lower observed term is
fenced, never adopted). A stale leader's append carries an old epoch and is fenced
by followers and clients; it cannot advance the HW because it cannot reach a quorum.
At the election boundary, the leader-completeness restriction (`[C4-I4]`, #614)
makes a candidate eligible ONLY if it is in the ISR, holds the committed log up to
the cluster-known HW, and has no detected divergence — so a stale (behind-HW) or
corrupt (divergent) replica is INELIGIBLE by construction. This is the Kafka ELR
"Leader Candidate Completeness" (KIP-966) shape, and it is precisely the property
the Jepsen NATS 2.12.1 analysis found NATS violating: a corrupt node "managed to
become the leader of the cluster despite its corrupt state" and then deleted the
stream, losing ~49.7% of acknowledged writes.

**Extends.** The C1-I3 leader epoch (#668) + the C4-I4 leader-completeness
restriction (#614). It is the cluster split-brain / election-safety invariant.

**Checker.** `check_epoch_monotonic(committed, cluster_epoch)` — over the committed
records' epochs in offset order, asserts the sequence is non-decreasing and no epoch
exceeds the cluster-known epoch. The negative fixtures: an epoch that regresses
across offsets (a stale leader committing after a newer one) and a commit under an
epoch above the cluster-known epoch are each rejected.

The election-eligibility predicate that ENFORCES CI4 at the election boundary is
`LeaderEligibility` in `crates/ironbus-core/src/cluster_invariants.rs` (the pure
predicate) and `cluster::eligibility` in `ironbus-server` (the adapter that projects
the ISR, the durable frontier, and the divergence report onto it). Eligibility =
`(in ISR) AND (durable prefix >= committed HW) AND (no detected divergence)`. The
metadata-plane placement consults `eligible_leaders` and designates a leader only
from the eligible set; the placement/rebalance itself (which eligible replica, and
when) is C5.

---

## The cluster checkers, at a glance

`crates/ironbus-core/src/cluster_invariants.rs` implements four pure checkers over
observable cluster state, plus the leader-completeness eligibility predicate. They
are a SEPARATE, independently-numbered set from the single-node checkers. Each is a
pure function returning the first `ClusterInvariantViolation` or `Ok(())`, and each
has a known-bad negative fixture in its tests, so a checker that always passes is
itself caught.

| Cluster checker | Statement | Extends | Beats (NATS failure) |
| --- | --- | --- | --- |
| CI1 `check_cluster_durable_prefix` | in-sync replicas share the committed prefix | I1 | silent replica drift (`#5576`) |
| CI2 `check_quorum_fsync_ack` | a `C2-fsync` ack implies a quorum fsync | I2 | ack ≠ fsync (`#7564`) |
| CI3 `check_divergence_handled` | divergence is bounded + reported + repaired, never silently served / deleted | I3 | minority corruption deletes the stream (`#7556`) |
| CI4 `check_epoch_monotonic` | epochs are monotonic; no stale-leader-commit | C1-I3 (#668) + C4-I4 (#614) | corrupt node wins election (Jepsen 2.12.1) |

The eligibility predicate `LeaderEligibility` is the construction behind CI4: a
stale/corrupt replica is excluded from leadership BY CONSTRUCTION, so the
corrupt-node-wins-and-deletes failure cannot occur. See
[MISSION.md](MISSION.md) for where cluster recovery sits in the v2 roadmap, and
[RECOVERY.md](RECOVERY.md) and [DURABILITY.md](DURABILITY.md) for the single-node
recovery and durability contracts the cluster invariants extend.

---

## Single node is byte-identical

With no cluster (`n = 1`), none of CI1 to CI4 engages and the lone replica is
trivially compliant: it is its own in-sync set, its committed prefix is identical to
itself, its `C2-fsync` ack degenerates to the single-node local-fsync I2 ack, it
cannot diverge from itself, and it is trivially eligible to lead (its durable prefix
IS the committed HW). The eligibility / CI layer never constructs in a standalone
broker — the zero-config single-node path is byte-for-byte today's broker, exactly
as the single-node invariants require.
