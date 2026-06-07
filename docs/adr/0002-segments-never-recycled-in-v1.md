# 0002. v1 never recycles a segment id

- **Status**: Accepted
- **Owning issue**: [#18](https://github.com/ELares/IronBus/issues/18) (security, encryption at rest), decided in #139

## Context

The log is a chain of segments, each identified by a numeric segment id.
Retention (#13) reclaims disk by deleting whole old sealed segments. A tempting
optimization is to reuse the id of a deleted segment for a fresh one, keeping the
id space dense. But IronBus offers optional encryption at rest (#18) with
AES-256-GCM or ChaCha20-Poly1305, and an at-rest nonce is derived in part from
the segment id. Reusing a segment id under a fixed key would reuse a nonce, which
is a catastrophic failure for both of those AEAD constructions.

## Decision

In v1 a segment id is never recycled. A new segment always gets a fresh id
strictly greater than any id ever used, across rolls and across a restart. The
on-disk ids form a contiguous, monotonic, never-recycled run; deleting an old
segment leaves a hole at the bottom rather than freeing its id for reuse.

This is pinned by the storage test
`segment_ids_increase_monotonically_and_are_never_recycled` in
`crates/ironbus-storage/src/log.rs`, whose comment records the rule directly:
"#139 decision: v1 never recycles segments. A new segment always gets a fresh id
higher than any existing one ... This keeps the at-rest nonce (#18) safe: a
segment_id is never reused under a fixed key." The test appends across several
segment rolls, reopens the data directory, and asserts the new segments take ids
strictly greater than the previous maximum while every prior id is retained.

## Consequences

- The at-rest nonce stays unique under a fixed key without any extra nonce
  bookkeeping: the segment id is monotonic by construction, so it is safe nonce
  material.
- The id space is allowed to be sparse at the bottom after retention deletes old
  segments; a low id is gone for good, never overwritten.
- Any future scheme that wants to recycle ids (it has no current motivation)
  would have to be a v2 decision that first solves the nonce reuse it would
  otherwise create, and would supersede this ADR.
