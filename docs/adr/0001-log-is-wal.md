# 0001. The active segment is the write-ahead log

- **Status**: Accepted
- **Owning issue**: [#4](https://github.com/ELares/IronBus/issues/4) (storage engine), [#6](https://github.com/ELares/IronBus/issues/6) (durability)

## Context

Many durable systems keep a separate write-ahead log in front of their main
store, then apply the WAL into that store and keep the two in sync. On a
single-topic edge queue that second structure is pure overhead: another file to
fsync, another thing that can disagree with the data after a power cut, and a
second copy of every byte on flash that is already wearing.

## Decision

There is no separate WAL file. The active log segment IS the write-ahead log. A
publish is one framed, checksummed, record-aligned append to the active segment,
group-committed with an `fdatasync`, and that append is the durable record. The
offset index is derived from the log and rebuilt on startup, never authoritative
on its own.

This is the project's headline storage decision. The top-level `README.md`
states it directly: "The active segment **is** the write-ahead log: there is no
separate WAL file to keep in sync." The architecture diagram in the README
labels the active segment "(this IS the WAL)", the #4 issue row reads "the active
segment is the WAL", and the "Key decisions already committed" table records it
as "Log-is-WAL ... No separate WAL file. The offset index is derived and
rebuildable."

## Consequences

- One file to make durable, not two, and no WAL-versus-store reconciliation step
  on recovery. Recovery is replay of the log itself: truncate a torn tail, take
  the longest valid prefix, rebuild the derived index.
- Every record on disk carries a CRC32C, so a flipped bit is caught on read, and
  the durability contract (no acknowledged write lost below its configured
  durability level) is a property of the single log, not of two structures
  agreeing.
- Less write amplification on flash, which matters on an edge node (#20).
- The cost is that the log is the only durable artifact, so its framing,
  checksum, and recovery path must be exactly right; that is what the record
  format (#5) and crash-recovery (#7) work pins down.
