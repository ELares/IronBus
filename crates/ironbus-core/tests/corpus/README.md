<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus v1 conformance corpus (#45)

A frozen, checked-in set of byte-exact fixtures for the v1 on-disk format (the record frame and
the segment header/footer). Each fixture is the exact bytes a conformant v1 encoder produces,
paired with the verdict a conformant v1 decoder (or the recovery path built on it) must return.

The corpus is the executable freeze of the format: a deterministic generator regenerates every
fixture and asserts it equals the bytes committed here, so an unintended format change (a field
width, an endianness, a flag derivation) fails CI as byte drift. It is also a cross-platform
byte-identity gate: x86_64, aarch64, and i686 all regenerate these bytes and cross-verify the
CRCs, so an endianness or alignment bug that only manifests on aarch64 is caught here, not in
production on an edge box.

## Layout

- The generator lives in `crates/ironbus-core/tests/conformance/mod.rs`. It is fully
  deterministic: fixed seeds, fixed sequences, fixed timestamps, no `now()` and no randomness.
- The gate test is `crates/ironbus-core/tests/conformance_corpus.rs`. It regenerates the
  fixtures, asserts byte/digest identity with the files here, asserts each fixture decodes to its
  expected verdict, runs round-trip property tests over the full size space within the caps, and
  reproduces the worked format dump from the versioning task (docs/COMPATIBILITY.md and
  docs/CONTRACTS.md) against the `record_minimal` fixture.
- The storage cross-check is `crates/ironbus-storage/tests/conformance_recovery.rs`. It loads the
  segment fixtures here through the REAL recovery path (`Log::open`) and asserts recovery emits
  exactly the loss reason and span each fixture declares.

Each small fixture is committed as `<name>.bin` (the raw bytes, compared byte-for-byte). The one
multi-MiB fixture (`record_max_size`, a 16 MiB frame) is committed as `<name>.digest` instead, a
one-line `len=... frame_crc=... header_crc=... body_crc=...` digest, to keep the 16 MiB blob out
of git history. The digest is a pure function of the exact bytes (the bytes are fully
reproducible from the generator), so it is still a byte-exact gate.

## Fixtures

| File | What it is | Expected verdict |
|------|------------|------------------|
| `record_minimal.bin` | A minimal record: no key, no headers, a one-byte payload, below the xxh3 threshold. | Intact record. |
| `record_key_only.bin` | A key-only record: a routing key, empty headers and payload (HAS_KEY derived). | Intact record. |
| `record_key_headers_payload.bin` | A record with a key, a headers blob, and a payload, all non-empty. | Intact record. |
| `record_compressed.bin` | A record with the COMPRESSED flag set and preserved (framing unchanged). | Intact record. |
| `record_compressed_over_threshold.bin` | A compressed record over the xxh3 threshold (COMPRESSED + derived HAS_XXH3 both set; the xxh3 field present). | Intact record. |
| `record_max_size.digest` | A max-size record: total frame exactly `DEFAULT_MAX_RECORD_BYTES` (16 MiB), carrying the xxh3 field. Digest-frozen. | Intact record. |
| `segment_sealed_with_footer.bin` | A multi-record sealed segment: a 64-byte header, three records, a clean 32-byte footer bound to the header. | Intact segment, footer present. |
| `segment_active_no_footer.bin` | An active (unsealed) segment: a 64-byte header and three records, no footer (the live write-ahead-log shape). | Intact segment, no footer. |
| `segment_torn_tail_mid_body.bin` | A torn-tail segment: the last record's header landed but its body is truncated mid-write. | Torn-truncate; recovery `TornTail` over the partial frame. |
| `segment_torn_tail_mid_trailer.bin` | A torn-tail segment: the last record's trailer is partially written. | Torn-truncate; recovery `TornTail` to the prior record boundary. |
| `segment_mid_log_bit_flip.bin` | A single-bit-flip mid-log corruption: a body byte of the second record is flipped. | Skip-and-report `CorruptRecordBody` from the second frame to EOF; the first record survives. |
| `segment_zero_window_tail.bin` | A zero-window (preallocated / zero-filled) record region after a valid header. | Skip-and-report `CorruptRecordHeader` over the zeroed span; zero records recovered. |
| `record_newer_version_reject.bin` | A structurally valid frame with version byte = 2 and a recomputed header CRC. | Fail-closed reject: `UnsupportedVersion(2)`. |
| `segment_header.bin` | A standalone 64-byte segment header with fixed ids and a fixed creation timestamp. | Intact segment header. |

The loss tuple a torn/corrupt fixture declares is the `(reason, byte_offset_start,
byte_offset_end)` recovery emits as an `ironbus_storage::loss::LossEvent`; the storage cross-check
asserts the real recovery path produces it.

## Regenerating

The corpus is regenerated only for a DELIBERATE format change (which must also bump
`FORMAT_VERSION`). To rewrite the files from the generator:

```sh
IRONBUS_REGENERATE_CORPUS=1 cargo test -p ironbus-core --test conformance_corpus \
    generator_reproduces_the_checked_in_corpus_bytes_exactly
```

Without that env var (the default, and always in CI) the test ASSERTS against the committed
files and fails on any drift. Review the resulting diff carefully: a change here is a change to
the durable, deployed on-disk format.
