// SPDX-License-Identifier: MIT OR Apache-2.0
//! The deterministic conformance-corpus generator for the v1 on-disk format (#45).
//!
//! This module emits a FIXED, deterministic set of byte-exact fixtures for the frozen
//! record frame and segment header/footer, each paired with the verdict a v1 decoder must
//! return for it. It is the single source of truth that both the byte-identity gate (the
//! generator must reproduce the checked-in bytes EXACTLY, so an unintended format change
//! fails CI) and the cross-platform job (`x86_64` and `aarch64` must produce identical bytes and
//! each verify the other's CRCs) refer to.
//!
//! Determinism is paramount: every fixture uses fixed seeds, fixed sequences, and fixed
//! timestamps. There is no `now()`, no randomness, and no IO in the generator itself (the
//! encoders are the IO-free `ironbus_core::{codec, segment}` paths). The corpus files are
//! written and read by the test target, never by this module, so the core crate stays
//! IO-free even in its test fixtures' construction.
//!
//! Each fixture's [`Verdict`] describes the decoder outcome at the level the format freezes:
//! - [`Verdict::IntactRecord`]: `decode` returns a record consuming the whole frame.
//! - [`Verdict::IntactSegmentHeader`] / [`Verdict::IntactSegmentFooter`]: the segment
//!   structure decodes to the expected fields.
//! - [`Verdict::TornTruncate`]: `decode` returns [`DecodeError::Truncated`] (a torn or
//!   partially written tail; recovery truncates to the prior intact boundary).
//! - [`Verdict::SkipAndReport`]: `decode` returns a corruption error that recovery turns into
//!   a skip-and-report with the named [`ReasonCode`] and loss span (the loss tuple is the
//!   `(reason, byte_offset_start, byte_offset_end)` recovery would emit for the fixture).
//! - [`Verdict::FailClosedReject`]: `decode` rejects a newer-version or otherwise unparseable
//!   frame fail-closed (e.g. [`DecodeError::UnsupportedVersion`]).

use ironbus_core::codec::{decode, encode, DecodeError, RecordView};
use ironbus_core::format::{
    header_offsets, RECORD_HEADER_LEN, RECORD_TRAILER_LEN, RECORD_XXH3_LEN, SEGMENT_FOOTER_LEN,
    SEGMENT_HEADER_LEN, XXH3_PAYLOAD_THRESHOLD,
};
use ironbus_core::segment::{SegmentFooter, SegmentHeader};
use ironbus_core::types::{Offset, RecordFlags, Seq};

/// The stable numeric reason codes a torn or corrupt span maps to, mirrored from
/// `ironbus_storage::loss::ReasonCode` so the core-crate corpus can name the recovery verdict
/// without depending on the storage crate. The numbers are the FROZEN codes pinned by
/// `ironbus_storage::loss::ReasonCode::code` (`TornTail` = 1, `CorruptRecordHeader` = 2,
/// `CorruptRecordBody` = 3); a storage-side test cross-checks they agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonCode {
    /// A torn or unsynced tail truncated to a consistent prefix (code 1).
    TornTail,
    /// A record header failed its checksum, magic, or version (code 2).
    CorruptRecordHeader,
    /// A record header was intact but its body failed its checksum (code 3).
    CorruptRecordBody,
}

impl ReasonCode {
    /// The frozen numeric code, identical to `ironbus_storage::loss::ReasonCode::code`.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            ReasonCode::TornTail => 1,
            ReasonCode::CorruptRecordHeader => 2,
            ReasonCode::CorruptRecordBody => 3,
        }
    }
}

/// A contiguous span of bytes recovery would drop, with its cause. The `(reason, start, end)`
/// triple is exactly the shape `ironbus_storage::loss::LossEvent` records, so a fixture's
/// expected loss tuple can be asserted against the real recovery path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossTuple {
    /// Why the span was dropped.
    pub reason: ReasonCode,
    /// The byte offset within the fixture where the lost span begins.
    pub start: u64,
    /// The byte offset within the fixture where the lost span ends (exclusive).
    pub end: u64,
}

/// The expected decoder verdict for a fixture: what a conformant v1 decoder (or the recovery
/// path built on it) must return for the fixture's exact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// `decode` returns a record consuming the whole frame, with these exact fields.
    IntactRecord(ExpectedRecord),
    /// `SegmentHeader::decode` returns these exact fields.
    IntactSegmentHeader(ExpectedSegmentHeader),
    /// A multi-record segment that decodes to a sequence of intact records and (optionally)
    /// a clean footer. `records` are decoded from the record region; `has_footer` is whether
    /// the trailing 32 bytes parse as a `SegmentFooter` bound to the header.
    IntactSegment {
        /// The records the record region decodes to, in order.
        records: Vec<ExpectedRecord>,
        /// Whether a clean, header-bound footer seals the segment.
        has_footer: bool,
    },
    /// `decode` returns [`DecodeError::Truncated`]: a torn or partially written tail. The
    /// loss tuple is what recovery would emit when it truncates to the prior intact boundary.
    TornTruncate(LossTuple),
    /// `decode` returns a corruption error recovery turns into a skip-and-report with this
    /// loss tuple (a mid-log single-bit flip, a zero-window tail, etc.).
    SkipAndReport(LossTuple),
    /// `decode` rejects the frame fail-closed (a newer-version record a v1 reader refuses).
    FailClosedReject(DecodeError),
}

/// The record fields a fixture's intact-record verdict pins. Owned (not borrowed) so a fixture
/// can be compared without keeping the source bytes alive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedRecord {
    /// The per-segment sequence number.
    pub seq: u64,
    /// The producer timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// The raw flags byte as stored.
    pub flags: u8,
    /// The routing or ordering key bytes.
    pub key: Vec<u8>,
    /// The headers blob bytes.
    pub headers: Vec<u8>,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

impl ExpectedRecord {
    /// Builds the expected record from a borrowed [`RecordView`] (owning copies of its slices).
    fn from_view(v: &RecordView<'_>) -> ExpectedRecord {
        ExpectedRecord {
            seq: v.seq.get(),
            timestamp_ms: v.timestamp_ms,
            flags: v.flags.bits(),
            key: v.key.to_vec(),
            headers: v.headers.to_vec(),
            payload: v.payload.to_vec(),
        }
    }

    /// Asserts a decoded [`RecordView`] matches this expectation field-for-field.
    pub fn assert_matches(&self, v: &RecordView<'_>) {
        assert_eq!(v.seq.get(), self.seq, "seq");
        assert_eq!(v.timestamp_ms, self.timestamp_ms, "timestamp_ms");
        assert_eq!(v.flags.bits(), self.flags, "flags");
        assert_eq!(v.key, &self.key[..], "key");
        assert_eq!(v.headers, &self.headers[..], "headers");
        assert_eq!(v.payload, &self.payload[..], "payload");
    }
}

/// The segment-header fields a fixture's intact-segment-header verdict pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedSegmentHeader {
    /// The monotonic segment identifier.
    pub segment_id: u64,
    /// The sequence of the first record in the segment.
    pub base_seq: u64,
    /// The log offset of the first record in the segment.
    pub base_offset: u64,
    /// The wall-clock creation time, milliseconds.
    pub created_unix_ms: u64,
    /// The reserved-in-v1 flags field.
    pub flags: u16,
}

/// One named conformance fixture: its exact on-disk bytes plus the verdict a conformant v1
/// decoder must return for them. `description` is the human-readable corpus catalogue entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixture {
    /// The stable file-stem name (the checked-in file is `<name>.bin`, or `<name>.digest` when
    /// frozen by digest).
    pub name: &'static str,
    /// A one-line description for the corpus catalogue.
    pub description: &'static str,
    /// The exact on-disk bytes.
    pub bytes: Vec<u8>,
    /// How the fixture's bytes are frozen on disk: as a raw `.bin`, or (for a multi-MiB
    /// fixture that would bloat the repo) as a small `.digest` artifact that is still a
    /// byte-exact gate.
    pub freeze: Freeze,
    /// The verdict a conformant v1 decoder (or recovery on top of it) must return.
    pub verdict: Verdict,
}

/// How a fixture's bytes are committed to the repo. Both modes are byte-EXACT gates: a single
/// flipped bit changes the committed artifact and fails CI. The digest mode exists only to keep
/// a multi-MiB fixture (the max-size record) out of the git history while still pinning its
/// exact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freeze {
    /// The raw bytes are committed as `<name>.bin` and compared byte-for-byte.
    RawBytes,
    /// A small text digest is committed as `<name>.digest` (the exact length plus three
    /// independent CRC32C checksums: over the whole frame, over the header CRC range, and over
    /// the body). The bytes are fully reproducible from the deterministic generator, so the
    /// digest is the frozen artifact and any byte drift changes it.
    Digest,
}

/// The committed digest line for a digest-frozen fixture: `len=<n> frame_crc=<hex> \
/// header_crc=<hex> body_crc=<hex>`. A pure function of the exact bytes, so it is the byte-exact
/// gate for a fixture too large to check in raw.
#[must_use]
pub fn digest_line(bytes: &[u8]) -> String {
    let frame_crc = crc32c::crc32c(bytes);
    let header_crc = crc32c::crc32c(&bytes[RECORD_HEADER_CRC_RANGE_FOR_DIGEST]);
    // The body runs from the header end to just before the (xxh3 field +) trailer; for the
    // digest we checksum the whole region between the header and the final 8-byte trailer, which
    // includes the xxh3 field when present. That is still a pure function of the exact bytes.
    let body_end = bytes.len() - RECORD_TRAILER_LEN;
    let body_crc = crc32c::crc32c(&bytes[RECORD_HEADER_LEN..body_end]);
    format!(
        "len={} frame_crc={frame_crc:08x} header_crc={header_crc:08x} body_crc={body_crc:08x}\n",
        bytes.len()
    )
}

/// The header-CRC byte range, named locally so `digest_line` does not need to import the format
/// range constant under a different name.
const RECORD_HEADER_CRC_RANGE_FOR_DIGEST: core::ops::Range<usize> = 0..32;

/// Encodes one record to its exact frame bytes. Test-only: the corpus is a test fixture, so a
/// panic on an encode error (which a fixed, in-cap input never hits) fails the test loudly.
fn frame(
    seq: u64,
    timestamp_ms: u64,
    flags: RecordFlags,
    key: &[u8],
    headers: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let rec = RecordView {
        seq: Seq::new(seq),
        timestamp_ms,
        flags,
        key,
        headers,
        payload,
    };
    let mut buf = Vec::new();
    let n = encode(&rec, &mut buf).expect("fixed in-cap fixture encodes");
    assert_eq!(n, buf.len(), "encode returns the written length");
    buf
}

/// Decodes a frame's bytes and returns the owned expected-record it yields, asserting the
/// whole frame was consumed. Used to derive an intact-record verdict from the same encoder the
/// fixture was built with, so the verdict can never drift from the bytes.
fn expect_intact(bytes: &[u8]) -> ExpectedRecord {
    let (view, consumed) = decode(bytes).expect("a freshly encoded frame decodes");
    assert_eq!(consumed, bytes.len(), "decode consumes the whole frame");
    ExpectedRecord::from_view(&view)
}

/// A deterministic, fixed byte pattern of length `len` seeded by `seed`: `b[i] = seed ^ (i &
/// 0xff)`. No randomness, no clock; the same `(seed, len)` always yields the same bytes, on
/// every platform, so a fixture built from it is byte-identical across architectures. The mask
/// keeps the index in a byte without a lossy `as` cast (pedantic-clean on every target width).
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed ^ u8::try_from(i & 0xff).expect("masked to a byte"))
        .collect()
}

/// The fixed segment header every multi-record fixture is built under (deterministic ids and a
/// fixed creation timestamp, never `now()`).
fn corpus_segment_header() -> SegmentHeader {
    SegmentHeader {
        segment_id: 7,
        base_seq: Seq::new(100),
        base_offset: Offset::new(4096),
        created_unix_ms: 1_700_000_000_000,
        flags: 0,
    }
}

/// One record's logical spec for the multi-record-segment fixtures. A named struct (not a wide
/// tuple) keeps the fixed record set readable and avoids a very-complex-type lint.
struct RecordSpec {
    seq: u64,
    timestamp_ms: u64,
    flags: RecordFlags,
    key: &'static [u8],
    headers: &'static [u8],
    payload: &'static [u8],
}

/// Builds the THREE records of the multi-record-segment fixtures (a stable, fixed set), in
/// order. Sequence starts at the header's `base_seq` so the segment is internally consistent (a
/// record's seq falls in `[base_seq, base_seq + count)`).
fn segment_record_specs() -> [RecordSpec; 3] {
    [
        RecordSpec {
            seq: 100,
            timestamp_ms: 1_700_000_000_000,
            flags: RecordFlags::EMPTY,
            key: b"alpha",
            headers: b"",
            payload: b"first-record",
        },
        RecordSpec {
            seq: 101,
            timestamp_ms: 1_700_000_000_001,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"h=1",
            payload: b"second",
        },
        RecordSpec {
            seq: 102,
            timestamp_ms: 1_700_000_000_002,
            flags: RecordFlags::COMPRESSED,
            key: b"key3",
            headers: b"",
            payload: b"third-record-payload",
        },
    ]
}

/// Encodes the segment-header bytes followed by the three records, returning the bytes and the
/// expected decoded records. Shared by the multi-record-segment fixtures (footer / no-footer /
/// torn-tail / mid-log-corruption variants), so they share one record region byte-for-byte.
fn segment_record_region() -> (Vec<u8>, Vec<ExpectedRecord>) {
    let mut bytes = corpus_segment_header().encode().to_vec();
    let mut records = Vec::new();
    for s in segment_record_specs() {
        let f = frame(s.seq, s.timestamp_ms, s.flags, s.key, s.headers, s.payload);
        records.push(expect_intact(&f));
        bytes.extend_from_slice(&f);
    }
    (bytes, records)
}

/// Generates the complete, ordered conformance corpus: every fixture the issue's acceptance
/// criteria enumerate, with byte-exact bytes and the expected verdict. The ORDER is stable so
/// the catalogue and the checked-in files line up.
#[must_use]
#[allow(clippy::too_many_lines)] // one self-documenting list of fixtures; splitting it hurts readability.
pub fn corpus() -> Vec<Fixture> {
    let mut out = Vec::new();

    // --- A minimal record: no key, no headers, a tiny payload. ----------------------------
    {
        let bytes = frame(1, 1_700_000_000_000, RecordFlags::EMPTY, b"", b"", b"x");
        let verdict = Verdict::IntactRecord(expect_intact(&bytes));
        out.push(Fixture {
            name: "record_minimal",
            freeze: Freeze::RawBytes,
            description:
                "Minimal record: no key, no headers, a one-byte payload, below the xxh3 threshold.",
            bytes,
            verdict,
        });
    }

    // --- Key only: a routing key, no headers, no payload. ---------------------------------
    {
        let bytes = frame(
            2,
            1_700_000_000_010,
            RecordFlags::EMPTY,
            b"order-42",
            b"",
            b"",
        );
        let verdict = Verdict::IntactRecord(expect_intact(&bytes));
        out.push(Fixture {
            name: "record_key_only",
            freeze: Freeze::RawBytes,
            description:
                "Key-only record: a routing key, empty headers and payload; HAS_KEY is derived.",
            bytes,
            verdict,
        });
    }

    // --- Key + headers + payload. ---------------------------------------------------------
    {
        let bytes = frame(
            3,
            1_700_000_000_020,
            RecordFlags::EMPTY,
            b"k",
            b"content-type=app/json",
            b"{\"v\":1}",
        );
        let verdict = Verdict::IntactRecord(expect_intact(&bytes));
        out.push(Fixture {
            name: "record_key_headers_payload",
            freeze: Freeze::RawBytes,
            description: "Record with a key, a headers blob, and a payload, all non-empty.",
            bytes,
            verdict,
        });
    }

    // --- A compressed record: the caller-controlled COMPRESSED flag is preserved. ---------
    {
        // The payload here is opaque stored bytes; the COMPRESSED bit only signals the codec,
        // it does not change framing. A fixed pattern keeps it byte-stable.
        let payload = pattern(0xC5, 48);
        let bytes = frame(
            4,
            1_700_000_000_030,
            RecordFlags::COMPRESSED,
            b"ckey",
            b"",
            &payload,
        );
        let verdict = Verdict::IntactRecord(expect_intact(&bytes));
        out.push(Fixture {
            name: "record_compressed",
            freeze: Freeze::RawBytes,
            description: "Compressed record: the COMPRESSED flag is set and preserved; framing is unchanged.",
            bytes,
            verdict,
        });
    }

    // --- A max-size record at the default max_record_bytes (16 MiB total frame). ----------
    // Sizing it to land EXACTLY at DEFAULT_MAX_RECORD_BYTES exercises the largest record the
    // default policy allows, including the xxh3 field (body is far over the threshold), so the
    // frozen total-size arithmetic at the boundary is pinned.
    {
        // total = header + body + xxh3(8) + trailer = DEFAULT_MAX_RECORD_BYTES (16 MiB).
        let total = ironbus_core::format::DEFAULT_MAX_RECORD_BYTES as usize;
        let body_len = total - RECORD_HEADER_LEN - RECORD_XXH3_LEN - RECORD_TRAILER_LEN;
        assert!(
            body_len >= XXH3_PAYLOAD_THRESHOLD as usize,
            "max record carries the xxh3 field"
        );
        let payload = pattern(0x5A, body_len);
        let bytes = frame(5, 1_700_000_000_040, RecordFlags::EMPTY, b"", b"", &payload);
        assert_eq!(
            bytes.len(),
            total,
            "max-size frame is exactly DEFAULT_MAX_RECORD_BYTES"
        );
        let verdict = Verdict::IntactRecord(expect_intact(&bytes));
        out.push(Fixture {
            name: "record_max_size",
            // 16 MiB raw would bloat git history, so this one fixture is frozen by a small
            // digest (still a byte-exact gate; the bytes are reproducible from the generator).
            freeze: Freeze::Digest,
            description: "Max-size record: total frame exactly DEFAULT_MAX_RECORD_BYTES (16 MiB), carrying the xxh3 field.",
            bytes,
            verdict,
        });
    }

    // --- A compressed record OVER the xxh3 threshold, so both flags ride together. --------
    {
        let payload = pattern(0x9E, XXH3_PAYLOAD_THRESHOLD as usize + 32);
        let bytes = frame(
            6,
            1_700_000_000_050,
            RecordFlags::COMPRESSED,
            b"big",
            b"",
            &payload,
        );
        let verdict = Verdict::IntactRecord(expect_intact(&bytes));
        out.push(Fixture {
            name: "record_compressed_over_threshold",
            freeze: Freeze::RawBytes,
            description: "Compressed, over-threshold record: COMPRESSED and the derived HAS_XXH3 both set; the xxh3 field is present.",
            bytes,
            verdict,
        });
    }

    // --- A multi-record segment with a clean footer (a sealed segment). -------------------
    let (region, region_records) = segment_record_region();
    {
        let count = u32::try_from(region_records.len()).expect("three records fit a u32");
        let footer = SegmentFooter {
            segment_id: corpus_segment_header().segment_id,
            last_seq: Seq::new(102),
            record_count: count,
        };
        let mut bytes = region.clone();
        bytes.extend_from_slice(&footer.encode());
        out.push(Fixture {
            name: "segment_sealed_with_footer",
            freeze: Freeze::RawBytes,
            description: "Multi-record sealed segment: a 64-byte header, three records, and a clean 32-byte footer bound to the header.",
            bytes,
            verdict: Verdict::IntactSegment {
                records: region_records.clone(),
                has_footer: true,
            },
        });
    }

    // --- An active segment with no footer (the common write-ahead-log shape). -------------
    {
        out.push(Fixture {
            name: "segment_active_no_footer",
            freeze: Freeze::RawBytes,
            description: "Active (unsealed) segment: a 64-byte header and three records, no footer; the live write-ahead-log shape.",
            bytes: region.clone(),
            verdict: Verdict::IntactSegment {
                records: region_records.clone(),
                has_footer: false,
            },
        });
    }

    // --- A torn-tail segment, truncated MID-BODY of the last record. ----------------------
    // The first two records are whole; the third's header is on disk but its body is chopped,
    // so the declared frame runs past the file end: decode -> Truncated, recovery -> TornTail.
    {
        let third_start = {
            // Header + the two whole frames preceding the third record.
            let whole_two: usize = region_records[..2].iter().map(frame_len_of).sum();
            SEGMENT_HEADER_LEN + whole_two
        };
        let mut bytes = region.clone();
        // Keep the header plus two body bytes of the third record, then chop.
        bytes.truncate(third_start + RECORD_HEADER_LEN + 2);
        out.push(Fixture {
            name: "segment_torn_tail_mid_body",
            freeze: Freeze::RawBytes,
            description: "Torn-tail segment: the last record's header landed but its body is truncated; decode is Truncated, recovery a TornTail over the partial frame.",
            verdict: Verdict::TornTruncate(LossTuple {
                reason: ReasonCode::TornTail,
                start: third_start as u64,
                end: bytes.len() as u64,
            }),
            bytes,
        });
    }

    // --- A torn-tail segment, truncated MID-TRAILER of the last record. -------------------
    // The last record's header and body landed but its 8-byte trailer was only partly written,
    // so total_len still runs past the file end: decode -> Truncated, recovery -> TornTail.
    {
        let third_start = {
            let whole_two: usize = region_records[..2].iter().map(frame_len_of).sum();
            SEGMENT_HEADER_LEN + whole_two
        };
        let mut bytes = region.clone();
        // Drop the last three trailer bytes of the final frame.
        bytes.truncate(region.len() - 3);
        out.push(Fixture {
            name: "segment_torn_tail_mid_trailer",
            freeze: Freeze::RawBytes,
            description: "Torn-tail segment: the last record's trailer is partially written; decode is Truncated, recovery a TornTail to the prior record boundary.",
            verdict: Verdict::TornTruncate(LossTuple {
                reason: ReasonCode::TornTail,
                start: third_start as u64,
                end: (region.len() - 3) as u64,
            }),
            bytes,
        });
    }

    // --- A single-bit-flip MID-LOG corruption (body of the second record). ----------------
    // The flip is inside the second record's body, so the first survives and recovery stops at
    // the second's frame start: decode of that frame -> BadBodyCrc, recovery -> CorruptRecordBody.
    {
        let first_len = frame_len_of(&region_records[0]);
        let second_start = SEGMENT_HEADER_LEN + first_len;
        let mut bytes = region.clone();
        // A body byte of the second record (just past its header).
        let flip_at = second_start + RECORD_HEADER_LEN;
        bytes[flip_at] ^= 0x01;
        out.push(Fixture {
            name: "segment_mid_log_bit_flip",
            freeze: Freeze::RawBytes,
            description: "Single-bit-flip mid-log corruption: a body byte of the second record is flipped; the first survives, recovery skips-and-reports CorruptRecordBody from the second frame to the file end.",
            verdict: Verdict::SkipAndReport(LossTuple {
                reason: ReasonCode::CorruptRecordBody,
                start: second_start as u64,
                end: region.len() as u64,
            }),
            bytes,
        });
    }

    // --- A zero-window (preallocated / zero-filled) tail. ---------------------------------
    // The record region is entirely zero-filled, modelling a freshly preallocated segment whose
    // records never landed. A zero word is not a valid record magic: decode at the region start
    // -> BadMagic, recovery -> CorruptRecordHeader over the zeroed bytes (zero records recovered).
    {
        let mut bytes = corpus_segment_header().encode().to_vec();
        bytes.resize(SEGMENT_HEADER_LEN + 256, 0);
        out.push(Fixture {
            name: "segment_zero_window_tail",
            freeze: Freeze::RawBytes,
            description: "Zero-window tail: a valid header then a zero-filled (preallocated) record region; no record decodes, recovery reports the zeroed span as a corrupt-header skip.",
            verdict: Verdict::SkipAndReport(LossTuple {
                reason: ReasonCode::CorruptRecordHeader,
                start: SEGMENT_HEADER_LEN as u64,
                end: bytes.len() as u64,
            }),
            bytes,
        });
    }

    // --- A newer-version record that v1 must reject (fail-closed). ------------------------
    // A well-formed v1 frame whose version byte is bumped to 2 (with the header CRC recomputed
    // so the VERSION check, not the CRC, is what fires). A v1 reader refuses it outright.
    {
        let mut bytes = frame(
            9,
            1_700_000_000_060,
            RecordFlags::EMPTY,
            b"k",
            b"",
            b"future",
        );
        bytes[header_offsets::VERSION] = 2;
        // Recompute the header CRC over [0, 32) so we exercise the version refusal, not a CRC fail.
        let crc = crc32c::crc32c(&bytes[ironbus_core::format::RECORD_HEADER_CRC_RANGE]);
        bytes[header_offsets::HEADER_CRC..header_offsets::HEADER_CRC + 4]
            .copy_from_slice(&crc.to_le_bytes());
        out.push(Fixture {
            name: "record_newer_version_reject",
            freeze: Freeze::RawBytes,
            description: "Newer-version record: a structurally valid frame with version byte = 2 and a recomputed header CRC; a v1 reader fails closed with UnsupportedVersion(2).",
            verdict: Verdict::FailClosedReject(DecodeError::UnsupportedVersion(2)),
            bytes,
        });
    }

    // --- A bare segment header (the segment-structure conformance leg). -------------------
    {
        let h = corpus_segment_header();
        out.push(Fixture {
            name: "segment_header",
            freeze: Freeze::RawBytes,
            description: "A standalone 64-byte segment header with fixed ids and a fixed creation timestamp.",
            bytes: h.encode().to_vec(),
            verdict: Verdict::IntactSegmentHeader(ExpectedSegmentHeader {
                segment_id: h.segment_id,
                base_seq: h.base_seq.get(),
                base_offset: h.base_offset.get(),
                created_unix_ms: h.created_unix_ms,
                flags: h.flags,
            }),
        });
    }

    out
}

/// The on-disk frame length of a record described by an [`ExpectedRecord`]: header + stored
/// body + (the xxh3 field if the stored body reaches the threshold) + trailer. Lets a fixture
/// locate per-record boundaries without re-encoding.
fn frame_len_of(r: &ExpectedRecord) -> usize {
    let body = r.key.len() + r.headers.len() + r.payload.len();
    let xxh3 = if body >= XXH3_PAYLOAD_THRESHOLD as usize {
        RECORD_XXH3_LEN
    } else {
        0
    };
    RECORD_HEADER_LEN + body + xxh3 + RECORD_TRAILER_LEN
}

/// Decodes the records out of a segment fixture's record region (everything after the 64-byte
/// header), stopping at the first non-record (a footer, a torn tail, or corruption). Returns the
/// decoded records and the byte offset where decoding stopped. The byte-identity gate uses this
/// to assert a fixture decodes to its expected record sequence on every platform.
///
/// # Panics
/// Panics (failing the test) if a frame the fixture claims is intact does not decode; that is the
/// gate firing, which is the desired behavior in a test.
#[must_use]
pub fn decode_segment_records(bytes: &[u8]) -> (Vec<ExpectedRecord>, usize) {
    let mut pos = SEGMENT_HEADER_LEN;
    let mut records = Vec::new();
    loop {
        if pos >= bytes.len() {
            break;
        }
        match decode(&bytes[pos..]) {
            Ok((view, consumed)) => {
                records.push(ExpectedRecord::from_view(&view));
                pos += consumed;
            }
            Err(_) => break,
        }
    }
    (records, pos)
}

/// Returns whether the trailing 32 bytes of `bytes` parse as a [`SegmentFooter`] bound to the
/// corpus header's `segment_id`. A clean footer must decode AND name the same segment.
#[must_use]
pub fn has_clean_footer(bytes: &[u8]) -> bool {
    if bytes.len() < SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN {
        return false;
    }
    let tail = &bytes[bytes.len() - SEGMENT_FOOTER_LEN..];
    match SegmentFooter::decode(tail) {
        Ok(f) => f.segment_id == corpus_segment_header().segment_id,
        Err(_) => false,
    }
}
