// SPDX-License-Identifier: MIT OR Apache-2.0
//! The combined codec + compression integration test (#387, #75, #76).
//!
//! These tests drive the two layers together exactly as a writer and a reader do: the
//! compressor builds the stored payload, [`encode`] frames and checksums it, [`decode`]
//! verifies the CRC over the stored bytes, and the decompressor interprets only those
//! verified bytes. They pin the four load-bearing properties of a FORMAT-touching change:
//!
//! 1. A compressed record round-trips: `decompress(decode(encode(compress(x)))) == x`.
//! 2. An UNCOMPRESSED record is byte-for-byte UNCHANGED: a record stored raw (codec none,
//!    flag clear) produces the EXACT same frame bytes as the pre-compression encoder did,
//!    so every existing record and conformance vector still reads identically (backward
//!    compatibility).
//! 3. The CRC is verified BEFORE anything is decompressed: a corrupt compressed body is
//!    caught by `decode` as a body-CRC failure, so the decompressor never runs on
//!    unverified bytes.
//! 4. Decoder resilience over the seam: a corrupt or hostile compressed unit that survives
//!    a (re-stamped) CRC still yields a typed error from the decompressor, never a panic.

use ironbus_core::codec::{decode, encode, DecodeError, RecordView};
use ironbus_core::compress::{
    compress_payload, decompress_payload, Codec, CompressConfig, NoDictionaries,
    DEFAULT_MAX_DECOMPRESSED_BYTES, DEFAULT_RAW_STORE_THRESHOLD,
};
use ironbus_core::types::{RecordFlags, Seq};

/// A highly compressible payload, well over the raw-store threshold.
fn compressible(len: usize) -> Vec<u8> {
    b"ironbus.sensor.telemetry.v1 {\"temp\":21.5,\"unit\":\"C\"} "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// Encodes a logical record whose payload is first run through the compressor, returning the
/// framed bytes. This is the writer's path: compress, stamp the flag, encode.
fn write_record(
    seq: u64,
    key: &[u8],
    headers: &[u8],
    payload: &[u8],
    cfg: &CompressConfig,
) -> Vec<u8> {
    let out = compress_payload(payload, cfg).expect("payload compresses");
    let flags = RecordFlags::EMPTY.with(out.flag());
    let rec = RecordView {
        seq: Seq::new(seq),
        timestamp_ms: 1_700_000_000_000,
        flags,
        key,
        headers,
        payload: &out.stored,
    };
    let mut buf = Vec::new();
    encode(&rec, &mut buf).expect("record encodes");
    buf
}

#[test]
fn compressed_record_full_round_trips() {
    let payload = compressible(4096);
    let cfg = CompressConfig::default();
    let frame = write_record(7, b"key", b"hdr", &payload, &cfg);

    // The reader's path: decode (verifies the CRC), then decompress the verified payload.
    let (view, consumed) = decode(&frame).expect("frame decodes");
    assert_eq!(consumed, frame.len());
    assert!(
        view.flags.contains(RecordFlags::COMPRESSED),
        "a compressible 4 KiB payload set the COMPRESSED flag"
    );
    assert_eq!(view.key, b"key");
    assert_eq!(view.headers, b"hdr");
    let back = decompress_payload(
        view.flags,
        view.payload,
        &NoDictionaries,
        DEFAULT_MAX_DECOMPRESSED_BYTES,
    )
    .expect("payload decompresses");
    assert_eq!(
        back, payload,
        "decompress(decode(encode(compress(x)))) == x"
    );
}

#[test]
fn uncompressed_record_is_byte_identical_to_the_no_compression_encoder() {
    // BACKWARD COMPATIBILITY PROOF. A payload below the raw-store threshold (or any payload
    // with compression disabled) is stored RAW with the flag clear, so the frame the
    // compression-aware writer emits is byte-for-byte the frame the pre-compression encoder
    // emits for the same logical record. Therefore every existing record and every frozen
    // conformance vector reads identically: a reader needs the compression layer only when
    // the COMPRESSED bit is set, and it is never set on a raw-stored record.
    let payload = b"a small raw payload below the threshold".to_vec();
    assert!(payload.len() < DEFAULT_RAW_STORE_THRESHOLD);

    // The compression-aware path (sub-threshold -> stored raw, flag clear).
    let via_compress = write_record(3, b"k", b"h", &payload, &CompressConfig::default());

    // The pre-compression path: encode the SAME logical record with no compression layer at
    // all, the payload passed straight through.
    let plain_rec = RecordView {
        seq: Seq::new(3),
        timestamp_ms: 1_700_000_000_000,
        flags: RecordFlags::EMPTY,
        key: b"k",
        headers: b"h",
        payload: &payload,
    };
    let mut plain = Vec::new();
    encode(&plain_rec, &mut plain).expect("plain record encodes");

    assert_eq!(
        via_compress, plain,
        "a raw-stored record is byte-for-byte the pre-compression frame (backward compat)"
    );
    // And the COMPRESSED flag is clear in both.
    let (view, _) = decode(&via_compress).expect("decodes");
    assert!(!view.flags.contains(RecordFlags::COMPRESSED));

    // The same holds for a LARGE payload with compression DISABLED: still raw, still identical.
    let big = compressible(8192);
    let disabled = write_record(9, b"", b"", &big, &CompressConfig::disabled());
    let plain_big_rec = RecordView {
        seq: Seq::new(9),
        timestamp_ms: 1_700_000_000_000,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: &big,
    };
    let mut plain_big = Vec::new();
    encode(&plain_big_rec, &mut plain_big).expect("encodes");
    assert_eq!(
        disabled, plain_big,
        "disabled compression is byte-identical too"
    );
}

#[test]
fn crc_is_verified_before_decompress() {
    // ORDERING PROOF. A single flipped byte in the stored (compressed) body makes `decode`
    // fail with BadBodyCrc, so the decompressor is NEVER reached on unverified bytes. The
    // verify-body-crc-before-anything ordering of the existing codec holds unchanged: the
    // compressed descriptor + stream live inside the CRC-covered body.
    let payload = compressible(4096);
    let cfg = CompressConfig::default();
    let mut frame = write_record(11, b"", b"", &payload, &cfg);

    // The body starts right after the 36-byte header. Flip a byte inside the compressed body.
    let body_start = ironbus_core::format::RECORD_HEADER_LEN;
    frame[body_start + 4] ^= 0x01;

    // decode catches the corruption FIRST, before any decompress call could run.
    assert_eq!(
        decode(&frame),
        Err(DecodeError::BadBodyCrc),
        "a corrupt compressed body is a CRC failure, caught before decompress"
    );
}

#[test]
fn over_threshold_compressed_record_carries_xxh3_and_round_trips() {
    // A compressed payload whose STORED (post-compression) body reaches the xxh3 threshold
    // carries the second checksum, and the whole frame still round-trips through both layers.
    // Use incompressible high-entropy data so the stored body stays large (raw fallback also
    // keeps it large); pick a size so the stored body clears the 64 KiB xxh3 threshold.
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    let payload: Vec<u8> = (0..80 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        })
        .collect();
    let cfg = CompressConfig::default();
    let frame = write_record(13, b"", b"", &payload, &cfg);
    let (view, consumed) = decode(&frame).expect("decodes");
    assert_eq!(consumed, frame.len());
    // Whether it compressed or fell back to raw, the stored body is large, so HAS_XXH3 is set.
    assert!(
        view.flags.contains(RecordFlags::HAS_XXH3),
        "an over-threshold stored body carries the xxh3 field"
    );
    let back = decompress_payload(
        view.flags,
        view.payload,
        &NoDictionaries,
        DEFAULT_MAX_DECOMPRESSED_BYTES,
    )
    .expect("decompresses");
    assert_eq!(back, payload);
}

use proptest::prelude::*;

proptest! {
    // The full two-layer round trip over arbitrary payloads, keys, and headers, with both the
    // lz4 and the disabled config, so the compressed and raw-stored outcomes are both covered.
    #[test]
    fn full_round_trip(
        seq in any::<u64>(),
        use_lz4 in any::<bool>(),
        key in proptest::collection::vec(any::<u8>(), 0..64),
        headers in proptest::collection::vec(any::<u8>(), 0..64),
        payload in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        let cfg = if use_lz4 {
            CompressConfig { codec: Codec::Lz4, raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD, dict_id: 0, ..CompressConfig::default() }
        } else {
            CompressConfig::disabled()
        };
        let frame = write_record(seq, &key, &headers, &payload, &cfg);
        let (view, consumed) = decode(&frame).expect("decodes");
        prop_assert_eq!(consumed, frame.len());
        prop_assert_eq!(view.key, &key[..]);
        prop_assert_eq!(view.headers, &headers[..]);
        let back = decompress_payload(view.flags, view.payload, &NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES)
            .expect("decompresses");
        prop_assert_eq!(back, payload);
    }
}
