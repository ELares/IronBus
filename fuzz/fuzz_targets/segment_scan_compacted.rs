// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the v2 COMPACTED recovery parser (#847): `scan_compacted`, `compacted_byte_positions`,
//! and `scan_compacted_range` decode the trailing footer + 44-byte compaction-metadata block and
//! walk the sparse survivor region of a compacted segment on EVERY startup over untrusted on-disk
//! bytes a brownout or attacker may have corrupted. The dense `segment_scan` fuzzer cannot reach
//! them: random bytes never satisfy the header magic + CRC, and even then `is_compacted()` needs
//! the version and the COMPACTED flag to agree, so the v2 parsers are effectively unreachable
//! there. This structure-aware target PREPENDS a valid v2 compacted header (correct magic/CRC,
//! COMPACTED flag) so every input lands squarely in the v2 length/slice arithmetic the issue flags
//! (`footer_start = block_start - footer_len`, `body_len = footer_start.saturating_sub(header_end)`,
//! the frame walk, the `cursor == footer_start - header_end` tail check). It must NEVER panic, only
//! return `Ok(None)`, a typed `Err`, or a bounded valid prefix.
#![no_main]

use ironbus_core::format::{SEGMENT_FLAG_COMPACTED, SEGMENT_HEADER_LEN};
use ironbus_core::segment::SegmentHeader;
use ironbus_core::types::{Offset, Seq};
use ironbus_storage::io::{InMemoryFile, RandomAccessFile};
use ironbus_storage::segment::SegmentReader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first 12 bytes drive the arbitrary `scan_compacted_range` arguments; the remainder is the
    // trailing survivor-body + footer + meta region appended after the synthesized header. Short
    // inputs still run (zero-filled control, empty body), so the early length guards are exercised.
    let mut ctrl = [0u8; 12];
    let split = data.len().min(12);
    ctrl[..split].copy_from_slice(&data[..split]);
    let body = &data[split..];

    // A fixed, CRC-valid v2 compacted header with an identity offset-minus-seq delta (base_offset
    // == base_seq). Fixing the header spends all fuzzer entropy on the trailing region — the
    // OOB/panic surface the issue targets — instead of on re-deriving a valid header each run.
    let base_seq = 1u64;
    let base_off = 1u64;
    let header = SegmentHeader {
        segment_id: 1,
        base_seq: Seq::new(base_seq),
        base_offset: Offset::new(base_off),
        created_unix_ms: 0,
        flags: SEGMENT_FLAG_COMPACTED,
    };

    let file = InMemoryFile::new();
    if file.write_all_at(&header.encode(), 0).is_err() {
        return;
    }
    if file.write_all_at(body, SEGMENT_HEADER_LEN as u64).is_err() {
        return;
    }
    // A header we just encoded with the COMPACTED flag must always decode; a failure here is an
    // environment error, not a parser bug, so drop the input rather than assert.
    let Ok(reader) = SegmentReader::open(file) else {
        return;
    };

    // The two whole-segment v2 parsers: each must return a typed result, never panic, on ANY
    // trailing region (torn footer/meta, garbage frames, an inconsistent record count or length).
    let _ = reader.scan_compacted();
    let _ = reader.compacted_byte_positions();

    // The seek-forward range read over ARBITRARY start_byte / read_end / max / max_bytes. Clamp the
    // two byte cursors to the file length so the single-shot buffer allocation stays bounded by the
    // input size: an unbounded `read_end` would be a trivial allocation bomb, not the length/slice
    // arithmetic bug class under test. Everything else is fed straight from the fuzzer.
    let file_len = SEGMENT_HEADER_LEN as u64 + body.len() as u64;
    let start_byte =
        u64::from(u32::from_le_bytes([ctrl[0], ctrl[1], ctrl[2], ctrl[3]])) % (file_len + 1);
    let read_end =
        u64::from(u32::from_le_bytes([ctrl[4], ctrl[5], ctrl[6], ctrl[7]])) % (file_len + 1);
    let max = usize::from(u16::from_le_bytes([ctrl[8], ctrl[9]]) % 64);
    let mb_raw = u16::from_le_bytes([ctrl[10], ctrl[11]]);
    let max_bytes = if mb_raw == 0 {
        None
    } else {
        Some(usize::from(mb_raw) % (body.len() + 1))
    };
    let _ = reader.scan_compacted_range(start_byte, base_off, base_seq, read_end, max, max_bytes);
});
