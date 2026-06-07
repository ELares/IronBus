// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the segment recovery scan (#7, #21): the reader parses untrusted on-disk bytes during
//! recovery, so scanning any byte string must never panic, only error or yield a bounded valid
//! prefix. This is the most security-critical parser: it runs on every startup over disk bytes
//! an attacker or a brownout may have corrupted.
#![no_main]

use ironbus_storage::io::{InMemoryFile, RandomAccessFile};
use ironbus_storage::segment::SegmentReader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let file = InMemoryFile::new();
    if file.write_all_at(data, 0).is_err() {
        return;
    }
    if let Ok(reader) = SegmentReader::open(file) {
        let _ = reader.scan();
        let _ = reader.scan_recovery();
    }
});
