// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the producer-sequence snapshot decoder (#834): a torn or hostile durable checkpoint
//! payload must never panic, only return a typed `SeqSnapshotError` or a valid high-water set.
//! Mirrors the sibling `cursor_snapshot` target for the idempotent-producer high-water map.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_core::producer_seq::decode_seq_snapshot(data);
});
