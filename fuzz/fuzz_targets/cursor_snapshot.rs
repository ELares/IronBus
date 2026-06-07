// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the AckCursor snapshot decoder (#60, #235): a torn or hostile checkpoint payload must
//! never panic, only return a typed SnapshotError or a valid cursor.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_core::cursor::AckCursor::decode_snapshot(data);
});
