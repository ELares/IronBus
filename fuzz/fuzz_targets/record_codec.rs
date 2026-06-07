// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the record-frame decoder (#21, #123): it parses untrusted bytes on the recovery and
//! delivery paths, so it must never panic or read out of bounds on any input, only return a
//! typed error or a valid record view. A crasher found here becomes a permanent regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_core::codec::decode(data);
    let _ = ironbus_core::codec::decoded_len(data);
});
