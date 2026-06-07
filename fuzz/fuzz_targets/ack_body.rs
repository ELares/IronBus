// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the ACK body decoder (#21, #123): the broker parses this untrusted consumer frame body,
//! so decoding any byte string must never panic or read out of bounds, only return a typed
//! BodyError or a valid view. A crasher found here becomes a permanent regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_proto::message::decode_ack(data);
});
