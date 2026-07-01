// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the SubSubject body decoder (#851): the broker parses this untrusted subject-addressed
//! consumer frame body from the leader ingress, so decoding any byte string must never panic or read
//! out of bounds, only return a typed BodyError or a valid view. A crasher found here becomes a
//! permanent regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_proto::message::decode_sub_subject(data);
});
