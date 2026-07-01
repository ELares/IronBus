// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the PubTo body decoder (#851): the broker parses this untrusted stream-addressed producer
//! frame body from the leader ingress, so decoding any byte string must never panic or read out of
//! bounds, only return a typed BodyError or a valid view. PubTo is a VERBATIM carrier: on a decoded
//! view the broker feeds the `pub_body` tail straight into `decode_pub`, so drive that composition
//! here too. A crasher found here becomes a permanent regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(view) = ironbus_proto::message::decode_pub_to(data) {
        let _ = ironbus_proto::message::decode_pub(view.pub_body);
    }
});
