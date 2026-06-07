// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the length-framed wire decoder (#11, #21): a malicious or corrupt client byte stream
//! must never panic the broker's frame parser, only error or report an incomplete frame.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_proto::frame::decode_frame(data);
});
