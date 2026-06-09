// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the INFO handshake body decoder (#292, refs #21, #123): a malicious server's Info advertisement
//! is attack surface for the client (which parses it to adopt the negotiated per-consumer credit), so
//! decoding any byte string must never panic, read out of bounds, or over-allocate (the declared field
//! length is cap-before-alloc bounded against the actual body), only return a typed BodyError or a
//! valid view. A crasher found here becomes a permanent regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_proto::message::decode_info(data);
});
