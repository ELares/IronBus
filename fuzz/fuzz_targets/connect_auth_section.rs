// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the CONNECT auth-section parser (#631, #884; refs #21, #123): `parse_connect_auth` runs on
//! the UNTRUSTED `Connect` body of a not-yet-authenticated connection — the single most hostile
//! input position in the broker (under the release profile's `panic = "abort"`, a panic here is an
//! unauthenticated remote kill). Parsing any byte string must never panic, read out of bounds, or
//! over-allocate: only `Ok(None)` (no auth section), `Ok(Some(credential))`, or a typed `BodyError`.
//! A crasher found here becomes a permanent regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_proto::message::parse_connect_auth(data);
});
