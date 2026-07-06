// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the password credential-material unpacker (#631, #884; refs #21, #123):
//! `unpack_password_material` splits ATTACKER-SUPPLIED credential bytes (two u16-length-prefixed
//! fields, username then password) on a not-yet-authenticated connection, BEFORE the Argon2id
//! verify runs. Under the release profile's `panic = "abort"`, a panic here is an unauthenticated
//! remote kill, so unpacking any byte string must never panic or read out of bounds: only a valid
//! `(username, password)` view pair or a typed `BodyError`. A crasher found here becomes a
//! permanent regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ironbus_proto::message::unpack_password_material(data);
});
