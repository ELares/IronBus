// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the compressed-unit decoder (#76, #387): it decompresses an untrusted, attacker-shaped
//! compressed payload (a descriptor + codec stream) on the read/recovery path, so it must NEVER
//! panic, read out of bounds, or allocate unbounded memory on any input. It may only return a
//! typed `DecompressError` or a valid payload, with every allocation bounded by the per-unit
//! decompressed cap. A crasher found here becomes a permanent regression seed.
//!
//! The fuzzer drives the bytes through the `COMPRESSED`-flagged decode path with the default cap,
//! so a decompression bomb (a huge claimed `uncompressed_len`) is rejected before allocation and a
//! corrupt lz4 stream returns a typed error rather than panicking. It also exercises the
//! descriptor reader on its own.
#![no_main]

use libfuzzer_sys::fuzz_target;

use ironbus_core::compress::{
    decompress_payload, read_descriptor, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES,
};
use ironbus_core::types::RecordFlags;

fuzz_target!(|data: &[u8]| {
    // The descriptor reader must never panic on a short or arbitrary buffer.
    let _ = read_descriptor(data);

    // The full compressed-unit decode path with the default decompressed cap: any input is a
    // typed error or a bounded, valid payload, never a panic and never an unbounded allocation.
    let _ = decompress_payload(
        RecordFlags::COMPRESSED,
        data,
        &NoDictionaries,
        DEFAULT_MAX_DECOMPRESSED_BYTES,
    );

    // The flag-clear path is the identity copy; exercise it too so the fuzzer covers both branches.
    let _ = decompress_payload(
        RecordFlags::EMPTY,
        data,
        &NoDictionaries,
        DEFAULT_MAX_DECOMPRESSED_BYTES,
    );
});
