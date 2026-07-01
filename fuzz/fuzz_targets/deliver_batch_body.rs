// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the DeliverBatch body decoder (#541, #850): a hostile server's raw-framed batch is attack
//! surface for the client, so decoding any byte string must never panic or read out of bounds —
//! only return a typed BodyError or a valid (header, record_bytes) view whose borrowed record slice
//! lies WHOLLY within the input body. On Ok we then iterate the on-disk record codec over
//! record_bytes EXACTLY as the client's batch loop does (advance by the reported `consumed`), which
//! must also never panic and must make forward progress. A crasher found here becomes a permanent
//! regression seed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((_header, record_bytes)) = ironbus_proto::message::decode_deliver_batch(data) else {
        return;
    };
    // The borrowed record-bytes slice MUST be a sub-slice of the input body (everything after the
    // declared header block). Assert it in-bounds so a future edit that over-read the body, or
    // returned a slice from a different buffer, is caught here rather than as UB downstream.
    let base = data.as_ptr() as usize;
    let start = record_bytes.as_ptr() as usize;
    assert!(
        start >= base && start + record_bytes.len() <= base + data.len(),
        "decode_deliver_batch returned an out-of-bounds record slice",
    );
    // Iterate the on-disk record codec exactly as the client's batch loop does. Each frame is
    // CRC-verified and decoded; a bad frame stops the run. This must never panic, and `consumed`
    // is always > 0 for an Ok frame (a full header + trailer), so the loop always terminates — the
    // defensive `break` on a zero `consumed` keeps a fuzz iteration finite even if that ever regresses.
    let mut cursor = 0usize;
    while cursor < record_bytes.len() {
        match ironbus_core::codec::decode(&record_bytes[cursor..]) {
            Ok((_view, consumed)) => {
                if consumed == 0 {
                    break;
                }
                cursor += consumed;
            }
            Err(_) => break,
        }
    }
});
