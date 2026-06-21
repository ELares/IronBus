// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one CRC32C entry point IronBus uses for record / segment / cursor integrity.
//!
//! Every IronBus on-disk integrity check (the record-frame header + body CRCs in
//! [`crate::codec`], the segment header/footer CRCs in [`crate::segment`], and the durable geo
//! resume-cursor file in `ironbus-server`'s `cluster::geo`) hashes with the SAME Castagnoli CRC32C
//! polynomial via the `crc32c` crate, which auto-selects the hardware SSE4.2 / ARMv8-CRC instruction at
//! runtime and falls back to a portable table. This thin re-export gives callers OUTSIDE `ironbus-core`
//! (notably `ironbus-server`'s durable cursor) ONE stable, IO-free CRC32C without each crate taking a
//! direct `crc32c` dependency, so the integrity hash is one function for the whole project.

/// Compute the CRC32C (Castagnoli) checksum of `bytes`. Hardware-accelerated where available, portable
/// elsewhere — the SAME hash the record and segment integrity checks use.
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32c::crc32c(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_matches_the_underlying_crate_and_is_deterministic() {
        assert_eq!(crc32c(b"ironbus"), crc32c::crc32c(b"ironbus"));
        assert_eq!(crc32c(b""), crc32c(b""));
        assert_ne!(crc32c(b"a"), crc32c(b"b"));
    }
}
