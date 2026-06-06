// SPDX-License-Identifier: MIT OR Apache-2.0
//! Internal little-endian read helpers shared by the record and segment codecs.

#[inline]
pub(crate) fn read_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[inline]
pub(crate) fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[inline]
pub(crate) fn read_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}
