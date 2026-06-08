// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmark contrasting the realized CRC32C path against a portable,
//! table-driven reference (#386, the #112 residual).
//!
//! CRC32C (Castagnoli) is the resync-gating checksum on every record frame and segment
//! header/footer (`ironbus_core::format`), computed via the `crc32c` crate. That crate
//! AUTO-SELECTS its implementation at runtime: on `x86_64` it uses the SSE4.2 `crc32` instruction
//! when present, on `aarch64` it uses the `ARMv8` CRC extension when present, and otherwise it falls
//! back to a software table. It does NOT expose a public portable-only entry point (its `sw`
//! module is private), so this bench cannot call the crate's own fallback in isolation. Instead it
//! benches two things over the same fixed inputs and is HONEST about each:
//!
//! 1. `crate/realized`: `crc32c::crc32c`, the path the broker actually runs. On a CPU with the
//!    instruction (the usual `x86_64` dev/CI box, and an `ARMv8.0-A`+CRC core) this is the
//!    hardware-accelerated path; on a CPU without it the crate's own software fallback. The
//!    benchmark name says "realized" precisely because which one runs is decided at runtime by the
//!    host CPU, not by this bench.
//! 2. `portable/table`: a simple, self-contained, `#[forbid(unsafe_code)]`-clean table-driven
//!    CRC32C included in this bench as a portability REFERENCE. It is the same algorithm (the
//!    reflected Castagnoli polynomial `0x82F6_3B78`) and is verified against `crc32c::crc32c` for a
//!    fixed input before the timing loop, so the comparison is apples-to-apples. It is NOT the
//!    `crc32c` crate's internal fallback; it is a reference so the realized-vs-portable speedup is
//!    visible on any host (the realized path equals this table when no hardware CRC exists).
//!
//! Both paths are architecture-neutral source (no x86-only intrinsics in this file), so the same
//! `cargo bench -p ironbus-core` runs on an aarch64 reference core (the ARM device residual; the
//! committed numbers are x86). Inputs are fixed bytes (deterministic, no ambient randomness) and
//! `black_box` hides them from the optimizer. Run on demand (`cargo bench -p ironbus-core`), NOT in
//! per-PR CI; the regression gate is tracked separately (#114).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Representative checksum input sizes: a 64 B record-ish body, a 4 KiB body, and a 64 KiB body
/// (the `XXH3_PAYLOAD_THRESHOLD`, the largest body the CRC alone still gates). They bracket the
/// per-call fixed overhead (small inputs) against the steady-state per-byte rate (large inputs).
const SIZES: [usize; 3] = [64, 4 * 1024, 64 * 1024];

/// The reflected CRC32C (Castagnoli) polynomial, `0x1EDC6F41` reflected to `0x82F6_3B78`. This is
/// the same polynomial the `crc32c` crate and the on-disk format use; a portable reference must use
/// it so the two paths produce identical checksums.
const CASTAGNOLI_REFLECTED: u32 = 0x82F6_3B78;

/// Builds the 256-entry CRC32C lookup table for the byte-at-a-time portable reference. Pure const
/// arithmetic (shifts and xors), no unsafe, no intrinsics, so it compiles and runs on any target.
fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ CASTAGNOLI_REFLECTED
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// A portable, table-driven CRC32C over `data`, matching `crc32c::crc32c`'s output bit-for-bit (the
/// standard CRC32C init/final xor with `0xFFFF_FFFF`). This is the architecture-neutral REFERENCE
/// the realized path is compared against; it is not the crate's private fallback.
fn crc32c_portable(table: &[u32; 256], data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let idx = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// Builds a deterministic input of `len` bytes: a fixed byte ramp, never random, so every run
/// checksums the identical bytes.
fn input(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// The realized `crc32c::crc32c` path (hardware-accelerated when the host CPU has the instruction,
/// the crate's software fallback otherwise) versus the portable table-driven reference, over the
/// same fixed inputs. Throughput is the input size so the per-byte rates are directly comparable;
/// the realized-over-portable ratio is the hardware speedup on a CRC-capable host.
fn bench_crc32c(c: &mut Criterion) {
    let table = build_table();
    let mut group = c.benchmark_group("crc32c");
    for &size in &SIZES {
        let data = input(size);
        // Sanity: the portable reference and the crate agree on these inputs, so the two timed
        // paths compute the SAME checksum (an apples-to-apples comparison, not two different CRCs).
        assert_eq!(
            crc32c_portable(&table, &data),
            crc32c::crc32c(&data),
            "the portable reference must match the crc32c crate for size {size}"
        );
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("realized", size), &data, |b, data| {
            b.iter(|| black_box(crc32c::crc32c(black_box(data))));
        });
        group.bench_with_input(BenchmarkId::new("portable", size), &data, |b, data| {
            b.iter(|| black_box(crc32c_portable(black_box(&table), black_box(data))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_crc32c);
criterion_main!(benches);
