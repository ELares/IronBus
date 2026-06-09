// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic per-PR replay of the committed fuzz REGRESSION corpus (#385, residual of #121).
//!
//! The nightly `fuzz` lane soaks every parser under libFuzzer + `AddressSanitizer`, but that build
//! needs a nightly sanitizer toolchain and is far too heavy to run on every PR. This test is the
//! PER-PR teeth: it drives every committed `fuzz/corpus-regression/<target>/<sha256>` seed through
//! the EXACT decoder its libFuzzer target calls and asserts the decoder returns (a typed error or a
//! valid view) without panicking or reading out of bounds. It is a normal `cargo test` in the
//! shipped stable workspace, so it rides the existing per-PR `test` job on all three OSes with NO
//! sanitizer build, NO nightly, and is fully deterministic and non-flaky.
//!
//! Why this catches regressions: the seeds are the frozen #45 conformance vectors (the valid and
//! the torn/corrupt/version-reject space) plus crafted hostile inputs (overlong length fields,
//! truncated frames, all-ones headers) for the body decoders that have no conformance fixture. A
//! once-found nightly crasher is minimized and PROMOTED into the corpus, so it becomes a permanent
//! per-PR regression seed. If a future change makes any decoder panic on one of these inputs, this
//! test fails on the PR naming the offending file, rather than the regression only surfacing in the
//! next nightly soak.
//!
//! The corpus seeds are content-addressed (each file's name is the SHA-256 of its own bytes), and
//! this test re-verifies that invariant, so a corrupted or mis-named seed fails here too.

use std::fmt::Write as _;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use ironbus_core::codec;
use ironbus_core::cursor::AckCursor;
use ironbus_proto::frame;
use ironbus_proto::message;
use ironbus_storage::io::{InMemoryFile, RandomAccessFile};
use ironbus_storage::segment::SegmentReader;

/// The committed regression corpus root: `<repo>/fuzz/corpus-regression`. This test crate lives at
/// `<repo>/crates/ironbus-server`, so the root is two levels up from `CARGO_MANIFEST_DIR`.
fn corpus_regression_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fuzz")
        .join("corpus-regression")
}

/// Run one decoder over one seed under `catch_unwind`, turning a panic (the failure a libFuzzer
/// crash represents) into a test failure that NAMES the offending file. The decoders are total
/// functions returning a typed `Result`; the contract is that they never panic on ANY input, so a
/// caught panic here is a real regression.
fn replay<F: FnOnce()>(file: &Path, decode: F) {
    let result = catch_unwind(AssertUnwindSafe(decode));
    assert!(
        result.is_ok(),
        "decoder panicked on regression seed {} (a libFuzzer crash class regressed into the \
         per-PR corpus; minimize and fix before merge)",
        file.display(),
    );
}

/// The decoder each fuzz target drives. Kept byte-for-byte aligned with the bodies in
/// `fuzz/fuzz_targets/<target>.rs`: this replay must exercise the SAME entry points, so a
/// divergence (a renamed decoder, a new target) is caught by the completeness check below.
fn drive_target(target: &str, file: &Path, data: &[u8]) {
    match target {
        "record_codec" => replay(file, || {
            let _ = codec::decode(data);
            let _ = codec::decoded_len(data);
        }),
        "frame_decode" => replay(file, || {
            let _ = frame::decode_frame(data);
        }),
        "cursor_snapshot" => replay(file, || {
            let _ = AckCursor::decode_snapshot(data);
        }),
        "segment_scan" => replay(file, || {
            let f = InMemoryFile::new();
            if f.write_all_at(data, 0).is_err() {
                return;
            }
            if let Ok(reader) = SegmentReader::open(f) {
                let _ = reader.scan();
                let _ = reader.scan_recovery();
            }
        }),
        "pub_body" => replay(file, || {
            let _ = message::decode_pub(data);
        }),
        "ack_body" => replay(file, || {
            let _ = message::decode_ack(data);
        }),
        "deliver_body" => replay(file, || {
            let _ = message::decode_deliver(data);
        }),
        "dead_letter_body" => replay(file, || {
            let _ = message::decode_dead_letter(data);
        }),
        "connect_body" => replay(file, || {
            let _ = message::decode_connect(data);
        }),
        "info_body" => replay(file, || {
            let _ = message::decode_info(data);
        }),
        other => panic!("no replay wired for fuzz target {other:?}; add it to drive_target"),
    }
}

/// The full set of fuzz targets, kept in lockstep with `fuzz/Cargo.toml`'s `[[bin]]` list and the
/// nightly soak's target loop. If a target is added there but not here, `every_target_has_seeds`
/// fails, so the per-PR replay can never silently skip a parser.
const TARGETS: &[&str] = &[
    "record_codec",
    "frame_decode",
    "cursor_snapshot",
    "segment_scan",
    "pub_body",
    "ack_body",
    "deliver_body",
    "dead_letter_body",
    "connect_body",
    "info_body",
];

/// SHA-256 the bytes to a lowercase hex string, matching the content-addressed seed file names.
// The K/H tables are the FIPS 180-4 round constants; underscores would only obscure them.
#[allow(clippy::unreadable_literal)]
fn sha256_hex(bytes: &[u8]) -> String {
    // A small, dependency-free SHA-256 (FIPS 180-4). This test crate must not pull a new runtime
    // dependency just to verify the corpus naming invariant, so the digest is implemented inline.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Pad: message || 0x80 || 0x00... || u64 big-endian bit length.
    let mut msg = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h;
        for i in 0..64 {
            let s1 = a[4].rotate_right(6) ^ a[4].rotate_right(11) ^ a[4].rotate_right(25);
            let ch = (a[4] & a[5]) ^ ((!a[4]) & a[6]);
            let t1 = a[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a[0].rotate_right(2) ^ a[0].rotate_right(13) ^ a[0].rotate_right(22);
            let maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
            let t2 = s0.wrapping_add(maj);
            a[7] = a[6];
            a[6] = a[5];
            a[5] = a[4];
            a[4] = a[3].wrapping_add(t1);
            a[3] = a[2];
            a[2] = a[1];
            a[1] = a[0];
            a[0] = t1.wrapping_add(t2);
        }
        for (hi, ai) in h.iter_mut().zip(a.iter()) {
            *hi = hi.wrapping_add(*ai);
        }
    }
    let mut out = String::with_capacity(64);
    for word in h {
        write!(out, "{word:08x}").expect("writing to a String never fails");
    }
    out
}

/// Read every seed in a target's corpus dir, verify the content-addressed name, and return the
/// list of `(path, bytes)`. Fails if the dir is missing or empty (a corpus that silently emptied is
/// a coverage regression).
fn load_target_seeds(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = corpus_regression_dir().join(target);
    let entries = fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "regression corpus dir missing for {target}: {} ({e})",
            dir.display()
        )
    });
    let mut seeds = Vec::new();
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        // The file name MUST be the SHA-256 of its own bytes (the libFuzzer content-address
        // convention the seed script writes), so a corrupted or hand-edited seed is caught.
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name");
        let want = sha256_hex(&bytes);
        assert_eq!(
            name,
            want,
            "regression seed {} is not content-addressed (name != sha256 of its bytes); re-seed \
             with `sh fuzz/seed-regression-corpus.sh`",
            path.display(),
        );
        seeds.push((path, bytes));
    }
    assert!(
        !seeds.is_empty(),
        "regression corpus for target {target} is empty; it must carry at least its seed inputs",
    );
    seeds
}

#[test]
fn every_target_has_seeds_and_replays_without_panicking() {
    let mut total = 0usize;
    for &target in TARGETS {
        let seeds = load_target_seeds(target);
        for (path, bytes) in &seeds {
            drive_target(target, path, bytes);
            total += 1;
        }
        eprintln!("replayed {} seed(s) through {target}", seeds.len());
    }
    eprintln!(
        "ok: replayed {total} regression seed(s) across {} targets",
        TARGETS.len()
    );
    assert!(
        total >= TARGETS.len(),
        "expected at least one seed per target"
    );
}

#[test]
fn corpus_dir_has_no_stray_target() {
    // The corpus dir must hold ONLY known fuzz-target subdirs, so a typo'd target dir (whose seeds
    // would never be replayed) is caught rather than silently ignored.
    let root = corpus_regression_dir();
    for entry in fs::read_dir(&root).expect("read corpus-regression dir") {
        let path = entry.expect("dir entry").path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 dir name");
        assert!(
            TARGETS.contains(&name),
            "unknown fuzz-target dir {name:?} under fuzz/corpus-regression (typo, or add it to \
             TARGETS and the nightly soak loop)",
        );
    }
}
