# IronBus fuzz targets

Coverage-guided fuzzing of every parser that reads untrusted or possibly corrupt bytes
(issues [#21](https://github.com/ELares/IronBus/issues/21),
[#123](https://github.com/ELares/IronBus/issues/123)). The crate's property tests already
round-trip structured inputs; these targets drive the raw decoders with libFuzzer's
mutated byte strings under AddressSanitizer, so an out-of-bounds read or a panic on a
hostile or brownout-corrupted input surfaces as a crash rather than in production.

The contract every target asserts is the same one the proptests assume: on **any** input
the parser only returns a typed error or a valid view, it never panics and never reads out
of bounds.

## Targets

| Target | Parser | Why it matters |
| --- | --- | --- |
| `record_codec` | `ironbus_core::codec::decode` / `decoded_len` | The record-frame decoder runs on the recovery and delivery paths. |
| `frame_decode` | `ironbus_proto::frame::decode_frame` | The length-framed wire decoder reads bytes straight off a client socket. |
| `cursor_snapshot` | `ironbus_core::cursor::AckCursor::decode_snapshot` | A torn or hostile durable checkpoint payload must not crash recovery. |
| `segment_scan` | `ironbus_storage::segment::SegmentReader` scan and recovery | The most security-critical parser: it runs on every startup over on-disk bytes a power cut may have corrupted. |

## Running locally

The crate is detached from the main workspace (it has its own empty `[workspace]` table) so
the stable, merge-blocking workspace is never built with the nightly sanitizer toolchain.
cargo-fuzz needs a nightly toolchain:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# Soak one target (Ctrl-C to stop), or bound it with -max_total_time=<seconds>.
cargo +nightly fuzz run record_codec -- -max_total_time=60

# Build every target without running, to check they still compile.
cargo +nightly fuzz build
```

A crash drops the offending input under `fuzz/artifacts/<target>/`. Minimize it
(`cargo +nightly fuzz tmin <target> <crash-file>`) and add the minimized input as a
permanent regression seed.

## CI

The nightly workflow's `fuzz` job soaks every target for a few minutes under ASan on each
run. A crash fails the job and uploads the crashing input as an artifact for triage. The
build outputs, the discovered corpora, and the crash artifacts are git-ignored;
`Cargo.lock` is committed so a soak is reproducible.
