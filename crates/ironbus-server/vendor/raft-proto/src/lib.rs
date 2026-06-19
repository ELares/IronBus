// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vendored, build-script-free `raft-proto` 0.7.0.
//!
//! Upstream `raft-proto` (Apache-2.0, (c) The TiKV Project Authors) ships a `build.rs`
//! that, on every build, runs a protobuf code-generation step over `eraftpb.proto`
//! (`protobuf-build` -> `protoc`/`prost-build`). IronBus deliberately has NO build-time
//! code generation anywhere (`ironbus-proto` is hand-rolled and zero-dep), and that
//! build script touches the three gates the consensus-crate decision is most careful
//! about: the reproducible static-musl release build, the MSRV-1.78 floor, and the
//! zero-build-script / pure-Rust supply-chain posture.
//!
//! So this crate VENDORS the generated codec instead: it is a byte-for-byte drop-in for
//! `raft-proto` 0.7.0's public surface (`eraftpb`, `confchange`, `confstate`, `prelude`,
//! `util`), but with the build script removed and the generated `eraftpb` module committed
//! as source (`src/protos/eraftpb.rs`). The upstream `raft` 0.7.0 crate is pointed at this
//! copy via `[patch.crates-io] raft-proto = { path = ... }` in the workspace manifest, so
//! the IronBus build links the real, production raft-rs core while running NO `protoc` and
//! NO build-script codegen. It depends only on the pure-Rust `protobuf` 2 RUNTIME crate.
//!
//! ## Regenerating `src/protos/eraftpb.rs` (only if `raft`/`raft-proto` is bumped)
//!
//! The committed `eraftpb.rs` was produced ONCE, out-of-band, by the PURE-RUST
//! `protobuf-codegen-pure` 2.28 compiler (NO `protoc`, NO C toolchain) from upstream
//! raft-proto 0.7.0's `proto/eraftpb.proto`, with the include path pointing at
//! `protobuf-build`'s `include/` (for `rustproto.proto`, which carries the
//! `carllerche_bytes_for_bytes_all` option => `bytes::Bytes` fields, matching raft 0.7's
//! `protobuf-codec` feature). Recipe (run in a throwaway crate, then copy the output here
//! and re-prepend the SPDX + provenance header):
//!
//! ```text
//! # Cargo.toml: protobuf-codegen-pure = "=2.28.0"
//! protobuf_codegen_pure::Codegen::new()
//!     .out_dir("out")
//!     .input("<raft-proto>/proto/eraftpb.proto")
//!     .include("<raft-proto>/proto")
//!     .include("<protobuf-build>/include")  // for rustproto.proto
//!     .run().unwrap();
//! ```
//!
//! `#![allow(...)]` blankets live at the top of `eraftpb.rs` and at this crate root so the
//! generated code (and the two unmodified TiKV helper modules) never trip the workspace
//! `-D warnings` clippy/rustc gate; this crate is reached as a path/patch dependency, so it
//! IS lint-visible and must silence its own generated noise.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(warnings)]
#![allow(clippy::field_reassign_with_default)]

mod confchange;
mod confstate;

pub use crate::confchange::{
    new_conf_change_single, parse_conf_change, stringify_conf_change, ConfChangeI,
};
pub use crate::confstate::conf_state_eq;
pub use crate::protos::eraftpb;

#[path = "protos/mod.rs"]
mod protos;

mod snapshot_impl {
    use crate::protos::eraftpb::Snapshot;

    impl Snapshot {
        /// For a given snapshot, determine if it's empty or not.
        pub fn is_empty(&self) -> bool {
            self.get_metadata().index == 0
        }
    }
}

pub mod prelude {
    pub use crate::eraftpb::{
        ConfChange, ConfChangeSingle, ConfChangeTransition, ConfChangeType, ConfChangeV2,
        ConfState, Entry, EntryType, HardState, Message, MessageType, Snapshot, SnapshotMetadata,
    };
}

pub mod util {
    use crate::eraftpb::ConfState;

    impl<Iter1, Iter2> From<(Iter1, Iter2)> for ConfState
    where
        Iter1: IntoIterator<Item = u64>,
        Iter2: IntoIterator<Item = u64>,
    {
        fn from((voters, learners): (Iter1, Iter2)) -> Self {
            let mut conf_state = ConfState::default();
            conf_state.mut_voters().extend(voters.into_iter());
            conf_state.mut_learners().extend(learners.into_iter());
            conf_state
        }
    }
}
