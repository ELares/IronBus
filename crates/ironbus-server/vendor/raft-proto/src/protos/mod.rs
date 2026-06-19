// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vendored protobuf modules for `raft-proto`.
//!
//! `eraftpb` is a FILE module (not an inline `mod`) on purpose: the pre-generated
//! rust-protobuf output opens with inner attributes (`#![allow(...)]`), which are only
//! valid as the first tokens of a file module. Declaring it here (rather than
//! `include!`-ing it inside an inline `mod {}`) keeps those inner attributes legal.

pub mod eraftpb;
