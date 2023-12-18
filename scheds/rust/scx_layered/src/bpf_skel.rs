// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// We can't directly include the generated skeleton in main.rs as it may
// contain compiler attributes that can't be `include!()`ed via macro and we
// can't use the `#[path = "..."]` because `concat!(env!("OUT_DIR"),
// "/bpf.skel.rs")` does not work inside the path attribute yet (see
// https://github.com/rust-lang/rust/pull/83366).

include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
