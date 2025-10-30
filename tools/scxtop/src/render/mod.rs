// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// Process and thread rendering
pub mod process;
// Memory rendering
pub mod memory;

pub use memory::MemoryRenderer;
pub use process::ProcessRenderer;
