// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler helpers facade.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Reexports the slice, deadline, placement, and queue helpers.
//! Tests reach the mirrors through this facade, so every reexport is used.

pub use crate::flow_cgrp::HINT_MAX;
pub use crate::flow_edf::*;
#[cfg(test)]
pub use crate::flow_preempt::*;
#[cfg(test)]
pub use crate::flow_runtime::*;
#[cfg(test)]
pub use crate::flow_select::*;
pub use crate::flow_slice::*;
// Test-only queue id mirror with no production use, so it stays out of
// the binary and only builds for tests.
#[cfg(test)]
pub use crate::flow_slot::*;
