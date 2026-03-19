// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// Scheduling support modules used by the current Cognis design:
//   - Heuristic task classifier (observability + light behavioral hints)
//   - Deterministic slice controller (load-driven, zero-alloc)
//   - Trust table (kept for observability and exit cleanup)

pub mod classifier;
pub mod policy;
pub mod trust;

// Re-export the most commonly used types for convenience.
pub use classifier::{HeuristicClassifier, TaskFeatures, TaskLabel};
pub use policy::SliceController;
pub use trust::{ExitObservation, TrustTable, SHAME_MAX};
