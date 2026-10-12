// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Idle CIDs, for a scheduler written with `#[scheduler]`: cid_idle's
//! picks over `Task` and `Cid`. The runtime keeps the idle state itself,
//! see `sched`.

use crate::{cid_idle, sched::Cid, task::Task};

pub use crate::cid_idle::{Kind, Scope};

/// Claim an idle CID of `kind` for `task` in `scope` around `anchor`,
/// among the CIDs the task may run on. `Scope::Core` tries the anchor
/// first and then its siblings. A wider scope starts at the CID after the
/// anchor and wraps.
///
/// The claim keeps other picks off the CID. It does not keep the CPU idle
/// until the task arrives.
#[inline(always)]
pub fn pick(task: &Task, anchor: Cid, scope: Scope, kind: Kind) -> Option<Cid> {
    let cid = cid_idle::pick(task, anchor, scope, kind).raw();
    if cid >= 0 { Some(Cid(cid)) } else { None }
}

/// Do `a` and `b` hold the same CIDs around `anchor`? A search that widens
/// can skip the second scope, which would repeat the first.
#[inline(always)]
pub fn scope_same(anchor: Cid, a: Scope, b: Scope) -> bool {
    cid_idle::scope_same(anchor, a, b)
}

/// Does the machine have cores of more than one CID? Without them every
/// idle CID is a whole idle core, and a `Kind::FullCore` pick is a
/// `Kind::AnyCpu` one.
#[inline(always)]
pub fn smt() -> bool {
    cid_idle::smt()
}

/// Is `cid` idle, as far as the idle tracking knows?
#[inline(always)]
pub fn test(cid: Cid) -> bool {
    cid.is_idle()
}
