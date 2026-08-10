// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
// Author: Changwoo Min <changwoo@igalia.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Userspace helpers for the cgroup-related BPF libraries. Currently this
//! covers `lib/cgroup_bw` (cpu.max); a scheduler that links it calls the
//! helper below once between opening and loading its skeleton.

use anyhow::anyhow;
use anyhow::Result;
use libbpf_rs::OpenObject;

/// Per-cgroup context map defined in `lib/cgroup_bw.bpf.c`.
const CBW_CGRP_MAP: &str = "cbw_cgrp_map";
/// Per-(cgroup, LLC) context map defined in `lib/cgroup_bw.bpf.c`.
const CBW_CGRP_LLC_MAP: &str = "cbw_cgrp_llc_map";
/// cgroup-id tables sized in lockstep with the cgroup cap.
const CBW_CGROUP_IDS: &str = "cbw_cgroup_ids";
const CBW_THROTTLED_CGROUP_IDS: &str = "cbw_throttled_cgroup_ids";
/// Per-level accumulator map, sized to the cgroup nesting-depth cap.
const CBW_TREE_LEVELS_MAP: &str = "tree_levels_map";

fn set_map_max_entries(open_obj: &mut OpenObject, name: &str, max_entries: u32) -> Result<()> {
    open_obj
        .maps_mut()
        .find(|m| m.name().to_str() == Some(name))
        .ok_or_else(|| anyhow!("cgroup_bw: map `{name}` not found"))?
        .set_max_entries(max_entries)?;
    Ok(())
}

/// Size the `lib/cgroup_bw` (cpu.max) BPF maps for the running system.
///
/// Call once between opening and loading the skeleton. A BPF map's
/// `max_entries` is fixed at load time, so every runtime-dependent size is set
/// here:
///
/// - `nr_cgrp_max` caps the number of managed cgroups: it sizes `cbw_cgrp_map`
///   and the two cgroup-id tables. The caller must mirror it to the
///   `nr_cgrp_max` rodata so the BPF admission gate matches the map sizes.
/// - `tree_height_max` caps the managed cgroup nesting depth: it sizes
///   `tree_levels_map` (a per-CPU per-level accumulator). The caller must
///   mirror it to the `tree_height_max` rodata.
/// - `nr_llcs` sizes `cbw_cgrp_llc_map` (one entry per LLC per tracked cgroup)
///   to `nr_cgrp_max * nr_llcs`.
pub fn resize_cgroup_bw(
    open_obj: &mut OpenObject,
    nr_cgrp_max: u32,
    tree_height_max: u32,
    nr_llcs: usize,
) -> Result<()> {
    for name in [CBW_CGRP_MAP, CBW_CGROUP_IDS, CBW_THROTTLED_CGROUP_IDS] {
        set_map_max_entries(open_obj, name, nr_cgrp_max)?;
    }

    set_map_max_entries(open_obj, CBW_TREE_LEVELS_MAP, tree_height_max)?;

    let llc_max = nr_cgrp_max
        .checked_mul(nr_llcs as u32)
        .ok_or_else(|| anyhow!("cgroup_bw: `{CBW_CGRP_LLC_MAP}` size overflow"))?;
    set_map_max_entries(open_obj, CBW_CGRP_LLC_MAP, llc_max)?;

    Ok(())
}
