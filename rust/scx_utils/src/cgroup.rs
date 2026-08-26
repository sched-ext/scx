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

/// Size the cpu.max per-(cgroup, LLC) context map to the running system.
///
/// `cbw_cgrp_llc_map` holds one entry per LLC for each tracked cgroup. Its
/// BPF definition ships with a single-LLC default (`CBW_NR_CGRP_MAX`
/// entries) because a BPF map's `max_entries` is fixed at load time while
/// the LLC count is only known at runtime. Call this once after opening and
/// before loading the skeleton to grow it to `<cgroup cap> * nr_llcs`.
///
/// The cgroup cap is read from the sibling `cbw_cgrp_map`, so the
/// `CBW_NR_CGRP_MAX` constant stays defined only in the BPF source.
pub fn resize_cgroup_bw_llc_map(open_obj: &mut OpenObject, nr_llcs: usize) -> Result<()> {
    let cgrp_max = open_obj
        .maps_mut()
        .find(|m| m.name().to_str() == Some(CBW_CGRP_MAP))
        .map(|m| m.max_entries())
        .ok_or_else(|| anyhow!("cgroup_bw: map `{CBW_CGRP_MAP}` not found"))?;

    let max_entries = cgrp_max
        .checked_mul(nr_llcs as u32)
        .ok_or_else(|| anyhow!("cgroup_bw: `{CBW_CGRP_LLC_MAP}` size overflow"))?;

    open_obj
        .maps_mut()
        .find(|m| m.name().to_str() == Some(CBW_CGRP_LLC_MAP))
        .ok_or_else(|| anyhow!("cgroup_bw: map `{CBW_CGRP_LLC_MAP}` not found"))?
        .set_max_entries(max_entries)?;

    Ok(())
}
