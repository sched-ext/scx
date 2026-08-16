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
use libbpf_rs::btf::types::DataSec;
use libbpf_rs::btf::types::MemberAttr;
use libbpf_rs::btf::types::Struct;
use libbpf_rs::btf::types::Var;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Btf;
use libbpf_rs::MapType;
use libbpf_rs::OpenObject;
use log::info;
use log::warn;

use crate::compat::ksym_exists;

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

/// Kernel support tier for `lib/cgroup_bw` (cpu.max), detected from vmlinux BTF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupBwSupport {
    /// The kernel has no `ops.cgroup_set_bandwidth()`; cpu.max cannot be
    /// enforced. The caller must disable its `cgroup_set_bandwidth` member.
    Unsupported,
    /// `ops.cgroup_set_bandwidth()` exists but may not sleep, so per-cgroup
    /// contexts are pre-reserved during `ops.cgroup_init()`.
    Reserved,
    /// `ops.cgroup_set_bandwidth()` may sleep, so contexts are allocated on
    /// demand.
    Sleepable,
}

/// Locate the named global in the object BTF, returning its `.rodata`-style
/// section name and byte offset within that section. `None` if absent.
fn rodata_var_offset(btf: &Btf<'_>, var_name: &str) -> Option<(String, u32)> {
    for datasec in btf.type_by_kind::<DataSec>() {
        let Some(sec) = datasec.name().and_then(|n| n.to_str()) else {
            continue;
        };
        for i in 0..datasec.len() {
            let Some(vsi) = datasec.get(i) else { continue };
            let Some(var) = btf.type_by_id::<Var>(vsi.ty) else {
                continue;
            };
            if var.name().and_then(|n| n.to_str()) == Some(var_name) {
                return Some((sec.to_string(), vsi.offset));
            }
        }
    }
    None
}

/// Byte offset of `member` within struct `struct_name` in the object BTF.
/// `None` if the struct or member is absent, or the member is a bitfield.
fn struct_member_offset(btf: &Btf<'_>, struct_name: &str, member: &str) -> Option<u32> {
    let st: Struct = btf.type_by_name(struct_name)?;
    for i in 0..st.len() {
        let m = st.get(i)?;
        if m.name.and_then(|n| n.to_str()) == Some(member) {
            return match m.attr {
                MemberAttr::Normal { offset } => Some(offset / 8),
                MemberAttr::BitField { .. } => None,
            };
        }
    }
    None
}

/// Null the `cgroup_set_bandwidth` callback pointer in the scheduler's
/// struct_ops map so libbpf does not relocate it against a kernel that has no
/// such member. The struct_ops map's initial value is laid out per the object
/// BTF's `struct sched_ext_ops`, which is where the offset is read.
fn disable_set_bandwidth(open_obj: &mut OpenObject) -> Result<()> {
    let off = {
        let obj = open_obj.as_libbpf_object();
        let btf = Btf::from_bpf_object(unsafe { obj.as_ref() })?
            .ok_or_else(|| anyhow!("cgroup_bw: object has no BTF"))?;
        struct_member_offset(&btf, "sched_ext_ops", "cgroup_set_bandwidth")
            .ok_or_else(|| anyhow!("cgroup_bw: `sched_ext_ops.cgroup_set_bandwidth` not in BTF"))?
            as usize
    };
    let mut map = open_obj
        .maps_mut()
        .find(|m| m.map_type() == MapType::StructOps)
        .ok_or_else(|| anyhow!("cgroup_bw: no struct_ops map"))?;
    let data = map
        .initial_value_mut()
        .ok_or_else(|| anyhow!("cgroup_bw: struct_ops map has no initial value"))?;
    let end = off
        .checked_add(std::mem::size_of::<u64>())
        .filter(|e| *e <= data.len())
        .ok_or_else(|| anyhow!("cgroup_bw: cgroup_set_bandwidth offset {off} out of range"))?;
    data[off..end].fill(0);
    Ok(())
}

/// Detect kernel cpu.max support for `lib/cgroup_bw` and configure the library
/// accordingly. Call once between opening and loading the skeleton;
/// `set_bw_prog_name` is the name of the scheduler's `cgroup_set_bandwidth`
/// callback program.
///
/// All three tiers are handled here: on `Unsupported` the callback is disabled
/// in the struct_ops map; on `Sleepable` the callback is marked
/// `BPF_F_SLEEPABLE` and the library's `bw_set_sleepable` rodata flag is set
/// together (the flag makes the sleepable kfuncs loadable and the const makes
/// the verifier keep that path, so neither is valid without the other); on
/// `Reserved` nothing is changed. The caller only needs the returned tier if
/// it wants to log or branch on it.
pub fn setup_cgroup_bw(
    open_obj: &mut OpenObject,
    set_bw_prog_name: &str,
) -> Result<CgroupBwSupport> {
    if !ksym_exists("scx_group_set_bandwidth")? {
        disable_set_bandwidth(open_obj)?;
        warn!("cgroup_bw: cpu.max status: UNSUPPORTED (kernel lacks ops.cgroup_set_bandwidth); disabling");
        return Ok(CgroupBwSupport::Unsupported);
    }
    // The kernel advertises the sleepable ops.cgroup_set_bandwidth() allowance
    // through a BTF capability marker (see DEFINE_SCX_COMPAT_MARKER in the
    // kernel). Its absence means the callback must stay non-sleepable and
    // pre-reserve contexts.
    if !ksym_exists("scx_compat_marker_cgroup_set_bandwidth_may_sleep")? {
        info!("cgroup_bw: cpu.max status: RESERVED (contexts pre-reserved at cgroup_init)");
        return Ok(CgroupBwSupport::Reserved);
    }

    // Mark the set_bandwidth callback sleepable.
    {
        let mut prog = open_obj
            .progs_mut()
            .find(|p| p.name().to_str() == Some(set_bw_prog_name))
            .ok_or_else(|| anyhow!("cgroup_bw: program `{set_bw_prog_name}` not found"))?;
        let ptr = prog.as_libbpf_object().as_ptr();
        let flags = unsafe { libbpf_rs::libbpf_sys::bpf_program__flags(ptr) };
        prog.set_flags(flags | libbpf_rs::libbpf_sys::BPF_F_SLEEPABLE);
    }

    // Flip the matching admission gate: find `bw_set_sleepable` in the object
    // BTF, then set that byte in its rodata map's initial value. libbpf builds
    // the internal map name as "<obj-name-truncated-to-8>.rodata", so the
    // section suffix always survives and `ends_with` matches it.
    let (sec, off) = {
        let obj = open_obj.as_libbpf_object();
        let btf = Btf::from_bpf_object(unsafe { obj.as_ref() })?
            .ok_or_else(|| anyhow!("cgroup_bw: object has no BTF"))?;
        rodata_var_offset(&btf, "bw_set_sleepable")
            .ok_or_else(|| anyhow!("cgroup_bw: rodata var `bw_set_sleepable` not found"))?
    };
    let mut map = open_obj
        .maps_mut()
        .find(|m| m.name().to_str().is_some_and(|n| n.ends_with(sec.as_str())))
        .ok_or_else(|| anyhow!("cgroup_bw: internal map for `{sec}` not found"))?;
    let data = map
        .initial_value_mut()
        .ok_or_else(|| anyhow!("cgroup_bw: `{sec}` map has no initial value"))?;
    *data
        .get_mut(off as usize)
        .ok_or_else(|| anyhow!("cgroup_bw: `bw_set_sleepable` offset {off} out of range"))? = 1;

    info!("cgroup_bw: cpu.max status: SLEEPABLE (contexts allocated on demand)");
    Ok(CgroupBwSupport::Sleepable)
}
