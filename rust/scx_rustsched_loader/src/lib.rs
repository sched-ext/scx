// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Loading and running a Rust BPF sched_ext scheduler: the object, the
//! struct_ops map the kernel can take, the configuration table's kernel
//! entries resolved from BTF, the map sizes set before the load, the
//! attach, the exit record, the arena statistics, the per-callback
//! profiler, the sampler of the per-CID queues, and the CPU capacity and
//! packing tiers the runtime ranks CIDs by. Nothing here is particular to
//! a scheduling policy.

use std::{
    collections::BTreeMap,
    ffi::{CString, OsStr},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub use anyhow::Result;
use anyhow::{Context, bail, ensure};
use libbpf_rs::{
    Btf, Link, MapCore, MapFlags, ObjectBuilder, OpenObject, ProgramType,
    btf::{
        BtfType, HasSize, ReferencesType,
        types::{
            Composite, Enum, Enum64, Func, FuncProto, Int, IntEncoding, MemberAttr, Ptr, Struct,
        },
    },
};
use log::{info, warn};
pub use scx_rustsched_abi as config;
pub use scx_rustsched_macros::Opts;
/// The kernel's sched_ext flags, 0 where it lacks one, for a scheduler's
/// user space to choose the ops flags it loads with, see `Params::add_flags()`.
pub use scx_utils::compat;
use scx_utils::{UserExitInfo, libbpf_clap_opts::LibbpfOpts};

/// The eligible deadline queue, from the source the BPF program is built
/// from: the loader reads the queues in the arena through the same code.
#[path = "../../scx_rustsched/src/edq.rs"]
pub mod edq;
mod queues;
pub mod tiers;

pub use libbpf_rs::Object;
pub use queues::{ArenaView, CidTableReader, QueueSampler, QueueStats};
pub use tiers::Tiers;

/// The attached scheduler's object, shared. What reads the arena keeps a
/// clone, and with it the arena's mapping, which goes with the object.
#[derive(Clone)]
pub struct Loaded(Arc<Object>);

impl std::ops::Deref for Loaded {
    type Target = Object;

    fn deref(&self) -> &Object {
        &self.0
    }
}

/// One struct_ops program's run count, run time and recursion misses, as
/// the kernel accounts them while the profiler is enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpStats {
    pub calls: u64,
    pub ns: u64,
    pub misses: u64,
}

/// The struct_ops map of the BPF object whose cgroup callbacks have the
/// names the running kernel gives them: cpuctl_*, or cgroup_* on a kernel
/// from before the cid form renamed them. None for a kernel built without
/// group scheduling, which has neither.
pub fn cgroup_ops() -> Result<Option<&'static str>> {
    let btf = Btf::from_vmlinux().context("read running kernel BTF")?;
    let ops = btf
        .type_by_name::<Struct<'_>>("sched_ext_ops_cid")
        .context("find sched_ext_ops_cid")?;
    let has = |name: &str| {
        Composite::from(ops)
            .iter()
            .any(|member| member.name == Some(OsStr::new(name)))
    };
    Ok(if has("cpuctl_init") {
        Some("rust_ops")
    } else if has("cgroup_init") {
        Some("rust_ops_cgroup")
    } else {
        None
    })
}

/// The byte range of the member `name` of the BPF object's struct_ops type
/// `ops`, read off its BTF.
pub fn ops_member(
    object_name: &str,
    object: &[u8],
    ops: &str,
    name: &str,
) -> Result<std::ops::Range<usize>> {
    let btf = Btf::from_raw(object_name, object)?.context("read BPF object BTF")?;
    let local = btf
        .type_by_name::<Struct<'_>>(ops)
        .with_context(|| format!("find the BPF object's {ops}"))?;
    let (field, offset) = member(&btf, local, name)?;
    let size = Int::try_from(field)
        .map_err(|_| anyhow::anyhow!("{ops}.{name} is not an integer"))?
        .size();
    let start = offset as usize;
    Ok(start..start + size)
}

/// The byte ranges, in the BPF object's struct_ops type `ops`, of the
/// cgroup callbacks the running kernel's sched_ext_ops_cid lacks, read off
/// both BTFs: all of them on a kernel built without group scheduling, the
/// newer ones on an older kernel. libbpf skips a member the kernel lacks only
/// when it is zero.
pub fn missing_callbacks(
    object_name: &str,
    object: &[u8],
    ops: &str,
) -> Result<Vec<std::ops::Range<usize>>> {
    let vmlinux = Btf::from_vmlinux().context("read running kernel BTF")?;
    let kernel = vmlinux
        .type_by_name::<Struct<'_>>("sched_ext_ops_cid")
        .context("find sched_ext_ops_cid")?;
    let kernel = Composite::from(kernel);
    let kernel: Vec<_> = kernel.iter().filter_map(|member| member.name).collect();
    let btf = Btf::from_raw(object_name, object)?.context("read BPF object BTF")?;
    let local = btf
        .type_by_name::<Struct<'_>>(ops)
        .with_context(|| format!("find the BPF object's {ops}"))?;
    Composite::from(local)
        .iter()
        .filter(|member| {
            member.name.is_some_and(|name| {
                let bytes = name.as_encoded_bytes();
                (bytes.starts_with(b"cpuctl_") || bytes.starts_with(b"cgroup_"))
                    && !kernel.contains(&name)
            })
        })
        .map(|member| match member.attr {
            MemberAttr::Normal { offset } if offset % 8 == 0 => {
                let start = offset as usize / 8;
                Ok(start..start + 8)
            }
            _ => bail!("unexpected cgroup callback member"),
        })
        .collect()
}

/// The value of the enumerator `name` in kernel BTF, if the kernel has it.
pub fn enumerator(btf: &Btf<'_>, name: &str) -> Option<u64> {
    btf.type_by_kind::<Enum<'_>>()
        .find_map(|kind| {
            kind.iter()
                .find(|value| value.name == Some(OsStr::new(name)))
                .map(|value| value.value as u64)
        })
        .or_else(|| {
            btf.type_by_kind::<Enum64<'_>>().find_map(|kind| {
                kind.iter()
                    .find(|value| value.name == Some(OsStr::new(name)))
                    .map(|value| value.value as u64)
            })
        })
}

/// Does the running kernel's scx_bpf_cid_topo() take the structure's
/// size? Such a kernel copies only the fields it has and leaves the rest
/// at -1, so its structure may still be the legacy one, without the
/// cluster fields.
pub fn sized_topology() -> Result<bool> {
    let btf = Btf::from_vmlinux().context("read running kernel BTF")?;
    let function = btf
        .type_by_name::<Func<'_>>("scx_bpf_cid_topo")
        .context("find scx_bpf_cid_topo")?;
    let prototype = FuncProto::try_from(function.referenced_type())
        .map_err(|_| anyhow::anyhow!("scx_bpf_cid_topo has no function prototype"))?;
    let topology = btf
        .type_by_name::<Struct<'_>>("scx_cid_topo")
        .context("find scx_cid_topo")?;
    match prototype.len() {
        2 => {
            ensure!(topology.size() == 32, "unexpected legacy CID topology size");
            Ok(false)
        }
        3 => {
            ensure!(
                matches!(topology.size(), 32 | 40),
                "unexpected sized CID topology size"
            );
            Ok(true)
        }
        count => bail!("unsupported scx_bpf_cid_topo argument count: {count}"),
    }
}

pub fn member<'btf>(
    btf: &'btf Btf<'_>,
    structure: Struct<'btf>,
    name: &str,
) -> Result<(BtfType<'btf>, u64)> {
    let composite = Composite::from(structure);
    let member = composite
        .iter()
        .find(|member| member.name == Some(OsStr::new(name)))
        .with_context(|| format!("kernel BTF is missing field {name}"))?;
    let MemberAttr::Normal { offset } = member.attr else {
        bail!("kernel field {name} is a bitfield");
    };
    ensure!(offset % 8 == 0, "kernel field {name} is not byte aligned");
    let field = btf
        .type_by_id::<BtfType<'_>>(member.ty)
        .context("resolve field type")?
        .skip_mods_and_typedefs();
    Ok((field, u64::from(offset / 8)))
}

/// Pages the pool of task slots starts with. It grows as tasks need more.
pub const POOL_PAGES: u32 = 512;

/// The configuration table's kernel entries: the offsets and enumerators
/// resolved from the running kernel's BTF, the pool size, the dump length,
/// the tick period and the runtime's options, a mask of `config::runtime`'s
/// bits.
pub fn configuration(dump_len: u32, runtime_options: u64) -> Result<[u64; config::WORDS]> {
    let btf = Btf::from_vmlinux().context("read running kernel BTF")?;
    let task = btf
        .type_by_name::<Struct<'_>>("task_struct")
        .context("find task_struct")?;
    let (entity, entity_offset) = member(&btf, task, "scx")?;
    let entity =
        Struct::try_from(entity).map_err(|_| anyhow::anyhow!("task_struct.scx is not a struct"))?;
    let mut values = [0; config::WORDS];
    values[config::ARENA_PAGES] = u64::from(POOL_PAGES);
    values[config::RUNTIME_OPTIONS] = runtime_options;
    values[config::TICK_NS] = tick_ns();
    for (index, name, size) in [
        (config::SCX_SLICE, "slice", 8),
        (config::SCX_FLAGS, "flags", 4),
        (config::SCX_TID, "tid", 8),
        (config::DSQ_VTIME, "dsq_vtime", 8),
    ] {
        let (field, offset) = member(&btf, entity, name)?;
        let integer =
            Int::try_from(field).map_err(|_| anyhow::anyhow!("scx.{name} is not an integer"))?;
        ensure!(
            integer.size() == size
                && integer.bits as usize == size * 8
                && integer.offset == 0
                && matches!(integer.encoding, IntEncoding::None),
            "unexpected type for scx.{name}"
        );
        let offset = entity_offset + offset;
        ensure!(
            offset % size as u64 == 0 && offset + size as u64 <= task.size() as u64,
            "invalid task offset for scx.{name}"
        );
        values[index] = offset;
    }
    let (cpus, cpus_offset) = member(&btf, task, "cpus_ptr")?;
    Ptr::try_from(cpus).map_err(|_| anyhow::anyhow!("task_struct.cpus_ptr is not a pointer"))?;
    ensure!(
        cpus_offset % 8 == 0 && cpus_offset + 8 <= task.size() as u64,
        "invalid cpus_ptr offset"
    );
    values[config::CPUS_PTR] = cpus_offset;
    let (migration, migration_offset) = member(&btf, task, "migration_disabled")?;
    let migration = Int::try_from(migration)
        .map_err(|_| anyhow::anyhow!("task_struct.migration_disabled is not an integer"))?;
    ensure!(
        migration.size() == 2
            && migration.bits == 16
            && migration.offset == 0
            && matches!(migration.encoding, IntEncoding::None)
            && migration_offset % 2 == 0
            && migration_offset + 2 <= task.size() as u64,
        "invalid migration_disabled field"
    );
    values[config::MIGRATION_DISABLED] = migration_offset;
    let (flags, flags_offset) = member(&btf, task, "flags")?;
    let flags =
        Int::try_from(flags).map_err(|_| anyhow::anyhow!("task_struct.flags is not an integer"))?;
    ensure!(
        flags.size() == 4
            && flags.bits == 32
            && flags.offset == 0
            && matches!(flags.encoding, IntEncoding::None)
            && flags_offset % 4 == 0
            && flags_offset + 4 <= task.size() as u64,
        "invalid task flags field"
    );
    values[config::TASK_FLAGS] = flags_offset;
    // sched_attr.sched_runtime lands in se.slice and sets se.custom_slice.
    let (fair, fair_offset) = member(&btf, task, "se")?;
    let fair =
        Struct::try_from(fair).map_err(|_| anyhow::anyhow!("task_struct.se is not a struct"))?;
    for (index, name, size) in [
        (config::CUSTOM_SLICE, "custom_slice", 1),
        (config::SE_SLICE, "slice", 8),
    ] {
        let (field, offset) = member(&btf, fair, name)?;
        let integer =
            Int::try_from(field).map_err(|_| anyhow::anyhow!("se.{name} is not an integer"))?;
        ensure!(
            integer.size() == size && integer.bits as usize == size * 8 && integer.offset == 0,
            "unexpected type for se.{name}"
        );
        let offset = fair_offset + offset;
        ensure!(
            offset % size as u64 == 0 && offset + size as u64 <= task.size() as u64,
            "invalid task offset for se.{name}"
        );
        values[index] = offset;
    }
    // A task with fewer CPUs allowed than there are is restricted, and its
    // fork placement counts only the CPUs it may use.
    let (allowed, allowed_offset) = member(&btf, task, "nr_cpus_allowed")?;
    let allowed = Int::try_from(allowed)
        .map_err(|_| anyhow::anyhow!("task_struct.nr_cpus_allowed is not an integer"))?;
    ensure!(
        allowed.size() == 4 && allowed.offset == 0 && allowed_offset % 4 == 0,
        "invalid nr_cpus_allowed field"
    );
    values[config::NR_CPUS_ALLOWED] = allowed_offset;
    // rq->clock_task, rq_clock_task(): the runqueue's clock less IRQ and
    // steal time, whose drift from the rq clock capacity pressure counts.
    let runqueue = btf
        .type_by_name::<Struct<'_>>("rq")
        .context("find struct rq")?;
    let (clock, clock_offset) = member(&btf, runqueue, "clock_task")?;
    let clock =
        Int::try_from(clock).map_err(|_| anyhow::anyhow!("rq.clock_task is not an integer"))?;
    ensure!(
        clock.size() == 8 && clock_offset % 8 == 0 && clock_offset + 8 <= runqueue.size() as u64,
        "invalid rq.clock_task field"
    );
    values[config::RQ_CLOCK_TASK] = clock_offset;
    // The cgroup fields group scheduling reads: a cgroup's depth, whether it
    // is still online as its cpu controller exits it, and the cpu.weight it
    // starts with. A kernel built without group scheduling has none of it.
    if let Some(args) = btf.type_by_name::<Struct<'_>>("scx_cgroup_init_args") {
        let cgroup = btf
            .type_by_name::<Struct<'_>>("cgroup")
            .context("find struct cgroup")?;
        let (level, level_offset) = member(&btf, cgroup, "level")?;
        let level =
            Int::try_from(level).map_err(|_| anyhow::anyhow!("cgroup.level is not an integer"))?;
        ensure!(
            level.size() == 4 && level_offset % 4 == 0,
            "invalid cgroup.level field"
        );
        values[config::TG_LEVEL] = level_offset;
        let (state, state_offset) = member(&btf, cgroup, "self")?;
        let state =
            Struct::try_from(state).map_err(|_| anyhow::anyhow!("cgroup.self is not a struct"))?;
        let (flags, flags_offset) = member(&btf, state, "flags")?;
        let flags = Int::try_from(flags)
            .map_err(|_| anyhow::anyhow!("cgroup.self.flags is not an integer"))?;
        ensure!(
            flags.size() == 4 && (state_offset + flags_offset) % 4 == 0,
            "invalid cgroup.self.flags field"
        );
        values[config::TG_FLAGS] = state_offset + flags_offset;
        values[config::TG_ONLINE] = btf
            .type_by_kind::<Enum<'_>>()
            .find_map(|kind| {
                kind.iter()
                    .find(|value| value.name == Some(OsStr::new("CSS_ONLINE")))
                    .map(|value| value.value as u64)
            })
            .context("find CSS_ONLINE")?;
        let (weight, weight_offset) = member(&btf, args, "weight")?;
        let weight = Int::try_from(weight)
            .map_err(|_| anyhow::anyhow!("scx_cgroup_init_args.weight is not an integer"))?;
        ensure!(
            weight.size() == 4 && weight_offset % 4 == 0,
            "invalid scx_cgroup_init_args.weight field"
        );
        values[config::TG_WEIGHT] = weight_offset;
        // The cpu.max a cgroup already has when the scheduler loads, which
        // no set_bandwidth reports. Older kernels have none of it.
        for (index, name) in [
            (config::BW_PERIOD, "bw_period_us"),
            (config::BW_QUOTA, "bw_quota_us"),
            (config::BW_BURST, "bw_burst_us"),
        ] {
            if let Ok((field, offset)) = member(&btf, args, name)
                && Int::try_from(field).is_ok_and(|field| field.size() == 8)
                && offset % 8 == 0
                && offset != 0
            {
                values[index] = offset;
            }
        }
        // The cpu controller's css pointer, cgroup.subsys[cpu_cgrp_id],
        // which is its task_group, and task_group.idle, for a cgroup made
        // idle before the scheduler was loaded.
        let (_, subsys_offset) = member(&btf, cgroup, "subsys")?;
        let cpu = btf
            .type_by_kind::<Enum<'_>>()
            .find_map(|kind| {
                kind.iter()
                    .find(|value| value.name == Some(OsStr::new("cpu_cgrp_id")))
                    .map(|value| value.value as u64)
            })
            .context("find cpu_cgrp_id")?;
        let pointer = btf.ptr_size()?.get() as u64;
        values[config::CPU_CSS] = subsys_offset + cpu * pointer;
        if let Some(group) = btf.type_by_name::<Struct<'_>>("task_group")
            && let Ok((_, css_offset)) = member(&btf, group, "css")
            && let Ok((idle, idle_offset)) = member(&btf, group, "idle")
            && css_offset == 0
            && Int::try_from(idle).is_ok_and(|idle| idle.size() == 4)
        {
            values[config::TG_IDLE] = idle_offset;
        }
        // The cgroup's id, cgroup.kn->id, by which bpf_cgroup_from_id()
        // finds a cgroup again where no op hands it over.
        if let Ok((_, node_offset)) = member(&btf, cgroup, "kn")
            && let Some(node) = btf.type_by_name::<Struct<'_>>("kernfs_node")
            && let Ok((id, id_offset)) = member(&btf, node, "id")
            && Int::try_from(id).is_ok_and(|id| id.size() == 8)
        {
            values[config::TG_KN] = node_offset;
            values[config::KN_ID] = id_offset;
        }
    }
    // The exit record ops.exit() copies, the dump context ops.dump_task()
    // reads, and the task fields that say how long a task has waited.
    let exit = btf
        .type_by_name::<Struct<'_>>("scx_exit_info")
        .context("find struct scx_exit_info")?;
    values[config::EXIT_CPU] = member(&btf, exit, "exit_cpu").map_or(0, |(_, offset)| offset + 1);
    for (index, name) in [
        (config::EXIT_CODE, "exit_code"),
        (config::EXIT_REASON, "reason"),
        (config::EXIT_MSG, "msg"),
        (config::EXIT_DUMP, "dump"),
        (config::EXIT_KIND, "kind"),
    ] {
        values[index] = member(&btf, exit, name)?.1;
    }
    values[config::DUMP_LEN] = u64::from(dump_len);
    let dump = btf
        .type_by_name::<Struct<'_>>("scx_dump_ctx")
        .context("find struct scx_dump_ctx")?;
    values[config::DUMP_AT_JIFFIES] = member(&btf, dump, "at_jiffies")?.1;
    values[config::DUMP_AT_NS] = member(&btf, dump, "at_ns")?.1;
    values[config::RUNNABLE_AT] = entity_offset + member(&btf, entity, "runnable_at")?.1;
    values[config::PID] = member(&btf, task, "pid")?.1;
    // The enqueue flags and re-enqueue reasons that say whether
    // ops.select_cid() placed a task and why the kernel handed one back,
    // and the lazy preemption flag, 0 where the kernel has none.
    for (index, name) in [
        (config::ENQ_CPU_SELECTED, "SCX_ENQ_CPU_SELECTED"),
        (config::ENQ_IMMED, "SCX_ENQ_IMMED"),
        (config::ENQ_REENQ, "SCX_ENQ_REENQ"),
        (config::REENQ_MASK, "SCX_TASK_REENQ_REASON_MASK"),
        (config::REENQ_IMMED, "SCX_TASK_REENQ_IMMED"),
        (config::REENQ_PREEMPTED, "SCX_TASK_REENQ_PREEMPTED"),
        (config::ENQ_LAST, "SCX_ENQ_LAST"),
        (config::ENQ_PREEMPT_LAZY, "SCX_ENQ_PREEMPT_LAZY"),
        (config::ENQ_BLOCKED, "SCX_ENQ_BLOCKED"),
    ] {
        values[index] = enumerator(&btf, name).unwrap_or(0);
    }
    // Whether a task is a proxy-execution donor, on a kernel that has it.
    if let Ok((blocked, offset)) = member(&btf, task, "is_blocked")
        && Int::try_from(blocked).is_ok_and(|blocked| blocked.size() == 1)
    {
        values[config::IS_BLOCKED] = offset;
    }
    // Whether the groups of a CPU's sd_llc are clusters, for the idle scan
    // to search the target's cluster first: sched_domain.groups plus one,
    // 0 where it cannot be read, sched_group.flags and SD_CLUSTER.
    if let (Some(domain), Some(group), Some(cluster)) = (
        btf.type_by_name::<Struct<'_>>("sched_domain"),
        btf.type_by_name::<Struct<'_>>("sched_group"),
        enumerator(&btf, "SD_CLUSTER"),
    ) && let (Ok((groups, groups_offset)), Ok((flags, flags_offset))) =
        (member(&btf, domain, "groups"), member(&btf, group, "flags"))
        && Ptr::try_from(groups).is_ok()
        && Int::try_from(flags).is_ok_and(|flags| flags.size() == 4)
        && groups_offset % 8 == 0
        && flags_offset % 4 == 0
    {
        values[config::SD_GROUPS] = groups_offset + 1;
        values[config::SG_FLAGS] = flags_offset;
        values[config::SD_CLUSTER] = cluster;
    }
    // The task's load weight, set_load_weight(): its nice level, or
    // WEIGHT_IDLEPRIO for SCHED_IDLE.
    for (index, name) in [
        (config::STATIC_PRIO, "static_prio"),
        (config::POLICY, "policy"),
    ] {
        let (field, offset) = member(&btf, task, name)?;
        let integer = Int::try_from(field)
            .map_err(|_| anyhow::anyhow!("task_struct.{name} is not an integer"))?;
        ensure!(
            integer.size() == 4
                && integer.bits == 32
                && integer.offset == 0
                && offset % 4 == 0
                && offset + 4 <= task.size() as u64,
            "invalid task_struct.{name} field"
        );
        values[index] = offset;
    }
    Ok(values)
}

/// The arena's size in pages, as scheds/include/lib/arena_map.h declares it:
/// address space only, backed by the pages actually allocated. An arena
/// spans at most 4 GiB, which 2^16 pages keep to with 64 KiB pages on arm64.
const ARENA_PAGES: u32 = if cfg!(target_arch = "aarch64") {
    1 << 16
} else {
    1 << 20
};

/// Open the object `object` as `name`, with libbpf's open options that
/// ObjectBuilder does not take, such as a BPF token path, as the C
/// schedulers pass them.
pub fn open(name: &str, object: &[u8], libbpf: &LibbpfOpts, verbose: bool) -> Result<OpenObject> {
    // build.rs leaves the objects empty on a host without the Rust BPF
    // toolchain, so that workspace builds do not need it.
    ensure!(
        !object.is_empty(),
        "built without the Rust BPF toolchain (rust-src, bpf-linker and \
         llvm-objcopy): install it and rebuild {name}"
    );
    let mut builder = ObjectBuilder::default();
    builder.name(name)?;
    builder.debug(verbose);
    let name = CString::new(name)?;
    Ok(match libbpf.clone().into_bpf_open_opts() {
        Some(mut opts) => {
            opts.object_name = name.as_ptr();
            let pointer = unsafe {
                libbpf_rs::libbpf_sys::bpf_object__open_mem(
                    object.as_ptr().cast(),
                    object.len() as libbpf_rs::libbpf_sys::size_t,
                    &opts,
                )
            };
            let pointer = NonNull::new(pointer).ok_or_else(|| {
                anyhow::anyhow!("open Rust BPF object: {}", std::io::Error::last_os_error())
            })?;
            unsafe { OpenObject::from_ptr(pointer) }
        }
        None => builder
            .open_memory(object)
            .context("open Rust BPF object")?,
    })
}

/// Pick the struct_ops map of the object `name` the kernel can take: the one whose cgroup
/// callbacks it knows, `cgroup_ops`, or `rust_ops` without the callbacks
/// it lacks, which are zeroed in the map's initial value. The exit dump
/// buffer is sized to `dump_len` and the map told so. Returns the map's
/// name.
pub fn select_ops(
    name: &str,
    open: &mut OpenObject,
    object: &[u8],
    cgroup_ops: Option<&'static str>,
    dump_len: u32,
) -> Result<&'static str> {
    let ops = cgroup_ops.unwrap_or("rust_ops");
    let ops_type = ops_type(ops);
    let callbacks = missing_callbacks(name, object, ops_type)?;
    let dump_length = ops_member(name, object, ops_type, "exit_dump_len")?;
    // The buffer ops.exit() copies the debug dump into, as long as the
    // dump the kernel is asked for.
    open.maps_mut()
        .find(|map| map.name() == OsStr::new(".data.uei_dump"))
        .context("find the exit dump")?
        .set_value_size(dump_len)?;
    for mut map in open.maps_mut() {
        let name = map.name().to_owned();
        if name.as_encoded_bytes().starts_with(b"rust_ops") {
            map.set_autocreate(name == OsStr::new(ops))?;
            if name == OsStr::new(ops) {
                let data = map
                    .initial_value_mut()
                    .context("initialize the struct_ops map")?;
                for range in &callbacks {
                    data.get_mut(range.clone())
                        .context("cgroup callback beyond the struct_ops map")?
                        .fill(0);
                }
                let length = dump_length.clone();
                data.get_mut(length)
                    .context("exit_dump_len beyond the struct_ops map")?
                    .copy_from_slice(&dump_len.to_ne_bytes());
            }
        }
    }
    Ok(ops)
}

/// The BPF object's struct_ops type of the map `ops`.
fn ops_type(ops: &str) -> &'static str {
    if ops == "rust_ops" {
        "sched_ext_ops_cid"
    } else {
        "sched_ext_ops_cid___cgroup"
    }
}

/// The ops flags the struct_ops map `ops` asks the kernel for, as
/// `#[scheduler]` declares them.
pub fn ops_flags(name: &str, open: &mut OpenObject, object: &[u8], ops: &str) -> Result<u64> {
    let range = ops_member(name, object, ops_type(ops), "flags")?;
    let map = open
        .maps_mut()
        .find(|map| map.name() == OsStr::new(ops))
        .context("find the struct_ops map")?;
    let bytes = map
        .initial_value()
        .and_then(|data| data.get(range))
        .context("flags beyond the struct_ops map")?;
    Ok(u64::from_ne_bytes(bytes.try_into()?))
}

/// Load the struct_ops map `ops` with the ops `flags`.
pub fn set_ops_flags(
    name: &str,
    open: &mut OpenObject,
    object: &[u8],
    ops: &str,
    flags: u64,
) -> Result<()> {
    let range = ops_member(name, object, ops_type(ops), "flags")?;
    let mut map = open
        .maps_mut()
        .find(|map| map.name() == OsStr::new(ops))
        .context("find the struct_ops map")?;
    map.initial_value_mut()
        .and_then(|data| data.get_mut(range))
        .context("flags beyond the struct_ops map")?
        .copy_from_slice(&flags.to_ne_bytes());
    Ok(())
}

/// The longest watchdog timeout the kernel takes, SCX_WATCHDOG_MAX_TIMEOUT,
/// which is also what it applies when the timeout is 0.
pub const WATCHDOG_MAX_TIMEOUT_MS: u32 = 30_000;

/// Load the struct_ops map `ops` with the watchdog timeout `timeout_ms`, in
/// place of `timeout_ms` of `#[scheduler]`.
pub fn set_ops_timeout(
    name: &str,
    open: &mut OpenObject,
    object: &[u8],
    ops: &str,
    timeout_ms: u32,
) -> Result<()> {
    // The kernel refuses a longer one with EINVAL, which says less.
    ensure!(
        timeout_ms <= WATCHDOG_MAX_TIMEOUT_MS,
        "the watchdog timeout is at most {WATCHDOG_MAX_TIMEOUT_MS} ms, not {timeout_ms}"
    );
    let range = ops_member(name, object, ops_type(ops), "timeout_ms")?;
    let mut map = open
        .maps_mut()
        .find(|map| map.name() == OsStr::new(ops))
        .context("find the struct_ops map")?;
    map.initial_value_mut()
        .and_then(|data| data.get_mut(range))
        .context("timeout_ms beyond the struct_ops map")?
        .copy_from_slice(&timeout_ms.to_ne_bytes());
    Ok(())
}

/// The length of the debug dump the scheduler's struct_ops map asks for,
/// `dump_len` of `#[scheduler]`.
pub fn declared_dump_len(name: &str, open: &mut OpenObject, object: &[u8]) -> Result<u32> {
    let range = ops_member(name, object, "sched_ext_ops_cid", "exit_dump_len")?;
    let mut map = open
        .maps_mut()
        .find(|map| map.name() == OsStr::new("rust_ops"))
        .context("find the struct_ops map")?;
    let bytes = map
        .initial_value_mut()
        .context("read the struct_ops map")?
        .get(range)
        .context("exit_dump_len beyond the struct_ops map")?;
    // Zero asks the kernel for its default.
    Ok(match u32::from_ne_bytes(bytes.try_into()?) {
        0 => EXIT_DUMP_DEFAULT,
        length => length,
    })
}

/// Size the arena and, when the object has them, the hrtick timers, one
/// per CID. CIDs are dense and never exceed nr_cpu_ids.
pub fn size_maps(open: &mut OpenObject) -> Result<()> {
    open.maps_mut()
        .find(|map| map.name() == OsStr::new("arena"))
        .context("find arena map")?
        .set_max_entries(ARENA_PAGES)?;
    for mut map in open
        .maps_mut()
        .filter(|map| map.name() == OsStr::new("hrticks"))
    {
        map.set_max_entries(libbpf_rs::num_possible_cpus()? as u32)?;
    }
    Ok(())
}

/// Fill the frozen configuration table with `config`.
pub fn set_config(open: &mut OpenObject, config: &[u64]) -> Result<()> {
    let mut map = open
        .maps_mut()
        .find(|map| map.name().as_encoded_bytes().ends_with(b".rodata.config"))
        .context("find scheduler configuration")?;
    let data = map
        .initial_value_mut()
        .context("initialize scheduler configuration")?;
    ensure!(
        data.len() == std::mem::size_of_val(config),
        "unexpected configuration size"
    );
    for (destination, value) in data.as_chunks_mut::<8>().0.iter_mut().zip(config) {
        *destination = value.to_ne_bytes();
    }
    Ok(())
}

/// Attach the scheduler through its struct_ops map `ops`.
pub fn attach(object: &mut Object, ops: &str) -> Result<Link> {
    object
        .maps_mut()
        .find(|map| map.name() == OsStr::new(ops))
        .context("find the struct_ops map")?
        .attach_struct_ops()
        .context("attach sched_ext scheduler")
}

/// The arena statistics the BPF side keeps, see pool.rs: slots taken and
/// released, validation errors, failed and successful page allocations,
/// and idle-mask updates that ran out of retries.
pub fn arena_stats(object: &Object) -> Result<[u64; 6]> {
    let stats = object
        .maps()
        .find(|map| map.name() == OsStr::new(".data.astats"))
        .context("find arena statistics")?;
    let mut data = [0_u8; 48];
    ensure!(
        stats.lookup_into(&0_u32.to_ne_bytes(), &mut data, MapFlags::ANY)?,
        "read arena statistics"
    );
    let mut counters = [0; 6];
    for (counter, bytes) in counters.iter_mut().zip(data.as_chunks::<8>().0) {
        *counter = u64::from_ne_bytes(*bytes);
    }
    Ok(counters)
}

/// What the statistics must say after a clean run.
pub fn check_arena_stats(counters: &[u64; 6]) -> Result<()> {
    ensure!(
        counters[0] == counters[1],
        "arena task contexts were not all released"
    );
    ensure!(counters[2] == 0, "arena task context validation failed");
    ensure!(counters[5] == 0, "idle state CAS retries exhausted");
    Ok(())
}

/// Each callback is its own BPF program and the kernel keeps a run count and
/// a run time per program once the accounting is switched on. That costs two
/// clock reads around every callback, so it is on only while a stats client
/// is polling and goes away by itself once nobody has asked for a while.
pub struct OpsProfiler {
    /// Holding the descriptor keeps the accounting enabled.
    pub enabled: Option<OwnedFd>,
    last_read: Instant,
    warned: bool,
}

impl Default for OpsProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl OpsProfiler {
    /// How long without a stats request before the accounting is dropped.
    const IDLE: Duration = Duration::from_secs(5);

    pub fn new() -> Self {
        Self {
            enabled: None,
            last_read: Instant::now(),
            warned: false,
        }
    }

    fn enable(&mut self) {
        if self.enabled.is_some() {
            return;
        }
        let fd = unsafe {
            libbpf_rs::libbpf_sys::bpf_enable_stats(libbpf_rs::libbpf_sys::BPF_STATS_RUN_TIME)
        };
        if fd < 0 {
            if !self.warned {
                eprintln!(
                    "BPF run-time stats unavailable: {}",
                    std::io::Error::last_os_error()
                );
                self.warned = true;
            }
            return;
        }
        self.enabled = Some(unsafe { OwnedFd::from_raw_fd(fd) });
    }

    /// Drop the accounting once no client has polled for a while.
    pub fn expire(&mut self) {
        if self.enabled.is_some() && self.last_read.elapsed() > Self::IDLE {
            self.enabled = None;
        }
    }

    /// Cumulative counts and times of every struct_ops program, keyed by the
    /// callback name. The kernel truncates program names, so the names come
    /// from the object.
    pub fn sample(&mut self, object: &Object) -> BTreeMap<String, OpStats> {
        self.last_read = Instant::now();
        self.enable();
        let mut ops = BTreeMap::new();
        if self.enabled.is_none() {
            return ops;
        }
        for program in object.progs() {
            if program.prog_type() != ProgramType::StructOps {
                continue;
            }
            let mut info: libbpf_rs::libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&info) as u32;
            let result = unsafe {
                libbpf_rs::libbpf_sys::bpf_prog_get_info_by_fd(
                    program.as_fd().as_raw_fd(),
                    (&raw mut info).cast(),
                    &mut len,
                )
            };
            if result != 0 {
                continue;
            }
            let name = program.name().to_string_lossy();
            // A callback of #[scheduler] is scx_NAME, a hand-written entry
            // point rust_NAME.
            let name = name
                .strip_prefix("scx_")
                .or_else(|| name.strip_prefix("rust_"))
                .unwrap_or(&name)
                .to_string();
            ops.insert(
                name,
                OpStats {
                    calls: info.run_cnt,
                    ns: info.run_time_ns,
                    misses: info.recursion_misses,
                },
            );
        }
        ops
    }
}

/// What the arena holds, from the map's memlock accounting, which kernels
/// from 7.3 keep for the allocated pages, and the size of the map.
pub fn arena_usage(object: &Object) -> (Option<u64>, u64) {
    let Some(map) = object.maps().find(|map| map.name() == OsStr::new("arena")) else {
        return (None, 0);
    };
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    let max = u64::from(map.max_entries()) * page;
    let fd = map.as_fd().as_raw_fd();
    let memlock: u64 = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("memlock:"))
                .and_then(|value| value.trim().parse().ok())
        })
        .unwrap_or(0);
    ((memlock > 0).then_some(memlock), max)
}

/// SCX_EXIT_UNREG_KERN, the last of the graceful exit kinds.
const EXIT_UNREG_KERN: i32 = 66;

/// SCX_EXIT_DUMP_DFL_LEN, the dump length the kernel uses for 0.
pub const EXIT_DUMP_DEFAULT: u32 = 32768;
/// Size of struct user_exit_info: kind, exit_cpu, exit_code, a 128-byte
/// reason and a 1024-byte message.
const UEI_BYTES: usize = 4 + 4 + 8 + 128 + 1024;

/// The exit record ops.exit() keeps, reported as scx_utils reports it: the
/// debug dump and the exit reason, as an error for an error exit.
pub fn exit_report(object: &Object, dump_len: u32) -> Result<Option<UserExitInfo>> {
    let uei = object
        .maps()
        .find(|map| map.name() == OsStr::new(".data.uei"))
        .context("find the exit record")?;
    let mut record = vec![0_u8; UEI_BYTES];
    ensure!(
        uei.lookup_into(&0_u32.to_ne_bytes(), &mut record, MapFlags::ANY)?,
        "read the exit record"
    );
    if i32::from_ne_bytes(record[0..4].try_into()?) == 0 {
        return Ok(None);
    }
    let dump = object
        .maps()
        .find(|map| map.name() == OsStr::new(".data.uei_dump"))
        .context("find the exit dump")?;
    let mut text = vec![0_u8; dump_len as usize + 1];
    dump.lookup_into(
        &0_u32.to_ne_bytes(),
        &mut text[..dump_len as usize],
        MapFlags::ANY,
    )?;
    record[UEI_BYTES - 1] = 0;
    record[16 + 127] = 0;
    Ok(Some(UserExitInfo::new(
        record[0..4].as_ptr().cast(),
        record[8..16].as_ptr().cast(),
        record[4..8].as_ptr().cast(),
        record[16..].as_ptr().cast(),
        record[16 + 128..].as_ptr().cast(),
        text.as_ptr().cast(),
    )))
}

/// TICK_NSEC. The coarse clocks advance only from the timer interrupt, so
/// their resolution is the tick period.
fn tick_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC_COARSE, &mut time) };
    if result == 0 && time.tv_sec == 0 && time.tv_nsec > 0 {
        time.tv_nsec as u64
    } else {
        1_000_000
    }
}

/// The section of a tunable: `scx_rustsched::params!` puts each in a read-only
/// section of its own, named PREFIX NAME "." TYPE.
const PARAM_PREFIX: &str = ".rodata.param.";

/// A tunable's name as the command line takes it.
fn param_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

/// The name, in lower case, and the type of the tunable the map `section`
/// holds, if it holds one.
fn param_of(section: &OsStr) -> Option<(String, String)> {
    let (name, ty) = section
        .to_str()?
        .strip_prefix(PARAM_PREFIX)?
        .rsplit_once('.')?;
    Some((param_name(name), ty.to_owned()))
}

/// The value `text` gives a tunable of type `ty` and `size` bytes: true or
/// false for a bool, and otherwise an integer, decimal or 0x hexadecimal,
/// in the range of the type. None if it is not one.
fn param_parse(ty: &str, size: usize, text: &str) -> Option<u64> {
    let bits = 8 * u32::try_from(size).ok()?;
    if !(8..=64).contains(&bits) {
        return None;
    }
    match (ty, text) {
        ("bool", "true" | "1") => Some(1),
        ("bool", "false" | "0") => Some(0),
        ("bool", _) => None,
        _ if ty.starts_with('i') => text
            .parse::<i64>()
            .ok()
            .filter(|value| (value << (64 - bits)) >> (64 - bits) == *value)
            .map(|value| value as u64),
        _ => match text.strip_prefix("0x") {
            Some(digits) => u64::from_str_radix(digits, 16).ok(),
            None => text.parse::<u64>().ok(),
        }
        .filter(|value| bits == 64 || value >> bits == 0),
    }
}

/// The element type of an array tunable, whose type is its element's in
/// brackets.
fn param_element(ty: &str) -> Option<&str> {
    ty.strip_prefix('[')?.strip_suffix(']')
}

/// A value a tunable can hold: an integer or a bool, alone or as the
/// element of an array.
pub trait ParamValue: Copy {
    /// The type as `scx_rustsched::params!` names it.
    const TYPE: &'static str;
    /// Append the value as the object holds it.
    fn append(self, bytes: &mut Vec<u8>);
}

macro_rules! param_values {
    ($($type:ident),*) => {
        $(impl ParamValue for $type {
            const TYPE: &'static str = stringify!($type);
            fn append(self, bytes: &mut Vec<u8>) {
                bytes.extend_from_slice(&self.to_ne_bytes());
            }
        })*
    };
}
param_values!(u8, u16, u32, u64, i8, i16, i32, i64);

impl ParamValue for bool {
    const TYPE: &'static str = "bool";
    fn append(self, bytes: &mut Vec<u8>) {
        bytes.push(u8::from(self));
    }
}

/// The tunables of an object that is open and not loaded yet, the ones it
/// declares with `scx_rustsched::params!`, to set before the load, and the ops
/// flags it is loaded with. It records which tunables were set: run()
/// refuses to start a scheduler that has one nobody set.
pub struct Params<'a> {
    open: &'a mut OpenObject,
    set: std::collections::BTreeSet<String>,
    flags: u64,
}

impl<'a> Params<'a> {
    /// The tunables of `open`, which is loaded with the ops `flags`.
    pub fn new(open: &'a mut OpenObject, flags: u64) -> Self {
        Self {
            open,
            set: Default::default(),
            flags,
        }
    }

    /// The ops flags the scheduler is loaded with: the ones `#[scheduler]`
    /// declares until changed here.
    pub fn flags(&self) -> u64 {
        self.flags
    }

    /// Load the scheduler with the ops `flags` too, such as one the
    /// running kernel may lack, which `compat` reads as 0 there.
    pub fn add_flags(&mut self, flags: u64) {
        self.flags |= flags;
    }

    /// Load the scheduler without the ops `flags`.
    pub fn clear_flags(&mut self, flags: u64) {
        self.flags &= !flags;
    }

    /// The type of the tunable `name`, if the scheduler has it.
    pub fn type_of(&mut self, name: &str) -> Option<String> {
        let name = param_name(name);
        self.open
            .maps_mut()
            .filter_map(|map| param_of(map.name()))
            .find_map(|(found, ty)| (found == name).then_some(ty))
    }

    /// Give the tunable `name`, of type `ty`, the first `data.len()` bytes
    /// `bytes(data.len())` returns.
    fn write(
        &mut self,
        name: &str,
        bytes: impl FnOnce(&str, usize) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let name = param_name(name);
        let (mut map, ty) = self
            .open
            .maps_mut()
            .find_map(|map| match param_of(map.name()) {
                Some((found, ty)) if found == name => Some((map, ty)),
                _ => None,
            })
            .with_context(|| format!("the scheduler has no parameter {name}"))?;
        let data = map
            .initial_value_mut()
            .with_context(|| format!("parameter {name} has no value"))?;
        let bytes = bytes(&ty, data.len()).with_context(|| format!("parameter {name}"))?;
        data.copy_from_slice(&bytes);
        self.set.insert(name);
        Ok(())
    }

    /// Set a tunable from the value of a command line option: true or
    /// false for a bool, and otherwise an integer, decimal or 0x
    /// hexadecimal, in the range of the tunable's type.
    pub fn set_text(&mut self, name: &str, text: &str) -> Result<()> {
        self.write(name, |ty, size| {
            let value = param_parse(ty, size, text)
                .with_context(|| format!("{text:?} is not a valid {ty}"))?;
            Ok(value.to_ne_bytes()[..size].to_vec())
        })
    }

    /// Set a tunable from values of its own type: one for an integer or a
    /// bool, and for an array at most as many as it has elements, the
    /// rest of which become zero.
    pub fn set<T: ParamValue>(&mut self, name: &str, values: &[T]) -> Result<()> {
        self.write(name, |ty, size| {
            let array = param_element(ty);
            ensure!(
                array.unwrap_or(ty) == T::TYPE,
                "it is {ty}, not {}",
                T::TYPE
            );
            let mut bytes = Vec::new();
            values.iter().for_each(|value| value.append(&mut bytes));
            ensure!(
                bytes.len() == size || array.is_some() && bytes.len() < size,
                "{} values do not fit {ty} of {size} bytes",
                values.len()
            );
            bytes.resize(size, 0);
            Ok(bytes)
        })
    }

    /// Set the tunables the options `A` name, from the command line as
    /// parsed: an option sets the tunable of its name, so `steal`, given
    /// as `--steal`, sets `STEAL`. A time in microseconds or milliseconds
    /// sets the tunable in nanoseconds: `slice_us`, given as `--slice-us`,
    /// sets `SLICE_NS` to a thousand times its value. An option's default
    /// is the one in `A`, which the scheduler starts with whatever default
    /// the tunable was declared with. An option that names no tunable, or
    /// an array, is left to the scheduler's own settings.
    pub fn set_options<A: clap::Args>(&mut self, matches: &clap::ArgMatches) -> Result<()> {
        for (name, value) in named::<A>(matches) {
            let scalar = |ty: String| param_element(&ty).is_none();
            if let Some(ty) = self.type_of(&name) {
                if scalar(ty) {
                    self.set_text(&name, &value)?;
                }
                continue;
            }
            let Some((tunable, factor)) = time_unit(&name) else {
                continue;
            };
            if self.type_of(&tunable).is_some_and(scalar) {
                let scaled = value
                    .parse::<i128>()
                    .ok()
                    .and_then(|value| value.checked_mul(factor))
                    .with_context(|| {
                        format!("--{}: {value:?} is not a time", name.replace('_', "-"))
                    })?;
                self.set_text(&tunable, &scaled.to_string())
                    .with_context(|| format!("--{} {value}", name.replace('_', "-")))?;
            }
        }
        Ok(())
    }

    /// Fail if the scheduler has a tunable that was not set: an option
    /// whose name does not match the tunable it is meant for, or one left
    /// out of the loader's own settings.
    pub fn check(self) -> Result<()> {
        let unset: Vec<_> = self
            .open
            .maps_mut()
            .filter_map(|map| Some(param_of(map.name())?.0))
            .filter(|name| !self.set.contains(name))
            .collect();
        ensure!(
            unset.is_empty(),
            "no option sets the scheduler's parameters: {}",
            unset.join(", ")
        );
        Ok(())
    }
}

/// How run() loads and runs a scheduler.
#[derive(Default)]
pub struct RunOptions {
    /// libbpf's open options, such as a BPF token path.
    pub libbpf: LibbpfOpts,
    /// Print libbpf's debug output.
    pub verbose: bool,
    /// Load the object and stop, without attaching it.
    pub verify: bool,
    /// Detach after this many seconds.
    pub duration: Option<u64>,
    /// Bytes of the kernel's debug dump to keep at exit, 0 for what the
    /// scheduler declares.
    pub exit_dump_len: u32,
    /// The watchdog timeout in milliseconds, 0 for what the scheduler
    /// declares.
    pub timeout_ms: u32,
    /// Print the scheduler's statistics at this interval, in seconds.
    pub stats: Option<f64>,
    /// The scheduler's version, for `Scheduler::attached()`.
    pub version: &'static str,
}

/// How the CPUs' capacities and packing ranks are read for the scheduler,
/// see tiers.rs.
pub struct Capacity {
    pub mode: tiers::CapacityMode,
    /// Capacities within this many percent of each other are one tier.
    pub tolerance_pct: Option<u32>,
    /// Ignore the kernel's packing priorities.
    pub no_asym_packing: bool,
}

impl Default for Capacity {
    fn default() -> Self {
        Self {
            mode: tiers::CapacityMode::Kernel,
            tolerance_pct: None,
            no_asym_packing: false,
        }
    }
}

/// What a scheduler does while no stats client asks, see [`Stats::idle`].
type Idle = Option<Box<dyn FnMut(&Loaded)>>;

/// A scheduler's statistics: what it serves to scx_stats clients, and how
/// `--stats` and `--monitor` print it. A scheduler has none unless its
/// [`Scheduler::stats`] returns this, built from its two callbacks.
pub struct Stats {
    describe: Box<dyn Fn() -> Result<()>>,
    #[allow(clippy::type_complexity)]
    serve: Box<dyn FnOnce(Idle) -> Result<Box<dyn FnMut(&Loaded, Duration) -> Result<()>>>>,
    idle: Idle,
    monitor: Box<dyn FnOnce(Duration, Arc<AtomicBool>) -> Result<()> + Send>,
}

impl Stats {
    /// `data` describes the metrics `M` to the stats server, `metrics`
    /// reads them from the running scheduler each time a client asks, and
    /// `show` prints what a client received, once per interval.
    pub fn new<M>(
        data: fn() -> scx_stats::StatsServerData<(), M>,
        mut metrics: impl FnMut(&Loaded) -> M + 'static,
        mut show: impl FnMut(M, Duration) -> Result<()> + Send + 'static,
    ) -> Self
    where
        M: Send + 'static + for<'a> serde::Deserialize<'a>,
    {
        Self {
            describe: Box::new(move || data().describe_meta(&mut std::io::stdout(), None)),
            idle: None,
            serve: Box::new(move |mut idle: Idle| {
                let server = scx_stats::StatsServer::new(data()).launch()?;
                let (responses, requests) = server.channels();
                Ok(Box::new(move |object: &Loaded, timeout: Duration| {
                    // The server answers its clients for as long as it lives.
                    let _server = &server;
                    match requests.recv_timeout(timeout) {
                        Ok(()) => responses
                            .send(metrics(object))
                            .map_err(|_| anyhow::anyhow!("stats client went away"))?,
                        Err(error) if error.is_timeout() => {
                            if let Some(idle) = idle.as_mut() {
                                idle(object);
                            }
                        }
                        Err(error) => Err(error)?,
                    }
                    Ok(())
                }))
            }),
            monitor: Box::new(move |interval, shutdown| {
                scx_utils::monitor_stats::<M>(
                    &[],
                    interval,
                    || shutdown.load(Ordering::Relaxed),
                    |metrics| show(metrics, interval),
                )
            }),
        }
    }
}

impl Stats {
    /// Call `idle` about ten times a second while no client asks, for
    /// what the scheduler keeps only for a client, such as the callback
    /// profiler's accounting, to be dropped once nobody has asked for a
    /// while.
    pub fn idle(mut self, idle: impl FnMut(&Loaded) + 'static) -> Self {
        self.idle = Some(Box::new(idle));
        self
    }
}

/// What a scheduler adds to the loader, on its options. Every method has a
/// default, so `impl Scheduler for Opts {}` is a scheduler with nothing
/// but the tunables its options name.
pub trait Scheduler: clap::Args {
    /// Set the tunables no option sets by its name, see `main!`.
    fn settings(&self, _params: &mut Params) -> Result<()> {
        Ok(())
    }

    /// What the scheduler asks of the runtime, a mask of
    /// `config::runtime`'s bits.
    fn runtime(&self) -> u64 {
        0
    }

    /// How the CPUs' capacities and packing ranks are read.
    fn capacity(&self) -> Capacity {
        Capacity::default()
    }

    /// The scheduler's statistics, for `--stats` and `--monitor`. None: it
    /// has no statistics.
    fn stats(&self) -> Option<Stats> {
        None
    }

    /// Called once the scheduler is attached and its init has run, with
    /// what the loader knows about the run, for the scheduler to report as
    /// it likes.
    fn attached(&self, attached: &Attached<'_>) {
        info!("{} attached", attached.name());
    }

    /// Called when the scheduler was unregistered without an error, `why`
    /// being the reason, and the message if any. An error exit is reported
    /// by the loader, with the kernel's debug dump.
    fn stopped(&self, name: &str, why: &str) {
        info!("{name} stopped: {why}");
    }
}

/// The run of an attached scheduler, see `Scheduler::attached()`: one
/// method for each thing the loader knows about it.
pub struct Attached<'a> {
    name: &'a str,
    version: &'a str,
    object: &'a Object,
    flags: u64,
    runtime: u64,
    tiers: Option<&'a Tiers>,
    topology: std::cell::OnceCell<Option<Topology>>,
}

/// What `Attached` reads off scx_utils' Topology, once asked.
struct Topology {
    nr_cpus: usize,
    nr_nodes: usize,
    smt: bool,
}

impl Attached<'_> {
    /// The scheduler's name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// The scheduler's version.
    pub fn version(&self) -> &str {
        self.version
    }

    /// The version with the build's git revision and target, what
    /// `--version` prints.
    pub fn build(&self) -> String {
        scx_utils::build_id::full_version(self.version)
    }

    /// The loaded object, to read what the scheduler's init computed.
    pub fn object(&self) -> &Object {
        self.object
    }

    /// The running kernel's release string, what uname -r prints.
    pub fn kernel_release(&self) -> String {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } != 0 {
            return "unknown".to_string();
        }
        unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }

    /// The tick period in nanoseconds, TICK_NSEC.
    pub fn tick_ns(&self) -> u64 {
        tick_ns()
    }

    fn topology(&self) -> Option<&Topology> {
        self.topology
            .get_or_init(|| {
                let topology = scx_utils::Topology::new().ok()?;
                Some(Topology {
                    nr_cpus: topology.all_cpus.len(),
                    nr_nodes: topology
                        .nodes
                        .values()
                        .filter(|node| !node.all_cpus.is_empty())
                        .count(),
                    smt: topology.smt_enabled,
                })
            })
            .as_ref()
    }

    /// The machine's CPUs. None when the topology cannot be read.
    pub fn nr_cpus(&self) -> Option<usize> {
        Some(self.topology()?.nr_cpus)
    }

    /// The machine's NUMA nodes with CPUs. None when the topology cannot be
    /// read.
    pub fn nr_nodes(&self) -> Option<usize> {
        Some(self.topology()?.nr_nodes)
    }

    /// Does the runtime treat the machine's NUMA nodes as one?
    pub fn numa_disabled(&self) -> bool {
        self.runtime & config::runtime::DISABLE_NUMA != 0
    }

    /// Does the runtime use SMT: the machine has it, and the runtime is not
    /// told to treat every CPU as a core of its own. None when the topology
    /// cannot be read.
    pub fn smt(&self) -> Option<bool> {
        Some(self.topology()?.smt && self.runtime & config::runtime::DISABLE_SMT == 0)
    }

    /// The ops flags the struct_ops map asks the kernel for.
    pub fn ops_flags(&self) -> u64 {
        self.flags
    }

    /// The CPUs' capacity and packing tiers, if they could be read.
    pub fn tiers(&self) -> Option<&Tiers> {
        self.tiers
    }

    /// Bytes the arena holds, when the kernel accounts them, and the
    /// arena's size, see `arena_usage()`.
    pub fn arena_usage(&self) -> (Option<u64>, u64) {
        arena_usage(self.object)
    }
}

/// Read the CPUs' capacities and packing priorities and hand them to the
/// loaded object, see tiers.rs.
fn publish_tiers(object: &mut Object, capacity: &Capacity) -> Result<Tiers> {
    let mut tiers = tiers::Tiers::new(capacity.mode, capacity.tolerance_pct)?;
    tiers.read_priorities(object, capacity.no_asym_packing)?;
    tiers.publish(object)?;
    Ok(tiers)
}

/// The stats client, in its own thread: beside the scheduler with
/// `--stats`, started once its server is up.
fn spawn_monitor(
    monitor: Box<dyn FnOnce(Duration, Arc<AtomicBool>) -> Result<()> + Send>,
    interval: f64,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Err(error) = monitor(Duration::from_secs_f64(interval), shutdown) {
            eprintln!("stats monitor thread finished because of an error {error}");
        }
    })
}

/// Load, attach and run the scheduler `name` until `shutdown` is set, the
/// duration is over or the kernel ejects it. `legacy` and `sized` are the
/// two objects scx_rustsched_build leaves in OUT_DIR, of which the running
/// kernel takes one. `matches` is the command line the options
/// `scheduler` were parsed from: its options set the tunables they name,
/// and the scheduler's own settings the rest.
pub fn run<S: Scheduler>(
    name: &str,
    legacy: &[u8],
    sized: &[u8],
    options: &RunOptions,
    shutdown: &Arc<AtomicBool>,
    matches: &clap::ArgMatches,
    scheduler: &S,
) -> Result<()> {
    let bytes = if sized_topology()? { sized } else { legacy };
    let mut open = open(name, bytes, &options.libbpf, options.verbose)?;
    let dump_len = match options.exit_dump_len {
        0 => declared_dump_len(name, &mut open, bytes)?,
        len => len,
    };
    let config = configuration(dump_len, scheduler.runtime())?;
    // A scheduler with cgroup callbacks has a second map for a kernel
    // that names them cgroup_*.
    let cgroup = if open
        .maps_mut()
        .any(|map| map.name() == OsStr::new("rust_ops_cgroup"))
    {
        cgroup_ops()?
    } else {
        None
    };
    let ops = select_ops(name, &mut open, bytes, cgroup, dump_len)?;
    if options.timeout_ms != 0 {
        set_ops_timeout(name, &mut open, bytes, ops, options.timeout_ms)?;
    }
    let declared = ops_flags(name, &mut open, bytes, ops)?;
    size_maps(&mut open)?;
    let mut config = config;
    let mut params = Params::new(&mut open, declared);
    params.set_options::<S>(matches)?;
    // A scheduler that counts for its statistics only when they are asked
    // for declares a `STATS` tunable: it is true with --stats.
    if params.type_of("stats").as_deref() == Some("bool") {
        params.set("stats", &[options.stats.is_some()])?;
    }
    scheduler.settings(&mut params)?;
    let flags = params.flags();
    params.check()?;
    set_ops_flags(name, &mut open, bytes, ops, flags)?;
    config[config::OPS_FLAGS] = flags;
    set_config(&mut open, &config)?;
    let mut object = open.load().context("load Rust BPF object")?;
    if options.verify {
        println!("Rust BPF object verified successfully");
        return Ok(());
    }
    // The CPUs' capacities and packing ranks, for a scheduler that reads
    // them at init. One that does not is not held back by a machine they
    // cannot be read on.
    let tiers = publish_tiers(&mut object, &scheduler.capacity())
        .inspect_err(|error| warn!("CPU capacities and ranks not read: {error:#}"))
        .ok();
    let link = attach(&mut object, ops)?;
    let object = Loaded(Arc::new(object));
    scheduler.attached(&Attached {
        name,
        version: options.version,
        object: &object,
        flags,
        runtime: scheduler.runtime(),
        tiers: tiers.as_ref(),
        topology: std::cell::OnceCell::new(),
    });
    let start = Instant::now();
    // The stats server answers clients from this loop, --stats among them.
    let (mut serve, mut monitor) = match scheduler.stats() {
        Some(stats) => {
            let serve = (stats.serve)(stats.idle)?;
            let monitor = options
                .stats
                .map(|interval| spawn_monitor(stats.monitor, interval, shutdown.clone()));
            (Some(serve), monitor)
        }
        None => (None, None),
    };
    while !shutdown.load(Ordering::Relaxed)
        && options
            .duration
            .is_none_or(|seconds| start.elapsed() < Duration::from_secs(seconds))
        && exit_report(&object, dump_len)?.is_none()
    {
        match serve.as_mut() {
            Some(serve) => serve(&object, Duration::from_millis(100))?,
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    if let Some(monitor) = monitor.take() {
        let _ = monitor.join();
    }
    drop(serve);
    drop(link);
    // The counters are printed with -v, and whenever they say the run was
    // not clean, which fails it.
    let counters = arena_stats(&object)?;
    let clean = check_arena_stats(&counters);
    if options.verbose || clean.is_err() {
        info!(
            "arena: allocated={} freed={} errors={} failures={} pages={}",
            counters[0], counters[1], counters[2], counters[3], counters[4]
        );
        info!("idle: cas_failures={}", counters[5]);
    }
    clean?;
    // A graceful unregister is one line; an error exit keeps the standard
    // report, with the debug dump.
    if let Some(why) = exit_summary(&object)? {
        scheduler.stopped(name, &why);
        return Ok(());
    }
    match exit_report(&object, dump_len)? {
        Some(info) => info.report(),
        None => Ok(()),
    }
}

/// A graceful unregister as one line, "reason" or "reason (msg)", read off
/// the exit record. None when the scheduler has not exited, or was kicked
/// out by an error, which keeps the standard report and its debug dump.
fn exit_summary(object: &Object) -> Result<Option<String>> {
    let uei = object
        .maps()
        .find(|map| map.name() == OsStr::new(".data.uei"))
        .context("find the exit record")?;
    let mut record = vec![0_u8; UEI_BYTES];
    ensure!(
        uei.lookup_into(&0_u32.to_ne_bytes(), &mut record, MapFlags::ANY)?,
        "read the exit record"
    );
    let kind = i32::from_ne_bytes(record[0..4].try_into()?);
    if kind == 0 || kind > EXIT_UNREG_KERN {
        return Ok(None);
    }
    let text = |bytes: &[u8]| {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    };
    let reason = text(&record[16..16 + 128]);
    let msg = text(&record[16 + 128..]);
    Ok(Some(match (reason.is_empty(), msg.is_empty()) {
        (true, _) => "unknown reason".to_string(),
        (false, true) => reason,
        (false, false) => format!("{reason} ({msg})"),
    }))
}

/// The options every scheduler takes, beside its own.
#[derive(clap::Parser)]
struct Cli {
    #[arg(short = 'v', long, help = "Enable libbpf debug output")]
    verbose: bool,
    #[arg(short = 'V', long, help = "Print the scheduler version and exit")]
    version: bool,
    #[arg(long, help = "Load the BPF object and exit")]
    verify: bool,
    #[arg(long, help = "Run for this many seconds")]
    duration: Option<u64>,
    #[arg(
        long,
        default_value_t = 0,
        help = "Exit debug dump buffer length. 0 indicates default"
    )]
    exit_dump_len: u32,
    #[arg(
        long,
        default_value_t = 0,
        help = "Watchdog timeout in milliseconds, at most 30000. 0 keeps the scheduler's own"
    )]
    timeout_ms: u32,
    #[arg(long, help = "Enable stats monitoring with the specified interval")]
    stats: Option<f64>,
    #[arg(
        long,
        help = "Run in stats monitoring mode with the specified interval. Scheduler is not launched"
    )]
    monitor: Option<f64>,
    #[arg(long, help = "Show descriptions for statistics")]
    help_stats: bool,
    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

/// The options of a scheduler with no tunables.
#[derive(clap::Args)]
pub struct NoOpts {}

impl Scheduler for NoOpts {}

/// The tunable in nanoseconds that an option in microseconds or
/// milliseconds sets, and the factor: `slice_us` sets `slice_ns`, 1000.
fn time_unit(option: &str) -> Option<(String, i128)> {
    [("_us", 1_000), ("_ms", 1_000_000)]
        .into_iter()
        .find_map(|(suffix, factor)| Some((format!("{}_ns", option.strip_suffix(suffix)?), factor)))
}

/// The options of `A` with their values as given or defaulted, by name.
fn named<A: clap::Args>(matches: &clap::ArgMatches) -> Vec<(String, String)> {
    A::augment_args(clap::Command::new(""))
        .get_arguments()
        .filter_map(|arg| {
            let name = arg.get_id().as_str();
            let value = matches.get_raw(name)?.next()?;
            Some((name.to_owned(), value.to_string_lossy().into_owned()))
        })
        .collect()
}

/// Log at info level to stderr, each line with the local time and its
/// level, as the C-form schedulers do.
fn init_logger() -> Result<()> {
    let mut config = simplelog::ConfigBuilder::new();
    // The local offset cannot be read safely once there is more than one
    // thread, and the time is then UTC.
    let _ = config.set_time_offset_to_local();
    config
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Info,
        config.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    Ok(())
}

/// The whole loader of a scheduler: parse the command line, then run()
/// until Ctrl-C. `main!` calls this with the scheduler's name, version and
/// objects, and with its options as `S`.
pub fn cli<S: Scheduler>(
    name: &'static str,
    version: &'static str,
    about: &'static str,
    legacy: &[u8],
    sized: &[u8],
) -> Result<()> {
    use clap::{Args, FromArgMatches};

    let command = Cli::augment_args(S::augment_args(clap::Command::new(name)));
    let matches = command.about(about).get_matches();
    let options = Cli::from_arg_matches(&matches)?;
    let scheduler = S::from_arg_matches(&matches)?;
    if options.version {
        println!("{name} {}", scx_utils::build_id::full_version(version));
        return Ok(());
    }
    init_logger()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = shutdown.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    if options.help_stats || options.monitor.is_some() || options.stats.is_some() {
        let stats = scheduler
            .stats()
            .with_context(|| format!("{name} has no statistics"))?;
        if options.help_stats {
            return (stats.describe)();
        }
        if let Some(interval) = options.monitor {
            return (stats.monitor)(Duration::from_secs_f64(interval), shutdown);
        }
    }
    run(
        name,
        legacy,
        sized,
        &RunOptions {
            libbpf: options.libbpf,
            verbose: options.verbose,
            verify: options.verify,
            duration: options.duration,
            exit_dump_len: options.exit_dump_len,
            timeout_ms: options.timeout_ms,
            stats: options.stats,
            version,
        },
        &shutdown,
        &matches,
        &scheduler,
    )
}

/// The `main()` of a scheduler: the objects its build script left in
/// OUT_DIR, loaded and run by cli(). The scheduler's options are a
/// `clap::Args` structure, each field named as the tunable it sets, a
/// time in microseconds as the tunable in nanoseconds, and what else the scheduler adds to the loader is its `Scheduler`
/// implementation:
///
/// ```ignore
/// #[derive(clap::Args)]
/// struct Opts {
///     /// Scheduling slice duration in microseconds.
///     #[clap(short = 's', long, default_value = "5000")]
///     slice_us: u64,
/// }
///
/// impl scx_rustsched_loader::Scheduler for Opts {}
///
/// scx_rustsched_loader::main!("A minimal sched_ext scheduler written in Rust BPF", Opts);
/// ```
///
/// An option that is not the tunable's value as it stands, such as a
/// list of CPUs that the scheduler takes as a mask, has a name of its
/// own, and `Scheduler::settings()` sets the tunable from it:
///
/// ```ignore
/// impl scx_rustsched_loader::Scheduler for Opts {
///     fn settings(
///         &self,
///         params: &mut scx_rustsched_loader::Params,
///     ) -> scx_rustsched_loader::Result<()> {
///         params.set("primary_cpus", &mask_of(&self.primary_domain)?)
///     }
/// }
/// ```
///
/// Every tunable of the scheduler has to be set by one or the other.
#[macro_export]
macro_rules! main {
    ($about:expr) => {
        $crate::main!($about, $crate::NoOpts);
    };
    ($about:expr, $opts:ty) => {
        fn main() -> $crate::Result<()> {
            $crate::cli::<$opts>(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                $about,
                include_bytes!(concat!(env!("OUT_DIR"), "/scheduler-legacy.bpf.o")),
                include_bytes!(concat!(env!("OUT_DIR"), "/scheduler-sized.bpf.o")),
            )
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_sections() {
        let of = |section: &str| param_of(OsStr::new(section));
        assert_eq!(
            of(".rodata.param.SLICE_NS.u64"),
            Some(("slice_ns".into(), "u64".into()))
        );
        assert_eq!(
            of(".rodata.param.STEAL.bool"),
            Some(("steal".into(), "bool".into()))
        );
        assert_eq!(of(".rodata.config"), None);
        assert_eq!(of(".rodata.param.NOTYPE"), None);
        assert_eq!(param_name("Slice-NS"), "slice_ns");
    }

    #[test]
    fn params_from_options() {
        use clap::{Args, FromArgMatches};

        #[derive(clap::Args)]
        struct Opts {
            #[clap(short = 's', long, default_value = "5000000")]
            slice_ns: u64,
            #[clap(long, action = clap::ArgAction::Set, default_value = "true")]
            steal: bool,
            #[clap(long)]
            fast: bool,
        }

        let parse = |line: &[&str]| {
            let command = Cli::augment_args(Opts::augment_args(clap::Command::new("test")));
            let matches = command.get_matches_from(line);
            assert!(Cli::from_arg_matches(&matches).is_ok());
            named::<Opts>(&matches)
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            parse(&["test"]),
            ["slice_ns=5000000", "steal=true", "fast=false"]
        );
        assert_eq!(
            parse(&["test", "-s", "1000", "--steal", "false", "--fast", "-v"]),
            ["slice_ns=1000", "steal=false", "fast=true"]
        );
    }

    #[test]
    fn param_arrays() {
        assert_eq!(
            param_of(OsStr::new(".rodata.param.PRIMARY_CPUS.[u64]")),
            Some(("primary_cpus".into(), "[u64]".into()))
        );
        assert_eq!(param_element("[u64]"), Some("u64"));
        assert_eq!(param_element("u64"), None);
        let mut bytes = Vec::new();
        [1_u16, 0x0203]
            .iter()
            .for_each(|value| value.append(&mut bytes));
        true.append(&mut bytes);
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[..2], 1_u16.to_ne_bytes());
        assert_eq!(bytes[4], 1);
        assert_eq!(<i32 as ParamValue>::TYPE, "i32");
    }

    #[test]
    fn param_values() {
        assert_eq!(param_parse("u64", 8, "5000000"), Some(5_000_000));
        assert_eq!(param_parse("u64", 8, "0x10"), Some(16));
        assert_eq!(param_parse("u64", 8, "-1"), None);
        assert_eq!(
            param_parse("u32", 4, "4294967295"),
            Some(u64::from(u32::MAX))
        );
        assert_eq!(param_parse("u32", 4, "4294967296"), None);
        assert_eq!(param_parse("u8", 1, "256"), None);
        assert_eq!(param_parse("i32", 4, "-1"), Some(u64::MAX));
        assert_eq!(param_parse("i32", 4, "2147483648"), None);
        assert_eq!(param_parse("i8", 1, "-128"), Some(-128_i64 as u64));
        assert_eq!(param_parse("i8", 1, "-129"), None);
        assert_eq!(param_parse("bool", 1, "true"), Some(1));
        assert_eq!(param_parse("bool", 1, "0"), Some(0));
        assert_eq!(param_parse("bool", 1, "7"), None);
        assert_eq!(param_parse("u64", 16, "1"), None);
        assert_eq!(param_parse("u64", 8, "many"), None);
    }

    #[test]
    fn time_units() {
        assert_eq!(time_unit("slice_us"), Some(("slice_ns".into(), 1_000)));
        assert_eq!(
            time_unit("timeout_ms"),
            Some(("timeout_ns".into(), 1_000_000))
        );
        assert_eq!(time_unit("slice_ns"), None);
        assert_eq!(time_unit("bonus"), None);
    }
}
