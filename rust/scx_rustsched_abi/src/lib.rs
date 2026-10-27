// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! What a Rust BPF sched_ext scheduler and its loader agree on: the layout
//! of the configuration table, `.rodata.config`, that the loader fills in
//! from the running kernel's BTF before the object is loaded, and that the
//! BPF side reads by index. Both sides depend on this crate, which
//! compiles for the BPF target and the host.
//!
//! Every entry is a u64; an offset or enumerator the kernel lacks reads as
//! 0. A scheduler's own settings are not here: they are its tunables,
//! which the BPF side declares.

#![no_std]

/// Words in the table: the entries below, and room for more.
pub const WORDS: usize = 64;

/// task_struct.scx.slice, what is left of the task's slice.
pub const SCX_SLICE: usize = 0;
/// task_struct.static_prio.
pub const STATIC_PRIO: usize = 1;
/// Pages the task context pool starts with.
pub const ARENA_PAGES: usize = 2;
/// task_struct.cpus_ptr.
pub const CPUS_PTR: usize = 3;
/// task_struct.migration_disabled.
pub const MIGRATION_DISABLED: usize = 4;
/// task_struct.flags.
pub const TASK_FLAGS: usize = 5;
/// task_struct.scx.flags.
pub const SCX_FLAGS: usize = 6;
/// The tick period in ns.
pub const TICK_NS: usize = 7;
/// task_struct.se.custom_slice and se.slice, a request set with
/// sched_setattr().
pub const CUSTOM_SLICE: usize = 8;
pub const SE_SLICE: usize = 9;
/// task_struct.scx.tid.
pub const SCX_TID: usize = 10;
/// task_struct.nr_cpus_allowed.
pub const NR_CPUS_ALLOWED: usize = 11;
/// rq.clock_task.
pub const RQ_CLOCK_TASK: usize = 12;
/// task_struct.scx.dsq_vtime, where the context address is stashed.
pub const DSQ_VTIME: usize = 13;
/// task_struct.policy.
pub const POLICY: usize = 14;
/// Task group fields, see cgroup.rs: cgroup.level, the online state and
/// flags, the weight, the cpu subsystem's css pointer and the idle flag.
pub const TG_LEVEL: usize = 15;
pub const TG_FLAGS: usize = 16;
pub const TG_ONLINE: usize = 17;
pub const TG_WEIGHT: usize = 18;
pub const CPU_CSS: usize = 19;
pub const TG_IDLE: usize = 20;
/// scx_cgroup_init_args.bw_period_us, bw_quota_us and bw_burst_us.
pub const BW_PERIOD: usize = 21;
pub const BW_QUOTA: usize = 22;
pub const BW_BURST: usize = 23;
/// Enqueue flags and re-enqueue reasons, 0 where the kernel has none.
pub const ENQ_CPU_SELECTED: usize = 24;
pub const ENQ_IMMED: usize = 25;
pub const ENQ_REENQ: usize = 26;
pub const REENQ_MASK: usize = 27;
pub const REENQ_IMMED: usize = 28;
pub const REENQ_PREEMPTED: usize = 29;
/// scx_exit_info fields, exit_cpu plus one, and the dump length.
pub const EXIT_CPU: usize = 30;
pub const EXIT_CODE: usize = 31;
pub const EXIT_REASON: usize = 32;
pub const EXIT_MSG: usize = 33;
pub const EXIT_DUMP: usize = 34;
pub const DUMP_LEN: usize = 35;
/// scx_dump_ctx.at_jiffies and at_ns.
pub const DUMP_AT_JIFFIES: usize = 36;
pub const DUMP_AT_NS: usize = 37;
/// task_struct.scx.runnable_at and task_struct.pid.
pub const RUNNABLE_AT: usize = 38;
pub const PID: usize = 39;
/// scx_exit_info.kind.
pub const EXIT_KIND: usize = 40;
/// sched_domain.groups plus one, sched_group.flags and SD_CLUSTER, 0
/// where the cluster of a CPU cannot be told.
pub const SD_GROUPS: usize = 41;
pub const SG_FLAGS: usize = 42;
pub const SD_CLUSTER: usize = 43;
pub const ENQ_LAST: usize = 44;
pub const ENQ_PREEMPT_LAZY: usize = 45;

/// The runtime's own options, a mask of the bits in [`runtime`].
pub const RUNTIME_OPTIONS: usize = 46;

/// cgroup.kn and kernfs_node.id, which give a cgroup's id, 0 where it
/// cannot be read.
pub const TG_KN: usize = 47;
pub const KN_ID: usize = 48;

/// SCX_ENQ_BLOCKED, 0 where the kernel has no proxy execution for
/// sched_ext, and task_struct.is_blocked, 0 where it has none.
pub const ENQ_BLOCKED: usize = 49;
pub const IS_BLOCKED: usize = 50;
/// The ops flags the scheduler was loaded with: those `#[scheduler]`
/// declares, as its user space changed them.
pub const OPS_FLAGS: usize = 51;
/// task_struct.se.sum_exec_runtime: the runtime the kernel has accounted
/// to a task.
pub const SUM_EXEC_RUNTIME: usize = 52;

/// The bits of RUNTIME_OPTIONS: what a scheduler asks of the runtime's
/// topology, idle scans and clock, rather than of its own policy.
pub mod runtime {
    /// Make every CID a core of its own, so that nothing prefers whole
    /// idle cores or ranks siblings.
    pub const DISABLE_SMT: u64 = 1 << 0;
    /// Make the machine one node.
    pub const DISABLE_NUMA: u64 = 1 << 1;
    /// A whole idle core anywhere wins over a busy core's idle sibling.
    pub const SMT_WHOLE_CORE: u64 = 1 << 2;
    /// Rank the threads of a core by CPU number.
    pub const SMT_ASYM_PACKING: u64 = 1 << 3;
    /// The task clock is the rq clock: charge wall time.
    pub const NO_TASK_CLOCK: u64 = 1 << 4;
}
