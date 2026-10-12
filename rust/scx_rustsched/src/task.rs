// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! What the program reads from a task_struct, at the offsets the loader
//! resolved from the kernel's BTF: its policy and weight, whether it is
//! still runnable, and where it may run.

use core::ptr::read_volatile;

use crate::{
    cid_idle, config, helpers,
    kfuncs::{bpf_cpumask_test_cpu, scx_bpf_task_cid, scx_bpf_task_set_slice},
    ops::{SCX_TASK_QUEUED, cpumask, task_struct},
};

/// The weight of nice 0, NICE_0_LOAD.
pub const NICE_0_WEIGHT: u64 = 1024;

/// The kernel's nice-to-weight table, sched_prio_to_weight[], indexed by
/// static_prio - MAX_RT_PRIO.
const PRIO_TO_WEIGHT: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

const MAX_RT_PRIO: u32 = 100;
pub const SCHED_BATCH: u32 = 3;
pub const SCHED_IDLE: u32 = 5;

/// The task's scheduling policy.
#[inline(always)]
pub unsafe fn task_policy(task: *mut task_struct) -> u32 {
    unsafe {
        let policy_offset = config::get(config::POLICY) as usize;
        read_volatile(task.cast::<u8>().add(policy_offset).cast::<u32>())
    }
}

const PF_EXITING: u32 = 0x4;

/// Is `task` exiting?
#[inline(always)]
pub unsafe fn exiting(task: *mut task_struct) -> bool {
    unsafe {
        let flags_offset = config::get(config::TASK_FLAGS) as usize;
        read_volatile(task.cast::<u8>().add(flags_offset).cast::<u32>()) & PF_EXITING != 0
    }
}

/// The weight of a SCHED_IDLE task, WEIGHT_IDLEPRIO.
pub const WEIGHT_IDLEPRIO: u64 = 3;

/// The task's load weight as fair.c gives it, set_load_weight(): its nice
/// level's, or WEIGHT_IDLEPRIO for SCHED_IDLE. NICE_0_WEIGHT is nice 0.
#[inline(always)]
pub unsafe fn task_weight(task: *mut task_struct) -> u64 {
    unsafe {
        if task_policy(task) == SCHED_IDLE {
            return WEIGHT_IDLEPRIO;
        }
        let prio_offset = config::get(config::STATIC_PRIO) as usize;
        let prio = read_volatile(task.cast::<u8>().add(prio_offset).cast::<i32>());
        match PRIO_TO_WEIGHT.get(prio.wrapping_sub(MAX_RT_PRIO as i32) as u32 as usize) {
            Some(weight) => u64::from(*weight),
            None => NICE_0_WEIGHT,
        }
    }
}

/// Is `task` still runnable, rather than going to sleep?
#[inline(always)]
pub unsafe fn task_queued(task: *mut task_struct) -> bool {
    unsafe {
        let flags_offset = config::get(config::SCX_FLAGS) as usize;
        read_volatile(task.cast::<u8>().add(flags_offset).cast::<u32>()) & SCX_TASK_QUEUED != 0
    }
}

/// Can `task` run on the CPU of a CID right now?
#[inline(always)]
pub unsafe fn runs_on(task: *mut task_struct, cpu: i32) -> bool {
    unsafe {
        let mask_offset = config::get(config::CPUS_PTR) as usize;
        let migration_offset = config::get(config::MIGRATION_DISABLED) as usize;
        let mask = read_volatile(task.cast::<u8>().add(mask_offset).cast::<*const cpumask>());
        let migration = read_volatile(task.cast::<u8>().add(migration_offset).cast::<u16>());
        cpu >= 0 && migration == 0 && bpf_cpumask_test_cpu(cpu as u32, mask)
    }
}

/// Is `task` bound to its CPU, is_pcpu_task(): one CPU allowed, or
/// migration disabled?
///
/// The BPF prologue disables migration for the current task while a program
/// runs, so the task a tick or a dispatch runs in reads 1 without being
/// pinned. As is_migration_disabled() in scx's common.bpf.h decides, a
/// count of 1 pins only another task.
#[inline(always)]
pub unsafe fn pinned(task: *mut task_struct) -> bool {
    unsafe {
        let allowed_offset = config::get(config::NR_CPUS_ALLOWED) as usize;
        let migration_offset = config::get(config::MIGRATION_DISABLED) as usize;
        let migration = read_volatile(task.cast::<u8>().add(migration_offset).cast::<u16>());
        read_volatile(task.cast::<u8>().add(allowed_offset).cast::<u32>()) == 1
            || migration > 1
            || (migration == 1 && helpers::get_current_task() != task)
    }
}

/// Has `task` disabled migration, counting the BPF prologue's own disable
/// for the current task? pinned() tells the two apart.
#[inline(always)]
pub unsafe fn migration_disabled(task: *mut task_struct) -> bool {
    unsafe {
        let migration_offset = config::get(config::MIGRATION_DISABLED) as usize;
        read_volatile(task.cast::<u8>().add(migration_offset).cast::<u16>()) != 0
    }
}

/// The CID `task` is on.
#[inline(always)]
pub unsafe fn task_cid(task: *mut task_struct) -> i32 {
    unsafe { scx_bpf_task_cid(task) }
}

/// Can `task` be dispatched on `cid`? A task always can on the CID it is
/// on, which enqueue chose within its affinity, migration disabled or not.
#[inline(always)]
pub unsafe fn allowed_on(task: *mut task_struct, cid: i32) -> bool {
    unsafe { scx_bpf_task_cid(task) == cid || runs_on(task, cid_idle::cpu(cid)) }
}

/// A task, as a callback of `#[scheduler]` takes it: a reference to the
/// kernel's task_struct that is valid for the callback it was passed to.
#[repr(transparent)]
pub struct Task(task_struct);

impl Task {
    /// # Safety
    /// `task` must be a task the kernel passed to the running callback.
    #[inline(always)]
    pub unsafe fn from_ptr<'task>(task: *mut task_struct) -> &'task Task {
        unsafe { &*task.cast::<Task>() }
    }

    /// The task as the kfuncs take it.
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut task_struct {
        (self as *const Task).cast_mut().cast()
    }

    /// The task's weight, from its nice level: 1024 at nice 0.
    #[inline(always)]
    pub fn weight(&self) -> u64 {
        unsafe { task_weight(self.as_ptr()) }
    }

    /// The CID the task is on, or last ran on.
    #[inline(always)]
    pub fn cid(&self) -> crate::sched::Cid {
        crate::sched::Cid(unsafe { task_cid(self.as_ptr()) })
    }

    /// May the task run on `cid`?
    #[inline(always)]
    pub fn allowed_on(&self, cid: crate::sched::Cid) -> bool {
        unsafe { allowed_on(self.as_ptr(), cid.0) }
    }

    /// Is the task exiting?
    #[inline(always)]
    pub fn exiting(&self) -> bool {
        unsafe { exiting(self.as_ptr()) }
    }

    /// The task's pid: the id of the thread.
    #[inline(always)]
    pub fn pid(&self) -> i32 {
        unsafe { self.field::<i32>(config::PID) }
    }

    /// Is the task bound to one CPU, by its affinity or because it
    /// disabled migration?
    #[inline(always)]
    pub fn pinned(&self) -> bool {
        unsafe { pinned(self.as_ptr()) }
    }

    /// Is the task still runnable, rather than going to sleep? What
    /// ops.stopping() and ops.dispatch() ask of the task that just ran.
    #[inline(always)]
    pub fn queued(&self) -> bool {
        unsafe { task_queued(self.as_ptr()) }
    }

    /// Is the task on a CPU right now?
    #[inline(always)]
    pub fn running(&self) -> bool {
        unsafe { crate::kfuncs::scx_bpf_task_running(self.as_ptr()) }
    }

    /// When the task last became runnable, in jiffies.
    #[inline(always)]
    pub fn runnable_at(&self) -> u64 {
        unsafe { self.field::<u64>(config::RUNNABLE_AT) }
    }

    /// What is left of the task's slice, in nanoseconds.
    #[inline(always)]
    pub fn slice(&self) -> u64 {
        unsafe { self.field::<u64>(config::SCX_SLICE) }
    }

    /// Set what is left of the task's slice. Zero makes a running task
    /// give the CPU up.
    #[inline(always)]
    pub fn set_slice(&self, slice: u64) {
        unsafe { scx_bpf_task_set_slice(self.as_ptr(), slice) };
    }

    /// `value` scaled inversely by the task's weight: unchanged at nice
    /// 0, smaller for a heavier task. Turns run time into virtual time.
    #[inline(always)]
    pub fn scale_inverse(&self, value: u64) -> u64 {
        (value * NICE_0_WEIGHT)
            .checked_div(self.weight())
            .unwrap_or(value)
    }

    /// The scheduler's state of the task, see `state`.
    #[inline(always)]
    pub fn state<T: crate::state::TaskState>(&self) -> Option<&T> {
        unsafe { crate::state::get(self.as_ptr()) }
    }

    /// The field of the task at the offset in entry `index` of the
    /// configuration table.
    #[inline(always)]
    unsafe fn field<T: Copy>(&self, index: usize) -> T {
        unsafe {
            read_volatile(
                self.as_ptr()
                    .cast::<u8>()
                    .add(config::offset(index))
                    .cast::<T>(),
            )
        }
    }
}
