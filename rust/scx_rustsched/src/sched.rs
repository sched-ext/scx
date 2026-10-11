// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! A scheduler as an `impl` block of typed callbacks.
//!
//! ```ignore
//! use scx_rustsched as scx;
//! use scx::prelude::*;
//!
//! #[scx::scheduler(name = "simple", flags = ENQ_LAST)]
//! impl Simple {
//!     fn select_cid(task: &Task, prev: Cid, flags: WakeFlags) -> Cid {
//!         idle::pick(task, prev, Scope::Llc, Kind::AnyCpu).unwrap_or(prev)
//!     }
//!     fn enqueue(task: &Task, flags: EnqFlags) {
//!         dsq::insert(task, Dsq::Global, SLICE_DFL, flags);
//!     }
//! }
//! ```
//!
//! `#[scheduler]` declares the type, the BPF entry point of each callback
//! the block defines and the struct_ops map. A callback takes the
//! kernel's arguments in the kernel's order, each as any type that
//! implements `Arg` for that position: `&Task` or `Option<&Task>` for a
//! task, `Cid` for a CID, a flags type or `u64` for flags, `bool`. It may
//! leave trailing arguments out. It returns what `Ret` converts: nothing, a
//! `Cid`, a `bool`, or `Result<(), i32>` with a negative errno.
//!
//! The callbacks: select_cid(task, prev, wake_flags) -> Cid,
//! enqueue(task, enq_flags), dequeue(task, deq_flags), dispatch(cid, prev),
//! tick(task), running(task), stopping(task, runnable),
//! quiescent(task, deq_flags), enable(task), update_idle(cid, idle) and
//! init().
//!
//! The runtime does its own part in three of them, before or after the
//! scheduler's: ops.init() sets up the idle tracking, ops.update_idle()
//! mirrors each transition into it, and ops.dispatch() marks a CID idle
//! again when it leaves with nothing to run, since the kernel reports no
//! transition for a CPU that was woken and went back to sleep. ops.exit()
//! records the exit for the loader. A scheduler never has to define any of
//! those to have `idle::pick()` work.

use crate::{
    cid_idle, config,
    kfuncs::scx_bpf_dsq_nr_queued,
    ops::{SCX_DSQ_LOCAL, task_struct},
    task::Task,
};

pub use scx_rustsched_macros::scheduler;

/// A CPU as the scheduler sees it: an index into the kernel's
/// topology-ordered CID space, where the CPUs of a core, an LLC and a node
/// are contiguous.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Cid(pub i32);

impl Cid {
    /// The CID as the kfuncs take it.
    #[inline(always)]
    pub fn raw(self) -> i32 {
        self.0
    }
}

macro_rules! flags {
    ($(#[$doc:meta])* $name:ident { $($(#[$flag_doc:meta])* $flag:ident = $value:expr,)* }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name(pub u64);

        impl $name {
            $($(#[$flag_doc])* pub const $flag: Self = Self($value);)*

            /// Are all the bits of `other` set?
            #[inline(always)]
            pub fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            /// The flags as the kfuncs take them.
            #[inline(always)]
            pub fn raw(self) -> u64 {
                self.0
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;

            #[inline(always)]
            fn bitor(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }
        }
    };
}

flags! {
    /// The flags of a wakeup, ops.select_cid()'s.
    WakeFlags {
        /// A fork: the task has never run.
        FORK = 4,
        /// A wakeup of a task that slept, rather than a fork or an exec.
        TTWU = 8,
        /// The waker is about to sleep.
        SYNC = 16,
        /// The task is to stay on the CPU the wakeup runs on, the kernel's
        /// WF_CURRENT_CPU.
        CURRENT_CPU = 0x40,
    }
}

flags! {
    /// The flags of an enqueue, ops.enqueue()'s, which dsq::insert() takes.
    EnqFlags {
        NONE = 0,
        /// The task was just woken.
        WAKEUP = 1,
        /// Put the task at the head of the DSQ.
        HEAD = 1 << 4,
        /// Preempt the task running on the target CPU.
        PREEMPT = 1 << 32,
    }
}

flags! {
    /// The flags of a dequeue, ops.dequeue()'s and ops.quiescent()'s.
    DeqFlags {
        /// The task is going to sleep.
        SLEEP = 1,
    }
}

/// One of the kernel's arguments to a callback, as the type the callback
/// declares for it.
pub trait Arg {
    /// # Safety
    /// `context` must be the callback's context, with argument `index`.
    unsafe fn arg(context: *const u64, index: usize) -> Self;
}

impl<'task> Arg for &'task Task {
    #[inline(always)]
    unsafe fn arg(context: *const u64, index: usize) -> Self {
        unsafe { Task::from_ptr(*context.add(index) as *mut task_struct) }
    }
}

impl<'task> Arg for Option<&'task Task> {
    #[inline(always)]
    unsafe fn arg(context: *const u64, index: usize) -> Self {
        let task = unsafe { *context.add(index) } as *mut task_struct;
        if task.is_null() {
            None
        } else {
            Some(unsafe { Task::from_ptr(task) })
        }
    }
}

impl Arg for Cid {
    #[inline(always)]
    unsafe fn arg(context: *const u64, index: usize) -> Self {
        Cid(unsafe { *context.add(index) } as i32)
    }
}

impl Arg for bool {
    #[inline(always)]
    unsafe fn arg(context: *const u64, index: usize) -> Self {
        unsafe { *context.add(index) != 0 }
    }
}

impl Arg for u64 {
    #[inline(always)]
    unsafe fn arg(context: *const u64, index: usize) -> Self {
        unsafe { *context.add(index) }
    }
}

macro_rules! flags_arg {
    ($($name:ident),*) => {
        $(impl Arg for $name {
            #[inline(always)]
            unsafe fn arg(context: *const u64, index: usize) -> Self {
                $name(unsafe { *context.add(index) })
            }
        })*
    };
}
flags_arg!(WakeFlags, EnqFlags, DeqFlags);

/// What a callback returns, as the kernel takes it.
pub trait Ret {
    fn ret(self) -> u64;
}

impl Ret for () {
    #[inline(always)]
    fn ret(self) -> u64 {
        0
    }
}

impl Ret for Cid {
    #[inline(always)]
    fn ret(self) -> u64 {
        self.0 as u64
    }
}

impl Ret for bool {
    #[inline(always)]
    fn ret(self) -> u64 {
        u64::from(self)
    }
}

impl Ret for Result<(), i32> {
    #[inline(always)]
    fn ret(self) -> u64 {
        match self {
            Ok(()) => 0,
            Err(errno) => errno as u64,
        }
    }
}

/// The entry of every callback: reference the arena, which a program that
/// reads arena memory must do once.
#[inline(always)]
pub fn enter() {
    crate::pool::touch();
}

/// The runtime's part of ops.init(): the idle tracking and the per-CID
/// table under it. Returns 0 or a negative errno.
///
/// # Safety
/// Only from ops.init().
#[inline(always)]
pub unsafe fn init() -> i32 {
    unsafe { cid_idle::init() }
}

/// The runtime's part of ops.update_idle(cid, idle).
///
/// # Safety
/// `context` must be ops.update_idle()'s.
#[inline(always)]
pub unsafe fn update_idle(context: *const u64) {
    unsafe { cid_idle::update(*context as i32, *context.add(1) != 0) };
}

/// The runtime's part of ops.dispatch(cid, prev), after the scheduler's: a
/// CID that leaves with nothing on its local DSQ and the idle task current
/// is idle again. The kernel calls ops.update_idle() only when a CPU
/// enters or leaves the idle task, so a CPU that a claim woke for a task
/// another CPU then took would otherwise stay claimed.
///
/// # Safety
/// `context` must be ops.dispatch()'s.
#[inline(always)]
pub unsafe fn dispatched(context: *const u64) {
    unsafe {
        if scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL) == 0 {
            cid_idle::rearm(*context as i32, config::get(config::TASK_FLAGS) as usize);
        }
    }
}
