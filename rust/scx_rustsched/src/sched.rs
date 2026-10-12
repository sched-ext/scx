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
//! task, `Cid` for a CID, a flags type or `u64` for flags, `bool`, `u32`,
//! `Cmask`, and `&Cgroup`, `&CgroupArgs`, `&DumpCtx` and `&ExitInfo`. It may
//! leave trailing arguments out. It returns what `Ret` converts: nothing, a
//! `Cid`, a `bool`, or `Result<(), Error>`.
//!
//! The callbacks, by what they are about:
//!
//! - the scheduler: init(), exit(info), cid_online(cid), cid_offline(cid);
//! - a task's life: init_task(task), exit_task(task), enable(task),
//!   disable(task), set_weight(task, weight), set_cmask(task, cmask);
//! - scheduling: select_cid(task, prev, wake_flags) -> Cid,
//!   enqueue(task, enq_flags), dequeue(task, deq_flags),
//!   dispatch(cid, prev), runnable(task, enq_flags), running(task),
//!   stopping(task, runnable), quiescent(task, deq_flags), tick(task),
//!   yield_task(from, to) -> bool, core_sched_before(a, b) -> bool,
//!   update_idle(cid, idle);
//! - the debug dump: dump(dump), dump_cid(dump, cid, idle),
//!   dump_task(dump, task), see `dump`;
//! - cgroups: cgroup_init(cgroup, args), cgroup_exit(cgroup),
//!   cgroup_prep_move(task, from, to), cgroup_move(task, from, to),
//!   cgroup_cancel_move(task, from, to), cgroup_set_weight(cgroup, weight),
//!   cgroup_set_bandwidth(cgroup, period_us, quota_us, burst_us) and
//!   cgroup_set_idle(cgroup, idle), see `cgroup`.
//!
//! yield_task is ops.yield(), `yield` being a keyword. A scheduler that
//! defines cid_online or cid_offline handles CPU hotplug itself; the
//! kernel ejects one that defines neither when a CPU comes or goes.
//!
//! `task_slot = Type` in the attribute gives every task a `Type` of the
//! scheduler's own in the arena, see `slots`, and `cid_slot = Type` every
//! CID, see `cid_table`.
//!
//! `#[global]` makes a function of the scheduler's one the verifier checks
//! once, see `scx_rustsched_macros`.
//!
//! The runtime does its own part in three of them, before or after the
//! scheduler's: ops.init() sets up the idle tracking, ops.update_idle()
//! mirrors each transition into it, and ops.dispatch() marks a CID idle
//! again when it leaves with nothing to run, since the kernel reports no
//! transition for a CPU that was woken and went back to sleep. ops.exit()
//! records the exit for the loader, before the scheduler's own. A scheduler
//! never has to define any of those to have `idle::pick()` work.
//!
//! `idle_tracking = false` in the attribute leaves the idle tracking to
//! the scheduler, which then calls `cid_idle` from those three callbacks
//! itself.

use crate::{
    cgroup::{Cgroup, CgroupArgs},
    cid_idle,
    cmask::Cmask,
    config,
    dump::DumpCtx,
    kfuncs::{scx_bpf_dsq_nr_queued, scx_bpf_kick_cid, scx_bpf_this_cid},
    ops::{SCX_DSQ_LOCAL, task_struct},
    task::Task,
    uei::ExitInfo,
};

pub use scx_rustsched_macros::{global, scheduler};

/// A CID or none, in one register: what a search for a CID returns.
///
/// `Option<Cid>` is two values to the compiler, a tag and a CID, and the
/// CID of a `None` is undefined. Where two paths meet, one with a CID and
/// one without, the compiler may copy that undefined half, and the
/// verifier refuses a read of a register nothing wrote. So a CID that may
/// be none is carried as the kernel carries one, a negative number for
/// none, and turned into an `Option` where it is used:
///
/// ```ignore
/// if let Some(cid) = search(task).get() { ... }
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct OptCid(i32);

impl OptCid {
    pub const NONE: OptCid = OptCid(-1);

    #[inline(always)]
    pub fn some(cid: Cid) -> OptCid {
        OptCid(cid.0)
    }

    /// From a number as the kernel returns one where a CID is expected:
    /// negative for none.
    #[inline(always)]
    pub fn from_raw(raw: i32) -> OptCid {
        OptCid(raw)
    }

    /// The CID, or -1 or the negative number it was made from.
    #[inline(always)]
    pub fn raw(self) -> i32 {
        self.0
    }

    #[inline(always)]
    pub fn get(self) -> Option<Cid> {
        if self.0 >= 0 { Some(Cid(self.0)) } else { None }
    }

    #[inline(always)]
    pub fn is_some(self) -> bool {
        self.0 >= 0
    }

    #[inline(always)]
    pub fn is_none(self) -> bool {
        self.0 < 0
    }

    /// The CID, or `default` for none.
    #[inline(always)]
    pub fn unwrap_or(self, default: Cid) -> Cid {
        if self.0 >= 0 { Cid(self.0) } else { default }
    }
}

impl From<Option<Cid>> for OptCid {
    #[inline(always)]
    fn from(cid: Option<Cid>) -> OptCid {
        match cid {
            Some(cid) => OptCid(cid.0),
            None => OptCid::NONE,
        }
    }
}

/// A CPU as the scheduler sees it: an index into the kernel's
/// topology-ordered CID space, where the CPUs of a core, an LLC and a node
/// are contiguous.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Cid(pub i32);

impl Cid {
    /// No CID: what a search that found none returns where the kernel's
    /// convention of a negative number is kept.
    pub const NONE: Cid = Cid(-1);

    /// The CID as the kfuncs take it.
    #[inline(always)]
    pub fn raw(self) -> i32 {
        self.0
    }

    /// The CID as an index into a per-CID table or a mask.
    #[inline(always)]
    pub fn index(self) -> u32 {
        self.0 as u32
    }

    /// Is this a CID at all, rather than `NONE` or an error code?
    #[inline(always)]
    pub fn is_some(self) -> bool {
        self.0 >= 0
    }

    /// The CID the callback runs on.
    #[inline(always)]
    pub fn current() -> Cid {
        Cid(unsafe { scx_bpf_this_cid() })
    }

    /// The CID of a CPU, by the kernel's number for it.
    #[inline(always)]
    pub fn from_cpu(cpu: i32) -> Cid {
        Cid(unsafe { crate::kfuncs::scx_bpf_cpu_to_cid(cpu) })
    }

    /// The number of CPU numbers the kernel has, nr_cpu_ids: a task allowed
    /// on fewer CPUs is restricted.
    #[inline(always)]
    pub fn nr_cpus() -> u32 {
        crate::cids::nr_cpu_ids()
    }

    /// Tell the frequency governor how busy the CID is, of 1024.
    #[inline(always)]
    pub fn set_perf(self, perf: u32) {
        unsafe { crate::kfuncs::scx_bpf_cidperf_set(self.0, perf) };
    }

    /// The number of CIDs: they are `Cid(0)` to `Cid(count - 1)`.
    #[inline(always)]
    pub fn count() -> u32 {
        crate::cids::count()
    }

    /// Every CID, in topology order.
    #[inline(always)]
    pub fn all() -> Cids {
        Cids(crate::loops::range(0, Self::count()))
    }

    /// The CIDs of `scope` around this one, itself among them: its core,
    /// its LLC, its node.
    #[inline(always)]
    pub fn scope(self, scope: crate::cid_idle::Scope) -> Cids {
        let (base, count) = cid_idle::scope_cids(self, scope);
        Cids(crate::loops::range(base, base + count))
    }

    /// The scheduler's entry for the CID, of the type it declared with
    /// `#[scheduler(cid_slot = T)]`. `None` for a number that is not a
    /// CID.
    #[inline(always)]
    pub fn slot<T: crate::cid_table::CidSlot>(self) -> Option<T> {
        crate::cid_table::slot(self)
    }

    /// Make the CID go through the scheduler again: wake it if it is
    /// idle, and with `KickFlags::PREEMPT` take the CPU from what runs
    /// there. `KickFlags::IDLE` kicks it only if it is idle.
    #[inline(always)]
    pub fn kick(self, flags: KickFlags) {
        unsafe { scx_bpf_kick_cid(self.0, flags.0) };
    }
}

/// CIDs to loop over, from `Cid::all()` or `Cid::scope()`. The loop is one
/// the verifier can bound, so it may also end early, when the program has
/// used up its loop budget, which no topology comes near.
pub struct Cids(crate::loops::Range);

impl Iterator for Cids {
    type Item = Cid;

    #[inline(always)]
    fn next(&mut self) -> Option<Cid> {
        self.0.next().map(|cid| Cid(cid as i32))
    }
}

/// Why a callback failed, as the negative errno the kernel takes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Error(pub i32);

impl Error {
    pub const ENOENT: Error = Error(-2);
    pub const ENOMEM: Error = Error(-12);
    pub const EBUSY: Error = Error(-16);
    pub const EINVAL: Error = Error(-22);

    /// A kernel-style result as a callback returns it: 0, or a negative
    /// errno.
    #[inline(always)]
    pub fn check(result: i32) -> Result<(), Error> {
        match result {
            0 => Ok(()),
            errno => Err(Error(errno)),
        }
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
    /// How `Cid::kick()` kicks.
    KickFlags {
        NONE = 0,
        /// Only if the CID is idle.
        IDLE = 1,
        /// Preempt the task running there.
        PREEMPT = 2,
    }
}

impl EnqFlags {
    /// Is the task the last runnable one of a CPU that found nothing else
    /// to run? The kernel enqueues it so only for a scheduler that asked
    /// with the `ENQ_LAST` flag, and otherwise keeps it running. The CPU
    /// has made its pick by then and goes idle: a task left on a queue
    /// stays there until something makes a CPU look, such as a kick.
    #[inline(always)]
    pub fn last(self) -> bool {
        let last = crate::config::get(crate::config::ENQ_LAST);
        last != 0 && self.0 & last != 0
    }

    /// Is the task a proxy-execution donor that has just blocked on a
    /// mutex? Only with the `ENQ_BLOCKED` flag, see `Task::is_blocked()`.
    #[inline(always)]
    pub fn blocked(self) -> bool {
        let blocked = crate::config::get(crate::config::ENQ_BLOCKED);
        blocked != 0 && self.0 & blocked != 0
    }

    /// Did ops.select_cid() run for this enqueue? It does not for a wakeup
    /// the kernel queued to the task's CPU, which the `ALLOW_QUEUED_WAKEUP`
    /// flag allows, nor for an enqueue that is not a wakeup. A scheduler
    /// that places tasks in ops.select_cid() looks for a CID in
    /// ops.enqueue() when this is false and the task is not running. True
    /// on a kernel that does not say.
    #[inline(always)]
    pub fn cid_selected(self) -> bool {
        let selected = crate::config::get(crate::config::ENQ_CPU_SELECTED);
        selected == 0 || self.0 & selected != 0
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
        // The kernel's caller sets only the low byte of a bool's slot.
        unsafe { *context.add(index) & 0xff != 0 }
    }
}

impl Arg for Cmask {
    #[inline(always)]
    unsafe fn arg(context: *const u64, index: usize) -> Self {
        unsafe { Cmask::from_raw(*context.add(index)) }
    }
}

impl Arg for u32 {
    #[inline(always)]
    unsafe fn arg(context: *const u64, index: usize) -> Self {
        unsafe { *context.add(index) as u32 }
    }
}

macro_rules! handle_arg {
    ($($name:ty),*) => {
        $(impl<'handle> Arg for &'handle $name {
            #[inline(always)]
            unsafe fn arg(context: *const u64, index: usize) -> Self {
                unsafe { <$name>::from_ptr(*context.add(index) as *mut _) }
            }
        })*
    };
}
handle_arg!(Cgroup, CgroupArgs, DumpCtx, ExitInfo);

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

impl Ret for Result<(), Error> {
    #[inline(always)]
    fn ret(self) -> u64 {
        match self {
            Ok(()) => 0,
            Err(error) => error.0 as u64,
        }
    }
}

/// A value as a BPF global function takes or returns it, for `#[global]`:
/// a scalar, or a pointer to a task the build tags as trusted.
pub trait Abi {
    type Raw;

    fn into_raw(self) -> Self::Raw;

    /// # Safety
    /// `raw` must come from `into_raw()`, in the same callback.
    unsafe fn from_raw(raw: Self::Raw) -> Self;
}

macro_rules! scalar_abi {
    ($($name:ty),*) => {
        $(impl Abi for $name {
            type Raw = $name;

            #[inline(always)]
            fn into_raw(self) -> $name {
                self
            }

            #[inline(always)]
            unsafe fn from_raw(raw: $name) -> $name {
                raw
            }
        })*
    };
}
scalar_abi!((), bool, i32, u32, i64, u64);

macro_rules! wrapped_abi {
    ($($name:ident: $raw:ty),*) => {
        $(impl Abi for $name {
            type Raw = $raw;

            #[inline(always)]
            fn into_raw(self) -> $raw {
                self.0
            }

            #[inline(always)]
            unsafe fn from_raw(raw: $raw) -> $name {
                $name(raw)
            }
        })*
    };
}
wrapped_abi!(Cid: i32, OptCid: i32, WakeFlags: u64, EnqFlags: u64, DeqFlags: u64, KickFlags: u64);

impl<'task> Abi for &'task Task {
    type Raw = *mut task_struct;

    #[inline(always)]
    fn into_raw(self) -> *mut task_struct {
        self.as_ptr()
    }

    #[inline(always)]
    unsafe fn from_raw(raw: *mut task_struct) -> &'task Task {
        unsafe { Task::from_ptr(raw) }
    }
}

/// A pointer passes as it is: to a structure on the caller's stack that
/// the function fills, which the verifier bounds by the structure's size.
impl<T> Abi for *mut T {
    type Raw = *mut T;

    #[inline(always)]
    fn into_raw(self) -> *mut T {
        self
    }

    #[inline(always)]
    unsafe fn from_raw(raw: *mut T) -> *mut T {
        raw
    }
}

/// The entry of every callback: reference the arena, which a program that
/// reads arena memory must do once.
#[inline(always)]
pub fn enter() {
    crate::pool::touch();
}

/// The runtime's part of ops.init(): the idle tracking and the per-CID
/// table under it.
///
/// # Safety
/// Only from ops.init().
#[inline(always)]
pub unsafe fn init() -> Result<(), Error> {
    match unsafe { cid_idle::init() } {
        0 => Ok(()),
        errno => Err(Error(errno)),
    }
}

/// The runtime's part of ops.init() for a scheduler with an entry `T`
/// per CID: the table, zeroed.
///
/// # Safety
/// Only from ops.init().
#[inline(always)]
pub unsafe fn init_cid_slots<T: crate::cid_table::CidSlot>() -> Result<(), Error> {
    Error::check(unsafe { crate::cid_table::init_slots::<T>() })
}

/// The runtime's part of ops.init() for a scheduler with a slot `T` per
/// task: the pool, with the pages the loader configured.
///
/// # Safety
/// Only from ops.init().
#[inline(always)]
pub unsafe fn init_slots<T: crate::slots::TaskSlot>() -> Result<(), Error> {
    Error::check(unsafe { crate::slots::initialize_pool::<T>(config::get(config::ARENA_PAGES)) })
}

/// The runtime's part of ops.init_task(task, args) for a scheduler with a
/// slot `T` per task: give the task one, reset.
///
/// # Safety
/// `context` must be ops.init_task()'s.
#[inline(always)]
pub unsafe fn create_slot<T: crate::slots::TaskSlot>(context: *const u64) -> Result<(), Error> {
    Error::check(unsafe { crate::slots::initialize::<T>(*context as *mut task_struct) })
}

/// The runtime's part of ops.enable(task) for a scheduler with a slot `T`
/// per task: keep the slot's address in the task, if `T` asks for it.
///
/// # Safety
/// `context` must be ops.enable()'s.
#[inline(always)]
pub unsafe fn stash_slot<T: crate::slots::TaskSlot>(context: *const u64) {
    unsafe { crate::slots::stash::<T>(*context as *mut task_struct) };
}

/// The runtime's part of ops.exit_task(task, args) for a scheduler with a
/// slot `T` per task, after the scheduler's: take the slot back.
///
/// # Safety
/// `context` must be ops.exit_task()'s.
#[inline(always)]
pub unsafe fn release_slot<T: crate::slots::TaskSlot>(context: *const u64) {
    unsafe { crate::slots::release::<T>(*context as *mut task_struct) };
}

/// The runtime's part of ops.update_idle(cid, idle).
///
/// # Safety
/// `context` must be ops.update_idle()'s.
#[inline(always)]
pub unsafe fn update_idle(context: *const u64) {
    unsafe { cid_idle::update(Cid(*context as i32), *context.add(1) != 0) };
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
            cid_idle::rearm(
                Cid(*context as i32),
                config::get(config::TASK_FLAGS) as usize,
            );
        }
    }
}
