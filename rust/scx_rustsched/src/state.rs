// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The scheduler's own state per task, as a type.
//!
//! ```ignore
//! #[derive(Default)]
//! struct TaskCtx {
//!     vtime: Var<u64>,
//! }
//!
//! #[scx::scheduler(name = "vtime", task = TaskCtx)]
//! impl Vtime {
//!     fn enable(task: &Task) {
//!         let Some(ctx) = task.state::<TaskCtx>() else { return };
//!         ctx.vtime.set(VTIME_NOW.get());
//!     }
//! }
//! ```
//!
//! `task = TaskCtx` gives every task of the scheduler a `TaskCtx`, created
//! as `TaskCtx::default()` in ops.init_task() and freed by the kernel with
//! the task. `Task::state()` hands it out as a shared reference, so its
//! fields are `Var`s. It is `None` only for a task the scheduler was never
//! given, such as the idle task or one of another scheduling class.
//!
//! The state lives in BPF task storage, which the verifier bounds-checks:
//! the kernel finds a task's storage from the task, and a reference to it
//! is an ordinary map value.

use core::ffi::c_void;

use crate::{helpers, ops::task_struct, sched::Error};

/// The BTF-defined map of a task storage whose value is `T`.
#[repr(C)]
pub struct TaskStorage<T> {
    r#type: *const [u32; 29],
    map_flags: *const [u32; 1],
    key: *const i32,
    value: *const T,
}

impl<T> TaskStorage<T> {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            map_flags: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
        }
    }
}

/// A type that is the scheduler's per-task state, which `task_state!`
/// implements.
pub trait TaskState: Default + 'static {
    /// The task storage map that holds it.
    fn map() -> *mut c_void;
}

/// Declare `$type` as the per-task state: its map, `task_state`, and its
/// `TaskState`. `#[scheduler(task = $type)]` does this.
#[macro_export]
macro_rules! task_state {
    ($type:ty) => {
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".maps")]
        pub static mut task_state: $crate::state::TaskStorage<$type> =
            $crate::state::TaskStorage::new();

        impl $crate::state::TaskState for $type {
            #[inline(always)]
            fn map() -> *mut core::ffi::c_void {
                (&raw mut task_state).cast()
            }
        }
    };
}

/// Give `task` its state, `T::default()`, from ops.init_task().
///
/// # Safety
/// `task` must be ops.init_task()'s.
#[inline(always)]
pub unsafe fn create<T: TaskState>(task: *mut task_struct) -> Result<(), Error> {
    let mut initial = T::default();
    let state: *mut T =
        unsafe { helpers::task_storage_get(T::map(), task, (&raw mut initial).cast(), 1) };
    if state.is_null() {
        return Err(Error::ENOMEM);
    }
    Ok(())
}

/// The state of `task`, or `None` if it has none.
///
/// # Safety
/// `task` must be a task the kernel passed to the running callback, and
/// the reference must not outlive the callback.
#[inline(always)]
pub unsafe fn get<'task, T: TaskState>(task: *mut task_struct) -> Option<&'task T> {
    let state: *mut T =
        unsafe { helpers::task_storage_get(T::map(), task, core::ptr::null_mut(), 0) };
    if state.is_null() {
        None
    } else {
        Some(unsafe { &*state })
    }
}
