// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The pool of per-task slots in the arena: the task-storage map that
//! ties a task to its slot, and the free list the slots are handed out
//! from.
//!
//! This is the per-task state of a scheduler that queues tasks in the
//! arena, where an EDQ node has to live and other CPUs reach a task's
//! state by address, and of any scheduler that wants its state there.
//! `state` is the alternative, in task storage, which hands out
//! references.
//!
//! The scheduler declares what a slot holds with `arena_struct!` and
//! implements `TaskSlot` for it:
//!
//! ```ignore
//! scx::arena_struct! {
//!     pub struct TaskCtx { vtime: u64, node: [u64; NODE_WORDS] }
//! }
//! impl scx::slots::TaskSlot for TaskCtx {}
//!
//! #[scx::scheduler(name = "...", task_slot = TaskCtx)]
//! impl Sched {
//!     fn running(task: &Task) {
//!         let Some(ctx) = task.slot::<TaskCtx>() else { return };
//!         ctx.vtime().set(...);
//!     }
//! }
//! ```
//!
//! `#[scheduler(task_slot = Type)]` then sets the pool up in ops.init(),
//! gives each task a slot in ops.init_task(), reset, and takes it back
//! after the scheduler's ops.exit_task(). A slot starts with two words of
//! the pool's own, a cookie a lookup checks and the free list's link, and
//! the scheduler's structure follows them.

use core::ptr::{null, null_mut, read_volatile, write_volatile};

use crate::{
    arena::Struct,
    config,
    edq::Memory,
    helpers,
    kfuncs::{bpf_arena_alloc_pages, scx_bpf_task_set_dsq_vtime},
    mem,
    pool::{self, Arena, arena},
    slab, task_struct,
};

/// What a live slot starts with, and what a lookup checks.
const COOKIE: u64 = 0x5255535453435801;
/// Pages a pool that ran dry grows by.
const CHUNK_PAGES: u32 = 8;
/// Page allocations retried before a growth fails: bpf_arena_alloc_pages()
/// takes pages with alloc_pages_nolock(), which fails under contention on
/// the free lists even with memory free, as lib/sdt_alloc.bpf.c retries.
const ALLOC_RETRIES: u32 = 64;

/// The pool's words at the start of a slot: the cookie, and the link to
/// the next free slot while this one is free, see slab.rs.
const HEADER: u64 = 16;
const LINK: u64 = 8;

/// What the scheduler keeps per task, in a slot of the pool.
pub trait TaskSlot: Struct {
    /// Keep the slot's address in the task itself, in
    /// task_struct.scx.dsq_vtime, so that a lookup costs a load where the
    /// task storage costs a call. Only for a scheduler that orders no DSQ
    /// by vtime, since that is what the field is for. The kernel resets
    /// the field when the task leaves the scheduler.
    const STASH: bool = false;

    /// Bring a slot just taken from the free list to the state a new task
    /// starts in, before it is published to the task. Every field a
    /// reader may see before the first write to it has to be set: a slot
    /// comes back with what its last task left in it.
    #[inline(always)]
    fn reset(&self) {
        self.zero();
    }

    /// The task is leaving: may its slot be handed to another task? A
    /// slot whose queue node something still holds must say no, and is
    /// then leaked and counted as an error rather than reused under its
    /// holder.
    #[inline(always)]
    fn detach(&self) -> bool {
        true
    }
}

/// Bytes per slot: the header and the structure, rounded up to a power of
/// two so that slots tile a page.
const fn slot_size<T: TaskSlot>() -> u64 {
    let size = (HEADER + T::SIZE).next_power_of_two();
    assert!(size <= 4096, "a task slot does not fit in a page");
    size
}

#[inline(always)]
fn stash_offset<T: TaskSlot>() -> usize {
    if T::STASH {
        config::get(config::DSQ_VTIME) as usize
    } else {
        0
    }
}

/// What the task storage holds: the address of the task's structure, past
/// its slot's header, so that a lookup returns it as it reads it.
#[repr(C)]
pub struct TaskRef {
    address: u64,
}

#[repr(C)]
pub struct TaskStorageMap {
    r#type: *const [u32; 29],
    map_flags: *const [u32; 1],
    key: *const i32,
    value: *const TaskRef,
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".maps")]
pub static mut task_refs: TaskStorageMap = TaskStorageMap {
    r#type: null(),
    map_flags: null(),
    key: null(),
    value: null(),
};

/// The address of the free list's head word, in a page of its own.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.slab")]
static mut SLAB: [u64; 1] = [0; 1];

#[inline(always)]
fn head() -> u64 {
    unsafe { read_volatile((&raw const SLAB).cast::<u64>()) }
}

/// Allocate `pages` pages, retried as ALLOC_RETRIES says, and carve them
/// into slots on the free list, all but the first if `keep_first`. Returns
/// the first page, which is the first slot, or 0 if no pages could be had.
#[inline(always)]
unsafe fn grow<T: TaskSlot>(pages: u32, keep_first: bool) -> u64 {
    let mut memory = null_mut();
    Arena.repeat(ALLOC_RETRIES, || unsafe {
        memory = bpf_arena_alloc_pages((&raw mut arena).cast(), null_mut(), pages, -1, 0);
        memory.is_null()
    });
    if memory.is_null() {
        pool::count(3);
        return 0;
    }
    pool::add(4, u64::from(pages));
    let size = const { slot_size::<T>() };
    let slots = pages * (4096 / size) as u32;
    let skip = u32::from(keep_first);
    let first = memory as u64 + u64::from(skip) * size;
    if slots > skip {
        unsafe {
            for value in crate::loops::range(0, slots - skip - 1) {
                slab::link_next(Arena, first, u64::from(value), size, LINK);
            }
        }
        let last = first + u64::from(slots - skip - 1) * size;
        if !unsafe { slab::push_chain(Arena, head(), first, last, LINK) } {
            // Leaked, not lost: the free list stayed contended throughout.
            pool::count(2);
        }
    }
    memory as u64
}

/// Set up the free list and carve the initial pool of `pages` pages.
#[inline(always)]
pub unsafe fn initialize_pool<T: TaskSlot>(pages: u64) -> i32 {
    if pages == 0 || pages > 8192 {
        return -22;
    }
    let page = unsafe { bpf_arena_alloc_pages((&raw mut arena).cast(), null_mut(), 1, -1, 0) };
    if page.is_null() {
        pool::count(3);
        return -12;
    }
    unsafe {
        SLAB[0] = page as u64;
        Arena.store(page as u64, slab::empty());
    }
    if unsafe { grow::<T>(pages as u32, false) } == 0 {
        return -12;
    }
    0
}

#[inline(always)]
unsafe fn storage(task: *mut task_struct, create: bool) -> *mut TaskRef {
    unsafe { helpers::task_storage_get(&raw mut task_refs, task, null_mut(), u64::from(create)) }
}

#[inline(always)]
unsafe fn delete_storage(task: *mut task_struct) {
    unsafe { helpers::task_storage_delete(&raw mut task_refs, task) };
}

#[inline(always)]
unsafe fn set_cookie(page: u64) {
    unsafe { mem::store(page, 0, COOKIE) }
}

#[inline(always)]
unsafe fn cookie_of(page: u64) -> u64 {
    unsafe { mem::load(page, 0) }
}

/// Give `task` a slot: taken from the free list, or from pages the pool
/// grows by when it ran dry, which init_task may do as it is sleepable.
/// Returns 0, or -ENOMEM.
#[inline(always)]
pub unsafe fn initialize<T: TaskSlot>(task: *mut task_struct) -> i32 {
    unsafe {
        let reference = storage(task, true);
        if reference.is_null() {
            pool::count(3);
            return -12;
        }
        let mut page = slab::pop(Arena, head(), LINK);
        if page == 0 {
            page = grow::<T>(CHUNK_PAGES, true);
        }
        if page == 0 {
            delete_storage(task);
            return -12;
        }
        set_cookie(page);
        T::from_address(page + HEADER).reset();
        write_volatile(&raw mut (*reference).address, page + HEADER);
        pool::count(0);
    }
    0
}

/// The slot address kept in the task itself, task_struct.scx.dsq_vtime,
/// or 0. scx_eevdf keeps it there too: nothing here orders a DSQ by vtime,
/// the kernel resets the field when the task leaves the scheduler, and
/// reading it costs a load where the task storage costs a lookup. The
/// field's offset is `stash_offset`, 0 when the kernel has no such field.
#[inline(always)]
unsafe fn stashed(task: *mut task_struct, stash_offset: usize) -> u64 {
    unsafe {
        if stash_offset == 0 {
            return 0;
        }
        read_volatile(task.cast::<u8>().add(stash_offset).cast::<u64>())
    }
}

/// Keep the slot address in the task for the fast lookup, from
/// ops.enable(), once the task is the scheduler's, if the slot type asks
/// for it. Only that op writes the field, and the kernel zeroes it at
/// fork, init_scx_entity(), and when the task leaves the scheduler, before
/// exit_task releases the slot: a value there is this task's live slot,
/// with no cookie to check.
#[inline(always)]
pub unsafe fn stash<T: TaskSlot>(task: *mut task_struct) {
    if !T::STASH {
        return;
    }
    unsafe {
        let reference = storage(task, false);
        if reference.is_null() {
            return;
        }
        let page = read_volatile(&raw const (*reference).address);
        if page != 0 {
            scx_bpf_task_set_dsq_vtime(task, page);
        }
    }
}

#[inline(always)]
unsafe fn page_optional(task: *mut task_struct, stash_offset: usize) -> Option<u64> {
    unsafe {
        let page = stashed(task, stash_offset);
        if page != 0 {
            return Some(page);
        }
        let reference = storage(task, false);
        if reference.is_null() {
            return None;
        }
        let page = read_volatile(&raw const (*reference).address);
        if page == 0 {
            return None;
        }
        if cookie_of(page - HEADER) != COOKIE {
            pool::count(2);
            return None;
        }
        Some(page)
    }
}

#[inline(always)]
unsafe fn page_of(task: *mut task_struct, stash_offset: usize) -> Option<u64> {
    unsafe {
        let page = stashed(task, stash_offset);
        if page != 0 {
            return Some(page);
        }
        let reference = storage(task, false);
        if reference.is_null() {
            pool::count(2);
            return None;
        }
        let page = read_volatile(&raw const (*reference).address);
        if page == 0 || cookie_of(page - HEADER) != COOKIE {
            pool::count(2);
            return None;
        }
        Some(page)
    }
}

/// The slot of a task that may have none, such as the task that runs a
/// wakeup: the idle task, or one of a higher class. A missing slot is not
/// an error here; a corrupt one still is.
#[inline(always)]
pub unsafe fn lookup_optional<T: TaskSlot>(task: *mut task_struct) -> Option<T> {
    unsafe { page_optional(task, stash_offset::<T>()).map(T::from_address) }
}

/// The slot of a task of the scheduler's. None, counted as an error, when
/// the task has none or its slot is corrupt.
#[inline(always)]
pub unsafe fn lookup<T: TaskSlot>(task: *mut task_struct) -> Option<T> {
    unsafe { page_of(task, stash_offset::<T>()).map(T::from_address) }
}

/// The task leaves the scheduler: give its slot back to the free list,
/// unless the slot type says something still holds it, and drop its
/// storage.
#[inline(always)]
pub unsafe fn release<T: TaskSlot>(task: *mut task_struct) {
    unsafe {
        let reference = storage(task, false);
        if reference.is_null() {
            return;
        }
        let address = read_volatile(&raw const (*reference).address);
        if address != 0 {
            let page = address - HEADER;
            if cookie_of(page) == COOKIE && !T::from_address(address).detach() {
                // Leaked: the slot stays the task's until the storage goes
                // with the task, and no other task is given it.
                pool::count(2);
                return;
            }
            write_volatile(&raw mut (*reference).address, 0);
            if cookie_of(page) != COOKIE {
                pool::count(2);
            }
            if slab::push(Arena, head(), page, LINK) {
                pool::count(1);
            } else {
                pool::count(2);
            }
        }
        delete_storage(task);
    }
}
