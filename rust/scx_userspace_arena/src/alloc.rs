// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_intf::scx_userspace_arena_alloc_pages_args;
use crate::bpf_intf::scx_userspace_arena_free_pages_args;

use anyhow::Result;
use buddy_system_allocator::Heap;
use libbpf_rs::ProgramInput;

use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::Mutex;

/// A subset of the features of `std::alloc::Allocator` which is experimental. Changed the error
/// types to `anyhow::Error` so we can forward libbpf_rs errors. This will likely need to be the
/// empty struct `std::alloc::AllocError` if we migrate to the official trait (and panic
/// accordingly).
///
/// # Safety
///
/// See https://doc.rust-lang.org/std/alloc/trait.Allocator.html#safety
pub unsafe trait Allocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, anyhow::Error>;

    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, anyhow::Error> {
        let ptr = self.allocate(layout)?;
        // SAFETY: `allocate` returns a valid memory block
        let slice: &mut [u8] = unsafe { &mut *ptr.as_ptr() };
        slice.fill(0);
        Ok(ptr)
    }

    /// # Safety
    ///
    /// See https://doc.rust-lang.org/std/alloc/trait.Allocator.html#safety-1
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout);
}

type FreeList = Vec<(NonNull<[u8]>, Layout)>;

pub struct HeapAllocator<T>
where
    T: Allocator,
{
    backing_allocator: T,
    alloc: Mutex<(Heap<31>, FreeList)>,
}

impl<T> HeapAllocator<T>
where
    T: Allocator,
{
    pub fn new(backing_allocator: T) -> Self {
        Self {
            backing_allocator,
            alloc: Mutex::new((Heap::empty(), Vec::new())),
        }
    }
}

impl<T> Drop for HeapAllocator<T>
where
    T: Allocator,
{
    fn drop(&mut self) {
        for a in self.alloc.get_mut().unwrap().1.iter() {
            let first_byte_pointer = unsafe {
                // SAFETY: it's definitely not null
                NonNull::new_unchecked(a.0.as_ptr() as *mut u8)
            };
            unsafe {
                // SAFETY: it was allocated by this allocator so this is safe
                self.backing_allocator.deallocate(first_byte_pointer, a.1);
            }
        }
    }
}

unsafe impl<T> Allocator for HeapAllocator<T>
where
    T: Allocator,
{
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, anyhow::Error> {
        let mut guard = self.alloc.lock().unwrap();
        let (alloc, free_list) = &mut *guard;

        if let Ok(a) = alloc.alloc(layout) {
            // `Heap` doesn't match the allocator API. It returns a `NonNull<u8>`, but we want a
            // `NonNull<[u8]>`. Simply use the length from the Layout, as it will always have
            // allocated at least enough memory.
            return Ok(NonNull::slice_from_raw_parts(a, layout.size()));
        }

        // try to strike a balance between backing allocations being unmergeable and wasting pinned
        // kernel memory (we're effectively never going to free this).
        let next_allocation_size = alloc
            .stats_total_bytes()
            .next_power_of_two()
            .clamp(16 * 1024, 1024 * 1024);
        let backing_layout = if layout.size() > next_allocation_size {
            layout
        } else {
            Layout::from_size_align(next_allocation_size, 1)?
        };
        let ptr = self.backing_allocator.allocate(backing_layout)?;

        free_list.push((ptr, backing_layout));

        unsafe {
            // SAFETY: `allocate` returns a valid memory block
            alloc.init(ptr.cast::<u8>().as_ptr() as usize, backing_layout.size())
        };

        alloc
            .alloc(layout)
            .map(|a| NonNull::slice_from_raw_parts(a, layout.size()))
            .map_err(|_| anyhow::anyhow!("failed to allocate"))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.alloc.lock().unwrap().0.dealloc(ptr, layout)
    }
}

/// Helper to call an allocate program with the correct arguments.
///
/// # Safety
///
/// Caller must ensure that the BPF program has the expected signature and behaviour. Effectively,
/// the program must have the same behaviour as `scx_userspace_arena_allocate` in
/// "lib/sdt_alloc.bpf.c", and ideally be that program.
pub unsafe fn call_allocate_program(
    prog: &libbpf_rs::ProgramMut<'_>,
    layout: Layout,
) -> anyhow::Result<NonNull<[u8]>> {
    let mut args = scx_userspace_arena_alloc_pages_args {
        sz: u32::try_from(layout.size())?,
        ret: std::ptr::null_mut(),
    };
    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut args as *mut _ as *mut u8,
                std::mem::size_of_val(&args),
            )
        }),
        ..Default::default()
    };
    prog.test_run(input)?;

    let base = NonNull::new(args.ret as *mut u8)
        .ok_or_else(|| anyhow::anyhow!("arena allocation failed"))?;

    Ok(NonNull::slice_from_raw_parts(base, args.sz as usize))
}

/// Helper to call a deallocate program with the correct arguments.
///
/// # Safety
///
/// Caller must ensure that the BPF program has the expected signature and behaviour. Effectively,
/// the program must have the same behaviour as `scx_userspace_arena_deallocate` in
/// "lib/sdt_alloc.bpf.c", and ideally be that program.
pub unsafe fn call_deallocate_program(
    prog: &libbpf_rs::ProgramMut<'_>,
    addr: NonNull<u8>,
    layout: Layout,
) {
    let mut args = scx_userspace_arena_free_pages_args {
        addr: addr.as_ptr() as *mut std::ffi::c_void,
        sz: u32::try_from(layout.size())
            .expect("memory allocated in the arena must fit in 32-bits"),
    };
    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut args as *mut _ as *mut u8,
                std::mem::size_of_val(&args),
            )
        }),
        ..Default::default()
    };
    prog.test_run(input).unwrap();
}
