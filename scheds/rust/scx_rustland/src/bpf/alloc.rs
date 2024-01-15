// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::UnsafeCell;
use std::sync::{Mutex, MutexGuard};

/// scx_rustland: memory allocator.
///
/// RustLandAllocator is a very simple block-based memory allocator that relies on a pre-allocated
/// buffer and an array to manage the status of allocated and free blocks.
///
/// The purpose of this allocator is to prevent the user-space scheduler from triggering page
/// faults, which could lead to potential deadlocks under heavy system load conditions.
///
/// Despite its simplicity, this allocator exhibits reasonable speed and efficiency in meeting
/// memory requests from the user-space scheduler, particularly when dealing with small, uniformly
/// sized allocations.

// Pre-allocate an area of 64MB, with a block size of 64 bytes, that should be reasonable enough to
// handle small uniform allocations performed by the user-space scheduler without introducing too
// much fragmentation and overhead.
const ARENA_SIZE: usize = 64 * 1024 * 1024;
const BLOCK_SIZE: usize = 64;
const NUM_BLOCKS: usize = ARENA_SIZE / BLOCK_SIZE;

#[repr(C, align(4096))]
struct RustLandMemory {
    // Pre-allocated buffer.
    arena: UnsafeCell<[u8; ARENA_SIZE]>,
    // Allocation map.
    //
    // Each slot represents the status of a memory block (true = allocated, false = free).
    allocation_map: Mutex<[bool; NUM_BLOCKS]>,
}

unsafe impl Sync for RustLandMemory {}

// Memory pool for the allocator.
static MEMORY: RustLandMemory = RustLandMemory {
    arena: UnsafeCell::new([0; ARENA_SIZE]),
    allocation_map: Mutex::new([false; NUM_BLOCKS]),
};

// Main allocator class.
pub struct RustLandAllocator;

impl RustLandAllocator {
    unsafe fn block_to_addr(&self, block: usize) -> *mut u8 {
        MEMORY.arena.get().cast::<u8>().add(block * BLOCK_SIZE)
    }

    unsafe fn is_aligned(&self, block: usize, align_size: usize) -> bool {
        self.block_to_addr(block) as usize & (align_size - 1) == 0
    }

    pub fn lock_memory(&self) {
        unsafe {
            // Call setrlimit to set the locked-in-memory limit to unlimited.
            let new_rlimit = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            let res = libc::setrlimit(libc::RLIMIT_MEMLOCK, &new_rlimit);
            if res != 0 {
                panic!("setrlimit failed with error code: {}", res);
            }

            // Lock all memory to prevent being paged out.
            let res = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
            if res != 0 {
                panic!("mlockall failed with error code: {}", res);
            }
        };
    }
}

// Override global allocator methods.
unsafe impl GlobalAlloc for RustLandAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();

        // Find the first sequence of free blocks that can accommodate the requested size.
        let mut map_guard: MutexGuard<[bool; NUM_BLOCKS]> = MEMORY.allocation_map.lock().unwrap();
        let mut contiguous_blocks = 0;
        let mut start_block = None;

        for (block, &is_allocated) in map_guard.iter().enumerate() {
            // Reset consecutive blocks count if an allocated block is encountered or if the
            // first block is not aligned to the requested alignment.
            if is_allocated
                || (contiguous_blocks == 0 && !self.is_aligned(block, align))
            {
                contiguous_blocks = 0;
            } else {
                contiguous_blocks += 1;
                if contiguous_blocks * BLOCK_SIZE >= size {
                    // Found a sequence of free blocks that can accommodate the size.
                    start_block = Some(block + 1 - contiguous_blocks);
                    break;
                }
            }
        }

        match start_block {
            Some(start) => {
                // Mark the corresponding blocks as allocated.
                for i in start..start + contiguous_blocks {
                    map_guard[i] = true;
                }
                // Return a pointer to the aligned allocated block.
                self.block_to_addr(start)
            }
            None => {
                // No contiguous block sequence found, just panic.
                //
                // NOTE: we want to panic here so that we can better detect when we run out of
                // memory, instead of returning a null_ptr that could potentially hide the real
                // problem.
                panic!("Out of memory");
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size();

        // Calculate the block index from the released pointer.
        let offset = ptr as usize - MEMORY.arena.get() as usize;
        let start_block = offset / BLOCK_SIZE;
        let end_block = (offset + size - 1) / BLOCK_SIZE + 1;

        // Update the allocation map for all blocks in the released range.
        let mut map_guard: MutexGuard<[bool; NUM_BLOCKS]> = MEMORY.allocation_map.lock().unwrap();
        for index in start_block..end_block {
            map_guard[index] = false;
        }
    }
}
