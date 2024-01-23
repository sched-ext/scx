// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::UnsafeCell;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
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

// State of special sysctl VM settings.
//
// This is used to save the previous state of some procfs settings that must be changed by the
// user-space scheduler.
struct VmSettings {
    // We cannot allow page faults in the user-space scheduler, otherwise we may hit deadlock
    // conditions: a kthread may need to run to resolve the page fault, but the user-space
    // scheduler is waiting on the page fault to be resolved => deadlock.
    //
    // To prevent this from happening automatically enforce vm.compact_unevictable_allowed=0 when
    // the scheduler is running, to disable compaction of unevictable memory pages and make sure
    // that the scheduler never faults.
    //
    // The original value will be restored when the user-space scheduler exits.
    compact_unevictable_allowed: i32,
}

impl VmSettings {
    // Return the content of a procfs file as i32.
    fn read_procfs(&self, file_path: &str) -> i32 {
        let file = File::open(file_path).expect(&format!("Failed to open {}", file_path));
        let reader = BufReader::new(file);

        if let Some(Ok(line)) = reader.lines().next() {
            let value: i32 = match line.trim().parse() {
                Ok(v) => v,
                Err(_) => panic!("Failed to parse {}", file_path),
            };

            value
        } else {
            panic!("empty {}", file_path);
        }
    }

    // Write an i32 to a file in procfs.
    fn write_procfs(&self, file_path: &str, value: i32) {
        let mut file = File::create(file_path).expect(&format!("Failed to open {}", file_path));
        file.write_all(value.to_string().as_bytes())
            .expect(&format!("Failed to write to {}", file_path));
    }

    // Save all the sysctl VM settings in the internal state.
    fn save(&self) {
        let compact_unevictable_allowed = "/proc/sys/vm/compact_unevictable_allowed";
        let value = self.read_procfs(compact_unevictable_allowed);
        unsafe {
            VM.compact_unevictable_allowed = value;
        };
        self.write_procfs(compact_unevictable_allowed, 0);
    }

    // Restore all the previous sysctl vm settings.
    fn restore(&self) {
        let compact_unevictable_allowed = "/proc/sys/vm/compact_unevictable_allowed";
        let value = unsafe { VM.compact_unevictable_allowed };
        self.write_procfs(compact_unevictable_allowed, value);
    }
}

// Special sysctl VM settings.
static mut VM: VmSettings = VmSettings {
    compact_unevictable_allowed: 0,
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
            VM.save();

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

    pub fn unlock_memory(&self) {
        unsafe {
            VM.restore();
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
            if is_allocated || (contiguous_blocks == 0 && !self.is_aligned(block, align)) {
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
