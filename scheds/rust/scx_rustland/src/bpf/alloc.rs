// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::alloc::{GlobalAlloc, Layout};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use buddy_alloc::{BuddyAllocParam, FastAllocParam, NonThreadsafeAlloc};

// Buddy allocator parameters.
const FAST_HEAP_SIZE: usize = 1024 * 1024; // 1M
const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64M
const LEAF_SIZE: usize = 64;

#[repr(align(4096))]
pub struct AlignedHeap<const N: usize>([u8; N]);

// Statically pre-allocated memory arena.
static mut FAST_HEAP: AlignedHeap<FAST_HEAP_SIZE> = AlignedHeap([0u8; FAST_HEAP_SIZE]);
static mut HEAP: AlignedHeap<HEAP_SIZE> = AlignedHeap([0u8; HEAP_SIZE]);

// Override default memory allocator.
//
// To prevent potential deadlock conditions under heavy loads, any scheduler that delegates
// scheduling decisions to user-space should avoid triggering page faults.
//
// To address this issue, replace the global allocator with a custom one (RustLandAllocator),
// designed to operate on a pre-allocated buffer. This, coupled with the memory locking achieved
// through mlockall(), prevents page faults from occurring during the execution of the user-space
// scheduler.
#[cfg_attr(not(test), global_allocator)]
pub static ALLOCATOR: RustLandAllocator = unsafe {
    let fast_param = FastAllocParam::new(FAST_HEAP.0.as_ptr(), FAST_HEAP_SIZE);
    let buddy_param = BuddyAllocParam::new(HEAP.0.as_ptr(), HEAP_SIZE, LEAF_SIZE);
    RustLandAllocator {
        arena: NonThreadsafeAlloc::new(fast_param, buddy_param),
    }
};

// Main allocator class.
pub struct RustLandAllocator {
    pub arena: NonThreadsafeAlloc,
}

impl RustLandAllocator {
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
        self.arena.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.arena.dealloc(ptr, layout);
    }
}

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
