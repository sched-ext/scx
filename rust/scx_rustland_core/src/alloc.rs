// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// Buddy allocator code imported from https://github.com/jjyr/buddy-alloc
// and distributed under the terms of the MIT license.
//
// MIT License:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use core::cell::RefCell;
use std::alloc::{GlobalAlloc, Layout};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::num::ParseIntError;

/// Buddy allocator
///
/// The following code is strongly based on https://github.com/jjyr/buddy-alloc and imported
/// directly here to make packaging easier.

const OOM_MSG: &str = "requires more memory space to initialize BuddyAlloc";
const LEAF_ALIGN_ERROR_MSG: &str = "leaf size must be align to 16 bytes";
/// required align to 16 bytes, since Node takes 16 bytes on 64-bits machine.
pub const MIN_LEAF_SIZE_ALIGN: usize = 16;

const fn block_size_2base(k: usize, leaf2base: usize) -> usize {
    (1 << k) << leaf2base
}

const fn nblock(k: usize, entries_size: usize) -> usize {
    1 << (entries_size - k - 1)
}

const fn roundup(n: usize, sz2base: usize) -> usize {
    (((n - 1) >> sz2base) + 1) << sz2base
}

fn log2(mut n: usize) -> usize {
    let mut k = 0;
    while n > 1 {
        k += 1;
        n >>= 1;
    }
    k
}

fn bit_isset(bit_array: *const u8, i: usize) -> bool {
    unsafe {
        let b = bit_array.add(i >> 3);
        let m = 1 << (i % 8);
        *b & m == m
    }
}

fn bit_set(bit_array: *mut u8, i: usize) {
    unsafe {
        let b = bit_array.add(i >> 3);
        let m = 1 << (i % 8);
        *b |= m;
    }
}

fn bit_clear(bit_array: *mut u8, i: usize) {
    debug_assert!(bit_isset(bit_array, i));
    unsafe {
        let b = bit_array.add(i >> 3);
        let m = 1 << (i % 8);
        *b &= !m;
    }
}

// find a min k that great than n bytes
pub fn first_up_k(n: usize, leaf_size: usize) -> usize {
    let mut k = 0;
    let mut size = leaf_size;
    while size < n {
        k += 1;
        size <<= 1;
    }
    k
}

struct Node {
    next: *mut Node,
    prev: *mut Node,
}

impl Node {
    fn init(list: *mut Node) {
        unsafe {
            (*list).next = list;
            (*list).prev = list;
        }
    }

    fn remove(list: *mut Node) {
        unsafe {
            (*(*list).prev).next = (*list).next;
            (*(*list).next).prev = (*list).prev;
        }
    }

    fn pop(list: *mut Node) -> *mut Node {
        debug_assert!(!Self::is_empty(list));
        let n_list: *mut Node = unsafe { (*list).next };
        Self::remove(n_list);
        n_list
    }

    fn push(list: *mut Node, p: *mut u8) {
        let p = p.cast::<Node>();
        unsafe {
            let n_list: Node = Node {
                prev: list,
                next: (*list).next,
            };
            // pointer aligned to 16 bytes(MIN_LEAF_SIZE_ALIGN), so it's safe to use write
            p.write(n_list);
            (*(*list).next).prev = p;
            (*list).next = p;
        }
    }

    fn is_empty(list: *const Node) -> bool {
        unsafe { (*list).next as *const Node == list }
    }
}

struct Entry {
    free: *mut Node,
    /// Bit array to keep tracking alloc
    alloc: *mut u8,
    /// Bit array to keep tracking split
    split: *mut u8,
}

impl Default for Entry {
    fn default() -> Self {
        Entry {
            free: core::ptr::null_mut(),
            alloc: core::ptr::null_mut(),
            split: core::ptr::null_mut(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct BuddyAllocParam {
    /// Base addr: the start address
    base_addr: *const u8,
    /// Len: available bytes from the start address
    len: usize,
    /// Leaf size: the min size to allocate
    leaf_size: usize,
    /// Zero filled: in many cases, provided address might already be zero filled,
    /// in which case we can reduce re-filling zeros to the data again.
    zero_filled: bool,
}

impl BuddyAllocParam {
    /// Base addr: the start address
    /// Len: available bytes from the start address
    /// Leaf size: the min size to allocate
    pub const fn new(base_addr: *const u8, len: usize, leaf_size: usize) -> Self {
        BuddyAllocParam {
            base_addr,
            len,
            leaf_size,
            zero_filled: false,
        }
    }
}

pub struct BuddyAlloc {
    /// memory start addr
    base_addr: usize,
    /// memory end addr
    end_addr: usize,
    /// unavailable memories at end_addr
    unavailable: usize,
    entries: *mut Entry,
    entries_size: usize,
    /// min size of a block, represent in 1 << leaf2base
    leaf2base: usize,
}

impl BuddyAlloc {
    /// # Safety
    ///
    /// The `base_addr..(base_addr + len)` must be allocated before using,
    /// and must guarantee no others write to the memory range, to avoid undefined behaviors.
    /// The new function panic if memory space not enough for initialize BuddyAlloc.
    pub unsafe fn new(param: BuddyAllocParam) -> Self {
        let BuddyAllocParam {
            base_addr,
            len,
            leaf_size,
            zero_filled,
        } = param;
        let mut base_addr = base_addr as usize;
        let end_addr = base_addr + len;
        assert!(
            leaf_size % MIN_LEAF_SIZE_ALIGN == 0 && leaf_size != 0,
            "{}",
            LEAF_ALIGN_ERROR_MSG
        );
        let leaf2base = log2(leaf_size);
        base_addr = roundup(base_addr, leaf2base);
        // we use (k + 1)-th entry's split flag to test existence of k-th entry's blocks;
        // to accoding this convention, we make a dummy (entries_size - 1)-th entry.
        // so we plus 2 on entries_size.
        let entries_size = log2((end_addr - base_addr) >> leaf2base) + 2;

        // alloc buddy allocator memory
        let used_bytes = core::mem::size_of::<Entry>() * entries_size;
        debug_assert!(end_addr >= base_addr + used_bytes, "{}", OOM_MSG);
        let entries = base_addr as *mut Entry;
        base_addr += used_bytes;

        let buddy_list_size = core::mem::size_of::<Node>();
        // init entries free
        for k in 0..entries_size {
            // use one bit for per memory block
            debug_assert!(end_addr >= base_addr + buddy_list_size, "{}", OOM_MSG);
            let entry = entries.add(k).as_mut().expect("entry");
            entry.free = base_addr as *mut Node;
            if !zero_filled {
                core::ptr::write_bytes(entry.free, 0, buddy_list_size);
            }
            Node::init(entry.free);
            base_addr += buddy_list_size;
        }

        // init alloc
        for k in 0..entries_size {
            // use one bit for per memory block
            // use shift instead `/`, 8 == 1 << 3
            let used_bytes = roundup(nblock(k, entries_size), 3) >> 3;
            debug_assert!(end_addr >= base_addr + used_bytes, "{}", OOM_MSG);
            let entry = entries.add(k).as_mut().expect("entry");
            entry.alloc = base_addr as *mut u8;
            // mark all blocks as allocated
            if !zero_filled {
                core::ptr::write_bytes(entry.alloc, 0, used_bytes);
            }
            base_addr += used_bytes;
        }

        // init split
        for k in 1..entries_size {
            // use one bit for per memory block
            // use shift instead `/`, 8 == 1 << 3
            let used_bytes = roundup(nblock(k, entries_size), 3) >> 3;
            debug_assert!(end_addr >= base_addr + used_bytes, "{}", OOM_MSG);
            let entry = entries.add(k).as_mut().expect("entry");
            entry.split = base_addr as *mut u8;
            if !zero_filled {
                core::ptr::write_bytes(entry.split, 0, used_bytes);
            }
            base_addr += used_bytes;
        }

        // align base_addr to leaf size
        base_addr = roundup(base_addr, leaf2base);
        assert!(end_addr >= base_addr, "{}", OOM_MSG);
        debug_assert_eq!(
            (base_addr >> leaf2base) << leaf2base,
            base_addr,
            "misalignment"
        );

        let mut allocator = BuddyAlloc {
            base_addr,
            end_addr,
            entries,
            entries_size,
            leaf2base,
            unavailable: 0,
        };
        allocator.init_free_list();
        allocator
    }

    fn init_free_list(&mut self) {
        let mut base_addr = self.base_addr;
        let end_addr = self.end_addr;
        let entries_size = self.entries_size;

        // try alloc blocks
        for k in (0..(entries_size - 1)).rev() {
            let block_size = block_size_2base(k, self.leaf2base);
            let entry = self.entry(k);
            let parent_entry = self.entry(k + 1);

            // alloc free blocks
            while base_addr + block_size <= end_addr {
                debug_assert!(!bit_isset(
                    entry.alloc,
                    self.block_index(k, base_addr as *const u8)
                ));
                Node::push(entry.free, base_addr as *mut u8);
                // mark parent's split and alloc
                let block_index = self.block_index(k, base_addr as *const u8);
                if block_index & 1 == 0 {
                    let parent_index = self.block_index(k + 1, base_addr as *const u8);
                    bit_set(parent_entry.alloc, parent_index);
                    bit_set(parent_entry.split, parent_index);
                }
                base_addr += block_size;
            }

            // mark unavailable blocks as allocated
            let n = nblock(k, entries_size);
            let unavailable_block_index = self.block_index(k, base_addr as *const u8);
            debug_assert!(unavailable_block_index < n);
            bit_set(entry.alloc, unavailable_block_index);
        }

        self.unavailable = end_addr - base_addr;
    }

    pub fn malloc(&mut self, nbytes: usize) -> *mut u8 {
        let fk = first_up_k(nbytes, 1 << self.leaf2base);
        let mut k = match (fk..self.entries_size).find(|&k| !Node::is_empty(self.entry(k).free)) {
            Some(k) => k,
            None => return core::ptr::null_mut(),
        };
        let p: *mut u8 = Node::pop(self.entry(k).free) as *mut u8;
        bit_set(self.entry(k).alloc, self.block_index(k, p));
        while k > fk {
            let q: *mut u8 = (p as usize + block_size_2base(k - 1, self.leaf2base)) as *mut u8;
            bit_set(self.entry(k).split, self.block_index(k, p));
            let parent_entry = self.entry(k - 1);
            bit_set(parent_entry.alloc, self.block_index(k - 1, p));
            debug_assert!(!bit_isset(parent_entry.alloc, self.block_index(k - 1, q)));
            Node::push(parent_entry.free, q);
            k -= 1;
        }
        debug_assert_eq!(
            ((p as usize) >> self.leaf2base) << self.leaf2base,
            p as usize,
            "misalignment"
        );
        p
    }

    pub fn free(&mut self, mut p: *mut u8) {
        let mut k = self.find_k_for_p(p);
        while k < (self.entries_size - 1) {
            let block_index = self.block_index(k, p);
            let entry = self.entry(k);
            bit_clear(entry.alloc, block_index);
            let is_head = block_index & 1 == 0;
            let buddy = if is_head {
                block_index + 1
            } else {
                block_index - 1
            };
            if bit_isset(entry.alloc, buddy) {
                break;
            }
            // merge buddy since its free
            // 1. clear split of k + 1
            // 2. set p to the address of merged block
            // 3. repeat for k = k + 1 until reach MAX_K
            // 4. push p back to k entry free list
            let q = self.block_addr(k, buddy);
            Node::remove(q as *mut Node);
            if !is_head {
                p = q as *mut u8;
            }
            bit_clear(self.entry(k + 1).split, self.block_index(k + 1, p));
            k += 1;
        }
        debug_assert!(!bit_isset(self.entry(k).alloc, self.block_index(k, p)));
        Node::push(self.entry(k).free, p);
    }

    fn entry(&self, i: usize) -> &Entry {
        debug_assert!(i < self.entries_size, "index out of range");
        unsafe { self.entries.add(i).as_ref().expect("entry") }
    }

    /// find k for p
    fn find_k_for_p(&self, p: *const u8) -> usize {
        for k in 0..(self.entries_size - 1) {
            if bit_isset(self.entry(k + 1).split, self.block_index(k + 1, p)) {
                debug_assert!(bit_isset(self.entry(k).alloc, self.block_index(k, p)));
                return k;
            }
        }
        0
    }

    /// block index of p under k
    fn block_index(&self, k: usize, p: *const u8) -> usize {
        if (p as usize) < self.base_addr {
            // TODO handle this outside
            panic!("out of memory");
        }
        let n = p as usize - self.base_addr;
        // equal to: n / block_size_2base(k, self.leaf2base);
        let index = (n >> k) >> self.leaf2base;
        debug_assert!(index < nblock(k, self.entries_size));
        index
    }

    /// block addr of index under k
    fn block_addr(&self, k: usize, i: usize) -> usize {
        // equal to: i * block_size_2base(k, self.leaf2base);
        let n = (i << k) << self.leaf2base;
        self.base_addr + n
    }
}

// Main allocator class.
pub struct UserAllocator {
    buddy_alloc_param: BuddyAllocParam,
    inner_buddy_alloc: RefCell<Option<BuddyAlloc>>,
}

impl UserAllocator {
    pub const fn new(buddy_alloc_param: BuddyAllocParam) -> Self {
        UserAllocator {
            inner_buddy_alloc: RefCell::new(None),
            buddy_alloc_param,
        }
    }

    unsafe fn fetch_buddy_alloc<R, F: FnOnce(&mut BuddyAlloc) -> R>(&self, f: F) -> R {
        let mut inner = self.inner_buddy_alloc.borrow_mut();
        if inner.is_none() {
            inner.replace(BuddyAlloc::new(self.buddy_alloc_param));
        }
        f(inner.as_mut().expect("nerver"))
    }

    pub fn lock_memory(&self) {
        unsafe {
            match VM.save() {
                Ok(_) => {}
                Err(res) => eprintln!("WARNING: {}\n", res),
            };

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
            match VM.restore() {
                Ok(_) => {}
                Err(res) => eprintln!("WARNING: {}\n", res),
            }
        };
    }
}

// Override global allocator methods.
unsafe impl GlobalAlloc for UserAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let bytes = layout.size();
        self.fetch_buddy_alloc(|alloc| alloc.malloc(bytes))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        self.fetch_buddy_alloc(|alloc| alloc.free(ptr));
    }
}

unsafe impl Sync for UserAllocator {}

// Buddy allocator parameters.
const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64M
const LEAF_SIZE: usize = 64;

#[repr(align(4096))]
struct AlignedHeap<const N: usize>([u8; N]);

// Statically pre-allocated memory arena.
static mut HEAP: AlignedHeap<HEAP_SIZE> = AlignedHeap([0u8; HEAP_SIZE]);

// Override default memory allocator.
//
// To prevent potential deadlock conditions under heavy loads, any scheduler that delegates
// scheduling decisions to user-space should avoid triggering page faults.
//
// To address this issue, replace the global allocator with a custom one (UserAllocator),
// designed to operate on a pre-allocated buffer. This, coupled with the memory locking achieved
// through mlockall(), prevents page faults from occurring during the execution of the user-space
// scheduler.
#[cfg_attr(not(test), global_allocator)]
pub static ALLOCATOR: UserAllocator =
    unsafe { UserAllocator::new(BuddyAllocParam::new(HEAP.0.as_ptr(), HEAP_SIZE, LEAF_SIZE)) };

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
    fn read_procfs(&self, file_path: &str) -> Result<i32, String> {
        // Attempt to open the file
        let file = match File::open(file_path) {
            Ok(f) => f,
            Err(err) => return Err(format!("Failed to open {}: {}", file_path, err)),
        };

        let reader = BufReader::new(file);

        if let Some(Ok(line)) = reader.lines().next() {
            let value: Result<i32, ParseIntError> = line.trim().parse();
            match value {
                Ok(v) => Ok(v),
                Err(err) => Err(format!("Failed to parse {}: {}", file_path, err)),
            }
        } else {
            Err(format!("File is empty: {}", file_path))
        }
    }

    // Write an i32 to a file in procfs.
    fn write_procfs(&self, file_path: &str, value: i32) -> Result<(), String> {
        // Attempt to create or open the file
        let mut file = match File::create(file_path) {
            Ok(f) => f,
            Err(err) => return Err(format!("Failed to open {}: {}", file_path, err)),
        };

        // Attempt to write the value to the file
        if let Err(err) = write!(file, "{}", value) {
            return Err(format!("Failed to write to {}: {}", file_path, err));
        }

        Ok(()) // Return Ok if writing was successful
    }

    // Save all the sysctl VM settings in the internal state.
    fn save(&self) -> Result<(), String> {
        let compact_unevictable_allowed = "/proc/sys/vm/compact_unevictable_allowed";
        let value = self.read_procfs(compact_unevictable_allowed)?;
        unsafe {
            VM.compact_unevictable_allowed = value;
        };
        self.write_procfs(compact_unevictable_allowed, 0)?;

        Ok(())
    }

    // Restore all the previous sysctl vm settings.
    fn restore(&self) -> Result<(), String> {
        let compact_unevictable_allowed = "/proc/sys/vm/compact_unevictable_allowed";
        let value = unsafe { VM.compact_unevictable_allowed };
        self.write_procfs(compact_unevictable_allowed, value)?;

        Ok(())
    }
}

// Special sysctl VM settings.
static mut VM: VmSettings = VmSettings {
    compact_unevictable_allowed: 0,
};
