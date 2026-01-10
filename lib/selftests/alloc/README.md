ARENA ASAN FRAMEWORK
====================

This is a short document logging the development of ASAN for BPF arena memory.
The document will be removed once development is complete and the feature is
upstreamed to the kernel. 

Initial development for the feature was done in https://github.com/etsal/aasan/tree/fixup.
The initial code contribution here in the scx/ repo squashes the development history for
clarity. Later upstreaming will split the code into separate features.

STATUS
======

Fully functional, still in development. The three allocators are passing their selftests,
both for the allocators themselves and for ASAN support. Reporting is currently manual
because it makes testing easier, but can be trivially changed to produce backtraces. This
is due to BUG()-style reporting being implicitly included as a feature in the patchset.

The allocators currently require ASAN, but adding a no-op ASAN header is to avoid this is
trivial.

ASAN support requires an LLVM compiler built from HEAD and bpf-next.

DESIGN
======

We have two axes on which we need to work:

- MECHANISM: The main KASAN mechanism.
- ALLOCATOR: The consumer of the mechanism. It is co-designed with KASAN because
  it is the same consumer.
- TESTING: The tests are important because there are many, many edge cases that
  we need to cover, otherwise we may get false positives and false negatives.

We need analogues for all the code in mm/kasan:

- common.c: KASAN common API between the different backends
- generic.c: KASAN public API (most of the public functions are here)
- init.c: Bootstrapping code and fallback for large virtual memory mappings
- quarantine.c: Quarantining code for catching use-after-free
- report.c: Common reporting infrastructure, w/ parsing and printing
- report-generic.c: Code for filling in the reports printed out by
  report.c, including traversing the stack (since we are using the stack
  depot to store everything)
- shadow.c: Management of the shadow backing code, based on vmalloc

- [ We shouldn't need the code for dynamically creating shadow regions
here, since it is built into the arena.]


PLAN
====

We implement KASAN in passes, feature by feature. We want each
feature to be self-contained, i.e. not depend on later features.

For each feature we implement the basic KASAN mechanism, then we
integrate it with the allocator. We then write test cases that 
exercise the allocator. We define features in terms of KASAN's
public functions, exported or not, and implement the same or
equivalent functionality in AASAN.

Items tagged with - [M] for mechanism, - [A] for allocator features,
and - [T] for testing. - [C] is for compiler features, with only
two instances - one for heap memory and one for global objects.
We limit ourselves to heap memory for now. We deal with global
objects last, if at all.

Some observations:

- We do not need to bootstrap the shadow region of memory. AASAN
  interprets shadow map value 0 as "valid", and arena memory is
  zeroed out when allocated. We initialize AASAN with non-arena
  BPF code, so we do not have the bootstrapping problem that the
  KASAN solves with the dummy shadow memory region mapping in init.c.
- We ignore stack-related ASAN functions, since we cannot stack
  allocate arena memory.
- We do not require more than one aux stack because it is only useful
  when chaining contexts together. Chaining BPF contexts together is 
  only possible with exceptions, when we are already tearing down
  the execution context. Tracking memory access violations is then
  not that useful in that context.
- We do not dynamically allocate shadow regions. We have a single
  arena and allocate its "virtual address space" when we create it.
  The shadow memory region is built into it and never has to expand.
- We depend on arena page fault reporting for accesses to completely
  unallocated arena memory. This mirrors how touching nonexistent 
  memory pages in KASAN triggers a fault. This is why we don't need
  to eagerly poison the shadow map and can leave it full of 0s, which
  means memory from bpf_alloc_pages() is immediately valid. This is 
  also why we poison it when we insert it into the allocator.


Basic functionality
-------------------

- [A] Basic allocator prototype(s)
    - static allocator (no frees)
    - stack allocator (page granularity)
    - buddy allocator (generic power-of-2 objects)
- [A] Separating the allocator codebases
- [T] Selftest stubs for the allocators
- [A] Adding allocator destructors for testing
    - track static alloc allocated blocks to free on destroy()
    - free all stack segments in stack allocator on destroy()
    - destroy buddy allocator chunks on destroy()
- [T] Initial testing for allocator
    - static: Alloc/fill, alloc/fill, check, alloc/fill, check, etc.
- [M] kasan_poison
- [M] kasan_unpoison
- [M] ASAN intrinsics - [generic.c]
- [A] Add intrinsics to static allocator
    - Poisoning on chunk allocation
    - Unpoisoning on user allocation
- [T] Basic passing tests
	- Get memory into the allocator and ensure it's poisoned
	- Allocate memory to the user and ensure it's valid
		- Test with sizes 1 to 128
	- Allocate memory to the user and ensure memory right
	  before it and right after it is invalid
	  	- Test with sizes 1 to 128
	- Allocate with a set memory gap between allocations
		- Has to be a multiple of GRANULE

Removing Temporary Workarounds
------------------------------

- [M] Reason about offsets within the arena. Ensure ASAN works
even with user-specified arena offsets.
==================> WE ARE HERE
- [M] Make the explicit ASAN calls conditional
- [A] Rename allocators to remove scx prefix

- [M] Dynamically allocate shadow map memory. Possibly use a 
per-page statically allocated map to see whether we have allocated
a page for that part of the map.
    - One page of a residence map tracks 8 * 4K = 32K pages. We only need
    to track the pages of the shadow map, which is 1/8th of the 
    address space = 512MiB worth of pages = 128K pages. So a residence
    map with 4 pages is enough to tell us whether we need to allocate
    memory for the shadow map.

Alloc/Free Tracking
-------------------

- [M] kasan_set_track

- [M] kasan_save_alloc_info
- [M] kasan_save_free_info

- [M] kasan_get_alloc_meta	
- [M] kasan_get_free_meta

- [A] Store allocation and freeing info for allocations 

- [T] More testing

Reporting
---------

- [M] kasan_disable_current - [Critical sections/Nesting]
- [M] kasan_enable_current  - [Critical sections/Nesting]
- [T] Add tests with controlled invalid accesses
- [A] Add a prototype object allocator
- [M] kasan_get_alloc_size
- [T] Ensure kasan_get_alloc_size works with different sizes
- [M] kasan_non_canonical_hook
- [M] print_memory_metadata -> kasan_metadata_fetch_row
- [M] kasan_print_address_stack_frame
- [M] kasan_find_first_bad_addr
- [M] kasan_complete_mode_report_info
- [M] kasan_report
- [M] __asan_report_*() intrinsics
- [T] Add extra calls (noinline) and ensure the alloc info
is accurate

Redzoning
---------

- [M] __kasan_kmalloc_large
- [M] __kasan_krealloc
- [M] __kasan_kmalloc
- [M] __kasan_kfree
- [M] __kasan_kfree_large

Invalid Allocs/Frees
--------------------

- [M] kasan_byte_accessible
- [M] kasan_report_invalid_free
- [M] __kasan_kfree	- [EXPAND]
- [M] __kasan_kfree_large - [EXPAND]

- [A] Add double-free test to the allocator
- [T] Double frees test should return the specific error
- [T] Use-after-free (UAF) test should return that it is UAF 
instead of generic error

Quarantining
------------

- [M] kasan_quarantine_put
- [M] kasan_quarantine_reduce
- [M] kasan_quarantine_remove_cache
- [M] kasan_cache_shrink
- [M] kasan_cache_shutdown
- [T] Add testing with allocating/freeing in quick
succession (base allocator)
- [T] Same testing, but with the object allocator

Global objects
--------------

- [C] Compiler support/options to instrument in AddressSanitizer.cpp
- [M] __asan_register_globals
- [M] __asan_unregister_globals
- [T] Add redzone testing for globals of different sizes

Not Strictly Necessary
----------------------

- [M] __asan_memset
- [M] __asan_memmove
- [M] __asan_memcpy
- [M] __kasan_check_read
- [M] __kasan_check_write
- [M] kasan_check_range
- [M] __kasan_unpoison_range

