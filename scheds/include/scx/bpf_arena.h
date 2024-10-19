#pragma once

/*#ifndef __BPF_FEATURE_ADDR_SPACE_CAST
static inline void ___bpf_arena_addr_space_cast_sanity_check___(void)
{
	_Static_assert(false, "__BPF_FEATURE_ADDR_SPACE_CAST missing");
}
#endif*/

#ifndef NUMA_NO_NODE
#define	NUMA_NO_NODE	(-1)
#endif

#define arena_container_of(ptr, type, member)			\
	({							\
		void __arena *__mptr = (void __arena *)(ptr);	\
		((type *)(__mptr - offsetof(type, member)));	\
	})

#ifdef __BPF__ /* when compiled as bpf program */

#ifndef PAGE_SIZE
#define PAGE_SIZE __PAGE_SIZE
#endif

#define __arena __attribute__((address_space(1)))
#define __arena_global __attribute__((address_space(1)))

void __arena* bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
				    int node_id, __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr, __u32 page_cnt) __ksym __weak;

#else /* when compiled as user space code */

#define __arena
#define __arena_global

#endif
