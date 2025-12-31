#pragma once

#ifdef __BPF__

#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

u64 scx_static_alloc_internal(size_t bytes, size_t alignment);
#define scx_static_alloc(bytes, alignment) ((void __arena *)scx_static_alloc_internal((bytes), (alignment)))
int scx_static_init(size_t max_alloc_pages);
int scx_static_destroy(void);
int scx_static_memlimit(u64 lim_memusage);

#endif /* __BPF__ */

struct scx_static {
	size_t max_contig_bytes;
	void __arena *memory;
	size_t off;
	size_t lim_memusage;
	size_t cur_memusage;
};

