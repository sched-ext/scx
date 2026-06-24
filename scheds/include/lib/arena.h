#pragma once

#include <lib/topology.h>

#define NR_CPU_IDS_UNINIT (~(u32)0)

/* For userspace programs, __arena is a no-op. */
#if !defined(__arena) &&  !defined(__BPF__)
#define __arena
#endif

struct arena_init_args {
	u64 static_pages;
	u64 task_ctx_size;
};

int arena_init(struct arena_init_args *args);

struct arena_alloc_mask_args {
	u64 bitmap;
};

int arena_alloc_mask(struct arena_alloc_mask_args *args);

struct arena_topology_node_init_args {
	u64 bitmap;
	u64 data_size;
	u64 id;
};

int arena_topology_node_init(struct arena_topology_node_init_args *args);

/*
 * Must be called once before any arena_topology_node_init() calls to set the
 * per-level maximum number of children. The array is indexed by topo_level.
 */
struct arena_topology_init_args {
	u32 max_children[TOPO_MAX_LEVEL];
};

int arena_topology_init(struct arena_topology_init_args *args);

int arena_topology_print(void);
