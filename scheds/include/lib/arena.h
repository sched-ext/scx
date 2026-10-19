#pragma once

#include <lib/topology.h>

#define NR_CPU_IDS_UNINIT (~(u32)0)

/* For userspace programs, __arena is a no-op. */
#if !defined(__arena) &&  !defined(__BPF__)
#define __arena
#endif

/* arena_init() steps, reported in arena_init_args.failed_step */
enum arena_init_step {
	ARENA_INIT_DONE,
	ARENA_INIT_NULL_GUARD,
	ARENA_INIT_STATIC,
	ARENA_INIT_NR_CPU_IDS,
	ARENA_INIT_BITMAP,
	ARENA_INIT_CMASK,
	ARENA_INIT_TASK,
	ARENA_INIT_RB,
	ARENA_INIT_ATQ,
};

struct arena_init_args {
	u64 static_pages;
	u64 task_ctx_size;
	/* task ctx element alignment, 0 for word alignment */
	u64 task_ctx_align;
	/* out: the step that failed, ARENA_INIT_DONE on success */
	enum arena_init_step failed_step;
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
