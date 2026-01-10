#pragma once

#define NR_CPU_IDS_UNINIT (~(u32)0)

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

int arena_topology_print(void);
