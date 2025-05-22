#pragma once

struct arena_init_args {
	u64 static_pages;
	u64 task_ctx_size;
};

int arena_init(struct arena_init_args *args);
int arena_alloc_mask(void);

struct arena_topology_node_init_args {
	u64 setup_ptr;
};

int arena_topology_node_init();
int arena_topology_print(void);
