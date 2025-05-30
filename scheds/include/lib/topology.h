#pragma once

struct topology;
typedef struct topology __arena * topo_ptr;

#define TOPO_MAX_CHILDREN (16)

enum topo_level {
	TOPO_TOP	= 0,
	TOPO_NODE	= 1,
	TOPO_LLC	= 2,
	TOPO_CORE	= 3,
	TOPO_CPU	= 4,
	TOPO_MAX_LEVEL	= 5,
};

struct topology {
	topo_ptr parent;
	topo_ptr children[TOPO_MAX_CHILDREN];
	size_t nr_children;
	scx_bitmap_t mask;
	enum topo_level level;

	/* Generic pointer, can be used for anything. */
	void *data;
};

topo_ptr topo_all __weak;

int topo_init(scx_bitmap_t __arg_arena mask);
int topo_contains(topo_ptr topo, u32 cpu);

u64 topo_mask_level_internal(topo_ptr topo, enum topo_level level);
#define topo_mask_level(topo, level) ((scx_bitmap_t) topo_mask_level_internal((topo), (level))

int topo_print(void);
