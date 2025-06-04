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
	u64 id;

	/* Generic pointer, can be used for anything. */
	void __arena *data;
};

extern volatile topo_ptr topo_all;

int topo_init(scx_bitmap_t __arg_arena mask, u64 data_size, u64 id);
int topo_contains(topo_ptr topo, u32 cpu);

u64 topo_mask_level_internal(topo_ptr topo, enum topo_level level);
#define topo_mask_level(topo, level) ((scx_bitmap_t) topo_mask_level_internal((topo), (level)))

int topo_print(void);
int topo_print_by_level(void);

struct topo_iter {
	/* The current topology node. */
	topo_ptr topo;
	/*
	 * The index for every node in the path of the tree for , -1 denotes levels > the current one.
	 * E.g., [0, 1, 2, 1, 2] means:
	 * - index on level 0 (we only have one top-level node]
	 * - index 1 on level 1 (the top-level node's second child)
	 * - index 2 on level 2 (the NUMA node topology node's third child)
	 * and so on.
	 */
	int indices[TOPO_MAX_LEVEL];
};

/* Below is the machinery required for traversing the topology. It's better not to use it directly. */
__weak u64 topo_iter_level_internal(struct topo_iter *iter, enum topo_level lvl);
static inline int topo_iter_start(struct topo_iter *iter)
{
	int ind;

	if (!topo_all)
		return -EINVAL;

	iter->topo = topo_all;
	bpf_for(ind, 0, TOPO_MAX_LEVEL)
		iter->indices[ind] = -1;

	return 0;
}

#define TOPO_FOR_EACH_LEVEL(_iter, _topo, _lvl)		\
	topo_iter_start((_iter));			\
	while (((_topo) = ((topo_ptr)topo_iter_level_internal((_iter), _lvl))) && can_loop)

/* User-friendly macros that are good for usage within schedulers. */
#define TOPO_FOR_EACH_NODE(_iter, _topo) TOPO_FOR_EACH_LEVEL((_iter), (_topo), TOPO_NODE)
#define TOPO_FOR_EACH_LLC(_iter, _topo) TOPO_FOR_EACH_LEVEL((_iter), (_topo), TOPO_LLC)
#define TOPO_FOR_EACH_CORE(_iter, _topo) TOPO_FOR_EACH_LEVEL((_iter), (_topo), TOPO_CORE)
#define TOPO_FOR_EACH_CPU(_iter, _topo) TOPO_FOR_EACH_LEVEL((_iter), (_topo), TOPO_CPU)

extern u64 topo_nodes[TOPO_MAX_LEVEL][NR_CPUS];
