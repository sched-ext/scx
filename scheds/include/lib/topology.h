#pragma once

#include <lib/cpumask.h>

struct topology;
typedef struct topology __arena * topo_ptr;

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
	size_t nr_children;
	scx_bitmap_t mask;
	/*
	 * level and level_ids are hot in the fast path; keep them adjacent
	 * to ensure they land in the same cache line.
	 */
	enum topo_level level;
	s16 level_ids[TOPO_MAX_LEVEL];

	/* Generic pointer, can be used for anything. */
	void __arena *data;

	/*
	 * Variable-length children array. Allocated as part of the struct via
	 * scx_static_alloc(sizeof(struct topology) + max_children * sizeof(topo_ptr)).
	 * The per-level capacity is stored in topo_max_children[].
	 */
	topo_ptr children[];
};

extern volatile topo_ptr topo_all;

/*
 * Per-level maximum number of children. Must be set via arena_topology_init()
 * before any topo_init() calls. Each node at level L is allocated with
 * topo_max_children[L] child pointer slots.
 */
extern u32 topo_max_children[TOPO_MAX_LEVEL];

int topo_init(scx_bitmap_t __arg_arena mask, u64 data_size, s16 id);
int topo_contains(topo_ptr topo, u32 cpu);
int topo_cpu_to_llc_id(u32 cpu);

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
extern int nr_topo_nodes[TOPO_MAX_LEVEL];

#define TOPO_NR(type) nr_topo_nodes[TOPO_##type - 1]
