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

struct topo_iter {
	topo_ptr topo;
	size_t i;
};

#define TOPO_ITER_INIT(_iter, _topo)	\
	do { (_iter).topo = (_topo); (_iter).i = 0; } while (0)

#define TOPO_ITER_DONE(_iter) ((_iter).i == (_iter).topo->nr_children)

#define TOPO_ITER_NEXT(_iter) \
	(TOPO_ITER_DONE(_iter) ? NULL : (_iter).topo->children[(_iter).i++])

#define TOPO_FOR_EACH_CHILD(_iter, _topo, _child)		\
	TOPO_ITER_INIT(_iter, _topo);				\
	for ((_child) = NULL; (_child = TOPO_ITER_NEXT(_iter)) && can_loop;)

int topo_init(scx_bitmap_t __arg_arena mask);
int topo_contains(topo_ptr topo, u32 cpu);

u64 topo_mask_level_internal(topo_ptr topo, enum topo_level level);
#define topo_mask_level(topo, level) ((scx_bitmap_t) topo_mask_level_internal((topo), (level))

int topo_print(void);
