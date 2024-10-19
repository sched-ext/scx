#pragma once

#include "bpf_arena.h"

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

enum sdt_task_consts {
	SDT_TASK_LEVELS			= 3,	/* three levels of internal nodes */
	SDT_TASK_ENT_SIZE		= sizeof(void *),
	SDT_TASK_ENTS_PER_CHUNK_SHIFT	= 9,
	SDT_TASK_ENTS_PER_CHUNK		= 1 << SDT_TASK_ENTS_PER_CHUNK_SHIFT,
	SDT_TASK_CHUNK_BITMAP_U64S	= div_round_up(SDT_TASK_ENTS_PER_CHUNK, 64),
};

union sdt_task_id {
	__s64				val;
	struct {
		__s32			idx;	/* index in the radix tree */
		__s32			gen;	/* ++'d on recycle so that it forms unique'ish 64bit ID */
	};
};

struct sdt_task_chunk;

/*
 * Each index page is described by the following descriptor which carries the
 * bitmap. This way the actual index can host power-of-two numbers of entries
 * which makes indexing cheaper.
 */
struct sdt_task_desc {
	__u64				bitmap[SDT_TASK_CHUNK_BITMAP_U64S];
	__u64				nr_free;
	struct sdt_task_chunk __arena	*chunk;
};

/*
 * Leaf node containing per-task data.
 */
struct sdt_task_data {
	union sdt_task_id		tid;
	__u64				tptr;
	__u64				data[];
};

/*
 * Intermediate node pointing to another intermediate node or leaf node.
 */
struct sdt_task_chunk {
	union {
		struct sdt_task_desc __arena *descs[SDT_TASK_ENTS_PER_CHUNK];
		struct sdt_task_data __arena *data[SDT_TASK_ENTS_PER_CHUNK];
	};
};

/*
 * Simple memory allocation pool to allocate the descriptors, intermediate and
 * leaf nodes.
 */
struct sdt_task_pool_elem {
	struct sdt_task_pool_elem __arena *next;
};

struct sdt_task_pool {
	struct sdt_task_pool_elem __arena *first;
	__u64				elem_size;
};
