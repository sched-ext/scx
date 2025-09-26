#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>
#endif /* __BPF__ */

#include <lib/rbtree.h>

enum scx_atq_consts {
	SCX_ATQ_INF_CAPACITY  = ((u64)-1),
	SCX_ATQ_FIFO = ((u64)-1)
};

enum scx_task_throttle {
	SCX_TSK_CANRUN = 0,
	SCX_TSK_THROTTLED
};

struct scx_atq {
	rbtree_t *tree;
	arena_spinlock_t lock;
	u64 capacity;
	u64 size;
	u64 seq;
	u64 fifo;
};


typedef struct scx_atq __arena scx_atq_t;

struct scx_task_common {
	struct rbnode atq;	/* rbnode for being inserted into ATQs */
	enum scx_task_throttle state;
};

typedef struct scx_task_common __arena scx_task_common;

#ifdef __BPF__
u64 scx_atq_create_internal(bool fifo, size_t capacity);
#define scx_atq_create(fifo) scx_atq_create_internal((fifo), SCX_ATQ_INF_CAPACITY)
#define scx_atq_create_size(fifo, capacity) scx_atq_create_internal((fifo), (capacity))
int scx_atq_insert(scx_atq_t *atq, rbnode_t __arg_arena *node, u64 task_ptr);
int scx_atq_insert_vtime(scx_atq_t __arg_arena *atq, rbnode_t __arg_arena *node, u64 task_ptr, u64 vtime);
int scx_atq_nr_queued(scx_atq_t *atq);
u64 scx_atq_pop(scx_atq_t *atq);
u64 scx_atq_peek(scx_atq_t *atq);
#endif /* __BPF__ */
