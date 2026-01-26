#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>

#else /* __BPF__ */
#define atomic_t u64
#endif /* __BPF__ */

#include <bpf_arena_spin_lock.h>
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
	struct rbnode node;	/* rbnode for being inserted into ATQs */
	scx_atq_t *atq;
	enum scx_task_throttle state;
};

typedef struct scx_task_common __arena scx_task_common;

#ifdef __BPF__
u64 scx_atq_create_internal(bool fifo, size_t capacity);
#define scx_atq_create(fifo) scx_atq_create_internal((fifo), SCX_ATQ_INF_CAPACITY)
#define scx_atq_create_size(fifo, capacity) scx_atq_create_internal((fifo), (capacity))
int scx_atq_insert(scx_atq_t *atq, scx_task_common *taskc);
int scx_atq_insert_vtime(scx_atq_t __arg_arena *atq, scx_task_common *taskc, u64 vtime);
int scx_atq_remove(scx_atq_t *atq, scx_task_common *taskc);
int scx_atq_insert_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc);
int scx_atq_insert_vtime_unlocked(scx_atq_t __arg_arena *atq, scx_task_common __arg_arena *taskc, u64 vtime);
int scx_atq_remove_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc);
int scx_atq_nr_queued(scx_atq_t *atq);
u64 scx_atq_pop(scx_atq_t *atq);
u64 scx_atq_peek(scx_atq_t *atq);
int scx_atq_cancel(scx_task_common *taskc);

static __always_inline
int scx_atq_lock(scx_atq_t __arg_arena *atq)
{
	return arena_spin_lock(&atq->lock);
}

static __always_inline
void scx_atq_unlock(scx_atq_t __arg_arena *atq)
{
	arena_spin_unlock(&atq->lock);
}
#endif /* __BPF__ */
