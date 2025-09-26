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

struct scx_atq {
	rbtree_t *tree;
	arena_spinlock_t lock;
	u64 capacity;
	u64 size;
	u64 seq;
	u64 fifo;
};


typedef struct scx_atq __arena scx_atq_t;

#ifdef __BPF__
u64 scx_atq_create_internal(bool fifo, size_t capacity);
#define scx_atq_create(fifo) scx_atq_create_internal((fifo), SCX_ATQ_INF_CAPACITY)
#define scx_atq_create_size(fifo, capacity) scx_atq_create_internal((fifo), (capacity))
int scx_atq_insert(scx_atq_t *atq_ptr, u64 taskc_ptr);
int scx_atq_insert_vtime(scx_atq_t *atq, u64 taskc_ptr, u64 vtime);
int scx_atq_nr_queued(scx_atq_t *atq);
u64 scx_atq_pop(scx_atq_t *atq);
u64 scx_atq_peek(scx_atq_t *atq);
#endif /* __BPF__ */
