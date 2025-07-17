#pragma once

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#include <lib/minheap.h>

#define SCX_ATQ_MAX_CAPACITY (65536)

struct scx_atq {
	scx_minheap_t *heap;
	arena_spinlock_t lock;
	u64 seq;
	u64 fifo;
}

typedef __arena scx_atq, scx_atq_t;

u64 scx_atq_create_internal(bool fifo, size_t capacity);
#define scx_atq_create(fifo) scx_atq_create_internal((fifo), SCX_ATQ_MAX_CAPACITY)
#define scx_atq_create_size(fifo, capacity) scx_atq_create_internal((fifo), (capacity))
int scx_atq_insert(scx_atq *atq_ptr, u64 taskc_ptr);
int scx_atq_insert_vtime(scx_atq_t *atq, u64 taskc_ptr, u64 vtime);
int scx_atq_nr_queued(scx_atq_t *atq);
u64 scx_atq_pop(scx_atq_t *atq);
u64 scx_atq_peek(scx_atq_t *atq);
