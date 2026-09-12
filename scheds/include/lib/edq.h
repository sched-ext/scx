/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. */
#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <bpf_atomic.h>
#endif

#define SCX_EDQ_DEAD ((u64)1)

struct scx_edq;
struct scx_edq_node;

typedef struct scx_edq __arena scx_edq_t;
typedef struct scx_edq_node __arena scx_edq_node_t;

struct scx_edq_node {
	scx_edq_node_t *parent;
	scx_edq_node_t *left;
	scx_edq_node_t *right;
	u64 deadline;
	u64 eligibility;
	u64 min_eligibility;
	u64 seq;
	u32 height;
};

struct scx_edq_task {
	struct scx_edq_node node;
	int holdcnt;
	scx_edq_t *edq;
};

typedef struct scx_edq_task __arena scx_edq_task_t;

/*
 * A deadline-ordered intrusive AVL tree augmented with the minimum
 * eligibility value of every subtree. The queue itself can be embedded in
 * another arena object, avoiding a per-queue allocation.
 *
 * All queue operations must run with preemption disabled. EDQ deliberately
 * leaves context protection to its caller so sched_ext callbacks which
 * already hold an rq lock don't pay for redundant BPF kfunc calls.
 */
struct scx_edq {
	scx_edq_node_t *root;
	scx_edq_node_t *first;
	/* Lockless advisory snapshot for deadline-only policy decisions. */
	u64 first_deadline;
	u32 lock;
	u64 nr;
	u64 seq;
};

#ifdef __BPF__
int scx_edq_insert(scx_edq_t __arg_arena *edq,
		    scx_edq_task_t __arg_arena *task,
		    u64 deadline, u64 eligibility);
int scx_edq_remove(scx_edq_t __arg_arena *edq,
		    scx_edq_task_t __arg_arena *task);
int scx_edq_try_remove(scx_edq_t __arg_arena *edq,
			scx_edq_task_t __arg_arena *task);
u64 scx_edq_pop(scx_edq_t __arg_arena *edq, bool hold);
u64 scx_edq_pop_first_eligible(scx_edq_t __arg_arena *edq, u64 cutoff,
				 bool hold);
u64 scx_edq_pop_first_eligible_or_first(scx_edq_t __arg_arena *edq,
					 u64 cutoff, bool hold);
u64 scx_edq_peek_hold(scx_edq_t __arg_arena *edq);
int scx_edq_try_peek_hold(scx_edq_t __arg_arena *edq, u64 *task __arg_nonnull);
u64 scx_edq_nr_queued(scx_edq_t __arg_arena *edq);
int scx_edq_task_init(scx_edq_task_t __arg_arena *task);
int scx_edq_task_fini(scx_edq_task_t __arg_arena *task);
int scx_edq_task_detach(scx_edq_task_t __arg_arena *task);

/*
 * Lockless snapshot of the earliest deadline, for advisory decisions that
 * accept a stale value when the queue changes underneath them. -ENOENT when
 * the queue is empty.
 */
static __always_inline int scx_edq_first_deadline(scx_edq_t __arg_arena *edq,
						  u64 *deadline)
{
	*deadline = READ_ONCE(edq->first_deadline);
	return READ_ONCE(edq->nr) ? 0 : -ENOENT;
}

static __always_inline void scx_edq_task_hold(scx_edq_task_t __arg_arena *task)
{
	__atomic_add_fetch(&task->holdcnt, 1, 0);
}

static __always_inline void scx_edq_task_drop(scx_edq_task_t __arg_arena *task)
{
	__atomic_add_fetch(&task->holdcnt, -1, 0);
}

static __always_inline int scx_edq_lock(scx_edq_t __arg_arena *edq)
{
	if (!READ_ONCE(edq->lock) && cmpxchg(&edq->lock, 0, 1) == 0)
		return 0;
	while (can_loop) {
		if (!READ_ONCE(edq->lock) && cmpxchg(&edq->lock, 0, 1) == 0)
			return 0;
		cpu_relax();
	}
	scx_bpf_error("scx_edq: lock timed out");
	return -ETIMEDOUT;
}

static __always_inline int scx_edq_trylock(scx_edq_t __arg_arena *edq)
{
	/* Avoid a locked RMW and cacheline bounce when contention is visible. */
	if (!READ_ONCE(edq->lock) && cmpxchg(&edq->lock, 0, 1) == 0)
		return 0;
	return -EBUSY;
}

static __always_inline void scx_edq_unlock(scx_edq_t __arg_arena *edq)
{
	/*
	 * Use BPF_STORE_REL when the target ISA supports it. The legacy release
	 * helper is sufficient on x86 TSO, but on weakly ordered targets it can
	 * lower to an unordered atomic followed by a plain store (e.g., current
	 * arm64 -mcpu=v3 builds emit STSET followed by STRW). Use an exchange
	 * there so publishing the unlocked state has release ordering.
	 */
#if defined(__BPF_FEATURE_LOAD_ACQ_STORE_REL)
	__atomic_store_n(&edq->lock, 0, __ATOMIC_RELEASE);
#elif defined(__TARGET_ARCH_x86)
	smp_store_release(&edq->lock, 0);
#else
	(void)__sync_lock_test_and_set(&edq->lock, 0);
#endif
}
#endif
