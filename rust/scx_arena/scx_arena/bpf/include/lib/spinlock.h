/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Arena spinlock wrappers for schedulers. A failed acquire aborts the
 * scheduler.
 */
#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_spin_lock.h>
#include <lib/cleanup.bpf.h>

/**
 * scx_spin_lock - Acquire @lock or abort the scheduler
 * @lock: the arena spinlock to acquire
 *
 * A failed acquire is a bug or a misconfiguration: a bounded spin ran out, a
 * cpu nested more queue nodes than it has, or the kernel is configured for
 * more cpus than the lock supports. After a timeout the queue is inconsistent,
 * so there is nothing a scheduler can do with the error. The caller then runs
 * its critical section unlocked while the scheduler is torn down.
 */
static __always_inline void scx_spin_lock(arena_spinlock_t __arena *lock)
{
	int ret = arena_spin_lock(lock);

	if (unlikely(ret)) {
		scx_bpf_error("arena_spin_lock failed (%d)", ret);
		/*
		 * arena_spin_lock() returns with preemption enabled on a
		 * failure. Disable it so that the caller's unlock stays balanced.
		 */
		bpf_preempt_disable();
	}
}

static __always_inline void scx_spin_unlock(arena_spinlock_t __arena *lock)
{
	arena_spin_unlock(lock);
}

/**
 * scx_spin_lock_irqsave - Acquire @lock with irqs off or abort the scheduler
 * @lock: the arena spinlock to acquire
 * @flags: where the irq state is saved, a local of the calling program
 *
 * For a lock that nests inside an irq-safe lock, such as one a callback takes
 * under the rq lock. Every holder of such a lock keeps irqs off, or an irq on a
 * holder's cpu can wait for the outer lock while that holder waits for @lock.
 */
static __always_inline void scx_spin_lock_irqsave(arena_spinlock_t __arena *lock,
						  unsigned long *flags)
{
	bpf_local_irq_save(flags);
	scx_spin_lock(lock);
}

static __always_inline void scx_spin_unlock_irqrestore(arena_spinlock_t __arena *lock,
						       unsigned long *flags)
{
	scx_spin_unlock(lock);
	bpf_local_irq_restore(flags);
}

/*
 * The destructor unlocks unconditionally. The verifier cannot prove an arena
 * pointer non-NULL, so DEFINE_GUARD's NULL test would leave it a path that
 * exits with preemption disabled.
 */
DEFINE_CLASS(scx_spin_lock, arena_spinlock_t __arena *, scx_spin_unlock(_T),
	     ({ scx_spin_lock(_T); _T; }), arena_spinlock_t __arena *_T)

/*
 * The irqsave guard constructs in place. The verifier ties the saved irq state
 * to the stack slot the save wrote, so the constructor is a macro that keeps
 * the flags in a compound literal of the caller's block, never in a value a
 * function returns.
 */
struct scx_spin_lock_irqsave_guard {
	arena_spinlock_t __arena *lock;
	unsigned long flags;
};

typedef struct scx_spin_lock_irqsave_guard *class_scx_spin_lock_irqsave_t;

static __always_inline class_scx_spin_lock_irqsave_t
__scx_spin_lock_irqsave_guard_init(struct scx_spin_lock_irqsave_guard *g)
{
	scx_spin_lock_irqsave(g->lock, &g->flags);
	return g;
}

static __always_inline void
class_scx_spin_lock_irqsave_destructor(class_scx_spin_lock_irqsave_t *p)
{
	scx_spin_unlock_irqrestore((*p)->lock, &(*p)->flags);
}

#define class_scx_spin_lock_irqsave_constructor(_lock)				\
	__scx_spin_lock_irqsave_guard_init(					\
		&(struct scx_spin_lock_irqsave_guard){ .lock = (_lock) })
#endif /* __BPF__ */
