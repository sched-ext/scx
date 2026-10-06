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

/*
 * The destructor unlocks unconditionally. The verifier cannot prove an arena
 * pointer non-NULL, so DEFINE_GUARD's NULL test would leave it a path that
 * exits with preemption disabled.
 */
DEFINE_CLASS(scx_spin_lock, arena_spinlock_t __arena *, scx_spin_unlock(_T),
	     ({ scx_spin_lock(_T); _T; }), arena_spinlock_t __arena *_T)
#endif /* __BPF__ */
