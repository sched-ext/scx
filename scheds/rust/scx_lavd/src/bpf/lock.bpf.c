/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

#define LAVD_TRACE_SEM
#define LAVD_TRACE_MUTEX
#define LAVD_TRACE_WW_MUTEX
#define LAVD_TRACE_RT_MUTEX
#define LAVD_TRACE_RW_SEM
#define LAVD_TRACE_PERCPU_RW_SEM 
#define LAVD_TRACE_FUTEX

static void try_inc_lock_boost(struct task_ctx *taskc)
{
	if (taskc)
		taskc->lock_boost++;
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void try_dec_lock_boost(struct task_ctx *taskc)
{
	if (taskc && taskc->lock_boost > 0)
		taskc->lock_boost--;
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void inc_lock_boost(void)
{
	struct task_ctx *taskc = try_get_current_task_ctx();
	try_inc_lock_boost(taskc);
}

static void dec_lock_boost(void)
{
	struct task_ctx *taskc = try_get_current_task_ctx();
	try_dec_lock_boost(taskc);
}


static void try_inc_futex_boost(struct task_ctx *taskc, u32 *uaddr)
{
	if (taskc && (taskc->futex_uaddr != uaddr)) {
		taskc->futex_boost++;
		taskc->futex_uaddr = uaddr;
	}
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void try_dec_futex_boost(struct task_ctx *taskc, u32 *uaddr)
{
	if (taskc && taskc->futex_boost > 0) {
		taskc->futex_boost--;
		taskc->futex_uaddr = NULL;
	}
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void inc_futex_boost(u32 *uaddr)
{
	struct task_ctx *taskc = try_get_current_task_ctx();
	try_inc_futex_boost(taskc, uaddr);
}

static void dec_futex_boost(u32 *uaddr)
{
	struct task_ctx *taskc = try_get_current_task_ctx();
	try_dec_futex_boost(taskc, uaddr);
}

static void reset_lock_futex_boost(struct task_ctx *taskc)
{
	taskc->lock_cnt = 0;
	taskc->lock_boost = 0;
	taskc->futex_boost = 0;
	taskc->futex_uaddr = NULL;
}

/**
 * semaphore in kernel (kernel/locking/semaphore.c)
 * - void __sched down(struct semaphore *sem)
 * - int __sched down_interruptible(struct semaphore *sem)
 * - int __sched down_killable(struct semaphore *sem)
 * - int __sched down_trylock(struct semaphore *sem)
 * - int __sched down_timeout(struct semaphore *sem, long timeout)
 * - void __sched up(struct semaphore *sem)
 */
#ifdef LAVD_TRACE_SEM
struct semaphore;

SEC("fexit/down")
int BPF_PROG(fexit_down, struct semaphore *sem)
{
	/*
	 * A semaphore is successfully acquired.
	 */
	inc_lock_boost();
	return 0;
}

SEC("fexit/down_interruptible")
int BPF_PROG(fexit_down_interruptible, struct semaphore *sem, int ret)
{
	if (ret == 0) {
		/*
		 * A semaphore is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/down_killable")
int BPF_PROG(fexit_down_killable, struct semaphore *sem, int ret)
{
	if (ret == 0) {
		/*
		 * A semaphore is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/down_trylock")
int BPF_PROG(fexit_down_trylock, struct semaphore *sem, int ret)
{
	if (ret == 0) {
		/*
		 * A semaphore is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/up")
int BPF_PROG(fexit_up, struct semaphore *sem)
{
	/*
	 * A semaphore is successfully released.
	 */
	dec_lock_boost();
	return 0;
}
#endif /* LAVD_TRACE_SEM */


/**
 * mutex in kernel (kernel/locking/mutex.c)
 * - void __sched mutex_lock(struct mutex *lock)
 * - int __sched mutex_lock_interruptible(struct mutex *lock)
 * - int __sched mutex_lock_killable(struct mutex *lock)
 * - int __sched mutex_trylock(struct mutex *lock)
 * - void __sched mutex_unlock(struct mutex *lock)
 *
 * - int __sched ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
 * - int __sched ww_mutex_lock_interruptible(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
 * - int ww_mutex_trylock(struct ww_mutex *ww, struct ww_acquire_ctx *ww_ctx)
 * - void __sched ww_mutex_unlock(struct ww_mutex *lock)
 */
#ifdef LAVD_TRACE_MUTEX
struct mutex;
SEC("fexit/mutex_lock")
int BPF_PROG(fexit_mutex_lock, struct mutex *mutex)
{
	/*
	 * A mutex is successfully acquired.
	 */
	inc_lock_boost();
	return 0;
}

SEC("fexit/mutex_lock_interruptible")
int BPF_PROG(fexit_mutex_lock_interruptible, struct mutex *mutex, int ret)
{
	if (ret == 0) {
		/*
		 * A mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/mutex_lock_killable")
int BPF_PROG(fexit_mutex_lock_killable, struct mutex *mutex, int ret)
{
	if (ret == 0) {
		/*
		 * A mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/mutex_trylock")
int BPF_PROG(fexit_mutex_trylock, struct mutex *mutex, int ret)
{
	if (ret == 1) {
		/*
		 * A mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/mutex_unlock")
int BPF_PROG(fexit_mutex_unlock, struct mutex *mutex)
{
	/*
	 * A mutex is successfully released.
	 */
	dec_lock_boost();
	return 0;
}
#endif /* LAVD_TRACE_MUTEX */

#ifdef LAVD_TRACE_WW_MUTEX
struct ww_mutex;
struct ww_acquire_ctx;

SEC("fexit/ww_mutex_lock")
int BPF_PROG(fexit_ww_mutex_lock, struct ww_mutex *lock, struct ww_acquire_ctx *x, int ret)
{
	if (ret == 0) {
		/*
		 * A ww_mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/ww_mutex_lock_interruptible")
int BPF_PROG(fexit_ww_mutex_lock_interruptible, struct ww_mutex *lock, struct ww_acquire_ctx *x, int ret)
{
	if (ret == 0) {
		/*
		 * A ww_mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/ww_mutex_trylock")
int BPF_PROG(fexit_ww_mutex_trylock, struct ww_mutex *lock, struct ww_acquire_ctx *x, int ret)
{
	if (ret == 1) {
		/*
		 * A ww_mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/ww_mutex_unlock")
int BPF_PROG(fexit_ww_mutex_unlock, struct ww_mutex *lock)
{
	/*
	 * A ww_mutex is successfully released.
	 */
	dec_lock_boost();
	return 0;
}
#endif /* LAVD_TRACE_WW_MUTEX */

/**
 * RT-mutex in kernel (kernel/locking/rtmutex_api.c)
 * - void __sched rt_mutex_lock(struct rt_mutex *lock)
 * - int __sched rt_mutex_lock_interruptible(struct rt_mutex *lock)
 * - int __sched rt_mutex_lock_killable(struct rt_mutex *lock)
 * - int __sched rt_mutex_trylock(struct rt_mutex *lock)
 * - void __sched rt_mutex_unlock(struct rt_mutex *lock)
 */
#ifdef LAVD_TRACE_RT_MUTEX
struct rt_mutex;

SEC("fexit/rt_mutex_lock")
int BPF_PROG(fexit_rt_mutex_lock, struct rt_mutex *lock)
{
	/*
	 * An rt_mutex is successfully acquired.
	 */
	inc_lock_boost();
	return 0;
}

SEC("fexit/rt_mutex_lock_interruptible")
int BPF_PROG(fexit_rt_mutex_lock_interruptible, struct rt_mutex *lock, int ret)
{
	if (ret == 0) {
		/*
		 * An rt_mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/rt_mutex_lock_killable")
int BPF_PROG(fexit_rt_mutex_lock_killable, struct rt_mutex *lock, int ret)
{
	if (ret == 0) {
		/*
		 * An rt_mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/rt_mutex_trylock")
int BPF_PROG(fexit_rt_mutex_trylock, struct rt_mutex *lock, int ret)
{
	if (ret == 1) {
		/*
		 * An rt_mutex is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/rt_mutex_unlock")
int BPF_PROG(fexit_rt_mutex_unlock, struct rt_mutex *lock)
{
	/*
	 * An rt_mutex is successfully released.
	 */
	dec_lock_boost();
	return 0;
}
#endif /* LAVD_TRACE_RT_MUTEX */

/**
 * Reader-writer semaphore in kernel (kernel/locking/rwsem.c)
 * The kernel rwsem prioritizes readers, so here prioritizes writers only.
 * - void __sched down_write(struct rw_semaphore *sem)
 * - int __sched down_write_killable(struct rw_semaphore *sem)
 * - int down_write_trylock(struct rw_semaphore *sem)
 * - void up_write(struct rw_semaphore *sem)
 * - void downgrade_write(struct rw_semaphore *sem)
 */
#ifdef LAVD_TRACE_RW_SEM
struct rw_semaphore;

SEC("fexit/down_write")
int BPF_PROG(fexit_down_write, struct rw_semaphore *sem)
{
	/*
	 * An rw_semaphore is successfully acquired.
	 */
	inc_lock_boost();
	return 0;
}


SEC("fexit/down_write_killable")
int BPF_PROG(fexit_down_write_killable, struct rw_semaphore *sem, int ret)
{
	if (ret == 0) {
		/*
		 * An rw_semaphore is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/down_write_trylock")
int BPF_PROG(fexit_down_write_trylock, struct rw_semaphore *sem, int ret)
{
	if (ret == 1) {
		/*
		 * An rw_semaphore is successfully acquired.
		 */
		inc_lock_boost();
	}
	return 0;
}

SEC("fexit/up_write")
int BPF_PROG(fexit_up_write, struct rw_semaphore *sem)
{
	/*
	 * An rw_semaphore is successfully released.
	 */
	dec_lock_boost();
	return 0;
}

SEC("fexit/downgrade_write")
int BPF_PROG(fexit_downgrade_write, struct rw_semaphore *sem)
{
	/*
	 * An rw_semaphore is successfully downgraded to a read lock.
	 */
	dec_lock_boost();
	return 0;
}
#endif /* LAVD_TRACE_RW_SEM */

/**
 * Per-CPU reader-writer semaphore in kernel (kernel/locking/percpu-rwsem.c)
 * The kernel rwsem prioritizes readers, so here prioritizes writers only.
 * - void __sched percpu_down_write(struct percpu_rw_semaphore *sem)
 * - void percpu_up_write(struct percpu_rw_semaphore *sem)
 */
#ifdef LAVD_TRACE_PERCPU_RW_SEM
struct percpu_rw_semaphore;

SEC("fexit/percpu_down_write")
int BPF_PROG(fexit_percpu_down_write, struct percpu_rw_semaphore *sem)
{
	/*
	 * An percpu_rw_semaphore is successfully acquired.
	 */
	inc_lock_boost();
	return 0;
}


SEC("fexit/percpu_up_write")
int BPF_PROG(fexit_percpu_up_write, struct percpu_rw_semaphore *sem)
{
	/*
	 * An percpu_rw_semaphore is successfully released.
	 */
	dec_lock_boost();
	return 0;
}
#endif /* LAVD_TRACE_PERCPU_RW_SEM */


/**
 * Futex for userspace synchronization primiteves (kernel/futex/)
 *
 * Trace futex_wait() and futex_wake() variants similar as in-kernel lock
 * and unlock. However, in the case of futex, the user-level implementation,
 * like NTPL, can skip futex_wait() and futex_wake() for performance
 * optimization to reduce syscall overhead. Hence, tracing only the 
 * kernel-side futex calls reveals incomplete user-level lock status. Also,
 * futex's spurious wake-up further complicates the problem; a lock holder
 * can call futex_wait() more than once for a single lock acquisition.
 * One potential approach would be using uprobe to directly hook a posix
 * library calls. However, it would incur high overhead since uprobe is based
 * on a trap causing context switching, diminishing the optimization of
 * a user-level lock implementation.
 *
 * Our approximated approach is as follows:
 * - When a futex_wait() call is skipped in the lock acquisition path, that
 *   means there is no waiter -- the lock is not contending. Hence, we don't
 *   need to boost the lock holder, so we don't care.
 * - When a task calls futex_wait() more than once before calling futex_wake(),
 *   that means a task reties futex_wait() after the spurious wake-up. Hence,
 *   we can safely ignore the second futex_wait() call onwards.
 * - When a futex_wake() is skipped, it indicates that there is no waiter and
 *   the lock is not contending. However, it also means we cannot determine
 *   when the user-space lock is released. Here, we assume that a reasonably
 *   designed critical section is short enough and too long a critical section
 *   is not worth boosting. So when a futex_wake() is not called within a one
 *   time slice, we assume futex_wake() is skipped.
 *
 * We trace the folloing futex calls:
 * - int __futex_wait(u32 *uaddr, unsigned int flags, u32 val, struct hrtimer_sleeper *to, u32 bitset)
 * - int futex_wait_multiple(struct futex_vector *vs, unsigned int count, struct hrtimer_sleeper *to)
 * - int futex_wait_requeue_pi(u32 *uaddr, unsigned int flags, u32 val, ktime_t *abs_time, u32 bitset, u32 *uaddr2)
 *
 * - int futex_wake(u32 *uaddr, unsigned int flags, int nr_wake, u32 bitset)
 * - int futex_wake_op(u32 *uaddr1, unsigned int flags, u32 *uaddr2, int nr_wake, int nr_wake2, int op)
 *
 * - int futex_lock_pi(u32 *uaddr, unsigned int flags, ktime_t *time, int trylock)
 * - int futex_unlock_pi(u32 *uaddr, unsigned int flags)
 */
#ifdef LAVD_TRACE_FUTEX
struct futex_vector;
struct hrtimer_sleeper;

SEC("fexit/__futex_wait")
int BPF_PROG(fexit___futex_wait, u32 *uaddr, unsigned int flags, u32 val, struct hrtimer_sleeper *to, u32 bitset, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is acquired.
		 */
		inc_futex_boost(uaddr);
	}
	return 0;
}

SEC("fexit/futex_wait_multiple")
int BPF_PROG(fexit_futex_wait_multiple, struct futex_vector *vs, unsigned int count, struct hrtimer_sleeper *to, int ret)
{
	if (ret == 0) {
		/*
		 * All of futexes are acquired.
		 *
		 * We don't want to traverse futex_vector here since that's
		 * a userspace address. Hence we just pass an invalid adderess
		 * to consider all futex_waitv() calls are for the same address.
		 * Thit is a conservative approximation boosting less.
		 */
		inc_futex_boost((u32 *)0xbeefcafe); 
	}
	return 0;
}

SEC("fexit/futex_wait_requeue_pi")
int BPF_PROG(fexit_futex_wait_requeue_pi, u32 *uaddr, unsigned int flags, u32 val, ktime_t *abs_time, u32 bitset, u32 *uaddr2, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is acquired.
		 */
		inc_futex_boost(uaddr);
	}
	return 0;
}

SEC("fexit/futex_wake")
int BPF_PROG(fexit_futex_wake, u32 *uaddr, unsigned int flags, int nr_wake, u32 bitset, int ret)
{
	if (ret >= 0) {
		/*
		 * A futex is released.
		 */
		dec_futex_boost(uaddr);
	}
	return 0;
}


SEC("fexit/futex_wake_op")
int BPF_PROG(fexit_futex_wake_op, u32 *uaddr1, unsigned int flags, u32 *uaddr2, int nr_wake, int nr_wake2, int op, int ret)
{
	if (ret >= 0) {
		/*
		 * A futex is released.
		 */
		dec_futex_boost(uaddr1);
	}
	return 0;
}

SEC("fexit/futex_lock_pi")
int BPF_PROG(fexit_futex_lock_pi, u32 *uaddr, unsigned int flags, ktime_t *time, int trylock, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is acquired.
		 */
		inc_futex_boost(uaddr);
	}
	return 0;
}

SEC("fexit/futex_unlock_pi")
int BPF_PROG(fexit_futex_unlock_pi, u32 *uaddr, unsigned int flags, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is released.
		 */
		dec_futex_boost(uaddr);
	}
	return 0;
}
#endif /* LAVD_TRACE_FUTEX */


/**
 * TODO: NTsync driver in recent kernel (when ntsync is fully mainlined)
 * - https://lore.kernel.org/lkml/20240519202454.1192826-28-zfigura@codeweavers.com/
 * - https://github.com/torvalds/linux/blob/master/drivers/misc/ntsync.c
 * - https://www.youtube.com/watch?v=NjU4nyWyhU8
 */
