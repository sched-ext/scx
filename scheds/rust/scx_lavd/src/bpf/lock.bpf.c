/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

static void try_inc_futex_boost(struct task_ctx *taskc, struct cpu_ctx *cpuc, u32 *uaddr)
{
	if (taskc && cpuc && (taskc->futex_uaddr != uaddr)) {
		taskc->futex_boost++;
		taskc->futex_uaddr = uaddr;
		cpuc->lock_holder = is_lock_holder(taskc);
	}
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void try_dec_futex_boost(struct task_ctx *taskc, struct cpu_ctx *cpuc, u32 *uaddr)
{
	if (taskc && cpuc && taskc->futex_boost > 0) {
		taskc->futex_boost--;
		taskc->futex_uaddr = NULL;
		cpuc->lock_holder = is_lock_holder(taskc);
	}
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void inc_futex_boost(u32 *uaddr)
{
	struct task_ctx *taskc = try_get_current_task_ctx();
	struct cpu_ctx *cpuc = get_cpu_ctx();
	try_inc_futex_boost(taskc, cpuc, uaddr);
}

static void dec_futex_boost(u32 *uaddr)
{
	struct task_ctx *taskc = try_get_current_task_ctx();
	struct cpu_ctx *cpuc = get_cpu_ctx();
	try_dec_futex_boost(taskc, cpuc, uaddr);
}

static void reset_lock_futex_boost(struct task_ctx *taskc, struct cpu_ctx *cpuc)
{
	if (is_lock_holder(taskc))
		taskc->need_lock_boost = true;

	taskc->futex_boost = 0;
	taskc->futex_uaddr = NULL;
	cpuc->lock_holder = false;
}

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

/**
 * TODO: NTsync driver in recent kernel (when ntsync is fully mainlined)
 * - https://lore.kernel.org/lkml/20240519202454.1192826-28-zfigura@codeweavers.com/
 * - https://github.com/torvalds/linux/blob/master/drivers/misc/ntsync.c
 * - https://www.youtube.com/watch?v=NjU4nyWyhU8
 */
