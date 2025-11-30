/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static void __inc_futex_boost(struct cpu_ctx *cpuc)
{
	struct task_struct *p = bpf_get_current_task_btf();
	task_ctx *taskc = get_task_ctx(p);

	if (taskc) {
		if (!cpuc)
			cpuc = get_cpu_ctx();

		if (cpuc) {
			set_task_flag(taskc, LAVD_FLAG_FUTEX_BOOST);
			cpuc->flags = taskc->flags;
		}
	}
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void __dec_futex_boost(struct cpu_ctx *cpuc)
{
	struct task_struct *p = bpf_get_current_task_btf();
	task_ctx *taskc = get_task_ctx(p);

	if (taskc && test_task_flag(taskc, LAVD_FLAG_FUTEX_BOOST)) {
		if (!cpuc)
			cpuc = get_cpu_ctx();

		if (cpuc) {
			reset_task_flag(taskc, LAVD_FLAG_FUTEX_BOOST);
			cpuc->flags = taskc->flags;
		}
	}
	/*
	 * If taskc is null, the task is not under sched_ext so ignore the error.
	 */
}

static void inc_futex_boost(void)
{
	__inc_futex_boost(NULL);
}

static void dec_futex_boost(void)
{
	__dec_futex_boost(NULL);
}

__hidden
void reset_lock_futex_boost(task_ctx *taskc, struct cpu_ctx *cpuc)
{
	if (is_lock_holder(taskc))
		set_task_flag(taskc, LAVD_FLAG_NEED_LOCK_BOOST);

	reset_task_flag(taskc, LAVD_FLAG_FUTEX_BOOST);
	cpuc->flags = taskc->flags;
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
 * - We do not distinguish futex user addresses to lower the tracing burden.
 *
 * We trace either ftrace entries or tracepoint entries. Ftrace is low-overhead,
 * but it does not provide stability, as function entries can disappear if
 * functions are inlined according to specific kernel configurations. Hence,
 * the BPF offers both ftrace and tracepoint, allowing userspace to make a
 * decision based on availability.
 *
 * The overhead of tracepoint, fentry, and fexit on AMD Ryzen 9 PRO 6950H are
 * as follows:
 *   - tracepoint: 130ns
 *   - fentry:      48ns
 *   - fexit:       76ns
 */

/*
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

SEC("?fexit/__futex_wait")
int BPF_PROG(fexit___futex_wait, u32 *uaddr, unsigned int flags, u32 val, struct hrtimer_sleeper *to, u32 bitset, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is acquired.
		 */
		inc_futex_boost();
	}
	return 0;
}

SEC("?fexit/futex_wait_multiple")
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
		inc_futex_boost();
	}
	return 0;
}

SEC("?fexit/futex_wait_requeue_pi")
int BPF_PROG(fexit_futex_wait_requeue_pi, u32 *uaddr, unsigned int flags, u32 val, ktime_t *abs_time, u32 bitset, u32 *uaddr2, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is acquired.
		 */
		inc_futex_boost();
	}
	return 0;
}

SEC("?fexit/futex_wake")
int BPF_PROG(fexit_futex_wake, u32 *uaddr, unsigned int flags, int nr_wake, u32 bitset, int ret)
{
	if (ret >= 0) {
		/*
		 * A futex is released.
		 */
		dec_futex_boost();
	}
	return 0;
}


SEC("?fexit/futex_wake_op")
int BPF_PROG(fexit_futex_wake_op, u32 *uaddr1, unsigned int flags, u32 *uaddr2, int nr_wake, int nr_wake2, int op, int ret)
{
	if (ret >= 0) {
		/*
		 * A futex is released.
		 */
		dec_futex_boost();
	}
	return 0;
}

SEC("?fexit/futex_lock_pi")
int BPF_PROG(fexit_futex_lock_pi, u32 *uaddr, unsigned int flags, ktime_t *time, int trylock, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is acquired.
		 */
		inc_futex_boost();
	}
	return 0;
}

SEC("?fexit/futex_unlock_pi")
int BPF_PROG(fexit_futex_unlock_pi, u32 *uaddr, unsigned int flags, int ret)
{
	if (ret == 0) {
		/*
		 * A futex is released.
		 */
		dec_futex_boost();
	}
	return 0;
}


/*
 * We trace the folloing futex tracepoints:
 * - sys_exit_futex
 * - sys_exit_futex_wait
 * - sys_exit_futex_waitv
 * - sys_exit_futex_wake
 */

/*
 * The following defines are from 'linux/include/uapi/linux/futex.h'
 */
#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12
#define FUTEX_LOCK_PI2		13

#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

struct tp_syscall_enter_futex {
	struct trace_entry ent;
	int __syscall_nr;
	u32 __attribute__((btf_type_tag("user"))) * uaddr;
	int op;
	u32 val;
	struct __kernel_timespec __attribute__((btf_type_tag("user"))) * utime;
	u32 __attribute__((btf_type_tag("user"))) * uaddr2;
	u32 val3;
};

struct tp_syscall_exit {
	struct trace_entry ent;
	int __syscall_nr;
	long ret;
};

SEC("?tracepoint/syscalls/sys_enter_futex")
int rtp_sys_enter_futex(struct tp_syscall_enter_futex *ctx)
{
	struct cpu_ctx *cpuc = get_cpu_ctx();

	if (cpuc)
		cpuc->futex_op = ctx->op;
	return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex")
int rtp_sys_exit_futex(struct tp_syscall_exit *ctx)
{
	struct cpu_ctx *cpuc;
	int cmd;

	if (ctx->ret < 0)
		return 0;

	cpuc = get_cpu_ctx();
	if (!cpuc)
		return 0;

	cmd = cpuc->futex_op & FUTEX_CMD_MASK;
	switch (cmd) {
	case FUTEX_WAIT:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAIT_REQUEUE_PI:
		if (ctx->ret == 0) /* 0 for wait success */
			__inc_futex_boost(cpuc);
		return 0;

	case FUTEX_WAKE:
	case FUTEX_WAKE_BITSET:
	case FUTEX_WAKE_OP:
		if (ctx->ret > 0) /* the number of waiters that were woken up */
			__dec_futex_boost(cpuc);
		return 0;

	case FUTEX_LOCK_PI:
	case FUTEX_LOCK_PI2:
	case FUTEX_TRYLOCK_PI:
		if (ctx->ret == 0) /* 0 for successful locking */
			__inc_futex_boost(cpuc);
		return 0;

	case FUTEX_UNLOCK_PI:
		if (ctx->ret == 0) /* 0 for successful unlocking */
			__dec_futex_boost(cpuc);
		return 0;
	}

	return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex_wait")
int rtp_sys_exit_futex_wait(struct tp_syscall_exit *ctx)
{
	if (ctx->ret == 0) /* 0 for wait success */
		inc_futex_boost();
	return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex_waitv")
int rtp_sys_exit_futex_waitv(struct tp_syscall_exit *ctx)
{
	if (ctx->ret >= 0) /* array index of one of the woken futexes */
		inc_futex_boost();
	return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex_wake")
int rtp_sys_exit_futex_wake(struct tp_syscall_exit *ctx)
{
	if (ctx->ret > 0) /* the number of waiters that were woken up */
		dec_futex_boost();
	return 0;
}

/**
 * TODO: NTsync driver in recent kernel (when ntsync is fully mainlined)
 * - https://lore.kernel.org/lkml/20240519202454.1192826-28-zfigura@codeweavers.com/
 * - https://github.com/torvalds/linux/blob/master/drivers/misc/ntsync.c
 * - https://www.youtube.com/watch?v=NjU4nyWyhU8
 */
