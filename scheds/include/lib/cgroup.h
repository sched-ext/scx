/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#pragma once

#include <errno.h>

/**
 * Configs for cpu.max
 */
struct scx_cgroup_bw_config {
	/* verbose level */
	int		verbose;
};

/**
 * scx_cgroup_bw_lib_init - Initialize the library with a configuration.
 * @config: tunnables, see the struct definition.
 *
 * It should be called for the library initialization before calling any
 * other API.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_lib_init(struct scx_cgroup_bw_config *config);

/**
 * scx_cgroup_bw_init - Initialize a cgroup for CPU bandwidth control.
 * @cgrp: cgroup being initialized.
 * @args: init arguments, see the struct definition.
 *
 * Either the BPF scheduler is being loaded or @cgrp created, initialize
 * @cgrp for CPU bandwidth control. When being loaded, cgroups are initialized
 * in a pre-order from the root. This operation may block.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted);

/**
 * scx_cgroup_bw_exit - Exit a cgroup.
 * @cgrp: cgroup being exited
 *
 * Either the BPF scheduler is being unloaded or @cgrp destroyed, exit
 * @cgrp for sched_ext. This operation my block.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted);

/**
 * scx_cgroup_bw_set - A cgroup's bandwidth is being changed.
 * @cgrp: cgroup whose bandwidth is being updated
 * @period_us: bandwidth control period
 * @quota_us: bandwidth control quota
 * @burst_us: bandwidth control burst
 *
 * Update @cgrp's bandwidth control parameters. This is from the cpu.max
 * cgroup interface.
 *
 * @quota_us / @period_us determines the CPU bandwidth @cgrp is entitled
 * to. For example, if @period_us is 1_000_000 and @quota_us is
 * 2_500_000. @cgrp is entitled to 2.5 CPUs. @burst_us can be
 * interpreted in the same fashion and specifies how much @cgrp can
 * burst temporarily. The specific control mechanism and thus the
 * interpretation of @period_us and burstiness is upto to the BPF
 * scheduler.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_set(struct cgroup *cgrp __arg_trusted, u64 period_us, u64 quota_us, u64 burst_us);

/**
 * scx_cgroup_bw_throttled - Check if the cgroup is throttled or not.
 * @cgrp: cgroup where a task belongs to.
 *
 * Return 0 when the cgroup is not throttled,
 * -EAGAIN when the cgroup is throttled, and
 * -errno for some other failures.
 */
int scx_cgroup_bw_throttled(struct cgroup *cgrp __arg_trusted);

/**
 * scx_cgroup_bw_consume - Consume the time actually used after the task execution.
 * @cgrp: cgroup where a task belongs to.
 * @consumed_ns: amount of time actually used.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_consume(struct cgroup *cgrp __arg_trusted, u64 consumed_ns);

/**
 * scx_cgroup_bw_put_aside - Put aside a task to execute it when the cgroup is
 * unthrottled later.
 * @p: a task to be put aside since the cgroup is throttled.
 * @taskc: a task-embedded pointer to scx_task_common.
 * @vtime: vtime of a task @p.
 * @cgrp: cgroup where a task belongs to.
 *
 * When a cgroup is throttled (i.e., scx_cgroup_bw_reserve() returns -EAGAIN),
 * a task that is in the ops.enqueue() path should be put aside to the BTQ of
 * its associated LLC context. When the cgroup becomes unthrottled again,
 * the registered enqueue_cb() will be called to re-enqueue the task for
 * execution.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_put_aside(struct task_struct *p __arg_trusted, u64 taskc, u64 vtime, struct cgroup *cgrp __arg_trusted);

/**
 * scx_cgroup_bw_reenqueue - Reenqueue backlogged tasks.
 *
 * When a cgroup is throttled, a task should be put aside at the ops.enqueue()
 * path. Once the cgroup becomes unthrottled again, such backlogged tasks
 * should be requeued for execution. To this end, a BPF scheduler should call
 * this at the beginning of its ops.dispatch() method, so that backlogged tasks
 * can be reenqueued if necessary.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_reenqueue(void);

/**
 * scx_cgroup_bw_cancel - Cancel throttling for a task.
 *
 * @taskc: Pointer to the scx_task_common task context. Passed as a u64
 * to avoid exposing the scx_task_common type to the scheduler.
 *
 * Tasks may be dequeued from the BPF side by the scx core during system
 * calls like sched_setaffinity(2). In that case, we must cancel any
 * throttling-related ATQ insert operations for the task:
 * - We must avoid double inserts caused by the dequeued task being
 *   reenqueed and throttled again while still in an ATQ.
 * - We want to remove tasks not in scx anymore from throttling. While
 *   inserting non-scx tasks into a DSQ is a no-op, we would like our
 *   accounting to be as accurate as possible.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_cancel(u64 taskc);

/**
 * REGISTER_SCX_CGROUP_BW_ENQUEUE_CB - Register an enqueue callback.
 * @eqcb: A function name with a prototype of 'void fn(void * __arg_arena)'.
 *
 * @eqcb enqueues a task with @pid following the BPF scheduler's
 * regular enqueue path. @enqueue_cb will be called when a throttled cgroup
 * becomes available again or when the cgroup is exiting for some reason.
 * @eqcb MUST enqueue the task; otherwise, the task will be lost and
 * never be scheduled.
 */
#define REGISTER_SCX_CGROUP_BW_ENQUEUE_CB(eqcb)					\
	__hidden int scx_cgroup_bw_enqueue_cb(u64 taskc)			\
	{									\
		extern int eqcb(u64);						\
		eqcb(taskc);							\
		return 0;							\
	}
