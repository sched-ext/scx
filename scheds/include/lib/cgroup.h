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
 * scx_cgroup_bw_lib_init - 
 * @config:
 *
 * Returns
 */
int scx_cgroup_bw_lib_init(struct scx_cgroup_bw_config *config);

/**
 * scx_cgroup_bw_init - 
 * @cgrp:
 * @args:
 *
 * Returns
 */
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted);

/**
 * scx_cgroup_bw_exit - 
 * @cgrp:
 *
 * Returns
 */
int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted);

/**
 * scx_cgroup_bw_set - 
 * @cgrp:
 *
 * Returns
 */
int scx_cgroup_bw_set(struct cgroup *cgrp __arg_trusted, u64 period_us, u64 quota_us, u64 burst_us);

/**
 * scx_cgroup_bw_throttled -
 * @cgrp:
 *
 * Returns
 */
int scx_cgroup_bw_throttled(struct cgroup *cgrp __arg_trusted);

/**
 * scx_cgroup_bw_consume - 
 * @cgrp:
 * @consumed_ns:
 *
 * Returns
 */
int scx_cgroup_bw_consume(struct cgroup *cgrp __arg_trusted, u64 consumed_ns);

/**
 * scx_cgroup_bw_put_aside - 
 * @p:
 * @taskc:
 * @vtime:
 * @cgrp:
 *
 * Returns
 */
int scx_cgroup_bw_put_aside(struct task_struct *p __arg_trusted, u64 taskc, u64 vtime, struct cgroup *cgrp __arg_trusted);

/**
 * scx_cgroup_bw_reenqueue -
 *
 * Returns
 */
int scx_cgroup_bw_reenqueue(void);

/**
 * scx_cgroup_bw_cancel -
 *
 * Returns
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
