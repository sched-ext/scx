/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __TASKS_H
#define __TASKS_H

#ifndef SCX_MAIN_SCHED
#error "Should only be included from the main sched BPF C file"
#endif

#include <scx/common.bpf.h>
#include <scx/user_exit_info.h>

#include "intf.h"

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

static struct task_ctx *tasks_try_lookup_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

static struct task_ctx *tasks_lookup_ctx(struct task_struct *p)
{
	struct task_ctx *taskc;

	taskc = tasks_try_lookup_ctx(p);
	if (!taskc)
		scx_bpf_error("Failed to lookup task ctx for %s[%d]", p->comm, p->pid);

	return taskc;
}

static int tasks_init_task(struct task_struct *p, __maybe_unused struct scx_init_task_args *args)
{

	struct task_ctx *taskc;
	int err;


	taskc = bpf_task_storage_get(&task_ctxs, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc)
		return -ENOMEM;

	err = create_assign_cpumask(&taskc->cpumask);
	if (err)
		return err;

	return 0;
}

#endif // __TASKS_H
