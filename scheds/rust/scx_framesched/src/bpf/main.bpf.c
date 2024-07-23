/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#include <scx/common.bpf.h>
#include <scx/user_exit_info.h>

#include "helpers.h"
#include "intf.h"

#ifdef SCX_MAIN_SCHED
#error "SCX_MAIN_SCHED declared outside of main.bpf.c"
#endif

#define SCX_MAIN_SCHED
#include "pcpu.h"
#include "qos.h"
#include "domains.h"
#include "tasks.h"
#undef SCX_MAIN_SCHED

char _license[] SEC("license") = "GPL";

const volatile u8 debug;

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(framesched_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *taskc;

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return;

	taskc->runtime.curr_runtime = 0;
}

void BPF_STRUCT_OPS(framesched_running, struct task_struct *p)
{
	struct task_ctx *taskc;
	u64 now = bpf_ktime_get_ns();

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return;

	taskc->runtime.running_at = now;
}

void BPF_STRUCT_OPS(framesched_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	u64 now = bpf_ktime_get_ns(), runtime;

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return;

	runtime = now - taskc->runtime.running_at;
	taskc->runtime.curr_runtime += runtime;

	if (!runnable)
		taskc->runtime.average_runtime =
			calc_avg(taskc->runtime.average_runtime,
				 taskc->runtime.curr_runtime);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(framesched_init_task,
			     struct task_struct *p,
			     struct scx_init_task_args *args)
{
	int err;
	struct task_ctx *taskc;

	err = tasks_init_task(p, args);
	if (err)
		return err;

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return -ENOENT;

	tasks_publish_notif(p, taskc);
	err = domains_task_pick_dom(p, taskc);
	if (err && !taskc->orphaned) {
		scx_bpf_error("Failed to pick domain for %s[%d]", p->comm, p->pid);
		return err;
	} else {
		return 0;
	}
}

void BPF_STRUCT_OPS(framesched_cgroup_move,
		    struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *taskc = tasks_lookup_ctx(p);

	if (!taskc)
		return;

	tasks_publish_notif(p, taskc);
}

void BPF_STRUCT_OPS(framesched_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *taskc = tasks_lookup_ctx(p);

	if (!taskc)
		return;

	tasks_publish_notif(p, taskc);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(framesched_init)
{
	u32 dom;
	s32 cpu;
	int err;

	bpf_for(dom, 0, nr_dom_ids) {
		err = domains_init_dom(dom);
		if (err)
			return err;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		err = pcpu_init_ctx(cpu);
		if (err)
			return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(framesched_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(framesched,
		.cgroup_move		= (void *)framesched_cgroup_move,
		.exit			= (void *)framesched_exit,
		.init			= (void *)framesched_init,
		.init_task		= (void *)framesched_init_task,
		.runnable		= (void *)framesched_runnable,
		.running		= (void *)framesched_running,
		.set_weight		= (void *)framesched_set_weight,
		.stopping		= (void *)framesched_stopping,
		.timeout_ms		= 10000,
		.name			= "framesched");
