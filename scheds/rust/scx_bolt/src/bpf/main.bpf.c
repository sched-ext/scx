/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#include <scx/common.bpf.h>
#include <scx/user_exit_info.h>

#include "intf.h"

#define SCX_MAIN_SCHED
#include "domains.h"
#include "tasks.h"
#include "pcpu.h"
#undef SCX_MAIN_SCHED

char _license[] SEC("license") = "GPL";

const volatile u8 debug;

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS_SLEEPABLE(bolt_init_task,
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

	err = domains_task_pick_dom(p, taskc);
	if (err && !taskc->orphaned) {
		scx_bpf_error("Failed to pick domain for %s[%d]", p->comm, p->pid);
		return err;
	} else {
		return 0;
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(bolt_init)
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

void BPF_STRUCT_OPS(bolt_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(bolt,
		.init_task		= (void *)bolt_init_task,
		.init			= (void *)bolt_init,
		.exit			= (void *)bolt_exit,
		.timeout_ms		= 10000,
		.name			= "bolt");
