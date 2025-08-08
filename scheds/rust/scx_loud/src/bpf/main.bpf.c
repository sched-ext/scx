/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

volatile u32 nr_cpus;

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

static s32 pick_idle_cpu(struct task_struct *p)
{
	u64 max_cpu = scx_bpf_nr_cpu_ids();
	s32 i, cpu;

	bpf_for(i, 0, nr_cpus) {
		cpu = max_cpu - i - 1;
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}

	return -EBUSY;
}

s32 BPF_STRUCT_OPS(loud_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	cpu = pick_idle_cpu(p);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return cpu;
	}

	return prev_cpu;
}

void BPF_STRUCT_OPS(loud_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;

	/*
	 * Aggressively attempt to migrate the task to an idle CPU.
	 */
	cpu = pick_idle_cpu(p);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, enq_flags);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
	scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(loud_dispatch, s32 cpu, struct task_struct *prev)
{
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = SCX_SLICE_DFL;
}

void BPF_STRUCT_OPS(loud_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(loud_ops,
	       .select_cpu		= (void *)loud_select_cpu,
	       .enqueue			= (void *)loud_enqueue,
	       .dispatch		= (void *)loud_dispatch,
	       .exit			= (void *)loud_exit,
	       .timeout_ms		= 5000,
	       .name			= "loud");
