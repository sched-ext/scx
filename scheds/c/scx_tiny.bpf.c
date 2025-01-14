/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_tiny: a tiny sched_ext scheduler.
 *
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS(tiny_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

void BPF_STRUCT_OPS(tiny_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(tiny_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(tiny_ops,
	       .select_cpu		= (void *)tiny_select_cpu,
	       .enqueue			= (void *)tiny_enqueue,
	       .exit			= (void *)tiny_exit,
	       .timeout_ms		= 5000,
	       .name			= "tiny");
