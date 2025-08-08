/* SPDX-License-Identifier: GPL-2.0 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS(drop_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;
}

void BPF_STRUCT_OPS(drop_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Dispatch only kthreads */
	if (p->flags & PF_KTHREAD)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);

	/* Drop regular tasks on the floor */
}

void BPF_STRUCT_OPS(drop_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(drop_ops,
	       .select_cpu		= (void *)drop_select_cpu,
	       .enqueue			= (void *)drop_enqueue,
	       .exit			= (void *)drop_exit,
	       .timeout_ms		= 5000,
	       .name			= "drop");
