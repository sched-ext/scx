/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>

#ifndef SCX_OPS_BUILTIN_IDLE_PER_NODE
#define SCX_OPS_BUILTIN_IDLE_PER_NODE	(1ULL << 6)
#endif
#ifndef SCX_PICK_IDLE_IN_NODE
#define SCX_PICK_IDLE_IN_NODE		(1LLU << 1)
#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

static bool is_wake_sync(const struct task_struct *current, u64 wake_flags)
{
	return (wake_flags & SCX_WAKE_SYNC) && !(current->flags & PF_EXITING);
}

s32 BPF_STRUCT_OPS(topo_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();
	s32 cpu = bpf_get_smp_processor_id();

	if (is_wake_sync(current, wake_flags))
		return cpu;

	if ((prev_cpu == cpu) && is_kthread(current) && (p->nr_cpus_allowed == 1))
		return cpu;

	cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
	if (cpu >= 0)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	else
		cpu = prev_cpu;

	return cpu;
}

void BPF_STRUCT_OPS(topo_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}

	if (!__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p)) {
		s32 cpu;

		cpu = scx_bpf_select_cpu_and(p, scx_bpf_task_cpu(p), 0, p->cpus_ptr, 0);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, enq_flags);
			return;
		}
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);

	scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(topo_dispatch, s32 cpu, struct task_struct *prev)
{
	if (prev && is_queued(prev))
		prev->scx.slice = SCX_SLICE_DFL;
}

void BPF_STRUCT_OPS(topo_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(topo_ops,
	       .select_cpu		= (void *)topo_select_cpu,
	       .enqueue			= (void *)topo_enqueue,
	       .dispatch		= (void *)topo_dispatch,
	       .exit			= (void *)topo_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_BUILTIN_IDLE_PER_NODE |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= 5000,
	       .name			= "topo");
