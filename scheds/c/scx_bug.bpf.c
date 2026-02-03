/* SPDX-License-Identifier: GPL-2.0 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 4096);
	__type(value, s32);
} global_queue SEC(".maps");

s32 BPF_STRUCT_OPS(bug_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	/*
	 * Force all tasks to go through ops.enqueue().
	 */
	return prev_cpu;
}

void BPF_STRUCT_OPS(bug_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid = p->pid;

	/*
	 * Insert the task to the global BPF queue.
	 */
	if (bpf_map_push_elem(&global_queue, &pid, 0)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}
}

void BPF_STRUCT_OPS(bug_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p;
	s32 pid;

	bpf_repeat(BPF_MAX_LOOPS) {
		if (bpf_map_pop_elem(&global_queue, &pid))
			break;

		p = bpf_task_from_pid(pid);
		if (!p)
			continue;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			cpu = scx_bpf_pick_any_cpu(p->cpus_ptr, 0);

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
		bpf_task_release(p);

		break;
	}
}

void BPF_STRUCT_OPS(bug_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(bug_ops,
	       .select_cpu		= (void *)bug_select_cpu,
	       .enqueue			= (void *)bug_enqueue,
	       .dispatch		= (void *)bug_dispatch,
	       .exit			= (void *)bug_exit,
	       .timeout_ms		= 5000,
	       .name			= "bug");
