// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
u64 scx_bpf_task_wake_signal_v1(struct task_struct *p) __ksym;
u64 scx_bpf_cpu_irq_ns_v1(s32 cpu) __ksym;
s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev, u64 flags, bool *idle) __ksym;
void scx_bpf_dsq_insert(struct task_struct *p, u64 id, u64 slice, u64 flags) __ksym;
bool scx_bpf_dsq_move_to_local(u64 id) __ksym;
s32 scx_bpf_create_dsq(u64 id, s32 node) __ksym;

struct results {
	u64 selected, running, stop_nonzero, tagged_runs, irq, bad_irq, exit_kind;
	u64 running_at, zero_runs;
	u32 target;
};
struct results result;

SEC("struct_ops.s/signals_init")
s32 BPF_PROG(signals_init)
{
	return scx_bpf_create_dsq(7, -1);
}

SEC("struct_ops/signals_select")
s32 BPF_PROG(signals_select, struct task_struct *p, s32 prev, u64 flags)
{
	bool idle = false;

	if (p->pid == result.target) {
		u64 token = scx_bpf_task_wake_signal_v1(p);

		if (token)
			result.selected = token;
	}
	return scx_bpf_select_cpu_dfl(p, prev, flags, &idle);
}

SEC("struct_ops/signals_enqueue")
void BPF_PROG(signals_enqueue, struct task_struct *p, u64 flags)
{
	scx_bpf_dsq_insert(p, 7, 1000000, flags);
}

SEC("struct_ops/signals_dispatch")
void BPF_PROG(signals_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(7);
}

SEC("struct_ops/signals_running")
void BPF_PROG(signals_running, struct task_struct *p)
{
	u64 token;

	if (p->pid != result.target)
		return;
	token = scx_bpf_task_wake_signal_v1(p);
	if (token) {
		result.running = token;
		result.running_at = bpf_ktime_get_ns();
		result.tagged_runs++;
	} else {
		result.zero_runs++;
	}
	result.irq = scx_bpf_cpu_irq_ns_v1(bpf_get_smp_processor_id());
	result.bad_irq = scx_bpf_cpu_irq_ns_v1(-1);
}

SEC("struct_ops/signals_stopping")
void BPF_PROG(signals_stopping, struct task_struct *p, bool runnable)
{
	if (p->pid == result.target && scx_bpf_task_wake_signal_v1(p))
		result.stop_nonzero++;
}

SEC("struct_ops/signals_exit")
void BPF_PROG(signals_exit, struct scx_exit_info *ei)
{
	result.exit_kind = ei->kind;
}

SEC(".struct_ops.link")
struct sched_ext_ops signals_ops = {
	.init = (void *)signals_init,
	.select_cpu = (void *)signals_select,
	.enqueue = (void *)signals_enqueue,
	.dispatch = (void *)signals_dispatch,
	.running = (void *)signals_running,
	.stopping = (void *)signals_stopping,
	.exit = (void *)signals_exit,
	.flags = SCX_OPS_WAKE_SIGNAL,
	.timeout_ms = 5000,
	.name = "cake_signal_test",
};
