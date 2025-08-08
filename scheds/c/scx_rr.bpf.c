/* SPDX-License-Identifier: GPL-2.0 */

#include <scx/common.bpf.h>

#define SHARED_DSQ	0
#define SLICE_NS	SCX_SLICE_DFL

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Select per-CPU DSQs (when true) or a global DSQ (false).
 *
 * Per-CPU DSQs can help improve locality, global DSQ can help improve
 * responsiveness.
 */
const volatile bool pcpu_dsq = false;

/*
 * If true, prioritize waker's CPU on wakeup, otherwise keep the task
 * running on its previously used CPU.
 */
const volatile bool use_waker = false;

/*
 * Evaluate the task's time slice proportionally to its weight and
 * inversely proportional to the amount of contending tasks.
 */
static u64 task_slice(struct task_struct *p, s32 cpu)
{
	u64 nr_wait = scx_bpf_dsq_nr_queued(pcpu_dsq ?
					SCX_DSQ_LOCAL_ON | cpu : SHARED_DSQ);

	return SLICE_NS / (nr_wait + 1) * p->scx.weight / 100;
}

/*
 * Called on task wakeup to give the task a chance to migrate to an idle
 * CPU.
 */
s32 BPF_STRUCT_OPS(rr_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	/*
	 * Prioritize waker's CPU (current CPU) if @use_waker is enabled
	 * and ignore the previously used CPU.
	 */
	if (use_waker)
		prev_cpu = bpf_get_smp_processor_id();

	/*
	 * Rely on the sched_ext built-in idle CPU selection policy (that
	 * automatically applies topology optimizations).
	 */
	cpu = scx_bpf_select_cpu_and(p, prev_cpu, 0, p->cpus_ptr, 0);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, cpu), 0);
		return cpu;
	}

	return prev_cpu;
}

/*
 * Return true if we should attempt a task migration to an idle CPU, false
 * otherwise.
 *
 * We want to attempt a migration on task wakeup, if ops.select_cpu() was
 * skipped.
 */
static bool need_migrate(const struct task_struct *p, u64 enq_flags)
{
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p))
		return false;

	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Called when a task expired its time slice and still needs to run or on
 * wakeup when there's no idle CPU available.
 */
void BPF_STRUCT_OPS(rr_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu, prev_cpu = scx_bpf_task_cpu(p);

	if (need_migrate(p, enq_flags)) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, 0, p->cpus_ptr, 0);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   task_slice(p, cpu), enq_flags);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	scx_bpf_dsq_insert(p, pcpu_dsq ? SCX_DSQ_LOCAL : SHARED_DSQ,
			   task_slice(p, prev_cpu), enq_flags);
	scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Called when a CPU becomes available: dispatch the next task on the CPU
 * or let the CPU go idle.
 */
void BPF_STRUCT_OPS(rr_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!pcpu_dsq && scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;

	/*
	 * If no other task is contending the CPU and the previous task
	 * still wants to run, let it run by refilling its time slice.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = task_slice(prev, cpu);
}

/*
 * Scheduler exit callback.
 */
void BPF_STRUCT_OPS(rr_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Scheduler init callback.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(rr_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

SCX_OPS_DEFINE(rr_ops,
	       .select_cpu		= (void *)rr_select_cpu,
	       .enqueue			= (void *)rr_enqueue,
	       .dispatch		= (void *)rr_dispatch,
	       .init			= (void *)rr_init,
	       .exit			= (void *)rr_exit,
	       .flags			= SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= 5000,
	       .name			= "rr");
