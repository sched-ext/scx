/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_vder: Virtual Deadline with Execution Runtime.
 *
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>

#define SCX_OPS_ENQ_MIGRATION_DISABLED  (1LLU << 4)
#define SCX_OPS_ALLOW_QUEUED_WAKEUP	(1LLU << 5)
#define SCX_OPS_BUILTIN_IDLE_PER_NODE	(1LLU << 6)
#define SCX_PICK_IDLE_IN_NODE		(1LLU << 1)

#define NR_NODES			8

int scx_bpf_cpu_node(s32 cpu) __ksym __weak;
s32 scx_bpf_pick_idle_cpu_in_node(const cpumask_t *cpus_allowed, int node, u64 flags) __ksym __weak;
const struct cpumask *scx_bpf_get_idle_smtmask_node(int node) __ksym __weak;

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),
};

char _license[] SEC("license") = "GPL";

/*
 * Define struct user_exit_info which is shared between BPF and userspace
 * to communicate the exit status.
 */
UEI_DEFINE(uei);

/*
 * Try to wake up an idle CPU that can immediately process the task.
 */
static void kick_idle_cpu(const struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	int node = scx_bpf_cpu_node(cpu);

	/*
	 * Look for an idle CPU that can immediately execute the task.
	 *
	 * Note that we do not want to mark the CPU as busy, since we don't
	 * know at this stage if we'll actually dispatch any task on it.
	 */
	cpu = scx_bpf_pick_idle_cpu_in_node(p->cpus_ptr, node, 0);
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * Attempt to dispatch a task directly to its assigned CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
static bool try_direct_dispatch(struct task_struct *p, u64 enq_flags)
{
	/*
	 * If a task has been re-enqueued because its assigned CPU has been
	 * taken by a higher priority scheduling class, force it to follow
	 * the regular scheduling path and give it a chance to run on a
	 * different CPU.
	 */
	if (enq_flags & SCX_ENQ_REENQ)
		return false;

	/*
	 * If ops.select_cpu() has been skipped, try direct dispatch.
	 */
	if (!(enq_flags & SCX_ENQ_CPU_SELECTED)) {
		s32 prev_cpu = scx_bpf_task_cpu(p);

		/*
		 * Dispatch tasks that can only run on a single CPU directly, but give
		 * them a shorter time slice.
		 */
		if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, NSEC_PER_MSEC, enq_flags);
			return true;
		}

		/*
		 * Dispatch directly in case of wakeup, but also assign a
		 * shorter time slice.
		 */
		if (enq_flags & SCX_ENQ_WAKEUP) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, NSEC_PER_MSEC, enq_flags);
			return true;
		}

		/*
		 * If the local shared DSQ is empty and the previous CPU can
		 * still be used by the task, perform the direct dispatch.
		 */
		if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cpu) &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
					   SCX_SLICE_DFL, enq_flags);
			return true;
		}
	}

	/*
	 * Direct dispatch not possible, follow the regular scheduling
	 * path.
	 */
	return false;
}

/*
 * Task @p has been queued to the scheduler.
 */
void BPF_STRUCT_OPS(vder_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p);
	int node = scx_bpf_cpu_node(cpu);

	/*
	 * Attempt to dispatch the task directly on its assigned CPU.
	 */
	if (try_direct_dispatch(p, enq_flags))
		return;

	/*
	 * Queue the task to the shared DSQ.
	 */
	scx_bpf_dsq_insert(p, node, NSEC_PER_MSEC, enq_flags);

	/*
	 * Try to proactively wake up an idle CPU, so that it can
	 * immediately execute the task in case its current CPU is busy.
	 */
	kick_idle_cpu(p);
}

void BPF_STRUCT_OPS(vder_dispatch, s32 cpu, struct task_struct *prev)
{
	int node = scx_bpf_cpu_node(cpu);

	scx_bpf_dsq_move_to_local(node);
}

void BPF_STRUCT_OPS(vder_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
	 * When a CPU is taken by a higher priority scheduler class,
	 * re-enqueue all the tasks that are waiting in the local DSQ, so
	 * that we can give them a chance to run on another CPU.
	 */
	scx_bpf_reenqueue_local();
}

s32 BPF_STRUCT_OPS_SLEEPABLE(vder_init)
{
	int node;

	bpf_for(node, 0, NR_NODES) {
		int ret = scx_bpf_create_dsq(node, -1);
		if (ret)
			return ret;
	}

	return 0;
}

void BPF_STRUCT_OPS(vder_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(vder_ops,
	       .enqueue			= (void *)vder_enqueue,
	       .dispatch		= (void *)vder_dispatch,
	       .cpu_release		= (void *)vder_cpu_release,
	       .init			= (void *)vder_init,
	       .exit			= (void *)vder_exit,
	       // .flags			= SCX_OPS_BUILTIN_IDLE_PER_NODE | SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .flags			= SCX_OPS_BUILTIN_IDLE_PER_NODE,
	       .timeout_ms		= 5000,
	       .name			= "vder");
