/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include "scx_cosmos.h"

#define CLOCK_MONOTONIC		1

/*
 * Subset of CPUs to prioritize.
 */
private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * the CPU).
 */
const volatile bool primary_all = true;

/*
 * Default time slice.
 */
const volatile u64 slice_ns = 10000ULL;

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static u64 nr_cpu_ids;

/*
 * Timer used to defer idle CPU wakeups.
 *
 * Instead of triggering wake-up events directly from hot paths, such as
 * ops.enqueue(), idle CPUs are kicked using the wake-up timer.
 */
struct wakeup_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct wakeup_timer);
} wakeup_timer SEC(".maps");

/*
 * Pick an optimal idle CPU for task @p (as close as possible to @prev_cpu).
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);
	s32 cpu;

	/*
	 * If a primary domain is defined, try to pick an idle CPU from
	 * there first.
	 */
	if (!primary_all && mask) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, mask, 0);
		if (cpu >= 0)
			return cpu;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Initialize a new cpumask, return 0 in case of success or a negative
 * value otherwise.
 */
static int init_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *mask;

	mask = *p_cpumask;
	if (mask)
		return 0;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	mask = bpf_kptr_xchg(p_cpumask, mask);
	if (mask)
		bpf_cpumask_release(mask);

	return *p_cpumask ? 0 : -ENOMEM;
}

/*
 * Called from user-space to add CPUs to the the primary domain.
 */
SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask)
		bpf_cpumask_set_cpu(input->cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Kick idle CPUs with pending tasks.
 */
static int wakeup_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;
	int err;

	/*
	 * Iterate over all CPUs and wake up those that have pending tasks
	 * in their local DSQ.
	 *
	 * Note that tasks are only enqueued in ops.enqueue(), but we never
	 * wake-up the CPUs from there to reduce locking contention and
	 * overhead in the hot path.
         */
	bpf_for(cpu, 0, nr_cpu_ids)
		if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu))
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	err = bpf_timer_start(timer, slice_ns, 0);
	if (err)
		scx_bpf_error("Failed to re-arm duty cycle timer");

	return 0;
}

s32 BPF_STRUCT_OPS(cosmos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	/*
	 * Try to find an idle CPU and dispatch the task directly to the
	 * target CPU.
	 *
	 * Since we only use local DSQs, there's no reason to bounce the
	 * task to ops.enqueue(). Dispatching directly from here, even if
	 * we can't find an idle CPU, allows to save some locking overhead.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);

	return cpu < 0 ? prev_cpu : cpu;
}

void BPF_STRUCT_OPS(cosmos_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;

	/*
	 * Attempt a migration on wakeup or if the task was re-enqueued due
	 * to a higher scheduling class stealing the CPU it was queued on.
	 */
	if (!scx_bpf_task_running(p) || (enq_flags & SCX_ENQ_REENQ)) {
		if (!is_pcpu_task(p)) {
			cpu = pick_idle_cpu(p, prev_cpu, 0);
			if (cpu >= 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
						   slice_ns, enq_flags);
				return;
			}
		}
	}

	/*
	 * Keep using the same CPU while the task is running or if the
	 * system is saturated.
	 */
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
}

void BPF_STRUCT_OPS(cosmos_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * If the previous task expired its time slice, but no other task
	 * wants to run on this CPU, allow the previous task to run for
	 * another time slot.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = slice_ns;
}

void BPF_STRUCT_OPS(cosmos_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
	 * A higher scheduler class stole the CPU, re-enqueue all the tasks
	 * that are waiting on this CPU and give them a chance to pick
	 * another idle CPU.
	 */
	scx_bpf_reenqueue_local();
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cosmos_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	timer = bpf_map_lookup_elem(&wakeup_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup wakeup timer");
		return -ESRCH;
	}

	bpf_timer_init(timer, &wakeup_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, wakeup_timerfn);

	err = bpf_timer_start(timer, slice_ns, 0);
	if (err) {
		scx_bpf_error("Failed to arm wakeup timer");
		return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cosmos_ops,
	       .select_cpu		= (void *)cosmos_select_cpu,
	       .enqueue			= (void *)cosmos_enqueue,
	       .dispatch		= (void *)cosmos_dispatch,
	       .cpu_release		= (void *)cosmos_cpu_release,
	       .init			= (void *)cosmos_init,
	       .exit			= (void *)cosmos_exit,
               .flags			= SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ENQ_LAST |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .name			= "cosmos");
