/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A scheduler that periodically shuts down operation to accommodate the power
 * constraints of an embedded device.
 *
 * This scheduler has no topology awareness, and assumes that the whole system
 * operates from a single LLC.
 *
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

enum {
	SHARED_DSQ		= 0,
	MSEC_PER_SEC		= 1000LLU,
	USEC_PER_MSEC		= 1000LLU,
	NSEC_PER_USEC		= 1000LLU,
	NSEC_PER_MSEC		= USEC_PER_MSEC * NSEC_PER_USEC,
	USEC_PER_SEC		= USEC_PER_MSEC * MSEC_PER_SEC,
	NSEC_PER_SEC		= NSEC_PER_USEC * USEC_PER_SEC,
};

#define CLOCK_BOOTTIME 7
#define NUMA_NO_NODE -1

/* Read-only variables set during scheduler init */
const volatile u32 nr_cpu_ids;
const volatile u64 slice_ns = 1 * NSEC_PER_MSEC;
const volatile u64 dcycle_run_ns = 8 * NSEC_PER_MSEC;
const volatile u64 dcycle_idle_ns = 14 * NSEC_PER_MSEC;

/* Dynamic variables that can change at runtime */
static u64 in_work_mode = 1;
static u64 generation;

static u64 vtime_now;
UEI_DEFINE(uei);

struct dcycle_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct dcycle_timer);
} dcycle_timer SEC(".maps");

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static s32 try_dispatch_local(struct task_struct *p, s32 prev_cpu, u64 flags)
{
	u64 curr_gen = __sync_fetch_and_add(&generation, 0);
	bool running = !!__sync_fetch_and_add(&in_work_mode, 0);
	s32 cpu = prev_cpu;

	if (!running)
		return -ENOENT;

	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			goto dispatch_check_gen;
	}

	if (p->nr_cpus_allowed == 1)
		return -ENOENT;

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		goto dispatch_check_gen;

	return -ENOENT;

dispatch_check_gen:
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu, slice_ns, flags);
	/*
	 * If generation number has progressed then the timer has run and we
	 * need to ensure that the resched path happens again so we don't
	 * accidentally run a task we shouldn't. This guarantees that either
	 * us, or the timer callback, will cause all CPUs to be preempted.
	 */
	if (__sync_fetch_and_add(&generation, 0) > curr_gen) {
		p->scx.slice = 0;
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	}
	return cpu;
}

s32 BPF_STRUCT_OPS(joule_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	cpu = try_dispatch_local(p, prev_cpu, wake_flags);
	if (cpu < 0)
		cpu = prev_cpu;

	return cpu;
}

void BPF_STRUCT_OPS(joule_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 vtime = p->scx.dsq_vtime;
	s32 prev_cpu = scx_bpf_task_cpu(p);
	s32 cpu;

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (vtime_before(vtime, vtime_now - slice_ns))
		vtime = vtime_now - slice_ns;

	cpu = try_dispatch_local(p, prev_cpu, enq_flags);

	if (cpu < 0)
		scx_bpf_dispatch_vtime(p, SHARED_DSQ, slice_ns, vtime, enq_flags);
}

void BPF_STRUCT_OPS(joule_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 curr_gen = __sync_fetch_and_add(&generation, 0);

	if (!__sync_fetch_and_add(&in_work_mode, 0))
		return;

	scx_bpf_consume(SHARED_DSQ);
	/*
	 * Same as in the direct dispatch path, let's make sure we kick the CPU
	 * if we're transitioning into idle mode to avoid doing excess work.
	 */
	if (__sync_fetch_and_add(&generation, 0) > curr_gen)
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
}

void BPF_STRUCT_OPS(joule_running, struct task_struct *p)
{
	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(joule_stopping, struct task_struct *p, bool runnable)
{
	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(joule_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

static int dcycle_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	bool disabling = __sync_fetch_and_add(&in_work_mode, 0);
	s32 cpu;
	u64 flags, duration;
	int err;

	if (disabling) {
		__sync_fetch_and_add(&in_work_mode, -1);
		/*
		 * SCX_KICK_PREEMPT will only send resched IPIs to non-idle
		 * CPUs that need to be preempted
		 */
		flags = SCX_KICK_PREEMPT;
		duration = dcycle_idle_ns;
	} else {
		__sync_fetch_and_add(&in_work_mode, 1);
		/* SCX_KICK_IDLE will only send resched IPIs to idle CPUs */
		flags = SCX_KICK_IDLE;
		duration = dcycle_run_ns;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		scx_bpf_kick_cpu(cpu, flags);
	}

	__sync_fetch_and_add(&generation, 1);
	err = bpf_timer_start(timer, duration, 0);
	if (err)
		scx_bpf_error("Failed to re-arm dcycle timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(joule_init)
{
	struct bpf_timer *timer;
	int err;
	u32 key = 0;

	timer = bpf_map_lookup_elem(&dcycle_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup dcycle timer");
		return -ESRCH;
	}

	bpf_timer_init(timer, &dcycle_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, dcycle_timerfn);
	err = bpf_timer_start(timer, dcycle_run_ns, 0);
	if (err) {
		scx_bpf_error("Failed to arm dcycle timer");
		return err;
	}

	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(joule_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(joule_ops,
	       .select_cpu		= (void *)joule_select_cpu,
	       .enqueue			= (void *)joule_enqueue,
	       .dispatch		= (void *)joule_dispatch,
	       .running			= (void *)joule_running,
	       .stopping		= (void *)joule_stopping,
	       .enable			= (void *)joule_enable,
	       .init			= (void *)joule_init,
	       .exit			= (void *)joule_exit,
	       .name			= "joule");
