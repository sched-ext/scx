/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_vder: Virtual Deadline with Execution Runtime.
 *
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>

extern unsigned CONFIG_HZ __kconfig;

enum {
	SHARED_DSQ		= 0,
	FALLBACK_DSQ		= 1,
	MSEC_PER_SEC		= 1000LLU,
	USEC_PER_MSEC		= 1000LLU,
	NSEC_PER_USEC		= 1000LLU,
	NSEC_PER_MSEC		= USEC_PER_MSEC * NSEC_PER_USEC,
	USEC_PER_SEC		= USEC_PER_MSEC * MSEC_PER_SEC,
	NSEC_PER_SEC		= NSEC_PER_USEC * USEC_PER_SEC,
};

char _license[] SEC("license") = "GPL";

/*
 * Define struct user_exit_info which is shared between BPF and userspace
 * to communicate the exit status.
 */
UEI_DEFINE(uei);

const volatile u32 nr_cpu_ids = 1;
const volatile s32 central_cpu;
const volatile u64 slice_ns;
const volatile u64 config_hz;

struct {
        __uint(type, BPF_MAP_TYPE_QUEUE);
        __uint(max_entries, 4096);
        __type(value, s32);
} central_q SEC(".maps");

bool RESIZABLE_ARRAY(data, idle_cpus);
u64 RESIZABLE_ARRAY(data, cpu_started_at);

struct sched_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct sched_timer);
} sched_timer SEC(".maps");

static inline u64 tick_ns(void)
{
	return NSEC_PER_SEC / (config_hz ? : CONFIG_HZ);
}

static bool try_direct_dispatch(struct task_struct *p, u64 enq_flags)
{
	if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
				   enq_flags | SCX_ENQ_PREEMPT);
		return true;
	}

	return false;
}

s32 BPF_STRUCT_OPS(vder_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	/*
	 * Route wakeups to the central CPU to minimize noise on the other
	 * CPUs.
	 */
	return central_cpu;
}

void BPF_STRUCT_OPS(vder_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid = p->pid;

	/*
	 * Attempt to dispatch the task directly on its assigned CPU.
	 */
	if (try_direct_dispatch(p, enq_flags))
		return;

	/*
	 * Push the task to the central queue.
	 */
	if (bpf_map_push_elem(&central_q, &pid, 0)) {
		scx_bpf_dsq_insert(p, FALLBACK_DSQ, SCX_SLICE_INF, enq_flags);
		return;
	}

	/*
	 * Trigger a resched when a task is successfully enqueued.
	 */
	scx_bpf_kick_cpu(central_cpu, SCX_KICK_PREEMPT);
}

static bool dispatch_to_cpu(s32 cpu)
{
	struct task_struct *p;
	s32 pid;

	bpf_repeat(BPF_MAX_LOOPS) {
		if (bpf_map_pop_elem(&central_q, &pid))
			break;

		p = bpf_task_from_pid(pid);
		if (!p)
			continue;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			scx_bpf_dsq_insert(p, FALLBACK_DSQ, SCX_SLICE_INF, 0);
			bpf_task_release(p);

			if (!scx_bpf_dispatch_nr_slots())
				break;
			continue;
		}

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, 0);
		bpf_task_release(p);

		if (cpu != central_cpu)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

		return true;
	}

	return false;
}

void BPF_STRUCT_OPS(vder_dispatch, s32 cpu, struct task_struct *prev)
{
	if (cpu == central_cpu) {
		bpf_for(cpu, 0, nr_cpu_ids) {
			bool *idle;

			if (cpu == central_cpu)
				continue;

			if (!scx_bpf_dispatch_nr_slots())
				break;

			idle = ARRAY_ELEM_PTR(idle_cpus, cpu, nr_cpu_ids);
			if (!idle || !*idle)
				continue;

			if (dispatch_to_cpu(cpu))
				*idle = false;
		}

		if (!scx_bpf_dispatch_nr_slots()) {
			scx_bpf_kick_cpu(central_cpu, SCX_KICK_PREEMPT);
			return;
		}

		if (scx_bpf_dsq_move_to_local(FALLBACK_DSQ))
			return;

		dispatch_to_cpu(central_cpu);
	} else {
		bool *idle;

		if (scx_bpf_dsq_move_to_local(FALLBACK_DSQ))
			return;

                idle = ARRAY_ELEM_PTR(idle_cpus, cpu, nr_cpu_ids);
                if (idle)
                        *idle = true;

		scx_bpf_kick_cpu(central_cpu, SCX_KICK_PREEMPT);
	}
}

/*
 * Task @p is about to start running on a CPU.
 */
void BPF_STRUCT_OPS(vder_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	u64 *started_at;

	started_at = ARRAY_ELEM_PTR(cpu_started_at, cpu, nr_cpu_ids);
	if (started_at)
		*started_at = scx_bpf_now() ? : 1;
}

/*
 * Task @p is about to release the CPU.
 */
void BPF_STRUCT_OPS(vder_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	u64 *started_at;

	started_at = ARRAY_ELEM_PTR(cpu_started_at, cpu, nr_cpu_ids);
	if (started_at)
		*started_at = 0;
}

static int sched_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = scx_bpf_now();
	s32 cpu, curr_cpu;

	curr_cpu = bpf_get_smp_processor_id();
	if (curr_cpu != central_cpu) {
		scx_bpf_error("Central timer ran on CPU %d, not central CPU %d",
			      curr_cpu, central_cpu);
		return 0;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		u64 *started_at;

		if (cpu == central_cpu)
			continue;

		started_at = ARRAY_ELEM_PTR(cpu_started_at, cpu, nr_cpu_ids);
		if (started_at && *started_at &&
		    time_before(now, *started_at + slice_ns))
			continue;

		if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) &&
		    !scx_bpf_dsq_nr_queued(FALLBACK_DSQ))
			continue;

		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	}

	bpf_timer_start(timer, tick_ns(), BPF_F_TIMER_CPU_PIN);

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(vder_init)
{
	u32 key = 0;
	struct bpf_timer *timer;
	int ret;

	timer = bpf_map_lookup_elem(&sched_timer, &key);
	if (!timer)
		return -ESRCH;

	if (bpf_get_smp_processor_id() != central_cpu) {
		scx_bpf_error("init from non-central CPU");
		return -EINVAL;
	}

	bpf_timer_init(timer, &sched_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, sched_timerfn);
	ret = bpf_timer_start(timer, tick_ns(), BPF_F_TIMER_CPU_PIN);
	if (ret) {
		scx_bpf_error("bpf_timer_start failed (%d)", ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;

	return scx_bpf_create_dsq(FALLBACK_DSQ, -1);
}

void BPF_STRUCT_OPS(vder_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(vder_ops,
	       .select_cpu		= (void *)vder_select_cpu,
	       .enqueue			= (void *)vder_enqueue,
	       .dispatch		= (void *)vder_dispatch,
	       .running			= (void *)vder_running,
	       .stopping		= (void *)vder_stopping,
	       .init			= (void *)vder_init,
	       .exit			= (void *)vder_exit,
	       .flags			= SCX_OPS_ENQ_LAST,
	       .timeout_ms		= 5000,
	       .name			= "vder");
