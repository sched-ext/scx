/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include "intf.h"

#define MAX_CPUS		1024

extern unsigned CONFIG_HZ __kconfig;

enum {
	SHARED_DSQ		= 0,
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

const volatile u32 nr_cpu_ids;
const volatile bool smt_enabled;
const volatile u64 slice_ns;
const volatile u64 tick_freq;

/*
 * CPUs sorted by their capacity in descendent order.
 */
const volatile u64 preferred_cpus[MAX_CPUS];

/*
 * Scheduling statistics.
 */
volatile u64 nr_ticks, nr_preemptions;
volatile u64 nr_direct_dispatches, nr_timer_dispatches, nr_primary_dispatches;

struct cpu_ctx {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, MAX_CPUS);
} cpu_ctx_stor SEC(".maps");

struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	return bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
}

/*
 * CPUs assigned to handle scheduling events.
 */
private(TICKLESS) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Return true if the target @cpu is a primary CPU (dedicated to process
 * scheduling events), false otherwise.
 */
static bool is_primary_cpu(s32 cpu)
{
	const struct cpumask *primary;
	bool ret;

	bpf_rcu_read_lock();
	primary = cast_mask(primary_cpumask);
	if (!primary) {
		scx_bpf_error("Primary CPUs not initialized");
		ret = false;
	} else {
		ret = bpf_cpumask_test_cpu(cpu, primary);
	}
	bpf_rcu_read_unlock();

	return ret;
}

/*
 * Return a random CPU from the pool of CPUs dedicated to process
 * scheduling events.
 */
static s32 pick_primary_cpu(void)
{
	const struct cpumask *primary;

	primary = cast_mask(primary_cpumask);
	if (!primary) {
		scx_bpf_error("Primary CPUs not initialized");
		return -ENOENT;
	}
	return bpf_cpumask_any_distribute(primary);
}

/*
 * Per-task context.
 */
struct task_ctx {
	/*
	 * Timestamp (in ns) when the task ran last time.
	 */
	u64 last_run_at;

	/*
	 * Sum of the task's runtime from when it becomes runnable (ready
	 * to run on a CPU) to when the task voluntarily releases the CPU
	 * (either by completing its execution or waiting for an event).
	 */
	u64 exec_runtime;

	/*
	 * Task's deadline, defined as:
	 *
	 *   deadline = vruntime + exec_vruntime
	 *
	 * Here, vruntime represents the task's total runtime, scaled inversely by
	 * its weight, while exec_vruntime accounts for the vruntime accumulated
	 * from the moment the task becomes runnable until it voluntarily releases
	 * the CPU.
	 *
	 * Fairness is ensured through vruntime, whereas exec_vruntime helps in
	 * prioritizing latency-sensitive tasks: tasks that are frequently blocked
	 * waiting for an event (typically latency sensitive) will accumulate a
	 * smaller exec_vruntime, compared to tasks that continuously consume CPU
	 * without interruption.
	 *
	 * As a result, tasks with a smaller exec_vruntime will have a shorter
	 * deadline and will be dispatched earlier, ensuring better responsiveness
	 * for latency-sensitive tasks.
	 */
	u64 deadline;
};

/*
 * BPF map to store the context of each task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return the context of @p, or NULL if the task doesn't exist.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

/*
 * Keep track of the current global vruntime.
 *
 * The vuntime is defined as the task's runtime inversely scaled using the
 * task's weight (priority).
 */
static u64 vtime_now;

/*
 * Update and return the task's deadline.
 */
static u64 task_deadline(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 vtime_min;

	/*
	 * Limit the amount of vtime budget that an idling task can
	 * accumulate to prevent excessive prioritization of sleeping
	 * tasks.
	 *
	 * Tasks with a higher weight get a bigger "bucket" for their
	 * allowed accumulated time budget.
	 */
	vtime_min = vtime_now - slice_ns;
	if (time_before(tctx->deadline, vtime_min))
		tctx->deadline = vtime_min;

	/*
	 * Add the execution vruntime to the deadline.
	 */
	return tctx->deadline + scale_by_task_weight_inverse(p, tctx->exec_runtime);
}

/*
 * Return the time interval between two ticks in ns.
 */
static inline u64 tick_interval_ns(void)
{
	u64 freq = tick_freq ? : CONFIG_HZ;

	return NSEC_PER_SEC / freq;
}

/*
 * Return true if the waker commits to release the CPU after waking up @p,
 * false otherwise.
 */
static bool is_wake_sync(u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();

	return (wake_flags & SCX_WAKE_SYNC) && !(current->flags & PF_EXITING);
}

s32 BPF_STRUCT_OPS(tickless_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	/*
	 * Consider sync wakeups almost like a function call and try to route
	 * the wakee to the waker's CPU.
	 */
	if (is_wake_sync(wake_flags))
		return bpf_get_smp_processor_id();

	/*
	 * Always route wakeups to a CPU from the primary group to minimize
	 * noise on the other CPUs.
	 *
	 * Also make sure to lock the selected CPU, so that it's not picked
	 * when distributing tasks in dispatch_all_cpus().
	 */
	cpu = pick_primary_cpu();
	scx_bpf_test_and_clear_cpu_idle(cpu);

	return cpu;
}

void BPF_STRUCT_OPS(tickless_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 deadline;

	/*
	 * Insert the task to the shared queue.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	deadline = task_deadline(p, tctx);
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_INF, deadline, enq_flags);
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Try to consume a task from the shared queue and dispatch on a target
 * @cpu.
 *
 * Return true if a task was dispatched, false otherwise.
 */
static bool dispatch_cpu(s32 cpu, bool from_dispatch)
{
	struct task_struct *p;
	bool dispatched = false;

	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, SHARED_DSQ, 0) {
		 /*
		  * This is a workaround for the BPF verifier's pointer
		  * validation limitations. Once the verifier gets smarter
		  * we can remove this bpf_task_from_pid().
                  */
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}

		/*
		 * If there's an eligible task in the SHARED_DSQ that can
		 * run on this CPU, clear the CPU's idle state and dispatch
		 * the task. Otherwise, immediately give up and move to the
		 * next CPU, since the goal is to avoid contention as much
		 * as possible, so that tasks can keep using their infinite
		 * time slice.
		 *
		 * However, if the first eligible task in the SHARED_DSQ is
		 * a per-CPU task, dispatch it regardless of the CPU's idle
		 * state, since contention is unavoidable in this case (the
		 * task can only run on this CPU). Then the currently
		 * running task will be made preemptible by the BPF timer,
		 * changing its time slice from SCX_SLICE_INF to a finite
		 * slice_ns.
		 *
		 * In this way we can still minimize CPU contention without
		 * introducing starvation for per-CPU tasks.
		 */
		if (!scx_bpf_test_and_clear_cpu_idle(cpu) && !is_pcpu_task(p)) {
			bpf_task_release(p);
			break;
		}

		if (!__COMPAT_scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL_ON | cpu, 0)) {
			bpf_task_release(p);
			continue;
		}
		if (from_dispatch)
			__sync_fetch_and_add(&nr_primary_dispatches, 1);
		else
			__sync_fetch_and_add(&nr_timer_dispatches, 1);
		dispatched = true;

		bpf_task_release(p);

		break;
	}
	bpf_rcu_read_unlock();

	return dispatched;
}

/*
 * Consume tasks from the shared queue and distribute them evenly across
 * the available CPUs.
 *
 * If @do_idle_smt is true, consider only full-idle SMT cores.
 *
 * If @from_dispatch is true, the function is called from ops.dispatch()
 * (used to check if we have enough dispatch slots available).
 */
static bool dispatch_all_cpus(bool do_idle_smt, bool from_dispatch)
{
	const struct cpumask *mask;
	s32 i, cpu;
	bool is_done = false;

	if (!scx_bpf_dsq_nr_queued(SHARED_DSQ))
		return true;

	if (!smt_enabled & do_idle_smt)
		return false;

	mask = do_idle_smt ? scx_bpf_get_idle_smtmask() : NULL;

	bpf_for(i, 0, MIN(nr_cpu_ids, MAX_CPUS)) {
		/*
		 * Try to lock the first idle CPU available and attempt to
		 * dispatch a task.
		 */
		cpu = preferred_cpus[i];
		if ((mask && !bpf_cpumask_test_cpu(cpu, mask)))
			continue;

		/*
		 * Wakeup the selected CPU, if no task is dispatched the CPU
		 * will automatically reset its idle state.
		 */
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

		/*
		 * Do not distribute tasks to the primary CPUs, keep them
		 * as a last resort.
		 */
		if (is_primary_cpu(cpu))
			continue;

		/*
		 * Consume a task from the shared DSQ and dispatch it to
		 * the target CPU.
		 */
		dispatch_cpu(cpu, from_dispatch);

		/*
		 * Stop dispatching if all the pending tasks have been
		 * distributed.
		 */
		if (!scx_bpf_dsq_nr_queued(SHARED_DSQ)) {
			is_done = true;
			break;
		}
	}

	if (mask)
		scx_bpf_put_cpumask(mask);

	return is_done;
}

static int sched_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;

	/*
	 * Dispatch tasks on the available CPUs.
	 */
	if (!dispatch_all_cpus(true, false))
		dispatch_all_cpus(false, false);

	/*
	 * Check if we need to preempt the running tasks.
	 */
	bpf_rcu_read_lock();
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct task_struct *p = __COMPAT_scx_bpf_cpu_curr(cpu);

		/*
		 * Ignore CPU if idle task is running.
		 */
		if (!p || p->flags & PF_IDLE)
			continue;

		/*
		 * Ignore CPUs without any task waiting.
		 */
		if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) &&
		    !scx_bpf_dsq_nr_queued(SHARED_DSQ))
			continue;

		/*
		 * Set a finite time slice to the running task, so that it
		 * can be preempted.
		 */
		if (p->scx.slice == SCX_SLICE_INF) {
			p->scx.slice = slice_ns;
			__sync_fetch_and_add(&nr_preemptions, 1);
		}
	}
	bpf_rcu_read_unlock();

	bpf_timer_start(timer, tick_interval_ns(), 0);

	return 0;
}

/*
 * Start the BPF timer on a target CPU.
 */
static void init_timer(s32 cpu)
{
	struct cpu_ctx *cctx;
	int ret;

	if (!is_primary_cpu(cpu))
		scx_bpf_error("starting timer on cpu%d, which is not a scheduling CPU", cpu);

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	bpf_timer_init(&cctx->timer, &cpu_ctx_stor, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&cctx->timer, sched_timerfn);

	ret = bpf_timer_start(&cctx->timer, tick_interval_ns(), 0);
	if (ret)
		scx_bpf_error("failed to fire up timer on cpu%d: %d", cpu, ret);
}

void BPF_STRUCT_OPS(tickless_dispatch, s32 cpu, struct task_struct *prev)
{
	if (is_primary_cpu(cpu)) {
		/*
		 * Try to bounce all the queued tasks to the available
		 * tickless CPUs first.
		 */
		if (!dispatch_all_cpus(true, true))
			dispatch_all_cpus(false, true);
	}

	/*
	 * Consume a task from the shared DSQ.
	 *
	 * This applies also to primary CPUs: if there are still tasks in
	 * the shared DSQ after distributing them to the tickless CPUs,
	 * primary CPUs will also start consuming them.
	 */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}

	/*
	 * Keep running the previous task if it still wants to run.
	 */
	if (prev && prev->scx.flags & SCX_TASK_QUEUED)
		prev->scx.slice = SCX_SLICE_INF;
}

/*
 * Task @p is ready to run.
 */
void BPF_STRUCT_OPS(tickless_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Reset the execution runtime, as we are starting the task either
	 * from the beginning of its lifetime or after it has been blocked.
	 */
	tctx->exec_runtime = 0;
}

/*
 * Task @p is about to start running on a CPU.
 */
void BPF_STRUCT_OPS(tickless_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Update the run timestamp (used to evaluate the used time slice).
	 */
	tctx->last_run_at = scx_bpf_now();

	/*
	 * Update the global vruntime as a new task is starting to use a
	 * CPU.
	 */
	if (time_before(vtime_now, tctx->deadline))
		vtime_now = tctx->deadline;
}

void BPF_STRUCT_OPS(tickless_tick, struct task_struct *p)
{
	__sync_fetch_and_add(&nr_ticks, 1);
}

/*
 * Task @p is about to release the CPU.
 */
void BPF_STRUCT_OPS(tickless_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the time slice used by the task.
	 */
	slice = scx_bpf_now() - tctx->last_run_at;

	/*
	 * Update task's execution time (exec_runtime), but never account
	 * more than 1s of runtime to prevent excessive de-prioritization
	 * of CPU-intensive tasks (which could lead to starvation).
	 */
	if (tctx->exec_runtime < NSEC_PER_SEC)
		tctx->exec_runtime += slice;

	/*
	 * Update task's vruntime.
	 */
	tctx->deadline += scale_by_task_weight_inverse(p, slice);
}

/*
 * Task @p is entering the BPF scheduler.
 */
void BPF_STRUCT_OPS(tickless_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Initialize the task vruntime to the current global vruntime.
	 */
	tctx->deadline = vtime_now;
}

/*
 * Task @p is created.
 */
s32 BPF_STRUCT_OPS(tickless_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

/*
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

/*
 * Initialize a cpumask (if not already initialized).
 */
static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/*
	 * Do nothing if the mask is already initialized.
	 */
	mask = *cpumask;
	if (mask)
		return 0;

	/*
	 * Create the CPU mask.
	 */
	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
}

/*
 * Add a CPU to the pool of CPUs dedicated to process scheduling
 * events.
 *
 * If the target CPU is a negative value, clear the whole mask (this can be
 * used to reset the primary group).
 */
SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	s32 cpu = input->cpu_id;
	int ret;

	ret = init_cpumask(&primary_cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();

	mask = primary_cpumask;
	if (mask) {
		if (cpu < 0)
			bpf_cpumask_clear(mask);
		else
			bpf_cpumask_set_cpu(cpu, mask);
	}

	bpf_rcu_read_unlock();

	return ret;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(tickless_init)
{
	int ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret < 0)
		return ret;

	init_timer(bpf_get_smp_processor_id());

	return 0;
}

void BPF_STRUCT_OPS(tickless_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(tickless_ops,
	       .select_cpu		= (void *)tickless_select_cpu,
	       .enqueue			= (void *)tickless_enqueue,
	       .dispatch		= (void *)tickless_dispatch,
	       .runnable		= (void *)tickless_runnable,
	       .running			= (void *)tickless_running,
	       .tick			= (void *)tickless_tick,
	       .stopping		= (void *)tickless_stopping,
	       .enable			= (void *)tickless_enable,
	       .init_task		= (void *)tickless_init_task,
	       .init			= (void *)tickless_init,
	       .exit			= (void *)tickless_exit,
	       .timeout_ms		= 5000,
	       .name			= "tickless");
