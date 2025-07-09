/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include "scx_cosmos.h"

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define CLOCK_MONOTONIC		1

#define SHARED_DSQ		0

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

/*
 * User CPU utilization threshold to determine when the system is busy.
 */
const volatile u64 busy_threshold;

/*
 * Current global CPU utilization percentage in the range [0 .. 1024].
 */
volatile u64 cpu_util;

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static u64 nr_cpu_ids;

static u64 vtime_now;

/*
 * Per-task context.
 */
struct task_ctx {
	u64 last_run_at;
	u64 exec_runtime;
	u64 vtime;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

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
 * Pick an optimal idle CPU for task @p (as close as possible to
 * @prev_cpu).
 *
 * Return the CPU id or a negative value if an idle CPU can't be found.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool from_enqueue)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);
	s32 cpu;

	/*
	 * Fallback to the old API if the kernel doesn't support
	 * scx_bpf_select_cpu_and().
	 */
	if (!bpf_ksym_exists(scx_bpf_select_cpu_and)) {
		bool is_idle = false;

		if (from_enqueue)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

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
 *
 * Instead of waking up CPU when tasks are enqueued, we defer the wakeup
 * using this timer handler, in order to have a faster enqueue hot path.
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

	/*
	 * Re-arm the wakeup timer.
	 */
	err = bpf_timer_start(timer, slice_ns, 0);
	if (err)
		scx_bpf_error("Failed to re-arm duty cycle timer");

	return 0;
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 * The goal is to limit how much virtual time budget a sleeping task can
 * accumulate.
 *
 * This budget is:
 *   - proportional to the task's weight (heavier tasks get more),
 *   - inversely proportional to the amount of CPU time the task has
 *     accumulated since it last slept (exec_runtime).
 *
 * As a result:
 *   - tasks that sleep often are rewarded with a longer budget,
 *   - CPU-bound tasks accumulate less budget.
 *
 * Then the vruntime is clamped to a minimum value using this budget,
 * preventing it from falling too far behind to avoid starvation and
 * preserving fairness over time.
 */
static u64 task_dl(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 vsleep_max = scale_by_task_weight(p, SCX_SLICE_DFL - tctx->exec_runtime);
	u64 vtime_min = vtime_now - vsleep_max;

	if (time_before(tctx->vtime, vtime_min))
		tctx->vtime = vtime_min;

	return tctx->vtime;
}

/*
 * Return a time slice scaled by the task's weight.
 */
static u64 task_slice(const struct task_struct *p)
{
	return scale_by_task_weight(p, slice_ns);
}

/*
 * Return true if the system is busy, false otherwise. This function
 * determines when the scheduler needs to switch to deadline-mode (using a
 * single shared DSQ) vs round-robin mode (using per-CPU DSQs).
 */
static bool is_system_busy(void)
{
	return cpu_util >= busy_threshold;
}

/*
 * Return true if we should attempt a task migration to an idle CPU, false
 * otherwise.
 */
static bool need_migrate(const struct task_struct *p, u64 enq_flags)
{
	/*
	 * Per-CPU tasks are not allowed to migrate.
	 */
	if (is_pcpu_task(p))
		return false;

	/*
	 * Attempt a migration on wakeup (if ops.select_cpu() was skipped)
	 * or if the task was re-enqueued due to a higher scheduling class
	 * stealing the CPU it was queued on.
	 */
	return (!__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p)) ||
	       (enq_flags & SCX_ENQ_REENQ);
}

s32 BPF_STRUCT_OPS(cosmos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	s32 cpu;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	/*
	 * Try to find an idle CPU and dispatch the task directly to the
	 * target CPU.
	 *
	 * Since we only use local DSQs, there's no reason to bounce the
	 * task to ops.enqueue(). Dispatching directly from here, even if
	 * we can't find an idle CPU, allows to save some locking overhead.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, false);
	if (cpu >= 0 || !is_system_busy())
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);

	return cpu >= 0 ? cpu : prev_cpu;
}

void BPF_STRUCT_OPS(cosmos_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Attempt to dispatch directly to an idle CPU if the task can
	 * migrate.
	 */
	if (need_migrate(p, enq_flags)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0, true);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p), enq_flags);
			return;
		}
	}

	/*
	 * Keep using the same CPU while the task is running or if the
	 * system is saturated.
	 */
	if (!is_system_busy()) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
		return;
	}
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, task_slice(p), task_dl(p, tctx), enq_flags);
}

void BPF_STRUCT_OPS(cosmos_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Check if the there's any task waiting in the shared DSQ and
	 * dispatch.
	 */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;

	/*
	 * If the previous task expired its time slice, but no other task
	 * wants to run on this CPU, allow the previous task to run for
	 * another time slot.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = task_slice(prev);
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

void BPF_STRUCT_OPS(cosmos_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Reset exec runtime (accumulated execution time since last
	 * sleep).
	 */
	tctx->exec_runtime = 0;
}

void BPF_STRUCT_OPS(cosmos_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = scx_bpf_now();

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, tctx->vtime))
		vtime_now = tctx->vtime;
}

void BPF_STRUCT_OPS(cosmos_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the used time slice.
	 */
	slice = MIN(scx_bpf_now() - tctx->last_run_at, SCX_SLICE_DFL);

	/*
	 * Update the vruntime and the total accumulated runtime since last
	 * sleep.
	 *
	 * Cap the maximum accumulated time since last sleep to
	 * SCX_SLICE_DFL, to prevent starving CPU-intensive tasks.
	 */
	tctx->vtime += scale_by_task_weight_inverse(p, slice);
	tctx->exec_runtime = MIN(tctx->exec_runtime + slice, SCX_SLICE_DFL);
}

s32 BPF_STRUCT_OPS(cosmos_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cosmos_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	err = scx_bpf_create_dsq(SHARED_DSQ, 0);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

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
	       .runnable		= (void *)cosmos_runnable,
	       .running			= (void *)cosmos_running,
	       .stopping		= (void *)cosmos_stopping,
	       .cpu_release		= (void *)cosmos_cpu_release,
	       .init_task		= (void *)cosmos_init_task,
	       .init			= (void *)cosmos_init,
	       .exit			= (void *)cosmos_exit,
	       .timeout_ms		= 5000,
	       .name			= "cosmos");
