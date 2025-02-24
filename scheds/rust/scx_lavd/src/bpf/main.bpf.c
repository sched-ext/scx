/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_lavd: Latency-criticality Aware Virtual Deadline (LAVD) scheduler
 * =====================================================================
 *
 * LAVD is a new scheduling algorithm which is still under development. It is
 * motivated by gaming workloads, which are latency-critical and
 * communication-heavy. It aims to minimize latency spikes while maintaining
 * overall good throughput and fair use of CPU time among tasks.
 *
 *
 * 1. Overall procedure of the LAVD scheduler
 * ------------------------------------------
 *
 * LAVD is a deadline-based scheduling algorithm, so its overall procedure is
 * similar to other deadline-based scheduling algorithms. Under LAVD, a
 * runnable task has its time slice and virtual deadline. The LAVD scheduler
 * picks a task with the closest virtual deadline and allows it to execute for
 * the given time slice.
 *
 *
 * 2. Latency criticality: how to determine how latency-critical a task is
 * -----------------------------------------------------------------------
 *
 * The LAVD scheduler leverages how much latency-critical a task is in making
 * various scheduling decisions. For example, if the execution of Task A is not
 * latency critical -- i.e., the scheduling delay of Task A does not affect the
 * end performance much, a scheduler would defer the scheduling of Task A to
 * serve more latency-critical urgent tasks first.
 *
 * Then, how do we know if a task is latency-critical or not? One can ask a
 * developer to annotate the process/thread's latency criticality, for example,
 * using a latency nice interface. Unfortunately, that is not always possible,
 * especially when running existing software without modification.
 *
 * We leverage a task's communication and behavioral properties to quantify its
 * latency criticality. Suppose there are three tasks: Task A, B, and C, and
 * they are in a producer-consumer relation; Task A's completion triggers the
 * execution of Task B, and Task B's completion triggers Task C. Many
 * event-driven systems can be represented as task graphs.
 *
 *        [Task x] --> [Task B] --> [Task C]
 *
 * We define Task B is more latency-critical in the following cases: a) as Task
 * B's runtime per schedule is shorter (runtime B) b) as Task B wakes Task C
 * more frequently (wake_freq B) c) as Task B waits for Task A more frequently
 * (wait_freq B)
 *
 * Intuitively, if Task B's runtime per schedule is long, a relatively short
 * scheduling delay won't affect a lot; if Task B frequently wakes up Task C,
 * the scheduling delay of Task B also delays the execution of Task C;
 * similarly, if Task B often waits for Task A, the scheduling delay of Task B
 * delays the completion of executing the task graph.
 *
 *
 * 3. Virtual deadline: when to execute a task
 * -------------------------------------------
 *
 * The latency criticality of a task is used to determine task's virtual
 * deadline. A more latency-critical task will have a tighter (shorter)
 * deadline, so the scheduler picks such a task more urgently among runnable
 * tasks.
 *
 *
 * 4. Time slice: how long execute a task
 * --------------------------------------
 *
 * We borrow the time slice calculation idea from the CFS and scx_rustland
 * schedulers. The LAVD scheduler tries to schedule all the runnable tasks at
 * least once within a predefined time window, which is called a targeted
 * latency. For example, if a targeted latency is 15 msec and 10 tasks are
 * runnable, the scheduler equally divides 15 msec of CPU time into 10 tasks.
 * Of course, the scheduler will consider the task's priority -- a task with
 * higher priority (lower nice value) will receive a longer time slice.
 *
 * The scheduler also considers the behavioral properties of a task in
 * determining the time slice. If a task is compute-intensive, so it consumes
 * the assigned time slice entirely, the scheduler boosts such task's time
 * slice and assigns a longer time slice. Next, if a task is freshly forked,
 * the scheduler assigns only half of a regular time slice so it can make a
 * more educated decision after collecting the behavior of a new task. This
 * helps to mitigate fork-bomb attacks.
 *
 *
 * 5. Fairness: how to enforce the fair use of CPU time
 * ----------------------------------------------------
 *
 * Assigning a task's time slice per its priority does not guarantee the fair
 * use of CPU time. That is because a task can be more (or less) frequently
 * executed than other tasks or yield CPU before entirely consuming its
 * assigned time slice.
 *
 * The scheduler treats the over-scheduled (or ineligible) tasks to enforce the
 * fair use of CPU time. It defers choosing over-scheduled tasks to reduce the
 * frequency of task execution. The deferring time- ineligible duration- is
 * proportional to how much time is over-spent and added to the task's
 * deadline.
 *
 * 6. Preemption
 * -------------
 *
 * A task can be preempted (de-scheduled) before exhausting its time slice. The
 * scheduler uses two preemption mechanisms: 1) yield-based preemption and
 * 2) kick-based preemption.
 *
 * In every scheduler tick interval (when ops.tick() is called), the running
 * task checks if a higher priority task awaits execution in the global run
 * queue. If so, the running task shrinks its time slice to zero to trigger
 * re-scheduling for another task as soon as possible. This is what we call
 * yield-based preemption. In addition to the tick interval, the scheduler
 * additionally performs yield-based preemption when there is no idle CPU on
 * ops.select_cpu() and ops.enqueue(). The yield-based preemption takes the
 * majority (70-90%) of preemption operations in the scheduler.
 *
 * The kick-based preemption is to _immediately_ schedule an urgent task, even
 * paying a higher preemption cost. When a task is enqueued to the global run
 * queue (because no idle CPU is available), the scheduler checks if the
 * currently enqueuing task is urgent enough. The urgent task should be very
 * latency-critical (e.g., top 25%), and its latency priority should be very
 * high (e.g., 15). If the task is urgent enough, the scheduler finds a victim
 * CPU, which runs a lower-priority task, and kicks the remote victim CPU by
 * sending IPI. Then, the remote CPU will preempt out its running task and
 * schedule the highest priority task in the global run queue. The scheduler
 * uses 'The Power of Two Random Choices' heuristic so all N CPUs can run the N
 * highest priority tasks.
 *
 *
 * 7. Performance criticality
 * --------------------------
 *
 * We define the performance criticality metric to express how sensitive a task
 * is to CPU frequency. The more performance-critical a task is, the higher the
 * CPU frequency will be assigned. A task is more performance-critical in the
 * following conditions: 1) the task's runtime in a second is longer (i.e.,
 * task runtime x frequency), 2) the task's waiting or waken-up frequencies are
 * higher (i.e., the task is in the middle of the task chain).
 *
 *
 * 8. CPU frequency scaling
 * ------------------------
 *
 * Two factors determine the clock frequency of a CPU: 1) the current CPU
 * utilization and 2) the current task's CPU criticality compared to the
 * system-wide average performance criticality. This effectively boosts the CPU
 * clock frequency of performance-critical tasks even when the CPU utilization
 * is low.
 *
 * When actually changing the CPU's performance target, we should be able to
 * quickly capture the demand for spiky workloads while providing steady clock
 * frequency to avoid unexpected performance fluctuations. To this end, we
 * quickly increase the clock frequency when a task gets running but gradually
 * decrease it upon every tick interval.
 *
 *
 * 9. Core compaction
 * ------------------
 *
 * When system-wide CPU utilization is low, it is very likely all the CPUs are
 * running with very low utilization. All CPUs run with low clock frequency due
 * to dynamic frequency scaling, frequently going in and out from/to C-state.
 * That results in low performance (i.e., low clock frequency) and high power
 * consumption (i.e., frequent P-/C-state transition).
 *
 * The idea of *core compaction* is using less number of CPUs when system-wide
 * CPU utilization is low (say < 50%). The chosen cores (called "active cores")
 * will run in higher utilization and higher clock frequency, and the rest of
 * the cores (called "idle cores") will be in a C-state for a much longer
 * duration. Thus, the core compaction can achieve higher performance with
 * lower power consumption.
 *
 * One potential problem of core compaction is latency spikes when all the
 * active cores are overloaded. A few techniques are incorporated to solve this
 * problem. 1) Limit the active CPU core's utilization below a certain limit
 * (say 50%). 2) Do not use the core compaction when the system-wide
 * utilization is moderate (say 50%). 3) Do not enforce the core compaction for
 * kernel and pinned user-space tasks since they are manually optimized for
 * performance.
 *
 *
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/*
 * Include sub-modules
 */
#include "util.bpf.c"
#include "power.bpf.c"
#include "introspec.bpf.c"
#include "sys_stat.bpf.c"
#include "preempt.bpf.c"
#include "lock.bpf.c"

/*
 * Logical current clock
 */
static u64		cur_logical_clk;

/*
 * Current service time
 */
static u64		cur_svc_time;


/*
 * The minimum and maximum of time slice
 */
const volatile u64	slice_min_ns = LAVD_SLICE_MIN_NS_DFL;
const volatile u64	slice_max_ns = LAVD_SLICE_MAX_NS_DFL;

static u32 calc_greedy_ratio(struct task_ctx *taskc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u32 ratio;

	if (!have_scheduled(taskc)) {
		ratio = LAVD_GREEDY_RATIO_NEW;
		goto out;
	}

	/*
	 * The greedy ratio of a task represents how much time the task
	 * overspent CPU time compared to the ideal, fair CPU allocation. It is
	 * the ratio of task's actual service time to average service time in a
	 * system.
	 */
	ratio = (1000 * taskc->svc_time) / stat_cur->avg_svc_time;

out:
	taskc->is_greedy = ratio > 1000;
	return ratio;
}

static u32 calc_greedy_factor(u32 greedy_ratio)
{
	/*
	 * For all under-utilized tasks, we treat them equally.
	 */
	if (greedy_ratio <= 1000)
		return 1000;

	/*
	 * For over-utilized tasks, we give some mild penalty.
	 */
	return 1000 + ((greedy_ratio - 1000) / LAVD_LC_GREEDY_PENALTY);

}

static u64 calc_runtime_factor(u64 runtime, u64 weight_ft)
{
	u64 ft = rsigmoid_u64(runtime, LAVD_LC_RUNTIME_MAX);
	return (ft / weight_ft) + 1;
}

static u64 calc_freq_factor(u64 freq, u64 weight_ft)
{
	u64 ft = sigmoid_u64(freq, LAVD_LC_FREQ_MAX);
	return (ft * weight_ft * LAVD_LC_FREQ_OVER_RUNTIME) + 1;
}

static u64 calc_weight_factor(struct task_struct *p, struct task_ctx *taskc)
{
	u64 weight_boost = 1;
	u64 weight_ft;

	/*
	 * Prioritize a wake-up task since this is a clear sign of immediate
	 * consumer. If it is a synchronous wakeup, double the prioritization.
	 */
	weight_boost += taskc->wakeup_ft * LAVD_LC_WEIGHT_BOOST;

	/*
	 * Prioritize a kernel task since many kernel tasks serve
	 * latency-critical jobs.
	 */
	if (is_kernel_task(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST;

	/*
	 * Prioritize a migration-disabled task since it has restrictions
	 * in placement so it tends to be delayed.
	 */
	if (is_per_cpu_task(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST;

	/*
	 * Prioritize a lock holder for faster system-wide forward progress.
	 */
	if (taskc->need_lock_boost) {
		taskc->need_lock_boost = false;
		weight_boost += LAVD_LC_WEIGHT_BOOST;
	}

	weight_ft = p->scx.weight * weight_boost;
	return weight_ft;
}

static void calc_perf_cri(struct task_struct *p, struct task_ctx *taskc)
{
	u64 wait_freq_ft, wake_freq_ft, perf_cri = 1000;

	/*
	 * A task is more CPU-performance sensitive when it meets the following
	 * conditions:
	 *
	 * - It is in the middle of the task graph (high wait and wake
	 *   frequencies).
	 * - Its runtime and frequency are high;
	 * - Its nice priority is high;
	 *
	 * We use the log-ed value since the raw value follows the highly
	 * skewed distribution.
	 *
	 * Note that we use unadjusted weight to reflect the pure task priority.
	 */
	if (have_little_core) {
		wait_freq_ft = calc_freq_factor(taskc->wait_freq, p->scx.weight);
		wake_freq_ft = calc_freq_factor(taskc->wake_freq, p->scx.weight);
		perf_cri = log2_u64(wait_freq_ft * wake_freq_ft);
		perf_cri += log2_u64(max(taskc->run_freq, 1) *
				     max(taskc->run_time_ns, 1) * p->scx.weight);
	}

	taskc->perf_cri = perf_cri;
}

static void calc_lat_cri(struct task_struct *p, struct task_ctx *taskc)
{
	u64 weight_ft, wait_freq_ft, wake_freq_ft, runtime_ft;
	u64 lat_cri;

	/*
	 * Adjust task's weight based on the scheduling context, such as
	 * if it is a kernel task, lock holder, etc.
	 */
	weight_ft = calc_weight_factor(p, taskc);

	/*
	 * A task is more latency-critical as its wait or wake frequencies
	 * (i.e., wait_freq and wake_freq) are higher.
	 *
	 * Since those frequencies are unbounded and their upper limits are
	 * unknown, we transform them using sigmoid-like functions. For wait
	 * and wake frequencies, we use a sigmoid function (sigmoid_u64), which
	 * is monotonically increasing since higher frequencies mean more
	 * latency-critical.
	 */
	wait_freq_ft = calc_freq_factor(taskc->wait_freq, weight_ft);
	wake_freq_ft = calc_freq_factor(taskc->wake_freq, weight_ft);
	runtime_ft = calc_runtime_factor(taskc->run_time_ns, weight_ft);

	/*
	 * Wake frequency and wait frequency represent how much a task is used
	 * for a producer and a consumer, respectively. If both are high, the
	 * task is in the middle of a task chain. The ratio tends to follow an
	 * exponentially skewed distribution, so we linearize it using log2. We
	 * add +1 to guarantee the latency criticality (log2-ed) is always
	 * positive.
	 */
	lat_cri = log2_u64(wait_freq_ft);
	lat_cri += log2_u64(wake_freq_ft);
	lat_cri += log2_u64(runtime_ft);

	/*
	 * Determine latency criticality of a task in a context-aware manner by
	 * considering which task wakes up this task. If its waker is more
	 * latency-critcial, inherit waker's latency criticality.
	 */
	taskc->lat_cri = max(lat_cri, taskc->lat_cri_waker);
}

static u64 calc_adj_runtime(u64 runtime)
{
	/*
	 * Convert highly skewed runtime distribution to
	 * mildlyskewed distribution.
	 */
	u64 adj_runtime = log2_u64(runtime + 1);
	return adj_runtime * adj_runtime;
}

static u64 calc_virtual_deadline_delta(struct task_struct *p,
					struct task_ctx *taskc)
{
	u64 deadline, adj_runtime;
	u32 greedy_ratio, greedy_ft;

	/*
	 * Calculate the deadline based on runtime,
	 * latency criticality, and greedy ratio.
	 */
	calc_perf_cri(p, taskc);
	calc_lat_cri(p, taskc);
	greedy_ratio = calc_greedy_ratio(taskc);
	greedy_ft = calc_greedy_factor(greedy_ratio);
	adj_runtime = calc_adj_runtime(taskc->run_time_ns);

	deadline = (adj_runtime / taskc->lat_cri) * greedy_ft;

	return deadline;
}

static u32 clamp_time_slice_ns(u32 slice)
{
	if (slice < slice_min_ns)
		slice = slice_min_ns;
	else if (slice > slice_max_ns)
		slice = slice_max_ns;
	return slice;
}

static u64 calc_time_slice(struct task_struct *p, struct task_ctx *taskc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 nr_queued;
	u32 slice;

	/*
	 * The time slice should be short enough to schedule all runnable tasks
	 * at least once within a targeted latency.
	 */
	nr_queued = stat_cur->nr_queued_task + 1;
	slice = (LAVD_TARGETED_LATENCY_NS * stat_cur->nr_active) / nr_queued;

	/*
	 * Keep the slice in [slice_min_ns, slice_max_ns].
	 */
	slice = clamp_time_slice_ns(slice);

	/*
	 * Boost time slice for CPU-bound tasks.
	 */
	slice += (LAVD_SLICE_BOOST_MAX_FT * slice *
		  taskc->slice_boost_prio) / LAVD_SLICE_BOOST_MAX_STEP;

	/*
	 * If a task has yet to be scheduled (i.e., a freshly forked task or a
	 * task just under sched_ext), don't give a fair amount of time slice
	 * until knowing its properties. This helps to mitigate potential
	 * system starvation caused by massively forking tasks (i.e., fork-bomb
	 * attacks).
	 */
	if (!have_scheduled(taskc))
		slice >>= 2;

	taskc->slice_ns = slice;
	return slice;
}

static void reset_suspended_duration(struct cpu_ctx *cpuc)
{
	if (cpuc->online_clk > cpuc->offline_clk)
		cpuc->offline_clk = cpuc->online_clk;
}

static u64 get_suspended_duration_and_reset(struct cpu_ctx *cpuc)
{
	/*
	 * When a system is suspended, a task is also suspended in a running
	 * stat on the CPU. Hence, we subtract the suspended duration when it
	 * resumes.
	 */

	u64 duration = 0;

	if (cpuc->online_clk > cpuc->offline_clk) {
		duration = time_delta(cpuc->online_clk, cpuc->offline_clk);
		/*
		 * Once calculated, reset the duration to zero.
		 */
		cpuc->offline_clk = cpuc->online_clk;
	}

	return duration;
}

static void update_stat_for_runnable(struct task_struct *p,
				     struct task_ctx *taskc)
{
	/*
	 * Reflect task's load immediately.
	 */
	taskc->acc_run_time_ns = 0;
}

static void advance_cur_logical_clk(struct task_struct *p)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 vlc, clc, ret_clc;
	u64 nr_queued, delta, new_clk;

	vlc = READ_ONCE(p->scx.dsq_vtime);
	clc = READ_ONCE(cur_logical_clk);

	for (int i = 0; i < LAVD_MAX_RETRY; ++i) {
		/*
		 * The clock should not go backward, so do nothing.
		 */
		if (vlc <= clc)
			return;

		/*
		 * Advance the clock up to the task's deadline. When overloaded,
		 * advance the clock slower so other can jump in the run queue.
		 */
		nr_queued = max(stat_cur->nr_queued_task, 1);
		delta = (vlc - clc) / nr_queued;
		new_clk = clc + delta;

		ret_clc = __sync_val_compare_and_swap(&cur_logical_clk, clc, new_clk);
		if (ret_clc == clc) /* CAS success */
			return;

		/*
		 * Retry with the updated clc
		 */
		clc = ret_clc;
	}
}

static void update_stat_for_running(struct task_struct *p,
				    struct task_ctx *taskc,
				    struct cpu_ctx *cpuc, u64 now)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 wait_period, interval;

	/*
	 * Update the current logical clock.
	 */
	advance_cur_logical_clk(p);

	/*
	 * Since this is the start of a new schedule for @p, we update run
	 * frequency in a second using an exponential weighted moving average.
	 */
	if (have_scheduled(taskc)) {
		wait_period = time_delta(now, taskc->last_quiescent_clk);
		interval = taskc->run_time_ns + wait_period;
		taskc->run_freq = calc_avg_freq(taskc->run_freq, interval);
	}

	/*
	 * Update task state when starts running.
	 */
	taskc->wakeup_ft = 0;
	taskc->last_running_clk = now;

	/*
	 * Reset task's lock and futex boost count
	 * for a lock holder to be boosted only once.
	 */
	reset_lock_futex_boost(taskc, cpuc);

	/*
	 * Update per-CPU latency criticality information
	 * for every-scheduled tasks.
	 */
	if (cpuc->max_lat_cri < taskc->lat_cri)
		cpuc->max_lat_cri = taskc->lat_cri;
	cpuc->sum_lat_cri += taskc->lat_cri;
	cpuc->nr_sched++;

	/*
	 * Update per-CPU performanc criticality information
	 * for every-scheduled tasks.
	 */
	if (have_little_core) {
		if (cpuc->max_perf_cri < taskc->perf_cri)
			cpuc->max_perf_cri = taskc->perf_cri;
		if (cpuc->min_perf_cri > taskc->perf_cri)
			cpuc->min_perf_cri = taskc->perf_cri;
		cpuc->sum_perf_cri += taskc->perf_cri;
	}

	/*
	 * Update statistics information.
	 */
	if (is_lat_cri(taskc, stat_cur))
		cpuc->nr_lat_cri++;

	if (is_perf_cri(taskc, stat_cur))
		cpuc->nr_perf_cri++;

	/*
	 * It is clear there is no need to consider the suspended duration
	 * while running a task, so reset the suspended duration to zero.
	 */
	reset_suspended_duration(cpuc);
}

static void update_stat_for_stopping(struct task_struct *p,
				     struct task_ctx *taskc,
				     struct cpu_ctx *cpuc)
{
	u64 now = scx_bpf_now();
	u64 suspended_duration, task_run_time;

	/*
	 * Update task's run_time. When a task is scheduled consecutively
	 * without ops.quiescent(), the task's runtime is accumulated for
	 * statistics. Suppose a task is scheduled 2ms, 2ms, and 2ms with the
	 * time slice exhausted. If 6ms of time slice was given in the first
	 * place, the task will entirely consume the time slice. Hence, the
	 * consecutive execution is accumulated and reflected in the
	 * calculation of runtime statistics.
	 */
	suspended_duration = get_suspended_duration_and_reset(cpuc);
	task_run_time = time_delta(now, taskc->last_running_clk + suspended_duration);
	taskc->acc_run_time_ns += task_run_time;
	taskc->run_time_ns = calc_avg(taskc->run_time_ns, taskc->acc_run_time_ns);
	taskc->last_stopping_clk = now;

	taskc->svc_time += task_run_time / p->scx.weight;

	/*
	 * Reset waker's latency criticality here to limit the latency boost of
	 * a task. A task will be latency-boosted only once after wake-up.
	 */
	taskc->lat_cri_waker = 0;

	/*
	 * Increase total service time of this CPU.
	 */
	cpuc->tot_svc_time += taskc->svc_time;

	/*
	 * Update the current service time if necessary.
	 */
	if (READ_ONCE(cur_svc_time) < taskc->svc_time)
		WRITE_ONCE(cur_svc_time, taskc->svc_time);

	/*
	 * Reset task's lock and futex boost count
	 * for a lock holder to be boosted only once.
	 */
	reset_lock_futex_boost(taskc, cpuc);
	taskc->lock_holder_xted = false;
}

static bool match_task_core_type(struct task_ctx *taskc,
				 struct cpu_ctx *cpuc_prev,
				 struct sys_stat *stat_cur)
{
	/*
	 * If a task is performance critical, it is better to run on a big core
	 * even paying some cost looking for a big core.
	 */
	if (is_perf_cri(taskc, stat_cur) && !cpuc_prev->big_core)
		return false;

	/*
	 * Otherwise, it doesn't matter where it runs.
	 */
	return true;
}

static __always_inline
bool could_run_on(struct task_struct *p, s32 cpu,
			 struct bpf_cpumask *a_cpumask,
			 struct bpf_cpumask *o_cpumask)
{
	bool ret;

	ret = bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
	      (bpf_cpumask_test_cpu(cpu, cast_mask(a_cpumask)) ||
	       bpf_cpumask_test_cpu(cpu, cast_mask(o_cpumask)));

	return ret;
}

static __always_inline
bool test_and_clear_cpu_idle(s32 cpu, const struct cpumask *idle_mask,
			     bool reserve_cpu)
{
	if (reserve_cpu)
		return scx_bpf_test_and_clear_cpu_idle(cpu);
	return bpf_cpumask_test_cpu(cpu, idle_mask);
}

static __always_inline
s32 find_idle_cpu_in(struct bpf_cpumask *cpumask,
		     const struct cpumask *idle_mask, bool reserve_cpu)
{
	s32 cpu_id;

	if (reserve_cpu) {
		/*
		 * Pick a fully idle core within a cpumask, then pick an
		 * any idle core if there is no.
		 */
		cpu_id = scx_bpf_pick_idle_cpu(cast_mask(cpumask), 0);
	} else {
		cpu_id = bpf_cpumask_any_and_distribute(cast_mask(cpumask), idle_mask);
		if (cpu_id >= nr_cpu_ids)
			cpu_id = -EBUSY;
	}

	return cpu_id;
}

static __always_inline
s32 find_idle_cpu(struct task_struct *p, struct task_ctx *taskc, s32 prev_cpu,
		  u64 wake_flags, bool reserve_cpu, bool *is_idle)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc, *cpuc_prev, *cpuc_waker;
	struct bpf_cpumask *a_cpumask, *o_cpumask, *t_cpumask, *t2_cpumask;
	struct bpf_cpumask *active, *ovrflw, *big, *little;
	struct bpf_cpumask *cpdom_mask_prev, *cpdom_mask_waker;
	const struct cpumask *idle_mask;
	s32 cpu_id, waker_cpu;
	int cpdom_id;

	idle_mask = scx_bpf_get_idle_cpumask();

	/*
	 * If there is no idle cpu, stay on the previous cpu.
	 */
	if (!have_idle_cpus(idle_mask)) {
		cpu_id = prev_cpu;
		goto out;
	}

	/*
	 * If a task can run only on a single CPU (e.g., per-CPU kworker), we
	 * simply check if a task is still pinned on the prev_cpu and go.
	 */
	if (is_per_cpu_task(p) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		if (test_and_clear_cpu_idle(prev_cpu, idle_mask, reserve_cpu))
			*is_idle = true;
		cpu_id = prev_cpu;
		goto out;
	}

	/*
	 * Prepare cpumaks.
	 */
	bpf_rcu_read_lock();

	cpuc = get_cpu_ctx();
	cpuc_prev = get_cpu_ctx_id(prev_cpu);
	if (!cpuc || !cpuc_prev || !taskc) {
		scx_bpf_error("Failed to lookup the current cpu_ctx");
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	a_cpumask = cpuc->tmp_a_mask;
	o_cpumask = cpuc->tmp_o_mask;
	t_cpumask = cpuc->tmp_t_mask;
	t2_cpumask = cpuc->tmp_t2_mask;
	active  = active_cpumask;
	ovrflw  = ovrflw_cpumask;
	big = big_cpumask;
	little = little_cpumask;
	if (!a_cpumask || !o_cpumask || !t_cpumask || !t2_cpumask ||
	    !active || !ovrflw || !big || !little) {
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	cpdom_id = cpuc_prev->cpdom_id;
	cpdom_mask_prev = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (!cpdom_mask_prev) {
		scx_bpf_error("Failed to lookup cpdom_cpumask for %d",
			      cpuc_prev->cpdom_id);
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	cpuc_waker = get_cpu_ctx();
	if (!cpuc_waker) {
		scx_bpf_error("Failed to lookup the current cpu_ctx");
		cpu_id = -ENOENT;
		goto unlock_out;
	}
	waker_cpu = cpuc_waker->cpu_id;

	cpdom_id = cpuc_waker->cpdom_id;
	cpdom_mask_waker = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (!cpdom_mask_waker) {
		scx_bpf_error("Failed to lookup cpdom_cpumask for %d",
			      cpuc_waker->cpdom_id);
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	bpf_cpumask_and(a_cpumask, p->cpus_ptr, cast_mask(active));
	bpf_cpumask_and(o_cpumask, p->cpus_ptr, cast_mask(ovrflw));

	/*
	 * Try to stay on the previous core if it is on active or ovrfw.
	 */
	if (match_task_core_type(taskc, cpuc_prev, stat_cur) &&
	    could_run_on(p, prev_cpu, a_cpumask, o_cpumask) &&
	    test_and_clear_cpu_idle(prev_cpu, idle_mask, reserve_cpu)) {
		cpu_id = prev_cpu;
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Try to stay on the waker's core if it is on active or ovrfw.
	 */
	if (wake_flags & SCX_WAKE_SYNC && prev_cpu != waker_cpu &&
	    match_task_core_type(taskc, cpuc_waker, stat_cur) &&
	    could_run_on(p, waker_cpu, a_cpumask, o_cpumask) &&
	    test_and_clear_cpu_idle(waker_cpu, idle_mask, reserve_cpu)) {
		cpu_id = waker_cpu;
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Find cpumasks for a matching core type and LLC domain.
	 */
	if (bpf_cpumask_empty(cast_mask(a_cpumask)))
		goto start_omask;

	if (!have_little_core || is_perf_cri(taskc, stat_cur) || no_core_compaction) {
		bpf_cpumask_and(t_cpumask, cast_mask(a_cpumask), cast_mask(big));
	}
	else {
		bpf_cpumask_and(t_cpumask, cast_mask(a_cpumask), cast_mask(little));
		goto start_llc_mask;
	}

	/*
	 * Pick an idle core among turbo boost-enabled CPUs with a matching
	 * core type.
	 */
	if (!have_turbo_core || no_prefer_turbo_core || !turbo_cpumask)
		goto start_llc_mask;

	bpf_cpumask_and(t2_cpumask, cast_mask(t_cpumask), cast_mask(turbo_cpumask));
	if (bpf_cpumask_empty(cast_mask(t2_cpumask)))
		goto start_llc_mask;

	cpu_id = find_idle_cpu_in(t2_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Pick an idle core among active CPUs with a matching core type within
	 * the prev CPU's LLC domain.
	 */
start_llc_mask:
	bpf_cpumask_and(t2_cpumask, cast_mask(t_cpumask), cast_mask(cpdom_mask_prev));
	if (bpf_cpumask_empty(cast_mask(t2_cpumask)))
		goto start_tmask;

	cpu_id = find_idle_cpu_in(t2_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Pick an idle core among active CPUs with a matching core type within
	 * the waker CPU's LLC domain.
	 */
	if (wake_flags & SCX_WAKE_SYNC && prev_cpu != waker_cpu) {
		bpf_cpumask_and(t2_cpumask, cast_mask(t_cpumask), cast_mask(cpdom_mask_waker));
		if (bpf_cpumask_empty(cast_mask(t2_cpumask)))
			goto start_tmask;

		cpu_id = find_idle_cpu_in(t2_cpumask, idle_mask, reserve_cpu);
		if (cpu_id >= 0) {
			*is_idle = true;
			goto unlock_out;
		}
	}

	/*
	 * Pick an idle core among active CPUs with a matching core type.
	 */
start_tmask:
	if (have_little_core) {
		cpu_id = find_idle_cpu_in(t_cpumask, idle_mask, reserve_cpu);
		if (cpu_id >= 0) {
			*is_idle = true;
			goto unlock_out;
		}
	}

	/*
	 * Pick a idle core among active CPUs.
	 */
	cpu_id = find_idle_cpu_in(a_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Pick an any idle core among overflow CPUs.
	 */
start_omask:
	if (bpf_cpumask_empty(cast_mask(o_cpumask)))
		goto start_any_mask;

	cpu_id = find_idle_cpu_in(o_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * If there is no idle core under our control, pick random core
	 * either in active of overflow CPUs.
	 */
	if (!bpf_cpumask_empty(cast_mask(a_cpumask))) {
		cpu_id = bpf_cpumask_any_distribute(cast_mask(a_cpumask));
		goto unlock_out;
	}

	if (!bpf_cpumask_empty(cast_mask(o_cpumask))) {
		cpu_id = bpf_cpumask_any_distribute(cast_mask(o_cpumask));
		goto unlock_out;
	}

	/*
	 * If the task cannot run on either active or overflow cores,
	 * stay on the previous core (if it is okay) or one of its taskset.
	 * Then, put the CPU to the overflow set.
	 */
start_any_mask:
	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		cpu_id = prev_cpu;
	else
		cpu_id = bpf_cpumask_any_distribute(p->cpus_ptr);
	bpf_cpumask_set_cpu(cpu_id, ovrflw);

unlock_out:
	bpf_rcu_read_unlock();

out:
	scx_bpf_put_idle_cpumask(idle_mask);

	/*
	 * Note that we don't need to kick the picked CPU here since the
	 * ops.select_cpu() path internally triggers kicking cpu if necessary.
	 */
	return cpu_id;
}

static u64 calc_when_to_run(struct task_struct *p, struct task_ctx *taskc)
{
	u64 deadline_delta;

	/*
	 * Before enqueueing a task to a run queue, we should decide when a
	 * task should be scheduled.
	 */
	deadline_delta = calc_virtual_deadline_delta(p, taskc);
	return READ_ONCE(cur_logical_clk) + deadline_delta;
}

s32 BPF_STRUCT_OPS(lavd_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool found_idle = false;
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	u64 dsq_id;
	s32 cpu_id;

	taskc = get_task_ctx(p);
	if (!taskc)
		return prev_cpu;
	taskc->wakeup_ft += !!(wake_flags & SCX_WAKE_SYNC);

	/*
	 * Find an idle cpu and reserve it since the task @p will run
	 * on the idle cpu.
	 */
	cpu_id = find_idle_cpu(p, taskc, prev_cpu, wake_flags, true, &found_idle);
	if (found_idle) {
		/*
		 * If there is an idle cpu and its associated DSQ is empty,
		 * disptach the task to the idle cpu right now.
		 */
		cpuc = get_cpu_ctx_id(cpu_id);
		if (!cpuc) {
			scx_bpf_error("Failed to look up cpu context context");
			return cpu_id;
		}
		dsq_id = cpuc->cpdom_id;

		if (!scx_bpf_dsq_nr_queued(dsq_id)) {
			p->scx.dsq_vtime = calc_when_to_run(p, taskc);
			p->scx.slice = calc_time_slice(p, taskc);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, p->scx.slice, 0);
			return cpu_id;
		}
	}

	/*
	 * Even if there is no idle cpu, still repect the chosen cpu.
	 */
	return cpu_id >= 0 ? cpu_id : prev_cpu;
}

static u64 find_proper_dsq(struct task_ctx *taskc, struct cpu_ctx *cpuc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	bool perf_cri = is_perf_cri(taskc, stat_cur);
	bool big_core = cpuc->big_core;

	/*
	 * If a task type and a core type matches, use the current cpu's
	 * compute domain DSQ.
	 */
	if (perf_cri == big_core)
		return cpuc->cpdom_id;

	/*
	 * Otherwise, use the DSQ of an alternative core type.
	 */
	return cpuc->cpdom_alt_id;
}

static bool try_kick_task_idle_cpu(struct task_struct *p,
				   struct task_ctx *taskc, s32 prev_cpu)
{
	bool found_idle = false;
	s32 cpu;

	/*
	 * Find an idle cpu but do not reserve the idle cpu. That is because
	 * there is no guarantee the idle cpu will be picked up at this point.
	 */
	cpu = find_idle_cpu(p, taskc, prev_cpu, 0, false, &found_idle);
	if (found_idle && cpu >= 0) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return true;
	}

	return false;
}

void BPF_STRUCT_OPS(lavd_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cpuc_task, *cpuc_cur;
	struct task_ctx *taskc;
	s32 prev_cpu;
	u64 dsq_id, now;

	/*
	 * Place a task to a run queue of current cpu's compute domain.
	 *
	 * If there is an idle CPU at the ops.select_cpu(), the task is already
	 * dispatched at ops.select_cpu(), so ops.enqueue() won't be called.
	 * Hence, the task that is enqueued here are the cases: 1) there is no
	 * idle CPU when ops.select_cpu() or 2) the task is not the case of
	 * being wakened up (i.e., resume after preemption). Therefore, we
	 * always put the task to the global DSQ, so any idle CPU can pick it
	 * up.
	 */
	taskc = get_task_ctx(p);
	prev_cpu = scx_bpf_task_cpu(p);
	cpuc_task = get_cpu_ctx_id(prev_cpu);
	cpuc_cur = get_cpu_ctx();
	if (!cpuc_cur || !cpuc_task || !taskc)
		return;

	/*
	 * Calculate when a task can be scheduled for how long.
	 */
	taskc->wakeup_ft += !!(enq_flags & SCX_ENQ_WAKEUP);
	p->scx.dsq_vtime = calc_when_to_run(p, taskc);
	p->scx.slice = calc_time_slice(p, taskc);

	/*
	 * Enqueue the task to one of task's DSQs based on its virtual deadline.
	 *
	 * We do not perform direct dispatch to a local DSQ (SCX_DSQ_LOCAL_ON)
	 * on purpose. In particular, the direct dispatch at SCX_ENQ_CPU_SELECTED
	 * could increase tail latencies because it gives too much favor to
	 * non-migratable tasks, so stalling others.
	 */
	dsq_id = find_proper_dsq(taskc, cpuc_task);
	prev_cpu = scx_bpf_task_cpu(p);
	scx_bpf_dsq_insert_vtime(p, dsq_id, p->scx.slice, p->scx.dsq_vtime,
				 enq_flags);

	/*
	 * If there is an idle cpu for the task, try to kick it up now
	 * so it can consume the task immediately.
	 */
	if (try_kick_task_idle_cpu(p, taskc, prev_cpu))
		return;

	/*
	 * If there is no idle cpu for an eligible task, try to preempt a task.
	 * Try to find and kick a victim CPU, which runs a less urgent task.
	 * The kick will be done asynchronously.
	 */
	now = scx_bpf_now();
	try_find_and_kick_victim_cpu(p, taskc, cpuc_cur, dsq_id, now);
}

static bool consume_dsq(u64 dsq_id)
{
	struct cpdom_ctx *cpdomc;

	/*
	 * Update the last consume clock of the compute domain.
	 */
	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
		return false;
	}

	/*
	 * Try to consume a task on the associated DSQ.
	 */
	return scx_bpf_dsq_move_to_local(dsq_id);
}

static bool try_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	u64 nr_nbr, dsq_id;
	s64 nuance;

	/*
	 * If all CPUs are not used -- i.e., the system is under-utilized,
	 * there is no point of load balancing. It is better to make an
	 * effort to increase the system utilization.
	 */
	if (!use_full_cpus())
		return false;

	/*
	 * Probabilistically make a go or no go decision to avoid the
	 * thundering herd problem. In other words, one out of nr_cpus
	 * will try to steal a task at a moment.
	 */
	if (!prob_x_out_of_y(1, cpdomc->nr_cpus * LAVD_CPDOM_X_PROB_FT))
		return false;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	nuance = bpf_get_prandom_u32();
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbor in the same distance in arbitrary order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++, nuance = dsq_id + 1) {
			if (j >= nr_nbr)
				break;

			dsq_id = pick_any_bit(cpdomc->neighbor_bits[i], nuance);
			if (dsq_id == -ENOENT)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
				return false;
			}

			if (!cpdomc_pick->is_stealee || !cpdomc_pick->is_active)
				continue;

			/*
			 * If task stealing is successful, mark the stealer
			 * and the stealee's job done. By marking done,
			 * those compute domains would not be involved in
			 * load balancing until the end of this round,
			 * so this helps gradual migration. Note that multiple
			 * stealers can steal tasks from the same stealee.
			 * However, we don't coordinate concurrent stealing
			 * because the chance is low and there is no harm
			 * in slight over-stealing.
			 */
			if (consume_dsq(dsq_id)) {
				WRITE_ONCE(cpdomc_pick->is_stealee, false);
				WRITE_ONCE(cpdomc->is_stealer, false);
				return true;
			}
		}

		/*
		 * Now, we need to steal a task from a farther neighbor
		 * for load balancing. Since task migration from a farther
		 * neighbor is more expensive (e.g., crossing a NUMA boundary),
		 * we will do this with a lot of hesitation. The chance of
		 * further migration will decrease exponentially as distance
		 * increases, so, on the other hand, it increases the chance
		 * of closer migration.
		 */
		if (!prob_x_out_of_y(1, LAVD_CPDOM_X_PROB_FT))
			break;
	}

	return false;
}

static bool force_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	u64 nr_nbr, dsq_id;
	s64 nuance;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	nuance = bpf_get_prandom_u32();
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbor in the same distance in arbitrary order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++, nuance = dsq_id + 1) {
			if (j >= nr_nbr)
				break;

			dsq_id = pick_any_bit(cpdomc->neighbor_bits[i], nuance);
			if (dsq_id == -ENOENT)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
				return false;
			}

			if (!cpdomc_pick->is_active)
				continue;

			if (consume_dsq(dsq_id))
				return true;
		}
	}

	return false;
}

static bool consume_task(struct cpu_ctx *cpuc)
{
	struct cpdom_ctx *cpdomc;
	u64 dsq_id;

	dsq_id = cpuc->cpdom_id;
	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
		return false;
	}

	/*
	 * If the current compute domain is a stealer, try to steal
	 * a task from any of stealee domains probabilistically.
	 */
	if (READ_ONCE(cpdomc->is_stealer) && try_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	/*
	 * Try to consume a task from CPU's associated DSQ.
	 */
	if (consume_dsq(dsq_id))
		return true;

	/*
	 * If there is no task in the assssociated DSQ, traverse neighbor
	 * compute domains in distance order -- task stealing.
	 */
	if (force_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	return false;

	/*
	 * Task migration across compute domains happens.
	 * Update the statistics.
	 */
x_domain_migration_out:
	cpuc->nr_x_migration++;
	return true;
}

static bool try_continue_lock_holder(struct task_struct *prev,
				     struct task_ctx *taskc,
				     struct cpu_ctx *cpuc)
{
	if (!(prev->scx.flags & SCX_TASK_QUEUED) || !is_lock_holder(taskc))
		return false;

	/*
	 * Refill the time slice.
	 */
	prev->scx.slice = calc_time_slice(prev, taskc);

	/*
	 * Reset prev task's lock and futex boost count
	 * for a lock holder to be boosted only once.
	 */
	reset_lock_futex_boost(taskc, cpuc);
	taskc->lock_holder_xted = true;

	return true;
}

void BPF_STRUCT_OPS(lavd_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;
	struct bpf_cpumask *active, *ovrflw;
	struct task_struct *p;
	u64 dsq_id;
	bool try_consume = false;

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc) {
		scx_bpf_error("Failed to look up cpu context context");
		return;
	}
	dsq_id = cpuc->cpdom_id;

	/*
	 * If a task newly holds a lock, continue to execute it
	 * to make system-wide forward progress.
	 */
	if (prev) {
		taskc = get_task_ctx(prev);
		if (!taskc) {
			scx_bpf_error("Failed to look up task context");
			return;
		}

		if (try_continue_lock_holder(prev, taskc, cpuc))
			return;
	}

	/*
	 * If all CPUs are using, directly consume without checking CPU masks.
	 */
	if (use_full_cpus()) {
		try_consume = true;
		goto consume_out;
	}

	/*
	 * Prepare cpumasks.
	 */
	bpf_rcu_read_lock();

	active = active_cpumask;
	ovrflw = ovrflw_cpumask;
	if (!active || !ovrflw) {
		scx_bpf_error("Failed to prepare cpumasks.");
		goto unlock_out;
	}

	/*
	 * If the CPU belonges to the active or overflow set, dispatch a task.
	 */
	if (bpf_cpumask_test_cpu(cpu, cast_mask(active)) ||
	    bpf_cpumask_test_cpu(cpu, cast_mask(ovrflw))) {
		try_consume = true;
		goto unlock_out;
	}

	/*
	 * If this CPU is not either in active or overflow CPUs, it tries to
	 * find and run a task pinned to run on this CPU.
	 */
	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		/*
		 * Prioritize kernel tasks because most kernel tasks are pinned
		 * to a particular CPU and latency-critical (e.g., ksoftirqd,
		 * kworker, etc).
		 */
		if (is_kernel_task(p)) {
			bpf_cpumask_set_cpu(cpu, ovrflw);
			try_consume = true;
			break;
		}

		/*
		 * This is a hack to bypass the restriction of the current BPF
		 * not trusting the pointer p. Once the BPF verifier gets
		 * smarter, we can remove bpf_task_from_pid().
		 */
		p = bpf_task_from_pid(p->pid);
		if (!p)
			goto unlock_out;

		/*
		 * If a task can run on active or overflow CPUs, it just does
		 * nothing to go idle.
		 */
		if (bpf_cpumask_intersects(cast_mask(active), p->cpus_ptr) ||
		    bpf_cpumask_intersects(cast_mask(ovrflw), p->cpus_ptr))
			goto release_break;

		/*
		 * This is the first time a particular pinned user-space task
		 * is run on this CPU at this interval. From now on, this CPU
		 * will be part of the overflow CPU so can be used to run the
		 * pinned task and the other tasks. Note that we don't need to
		 * kick @cpu here since @cpu is the current CPU, which is
		 * obviously not idle.
		 */
		bpf_cpumask_set_cpu(cpu, ovrflw);

		/*
		 * Otherwise, that means there is a task that should run on
		 * this particular CPU. So, consume one of such tasks.
		 *
		 * Note that this path is not optimized since
		 * scx_bpf_dsq_move_to_local() should traverse until it finds
		 * any task that can run on this CPU. The scheduled task might
		 * be runnable on the active cores. We will optimize this path
		 * after introducing per-core DSQ.
		 */
		try_consume = true;

release_break:
		bpf_task_release(p);
		break;
	}

unlock_out:
	bpf_rcu_read_unlock();

	/*
	 * Note that the verifier in 6.8 kernel cannot correctly verifies the
	 * code when consume_task() is under a rcu-read-lock region. Hence, we
	 * moveed it outside of the rcu region. :-(
	 */
consume_out:
	/*
	 * Consume a task if requested.
	 */
	if (try_consume && consume_task(cpuc))
		return;

	/*
	 * If nothing to run, continue to run the previous task.
	 */
	if (prev && prev->scx.flags & SCX_TASK_QUEUED)
		prev->scx.slice = calc_time_slice(prev, taskc);
}

void BPF_STRUCT_OPS(lavd_tick, struct task_struct *p_run)
{
	struct cpu_ctx *cpuc_run;
	struct task_ctx *taskc_run;
	u64 now;
	bool preempted;

	cpuc_run = get_cpu_ctx();
	taskc_run = get_task_ctx(p_run);
	if (!cpuc_run || !taskc_run)
		goto update_cpuperf;

	/*
	 * Try to yield the current CPU if there is a higher priority task in
	 * the run queue.
	 */
	now = scx_bpf_now();
	preempted = try_yield_current_cpu(p_run, cpuc_run, taskc_run, now);

	/*
	 * Update performance target of the current CPU if the current running
	 * task continues to run.
	 */
	if (!preempted) {
update_cpuperf:
		try_decrease_cpuperf_target(cpuc_run);
	}
}

void BPF_STRUCT_OPS(lavd_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_struct *waker;
	struct task_ctx *p_taskc, *waker_taskc;
	u64 now, interval;

	/*
	 * Add task load based on the current statistics regardless of a target
	 * rq. Statistics will be adjusted when more accurate statistics become
	 * available (ops.running).
	 */
	p_taskc = get_task_ctx(p);
	if (!p_taskc)
		return;

	update_stat_for_runnable(p, p_taskc);

	/*
	 * When a task @p is wakened up, the wake frequency of its waker task
	 * is updated. The @current task is a waker and @p is a waiter, which
	 * is being wakened up now.
	 */
	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;

	/*
	 * Filter out unrelated tasks.
	 */
	waker = bpf_get_current_task_btf();
	waker_taskc = try_get_task_ctx(waker);
	if (!waker_taskc) {
		/*
		 * In this case, the waker could be an idle task
		 * (swapper/_[_]), so we just ignore.
		 */
		return;
	}

	/*
	 * Update wake frequency.
	 */
	now = scx_bpf_now();
	interval = time_delta(now, waker_taskc->last_runnable_clk);
	waker_taskc->wake_freq = calc_avg_freq(waker_taskc->wake_freq, interval);
	waker_taskc->last_runnable_clk = now;

	/*
	 * Propagate waker's latency criticality to wakee. Note that we pass
	 * task's self latency criticality to limit the context into one hop.
	 */
	p_taskc->lat_cri_waker = waker_taskc->lat_cri;
}

void BPF_STRUCT_OPS(lavd_running, struct task_struct *p)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;
	u64 now = scx_bpf_now();

	/*
	 * Update task statistics
	 */
	cpuc = get_cpu_ctx();
	taskc = get_task_ctx(p);
	if (!cpuc || !taskc)
		return;

	update_stat_for_running(p, taskc, cpuc, now);

	/*
	 * Calculate the task's time slice.
	 */
	p->scx.slice = calc_time_slice(p, taskc);

	/*
	 * Calculate the task's CPU performance target and update if the new
	 * target is higher than the current one. The CPU's performance target
	 * urgently increases according to task's target but it decreases
	 * gradually according to EWMA of past performance targets.
	 */
	calc_cpuperf_target(stat_cur, taskc, cpuc);
	try_increase_cpuperf_target(cpuc);

	/*
	 * Update running task's information for preemption
	 */
	cpuc->lat_cri = taskc->lat_cri;
	cpuc->stopping_tm_est_ns = get_est_stopping_time(taskc, now);

	/*
	 * If there is a relevant introspection command with @p, process it.
	 */
	try_proc_introspec_cmd(p, taskc);
}

static bool slice_fully_consumed(struct cpu_ctx *cpuc, struct task_ctx *taskc)
{
	u64 run_time_ns;

	run_time_ns = time_delta(taskc->last_stopping_clk, taskc->last_running_clk);
	return run_time_ns > 0 && run_time_ns >= taskc->slice_ns;
}

static void adjust_slice_boost(struct cpu_ctx *cpuc, struct task_ctx *taskc)
{
	/*
	 * Count how many times a task completely consumed the assigned time
	 * slice to boost the task's slice when CPU is under-utilized. If not
	 * fully consumed, decrease the slice boost priority by half.
	 */
	if (slice_fully_consumed(cpuc, taskc)) {
		if (taskc->slice_boost_prio < LAVD_SLICE_BOOST_MAX_STEP)
			taskc->slice_boost_prio++;
	}
	else {
		if (taskc->slice_boost_prio)
			taskc->slice_boost_prio >>= 1;
	}
}

void BPF_STRUCT_OPS(lavd_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;

	/*
	 * Update task statistics
	 */
	cpuc = get_cpu_ctx();
	taskc = get_task_ctx(p);
	if (!cpuc || !taskc)
		return;

	update_stat_for_stopping(p, taskc, cpuc);

	/*
	 * Adjust slice boost for the task's next schedule.
	 */
	adjust_slice_boost(cpuc, taskc);
}

void BPF_STRUCT_OPS(lavd_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;
	u64 now, interval;

	/*
	 * Substract task load from the current CPU's load.
	 */
	cpuc = get_cpu_ctx();
	taskc = get_task_ctx(p);
	if (!cpuc || !taskc)
		return;

	/*
	 * If a task @p is dequeued from a run queue for some other reason
	 * other than going to sleep, it is an implementation-level side
	 * effect. Hence, we don't care this spurious dequeue.
	 */
	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	/*
	 * When a task @p goes to sleep, its associated wait_freq is updated.
	 */
	now = scx_bpf_now();
	interval = time_delta(now, taskc->last_quiescent_clk);
	taskc->wait_freq = calc_avg_freq(taskc->wait_freq, interval);
	taskc->last_quiescent_clk = now;
}

static void cpu_ctx_init_online(struct cpu_ctx *cpuc, u32 cpu_id, u64 now)
{
	cpuc->idle_start_clk = 0;
	cpuc->cpu_id = cpu_id;
	cpuc->lat_cri = 0;
	cpuc->stopping_tm_est_ns = SCX_SLICE_INF;
	WRITE_ONCE(cpuc->online_clk, now);
	barrier();

	cpuc->is_online = true;
}

static void cpu_ctx_init_offline(struct cpu_ctx *cpuc, u32 cpu_id, u64 now)
{
	cpuc->idle_start_clk = 0;
	cpuc->cpu_id = cpu_id;
	WRITE_ONCE(cpuc->offline_clk, now);
	cpuc->is_online = false;
	barrier();

	cpuc->lat_cri = 0;
	cpuc->stopping_tm_est_ns = SCX_SLICE_INF;
}

void BPF_STRUCT_OPS(lavd_cpu_online, s32 cpu)
{
	/*
	 * When a cpu becomes online, reset its cpu context and trigger the
	 * recalculation of the global cpu load.
	 */
	u64 now = scx_bpf_now();
	struct cpu_ctx *cpuc;

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc)
		return;

	cpu_ctx_init_online(cpuc, cpu, now);

	__sync_fetch_and_add(&nr_cpus_onln, 1);
	update_sys_stat();
}

void BPF_STRUCT_OPS(lavd_cpu_offline, s32 cpu)
{
	/*
	 * When a cpu becomes offline, trigger the recalculation of the global
	 * cpu load.
	 */
	u64 now = scx_bpf_now();
	struct cpu_ctx *cpuc;

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc)
		return;

	cpu_ctx_init_offline(cpuc, cpu, now);

	__sync_fetch_and_sub(&nr_cpus_onln, 1);
	update_sys_stat();
}

void BPF_STRUCT_OPS(lavd_update_idle, s32 cpu, bool idle)
{
	/*
	 * The idle duration is accumulated to calculate the CPU utilization.
	 * Since SCX_OPS_KEEP_BUILTIN_IDLE is specified, we still rely on the
	 * default idle core tracking and core selection algorithm.
	 */

	struct cpu_ctx *cpuc;
	u64 now;

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc)
		return;

	now = scx_bpf_now();

	/*
	 * The CPU is entering into the idle state.
	 */
	if (idle) {
		cpuc->idle_start_clk = now;

		/*
		 * As an idle task cannot be preempted,
		 * per-CPU preemption information should be cleared.
		 */
		reset_cpu_preemption_info(cpuc, false);
	}
	/*
	 * The CPU is exiting from the idle state.
	 */
	else {
		/*
		 * If idle_start_clk is zero, that means entering into the idle
		 * is not captured by the scx (i.e., the scx scheduler is
		 * loaded when this CPU is in an idle state).
		 */
		u64 old_clk = cpuc->idle_start_clk;
		if (old_clk != 0) {
			/*
			 * The CAS failure happens when idle_start_clk is
			 * updated by the update timer. That means the update
			 * timer already took the idle_time duration. Hence the
			 * idle duration should not be accumulated.
			 */
			u64 duration = time_delta(now, old_clk);
			bool ret = __sync_bool_compare_and_swap(
					&cpuc->idle_start_clk, old_clk, 0);
			if (ret)
				cpuc->idle_total += duration;
		}
	}
}

void BPF_STRUCT_OPS(lavd_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	taskc = get_task_ctx(p);
	if (!taskc) {
		scx_bpf_error("task_ctx_stor first lookup failed");
		return;
	}

	set_on_core_type(taskc, cpumask);
}

void BPF_STRUCT_OPS(lavd_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	struct cpu_ctx *cpuc;

	/*
	 * When the scx scheduler loses control of a CPU,
	 * reset the CPU's preemption information so it cannot be a victim.
	 */
	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc) {
		scx_bpf_error("Failed to lookup cpu_ctx %d", cpu);
		return;
	}
	reset_cpu_preemption_info(cpuc, true);

	/*
	 * When a CPU is released to serve higher priority scheduler class,
	 * requeue the tasks in a local DSQ to the global enqueue.
	 */
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(lavd_enable, struct task_struct *p)
{
	struct task_ctx *taskc;

	/*
	 * Set task's service time to the current, minimum service time.
	 */
	taskc = get_task_ctx(p);
	if (!taskc) {
		scx_bpf_error("task_ctx_stor first lookup failed");
		return;
	}

	taskc->svc_time = READ_ONCE(cur_svc_time);
}

static void init_task_ctx(struct task_struct *p, struct task_ctx *taskc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 now = scx_bpf_now();

	__builtin_memset(taskc, 0, sizeof(*taskc));
	taskc->last_running_clk = now; /* for run_time_ns */
	taskc->last_stopping_clk = now; /* for run_time_ns */
	taskc->run_time_ns = slice_max_ns;
	taskc->svc_time = stat_cur->avg_svc_time * LAVD_NEW_PROC_PENALITY;

	set_on_core_type(taskc, p->cpus_ptr);
}

s32 BPF_STRUCT_OPS(lavd_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *taskc;

	/*
	 * When @p becomes under the SCX control (e.g., being forked), @p's
	 * context data is initialized. We can sleep in this function and the
	 * following will automatically use GFP_KERNEL.
	 */
	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc || !p) {
		scx_bpf_error("task_ctx_stor first lookup failed");
		return -ENOMEM;
	}


	/*
	 * Initialize @p's context.
	 */
	init_task_ctx(p, taskc);
	return 0;
}

static s32 init_cpdoms(u64 now)
{
	struct cpdom_ctx *cpdomc;
	int err;

	for (int i = 0; i < LAVD_CPDOM_MAX_NR; i++) {
		/*
		 * Fetch a cpdom context.
		 */
		cpdomc = MEMBER_VPTR(cpdom_ctxs, [i]);
		if (!cpdomc) {
			scx_bpf_error("Failed to lookup cpdom_ctx for %d", i);
			return -ESRCH;
		}
		if (!cpdomc->is_active)
			continue;

		/*
		 * Create an associated DSQ on its associated NUMA domain.
		 */
		err = scx_bpf_create_dsq(cpdomc->id, cpdomc->node_id);
		if (err) {
			scx_bpf_error("Failed to create a DSQ for cpdom %llu on NUMA node %d",
				      cpdomc->id, cpdomc->node_id);
			return err;
		}

		/*
		 * Update the number of compute domains.
		 */
		nr_cpdoms = i + 1;
	}

	return 0;
}

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

static int init_cpumasks(void)
{
	const struct cpumask *online_cpumask;
	struct bpf_cpumask *active;
	int err = 0;

	bpf_rcu_read_lock();
	err = calloc_cpumask(&active_cpumask);
	active = active_cpumask;
	if (err || !active)
		goto out;

	err = calloc_cpumask(&ovrflw_cpumask);
	if (err)
		goto out;

	err = calloc_cpumask(&turbo_cpumask);
	if (err)
		goto out;

	err = calloc_cpumask(&big_cpumask);
	if (err)
		goto out;

	err = calloc_cpumask(&little_cpumask);
	if (err)
		goto out;

	/*
	 * Initially activate all online CPUs until we know the system load.
	 */
	online_cpumask = scx_bpf_get_online_cpumask();
	nr_cpus_onln = bpf_cpumask_weight(online_cpumask);
	bpf_cpumask_copy(active, online_cpumask);
	scx_bpf_put_cpumask(online_cpumask);

out:
	bpf_rcu_read_unlock();
	return err;
}

static s32 init_per_cpu_ctx(u64 now)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *turbo, *big, *little, *active, *ovrflw, *cd_cpumask;
	struct cpdom_ctx *cpdomc;
	int cpu, i, j, err = 0, nr_cpus_non_zero = 0;
	u64 cpdom_id;
	u32 sum_capacity = 0, avg_capacity, big_capacity = 0;
	u16 turbo_cap;

	bpf_rcu_read_lock();

	/*
	 * Prepare cpumasks.
	 */
	turbo = turbo_cpumask;
	big = big_cpumask;
	little = little_cpumask;
	active  = active_cpumask;
	ovrflw  = ovrflw_cpumask;
	if (!turbo || !big|| !little || !active || !ovrflw) {
		scx_bpf_error("Failed to prepare cpumasks.");
		err = -ENOMEM;
		goto unlock_out;
	}

	/*
	 * Initilize CPU info
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			err = -ESRCH;
			goto unlock_out;
		}

		err = calloc_cpumask(&cpuc->tmp_a_mask);
		if (err)
			goto unlock_out;

		err = calloc_cpumask(&cpuc->tmp_o_mask);
		if (err)
			goto unlock_out;

		err = calloc_cpumask(&cpuc->tmp_t_mask);
		if (err)
			goto unlock_out;

		err = calloc_cpumask(&cpuc->tmp_t2_mask);
		if (err)
			goto unlock_out;

		if (bpf_cpumask_test_cpu(cpu, cast_mask(active)))
			cpu_ctx_init_online(cpuc, cpu, now);
		else
			cpu_ctx_init_offline(cpuc, cpu, now);

		cpuc->capacity = get_cpuperf_cap(cpu);
		cpuc->offline_clk = now;
		cpuc->cpdom_poll_pos = cpu % LAVD_CPDOM_MAX_NR;
		cpuc->min_perf_cri = 1000;
		cpuc->futex_op = LAVD_FUTEX_OP_INVALID;

		if (cpuc->capacity > 0) {
			sum_capacity += cpuc->capacity;
			nr_cpus_non_zero++;
		}
	}

	/*
	 * Get turbo capacitiy.
	 */
	turbo_cap = get_cputurbo_cap();

	/*
	 * Classify CPU into BIG or little cores based on their average capacity.
	 */
	avg_capacity = sum_capacity / nr_cpus_non_zero;
	bpf_for(cpu, 0, nr_cpu_ids) {
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			err = -ESRCH;
			goto unlock_out;
		}

		cpuc->big_core = cpuc->capacity >= avg_capacity;
		if (cpuc->big_core) {
			nr_cpus_big++;
			big_capacity += cpuc->capacity;
			bpf_cpumask_set_cpu(cpu, big);
			/*
			 * Initially, all big cores are in the active domain
			 * and all little cores in the overflow domain.
			 */
			bpf_cpumask_set_cpu(cpu, active);
		}
		else {
			bpf_cpumask_set_cpu(cpu, little);
			bpf_cpumask_set_cpu(cpu, ovrflw);
			have_little_core = true;
		}

		cpuc->turbo_core = cpuc->capacity == turbo_cap;
		if (cpuc->turbo_core) {
			bpf_cpumask_set_cpu(cpu, turbo);
			have_turbo_core = true;
			debugln("CPU %d is a turbo core.", cpu);
		}
	}
	default_big_core_ratio = (1000 * big_capacity) / sum_capacity;

	/*
	 * Initialize compute domain id.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
		if (!cpdomc || !cd_cpumask) {
			scx_bpf_error("Failed to lookup cpdom_ctx for %llu", cpdom_id);
			err = -ESRCH;
			goto unlock_out;
		}
		if (!cpdomc->is_active)
			continue;

		bpf_for(i, 0, LAVD_CPU_ID_MAX/64) {
			u64 cpumask = cpdomc->__cpumask[i];
			bpf_for(j, 0, 64) {
				if (cpumask & 0x1LLU << j) {
			 		cpu = (i * 64) + j;
					bpf_cpumask_set_cpu(cpu, cd_cpumask);
					cpuc = get_cpu_ctx_id(cpu);
					if (!cpuc) {
						scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
						err = -ESRCH;
						goto unlock_out;
					}
					cpuc->cpdom_id = cpdomc->id;
					cpuc->cpdom_alt_id = cpdomc->alt_id;
					cpdomc->nr_cpus++;
				}
			}
		}
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			err = -ESRCH;
			goto unlock_out;
		}
		debugln("cpu:%d cpdom_id: %llu alt_id: %llu",
			cpu, cpuc->cpdom_id, cpuc->cpdom_alt_id);
	}

unlock_out:
	bpf_rcu_read_unlock();
	return err;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lavd_init)
{
	u64 now = scx_bpf_now();
	int err;

	/*
	 * Create compute domains.
	 */
	err = init_cpdoms(now);
	if (err)
		return err;

	/*
	 * Allocate cpumask for core compaction.
	 *  - active CPUs: a group of CPUs will be used for now.
	 *  - overflow CPUs: a pair of hyper-twin which will be used when there
	 *    is no idle active CPUs.
	 */
	err = init_cpumasks();
	if (err)
		return err;

	/*
	 * Initialize per-CPU context.
	 */
	err = init_per_cpu_ctx(now);
	if (err)
		return err;

	/*
	 * Initialize the last update clock and the update timer to track
	 * system-wide CPU load.
	 */
	err = init_sys_stat(now);
	if (err)
		return err;

	/*
	 * Initialize the low cpu watermark for autopilot mode.
	 */
	init_autopilot_low_util();

	/*
	 * Initilize the current logical clock and service time.
	 */
	WRITE_ONCE(cur_logical_clk, 0);
	WRITE_ONCE(cur_svc_time, 0);

	return err;
}

void BPF_STRUCT_OPS(lavd_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(lavd_ops,
	       .select_cpu		= (void *)lavd_select_cpu,
	       .enqueue			= (void *)lavd_enqueue,
	       .dispatch		= (void *)lavd_dispatch,
	       .tick			= (void *)lavd_tick,
	       .runnable		= (void *)lavd_runnable,
	       .running			= (void *)lavd_running,
	       .stopping		= (void *)lavd_stopping,
	       .quiescent		= (void *)lavd_quiescent,
	       .cpu_online		= (void *)lavd_cpu_online,
	       .cpu_offline		= (void *)lavd_cpu_offline,
	       .update_idle		= (void *)lavd_update_idle,
	       .set_cpumask		= (void *)lavd_set_cpumask,
	       .cpu_release		= (void *)lavd_cpu_release,
	       .enable			= (void *)lavd_enable,
	       .init_task		= (void *)lavd_init_task,
	       .init			= (void *)lavd_init,
	       .exit			= (void *)lavd_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE |
					  SCX_OPS_ENQ_EXITING,
	       .timeout_ms		= 30000U,
	       .name			= "lavd");

