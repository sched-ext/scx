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
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/*
 * Sched related globals
 */
volatile u64		nr_cpus_onln;
static volatile u64	nr_cpus_big;

struct sys_stat	__sys_stats[2];
volatile int	__sys_stat_idx;

private(LAVD) struct bpf_cpumask __kptr *turbo_cpumask; /* CPU mask for turbo CPUs */
private(LAVD) struct bpf_cpumask __kptr *big_cpumask; /* CPU mask for big CPUs */
private(LAVD) struct bpf_cpumask __kptr *little_cpumask; /* CPU mask for little CPUs */
private(LAVD) struct bpf_cpumask __kptr *active_cpumask; /* CPU mask for active CPUs */
private(LAVD) struct bpf_cpumask __kptr *ovrflw_cpumask; /* CPU mask for overflow CPUs */
private(LAVD) struct bpf_cpumask cpdom_cpumask[LAVD_CPDOM_MAX_NR]; /* CPU mask for each compute domain */

static u64		LAVD_AP_LOW_UTIL;
static bool		have_turbo_core;
static bool		have_little_core;

/*
 * CPU topology
 */
const volatile u16	cpu_order_performance[LAVD_CPU_ID_MAX]; /* CPU preference order for performance and balanced mode */
const volatile u16	cpu_order_powersave[LAVD_CPU_ID_MAX]; /* CPU preference order for powersave mode */
const volatile u16	__cpu_capacity_hint[LAVD_CPU_ID_MAX]; /* CPU capacity based on 1000 */
struct cpdom_ctx	cpdom_ctxs[LAVD_CPDOM_MAX_NR]; /* contexts for compute domains */


/*
 * Logical current clock
 */
static u64		cur_logical_clk;

/*
 * Current service time
 */
static u64		cur_svc_time;

/*
 * Big core's compute ratio among currently active cores
 */
static u32		cur_big_core_ratio;

/*
 * Big core's compute ratio when all cores are active
 */
static u32		default_big_core_ratio;

/*
 * Options
 */
volatile bool		no_core_compaction;
volatile bool		no_freq_scaling;
volatile bool		no_prefer_turbo_core;
volatile bool		is_powersave_mode;
volatile bool		reinit_cpumask_for_performance;
const volatile bool	is_autopilot_on;
const volatile u32 	is_smt_active;
const volatile u8	verbose;

/*
 * Statistics
 */
volatile int		power_mode;
volatile u64		last_power_mode_clk;
volatile u64		performance_mode_ns;
volatile u64		balanced_mode_ns;
volatile u64		powersave_mode_ns;

/*
 * Exit infomation
 */
UEI_DEFINE(uei);

#define debugln(fmt, ...)						\
({									\
	if (verbose > 0)						\
		bpf_printk("[%s:%d] " fmt, __func__, __LINE__,		\
					##__VA_ARGS__);			\
})

#define traceln(fmt, ...)						\
({									\
	if (verbose > 1)						\
		bpf_printk("[%s:%d] " fmt, __func__, __LINE__,		\
					##__VA_ARGS__);			\
})

#ifndef min
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifndef max
#define max(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

/*
 * Timer for updating system-wide CPU utilization periorically
 */
struct update_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct update_timer);
} update_timer SEC(".maps");

/*
 * per-CPU globals
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Per-task scheduling context
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Preemption related ones
 */
struct preemption_info {
	u64		stopping_tm_est_ns;
	u64		last_kick_clk;
	u64		lat_cri;
	struct cpu_ctx	*cpuc;
};

/*
 * Introspection commands
 */
struct introspec intrspc;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 /* 16 KB */);
} introspec_msg SEC(".maps");

static u16 get_nice_prio(struct task_struct *p);
static int reinit_active_cpumask_for_performance(void);
static void update_power_mode_time(void);

static u64 sigmoid_u64(u64 v, u64 max)
{
	/*
	 * An integer approximation of the sigmoid function. It is convenient
	 * to use the sigmoid function since it has a known upper and lower
	 * bound, [0, max].
	 *
	 *      |
	 *	|      +------ <= max
	 *	|    /
	 *	|  /
	 *	|/
	 *	+------------->
	 */
	return (v > max) ? max : v;
}

static u64 rsigmoid_u64(u64 v, u64 max)
{
	/*
	 * A horizontally flipped version of sigmoid function. Again, it is
	 * convenient since the upper and lower bound of the function is known,
	 * [0, max].
	 *
	 *
	 *      |
	 *	|\ <= max
	 *	| \
	 *	|  \
	 *	|   \
	 *	+----+-------->
	 */
	return (v >= max) ? 0 : max - v;
}

static struct task_ctx *try_get_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

static struct task_ctx *get_task_ctx(struct task_struct *p)
{
	struct task_ctx *taskc;

	taskc = try_get_task_ctx(p);
	if (!taskc)
		scx_bpf_error("task_ctx lookup failed for %s[%d]",
			      p->comm, p->pid);
	return taskc;
}

static struct cpu_ctx *get_cpu_ctx(void)
{
	const u32 idx = 0;
	struct cpu_ctx *cpuc;

	cpuc = bpf_map_lookup_elem(&cpu_ctx_stor, &idx);
	if (!cpuc)
		scx_bpf_error("cpu_ctx lookup failed for current cpu");

	return cpuc;
}

static struct cpu_ctx *get_cpu_ctx_id(s32 cpu_id)
{
	const u32 idx = 0;
	struct cpu_ctx *cpuc;

	cpuc = bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu_id);
	if (!cpuc)
		scx_bpf_error("cpu_ctx lookup failed for %d", cpu_id);

	return cpuc;
}

static struct sys_stat *get_sys_stat_cur(void)
{
	if (READ_ONCE(__sys_stat_idx) == 0)
		return &__sys_stats[0];
	return &__sys_stats[1];
}

static struct sys_stat *get_sys_stat_next(void)
{
	if (READ_ONCE(__sys_stat_idx) == 0)
		return &__sys_stats[1];
	return &__sys_stats[0];
}

static void flip_sys_stat(void)
{
	WRITE_ONCE(__sys_stat_idx, __sys_stat_idx ^ 0x1);
}

static bool is_lat_cri(struct task_ctx *taskc, struct sys_stat *stat_cur)
{
	return taskc->lat_cri >= stat_cur->avg_lat_cri;
}

static bool is_perf_cri(struct task_ctx *taskc, struct sys_stat *stat_cur)
{
	if (READ_ONCE(taskc->on_big) && READ_ONCE(taskc->on_little))
		return taskc->perf_cri >= stat_cur->thr_perf_cri;
	return READ_ONCE(taskc->on_big);
}

static bool is_greedy(struct task_ctx *taskc)
{
	return taskc->greedy_ratio > 1000;
}

static bool is_eligible(struct task_ctx *taskc)
{
	return !is_greedy(taskc);
}


static __always_inline
int submit_task_ctx(struct task_struct *p, struct task_ctx *taskc, u32 cpu_id)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc;
	struct msg_task_ctx *m;

	cpuc = get_cpu_ctx_id(cpu_id);
	if (!cpuc)
		return -EINVAL;

	m = bpf_ringbuf_reserve(&introspec_msg, sizeof(*m), 0);
	if (!m)
		return -ENOMEM;

	m->hdr.kind = LAVD_MSG_TASKC;
	m->taskc_x.pid = p->pid;
	memcpy(m->taskc_x.comm, p->comm, TASK_COMM_LEN);
	m->taskc_x.static_prio = get_nice_prio(p);
	m->taskc_x.cpu_util = cpuc->util / 10;
	m->taskc_x.cpu_id = cpu_id;
	m->taskc_x.avg_lat_cri = stat_cur->avg_lat_cri;
	m->taskc_x.thr_perf_cri = stat_cur->thr_perf_cri;
	m->taskc_x.nr_active = stat_cur->nr_active;
	m->taskc_x.cpuperf_cur = cpuc->cpuperf_cur;

	m->taskc_x.stat[0] = is_lat_cri(taskc, stat_cur) ? 'L' : 'R';
	m->taskc_x.stat[1] = is_perf_cri(taskc, stat_cur) ? 'H' : 'I';
	m->taskc_x.stat[2] = cpuc->big_core ? 'B' : 'T';
	m->taskc_x.stat[3] = is_greedy(taskc) ? 'G' : 'E';
	m->taskc_x.stat[4] = taskc->victim_cpu >= 0 ? 'P' : 'N';
	m->taskc_x.stat[5] = '\0';

	memcpy(&m->taskc, taskc, sizeof(m->taskc));

	bpf_ringbuf_submit(m, 0);

	return 0;
}

static void proc_introspec_sched_n(struct task_struct *p,
				   struct task_ctx *taskc, u32 cpu_id)
{
	u64 cur_nr, prev_nr;
	int i;

	/* introspec_arg is the number of schedules remaining */
	cur_nr = intrspc.arg;

	/*
	 * Note that the bounded retry (@LAVD_MAX_RETRY) does *not *guarantee*
	 * to decrement introspec_arg. However, it is unlikely to happen. Even
	 * if it happens, it is nothing but a matter of delaying a message
	 * delivery. That's because other threads will try and succeed the CAS
	 * operation eventually. So this is good enough. ;-)
	 */
	for (i = 0; cur_nr > 0 && i < LAVD_MAX_RETRY; i++) {
		prev_nr = __sync_val_compare_and_swap(
				&intrspc.arg, cur_nr, cur_nr - 1);
		/* CAS success: submit a message and done */
		if (prev_nr == cur_nr) {
			submit_task_ctx(p, taskc, cpu_id);
			break;
		}
		/* CAS failure: retry */
		cur_nr = prev_nr;
	}
}

static void proc_introspec_pid(struct task_struct *p, struct task_ctx *taskc,
			       u32 cpu_id)
{
	if (p->pid == intrspc.arg)
		submit_task_ctx(p, taskc, cpu_id);
}

static bool have_scheduled(struct task_ctx *taskc)
{
	/*
	 * If task's time slice hasn't been updated, that means the task has
	 * been scheduled by this scheduler.
	 */
	return taskc->slice_ns != 0;
}

static void try_proc_introspec_cmd(struct task_struct *p,
				   struct task_ctx *taskc, u32 cpu_id)
{
	if (LAVD_CPU_ID_HERE == cpu_id)
		cpu_id = bpf_get_smp_processor_id();

	switch(intrspc.cmd) {
	case LAVD_CMD_SCHED_N:
		proc_introspec_sched_n(p, taskc, cpu_id);
		break;
	case LAVD_CMD_NOP:
		/* do nothing */
		break;
	default:
		scx_bpf_error("Unknown introspec command: %d", intrspc.cmd);
		break;
	}
}

static u32 calc_avg32(u32 old_val, u32 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.75 * old) + (0.25 * new)
	 */
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static u64 calc_avg(u64 old_val, u64 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.75 * old) + (0.25 * new)
	 */
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static u64 calc_avg_freq(u64 old_freq, u64 interval)
{
	u64 new_freq, ewma_freq;

	/*
	 * Calculate the exponential weighted moving average (EWMA) of a
	 * frequency with a new interval measured.
	 */
	new_freq = LAVD_TIME_ONE_SEC / interval;
	ewma_freq = calc_avg(old_freq, new_freq);
	return ewma_freq;
}

struct sys_stat_ctx {
	struct sys_stat *stat_cur;
	struct sys_stat	*stat_next;
	u64		now;
	u64		duration;
	u64		duration_total;
	u64		idle_total;
	u64		compute_total;
	u64		load_actual;
	u64		tot_svc_time;
	u64		nr_queued_task;
	u64		load_run_time_ns;
	s32		max_lat_cri;
	s32		avg_lat_cri;
	u64		sum_lat_cri;
	u32		nr_sched;
	u32		nr_migration;
	u32		nr_preemption;
	u32		nr_greedy;
	u32		nr_perf_cri;
	u32		nr_lat_cri;
	u32		nr_big;
	u32		nr_pc_on_big;
	u32		nr_lc_on_big;
	u64		min_perf_cri;
	u64		avg_perf_cri;
	u64		max_perf_cri;
	u64		sum_perf_cri;
	u32		thr_perf_cri;
	u64		new_util;
	u32		nr_violation;
};

static void init_sys_stat_ctx(struct sys_stat_ctx *c)
{
	memset(c, 0, sizeof(*c));

	c->stat_cur = get_sys_stat_cur();
	c->stat_next = get_sys_stat_next();
	c->min_perf_cri = 1000;
	c->now = bpf_ktime_get_ns();
	c->duration = c->now - c->stat_cur->last_update_clk;
	c->stat_next->last_update_clk = c->now;
}

static void collect_sys_stat(struct sys_stat_ctx *c)
{
	u64 dsq_id;
	int cpu, nr;

	bpf_for(cpu, 0, nr_cpus_onln) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			c->compute_total = 0;
			break;
		}

		/*
		 * Accumulate cpus' loads.
		 */
		c->load_actual += cpuc->load_actual;
		c->load_run_time_ns += cpuc->load_run_time_ns;
		c->tot_svc_time += cpuc->tot_svc_time;
		cpuc->tot_svc_time = 0;

		/*
		 * Accumulate statistics.
		 */
		if (cpuc->big_core) {
			c->nr_big += cpuc->nr_sched;
			c->nr_pc_on_big += cpuc->nr_perf_cri;
			c->nr_lc_on_big += cpuc->nr_lat_cri;
		}
		c->nr_perf_cri += cpuc->nr_perf_cri;
		cpuc->nr_perf_cri = 0;

		c->nr_lat_cri += cpuc->nr_lat_cri;
		cpuc->nr_lat_cri = 0;

		c->nr_migration += cpuc->nr_migration;
		cpuc->nr_migration = 0;

		c->nr_preemption += cpuc->nr_preemption;
		cpuc->nr_preemption = 0;

		c->nr_greedy += cpuc->nr_greedy;
		cpuc->nr_greedy = 0;

		/*
		 * Accumulate task's latency criticlity information.
		 *
		 * While updating cpu->* is racy, the resulting impact on
		 * accuracy should be small and very rare and thus should be
		 * fine.
		 */
		c->sum_lat_cri += cpuc->sum_lat_cri;
		cpuc->sum_lat_cri = 0;

		c->nr_sched += cpuc->nr_sched;
		cpuc->nr_sched = 0;

		if (cpuc->max_lat_cri > c->max_lat_cri)
			c->max_lat_cri = cpuc->max_lat_cri;
		cpuc->max_lat_cri = 0;

		/*
		 * Accumulate task's performance criticlity information.
		 */
		if (cpuc->min_perf_cri < c->min_perf_cri)
			c->min_perf_cri = cpuc->min_perf_cri;
		cpuc->min_perf_cri = 1000;

		if (cpuc->max_perf_cri > c->max_perf_cri)
			c->max_perf_cri = cpuc->max_perf_cri;
		cpuc->max_perf_cri = 0;

		c->sum_perf_cri += cpuc->sum_perf_cri;
		cpuc->sum_perf_cri = 0;

		/*
		 * If the CPU is in an idle state (i.e., idle_start_clk is
		 * non-zero), accumulate the current idle peirod so far.
		 */
		for (int i = 0; i < LAVD_MAX_RETRY; i++) {
			u64 old_clk = cpuc->idle_start_clk;
			if (old_clk == 0)
				break;

			bool ret = __sync_bool_compare_and_swap(
					&cpuc->idle_start_clk, old_clk, c->now);
			if (ret) {
				cpuc->idle_total += c->now - old_clk;
				break;
			}
		}

		/*
		 * Calculcate per-CPU utilization
		 */
		u64 compute = 0;
		if (c->duration > cpuc->idle_total)
			compute = c->duration - cpuc->idle_total;

		c->new_util = (compute * LAVD_CPU_UTIL_MAX) / c->duration;
		cpuc->util = calc_avg(cpuc->util, c->new_util);

		if (cpuc->turbo_core) {
			if (cpuc->util > LAVD_CC_PER_TURBO_CORE_MAX_CTUIL)
				c->nr_violation += 1000;
		}
		else {
			if (cpuc->util > LAVD_CC_PER_CORE_MAX_CTUIL)
				c->nr_violation += 1000;
		}

		/*
		 * Accmulate system-wide idle time
		 */
		c->idle_total += cpuc->idle_total;
		cpuc->idle_total = 0;
	}
 
	bpf_for(dsq_id, 0, LAVD_CPDOM_MAX_NR) {
		nr = scx_bpf_dsq_nr_queued(dsq_id);
		if (nr > 0)
			c->nr_queued_task += nr;
	}
}

static void calc_sys_stat(struct sys_stat_ctx *c)
{
	c->duration_total = c->duration * nr_cpus_onln;
	if (c->duration_total > c->idle_total)
		c->compute_total = c->duration_total - c->idle_total;
	else
		c->compute_total = 0;
	c->new_util = (c->compute_total * LAVD_CPU_UTIL_MAX)/c->duration_total;

	if (c->nr_sched == 0) {
		/*
		 * When a system is completely idle, it is indeed possible
		 * nothing scheduled for an interval.
		 */
		c->max_lat_cri = c->stat_cur->max_lat_cri;
		c->avg_lat_cri = c->stat_cur->avg_lat_cri;

		c->min_perf_cri = c->stat_cur->min_perf_cri;
		c->max_perf_cri = c->stat_cur->max_perf_cri;
		c->avg_perf_cri = c->stat_cur->avg_perf_cri;
	}
	else {
		c->avg_lat_cri = c->sum_lat_cri / c->nr_sched;
		c->avg_perf_cri = c->sum_perf_cri / c->nr_sched;
	}
}

static void update_sys_stat_next(struct sys_stat_ctx *c)
{
	static int cnt = 0;
	u64 avg_svc_time = 0;

	/*
	 * Update the CPU utilization to the next version.
	 */
	struct sys_stat *stat_cur = c->stat_cur;
	struct sys_stat *stat_next = c->stat_next;

	stat_next->load_actual =
		calc_avg(stat_cur->load_actual, c->load_actual);
	stat_next->util =
		calc_avg(stat_cur->util, c->new_util);

	stat_next->max_lat_cri =
		calc_avg32(stat_cur->max_lat_cri, c->max_lat_cri);
	stat_next->avg_lat_cri =
		calc_avg32(stat_cur->avg_lat_cri, c->avg_lat_cri);
	stat_next->thr_lat_cri = stat_next->max_lat_cri -
		((stat_next->max_lat_cri - stat_next->avg_lat_cri) >> 1);

	stat_next->min_perf_cri =
		calc_avg32(stat_cur->min_perf_cri, c->min_perf_cri);
	stat_next->avg_perf_cri =
		calc_avg32(stat_cur->avg_perf_cri, c->avg_perf_cri);
	stat_next->max_perf_cri =
		calc_avg32(stat_cur->max_perf_cri, c->max_perf_cri);
	stat_next->thr_perf_cri =
		c->stat_cur->thr_perf_cri; /* will be updated later */

	stat_next->nr_violation =
		calc_avg32(stat_cur->nr_violation, c->nr_violation);

	if (c->nr_sched > 0)
		avg_svc_time = c->tot_svc_time / c->nr_sched;
	stat_next->avg_svc_time =
		calc_avg(stat_cur->avg_svc_time, avg_svc_time);

	stat_next->nr_queued_task =
		calc_avg(stat_cur->nr_queued_task, c->nr_queued_task);


	/*
	 * Half the statistics every minitue so the statistics hold the
	 * information on a few minutes.
	 */
	if (cnt++ == LAVD_SYS_STAT_DECAY_TIMES) {
		cnt = 0;
		stat_next->nr_sched >>= 1;
		stat_next->nr_migration >>= 1;
		stat_next->nr_preemption >>= 1;
		stat_next->nr_greedy >>= 1;
		stat_next->nr_perf_cri >>= 1;
		stat_next->nr_lat_cri >>= 1;
		stat_next->nr_big >>= 1;
		stat_next->nr_pc_on_big >>= 1;
		stat_next->nr_lc_on_big >>= 1;

		__sync_fetch_and_sub(&performance_mode_ns, performance_mode_ns/2);
		__sync_fetch_and_sub(&balanced_mode_ns, balanced_mode_ns/2);
		__sync_fetch_and_sub(&powersave_mode_ns, powersave_mode_ns/2);
	}

	stat_next->nr_sched += c->nr_sched;
	stat_next->nr_migration += c->nr_migration;
	stat_next->nr_preemption += c->nr_preemption;
	stat_next->nr_greedy += c->nr_greedy;
	stat_next->nr_perf_cri += c->nr_perf_cri;
	stat_next->nr_lat_cri += c->nr_lat_cri;
	stat_next->nr_big += c->nr_big;
	stat_next->nr_pc_on_big += c->nr_pc_on_big;
	stat_next->nr_lc_on_big += c->nr_lc_on_big;

	update_power_mode_time();
}

static void do_update_sys_stat(void)
{
	struct sys_stat_ctx c;

	/*
	 * Collect and prepare the next version of stat.
	 */
	init_sys_stat_ctx(&c);
	collect_sys_stat(&c);
	calc_sys_stat(&c);
	update_sys_stat_next(&c);

	/*
	 * Make the next version atomically visible.
	 */
	flip_sys_stat();
}

static u64 calc_nr_active_cpus(struct sys_stat *stat_cur)
{
	u64 nr_active;

	/*
	 * nr_active = ceil(nr_cpus_onln * cpu_util * per_core_max_util)
	 */
	nr_active  = (nr_cpus_onln * stat_cur->util * 1000) + 500;
	nr_active /= (LAVD_CC_PER_CORE_MAX_CTUIL * 1000);

	/*
	 * If a few CPUs are particularly busy, boost the active CPUs more.
	 */
	nr_active += min(LAVD_CC_NR_OVRFLW, (stat_cur->nr_violation) / 1000);
	nr_active = max(min(nr_active, nr_cpus_onln),
			LAVD_CC_NR_ACTIVE_MIN);

	return nr_active;
}

static bool clear_cpu_periodically(u32 cpu, struct bpf_cpumask *cpumask)
{
	u32 clear;

	/*
	 * If the CPU is on, we clear the bit once every four times
	 * (LAVD_CC_CPU_PIN_INTERVAL_DIV). Hence, the bit will be
	 * probabilistically cleared once every 100 msec (4 * 25 msec).
	 */
	clear = !(bpf_get_prandom_u32() % LAVD_CC_CPU_PIN_INTERVAL_DIV);
	if (clear)
		bpf_cpumask_clear_cpu(cpu, cpumask);

	return clear;
}

static void do_core_compaction(void)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
	int nr_cpus, nr_active, nr_active_old, cpu, i;
	u32 sum_capacity = 0, big_capacity = 0;
	bool clear;
	const volatile u16 *cpu_order;

	bpf_rcu_read_lock();

	/*
	 * Prepare cpumasks.
	 */
	active = active_cpumask;
	ovrflw = ovrflw_cpumask;
	if (!active || !ovrflw) {
		scx_bpf_error("Failed to prepare cpumasks.");
		goto unlock_out;
	}

	/*
	 * Decide a cpuorder to use according to its power mode.
	 */
	if (is_powersave_mode)
		cpu_order = cpu_order_powersave;
	else
		cpu_order = cpu_order_performance;

	/*
	 * Assign active and overflow cores
	 */
	nr_active_old = stat_cur->nr_active;
	nr_active = calc_nr_active_cpus(stat_cur);
	nr_cpus = nr_active + LAVD_CC_NR_OVRFLW;
	bpf_for(i, 0, nr_cpus_onln) {
		if (i >= LAVD_CPU_ID_MAX)
			break;

		/*
		 * Skip offline cpu
		 */
		cpu = cpu_order[i];
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc || !cpuc->is_online) {
			bpf_cpumask_clear_cpu(cpu, active);
			bpf_cpumask_clear_cpu(cpu, ovrflw);
			continue;
		}

		/*
		 * Assign an online cpu to active and overflow cpumasks
		 */
		if (i < nr_cpus) {
			if (i < nr_active) {
				bpf_cpumask_set_cpu(cpu, active);
				bpf_cpumask_clear_cpu(cpu, ovrflw);
			}
			else {
				bpf_cpumask_set_cpu(cpu, ovrflw);
				bpf_cpumask_clear_cpu(cpu, active);
			}
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

			/*
			 * Calculate big capacity ratio among active cores.
			 */
			sum_capacity += cpuc->capacity;
			if (cpuc->big_core)
				big_capacity += cpuc->capacity;
		}
		else {
			if (i < nr_active_old) {
				bpf_cpumask_clear_cpu(cpu, active);
				bpf_cpumask_clear_cpu(cpu, ovrflw);
			}
			else {
				/*
				 * This is the case when a CPU belongs to the
				 * overflow set even though that CPU was not an
				 * overflow set initially. This can happen only
				 * when a pinned userspace task ran on this
				 * CPU. In this case, we keep the CPU in an
				 * overflow set since the CPU will be used
				 * anyway for the task. This will promote equal
				 * use of all used CPUs, lowering the energy
				 * consumption by avoiding a few CPUs being
				 * turbo-boosted. Hence, we do not clear the
				 * overflow cpumask here for a while,
				 * approximately for LAVD_CC_CPU_PIN_INTERVAL.
				 */
				bpf_cpumask_clear_cpu(cpu, active);
				clear = clear_cpu_periodically(cpu, ovrflw);
				if (!clear)
					scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			}
		}
	}

	cur_big_core_ratio = (1000 * big_capacity) / sum_capacity;
	stat_cur->nr_active = nr_active;

unlock_out:
	bpf_rcu_read_unlock();
}

static void update_power_mode_time(void)
{
	u64 now = bpf_ktime_get_ns();
	u64 delta;

	if (last_power_mode_clk == 0)
		last_power_mode_clk = now;

	delta = now - last_power_mode_clk;
	last_power_mode_clk = now;

	switch (power_mode) {
	case LAVD_PM_PERFORMANCE:
		__sync_fetch_and_add(&performance_mode_ns, delta);
		break;
	case LAVD_PM_BALANCED:
		__sync_fetch_and_add(&balanced_mode_ns, delta);
		break;
	case LAVD_PM_POWERSAVE:
		__sync_fetch_and_add(&powersave_mode_ns, delta);
		break;
	}
}


static int do_set_power_profile(s32 pm, int util)
{
	/*
	 * Skip setting the mode if alreay in the same mode.
	 */
	if (power_mode == pm)
		return 0;

	/*
	 * Update power mode time
	 */
	update_power_mode_time();
	power_mode = pm;

	/*
	 * Change the power mode.
	 */
	switch (pm) {
	case LAVD_PM_PERFORMANCE:
		no_core_compaction = true;
		no_freq_scaling = true;
		no_prefer_turbo_core = false;
		is_powersave_mode = false;

		/*
		 * Since the core compaction becomes off, we need to
		 * reinitialize the active and overflow cpumask for performance
		 * mode.
		 *
		 * Note that a verifier in an old kernel does not allow calling
		 * bpf_cpumask_set_cpu(), so we defer the actual update to our
		 * timer handler, update_sys_stat().
		 */
		reinit_cpumask_for_performance = true;
		debugln("Set the scheduler's power profile to performance mode: %d", util);
		break;
	case LAVD_PM_BALANCED:
		no_core_compaction = false;
		no_freq_scaling = false;
		no_prefer_turbo_core = false;
		is_powersave_mode = false;
		reinit_cpumask_for_performance = false;
		debugln("Set the scheduler's power profile to balanced mode: %d", util);
		break;
	case LAVD_PM_POWERSAVE:
		no_core_compaction = false;
		no_freq_scaling = false;
		no_prefer_turbo_core = true;
		is_powersave_mode = true;
		reinit_cpumask_for_performance = false;
		debugln("Set the scheduler's power profile to power-save mode: %d", util);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int do_autopilot(void)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();

	/*
	 * If the CPU utiulization is very low (say <= 5%), it means high
	 * performance is not required. We run the scheduler in powersave mode
	 * to save energy consumption.
	 */
	if (stat_cur->util <= LAVD_AP_LOW_UTIL)
		return do_set_power_profile(LAVD_PM_POWERSAVE, stat_cur->util);

	/*
	 * If the CPU utiulization is moderate (say > 5%, <= 30%), we run the
	 * scheduler in balanced mode. Actually, balanced mode can save energy
	 * consumption only under moderate CPU load.
	 */
	if (stat_cur->util <= LAVD_AP_HIGH_UTIL)
		return do_set_power_profile(LAVD_PM_BALANCED, stat_cur->util);

	/*
	 * If the CPU utilization is high enough (say > 30%), we run the
	 * scheduler in performance mode. The system indeed needs perrformance
	 * also there is little energy benefit even under balanced mode anyway.
	 */
	return do_set_power_profile(LAVD_PM_PERFORMANCE, stat_cur->util);
}

static void update_thr_perf_cri(void)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u32 little_core_ratio, delta, diff, thr;

	if (no_core_compaction || !have_little_core)
		cur_big_core_ratio = default_big_core_ratio;

	/*
	 * If all active cores are big, all tasks should run on the big cores.
	 */
	if (cur_big_core_ratio == 1000) {
		stat_cur->thr_perf_cri = 0;
		return;
	}

	/*
	 * We approximate the distribution of performance criticality of tasks
	 * using min, avg, and max performance criticality of a given period.
	 *
	 *   min_perf_cri
	 *   |         avg_perf_cri
	 *   |         |                       max_perf_cri
	 *   |         |                       |
	 *   <--------><----------------------->
	 *
	 * The half of compute capacity should be assigned to the below average
	 * tasks (< avg_perf_cri), and the other half should assigned to the
	 * above average tasks (>= avg_perf_cri).
	 *
	 *   <------------><------------------->
	 *   |            |                    |
	 *   |            |                    1000
	 *   |            1000 - big_core_ratio (i.e., little_core_ratio)
	 *   0
	 */
	little_core_ratio = 1000 - cur_big_core_ratio;
	if (little_core_ratio < 500) {
		/*
		 *   min_perf_cri
		 *   |         avg_perf_cri
		 *   |         |                       max_perf_cri
		 *   |         |                       |
		 *   <--------><----------------------->
		 *
		 *   <-///-><-------------------------->
		 *   |     |                           |
		 *   |     |                           1000
		 *   |     little_core_ratio
		 *   0
		 */
		delta = stat_cur->avg_perf_cri - stat_cur->min_perf_cri;
		diff = (delta * little_core_ratio) / 1000;
		thr = diff + stat_cur->min_perf_cri;
	}
	else {
		/*
		 *   min_perf_cri
		 *   |         avg_perf_cri
		 *   |         |                       max_perf_cri
		 *   |         |                       |
		 *   <--------><----------------------->
		 *
		 *   <---------------------><-////////->
		 *   |                     |           |
		 *   |                     |           1000
		 *   |                     little_core_ratio
		 *   0
		 */
		delta = stat_cur->max_perf_cri - stat_cur->avg_perf_cri;
		diff = (delta * cur_big_core_ratio) / 1000;
		thr = stat_cur->max_perf_cri - diff;
	}

	stat_cur->thr_perf_cri = thr;
}

static void update_sys_stat(void)
{
	do_update_sys_stat();

	if (is_autopilot_on)
		do_autopilot();

	if (!no_core_compaction)
		do_core_compaction();

	update_thr_perf_cri();

	if (reinit_cpumask_for_performance) {
		reinit_cpumask_for_performance = false;
		reinit_active_cpumask_for_performance();
	}
}

static int update_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	update_sys_stat();

	err = bpf_timer_start(timer, LAVD_SYS_STAT_INTERVAL_NS, 0);
	if (err)
		scx_bpf_error("Failed to arm update timer");

	return 0;
}

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
	taskc->greedy_ratio = max(ratio, 1);
	return ratio;
}

static u16 get_nice_prio(struct task_struct *p)
{
	u16 prio = p->static_prio - MAX_RT_PRIO; /* [0, 40) */
	return prio;
}

static u64 calc_runtime_factor(u64 runtime)
{
	u64 ft = rsigmoid_u64(runtime, LAVD_LC_RUNTIME_MAX);
	return (ft >> LAVD_LC_RUNTIME_SHIFT) + 1;
}

static u64 calc_freq_factor(u64 freq)
{
	u64 ft = sigmoid_u64(freq, LAVD_LC_FREQ_MAX);
	return ft + 1;
}

static s64 calc_static_prio_factor(struct task_struct *p)
{
	/*
	 * A nicer task with >20 static priority will get penalized with
	 * negative latency-criticality. However, a greedier task with <20
	 * static priority will get boosted.
	 */
	return (20 - get_nice_prio(p)) >> 1;
}

static bool is_kernel_task(struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

static u64 calc_lat_cri(struct task_struct *p, struct task_ctx *taskc,
			u64 enq_flags)
{
	u64 wait_freq_ft, wake_freq_ft, runtime_ft;
	u64 lat_cri;

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
	wait_freq_ft = calc_freq_factor(taskc->wait_freq);
	wake_freq_ft = calc_freq_factor(taskc->wake_freq);
	runtime_ft = calc_runtime_factor(taskc->run_time_ns);

	/*
	 * Wake frequency and wait frequency represent how much a task is used
	 * for a producer and a consumer, respectively. If both are high, the
	 * task is in the middle of a task chain. The ratio tends to follow an
	 * exponentially skewed distribution, so we linearize it using log2. We
	 * add +1 to guarantee the latency criticality (log2-ed) is always
	 * positive.
	 */
	lat_cri = log2_u64(runtime_ft * wait_freq_ft + 1) +
		  log2_u64(wake_freq_ft * wake_freq_ft + 1);

	/*
	 * A user-provided nice value is a strong hint for latency-criticality.
	 */
	lat_cri += calc_static_prio_factor(p);

	/*
	 * Prioritize a wake-up task since this is a clear sign of immediate
	 * consumer. If it is a synchronous wakeup, doule the prioritization.
	 */
	taskc->wakeup_ft += !!(enq_flags & SCX_ENQ_WAKEUP);
	lat_cri += taskc->wakeup_ft * LAVD_LC_WAKEUP_FT;

	/*
	 * Prioritize a kernel task since many kernel tasks serve
	 * latency-critical jobs.
	 */
	if (is_kernel_task(p))
		lat_cri += LAVD_LC_KTHREAD_FT;

	/*
	 * Make sure the lat_cri is non-zero.
	 */
	taskc->lat_cri_self = max(lat_cri, 1);

	/*
	 * Determine latency criticality of a task in a context-aware manner by
	 * considering which task wakes up this task. If its waker is more
	 * latency-critcial, inherit waker's latency criticality.
	 */
	taskc->lat_cri = max(taskc->lat_cri_self, taskc->lat_cri_waker);

	return taskc->lat_cri;
}

static void calc_virtual_deadline_delta(struct task_struct *p,
					struct task_ctx *taskc, u64 enq_flags)
{
	u64 deadline, lat_cri, greedy_ratio;

	/*
	 * Calculate the deadline based on latency criticality and greedy ratio.
	 */
	lat_cri = calc_lat_cri(p, taskc, enq_flags);
	greedy_ratio = calc_greedy_ratio(taskc);
	deadline = (LAVD_SLICE_MAX_NS * greedy_ratio) / (1000 * lat_cri);
	taskc->vdeadline_delta_ns = deadline;
}

static u64 calc_task_load_actual(struct task_ctx *taskc)
{
	/*
	 * The actual load is the CPU time consumed in a time interval, which
	 * can be calculated from task's average run time and frequency.
	 */
	const s64 interval_adj = LAVD_TIME_ONE_SEC / LAVD_SYS_STAT_INTERVAL_NS;
	return (taskc->run_time_ns * taskc->run_freq) / interval_adj;
}

static u64 clamp_time_slice_ns(u64 slice)
{
	if (slice < LAVD_SLICE_MIN_NS)
		slice = LAVD_SLICE_MIN_NS;
	else if (slice > LAVD_SLICE_MAX_NS)
		slice = LAVD_SLICE_MAX_NS;
	return slice;
}

static u64 calc_time_slice(struct task_struct *p, struct task_ctx *taskc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 nr_queued, slice;

	/*
	 * The time slice should be short enough to schedule all runnable tasks
	 * at least once within a targeted latency.
	 */
	nr_queued = stat_cur->nr_queued_task + 1;
	slice = (LAVD_TARGETED_LATENCY_NS * stat_cur->nr_active) / nr_queued;

	/*
	 * Keep the slice in [LAVD_SLICE_MIN_NS, LAVD_SLICE_MAX_NS].
	 */
	slice = clamp_time_slice_ns(slice);

	/*
	 * Boost time slice for CPU-bound tasks.
	 */
	if (is_eligible(taskc)) {
		slice += (LAVD_SLICE_BOOST_MAX_FT * slice *
			  taskc->slice_boost_prio) / LAVD_SLICE_BOOST_MAX_STEP;
	}

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
		duration = cpuc->online_clk - cpuc->offline_clk;
		/*
		 * Once calculated, reset the duration to zero.
		 */
		cpuc->offline_clk = cpuc->online_clk;
	}

	return duration;
}

static void update_stat_for_runnable(struct task_struct *p,
				     struct task_ctx *taskc,
				     struct cpu_ctx *cpuc)
{
	/*
	 * Reflect task's load immediately.
	 */
	taskc->load_actual = calc_task_load_actual(taskc);
	taskc->acc_run_time_ns = 0;
	cpuc->load_actual += taskc->load_actual;
	cpuc->load_run_time_ns += clamp_time_slice_ns(taskc->run_time_ns);
}

static void advance_cur_logical_clk(struct task_ctx *taskc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 vlc, clc;
	u64 nr_queued, delta, new_clk;

	/*
	 * The clock should not go backward, so do nothing.
	 */
	vlc = READ_ONCE(taskc->vdeadline_log_clk);
	clc = READ_ONCE(cur_logical_clk);
	if (vlc <= clc)
		return;

	/*
	 * Advance the clock up to the task's deadline. When overloaded,
	 * advance the clock slower so other can jump in the run queue.
	 */
	nr_queued = max(stat_cur->nr_queued_task, 1);
	delta = (vlc - clc) / nr_queued;
	new_clk = clc + delta;

	WRITE_ONCE(cur_logical_clk, new_clk);
}

static void update_stat_for_running(struct task_struct *p,
				    struct task_ctx *taskc,
				    struct cpu_ctx *cpuc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 wait_period, interval;
	u64 now = bpf_ktime_get_ns();
	u64 wait_freq_ft, wake_freq_ft, perf_cri;

	/*
	 * Update the current logical clock.
	 */
	advance_cur_logical_clk(taskc);

	/*
	 * Since this is the start of a new schedule for @p, we update run
	 * frequency in a second using an exponential weighted moving average.
	 */
	if (have_scheduled(taskc)) {
		wait_period = now - taskc->last_quiescent_clk;
		interval = taskc->run_time_ns + wait_period;
		taskc->run_freq = calc_avg_freq(taskc->run_freq, interval);
	}

	/*
	 * Update per-CPU latency criticality information for ever-scheduled
	 * tasks.
	 */
	if (cpuc->max_lat_cri < taskc->lat_cri)
		cpuc->max_lat_cri = taskc->lat_cri;
	cpuc->sum_lat_cri += taskc->lat_cri;
	cpuc->nr_sched++;

	/*
	 * It is clear there is no need to consider the suspended duration
	 * while running a task, so reset the suspended duration to zero.
	 */
	reset_suspended_duration(cpuc);

	/*
	 * Update task's performance criticality
	 *
	 * A task is more CPU-performance sensitive when it meets the following
	 * conditions:
	 *
	 * - It is in the middle of the task graph (high wait and wake
	 *   frequencies).
	 * - Its runtime and frequency are high;
	 * - Its nice priority is high;
	 * - It is a woken-up task.
	 *
	 * We use the log-ed value since the raw value follows the highly
	 * skewed distribution.
	 */
	wait_freq_ft = calc_freq_factor(taskc->wait_freq);
	wake_freq_ft = calc_freq_factor(taskc->wake_freq);
	perf_cri = log2_u64(wait_freq_ft * wake_freq_ft * wake_freq_ft);
	perf_cri += log2_u64(max(taskc->run_freq, 1) *
			     max(taskc->run_time_ns, 1));
	perf_cri += calc_static_prio_factor(p);
	perf_cri += taskc->wakeup_ft * LAVD_LC_WAKEUP_FT;
	taskc->wakeup_ft = 0;

	taskc->perf_cri = perf_cri;
	if (cpuc->max_perf_cri < taskc->perf_cri)
		cpuc->max_perf_cri = taskc->perf_cri;
	if (cpuc->min_perf_cri > taskc->perf_cri)
		cpuc->min_perf_cri = taskc->perf_cri;
	cpuc->sum_perf_cri += taskc->perf_cri;

	/*
	 * Update task state when starts running.
	 */
	taskc->last_running_clk = now;

	/*
	 * Update statistics information.
	 */
	if (taskc->cpu_id != cpuc->cpu_id) {
		taskc->cpu_id = cpuc->cpu_id;
		cpuc->nr_migration++;
	}

	if (taskc->victim_cpu >= 0)
		cpuc->nr_preemption++;
	
	if (is_lat_cri(taskc, stat_cur))
		cpuc->nr_lat_cri++;

	if (is_perf_cri(taskc, stat_cur))
		cpuc->nr_perf_cri++;

	if (is_greedy(taskc))
		cpuc->nr_greedy++;
}

static void update_stat_for_stopping(struct task_struct *p,
				     struct task_ctx *taskc,
				     struct cpu_ctx *cpuc)
{
	u64 now = bpf_ktime_get_ns();
	u64 old_run_time_ns, suspended_duration, task_run_time;

	/*
	 * Update task's run_time. When a task is scheduled consecutively
	 * without ops.quiescent(), the task's runtime is accumulated for
	 * statistics. Suppose a task is scheduled 2ms, 2ms, and 2ms with the
	 * time slice exhausted. If 6ms of time slice was given in the first
	 * place, the task will entirely consume the time slice. Hence, the
	 * consecutive execution is accumulated and reflected in the
	 * calculation of runtime statistics.
	 */
	old_run_time_ns = taskc->run_time_ns;
	suspended_duration = get_suspended_duration_and_reset(cpuc);
	task_run_time = now - taskc->last_running_clk - suspended_duration;
	taskc->acc_run_time_ns += task_run_time;
	taskc->run_time_ns = calc_avg(taskc->run_time_ns, taskc->acc_run_time_ns);
	taskc->last_stopping_clk = now;

	taskc->svc_time += task_run_time / p->scx.weight;
	taskc->victim_cpu = (s32)LAVD_CPU_ID_NONE;

	/*
	 * Reset waker's latency criticality here to limit the latency boost of
	 * a task. A task will be latency-boosted only once after wake-up.
	 */
	taskc->lat_cri_waker = 0;

	/*
	 * After getting updated task's runtime, compensate CPU's total
	 * runtime.
	 */
	cpuc->load_run_time_ns = cpuc->load_run_time_ns -
				 clamp_time_slice_ns(old_run_time_ns) +
				 clamp_time_slice_ns(taskc->run_time_ns);
	/*
	 * Increase total service time of this CPU.
	 */
	cpuc->tot_svc_time += taskc->svc_time;

	/*
	 * Update the current service time if necessary.
	 */
	if (READ_ONCE(cur_svc_time) < taskc->svc_time)
		WRITE_ONCE(cur_svc_time, taskc->svc_time);
}

static void update_stat_for_quiescent(struct task_struct *p,
				      struct task_ctx *taskc,
				      struct cpu_ctx *cpuc)
{
	/*
	 * When quiescent, reduce the per-CPU task load. Per-CPU task load will
	 * be aggregated periodically at update_sys_cpu_load().
	 */
	cpuc->load_actual -= taskc->load_actual;
	cpuc->load_run_time_ns -= clamp_time_slice_ns(taskc->run_time_ns);
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
s32 pick_idle_cpu_in(struct bpf_cpumask *cpumask)
{
	s32 cpu_id;

	if (is_smt_active) {
		/*
		 * Pick a fully idle core within a cpumask.
		 */
		cpu_id = scx_bpf_pick_idle_cpu(cast_mask(cpumask),
					       SCX_PICK_IDLE_CORE);
	}

	if (!is_smt_active || cpu_id < 0) {
		/*
		 * Pick a fully idle core within a cpumask even if its
		 * hypertwin is in use.
		 */
		cpu_id = scx_bpf_pick_idle_cpu(cast_mask(cpumask), 0);
	}

	return cpu_id;
}

static s32 pick_idle_cpu(struct task_struct *p, struct task_ctx *taskc,
			 s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc, *cpuc_prev, *cpuc_waker;
	struct bpf_cpumask *a_cpumask, *o_cpumask, *t_cpumask, *t2_cpumask;
	struct bpf_cpumask *active, *ovrflw, *big, *little;
	struct bpf_cpumask *cpdom_mask_prev, *cpdom_mask_waker;
	s32 cpu_id, waker_cpu;

	/*
	 * If a task can run only on a single CPU (e.g., per-CPU kworker), we
	 * simply check if a task is still pinned on the prev_cpu and go.
	 */
	if (p->nr_cpus_allowed == 1 &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
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

	cpdom_mask_prev = MEMBER_VPTR(cpdom_cpumask, [cpuc_prev->cpdom_id]);
	if (!cpdom_mask_prev) {
		scx_bpf_error("Failed to lookup cpdom_cpumask for %d",
			      cpuc_prev->cpdom_id);
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	waker_cpu = bpf_get_smp_processor_id();
	cpuc_waker = get_cpu_ctx_id(waker_cpu);
	if (!cpuc_waker) {
		scx_bpf_error("Failed to lookup the current cpu_ctx");
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	cpdom_mask_waker = MEMBER_VPTR(cpdom_cpumask, [cpuc_waker->cpdom_id]);
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
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
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
	    scx_bpf_test_and_clear_cpu_idle(waker_cpu)) {
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

	cpu_id = pick_idle_cpu_in(t2_cpumask);
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

	cpu_id = pick_idle_cpu_in(t2_cpumask);
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

		cpu_id = pick_idle_cpu_in(t2_cpumask);
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
		cpu_id = pick_idle_cpu_in(t_cpumask);
		if (cpu_id >= 0) {
			*is_idle = true;
			goto unlock_out;
		}
	}

	/*
	 * Pick a idle core among active CPUs.
	 */
	cpu_id = pick_idle_cpu_in(a_cpumask);
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

	cpu_id = scx_bpf_pick_idle_cpu(cast_mask(o_cpumask), 0);
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

	/*
	 * Note that we don't need to kick the picked CPU here since the
	 * ops.select_cpu() path internally triggers kicking cpu if necessary.
	 */
unlock_out:
	bpf_rcu_read_unlock();
out:
	return cpu_id;
}

s32 BPF_STRUCT_OPS(lavd_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool found_idle = false;
	struct task_ctx *taskc;
	s32 cpu_id;

	taskc = get_task_ctx(p);
	if (!taskc)
		return prev_cpu;

	cpu_id = pick_idle_cpu(p, taskc, prev_cpu, wake_flags, &found_idle);
	if (found_idle)
		return cpu_id;

	taskc->wakeup_ft += !!(wake_flags & SCX_WAKE_SYNC);

	return (cpu_id >= 0) ? cpu_id : prev_cpu;
}


static void calc_when_to_run(struct task_struct *p, struct task_ctx *taskc,
			     u64 enq_flags)
{
	u64 vlc;

	/*
	 * Before enqueueing a task to a run queue, we should decide when a
	 * task should be scheduled.
	 */
	calc_virtual_deadline_delta(p, taskc, enq_flags);

	/*
	 * Update the logical clock of the virtual deadline.
	 */
	vlc = READ_ONCE(cur_logical_clk) + taskc->vdeadline_delta_ns;
	WRITE_ONCE(taskc->vdeadline_log_clk, vlc);
}

static u64 get_est_stopping_time(struct task_ctx *taskc)
{
	return bpf_ktime_get_ns() + taskc->run_time_ns;
}

static int comp_preemption_info(struct preemption_info *prm_a,
				struct preemption_info *prm_b)
{
	/*
	 * Check if one's latency priority _or_ deadline is smaller or not.
	 */
	if ((prm_a->lat_cri < prm_b->lat_cri) ||
	    (prm_a->stopping_tm_est_ns < prm_b->stopping_tm_est_ns))
		return -1;
	if ((prm_a->lat_cri > prm_b->lat_cri) ||
	    (prm_a->stopping_tm_est_ns > prm_b->stopping_tm_est_ns))
		return 1;
	return 0;
}

static  bool can_task1_kick_task2(struct preemption_info *prm_task1,
				  struct preemption_info *prm_task2)
{
	return comp_preemption_info(prm_task1, prm_task2) < 0;
}

static  bool can_cpu1_kick_cpu2(struct preemption_info *prm_cpu1,
				struct preemption_info *prm_cpu2,
				struct cpu_ctx *cpuc2)
{
	/*
	 * Set a CPU information
	 */
	prm_cpu2->stopping_tm_est_ns = cpuc2->stopping_tm_est_ns;
	prm_cpu2->lat_cri = cpuc2->lat_cri;
	prm_cpu2->cpuc = cpuc2;
	prm_cpu2->last_kick_clk = cpuc2->last_kick_clk;

	/*
	 * If that CPU runs a lower priority task, that's a victim
	 * candidate.
	 */
	return can_task1_kick_task2(prm_cpu1, prm_cpu2);
}

static bool is_worth_kick_other_task(struct task_ctx *taskc)
{
	/*
	 * The scx_bpf_kick_cpu() used for preemption is expensive as an IPI is
	 * involved. Hence, we first judiciously check whether it is worth
	 * trying to victimize another CPU as the current task is urgent
	 * enough.
	 */
	struct sys_stat *stat_cur = get_sys_stat_cur();

	return (taskc->lat_cri >= stat_cur->thr_lat_cri);
}

static bool can_cpu_be_kicked(u64 now, struct cpu_ctx *cpuc)
{
	u64 delta = now - cpuc->last_kick_clk;
	return delta >= LAVD_PREEMPT_KICK_MARGIN;
}

static struct cpu_ctx *find_victim_cpu(const struct cpumask *cpumask,
				       struct task_ctx *taskc,
				       u64 *p_old_last_kick_clk)
{
	/*
	 * We see preemption as a load-balancing problem. In a system with N
	 * CPUs, ideally, the top N tasks with the highest latency priorities
	 * should run on the N CPUs all the time. This is the same as the
	 * load-balancing problem; the load-balancing problem finds a least
	 * loaded server, and the preemption problem finds a CPU running a
	 * least latency critical task. Hence, we use the 'power of two random
	 * choices' technique.
	 */
	u64 now = bpf_ktime_get_ns();
	struct cpu_ctx *cpuc;
	struct preemption_info prm_task, prm_cpus[2], *victim_cpu;
	int cpu, nr_cpus;
	int i, v = 0, cur_cpu = bpf_get_smp_processor_id();
	int ret;

	/*
	 * Get task's preemption information for comparison.
	 */
	prm_task.stopping_tm_est_ns = get_est_stopping_time(taskc) +
				      LAVD_PREEMPT_KICK_MARGIN;
	prm_task.lat_cri = taskc->lat_cri;
	prm_task.cpuc = cpuc = get_cpu_ctx();
	if (!cpuc) {
		scx_bpf_error("Failed to lookup the current cpu_ctx");
		goto null_out;
	}
	prm_task.last_kick_clk = cpuc->last_kick_clk;

	/*
	 * First, test the current CPU since it can skip the expensive IPI.
	 */
	if (can_cpu_be_kicked(now, cpuc) &&
	    bpf_cpumask_test_cpu(cur_cpu, cpumask) &&
	    can_cpu1_kick_cpu2(&prm_task, &prm_cpus[0], cpuc)) {
		victim_cpu = &prm_task;
		goto bingo_out;
	}

	/*
	 * If the current CPU cannot be a victim, let's check if it is worth to
	 * try to kick other CPU at the expense of IPI.
	 */
	if (!is_worth_kick_other_task(taskc))
		goto null_out;

	/*
	 * Randomly find _two_ CPUs that run lower-priority tasks than @p. To
	 * traverse CPUs in a random order, we start from a random CPU ID in a
	 * random direction (left or right). The random-order traversal helps
	 * to mitigate the thundering herd problem. Otherwise, all CPUs may end
	 * up finding the same victim CPU.
	 *
	 * In the worst case, the current logic traverses _all_ CPUs. It would
	 * be too expensive to perform every task queue. We need to revisit
	 * this if the traversal cost becomes problematic.
	 */
	barrier();
	nr_cpus = bpf_cpumask_weight(cpumask);
	bpf_for(i, 0, nr_cpus_onln) {
		/*
		 * Decide a CPU ID to examine.
		 */
		cpu = bpf_cpumask_any_distribute(cpumask);

		/*
		 * Check whether that CPU is qualified to run @p.
		 */
		if (cur_cpu == cpu || !can_cpu_be_kicked(now, cpuc))
			continue;

		/*
		 * If that CPU runs a lower priority task, that's a victim
		 * candidate.
		 */
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			goto null_out;
		}
		ret = can_cpu1_kick_cpu2(&prm_task, &prm_cpus[v], cpuc);
		if (ret == true && ++v >= 2)
			break;
	}

	/*
	 * Choose a final victim CPU.
	 */
	switch(v) {
	case 2:	/* two dandidates */
		victim_cpu = can_task1_kick_task2(&prm_cpus[0], &prm_cpus[1]) ?
				&prm_cpus[0] : &prm_cpus[1];
		goto bingo_out;
	case 1:	/* one candidate */
		victim_cpu = &prm_cpus[0];
		goto bingo_out;
	case 0:	/* no candidate */
		goto null_out;
	default:/* something wrong */
		goto null_out;
	}

bingo_out:
	taskc->victim_cpu = victim_cpu->cpuc->cpu_id;
	*p_old_last_kick_clk = victim_cpu->last_kick_clk;
	return victim_cpu->cpuc;

null_out:
	taskc->victim_cpu = (s32)LAVD_CPU_ID_NONE;
	return NULL;
}

static bool kick_cpu(struct cpu_ctx *victim_cpuc, u64 victim_last_kick_clk)
{
	/*
	 * If the current CPU is a victim, we just reset the current task's
	 * time slice as an optimization. Othewise, kick the remote CPU for
	 * preemption.
	 *
	 * Kicking the victim CPU does _not_ guarantee that task @p will run on
	 * that CPU. Enqueuing @p to the global queue is one operation, and
	 * kicking the victim is another asynchronous operation. However, it is
	 * okay because, anyway, the victim CPU will run a higher-priority task
	 * than @p.
	 */
	if (bpf_get_smp_processor_id() == victim_cpuc->cpu_id) {
		struct task_struct *tsk = bpf_get_current_task_btf();
		tsk->scx.slice = 0;
		return true;
	}

	/*
	 * Kick the remote victim CPU if it is not victimized yet by another
	 * concurrent kick task.
	 */
	bool ret = __sync_bool_compare_and_swap(&victim_cpuc->last_kick_clk,
						victim_last_kick_clk,
						bpf_ktime_get_ns());
	if (ret)
		scx_bpf_kick_cpu(victim_cpuc->cpu_id, SCX_KICK_PREEMPT);

	return ret;
}

static bool try_find_and_kick_victim_cpu(struct task_struct *p,
					 struct task_ctx *taskc,
					 struct cpu_ctx *cpuc_cur,
					 u64 dsq_id)
{
	struct bpf_cpumask *cd_cpumask, *cpumask;
	struct cpdom_ctx *cpdomc;
	struct cpu_ctx *victim_cpuc;
	u64 victim_last_kick_clk;
	bool ret = false;

	/*
	 * Prepare a cpumak so we find a victim @p's compute domain.
	 */
	cpumask = cpuc_cur->tmp_t_mask;
	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [dsq_id]);
	if (!cpdomc || !cd_cpumask || !cpumask)
		return false;

	bpf_cpumask_and(cpumask, cast_mask(cd_cpumask), cast_mask(p->cpus_ptr));

	/*
	 * Find a victim CPU among CPUs that run lower-priority tasks.
	 */
	victim_cpuc = find_victim_cpu(cast_mask(cpumask), taskc, &victim_last_kick_clk);

	/*
	 * If a victim CPU is chosen, preempt the victim by kicking it.
	 */
	if (victim_cpuc)
		ret = kick_cpu(victim_cpuc, victim_last_kick_clk);

	if (!ret)
		taskc->victim_cpu = (s32)LAVD_CPU_ID_NONE;

	return ret;
}

static bool try_yield_current_cpu(struct task_struct *p_run,
				  struct cpu_ctx *cpuc_run,
				  struct task_ctx *taskc_run)
{
	struct task_struct *p_wait;
	struct task_ctx *taskc_wait;
	struct preemption_info prm_run, prm_wait;
	s32 cpu_id = scx_bpf_task_cpu(p_run), wait_vtm_cpu_id;
	bool ret = false;

	/*
	 * If there is a higher priority task waiting on the global rq, the
	 * current running task yield the CPU by shrinking its time slice to
	 * zero.
	 */
	prm_run.stopping_tm_est_ns = taskc_run->last_running_clk +
				     taskc_run->run_time_ns -
				     LAVD_PREEMPT_TICK_MARGIN;
	prm_run.lat_cri = taskc_run->lat_cri;

	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p_wait, cpuc_run->cpdom_id, 0) {
		taskc_wait = get_task_ctx(p_wait);
		if (!taskc_wait)
			break;

		wait_vtm_cpu_id = taskc_wait->victim_cpu;
		if (wait_vtm_cpu_id != (s32)LAVD_CPU_ID_NONE)
			break;

		prm_wait.stopping_tm_est_ns = get_est_stopping_time(taskc_wait);
		prm_wait.lat_cri = taskc_wait->lat_cri;

		if (can_task1_kick_task2(&prm_wait, &prm_run)) {
			/*
			 * The atomic CAS guarantees only one task yield its
			 * CPU for the waiting task.
			 */
			ret = __sync_bool_compare_and_swap(
					&taskc_wait->victim_cpu,
					(s32)LAVD_CPU_ID_NONE, cpu_id);
			if (ret)
				p_run->scx.slice = 0;
		}

		/*
		 * Test only the first entry on the DSQ.
		 */
		break;
	}
	bpf_rcu_read_unlock();

	return ret;
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

void BPF_STRUCT_OPS(lavd_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cpuc_task, *cpuc_cur;
	struct task_ctx *taskc;
	s32 cpu_id;
	u64 dsq_id;

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
	cpu_id = scx_bpf_task_cpu(p);
	taskc = get_task_ctx(p);
	cpuc_task = get_cpu_ctx_id(cpu_id);
	cpuc_cur = get_cpu_ctx();
	if (!cpuc_cur || !cpuc_task || !taskc)
		return;

	/*
	 * Calculate when a tack can be scheduled.
	 *
	 * Note that the task's time slice will be calculated and reassigned
	 * right before running at ops.running().
	 */
	calc_when_to_run(p, taskc, enq_flags);
	dsq_id = find_proper_dsq(taskc, cpuc_task);

	/*
	 * If a task is eligible, try to preempt a task.
	 */
	if (is_eligible(taskc)) {
		struct task_ctx *taskc_run;
		struct task_struct *p_run;
		/*
		 * Try to find and kick a victim CPU, which runs a less urgent
		 * task. The kick will be done asynchronously.
		 */
		try_find_and_kick_victim_cpu(p, taskc, cpuc_cur, dsq_id);

		/*
		 * If the current task has something to yield, try preempt it.
		 */
		p_run = bpf_get_current_task_btf();
		taskc_run = try_get_task_ctx(p_run);
		if (taskc_run && p_run->scx.slice != 0)
			try_yield_current_cpu(p_run, cpuc_cur, taskc_run);
	}

	/*
	 * Calculate the task's time slice.
	 */
	p->scx.slice = calc_time_slice(p, taskc);

	/*
	 * Enqueue the task to one of task's DSQs based on its virtual deadline.
	 */
	scx_bpf_dispatch_vtime(p, dsq_id, p->scx.slice,
			       taskc->vdeadline_log_clk, enq_flags);
}

static bool use_full_cpus(void)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	return (stat_cur->nr_active + LAVD_CC_NR_OVRFLW) >= nr_cpus_onln;
}

static u64 pick_any_bit(u64 bitmap, u64 nuance)
{
	u64 i, pos;

	bpf_for(i, 0, 64) {
		pos = (i + nuance) % 64;
		if (bitmap & (1LLU << pos))
			return pos;
	}

	return -ENOENT;
}

static bool consume_dsq(s32 cpu, u64 dsq_id, u64 now)
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
	WRITE_ONCE(cpdomc->last_consume_clk, now);

	/*
	 * Try to consume a task on the associated DSQ.
	 */
	if (scx_bpf_consume(dsq_id))
		return true;
	return false;
}

static bool consume_starving_task(s32 cpu, struct cpu_ctx *cpuc, u64 now)
{
	struct cpdom_ctx *cpdomc;
	u64 dsq_id = cpuc->cpdom_poll_pos;
	u64 dl;
	bool ret = false;
	int i;

	bpf_for(i, 0, LAVD_CPDOM_MAX_NR) {
		dsq_id = (dsq_id + i) % LAVD_CPDOM_MAX_NR;

		if (dsq_id == cpuc->cpdom_id)
			continue;
	
		cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
		if (!cpdomc) {
			scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
			goto out;
		}
	
		if (cpdomc->is_active) {
			dl = READ_ONCE(cpdomc->last_consume_clk) + LAVD_CPDOM_STARV_NS;
			if (dl < now) {
				ret = consume_dsq(cpu, dsq_id, now);
			}
			goto out;
		}
	}
out:
	cpuc->cpdom_poll_pos = (dsq_id + 1) % LAVD_CPDOM_MAX_NR;
	return ret;
}

static bool consume_task(s32 cpu, struct cpu_ctx *cpuc, u64 now)
{
	struct cpdom_ctx *cpdomc, *cpdomc_pick;
	u64 dsq_id, nr_nbr;
	s64 nuance;

	/*
	 * If there is a starving DSQ, try to consume it first.
	 */
	if (consume_starving_task(cpu, cpuc, now))
		return true;

	/*
	 * Try to consume from CPU's associated DSQ.
	 */
	dsq_id = cpuc->cpdom_id;
	if (consume_dsq(cpu, dsq_id, now))
		return true;

	/*
	 * If there is no task in the assssociated DSQ, traverse neighbor
	 * compute domains in distance order -- task stealing.
	 */
	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
		return false;
	}

	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		nuance = bpf_get_prandom_u32();
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
	
			if (consume_dsq(cpu, dsq_id, now))
				return true;
		}
	}
	
	return false;
}

void BPF_STRUCT_OPS(lavd_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 now = bpf_ktime_get_ns();
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
	struct task_struct *p;
	struct task_ctx *taskc;
	u64 dsq_id = 0;
	bool try_consume = false;

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc) {
		scx_bpf_error("Failed to look up cpu context or task context");
		return;
	}
	dsq_id = cpuc->cpdom_id;

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
		 * Note that this path is not optimized since scx_bpf_consume()
		 * should traverse until it finds any task that can run on this
		 * CPU. The scheduled task might be runnable on the active
		 * cores. We will optimize this path after introducing per-core
		 * DSQ.
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
	if (!try_consume)
		return;
	if (consume_task(cpu, cpuc, now))
		return;

	/*
	 * If no other task is consumed, the scheduler will keep continue to
	 * run the prev task, so let's re-assigne its time slice.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		taskc = get_task_ctx(prev);
		if (!taskc) {
			scx_bpf_error("Failed to look up task context");
			return;
		}
		prev->scx.slice = calc_time_slice(prev, taskc);
	}
}

static int calc_cpuperf_target(struct sys_stat *stat_cur,
			       struct task_ctx *taskc, struct cpu_ctx *cpuc)
{
	u64 max_load, cpu_load;
	u32 cpuperf_target;

	if (!stat_cur || !taskc || !cpuc)
		return -EINVAL;

	if (no_freq_scaling) {
		cpuc->cpuperf_task = SCX_CPUPERF_ONE;
		cpuc->cpuperf_avg = SCX_CPUPERF_ONE;
		return 0;
	}

	/*
	 * We determine the clock frequency of a CPU using two factors: 1) the
	 * current CPU utilization (cpuc->util) and 2) the current task's
	 * performance criticality (taskc->perf_cri) compared to the
	 * system-wide average performance criticality
	 * (stat_cur->thr_perf_cri).
	 *
	 * When a current CPU utilization is 85% and the current task's
	 * performance criticality is the same as the system-wide average
	 * criticality, we set the target CPU frequency to the maximum.
	 *
	 * In other words, even if CPU utilization is not so high, the target
	 * CPU frequency could be high when the task's performance criticality
	 * is high enough (i.e., boosting CPU frequency). On the other hand,
	 * the target CPU frequency could be low even if CPU utilization is
	 * high when a non-performance-critical task is running (i.e.,
	 * deboosting CPU frequency).
	 */
	max_load = stat_cur->thr_perf_cri * LAVD_CPU_UTIL_MAX_FOR_CPUPERF;
	cpu_load = taskc->perf_cri * cpuc->util;
	cpuperf_target = (cpu_load * SCX_CPUPERF_ONE) / max_load;
	cpuperf_target = min(cpuperf_target, SCX_CPUPERF_ONE);

	cpuc->cpuperf_task = cpuperf_target;
	cpuc->cpuperf_avg = calc_avg32(cpuc->cpuperf_avg, cpuperf_target);
	return 0;
}

static bool try_increase_cpuperf_target(struct cpu_ctx *cpuc)
{
	/*
	 * When a task becomes running, update CPU's performance target only
	 * when the current task's target performance is higher. This helps
	 * rapidly adopt workload changes by rapidly increasing CPU's
	 * performance target.
	 */
	u32 target;

	if (!cpuc)
		return false;

	target = max(cpuc->cpuperf_task, cpuc->cpuperf_avg);
	if (cpuc->cpuperf_cur < target) {
		cpuc->cpuperf_cur = target;
		scx_bpf_cpuperf_set(cpuc->cpu_id, target);
		return true;
	}

	return false;
}

static bool try_decrease_cpuperf_target(struct cpu_ctx *cpuc)
{
	/*
	 * Upon every tick interval, we try to decrease the CPU's performance
	 * target if the current one is higher than both the current task's
	 * target and EWMA of past targets. This helps gradually adopt workload
	 * changes upon sudden down falls.
	 */
	u32 target;

	if (!cpuc)
		return false;

	target = max(cpuc->cpuperf_task, cpuc->cpuperf_avg);
	if (cpuc->cpuperf_cur != target) {
		cpuc->cpuperf_cur = target;
		scx_bpf_cpuperf_set(cpuc->cpu_id, target);
		return true;
	}

	return false;
}

void BPF_STRUCT_OPS(lavd_tick, struct task_struct *p_run)
{
	struct cpu_ctx *cpuc_run;
	struct task_ctx *taskc_run;
	bool preempted = false;


	/*
	 * Try to yield the current CPU if there is a higher priority task in
	 * the run queue.
	 */
	cpuc_run = get_cpu_ctx();
	taskc_run = get_task_ctx(p_run);
	if (!cpuc_run || !taskc_run)
		goto freq_out;

	preempted = try_yield_current_cpu(p_run, cpuc_run, taskc_run);

	/*
	 * Update performance target of the current CPU if the current running
	 * task continues to run.
	 */
freq_out:
	if (!preempted)
		try_decrease_cpuperf_target(cpuc_run);
}

void BPF_STRUCT_OPS(lavd_runnable, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cpuc;
	struct task_struct *waker;
	struct task_ctx *p_taskc, *waker_taskc;
	u64 now, interval;

	/*
	 * Add task load based on the current statistics regardless of a target
	 * rq. Statistics will be adjusted when more accurate statistics become
	 * available (ops.running).
	 */
	cpuc = get_cpu_ctx();
	p_taskc = get_task_ctx(p);
	if (!cpuc || !p_taskc)
		return;

	update_stat_for_runnable(p, p_taskc, cpuc);

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
	now = bpf_ktime_get_ns();
	interval = now - waker_taskc->last_runnable_clk;
	waker_taskc->wake_freq = calc_avg_freq(waker_taskc->wake_freq, interval);
	waker_taskc->last_runnable_clk = now;

	/*
	 * Propagate waker's latency criticality to wakee. Note that we pass
	 * task's self latency criticality to limit the context into one hop.
	 */
	p_taskc->lat_cri_waker = waker_taskc->lat_cri_self;
}

void BPF_STRUCT_OPS(lavd_running, struct task_struct *p)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;

	/*
	 * Update task statistics
	 */
	cpuc = get_cpu_ctx();
	taskc = get_task_ctx(p);
	if (!cpuc || !taskc)
		return;

	update_stat_for_running(p, taskc, cpuc);

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
	cpuc->stopping_tm_est_ns = get_est_stopping_time(taskc);

	/*
	 * If there is a relevant introspection command with @p, process it.
	 */
	try_proc_introspec_cmd(p, taskc, LAVD_CPU_ID_HERE);
}

static bool slice_fully_consumed(struct cpu_ctx *cpuc, struct task_ctx *taskc)
{
	u64 run_time_ns;

	/*
	 * Sanity check just to make sure the runtime is positive.
	 */
	if (taskc->last_stopping_clk < taskc->last_running_clk) {
		scx_bpf_error("run_time_ns is negative: 0x%llu - 0x%llu",
			      taskc->last_stopping_clk, taskc->last_running_clk);
	}

	run_time_ns = taskc->last_stopping_clk - taskc->last_running_clk;

	return run_time_ns >= taskc->slice_ns;
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

	update_stat_for_quiescent(p, taskc, cpuc);

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
	now = bpf_ktime_get_ns();
	interval = now - taskc->last_quiescent_clk;
	taskc->wait_freq = calc_avg_freq(taskc->wait_freq, interval);
	taskc->last_quiescent_clk = now;
}

static void cpu_ctx_init_online(struct cpu_ctx *cpuc, u32 cpu_id, u64 now)
{
	cpuc->idle_start_clk = 0;
	cpuc->cpu_id = cpu_id;
	cpuc->lat_cri = 0;
	cpuc->stopping_tm_est_ns = LAVD_TIME_INFINITY_NS;
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
	cpuc->stopping_tm_est_ns = LAVD_TIME_INFINITY_NS;
}

void BPF_STRUCT_OPS(lavd_cpu_online, s32 cpu)
{
	/*
	 * When a cpu becomes online, reset its cpu context and trigger the
	 * recalculation of the global cpu load.
	 */
	u64 now = bpf_ktime_get_ns();
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
	u64 now = bpf_ktime_get_ns();
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

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc)
		return;

	/*
	 * The CPU is entering into the idle state.
	 */
	if (idle) {
		cpuc->idle_start_clk = bpf_ktime_get_ns();
		cpuc->lat_cri = 0;
		cpuc->stopping_tm_est_ns = LAVD_TIME_INFINITY_NS;
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
			u64 duration = bpf_ktime_get_ns() - old_clk;
			bool ret = __sync_bool_compare_and_swap(
					&cpuc->idle_start_clk, old_clk, 0);
			if (ret)
				cpuc->idle_total += duration;
		}
	}
}

static void set_on_core_type(struct task_ctx *taskc,
				 const struct cpumask *cpumask)
{
	bool on_big = false, on_little = false;
	struct cpu_ctx *cpuc;
	int cpu;

	bpf_for(cpu, 0, nr_cpus_onln) {
		if (!bpf_cpumask_test_cpu(cpu, cpumask))
			continue;

		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to look up cpu_ctx: %d", cpu);
			return;
		}

		if (cpuc->big_core)
			on_big = true;
		else
			on_little = true;

		if (on_big && on_little)
			break;
	}

	WRITE_ONCE(taskc->on_big, on_big);
	WRITE_ONCE(taskc->on_little, on_little);
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

static void init_task_ctx(struct task_struct *p, struct task_ctx *taskc)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u64 now = bpf_ktime_get_ns();

	memset(taskc, 0, sizeof(*taskc));
	taskc->last_running_clk = now; /* for run_time_ns */
	taskc->last_stopping_clk = now; /* for run_time_ns */
	taskc->run_time_ns = LAVD_SLICE_MAX_NS;
	taskc->victim_cpu = (s32)LAVD_CPU_ID_NONE;
	taskc->svc_time = stat_cur->avg_svc_time * LAVD_NEW_PROC_PENALITY;

	set_on_core_type(taskc, p->cpus_ptr);
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

		WRITE_ONCE(cpdomc->last_consume_clk, now);

		/*
		 * Create an associated DSQ.
		 */
		err = scx_bpf_create_dsq(cpdomc->id, -1);
		if (err) {
			scx_bpf_error("Failed to create a DSQ for cpdom %llu", cpdomc->id);
			return err;
		}
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
	struct bpf_cpumask *active;
	int err = 0;
	u32 cpu;

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
	 * Initially activate all CPUs until we know the system load.
	 */
	bpf_for(cpu, 0, nr_cpus_onln) {
		bpf_cpumask_set_cpu(cpu, active);
	}

out:
	bpf_rcu_read_unlock();
	return err;
}

static u16 get_cpuperf_cap(s32 cpu)
{
	if (cpu >= 0 && cpu < LAVD_CPU_ID_MAX)
		return __cpu_capacity_hint[cpu];

	scx_bpf_error("Infeasible CPU id: %d", cpu);
	return 1;
}

static u16 get_cputurbo_cap(void)
{
	u16 turbo_cap = 0;
	int nr_turbo = 0, cpu;

	/*
	 * Find the maximum CPU frequency
	 */
	for (cpu = 0; cpu < LAVD_CPU_ID_MAX; cpu++) {
		if (__cpu_capacity_hint[cpu] > turbo_cap) {
			turbo_cap = __cpu_capacity_hint[cpu];
			nr_turbo++;
		}
	}

	/*
	 * If all CPU's frequencies are the same, ignore the turbo.
	 */
	if (nr_turbo <= 1)
		turbo_cap = 0;

	return turbo_cap;
}

static int reinit_active_cpumask_for_performance(void)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
	int cpu, err = 0;

	barrier();
	bpf_rcu_read_lock();

	/*
	 * Prepare cpumasks.
	 */
	active  = active_cpumask;
	ovrflw  = ovrflw_cpumask;
	if (!active || !ovrflw) {
		scx_bpf_error("Failed to prepare cpumasks.");
		err = -ENOMEM;
		goto unlock_out;
	}


	/*
	 * Once core compaction becomes off in performance mode,
	 * reinitialize active/overflow cpumasks to reflect the mode change.
	 */
	bpf_for(cpu, 0, nr_cpus_onln) {
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			err = -ESRCH;
			goto unlock_out;
		}

		if (cpuc->big_core)
			bpf_cpumask_set_cpu(cpu, active);
		else
			bpf_cpumask_set_cpu(cpu, ovrflw);
	}

unlock_out:
	bpf_rcu_read_unlock();
	return err;
}

static s32 init_per_cpu_ctx(u64 now)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *turbo, *big, *little, *active, *ovrflw, *cd_cpumask;
	struct cpdom_ctx *cpdomc;
	int cpu, i, j, err = 0;
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
	bpf_for(cpu, 0, nr_cpus_onln) {
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

		cpu_ctx_init_online(cpuc, cpu, now);
		cpuc->capacity = get_cpuperf_cap(cpu);
		cpuc->offline_clk = now;
		cpuc->cpdom_poll_pos = cpu % LAVD_CPDOM_MAX_NR;
		cpuc->min_perf_cri = 1000;

		sum_capacity += cpuc->capacity;
	}

	/*
	 * Get turbo capacitiy.
	 */
	turbo_cap = get_cputurbo_cap();

	/*
	 * Classify CPU into BIG or little cores based on their average capacity.
	 */
	avg_capacity = sum_capacity / nr_cpus_onln;
	bpf_for(cpu, 0, nr_cpus_onln) {
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
	bpf_for(cpdom_id, 0, LAVD_CPDOM_MAX_NR) {
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
				}
			}
		}
	}

	bpf_for(cpu, 0, nr_cpus_onln) {
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

static s32 init_sys_stat(u64 now)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	memset(__sys_stats, 0, sizeof(__sys_stats));
	__sys_stats[0].last_update_clk = now;
	__sys_stats[1].last_update_clk = now;
	__sys_stats[0].nr_active = nr_cpus_big;
	__sys_stats[1].nr_active = nr_cpus_big;

	timer = bpf_map_lookup_elem(&update_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup update timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &update_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, update_timer_cb);
	err = bpf_timer_start(timer, LAVD_SYS_STAT_INTERVAL_NS, 0);
	if (err) {
		scx_bpf_error("Failed to arm update timer");
		return err;
	}

	return 0;
}

static void init_autopilot_low_util(void)
{
	if (nr_cpus_big < nr_cpus_onln) {
		/*
		 * When there are little cores, we move up to the balanced mode
		 * if one little core is fully utilized.
		 */
		LAVD_AP_LOW_UTIL = 1000 / nr_cpus_onln;
	}
	else {
		/*
		 * When there are only big cores, we move up to the balanced
		 * mode if two big cores are fully utilized.
		 */
		LAVD_AP_LOW_UTIL = (2 * 1000) / nr_cpus_onln;
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lavd_init)
{
	u64 now = bpf_ktime_get_ns();
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

SEC("syscall")
int set_power_profile(struct power_arg *input)
{
	return do_set_power_profile(input->power_mode, 0);
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
	       .enable			= (void *)lavd_enable,
	       .init_task		= (void *)lavd_init_task,
	       .init			= (void *)lavd_init,
	       .exit			= (void *)lavd_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms		= 30000U,
	       .name			= "lavd");
