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
 * We define Task B is more latency-critical in the following cases:
 *  a) as Task B's runtime per schedule is shorter (runtime B)
 *  b) as Task B wakes Task C more frequently (wake_freq B)
 *  c) as Task B waits for Task A more frequently (wait_freq B)
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
 * deadline. Additionally, if a task is compute-intensive and not
 * latency-critical, the scheduler automatically reduces its time slice, since
 * its runtime per schedule is sufficiently long enough without voluntarily
 * yielding the CPU. Note that reducing the time slice of a latency-critical
 * task for fairness is not very effective because the scheduling overhead
 * might be detrimental.
 *
 *
 * Copyright (c) 2023, 2024 Changwoo Min <changwoo@igalia.com>
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
volatile u64			nr_cpus_onln;

static struct sys_cpu_util	__sys_cpu_util[2];
static volatile int		__sys_cpu_util_idx;

volatile u64			max_lat_cri;
struct user_exit_info		uei;

const volatile u8		verbose;

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
 * Introspection commands
 */
struct introspec intrspc;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 /* 16 KB */);
} introspec_msg SEC(".maps");

/*
 * A nice priority to CPU usage weight array
 * -----------------------------------------
 *
 * This is the exact same weight array in the kernel (kernel/sched/core.c). We
 * used the same array on purpose to provide the same level of fairness. Each
 * step increases by around 23%. Here is the comments from the kernel source
 * code for reference:
 *
 * "Nice levels are multiplicative, with a gentle 10% change for every nice
 * level changed. I.e. when a CPU-bound task goes from nice 0 to nice 1, it
 * will get ~10% less CPU time than another CPU-bound task that remained on
 * nice 0."
 *
 * "The "10% effect" is relative and cumulative: from _any_ nice level, if you
 * go up 1 level, it's -10% CPU usage, if you go down 1 level it's +10% CPU
 * usage. (to achieve that we use a multiplier of 1.25. If a task goes up by
 * ~10% and another task goes down by ~10% then the relative distance between
 * them is ~25%.)"
 */
static const u64 sched_prio_to_slice_weight[NICE_WIDTH] = {
	/* weight	nice priority	sched priority */
	/* ------	-------------	-------------- */
	88761,		/* -20		 0 */
	71755,		/* -19		 1 */
	56483,		/* -18		 2 */
	46273,		/* -17		 3 */
	36291,		/* -16		 4 */
	29154,		/* -15		 5 */
	23254,		/* -14		 6 */
	18705,		/* -13		 7 */
	14949,		/* -12		 8 */
	11916,		/* -11		 9 */
	 9548,		/* -10		10 */
	 7620,		/*  -9		11 */
	 6100,		/*  -8		12 */
	 4904,		/*  -7		13 */
	 3906,		/*  -6		14 */
	 3121,		/*  -5		15 */
	 2501,		/*  -4		16 */
	 1991,		/*  -3		17 */
	 1586,		/*  -2		18 */
	 1277,		/*  -1		19 */
	 1024,		/*   0		20 */
	  820,		/*   1		21 */
	  655,		/*   2		22 */
	  526,		/*   3		23 */
	  423,		/*   4		24 */
	  335,		/*   5		25 */
	  272,		/*   6		26 */
	  215,		/*   7		27 */
	  172,		/*   8		28 */
	  137,		/*   9		29 */
	  110,		/*  10		30 */
	   87,		/*  11		31 */
	   70,		/*  12		32 */
	   56,		/*  13		33 */
	   45,		/*  14		34 */
	   36,		/*  15		35 */
	   29,		/*  16		36 */
	   23,		/*  17		37 */
	   18,		/*  18		38 */
	   15,		/*  19		39 */
};

/*
 * A nice priority to latency weight array
 * ---------------------------------------
 *
 * It is used to determine the virtual deadline. Each step increases by 10%.
 * The idea behind the virtual deadline is to limit the competition window
 * among concurrent tasks. For example, in the case of a normal priority task
 * with priority 19 (or nice 0), its corresponding value is 10,000,000 nsec (or
 * 10 msec). This guarantees that any tasks enqueued in 10 msec after the task
 * is enqueued will not compete with the task. The array is adapted from the
 * MuQSS scheduler. We choose a different distribution for
 * sched_prio_to_latency_weight on purpose instead of inversing
 * sched_prio_to_slice_weight. That is because sched_prio_to_slice_weight is
 * too steep to use for latency. We normalized the values so that the normal
 * priority (nice 0) has a deadline of 10 msec. The virtual deadline ranges
 * from 1.5 msec to 60.9 msec.
 */
static const u64 sched_prio_to_latency_weight[NICE_WIDTH] = {
	/* weight	nice priority	sched priority	vdeadline (usec)  */
	/* ------	-------------	--------------	----------------  */
	  383,		/* -20		 0		 1532 */
	  419,		/* -19		 1 		 1676 */
	  461,		/* -18		 2 		 1844 */
	  505,		/* -17		 3 		 2020 */
	  553,		/* -16		 4 		 2212 */
	  607,		/* -15		 5 		 2428 */
	  667,		/* -14		 6 		 2668 */
	  733,		/* -13		 7 		 2932 */
	  804,		/* -12		 8 		 3216 */
	  882,		/* -11		 9 		 3528 */
	  969,		/* -10		10 		 3876 */
	 1065,		/*  -9		11 		 4260 */
	 1169,		/*  -8		12 		 4676 */
	 1286,		/*  -7		13 		 5144 */
	 1414,		/*  -6		14 		 5656 */
	 1555,		/*  -5		15 		 6220 */
	 1711,		/*  -4		16 		 6844 */
	 1881,		/*  -3		17 		 7524 */
	 2066,		/*  -2		18 		 8264 */
	 2273,		/*  -1		19 		 9092 */
	 2500,		/*   0		20 		10000 */
	 2748,		/*   1		21 		10992 */
	 3020,		/*   2		22 		12080 */
	 3322,		/*   3		23 		13288 */
	 3654,		/*   4		24 		14616 */
	 4019,		/*   5		25 		16076 */
	 4420,		/*   6		26 		17680 */
	 4859,		/*   7		27 		19436 */
	 5344,		/*   8		28 		21376 */
	 5876,		/*   9		29 		23504 */
	 6462,		/*  10		30 		25848 */
	 7108,		/*  11		31 		28432 */
	 7817,		/*  12		32 		31268 */
	 8597,		/*  13		33 		34388 */
	 9456,		/*  14		34 		37824 */
	10401,		/*  15		35 		41604 */
	11438,		/*  16		36 		45752 */
	12581,		/*  17		37 		50324 */
	13837,		/*  18		38 		55348 */
	15218,		/*  19		39 		60872 */
};

/*
 * A latency priority to greedy ratios for eligibility
 * ---------------------------------------------------
 *
 * This table is nothing but sched_prio_to_slice_weight * (1000/1024) for
 * direct comparison against greedy_ratio, which is based on 1000.
 *
 * We distribute CPU time based on its nice (static) priorities described in
 * sched_prio_to_slice_weight, the same as the conventional way, for the fair
 * use of CPU time. However, when checking whether a particular task is
 * eligible, we consider its (dynamic) latency priority. Because a
 * latency-critical task may have CPU usage spikes to meet its (soft) deadline,
 * too strict fairness enforcement does not work well.
 *
 * Hence, we are more generous to a latency-critical task and aim for eventual
 * fairness of CPU time. To this end, we determine the task's time slice and
 * ineligible duration based on its nice priority for fairness. But we check if
 * a task is greedier compared to its (dynamic) _latency_ priority (not nice
 * priority). This allows the task to use more CPU time temporarily, but
 * eventually, its CPU time is under fairness control using time slice and
 * ineligibility duration calculation.
 */
static const u64 lat_prio_to_greedy_thresholds[NICE_WIDTH] = {
	/* weight	nice priority	sched priority */
	/* ------	-------------	-------------- */
	86681,		/* -20		 0 */
	70073,		/* -19		 1 */
	55159,		/* -18		 2 */
	45188,		/* -17		 3 */
	35440,		/* -16		 4 */
	28471,		/* -15		 5 */
	22709,		/* -14		 6 */
	18267,		/* -13		 7 */
	14599,		/* -12		 8 */
	11637,		/* -11		 9 */
	 9324,		/* -10		10 */
	 7441,		/*  -9		11 */
	 5957,		/*  -8		12 */
	 4789,		/*  -7		13 */
	 3814,		/*  -6		14 */
	 3048,		/*  -5		15 */
	 2442,		/*  -4		16 */
	 1944,		/*  -3		17 */
	 1549,		/*  -2		18 */
	 1247,		/*  -1		19 */
	 1000,		/*   0		20 */
	 1000,		/*   1		21 */
	 1000,		/*   2		22 */
	 1000,		/*   3		23 */
	 1000,		/*   4		24 */
	 1000,		/*   5		25 */
	 1000,		/*   6		26 */
	 1000,		/*   7		27 */
	 1000,		/*   8		28 */
	 1000,		/*   9		29 */
	 1000,		/*  10		30 */
	 1000,		/*  11		31 */
	 1000,		/*  12		32 */
	 1000,		/*  13		33 */
	 1000,		/*  14		34 */
	 1000,		/*  15		35 */
	 1000,		/*  16		36 */
	 1000,		/*  17		37 */
	 1000,		/*  18		38 */
	 1000,		/*  19		39 */
};


static u16 get_nice_prio(struct task_struct *p);
static u64 get_task_load_ideal(struct task_struct *p);

static bool put_local_rq(struct task_struct *p, struct task_ctx *taskc,
			 u64 enq_flags);
static bool put_global_rq(struct task_struct *p, struct task_ctx *taskc,
			  u64 enq_flags);

static inline __attribute__((always_inline)) u32 bpf_log2(u32 v)
{
	u32 r;
	u32 shift;
	
	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

static inline __attribute__((always_inline)) u32 bpf_log2l(u64 v)
{
	u32 hi = v >> 32;
	if (hi)
		return bpf_log2(hi) + 32 + 1;
	else
		return bpf_log2(v) + 1;
}

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
	return (v > max) ? 0 : max - v;
}

static struct cpu_ctx *get_cpu_ctx(void)
{
	const u32 idx = 0;

	return bpf_map_lookup_elem(&cpu_ctx_stor, &idx);
}

static struct cpu_ctx *get_cpu_ctx_id(s32 cpu)
{
	const u32 idx = 0;

	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

static struct sys_cpu_util *get_sys_cpu_util_cur(void)
{
	if (__sys_cpu_util_idx == 0)
		return &__sys_cpu_util[0];
	return &__sys_cpu_util[1];
}

static struct sys_cpu_util *get_sys_cpu_util_next(void)
{
	if (__sys_cpu_util_idx == 0)
		return &__sys_cpu_util[1];
	return &__sys_cpu_util[0];
}

static void flip_sys_cpu_util(void)
{
	__sys_cpu_util_idx ^= 0x1;
}

static int submit_task_ctx(struct task_struct *p, struct task_ctx *taskc,
			   u16 cpu_id)
{
	struct sys_cpu_util *cutil_cur = get_sys_cpu_util_cur();
	struct msg_task_ctx *m;

	m = bpf_ringbuf_reserve(&introspec_msg, sizeof(*m), 0);
	if (!m)
		return -ENOMEM;

	m->hdr.kind = LAVD_MSG_TASKC;
	m->taskc_x.pid = p->pid;
	memcpy(m->taskc_x.comm, p->comm, TASK_COMM_LEN);
	m->taskc_x.static_prio = get_nice_prio(p);
	m->taskc_x.cpu_util = cutil_cur->util / 10;
	m->taskc_x.cpu_id = cpu_id;
	memcpy(&m->taskc, taskc, sizeof(m->taskc));

	bpf_ringbuf_submit(m, 0);

	return 0;
}

static void proc_introspec_sched_n(struct task_struct *p,
				   struct task_ctx *taskc, u16 cpu_id)
{
	u64 cur_nr, prev_nr;
	int i;

	/* introspec_arg is the number of schedules remaining */
	cur_nr = intrspc.arg;

	/*
	 * Note that the bounded retry (@LAVD_MAX_CAS_RETRY) does *not
	 * *guarantee* to decrement introspec_arg. However, it is unlikely to
	 * happen. Even if it happens, it is nothing but a matter of delaying a
	 * message delivery. That's because other threads will try and succeed
	 * the CAS operation eventually. So this is good enough. ;-)
	 */
	for (i = 0; cur_nr > 0 && i < LAVD_MAX_CAS_RETRY; i++) {
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
			       u16 cpu_id)
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

static void proc_dump_all_tasks(struct task_struct *p)
{
	struct task_struct *pos;
	struct task_ctx *taskc;

	bpf_rcu_read_lock();

	bpf_for_each(task, pos, NULL, BPF_TASK_ITER_ALL_THREADS) {
		taskc = bpf_task_storage_get(&task_ctx_stor, pos, 0, 0);
		/*
		 * If a task is not under sched_ext, taskc is NULL.
		 */
		if (taskc && have_scheduled(taskc))
			submit_task_ctx(pos, taskc, LAVD_CPU_ID_NONE);
	}

	bpf_rcu_read_unlock();
}

static void try_proc_introspec_cmd(struct task_struct *p,
				   struct task_ctx *taskc, u16 cpu_id)
{
	bool ret;

	if (LAVD_CPU_ID_HERE == cpu_id)
		cpu_id = bpf_get_smp_processor_id();

	switch(intrspc.cmd) {
	case LAVD_CMD_SCHED_N:
		proc_introspec_sched_n(p, taskc, cpu_id);
		break;
	case LAVD_CMD_PID:
		proc_introspec_pid(p, taskc, cpu_id);
		break;
	case LAVD_CMD_DUMP:
		/*
		 * When multiple tasks can compete to dump all, only the winner
		 * task actually does the job.
		 */
		ret = __sync_bool_compare_and_swap(&intrspc.cmd,
				LAVD_CMD_DUMP, LAVD_CMD_NOP);
		if (ret)
			proc_dump_all_tasks(p);
		break;
	case LAVD_CMD_NOP:
		/* do nothing */
		break;
	default:
		scx_bpf_error("Unknown introspec command: %d", intrspc.cmd);
		break;
	}
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

static void update_sys_cpu_load(void)
{
	struct sys_cpu_util *cutil_cur = get_sys_cpu_util_cur();
	struct sys_cpu_util *cutil_next = get_sys_cpu_util_next();
	u64 now, duration, duration_total;
	u64 idle_total = 0, compute_total = 0;
	u64 load_actual = 0, load_ideal = 0;
	u64 new_util;
	int cpu;

	now = bpf_ktime_get_ns();
	duration = now - cutil_cur->last_update_clk;

	bpf_for(cpu, 0, nr_cpus_onln) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("cpu_ctx_stor lookup failed");
			compute_total = 0;
			break;
		}

		/*
		 * Accumulate task's ideal and actual loads.
		 */
		load_actual += cpuc->load_actual;
		load_ideal += cpuc->load_ideal;

		/*
		 * If the CPU is in an idle state (i.e., idle_start_clk is
		 * non-zero), accumulate the current idle peirod so far.
		 */
		for (int i = 0; i < LAVD_MAX_CAS_RETRY; i++) {
			u64 old_clk = cpuc->idle_start_clk;
			if (old_clk == 0)
				break;

			bool ret = __sync_bool_compare_and_swap(
					&cpuc->idle_start_clk, old_clk, now);
			if (ret) {
				idle_total += now - old_clk;
				break;
			}
		}

		idle_total += cpuc->idle_total;
		cpuc->idle_total = 0;
	}

	duration_total = duration * nr_cpus_onln;
	if (duration_total > idle_total)
		compute_total = duration_total - idle_total;
	new_util = (compute_total * LAVD_CPU_UTIL_MAX) / duration_total;

	/*
	 * Update the CPU utilization to the next version, and then make the
	 * next version atomically visible.
	 */
	cutil_next->load_actual = calc_avg(cutil_cur->load_actual, load_actual);
	cutil_next->load_ideal = calc_avg(cutil_cur->load_ideal, load_ideal);
	cutil_next->util = calc_avg(cutil_cur->util, new_util);
	cutil_next->last_update_clk = now;
	flip_sys_cpu_util();
}

static void decay_max_lat_cri(void)
{
	/*
	 * Decrease max_lat_cri by 3.13% (>> 5) every update interval. The
	 * maximum can be bumped up for a moment, then the actual lat_cri
	 * values could never reach the maximum value. To address this, we
	 * decrease the maximum value here so that the maximum can be bumped up
	 * again to the actual maximum. This helps to manage max_lat_cri close
	 * to the actual maximum value tightly. Note that we don't need to
	 * handle the CAS failure. That is because the CAS failure means
	 * another task bumps the old maximum to the higher, actual maximum.
	 */
	u64 cur_max = max_lat_cri;
	u64 delta = (cur_max >> 5) ? : 1;
	s64 new_max = cur_max - delta;

	if (new_max > 0)
		__sync_val_compare_and_swap(&max_lat_cri, cur_max, new_max);
}

static int update_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	update_sys_cpu_load();
	decay_max_lat_cri();

	err = bpf_timer_start(timer, LAVD_CPU_UTIL_INTERVAL_NS, 0);
	if (err)
		scx_bpf_error("Failed to arm update timer");

	return 0;
}

static u64 calc_greedy_ratio(struct task_struct *p, struct task_ctx *taskc)
{
	struct sys_cpu_util *cutil = get_sys_cpu_util_cur();
	u64 ratio;

	/*
	 * The greedy ratio of a task represents how much time the task
	 * overspent CPU time compared to the ideal, fair CPU allocation. It is
	 * the ratio of task's actual ratio to its ideal ratio. The actual
	 * ratio is the ratio of the task's average runtime to the total
	 * runtime in a system. The ideal ratio is the ratio of the task's
	 * weight, derived from its nice priority, to the sum of weights in a
	 * system. We use the moving averages (EWMA: exponentially weighted
	 * moving average) instead of the actual summation, which never decays.
	 */
	ratio = (1000 * taskc->load_actual * cutil->load_ideal) /
		(cutil->load_actual * get_task_load_ideal(p));
	taskc->greedy_ratio = ratio;
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

static u64 calc_lat_factor(u64 lat_prio)
{
	return LAVD_ELIGIBLE_TIME_LAT_FT * (NICE_WIDTH - lat_prio);
}

static u64 calc_greedy_factor(struct task_ctx *taskc)
{
	u64 greedy_ratio = taskc->greedy_ratio;
	s16 lat_prio = taskc->lat_prio;
	u64 greedy_threshold;
	u64 gr_ft;

	if (lat_prio < 0)
		lat_prio = 0;
	else if (lat_prio >= NICE_WIDTH)
		lat_prio = NICE_WIDTH - 1;

	/*
	 * When determining how greedy a task is, we are more generous to a
	 * latency-critical task with a low lat_prio value. That is because a
	 * latency-critical task can temporarily overspend CPU time. However,
	 * the time slice and ineligible duration allocation will eventually
	 * enforce fairness.
	 */
	greedy_threshold = lat_prio_to_greedy_thresholds[lat_prio];

	gr_ft = (greedy_ratio * 1000) / greedy_threshold;
	if (gr_ft < 1000)
		gr_ft = 1000;
	else
		gr_ft *= LAVD_SLICE_GREEDY_FT;

	return gr_ft;
}

static bool is_eligible(struct task_ctx *taskc)
{
	u64 greedy_threshold;
	s16 lat_prio = taskc->lat_prio;

	if (lat_prio < 0)
		lat_prio = 0;
	else if (lat_prio >= NICE_WIDTH)
		lat_prio = NICE_WIDTH - 1;

	/*
	 * Similar to the greedy factor calculation, we have a loose bound for
	 * a latency-critical task. That makes a latency-critical task less
	 * frequently ineligible for low (tail) latency.
	 */
	greedy_threshold = lat_prio_to_greedy_thresholds[lat_prio];

	return taskc->greedy_ratio <= greedy_threshold;
}

static bool is_wakeup_wf(u64 wake_flags)
{
	/*
	 * We don't need to test SCX_WAKE_SYNC because SCX_WAKE_SYNC should
	 * only be set when SCX_WAKE_TTWU is set.
	 */
	return wake_flags & SCX_WAKE_TTWU;
}

static bool is_wakeup_ef(u64 enq_flags)
{
	return enq_flags & SCX_ENQ_WAKEUP;
}

static u64 calc_eligible_delta(struct task_struct *p, struct task_ctx *taskc)
{
	/*
	 * We calculate how long a task should be ineligible for execution. To
	 * this end, the scheduler stretches the ineligible duration of a task
	 * so it can control the frequency of the task's running to let the
	 * task pay its debut. Reducing the time slice of a task would be
	 * another approach. However, adjusting the time slice for fairness
	 * does not work well since many latency-critical tasks voluntarily
	 * yield CPU waiting for an event before expiring its time slice. 
	 *
	 * task's freq_new =
	 *	freq_old / greedy_ratio = 
	 *	unit_time / (interval_old * greedy_ratio) = 
	 *	unit_time / interval_new
	 *
	 * task's interval_new =
	 *	task's interval_old * greedy_ratio =
	 *	when the task become eligible.
	 */
	u64 delta_ns;
	u64 lat_ft;

	/*
	 * Get how greedy this task has been to enforce fairness if necessary.
	 * If a task is too greedy so it is not eligible, don't put it to the
	 * local rq to seek another eligible task later.
	 */
	calc_greedy_ratio(p, taskc);

	/*
	 * Considering task's greedy ratio, decide if a task is now eligible.
	 */
	if (is_eligible(taskc)) {
		delta_ns = 0;
		goto out;
	}

	/*
	 * As a task is more latency-critical, it will have a shorter but more
	 * frequent ineligibility durations.
	 */
	lat_ft = calc_lat_factor(taskc->lat_prio);
	delta_ns = (LAVD_TIME_ONE_SEC / (1000 * taskc->run_freq)) *
		   (taskc->greedy_ratio / (lat_ft + 1));

	if (delta_ns > LAVD_ELIGIBLE_TIME_MAX)
		delta_ns = LAVD_ELIGIBLE_TIME_MAX;

out:
	taskc->eligible_delta_ns = delta_ns;
	return delta_ns;
}

static int sum_prios_for_lat(struct task_struct *p, int nice_prio,
			     int lat_boost_prio)
{
	int prio;

	/*
	 * Bound the final scheduler priority to the NICE_WIDTHE, [0, 40).
	 */
	prio = nice_prio + lat_boost_prio;
	if (prio >= NICE_WIDTH)
		prio = NICE_WIDTH - 1;
	else if (prio < 0)
		prio = 0;

	return prio;
}

static int boost_lat(struct task_struct *p, struct task_ctx *taskc,
		     bool is_wakeup)
{
	u64 run_time_ft = 0, wait_freq_ft = 0, wake_freq_ft = 0;
	u64 lat_cri_raw = 0, cur_max = 0, lat_cri = 0;
	u16 static_prio;
	int boost;

	/*
	 * If a task has yet to be scheduled (i.e., a freshly forked task or a
	 * task just under sched_ext), don't boost its priority before knowing
	 * its property.
	 */
	if (!have_scheduled(taskc)) {
		boost = 0;
		goto out;
	}

	/*
	 * A task is more latency-critical as its wait or wake frequencies
	 * (i.e., wait_freq and wake_freq) are higher and/or its runtime per
	 * schedule (run_time) is shorter.
	 *
	 * Since those numbers are unbounded and their upper limits are
	 * unknown, we transform them using sigmoid-like functions. For wait
	 * and wake frequencies, we use a sigmoid function (sigmoid_u64), which
	 * is monotonically increasing since higher frequencies mean more
	 * latency-critical. For per-schedule runtime, we use a horizontally
	 * flipped version of the sigmoid function (rsigmoid_u64) because a
	 * shorter runtime means more latency-critical.
	 */
	run_time_ft = calc_runtime_factor(taskc->run_time_ns);
	wait_freq_ft = calc_freq_factor(taskc->wait_freq);
	wake_freq_ft = calc_freq_factor(taskc->wake_freq);

	/*
	 * A raw latency criticality factor consists of two parts -- a
	 * frequency part and a runtime part.
	 *
	 * Wake frequency and wait frequency represent how much a task is used
	 * for a producer and a consumer, respectively. If both are high, the
	 * task is in the middle of a task chain. We multiply frequencies --
	 * wait_freq * wake_freq * wake_freq -- to amplify the subtle
	 * differences in frequencies than simple addition. Also, we square
	 * wake_freq to prioritize scheduling of a producer task. That's
	 * because if the scheduling of a producer task is delayed, all the
	 * following consumer tasks are also delayed.
	 *
	 * For the runtime part, we cubic the runtime to amplify the subtle
	 * differences.
	 *
	 * We aggregate the frequency part and the runtime part using addition.
	 * In this way, if a task is either high-frequency _or_ short-runtime,
	 * it is considered latency-critical. Of course, such a task with both
	 * high frequency _and_ short runtime is _super_ latency-critical.
	 */
	lat_cri_raw = (wait_freq_ft * wake_freq_ft * wake_freq_ft) + 
		      (run_time_ft * run_time_ft * run_time_ft);

	/*
	 * The ratio above tends to follow an exponentially skewed
	 * distribution, so we linearize it using log2 before converting it to
	 * a boost priority. We add +1 to guarantee the latency criticality
	 * (log2-ed) is always positive.
	 *
	 * Note that the priority-to-weight conversion table is non-linear.
	 * Through this process -- log2(ratio) then priority to weight
	 * conversion, we mitigate the exponentially skewed distribution to
	 * non-linear distribution.
	 */
	lat_cri = bpf_log2l(lat_cri_raw + 1);

	/*
	 * Update the global @max_lat_cri if necessary. Updating @max_lat_cri
	 * is racy because it can be tested and updated concurrently from
	 * multiple CPUs. So we use an atomic cmpxchg.
	 *
	 * Note that the bounded retry (@LAVD_MAX_CAS_RETRY) does *not
	 * *guarantee* the update of @max_lat_cri. However, it is unlikely to
	 * happen, and even if it happens, the incorrect value will be
	 * corrected next time anyway. So let's just live with it. 
	 *
	 * We decay @max_lat_cri periodially (at decay_max_lat_cri) to maintain
	 * @max_lat_cri up-to-date.
	 */
	cur_max = max_lat_cri;
	for (int i = 0; lat_cri > cur_max && i < LAVD_MAX_CAS_RETRY; i++) {
		cur_max = __sync_val_compare_and_swap(&max_lat_cri, cur_max,
				lat_cri);
	}

	/*
	 * Convert @p's latency criticality to its boost priority linearly.
	 */
	boost = (LAVD_BOOST_RANGE - ((lat_cri * LAVD_BOOST_RANGE) / cur_max)) - 
		(LAVD_BOOST_RANGE >> 1);

	/*
	 * When a task is wakening up, boost its latency boost priority by 1.
	 */
	if (is_wakeup)
		boost -= LAVD_BOOST_WAKEUP_LAT;

out:
	static_prio = get_nice_prio(p);
	taskc->lat_prio = sum_prios_for_lat(p, static_prio, boost);
	taskc->lat_boost_prio = boost;

	return boost;
}

static u64 calc_latency_weight(struct task_struct *p, struct task_ctx *taskc,
			       bool is_wakeup)
{
	int nice_prio, lat_boost_prio, prio;
	u64 weight;

	/*
	 * Aggregate nice priority and latency boost priority, then convert the
	 * final priority to weight.
	 */
	nice_prio = get_nice_prio(p);
	lat_boost_prio = boost_lat(p, taskc, is_wakeup);
	prio = sum_prios_for_lat(p, nice_prio, lat_boost_prio);

	weight = sched_prio_to_latency_weight[prio];
	return weight;
}

static u64 calc_virtual_dealine_delta(struct task_struct *p,
				      struct task_ctx *taskc,
				      u64 enq_flags)
{
	u64 vdeadline_delta_ns, weight;
	bool is_wakeup;

	/* Virtual deadline of @p is defined as follows:
	 *
	 *   vdeadline = now + (a full time slice * latency weight)
	 *
	 * where
	 *   - weigth is detemined by nice priority and boost priorty
	 *   - (a full time slice * latency weight) determins the time window
	 *   of competition among concurrent tasks.
	 *
	 * Note that not using average runtime (taskc->run_time) is intentional
	 * because task's average runtime is already reflected in calculating
	 * boost priority (and weight).
	 */
	is_wakeup = is_wakeup_ef(enq_flags);
	weight = calc_latency_weight(p, taskc, is_wakeup);
	vdeadline_delta_ns = (LAVD_SLICE_MAX_NS * weight) / 1000;
	taskc->vdeadline_delta_ns = vdeadline_delta_ns;
	return vdeadline_delta_ns;
}

static u64 get_task_load_ideal(struct task_struct *p)
{
	int prio;
	u64 weight;

	/*
	 * The task's ideal load is simply the weight based on the task's nice
	 * priority (without considering boosting). Note that the ideal load
	 * and actual load are not compatible for comparison. However, the
	 * ratios of them are directly comparable. 
	 */
	prio = get_nice_prio(p);
	if (prio >= NICE_WIDTH)
		prio = NICE_WIDTH - 1;
	else if (prio < 0)
		prio = 0;

	weight = sched_prio_to_slice_weight[prio];
	return weight;
}

static u64 calc_task_load_actual(struct task_ctx *taskc)
{
	/*
	 * The actual load is the CPU time consumed in a time interval, which
	 * can be calculated from task's average run time and frequency.
	 */
	const s64 interval_adj = LAVD_TIME_ONE_SEC / LAVD_CPU_UTIL_INTERVAL_NS;
	return (taskc->run_time_ns * taskc->run_freq) / interval_adj;
}

static u64 calc_slice_share(struct task_struct *p, struct task_ctx *taskc)
{
	/*
	 * Task's CPU time share within a targeted latency window is basically
	 * determined by its nice priority (and its corresponding weight). In
	 * addition, if a task is compute-bound with high slice_boost_prio, the
	 * scheduler tries to allocate a longer time slice.
	 */
	u64 share = get_task_load_ideal(p);

	share += (share * taskc->slice_boost_prio) / LAVD_SLICE_BOOST_MAX;

	return share;
}

static u64 calc_time_slice(struct task_struct *p, struct task_ctx *taskc)
{
	struct sys_cpu_util *cutil_cur = get_sys_cpu_util_cur();
	u64 slice, share, gr_ft;

	/*
	 * The time slice should be short enough to schedule all runnable tasks
	 * at least once within a targeted latency.
	 */
	share = calc_slice_share(p, taskc);
	slice = (share * nr_cpus_onln) *
		(LAVD_TARGETED_LATENCY_NS / cutil_cur->load_ideal);

	/*
	 * Take the task's greedy ratio into consideration. We assign a shorter
	 * time slice when the task is greedy but not latency-critical.
	 */
	gr_ft = calc_greedy_factor(taskc);
	slice = (slice * 1000) / gr_ft;

	/*
	 * Keep the slice in [LAVD_SLICE_MIN_NS, LAVD_SLICE_MAX_NS].
	 */
	if (slice < LAVD_SLICE_MIN_NS)
		slice = LAVD_SLICE_MIN_NS;
	else if (slice > LAVD_SLICE_MAX_NS)
		slice = LAVD_SLICE_MAX_NS;

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

static bool transit_task_stat(struct task_ctx *taskc, int tgt_stat)
{
	/*
	 * Update task loads only when the state transition is valid.
	 *
	 * initial state
	 * -------------
	 *     |
	 *    \/
	 * [STOPPING] --> [ENQ] --> [RUNNING]
	 *    /\                        |
	 *    |                         |
	 *    +-------------------------+
	 */
	const static int valid_tgt_stat[] = {
		LAVD_TASK_STAT_ENQ,
		LAVD_TASK_STAT_RUNNING,
		LAVD_TASK_STAT_STOPPING,
	};
	int src_stat = taskc->stat;

	if (src_stat < _LAVD_TASK_STAT_MIN || src_stat > _LAVD_TASK_STAT_MAX) {
		scx_bpf_error("Invalid task state: %d", src_stat);
		return false;
	}

	if (valid_tgt_stat[src_stat] == tgt_stat) {
		taskc->stat = tgt_stat;
		return true;
	}

	return false;
}

static void update_stat_for_enq(struct task_struct *p, struct task_ctx *taskc,
				struct cpu_ctx *cpuc)
{
	/*
	 * Reflect task's load immediately.
	 */
	taskc->load_actual = calc_task_load_actual(taskc);
	cpuc->load_actual += taskc->load_actual;
	cpuc->load_ideal  += get_task_load_ideal(p);
}

static void update_stat_for_run(struct task_struct *p, struct task_ctx *taskc,
				struct cpu_ctx *cpuc)
{
	u64 now, wait_period, interval;

	/*
	 * Since this is the start of a new schedule for @p, we update run
	 * frequency in a second using an exponential weighted moving average.
	 */
	now = bpf_ktime_get_ns();
	wait_period = now - taskc->last_stop_clk;
	interval = taskc->run_time_ns + wait_period;
	taskc->run_freq = calc_avg_freq(taskc->run_freq, interval);

	/*
	 * Update task state when starts running.
	 */
	taskc->last_start_clk = now;
}

static void update_stat_for_stop(struct task_struct *p, struct task_ctx *taskc,
				 struct cpu_ctx *cpuc)
{
	u64 now, run_time_ns;

	/*
	 * If the task was runnable before governed by this scheduler, ignore
	 * this run.
	 */
	now = bpf_ktime_get_ns();
	if (now < taskc->last_start_clk)
		return;

	/*
	 * When stopped, reduce the per-CPU task load. Per-CPU task load will
	 * be aggregated periodically at update_sys_cpu_load().
	 */
	cpuc->load_actual -= taskc->load_actual;
	cpuc->load_ideal  -= get_task_load_ideal(p);

	/*
	 * Update task's run_time.
	 */
	run_time_ns = now - taskc->last_start_clk;
	taskc->run_time_ns = calc_avg(taskc->run_time_ns, run_time_ns);
	taskc->last_stop_clk = now;
}

static void calc_when_to_run(struct task_struct *p, struct task_ctx *taskc,
			     u64 enq_flags)
{
	/*
	 * Before enqueueing a task to a run queue, we should decide when a
	 * task should be scheduled. It is determined by two factors: how
	 * urgent it is - vdeadline_delta_ns - and when it becomes eligible if
	 * overscheduled - eligible_time_ns.
	 */
	calc_virtual_dealine_delta(p, taskc, enq_flags);
	calc_eligible_delta(p, taskc);
}

static bool put_local_rq(struct task_struct *p, struct task_ctx *taskc,
			 u64 enq_flags)
{
	/*
	 * Calculate when a tack can be scheduled. If a task is cannot be
	 * scheduled soonish (i.e., the task is ineligible since
	 * overscheduled), we do not put this to local run queue, which is for
	 * immediate execution.
	 *
	 * Note that the task's time slice will be calculated and reassigned
	 * right before running at ops.running().
	 */
	calc_when_to_run(p, taskc, enq_flags);
	if (!is_eligible(taskc))
		return false;

	/*
	 * Add task load based on the current statistics regardless of a target
	 * rq. Statistics will be adjusted when more accurate statistics
	 * become available (ops.running).
	 */
	struct cpu_ctx *cpuc = get_cpu_ctx();
	if (!cpuc) {
		scx_bpf_error("cpu_ctx_stor lookup failed");
		return false;
	}

	if (transit_task_stat(taskc, LAVD_TASK_STAT_ENQ))
		update_stat_for_enq(p, taskc, cpuc);

	/*
	 * This task should be scheduled as soon as possible (e.g., wakened up)
	 * so the deadline is no use and enqueued into a local DSQ, which
	 * always follows a FIFO order.
	 */
	taskc->vdeadline_delta_ns = 0;
	taskc->eligible_delta_ns = 0;
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL, LAVD_SLICE_MAX_NS, enq_flags);
	return true;
}

static bool put_global_rq(struct task_struct *p, struct task_ctx *taskc,
			  u64 enq_flags)
{
	struct cpu_ctx *cpuc;
	u64 vdeadline;

	/*
	 * Calculate when a tack can be scheduled.
	 *
	 * Note that the task's time slice will be calculated and reassigned
	 * right before running at ops.running().
	 */
	calc_when_to_run(p, taskc, enq_flags);

	/*
	 * Reflect task's load immediately.
	 */
	cpuc = get_cpu_ctx();
	if (!cpuc) {
		scx_bpf_error("cpu_ctx_stor lookup failed");
		return false;
	}
	if (transit_task_stat(taskc, LAVD_TASK_STAT_ENQ))
		update_stat_for_enq(p, taskc, cpuc);

	/*
	 * Enqueue the task to the global runqueue based on its virtual
	 * deadline.
	 */
	vdeadline = taskc->eligible_delta_ns + taskc->vdeadline_delta_ns +
		    bpf_ktime_get_ns();
	scx_bpf_dispatch_vtime(p, LAVD_GLOBAL_DSQ, LAVD_SLICE_MAX_NS,
			       vdeadline, enq_flags);
	return true;
}

s32 BPF_STRUCT_OPS(lavd_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool found_idle = false;
	s32 cpu_id;

	/*
	 * When a task wakes up, we should decide where to place the task at
	 * ops.select_cpu(). We make a best effort to find an idle CPU. If
	 * there is an idle CPU and a task is a true-wake-up task (not just
	 * fork-ed or execv-ed), we consider such a task as a latency-critical
	 * task, so directly dispatch to the local FIFO queue of the chosen
	 * CPU. If the task is directly dispatched here, the sched_ext won't
	 * call ops.enqueue().
	 */
	cpu_id = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &found_idle);

	if (found_idle && is_wakeup_wf(wake_flags)) {
		struct task_ctx *taskc;

		taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (!taskc) {
			scx_bpf_error("task_ctx_stor lookup failed");
			return prev_cpu;
		}

		if (!put_local_rq(p, taskc, 0)) {
			/*
			 * If a task is overscheduled (greedy_ratio > 1000), we
			 * do not select a CPU, so that later the enqueue
			 * operation can put it to the global queue.
			 */
			return prev_cpu;
		}
	}

	return cpu_id;
}

void BPF_STRUCT_OPS(lavd_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *taskc;
	
	/*
	 * If there is an idle CPU at the ops.select_cpu(), the task is already
	 * dispatched at ops.select_cpu(), so ops.enqueue() won't be called.
	 * Hence, the task that is enqueued here are the cases: 1) there is no
	 * idle CPU when ops.select_cpu() or 2) the task is not the case of
	 * being wakened up (i.e., resume after preemption). Therefore, we
	 * always put the task to the global DSQ, so any idle CPU can pick it
	 * up.
	 */
	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("task_ctx_stor lookup failed");
		return;
	}

	/*
	 * Place a task to the global run queue.
	 */
	put_global_rq(p, taskc, enq_flags);
}

void BPF_STRUCT_OPS(lavd_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Now, a CPU has no task to run, so it gets a task from the global run
	 * queue for execution.
	 */
	scx_bpf_consume(LAVD_GLOBAL_DSQ);
}

void BPF_STRUCT_OPS(lavd_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_struct *waker;
	struct task_ctx *taskc;
	u64 now, interval;

	/*
	 * When a task @p is wakened up, the wake frequency of its waker task
	 * is updated. The @current task is a waker and @p is a waiter, which
	 * is being wakened up now.
	 */
	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;

	waker = bpf_get_current_task_btf();
	taskc = bpf_task_storage_get(&task_ctx_stor, waker, 0, 0);
	if (!taskc) {
		/*
		 * In this case, the waker is either an idle task or a task not
		 * governed by scx, so we just ignore.
		 */
		return;
	}

	now = bpf_ktime_get_ns();
	interval = now - taskc->last_wake_clk;
	taskc->wake_freq = calc_avg_freq(taskc->wake_freq, interval);
	taskc->last_wake_clk = now;
}

void BPF_STRUCT_OPS(lavd_running, struct task_struct *p)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;

	/*
	 * Update task statistics then adjust task load based on the update.
	 */
	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("task_ctx_stor lookup failed");
		return;
	}

	cpuc = get_cpu_ctx();
	if (!cpuc) {
		scx_bpf_error("cpu_ctx_stor lookup failed");
		return;
	}

	if (transit_task_stat(taskc, LAVD_TASK_STAT_RUNNING))
		update_stat_for_run(p, taskc, cpuc);

	/*
	 * Calcualte task's time slice based on updated load.
	 */
	p->scx.slice = calc_time_slice(p, taskc);

	/*
	 * If there is a relevant introspection command with @p, process it.
	 */
	try_proc_introspec_cmd(p, taskc, LAVD_CPU_ID_HERE);
}

static bool slice_fully_consumed(struct cpu_ctx *cpuc, struct task_ctx *taskc)
{
	u64 run_time_ns = 0;

	if (taskc->last_stop_clk > taskc->last_start_clk)
		run_time_ns = taskc->last_stop_clk - taskc->last_start_clk;

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
		if (taskc->slice_boost_prio < LAVD_SLICE_BOOST_MAX)
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
	 * Reduce the task load.
	 */
	cpuc = get_cpu_ctx();
	if (!cpuc) {
		scx_bpf_error("cpu_ctx_stor lookup failed");
		return;
	}

	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("task_ctx_stor lookup failed");
		return;
	}

	if (transit_task_stat(taskc, LAVD_TASK_STAT_STOPPING))
		update_stat_for_stop(p, taskc, cpuc);

	/*
	 * Adjust slice boost for the task's next schedule.
	 */
	adjust_slice_boost(cpuc, taskc);
}

void BPF_STRUCT_OPS(lavd_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *taskc;
	u64 now, interval;

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
	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("task_ctx_stor lookup failed");
		return;
	}

	now = bpf_ktime_get_ns();
	interval = now - taskc->last_wait_clk;
	taskc->wait_freq = calc_avg_freq(taskc->wait_freq, interval);
	taskc->last_wait_clk = now;
}

void BPF_STRUCT_OPS(lavd_cpu_online, s32 cpu)
{
	/*
	 * When a cpu becomes online, reset its cpu context and trigger the
	 * recalculation of the global cpu load.
	 */
	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);

	if (!cpuc) {
		scx_bpf_error("cpu_ctx_stor lookup failed");
		return;
	}

	memset(cpuc, 0, sizeof(*cpuc));

	__sync_fetch_and_add(&nr_cpus_onln, 1);
	update_sys_cpu_load();
}

void BPF_STRUCT_OPS(lavd_cpu_offline, s32 cpu)
{
	/*
	 * When a cpu becomes offline, trigger the recalculation of the global
	 * cpu load.
	 */
	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);

	if (!cpuc) {
		scx_bpf_error("cpu_ctx_stor lookup failed");
		return;
	}

	memset(cpuc, 0, sizeof(*cpuc));

	__sync_fetch_and_sub(&nr_cpus_onln, 1);
	update_sys_cpu_load();
}

void BPF_STRUCT_OPS(lavd_update_idle, s32 cpu, bool idle)
{
	/*
	 * The idle duration is accumulated to calculate the CPU utilization.
	 * Since SCX_OPS_KEEP_BUILTIN_IDLE is specified, we still rely on the
	 * default idle core tracking and core selection algorithm.
	 */

	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);

	if (!cpuc) {
		scx_bpf_error("cpu_ctx_stor lookup failed");
		return;
	}

	/*
	 * The CPU is entering into the idle state.
	 */
	if (idle)
		cpuc->idle_start_clk = bpf_ktime_get_ns();
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

s32 BPF_STRUCT_OPS(lavd_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *taskc;
	u64 now;

	/*
	 * When @p becomes under the SCX control (e.g., being forked), @p's
	 * context data is initialized. We can sleep in this function and the
	 * following will automatically use GFP_KERNEL.
	 */
	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc) {
		scx_bpf_error("task_ctx_stor first lookup failed");
		return -ENOMEM;
	}

	/*
	 * Initialize @p's context.
	 */
	now = bpf_ktime_get_ns();
	taskc->last_start_clk = now;
	taskc->last_stop_clk = now;
	taskc->last_wait_clk = now;
	taskc->last_wake_clk = now;
	taskc->greedy_ratio = 1000;

	/*
	 * When a task is forked, we immediately reflect changes to the current
	 * ideal load not to over-allocate time slices without counting forked
	 * tasks.
	 */
	if (args->fork) {
		struct sys_cpu_util *cutil_cur;
		static u64 load_ideal;

		load_ideal = get_task_load_ideal(p);
		cutil_cur = get_sys_cpu_util_cur();

		__sync_fetch_and_add(&cutil_cur->load_ideal, load_ideal);
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lavd_init)
{
	struct bpf_timer *timer;
	u64 now;
	u32 key = 0;
	int err;

	/*
	 * Create a central task queue.
	 */
	err = scx_bpf_create_dsq(LAVD_GLOBAL_DSQ, -1);
	if (err) {
		scx_bpf_error("Failed to create a shared DSQ");
		return err;
	}

	/*
	 * Initialize the last update clock and the update timer to track
	 * system-wide CPU load.
	 */
	now = bpf_ktime_get_ns();
	__sys_cpu_util[0].last_update_clk = now;
	__sys_cpu_util[1].last_update_clk = now;

	timer = bpf_map_lookup_elem(&update_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup update timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &update_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, update_timer_fn);
	err = bpf_timer_start(timer, LAVD_CPU_UTIL_INTERVAL_NS, 0);
	if (err) {
		scx_bpf_error("Failed to arm update timer");
		return err;
	}

	/*
	 * Switch all tasks to scx tasks.
	 */
	scx_bpf_switch_all();

	return err;
}

void BPF_STRUCT_OPS(lavd_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops lavd_ops = {
	.select_cpu		= (void *)lavd_select_cpu,
	.enqueue		= (void *)lavd_enqueue,
	.dispatch		= (void *)lavd_dispatch,
	.runnable		= (void *)lavd_runnable,
	.running		= (void *)lavd_running,
	.stopping		= (void *)lavd_stopping,
	.quiescent		= (void *)lavd_quiescent,
	.cpu_online		= (void *)lavd_cpu_online,
	.cpu_offline		= (void *)lavd_cpu_offline,
	.update_idle		= (void *)lavd_update_idle,
	.init_task		= (void *)lavd_init_task,
	.init			= (void *)lavd_init,
	.exit			= (void *)lavd_exit,
	.flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	.timeout_ms		= 5000U,
	.name			= "lavd",
};

