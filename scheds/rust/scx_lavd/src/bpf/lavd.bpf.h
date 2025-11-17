/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#ifndef __LAVD_H
#define __LAVD_H

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>

/*
 * common macros
 */
#define U64_MAX		((u64)~0ULL)
#define S64_MAX		((s64)(U64_MAX >> 1))
#define U32_MAX		((u32)~0U)
#define S32_MAX		((s32)(U32_MAX >> 1))

#define LAVD_SHIFT			10
#define LAVD_SCALE			(1L << LAVD_SHIFT)
#define p2s(percent)			(((percent) << LAVD_SHIFT) / 100)
#define s2p(scale)			(((scale) * 100) >> LAVD_SHIFT)

#define cpdom_to_dsq(cpdom_id)		((cpdom_id) | LAVD_DSQ_TYPE_CPDOM << LAVD_DSQ_TYPE_SHFT)
#define dsq_to_cpdom(dsq_id)		((dsq_id) & LAVD_DSQ_ID_MASK)
#define dsq_to_cpu(dsq_id)		((dsq_id) & LAVD_DSQ_ID_MASK)
#define dsq_type(dsq_id)		(((dsq_id) & LAVD_DSQ_TYPE_MASK) >> LAVD_DSQ_TYPE_SHFT)

/*
 * common constants
 */
enum consts_internal {
	CLOCK_BOOTTIME			= 7,
	CACHELINE_SIZE			= 64,

	NSEC_PER_USEC			= 1000ULL,
	NSEC_PER_MSEC			= (1000ULL * NSEC_PER_USEC),

	LAVD_TIME_ONE_SEC		= (1000ULL * NSEC_PER_MSEC),
	LAVD_MAX_RETRY			= 3,

	LAVD_TARGETED_LATENCY_NS	= (10ULL * NSEC_PER_MSEC),
	LAVD_SLICE_MIN_NS_DFL		= (500ULL * NSEC_PER_USEC), /* min time slice */
	LAVD_SLICE_MAX_NS_DFL		= (5ULL * NSEC_PER_MSEC), /* max time slice */
	LAVD_SLICE_BOOST_BONUS		= LAVD_SLICE_MIN_NS_DFL,
	LAVD_SLICE_BOOST_MAX		= (500ULL * NSEC_PER_MSEC),
	LAVD_ACC_RUNTIME_MAX		= LAVD_SLICE_MAX_NS_DFL,
	LAVD_DL_COMPETE_WINDOW		= (LAVD_SLICE_MAX_NS_DFL >> 16), /* assuming task's latency
									    criticality is around 1000. */

	LAVD_LC_FREQ_MAX                = 400000,
	LAVD_LC_RUNTIME_MAX		= LAVD_TIME_ONE_SEC,
	LAVD_LC_WEIGHT_BOOST		= 128, /* 2^7 */
	LAVD_LC_GREEDY_SHIFT		= 3, /* 12.5% */
	LAVD_LC_WAKE_INTERVAL_MIN	= LAVD_SLICE_MIN_NS_DFL,
	LAVD_LC_INH_WAKEE_SHIFT		= 2, /* 25.0% of wakee's latency criticality */
	LAVD_LC_INH_WAKER_SHIFT		= 3, /* 12.5 of waker's latency criticality */

	LAVD_CPU_UTIL_MAX_FOR_CPUPERF	= p2s(85), /* 85.0% */

	LAVD_SYS_STAT_INTERVAL_NS	= (2 * LAVD_SLICE_MAX_NS_DFL),
	LAVD_SYS_STAT_DECAY_TIMES	= ((2ULL * LAVD_TIME_ONE_SEC) / LAVD_SYS_STAT_INTERVAL_NS),

	LAVD_CC_PER_CORE_SHIFT		= 1,  /* 50%: maximum per-core CPU utilization */
	LAVD_CC_UTIL_SPIKE		= p2s(90), /* When the CPU utilization is almost full (90%),
						      it is likely that the actual utilization is even
						      higher than that. */
	LAVD_CC_CPU_PIN_INTERVAL	= (250ULL * NSEC_PER_MSEC),
	LAVD_CC_CPU_PIN_INTERVAL_DIV	= (LAVD_CC_CPU_PIN_INTERVAL / LAVD_SYS_STAT_INTERVAL_NS),

	LAVD_AP_HIGH_UTIL_DFL_SMT_RT	= p2s(25),
	LAVD_AP_HIGH_UTIL_DFL_NO_SMT_RT	= p2s(50), /* 50%: balanced mode when 10% < cpu util <= 50%,
							  performance mode when cpu util > 50% */

	LAVD_CPDOM_MIG_SHIFT_UL		= 2, /* when under-loaded:  1/2**2 = [-25.0%, +25.0%] */
	LAVD_CPDOM_MIG_SHIFT		= 3, /* when midely loaded: 1/2**3 = [-12.5%, +12.5%] */
	LAVD_CPDOM_MIG_SHIFT_OL		= 4, /* when over-loaded:   1/2**4 = [-6.25%, +6.25%] */
	LAVD_CPDOM_MIG_PROB_FT		= (LAVD_SYS_STAT_INTERVAL_NS / LAVD_SLICE_MAX_NS_DFL), /* roughly twice per interval */

	LAVD_FUTEX_OP_INVALID		= -1,
};

enum consts_flags {
	LAVD_FLAG_FUTEX_BOOST		= (0x1 << 0), /* futex acquired or not */
	LAVD_FLAG_NEED_LOCK_BOOST	= (0x1 << 1), /* need to boost lock for deadline calculation */
	LAVD_FLAG_IS_GREEDY		= (0x1 << 2), /* task's overscheduling ratio compared to its nice priority */
	LAVD_FLAG_IS_AFFINITIZED	= (0x1 << 3), /* is this task pinned to a subset of all CPUs? */
	LAVD_FLAG_IS_WAKEUP		= (0x1 << 4), /* is this a wake up? */
	LAVD_FLAG_IS_SYNC_WAKEUP	= (0x1 << 5), /* is this a sync wake up? */
	LAVD_FLAG_ON_BIG		= (0x1 << 6), /* can a task run on a big core? */
	LAVD_FLAG_ON_LITTLE		= (0x1 << 7), /* can a task run on a little core? */
	LAVD_FLAG_SLICE_BOOST		= (0x1 << 8), /* task's time slice is boosted. */
	LAVD_FLAG_IDLE_CPU_PICKED	= (0x1 << 9), /* an idle CPU is picked at ops.select_cpu() */
};

/*
 * Compute domain context
 * - system > numa node > llc domain > compute domain per core type (P or E)
 */
struct cpdom_ctx {
	u64	id;				    /* id of this compute domain */
	u64	alt_id;				    /* id of the closest compute domain of alternative type */
	u8	numa_id;			    /* numa domain id */
	u8	llc_id;				    /* llc domain id */
	u8	is_big;				    /* is it a big core or little core? */
	u8	is_valid;			    /* is this a valid compute domain? */
	u8	is_stealer;			    /* this domain should steal tasks from others */
	u8	is_stealee;			    /* stealer doamin should steal tasks from this domain */
	u16	nr_cpus;			    /* the number of CPUs in this compute domain */
	u16	nr_active_cpus;			    /* the number of active CPUs in this compute domain */
	u16	nr_acpus_temp;			    /* temp for nr_active_cpus */
	u32	sc_load;			    /* scaled load considering DSQ length and CPU utilization */
	u32	nr_queued_task;			    /* the number of queued tasks in this domain */
	u32	cur_util_sum;			    /* the sum of CPU utilization in the current interval */
	u32	avg_util_sum;			    /* the sum of average CPU utilization */
	u32	cap_sum_active_cpus;		    /* the sum of capacities of active CPUs in this domain */
	u32	cap_sum_temp;			    /* temp for cap_sum_active_cpus */
	u32	dsq_consume_lat;		    /* latency to consume from dsq, shows how contended the dsq is */
	u8	nr_neighbors[LAVD_CPDOM_MAX_DIST];  /* number of neighbors per distance */
	u64	neighbor_bits[LAVD_CPDOM_MAX_DIST]; /* bitmask of neighbor bitmask per distance */
	u64	__cpumask[LAVD_CPU_ID_MAX/64];	    /* cpumasks belongs to this compute domain */
} __attribute__((aligned(CACHELINE_SIZE)));

extern struct cpdom_ctx		cpdom_ctxs[LAVD_CPDOM_MAX_NR];
extern struct bpf_cpumask	cpdom_cpumask[LAVD_CPDOM_MAX_NR];
extern int			nr_cpdoms;

typedef struct task_ctx __arena task_ctx;

u64 get_task_ctx_internal(struct task_struct *p);
#define get_task_ctx(p) ((task_ctx *)get_task_ctx_internal((p)))

struct cpu_ctx *get_cpu_ctx(void);
struct cpu_ctx *get_cpu_ctx_id(s32 cpu_id);
struct cpu_ctx *get_cpu_ctx_task(const struct task_struct *p);

/*
 * CPU context
 */
struct cpu_ctx {
	/* 
	 * Information used to keep track of CPU utilization
	 */
	volatile u32	avg_util;	/* average of the CPU utilization */
	volatile u32	cur_util;	/* CPU utilization of the current interval */
	volatile u32	avg_sc_util;	/* average of the scaled CPU utilization, which is capacity and frequency invariant. */
	volatile u32	cur_sc_util;	/* the scaled CPU utilization of the current interval, which is capacity and frequency invariant. */
	volatile u64	idle_total;	/* total idle time so far */
	volatile u64	idle_start_clk;	/* when the CPU becomes idle */

	/*
	 * Information used to keep track of load
	 */
	volatile u64	tot_svc_time;	/* total service time on a CPU scaled by tasks' weights */
	volatile u64	tot_sc_time;	/* total scaled CPU time, which is capacity and frequency invariant. */
	volatile u64	cpu_release_clk; /* when the CPU is taken by higher-priority scheduler class */

	/*
	 * Information used to keep track of latency criticality
	 */
	volatile u32	max_lat_cri;	/* maximum latency criticality */
	volatile u32	nr_sched;	/* number of schedules */
	volatile u64	sum_lat_cri;	/* sum of latency criticality */

	/*
	 * Information used to keep track of performance criticality
	 */
	volatile u64	sum_perf_cri;	/* sum of performance criticality */
	volatile u32	min_perf_cri;	/* mininum performance criticality */
	volatile u32	max_perf_cri;	/* maximum performance criticality */

	/*
	 * Information of a current running task for preemption
	 */
	volatile u64	running_clk;	/* when a task starts running */
	volatile u64	est_stopping_clk; /* estimated stopping time */
	volatile u64	flags;		/* cached copy of task's flags */
	volatile u32	nr_pinned_tasks; /* the number of pinned tasks waiting for running on this CPU */
	volatile s32	futex_op;	/* futex op in futex V1 */
	volatile u16	lat_cri;	/* latency criticality */
	volatile u8	is_online;	/* is this CPU online? */

	/*
	 * Information for CPU frequency scaling
	 */
	u32		cpuperf_cur;	/* CPU's current performance target */

	/*
	 * Fields for core compaction
	 *
	 */
	u16		cpu_id;		/* cpu id */
	u16		capacity;	/* CPU capacity based on 1024 */
	u8		big_core;	/* is it a big core? */
	u8		turbo_core;	/* is it a turbo core? */
	u8		llc_id;		/* llc domain id */
	u8		cpdom_id;	/* compute domain id */
	u8		cpdom_alt_id;	/* compute domain id of anternative type */
	u8		cpdom_poll_pos;	/* index to check if a DSQ of a compute domain is starving */

	/*
	 * Information for statistics.
	 */
	volatile u32	nr_preempt;
	volatile u32	nr_x_migration;
	volatile u32	nr_perf_cri;
	volatile u32	nr_lat_cri;

	/*
	 * Information for cpu hotplug
	 */
	u64		online_clk;	/* when a CPU becomes online */
	u64		offline_clk;	/* when a CPU becomes offline */

	/*
	 * Temporary cpu masks
	 */
	struct bpf_cpumask __kptr *tmp_a_mask; /* for active set */
	struct bpf_cpumask __kptr *tmp_o_mask; /* for overflow set */
	struct bpf_cpumask __kptr *tmp_l_mask; /* for online cpumask */
	struct bpf_cpumask __kptr *tmp_i_mask; /* for idle cpumask */
	struct bpf_cpumask __kptr *tmp_t_mask;
	struct bpf_cpumask __kptr *tmp_t2_mask;
	struct bpf_cpumask __kptr *tmp_t3_mask;
} __attribute__((aligned(CACHELINE_SIZE)));

extern const volatile u64	nr_llcs;	/* number of LLC domains */
const extern volatile u32	nr_cpu_ids;
extern volatile u64		nr_cpus_onln;	/* current number of online CPUs */

extern const volatile u16	cpu_capacity[LAVD_CPU_ID_MAX];
extern const volatile u8	cpu_big[LAVD_CPU_ID_MAX];
extern const volatile u8	cpu_turbo[LAVD_CPU_ID_MAX];

/* Logging helpers. */

extern const volatile bool	no_wake_sync;
extern const volatile bool	no_slice_boost;
extern const volatile u8	verbose;

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

/* Arithmetic helpers. */

#ifndef min
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifndef max
#define max(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef clamp
#define clamp(val, lo, hi) min(max(val, lo), hi)
#endif

u64 calc_avg(u64 old_val, u64 new_val);
u64 calc_asym_avg(u64 old_val, u64 new_val);

/* Bitmask helpers. */
static __always_inline int cpumask_next_set_bit(u64 *cpumask)
{
	/*
	 * Check the cpumask is not empty. ctzll(x) is only well-defined
	 * for nonzero x; that's why we check for zero earlier to avoid
	 * undefined behavior.
	 */
	if (!*cpumask)
		return -ENOENT;

	/* Find the next set bit. */
	int bit = ctzll(*cpumask);

	/*
	 * This is equivalent to finding and clearing the least significant set
	 * bit.  The statement works because subtracting one from a nonzero bit
	 * flips all bits from the lowest set bit (inclusive) to the rightmost
	 * position; Then, The logic here ANDing it with the original value
	 * clears the lowest set bit.
	 */
	*cpumask &= *cpumask - 1;
	return bit;
}

/* System statistics module .*/
extern struct sys_stat		sys_stat;

s32 init_sys_stat(u64 now);
int update_sys_stat(void);

extern volatile u64		performance_mode_ns;
extern volatile u64		balanced_mode_ns;
extern volatile u64		powersave_mode_ns;

/* Helpers from util.bpf.c for querying CPU/task state. */
extern const volatile bool	per_cpu_dsq;
extern const volatile u64	pinned_slice_ns;

extern volatile bool		reinit_cpumask_for_performance;
extern volatile bool		no_preemption;
extern volatile bool		no_core_compaction;
extern volatile bool		no_freq_scaling;

bool test_cpu_flag(struct cpu_ctx *cpuc, u64 flag);
void set_cpu_flag(struct cpu_ctx *cpuc, u64 flag);
void reset_cpu_flag(struct cpu_ctx *cpuc, u64 flag);

bool is_lock_holder(task_ctx *taskc);
bool is_lock_holder_running(struct cpu_ctx *cpuc);
bool have_scheduled(task_ctx *taskc);
bool have_pending_tasks(struct cpu_ctx *cpuc);
bool can_boost_slice(void);
bool is_lat_cri(task_ctx *taskc);
u16 get_nice_prio(struct task_struct *p);
u32 cpu_to_dsq(u32 cpu);

void set_task_flag(task_ctx *taskc, u64 flag);
void reset_task_flag(task_ctx *taskc, u64 flag);
bool test_task_flag(task_ctx *taskc, u64 flag);
void reset_task_flag(task_ctx *taskc, u64 flag);

static __always_inline bool use_per_cpu_dsq(void)
{
	return per_cpu_dsq || pinned_slice_ns;
}

static __always_inline bool use_cpdom_dsq(void)
{
	return !per_cpu_dsq;
}

s32 nr_queued_on_cpu(struct cpu_ctx *cpuc);
u64 get_target_dsq_id(struct task_struct *p, struct cpu_ctx *cpuc);

extern struct bpf_cpumask __kptr *turbo_cpumask; /* CPU mask for turbo CPUs */
extern struct bpf_cpumask __kptr *big_cpumask; /* CPU mask for big CPUs */
extern struct bpf_cpumask __kptr *little_cpumask; /* CPU mask for little CPUs */
extern struct bpf_cpumask __kptr *active_cpumask; /* CPU mask for active CPUs */
extern struct bpf_cpumask __kptr *ovrflw_cpumask; /* CPU mask for overflow CPUs */

/* Power management helpers. */
int do_core_compaction(void);
int update_thr_perf_cri(void);
int reinit_active_cpumask_for_performance(void);
bool is_perf_cri(task_ctx *taskc);

extern bool			have_little_core;
extern bool			have_turbo_core;
extern const volatile bool	is_smt_active;

extern u64			total_capacity;
extern u64			one_little_capacity;
extern u32			cur_big_core_scale;
extern u32			default_big_core_scale;

int init_autopilot_caps(void);
int update_autopilot_high_cap(void);
u64 scale_cap_freq(u64 dur, s32 cpu);

int reset_cpuperf_target(struct cpu_ctx *cpuc);
int update_cpuperf_target(struct cpu_ctx *cpuc);
u16 get_cpuperf_cap(s32 cpu);

int reset_suspended_duration(struct cpu_ctx *cpuc);
u64 get_suspended_duration_and_reset(struct cpu_ctx *cpuc);

const volatile u16 *get_cpu_order(void);

/* Load balancer helpers. */

int plan_x_cpdom_migration(void);

/* Preemption management helpers. */
void shrink_slice_at_tick(struct task_struct *p, struct cpu_ctx *cpuc, u64 now);

/* Futex lock-related helpers. */

void reset_lock_futex_boost(task_ctx *taskc, struct cpu_ctx *cpuc);

/* Scheduler introspection-related helpers. */

u64 get_est_stopping_clk(task_ctx *taskc, u64 now);
void try_proc_introspec_cmd(struct task_struct *p, task_ctx *taskc);
void reset_cpu_preemption_info(struct cpu_ctx *cpuc, bool released);
int shrink_boosted_slice_remote(struct cpu_ctx *cpuc, u64 now);
void shrink_boosted_slice_at_tick(struct task_struct *p,
					 struct cpu_ctx *cpuc, u64 now);
void preempt_at_tick(struct task_struct *p, struct cpu_ctx *cpuc);
void try_find_and_kick_victim_cpu(struct task_struct *p,
					 task_ctx *taskc,
					 s32 preferred_cpu,
					 u64 dsq_id);

extern volatile bool is_monitored;

#endif /* __LAVD_H */
