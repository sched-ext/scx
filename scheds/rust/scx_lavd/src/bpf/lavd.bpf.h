/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#ifndef __LAVD_H
#define __LAVD_H

/*
 * common macros
 */
#define U64_MAX		((u64)~0U)
#define S64_MAX		((s64)(U64_MAX >> 1))
#define U32_MAX		((u32)~0U)
#define S32_MAX		((s32)(U32_MAX >> 1))

#define LAVD_SHIFT			10
#define LAVD_SCALE			(1L << LAVD_SHIFT)
#define p2s(percent)			(((percent) << LAVD_SHIFT) / 100)
#define s2p(scale)			(((scale) * 100) >> LAVD_SHIFT)

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

	LAVD_TARGETED_LATENCY_NS	= (20ULL * NSEC_PER_MSEC),
	LAVD_SLICE_MIN_NS_DFL		= (500ULL * NSEC_PER_USEC), /* min time slice */
	LAVD_SLICE_MAX_NS_DFL		= (5ULL * NSEC_PER_MSEC), /* max time slice */
	LAVD_ACC_RUNTIME_MAX		= LAVD_SLICE_MAX_NS_DFL,
	LAVD_DL_COMPETE_WINDOW		= (LAVD_SLICE_MAX_NS_DFL >> 14), /* assuming task's latency
									    criticality is around 1000. */

	LAVD_LC_FREQ_MAX                = 400000,
	LAVD_LC_RUNTIME_MAX		= LAVD_TIME_ONE_SEC,
	LAVD_LC_WEIGHT_BOOST		= 128, /* 2^7 */
	LAVD_LC_GREEDY_SHIFT		= 3, /* 12.5% */
	LAVD_LC_INH_WAKEE_SHIFT		= 2, /* 25.0% of wakee's latency criticality */
	LAVD_LC_INH_WAKER_SHIFT		= 3, /* 12.5 of waker's latency criticality */

	LAVD_CPU_UTIL_MAX_FOR_CPUPERF	= p2s(85), /* 85.0% */

	LAVD_SYS_STAT_INTERVAL_NS	= LAVD_TARGETED_LATENCY_NS,
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
	LAVD_CPDOM_MIG_PROB_FT		= (LAVD_SYS_STAT_INTERVAL_NS / (2 * LAVD_SLICE_MAX_NS_DFL)), /* roughly twice per interval */

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
};

/*
 * Compute domain context
 * - system > numa node > llc domain > compute domain per core type (P or E)
 */
struct cpdom_ctx {
	u64	id;				    /* id of this compute domain (== dsq_id) */
	u64	alt_id;				    /* id of the closest compute domain of alternative type (== dsq id) */
	u8	node_id;			    /* numa domain id */
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
	u32	cap_sum_active_cpus;		    /* the sum of capacities of active CPUs in this domain */
	u32	cap_sum_temp;			    /* temp for cap_sum_active_cpus */
	u32	dsq_consume_lat;		    /* latency to consume from dsq, shows how contended the dsq is */
	u8	nr_neighbors[LAVD_CPDOM_MAX_DIST];  /* number of neighbors per distance */
	u64	neighbor_bits[LAVD_CPDOM_MAX_DIST]; /* bitmask of neighbor bitmask per distance */
	u64	__cpumask[LAVD_CPU_ID_MAX/64];	    /* cpumasks belongs to this compute domain */
} __attribute__((aligned(CACHELINE_SIZE)));

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
	u8		cpdom_id;	/* compute domain id (== dsq_id) */
	u8		cpdom_alt_id;	/* compute domain id of anternative type (== dsq_id) */
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


#endif /* __LAVD_H */
