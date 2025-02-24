/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#ifndef __LAVD_H
#define __LAVD_H

/*
 * common constants
 */
enum consts_internal  {
	CLOCK_BOOTTIME			= 7,
	CACHELINE_SIZE			= 64,

	NSEC_PER_USEC			= 1000ULL,
	NSEC_PER_MSEC			= (1000ULL * NSEC_PER_USEC),

	LAVD_TIME_ONE_SEC		= (1000ULL * NSEC_PER_MSEC),
	LAVD_MAX_RETRY			= 3,

	LAVD_TARGETED_LATENCY_NS	= (20ULL * NSEC_PER_MSEC),
	LAVD_SLICE_MIN_NS_DFL		= (300ULL * NSEC_PER_USEC), /* min time slice */
	LAVD_SLICE_MAX_NS_DFL		= (5ULL * NSEC_PER_MSEC), /* max time slice */

	LAVD_LC_FREQ_MAX		= 1000000,
	LAVD_LC_RUNTIME_MAX		= LAVD_TIME_ONE_SEC,
	LAVD_LC_WEIGHT_BOOST		= 128, /* 2^7 */
	LAVD_LC_GREEDY_PENALTY		= 20,  /* 20% */
	LAVD_LC_FREQ_OVER_RUNTIME	= 100,  /* 100x */

	LAVD_SLICE_BOOST_MAX_FT		= 3, /* maximum additional 3x of slice */
	LAVD_SLICE_BOOST_MAX_STEP	= 6, /* 6 slice exhausitions in a row */
	LAVD_NEW_PROC_PENALITY		= 5,
	LAVD_GREEDY_RATIO_NEW		= (1000 * LAVD_NEW_PROC_PENALITY),

	LAVD_CPU_UTIL_MAX		= 1000, /* 100.0% */
	LAVD_CPU_UTIL_MAX_FOR_CPUPERF	= 850, /* 85.0% */

	LAVD_SYS_STAT_INTERVAL_NS	= (50ULL * NSEC_PER_MSEC),
	LAVD_SYS_STAT_DECAY_TIMES	= ((2ULL * LAVD_TIME_ONE_SEC) / LAVD_SYS_STAT_INTERVAL_NS),

	LAVD_CC_PER_CORE_MAX_CTUIL	= 500, /* maximum per-core CPU utilization */
	LAVD_CC_PER_TURBO_CORE_MAX_CTUIL = 750, /* maximum per-core CPU utilization for a turbo core */
	LAVD_CC_NR_ACTIVE_MIN		= 1, /* num of mininum active cores */
	LAVD_CC_NR_OVRFLW		= 1, /* num of overflow cores */
	LAVD_CC_CPU_PIN_INTERVAL	= (1ULL * LAVD_TIME_ONE_SEC),
	LAVD_CC_CPU_PIN_INTERVAL_DIV	= (LAVD_CC_CPU_PIN_INTERVAL / LAVD_SYS_STAT_INTERVAL_NS),

	LAVD_AP_HIGH_UTIL		= 700, /* balanced mode when 10% < cpu util <= 40%,
						  performance mode when cpu util > 40% */

	LAVD_CPDOM_MIGRATION_SHIFT	= 3, /* 1/2**3 = +/- 12.5% */
	LAVD_CPDOM_X_PROB_FT		= (LAVD_SYS_STAT_INTERVAL_NS /
					   (2 * LAVD_SLICE_MAX_NS_DFL)), /* roughly twice per interval */

	LAVD_FUTEX_OP_INVALID		= -1,
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
	u8	is_active;			    /* if this compute domain is active */
	u8	is_stealer;			    /* this domain should steal tasks from others */
	u8	is_stealee;			    /* stealer doamin should steal tasks from this domain */
	u16	nr_cpus;			    /* the number of CPUs in this compute domain */
	u32	nr_q_tasks_per_cpu;		    /* the number of queued tasks per CPU in this domain (x1000) */
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
	volatile u64	util;		/* average of the CPU utilization */
	volatile u64	idle_total;	/* total idle time so far */
	volatile u64	idle_start_clk;	/* when the CPU becomes idle */

	/*
	 * Information used to keep track of load
	 */
	volatile u64	tot_svc_time;	/* total service time on a CPU */

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
	volatile u64	stopping_tm_est_ns; /* estimated stopping time */
	volatile s32	futex_op;	/* futex op in futex V1 */
	volatile u16	lat_cri;	/* latency criticality */
	volatile u8	is_online;	/* is this CPU online? */
	volatile u8	lock_holder;	/* is a lock holder running */

	/*
	 * Information for CPU frequency scaling
	 */
	u32		cpuperf_cur;	/* CPU's current performance target */
	u32		cpuperf_task;	/* task's CPU performance target */
	u32		cpuperf_avg;	/* EWMA of task's CPU performance target */

	/*
	 * Fields for core compaction
	 *
	 */
	u16		cpu_id;		/* cpu id */
	u16		capacity;	/* CPU capacity based on 1000 */
	u8		big_core;	/* is it a big core? */
	u8		turbo_core;	/* is it a turbo core? */
	u8		cpdom_id;	/* compute domain id (== dsq_id) */
	u8		cpdom_alt_id;	/* compute domain id of anternative type (== dsq_id) */
	u8		cpdom_poll_pos;	/* index to check if a DSQ of a compute domain is starving */

	/*
	 * Information for statistics.
	 */
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
	struct bpf_cpumask __kptr *tmp_a_mask;
	struct bpf_cpumask __kptr *tmp_o_mask;
	struct bpf_cpumask __kptr *tmp_t_mask;
	struct bpf_cpumask __kptr *tmp_t2_mask;
} __attribute__((aligned(CACHELINE_SIZE)));


#endif /* __LAVD_H */
