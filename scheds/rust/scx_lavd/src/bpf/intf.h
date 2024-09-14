/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;

#define U64_MAX ((u64)~0ULL)

enum {
	TASK_COMM_LEN = 16,
	SCX_SLICE_INF = U64_MAX,
};

#define __kptr
#endif

#ifdef __VMLINUX_H__
#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)
#define MAX_RT_PRIO	100

struct bpf_iter_task;
extern int bpf_iter_task_new(struct bpf_iter_task *it,
		struct task_struct *task, unsigned int flags) __weak __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __weak __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __weak __ksym;
#endif /* __KERNEL__ */

/*
 * common constants
 */
enum consts {
	CLOCK_BOOTTIME			= 7,
	CACHELINE_SIZE			= 64,
	NSEC_PER_USEC			= 1000ULL,
	NSEC_PER_MSEC			= (1000ULL * NSEC_PER_USEC),
	LAVD_TIME_ONE_SEC		= (1000ULL * NSEC_PER_MSEC),
	LAVD_TIME_INFINITY_NS		= SCX_SLICE_INF,
	LAVD_MAX_RETRY			= 4,

	LAVD_TARGETED_LATENCY_NS	= (20ULL * NSEC_PER_MSEC),
	LAVD_SLICE_MIN_NS		= (300ULL * NSEC_PER_USEC), /* min time slice */
	LAVD_SLICE_MAX_NS		= (3ULL * NSEC_PER_MSEC), /* max time slice */
	LAVD_SLICE_UNDECIDED		= SCX_SLICE_INF,

	LAVD_LC_FREQ_MAX		= 1000000,
	LAVD_LC_RUNTIME_MAX		= LAVD_TARGETED_LATENCY_NS,
	LAVD_LC_RUNTIME_SHIFT		= 15,
	LAVD_LC_WAKEUP_FT		= 30,
	LAVD_LC_KTHREAD_FT		= 30,

	LAVD_SLICE_BOOST_MAX_FT		= 3, /* maximum additional 3x of slice */
	LAVD_SLICE_BOOST_MAX_STEP	= 6, /* 6 slice exhausitions in a row */
	LAVD_NEW_PROC_PENALITY		= 5,
	LAVD_GREEDY_RATIO_NEW		= (1000 * LAVD_NEW_PROC_PENALITY),

	LAVD_CPU_UTIL_MAX		= 1000, /* 100.0% */
	LAVD_CPU_UTIL_MAX_FOR_CPUPERF	= 850, /* 85.0% */
	LAVD_CPU_ID_HERE		= ((u32)-2),
	LAVD_CPU_ID_NONE		= ((u32)-1),
	LAVD_CPU_ID_MAX			= 512,

	LAVD_PREEMPT_KICK_MARGIN	= (1ULL * NSEC_PER_MSEC),
	LAVD_PREEMPT_TICK_MARGIN	= (100ULL * NSEC_PER_USEC),

	LAVD_SYS_STAT_INTERVAL_NS	= (50ULL * NSEC_PER_MSEC),
	LAVD_SYS_STAT_DECAY_TIMES	= (2ULL * LAVD_TIME_ONE_SEC) / LAVD_SYS_STAT_INTERVAL_NS,
	LAVD_CC_PER_CORE_MAX_CTUIL	= 500, /* maximum per-core CPU utilization */
	LAVD_CC_PER_TURBO_CORE_MAX_CTUIL = 750, /* maximum per-core CPU utilization for a turbo core */
	LAVD_CC_NR_ACTIVE_MIN		= 1, /* num of mininum active cores */
	LAVD_CC_NR_OVRFLW		= 1, /* num of overflow cores */
	LAVD_CC_CPU_PIN_INTERVAL	= (1ULL * LAVD_TIME_ONE_SEC),
	LAVD_CC_CPU_PIN_INTERVAL_DIV	= (LAVD_CC_CPU_PIN_INTERVAL /
					   LAVD_SYS_STAT_INTERVAL_NS),

	LAVD_AP_HIGH_UTIL		= 700, /* balanced mode when 10% < cpu util <= 40%,
						  performance mode when cpu util > 40% */

	LAVD_CPDOM_MAX_NR		= 32, /* maximum number of compute domain */
	LAVD_CPDOM_MAX_DIST		= 4,  /* maximum distance from one compute domain to another */
	LAVD_CPDOM_STARV_NS		= (5ULL * NSEC_PER_MSEC),

	LAVD_STATUS_STR_LEN		= 5, /* {LR: Latency-critical, Regular}
						{HI: performance-Hungry, performance-Insensitive}
						{BT: Big, liTtle}
						{EG: Eligible, Greedy}
						{PN: Preemption, Not} */
};

/*
 * System-wide stats
 */
struct sys_stat {
	volatile u64	last_update_clk;
	volatile u64	util;		/* average of the CPU utilization */

	volatile u64	load_actual;	/* average actual load of runnable tasks */
	volatile u64	avg_svc_time;	/* average service time per task */
	volatile u64	nr_queued_task;

	volatile u32	avg_lat_cri;	/* average latency criticality (LC) */
	volatile u32	max_lat_cri;	/* maximum latency criticality (LC) */
	volatile u32	thr_lat_cri;	/* latency criticality threshold for kicking */

	volatile u32	avg_perf_cri;	/* average performance criticality */

	volatile u32	nr_violation;	/* number of utilization violation */
	volatile u32	nr_active;	/* number of active cores */

	volatile u64	nr_sched;	/* total scheduling so far */
	volatile u64	nr_migration;	/* number of task migration */
	volatile u64	nr_preemption;	/* number of preemption */
	volatile u64	nr_greedy;	/* number of greedy tasks scheduled */
	volatile u64	nr_perf_cri;	/* number of performance-critical tasks scheduled */
	volatile u64	nr_lat_cri;	/* number of latency-critical tasks scheduled */
	volatile u64	nr_big;		/* scheduled on big core */
	volatile u64	nr_pc_on_big;	/* performance-critical tasks scheduled on big core */
	volatile u64	nr_lc_on_big;	/* latency-critical tasks scheduled on big core */
};

/*
 * Compute domain context
 * - system > numa node > llc domain > compute domain per core type (P or E)
 */
struct cpdom_ctx {
	u64	id;				    /* id of this compute domain (== dsq_id) */
	u64	alt_id;				    /* id of the closest compute domain of alternative type (== dsq id) */
	u64	last_consume_clk;		    /* when the associated DSQ was consumed */
	u8	is_big;				    /* is it a big core or little core? */
	u8	is_active;			    /* if this compute domain is active */
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
	volatile u64	load_actual;	/* actual load of runnable tasks */
	volatile u64	load_run_time_ns; /* total runtime of runnable tasks */
	volatile u64	tot_svc_time;	/* total service time on a CPU */
	volatile u64	last_kick_clk;	/* when the CPU was kicked */

	/*
	 * Information for cpu hotplug
	 */
	u64		online_clk;	/* when a CPU becomes online */
	u64		offline_clk;	/* when a CPU becomes offline */

	/*
	 * Information used to keep track of latency criticality
	 */
	volatile u32	max_lat_cri;	/* maximum latency criticality */
	volatile u32	sum_lat_cri;	/* sum of latency criticality */
	volatile u32	nr_sched;	/* number of schedules */

	/*
	 * Information used to keep track of performance criticality
	 */
	volatile u64	sum_perf_cri;	/* sum of performance criticality */

	/*
	 * Information of a current running task for preemption
	 */
	volatile u64	stopping_tm_est_ns; /* estimated stopping time */
	volatile u16	lat_cri;	/* latency criticality */
	volatile u8	is_online;	/* is this CPU online? */
	s32		cpu_id;		/* cpu id */

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
	u16		capacity;	/* CPU capacity based on 1000 */
	u8		big_core;	/* is it a big core? */
	u8		turbo_core;	/* is it a turbo core? */
	u8		cpdom_id;	/* compute domain id (== dsq_id) */
	u8		cpdom_alt_id;	/* compute domain id of anternative type (== dsq_id) */
	u8		cpdom_poll_pos;	/* index to check if a DSQ of a compute domain is starving */
	struct bpf_cpumask __kptr *tmp_a_mask;	/* temporary cpu mask */
	struct bpf_cpumask __kptr *tmp_o_mask;	/* temporary cpu mask */
	struct bpf_cpumask __kptr *tmp_t_mask;	/* temporary cpu mask */
	struct bpf_cpumask __kptr *tmp_t2_mask;	/* temporary cpu mask */

	/*
	 * Information for statistics.
	 */
	volatile u32	nr_migration;	/* number of migrations */
	volatile u32	nr_preemption;	/* number of migrations */
	volatile u32	nr_greedy;	/* number of greedy tasks scheduled */
	volatile u32	nr_perf_cri;
	volatile u32	nr_lat_cri;
} __attribute__((aligned(CACHELINE_SIZE)));

/*
 * Task context
 */
struct task_ctx {
	/*
	 * Clocks when a task state transition happens for task statistics calculation
	 */
	u64	last_runnable_clk;	/* last time when a task wakes up others */
	u64	last_running_clk;	/* last time when scheduled in */
	u64	last_stopping_clk;	/* last time when scheduled out */
	u64	last_quiescent_clk;	/* last time when a task waits for an event */

	/*
	 * Task running statistics for latency criticality calculation
	 */
	u64	acc_run_time_ns;	/* accmulated runtime from runnable to quiescent state */
	u64	run_time_ns;		/* average runtime per schedule */
	u64	run_freq;		/* scheduling frequency in a second */
	u64	wait_freq;		/* waiting frequency in a second */

	u64	wake_freq;		/* waking-up frequency in a second */
	u64	load_actual;		/* task load derived from run_time and run_freq */
	u64	svc_time;		/* total CPU time consumed for this task */

	/*
	 * Task deadline and time slice
	 */
	u64	vdeadline_log_clk;	/* logical clock of the deadilne */
	u64	vdeadline_delta_ns;	/* time delta until task's virtual deadline */
	u64	slice_ns;		/* time slice */
	u32	greedy_ratio;		/* task's overscheduling ratio compared to its nice priority */
	u32	lat_cri;		/* calculated latency criticality */
	volatile s32 victim_cpu;
	u16	slice_boost_prio;	/* how many times a task fully consumed the slice */
	u8	wakeup_ft;		/* regular wakeup = 1, sync wakeup = 2 */

	/*
	 * Task's performance criticality
	 */
	u8	on_big;			/* executable on a big core */
	u8	on_little;		/* executable on a little core */
	u32	perf_cri;		/* performance criticality of a task */

	/*
	 * Information for statistics collection
	 */
	u32	cpu_id;			/* CPU ID scheduled on */
};

/*
 * Task's extra context for report
 */
struct task_ctx_x {
	pid_t	pid;
	char	comm[TASK_COMM_LEN + 1];
	char	stat[LAVD_STATUS_STR_LEN + 1];
	u16	static_prio;	/* nice priority */
	u32	cpu_id;		/* where a task ran */
	u64	cpu_util;	/* cpu utilization in [0..100] */
	u32	avg_perf_cri;	/* average performance criticality */
	u32	avg_lat_cri;	/* average latency criticality */
	u32	nr_active;	/* number of active cores */
	u32	cpuperf_cur;	/* CPU's current performance target */
};


/*
 * introspection
 */
enum {
       LAVD_CMD_NOP		= 0x0,
       LAVD_CMD_SCHED_N		= 0x1,
};

enum {
       LAVD_MSG_TASKC		= 0x1,
};

struct introspec {
	volatile u64	arg;
	volatile u32	cmd;
};

struct msg_hdr {
	u32		kind;
};

struct msg_task_ctx {
	struct msg_hdr		hdr;
	struct task_ctx		taskc;
	struct task_ctx_x	taskc_x;
};


/*
 * BPF syscall
 */
enum {
	LAVD_PM_PERFORMANCE	= 0,
	LAVD_PM_BALANCED	= 1,
	LAVD_PM_POWERSAVE	= 2,

	LAVD_PM_MAX		= 3
};

struct power_arg {
	s32	power_mode;
};

#endif /* __INTF_H */
