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
enum {
	LAVD_CPU_ID_MAX			= 512,

	LAVD_CPDOM_MAX_NR		= 128, /* maximum number of compute domain */
	LAVD_CPDOM_MAX_DIST		= 3,  /* maximum distance from one compute domain to another */

	LAVD_PCO_STATE_MAX		= 11, /* maximum number of performance vs. CPU order states */

	LAVD_STATUS_STR_LEN		= 4,  /* {LR: Latency-critical, Regular}
						 {HI: performance-Hungry, performance-Insensitive}
						 {BT: Big, liTtle}
						 {EG: Eligible, Greedy} */
};

/*
 *  DSQ (dispatch queue) IDs are 64bit of the format:
 *  Lower 63 bits are reserved by users
 *
 *   Bits: [63] [62 .. 14] [13 .. 12] [11 .. 0]
 *         [ B] [    R   ] [    T   ] [   ID  ]
 *
 *    B: Sched_ext built-in ID bit, see include/linux/sched/ext.h
 *    R: Reserved
 *    T: Type of LAVD DSQ
 *   ID: DSQ ID
 */
enum {
	LAVD_DSQ_TYPE_SHFT		= 12,
	LAVD_DSQ_TYPE_MASK		= 0x3 << LAVD_DSQ_TYPE_SHFT,
	LAVD_DSQ_ID_SHFT		= 0,
	LAVD_DSQ_ID_MASK		= 0xfff << LAVD_DSQ_ID_SHFT,
	LAVD_DSQ_NR_TYPES		= 2,
	LAVD_DSQ_TYPE_CPDOM		= 1,
	LAVD_DSQ_TYPE_CPU		= 0,
};

/*
 * System-wide stats
 */
struct sys_stat {
	u64	last_update_clk;
	u64	avg_util;	/* average of the CPU utilization */
	u64	avg_sc_util;	/* average of the scaled CPU utilization,
				   which is capacity and frequency invariant */

	u64	avg_svc_time;	/* average service time per task */
	u64	nr_queued_task;
	u64	slice;		/* base time slice */

	u32	avg_lat_cri;	/* average latency criticality (LC) */
	u32	max_lat_cri;	/* maximum latency criticality (LC) */
	u32	thr_lat_cri;	/* latency criticality threshold for kicking */

	u32	min_perf_cri;	/* minimum performance criticality */
	u32	avg_perf_cri;	/* average performance criticality */
	u32	max_perf_cri;	/* maximum performance criticality */
	u32	thr_perf_cri;	/* performance criticality threshold */

	u32	nr_stealee;	/* number of compute domains to be migrated */
	u32	nr_active;	/* number of active CPUs */
	u32	nr_active_cpdoms; /* number of active compute domains */

	u64	nr_sched;	/* total scheduling so far */
	u64	nr_preempt;	/* total number of preemption operations triggered */
	u64	nr_perf_cri;	/* number of performance-critical tasks scheduled */
	u64	nr_lat_cri;	/* number of latency-critical tasks scheduled */
	u64	nr_x_migration; /* number of cross domain migration */
	u64	nr_big;		/* scheduled on big core */
	u64	nr_pc_on_big;	/* performance-critical tasks scheduled on big core */
	u64	nr_lc_on_big;	/* latency-critical tasks scheduled on big core */
};

/*
 * Task context
 */
struct atq_ctx {
	u64	dummy[8];
};

struct task_ctx {
	/*
	 * Do NOT change the position of atq. It should be at the beginning
	 * of the task_ctx. 
	 *
	 * TODO: The type of atq should be scx_task_common. However, to
	 * workaround the complex header dependencies, a large enough space
	 * that can hold scx_task_common is allocated for now. This will be
	 * fixed later after some more refactoring.
	 */
	struct atq_ctx atq;

	/*
	 * Clocks when a task state transition happens for task statistics calculation
	 */
	u64	last_runnable_clk;	/* last time when a task became runnable */
	u64	last_running_clk;	/* last time when scheduled in */
	u64	last_measured_clk;	/* last time when running time was measured */
	u64	last_stopping_clk;	/* last time when scheduled out */
	u64	last_quiescent_clk;	/* last time when a task became asleep */

	/*
	 * Task running statistics for latency criticality calculation
	 */
	u64	acc_runtime;		/* accmulated runtime from runnable to quiescent state */
	u64	avg_runtime;		/* average runtime per schedule */
	u64	run_freq;		/* scheduling frequency in a second */
	u64	wait_freq;		/* waiting frequency in a second */
	u64	wake_freq;		/* waking-up frequency in a second */
	u64	svc_time;		/* total CPU time consumed for this task scaled by task's weight */
	u32	prev_cpu_id;		/* where a task ran last time */

	/*
	 * Task deadline and time slice
	 */
	u32	lat_cri;		/* final context-aware latency criticality */
	u32	lat_cri_waker;		/* waker's latency criticality */
	u32	perf_cri;		/* performance criticality of a task */
	u64	slice;			/* time slice */

	/*
	 * Task cgroup and id
	 */
	pid_t	pid;			/* pid for this task */
	u64	cgrp_id;		/* cgroup id of this task */

	/*
	 * Task status
	 */
	volatile u64	flags;		/* LAVD_FLAG_* */
	u32	cpdom_id;		/* chosen compute domain id at ops.enqueue() */
	u32	suggested_cpu_id;	/* suggested CPU ID at ops.enqueue() and ops.select_cpu() */

	/*
	 * Additional information when the scheduler is monitored,
	 * so it is updated only when is_monitored is true.
	 */
	u64	resched_interval;	/* reschedule interval in ns: [last running, this running] */
	u32	cpu_id;			/* where a task is running now */
	u64	last_slice_used;	/* time(ns) used in last scheduled interval: [last running, last stopping] */
	pid_t	waker_pid;		/* last waker's PID */
	char	waker_comm[TASK_COMM_LEN + 1]; /* last waker's comm */
};

/*
 * Task's extra context for report
 */
struct task_ctx_x {
	char	comm[TASK_COMM_LEN + 1];
	char	stat[LAVD_STATUS_STR_LEN + 1];
	u16	static_prio;	/* nice priority */
	u64	cpu_util;	/* cpu utilization in [0..100] */
	u64	cpu_sutil;	/* scaled cpu utilization in [0..100] */
	u64	rerunnable_interval;	/* rerunnable interval in ns: [last quiescent, last runnable] */
	u32	thr_perf_cri;	/* performance criticality threshold */
	u32	avg_lat_cri;	/* average latency criticality */
	u32	nr_active;	/* number of active cores */
	u32	cpuperf_cur;	/* CPU's current performance target */
	u64	dsq_id;		/* CPU's associated DSQ */
	u64	dsq_consume_lat; /* DSQ's consume latency */
};


/*
 * introspection
 */
enum {
       LAVD_CMD_NOP		= 0x0,
       LAVD_CMD_SCHED_N		= 0x1,
};

enum {
       LAVD_MSG_TASKC		= 0x1
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
