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

enum {
	TASK_COMM_LEN = 16,
};

#endif

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
 * Task information for report
 */
struct task_ctx_x {
	pid_t	pid;			/* pid for this task */
	char	comm[TASK_COMM_LEN + 1];
	char	stat[LAVD_STATUS_STR_LEN + 1];
	u32	cpu_id;			/* where a task is running now */
	u32	prev_cpu_id;		/* where a task ran last time */
	u32	suggested_cpu_id;	/* suggested CPU ID at ops.enqueue() and ops.select_cpu() */
	pid_t	waker_pid;		/* last waker's PID */
	char	waker_comm[TASK_COMM_LEN + 1]; /* last waker's comm */
	u64	slice;		/* base time slice */
	u16	normalized_lat_cri;	/* lat_cri normalized to [0, 1024] scale */
	u32	avg_lat_cri;	/* average latency criticality */
	u16	static_prio;	/* nice priority */
	u64	rerunnable_interval;	/* rerunnable interval in ns: [last quiescent, last runnable] */
	u64	resched_interval;	/* reschedule interval in ns: [last running, this running] */
	u64	run_freq;		/* scheduling frequency in a second */
	u64	avg_runtime;		/* average runtime per schedule */
	u64	wait_freq;		/* waiting frequency in a second */
	u64	wake_freq;		/* waking-up frequency in a second */
	u32	perf_cri;		/* performance criticality of a task */
	u32	thr_perf_cri;	/* performance criticality threshold */
	u32	cpuperf_cur;	/* CPU's current performance target */
	u32	lat_capacity;	/* latency capacity: 1024 - avg_stolen_est */
	u64	cpu_sutil;	/* scaled cpu utilization in [0..100] */
	u32	nr_active;	/* number of active cores */
	u64	dsq_id;		/* CPU's associated DSQ */
	u64	dsq_consume_lat; /* DSQ's consume latency */
	u64	last_slice_used;	/* time(ns) used in last scheduled interval: [last running, last stopping] */
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
