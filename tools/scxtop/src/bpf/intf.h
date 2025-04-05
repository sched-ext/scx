// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif
#include <stdbool.h>


enum consts {
	MAX_COMM	= 16,
};

enum stat_id {
	STAT_DROPPED_EVENTS,
	NR_SCXTOP_STATS,
};

enum mode {
	MODE_NORMAL,
	MODE_TRACING,
	MODE_TRACE_STOPPING,
};

enum event_type {
	CPU_HP_ENTER,
	CPU_HP_EXIT,
	CPU_PERF_SET,
	EXEC,
	EXIT,
	FORK,
	GPU_MEM,
	HW_PRESSURE,
	IPI,
	PSTATE_SAMPLE,
	SCHED_REG,
	SCHED_SWITCH,
	SCHED_UNREG,
	SCHED_WAKEUP,
	SCHED_WAKING,
	SOFTIRQ,
	TRACE_STARTED,
	TRACE_STOPPED,
	EVENT_MAX,
};

struct sched_switch_event {
	u32		cpu;
	bool		preempt;
	char		next_comm[MAX_COMM];
	u64		next_dsq_id;
	u64		next_dsq_lat_us;
	u32		next_dsq_nr;
	u64		next_dsq_vtime;
	u64		next_slice_ns;
	u32		next_pid;
	u32		next_tgid;
	int		next_prio;
	char		prev_comm[MAX_COMM];
	u64		prev_dsq_id;
	u64		prev_used_slice_ns;
	u64		prev_slice_ns;
	u32		prev_pid;
	u32		prev_tgid;
	u64		prev_state;
	int		prev_prio;
};

struct wakeup_event {
	u32		pid;
	u32		tgid;
	int		prio;
	char		comm[MAX_COMM];
};

struct set_perf_event {
	u32		perf;
};

struct softirq_event {
	u64		entry_ts;
	u64		exit_ts;
	u32		pid;
	int		softirq_nr;
};

struct exit_event {
	u32		pid;
	u32		prio;
	u32		tgid;
	char		comm[MAX_COMM];
};

struct fork_event {
	u32		parent_pid;
	u32		child_pid;
	char		parent_comm[MAX_COMM];
	char		child_comm[MAX_COMM];
};

struct exec_event {
	u32             old_pid;
	u32             pid;
};

struct ipi_event {
	u32		pid;
	u32		target_cpu;
};

struct gpu_mem_event {
	u64             size;
	u32             gpu;
	u32             pid;
};

struct cpuhp_enter_event {
	u32             cpu;
	u32             pid;
	int             target;
	int             state;
};

struct cpuhp_exit_event {
	u32             cpu;
	u32             pid;
	int             state;
	int             idx;
	int             ret;
};

struct hw_pressure_event {
	u64             hw_pressure;
	u32             cpu;
};

struct trace_started_event {
	bool		start_immediately;
	bool		stop_scheduled;
};

struct pstate_sample_event {
	u32             busy;
};

struct bpf_event {
	int		type;
	u64		ts;
	u32		cpu;
	union {
		struct  exit_event exit;
		struct  fork_event fork;
		struct  exec_event exec;
		struct  hw_pressure_event hwp;
		struct  gpu_mem_event gm;
		struct  cpuhp_enter_event chp;
		struct  cpuhp_exit_event cxp;
		struct	ipi_event ipi;
		struct  pstate_sample_event pstate;
		struct	sched_switch_event sched_switch;
		struct	set_perf_event perf;
		struct	softirq_event softirq;
		struct	wakeup_event wakeup;
		struct	wakeup_event waking;
		struct  trace_started_event trace;
	} event;
};

struct task_ctx {
	u64		wakeup_ts;
	u64		dsq_id;
	u64		dsq_insert_time;
	u64		dsq_vtime;
	u64		slice_ns;
	u64		last_run_ns;
};

struct schedule_stop_trace_args {
	u64		stop_timestamp;
};

#endif /* __INTF_H */
