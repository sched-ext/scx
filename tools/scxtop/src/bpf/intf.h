// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
typedef unsigned char	   u8;
typedef unsigned int	   u32;
typedef unsigned long long u64;
typedef long long	   s64;
struct scx_event_stats;
#endif
#include <stdbool.h>

enum consts {
	MAX_COMM = 16,
	/*
   * LAYER_ID_INDEX is the current index of layer_id in the layered task_ctx
   * struct
   * (https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_layered/src/bpf/main.bpf.c#L577).
   * Whenever a new field is added above layer_id, LAYER_ID_INDEX must be
   * incremented.
   */
	LAYER_ID_INDEX = 2,

	/* Stack trace configuration */
	MAX_STACK_DEPTH = 127, /* Maximum number of stack frames to capture */
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
	WAIT,
	GPU_MEM,
	HW_PRESSURE,
	IPI,
	KPROBE,
	PERF_SAMPLE,
	SCHED_HANG,
	SCHED_MIGRATE,
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
	u32  cpu;
	bool preempt;
	u8   next_comm[MAX_COMM];
	u64  next_dsq_id;
	u64  next_dsq_lat_us;
	u32  next_dsq_nr;
	u64  next_dsq_vtime;
	u64  next_slice_ns;
	u32  next_pid;
	u32  next_tgid;
	int  next_prio;
	int  next_layer_id;
	u8   prev_comm[MAX_COMM];
	u64  prev_dsq_id;
	u64  prev_used_slice_ns;
	u64  prev_slice_ns;
	u32  prev_pid;
	u32  prev_tgid;
	u64  prev_state;
	int  prev_prio;
	int  prev_layer_id;
};

struct wakeup_event {
	u32 pid;
	u32 tgid;
	int prio;
	u32 waker_pid;
	u8  comm[MAX_COMM];
	u8  waker_comm[MAX_COMM];
};

struct migrate_event {
	u32 pid;
	int prio;
	u32 dest_cpu;
	u8  comm[MAX_COMM];
};

struct set_perf_event {
	u32 perf;
};

struct softirq_event {
	u64 entry_ts;
	u64 exit_ts;
	u32 pid;
	int softirq_nr;
};

struct exit_event {
	u32 pid;
	u32 prio;
	u32 tgid;
	u8  comm[MAX_COMM];
};

struct fork_event {
	u32 parent_pid;
	u32 parent_tgid;
	u32 child_pid;
	u32 child_tgid;
	int parent_layer_id;
	int child_layer_id;
	u8  parent_comm[MAX_COMM];
	u8  child_comm[MAX_COMM];
};

struct exec_event {
	u32 old_pid;
	u32 pid;
	int layer_id;
};

struct wait_event {
	u32 pid;
	int prio;
	u8  comm[MAX_COMM];
};

struct hang_event {
	u32 pid;
	u8  comm[MAX_COMM];
};

struct ipi_event {
	u32 pid;
	u32 target_cpu;
};

struct gpu_mem_event {
	u64 size;
	u32 gpu;
	u32 pid;
};

struct cpuhp_enter_event {
	u32 cpu;
	u32 pid;
	int target;
	int state;
};

struct cpuhp_exit_event {
	u32 cpu;
	u32 pid;
	int state;
	int idx;
	int ret;
};

struct hw_pressure_event {
	u64 hw_pressure;
	u32 cpu;
};

struct trace_started_event {
	bool start_immediately;
	bool stop_scheduled;
};

struct kprobe_event {
	u32 pid;
	u64 instruction_pointer;
};

struct perf_sample_event {
	u32  pid;
	u64  instruction_pointer;
	u32  cpu_id;
	int  layer_id;
	bool is_kernel;
	u32  kernel_stack_size;
	u32  user_stack_size;
	u64  kernel_stack[MAX_STACK_DEPTH];
	u64  user_stack[MAX_STACK_DEPTH];
};

struct bpf_event {
	int type;
	u64 ts;
	u32 cpu;
	union {
		struct exit_event	   exit;
		struct fork_event	   fork;
		struct exec_event	   exec;
		struct wait_event	   wait;
		struct hw_pressure_event   hwp;
		struct gpu_mem_event	   gm;
		struct cpuhp_enter_event   chp;
		struct cpuhp_exit_event	   cxp;
		struct ipi_event	   ipi;
		struct sched_switch_event  sched_switch;
		struct set_perf_event	   perf;
		struct softirq_event	   softirq;
		struct wakeup_event	   wakeup;
		struct wakeup_event	   waking;
		struct migrate_event	   migrate;
		struct hang_event	   hang;
		struct trace_started_event trace;
		struct kprobe_event	   kprobe;
		struct perf_sample_event   perf_sample;
	} event;
};

struct task_ctx {
	u64 wakeup_ts;
	u64 dsq_id;
	u64 dsq_insert_time;
	u64 dsq_vtime;
	u64 slice_ns;
	u64 last_run_ns;
	u32 last_waker_pid;
	u8  last_waker_comm[MAX_COMM];
	bool is_sampled; // True if this thread is currently being sampled for this wakeup->run cycle
};

struct schedule_stop_trace_args {
	u64 stop_timestamp;
};

// Simplified sched_ext stats
struct scxtop_sched_ext_stats {
	s64 select_cpu_fallback;
	s64 dispatch_local_dsq_offline;
	s64 dispatch_keep_last;
	s64 enq_skip_exiting;
	s64 enq_skip_migration_disabled;
	s64 timestamp_ns; // When these stats were collected
};

// Syscall args for collecting sched_ext stats
struct collect_scx_stats_args {
	struct scxtop_sched_ext_stats stats;
};

struct layered_task_ctx {
	u32 data_a;
	u32 data_b;
	u32 layer_id;
};

#endif /* __INTF_H */
