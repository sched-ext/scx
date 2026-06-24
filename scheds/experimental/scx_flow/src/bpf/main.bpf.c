/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * scx_flow BPF scheduler — entry point.
 *
 * This file defines the BPF maps, volatiles, and ops dispatch table.
 * The scheduling logic is organized into separate modules included below:
 *   helpers.bpf.c    — utility functions and macros
 *   select_cpu.bpf.c — CPU selection
 *   enqueue.bpf.c    — enqueue routing (wakeup fast path / Waiting Room)
 *   dispatch.bpf.c   — DSQ dispatch (pinned DSQ, FLOW_BATCH_DSQ)
 *   budget.bpf.c     — budget lifecycle (runnable, running, stopping)
 *   task.bpf.c       — task lifecycle (init, enable, exit, yield, cpu_release)
 *   carriage.bpf.c   — Waiting Room stats window and slice computation
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct task_ctx {
	s64 budget_ns;
	s64 last_refill_ns;
	u64 last_run_at;
	u64 last_sleep_ns;
	u64 sleep_started_at;
	s32 last_cpu;
	s32 last_llc;		/* for migration cost calculation */
	s32 runnable_cpu;	/* CPU where flow_runnable incremented per_cpu_runnable */
	s32 wake_cpu;
	bool wake_cpu_idle;
	bool wake_cpu_valid;
	bool first_run;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state SEC(".maps");

/* Per-core topology — populated at init by Rust userspace. */
volatile u64 per_cpu_max_freq_khz[1024];
volatile u64 per_cpu_llc_id[1024];
volatile u64 per_cpu_is_smt[1024];	/* 1 = SMT secondary (for web UI) */
volatile u64 per_cpu_sibling_count[1024]; /* threads per core (for bandwidth) */
volatile u64 per_cpu_runnable[1024];	/* current runnable count per CPU */
volatile u64 system_total_khz;		/* sum of all core_effective_khz */
volatile u64 nr_cpu_ids;

/* Scheduler PID — set by userspace before attach.
 * Tasks matching this PID bypass the carriage pool. */
volatile u64 flow_scheduler_pid;

/* Carriage pool — stats window buffer.
 * Records recently-dispatched task PIDs for the web UI.
 * All slots pre-allocated in BSS. */
struct flow_carriage carriage_pool[FLOW_NR_CARRIAGES];
volatile u64 carriage_producer;



/* System-level counters */
volatile u64 on_cpu;
volatile u64 total_runtime;
volatile u64 pinned_dispatches;
volatile u64 prio_dispatches;	/* wakeup fast path dispatches */
volatile u64 budget_exhaustions;
volatile u64 runnable_wakeups;
volatile u64 cpu_release_reenqueues;
volatile u64 init_task_events;
volatile u64 enable_events;
volatile u64 exit_task_events;
volatile u64 cpu_migrations;

/* Tunable bounds (compile-time defaults, no-knobs) */
volatile u64 tune_reserved_max_ns = FLOW_SLICE_RESERVED_MAX_NS;
volatile u64 tune_interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_NS;

#include "helpers.bpf.c"
#include "select_cpu.bpf.c"
#include "carriage.bpf.c"	/* must precede enqueue/dispatch for function visibility */
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "budget.bpf.c"
#include "task.bpf.c"

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;
	s32 cpu;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	if (nr_cpu_ids > 1024) {
		scx_bpf_error("nr_cpu_ids (%llu) exceeds max supported (1024)",
			      nr_cpu_ids);
		return -E2BIG;
	}

	/* Create shared vtime-ordered DSQ for non-wakeup traffic. */
	ret = scx_bpf_create_dsq(FLOW_BATCH_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create batch DSQ: %d", ret);
		return ret;
	}

	/* Create per-CPU vtime DSQs and per-CPU pinned DSQs. */
	bpf_for(cpu, 0, nr_cpu_ids) {
		ret = scx_bpf_create_dsq(FLOW_VTIME_DSQ_BASE + (u32)cpu, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("failed to create vtime DSQ for CPU %d: %d",
				      cpu, ret);
			return ret;
		}
		ret = scx_bpf_create_dsq(FLOW_PINNED_DSQ_BASE + (u32)cpu, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("failed to create pinned DSQ for CPU %d: %d",
				      cpu, ret);
			return ret;
		}
	}

	carriage_producer = 0;

	return 0;
}

void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}

SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dispatch		= (void *)flow_dispatch,
	       .cpu_release		= (void *)flow_cpu_release,
	       .runnable		= (void *)flow_runnable,
	       .enable			= (void *)flow_enable,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .init_task		= (void *)flow_init_task,
	       .exit_task		= (void *)flow_exit_task,
	       .init			= (void *)flow_init,
	       .yield			= (void *)flow_yield,
	       .exit			= (void *)flow_exit,
	       .timeout_ms		= 5000,
	       .name			= "scx_flow");
