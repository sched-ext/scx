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
 *   enqueue.bpf.c    — enqueue routing (pinned -> vtime)
 *   dispatch.bpf.c   — DSQ hierarchy dispatch
 *   budget.bpf.c     — budget lifecycle (runnable, running, stopping)
 *   task.bpf.c       — task lifecycle (init, enable, exit, yield, cpu_release)
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

volatile u64 nr_running;
volatile u64 total_runtime;
volatile u64 pinned_dispatches;
volatile u64 prio_dispatches;
volatile u64 tier_priority_dispatches;
volatile u64 tier_normal_dispatches;
volatile u64 tier_low_dispatches;
volatile u64 tier_deficit_dispatches;
volatile u64 budget_refill_events;
volatile u64 budget_exhaustions;
volatile u64 runnable_wakeups;
volatile u64 cpu_release_reenqueues;
volatile u64 init_task_events;
volatile u64 enable_events;
volatile u64 exit_task_events;
volatile u64 cpu_migrations;
volatile u64 tune_reserved_max_ns = FLOW_SLICE_RESERVED_MAX_NS;
volatile u64 tune_interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_NS;

static u64 nr_cpu_ids;

#include "helpers.bpf.c"
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "budget.bpf.c"
#include "task.bpf.c"

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;
	s32 cpu;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	bpf_for(cpu, 0, nr_cpu_ids) {
		ret = scx_bpf_create_dsq(FLOW_PINNED_DSQ_BASE + (u32)cpu, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("failed to create pinned DSQ for CPU %d: %d",
				      cpu, ret);
			return ret;
		}
	}

	ret = scx_bpf_create_dsq(FLOW_TIER_PRIORITY_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) return ret;
	ret = scx_bpf_create_dsq(FLOW_TIER_NORMAL_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) return ret;
	ret = scx_bpf_create_dsq(FLOW_TIER_LOW_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) return ret;
	ret = scx_bpf_create_dsq(FLOW_TIER_DEFICIT_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) return ret;

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
