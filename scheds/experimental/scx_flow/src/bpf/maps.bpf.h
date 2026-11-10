// SPDX-License-Identifier: GPL-2.0
/*
 * Tables for the flow scheduler.
 *
 * Task storage holds one entry per task. CPU storage holds the seed
 * view written at startup with the cluster index only; cache and node
 * placement come from the upstream topology tree. LLC storage holds
 * per LLC counters. Globals hold the running view,
 * the per LLC floor, the per CPU queues as one embedded queue per CPU
 * in arena memory, the forward coalescing state, and two
 * switches for cluster choice plus thread shape. Each CPU owns one
 * queue in deadline order bounded at 64 total. A null queue means the CPU
 * is offline or its queue was never built. Thread shape defaults on so a
 * missed seed stays conservative. The CPU plus LLC tables are written once, so a
 * CPU that arrives late needs a restart to be seen. Liveness comes
 * from the topology tree, so no separate live table is kept. The
 * arena task map from the task allocator is infra and not counted
 * in the three maps here.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_MAPS_BPF_H
#define __FLOW_MAPS_BPF_H
#include "intf.h"
#include <lib/edq.h>
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_ctx);
} cpu_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_LLCS);
	__type(key, u32);
	__type(value, struct flow_llc_stats);
} llc_stats_stor SEC(".maps");
volatile u64 flow_ccx_prefer;
volatile u64 flow_smt_enabled = 1;
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
s64 flow_llc_seq[FLOW_MAX_LLCS];
struct scx_edq __arena *flow_edqs;
u64 flow_fwd_pid[FLOW_MAX_LLCS + 1];
s64 flow_fwd_vtime[FLOW_MAX_LLCS + 1];
s32 flow_fwd_owner[FLOW_MAX_LLCS + 1];
#endif
