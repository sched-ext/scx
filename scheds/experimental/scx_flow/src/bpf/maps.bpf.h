// SPDX-License-Identifier: GPL-2.0
/*
 * Tables for the flow scheduler.
 *
 * Task storage holds one entry per task. CPU storage holds the seed
 * view written at startup with the cluster index only. Cache and node
 * placement come from the upstream topology tree. LLC storage holds
 * per LLC counters. Globals hold the running view, the per LLC floor,
 * the per CPU tree roots in arena memory, the forward coalescing
 * state, and two switches for cluster choice plus thread shape. Each
 * CPU owns one tree in deadline order with depth bound at RB_MAX_DEPTH.
 * Leftmost wins with ties right in RB_DUPLICATE-compatible order. Trees
 * hold without bound on live task count. A null root means the CPU is
 * offline or its tree was never built. Offline roots still reap through
 * the same drain. Thread shape defaults on. A missed seed stays
 * conservative. The CPU plus LLC tables are written once. A CPU that
 * arrives late needs a restart to be seen. Liveness comes from the
 * topology tree. No separate live table is kept. The arena task map
 * from the task allocator is infra and not counted in the three maps
 * here. Proxies stay BSS only with no map and no wire bytes. The wire
 * keeps one hundred four bytes. Fallback is best effort. Each fallback
 * cause has its own BSS counter. The wire fallback counter sums them.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_MAPS_BPF_H
#define __FLOW_MAPS_BPF_H
#include "intf.h"
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
struct flow_rb_root __arena *flow_rb_roots;
u64 flow_fwd_pid[FLOW_MAX_LLCS + 1];
s64 flow_fwd_vtime[FLOW_MAX_LLCS + 1];
s32 flow_fwd_owner[FLOW_MAX_LLCS + 1];
/* BSS counters with no wire bytes. Each stays in BSS with no map and
 * no userspace reader. The wire keeps one hundred four bytes. Lag clamp
 * counts kick path clamps at LAG_MAX. Depth holds the last insert depth.
 * Depth max holds the largest insert depth seen. Duplicate counts equal
 * key inserts chained right. Leftmost hit counts leftmost pops. E strip
 * probe counts fallback probes with a head present after the distant
 * pass. Fallback cause counters split no CPU plus pinned plus contention
 * plus alloc miss plus depth overflow. The fair header adds fold plus
 * saturate plus freeze counters with the same pattern and no wire bytes.
 * All stay integer only with mask
 * live checks only. Read them with a BSS dump. The wire fallback counter
 * sums all causes. */
u64 m_lag_clamp;
u64 m_rb_depth;
u64 m_rb_depth_max;
u64 m_dup_chain;
u64 m_leftmost_hit;
u64 m_estrip_probe;
u64 m_fb_nocpu;
u64 m_fb_pinned;
u64 m_fb_contention;
u64 m_fb_alloc;
u64 m_fb_depth;
#endif
