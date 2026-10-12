// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core at 4.8.11.
 *
 * Maps hold task state, CPU pid plus cursor plus minimum rows, the
 * topology view, the capacity view, the flat hint rows, the per CPU
 * stats rows, and the perf level rows. Init creates one local queue
 * per CPU plus one shared queue per node plus one machine queue plus
 * one value ordered reject queue, and it fails loudly on over bound counts. Ops
 * split across per logic files with maps plus init plus exit plus the
 * ops table only here. Hotplug needs a restart, and the watchdog stays
 * at 20 seconds.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
#include "topology.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
/* Per task state for the life of the task. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
/* Per CPU pid with placement cursor plus minimum. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");
/* Per CPU topology view with sibling plus node. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_topo);
} topo_stor SEC(".maps");
/* Per CPU capacity view with one units row. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_cap);
} cap_stor SEC(".maps");
/* Flat period hint by id with miss default. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOW_HINT_MAX);
	__type(key, u64);
	__type(value, struct flow_hint);
} hint_stor SEC(".maps");
/* Task to hierarchy cache with pid key plus id value. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, u32);
	__type(value, u64);
} cgrp_cache_stor SEC(".maps");
/* Per CPU stats rows with no shared read modify write. Each CPU owns */
/* one row keyed by its id, so updates touch only the local row. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_sched_stats);
} cpu_stats_stor SEC(".maps");
/* Last perf level per CPU with no call on steady. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cpu_perf_last SEC(".maps");
/* Global reclaim credit from completer saved deltas with no knob. */
/* One u64 row holds the unused cost funding for dispatch reclaim with */
/* saturation at 1s, so completions fund retries with no task pointer. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} reclaim_credit_stor SEC(".maps");
volatile u64 nr_cpu_ids;
volatile u64 nr_node_ids;
#include "stats.bpf.c"
#include "cgroup.bpf.c"
#include "vtime.bpf.c"
#include "weight.bpf.c"
#include "edf.bpf.c"
#include "task_placement.bpf.c"
#include "timer.bpf.c"
#include "preempt.bpf.c"
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "lifecycle.bpf.c"
/**
 * flow_init - create queues plus seed CPU state.
 *
 * Creates one local queue per CPU plus one node queue per node plus
 * one machine queue plus one value ordered reject queue. Seeds per CPU state plus
 * capacity rows, then derives the node count from the seeded view.
 * Fails loudly on over bound counts with no partial attach.
 *
 * Returns: 0 on success, negative errno on failure.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;
	u64 n;
	s32 cpu;
	u64 want = 1;
	n = scx_bpf_nr_cpu_ids();
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	nr_cpu_ids = n;
	{
		s32 c;
		u32 hi = 0;
		bool seen = false;
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			u32 key;
			struct flow_topo *tp;
			u32 nd;
			if (c < 0)
				continue;
			if ((u64)c >= n)
				break;
			key = (u32)c;
			tp = bpf_map_lookup_elem(&topo_stor,
			    &key);
			if (!tp)
				continue;
			nd = READ_ONCE(tp->node);
			if (!flow_topo_node_ok(nd))
				continue;
			if (!seen || nd > hi) {
				hi = nd;
				seen = true;
			}
		}
		if (seen)
			want = (u64)hi + 1;
		if (want < 1)
			want = 1;
		if (want > (u64)FLOW_MAX_NODES)
			want = (u64)FLOW_MAX_NODES;
		nr_node_ids = want;
	}
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		struct flow_cpu_state *st;
		struct flow_cpu_cap *cp;
		u32 key;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		key = (u32)cpu;
		st = bpf_map_lookup_elem(&cpu_state_stor, &key);
		if (st) {
			st->running_pid = 0;
			st->cursor = (u32)cpu;
			st->min_vruntime = 0;
		}
		cp = bpf_map_lookup_elem(&cap_stor, &key);
		if (cp)
			cp->units = (u32)FLOW_CAP_BASE;
	}
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u64 local;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		local = flow_local_dsq((u32)cpu);
		if (!flow_dsq_valid(local)) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(local, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	{
		u32 node;
		u64 nn = nr_node_ids;
		if (nn > (u64)FLOW_MAX_NODES)
			nn = (u64)FLOW_MAX_NODES;
		bpf_for(node, 0, FLOW_MAX_NODES) {
			u64 nd;
			if ((u64)node >= nn)
				break;
			nd = flow_node_dsq(node);
			if (!flow_dsq_valid(nd)) {
				scx_bpf_error("dsq id over bound");
				return -EINVAL;
			}
			ret = scx_bpf_create_dsq(nd, -1);
			if (ret < 0 && ret != -EEXIST) {
				scx_bpf_error("dsq create failed");
				return ret;
			}
		}
	}
	if (!flow_dsq_valid(flow_machine_dsq())) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq(flow_machine_dsq(), -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	if (!flow_dsq_valid(flow_overflow_dsq())) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq(flow_overflow_dsq(), -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	return 0;
}
/**
 * flow_exit - record exit info on teardown.
 * @info: exit info from the kernel.
 *
 * Records the exit reason with no extra work.
 */
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .enable			= (void *)flow_enable,
	       .disable			= (void *)flow_disable,
	       .exit_task		= (void *)flow_exit_task,
	       .cpu_release		= (void *)flow_cpu_release,
	       .cgroup_init		= (void *)flow_cgroup_init,
	       .cgroup_exit		= (void *)flow_cgroup_exit,
	       .cgroup_prep_move	= (void *)flow_cgroup_prep_move,
	       .cgroup_move		= (void *)flow_cgroup_move,
	       .cgroup_cancel_move	= (void *)flow_cgroup_cancel_move,
	       .cgroup_set_weight	= (void *)flow_cgroup_set_weight,
	       .set_weight		= (void *)flow_set_weight,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
