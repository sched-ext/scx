/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A variation on scx_simple with CPU selection that prioritizes an idle
 * previous CPU over finding a fully idle core (as is done in scx_simple and
 * scx_rusty).
 *
 * Outperforms the in-kernel fair class (v6.12), scx_simple, and scx_rusty on
 * OLTP workloads run on systems with simple topology (i.e. non-NUMA, single
 * LLC).
 *
 * Copyright (c) 2025, Oracle and/or its affiliates.
 * Copyright (c) 2025, Daniel Jordan <daniel.m.jordan@oracle.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 4);			/* [local, select_fail, prev_cpu, idle_cpu] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(prev_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_inc(2);	/* prev_cpu */
		cpu = prev_cpu;
		goto insert;
	}

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0) {
		stat_inc(3);	/* idle_cpu */
		goto insert;
	}

	stat_inc(1);		/* select_fail */

	return prev_cpu;

insert:
	stat_inc(0);		/* local */
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

void BPF_STRUCT_OPS(prev_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(prev_ops,
	.select_cpu		= (void *)prev_select_cpu,
	.exit			= (void *)prev_exit,
	.name			= "prev"
);
