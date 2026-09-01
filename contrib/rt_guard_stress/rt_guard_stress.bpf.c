// SPDX-License-Identifier: GPL-2.0
/*
 * rt_guard_stress.bpf.c — minimal scheduler + rt_guard sched_switch interceptor.
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/scx_rt_guard.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

SCX_RT_GUARD_SCHED_SWITCH_PROG(rt_guard_stress_switch)

void BPF_STRUCT_OPS(rt_guard_stress_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops rt_guard_stress_ops = {
	.exit			= (void *)rt_guard_stress_exit,
	.name			= "rt_guard_stress",
};
