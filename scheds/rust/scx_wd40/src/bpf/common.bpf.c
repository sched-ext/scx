/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include <lib/sdt_task.h>

#include "intf.h"
#include "types.h"
#include "lb_domain.h"

#include <scx/bpf_arena_common.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile u32 dom_numa_id_map[MAX_DOMS];
const volatile u32 debug;
const volatile u32 load_half_life = 1000000000	/* 1s */;

__hidden
u32 dom_node_id(u32 dom_id)
{
	const volatile u32 *nid_ptr;

	nid_ptr = MEMBER_VPTR(dom_numa_id_map, [dom_id]);
	if (!nid_ptr) {
		scx_bpf_error("Couldn't look up node ID for %d", dom_id);
		return 0;
	}
	return *nid_ptr;
}

__hidden
struct task_ctx *try_lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx __arena *taskc = sdt_task_data(p);
	return (struct task_ctx *)taskc;
}

__hidden
struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *taskc;

	taskc = try_lookup_task_ctx(p);
	if (!taskc)
		scx_bpf_error("task_ctx lookup failed for task %p", p);

	return taskc;
}

__weak
s32 create_save_cpumask(struct bpf_cpumask **kptr)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("Failed to create cpumask");
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(kptr, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	return 0;
}
