/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#include <lib/cpumask.h>

#include "intf.h"
#include "types.h"
#include "lb_domain.h"

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile u32 dom_numa_id_map[MAX_DOMS];
const volatile u32 debug;
const volatile u32 load_half_life = 1000000000	/* 1s */;
const volatile u32 nr_doms = 32;	/* !0 for veristat, set during init */
const volatile u32 nr_nodes = 32;	/* !0 for veristat, set during init */

/* base slice duration */
volatile u64 slice_ns;

/*
 * Statistics
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, RUSTY_NR_STATS);
} stats SEC(".maps");

__weak
int stat_add(enum stat_idx idx, u64 addend)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += addend;

	return 0;
}


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
