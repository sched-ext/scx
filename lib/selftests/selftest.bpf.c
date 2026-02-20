/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>

#include <lib/rbtree.h>

#include "selftest.h"

/*
 * Test selector for arena_selftest. SCX_SELFTEST_ID_ALL (0) runs all tests;
 * any other value from enum scx_selftest_id runs only the matching test.
 * Set from userspace via the bss map before invoking arena_selftest.
 */
u32 selftest_run_id;

#define SELFTEST_RUN(id, fn, name)					\
	if (!selftest_run_id || selftest_run_id == (id)) {		\
		ret = fn();						\
		if (ret) {						\
			bpf_printk(name " failed with %d", ret);	\
			return ret;					\
		}							\
	}

SEC("syscall")
int arena_selftest(void)
{
	int ret;

	SELFTEST_RUN(SCX_SELFTEST_ID_ARENA_TOPOLOGY_TIMER,
		     scx_selftest_arena_topology_timer,
		     "scx_selftest_arena_topology_timer");
	SELFTEST_RUN(SCX_SELFTEST_ID_ATQ,
		     scx_selftest_atq,
		     "scx_selftest_atq");
	SELFTEST_RUN(SCX_SELFTEST_ID_DHQ,
		     scx_selftest_dhq,
		     "scx_selftest_dhq");
	SELFTEST_RUN(SCX_SELFTEST_ID_BTREE,
		     scx_selftest_btree,
		     "scx_selftest_btree");
	SELFTEST_RUN(SCX_SELFTEST_ID_LVQUEUE,
		     scx_selftest_lvqueue,
		     "scx_selftest_lvqueue");
	SELFTEST_RUN(SCX_SELFTEST_ID_MINHEAP,
		     scx_selftest_minheap,
		     "scx_selftest_minheap");
	SELFTEST_RUN(SCX_SELFTEST_ID_RBTREE,
		     scx_selftest_rbtree,
		     "scx_selftest_rbtree");
	SELFTEST_RUN(SCX_SELFTEST_ID_TOPOLOGY,
		     scx_selftest_topology,
		     "scx_selftest_topology");
	SELFTEST_RUN(SCX_SELFTEST_ID_BITMAP,
		     scx_selftest_bitmap,
		     "scx_selftest_bitmap");

	bpf_printk("Selftests successful.");

	return 0;
}

char _license[] SEC("license") = "GPL";
