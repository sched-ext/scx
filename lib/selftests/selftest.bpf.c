/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>

#include <lib/rbtree.h>

#include "selftest.h"

SEC("syscall")
int arena_selftest(void)
{
	int ret;

	ret = scx_selftest_arena_topology_timer();
	if (ret) {
		bpf_printk("scx_selftest_topology failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_atq();
	if (ret) {
		bpf_printk("scx_selftest_atq failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_dhq();
	if (ret) {
		bpf_printk("scx_selftest_dhq failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_btree();
	if (ret) {
		bpf_printk("scx_selftest_btree failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_lvqueue();
	if (ret) {
		bpf_printk("scx_selftest_lvqueue failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_minheap();
	if (ret) {
		bpf_printk("scx_selftest_minheap failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_rbtree();
	if (ret) {
		bpf_printk("scx_selftest_rbtree failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_topology();
	if (ret) {
		bpf_printk("scx_selftest_topology failed with %d", ret);
		return ret;
	}

	bpf_printk("Selftests successful.");

	return 0;
}

char _license[] SEC("license") = "GPL";
