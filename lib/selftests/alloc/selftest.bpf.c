/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>

#include <alloc/asan.h>

#include "selftest.h"

SEC("syscall")
int alloc_selftest(void)
{
	int ret;

	ret = scx_selftest_static();
	if (ret) {
		bpf_printk("scx_selftest_static failed with %d", ret);
		return ret;
	}

	ret = scx_selftest_buddy();
	if (ret) {
		bpf_printk("scx_selftest_buddy failed with %d", ret);
		return ret;
	}

	bpf_printk("Alloc selftests successful.");

	return 0;
}

char _license[] SEC("license") = "GPL";
