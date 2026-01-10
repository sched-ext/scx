/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#include <alloc/common.h>

#include <alloc/asan.h>

#include "selftest.h"

SEC("syscall")
int alloc_selftest(void)
{
	int ret;

	ret = bump_selftest();
	if (ret) {
		bpf_printk("bump_selftest failed with %d", ret);
		return ret;
	}

	ret = buddy_selftest();
	if (ret) {
		bpf_printk("buddy_selftest failed with %d", ret);
		return ret;
	}

	bpf_printk("Alloc selftests successful.");

	return 0;
}

char _license[] SEC("license") = "GPL";
