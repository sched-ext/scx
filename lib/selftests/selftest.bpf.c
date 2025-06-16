/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>

#include "selftest.h"

SEC("syscall")
int arena_selftest(void)
{
	int ret;

	ret = scx_selftest_bitmap();
	if (ret)
		return ret;

	return 0;
}
