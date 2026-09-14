/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Daniel Hodges <hodgesd@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/arena.h>
#include <lib/percpu.h>
#include <lib/cpumask.h>
#include <lib/topology.h>

#include "selftest.h"

#define SCX_TOPOLOGY_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_topology_ ## suffix)


__weak
int scx_selftest_topology_contains(void)
{
	int cpu, ret;

	cpu = bpf_get_smp_processor_id();
	ret = topo_contains(topo_all, (u32)cpu);
	if (!ret) {
		bpf_printk("TOPO: failed to get cpu %d", cpu);
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_topology_print(void)
{
	topo_print();

	return 0;
}


__weak
int scx_selftest_topology(void)
{
	// Assume topology has been initialized before the test
	if (!topo_all) {
		bpf_printk("TOPO: failed to initialize topology");
		return -EINVAL;
	}

	SCX_TOPOLOGY_SELFTEST(contains);
	SCX_TOPOLOGY_SELFTEST(print);

	return 0;
}
