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

#define SCX_TOPOLOGY_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_arena_topology_timer_ ## suffix)

struct test_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct test_timer);
} topology_timer_map SEC(".maps");

volatile bool timer_callback_executed = false;
volatile bool topology_accessed_in_timer = false;

struct topology_data {
	u64 magic_value;
	u32 access_count;
	u32 cpu_id;
};

static struct topology_data __arena * topo_get_data(topo_ptr topo)
{
	if (!topo || !topo->data)
		return NULL;

	return (struct topology_data __arena *)topo->data;
}

static int topo_update_data(topo_ptr topo, u64 magic, u32 cpu)
{
	struct topology_data __arena *data = topo_get_data(topo);

	if (!data)
		return -EINVAL;

	data->magic_value = magic;
	data->access_count++;
	data->cpu_id = cpu;

	return 0;
}

static bool topo_verify_data(topo_ptr topo, u64 expected_magic)
{
	struct topology_data __arena *data = topo_get_data(topo);

	if (!data)
		return false;

	return data->magic_value == expected_magic && data->access_count > 0;
}

volatile bool timer_with_helpers_executed = false;
volatile u64 timer_arena_data_magic = 0;
volatile u32 timer_arena_data_count = 0;

static int topology_timer_callback(void *map, int *key, struct bpf_timer *timer)
{
	topo_ptr topo;
	int i;

	timer_callback_executed = true;

	if (!topo_all) {
		bpf_printk("TOPO TIMER: topo_all is NULL");
		return 0;
	}

	if (topo_all->mask && topo_all->nr_children > 0) {
		topology_accessed_in_timer = true;

		for (i = 0; i < topo_all->nr_children && i < TOPO_MAX_CHILDREN && can_loop; i++) {
			topo = topo_all->children[i];
			/* make sure we can deference arena pointers */
			if (topo && topo->mask) {
				break;
			}
		}
	}

	bpf_printk("TOPO TIMER: accessed topology, children=%d",
		   topo_all->nr_children);

	return 0;
}

static int topology_timer_callback_with_helpers(void *map, int *key,
						struct bpf_timer *timer)
{
	struct topology_data __arena *data;
	topo_ptr child;
	struct topo_iter iter;
	u64 expected_magic = 0xCAFEBABE00000000ULL;
	int ret, i;

	timer_with_helpers_executed = true;

	if (!topo_all) {
		bpf_printk("TOPO TIMER HELPERS: topo_all is NULL");
		return 0;
	}

	data = topo_get_data(topo_all);
	if (!data) {
		bpf_printk("TOPO TIMER HELPERS: failed to get data via helper");
		return 0;
	}

	timer_arena_data_magic = data->magic_value;
	timer_arena_data_count = data->access_count;

	ret = topo_update_data(topo_all, expected_magic + 100, bpf_get_smp_processor_id());
	if (ret) {
		bpf_printk("TOPO TIMER HELPERS: failed to update data: %d", ret);
		return 0;
	}

	if (!topo_verify_data(topo_all, expected_magic + 100)) {
		bpf_printk("TOPO TIMER HELPERS: data verification failed");
		return 0;
	}

	i = 0;
	TOPO_FOR_EACH_CPU(&iter, child) {
		if (i >= 2)  /* Limit iteration */
			break;

		data = topo_get_data(child);
		if (data) {
			bpf_printk("TOPO TIMER HELPERS: child %d magic=0x%llx count=%d",
				   i, data->magic_value, data->access_count);
		}
		i++;
	}

	bpf_printk("TOPO TIMER HELPERS: test passed, accessed %d children", i);

	return 0;
}

__weak
int scx_selftest_arena_topology_timer_timer_access(void)
{
	struct test_timer *timer_elem;
	u32 timer_key = 0;
	int ret;

	timer_callback_executed = false;
	topology_accessed_in_timer = false;

	if (!topo_all) {
		bpf_printk("TOPO TIMER: topology not initialized");
		return -EINVAL;
	}

	timer_elem = bpf_map_lookup_elem(&topology_timer_map, &timer_key);
	if (!timer_elem) {
		bpf_printk("TOPO TIMER: failed to lookup timer");
		return -EINVAL;
	}

	ret = bpf_timer_init(&timer_elem->timer, &topology_timer_map, CLOCK_MONOTONIC);
	if (ret) {
		bpf_printk("TOPO TIMER: bpf_timer_init failed: %d", ret);
		return ret;
	}

	ret = bpf_timer_set_callback(&timer_elem->timer, topology_timer_callback);
	if (ret) {
		bpf_printk("TOPO TIMER: bpf_timer_set_callback failed: %d", ret);
		return ret;
	}

	ret = bpf_timer_start(&timer_elem->timer, 0, 0);
	if (ret) {
		bpf_printk("TOPO TIMER: bpf_timer_start failed: %d", ret);
		return ret;
	}

	/*
	 * Give the timer a chance to fire. BPF timers run asynchronously in
	 * softirq context, so we need to yield/wait for it to execute.
	 * Use a simple busy-wait loop to allow the callback to run.
	 */
	bpf_for(ret, 0, 1000000) {
		if (timer_callback_executed)
			break;
	}

	/*
	 * Verify that:
	 * 1. The callback was executed
	 * 2. Arena topology was successfully accessed from the callback
	 */
	if (!timer_callback_executed) {
		bpf_printk("TOPO TIMER: callback not executed after waiting");
		return -EINVAL;
	}

	if (!topology_accessed_in_timer) {
		bpf_printk("TOPO TIMER: failed to access topology in callback");
		return -EINVAL;
	}

	ret = bpf_timer_cancel(&timer_elem->timer);
	if (ret && ret != -EDEADLK) {
		bpf_printk("TOPO TIMER: bpf_timer_cancel failed: %d", ret);
	}

	bpf_printk("TOPO TIMER: test passed");
	return 0;
}

__weak
int scx_selftest_arena_topology_timer_timer_with_helpers(void)
{
	struct topology_data __arena *data;
	struct test_timer *timer_elem;
	struct topo_iter iter;
	topo_ptr child;
	u32 timer_key = 0;
	int ret, i;
	u64 magic = 0xCAFEBABE00000000ULL;

	timer_with_helpers_executed = false;
	timer_arena_data_magic = 0;
	timer_arena_data_count = 0;

	if (!topo_all) {
		bpf_printk("TOPO TIMER HELPERS: topology not initialized");
		return -EINVAL;
	}

	data = (struct topology_data __arena *)scx_static_alloc(sizeof(struct topology_data), 8);
	if (!data) {
		bpf_printk("TOPO TIMER HELPERS: failed to allocate arena data");
		return -ENOMEM;
	}

	data->magic_value = magic;
	data->access_count = 0;
	data->cpu_id = 0;
	topo_all->data = (void __arena *)data;

	i = 0;
	TOPO_FOR_EACH_CPU(&iter, child) {
		struct topology_data __arena *child_data;

		if (i >= 2)
			break;

		child_data = (struct topology_data __arena *)
			scx_static_alloc(sizeof(struct topology_data), 8);
		if (!child_data)
			continue;

		child_data->magic_value = magic + i + 1;
		child_data->access_count = i;
		child_data->cpu_id = child->id;
		child->data = (void __arena *)child_data;
		i++;
	}

	timer_elem = bpf_map_lookup_elem(&topology_timer_map, &timer_key);
	if (!timer_elem) {
		bpf_printk("TOPO TIMER HELPERS: failed to lookup timer");
		return -EINVAL;
	}

	/* Cancel any existing timer first (from previous test) */
	bpf_timer_cancel(&timer_elem->timer);

	ret = bpf_timer_init(&timer_elem->timer, &topology_timer_map, CLOCK_MONOTONIC);
	if (ret) {
		bpf_printk("TOPO TIMER HELPERS: bpf_timer_init failed: %d", ret);
		return ret;
	}

	ret = bpf_timer_set_callback(&timer_elem->timer, topology_timer_callback_with_helpers);
	if (ret) {
		bpf_printk("TOPO TIMER HELPERS: bpf_timer_set_callback failed: %d", ret);
		return ret;
	}

	ret = bpf_timer_start(&timer_elem->timer, 0, 0);
	if (ret) {
		bpf_printk("TOPO TIMER HELPERS: bpf_timer_start failed: %d", ret);
		return ret;
	}

	bpf_for(ret, 0, 1000000) {
		if (timer_with_helpers_executed)
			break;
	}

	if (!timer_with_helpers_executed) {
		bpf_printk("TOPO TIMER HELPERS: callback not executed after waiting");
		return -EINVAL;
	}

	if (timer_arena_data_magic == 0) {
		bpf_printk("TOPO TIMER HELPERS: failed to read arena data in timer");
		return -EINVAL;
	}

	data = topo_get_data(topo_all);
	if (!data || data->magic_value != magic + 100) {
		bpf_printk("TOPO TIMER HELPERS: arena data not updated correctly");
		return -EINVAL;
	}

	if (data->access_count < 1) {
		bpf_printk("TOPO TIMER HELPERS: access count not incremented");
		return -EINVAL;
	}

	bpf_printk("TOPO TIMER HELPERS: test passed - helpers work in timer context");
	return 0;
}

__weak
int scx_selftest_arena_topology_timer_arena_data(void)
{
	struct topology_data __arena *data;
	topo_ptr child;
	struct topo_iter iter;
	int ret, i;
	u64 magic = 0xDEADBEEF12345678ULL;

	if (!topo_all) {
		bpf_printk("TOPO ARENA DATA: topology not initialized");
		return -EINVAL;
	}

	/*
	 * Allocate arena data for the root topology node.
	 * Note: In production code, this would typically be done during
	 * topology initialization via topo_init() with a non-zero data_size.
	 */
	data = (struct topology_data __arena *)scx_static_alloc(sizeof(struct topology_data), 8);
	if (!data) {
		bpf_printk("TOPO ARENA DATA: failed to allocate arena data");
		return -ENOMEM;
	}

	data->magic_value = magic;
	data->access_count = 0;
	data->cpu_id = 0;

	topo_all->data = (void __arena *)data;

	data = topo_get_data(topo_all);
	if (!data) {
		bpf_printk("TOPO ARENA DATA: failed to get data via helper");
		return -EINVAL;
	}

	if (data->magic_value != magic) {
		bpf_printk("TOPO ARENA DATA: magic mismatch got=%llx want=%llx",
			   data->magic_value, magic);
		return -EINVAL;
	}

	ret = topo_update_data(topo_all, magic + 1, bpf_get_smp_processor_id());
	if (ret) {
		bpf_printk("TOPO ARENA DATA: failed to update data: %d", ret);
		return ret;
	}

	if (!topo_verify_data(topo_all, magic + 1)) {
		bpf_printk("TOPO ARENA DATA: data verification failed after update");
		return -EINVAL;
	}

	data = topo_get_data(topo_all);
	if (data->access_count != 1) {
		bpf_printk("TOPO ARENA DATA: unexpected access count: %d", data->access_count);
		return -EINVAL;
	}

	i = 0;
	TOPO_FOR_EACH_CPU(&iter, child) {
		struct topology_data __arena *child_data;

		if (i >= 2)  /* Limit iteration for testing */
			break;

		child_data = (struct topology_data __arena *)
			scx_static_alloc(sizeof(struct topology_data), 8);
		if (!child_data) {
			bpf_printk("TOPO ARENA DATA: failed to allocate child data");
			continue;
		}

		child_data->magic_value = magic + i + 2;
		child_data->access_count = 0;
		child_data->cpu_id = child->id;
		child->data = (void __arena *)child_data;

		ret = topo_update_data(child, magic + i + 2, child->id);
		if (ret) {
			bpf_printk("TOPO ARENA DATA: failed to update child %d data", i);
			return ret;
		}

		if (!topo_verify_data(child, magic + i + 2)) {
			bpf_printk("TOPO ARENA DATA: child %d verification failed", i);
			return -EINVAL;
		}

		i++;
	}

	bpf_printk("TOPO ARENA DATA: test passed, processed %d nodes", i + 1);
	return 0;
}


__weak
int scx_selftest_arena_topology_timer(void)
{
	// Assume topology has been initialized before the test
	if (!topo_all) {
		bpf_printk("TOPO: failed to initialize topology");
		return -EINVAL;
	}

	SCX_TOPOLOGY_SELFTEST(timer_access);
	SCX_TOPOLOGY_SELFTEST(timer_with_helpers);
	SCX_TOPOLOGY_SELFTEST(arena_data);

	return 0;
}
