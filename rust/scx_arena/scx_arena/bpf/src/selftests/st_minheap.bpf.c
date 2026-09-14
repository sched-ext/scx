/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/minheap.h>

#include "selftest.h"

#define HEAP_CAPACITY (32ULL)

/*
 * Try to pop an empty heap.
 */
static
int scx_selftest_minheap_empty(scx_minheap_t *heap)
{
	struct scx_minheap_elem helem;
	int ret;

	if (heap->size)
		return -EINVAL;

	ret = scx_minheap_pop(heap, &helem);
	if (!ret)
		return -EINVAL;

	return 0;
}

/* XXX Overflowing maximum capacity test */

static
int scx_selftest_minheap_ascending(scx_minheap_t *heap)
{
	u64 keys[] = { 2, 5, 9, 15, 22, 30 };
	const size_t capacity = sizeof(keys) / sizeof(keys[0]);
	struct scx_minheap_elem helem;
	u64 prev = 0;
	int ret, i;

	if (heap->size)
		return -EINVAL;

	if (capacity > heap->capacity)
		return -E2BIG;

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_insert(heap, keys[i], keys[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_pop(heap, &helem);
		if (ret)
			return ret;

		if (helem.elem != helem.weight) {
			bpf_printk("invalid element (%ld %ld)", prev, helem.weight);
			return -EINVAL;
		}

		if (prev > helem.weight) {
			bpf_printk("weight inversion %ld %ld", prev, helem.weight);
			return -EINVAL;
		}

		prev = helem.elem;
	}

	return 0;
}

static
int scx_selftest_minheap_descending(scx_minheap_t *heap)
{
	u64 keys[] = { 13, 11, 9, 7, 5, 3, 1 };
	const size_t capacity = sizeof(keys) / sizeof(keys[0]);
	struct scx_minheap_elem helem;
	u64 prev = 0;
	int ret, i;

	if (heap->size)
		return -EINVAL;

	if (capacity > heap->capacity)
		return -E2BIG;

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_insert(heap, keys[i], keys[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_pop(heap, &helem);
		if (ret)
			return ret;

		if (helem.elem != helem.weight) {
			bpf_printk("invalid element (%ld %ld)", prev, helem.weight);
			return -EINVAL;
		}

		if (prev > helem.weight) {
			bpf_printk("weight inversion %ld %ld", prev, helem.weight);
			return -EINVAL;
		}

		prev = helem.elem;
	}

	return 0;
}

static
int scx_selftest_minheap_alternating(scx_minheap_t *heap)
{
	u64 keys[] = { 23, 12, 55, 42, 67, 3, 15, 8 };
	const size_t capacity = sizeof(keys) / sizeof(keys[0]);
	struct scx_minheap_elem helem;
	u64 prev = 0;
	int ret, i;

	if (heap->size)
		return -EINVAL;

	if (capacity > heap->capacity)
		return -E2BIG;

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_insert(heap, keys[i], keys[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_pop(heap, &helem);
		if (ret)
			return ret;

		if (helem.elem != helem.weight) {
			bpf_printk("invalid element (%ld %ld)", prev, helem.weight);
			return -EINVAL;
		}

		if (prev > helem.weight) {
			bpf_printk("weight inversion %ld %ld", prev, helem.weight);
			return -EINVAL;
		}

		prev = helem.elem;
	}

	return 0;
}

static
int scx_selftest_minheap_random(scx_minheap_t *heap)
{
	u64 keys[] = { 97, 79, 88, 2, 51, 75, 71, 59, 12, 7, 37 };
	const size_t capacity = sizeof(keys) / sizeof(keys[0]);
	struct scx_minheap_elem helem;
	u64 prev = 0;
	int ret, i;

	if (heap->size)
		return -EINVAL;

	if (capacity > heap->capacity)
		return -E2BIG;

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_insert(heap, keys[i], keys[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < capacity && can_loop; i++) {
		ret = scx_minheap_pop(heap, &helem);
		if (ret)
			return ret;

		if (helem.elem != helem.weight) {
			bpf_printk("invalid element (%ld %ld)", prev, helem.weight);
			return -EINVAL;
		}

		if (prev > helem.weight) {
			bpf_printk("weight inversion %ld %ld", prev, helem.weight);
			return -EINVAL;
		}

		prev = helem.elem;
	}

	return 0;
}

static
int scx_selftest_minheap_read_back(scx_minheap_t *heap)
{
	struct scx_minheap_elem helem;
	u64 elem = 5;
	u64 weight = 12;
	int ret;

	if (heap->size)
		return -EINVAL;

	ret = scx_minheap_insert(heap, elem, weight);
	if (ret)
		return ret;

	ret = scx_minheap_pop(heap, &helem);
	if (ret)
		return ret;

	if (helem.elem != elem) {
		bpf_printk("Expected elem %ld, found %d", elem, helem.elem);
		return -EINVAL;
	}

	if (helem.weight != weight) {
		bpf_printk("Expected elem %ld, found %d", weight, helem.weight);
		return -EINVAL;
	}

	return 0;
}
#define SCX_MINHEAP_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_minheap_ ## suffix, heap)

__weak
int scx_selftest_minheap(void)
{
	scx_minheap_t *heap;

	heap = scx_minheap_alloc(HEAP_CAPACITY);
	if (!heap) {
		bpf_printk("Could not allocate heap");
		return -ENOMEM;
	}

	SCX_MINHEAP_SELFTEST(empty);
	SCX_MINHEAP_SELFTEST(read_back);
	SCX_MINHEAP_SELFTEST(ascending);
	SCX_MINHEAP_SELFTEST(descending);
	SCX_MINHEAP_SELFTEST(alternating);
	SCX_MINHEAP_SELFTEST(random);

	return 0;
}
