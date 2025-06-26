/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

#include <lib/minheap.h>

__weak
u64 scx_minheap_alloc_internal(size_t capacity)
{
	size_t alloc_size = sizeof(scx_minheap_t);
	scx_minheap_t *heap;

	heap = scx_static_alloc(alloc_size, 1);
	if (!heap)
		return (u64)NULL;

	heap->helems = scx_static_alloc(capacity * sizeof(*heap->helems), 1);
	if (!heap->helems) {
		/* 
		 * XXXETSAL: Once we move on from the static alloc,
		 * properly free the initial allocation.
		 */
		return (u64)NULL;
	}

	heap->capacity = capacity;
	heap->size = 0;

	return (u64)heap;
}

__weak
int scx_minheap_balance_top_down(void __arena *heap_ptr __arg_arena)
{
	scx_minheap_t *heap = (scx_minheap_t *)heap_ptr;
	u64 elem, weight;
	int child, next;
	int off, ind;

	for (ind = 0; ind < heap->size && can_loop; ind = next) {

		next = ind;
		for (off = 1; off < 3 && can_loop; off++) {
			/*
			 * Correspondence between parent and children is:
			 * y = 2x + 1, y = 2x + 2
			 */
			child = 2 * ind + off;

			if (child >= heap->size)
				continue;

			if (heap->helems[next].weight <= heap->helems[child].weight)
				continue;

			next = child;
		}

		if (next == ind)
			break;

		elem = heap->helems[next].elem;
		weight = heap->helems[next].weight;

		heap->helems[next].elem = heap->helems[ind].elem;
		heap->helems[next].weight = heap->helems[ind].weight;

		heap->helems[ind].elem = elem;
		heap->helems[ind].weight= weight;
	}

	return 0;
}

static inline
int scx_minheap_balance_bottom_up(void __arena *heap_ptr __arg_arena)
{
	scx_minheap_t *heap = (scx_minheap_t *)heap_ptr;
	u64 elem, weight;
	int parent;
	int ind;

	for (ind = heap->size - 1; ind > 0 && can_loop; ind = parent) {
		parent = ind % 2 ? ind / 2 : ind / 2 - 1;

		if (heap->helems[parent].weight <= heap->helems[ind].weight)
			break;

		elem = heap->helems[parent].elem;
		weight = heap->helems[parent].weight;

		heap->helems[parent].elem = heap->helems[ind].elem;
		heap->helems[parent].weight = heap->helems[ind].weight;

		heap->helems[ind].elem = elem;
		heap->helems[ind].weight = weight;
	}

	return 0;
}

__hidden
int scx_minheap_insert(void __arena *heap_ptr __arg_arena, u64 elem, u64 weight)
{
	scx_minheap_t *heap = (scx_minheap_t *)heap_ptr;

	if (heap->size == heap->capacity)
		return -ENOSPC;

	heap->helems[heap->size].elem = elem;
	heap->helems[heap->size].weight = weight;

	heap->size += 1;

	scx_minheap_balance_bottom_up(heap);

	return 0;
}
