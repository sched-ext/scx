/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/minheap.h>

__weak
scx_minheap_t *scx_minheap_alloc(ssize_t capacity)
{
	scx_minheap_t *heap;
	size_t alloc_size = sizeof(scx_minheap_t);

	alloc_size += capacity * sizeof(*heap->helems);

	heap = scx_static_alloc(alloc_size, 1);
	if (!heap)
		return NULL;

	return heap;
}

static
int scx_minheap_balance(scx_minheap_t *heap, int ind)
{
	struct scx_minheap_elem htmp;
	int parent;

	if (ind >= heap->size)
		return -EINVAL;

	while (ind >= 0 && can_loop) {
		parent = (ind - 1) / 2;

		if (heap->helems[parent].weight <= heap->helems[ind].weight)
			break;

		htmp = heap->helems[parent];
		heap->helems[parent] = heap->helems[ind];
		heap->helems[ind] = htmp;
	}

	return 0;
}

__weak
int scx_minheap_insert(scx_minheap_t *heap, u64 elem, u64 weight)
{
	struct scx_minheap_elem helem = {
		.elem = elem,
		.weight = weight,
	};

	if (heap->size == heap->capacity)
		return -ENOSPC;

	heap->helems[heap->size++] = helem;

	scx_minheap_balance(heap, heap->size - 1);

	return 0;
}

__weak
int scx_minheap_pop(scx_minheap_t *heap, struct scx_minheap_elem *helem)
{
	if (heap->size == 0)
		return -EINVAL;

	*helem = heap->helems[0];
	heap->helems[0] = heap->helems[heap->size - 1];
	heap->size -= 1;

	scx_minheap_balance(heap, 0);

	return 0;
}

