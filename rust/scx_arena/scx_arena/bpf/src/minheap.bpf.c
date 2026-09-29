/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

#include <lib/minheap.h>

static __always_inline void
scx_minheap_swap_elems(struct scx_minheap_elem __arena *a __arg_arena,
                       struct scx_minheap_elem __arena *b __arg_arena)
{
        u64 tmp_elem = a->elem;
        u64 tmp_weight = a->weight;

        a->elem = b->elem;
        a->weight = b->weight;

        b->elem = tmp_elem;
        b->weight = tmp_weight;
}

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

		scx_minheap_swap_elems(&heap->helems[next], &heap->helems[ind]);
	}

	return 0;
}

static inline
int scx_minheap_balance_bottom_up(void __arena *heap_ptr __arg_arena)
{
	scx_minheap_t *heap = (scx_minheap_t *)heap_ptr;
	int parent;
	int ind;

	for (ind = heap->size - 1; ind > 0 && can_loop; ind = parent) {
		parent = (ind - 1) >> 1;

		if (heap->helems[parent].weight <= heap->helems[ind].weight)
			break;

		scx_minheap_swap_elems(&heap->helems[parent], &heap->helems[ind]);
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

/* Inlined because we are passing a non-arena pointer argument. */
__hidden
int scx_minheap_pop(void __arena *heap_ptr __arg_arena, struct scx_minheap_elem *helem __arg_trusted)
{
	scx_minheap_t *heap = (scx_minheap_t *)heap_ptr;

	if (heap->size == 0)
		return -EINVAL;

	helem->elem = heap->helems[0].elem;
	helem->weight = heap->helems[0].weight;

	heap->helems[0].elem = heap->helems[heap->size - 1].elem;
	heap->helems[0].weight = heap->helems[heap->size - 1].weight;

	heap->size -= 1;

	scx_minheap_balance_top_down(heap);

	return 0;
}

__hidden
int scx_minheap_dump(scx_minheap_t *heap __arg_arena)
{
	int i;

	bpf_printk("HEAP %p SIZE %ld", heap, heap->size);
	for (i = 0; i < heap->size && can_loop; i++)
		bpf_printk("[0] (0x%lx, %ld)", heap->helems[i].elem, heap->helems[i].weight);

	return 0;
}
