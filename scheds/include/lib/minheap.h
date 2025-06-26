#pragma once

struct scx_minheap_elem {
	u64 elem;
	u64 weight;
};

struct scx_minheap {
	u64				size;
	u64				capacity;
	struct scx_minheap_elem		__arena *helems;
};

typedef struct scx_minheap __arena scx_minheap_t;

u64 scx_minheap_alloc_internal(size_t capacity);
#define scx_minheap_alloc(capacity) (scx_minheap_t *)scx_minheap_alloc_internal(capacity);

int scx_minheap_balance_top_down(void __arena *heap_ptr __arg_arena);
int scx_minheap_insert(void __arena *heap_ptr __arg_arena, u64 elem, u64 weight);

/* Inlined because we are passing a non-arena pointer argument. */
static inline
int scx_minheap_pop(void __arena *heap_ptr __arg_arena, struct scx_minheap_elem *helem __arg_trusted)
{
	scx_minheap_t *heap = (scx_minheap_t *)heap_ptr;

	if (heap->size == 0)
		return -EINVAL;

	helem->elem = heap->helems[0].elem;
	helem->weight = heap->helems[0].elem;

	heap->helems[0].elem = heap->helems[heap->size - 1].elem;
	heap->helems[0].weight = heap->helems[heap->size - 1].weight;

	heap->size -= 1;

	scx_minheap_balance_top_down(heap);

	return 0;
}

