#pragma once

struct scx_minheap_elem {
	u64 elem;
	u64 weight;
};

#define SCX_MINHEAP_MAX_CAPACITY (128)

/*
 * XXXETSAL: We are currently splitting the keys and values into two arrays
 * because of verifier pain. The solution we need is to use an array of
 * scx_minheap_elem data structures whose size we adjust as needed.
 */

struct scx_minheap {
	u64				size;
	u64				capacity;
	u64				elems[SCX_MINHEAP_MAX_CAPACITY];
	u64				weights[SCX_MINHEAP_MAX_CAPACITY];
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

	helem->elem = heap->elems[0];
	helem->weight = heap->elems[0];

	heap->elems[0] = heap->elems[heap->size - 1];
	heap->weights[0] = heap->weights[heap->size - 1];

	heap->size -= 1;

	scx_minheap_balance_top_down(heap);

	return 0;
}

