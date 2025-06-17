#pragma once

struct scx_minheap_elem {
	u64 elem;
	u64 weight;
};

struct scx_minheap {
	u64				size;
	u64				capacity;
	struct scx_minheap_elem		helems[];
};

typedef struct scx_minheap __arena scx_minheap_t;

u64 scx_minheap_alloc_internal(size_t capacity);
#define scx_minheap_alloc(capacity) (scx_minheap_t *)scx_minheap_alloc_internal(capacity);

int scx_minheap_pop(scx_minheap_t *heap, struct scx_minheap_elem *helem);
int scx_minheap_insert(scx_minheap_t *heap, u64 elem, u64 weight);
