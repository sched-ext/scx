#pragma once

struct stk_seg;
typedef struct stk_seg __arena stk_seg_t;

/*
 * We devote a single page to stk_seg, and size
 * the void * array so it fits exactly in it.
 * Account for prev/next pointers (2 * sizeof(void *)).
 */
#define STK_SEG_MAX ((PAGE_SIZE - 2 * sizeof(void *)) / sizeof(void *))

struct stk_seg {
	void __arena	*elems[STK_SEG_MAX];
	stk_seg_t	*prev;
	stk_seg_t	*next;
};

/*
 * Extensible stack struct.
 */
struct stk {
	arena_spinlock_t __arena *lock;

	stk_seg_t *first;	/* First stack segment. */
	stk_seg_t *last;

	stk_seg_t *current;	/* Current stack segment. */
	__u64 cind;

	__u64 capacity;		/* Free slots in the stack. */
	__u64 available;	/* Available items in the stack. */
	__u64 data_size;
	__u64 nr_pages_per_alloc;

	stk_seg_t *reserve;
};


#ifdef __BPF__

u64 stk_alloc(struct stk *stack);
int stk_init(struct stk *stackp, arena_spinlock_t __arena *lock,
		__u64 data_size, __u64 nr_pages_per_alloc);
void stk_destroy(struct stk *stack);
int stk_free_internal(struct stk *stack, __u64 elem);

#define stk_free(stack, elem) stk_free_internal(stack, (__u64)elem)

#endif /* __BPF__ */
