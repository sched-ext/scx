#pragma once

#ifdef __BPF__
#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>
#else /* __BPF__ */
#include <scx/bpf_arena_common.h>
#endif

struct scx_stk_seg;
typedef struct scx_stk_seg __arena scx_stk_seg_t;

/*
 * We devote a single page to scx_stk_seg, and size
 * the void * array so it fits exactly in it.
 * Account for prev/next pointers (2 * sizeof(void *)).
 */
#define SCX_STK_SEG_MAX ((PAGE_SIZE - 2 * sizeof(void *)) / sizeof(void *))

struct scx_stk_seg {
	void __arena	*elems[SCX_STK_SEG_MAX];
	scx_stk_seg_t	*prev;
	scx_stk_seg_t	*next;
};

/*
 * Extensible stack struct.
 */
struct scx_stk {
	arena_spinlock_t __arena *lock;

	scx_stk_seg_t *first;	/* First stack segment. */
	scx_stk_seg_t *last;

	scx_stk_seg_t *current;	/* Current stack segment. */
	__u64 cind;

	__u64 capacity;		/* Free slots in the stack. */
	__u64 available;	/* Available items in the stack. */
	__u64 data_size;
	__u64 nr_pages_per_alloc;

	scx_stk_seg_t *reserve;
};


#ifdef __BPF__

u64 scx_stk_alloc(struct scx_stk *stack);
int scx_stk_init(struct scx_stk *stackp, arena_spinlock_t __arena *lock,
		__u64 data_size, __u64 nr_pages_per_alloc);
void scx_stk_destroy(struct scx_stk *stack);
int scx_stk_free_internal(struct scx_stk *stack, __u64 elem);

#define scx_stk_free(stack, elem) scx_stk_free_internal(stack, (__u64)elem)

#endif /* __BPF__ */
