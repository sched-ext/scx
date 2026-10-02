#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <bpf_arena_spin_lock.h>
#endif /* __BPF__ */

#include <lib/minheap.h>

#define SCX_DHQ_INF_CAPACITY ((u64)-1)

/* Dequeue modes */
#define SCX_DHQ_MODE_ALTERNATING	0
#define SCX_DHQ_MODE_PRIORITY		1
#define SCX_DHQ_MODE_BALANCED		2

/* Strand identifiers */
#define SCX_DHQ_STRAND_A		0
#define SCX_DHQ_STRAND_B		1
#define SCX_DHQ_STRAND_AUTO		2  /* Auto-select based on balancing */

/**
 * scx_dhq - Double Helix Queue
 *
 * A queue structure inspired by DNA's double helix with two intertwined
 * strands. Tasks can be enqueued to either strand and dequeued according
 * to different strategies (alternating, priority-based, or balanced).
 *
 * For cross-LLC task migration, strands typically represent the two LLCs
 * sharing the queue. The max_imbalance constraint applies only to enqueue
 * (based on size) to prevent one LLC from flooding the DHQ. On dequeue,
 * asymmetric consumption is allowed so idle LLCs can freely steal work
 * from busy LLCs without being blocked by imbalance constraints.
 *
 * @strand_a: Min heap for strand A
 * @strand_b: Min heap for strand B
 * @lock: Arena spinlock for thread-safety
 * @capacity: Total capacity across both strands
 * @size_a: Number of tasks in strand A
 * @size_b: Number of tasks in strand B
 * @seq_a: Sequence number for strand A (FIFO mode)
 * @seq_b: Sequence number for strand B (FIFO mode)
 * @dequeue_count_a: Number of dequeues from strand A (tracking only)
 * @dequeue_count_b: Number of dequeues from strand B (tracking only)
 * @max_imbalance: Maximum size difference on enqueue (0 = no limit)
 * @fifo: FIFO mode flag (1 = FIFO, 0 = priority/vtime)
 * @last_strand: Last strand dequeued from (for alternating mode)
 * @mode: Dequeue mode (ALTERNATING, PRIORITY, or BALANCED)
 */
struct scx_dhq {
	scx_minheap_t *strand_a;
	scx_minheap_t *strand_b;
	arena_spinlock_t lock;
	u64 capacity;
	u64 size_a;
	u64 size_b;
	u64 seq_a;
	u64 seq_b;
	u64 dequeue_count_a;
	u64 dequeue_count_b;
	u64 max_imbalance;
	u8 fifo;
	u8 last_strand;
	u8 mode;
};

typedef struct scx_dhq __arena scx_dhq_t;

#ifdef __BPF__
/**
 * scx_dhq_create_internal - Create a double helix queue
 * @fifo: true for FIFO mode, false for vtime/priority mode
 * @capacity: Total capacity (SCX_DHQ_INF_CAPACITY for unlimited)
 * @mode: Dequeue mode (ALTERNATING, PRIORITY, or BALANCED)
 * @max_imbalance: Maximum size difference allowed on enqueue (0 for unlimited)
 *                 NOTE: Only applies to enqueue, not dequeue. This prevents
 *                 one strand from flooding the queue while allowing asymmetric
 *                 consumption on dequeue for efficient cross-LLC work stealing.
 *
 * Returns: Pointer to scx_dhq_t or NULL on failure
 */
u64 scx_dhq_create_internal(bool fifo, size_t capacity, u64 mode, u64 max_imbalance);

#define scx_dhq_create(fifo, mode) \
	scx_dhq_create_internal((fifo), SCX_DHQ_INF_CAPACITY, (mode), 0)

#define scx_dhq_create_size(fifo, capacity, mode) \
	scx_dhq_create_internal((fifo), (capacity), (mode), 0)

#define scx_dhq_create_balanced(fifo, capacity, mode, max_imbalance) \
	scx_dhq_create_internal((fifo), (capacity), (mode), (max_imbalance))

/**
 * scx_dhq_insert - Insert task into DHQ in FIFO mode
 * @dhq_ptr: Pointer to double helix queue
 * @taskc_ptr: Pointer to task context
 * @strand: Target strand (STRAND_A, STRAND_B, or STRAND_AUTO)
 *
 * Returns: 0 on success, negative error code on failure
 */
int scx_dhq_insert(scx_dhq_t *dhq_ptr, u64 taskc_ptr, u64 strand);

/**
 * scx_dhq_insert_vtime - Insert task into DHQ with vtime/priority
 * @dhq: Pointer to double helix queue
 * @taskc_ptr: Pointer to task context
 * @vtime: Virtual time / priority value
 * @strand: Target strand (STRAND_A, STRAND_B, or STRAND_AUTO)
 *
 * Returns: 0 on success, negative error code on failure
 */
int scx_dhq_insert_vtime(scx_dhq_t *dhq, u64 taskc_ptr, u64 vtime, u64 strand);

/**
 * scx_dhq_nr_queued - Get total number of queued tasks
 * @dhq: Pointer to double helix queue
 *
 * Returns: Total number of tasks in both strands
 */
int scx_dhq_nr_queued(scx_dhq_t *dhq);

/**
 * scx_dhq_nr_queued_strand - Get number of queued tasks in specific strand
 * @dhq: Pointer to double helix queue
 * @strand: Target strand (STRAND_A or STRAND_B)
 *
 * Returns: Number of tasks in specified strand
 */
int scx_dhq_nr_queued_strand(scx_dhq_t *dhq, u64 strand);

/**
 * scx_dhq_pop - Dequeue task according to queue mode
 * @dhq: Pointer to double helix queue
 *
 * Returns: Task context pointer or NULL if empty
 */
u64 scx_dhq_pop(scx_dhq_t *dhq);

/**
 * scx_dhq_pop_strand - Dequeue task from specific strand
 * @dhq: Pointer to double helix queue
 * @strand: Target strand (STRAND_A or STRAND_B)
 *
 * Returns: Task context pointer or NULL if strand is empty
 */
u64 scx_dhq_pop_strand(scx_dhq_t *dhq, u64 strand);

/**
 * scx_dhq_peek - Peek at next task without removing it
 * @dhq: Pointer to double helix queue
 *
 * Returns: Task context pointer or NULL if empty
 */
u64 scx_dhq_peek(scx_dhq_t *dhq);

/**
 * scx_dhq_peek_strand - Peek at next task in specific strand
 * @dhq: Pointer to double helix queue
 * @strand: Target strand (STRAND_A or STRAND_B)
 *
 * Returns: Task context pointer or NULL if strand is empty
 */
u64 scx_dhq_peek_strand(scx_dhq_t *dhq, u64 strand);
#endif /* __BPF__ */
