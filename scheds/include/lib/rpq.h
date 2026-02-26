/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <bpf_arena_spin_lock.h>
#endif /* __BPF__ */

/*
 * Relaxed Priority Queue (RPQ) - a scalable concurrent priority queue
 * based on the MultiQueue design (Rihani, Sanders, Dementiev - SPAA 2015).
 *
 * Maintains nr_queues independent binary min-heaps, each protected by its
 * own arena spinlock. Insert picks a random heap; pop uses the "power of
 * two choices" heuristic to select the heap with the smaller minimum.
 *
 * Provides O(nr_queues)-relaxed semantics: the element returned by pop
 * may not be the global minimum, but is within the top O(nr_queues)
 * elements with high probability.
 *
 * All internal heaps are pre-allocated as flat arrays in the BPF arena.
 * Heap operations (sift-up, sift-down) have loop counts bounded by
 * log2(per_queue_capacity), satisfying the BPF verifier.
 */

struct rpq_elem {
	u64 elem;	/* Payload (typically a pointer cast to u64) */
	u64 key;	/* Priority key (lower = higher priority) */
};

/*
 * Individual min-heap within the multiqueue.
 * Each heap has its own lock for independent, low-contention access.
 *
 * min_key is maintained under the lock and provides a single-word
 * lockless peek target for the "power of two choices" heuristic.
 * Set to (u64)-1 when the heap is empty.
 */
struct rpq_heap;
typedef struct rpq_heap __arena rpq_heap_t;

struct rpq_heap {
	arena_spinlock_t lock;
	u64 min_key;		/* Lockless peek target, (u64)-1 = empty */
	u64 size;
	u64 capacity;
	struct rpq_elem __arena *elems;
};

/*
 * Relaxed Priority Queue container.
 * Holds an array of nr_queues independent min-heaps.
 *
 * Typical usage: nr_queues = c * nr_cpus, where c >= 2.
 * With c = 2 and 64 CPUs, there are 128 internal heaps and the
 * expected rank error of pop is O(128).
 *
 * The d parameter controls how many queues are sampled during pop
 * ("pick-d" heuristic, generalizing power-of-two-choices).
 * d=2 is the standard MultiQueue design. Higher d gives better
 * rank quality at the cost of more cache-line reads per pop.
 */
struct rpq;
typedef struct rpq __arena rpq_t;

struct rpq {
	u32 nr_queues;
	u32 d;			/* Pick-d choices for pop heuristic */
	rpq_heap_t *queues;
};

#ifdef __BPF__

u64 rpq_create_internal(u32 nr_queues, u64 per_queue_capacity, u32 d);
#define rpq_create(nr_queues, per_queue_cap) \
	((rpq_t *)rpq_create_internal((nr_queues), (per_queue_cap), 2))
#define rpq_create_d(nr_queues, per_queue_cap, d) \
	((rpq_t *)rpq_create_internal((nr_queues), (per_queue_cap), (d)))

int rpq_insert(rpq_t *pq, u64 elem, u64 key);
int rpq_insert_home(rpq_t *pq, u64 elem, u64 key, u32 home);
int rpq_pop(rpq_t *pq, u64 *elem, u64 *key);
int rpq_pop_home(rpq_t *pq, u64 *elem, u64 *key, u32 home);
int rpq_peek(rpq_t *pq, u64 *elem, u64 *key);
int rpq_size(rpq_t *pq);
int rpq_destroy(rpq_t *pq);

#endif /* __BPF__ */
