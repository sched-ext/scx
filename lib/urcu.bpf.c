/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <scx/common.bpf.h>
#include <libarena/common.h>

#include <lib/urcu.h>

/*
 * Poor man's userspace-driven RCU, standing in until BPF grows bpf_call_rcu().
 * scx_urcu_free() pushes nodes onto the active side of a two-sided list.
 * Userspace waits using membarrier(MEMBARRIER_CMD_GLOBAL), which is
 * synchronize_rcu(), and then runs a BPF program which calls scx_urcu_reclaim()
 * to return the draining side to the allocator and flip the sides.
 *
 * A side may only be reclaimed after a grace period which started after the
 * side stopped being active. Readers still holding pointers into the payloads
 * and frees which read the active index before the flip are all inside RCU
 * read sections which such a grace period waits out.
 */

/* sized so that exhaustion means seconds of spinning */
#define SCX_URCU_CAS_TRIES	(1U << 23)

/* per-call reclaim cap to bound the verifier walk */
#define SCX_URCU_RECLAIM_BATCH	4096

/*
 * Doorbell waking userspace when a free makes the lists go empty to non-empty,
 * shared by every scx_urcu instance: a wakeup should drain all of them.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} scx_urcu_doorbell SEC(".maps");

/*
 * Take a node off the instance's freelist, allocating one only when the
 * freelist runs dry. Reclaim returns every node it drains, so an instance
 * settles at its high water mark of concurrently deferred frees and stops
 * allocating.
 */
static scx_urcu_node_t *scx_urcu_node_get(struct scx_urcu *urcu)
{
	scx_urcu_node_t *node;
	u32 i;

	bpf_for(i, 0, SCX_URCU_CAS_TRIES) {
		node = (scx_urcu_node_t *)READ_ONCE(urcu->freelist);
		if (!node)
			break;

		if (__sync_val_compare_and_swap(&urcu->freelist, (u64)node,
						node->next) == (u64)node)
			return node;
	}

	return (scx_urcu_node_t *)arena_malloc(sizeof(struct scx_urcu_node));
}

static void scx_urcu_node_put(struct scx_urcu *urcu, scx_urcu_node_t *node)
{
	u32 i;

	bpf_for(i, 0, SCX_URCU_CAS_TRIES) {
		u64 head = READ_ONCE(urcu->freelist);

		node->next = head;
		if (__sync_val_compare_and_swap(&urcu->freelist, head,
						(u64)node) == head)
			return;
	}

	/* Give up on recycling rather than spin forever, the node is ours. */
	arena_free(node);
}

/* Whether any node is awaiting reclaim. */
__hidden
int scx_urcu_pending(struct scx_urcu *urcu)
{
	return READ_ONCE(urcu->head[0]) || READ_ONCE(urcu->head[1]);
}

__hidden
void scx_urcu_free(struct scx_urcu *urcu, void __arena *payload)
{
	scx_urcu_node_t *node;
	u32 side, i;

	arena_subprog_init();

	node = scx_urcu_node_get(urcu);
	if (unlikely(!node)) {
		scx_bpf_error("urcu node allocation failed");
		return;
	}

	node->payload = payload;

	side = READ_ONCE(urcu->active) & 1;
	bpf_for(i, 0, SCX_URCU_CAS_TRIES) {
		u64 head = READ_ONCE(urcu->head[side]);

		node->next = head;
		if (__sync_val_compare_and_swap(&urcu->head[side], head, (u64)node) != head)
			continue;

		/*
		 * Ring on this side's empty to non-empty transition.
		 *
		 * No wakeup is lost: userspace sleeps only after seeing both
		 * sides empty, so the first free afterwards lands on an empty
		 * side and rings, and later frees pile behind it.
		 *
		 * Testing the other side too would lose wakeups: a free which
		 * read the side before a flip lands opposite one which read it
		 * after, and each can see the other's node and stay quiet.
		 */
		if (!head) {
			u32 *e = bpf_ringbuf_reserve(&scx_urcu_doorbell, sizeof(*e), 0);

			/* a full doorbell already has wakeups pending */
			if (e) {
				*e = 0;
				bpf_ringbuf_submit(e, 0);
			}
		}
		return;
	}

	scx_urcu_node_put(urcu, node);
	scx_bpf_error("urcu free CAS exhausted");
}

/*
 * Call only after a grace period which started after the previous call. Returns
 * nonzero when the batch cap cut the walk short: call again, the leftovers need
 * no new grace period.
 */
__hidden
int scx_urcu_reclaim(struct scx_urcu *urcu)
{
	u32 side = (READ_ONCE(urcu->active) ^ 1) & 1;
	u32 i;

	arena_subprog_init();

	/*
	 * The grace period has flushed every free which could still see this
	 * side as active, so plain accesses suffice from here on.
	 */
	bpf_for(i, 0, SCX_URCU_RECLAIM_BATCH) {
		scx_urcu_node_t *node = (scx_urcu_node_t *)urcu->head[side];

		if (!node)
			break;
		urcu->head[side] = node->next;

		arena_free(node->payload);
		scx_urcu_node_put(urcu, node);
	}

	if (urcu->head[side])
		return 1;

	/*
	 * The xchg keeps the flip from becoming visible before the walk's head
	 * updates: a free that saw the flip early could push onto a stale head
	 * value which the walk's store then overwrites.
	 */
	__sync_lock_test_and_set(&urcu->active, side);
	return 0;
}
