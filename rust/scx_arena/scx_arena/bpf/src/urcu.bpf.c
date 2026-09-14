/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#include <scx/common.bpf.h>

#include <lib/sdt_alloc.h>

/*
 * Poor man's userspace-driven RCU, standing in until BPF grows bpf_call_rcu().
 * scx_urcu_free() pushes freed nodes onto the active side of a two-sided list.
 * Userspace waits using membarrier(MEMBARRIER_CMD_GLOBAL), which is
 * synchronize_rcu(), and then runs a BPF program which calls scx_urcu_reclaim()
 * to return the draining side to the allocator and flip the sides.
 *
 * A side may only be reclaimed after a grace period which started after the
 * side stopped being active. Readers still holding pointers into the nodes and
 * frees which read the active index before the flip are all inside RCU read
 * sections which such a grace period waits out.
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

/* Whether any node is awaiting reclaim. */
__hidden
int scx_urcu_pending(struct scx_urcu *urcu)
{
	return READ_ONCE(urcu->head[0]) || READ_ONCE(urcu->head[1]);
}

__hidden
void scx_urcu_free(struct scx_urcu *urcu, struct scx_allocator *alloc,
		   void __arena *payload)
{
	struct sdt_data __arena *data = sdt_tailer(alloc, payload);
	u32 side, i;

	scx_arena_subprog_init();

	side = READ_ONCE(urcu->active) & 1;
	bpf_for(i, 0, SCX_URCU_CAS_TRIES) {
		u64 head = READ_ONCE(urcu->head[side]);

		data->urcu_link = head;
		if (__sync_val_compare_and_swap(&urcu->head[side], head,
						(u64)data) != head)
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
			u32 *e = bpf_ringbuf_reserve(&scx_urcu_doorbell,
						     sizeof(*e), 0);

			/* a full doorbell already has wakeups pending */
			if (e) {
				*e = 0;
				bpf_ringbuf_submit(e, 0);
			}
		}
		return;
	}
	scx_bpf_error("urcu free CAS exhausted");
}

/*
 * Call only after a grace period which started after the previous call. Returns
 * nonzero when the batch cap cut the walk short: call again, the leftovers need
 * no new grace period.
 */
__hidden
int scx_urcu_reclaim(struct scx_urcu *urcu, struct scx_allocator *alloc)
{
	u32 side = (READ_ONCE(urcu->active) ^ 1) & 1;
	u32 i;

	scx_arena_subprog_init();

	/*
	 * The grace period has flushed every free which could still see this
	 * side as active, so plain accesses suffice from here on.
	 */
	bpf_for(i, 0, SCX_URCU_RECLAIM_BATCH) {
		struct sdt_data __arena *data =
			(struct sdt_data __arena *)urcu->head[side];

		if (!data)
			break;
		urcu->head[side] = data->urcu_link;
		scx_alloc_free_idx(alloc, data->tid.idx);
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
