/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */
#pragma once

/*
 * Poor man's userspace-driven RCU for arena allocations. Freed payloads
 * accumulate on the active side while the draining side sits out a grace
 * period which userspace provides, membarrier(MEMBARRIER_CMD_GLOBAL) being
 * synchronize_rcu(), before they are returned to the allocator. Stands in
 * until BPF grows bpf_call_rcu().
 *
 * The list is not intrusive: libarena hands out blocks that are payload from
 * the first byte, with the order and allocation bitmaps living in the chunk
 * header, so there is no per-allocation word to thread a link through, and the
 * payload itself is still visible to readers for the whole grace period.
 * Each deferred free therefore takes a separate node, recycled through a
 * per-instance freelist so the steady state allocates nothing.
 */

struct scx_urcu_node;
typedef struct scx_urcu_node __arena scx_urcu_node_t;

struct scx_urcu_node {
	u64		next;		/* next node on the side or freelist, 0 to end */
	void __arena	*payload;	/* the allocation awaiting reclaim */
};

struct scx_urcu {
	u64		head[2];	/* scx_urcu_node_t ptrs linked via ->next */
	u64		freelist;	/* recycled nodes, linked via ->next */
	u32		active;
};

#ifdef __BPF__

int scx_urcu_pending(struct scx_urcu *urcu);
void scx_urcu_free(struct scx_urcu *urcu, void __arena *payload);
int scx_urcu_reclaim(struct scx_urcu *urcu);

#endif /* __BPF__ */
