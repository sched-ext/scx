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
 * The payload itself remains visible to readers for the whole grace period.
 * scx_urcu_free() tracks it with a separate node recycled through a
 * per-instance freelist. Allocations whose layout reserves a node can instead
 * use scx_urcu_free_embedded(), which never allocates in the free path.
 */

struct scx_urcu_node;
typedef struct scx_urcu_node __arena scx_urcu_node_t;

struct scx_urcu_node {
	u64		next;		/* next node on the side or freelist, 0 to end */
	void __arena	*payload;	/* the allocation awaiting reclaim */
	u64		recycle;	/* node is a separate recyclable allocation */
};

struct scx_urcu {
	u64		head[2];	/* scx_urcu_node_t ptrs linked via ->next */
	u64		freelist;	/* recycled nodes, linked via ->next */
	u32		active;
};

#ifdef __BPF__

int scx_urcu_pending(struct scx_urcu *urcu);
void scx_urcu_free(struct scx_urcu *urcu, void __arena *payload);
void scx_urcu_free_embedded(struct scx_urcu *urcu, void __arena *payload,
			    scx_urcu_node_t *node);
int scx_urcu_reclaim(struct scx_urcu *urcu);

#endif /* __BPF__ */
