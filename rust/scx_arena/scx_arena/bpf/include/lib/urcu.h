/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */
#pragma once

/*
 * Userspace-driven RCU for arena allocations. Payloads wait on one side of a
 * two-sided list while userspace provides a grace period. Nodes are separate
 * allocations because libarena payloads have no private tailer storage.
 */
struct scx_urcu_node;
typedef struct scx_urcu_node __arena scx_urcu_node_t;

struct scx_urcu_node {
	u64		next;
	void __arena	*payload;
};

struct scx_urcu {
	u64		head[2];
	u64		freelist;
	u32		active;
};

#ifdef __BPF__

int scx_urcu_pending(struct scx_urcu *urcu);
void scx_urcu_free(struct scx_urcu *urcu, void __arena *payload);
int scx_urcu_reclaim(struct scx_urcu *urcu);

#endif /* __BPF__ */
