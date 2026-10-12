// SPDX-License-Identifier: GPL-2.0
/*
 * Topology init helpers for the flow scheduler.
 *
 * Holds only the node bound check used by flow_init to derive the
 * node count from the seeded view. Hot paths never include this
 * header, so enqueue plus select plus dispatch keep their order.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_TOPOLOGY_H
#define __FLOW_TOPOLOGY_H

#include "intf.h"

/* True when the seeded node id fits the node bound. */
/* Out of bound rows never shape the node count, so large hosts fold */
/* to the machine queue with no trap. Init only with no hot-path use. */
static __always_inline bool flow_topo_node_ok(u32 node)
{
	return node < (u32)FLOW_MAX_NODES;
}

#endif /* __FLOW_TOPOLOGY_H */
