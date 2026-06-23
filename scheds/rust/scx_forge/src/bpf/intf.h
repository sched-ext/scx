/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),

	/* Kernel definitions */
	CLOCK_BOOTTIME		= 7,

	/* scx_forge topology map limits. */
	FORGE_MAX_CPUS		= 4096,
	FORGE_MAX_TOPO_DOMAINS	= FORGE_MAX_CPUS,
	FORGE_MAX_TOPO_DISTANCES	= 65536,
	FORGE_TOPO_CPUMASK_WORDS	= FORGE_MAX_CPUS / 64,
};

enum forge_topo_core_type {
	FORGE_TOPO_CORE_BIG		= 0,
	FORGE_TOPO_CORE_BIG_TURBO	= 1,
	FORGE_TOPO_CORE_LITTLE		= 2,
};

/*
 * Topology level of the user-created DSQs.
 *
 * Shared with the Rust control plane so the @topo_dsq knob can be selected at
 * load time. Keep the values in sync with the DsqTopology CLI enum in main.rs.
 */
enum topology_dsq_type {
	TOPO_DSQ_CPU	= 0,	/* Per-CPU DSQs */
	TOPO_DSQ_LLC	= 1,	/* Per-LLC DSQs */
	TOPO_DSQ_NODE	= 2,	/* Per-node DSQs */
	TOPO_DSQ_GLOBAL	= 3,	/* Single shared DSQ */
};

/*
 * Ordering algorithm used for the queue key of vtime-ordered DSQs.
 *
 * Shared with the Rust control plane (the @ordering knob / --ordering CLI
 * flag). Keep the values in sync with the QueueOrdering CLI enum in main.rs.
 */
enum ordering_type {
	ORDER_VRUNTIME	= 0,	/* Virtual-runtime (CFS-like) fair ordering */
	ORDER_DEADLINE	= 1,	/* Earliest-deadline-first (weighted) */
	ORDER_FIFO	= 2,	/* First-in-first-out (by enqueue time) */
};

/*
 * Wakeup idle-CPU selection policy.
 *
 * Shared with the Rust control plane (the @idle_policy knob / --idle-policy
 * CLI flag). Keep the values in sync with the IdlePolicy CLI enum in main.rs.
 */
enum idle_policy_type {
	IDLE_CAPACITY	= 0,	/* Capacity-aware waker preference */
	IDLE_WAKEE	= 1,	/* Keep the wakee on its previous CPU */
	IDLE_WAKER	= 2,	/* Move the wakee toward the waker CPU */
	IDLE_THREAD	= 3,	/* Move toward the waker only for same-process threads */
	IDLE_STICKY	= 4,	/* Fall back to the previous CPU when none is idle */
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

struct cpu_arg {
	s32 cpu_id;
};

struct domain_arg {
	s32 cpu_id;
	s32 sibling_cpu_id;
};

struct forge_topo_cpumask {
	u64 bits[FORGE_TOPO_CPUMASK_WORDS];
};

struct forge_topology {
	u32 nr_cpu_ids;
	u32 nr_possible_cpus;
	u32 nr_online_cpus;
	u32 nr_nodes;
	u32 nr_llcs;
	u32 nr_cores;
	u32 nr_cpus;
	u8 smt_enabled;
	u8 numa_enabled;
	u8 reserved[2];
	struct forge_topo_cpumask span;
};

struct forge_topo_cpu {
	u32 id;
	u32 core_id;
	u32 llc_id;
	u32 llc_dense_id;
	u32 node_id;
	u32 package_id;
	s32 cluster_id;
	u32 l2_id;
	u32 l3_id;
	u32 smt_level;
	u32 core_type;
	u64 min_freq;
	u64 max_freq;
	u64 base_freq;
	u64 cpu_capacity;
	u64 pm_qos_resume_latency_us;
	u64 trans_lat_ns;
	u64 cache_size;
};

struct forge_topo_core {
	u32 id;
	u32 kernel_id;
	s32 cluster_id;
	u32 llc_id;
	u32 llc_dense_id;
	u32 node_id;
	u32 nr_cpus;
	u32 core_type;
	struct forge_topo_cpumask span;
};

struct forge_topo_llc {
	u32 id;
	u32 kernel_id;
	u32 dense_id;
	u32 node_id;
	u32 nr_cores;
	u32 nr_cpus;
	struct forge_topo_cpumask span;
};

struct forge_topo_node {
	u32 id;
	u32 nr_llcs;
	u32 nr_cores;
	u32 nr_cpus;
	u32 nr_distances;
	struct forge_topo_cpumask span;
};

struct forge_topo_distance_key {
	u32 node_id;
	u32 distance_idx;
};

#endif /* __INTF_H */
