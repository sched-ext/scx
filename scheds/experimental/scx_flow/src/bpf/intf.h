// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants for the flow scheduler.
 *
 * Each CPU owns one queue ordered by virtual deadline. Ties
 * leave in insertion order. One fallback queue holds tasks that have
 * no usable CPU in FIFO order as a best effort overflow with no extra
 * promise. Pinned tasks run on their local queue. Placement keeps the
 * constrained target with no load scan. Draining walks local first
 * then same LLC then same node then distant remote last in deadline order
 * with idle starts at once. Each per CPU queue holds bounded at 64
 * total with one millis slices. Each enqueue prices the task by its
 * nice weight. A task pays for the time it burns, scaled by that weight. Fresh times move past
 * a per LLC floor so two tasks never share the same value, with a
 * direct store of the last observed value plus one when the loop
 * loses too often. Virtual deadline adds a nice based step scaled
 * by the burst to the floored time through the shared charge path,
 * so a larger weight or a shorter run gives an earlier due time.
 * Slices hold one fixed quantum with a small floor. Burst holds the
 * last run length. Overload keeps a guaranteed admit with live plus
 * tolerance plus bound plus room plus cap. A full target evicts at most
 * one ready task with the latest deadline in the lowest implicit band
 * through a bounded scan of at most eight. Bands come from the nice
 * weight through the fair helper with no new field. Rejects stay in the
 * fallback queue in FIFO order. Stopping plus tick reclaim at most one
 * saved delta from burst past burnt with room plus live plus allowed
 * and idle only kick. A shared enqueue with a due time ahead of the
 * running due time kicks for preempt with idle wakes otherwise. Each running instance kicks at most once.
 * A runnable yield with no burnt time still moves the stored time forward by one. Each per CPU queue
 * holds bounded at 64 total with the fallback holding at most one
 * thousand twenty four. Queues come from the upstream deadline
 * library with always eligible tasks, and placement follows the upstream
 * topology library with liveness from the same tree. Arena holds one
 * queue node per task beside the task state.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_INTF_H
#define __FLOW_INTF_H
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
#endif
#include <stdbool.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif
#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif
enum flow_consts {
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_MAX_LLCS = 64ULL,
	FLOW_MAX_NODES = 8ULL,
	FLOW_QUEUE_CAP = 64ULL,
	FLOW_FALLBACK_CAP = 1024ULL,
	FLOW_RED_TOL_NS = 64000ULL,
	FLOW_RED_EMAX_NS = 256000ULL,
	FLOW_RED_EVICT_MAX = 8ULL,
	FLOW_SLICE_MIN_NS = 1000000ULL,
	FLOW_SLICE_FLOOR_NS = 62500ULL,
	FLOW_EXIT_SLICE_NS = 1000ULL,
	FLOW_FAIR_BASE_NS = 20000ULL,
	FLOW_FAIR_EXTRA_NS = 1000ULL,
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	FLOW_FLAG_QUEUED = 1ULL,
};
/* Per task state. Vtime is charged service. Slice holds the time
 * left in the current quantum. Gen identifies the running instance.
 * Llc records the last enqueue target. Flags holds the queued bit.
 * Vd holds the due time for queue order. Burst holds the run length
 * used for the due time. */
struct flow_task_ctx {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 flags;
	s64 vd;
	u64 burst_ns;
};
/* Arena per task queue node. Storage holds the upstream queue node
 * with the pid beside it for owner lookup. The node sits at offset
 * zero so a queue pop address is also this address. Sized for the
 * task allocator with spare words for growth. */
struct flow_arena_task {
	u64 storage[16];
	s32 pid;
	u32 pad;
};
/* Per CPU running view. Gen counts runs. Pad holds the last kicked
 * generation, so each run kicks at most once. Vd mirrors the running
 * task due time for gap checks. */
struct flow_running_state {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 pad;
	s64 vd;
};
/* Per CPU seed from userspace. Holds the CPU id plus the cluster
 * index assigned at startup. Cache and node placement come from the
 * upstream topology tree, so no cached copy lives here. The cluster
 * index stays here as an interim until it moves into the tree data
 * pointer, which needs a non-zero data size at tree build time. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 ccx_id;
	u32 reserved;
	u32 pad;
};
/* Per LLC counters. The order matches the userspace reader.
 * Queued counts tasks waiting in shared queues. Dispatched counts
 * moves to a local queue. Fallback counts fallback inserts. Steal
 * counts remote moves, with a split count kept on the thief.
 * Duplicate counts requeues dropped while already queued. Kick
 * counts preempt plus idle and skipped wakes. Overrun counts full
 * slice burns. Blocked counts stops that leave the task runnable.
 * Orphan counts mask change kicks. Forward counts heads passed to
 * their owner. */
struct flow_llc_stats {
	u64 queued;
	u64 dispatched;
	u64 fallback;
	u64 steal;
	u64 fb_duplicate;
	u64 steal_llc;
	u64 kick_preempt;
	u64 kick_idle;
	u64 kick_skip;
	u64 overrun;
	u64 blocked;
	u64 orphan_kick;
	u64 hol_forward;
};
#ifdef __BPF__
static __always_inline bool flow_llc_ok(u32 llc)
{
	return llc < (u32)FLOW_MAX_LLCS;
}
static __always_inline bool flow_cpu_ok(u32 cpu)
{
	return cpu < (u32)FLOW_MAX_CPUS;
}
static __always_inline bool flow_node_ok(u32 node)
{
	return node < (u32)FLOW_MAX_NODES;
}
#endif
#endif
