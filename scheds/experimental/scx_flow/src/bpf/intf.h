// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants for the flow scheduler.
 *
 * Each CPU has one queue ordered by virtual deadline. Ties
 * leave in insertion order. One fallback queue holds tasks that have
 * no usable CPU in FIFO order. It is best effort overflow. Each task
 * holds at most one fallback slot through the queued bit. The backlog
 * stays within the live task count. Pinned tasks run on their local
 * queue. Placement keeps the constrained target. Drain walks local
 * first, then same cache group, then same LLC, then same node, then
 * distant remote, then fallback last. Tiers stay L1 greater than L2
 * greater than L3. Short form is L1>L2>L3. Idle starts at once. Size
 * breaks ties only inside one tier with larger buckets first within tier
 * when both buckets are known. Each per CPU queue holds without bound
 * with one millisecond slices. Each enqueue prices the task by its
 * effective weight from nice plus live share. A task pays for the time
 * it burns, scaled by that weight. Fresh times move past a per LLC
 * floor. Stored times stay best effort unique. A direct store of the
 * last observed value plus one runs when the loop loses too often.
 * A rare duplicate keeps insertion order. Virtual deadline adds an
 * effective based step scaled by the burst to the floored time. A
 * larger effective weight or a shorter run gives an earlier due time.
 * Slices hold one fixed quantum with a small floor. Burst holds the
 * last run length. An insert miss keeps the newcomer in the fallback
 * queue in FIFO order with no evict. Stopping plus tick keep the burst
 * and run state with guarded preempt and no reclaim. A shared enqueue
 * with a due time ahead of the
 * running due time preempts guarded. Each running instance kicks at most once. A runnable yield with no burnt time still moves the stored
 * time forward by one. Each per CPU queue holds with depth bound at
 * RB_MAX_DEPTH. The fallback holds at most one slot per live task in
 * FIFO order with no extra bound. Per CPU trees use an unbalanced BST
 * with always eligible tasks. Placement follows the upstream topology
 * library. Liveness comes from the same tree. Arena holds one BST node
 * per task beside the task state. The tree drains leftmost wins with
 * ties right in RB_DUPLICATE-compatible order. Per CPU drain runs
 * through LOCAL only with offline reap. The base constant stays
 * kept unused reserved with no reader. The queue caps stay reserved
 * with no reader for sizing only.
 * Every non duplicate ends in a queue insert with the gauge paired by
 * a saturating floor for telemetry only.
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
	FLOW_QUEUE_CAP = 64ULL, /* Kept reserved. */
	FLOW_FALLBACK_CAP = 1024ULL, /* Kept reserved. */
	FLOW_SLICE_MIN_NS = 1000000ULL,
	FLOW_SLICE_FLOOR_NS = 62500ULL,
	FLOW_EXIT_SLICE_NS = 1000ULL,
	FLOW_FAIR_BASE_NS = 20000ULL, /* Kept unused reserved. */
	FLOW_FAIR_EXTRA_NS = 1000ULL, /* Kept unused reserved. */
	FLOW_SEQ_FLOOR_STEP_NS = 1000000ULL,
	FLOW_LAG_MAX_NS = 8000000ULL,
	FLOW_RB_MAX_DEPTH = 32ULL,
	FLOW_RUN_WIN_NS = 30000000000ULL,
	FLOW_RUN_SPAN_NS = 4000000000ULL,
	FLOW_RUN_NEED = 4ULL,
	FLOW_RUN_RING = 8ULL,
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	FLOW_FLAG_QUEUED = 1ULL,
	FLOW_FLAG_IN_RB = 2ULL,
	FLOW_KICK_GAP_NS = 100000ULL,
	FLOW_KICK_GRAN_NS = 200000ULL,
	FLOW_KICK_TAIL_NS = 100000ULL,
};
/* Per task state. Vtime is charged service. Slice holds the time
 * left in the current quantum. Gen identifies the running instance.
 * Llc records the last enqueue target. Flags holds the queued bit.
 * Virtual deadline holds the due time for queue order. Burst holds the
 * run length
 * used for the due time. Run holds eight recent run lengths with
 * close stamps for stable tasks. Head is the next slot masked with
 * seven. Pruned counts stale drops. Min plus max hold the kept range.
 * Known marks a stable range for the hard path. Total holds the
 * current run sum capped at thirty seconds. A stable range needs four
 * kept entries over a four second span inside a thirty second window
 * with a tight range check. A zero or backward clock freezes with no
 * ring move. The state holds two
 * hundred sixteen bytes. */
struct flow_task_ctx {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 flags;
	s64 vd;
	u64 burst_ns;
	u64 run_dur[8];
	u64 run_stamp[8];
	u64 run_min;
	u64 run_max;
	u64 run_total;
	u32 run_head;
	u32 run_pruned;
	u32 run_known;
	u32 run_pad;
};
/* Arena per task slot. Storage holds the reserved slot with the pid
 * beside it. The slot sits at offset zero. Slot storage zero holds the
 * insert key for remove stability. The slot holds one hundred thirty six
 * bytes. State plus slot stay within five hundred twelve bytes per task.
 * The tree node for enqueue lives in slab memory, not in this slot. The
 * red black entry slab adds up to forty eight bytes per queued task at
 * most. The queued bit plus the tree bit bound the slab count to the live
 * task count. Three hundred fifty two plus forty eight stays at four
 * hundred within five hundred twelve. The tree is an unbalanced BST with
 * ties right and depth bound at RB_MAX_DEPTH. Contention plus depth
 * overflow plus alloc miss fall back to FIFO. The tree drains leftmost
 * wins with ties chained right. Remove uses successor splice with no
 * orphan and no leak. Verifier keeps straight line order. Leftmost walks
 * use the bounded hold only. Sizes stay 216 plus 136 plus 352 plus 512
 * with 48 plus 16. Two level vruntime keeps vtime plus due time with lag
 * clamped at LAG_MAX with integer only. LAG_MAX caps lateness at eight
 * milliseconds with saturation on skew and on excess. Lag clamp runs in
 * the kick path. It does not change pricing. Pricing stays vruntime
 * only. */
struct flow_arena_task {
	u64 storage[16];
	s32 pid;
	u32 pad;
};
/* Per CPU tree node. Parent plus color pack into one u64. Right plus
 * left hold arena addresses. Pid plus pad close the node. Owner lookup
 * uses the pid. Node size stays at thirty two bytes inside the one
 * hundred thirty six byte arena slot. A null root means the CPU is
 * offline or its tree was never built. The rule fails closed as before.
 * The node is a plain BST link. Color is unused. Depth stays bound. */
struct flow_rb_node {
	u64 __rb_parent_color;
	u64 rb_right;
	u64 rb_left;
	s32 pid;
	u32 pad;
};
/* Per CPU tree root in arena memory. Root holds the tree address
 * as u64. Zero means empty. Count holds the tree occupancy. The queued
 * gauge in per LLC stats is the live bound. Lock guards insert plus pop.
 * The lock uses a short try. Contention falls back to FIFO with no wait.
 * Depth overflow plus contention plus alloc miss all fall back to FIFO. */
struct flow_rb_root {
	u64 root;
	u32 cnt;
	u32 lock;
};
/* Node stays at thirty two bytes inside the arena slot. */
_Static_assert(sizeof(struct flow_rb_node) == 32, "flow_rb_node size drifted");
/* Tree entry in slab memory. Node holds the link. Key holds the biased
 * deadline. Owner holds the target CPU. Pad2 stays reserved as zero. The
 * entry is the unit counted for the slab envelope. Owner is checked on
 * remove with key plus pid plus owner. */
struct flow_rb_entry {
	struct flow_rb_node node;
	u64 key;
	u32 owner;
	u32 pad2;
};
/* Entry stays at forty eight bytes. State plus slot plus entry stay at
 * four hundred within five hundred twelve. */
_Static_assert(sizeof(struct flow_rb_entry) == 48, "flow_rb_entry size drifted");
/* Arena task stays at one hundred thirty six bytes with no growth, so
 * state plus node stay at three hundred fifty two within five hundred
 * twelve per task. */
_Static_assert(sizeof(struct flow_arena_task) == 136, "flow_arena_task size drifted");
/* Per CPU running view. Gen counts runs. Pad holds the last kicked
 * generation, so each run kicks at most once. Virtual deadline mirrors
 * the running task due time for gap checks. Start holds the run start
 * wall time for granularity checks. Slice holds the left slice for tail
 * checks. The view holds forty eight bytes. */
struct flow_running_state {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 pad;
	s64 vd;
	u64 start_ts;
};
/* The running view holds forty eight bytes with no growth. */
_Static_assert(sizeof(struct flow_running_state) == 48, "flow_running_state size drifted");
/* Per CPU seed from userspace. Holds the CPU id plus the cluster
 * index assigned at startup. Cache and node placement come from the
 * upstream topology tree, so no cached copy lives here. The cluster
 * index stays here as an interim until it moves into the tree data
 * pointer, which needs a non-zero data size at tree build time. The
 * spare word holds three size buckets plus one reserved byte. Each
 * bucket is a u8 with zero meaning unknown. The buckets share one
 * aggregated per CPU share from userspace. The seed stays sixteen
 * bytes total. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 ccx_id;
	u8 l2_bkt;
	u8 l3_bkt;
	u8 cache_cls;
	u8 rsv;
	u32 pad;
};
/* The seed stays sixteen bytes with no growth. */
_Static_assert(sizeof(struct flow_cpu_ctx) == 16, "flow_cpu_ctx size drifted");
/* The task state stays two hundred sixteen bytes with no growth, so state
 * plus node stay within five hundred twelve bytes per task. */
_Static_assert(sizeof(struct flow_task_ctx) == 216, "flow_task_ctx size drifted");
/* Bucket ladder over kibibytes. Zero means unknown with no size.
 * Larger numbers mean larger caches. Values cap at the top with no
 * wrap. Mirrors cache_bucket in topology.rs with identical thresholds.
 * Keep both in sync. Compares promote to int per C rules with identical
 * result and no extra budget. */
static __always_inline u8 cache_bucket(u32 kb)
{
	if (!kb)
		return 0;
	if (kb <= 32U)
		return 1;
	if (kb <= 48U)
		return 2;
	if (kb <= 256U)
		return 3;
	if (kb <= 512U)
		return 4;
	if (kb <= 1024U)
		return 5;
	if (kb <= 8192U)
		return 6;
	if (kb <= 16384U)
		return 7;
	if (kb <= 32768U)
		return 8;
	if (kb <= 98304U)
		return 9;
	if (kb <= 524288U)
		return 10;
	return 255;
}
/* Per LLC counters. The order matches the userspace reader.
 * Queued counts tasks waiting in shared queues. Dispatched counts
 * moves to a local queue. Fallback counts fallback inserts. Steal
 * counts remote moves, with a split count kept on the thief.
 * Duplicate counts requeues dropped while already queued. Kick
 * counts idle plus skipped wakes with the preempt count at zero. Overrun counts full
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
