// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler.
 *
 * The scheduler keeps one local queue per CPU plus one shared queue
 * per node plus one shared queue per machine plus one overflow tail.
 * Homeless work parks in the overflow tail with all other parks.
 * Every task carries a release plus a period plus an absolute
 * deadline, and each queue orders by that deadline. Admission holds
 * total declared use under ninety five percent of the machine, so
 * admitted work can meet its deadlines. A miss counts when wall
 * completion passes release plus deadline, and a miss parks the task
 * in overflow with a direct kick and no wait. Placement takes the
 * slowest sufficient CPU among the allowed set that can meet the
 * deadline, so light work never takes a fast CPU that other work
 * needs. Hints from the flat view tune the period only, and no group
 * or pool shapes order. See select_cpu.bpf.c for placement and
 * enqueue.bpf.c for admission plus the deadline choice and
 * dispatch.bpf.c for the four single moves and lifecycle.bpf.c for
 * the miss count and timer.bpf.c for the leftover charge plus the
 * miss count.
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
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif
/* Fixed slice of 2ms with no knob. Every insert uses this slice. */
/* Two ms covers two 1ms wakeups, so one slice always spans the */
/* cheapest wakeup granularity with margin for one late wakeup. */
enum flow_consts {
	FLOW_QUANTUM_NS = 2000000ULL,
	/* Default period of 16ms with no knob. Holds eight slices, */
	/* so a fully used task still leaves room for one park plus */
	/* one retry inside the period. */
	FLOW_PERIOD_NS = 16000000ULL,
	FLOW_WEIGHT_MIN = 1ULL,
	FLOW_WEIGHT_BASE = 128ULL,
	FLOW_WEIGHT_MAX = 16384ULL,
	/* CPU bound of 512 rows with no knob. Covers the largest test */
	/* host with wide margin while halving array memory. */
	FLOW_MAX_CPUS = 512ULL,
	/* Node bound of 8 rows with no knob. Covers the largest test */
	/* host with wide margin while keeping the node scan small. */
	FLOW_MAX_NODES = 8ULL,
	/* Hint bound of 4096 rows with no knob. Keys are hierarchy ids */
	/* with no dense use, so the table holds large hosts with room */
	/* for churn. Full tables fail closed to the default period */
	/* with no eviction and no stall. */
	FLOW_HINT_MAX = 4096ULL,
	/* Local queue region base. Holds 512 ids, one per CPU. */
	FLOW_LOCAL_BASE = 0x5100ULL,
	/* Node queue region base. Holds 8 ids, one per node. */
	FLOW_NODE_BASE = 0x5900ULL,
	/* Machine queue id shared by every CPU. */
	FLOW_MACHINE = 0x5A00ULL,
	/* Overflow tail id shared by every CPU. */
	FLOW_OVERFLOW = 0x5A01ULL,
	/* Queue count of 522. Holds 512 local plus 8 node plus one */
	/* machine plus one overflow. */
	FLOW_MAX_DSQS = 522ULL,
	/* Dispatch batch of 16 moves per pass with no knob. One pass */
	/* moves one task per tier for four moves at most, so the ops */
	/* table holds every pass with room and no shared math. */
	FLOW_DISPATCH_MAX_BATCH = 16ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	/* Admission bound of 950 per mille with no knob. Holds use */
	/* under ninety five percent, so admitted work keeps idle time */
	/* for late wakeups. */
	FLOW_ADMIT_PERMILLE = 950ULL,
	/* Base capacity of 1024 units with no knob. Every CPU on a */
	/* symmetric host offers the same units, so the slowest */
	/* sufficient pick falls to the lowest sufficient id. */
	FLOW_CAP_BASE = 1024ULL,
	/* CPU performance levels at half plus max with no knob. Any own */
	/* plus local plus running picks max else half with no shared use. */
	FLOW_CPU_PERF_HALF = 512ULL,
	FLOW_CPU_PERF_MAX = 1024ULL,
};
/* Per task state at 72B with release plus period plus deadline plus */
/* runtime plus stamps plus hint plus miss count plus admit share. */
/* Release holds the last release time for the miss check. A zero */
/* release means no release yet, so the miss check skips with no count. */
/* Period holds the relative period in nanos for the next deadline. */
/* A zero period means no hint yet, so the default period applies. */
/* Deadline holds the absolute deadline for queue order and the miss */
/* check. A zero deadline means no order yet, so preempt compares skip */
/* with no kick and the miss check skips with no count. */
/* Vruntime holds the scaled runtime served so far for order ties. */
/* A zero runtime means no service yet, so fresh tasks order by */
/* deadline alone. */
/* Wait holds the last enqueue time. A zero wait means the task */
/* never queued. Every queue join stamps the task, so queued work */
/* always carries a stamp. */
/* Run holds the segment start while on CPU else zero, so a claimed */
/* start pairs the on CPU gauge with the stopping charge. Running */
/* claims from zero only with a compare and swap, so a second running */
/* without a stop keeps the first start with no second count. */
/* Stopping versus disable or exit claims once with atomics, so each */
/* counted start meets exactly one gauge drop with no owner gate. */
/* Hint holds the flat period hint in micros for admission. A zero */
/* hint means no hint, so the default period applies. Misses holds */
/* the count of deadline misses for the life of the task with */
/* saturating adds, so a huge miss count clamps instead of wrapping. */
/* Admit share holds the added per mille share with zero for none, */
/* so the stop drops the stored value with no drift on hint change. */
/* Admit CPU holds the CPU where the share was added, so a moved task */
/* still debits the right row with no wrong CPU drop. Only admitted */
/* inserts touch the admitted rows, parks and homeless work never do. */
/* Stamps stay per task owned with no atomics except the run claim, */
/* only counters use atomics. Cursor and miss scans stay best effort */
/* with no atomic order. */
struct flow_task_ctx {
	u64 release;
	u64 period;
	u64 deadline;
	u64 vruntime;
	u64 wait_at;
	u64 run_at;
	u32 hint_us;
	u32 misses;
	u64 admit_share;
	u32 admit_cpu;
	u32 __pad;
};
/* Per CPU state at 8B with running pid plus placement cursor. */
/* Pid holds the task now on the CPU else zero. Owner clears use a */
/* compare and swap, so a stale exit never clears a new owner. */
/* Cursor spreads the placement scans with no hotspot. The cursor races */
/* best effort with no atomic order. Dispatch uses a fixed tier order */
/* with no cursor use. */
struct flow_cpu_state {
	u32 running_pid;
	u32 cursor;
};
/* Per CPU topology view at 8B with sibling plus node. */
/* Smt sib holds the thread sibling or all ones when unknown. */
/* Node holds the node id used by placement and dispatch. */
struct flow_topo {
	u32 smt_sib;
	u32 node;
};
/* Per CPU capacity view at 4B with one units row. */
/* Units hold the capacity in base units for the slowest sufficient */
/* pick. A zero row means unknown, so the base applies. */
struct flow_cpu_cap {
	u32 units;
};
/* Per CPU admitted use at 8B with one per mille row. */
/* Admitted holds the sum of admitted per mille shares on the CPU */
/* with saturating math, so a huge hint clamps instead of wrapping. */
struct flow_cpu_admit {
	u64 permille;
};
/* Flat period hint at 8B with one micros row per id. */
/* Hint holds the period in micros with zero for no hint. The flat */
/* view tunes the period only, and no group or pool shapes order. */
struct flow_hint {
	u64 period_us;
};
/* Scheduler counters with 15 fields. Homeless parks count in the */
/* overflow moves, so every tier move has a live counter. */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 inserts;
	u64 requeues;
	u64 completions;
	u64 local_moves;
	u64 node_moves;
	u64 machine_moves;
	u64 over_moves;
	u64 kicks;
	u64 admits;
	u64 rejects;
	u64 misses;
	u64 parks;
	u64 gate_rejects;
};
/* Task state holds release plus period plus deadline plus runtime */
/* plus stamps plus hint plus misses plus admit share in 72 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 72,
	"task state stays at 72B");
/* CPU state holds pid plus cursor in 8 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 8,
	"cpu state stays at 8B");
/* Topology view holds sibling plus node in 8 bytes. */
_Static_assert(sizeof(struct flow_topo) == 8,
	"topology view stays at 8B");
/* Stats hold 15 counters in 120 bytes. */
_Static_assert(sizeof(struct flow_sched_stats) == 120,
	"stats stay at 120B");
/* Queue count holds local plus node plus machine plus overflow. */
_Static_assert(FLOW_MAX_DSQS ==
	FLOW_MAX_CPUS + FLOW_MAX_NODES + 2,
	"dsq count stays local plus node plus two");
/* True when the first time is before the second with wrap safety. */
/* The signed diff keeps order across the u64 wrap with no branch. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Saturated add of two times with clamp on wrap. */
/* A wrap clamps to max, so a huge sum never falls to the front. */
static __always_inline u64 flow_sat_add(u64 a,
	u64 b)
{
	u64 out = a + b;
	if (out < a)
		return (u64)~0ULL;
	return out;
}
/* Clamped weight in 1 to 16384 with base 128. */
/* Zero or oversize weights fail closed to the nearer bound. */
static __always_inline u32 flow_weight_clamp(u32 w)
{
	if (w < (u32)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (w > (u32)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return w;
}
/* Advanced runtime after one execution segment. */
/* Scales raw time by base over weight with a split divide, so heavy */
/* weights advance slowly and light weights advance fast. The split */
/* keeps every intermediate small for real segments, a segment past */
/* the scale bound saturates at once, and both adds saturate too, so */
/* huge inputs clamp instead of wrapping. One stop per slice keeps */
/* the two divides cheap beside the slice. */
static __always_inline u64 flow_vruntime_advance(u64 vruntime,
	u64 delta, u32 weight)
{
	u64 w = (u64)flow_weight_clamp(weight);
	u64 q = delta / w;
	u64 head;
	u64 tail;
	u64 adv;
	u64 out;
	if (q > (u64)~0ULL / (u64)FLOW_WEIGHT_BASE)
		return (u64)~0ULL;
	head = q * (u64)FLOW_WEIGHT_BASE;
	tail = delta % w * (u64)FLOW_WEIGHT_BASE / w;
	adv = flow_sat_add(head, tail);
	if (adv == (u64)~0ULL)
		return (u64)~0ULL;
	out = flow_sat_add(vruntime, adv);
	return out;
}
/* Absolute deadline from release plus relative period. */
/* The add saturates, so a huge release clamps instead of wrapping */
/* to the front. */
static __always_inline u64 flow_deadline_at(u64 release,
	u64 period)
{
	return flow_sat_add(release, period);
}
/* Period for one task from hint else default. */
/* A zero hint means no hint, so the default period applies. The hint */
/* converts from micros to nanos with saturation, so a huge hint */
/* clamps instead of wrapping to a short period. */
static __always_inline u64 flow_task_period(u32 hint_us)
{
	u64 hint;
	if (!hint_us)
		return (u64)FLOW_PERIOD_NS;
	hint = (u64)hint_us;
	if (hint > 18446744073709551ULL)
		return (u64)~0ULL;
	return hint * 1000ULL;
}
/* True when one task missed its deadline at the given time. */
/* A zero deadline means no order yet, so the check skips. A zero */
/* release means no release yet, so the check skips too. A time that */
/* falls before the deadline passes, so only a time past the deadline */
/* counts a miss. */
static __always_inline bool flow_missed(u64 release,
	u64 deadline, u64 now)
{
	if (release == 0)
		return false;
	if (deadline == 0)
		return false;
	if (flow_time_before(now, deadline))
		return false;
	if (now == deadline)
		return false;
	return true;
}
/* Local queue id of one CPU from base plus id. */
/* One ordered queue per CPU keeps deadline order local. */
static __always_inline u64 flow_local_dsq(u32 cpu)
{
	return (u64)FLOW_LOCAL_BASE + (u64)cpu;
}
/* Shared queue id of one node from base plus id. */
/* One ordered queue per node shares work inside the node. */
static __always_inline u64 flow_node_dsq(u32 node)
{
	return (u64)FLOW_NODE_BASE + (u64)node;
}
/* Id of the machine queue shared by every CPU. */
/* Work with no node home rests here with mask wins on drain. */
static __always_inline u64 flow_machine_dsq(void)
{
	return (u64)FLOW_MACHINE;
}
/* Id of the overflow tail shared by every CPU. */
/* Missed parks plus pinned tasks rest here with mask wins on drain. */
static __always_inline u64 flow_overflow_dsq(void)
{
	return (u64)FLOW_OVERFLOW;
}
/* True when one id names a live scheduler queue. */
/* Local plus node plus machine plus overflow pass, and all other */
/* ids fail, so a stale id never moves work. */
static __always_inline bool flow_dsq_valid(u64 dsq)
{
	if (dsq >= (u64)FLOW_LOCAL_BASE &&
	    dsq < (u64)FLOW_LOCAL_BASE + (u64)FLOW_MAX_CPUS)
		return true;
	if (dsq >= (u64)FLOW_NODE_BASE &&
	    dsq < (u64)FLOW_NODE_BASE + (u64)FLOW_MAX_NODES)
		return true;
	if (dsq == (u64)FLOW_MACHINE)
		return true;
	if (dsq == (u64)FLOW_OVERFLOW)
		return true;
	return false;
}
/* Per mille share of one slice in one period with saturation. */
/* A zero period means no bound, so the share stays zero. The math */
/* scales slice times 1000 over period, so a 2ms slice in a 16ms */
/* period takes 125 per mille. */
static __always_inline u64 flow_slice_permillle(u64 period)
{
	if (!period)
		return 0;
	return (u64)FLOW_QUANTUM_NS * 1000ULL / period;
}
/* True when one CPU can admit one more per mille share. */
/* The admitted sum plus the new share must stay under the bound, so */
/* admitted work keeps idle time for late wakeups. Saturated sums */
/* fail closed, so a wrapped sum never admits. */
static __always_inline bool flow_admit_ok(u64 admitted,
	u64 share)
{
	u64 sum = admitted + share;
	if (sum < admitted)
		return false;
	return sum <= (u64)FLOW_ADMIT_PERMILLE;
}
#endif
