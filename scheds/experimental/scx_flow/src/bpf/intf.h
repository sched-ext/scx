// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler at 4.8.11.
 *
 * The scheduler keeps one local queue per CPU plus one shared queue
 * per node plus one shared queue per machine plus one value ordered
 * reject queue. Homeless work with no live CPU plus gate misses waits
 * in the reject queue by value with mask wins on drain.
 * Idle CPUs steal one task from peer locals as the fifth tier with
 * a bounded window of 4 to 8 peers proportional to remaining visits.
 * Every task earns an absolute deadline from now plus a period, and
 * each queue orders by the strict EDF key through the kernel priority
 * queue. The strict key holds the earlier of deadline plus virtual
 * deadline with a 2ms lag bound, so the earliest key always
 * runs next. Each fresh wait earns a dynamic slice from the saturated
 * remaining time clamped to 10us at the floor plus 1ms at the ceiling,
 * so near deadlines pace tightly while far deadlines still rotate each
 * millisecond. A miss holds the stored slice else floors it to 10us
 * with a fresh deadline plus a tier rejoin rederived through the same
 * escalation plus skip aging, and a zero slice inherits the 1ms
 * quantum. A global completer credit at or past 128us reclaims one
 * value ordered reject with positive laxity plus the same key or a
 * strictly after key with one bounded move, so overload drains without
 * starving the tiers. A miss counts when wall time passes the deadline, and
 * the miss rejoins a tier queue with a fresh deadline plus a direct
 * kick and no wait. Placement takes the slowest sufficient CPU among
 * the allowed set that can meet the deadline, so light work never
 * takes a fast CPU that other work needs. Hints from the flat view
 * tune the period plus the weight, and no group or pool shapes order.
 * Each stop feeds the burst predictor average plus deviation with
 * shift updates, so later deadlines track recent bursts with no table
 * walk. See select_cpu.bpf.c for placement and enqueue.bpf.c for the
 * deadline choice plus dispatch.bpf.c for the tier scans and
 * lifecycle.bpf.c for the miss count and timer.bpf.c for the leftover
 * charge plus the miss count.
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
/* Slice ceiling of 1ms with no knob. Caps the dynamic slice plus the */
/* preempt tail window plus the carryover, so one slice always spans */
/* one wakeup with no extra hold. Fresh waits clamp the saturated */
/* remaining time to this ceiling with a 10us floor. */
enum flow_consts {
	FLOW_QUANTUM_NS = 1000000ULL,
	/* Dynamic slice floor of 10us with no knob. Holds the smallest */
	/* charge that still outlasts the kick cost, so near deadlines */
	/* pace tightly with no zero slice. Misses hold else floor here, */
	/* and a zero slice inherits the ceiling. */
	FLOW_SLICE_MIN_NS = 10000ULL,
	/* Default period of 16ms with no knob. Holds sixteen slices, */
	/* so a fully used task still leaves room for one wait plus */
	/* one retry inside the period. */
	FLOW_PERIOD_NS = 16000000ULL,
	/* Predictor bounds with no knob. Holds 1ns to 1s, so a huge */
	/* burst clamps instead of wrapping to a short deadline. */
	FLOW_PRED_MIN_NS = 1ULL,
	FLOW_PRED_MAX_NS = 1000000000ULL,
	FLOW_WEIGHT_MIN = 1ULL,
	FLOW_WEIGHT_BASE = 128ULL,
	FLOW_WEIGHT_MAX = 16384ULL,
	/* CPU bound of 1024 rows with no knob. Covers the largest test */
	/* host with wide margin while keeping array memory bounded. */
	FLOW_MAX_CPUS = 1024ULL,
	/* Node bound of 16 rows with no knob. Covers the largest test */
	/* host with wide margin while keeping the node scan bounded. */
	FLOW_MAX_NODES = 16ULL,
	/* Hint bound of 8192 rows with no knob. Keys are hierarchy ids */
	/* with no dense use, so the table holds large hosts with room */
	/* for churn. Full tables fail closed to the default period */
	/* with no eviction and no stall. */
	FLOW_HINT_MAX = 8192ULL,
	/* Local queue region base. Holds 1024 ids, one per CPU. */
	FLOW_LOCAL_BASE = 0x5100ULL,
	/* Node queue region base. Holds 16 ids, one per node. */
	FLOW_NODE_BASE = 0x5900ULL,
	/* Machine queue id shared by every CPU. */
	FLOW_MACHINE = 0x5A00ULL,
	/* Overflow reject id for overload past tier order with value order. */
/* Named overflow frozen for wire compat only and it holds the value */
/* ordered reject queue drained only by reclaim, never a tier overflow. */
	FLOW_OVERFLOW = 0x5A01ULL,
	/* Queue count of 1042. Holds 1024 local plus 16 node plus one */
	/* machine plus one value ordered reject. */
	FLOW_MAX_DSQS = 1042ULL,
	/* Dispatch visit cap of 8 entries per pass with no knob. Caps */
	/* visited entries per pass shared across five tiers regardless of */
	/* moves, so one pass never holds RCU across the whole queue on */
	/* mask misses. Moves take at most one per tier per pass bounded */
	/* by remaining dispatch slots, and leftover work resumes next pass, */
	/* so the pass stays work conserving across passes. The steal window */
	/* spans 4 to 8 peers proportional to remaining visits. */
	FLOW_DISPATCH_MAX_VISIT = 8ULL,
	/* Steal peer window with no knob. Scans at least 4 peers and at */
	/* most 8 peers per pass, so the steal stays bounded with no */
	/* hotspot while large hosts still find work. */
	FLOW_STEAL_MIN_PEERS = 4ULL,
	FLOW_STEAL_MAX_PEERS = 8ULL,
	/* BSF fallback bound of 4 peers with no knob. Scans the next four */
	/* past the 8 peer SSF window from cursor plus 9, so select covers */
	/* twelve unique peers per pass with no topology walk and no overlap. */
	/* Keeps the fallback cheap while extending coverage with the same order. */
	FLOW_BSF_MAX_PEERS = 4ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	/* Base capacity of 1024 units with no knob. Every CPU on a */
	/* symmetric host offers the same units, so the slowest */
	/* sufficient pick falls to the lowest sufficient id. */
	FLOW_CAP_BASE = 1024ULL,
	/* CPU performance levels at half plus max with no knob. Any own */
	/* plus local plus running picks max else half with no shared use. */
	FLOW_CPU_PERF_HALF = 512ULL,
	FLOW_CPU_PERF_MAX = 1024ULL,
	/* Preempt leads by 100us with no knob, so near ties never bounce */
	/* while urgent gaps still preempt at once. The floor stays at */
	/* 100us with one kick per wait. */
	FLOW_PREEMPT_MARGIN_NS = 100000ULL,
	/* Preempt waits out a 100us tail with no knob, so a nearly done */
	/* owner finishes instead of taking a kick. The floor stays at */
	/* 100us with one kick per wait. */
	FLOW_PREEMPT_TAIL_NS = 100000ULL,
	/* Allowed lag bound of 2ms with no knob. Newly woken tasks clamp */
	/* within this distance of the CPU minimum, so sleepers gain no */
	/* more than one extra slice of boost with no storm. */
	FLOW_VLAG_MAX_NS = 2000000ULL,
	/* RED bound of 128us with no knob. Caps the maximum exceeding */
	/* time, so a global credit at or past this bound reclaims one */
	/* reject, and a victim cost at or below this bound keeps the */
	/* newcomer with no swap. The bound caps lateness with no share */
	/* shaping. */
	FLOW_RED_EMAX_NS = 128000ULL,
	/* RED tolerance of 64us with no knob. Holds the guarantee slack */
	/* for hard tasks only, so critical tasks keep zero tolerance */
	/* with no late run. Tolerance aids the guarantee with no order */
	/* shaping. */
	FLOW_RED_TOL_NS = 64000ULL,
	/* Adaptive grow step of 64us with no knob. Widens the slice on */
	/* a miss, so a short burst earns room with no storm. */
	/* Like fair.c, the step paces service, unlike rt.c, no fixed priority holds. */
	/* Clamps with the slice floor plus ceiling. */
	FLOW_ADAPT_GROW_NS = 64000ULL,
	/* Adaptive shrink step of 128us with no knob. Narrows the slice */
	/* on a hit, so an idle task returns room with no stall. */
	/* Like fair.c, the step tracks load, unlike rt.c, no fixed priority holds. */
	/* Clamps with the slice floor plus ceiling. */
	FLOW_ADAPT_SHRINK_NS = 128000ULL,
};
/* Static dispatch tier order with no reorder. Local plus node plus */
/* machine plus overflow plus steal drain in fair order through the */
/* kernel priority queues with the reject value ordered. Every pass follows */
/* this order with no load based swap, so the verifier sees one fixed */
/* path. Dispatch calls the tier moves directly with no index switch, */
/* so no tier index needs storage. The steal tier scans peer locals */
/* within the bounded window with mask wins. */
/* Per task state at 72B with vruntime plus deadline plus stamps plus */
/* predictor plus lag plus weight plus slice plus hint plus hint weight */
/* plus misses plus adapt miss plus adapt sat plus adapt delta. */
/* Vruntime holds the scaled service in nanos with zero for no history. */
/* A zero vruntime means no service yet, so the first virtual deadline */
/* falls near now with no boost past the lag bound. Deadline holds the */
/* absolute EDF deadline for queue order and the miss check. A zero */
/* deadline means no order yet, so preempt compares skip with no kick */
/* and the miss check skips with no count. Wait holds the last enqueue */
/* time. A zero wait means the task never queued. Every queue join */
/* stamps the task, so queued work always carries a stamp. Run holds */
/* the segment start while on CPU else zero, so a claimed start pairs */
/* the stopping charge with no BPF gauge. The on CPU gauge lives in */
/* the snapshot with no BPF count. Running claims from zero only with */
/* a compare and swap, so a second running without a stop keeps the */
/* first start with no second use. Stopping versus disable or exit */
/* claims once with atomics, so each claimed start meets exactly one */
/* charge with no owner gate. Hint weight holds the flat hint share */
/* clamped to range with 128 for neutral, stored alongside the task */
/* base so requeues plus stopping plus leftover keep the heavy share */
/* with no cache lookup and no neutral cliff. A zero means no history, */
/* so the effective helper maps it to neutral. Avg holds */
/* the burst average in nanos in 32 bits with zero for no history. Dev */
/* holds the burst deviation in nanos in 32 bits with zero for no */
/* history. Values clamp to 1ns to 1s, so a huge burst never wraps. */
/* Vlag holds the allowed lag in nanos as a signed bound with zero for */
/* no slack. Weight holds the task base share clamped to range with */
/* 128 for neutral, and the effective share stacks task times hint */
/* over 128 on the stack with no store. Slice holds the per task slice */
/* in nanos with the dynamic remaining clamp on fresh waits. A miss */
/* holds the stored slice else floors it to 10us, and a zero slice */
/* inherits the 1ms quantum with strict preempt on a fresh quantum. */
/* Hint holds the flat period */
/* hint in micros for the deadline. A zero hint means no hint, so the */
/* default period applies. Misses holds the count of deadline misses */
/* for the life of the task with saturating adds, so a huge miss count */
/* clamps instead of wrapping. Lifetime by design, so promotion latches */
/* once 8 holds with the same one-move bound. A windowed decay stays a */
/* noted alternative with no knob here. Adapt miss holds the consecutive */
/* miss streak for the adaptive slice with saturation at 0xffff, so a */
/* ragged burst widens step by step with no wrap. Adapt sat holds the */
/* clamp streak at the slice floor plus ceiling with saturation, so a */
/* stuck slice shows its bound with no extra map. Adapt delta holds the */
/* last saved execution in nanos per task for debug, while the global */
/* completer credit funds reclaim, so a completion with delta at or */
/* past 128us reclaims one reject with no scan. */
/* Like fair.c, vruntime paces order, unlike rt.c, no fixed priority holds. */
/* C holds burst else slice else quantum with no knob, and V holds */
/* weight with zero mapped to 128, so the slice adapts while virtual */
/* time stays untouched. Stamps stay per task owned with no */
/* atomics except the run claim, only counters use atomics. Cursor and */
/* miss scans stay best effort with no atomic order. */
struct flow_task_ctx {
	u64 vruntime;
	u64 deadline;
	u64 wait_at;
	u64 run_at;
	u32 hint_w;
	u32 avg_ns;
	u32 dev_ns;
	s32 vlag;
	u32 weight;
	u32 slice_ns;
	u32 hint_us;
	u32 misses;
	u16 adapt_miss;
	u16 adapt_sat;
	u32 adapt_delta;
};
/* Per CPU state at 16B with running pid plus placement cursor plus */
/* minimum vruntime. Pid holds the task now on the CPU else zero. */
/* Owner clears use a compare and swap, so a stale exit never clears a */
/* new owner. Cursor is shared by select SSF plus BSF and dispatch */
/* steal with stride two and best effort races plus no atomic order. */
/* A success advances past the picked peer, so the next pass starts */
/* fresh with no hotspot. Min vruntime tracks the smallest served */
/* vruntime on the CPU with zero for no history, so newly woken tasks */
/* clamp without gaining past the lag bound. The minimum folds forward */
/* only and holds stale on idle with the lag bound capping the boost, */
/* so no decay timer runs and rejoins stay bounded with no storm. */
struct flow_cpu_state {
	u32 running_pid;
	u32 cursor;
	u64 min_vruntime;
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
/* Flat period plus weight hint at 8B with one row per id. */
/* Period holds the period in micros with zero for no hint, and weight */
/* holds the scheduling share with 128 for neutral. The flat view tunes */
/* the period plus the weight only, and no group or pool shapes order. */
struct flow_hint {
	u32 period_us;
	u32 weight;
};
/* Scheduler counters with 17 fields. Reject plus reclaim moves count */
/* RED overload plus reclaim detail with no extra map, so stats stay at */
/* 136B. Overflow plus steal moves count in the local bucket with no new */
/* counter. Rejects plus on CPU stay frozen at zero in BPF snapshot-counted */
/* for wire compat only with no BPF writer, while real rejects count in gate */
/* plus RED rejects. Readers must use gate_rejects for drops plus red_rejects */
/* for overload, and the snapshot counts live pids for the on CPU gauge. Miss */
/* plus Term where Term equals completions stay counters only with no queues, */
/* so misses plus completions record history with no extra queue. Preempt kicks */
/* count busy preempts sent, and preempt skipped counts suppressed preempts held */
/* by margin plus tail plus eligibility. Counters run with no knob and no fixed */
/* priority. */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 inserts;
	u64 requeues;
	u64 completions;
	u64 local_moves;
	u64 node_moves;
	u64 machine_moves;
	u64 kicks;
	u64 admits;
	u64 rejects;
	u64 misses;
	u64 gate_rejects;
	u64 preempt_kicks;
	u64 preempt_skipped;
	u64 red_rejects;
	u64 red_reclaims;
};
/* Task state holds vruntime plus deadline plus stamps plus predictor */
/* plus lag plus weight plus slice plus hint plus misses plus adapt */
/* miss plus sat plus delta in 72 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 72,
	"task state stays at 72B");
/* CPU state holds pid plus cursor plus minimum vruntime in 16 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 16,
	"CPU state stays at 16B");
/* Topology view holds sibling plus node in 8 bytes. */
_Static_assert(sizeof(struct flow_topo) == 8,
	"topology view stays at 8B");
/* Stats hold 17 counters in 136 bytes. */
_Static_assert(sizeof(struct flow_sched_stats) == 136,
	"stats stay at 136B");
/* Queue count holds local plus node plus machine plus overflow. */
/* Steal reuses peer locals with no new queue, so the count stays. */
_Static_assert(FLOW_MAX_DSQS ==
	FLOW_MAX_CPUS + FLOW_MAX_NODES + 2,
	"dsq count stays local plus node plus two");
/**
 * flow_time_before - test time order with wrap safety.
 * @a: first time in nanos.
 * @b: second time in nanos.
 *
 * The signed diff keeps order across the u64 wrap with no branch.
 *
 * Outlined with noinline to keep verifier headroom on the select plus
 * drain paths with no order change, so SSF plus BSF share one copy.
 *
 * Returns: true when @a falls before @b, else false.
 */
static __noinline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/**
 * flow_sat_add - add two times with clamp on wrap.
 * @a: first addend in nanos.
 * @b: second addend in nanos.
 *
 * A wrap clamps to max, so a huge sum never falls to the front.
 *
 * Returns: saturated sum of @a plus @b.
 */
static __always_inline u64 flow_sat_add(u64 a,
	u64 b)
{
	u64 out = a + b;
	if (out < a)
		return (u64)~0ULL;
	return out;
}
/**
 * flow_weight_clamp - clamp one share into range.
 * @w: raw share with zero for no history.
 *
 * Zero maps to 1, so an explicit zero earns the lightest share while
 * missing state stays neutral via the effective helper. Oversize
 * shares fail closed to the top bound.
 *
 * Returns: clamped share from 1 to 16384.
 */
static __always_inline u32 flow_weight_clamp(u32 w)
{
	if (w < (u32)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (w > (u32)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return w;
}
/**
 * flow_share_combine - combine two shares into one effective share.
 * @task_w: task base share, clamped to range.
 * @hint_w: hint share, clamped to range.
 *
 * Multiplies the shares then shifts right by 7 for divide by 128,
 * so the neutral pair of 128 plus 128 stays neutral with no divide.
 * A small product clamps to the floor, and a large product clamps
 * to the top with no wrap.
 *
 * Returns: effective share from 1 to 16384.
 */
static __always_inline u32 flow_share_combine(u32 task_w,
	u32 hint_w)
{
	u32 t = flow_weight_clamp(task_w);
	u32 h = flow_weight_clamp(hint_w);
	u64 prod = (u64)t * (u64)h;
	u64 eff = prod >> 7;
	if (eff < (u64)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (eff > (u64)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return (u32)eff;
}
/**
 * flow_task_effective_weight - effective share of one task plus hint.
 * @task_w: task base share with zero for neutral.
 * @hint_w: hint share with zero for neutral.
 *
 * Maps each zero input to the neutral share of 128, then combines
 * with the shared helper, so missing state stays neutral with no
 * special case at the caller.
 *
 * Returns: effective share from 1 to 16384.
 */
static __always_inline u32 flow_task_effective_weight(u32 task_w,
	u32 hint_w)
{
	u32 t = task_w ? task_w : (u32)FLOW_WEIGHT_BASE;
	u32 h = hint_w ? hint_w : (u32)FLOW_WEIGHT_BASE;
	return flow_share_combine(t, h);
}
/**
 * flow_scaled_delta - scaled service for one delta at one weight.
 * @delta: raw service in nanos.
 * @weight: scheduling share, clamped to range.
 *
 * Scales inversely with weight through one divide, so the neutral
 * weight of 128 keeps the delta unchanged while lighter tasks grow
 * and heavier tasks shrink with no band jump. Mirrors the fair
 * scaler in weight.bpf.c with saturation and a floor of one.
 *
 * Returns: scaled service in nanos.
 */
static __always_inline u64 flow_scaled_delta(u64 delta,
	u32 weight)
{
	u32 w = flow_weight_clamp(weight);
	u64 prod;
	u64 out;
	if (delta == 0)
		return 0;
	/* Clamp never returns zero, so no zero guard is needed here. */
	if (delta > (u64)~0ULL / (u64)FLOW_WEIGHT_BASE)
		return (u64)~0ULL;
	prod = delta * (u64)FLOW_WEIGHT_BASE;
	out = prod / (u64)w;
	if (out == 0)
		return 1;
	return out;
}
/**
 * flow_vruntime_advance - advance vruntime by one delta at one weight.
 * @vruntime: base vruntime in nanos.
 * @delta: raw service in nanos.
 * @weight: scheduling share, clamped to range.
 *
 * Adds the scaled service to the base, so heavy tasks advance slowly
 * while light tasks advance quickly with one divide. A wrap clamps to
 * max, so a huge vruntime never falls to the front.
 *
 * Returns: advanced vruntime in nanos.
 */
static __always_inline u64 flow_vruntime_advance(u64 vruntime,
	u64 delta, u32 weight)
{
	return flow_sat_add(vruntime, flow_scaled_delta(delta, weight));
}
/**
 * flow_lag_clamp - clamp lag within the allowed bound.
 * @lag: raw lag in nanos as a signed bound.
 *
 * Values past plus or minus 2ms fold to the nearer bound with
 * saturation, so a stale lag never grants a huge boost with no storm.
 *
 * Returns: clamped lag from minus 2ms to 2ms.
 */
static __always_inline s32 flow_lag_clamp(s32 lag)
{
	s32 bound = (s32)FLOW_VLAG_MAX_NS;
	if (lag > bound)
		return bound;
	if (lag < -bound)
		return -bound;
	return lag;
}
/**
 * flow_eligible - test vruntime eligibility against the CPU minimum.
 * @vruntime: task vruntime in nanos.
 * @min_vruntime: CPU minimum vruntime in nanos.
 * @vlag: allowed lag in nanos as a signed bound.
 *
 * Eligible means the vruntime falls no more than the allowed lag past
 * the minimum, so lagging tasks wait while leading tasks pace. A negative
 * lag clamps to zero with no boost, so a negative bound never grants slack.
 * The signed diff keeps order across the u64 wrap with no branch, and a
 * saturated minimum plus lag never wraps to the front.
 *
 * Returns: true when eligible, else false.
 */
static __always_inline bool flow_eligible(u64 vruntime,
	u64 min_vruntime, s32 vlag)
{
	s32 lag = flow_lag_clamp(vlag);
	u64 limit;
	if (lag < 0)
		lag = 0;
	limit = flow_sat_add(min_vruntime, (u64)lag);
	if (limit == (u64)~0ULL)
		return true;
	if (vruntime == limit)
		return true;
	return flow_time_before(vruntime, limit);
}
/**
 * flow_virt_deadline - virtual deadline from base plus request.
 * @ve: eligible base in nanos.
 * @request: requested service in nanos.
 * @weight: scheduling share, clamped to range.
 *
 * Adds the scaled request to the eligible base with saturation, so a
 * heavy task earns a near deadline while a light task earns a far one
 * with one divide. A wrap clamps to max, so a huge sum never jumps to
 * the front.
 *
 * Returns: virtual deadline in nanos.
 */
static __always_inline u64 flow_virt_deadline(u64 ve,
	u64 request, u32 weight)
{
	return flow_sat_add(ve, flow_scaled_delta(request, weight));
}
/**
 * flow_fair_vtime - fair queue key from deadline plus virtual time.
 * @deadline: absolute EDF deadline in nanos, zero for no order.
 * @vd: virtual deadline in nanos, zero for no order.
 *
 * The EDF deadline caps latency while the virtual deadline paces
 * fairness, so urgent tasks still win while hogs fall behind. A zero
 * deadline means no EDF order yet, so the virtual deadline rules. The
 * signed diff picks the earlier time with wrap safety. Kept alongside
 * flow_edf_key as the same strict key by design and this name serves fair
 * voice while the alias serves EDF voice with one shared copy.
 *
 * Returns: earlier of @deadline plus @vd in nanos.
 */
static __always_inline u64 flow_fair_vtime(u64 deadline,
	u64 vd)
{
	if (deadline == 0)
		return vd;
	if (vd == 0)
		return deadline;
	if (flow_time_before(vd, deadline))
		return vd;
	return deadline;
}
/**
 * flow_edf_key - strict EDF sort key from deadline plus virtual time.
 * @deadline: absolute EDF deadline in nanos, zero for no order.
 * @vd: virtual deadline in nanos, zero for no order.
 *
 * The strict key is the earlier of the two times with wrap safety,
 * so the closest deadline always wins with no band jump. Intentional
 * alias of flow_fair_vtime kept for EDF voice with one shared copy
 * plus no extra verifier cost and sort-key callers use this name while
 * fair-time callers use the other with the same result.
 *
 * Returns: earlier of @deadline plus @vd in nanos.
 */
static __always_inline u64 flow_edf_key(u64 deadline,
	u64 vd)
{
	return flow_fair_vtime(deadline, vd);
}
/**
 * flow_remaining_ns - saturated time left until the deadline.
 * @deadline: absolute EDF deadline in nanos, zero for no order.
 * @now: current time in nanos.
 *
 * Feeds the dynamic slice plus slack display only, never the sort key,
 * so the order stays the strict earlier of deadline plus virtual time.
 * A zero deadline means no order yet, and a past deadline means no
 * time left, so both read zero with no wrap.
 *
 * Returns: saturated remaining time in nanos.
 */
static __always_inline u64 flow_remaining_ns(u64 deadline,
	u64 now)
{
	if (deadline == 0)
		return 0;
	if (flow_time_before(now, deadline))
		return deadline - now;
	return 0;
}
/**
 * flow_slice_for - dynamic slice from the saturated remaining time.
 * @deadline: absolute EDF deadline in nanos.
 * @now: current time in nanos.
 *
 * Clamps the remaining time to the 10us floor plus the 1ms ceiling
 * with no knob, so near deadlines pace tightly while far deadlines
 * still rotate each millisecond. A zero plus a past deadline floors
 * to 10us with no zero slice.
 *
 * Returns: dynamic slice in nanos from 10us to 1ms.
 */
static __always_inline u32 flow_slice_for(u64 deadline,
	u64 now)
{
	u64 rem = flow_remaining_ns(deadline, now);
	if (rem < (u64)FLOW_SLICE_MIN_NS)
		return (u32)FLOW_SLICE_MIN_NS;
	if (rem > (u64)FLOW_QUANTUM_NS)
		return (u32)FLOW_QUANTUM_NS;
	return (u32)rem;
}
/**
 * flow_slice_inherit - slice default for zero stored state.
 * @cur: stored slice in nanos, zero for no history.
 *
 * A zero slice means no history, so the 1ms quantum applies with no
 * extra write at the caller.
 *
 * Returns: @cur else the 1ms quantum.
 */
static __always_inline u32 flow_slice_inherit(u32 cur)
{
	if (cur == 0)
		return (u32)FLOW_QUANTUM_NS;
	return cur;
}
/**
 * flow_slice_miss_hold - miss slice with hold else floor only.
 * @cur: stored slice in nanos, zero for no history.
 *
 * A miss never recomputes the dynamic slice, so the miss path holds
 * the stored charge else floors it to 10us with no zero slice and no
 * knob. The fresh deadline plus the re-derived tier rejoin carry the
 * urgency with skip aging in the miss count. Pinned plus open miss
 * paths share this helper, so the two holds never skew.
 *
 * Returns: held slice else the 10us floor.
 */
static __always_inline u32 flow_slice_miss_hold(u32 cur)
{
	u32 s = flow_slice_inherit(cur);
	if (s < (u32)FLOW_SLICE_MIN_NS)
		return (u32)FLOW_SLICE_MIN_NS;
	return s;
}
/**
 * flow_red_cost - worst cost from burst else slice else quantum.
 * @avg: burst average in nanos, zero for no history.
 * @slice: stored slice in nanos, zero for no history.
 *
 * The cost bounds the guarantee with no share shaping. A burst average wins when present, else the stored slice,
 * else the 1ms quantum, so C tracks recent runs with no table walk.
 *
 * Returns: cost in nanos from 10us to 1ms.
 */
static __always_inline u64 flow_red_cost(u64 avg, u32 slice)
{
	if (avg) {
		if (avg < (u64)FLOW_SLICE_MIN_NS)
			return (u64)FLOW_SLICE_MIN_NS;
		if (avg > (u64)FLOW_QUANTUM_NS)
			return (u64)FLOW_QUANTUM_NS;
		return avg;
	}
	if (slice) {
		if ((u64)slice < (u64)FLOW_SLICE_MIN_NS)
			return (u64)FLOW_SLICE_MIN_NS;
		if ((u64)slice > (u64)FLOW_QUANTUM_NS)
			return (u64)FLOW_QUANTUM_NS;
		return (u64)slice;
	}
	return (u64)FLOW_QUANTUM_NS;
}
/**
 * flow_red_tol - guarantee tolerance for one task.
 * @is_crit: true when latency critical with no tolerance.
 *
 * Tolerance aids the guarantee only with no order shaping. Critical tasks keep zero, hard tasks
 * keep 64us, so the check stays strict for urgent work.
 *
 * Returns: tolerance in nanos, zero for critical.
 */
static __always_inline u64 flow_red_tol(bool is_crit)
{
	if (is_crit)
		return 0;
	return (u64)FLOW_RED_TOL_NS;
}
/**
 * flow_red_residual - residual time from deadline plus cost.
 * @deadline: absolute deadline in nanos, zero means no order.
 * @now: current time in nanos.
 * @cost: remaining worst cost in nanos.
 *
 * The residual tests the guarantee with no vruntime shaping. A zero deadline means no order, so the check
 * passes with a large residual. A past deadline yields a negative
 * residual with wrap safety.
 *
 * Returns: signed residual in nanos.
 */
static __always_inline s64 flow_red_residual(u64 deadline, u64 now,
	u64 cost)
{
	s64 left;
	if (deadline == 0)
		return (s64)FLOW_PRED_MAX_NS;
	if (flow_time_before(now, deadline))
		left = (s64)(deadline - now);
	else if (now == deadline)
		left = 0;
	else
		left = -((s64)(now - deadline));
	left -= (s64)cost;
	return left;
}
/**
 * flow_red_exceed - exceeding time from residual plus tolerance.
 * @resid: signed residual in nanos.
 * @tol: guarantee tolerance in nanos, zero for critical.
 *
 * The exceed marks lateness with no share shaping. A residual plus tolerance at or past zero means no
 * exceed, else the negated sum bounds the needed reclaim.
 *
 * Returns: exceeding time in nanos, zero when schedulable.
 */
static __always_inline u64 flow_red_exceed(s64 resid, u64 tol)
{
	s64 sum = resid + (s64)tol;
	if (sum >= 0)
		return 0;
	return (u64)(-sum);
}
/**
 * flow_red_value - admission value from weight plus critical.
 * @weight: task base share, zero maps to 128.
 * @is_crit: true marks critical with maximum value.
 *
 * Value orders the reject queue with no vruntime shaping. Critical tasks hold the top value with no reject, hard
 * tasks hold the clamped base share, so the greatest value reclaims
 * first with no storm.
 *
 * Returns: value from 1 to 16384, top for critical.
 */
static __always_inline u32 flow_red_value(u32 weight, bool is_crit)
{
	if (is_crit)
		return (u32)FLOW_WEIGHT_MAX;
	if (weight == 0)
		weight = (u32)FLOW_WEIGHT_BASE;
	return flow_weight_clamp(weight);
}
/**
 * flow_red_laxity - laxity from deadline plus cost.
 * @deadline: absolute deadline in nanos, zero means no order.
 * @now: current time in nanos.
 * @cost: remaining worst cost in nanos.
 *
 * Laxity gates reclaim with no vruntime shaping. A zero deadline means no order with zero laxity, a past
 * deadline means no laxity, else the saturated remainder holds.
 *
 * Returns: laxity in nanos, zero when none.
 */
static __always_inline u64 flow_red_laxity(u64 deadline, u64 now,
	u64 cost)
{
	u64 rem;
	if (deadline == 0)
		return 0;
	if (!flow_time_before(now, deadline) && now != deadline)
		return 0;
	rem = deadline - now;
	if (rem < cost)
		return 0;
	return rem - cost;
}
/**
 * flow_reject_key - reject queue key from value.
 * @value: admission value from 1 to 16384.
 *
 * Orders the reject queue by decreasing value through the kernel
 * priority queue, so the greatest value drains first on reclaim. A
 * larger value maps to a smaller key with no wrap.
 *
 * Returns: queue key in nanos.
 */
static __always_inline u64 flow_reject_key(u32 value)
{
	u32 v = flow_weight_clamp(value);
	return (u64)((u32)FLOW_WEIGHT_MAX - v);
}
/**
 * flow_adapt_up - widen the slice by 64us with clamp.
 * @cur: stored slice in nanos, zero inherits the quantum.
 *
 * Like fair.c, the step paces service, unlike rt.c, no fixed priority
 * holds. Adds 64us with saturation, then clamps to 10us plus 1ms,
 * so a miss earns room with no wrap. Virtual time stays untouched.
 *
 * Returns: adapted slice in nanos from 10us to 1ms.
 */
static __always_inline u32 flow_adapt_up(u32 cur)
{
	u64 s = (u64)flow_slice_inherit(cur);
	s = flow_sat_add(s, (u64)FLOW_ADAPT_GROW_NS);
	if (s < (u64)FLOW_SLICE_MIN_NS)
		return (u32)FLOW_SLICE_MIN_NS;
	if (s > (u64)FLOW_QUANTUM_NS)
		return (u32)FLOW_QUANTUM_NS;
	return (u32)s;
}
/**
 * flow_adapt_down - narrow the slice by 128us with clamp.
 * @cur: stored slice in nanos, zero inherits the quantum.
 *
 * Like fair.c, the step tracks load, unlike rt.c, no fixed priority
 * holds. Subtracts 128us with floor at 10us, then clamps to 1ms, so
 * a hit returns room with no stall. Virtual time stays untouched.
 *
 * Returns: adapted slice in nanos from 10us to 1ms.
 */
static __always_inline u32 flow_adapt_down(u32 cur)
{
	u64 s = (u64)flow_slice_inherit(cur);
	if (s <= (u64)FLOW_ADAPT_SHRINK_NS)
		return (u32)FLOW_SLICE_MIN_NS;
	s -= (u64)FLOW_ADAPT_SHRINK_NS;
	if (s < (u64)FLOW_SLICE_MIN_NS)
		return (u32)FLOW_SLICE_MIN_NS;
	if (s > (u64)FLOW_QUANTUM_NS)
		return (u32)FLOW_QUANTUM_NS;
	return (u32)s;
}
/**
 * flow_carry_for - carryover slice from unused quantum with clamp.
 * @delta: raw service in nanos of the yielding slice.
 *
 * Keeps the unused quantum remainder with clamp to 10us plus 1ms
 * through the adapt bounds, so a tiny remainder never floors below
 * the slice minimum with no zero slice. Callers gate on runnable plus
 * short plus latency-critical plus no wall miss, so only short bursts
 * carry with no virtual change.
 *
 * Returns: carry slice in nanos from 10us to 1ms.
 */
static __always_inline u32 flow_carry_for(u64 delta)
{
	u64 q = (u64)FLOW_QUANTUM_NS;
	u64 c;
	if (delta >= q)
		return (u32)FLOW_SLICE_MIN_NS;
	c = q - delta;
	if (c < (u64)FLOW_SLICE_MIN_NS)
		return (u32)FLOW_SLICE_MIN_NS;
	if (c > q)
		return (u32)FLOW_QUANTUM_NS;
	return (u32)c;
}
/**
 * flow_deadline_at - absolute deadline from now plus period.
 * @now: current time in nanos.
 * @period: relative period in nanos.
 *
 * The add saturates, so a huge now clamps instead of wrapping to
 * the front.
 *
 * Returns: absolute deadline in nanos.
 */
static __always_inline u64 flow_deadline_at(u64 now,
	u64 period)
{
	return flow_sat_add(now, period);
}
/**
 * flow_task_period - period for one task from hint else default.
 * @hint_us: flat period hint in micros, zero for no hint.
 *
 * A zero hint means no hint, so the default period of 16ms applies.
 * The hint converts from micros to nanos with saturation, so a huge
 * hint clamps instead of wrapping to a short period.
 *
 * Returns: period in nanos.
 */
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
/**
 * flow_pred_clamp - clamp predictor value to 1ns to 1s.
 * @v: raw value in nanos.
 *
 * Values below the floor rise to 1ns and values past the top fall
 * to 1s, so a huge burst never wraps to a short deadline.
 *
 * Returns: clamped value in nanos.
 */
static __always_inline u64 flow_pred_clamp(u64 v)
{
	if (v < (u64)FLOW_PRED_MIN_NS)
		return (u64)FLOW_PRED_MIN_NS;
	if (v > (u64)FLOW_PRED_MAX_NS)
		return (u64)FLOW_PRED_MAX_NS;
	return v;
}
/**
 * flow_pred_avg - updated burst average with shift 3.
 * @avg: old average in nanos, zero for no history.
 * @delta: new sample in nanos.
 *
 * A zero average means no history, so the first sample sets the
 * average at once. Later samples move one eighth toward the new
 * delta with shifts only, so the verifier keeps no divide. The
 * result clamps to 1ns to 1s, so a spike never wraps.
 *
 * Returns: updated average in nanos.
 */
static __always_inline u64 flow_pred_avg(u64 avg,
	u64 delta)
{
	u64 d;
	u64 diff;
	d = flow_pred_clamp(delta ? delta :
	    (u64)FLOW_PRED_MIN_NS);
	if (avg == 0)
		return d;
	if (d > avg) {
		diff = (d - avg) >> 3;
		return flow_pred_clamp(flow_sat_add(avg,
		    diff));
	}
	diff = (avg - d) >> 3;
	if (diff > avg)
		return (u64)FLOW_PRED_MIN_NS;
	return flow_pred_clamp(avg - diff);
}
/**
 * flow_pred_dev - updated burst deviation with shift 2.
 * @dev: old deviation in nanos, zero for no history.
 * @avg: new average in nanos from flow_pred_avg, zero for no history.
 * @delta: new sample in nanos.
 *
 * Tracks the absolute error between delta and the new average with
 * one quarter steps, so a stable burst keeps a small margin while a
 * ragged burst widens the deadline with no jump. Callers pass the new
 * average from flow_pred_avg, so the margin tracks the fresh mean. A
 * zero deviation means no history, so the first value takes the max of
 * error and new average quarter as the floor. The result clamps the
 * same way with no divide and shifts stay at 2.
 *
 * Returns: updated deviation in nanos.
 */
static __always_inline u64 flow_pred_dev(u64 dev,
	u64 avg, u64 delta)
{
	u64 d;
	u64 a;
	u64 err;
	u64 diff;
	u64 floor;
	d = flow_pred_clamp(delta ? delta :
	    (u64)FLOW_PRED_MIN_NS);
	a = avg ? avg : d;
	err = d > a ? d - a : a - d;
	err = flow_pred_clamp(err ? err :
	    (u64)FLOW_PRED_MIN_NS);
	if (dev == 0) {
		floor = avg >> 2;
		if (floor > err)
			return flow_pred_clamp(floor);
		return err;
	}
	if (err > dev) {
		diff = (err - dev) >> 2;
		return flow_pred_clamp(flow_sat_add(dev,
		    diff));
	}
	diff = (dev - err) >> 2;
	if (diff > dev)
		return (u64)FLOW_PRED_MIN_NS;
	return flow_pred_clamp(dev - diff);
}
/**
 * flow_pred_period - predicted period from average plus deviation.
 * @avg: burst average in nanos, zero for no history.
 * @dev: burst deviation in nanos.
 *
 * A zero average means no history, so the default period of 16ms
 * applies. Later periods add average plus deviation with saturation,
 * so a stable burst keeps a tight deadline while a ragged burst holds
 * margin with no wrap past 1s.
 *
 * Returns: predicted period in nanos.
 */
static __always_inline u64 flow_pred_period(u64 avg,
	u64 dev)
{
	u64 sum;
	if (avg == 0)
		return (u64)FLOW_PERIOD_NS;
	sum = flow_sat_add(avg, dev);
	if (sum == (u64)~0ULL)
		return (u64)FLOW_PRED_MAX_NS;
	return flow_pred_clamp(sum);
}
/**
 * flow_pred_deadline - predicted deadline from now plus predictor.
 * @now: current time in nanos.
 * @avg: burst average in nanos, zero for no history.
 * @dev: burst deviation in nanos.
 * @hint_us: flat period hint in micros, zero for no hint.
 *
 * A zero average means no history, so the hint period applies with
 * the default of 16ms when the hint is zero. Later wakeups add the
 * predicted period with saturation, so a huge now clamps instead of
 * wrapping to the front. Fair order via kernel priority queue holds
 * the earlier of this deadline plus the virtual deadline, so the
 * earliest fair time wins with lag bounds.
 *
 * Returns: absolute deadline in nanos.
 */
static __always_inline u64 flow_pred_deadline(u64 now,
	u64 avg, u64 dev, u32 hint_us)
{
	u64 period;
	if (avg == 0)
		period = flow_task_period(hint_us);
	else
		period = flow_pred_period(avg, dev);
	return flow_deadline_at(now, period);
}
/**
 * flow_lat_crit - test latency-critical from predictor slack.
 * @avg: burst average in nanos, zero for no history.
 * @dev: burst deviation in nanos.
 *
 * A zero average means no history, so the task counts as latency
 * critical with no stall. Later tasks add average plus deviation with
 * saturation, so a short predicted burst within one quantum stays
 * critical while a long burst paces at slice expiry. Uses the quantum
 * with no new map plus no new queue plus no knob.
 *
 * Returns: true when latency-critical, else false.
 */
static __always_inline bool flow_lat_crit(u64 avg,
	u64 dev)
{
	u64 pred;
	if (avg == 0)
		return true;
	pred = flow_sat_add(avg, dev);
	if (pred == (u64)~0ULL)
		return false;
	return pred <= (u64)FLOW_QUANTUM_NS;
}
/**
 * flow_fallback_deadline - fallback deadline from now plus hint.
 * @now: current time in nanos.
 * @hint_us: flat period hint in micros, zero for no hint.
 *
 * Tasks with no state or no history join a tier queue at once with
 * this deadline, so no path needs a tail queue with no wait.
 *
 * Returns: absolute deadline in nanos.
 */
static __always_inline u64 flow_fallback_deadline(u64 now,
	u32 hint_us)
{
	return flow_deadline_at(now, flow_task_period(hint_us));
}
/**
 * flow_missed - test deadline miss at the given time.
 * @deadline: absolute deadline in nanos, zero for no order.
 * @now: current time in nanos.
 *
 * A zero deadline means no order yet, so the check skips. A time that
 * falls before or on the deadline passes, so only a strictly later
 * time counts a miss with wrap safety.
 *
 * Returns: true when missed, else false.
 */
static __always_inline bool flow_missed(u64 deadline,
	u64 now)
{
	if (deadline == 0)
		return false;
	if (flow_time_before(now, deadline))
		return false;
	if (now == deadline)
		return false;
	return true;
}
/**
 * flow_local_dsq - local queue id of one CPU.
 * @cpu: CPU id below the 1024 bound.
 *
 * One ordered queue per CPU keeps fair order local.
 *
 * Returns: local queue id.
 */
static __always_inline u64 flow_local_dsq(u32 cpu)
{
	return (u64)FLOW_LOCAL_BASE + (u64)cpu;
}
/**
 * flow_node_dsq - shared queue id of one node.
 * @node: node id below the 16 bound.
 *
 * One ordered queue per node shares work inside the node.
 *
 * Returns: node queue id.
 */
static __always_inline u64 flow_node_dsq(u32 node)
{
	return (u64)FLOW_NODE_BASE + (u64)node;
}
/**
 * flow_machine_dsq - id of the machine queue.
 *
 * Work with no node home rests here with mask wins on drain.
 *
 * Returns: machine queue id shared by every CPU.
 */
static __always_inline u64 flow_machine_dsq(void)
{
	return (u64)FLOW_MACHINE;
}
/**
 * flow_overflow_dsq - id of the value ordered reject queue.
 *
 * Bursts past tier order wait here by value with mask wins.
 *
 * Returns: overflow queue id shared by every CPU.
 */
static __always_inline u64 flow_overflow_dsq(void)
{
	return (u64)FLOW_OVERFLOW;
}
/**
 * flow_dsq_valid - test live scheduler queue id.
 * @dsq: queue id to test.
 *
 * Local plus node plus machine plus overflow pass, and all other ids
 * fail, so a stale id never moves work. Sparse nodes fold to machine
 * at the caller with no panic, so holes in the node view stay safe.
 * The kernel global queue never passes for wire compat with homeless
 * work in machine.
 *
 * Returns: true when live, else false.
 */
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
/**
 * flow_is_pow2 - test power of two with no divide.
 * @n: value to test.
 *
 * Zero never counts as a power of two, so the mask path never
 * runs on an empty host with no divide by zero.
 *
 * Returns: true when @n holds exactly one bit, else false.
 */
static __always_inline bool flow_is_pow2(u64 n)
{
	return n != 0 && (n & (n - 1ULL)) == 0;
}
/**
 * flow_wrap_idx - wrap base into 0 to n minus 1 with pow2 fast path.
 * @base: unwrapped index stock plus offset.
 * @n: host count above one and within the 1024 bound.
 *
 * Powers of two mask with base and n minus 1, so the hot
 * 16 CPU path skips the modulo divide with the same order.
 * Other hosts fall back to modulo with the same result and
 * no extra branch past the power check. Callers guard n above
 * one, so a zero or one host never divides by zero here.
 *
 * Returns: wrapped index below @n.
 */
static __always_inline u32 flow_wrap_idx(u64 base, u32 n)
{
	if (n == 0)
		return 0;
	if (flow_is_pow2((u64)n))
		return (u32)(base & ((u64)n - 1ULL));
	return (u32)(base % (u64)n);
}
#endif
