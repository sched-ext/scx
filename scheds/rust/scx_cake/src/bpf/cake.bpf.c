/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake — a clean-slate sched_ext scheduler.
 *
 * One release algorithm, eight callbacks, built on kernel primitives. Release
 * defaults use no task-history model, runtime telemetry, attributes, or
 * division; compile-time research variants are kept out of the default path.
 * One immutable loader-filled map describes real SMT siblings. Scheduling
 * policy itself remains state-derived. See DESIGN.md for rationale.
 *
 * Model of operation
 * ------------------
 *   - Placement starts with one kfunc, scx_bpf_select_cpu_dfl(). It computes
 *     the saturation tiers we want (idle full core, then idle SMT sibling,
 *     then "saturated") while preserving prev-CPU cache warmth, WAKE_SYNC,
 *     and LLC locality. When it hands back an idle CPU we normally
 *     direct-dispatch; a sparse WAKE_SYNC/qmark/exact-head guard declines the
 *     shortcut if it would jump an older per-CPU vtime claim. Otherwise the
 *     task falls through to ops.enqueue().
 *   - Under saturation a task queues on the vtime DSQ of the CPU the kernel
 *     validated for it (dsq_id == task_cpu): the insert happens under that
 *     CPU's already-held rq lock, so the queue lock is contended only by its
 *     owner and occasional stealers — never the degree-nr_cpus global rbtree
 *     that serialized 3M wakes/s. Slice-expiry requeues resolve on their own
 *     CPU (L1/L2 stays warm); an idle CPU pulls work via a staggered ring
 *     steal in dispatch, so nothing strands. Work-conservation is enforced by
 *     kicking one claimed-idle CPU per insert (custom DSQs have no auto-kick;
 *     an idle *owner* is already resched'd by core's activate→wakeup_preempt
 *     under the same rq-lock hold, so no insert kick is needed for it).
 *   - Under low load a CPU whose queue is empty keeps its current task running
 *     (slice refill), cutting per-quantum reprocessing. Contention preempts it
 *     instantly via SCX_KICK_PREEMPT.
 *   - Fairness is a single dsq_vtime advanced by a reciprocal-weight table
 *     (no division on the hot path); per-CPU run-start stamps give correct
 *     wall-time charge across keep-running rounds.
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#include <scx/common.bpf.h>
#include "intf.h"

_Static_assert((MAX_CPUS & (MAX_CPUS - 1)) == 0,
	       "MAX_CPUS must remain a power of two");
_Static_assert((RECIP_TABLE_SIZE & (RECIP_TABLE_SIZE - 1)) == 0,
	       "reciprocal table must remain mask-indexable");
_Static_assert(HOME_PREEMPT_YOUNG_NS < HOME_PREEMPT_BASE_MARGIN_NS,
	       "young-current window must fit inside the base margin");
_Static_assert(CAKE_NR_CPUS <= MAX_CPUS,
	       "build-host CPU span must fit Cake MAX_CPUS");

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Compile-time enum immediates. enums.autogen.bpf.h #defines each SCX_* name
 * onto a loader-filled `const volatile u64 __SCX_*` — a rodata memory load on
 * every hot-path use. #undef the five names cake uses and rebind them to
 * bpf_core_enum_value(), which CO-RE resolves to a load-time immediate
 * (precedent: compat.bpf.h uses this mechanism on scx_enq_flags).
 *
 * The #undef is PERMANENT — deliberately no push/pop: macro bodies expand at
 * the use site, so a pop would silently rebind the enumerator names back to
 * the volatile shadows inside every CAKE_* expansion. Must sit after all scx
 * header includes; cake never uses the SCX_* macro forms below this point.
 */
#undef SCX_DSQ_LOCAL
#undef SCX_DSQ_LOCAL_ON
#undef SCX_ENQ_WAKEUP
#undef SCX_KICK_IDLE
#undef SCX_KICK_PREEMPT
#undef SCX_TASK_QUEUED
#undef SCX_WAKE_SYNC
#define CAKE_DSQ_LOCAL    bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL)
#define CAKE_DSQ_LOCAL_ON bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL_ON)
#define CAKE_ENQ_WAKEUP   bpf_core_enum_value(enum scx_enq_flags,    SCX_ENQ_WAKEUP)
#define CAKE_KICK_IDLE    bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_IDLE)
#define CAKE_KICK_PREEMPT bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_PREEMPT)
#define CAKE_TASK_QUEUED  bpf_core_enum_value(enum scx_ent_flags,    SCX_TASK_QUEUED)
#define CAKE_WAKE_SYNC    bpf_core_enum_value(enum scx_wake_flags,   SCX_WAKE_SYNC)

/*
 * task_struct::policy's SCHED_* values are plain uapi macros, not a BTF enum
 * (bpf_core_enum_value has nothing to hook here) -- guarded local defines,
 * same convention scx_pandemonium already uses for this exact check.
 */
#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif
#ifndef SCHED_RR
#define SCHED_RR   2
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

/*
 * All mutable hot state in ONE BSS struct built from 128-byte-stride slots.
 * This replaces the former
 * __attribute__((aligned(64))) uses with pure layout: any two accessed words
 * are >= 128 bytes apart in offset, so regardless of the struct's base
 * alignment their 64B line indexes differ by >= 2 — never the same cache
 * line, and never the same adjacent-line-prefetcher 128B pair.
 */
struct cake_slot {
	u64 word;
	u64 pad[STATE_SLOT_WORDS - 1];
};

struct cake_run_slot {
	u64 stamp;
	u64 sum;
#if CAKE_MDBLS_STAGE > 0
	u32 remaining_ns;
	u8 confidence;
	u8 pad8[3];
	u64 pad[STATE_SLOT_WORDS - 3];
#else
	u64 pad[STATE_SLOT_WORDS - 2];
#endif
};

#if CAKE_MDBLS_STAGE > 0
/*
 * Compact activation model. Nanosecond estimates saturate at u32 (4.29s),
 * far beyond Cake's one-horizon decision bound. Dyadic EWMAs keep the update
 * path division-free; confidence becomes authoritative only after two full
 * activation/period observations and saturates after eight.
 */
struct cake_task_ctx {
	u64 last_runnable_ns;
	u64 activation_start_sum;
	u32 burst_ns;
	u32 period_ns;
	u16 samples;
	u8 confidence;
	u8 flags;
};

enum cake_task_flags {
	CAKE_HAS_BURST = 1U << 0,
	CAKE_HAS_PERIOD = 1U << 1,
};

_Static_assert(sizeof(struct cake_task_ctx) == 32,
	       "M-DBLS task state must stay compact");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_task_ctx);
} cake_task_stor SEC(".maps");
#endif

#if CAKE_MDBLS_TELEMETRY
#define MDBLS_HIST_BINS 8
struct cake_mdbls_stats {
	u64 runnable;
	u64 quiescent;
	u64 prediction_samples;
	u64 confident_samples;
	u64 burst_ns_sum;
	u64 period_ns_sum;
	u64 error_ns_sum;
	u64 preempt_eval;
	u64 preempt_cold;
	u64 golden_preempt;
	u64 learned_preempt;
	u64 learned_only;
	u64 golden_only;
	u64 slice_eval;
	u64 slice_cold;
	u64 slice_short;
	u64 slice_base;
	u64 slice_long;
	u64 burst_hist[MDBLS_HIST_BINS];
	u64 error_hist[MDBLS_HIST_BINS];
	u64 pressure_hist[MDBLS_HIST_BINS];
	u64 confidence_hist[MDBLS_HIST_BINS];
	u64 slice_hist[MDBLS_HIST_BINS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cake_mdbls_stats);
} mdbls_stats SEC(".maps");
#endif

#if CAKE_IRQ_SHADOW_MODE > 0
/*
 * I0 IRQ-capacity observer. Each callback CPU writes its own per-CPU shard,
 * keyed by the CPU Cake already selected, so observation needs no atomics and
 * cannot create a shared writer line. Modes 1 (cost control) and 2 (observer)
 * compile this exact BPF path; only detach-time userspace interpretation
 * differs. Mode 0 removes the map, helper, calls, and argument evaluation.
 */
struct cake_irq_shadow_stats {
	u64 samples;
	u64 dfl_idle_samples;
	u64 direct_dispatch_samples;
	u64 enqueue_samples;
	u64 wake_sync_samples;
	u64 clock_unavailable_samples;
	u64 sibling_unavailable_samples;
	u64 first_wall_ns;
	u64 last_wall_ns;
	u64 first_target_irq_ns;
	u64 last_target_irq_ns;
	u64 first_sibling_irq_ns;
	u64 last_sibling_irq_ns;
	u64 sibling_cpu;
};

_Static_assert(sizeof(struct cake_irq_shadow_stats) == 14 * sizeof(u64),
	       "IRQ shadow ABI must remain fixed-width");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, struct cake_irq_shadow_stats);
} irq_shadow_stats SEC(".maps");
#endif

#if CAKE_QMARK_MODE == 0
struct cake_qmark_slot {
	u64 word;
#if CAKE_QMARK_SLOT_BYTES > 8
	u64 pad[CAKE_QMARK_SLOT_BYTES / sizeof(u64) - 1];
#endif
};
_Static_assert(CAKE_QMARK_SLOT_BYTES >= sizeof(u64) &&
	       CAKE_QMARK_SLOT_BYTES % sizeof(u64) == 0,
	       "qmark slot must be an integral number of u64 words");
_Static_assert(sizeof(struct cake_qmark_slot) == CAKE_QMARK_SLOT_BYTES,
	       "qmark slot must match its compile-time stride");
#endif

_Static_assert(sizeof(struct cake_slot) == STATE_SLOT_BYTES,
		       "cake_slot must preserve cache-isolation stride");
_Static_assert(sizeof(struct cake_run_slot) == STATE_SLOT_BYTES,
		       "cake_run_slot must preserve cache-isolation stride");

struct cake_state {
	/*
	 * .word = global vtime frontier. Written by all CPUs in running()
	 * (conditional store), read in enqueue/enable. The sleeper clamp
	 * against it is load-bearing for futex handoff.
	 */
	struct cake_slot frontier;
	/*
	 * .word = nr_cpu_ids, written ONCE in ops.init and read-only after —
	 * its own slot so frontier RFOs never dirty the line the steal loop
	 * reads.
	 */
	struct cake_slot ncpu;
	/*
	 * Per-CPU run accounting. stamp is read remotely only by saturated wake
	 * preemption; sum is owner-only and holds the sum_exec_runtime snapshot
	 * taken in running(). Keeping both lifecycle-coupled values in one isolated
	 * slot makes running() dirty one cache line instead of two while preserving
	 * the 128-byte inter-CPU stride.
	 *
	 * ops.stopping charges used = p->se.sum_exec_runtime - this, with
	 * ZERO clock reads: the kernel calls update_curr_scx() immediately
	 * before invoking ops.stopping (both call sites, verified in the
	 * tree), so sum_exec is boundary-exact there — unlike mid-slice
	 * remote reads, which stay on the ktime stamp above for
	 * eligibility.
	 */
	struct cake_run_slot run[MAX_CPUS];
	/*
	 * .word = "DSQ[i] may hold work" hint gating the steal ring.
	 * bpfstats: a going-idle dispatch spent 199ns/call — 30% of the
	 * whole pipe benchmark — walking 15+ EMPTY queues through hashed
	 * kfuncs. Stealers now read these (cached, shared) lines and hash
	 * only marked queues. Set by enqueue BEFORE its insert; the owner
	 * clears it before peeking its own head and re-marks if the peek
	 * hits, so an insert can never be hidden by a concurrent clear.
	 * Races are benign by construction: a stale mark costs one wasted
	 * move attempt, a missed mark delays only THEFT — the owner serves
	 * its own queue on every dispatch regardless, and the existing
	 * activate/kick guarantees that owners dispatch are untouched.
	 */
#if CAKE_QMARK_MODE == 0
	struct cake_qmark_slot qmark[MAX_CPUS];
#elif CAKE_QMARK_MODE == 1
	u8 qmark[MAX_CPUS];
#elif CAKE_QMARK_MODE == 2
	u64 qmark[(MAX_CPUS + 63) / 64];
#elif CAKE_QMARK_MODE != 3
#error "unknown CAKE_QMARK_MODE"
#endif
	/*
	 * .word = "curr was preempt-kicked" — set beside every
	 * CAKE_KICK_PREEMPT, read-and-cleared by the victim CPU's next
	 * continuation enqueue. A preempt-requeue (handoff spinner) must
	 * never overflow: its partner is here. Owner-cleared, one-shot
	 * benign races like qmark.
	 */
	struct cake_slot pmark[MAX_CPUS];
};

static struct cake_state cake;

#if CAKE_MDBLS_TELEMETRY
static __always_inline struct cake_mdbls_stats *cake_mdbls_stats(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&mdbls_stats, &key);
}

/* Log-spaced nanosecond bins: <=1us, 4us, 16us, 64us, 256us, 1ms, 4ms, >4ms. */
static __always_inline u32 cake_mdbls_time_bin(u64 ns)
{
	if (ns <= 1000)
		return 0;
	if (ns <= 4000)
		return 1;
	if (ns <= 16000)
		return 2;
	if (ns <= 64000)
		return 3;
	if (ns <= 256000)
		return 4;
	if (ns <= 1000000)
		return 5;
	if (ns <= 4000000)
		return 6;
	return 7;
}

static __always_inline u32 cake_mdbls_q8_bin(u64 value)
{
	return value >= 224 ? 7 : (u32)(value >> 5);
}
#endif

#if CAKE_MDBLS_STAGE > 0
static __always_inline struct cake_task_ctx *cake_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&cake_task_stor, p, 0, 0);
}

static __always_inline u32 cake_u32_sat(u64 value)
{
	return value > (u64)~0U ? ~0U : (u32)value;
}

static __always_inline u32 cake_ewma4(u32 old, u32 sample)
{
	if (!old)
		return sample;
	if (sample > old)
		return old + ((sample - old) >> 2);
	return old - ((old - sample) >> 2);
}

#if CAKE_MDBLS_STAGE >= 2
static __always_inline u32 cake_horizon(u32 value)
{
	return value > SLICE_NS ? SLICE_NS : value;
}

static __always_inline u32 cake_remaining(const struct cake_task_ctx *tctx,
					  const struct task_struct *p)
{
	u64 attained = p->se.sum_exec_runtime - tctx->activation_start_sum;

	return tctx->burst_ns > attained ?
	       cake_horizon(tctx->burst_ns - (u32)attained) : 0;
}
#endif
#endif

static __always_inline void cake_qmark_set(u32 cpu)
{
	cpu &= MAX_CPUS - 1;
#if CAKE_QMARK_MODE == 0
	cake.qmark[cpu].word = 1;
#elif CAKE_QMARK_MODE == 1
	cake.qmark[cpu] = 1;
#elif CAKE_QMARK_MODE == 2
	__sync_fetch_and_or(&cake.qmark[cpu >> 6], 1ULL << (cpu & 63));
#endif
}

static __always_inline void cake_qmark_clear(u32 cpu)
{
	cpu &= MAX_CPUS - 1;
#if CAKE_QMARK_MODE == 0
	cake.qmark[cpu].word = 0;
#elif CAKE_QMARK_MODE == 1
	cake.qmark[cpu] = 0;
#elif CAKE_QMARK_MODE == 2
	__sync_fetch_and_and(&cake.qmark[cpu >> 6], ~(1ULL << (cpu & 63)));
#endif
}

static __always_inline bool cake_qmark_test(u32 cpu)
{
	cpu &= MAX_CPUS - 1;
#if CAKE_QMARK_MODE == 0
	return cake.qmark[cpu].word;
#elif CAKE_QMARK_MODE == 1
	return cake.qmark[cpu];
#elif CAKE_QMARK_MODE == 2
	return cake.qmark[cpu >> 6] & (1ULL << (cpu & 63));
#else
	return true;
#endif
}

/*
 * Immutable host topology populated by the Rust loader before BPF load. This
 * is read only on the global-wake idle-kick fallback, not on select_cpu's
 * direct-dispatch path. -1 means the CPU has no online SMT sibling.
 */
const volatile s32 cpu_sibling[MAX_CPUS];

#if CAKE_IRQ_SHADOW_MODE > 0
static __always_inline void
cake_irq_shadow_record(s32 cpu, bool is_idle, bool direct_dispatch,
		       u64 wake_flags)
{
	struct cake_irq_shadow_stats *stats;
	u64 wall_ns, target_irq_ns = 0, sibling_irq_ns = 0;
	bool clock_available;
	s32 sibling;
	u32 target;

	if (cpu < 0 || (u32)cpu >= MAX_CPUS || (u64)(u32)cpu >= cake.ncpu.word)
		return;
	target = (u32)cpu;
	stats = bpf_map_lookup_elem(&irq_shadow_stats, &target);
	if (!stats)
		return;

	wall_ns = bpf_ktime_get_ns();
	clock_available = bpf_core_type_exists(struct irqtime___local) &&
			  bpf_ksym_exists(&cpu_irqtime);
	if (clock_available)
		target_irq_ns = scx_clock_irq(target);
	else
		stats->clock_unavailable_samples++;

	sibling = cpu_sibling[target];
	if (sibling >= 0 && (u32)sibling < MAX_CPUS &&
	    (u64)(u32)sibling < cake.ncpu.word) {
		if (clock_available)
			sibling_irq_ns = scx_clock_irq((u32)sibling);
	} else {
		stats->sibling_unavailable_samples++;
		sibling = -1;
	}

	if (!stats->samples) {
		stats->first_wall_ns = wall_ns;
		stats->first_target_irq_ns = target_irq_ns;
		stats->first_sibling_irq_ns = sibling_irq_ns;
		stats->sibling_cpu = sibling < 0 ? ~0ULL : (u64)(u32)sibling;
	}
	stats->samples++;
	stats->dfl_idle_samples += is_idle;
	stats->direct_dispatch_samples += direct_dispatch;
	stats->enqueue_samples += !direct_dispatch;
	stats->wake_sync_samples += !!(wake_flags & CAKE_WAKE_SYNC);
	stats->last_wall_ns = wall_ns;
	stats->last_target_irq_ns = target_irq_ns;
	stats->last_sibling_irq_ns = sibling_irq_ns;
}

#define cake_irq_shadow_observe(cpu, is_idle, direct_dispatch, wake_flags) \
	cake_irq_shadow_record(cpu, is_idle, direct_dispatch, wake_flags)
#else
#define cake_irq_shadow_observe(cpu, is_idle, direct_dispatch, wake_flags) \
	do { } while (0)
#endif

#if CAKE_NR_CCDS > 1
/* Loader-sorted: same CCD, same cache-capacity tier, then unrestricted. */
const volatile u16 cpu_steal_order[CAKE_NR_CPUS * CAKE_NR_CPUS];
#endif

/*
 * Reciprocal-weight table for division-free vtime charging.
 *
 *   recip_weight[i] = (1024 << 20) / sched_prio_to_weight[i]
 *
 * so that `used * recip_weight[i] >> 20 == used * 1024 / weight`, i.e. the
 * EEVDF charge that advances a nice-0 task's vtime by exactly `used` and a
 * heavier (negative-nice) task's vtime proportionally slower.
 *
 * Indexed by `nice + 20 == static_prio - 100 ∈ [0, 39]`. SCHED_IDLE has
 * the kernel's distinct raw weight 3 at IDLE_RECIP_INDEX; static_prio alone
 * cannot identify it. The table is sized to 64 (a power of 2) so the index
 * masks cleanly; entries [41, 63] are padded with the lightest nice weight.
 */
static const u64 recip_weight[RECIP_TABLE_SIZE] = {
	   12097,    14964,    19009,    23204,    29587, /* nice -20..-16 */
	   36830,    46174,    57404,    71827,    90109, /* nice -15..-11 */
	  112457,   140911,   176023,   218952,   274895, /* nice -10..-6  */
	  344037,   429324,   539297,   677012,   840831, /* nice  -5..-1  */
	 1048576,  1309441,  1639300,  2041334,  2538396, /* nice  +0..+4  */
	 3205199,  3947580,  4994148,  6242685,  7837531, /* nice  +5..+9  */
	 9761289, 12341860, 15339168, 19173961, 23860929, /* nice +10..+14 */
	29826161, 37025580, 46684427, 59652323, 71582788, /* nice +15..+19 */
	/* SCHED_IDLE raw weight 3, then padding [41..63] at nice +19. */
	357913941, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
};

#define CAKE_RECIP_RUNTIME_FAST_MAX (~0ULL / (u64)MAX_RECIP_WEIGHT)

static __noinline u64 cake_scale_vtime_slow(u64 runtime, u64 reciprocal)
{
	return (runtime >> RECIP_SHIFT) * reciprocal +
	       ((runtime & RECIP_MASK) * reciprocal >> RECIP_SHIFT);
}

/* Share the compatibility fallback instead of expanding it at every peek. */
#if !CAKE_SCALAR_PEEK
static __noinline struct task_struct *cake_dsq_peek(u64 dsq_id)
{
	return __COMPAT_scx_bpf_dsq_peek(dsq_id);
}
#endif

#if CAKE_SCALAR_PEEK
static __noinline bool cake_dsq_head_vtime(u64 dsq_id, u64 *vtime)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(dsq_id);

	if (!p)
		return false;
	*vtime = p->scx.dsq_vtime;
	return true;
}
#endif

/*
 * Return runtime scaled by the task's reciprocal weight without allowing the
 * full-width `runtime * reciprocal` intermediate to wrap. Splitting runtime at
 * the fixed-point radix is algebraically identical:
 *
 *   (runtime * reciprocal) >> shift
 *     = (runtime >> shift) * reciprocal
 *       + ((runtime & mask) * reciprocal >> shift)
 *
 * For normal scheduler intervals the result is bit-for-bit identical to the
 * old expression. The high product remains safe for more than eight years of
 * uninterrupted nice-19 runtime, far beyond the runnable-stall watchdog.
 */
static __always_inline u64 cake_scale_vtime(u64 runtime, u32 idx)
{
	u64 reciprocal = recip_weight[idx & RECIP_INDEX_MASK];

	/* Every ordinary slice takes the original single-multiply fast path. */
	if (runtime <= CAKE_RECIP_RUNTIME_FAST_MAX)
		return (runtime * reciprocal) >> RECIP_SHIFT;

	return cake_scale_vtime_slow(runtime, reciprocal);
}

/* Preserve the exact 40-level nice table while honoring SCHED_IDLE weight 3. */
static __always_inline u32 cake_recip_index(const struct task_struct *p)
{
	if (p->policy == SCHED_IDLE)
		return IDLE_RECIP_INDEX;
	return (u32)(p->static_prio - STATIC_PRIO_BASE);
}

#if CAKE_MDBLS_STAGE >= 2 && CAKE_MDBLS_PREEMPT
/*
 * M-DBLS wake balance, expressed entirely in one-slice bounded integers.
 * Fair debt is the waiter's lag behind the frontier. Learned slack risk fades
 * as local pressure rises; current completion value does the same. A cold
 * waiter preserves the exact Golden gate passed in by the caller.
 */
static __always_inline bool cake_mdbls_preempt(struct task_struct *p, s32 tcpu,
					       u64 waiter_vtime, u64 live,
					       u64 ran, u64 pressure,
					       bool golden)
{
	struct cake_task_ctx *waiter = cake_task_ctx(p);
	struct cake_run_slot *run = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	u64 debt = 0, remaining, projected, slack, miss, learned;
	u64 wait_risk, finish, cost;
	bool decision;
#if CAKE_MDBLS_TELEMETRY
	struct cake_mdbls_stats *stats = cake_mdbls_stats();

	if (stats) {
		stats->preempt_eval++;
		stats->golden_preempt += golden;
		stats->pressure_hist[cake_mdbls_q8_bin(pressure)]++;
	}
#endif

	if (!waiter || waiter->confidence < (MDBLS_CONF_STEP * 2) ||
	    !(waiter->flags & CAKE_HAS_PERIOD)) {
#if CAKE_MDBLS_TELEMETRY
		if (stats)
			stats->preempt_cold++;
#endif
		return golden;
	}
	if (!time_before(waiter_vtime, live))
		return false;

	if (time_before(waiter_vtime, cake.frontier.word)) {
		debt = cake.frontier.word - waiter_vtime;
		if (debt > SLICE_NS)
			debt = SLICE_NS;
	}

	remaining = run->remaining_ns > ran ? run->remaining_ns - ran : 0;
	projected = remaining + MDBLS_SWITCH_COST_NS;
	if (projected > SLICE_NS)
		projected = SLICE_NS;
	slack = waiter->period_ns > waiter->burst_ns ?
		waiter->period_ns - waiter->burst_ns : 0;
	if (slack > SLICE_NS)
		slack = SLICE_NS;
	miss = projected > slack ? projected - slack : 0;
	if (pressure > MDBLS_CONF_MAX)
		pressure = MDBLS_CONF_MAX;
	learned = ((u64)waiter->confidence * miss *
		   (MDBLS_CONF_MAX - pressure)) >> 16;
	wait_risk = debt + learned;
	if (wait_risk > SLICE_NS)
		wait_risk = SLICE_NS;
	finish = ((u64)run->confidence * remaining *
		  (MDBLS_CONF_MAX - pressure)) >> 16;
	cost = finish + MDBLS_SWITCH_COST_NS;
	decision = wait_risk > cost;
#if CAKE_MDBLS_TELEMETRY
	if (stats) {
		stats->learned_preempt += decision;
		stats->learned_only += decision && !golden;
		stats->golden_only += golden && !decision;
		stats->confidence_hist[cake_mdbls_q8_bin(waiter->confidence)]++;
	}
#endif
	return decision;
}
#endif

#if CAKE_MDBLS_STAGE >= 3
/* Reconsider sooner under waiter pressure, later only for confident remainder. */
static __always_inline u64 cake_mdbls_slice(struct task_struct *p, u64 nq)
{
	struct cake_task_ctx *tctx = cake_task_ctx(p);
	u64 pressure, remaining, finish, slice;
#if CAKE_MDBLS_TELEMETRY
	struct cake_mdbls_stats *stats = cake_mdbls_stats();

	if (stats)
		stats->slice_eval++;
#endif

	if (!tctx || tctx->confidence < (MDBLS_CONF_STEP * 2) ||
	    !(tctx->flags & CAKE_HAS_BURST)) {
#if CAKE_MDBLS_TELEMETRY
		if (stats)
			stats->slice_cold++;
#endif
		return nq ? CONTENDED_SLICE_NS : SLICE_NS;
	}

	pressure = nq << 6;
	if (pressure > MDBLS_CONF_MAX)
		pressure = MDBLS_CONF_MAX;
	remaining = cake_remaining(tctx, p);
	finish = ((u64)tctx->confidence * remaining *
		  (MDBLS_CONF_MAX - pressure)) >> 16;
	slice = SLICE_NS + finish;
	slice -= ((u64)MDBLS_MIN_SLICE_NS * pressure) >> 8;
	if (slice < MDBLS_MIN_SLICE_NS)
		slice = MDBLS_MIN_SLICE_NS;
	if (slice > MDBLS_MAX_SLICE_NS)
		slice = MDBLS_MAX_SLICE_NS;
#if CAKE_MDBLS_TELEMETRY
	if (stats) {
		stats->slice_short += slice < SLICE_NS;
		stats->slice_base += slice == SLICE_NS;
		stats->slice_long += slice > SLICE_NS;
		stats->slice_hist[cake_mdbls_time_bin(slice)]++;
		stats->pressure_hist[cake_mdbls_q8_bin(pressure)]++;
		stats->confidence_hist[cake_mdbls_q8_bin(tctx->confidence)]++;
	}
#endif
	return slice;
}
#endif

/*
 * Live wake preemption (EEVDF update_curr + preempt_sync analogue). With
 * per-CPU queues a woken task can only run on its home CPU, so a stale
 * comparison strands it behind the whole 1ms slice of whatever runs there:
 * curr's dsq_vtime is charged only at stopping, so mid-slice it looks
 * eternally deserving and a full-slice margin never fired — futex collapsed
 * 20-50x on the per-CPU topology (2026-07-01). Charge curr's in-flight
 * runtime from its own run-start stamp (the exact stopping() math) so the
 * comparison is against its TRUE vtime. This helper serves only GLOBAL
 * wakes (the home path preempts inline, floor-less — that half is the
 * futex handoff). Here curr's first SLICE_NS/8 stays protected:
 * the wakee sits in the global queue, not on this CPU, so a floor-less
 * kick is pure churn — dropping the floor cost futex 4.78M -> 3.51M
 * while moving schbench p99 not at all (bisected both directions,
 * 2026-07-04). A zero curr_vtime means a higher class (RT/DL) or the
 * idle task, which we can't or needn't preempt this way.
 *
 * The remote read of the owner's stamp slot is the one cross-CPU touch of
 * that line, confined to saturated wakeups; the owner rewrites it once per
 * context switch.
 */
static __always_inline bool cake_wake_preempt(struct task_struct *p, s32 tcpu)
{
	struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(tcpu);
	u64 curr_vtime, ran, live;
	u32 cidx;
	bool preempt;

	if (!curr)
		return false;
	curr_vtime = curr->scx.dsq_vtime;
	if (!curr_vtime)
		return false;

	ran = bpf_ktime_get_ns() - cake.run[(u32)tcpu & (MAX_CPUS - 1)].stamp;
	cidx = cake_recip_index(curr);
	live = curr_vtime + cake_scale_vtime(ran, cidx);
	preempt = ran >= GLOBAL_PREEMPT_PROTECT_NS &&
		  time_before(p->scx.dsq_vtime, live);
#if CAKE_MDBLS_STAGE >= 2 && CAKE_MDBLS_PREEMPT
	if (ran >= GLOBAL_PREEMPT_PROTECT_NS) {
		u64 pressure = scx_bpf_dsq_nr_queued((u64)WAKE_DSQ) << 6;
		bool learned_preempt;

		learned_preempt = cake_mdbls_preempt(p, tcpu, p->scx.dsq_vtime,
						      live, ran, pressure, preempt);
#if CAKE_MDBLS_PREEMPT == 1
		preempt = learned_preempt;
#else
		(void)learned_preempt;
#endif
	}
#endif
	if (!preempt)
		return false;

	scx_bpf_kick_cpu(tcpu, CAKE_KICK_PREEMPT);
	return true;
}

/*
 * Compute-occupant wake preemption (mutation M, 2026-07-19; N4b evidence).
 * Under contention, 1.4% of global wakes wait out full occupant slices —
 * latencies quantized at exactly 3.0-4.0 ms and 4.5-5.0 ms (the two slice
 * lengths) — and serialized handoff chains multiply those stalls into the
 * Rc futex collapse (−60..−82%). The regimes separate by pure state: a
 * wake-herd peer NEVER accumulates ran >= SLICE/2 (it blocks within
 * microseconds), while external compute mid-slice always does. Preempting
 * only such occupants is therefore structurally inert in the quiet-storm
 * regime that falsified the unconditional neighbor probe (−27%), and
 * serves the stranded wake in exactly the case EEVDF does.
 */
static __always_inline bool cake_wake_preempt_compute(struct task_struct *p,
						      s32 tcpu)
{
	struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(tcpu);
	u64 curr_vtime, ran, live;
	u32 cidx;

	if (!curr)
		return false;
	curr_vtime = curr->scx.dsq_vtime;
	if (!curr_vtime)
		return false;
	ran = bpf_ktime_get_ns() - cake.run[(u32)tcpu & (MAX_CPUS - 1)].stamp;
	if (ran < SLICE_NS / 2)
		return false;
	cidx = cake_recip_index(curr);
	live = curr_vtime + cake_scale_vtime(ran, cidx);
	if (!time_before(p->scx.dsq_vtime, live))
		return false;
	scx_bpf_kick_cpu(tcpu, CAKE_KICK_PREEMPT);
	return true;
}

/*
 * S1 — cadence-proportional sleeper depth (2026-07-19, graph node S1).
 * The uniform clamp floor quantizes every sleeper to one key (law N2), so a
 * 100 us audio burst and a full-slice compute wake tie and serve FIFO — the
 * audio-under-compile defect and the Rc schbench deepening. Deepen the floor
 * proportionally to the task's unused slice fraction (dose set below):
 * burst ~ slice keeps exactly today's floor (compute unchanged, implicit
 * demotion), short-burst cadence tasks earn extra depth (promotion), bounded
 * so the peer hysteresis (2 slices) still dominates a fresh storm wake's
 * maximum deficit. Burst estimate: sum_exec >> log2(nvcsw) — within 2x
 * of the true mean, no division, six branch-free conditional shifts.
 */
static __always_inline u32 cake_log2_u64(u64 v)
{
	u32 r = 0;

	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8)  { v >>= 8;  r += 8; }
	if (v >> 4)  { v >>= 4;  r += 4; }
	if (v >> 2)  { v >>= 2;  r += 2; }
	r += (u32)(v >> 1);
	return r;
}

static __always_inline u64 cake_cadence_depth(const struct task_struct *p)
{
	u64 burst = p->se.sum_exec_runtime >>
		    cake_log2_u64(p->nvcsw | 1);

	if (burst >= SLICE_NS)
		return 0;
	/*
	 * S1d dose (2026-07-20): three quarters of the unused slice fraction.
	 * The 2026-07-20 bracket measured futex monotone in depth (/8 -16%,
	 * /4 +12%, /2 +39%) with schbench-light/pipe/lock-pi flat, so take the
	 * deepest dose that keeps the peer hysteresis (2 slices) strictly
	 * dominant: max depth 0.75 slice -> fresh storm deficit ~1.75 slice.
	 */
	return ((SLICE_NS - burst) >> 1) + ((SLICE_NS - burst) >> 2);
}

/*
 * ops.select_cpu — placement plus guarded direct admission.
 *
 * If select_cpu_dfl found an idle CPU (full idle core, else idle SMT sibling)
 * we normally direct-dispatch to the local DSQ for lowest latency and let the
 * kernel auto-reschedule. A WAKE_SYNC/qmark/exact-head guard can decline that
 * shortcut to preserve an older visible claim. Otherwise the system is
 * saturated on this task's affinity: return the selected CPU and let
 * ops.enqueue() arbitrate on vtime.
 */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		/*
		 * Distrust dfl's WAKE_SYNC waker-affinity return. The kfunc
		 * reports is_idle=true for ANY successful pick — including
		 * "wake @p to the local DSQ of the waker", which returns the
		 * waker's still-BUSY CPU and only requires that idle capacity
		 * exist somewhere (kernel idle.c). Direct-dispatching there is
		 * a one-way door into co-location for buffered streams: the
		 * wakee's prev aliases the waker's CPU forever after, every
		 * message pays a context-switch round trip, and the pair never
		 * re-splits. Measured 2026-07-10: pipe welded 196K ops/s at
		 * 5.09 us/op vs native's split-parallel 1.28M at 0.78 us/op —
		 * the buffer is exactly what makes parallelism profitable.
		 * Redirect to the idle capacity dfl itself just proved exists;
		 * a genuinely serial handoff converges back on the next wake
		 * (its partner's prev is then genuinely idle). Under real
		 * saturation pick_idle fails and the wakee queues behind the
		 * about-to-sleep waker — the EEVDF serial-handoff shape.
		 * Futex and schbench wakes carry no WAKE_SYNC.
		 */
		if ((wake_flags & CAKE_WAKE_SYNC) &&
		    cpu == (s32)bpf_get_smp_processor_id()) {
			s32 idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

			if (idle >= 0)
				cpu = idle;
		}

		/*
		 * Ordered direct admission. WAKE_SYNC is the kernel's explicit
		 * handoff hint, while qmark is only a cheap indication that the
		 * finalized target's custom vtime DSQ may contain an older claim.
		 * Confirm it with one lockless head snapshot and duplicate enqueue's
		 * exact sleeper clamp before deciding whether terminal direct dispatch
		 * would jump that claim. Returning without an insert deliberately falls
		 * through to ordinary enqueue; stale qmarks and ties keep today's fast
		 * path. The snapshot is advisory, not a reservation.
		 */
		if ((wake_flags & CAKE_WAKE_SYNC) &&
		    cake_qmark_test((u32)cpu)) {
			u64 head_vtime = 0;
			bool has_head = false;

#if CAKE_SCALAR_PEEK
			has_head = cake_dsq_head_vtime((u64)(u32)cpu,
						   &head_vtime);
#else
			{
				struct task_struct *head;

				head = cake_dsq_peek((u64)(u32)cpu);
				if (head) {
					head_vtime = head->scx.dsq_vtime;
					has_head = true;
				}
			}
#endif

			if (has_head) {
				u64 lo = cake.frontier.word - SLICE_NS;
				u64 d = p->scx.dsq_vtime - lo;
				u64 wake_vtime;

				wake_vtime = lo + (d & ~((u64)((s64)d >> 63)));
				if (time_before(head_vtime, wake_vtime)) {
					cake_irq_shadow_observe(cpu, is_idle, false,
								wake_flags);
					return cpu;
				}
			}
		}
		scx_bpf_dsq_insert(p, CAKE_DSQ_LOCAL, SLICE_NS, 0);
		cake_irq_shadow_observe(cpu, is_idle, true, wake_flags);
		return cpu;
	}

	/*
	 * Saturated handoff convergence. select_cpu runs in the wake path before
	 * an optional queued activation, so the callback CPU is the waker CPU.
	 * Its queue state is authoritative: if both queues are empty, returning it
	 * cannot jump queued work and lets enqueue perform the ordinary vtime
	 * insert. Process identity is deliberately irrelevant.
	 */
	{
		s32 waker_cpu = (s32)bpf_get_smp_processor_id();

		if (bpf_cpumask_test_cpu(waker_cpu, p->cpus_ptr) &&
		    !scx_bpf_dsq_nr_queued(CAKE_DSQ_LOCAL_ON | (u32)waker_cpu) &&
		    !scx_bpf_dsq_nr_queued((u64)(u32)waker_cpu)) {
			/*
			 * WAKE_SYNC is an explicit handoff signal. Converge on the empty
			 * callback CPU, but do not direct-dispatch with LOCAL_ON: that
			 * would force a preempt and bypass live-vtime eligibility.
			 */
			if (wake_flags & CAKE_WAKE_SYNC) {
				cake_irq_shadow_observe(waker_cpu, is_idle, false,
							wake_flags);
				return waker_cpu;
			}

			/*
			 * A plain wake has no handoff promise. Converge only a wakee whose
			 * raw vtime proves it slept behind the frontier, matching the
			 * sleeper class used by enqueue. A frontier-running compute peer
			 * keeps dfl's prev placement and cache warmth. This wakee-only
			 * state rule remains valid in queued callback context and is
			 * process-agnostic.
			 */
			if (time_before(p->scx.dsq_vtime + SLEEPER_LAG_NS,
					cake.frontier.word)) {
				cake_irq_shadow_observe(waker_cpu, is_idle, false,
							wake_flags);
				return waker_cpu;
			}
		}
	}

	cake_irq_shadow_observe(cpu, is_idle, false, wake_flags);
	return cpu;
}

/*
 * ops.enqueue — reached when no idle CPU was claimed or guarded direct
 * admission found an older visible per-CPU claim.
 *
 * Insert into the OWNER's vtime queue: dsq_id == task_cpu. task_cpu is
 * post-core-validation and always in p->cpus_ptr (pinned tasks that skipped
 * select_cpu included), and ops.enqueue runs holding that CPU's rq lock, so
 * either the owner scans its own DSQ after this insert, or core's
 * activate→wakeup_preempt rescheds it out of idle for us — no insert kick is
 * needed for the owner. On a same-CPU futex handoff the insert and consume
 * both happen under this CPU's own rq lock: EEVDF's in-place shape.
 *
 * Then keep the rest of the machine work-conserving: if any eligible CPU is
 * idle, kick it (pick CLAIMS the idle bit, so concurrent wakers fan out to
 * distinct CPUs; under saturation this is a read-only scan of an all-zero
 * mask — zero atomics); else, on a wakeup, preempt the target CPU if the
 * task running there is a full slice less deserving (later vtime).
 *
 * Callee-saved across kfuncs: p, enq_flags, tcpu — no spills. Recompute over
 * hold: the kernel writes the clamped vtime back into p->scx.dsq_vtime inside
 * the insert, so the preempt margin reloads it from p rather than holding vt
 * live across three kfunc calls.
 */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
	/*
	 * task_cpu(p), read directly: the kfunc body is one CO-RE-able load
	 * (READ_ONCE(task_thread_info(p)->cpu); THREAD_INFO_IN_TASK is
	 * unconditional on x86-64), so calling it paid a full kfunc
	 * call-clobber — r1-r5 dead, tcpu spilled to stack and reloaded
	 * around every later kfunc — on the hottest enqueue path for one
	 * 4-byte load. p is already verified PTR_TO_BTF_ID here.
	 */
	s32 tcpu = (s32)p->thread_info.cpu;
	u64 lo, d, vt;
	s32 idle;

	/*
	 * Sleeper clamp max(own, frontier - one slice): branchless and
	 * wrap-safe under time_before() semantics —
	 *   d = own - lo; own >= lo => (s64)d >= 0 => mask = ~0 => lo + d = own
	 *                 own <  lo => (s64)d <  0 => mask =  0 => lo + 0 = lo
	 */
	lo = cake.frontier.word - SLICE_NS;
	d  = p->scx.dsq_vtime - lo;
	vt = lo + (d & ~((u64)((s64)d >> 63)));

	/*
	 * A permanently pinned kernel thread has exactly one place where forward
	 * progress is possible. Give its wake episode directly to that CPU's local
	 * DSQ instead of making essential softirq/workqueue service wait behind the
	 * shared wake/own arbitration. Only the wake takes this path: a runnable
	 * continuation returns through the normal weighted-vtime queue below.
	 */
	/*
	 * Extended 2026-07-19 from pinned-only to ALL kthread wakes (P0):
	 * the kernel's scx watchdog rides UNBOUND kworkers, and under a futex
	 * storm those queued as ordinary herd citizens — wake->run p99 17 ms /
	 * max 192 ms measured — accumulating past the 5 s check-in and getting
	 * cake evicted. Kernel-infrastructure service is bounded by one
	 * occupant slice on the selected CPU instead of herd order. PF_KTHREAD
	 * is scheduling state, not workload identity.
	 */
	if ((enq_flags & CAKE_ENQ_WAKEUP) && (p->flags & PF_KTHREAD)) {
		scx_bpf_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)tcpu,
				   SLICE_NS, enq_flags);
		return;
	}

	/*
	 * Wakeups are global, continuations are local. A woken task must be
	 * findable by the FIRST CPU that blocks anywhere — pinning it to one
	 * home CPU's queue strands handoff chains behind a stranger's slice
	 * (futex 20-50x, 2026-07-01); a slice-expired task wants exactly its
	 * home CPU for L1/L2 warmth (the schbench p99 requeue band). The
	 * routing key is the enqueue's own wakeup bit: one algorithm, no
	 * state, no detector.
	 *
	 * EXCEPT single-CPU tasks: the global queue exists so that ANY
	 * blocking CPU can pick the wakee up, and for nr_cpus_allowed == 1
	 * that premise is false — only tcpu may run it, and a pinned wake
	 * stranded in WAKE_DSQ ate the 5s runnable-stall watchdog
	 * (stress-ng-futex, 2026-07-02). Pinned user tasks and kernel-thread
	 * continuations use their owner's vtime queue; pinned kernel-thread
	 * wakes take the direct local safety path above. Every other CPU's
	 * WAKE consume therefore avoids tasks it can never run.
	 */
	/*
	 * Empty-home carve-out (EEVDF's futex shape), sleeper-gated on BOTH
	 * ends. Futex wakes carry no WF_SYNC, so EEVDF's futex locality is
	 * prev-CPU stickiness PLUS floor-less eligibility preemption —
	 * measured 2026-07-02, each half alone loses: wake-global = flow
	 * without locality, home routing alone = locality without flow. A
	 * wake whose own CPU's queue is empty queues at home when either
	 *
	 *   - the wake is LOCAL (this CPU waking onto itself: curr is the
	 *     waker — the converged-pair signature; the raw-vtime test
	 *     flaps for it because the clamp rewrites the wakee to exactly
	 *     frontier - SLICE every insert), or
	 *   - the WAKEE is a sleeper (raw vtime more than half a slice
	 *     behind the frontier — the handoff shape: it accrues nothing
	 *     between wakes), or
	 *   - the CURR there is a valve (live vtime a full slice behind —
	 *     a low-duty dispatcher about to block; the wakee just waits it
	 *     out, no preempt or kick needed).
	 *
	 * When NEITHER holds, wakee and curr are frontier-running compute
	 * peers, and homing the wakee builds a trap: cake has no periodic
	 * balancer, so two workers sharing one CPU mutually preempt forever
	 * while other CPUs run one worker each — every affected schbench
	 * request stretched exactly 2x (p99 9072us == 2 x p50 4648us vs
	 * native 5832us, 2026-07-04). Peer wakes go to the global queue
	 * where the FIRST CPU to block anywhere picks them up — stateless
	 * rotation, the very musical-chairs EEVDF gets from blocked-load
	 * wake_affine. A congested home always falls back to the global
	 * queue (the pure per-CPU 20-50x collapse), and an RT/idle-owned
	 * home (curr_vtime 0) does too rather than queue behind a class we
	 * cannot preempt. Pinned tasks never reach this path.
	 */
	if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1) {
		struct task_struct *curr;

		/* S1: cadence-deep floor for wakes; see cake_cadence_depth. */
		{
			u64 lo2 = lo - cake_cadence_depth(p);
			u64 d2 = p->scx.dsq_vtime - lo2;

			vt = (lo2 + (d2 & ~((u64)((s64)d2 >> 63)))) & ~0ULL;
		}
		u64 live = 0, ran = 0;
		bool home = false;

		/*
		 * Queued activation may execute enqueue on the home CPU after
		 * select_cpu has run on the waker. This is callback locality, not
		 * process or waker identity, and is used only as a convergence hint.
		 */
		bool callback_on_home = (u32)tcpu == bpf_get_smp_processor_id();

		/*
		 * Self-race first: waking the task this CPU is still
		 * switching out (sub-slice block/wake cadence rides the
		 * ttwu wakelist and lands here with curr == p — the
		 * pipe/futex on-cpu shape). It is the hottest single wake
		 * path, so it runs BEFORE the nr_queued rhashtable lookup:
		 * cpu_curr is a plain per-cpu rq deref. Home is right even
		 * with a non-empty queue — p was current here microseconds
		 * ago (continuation-local by definition) and the vtime
		 * order keeps whatever is queued ahead of it fair.
		 * Eligibility, the ktime read, and a preempt kick would
		 * all be spent against ourselves; insert and let the
		 * in-flight schedule() repick — core's activate already
		 * rescheds an idling owner.
		 */
		curr = __COMPAT_scx_bpf_cpu_curr(tcpu);
		if (curr == p) {
			cake_qmark_set((u32)tcpu);
			scx_bpf_dsq_insert_vtime(p, (u64)(u32)tcpu, SLICE_NS,
						 vt, enq_flags);
			return;
		}

		/*
		 * M8: an RT-owned CPU is NOT "free or imminently free" the
		 * way idle is -- it may burst again (compositor/audio RT
		 * threads), and the kernel preempts SCX unconditionally for
		 * it regardless of anything cake does. CFS/EEVDF discounts a
		 * CPU's usable capacity by its RT/DL load average
		 * (scale_rt_capacity(), fair.c) before placing a task there;
		 * sched_ext's idle tracking has no equivalent, so approximate
		 * it here: don't home-route onto an RT-owned CPU, route to
		 * the global queue instead.
		 */
		bool rt_owned = curr && (curr->policy == SCHED_FIFO ||
					 curr->policy == SCHED_RR ||
					 curr->policy == SCHED_DEADLINE);
		/*
		 * Cache the home-queue depth once. The empty-home and peer-home
		 * arms below both test nr_queued(tcpu), and nothing inserts to
		 * tcpu between them (the insert lives in the mutually-exclusive
		 * `if (home)` arm), so the second lookup was a redundant
		 * rhashtable walk on the hottest wakeup path. rt_owned short-
		 * circuits both arms, so skip the lookup entirely when it holds.
		 */
		u64 nq_home = rt_owned ? 1 :
			      scx_bpf_dsq_nr_queued((u64)(u32)tcpu);

		if (!rt_owned && !nq_home) {
			u64 cv = curr ? curr->scx.dsq_vtime : 0;

			if (!cv) {
				/*
				 * Idle-owned empty home: the CPU is free or
				 * imminently free — the best claim there is.
				 * Sending this case global was the pipe leak:
				 * a wake racing its partner's idle transition
				 * took a WAKE_DSQ insert + pick_idle + kick
				 * detour on every message. No preempt exists
				 * to fire (live stays 0).
				 */
				home = true;
			} else {
				ran = bpf_ktime_get_ns() -
				      cake.run[(u32)tcpu & (MAX_CPUS - 1)].stamp;
				u32 cidx = cake_recip_index(curr);

				live = cv + cake_scale_vtime(ran, cidx);
				/*
				 * A LOCAL wake (this CPU waking onto itself —
				 * curr is the waker, about to block or be
				 * preempted) always claims home: it is the
				 * converged handoff pair, and its raw-vtime
				 * sleeper test flaps because the clamp itself
				 * writes the wakee back to within one slice
				 * of the frontier every insert (routing that
				 * flap globally collapsed futex 4.8M -> 0.98M,
				 * 2026-07-04). Remote wakes need a sleeper on
				 * one end.
				 */
				home = callback_on_home ||
				       (s64)d < (s64)SLEEPER_LAG_NS ||
				       time_before(live, lo);
			}
		}

		/*
		 * Fold all three home-routing reasons through one insert site:
		 * an explicit home claim, a peer wake onto an empty schedulable
		 * home (prev-CPU warmth, no forced preempt — the global detour
		 * sent every such request to a random cold L2), and an existing
		 * global backlog (the oversubscription signature: scattering
		 * another wake buys nothing, it lands cold and splits its pair —
		 * the t32/t64 herd collapse). The WAKE_DSQ probe stays lazy: the
		 * first two reasons never pay for the oversubscription signal.
		 */
		bool queue_home = home || (!rt_owned && !nq_home);

		if (!queue_home)
			queue_home = scx_bpf_dsq_nr_queued((u64)WAKE_DSQ);

		/*
		 * Decide destination and preemption once, publish the task once,
		 * then perform the optional wake action. Only an explicit home
		 * claim may preempt; peer/backlog homing preserves ordinary vtime.
		 */
		u64 wake_dsq = queue_home ? (u64)(u32)tcpu : (u64)WAKE_DSQ;
		bool preempt = home && live && ran < HOME_PREEMPT_YOUNG_NS &&
			       time_before(vt + HOME_PREEMPT_BASE_MARGIN_NS -
					   (ran >> 1), live);
#if CAKE_MDBLS_STAGE >= 2 && CAKE_MDBLS_PREEMPT
		if (home && live && ran < HOME_PREEMPT_YOUNG_NS) {
			bool learned_preempt = cake_mdbls_preempt(p, tcpu, vt, live,
								      ran, nq_home << 6,
								      preempt);

#if CAKE_MDBLS_PREEMPT == 1
			preempt = learned_preempt;
#else
			(void)learned_preempt;
#endif
		}
#endif
		bool hold_home = home && callback_on_home && !live;

		if (queue_home)
			cake_qmark_set((u32)tcpu);
		scx_bpf_dsq_insert_vtime(p, wake_dsq, SLICE_NS, vt, enq_flags);

		if (preempt) {
			cake.pmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
			scx_bpf_kick_cpu(tcpu, CAKE_KICK_PREEMPT);
			return;
		}
		if (hold_home)
			return;

		/* Prefer an idle SMT sibling for globally queued cold pickup. */
		if (!queue_home) {
			s32 sib = cpu_sibling[(u32)tcpu & (MAX_CPUS - 1)];

			if (sib >= 0 && bpf_cpumask_test_cpu(sib, p->cpus_ptr) &&
			    scx_bpf_test_and_clear_cpu_idle(sib)) {
				scx_bpf_kick_cpu(sib, CAKE_KICK_IDLE);
				return;
			}
		}

		idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (idle >= 0)
			scx_bpf_kick_cpu(idle, CAKE_KICK_IDLE);
		else if (!home && !cake_wake_preempt(p, tcpu)) {
			/* No idle CPU and tcpu refused: hunt a mid-slice
			 * compute occupant among 3 neighbors (see
			 * cake_wake_preempt_compute). */
			u32 nrc = (u32)cake.ncpu.word;
			u32 cand = (u32)tcpu;
			u32 pi;

			for (pi = 0; pi < 3; pi++) {
				cand++;
				if (cand >= nrc)
					cand = 0;
				if (!bpf_cpumask_test_cpu((s32)cand,
							  p->cpus_ptr))
					continue;
				if (cake_wake_preempt_compute(p, (s32)cand))
					break;
			}
		}
		return;
	}

	/*
	 * A continuation that lands behind a waiter is one half of an
	 * alternating pair — the only place turn length is paid for in L2
	 * refills (the 1ms->2ms base-slice change bought schbench p99
	 * 7368->6984, sat +30%, cache +18% by halving exactly this). Give
	 * the alternation a longer 3ms turn: wake storms never take this
	 * path (fork/thread margins stay), an empty queue keeps the base
	 * slice, and wake service rides preempts and kicks, not expiry
	 * cadence. This is a binary distinction, not the falsified
	 * queue-depth ladder.
	 */
	{
		u64 nq = scx_bpf_dsq_nr_queued((u64)(u32)tcpu);
		u64 was_preempted = cake.pmark[(u32)tcpu & (MAX_CPUS - 1)].word;
		u64 continuation_dsq = (u64)(u32)tcpu;
		u64 continuation_slice;

#if CAKE_MDBLS_STAGE >= 3 && CAKE_MDBLS_SLICE
		{
			u64 learned_slice = cake_mdbls_slice(p, nq);

#if CAKE_MDBLS_SLICE == 1
			continuation_slice = learned_slice;
#else
			(void)learned_slice;
			continuation_slice = nq ? CONTENDED_SLICE_NS : SLICE_NS;
#endif
		}
#else
		continuation_slice = nq ? CONTENDED_SLICE_NS : SLICE_NS;
#endif

		cake.pmark[(u32)tcpu & (MAX_CPUS - 1)].word = 0;
		if (nq >= OVERFLOW_QUEUE_DEPTH && p->nr_cpus_allowed > 1 && !was_preempted &&
		    !scx_bpf_dsq_nr_queued((u64)WAKE_DSQ)) {
			continuation_dsq = (u64)OVF_DSQ;
			continuation_slice = SLICE_NS;
		} else {
			cake_qmark_set((u32)tcpu);
		}
		scx_bpf_dsq_insert_vtime(p, continuation_dsq, continuation_slice,
					 vt, enq_flags);

		/*
		 * Pinned-wake service (census-verified 2026-07-19). A pinned
		 * user task's wake lands here — not the wake path — because
		 * nr_cpus_allowed == 1, and NO other CPU may steal it, so a
		 * wake behind a busy occupant used to wait out the occupant's
		 * whole slice (lock-pi pins its workers: handoff p99 3.9 ms
		 * vs native 171 µs, −86.6%; census: 114k of these per arm vs
		 * 14 truly flagless). Native wakeup-preempts by eligibility.
		 * Preempt by RAW sleep depth (the clamp erases deservingness;
		 * a pinned wake has no work-conservation alternative, so this
		 * cannot collide with the closed global wake-service
		 * frontier — multi-CPU wakes never take this branch).
		 */
		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed == 1 &&
		    continuation_dsq == (u64)(u32)tcpu) {
			struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(tcpu);
			u64 cv = curr ? curr->scx.dsq_vtime : 0;

			if (cv) {
				u64 cran = bpf_ktime_get_ns() -
					   cake.run[(u32)tcpu & (MAX_CPUS - 1)].stamp;
				u64 clive = cv + cake_scale_vtime(cran,
							cake_recip_index(curr));
				u64 dd = d + SLICE_NS;
				u64 pvt = lo - SLICE_NS +
					  (dd & ~((u64)((s64)dd >> 63)));

				if (time_before(pvt + HOME_PREEMPT_BASE_MARGIN_NS,
						clive)) {
					cake.pmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
					scx_bpf_kick_cpu(tcpu, CAKE_KICK_PREEMPT);
				}
			}
		}
	}

	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle >= 0)
		scx_bpf_kick_cpu(idle, CAKE_KICK_IDLE);
}

/*
 * ops.dispatch — aged-overflow rescue, earliest eligible vtime of {own queue,
 * wake queue}, then staggered ring steal and keep-running.
 *
 * 1) Overflow safety: a lockless OVF_DSQ head snapshot joins service once it
 *    trails the global service frontier by OVF_RESCUE_HYSTERESIS_NS. Overflow continuations
 *    used to be attempted only after both own and wake queues were empty;
 *    saturated futex kept at least one of those queues continuously populated,
 *    so compatible Codex and Steam tasks sat runnable in OVF_DSQ for >6s and
 *    tripped the watchdog (three reproductions, including the exact fold
 *    parent, 2026-07-11). The lag gate preserves ordinary own/wake locality
 *    and avoids making the global overflow lock a first-choice hot point, but
 *    a frozen overflow head necessarily ages across the frontier and receives
 *    bounded service. The normal third-choice consume remains as the empty-
 *    channel fast pickup and as a stale-snapshot fallback.
 * 2) Own DSQ vs the global wake queue: two lockless peeks (one RCU load of
 *    first_task each — no DSQ lock, so the 3M-wakes/s serialization stays
 *    dead) pick whichever head has the earlier vtime; the other is the
 *    immediate fallback. Own-first-always starved WAKE_DSQ whenever own
 *    queues never emptied — pure-spinner saturation requeues a continuation
 *    every slice, dispatch always found local work, and a woken task waited
 *    out the 5s watchdog (stress-ng-futex, 2026-07-02). Vtime comparison
 *    seals that at the source: a stranded wake head's vtime is frozen while
 *    every running task's advances past it, so each CPU soon prefers the
 *    wake head — starvation-free with no rescue path, and it is the
 *    latency rule too: a blocker that sleeps often carries low vtime and
 *    beats the warm backlog the moment it wakes. Insert and the own-queue
 *    consume are both under this CPU's rq lock, so that DSQ spinlock is
 *    uncontended except for occasional stealers. Slice-expiry requeues (the
 *    schbench +1.7ms tail) resolve right here, and select_cpu placement
 *    (L1/L2 warmth, the x265 fix) is honored because nobody else drains
 *    this queue while we're busy.
 * 3) Steal ring: two constant-start half-loops in ascending order from
 *    cpu+1, wraparound expressed as the second loop — no modulo, no wrap
 *    arithmetic, structurally unroll-resistant, verifier-friendly. The
 *    own-offset start is a zero-cost anti-herd stagger. A blind
 *    move_to_local takes the victim's min-vtime task, skips tasks whose
 *    cpumask excludes us, and self-corrects any cross-queue vtime inversion;
 *    an empty victim costs one lockless list-empty read. Migration happens
 *    at the work-conserving minimum: only when this CPU would otherwise
 *    idle or refill (pull model).
 * 4) Everything visibly empty → keep the previous task running with a fresh
 *    slice (the +46% stress-ng-cpu-cache-mem lever). It cannot starve
 *    queued work: our own move_to_local returning false proved DSQ[cpu]
 *    empty under its lock, and the kernel would otherwise keep prev anyway
 *    with its 20ms default slice — the refill preserves cake's 1ms cadence.
 *
 * Only scalars stay live across the move kfuncs (a successful remote
 * consume drops this rq's lock mid-call; we return immediately on success).
 */
void BPF_STRUCT_OPS(cake_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 ucpu = (u32)cpu;
	u64 first = (u64)ucpu, second = (u64)WAKE_DSQ;
#if CAKE_SCALAR_PEEK
	u64 own_vtime = 0, wake_vtime = 0, ovf_vtime = 0;
	bool has_own, has_wake, has_ovf;
#else
	struct task_struct *own, *wake, *ovf;
#endif
	u32 nr, i, idx;

	/*
	 * Point-in-time snapshots; a stale read only mis-orders the two
	 * consume attempts, both of which still happen. NULL from an empty
	 * queue keeps own-first (second try still drains the wake queue: a
	 * blocking CPU picking up the earliest-vtime waker IS the handoff
	 * fast path).
	 *
	 * The one-slice margin is hysteresis, not fairness slack: sleeper-
	 * clamped wake heads sit *slightly* earlier than own heads almost
	 * always, and a plain earliest-vtime rule sent every CPU to the
	 * global queue first — move_to_local takes the DSQ lock, and the
	 * wake-storm serialization came right back (futex −49%, 2026-07-02).
	 * Own-first within the margin keeps the uncontended fast path; a
	 * genuinely stranded wake head freezes while own heads advance past
	 * it by more than a slice within a few quanta, and then every CPU
	 * prefers it until it drains — the starvation seal stays structural.
	 */
	cake_qmark_clear(ucpu);
#if CAKE_SCALAR_PEEK
	has_own = cake_dsq_head_vtime((u64)ucpu, &own_vtime);
	if (has_own)
		cake_qmark_set(ucpu);
	has_wake = cake_dsq_head_vtime((u64)WAKE_DSQ, &wake_vtime);
	if (has_wake && (!has_own ||
		 time_before(wake_vtime +
			     (time_before(wake_vtime,
					  cake.frontier.word - SLEEPER_LAG_NS) ?
				      DEEP_WAKE_HYSTERESIS_NS :
				      PEER_WAKE_HYSTERESIS_NS),
			     own_vtime))) {
		first  = (u64)WAKE_DSQ;
		second = (u64)ucpu;
	}
	has_ovf = cake_dsq_head_vtime((u64)OVF_DSQ, &ovf_vtime);
	if (has_ovf &&
	    time_before(ovf_vtime + OVF_RESCUE_HYSTERESIS_NS,
			cake.frontier.word) &&
	    scx_bpf_dsq_move_to_local((u64)OVF_DSQ, 0))
		return;
#else
	own  = cake_dsq_peek((u64)ucpu);
	if (own)
		cake_qmark_set(ucpu);
	wake = cake_dsq_peek((u64)WAKE_DSQ);
	if (wake && (!own ||
		     time_before(wake->scx.dsq_vtime +
						  (time_before(wake->scx.dsq_vtime,
							       cake.frontier.word -
								       SLEEPER_LAG_NS) ?
							  DEEP_WAKE_HYSTERESIS_NS :
							  PEER_WAKE_HYSTERESIS_NS),
				 own->scx.dsq_vtime))) {
		first  = (u64)WAKE_DSQ;
		second = (u64)ucpu;
	}
	ovf = cake_dsq_peek((u64)OVF_DSQ);
	if (ovf &&
	    time_before(ovf->scx.dsq_vtime + OVF_RESCUE_HYSTERESIS_NS,
			cake.frontier.word) &&
	    scx_bpf_dsq_move_to_local((u64)OVF_DSQ, 0))
		return;
#endif
	if (scx_bpf_dsq_move_to_local(first, 0))
		return;
	if (scx_bpf_dsq_move_to_local(second, 0))
		return;
	if (scx_bpf_dsq_move_to_local((u64)OVF_DSQ, 0))
		return;

	nr = (u32)cake.ncpu.word;

#if CAKE_NR_CCDS > 1 && CAKE_CCD_STEAL_POLICY > 0
	/* One precomputed locality order avoids verifier-multiplying scan loops. */
	if (ucpu >= CAKE_NR_CPUS)
		return;
	for (i = 0; i < MAX_CPUS; i++) {
		if (i >= CAKE_NR_CPUS || i + 1 >= nr)
			break;
		idx = cpu_steal_order[ucpu * CAKE_NR_CPUS + i];
		if (cake_qmark_test(idx) &&
		    scx_bpf_dsq_move_to_local((u64)idx, 0))
			return;
	}
#else
	for (i = 0; i < MAX_CPUS; i++) {	/* upper half: cpu+1 .. nr-1 */
		idx = ucpu + 1 + i;
		if (idx >= nr)
			break;
		if (cake_qmark_test(idx) &&
		    scx_bpf_dsq_move_to_local((u64)idx, 0))
			return;
	}
	for (i = 0; i < MAX_CPUS; i++) {	/* lower half: 0 .. cpu-1 */
		if (i >= ucpu)
			break;
		if (cake_qmark_test(i) &&
		    scx_bpf_dsq_move_to_local((u64)i, 0))
			return;
	}
#endif

	if (prev && (prev->scx.flags & CAKE_TASK_QUEUED))
#if CAKE_DIRECT_SLICE_STORE
		prev->scx.slice = SLICE_NS;
#else
		scx_bpf_task_set_slice(prev, SLICE_NS);
#endif
}

/*
 * ops.running — stamp the per-CPU run start and advance the global vtime
 * frontier to this task's deadline.
 *
 * The dsq_vtime read is hoisted above the helper call so only the scalar
 * stays live across it (holding p forced a stack spill/reload per context
 * switch). The frontier store is deliberately conditional, NOT a branchless
 * max: the frontier is the hottest shared line in the scheduler and a select
 * would dirty it on every quantum on every CPU even when it doesn't move. A
 * predictable branch is cheaper than a guaranteed RFO. (Racy read-check-write
 * is fine — the frontier is advisory and monotonic enough under time_before
 * semantics.)
 */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
	u64 task_vtime = p->scx.dsq_vtime;
	u32 cpu = bpf_get_smp_processor_id();
	struct cake_run_slot *run = &cake.run[cpu & (MAX_CPUS - 1)];

	run->stamp = bpf_ktime_get_ns();
	run->sum = p->se.sum_exec_runtime;
#if CAKE_MDBLS_STAGE >= 2
	{
		struct cake_task_ctx *tctx = cake_task_ctx(p);

		run->remaining_ns = tctx ? cake_remaining(tctx, p) : 0;
		run->confidence = tctx ? tctx->confidence : 0;
	}
#endif

	if (time_before(cake.frontier.word, task_vtime))
		cake.frontier.word = task_vtime;
}

/*
 * ops.stopping — charge the wall time used to the task's vtime, weighted by
 * the reciprocal table (no division on the hot path).
 */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u64 used = p->se.sum_exec_runtime -
		   cake.run[cpu & (MAX_CPUS - 1)].sum;
	u32 idx = cake_recip_index(p);

	/*
	 * Direct write, not scx_bpf_task_set_dsq_vtime(): this fires on every
	 * context switch out, and the compat kfunc's sub-scheduler authority
	 * check (scx_prog_sched()/scx_task_on_sched(), see internal.h) costs a
	 * measured +28-36% here on kernels with CONFIG_EXT_SUB_SCHED=y (three
	 * independent A/Bs, forensically verified against BPF prog id/loaded_at
	 * to rule out stale-measurement contamination, 2026-07-08). cake is a
	 * flat root scheduler that will never have sub-schedulers to authorize
	 * against, so the check is pure overhead here. Still deprecated (emits
	 * a kernel log warning, not a functional break) -- acceptable trade for
	 * the hottest per-switch callback in the scheduler.
	 */
	p->scx.dsq_vtime += cake_scale_vtime(used, idx);
}

#if CAKE_MDBLS_STAGE > 0
/* One observation per blocked-to-runnable activation, independent of routing. */
void BPF_STRUCT_OPS(cake_runnable, struct task_struct *p, u64 enq_flags)
{
	struct cake_task_ctx *tctx = cake_task_ctx(p);
	u64 now, period;
#if CAKE_MDBLS_TELEMETRY
	struct cake_mdbls_stats *stats = cake_mdbls_stats();

	if (stats)
		stats->runnable++;
#endif

	if (!tctx)
		return;
	now = bpf_ktime_get_ns();
	if (tctx->last_runnable_ns) {
		period = now - tctx->last_runnable_ns;
		tctx->period_ns = cake_ewma4(tctx->period_ns,
						 cake_u32_sat(period));
		tctx->flags |= CAKE_HAS_PERIOD;
	}
	tctx->last_runnable_ns = now;
	tctx->activation_start_sum = p->se.sum_exec_runtime;
}

void BPF_STRUCT_OPS(cake_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct cake_task_ctx *tctx = cake_task_ctx(p);
	u64 activation, error;
	u32 confidence;
#if CAKE_MDBLS_TELEMETRY
	struct cake_mdbls_stats *stats = cake_mdbls_stats();
#endif

	if (!tctx)
		return;
	activation = p->se.sum_exec_runtime - tctx->activation_start_sum;
	error = tctx->burst_ns > activation ?
		tctx->burst_ns - activation : activation - tctx->burst_ns;
#if CAKE_MDBLS_TELEMETRY
	if (stats) {
		stats->quiescent++;
		stats->prediction_samples += !!(tctx->flags & CAKE_HAS_BURST);
		stats->confident_samples += tctx->confidence >= (MDBLS_CONF_STEP * 2);
		stats->burst_ns_sum += activation;
		stats->period_ns_sum += tctx->period_ns;
		stats->error_ns_sum += error;
		stats->burst_hist[cake_mdbls_time_bin(activation)]++;
		stats->error_hist[cake_mdbls_time_bin(error)]++;
		stats->confidence_hist[cake_mdbls_q8_bin(tctx->confidence)]++;
	}
#endif
	tctx->burst_ns = cake_ewma4(tctx->burst_ns, cake_u32_sat(activation));
	tctx->flags |= CAKE_HAS_BURST;
	if (tctx->samples != (u16)~0U)
		tctx->samples++;
	if (!(tctx->flags & CAKE_HAS_PERIOD))
		return;
	confidence = (u32)tctx->samples * MDBLS_CONF_STEP;
	tctx->confidence = confidence > MDBLS_CONF_MAX ?
		MDBLS_CONF_MAX : (u8)confidence;
}

s32 BPF_STRUCT_OPS(cake_init_task, struct task_struct *p,
			   struct scx_init_task_args *args)
{
	return bpf_task_storage_get(&cake_task_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE) ? 0 : -ENOMEM;
}
#endif

/*
 * ops.enable — a freshly enabled task starts at the current vtime frontier so
 * it is neither starved nor granted a windfall of credit.
 */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, cake.frontier.word);
}

/*
 * ops.init (sleepable, one-shot): cache nr_cpu_ids once — it's a kfunc,
 * never to be called on a hot path — then create one custom vtime DSQ per
 * possible CPU, dsq_id == cpu (raw small ids are safe: the kernel reserves
 * only bit-63 builtin ids). init completes before any other callback runs,
 * so there is no ordering hazard on cake.ncpu.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	u32 nr = scx_bpf_nr_cpu_ids();
	s32 i, ret;

	if (nr > MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids %u exceeds Cake MAX_CPUS %u", nr,
			      MAX_CPUS);
		return -EINVAL;
	}
	cake.ncpu.word = nr;

	bpf_for(i, 0, nr) {
		ret = scx_bpf_create_dsq((u64)(u32)i, -1);
		if (ret)
			return ret;
	}
	ret = scx_bpf_create_dsq(WAKE_DSQ, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(OVF_DSQ, -1);
}

void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * ALLOW_QUEUED_WAKEUP: after select_cpu chooses the target, remote activation
 * may ride the batched TTWU queue instead of taking the remote rq lock per
 * wake. enqueue therefore treats its callback CPU only as a locality signal;
 * no policy depends on process identity or assumes enqueue's current is waker.
 */
SCX_OPS_DEFINE(cake_ops,
	       .select_cpu	= (void *)cake_select_cpu,
#if CAKE_MDBLS_STAGE > 0
	       .runnable	= (void *)cake_runnable,
	       .quiescent	= (void *)cake_quiescent,
#endif
	       .enqueue		= (void *)cake_enqueue,
	       .dispatch	= (void *)cake_dispatch,
	       .running		= (void *)cake_running,
	       .stopping	= (void *)cake_stopping,
	       .enable		= (void *)cake_enable,
#if CAKE_MDBLS_STAGE > 0
	       .init_task	= (void *)cake_init_task,
#endif
	       .init		= (void *)cake_init,
	       .exit		= (void *)cake_exit,
	       .flags		= SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms	= WATCHDOG_TIMEOUT_MS,
	       .name		= "cake");
