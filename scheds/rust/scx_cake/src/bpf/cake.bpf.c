/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake: claimed idle placement, per-CPU continuation queues, per-LLC
 * wake pools and weighted virtual time.
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#include <scx/common.bpf.h>
#include "intf.h"

extern u64 bpf_ctz64(u64 x) __weak __ksym;
extern u64 bpf_popcnt64(u64 x) __weak __ksym;
const volatile bool cake_native_ctz;
const volatile bool cake_native_popcnt;

static __always_inline u32 cake_ctz64(u64 word)
{
	if (cake_native_ctz)
		/* Nonzero CPU masks retain the verifier's 0..63 bound. */
		return (u32)bpf_ctz64(word) & 63;
	return (u32)__builtin_ctzll(word);
}

static __always_inline u32 cake_popcnt64(u64 word)
{
	if (cake_native_popcnt)
		return (u32)bpf_popcnt64(word);
	return (u32)__builtin_popcountll(word);
}

#include "wake-signals.bpf.h"

/* on_cpu went from int to u8; an unsigned local int lets CO-RE narrow the load on either kernel. */
struct task_struct___cake_on_cpu {
	u32 on_cpu;
} __attribute__((preserve_access_index));

static __always_inline u32 cake_on_cpu_size(void)
{
	struct task_struct___cake_on_cpu *task = NULL;

	if (bpf_core_field_exists(task->on_cpu))
		return bpf_core_field_size(task->on_cpu);
	return 0;
}

static __always_inline bool cake_task_on_cpu(struct task_struct *p)
{
	struct task_struct___cake_on_cpu *task = (void *)p;
	u32 size = cake_on_cpu_size();

	if (size == sizeof(u8) || size == sizeof(u32))
		return task->on_cpu != 0;
	/* Unknown layout: retain the idle kick rather than assume continuation. */
	return false;
}

/* Startup diagnostics, populated once from the actual CO-RE/kfunc choices. */
u32 cake_compat_on_cpu_size;
bool cake_compat_cpu_curr_kfunc;

_Static_assert((MAX_CPUS & (MAX_CPUS - 1)) == 0,
	       "MAX_CPUS must remain a power of two");
_Static_assert((RECIP_TABLE_SIZE & (RECIP_TABLE_SIZE - 1)) == 0,
	       "reciprocal table must remain mask-indexable");
_Static_assert(STEAL_SPAN <= MAX_CPUS,
	       "steal matrix span must fit Cake MAX_CPUS");

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* SCX_* enumerators as load-time immediates, not rodata loads; must follow every scx header. */
#undef SCX_DSQ_LOCAL
#undef SCX_DSQ_LOCAL_ON
#undef SCX_ENQ_WAKEUP
#undef SCX_ENQ_IMMED
#undef SCX_KICK_IDLE
#undef SCX_KICK_PREEMPT
#undef SCX_TASK_QUEUED
#undef SCX_WAKE_SYNC
#define CAKE_DSQ_LOCAL    bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL)
#define CAKE_DSQ_LOCAL_ON bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL_ON)
#define CAKE_ENQ_WAKEUP   bpf_core_enum_value(enum scx_enq_flags,    SCX_ENQ_WAKEUP)
/* The CO-RE enum builtin cannot fold these 64-bit enumerators: their scx ABI values. */
#define CAKE_ENQ_PREEMPT  ((u64)1 << 32)
#define CAKE_ENQ_REENQ    ((u64)1 << 40)
/* An idle claim can lose its CPU before insertion: IMMED returns it via enqueue; 0 if absent. */
#define CAKE_ENQ_IMMED    __COMPAT_ENUM_OR_ZERO(enum scx_enq_flags, SCX_ENQ_IMMED)
#define CAKE_KICK_IDLE    bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_IDLE)
#define CAKE_KICK_PREEMPT bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_PREEMPT)
#define CAKE_TASK_QUEUED  bpf_core_enum_value(enum scx_ent_flags,    SCX_TASK_QUEUED)
/* IMMED on a local DSQ: core re-enqueues the task when a higher class preempts it; 0 if absent. */
#define CAKE_TASK_IMMED   SCX_TASK_IMMED
#define CAKE_WAKE_SYNC    bpf_core_enum_value(enum scx_wake_flags,   SCX_WAKE_SYNC)
#define CAKE_WAKE_TTWU    bpf_core_enum_value(enum scx_wake_flags,   SCX_WAKE_TTWU)
#define CAKE_PICK_IDLE_CORE \
	bpf_core_enum_value(enum scx_pick_idle_cpu_flags, SCX_PICK_IDLE_CORE)

/* Diagnostics: placement census, hold attribution, black box (--toggle probe=1). */
const volatile u8 cake_tog_probe;

/* PROBE census (enum cake_stat): per-CPU map, plain increment on this CPU's copy. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CAKE_STAT_NR);
	__type(key, u32);
	__type(value, u64);
} cake_stats SEC(".maps");

/* PROBE gates-reached census, one slot per CPU; never inline in select_cpu: it spilled prev_cpu. */
u64 cake_tried[MAX_CPUS][STATE_SLOT_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
_Static_assert((int)CAKE_TRIED_NR <= (int)STATE_SLOT_WORDS, "one slot per CPU holds the gates");

/* Plain increment: interrupts off on @cpu, except the retake: only the seat's holder gets there. */
static __always_inline void cake_tried_inc(u32 cpu, u32 idx)
{
	if (unlikely(cake_tog_probe))
		cake_tried[cpu & (MAX_CPUS - 1)][idx & (CAKE_TRIED_NR - 1)]++;
}

/* Cold: a hot probe site is one rodata test and a call the verifier removes with the toggle off. */
static __noinline void cake_stat_inc_cold(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&cake_stats, &idx);

	if (v)
		(*v)++;
}

static __noinline void cake_stat_add_cold(u32 idx, u64 add)
{
	u64 *v = bpf_map_lookup_elem(&cake_stats, &idx);

	if (v)
		*v += add;
}

/* Two counts from one toggle test: a class total and its site. */
static __noinline void cake_stat_inc2_cold(u32 idx, u32 site)
{
	cake_stat_inc_cold(idx);
	cake_stat_inc_cold(site);
}

static __always_inline void cake_stat_inc(u32 idx)
{
	if (unlikely(cake_tog_probe))
		cake_stat_inc_cold(idx);
}

static __always_inline void cake_stat_inc2(u32 idx, u32 site)
{
	if (unlikely(cake_tog_probe))
		cake_stat_inc2_cold(idx, site);
}

_Static_assert(CAKE_SITE_TACIW_PINNED - CAKE_SITE_TACIW_HOME ==
	       CAKE_SITE_TACI_PINNED - CAKE_SITE_TACI_HOME,
	       "claim wins mirror claim sites one for one");

/* PROBE site timing, summed per CPU; the call is in both arms so no clock crosses it when hot. */
#define CAKE_TIMED_COLD(site, expr) ({						\
	u64 __t0 = bpf_ktime_get_ns();						\
	typeof(expr) __r = (expr);						\
	cake_stat_add_cold((site), bpf_ktime_get_ns() - __t0);			\
	__r; })
#define CAKE_TIMED(site, expr) ({						\
	typeof(expr) __r;							\
	if (unlikely(cake_tog_probe))						\
		__r = CAKE_TIMED_COLD(site, expr);				\
	else									\
		__r = (expr);							\
	__r; })
#define CAKE_TIMED_VOID_COLD(site, stmt) do {					\
	u64 __t0 = bpf_ktime_get_ns();						\
	stmt;									\
	cake_stat_add_cold((site), bpf_ktime_get_ns() - __t0);			\
} while (0)
#define CAKE_TIMED_VOID(site, stmt) do {					\
	if (unlikely(cake_tog_probe))						\
		CAKE_TIMED_VOID_COLD(site, stmt);				\
	else									\
		stmt;								\
} while (0)

/* Fully ordered RMW: LOCK on x86; elsewhere the fetching form, which clang < 20 drops if unread. */
#ifdef __TARGET_ARCH_x86
#define CAKE_RMW_FULL(op, ptr, val) __atomic_fetch_##op(ptr, val, __ATOMIC_RELAXED)
#else
#define CAKE_RMW_FULL(op, ptr, val) ({						\
	typeof(*(ptr)) __rmw = __atomic_fetch_##op(ptr, val, __ATOMIC_SEQ_CST);	\
	barrier_var(__rmw);							\
})
#endif

/* Every present CPU id is below 64: the word paths use word 0. Not the span: hotplug headroom. */
const volatile u8 cake_one_word = 1;

/* One-word hosts: @word is really idle, @claimed is taken; all clear until each CPU re-picks. */
static struct {
	u64 word;
	u64 claimed;
	u8 pad[STATE_SLOT_BYTES - 2 * sizeof(u64)];
} cake_own_idle __attribute__((aligned(STATE_SLOT_BYTES)));

/* A hot-added id past the word has no bit, until the hotplug restart reloads cake as wide. */
static __always_inline u64 cake_own_bit(s32 cpu)
{
	return (u32)cpu < CPU_WORD_BITS ? 1ULL << cpu : 0;
}

/* A lost claim costs a read, not a locked operation. */
static __always_inline bool cake_claim_cpu(s32 cpu)
{
	u64 bit = cake_own_bit(cpu);

	if (!cake_one_word)
		return scx_bpf_test_and_clear_cpu_idle(cpu);
	if (!(READ_ONCE(cake_own_idle.word) & ~READ_ONCE(cake_own_idle.claimed) & bit))
		return false;
	return !(__atomic_fetch_or(&cake_own_idle.claimed, bit, __ATOMIC_RELAXED) & bit);
}

/* PROBE site census wrappers, cold like the counters; one count each under --toggle probe=1. */
static __noinline bool cake_taci_probe(s32 cpu, u32 site)
{
	bool won = CAKE_TIMED_COLD(CAKE_SITE_T_TACI, cake_claim_cpu(cpu));

	cake_stat_inc2_cold(CAKE_SITE_TACI, site);
	if (won)
		cake_stat_inc2_cold(CAKE_SITE_TACI_WIN,
				    site + (CAKE_SITE_TACIW_HOME - CAKE_SITE_TACI_HOME));
	return won;
}

static __always_inline bool cake_taci(s32 cpu, u32 site)
{
	if (unlikely(cake_tog_probe))
		return cake_taci_probe(cpu, site);
	return cake_claim_cpu(cpu);
}

/* CLOCK_MONOTONIC, for deltas against kernel ktime fields; one clocksource read per call. */
static __always_inline u64 cake_now(u32 site)
{
	cake_stat_inc2(CAKE_SITE_KT, site);
	return bpf_ktime_get_ns();
}

/* Task age from jiffies, no clocksource read: a lifetime quantity, never a deadline or a delta. */
const volatile u64 cake_tick_ns;	/* the loader's coarse clock_getres; 0: precise clock */
u64 cake_jiffies_offset;	/* precise ns minus jiffies * tick, at init */
const volatile u64 cake_vcap_unit_ns = SLICE_NS + TICK_MAX_NS;	/* longest run: grant plus a tick */

static __always_inline u64 cake_task_age(const struct task_struct *p, u32 site)
{
	u64 now;

	cake_stat_inc2(CAKE_SITE_KT, site);
	if (cake_tick_ns)
		now = bpf_jiffies64() * cake_tick_ns + cake_jiffies_offset;
	else
		now = bpf_ktime_get_ns();
	return time_delta(now, p->start_time);
}

/* The rq clock, comparable only within this family; it orders per CPU, so readers clamp deltas. */
static __always_inline u64 cake_now_rq(u32 site)
{
	cake_stat_inc2(CAKE_SITE_KT, site);
	return scx_bpf_now();
}

static __noinline s32 cake_pick_idle_probe(const struct cpumask *m, u64 flags)
{
	cake_stat_inc_cold(CAKE_SITE_PICK_IDLE);
	return CAKE_TIMED_COLD(CAKE_SITE_T_PICK, scx_bpf_pick_idle_cpu(m, flags));
}

static __always_inline s32 cake_pick_idle(const struct cpumask *m, u64 flags)
{
	if (unlikely(cake_tog_probe))
		return cake_pick_idle_probe(m, flags);
	return scx_bpf_pick_idle_cpu(m, flags);
}

static __noinline void cake_kick_probe(s32 cpu, u64 flags)
{
	cake_stat_inc_cold(CAKE_SITE_KICK);
	CAKE_TIMED_VOID_COLD(CAKE_SITE_T_KICK, scx_bpf_kick_cpu(cpu, flags));
}

static __always_inline void cake_kick(s32 cpu, u64 flags)
{
	if (unlikely(cake_tog_probe))
		cake_kick_probe(cpu, flags);
	else
		scx_bpf_kick_cpu(cpu, flags);
}

static __noinline s32 cake_nrq_probe(u64 dsq_id)
{
	cake_stat_inc_cold(CAKE_SITE_NRQ);
	return CAKE_TIMED_COLD(CAKE_SITE_T_NRQ, scx_bpf_dsq_nr_queued(dsq_id));
}

static __always_inline s32 cake_nrq(u64 dsq_id)
{
	if (unlikely(cake_tog_probe))
		return cake_nrq_probe(dsq_id);
	return scx_bpf_dsq_nr_queued(dsq_id);
}

/* PROBE (hold attribution): tag every placement with its queue kind. */
static __noinline void cake_probe_place(struct task_struct *p, u64 dsq_id,
					u64 enq_flags);

/* Kfunc bindings: same-shape compat arms stay inline, where the verifier prunes them. */
static __noinline bool cake_dsq_insert_vtime_probe(struct task_struct *p, u64 dsq_id,
						   u64 slice, u64 vtime, u64 enq_flags)
{
	cake_stat_inc_cold(CAKE_SITE_DSQ_INSERT);
	cake_probe_place(p, dsq_id, enq_flags);
	return CAKE_TIMED_COLD(CAKE_SITE_T_INSERT,
			       scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags));
}

/* compat's wrapper packs its arguments into a struct on the stack. */
static __noinline bool cake_dsq_insert_vtime(struct task_struct *p, u64 dsq_id,
					     u64 slice, u64 vtime, u64 enq_flags)
{
	/* Guarded here: the verifier removes the call, not only its body. */
	if (unlikely(cake_tog_probe))
		return cake_dsq_insert_vtime_probe(p, dsq_id, slice, vtime, enq_flags);
	return scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
}

static __noinline bool cake_dsq_insert_probe(struct task_struct *p, u64 dsq_id,
					     u64 slice, u64 enq_flags)
{
	cake_stat_inc_cold(CAKE_SITE_DSQ_INSERT);
	cake_probe_place(p, dsq_id, enq_flags);
	return CAKE_TIMED_COLD(CAKE_SITE_T_INSERT,
			       scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags));
}

static __always_inline bool cake_dsq_insert(struct task_struct *p, u64 dsq_id,
					    u64 slice, u64 enq_flags)
{
	if (unlikely(cake_tog_probe))
		return cake_dsq_insert_probe(p, dsq_id, slice, enq_flags);
	return scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags);
}

__noinline s32 cake_move_deep(u64 dsq_id, s32 cpu);

static __always_inline bool cake_move_local(u64 dsq_id, s32 cpu, s32 depth)
{
	if (depth >= CAKE_DSQ_SCAN_DEPTH)
		return cake_move_deep(dsq_id, cpu);
	return scx_bpf_dsq_move_to_local(dsq_id, 0);
}

static __noinline bool cake_move_to_local_probe(u64 dsq_id, s32 cpu, s32 depth)
{
	cake_stat_inc_cold(CAKE_SITE_MOVE_LOCAL);
	return CAKE_TIMED_COLD(CAKE_SITE_T_MOVE, cake_move_local(dsq_id, cpu, depth));
}

static __always_inline bool cake_move_to_local(u64 dsq_id, s32 cpu, s32 depth)
{
	if (unlikely(cake_tog_probe))
		return cake_move_to_local_probe(dsq_id, cpu, depth);
	return cake_move_local(dsq_id, cpu, depth);
}

/* Occupant of @cpu, racy as the kfunc. flatten: LLVM outlines an inline seen twice into a call. */
static __noinline __attribute__((flatten)) struct task_struct *cake_cpu_curr(s32 cpu)
{
	if (unlikely(cake_tog_probe)) {
		cake_stat_inc_cold(CAKE_SITE_CPU_CURR);
		return CAKE_TIMED_COLD(CAKE_SITE_T_CPU_CURR, __COMPAT_scx_bpf_cpu_curr(cpu));
	}
	return __COMPAT_scx_bpf_cpu_curr(cpu);
}

/* Local-DSQ depth. */
static __always_inline u64 cake_local_nr(s32 cpu)
{
	return cake_nrq(CAKE_DSQ_LOCAL_ON | (u32)cpu);
}

/* compat's fallback before 7.1 keeps an iterator on the stack. */
static __noinline struct task_struct *cake_dsq_peek(u64 dsq_id)
{
	return __COMPAT_scx_bpf_dsq_peek(dsq_id);
}

/* Direct field write: scx_bpf_task_set_slice() runs an authority check cake never needs. */
static __always_inline void cake_set_slice(struct task_struct *p, u64 slice)
{
	p->scx.slice = slice;
}

/* SCHED_* are uapi macros, not a BTF enum, so CO-RE has nothing to hook. */
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

/* Hot state: a BSS struct of 128-byte slots, so two words never share a line or prefetcher pair. */
struct cake_slot {
	u64 word;
	u64 pad[STATE_SLOT_WORDS - 1];
};

struct cake_frontier_slot {
	u64 word;	/* F: the global vtime frontier */
	u64 stamp;	/* rq clock of F's last store: the rate band's base */
	u64 pad[STATE_SLOT_WORDS - 2];
};
_Static_assert(sizeof(struct cake_frontier_slot) == STATE_SLOT_BYTES,
	       "cake_frontier_slot must keep the slot stride");

struct cake_llc_slot {
	u64 pending;	/* tasks inserted and not yet seen out of the pool: proof */
	u64 unserved;	/* inserts not yet moved out by a serve: the interlock's kick */
	u64 mark;
	u64 served;
	u64 pad[STATE_SLOT_WORDS - 4];
};
_Static_assert(sizeof(struct cake_llc_slot) == STATE_SLOT_BYTES,
	       "cake_llc_slot must keep the slot stride");

struct cake_run_slot {
	u64 stamp;
	u64 sum;
	/* Handoff learning: WOKE plus a saturating wake-then-block count; owner-written. */
	u64 hint;
	/* Holder placed behind a stranger, whose re-enqueue reads this and takes the pool. */
	u64 retake;
	/* x86 TSO, barrier() only: write stamp, pid; then 0, charge; read vtime, pid, stamp. */
	u64 pid;	/* the stamp's owner, 0 off-CPU */
	/* The slice ops.running granted, by its stamp so a remote reader needs one line. */
	u64 grant;
	u64 pend_spin;
	u64 frontier;	/* F as ops.running left it: the charge ceiling's base */
	/* PROBE, second line so the hot ops stay on the first: what ops.cpu_release cannot peek. */
	u64 out_sum;
	u64 out_nvcsw;
	u64 out_slice;
	u64 out_immed;
	u64 release;
	u64 pad[STATE_SLOT_WORDS - 13];
};

enum {
	CAKE_HINT_WOKE		= 1ULL << 0,
	CAKE_HINT_CONF_SHIFT	= 8,
	CAKE_HINT_CONF_MAX	= 3,
	CAKE_NEIGHBOUR_PROBE_DEPTH = 3,
};

/* A quantum this short "woke someone and got out of the way": a hardware cost, not the slice. */
const volatile u64 cake_handoff_max_ns		= 1464;

/* Mean burst: runtime per voluntary switch, exact to the nanosecond. */
static __always_inline u64 cake_burst_ns(const struct task_struct *p)
{
	return p->se.sum_exec_runtime / (p->nvcsw | 1);
}

/* Burst under one handoff: relocating costs more than the wait it cures, so it keeps its home. */
static __always_inline bool cake_subhandoff(const struct task_struct *p)
{
	u64 n = p->nvcsw | 1;

	return !(n >> 32) && p->se.sum_exec_runtime < cake_handoff_max_ns * n;
}

/* Stage class: cross-multiply while the product fits; past that no u64 runtime reaches it. */
static __always_inline bool cake_stage(const struct task_struct *p)
{
	u64 n = p->nvcsw | 1;

	return n <= (~0ULL / SEAT_BURST_MIN_NS) &&
	       p->se.sum_exec_runtime >= SEAT_BURST_MIN_NS * n;
}

/* High word of the 128-bit @x * @y, from 32-bit limbs. */
static __always_inline u64 cake_mul_hi(u64 x, u64 y)
{
	u64 xl = (u32)x, xh = x >> 32, yl = (u32)y, yh = y >> 32;
	u64 lh = xl * yh, hl = xh * yl, mid;

	/* Opaque cross terms: LLVM folds the limbs into a 128-bit multiply, a libcall BPF lacks. */
	barrier_var(lh);
	barrier_var(hl);
	mid = ((xl * yl) >> 32) + (u32)lh + (u32)hl;
	return xh * yh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

/* Cold: the exact 128-bit compare. */
static __noinline bool cake_cross_gt_wide(u64 a, u64 n, u64 b, u64 m)
{
	u64 ha = cake_mul_hi(a, n), hb = cake_mul_hi(b, m);

	return ha != hb ? ha > hb : a * n > b * m;
}

/* @a * @n > @b * @m; a long-lived busy thread's products pass u64: those take the wide form. */
static __always_inline bool cake_cross_gt(u64 a, u64 n, u64 b, u64 m)
{
	if (likely(!((a | b | n | m) >> 32)))
		return a * n > b * m;
	return cake_cross_gt_wide(a, n, b, m);
}

/* Waits longer than it runs? Mean wait vs mean burst, cross-multiplied; not a tuning. */
static __always_inline bool cake_starved(const struct task_struct *p)
{
	u64 wait = p->sched_info.run_delay >> CAKE_RATIO_SHIFT;
	u64 run = p->se.sum_exec_runtime >> CAKE_RATIO_SHIFT;

	if (!run)
		return false;
	return cake_cross_gt(wait, p->nvcsw | 1, run, p->sched_info.pcount | 1);
}

/* Waits longer than its own slice? cake_starved has no dead zone; relocation pays past one turn. */
static __always_inline bool cake_starved_turn(const struct task_struct *p)
{
	u64 wait = p->sched_info.run_delay >> CAKE_RATIO_SHIFT;
	u64 run = p->se.sum_exec_runtime >> CAKE_RATIO_SHIFT;

	if (!run)
		return false;
	return cake_cross_gt(wait, p->nvcsw | 1, run << 1, p->sched_info.pcount | 1);
}

_Static_assert(sizeof(struct cake_slot) == STATE_SLOT_BYTES,
	       "cake_slot must preserve cache-isolation stride");
_Static_assert(sizeof(struct cake_run_slot) == STATE_SLOT_BYTES,
	       "cake_run_slot must preserve cache-isolation stride");

struct cake_state {
	/* Global vtime frontier: raised by ops.running within a wall-rate band. */
	struct cake_frontier_slot frontier;
	/* Run accounting: stamp read remotely; sum owner-only, so ops.stopping reads no clock. */
	struct cake_run_slot run[MAX_CPUS];
	/* One line per pool: a both-empty dispatch reads token, mark and serve stamp together. */
	struct cake_llc_slot pool[MAX_LLCS];
	/* One pool offer for a claimed idle CPU's next dispatch: source pool + 1; 0 none. */
	struct cake_slot remote_pool[CPU_WORD_BITS];
	/* "DSQ[i] may hold work", gating the steal ring, one bit per CPU; a stale bit is benign. */
	u64 qmask[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
};

_Static_assert(sizeof(((struct cake_state *)0)->qmask) <= STATE_SLOT_BYTES,
	       "qmask must fit one cache-isolation slot");

static struct cake_state cake;

/* The retake's occupant read and gate count; its own frame: inline, the count spills prev_cpu. */
static __noinline struct task_struct *cake_cpu_curr_retake(s32 cpu)
{
	cake_tried_inc((u32)cpu, CAKE_TRIED_RETAKE);
	return cake_cpu_curr(cpu);
}

/* Test first: an unconditional atomic on this shared word would serialise every dispatch. */
static __always_inline void cake_qmark_set(u32 cpu)
{
	u64 bit;

	cpu &= MAX_CPUS - 1;
	bit = 1ULL << (cpu & 63);
	if (!(cake.qmask[cpu >> 6] & bit)) {
		cake_stat_inc(CAKE_SITE_QMARK_SET);
		CAKE_TIMED_VOID(CAKE_SITE_T_QMARK,
				__atomic_fetch_or(&cake.qmask[cpu >> 6], bit, __ATOMIC_RELAXED));
	} else {
		cake_stat_inc(CAKE_SITE_QMARK_SET_SKIP);
	}
}

static __always_inline void cake_qmark_clear(u32 cpu)
{
	u64 bit;

	cpu &= MAX_CPUS - 1;
	bit = 1ULL << (cpu & 63);
	if (cake.qmask[cpu >> 6] & bit) {
		cake_stat_inc(CAKE_SITE_QMARK_CLR);
		CAKE_TIMED_VOID(CAKE_SITE_T_QMARK,
				__atomic_fetch_and(&cake.qmask[cpu >> 6], ~bit, __ATOMIC_RELAXED));
	} else {
		cake_stat_inc(CAKE_SITE_QMARK_CLR_SKIP);
	}
}

static __always_inline bool cake_qmark_test(u32 cpu)
{
	cpu &= MAX_CPUS - 1;
	return cake.qmask[cpu >> 6] & (1ULL << (cpu & 63));
}

/* Queue count, not the mark (a steal hint). Own frame: inline adds a fill to select_cpu. */
static __noinline bool cake_cpu_dsq_idle(u32 cpu)
{
	return !cake_nrq((u64)cpu);
}

/* Republish from a peek. __noinline: inline, LLVM hoists the address over it and spills cpu. */
static __noinline void cake_qmark_publish(u32 cpu, bool queued)
{
	if (queued)
		cake_qmark_set(cpu);
	else
		cake_qmark_clear(cpu);
}

extern const volatile u32 nr_llcs;

/* More than one wake pool; rodata, so a one-LLC host's verifier removes each foreign-pool call. */
static __always_inline bool cake_multi_llc(void)
{
	return nr_llcs > 1;
}

/* Foreign rescue skips pools with a clear mark: set after the insert (cake_wake_mark_retire). */
static __always_inline void cake_wake_mark_set(u32 llc)
{
	if (!cake_multi_llc())
		return;
	if (!__atomic_exchange_n(&cake.pool[llc & (MAX_LLCS - 1)].mark,
				 1, __ATOMIC_SEQ_CST))
		cake_stat_inc(CAKE_SITE_WAKE_MARK_ST);
}

static __always_inline void cake_pool_pending_inc(u32 llc)
{
	struct cake_llc_slot *ps = &cake.pool[llc & (MAX_LLCS - 1)];

	__sync_fetch_and_add(&ps->pending, 1);
	/* Before the idle word read: the barrier pairs with cake_own_idle_set's. */
	CAKE_RMW_FULL(add, &ps->unserved, 1);
}

/* Claim an insert before the move: the interlock counts only inserts no CPU is taking. */
static __always_inline bool cake_pool_claim(u32 llc)
{
	u64 *w = &cake.pool[llc & (MAX_LLCS - 1)].unserved;

	if ((s64)*w <= 0)
		return false;
	if ((s64)__sync_fetch_and_sub(w, 1) > 0)
		return true;
	CAKE_RMW_FULL(add, w, 1);
	return false;
}

/* A claimed serve; a move that takes nothing gives the claim back. */
static __always_inline bool cake_pool_serve(u64 pool, u32 llc, s32 cpu, s32 depth)
{
	if (!cake_pool_claim(llc))
		return false;
	if (cake_move_to_local(pool, cpu, depth))
		return true;
	/* Raises the count again: the same barrier as cake_pool_pending_inc's. */
	CAKE_RMW_FULL(add, &cake.pool[llc & (MAX_LLCS - 1)].unserved, 1);
	return false;
}

/* Inserts in flight; unserved raised with a zero token is a pop the serve never saw: clear it. */
static __always_inline u64 cake_pool_unserved(u32 llc)
{
	struct cake_llc_slot *ps = &cake.pool[llc & (MAX_LLCS - 1)];
	u64 u = ps->unserved;

	if (u && !ps->pending && __sync_bool_compare_and_swap(&ps->unserved, u, 0)) {
		/* An insert between the token read and the CAS raised both: give its count back. */
		if (!ps->pending) {
			cake_stat_inc(CAKE_SITE_PEND_HEAL);
			return 0;
		}
		CAKE_RMW_FULL(add, &ps->unserved, 1);
		return 1;
	}
	return u;
}

static __always_inline void cake_pool_pending_dec(u32 llc)
{
	__atomic_fetch_sub(&cake.pool[llc & (MAX_LLCS - 1)].pending, 1, __ATOMIC_RELAXED);
}

/* The low bits are a fast hint for the token held in task storage. */
static __always_inline u64 cake_pool_tag(u64 slice, u32 llc)
{
	return (slice & ~(u64)CAKE_POOL_TAG_MASK) | ((llc & (MAX_LLCS - 1)) + 1);
}

_Static_assert(!(SLICE_NS & CAKE_POOL_TAG_MASK),
	       "the flat slice must leave the pool tag bits clear");

static __always_inline bool cake_pool_pending(u32 llc)
{
	return cake.pool[llc & (MAX_LLCS - 1)].pending != 0;
}

/* Loader-filled SMT map; -1 means the CPU has no online sibling. */
const volatile s32 cpu_sibling[MAX_CPUS];
/* Every other thread of a CPU's core, for numbering the shift fold cannot express. */
const volatile u64 cake_core_mates[CPU_WORD_BITS];
/* Loader-proven uniform SMT displacement; 64 selects the generic map walk. */
const volatile u32 cake_smt_shift = CPU_WORD_BITS;
const volatile u64 cake_smt_left;
const volatile u64 cake_smt_right;

/* Loader-maintained and live: sink-ness follows device load. The first word is the hot read. */
u64 cpu_irq_hot_words[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* The same set expanded to whole cores by the loader, not on every claim walk. */
u64 cpu_irq_hot_cores[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));

/* In-handler depth from the handler tracepoints; owner-written, remote reads race benignly. */
struct cake_irq_slot {
	u32 depth;
	u8 pad[STATE_SLOT_BYTES - sizeof(u32)];
};
/* One slot per CPU, not per sibling pair: sharing took the sink's line away mid-handler. */
struct cake_irq_slot cake_irq_live[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));

static __always_inline bool cake_cpu_irq_hot(u32 c)
{
	return cpu_irq_hot_words[(c & (MAX_CPUS - 1)) >> 6] & (1ULL << (c & 63));
}

/* Bad wake target: chronically loud (the mask) or inside a handler now; each misses the other. */
static __always_inline bool cake_cpu_irq_bad(s32 cpu)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	return cpu >= 0 && (cake_cpu_irq_hot(c) || cake_irq_live[c].depth ||
			   cake_signal_irq_hot(c));
}

/* A tick due within one wake hop lands the task in the handler. The loader's probe p99; 0: off. */
const volatile u64 cake_wake_hop_ns;

extern const struct tick_device tick_cpu_device __ksym __weak;

/* One clock per idle search, so every candidate is judged alike; 0 with the predictor off. */
static __always_inline u64 cake_tick_clock(void)
{
	if (!cake_wake_hop_ns || !bpf_ksym_exists(&tick_cpu_device))
		return 0;
	return cake_now(CAKE_SITE_KT_TICKSOON);
}

/* Is @cpu's timer due within one wake hop of @now? False with the predictor off. */
static __noinline bool cake_cpu_tick_soon(s32 cpu, u64 now)
{
	const struct tick_device *td;
	const struct clock_event_device *ed;
	u64 next;

	if (!now)
		return false;
	td = bpf_per_cpu_ptr(&tick_cpu_device, (u32)cpu);
	if (!td)
		return false;
	ed = td->evtdev;
	if (!ed)
		return false;
	/* Overdue: the tick is firing now. A stopped nohz tick reads far-future and never trips. */
	next = (u64)ed->next_event;
	return next <= now + cake_wake_hop_ns;
}

static __always_inline void cake_irq_edge(bool enter)
{
	u32 c = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
	u32 *d = &cake_irq_live[c].depth;

	if (enter)
		(*d)++;
	else if (*d)
		/* Attach can land mid-handler: first exit has no entry. */
		(*d)--;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(cake_irq_enter)
{
	cake_irq_edge(true);
	return 0;
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(cake_irq_leave)
{
	cake_irq_edge(false);
	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(cake_softirq_enter)
{
	cake_irq_edge(true);
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(cake_softirq_leave)
{
	cake_irq_edge(false);
	return 0;
}

/* The CPU span cake scans; rodata folds the walk bounds; ops.init checks it against nr_cpu_ids. */
const volatile u32 nr_cpu_span;
/* Three times the online CPU count of each CPU's LLC, and of the host. */
const volatile u32 cpu_llc_online3[MAX_CPUS];
const volatile u32 nr_cpu_online3;
/* Idle-word bits tried per claim: at least CLAIM_TRIES_MIN, a quarter of the die. */
const volatile u32 cake_claim_tries = CLAIM_TRIES_MIN;
/* One-word host: affinity is one load of the task's own mask word. */
static __always_inline bool cake_allowed(const struct task_struct *p, s32 cpu)
{
	if (cake_one_word && (u32)cpu < CPU_WORD_BITS)
		return (p->cpus_ptr->bits[0] >> ((u32)cpu & 63)) & 1;
	return bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

/* runnable_at is an unsigned long in kernel jiffies, including on 32-bit kernels. */
static __always_inline bool cake_head_delayed(u64 runnable_at)
{
	u64 tick = cake_tick_ns;
	u64 hz, elapsed, limit;

	if (!tick)
		return false;
	hz = (1000000000ULL + tick / 2) / tick;
	limit = (hz * WATCHDOG_TIMEOUT_MS + 1999) / 2000;
	elapsed = bpf_jiffies64() - runnable_at;
	if (bpf_core_field_size(((struct task_struct *)0)->scx.runnable_at) == 4)
		return (s32)elapsed >= (s32)limit;
	return (s64)elapsed >= (s64)limit;
}

/* Verify the bounded walk once, independently of the steal ring's CPU loop. */
__noinline s32 cake_move_deep(u64 dsq_id, s32 cpu)
{
	struct task_struct *p;
	u64 runnable_at = 0;
	s32 pid = 0;
	u32 scanned = 0;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		if (cake_allowed(p, cpu) &&
		    (cpu == (s32)p->thread_info.cpu || !is_migration_disabled(p)))
			return scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
						CAKE_DSQ_LOCAL_ON | (u32)cpu, 0);
		if (!scanned) {
			runnable_at = p->scx.runnable_at;
			pid = p->pid;
		}
		if (++scanned == CAKE_DSQ_SCAN_MAX)
			break;
	}

	if (scanned != CAKE_DSQ_SCAN_MAX || !cake_head_delayed(runnable_at))
		return false;
	/* The owner may have drained the head while we examined the prefix. */
	p = cake_dsq_peek(dsq_id);
	if (p && p->pid == pid && p->scx.runnable_at == runnable_at &&
	    cake_nrq(dsq_id) >= CAKE_DSQ_SCAN_DEPTH)
		scx_bpf_exit(0, "deep DSQ %llu: CPU %d cannot serve prefix, head pid %d",
			     dsq_id, cpu, pid);
	return false;
}

/* Loader-sorted: same CCD, same cache tier, then the rest; live only with multiple CCDs in span. */
const volatile u16 cpu_steal_order[STEAL_SPAN * STEAL_SPAN];
/* Populated entries per row, distinct from the possible CPU ID span. */
const volatile u32 nr_steal_cpus;
/* The CPUs sharing each CPU's LLC; all ones on a one-LLC host or an unreadable topology. */
const volatile u64 cpu_llc_word[MAX_CPUS];
/* Dense LLC index per CPU (0 on a one-LLC host) and the LLC count. */
const volatile u8 cpu_llc_id[MAX_CPUS];
/* Physical domain identity survives pool collapse, for every CPU; 0xffff: topology unknown. */
const volatile u16 cpu_llc_domain[MAX_CPUS];
const volatile u32 nr_llcs = 1;

static __always_inline u32 cake_llc_of(s32 cpu)
{
	if (!cake_multi_llc())
		return 0;
	return (u32)cpu_llc_id[(u32)cpu & (MAX_CPUS - 1)] & (MAX_LLCS - 1);
}

static __always_inline u64 cake_pool_dsq(u32 llc)
{
	return (u64)LLC_WAKE_DSQ_BASE + (llc & (MAX_LLCS - 1));
}

/* Physical locality, independent of the pool layout. */
static __always_inline bool cake_cross_llc(s32 from, s32 to)
{
	u32 a = (u32)from, b = (u32)to;
	u16 da, db;

	if (a >= MAX_CPUS || b >= MAX_CPUS)
		return false;
	/* LLVM may merge the bounds into (a | b), which the verifier cannot carry back. */
	barrier_var(a);
	barrier_var(b);
	da = cpu_llc_domain[a & (MAX_CPUS - 1)];
	db = cpu_llc_domain[b & (MAX_CPUS - 1)];
	return da != 0xffff && db != 0xffff && da != db;
}

/* PROBE: count a cross-die placement at @site; called only under the toggle. */
static __noinline void cake_probe_x(u32 site, s32 from, s32 to)
{
	if (cake_cross_llc(from, to))
		cake_stat_inc(site);
}
const volatile u8 steal_order_live;

/* (1024 << 20) / sched_prio_to_weight[i], i = static_prio - 100; SCHED_IDLE at IDLE_RECIP_INDEX. */
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

/* Cold: only a runtime past CAKE_RECIP_RUNTIME_FAST_MAX reaches the split. */
static __noinline u64 cake_scale_vtime_slow(u64 base, u64 runtime, u64 reciprocal)
{
	return base + (runtime >> RECIP_SHIFT) * reciprocal +
	       ((runtime & RECIP_MASK) * reciprocal >> RECIP_SHIFT);
}

/* @base + @runtime scaled by the reciprocal; @base folds in so it need not live across the call. */
static __always_inline u64 cake_scale_vtime_add(u64 base, u64 runtime, u32 idx)
{
	u64 reciprocal = recip_weight[idx & RECIP_INDEX_MASK];

	/* Every ordinary slice fits the single multiply. */
	if (runtime <= CAKE_RECIP_RUNTIME_FAST_MAX)
		return base + ((runtime * reciprocal) >> RECIP_SHIFT);

	return cake_scale_vtime_slow(base, runtime, reciprocal);
}

/* max(@d, 0) for a wrapped vtime difference, branchless: a negative @d masks to 0. */
static __always_inline u64 cake_delta_clamp(u64 d)
{
	return d & ~((u64)((s64)d >> 63));
}

/* min(@v, @hi) for vtimes, branchless and wrap-safe. */
static __always_inline u64 cake_vtime_ceil(u64 v, u64 hi)
{
	return hi - cake_delta_clamp(hi - v);
}

_Static_assert(((u64)SLICE_NS + TICK_MAX_NS) * (u64)MAX_RECIP_WEIGHT < (~0ULL >> 1),
	       "the cap product fits u64");

/* Lead over the frontier a weight may hold: its longest run's charge, within [grain, cap max]. */
static __always_inline u64 cake_vtime_cap(u64 reciprocal)
{
	u64 cap = (cake_vcap_unit_ns * reciprocal) >> RECIP_SHIFT;

	/* A longer span (SCX_SLICE_DFL placement, kept prev) clips: a lower key, never a wait. */
	cap = cap < CAKE_VTIME_CAP_MAX_NS ? cap : CAKE_VTIME_CAP_MAX_NS;
	return cap > FRONTIER_GRAIN_NS ? cap : FRONTIER_GRAIN_NS;
}

/* Preserve the exact 40-level nice table while honoring SCHED_IDLE weight 3. */
static __always_inline u32 cake_recip_index(const struct task_struct *p)
{
	if (p->policy == SCHED_IDLE)
		return IDLE_RECIP_INDEX;
	return (u32)(p->static_prio - STATIC_PRIO_BASE);
}

/* @curr's live vtime on @tcpu, 0 if none; @ran_out is its run so far; @now 0 reads the clock. */
static __always_inline u64 cake_occupant_live_of(struct task_struct *curr, s32 tcpu,
						 u64 now, u64 *ran_out)
{
	struct cake_run_slot *rs = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	u64 cv, ran, stamp;
	u32 cidx;

	if (!curr)
		return 0;
	/* Not on the ext runqueue (RT, DL, idle, SCHED_FIFO with a stale dsq_vtime): no victim. */
	if (!(curr->scx.flags & CAKE_TASK_QUEUED))
		return 0;
	cv = curr->scx.dsq_vtime;
	if (!cv)
		return 0;
	/* Writers' reverse: owner match proves vtime uncharged, stamp new; a tear under-prices. */
	barrier();
	if (rs->pid != (u64)(u32)curr->pid)
		return 0;
	barrier();	/* owner before stamp */
	cidx = cake_recip_index(curr);

	stamp = rs->stamp;
	ran = time_delta(now ? now : cake_now_rq(CAKE_SITE_KT_OCCUPANT), stamp);
	*ran_out = ran;
	return cake_scale_vtime_add(cv, ran, cidx);
}

/* The pinned-wake form: its own frame keeps that check free of spills. */
static __noinline u64 cake_occupant_live(s32 tcpu, u64 *ran_out)
{
	return cake_occupant_live_of(cake_cpu_curr(tcpu), tcpu, 0, ran_out);
}

static u64 cake_seat_word __attribute__((aligned(STATE_SLOT_BYTES)));

/* Fixed homes: pid << 8 | cpu + 1 per slot; read at every wake, written at share samples. */
static u64 cake_home[HOME_SLOTS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* Per CPU: the owner's slot value and its last sample time; sample path only. */
static u64 cake_home_val[CPU_WORD_BITS] __attribute__((aligned(STATE_SLOT_BYTES)));
static u64 cake_home_seen[CPU_WORD_BITS];
static u64 cake_home_cores;
/* Busy share samples per census; more than the cores can give: nobody is special, homes are not used. */
static u64 cake_home_census_t;
static u32 cake_home_census;
static u8 cake_home_crowded;

static __always_inline s32 cake_home_cpu(const struct task_struct *p)
{
	u64 v = cake_home[(u32)p->pid & (HOME_SLOTS - 1)];

	return (v >> 8) == (u64)(u32)p->pid ? (s32)(v & 0xff) - 1 : -1;
}

/* Wide hosts: idle mask addresses, for a one-load hot read. Own section: a kptr's map cannot be mmapped. */
static struct cpumask __kptr_untrusted *cake_mask_cpu SEC(".data.masks");
static struct cpumask __kptr_untrusted *cake_mask_smt SEC(".data.masks");

/* The claimable set: cake's word, or a wide host's kernel mask, whose refreshes update_idle misses. */
static __always_inline u64 cake_idle_word(void)
{
	struct cpumask *m;

	if (cake_one_word)
		return READ_ONCE(cake_own_idle.word) & ~READ_ONCE(cake_own_idle.claimed);
	m = cake_mask_cpu;
	if (likely(m))
		return m->bits[0];
	return 0;
}

/* Irregular SMT numbering, or more than two threads a core: each idle thread asks its core. */
static __noinline u64 cake_own_cores_walk(u64 w)
{
	u64 rest = w, cores = w;
	u32 i;

	for (i = 0; i < CPU_WORD_BITS && rest; i++) {
		u64 c = cake_ctz64(rest);

		barrier_var(c);	/* keep the mask on the load's register */
		if (cake_core_mates[c & 63] & ~w)
			cores &= ~(1ULL << (c & 63));
		rest &= rest - 1;
	}
	return cores;
}

/* Whole idle cores of @w: a thread whose sibling is idle, or one with no sibling. */
static __always_inline u64 cake_own_cores(u64 w)
{
	u32 shift = cake_smt_shift;

	if (!shift)
		return w;
	if (shift < CPU_WORD_BITS)
		return w & (((w & cake_smt_left) << shift) | ((w & cake_smt_right) >> shift) |
			    ~(cake_smt_left | cake_smt_right));
	return cake_own_cores_walk(w);
}

/* From @word, not the claimable set: a claimed core stays whole until that CPU really runs. */
static __always_inline u64 cake_core_word(void)
{
	struct cpumask *m;

	if (cake_one_word)
		return cake_own_cores(READ_ONCE(cake_own_idle.word));
	m = cake_mask_smt;
	if (likely(m))
		return m->bits[0];
	return 0;
}

/* Wide-host home test: the sibling's occupant, so it misses an undispatched claim. */
static __always_inline bool cake_core_contended(s32 cpu)
{
	s32 sib = cpu_sibling[(u32)cpu & (MAX_CPUS - 1)];
	struct task_struct *curr;

	cake_stat_inc(CAKE_SITE_CORE_CONTENDED);
	if (sib < 0)
		return false;

	curr = cake_cpu_curr(sib);
	return curr && curr->pid;
}

/* Home not a whole idle core? @cores: whole-core word; a wide host's also drops a claimed core. */
static __always_inline bool cake_core_busy(u64 cores, s32 cpu)
{
	cake_stat_inc(CAKE_SITE_CORE_CONTENDED);
	return (u32)cpu >= CPU_WORD_BITS || !(cores & (1ULL << ((u32)cpu & 63)));
}

/* Hybrid hosts: the high-capacity CPUs; zero tiers on a uniform host folds the arm. */
const volatile u8 cake_cap_tiers;
const volatile u64 cake_cap_word;
/* cpuidle exit latency per state and the deepest enabled state; 0: no driver. */
const volatile u64 cake_idle_state_ns[CAKE_IDLE_STATES];
const volatile u64 cake_idle_exit_max_ns;
/* CPUs asleep in a state whose exit outlasts one handoff, from the cpu_idle tracepoint. */
u64 cake_deep_idle_word __attribute__((aligned(STATE_SLOT_BYTES)));
u8 cake_idle_deep[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* Startup preference for fixed homes and stage wakes; zero leaves every die eligible. */
const volatile u64 cake_llc_pref_word;

static __always_inline u64 cake_deep_word(void)
{
	return cake_idle_exit_max_ns ? cake_deep_idle_word : 0;
}

/* One-word hosts with a cpuidle driver: the governor's state on entry, PWR_EVENT_EXIT on exit. */
SEC("tp_btf/cpu_idle")
int BPF_PROG(cake_cpu_idle, u32 state, u32 cpu_id)
{
	u32 c = cpu_id & (MAX_CPUS - 1);

	if (c >= CPU_WORD_BITS)
		return 0;
	if (state == (u32)-1) {
		if (cake_idle_deep[c]) {
			cake_idle_deep[c] = 0;
			__atomic_fetch_and(&cake_deep_idle_word, ~(1ULL << c), __ATOMIC_RELAXED);
		}
	} else if (state < CAKE_IDLE_STATES &&
		   cake_idle_state_ns[state] > cake_handoff_max_ns) {
		cake_idle_deep[c] = 1;
		__atomic_fetch_or(&cake_deep_idle_word, 1ULL << c, __ATOMIC_RELAXED);
	}
	return 0;
}

/* Lower rank is better. Equal/unknown platforms prune the ranked scan. */
const volatile u32 cake_rank_tiers;
/* Not rodata: a one-bit tier the verifier can read splits every claim try per core. */
u64 cpu_perf_tier[CPU_WORD_BITS] SEC(".data.cake_ranks");
const volatile u64 cpu_perf_known;

static __always_inline u64 cake_rank_tier(u64 w)
{
	u32 i;

	if (cake_rank_tiers <= 1 || (w & ~cpu_perf_known))
		return w;
	for (i = 0; i < CPU_WORD_BITS; i++) {
		u64 best;

		if (i >= cake_rank_tiers)
			break;
		best = w & cpu_perf_tier[i];
		if (best)
			return best;
	}
	return w; /* newly online/unranked CPUs remain usable */
}

/* Serializes owner and reservation-bit transitions on this CPU; no helpers under the lock. */
struct cake_seat_lock {
	struct bpf_spin_lock lock;
	u8 pad[STATE_SLOT_BYTES - sizeof(struct bpf_spin_lock)];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CPU_WORD_BITS);
	__type(key, u32);
	__type(value, struct cake_seat_lock);
} cake_seat_locks SEC(".maps");

enum { CAKE_SEAT_RELEASE, CAKE_SEAT_RUN, CAKE_SEAT_HOLD };

/* A seat: the CPU a stage thread blocked on, held for its return; apart from the dirty run slot. */
struct cake_seat_slot {
	u64 pid;	/* owner persists for retake after running clears the seat bit */
	u64 seq;	/* acquisition generation disambiguates retirement after PID reuse */
	u64 held;	/* this CPU's bit of cake_seat_word: one-CPU tests read their own line */
	u64 pad[STATE_SLOT_WORDS - 3];
};
static struct cake_seat_slot cake_seat[CPU_WORD_BITS] __attribute__((aligned(STATE_SLOT_BYTES)));
_Static_assert(sizeof(struct cake_seat_slot) == STATE_SLOT_BYTES,
	       "cake_seat_slot must preserve cache-isolation stride");

/* The mask follows the barrier, on the scaled register, or the verifier bounds it by MAX_CPUS. */
static __always_inline u64 cake_seat_pid(u32 cpu)
{
	u64 c = cpu;	/* a u32 here costs a zero-extend pair */

	barrier_var(c);
	return cake_seat[c & 63].pid;
}

/* Is @p the task the seat record of @cpu names? */
static __always_inline bool cake_seat_owner(u32 cpu, const struct task_struct *p)
{
	return cake_seat_pid(cpu) == (u64)(u32)p->pid;
}

/* Is @cpu a held seat? The CPU's own slot line, not the shared word every stage switch rewrites. */
static __always_inline bool cake_seat_held(u32 cpu)
{
	u64 c = cpu;

	barrier_var(c);	/* keep the mask on the load's register */
	return cake_seat[c & 63].held != 0;
}

/* Word RMWs relaxed: lock-prefixed or/and, not __sync's cmpxchg loop; x86: still a full barrier. */
static __always_inline u64 cake_seat_update(u32 cpu, u32 pid, u32 action, u64 seq)
{
	struct cake_seat_lock *lock;
	struct cake_seat_slot *ss;
	u64 bit;

	if (!cake_one_word || cpu >= CPU_WORD_BITS)
		return 0;
	/* No lock: HOLD and RUN hold rq(cpu); RELEASE decides on pid and seq, which RUN leaves. */
	if (action == CAKE_SEAT_RUN) {
		u64 c = cpu;

		barrier_var(c);	/* keep the mask on the store's register */
		c &= 63;
		cake_seat[c].held = 0;
		__atomic_fetch_and(&cake_seat_word, ~(1ULL << c), __ATOMIC_RELAXED);
		return 0;
	}
	lock = bpf_map_lookup_elem(&cake_seat_locks, &cpu);
	if (!lock)
		return 0;
	/* The helper can invalidate the verifier's bound on the stack key: rebound it here. */
	cpu &= 63;
	ss = &cake_seat[cpu];
	bit = 1ULL << cpu;
	bpf_spin_lock(&lock->lock);
	if (action == CAKE_SEAT_HOLD) {
		seq = ++ss->seq;
		ss->pid = pid;
		ss->held = 1;
		__atomic_fetch_or(&cake_seat_word, bit, __ATOMIC_RELAXED);
	} else if (ss->pid == pid && ss->seq == seq) {
		ss->held = 0;
		__atomic_fetch_and(&cake_seat_word, ~bit, __ATOMIC_RELAXED);
		ss->pid = 0;
	}
	bpf_spin_unlock(&lock->lock);
	return seq;
}

/* Is @cpu a seat held by a task other than @p? Counts the leak at @site. */
static __always_inline bool cake_seat_blocks(s32 cpu, const struct task_struct *p,
					     u32 site)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	if (c >= CPU_WORD_BITS || !cake_seat_held(c) ||
	    cake_seat_owner(c, p))
		return false;
	cake_stat_inc(site);
	/* A rodata read, not a constant: folds the same, but a constant adds select_cpu spills. */
	return cake_one_word != 0;
}
/* Wide hosts: actual idle occupancy, never claim availability; the serial gate counts it. */
static u64 cake_idle_words[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* PROBE scratch: the pool head this CPU is about to take is from another die. */
static u8 cake_probe_pool_x[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));

/* Expand a CPU set through the SMT map: a preference, never a reservation. */
static __always_inline u64 cake_smt_expand(u64 seats)
{
	u64 cores = seats;
	u32 i, shift = cake_smt_shift;

	/* The map factored once at startup; no-SMT maps reduce to identity. */
	if (!shift)
		return seats;
	if (shift < CPU_WORD_BITS)
		return seats | ((seats & cake_smt_left) << shift) |
		       ((seats & cake_smt_right) >> shift);

	for (i = 0; i < CPU_WORD_BITS && seats; i++) {
		u32 c = cake_ctz64(seats);
		s32 sib = cpu_sibling[c & (MAX_CPUS - 1)];

		if (sib >= 0 && sib < CPU_WORD_BITS)
			cores |= 1ULL << ((u32)sib & 63);
		seats &= seats - 1;
	}
	return cores;
}

/* Chronic IRQ preference on cores; keep the set when every choice is noisy. */
static __always_inline u64 cake_prefer_irq_clean(u64 word, u64 noisy)
{
	u64 clean = word & ~noisy;

	return clean ? clean : word;
}

/* Cold choices: whole core, seat, IRQ interference, platform rank; callers drop failed claims. */
static __always_inline s32 cake_pick_cold(u64 w, u64 cores, u64 seats, u64 noisy)
{
	u64 best;

	/* Capacity before anything: an idle little core is always a whole core. */
	if (cake_cap_tiers && (w & cake_cap_word))
		w &= cake_cap_word;
	best = w & cores;

	if (!best)
		best = w;
	if (best & ~seats)
		best &= ~seats;
	return (s32)cake_ctz64(cake_rank_tier(cake_prefer_irq_clean(best, noisy)));
}

/* Up to cake_claim_tries ranked picks from @w, each claimed or dropped; -1: every claim lost. */
static __always_inline s32 cake_claim_ranked(u64 w, u64 cores, u64 seats, u64 noisy, u32 site)
{
	u32 i;

	for (i = 0; i < cake_claim_tries && w; i++) {
		s32 c = cake_pick_cold(w, cores, seats, noisy);

		if (cake_taci(c, site))
			return c;
		w &= ~(1ULL << ((u32)c & 63));
	}
	return -1;
}

/* PROBE: the queue a placement used; the first five index the PL, H3 and H10 census rows. */
enum cake_place_kind {
	CAKE_PLACE_LOCAL,	/* select_cpu direct, own CPU */
	CAKE_PLACE_LOCAL_ON,	/* LOCAL_ON another CPU */
	CAKE_PLACE_CPUQ_WAKE,	/* a wake into a per-CPU DSQ */
	CAKE_PLACE_CPUQ_CONT,	/* a continuation into a per-CPU DSQ */
	CAKE_PLACE_POOL,	/* an LLC wake pool */
	CAKE_PLACE_SELF,	/* LOCAL_ON to the calling CPU */
	CAKE_PLACE_HOME_BUSY,	/* a home claim on a CPU that runs a task */
};
_Static_assert(CAKE_STAT_PL_GLOBAL - CAKE_STAT_PL_LOCAL == CAKE_PLACE_POOL &&
	       CAKE_STAT_H3_GLOBAL - CAKE_STAT_H3_LOCAL == CAKE_PLACE_POOL &&
	       CAKE_STAT_H10_GLOBAL - CAKE_STAT_H10_LOCAL == CAKE_PLACE_POOL,
	       "census rows follow cake_place_kind");

/* PROBE hold attribution -- not for scoring. */
struct cake_probe_tag {
	u64 place_ns;
	u32 kind;
	u32 target;		/* dsq id low bits (cpu) */
	u32 caller;		/* placing CPU */
	u32 waker_pid;
	u64 seats, core_free, idle_word;
};

/* PROBE black box: the placement context of the last waits > 10 ms. */
struct cake_bb_rec {
	u64 wait_ns, place_ns, seats, core_free, idle_word;
	u32 pid, kind, target, caller, waker_pid, ran_on;
	char comm[16];
};
struct cake_bb_rec cake_blackbox[4];
u32 cake_blackbox_n;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_probe_tag);
} cake_probe_tags SEC(".maps");

/* Slot-aligned: unaligned it false-shared cake_seat_word's line under probe=1. */
static u32 cake_probe_busy_flag[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));

static __noinline void cake_probe_place(struct task_struct *p, u64 dsq_id,
					u64 enq_flags)
{
	struct cake_probe_tag *t;
	u32 kind;
	u32 me;

	me = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

	if (!(dsq_id & CAKE_DSQ_LOCAL_ON) && dsq_id >= (u64)LLC_WAKE_DSQ_BASE &&
	    dsq_id < (u64)LLC_WAKE_DSQ_BASE + MAX_LLCS)
		kind = CAKE_PLACE_POOL;
	else if (dsq_id & CAKE_DSQ_LOCAL_ON)
		kind = ((u32)dsq_id & (MAX_CPUS - 1)) ==
		       (bpf_get_smp_processor_id() & (MAX_CPUS - 1)) ?
		       CAKE_PLACE_SELF : CAKE_PLACE_LOCAL_ON;
	else if (dsq_id == CAKE_DSQ_LOCAL)
		kind = CAKE_PLACE_LOCAL;
	else
		kind = (enq_flags & CAKE_ENQ_WAKEUP) ? CAKE_PLACE_CPUQ_WAKE : CAKE_PLACE_CPUQ_CONT;
	t = bpf_task_storage_get(&cake_probe_tags, p, 0, 0);
	if (!t)
		return;
	t->place_ns = cake_now_rq(CAKE_SITE_KT_PROBE);
	t->target = (u32)dsq_id & (MAX_CPUS - 1);
	t->caller = me;
	{
		struct task_struct *w = bpf_get_current_task_btf();

		t->waker_pid = w ? (u32)w->pid : 0;
	}
	t->seats = cake_seat_word; t->core_free = cake_core_word();
	t->idle_word = cake_idle_word();
	if (cake_probe_busy_flag[me]) {
		kind = CAKE_PLACE_HOME_BUSY;
		cake_probe_busy_flag[me] = 0;
	}
	t->kind = kind;
	if (kind == CAKE_PLACE_HOME_BUSY)
		return;
	cake_stat_inc(kind == CAKE_PLACE_SELF ? CAKE_STAT_PL_SELF : CAKE_STAT_PL_LOCAL + kind);
}

/* Grant @hc still holds on @tcpu: CAKE_GRANT_VACANT if mid-switch or torn, else what is left. */
#define CAKE_GRANT_VACANT (~0ULL)

static __always_inline u64 cake_grant_left(struct task_struct *hc, s32 tcpu)
{
	struct cake_run_slot *rs = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	u64 ran;

	if (rs->pid != (u64)(u32)hc->pid)
		return CAKE_GRANT_VACANT;
	barrier();	/* owner before stamp */
	ran = time_delta(cake_now_rq(CAKE_SITE_KT_OCCUPANT), rs->stamp);
	return ran >= rs->grant ? 0 : rs->grant - ran;
}

/* PROBE: the occupant's remaining grant, in tick bands, behind a pooled wake. */
static __noinline void cake_probe_grant(struct task_struct *hc, s32 tcpu)
{
	u64 rem = cake_grant_left(hc, tcpu);

	if (rem == CAKE_GRANT_VACANT)
		cake_stat_inc_cold(CAKE_SITE_GRANT_VACANT);
	else if (!rem)
		cake_stat_inc_cold(CAKE_SITE_GRANT_EXPIRED);
	else
		cake_stat_inc_cold(cake_tick_ns && rem < cake_tick_ns ?
				   CAKE_SITE_GRANT_LT_TICK : CAKE_SITE_GRANT_GE_TICK);
}

/* PROBE (hold attribution): charge the placement-to-run wait to its queue kind; log long waits. */
static __noinline void cake_probe_run(struct task_struct *p)
{
	/* Running's clock, from the slot it stamped before this call. */
	u64 now = cake.run[(u32)p->thread_info.cpu & (MAX_CPUS - 1)].stamp;
	struct cake_probe_tag *t;
	u64 wait;

	t = bpf_task_storage_get(&cake_probe_tags, p, 0, 0);
	if (!t || !t->place_ns)
		return;
	wait = time_delta(now, t->place_ns);
	if (wait > 10 * NSEC_PER_MSEC) {
		/* Not relaxed: LLVM 20 to 23 drop the fetch of a relaxed add. */
		u32 i = __sync_fetch_and_add(&cake_blackbox_n, 1) & 3;
		struct cake_bb_rec *b = &cake_blackbox[i];

		b->wait_ns = wait; b->place_ns = t->place_ns; b->seats = t->seats;
		b->core_free = t->core_free;
		b->idle_word = t->idle_word; b->pid = (u32)p->pid; b->kind = t->kind;
		b->target = t->target; b->caller = t->caller; b->waker_pid = t->waker_pid;
		b->ran_on = (u32)p->thread_info.cpu;
		__builtin_memcpy(b->comm, p->comm, 16);
	}
	t->place_ns = 0;
	if (wait > 300 * NSEC_PER_USEC)
		cake_stat_inc(t->kind == CAKE_PLACE_HOME_BUSY ? CAKE_STAT_H3_HOME_BUSY :
			      t->kind == CAKE_PLACE_SELF ? CAKE_STAT_H3_SELF :
			      CAKE_STAT_H3_LOCAL + (t->kind & 7));
	if (wait > 1000 * NSEC_PER_USEC && t->kind != CAKE_PLACE_HOME_BUSY)
		cake_stat_inc(t->kind == CAKE_PLACE_SELF ? CAKE_STAT_H10_SELF :
			      CAKE_STAT_H10_LOCAL + (t->kind & 7));
}

/* Task storage follows the task across kernel refills of its slice. */
struct cake_groove {
	u16 seat_cpu; /* owned CPU + 1, including retained retake identity */
	u16 pool_tag; /* LLC + 1 while this task owns a pending token */
	u32 seat_pid; /* identity used at acquisition; nonleader exec changes pid */
	u64 seat_seq; /* release only this acquisition, including after PID reuse */
	u64 win_t;    /* share window start */
	u64 win_exec; /* sum_exec_runtime at the window start */
};

/* Seat holders by pid: ops.running reads one word so a non-holder skips the task-storage lookup. */
static u32 cake_seat_holders[SEAT_HOLDER_SLOTS] __attribute__((aligned(STATE_SLOT_BYTES)));
_Static_assert((SEAT_HOLDER_SLOTS & (SEAT_HOLDER_SLOTS - 1)) == 0,
	       "the holder census indexes by a pid mask");

static __always_inline u32 *cake_seat_holder(u32 pid)
{
	return &cake_seat_holders[pid & (SEAT_HOLDER_SLOTS - 1)];
}

/* A task's callbacks serialize its storage; seat replacement elsewhere is not, hence the lock. */
static __always_inline void cake_seat_retire(struct cake_groove *gr, u32 pid,
					    u32 keep_cpu_plus_one)
{
	if (gr && gr->seat_cpu &&
	    (gr->seat_cpu != keep_cpu_plus_one || gr->seat_pid != pid)) {
		cake_seat_update((u32)gr->seat_cpu - 1, gr->seat_pid,
				 CAKE_SEAT_RELEASE, gr->seat_seq);
		gr->seat_cpu = 0;
		__sync_fetch_and_sub(cake_seat_holder(gr->seat_pid), 1);
	}
}

/* Clear, then recheck: a producer inserts before its mark, so one of the two keeps it visible. */
static __noinline void cake_wake_mark_retire(u32 llc)
{
	u32 l = llc & (MAX_LLCS - 1);

	if (!cake.pool[l].mark)
		return;
	__atomic_exchange_n(&cake.pool[l].mark, 0, __ATOMIC_SEQ_CST);
	if (cake_nrq(cake_pool_dsq(l)))
		cake_wake_mark_set(l);
}

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_groove);
} cake_grooves SEC(".maps");

/* Lookup only: a create allocates, and the allocator may wake a kworker under the rq lock. */
static __always_inline struct cake_groove *cake_groove_of(struct task_struct *p)
{
	if (unlikely(cake_tog_probe)) {
		cake_stat_inc_cold(CAKE_SITE_TASK_STORAGE);
		return CAKE_TIMED_COLD(CAKE_SITE_T_TASK_STORAGE,
				       bpf_task_storage_get(&cake_grooves, p, 0, 0));
	}
	return bpf_task_storage_get(&cake_grooves, p, 0, 0);
}

static __always_inline void cake_pool_retire(struct task_struct *p, struct cake_groove *gr)
{
	u32 tag = gr ? gr->pool_tag : 0;

	if (!tag)
		return;
	gr->pool_tag = 0;
	cake_pool_pending_dec(tag - 1);
	if ((p->scx.slice & CAKE_POOL_TAG_MASK) == tag)
		p->scx.slice &= ~(u64)CAKE_POOL_TAG_MASK;
}

static __noinline void cake_pool_retire_task(struct task_struct *p)
{
	cake_pool_retire(p, bpf_task_storage_get(&cake_grooves, p, 0, 0));
}

static __always_inline void cake_pool_seen(struct task_struct *p)
{
	if (p->scx.slice & CAKE_POOL_TAG_MASK)
		cake_pool_retire_task(p);
}

/* Publish the token before an idle CPU can observe the insert. */
static __noinline void cake_pool_insert(struct task_struct *p, s32 tcpu,
					u64 slice, u64 vt, u64 flags)
{
	u32 llc = cake_llc_of(tcpu);
	struct cake_groove *gr = cake_groove_of(p);

	if (!gr) {
		cake_dsq_insert(p, SCX_DSQ_GLOBAL, slice, flags);
		return;
	}
	if (gr->pool_tag)
		cake_pool_retire(p, gr);
	gr->pool_tag = llc + 1;
	cake_pool_pending_inc(llc);
	cake_dsq_insert_vtime(p, cake_pool_dsq(llc), cake_pool_tag(slice, llc), vt, flags);
	cake_wake_mark_set(llc);
}

static __noinline u64 cake_task_slice(struct task_struct *p __arg_trusted);
static __noinline s32 cake_pick_idle_clean(struct task_struct *p __arg_trusted);
static __noinline s32 cake_claim_free(u64 free);

/* One core bit for both SMT threads: one home per core. */
static __always_inline u64 cake_home_core_bit(u32 cpu)
{
	s32 sib = cpu_sibling[cpu & (MAX_CPUS - 1)];

	if (sib >= 0 && (u32)sib < cpu)
		cpu = (u32)sib;
	return 1ULL << (cpu & 63);
}

/* Drop @cpu's home if @val still owns it. */
static __noinline void cake_home_drop(u32 cpu, u64 val)
{
	u32 c = cpu & (CPU_WORD_BITS - 1);

	if (!val || !__sync_bool_compare_and_swap(&cake_home_val[c], val, 0))
		return;
	__sync_bool_compare_and_swap(&cake_home[(val >> 8) & (HOME_SLOTS - 1)], val, 0);
	__atomic_fetch_and(&cake_home_cores, ~cake_home_core_bit(c), __ATOMIC_RELAXED);
}

/* Drop the home @p owns, if any. */
static __always_inline void cake_home_leave(const struct task_struct *p)
{
	s32 h = cake_home_cpu(p);

	if (h >= 0)
		cake_home_drop((u32)h, ((u64)(u32)p->pid << 8) | (u32)(h + 1));
}

/* Share sample at a block: claim this CPU as home when busy, give it up when not. */
static __noinline void cake_home_sample(struct task_struct *p __arg_trusted, u32 cpu)
{
	struct cake_groove *gr = cake_groove_of(p);
	u32 c = cpu & (CPU_WORD_BITS - 1);
	u64 now, el, ran, bit, val, old, best, free, pref;
	s32 h, sib;

	if (!gr)
		return;
	now = bpf_ktime_get_ns();
	el = now - gr->win_t;
	if (el < HOME_WINDOW_NS)
		return;
	ran = p->se.sum_exec_runtime - gr->win_exec;
	gr->win_t = now;
	gr->win_exec = p->se.sum_exec_runtime;
	if (now - cake_home_census_t > HOME_CENSUS_WINDOWS * HOME_WINDOW_NS) {
		/* One home per core: online CPUs less the second SMT threads. */
		cake_home_crowded = cake_home_census >
			HOME_CENSUS_WINDOWS * (nr_cpu_online3 / 3 - cake_popcnt64(cake_smt_right));
		cake_home_census = 0;
		cake_home_census_t = now;
	}
	if (ran * HOME_ON_DIV >= el)
		cake_home_census++;
	h = cake_home_cpu(p);
	if (h >= 0) {
		if (ran * HOME_OFF_DIV < el || cake_home_crowded || !cake_allowed(p, h))
			cake_home_leave(p);
		else
			cake_home_seen[(u32)h & (CPU_WORD_BITS - 1)] = now;
		return;
	}
	if (ran * HOME_ON_DIV < el || cake_home_crowded || p->nr_cpus_allowed == 1)
		return;
	free = p->cpus_ptr->bits[0];
	pref = cake_llc_pref_word;
	if (pref) {
		u64 allowed = free;

		/* Keep secondary threads available when affinity excludes the primary. */
		free &= ~cake_smt_expand(cake_home_cores) & ~cpu_irq_hot_words[0];
		if (!free && !(allowed & (1ULL << c)))
			return;
		if (free & pref)
			free &= pref;
	} else {
		free &= ~cake_home_cores & ~cake_smt_right;
	}
	best = cake_rank_tier(free);
	if (best && !(best & (pref ? 1ULL << c : cake_home_core_bit(c))))
		c = cake_ctz64(best);
	/* The verifier needs the bound on the value it indexes with. */
	barrier_var(c);
	c &= CPU_WORD_BITS - 1;
	if (cake_cpu_irq_bad((s32)c))
		return;
	bit = cake_home_core_bit(c);
	if (cake_home_cores & bit) {
		/* A home whose owner stopped sampling is free again. */
		sib = cpu_sibling[c & (MAX_CPUS - 1)];
		old = cake_home_val[c];
		if (old && now - cake_home_seen[c] > HOME_STALE_NS)
			cake_home_drop(c, old);
		if (sib >= 0 && (u32)sib < CPU_WORD_BITS) {
			old = cake_home_val[(u32)sib & (CPU_WORD_BITS - 1)];
			if (old && now - cake_home_seen[(u32)sib & (CPU_WORD_BITS - 1)] > HOME_STALE_NS)
				cake_home_drop((u32)sib, old);
		}
	}
	if (__atomic_fetch_or(&cake_home_cores, bit, __ATOMIC_RELAXED) & bit)
		return;
	val = ((u64)(u32)p->pid << 8) | (c + 1);
	if (!__sync_bool_compare_and_swap(&cake_home[(u32)p->pid & (HOME_SLOTS - 1)], 0, val)) {
		__atomic_fetch_and(&cake_home_cores, ~bit, __ATOMIC_RELAXED);
		return;
	}
	cake_home_seen[c] = now;
	cake_home_val[c] = val;
}

/* A wakee's wait behind a fresh occupant, capped by its own slice; own frame: two call sites. */
static __noinline u64 cake_wake_protect(u32 protect_shift, u64 slice)
{
	u64 protect = (u64)SLICE_NS >> protect_shift;

	return slice < protect ? slice : protect;
}

/* The occupant yields past @protect if @p beats its LIVE vtime (dsq_vtime lags until stopping). */
static __noinline bool cake_wake_preempt(struct task_struct *p, struct task_struct *curr,
					 s32 tcpu, u64 protect, u64 now)
{
	u64 ran = 0;
	u64 live = cake_occupant_live_of(curr, tcpu, now, &ran);

	/* PROBE: the gate refusing a microsecond successor; the guard drops the task reads. */
	if (cake_tog_probe) {
		u64 se = p->se.sum_exec_runtime;
		u64 n = p->nvcsw | 1;

		cake_stat_inc(CAKE_STAT_WP_ATTEMPT);
		if (!((4096 | n) >> 32) && se < 4096 * n)
			cake_stat_inc(CAKE_STAT_WP_TINY);
		if (!((65536 | n) >> 32) && se < 65536 * n)
			cake_stat_inc(CAKE_STAT_WP_SMALL);
	}

	if (!live)
		return false;
	if (ran < protect) {
		cake_stat_inc(CAKE_STAT_WP_PROTECT);
		return false;
	}
	if (!time_before(p->scx.dsq_vtime, live)) {
		cake_stat_inc(CAKE_STAT_WP_VTIME);
		return false;
	}

	/* Never preempt a starved occupant; tested last so rejections stay cheap. */
	if (curr && cake_starved(curr)) {
		cake_stat_inc(CAKE_STAT_WP_STARVED);
		return false;
	}
	/* Never evict a stage on its own seat, though every gate above elects its high vtime. */
	if (curr && (u32)tcpu < CPU_WORD_BITS && cake_seat_owner((u32)tcpu, curr)) {
		cake_stat_inc(CAKE_SITE_SEAT_IMMUNE);
		return false;
	}

	cake_stat_inc(CAKE_STAT_WP_FIRED);
	return true;
}

/* Narrow hosts: claim an idle core (@cores is an old snapshot), then a thread; -1: to the pool. */
static __noinline s32 cake_claim_warm(struct task_struct *p __arg_trusted, u64 cores)
{
	u32 prev = (u32)p->thread_info.cpu & (MAX_CPUS - 1);
	u64 w, seats, preferred, noisy;
	s32 c;

	if (!cake_one_word)
		return -1;
	w = cake_idle_word() & p->cpus_ptr->bits[0];
	if (cake_multi_llc()) {
		u64 pref = cake_llc_pref_word;

		if (cake_stage(p)) {
			/* A stage thread off the preferred die re-homes if a core is free there. */
			if (pref && !(cpu_llc_word[prev] & pref) && (w & pref & cores)) {
				c = cake_pick_cold(w & pref, cores, cake_smt_expand(cake_seat_word),
						   cpu_irq_hot_cores[0] | cake_deep_word());
				if (cake_taci(c, CAKE_SITE_TACI_WARM))
					return c;
			}
		} else {
			/* A worker follows its waker's die, where the data is. */
			prev = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
		}
	}
	w &= cpu_llc_word[prev];
	if (!w)
		return -1;
	cores &= w;
	/* One IRQ snapshot per search, expanded to cores by the loader. */
	noisy = cpu_irq_hot_cores[0] | cake_deep_word();
	seats = cake_seat_word;
	if (prev < CPU_WORD_BITS && cake_seat_owner(prev, p))
		seats &= ~(1ULL << prev);
	seats = cake_smt_expand(seats);
	preferred = cores & ~seats;
	if (!preferred)
		preferred = cores;
	preferred = cake_prefer_irq_clean(preferred, noisy);
	/* The task's own core first when preferred: without it main threads migrate more. */
	if (prev < CPU_WORD_BITS && (preferred & (1ULL << prev))) {
		if (cake_taci((s32)prev, CAKE_SITE_TACI_GROOVE))
			return (s32)prev;
		w &= ~(1ULL << prev);
	}
	/* A failed preferred claim cannot discard less-preferred idle CPUs. */
	return cake_claim_ranked(w, cores, seats, noisy, CAKE_SITE_TACI_WARM);
}

/* Co-location's bet: at least 3/4 of the waker's die idle; wide hosts: the machine-wide count. */
static __noinline bool cake_system_serial(u32 wc)
{
	u32 c = wc & (MAX_CPUS - 1);
	u32 i, n = 0;

	if (cake_one_word)
		return cake_popcnt64(cake_idle_word() & cpu_llc_word[c]) * 4 >=
		       cpu_llc_online3[c];
	for (i = 0; i < QMASK_WORDS; i++) {
		if ((i << 6) >= nr_cpu_span)
			break;
		n += cake_popcnt64(cake_idle_words[i]);
	}
	return n * 4 >= nr_cpu_online3;
}

/* The serial gate's first call, counted as reached; not inline in select_cpu (see cake_tried). */
static __noinline bool cake_system_serial_tried(u32 wc)
{
	cake_tried_inc(wc, CAKE_TRIED_SERIAL);
	return cake_system_serial(wc);
}

/* Is the occupant within one handoff of its mean burst end? nrq counts only waiters. */
static __noinline bool cake_handoff_yields(s32 tcpu)
{
	struct task_struct *curr = cake_cpu_curr(tcpu);
	struct cake_run_slot *rs = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	u64 ran, burst, lim, n;

	/* Non-SCX state cannot prove the occupant will yield; nor can a slot it does not own. */
	if (!curr || !(curr->scx.flags & CAKE_TASK_QUEUED) || !curr->scx.dsq_vtime)
		return false;
	barrier();	/* vtime before owner */
	if (rs->pid != (u64)(u32)curr->pid)
		return false;
	barrier();	/* owner before stamp */

	ran = time_delta(cake_now_rq(CAKE_SITE_KT_HANDOFF), rs->stamp);
	n = curr->nvcsw | 1;
	lim = ran + cake_handoff_max_ns;

	if (!((lim | n) >> 32))
		return curr->se.sum_exec_runtime < lim * n;

	burst = cake_burst_ns(curr);
	return burst <= ran || burst - ran < cake_handoff_max_ns;
}

/* Keep the quotient for admission. The grant rounds away the doubled burst's low-bit correction. */
static __always_inline u64 cake_slice_from_service(u64 runtime, u64 age, u64 n,
						   u64 *q_out)
{
	u64 cycle_budget = age >> PERIOD_SLICE_CAP_SHIFT;
	u64 work = cycle_budget >> 1;
	u64 q, want;
	u64 cap = (u64)SLICE_NS >> PERIOD_SLICE_CAP_SHIFT;

	if (runtime < work)
		work = runtime;
	q = work / n;
	*q_out = q;
	_Static_assert(!(SLICE_NS & 1) && (CAKE_POOL_TAG_MASK & 1),
		       "the compute threshold and grant mask must ignore bit zero");
	want = q << 1;

	/* A grant that wants a whole slice is a compute task's. */
	if (want >= SLICE_NS)
		cap >>= 1;
	if (want > cap)
		want = cap;
	if (want < cake_handoff_max_ns)
		want = cake_handoff_max_ns;
	/* The low bits are the pool tag's (cake_pool_tag): zero on every grant. */
	return want & ~(u64)CAKE_POOL_TAG_MASK;
}

/* Twice the mean burst, capped at half the mean cycle and the slice, floored at the handoff. */
static __noinline u64 cake_task_slice(struct task_struct *p __arg_trusted)
{
	u64 age = cake_task_age(p, CAKE_SITE_KT_PERIOD);
	u64 q;

	if (age < SLICE_NS)
		age = SLICE_NS;
	return cake_slice_from_service(p->se.sum_exec_runtime, age, p->nvcsw | 1, &q);
}

/* Three quarters of the unused slice, as two shifts. */
#define CAKE_SLEEPER_DOSE(unused) (((unused) >> 1) + ((unused) >> 2))	/* 3/4 */

static __always_inline u64 cake_sleeper_dose(u64 unused)
{
	return CAKE_SLEEPER_DOSE(unused);
}

/* Half the watchdog bounds the key window; the rest is drain, tick, clock skew and RT hold. */
#define CAKE_KEY_BUDGET_NS ((u64)WATCHDOG_TIMEOUT_MS * NSEC_PER_MSEC / 2)
/* Keys a wait crosses: cap max, the sleeper floor, own/pool hysteresis (cake_dispatch), grain. */
#define CAKE_FLOOR_WINDOW_NS (CAKE_VTIME_CAP_MAX_NS + 2 * (u64)SLICE_NS +		\
			      CAKE_SLEEPER_DOSE((u64)SLICE_NS) + FRONTIER_GRAIN_NS)
_Static_assert((CAKE_FLOOR_WINDOW_NS << RATE_FLOOR_SHIFT) <= CAKE_KEY_BUDGET_NS,
	       "the floor crosses the key window within its watchdog share");
_Static_assert((CAKE_FLOOR_WINDOW_NS << (RATE_FLOOR_SHIFT + 1)) > CAKE_KEY_BUDGET_NS,
	       "RATE_FLOOR_SHIFT is the largest shift that fits");

/* Grant and key from one load set; deeper floor starved-only: ungated, a worker beats a stage. */
static __always_inline u64 cake_admit_frame(struct task_struct *p, u64 *vt)
{
	u64 age = cake_task_age(p, CAKE_SITE_KT_PERIOD);
	u64 runtime = p->se.sum_exec_runtime;
	u64 n = p->nvcsw | 1;
	u64 q, slice, depth = 0, lo;

	if (age < SLICE_NS)
		age = SLICE_NS;
	slice = cake_slice_from_service(runtime, age, n, &q);
	if (cake_starved(p)) {
		u64 burst = runtime <= ((age >> PERIOD_SLICE_CAP_SHIFT) >> 1) ?
			    q : runtime / n;

		if (burst < SLICE_NS)
			depth = cake_sleeper_dose(SLICE_NS - burst);
	}
	lo = cake.frontier.word - SLICE_NS - depth;
	*vt = lo + cake_delta_clamp(p->scx.dsq_vtime - lo);
	return slice;
}

/* The undecided wake: key beside the grant; the insert ending the route stamps it. */
static __noinline u64 cake_wake_admit(struct task_struct *p __arg_trusted, u64 *vt)
{
	return cake_admit_frame(p, vt);
}

/* dsq_insert() takes no vtime: stamp or a sleeper keeps an old key. Own frame, no slot per site. */
static __noinline u64 cake_admit_direct(struct task_struct *p __arg_trusted)
{
	u64 vt;
	u64 slice = cake_admit_frame(p, &vt);

	p->scx.dsq_vtime = vt;
	return slice;
}

/* Home holds a well-served peer: claim here, as enqueue's claim costs two rq-lock switches. */
static __noinline s32 cake_select_undecided(struct task_struct *p __arg_trusted,
					    s32 prev_cpu)
{
	struct task_struct *hc;
	s32 idle;

	if (prev_cpu < 0 || (p->flags & PF_KTHREAD) || cake_starved_turn(p))
		return prev_cpu;
	hc = cake_cpu_curr(prev_cpu);
	if (!hc || hc == p || (hc->flags & PF_IDLE) || cake_starved(hc))
		return prev_cpu;
	idle = cake_pick_idle_clean(p);
	if (idle < 0)
		return prev_cpu;	/* enqueue routes it (the pool) */
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)idle, cake_admit_direct(p),
			CAKE_ENQ_IMMED);
	cake_stat_inc(CAKE_STAT_SELECT_DIRECT);
	return idle;
}

/* ops.select_cpu: claimed idle CPU, admitted busy home, or prev_cpu, which ops.enqueue pools. */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool device_wake = cake_signal_wake(p, wake_flags & CAKE_WAKE_TTWU);
	bool stage;
	/* A busy/ineligible home is not a warm-half candidate. */
	bool home_askable = false, seat_blocked;
	u32 home_decline = CAKE_STAT_HD_SYNC;
	u64 cores = 0;
	u64 flags;
	s32 c;
	s32 home = cake_one_word && !cake_home_crowded ? cake_home_cpu(p) : -1;

	cake_stat_inc(CAKE_STAT_SELECT);

	/* Serial handoff, no preempt. SYNC collapses pipes; an ISR wake looks like a handoff. */
	{
		u32 wc = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
		struct cake_run_slot *wr = &cake.run[wc];
		bool serial = ((wr->hint >> CAKE_HINT_CONF_SHIFT) &
			       CAKE_HINT_CONF_MAX) >= CAKE_HINT_CONF_MAX;

		if (!device_wake && !(wr->hint & CAKE_HINT_WOKE))
			wr->hint |= CAKE_HINT_WOKE;

		/* No core-contended veto: it exiled mutex pairs from co-location. */
		if (!device_wake && serial && !(wake_flags & CAKE_WAKE_SYNC) &&
		    !cake_cpu_irq_bad((s32)wc) &&
		    cake_allowed(p, (s32)wc) &&
		    cake_system_serial_tried(wc) &&
		    cake_cpu_dsq_idle(wc) &&
		    !cake_local_nr((s32)wc) &&
		    cake_handoff_yields((s32)wc)) {
			if (unlikely(cake_tog_probe)) {
				cake_stat_inc_cold(CAKE_STAT_SERIAL);
				cake_probe_x(CAKE_SITE_SERIAL_X, prev_cpu, (s32)wc);
			}
			c = (s32)wc;
			flags = 0;
			goto place;
		}
	}

	/* Return to a fixed home when its occupant can give up the CPU. */
	if (home >= 0 && cake_allowed(p, home)) {
		c = home;
		flags = 0;
		if (cake_taci(home, CAKE_SITE_TACI_WARM)) {
			flags = CAKE_ENQ_IMMED;
		} else {
			struct task_struct *hc = cake_cpu_curr_retake(home);

			if (hc && hc != p && !(hc->flags & PF_IDLE) &&
			    !(hc->scx.flags & CAKE_TASK_QUEUED)) {
				/* A higher class may already have drained the local DSQ. */
				u64 free = cake_idle_word() & p->cpus_ptr->bits[0] &
					   ~(1ULL << ((u32)home & 63));
				u64 near = free & cpu_llc_word[(u32)home & (MAX_CPUS - 1)];

				if (!free)
					return prev_cpu;
				c = cake_claim_free(near ? near : free);
				if (c < 0)
					return prev_cpu;	/* ops.enqueue can use a stealable queue */
				flags = CAKE_ENQ_IMMED;
				goto place;
			}

			/*
			 * A lost claim under the idle task: another task is already
			 * queued here, so the owner goes to the head. An unreadable
			 * occupant is mid-switch: preempt whatever lands.
			 */
			if (!hc || (hc != p && (hc->nr_cpus_allowed > 1 || (hc->flags & PF_IDLE)))) {
				cake.run[(u32)home & (MAX_CPUS - 1)].retake = 1;
				flags = CAKE_ENQ_PREEMPT;
			}
		}
		goto place;
	}

	/* Serial placement above needs neither groove storage nor stage class. */
	stage = cake_stage(p);

	/* Seat retake from a non-stage occupant; a bit still up: nothing ran, no occupant read. */
	if (stage && prev_cpu >= 0 && (u32)prev_cpu < CPU_WORD_BITS &&
	    !cake_seat_held((u32)prev_cpu) &&
	    cake_seat_owner((u32)prev_cpu, p) &&
	    !cake_cpu_irq_bad(prev_cpu) &&
	    cake_allowed(p, prev_cpu)) {
		struct task_struct *hc = cake_cpu_curr_retake(prev_cpu);

		/* Retake needs eligibility, not a price: read one occupant. */
		if (hc && (hc->scx.flags & CAKE_TASK_QUEUED) &&
		    hc->scx.dsq_vtime && hc != p && hc->nr_cpus_allowed > 1 &&
		    !cake_stage(hc)) {
			cake.run[(u32)prev_cpu & (MAX_CPUS - 1)].retake = 1;
			/* ENQ_PREEMPT evicts under enqueue's rq lock; a kick locks it twice. */
			cake_stat_inc(CAKE_SITE_SEAT_RETAKE);
			c = prev_cpu;
			flags = CAKE_ENQ_PREEMPT;
			goto place;
		}
	}

	/* One whole-core snapshot for home test and warm claim; the atomic claim decides. */
	if (cake_one_word)
		cores = cake_core_word();
	if (cake_one_word && prev_cpu >= 0 &&
	    (!(wake_flags & CAKE_WAKE_SYNC) || stage) &&
	    cake_core_busy(cores, prev_cpu)) {
		/* PROBE: the exile a one-word host could not count. */
		if (stage)
			cake_stat_inc(CAKE_STAT_HD_COREBUSY);
		goto skip_home;
	}
	/* Another task's held seat is not this task's home. */
	seat_blocked = prev_cpu >= 0 &&
		       cake_seat_blocks(prev_cpu, p, CAKE_SITE_LEAK_HOME);
	if (cake_tog_probe && stage && prev_cpu >= 0 && !seat_blocked)
		cake_stat_inc(CAKE_SITE_STAGE_PROBE);
	/* Warm home, not on a contended core; a stage keeps it on SYNC: L1 beats the waker's. */
	if ((!(wake_flags & CAKE_WAKE_SYNC) || stage) &&
	    prev_cpu >= 0 && !seat_blocked) {
		if (cake_starved_turn(p) && !cake_subhandoff(p))
			home_decline = CAKE_STAT_HD_STARVED;
		/* The thread, not the core: a sibling pays less than a cold home. */
		else if (cake_cpu_irq_bad(prev_cpu))
			home_decline = CAKE_STAT_HD_IRQ;
		else if (!cake_allowed(p, prev_cpu))
			home_decline = CAKE_STAT_HD_AFF;
		else {
			home_askable = true;
			home_decline = !cake_one_word && cake_core_contended(prev_cpu) ?
				CAKE_STAT_HD_CONTENDED : CAKE_STAT_HD_NOTIDLE;
		}
	}
	if (home_askable && home_decline != CAKE_STAT_HD_CONTENDED &&
	    cake_taci(prev_cpu, CAKE_SITE_TACI_HOME)) {

		if (cake_tog_probe) {	/* PROBE: is the claimed CPU actually running someone? */
			struct task_struct *hc = cake_cpu_curr(prev_cpu);
			u32 me = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

			if (hc && hc->pid) {
				cake_stat_inc(CAKE_STAT_HOME_BUSY);
				cake_probe_busy_flag[me] = 1;
			}
			if (cake_nrq(CAKE_DSQ_LOCAL_ON | (u32)prev_cpu) > 0)
				cake_stat_inc(CAKE_STAT_HOME_LOCALQ);
		}
		cake_stat_inc(CAKE_STAT_HOME);
		c = prev_cpu;
		flags = CAKE_ENQ_IMMED;
		goto place;
	}
	if (cake_tog_probe && stage && prev_cpu >= 0 && !seat_blocked)
		cake_stat_inc(home_decline);
skip_home:

	/* Claimed warm placement or the pool; nothing unclaimed below. */
	c = cake_claim_warm(p, cores);

	if (c < 0)
		return cake_select_undecided(p, prev_cpu);
	if (cake_tog_probe)
		cake_probe_x(CAKE_SITE_CLAIM_X, prev_cpu, c);
	flags = CAKE_ENQ_IMMED;
place:
	/* One insert for every decided arm. */
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)c, cake_admit_direct(p), flags);
	return c;
}

/* Idle pick retrying away from loud or mid-handler CPUs; a bad one still beats queueing. */
static __noinline s32 cake_pick_idle_clean(struct task_struct *p __arg_trusted)
{
	s32 cpu;

	if (cake_one_word) {
		u32 prev = (u32)p->thread_info.cpu & (MAX_CPUS - 1);
		u64 w = cake_idle_word() & p->cpus_ptr->bits[0] & cpu_llc_word[prev];
		u64 cores;
		u64 seats;
		u64 noisy;
		u64 now;
		u64 rejected = 0;
		u32 i;

		/* An empty snapshot ends this search: no ranking or IRQ reads on it. */
		if (!w)
			return -1;
		cores = cake_core_word() & w;
		seats = cake_smt_expand(cake_seat_word);
		noisy = cpu_irq_hot_cores[0] | cake_deep_word();
		now = cake_tick_clock();

		/* Loud or mid-handler, then about to tick; each reject counted on its own. */
		for (i = 0; i < cake_claim_tries && w; i++) {
			cpu = cake_pick_cold(w, cores, seats, noisy);
			w &= ~(1ULL << cpu);
			if (cake_cpu_irq_bad(cpu)) {
				cake_stat_inc(CAKE_SITE_REJ_IRQ);
				rejected |= 1ULL << cpu;
			} else {
				cake_tried_inc(bpf_get_smp_processor_id(), CAKE_TRIED_TICK);
				if (cake_cpu_tick_soon(cpu, now)) {
					cake_stat_inc(CAKE_SITE_REJ_TICK);
					rejected |= 1ULL << cpu;
				} else if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY)) {
					return cpu;
				}
			}
		}
		/* A preference: never strand work on a die left noisy, reserved or partial. */
		cpu = cake_claim_ranked(w | rejected, cores, seats, noisy,
					CAKE_SITE_TACI_NOTIFY);
		if (cpu >= 0)
			return cpu;
		/* A die-local pool is offered remotely by its caller. */
		if (cake_multi_llc())
			return -1;
		/* Claims lost past the tries: any idle CPU, a whole core first. */
		w = cake_idle_word() & p->cpus_ptr->bits[0];
		cores = cake_core_word() & w;
		for (i = 0; i < CPU_WORD_BITS && w; i++) {
			cpu = (s32)cake_ctz64(cores ? cores : w);
			if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY))
				return cpu;
			w &= ~(1ULL << ((u32)cpu & 63));
			cores &= w;
		}
		return -1;
	}

	/* Kernel fallback covers wide hosts. */
	cpu = cake_pick_idle(p->cpus_ptr, CAKE_PICK_IDLE_CORE);
	if (cpu < 0)
		cpu = cake_pick_idle(p->cpus_ptr, 0);
	return cpu;
}

/* Claim one CPU of @free; an unclaimed kick races direct placement. */
static __noinline s32 cake_claim_free(u64 free)
{
	u64 cores = cake_core_word();
	u64 seats = cake_smt_expand(cake_seat_word);
	u64 noisy = cpu_irq_hot_cores[0];

	return cake_claim_ranked(free, cores, seats, noisy, CAKE_SITE_TACI_NOTIFY);
}

/* No local idle winner: offer one compatible remote CPU the pool; the idle claim bounds fan-out. */
static __noinline bool cake_offer_remote(struct task_struct *p __arg_trusted, s32 tcpu)
{
	u64 w, cores, seats, noisy;
	u32 i;

	if (!cake_one_word)
		return false;
	w = cake_idle_word() & p->cpus_ptr->bits[0] &
		~cpu_llc_word[(u32)tcpu & (MAX_CPUS - 1)];
	cores = w ? cake_core_word() & w : 0;
	seats = cake_smt_expand(cake_seat_word);
	noisy = w ? cpu_irq_hot_cores[0] : 0;
	for (i = 0; i < cake_claim_tries && w; i++) {
		s32 cpu = cake_pick_cold(w, cores, seats, noisy);

		if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY)) {
			u32 target = (u32)cpu;

			/* LLVM drops the mask, knowing ctz < 64; the verifier sees only < 256. */
			barrier_var(target);
			__atomic_exchange_n(&cake.remote_pool[target & 63].word,
					    (u64)cake_llc_of(tcpu) + 1, __ATOMIC_SEQ_CST);
			cake_kick(cpu, CAKE_KICK_IDLE);
			return true;
		}
		w &= ~(1ULL << ((u32)cpu & 63));
	}
	return false;
}

/* A wake bound to @cpu, keeping its key; @flags: IMMED for a claimed idle CPU, PREEMPT to evict. */
static __always_inline void cake_wake_bind(struct task_struct *p, s32 cpu,
					   u64 slice, u64 vt, u64 flags)
{
	p->scx.dsq_vtime = vt;
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)cpu, slice,
			CAKE_ENQ_WAKEUP | flags);
}

/* Place a pool-bound wake. Static: curr keeps its pointer type with no global-subprogram trust. */
static __noinline s32 cake_wake_place(struct task_struct *p __arg_trusted, s32 tcpu,
				     u64 slice, u64 vt,
				     struct task_struct *curr)
{
	s32 idle;
	u64 now;

	idle = cake_pick_idle_clean(p);
	if (idle >= 0) {
		if (unlikely(cake_tog_probe)) {
			cake_stat_inc_cold(CAKE_SITE_NOTIFY_KICK);
			cake_probe_x(CAKE_SITE_NOTIFY_KICK_X, tcpu, idle);
		}
		cake_wake_bind(p, idle, slice, vt, CAKE_ENQ_IMMED);
		return 0;
	}

	/* Pre-6.18 rq->curr is untrusted, so the caller passes NULL there: read it here. */
	if (!bpf_ksym_exists(scx_bpf_cpu_curr))
		curr = cake_cpu_curr(tcpu);

	/* Decide now: with no .tick, deciding neither leaves the wakee to the watchdog. */
	now = cake_now_rq(CAKE_SITE_KT_OCCUPANT);
	if (cake_wake_preempt(p, curr, tcpu,
			      cake_wake_protect(PREEMPT_PROTECT_SHIFT, slice), now)) {
		cake_wake_bind(p, tcpu, slice, vt, CAKE_ENQ_PREEMPT);
		return 0;
	}

	/* Hunt a mid-slice compute occupant among the neighbours. */
	{
		u32 cand = (u32)tcpu;
		u32 pi;

		cake_tried_inc(bpf_get_smp_processor_id(), CAKE_TRIED_PROBE);
		for (pi = 0; pi < CAKE_NEIGHBOUR_PROBE_DEPTH; pi++) {
			/* Loader's order, same die first: cpu+1 wraps into the other die. */
			if (steal_order_live && (u32)tcpu < STEAL_SPAN) {
				if (pi >= nr_steal_cpus)
					break;
				/* Compare on the scaled register: no later bound carries back. */
				u32 ix = (u32)tcpu * STEAL_SPAN + pi;

				barrier_var(ix);
				if (ix >= STEAL_SPAN * STEAL_SPAN)
					break;
				cand = cpu_steal_order[ix];
			} else {
				break;
			}
			if (!cake_allowed(p, (s32)cand))
				continue;
			if (cake_wake_preempt(p, cake_cpu_curr((s32)cand), (s32)cand,
					      cake_wake_protect(PROBE_PROTECT_SHIFT, slice),
					      now)) {
				if (unlikely(cake_tog_probe)) {
					cake_stat_inc_cold(CAKE_SITE_PROBE_FIRED);
					cake_probe_x(CAKE_SITE_PROBE_FIRED_X, tcpu, (s32)cand);
				}
				cake_wake_bind(p, (s32)cand, slice, vt, CAKE_ENQ_PREEMPT);
				return 0;
			}
		}
	}

	/* Undecided: the pool, then the search only the insert can make complete. */
	cake_pool_insert(p, tcpu, slice, vt, CAKE_ENQ_WAKEUP);	/* PRIQ reads no positional bit */
	idle = cake_pick_idle_clean(p);
	if (idle >= 0) {
		cake_kick(idle, CAKE_KICK_IDLE);
		return 0;
	}
	if (cake_multi_llc())
		cake_offer_remote(p, tcpu);
	return 0;
}

/* The wake half of ops.enqueue. Global for its own register budget; s32: pre-6.19 rejects void. */
__noinline s32 cake_enqueue_wake(struct task_struct *p __arg_trusted, s32 tcpu)
{
	struct task_struct *curr = cake_cpu_curr(tcpu);

	/* Self-race: waking what this CPU still switches out (ttwu wakelist); the hottest path. */
	if (curr == p) {
		u64 slice = cake_admit_direct(p);

		cake_qmark_set((u32)tcpu);
		cake_dsq_insert_vtime(p, (u64)(u32)tcpu, slice, p->scx.dsq_vtime,
				      CAKE_ENQ_WAKEUP);
		return 0;
	}

	/* cake_wake_place: a claimed idle CPU, a yielding occupant, or the pool. */
	{
		u64 vt;
		u64 slice = cake_wake_admit(p, &vt);

		cake_wake_place(p, tcpu, slice, vt,
				bpf_ksym_exists(scx_bpf_cpu_curr) ? curr : NULL);
	}
	return 0;
}

/* select_cpu never runs for a one-CPU wake: its home claim, screened by the idle word. */
static __always_inline bool cake_pinned_claim(s32 cpu)
{
	if (cake_one_word && (u32)cpu < CPU_WORD_BITS &&
	    !(cake_idle_word() & (1ULL << ((u32)cpu & 63))))
		return false;
	return cake_taci(cpu, CAKE_SITE_TACI_PINNED);
}

/* No other CPU may steal a pinned wake: preempt by sleep depth @d, read before the insert. */
static __noinline bool cake_pinned_wake_preempt(struct task_struct *p __arg_trusted,
						s32 tcpu, u64 d, u64 slice)
{
	u64 cran = 0;
	u64 clive = cake_occupant_live(tcpu, &cran);
	u64 lo, pvt, vs;

	if (!clive)
		return false;

	vs = SLICE_NS;
	lo = cake.frontier.word - vs;
	pvt = lo - vs + cake_delta_clamp(d + vs);

	/* The margin is the wakee's own slice, so a microsecond sleeper can still win. */
	return time_before(pvt + slice, clive);
}

/* ops.enqueue: queue on the owner, except kthread and starved wakes, collisions and requeues. */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* task_cpu(p) read directly; the kfunc is one load behind a call. */
	s32 tcpu = (s32)p->thread_info.cpu;
	u64 lo, d, slice;
	s32 idle;
	bool pooled = false, alone, pin;

	/* A pooled task re-enqueued before it ran (property change, requeue). */
	cake_pool_seen(p);

	/* Kernel-thread wakes to the local DSQ: the scx watchdog rides unbound kworkers. */
	if ((enq_flags & CAKE_ENQ_WAKEUP) && (p->flags & PF_KTHREAD)) {
		/* A one-CPU task can land only on its own CPU: nothing to pick. */
		s32 kcpu = p->nr_cpus_allowed > 1 ? cake_pick_idle_clean(p) : -1;
		u64 kflags = enq_flags;

		if (kcpu >= 0)
			kflags |= CAKE_ENQ_IMMED;
		else if (p->nr_cpus_allowed == 1 &&
			 cake_pinned_wake_preempt(p, tcpu, p->scx.dsq_vtime -
						  (cake.frontier.word - SLICE_NS),
						  SLICE_NS)) {
			cake_stat_inc(CAKE_SITE_PINNED_PREEMPT);
			kflags |= CAKE_ENQ_PREEMPT;
		}

		/* No idle claim: the pool bounds the wait by vtime, not the occupant's slice. */
		if (kcpu < 0 && p->nr_cpus_allowed > 1) {
			cake_stat_inc(CAKE_SITE_KT_POOL);
			cake_enqueue_wake(p, tcpu);
			return;
		}

		if (unlikely(cake_tog_probe)) {
			cake_stat_inc_cold(CAKE_SITE_KT_LOCAL);
			if (kcpu >= 0)
				cake_probe_x(CAKE_SITE_KT_LOCAL_X, tcpu, kcpu);
		}
		/* The key only: a kthread's grant is the flat slice. */
		cake_admit_direct(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON |
				   (u32)(kcpu >= 0 ? kcpu : tcpu),
				   SLICE_NS, kflags);
		return;
	}

	/* The clamp floor, and the raw sleep depth the pinned preempt reads before the insert. */
	lo = cake.frontier.word - SLICE_NS;
	d  = p->scx.dsq_vtime - lo;

	/* A turn-starved wake goes to wake placement; one-CPU tasks take the continuation arm. */
	if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1 &&
	    cake_starved_turn(p)) {
		cake_enqueue_wake(p, tcpu);
		return;
	}

	/* Continuations stay on the owner's queue, open to steals; forced requeues: the pool. */
	{
		/* A requeue keeps its key, floored a starved wake's depth below lo. */
		u64 rlo = lo - (CAKE_SLEEPER_DOSE((u64)SLICE_NS) &
			       -(u64)!!(enq_flags & CAKE_ENQ_REENQ));
		u64 vt = rlo + cake_delta_clamp(p->scx.dsq_vtime - rlo);
		struct task_struct *hc = NULL;

		/* Anti-collision: home held by an equally served peer; p is not turn-starved. */
		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1)
			hc = cake_cpu_curr(tcpu);
		if (hc && hc != p && !(hc->flags & PF_IDLE) && !cake_starved(hc)) {
			/* No claim here (deferred-local lane): the grant, then the pool. */
			if (unlikely(cake_tog_probe))
				cake_probe_grant(hc, tcpu);
			/* Past its grant, the occupant yields now; a seated stage stays. */
			if (!(enq_flags & CAKE_ENQ_REENQ) &&
			    (hc->scx.flags & CAKE_TASK_QUEUED) && hc->scx.dsq_vtime &&
			    !((u32)tcpu < CPU_WORD_BITS && cake_seat_owner((u32)tcpu, hc)) &&
			    (cake_home_crowded || cake_home_cpu(hc) != tcpu) &&
			    !cake_grant_left(hc, tcpu)) {
				cake_stat_inc(CAKE_SITE_EXPIRY_PREEMPT);
				cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)tcpu,
						cake_admit_direct(p), enq_flags | CAKE_ENQ_PREEMPT);
				return;
			}
			slice = cake_admit_direct(p);
			cake_pool_insert(p, tcpu, slice, p->scx.dsq_vtime, enq_flags);
			pooled = true;
			/* A CPU idling between pick and insert read the pool empty: search. */
			goto kick_idle;
		}

		/* A forced requeue cannot rely on its owner: pool it, then kick_idle. */
		if (p->nr_cpus_allowed > 1 &&
		    ((enq_flags & CAKE_ENQ_REENQ) ||
		     ((u32)tcpu < CPU_WORD_BITS &&
		      cake.run[(u32)tcpu & (MAX_CPUS - 1)].retake &&
		      !cake_seat_owner((u32)tcpu, p)))) {
			if (cake_tog_probe && !(enq_flags & CAKE_ENQ_REENQ))
				cake_stat_inc(CAKE_SITE_SEAT_REROUTE);
			/* A claimed idle CPU serves the evictee; the pool if no claim wins. */
			idle = cake_pick_idle_clean(p);
			if (idle >= 0) {
				p->scx.dsq_vtime = vt;
				cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)idle,
						cake_task_slice(p), enq_flags | CAKE_ENQ_IMMED);
				cake_stat_inc(CAKE_STAT_POOL_DIRECT);
				return;
			}
			cake_pool_insert(p, tcpu, cake_task_slice(p), vt, enq_flags);
			pooled = true;
			goto kick_idle;
		}

		slice = cake_task_slice(p);
		/* put_prev serves its queue next: no kick; the mark is read pre-insert. */
		alone = !(enq_flags & CAKE_ENQ_WAKEUP) && cake_task_on_cpu(p) &&
			!cake_qmark_test((u32)tcpu) && !cake_pool_pending(cake_llc_of(tcpu));
		pin = false;
		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed == 1) {
			/* Under this rq lock a clear mark proves the own queue empty. */
			bool empty = !cake_qmark_test((u32)tcpu);
			bool claim = empty && cake_pinned_claim(tcpu);

			pin = !claim && cake_pinned_wake_preempt(p, tcpu, d, slice);
			/* Nothing queued to pass: no ops.dispatch at the pick, and no kick. */
			if (claim || (empty && pin)) {
				cake_stat_inc(claim ? CAKE_SITE_PINNED_CLAIM :
					      CAKE_SITE_PINNED_PREEMPT);
				p->scx.dsq_vtime = vt;
				cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)tcpu, slice,
						enq_flags | (claim ? CAKE_ENQ_IMMED :
							     CAKE_ENQ_PREEMPT));
				return;
			}
		}
		/* A user DSQ ignores ENQ_PREEMPT: verdict before the insert, kick after. */
		cake_qmark_set((u32)tcpu);
		cake_dsq_insert_vtime(p, (u64)(u32)tcpu, slice, vt, enq_flags);
		if (pin) {
			cake_stat_inc(CAKE_SITE_PINNED_PREEMPT);
			cake_stat_inc(CAKE_SITE_PINNED_KICK);
			cake_kick(tcpu, CAKE_KICK_PREEMPT);
		}
		if (alone && !cake_local_nr(tcpu)) {
			cake_stat_inc(CAKE_SITE_KICK_ALONE);
			goto no_idle;
		}
	}

kick_idle:

	/* Core's activate path wakes an idle owner, the only CPU a one-CPU task's pick names. */
	idle = p->nr_cpus_allowed > 1 ? cake_pick_idle_clean(p) : -1;
	if (idle >= 0) {
		cake_kick(idle, CAKE_KICK_IDLE);
		return;
	}
no_idle:
	if (pooled && cake_multi_llc())
		cake_offer_remote(p, tcpu);
}

/* PROBE: count a steal attempt from @idx by die relation; the move may find the queue empty. */
static __always_inline void cake_probe_steal(u32 ucpu, u32 idx)
{
	if (cake_tog_probe) {
		cake_stat_inc(CAKE_SITE_STEAL_MOVED);
		if (cake_cross_llc((s32)ucpu, (s32)idx))
			cake_stat_inc(CAKE_SITE_STEAL_MOVED_X);
	}
}

/* Ring steal from cpu+1; a missed bit costs a steal. Global: verified once, not per caller. */
__noinline bool cake_ring_walk(u32 ucpu)
{
	u32 nr = nr_cpu_span;
	u32 cw = (u32)-1;	/* which qmask word `m` holds; none yet */
	u64 m = 0;
	u32 i;

	if (steal_order_live && ucpu < STEAL_SPAN) {
		u32 row = ucpu;

		/* LLVM drops the mask after the compare; a global proves the index on its own. */
		barrier_var(row);
		row &= STEAL_SPAN - 1;
		/* One precomputed locality order avoids verifier-multiplying scan loops. */
		for (i = 0; i < STEAL_SPAN; i++) {
			u32 idx;

			if (i >= nr_steal_cpus)
				break;
			idx = cpu_steal_order[row * STEAL_SPAN + i];
			if (!cake_qmark_test(idx))
				continue;
			/* Across a die, only a head a slice behind the frontier pays the fabric. */
			if (cake_cross_llc((s32)ucpu, (s32)idx)) {
				struct task_struct *h = cake_dsq_peek((u64)idx);

				if (!h || !time_before(h->scx.dsq_vtime + SLICE_NS,
						       cake.frontier.word))
					continue;
			}
			cake_probe_steal(ucpu, idx);
			if (cake_move_to_local(idx, (s32)ucpu, cake_nrq(idx)))
				return true;
		}
		return false;
	}

	for (i = 1; i < MAX_CPUS; i++) {
		u32 idx = ucpu + i, wi;

		if (i >= nr)
			break;
		if (idx >= nr)
			idx -= nr;
		wi = (idx >> 6) & (QMASK_WORDS - 1);
		if (wi != cw) {
			cw = wi;
			m = cake.qmask[wi];
		}
		if (!(m & (1ULL << (idx & 63))))
			continue;
		cake_probe_steal(ucpu, idx);
		if (cake_move_to_local(idx, (s32)ucpu, cake_nrq(idx)))
			return true;
	}

	return false;
}

/* Nothing marked anywhere is one word read in the caller's frame, not a call into the walk. */
static __always_inline bool cake_ring_steal(u32 ucpu)
{
	if (cake_one_word &&
	    !(cake.qmask[0] & ~(1ULL << (ucpu & 63))))
		return false;
	return cake_ring_walk(ucpu);
}

/* Has the global wake queue gone unserved for a full WALL-clock window? */
static __noinline bool cake_wake_starved(u32 llc)
{
	return time_before(cake.pool[llc & (MAX_LLCS - 1)].served +
			   WAKE_STARVE_WALL_NS, cake_now_rq(CAKE_SITE_KT_WAKECLOCK));
}

/* Record that someone served the global wake queue. */
static __noinline void cake_wake_serve_stamp(u32 llc)
{
	cake_stat_inc(CAKE_SITE_WAKE_SERVED_ST);
	cake.pool[llc & (MAX_LLCS - 1)].served = cake_now_rq(CAKE_SITE_KT_WAKECLOCK);
}

/* An empty pool is served; store at half a window old: a blind store is an RFO per switch. */
static __noinline void cake_wake_idle_stamp(u32 llc)
{
	u64 now = cake_now_rq(CAKE_SITE_KT_WAKECLOCK);
	struct cake_llc_slot *ws = &cake.pool[llc & (MAX_LLCS - 1)];

	if (time_before(ws->served + WAKE_STARVE_REFRESH_NS, now)) {
		cake_stat_inc(CAKE_SITE_WAKE_SERVED_ST);
		ws->served = now;
	}
}

/* No clock on the both-empty path: this CPU's run stamp says when the serve stamp is stale. */
static __always_inline void cake_wake_idle_refresh(u32 llc, u32 ucpu)
{
	u64 served = cake.pool[llc & (MAX_LLCS - 1)].served;
	u64 seen = cake.run[ucpu & (MAX_CPUS - 1)].stamp;

	if (time_before(served + WAKE_STARVE_REFRESH_NS, seen))
		cake_wake_idle_stamp(llc);
}

/* Other dies' pools: only a head a slice behind the frontier, or a pool unserved for the wall. */
static __noinline bool cake_llc_pool_rescue(u32 own, s32 cpu)
{
	u32 i;

	for (i = 0; i < MAX_LLCS; i++) {
		struct task_struct *h;

		if (i >= nr_llcs)
			break;
		if (i == own || !cake.pool[i].mark)
			continue;
		h = cake_dsq_peek(cake_pool_dsq(i));
		if (!h) {
			cake_wake_mark_retire(i);
			continue;
		}
		if (time_before(h->scx.dsq_vtime + SLICE_NS, cake.frontier.word) ||
		    cake_wake_starved(i)) {
			u64 pool = cake_pool_dsq(i);

			if (cake_pool_serve(pool, i, cpu, cake_nrq(pool))) {
				cake_wake_serve_stamp(i);
				return true;
			}
		}
	}
	return false;
}

/* An offered pool is eligible at once; cleared even on failure, so no stale offer remains. */
static __noinline bool cake_take_remote(u32 cpu)
{
	u64 offer;
	u32 llc;

	if (!cake_one_word || cpu >= CPU_WORD_BITS)
		return false;
	if (!cake.remote_pool[cpu & 63].word)
		return false;
	offer = __atomic_exchange_n(&cake.remote_pool[cpu & 63].word, 0,
				    __ATOMIC_SEQ_CST);
	if (!offer || offer > nr_llcs)
		return false;
	llc = (u32)(offer - 1) & (MAX_LLCS - 1);
	if (llc == cake_llc_of((s32)cpu))
		return false;
	if (!cake_pool_serve(cake_pool_dsq(llc), llc, (s32)cpu,
			     cake_nrq(cake_pool_dsq(llc))))
		return false;
	cake_wake_serve_stamp(llc);
	return true;
}

/* Nothing has landed yet: the insert lands after its op returns, so kick self and pick again. */
static __noinline void cake_pending_spin(u32 ucpu)
{
	struct cake_run_slot *rs = &cake.run[ucpu & (MAX_CPUS - 1)];

	/* The bound ends the kick storm only: cake_pool_unserved clears a count outliving it. */
	if (rs->pend_spin < CAKE_PEND_SPIN_MAX) {
		rs->pend_spin++;
		cake_stat_inc(CAKE_SITE_PEND_KICK);
		/* PREEMPT: a refilled prev would keep the CPU and the kick never reach dispatch. */
		cake_kick((s32)ucpu, CAKE_KICK_PREEMPT);
	}
}

/* No token is the common case: one line read in the caller's frame. */
static __always_inline void cake_pending_wait(u32 ucpu, u32 llc)
{
	if (cake_pool_unserved(llc))
		cake_pending_spin(ucpu);
	else
		cake.run[ucpu & (MAX_CPUS - 1)].pend_spin = 0;
}

/* Both-empty exit: retire a stale mark, refresh the stamp, steal, rescue or wait on the token. */
static __always_inline bool cake_dispatch_empty(u32 ucpu, u32 llc, bool multi)
{
	if (multi)
		cake_wake_mark_retire(llc);
	cake_wake_idle_refresh(llc, ucpu);
	if (cake_ring_steal(ucpu) || (multi && cake_llc_pool_rescue(llc, (s32)ucpu)))
		return true;
	cake_pending_wait(ucpu, llc);
	return false;
}

/* This CPU took its pool's head: stamp the serve; PROBE counts it, and a head from another die. */
static __always_inline void cake_pool_served(u32 ucpu, u32 llc)
{
	u32 slot;

	cake_wake_serve_stamp(llc);
	if (cake_tog_probe) {
		cake_stat_inc(CAKE_SITE_POOL_SERVED);
		slot = ucpu & (MAX_CPUS - 1);
		barrier_var(slot);	/* keep the mask on the load's register */
		if (cake_probe_pool_x[slot])
			cake_stat_inc(CAKE_SITE_POOL_SERVED_X);
	}
}

/* Earliest vtime of {own queue, pool}, then the ring steal. Own frame: @prev stays out of it. */
static __noinline bool cake_dispatch_search(s32 cpu)
{
	u32 ucpu = (u32)cpu;
	const bool multi = cake_multi_llc();
	u32 llc = cake_llc_of(cpu);
	u64 pool = cake_pool_dsq(llc);
	u64 first = (u64)ucpu, second = pool;
	struct task_struct *own, *wake;
	u32 own_n = 0, wake_n;

	if (multi && cake_take_remote(ucpu))
		return true;

	/* Own queue first, by a slice: without it every CPU takes the pool and serialises. */
	{
		bool seat;

		/* A clear mark proves it empty: inserts set it under this lock, only we clear. */
		if (cake_qmark_test(ucpu)) {
			own_n = (u32)cake_nrq((u64)ucpu);
			if (!own_n)
				cake_qmark_publish(ucpu, false);
		}
		/* A zero token proves the pool empty; a raised one may be a task not yet run. */
		if (!own_n && !cake_pool_pending(llc))
			return cake_dispatch_empty(ucpu, llc, multi);
		wake_n = (u32)cake_nrq(pool);
		if (!(own_n | wake_n))
			return cake_dispatch_empty(ucpu, llc, multi);
		/* Test before set: an unconditional store took the shared line every dispatch. */
		if (wake_n)
			cake_wake_mark_set(llc);
		seat = !own_n && cake_one_word && ucpu < CPU_WORD_BITS && cake_seat_held(ucpu);
		/* A peek is a DSQ hash lookup: read a head only to order, seat-test or count. */
		own = own_n && wake_n ? cake_dsq_peek((u64)ucpu) : NULL;
		/* A held seat takes no pool work while another idle CPU is nobody's seat. */
		wake = wake_n && (own_n || seat) ?
		       cake_dsq_peek(pool) : NULL;
		if (seat) {
			/* A free CPU on this die only; pool work is never kicked across the L3. */
			u64 free = cake_idle_word() & ~cake_seat_word &
				   cpu_llc_word[ucpu & (MAX_CPUS - 1)];

			/* Kick where the head can run: else it strands for the watchdog. */
			if (wake)
				free &= wake->cpus_ptr->bits[0];
			if (free && (wake || (cake.qmask[0] & ~(1ULL << ucpu)))) {
				cake_stat_inc(CAKE_SITE_LEAK_DISPATCH);
				/* The seat waits for its holder; a head past the wall is served. */
				if (!(wake && cake_wake_starved(llc))) {
					s32 c = cake_claim_free(free);

					/* No claim won: the seat serves the head itself. */
					if (c >= 0) {
						cake_stat_inc(CAKE_SITE_SEAT_DECLINE);
						cake_kick(c, CAKE_KICK_IDLE);
						return false;
					}
				}
			}
		}
		if (!wake_n) {
			if (multi)
				cake_wake_mark_retire(llc);
			/* An empty pool is served; a CPU back from idle may read it starved. */
			cake_wake_idle_refresh(llc, ucpu);
		}
		/* Pool first if own is empty, the margin favours it or it is starved. */
		if (!own_n) {
			first  = pool;
			second = (u64)ucpu;
		} else if (wake) {
			if (!own ||
			    time_before(wake->scx.dsq_vtime + SLICE_NS,
					own->scx.dsq_vtime) ||
			    cake_wake_starved(llc)) {
				first  = pool;
				second = (u64)ucpu;
			}
		}
		if (cake_tog_probe && wake_n) {
			/* PROBE: the pool head's previous die vs this one, before the move. */
			struct task_struct *h = wake ? wake : cake_dsq_peek(pool);
			u32 slot = ucpu & (MAX_CPUS - 1);

			/* It reloads past the peek; keep the mask on the store's register. */
			barrier_var(slot);
			cake_probe_pool_x[slot] =
				h && cake_cross_llc((s32)h->thread_info.cpu, cpu);
		}
	}
	if (first == pool ? cake_pool_serve(pool, llc, cpu, wake_n) :
			    cake_move_to_local(first, cpu, own_n)) {
		/* The owner took its last task: clear now, or every thief walks an empty queue. */
		if (first != pool && own_n == 1)
			cake_qmark_publish(ucpu, false);
		if (first == pool)
			cake_pool_served(ucpu, llc);
		return true;
	}
	/* Unconditional: a second healing net under a lost mark; a peek guard spilled. */
	if (second == pool ? cake_pool_serve(pool, llc, cpu, cake_nrq(pool)) :
			     cake_move_to_local(second, cpu, cake_nrq(second))) {
		if (second == pool)
			cake_pool_served(ucpu, llc);
		return true;
	}

	/* Moves failed: head not runnable here. Re-peek, wake may be NULL or stale; forward it. */
	if (cake_one_word) {
		wake = cake_dsq_peek(pool);
		if (wake) {
			u64 can = cake_idle_word() & wake->cpus_ptr->bits[0] &
				  cpu_llc_word[ucpu & (MAX_CPUS - 1)] &
				  ~(1ULL << (ucpu & 63));

			if (can & ~cake_seat_word)
				can &= ~cake_seat_word;
			if (can) {
				s32 c = cake_claim_free(can);

				if (c >= 0) {
					cake_stat_inc(CAKE_SITE_POOL_FORWARD);
					cake_kick(c, CAKE_KICK_IDLE);
				}
			}
		}
	}

	return cake_ring_steal(ucpu) ||
	       (multi && cake_llc_pool_rescue(llc, cpu));
}

/* The idle bit is set first: an insert that read it old raised the token seen here. */
static __always_inline void cake_idle_interlock(s32 cpu)
{
	if (cake_pool_unserved(cake_llc_of(cpu))) {
		cake_stat_inc(CAKE_SITE_UI_KICK);
		scx_bpf_kick_cpu(cpu, 0);
	}
}

/* Publish @bit, then re-read the pool: the barrier pairs with cake_pool_pending_inc's. */
static __always_inline void cake_own_idle_set(u64 bit, s32 cpu)
{
	/* Ended on idle entry, not exit: the locked op stays off the path to the woken task. */
	if (READ_ONCE(cake_own_idle.claimed) & bit)
		__atomic_fetch_and(&cake_own_idle.claimed, ~bit, __ATOMIC_RELAXED);
	CAKE_RMW_FULL(or, &cake_own_idle.word, bit);
	barrier();
	cake_idle_interlock(cpu);
}

/* Going busy ends the core's whole read too, because a claim leaves the bit set. */
static __always_inline void cake_own_idle_clear(u64 bit)
{
	if (READ_ONCE(cake_own_idle.word) & bit)
		__atomic_fetch_and(&cake_own_idle.word, ~bit, __ATOMIC_RELAXED);
}

/* Is @cpu's occupant its idle task? Core scheduling dispatches for a sibling from this CPU. */
static __always_inline bool cake_cpu_runs_idle(s32 cpu)
{
	struct task_struct *curr;

	if (likely(cpu == (s32)bpf_get_smp_processor_id()))
		return bpf_get_current_task_btf()->flags & PF_IDLE;
	curr = cake_cpu_curr(cpu);
	return curr && (curr->flags & PF_IDLE);
}

/* A re-pick has no ops.update_idle: restore the bit of a CPU staying idle after a lost claim. */
static __always_inline void cake_own_idle_rearm(s32 cpu)
{
	u64 bit = cake_own_bit(cpu);

	if (!cake_cpu_runs_idle(cpu) || (cake_idle_word() & bit) || cake_local_nr(cpu))
		return;
	cake_own_idle_set(bit, cpu);
}

/* ops.dispatch: run the search; with nothing anywhere, refill prev rather than idle. */
void BPF_STRUCT_OPS(cake_dispatch, s32 cpu, struct task_struct *prev)
{
	/* Search first: a NULL test on prev would verify the search once per outcome. */
	bool found = cake_dispatch_search(cpu);
	/* A sibling's core pick can drop the rq lock mid-search: prev may no longer run there. */
	bool queued = prev && (prev->scx.flags & CAKE_TASK_QUEUED) &&
		      cpu == (s32)bpf_get_smp_processor_id();

	/* Bypass hides the exit from idle, and a CPU-bound prev may never idle to repair the bit. */
	if (cake_one_word && queued)
		cake_own_idle_clear(cake_own_bit(cpu));
	if (found)
		return;

	/* A local insert mid-dispatch skipped its preempt: refill only if nothing landed. */
	if (queued && !cake_local_nr(cpu)) {
		cake_set_slice(prev, cake_task_slice(prev));
		return;
	}
	if (cake_one_word)
		cake_own_idle_rearm(cpu);
}

/* ops.yield: give the slice up only to waiting work; with no op every yield runs dispatch. */
bool BPF_STRUCT_OPS(cake_yield, struct task_struct *from, struct task_struct *to)
{
	struct rq *rq = bpf_this_cpu_ptr(&runqueues);
	u32 cpu = bpf_get_smp_processor_id();

	if (to)
		return false;
	/* Own-queue and local tasks all count on this rq; pooled ones may not. */
	if (rq->scx.nr_running > 1 || cake_pool_pending(cake_llc_of((s32)cpu)) ||
	    (cake_multi_llc() && cake_one_word && cpu < CPU_WORD_BITS &&
	     cake.remote_pool[cpu & 63].word)) {
		cake_stat_inc(CAKE_SITE_YIELD_GIVE);
		cake_set_slice(from, 0);
	} else {
		cake_stat_inc(CAKE_SITE_YIELD_KEEP);
	}
	return false;
}

/* PROBE census: releases by arrival path, burst band and reason; holds by band. */
u64 cake_release_census[CAKE_RELEASE_PATHS][CAKE_RELEASE_BANDS]
	__attribute__((aligned(STATE_SLOT_BYTES)));
u64 cake_release_reason[CAKE_RELEASE_REASONS] __attribute__((aligned(STATE_SLOT_BYTES)));
u64 cake_acquire_hist[CAKE_RELEASE_BANDS] __attribute__((aligned(STATE_SLOT_BYTES)));

/* log2 band of @ns above @shift, saturating at @bands - 1. */
static __always_inline u32 cake_log2_band(u64 ns, u32 shift, u32 bands)
{
	u64 v = ns >> shift;
	u32 b = 0;

	while (b < bands - 1 && (v >> (b + 1)))
		b++;
	return b;
}

static __always_inline u32 cake_release_band(u64 ns)
{
	return cake_log2_band(ns, CAKE_RELEASE_BAND_SHIFT, CAKE_RELEASE_BANDS);
}

/* PROBE: log2 histograms of what the fixed thresholds stand for; nothing in BPF reads them. */
u64 cake_hist[MAX_CPUS][CAKE_HIST_KINDS][CAKE_HIST_BANDS]
	__attribute__((aligned(STATE_SLOT_BYTES)));

static __always_inline void cake_hist_add(u32 kind, u64 ns)
{
	u32 c = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

	cake_hist[c][kind & (CAKE_HIST_KINDS - 1)][cake_log2_band(ns, CAKE_HIST_SHIFT, CAKE_HIST_BANDS)]++;
}

/* A direct placement's wait from enqueue stamp to this run; a pooled task's includes its queue. */
static __noinline void cake_probe_hop(struct task_struct *p, u64 now)
{
	u64 lq;

	if (!(p->scx.flags & CAKE_TASK_IMMED))
		return;
	if (!bpf_core_field_exists(p->sched_info.last_queued))
		return;
	lq = p->sched_info.last_queued;
	if (lq && now > lq)
		cake_hist_add(CAKE_HIST_HOP, now - lq);
}

/* PROBE: at block, the mean burst and, after a wake, the quantum just used. */
static __noinline void cake_probe_quantum(struct task_struct *p, u64 used, bool woke)
{
	if (woke)
		cake_hist_add(CAKE_HIST_HANDOFF, used);
	cake_hist_add(CAKE_HIST_BURST, cake_burst_ns(p));
}

/* PROBE: count the release by path, burst band and reason; stamp it for the acquire. */
static __noinline void cake_probe_release(s32 cpu, struct scx_cpu_release_args *args)
{
	struct cake_run_slot *rs = &cake.run[(u32)cpu & (MAX_CPUS - 1)];
	struct task_struct *d = args->task;
	u32 path = !rs->out_slice ? 2 : rs->out_immed ? 1 : 0;
	u32 reason = (u32)args->reason;
	u64 burst = d ? d->se.sum_exec_runtime / (d->nvcsw | 1) : 0;
	u32 band = cake_release_band(burst);

	cake_stat_inc_cold(CAKE_SITE_RELEASE);
	/* No mask: one of three constants, and a power-of-two mask folded IMMED into the first. */
	__sync_fetch_and_add(&cake_release_census[path]
					     [band & (CAKE_RELEASE_BANDS - 1)], 1);
	__sync_fetch_and_add(&cake_release_reason[reason & (CAKE_RELEASE_REASONS - 1)], 1);
	rs->release = cake_now_rq(CAKE_SITE_KT_OCCUPANT);
}

/* PROBE: how long the higher class held this CPU, from the release stamp. */
static __noinline void cake_probe_acquire(s32 cpu)
{
	struct cake_run_slot *rs = &cake.run[(u32)cpu & (MAX_CPUS - 1)];
	u64 hold;

	if (!rs->release)
		return;
	hold = time_delta(cake_now_rq(CAKE_SITE_KT_OCCUPANT), rs->release);
	rs->release = 0;
	cake_stat_inc_cold(CAKE_SITE_ACQUIRE);
	__sync_fetch_and_add(&cake_acquire_hist[cake_release_band(hold) & (CAKE_RELEASE_BANDS - 1)], 1);
}

/* A higher class took this CPU: re-enqueue local tasks, which the steal queues cannot reach. */
void BPF_STRUCT_OPS(cake_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	u32 owner = (u32)cpu;
	struct task_struct *head;
	u64 free, eligible;
	s32 c;

	if (unlikely(cake_tog_probe))
		cake_probe_release(cpu, args);
	scx_bpf_reenqueue_local();
	if (!cake_one_word || !cake_qmark_test(owner))
		return;
	free = cake_idle_word() & cpu_llc_word[owner & (MAX_CPUS - 1)] &
	       ~(1ULL << (owner & 63));
	if (!free)
		return;
	head = cake_dsq_peek(owner);
	if (!head)
		return;
	eligible = free & head->cpus_ptr->bits[0];
	c = eligible ? cake_claim_free(eligible) : -1;
	/* A thief can pass an ineligible head and serve the next movable task. */
	if (c < 0 && (free & ~eligible) && cake_nrq(owner) > 1)
		c = cake_claim_free(free & ~eligible);
	if (c >= 0) {
		cake_stat_inc(CAKE_SITE_RELEASE_SERVE);
		cake_kick(c, CAKE_KICK_IDLE);
	}
}

/* The higher class is done. Registered only under --toggle probe=1: hold census. */
void BPF_STRUCT_OPS(cake_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	if (unlikely(cake_tog_probe))
		cake_probe_acquire(cpu);
}

/* A task returning far ahead must not drag peers' wake floor: cap an outlier by live service. */
static __noinline u64 cake_frontier_candidate(u64 vtime, u64 f, u32 cpu)
{
	u64 near = f + SLICE_NS;
	u64 now;
	int c;

	if (!time_before(near, vtime))
		return vtime;
	/* Running's own clock, from the slot it just stamped. */
	now = cake.run[cpu & (MAX_CPUS - 1)].stamp;
	/* Numeric iteration keeps verifier work bounded on wide CPU spans. */
	bpf_for(c, 0, nr_cpu_span < MAX_CPUS ? nr_cpu_span : MAX_CPUS) {
		u64 ran = 0, live;

		if ((u32)c == cpu)
			continue;
		/* One clock for the sweep: running's own. */
		live = cake_occupant_live_of(cake_cpu_curr((s32)c), (s32)c, now, &ran);
		if (live && time_before(live, vtime)) {
			vtime = live;
			if (!time_before(near, vtime))
				break;
		}
	}
	return vtime;
}

/* CAS F from @f to @v, stamped @now, returning F after: F bounds every key, a lower one loses. */
static __always_inline u64 cake_frontier_store(u64 f, u64 v, u64 now)
{
	u64 seen = __sync_val_compare_and_swap(&cake.frontier.word, f, v);

	if (seen != f)
		return seen;
	cake.frontier.stamp = now;
	cake_stat_inc(CAKE_SITE_FRONTIER_ST);
	return v;
}

/* Step F toward @vtime by [dt >> RATE_FLOOR_SHIFT, dt], dt the wall time since its last store. */
static __noinline u64 cake_frontier_step(u64 vtime, u64 f, u32 cpu, u64 now)
{
	s64 dt = time_delta(now, cake.frontier.stamp), up = 0, step;

	if (dt < FRONTIER_GRAIN_NS)	/* step <= dt: no store is possible */
		return f;
	if (!time_before(vtime, f + FRONTIER_GRAIN_NS))
		up = (s64)(cake_frontier_candidate(vtime, f, cpu) - f);
	step = up < dt ? up : dt;
	step = step > (dt >> RATE_FLOOR_SHIFT) ? step : dt >> RATE_FLOOR_SHIFT;
	if (step < FRONTIER_GRAIN_NS)
		return f;
	return cake_frontier_store(f, f + step, now);
}

/* F after ops.running: most runs are within a grain of F and owe the rate floor under a grain. */
static __always_inline u64 cake_frontier_advance(u64 vtime, u32 cpu, u64 now)
{
	u64 f = cake.frontier.word;

	if (time_before(vtime, f + FRONTIER_GRAIN_NS) &&
	    time_delta(now, cake.frontier.stamp) < (FRONTIER_GRAIN_NS << RATE_FLOOR_SHIFT))
		return f;
	return cake_frontier_step(vtime, f, cpu, now);
}

/* @cpu's rq clock as last updated: no TSC read when scx_bpf_now() finds it invalid here. */
static __always_inline u64 cake_running_clock(u32 cpu)
{
	struct rq *rq;
	u64 clock;

	if (!bpf_core_field_exists(struct rq, scx.clock))
		return cake_now_rq(CAKE_SITE_KT_RUNNING);
	cake_stat_inc2(CAKE_SITE_KT, CAKE_SITE_KT_RUNNING);
	rq = bpf_per_cpu_ptr(&runqueues, cpu);
	clock = rq ? rq->scx.clock : 0;
	return clock ? clock : scx_bpf_now();
}

/* ops.running: stamp the per-CPU run start; advance the frontier within its wall-rate band. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
	/* The task's CPU, not the smp id: a remote property change fires this op elsewhere. */
	u32 cpu = p->thread_info.cpu;
	struct cake_run_slot *run = &cake.run[cpu & (MAX_CPUS - 1)];
	u64 now = cake_running_clock(cpu);

	cake_signal_running(p, cpu);

	/* First: the grant below and every later reader want the untagged slice. */
	cake_pool_seen(p);
	run->stamp = now;
	run->sum = p->se.sum_exec_runtime;
	run->retake = 0;
	run->grant = p->scx.slice;
	/* Stamp before owner (see cake_run_slot). */
	barrier();
	run->pid = (u64)(u32)p->pid;
	if (unlikely(cake_tog_probe)) {
		cake_stat_inc_cold(CAKE_SITE_RUNNING);
		CAKE_TIMED_VOID_COLD(CAKE_SITE_T_CAL, (void)0);
		cake_probe_run(p);
		cake_probe_hop(p, now);
	}
	/* Task storage only for a seat held elsewhere: a census miss skips the lookup. */
	if (cake_one_word) {
		/* Holder census, then this CPU's seat line: neither test reads the shared word. */
		if (*cake_seat_holder((u32)p->pid)) {
			struct cake_groove *gr =
				bpf_task_storage_get(&cake_grooves, p, 0, 0);

			cake_seat_retire(gr, (u32)p->pid, cpu + 1);
		}
		if (cpu < CPU_WORD_BITS && cake_seat_held(cpu))
			cake_seat_update(cpu, (u32)p->pid, CAKE_SEAT_RUN, 0);
	}

	/* Late: nothing charges p's vtime while it runs; the stamp reload keeps now unspilled. */
	run->frontier = cake_frontier_advance(p->scx.dsq_vtime, cpu, run->stamp);
}

/* ops.stopping: charge the wall time used to the task's vtime, by the reciprocal table. */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	/* The task's CPU, never the callback's (see ops.running). */
	u32 cpu = p->thread_info.cpu;
	u64 used = p->se.sum_exec_runtime -
		   cake.run[cpu & (MAX_CPUS - 1)].sum;
	u32 idx = cake_recip_index(p);
	struct cake_run_slot *rs = &cake.run[cpu & (MAX_CPUS - 1)];
	u64 hint = 0, charged, ceil;

	/* Vacant until the next running stamps it; the vtime charge stays after this zero. */
	rs->pid = 0;
	barrier();
	/* PROBE: a runnable task was displaced or expired; keep what cpu_release prices it by. */
	if (unlikely(cake_tog_probe)) {
		if (runnable) {
			rs->out_sum = p->se.sum_exec_runtime;
			rs->out_nvcsw = p->nvcsw;
			rs->out_slice = p->scx.slice;
			rs->out_immed = p->scx.flags & CAKE_TASK_IMMED;
		} else {
			cake_probe_quantum(p, used, rs->hint & CAKE_HINT_WOKE);
		}
	}
	/* Charge residue reads as a pool tag; the kernel's later charges keep a zero slice zero. */
	p->scx.slice = runnable ? p->scx.slice & ~(u64)CAKE_POOL_TAG_MASK : 0;
	/* Share sample once per HOME_TICK_MASK + 1 blocks. */
	if (cake_one_word && !runnable && cpu < CPU_WORD_BITS && !(p->nvcsw & HOME_TICK_MASK))
		cake_home_sample(p, cpu);
	/* No groove: no reservation. Stage tested last: gates cost a load, it an imul. */
	if (cake_one_word && !runnable && cpu < CPU_WORD_BITS && cake_stage(p)) {
		struct cake_groove *gr = cake_groove_of(p);

		if (gr) {
			cake_seat_retire(gr, (u32)p->pid, cpu + 1);
			/* Once per held record: a hold kept by the retire is already counted. */
			if (!gr->seat_cpu)
				__sync_fetch_and_add(cake_seat_holder((u32)p->pid), 1);
			gr->seat_seq = cake_seat_update(cpu, (u32)p->pid, CAKE_SEAT_HOLD, 0);
			gr->seat_cpu = (u16)(cpu + 1);
			gr->seat_pid = (u32)p->pid;
		}
	}

	/* Consecutive wake-then-block quanta, saturating: latching on one trips on a producer. */
	hint = (rs->hint >> CAKE_HINT_CONF_SHIFT) & CAKE_HINT_CONF_MAX;
	if (!runnable) {
		if ((rs->hint & CAKE_HINT_WOKE)) {
			if (used < cake_handoff_max_ns) {
				if (hint < CAKE_HINT_CONF_MAX)
					hint++;
			} else {
				hint = 0;
			}
		} else {
			hint = 0;
		}
	}
	hint <<= CAKE_HINT_CONF_SHIFT;
	rs->hint = hint;

	charged = cake_scale_vtime_add(p->scx.dsq_vtime, used, idx);
	ceil = rs->frontier + cake_vtime_cap(recip_weight[idx & RECIP_INDEX_MASK]);
	/* Direct write: scx_bpf_task_set_dsq_vtime()'s authority check costs too much here. */
	p->scx.dsq_vtime = cake_vtime_ceil(charged, ceil);
}

/* ops.update_idle: the idle word and the pool interlock; wide hosts mirror occupancy into words. */
void BPF_STRUCT_OPS(cake_update_idle, s32 cpu, bool idle)
{
	u32 c;
	u64 bit;

	if (cake_one_word) {
		bit = cake_own_bit(cpu);
		if (idle)
			cake_own_idle_set(bit, cpu);
		else
			cake_own_idle_clear(bit);
		return;
	}
	if (idle)
		cake_idle_interlock(cpu);
	c = (u32)cpu & (MAX_CPUS - 1);
	bit = 1ULL << (c & 63);
	if (idle)
		__atomic_fetch_or(&cake_idle_words[c >> 6], bit, __ATOMIC_RELAXED);
	else
		__atomic_fetch_and(&cake_idle_words[c >> 6], ~bit, __ATOMIC_RELAXED);
}

/* A temporary dequeue can replace the slice before the task next reaches Cake. */
void BPF_STRUCT_OPS(cake_quiescent, struct task_struct *p, u64 deq_flags)
{
	if (!(deq_flags & SCX_DEQ_SLEEP))
		cake_pool_retire_task(p);
}

/* ops.init_task: the one place task storage is made; a failed create costs the task its home. */
s32 BPF_STRUCT_OPS(cake_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	bpf_task_storage_get(&cake_grooves, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (unlikely(cake_tog_probe))
		bpf_task_storage_get(&cake_probe_tags, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}

/* ops.enable: a fresh task starts at the vtime frontier, neither starved nor in credit. */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, cake.frontier.word);
}

/* ops.exit_task: a holder gives its seat back, or a recycled pid inherits it on a quiet host. */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct cake_groove *gr = bpf_task_storage_get(&cake_grooves, p, 0, 0);

	cake_pool_retire(p, gr);
	if (!cake_one_word)
		return;
	cake_seat_retire(gr, (u32)p->pid, 0);
	cake_home_leave(p);
}

/* ops.disable: a blocked holder leaving the class would keep its seat until that CPU runs. */
void BPF_STRUCT_OPS(cake_disable, struct task_struct *p)
{
	struct cake_groove *gr;

	gr = bpf_task_storage_get(&cake_grooves, p, 0, 0);
	cake_pool_retire(p, gr);
	if (!cake_one_word)
		return;
	cake_seat_retire(gr, (u32)p->pid, 0);
	cake_home_leave(p);
}

/* ops.init: refuse a span under nr_cpu_ids; one vtime DSQ per possible CPU, one pool per LLC. */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	cake_compat_on_cpu_size = cake_on_cpu_size();
	cake_compat_cpu_curr_kfunc = bpf_ksym_exists(scx_bpf_cpu_curr);
	/* Wide: the masks live as long as the machine. One-word hosts: no builtin idle, these raise an error. */
	if (!cake_one_word) {
		const struct cpumask *im = scx_bpf_get_idle_cpumask();
		const struct cpumask *sm = scx_bpf_get_idle_smtmask();

		if (im) {
			cake_mask_cpu = (struct cpumask *)im;
			scx_bpf_put_idle_cpumask(im);
		}
		if (sm) {
			cake_mask_smt = (struct cpumask *)sm;
			scx_bpf_put_idle_cpumask(sm);
		}
	}
	u32 nr = scx_bpf_nr_cpu_ids();
	s32 i, ret;

	if (nr > MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids %u exceeds Cake MAX_CPUS %u", nr,
			      MAX_CPUS);
		return -EINVAL;
	}
	if (nr_cpu_span < nr) {
		scx_bpf_error("loader CPU span %u is narrower than nr_cpu_ids %u",
			      nr_cpu_span, nr);
		return -EINVAL;
	}

	/* Tick clock for task age: the offset to the precise clock, measured once. */
	if (cake_tick_ns)
		cake_jiffies_offset = bpf_ktime_get_ns() - bpf_jiffies64() * cake_tick_ns;
	cake.frontier.stamp = scx_bpf_now();	/* the rate band starts at attach */

	bpf_for(i, 0, nr) {
		ret = scx_bpf_create_dsq((u64)(u32)i, -1);
		if (ret)
			return ret;
	}
	/* One wake pool per LLC; a one-LLC host uses pool 0. */
	bpf_for(i, 0, MAX_LLCS) {
		if ((u32)i >= nr_llcs)
			break;
		ret = scx_bpf_create_dsq(cake_pool_dsq((u32)i), -1);
		if (ret)
			return ret;
	}

	/* Seed wide actual-idle occupancy only. */
	if (!cake_one_word) {
		const struct cpumask *im = scx_bpf_get_idle_cpumask();
		u32 c;

		bpf_for(c, 0, nr_cpu_span) {
			if (bpf_cpumask_test_cpu((s32)c, im))
				cake_idle_words[(c & (MAX_CPUS - 1)) >> 6] |=
					1ULL << (c & 63);
		}
		scx_bpf_put_idle_cpumask(im);
	}

	return 0;
}

/* Core event counters, copied out at exit for the loader's report. */
struct scx_event_stats cake_events;
/* Snapshot the signed pool balances before the loader releases the maps. */
u64 cake_exit_pending[MAX_LLCS];
u64 cake_exit_unserved[MAX_LLCS];

void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	u32 i;

	__COMPAT_scx_bpf_events(&cake_events, sizeof(cake_events));
	for (i = 0; i < MAX_LLCS; i++) {
		cake_exit_pending[i] = cake.pool[i].pending;
		cake_exit_unserved[i] = cake.pool[i].unserved;
	}
	UEI_RECORD(uei, ei);
}

/* QUEUED_WAKEUP: enqueue's current may not be the waker. ENQ_EXITING, or cpu_release ejects us. */
SCX_OPS_DEFINE(cake_ops,
	       .select_cpu	= (void *)cake_select_cpu,
	       .enqueue		= (void *)cake_enqueue,
	       .dispatch	= (void *)cake_dispatch,
	       .cpu_release	= (void *)cake_cpu_release,
	       .cpu_acquire	= (void *)cake_cpu_acquire,
	       .quiescent	= (void *)cake_quiescent,
	       .running		= (void *)cake_running,
	       .stopping	= (void *)cake_stopping,
	       .yield		= (void *)cake_yield,
	       .update_idle	= (void *)cake_update_idle,
	       .init_task	= (void *)cake_init_task,
	       .enable		= (void *)cake_enable,
	       .exit_task	= (void *)cake_exit_task,
	       .disable		= (void *)cake_disable,
	       .init		= (void *)cake_init,
	       .exit		= (void *)cake_exit,
	       .flags		= SCX_OPS_ALLOW_QUEUED_WAKEUP |
				  SCX_OPS_KEEP_BUILTIN_IDLE |
				  SCX_OPS_ENQ_EXITING,
	       .timeout_ms	= WATCHDOG_TIMEOUT_MS,
	       .name		= "cake");
