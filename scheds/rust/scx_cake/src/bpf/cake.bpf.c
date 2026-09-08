/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake — a clean-slate sched_ext scheduler.
 *
 * Claimed idle placement and per-CPU continuation queues, with per-LLC
 * wake pools and weighted virtual time. Kernel masks own idle availability;
 * task-owned seat history and platform rank order otherwise eligible CPUs.
 * STATE.md records policy history and the active experiment boundaries.
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
_Static_assert(STEAL_SPAN <= MAX_CPUS,
	       "steal matrix span must fit Cake MAX_CPUS");

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Rebind the SCX_* enumerators cake uses from autogen's rodata shadows to
 * bpf_core_enum_value(), i.e. from a load per use to a load-time immediate.
 * The #undef is PERMANENT and must follow every scx header (§R.9).
 */
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
/* The CO-RE enum builtin cannot fold these 64-bit enumerators; spell their
 * scx ABI values here (PREEMPT bit 32, REENQ bit 40). */
#define CAKE_ENQ_PREEMPT  ((u64)1 << 32)
#define CAKE_ENQ_REENQ    ((u64)1 << 40)
/* An idle claim can lose its CPU before insertion. Let the kernel return
 * that work through enqueue instead of parking it on a busy local DSQ.
 * Enum existence folds at load time; older kernels keep the existing path. */
#define CAKE_ENQ_IMMED    __COMPAT_ENUM_OR_ZERO(enum scx_enq_flags, SCX_ENQ_IMMED)
#define CAKE_KICK_IDLE    bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_IDLE)
#define CAKE_KICK_PREEMPT bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_PREEMPT)
#define CAKE_TASK_QUEUED  bpf_core_enum_value(enum scx_ent_flags,    SCX_TASK_QUEUED)
#define CAKE_WAKE_SYNC    bpf_core_enum_value(enum scx_wake_flags,   SCX_WAKE_SYNC)
#define CAKE_PICK_IDLE_CORE \
	bpf_core_enum_value(enum scx_pick_idle_cpu_flags, SCX_PICK_IDLE_CORE)

/* Declared ahead of the toggle block: the probe census below reads it. */
const volatile u8 cake_tog_g85 = 1;		/* §G85 seat rules; --toggle g85=0 is the field off-switch */
const volatile u8 cake_tog_g86 = 1;		/* §G86 claim walk + kthread pool; --toggle g86=0 is the field off-switch */
const volatile u8 cake_tog_g89 = 1;		/* §G89 die-local pool, hint, pick, steal gate, probe order; --toggle g89=0 = one pool, LLC-blind */
const volatile u8 cake_tog_g87 = 1;		/* §G87 wakee-bounded protect window and pinned margin; --toggle g87=0 is the off-switch (approved 2026-09-04) */			/* a wakee's wait behind a fresh occupant is bounded by its own slice, not SLICE_NS>>4; pinned wakes preempt by the wakee's slice (§G87) */
const volatile u8 cake_tog_probe;		/* diagnostics: placement census, hold attribution, black box (--toggle probe=1) */

/*
 * DIAGNOSTIC PROBE — not for scoring. Per-arm placement census for
 * ops.select_cpu, so the mailbox hit rate is a measurement instead of an
 * assumption (STATE.md pillar 3 lists it unmeasured). Per-CPU map, plain
 * increment on this CPU's own copy: no atomic, no shared line.
 * Keep disabled for scoring runs.
 */
enum cake_stat {
	CAKE_STAT_SELECT = 0,		/* ops.select_cpu entries */
	CAKE_STAT_SERIAL,		/* serial-handoff arm placed */
	CAKE_STAT_HOME,			/* prev-cpu warm home claim placed */
	CAKE_STAT_WP_ATTEMPT,		/* wake_preempt reached with a live occupant */
	CAKE_STAT_WP_TINY,		/* wakee burst <= 4us (microsecond-class shape) */
	CAKE_STAT_WP_SMALL,		/* wakee burst <= 64us */
	CAKE_STAT_WP_PROTECT,		/* rejected: protect window not met */
	CAKE_STAT_WP_VTIME,		/* rejected: vtime bar */
	CAKE_STAT_WP_STARVED,		/* rejected: pipeline-stage veto */
	CAKE_STAT_WP_FIRED,		/* kick issued */
	/* PROBE hold attribution: 5 queue kinds x {placed, wait>300us, wait>1ms} */
	CAKE_STAT_PL_LOCAL,		/* select_cpu direct, own CPU (LOCAL) */
	CAKE_STAT_PL_LOCAL_ON,		/* select_cpu direct, LOCAL_ON|cpu */
	CAKE_STAT_PL_CPUQ_WAKE,		/* enqueue wake into a per-CPU DSQ */
	CAKE_STAT_PL_CPUQ_CONT,		/* enqueue continuation into a per-CPU DSQ */
	CAKE_STAT_PL_GLOBAL,		/* WAKE_DSQ */
	CAKE_STAT_H3_LOCAL, CAKE_STAT_H3_LOCAL_ON, CAKE_STAT_H3_CPUQ_WAKE,
	CAKE_STAT_H3_CPUQ_CONT, CAKE_STAT_H3_GLOBAL,
	CAKE_STAT_H10_LOCAL, CAKE_STAT_H10_LOCAL_ON, CAKE_STAT_H10_CPUQ_WAKE,
	CAKE_STAT_H10_CPUQ_CONT, CAKE_STAT_H10_GLOBAL,
	CAKE_STAT_PL_SELF, CAKE_STAT_H3_SELF, CAKE_STAT_H10_SELF, /* LOCAL_ON to the calling CPU */
	CAKE_STAT_HD_SYNC, CAKE_STAT_HD_STARVED, CAKE_STAT_HD_IRQ,
	CAKE_STAT_HD_AFF, CAKE_STAT_HD_CONTENDED, CAKE_STAT_HD_NOTIDLE, /* PROBE: home declines */
	CAKE_STAT_HOME_BUSY,		/* home claim succeeded on a CPU with a running task */
	CAKE_STAT_HOME_LOCALQ,		/* home claim succeeded on a CPU whose local DSQ is non-empty */
	CAKE_STAT_H3_HOME_BUSY,		/* ... and the wakee then waited >300us */
	/* PROBE site census: how often each shared-line write, clock read
	 * and claiming kfunc fires (atomics audit 2026-09-03). */
	CAKE_SITE_UI_ENTER,
	CAKE_SITE_UI_ENTER_IDLEW,
	CAKE_SITE_UI_EXIT,
	CAKE_SITE_UI_EXIT_IDLEW,
	CAKE_SITE_QMARK_SET,
	CAKE_SITE_QMARK_SET_SKIP,
	CAKE_SITE_QMARK_CLR,
	CAKE_SITE_QMARK_CLR_SKIP,
	CAKE_SITE_SEAT_CLR,
	CAKE_SITE_SEAT_SET,
	CAKE_SITE_RUNNING,
	CAKE_SITE_FRONTIER_ST,
	CAKE_SITE_WAKE_SERVED_ST,
	CAKE_SITE_WAKE_MARK_ST,
	CAKE_SITE_TACI,
	CAKE_SITE_TACI_WIN,
	CAKE_SITE_TACI_STAGE,
	CAKE_SITE_TACI_HOME,
	CAKE_SITE_TACI_GROOVE,
	CAKE_SITE_TACI_WARM_CORE,
	CAKE_SITE_TACI_WARM_THREAD,
	CAKE_SITE_TACI_WARM,
	CAKE_SITE_TACI_HINT,
	CAKE_SITE_TACI_NOTIFY,
	CAKE_SITE_PICK_IDLE,
	CAKE_SITE_KICK,
	CAKE_SITE_NRQ,
	CAKE_SITE_DSQ_INSERT,
	CAKE_SITE_MOVE_LOCAL,
	CAKE_SITE_KT,
	CAKE_SITE_KT_PERIOD,
	CAKE_SITE_KT_TICKSOON,
	CAKE_SITE_KT_OCCUPANT,
	CAKE_SITE_KT_HANDOFF,
	CAKE_SITE_KT_WAKECLOCK,
	CAKE_SITE_KT_RUNNING,
	CAKE_SITE_KT_PROBE,
	CAKE_SITE_TASK_STORAGE,
	CAKE_SITE_CPU_CURR,
	CAKE_SITE_CORE_CONTENDED,
	CAKE_SITE_STAGE_PROBE,
	CAKE_SITE_TACIW_STAGE,
	CAKE_SITE_TACIW_HOME,
	CAKE_SITE_TACIW_GROOVE,
	CAKE_SITE_TACIW_WARM_CORE,
	CAKE_SITE_TACIW_WARM_THREAD,
	CAKE_SITE_TACIW_WARM,
	CAKE_SITE_TACIW_HINT,
	CAKE_SITE_TACIW_NOTIFY,
	/* clock-pair sums (ns) around one call each; T_CAL is the empty pair. */
	CAKE_SITE_T_NRQ,
	CAKE_SITE_T_TACI,
	CAKE_SITE_T_PICK,
	CAKE_SITE_T_KICK,
	CAKE_SITE_T_CPU_CURR,
	CAKE_SITE_T_TASK_STORAGE,
	CAKE_SITE_T_MOVE,
	CAKE_SITE_T_INSERT,
	CAKE_SITE_T_UI_IDLEW,
	CAKE_SITE_T_QMARK,
	CAKE_SITE_T_CAL,
	/* §G85 seat leaks, counted whether or not the toggle blocks them. */
	CAKE_SITE_LEAK_HOME,
	CAKE_SITE_LEAK_KICK,
	CAKE_SITE_LEAK_DISPATCH,
	/* §G85 seat rules, one count per fire. */
	CAKE_SITE_SEAT_IMMUNE,
	CAKE_SITE_SEAT_RETAKE,
	CAKE_SITE_SEAT_REROUTE,
	CAKE_SITE_SEAT_DECLINE,
	/* A pool head this CPU may not run, forwarded to one that may. */
	CAKE_SITE_POOL_FORWARD,
	/* §G86: a second or later bit tried; a kthread wake sent to the pool. */
	CAKE_SITE_CLAIM_RETRY,
	CAKE_SITE_KT_POOL,
	/* §G88 cross-LLC census: placements and moves whose destination die is
	 * not the task's previous die, per site, with each site's total. */
	CAKE_SITE_SERIAL_X,
	CAKE_SITE_KT_LOCAL,
	CAKE_SITE_KT_LOCAL_X,
	CAKE_SITE_CLAIM_X,
	CAKE_SITE_NOTIFY_KICK,
	CAKE_SITE_NOTIFY_KICK_X,
	CAKE_SITE_PROBE_FIRED,
	CAKE_SITE_PROBE_FIRED_X,
	CAKE_SITE_POOL_SERVED,
	CAKE_SITE_POOL_SERVED_X,
	CAKE_SITE_STEAL_MOVED,
	CAKE_SITE_STEAL_MOVED_X,
	CAKE_STAT_POOL_DIRECT,		/* pool-bound wake directly used an idle claim */
	CAKE_STAT_NR,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CAKE_STAT_NR);
	__type(key, u32);
	__type(value, u64);
} cake_stats SEC(".maps");

static __always_inline void cake_stat_inc(u32 idx)
{
	u64 *v;

	if (!cake_tog_probe)
		return;
	v = bpf_map_lookup_elem(&cake_stats, &idx);

	if (v)
		(*v)++;
}

static __always_inline void cake_stat_add(u32 idx, u64 add)
{
	u64 *v;

	if (!cake_tog_probe)
		return;
	v = bpf_map_lookup_elem(&cake_stats, &idx);

	if (v)
		*v += add;
}

/* PROBE site timing: a clock pair around one call, summed per CPU; the
 * running callback records an empty pair (T_CAL) to subtract. */
#define CAKE_TIMED(site, expr) ({						\
	u64 __t0 = cake_tog_probe ? bpf_ktime_get_ns() : 0;			\
	typeof(expr) __r = (expr);						\
	if (cake_tog_probe)							\
		cake_stat_add((site), bpf_ktime_get_ns() - __t0);		\
	__r; })
#define CAKE_TIMED_VOID(site, stmt) do {					\
	u64 __t0 = cake_tog_probe ? bpf_ktime_get_ns() : 0;			\
	stmt;									\
	if (cake_tog_probe)							\
		cake_stat_add((site), bpf_ktime_get_ns() - __t0);		\
} while (0)

/* PROBE site census wrappers: the kfunc, the clock read, plus one per-CPU
 * count each when --toggle probe=1; the count is dead code when off. */
static __always_inline bool cake_taci(s32 cpu, u32 site)
{
	bool won = CAKE_TIMED(CAKE_SITE_T_TACI, scx_bpf_test_and_clear_cpu_idle(cpu));

	cake_stat_inc(CAKE_SITE_TACI);
	cake_stat_inc(site);
	if (won) {
		cake_stat_inc(CAKE_SITE_TACI_WIN);
		cake_stat_inc(site + (CAKE_SITE_TACIW_STAGE - CAKE_SITE_TACI_STAGE));
	}
	return won;
}

static __always_inline u64 cake_now(u32 site)
{
	cake_stat_inc(CAKE_SITE_KT);
	cake_stat_inc(site);
	return bpf_ktime_get_ns();
}

static __always_inline s32 cake_pick_idle(const struct cpumask *m, u64 flags)
{
	cake_stat_inc(CAKE_SITE_PICK_IDLE);
	return CAKE_TIMED(CAKE_SITE_T_PICK, scx_bpf_pick_idle_cpu(m, flags));
}

static __always_inline void cake_kick(s32 cpu, u64 flags)
{
	cake_stat_inc(CAKE_SITE_KICK);
	CAKE_TIMED_VOID(CAKE_SITE_T_KICK, scx_bpf_kick_cpu(cpu, flags));
}

static __always_inline s32 cake_nrq(u64 dsq_id)
{
	cake_stat_inc(CAKE_SITE_NRQ);
	return CAKE_TIMED(CAKE_SITE_T_NRQ, scx_bpf_dsq_nr_queued(dsq_id));
}

/*
 * Cake-local kfunc bindings through compat.bpf.h's ladders, shaped so the
 * modern kernel pays nothing (§R.8): a ladder whose arms are alternative
 * calls with one argument shape stays inline — the verifier deletes the
 * untaken arms and the register allocation is that of a single call. A
 * ladder whose fallback needs its own stack or argument shape (the
 * insert_vtime args struct, the dsq_peek iterator, the cpu_curr rq deref)
 * is confined to a static __noinline subprogram, so its cost stays inside
 * that frame instead of the hot caller. Global subprograms return s32, not
 * void: a pre-6.19 verifier rejects a void return from a global function.
 */
/* PROBE (hold attribution): tag every placement with its queue kind. */
static __noinline void cake_probe_place(struct task_struct *p, u64 dsq_id,
					u64 enq_flags);

static __noinline void cake_kick_preempt(s32 cpu);

static __noinline bool cake_dsq_insert_vtime(struct task_struct *p, u64 dsq_id,
					     u64 slice, u64 vtime, u64 enq_flags)
{
	cake_stat_inc(CAKE_SITE_DSQ_INSERT);
	cake_probe_place(p, dsq_id, enq_flags);
	return CAKE_TIMED(CAKE_SITE_T_INSERT,
			  scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags));
}

static __always_inline bool cake_dsq_insert(struct task_struct *p, u64 dsq_id,
					    u64 slice, u64 enq_flags)
{
	cake_stat_inc(CAKE_SITE_DSQ_INSERT);
	cake_probe_place(p, dsq_id, enq_flags);
	return CAKE_TIMED(CAKE_SITE_T_INSERT, scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags));
}

static __always_inline bool cake_move_to_local(u64 dsq_id)
{
	cake_stat_inc(CAKE_SITE_MOVE_LOCAL);
	return CAKE_TIMED(CAKE_SITE_T_MOVE, scx_bpf_dsq_move_to_local(dsq_id, 0));
}

/* The occupant of @cpu; advisory-racy exactly as the kfunc read is. */
static __noinline struct task_struct *cake_cpu_curr(s32 cpu)
{
	cake_stat_inc(CAKE_SITE_CPU_CURR);
	return CAKE_TIMED(CAKE_SITE_T_CPU_CURR, __COMPAT_scx_bpf_cpu_curr(cpu));
}

/* Local-DSQ depth. */
static __always_inline u64 cake_local_nr(s32 cpu)
{
	return cake_nrq(CAKE_DSQ_LOCAL_ON | (u32)cpu);
}

static __noinline struct task_struct *cake_dsq_peek(u64 dsq_id)
{
	return __COMPAT_scx_bpf_dsq_peek(dsq_id);
}

/*
 * Direct field write, not scx_bpf_task_set_slice(): the kfunc runs a
 * sub-scheduler authority check cake can never need (§R.17).
 */
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

/*
 * All mutable hot state in ONE BSS struct of 128-byte-stride slots, so any two
 * accessed words land in different 64 B lines AND different adjacent-line
 * prefetcher pairs whatever the struct's base alignment (§R.10).
 */
struct cake_slot {
	u64 word;
	u64 pad[STATE_SLOT_WORDS - 1];
};

struct cake_run_slot {
	u64 stamp;
	u64 sum;
	/*
	 * Per-CPU handoff learning: WOKE plus a saturating confidence count of
	 * consecutive wake-then-block-quickly quanta. Owner-written only, so no
	 * atomics, and it rides a line running/stopping already own (§R.18).
	 */
	u64 hint;
	/* Owner persists for retake after running clears the sleeping-seat bit. */
	u64 seat_pid;
	/* §G85: the holder was just placed behind a stranger; the stranger's
	 * re-enqueue reads it and takes the pool; ops.running clears it. */
	u64 retake;
	/* Acquisition generation disambiguates retirement after PID reuse. */
	u64 seat_seq;
	u64 pad[STATE_SLOT_WORDS - 6];
};

enum {
	CAKE_HINT_WOKE		= 1ULL << 0,
	CAKE_HINT_CONF_SHIFT	= 8,
	CAKE_HINT_CONF_MAX	= 3,
	CAKE_NEIGHBOUR_PROBE_DEPTH = 3,
};

/*
 * HARDWARE-ANCHORED: how short a quantum still counts as "woke someone and got
 * out of the way". A property of this CPU's syscall and switch path, not of
 * the timeslice. In rodata so libbpf's freeze folds it. The loader probes the
 * hardware and LOGS it but must NOT drive it yet (§S.5).
 */
const volatile u64 cake_handoff_max_ns		= 1464;

/*
 * Campaign toggles (`--toggle gNN=0|1`): rodata, so the verifier deletes the
 * off arm at attach and one binary serves both arms — the sanctioned §S.6
 * exception. Scaffolding; defaults are tip behavior (STATE.md 2026-08-22).
 */

/* §G54: next_pow2(nr_cpu_span) - 1, derived in the loader — the rotor
 * masks instead of dividing (no modulo on a per-transition path). */



/*
 * §G56 FOLD: the steal walk as per-LLC qmask bands. One AND plus a
 * find-first-set answers a whole band; the locality (and, under g52, the
 * preferred-core) order lives in the BAND order, not a per-CPU element
 * walk. Narrow hosts only (span <= 64, one qmask word); wide hosts keep
 * the §G25 walk. All loader-filled from runtime topology.
 */



/*
 * This task's mean burst: runtime per voluntary switch, exact to the
 * nanosecond. Supersedes >> log2(nvcsw), which banded (§G11).
 */
static __always_inline u64 cake_burst_ns(const struct task_struct *p)
{
	return p->se.sum_exec_runtime / (p->nvcsw | 1);
}

/* Stage class (§G79). Cross-multiply only when the product fits; beyond
 * that bound even the largest u64 runtime cannot reach the threshold. */
static __always_inline bool cake_stage(const struct task_struct *p)
{
	u64 n = p->nvcsw | 1;

	return n <= (~0ULL / SEAT_BURST_MIN_NS) &&
	       p->se.sum_exec_runtime >= SEAT_BURST_MIN_NS * n;
}

/*
 * Does this task wait longer than it runs? run_delay is the kernel's lifetime
 * runnable-but-not-running total and pcount its dispatch count, so
 * run_delay/pcount is the mean wait against sum_exec_runtime/nvcsw for the
 * mean burst. Cross-multiplied to spend no divide; both sides carry the same
 * pre-scale, which therefore cancels. The threshold is waiting longer than you
 * run — a definition, not a tuning — and it replaces a burst magnitude that
 * measured the wrong axis entirely (§G12).
 */
static __always_inline bool cake_starved(const struct task_struct *p)
{
	u64 wait = p->sched_info.run_delay >> CAKE_RATIO_SHIFT;
	u64 run = p->se.sum_exec_runtime >> CAKE_RATIO_SHIFT;

	if (!run)
		return false;
	return wait * (p->nvcsw | 1) > run * (p->sched_info.pcount | 1);
}

/*
 * Does this task wait longer than one turn of its OWN? cake_starved has no
 * dead zone: as the burst shrinks any queueing wins, so a fan-out worker
 * that runs microseconds reads starved on the wake hop alone. Relocation
 * pays only past a whole turn, so the margin is the task's own slice --
 * twice burst, cake_task_slice's grant -- and no constant enters (§G12).
 */
static __always_inline bool cake_starved_turn(const struct task_struct *p)
{
	u64 wait = p->sched_info.run_delay >> CAKE_RATIO_SHIFT;
	u64 run = p->se.sum_exec_runtime >> CAKE_RATIO_SHIFT;

	if (!run)
		return false;
	return wait * (p->nvcsw | 1) > (run << 1) * (p->sched_info.pcount | 1);
}

_Static_assert(sizeof(struct cake_slot) == STATE_SLOT_BYTES,
	       "cake_slot must preserve cache-isolation stride");
_Static_assert(sizeof(struct cake_run_slot) == STATE_SLOT_BYTES,
	       "cake_run_slot must preserve cache-isolation stride");

struct cake_state {
	/* Global vtime frontier: conditional store from every ops.running. */
	struct cake_slot frontier;
	/*
	 * Per-CPU run accounting. stamp is read remotely by saturated wake
	 * preemption; sum is owner-only and lets ops.stopping charge runtime
	 * with zero clock reads. Both in one slot, so ops.running dirties one
	 * line rather than two (§R.10).
	 */
	struct cake_run_slot run[MAX_CPUS];
	/* ktime each LLC's wake pool was last consumed by any of its CPUs (§R.16, §G89). */
	struct cake_slot wake_served[MAX_LLCS];
	/*
	 * "WAKE_DSQ may hold work" mark gating the global peek in dispatch
	 * (§G41). Own slot: every CPU reads it every dispatch, and it must not
	 * share a line with wake_served, which serving CPUs store to (§R.10).
	 */
	struct cake_slot wake_mark[MAX_LLCS];
	/* A claimed remote idle CPU accepts one pool offer at its next dispatch.
	 * Zero means none; otherwise the value is the source pool index + 1. */
	struct cake_slot remote_pool[64];
	/*
	 * "DSQ[i] may hold work" hint gating the steal ring, one bit per CPU, so
	 * a going-idle dispatch reads QMASK_WORDS words instead of probing one
	 * 128 B slot per CPU. A stale bit is benign by construction (§G25).
	 */
	u64 qmask[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
};

_Static_assert(sizeof(((struct cake_state *)0)->qmask) <= STATE_SLOT_BYTES,
	       "qmask must fit one cache-isolation slot");

static struct cake_state cake;


/*
 * Test before writing, now for a second reason: the bit lives in a word shared
 * with 63 other CPUs, so an unconditional atomic would serialise every dispatch
 * on one line. The plain read is the common case and costs no bus traffic; the
 * atomic fires only on an actual empty<->nonempty transition (§G25, §R.10).
 */
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

/*
 * Wake-routing emptiness reads the queue count directly. Queue marks are
 * steal hints, not proof of emptiness; this count is still only a snapshot.
 * __noinline: inlined, the word address pins across the callers' kfuncs (§G44).
 */
static __noinline bool cake_cpu_dsq_idle(u32 cpu)
{
	return !cake_nrq((u64)cpu);
}

/*
 * Republish this CPU's mark from a head peek. Deliberately __noinline: inlined,
 * LLVM shares the bit and word address between the set and clear arms, hoists
 * both ABOVE the peek call that decides between them, and pins them across it —
 * evicting the caller's own cpu id to the stack (§G25).
 */
static __noinline void cake_qmark_publish(u32 cpu, bool queued)
{
	if (queued)
		cake_qmark_set(cpu);
	else
		cake_qmark_clear(cpu);
}

/*
 * Foreign rescue skips pools with a clear mark; local dispatch still checks
 * its own pool directly. The setter marks AFTER insertion and retirement
 * clears before rechecking. Publish atomically after the insert:
 * a conditional load/store can miss a racing clear while the queue write
 * is still buffered. A single pool has no foreign mark readers.
 */
extern const volatile u32 nr_llcs;

static __always_inline void cake_wake_mark_set(u32 llc)
{
	if (!cake_tog_g89 || nr_llcs <= 1)
		return;
	if (!__atomic_exchange_n(&cake.wake_mark[llc & (MAX_LLCS - 1)].word,
				 1, __ATOMIC_SEQ_CST))
		cake_stat_inc(CAKE_SITE_WAKE_MARK_ST);
}

/* Loader-filled SMT map; -1 means the CPU has no online sibling. */
const volatile s32 cpu_sibling[MAX_CPUS];
/* Loader-proven uniform SMT displacement; 64 selects the generic map walk. */
const volatile u32 cake_smt_shift = 64;
const volatile u64 cake_smt_left;
const volatile u64 cake_smt_right;

/* Loader-maintained, LIVE (§G21, §G30): sink-ness follows device load, so
 * the loader re-probes on its run loop. */
u64 cpu_irq_hot_words[QMASK_WORDS];

/* Kernel-pushed, live to the instruction (§G35): handler entry/exit
 * tracepoints keep a per-CPU in-handler depth. Only the owning CPU writes;
 * cross-CPU reads race benignly (a stale read costs one placement, same as
 * today). Slot-padded so kHz-rate writers never share a line with each
 * other or with the wake-path readers. */
struct cake_irq_slot {
	u32 depth;
	u8 pad[STATE_SLOT_BYTES - sizeof(u32)];
};
struct cake_irq_slot cake_irq_live[MAX_CPUS]; /* global: the loader reads it under -v */

/* Bad wake target: chronically loud (§G33 mask, the average truth) or
 * inside a handler right now (§G35, the instantaneous truth). Each alone
 * misses what the other sees. */
static __always_inline bool cake_cpu_irq_bad(s32 cpu)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	return cpu >= 0 && ((cpu_irq_hot_words[c >> 6] & (1ULL << (c & 63))) ||
			    cake_irq_live[c].depth);
}

/* An IRQ on either SMT thread competes for the physical core. The live
 * depth is advisory; a quiet read cannot promise an interrupt-free run. */
static __always_inline bool cake_core_irq_bad(s32 cpu)
{
	s32 sibling = cpu_sibling[(u32)cpu & (MAX_CPUS - 1)];

	return cake_cpu_irq_bad(cpu) ||
	       (sibling >= 0 && cake_cpu_irq_bad(sibling));
}

/* The timer is the one interrupt scheduled ahead of time (§G36): a CPU whose
 * next tick fires within one measured wake hop would land the task inside
 * the handler the §G35 check just missed. Hop cost is the loader's startup
 * hop probe p99; zero (probe failed) turns the predictor off. Device IRQs
 * stay unpredictable -- below this is physics. */
const volatile u64 cake_wake_hop_ns;

extern const struct tick_device tick_cpu_device __ksym __weak;

static __noinline bool cake_cpu_tick_soon(s32 cpu)
{
	const struct tick_device *td;
	const struct clock_event_device *ed;
	u64 next;

	if (!cake_wake_hop_ns || !bpf_ksym_exists(&tick_cpu_device))
		return false;
	td = bpf_per_cpu_ptr(&tick_cpu_device, (u32)cpu);
	if (!td)
		return false;
	ed = td->evtdev;
	if (!ed)
		return false;
	/* An overdue next_event means the tick is firing right now; a
	 * stopped nohz tick reads as far-future and never trips. */
	next = (u64)ed->next_event;
	return next <= cake_now(CAKE_SITE_KT_TICKSOON) + cake_wake_hop_ns;
}

/* The two-truth cleanliness test, spelled once: chronically loud or
 * mid-handler (§G30/§G35) OR about to take its tick (§G36). */
static __always_inline bool cake_cpu_clean(s32 cpu)
{
	return !cake_cpu_irq_bad(cpu) && !cake_cpu_tick_soon(cpu);
}

static __always_inline void cake_irq_edge(bool enter)
{
	u32 c = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

	if (enter)
		cake_irq_live[c].depth++;
	else if (cake_irq_live[c].depth)
		/* Attach can land mid-handler: first exit has no entry. */
		cake_irq_live[c].depth--;
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

/*
 * The CPU id span cake scans, bounding the steal ring and neighbour probe.
 * Rodata, so libbpf's freeze lets the verifier fold it and prune the walk's
 * bound checks; ops.init validates it against nr_cpu_ids (§R.21).
 */
const volatile u32 nr_cpu_span;
/* Every PRESENT CPU id is below 64: the idle words, seats, qmask and the
 * die-local claims run on word 0. Keyed on present ids, not the span: a
 * guest with hotplug headroom has a span past 64 and eight CPUs (audit
 * 2026-09-06). The loader sets it; a wider host keeps the counted census. */
const volatile u8 cake_one_word = 1;

/* Loader-sorted: same CCD, same cache-capacity tier, then unrestricted.
 * Fixed span so one binary fits any host; live only when the loader saw
 * multiple CCDs AND the host fits the matrix — rodata, so the verifier
 * folds the dead branch away on every other machine. */
const volatile u16 cpu_steal_order[STEAL_SPAN * STEAL_SPAN];
/* Populated entries per row, distinct from the possible CPU ID span. */
const volatile u32 nr_steal_cpus;
/* §G88: the CPUs sharing each CPU's LLC, one word per CPU (bits < 64; the
 * census paths only run on hosts inside one word). Loader-filled; a host
 * with one LLC or an unreadable topology gets all ones, which is exactly
 * the LLC-blind walk of 2026-09-04 that cost a 9950X3D 60% of its 1% low. */
const volatile u64 cpu_llc_word[MAX_CPUS];
/* §G89: dense LLC index per CPU (0 on a one-LLC host) and the LLC count. */
const volatile u8 cpu_llc_id[MAX_CPUS];
/* Physical domain identity survives pool collapse and covers every CPU.
 * 0xffff means topology unavailable; narrow masks are only pick accelerators. */
const volatile u16 cpu_llc_domain[MAX_CPUS];
const volatile u32 nr_llcs = 1;

static __always_inline u32 cake_llc_of(s32 cpu)
{
	return cake_tog_g89 ?
	       (u32)cpu_llc_id[(u32)cpu & (MAX_CPUS - 1)] & (MAX_LLCS - 1) : 0;
}

static __always_inline u64 cake_pool_dsq(u32 llc)
{
	return (u64)LLC_WAKE_DSQ_BASE + (llc & (MAX_LLCS - 1));
}

/* Physical locality, independent of the pool layout and g89 toggle. */
static __always_inline bool cake_cross_llc(s32 from, s32 to)
{
	u32 a = (u32)from, b = (u32)to;
	u16 da, db;

	if (a >= MAX_CPUS || b >= MAX_CPUS)
		return false;
	/* Keep the masks on the indexing registers: LLVM may combine the
	 * bounds above into (a | b), which the verifier cannot propagate back. */
	barrier_var(a);
	barrier_var(b);
	da = cpu_llc_domain[a & (MAX_CPUS - 1)];
	db = cpu_llc_domain[b & (MAX_CPUS - 1)];
	return da != 0xffff && db != 0xffff && da != db;
}

/* PROBE: count a cross-die placement at @site. Called only under the probe
 * toggle, so the die test never sits in a hot frame. */
static __noinline void cake_probe_x(u32 site, s32 from, s32 to)
{
	if (cake_cross_llc(from, to))
		cake_stat_inc(site);
}
const volatile u8 steal_order_live;

/*
 * Reciprocal-weight table for division-free vtime charging:
 *
 *   recip_weight[i] = (1024 << 20) / sched_prio_to_weight[i]
 *
 * so `used * recip_weight[i] >> 20 == used * 1024 / weight`. Indexed by
 * `nice + 20 == static_prio - 100 ∈ [0, 39]`, with SCHED_IDLE's distinct raw
 * weight 3 at IDLE_RECIP_INDEX. Sized to a power of 2 so the index masks.
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

static __noinline u64 cake_scale_vtime_slow(u64 base, u64 runtime, u64 reciprocal)
{
	return base + (runtime >> RECIP_SHIFT) * reciprocal +
	       ((runtime & RECIP_MASK) * reciprocal >> RECIP_SHIFT);
}


/*
 * Return @base plus @runtime scaled by the task's reciprocal weight, without
 * letting the full-width product wrap. Splitting runtime at the fixed-point
 * radix is algebraically identical and stays exact past eight years of
 * uninterrupted nice-19 runtime. @base is folded in here rather than added by
 * the caller so it need not live across the overflow-safe call (§R.11).
 */
static __always_inline u64 cake_scale_vtime_add(u64 base, u64 runtime, u32 idx)
{
	u64 reciprocal = recip_weight[idx & RECIP_INDEX_MASK];

	/* Every ordinary slice takes the original single-multiply fast path. */
	if (runtime <= CAKE_RECIP_RUNTIME_FAST_MAX)
		return base + ((runtime * reciprocal) >> RECIP_SHIFT);

	return cake_scale_vtime_slow(base, runtime, reciprocal);
}

static __always_inline u64 cake_scale_vtime(u64 runtime, u32 idx)
{
	return cake_scale_vtime_add(0, runtime, idx);
}

/* Preserve the exact 40-level nice table while honoring SCHED_IDLE weight 3. */
static __always_inline u32 cake_recip_index(const struct task_struct *p)
{
	if (p->policy == SCHED_IDLE)
		return IDLE_RECIP_INDEX;
	return (u32)(p->static_prio - STATIC_PRIO_BASE);
}

/*
 * The occupant of @tcpu, as the only two numbers any caller wants: how long it
 * has held the CPU, and its live vtime once that runtime is charged. Returns 0
 * when there is no SCX occupant (idle, or a class carrying no vtime); @ran_out
 * is written only when it returns non-zero. Five call sites once computed this
 * identically (§R.11).
 */
static __noinline u64 cake_occupant_live(s32 tcpu, u64 *ran_out)
{
	struct cake_run_slot *rs = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	struct task_struct *curr;
	u64 cv, ran, stamp;
	u32 cidx;

	curr = cake_cpu_curr(tcpu);
	if (!curr)
		return 0;
	/* Not on the ext runqueue: RT, DL or idle, or a thread promoted to
	 * SCHED_FIFO after it ran here, whose dsq_vtime the kernel leaves
	 * behind (audit 2026-09-06). Nothing to out-deserve or evict. */
	if (!(curr->scx.flags & CAKE_TASK_QUEUED))
		return 0;
	cv = curr->scx.dsq_vtime;
	if (!cv)
		return 0;
	cidx = cake_recip_index(curr);

	stamp = rs->stamp;
	ran = cake_now(CAKE_SITE_KT_OCCUPANT) - stamp;
	*ran_out = ran;
	return cake_scale_vtime_add(cv, ran, cidx);
}

static u64 cake_seat_word __attribute__((aligned(STATE_SLOT_BYTES)));

/* The kernel owns claim and idle-to-idle recovery. Never mirror claimable
 * state in BSS: update_idle does not report every idle-mask refresh. */
static __always_inline u64 cake_idle_word(void)
{
	const struct cpumask *mask = scx_bpf_get_idle_cpumask();
	u64 word = mask->bits[0];

	scx_bpf_put_idle_cpumask(mask);
	return word;
}

static __always_inline u64 cake_core_word(void)
{
	const struct cpumask *mask = scx_bpf_get_idle_smtmask();
	u64 word = mask->bits[0];

	scx_bpf_put_idle_cpumask(mask);
	return word;
}

/* A home must remain available as a whole core, including pending claims
 * on any SMT sibling. A sibling's current task misses claim-to-dispatch
 * transitions. Wide hosts retain the existing occupant check (§G38). */
static __always_inline bool cake_core_contended(s32 cpu)
{
	s32 sib;
	struct task_struct *curr;

	cake_stat_inc(CAKE_SITE_CORE_CONTENDED);
	/* Without SMT the kernel returns its logical-idle mask. This one
	 * read therefore covers both the home CPU and every sibling. */
	if (cake_one_word)
		return (u32)cpu >= 64 ||
		       !(cake_core_word() & (1ULL << ((u32)cpu & 63)));
	sib = cpu_sibling[(u32)cpu & (MAX_CPUS - 1)];
	if (sib < 0)
		return false;

	curr = cake_cpu_curr(sib);
	return curr && curr->pid;
}

/* Lower rank is better. Equal/unknown platforms prune the ranked scan. */
const volatile u32 cake_rank_tiers;
const volatile u64 cpu_perf_tier[64];
const volatile u64 cpu_perf_known;

static __always_inline u64 cake_rank_tier(u64 w)
{
	u32 i;

	if (cake_rank_tiers <= 1 || (w & ~cpu_perf_known))
		return w;
	for (i = 0; i < 64; i++) {
		u64 best;

		if (i >= cake_rank_tiers)
			break;
		best = w & cpu_perf_tier[i];
		if (best)
			return best;
	}
	return w; /* newly online/unranked CPUs remain usable */
}

/* Serializes owner + reservation-bit transitions on this CPU only. No
 * helpers may run under the lock; all decisions still revalidate claims. */
struct cake_seat_lock {
	struct bpf_spin_lock lock;
	u8 pad[STATE_SLOT_BYTES - sizeof(struct bpf_spin_lock)];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct cake_seat_lock);
} cake_seat_locks SEC(".maps");

enum { CAKE_SEAT_RELEASE, CAKE_SEAT_RUN, CAKE_SEAT_HOLD };

static __always_inline u64 cake_seat_update(u32 cpu, u32 pid, u32 action, u64 seq)
{
	struct cake_seat_lock *lock;
	struct cake_run_slot *rs;
	u64 bit;

	if (!cake_tog_g85 || !cake_one_word || cpu >= 64)
		return 0;
	lock = bpf_map_lookup_elem(&cake_seat_locks, &cpu);
	if (!lock)
		return 0;
	/* The helper can invalidate the verifier's bound on the stack key.
	 * Rebound the reloaded value before the array access and shift. */
	cpu &= 63;
	rs = &cake.run[cpu];
	bit = 1ULL << cpu;
	bpf_spin_lock(&lock->lock);
	if (action == CAKE_SEAT_HOLD) {
		seq = ++rs->seat_seq;
		rs->seat_pid = pid;
		__sync_fetch_and_or(&cake_seat_word, bit);
	} else if (action == CAKE_SEAT_RUN ||
		   (rs->seat_pid == pid && rs->seat_seq == seq)) {
		__sync_fetch_and_and(&cake_seat_word, ~bit);
		if (action == CAKE_SEAT_RELEASE)
			rs->seat_pid = 0;
	}
	bpf_spin_unlock(&lock->lock);
	return seq;
}

/* §G85: is @cpu a seat held by a task other than @p? Counts the leak at
 * @site and blocks the caller. */
static __always_inline bool cake_seat_blocks(s32 cpu, const struct task_struct *p,
					     u32 site)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	if (c >= 64 || !((cake_seat_word >> c) & 1) ||
	    cake.run[c].seat_pid == (u64)(u32)p->pid)
		return false;
	cake_stat_inc(site);
	return cake_tog_g85;
}
static u64 cake_idle_words[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* PROBE scratch: was the pool head this CPU is about to take from another die. */
static u8 cake_probe_pool_x[MAX_CPUS];

/* Expand a CPU set through the loader's SMT map. Used for preferences,
 * never as a reservation of both threads. */
static __always_inline u64 cake_smt_expand(u64 seats)
{
	u64 cores = seats;
	u32 i, shift = cake_smt_shift;

	/* This is the same map, factored once at startup instead of walking
	 * each held seat on every placement. No-SMT maps reduce to identity. */
	if (!shift)
		return seats;
	if (shift < 64)
		return seats | ((seats & cake_smt_left) << shift) |
		       ((seats & cake_smt_right) >> shift);

	for (i = 0; i < 64 && seats; i++) {
		u32 c = (u32)__builtin_ctzll(seats);
		s32 sib = cpu_sibling[c & (MAX_CPUS - 1)];

		if (sib >= 0 && sib < 64)
			cores |= 1ULL << ((u32)sib & 63);
		seats &= seats - 1;
	}
	return cores;
}

/* The existing chronic IRQ measurement, applied to physical cores. Keep
 * the eligible set when every choice is noisy: work must still progress. */
static __always_inline u64 cake_prefer_irq_clean(u64 word, u64 noisy)
{
	u64 clean = word & ~noisy;

	return clean ? clean : word;
}

/* Cold choices: whole core, seat, measured IRQ interference, then platform
 * rank. The caller removes failed claims from its FULL eligible set. */
static __always_inline s32 cake_pick_cold(u64 w, u64 cores, u64 seats, u64 noisy)
{
	u64 best = w & cores;

	if (!best)
		best = w;
	if (best & ~seats)
		best &= ~seats;
	return (s32)__builtin_ctzll(cake_rank_tier(cake_prefer_irq_clean(best, noisy)));
}

/* PROBE hold attribution -- not for scoring. */
struct cake_probe_tag {
	u64 place_ns;
	u32 kind;
	u32 target;		/* dsq id low bits (cpu) */
	u32 caller;		/* placing CPU */
	u32 waker_pid;
	u64 seats, core_free, thread_free, idle_word;
};

/* PROBE black box: the placement context of the last waits > 10 ms. */
struct cake_bb_rec {
	u64 wait_ns, place_ns, seats, core_free, thread_free, idle_word;
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

static u32 cake_probe_busy_flag[MAX_CPUS];

static __noinline void cake_probe_place(struct task_struct *p, u64 dsq_id,
					u64 enq_flags)
{
	struct cake_probe_tag *t;
	u32 kind;
	u32 me;

	if (!cake_tog_probe)
		return;
	me = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

	if (!(dsq_id & CAKE_DSQ_LOCAL_ON) && dsq_id >= (u64)LLC_WAKE_DSQ_BASE &&
	    dsq_id < (u64)LLC_WAKE_DSQ_BASE + MAX_LLCS)
		kind = 4;
	else if (dsq_id & CAKE_DSQ_LOCAL_ON)
		kind = ((u32)dsq_id & (MAX_CPUS - 1)) ==
		       (bpf_get_smp_processor_id() & (MAX_CPUS - 1)) ? 5 : 1;
	else if (dsq_id == CAKE_DSQ_LOCAL)
		kind = 0;
	else
		kind = (enq_flags & CAKE_ENQ_WAKEUP) ? 2 : 3;
	t = bpf_task_storage_get(&cake_probe_tags, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	t->place_ns = cake_now(CAKE_SITE_KT_PROBE);
	t->target = (u32)dsq_id & (MAX_CPUS - 1);
	t->caller = me;
	{
		struct task_struct *w = bpf_get_current_task_btf();

		t->waker_pid = w ? (u32)w->pid : 0;
	}
	t->seats = cake_seat_word; t->core_free = cake_core_word();
	t->thread_free = cake_idle_word(); t->idle_word = cake_idle_word();
	if (cake_probe_busy_flag[me]) {
		kind = 6;
		cake_probe_busy_flag[me] = 0;
	}
	t->kind = kind;
	if (kind == 6)
		return;
	cake_stat_inc(kind == 5 ? CAKE_STAT_PL_SELF : CAKE_STAT_PL_LOCAL + kind);
}

static __noinline void cake_probe_run(struct task_struct *p, u64 now)
{
	struct cake_probe_tag *t;
	u64 wait;

	if (!cake_tog_probe)
		return;
	t = bpf_task_storage_get(&cake_probe_tags, p, 0, 0);
	if (!t || !t->place_ns)
		return;
	wait = now - t->place_ns;
	if (wait > 10 * NSEC_PER_MSEC) {
		u32 i = __atomic_fetch_add(&cake_blackbox_n, 1, __ATOMIC_RELAXED) & 3;
		struct cake_bb_rec *b = &cake_blackbox[i];

		b->wait_ns = wait; b->place_ns = t->place_ns; b->seats = t->seats;
		b->core_free = t->core_free; b->thread_free = t->thread_free;
		b->idle_word = t->idle_word; b->pid = (u32)p->pid; b->kind = t->kind;
		b->target = t->target; b->caller = t->caller; b->waker_pid = t->waker_pid;
		b->ran_on = (u32)p->thread_info.cpu;
		__builtin_memcpy(b->comm, p->comm, 16);
	}
	t->place_ns = 0;
	if (wait > 300 * NSEC_PER_USEC)
		cake_stat_inc(t->kind == 6 ? CAKE_STAT_H3_HOME_BUSY :
			      t->kind == 5 ? CAKE_STAT_H3_SELF :
			      CAKE_STAT_H3_LOCAL + (t->kind & 7));
	if (wait > 1000 * NSEC_PER_USEC)
		cake_stat_inc(t->kind == 5 ? CAKE_STAT_H10_SELF :
			      CAKE_STAT_H10_LOCAL + (t->kind & 7));
}

/*
 * Wake preemption: kick @tcpu off its occupant for @p, but only once the
 * occupant has run at least @min_ran and @p out-deserves its LIVE vtime.
 *
 * @min_ran is a fraction of the observed FRAME, not of the timeslice: how long
 * a waker may be made to wait is a display question. A sixteenth at the
 * global-wake floor, a quarter for the speculative neighbour probe, which must
 * be surer before disturbing another CPU (§G11.4).
 *
 * LIVE vtime, not the stored one: curr's dsq_vtime is charged only at
 * stopping, so mid-slice it looks eternally deserving. A zero live vtime means
 * RT/DL or idle, which we neither can nor need preempt. §R.1.
 */
/* Placement history orders equivalent candidates, never proves availability.
 * Successful home placement skips this lookup; seats retain an explicit owner. */
struct cake_groove {
	u16 seat_cpu; /* owned CPU + 1, including retained retake identity */
	s16 last_win;		/* cpu + 1; 0 = none */
	u32 seat_pid; /* identity used at acquisition; nonleader exec changes pid */
	u64 seat_seq; /* release only this acquisition, including after PID reuse */
};

/* A task's callbacks serialize its storage. Seat replacement on another
 * CPU is concurrent, hence the owner-checked locked transition below. */
static __always_inline void cake_seat_retire(struct cake_groove *gr, u32 pid,
					    u32 keep_cpu_plus_one)
{
	if (gr && gr->seat_cpu &&
	    (gr->seat_cpu != keep_cpu_plus_one || gr->seat_pid != pid)) {
		cake_seat_update((u32)gr->seat_cpu - 1, gr->seat_pid,
				 CAKE_SEAT_RELEASE, gr->seat_seq);
		gr->seat_cpu = 0;
	}
}

/* One pool insert: the die's pool, then its mark, after the insert (§G41). */
static __always_inline void cake_pool_insert(struct task_struct *p, s32 tcpu,
					     u64 slice, u64 vt, u64 flags)
{
	u32 llc = cake_llc_of(tcpu);

	cake_dsq_insert_vtime(p, cake_pool_dsq(llc), slice, vt, flags);
	cake_wake_mark_set(llc);
}

/* Retire an observed empty pool, then recheck after the clear. A producer
 * inserts before publishing its mark, so either this recheck or that
 * publication preserves visibility. Only empty transitions pay the atomic. */
static __noinline void cake_wake_mark_retire(u32 llc)
{
	u32 l = llc & (MAX_LLCS - 1);

	if (!cake.wake_mark[l].word)
		return;
	__atomic_exchange_n(&cake.wake_mark[l].word, 0, __ATOMIC_SEQ_CST);
	if (cake_nrq(cake_pool_dsq(l)))
		cake_wake_mark_set(l);
}

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_groove);
} cake_grooves SEC(".maps");

static __always_inline struct cake_groove *cake_groove_of(struct task_struct *p)
{
	cake_stat_inc(CAKE_SITE_TASK_STORAGE);
	return CAKE_TIMED(CAKE_SITE_T_TASK_STORAGE,
			  bpf_task_storage_get(&cake_grooves, p, 0,
					       BPF_LOCAL_STORAGE_GET_F_CREATE));
}

static __noinline u64 cake_task_slice(struct task_struct *p __arg_trusted);

static __noinline bool cake_wake_preempt(struct task_struct *p, s32 tcpu,
					 u32 protect_shift, u64 slice)
{
	u64 ran = 0;
	u64 live = cake_occupant_live(tcpu, &ran);
	struct task_struct *curr;

	/* §G39-B' census: which gate refuses the microsecond-class successor.
	 * Counters only -- behavior is identical to the ungated build. Shape
	 * buckets are cross-multiplied so the census spends no divide (§R.24). */
	/* Guard the classification itself so normal execution drops its
	 * task reads and arithmetic along with the counters. */
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
	/* §G87: how long a wakee may be made to wait is bounded by ITS OWN
	 * slice, not only by a fixed frame fraction: a microsecond sleeper
	 * (timer wake, input, audio) behind a fresh occupant waited out the
	 * whole SLICE_NS>>4 window -- cyclictest spikes >100 us at 5x native,
	 * schbench wake p99.9 equal to the window (2026-09-04). The occupant
	 * keeps at least the handoff floor, which the slice already carries. */
	{
		u64 protect = (u64)SLICE_NS >> protect_shift;

		/* the wakee's slice was computed once at its insert (§G87) */
		if (cake_tog_g87 && slice < protect)
			protect = slice;
		if (ran < protect) {
			cake_stat_inc(CAKE_STAT_WP_PROTECT);
			return false;
		}
	}
	if (!time_before(p->scx.dsq_vtime, live)) {
		cake_stat_inc(CAKE_STAT_WP_VTIME);
		return false;
	}

	/*
	 * Never preempt a pipeline stage; tested last so rejections stay
	 * cheap (§G10.5).
	 */
	curr = cake_cpu_curr(tcpu);
	if (curr && cake_starved(curr)) {
		cake_stat_inc(CAKE_STAT_WP_STARVED);
		return false;
	}
	/* §G85: a stage back on its own seat is not the victim. It runs more
	 * than it waits, so cake_starved never covers it, and it carries the
	 * highest live vtime on the box, so every gate above elects it. */
	if (cake_tog_g85 && curr && (u32)tcpu < 64 &&
	    cake.run[(u32)tcpu & (MAX_CPUS - 1)].seat_pid ==
	    (u64)(u32)curr->pid) {
		cake_stat_inc(CAKE_SITE_SEAT_IMMUNE);
		return false;
	}

	cake_stat_inc(CAKE_STAT_WP_FIRED);
	cake_kick_preempt(tcpu);
	return true;
}


/*
 * Is the SYSTEM serial right now? Co-location is a bet that there is nowhere
 * better than the waker's CPU, and that is only true when almost nothing is
 * runnable. Per-CPU emptiness cannot answer this -- a parallel workload with
 * fewer threads than CPUs has empty per-CPU queues by definition -- so the
 * discriminant has to be the global one (§G9.3, §G10).
 *
 * Restored 2026-07-30: G9.4 deleted this term as "cheaper AND sharper" and the
 * game regression dates from exactly there. Helldivers 2 runs ~62% idle
 * against this 75% threshold, so it declines precisely where G9.4 admits.
 */
/* §G45: idle census kept by ops.update_idle. On a host inside one word the
 * count is the word's popcount (§G82); a wider host keeps this counter,
 * which flips with the bit (test-gated, idempotent) and ops.init seeds. */
static u64 cake_idle_nr __attribute__((aligned(STATE_SLOT_BYTES)));

static __always_inline u32 cake_idle_count(void)
{
	if (cake_one_word)
		return (u32)__builtin_popcountll(cake_idle_word());
	return (u32)cake_idle_nr;
}

/* Kernel idle masks are advisory snapshots; only a successful atomic
 * test-and-clear authorizes direct placement on the selected logical CPU. */

/* §G79 SEAT HOLD. A stage-class thread (burst >= SEAT_BURST_MIN_NS) that
 * blocks will wake again within the frame; in the stack its core was taken
 * in that gap by a dxvk or render wake and it came back cold 450 times a
 * second (GameThread 12,629 migrations vs 1.1.3's 650). Its CPU is marked
 * held; other wakes skip held cores while any other core is free; whoever
 * runs there clears it. The owner's home claim on its own seat is unaffected. */


/* §G69: every local placement is CLAIMED at this instant (1.1.3's certainty)
 * and chosen warm-first (cake's placement): a whole idle core from the
 * census, then any idle thread, each taken with the atomic idle claim so a
 * second waker can never stack behind it. Narrow hosts only; -1 sends the
 * wake to the pool. */
static __noinline s32 cake_claim_warm(struct task_struct *p __arg_trusted,
				      s32 groove)
{
	u32 prev = (u32)p->thread_info.cpu & (MAX_CPUS - 1);
	u64 w, cores, seats, preferred, noisy;
	s32 c;
	u32 i;

	if (!cake_one_word)
		return -1;
	w = cake_idle_word() & p->cpus_ptr->bits[0] & cpu_llc_word[prev];
	if (!w)
		return -1;
	cores = cake_core_word() & w;
	/* One IRQ snapshot per search, including on irregular SMT maps. */
	noisy = cake_smt_expand(cpu_irq_hot_words[0]);
	seats = cake_tog_g85 ? cake_seat_word : 0;
	if (prev < 64 && cake.run[prev].seat_pid == (u64)(u32)p->pid)
		seats &= ~(1ULL << prev);
	seats = cake_smt_expand(seats);
	preferred = cores & ~seats;
	if (!preferred)
		preferred = cores;
	preferred = cake_prefer_irq_clean(preferred, noisy);
	/* A remembered warm winner precedes platform rank on equivalent cores. */
	if (groove >= 0 && groove < 64 && (preferred & (1ULL << groove))) {
		if (cake_taci(groove, CAKE_SITE_TACI_GROOVE))
			return groove;
		w &= ~(1ULL << groove);
	}
	/* A failed preferred claim cannot discard less-preferred idle CPUs. */
	for (i = 0; i < CLAIM_TRIES && w; i++) {
		c = cake_pick_cold(w, cores, seats, noisy);
		if (cake_taci(c, CAKE_SITE_TACI_WARM))
			return c;
		w &= ~(1ULL << c);
		if (!cake_tog_g86)
			break;
	}
	return -1;
}

static __noinline void cake_kick_preempt(s32 cpu)
{
	cake_kick(cpu, CAKE_KICK_PREEMPT);
}



static __noinline bool cake_system_serial(void)
{
	u32 nr;

	/* One word read replaces the kernel mask walk per wake (§G45). */
	nr = cake_idle_count();

	return nr * 4 >= nr_cpu_span * 3;
}

/*
 * The liveness term: cake_nrq() counts tasks WAITING, never the
 * one EXECUTING, so a CPU busy mid-slice reads as empty and the co-location
 * gate would admit onto it. Admit when a known SCX occupant is within one
 * handoff of its own typical burst end. This estimates a likely yield.
 *
 * Measured RELATIVE to the occupant, not against a fixed age: an absolute
 * window cannot tell a serial partner about to block from a long-running
 * thread that merely started recently, and reading it as the latter is what
 * cost Helldivers 2 its tails (§R.1, §G9.7; game result in STATE.md).
 *
 * Cannot be exact: ALLOW_QUEUED_WAKEUP hides the waker, and historical burst
 * length cannot prove that the occupant's next operation will block.
 *
 * The verdict is burst < ran + max, cross-multiplied to sum_exec <
 * (ran + max) * nvcsw so the gate spends no divide; operands >= 2^32 take
 * the exact divide path instead (§R.24).
 */
static __noinline bool cake_handoff_yields(s32 tcpu)
{
	struct task_struct *curr = cake_cpu_curr(tcpu);
	u64 ran, burst, lim, n;

	/* Missing/non-SCX state cannot prove that an occupant will yield. */
	if (!curr || !(curr->scx.flags & CAKE_TASK_QUEUED) || !curr->scx.dsq_vtime)
		return false;

	ran = cake_now(CAKE_SITE_KT_HANDOFF) -
	      cake.run[(u32)tcpu & (MAX_CPUS - 1)].stamp;
	n = curr->nvcsw | 1;
	lim = ran + cake_handoff_max_ns;

	if (!((lim | n) >> 32))
		return curr->se.sum_exec_runtime < lim * n;

	burst = cake_burst_ns(curr);
	return burst <= ran || burst - ran < cake_handoff_max_ns;
}


/* Exact min(2 * floor(runtime/n), floor(age/(2*n))) with one division.
 * Its half is q = floor(min(runtime, floor(age/4))/n). The low bit is
 * present only if BOTH original terms reach 2*q+1. q*n <= runtime and
 * q*n <= age/4, so both remainder tests and shifts are overflow-safe. */
static __always_inline u64 cake_slice_from_service(u64 runtime, u64 age, u64 n)
{
	u64 cycle_budget = age >> PERIOD_SLICE_CAP_SHIFT;
	u64 work = cycle_budget >> 1;
	u64 q, base, want;
	u64 cap = (u64)SLICE_NS >> PERIOD_SLICE_CAP_SHIFT;

	if (runtime < work)
		work = runtime;
	q = work / n;
	base = q * n;
	want = (q << 1) + (runtime - base >= n &&
			   cycle_budget - (base << 1) >= n);

	if (want > cap)
		want = cap;
	if (want < cake_handoff_max_ns)
		want = cake_handoff_max_ns;
	return want;
}

/* Twice the mean burst, capped at half the mean cycle and fixed slice,
 * then floored at the handoff cost. This is a preemption timer (§G10.4,
 * §G18, §R.28); all inputs come from the task, with one clock read. */
static __noinline u64 cake_task_slice(struct task_struct *p __arg_trusted)
{
	return cake_slice_from_service(p->se.sum_exec_runtime,
			cake_now(CAKE_SITE_KT_PERIOD) - p->start_time,
			p->nvcsw | 1);
}

/* The S1d dose: three quarters of the unused slice, as two shifts (§R.13). */
static __always_inline u64 cake_sleeper_dose(u64 unused)
{
	return (unused >> 1) + (unused >> 2);	/* 3/4 */
}

/*
 * How much deeper than the uniform floor this task's sleeper key may sit:
 * proportional to the slice fraction it leaves unused, so a short-burst
 * cadence task outranks a full-slice compute wake instead of tying it and
 * serving FIFO. Burst estimate is sum_exec >> log2(nvcsw) — no map, no
 * division, within 2x of the true mean (§R.13). Stage bursts only: the dose
 * inverts with burst, so ungated it ranks a worker above a render stage
 * (§G10.6).
 */
static __always_inline u64 cake_cadence_depth(const struct task_struct *p)
{
	u64 burst = cake_burst_ns(p);
	u64 vs = SLICE_NS;

	if (!cake_starved(p) || burst >= vs)
		return 0;
	return cake_sleeper_dose(vs - burst);
}

/*
 * The wake arm's insert key: the sleeper clamp taken against a floor deepened
 * by the task's unused slice fraction. Recomputed at each use rather than held
 * — every input is a plain load, and the frontier it reads is advisory, so a
 * later read is simply a fresher one (§R.13).
 */
static __noinline u64 cake_wake_vtime(const struct task_struct *p)
{
	u64 lo = cake.frontier.word - SLICE_NS - cake_cadence_depth(p);
	u64 d  = p->scx.dsq_vtime - lo;

	return lo + (d & ~((u64)((s64)d >> 63)));
}

/*
 * Direct dispatch must pay the same vtime floor as a queued admission —
 * scx_bpf_dsq_insert() takes no vtime, so without this a long sleeper admitted
 * directly keeps an arbitrarily old key and monopolises the moment load rises.
 * Admission is service whichever door it comes through (§R.13).
 */
static __always_inline void cake_direct_clamp(struct task_struct *p)
{
	p->scx.dsq_vtime = cake_wake_vtime(p);
}



/*
 * ops.select_cpu — claimed idle placement, admitted busy home, or the pool.
 *
 * Idle choices require a kernel claim. Serial handoff and seat retake are
 * explicit admissions behind an occupant; neither claims that CPU is idle.
 * A wake admitted by none of these paths returns prev_cpu and ops.enqueue
 * puts it in the shared pool (§G65, §G69, §G71).
 */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct cake_groove *gr;
	bool stage;
	/* A busy/ineligible home is not a warm-half candidate. */
	bool home_askable = false, seat_blocked;
	u32 home_decline = CAKE_STAT_HD_SYNC;
	s32 c;

	cake_stat_inc(CAKE_STAT_SELECT);

	/*
	 * Serial-handoff co-location, for an inferred handoff pair: a
	 * saturated learned handoff bit, no WAKE_SYNC, the wakee allowed here,
	 * both queues empty, and an occupant estimated to yield soon. No
	 * preempt -- the waker still holds the mutex. Never onto an interrupt
	 * sink: an ISR-origin wake mimics the handoff shape, but the "waker" is
	 * interrupt context and its CPU carries the ISR shadow (§G30). MUST run
	 * before select_cpu_dfl(), which RESERVES the idle CPU it returns
	 * (§R.1). Letting SYNC wakes in was tried and ABORTED: pipe -36.8%,
	 * context switches +46% -- the §R.6 weld, measured again (§G39).
	 */
	{
		u32 wc = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
		struct cake_run_slot *wr = &cake.run[wc];
		bool serial = ((wr->hint >> CAKE_HINT_CONF_SHIFT) &
			       CAKE_HINT_CONF_MAX) >= CAKE_HINT_CONF_MAX;

		if (!(wr->hint & CAKE_HINT_WOKE))
			wr->hint |= CAKE_HINT_WOKE;

		/* No core-contended veto here: the sibling's occupant in a
		 * handoff regime is usually another transient pair, and the
		 * veto exiled mutex pairs from co-location for a measured
		 * -69% (§G38.1 amendment; the home claim keeps its veto). */
		if (serial && !(wake_flags & CAKE_WAKE_SYNC) &&
		    !cake_cpu_irq_bad((s32)wc) &&
		    bpf_cpumask_test_cpu((s32)wc, p->cpus_ptr) &&
		    cake_system_serial() &&
		    cake_cpu_dsq_idle(wc) &&
		    !cake_local_nr((s32)wc) &&
		    cake_handoff_yields((s32)wc)) {
			s32 wcpu = (s32)wc;

			cake_direct_clamp(p);
			cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)wcpu,
					cake_task_slice(p), 0);
			cake_stat_inc(CAKE_STAT_SERIAL);
			if (cake_tog_probe)
				cake_probe_x(CAKE_SITE_SERIAL_X, prev_cpu, wcpu);
			return wcpu;
		}
	}

	/* Serial placement above needs neither groove storage nor stage class. */
	stage = cake_stage(p);

	/*
	 * Cache-warm home claim for a task that is SERVED rather than waiting:
	 * select_cpu_dfl prefers a fully idle core over a merely idle prev_cpu,
	 * which is wrong for an occupant of its own cache. WAKE_SYNC excluded --
	 * there the waker's cache holds the data. MUST precede select_cpu_dfl(),
	 * which reserves what it returns (§G13).
	 *
	 * The claim is declined on a contended core: the home is only warm if
	 * the task gets the whole core to run on (§G38).
	 */
	/* §G85 RETAKE: a stage whose own seat is run by a non-stage occupant
	 * (the seat's dispatch took pool work while the stage blocked) takes
	 * the seat back at once: placed behind the occupant, the occupant
	 * kicked out and rerouted to the pool by ops.enqueue. Unfair on
	 * purpose: the frame path outranks a worker slice (GAME-FIRST). RT,
	 * idle, pinned and another stage are never evicted. */
	/* The seat bit still up means nothing ran there since the holder
	 * blocked (running clears it), so there is no occupant to evict: the
	 * occupant read below is skipped on the common return (audit
	 * 2026-09-06). */
	if (cake_tog_g85 && stage && prev_cpu >= 0 && (u32)prev_cpu < 64 &&
	    !((cake_seat_word >> prev_cpu) & 1) &&
	    cake.run[(u32)prev_cpu & (MAX_CPUS - 1)].seat_pid ==
	    (u64)(u32)p->pid &&
	    !cake_core_irq_bad(prev_cpu) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		struct task_struct *hc = cake_cpu_curr(prev_cpu);

		/* Retake needs eligibility, not a weighted runtime calculation.
		 * Read one occupant instead of pricing one and testing another. */
		if (hc && (hc->scx.flags & CAKE_TASK_QUEUED) &&
		    hc->scx.dsq_vtime && hc != p && hc->nr_cpus_allowed > 1 &&
		    !cake_stage(hc)) {
			cake.run[(u32)prev_cpu & (MAX_CPUS - 1)].retake = 1;
			cake_direct_clamp(p);
			cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)prev_cpu,
					cake_task_slice(p), 0);
			cake_kick_preempt(prev_cpu);
			cake_stat_inc(CAKE_SITE_SEAT_RETAKE);
			return prev_cpu;
		}
	}

	/* One whole-core snapshot covers logical availability and pending
	 * sibling claims. The successful atomic claim below still decides
	 * admission; a second availability read would not reserve a core. */
	if (cake_one_word && prev_cpu >= 0 && cake_core_contended(prev_cpu))
		goto skip_home;
	/* §G85: another task's held seat is not this task's home. */
	seat_blocked = prev_cpu >= 0 &&
		       cake_seat_blocks(prev_cpu, p, CAKE_SITE_LEAK_HOME);
	/* §G80: the groove counts a MISS only when the home was asked and was
	 * busy (sibling running, or the idle claim lost). The SYNC, starvation
	 * and IRQ gates are not the home's fault; counting them sent stage
	 * threads cold on 11.4% of all wakes (probe 2026-09-02). */
	/* §G81: a stage-class wakee (burst >= SEAT_BURST_MIN_NS) keeps its warm
	 * home even on a SYNC wake: its own predictor and L1 outweigh the
	 * waker's line at that burst length (hd_sync 31k/30 s, GameThread
	 * 8,835 migrations vs 1.1.3's 650). */
	/* One decision and one claim attempt in both diagnostic and normal
	 * execution. The probe records that decision instead of making its
	 * own idle claim (which used to change placement and retry count). */
	if (cake_tog_probe && stage && prev_cpu >= 0 && !seat_blocked)
		cake_stat_inc(CAKE_SITE_STAGE_PROBE);
	if ((!(wake_flags & CAKE_WAKE_SYNC) || stage) &&
	    prev_cpu >= 0 && !seat_blocked) {
		if (cake_starved_turn(p))
			home_decline = CAKE_STAT_HD_STARVED;
		else if (cake_core_irq_bad(prev_cpu))
			home_decline = CAKE_STAT_HD_IRQ;
		else if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
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
		cake_direct_clamp(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)prev_cpu,
				cake_task_slice(p), CAKE_ENQ_IMMED);
		cake_stat_inc(CAKE_STAT_HOME);
		return prev_cpu;
	}
	if (cake_tog_probe && stage && prev_cpu >= 0 && !seat_blocked)
		cake_stat_inc(home_decline);
skip_home:


	/* §G69: claimed warm placement or the pool; nothing unclaimed below. */
	gr = cake_one_word ? cake_groove_of(p) : NULL;
	c = cake_claim_warm(p, gr ? (s32)gr->last_win - 1 : -1);
	if (gr && c >= 0)
		gr->last_win = (s16)(c + 1);

	if (c >= 0) {
		if (cake_tog_probe)
			cake_probe_x(CAKE_SITE_CLAIM_X, prev_cpu, c);
		cake_direct_clamp(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)c,
				cake_task_slice(p), CAKE_ENQ_IMMED);
		return c;
	}
	return prev_cpu;	/* enqueue routes it (the pool, §G65) */
}

/* Idle pick with one retry away from a bad target (§G30, §G35): prefer a
 * CPU that is neither chronically loud nor mid-handler; when only a bad one
 * is idle it still wins -- any CPU beats queueing. */
static __noinline s32 cake_pick_idle_clean(struct task_struct *p __arg_trusted)
{
	s32 cpu;

	if (cake_one_word) {
		u32 prev = (u32)p->thread_info.cpu & (MAX_CPUS - 1);
		u64 w = cake_idle_word() & p->cpus_ptr->bits[0] & cpu_llc_word[prev];
		u64 cores = w ? cake_core_word() & w : 0;
		u64 seats = cake_tog_g85 ? cake_smt_expand(cake_seat_word) : 0;
		u64 noisy = w ? cake_smt_expand(cpu_irq_hot_words[0]) : 0;
		u64 rejected = 0;
		u32 i;

		for (i = 0; i < CLAIM_TRIES && w; i++) {
			cpu = cake_pick_cold(w, cores, seats, noisy);
			w &= ~(1ULL << cpu);
			if (!cake_cpu_clean(cpu))
				rejected |= 1ULL << cpu;
			else if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY))
				return cpu;
			if (!cake_tog_g86)
				break;
		}
		/* Cleanliness is a preference. Never strand work on a die whose
		 * remaining capacity is noisy, reserved, or a partial SMT core. */
		w |= rejected;
		for (i = 0; i < CLAIM_TRIES && w; i++) {
			cpu = cake_pick_cold(w, cores, seats, noisy);
			if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY))
				return cpu;
			w &= ~(1ULL << cpu);
		}
		if (cake_tog_g89 && nr_llcs > 1)
			return -1;
	}

	/* Kernel fallback covers wide hosts and concurrent availability changes. */
	cpu = cake_pick_idle(p->cpus_ptr, CAKE_PICK_IDLE_CORE);
	if (cpu < 0)
		cpu = cake_pick_idle(p->cpus_ptr, 0);
	return cpu;
}

/* Local service had no idle winner. Offer one compatible remote CPU the
 * already-published pool, using the kernel idle claim to bound fan-out. */
static __noinline bool cake_offer_remote(struct task_struct *p __arg_trusted, s32 tcpu)
{
	u64 w, cores, seats, noisy;
	u32 i;

	if (!cake_tog_g89 || nr_llcs <= 1 || !cake_one_word)
		return false;
	w = cake_idle_word() & p->cpus_ptr->bits[0] &
		~cpu_llc_word[(u32)tcpu & (MAX_CPUS - 1)];
	cores = w ? cake_core_word() & w : 0;
	seats = cake_tog_g85 ? cake_smt_expand(cake_seat_word) : 0;
	noisy = w ? cake_smt_expand(cpu_irq_hot_words[0]) : 0;
	for (i = 0; i < CLAIM_TRIES && w; i++) {
		s32 cpu = cake_pick_cold(w, cores, seats, noisy);

		if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY)) {
			u32 target = (u32)cpu;

			/* LLVM knows ctz is < 64 and otherwise removes the mask.
			 * Its BPF byte-table lowering only proves < 256 to the
			 * verifier. Keep the bound on the actual array index. */
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

/*
 * Post-insert notification: tell somebody the task is runnable. The task is
 * already published, so only p, tcpu and the route cross this boundary — which
 * is what makes the cut cheap (§R.11).
 */
__noinline s32 cake_wake_notify(struct task_struct *p __arg_trusted, s32 tcpu,
				u64 slice)
{
	s32 idle;

	idle = cake_pick_idle_clean(p);
	if (idle >= 0) {
		cake_stat_inc(CAKE_SITE_NOTIFY_KICK);
		if (cake_tog_probe)
			cake_probe_x(CAKE_SITE_NOTIFY_KICK_X, tcpu, idle);
		cake_kick(idle, CAKE_KICK_IDLE);
		return 0;
	}

	/* An idle SMT sibling keeps globally queued cold pickup on a warm core.
	 * Ranked BELOW a clean idle pick: the sibling shares the core with a
	 * runner, and that costs more than the L2 it saves (§G38). */
	{
		s32 sib = cpu_sibling[(u32)tcpu & (MAX_CPUS - 1)];

		if (sib >= 0 && cake_cpu_clean(sib) &&
		    bpf_cpumask_test_cpu(sib, p->cpus_ptr) &&
		    cake_taci(sib, CAKE_SITE_TACI_NOTIFY)) {
			cake_kick(sib, CAKE_KICK_IDLE);
			return 0;
		}
	}

	/*
	 * No idle CPU anywhere, and every route still owes tcpu a decision:
	 * either the occupant loses the CPU, or the wakee waits because the
	 * occupant genuinely deserves it. Cake registers no .tick, so an arm
	 * that decides neither leaves the wakee on the 5 s watchdog (§R.14).
	 */
	if (cake_wake_preempt(p, tcpu, PREEMPT_PROTECT_SHIFT, slice))
		return 0;

	/*
	 * Globally queued only: hunt a mid-slice compute occupant among the
	 * neighbours. A home-routed wake stays put -- stealing it back off the
	 * queue would spend the locality the routing just bought.
	 */
	{
		u32 cand = (u32)tcpu;
		u32 pi;

		for (pi = 0; pi < CAKE_NEIGHBOUR_PROBE_DEPTH; pi++) {
			/* §G89: the loader's locality order (same die first)
			 * instead of cpu+1, which wraps into the other die. */
			if (cake_tog_g89 && steal_order_live &&
			    (u32)tcpu < STEAL_SPAN) {
				if (pi >= nr_steal_cpus)
					break;
				/* the compare must land on the register the load
				 * uses: the compiler hoists the scale ahead of any
				 * compare on tcpu, and the verifier does not carry a
				 * later bound back to the scaled register */
				u32 ix = (u32)tcpu * STEAL_SPAN + pi;

				barrier_var(ix);
				if (ix >= STEAL_SPAN * STEAL_SPAN)
					break;
				cand = cpu_steal_order[ix];
			} else {
				cand++;
				if (cand >= nr_cpu_span)
					cand = 0;
			}
			if (!bpf_cpumask_test_cpu((s32)cand, p->cpus_ptr))
				continue;
			if (cake_wake_preempt(p, (s32)cand,
					       PROBE_PROTECT_SHIFT, slice)) {
				cake_stat_inc(CAKE_SITE_PROBE_FIRED);
				if (cake_tog_probe)
					cake_probe_x(CAKE_SITE_PROBE_FIRED_X, tcpu, (s32)cand);
				return 0;
			}
		}
	}
	cake_offer_remote(p, tcpu);
	return 0;
}

/*
 * The wake half of ops.enqueue: route the wakee, insert it, then notify.
 *
 * A wake and a continuation are two algorithms, not one algorithm with a
 * shared flag set, so each gets its own subprogram and its own register
 * budget. Global rather than static so it keeps its own BTF signature and
 * frame; @p is __arg_trusted because the verifier checks it independently
 * (§R.11).
 */
__noinline s32 cake_enqueue_wake(struct task_struct *p __arg_trusted, s32 tcpu)
{
	struct task_struct *curr = cake_cpu_curr(tcpu);

	/*
	 * Self-race first: waking the task this CPU is still switching out
	 * (sub-slice block/wake cadence rides the ttwu wakelist and lands here
	 * with curr == p -- the pipe/futex on-cpu shape). Home is right even
	 * behind a non-empty queue, since p ran here microseconds ago and vtime
	 * order keeps the queue fair; eligibility and a kick would both be
	 * spent against ourselves. Hottest wake path, so it precedes the
	 * nr_queued rhashtable lookup (§R.14).
	 */
	if (curr == p) {
		cake_qmark_set((u32)tcpu);
		cake_dsq_insert_vtime(p, (u64)(u32)tcpu,
				      cake_task_slice(p),
				      cake_wake_vtime(p), CAKE_ENQ_WAKEUP);
		return 0;
	}

	/*
	 * §G65: every other wake takes the pool, visible to every idle CPU and
	 * kicked. The wake bit as a literal, not the caller's enq_flags: a PRIQ
	 * insert into a custom DSQ reads none of the caller's positional bits
	 * (§R.5).
	 */
	{
		u64 vt = cake_wake_vtime(p);
		u64 slice = cake_task_slice(p);

		cake_pool_insert(p, tcpu, slice, vt, CAKE_ENQ_WAKEUP);
		cake_wake_notify(p, tcpu, slice);
	}
	return 0;
}

/*
 * Pinned-wake service. A pinned user task's wake lands on the continuation
 * path because nr_cpus_allowed == 1, and NO other CPU may steal it, so without
 * this it waits out the occupant's whole slice. Preempts by RAW sleep depth
 * @d, which must be read before the insert rewrites p->scx.dsq_vtime (§R.14).
 */
static __noinline void cake_pinned_wake_preempt(struct task_struct *p __arg_trusted,
						s32 tcpu, u64 d, u64 slice)
{
	u64 cran = 0;
	u64 clive = cake_occupant_live(tcpu, &cran);
	u64 lo, dd, pvt, vs;

	if (!clive)
		return;

	vs = SLICE_NS;
	lo = cake.frontier.word - vs;
	dd = d + vs;
	pvt = lo - vs + (dd & ~((u64)((s64)dd >> 63)));

	/* §G87: the margin is the wakee's own slice, not half of SLICE_NS: a
	 * pinned microsecond sleeper could not out-deserve any occupant by
	 * 1.5 ms and waited for the slice end (cyclictest on one CPU). */
	if (time_before(pvt + (cake_tog_g87 ? slice : (vs >> 1)), clive))
		cake_kick_preempt(tcpu);
}


/*
 * ops.enqueue — reached when no idle CPU was claimed, or guarded direct
 * admission found an older visible per-CPU claim.
 *
 * Insert into the OWNER's vtime queue, dsq_id == task_cpu: task_cpu is
 * post-core-validation and always in p->cpus_ptr, and this callback holds that
 * CPU's rq lock, so either the owner scans its own DSQ after the insert or
 * core's activate→wakeup_preempt rescheds it out of idle for us — no insert
 * kick is owed to the owner. On a same-CPU futex handoff the insert and the
 * consume both happen under one rq lock: EEVDF's in-place shape.
 *
 * Then keep the rest of the machine work-conserving by kicking one idle CPU,
 * whose idle bit pick_idle CLAIMS, so concurrent wakers fan out.
 */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* task_cpu(p) read directly; the kfunc is one load behind a call (§R.17). */
	s32 tcpu = (s32)p->thread_info.cpu;
	u64 lo, d, slice;
	s32 idle;
	bool pooled = false;

	/*
	 * Kernel-thread wakes go straight to the selected CPU's local DSQ, so
	 * essential softirq/workqueue service is bounded by one occupant slice
	 * rather than herd order — the scx watchdog itself rides unbound
	 * kworkers. PF_KTHREAD is scheduling state, not workload identity. Only
	 * the wake takes this path; a continuation falls through (§R.14). An idle
	 * CPU serves it as promptly and evicts nobody (§G20).
	 */

	if ((enq_flags & CAKE_ENQ_WAKEUP) && (p->flags & PF_KTHREAD)) {
		/* A one-CPU task can only land on its own CPU: the pick's
		 * word walk and two kernel scans found nothing else by
		 * definition (audit 2026-09-06). */
		s32 kcpu = p->nr_cpus_allowed > 1 ? cake_pick_idle_clean(p) : -1;

		/* §G86: nothing idle was claimed. The pool with the notify's
		 * preempt bounds the wait by a vtime test, not by the occupant's
		 * slice: the display kthreads the nvidia ISR wakes queued behind
		 * a worker for 110 us median and 1.5 ms max while another CPU
		 * sat idle 95% of the time (HD2 chain trace 2026-09-04). Pinned
		 * kthreads keep the local queue: no other CPU may serve them. */
		if (kcpu < 0 && cake_tog_g86 && p->nr_cpus_allowed > 1) {
			cake_stat_inc(CAKE_SITE_KT_POOL);
			cake_enqueue_wake(p, tcpu);
			return;
		}

		cake_stat_inc(CAKE_SITE_KT_LOCAL);
		if (cake_tog_probe && kcpu >= 0)
			cake_probe_x(CAKE_SITE_KT_LOCAL_X, tcpu, kcpu);
		cake_direct_clamp(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON |
				   (u32)(kcpu >= 0 ? kcpu : tcpu),
				   SLICE_NS, enq_flags |
				   (kcpu >= 0 ? CAKE_ENQ_IMMED : 0));
		return;
	}

	/*
	 * Sleeper clamp max(own, frontier - one slice), branchless and wrap-safe
	 * under time_before() semantics:
	 *   d = own - lo; own >= lo => (s64)d >= 0 => mask = ~0 => lo + d = own
	 *                 own <  lo => (s64)d <  0 => mask =  0 => lo + 0 = lo
	 * Only the continuation arm consumes it; the wake arm derives its own
	 * cadence-deep floor (§R.13).
	 */
	lo = cake.frontier.word - SLICE_NS;
	d  = p->scx.dsq_vtime - lo;

	/*
	 * STAGE wakeups are global, everything else is local -- the routing key
	 * is the wakeup bit AND the burst class (§G10.2). Single-CPU tasks take
	 * the continuation arm regardless (§R.14).
	 */
	if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1 &&
	    cake_starved_turn(p)) {
		cake_enqueue_wake(p, tcpu);
		return;
	}

	/*
	 * The continuation arm. Ordinary continuations stay on their owner's
	 * queue: the mark exposes them to the steal ring while preserving their
	 * L1/L2 warmth. Forced requeues and seat collisions use the pool below.
	 * A separate overflow bucket needed two catchers and stalled anyway
	 * (§R.15). The slice is the task's own, not a flat grant (§G10).
	 */
	{
		u64 vt = lo + (d & ~((u64)((s64)d >> 63)));
		struct task_struct *hc = NULL;

		/*
		 * Anti-collision: home held by an equally well-served PEER. The
		 * depth-blind home rule above is right for a worker occupant,
		 * whose slice is short, and wrong for a peer, whose whole slice
		 * must be waited out while other CPUs sit idle. Reaching this
		 * arm already proves p is not turn-starved, so only the
		 * occupant needs testing (§G17).
		 */
		/* The occupant is asked only on the wake arm that reads it: a
		 * slice-expiry continuation paid the kfunc for nothing (audit
		 * 2026-09-06). */
		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1)
			hc = cake_cpu_curr(tcpu);
		if (hc && !(hc->flags & PF_IDLE) && !cake_starved(hc)) {
			/* An idle claim can serve this wake directly, without
			 * publishing it behind a different pool head. Forced
			 * requeues retain their pool escape after IMMED rejection. */
			if (!(enq_flags & CAKE_ENQ_REENQ)) {
				idle = cake_pick_idle_clean(p);
				if (idle >= 0) {
					cake_direct_clamp(p);
					cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)idle,
							cake_task_slice(p), enq_flags | CAKE_ENQ_IMMED);
					cake_stat_inc(CAKE_STAT_POOL_DIRECT);
					return;
				}
			}
			cake_pool_insert(p, tcpu, cake_task_slice(p),
					 cake_wake_vtime(p), enq_flags);
			pooled = true;
			if (!(enq_flags & CAKE_ENQ_REENQ))
				goto no_idle;
			goto kick_idle;
		}

		/* A forced requeue can no longer rely on service at its owner:
		 * cpu_release evacuates work displaced by a higher class. Use
		 * the pool so kick_idle can offer an idle remote die when this
		 * die is full. Keep continuation vtime, without sleeper credit.
		 * §G85 seat collisions use this same route; pinned tasks cannot. */
		if (p->nr_cpus_allowed > 1 &&
		    ((enq_flags & CAKE_ENQ_REENQ) ||
		     (cake_tog_g85 && (u32)tcpu < 64 &&
		      cake.run[(u32)tcpu & (MAX_CPUS - 1)].retake &&
		      cake.run[(u32)tcpu & (MAX_CPUS - 1)].seat_pid !=
		      (u64)(u32)p->pid))) {
			if (cake_tog_probe && !(enq_flags & CAKE_ENQ_REENQ))
				cake_stat_inc(CAKE_SITE_SEAT_REROUTE);
			cake_pool_insert(p, tcpu, cake_task_slice(p), vt, enq_flags);
			pooled = true;
			goto kick_idle;
		}

		slice = cake_task_slice(p);
		cake_qmark_set((u32)tcpu);
		cake_dsq_insert_vtime(p, (u64)(u32)tcpu, slice, vt, enq_flags);

		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed == 1)
			cake_pinned_wake_preempt(p, tcpu, d, slice);
	}

kick_idle:

	/* A one-CPU task's owner is rescheduled by core's activate path (see
	 * above); the pick could only ever name that owner. */
	idle = p->nr_cpus_allowed > 1 ? cake_pick_idle_clean(p) : -1;
	if (idle >= 0) {
		cake_kick(idle, CAKE_KICK_IDLE);
		return;
	}
no_idle:
	if (pooled)
		cake_offer_remote(p, tcpu);
}

/*
 * Staggered ring steal: visit the other CPUs' queues in ring order from cpu+1
 * and move the first task found. The marks are a BITMASK, so a span of 64 or
 * fewer CPUs answers every probe from ONE cache line instead of one 128 B slot
 * per CPU (§G25). The own-offset start is the anti-herd stagger (§R.7).
 *
 * The word is snapshotted, reloaded only when the walk crosses into another
 * one, so a span of 64 or fewer costs a SINGLE load for the whole ring. Missing
 * a bit raised mid-walk costs a steal and never liveness — the owner is
 * rescheduled by core's activate->wakeup_preempt regardless (see ops.enqueue).
 * One subtraction wraps the index — no modulo.
 */

/* PROBE: count a steal from @idx's queue by die relation; never gates. The
 * count is per attempt that reached the move; the move itself may find the
 * queue empty, so read it beside STEAL_MOVED's own-die share, not as a rate. */
static __always_inline bool cake_probe_steal(u32 ucpu, u32 idx)
{
	if (cake_tog_probe) {
		cake_stat_inc(CAKE_SITE_STEAL_MOVED);
		if (cake_cross_llc((s32)ucpu, (s32)idx))
			cake_stat_inc(CAKE_SITE_STEAL_MOVED_X);
	}
	return true;
}

static __noinline bool cake_ring_steal(u32 ucpu)
{
	u32 nr = nr_cpu_span;
	u32 cw = (u32)-1;	/* which qmask word `m` holds; none yet */
	u64 m = 0;
	u32 i;

	/* §G77: nothing marked anywhere is one word read, not a ring walk. */
	if (cake_one_word &&
	    !(cake.qmask[0] & ~(1ULL << (ucpu & 63))))
		return false;

	if (CCD_STEAL_POLICY > 0 && steal_order_live && ucpu < STEAL_SPAN) {
		/* One precomputed locality order avoids verifier-multiplying
		 * scan loops. */
		for (i = 0; i < STEAL_SPAN; i++) {
			u32 idx;

			if (i >= nr_steal_cpus)
				break;
			idx = cpu_steal_order[ucpu * STEAL_SPAN + i];
			if (!cake_qmark_test(idx))
				continue;
			/* §G89: across a die boundary only a head a whole slice
			 * behind the frontier is worth the fabric; a fresh wake,
			 * stage or worker, waits for its own die. */
			if (cake_tog_g89 && cake_cross_llc((s32)ucpu, (s32)idx)) {
				struct task_struct *h = cake_dsq_peek((u64)idx);

				if (!h || !time_before(h->scx.dsq_vtime + SLICE_NS,
						       cake.frontier.word))
					continue;
			}
			if (cake_probe_steal(ucpu, idx) && cake_move_to_local((u64)idx))
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
		if (cake_probe_steal(ucpu, idx) && cake_move_to_local((u64)idx))
			return true;
	}

	return false;
}

/* Has the global wake queue gone unserved for a full WALL-clock window? */
static __noinline bool cake_wake_starved(u32 llc)
{
	return time_before(cake.wake_served[llc & (MAX_LLCS - 1)].word +
			   WAKE_STARVE_WALL_NS, cake_now(CAKE_SITE_KT_WAKECLOCK));
}

/* Record that someone served the global wake queue. */
static __noinline void cake_wake_serve_stamp(u32 llc)
{
	cake_stat_inc(CAKE_SITE_WAKE_SERVED_ST);
	cake.wake_served[llc & (MAX_LLCS - 1)].word = cake_now(CAKE_SITE_KT_WAKECLOCK);
}

/*
 * An EMPTY wake queue is a SERVED wake queue — without this the escalation is
 * permanently armed in any regime where wakes mostly route home. Refreshed
 * only once the stamp is already half a window old, because every CPU's
 * dispatch polls this line and an unconditional store would cost an RFO at
 * context-switch rate (§R.16).
 */
static __noinline void cake_wake_idle_stamp(u32 llc)
{
	u64 now = cake_now(CAKE_SITE_KT_WAKECLOCK);
	struct cake_slot *ws = &cake.wake_served[llc & (MAX_LLCS - 1)];

	if (time_before(ws->word + WAKE_STARVE_REFRESH_NS, now)) {
		cake_stat_inc(CAKE_SITE_WAKE_SERVED_ST);
		ws->word = now;
	}
}

/* The both-empty dispatch also saw the pool served, but §G76 keeps the
 * clock off that path: the stamp is refreshed only when this CPU's own last
 * running stamp, already in a line it owns, says the served stamp is half a
 * starvation window stale. One clock read per half window per die, and the
 * stamp no longer goes stale on a lightly loaded die, where it made every
 * contested dispatch and every foreign rescue read "starved" and the seat
 * decline serve instead (audit 2026-09-06). */
static __always_inline void cake_wake_idle_refresh(u32 llc, u32 ucpu)
{
	u64 served = cake.wake_served[llc & (MAX_LLCS - 1)].word;
	u64 seen = cake.run[ucpu & (MAX_CPUS - 1)].stamp;

	if (time_before(served + WAKE_STARVE_REFRESH_NS, seen))
		cake_wake_idle_stamp(llc);
}

/* §G89: the other dies' pools, taken only when a head is a whole slice
 * behind the frontier or its pool went unserved for the wall. A die with
 * idle CPUs helps a saturated die; a fresh wake waits for its own. */
static __noinline bool cake_llc_pool_rescue(u32 own)
{
	u32 i;

	if (!cake_tog_g89 || nr_llcs <= 1)
		return false;
	for (i = 0; i < MAX_LLCS; i++) {
		struct task_struct *h;

		if (i >= nr_llcs)
			break;
		if (i == own || !cake.wake_mark[i].word)
			continue;
		h = cake_dsq_peek(cake_pool_dsq(i));
		if (!h) {
			cake_wake_mark_retire(i);
			continue;
		}
		if (time_before(h->scx.dsq_vtime + SLICE_NS, cake.frontier.word) ||
		    cake_wake_starved(i)) {
			if (cake_move_to_local(cake_pool_dsq(i))) {
				cake_wake_serve_stamp(i);
				return true;
			}
		}
	}
	return false;
}

/* An offered pool is eligible immediately: the producer already found its
 * own die full. Consume revalidates affinity and migration constraints.
 * Clear even on failure so an empty/replaced head cannot leave a stale offer. */
static __noinline bool cake_take_remote(u32 cpu)
{
	u64 offer;
	u32 llc;

	if (!cake_tog_g89 || nr_llcs <= 1 || !cake_one_word || cpu >= 64)
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
	if (!cake_move_to_local(cake_pool_dsq(llc)))
		return false;
	cake_wake_serve_stamp(llc);
	return true;
}

/*
 * The dispatch search: earliest eligible vtime of {own queue, wake queue},
 * then the staggered ring steal. Returns true when it moved work local.
 *
 * Two lockless head peeks pick the earlier vtime and the other is the
 * immediate fallback. The vtime comparison is what makes this starvation-free
 * with no rescue path — a stranded wake head's vtime is frozen while running
 * tasks advance past it (§R.3, §R.7).
 */
static __noinline bool cake_dispatch_search(s32 cpu)
{
	u32 ucpu = (u32)cpu;
	u32 llc = cake_llc_of(cpu);
	u64 pool = cake_pool_dsq(llc);
	u64 first = (u64)ucpu, second = pool;
	struct task_struct *own, *wake;

	if (cake_take_remote(ucpu))
		return true;

	/*
	 * Own queue first, global wake queue second, with a one-slice margin.
	 * The margin is HYSTERESIS, not fairness slack: without it every CPU
	 * takes the global lock first and the wake-storm serialisation returns.
	 * The head peek republishes the mark with one conditional store (§R.3).
	 */
	/* §G76: an empty own queue costs one count, not an iterator; both
	 * queues empty skips both move attempts. Measured 111-120 ns/run at
	 * 78k runs/s on the game's own cores (bpfstats 2026-09-02) against
	 * 1.1.3's 20 ns -- dispatch is where an idle-bound CPU spends its BPF. */
	{
		u32 own_n = (u32)cake_nrq((u64)ucpu);
		u32 wake_n;

		own = own_n ? cake_dsq_peek((u64)ucpu) : NULL;
		/* Marks and the empty test come from scalars: a pointer-to-bool
		 * or a pointer pair test lowers to an OR the verifier refuses. */
		cake_qmark_publish(ucpu, own_n != 0);
		/* The pool by its COUNT, not the mark: the mark has the holes the
		 * unconditional second move used to heal (§G41), and trusting it
		 * here stalled the game 20 ms. Two counts replace two iterators and
		 * two blind moves on the empty path. */
		wake_n = (u32)cake_nrq(pool);
		/* Test before set: the unconditional store took the shared line
		 * on every dispatch with a non-empty pool (audit 2026-09-06). */
		if (wake_n)
			cake_wake_mark_set(llc);
		/* §G85 leak 3: a held seat with an empty own queue would take
		 * pool work or steal, and its stage thread would return to a
		 * busy CPU (the hold). While another idle CPU is nobody's seat,
		 * the seat stays idle; that CPU was kicked for the pool wake. */
		wake = wake_n ? cake_dsq_peek(pool) : NULL;
		if (!own_n && cake_one_word && ucpu < 64 &&
		    ((cake_seat_word >> ucpu) & 1)) {
			/* §G88: a free CPU on this die only; pool work never
			 * gets kicked across the L3 boundary from here. */
			u64 free = cake_idle_word() & ~cake_seat_word &
				   cpu_llc_word[ucpu & (MAX_CPUS - 1)];

			/* The kick lands where the pool head can RUN: the
			 * kernel's consume skips a task the CPU may not serve,
			 * and a seat that declined a head no free CPU could run
			 * stranded it for the watchdog (review 2026-09-06). With
			 * no such CPU the seat falls through and serves the head
			 * when it may. Work in another CPU's own queue needs no
			 * test: its owner serves it regardless. */
			if (wake)
				free &= wake->cpus_ptr->bits[0];
			if (free && (wake || (cake.qmask[0] & ~(1ULL << ucpu)))) {
				cake_stat_inc(CAKE_SITE_LEAK_DISPATCH);
				/* §G85: the seat stays idle for its holder; an
				 * idle CPU that is nobody's seat is kicked for the
				 * work. Declining WITHOUT the kick stranded pool
				 * wakes on appsim (p99 0.65 -> 0.80 ms, 2026-09-03).
				 * A head nobody served for the wall-clock window is
				 * served here, not declined again (§G11.2). */
				if (cake_tog_g85 &&
				    !(wake && cake_wake_starved(llc))) {
					cake_stat_inc(CAKE_SITE_SEAT_DECLINE);
					cake_kick(cake_pick_cold(free, cake_core_word(),
						 cake_smt_expand(cake_seat_word),
						 cake_smt_expand(cpu_irq_hot_words[0])),
						  CAKE_KICK_IDLE);
					return false;
				}
			}
		}
		if (!wake_n) {
			if (cake_tog_g89 && nr_llcs > 1)
				cake_wake_mark_retire(llc);
			if (!own_n) {
				cake_wake_idle_refresh(llc, ucpu);
				return cake_ring_steal(ucpu) ||
				       cake_llc_pool_rescue(llc);
			}
			/* an empty pool is served: the starvation clock only
			 * matters when the own queue competes with it */
			cake_wake_idle_stamp(llc);
		}
	}
	if (wake) {
		u64 wv = wake->scx.dsq_vtime;
		/*
		 * Either the vtime margin favours the wake head, or nobody
		 * served that queue in a wall-clock window (§R.16, §G11.2).
		 */
		if (!own ||
		    time_before(wv + SLICE_NS,
				own->scx.dsq_vtime) ||
		    cake_wake_starved(llc)) {
			first  = pool;
			second = (u64)ucpu;
		}
	}
	if (cake_tog_probe && wake) {
		/* PROBE: the pool head's previous die vs this CPU's, before the
		 * move that may take it (the take is confirmed by wake_served). */
		if (cake_cross_llc((s32)wake->thread_info.cpu, cpu))
			cake_probe_pool_x[ucpu & (MAX_CPUS - 1)] = 1;
		else
			cake_probe_pool_x[ucpu & (MAX_CPUS - 1)] = 0;
	}
	if (cake_move_to_local(first)) {
		if (first == pool) {
			cake_wake_serve_stamp(llc);
			if (cake_tog_probe) {
				cake_stat_inc(CAKE_SITE_POOL_SERVED);
				if (cake_probe_pool_x[ucpu & (MAX_CPUS - 1)])
					cake_stat_inc(CAKE_SITE_POOL_SERVED_X);
			}
		}
		return true;
	}
	/* Unconditional: a second healing net under a lost mark, and a
	 * peek-guard here measured 5 spills against this shape's 0 (§G41). */
	if (cake_move_to_local(second)) {
		if (second == pool) {
			cake_wake_serve_stamp(llc);
			if (cake_tog_probe) {
				cake_stat_inc(CAKE_SITE_POOL_SERVED);
				if (cake_probe_pool_x[ucpu & (MAX_CPUS - 1)])
					cake_stat_inc(CAKE_SITE_POOL_SERVED_X);
			}
		}
		return true;
	}

	/* Both moves failed: this CPU may not
	 * run it (affinity, migration disabled) and the kernel's consume
	 * skipped it silently. Forward the wake to an idle CPU on this die
	 * that may: a non-seat first, which consumes on its own dispatch; a
	 * compatible seat only when nothing else is idle, and that seat
	 * finds no free compatible CPU above and attempts service. Re-peek:
	 * either move may have raced with consumption of the old head. One
	 * kick per failed search; the head and idle mask remain advisory.
	 * Wider hosts have no seats and enqueue kicks honour affinity. */
	if (cake_one_word) {
		wake = cake_dsq_peek(pool);
		if (wake) {
			u64 can = cake_idle_word() & wake->cpus_ptr->bits[0] &
				  cpu_llc_word[ucpu & (MAX_CPUS - 1)] &
				  ~(1ULL << (ucpu & 63));

			if (can & ~cake_seat_word)
				can &= ~cake_seat_word;
			if (can) {
				cake_stat_inc(CAKE_SITE_POOL_FORWARD);
				cake_kick(cake_pick_cold(can, cake_core_word(),
					 cake_smt_expand(cake_seat_word),
					 cake_smt_expand(cpu_irq_hot_words[0])),
					  CAKE_KICK_IDLE);
			}
		}
	}

	return cake_ring_steal(ucpu) || cake_llc_pool_rescue(llc);
}

/*
 * ops.dispatch — run the search, and if it finds nothing anywhere keep prev
 * running with a fresh slice rather than idling.
 */
void BPF_STRUCT_OPS(cake_dispatch, s32 cpu, struct task_struct *prev)
{
	if (cake_dispatch_search(cpu))
		return;

	if (prev && (prev->scx.flags & CAKE_TASK_QUEUED)) {
		cake_set_slice(prev, cake_task_slice(prev));
		return;
	}

}

/* A higher scheduling class has taken this CPU. Core otherwise keeps an
 * interrupted SCX task with slice remaining on this CPU's local DSQ, beyond
 * the reach of Cake's steal queues. Re-enqueue those tasks through the normal
 * affinity-aware continuation path so idle CPUs can serve them. This adds no
 * prediction or BPF callback on ordinary SCX-to-SCX switches. */
void BPF_STRUCT_OPS(cake_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
}

/* A task returning with a large weighted lead must not drag active peers'
 * wake floor along with it. Ordinary advances avoid all remote reads. For
 * an outlier, cap against observed live service, stopping once the lead is
 * within the existing admission window. Weights and queue keys stay intact;
 * a host running only low-weight work can still advance its weighted clock. */
static __noinline u64 cake_frontier_candidate(u64 vtime, u32 cpu)
{
	u64 near = cake.frontier.word + SLICE_NS;
	int c;

	if (!time_before(near, vtime))
		return vtime;
	/* Numeric iteration keeps verifier work bounded on wide CPU spans.
	 * Ordinary advances return before creating the iterator. */
	bpf_for(c, 0, nr_cpu_span < MAX_CPUS ? nr_cpu_span : MAX_CPUS) {
		u64 ran = 0, live;

		if ((u32)c == cpu)
			continue;
		live = cake_occupant_live((s32)c, &ran);
		if (live && time_before(live, vtime)) {
			vtime = live;
			if (!time_before(near, vtime))
				break;
		}
	}
	return vtime;
}

/*
 * ops.running — stamp the per-CPU run start and advance the global vtime
 * frontier to this task's deadline.
 *
 * The frontier store is deliberately conditional, NOT a branchless max: this
 * is the hottest shared line in the scheduler, and a select would dirty it
 * every quantum on every CPU even when it does not move. The racy
 * read-check-write is fine — the frontier is advisory and monotonic enough
 * under time_before() semantics.
 */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
	u64 task_vtime = p->scx.dsq_vtime;
	/* The TASK's CPU: a remote property change fires these ops from the
	 * caller's CPU, whose smp id charged a foreign slot (§G42). */
	u32 cpu = p->thread_info.cpu;
	struct cake_run_slot *run = &cake.run[cpu & (MAX_CPUS - 1)];
	u64 now = cake_now(CAKE_SITE_KT_RUNNING);

	run->stamp = now;
	run->sum = p->se.sum_exec_runtime;
	run->retake = 0;
	cake_stat_inc(CAKE_SITE_RUNNING);
	CAKE_TIMED_VOID(CAKE_SITE_T_CAL, (void)0);
	if (cake_tog_g85 && cake_one_word) {
		struct cake_groove *gr = bpf_task_storage_get(&cake_grooves, p, 0, 0);

		cake_seat_retire(gr, (u32)p->pid, cpu + 1);
		if (cpu < 64 && (cake_seat_word & (1ULL << cpu)))
			cake_seat_update(cpu, (u32)p->pid, CAKE_SEAT_RUN, 0);
	}
	if (cake_tog_probe)
		cake_probe_run(p, now);


	if (time_before(cake.frontier.word, task_vtime)) {
		task_vtime = cake_frontier_candidate(task_vtime, cpu);
		if (time_before(cake.frontier.word, task_vtime)) {
			cake_stat_inc(CAKE_SITE_FRONTIER_ST);
			cake.frontier.word = task_vtime;
		}
	}
}

/*
 * ops.stopping — charge the wall time used to the task's vtime, weighted by
 * the reciprocal table (no division on the hot path).
 */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	/* The task's CPU, never the callback's (§G42; see ops.running). */
	u32 cpu = p->thread_info.cpu;
	u64 used = p->se.sum_exec_runtime -
		   cake.run[cpu & (MAX_CPUS - 1)].sum;
	u32 idx = cake_recip_index(p);
	struct cake_run_slot *rs = &cake.run[cpu & (MAX_CPUS - 1)];
	u64 hint = 0;
	bool stage;

	stage = cake_stage(p);

	/* Allocation failure means no reservation, never failed scheduling. */
	if (cake_tog_g85 && cake_one_word && !runnable && cpu < 64 && stage) {
		struct cake_groove *gr = cake_groove_of(p);

		if (gr) {
			cake_seat_retire(gr, (u32)p->pid, cpu + 1);
			gr->seat_seq = cake_seat_update(cpu, (u32)p->pid, CAKE_SEAT_HOLD, 0);
			gr->seat_cpu = (u16)(cpu + 1);
			gr->seat_pid = (u32)p->pid;
		}
	}

	/*
	 * Count consecutive wake-then-block-quickly quanta. `used` is already
	 * exact here and `runnable` distinguishes blocking from a requeue, so
	 * the test costs no clock read. The counter saturates rather than
	 * latching a single quantum, because a producer trips that by accident
	 * and a real handoff partner repeats it; a preempted task never
	 * finished its pattern, so it leaves the count alone (§R.18).
	 */
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
	if (rs->hint != hint)
		rs->hint = hint;


	/*
	 * Direct write, not scx_bpf_task_set_dsq_vtime(): the kfunc's
	 * sub-scheduler authority check measured +28-36% on this, the hottest
	 * per-switch callback in the scheduler (§R.17).
	 */
	p->scx.dsq_vtime += cake_scale_vtime(used, idx);
}

/*
 * ops.update_idle — the §G45 census. KEEP_BUILTIN_IDLE preserves the kernel
 * tracking every pick still uses; this only mirrors it into one word.
 */
void BPF_STRUCT_OPS(cake_update_idle, s32 cpu, bool idle)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);
	u64 bit = 1ULL << (c & 63);

	/* Wide-host count is actual idle occupancy, never claim availability. */
	if (cake_one_word)
		return;
	if (idle) {
		if (!(__sync_fetch_and_or(&cake_idle_words[c >> 6], bit) & bit))
			__sync_fetch_and_add(&cake_idle_nr, 1);
	} else {
		if (__sync_fetch_and_and(&cake_idle_words[c >> 6], ~bit) & bit)
			__sync_fetch_and_sub(&cake_idle_nr, 1);
	}
}

/*
 * ops.enable — a freshly enabled task starts at the current vtime frontier so
 * it is neither starved nor granted a windfall of credit.
 */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, cake.frontier.word);
}

/*
 * ops.exit_task: a holder that exits gives its seat back. Only running on
 * that CPU clears a seat, and on a quiet host nothing runs there, so the
 * seat outlived its holder and a recycled pid inherited the retake and the
 * immunity (audit 2026-09-06). The exit rate is not a hot path.
 */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct cake_groove *gr;

	if (!cake_tog_g85 || !cake_one_word)
		return;
	gr = bpf_task_storage_get(&cake_grooves, p, 0, 0);
	cake_seat_retire(gr, (u32)p->pid, 0);
}

/*
 * ops.init (sleepable, one-shot): confirm the loader's frozen CPU span covers
 * the kernel's own nr_cpu_ids, then create one custom vtime DSQ per possible
 * CPU, dsq_id == cpu. A span narrower than nr_cpu_ids would stop the steal
 * ring short, so refuse it rather than silently under-scan (§R.21).
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
	if (nr_cpu_span < nr) {
		scx_bpf_error("loader CPU span %u is narrower than nr_cpu_ids %u",
			      nr_cpu_span, nr);
		return -EINVAL;
	}

	bpf_for(i, 0, nr) {
		ret = scx_bpf_create_dsq((u64)(u32)i, -1);
		if (ret)
			return ret;
	}
	/* §G89: one wake pool per LLC; a one-LLC host, or g89=0, uses pool 0. */
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
		u32 c, n = 0;

		bpf_for(c, 0, nr_cpu_span) {
			if (bpf_cpumask_test_cpu((s32)c, im)) {
				cake_idle_words[(c & (MAX_CPUS - 1)) >> 6] |=
					1ULL << (c & 63);
				n++;
			}
		}
		scx_bpf_put_idle_cpumask(im);
		cake_idle_nr = n;
	}

	return 0;
}

/* Core event counters, copied out at exit so the loader can report them
 * (self-telemetry; the core already counts, cake only reads at detach). */
struct scx_event_stats cake_events;

void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	__COMPAT_scx_bpf_events(&cake_events, sizeof(cake_events));
	UEI_RECORD(uei, ei);
}

/*
 * ALLOW_QUEUED_WAKEUP lets remote activation ride the batched TTWU queue
 * instead of taking the remote rq lock per wake, so no policy here may depend
 * on process identity or assume enqueue's current is the waker (§R.20).
 */
SCX_OPS_DEFINE(cake_ops,
	       .select_cpu	= (void *)cake_select_cpu,
	       .enqueue		= (void *)cake_enqueue,
	       .dispatch	= (void *)cake_dispatch,
	       .cpu_release	= (void *)cake_cpu_release,
	       .running		= (void *)cake_running,
	       .stopping	= (void *)cake_stopping,
	       .update_idle	= (void *)cake_update_idle,
	       .enable		= (void *)cake_enable,
	       .exit_task	= (void *)cake_exit_task,
	       .init		= (void *)cake_init,
	       .exit		= (void *)cake_exit,
	       .flags		= SCX_OPS_ALLOW_QUEUED_WAKEUP |
				  SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms	= WATCHDOG_TIMEOUT_MS,
	       .name		= "cake");
