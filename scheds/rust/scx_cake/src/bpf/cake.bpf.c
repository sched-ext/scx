/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake — a clean-slate sched_ext scheduler.
 *
 * One release algorithm, eight callbacks, built on kernel primitives. No
 * task-history model, telemetry, attributes, division, or build-variant
 * switches: policy is source constants and derived state, so an A/B is two
 * commits. Wakeups queue on a global DSQ so the first CPU to block finds them;
 * continuations queue at home for cache warmth; an idle CPU pulls work with a
 * staggered ring steal. Fairness is a single dsq_vtime advanced by a
 * reciprocal-weight table.
 *
 * DESIGN.md has the model of operation. HYPOTHESES.md §R holds the design
 * rationale and the measurements behind each decision here; §S the constants.
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
#undef SCX_KICK_IDLE
#undef SCX_KICK_PREEMPT
#undef SCX_TASK_QUEUED
#undef SCX_WAKE_SYNC
#define CAKE_DSQ_LOCAL    bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL)
#define CAKE_DSQ_LOCAL_ON bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL_ON)
#define CAKE_ENQ_WAKEUP   bpf_core_enum_value(enum scx_enq_flags,    SCX_ENQ_WAKEUP)
/* SCX_ENQ_PREEMPT is bit 32 (scx enums ABI); the CO-RE enum builtin cannot
 * fold a 64-bit enumerator, so the ABI value is spelled here. */
#define CAKE_ENQ_PREEMPT  ((u64)1 << 32)
#define CAKE_KICK_IDLE    bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_IDLE)
#define CAKE_KICK_PREEMPT bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_PREEMPT)
#define CAKE_TASK_QUEUED  bpf_core_enum_value(enum scx_ent_flags,    SCX_TASK_QUEUED)
#define CAKE_WAKE_SYNC    bpf_core_enum_value(enum scx_wake_flags,   SCX_WAKE_SYNC)
#define CAKE_PICK_IDLE_CORE \
	bpf_core_enum_value(enum scx_pick_idle_cpu_flags, SCX_PICK_IDLE_CORE)

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

/* §G68 EXPERIMENT: a VIP task's insert always carries ENQ_PREEMPT, so a
 * non-VIP occupant of a local queue it lands in is thrown off at once.
 * Defined after the toggles and the state block; prototypes here. */
static __noinline bool cake_vip(const struct task_struct *p);
static __noinline u64 cake_vip_head_vtime(void);
static __noinline void cake_kick_preempt(s32 cpu);

static __noinline bool cake_dsq_insert_vtime(struct task_struct *p, u64 dsq_id,
					     u64 slice, u64 vtime, u64 enq_flags)
{
	cake_probe_place(p, dsq_id, enq_flags);
	if (cake_vip(p)) {
		enq_flags |= CAKE_ENQ_PREEMPT;
		vtime = cake_vip_head_vtime();	/* pool head */
	}
	return scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
}

static __always_inline bool cake_dsq_insert(struct task_struct *p, u64 dsq_id,
					    u64 slice, u64 enq_flags)
{
	cake_probe_place(p, dsq_id, enq_flags);
	if (cake_vip(p))
		enq_flags |= CAKE_ENQ_PREEMPT;
	return scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags);
}

static __always_inline bool cake_move_to_local(u64 dsq_id)
{
	return scx_bpf_dsq_move_to_local(dsq_id, 0);
}

/* Campaign toggle, declared here because the readers below precede the
 * toggle block (§M7; the block documents the campaign). */
const volatile u8 cake_tog_m7;				/* runqueues direct reads (§M7) */

extern struct rq runqueues __ksym __weak;

/*
 * The occupant of @cpu. Direct percpu-rq deref when the symbol resolves
 * (§M7): one load chain, no kfunc crossing; advisory-racy exactly as the
 * kfunc read is. Falls back to the kfunc where BTF lacks the symbol, so
 * no host loses the answer.
 */
static __noinline struct task_struct *cake_cpu_curr(s32 cpu)
{
	if (cake_tog_m7 && bpf_ksym_exists(&runqueues)) {
		struct rq *rq = bpf_per_cpu_ptr(&runqueues, cpu);

		return rq ? rq->curr : NULL;
	}
	return __COMPAT_scx_bpf_cpu_curr(cpu);
}

/* Local-DSQ depth without the kfunc (§M7): same field the kfunc returns,
 * read through the percpu rq; advisory-racy under the same trust model. */
static __always_inline u64 cake_local_nr(s32 cpu)
{
	if (cake_tog_m7 && bpf_ksym_exists(&runqueues)) {
		struct rq *rq = bpf_per_cpu_ptr(&runqueues, cpu);

		if (rq)
			return rq->scx.local_dsq.nr;
	}
	return scx_bpf_dsq_nr_queued(CAKE_DSQ_LOCAL_ON | (u32)cpu);
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
	/* The last two departures' slices, pid<<32 | slice (§G46). */
	u64 slice_cache[2];
	/*
	 * Occupant mirror (§M6): running publishes, stopping clears. occupant
	 * packs pid<<32 | recip-index; 0 = off-mirror (idle or a non-SCX
	 * class), and mirror_vtime is trusted only under a nonzero occupant.
	 * dsq_vtime is charged at stopping, so the mirrored value is exact
	 * for the whole slice.
	 */
	u64 occupant;
	u64 mirror_vtime;
	/*
	 * §G57: when this CPU's occupant is predicted to leave it, written by
	 * running on a line it already dirties. A saturated wake reads its
	 * mask's slots and queues behind the earliest.
	 */
	u64 free_at;
	/*
	 * §G58: pre-wake reservation, pid and expiry. The timer callback
	 * writes both for an idle CPU; the named task's wake consumes it, every
	 * other placement skips the CPU until the expiry.
	 */
	u64 reserved_pid;
	u64 reserved_until;
	u64 pad[STATE_SLOT_WORDS - 10];
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
const volatile u8 cake_tog_g46;				/* departing-slice cache (§G46) */
const volatile u8 cake_tog_g39b;			/* home-notify preempt (§G39-B') */
const volatile u8 cake_tog_m6;				/* occupant mirror (§M6) */
const volatile u8 cake_tog_g51;				/* idle-depth model (§G51) */
const volatile u8 cake_tog_g52;				/* preferred-core rank (§G52) */

/* §G54: next_pow2(nr_cpu_span) - 1, derived in the loader — the rotor
 * masks instead of dividing (no modulo on a per-transition path). */
const volatile u32 cake_span_mask;

/* §G51: cpuidle state index -> exit latency (us), loader-read from sysfs.
 * All-zero (no cpuidle driver) leaves the depth model inert. */
const volatile u32 cake_cstate_exit_us[CAKE_CSTATE_TABLE];

/* §G52: CPPC highest_perf per CPU, loader-read; zero = unknown. */
const volatile u8 cpu_perf_rank[MAX_CPUS];

/*
 * §G56 FOLD: the steal walk as per-LLC qmask bands. One AND plus a
 * find-first-set answers a whole band; the locality (and, under g52, the
 * preferred-core) order lives in the BAND order, not a per-CPU element
 * walk. Narrow hosts only (span <= 64, one qmask word); wide hosts keep
 * the §G25 walk. All loader-filled from runtime topology.
 */
const volatile u8 cake_tog_probe;		/* diagnostics: placement census, hold attribution, black box (--toggle probe=1) */
const volatile u8 cake_tog_g56;			/* banded steal fold (§G56) */
const volatile u8 cake_tog_g57;			/* earliest-free pick (§G57) */
const volatile u8 cake_tog_g58;			/* frame pre-wake (§G58) */
const volatile u8 cake_tog_g59;			/* idle-depth pick (§G59) */
const volatile u8 cake_tog_g60;			/* whole-core census placement (§G60) */
const volatile u8 cake_tog_g61;			/* census collision preempt (§G61) */
const volatile u8 cake_tog_g62;			/* census placements claim the CPU (§G62) */
const volatile u8 cake_tog_g63;			/* 1.1.3 pool mode: no direct dispatch, every wake global (§G63) */
const volatile u8 cake_tog_g64;			/* verified direct dispatch: dfl claim only in select_cpu (§G64) */
const volatile u8 cake_tog_g65			= 1;	/* every enqueued wake takes the pool, herd gate off (§G65) */
const volatile u8 cake_tog_g66;			/* serial handoff arm off: never place on a busy waker CPU (§G66) */
const volatile u8 cake_tog_g67;			/* unclaimed census direct paths off: home claim or pool (§G67) */
const volatile u8 cake_tog_g68;			/* EXPERIMENT: one process is VIP -- preempts, kicks, pool head (§G68) */
const volatile u32 cake_vip_tgid;		/* §G68: the VIP process, loader-found by comm */
const volatile u8 cake_tog_g69			= 1;	/* claimed warm placement: prev, whole idle core, idle thread, else pool (§G69) */
const volatile u8 cake_tog_g70;			/* EXPERIMENT: the VIP process is immune to preempt kicks (§G70) */
const volatile u8 cake_tog_g72;			/* L2 handoff: same-mm microsecond wakee onto the waker's idle sibling (§G72) */
const volatile u8 cake_tog_g71			= 1;	/* idle-side published claim words: one atomic per placement, no scan (§G71) */
const volatile u8 cake_tog_g73;			/* distributed pick: start the claim search at prev_cpu's core, wrap (§G73) */
const volatile u8 cake_tog_g74;			/* published-burst stacking: queue behind a busy prev only when it frees within tolerance (§G74) */
const volatile u8 cake_tog_g75			= 1;	/* grooves: per-task placement history orders the ladder and skips a failing home claim (§G75) */
const volatile u8 cake_tog_g77			= 1;	/* lean 2: steal ring skipped on an empty qmask (§G77) */
const volatile u8 cake_tog_g78;			/* spread once, then stick: a task's first whole-core claim rotates, its groove keeps it (§G78) */
const volatile u8 cake_tog_g79			= 1;	/* seat hold: a blocked stage keeps its core for its gap; other wakes skip it (§G79) */
const volatile u8 cake_tog_g81			= 1;	/* stage-class tasks keep the warm home on SYNC wakes (§G81) */

/* §G58: how far ahead of a predicted wake the reservation fires. Loader:
 * twice the deepest cpuidle exit latency, or the default without a table. */
const volatile u64 cake_prewake_lead_ns;
const volatile u8 cake_cpu_llc[MAX_CPUS];	/* cpu -> compact LLC index */
const volatile u64 cake_llc_qword[MAX_LLCS];	/* LLC membership, word 0 */
const volatile u8 cake_llc_order[MAX_LLCS][MAX_LLCS]; /* band steal order */
const volatile u32 cake_nr_llcs = 1;


/*
 * Observed frame period: measured, never inherited from a timeslice. Published
 * by the loader from the votes below; no policy consumes it yet (§G11).
 */
u64 cake_frame_ns __attribute__((aligned(STATE_SLOT_BYTES)));

/*
 * The same estimate filtered PESSIMISTICALLY (§G18). Diagnostic only: no
 * policy consumes it (§R.28).
 */
u64 cake_frame_floor_ns __attribute__((aligned(STATE_SLOT_BYTES)));

/*
 * DIAGNOSTIC ONLY: the loader still publishes min(3/4 x frame floor,
 * SLICE_NS) for the --verbose clock line, but no policy consumes it.
 * As the shared geometry unit it let one fast desktop crowd tighten every
 * task's patience windows — measured as a 2x handoff-tail mode flip.
 * Geometry is per task now (§R.28).
 */
u64 cake_frame_slice_ns __attribute__((aligned(STATE_SLOT_BYTES)));

/*
 * Frame-clock votes: the period is the cadence the MOST threads agree on, and
 * each bucket sums so the published value is exact. Loader takes the argmax
 * once a second and clears (§R.22).
 */
struct cake_frame_bucket {
	u64 count;
	u64 sum;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FRAME_BUCKETS);
	__type(key, u32);
	__type(value, struct cake_frame_bucket);
} cake_frame_hist SEC(".maps");

/*
 * This task's mean burst: runtime per voluntary switch, exact to the
 * nanosecond. Supersedes >> log2(nvcsw), which banded (§G11).
 */
static __always_inline u64 cake_burst_ns(const struct task_struct *p)
{
	return p->se.sum_exec_runtime / (p->nvcsw | 1);
}

/*
 * This task's mean CYCLE: lifetime per voluntary switch, cake_burst_ns's
 * wall-axis twin (§G12). Clamped to the fixed slice so a task that rarely
 * yields is bounded as compute, not trusted forever (§R.28).
 */
static __always_inline u64 cake_period_ns(const struct task_struct *p)
{
	u64 per = (bpf_ktime_get_ns() - p->start_time) / (p->nvcsw | 1);

	return per > SLICE_NS ? SLICE_NS : per;
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

/*
 * Fold this task's mean wake cadence into the frame clock: a display-coupled
 * thread reports the frame period directly, and casts one vote for it (§G11).
 * The range gate is cross-multiplied so the off-cadence majority — every
 * ops.running caller — never divides; nvcsw >= 2^32 takes the exact divide
 * path instead (§R.24).
 */
__noinline s32 cake_frame_observe(struct task_struct *p __arg_trusted, u64 now)
{
	u64 n = p->nvcsw | 1;
	u64 delta = now - p->start_time;
	struct cake_frame_bucket *b;
	u64 per;
	u32 idx;

	/*
	 * Only a thread that sleeps most of its life votes: burst < period/2
	 * with both sides over the same nvcsw, so the divisor CANCELS and the
	 * gate is one shift — a worker crowd that burns its cycle is load,
	 * not a display cadence (§G27.1; live: 26 Hz loader crowds won the
	 * argmax mid-game, 2026-08-17).
	 */
	if ((p->se.sum_exec_runtime << 1) >= delta)
		return 0;

	if (!(n >> 32) &&
	    (delta < FRAME_PERIOD_MIN_NS * n ||
	     delta >= (FRAME_PERIOD_MAX_NS + 1) * n))
		return 0;

	per = delta / n;
	if (per < FRAME_PERIOD_MIN_NS || per > FRAME_PERIOD_MAX_NS)
		return 0;

	idx = (u32)(per >> FRAME_BUCKET_SHIFT) & (FRAME_BUCKETS - 1);
	b = bpf_map_lookup_elem(&cake_frame_hist, &idx);
	if (!b)
		return 0;

	/* This CPU's own copy: no atomic, no shared line (§R.22). */
	b->count++;
	b->sum += per;
	return 0;
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
	/* ktime the global wake queue was last consumed by ANY CPU (§R.16). */
	struct cake_slot wake_served;
	/*
	 * "WAKE_DSQ may hold work" mark gating the global peek in dispatch
	 * (§G41). Own slot: every CPU reads it every dispatch, and it must not
	 * share a line with wake_served, which serving CPUs store to (§R.10).
	 */
	struct cake_slot wake_mark;
	/*
	 * One recently idled CPU, cpu id + 1 (0 = none), published by its own
	 * going-idle dispatch so the wake path can claim it with a single
	 * test-and-clear instead of an idle-mask scan (§G43).
	 */
	struct cake_slot idle_hint;
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
	if (!(cake.qmask[cpu >> 6] & bit))
		__atomic_fetch_or(&cake.qmask[cpu >> 6], bit, __ATOMIC_RELAXED);
}

static __always_inline void cake_qmark_clear(u32 cpu)
{
	u64 bit;

	cpu &= MAX_CPUS - 1;
	bit = 1ULL << (cpu & 63);
	if (cake.qmask[cpu >> 6] & bit)
		__atomic_fetch_and(&cake.qmask[cpu >> 6], ~bit, __ATOMIC_RELAXED);
}

static __always_inline bool cake_qmark_test(u32 cpu)
{
	cpu &= MAX_CPUS - 1;
	return cake.qmask[cpu >> 6] & (1ULL << (cpu & 63));
}

/*
 * Wake-routing emptiness: a CLEAR bit already proves the DSQ empty (insert
 * marks first, §G25); the rhashtable lookup is paid only on a set bit. A
 * stale clear misroutes one wake, healed by the owner's next own-queue peek.
 * __noinline: inlined, the word address pins across the callers' kfuncs (§G44).
 */
static __noinline bool cake_cpu_dsq_idle(u32 cpu)
{
	return !scx_bpf_dsq_nr_queued((u64)cpu);
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
 * §G25's mark for the ownerless WAKE_DSQ, where a stale CLEAR is not benign:
 * no owner rescans that queue, so the setter marks AFTER the insert and
 * retirement is clear-then-repeek. Protocol: §G41. Test before set (§R.10).
 */
static __always_inline void cake_wake_mark_set(void)
{
	if (!cake.wake_mark.word)
		cake.wake_mark.word = 1;
}

/* Loader-filled SMT map; -1 means the CPU has no online sibling. */
const volatile s32 cpu_sibling[MAX_CPUS];

/* Loader-maintained, LIVE (§G21, §G30): sink-ness follows device load, so
 * the loader re-probes on its run loop and bumps cake_sink_gen on change. */
u8 cpu_irq_hot[MAX_CPUS];
u32 cake_sink_gen;

/* Kernel-pushed, live to the instruction (§G35): handler entry/exit
 * tracepoints keep a per-CPU in-handler depth. Only the owning CPU writes;
 * cross-CPU reads race benignly (a stale read costs one placement, same as
 * today). Slot-padded so kHz-rate writers never share a line with each
 * other or with the wake-path readers. */
struct cake_irq_slot {
	u32 depth;
	/* §G51: cpuidle state index + 1 while idle, 0 awake; owner-written
	 * at the cpu_idle tracepoint. Same owner and line as depth. */
	u32 cstate;
	/* §G54: mailbox index + 1 where this CPU parked itself, 0 unparked;
	 * owner-written at idle entry/exit. */
	u32 park;
	u8 pad[STATE_SLOT_BYTES - 3 * sizeof(u32)];
};
static struct cake_irq_slot cake_irq_live[MAX_CPUS];

/* §G54 self-park mailboxes: one padded slot per WAKER CPU, value = parked
 * cpu + 1. The idle CPU writes itself in at idle entry (self-gated: it
 * evaluates its own cleanliness with local reads) and retracts at exit;
 * the waker consumes its own slot with a plain store — no atomics, and no
 * cross-waker claim race by construction (§R.29 taken to completion). */
static struct cake_slot cake_mailbox[MAX_CPUS];
static u64 cake_park_rotor;

/* §G54.1: mailbox entry quality — set when the parker's whole core is idle
 * (§G38 imported to the producer). Whole-core entries may overwrite
 * half-core entries, never the reverse. */
#define CAKE_PARK_CORE	(1ULL << 31)

/* §G54.1: consumers share one slot per physical core (the sibling with the
 * lower id names it), concentrating parked entries into half the slots. */
static __always_inline u32 cake_core_slot(u32 c)
{
	s32 sib = cpu_sibling[c & (MAX_CPUS - 1)];

	return (sib >= 0 && (u32)sib < c) ? (u32)sib & (MAX_CPUS - 1) : c;
}

/* Bad wake target: chronically loud (§G33 mask, the average truth) or
 * inside a handler right now (§G35, the instantaneous truth). Each alone
 * misses what the other sees. */
static __always_inline bool cake_cpu_irq_bad(s32 cpu)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	return cpu >= 0 && (cpu_irq_hot[c] || cake_irq_live[c].depth);
}

/* A thread whose SMT sibling executes delivers a fraction of the core, so an
 * idle thread on a busy core is not the same offer as an idle core. Cake ranks
 * cache warmth above that difference; measured on a live aim trainer the trade
 * is inverted, and it inverts on an idle machine where the alternative core is
 * free (§G38). */
static __always_inline bool cake_core_contended(s32 cpu)
{
	s32 sib = cpu_sibling[(u32)cpu & (MAX_CPUS - 1)];
	struct task_struct *curr;

	if (sib < 0)
		return false;

	/*
	 * Mirror hit answers without the rq deref chain (§M6). Zero is
	 * ambiguous -- idle or a non-SCX class -- so only nonzero decides.
	 */
	if (cake_tog_m6 && cake.run[(u32)sib & (MAX_CPUS - 1)].occupant)
		return true;

	curr = cake_cpu_curr(sib);

	return curr && curr->pid;
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
	return next <= bpf_ktime_get_ns() + cake_wake_hop_ns;
}

/* The two-truth cleanliness test, spelled once: chronically loud or
 * mid-handler (§G30/§G35) OR about to take its tick (§G36). */
static __always_inline bool cake_cpu_clean(s32 cpu)
{
	return !cake_cpu_irq_bad(cpu) && !cake_cpu_tick_soon(cpu);
}

/* Escape pick away from a bad target: a whole idle core first (§G38), but a
 * poisoned core winner -- the permanently idle sink core -- must not cost the
 * escape, so a bad core pick re-picks thread-grain. The first pick's
 * test-and-clear consumed the bad core's idle bit, so a repeated core pick
 * cannot return it again. A subprogram, not inline: expanded twice in
 * select_cpu it costs a spill there (§G38.1, §R.11). */
static __noinline s32 cake_pick_idle_escape(struct task_struct *p __arg_trusted)
{
	s32 alt = scx_bpf_pick_idle_cpu(p->cpus_ptr, CAKE_PICK_IDLE_CORE);

	if (alt < 0 || !cake_cpu_clean(alt))
		alt = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

	return alt;
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

/* §G51: mirror the CPU's cpuidle state so placement can rank shallow idle
 * above deep. Fires on the idling CPU itself at entry (state index) and
 * exit (~0), so the byte is exact at every transition. */
SEC("?tp_btf/cpu_idle")
int BPF_PROG(cake_cpu_idle, unsigned int state, unsigned int cpu_id)
{
	u32 c;

	if (!cake_tog_g51)
		return 0;
	c = cpu_id & (MAX_CPUS - 1);
	cake_irq_live[c].cstate = state == (unsigned int)-1 ? 0 : state + 1;
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(cake_softirq_leave)
{
	cake_irq_edge(false);
	return 0;
}

/* Rebuilt from cpu_irq_hot when nonsink_gen trails cake_sink_gen: the
 * first-choice placement set (§G23, §G30). */
private(CAKE_NONSINK) struct bpf_cpumask __kptr *nonsink_cpumask;
static u32 nonsink_gen;

/*
 * The CPU id span cake scans, bounding the steal ring and neighbour probe.
 * Rodata, so libbpf's freeze lets the verifier fold it and prune the walk's
 * bound checks; ops.init validates it against nr_cpu_ids (§R.21).
 */
const volatile u32 nr_cpu_span;

/* Concurrent rebuilds race benignly — the kptr xchg keeps exactly one; gen
 * is captured pre-build so a mid-build republish re-triggers (§G30). */
static __noinline int cake_nonsink_rebuild(u32 gen)
{
	struct bpf_cpumask *mask = bpf_cpumask_create();
	int i;

	if (!mask)
		return -ENOMEM;
	bpf_for(i, 0, nr_cpu_span) {
		if (!cpu_irq_hot[(u32)i & (MAX_CPUS - 1)])
			bpf_cpumask_set_cpu((u32)i, mask);
	}
	mask = bpf_kptr_xchg(&nonsink_cpumask, mask);
	if (mask)
		bpf_cpumask_release(mask);
	nonsink_gen = gen;
	return 0;
}

/* Loader-sorted: same CCD, same cache-capacity tier, then unrestricted.
 * Fixed span so one binary fits any host; live only when the loader saw
 * multiple CCDs AND the host fits the matrix — rodata, so the verifier
 * folds the dead branch away on every other machine. */
const volatile u16 cpu_steal_order[STEAL_SPAN * STEAL_SPAN];
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

	/*
	 * Mirror path (§M6): dsq_vtime is charged only at stopping, so the
	 * published copy is exact for the whole slice; recip-index rides the
	 * occupant word. One line instead of the rq->curr chain.
	 */
	if (cake_tog_m6) {
		u64 occ = rs->occupant;

		if (!occ)
			return 0;
		cv = rs->mirror_vtime;
		if (!cv)
			return 0;
		cidx = (u32)occ & 0xff;
	} else {
		curr = cake_cpu_curr(tcpu);
		if (!curr)
			return 0;
		cv = curr->scx.dsq_vtime;
		if (!cv)
			return 0;
		cidx = cake_recip_index(curr);
	}

	stamp = rs->stamp;
	ran = bpf_ktime_get_ns() - stamp;
	*ran_out = ran;
	return cake_scale_vtime_add(cv, ran, cidx);
}

/*
 * DIAGNOSTIC PROBE — not for scoring. Per-arm placement census for
 * ops.select_cpu, so the mailbox hit rate is a measurement instead of an
 * assumption (STATE.md pillar 3 lists it unmeasured). Per-CPU map, plain
 * increment on this CPU's own copy: no atomic, no shared line, same shape
 * as cake_frame_hist. REVERT before any scoring run.
 */
enum cake_stat {
	CAKE_STAT_SELECT = 0,		/* ops.select_cpu entries */
	CAKE_STAT_SERIAL,		/* serial-handoff arm placed */
	CAKE_STAT_HOME,			/* prev-cpu warm home claim placed */
	CAKE_STAT_PARK_REACHED,		/* cake_park_take called */
	CAKE_STAT_PARK_PREV,		/* park_take won on prev warmth */
	CAKE_STAT_PARK_MBOX,		/* park_take won on the mailbox */
	CAKE_STAT_OPT_REACHED,		/* cake_optimistic_place called */
	CAKE_STAT_OPT_HIT,		/* cake_optimistic_place placed */
	CAKE_STAT_RANKED,		/* fell through to the ranked pick */
	CAKE_STAT_WP_ATTEMPT,		/* wake_preempt reached with a live occupant */
	CAKE_STAT_WP_TINY,		/* wakee burst <= 4us (microsecond-class shape) */
	CAKE_STAT_WP_SMALL,		/* wakee burst <= 64us */
	CAKE_STAT_WP_PROTECT,		/* rejected: protect window not met */
	CAKE_STAT_WP_VTIME,		/* rejected: vtime bar */
	CAKE_STAT_WP_STARVED,		/* rejected: pipeline-stage veto */
	CAKE_STAT_WP_FIRED,		/* kick issued */
	CAKE_STAT_FREE_PICK,		/* §G57 placed behind an earlier-free CPU */
	CAKE_STAT_PREWAKE_FIRE,		/* §G58 timer fired on an idle CPU */
	CAKE_STAT_RESERVED_TAKE,	/* §G58 wake took its reservation */
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
	CAKE_STAT_HD_SKIP, CAKE_STAT_HD_SYNC, CAKE_STAT_HD_STARVED, CAKE_STAT_HD_IRQ,
	CAKE_STAT_HD_AFF, CAKE_STAT_HD_CONTENDED, CAKE_STAT_HD_NOTIDLE, /* PROBE: home declines */
	CAKE_STAT_HOME_BUSY,		/* home claim succeeded on a CPU with a running task */
	CAKE_STAT_HOME_LOCALQ,		/* home claim succeeded on a CPU whose local DSQ is non-empty */
	CAKE_STAT_H3_HOME_BUSY,		/* ... and the wakee then waited >300us */
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

static u64 cake_core_free __attribute__((aligned(STATE_SLOT_BYTES)));
static u64 cake_seat_word __attribute__((aligned(STATE_SLOT_BYTES)));
static u64 cake_idle_words[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));

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

	if (dsq_id == (u64)WAKE_DSQ)
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
	t->place_ns = bpf_ktime_get_ns();
	t->target = (u32)dsq_id & (MAX_CPUS - 1);
	t->caller = me;
	{
		struct task_struct *w = bpf_get_current_task_btf();

		t->waker_pid = w ? (u32)w->pid : 0;
	}
	t->seats = cake_seat_word; t->core_free = cake_core_free;
	t->thread_free = cake_idle_words[0]; t->idle_word = cake_idle_words[0];
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
static __noinline bool cake_wake_preempt(struct task_struct *p, s32 tcpu,
					 u32 protect_shift)
{
	u64 ran = 0;
	u64 live = cake_occupant_live(tcpu, &ran);
	struct task_struct *curr;
	u64 se = p->se.sum_exec_runtime;
	u64 n = p->nvcsw | 1;

	/* §G39-B' census: which gate refuses the microsecond-class successor.
	 * Counters only -- behavior is identical to the ungated build. Shape
	 * buckets are cross-multiplied so the census spends no divide (§R.24). */
	cake_stat_inc(CAKE_STAT_WP_ATTEMPT);
	if (!((4096 | n) >> 32) && se < 4096 * n)
		cake_stat_inc(CAKE_STAT_WP_TINY);
	if (!((65536 | n) >> 32) && se < 65536 * n)
		cake_stat_inc(CAKE_STAT_WP_SMALL);

	if (!live)
		return false;
	if (ran < (u64)SLICE_NS >> protect_shift) {
		cake_stat_inc(CAKE_STAT_WP_PROTECT);
		return false;
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
	if (nr_cpu_span <= 64)
		return (u32)__builtin_popcountll(cake_idle_words[0]);
	return (u32)cake_idle_nr;
}

/* §G71: the idle side publishes, the waker claims with ONE atomic. A CPU
 * entering idle sets its bit in the §G45 census word (the thread word,
 * §G82), and in core_free when its sibling is idle too; leaving idle clears
 * both (and the sibling's core bit). The words choose; the kernel idle bit
 * claims. Narrow hosts (span <= 64). */

/* §G79 SEAT HOLD. A stage-class thread (burst >= SEAT_BURST_MIN_NS) that
 * blocks will wake again within the frame; in the stack its core was taken
 * in that gap by a dxvk or render wake and it came back cold 450 times a
 * second (GameThread 12,629 migrations vs 1.1.3's 650). Its CPU is marked
 * held; other wakes skip held cores while any other core is free; whoever
 * runs there clears it. The owner's home claim on its own seat is unaffected. */


/* §G60: whole core, judged from the census alone -- the sibling's idle bit,
 * no rq deref. The §G38 rule (a whole idle core outranks an idle thread on a
 * busy core) guarded the home claim and the ranked pick; the census
 * consumers built after it (§G53 first-fit, §G54 mailbox and prev-cpu take)
 * run ahead of both and were placing on half cores. */
static __always_inline bool cake_core_idle_census(u32 c)
{
	s32 sib = cpu_sibling[c & (MAX_CPUS - 1)];

	if (sib < 0)
		return true;
	return (cake_idle_words[((u32)sib & (MAX_CPUS - 1)) >> 6] >>
		((u32)sib & 63)) & 1;
}

static __noinline bool cake_vip(const struct task_struct *p)
{
	return cake_tog_g68 && (u32)p->tgid == cake_vip_tgid;
}

/* §G69: every local placement is CLAIMED at this instant (1.1.3's certainty)
 * and chosen warm-first (cake's placement): a whole idle core from the
 * census, then any idle thread, each taken with the atomic idle claim so a
 * second waker can never stack behind it. Narrow hosts only; -1 sends the
 * wake to the pool. */
static __noinline s32 cake_claim_warm(struct task_struct *p __arg_trusted,
				      s32 groove)
{
	u64 aff = p->cpus_ptr->bits[0];
	u64 idle = cake_idle_words[0] & aff;
	u64 half = 0;
	u32 k;

	if (nr_cpu_span > 64)
		return -1;

	/* §G78: a task with no groove yet takes its first whole core from a
	 * rotor, so the game's threads land on DIFFERENT cores and each keeps
	 * its own predictor and L1 (per-CPU busy 39/33/26/27% on cores 0-3 vs
	 * 1.1.3's even 10%; branch misses +34%). From then on the groove
	 * (last_win) is its home; §G73 rotated on every wake and paid cold. */
	if (cake_tog_g78 && groove < 0) {
		u64 w = cake_core_free & aff;

		if (w) {
			u32 r = (u32)__atomic_fetch_add(&cake_park_rotor, 1,
							__ATOMIC_RELAXED) & 63;
			u64 hi = w & (~0ULL << r);
			s32 c = (s32)__builtin_ctzll(hi ? hi : w);

			if (scx_bpf_test_and_clear_cpu_idle(c))
				return c;
		}
	}

	/* §G75: the CPU this task last won, if it is a free whole core now. */
	if (groove >= 0 && groove < 64 &&
	    ((cake_core_free >> groove) & 1) && ((aff >> groove) & 1) &&
	    scx_bpf_test_and_clear_cpu_idle(groove))
		return groove;

	/* §G71: one atomic on a published word replaces the scan. */
	if (cake_tog_g71) {
		/* The published words CHOOSE (one read each); the kernel idle bit
		 * CLAIMS (one kfunc). Two kfuncs at most per wake, no scan. */
		u64 seats = cake_tog_g79 ? cake_seat_word : 0;
		u64 w = cake_core_free & aff & ~seats;
		/* §G73: the search starts at the task's own core and wraps,
		 * so idle cores are used in turn instead of the lowest one
		 * absorbing every placement (L2 thrash, cold every time). */
		u32 r = cake_tog_g73 ? ((u32)p->thread_info.cpu & 63) : 0;
		s32 c;

		if (!w)
			w = cake_core_free & aff;	/* only held cores left: take one */
		if (w) {
			u64 hi = w & (~0ULL << r);

			c = (s32)__builtin_ctzll(hi ? hi : w);
			if (scx_bpf_test_and_clear_cpu_idle(c))
				return c;
		}
		w = cake_idle_words[0] & aff & ~seats;
		if (!w)
			w = cake_idle_words[0] & aff;
		if (w) {
			u64 hi = w & (~0ULL << r);

			c = (s32)__builtin_ctzll(hi ? hi : w);
			if (c < 64 && !((cake_core_free >> c) & 1) &&
			    scx_bpf_test_and_clear_cpu_idle(c))
				return c;
		}
		return -1;
	}

	/* §G72: a microsecond-class wakee of the waker's own address space
	 * takes the waker's idle SMT sibling: shared L2, no wait, and at that
	 * burst length the sibling costs the waker nothing measurable. Long
	 * bursts keep whole cores (§G38). */
	if (cake_tog_g72 && cake_burst_ns(p) <= L2_HANDOFF_BURST_NS) {
		struct task_struct *w = bpf_get_current_task_btf();
		u32 wc = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
		s32 sib = cpu_sibling[wc];

		if (w && w->mm && w->mm == p->mm && sib >= 0 &&
		    ((idle >> ((u32)sib & 63)) & 1) &&
		    scx_bpf_test_and_clear_cpu_idle(sib))
			return sib;
	}
	for (k = 0; k < DEPTH_SCAN_MAX && idle; k++) {
		s32 c = (s32)__builtin_ctzll(idle);

		idle &= idle - 1;
		if (!cake_core_idle_census((u32)c)) {
			half |= 1ULL << (c & 63);
			continue;
		}
		if (scx_bpf_test_and_clear_cpu_idle(c))
			return c;
	}
	for (k = 0; k < 2 && half; k++) {
		s32 c = (s32)__builtin_ctzll(half);

		half &= half - 1;
		if (scx_bpf_test_and_clear_cpu_idle(c))
			return c;
	}
	return -1;
}

static __noinline u64 cake_vip_head_vtime(void)
{
	return cake.frontier.word - SLICE_NS;
}

/* §G70 EXPERIMENT: every preempt kick goes through here; a VIP occupant is
 * never thrown off, it finishes its burst. */
static __noinline void cake_kick_preempt(s32 cpu)
{
	if (cake_tog_g70 && cake_vip_tgid) {
		struct task_struct *oc = cake_cpu_curr(cpu);

		if (oc && oc->pid && (u32)oc->tgid == cake_vip_tgid)
			return;
	}
	scx_bpf_kick_cpu(cpu, CAKE_KICK_PREEMPT);
}

/* §G75 GROOVES: a task's own placement history. The home claim is the
 * warmest rung and the most expensive question (a kernel atomic); a task
 * whose home keeps being busy stops asking after GROOVE_HOME_MISS misses and
 * re-probes once every GROOVE_PROBE_MASK+1 wakes. The CPU its whole-core
 * claim last won is tried first next time -- the groove -- under the same
 * single-writer claim, so history orders the choice and never replaces the
 * claim. One task-storage lookup per wake. */
struct cake_groove {
	u8 home_miss;
	u8 wakes;
	s16 last_win;		/* cpu + 1; 0 = none */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_groove);
} cake_grooves SEC(".maps");

static __always_inline struct cake_groove *cake_groove_of(struct task_struct *p)
{
	if (!cake_tog_g75)
		return NULL;
	return bpf_task_storage_get(&cake_grooves, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* §G61: a census placement is unverified -- the wakee goes into the local
 * queue of a CPU whose idle bit was set, with no claim. When that CPU is
 * already running something else by the time the insert lands, the wakee
 * waits behind that occupant for up to its whole slice and no other CPU can
 * serve a local queue: the HOLD shape, 0.7-1.7 ms on the KovaaKs render
 * path (wake decomposition 2026-09-02), absent on 1.1.3 whose shared queue
 * any idle CPU drains. The collision is the occupant's to pay. */
static __always_inline void cake_collision_preempt(struct task_struct *p,
						   s32 cpu)
{
	struct task_struct *curr;

	if (!cake_tog_g61)
		return;
	curr = cake_cpu_curr(cpu);
	if (curr && curr->pid && curr != p)
		cake_kick_preempt(cpu);
}

static __noinline bool cake_system_serial(void)
{
	u32 nr;

	/* One word read replaces the kernel mask walk per wake (§G45). */
	nr = cake_idle_count();

	return nr * 4 >= nr_cpu_span * 3;
}

/*
 * The liveness term: scx_bpf_dsq_nr_queued() counts tasks WAITING, never the
 * one EXECUTING, so a CPU busy mid-slice reads as empty and the co-location
 * gate would admit onto it. Admit when there is no SCX occupant, or when the
 * occupant is within one handoff of the end of its OWN typical burst and so
 * about to yield the CPU anyway.
 *
 * Measured RELATIVE to the occupant, not against a fixed age: an absolute
 * window cannot tell a serial partner about to block from a long-running
 * thread that merely started recently, and reading it as the latter is what
 * cost Helldivers 2 its tails (§R.1, §G9.7; game result in STATE.md).
 *
 * Cannot be exact: ALLOW_QUEUED_WAKEUP hides the waker and cake keeps no
 * per-task state, so this refuses a bad bet rather than proving a good one.
 *
 * The verdict is burst < ran + max, cross-multiplied to sum_exec <
 * (ran + max) * nvcsw so the gate spends no divide; operands >= 2^32 take
 * the exact divide path instead (§R.24).
 */
static __noinline bool cake_handoff_yields(s32 tcpu)
{
	struct task_struct *curr = cake_cpu_curr(tcpu);
	u64 ran, burst, lim, n;

	if (!curr || !curr->scx.dsq_vtime)
		return true;

	ran = bpf_ktime_get_ns() -
	      cake.run[(u32)tcpu & (MAX_CPUS - 1)].stamp;
	n = curr->nvcsw | 1;
	lim = ran + cake_handoff_max_ns;

	if (!((lim | n) >> 32))
		return curr->se.sum_exec_runtime < lim * n;

	burst = cake_burst_ns(curr);
	return burst <= ran || burst - ran < cake_handoff_max_ns;
}


/*
 * The slice this task needs: twice its own burst, capped at half its OWN
 * cycle -- a task must not hold a CPU past its next wake -- floored at the
 * handoff cost. The grant is a PREEMPTION TIMER, not a vtime question
 * (§G10.4, §G18, §R.28).
 */
static __noinline u64 cake_task_slice(struct task_struct *p __arg_trusted)
{
	u64 want = cake_burst_ns(p) << 1;
	u64 cap = cake_period_ns(p) >> PERIOD_SLICE_CAP_SHIFT;

	if (want > cap)
		want = cap;
	if (want < cake_handoff_max_ns)
		want = cake_handoff_max_ns;
	return want;
}

/*
 * §G46: serve the insert sites from the departure cache — one load + compare
 * against cake_task_slice's two divides and a clock read. Tagged by pid, two
 * entries because handoff pairs alternate; staleness is one quantum of
 * estimator drift. The slot is the task's own CPU — where it last stopped —
 * read here, not passed, so callers keep no extra live value. Miss: compute.
 */
static __noinline u64 cake_task_slice_cached(struct task_struct *p __arg_trusted)
{
	if (cake_tog_g46) {
		struct cake_run_slot *rs =
			&cake.run[(u32)p->thread_info.cpu & (MAX_CPUS - 1)];
		u64 tag = (u64)(u32)p->pid << 32;
		u64 e0 = rs->slice_cache[0];
		u64 e1 = rs->slice_cache[1];

		if ((e0 & ~0xffffffffULL) == tag)
			return (u32)e0;
		if ((e1 & ~0xffffffffULL) == tag)
			return (u32)e1;
	}
	return cake_task_slice(p);
}

/* The cache's write half, called LAST in stopping so the caller carries
 * nothing across it; the slot line is one this op already owns (§G46). */
static __noinline void cake_slice_publish(struct task_struct *p __arg_trusted)
{
	struct cake_run_slot *rs =
		&cake.run[(u32)p->thread_info.cpu & (MAX_CPUS - 1)];
	u64 ent = ((u64)(u32)p->pid << 32) | (u32)cake_task_slice(p);

	rs->slice_cache[1] = rs->slice_cache[0];
	rs->slice_cache[0] = ent;
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
 * Home-arm notification, decided AFTER the insert rather than carried across
 * it. Returns true when tcpu needs nothing further from us. Both re-read
 * inputs are exact there, not approximations (§R.14). A zero curr vtime means
 * an idle- or higher-class-owned home with no preempt to fire, where the only
 * question left is whether core already rescheduled it for us.
 */
static __noinline bool cake_home_notify(struct task_struct *p, s32 tcpu)
{
	u64 ran = 0;
	u64 live = cake_occupant_live(tcpu, &ran);

	if (!live) {
		if ((u32)tcpu == bpf_get_smp_processor_id())
			return true;
		/* Idle-owned REMOTE home: kick the home itself, not some idle
		 * CPU elsewhere -- the queue lives on tcpu and a foreign kick
		 * only finds it through the steal ring. Measured on live
		 * KovaaKs: every slow GameThread wake (>20 µs, p99 128 vs
		 * native 6) had idle capacity and 75% an idle home (§G40). */
		scx_bpf_kick_cpu(tcpu, CAKE_KICK_IDLE);
		return true;
	}

	if (ran >= ((u64)SLICE_NS >> 5) ||
	    !time_before(p->scx.dsq_vtime + (SLICE_NS >> 1) -
			 (ran >> HOME_PREEMPT_RAN_CREDIT_SHIFT), live))
		return false;

	cake_kick_preempt(tcpu);
	return true;
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

static __noinline s32 cake_idle_hint_claim(struct task_struct *p __arg_trusted);


/* Affinity by direct bitmap read (§G54, the §M7 idea applied to cpumask):
 * one load chain instead of a helper crossing. Constant offset only — the
 * verifier refuses a variable-offset load through a trusted cpumask; the
 * rodata gate lets it delete the kfunc arm at load on hosts within one word. */
static __always_inline bool cake_affine(struct task_struct *p, s32 cpu)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	if (nr_cpu_span <= 64)
		return (p->cpus_ptr->bits[0] >> (c & 63)) & 1;
	return bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

/* §G58: is @c held for a task other than @p right now? One slot read; the
 * line belongs to an idle CPU, so it is quiet. */
static __always_inline bool cake_reserved_for_other(const struct task_struct *p,
						    u32 c, u64 now)
{
	struct cake_run_slot *rs = &cake.run[c & (MAX_CPUS - 1)];
	u64 rp = rs->reserved_pid;

	return rp && rp != (u64)(u32)p->pid &&
	       time_before(now, rs->reserved_until);
}

/* §G59: the exit latency this idle CPU would pay, from the §G51 mirror and
 * the loader's table. Zero when unknown, which ranks as shallow. */
static __always_inline u64 cake_idle_exit_ns(u32 c)
{
	u32 cs = cake_irq_live[c & (MAX_CPUS - 1)].cstate;

	if (!cs)
		return 0;
	return (u64)cake_cstate_exit_us[(cs - 1) & (CAKE_CSTATE_TABLE - 1)] *
	       NSEC_PER_USEC;
}

/*
 * §G59 pick over the census: among the first DEPTH_SCAN_MAX affine idle
 * CPUs, the one with the smallest exit latency; ties keep census order, so
 * with the table empty this IS the §G53 first fit. §G58 reservations for
 * other tasks are skipped. Narrow hosts only; wide hosts keep the walk.
 */
static __noinline s32 cake_shallowest_idle(struct task_struct *p __arg_trusted)
{
	u64 idle = cake_idle_words[0];
	u64 aff = p->cpus_ptr->bits[0];
	u64 best_exit = ~0ULL;
	u64 now = 0;
	s32 best = -1;
	u32 k;

	if (cake_tog_g58)
		now = bpf_ktime_get_ns();
	for (k = 0; k < DEPTH_SCAN_MAX && idle; k++) {
		u32 c = (u32)__builtin_ctzll(idle);
		u64 e;

		idle &= idle - 1;
		if (!((aff >> (c & 63)) & 1))
			continue;
		if (cake_tog_g58 && cake_reserved_for_other(p, c, now))
			continue;
		e = cake_tog_g59 ? cake_idle_exit_ns(c) : 0;
		if (e < best_exit) {
			best_exit = e;
			best = (s32)c;
		}
		if (!e)
			break;
	}
	return best;
}

/*
 * §G57 consumer: a wake with nothing idle in its mask picks the affine CPU
 * in its home LLC whose occupant is predicted to leave first, from the run
 * slots' free_at, and queues there instead of behind its home occupant.
 * The move must clear FREE_MOVE_MARGIN: a partner about to yield keeps the
 * wake home, which is what protects the messaging herd, and a mid-burst
 * worker loses it, which is what unstrands the game. A stale slot (older
 * than a slice: an RT or idle occupant) is never a target and never moved
 * from. Narrow hosts only.
 */
static __noinline s32 cake_free_pick(struct task_struct *p __arg_trusted,
				     s32 tcpu)
{
	u32 t = (u32)tcpu & (MAX_CPUS - 1);
	u64 aff = p->cpus_ptr->bits[0];
	u64 w, now, home_at, best_at;
	s32 best = -1;
	u32 k;

	if (nr_cpu_span > 64 || (aff & cake_idle_words[0]))
		return -1;
	w = aff & cake_llc_qword[cake_cpu_llc[t] & (MAX_LLCS - 1)];
	w &= ~(1ULL << (t & 63));
	if (!w)
		return -1;

	now = bpf_ktime_get_ns();
	home_at = cake.run[t].free_at;
	if (time_before(home_at + SLICE_NS, now))
		return -1;
	best_at = home_at;
	for (k = 0; k < 64 && w; k++) {
		u32 c = (u32)__builtin_ctzll(w);
		u64 at = cake.run[c & (MAX_CPUS - 1)].free_at;

		w &= w - 1;
		if (time_before(at + SLICE_NS, now))
			continue;
		if (time_before(at, best_at)) {
			best_at = at;
			best = (s32)c;
		}
	}
	if (best < 0 ||
	    !time_before(best_at + ((u64)SLICE_NS >> FREE_MOVE_MARGIN_SHIFT),
			 home_at))
		return -1;
	return best;
}

/*
 * §G58 consumer: the reservation the pre-wake timer left on prev for THIS
 * task. Read before every other placement claim: the CPU was kicked awake
 * for this wake, so the vetoes that would send the task elsewhere (turn
 * starvation, a busy sibling) are already priced into the prediction.
 */
static __noinline s32 cake_reserved_take(struct task_struct *p __arg_trusted,
					 s32 prev_cpu)
{
	u32 c = (u32)prev_cpu & (MAX_CPUS - 1);
	struct cake_run_slot *rs = &cake.run[c];

	if (rs->reserved_pid != (u64)(u32)p->pid)
		return -1;
	if (!time_before(bpf_ktime_get_ns(), rs->reserved_until)) {
		rs->reserved_pid = 0;
		return -1;
	}
	if (!cake_affine(p, prev_cpu) ||
	    !scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return -1;
	rs->reserved_pid = 0;
	cake_stat_inc(CAKE_STAT_RESERVED_TAKE);
	cake_direct_clamp(p);
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | c, cake_task_slice_cached(p), 0);
	return prev_cpu;
}

/* §G54 consumer: prev-warmth first (census bit, optimistic), then this
 * waker's own core mailbox. Both place without a consuming claim — a stale
 * entry costs one occupant wait, the §G53-measured trade. A subprogram so
 * the frame cost stays off select_cpu (§R.11). */
static __noinline s32 cake_park_take(struct task_struct *p __arg_trusted,
				     s32 prev_cpu)
{
	u32 wc = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
	u64 mbox;
	s32 ocpu = -1;

	if (prev_cpu >= 0) {
		u32 pc = (u32)prev_cpu & (MAX_CPUS - 1);

		if ((cake_idle_words[pc >> 6] >> (pc & 63)) & 1 &&
		    !cpu_irq_hot[pc] && cake_affine(p, prev_cpu) &&
		    !(cake_tog_g60 && !cake_core_idle_census(pc)) &&
		    !(cake_tog_g58 &&
		      cake_reserved_for_other(p, pc, bpf_ktime_get_ns()))) {
			ocpu = prev_cpu;
			cake_stat_inc(CAKE_STAT_PARK_PREV);
		}
	}
	if (ocpu < 0) {
		u32 slot = cake_core_slot(wc);

		mbox = cake_mailbox[slot].word;
		if (mbox) {
			s32 mcpu = (s32)(u32)((mbox & ~CAKE_PARK_CORE) - 1);

			if (cake_affine(p, mcpu) &&
			    !(cake_tog_g60 &&
			      !cake_core_idle_census((u32)mcpu)) &&
			    !(cake_tog_g58 &&
			      cake_reserved_for_other(p, (u32)mcpu,
						      bpf_ktime_get_ns()))) {
				cake_mailbox[slot].word = 0;
				ocpu = mcpu;
				cake_stat_inc(CAKE_STAT_PARK_MBOX);
			}
		}
	}
	/*
	 * §G59: a parked CPU deep in idle loses to a shallower affine one.
	 * The mailbox entry is already consumed; the parker re-parks at its
	 * next idle entry, so a lost entry costs one wake's fallback.
	 */
	if (ocpu >= 0 && cake_tog_g59 && nr_cpu_span <= 64 &&
	    cake_idle_exit_ns((u32)ocpu)) {
		s32 alt = cake_shallowest_idle(p);

		if (alt >= 0 && alt != ocpu &&
		    cake_idle_exit_ns((u32)alt) < cake_idle_exit_ns((u32)ocpu))
			ocpu = alt;
	}
	if (ocpu < 0)
		return -1;
	/* §G62: the census bit is a hint several wakers read at once; the
	 * atomic claim is what keeps two of them out of one FIFO local queue
	 * (hold attribution probe 2026-09-02: every >300 us hold sat in a
	 * LOCAL_ON placement). Losing the claim falls through to the ranked
	 * pick, which claims what it returns. */
	if (cake_tog_g62 && !scx_bpf_test_and_clear_cpu_idle(ocpu))
		return -1;
	cake_direct_clamp(p);
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)ocpu,
			cake_task_slice_cached(p), 0);
	cake_collision_preempt(p, ocpu);
	return ocpu;
}

/* Wide-host census walk. A cpumask load needs a CONSTANT word index -- the
 * verifier refuses a variable one through a trusted pointer -- so past one
 * word affinity stays a kfunc. Its own subprogram, so the register pressure
 * of that crossing stays in this frame instead of the narrow path's (§R.8). */
static __noinline s32 cake_census_walk_wide(struct task_struct *p __arg_trusted)
{
	u32 wi;

	for (wi = 0; wi < QMASK_WORDS; wi++) {
		u64 w;
		u32 base = wi << 6;
		u32 k;

		if (base >= nr_cpu_span)
			break;
		w = cake_idle_words[wi];
		for (k = 0; k < 2 && w; k++) {
			s32 ocpu = (s32)(base + __builtin_ctzll(w));

			w &= w - 1;
			if (bpf_cpumask_test_cpu(ocpu, p->cpus_ptr))
				return ocpu;
		}
	}
	return -1;
}

/* Optimistic first-fit from the census (§G53): affinity is the only gate,
 * placement is unverified — the mailbox-miss fallback. A subprogram so the
 * walk costs select_cpu's frame nothing (§R.11).
 *
 * The census and the affinity mask are the SAME bitmap shape, so within one
 * word the per-bit kfunc becomes a shift against a word loaded once: no call
 * in the walk, nothing to keep callee-saved across one, and @p is not touched
 * again until the placement. Rodata gate, so the verifier deletes the wide
 * arm at load on every host inside one word (§G54). */
static __noinline s32 cake_optimistic_place(struct task_struct *p __arg_trusted)
{
	s32 ocpu = -1;

	if (nr_cpu_span <= 64) {
		if (cake_tog_g58 || cake_tog_g59) {
			ocpu = cake_shallowest_idle(p);
		} else {
			u64 idle = cake_idle_words[0];
			u64 aff = p->cpus_ptr->bits[0];
			u32 depth = cake_tog_g60 ? DEPTH_SCAN_MAX : 2;
			s32 half = -1;
			u32 k;

			/* §G60: the first affine WHOLE idle core wins; a half
			 * core is remembered and taken only when the scan finds
			 * no whole one, so an idle machine never doubles up. */
			for (k = 0; k < depth && idle; k++) {
				s32 c = (s32)__builtin_ctzll(idle);

				idle &= idle - 1;
				if (!((aff >> (c & 63)) & 1))
					continue;
				if (!cake_tog_g60 ||
				    cake_core_idle_census((u32)c)) {
					ocpu = c;
					break;
				}
				if (half < 0)
					half = c;
			}
			if (ocpu < 0)
				ocpu = half;
		}
	} else {
		ocpu = cake_census_walk_wide(p);
	}

	if (ocpu < 0)
		return -1;
	if (cake_tog_g62 && !scx_bpf_test_and_clear_cpu_idle(ocpu))
		return -1;	/* §G62: lost the race, see cake_park_take */
	cake_direct_clamp(p);
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)ocpu,
			cake_task_slice_cached(p), 0);
	cake_collision_preempt(p, ocpu);
	return ocpu;
}

/*
 * ops.select_cpu — placement plus guarded direct admission.
 *
 * When the ranked pick (nonsink set first, whole machine as fallback) finds an
 * idle CPU we normally direct-dispatch to the local DSQ for lowest latency,
 * unless the qmark guard sees an older visible claim. Otherwise the system is
 * saturated on this task's affinity: return the selected CPU and let
 * ops.enqueue() arbitrate on vtime.
 */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	struct cake_groove *gr = cake_groove_of(p);
	bool home_askable;

	cake_stat_inc(CAKE_STAT_SELECT);

	/* §G63: 1.1.3's queue semantics inside 1.2.x. No wake is ever parked
	 * in a CPU's private FIFO: select_cpu only picks and claims an idle
	 * CPU, ops.enqueue puts the wake in the shared vtime pool, and the
	 * claimed CPU (or any other idle one) drains it. The tail 1.1.3 keeps
	 * and 1.2.x lost (KovaaKs p99.9 1.75 vs 2.0-2.5 ms) is this property. */
	if (cake_tog_g63)
		return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	/* §G64: verified direct dispatch. The only local placement is the one
	 * the kernel's idle pick claimed this instant; every other wake takes
	 * the pool, where any idle CPU can serve it. 1.1.3's shape: it keeps
	 * the fast path for the certain case and never parks the rest. */
	if (cake_tog_g64) {
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		if (is_idle) {
			cake_direct_clamp(p);
			cake_dsq_insert(p, CAKE_DSQ_LOCAL,
					cake_task_slice_cached(p), 0);
		}
		return cpu;
	}


	/*
	 * Serial-handoff co-location, for a genuine handoff pair only: a
	 * saturated learned handoff bit, no WAKE_SYNC, the wakee allowed here,
	 * both queues empty, and an occupant that will actually yield. No
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
		if (serial && !cake_tog_g66 && !(wake_flags & CAKE_WAKE_SYNC) &&
		    !cake_cpu_irq_bad((s32)wc) &&
		    bpf_cpumask_test_cpu((s32)wc, p->cpus_ptr) &&
		    cake_system_serial() &&
		    cake_cpu_dsq_idle(wc) &&
		    !cake_local_nr((s32)wc) &&
		    cake_handoff_yields((s32)wc)) {
			s32 wcpu = (s32)wc;

			cake_direct_clamp(p);
			cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)wcpu,
					cake_task_slice_cached(p), 0);
			cake_stat_inc(CAKE_STAT_SERIAL);
			return wcpu;
		}
	}

	/* §G58: a CPU kicked awake for this exact wake is taken first. */
	if (cake_tog_g58 && prev_cpu >= 0) {
		s32 rcpu = cake_reserved_take(p, prev_cpu);

		if (rcpu >= 0)
			return rcpu;
	}

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
	{
		bool ask_home = true;

		if (gr) {
			gr->wakes++;
			if (gr->home_miss >= GROOVE_HOME_MISS &&
			    (gr->wakes & GROOVE_PROBE_MASK))
				ask_home = false;
		}
		if (!ask_home) {
			cake_stat_inc(CAKE_STAT_HD_SKIP);
			goto skip_home;
		}
	}
	/* PROBE: which gate declines the warm home, for the biggest burst tasks
	 * (stage class, burst >= 64 us), so GameThread's 9,300 migrations get a
	 * reason. Each gate is re-asked in order; the first refusal counts. */
	if (cake_burst_ns(p) >= SEAT_BURST_MIN_NS && prev_cpu >= 0) {
		if (wake_flags & CAKE_WAKE_SYNC) cake_stat_inc(CAKE_STAT_HD_SYNC);
		else if (cake_starved_turn(p)) cake_stat_inc(CAKE_STAT_HD_STARVED);
		else if (cake_cpu_irq_bad(prev_cpu)) cake_stat_inc(CAKE_STAT_HD_IRQ);
		else if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) cake_stat_inc(CAKE_STAT_HD_AFF);
		else if (cake_core_contended(prev_cpu)) cake_stat_inc(CAKE_STAT_HD_CONTENDED);
		else if (!scx_bpf_test_and_clear_cpu_idle(prev_cpu)) cake_stat_inc(CAKE_STAT_HD_NOTIDLE);
		else {
			/* the claim just succeeded: place, exactly as below */
			if (gr)
				gr->home_miss = 0;
			cake_direct_clamp(p);
			cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)prev_cpu,
					cake_task_slice_cached(p), 0);
			cake_stat_inc(CAKE_STAT_HOME);
			return prev_cpu;
		}
	}
	/* §G80: the groove counts a MISS only when the home was asked and was
	 * busy (sibling running, or the idle claim lost). The SYNC, starvation
	 * and IRQ gates are not the home's fault; counting them sent stage
	 * threads cold on 11.4% of all wakes (probe 2026-09-02). */
	/* §G81: a stage-class wakee (burst >= SEAT_BURST_MIN_NS) keeps its warm
	 * home even on a SYNC wake: its own predictor and L1 outweigh the
	 * waker's line at that burst length (hd_sync 31k/30 s, GameThread
	 * 8,835 migrations vs 1.1.3's 650). */
	home_askable = (!(wake_flags & CAKE_WAKE_SYNC) ||
			(cake_tog_g81 && cake_burst_ns(p) >= SEAT_BURST_MIN_NS)) &&
		       prev_cpu >= 0 &&
		       !cake_starved_turn(p) && !cake_cpu_irq_bad(prev_cpu) &&
		       bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr);
	if (home_askable && !cake_core_contended(prev_cpu) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		if (gr)
			gr->home_miss = 0;
		{	/* PROBE: is the claimed CPU actually running someone? */
			struct task_struct *hc = cake_cpu_curr(prev_cpu);
			u32 me = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

			if (hc && hc->pid) {
				cake_stat_inc(CAKE_STAT_HOME_BUSY);
				cake_probe_busy_flag[me] = 1;
			}
			if (scx_bpf_dsq_nr_queued(CAKE_DSQ_LOCAL_ON | (u32)prev_cpu) > 0)
				cake_stat_inc(CAKE_STAT_HOME_LOCALQ);
		}
		cake_direct_clamp(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)prev_cpu,
				cake_task_slice_cached(p), 0);
		cake_stat_inc(CAKE_STAT_HOME);
		return prev_cpu;
	}
	if (gr && home_askable && gr->home_miss < GROOVE_HOME_MISS)
		gr->home_miss++;
skip_home:


	/* §G69: claimed warm placement or the pool; nothing unclaimed below. */
	if (cake_tog_g69) {
		s32 c;

		/* §G74: the one stacking that is worth it. The warm prev CPU is
		 * busy, but its occupant published (§G57) that it frees within
		 * STACK_TOLERANCE_NS and nothing is queued there: queue the wakee
		 * in prev's OWN visible queue (served first at the occupant's
		 * stop, stealable meanwhile) instead of a cold idle core. This is
		 * the average the unclaimed stacking used to buy, without the
		 * millisecond holds it cost. */
		if (cake_tog_g74 && prev_cpu >= 0 &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    !cake_cpu_irq_bad(prev_cpu) &&
		    cake_cpu_dsq_idle((u32)prev_cpu)) {
			u64 now = bpf_ktime_get_ns();
			u64 at = cake.run[(u32)prev_cpu & (MAX_CPUS - 1)].free_at;

			if (time_after(at, now) &&
			    at - now <= STACK_TOLERANCE_NS) {
				cake_qmark_set((u32)prev_cpu);
				cake_dsq_insert_vtime(p, (u64)(u32)prev_cpu,
						      cake_task_slice_cached(p),
						      cake_wake_vtime(p),
						      CAKE_ENQ_WAKEUP);
				return prev_cpu;
			}
		}
		c = cake_claim_warm(p, gr ? (s32)gr->last_win - 1 : -1);
		if (gr && c >= 0)
			gr->last_win = (s16)(c + 1);

		if (c >= 0) {
			cake_direct_clamp(p);
			cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)c,
					cake_task_slice_cached(p), 0);
			return c;
		}
		return prev_cpu;	/* enqueue routes it (pool with g65) */
	}

	/*
	 * Self-park consumer (§G54): the decision was computed at idle-entry
	 * by the idle CPU itself; this reads it. Warmth-first — the combined
	 * pair with the walk ahead of this block re-priced §G53's tails.
	 */
	/* §G67: the only direct placement is the claimed warm home above;
	 * the unclaimed census paths (park, first-fit) stack a second wake
	 * onto a CPU whose first wake is still in flight. Everything else is
	 * pooled, visible, kicked. */
	if (cake_idle_count() && !cake_tog_g67) {
		s32 ocpu;

		cake_stat_inc(CAKE_STAT_PARK_REACHED);
		ocpu = cake_park_take(p, prev_cpu);
		if (ocpu >= 0)
			return ocpu;
	}

	/*
	 * Optimistic placement probe (§G53): EEVDF's shape — first affine
	 * census bit, place, no gates, no consuming claim. A collision costs
	 * one occupant wait, exactly what EEVDF accepts; the verify step was
	 * where §G48/§G50 spent more than they saved. With §G54 on, this is
	 * the mailbox-miss fallback.
	 */
	if (!cake_tog_g67) {
		s32 ocpu;

		cake_stat_inc(CAKE_STAT_OPT_REACHED);
		ocpu = cake_optimistic_place(p);
		if (ocpu >= 0) {
			cake_stat_inc(CAKE_STAT_OPT_HIT);
			return ocpu;
		}
	}

	/*
	 * First-choice placement runs dfl's ranking against the nonsink set,
	 * so a sink is claimed only when nothing quieter is idle -- the
	 * fallback ranks the whole machine and its claim is always the CPU
	 * returned, never abandoned (§G23).
	 */
	{
		u32 sgen = cake_sink_gen;
		const struct cpumask *ns;

		cake_stat_inc(CAKE_STAT_RANKED);

		/* One predictable compare catches a sink republish (§G30). */
		if (sgen != nonsink_gen)
			cake_nonsink_rebuild(sgen);
		ns = cast_mask(nonsink_cpumask);

		cpu = -1;
		/*
		 * Zero-skip (§G50): the census says nothing is idle, so both
		 * scans can only fail; a stale zero costs one queued wake,
		 * healed by the enqueue-side kick.
		 */
		if (!cake_idle_count())
			ns = NULL;
		if (ns && __COMPAT_HAS_scx_bpf_select_cpu_and)
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
						     ns, 0);
	}
	if (cpu >= 0)
		is_idle = true;
	else if (!cake_idle_count() &&
		 bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		cpu = prev_cpu;
	else
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		/*
		 * Distrust a WAKE_SYNC return of the waker's own CPU: it can be
		 * the waker's still-BUSY CPU, and taking it welds buffered
		 * pairs together permanently (§R.6). Re-rank without the SYNC
		 * flag.
		 */
		if ((wake_flags & CAKE_WAKE_SYNC) &&
		    cpu == (s32)bpf_get_smp_processor_id()) {
			const struct cpumask *ns = cast_mask(nonsink_cpumask);
			s32 idle;

			if (ns && __COMPAT_HAS_scx_bpf_select_cpu_and)
				idle = scx_bpf_select_cpu_and(p, prev_cpu, 0,
							      ns, 0);
			else
				idle = cake_pick_idle_escape(p);
			if (idle >= 0)
				cpu = idle;
		}

		/*
		 * The claimed CPU can be mid-handler at this instant -- the
		 * chronic mask cannot see a timer tick or a stray IRQ on a
		 * quiet CPU (§G35). One retry; the alternative must beat the
		 * original on BOTH truths, and when nothing quieter is idle
		 * the claim stands: an idle CPU behind a microsecond handler
		 * still beats queueing.
		 */
		if (cake_irq_live[(u32)cpu & (MAX_CPUS - 1)].depth ||
		    cake_cpu_tick_soon(cpu)) {
			s32 alt = cake_pick_idle_escape(p);

			if (alt >= 0 && cake_cpu_clean(alt))
				cpu = alt;
		}

		/*
		 * Ordered direct admission: confirm the qmark hint with one
		 * lockless head snapshot so the shortcut cannot jump an older
		 * claim. Advisory, not a reservation (§R.4).
		 */
		if ((wake_flags & CAKE_WAKE_SYNC) &&
		    cake_qmark_test((u32)cpu)) {
			struct task_struct *head;

			head = cake_dsq_peek((u64)(u32)cpu);
			if (head) {
				u64 head_vtime = head->scx.dsq_vtime;

				if (time_before(head_vtime, cake_wake_vtime(p)))
					return cpu;
			}
		}
		cake_direct_clamp(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL,
				cake_task_slice_cached(p), 0);
		return cpu;
	}

	/*
	 * Saturated handoff convergence on the callback CPU, whose queue state
	 * is authoritative: an explicit WAKE_SYNC handoff, or a wakee whose raw
	 * vtime proves it slept behind the frontier. A frontier-running compute
	 * peer keeps dfl's prev placement instead. Returning the CPU rather than
	 * direct-dispatching keeps live-vtime eligibility (§R.20).
	 */
	if ((wake_flags & CAKE_WAKE_SYNC) ||
	    time_before(p->scx.dsq_vtime + (SLICE_NS >> 1),
			cake.frontier.word)) {
		s32 waker_cpu = (s32)bpf_get_smp_processor_id();

		/* Same sink veto as the serial block (§G30, §G35). */
		if (!cake_cpu_irq_bad(waker_cpu) &&
		    bpf_cpumask_test_cpu(waker_cpu, p->cpus_ptr) &&
		    !cake_local_nr(waker_cpu) &&
		    cake_cpu_dsq_idle((u32)waker_cpu))
			return waker_cpu;
	}

	return cpu;
}

/* Claim the published going-idle CPU: the hint must pass every gate the
 * scan enforces -- §G30/§G33/§G35/§G36 cleanliness and the §G38 whole-core
 * preference -- so a hit changes cost, never ranking. The test-and-clear is
 * the verify AND the claim; the CAS retires our snapshot only, so a newer
 * publish survives. An affinity miss leaves the hint for other tasks (§G43). */
static __noinline s32 cake_idle_hint_claim(struct task_struct *p __arg_trusted)
{
	u64 h;
	bool claimed;
	s32 cpu;

	h = cake.idle_hint.word;
	if (!h)
		return -1;
	cpu = (s32)(u32)(h - 1);
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return -1;
	if (!cake_cpu_clean(cpu) || cake_core_contended(cpu))
		return -1;

	claimed = scx_bpf_test_and_clear_cpu_idle(cpu);
	(void)__sync_val_compare_and_swap(&cake.idle_hint.word, h, 0);
	return claimed ? cpu : -1;
}

/* Idle pick with one retry away from a bad target (§G30, §G35): prefer a
 * CPU that is neither chronically loud nor mid-handler; when only a bad one
 * is idle it still wins -- any CPU beats queueing. */
static __noinline s32 cake_pick_idle_clean(struct task_struct *p __arg_trusted)
{
	/* The hint short-circuits the scans; a miss costs one word read (§G43). */
	s32 cpu = cake_idle_hint_claim(p);

	if (cpu >= 0)
		return cpu;

	/* A whole idle core beats an idle thread beside a running one, and the
	 * flag costs nothing when no core is free (§G38). */
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, CAKE_PICK_IDLE_CORE);

	if (cpu < 0)
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

	if (cpu >= 0 && !cake_cpu_clean(cpu)) {
		s32 alt = cake_pick_idle_escape(p);

		if (alt >= 0 && cake_cpu_clean(alt))
			cpu = alt;
	}
	return cpu;
}

/* The wake routing decision: three reachable states, one value (§R.11). */
enum cake_route { ROUTE_GLOBAL = 0, ROUTE_HOME_QUEUE, ROUTE_HOME_CLAIM };

/*
 * Post-insert notification: tell somebody the task is runnable. The task is
 * already published, so only p, tcpu and the route cross this boundary — which
 * is what makes the cut cheap (§R.11).
 */
__noinline s32 cake_wake_notify(struct task_struct *p __arg_trusted, s32 tcpu,
				 u32 route)
{
	s32 idle;

	if (route == ROUTE_HOME_CLAIM && cake_home_notify(p, tcpu))
		return 0;


	/* §G39-B': a home-routed wakee sits in tcpu's own local queue, which
	 * no other CPU may serve -- the census (run 20260831) shows the idle
	 * kick firing here while the wakee still waits out the occupant's
	 * whole slice. The notification tcpu owes is a preempt attempt; a
	 * decline falls through to today's flow unchanged. */
	if (cake_tog_g39b && route != ROUTE_GLOBAL &&
	    cake_wake_preempt(p, tcpu, PREEMPT_PROTECT_SHIFT))
		return 0;

	idle = cake_pick_idle_clean(p);
	if (idle >= 0) {
		scx_bpf_kick_cpu(idle, CAKE_KICK_IDLE);
		return 0;
	}

	/* An idle SMT sibling keeps globally queued cold pickup on a warm core.
	 * Ranked BELOW a clean idle pick: the sibling shares the core with a
	 * runner, and that costs more than the L2 it saves (§G38). */
	if (route == ROUTE_GLOBAL) {
		s32 sib = cpu_sibling[(u32)tcpu & (MAX_CPUS - 1)];

		if (sib >= 0 && cake_cpu_clean(sib) &&
		    bpf_cpumask_test_cpu(sib, p->cpus_ptr) &&
		    scx_bpf_test_and_clear_cpu_idle(sib)) {
			scx_bpf_kick_cpu(sib, CAKE_KICK_IDLE);
			return 0;
		}
	}

	/*
	 * No idle CPU anywhere, and every route still owes tcpu a decision:
	 * either the occupant loses the CPU, or the wakee waits because the
	 * occupant genuinely deserves it. Cake registers no .tick, so an arm
	 * that decides neither leaves the wakee on the 5 s watchdog (§R.14).
	 */
	if (cake_wake_preempt(p, tcpu, PREEMPT_PROTECT_SHIFT))
		return 0;

	/*
	 * Globally queued only: hunt a mid-slice compute occupant among the
	 * neighbours. A home-routed wake stays put -- stealing it back off the
	 * queue would spend the locality the routing just bought.
	 */
	if (route != ROUTE_HOME_CLAIM) {
		u32 cand = (u32)tcpu;
		u32 pi;

		for (pi = 0; pi < CAKE_NEIGHBOUR_PROBE_DEPTH; pi++) {
			cand++;
			if (cand >= nr_cpu_span)
				cand = 0;
			if (!bpf_cpumask_test_cpu((s32)cand, p->cpus_ptr))
				continue;
			if (cake_wake_preempt(p, (s32)cand,
					       PROBE_PROTECT_SHIFT))
				break;
		}
	}
	return 0;
}

/*
 * Does this wake CLAIM its empty home, or merely queue there? A claim earns a
 * preempt; a mere queue takes prev-CPU warmth without one. Two frontier-running
 * compute peers must never claim the same CPU -- cake has no periodic balancer,
 * so they would mutually preempt forever (§R.2).
 *
 * The claims run cheapest first: the wakee is a sleeper (arithmetic on values
 * already in hand), the home is idle-owned, or the occupant is a valve about to
 * block (a clock read plus weight scaling, so it goes last).
 */
static __noinline bool cake_home_claim(struct task_struct *p __arg_trusted,
				       s32 tcpu)
{
	u64 vs = SLICE_NS;
	u64 lo = cake.frontier.word - vs;
	u64 ran = 0, live;

	/*
	 * The converged-pair claim is DELETED here: routing its traffic global
	 * cost futex 4.8M -> 0.98M, and it is UNMEASURED since (§R.19).
	 */
	if ((s64)(p->scx.dsq_vtime - lo) < (s64)(vs >> 1))
		return true;

	live = cake_occupant_live(tcpu, &ran);
	if (!live)
		return true;

	return time_before(live, cake.frontier.word - vs);
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
	bool empty_home;
	u32 route;

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
				      cake_task_slice_cached(p),
				      cake_wake_vtime(p), CAKE_ENQ_WAKEUP);
		return 0;
	}

	/*
	 * M8: an RT-owned CPU is never an empty home. It may burst again and
	 * the kernel preempts SCX for it unconditionally; EEVDF discounts such
	 * a CPU's capacity by its RT/DL load average and sched_ext's idle
	 * tracking has no equivalent, so approximate it here (§R.14).
	 */
	empty_home = !(curr && (curr->policy == SCHED_FIFO ||
				curr->policy == SCHED_RR ||
				curr->policy == SCHED_DEADLINE)) &&
		     cake_cpu_dsq_idle((u32)tcpu);

	route = empty_home ? ROUTE_HOME_QUEUE : ROUTE_GLOBAL;
	if (empty_home && cake_home_claim(p, tcpu))
		route = ROUTE_HOME_CLAIM;

	/*
	 * An already-backlogged global queue is the oversubscription
	 * signature: scattering one more wake buys nothing, it lands cold and
	 * splits its pair (the t32/t64 herd collapse). Probed lazily, so an
	 * empty home never pays for the signal.
	 */
	if (route == ROUTE_GLOBAL && scx_bpf_dsq_nr_queued((u64)WAKE_DSQ))
		route = ROUTE_HOME_QUEUE;
	if (cake_tog_g63 || cake_tog_g65)
		route = ROUTE_GLOBAL;	/* §G63/§G65: the pool, always */
	if (cake_vip(p) && route) {
		struct task_struct *oc = cake_cpu_curr(tcpu);

		if (oc && oc->pid && !cake_vip(oc))
			cake_kick_preempt(tcpu);
	}

	if (route)
		cake_qmark_set((u32)tcpu);
	/*
	 * The wake bit as a literal, not the caller's enq_flags: a PRIQ insert
	 * into a custom DSQ reads none of the caller's positional bits (§R.5).
	 */
	cake_dsq_insert_vtime(p,
			      route ? (u64)(u32)tcpu : (u64)WAKE_DSQ,
			      cake_task_slice_cached(p), cake_wake_vtime(p),
			      CAKE_ENQ_WAKEUP);
	/* AFTER the insert — the §G41 ordering half; qmask marks before
	 * because its owner's rescan makes a stale clear benign. */
	if (!route)
		cake_wake_mark_set();

	cake_wake_notify(p, tcpu, route);
	return 0;
}

/*
 * Pinned-wake service. A pinned user task's wake lands on the continuation
 * path because nr_cpus_allowed == 1, and NO other CPU may steal it, so without
 * this it waits out the occupant's whole slice. Preempts by RAW sleep depth
 * @d, which must be read before the insert rewrites p->scx.dsq_vtime (§R.14).
 */
static __noinline void cake_pinned_wake_preempt(struct task_struct *p __arg_trusted,
						s32 tcpu, u64 d)
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

	if (time_before(pvt + (vs >> 1), clive))
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
	u64 lo, d;
	s32 idle;

	/*
	 * Kernel-thread wakes go straight to the selected CPU's local DSQ, so
	 * essential softirq/workqueue service is bounded by one occupant slice
	 * rather than herd order — the scx watchdog itself rides unbound
	 * kworkers. PF_KTHREAD is scheduling state, not workload identity. Only
	 * the wake takes this path; a continuation falls through (§R.14). An idle
	 * CPU serves it as promptly and evicts nobody (§G20).
	 */

	if ((enq_flags & CAKE_ENQ_WAKEUP) && (p->flags & PF_KTHREAD)) {
		s32 kcpu = cake_pick_idle_clean(p);

		cake_direct_clamp(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON |
				   (u32)(kcpu >= 0 ? kcpu : tcpu),
				   SLICE_NS, enq_flags);
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
	 * §G57: with nothing idle in the mask, queue behind the CPU predicted
	 * to free first rather than the home occupant. No kick is owed: the
	 * target dispatches at that moment by construction, and the ring can
	 * still lift the task earlier. Both arms below are the strand shape
	 * this replaces (§S.8 field report).
	 */
	if (cake_tog_g57 && (enq_flags & CAKE_ENQ_WAKEUP) &&
	    p->nr_cpus_allowed > 1) {
		s32 fcpu = cake_free_pick(p, tcpu);

		if (fcpu >= 0) {
			cake_stat_inc(CAKE_STAT_FREE_PICK);
			cake_qmark_set((u32)fcpu);
			cake_dsq_insert_vtime(p, (u64)(u32)fcpu,
					      cake_task_slice_cached(p),
					      cake_wake_vtime(p), enq_flags);
			return;
		}
	}

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
	 * The continuation arm. It stays on its owner's queue whatever the
	 * depth there: the mark makes it visible to the steal ring, so leaving
	 * it keeps the L1/L2 warmth it was queued for and still conserves work.
	 * A separate overflow bucket needed two catchers and stalled anyway
	 * (§R.15). The slice is the task's own, not a flat grant (§G10).
	 */
	{
		u64 vt = lo + (d & ~((u64)((s64)d >> 63)));
		struct task_struct *hc = cake_cpu_curr(tcpu);

		/*
		 * Anti-collision: home held by an equally well-served PEER. The
		 * depth-blind home rule above is right for a worker occupant,
		 * whose slice is short, and wrong for a peer, whose whole slice
		 * must be waited out while other CPUs sit idle. Reaching this
		 * arm already proves p is not turn-starved, so only the
		 * occupant needs testing (§G17).
		 */
		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1 &&
		    hc && !(hc->flags & PF_IDLE) && !cake_starved(hc)) {
			cake_dsq_insert_vtime(p, (u64)WAKE_DSQ,
					      cake_task_slice_cached(p),
					      cake_wake_vtime(p), enq_flags);
			cake_wake_mark_set();	/* after the insert (§G41) */
			goto kick_idle;
		}

		cake_qmark_set((u32)tcpu);
		cake_dsq_insert_vtime(p, (u64)(u32)tcpu,
				      cake_task_slice_cached(p),
					 vt, enq_flags);

		/* §G39-B' iteration 2: the continuation arm is where the wine
		 * RPC chain actually waits (census run 20260831: starved_turn
		 * false, enqueue_wake never reached). A local insert behind a
		 * live occupant owes tcpu a preempt attempt; a decline keeps
		 * today's flow. The pinned shape below already had its own. */
		if (cake_tog_g39b && (enq_flags & CAKE_ENQ_WAKEUP) &&
		    p->nr_cpus_allowed > 1)
			cake_wake_preempt(p, tcpu, PREEMPT_PROTECT_SHIFT);

		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed == 1)
			cake_pinned_wake_preempt(p, tcpu, d);
	}

kick_idle:

	idle = cake_pick_idle_clean(p);
	if (idle >= 0)
		scx_bpf_kick_cpu(idle, CAKE_KICK_IDLE);
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
/*
 * §G56 FOLD. Each band is qmask AND LLC-membership: every queued CPU in the
 * band answers from two words, and find-first-set jumps straight to the
 * victim — no element walk. Bands run own-LLC first, then foreign LLCs in
 * loader order (§G52 rank-descending when live). The stagger splits the word
 * at the caller's own id — bits >= self first, then wrap — with a mask and
 * two ctz, NOT the §G25-rejected rotate.
 */
static __noinline bool cake_band_steal(u32 ucpu)
{
	u32 home = cake_cpu_llc[ucpu & (MAX_CPUS - 1)] & (MAX_LLCS - 1);
	u32 r = ucpu & 63;
	u32 b, k;

	for (b = 0; b < MAX_LLCS; b++) {
		u64 m;

		if (b >= cake_nr_llcs)
			break;
		m = cake.qmask[0] &
		    cake_llc_qword[cake_llc_order[home][b] & (MAX_LLCS - 1)];
		m &= ~(1ULL << r);	/* never probe ourselves */

		for (k = 0; k < 64; k++) {
			u64 hi = m & (~0ULL << r);
			u64 pick = hi ? hi : m;
			u32 idx;

			if (!pick)
				break;
			idx = (u32)__builtin_ctzll(pick);
			if (cake_move_to_local((u64)idx))
				return true;
			m &= ~(1ULL << (idx & 63));
		}
	}
	return false;
}

static __noinline bool cake_ring_steal(u32 ucpu)
{
	u32 nr = nr_cpu_span;
	u32 cw = (u32)-1;	/* which qmask word `m` holds; none yet */
	u64 m = 0;
	u32 i;

	if (cake_tog_g56 && nr_cpu_span <= 64)
		return cake_band_steal(ucpu);
	/* §G77: nothing marked anywhere is one word read, not a ring walk. */
	if (cake_tog_g77 && nr_cpu_span <= 64 &&
	    !(cake.qmask[0] & ~(1ULL << (ucpu & 63))))
		return false;

	if (CCD_STEAL_POLICY > 0 && steal_order_live && ucpu < STEAL_SPAN) {
		/* One precomputed locality order avoids verifier-multiplying
		 * scan loops. */
		for (i = 0; i < STEAL_SPAN; i++) {
			u32 idx;

			if (i + 1 >= nr)
				break;
			idx = cpu_steal_order[ucpu * STEAL_SPAN + i];
			if (cake_qmark_test(idx) &&
			    cake_move_to_local((u64)idx))
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
		if (cake_move_to_local((u64)idx))
			return true;
	}

	return false;
}

/* Has the global wake queue gone unserved for a full WALL-clock window? */
static __noinline bool cake_wake_starved(void)
{
	return time_before(cake.wake_served.word + WAKE_STARVE_WALL_NS,
			   bpf_ktime_get_ns());
}

/* Record that someone served the global wake queue. */
static __noinline void cake_wake_serve_stamp(void)
{
	cake.wake_served.word = bpf_ktime_get_ns();
}

/*
 * An EMPTY wake queue is a SERVED wake queue — without this the escalation is
 * permanently armed in any regime where wakes mostly route home. Refreshed
 * only once the stamp is already half a window old, because every CPU's
 * dispatch polls this line and an unconditional store would cost an RFO at
 * context-switch rate (§R.16).
 */
static __noinline void cake_wake_idle_stamp(void)
{
	u64 now = bpf_ktime_get_ns();

	if (time_before(cake.wake_served.word + WAKE_STARVE_REFRESH_NS, now))
		cake.wake_served.word = now;
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
	u64 first = (u64)ucpu, second = (u64)WAKE_DSQ;
	struct task_struct *own, *wake;

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
		u32 own_n = (u32)scx_bpf_dsq_nr_queued((u64)ucpu);
		u32 wake_n;

		own = own_n ? cake_dsq_peek((u64)ucpu) : NULL;
		/* Marks and the empty test come from scalars: a pointer-to-bool
		 * or a pointer pair test lowers to an OR the verifier refuses. */
		cake_qmark_publish(ucpu, own_n != 0);
		/* The pool by its COUNT, not the mark: the mark has the holes the
		 * unconditional second move used to heal (§G41), and trusting it
		 * here stalled the game 20 ms. Two counts replace two iterators and
		 * two blind moves on the empty path. */
		wake_n = (u32)scx_bpf_dsq_nr_queued((u64)WAKE_DSQ);
		if (wake_n)
			cake.wake_mark.word = 1;
		wake = wake_n ? cake_dsq_peek((u64)WAKE_DSQ) : NULL;
		if (!wake_n) {
			if (!own_n)
				return cake_ring_steal(ucpu);
			/* an empty pool is served: the starvation clock only
			 * matters when the own queue competes with it */
			cake_wake_idle_stamp();
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
		    cake_wake_starved()) {
			first  = (u64)WAKE_DSQ;
			second = (u64)ucpu;
		}
	}
	if (cake_move_to_local(first)) {
		if (first == (u64)WAKE_DSQ)
			cake_wake_serve_stamp();
		return true;
	}
	/* Unconditional: a second healing net under a lost mark, and a
	 * peek-guard here measured 5 spills against this shape's 0 (§G41). */
	if (cake_move_to_local(second)) {
		if (second == (u64)WAKE_DSQ)
			cake_wake_serve_stamp();
		return true;
	}

	return cake_ring_steal(ucpu);
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

	/*
	 * Going idle: publish this CPU as the wake path's one-load idle
	 * candidate. Freshest publisher wins; test before write (§G43, §R.10).
	 */
	{
		u64 hint = (u64)(u32)cpu + 1;

		if (cake.idle_hint.word != hint)
			cake.idle_hint.word = hint;
	}
}

/*
 * §G58 frame pre-wake. A display-coupled thread blocks with a known cycle,
 * so its next wake is a prediction, not a surprise: one timer per CPU,
 * armed at block time for the predicted wake minus the lead. The callback
 * reserves the CPU for that pid and kicks it out of idle, so the wake finds
 * a core already awake and held. A miss costs one idle kick and one unused
 * reservation window; nothing is ever queued or preempted on a prediction.
 */
struct cake_prewake {
	struct bpf_timer timer;
	u64 pid;
	u64 cpu;
	u64 window;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, struct cake_prewake);
} cake_prewake_map SEC(".maps");

static int cake_prewake_fire(void *map, void *key, void *value)
{
	struct cake_prewake *pw = value;
	u32 c = (u32)pw->cpu & (MAX_CPUS - 1);
	struct cake_run_slot *rs = &cake.run[c];

	/* Busy now: the prediction found a running CPU; nothing to hold. */
	if (!((cake_idle_words[c >> 6] >> (c & 63)) & 1))
		return 0;
	cake_stat_inc(CAKE_STAT_PREWAKE_FIRE);
	rs->reserved_pid = pw->pid;
	rs->reserved_until = bpf_ktime_get_ns() + pw->window;
	scx_bpf_kick_cpu((s32)c, CAKE_KICK_IDLE);
	return 0;
}

/*
 * The arm half, from stopping on a block. Same vote gate as the frame
 * clock (a thread that sleeps most of its life), raw cycle inside the
 * engine band, then next wake = this wake + cycle, less what already ran.
 * A cycle shorter than the lead cannot be pre-woken and is left alone.
 */
static __noinline void cake_prewake_arm(struct task_struct *p __arg_trusted,
					u64 used)
{
	u64 now = bpf_ktime_get_ns();
	u64 n = p->nvcsw | 1;
	u64 delta = now - p->start_time;
	struct cake_prewake *pw;
	u64 per, delay;
	u32 c;

	if ((p->se.sum_exec_runtime << 1) >= delta)
		return;
	if (!(n >> 32) &&
	    (delta < FRAME_PERIOD_MIN_NS * n ||
	     delta >= (FRAME_PERIOD_MAX_NS + 1) * n))
		return;
	per = delta / n;
	if (per < FRAME_PERIOD_MIN_NS || per > FRAME_PERIOD_MAX_NS)
		return;
	/*
	 * Only the published frame cadence arms a timer: the argmax bucket the
	 * loader elected, so a desktop full of 60 Hz sleepers does not become
	 * a kick storm when the game runs at another rate. No clock, no arm.
	 */
	if (!cake_frame_ns ||
	    (per >> FRAME_BUCKET_SHIFT) != (cake_frame_ns >> FRAME_BUCKET_SHIFT))
		return;
	if (per <= used + cake_prewake_lead_ns)
		return;
	delay = per - used - cake_prewake_lead_ns;

	c = (u32)p->thread_info.cpu & (MAX_CPUS - 1);
	pw = bpf_map_lookup_elem(&cake_prewake_map, &c);
	if (!pw)
		return;
	pw->pid = (u64)(u32)p->pid;
	pw->cpu = c;
	pw->window = per >> PREWAKE_WINDOW_SHIFT;
	if (pw->window < cake_prewake_lead_ns * PREWAKE_WINDOW_MULT)
		pw->window = cake_prewake_lead_ns * PREWAKE_WINDOW_MULT;
	bpf_timer_start(&pw->timer, delay, 0);
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
	u64 now = bpf_ktime_get_ns();

	run->stamp = now;
	run->sum = p->se.sum_exec_runtime;
	if (cake_tog_g79 && (cpu & (MAX_CPUS - 1)) < 64 &&
	    (cake_seat_word >> (cpu & 63)) & 1)
		__atomic_fetch_and(&cake_seat_word, ~(1ULL << (cpu & 63)),
				   __ATOMIC_RELAXED);
	cake_probe_run(p, now);

	/*
	 * §G57: the grant is twice the burst when uncapped, so half of it is
	 * the burst estimate with no divide; a capped grant still ends at the
	 * slice, so the estimate never lands after the CPU's next dispatch.
	 */
	if (cake_tog_g57 || cake_tog_g74)
		run->free_at = now + (p->scx.slice >> 1);

	/* Occupant mirror publish (§M6): the line is already dirty here. */
	if (cake_tog_m6) {
		run->mirror_vtime = task_vtime;
		run->occupant = ((u64)(u32)p->pid << 32) |
				(cake_recip_index(p) & 0xff);
	}

	cake_frame_observe(p, now);

	if (time_before(cake.frontier.word, task_vtime))
		cake.frontier.word = task_vtime;
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

	/* Mirror retire (§M6): zero = off-mirror until the next running. */
	if (cake_tog_m6)
		rs->occupant = 0;

	/* §G79: a blocking stage keeps its seat. */
	if (cake_tog_g79 && !runnable && (cpu & (MAX_CPUS - 1)) < 64 &&
	    cake_burst_ns(p) >= SEAT_BURST_MIN_NS)
		__atomic_fetch_or(&cake_seat_word, 1ULL << (cpu & 63),
				  __ATOMIC_RELAXED);

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

	if (cake_tog_g46)
		cake_slice_publish(p);
	if (cake_tog_g58 && !runnable)
		cake_prewake_arm(p, used);
}

/*
 * ops.update_idle — the §G45 census. KEEP_BUILTIN_IDLE preserves the kernel
 * tracking every pick still uses; this only mirrors it into one word.
 */
void BPF_STRUCT_OPS(cake_update_idle, s32 cpu, bool idle)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);
	u64 bit = 1ULL << (c & 63);

	if (idle) {
		/* §G82: one census word (the counter is wide hosts only), one
		 * core word set only when the sibling's bit is already up. Two
		 * siblings idling in the same instant can each miss the other
		 * and leave the core half-marked until either transitions again;
		 * the kernel accepts the same race on its own smt mask, and the
		 * idle claim still gates every placement. */
		if (!(cake_idle_words[c >> 6] & bit)) {
			__atomic_fetch_or(&cake_idle_words[c >> 6], bit,
					  __ATOMIC_RELAXED);
			if (nr_cpu_span > 64)
				__atomic_fetch_add(&cake_idle_nr, 1,
						   __ATOMIC_RELAXED);
		}
		if (cake_tog_g71 && c < 64) {
			s32 sib = cpu_sibling[c];

			if (sib < 0) {
				__atomic_fetch_or(&cake_core_free, bit, __ATOMIC_RELEASE);
			} else if ((u32)sib < 64 &&
				   (cake_idle_words[0] >> ((u32)sib & 63)) & 1) {
				/* the sibling is idle AND still unclaimed: both
				 * halves become whole cores */
				__atomic_fetch_or(&cake_core_free,
						  bit | (1ULL << ((u32)sib & 63)),
						  __ATOMIC_RELEASE);
			}
		}
		/*
		 * Self-park (§G54): gates run HERE, on the idle CPU, about
		 * itself, with local reads — the waker inherits a pre-gated
		 * answer. Rotor spreads parkers across waker mailboxes; an
		 * occupied slot skips one forward, then gives up (the census
		 * still names this CPU for the fallback ladder). Its consumer,
		 * cake_park_take, is reachable only off §G69 (§G82).
		 */
		if (!cake_tog_g69 && !cake_cpu_irq_bad(cpu) &&
		    !cake_cpu_tick_soon(cpu)) {
			u32 r = (u32)__atomic_fetch_add(&cake_park_rotor, 1,
							__ATOMIC_RELAXED);
			s32 sib = cpu_sibling[c];
			u64 entry = (u64)c + 1;
			u32 i;

			/* A whole idle core is the premium offer (§G38),
			 * judged here with idle-time reads. */
			if (sib < 0 ||
			    (cake_idle_words[((u32)sib & (MAX_CPUS - 1)) >> 6]
			     >> ((u32)sib & 63)) & 1)
				entry |= CAKE_PARK_CORE;
			for (i = 0; i < 2; i++) {
				u32 slot = (r + i) & cake_span_mask;
				u64 cur;

				if (slot >= nr_cpu_span)
					continue;
				slot = cake_core_slot(slot);
				cur = cake_mailbox[slot].word;
				if (!cur || ((entry & CAKE_PARK_CORE) &&
					     !(cur & CAKE_PARK_CORE))) {
					cake_mailbox[slot].word = entry;
					cake_irq_live[c].park = slot + 1;
					break;
				}
			}
		}
	} else {
		/* §G82: the thread bit goes first, so a sibling idling behind
		 * this exit reads a busy core; the core word pays an atomic only
		 * when it holds a bit. */
		if (cake_idle_words[c >> 6] & bit) {
			__atomic_fetch_and(&cake_idle_words[c >> 6], ~bit,
					   __ATOMIC_RELAXED);
			if (nr_cpu_span > 64)
				__atomic_fetch_sub(&cake_idle_nr, 1,
						   __ATOMIC_RELAXED);
		}
		if (cake_tog_g71 && c < 64) {
			s32 sib = cpu_sibling[c];
			u64 clear = bit;

			if (sib >= 0 && (u32)sib < 64)
				clear |= 1ULL << ((u32)sib & 63);
			if (cake_core_free & clear)
				__atomic_fetch_and(&cake_core_free, ~clear,
						   __ATOMIC_RELEASE);
		}
		/* Retract (§G54): only our own entry; a raced consumer has
		 * already taken it, and losing that race is benign. Off §G69
		 * only, with its producer (§G82). */
		if (!cake_tog_g69) {
			u32 park = cake_irq_live[c].park;

			if (park) {
				u32 slot = (park - 1) & (MAX_CPUS - 1);

				if ((cake_mailbox[slot].word &
				     ~CAKE_PARK_CORE) == (u64)c + 1)
					cake_mailbox[slot].word = 0;
				cake_irq_live[c].park = 0;
			}
		}
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
	ret = scx_bpf_create_dsq(WAKE_DSQ, -1);
	if (ret)
		return ret;

	/* §G58: one timer per CPU, initialised here as scx_layered does. */
	if (cake_tog_g58) {
		bpf_for(i, 0, nr) {
			u32 k = (u32)i;
			struct cake_prewake *pw =
				bpf_map_lookup_elem(&cake_prewake_map, &k);

			if (!pw)
				return -ENOENT;
			ret = bpf_timer_init(&pw->timer, &cake_prewake_map,
					     CLOCK_MONOTONIC);
			if (ret)
				return ret;
			ret = bpf_timer_set_callback(&pw->timer,
						     cake_prewake_fire);
			if (ret)
				return ret;
		}
	}

	/* Seed the §G45 census; every later transition corrects it. */
	{
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
		if (nr_cpu_span > 64)
			cake_idle_nr = n;
	}

	return cake_nonsink_rebuild(cake_sink_gen);
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
	       .running		= (void *)cake_running,
	       .stopping	= (void *)cake_stopping,
	       .update_idle	= (void *)cake_update_idle,
	       .enable		= (void *)cake_enable,
	       .init		= (void *)cake_init,
	       .exit		= (void *)cake_exit,
	       .flags		= SCX_OPS_ALLOW_QUEUED_WAKEUP |
				  SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms	= WATCHDOG_TIMEOUT_MS,
	       .name		= "cake");
