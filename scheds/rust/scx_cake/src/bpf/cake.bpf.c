/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake — a clean-slate sched_ext scheduler.
 *
 * One master algorithm, eight callbacks, built entirely on kernel primitives.
 * No feature flags, no build variants, no runtime telemetry, no volatile, no
 * attributes, no division. See DESIGN.md for the full rationale.
 *
 * Model of operation
 * ------------------
 *   - Placement is a single kfunc: scx_bpf_select_cpu_dfl(). It already
 *     computes the saturation tiers we want (idle full core, then idle SMT
 *     sibling, then "saturated") while preserving prev-CPU cache warmth,
 *     WAKE_SYNC, and LLC locality. When it hands back an idle CPU we
 *     direct-dispatch; otherwise the task falls through to ops.enqueue().
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
 * All mutable hot state in ONE BSS struct built from 128-byte-stride slots;
 * only .word of each slot is ever accessed. This replaces the former
 * __attribute__((aligned(64))) uses with pure layout: any two accessed words
 * are >= 128 bytes apart in offset, so regardless of the struct's base
 * alignment their 64B line indexes differ by >= 2 — never the same cache
 * line, and never the same adjacent-line-prefetcher 128B pair.
 */
struct cake_slot {
	u64 word;
	u64 pad[15];		/* sizeof == 128 */
};

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
	 * .word = per-CPU run-start ns. Written and read ONLY by CPU i: a
	 * stamp is charged on the same CPU that wrote it, so the 128B stride
	 * means zero cross-CPU traffic on the context-switch path.
	 */
	struct cake_slot stamp[MAX_CPUS];
	/*
	 * .word = per-CPU sum_exec_runtime snapshot taken in running().
	 * ops.stopping charges used = p->se.sum_exec_runtime - this, with
	 * ZERO clock reads: the kernel calls update_curr_scx() immediately
	 * before invoking ops.stopping (both call sites, verified in the
	 * tree), so sum_exec is boundary-exact there — unlike mid-slice
	 * remote reads, which stay on the ktime stamp above for
	 * eligibility. Owner-only, same 128B-stride isolation as stamp.
	 */
	struct cake_slot sum[MAX_CPUS];
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
	struct cake_slot qmark[MAX_CPUS];
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

/*
 * Reciprocal-weight table for division-free vtime charging.
 *
 *   recip_weight[i] = (1024 << 20) / sched_prio_to_weight[i]
 *
 * so that `used * recip_weight[i] >> 20 == used * 1024 / weight`, i.e. the
 * EEVDF charge that advances a nice-0 task's vtime by exactly `used` and a
 * heavier (negative-nice) task's vtime proportionally slower.
 *
 * Indexed by `nice + 20 == static_prio - 100 ∈ [0, 39]`. The table is sized to
 * 64 (a power of 2) so the index masks cleanly; entries [40, 63] are
 * unreachable for scx-managed SCHED_NORMAL/BATCH/IDLE tasks (static_prio is
 * always in [100, 139]) and are padded with the lightest-weight value.
 */
static const u64 recip_weight[64] = {
	   12097,    14964,    19009,    23204,    29587, /* nice -20..-16 */
	   36830,    46174,    57404,    71827,    90109, /* nice -15..-11 */
	  112457,   140911,   176023,   218952,   274895, /* nice -10..-6  */
	  344037,   429324,   539297,   677012,   840831, /* nice  -5..-1  */
	 1048576,  1309441,  1639300,  2041334,  2538396, /* nice  +0..+4  */
	 3205199,  3947580,  4994148,  6242685,  7837531, /* nice  +5..+9  */
	 9761289, 12341860, 15339168, 19173961, 23860929, /* nice +10..+14 */
	29826161, 37025580, 46684427, 59652323, 71582788, /* nice +15..+19 */
	/* padding [40..63]: unreachable, replicate the lightest weight */
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
};

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

	if (!curr)
		return false;
	curr_vtime = curr->scx.dsq_vtime;
	if (!curr_vtime)
		return false;

	ran = bpf_ktime_get_ns() - cake.stamp[(u32)tcpu & (MAX_CPUS - 1)].word;
	if (ran < (SLICE_NS >> 3))
		return false;

	cidx = (u32)(curr->static_prio - 100) & 63;
	live = curr_vtime + ((ran * recip_weight[cidx]) >> 20);
	if (!time_before(p->scx.dsq_vtime, live))
		return false;

	scx_bpf_kick_cpu(tcpu, CAKE_KICK_PREEMPT);
	return true;
}

/*
 * ops.select_cpu — THE placement decision, one kfunc.
 *
 * If select_cpu_dfl found an idle CPU (full idle core, else idle SMT sibling)
 * we direct-dispatch to the local DSQ for lowest latency and let the kernel
 * auto-reschedule. Otherwise the system is saturated on this task's affinity:
 * return the (non-idle) CPU and let ops.enqueue() queue on its vtime DSQ.
 */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dsq_insert(p, CAKE_DSQ_LOCAL, SLICE_NS, 0);
		return cpu;
	}

	/*
	 * EEVDF sync-handoff emulation for the saturated case
	 * select_cpu_dfl refuses to cover: its WAKE_SYNC convergence
	 * requires idle CPUs to exist, so under full saturation every
	 * futex handoff fell to the global wake queue and was consumed by
	 * whichever CPU blocked first — 0.7 migrations per context switch
	 * (22M/34M) versus EEVDF's 1 per ~3000, sloshing both working sets
	 * between L2s every round trip (futex 1.0M vs native 3.1M).
	 * EEVDF's wake_affine converges a sync wake onto the waker's CPU
	 * whenever the waker is the only thing on its rq: the waker is
	 * about to block, so its CPU is where the wakee runs soonest AND
	 * warmest — the pair collapses into a same-CPU L1 ping-pong. Same
	 * gate here (waker's local and own vtime queues both provably
	 * empty), so the FIFO local insert can't starve queued vtime work
	 * — the kernel's own "unfair when oversaturated" caveat on this
	 * shape is exactly what the emptiness check rules out.
	 */
	{
		s32 waker = (s32)bpf_get_smp_processor_id();

		if (bpf_cpumask_test_cpu(waker, p->cpus_ptr) &&
		    !scx_bpf_dsq_nr_queued(CAKE_DSQ_LOCAL_ON | (u32)waker) &&
		    !scx_bpf_dsq_nr_queued((u64)(u32)waker)) {
			if (wake_flags & CAKE_WAKE_SYNC) {
				scx_bpf_dsq_insert(p,
						   CAKE_DSQ_LOCAL_ON | (u32)waker,
						   SLICE_NS, 0);
				return waker;
			}

			/*
			 * Plain-wake convergence (EEVDF's saturated shape:
			 * select_idle_cpu finds nothing -> wakee runs on the
			 * affine target, i.e. the waker's CPU). dfl already
			 * proved nothing is idle, so this only redirects the
			 * wakee from its old prev to the waker — and that
			 * difference is the whole futex gap: a split pair is
			 * SELF-SUSTAINING under prev/home stickiness, and
			 * every wake of a split pair pays cross-CPU delivery
			 * plus a preempt of some unrelated CPU's curr —
			 * wake-to-run p50 1.42us / p99 19.9us with only 68%
			 * of wakes preempting, vs native 0.27us / 2.99us at
			 * 95% (traced 2026-07-03). Returning the waker makes
			 * the activate local; enqueue then sees an empty home
			 * (just checked), inserts on the waker's own vtime
			 * queue, and the floor-less home preempt collapses
			 * the pair onto one CPU — native's 66/33 ping-pong,
			 * IPI-free, and it STAYS converged because prev ==
			 * waker from then on. Unlike the sync path above the
			 * wakee takes the ordinary vtime insert, so a
			 * non-eligible wakee waits fairly and storm shapes
			 * keep their idle-kick fallback.
			 *
			 * Gated on either side being a genuine sleeper — raw
			 * dsq_vtime more than one slice behind the frontier,
			 * exactly the tasks the enqueue sleeper clamp would
			 * boost. Ungated convergence dragged warm runners off
			 * their prev (-12.3% cpu-cache-mem, 2026-07-03); with
			 * NEITHER side a sleeper both are frontier-running
			 * compute peers (ccm, x265 pools) and the wakee keeps
			 * dfl's prev placement. A sleeper WAKEE is the futex
			 * handoff — it accrues nothing between wakes. A
			 * sleeper WAKER is a dispatcher (schbench messenger:
			 * ~10% duty) whose CPU is a relief valve: without
			 * this half, two workers sharing one CPU mutually
			 * preempt forever — cake has no periodic balancer,
			 * so the trap pair never rotates and both requests
			 * stretch 2x (p99 9072us == 2 x p50 4648us vs native
			 * 5832us, histograms 2026-07-04). The escaped wakee
			 * queues behind the ineligible sleeper-waker and runs
			 * when it blocks moments later — no preempt, no kick.
			 * Once a pair co-locates, prev == waker and the gate
			 * is moot. `current` IS the waker here: on a shared-
			 * cache box every cross-CPU wake takes the direct
			 * ttwu path, and select_task_rq always runs in the
			 * waker's context.
			 */
			if (time_before(p->scx.dsq_vtime + (SLICE_NS >> 1),
					cake.frontier.word) ||
			    time_before(bpf_get_current_task_btf()->scx.dsq_vtime +
						(SLICE_NS >> 1),
					cake.frontier.word))
				return waker;
		}
	}

	return cpu;
}

/*
 * ops.enqueue — reached only when select_cpu claimed no idle CPU.
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
	 * that premise is false — only tcpu may run it, tcpu drains its own
	 * DSQ first, and under saturation it never looks further: a pinned
	 * kworker stranded in WAKE_DSQ ate the 5s runnable-stall watchdog
	 * (stress-ng-futex, 2026-07-02). In its owner's queue the vtime
	 * order guarantees progress, and every other CPU's WAKE consume
	 * stops paying to skip over a task it can never take.
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
		u64 live = 0, ran = 0;
		bool home = false;

		bool local = (u32)tcpu == bpf_get_smp_processor_id();

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
			cake.qmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
			scx_bpf_dsq_insert_vtime(p, (u64)(u32)tcpu, SLICE_NS,
						 vt, enq_flags);
			return;
		}

		if (!scx_bpf_dsq_nr_queued((u64)(u32)tcpu)) {
			u64 cv = curr ? curr->scx.dsq_vtime : 0;

			if (!cv) {
				/*
				 * Idle-owned (or RT-owned) empty home: the
				 * CPU is free or imminently free — the best
				 * claim there is. Sending this case global
				 * was the pipe leak: a wake racing its
				 * partner's idle transition took a WAKE_DSQ
				 * insert + pick_idle + kick detour on every
				 * message. No preempt exists to fire (live
				 * stays 0).
				 */
				home = true;
			} else {
				ran = bpf_ktime_get_ns() -
				      cake.stamp[(u32)tcpu & (MAX_CPUS - 1)].word;
				u32 cidx = (u32)(curr->static_prio - 100) & 63;

				live = cv + ((ran * recip_weight[cidx]) >> 20);
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
				home = local ||
				       (s64)d < (s64)(SLICE_NS >> 1) ||
				       time_before(live, lo);
			}
		}

		if (home) {
			cake.qmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
			scx_bpf_dsq_insert_vtime(p, (u64)(u32)tcpu, SLICE_NS,
						 vt, enq_flags);
			/*
			 * Home preempt BEFORE any idle kick: a kicked-idle
			 * third party's dispatch pulled the just-inserted
			 * home wakee through the steal ring, undoing the
			 * locality. When the wakee is eligible NOW the pair
			 * collapses onto tcpu (EEVDF's wake_preempt shape) —
			 * this wake created no other runnable work, and any
			 * CPU that idles later re-scans every queue through
			 * the steal ring, so the preempted curr can't strand.
			 * A local wake onto an idle-owned home returns too:
			 * schedule() here is imminent, and a pick_idle kick
			 * could only invite a third party to steal the wakee
			 * out of the very queue it just claimed.
			 */
			/*
			 * INVERTED floor: preempt only a YOUNG curr. The
			 * stateless spinner/worker discriminator is curr's
			 * own on-cpu age — a handoff ping-pong participant
			 * is always young (a few us between switches, futex),
			 * while a mid-request compute worker has run long
			 * unswitched (refills don't re-stamp). Flushing the
			 * old one for a us-service wakee was the schbench
			 * RPS tax (workers preempted 2.5x native, -2%
			 * capacity -> p99 amplified at critical load); the
			 * wakee is vtime-queued and takes over at curr's
			 * block or slice expiry anyway. EEVDF makes the same
			 * trade — its messengers WAIT (800ms runnable/12s)
			 * while workers run uninterrupted.
			 */
			/*
			 * Deadline margin (pick_eevdf semantics, and the
			 * legitimate form of native's victim selection): a
			 * bare-eligibility preempt fired for wakees only
			 * microseconds ahead of curr — the flap-zone churn
			 * class whose co-execution paid the −1% IPC tax.
			 * Demand a real win (an eighth-slice) before
			 * flushing curr: deep sleepers (futex children,
			 * dispatchers — clamp-boosted a full slice back)
			 * preempt exactly as before; marginal wakees wait
			 * the turn out, and their host's sibling runs solo
			 * meanwhile. NOTE: the 2026-07-01 "full-slice
			 * margin" falsification measured a margin against a
			 * STALE curr vtime; this one sits atop the correct
			 * live charge.
			 */
			if (live && ran < (SLICE_NS >> 5) &&
			    time_before(vt + (SLICE_NS >> 1), live)) {
				cake.pmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
				scx_bpf_kick_cpu(tcpu, CAKE_KICK_PREEMPT);
				return;
			}
			if (local && !live)
				return;
		} else if (!scx_bpf_dsq_nr_queued((u64)(u32)tcpu)) {
			/*
			 * Peer wake, empty home: queue at prev anyway —
			 * WARM, no preempt (it fails eligibility against a
			 * frontier curr and waits at most one turn). The
			 * global detour sent every such request to a random
			 * blocker: always cross-core, always a cold L2,
			 * while native's wake migrations stay near prev
			 * (often the SMT sibling — same core, same L2).
			 * Equal migration COUNTS, opposite warmth — the
			 * measured on-CPU slowdown on tail requests. The
			 * M12 trap that justified the detour was measured
			 * under 1ms turns with mutual-preempt churn; 3ms
			 * turns amortize the alternation and the young-curr
			 * floor removed the churn. A busy home still goes
			 * global below.
			 */
			cake.qmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
			scx_bpf_dsq_insert_vtime(p, (u64)(u32)tcpu, SLICE_NS,
						 vt, enq_flags);
		} else if (scx_bpf_dsq_nr_queued((u64)WAKE_DSQ)) {
			/*
			 * Global backlog = the oversubscription signature:
			 * a wake is already waiting there, so scattering
			 * another one buys nothing — it lands on a random
			 * cold CPU and splits its pair (the t32/t64 herd
			 * collapse: 995K/201K per sec vs native 2.8M/2.5M).
			 * Stay home instead — native's oversubscribed shape
			 * is pairs stable at prev, vtime-fair locally. At
			 * 1x the global queue drains ahead of wakes and
			 * this branch never fires.
			 */
			cake.qmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
			scx_bpf_dsq_insert_vtime(p, (u64)(u32)tcpu, SLICE_NS,
						 vt, enq_flags);
		} else {
			scx_bpf_dsq_insert_vtime(p, (u64)WAKE_DSQ, SLICE_NS,
						 vt, enq_flags);

			/*
			 * Targeted idle kick: prev's SMT sibling shares its
			 * L2, so if it is idle, wake IT to collect from the
			 * global queue — the pickup lands warm without any
			 * routing change (the wake stays in WAKE_DSQ for
			 * anyone; flow preserved). x265-class busy-home
			 * wakes hit this constantly; converged futex never
			 * reaches here. Falls through to the untargeted
			 * pick when the sibling is busy too.
			 */
			{
				u32 nrc = (u32)cake.ncpu.word;
				u32 half = nrc >> 1;
				s32 sib = (u32)tcpu < half ? tcpu + (s32)half :
							     tcpu - (s32)half;

				if (half &&
				    bpf_cpumask_test_cpu(sib, p->cpus_ptr) &&
				    scx_bpf_test_and_clear_cpu_idle(sib)) {
					scx_bpf_kick_cpu(sib, CAKE_KICK_IDLE);
					return;
				}
			}
		}

		idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (idle >= 0)
			scx_bpf_kick_cpu(idle, CAKE_KICK_IDLE);
		else if (!home)
			cake_wake_preempt(p, tcpu);
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

		/*
		 * Depth-2 overflow to OVF_DSQ — the saturation balance the
		 * design lacked (nothing idles at 2x compute, the steal
		 * ring never runs, imbalance persists: cache-t32 -16%).
		 * Own channel: routing through WAKE_DSQ corrupted the
		 * backlog-homing signal (futex t32 2.13M -> 0.64M). Only
		 * while the global wake queue is empty — backlog there
		 * means uniform depth (sat), where overflow helps nobody.
		 */
		u64 was_preempted = cake.pmark[(u32)tcpu & (MAX_CPUS - 1)].word;

		cake.pmark[(u32)tcpu & (MAX_CPUS - 1)].word = 0;
		if (nq >= 2 && p->nr_cpus_allowed > 1 && !was_preempted &&
		    !scx_bpf_dsq_nr_queued((u64)WAKE_DSQ)) {
			scx_bpf_dsq_insert_vtime(p, (u64)OVF_DSQ, SLICE_NS,
						 vt, enq_flags);
		} else {
			cake.qmark[(u32)tcpu & (MAX_CPUS - 1)].word = 1;
			scx_bpf_dsq_insert_vtime(p, (u64)(u32)tcpu,
						 nq ? SLICE_NS + (SLICE_NS >> 1) :
						      SLICE_NS,
						 vt, enq_flags);
		}
	}

	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle >= 0)
		scx_bpf_kick_cpu(idle, CAKE_KICK_IDLE);
}

/*
 * ops.dispatch — earliest eligible vtime of {own queue, wake queue}, then
 * staggered ring steal, then keep-running.
 *
 * 1) Own DSQ vs the global wake queue: two lockless peeks (one RCU load of
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
 * 2) Steal ring: two constant-start half-loops in ascending order from
 *    cpu+1, wraparound expressed as the second loop — no modulo, no wrap
 *    arithmetic, structurally unroll-resistant, verifier-friendly. The
 *    own-offset start is a zero-cost anti-herd stagger. A blind
 *    move_to_local takes the victim's min-vtime task, skips tasks whose
 *    cpumask excludes us, and self-corrects any cross-queue vtime inversion;
 *    an empty victim costs one lockless list-empty read. Migration happens
 *    at the work-conserving minimum: only when this CPU would otherwise
 *    idle or refill (pull model).
 * 3) Everything visibly empty → keep the previous task running with a fresh
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
	struct task_struct *own, *wake;
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
	cake.qmark[ucpu & (MAX_CPUS - 1)].word = 0;
	own  = __COMPAT_scx_bpf_dsq_peek((u64)ucpu);
	if (own)
		cake.qmark[ucpu & (MAX_CPUS - 1)].word = 1;
	wake = __COMPAT_scx_bpf_dsq_peek((u64)WAKE_DSQ);
	if (wake && (!own ||
		     time_before(wake->scx.dsq_vtime +
					 (time_before(wake->scx.dsq_vtime,
						      cake.frontier.word -
							      (SLICE_NS >> 1)) ?
						  SLICE_NS :
						  2 * SLICE_NS),
				 own->scx.dsq_vtime))) {
		first  = (u64)WAKE_DSQ;
		second = (u64)ucpu;
	}

	if (scx_bpf_dsq_move_to_local(first, 0))
		return;
	if (scx_bpf_dsq_move_to_local(second, 0))
		return;
	if (scx_bpf_dsq_move_to_local((u64)OVF_DSQ, 0))
		return;

	nr = (u32)cake.ncpu.word;

	for (i = 0; i < MAX_CPUS; i++) {	/* upper half: cpu+1 .. nr-1 */
		idx = ucpu + 1 + i;
		if (idx >= nr)
			break;
		if (cake.qmark[idx & (MAX_CPUS - 1)].word &&
		    scx_bpf_dsq_move_to_local((u64)idx, 0))
			return;
	}
	for (i = 0; i < MAX_CPUS; i++) {	/* lower half: 0 .. cpu-1 */
		if (i >= ucpu)
			break;
		if (cake.qmark[i & (MAX_CPUS - 1)].word &&
		    scx_bpf_dsq_move_to_local((u64)i, 0))
			return;
	}

	if (prev && (prev->scx.flags & CAKE_TASK_QUEUED))
		prev->scx.slice = SLICE_NS;
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

	cake.stamp[cpu & (MAX_CPUS - 1)].word = bpf_ktime_get_ns();
	cake.sum[cpu & (MAX_CPUS - 1)].word = p->se.sum_exec_runtime;

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
		   cake.sum[cpu & (MAX_CPUS - 1)].word;
	u32 idx = (u32)(p->static_prio - 100) & 63;

	p->scx.dsq_vtime += (used * recip_weight[idx]) >> 20;
}

/*
 * ops.enable — a freshly enabled task starts at the current vtime frontier so
 * it is neither starved nor granted a windfall of credit.
 */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = cake.frontier.word;
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

	if (nr > MAX_CPUS)
		nr = MAX_CPUS;
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
 * ALLOW_QUEUED_WAKEUP: remote wakeups ride the batched TTWU queue (one IPI
 * drains a list on the target) instead of the waker grabbing the remote rq
 * lock per wake — the futex/pipe handoff-storm shape. Safe here because no
 * cake callback reads `current` expecting the waker: with queued wakeups,
 * select_cpu/enqueue run on the target CPU in batch context (lavd precedent).
 */
SCX_OPS_DEFINE(cake_ops,
	       .select_cpu	= (void *)cake_select_cpu,
	       .enqueue		= (void *)cake_enqueue,
	       .dispatch	= (void *)cake_dispatch,
	       .running		= (void *)cake_running,
	       .stopping	= (void *)cake_stopping,
	       .enable		= (void *)cake_enable,
	       .init		= (void *)cake_init,
	       .exit		= (void *)cake_exit,
	       .flags		= SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms	= 5000,
	       .name		= "cake");
