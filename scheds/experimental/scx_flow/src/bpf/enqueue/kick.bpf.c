// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue direct bypass plus kick for the flow scheduler.
 *
 * Holds the idle direct bypass with the hoisted drain gate plus the
 * strict one kick per wait tail. An idle target takes the task straight
 * to its local queue with one idle kick per wait and no preempt, so
 * wakeups take a bounded direct jump past the tier plus dispatch hop
 * with one insert plus one kick and no zero-cost bypass. The bypass
 * runs only when empty plus earliest-only holds incl the reject queue
 * and the local plus node plus machine plus reject tiers hold no
 * queued work or the target still drains local plus node before the
 * strict key with an empty machine plus an empty reject, so an earlier key never waits behind
 * this arrival in a tier queue. Rechecks keep the same order with one
 * hoist. Strict fair order gates the bypass with eligibility plus
 * drain, so hogs pace through tiers with no direct jump and one kick
 * per wait stays. A direct preempt needs predictor slack plus an
 * eligible arrival plus a 100us margin lead with more than 100us still
 * left on the owner, so near ties plus nearly done owners never bounce
 * while one kick per wait stays with no storm. Exiting tasks stay
 * exempt with no queue wait and no gate. Runs under the caller with no
 * lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Tail args for the Outlined place plus kick with one call each. */
/* Bundles the live target plus the fair time plus the enqueue time */
/* plus the insert flags plus the requeue pace plus the hoisted */
/* eligibility, so each Outlined tail takes one pointer with no stack */
/* args and the bypass plus the kick share the same single reads. */
struct flow_enqueue_tail {
	s32 cpu;
	u64 vtime;
	u64 now;
	u64 enq_flags;
	bool is_reenq;
	bool hoist_elig;
};
/**
 * flow_enqueue_place - bypass idle direct or join a tier queue.
 * @p: task to place on its live target.
 * @t: tail args with target plus fair time plus time plus flags plus
 * eligibility, hoisted once by the caller with no second poll.
 *
 * Idle direct bypass only when tiers hold no earlier strict key. An idle
 * target takes the task straight to its local queue with one idle kick
 * per wait and no preempt, so wakeups take a bounded direct jump past
 * the tier plus dispatch hop with one insert plus one kick. The bypass runs only when the local plus node plus machine plus reject tiers hold
 * no queued work or the target still drains local plus node before the
 * strict key with an empty machine plus an empty reject, so an earlier key never waits behind this arrival in
 * a tier queue. The value ordered reject stays in scope here and a queued
 * vetoes the bypass with no jump. Local plus node depths hoist once here, so the empty
 * gate plus the drain gate share the same reads with no second poll.
 * The bypass inserts straight to local with no tier move count, so
 * admits vs moves drift by the bypass count with no loss while dispatch
 * moves still count each tier. The TOCTOU between the empty hints and
 * the direct insert only races a concurrent tier join with no loss,
 * since dispatch still drains in fair order with mask wins on the next
 * pass. Tier join through the hoisted combined drain escalation takes
 * the local tier when the hoisted drain finishes before the fair key,
 * else the node tier when live, else the machine tier, so no task waits
 * for a busy CPU while shared room stays open. Queue order plus tier
 * choice use the fair time while placement tests the deadline, so the
 * slowest sufficient CPU wins. Mask wins on dispatch drain with the
 * same order.
 *
 * Returns: true when the direct bypass took with one kick, else false
 * after a tier join with the kick left to the caller.
 *
 * Outlined with noinline to keep verifier headroom and the bypass plus
 * tier join leaves the kick tail with no inline growth and the same
 * order plus the same counts.
 */
static __noinline bool flow_enqueue_place(struct task_struct *p,
	struct flow_enqueue_tail *t)
{
	s32 cpu = t->cpu;
	u64 vtime = t->vtime;
	u64 now = t->now;
	struct flow_cpu_state *dst = flow_cpu((u32)cpu);
	if (dst && READ_ONCE(dst->running_pid) == 0) {
		u64 own = flow_local_dsq((u32)cpu);
		u32 node = flow_cpu_node((u32)cpu);
		bool node_valid = false;
		u64 node_dsq = 0;
		s32 lq = 0;
		s32 nq = 0;
		s32 mq = 0;
		s32 oq = 0;
		bool tiers_empty = false;
		bool drain_ok = false;
		if (node < (u32)FLOW_MAX_NODES &&
		    (u64)node < nr_node_ids) {
			node_dsq = flow_node_dsq(node);
			node_valid = true;
		}
		/* Hoist local plus node plus machine plus reject once with */
		/* signed hints, so the empty gate plus the drain gate plus */
		/* the tier escalation share one read with no repoll. The */
		/* reject queue stays in scope here by design and a queued */
		/* reject vetoes the bypass, so an earlier value never waits */
		/* behind this arrival. Like fair.c, the earliest key wins, */
		/* unlike rt.c, no fixed priority holds. */
		lq = scx_bpf_dsq_nr_queued(own);
		mq = scx_bpf_dsq_nr_queued(flow_machine_dsq());
		oq = scx_bpf_dsq_nr_queued(flow_overflow_dsq());
		if (node_valid)
			nq = scx_bpf_dsq_nr_queued(node_dsq);
		if (lq <= 0 && mq <= 0 && oq <= 0 && (!node_valid || nq <= 0))
			tiers_empty = true;
		/* Drain gate uses the same hoisted combined drain with */
		/* no kfunc, so the bypass tests fair order cheap. The machine */
		/* plus reject queues veto here too and the bypass needs an empty */
		/* machine plus an empty reject, so shared plus value order hold */
		/* with no jump. */
		drain_ok = flow_cpu_meets_fair_hint(lq, nq, vtime, now);
		if (mq > 0)
			drain_ok = false;
		if (oq > 0)
			drain_ok = false;
		if ((tiers_empty || drain_ok) && t->hoist_elig) {
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu,
			    (u64)FLOW_QUANTUM_NS, t->enq_flags);
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			flow_count_kick();
			return true;
		}
		/* Tier join through the hoisted combined drain escalation */
		/* with no second poll. The local tier takes the task when */
		/* the hoisted drain finishes before the fair key, else the */
		/* node tier when live, else the machine tier, so no task */
		/* waits for a busy CPU while shared room stays open. Queue */
		/* order plus tier choice use the fair time while placement */
		/* tests the deadline, so the slowest sufficient CPU wins. */
		/* Mask wins on dispatch drain with the same order. */
		flow_tier_insert_hint(p, cpu, vtime, now, lq, nq);
		return false;
	}
	/* Tier join through the shared insert with fair order. */
	/* The local queue takes the task when the target drains local plus */
	/* node before the fair key, else the node queue when live, else the */
	/* machine queue, so no task waits for a busy CPU while shared room */
	/* stays open. Queue order plus tier choice use the fair time while */
	/* placement tests the deadline, so the slowest sufficient CPU wins. */
	flow_tier_insert(p, cpu, vtime, now);
	return false;
}
/**
 * flow_enqueue_kick - kick one idle or preempt one busy target.
 * @p: waiting task that just joined a tier queue.
 * @t: tail args with target plus arrival fair time plus time plus
 * requeue pace plus eligibility, hoisted once by the caller.
 *
 * Idle targets kick at once with strict one kick per wait and no rate
 * window. The idle flag clears first so the kick sticks. The pid read
 * uses a relaxed load to match the running stores. Requeues skip the
 * occupant lookup with no task_from_pid cost, so slice rotation paces
 * at expiry with no extra kick. Busy preempts count in preempt_kicks on
 * success and in preempt_skipped on every hold by strict margin plus
 * tail plus eligibility with no missing fill, so the two counters track
 * urgency with no extra kick. Strict order uses wrap safe time before
 * throughout, so equal arrivals pace with no bounce. Idle kicks gate on
 * the hoisted eligibility, so hogs pace through tiers with no idle jump
 * while lagging tasks still wake at once. The gate stays with one
 * minimum read per wait, and the ineligible corner paces in tiers with
 * no kick and one skipped preempt with no storm. The running pid names
 * the occupant with no curr read. A trusted lookup carries the occupant
 * deadline, and a missing occupant fails closed with no kick and no
 * skipped count, since no urgency holds to track. The occupant CPU
 * validates before the compare, so a migrated occupant never kicks the
 * wrong CPU with no count. A zero occupant deadline means no order yet,
 * so the arrival paces with no kick and no skipped count. Only predictor
 * slack plus margin plus tail plus eligibility plus fair order holds
 * count as skipped. An urgent latency-critical arrival leads by 100us
 * with more than 100us left on the owner, so near ties plus nearly
 * done owners never bounce. The shared preempt helper holds the margin
 * plus tail with wrap safe order, so only a truly earlier arrival with
 * work left preempts at once with one kick per wait. Equal or later
 * arrivals pace at slice expiry with one skipped preempt. The fair time
 * leads here, so fairness plus urgency gate the kick. Eligibility
 * already passed above, so the helper checks lead plus tail only with
 * predictor slack gated before it.
 *
 * Outlined with noinline to keep verifier headroom and the RCU occupant
 * walk leaves the bypass plus tier join with no inline growth and the
 * same one kick per wait order.
 */
static __noinline void flow_enqueue_kick(struct task_struct *p,
	struct flow_enqueue_tail *t)
{
	s32 cpu = t->cpu;
	u64 vtime = t->vtime;
	u64 now = t->now;
	struct flow_cpu_state *st = flow_cpu((u32)cpu);
	u32 occ_pid;
	struct task_struct *trusted;
	struct flow_task_ctx *octx;
	u64 occ_deadline;
	u64 occ_start;
	if (!st)
		return;
	/* Idle kicks gate on the hoisted eligibility, so hogs pace */
	/* through tiers with no idle jump while lagging tasks still */
	/* wake at once. The gate stays with one minimum read per */
	/* wait, and the ineligible corner paces in tiers with no */
	/* kick and one skipped preempt with no storm. */
	if (!t->hoist_elig) {
		flow_count_preempt_skip();
		return;
	}
	if (READ_ONCE(st->running_pid) == 0) {
		scx_bpf_test_and_clear_cpu_idle(cpu);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		flow_count_kick();
		return;
	}
	/* Requeues pace at slice expiry with no occupant preempt, */
	/* so the task_from_pid plus cgroup plus 16 peer cost stays */
	/* out of the hot rotation path. */
	if (t->is_reenq)
		return;
	/* The running pid names the occupant with no curr read. */
	/* A trusted lookup carries the occupant deadline, and a */
	/* missing occupant fails closed with no kick and no skipped */
	/* count, since no urgency holds to track. The occupant CPU */
	/* validates before the compare, so a migrated occupant never */
	/* kicks the wrong CPU with no count. A zero occupant deadline */
	/* means no order yet, so the arrival paces with no kick and */
	/* no skipped count. Only margin plus tail plus eligibility */
	/* plus fair order holds count as skipped below. */
	occ_pid = READ_ONCE(st->running_pid);
	if (occ_pid == 0 || occ_pid == (u32)p->pid)
		return;
	bpf_rcu_read_lock();
	trusted = bpf_task_from_pid(occ_pid);
	if (!trusted) {
		bpf_rcu_read_unlock();
		return;
	}
	if (scx_bpf_task_cpu(trusted) != cpu) {
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		return;
	}
	octx = flow_lookup(trusted);
	if (!octx) {
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		return;
	}
	occ_deadline = READ_ONCE(octx->deadline);
	occ_start = READ_ONCE(octx->run_at);
	if (occ_deadline == 0) {
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		return;
	}
	/* Predictor slack gates the busy preempt with no new knob. */
	/* A batch arrival with a long predicted burst paces at slice */
	/* expiry with one skipped preempt, so only latency-critical work */
	/* with slack within one quantum preempts at once. Eligibility */
	/* already passed above, so this plus lead plus tail gate the kick. */
	{
		struct flow_task_ctx *actx = flow_lookup(p);
		if (actx) {
			u64 a_avg = (u64)READ_ONCE(actx->avg_ns);
			u64 a_dev = (u64)READ_ONCE(actx->dev_ns);
			if (!flow_lat_crit(a_avg, a_dev)) {
				bpf_task_release(trusted);
				bpf_rcu_read_unlock();
				flow_count_preempt_skip();
				return;
			}
		}
	}
	/* An urgent latency-critical arrival leads by 100us with more than */
	/* 100us left on the owner under the strict key, so near ties plus */
	/* nearly done owners never bounce. The owner paces on a fresh 1ms */
	/* quantum with no dynamic use. The shared preempt helper holds the */
	/* margin plus tail with wrap safe order, so only a truly earlier */
	/* arrival with work left preempts at once with one kick per wait. */
	/* Equal or later arrivals pace at slice expiry with one skipped */
	/* preempt. The strict key leads here, so fairness plus urgency gate */
	/* the kick. Eligibility already passed above, so the helper checks */
	/* lead plus tail only with slack gated just before it. */
	if (!flow_preempt_wants(vtime, occ_deadline, now,
	    occ_start)) {
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		flow_count_preempt_skip();
		return;
	}
	bpf_task_release(trusted);
	bpf_rcu_read_unlock();
	scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	flow_count_kick();
	flow_count_preempt_kick();
}
