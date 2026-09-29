// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Running claims the segment start from zero and counts the on CPU
 * gauge once per claim. Stopping claims the start once and charges
 * the raw segment to total runtime, then advances virtual runtime by
 * scaled time with the task weight, then drops the stored admitted
 * share, then counts one requeue per runnable stop else one
 * completion. A wall completion past release plus deadline counts
 * one miss with one park and no kick, since the task already left
 * the CPU. Enable clears
 * the release plus the period plus the deadline plus the runtime
 * plus the hint plus the miss count plus the stored share, and
 * disable plus exit charge a leftover segment at most once when
 * stopping never ran plus drop a stored share with no leak. A closed
 * gate in stopping plus disable still drops a stored share, so a
 * stale CPU never leaks its debit and enable meets zero by design.
 * Release clears a stale running view with no charge. The gate runs first in every op except the
 * exiting paths, so a stale CPU fails closed with one counter. See
 * intf.h for the shared helpers and enqueue.bpf.c for admission plus
 * the deadline choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	u64 now;
	u64 stamp;
	u64 prev;
	bool claimed = false;
	cpu = scx_bpf_task_cpu(p);
	/* The gate runs first with fail closed and no count on pass. */
	/* Exiting tasks never reach here through the running path. */
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	if (tctx) {
		/* Zero never marks a run, so a zero clock folds to one. */
		/* The claim swaps from zero only, so a second running */
		/* without a stop keeps the first start with no second */
		/* gauge count. */
		stamp = now ? now : 1;
		prev = __sync_val_compare_and_swap(&tctx->run_at,
		    0, stamp);
		claimed = prev == 0;
	}
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st)
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
inc:
	/* Count the on CPU gauge once per claimed start. */
	/* Tasks without state hold no claim, so they hold no count. */
	if (claimed)
		__sync_fetch_and_add(&flow_stats.on_cpu, 1);
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 start;
	cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		/* A closed gate still drops a stored share, so a stale CPU */
		/* never leaks its debit. */
		flow_admit_drop_stored(flow_lookup(p));
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	/* Tasks without state hold no claim, so they hold no count. */
	/* The pid view still clears when owned. */
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	/* The start claims with an exchange, so stopping versus disable */
	/* or exit charges once. A zero claim means no counted start, */
	/* so this pass drops with no charge and no gauge move, and */
	/* every counted start meets exactly one gauge drop. */
	start = __sync_lock_test_and_set(&tctx->run_at, 0);
	if (start == 0) {
		/* No claimed start still drops a stored share, so a queued */
		/* task that never ran never leaks its debit. */
		flow_admit_drop_stored(tctx);
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	if (flow_time_before(now, start))
		delta = 0;
	else
		delta = now - start;
	/* Every segment counts raw time with no weight scaling. */
	/* Order already carries weight through scaled runtime. */
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	/* Runtime advances by scaled time with the task weight. */
	/* A zero weight folds to base too, so the advance never divides */
	/* by zero. Two divides per stop stay cheap beside one slice. */
	tctx->vruntime = flow_vruntime_advance(tctx->vruntime,
	    delta, flow_weight_clamp(p->scx.weight));
	/* The admitted share drops once per stop with floor at zero. */
	/* The stored value drops, so a hint change between enqueue and */
	/* stop never drifts the row and a move never debits the wrong */
	/* CPU. A double drop stays empty with no second debit. */
	flow_admit_drop_stored(tctx);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	flow_on_cpu_dec();
	/* A wall completion past the deadline counts one miss with one */
	/* park and no kick, since the task already left the CPU. */
	if (!runnable && tctx->release &&
	    !flow_deadline_ok(tctx->deadline, now)) {
		flow_count_miss(tctx);
	}
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	__sync_fetch_and_add(&flow_stats.completions, 1);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_get(p);
	if (!tctx)
		return;
	/* Fresh tasks hold no release, no period, no deadline, no */
	/* runtime, no stamps, no hint, no misses, and no admit share. */
	/* The first enqueue anchors at now with one deadline. */
	tctx->release = 0;
	tctx->period = 0;
	tctx->deadline = 0;
	tctx->vruntime = 0;
	tctx->wait_at = 0;
	tctx->run_at = 0;
	tctx->hint_us = 0;
	tctx->misses = 0;
	tctx->admit_share = 0;
	tctx->admit_cpu = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		/* A closed gate still drops a stored share, so a stale CPU */
		/* never leaks its debit. */
		flow_admit_drop_stored(flow_lookup(p));
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	/* The gauge drop follows the claim with no owner gate. */
	/* A stored share drops here too, so a task that leaves without */
	/* a stop never leaks its debit. */
	flow_charge_leftover(p, tctx, cpu);
	flow_admit_drop_stored(tctx);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	/* Exiting tasks stay exempt from the gate with no count. */
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	/* The gauge drop follows the claim with no owner gate. */
	/* A stored share drops here too with no leak on exit. */
	flow_charge_leftover(p, tctx, cpu);
	flow_admit_drop_stored(tctx);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* The gate runs with no task here, so only the CPU checks. */
	/* A stale CPU counts one reject with no clear. */
	if (cpu >= 0 && !flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
}
