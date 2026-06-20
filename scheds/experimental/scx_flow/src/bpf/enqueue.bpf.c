/* Enqueue routing — included by main.bpf.c via #include
 *
 * Wakeup and pinned tasks bypass the carriage and are dispatched
 * directly to local DSQs.  Non-wakeup tasks go through
 * carriage_enqueue_task() which inserts into per-CPU DSQs
 * (FLOW_VTIME_DSQ_BASE + target_cpu) via scx_bpf_dsq_insert___v1. */

int BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	s32 target_cpu = -1;
	s32 task_cpu;
	bool is_wakeup;
	bool has_wake_target = false;

	/* Scheduler process bypass. */
	if (flow_scheduler_pid && (u64)(s32)p->pid == flow_scheduler_pid) {
		s32 sch_cpu = scx_bpf_task_cpu(p);
		u64 flags = FLOW_ENQ_HEAD | FLOW_ENQ_PREEMPT;
		if (sch_cpu >= 0 && (u32)sch_cpu < 1024)
			scx_bpf_dsq_insert___v1(p,
				FLOW_DSQ_LOCAL_ON | (u32)sch_cpu,
				FLOW_SLICE_MIN_NS, flags);
		else
			scx_bpf_dsq_insert___v1(p, FLOW_DSQ_LOCAL,
				FLOW_SLICE_MIN_NS, flags);
		return 0;
	}

	tctx = lookup_task_ctx(p);
	is_wakeup = enq_flags & FLOW_ENQ_WAKEUP;

	if (tctx && tctx->wake_cpu_valid) {
		target_cpu = tctx->wake_cpu;
		has_wake_target = true;
	}

	task_cpu = scx_bpf_task_cpu(p);

	/* Non-migratable: ensure target matches current CPU. */
	if (is_non_migratable(p) && task_cpu >= 0 &&
	    bpf_cpumask_test_cpu(task_cpu, p->cpus_ptr)) {
		if (!has_wake_target || target_cpu != task_cpu) {
			target_cpu = task_cpu;
			has_wake_target = true;
			if (tctx) {
				tctx->wake_cpu = task_cpu;
				tctx->wake_cpu_idle = false;
				tctx->wake_cpu_valid = true;
			}
		}
	}

	/* Pinned kthread: direct to local DSQ. */
	if (is_pinned_kthread(p)) {
		clear_wake_target(tctx);
		scx_bpf_dsq_insert___v1(p, FLOW_DSQ_LOCAL,
			FLOW_SLICE_MIN_NS, enq_flags);
		return 0;
	}

	/* Non-wakeup, non-migratable: per-CPU pinned DSQ. */
	if (!is_wakeup && tctx && is_non_migratable(p)) {
		s32 pin_cpu = task_cpu;
		if (pin_cpu >= 0 && valid_sched_cpu(pin_cpu)) {
			clear_wake_target(tctx);
			scx_bpf_dsq_insert___v1(p,
				FLOW_PINNED_DSQ_BASE + (u32)pin_cpu,
				FLOW_SLICE_MIN_NS, enq_flags);
			return 0;
		}
	}

	/* Wakeup fast path — bypass carriage. */
	if (is_wakeup) {
		if (has_wake_target && valid_sched_cpu(target_cpu)) {
			u64 wake_enq_flags;
			wake_enq_flags = enq_flags | FLOW_ENQ_HEAD;
			if (tctx && (tctx->first_run ||
				     tctx->budget_ns >= (s64)FLOW_SLICE_MIN_NS))
				wake_enq_flags |= FLOW_ENQ_PREEMPT;
			scx_bpf_cpuperf_set(target_cpu, SCX_CPUPERF_ONE);
			scx_bpf_dsq_insert___v1(p,
				FLOW_DSQ_LOCAL_ON | (u32)target_cpu,
				FLOW_SLICE_MIN_NS, wake_enq_flags);
		} else {
			scx_bpf_dsq_insert___v1(p, FLOW_DSQ_LOCAL,
				FLOW_SLICE_MIN_NS, FLOW_ENQ_HEAD);
		}
		__sync_fetch_and_add(&prio_dispatches, 1);
		clear_wake_target(tctx);
		return 0;
	}

	/* Non-wakeup re-enqueue: Waiting Room.
	 * carriage_enqueue_task always dispatches (no pool-full blocking). */
	carriage_enqueue_task(p, tctx);

	clear_wake_target(tctx);
	return 0;
}
