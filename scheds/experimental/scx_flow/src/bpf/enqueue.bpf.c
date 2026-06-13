/* Enqueue routing — included by main.bpf.c via #include */

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	s32 target_cpu = -1;
	s32 task_cpu;
	u64 slice_ns;
	bool is_wakeup;
	bool has_wake_target = false;

	tctx = lookup_task_ctx(p);
	slice_ns = task_slice_ns(tctx);
	is_wakeup = enq_flags & FLOW_ENQ_WAKEUP;

	if (tctx && tctx->wake_cpu_valid) {
		target_cpu = tctx->wake_cpu;
		has_wake_target = true;
	}

	task_cpu = scx_bpf_task_cpu(p);
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

	if (is_pinned_kthread(p)) {
		clear_wake_target(tctx);
		scx_bpf_dsq_insert(p, FLOW_DSQ_LOCAL, FLOW_SLICE_MIN_NS, enq_flags);
		return;
	}

	if (!is_wakeup && tctx && is_non_migratable(p)) {
		s32 pin_cpu = task_cpu;
		if (pin_cpu >= 0 && valid_sched_cpu(pin_cpu)) {
			clear_wake_target(tctx);
			scx_bpf_dsq_insert(p,
				FLOW_PINNED_DSQ_BASE + (u32)pin_cpu,
				task_slice_ns(tctx), enq_flags);
			return;
		}
	}

	if (is_wakeup && has_wake_target && valid_sched_cpu(target_cpu)) {
		u64 wake_enq_flags;
		slice_ns = FLOW_SLICE_MIN_NS;

		wake_enq_flags = enq_flags | FLOW_ENQ_HEAD;
		if (tctx && (tctx->first_run ||
			     tctx->budget_ns >= (s64)FLOW_SLICE_MIN_NS))
			wake_enq_flags |= FLOW_ENQ_PREEMPT;

		scx_bpf_cpuperf_set(target_cpu, SCX_CPUPERF_ONE);
		scx_bpf_dsq_insert(p, FLOW_DSQ_LOCAL_ON | (u32)target_cpu,
				   slice_ns, wake_enq_flags);
		__sync_fetch_and_add(&prio_dispatches, 1);
		clear_wake_target(tctx);
		return;
	}

	{
		s64 budget;

		if (tctx)
			budget = tctx->budget_ns;
		else
			budget = 0;

		/* Budget is in nanoseconds (s64).  Budget range after clamp is
	 * [-500 us, 2000 us] = [-500,000 ns, 2,000,000 ns].  Tiers:
	 *   PRIORITY: budget >= 1500 us (1,500,000 ns)  — long-sleep tasks
	 *   NORMAL:   budget >= 1000 us (1,000,000 ns)  — tasks with typical budget
	 *   LOW:      budget >=  500 us (  500,000 ns)  — tasks with modest budget
	 *   DEFICIT:  budget <   500 us (  500,000 ns)  — exhausted / bulk workers
	 *
	 * Tasks need 500 us * 100 = 50 ms of sleep to reach LOW,
	 * 100 ms for NORMAL, 150 ms for PRIORITY.  Interactive tasks
	 * that sleep longer earn higher priority. */
	if (budget >= FLOW_BUDGET_TIER_PRIORITY_NS)
			scx_bpf_dsq_insert(p, FLOW_TIER_PRIORITY_DSQ, slice_ns, enq_flags);
		else if (budget >= FLOW_BUDGET_TIER_NORMAL_NS)
			scx_bpf_dsq_insert(p, FLOW_TIER_NORMAL_DSQ, slice_ns, enq_flags);
		else if (budget >= FLOW_BUDGET_TIER_LOW_NS)
			scx_bpf_dsq_insert(p, FLOW_TIER_LOW_DSQ, slice_ns, enq_flags);
		else
			scx_bpf_dsq_insert(p, FLOW_TIER_DEFICIT_DSQ, slice_ns, enq_flags);
	}
	clear_wake_target(tctx);
}
