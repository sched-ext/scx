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
		scx_bpf_dsq_insert(p, FLOW_DSQ_LOCAL, task_slice_ns(NULL), enq_flags);
		return;
	}

	if (!is_wakeup && tctx && is_non_migratable(p)) {
		s32 pin_cpu = scx_bpf_task_cpu(p);
		if (pin_cpu >= 0 && valid_sched_cpu(pin_cpu)) {
			clear_wake_target(tctx);
			scx_bpf_dsq_insert(p,
				FLOW_PINNED_DSQ_BASE | (u32)pin_cpu,
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

	if (tctx) {
		s64 effective_budget = tctx->budget_ns > 0 ? tctx->budget_ns : 0;
		u64 vtime = FLOW_BUDGET_MAX_NS - (u64)effective_budget;

		scx_bpf_dsq_insert_vtime(p, FLOW_NORMAL_DSQ, slice_ns,
					  vtime, enq_flags);
	} else {
		scx_bpf_dsq_insert(p, FLOW_NORMAL_DSQ, slice_ns, enq_flags);
	}
	clear_wake_target(tctx);
}
