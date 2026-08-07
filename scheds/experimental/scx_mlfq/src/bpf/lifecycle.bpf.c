/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Task lifecycle, included by main.bpf.c via #include.
 *
 * init_task/enable initialize the task context; running() records the
 * running task's queue and pid, the wakeup-preemption inputs;
 * stopping() charges vruntime and the EMA gauge for the run segment and
 * advances the owning queue's virtual clock with the virtual time just
 * charged; exit_task() deletes the task storage; cpu_release() re-enqueues
 * local-DSQ leftovers when a CPU leaves the scheduler.
 */

static __always_inline void mlfq_reset_task_ctx(struct task_ctx *tctx,
						const struct task_struct *p,
						u64 now)
{
	tctx->vruntime = 0;
	tctx->vlag = 0;
	tctx->deadline = 0;
	tctx->last_run_at = 0;
	tctx->last_sleep_at = scx_bpf_task_running(p) ? 0 : now;
	tctx->queued_at = 0;
	tctx->weight = p->scx.weight;
	if (!tctx->weight)
		tctx->weight = 1;
	tctx->flags = MLFQ_TF_FIRST_RUN;
	tctx->wake_cpu_state = 0;
	mlfq_reset_classification(tctx);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = mlfq_alloc_task_ctx(p);
	if (!tctx)
		return -ENOMEM;

	mlfq_reset_task_ctx(tctx, p, scx_bpf_now());
	return 0;
}

void BPF_STRUCT_OPS(mlfq_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	/* init_task() is called for every task first; be defensive here. */
	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	mlfq_reset_task_ctx(tctx, p, scx_bpf_now());
}

void BPF_STRUCT_OPS(mlfq_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct mlfq_cpu_state *cpu;
	s32 cpu_id = bpf_get_smp_processor_id();

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Record the running task's queue and pid. The wakeup-preemption
	 * decision in enqueue() compares a wakeup's queue against the
	 * queue of the task running on the CPU it was last running on, so
	 * the record is refreshed on every context switch.
	 */
	cpu = mlfq_lookup_cpu_state(cpu_id);
	if (cpu) {
		cpu->running_queue = tctx->queue;
		cpu->running_pid = p->pid;
	}

	tctx->last_run_at = scx_bpf_now();
	tctx->flags &= ~MLFQ_TF_FIRST_RUN;

	__sync_fetch_and_add(&mlfq_stats.on_cpu, 1);

	/*
	 * cpufreq interaction: the interactive queue requests the maximum
	 * performance level through the sched_ext cpuperf API, and the
	 * other queues request the level matching the CPU's recent
	 * activity (mlfq_cpuperf_from_ema()). The kernel stores the
	 * target per CPU and schedutil follows it on every update, so
	 * setting it on every ops.running() makes the frequency track the
	 * task now on the CPU. With the scheduler in switch-all mode the
	 * target is the only utilization signal schedutil sees, so a
	 * stale maximum would keep the CPU at top frequency for the
	 * background work that follows an interactive task. The counter
	 * reports the interactive boosts.
	 */
	if (tctx->queue == 1) {
		scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), MLFQ_CPUPERF_Q1);
		__sync_fetch_and_add(&mlfq_stats.cpuperf_boosts, 1);
	} else if (cpu) {
		scx_bpf_cpuperf_set(scx_bpf_task_cpu(p),
				    mlfq_cpuperf_from_ema(cpu->cpu_ema));
	}
}

void BPF_STRUCT_OPS(mlfq_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	struct mlfq_cpu_state *cpu;
	struct queue_ctx *q;
	u64 now, delta = 0;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	now = scx_bpf_now();
	if (tctx->last_run_at && mlfq_time_before(tctx->last_run_at, now))
		delta = now - tctx->last_run_at;
	tctx->last_run_at = 0;

	if (delta) {
		/* vruntime advance + EMA climb for this run segment. */
		mlfq_update_vruntime(tctx, delta);
		mlfq_ema_climb_task(tctx, delta);
		/*
		 * The per-CPU busy gauge: the run segment climbs the
		 * gauge and the wall time since the previous segment
		 * decays it, so the gauge reflects the CPU's recent
		 * activity. The cpuperf target for the non-interactive
		 * queues is derived from it, so the frequency follows the
		 * load instead of staying pinned at the last level.
		 */
		cpu = mlfq_lookup_cpu_state(bpf_get_smp_processor_id());
		if (cpu) {
			u64 elapsed = 0;

			if (cpu->cpu_ema_at &&
			    mlfq_time_before(cpu->cpu_ema_at, now))
				elapsed = now - cpu->cpu_ema_at;
			cpu->cpu_ema = mlfq_ema_decay(cpu->cpu_ema, elapsed,
						      mlfq_ema_half_life_ns);
			cpu->cpu_ema = mlfq_ema_climb(cpu->cpu_ema, delta,
						      mlfq_budget_max_ns,
						      mlfq_alpha);
			cpu->cpu_ema_at = now;
		}
		/*
		 * Advance the owning queue's virtual clock with the
		 * virtual time just charged: the clock follows the
		 * service given to the queue, and placement anchors new
		 * arrivals to it. The queue lookup can fail when the task's
		 * queue state was not carried over, which is tolerated: the
		 * clock only needs to be near the service point and the
		 * placement clamp bounds the staleness.
		 */
		q = mlfq_lookup_queue(tctx->queue);
		if (q)
			mlfq_queue_advance_clock(q, tctx->vruntime);
		__sync_fetch_and_add(&mlfq_stats.total_runtime, delta);
	}

	if (!runnable)
		tctx->last_sleep_at = now;

	/*
	 * Keep the running-task record while the task remains runnable
	 * (preempted); clear it when the task goes to sleep so the
	 * wakeup-preemption decision never compares against a stale
	 * record.
	 */
	cpu = mlfq_lookup_cpu_state(bpf_get_smp_processor_id());
	if (cpu && !runnable) {
		cpu->running_queue = 0;
		cpu->running_pid = 0;
	}

	/* Diagnostic runnable count; guard against wrap-around. */
	if (__sync_fetch_and_sub(&mlfq_stats.on_cpu, 1) == 0)
		__sync_fetch_and_add(&mlfq_stats.on_cpu, 1);
}

void BPF_STRUCT_OPS(mlfq_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx *tctx;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	bpf_task_storage_delete(&task_ctx_stor, p);
}

/*
 * CPU release (hotplug offline, exit drain, higher-priority class take-over):
 * push any leftover local-DSQ tasks back through ops.enqueue() so they
 * re-enter the queue DSQs instead of being stranded on the released CPU.
 * Normally a no-op: by discipline the local DSQ depth is at most one task,
 * and a queued leftover is exactly the runnable task the CPU is leaving
 * behind. The re-enqueued leftovers land in the releasing CPU's queue
 * DSQs and are served by other CPUs' steal scans; the kernel's reenqueue
 * guard and the stall watchdog cap the pathological loop.
 * scx_bpf_reenqueue_local() is restricted to this callback (ext.c).
 */
void BPF_STRUCT_OPS(mlfq_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
}
