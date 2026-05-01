/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CAKE_ITER_BPF_H
#define __CAKE_ITER_BPF_H

/* cake_task_iter: SEC("iter/task") — replaces pid_to_tctx hash map.
 * Iterates all kernel tasks. Emits cake_iter_record for each managed task.
 * Userspace reads fixed-size records via link fd. Zero scheduling overhead.
 * No init/exit map ops: cake_init_task and cake_exit_task are lockless.
 *
 * Telemetry copies split into noinline batches to avoid register spills. */

#ifndef CAKE_RELEASE
struct cake_iter_record cake_iter_record_scratch SEC(".bss")
	__attribute__((aligned(256)));

#if CAKE_NEEDS_ARENA
/* Batch 1: timing fields (u64-heavy, 4 u64s + 3 u32s = ~44 bytes) */
static __noinline void iter_copy_timing(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.run_start_ns          = tctx->telemetry.run_start_ns;
	rec->telemetry.run_duration_ns       = tctx->telemetry.run_duration_ns;
	rec->telemetry.total_runtime_ns      = tctx->telemetry.total_runtime_ns;
	rec->telemetry.enqueue_start_ns      = tctx->telemetry.enqueue_start_ns;
	rec->telemetry.wait_duration_ns      = tctx->telemetry.wait_duration_ns;
	rec->telemetry.select_cpu_duration_ns= tctx->telemetry.select_cpu_duration_ns;
	rec->telemetry.enqueue_duration_ns   = tctx->telemetry.enqueue_duration_ns;
	rec->telemetry.dsq_insert_ns         = tctx->telemetry.dsq_insert_ns;
	rec->telemetry.jitter_accum_ns       = tctx->telemetry.jitter_accum_ns;
	rec->telemetry.stopping_duration_ns  = tctx->telemetry.stopping_duration_ns;
	rec->telemetry.running_duration_ns   = tctx->telemetry.running_duration_ns;
	rec->telemetry.max_runtime_us        = tctx->telemetry.max_runtime_us;
	rec->telemetry._pad4                 = 0;
	rec->telemetry.dispatch_gap_ns       = tctx->telemetry.dispatch_gap_ns;
	rec->telemetry.max_dispatch_gap_ns   = tctx->telemetry.max_dispatch_gap_ns;
}

/* Batch 2: gate hits + counters (all u32/u16 — compact) */
static __noinline void iter_copy_gates(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.gate_1_hits           = tctx->telemetry.gate_1_hits;
	rec->telemetry.gate_2_hits           = tctx->telemetry.gate_2_hits;
	rec->telemetry.gate_1w_hits          = tctx->telemetry.gate_1w_hits;
	rec->telemetry.gate_3_hits           = tctx->telemetry.gate_3_hits;
	rec->telemetry.gate_1p_hits          = tctx->telemetry.gate_1p_hits;
	rec->telemetry.gate_1c_hits          = tctx->telemetry.gate_1c_hits;
	rec->telemetry.gate_1cp_hits         = tctx->telemetry.gate_1cp_hits;
	rec->telemetry.gate_1d_hits          = tctx->telemetry.gate_1d_hits;
	rec->telemetry.gate_1wc_hits         = tctx->telemetry.gate_1wc_hits;
	rec->telemetry.gate_tun_hits         = tctx->telemetry.gate_tun_hits;
	rec->telemetry._pad2                 = 0;
	rec->telemetry.total_runs            = tctx->telemetry.total_runs;
	rec->telemetry.core_placement        = tctx->telemetry.core_placement;
	rec->telemetry.migration_count       = tctx->telemetry.migration_count;
	rec->telemetry.preempt_count         = tctx->telemetry.preempt_count;
	rec->telemetry.yield_count           = tctx->telemetry.yield_count;
	rec->telemetry.direct_dispatch_count = tctx->telemetry.direct_dispatch_count;
	rec->telemetry.enqueue_count         = tctx->telemetry.enqueue_count;
	rec->telemetry.cpumask_change_count  = tctx->telemetry.cpumask_change_count;
	rec->telemetry._pad3                 = 0;
}

/* Batch 3: histogram + identity fields */
static __noinline void iter_copy_hist(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.wait_hist_lt10us      = tctx->telemetry.wait_hist_lt10us;
	rec->telemetry.wait_hist_lt100us     = tctx->telemetry.wait_hist_lt100us;
	rec->telemetry.wait_hist_lt1ms       = tctx->telemetry.wait_hist_lt1ms;
	rec->telemetry.wait_hist_ge1ms       = tctx->telemetry.wait_hist_ge1ms;
	rec->telemetry.slice_util_pct        = tctx->telemetry.slice_util_pct;
	rec->telemetry.llc_id                = tctx->telemetry.llc_id;
	rec->telemetry.llc_run_mask          = tctx->telemetry.llc_run_mask;
	rec->telemetry.same_cpu_streak       = tctx->telemetry.same_cpu_streak;
	rec->telemetry._pad_recomp           = 0;
	rec->telemetry.wakeup_source_pid     = tctx->telemetry.wakeup_source_pid;
	rec->telemetry.nivcsw_snapshot       = tctx->telemetry.nivcsw_snapshot;
	rec->telemetry.nvcsw_delta           = tctx->telemetry.nvcsw_delta;
	rec->telemetry.nivcsw_delta          = tctx->telemetry.nivcsw_delta;
	rec->telemetry.pid_inner             = tctx->telemetry.pid;
	rec->telemetry.tgid                  = tctx->telemetry.tgid;
	/* comm: 16 bytes as two u64 reads via arena cast */
	*((__u64 *)&rec->telemetry.comm[0]) = *((__u64 __arena *)&tctx->telemetry.comm[0]);
	*((__u64 *)&rec->telemetry.comm[8]) = *((__u64 __arena *)&tctx->telemetry.comm[8]);
}

/* Batch 3b: task_struct anatomy fields, sampled only when userspace sweeps iter. */
static __noinline void iter_copy_anatomy(
	struct task_struct *task,
	struct cake_iter_record *rec)
{
	u32 flags = task->flags;
	u32 prio_pack = ((u32)task->prio & 0xff) |
			(((u32)task->static_prio & 0xff) << 8) |
			(((u32)task->normal_prio & 0xff) << 16);
	u16 anatomy_bits = 0;

	if (task->mm)
		anatomy_bits |= 1;
	if (flags & PF_KTHREAD)
		anatomy_bits |= 2;

	rec->telemetry._pad2 = flags;
	rec->telemetry._pad3 = (u16)task->policy;
	rec->telemetry._pad4 = prio_pack;
	rec->telemetry._pad_recomp = anatomy_bits;
}

/* Batch 4: enqueue substage timing + quantum + waker + per-CPU run counts */
static __noinline void iter_copy_substage(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	u32 init_ms = tctx->telemetry.lifecycle_init_ms;
	u32 now_ms = (u32)(bpf_ktime_get_ns() / 1000000ULL);

	rec->telemetry.gate_cascade_ns       = tctx->telemetry.gate_cascade_ns;
	rec->telemetry.lifecycle_init_ms     = init_ms;
	rec->telemetry.vtime_compute_ns      = tctx->telemetry.vtime_compute_ns;
	rec->telemetry.mbox_staging_ns       = tctx->telemetry.mbox_staging_ns;
	rec->telemetry.startup_latency_us    = tctx->telemetry.startup_latency_us;
	rec->telemetry.startup_enqueue_us    = tctx->telemetry.startup_enqueue_us;
	rec->telemetry.lifecycle_live_ms     = init_ms ? now_ms - init_ms : 0;
	rec->telemetry.startup_select_us     = tctx->telemetry.startup_select_us;
	rec->telemetry.quantum_full_count    = tctx->telemetry.quantum_full_count;
	rec->telemetry.quantum_yield_count   = tctx->telemetry.quantum_yield_count;
	rec->telemetry.quantum_preempt_count = tctx->telemetry.quantum_preempt_count;
	rec->telemetry.startup_first_phase   = tctx->telemetry.startup_first_phase;
	rec->telemetry.startup_phase_mask    = tctx->telemetry.startup_phase_mask;
	rec->telemetry.waker_cpu             = tctx->telemetry.waker_cpu;
	rec->telemetry._pad_waker            = 0;
	rec->telemetry.waker_tgid            = tctx->telemetry.waker_tgid;
	rec->telemetry.wake_reason_wait_ns[0] = tctx->telemetry.wake_reason_wait_ns[0];
	rec->telemetry.wake_reason_wait_ns[1] = tctx->telemetry.wake_reason_wait_ns[1];
	rec->telemetry.wake_reason_wait_ns[2] = tctx->telemetry.wake_reason_wait_ns[2];
	rec->telemetry.wake_reason_count[0] = tctx->telemetry.wake_reason_count[0];
	rec->telemetry.wake_reason_count[1] = tctx->telemetry.wake_reason_count[1];
	rec->telemetry.wake_reason_count[2] = tctx->telemetry.wake_reason_count[2];
	rec->telemetry.wake_reason_max_us[0] = tctx->telemetry.wake_reason_max_us[0];
	rec->telemetry.wake_reason_max_us[1] = tctx->telemetry.wake_reason_max_us[1];
	rec->telemetry.wake_reason_max_us[2] = tctx->telemetry.wake_reason_max_us[2];
	rec->telemetry.last_select_reason = tctx->telemetry.last_select_reason;
	rec->telemetry.last_select_path = tctx->telemetry.last_select_path;
	rec->telemetry.last_place_class = tctx->telemetry.last_place_class;
	rec->telemetry.last_waker_place_class = tctx->telemetry.last_waker_place_class;
	rec->telemetry.wake_same_tgid_count = tctx->telemetry.wake_same_tgid_count;
	rec->telemetry.wake_cross_tgid_count = tctx->telemetry.wake_cross_tgid_count;
	for (int _pi = 0; _pi < CAKE_PLACE_CLASS_MAX; _pi++) {
		rec->telemetry.home_place_wait_ns[_pi] = tctx->telemetry.home_place_wait_ns[_pi];
		rec->telemetry.home_place_wait_count[_pi] = tctx->telemetry.home_place_wait_count[_pi];
		rec->telemetry.home_place_wait_max_us[_pi] = tctx->telemetry.home_place_wait_max_us[_pi];
	}
	/* cpu_run_count: per-element arena reads */
for (int _ci = 0; _ci < CAKE_TELEM_MAX_CPUS; _ci++)
		rec->telemetry.cpu_run_count[_ci] = tctx->telemetry.cpu_run_count[_ci];
}
#endif /* CAKE_NEEDS_ARENA */
#endif /* !CAKE_RELEASE */

#ifndef CAKE_RELEASE
SEC("iter/task")
int cake_task_iter(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	if (!task)
		return 0;

	struct cake_iter_record *rec = &cake_iter_record_scratch;
	__builtin_memset(rec, 0, sizeof(*rec));

#if CAKE_NEEDS_ARENA
	/* Only emit tasks managed by this scheduler instance. */
	struct cake_task_ctx __arena *tctx = get_task_ctx(task);
	if (!tctx || !tctx->telemetry.pid)
		return 0;

	/* Build iter record from arena tctx data in BSS scratch, not stack. */
	rec->pid         = task->pid;
	rec->ppid        = tctx->ppid;
	rec->packed_info = tctx->packed_info |
			  ((u32)tctx->home_score << 8) |
			  (u32)tctx->home_core;
	rec->pelt_util = (u16)task->se.avg.util_avg;
	rec->allowed_cpus    = task->nr_cpus_allowed > 0xffff ? 0xffff : (u16)task->nr_cpus_allowed;
	rec->task_weight     = tctx->task_weight;
	rec->home_cpu        = tctx->home_cpu;

	/* Telemetry: batched noinline copies → 0 spills per batch.
	 * Each batch: 2 args (tctx+rec) = 2 callee-saves. */
	iter_copy_timing(tctx, rec);
	iter_copy_gates(tctx, rec);
	iter_copy_hist(tctx, rec);
	iter_copy_anatomy(task, rec);
	iter_copy_substage(tctx, rec);
#else
	rec->pid = task->pid;
	rec->ppid = task->real_parent ? task->real_parent->tgid : 0;
	rec->pelt_util = (u16)task->se.avg.util_avg;
	rec->allowed_cpus = task->nr_cpus_allowed > 0xffff
				    ? 0xffff
				    : (u16)task->nr_cpus_allowed;
	rec->task_weight = (u16)(task->scx.weight ?: 100);
	rec->home_cpu = CAKE_CPU_SENTINEL;
	rec->telemetry.pid_inner = task->pid;
	rec->telemetry.tgid = task->tgid;
	rec->telemetry._pad2 = task->flags;
	rec->telemetry._pad3 = (u16)task->policy;
	rec->telemetry._pad4 = ((u32)task->prio & 0xff) |
			       (((u32)task->static_prio & 0xff) << 8) |
			       (((u32)task->normal_prio & 0xff) << 16);
	rec->telemetry._pad_recomp =
		(task->mm ? 1 : 0) | ((task->flags & PF_KTHREAD) ? 2 : 0);
	*((__u64 *)&rec->telemetry.comm[0]) = *((__u64 *)&task->comm[0]);
	*((__u64 *)&rec->telemetry.comm[8]) = *((__u64 *)&task->comm[8]);
#endif

	bpf_seq_write(seq, rec, sizeof(*rec));
	return 0;
}
#endif /* !CAKE_RELEASE */

#endif /* __CAKE_ITER_BPF_H */
