/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CAKE_TELEMETRY_BPF_H
#define __CAKE_TELEMETRY_BPF_H

/* Per-CPU global stats — BSS array, 256B aligned per entry.
 * Direct indexing keeps the hot path simple and avoids helper indirection. */
#ifndef CAKE_RELEASE
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));

/* Debug-only exact select_cpu attribution.
 * target_count answers "which CPU got picked?"
 * prev_count answers "which previous lane fed that reason?"
 *
 * The target view excludes tunnel because tunnel does not choose an idle CPU;
 * the prev view includes it so busy-all fallbacks still show where stickiness
 * originated. */
u64 select_reason_target_count[CAKE_SELECT_REASON_MAX][CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 select_reason_prev_count[CAKE_SELECT_REASON_MAX][CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 home_seed_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 home_seed_reason_count[CAKE_SELECT_REASON_MAX][CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 pressure_probe_total[CAKE_PRESSURE_PROBE_SITE_MAX][CAKE_PRESSURE_PROBE_OUTCOME_MAX]
	SEC(".bss") __attribute__((aligned(256)));
u64 pressure_probe_cpu_count[CAKE_PRESSURE_PROBE_SITE_MAX]
			   [CAKE_PRESSURE_PROBE_OUTCOME_MAX][CAKE_MAX_CPUS]
	SEC(".bss") __attribute__((aligned(256)));
u64 pressure_anchor_block_total[CAKE_PRESSURE_PROBE_SITE_MAX]
			       [CAKE_PRESSURE_ANCHOR_REASON_MAX]
	SEC(".bss") __attribute__((aligned(256)));
u64 pressure_anchor_block_cpu_count[CAKE_PRESSURE_PROBE_SITE_MAX]
				    [CAKE_PRESSURE_ANCHOR_REASON_MAX]
				    [CAKE_MAX_CPUS]
	SEC(".bss") __attribute__((aligned(256)));
u64 wake_direct_target_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_busy_target_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_busy_local_target_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_busy_remote_target_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_target_wait_ns[CAKE_WAKE_REASON_MAX][CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_target_wait_count[CAKE_WAKE_REASON_MAX][CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_target_wait_max_ns[CAKE_WAKE_REASON_MAX][CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_target_wait_bucket_count[CAKE_WAKE_REASON_MAX][CAKE_MAX_CPUS]
				 [CAKE_WAKE_BUCKET_MAX] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_edge_missed_updates SEC(".bss") __attribute__((aligned(256)));
u32 local_pending_est[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u32 local_pending_max[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 local_pending_insert_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 local_pending_run_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u32 blocked_owner_pid[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u32 blocked_waiter_pid[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 blocked_owner_wait_ns[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 blocked_owner_wait_count[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
u64 blocked_owner_wait_max_ns[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
#endif


/* get_local_stats: returns this CPU's stats struct.
 * Uses direct array index (0ns) instead of bpf_per_cpu_ptr (25ns). */
#ifndef CAKE_RELEASE
static __always_inline struct cake_stats *get_local_stats(void)
{
	u32 cpu = bpf_get_smp_processor_id();
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* get_local_stats_for: same as above but avoids a redundant
 * bpf_get_smp_processor_id() kfunc call when CPU ID is already known. */
static __always_inline struct cake_stats *get_local_stats_for(u32 cpu)
{
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}
#else
static __always_inline struct cake_stats *get_local_stats(void)
{
	return NULL;
}

static __always_inline struct cake_stats *get_local_stats_for(u32 cpu __maybe_unused)
{
	return NULL;
}
#endif

#ifndef CAKE_RELEASE
#define CAKE_DEBUG_RINGBUF_SIZE (512 * 1024)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CAKE_DEBUG_RINGBUF_SIZE);
} debug_ringbuf SEC(".maps");
#endif

static __always_inline u32 cake_cb_bucket(u64 dur_ns)
{
	if (dur_ns < 250)
		return CAKE_CB_BUCKET_LT250NS;
	if (dur_ns < 500)
		return CAKE_CB_BUCKET_LT500NS;
	if (dur_ns < 1000)
		return CAKE_CB_BUCKET_LT1US;
	if (dur_ns < 2000)
		return CAKE_CB_BUCKET_LT2US;
	if (dur_ns < 5000)
		return CAKE_CB_BUCKET_LT5US;
	if (dur_ns < 10000)
		return CAKE_CB_BUCKET_LT10US;
	return CAKE_CB_BUCKET_GE10US;
}

static __noinline void cake_record_cb(struct cake_stats *s, u32 cb_idx, u64 dur_ns)
{
	if (!s || cb_idx >= CAKE_CB_MAX)
		return;

	s->callback_hist[cb_idx][cake_cb_bucket(dur_ns)]++;
	if (dur_ns >= CAKE_SLOW_CALLBACK_NS)
		s->callback_slow[cb_idx]++;

	switch (cb_idx) {
	case CAKE_CB_SELECT:
		s->nr_select_cpu_calls++;
		break;
	case CAKE_CB_ENQUEUE:
		s->nr_enqueue_calls++;
		break;
	case CAKE_CB_DISPATCH:
		s->nr_dispatch_calls++;
		break;
	case CAKE_CB_RUNNING:
		s->nr_running_calls++;
		break;
	case CAKE_CB_STOPPING:
		s->nr_stopping_calls++;
		break;
	}
}

#ifndef CAKE_RELEASE
static __always_inline void cake_record_wake_wait(
	u64 *sum, u64 *count, u64 *max_ns, u32 reason, u64 wait_ns)
{
	if (!sum || !count || !max_ns || reason == CAKE_WAKE_REASON_NONE ||
	    reason >= CAKE_WAKE_REASON_MAX)
		return;

	sum[reason] += wait_ns;
	count[reason]++;
	if (wait_ns > max_ns[reason])
		max_ns[reason] = wait_ns;
}

static __always_inline u32 cake_wake_bucket(u64 wait_ns)
{
	if (wait_ns < 50 * 1000ULL)
		return CAKE_WAKE_BUCKET_LT50US;
	if (wait_ns < 200 * 1000ULL)
		return CAKE_WAKE_BUCKET_LT200US;
	if (wait_ns < 1000 * 1000ULL)
		return CAKE_WAKE_BUCKET_LT1MS;
	if (wait_ns < 5000 * 1000ULL)
		return CAKE_WAKE_BUCKET_LT5MS;
	return CAKE_WAKE_BUCKET_GE5MS;
}

static __always_inline void cake_record_select_decision_wait(
	struct cake_stats *s, u8 reason, u64 wait_ns)
{
	if (!s || reason == CAKE_SELECT_REASON_NONE ||
	    reason >= CAKE_SELECT_REASON_MAX)
		return;

	s->select_reason_wait_ns[reason] += wait_ns;
	s->select_reason_wait_count[reason]++;
	if (wait_ns > s->select_reason_wait_max_ns[reason])
		s->select_reason_wait_max_ns[reason] = wait_ns;
	s->select_reason_bucket_count[reason][cake_wake_bucket(wait_ns)]++;
}

static __always_inline void cake_record_select_decision_cost(
	struct cake_stats *s, u8 reason, u64 dur_ns)
{
	if (!s || reason == CAKE_SELECT_REASON_NONE ||
	    reason >= CAKE_SELECT_REASON_MAX)
		return;

	s->select_reason_select_ns[reason] += dur_ns;
	s->select_reason_select_count[reason]++;
	if (dur_ns > s->select_reason_select_max_ns[reason])
		s->select_reason_select_max_ns[reason] = dur_ns;
}

static __noinline void cake_record_select_migration(
	struct cake_stats *s, u8 path, u8 reason)
{
	if (!s)
		return;

	if (path > CAKE_SELECT_PATH_NONE && path < CAKE_SELECT_PATH_MAX)
		s->select_path_migration_count[path]++;
	if (reason > CAKE_SELECT_REASON_NONE && reason < CAKE_SELECT_REASON_MAX)
		s->select_reason_migration_count[reason]++;
}

static __always_inline u8 cake_kick_kind_from_flags(u64 kick_flags)
{
	return kick_flags == SCX_KICK_PREEMPT
		? CAKE_KICK_KIND_PREEMPT
		: CAKE_KICK_KIND_IDLE;
}

static __always_inline u8 cake_classify_home_place(
	struct cake_task_ctx __arena *tctx, u32 cpu)
{
	u16 home_cpu;
	u8 home_core;

	if (!tctx || cpu >= nr_cpus)
		return CAKE_PLACE_REMOTE;

	home_cpu = tctx->home_cpu;
	if (home_cpu < nr_cpus && cpu == home_cpu)
		return CAKE_PLACE_HOME_CPU;

	home_core = tctx->home_core;
	if (home_core < 0xFF &&
	    cpu_core_id[cpu & (CAKE_MAX_CPUS - 1)] == home_core)
		return CAKE_PLACE_HOME_CORE;

	if (home_cpu < nr_cpus &&
	    cpu_llc_id[cpu & (CAKE_MAX_CPUS - 1)] ==
		    cpu_llc_id[home_cpu & (CAKE_MAX_CPUS - 1)])
		return CAKE_PLACE_HOME_LLC;

	return CAKE_PLACE_REMOTE;
}

static __always_inline u8 cake_classify_waker_place(
	struct cake_task_ctx __arena *tctx, u32 cpu)
{
	u16 waker_cpu;

	if (!tctx || cpu >= nr_cpus || !tctx->telemetry.wakeup_source_pid)
		return CAKE_PLACE_REMOTE;

	waker_cpu = tctx->telemetry.waker_cpu;
	if (waker_cpu >= nr_cpus)
		return CAKE_PLACE_REMOTE;
	if (cpu == waker_cpu)
		return CAKE_PLACE_HOME_CPU;
	if (cpu_core_id[cpu & (CAKE_MAX_CPUS - 1)] ==
	    cpu_core_id[waker_cpu & (CAKE_MAX_CPUS - 1)])
		return CAKE_PLACE_HOME_CORE;
	if (cpu_llc_id[cpu & (CAKE_MAX_CPUS - 1)] ==
	    cpu_llc_id[waker_cpu & (CAKE_MAX_CPUS - 1)])
		return CAKE_PLACE_HOME_LLC;
	return CAKE_PLACE_REMOTE;
}

static __always_inline void cake_record_place_wait(
	struct cake_stats *s, u64 *sum, u64 *count, u64 *max_ns, u8 cls, u64 wait_ns)
{
	if (!s || cls >= CAKE_PLACE_CLASS_MAX)
		return;

	sum[cls] += wait_ns;
	count[cls]++;
	if (wait_ns > max_ns[cls])
		max_ns[cls] = wait_ns;
}

static __always_inline void cake_record_place_run(
	struct cake_stats *s, u64 *sum, u64 *count, u64 *max_ns, u8 cls, u64 run_ns)
{
	if (!s || cls >= CAKE_PLACE_CLASS_MAX)
		return;

	sum[cls] += run_ns;
	count[cls]++;
	if (run_ns > max_ns[cls])
		max_ns[cls] = run_ns;
}

static __always_inline void cake_record_task_home_wait(
	struct cake_task_ctx __arena *tctx, u8 cls, u64 wait_ns)
{
	u32 wait_us;

	if (!tctx || cls >= CAKE_PLACE_CLASS_MAX)
		return;

	tctx->telemetry.home_place_wait_ns[cls] += wait_ns;
	tctx->telemetry.home_place_wait_count[cls]++;
	wait_us = wait_ns / 1000;
	if (wait_us > tctx->telemetry.home_place_wait_max_us[cls])
		tctx->telemetry.home_place_wait_max_us[cls] = wait_us;
}
#else
static __always_inline void cake_record_select_decision_cost(
	struct cake_stats *s __maybe_unused,
	u8 reason __maybe_unused,
	u64 dur_ns __maybe_unused)
{
}
#endif

#ifndef CAKE_RELEASE
static __always_inline void cake_debug_atomic_inc(u64 *ptr)
{
	__sync_fetch_and_add(ptr, 1);
}
#endif

/* debug_events.bpf.h owns ringbuf emission and wake-edge sampling.
 * It depends on debug_ringbuf, wake_edge_missed_updates, and cake_debug_atomic_inc. */
#include "debug_events.bpf.h"

#ifndef CAKE_RELEASE
static __noinline void cake_record_select_choice(u8 reason, s32 prev_cpu,
						 s32 target_cpu)
{
	if (!CAKE_STATS_ACTIVE || reason == CAKE_SELECT_REASON_NONE ||
	    reason >= CAKE_SELECT_REASON_MAX)
		return;

	if (prev_cpu >= 0 && prev_cpu < CAKE_MAX_CPUS)
		cake_debug_atomic_inc(
			&select_reason_prev_count[reason][prev_cpu & (CAKE_MAX_CPUS - 1)]);

	if (reason == CAKE_SELECT_REASON_TUNNEL || target_cpu < 0 ||
	    target_cpu >= CAKE_MAX_CPUS)
		return;

	cake_debug_atomic_inc(
		&select_reason_target_count[reason][target_cpu & (CAKE_MAX_CPUS - 1)]);
}

static __always_inline void cake_record_home_seed(u16 home_cpu, u8 reason)
{
	if (!CAKE_STATS_ACTIVE || home_cpu >= CAKE_MAX_CPUS)
		return;

	home_cpu &= (CAKE_MAX_CPUS - 1);
	cake_debug_atomic_inc(&home_seed_count[home_cpu]);

	if (reason > CAKE_SELECT_REASON_NONE && reason < CAKE_SELECT_REASON_MAX)
		cake_debug_atomic_inc(&home_seed_reason_count[reason][home_cpu]);
}

#if !CAKE_LEAN_SCHED
static __noinline void cake_record_pressure_probe(u8 site, u8 outcome,
						  s32 anchor_cpu)
{
	if (!CAKE_STATS_ACTIVE || site >= CAKE_PRESSURE_PROBE_SITE_MAX ||
	    outcome >= CAKE_PRESSURE_PROBE_OUTCOME_MAX)
		return;

	cake_debug_atomic_inc(&pressure_probe_total[site][outcome]);

	if (anchor_cpu < 0 || anchor_cpu >= CAKE_MAX_CPUS)
		return;

	cake_debug_atomic_inc(
		&pressure_probe_cpu_count[site][outcome]
					 [anchor_cpu & (CAKE_MAX_CPUS - 1)]);
}

static __noinline void cake_record_pressure_anchor_block(
	u8 site, u8 reason, s32 anchor_cpu)
{
	if (!CAKE_STATS_ACTIVE || site >= CAKE_PRESSURE_PROBE_SITE_MAX ||
	    reason >= CAKE_PRESSURE_ANCHOR_REASON_MAX)
		return;

	cake_debug_atomic_inc(&pressure_anchor_block_total[site][reason]);

	if (anchor_cpu < 0 || anchor_cpu >= CAKE_MAX_CPUS)
		return;

	cake_debug_atomic_inc(
		&pressure_anchor_block_cpu_count[site][reason]
						[anchor_cpu & (CAKE_MAX_CPUS - 1)]);
}
#endif

static __always_inline void cake_record_local_insert(u64 dsq_id)
{
	u32 target_cpu;
	u32 pending;
	u32 max_seen;

	if (!CAKE_STATS_ACTIVE ||
	    (dsq_id & SCX_DSQ_LOCAL_ON) != SCX_DSQ_LOCAL_ON)
		return;

	target_cpu = (u32)(dsq_id & SCX_DSQ_LOCAL_CPU_MASK);
	if (target_cpu >= CAKE_MAX_CPUS)
		return;

	target_cpu &= (CAKE_MAX_CPUS - 1);
	cake_debug_atomic_inc(&local_pending_insert_count[target_cpu]);
	pending = __sync_fetch_and_add(&local_pending_est[target_cpu], 1) + 1;
	max_seen = READ_ONCE(local_pending_max[target_cpu]);
	if (pending > max_seen)
		WRITE_ONCE(local_pending_max[target_cpu], pending);
}

static __always_inline void cake_record_local_run(u32 cpu)
{
	u32 pending;

	if (!CAKE_STATS_ACTIVE)
		return;

	cpu &= (CAKE_MAX_CPUS - 1);
	cake_debug_atomic_inc(&local_pending_run_count[cpu]);
	pending = READ_ONCE(local_pending_est[cpu]);
	if (pending > 0)
		__sync_fetch_and_add(&local_pending_est[cpu], (u32)-1);
}

#if !CAKE_LEAN_SCHED
static __noinline void cake_record_wake_target_insert(
	u32 target_cpu, bool direct, bool same_cpu)
{
	if (!CAKE_STATS_ACTIVE || target_cpu >= CAKE_MAX_CPUS)
		return;

	target_cpu &= (CAKE_MAX_CPUS - 1);
	if (direct) {
		cake_debug_atomic_inc(&wake_direct_target_count[target_cpu]);
		return;
	}

	cake_debug_atomic_inc(&wake_busy_target_count[target_cpu]);
	if (same_cpu)
		cake_debug_atomic_inc(&wake_busy_local_target_count[target_cpu]);
	else
		cake_debug_atomic_inc(&wake_busy_remote_target_count[target_cpu]);
}
#endif

static __noinline void cake_record_target_wait(
	u8 reason, u16 target_cpu, u64 wait_ns)
{
	u32 cpu;
	u32 bucket;
	u64 max_seen;

	if (!CAKE_STATS_ACTIVE || target_cpu >= CAKE_MAX_CPUS)
		return;

	cpu = target_cpu & (CAKE_MAX_CPUS - 1);
	bucket = cake_wake_bucket(wait_ns);
	if (bucket >= CAKE_WAKE_BUCKET_MAX)
		return;

#define CAKE_RECORD_TARGET_WAIT_REASON(reason_idx)				\
	do {									\
		cake_debug_atomic_inc(&wake_target_wait_count[reason_idx][cpu]); \
		__sync_fetch_and_add(&wake_target_wait_ns[reason_idx][cpu], \
				     wait_ns);				\
		cake_debug_atomic_inc(					\
			&wake_target_wait_bucket_count[reason_idx][cpu][bucket]); \
		max_seen = READ_ONCE(wake_target_wait_max_ns[reason_idx][cpu]); \
		if (wait_ns > max_seen)					\
			WRITE_ONCE(wake_target_wait_max_ns[reason_idx][cpu], wait_ns); \
	} while (0)

	switch (reason) {
	case CAKE_WAKE_REASON_DIRECT:
		CAKE_RECORD_TARGET_WAIT_REASON(CAKE_WAKE_REASON_DIRECT);
		break;
	case CAKE_WAKE_REASON_BUSY:
		CAKE_RECORD_TARGET_WAIT_REASON(CAKE_WAKE_REASON_BUSY);
		break;
	case CAKE_WAKE_REASON_QUEUED:
		CAKE_RECORD_TARGET_WAIT_REASON(CAKE_WAKE_REASON_QUEUED);
		break;
	default:
		break;
	}

#undef CAKE_RECORD_TARGET_WAIT_REASON
}
#else
static __always_inline void cake_record_select_choice(u8 reason, s32 prev_cpu,
						      s32 target_cpu)
{
}

static __always_inline void cake_record_pressure_probe(u8 site, u8 outcome,
						      s32 anchor_cpu)
{
}

static __always_inline void cake_record_pressure_anchor_block(
	u8 site, u8 reason, s32 anchor_cpu)
{
}
#endif


#ifndef CAKE_RELEASE
static __always_inline void cake_record_lifecycle_us(
	u64 *sum_us,
	u64 *count,
	u64 delta_us)
{
	*sum_us += delta_us;
	(*count)++;
}

static __always_inline u32 cake_startup_delta_us(
	struct cake_task_ctx __arena *tctx,
	u64 now_ns)
{
	u32 init_us = tctx->telemetry.startup_latency_us;
	u32 now_us = (u32)(now_ns / 1000ULL);

	return now_us - init_us;
}

static __always_inline bool cake_startup_trace_open(
	struct cake_task_ctx __arena *tctx)
{
	return tctx && tctx->telemetry.total_runs == 0 &&
	       tctx->telemetry.startup_latency_us > 0 &&
	       !(tctx->telemetry.startup_phase_mask & CAKE_STARTUP_MASK_RUNNING);
}

static __always_inline void cake_record_startup_phase(
	struct cake_task_ctx __arena *tctx,
	u8 phase,
	u8 mask)
{
	if (!cake_startup_trace_open(tctx))
		return;

	tctx->telemetry.startup_phase_mask |= mask;
	if (tctx->telemetry.startup_first_phase == CAKE_STARTUP_PHASE_NONE)
		tctx->telemetry.startup_first_phase = phase;
}

#if !CAKE_LEAN_SCHED
static __noinline void cake_record_startup_enqueue(
	struct cake_task_ctx __arena *tctx,
	struct cake_stats *s,
	u64 enqueue_start_ns)
{
	bool first_enqueue;

	if (!cake_startup_trace_open(tctx))
		return;

	first_enqueue =
		!(tctx->telemetry.startup_phase_mask & CAKE_STARTUP_MASK_ENQUEUE);
	cake_record_startup_phase(tctx, CAKE_STARTUP_PHASE_ENQUEUE,
				  CAKE_STARTUP_MASK_ENQUEUE);
	if (first_enqueue) {
		u32 delta_us = cake_startup_delta_us(tctx, enqueue_start_ns);

		tctx->telemetry.startup_enqueue_us = delta_us;
		cake_record_lifecycle_us(&s->lifecycle_init_enqueue_us,
					 &s->lifecycle_init_enqueue_count,
					 delta_us);
	}
}
#endif

static __noinline void cake_record_startup_select(
	struct cake_task_ctx __arena *tctx,
	struct cake_stats *s,
	u64 select_start_ns)
{
	bool first_select;

	if (!cake_startup_trace_open(tctx))
		return;

	first_select =
		!(tctx->telemetry.startup_phase_mask & CAKE_STARTUP_MASK_SELECT);
	cake_record_startup_phase(tctx, CAKE_STARTUP_PHASE_SELECT,
				  CAKE_STARTUP_MASK_SELECT);
	if (first_select) {
		u32 delta_us = cake_startup_delta_us(tctx, select_start_ns);

		tctx->telemetry.startup_select_us = delta_us;
		cake_record_lifecycle_us(&s->lifecycle_init_select_us,
					 &s->lifecycle_init_select_count,
					 delta_us);
	}
}
#endif


#ifndef CAKE_RELEASE
static __always_inline u32 cake_class_reason_bit(u32 reason)
{
	if (reason >= CAKE_WAKE_CLASS_REASON_MAX)
		return 0;
	return 1U << reason;
}

static __always_inline void cake_record_wake_class_reasons(
	struct cake_stats *stats, u32 reason_mask)
{
#pragma unroll
	for (u32 reason = 0; reason < CAKE_WAKE_CLASS_REASON_MAX; reason++) {
		if (reason_mask & cake_class_reason_bit(reason))
			stats->wake_class_reason_count[reason]++;
	}
}

static __noinline u8 cake_shadow_classify_task(
	struct task_struct *p,
	struct cake_task_ctx __arena *tctx,
	u32 *reason_mask)
{
	u32 mask = 0;

	if (p->se.avg.util_avg < 64)
		mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LOW_UTIL);
	if (p->prio < 120 || p->scx.weight > 120)
		mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LATENCY_PRIO);

	if (tctx) {
		u64 runs = tctx->telemetry.total_runs;
		u64 runtime = tctx->telemetry.total_runtime_ns;
		u64 full = tctx->telemetry.quantum_full_count;
		u64 preempt = tctx->telemetry.quantum_preempt_count;
		u64 q_total = full + tctx->telemetry.quantum_yield_count + preempt;

		if (runs) {
			u64 avg_runtime = runtime / runs;

			if (avg_runtime) {
				if (runs >= 32 && avg_runtime <= 100000)
					mask |= cake_class_reason_bit(
						CAKE_WAKE_CLASS_REASON_SHORT_RUN);
				if (runs >= 256 && avg_runtime <= 250000)
					mask |= cake_class_reason_bit(
						CAKE_WAKE_CLASS_REASON_WAKE_DENSE);
			}
		}

		if (q_total >= 32) {
			if (full * 100 >= q_total * 20)
				mask |= cake_class_reason_bit(
					CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY);
			if (preempt * 100 >= q_total * 10)
				mask |= cake_class_reason_bit(
					CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY);
		}
	}

	if (reason_mask)
		*reason_mask = mask;

	if ((mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LATENCY_PRIO)) ||
	    ((mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_SHORT_RUN)) &&
	     (mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_WAKE_DENSE))))
		return CAKE_WAKE_CLASS_SHIELD;
	if (mask & (cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY) |
		    cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY)))
		return CAKE_WAKE_CLASS_CONTAIN;
	return CAKE_WAKE_CLASS_NORMAL;
}

static __always_inline u8 cake_shadow_busy_preempt_decision(
	u8 wakee_class, u8 owner_class, u8 target_pressure)
{
	if (wakee_class == CAKE_WAKE_CLASS_SHIELD)
		return CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	if (owner_class == CAKE_WAKE_CLASS_CONTAIN)
		return CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	if (target_pressure >= 64)
		return CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	return CAKE_BUSY_PREEMPT_SHADOW_SKIP;
}

#define CAKE_BUSY_WAKE_WAIT_TAIL_NS 200000ULL

#if !CAKE_LEAN_SCHED
static __noinline void cake_record_busy_preempt_shadow(
	struct cake_stats *stats,
	u8 decision,
	u8 wakee_class,
	u8 owner_class,
	bool wake_target_local)
{
	if (!stats)
		return;
	if (decision < CAKE_BUSY_PREEMPT_SHADOW_MAX)
		stats->busy_preempt_shadow_count[decision]++;
	if (wakee_class < CAKE_WAKE_CLASS_MAX)
		stats->busy_preempt_shadow_wakee_class_count[wakee_class]++;
	if (owner_class < CAKE_WAKE_CLASS_MAX)
		stats->busy_preempt_shadow_owner_class_count[owner_class]++;
	if (wake_target_local)
		stats->busy_preempt_shadow_local++;
	else
		stats->busy_preempt_shadow_remote++;
}
#endif

#endif

#endif /* __CAKE_TELEMETRY_BPF_H */
