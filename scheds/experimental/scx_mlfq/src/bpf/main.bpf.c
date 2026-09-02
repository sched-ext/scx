/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multilevel Feedback Queue scheduling with per-queue EEVDF virtual time.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/*
 * This file defines the BPF maps, volatiles, and ops dispatch table.
 * The scheduling logic is organized into separate modules included below,
 * in dependency order:
 *   vtime.bpf.c      - EEVDF virtual-time substrate (virtual clock, placement)
 *   classify.bpf.c   - tree inference, EMA gauge, queue mapping, hysteresis
 *   lifecycle.bpf.c  - task state, init_task/enable/running/stopping/exit_task/cpu_release
 *   rtdl.bpf.c       - realtime/DL takeover tracking, sched_switch hook, evacuation
 *   select_cpu.bpf.c - CPU selection
 *   enqueue.bpf.c    - enqueue routing, aging, wakeup preemption
 *   dispatch.bpf.c   - queue service with quotas, cross-CPU stealing, keep path
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Per-task state, allocated in init_task()/enable() and freed in
 * exit_task() (BPF task storage is reclaimed on task exit regardless).
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per-queue virtual-clock state, keyed by queue id 1..3 (slot 0 unused).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_NR_QUEUES + 1);
	__type(key, u32);
	__type(value, struct queue_ctx);
} queue_ctx_stor SEC(".maps");

/*
 * Per-CPU state, keyed by cpu id. Bounds are validated against
 * nr_cpu_ids (<= MLFQ_MAX_CPUS, checked in init()).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_CPUS);
	__type(key, u32);
	__type(value, struct mlfq_cpu_state);
} cpu_state_stor SEC(".maps");

/*
 * Per-CPU Q1 occupancy for SMT isolation, keyed by cpu id.
 *
 * One byte per CPU padded to 8 bytes for map value alignment and to
 * keep per-CPU slots isolated from mlfq_stats BSS. The map is
 * BPF_MAP_TYPE_ARRAY with 8B values, so bpf_map_lookup_elem on a
 * sibling's key returns that CPU's occupancy (cross-CPU visibility).
 * Updates are plain stores to the CPU's own slot without __sync_*
 * on a shared line. Isolation from mlfq_stats is by map storage
 * (ARRAY, not BSS), so no false sharing dirties the stats line.
 * The rodata tables (mlfq_cpu_sibling, etc.) remain.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_CPUS);
	__type(key, u32);
	__type(value, struct mlfq_q1_occupancy);
} q1_occupancy SEC(".maps");

/*
 * Per-CPU realtime-occupancy state, keyed by cpu id. The flags reflect
 * the class of the last task that ran on the CPU (see rtdl.bpf.c). The
 * state is written by the sched_switch hook and read by the enqueue
 * redirect and the CPU selection.
 */
struct mlfq_rtdl_state_map rtdl_state_stor SEC(".maps");

/*
 * Op-latency histogram, keyed by op id (MLFQ_OP_LAT_* in intf.h). A
 * per-CPU array so the counters never contend. The Rust front-end sums
 * the CPUs for the stats output.
 */
struct mlfq_op_lat_map mlfq_op_lat SEC(".maps");

/*
 * Per-CPU wakeup-arrival counters (see mlfq_wakeup_counters in
 * intf.h). Each CPU owns its own slot, so the wakeup path bumps its
 * slot with no locked operation on a shared line and the u64 totals
 * cannot wrap. The adaptation fold consumes the window slots once per
 * step and the Rust front-end sums the totals for the stats output.
 */
struct mlfq_wakeup_stats_map mlfq_wakeup_stats SEC(".maps");

/*
 * Scheduler-wide state in .bss. The stats counters are shared across
 * CPUs and updated with atomic RMWs; volatile stops the compiler from
 * caching a value in a register across the atomic operations.
 * nr_cpu_ids is written once in init() before any other callback runs.
 */
volatile u64 nr_cpu_ids;
volatile u32 mlfq_steal_scan;
volatile u32 mlfq_idle_count;

/*
 * Per-LLC and per-queue runnable gauges, maintained by
 * mlfq_runnable_enter()/mlfq_runnable_exit() at every tracked insert
 * and leave-runnable event. mlfq_llc_runnable[llc] is the number of
 * tracked runnable tasks owned by each LLC domain; mlfq_queue_runnable
 * is the same count split per queue (index 0 unused, 1..3 = Q1..Q3);
 * mlfq_llc_idle[llc] mirrors mlfq_idle_count per domain, the steering
 * gate of the least-loaded-LLC placement step. The counts are advisory:
 * they cover tracked tasks only (the drop paths never touch them) and
 * drive placement heuristics, never correctness. The gauges are
 * zero-default, so the unpopulated state (LLC awareness disabled)
 * leaves them untouched by construction.
 * Declared before mlfq_stats so the tree-ctrl cache-line isolation
 * reasoning below stays accurate.
 */
volatile u32 mlfq_llc_runnable[MLFQ_MAX_LLCS];
volatile u32 mlfq_queue_runnable[MLFQ_NR_QUEUES + 1];
volatile u32 mlfq_llc_idle[MLFQ_MAX_LLCS];
volatile struct mlfq_stats mlfq_stats;

/*
 * GPU submit gauges. mlfq_gpu_submit_total counts every deduped
 * quantised gpu_submit bump (one per 10 ms window), mlfq_gpu_trace_mask
 * records which tracepoints attached (bit0 amdgpu_cs, bit1
 * amdgpu_cs_ioctl, bit2 gpu_sched) latched on every hit for the web
 * metrics. The total is deduped, not raw hits, so a single job that
 * fires 2-3 tracepoints in burst counts once.
 */
volatile u64 mlfq_gpu_submit_total;
volatile u32 mlfq_gpu_trace_mask;

/*
 * System wakeup gauges and the effective adaptation state, placed here
 * so the tree-ctrl cache-line isolation below is preserved.
 *
 * Cache-line discipline. The gauge block is written on the hot path by
 * the latency-EMA climb/decay pair at every measured wakeup episode
 * (the wakeup arrival counters live in the per-CPU map
 * mlfq_wakeup_stats, so they never touch this line). The adaptation
 * block is written only by the 1 Hz adaptation step and by
 * mlfq_init(). The classification hot path reads the adaptation block
 * (the effective band edges and the preemption guard) on every wakeup,
 * so the two blocks are pinned to separate 64-byte lines and the
 * per-wakeup gauge writes must never dirty the line the classification
 * reads.
 */
volatile struct mlfq_sys_gauge mlfq_sys_gauge __attribute__((aligned(64)));
volatile struct mlfq_adapt_state mlfq_adapt_state __attribute__((aligned(64)));

/*
 * Published MLFQ regression tree, double-buffered in a two-entry array
 * map (the type is declared in intf.h). The daemon writes the inactive
 * entry, then flips the meta (mlfq_tree_ctrl.meta) last; the BPF side
 * looks up the active entry once per inference.
 */
struct mlfq_tree_map mlfq_tree_map SEC(".maps");

/*
 * Published-tree control state (meta + sample limiter), committed by the
 * Rust front-end (the type is declared in intf.h). bss defaults zeroed,
 * which is the untrained state (trained bit clear): the prediction path
 * falls back to the EMA until the first tree is committed. The line is
 * read by the inference and the emission hot paths but written only by
 * the publish and the sample-window winner, so it must not share a line
 * with the write-hammered mlfq_stats counters. The
 * __attribute__((aligned(64))) on this instance pins it to a dedicated
 * 64-byte cache line, so the compiler places it on the line boundary
 * following mlfq_stats (256 bytes, a whole number of lines), and the
 * two blocks never share a line.
 */
volatile struct mlfq_tree_ctrl mlfq_tree_ctrl __attribute__((aligned(64)));

/*
 * Training-sample ring buffer. The stopping path emits one completed
 * sample per rate-limit window (mlfq_tree_ctrl.sample_last_at); the
 * userspace daemon drains it every 100 ms for the regression-tree
 * training. 1 MB holds about 12.4k samples of 84 bytes (1.3.11 ABI),
 * roughly 6.2 s of emission at the global rate limit, which absorbs a
 * multi-second daemon stall; drop-on-full is the natural backpressure
 * when the daemon cannot keep up, and the emission rate limits keep the
 * steady-state rate at one sample per MLFQ_TREE_SAMPLE_RATE_LIMIT_NS
 * globally and one per MLFQ_TREE_PER_TASK_LIMIT_NS per task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MLFQ_SAMPLE_RING_BYTES);
} mlfq_samples SEC(".maps");

/*
 * Placement bitmaps (see select_cpu.bpf.c).
 *
 * mlfq_primary_bitmap[0] holds the primary (big-core) CPU set;
 * mlfq_llc_bitmaps[llc_id] holds the CPU membership of one LLC domain.
 * Both are plain u64 bitmaps in ARRAY map values. The Rust front-end
 * writes them after load, and the CPU-selection path reads them directly
 * as map values, without any kernel cpumask kptr machinery or RCU
 * protection.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_bitmap);
} mlfq_primary_bitmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_LLCS);
	__type(key, u32);
	__type(value, struct mlfq_bitmap);
} mlfq_llc_bitmaps SEC(".maps");

/*
 * Per-LLC CPU lists (see intf.h). mlfq_llc_cpus[llc_id] holds the CPUs
 * of one LLC domain, the Tier-A same-LLC steal window of the dispatch
 * path. The Rust front-end writes the values after load, and the
 * dispatch path reads them directly as map values. An
 * unpopulated map entry (write failed or LLC awareness disabled) reads
 * as nr == 0, which skips the Tier-A scan and keeps today's behavior.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_LLCS);
	__type(key, u32);
	__type(value, struct mlfq_llc_cpu_list);
} mlfq_llc_cpus SEC(".maps");

/*
 * Constants: rodata. The declared defaults match the constants in
 * intf.h and are written by the Rust front-end before load; the section
 * is read-only afterwards, and the compiler must not fold them as
 * compile-time constants. The veristat configs supply the same values
 * as verification inputs.
 */
const volatile u64 mlfq_q1_slice_ns = MLFQ_Q1_SLICE_NS;
const volatile u64 mlfq_q2_slice_ns = MLFQ_Q2_SLICE_NS;
const volatile u64 mlfq_q3_slice_ns = MLFQ_Q3_SLICE_NS;
const volatile u64 mlfq_budget_max_ns = MLFQ_BUDGET_MAX_NS;
const volatile u64 mlfq_alpha = MLFQ_ALPHA;
const volatile u64 mlfq_t_l_ns = MLFQ_T_L_NS;
const volatile u64 mlfq_t_h_ns = MLFQ_T_H_NS;
const volatile u64 mlfq_ema_half_life_ns = MLFQ_EMA_HALF_LIFE_NS;
const volatile u64 mlfq_aging_period_ns = MLFQ_AGING_PERIOD_NS;
const volatile u64 mlfq_short_sleep_ns = MLFQ_SHORT_SLEEP_NS;
const volatile u64 mlfq_short_sleep_rate_limit_ns = MLFQ_SHORT_SLEEP_RATE_LIMIT_NS;
const volatile u64 mlfq_hysteresis_sleep_ns = MLFQ_HYSTERESIS_SLEEP_NS;
const volatile u64 mlfq_long_sleep_ns = MLFQ_LONG_SLEEP_NS;
const volatile u64 mlfq_sameq_preempt_min_run_ns = MLFQ_SAMEQ_PREEMPT_MIN_RUN_NS;
const volatile u64 mlfq_preempt_slice_ns = MLFQ_PREEMPT_SLICE_NS;
/*
 * The tree band edges, as rodata: the effective values of the
 * adaptation are computed from these runtime bases (the same treatment
 * as the EMA edges above), so the base must exist after load. The
 * intf.h enum constants remain the compile-time defaults and the source
 * of the emitted-label clamp.
 */
const volatile u64 mlfq_tree_t_int_ns = MLFQ_TREE_T_INT_NS;
const volatile u64 mlfq_tree_t_bound_ns = MLFQ_TREE_T_BOUND_NS;
/*
 * Master gate of the threshold adaptation, written by the Rust
 * front-end before load. When false the adaptation step returns
 * immediately, the effective values stay at their init-time base
 * (mlfq_init copies the rodata bases into the effective bss state), and
 * the classification consumes exactly the fixed thresholds.
 */
const volatile bool mlfq_adapt_enabled = true;
const volatile u32 mlfq_q1_quota = MLFQ_Q1_QUOTA;
const volatile u32 mlfq_q2_quota = MLFQ_Q2_QUOTA;
const volatile u32 mlfq_dispatch_max_batch = MLFQ_DISPATCH_MAX_BATCH;
const volatile u64 mlfq_rtdl_drain_interval_ns = MLFQ_RTDL_DRAIN_INTERVAL_NS;

/*
 * True when every CPU has the same capacity (uniform-capacity system). The
 * CPU-selection fast path skips all hybrid logic in that case. Written by
 * the Rust front-end from the discovered topology.
 */
const volatile bool mlfq_primary_all = true;

/*
 * Cache-domain data written by the Rust front-end before load. mlfq_nr_llcs
 * is the number of LLC domains with usable masks (0 disables the LLC step
 * entirely). mlfq_llc_has_primary marks LLCs that contain at least one
 * primary (big) core; mlfq_cpu_llc maps a CPU to its LLC domain
 * (MLFQ_MAX_LLCS, the sentinel, when the CPU is unknown or unmapped).
 */
const volatile u32 mlfq_nr_llcs;
const volatile u8 mlfq_llc_has_primary[MLFQ_MAX_LLCS];
const volatile u32 mlfq_cpu_llc[MLFQ_MAX_CPUS];

/*
 * Gates the saturation fast path in select_cpu() on the idle-CPU count
 * maintained by ops.update_idle(). Written by the Rust front-end before
 * load. It is 1 only when the kernel keeps its built-in idle tracking alongside
 * the callback (the KEEP_BUILTIN_IDLE flag). It is 0 on kernels without it, so
 * the lean path is dead and the behavior is unchanged.
 */
const volatile u32 mlfq_idle_tracking = 0;

/*
 * SMT sibling preference table, written by the Rust front-end
 * before load. mlfq_cpu_sibling[cpu] is the lowest-id other CPU sharing
 * cpu's physical core, or the CPU itself when the core is unpaired.
 * mlfq_smt_on is true only when at least one sibling differs from its
 * CPU, and it gates the sibling step. With SMT off or the table
 * unwritten (all-zero rodata can never fire it, and the write is
 * atomic pre-load) the step is dead and placement is unchanged.
 */
const volatile bool mlfq_smt_on = false;
const volatile u32 mlfq_cpu_sibling[MLFQ_MAX_CPUS];
/*
 * Core id per CPU, written by the Rust front-end before load.
 * Reserved for future topology debug/dump (e.g. BPF debug helper
 * validating sibling pairs or veristat topology introspection);
 * intentionally retained even though is_smt_sibling_q1_busy() uses
 * only mlfq_cpu_sibling today. Keeping the table costs 4 KiB rodata
 * and no extra BPF instructions until a debug helper reads it, so
 * no object inflation until wired. Do not remove as "dead".
 */
const volatile u32 mlfq_cpu_core[MLFQ_MAX_CPUS];

/* Reserved helper for mlfq_cpu_core; kept for future topology debug.
 * Marked unused to keep the rodata documented without warning.
 */
static __always_inline __attribute__((unused)) u32 mlfq_core_of_cpu(u32 cpu)
{
	if (cpu >= MLFQ_MAX_CPUS)
		return MLFQ_MAX_CPUS;
	return mlfq_cpu_core[cpu];
}

/*
 * Largest-LLC domain id for the Q1 placement bias, written by the
 * Rust front-end before load. The sentinel MLFQ_MAX_LLCS means "no
 * bias. Discovery failed, the machine has fewer than two LLC domains,
 * or two domains tie for the largest cache size. The bias is Q1-only
 * and non-exclusive, trading clock speed for cache capacity. The
 * sentinel keeps the step dead unless a strictly-largest domain exists.
 */
const volatile u32 mlfq_llc_largest = MLFQ_MAX_LLCS;

/*
 * Q1 occupancy helpers - Observer for per-CPU occupancy, Strategy for veto.
 *
 * The occupancy is tracked per-CPU in the q1_occupancy ARRAY map, one
 * 8-byte slot per CPU. Updates are plain stores to the CPU's own slot,
 * never a __sync_* on a BSS shared line, so no false sharing dirties
 * mlfq_stats. The sibling veto is logical: mlfq_cpu_sibling[CPU]
 * gives the sibling, mlfq_cpu_core[CPU] the core id, not a word bit.
 * is_smt_sibling_q1_busy checks the logical sibling's occupancy.
 */

/**
 * mlfq_q1_is_occupied - Test if CPU runs a Q1 task.
 * @cpu: CPU id.
 *
 * Return: true if occupancy slot is set.
 */
static __always_inline bool mlfq_q1_is_occupied(u32 cpu)
{
	struct mlfq_q1_occupancy *occ;
	u32 key = cpu;

	if (cpu >= MLFQ_MAX_CPUS)
		return false;
	occ = bpf_map_lookup_elem(&q1_occupancy, &key);
	return occ && occ->occupied;
}

/**
 * mlfq_q1_set - Mark or clear Q1 occupancy for CPU.
 * @cpu: CPU id.
 * @occupied: true to set, false to clear.
 *
 * Plain per-CPU store, no __sync_* on shared BSS line. The slot is
 * owned by @cpu, so no contention. Cache-line isolation from
 * mlfq_stats is preserved by the map storage.
 */
static __always_inline void mlfq_q1_set(u32 cpu, bool occupied)
{
	struct mlfq_q1_occupancy *occ;
	u32 key = cpu;

	if (cpu >= MLFQ_MAX_CPUS)
		return;
	occ = bpf_map_lookup_elem(&q1_occupancy, &key);
	if (occ)
		occ->occupied = occupied ? 1 : 0;
}

/**
 * is_smt_sibling_q1_busy - Logical sibling Q1 veto.
 * @cpu: Candidate CPU.
 *
 * Uses rodata mlfq_cpu_sibling logical lookup, not word-bit
 * arithmetic. When SMT is off or sibling is self, returns false.
 *
 * Return: true if sibling runs Q1.
 */
static __always_inline bool is_smt_sibling_q1_busy(s32 cpu)
{
	u32 sib;

	if (!mlfq_smt_on || cpu < 0 || cpu >= (s32)MLFQ_MAX_CPUS)
		return false;
	sib = mlfq_cpu_sibling[(u32)cpu];
	if (sib >= MLFQ_MAX_CPUS || sib == (u32)cpu)
		return false;
	return mlfq_q1_is_occupied(sib);
}

/*
 * mlfq_wakeup_window_fold - Consume the per-CPU wakeup windows.
 *
 * Sums every CPU's window slot and zeroes each one with an atomic
 * exchange, so a wakeup racing the fold lands in the next window
 * instead of being lost or double-counted. The caller is the 1 Hz
 * compare-and-swap winner, so the loop runs at most once per second.
 * A failed slot lookup is skipped. Each slot holds at most one fold
 * interval of arrivals, since the exchange zeroes it at every fold,
 * so the u64 sum stays far below overflow.
 *
 * Return: The arrivals since the last fold, as a u64 sum.
 */
static __always_inline u64 mlfq_wakeup_window_fold(void)
{
	struct mlfq_wakeup_counters *wc;
	u64 total = 0;
	u32 key = 0, cpu, nr_cpus;

	/* Snapshot the checked CPU count once, as mlfq_init does. */
	nr_cpus = (u32)nr_cpu_ids;
	bpf_for(cpu, 0, nr_cpus) {
		wc = bpf_map_lookup_percpu_elem(&mlfq_wakeup_stats, &key, cpu);
		if (!wc)
			continue;
		total += __atomic_exchange_n(&wc->window, 0, __ATOMIC_RELAXED);
	}
	return total;
}

/*
 * mlfq_adapt_step - Run one adaptation step and fold the rate gauge.
 * @now: Current time.
 * @elapsed: Wall time since the last step, nsecs.
 *
 * Recomputes the effective band edges and the preemption-residency
 * guard from the current gauges and the slew-limited shift. The shift
 * is slewed toward the gauge-derived target (at most
 * MLFQ_ADAPT_MAX_STEP per step) and the effective values are clamped to
 * the hard floor/ceiling ranges of each band, so the queue semantics
 * can never invert regardless of the gauges. The rate gauge is folded
 * here, once per step, so its EMA update is rate-limited by the same
 * cadence as the adaptation.
 *
 * The step is pure state math on the gauges and the bases. The only
 * consumer-visible effect is the effective band edges the
 * classification reads, so the step cannot disturb any safety
 * machinery.
 */
static __always_inline void mlfq_adapt_step(u64 now, u64 elapsed)
{
	s64 target;

	mlfq_sys_gauge.rate_ema =
		mlfq_sys_rate_step(mlfq_sys_gauge.rate_ema,
				   (u32)mlfq_wakeup_window_fold(), elapsed);
	mlfq_sys_gauge.adapt_steps++;

	target = mlfq_adapt_shift_target(mlfq_sys_gauge.lat_ema,
					 mlfq_sys_gauge.rate_ema);
	mlfq_adapt_state.shift_fp = mlfq_adapt_slew(mlfq_adapt_state.shift_fp,
						    target);

	mlfq_adapt_state.t_l_eff_ns = mlfq_adapt_band(
		mlfq_t_l_ns, mlfq_adapt_state.shift_fp,
		MLFQ_ADAPT_T_L_FLOOR_NS, MLFQ_ADAPT_T_L_CEIL_NS);
	mlfq_adapt_state.t_h_eff_ns = mlfq_adapt_band(
		mlfq_t_h_ns, mlfq_adapt_state.shift_fp,
		MLFQ_ADAPT_T_H_FLOOR_NS, MLFQ_ADAPT_T_H_CEIL_NS);
	mlfq_adapt_state.t_int_eff_ns = mlfq_adapt_band(
		mlfq_tree_t_int_ns, mlfq_adapt_state.shift_fp,
		MLFQ_ADAPT_T_INT_FLOOR_NS, MLFQ_ADAPT_T_INT_CEIL_NS);
	mlfq_adapt_state.t_bnd_eff_ns = mlfq_adapt_band(
		mlfq_tree_t_bound_ns, mlfq_adapt_state.shift_fp,
		MLFQ_ADAPT_T_BND_FLOOR_NS, MLFQ_ADAPT_T_BND_CEIL_NS);

#if MLFQ_CHECK
	if (!mlfq_check_bands(mlfq_adapt_state.t_l_eff_ns,
			      mlfq_adapt_state.t_h_eff_ns,
			      mlfq_adapt_state.t_int_eff_ns,
			      mlfq_adapt_state.t_bnd_eff_ns))
		scx_bpf_error("adaptation bands out of order: T_L=%llu T_H=%llu "
			      "T_INT=%llu T_BND=%llu",
			      mlfq_adapt_state.t_l_eff_ns,
			      mlfq_adapt_state.t_h_eff_ns,
			      mlfq_adapt_state.t_int_eff_ns,
			      mlfq_adapt_state.t_bnd_eff_ns);
#endif
}

/*
 * mlfq_maybe_adapt_step - Rate-limited adaptation step entry point.
 * @now: Current time.
 *
 * Runs at most once per MLFQ_ADAPT_MIN_INTERVAL_NS, gated by the
 * compare-and-swap single-winner pattern. The first caller past the
 * cadence wins the step and the rest fall through, so the step is
 * never run twice for one window even under load on every CPU. The
 * gate is checked from both callbacks that fire under load regardless
 * of direction (stopping and dispatch). On an idle system neither
 * fires, the gauges hold their values and the effective values stay
 * until the first switch steps them.
 *
 * The winner folds the accumulated wakeup waits into the latency
 * gauge before anything else, so the gauge stays live even with the
 * adaptation disabled. The rate fold and the shift step run only when
 * enabled. With the adaptation disabled, the rate EMA stays frozen, the
 * effective values stay at the init-time bases and the classification
 * consumes exactly the fixed thresholds.
 */
static __always_inline void mlfq_maybe_adapt_step(u64 now)
{
	u64 last, elapsed;

	last = mlfq_sys_gauge.step_at;
	if (mlfq_time_before(now, last + MLFQ_ADAPT_MIN_INTERVAL_NS))
		return;
	if (__sync_val_compare_and_swap(&mlfq_sys_gauge.step_at, last, now) !=
	    last)
		return;

	/* The winner measures the fold window against the pre-swap stamp. */
	elapsed = mlfq_time_before(now, last) ? 0 : now - last;
	mlfq_sys_gauge.lat_ema = mlfq_sys_lat_fold(
		mlfq_sys_gauge.lat_ema, mlfq_sys_gauge.wait_total,
		mlfq_sys_gauge.wait_count, elapsed,
		MLFQ_SYS_GAUGE_HALF_LIFE_NS, MLFQ_SYS_LAT_MAX_NS);
	mlfq_sys_gauge.wait_total = 0;
	mlfq_sys_gauge.wait_count = 0;

	if (!mlfq_adapt_enabled)
		return;
	mlfq_adapt_step(now, elapsed);
}

static struct task_ctx *mlfq_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

static struct task_ctx *mlfq_alloc_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline struct mlfq_cpu_state *mlfq_lookup_cpu_state(s32 cpu)
{
	u32 key;

	if (cpu < 0)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}

/*
 * mlfq_llc_of_cpu - LLC domain of a CPU, validated against the populated set.
 * @cpu: CPU id.
 *
 * Returns the rodata cpu->llc mapping when @cpu is in range and the
 * value is a populated domain id, MLFQ_MAX_LLCS (the hard bound of the
 * runnable gauges) otherwise. The sentinel turns every accounting
 * helper call into a no-op, so with LLC awareness disabled
 * (mlfq_nr_llcs == 0) every call yields it and the gauges never move.
 * The unpopulated state reproduces current behavior by construction.
 * The hard bound is checked as well as the populated count. An unmapped
 * CPU reads the MLFQ_MAX_LLCS sentinel from the front-end's default,
 * and a front-end bug writing mlfq_nr_llcs above MLFQ_MAX_LLCS must
 * not validate the sentinel (or a larger id) into a domain index.
 */
static __always_inline u32 mlfq_llc_of_cpu(u32 cpu)
{
	u32 llc;

	if (cpu >= MLFQ_MAX_CPUS)
		return MLFQ_MAX_LLCS;
	llc = mlfq_cpu_llc[cpu];
	return llc < MLFQ_MAX_LLCS && llc < mlfq_nr_llcs ? llc : MLFQ_MAX_LLCS;
}

#include "vtime.bpf.c"
#include "classify.bpf.c"
#include "lifecycle.bpf.c"
#include "rtdl.bpf.c"
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"

/*
 * gpu_submit tracepoints: raw tracepoints, about 200 insn, no loop.
 * amdgpu_cs and amdgpu_cs_ioctl cover AMD, and gpu_scheduler
 * drm_sched_job_queue covers any driver that uses gpu_sched,
 * including nouveau for your RTX 3050, so both vendors are handled.
 * Each logical GPU submission can fire 2-3 tracepoints in burst
 * (amdgpu_cs, amdgpu_cs_ioctl, gpu_sched) within microseconds; the
 * per-task dedup window (MLFQ_TREE_PER_TASK_LIMIT_NS, 10 ms) ensures
 * one quantised bump per window, so a single job does not saturate
 * gpu_submit 0..4. The window mirrors the per-task training-sample
 * limiter (fair.c-style time_before check), keeping
 * mlfq_gpu_submit_total as deduped bumps, not raw hits, and the
 * MLFQ_TF_DRM_WAKE flag as a deduped wake hint. The trace mask is
 * latched on every hit (even deduped) so the web metrics show which
 * tracepoints are present. Per-queue bounded-lag is preserved,
 * verifier 1M/512B, no new loop, and the handlers are knob free and
 * enabled by default when the tracepoints exist.
 * The SEC is "tracepoint/..." without "?" and without tp_btf, so
 * the attach uses the raw tracepoint and does not require BTF for
 * module tracepoints. The programs remain optional via userspace
 * autoload gating (bpf_program__set_autoload to false when the
 * tracepoint is absent), so load never hard-fails.
 */
static __always_inline void mlfq_gpu_submit_inc(struct task_struct *p,
						  u32 trace_bit)
{
	struct task_ctx *tctx = mlfq_lookup_task_ctx(p);
	u64 now;

	if (!tctx)
		return;
	/* Latch the trace mask on every hit, even deduped, so the
	 * gauge reflects which tracepoints are present on the machine.
	 * The dedup window gates only the quantised bump and the total.
	 */
	__sync_fetch_and_or(&mlfq_gpu_trace_mask, trace_bit);
	now = scx_bpf_now();
	/* Deduplicate burst of tracepoints for one logical submission.
	 * A single job can fire amdgpu_cs + amdgpu_cs_ioctl +
	 * drm_sched_job_queue together; without the window one job
	 * would bump gpu_submit by 2-3 and saturate 0..4 immediately,
	 * biasing the tree feature. Gate on the per-task 10 ms window
	 * (MLFQ_TREE_PER_TASK_LIMIT_NS), the same cadence as the
	 * per-task sample limiter, so at most one bump per window.
	 * Wrapping-safe via mlfq_time_before(), like fair.c.
	 */
	if (tctx->last_gpu_submit_at &&
	    !mlfq_time_before(tctx->last_gpu_submit_at +
			      MLFQ_TREE_PER_TASK_LIMIT_NS, now))
		return;
	tctx->last_gpu_submit_at = now;
	if (tctx->gpu_submit < 4)
		tctx->gpu_submit++;
	else
		tctx->gpu_submit = 4;
	tctx->flags |= MLFQ_TF_DRM_WAKE;
	__sync_fetch_and_add(&mlfq_gpu_submit_total, 1);
}

SEC("tracepoint/amdgpu/amdgpu_cs")
int mlfq_amdgpu_cs(void *ctx)
{
	struct task_struct *p = (struct task_struct *)bpf_get_current_task_btf();

	if (!p)
		return 0;
	mlfq_gpu_submit_inc(p, MLFQ_GPU_TRACE_AMDGPU_CS);
	return 0;
}

SEC("tracepoint/amdgpu/amdgpu_cs_ioctl")
int mlfq_amdgpu_cs_ioctl(void *ctx)
{
	struct task_struct *p = (struct task_struct *)bpf_get_current_task_btf();

	if (!p)
		return 0;
	mlfq_gpu_submit_inc(p, MLFQ_GPU_TRACE_AMDGPU_CS_IOCTL);
	return 0;
}

SEC("tracepoint/gpu_scheduler/drm_sched_job_queue")
int mlfq_gpu_sched_queue(void *ctx)
{
	struct task_struct *p = (struct task_struct *)bpf_get_current_task_btf();

	if (!p)
		return 0;
	mlfq_gpu_submit_inc(p, MLFQ_GPU_TRACE_GPU_SCHED);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init)
{
	struct queue_ctx *q;
	u32 key, qid, nr_cpus;
	s32 cpu;
	s32 ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (nr_cpu_ids > MLFQ_MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids (%llu) exceeds max supported (%llu)",
			      nr_cpu_ids, (u64)MLFQ_MAX_CPUS);
		return -E2BIG;
	}

	/*
	 * Snapshot the CPU count once; the DSQ creation loop and the
	 * id-space invariant below are keyed on it.
	 */
	nr_cpus = (u32)nr_cpu_ids;
	if (nr_cpus == 0) {
		scx_bpf_error("no possible CPUs");
		return -EINVAL;
	}

	/*
	 * Clamp the Q2/Q3 steal-scan window to the CPU count: on a machine
	 * with fewer CPUs than the cap, an unscaled window would re-peek
	 * the same remote DSQs multiple times per slot.
	 */
	mlfq_steal_scan = nr_cpus < MLFQ_STEAL_SCAN_MAX ?
			  nr_cpus : (u32)MLFQ_STEAL_SCAN_MAX;

	/*
	 * Create the per-CPU vtime-ordered queue DSQs. bpf_for() is an
	 * iterator-backed loop: the bound is a runtime value (the checked
	 * CPU count) and the iterator contract lets the verifier bound the
	 * iteration without unrolling it.
	 */
	bpf_for(cpu, 0, nr_cpus) {
		for (qid = 1; qid <= MLFQ_NR_QUEUES; qid++) {
			ret = scx_bpf_create_dsq(mlfq_dsq_id(qid, cpu), -1);
			if (ret < 0 && ret != -EEXIST) {
				scx_bpf_error("failed to create q%u cpu%d DSQ: %d",
					      qid, cpu, ret);
				return ret;
			}
		}
	}

	/*
	 * The dispatch batch is served as q1 + q2 + q3, with the Q3 share
	 * computed as the unsigned remainder of dispatch_max_batch (see
	 * dispatch.bpf.c). Quotas that cover the whole batch would wrap
	 * that remainder and unbind the Q3 service loop, so the
	 * configuration is rejected outright.
	 */
	if (mlfq_q1_quota + mlfq_q2_quota >= mlfq_dispatch_max_batch) {
		scx_bpf_error("Q1+Q2 quotas (%u+%u) must leave a Q3 share of "
			      "max batch %u",
			      mlfq_q1_quota, mlfq_q2_quota,
			      mlfq_dispatch_max_batch);
		return -EINVAL;
	}

	/*
	 * The tree band edges are rodata bases of the effective values;
	 * a base pair with the edges out of order would let the
	 * adaptation clamps fight the base, so the configuration is
	 * rejected outright.
	 */
	if (mlfq_tree_t_int_ns >= mlfq_tree_t_bound_ns) {
		scx_bpf_error("tree T_INT (%llu) must be strictly below "
			      "T_BOUND (%llu)",
			      mlfq_tree_t_int_ns, mlfq_tree_t_bound_ns);
		return -EINVAL;
	}

	/*
	 * The queue DSQ id space must stay below the top bits the kernel
	 * reserves for the SCX_DSQ_LOCAL / SCX_DSQ_LOCAL_ON flags, so the
	 * mlfq_dsq_id() arithmetic never collides with the local DSQ
	 * range. With the per-CPU layout the highest id is owned by the
	 * last queue on the last CPU.
	 */
	if (mlfq_dsq_id(MLFQ_NR_QUEUES, (s32)(nr_cpus - 1)) >= SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("queue DSQ id space overflows SCX_DSQ_LOCAL_ON");
		return -EINVAL;
	}

	/* Initialize the per-queue request slices. */
	for (key = 1; key <= MLFQ_NR_QUEUES; key++) {
		q = mlfq_lookup_queue(key);
		if (!q) {
			scx_bpf_error("queue %u map lookup failed", key);
			return -EINVAL;
		}
		q->max_slice_ns = mlfq_queue_slice(key);
	}

	/*
	 * Seed the effective adaptation state with the rodata bases. The
	 * bss block is zero-default, and a zeroed effective band would
	 * map every task to Q1; the copy makes the unpopulated state
	 * (adaptation disabled, or before the first step) reproduce the
	 * fixed thresholds exactly. The guard base is the same-queue
	 * minimum-residency rodata value (zero by default), so the
	 * disabled guard keeps the unconditional interactive preemption.
	 */
	mlfq_adapt_state.shift_fp = 0;
	mlfq_adapt_state.t_l_eff_ns = mlfq_t_l_ns;
	mlfq_adapt_state.t_h_eff_ns = mlfq_t_h_ns;
	mlfq_adapt_state.t_int_eff_ns = mlfq_tree_t_int_ns;
	mlfq_adapt_state.t_bnd_eff_ns = mlfq_tree_t_bound_ns;
	mlfq_adapt_state.guard_eff_ns = mlfq_sameq_preempt_min_run_ns;

	return 0;
}

void BPF_STRUCT_OPS(mlfq_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}

SCX_OPS_DEFINE(mlfq_ops,
	       .select_cpu		= (void *)mlfq_select_cpu,
	       .enqueue			= (void *)mlfq_enqueue,
	       .dispatch		= (void *)mlfq_dispatch,
	       .cpu_release		= (void *)mlfq_cpu_release,
	       .running			= (void *)mlfq_running,
	       .stopping		= (void *)mlfq_stopping,
	       /*
		* The runnable-accounting exit signal. The kernel
		* invokes ops.quiescent on every dequeue_task_scx()
		* regardless of the task's ops_state, gated only on
		* !task_on_rq_migrating (structurally unreachable for
		* sched-ext tasks), so it fires exactly once per
		* leave-runnable event. ops.dequeue is deliberately NOT
		* used. It fires only while ops_state is QUEUED, which the
		* dispatch moves leave set for same-rq moves and clear for
		* remote transfers, so it is not a complete signal on its
		* own. The callback releases the task's LLC/queue gauge
		* ownership.
		*/
	       .quiescent		= (void *)mlfq_quiescent,
	       .update_idle		= (void *)mlfq_update_idle,
	       .enable			= (void *)mlfq_enable,
	       .init			= (void *)mlfq_init,
	       .exit			= (void *)mlfq_exit,
	       .init_task		= (void *)mlfq_init_task,
	       .exit_task		= (void *)mlfq_exit_task,
	       .dispatch_max_batch	= MLFQ_DISPATCH_MAX_BATCH,
	       /*
		* The kernel's own default watchdog timeout. A shorter one
		* would trip on machines where real-time tasks saturate the
		* CPUs. The RT class is not throttled below its budget, so
		* the watchdog work can be starved for the whole burst, and
		* the scheduler would exit even though nothing in its own
		* queues stalled. The watchdog still fires on a genuinely
		* stalled queue within the kernel's maximum detection
		* latency.
		*/
	       .timeout_ms		= MLFQ_OPS_TIMEOUT_MS,
	       .name			= "mlfq");
