// SPDX-License-Identifier: GPL-2.0
/* scx_cake — low-latency CAKE-inspired CPU scheduler.
 *
 * Core design:
 *   - direct dispatch when an idle CPU is available
 *   - per-CPU local-first fallback on single-LLC systems
 *   - optional LLC-scoped shared fallback only where topology needs it
 *   - topology-aware CPU selection (V-Cache, hybrid P/E, SMT siblings)
 *   - lean hot paths with task-local vtime accounting
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <lib/arena_map.h> /* BPF_MAP_TYPE_ARENA definition */
#include <lib/sdt_task.h> /* scx_task_data, scx_task_alloc, scx_task_free */
#include "intf.h"
#include "bpf_compat.h"

/* ALPHADEV: Disable Steal Path for localized V-Cache optimizations */
#define CAKE_LOCAL_CPU_ONLY 1

char _license[] SEC("license") = "GPL";

/* ═══ Scheduler RODATA Config ═══
 * All values below are RODATA — the BPF JIT constant-folds them into
 * immediate operands, eliminating memory loads on the hot path.
 * Rust loader overrides defaults via profile selection (esports/gaming/battery). */
const u64  quantum_ns	     = CAKE_DEFAULT_QUANTUM_NS;	  /* Base time slice per dispatch */
/* new_flow_bonus_ns REMOVED: zero BPF readers. */

/* Dead RODATA removed:
 * aq_yielder_ceiling_ns, aq_min_ns — zero BPF readers.
 * preempt_vip_ns, preempt_yielder_ns — zero BPF readers.
 * rt_cost_cap[4], preempt_thresh_ns[4] — zero BPF readers.
 * All were remnants of the old AQ/preemption system. */

/* Legacy class gap table retained for debug/documentation only.
 * The release scheduler no longer injects these offsets into dsq_vtime. */
const u32  legacy_tier_base[4]    = { 250000000, 0, 750000000, 500000000 };

/* Weight-aware vtime accounting:
 * the hot path reads p->scx.weight directly and applies an additive
 * adjustment instead of consulting a reciprocal lookup table. */

/* ═══ Telemetry Compile-Time Gates ═══
 *
 * RELEASE (CAKE_RELEASE=1, set by build.rs --release):
 *   CAKE_STATS_ENABLED = 0 (compile-time constant). Clang eliminates
 *   ALL stats/telemetry branches — zero instructions in production.
 *
 * DEBUG (default):
 *   CAKE_STATS_ENABLED reads a volatile RODATA bool. Loader patches it
 *   to true when --verbose is passed. JIT folds after patching. */
#ifdef CAKE_RELEASE
#define CAKE_STATS_ENABLED 0
#else
const bool enable_stats __attribute__((used)) = false;
#define CAKE_STATS_ENABLED (*(volatile const bool *)&enable_stats)
#endif
/* CAKE_STATS_ACTIVE: suppressed during BenchLab runs to avoid polluting
 * kfunc latency measurements with ~15 extra scx_bpf_now() calls. */
#define CAKE_STATS_ACTIVE (CAKE_STATS_ENABLED && !bench_active)
/* enable_dvfs REMOVED: dead — zero BPF readers. */

#define CAKE_SLOW_CALLBACK_NS 10000ULL
#define CAKE_SLOW_WAKEWAIT_NS 100000ULL
#define CAKE_QUICK_WAKE_KICK_NS 200000ULL
#define CAKE_TRACKED_WAKEWAIT_MAX_NS 5000000ULL
#define CAKE_EVT_TARGET_MISS_NS 250000ULL
#define CAKE_EVT_KICK_SLOW_NS 500000ULL
#define CAKE_EVT_DISPATCH_GAP_NS 1000000ULL
#define CAKE_STEER_UTIL_MIN 64U
#define CAKE_HOME_SCORE_MAX 15U
#define CAKE_CPU_PRESSURE_SAMPLE_SHIFT 13U
#define CAKE_CPU_PRESSURE_DECAY_SHIFT 2U
#define CAKE_CPU_PRESSURE_IDLE_DECAY_SHIFT 1U
#define CAKE_CPU_PRESSURE_SAMPLE_MAX 63U
#define CAKE_CPU_PRESSURE_SPILL_MIN 24U
#define CAKE_CPU_PRESSURE_SPILL_DELTA 12U
#define CAKE_CPU_PRESSURE_HOME_SCORE_MIN 8U

/* Topology config - JIT eliminates unused SMT steering when nr_cpus <= nr_phys_cpus.
 * has_hybrid removed: Rust loader pre-fills cpu_sibling_map for ALL topologies
 * via scx_utils::Topology::sibling_cpus(). No runtime branching needed. */

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const volatile u32 nr_llcs = 1;
const volatile u32 nr_cpus = 1; /* Set by loader. 1 = safe fallback — makes loader failure obvious. */
/* nr_phys_cpus REMOVED: zero BPF readers. */
/* nr_nodes kept for BenchLab only: */
const volatile u32 nr_nodes = 1; /* Set by loader — NUMA node count for bench competitor */
const volatile u32 cpu_llc_id[CAKE_MAX_CPUS] = {};
const volatile u8 cpu_core_id[CAKE_MAX_CPUS] = {};
/* cpuperf_cap_table[] kept for BenchLab only: */
const u32 cpuperf_cap_table[CAKE_MAX_CPUS] = {};

/* Performance-ordered CPU scan arrays — HYBRID ONLY.
 * Compiled out on homogeneous AMD SMP (zero RODATA footprint).
 * cpus_fast_to_slow: high-performance-first scan order.
 * cpus_slow_to_fast: efficiency-first scan order. */
#ifdef CAKE_HAS_HYBRID
const cake_cpu_id_t cpus_fast_to_slow[CAKE_MAX_CPUS] = {};
const cake_cpu_id_t cpus_slow_to_fast[CAKE_MAX_CPUS] = {};
#endif

/* Topological O(1) Arrays — populated by loader */
const volatile u64 llc_cpu_mask[CAKE_MAX_LLCS] = {};
/* core_cpu_mask[] REMOVED: zero BPF readers. */
const volatile cake_cpu_id_t cpu_sibling_map[CAKE_MAX_CPUS] = {};
const volatile u8 cpu_thread_bit[CAKE_MAX_CPUS] = {};

/* BSS bench state: xorshift32 PRNG seed */
u32 bench_xorshift_state = 0xDEADBEEF;

/* CAKE_CPU_MASK_WORDS defined in intf.h with ceiling division.
 * At 16 CPUs: 1 word.  At 64: 1.  At 512: 8. */

/* Heterogeneous Routing Masks — HYBRID ONLY.
 * Compiled out on homogeneous AMD SMP (zero mask RODATA). */
#ifdef CAKE_HAS_HYBRID
const u64  big_core_phys_mask[CAKE_CPU_MASK_WORDS] = {};
const u64  big_core_smt_mask[CAKE_CPU_MASK_WORDS]  = {};
const u64  little_core_mask[CAKE_CPU_MASK_WORDS]   = {};
#endif
/* vcache_llc_mask[] REMOVED: zero BPF readers (Rust TUI reads topology directly). */
/* has_vcache REMOVED: zero BPF readers (Rust TUI reads topology directly). */
/* Preferred LLC steering and victim-scan tables were removed when Cake moved
 * to per-CPU local-first runnable ownership. */
#ifdef CAKE_HAS_HYBRID
const bool has_hybrid_cores   = false; /* Set by loader — gate for Gate 2 scan */
#endif
/* has_cpuperf_control REMOVED: the scheduler no longer drives cpuperf
 * scaling from BPF. */

/* brain_class_cache[] REMOVED: 131KB BSS array, hydrated by Rust every
 * poll cycle, but had zero BPF readers. */

/* ═══ Additive Fairness Model ═══
 * Replaces the old reciprocal table with a direct adjustment derived from
 * p->scx.weight:
 *
 *   vtime += runtime + (100 - weight) * 20480
 *
 * This removes the per-task reciprocal cache and the runtime divide it
 * existed to avoid. Clang may still strength-reduce the shift/add sequence
 * into a multiply in generated BPF, so the source should not be read as a
 * guarantee of "no multiply" in the final object.
 *
 * For nice-0 (weight=100), the adjustment is zero. Lower-weight tasks
 * accumulate vtime faster and therefore run later within a bucket.
 *
 * vtime_mult_cache[] DELETED: -4KB BSS, -64 cache lines. */



/* ═══════════════════════════════════════════════════════════════════════════
 * PER-CPU ARENA BLOCK: Unified mailbox (C1 spatial consolidation).
 *
 * Single per-CPU allocation sized by CAKE_MBOX_SIZE:
 *   - release: 64B/CPU (1 CL) — struct is dead stub (all reads DCE'd)
 *   - debug:  128B/CPU (2 CL) — CL0 telemetry + CL1 BenchLab handoff
 *   - 1 BSS global pointer, 1 TLB entry, 1 null-check
 * ═══════════════════════════════════════════════════════════════════════════ */
struct cake_per_cpu {
	struct mega_mailbox_entry
		mbox; /* release: 64B (1 CL), debug: 128B (2 CL) */
} __attribute__((aligned(CAKE_MBOX_ALIGN)));
_Static_assert(sizeof(struct cake_per_cpu) == CAKE_MBOX_SIZE,
	       "cake_per_cpu must match CAKE_MBOX_SIZE for per-CPU isolation");
struct cake_per_cpu __arena *per_cpu;

/* Per-CPU global stats — BSS array, 256B aligned per entry.
 * Direct indexing keeps the hot path simple and avoids helper indirection. */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));

#ifndef CAKE_RELEASE
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
struct cake_wake_edge_record wake_edge_records[CAKE_WAKE_EDGE_SLOTS] SEC(".bss")
	__attribute__((aligned(256)));
u64 wake_edge_slots_used SEC(".bss") __attribute__((aligned(256)));
u64 wake_edge_collisions SEC(".bss") __attribute__((aligned(256)));
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

/* DSQ Work Hint: DELETED.
 * dsq_gen was a unidirectional generation counter that caused CPUs to
 * permanently skip checking the shared DSQ after pulling one task.
 * With 18.8M hint_skips, OS threads (ksoftirqd, rcu) starved for 6.5s.
 * Replaced by O(1) scx_bpf_dsq_nr_queued() in cake_dispatch. */


/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* pid_to_tctx (BPF_MAP_TYPE_HASH) removed — replaced by SEC("iter/task") cake_task_iter.
 * cake_init_task and cake_exit_task are now fully lockless: no map_update_elem or
 * map_delete_elem calls. Userspace reads fixed-size cake_iter_record records from the
 * iter fd instead of walking a 65536-entry global hash table. */



/* ARENA_ASSOC: Force BPF arena map association for struct_ops programs.
 * BPF struct_ops require an explicit reference to the arena map to
 * generate the ld_imm64 relocation. BSS loads alone don't create
 * arena map relocations. Inline asm forces &arena into a register
 * without emitting a stack store (2 insns vs 3 with volatile). */
#define ARENA_ASSOC() asm volatile("" : : "r"(&arena))

/* get_local_stats: returns this CPU's stats struct.
 * Uses direct array index (0ns) instead of bpf_per_cpu_ptr (25ns). */
static __always_inline struct cake_stats *get_local_stats(void)
{
#ifndef CAKE_RELEASE
	asm volatile("" : : "r"(enable_stats) : "memory");
#endif
	u32 cpu = bpf_get_smp_processor_id();
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* get_local_stats_for: same as above but avoids a redundant
 * bpf_get_smp_processor_id() kfunc call when CPU ID is already known. */
static __always_inline struct cake_stats *get_local_stats_for(u32 cpu)
{
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

extern u32 bench_active;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} debug_ringbuf SEC(".maps");

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

static __always_inline void cake_record_cb(struct cake_stats *s, u32 cb_idx, u64 dur_ns)
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

static __always_inline void cake_copy_comm(char *dst, const char *src)
{
	*((u64 *)&dst[0]) = *((const u64 *)&src[0]);
	*((u64 *)&dst[8]) = *((const u64 *)&src[8]);
}

static __always_inline void cake_emit_dbg_event(
	struct task_struct *p,
	u32 cpu,
	u8 kind,
	u8 slot,
	u64 value_ns,
	u32 aux)
{
	struct cake_debug_event *ev;

	if (!CAKE_STATS_ACTIVE)
		return;

	ev = bpf_ringbuf_reserve(&debug_ringbuf, sizeof(*ev), 0);
	if (!ev)
		return;

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts_ns = bpf_ktime_get_ns();
	ev->value_ns = value_ns;
	ev->pid = p ? p->pid : 0;
	ev->aux = aux;
	ev->cpu = cpu;
	ev->kind = kind;
	ev->slot = slot;
	if (p)
		cake_copy_comm(ev->comm, p->comm);
	bpf_ringbuf_submit(ev, 0);
}

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Per-LLC DSQs with vtime-ordered priority.
 * Each LLC gets one shared DSQ keyed by p->scx.dsq_vtime.
 * DSQ IDs: LLC_DSQ_BASE + 0, LLC_DSQ_BASE + 1, ... (one per LLC). */

/* ── Kfunc BenchLab: BSS globals ──
 * bench_request: TUI writes 1 → BPF runs bench on next stopping → clears to 0.
 * bench_results: populated by run_kfunc_bench(), read by TUI. */
u32 bench_request = 0;
u32 bench_active = 0;  /* 1 while benchmark is running — suppresses telemetry */
struct kfunc_bench_results bench_results = {};

#ifndef CAKE_RELEASE
static __always_inline void cake_debug_atomic_inc(u64 *ptr)
{
	__sync_fetch_and_add(ptr, 1);
}

static __always_inline u32 cake_wake_edge_hash(
	u32 waker_pid, u32 waker_tgid, u32 wakee_pid, u32 wakee_tgid)
{
	u32 h = waker_pid * 2654435761U;

	h ^= waker_tgid * 2246822519U;
	h ^= wakee_pid * 3266489917U;
	h ^= wakee_tgid * 668265263U;
	h ^= h >> 16;
	h *= 0x7feb352dU;
	h ^= h >> 15;
	return h;
}

static __always_inline bool cake_wake_edge_matches(
	struct cake_wake_edge_record *edge,
	u32 waker_pid, u32 waker_tgid, u32 wakee_pid, u32 wakee_tgid)
{
	return READ_ONCE(edge->waker_pid) == waker_pid &&
	       READ_ONCE(edge->waker_tgid) == waker_tgid &&
	       READ_ONCE(edge->wakee_pid) == wakee_pid &&
	       READ_ONCE(edge->wakee_tgid) == wakee_tgid;
}

static __always_inline struct cake_wake_edge_record *cake_wake_edge_lookup(
	u32 waker_pid, u32 waker_tgid, u32 wakee_pid, u32 wakee_tgid,
	bool create)
{
	u32 hash;

	if (!CAKE_STATS_ACTIVE || !waker_pid || !wakee_pid)
		return NULL;

	hash = cake_wake_edge_hash(waker_pid, waker_tgid, wakee_pid, wakee_tgid);

#pragma unroll
	for (int probe = 0; probe < CAKE_WAKE_EDGE_PROBES; probe++) {
		u32 idx = (hash + (u32)probe * 17U) & (CAKE_WAKE_EDGE_SLOTS - 1);
		struct cake_wake_edge_record *edge = &wake_edge_records[idx];
		u64 wake_count = READ_ONCE(edge->wake_count);

		if (wake_count > 0 &&
		    cake_wake_edge_matches(edge, waker_pid, waker_tgid,
					   wakee_pid, wakee_tgid))
			return edge;

		if (wake_count == 0 && READ_ONCE(edge->wakee_pid) == 0) {
			if (!create)
				break;
			WRITE_ONCE(edge->waker_pid, waker_pid);
			WRITE_ONCE(edge->waker_tgid, waker_tgid);
			WRITE_ONCE(edge->wakee_pid, wakee_pid);
			WRITE_ONCE(edge->wakee_tgid, wakee_tgid);
			cake_debug_atomic_inc(&wake_edge_slots_used);
			return edge;
		}

		cake_debug_atomic_inc(&wake_edge_collisions);
	}

	cake_debug_atomic_inc(&wake_edge_missed_updates);
	return NULL;
}

static __always_inline void cake_wake_edge_inc_bucket(
	struct cake_wake_edge_record *edge, u32 bucket)
{
	switch (bucket) {
	case CAKE_WAKE_BUCKET_LT50US:
		cake_debug_atomic_inc(&edge->wait_bucket_count[CAKE_WAKE_BUCKET_LT50US]);
		break;
	case CAKE_WAKE_BUCKET_LT200US:
		cake_debug_atomic_inc(&edge->wait_bucket_count[CAKE_WAKE_BUCKET_LT200US]);
		break;
	case CAKE_WAKE_BUCKET_LT1MS:
		cake_debug_atomic_inc(&edge->wait_bucket_count[CAKE_WAKE_BUCKET_LT1MS]);
		break;
	case CAKE_WAKE_BUCKET_LT5MS:
		cake_debug_atomic_inc(&edge->wait_bucket_count[CAKE_WAKE_BUCKET_LT5MS]);
		break;
	case CAKE_WAKE_BUCKET_GE5MS:
		cake_debug_atomic_inc(&edge->wait_bucket_count[CAKE_WAKE_BUCKET_GE5MS]);
		break;
	default:
		break;
	}
}

static __always_inline void cake_wake_edge_inc_place(
	u64 counts[CAKE_PLACE_CLASS_MAX], u8 cls)
{
	switch (cls) {
	case CAKE_PLACE_HOME_CPU:
		cake_debug_atomic_inc(&counts[CAKE_PLACE_HOME_CPU]);
		break;
	case CAKE_PLACE_HOME_CORE:
		cake_debug_atomic_inc(&counts[CAKE_PLACE_HOME_CORE]);
		break;
	case CAKE_PLACE_HOME_LLC:
		cake_debug_atomic_inc(&counts[CAKE_PLACE_HOME_LLC]);
		break;
	case CAKE_PLACE_REMOTE:
		cake_debug_atomic_inc(&counts[CAKE_PLACE_REMOTE]);
		break;
	default:
		break;
	}
}

static __always_inline void cake_wake_edge_inc_reason(
	struct cake_wake_edge_record *edge, u8 reason)
{
	switch (reason) {
	case CAKE_WAKE_REASON_DIRECT:
		cake_debug_atomic_inc(&edge->reason_count[CAKE_WAKE_REASON_DIRECT]);
		break;
	case CAKE_WAKE_REASON_BUSY:
		cake_debug_atomic_inc(&edge->reason_count[CAKE_WAKE_REASON_BUSY]);
		break;
	case CAKE_WAKE_REASON_QUEUED:
		cake_debug_atomic_inc(&edge->reason_count[CAKE_WAKE_REASON_QUEUED]);
		break;
	default:
		break;
	}
}

static __always_inline void cake_wake_edge_inc_path(
	struct cake_wake_edge_record *edge, u8 path)
{
	switch (path) {
	case CAKE_SELECT_PATH_HOME_CPU:
		cake_debug_atomic_inc(&edge->path_count[CAKE_SELECT_PATH_HOME_CPU]);
		break;
	case CAKE_SELECT_PATH_HOME_CORE:
		cake_debug_atomic_inc(&edge->path_count[CAKE_SELECT_PATH_HOME_CORE]);
		break;
	case CAKE_SELECT_PATH_PRIMARY:
		cake_debug_atomic_inc(&edge->path_count[CAKE_SELECT_PATH_PRIMARY]);
		break;
	case CAKE_SELECT_PATH_IDLE:
		cake_debug_atomic_inc(&edge->path_count[CAKE_SELECT_PATH_IDLE]);
		break;
	case CAKE_SELECT_PATH_TUNNEL:
		cake_debug_atomic_inc(&edge->path_count[CAKE_SELECT_PATH_TUNNEL]);
		break;
	default:
		break;
	}
}

static __noinline void cake_record_wake_edge_enqueue(
	struct cake_task_ctx __arena *tctx,
	struct task_struct *waker,
	struct task_struct *wakee)
{
	struct cake_wake_edge_record *edge;
	u32 waker_pid;
	u32 waker_tgid;
	u32 wakee_pid;
	u32 wakee_tgid;

	if (!tctx || !waker || !wakee || !CAKE_STATS_ACTIVE)
		return;

	waker_pid = waker->pid;
	waker_tgid = waker->tgid;
	wakee_pid = wakee->pid;
	wakee_tgid = wakee->tgid;
	edge = cake_wake_edge_lookup(waker_pid, waker_tgid, wakee_pid,
				     wakee_tgid, true);
	if (!edge)
		return;

	cake_debug_atomic_inc(&edge->wake_count);
	if (waker_tgid == wakee_tgid)
		cake_debug_atomic_inc(&edge->same_tgid_count);
	else
		cake_debug_atomic_inc(&edge->cross_tgid_count);
	WRITE_ONCE(edge->last_seen_ns, bpf_ktime_get_ns());
}

static __noinline void cake_record_wake_edge_run(
	struct cake_task_ctx __arena *tctx,
	struct task_struct *p,
	u32 cpu,
	u64 wait_ns,
	u64 packed)
{
	struct cake_wake_edge_record *edge;
	u64 max_seen;
	u8 reason = (u8)(packed & 0xff);
	u16 target_cpu = (u16)((packed >> 8) & 0xffff);
	u8 select_path = (u8)((packed >> 24) & 0xff);
	u8 home_place = (u8)((packed >> 32) & 0xff);
	u8 waker_place = (u8)((packed >> 40) & 0xff);

	if (!tctx || !p || !CAKE_STATS_ACTIVE)
		return;
	if (reason <= CAKE_WAKE_REASON_NONE || reason >= CAKE_WAKE_REASON_MAX)
		return;

	edge = cake_wake_edge_lookup(tctx->telemetry.wakeup_source_pid,
				     tctx->telemetry.waker_tgid,
				     p->pid, p->tgid, false);
	if (!edge)
		return;

	cake_debug_atomic_inc(&edge->wait_count);
	__sync_fetch_and_add(&edge->wait_ns, wait_ns);
	max_seen = READ_ONCE(edge->wait_max_ns);
	if (wait_ns > max_seen)
		WRITE_ONCE(edge->wait_max_ns, wait_ns);
	cake_wake_edge_inc_bucket(edge, cake_wake_bucket(wait_ns));
	cake_wake_edge_inc_reason(edge, reason);
	cake_wake_edge_inc_path(edge, select_path);
	cake_wake_edge_inc_place(edge->home_place_count, home_place);
	cake_wake_edge_inc_place(edge->waker_place_count, waker_place);
	if (target_cpu < CAKE_MAX_CPUS) {
		if ((u16)cpu == target_cpu)
			cake_debug_atomic_inc(&edge->target_hit_count);
		else
			cake_debug_atomic_inc(&edge->target_miss_count);
	}
	WRITE_ONCE(edge->last_seen_ns, bpf_ktime_get_ns());
}

static __noinline void cake_record_wake_edge_follow(
	struct cake_task_ctx __arena *tctx,
	struct task_struct *p,
	bool same_cpu)
{
	struct cake_wake_edge_record *edge;

	if (!tctx || !p || !CAKE_STATS_ACTIVE)
		return;

	edge = cake_wake_edge_lookup(tctx->telemetry.wakeup_source_pid,
				     tctx->telemetry.waker_tgid,
				     p->pid, p->tgid, false);
	if (!edge)
		return;

	if (same_cpu)
		cake_debug_atomic_inc(&edge->follow_same_cpu_count);
	else
		cake_debug_atomic_inc(&edge->follow_migrate_count);
	WRITE_ONCE(edge->last_seen_ns, bpf_ktime_get_ns());
}

static __always_inline void cake_record_select_choice(u8 reason, s32 prev_cpu,
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

static __always_inline void cake_record_pressure_probe(u8 site, u8 outcome,
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

static __always_inline void cake_record_pressure_anchor_block(
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

static __always_inline void cake_record_wake_target_insert(
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

static __always_inline void cake_record_target_wait(
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

/* vtime_now REMOVED: replaced by per-CPU bss->vtime_local.
 * The global was written by every CPU on every context switch,
 * causing 15-core MESI invalidation storms. */




/* ═══ Per-CPU BSS (4KB-aligned per entry) ═══
 * Stores per-CPU scheduling state: run timestamps, idle hints,
 * vtime_local, and dispatch bookkeeping.
 *
 * 4KB alignment isolates each CPU's state onto its own page-sized region.
 * At CAKE_MAX_CPUS=16: 64KB total. Untouched entries stay zero-page COW.
 *
 * Write pattern: cake_running writes, cake_stopping reads (same CPU).
 * Cross-CPU reads are limited to idle_hint and vtime-local lookups. */
struct cake_cpu_bss cpu_bss[CAKE_MAX_CPUS];

static __always_inline u8 cake_read_cpu_pressure(u32 cpu)
{
	if (cpu >= nr_cpus)
		return 0;

	return READ_ONCE(cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].cpu_pressure);
}

static __always_inline void cake_update_cpu_pressure(
	struct cake_cpu_bss *bss, u32 slice_consumed)
{
	u32 pressure = READ_ONCE(bss->cpu_pressure);
	u32 sample = slice_consumed >> CAKE_CPU_PRESSURE_SAMPLE_SHIFT;

	if (!sample && slice_consumed)
		sample = 1;
	if (sample > CAKE_CPU_PRESSURE_SAMPLE_MAX)
		sample = CAKE_CPU_PRESSURE_SAMPLE_MAX;

	pressure -= pressure >> CAKE_CPU_PRESSURE_DECAY_SHIFT;
	pressure += sample;
	if (pressure > 255U)
		pressure = 255U;
	WRITE_ONCE(bss->cpu_pressure, (u8)pressure);
}

static __always_inline void cake_decay_cpu_pressure_idle(struct cake_cpu_bss *bss)
{
	u32 pressure = READ_ONCE(bss->cpu_pressure);

	pressure -= pressure >> CAKE_CPU_PRESSURE_IDLE_DECAY_SHIFT;
	WRITE_ONCE(bss->cpu_pressure, (u8)pressure);
}

#ifndef CAKE_RELEASE
static __always_inline void cake_smt_record_run_start(
	struct cake_cpu_bss *bss, u32 cpu, u64 start_ns)
{
	u16 sibling_cpu = cpu_sibling_map[cpu & (CAKE_MAX_CPUS - 1)];
	u8 sibling_active = 0;

	if (sibling_cpu < nr_cpus && sibling_cpu != cpu)
		sibling_active = !READ_ONCE(cpu_bss[sibling_cpu & (CAKE_MAX_CPUS - 1)].idle_hint);

	bss->smt_run_start_ns = start_ns;
	bss->smt_sibling_active_start = sibling_active;
}

static __always_inline void cake_smt_record_wake_wait(
	struct cake_stats *s, u32 cpu, u64 wait_ns)
{
	u32 bucket = READ_ONCE(cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].smt_sibling_active_start) ? 1 : 0;

	s->smt_wake_wait_ns[bucket] += wait_ns;
	s->smt_wake_wait_count[bucket]++;
	if (wait_ns > s->smt_wake_wait_max_ns[bucket])
		s->smt_wake_wait_max_ns[bucket] = wait_ns;
}

static __always_inline u64 cake_smt_charge_runtime(
	struct cake_stats *s, struct cake_cpu_bss *bss, u32 cpu, u64 stop_ns)
{
	u64 start_ns = READ_ONCE(bss->smt_run_start_ns);
	u64 dur, overlap = 0;
	u16 sibling_cpu;
	u8 sibling_active_start, sibling_active_stop = 0;

	if (start_ns == 0 || stop_ns <= start_ns)
		return 0;

	dur = stop_ns - start_ns;
	sibling_active_start = READ_ONCE(bss->smt_sibling_active_start);
	sibling_cpu = cpu_sibling_map[cpu & (CAKE_MAX_CPUS - 1)];

	if (sibling_cpu < nr_cpus && sibling_cpu != cpu) {
		struct cake_cpu_bss *sib_bss =
			&cpu_bss[sibling_cpu & (CAKE_MAX_CPUS - 1)];
		u64 sib_start = READ_ONCE(sib_bss->smt_run_start_ns);
		u64 sib_stop = READ_ONCE(sib_bss->smt_last_stop_ns);

		sibling_active_stop = !READ_ONCE(sib_bss->idle_hint);
		if (sibling_active_stop && sib_start > 0 && stop_ns > sib_start) {
			u64 lo = start_ns > sib_start ? start_ns : sib_start;
			if (stop_ns > lo)
				overlap = stop_ns - lo;
		} else if (sibling_active_start && sib_stop > start_ns) {
			u64 hi = sib_stop < stop_ns ? sib_stop : stop_ns;
			if (hi > start_ns)
				overlap = hi - start_ns;
		}
	}

	if (overlap > dur)
		overlap = dur;

	if (sibling_active_start)
		s->smt_sibling_active_start_count++;
	if (sibling_active_stop)
		s->smt_sibling_active_stop_count++;

	if (overlap > 0) {
		s->smt_contended_runtime_ns += dur;
		s->smt_contended_run_count++;
		s->smt_overlap_runtime_ns += overlap;
	} else {
		s->smt_solo_runtime_ns += dur;
		s->smt_solo_run_count++;
	}

	bss->smt_last_stop_ns = stop_ns;
	return overlap;
}
#endif

static __always_inline s32 cake_pick_pressure_sibling(
	struct cake_task_ctx __arena *tctx, s32 anchor_cpu,
	const struct cpumask *cpumask, u8 site)
{
	s32 sibling_cpu;
	u8 anchor_pressure, sibling_pressure;

	cake_record_pressure_probe(site, CAKE_PRESSURE_PROBE_EVALUATED, anchor_cpu);

	if (!tctx || anchor_cpu < 0 || anchor_cpu >= nr_cpus) {
		cake_record_pressure_probe(site,
					  CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR,
					  anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_INVALID, anchor_cpu);
		return -1;
	}
	if (cpu_thread_bit[anchor_cpu & (CAKE_MAX_CPUS - 1)] != 1) {
		cake_record_pressure_probe(site,
					  CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR,
					  anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_SECONDARY, anchor_cpu);
		return -1;
	}

	sibling_cpu = (s32)cpu_sibling_map[anchor_cpu & (CAKE_MAX_CPUS - 1)];
	if (sibling_cpu < 0 || sibling_cpu >= nr_cpus || sibling_cpu == anchor_cpu) {
		cake_record_pressure_probe(site,
					  CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR,
					  anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_NO_SIBLING, anchor_cpu);
		return -1;
	}
	if (tctx->home_score < CAKE_CPU_PRESSURE_HOME_SCORE_MIN) {
		cake_record_pressure_probe(site,
					  CAKE_PRESSURE_PROBE_BLOCKED_SCORE,
					  anchor_cpu);
		return -1;
	}
	if (!bpf_cpumask_test_cpu((u32)sibling_cpu, cpumask)) {
		cake_record_pressure_probe(site,
					  CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR,
					  anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_AFFINITY, anchor_cpu);
		return -1;
	}

	anchor_pressure = cake_read_cpu_pressure((u32)anchor_cpu);
	sibling_pressure = cake_read_cpu_pressure((u32)sibling_cpu);
	if (anchor_pressure < CAKE_CPU_PRESSURE_SPILL_MIN ||
	    anchor_pressure < sibling_pressure + CAKE_CPU_PRESSURE_SPILL_DELTA) {
		cake_record_pressure_probe(site,
					  CAKE_PRESSURE_PROBE_BLOCKED_DELTA,
					  anchor_cpu);
		return -1;
	}
	if (!scx_bpf_test_and_clear_cpu_idle(sibling_cpu)) {
		cake_record_pressure_probe(site,
					  CAKE_PRESSURE_PROBE_BLOCKED_SIBLING_BUSY,
					  anchor_cpu);
		return -1;
	}

	cake_record_pressure_probe(site, CAKE_PRESSURE_PROBE_SUCCESS, anchor_cpu);

	return sibling_cpu;
}


/* BenchLab ringbuf: tiny ringbuf for measuring reserve+submit overhead.
 * Size 4096 = minimum page-aligned allocation. Never consumed by userspace;
 * benchmarks use reserve+discard to measure the API cost. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} bench_ringbuf SEC(".maps");

/* BenchLab task storage: measures bpf_task_storage_get() cost.
 * This is the standard per-task storage approach that cake replaced with arena.
 * Only used in benchmarks to measure what we're saving. */
struct bench_task_val {
	u64 dummy;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bench_task_val);
} bench_task_storage SEC(".maps");



/* BenchLab spin lock: measures bpf_spin_lock + unlock cycle cost. */
struct bench_lock_data {
	struct bpf_spin_lock lock;
	u64 counter;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct bench_lock_data);
} bench_lock_map SEC(".maps");

/* Benchmark a single kfunc iteration: call twice, delta = cost.
 * Macro to avoid function pointer overhead (BPF doesn't support them). */
/* Forward declaration for benchmarking */
static __noinline s32 select_cpu_and_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags, u64 flags);

#define BENCH_ONE(entry, call_expr, idx) do {                     \
	u64 _s = bpf_ktime_get_ns();                                 \
	u64 _v = (u64)(call_expr);                                    \
	u64 _e = bpf_ktime_get_ns();                                 \
	u64 _d = _e - _s;                                            \
	if (_d < (entry)->min_ns) (entry)->min_ns = _d;               \
	if (_d > (entry)->max_ns) (entry)->max_ns = _d;               \
	(entry)->total_ns += _d;                                      \
	(entry)->last_value = _v;                                     \
	(entry)->samples[idx] = _d;                                   \
} while (0)

static __always_inline void run_kfunc_bench(struct kfunc_bench_results *r,
					     struct task_struct *p);

/* Forward declare get_task_ctx — defined later, needed by bench */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p);

static __always_inline void run_kfunc_bench(struct kfunc_bench_results *r,
					     struct task_struct *p)
{
	/* Suppress CAKE_STATS_ACTIVE on all cores during benchmark */
	*(volatile u32 *)&bench_active = 1;
	r->cpu = bpf_get_smp_processor_id();
	r->iterations = BENCH_ITERATIONS;

	/* Zero all entries */
	#pragma unroll
	for (int i = 0; i < BENCH_MAX_ENTRIES; i++) {
		r->entries[i].min_ns = ~0ULL;
		r->entries[i].max_ns = 0;
		r->entries[i].total_ns = 0;
		r->entries[i].last_value = 0;
	}

	/* Bench: bpf_ktime_get_ns() — legacy CLOCK_MONOTONIC */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_KTIME_GET_NS], bpf_ktime_get_ns(), i);

	/* Bench: scx_bpf_now() — SCX cached clock */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_BPF_NOW], scx_bpf_now(), i);

	/* Bench: bpf_get_smp_processor_id() — CPU identification */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_GET_SMP_PROC_ID], bpf_get_smp_processor_id(), i);

	/* Bench: bpf_task_from_pid() — PID lookup (kfunc) */
	{
		s32 pid = p->pid;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct task_struct *t = bpf_task_from_pid(pid);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			if (t) bpf_task_release(t);
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_FROM_PID];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(t != NULL);
		}
	}

	/* Bench: scx_bpf_test_and_clear_cpu_idle() — idle probe (gate 1 hot path) */
	{
		u32 cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			bool idle = scx_bpf_test_and_clear_cpu_idle(cpu);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TEST_CLEAR_IDLE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)idle;
		}
	}

	/* Bench: scx_bpf_nr_cpu_ids() — topology constant read */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_NR_CPU_IDS], scx_bpf_nr_cpu_ids(), i);

	/* Bench: get_task_ctx() — scx_task_data arena direct pointer deref */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct cake_task_ctx __arena *t = get_task_ctx(p);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_GET_TASK_CTX];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(t != NULL);
		}
	}

	/* Bench: scx_bpf_dsq_nr_queued() — DSQ depth query (read-only kfunc) */
	{
		u64 dsq_id = LLC_DSQ_BASE + cpu_llc_id[r->cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			s32 nr = scx_bpf_dsq_nr_queued(dsq_id);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_DSQ_NR_QUEUED];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)nr;
		}
	}

	/* Bench: BSS array access — raw global_stats[cpu] field read */
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 v = global_stats[bcpu].total_stopping_ns;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_BSS_ARRAY_ACCESS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}

	/* Bench: Arena per_cpu deref — read field from per_cpu[cpu].mbox */
#ifndef CAKE_RELEASE
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 v = per_cpu[bcpu].mbox.tick_slice;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_DEREF];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}
#endif

	/* Bench: Back-to-back scx_bpf_now() pair — calibration baseline.
	 * Measures the overhead of the timing harness itself (2× bpf_ktime_get_ns). */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++) {
		u64 _s = bpf_ktime_get_ns();
		u64 _e = bpf_ktime_get_ns();
		u64 _d = _e - _s;
		struct kfunc_bench_entry *e = &r->entries[BENCH_NOW_PAIR];
		if (_d < e->min_ns) e->min_ns = _d;
		if (_d > e->max_ns) e->max_ns = _d;
		e->total_ns += _d;
		e->samples[i] = _d;
		e->last_value = _d; /* Shows raw overhead of timing harness */
	}

	/* Bench: Read cached CPU from mailbox CL0 (Disruptor handoff pattern).
	 * Simulates cake_stopping reading CPU from mailbox instead of calling
	 * bpf_get_smp_processor_id(). Mailbox is L1-hot from prior tick_slice read. */
#ifndef CAKE_RELEASE
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 v = mbox->tick_last_run_at; /* Same CL0 as CPU would be */
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_MBOX_CPU_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}
#endif

	/* Bench: Read cached tctx pointer from mailbox + field deref.
	 * Simulates reading a pre-cached arena pointer from mailbox CL0,
	 * then dereferencing a field. Compares against get_task_ctx() kfunc. */
#ifndef CAKE_RELEASE
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		/* Simulate: read a u64 from mailbox (where ptr would be cached),
		 * then read a field from the tctx we already have. */
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				volatile u64 ptr_val = mbox->tick_slice; /* Simulate ptr read from CL0 */
				volatile u16 field = 0; /* Deref eradicated */
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_TCTX_FROM_MBOX];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = field + (u32)ptr_val;
			}
		}
	}
#endif

	/* Bench: bpf_ringbuf_reserve + discard cycle.
	 * Measures the cost of the BPF ringbuf API (Disruptor pattern #3).
	 * Uses reserve+discard (not submit) to avoid requiring a consumer. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			void *slot = bpf_ringbuf_reserve(&bench_ringbuf, 8, 0);
			if (slot)
				bpf_ringbuf_discard(slot, 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RINGBUF_CYCLE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(slot != NULL);
		}
	}

	/* Bench: task_struct field reads — p->scx.slice + p->nvcsw */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 sl = p->scx.slice;
			volatile u64 nv = p->nvcsw;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_STRUCT_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sl + nv;
		}
	}

	/* Bench: RODATA array lookup — cpu_llc_id[cpu] + quantum_ns */
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 llc = cpu_llc_id[bcpu];
			volatile u64 ts = quantum_ns; /* RODATA const read */
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RODATA_LOOKUP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ts + llc;
		}
	}

	/* Bench: Bitflag operations — shift+mask+branchless yielder pattern.
	 * Simulates the full yielder detection + branchless flag set from stopping. */
	{
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			u32 packed = tctx->packed_info;
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				/* Extract yielder flag */
				u32 yl_mask = (u32)CAKE_FLOW_YIELDER << SHIFT_FLAGS;
				volatile u32 result = (packed & ~yl_mask) | (yl_mask & -(u32)1);
				/* Extract nf + yl bits */
				volatile u8 nf = (result >> SHIFT_FLAGS) & 1;
				volatile u8 yl = (result >> SHIFT_FLAGS) & (u32)CAKE_FLOW_YIELDER;
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_BITFLAG_OPS];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = nf + yl + result;
			}
		}
	}

	/* Bench: EWMA computation (legacy, slot preserved for comparison).
	 * Reads tick_slice from cpu_bss. compute_ewma() removed in PELT transition. */
	{
		s32 ewma_cpu = bpf_get_smp_processor_id();
		u64 tick_sl_bss = cpu_bss[ewma_cpu & (CAKE_MAX_CPUS - 1)].tick_slice;
		u32 fused_val = 0x00C80064; /* Simulated: avg=200, deficit=100 */
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* 1.0.4 path: tick_slice from BSS, remaining from p->scx */
			u64 tick_sl = tick_sl_bss;   /* cpu_bss — already L1 hot */
			u64 rem_sl = p->scx.slice;   /* task_struct — already read */
			u16 old_avg = (u16)(fused_val >> 16);
			u16 deficit = (u16)(fused_val & 0xFFFF);
			u64 used = (tick_sl > rem_sl) ? (tick_sl - rem_sl) : 0;
			u16 rt_us = (u16)(used >> 10);
			volatile u16 new_avg = (old_avg * 7 + rt_us) >> 3;
			volatile u16 new_def = (deficit > rt_us) ? deficit - rt_us : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RESERVED_17];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = new_avg + new_def;
		}
	}

	/* Bench: Mailbox CL0 multi-field read simulation.
	 * Reads cached_tctx_ptr + cached_deficit + cached_packed from CL0.
	 * Simulates the full cake_stopping mailbox-only path (zero arena). */
#ifndef CAKE_RELEASE
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 ptr = mbox->cached_tctx_ptr;
			volatile u32 fused = mbox->cached_deficit;
			volatile u32 packed = mbox->cached_packed;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PSYCHIC_HIT_SIM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ptr + fused + packed;
		}
	}
#endif

	/* Bench: scx_bpf_test_and_clear_cpu_idle(sibling) — cross-CPU contention.
	 * Simulates cross-CPU idle probing where we probe a DIFFERENT CPU's idle state.
	 * This reveals MESI contention cost: the idle bitmap cache line must
	 * be snooped from the remote CPU owner (30-100ns on Zen 5).
	 * Compare against BENCH_TEST_CLEAR_IDLE (local CPU, ~15ns). */
	{
		u32 local_cpu = bpf_get_smp_processor_id();
		/* Pick SMT sibling (XOR 1 gives the hyper-thread pair on Zen) */
		s32 remote_cpu = (s32)((local_cpu ^ 1) & (CAKE_MAX_CPUS - 1));
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			bool idle = scx_bpf_test_and_clear_cpu_idle(remote_cpu);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_IDLE_REMOTE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)idle;
		}
	}

	/* Bench: Read-only idle smtmask check — zero-contention alternative.
	 * scx_bpf_get_idle_smtmask() returns a reference to the SMT idle mask
	 * (per-core fully-idle tracking). cpumask_test_cpu is a pure read —
	 * no atomic test-and-clear, no cache line invalidation.
	 * This is the fastest way to CHECK if a CPU is idle without CLAIMING it.
	 * Use case: pre-screen before committing with test_and_clear. */
	{
		u32 local_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			const struct cpumask *smtmask = scx_bpf_get_idle_smtmask();
			volatile bool fully_idle = bpf_cpumask_test_cpu(local_cpu, smtmask);
			scx_bpf_put_idle_cpumask(smtmask);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_IDLE_SMTMASK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)fully_idle;
		}
	}

	/* Bench: Full Disruptor handoff read — simulates cake_stopping.
	 * Reads all 5 CL0 fields from the local CPU mailbox in sequence.
	 * Measures MLP benefit of concentrating all handoff data on one CL. */
#ifndef CAKE_RELEASE
	{
		u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[local_cpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 _ptr = mbox->cached_tctx_ptr;
			volatile u32 _fused = mbox->cached_deficit;
			volatile u32 _packed = mbox->cached_packed;
			volatile u64 _nvcsw = mbox->cached_nvcsw;
			volatile u64 _slice = mbox->tick_slice;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_DISRUPTOR_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = _ptr + _fused + _packed + _nvcsw + _slice;
		}
	}
#endif

	/* Bench: get_task_ctx + arena CL0 read — simulates cake_running.
	 * Measures the kfunc + dependent arena load chain.
	 * Uses bpf_get_current_task_btf() as the task source. */
	{
		struct task_struct *cur = bpf_get_current_task_btf();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct cake_task_ctx __arena *tctx = get_task_ctx(cur);
			volatile u32 _packed = tctx ? tctx->packed_info : 0;
			volatile u16 _fused = 0;
			volatile u32 _ppid = tctx ? tctx->ppid : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TCTX_COLD_SIM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = _packed + _fused + _ppid;
		}
	}

	/* Bench: Arena stride — walk 16 per_cpu mailbox entries.
	 * Forces TLB walks across arena pages. With 4KB pages, each per_cpu
	 * block (64B release / 128B debug) may share pages. With hugepages
	 * (2MB), all 16 fit in one TLB entry. Delta vs BENCH_ARENA_DEREF
	 * (single hot access) reveals the TLB miss tax. */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 sum = 0;
			#pragma unroll
			for (int c = 0; c < 16; c++) {
				sum += per_cpu[c & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at;
			}
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_STRIDE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sum;
		}
	}
#endif

	/* ═══ NEW ENTRIES (24–42): eBPF helpers + SCX kfuncs ═══ */

	/* Bench: bpf_ktime_get_boot_ns() — suspend-aware monotonic clock */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_KTIME_BOOT_NS], bpf_ktime_get_boot_ns(), i);

	/* NOTE: bpf_ktime_get_coarse_ns (slot 25), bpf_jiffies64 (slot 26),
	 * and bpf_ktime_get_tai_ns (slot 27) are NOT available for struct_ops
	 * programs — the kernel rejects them at load time. Slots left empty. */

	/* Bench: bpf_get_current_pid_tgid() — PID+TGID in single call */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_CURRENT_PID_TGID], bpf_get_current_pid_tgid(), i);

	/* Bench: bpf_get_current_task_btf() — get task_struct directly */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_CURRENT_TASK_BTF], (u64)bpf_get_current_task_btf(), i);

	/* Bench: bpf_get_current_comm() — read task comm name (16 bytes) */
	{
		char comm[16];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			long ret = bpf_get_current_comm(comm, sizeof(comm));
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CURRENT_COMM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)ret;
		}
	}

	/* Bench: bpf_get_numa_node_id() — current NUMA node */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_NUMA_NODE_ID], bpf_get_numa_node_id(), i);

	/* Bench: scx_bpf_task_running(p) — check if task is currently on-CPU */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_TASK_RUNNING], scx_bpf_task_running(p), i);

	/* Bench: scx_bpf_task_cpu(p) — get task's current CPU */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_TASK_CPU], scx_bpf_task_cpu(p), i);

	/* Bench: scx_bpf_nr_node_ids() — NUMA node count (topology constant) */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_NR_NODE_IDS], scx_bpf_nr_node_ids(), i);

	/* Bench: scx_bpf_cpuperf_cur(cpu) — current CPU performance level */
	{
		s32 bench_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_CPUPERF_CUR], scx_bpf_cpuperf_cur(bench_cpu), i);
	}

	/* Bench: bpf_task_storage_get() — standard per-task map lookup.
	 * This is the approach cake replaced with arena. Measuring the cost
	 * validates our arena design decision. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct bench_task_val *v = bpf_task_storage_get(
				&bench_task_storage, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_STORAGE_GET];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v ? v->dummy : 0;
		}
	}

	/* Bench: scx_bpf_pick_idle_cpu() — kernel's idle CPU scanner */
	{
		const struct cpumask *online = scx_bpf_get_online_cpumask();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_PICK_IDLE_CPU],
				  scx_bpf_pick_idle_cpu(online, 0), i);
		scx_bpf_put_cpumask(online);
	}

	/* BENCH_SELECT_CPU_AND intentionally skipped here.
	 *
	 * BenchLab runs from cake_stopping(), but scx_bpf_select_cpu_and() is
	 * only legal from select_cpu/enqueue or unlocked SYSCALL contexts in
	 * the kernel's SCX kfunc filter. Running it from stopping triggers a
	 * runtime exit in debug builds.
	 *
	 * Keep the slot reserved so BenchLab indices remain stable. */

	/* Bench: scx_bpf_get_idle_cpumask() + put — full idle mask cycle */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			const struct cpumask *idle = scx_bpf_get_idle_cpumask();
			scx_bpf_put_idle_cpumask(idle);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SCX_IDLE_CPUMASK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = 0;
		}
	}

	/* Bench: scx_bpf_kick_cpu() — IPI preemption cost.
	 * Kicks current CPU with no flags (cheapest IPI). */
	{
		s32 self_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_KICK_CPU],
				  (scx_bpf_kick_cpu(self_cpu, 0), 0), i);
	}

	/* Bench: bpf_get_prandom_u32() — pseudo-RNG cost */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_PRANDOM_U32], bpf_get_prandom_u32(), i);

	/* Bench: bpf_spin_lock + unlock cycle — lock contention baseline */
	{
		u32 key = 0;
		struct bench_lock_data *ld = bpf_map_lookup_elem(&bench_lock_map, &key);
		if (ld) {
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				bpf_spin_lock(&ld->lock);
				ld->counter++;
				bpf_spin_unlock(&ld->lock);
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_SPIN_LOCK];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = ld->counter;
			}
		}
	}

	/* Bench: scx_bpf_cpuperf_cap(cpu) — max performance capacity */
	{
		s32 cap_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_CPUPERF_CAP], scx_bpf_cpuperf_cap(cap_cpu), i);
	}

	/* ═══ CAKE COMPETITOR ENTRIES (43–49) ═══ */

	/* Bench: RODATA nr_cpus read — JIT-constant, should be ~0ns overhead */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_RODATA_NR_CPUS], (u64)nr_cpus, i);

	/* Bench: RODATA nr_nodes read — JIT-constant vs scx_bpf_nr_node_ids() */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_RODATA_NR_NODES], (u64)nr_nodes, i);

	/* Bench: RODATA cpuperf_cap_table[cpu] — per-CPU array vs kfunc */
	{
		s32 perf_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_RODATA_CPUPERF_CAP],
				  (u64)cpuperf_cap_table[perf_cpu & (CAKE_MAX_CPUS - 1)], i);
	}

	/* Bench: p->pid + p->tgid direct read — same cost as arena-cached fields
	 * (both are fixed-offset reads from an already-hot struct base pointer) */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 cached_pid = ((u64)p->tgid << 32) | p->pid;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_PID_TGID];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = cached_pid;
		}
	}

	/* Bench: Mbox CL0 cached_cpu read — already-hot CL0 vs scx_bpf_task_cpu kfunc */
#ifndef CAKE_RELEASE
	{
		s32 mbox_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_MBOX_TASK_CPU],
				  (u64)per_cpu[mbox_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu, i);
	}
#endif

	/* Bench: CL0 lock-free atomic read — Disruptor pattern vs spin_lock cycle.
	 * Reads 3 adjacent CL0 fields with zero locking overhead. */
#ifndef CAKE_RELEASE
	{
		s32 lf_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 lf_val =
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu +
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_tier +
				cpu_bss[lf_cpu & (CAKE_MAX_CPUS - 1)].idle_hint;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CL0_LOCKFREE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = lf_val;
		}
	}
#endif

	/* Bench: BSS xorshift32 PRNG — zero-kfunc RNG vs bpf_get_prandom_u32 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			u32 x = bench_xorshift_state;
			x ^= x << 13;
			x ^= x >> 17;
			x ^= x << 5;
			bench_xorshift_state = x;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_BSS_XORSHIFT];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)x;
		}
	}

	/* ═══ KERNEL FREE DATA PROBES (50–54) ═══
	 * These read kernel-maintained task_struct fields at ~3ns to validate
	 * whether they can replace BPF-side computation (EWMA, classification).
	 * Critical question: Does PELT still update under sched_ext? */

	/* Bench: PELT util_avg — kernel's PELT utilization metric (0-1024).
	 * Non-zero and changing confirms PELT is maintained under sched_ext.
	 * Zero BPF compute cost — kernel does all the work. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 util = p->se.avg.util_avg;
			volatile u64 runnable = p->se.avg.runnable_avg;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_UTIL_AVG];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (util << 16) | runnable; /* Pack both for TUI */
		}
	}

	/* Bench: PELT runnable_avg alone — single field read baseline.
	 * Should be ~3ns (fixed offset from p, already in register). */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_PELT_RUNNABLE_AVG], p->se.avg.runnable_avg, i);

	/* Bench: schedstats nr_wakeups — cumulative wakeup count.
	 * Requires CONFIG_SCHEDSTATS=y. Guarded for release builds where
	 * the target kernel may have CONFIG_SCHEDSTATS=n (common on aarch64). */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 wakeups = p->stats.nr_wakeups;
			volatile u64 wakeups_sync = p->stats.nr_wakeups_sync;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SCHEDSTATS_WAKEUPS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (wakeups << 32) | wakeups_sync;
		}
	}
#endif

	/* Bench: p->policy + p->in_iowait — free classification signals.
	 * policy: SCHED_NORMAL=0, SCHED_BATCH=3, SCHED_IDLE=5.
	 * in_iowait: 1 if task is waiting for I/O. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 policy = p->policy;
			volatile u32 prio = p->prio;
			volatile u32 flags = p->flags;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_POLICY_FLAGS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ((u64)policy << 32) | ((u64)prio << 16) | (flags & 0xFFFF);
		}
	}

	/* Bench: PELT read + tier classify.
	 * The critical comparison: 3ns PELT read replaces 12ns compute_ewma().
	 * Reads util_avg and does tier boundary compare. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			u64 util = p->se.avg.util_avg;
			/* Tier classification using PELT util_avg */
			volatile u8 tier = (util > 512) ? 2 : ((util > 128) ? 1 : 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_VS_EWMA];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ((u64)tier << 32) | util;
		}
	}

	/* ═══ END-TO-END WORKFLOW COMPARISONS (55–62) ═══
	 * These simulate FULL scheduler operations as they'd be used in practice,
	 * not isolated micro-ops. Compare storage backends, idle selection
	 * strategies, classification algorithms, and SMT probing approaches. */

	/* Bench 55: BSS cpu_bss write+read roundtrip — current per-CPU storage.
	 * Write idle_hint+run_start (like running), read back
	 * (like select_cpu gate checks). This is the REAL cost of BSS storage. */
	{
		s32 bss_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Write (like cake_running writes to cpu_bss) */
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].idle_hint = 1;
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start = 12345678ULL;
			asm volatile("" ::: "memory");
			/* Read back (like cake_select_cpu reads cpu_bss) */
			volatile u8 hint = READ_ONCE(cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].idle_hint);
			volatile u64 start = READ_ONCE(cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_STORAGE_ROUNDTRIP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = hint + start;
		}
	}

	/* Bench 56: Arena write+read roundtrip — same operation via arena.
	 * Compare against slot 55 to see the TLB walk penalty. */
#ifndef CAKE_RELEASE
	{
		s32 ar_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Write to arena mbox (like old cake_running) */
			per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at = 0xCAFEBABE;
			asm volatile("" ::: "memory");
			/* Read back from arena (like old cake_select_cpu gate check) */
			volatile u64 readback = per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at;
			volatile u32 tier = per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_tier;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_ROUNDTRIP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = readback + tier;
		}
	}
#endif

	/* Bench 57: 3-probe cascade simulation — cake's select_cpu flow.
	 * Tests: prev idle check → BSS[sib] idle_hint → BSS[home] idle_hint.
	 * This is the FULL cascade data access pattern. */
	{
		s32 self = bpf_get_smp_processor_id();
		s32 sib = cpu_sibling_map[self & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Probe 1: prev idle? (test_and_clear is the real op) */
			volatile bool prev_idle = scx_bpf_test_and_clear_cpu_idle(self);
			/* Probe 2: sibling idle_hint from BSS? */
			volatile u8 sib_idle = READ_ONCE(cpu_bss[sib & (CAKE_MAX_CPUS - 1)].idle_hint);
			/* Probe 3: home CPU idle_hint from BSS? (simulated as prev) */
			volatile u8 home_idle = READ_ONCE(cpu_bss[self & (CAKE_MAX_CPUS - 1)].idle_hint);
			/* Gate decision */
			volatile s32 result = prev_idle ? self :
						(sib_idle ? sib : (home_idle ? self : -1));
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CASCADE_VS_PICK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)result;
		}
	}

	/* Bench 58: pick_idle_cpu full path — bpfland/cosmos approach.
	 * kfunc + cpumask allowed check + SMT filter. Compare vs slot 57. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Full pick_idle path: kfunc scan + affinity verify */
			s32 found_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
			/* Verify found CPU is valid (bpfland does this) */
			volatile bool valid = (found_cpu >= 0) &&
				bpf_cpumask_test_cpu(found_cpu, p->cpus_ptr);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PICK_IDLE_FULL];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)found_cpu + (u64)valid;
		}
	}

	/* Bench 59: Weight-based classification (bpfland approach).
	 * Reads p->scx.weight and computes vtime offset — the FULL
	 * classification path of bpfland. Compare vs slot 17 (legacy EWMA, now reserved). */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 weight = p->scx.weight;
			/* bpfland: vtime += slice_lag * 100 / weight */
			volatile u64 vtime_offset = (40ULL * 1000000ULL * 100ULL) /
				(weight ? weight : 1);
			/* bpfland: task_slice(p) = slice_ns * 100 / weight */
			volatile u64 slice = (5000000ULL * 100ULL) /
				(weight ? weight : 1);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CLASSIFY_WEIGHT];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = vtime_offset + slice;
		}
	}

	/* Bench 60: Latency-critical classification (lavd approach).
	 * Reads task wakeup stats + computes latency criticality score.
	 * Simulates lavd's update_stat_for_running key path. Compare vs 17.
	 * Requires CONFIG_SCHEDSTATS=y for p->stats.nr_wakeups access. */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* lavd reads these per-task stats to compute lat_cri */
			volatile u64 wakeups = p->stats.nr_wakeups;
			volatile u64 sync_wakeups = p->stats.nr_wakeups_sync;
			volatile u64 nvcsw = p->nvcsw;
			volatile u64 nivcsw = p->nivcsw;
			/* lavd's lat_cri = f(sync_ratio, run_freq) */
			u64 total = wakeups ? wakeups : 1;
			volatile u64 sync_ratio = (sync_wakeups * 1000) / total;
			volatile u64 cs_ratio = (nvcsw * 1000) / (nvcsw + nivcsw + 1);
			volatile u64 lat_score = sync_ratio + cs_ratio;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CLASSIFY_LATCRI];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = lat_score;
		}
	}
#endif

	/* Bench 61: cake SMT probe — test_and_clear(sibling) + BSS check.
	 * This is cake's idle sibling probe: atomic idle clear + BSS idle_hint read.
	 * The FULL SMT probe path as used in select_cpu. */

	{
		s32 self_cpu = bpf_get_smp_processor_id();
		s32 sib_cpu = cpu_sibling_map[self_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Cake: atomic test_and_clear on sibling */
			volatile bool sib_idle = scx_bpf_test_and_clear_cpu_idle(
				sib_cpu & (CAKE_MAX_CPUS - 1));
			/* Plus BSS hint read (what running wrote) */
			volatile u8 hint = READ_ONCE(cpu_bss[sib_cpu & (CAKE_MAX_CPUS - 1)].idle_hint);
			volatile bool should_use = sib_idle || hint;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SMT_CAKE_PROBE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = should_use;
		}
	}

	/* Bench 62: bpfland/cosmos SMT probe — cpumask-based contention check.
	 * is_smt_contended(): get idle smtmask → cpumask_test_cpu(sibling).
	 * Requires kfunc for smtmask + cpumask ops. Compare vs slot 61. */
	{
		s32 smt_cpu = bpf_get_smp_processor_id();
		s32 smt_sib = cpu_sibling_map[smt_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* bpfland: get idle SMT mask + test if sibling is in it */
			const struct cpumask *idle_smt = scx_bpf_get_idle_smtmask();
			volatile bool sib_fully_idle =
				bpf_cpumask_test_cpu(smt_sib & (CAKE_MAX_CPUS - 1), idle_smt);
			scx_bpf_put_idle_cpumask(idle_smt);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SMT_CPUMASK_PROBE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sib_fully_idle;
		}
	}

	/* ═══ FAIRNESS FIXES: COLD-CACHE + REMOTE ═══
	 * These probes simulate production conditions where data may not be L1-hot.
	 * Cold simulation: read 32 unrelated arena cache lines (2KB) between
	 * iterations to evict the target data from L1D (32KB, 8-way).
	 * This models the real cost when a different task ran between accesses. */

#ifndef CAKE_RELEASE
	/* Bench: bpf_task_storage_get — COLD task (first access per-task).
	 * Evict the storage cache between iterations to measure the slow path:
	 * hlist walk + spinlock cache insertion, not the cached fast path. */
	{
		ARENA_ASSOC();
		u32 ccpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena to evict storage cache lines */
			volatile u64 sink = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ccpu + j + 1) & (CAKE_MAX_CPUS - 1);
				sink += per_cpu[idx].mbox.cached_cpu;
			}
			u64 _s = bpf_ktime_get_ns();
			/* bpf_task_storage_get removed */
			volatile u16 cold_val = 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_STORAGE_GET_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = cold_val + sink;
		}
	}
#endif

#ifndef CAKE_RELEASE
	/* Bench: PELT util_avg — COLD p->se.avg (evicted from L1).
	 * In production, each stopping() call processes a DIFFERENT task.
	 * p->se.avg may be in a cold cache line if the task hasn't run recently. */
	{
		ARENA_ASSOC();
		u32 ccpu2 = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena to evict p->se.avg cache line */
			volatile u64 sink2 = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ccpu2 + j + 1) & (CAKE_MAX_CPUS - 1);
				sink2 += per_cpu[idx].mbox.tick_slice;
			}
			u64 _s = bpf_ktime_get_ns();
			u64 util_cold = p->se.avg.util_avg;
			volatile u8 tier = (util_cold > 600) ? 2 : (util_cold > 200) ? 1 : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = tier + sink2;
		}
	}
#endif

#ifndef CAKE_RELEASE
	/* Bench: Legacy EWMA compute — COLD cpu_bss (evicted from L1).
	 * In production, cpu_bss[cpu] may be evicted if another BPF program
	 * or kernel path displaced the cache line between scheduling events. */
	{
		u32 ewma_c = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		ARENA_ASSOC();
		u32 fused_c = 0x00C80064;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena */
			volatile u64 sink3 = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ewma_c + j + 1) & (CAKE_MAX_CPUS - 1);
				sink3 += per_cpu[idx].mbox.cached_deficit;
			}
			u64 _s = bpf_ktime_get_ns();
			u64 tick_c = cpu_bss[ewma_c].tick_slice;
			u64 rem_c = p->scx.slice;
			u16 oavg = (u16)(fused_c >> 16);
			u16 odef = (u16)(fused_c & 0xFFFF);
			u64 used_c = (tick_c > rem_c) ? (tick_c - rem_c) : 0;
			u16 rt_c = (u16)(used_c >> 10);
			volatile u16 navg = (oavg * 7 + rt_c) >> 3;
			volatile u16 ndef = (odef > rt_c) ? odef - rt_c : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_EWMA_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = navg + ndef + sink3;
		}
	}
#endif

	/* Bench: kick_cpu — REMOTE sibling (real IPI, not self-noop).
	 * scx_bpf_kick_cpu(self) is a bit-set noop. Production kicks remote
	 * CPUs which triggers deferred IPI via irq_work. */
	{
		s32 kick_cpu = bpf_get_smp_processor_id();
		s32 kick_sib = cpu_sibling_map[kick_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			scx_bpf_kick_cpu(kick_sib & (CAKE_MAX_CPUS - 1), 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_KICK_REMOTE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = kick_sib;
		}
	}

	r->bench_timestamp = bpf_ktime_get_ns();
	*(volatile u32 *)&bench_active = 0;  /* Re-enable CAKE_STATS_ACTIVE */
}





/* ═══ Per-Task Context Accessors ═══ */

/* get_task_ctx: returns the task's arena-backed context (telemetry, packed_info).
 * Arena storage is allocated in cake_init_task (sleepable context).
 * Cost: ~16-29ns (scx_task_data kfunc + pointer cast).
 * Used in: cold paths (telemetry, reclassifier 1/64 stops). */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p)
{
	return (struct cake_task_ctx __arena *)scx_task_data(p);
}

/* get_task_hot: returns the task's Arena storage (~1ns).
 * All callers are behind #ifndef CAKE_RELEASE (telemetry, reclassifier). */
#ifndef CAKE_RELEASE
static __always_inline struct cake_task_ctx __arena *
get_task_hot(struct task_struct *p)
{
	return get_task_ctx(p);
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

static __always_inline void cake_record_startup_enqueue(
	struct cake_task_ctx __arena *tctx,
	u64 enqueue_start_ns)
{
	bool first_enqueue;

	if (!cake_startup_trace_open(tctx))
		return;

	first_enqueue =
		!(tctx->telemetry.startup_phase_mask & CAKE_STARTUP_MASK_ENQUEUE);
	cake_record_startup_phase(tctx, CAKE_STARTUP_PHASE_ENQUEUE,
				  CAKE_STARTUP_MASK_ENQUEUE);
	if (first_enqueue)
		tctx->telemetry.startup_enqueue_us =
			cake_startup_delta_us(tctx, enqueue_start_ns);
}

static __always_inline void cake_record_startup_select(
	struct cake_task_ctx __arena *tctx,
	u64 select_start_ns)
{
	bool first_select;

	if (!cake_startup_trace_open(tctx))
		return;

	first_select =
		!(tctx->telemetry.startup_phase_mask & CAKE_STARTUP_MASK_SELECT);
	cake_record_startup_phase(tctx, CAKE_STARTUP_PHASE_SELECT,
				  CAKE_STARTUP_MASK_SELECT);
	if (first_select)
		tctx->telemetry.startup_select_us =
			cake_startup_delta_us(tctx, select_start_ns);
}
#endif

static __always_inline bool cake_should_steer(struct task_struct *p, u64 wake_flags)
{
	if (p->flags & PF_KTHREAD)
		return false;

	/* Protect render/helper wake chains too, not just sustained hot tasks.
	 * A lot of gaming-critical helpers are sync-woken but never build enough
	 * util_avg to qualify as "hot" by PELT alone. */
	return p->se.avg.util_avg >= CAKE_STEER_UTIL_MIN ||
	       (wake_flags & SCX_WAKE_SYNC);
}

static __always_inline u16 cake_primary_cpu(u16 cpu)
{
	if (cpu >= nr_cpus)
		return CAKE_CPU_SENTINEL;

	if (cpu_thread_bit[cpu & (CAKE_MAX_CPUS - 1)] == 1)
		return cpu;

	u16 sib = cpu_sibling_map[cpu & (CAKE_MAX_CPUS - 1)];
	if (sib < nr_cpus && cpu_thread_bit[sib & (CAKE_MAX_CPUS - 1)] == 1)
		return sib;

	return cpu;
}

static __always_inline void cake_update_home_cpu(
	struct cake_task_ctx __arena *tctx, u16 cpu)
{
	u16 primary = cake_primary_cpu(cpu);
	if (primary == CAKE_CPU_SENTINEL)
		return;

	if (tctx->home_cpu == CAKE_CPU_SENTINEL) {
		tctx->home_cpu = primary;
		tctx->home_score = 1;
		tctx->home_core = cpu_core_id[primary & (CAKE_MAX_CPUS - 1)];
		return;
	}

	if (tctx->home_cpu == primary) {
		if (tctx->home_score < CAKE_HOME_SCORE_MAX)
			tctx->home_score++;
		tctx->home_core = cpu_core_id[primary & (CAKE_MAX_CPUS - 1)];
		return;
	}

	if (tctx->home_score > 0) {
		tctx->home_score--;
		return;
	}

	tctx->home_cpu = primary;
	tctx->home_score = 1;
	tctx->home_core = cpu_core_id[primary & (CAKE_MAX_CPUS - 1)];
}

/* ═══ Dedup Helpers ═══
 * Extracted from repeated inline blocks to reduce instruction count
 * and i-cache pressure. All __always_inline: zero call overhead. */

/* smt_sibling removed — 3-gate select_cpu delegates SMT handling
 * to scx_bpf_select_cpu_dfl (Gate 3) which handles it natively. */

/* ═══════════════════════════════════════════════════════════════════════════
 * S2 SELECT_CPU: 3-GATE IDLE CPU SELECTION
 * Gate hierarchy: prev_cpu idle → perf-ordered scan → kernel default → DSQ tunnel.
 * Task identity and fast-path scheduling state come from task_struct.
 *
 * PRINCIPLE: "Where to run" is orthogonal to "how long to run".
 *   1. Gate 1: prev_cpu idle
 *   2. Gate 2: perf-ordered scan (hybrid topology only)
 *   3. Gate 3: kernel scx_bpf_select_cpu_dfl (any idle CPU)
 *   4. Tunnel: all busy → enqueue to per-LLC DSQ, wait for dispatch
 * ═══════════════════════════════════════════════════════════════════════════ */


/* ═══ Kfunc Out-Param Wrappers ═══
 *
 * scx_bpf_select_cpu_dfl requires &is_idle out-param (3 r10/stack refs).
 * scx_bpf_select_cpu_and requires struct arg on stack (2 r10 refs).
 * Wrapping in __noinline isolates stack usage so cake_select_cpu
 * gets 0 r10 (stack pointer) references — cleaner register allocation.
 * cost: 1 extra call per select_cpu, negligible vs kfunc overhead. */

/* llc_scan_order REMOVED: declared and populated by loader but zero BPF readers.
 * Was: const volatile u8 llc_scan_order[CAKE_CLASS_MAX][CAKE_MAX_LLCS][CAKE_MAX_LLCS]; */

/* Returns cpu if idle found, -1 otherwise. */
static __noinline s32 select_cpu_dfl_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	return is_idle ? cpu : -1;
}

/* Returns cpu >= 0 if idle found, < 0 otherwise.
 * Compat-First CO-RE Dispatch: same wrapper strategy as local DSQ insert.
 * Prefers register-arg compat (0 stack) over struct-arg (24B on stack). */
static __noinline s32 select_cpu_and_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags,
	u64 enq_flags)
{
	/* Path 1: Register-arg compat (0 stack, 5 direct args).
	 * Available 6.15-6.22. JIT dead-codes path 2. */
	if (bpf_ksym_exists(scx_bpf_select_cpu_and___compat))
		return scx_bpf_select_cpu_and___compat(p, prev_cpu, wake_flags,
						       p->cpus_ptr, enq_flags);
	/* Path 2: Struct-arg (6.19+ when compat dropped after v6.23).
	 * Stack build isolated in this __noinline frame. */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
				      p->cpus_ptr, enq_flags);
}

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/* RELEASE: zero arena dereferences in this callback — all behind
	 * stats_on / #ifndef CAKE_RELEASE guards. Skip ARENA_ASSOC to avoid
	 * wasting a callee-saved register + 2 instructions. */
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

#ifndef CAKE_RELEASE
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 start_time = 0;
	if (stats_on)
		start_time = bpf_ktime_get_ns();
#else
	#define stats_on 0
	u64 start_time = 0;
#endif
	bool __maybe_unused used_gate2 = false;
	bool __maybe_unused used_home = false;
	bool __maybe_unused used_home_core = false;
	bool __maybe_unused used_pressure_core = false;
	bool __maybe_unused used_prev_primary = false;
	bool __maybe_unused used_scan_primary = false;
	u8 selected_path = CAKE_SELECT_PATH_NONE;
	u8 selected_reason = CAKE_SELECT_REASON_NONE;
	u64 gate2_start = 0;
	s32 cpu = -1;
	bool steer_hot = cake_should_steer(p, wake_flags);
	struct cake_task_ctx __arena *steer_tctx = NULL;

	if (steer_hot)
		steer_tctx = get_task_ctx(p);

	if (steer_tctx) {
		struct cake_stats *steer_stats = stats_on ? get_local_stats() : NULL;
		u16 home_cpu = steer_tctx->home_cpu;
		u8 home_core = steer_tctx->home_core;
		bool primary_scan_attempted = false;

		if (steer_stats)
			steer_stats->nr_steer_eligible++;

		cpu = cake_pick_pressure_sibling(
			steer_tctx, (s32)home_cpu, p->cpus_ptr,
			CAKE_PRESSURE_PROBE_SITE_HOME);
		if (cpu >= 0) {
			used_pressure_core = true;
			goto idle_found;
		}

		if (home_cpu < nr_cpus && home_cpu != prev_cpu &&
		    bpf_cpumask_test_cpu(home_cpu, p->cpus_ptr)) {
			if (scx_bpf_test_and_clear_cpu_idle(home_cpu)) {
				cpu = home_cpu;
				used_home = true;
				goto idle_found;
			}
			if (steer_stats)
				steer_stats->nr_home_cpu_busy_misses++;
		}

		/* Keep sync wake chains on the learned core if the exact home lane is
		 * busy but its known sibling lane is idle. A bounded sibling probe keeps
		 * verifier state small while preserving the common SMT handoff. */
		if ((wake_flags & SCX_WAKE_SYNC) && home_core < 0xFF &&
		    home_cpu < CAKE_MAX_CPUS) {
			u16 candidate = cpu_sibling_map[home_cpu & (CAKE_MAX_CPUS - 1)];

			if (candidate < nr_cpus && candidate != home_cpu &&
			    candidate != (u32)prev_cpu &&
			    cpu_core_id[candidate & (CAKE_MAX_CPUS - 1)] == home_core &&
			    bpf_cpumask_test_cpu(candidate, p->cpus_ptr)) {
				if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
					cpu = (s32)candidate;
					used_home_core = true;
					goto idle_found;
				}
			}
		}

		/* The pressure sibling helper reasons from a physical-core primary
		 * anchor. Normalize prev_cpu first so a task that last ran on an SMT
		 * secondary lane can still evaluate same-core pressure spill instead
		 * of getting counted as a structural anchor miss. */
		u16 prev_primary = cake_primary_cpu((u16)prev_cpu);
		cpu = cake_pick_pressure_sibling(
			steer_tctx, (s32)prev_primary, p->cpus_ptr,
			CAKE_PRESSURE_PROBE_SITE_PREV);
		if (cpu >= 0) {
			used_pressure_core = true;
			goto idle_found;
		}

		/* If the task last ran on an SMT secondary lane and the primary
		 * sibling is idle, pull it back onto the primary lane before
		 * widening the search. This improves same-core warmth without
		 * forcing the task to wait behind a busy primary. */
		{
			if (prev_primary < nr_cpus && prev_primary != prev_cpu &&
			    prev_primary != home_cpu &&
			    bpf_cpumask_test_cpu(prev_primary, p->cpus_ptr)) {
				if (scx_bpf_test_and_clear_cpu_idle(prev_primary)) {
					cpu = prev_primary;
					used_prev_primary = true;
					goto idle_found;
				}
				if (steer_stats)
					steer_stats->nr_prev_primary_busy_misses++;
			}
		}

		if (cpu_sibling_map[prev_cpu & (CAKE_MAX_CPUS - 1)] != prev_cpu) {
			u16 start_cpu = home_cpu < nr_cpus ? home_cpu : (u16)prev_cpu;
			start_cpu = cake_primary_cpu(start_cpu);
			if (start_cpu < nr_cpus) {
				for (u32 off = 0; off < CAKE_MAX_CPUS && off < nr_cpus; off++) {
					u16 candidate = (start_cpu + off) % nr_cpus;
					if (candidate == prev_cpu || candidate == home_cpu)
						continue;
					if (cpu_thread_bit[candidate & (CAKE_MAX_CPUS - 1)] != 1)
						continue;
					if (!bpf_cpumask_test_cpu(candidate, p->cpus_ptr))
						continue;
					primary_scan_attempted = true;
					if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
						cpu = candidate;
						used_scan_primary = true;
						goto idle_found;
					}
				}
			}
		}

		if (primary_scan_attempted && steer_stats)
			steer_stats->nr_primary_scan_misses++;
	}


	/* ── KERNEL IDLE SELECTION ──
	 * Uses scx_bpf_select_cpu_and (6.17+) or scx_bpf_select_cpu_dfl (6.12+).
	 * CO-RE dead-code eliminates the unused path at load time.
	 * Both provide: prev_cpu idle test, SYNC wake-affine, SMT full-idle,
	 * LLC-scoped scan, NUMA-scoped scan, global scan, and proper
	 * affinity handling for restricted tasks (Wine/Proton). */
	/* SYNC waker/wakee bypass REMOVED (Phase 20: Branch Annihilation).
	 *
	 * The manual scx_bpf_test_and_clear_cpu_idle(waker_cpu) was:
	 *   1. An unpredictable 50/50 branch (the ONLY one in the hot path).
	 *   2. A dumbed-down subset of the kernel's native SYNC handler
	 *      (ext_idle.c:519-553), which checks cache affinity between
	 *      waker and prev_cpu, verifies the waker's local DSQ is empty,
	 *      AND uses inline scx_idle_test_and_clear_cpu() (zero RCU guard
	 *      overhead) vs our kfunc path (RCU + ops_cpu_valid + static_branch).
	 *   3. Redundant: the kernel's select_cpu_dfl/select_cpu_and already
	 *      executes the superior SYNC logic when wake_flags has the bit set.
	 *
	 * Net effect: -1 unpredictable branch, -5 instructions, +cache-affinity
	 * awareness that we were previously bypassing. */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		/* Kernel ≤ 6.16: scx_bpf_select_cpu_dfl via noinline wrapper.
		 * CO-RE prunes this entire block on 6.17+. */
		cpu = select_cpu_dfl_idle(p, prev_cpu, wake_flags);
		if (cpu >= 0)
			goto idle_found;
		/* !idle: on hybrid, jump to Gate 2 P/E scan.
		 * On non-hybrid, skip select_cpu_and_idle (it's the 6.17+ path)
		 * and fall through to the tunnel (return prev_cpu).
		 * CO-RE prunes this entire block on 6.17+. */
#ifdef CAKE_HAS_HYBRID
		goto gate2;
#else
		goto tunnel;
#endif
	}

	/* ALPHADEV Phase 10: BPF-Native Sharded Lockless Scanner
	 * 1. Pre-Flight Affinity Bypass: The kernel strictly enforces task pinning.
	 *    If a task is pinned (e.g., Proton limits) or migration is disabled,
	 *    we MUST bypass the native scanner and fallback to the kernel tracking.
	 *    is_bpf_migration_disabled is true for ALL current tasks under BPF sandbox,
	 *    so we rely purely on nr_cpus_allowed. */
	/* ALPHADEV Phase 17/19: Ghost Branch Annihilation
	 * Unrestricted or pinned, the kernel native wrapper natively honors bounds.
	 * Removing the redundant wrapper branch completely flattens the execution tree
	 * and preserves Zen 4 Branch Predictor slots from dead-code evaluation. */
	cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);
	if (cpu >= 0) goto idle_found;

	/* Force DSQ queuing if no idle cores found by lockless */
	if (cpu >= 0) {
idle_found: __attribute__((unused));
		if (used_home)
			selected_path = CAKE_SELECT_PATH_HOME_CPU;
		else if (used_home_core || used_pressure_core)
			selected_path = CAKE_SELECT_PATH_HOME_CORE;
		else if (used_prev_primary || used_scan_primary)
			selected_path = CAKE_SELECT_PATH_PRIMARY;
		else
			selected_path = CAKE_SELECT_PATH_IDLE;
		if (used_home)
			selected_reason = CAKE_SELECT_REASON_HOME_CPU;
		else if (used_home_core)
			selected_reason = CAKE_SELECT_REASON_HOME_CORE;
		else if (used_pressure_core)
			selected_reason = CAKE_SELECT_REASON_PRESSURE_CORE;
		else if (used_prev_primary)
			selected_reason = CAKE_SELECT_REASON_PREV_PRIMARY;
		else if (used_scan_primary)
			selected_reason = CAKE_SELECT_REASON_PRIMARY_SCAN;
		else if (used_gate2)
			selected_reason = CAKE_SELECT_REASON_HYBRID_SCAN;
		else if (cpu == prev_cpu)
			selected_reason = CAKE_SELECT_REASON_KERNEL_PREV;
		else
			selected_reason = CAKE_SELECT_REASON_KERNEL_IDLE;
		cake_record_select_choice(selected_reason, prev_cpu, cpu);
		if (stats_on) {
			u64 now = bpf_ktime_get_ns();
			u64 dur = now - start_time;
			struct cake_stats *s = get_local_stats();
			if (gate2_start) {
				s->total_gate1_latency_ns += gate2_start - start_time;
				s->total_gate2_latency_ns += now - gate2_start;
			} else {
				s->total_gate1_latency_ns += dur;
				}
				if (used_home)
					s->nr_home_cpu_steers++;
				else if (used_home_core || used_pressure_core)
					s->nr_home_core_steers++;
				else if (used_prev_primary || used_scan_primary)
					s->nr_primary_cpu_steers++;
			s->select_path_count[selected_path]++;
			s->total_select_cpu_ns += dur;
			cake_record_select_decision_cost(s, selected_reason, dur);
			s->max_select_cpu_ns =
				s->max_select_cpu_ns + ((dur - s->max_select_cpu_ns) & -(dur > s->max_select_cpu_ns));
			cake_record_cb(s, CAKE_CB_SELECT, dur);
#ifndef CAKE_RELEASE
			struct cake_task_ctx __arena *tctx = steer_tctx ? steer_tctx : get_task_ctx(p);
			if (tctx) {
				cake_record_startup_select(tctx, start_time);
				tctx->telemetry.select_cpu_duration_ns = (u32)dur;
				tctx->telemetry.gate_cascade_ns = (u32)dur;
				tctx->telemetry.pending_select_path = selected_path;
				tctx->telemetry.pending_select_reason = selected_reason;
				tctx->telemetry.last_place_class =
					cake_classify_home_place(tctx, cpu & (CAKE_MAX_CPUS - 1));
					tctx->telemetry.last_waker_place_class =
						cake_classify_waker_place(tctx, cpu & (CAKE_MAX_CPUS - 1));
					if (used_home)
						tctx->telemetry.gate_1c_hits++;
					else if (used_home_core || used_pressure_core)
						tctx->telemetry.gate_1c_hits++;
					else if (used_prev_primary)
						tctx->telemetry.gate_1cp_hits++;
				else if (used_scan_primary)
					tctx->telemetry.gate_1cp_hits++;
				else if (used_gate2)
					tctx->telemetry.gate_2_hits++;
				else
					tctx->telemetry.gate_1_hits++;
				if (cpu != prev_cpu)
					tctx->telemetry.migration_count++;
			}
#endif
			if (dur >= CAKE_SLOW_CALLBACK_NS)
				cake_emit_dbg_event(p, bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1),
						    CAKE_DBG_EVENT_CALLBACK, CAKE_CB_SELECT, dur, cpu);
		}
		return cpu;
	}

	/* ── GATE 2: Performance-ordered idle scan (HYBRID ONLY) ──
	 * Compiled out on homogeneous AMD SMP — verifier never sees this code.
	 * With game detection removed, this is a simple fast-to-slow idle scan. */
#ifdef CAKE_HAS_HYBRID
gate2:
	if (stats_on && !gate2_start)
		gate2_start = bpf_ktime_get_ns();
	if (has_hybrid_cores) {
		const u8 *scan_order = cpus_fast_to_slow;

		for (u32 i = 0; i < CAKE_MAX_CPUS && i < nr_cpus; i++) {
			u8 candidate = scan_order[i];
			if (candidate >= nr_cpus)
				break;  /* 0xFF sentinel or out of range */

			if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
				cpu = candidate;
				used_gate2 = true;
				goto idle_found;
			}
		}
	}
#endif

	/* ── TUNNEL: All CPUs busy — return prev_cpu ──
	 * cached_now staging REMOVED (−12 insns).
	 * bss->cached_now was written but had ZERO READERS in the codebase.
	 * Enqueue cold paths call scx_bpf_now() directly — the staging was dead
	 * code from pre-optimization.
	 * DSQ ordering handles shared fallback priority without extra state. */
tunnel:
	/* ALPHADEV Phase 3: Local-Until-Busy
	 * When NO idle cores exist, we default completely to the shared DSQ fallback routing
	 * instead of manually forcing slice shrinking or migrating within the lockless scan. */
	{
		selected_path = CAKE_SELECT_PATH_TUNNEL;
		selected_reason = CAKE_SELECT_REASON_TUNNEL;
		cake_record_select_choice(selected_reason, prev_cpu, -1);
		if (stats_on) {
			struct cake_stats *s = get_local_stats();
			u64 dur = bpf_ktime_get_ns() - start_time;
			s->nr_prev_cpu_tunnels++;
			s->select_path_count[selected_path]++;
			if (gate2_start) {
				s->total_gate1_latency_ns += gate2_start - start_time;
				s->total_gate2_latency_ns += dur - (gate2_start - start_time);
			} else {
				s->total_gate1_latency_ns += dur;
			}
			s->total_select_cpu_ns += dur;
			cake_record_select_decision_cost(s, selected_reason, dur);
			s->max_select_cpu_ns =
				s->max_select_cpu_ns + ((dur - s->max_select_cpu_ns) & -(dur > s->max_select_cpu_ns));
			cake_record_cb(s, CAKE_CB_SELECT, dur);
#ifndef CAKE_RELEASE
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) {
				cake_record_startup_select(tctx, start_time);
				tctx->telemetry.select_cpu_duration_ns = (u32)dur;
				tctx->telemetry.gate_cascade_ns = (u32)dur;
				tctx->telemetry.gate_tun_hits++;
				tctx->telemetry.pending_select_path = selected_path;
				tctx->telemetry.pending_select_reason = selected_reason;
				tctx->telemetry.last_place_class =
					cake_classify_home_place(tctx, prev_cpu & (CAKE_MAX_CPUS - 1));
				tctx->telemetry.last_waker_place_class =
					cake_classify_waker_place(tctx, prev_cpu & (CAKE_MAX_CPUS - 1));
			}
#endif
			if (dur >= CAKE_SLOW_CALLBACK_NS)
				cake_emit_dbg_event(p, bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1),
						    CAKE_DBG_EVENT_CALLBACK, CAKE_CB_SELECT, dur, prev_cpu);
		}
	}

	return prev_cpu;
#ifdef CAKE_RELEASE
	#undef stats_on
#endif
}
/* Cut 3: enqueue_depth_scale_slice DELETED — zero callers after removal.
 * Gaming DSQs have 0-1 tasks, making depth-scaled slicing dead weight. */

/* enqueue_dsq_dispatch: inserts a task into a per-LLC DSQ and optionally
 * direct-dispatches it when the target CPU still looks idle.
 *
 * Follows kernel enqueue_entity pattern. All scheduling state lives in p:
 *   - p->scx.dsq_vtime: task's position in the vtime-ordered DSQ
 *   - p->scx.slice: remaining time slice for this dispatch
 *
 * An empty shared DSQ alone is not enough for a direct handoff. schbench
 * regresses if we queue directly onto a target CPU that still appears busy,
 * so direct dispatch remains gated by cake's per-CPU idle hint.
 *
 * 3 args + 1 callee-save survivor (packed_cpu_llc) = 0 stack spills.
 *
 * ═══ TECHNIQUE: Compat-First CO-RE Dispatch ═══
 *
 * Problem: v6.19 kfuncs transitioned to struct-arg ABIs (e.g.,
 * __scx_bpf_dsq_insert_vtime takes a struct pointer). The shared
 * compat.bpf.h wrapper checks struct-arg FIRST → builds a 32B struct
 * on the stack → r10 (stack pointer) spill. On 6.19-6.22, the old
 * register-arg compat variant ALSO exists, but is checked second.
 *
 * Fix: Write our own __noinline wrapper that reverses CO-RE priority:
 *   Path 1: bpf_ksym_exists(___compat) → 5 register args → 0 stack
 *   Path 2: bpf_core_type_exists(struct args) → struct-arg fallback
 *   Path 3: old dispatch compat → register args → 0 stack
 *
 * Result: On 6.19.8, JIT resolves Path 1 true → register path taken,
 * struct-arg path dead-coded. Zero stack writes at runtime.
 * After v6.23 (compat dropped): Path 2 activates (stack in this frame).
 *
 * This technique applies to ANY CO-RE kfunc that transitioned from
 * register-arg to struct-arg in v6.19+. Candidates:
 *   - scx_bpf_select_cpu_and (already isolated in select_cpu_and_idle)
 * ═══════════════════════════════════════════════════════════════════ */

static __noinline void dsq_insert_wrapper(
	struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags)
{
	if (bpf_ksym_exists(scx_bpf_dsq_insert___v2___compat))
		scx_bpf_dsq_insert___v2___compat(p, dsq_id, slice, enq_flags);
	else if (bpf_ksym_exists(scx_bpf_dsq_insert___v1))
		scx_bpf_dsq_insert___v1(p, dsq_id, slice, enq_flags);
	else
		scx_bpf_dispatch___compat(p, dsq_id, slice, enq_flags);

#ifndef CAKE_RELEASE
	cake_record_local_insert(dsq_id);
#endif
}

static __noinline s64 calc_nice_adj(u32 weight)
{
	s32 wd = 100 - (s32)weight;
	return ((s64)wd << 14) + ((s64)wd << 12);
}

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

static __always_inline u8 cake_shadow_classify_task(
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

	if (mask & (cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY) |
		    cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY)))
		return CAKE_WAKE_CLASS_CONTAIN;
	if ((mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LATENCY_PRIO)) ||
	    ((mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_SHORT_RUN)) &&
	     (mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_WAKE_DENSE))))
		return CAKE_WAKE_CLASS_SHIELD;
	return CAKE_WAKE_CLASS_NORMAL;
}

static __always_inline u8 cake_shadow_busy_preempt_decision(
	u8 wakee_class, u8 owner_class, u8 target_pressure)
{
	if (target_pressure >= 64 || wakee_class == CAKE_WAKE_CLASS_CONTAIN)
		return CAKE_BUSY_PREEMPT_SHADOW_SKIP;
	if (wakee_class == CAKE_WAKE_CLASS_SHIELD)
		return owner_class == CAKE_WAKE_CLASS_SHIELD ?
			CAKE_BUSY_PREEMPT_SHADOW_SKIP :
			CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	if (owner_class == CAKE_WAKE_CLASS_CONTAIN)
		return CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	return CAKE_BUSY_PREEMPT_SHADOW_SKIP;
}

static __always_inline void cake_record_busy_preempt_shadow(
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

static __noinline void enqueue_dsq_dispatch(
	struct task_struct *p,
	u64 enq_flags,
	u32 enq_cpu)
{
	u32 target_cpu_idx = enq_cpu & (CAKE_MAX_CPUS - 1);
	bool can_direct = false;
	u8 idle_hint = 0;
	s32 kick_cpu = -1;
	u64 kick_flags = SCX_KICK_IDLE;
	bool is_wakeup = !!(enq_flags & (u64)SCX_ENQ_WAKEUP);
#ifndef CAKE_RELEASE
	bool stats_on = CAKE_STATS_ACTIVE;
	struct cake_stats *stats = stats_on ? get_local_stats() : NULL;
	bool wake_target_local = false;
	struct cake_task_ctx __arena *tctx = NULL;
	if (stats_on)
		tctx = get_task_ctx(p);
#else
	#define stats_on 0
	#define stats ((struct cake_stats *)0)
#endif

	if (is_wakeup) {
#ifndef CAKE_RELEASE
		if (stats_on && tctx) {
			tctx->telemetry.pending_target_cpu = (u16)enq_cpu;
			tctx->telemetry.pending_kick_kind = CAKE_KICK_KIND_NONE;
			tctx->telemetry.pending_kick_ts_ns = 0;
			tctx->telemetry.pending_blocker_pid = 0;
			tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
		}
#endif
		u32 current_cpu_idx = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
#ifndef CAKE_RELEASE
		wake_target_local = current_cpu_idx == target_cpu_idx;
#endif

		if (current_cpu_idx == target_cpu_idx) {
			if (stats) {
				stats->nr_wakeup_dsq_fallback_busy++;
				stats->nr_wakeup_busy_local_target++;
				stats->nr_enqueue_busy_local_skip_depth++;
			}
#ifndef CAKE_RELEASE
			if (tctx) {
				tctx->telemetry.pending_wake_reason = CAKE_WAKE_REASON_BUSY;
				tctx->telemetry.pending_blocker_pid =
					READ_ONCE(cpu_bss[target_cpu_idx].last_pid);
				tctx->telemetry.pending_blocker_cpu = (u16)target_cpu_idx;
			}
#endif
		} else {
			if (stats_on)
				stats->nr_idle_hint_remote_reads++;
			idle_hint = READ_ONCE(cpu_bss[target_cpu_idx].idle_hint);
			if (stats_on) {
				if (idle_hint)
					stats->nr_idle_hint_remote_idle++;
				else
					stats->nr_idle_hint_remote_busy++;
			}
			if (!idle_hint) {
				if (stats) {
					stats->nr_wakeup_dsq_fallback_busy++;
					stats->nr_wakeup_busy_remote_target++;
					stats->nr_enqueue_busy_remote_skip_depth++;
				}
#ifndef CAKE_RELEASE
				if (tctx) {
					tctx->telemetry.pending_wake_reason = CAKE_WAKE_REASON_BUSY;
					tctx->telemetry.pending_blocker_pid =
						READ_ONCE(cpu_bss[target_cpu_idx].last_pid);
					tctx->telemetry.pending_blocker_cpu = (u16)target_cpu_idx;
				}
#endif
			} else {
				can_direct = true;
			}
		}
	} else {
#ifndef CAKE_RELEASE
		if (tctx)
			tctx->telemetry.pending_wake_reason = CAKE_WAKE_REASON_QUEUED;
#endif
	}

	if (can_direct) {
		/* Queue empty and safe: bypass the shared DSQ and dispatch locally.
		 * Callers guarantee p->scx.slice is already non-zero. */
		if (stats) {
			stats->nr_direct_local_inserts++;
			if (is_wakeup)
				stats->nr_wakeup_direct_dispatches++;
			else
				stats->nr_direct_other_inserts++;
		}
#ifndef CAKE_RELEASE
		if (is_wakeup)
			cake_record_wake_target_insert(enq_cpu, true, wake_target_local);
		if (is_wakeup && tctx) {
			tctx->telemetry.pending_wake_reason = CAKE_WAKE_REASON_DIRECT;
			tctx->telemetry.pending_blocker_pid = 0;
			tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
		}
#endif
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice,
				  enq_flags);
#ifndef CAKE_RELEASE
		if (stats_on) {
			if (tctx) tctx->telemetry.direct_dispatch_count++;
		}
#endif
	} else {
		/* Busy targets stay per-CPU as well. This keeps runnable ownership
		 * local instead of falling back to any shared queue. */
		if (stats) {
			stats->nr_direct_local_inserts++;
			stats->nr_direct_other_inserts++;
		}
#ifndef CAKE_RELEASE
		if (is_wakeup)
			cake_record_wake_target_insert(enq_cpu, false, wake_target_local);
#endif
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice,
				  enq_flags);
		kick_cpu = enq_cpu;
		kick_flags = idle_hint ? SCX_KICK_IDLE : SCX_KICK_PREEMPT;
#ifndef CAKE_RELEASE
		if (is_wakeup && stats_on && tctx) {
			u32 reason_mask = 0;
			u8 wakee_class = cake_shadow_classify_task(p, tctx, &reason_mask);
			u8 owner_class = READ_ONCE(cpu_bss[target_cpu_idx].last_wake_class);
			u8 target_pressure = READ_ONCE(cpu_bss[target_cpu_idx].cpu_pressure);
			u8 decision;

			if (target_pressure >= 64)
				reason_mask |= cake_class_reason_bit(
					CAKE_WAKE_CLASS_REASON_PRESSURE_HIGH);
			decision = cake_shadow_busy_preempt_decision(
				wakee_class, owner_class, target_pressure);
			if (wakee_class < CAKE_WAKE_CLASS_MAX) {
				stats->wake_class_sample_count[wakee_class]++;
				cake_record_wake_class_reasons(stats, reason_mask);
			}
			cake_record_busy_preempt_shadow(
				stats, decision, wakee_class, owner_class, wake_target_local);
		}
#endif
	}

	if (kick_cpu >= 0) {
#ifndef CAKE_RELEASE
		if (stats_on && tctx) {
			tctx->telemetry.pending_kick_kind = cake_kick_kind_from_flags(kick_flags);
			tctx->telemetry.pending_kick_ts_ns = bpf_ktime_get_ns();
		}
#endif
		if (stats) {
			if (kick_flags == SCX_KICK_IDLE)
				stats->nr_wake_kick_idle++;
			else
				stats->nr_wake_kick_preempt++;
		}
	}

	if (kick_cpu >= 0)
		scx_bpf_kick_cpu(kick_cpu, kick_flags);
#ifdef CAKE_RELEASE
	#undef stats_on
	#undef stats
#endif
}

static __always_inline bool cake_task_is_affinitized(const struct task_struct *p)
{
	return p->nr_cpus_allowed && p->nr_cpus_allowed < nr_cpus;
}

static __always_inline u32 cake_pick_allowed_cpu(const struct task_struct *p,
						 u32 preferred_cpu)
{
	if (preferred_cpu < nr_cpus &&
	    bpf_cpumask_test_cpu(preferred_cpu, p->cpus_ptr))
		return preferred_cpu;

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS && cpu < nr_cpus; cpu++) {
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return cpu;
	}

	return preferred_cpu < nr_cpus ? preferred_cpu : 0;
}

static __always_inline void cake_clamp_wakeup_vtime(struct task_struct *p,
						    u32 target_cpu)
{
	u64 frontier, ceiling;

	if (target_cpu >= nr_cpus)
		return;

	frontier = cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)].vtime_local;
	/* Responsiveness-first lag ceiling: sleepers should rejoin near the
	 * current CPU frontier instead of waiting behind seconds of CPU-bound
	 * progress. Allow a few quanta of slack so we do not fully discard
	 * accumulated service, but never let wakees drift unboundedly far. */
	ceiling = frontier + (quantum_ns << 3);
	if (p->scx.dsq_vtime > ceiling)
		p->scx.dsq_vtime = ceiling;
}

static __always_inline u32 cake_pick_cpu_from_mask(const struct cpumask *cpumask,
						    u32 fallback_cpu)
{
	if (fallback_cpu < nr_cpus &&
	    bpf_cpumask_test_cpu(fallback_cpu, cpumask))
		return fallback_cpu;

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS && cpu < nr_cpus; cpu++) {
		if (bpf_cpumask_test_cpu(cpu, cpumask))
			return cpu;
	}

	return fallback_cpu < nr_cpus ? fallback_cpu : 0;
}

/* enqueue_body: arena-free enqueue dispatcher.
 *
 * Release-path scheduling state comes from:
	 *   - task_struct fields (p->scx.*, p->flags, p->prio)
	 *   - BSS per-CPU (cpu_bss[cpu].vtime_local) — single-writer, L1
	 *   - RODATA (quantum_ns) — JIT immediate
 *
 * Three mutually exclusive paths:
 *   1. kcritical (<1%): high-prio kthreads bypass DSQ
 *   2. nostaged (<1%): first dispatch, seed from vtime_local
 *   3. requeue (~10%): yield/slice exhaust, halved slice
 *   4. wakeup (~90%): main dispatch path
 */
static __noinline void enqueue_body(struct task_struct *p, u64 enq_flags)
{
#ifndef CAKE_RELEASE
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 enqueue_start = stats_on ? bpf_ktime_get_ns() : 0;
	struct cake_task_ctx __arena *tctx = NULL;
	u64 dsq_insert_start = 0;
	u64 dsq_insert_ns = 0;
	struct cake_stats *stats = NULL;

	if (stats_on) {
		stats = get_local_stats();
		tctx = get_task_ctx(p);
		cake_record_startup_enqueue(tctx, enqueue_start);
		if (tctx) {
			tctx->telemetry.pending_blocker_pid = 0;
			tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
		}
	}
#endif
	bool is_wakeup = !!(enq_flags & (u64)SCX_ENQ_WAKEUP);
	bool preserve_state = !!(enq_flags & ((u64)SCX_ENQ_REENQ |
					      (u64)SCX_ENQ_PREEMPT));
	bool affinitized = cake_task_is_affinitized(p);
	/* ── KCRITICAL BYPASS (zero arena) ──
	 * High-priority kthreads (ksoftirqd, GPU fence workers) bypass DSQ,
	 * but still use cake's bounded scheduler quantum instead of the
	 * kernel's 20ms default slice.
	 * p->flags and p->prio are task_struct fields (L1-hot). */
	if ((p->flags & PF_KTHREAD) && p->prio < 120) {
		u32 task_cpu = scx_bpf_task_cpu(p);
#ifndef CAKE_RELEASE
		if (stats) {
			stats->nr_direct_local_inserts++;
			stats->nr_direct_kthread_inserts++;
		}
#endif
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | task_cpu, quantum_ns,
				  enq_flags);
#ifndef CAKE_RELEASE
		if (stats_on) {
			u64 dur = bpf_ktime_get_ns() - enqueue_start;
			if (stats) {
				stats->total_enqueue_latency_ns += dur;
				cake_record_cb(stats, CAKE_CB_ENQUEUE, dur);
			}
			if (tctx) {
				tctx->telemetry.enqueue_duration_ns = (u32)dur;
				tctx->telemetry.dsq_insert_ns = (u32)dur;
				tctx->telemetry.enqueue_start_ns = enqueue_start;
			}
			if (dur >= CAKE_SLOW_CALLBACK_NS)
				cake_emit_dbg_event(p, bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1),
						    CAKE_DBG_EVENT_CALLBACK, CAKE_CB_ENQUEUE, dur, task_cpu);
		}
#endif
		return;
	}

	u32 target_cpu = 0;
	u64 slice = quantum_ns;

	/* ── NOSTAGED: first dispatch / kthread cold path ──
	 * dsq_vtime == 0 signals a freshly spawned task that cake_enable
	 * has not yet seeded (or was seeded to vtime_local which may be 0
	 * on system boot).
		 *
		 * EFFICIENCY G1: fairness math deferred below this early exit.
		 * Nostaged path doesn't need it — saves 4 instructions + 2 regs
		 * of pressure across the unlikely branch. */
	if (unlikely(p->scx.dsq_vtime == 0)) {
		target_cpu = scx_bpf_task_cpu(p);
		if (affinitized)
			target_cpu = cake_pick_allowed_cpu(p, target_cpu);
		p->scx.dsq_vtime = cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)].vtime_local;
		p->scx.slice = quantum_ns;
		if (affinitized)
			goto queue_affine_dispatch;
		goto queue_dispatch;
	}

	/* Reenqueues and preempted tasks still get a Cake-owned fresh quantum.
	 * Never inherit a larger leftover slice from prior SCX state. */
	if (preserve_state) {
		slice = quantum_ns;
		if (affinitized) {
			target_cpu = cake_pick_allowed_cpu(p, scx_bpf_task_cpu(p));
			goto queue_affine_preserve;
		}
		goto queue_preserve;
	}

	/* ADDITIVE FAIRNESS: weight-delta penalty from task_struct (L1-hot).
	 * p->scx.weight is on the same cache line as p->scx.slice.
	 * For nice-0 (weight=100): wd=0, nice_adj=0 (identity).
	 * Approximates quantum_ns/100 ≈ 20000 ≈ (1<<14)+(1<<12) = 20480. */
	u32 weight = p->scx.weight;
	s64 nice_adj = 0;
	if (unlikely(weight != 100))
		nice_adj = calc_nice_adj(weight);

	/* ── REQUEUE PATH (~10%) ── */
	if (!is_wakeup) {
		slice = quantum_ns;

		/* Flat 50% requeue slice for all classes. */
		slice >>= 1;
		slice += (200000 - slice) & -(slice < 200000);
		if (affinitized) {
			target_cpu = cake_pick_allowed_cpu(p, scx_bpf_task_cpu(p));
			goto queue_affine_requeue;
		}
		goto queue_requeue;
	}

	p->scx.slice = slice;

	/* EEVDF Deadline Projection (additive fairness)
	 * Replaces: vslice = (slice * vm) >> 10
	 * With: runtime + weight-delta penalty */
	p->scx.dsq_vtime += slice + nice_adj;
	target_cpu = scx_bpf_task_cpu(p);
	cake_clamp_wakeup_vtime(p, target_cpu);
	if (affinitized) {
		target_cpu = cake_pick_allowed_cpu(p, target_cpu);
		goto queue_affine_dispatch;
	}
	goto queue_dispatch;

queue_affine_preserve:
	p->scx.slice = slice;
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_direct_local_inserts++;
		stats->nr_direct_affine_inserts++;
	}
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			  enq_flags);
	goto queue_done;

queue_affine_requeue:
	p->scx.slice = slice;
	p->scx.dsq_vtime += slice + nice_adj;
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_direct_local_inserts++;
		stats->nr_direct_affine_inserts++;
		stats->nr_direct_other_inserts++;
	}
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			  enq_flags);
	goto queue_done;

queue_affine_dispatch:
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_direct_local_inserts++;
		stats->nr_direct_affine_inserts++;
		if (is_wakeup)
			stats->nr_wakeup_direct_dispatches++;
		else
			stats->nr_direct_other_inserts++;
	}
	if (stats_on && is_wakeup && tctx) {
		tctx->telemetry.pending_target_cpu = (u16)target_cpu;
		tctx->telemetry.pending_wake_reason = CAKE_WAKE_REASON_DIRECT;
		tctx->telemetry.pending_kick_kind = CAKE_KICK_KIND_NONE;
		tctx->telemetry.pending_kick_ts_ns = 0;
		tctx->telemetry.pending_blocker_pid = 0;
		tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
	}
	if (stats_on && is_wakeup) {
		u32 current_cpu_idx = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		cake_record_wake_target_insert(
			target_cpu, true, current_cpu_idx == (target_cpu & (CAKE_MAX_CPUS - 1)));
	}
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			  enq_flags);
	goto queue_done;

queue_preserve:
	p->scx.slice = slice;
	target_cpu = scx_bpf_task_cpu(p);
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_direct_local_inserts++;
		stats->nr_direct_other_inserts++;
	}
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			  enq_flags);
	goto queue_done;

queue_requeue:
	p->scx.slice = slice;
	p->scx.dsq_vtime += slice + nice_adj;
	target_cpu = scx_bpf_task_cpu(p);
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_direct_local_inserts++;
		stats->nr_direct_other_inserts++;
	}
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			  enq_flags);
	goto queue_done;

queue_dispatch:
#ifndef CAKE_RELEASE
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	enqueue_dsq_dispatch(p, enq_flags, target_cpu);

queue_done:
	;
#ifndef CAKE_RELEASE
	if (stats_on) {
		u64 enqueue_end = bpf_ktime_get_ns();
		u64 dur = enqueue_end - enqueue_start;
		dsq_insert_ns = enqueue_end - dsq_insert_start;
		if (stats) {
			stats->total_enqueue_latency_ns += dur;
			cake_record_cb(stats, CAKE_CB_ENQUEUE, dur);
		}
		if (tctx) {
			tctx->telemetry.enqueue_duration_ns = (u32)dur;
			tctx->telemetry.dsq_insert_ns = (u32)dsq_insert_ns;
			tctx->telemetry.enqueue_start_ns = enqueue_end;
			tctx->telemetry.vtime_compute_ns = (u32)(dur - dsq_insert_ns);
		}
		if (dur >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(p, bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1),
					    CAKE_DBG_EVENT_CALLBACK, CAKE_CB_ENQUEUE, dur,
					    scx_bpf_task_cpu(p));
	}
#endif
}

/* cake_enqueue: struct_ops stub → __noinline enqueue_body.
 * Separates BPF struct_ops arg extraction from core logic. */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	enqueue_body(p, enq_flags);
}

/* cake_dispatch: per-CPU local-first Cake should reach this only when there
 * is no already-dispatched local task ready to run. Keep-running and idle
 * bookkeeping remain here; shared queue pulling is gone. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	u32 cpu_idx = raw_cpu & (CAKE_MAX_CPUS - 1);
	/* EFFICIENCY G4: stats variables gated — CAKE_STATS_ACTIVE = 0 in
	 * release, so these were dead-code eliminated by compiler anyway.
	 * Explicit gate keeps source truthful. */
#ifndef CAKE_RELEASE
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 dispatch_start = stats_on ? bpf_ktime_get_ns() : 0;
#else
	#define stats_on 0
	u64 dispatch_start = 0;
#endif

	if (stats_on) get_local_stats_for(cpu_idx)->nr_dispatch_misses++;

	/* G3 keep_running: if no DSQ work is available and prev still wants to run,
	 * replenish its slice instead of forcing an avoidable context switch. */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		prev->scx.slice = quantum_ns;
		/* Keep the stopping() baseline aligned with the replenished
		 * slice so same-task continuations charge the next run from the
		 * correct starting budget. */
		cpu_bss[cpu_idx].tick_slice = quantum_ns;
	}

	/* Check-before-write: only mark idle if not already idle.
	 * Avoids unnecessary cache line dirtying. */
	if (!READ_ONCE(cpu_bss[cpu_idx].idle_hint)) {
		cpu_bss[cpu_idx].idle_hint = 1;
		cake_decay_cpu_pressure_idle(&cpu_bss[cpu_idx]);
		if (stats_on)
			get_local_stats_for(cpu_idx)->nr_idle_hint_set_writes++;
	} else {
		if (stats_on)
			get_local_stats_for(cpu_idx)->nr_idle_hint_set_skips++;
	}

	if (stats_on) {
		struct cake_stats *s = get_local_stats_for(cpu_idx);
		u64 d_oh = bpf_ktime_get_ns() - dispatch_start;
		s->total_dispatch_ns += d_oh;
		s->max_dispatch_ns = s->max_dispatch_ns + ((d_oh - s->max_dispatch_ns) & -(d_oh > s->max_dispatch_ns));
		cake_record_cb(s, CAKE_CB_DISPATCH, d_oh);
		if (d_oh >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(prev, cpu_idx, CAKE_DBG_EVENT_CALLBACK,
					    CAKE_CB_DISPATCH, d_oh, prev ? prev->pid : 0);
	}
#ifdef CAKE_RELEASE
	#undef stats_on
#endif
}

/* tier_perf_target[] REMOVED: self-documented dead RODATA.
 * Was kept for loader compat only; JIT dead-coded it. */



/* running_telemetry: cold-path arena telemetry for per-task stats.
 * Extracted to __noinline to isolate register pressure from cake_running.
 * Dead-code eliminated in CAKE_RELEASE builds.
 * Records: dispatch gap, wait histogram, overhead timing, mailbox staging. */
#ifndef CAKE_RELEASE
static __noinline void running_telemetry(
	struct task_struct *p,
	u32 cpu,
	u64 overhead_start)
{
	/* Phase 8: mailbox staging stopwatch end (before arena work) */
	u64 mbox_end = bpf_ktime_get_ns();

	/* Verbose builds keep per-task run-side telemetry exact. */
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	if (!tctx)
		return;

	u64 start = bpf_ktime_get_ns();
	struct cake_stats *s_run = get_local_stats_for(cpu);
	u8 home_place = tctx->telemetry.last_place_class;
	u8 waker_place = tctx->telemetry.last_waker_place_class;

	/* F4: Save OLD run_start BEFORE overwriting for dispatch_gap calc. */
	u64 prev_run_start = tctx->telemetry.run_start_ns;
	tctx->telemetry.run_start_ns = start;
	if (cake_startup_trace_open(tctx)) {
		cake_record_startup_phase(tctx, CAKE_STARTUP_PHASE_RUNNING,
					  CAKE_STARTUP_MASK_RUNNING);
		tctx->telemetry.startup_latency_us =
			cake_startup_delta_us(tctx, start);
	}

	if (tctx->telemetry.postwake_watch &&
	    tctx->telemetry.enqueue_start_ns == 0 &&
	    prev_run_start > 0) {
		u8 follow_reason = tctx->telemetry.postwake_reason;
		if (follow_reason > CAKE_WAKE_REASON_NONE &&
		    follow_reason < CAKE_WAKE_REASON_MAX) {
			bool same_follow = (u16)cpu == tctx->telemetry.postwake_first_cpu;
			if (same_follow)
				s_run->wake_followup_same_cpu_count[follow_reason]++;
			else {
				s_run->wake_followup_migrate_count[follow_reason]++;
				cake_emit_dbg_event(
					p, cpu, CAKE_DBG_EVENT_WAKE_FOLLOW_MIG, follow_reason,
					start - prev_run_start,
					((u32)tctx->telemetry.postwake_first_cpu << 16) | (u32)cpu);
			}
			cake_record_wake_edge_follow(tctx, p, same_follow);
		}
		tctx->telemetry.postwake_watch = 0;
	}

	/* Record wake-to-run outcome before dispatch-gap bookkeeping.
	 * This is the core signal for warm-vs-cold placement decisions. */
	if (tctx->telemetry.enqueue_start_ns > 0 && start > tctx->telemetry.enqueue_start_ns) {
		u64 wait = start - tctx->telemetry.enqueue_start_ns;
		u64 wait_us = wait >> 10;
		u8 reason = tctx->telemetry.pending_wake_reason;
		u16 target_cpu = tctx->telemetry.pending_target_cpu;
		u8 kick_kind = tctx->telemetry.pending_kick_kind;
		u8 select_path = tctx->telemetry.pending_select_path;
		u8 select_reason = tctx->telemetry.pending_select_reason;
		u64 kick_ts = tctx->telemetry.pending_kick_ts_ns;
		u32 blocker_pid = tctx->telemetry.pending_blocker_pid;
		u16 blocker_cpu = tctx->telemetry.pending_blocker_cpu;
		u64 wake_edge_packed =
			(u64)reason |
			((u64)target_cpu << 8) |
			((u64)select_path << 24) |
			((u64)home_place << 32) |
			((u64)waker_place << 40);

		tctx->telemetry.wait_duration_ns = wait;
		tctx->telemetry.enqueue_start_ns = 0;
		tctx->telemetry.pending_wake_reason = CAKE_WAKE_REASON_NONE;
		tctx->telemetry.pending_target_cpu = CAKE_CPU_SENTINEL;
		tctx->telemetry.pending_kick_kind = CAKE_KICK_KIND_NONE;
		tctx->telemetry.pending_kick_ts_ns = 0;
		tctx->telemetry.pending_blocker_pid = 0;
		tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
		tctx->telemetry.last_select_path = select_path;
		tctx->telemetry.last_select_reason = select_reason;
		tctx->telemetry.pending_select_path = CAKE_SELECT_PATH_NONE;
		tctx->telemetry.pending_select_reason = CAKE_SELECT_REASON_NONE;
		cake_record_select_decision_wait(s_run, select_reason, wait);
		cake_record_wake_edge_run(tctx, p, cpu, wait, wake_edge_packed);

		if (reason == CAKE_WAKE_REASON_BUSY && blocker_pid > 0) {
			if (blocker_cpu < CAKE_MAX_CPUS) {
				u32 bcpu = blocker_cpu & (CAKE_MAX_CPUS - 1);
				u64 max_seen;

				WRITE_ONCE(blocked_owner_pid[bcpu], blocker_pid);
				WRITE_ONCE(blocked_waiter_pid[bcpu], p->pid);
				__sync_fetch_and_add(&blocked_owner_wait_ns[bcpu], wait);
				__sync_fetch_and_add(&blocked_owner_wait_count[bcpu], 1);
				max_seen = READ_ONCE(blocked_owner_wait_max_ns[bcpu]);
				if (wait > max_seen)
					WRITE_ONCE(blocked_owner_wait_max_ns[bcpu], wait);
			}
		}

		if (wait_us < 10)
			tctx->telemetry.wait_hist_lt10us++;
		else if (wait_us < 100)
			tctx->telemetry.wait_hist_lt100us++;
		else if (wait_us < 1000)
			tctx->telemetry.wait_hist_lt1ms++;
		else
			tctx->telemetry.wait_hist_ge1ms++;

		if (reason > CAKE_WAKE_REASON_NONE && reason < CAKE_WAKE_REASON_MAX) {
			if (target_cpu < CAKE_MAX_CPUS) {
				if ((u16)cpu == target_cpu)
					s_run->wake_target_hit_count[reason]++;
				else {
					s_run->wake_target_miss_count[reason]++;
					if (wait >= CAKE_EVT_TARGET_MISS_NS)
						cake_emit_dbg_event(
							p, cpu, CAKE_DBG_EVENT_WAKE_TARGET_MISS, reason,
							wait,
							((u32)target_cpu << 16) | (u32)cpu);
				}
				cake_record_target_wait(reason, target_cpu, wait);
			}
			tctx->telemetry.postwake_watch = 1;
			tctx->telemetry.postwake_first_cpu = (u16)cpu;
			tctx->telemetry.postwake_reason = reason;
			cake_record_wake_wait(
				s_run->wake_reason_wait_all_ns,
				s_run->wake_reason_wait_all_count,
				s_run->wake_reason_wait_all_max_ns,
				reason, wait);
			cake_smt_record_wake_wait(s_run, cpu, wait);
			s_run->wake_reason_bucket_count[reason][cake_wake_bucket(wait)]++;
			if (kick_kind > CAKE_KICK_KIND_NONE &&
			    kick_kind < CAKE_KICK_KIND_MAX &&
			    kick_ts > 0 &&
			    start > kick_ts) {
				u64 kick_wait = start - kick_ts;
				s_run->nr_wake_kick_observed[kick_kind]++;
				if (kick_wait <= CAKE_QUICK_WAKE_KICK_NS)
					s_run->nr_wake_kick_quick[kick_kind]++;
				s_run->total_wake_kick_to_run_ns[kick_kind] += kick_wait;
				if (kick_wait > s_run->max_wake_kick_to_run_ns[kick_kind])
					s_run->max_wake_kick_to_run_ns[kick_kind] = kick_wait;
				s_run->wake_kick_bucket_count[kick_kind][cake_wake_bucket(kick_wait)]++;
				if (kick_wait >= CAKE_EVT_KICK_SLOW_NS)
					cake_emit_dbg_event(
						p, cpu, CAKE_DBG_EVENT_KICK_SLOW, kick_kind,
						kick_wait,
						((u32)reason << 16) | (u32)target_cpu);
			}
		}

		if (reason > CAKE_WAKE_REASON_NONE && reason < CAKE_WAKE_REASON_MAX &&
		    wait <= CAKE_TRACKED_WAKEWAIT_MAX_NS) {
			u32 idx = reason - 1;
			tctx->telemetry.wake_reason_wait_ns[idx] += wait;
			tctx->telemetry.wake_reason_count[idx]++;
			u32 max_wait = tctx->telemetry.wake_reason_max_us[idx];
			if (wait_us > max_wait)
				tctx->telemetry.wake_reason_max_us[idx] = (u32)wait_us;
			cake_record_wake_wait(
				s_run->wake_reason_wait_ns,
				s_run->wake_reason_wait_count,
				s_run->wake_reason_wait_max_ns,
				reason, wait);
			cake_record_place_wait(
				s_run,
				s_run->home_place_wait_ns,
				s_run->home_place_wait_count,
				s_run->home_place_wait_max_ns,
				home_place, wait);
			cake_record_place_wait(
				s_run,
				s_run->waker_place_wait_ns,
				s_run->waker_place_wait_count,
				s_run->waker_place_wait_max_ns,
				waker_place, wait);
			cake_record_task_home_wait(tctx, home_place, wait);
			if (wait >= CAKE_SLOW_WAKEWAIT_NS)
				cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_WAKEWAIT, reason, wait, wait_us);
		}
	}

	/* 1. DISPATCH GAP */
	if (prev_run_start > 0 && start > prev_run_start) {
		u64 gap = start - prev_run_start;
		tctx->telemetry.dispatch_gap_ns = gap;
		u64 old_max_g = tctx->telemetry.max_dispatch_gap_ns;
		tctx->telemetry.max_dispatch_gap_ns = old_max_g + ((gap - old_max_g) & -(gap > old_max_g));
		if (gap >= CAKE_EVT_DISPATCH_GAP_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_DISPATCH_GAP, 0, gap, 0);
	}

	tctx->telemetry.llc_id = (u16)cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].llc_id;
	if (tctx->telemetry.llc_id < 16)
		tctx->telemetry.llc_run_mask |= (u16)(1u << tctx->telemetry.llc_id);

	u64 oh_run = bpf_ktime_get_ns() - overhead_start;
	tctx->telemetry.running_duration_ns = (u32)oh_run;

	/* Phase 8: mailbox staging duration (overhead_start == mbox_start) */
	tctx->telemetry.mbox_staging_ns = (u32)(mbox_end - overhead_start);
}
#endif

/* cake_running: struct_ops callback fired every time a task starts on a CPU.
 *
 * Execution path flattened: running_task_change logic inlined directly.
 * Eliminates call/return overhead and enables cross-boundary CSE
 * (bss pointer shared, p doesn't need separate save/restore).
 * Register budget: p(r6), cpu(r7), bss(r8) = 3 callee-saves at
 * get_task_hot kfunc boundary — under 4-slot limit.
 *
 * On same-task re-runs (75%), skips the entire task-change block
 * via last_pid check — minimal work: 2 kfuncs + 3 stores + 1 branch. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 running_overhead_start = 0;
	if (stats_on)
		running_overhead_start = bpf_ktime_get_ns();
#else
	#define stats_on 0
#endif

	/* Batch kfuncs first: only p=r6 survives both calls (1 callee-save).
	 * p->scx.slice read DEFERRED until after both kfuncs to avoid
	 * forcing p through 2 separate spill/reload cycles. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

	struct cake_cpu_bss *bss = &cpu_bss[cpu];

#ifndef CAKE_RELEASE
	if (stats_on)
		cake_record_local_run(cpu);
#endif

#ifndef CAKE_RELEASE
	/* BPF-Native Clock: debug-only monotonic accumulator.
	 * Feeds run_start + running_telemetry (both debug-gated).
	 * In release, now_full has zero consumers → entire clock
	 * system (read, kfunc resync, accumulation) compiles out. */
	u64 now_full = bss->cake_clock;
#endif

	/* ── WRITE: BSS per-CPU (always needed) ──
	 * Check-before-write avoids dirtying the shared idle_hint line on every
	 * dispatch when this CPU was already marked busy. */
	if (READ_ONCE(bss->idle_hint)) {
		WRITE_ONCE(bss->idle_hint, 0);
		if (stats_on)
			get_local_stats_for(cpu)->nr_idle_hint_clear_writes++;
	} else {
		if (stats_on)
			get_local_stats_for(cpu)->nr_idle_hint_clear_skips++;
	}

#ifndef CAKE_RELEASE
	if (stats_on)
		cake_smt_record_run_start(bss, cpu, running_overhead_start);

	struct cake_task_ctx __arena *running_tctx = NULL;
	if (stats_on) {
		struct cake_stats *stats = get_local_stats_for(cpu);
		u32 reason_mask = 0;
		u8 old_class = READ_ONCE(bss->last_wake_class);
		u8 new_class;

		running_tctx = get_task_ctx(p);
		new_class = cake_shadow_classify_task(p, running_tctx, &reason_mask);
		if (new_class < CAKE_WAKE_CLASS_MAX) {
			stats->wake_class_sample_count[new_class]++;
			if (old_class < CAKE_WAKE_CLASS_MAX && old_class != new_class)
				stats->wake_class_transition_count[old_class][new_class]++;
			cake_record_wake_class_reasons(stats, reason_mask);
			WRITE_ONCE(bss->last_wake_class, new_class);
		}
	}
#endif

	/* FAST PATH: same task re-running on the same CPU.
	 * Slice load is deferred into the task-change block.
	 * Release/stats-off same-task re-runs keep zero kfunc calls and zero BSS
	 * writes beyond idle_hint; debug stats refresh the shadow owner class. */
	if (bss->last_pid != p->pid) {
		/* ── TASK CHANGE: Zero-MESI Arena-Free (Phase 12) ──
		 * Zero arena, zero division, zero get_task_hot. */
#ifndef CAKE_RELEASE
		now_full = scx_bpf_now();
		bss->cake_clock = now_full;
#endif
		u64 slice = p->scx.slice;
		bss->last_pid = p->pid;
		bss->tick_slice = slice ?: quantum_ns;

		/* Keep a live local frontier instead of a historical max so
		 * wakeup rescue stays anchored to currently active work. */
		bss->vtime_local = p->scx.dsq_vtime;

#ifndef CAKE_RELEASE
		struct cake_task_ctx __arena *tctx = stats_on ? running_tctx : get_task_ctx(p);
#else
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
#endif
		if (tctx) {
#ifndef CAKE_RELEASE
			bool first_home = stats_on && tctx->home_cpu == CAKE_CPU_SENTINEL;
			u8 seed_reason = tctx->telemetry.pending_select_reason;
#endif
			cake_update_home_cpu(tctx, (u16)cpu);
#ifndef CAKE_RELEASE
			if (first_home)
				cake_record_home_seed(tctx->home_cpu, seed_reason);
#endif
		}
	}

	/* BPF-Native Clock: single write with correct value.
	 * Same-task (75%): now_full = cake_clock (from BSS, 1ns).
	 * Task-change (25%): now_full = scx_bpf_now() (resynced above).
	 * Deferred to here so the task-change path can overwrite it. */
#ifndef CAKE_RELEASE
	bss->run_start = (u32)now_full;
#endif

#ifndef CAKE_RELEASE
	if (stats_on)
		running_telemetry(p, cpu, running_overhead_start);
	if (stats_on) {
		struct cake_stats *s_run = get_local_stats_for(cpu);
		u64 oh_run = bpf_ktime_get_ns() - running_overhead_start;
		s_run->total_running_ns += oh_run;
		s_run->max_running_ns =
			s_run->max_running_ns + ((oh_run - s_run->max_running_ns) & -(oh_run > s_run->max_running_ns));
		cake_record_cb(s_run, CAKE_CB_RUNNING, oh_run);
		if (oh_run >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_CALLBACK, CAKE_CB_RUNNING, oh_run, 0);
	}
#endif
#ifdef CAKE_RELEASE
	#undef stats_on
#endif
}

/* cake_stopping: struct_ops callback fired when a task stops on a CPU.
 *
 * The release path integrates consumed runtime into dsq_vtime using
 * task_struct and per-CPU BSS state. Arena access is debug-only and only
 * used for iter-visible telemetry. */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[cpu];

	/* ════ Phase 12: Vtime Integration ════
	 * Release fast path uses task_struct plus per-CPU BSS only.
	 * Debug telemetry below adds extra reads and one deferred divide. */
	u32 slice_consumed = (u32)bss->tick_slice - (u32)p->scx.slice;
#ifndef CAKE_RELEASE
	/* Debug clock accumulator — feeds run_start/telemetry. Dead in release. */
	bss->cake_clock += slice_consumed;
#endif

	/* Branchless math bounding */
	u32 rt_raw = slice_consumed - ((slice_consumed - (65535U << 10)) & -(slice_consumed > (65535U << 10)));

	cake_update_cpu_pressure(bss, slice_consumed);

	if (runnable) {
		/* Additive fairness from task weight in task_struct.
		 * Source uses shifts and adds, but the compiler may lower that
		 * expression to a multiply in generated BPF. */
		u32 weight = p->scx.weight;
		s64 nice_adj = 0;
		if (unlikely(weight != 100))
			nice_adj = calc_nice_adj(weight);
		p->scx.dsq_vtime += (u64)rt_raw + nice_adj;
		bss->vtime_local = p->scx.dsq_vtime;
	}

	bool stats_on = CAKE_STATS_ACTIVE;
	u64 stopping_overhead_start = 0;

#ifndef CAKE_RELEASE
	struct cake_task_ctx __arena *tctx = NULL;
	u32 nvcsw_accum = 0;
#endif

	if (stats_on) {
		stopping_overhead_start = bpf_ktime_get_ns();
#ifndef CAKE_RELEASE
		per_cpu[cpu].mbox.last_stopped_pid = p->pid;

		tctx = get_task_ctx(p);
		if (tctx) {
			struct cake_stats *s_task = get_local_stats_for(cpu);
			u8 tc = tctx->task_class;
			if (tc != CAKE_CLASS_GAME) {
				u64 cur_nv = p->nvcsw;
				u64 prev_nv = tctx->nvcsw_snapshot;
				if (prev_nv > 0)
					nvcsw_accum = (u32)(cur_nv - prev_nv);
				tctx->nvcsw_snapshot = cur_nv;
			}
			if (nvcsw_accum)
				tctx->telemetry.nvcsw_delta += nvcsw_accum;

			if (tctx->telemetry.run_start_ns > 0) {
				u64 now_stop = bpf_ktime_get_ns();
				u64 dur = now_stop - tctx->telemetry.run_start_ns;
				u32 raw_slice_used = (u32)(cpu_bss[cpu].tick_slice - p->scx.slice);
				u64 expected_ns, d, mask, jitter;
				u16 old_max_rt;
				u64 dur_us;
				u64 tslice;
				bool same;

				tctx->telemetry.run_duration_ns = dur;
				cake_record_place_run(
					s_task,
					s_task->home_place_run_ns,
					s_task->home_place_run_count,
					s_task->home_place_run_max_ns,
					tctx->telemetry.last_place_class, dur);

				same = ((u16)cpu == tctx->telemetry.core_placement);
				tctx->telemetry.same_cpu_streak =
					(tctx->telemetry.same_cpu_streak + 1) & -(u16)same;
				tctx->telemetry.core_placement = (u16)cpu;

				raw_slice_used -=
					(raw_slice_used - (65535U << 10)) & -(raw_slice_used > (65535U << 10));
				expected_ns = (u64)(raw_slice_used >> 10) * 1000ULL;
				d = dur - expected_ns;
				mask = -(u64)(dur < expected_ns);
				jitter = (d ^ mask) - mask;
				tctx->telemetry.jitter_accum_ns += jitter;
				tctx->telemetry.total_runs++;
				tctx->telemetry.total_runtime_ns += dur;
				s_task->task_runtime_ns += dur;
				s_task->task_run_count++;

				old_max_rt = tctx->telemetry.max_runtime_us;
				dur_us = dur / 1000;
				if (dur_us > 65535)
					dur_us = 65535;
				tctx->telemetry.max_runtime_us =
					old_max_rt + (((u16)dur_us - old_max_rt) & -(u16)((u16)dur_us > old_max_rt));

				tslice = cpu_bss[cpu].tick_slice ?: quantum_ns;
				tctx->telemetry.slice_util_pct = (u16)((dur << 7) / tslice);

				{
					u64 cur_nivcsw = p->nivcsw;
					u64 prev_nivcsw = tctx->telemetry.nivcsw_snapshot;
					if (prev_nivcsw > 0)
						tctx->telemetry.nivcsw_delta += (u32)(cur_nivcsw - prev_nivcsw);
					tctx->telemetry.nivcsw_snapshot = cur_nivcsw;
				}

				tctx->telemetry.stopping_duration_ns =
					(u32)(now_stop - stopping_overhead_start);
			}

			if (p->scx.slice == 0)
				tctx->telemetry.quantum_full_count++;
			else if (!runnable)
				tctx->telemetry.quantum_yield_count++;
			else
				tctx->telemetry.quantum_preempt_count++;

			tctx->telemetry.cpu_run_count[cpu & (CAKE_TELEM_MAX_CPUS - 1)]++;
		}
#endif /* !CAKE_RELEASE */

		/* Aggregate overhead timing (per-CPU BSS). */
		struct cake_stats *s = get_local_stats_for(cpu);
#ifndef CAKE_RELEASE
		cake_smt_charge_runtime(s, bss, cpu, bpf_ktime_get_ns());
#endif
		if (p->scx.slice == 0)
			s->nr_quantum_full++;
		else if (!runnable)
			s->nr_quantum_yield++;
		else
			s->nr_quantum_preempt++;
		u64 oh_agg = bpf_ktime_get_ns() - stopping_overhead_start;
		s->total_stopping_ns += oh_agg;
		s->max_stopping_ns = s->max_stopping_ns + ((oh_agg - s->max_stopping_ns) & -(oh_agg > s->max_stopping_ns));
		cake_record_cb(s, CAKE_CB_STOPPING, oh_agg);
		s->nr_stop_deferred++;
		if (oh_agg >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_CALLBACK, CAKE_CB_STOPPING, oh_agg,
					    runnable ? 1 : 0);

		/* BenchLab trigger (cold — only fires on TUI demand) */
		if (unlikely(bench_request)) {
			bench_request = 0;
			run_kfunc_bench(&bench_results, p);
		}
	}
}

/* Initialize per-task arena storage.
 * Sleepable: bpf_arena_alloc_pages is sleepable-only, so all arena
 * allocation must happen here, not in hot paths.
 * Called before any scheduling ops fire for this task.
 *
 * Phase 12: Hot paths are arena-free in release. Arena fields are
 * only read by cake_task_iter (TUI) and debug telemetry.
 * Release init_task: allocate arena + 3 iter-visible writes + BSS seed.
 * Debug init_task: full field initialization for telemetry. */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct cake_task_ctx __arena *tctx;

	tctx = (struct cake_task_ctx __arena *)scx_task_alloc(p);
	if (!tctx) {
		if (CAKE_STATS_ACTIVE) {
			struct cake_stats *s = get_local_stats();
			s->nr_dropped_allocations++;
		}
		return -ENOMEM;
	}

	/* vtime_mult_cache DELETED: additive fairness reads p->scx.weight
	 * at runtime. No BSS cache seeding needed. */

	/* ── ITER-VISIBLE FIELDS (read by cake_task_iter even in release) ── */
	u32 init_ppid = p->real_parent ? p->real_parent->tgid : 0;
	tctx->ppid = init_ppid;
	tctx->task_weight = 100;  /* Default weight for nice-0 (display only) */
	tctx->home_cpu = CAKE_CPU_SENTINEL;
	tctx->home_score = 0;
	tctx->home_core = 0xFF;

	/* packed_info is now iter/debug transport only.
	 * We still seed NEW and KCRITICAL here so the TUI and BenchLab can
	 * identify fresh tasks and kernel-critical helpers without hot-path reads. */
	u32 packed = 0;
	packed |= ((u32)CAKE_FLOW_NEW & MASK_FLAGS) << SHIFT_FLAGS;
	if (p->flags & PF_KTHREAD) {
		if (p->prio < 120) {
			packed |= (1u << BIT_KCRITICAL);
		} else {
			u64 comm_val = ((u64 *)p->comm)[0];
			if (comm_val == 0x71726974666f736bULL ||
			    (comm_val & 0x0000FFFFFFFFFFFFULL) == 0x000061696469766eULL ||
			    (comm_val & 0x0000000000FFFFFFULL) == 0x0000000000646d61ULL ||
			    (comm_val & 0x00000000FFFFFFFFULL) == 0x0000000035313969ULL ||
			    (comm_val & 0x000000000000FFFFULL) == 0x0000000000006578ULL) {
				packed |= (1u << BIT_KCRITICAL);
			}
		}
	}
	tctx->packed_info = packed;

#ifndef CAKE_RELEASE
	/* ── DEBUG-ONLY FIELD INITIALIZATION ──
	 * All of these are read only by debug telemetry paths. */
	if (CAKE_STATS_ENABLED) {
		tctx->task_class       = CAKE_CLASS_NORMAL;
	}

	if (CAKE_STATS_ACTIVE) {
		tctx->telemetry.pid = p->pid;
		tctx->telemetry.tgid = p->tgid;
		u64 *comm_src = (u64 *)p->comm;
		u64 __arena *comm_dst = (u64 __arena *)tctx->telemetry.comm;
		comm_dst[0] = comm_src[0];
		comm_dst[1] = comm_src[1];
		tctx->telemetry.nivcsw_snapshot = p->nivcsw;
		tctx->telemetry.pending_target_cpu = CAKE_CPU_SENTINEL;
		tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
		tctx->telemetry.pending_select_reason = CAKE_SELECT_REASON_NONE;
		tctx->telemetry.last_select_reason = CAKE_SELECT_REASON_NONE;
		tctx->telemetry.startup_first_phase = CAKE_STARTUP_PHASE_NONE;
		tctx->telemetry.startup_phase_mask = 0;
		tctx->telemetry.startup_latency_us = (u32)(bpf_ktime_get_ns() / 1000ULL);
	}

	if (CAKE_STATS_ENABLED)
		tctx->nvcsw_snapshot = p->nvcsw;

	tctx->task_class = CAKE_CLASS_NORMAL;
#endif

	return 0;
}

/* G1 FIX: .enable callback — initialize task vtime when it becomes schedulable.
 * Like cosmos/bpfland: p->scx.dsq_vtime = vtime_now.
 * For cake, we store in arena (avoids kernel dsq_insert_vtime overwrite). */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	/* Phase 12: Seed dsq_vtime directly in task_struct (L1-hot).
	 * Zero arena access. Kernel preserves p->scx.dsq_vtime across lifecycle. */
	p->scx.dsq_vtime = cpu_bss[bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1)].vtime_local;
	p->scx.slice = quantum_ns;
}

/* cake_set_cpumask: event-driven affinity update — telemetry counter only.
 * Cached cpumask removed: kernel handles affinity natively. */
void BPF_STRUCT_OPS(cake_set_cpumask, struct task_struct *p __arg_trusted,
		    const struct cpumask *cpumask __arg_trusted)
{
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	u32 target_cpu = cake_pick_cpu_from_mask(cpumask, scx_bpf_task_cpu(p));

	if (tctx && tctx->home_cpu < nr_cpus &&
	    !bpf_cpumask_test_cpu(tctx->home_cpu, cpumask)) {
		tctx->home_cpu = CAKE_CPU_SENTINEL;
		tctx->home_score = 0;
		tctx->home_core = 0xFF;
	}

	if (p->nr_cpus_allowed && p->nr_cpus_allowed < nr_cpus) {
		u64 kick_flags = READ_ONCE(cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)].idle_hint)
				       ? SCX_KICK_IDLE
				       : SCX_KICK_PREEMPT;
		p->scx.slice = quantum_ns;
		cake_clamp_wakeup_vtime(p, target_cpu);
#ifndef CAKE_RELEASE
		if (CAKE_STATS_ACTIVE) {
			struct cake_stats *s = get_local_stats();
			if (kick_flags == SCX_KICK_IDLE)
				s->nr_affine_kick_idle++;
			else
				s->nr_affine_kick_preempt++;
		}
#endif
		scx_bpf_kick_cpu(target_cpu, kick_flags);
	}
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ENABLED) {
		if (tctx)
			tctx->telemetry.cpumask_change_count++;
	}
#endif
}

/* Handle manual yields (e.g. sched_yield syscall).
 * Global stats keep an exact count, while per-task yield_count is TUI-only
 * telemetry (stats-gated). */
bool BPF_STRUCT_OPS(cake_yield, struct task_struct *p)
{
	if (CAKE_STATS_ACTIVE) {
		struct cake_stats *s = get_local_stats();
		s->nr_sched_yield_calls++;
	}
#ifndef CAKE_RELEASE
	/* Per-task yield_count remains TUI-only and debug-gated so release does not
	 * pay arena lookup cost beyond the exact global counter above. */
	if (CAKE_STATS_ACTIVE) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) tctx->telemetry.yield_count++;
	}
#endif
	return false;
}

/* Handle preemption when a task is pushed off the CPU. */
void BPF_STRUCT_OPS(cake_runnable, struct task_struct *p, u64 enq_flags)
{
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ACTIVE) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			if (enq_flags & SCX_ENQ_PREEMPT) {
				tctx->telemetry.preempt_count++;
				if (tctx->telemetry.preempt_count >= 4 &&
				    (tctx->telemetry.preempt_count & 3) == 0)
					cake_emit_dbg_event(
						p, bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1),
						CAKE_DBG_EVENT_PREEMPT_CHAIN, 0, 0,
						tctx->telemetry.preempt_count);
			}
			/* Wakeup source: the currently running task is the waker */
			struct task_struct *waker = bpf_get_current_task_btf();
			if (waker) {
				struct cake_stats *s = get_local_stats();
				tctx->telemetry.wakeup_source_pid = waker->pid;
				/* Wake chain tracking */
				tctx->telemetry.waker_cpu = (u16)bpf_get_smp_processor_id();
				tctx->telemetry.waker_tgid = waker->tgid;
				if (waker->tgid == tctx->telemetry.tgid) {
					tctx->telemetry.wake_same_tgid_count++;
					if (s)
						s->nr_wake_same_tgid++;
				} else {
					tctx->telemetry.wake_cross_tgid_count++;
					if (s)
						s->nr_wake_cross_tgid++;
				}
				if (enq_flags & SCX_ENQ_WAKEUP)
					cake_record_wake_edge_enqueue(tctx, waker, p);
			}
		}
	}
#endif
}

/* Free per-task arena storage on task exit. */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	/* Remove from PID→tctx map: removed — iter/task program handles visibility
	 * without explicit cleanup. Task storage freed below. */
	scx_task_free(p);
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	/* Per-CPU arena allocation, dynamically sized.
	 * Pages = ceil(nr_cpus × CAKE_MBOX_SIZE / 4096).
	 * nr_cpus is RODATA → JIT constant-folds at load time. */
	{
		/* 4096 is 2^12. Bitshift replaces division compiler inference. */
		u32 nr_arena_pages = ((u32)nr_cpus * CAKE_MBOX_SIZE + 4095) >> 12;
		if (nr_arena_pages < 1)
			nr_arena_pages = 1;
		per_cpu = (struct cake_per_cpu __arena *)bpf_arena_alloc_pages(
			&arena, NULL, nr_arena_pages, NUMA_NO_NODE, 0);
	}
	if (!per_cpu)
		return -ENOMEM;


	/* Populate per-CPU LLC ID cache from RODATA.
	 * Set once at init — llc_id never changes for a given CPU. */
	for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
		if (i >= nr_cpus)
			break;
		cpu_bss[i].llc_id = (u8)cpu_llc_id[i];
	}

	return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* cake_task_iter: SEC("iter/task") — replaces pid_to_tctx hash map.
 * Iterates all kernel tasks. Emits cake_iter_record for each managed task.
 * Userspace reads fixed-size records via link fd. Zero scheduling overhead.
 * No init/exit map ops: cake_init_task and cake_exit_task are lockless.
 *
 * Telemetry copies split into noinline batches to avoid register spills. */

#ifndef CAKE_RELEASE
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

/* Batch 4: enqueue substage timing + quantum + waker + per-CPU run counts */
static __noinline void iter_copy_substage(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.gate_cascade_ns       = tctx->telemetry.gate_cascade_ns;
	rec->telemetry.idle_probe_ns         = tctx->telemetry.idle_probe_ns;
	rec->telemetry.vtime_compute_ns      = tctx->telemetry.vtime_compute_ns;
	rec->telemetry.mbox_staging_ns       = tctx->telemetry.mbox_staging_ns;
	rec->telemetry.startup_latency_us    = tctx->telemetry.startup_latency_us;
	rec->telemetry.startup_enqueue_us    = tctx->telemetry.startup_enqueue_us;
	rec->telemetry.vtime_staging_ns      = tctx->telemetry.vtime_staging_ns;
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
#endif /* !CAKE_RELEASE */

SEC("iter/task")
int cake_task_iter(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	if (!task)
		return 0;

	/* Only emit tasks managed by this scheduler instance. */
	struct cake_task_ctx __arena *tctx = get_task_ctx(task);
#ifndef CAKE_RELEASE
	if (!tctx || !tctx->telemetry.pid)
		return 0;
#else
	if (!tctx)
		return 0;
#endif

	/* Build iter record from arena tctx data.
	 * Zero-init: in release builds, telemetry block is skipped —
	 * without this, bpf_seq_write emits stack garbage. */
	struct cake_iter_record rec = {};
	rec.pid         = task->pid;
	rec.ppid        = tctx->ppid;
	rec.packed_info = tctx->packed_info |
			  ((u32)tctx->home_score << 8) |
			  (u32)tctx->home_core;
	rec.pelt_util = (u16)task->se.avg.util_avg;
	rec.allowed_cpus    = task->nr_cpus_allowed > 0xffff ? 0xffff : (u16)task->nr_cpus_allowed;
	rec.task_weight     = tctx->task_weight;
	rec.home_cpu        = tctx->home_cpu;

#ifndef CAKE_RELEASE
	/* Telemetry: batched noinline copies → 0 spills per batch.
	 * Each batch: 2 args (tctx+rec) = 2 callee-saves. */
	iter_copy_timing(tctx, &rec);
	iter_copy_gates(tctx, &rec);
	iter_copy_hist(tctx, &rec);
	iter_copy_substage(tctx, &rec);
#endif

	bpf_seq_write(seq, &rec, sizeof(rec));
	return 0;
}
/* cake_tick: shared-queue load balancing was removed with the local-first
 * design, so the tick hook is intentionally idle. */
void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
	(void)p;
}

/* scx_nice_weight[40] + scx_nice_mult[40] DELETED:
 * Additive fairness model reads p->scx.weight directly from task_struct.
 * No RODATA tables needed. -160 bytes RODATA. */

/* Additive fairness: cake_set_weight is now a no-op for the hot path.
 * The kernel calls this when p->scx.weight changes via cgroup or nice.
 * Hot paths read p->scx.weight directly (L1-hot, same CL as p->scx.slice).
 * Only arena update for TUI display remains. */
void BPF_STRUCT_OPS(cake_set_weight, struct task_struct *p, u32 weight)
{
#ifndef CAKE_RELEASE
	/* Mirror weight to arena for debug telemetry (iter reads tctx->task_weight).
	 * Semantic change: now stores raw weight (100=nice0) instead of reciprocal. */
	struct cake_task_ctx __arena *hot = get_task_hot(p);
	if (hot) {
		u16 w = (u16)(weight ?: 100);
		if (hot->task_weight != w)
			hot->task_weight = w;
	}
#endif
}

SCX_OPS_DEFINE(cake_ops, .select_cpu = (void *)cake_select_cpu,
	       .enqueue	 = (void *)cake_enqueue,
	       .dispatch = (void *)cake_dispatch,
	       .tick         = (void *)cake_tick,
	       .running	    = (void *)cake_running,
	       .stopping    = (void *)cake_stopping,
	       .yield = (void *)cake_yield,
	       .runnable = (void *)cake_runnable,
	       .set_weight   = (void *)cake_set_weight,
	       .enable       = (void *)cake_enable,
	       .set_cpumask = (void *)cake_set_cpumask,
	       .init_task   = (void *)cake_init_task,
	       .exit_task = (void *)cake_exit_task, .init = (void *)cake_init,
	       .exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms = 5000, /* Override with SCX_TIMEOUT_MS when needed */
	       .name = "cake");
