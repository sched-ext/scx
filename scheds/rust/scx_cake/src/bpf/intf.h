/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake — clean-slate rewrite.
 *
 * Shared interface between the BPF scheduler and the Rust loader. Kept
 * intentionally tiny: no stats, DRR, futex, or telemetry structs. See
 * DESIGN.md for the full rationale.
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif /* __VMLINUX_H__ */

/*
 * Compile-time research surface. Release builds use these defaults; mutation
 * campaigns may override one definition with BPF_EXTRA_CFLAGS_POST_INCL.
 * Keeping the values compile-time preserves immediate folding and avoids a
 * runtime policy map or hot-path loads.
 */
#ifndef CAKE_SLICE_US
#define CAKE_SLICE_US 3000
#endif
#ifndef CAKE_SLEEPER_LAG_DIV
#define CAKE_SLEEPER_LAG_DIV 2
#endif
#ifndef CAKE_GLOBAL_PREEMPT_PROTECT_DIV
#define CAKE_GLOBAL_PREEMPT_PROTECT_DIV 8
#endif
#ifndef CAKE_HOME_PREEMPT_YOUNG_DIV
#define CAKE_HOME_PREEMPT_YOUNG_DIV 32
#endif
#ifndef CAKE_HOME_PREEMPT_MARGIN_DIV
#define CAKE_HOME_PREEMPT_MARGIN_DIV 2
#endif
#ifndef CAKE_CONTENDED_SLICE_NUM
#define CAKE_CONTENDED_SLICE_NUM 3
#endif
#ifndef CAKE_CONTENDED_SLICE_DEN
#define CAKE_CONTENDED_SLICE_DEN 2
#endif
#ifndef CAKE_DEEP_WAKE_HYST_SLICES
#define CAKE_DEEP_WAKE_HYST_SLICES 1
#endif
#ifndef CAKE_PEER_WAKE_HYST_SLICES
#define CAKE_PEER_WAKE_HYST_SLICES 2
#endif
#ifndef CAKE_OVF_RESCUE_HYST_SLICES
#define CAKE_OVF_RESCUE_HYST_SLICES 2
#endif
#ifndef CAKE_OVERFLOW_QUEUE_DEPTH
#define CAKE_OVERFLOW_QUEUE_DEPTH 6
#endif
#ifndef CAKE_NR_CCDS
#define CAKE_NR_CCDS 1
#endif
#ifndef CAKE_CCD_STEAL_POLICY
#define CAKE_CCD_STEAL_POLICY 2
#endif
#ifndef CAKE_NR_CPUS
#define CAKE_NR_CPUS 1024
#endif
#ifndef CAKE_QMARK_MODE
#define CAKE_QMARK_MODE 0
#endif
#ifndef CAKE_QMARK_SLOT_BYTES
#define CAKE_QMARK_SLOT_BYTES 128
#endif
#ifndef CAKE_DIRECT_SLICE_STORE
#define CAKE_DIRECT_SLICE_STORE 0
#endif
#ifndef CAKE_SCALAR_PEEK
#define CAKE_SCALAR_PEEK 0
#endif
#ifndef CAKE_MDBLS_STAGE
#define CAKE_MDBLS_STAGE 0
#endif
#ifndef CAKE_MDBLS_PREEMPT
#define CAKE_MDBLS_PREEMPT 1
#endif
#ifndef CAKE_MDBLS_SLICE
#define CAKE_MDBLS_SLICE 1
#endif
#ifndef CAKE_MDBLS_TELEMETRY
#define CAKE_MDBLS_TELEMETRY 0
#endif
#ifndef CAKE_IRQ_SHADOW_MODE
#define CAKE_IRQ_SHADOW_MODE 0
#endif

enum consts {
	NSEC_PER_USEC	= 1000,
	NSEC_PER_MSEC	= (1000 * NSEC_PER_USEC),

	/*
	 * Base time slice: a compile-time immediate, replacing the former
	 * `const volatile slice_ns` rodata global and its loader -s knob
	 * (one policy, no per-use policy load). 3 ms is the
	 * dose-responsed U-curve minimum (1, 2 and 4 ms all measured worse,
	 * 2026-07-04); continuations queued behind a waiter get 1.5x. The
	 * value fits int, so no >int enum extension is needed.
	 */
	SLICE_NS	= CAKE_SLICE_US * NSEC_PER_USEC,

	/*
	 * Dimensionless scheduling policy, expressed only as derived time.
	 * These names are intentionally about mechanism rather than workload:
	 * changing SLICE_NS keeps every eligibility window in the same family.
	 */
	SLEEPER_LAG_NS			= SLICE_NS / CAKE_SLEEPER_LAG_DIV,
	GLOBAL_PREEMPT_PROTECT_NS	= SLICE_NS / CAKE_GLOBAL_PREEMPT_PROTECT_DIV,
	HOME_PREEMPT_YOUNG_NS		= SLICE_NS / CAKE_HOME_PREEMPT_YOUNG_DIV,
	HOME_PREEMPT_BASE_MARGIN_NS	= SLICE_NS / CAKE_HOME_PREEMPT_MARGIN_DIV,
	CONTENDED_SLICE_NS		= SLICE_NS * CAKE_CONTENDED_SLICE_NUM /
					  CAKE_CONTENDED_SLICE_DEN,
	DEEP_WAKE_HYSTERESIS_NS		= CAKE_DEEP_WAKE_HYST_SLICES * SLICE_NS,
	PEER_WAKE_HYSTERESIS_NS		= CAKE_PEER_WAKE_HYST_SLICES * SLICE_NS,
	OVF_RESCUE_HYSTERESIS_NS	= CAKE_OVF_RESCUE_HYST_SLICES * SLICE_NS,
	OVERFLOW_QUEUE_DEPTH		= CAKE_OVERFLOW_QUEUE_DEPTH,
	MDBLS_MIN_SLICE_NS		= SLICE_NS / 2,
	MDBLS_MAX_SLICE_NS		= SLICE_NS * 2,
	MDBLS_SWITCH_COST_NS		= SLICE_NS / 32,
	MDBLS_CONF_STEP			= 32,
	MDBLS_CONF_MAX			= 255,
	NR_CCDS				= CAKE_NR_CCDS,
	BUILD_NR_CPUS			= CAKE_NR_CPUS,
	CCD_STEAL_POLICY		= CAKE_CCD_STEAL_POLICY,

	/*
	 * Fixed-point weight scaling. These are representation constants, not
	 * policy knobs. The split high/low product in cake_scale_vtime() avoids
	 * overflowing `runtime * reciprocal` on an unusually long uninterrupted
	 * run while preserving the exact former result for ordinary runtimes.
	 */
	RECIP_SHIFT		= 20,
	RECIP_ONE		= 1 << RECIP_SHIFT,
	RECIP_MASK		= RECIP_ONE - 1,
	STATIC_PRIO_BASE	= 100,
	RECIP_TABLE_SIZE	= 64,
	RECIP_INDEX_MASK	= RECIP_TABLE_SIZE - 1,
	IDLE_RECIP_INDEX	= 40,
	MAX_RECIP_WEIGHT	= 357913941,

	/* Cache-isolated mutable-state slot geometry. */
	STATE_SLOT_BYTES	= 128,
	STATE_SLOT_WORDS	= STATE_SLOT_BYTES / sizeof(u64),

	/* Runnable-stall safety watchdog, not a scheduling threshold. */
	WATCHDOG_TIMEOUT_MS	= 5 * 1000,

	/*
	 * Verifier sizing bound for per-CPU state and the steal loops. Power
	 * of 2 so hot-path indexes reduce to `cpu & (MAX_CPUS - 1)` — a mask,
	 * not a modulus, and provably in bounds for the verifier. NOT the DSQ
	 * count: one custom vtime DSQ per possible CPU is created at init
	 * (dsq_id == cpu, nr_cpu_ids of them).
	 */
	MAX_CPUS	= 1024,

	/*
	 * The global wake queue: wakeups queue here, continuations
	 * (slice-expiry requeues) queue on their CPU's own DSQ. A woken task
	 * must be findable by the FIRST CPU that blocks anywhere — handoff
	 * chains die waiting for one specific home CPU — while a preempted
	 * task wants exactly its home for cache warmth. One id above the
	 * per-CPU range.
	 */
	WAKE_DSQ	= MAX_CPUS,

	/*
	 * Saturation-balance overflow: depth-threshold expiry continuations route
	 * here (never to WAKE_DSQ — sharing that channel corrupted the
	 * backlog-homing signal and re-split futex pairs). Consumed after
	 * own and wake queues unless its head ages behind the service
	 * frontier, at which point dispatch gives it bounded rescue service.
	 */
	OVF_DSQ		= MAX_CPUS + 1,
};

#endif /* __CAKE_INTF_H */
