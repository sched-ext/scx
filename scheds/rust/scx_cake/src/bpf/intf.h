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

enum consts {
	NSEC_PER_USEC	= 1000,
	NSEC_PER_MSEC	= (1000 * NSEC_PER_USEC),

	/*
	 * Base time slice: a compile-time immediate, replacing the former
	 * `const volatile slice_ns` rodata global and its loader -s knob
	 * (one system, no volatile, no per-use memory load). 3 ms is the
	 * dose-responsed U-curve minimum (1, 2 and 4 ms all measured worse,
	 * 2026-07-04); continuations queued behind a waiter get 1.5x. The
	 * value fits int, so no >int enum extension is needed.
	 */
	SLICE_NS	= 3 * NSEC_PER_MSEC,

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
	 * Saturation-balance overflow: depth-2 expiry continuations route
	 * here (never to WAKE_DSQ — sharing that channel corrupted the
	 * backlog-homing signal and re-split futex pairs). Consumed after
	 * own and wake queues.
	 */
	OVF_DSQ		= MAX_CPUS + 1,
};

#endif /* __CAKE_INTF_H */
