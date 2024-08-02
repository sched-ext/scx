// Copyright (c) David Vernet <void@manifault.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
#endif

#include <scx/ravg.bpf.h>

enum consts {
	CACHELINE_SIZE		= 64,
	MAX_CPUS		= 1024,
};

/* Per-scheduling-domain context. */
struct dom_ctx {
	/* The ID of the domain. Also the ID of the domain's DSQ. */
	u32 id;

	/* The cpumask of the domain. */
	struct bpf_cpumask __kptr *cpumask;
};

/* Per-task context */
struct task_ctx {
	/* ID of the currently-assigned domain */
	u32 dom_id;

	/*
	 * Task domain cpumask AND p->cpus_ptr. Threads whose p->cpus_ptr is a
	 * subset of a domain's cpumask (all per-CPU threads, and other threads
	 * with CPU-pinning affinities that fit within a domain), are always
	 * pinned to the same CPU.
	 */
	struct bpf_cpumask __kptr *cpumask;

	/*
	 * Whether a task is pinned to its current domain. This is static
	 * between instances of the task's cpuset being updated.
	 */
	bool pinned;


	/*
	 * Whether a task is not matched to any domain. This can happen under
	 * normal circumstances if a task is affinitized to offline cores. For
	 * example, for per-CPU kthreads whose affinitized CPU is offlined.
	 *
	 * It is not an error to initialize an orphaned task, but it is an
	 * error if the task is scheduled.
	 */
	bool orphaned;
};

/* Per-CPU context */
struct pcpu_ctx {
	/*
	 * Used to ensure round-robin semantics where we're looping over and
	 * selecting something. For example, when we're selecting a domain for
	 * a task.
	 */
	int rr_idx;

	/* The ID of the domain for this CPU. Cannot change. */
	u32 dom_id;

	/* CPU capacity relative to the CPU with the maximum capacity in the system */
	u32 capacity;
} __attribute__((aligned(CACHELINE_SIZE)));

#endif /* __INTF_H */
