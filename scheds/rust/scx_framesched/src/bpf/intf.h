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
	MAX_PATH                = 4096,
	MAX_COMM                = 32,
	DEFAULT_WEIGHT		= 100,
	MAX_WEIGHT		= 10000,
};

/* Per-scheduling-domain context. */
struct dom_ctx {
	/* The ID of the domain. Also the ID of the domain's DSQ. */
	u32 id;

	/* The cpumask of the domain. */
	struct bpf_cpumask __kptr *cpumask;
};

/*
 * QoS latency abstraction used by the scheduler to scale deadline
 *
 * QoS is a representation of the latency sensitivity of the scheduling entity
 * in question. Users may use this QoS as a rough, approximate mental model, or
 * if they need to be more concrete they can use QoS to represent the rate at
 * which error increases with latency.
 */
enum fs_dl_qos {
	/* Negligible QoS: Very long delays are acceptable */
	FS_DL_QOS_LOW,

	/* Normal QoS: Latency is not critical */
	FS_DL_QOS_NORMAL,

	/*
	 * High QoS: Latency is very important, but it's not the end of the
	 * world if we occassionally miss a deadline under super heavy
	 * contention.
	 */
	FS_DL_QOS_HIGH,

	/*
	 * Max QoS: Latency is absolutely critical. Even short delays can cause
	 * a significant impact to interactivity.
	 */
	FS_DL_QOS_MAX,
	FS_DL_NUM_QOS,
};

struct entity_runtime {
	/*
	 * When the entity started running on the CPU.
	 */
	u64 running_at;

	/*
	 * The current amount of time that the task has been running for since
	 * it last became runnable.
	 */
	u64 curr_runtime;

	/*
	 * Average amount of time that the task runs for before being blocked.
	 */
	u64 average_runtime;

	/*
	 * Vruntime of the entity.
	 */
	u64 vruntime;

	/* The QoS of this scheduling entity */
	enum fs_dl_qos qos;
};

/* Per-task context */
struct task_ctx {
	/*
	 * Task domain cpumask AND p->cpus_ptr. Threads whose p->cpus_ptr is a
	 * subset of a domain's cpumask (all per-CPU threads, and other threads
	 * with CPU-pinning affinities that fit within a domain), are always
	 * pinned to the same CPU.
	 */
	struct bpf_cpumask __kptr *cpumask;

	/* The runtime for the task struct */
	struct entity_runtime runtime;

	/* For verifying task QoS updates */
	u64 token;

	/* ID of the currently-assigned domain */
	u32 dom_id;

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

/* Payload for notifying user space about updated task context. */
struct task_notif_msg {
	int pid;
	u64 token;
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

/* Cgroup local-storage context */
struct cgrp_ctx {
	/* Runtime */
	struct entity_runtime runtime;
};


#endif /* __INTF_H */
