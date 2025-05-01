#ifndef __TYPES_H
#define __TYPES_H

/*
 * XXXETSAL This is convoluted for a reason. We have a three way conflict here:
 *
 * 1) intf.h gets parsed by bindgen, and I guess bindgen does not fully
 * preprocess the file because it does not resolve __arena to
 * __attribute__((address_space(1))) and errors out. So we cannot use the
 * __arena macro from bpf_arena_common.h that involves all this #ifdef'ing.
 * 2) Clang 18 full-on crashes if we pass address_space(1) as an attribute as it
 * is unable to generate the address space conversion instruction.
 * 3) Clang 19 requires the address_space attribute because address space
 * conversions can only be implicit.
 *
 * The below snippet replicates as tersely as possible the logic in
 * bpf_arena_common.h to get the code passing with both Clang 18 and 19.
 */

struct dom_ctx;
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) && !defined(BPF_ARENA_FORCE_ASM)
typedef struct dom_ctx __attribute__((address_space(1))) *dom_ptr;
#else
typedef struct dom_ctx *dom_ptr;
#endif

struct task_ctx {
	/* The domains this task can run on */
	u64 dom_mask;
	u64 preferred_dom_mask;

	/* Arena pointer to this task's domain. */
	dom_ptr domc;

	u32 target_dom;
	u32 weight;
	bool runnable;
	u64 dom_active_tasks_gen;
	u64 deadline;

	u64 sum_runtime;
	u64 avg_runtime;
	u64 last_run_at;

	/* frequency with which a task is blocked (consumer) */
	u64 blocked_freq;
	u64 last_blocked_at;

	/* frequency with which a task wakes other tasks (producer) */
	u64 waker_freq;
	u64 last_woke_at;

	/* The task is a workqueue worker thread */
	bool is_kworker;

	/* Allowed on all CPUs and eligible for DIRECT_GREEDY optimization */
	bool all_cpus;

	/* select_cpu() telling enqueue() to queue directly on the DSQ */
	bool dispatch_local;

	/* For visibility from userspace, may become stale after multithreaded exec */
	u32 pid;

	struct ravg_data dcyc_rd;
};

/* XXXETSAL Same rationale as for dom_ptr. Remove once we dump Clang 18.*/

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) && !defined(BPF_ARENA_FORCE_ASM)
typedef struct task_ctx __attribute__((address_space(1))) *task_ptr;
#else
typedef struct task_ctx *task_ptr;
#endif

struct bucket_ctx {
	u64 dcycle;
	struct ravg_data rd;
};

struct dom_active_tasks {
	u64 genn;
	u64 read_idx;
	u64 write_idx;
	task_ptr tasks[MAX_DOM_ACTIVE_TPTRS];
};

struct dom_ctx {
	u32 id;
	u64 min_vruntime;

	u64 dbg_dcycle_printed_at;
	struct bucket_ctx buckets[LB_LOAD_BUCKETS];
	struct dom_active_tasks active_tasks;
};

struct node_ctx {
	struct bpf_cpumask __kptr *cpumask;
};

#endif /* __TYPES_H */
