#ifndef __TYPES_H
#define __TYPES_H

#include <lib/ravg.h>

typedef struct dom_ctx __arena *dom_ptr;
struct dom_ctx;

#define arena_lock_t arena_spinlock_t __arena *

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

	scx_bitmap_t cpumask;
};

typedef struct task_ctx __arena *task_ptr;

struct bucket_ctx {
	u64 dcycle;
	struct ravg_data rd;
};

struct dom_active_tasks {
	u64 gen;
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

	scx_bitmap_t cpumask;
	scx_bitmap_t direct_greedy_cpumask;
	scx_bitmap_t node_cpumask;

	arena_lock_t vtime_lock;
};

#endif /* __TYPES_H */
