#pragma once

#include <lib/atq.h>
#include <lib/minheap.h>

struct p2dq_timer {
	// if set to 0 the timer will only be scheduled once
	u64 interval_ns;
	u64 init_flags;
	int start_flags;
};

struct cpu_ctx {
	int				id;
	u32				llc_id;
	u64				affn_dsq;
	u64				slice_ns;
	u32				core_id;
	u32				dsq_index;
	u32				perf;
	bool				interactive;
	bool				is_big;
	bool				nice_task;
	u64				ran_for;
	u32				node_id;
	u64				mig_dsq;
	u64				llc_dsq;
	u64				max_load_dsq;

	scx_atq_t			*mig_atq;
};

struct llc_ctx {
	u32				id;
	u32				nr_cpus;
	u32				node_id;
	u64				vtime;
	u32				lb_llc_id;
	u64				last_period_ns;
	u64				dsq;
	u64				mig_dsq;
	u32				index;
	u64				load;
	u64				affn_load;
	u64				intr_load;
	u64				dsq_load[MAX_DSQS_PER_LLC];
	bool				saturated;

	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
	struct bpf_cpumask __kptr	*little_cpumask;
	struct bpf_cpumask __kptr	*node_cpumask;
	struct bpf_cpumask __kptr	*tmp_cpumask;

	scx_atq_t			*mig_atq;
	scx_minheap_t			*idle_cpu_heap;
	arena_spinlock_t		idle_lock;

	/* CPU sharding related fields */
	u32				nr_shards;
	u64				shard_dsqs[MAX_LLC_SHARDS];
};

struct node_ctx {
	u32				id;
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
};

struct task_p2dq {
	u64			dsq_id;
	u64			slice_ns;
	int			dsq_index;
	u32			llc_id;
	u32			node_id;
	u64			used;
	u64			last_dsq_id;
	u64 			last_run_started;
	u64 			last_run_at;
	u64			llc_runs; /* how many runs on the current LLC */
	u64			enq_flags;
	int			last_dsq_index;
	bool			interactive;
	bool			was_nice;

	/* The task is a workqueue worker thread */
	bool			is_kworker;

	/* Allowed to run on all CPUs */
	bool			all_cpus;
};

typedef struct task_p2dq __arena task_ctx;

enum enqueue_promise_kind {
	P2DQ_ENQUEUE_PROMISE_COMPLETE,
	P2DQ_ENQUEUE_PROMISE_VTIME,
	P2DQ_ENQUEUE_PROMISE_FIFO,
	P2DQ_ENQUEUE_PROMISE_ATQ_VTIME,
	P2DQ_ENQUEUE_PROMISE_ATQ_FIFO,
	P2DQ_ENQUEUE_PROMISE_FAILED,
};

struct enqueue_promise_vtime {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
	u64	vtime;

	scx_atq_t	*atq;
};

struct enqueue_promise_fifo {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;

	scx_atq_t	*atq;
};

// This struct is zeroed at the beginning of `async_p2dq_enqueue` and only
// relevant fields are set, so assume 0 as default when adding fields.
struct enqueue_promise {
	enum enqueue_promise_kind	kind;

	s32				cpu;
	bool				kick_idle;
	bool				has_cleared_idle;

	union {
		struct enqueue_promise_vtime	vtime;
		struct enqueue_promise_fifo	fifo;
	};
};
