#pragma once

struct p2dq_timer {
	// if set to 0 the timer will only be scheduled once
	u64 interval_ns;
	u64 init_flags;
	int start_flags;
};

struct cpu_ctx {
	int				id;
	u32				llc_id;
	u32				node_id;
	u64				dsq_index;
	u32				perf;
	bool				interactive;
	bool				is_big;
	u64				ran_for;
	u64				dsqs[MAX_DSQS_PER_LLC];
	u64				max_load_dsq;
};

struct llc_ctx {
	u32				id;
	u32				nr_cpus;
	u32				node_id;
	u64				vtime;
	u64				last_period_ns;
	u64				load;
	bool				all_big;
	u64				dsqs[MAX_DSQS_PER_LLC];
	u64				dsq_max_vtime[MAX_DSQS_PER_LLC];
	u64				dsq_load[MAX_DSQS_PER_LLC];
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
	struct bpf_cpumask __kptr	*little_cpumask;
};

struct node_ctx {
	u32				id;
	bool				all_big;
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
};

struct task_p2dq {
	u64			dsq_id;
	int			dsq_index;
	u32			cpu;
	u32			llc_id;
	u32			node_id;
	bool			runnable;
	u32			weight;
	u64			last_dsq_id;
	int			last_dsq_index;
	u64 			last_run_at;
	u64			llc_runs; /* how many runs on the current LLC */

	/* The task is a workqueue worker thread */
	bool			is_kworker;

	/* Allowed to run on all CPUs */
	bool			all_cpus;
};

typedef struct task_p2dq __arena task_ctx;

struct enqueue_promise_vtime {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
	u64	vtime;
};

struct enqueue_promise_fifo {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
};

struct enqueue_promise {
	enum enqueue_promise_kind	kind;
	union {
		struct enqueue_promise_vtime	vtime;
		struct enqueue_promise_fifo	fifo;
	};
};

