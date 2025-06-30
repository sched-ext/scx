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
	u64				affn_dsq;
	u32				dsq_index;
	u64				dsq_id;
	u64				slice_ns;
	u32				perf;
	bool				interactive;
	bool				is_big;
	u64				ran_for;
	u32				node_id;
	u64				intr_dsq;
	u64				mig_dsq;
	u64				llc_dsq;
	u64				max_load_dsq;
};

struct llc_ctx {
	u32				id;
	u32				nr_cpus;
	u32				node_id;
	u64				vtime;
	u32				lb_llc_id;
	u64				last_period_ns;
	u64				dsq;
	u64				intr_dsq;
	u64				mig_dsq;
	u32				index;
	u64				load;
	u64				affn_load;
	u64				intr_load;
	bool				all_big;
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
	struct bpf_cpumask __kptr	*little_cpumask;
	struct bpf_cpumask __kptr	*node_cpumask;
};

struct node_ctx {
	u32				id;
	bool				all_big;
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
	int			last_dsq_index;
	bool			interactive;

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
