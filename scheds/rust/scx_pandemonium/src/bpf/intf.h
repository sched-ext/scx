// PANDEMONIUM SHARED INTERFACE
// CONSTANTS AND STRUCTURES SHARED BETWEEN BPF (C23) AND RUST

#ifndef __INTF_H
#define __INTF_H

// BPF VERIFIER LOOP BOUNDS
#define MAX_CPUS  1024
#define MAX_NODES 32

// TUNING KNOBS -- RUST ADAPTIVE LOOP WRITES THESE, BPF READS THEM
// SINGLE-ELEMENT BPF_MAP_TYPE_ARRAY, UPDATED EVERY 50-1000MS
struct tuning_knobs {
	u64 slice_ns;           // BASE TIME SLICE (DEFAULT 1MS)
	u64 preempt_thresh_ns;  // TICK PREEMPTION THRESHOLD (DEFAULT 1MS)
	u64 lag_scale;          // DEADLINE LAG MULTIPLIER (DEFAULT 4)
	u64 batch_slice_ns;     // BATCH TASK SLICE CEILING (DEFAULT 20MS)
	u64 cpu_bound_thresh_ns; // CPU-BOUND DEMOTION THRESHOLD (REGIME-DEPENDENT)
	u64 lat_cri_thresh_high; // CLASSIFIER: LAT_CRITICAL THRESHOLD (DEFAULT 32)
	u64 lat_cri_thresh_low;  // CLASSIFIER: INTERACTIVE THRESHOLD (DEFAULT 8)
};

// PER-CPU STATISTICS (BPF_MAP_TYPE_PERCPU_ARRAY VALUE)
// RUST READS THESE FOR WORKLOAD REGIME DETECTION
struct pandemonium_stats {
	u64 nr_dispatches;      // TOTAL TASKS DISPATCHED (ALL PATHS)
	u64 nr_idle_hits;       // SELECT_CPU FAST PATH -> SCX_DSQ_LOCAL
	u64 nr_shared;          // ENQUEUE -> PER-NODE SHARED DSQ
	u64 nr_preempt;         // TICK PREEMPTIONS (BATCH TASK YIELDED)
	u64 wake_lat_sum;       // SUM WAKEUP->RUN LATENCY (NS)
	u64 wake_lat_max;       // MAX WAKEUP->RUN LATENCY (NS)
	u64 wake_lat_samples;   // COUNT OF WAKEUP LATENCY SAMPLES
	u64 nr_keep_running;    // TASKS REPLENISHED VIA keep_running()
	u64 nr_hard_kicks;      // ENQUEUE: SCX_KICK_PREEMPT (FRESH WAKEUP)
	u64 nr_soft_kicks;      // ENQUEUE: SOFT NUDGE (RE-ENQUEUE)
	u64 nr_enq_wakeup;      // ENQUEUE: TASK JUST WOKE UP (AWAKE_VTIME==0)
	u64 nr_enq_requeue;     // ENQUEUE: TASK RE-ENQUEUED (AWAKE_VTIME>0)
	u64 wake_lat_idle_sum;  // LATENCY SUM: IDLE FAST PATH (NS)
	u64 wake_lat_idle_cnt;  // LATENCY COUNT: IDLE FAST PATH
	u64 wake_lat_kick_sum;  // LATENCY SUM: HARD-KICKED ENQUEUE (NS)
	u64 wake_lat_kick_cnt;  // LATENCY COUNT: HARD-KICKED ENQUEUE
	u64 nr_guard_clamps;    // INTERACTIVE GUARD: BATCH SLICE CLAMPED
	u64 nr_procdb_hits;     // ENABLE: PRE-LEARNED CLASSIFICATION APPLIED
	// L2 CACHE AFFINITY INSTRUMENTATION (PHASE 2: MEASURE)
	// COUNTED IN select_cpu() IDLE PATH AND enqueue() TIER 1
	u64 nr_l2_hit_batch;
	u64 nr_l2_miss_batch;
	u64 nr_l2_hit_interactive;
	u64 nr_l2_miss_interactive;
	u64 nr_l2_hit_lat_crit;
	u64 nr_l2_miss_lat_crit;
};

// WAKEUP LATENCY SAMPLE -- PUSHED TO RING BUFFER FOR P99 CALCULATION
// BPF RECORDS THESE IN running(); RUST DRAINS FOR ADAPTIVE CONTROL
struct wake_lat_sample {
	u64 lat_ns;      // WAKEUP-TO-RUN LATENCY IN NANOSECONDS
	u64 sleep_ns;    // HOW LONG TASK SLEPT BEFORE THIS WAKEUP (0 IF UNKNOWN)
	u32 pid;         // TASK PID (FOR FILTERING)
	u8  path;        // 0=IDLE FAST PATH, 1=HARD KICK, 2=SOFT KICK
	u8  tier;        // TASK TIER AT WAKEUP TIME
	u8  _pad[2];
};

// PROCESS CLASSIFICATION: BPF OBSERVES, RUST LEARNS, BPF APPLIES
// SHARED BETWEEN BPF MAPS (task_class_observe, task_class_init) AND RUST (procdb.rs)
struct task_class_entry {
	u8  tier;
	u8  _pad[7];
	u64 avg_runtime;
	u64 runtime_dev;    // EWMA |RUNTIME - AVG_RUNTIME|
	u64 wakeup_freq;    // WAKEUP FREQUENCY (EWMA)
	u64 csw_rate;       // CONTEXT SWITCH RATE (EWMA)
};

#endif // __INTF_H
