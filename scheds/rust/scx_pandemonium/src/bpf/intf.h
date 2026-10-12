// PANDEMONIUM SHARED INTERFACE
// CONSTANTS AND STRUCTURES SHARED BETWEEN BPF (C23) AND RUST

#ifndef __INTF_H
#define __INTF_H

// BINDGEN/SCX COMPATIBILITY: provide kernel types unconditionally.
// vmlinux.h also typedefs these in BPF context; C11+ permits
// duplicate compatible typedefs, so no conflict.
typedef unsigned long long u64;
typedef unsigned char u8;

// BPF VERIFIER LOOP BOUNDS
#define MAX_CPUS  1024
#define MAX_NODES 32
// OVERFLOW-DOMAIN CEILING. DSQs ARE PRE-ALLOCATED AT INIT;
// nr_overflow_domains GATES WHICH ARE LIVE.
#define MAX_OVERFLOW_DOMAINS 32
// PER-CPU affinity_rank SLOT COUNT: MAX_CPUS >> 3 = 128 AT MAX_CPUS=1024.
// SLOTS PAST nr_cpu_ids - 1 HOLD (u32)-1; LOOPS EARLY-EXIT ON THE SENTINEL.
// MAP SIZE = MAX_CPUS * 128 * 4 = 512KB.
#define MAX_AFFINITY_CANDIDATES (MAX_CPUS >> 3)

// KERNEL PROCESS FLAGS (NOT IN vmlinux.h -- THESE ARE #define MACROS)
#define PF_KTHREAD 0x00200000

// TUNING KNOBS -- RUST ADAPTIVE LOOP WRITES THESE, BPF READS THEM
// SINGLE-ELEMENT BPF_MAP_TYPE_ARRAY, UPDATED EVERY 50-1000MS
struct tuning_knobs {
	u64 slice_ns;           // BASE TIME SLICE (DEFAULT 1MS)
	u64 preempt_thresh_ns;  // TICK PREEMPTION THRESHOLD (DEFAULT 1MS)
	u64 batch_slice_ns;     // BATCH TASK SLICE CEILING (DEFAULT 20MS)
	u64 affinity_mode;      // L2 PLACEMENT: 0=OFF, 1=WEAK, 2=STRONG
	u64 codel_thresh_ns;    // tick() PER-CPU SOJOURN SCAN THRESHOLD (SET BY RUST)
	u64 burst_slice_ns;     // SLICE CEILING DURING BURST/LONGRUN (DEFAULT 1MS)
	u64 topology_tau_ns;    // FIEDLER TIME CONSTANT, CAPACITY-AWARE IN N.
	                        // 0 = UNWRITTEN, BPF FALLBACKS STAY IN EFFECT
	u64 codel_eq_ns;        // CODEL EQUILIBRIUM, A POSITION IN THE TARGET BAND
	                        // FROM THE SPECTRAL-GAP DEFICIT. 0 = UNWRITTEN
	// THE PHI DISTANCE PENALTY IS NOT A KNOB: RUST PRE-FOLDS IT INTO THE
	// reff_value MAP IN NS AT TOPOLOGY DETECT AND BPF READS THAT MAP.
};

// PER-CPU STATISTICS (BPF_MAP_TYPE_PERCPU_ARRAY VALUE)
// RUST READS THESE FOR WORKLOAD REGIME DETECTION
struct pandemonium_stats {
	u64 nr_dispatches;      // TOTAL TASKS DISPATCHED (ALL PATHS)
	u64 nr_idle_hits;       // SELECT_CPU FAST PATH -> SCX_DSQ_LOCAL
	u64 nr_shared;          // ENQUEUE -> PER-NODE SHARED DSQ
	u64 nr_preempt;         // TICK PREEMPTIONS (BATCH TASK YIELDED)
	u64 wake_lat_sum;       // SUM WAKEUP->RUN LATENCY (NS)
	u64 wake_lat_samples;   // COUNT OF WAKEUP LATENCY SAMPLES
	u64 nr_keep_running;    // TASKS REPLENISHED VIA keep_running()
	u64 nr_hard_kicks;      // ENQUEUE: SCX_KICK_PREEMPT (FRESH WAKEUP)
	u64 nr_soft_kicks;      // ENQUEUE: SOFT NUDGE (RE-ENQUEUE)
	u64 nr_enq_wakeup;      // ENQUEUE: TASK JUST WOKE UP (!ran_since_wake)
	u64 nr_enq_requeue;     // ENQUEUE: TASK RE-ENQUEUED (ran_since_wake)
	u64 wake_lat_idle_sum;  // LATENCY SUM: IDLE FAST PATH (NS)
	u64 wake_lat_idle_cnt;  // LATENCY COUNT: IDLE FAST PATH
	u64 wake_lat_kick_sum;  // LATENCY SUM: HARD-KICKED ENQUEUE (NS)
	u64 wake_lat_kick_cnt;  // LATENCY COUNT: HARD-KICKED ENQUEUE
	// L2 CACHE AFFINITY, COUNTED IN select_cpu() IDLE PATH AND enqueue() TIER 1
	u64 nr_l2_hit_batch;
	u64 nr_l2_miss_batch;
	u64 nr_l2_hit_interactive;
	u64 nr_l2_miss_interactive;
	u64 nr_reenqueue;       // TASKS RESCUED BY scx_bpf_reenqueue_local()
	u64 batch_sojourn_ns;   // CURRENT OVERFLOW WAIT AGE (NS), WRITTEN BY tick()
	u64 longrun_mode_active;// 1 IF SUSTAINED OVERFLOW PRESSURE, WRITTEN BY tick()
	u64 nr_overflow_rescue; // DISPATCHES BY try_service_aged_overflow AT
	                        // codel_target_ns (STEP 2)
	// CROSS-DOMAIN LANDINGS BY PLACEMENT PATH, INDEXED BY XDOM_* BELOW.
	// THE ADAPTIVE LAYER SUMS XDOM_SEL_* + XDOM_ENQ_T1 AS THE MWU SCATTER
	// LOSS; XDOM_STEAL AND XDOM_STEP5 ARE EXCLUDED FROM IT.
	u64 nr_cross_domain[8];
	u64 nr_osc_park;        // OSCILLATOR ENVELOPE PARK ENTRIES (CPU-0 TICK)
	u64 nr_spill_kick_preempt; // select_cpu SEATS REDIRECTED OFF AN IDLE PICK
	                        // ONTO A BUSY SPILL CPU, KICKED SCX_KICK_PREEMPT
	u64 nr_steal;           // EVERY SUCCESSFUL STEP 1 PEER move_to_local,
	                        // CROSS- AND SAME-DOMAIN
	u64 nr_kick_declined;   // requeue_kick_flag RETURNING KICK_NONE,
	                        // SELF-TARGETED ONLY. NO KFUNC WAS CALLED
	u64 nr_stay_cost_held;  // anchor_stay_beats_move REFUSING THE
	                        // anchor -> target MOVE
	u64 nr_stay_move_taken; // THE SAME EDGE ADMITTED. HELD + TAKEN IS EVERY
	                        // anchor -> target DECISION THE WAKE PATH MADE
	// PER-CPU RUNNABLE DEPTH, ACCUMULATED AT TICK RATE. USERSPACE DIFFERENCES
	// BOTH FIELDS FOR AN INTERVAL MEAN, AS wake_lat_sum/wake_lat_samples DO.
	// MONOTONIC; NEVER RESET IN BPF.
	u64 rq_depth_sum;
	u64 rq_depth_samples;
};

// XDOM PATH INDICES FOR pandemonium_stats.nr_cross_domain[] (DIAGNOSTIC).
// THE INDICES ARE POSITIONAL IN ARCHIVED PROM LABELS: NEVER RENUMBER.
#define XDOM_SEL_TIGHT   0   // select_cpu sync pipe-partner co-location
#define XDOM_SEL_SYNC    1   // select_cpu WAKE_SYNC phi_warm_target
#define XDOM_SEL_NORMAL  2   // select_cpu normal_path phi_warm_target
#define XDOM_SEL_DFL     3   // select_cpu scx_bpf_select_cpu_dfl idle pick
#define XDOM_ENQ_T1      4   // enqueue TIER 1 idle (pick_idle_cpu_node)
#define XDOM_ENQ_T2      5   // enqueue TIER 2 warm-anchor spill
#define XDOM_STEAL       6   // dispatch STEP 1 R_eff steal (this_cpu vs peer)
#define XDOM_STEP5       7   // dispatch STEP 5 cross-domain work-conservation

#endif // __INTF_H
