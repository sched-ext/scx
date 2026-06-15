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
// PER-CCX OVERFLOW TIER CEILING. CHIPLET PARTS (AMD CCX/CCD) HAVE SMALL CCX
// COUNTS (Ryzen 3000: 2, EPYC: up to ~16); 32 IS A COMFORTABLE CAP.
// PRE-ALLOCATED AT INIT (DSQs ARE CHEAP); nr_ccx WALKED FROM Rust AT TOPOLOGY
// DETECT GATES WHICH ARE LIVE.
#define MAX_CCX_DOMAINS 32
// AFFINITY_RANK STORAGE PER CPU. EACH CPU'S R_eff-RANKED PEERS ARE
// STORED HERE; STEP 1 R_eff STEAL AND THE PLACEMENT-SIDE SPILL HELPER
// WALK THIS LIST WITH A TAU-DERIVED RUNTIME BUDGET CAPPED BY nr_cpu_ids
// - 1 (ACTUAL TOPOLOGY). MAX_AFFINITY_CANDIDATES IS THE COMPILE-TIME
// VERIFIER-SAFE LOOP BOUND, DERIVED FROM MAX_CPUS RATHER THAN HARDCODED:
// MAX_CPUS >> 3 (= 128 AT MAX_CPUS=1024) STAYS WELL UNDER THE VERIFIER
// PATH-STATE LIMIT WHILE COVERING SYSTEMS UP TO THAT WIDTH WITH NO
// TRUNCATION. UNUSED SLOTS PAST nr_cpu_ids - 1 ARE (u32)-1 SENTINEL;
// LOOPS EARLY-EXIT ON SENTINEL. MAP SIZE = MAX_CPUS * (MAX_CPUS >> 3)
// * 4 = 512KB AT MAX_CPUS=1024.
#define MAX_AFFINITY_CANDIDATES (MAX_CPUS >> 3)

// FAR-TIER STEAL TABLE WIDTH: THE FAR_CANDIDATES NEAREST CROSS-CCX PEERS
// PER CPU (R_EFF-ASCENDING). A DRY HOME CCX DOES NOT NEED A WIDE FAR
// SEARCH -- THE NEAREST FAR PEERS CARRY THE LOWEST PENALTY ANYWAY -- AND
// THE SMALL CONSTANT BOUND KEEPS THE DISPATCH WALK VERIFIER-TRIVIAL.
#define FAR_CANDIDATES 8

// KERNEL PROCESS FLAGS (NOT IN vmlinux.h -- THESE ARE #define MACROS)
#define PF_KTHREAD 0x00200000

// TUNING KNOBS -- RUST ADAPTIVE LOOP WRITES THESE, BPF READS THEM
// SINGLE-ELEMENT BPF_MAP_TYPE_ARRAY, UPDATED EVERY 50-1000MS
struct tuning_knobs {
	u64 slice_ns;           // BASE TIME SLICE (DEFAULT 1MS)
	u64 preempt_thresh_ns;  // TICK PREEMPTION THRESHOLD (DEFAULT 1MS)
	u64 batch_slice_ns;     // BATCH TASK SLICE CEILING (DEFAULT 20MS)
	u64 lat_cri_thresh_high; // CLASSIFIER: LAT_CRITICAL THRESHOLD (DEFAULT 32)
	u64 lat_cri_thresh_low;  // CLASSIFIER: INTERACTIVE THRESHOLD (DEFAULT 8)
	u64 affinity_mode;      // L2 PLACEMENT: 0=OFF, 1=WEAK, 2=STRONG
	u64 sojourn_thresh_ns;  // BATCH DSQ RESCUE THRESHOLD (SET BY RUST)
	u64 burst_slice_ns;     // SLICE CEILING DURING BURST/LONGRUN (SET BY RUST, DEFAULT 1MS)
	u64 topology_tau_ns;    // FIEDLER-DERIVED TIME CONSTANT (1/lambda_2).
	                        // 0 MEANS RUST HAS NOT YET WRITTEN tau; BPF
	                        // FALLBACK CONSTANTS REMAIN IN EFFECT UNTIL A
	                        // NONZERO VALUE LANDS. WRITTEN AT TOPOLOGY
	                        // DETECT AND ON HOTPLUG.
	u64 codel_eq_ns;        // R_eff-DERIVED CODEL EQUILIBRIUM TARGET.
	                        // <R_eff> * 2m * tau, CLAMPED [200us, 8ms].
	                        // 0 MEANS NOT YET WRITTEN. WRITTEN AT TOPOLOGY
	                        // DETECT AND ON HOTPLUG (CO-LOCATED WITH tau).
	// PHI DISTANCE PENALTY IS PRE-FOLDED INTO THE reff_value MAP (IN NS) BY
	// RUST AT TOPOLOGY DETECT -- NO KNOB FIELD: BPF READS THE MAP DIRECTLY.
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
	// L2 CACHE AFFINITY INSTRUMENTATION
	// COUNTED IN select_cpu() IDLE PATH AND enqueue() TIER 1
	u64 nr_l2_hit_batch;
	u64 nr_l2_miss_batch;
	u64 nr_l2_hit_interactive;
	u64 nr_l2_miss_interactive;
	u64 nr_l2_hit_lat_crit;
	u64 nr_l2_miss_lat_crit;
	// CPU RELEASE: TASKS RESCUED FROM LOCAL DSQ BY scx_bpf_reenqueue_local()
	u64 nr_reenqueue;
	// CODEL SOJOURN: CURRENT BATCH WAIT AGE (NS), WRITTEN BY tick()
	u64 batch_sojourn_ns;
	// LONGRUN: 1 IF SUSTAINED BATCH PRESSURE DETECTED, 0 OTHERWISE, WRITTEN BY tick()
	u64 longrun_mode_active;
	// OVERFLOW SOJOURN RESCUE: TASKS DISPATCHED BY try_service_older_overflow
	// AT overflow_sojourn_rescue_ns (DISPATCH STEP 2)
	u64 nr_overflow_rescue;
	// CROSS-CCX SCATTER ATTRIBUTION: PER-PLACEMENT-PATH COUNT OF LANDINGS
	// WHERE THE CHOSEN CPU IS IN A DIFFERENT CCX THAN THE TASK'S last_cpu.
	// INDEXED BY XCCX_* BELOW. THE ADAPTIVE LAYER CONSUMES THE PLACEMENT-SIDE
	// PATHS (XCCX_SEL_* + XCCX_ENQ_T1) AS THE MWU CROSS-CCX SCATTER LOSS
	// PATHWAY, AND THE BENCH SUITE SURFACES ALL PATHS PER RUN. THE PHI-CORRECT
	// PATHS (XCCX_STEAL, XCCX_STEP5) ARE TRACKED BUT EXCLUDED FROM THE LOSS --
	// THEY ARE DELIBERATE WORK-CONSERVATION MOVES, NOT SCATTER TO SUPPRESS.
	u64 nr_xccx[8];
	// OSCILLATOR ENVELOPE: PARK ENTRIES (CPU-0 TICK WRITER). ZERO AFTER AN
	// IDLE-HEAVY RUN MEANS THE ENVELOPE NEVER PARKED -- THE MIET-COLLAPSE
	// FAILURE MODE THE BENCH MUST BE ABLE TO DETECT.
	u64 nr_osc_park;
};

// XCCX path indices for pandemonium_stats.nr_xccx[] (diagnostic).
#define XCCX_SEL_TIGHT   0   // select_cpu WAKE_SYNC tight-partner colocation
#define XCCX_SEL_SYNC    1   // select_cpu WAKE_SYNC phi_warm_target
#define XCCX_SEL_NORMAL  2   // select_cpu normal_path phi_warm_target
#define XCCX_SEL_DFL     3   // select_cpu scx_bpf_select_cpu_dfl idle pick
#define XCCX_ENQ_T1      4   // enqueue TIER 1 idle (pick_idle_cpu_node)
#define XCCX_ENQ_T2      5   // enqueue TIER 2 warm-anchor spill
#define XCCX_STEAL       6   // dispatch STEP 1 R_eff steal (this_cpu vs peer)
#define XCCX_STEP5       7   // dispatch STEP 5 cross-CCX work-conservation scan

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
