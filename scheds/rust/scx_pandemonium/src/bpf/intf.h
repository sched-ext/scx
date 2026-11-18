// PANDEMONIUM SHARED INTERFACE
// CONSTANTS AND STRUCTURES SHARED BETWEEN BPF AND RUST

#ifndef __INTF_H
#define __INTF_H

// THE BPF SIDE GETS THESE FROM vmlinux.h. A BINDINGS PASS PARSES THIS HEADER
// ALONE, SO IT DEFINES THEM ITSELF WHEN vmlinux.h HAS NOT.
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
#endif

// BPF VERIFIER LOOP BOUNDS
#define MAX_CPUS  1024
// PER-CPU affinity_rank SLOT COUNT: MAX_CPUS >> 3 = 128 AT MAX_CPUS=1024.
// SLOTS PAST nr_cpu_ids - 1 HOLD (u32)-1; LOOPS EARLY-EXIT ON THE SENTINEL.
// MAP SIZE = MAX_CPUS * 128 * 4 = 512KB.
#define MAX_AFFINITY_CANDIDATES (MAX_CPUS >> 3)

// KERNEL PROCESS FLAGS (NOT IN vmlinux.h -- THESE ARE #define MACROS)
#define PF_KTHREAD 0x00200000

// THE PLACEMENT BASE COST's RAIL, ONE DEFINITION FOR BOTH SIDES: BPF HOLDS tau's
// COST AND THE LAYER's phi_base_ns TO IT, AND THE LAYER HOLDS WHAT IT WRITES TO
// IT. bpf_intf.rs MIRRORS IT AND ITS TEST READS THESE LINES.
#define PHI_BASE_MIN_NS  5000ULL
#define PHI_BASE_MAX_NS  100000ULL

// THE FLOOR UNDER EVERY SLICE BPF GRANTS, AND HOW MANY LIVE CoDel TARGETS A
// STANDING TASK MAY HOLD A CPU FOR WHILE standing_targets IS UNWRITTEN: THE
// BOUND A WAITER PAYS WHEN IT LANDS ON A BUSY CPU. THE LAYER WRITES ITS KNOBS
// ON THE SAME RAILS (tuning.rs TuningKnobs::applied); tuning.rs MIRRORS THEM
// AND bpf_intf.rs's TEST READS THESE LINES.
#define SLICE_MIN_NS            100000ULL
#define SLICE_STANDING_TARGETS  4ULL

// TUNING KNOBS -- RUST ADAPTIVE LOOP WRITES THESE, BPF READS THEM
// SINGLE-ELEMENT BPF_MAP_TYPE_ARRAY, UPDATED EVERY 50-1000MS
struct tuning_knobs {
	u64 slice_ns;           // BASE TIME SLICE (DEFAULT 1MS)
	u64 batch_slice_ns;     // BATCH TASK SLICE CEILING (DEFAULT 20MS)
	u64 codel_thresh_ns;    // tick() PER-CPU SOJOURN SCAN THRESHOLD (SET BY RUST)
	u64 topology_tau_ns;    // FIEDLER TIME CONSTANT, CAPACITY-AWARE IN N.
	                        // 0 = UNWRITTEN, BPF FALLBACKS STAY IN EFFECT
	u64 codel_eq_ns;        // CODEL EQUILIBRIUM, A POSITION IN THE TARGET BAND
	                        // FROM THE SPECTRAL-GAP DEFICIT. 0 = UNWRITTEN
	u64 phi_base_ns;        // THE PLACEMENT BASE COST THE LAYER MEASURED: THE
	                        // MEDIAN OVER TASKS OF A TASK's MEDIAN STINT AFTER A
	                        // CROSS-L3 WAKE LESS AFTER A SAME-L3 ONE (research
	                        // t14), ON [PHI_BASE_MIN_NS, PHI_BASE_MAX_NS] ON BOTH
	                        // SIDES. 0 = UNWRITTEN: tau's COST STANDS, AND A 0
	                        // WRITTEN AFTER A VALUE RESTORES IT
	u64 standing_targets;   // CoDel TARGETS A STANDING TASK MAY HOLD THE CPU
	                        // FOR. 0 = UNWRITTEN, SLICE_STANDING_TARGETS STANDS
	u64 waker_leave_ns;     // A WAKER THAT STOPS THIS SOON AFTER ITS WAKES SEATS
	                        // A PARTNER AS A SYNC WAKER DOES. 0 = OFF
	// THE PHI DISTANCE PENALTY IS NOT A KNOB: RUST PRE-FOLDS IT INTO THE
	// reff_value MAP IN NS AT TOPOLOGY DETECT AND BPF READS THAT MAP.
};

// PER-CPU STATISTICS (BPF_MAP_TYPE_PERCPU_ARRAY VALUE)
// RUST READS THESE FOR WORKLOAD REGIME DETECTION
struct pandemonium_stats {
	u64 nr_dispatches;      // TOTAL TASKS DISPATCHED (ALL PATHS)
	u64 nr_idle_hits;       // SELECT_CPU FAST PATH -> SCX_DSQ_LOCAL
	u64 nr_shared;          // ENQUEUE SEATS, EVERY TIER
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
	u64 nr_rescue;          // DISPATCHES THAT SERVED A LANE PAST codel_target_ns,
	                        // THE OSCILLATOR'S FORCING TERM
	// CROSS-DOMAIN LANDINGS BY PLACEMENT PATH, INDEXED BY XDOM_* BELOW. THE
	// [KNOBS] LINE's scatter_pct SUMS THE PLACEMENT PATHS XDOM_SEL_* AND
	// XDOM_ENQ_T1; THE STEAL, XDOM_STEAL, IS EXCLUDED FROM IT. SLOTS 5 AND 7 ARE
	// RETIRED AND STAY ZERO.
	u64 nr_cross_domain[8];
	u64 nr_osc_park;        // OSCILLATOR ENVELOPE PARK ENTRIES (CPU-0 TICK)
	u64 nr_spill_kick_preempt; // select_cpu SEATS REDIRECTED OFF AN IDLE PICK
	                        // ONTO A BUSY SPILL CPU, KICKED SCX_KICK_PREEMPT
	u64 nr_steal;           // EVERY SUCCESSFUL STEP 1 PEER move_to_local,
	                        // CROSS- AND SAME-DOMAIN
	u64 nr_kick_declined;   // requeue_kick_flag RETURNING KICK_NONE,
	                        // SELF-TARGETED ONLY. NO KFUNC WAS CALLED
	u64 nr_steal_lost;      // STEP 1 MOVES LOST TO ANOTHER THIEF OR THE PEER'S
	                        // OWN STEP 0; THE WALK WENT ON TO THE NEXT PEER
	u64 nr_steal_base_held; // PEER HEADS A STEAL WALK LEFT THAT tau's BASE COST
	                        // WOULD HAVE TAKEN: THE LIVE BASE COST's REFUSALS.
	                        // ZERO WHILE THE APPLIED COST IS tau's (THE BPF ARM)
	u64 nr_sleepless_cut;  // TIER 2 WAKES THAT MAY NOT CUT, SEATED BY THE CUT
	                        // ON A CPU WHOSE RESIDENT DOES NOT SLEEP
	u64 nr_sleepless_miss;  // THE SAME WAKES THAT FOUND NO SUCH RESIDENT WITHIN
	                        // THE WALK AND WAITED IN ORDER
};

// PER-CPU QUEUE RING. EACH TICK ADDS THIS CPU'S SEAT DEPTH, ITS LANE'S DEPTH
// AND ITS LOCAL DSQ'S DEPTH INTO THE SLOT FOR THE CURRENT BUCKET
// (epoch = ktime / depth_bucket_ns), AND EVERY running() ADDS THE RUN, WHETHER
// IT ENDED A WAKE, AND THE QUEUE WAIT IT ENDED, SO EVERY CPU SAMPLES ONE TIME
// GRID AND THE 1HZ LOOP READS EVERY SAMPLE INSTEAD OF ONE MEAN PER SECOND. A
// SLOT WHOSE epoch IS NOT THE ONE ASKED FOR HOLDS AN EARLIER LAP OR A CPU THAT
// NEITHER TICKED NOR RAN ANYTHING, AND READS ABSENT. domain IS THE CPU'S
// TOPOLOGY DOMAIN, SO USERSPACE FOLDS A DOMAIN'S CPUS FROM WHAT BPF ACTUALLY
// SAMPLED. POWER OF TWO.
#define DEPTH_RING_SLOTS 512

struct depth_slot {
	u64 epoch;
	u32 ticks;
	u32 own;                // SUM OF THIS CPU'S SEAT DEPTH OVER ticks
	u32 lane;               // SUM OF ITS LANE'S DEPTH OVER ticks
	u32 loc;                // SUM OF ITS LOCAL DSQ'S DEPTH OVER ticks
	u32 runs;               // TASKS THAT STARTED RUNNING HERE IN THE BUCKET
	u32 wakes;              // OF THOSE, THE RUNS THAT ENDED A WAKE: ARRIVALS
	u32 wait_us;            // SUM OF THE QUEUE WAITS THOSE RUNS ENDED, IN US:
	                        // THE QUEUE CLOCK, INSERT (OR WAKE) TO RUNNING
	u32 idle;               // OF THE WAKES, THOSE select_cpu SEATED ON AN IDLE
	                        // CPU: nr_idle_hits, PER BUCKET
	u32 min_wait_us;        // THE SHORTEST QUEUE WAIT THOSE RUNS ENDED, IN US:
	                        // CoDel's STANDING-QUEUE TEST. MEANINGFUL WHEN runs > 0
	u32 _pad;
};

struct depth_ring {
	u32 domain;
	u32 _pad;
	struct depth_slot slot[DEPTH_RING_SLOTS];
};

// PER-CPU FLOW ROW. running() COUNTS, ON THE CPU THE TASK NOW RUNS ON, WHERE
// EACH ARRIVAL CAME FROM: wake[s] FOR A WAKE WHOSE WAKER RAN ON CPU s, mig[s]
// FOR A RUN WHOSE PREVIOUS RUN WAS ON CPU s, ANOTHER CPU. CUMULATIVE AND
// WRAPPING; THE LOOP TAKES PER-TICK DELTAS. CPU d's ROW IS THE FLOW GRAPH'S
// EDGES INTO d.
struct flow_row {
	u32 wake[MAX_CPUS];
	u32 mig[MAX_CPUS];
};

// PER-CPU REFILL LEDGER. stopping() APPENDS ONE RECORD PER RUN THAT ENDED A
// CLASSED WAKE (running(): FROM ANOTHER CPU, NOT FROM THE IDLE TASK, NOT A
// KTHREAD's): (pid << 1 | crossed) << 32 | service_ns, crossed WHEN THE WAKER's
// CPU SITS IN ANOTHER DOMAIN (L3), THE SERVICE SATURATED AT u32. head COUNTS
// EVERY APPEND AND WRAPS; THE NEWEST RECORD IS rec[(head - 1) % REFILL_RING_SLOTS].
// POWER OF TWO.
#define REFILL_RING_SLOTS 1024

struct refill_ring {
	u32 head;
	u32 _pad;
	u64 rec[REFILL_RING_SLOTS];
};

// XDOM PATH INDICES FOR pandemonium_stats.nr_cross_domain[] (DIAGNOSTIC).
// THE INDICES ARE POSITIONAL IN ARCHIVED PROM LABELS: NEVER RENUMBER. 5 (THE
// TIER 2 SPILL, NEVER COUNTED) AND 7 (THE OVERFLOW'S CROSS-DOMAIN TAKE) ARE
// RETIRED, AND THEIR SLOTS STAY ZERO.
#define XDOM_SEL_TIGHT   0   // select_cpu sync pipe-partner co-location
#define XDOM_SEL_SYNC    1   // select_cpu WAKE_SYNC phi_warm_target
#define XDOM_SEL_NORMAL  2   // select_cpu normal_path phi_warm_target
#define XDOM_SEL_DFL     3   // select_cpu scx_bpf_select_cpu_dfl idle pick
#define XDOM_ENQ_T1      4   // enqueue TIER 1 idle (pick_idle_cpu_node)
#define XDOM_STEAL       6   // dispatch STEP 1 R_eff steal (this_cpu vs peer)

#endif // __INTF_H
