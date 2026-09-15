// PANDEMONIUM -- SCHED_EXT KERNEL SCHEDULER
// ADAPTIVE DESKTOP SCHEDULING FOR LINUX
//
// BPF: PRICED PLACEMENT + MULTI-TIER DISPATCH
// RUST: ADAPTIVE CONTROL LOOP + REAL-TIME TELEMETRY
//
// ARCHITECTURE:
//   SELECT_CPU IDLE FAST PATH -> PER-CPU DSQ (ADMISSION-BOUNDED, STEALABLE)
//   ENQUEUE TIER 1 IDLE FOUND -> THAT IDLE CPU'S PER-CPU DSQ (WARM)
//   ENQUEUE TIER 2 WARM-ANCHOR -> last_cpu PER-CPU DSQ
//   ENQUEUE TIER 3 FALLBACK    -> PER-DOMAIN OVERFLOW DSQ (SOJOURN-ORDERED)
//   DISPATCH -> OWN PER-CPU, R_eff STEAL, DOMAIN OVERFLOW, CROSS-DOMAIN, KEEP
//   TICK     -> PER-CPU SOJOURN (LOCAL + ROTATING SCAN) + PREEMPTION
//
// EVERY MOVE IS PRICED, NEVER GATED. A PRICE COMPARES ONE MEASURED QUANTITY
// AGAINST ONE THRESHOLD IN NANOSECONDS; DISTANCE ENTERS AS A FRACTION OF THE
// MACHINE'S R_eff SPAN, SO EVERY BOUND HOLDS AT EVERY TOPOLOGY.

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

// scx_bpf_task_set_slice() / scx_bpf_task_set_dsq_vtime() REPLACE DIRECT WRITES
// TO p->scx.slice / p->scx.dsq_vtime ON KERNEL 7.1+. THE WRAPPERS LIVE IN
// scx/compat.bpf.h AND PICK KFUNC-OR-DIRECT-WRITE VIA bpf_ksym_exists.
// READS OF THE SAME FIELDS ARE NOT DEPRECATED.

// CONFIGURATION (SET BY RUST VIA RODATA BEFORE LOAD)

const volatile u64 nr_cpu_ids = 1;

// BEHAVIORAL CONSTANTS

#define TRACE_SCHED 0


// PAIR LEDGER DEPTH. same_waker_runs COUNTS CONSECUTIVE WAKES FROM ONE PID.
// MIN IS HOW MANY LOOKS is_handoff_partner OWES BEFORE IT BELIEVES THE COUNT;
// CAP BOUNDS THE CREDIT A LONG-LIVED PAIR BANKS.
#define PAIR_OBS_MIN 8u
#define PAIR_OBS_CAP 16u


// RT SCHEDULING POLICIES (UAPI VALUES; NOT ALWAYS MACRO-EXPORTED VIA vmlinux.h).
#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif
#ifndef SCHED_RR
#define SCHED_RR   2
#endif

#define WEIGHT_INTERACTIVE   192   // 1.5X
#define WEIGHT_BATCH         128   // 1X

// STARVATION BOUND: THE AGE AT WHICH sweep_bound_preempt FORCES A HEAD OFF ITS
// CPU. TAU-DERIVED IN apply_tau_scaling() VIA K_LAG_CAP, CLAMPED [8MS, 80MS];
// 13.3MS AT THE 12C REFERENCE. NOT AN ORDERING BOUND -- task_deadline() RETURNS
// THE ARRIVAL STAMP AND READS NOTHING ELSE. THE VALUE BELOW IS A FALLBACK HELD
// ONLY UNTIL THE FIRST CPU-0 TICK DERIVES THE REAL ONE.
static u64 lag_cap_ns = 40000000ULL;

#define SLICE_MIN_NS 100000     // 100US FLOOR
// HOW MANY LIVE CoDel TARGETS A STANDING TASK MAY HOLD A CPU FOR. THIS IS THE
// BOUND A WAITER PAYS WHEN IT LANDS ON A BUSY CPU.
#define SLICE_STANDING_TARGETS  4ULL
// codel_starve_ns IS DERIVED FROM knobs->topology_tau_ns VIA scale_tau() AT THE
// FIRST CPU-0 TICK. THE NORMAL OVERFLOW-SERVICE THRESHOLD IS codel_target_ns
// ITSELF -- ONE THRESHOLD, ONE WRITER (THE CPU-0 TICK), NO SHADOW COPY.

// FIEDLER-SCALED TIMING CONSTANTS, Q16 DIMENSIONLESS RATIOS.
// target_ns = K_i * tau / 65536. EACH K_i IS A DIMENSIONLESS RATIO TO tau AND
// APPLIES TO EVERY TOPOLOGY UNCHANGED -- ONLY tau VARIES, 13.3MS AT THE 12C
// REFERENCE. K_LAG_CAP = 1.0 IS ONE COMMUTE TIME OF THE TOPOLOGY GRAPH.
#define K_Q16_SHIFT             16
#define K_CODEL_FLOOR             1147u   // 0.0175
#define K_STARVATION_RESCUE     273285u   // 4.17
#define K_LONGRUN              3276800u   // 50.0
#define K_CODEL_MAX               3277u   // 0.05
#define K_LAG_CAP                65536u   // 1.0
#define K_SPILL_BUDGET     80000000ULL    // TAU_SCALE_NS / 2; budget = K / tau
#define K_AFFINITY_SEARCH  40000000ULL    // TAU_SCALE_NS / 4; budget = K / tau

// OSCILLATOR DYNAMICS DERIVED FROM tau SO THE CONTROLLER RUNS ON THE SAME
// TIME CONSTANT AS THE CoDel TARGET RANGE IT MODULATES. pull_scale AND
// damping_shift ARE SMALL INTEGERS (1-4 AND 1-5 RESPECTIVELY) SO THEY USE
// DIRECT-DIVIDE RATHER THAN Q16 (Q16 LOSES PRECISION FOR SMALL-INTEGER
// OUTPUTS). velocity_cap COUPLES TO pull_scale: vcap = 50000 * pull.
#define K_OSC_PULL_THRESH_NS    10000000u  // 10MS PER pull-scale STEP
#define K_OSC_DAMP_THRESH_NS     8000000u  //  8MS PER damping-shift STEP
#define OSC_VELOCITY_CAP_PER_PULL  50000u  // vcap = OSC_VELOCITY_CAP_PER_PULL * pull


// GLOBALS

static u32 nr_nodes;
// nr_overflow_domains: NUMBER OF DISTINCT L3 cache DOMAINS IN llc_domain[]. SET BY RUST AT
// TOPOLOGY DETECT VIA write_nr_overflow_domains (.data SECTION, POST-LOAD MUTABLE). ON
// MONOLITHIC-L3 / UNSET, EQUALS nr_sockets (TYPICALLY 1) AND THE per-domain TIER
// COLLAPSES TO A SINGLE OVERFLOW DSQ -- EXACT PRIOR BEHAVIOR SHAPE.
volatile u32 nr_overflow_domains = 1;

// affinity_domain_peers: HOW MANY affinity_rank SLOTS STAY INSIDE A CPU'S OWN
// cache DOMAIN. WRITTEN BY RUST AT TOPOLOGY DETECT AS THE MINIMUM OVER CPUs,
// FLOORED AT 1, SO A BUDGET BOUNDED BY IT CANNOT LEAVE ANY CPU'S DOMAIN.
// affinity_rank IS SORTED BY R_eff ASCENDING, SO EVERY SAME-DOMAIN PEER PRECEDES
// EVERY CROSS-DOMAIN ONE AND THIS ALONE DECIDES WHETHER find_idle_by_affinity
// MAY LEAVE THE DOMAIN.
// INITIALISED TO 3, THE LEGACY CLAMP FLOOR, NOT TO ZERO. A ZERO INITIALISER
// PLACES IT IN .bss RATHER THAN .data, WHERE THE POST-LOAD WRITER CANNOT REACH.
volatile u32 affinity_domain_peers = 3;

// NO GLOBAL PREEMPT FLAG: tick() DERIVES THE DECISION PER-CPU FROM
// sojourn_stamp_pcpu[this_cpu] (OLDEST WAITER AGE) AGAINST A k*tau THRESHOLD,
// TIER-GATED ON THE RESIDENT. PER-CPU SO NO TOKEN FOR CPUs TO RACE OVER.

// OVERFLOW SOJOURN STAMP: WHEN THE DOMAIN'S OVERFLOW DSQ LAST WENT
// EMPTY -> NON-EMPTY. DISPATCH READS IT TO RESCUE TASKS AGING PAST
// codel_target_ns. ARMED BY CAS(0, now) ON TIER 3 INSERT, CLEARED ON
// DRAIN-TO-EMPTY, SO ITS AGE IS THE QUEUE'S CONTINUOUS-OCCUPANCY AGE.
// ONE STAMP PER DOMAIN, INDEXED BY dom AT EVERY ARM/CLEAR/READ: A SINGLE
// GLOBAL SCALAR LETS ONE DOMAIN'S STAMP MASK ANOTHER'S AGING. 64-BYTE
// ALIGNED SO NO TWO DOMAINS FALSE-SHARE THEIR CAS TRAFFIC.
struct sojourn_stamp_one { u64 ns; } __attribute__((aligned(64)));
static struct sojourn_stamp_one sojourn_stamp_overflow[MAX_OVERFLOW_DOMAINS];

// PER-CPU DSQ SOJOURN: TRACKS WHEN EACH PER-CPU DSQ TRANSITIONS
// FROM EMPTY. DISPATCH AND TICK CHECK THESE TO DETECT STALE TASKS.
// WORK STEALING + DEPTH GATE HANDLE MOST CASES; THIS IS THE SAFETY NET.
// CACHELINE-PADDED: ONE STAMP PER 64-BYTE LINE SO THE PER-PLACEMENT CAS AND THE
// PER-TICK CROSS-CPU SCAN DO NOT FALSE-SHARE NEIGHBOURS.
struct pcpu_stamp { u64 ns; } __attribute__((aligned(64)));
static struct pcpu_stamp sojourn_stamp_pcpu[MAX_CPUS];

// THE PER-CPU TIME LEDGER. A QUEUE'S LOAD IS TIME, NOT A TASK COUNT -- SLICES
// RUN 14.4us AT p50 AND 682us AT p99, A 47x SPREAD, SO NO SINGLE COUNT IS RIGHT
// AT BOTH ENDS.
// IT IS NOT A STAMP. A DRAIN ERASES A STAMP; A LEDGER A DRAIN CANNOT ERASE IS
// THE ENTIRE POINT.
// admitted_ns AND completed_ns ARE WRITTEN BY REMOTE WAKERS AND ARE ATOMIC. THE
// DEMAND WINDOW IS OWNER-ONLY IN stopping() AND NEEDS NO ATOMIC.
struct pcpu_ledger {
	u64 admitted_ns;      // sum of expected service charged at placement
	u64 completed_ns;     // sum refunded at dispatch/sleep/exit
	u64 demand_sum_ns;    // owner-only: observed service, this CPU
	u64 demand_cnt;       // owner-only: sample count
} __attribute__((aligned(64)));
static struct pcpu_ledger pcpu_ledger[MAX_CPUS];

// A LEDGER THAT FORGETS, NOT AN EWMA. BOTH ACCUMULATORS HALVE AT DEMAND_WINDOW
// SO THE MEAN TRACKS A WORKLOAD CHANGE WITH NO POLE AND NO HIDDEN STATE.
#define DEMAND_WINDOW      4096ULL
#define DEMAND_FALLBACK_NS 50000ULL   // 50us until a CPU has seen anything

static __always_inline u64 pcpu_demand_ns(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return DEMAND_FALLBACK_NS;
	u64 c = pcpu_ledger[cpu].demand_cnt;
	if (!c)
		return DEMAND_FALLBACK_NS;
	return pcpu_ledger[cpu].demand_sum_ns / c;
}

// WHAT IS OWED ON THIS SEAT, IN NANOSECONDS. ONE INDEXED ARRAY LOAD, NO REMOTE
// DSQ-OBJECT TOUCH.
static __always_inline u64 backlog_ns(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return 0;
	u64 a = pcpu_ledger[cpu].admitted_ns;
	u64 d = pcpu_ledger[cpu].completed_ns;
	return a > d ? a - d : 0;   // the floor absorbs a late refund after hotplug
}

static u64 codel_starve_ns;

// REENQUEUE RATE-LIMIT. cpu_release CALLS scx_bpf_reenqueue_local() ON EVERY RT
// PREEMPTION. A PER-CPU LEAKY TIME-BUDGET CAPS THE RATE: CREDIT ACCRUES WITH
// ELAPSED TIME AND IS SPENT PER REENQUEUE, SO SPARSE PREEMPTION REENQUEUES
// FREELY AND ONLY A SUSTAINED FLOOD THROTTLES. A BRIEF PREEMPTION LEAVES LOCAL
// TASKS HOME; THE REMOTE SOJOURN SCAN AND STEAL RESCUE A GENUINELY LONG HOLD.
// A PRICE ON THE ACT, NOT A GATE -- PLACEMENT IS UNTOUCHED.
// THE TWO CONSTANTS ARE ABSOLUTE WHERE EVERYTHING ELSE HERE SCALES FROM tau.
#define REENQ_MIN_INTERVAL_NS  1000000ULL  // >= 1ms between reenqueues / CPU
#define REENQ_BURST_NS         2000000ULL  // SHORT BURST BEFORE THROTTLING
static u64 reenq_credit[MAX_CPUS];
static u64 reenq_last[MAX_CPUS];
// THE PLACEMENT BASE COST: WHAT ANY MIGRATION COSTS IN L1 RESIDENCY, WHATEVER
// THE DISTANCE. 0.0005 OF tau, CLAMPED [5us, 100us].
#define K_PHI_BASE_Q16   33ULL          // 0.0005 in Q16
#define PHI_BASE_MIN_NS  5000ULL
#define PHI_BASE_MAX_NS  100000ULL
static u64 phi_base_cost_ns = 20000ULL;   // init fallback until tau lands

// PAIR-WARM SEAT MARKER -- THE STEAL-SIDE HALF OF TIGHT-PAIR COLOCATION.
// THE SEAT SITES STAMP THE PARTNER'S PER-CPU SEAT HERE; STEP 1'S STEAL READS IT
// IN ONE INDEXED LOOKUP, NO REMOTE task_ctx DEREF, AND PRICES THE SPLIT BY THE
// domain_phi SEAM. A PRICE, NOT A GATE -- A STARVING TASK IS STILL STOLEN AT A
// LONGER SOJOURN.
static u64 pair_warm_ns[MAX_CPUS];

// TAU-DERIVED LONGRUN PREEMPT BOOST. SET IN apply_tau_scaling() AS A
// STEP FUNCTION ON tau (SHIFT 2 WHEN tau < 4MS, ELSE 0). USED BY tick()
// TO LET BATCH RUNNERS HOLD A THIN-TOPOLOGY CPU LONGER UNDER SUSTAINED
// PRESSURE.
static u32 longrun_preempt_shift;

// CODEL STALL DETECTION WITH OSCILLATOR-ADAPTED TARGET
// BINARY FLOWING/STALLED DECISION (CoDel): IF MIN SOJOURN STAYS ABOVE THE
// TARGET FOR AN INTERVAL, THE DSQ IS DECLARED STALLED AND RESCUE FIRES.
// THE TARGET ITSELF FOLLOWS THE FULL DAMPED HARMONIC OSCILLATOR EQUATION:
//   ẍ + 2γẋ + ω₀²(x - c_eq) = F(t)
// F(t):    RESCUE-DRIVEN NEGATIVE IMPULSE (DETECT STALLS SOONER)
// 2γẋ:    DAMPING (BIT-SHIFT VELOCITY DECAY)
// ω₀²x:   SPRING (RESTORING TOWARD R_eff EQUILIBRIUM c_eq)
// CRITICALLY DAMPED: γ = ω₀ -> spring_shift = 2*damping_shift + 2.
// ALL OSCILLATOR PARAMETERS (DAMPING, SPRING, PULL SCALE, VELOCITY CAP,
// EQUILIBRIUM, TARGET FLOOR/MAX) ARE TAU-DERIVED AT init() AND
// RE-DERIVED ON HOTPLUG VIA apply_tau_scaling().
// REFERENCE: VAN JACOBSON CoDel (RFC 8289) + DAMPED HARMONIC OSCILLATOR.
#define OSCILLATOR_PULL_NS  8000     // BASE TIGHTEN IMPULSE

// CORE-SCALED CONSTANTS (SET ONCE IN init())
static u32 oscillator_damping_shift;      // VELOCITY DECAY SHIFT (2γ TERM)
static u32 oscillator_spring_shift;       // SPRING RESTORE SHIFT (ω₀² TERM).
                                          // SET TO 2*damping_shift + 2 IN
                                          // apply_tau_scaling() -- DISCRETE
                                          // EQUIVALENT OF γ = ω₀ (CRITICAL
                                          // DAMPING). NO OVERSHOOT, FASTEST
                                          // STABLE RETURN TO EQUILIBRIUM.
static u32 oscillator_pull_scale;         // RESCUE IMPULSE MULTIPLIER
static s64 oscillator_velocity_cap;       // VELOCITY CLAMP
// EXPOSED TO USERSPACE (NON-STATIC) SO MWU CAN READ OSCILLATOR STATE
// AND GATE ITS PATHWAYS ON WHAT BPF HAS ALREADY DECIDED. WITHOUT THIS,
// MWU AND THE OSCILLATOR INDEPENDENTLY ADAPT ON global_rescue_count
// AND DOUBLE-CORRECT.
u64 codel_target_floor_ns;         // CORE-SCALED FLOOR FOR TARGET
// ADAPTIVE STATE
u64 codel_target_ns;          // ADAPTIVE CENTER (EXPOSED FOR MWU)
static s64 oscillator_velocity_ns;        // DAMPED OSCILLATION VELOCITY
static u64 prev_rescue_snapshot;       // LAST-SEEN RESCUE COUNT
static u64 global_rescue_count;        // ATOMIC CROSS-CPU RESCUE ACCUMULATOR

// OSCILLATOR ENVELOPE: A DECAYED ENERGY RESERVOIR DRIVING THE OSCILLATOR'S OWN
// RECOMPUTE CADENCE. FULL EVERY-TICK WHEN HOT, A GRADED BAND BELOW THE RELEASE
// THRESHOLD, A TRUE PARK BELOW THE PARK THRESHOLD -- ZERO ARITHMETIC, TARGET
// PINNED AT ITS CLOSED-FORM FIXED POINT. CPU-0 TICK IS THE SINGLE WRITER;
// DISPATCH READS codel_target_ns WITH NO KNOWLEDGE THE ENVELOPE EXISTS.
#define OSC_ENV_DECAY_SHIFT     3    // RESERVOIR DECAY: env -= env >> 3 PER UPDATE
#define OSC_ENV_GRADED_DIV      4    // GRADED BAND: RECOMPUTE EVERY 4TH TICK
#define OSC_ENV_HEARTBEAT_TICKS 1024 // MAX-PARK SAFETY VALVE (~1s @ 1kHz, ~4s @ 250Hz)
static u64 osc_env_energy;           // DECAYED disp^2 + v^2 RESERVOIR
static u32 osc_env_skip;             // GRADED-BAND CADENCE DIVIDER
static bool osc_env_parked;          // OSCILLATOR PARKED AT EQUILIBRIUM
                                     // (bool, NOT u32: LLVM GlobalOpt SHRINKS A
                                     // 0/1-ONLY INTERNAL GLOBAL TO 1 BYTE WHILE
                                     // BTF KEEPS THE 4-BYTE TYPE -- THE KERNEL
                                     // REJECTS THE .bss DATASEC SIZE MISMATCH)
static u64 osc_env_park_ticks;       // TICKS SPENT PARKED (HEARTBEAT CAP)

// THE SINGLE UN-PARK OWNER. CALLED FROM THE CPU-0 TICK (RESCUE EDGE) AND FROM
// pandemonium_runnable (WAKE EDGE). RE-PRIMES THE RESERVOIR ABOVE RELEASE SO A
// BURSTY WAKE CANNOT IMMEDIATELY RE-PARK, AND RESETS THE GRADED-BAND DIVIDER
// AND HEARTBEAT. DOES NOT TOUCH oscillator_velocity_ns OR codel_target_ns --
// THE INTEGRATOR STAYS SINGLE-WRITER ON CPU 0.
static __always_inline void osc_env_unpark(void)
{
	u64 env_floor = (1ULL << (2 * oscillator_damping_shift)) +
			(1ULL << (2 * oscillator_spring_shift));
	u64 env_release = env_floor << (OSC_ENV_DECAY_SHIFT + 2);
	osc_env_parked = false;
	osc_env_park_ticks = 0;
	osc_env_skip = 0;
	osc_env_energy = env_release << 1;
}

// LONGRUN DETECTION
// TRACKS SUSTAINED OVERFLOW PRESSURE. WHEN THE DOMAIN'S OVERFLOW DSQ STAYS
// NON-EMPTY FOR > longrun_thresh_ns, task_slice() SUBSTITUTES burst_slice_ns
// AS THE BASE GRANT FOR EVERY TASK AND tick() WIDENS THE PREEMPT BAND.
// CLEARS WHEN THE OVERFLOW DSQ EMPTIES.
// longrun_thresh_ns AND codel_target_max_ns ARE RUNTIME STATICS SO
// THEY CAN BE REDERIVED FROM knobs->topology_tau_ns. INITIAL VALUES
// (2s, 2ms) ARE THE PRE-TAU FALLBACK USED FOR THE ~1MS WINDOW BEFORE
// THE FIRST TICK; apply_tau_scaling() OVERWRITES IMMEDIATELY.
static u64 longrun_thresh_ns = 2000000000ULL;
u64 codel_target_max_ns = 2000000ULL;             // EXPOSED FOR MWU
static bool longrun_mode;

// TAU-SCALING: SNAPSHOT OF LAST knobs->topology_tau_ns APPLIED.
// TICK() ON CPU 0 COMPARES AGAINST THE CURRENT KNOB VALUE; IF CHANGED,
// ALL TAU-DERIVED STATICS ARE REDERIVED. ZERO MEANS RUST HAS NOT YET
// WRITTEN tau (PRE-FIRST-TICK FALLBACK CONSTANTS REMAIN IN EFFECT).
static u64 last_tau_snapshot;

// R_eff-DERIVED CODEL EQUILIBRIUM TARGET. SET FROM knobs->codel_eq_ns IN
// apply_tau_scaling() (CO-LOCATED WITH tau, SAME WRITE TRIGGER). DRIVES
// THE OSCILLATOR'S SPRING (RESTORING TERM) -- WITHOUT IT THE OSCILLATOR
// HAS NO EQUILIBRIUM AND CAN ACCUMULATE OPEN-LOOP DRIFT.
// FALLBACK 2MS UNTIL RUST WRITES; SAME ORDER AS codel_target_max_ns.
static u64 codel_seed_ns = 2000000ULL;

// PHI MIGRATION POTENTIAL: THE DISTANCE PENALTY b*R_eff IS PRE-FOLDED INTO THE
// reff_value MAP IN NS BY RUST AT TOPOLOGY DETECT, SO STEP 1 READS IT DIRECTLY.
// NO BPF-SIDE SCALE GLOBAL, NO PER-TICK MIRROR, NO PER-STEAL MULTIPLY.

// USER EXIT

UEI_DEFINE(uei);

// MAPS

struct {
	// PER-CPU KNOBS. max_entries STAYS 1 -- EACH CPU GETS ITS OWN COPY OF THAT
	// ONE ENTRY, SO bpf_map_lookup_elem WITH key 0 RETURNS THIS CPU'S SLOT AND
	// NO CROSS-CPU ACCESS EXISTS.
	// topology_tau_ns, codel_eq_ns AND affinity_mode MUST HOLD THE SAME VALUE ON
	// EVERY CPU OR TAU-SCALING AND PLACEMENT DIVERGE BY WHICHEVER CPU OBSERVED.
	// Scheduler::write_tuning_knobs_percpu ENFORCES THAT.
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tuning_knobs);
} tuning_knobs_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct pandemonium_stats);
} stats_map SEC(".maps");

// CACHE DOMAIN MAP: l2_domain[cpu] = group_id
// POPULATED BY RUST AT STARTUP FROM SYSFS TOPOLOGY
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cache_domain SEC(".maps");

// EMERGENT OVERFLOW-DOMAIN MAP: cpu_domain[cpu] = DOMAIN ID FROM THE
// MIN-CONDUCTANCE TREE, PARTITIONED AT L3 GRANULARITY. THE OVERFLOW DSQs ARE
// KEYED BY IT, SO DISPATCH DRAINS ITS OWN DOMAIN THEN CLIMBS THE TREE.
// POPULATED BY RUST AT TOPOLOGY DETECT; READ BY cpu_domain_of().
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cpu_domain SEC(".maps");

// L2 SIBLINGS MAP: FLAT ARRAY FOR L2-AWARE CPU PLACEMENT
// l2_siblings[group_id * MAX_L2_SIBLINGS + slot] = cpu_id
// SENTINEL: (u32)-1 MARKS END OF GROUP
// POPULATED BY RUST AT STARTUP FROM CpuTopology
#define MAX_L2_SIBLINGS 8

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	// ONE SLOT PER L2 GROUP ON ANY TOPOLOGY. THE RUST WRITER INDEXES
	// group_id * MAX_L2_SIBLINGS + slot, SO A SMALLER MAP OVERFLOWS AND
	// ABORTS INIT ON PARTS WITH MANY PHYSICAL CORES.
	__uint(max_entries, MAX_CPUS * MAX_L2_SIBLINGS);
	__type(key, u32);
	__type(value, u32);
} l2_siblings SEC(".maps");

// RESISTANCE AFFINITY MAP: PER-CPU RANKED PLACEMENT TARGETS
// affinity_rank[cpu * MAX_AFFINITY_CANDIDATES + slot] = target_cpu
// SORTED BY ASCENDING EFFECTIVE RESISTANCE (LAPLACIAN PSEUDOINVERSE).
// SLOT 0 = CHEAPEST MIGRATION TARGET (TYPICALLY L2 SIBLING).
// POPULATED BY RUST AT STARTUP FROM EXACT R_EFF COMPUTATION.
// SENTINEL: (u32)-1 MARKS END OF VALID ENTRIES.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS * MAX_AFFINITY_CANDIDATES);
	__type(key, u32);
	__type(value, u32);
} affinity_rank SEC(".maps");

// PHI STEAL PENALTY, PRE-FOLDED IN NS. PAIRS 1:1 WITH affinity_rank -- THE RANK
// GIVES WHICH CPU, THIS GIVES ITS STEAL DELAY.
// reff_value[cpu * MAX_AFFINITY_CANDIDATES + slot] = (R_eff(cpu, target) * b) >> 16
// WHERE b = phi_dist_scale_q16, FOLDED BY RUST AT TOPOLOGY DETECT. THE STEAL
// READS IT DIRECTLY AS dist_extra -- NO RUNTIME MULTIPLY.
// ALL-ZERO ON MONOLITHIC OR --phi-scale 0, GIVING A FLAT codel_target.
// SENTINEL (u32)-1 = SLOT PAST THE TOPOLOGY END, TREATED AS 0 PENALTY.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS * MAX_AFFINITY_CANDIDATES);
	__type(key, u32);
	__type(value, u32);
} reff_value SEC(".maps");


// EMERGENT-DOMAIN CROSSING PRICE. PAIRS 1:1 WITH affinity_rank.
// domain_phi[cpu * MAX_AFFINITY_CANDIDATES + slot] = phi * 1e6 OF THE LOWEST
// COMMON-ANCESTOR CUT SEPARATING cpu FROM THAT SLOT'S TARGET, TAKEN FROM THE
// MIN-CONDUCTANCE DOMAIN TREE. A LOW phi IS A LOOSE SEAM (SOCKET OR CROSS-L3,
// FAR); A HIGH phi IS A TIGHT SEAM (NEAR).
// SENTINEL (u32)-1 = SAME LEAF, AND ALSO SLOTS PAST THE TOPOLOGY END.
// THIS IS THE CONTINUOUS REPLACEMENT FOR A SAME/DIFFERENT-DOMAIN TEST.
// POPULATED BY RUST AT TOPOLOGY DETECT.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS * MAX_AFFINITY_CANDIDATES);
	__type(key, u32);
	__type(value, u32);
} domain_phi SEC(".maps");

// R_eff AS A PURE FRACTION OF THE MACHINE'S SPAN, Q16. PAIRS 1:1 WITH
// affinity_rank. 0 = ADJACENT (SMT SIBLING), 65536 = THE MOST DISTANT PAIR ON
// THIS MACHINE, (u32)-1 = UNUSED SLOT. POPULATED BY RUST AT TOPOLOGY DETECT.
// THE SAME R_eff SHAPE AS reff_value WITH NO TIME UNIT ON IT. reff_value FOLDS
// AGAINST tau FOR THE STEAL; THE WAKE-PATH SITES COMPARE AGAINST ONE
// codel_target AND A backlog_ns QUANTISED AT ONE pcpu_demand_ns, TWO ORDERS
// SMALLER, SO THEY MULTIPLY THIS FRACTION BY THEIR OWN YARDSTICK INSTEAD.
// DIMENSIONLESS IS WHAT MAKES IT TOPOLOGY-INVARIANT: THE FRACTION STAYS IN
// [0,1] WHEN SLOT 0 CHANGES RUNG, SO EVERY PRICE BUILT ON IT STAYS BOUNDED.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS * MAX_AFFINITY_CANDIDATES);
	__type(key, u32);
	__type(value, u32);
} reff_frac SEC(".maps");

// STEP 1 SCAN RATE-LIMIT: per-CPU timestamp of the last R_eff steal scan.
// PERCPU SO IT IS THIS-CPU-LOCAL -- NO CROSS-CPU COHERENCE TRAFFIC. THE PEER
// WALK (affinity_rank + PER-PEER nr_queued) IS THE DOMINANT PER-DISPATCH CACHE
// COST UNDER WAKE-HEAVY LOADS; GATING IT TO ONE SCAN PER codel_target COLLAPSES
// THAT COST WITHOUT MISSING STEALABLE WORK (BACKLOG CAN'T AGE PAST THE STEAL
// THRESHOLD FASTER THAN THE THRESHOLD ITSELF).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} last_spill_scan SEC(".maps");

// WAKEUP LATENCY HISTOGRAM: 3 TIERS x 12 BUCKETS = 36 ENTRIES PER CPU
// BPF INCREMENTS IN running(); RUST READS ONCE PER SECOND IN MONITOR LOOP
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 36);
	__type(key, u32);
	__type(value, u64);
} wake_lat_hist SEC(".maps");

// SLEEP DURATION HISTOGRAM: 4 BUCKETS PER CPU
// BPF INCREMENTS IN running(); RUST READS ONCE PER SECOND
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, u64);
} sleep_hist SEC(".maps");

// PER-TASK CONTEXT

struct task_ctx {
	u64 last_woke_at;
	u64 cached_weight;
	u64 sleep_start_ns;  // SET IN quiescent(), USED IN running()
	u64 wait_since;      // WHEN THIS QUEUE WAIT BEGAN; 0 = NOT WAITING. STAMPED ON
	                     // THE FIRST INSERT AFTER A RUN, PRESERVED ACROSS REQUEUES,
	                     // CLEARED IN running() AND quiescent(). THE SOJOURN BASE.
	u64 run_exec_at;     // p->se.sum_exec_runtime AT running(). THE SERVICE LEDGER'S
	                     // BASE: stopping() DIFFS IT FOR TIME THE TASK ACTUALLY RAN,
	                     // WHICH IS ELAPSED MINUS THE IRQ TIME INSIDE THE WINDOW.
	u64 charge_ns;       // WHAT THIS TASK OWES ITS SEAT, 0 = NOT CHARGED. PAIRED
	                     // WITH charge_cpu SO A REFUND REACHES THE SEAT THAT WAS
	                     // DEBITED, EVEN AFTER THE TASK HAS MOVED.
	s32 charge_cpu;
	u32 standing_runs;   // CONSECUTIVE RUNS THAT CONSUMED A FULL codel_target_ns.
	                     // A SERVICE LEDGER, NOT AN ESTIMATOR: IT RECORDS WHAT WAS
	                     // RENDERED, NEVER GUESSES WHAT THE TASK IS. MAINTAINED IN
	                     // stopping(); RESET BY ANY SHORT RUN.
	s32 last_waker_pid;  // PID OF THE TASK THAT MOST RECENTLY WOKE THIS ONE.
	                     // KEYED ON IDENTITY, NOT CPU: A PID SURVIVES A
	                     // PARTNER'S MIGRATION. -1 = NONE SEEN YET.
	u32 same_waker_runs; // CONSECUTIVE WAKES FROM last_waker_pid, SATURATING. A
	                     // LEDGER OF WHAT HAPPENED, NOT A RATE -- THE SAME SHAPE
	                     // AS standing_runs. RESET BY A WAKE FROM ANOTHER PID.
	s32 last_cpu;        // LAST CPU THIS TASK RAN ON (FOR CACHE AFFINITY)
	s32 home_cpu;        // STABLE PLACEMENT HOME: PINNED TO THE FIRST CPU THE
	                     // TASK RAN ON; NEVER CHASES last_cpu. WARM-STAY ANCHOR
	                     // SO THE TASK RETURNS HOME INSTEAD OF DRIFTING. THE
	                     // RESTORING FORCE -- SEE THE ANCHOR IN warm_seat_pick.
	u8  dispatch_path;   // 0=IDLE, 1=HARD_KICK, 2=SOFT_KICK
	u8  ran_since_wake;  // is_wakeup = !ran_since_wake; SET 1 IN running(), 0 ON WAKE
	u8  _pad[2];
};

static __always_inline void ledger_refund(struct task_ctx *tctx)
{
	if (!tctx || !tctx->charge_ns)
		return;
	u32 c = (u32)tctx->charge_cpu;
	if (c < MAX_CPUS)
		__sync_fetch_and_add(&pcpu_ledger[c].completed_ns, tctx->charge_ns);
	tctx->charge_ns = 0;
	tctx->charge_cpu = -1;
}

// REFUND BEFORE CHARGING, SO A REQUEUE MOVES THE DEBIT RATHER THAN DOUBLING IT.
static __always_inline void ledger_charge(struct task_ctx *tctx, u32 cpu)
{
	if (!tctx || cpu >= MAX_CPUS)
		return;
	ledger_refund(tctx);
	u64 d = pcpu_demand_ns(cpu);
	__sync_fetch_and_add(&pcpu_ledger[cpu].admitted_ns, d);
	tctx->charge_ns = d;
	tctx->charge_cpu = (s32)cpu;
}


struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

// HELPERS

// PER-DOMAIN OVERFLOW DSQ IDs. LAYOUT:
//   [0, nr_cpu_ids)                             PER-CPU DSQs
//   [nr_cpu_ids + 2*MAX_NODES, ...)             PER-DOMAIN OVERFLOW
// THE 2*MAX_NODES GAP RESERVES IDs EARLIER PER-NODE TIERS USED, SO THE OFFSET IS
// HARDWARE-INDEPENDENT AT COMPILE TIME. DSQs ARE CREATED ONCE AT INIT FROM A
// FIXED MAP; THE RUNTIME nr_overflow_domains GATES WHICH ARE ADDRESSED.
static __always_inline u64 domain_inter_dsq(u32 dom)
{
	dom &= (MAX_OVERFLOW_DOMAINS - 1);   // NEVER INDEX PAST THE CREATED RANGE
	return nr_cpu_ids + 2ULL * MAX_NODES + (u64)dom;
}

// THE OVERFLOW DSQ RANGE MUST FIT THE RESERVED ID GAP AND NOT COLLIDE WITH THE
// PER-CPU DSQs AT [0, nr_cpu_ids). THE MASK ABOVE AND THIS ASSERT GUARANTEE IT.
_Static_assert(MAX_OVERFLOW_DOMAINS <= 2 * MAX_NODES,
	       "per-domain overflow DSQ ranges must fit the reserved id gap");

// THE OVERFLOW DOMAIN OF A CPU: THE EMERGENT DOMAIN FROM THE MIN-CONDUCTANCE
// TREE IN cpu_domain, NOT A DISCRETE llc_domain. THE PARTITION TARGETS L3
// GRANULARITY, SO ON A REAL PART THE TWO AGREE AND THE BOUNDARY IS DRAWN BY THE
// CONDUCTANCE LANDSCAPE RATHER THAN A HARDCODED TABLE. EVERY OVERFLOW SITE
// RE-KEYS HERE.
static __always_inline u32 cpu_domain_of(s32 cpu)
{
	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return 0;
	u32 key = (u32)cpu;
	u32 *cd = bpf_map_lookup_elem(&cpu_domain, &key);
	u32 dom = cd ? *cd : 0;
	// NEVER RETURN A DOMAIN BEYOND THE CREATED OVERFLOW-DSQ RANGE. THIS GUARDS
	// A STALE MAP VALUE OR A POST-DETECT HOTPLUG FROM INDEXING AN UNCREATED DSQ.
	return dom < MAX_OVERFLOW_DOMAINS ? dom : 0;
}

// CROSS-DOMAIN SCATTER BUMP. COUNTS A CROSS-DOMAIN LANDING ON PATH `idx` (XDOM_*)
// WHEN THE TASK'S HOME CPU AND THE CHOSEN CPU SIT IN DIFFERENT cache domains.
// last_home < 0 (NO PRIOR CPU) IS NOT A MIGRATION. FREE-COMPUTE: ONE cpu_domain_of
// COMPARE ON AN ALREADY-TAKEN PLACEMENT BRANCH. CONSUMED BY THE ADAPTIVE MWU
// SCATTER PATHWAY AND SURFACED PER-RUN BY THE BENCH SUITE.
static __always_inline void cross_domain_bump(struct pandemonium_stats *s, u32 idx,
				      s32 last_home, s32 dst)
{
	if (!s || idx >= 8 || last_home < 0)
		return;
	if (cpu_domain_of(last_home) != cpu_domain_of(dst))
		s->nr_cross_domain[idx] += 1;
}

static __always_inline struct pandemonium_stats *get_stats(void)
{
	u32 zero = 0;
	return bpf_map_lookup_elem(&stats_map, &zero);
}

static __always_inline struct tuning_knobs *get_knobs(void)
{
	u32 zero = 0;
	return bpf_map_lookup_elem(&tuning_knobs_map, &zero);
}

static __always_inline struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

static __always_inline struct task_ctx *ensure_task_ctx(struct task_struct *p)
{
	struct task_ctx zero = {};
	return bpf_task_storage_get(&task_ctx_stor, p, &zero,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

// L2 CACHE AFFINITY INSTRUMENTATION
// COMPARE SELECTED CPU'S L2 DOMAIN WITH TASK'S LAST_CPU DOMAIN.
// INCREMENT PER-TIER HIT/MISS COUNTERS. CALLED FROM select_cpu() AND enqueue().

static __always_inline void count_l2_affinity(struct pandemonium_stats *s,
					       const struct task_ctx *tctx,
					       s32 cpu, bool wq)
{
	u32 lcpu = (u32)tctx->last_cpu;
	u32 ncpu = (u32)cpu;
	u32 *ld = bpf_map_lookup_elem(&cache_domain, &lcpu);
	u32 *nd = bpf_map_lookup_elem(&cache_domain, &ncpu);
	bool hit = ld && nd && *ld == *nd;

	// TWO LANES, KEYED ON PF_WQ_WORKER DIRECTLY -- KWORKER VERSUS USERSPACE.
	// THE COUNTERS KEEP THEIR EXPORTED NAMES BECAUSE THE RUST SIDE READS THEM.
	if (wq) {
		if (hit) s->nr_l2_hit_interactive += 1;
		else     s->nr_l2_miss_interactive += 1;
	} else {
		if (hit) s->nr_l2_hit_batch += 1;
		else     s->nr_l2_miss_batch += 1;
	}
}

// RESISTANCE AFFINITY: IDLE CPU SEARCH BY EFFECTIVE RESISTANCE.
// WALKS THE R_eff-RANKED LIST FROM THE LAPLACIAN PSEUDOINVERSE. SLOT 0 IS THE
// CHEAPEST TARGET, SLOTS 1+ ASCEND. NO DEPTH GATE, NO DISPATCH, PURE SEARCH.
// REFERENCE: KYNG ET AL. EFFECTIVE RESISTANCE (STOC 2011, FOCS 2022)

// AFFINITY IDLE-SEARCH BUDGET, IN ONLINE CANDIDATES CHECKED RATHER THAN SLOTS
// WALKED -- THE EXPENSIVE OP IS scx_bpf_test_and_clear_cpu_idle, AND AN OFFLINE
// ENTRY SKIPS WITHOUT CHARGING.
//   budget = K_AFFINITY_SEARCH / tau = lambda_2 / 4
// HALF THE SPILL BUDGET'S DIVISOR BECAUSE THE PREDICATE COSTS MORE. 3 AT 12C,
// 8 AT 32C, SATURATING AT MAX_AFFINITY_CANDIDATES. SET IN apply_tau_scaling().
static u32 affinity_search_online = 3;

// RETURNS THE NEAREST IDLE CPU IN R_eff ORDER, OR -1 IF NONE IS IDLE WITHIN
// BUDGET. DECIDES ONLY *WHICH* IDLE, NEVER WHETHER TO MOVE.
// out_frac RECEIVES THAT CPU'S reff_frac (Q16), 0 WHEN THE ANCHOR ITSELF IS
// TAKEN SINCE THAT IS NOT A MOVE. THE CALLER PRICES THE anchor -> target EDGE
// WITH IT.
static __always_inline s32 find_idle_by_affinity(s32 src_cpu,
						 const struct cpumask *allowed,
						 u64 *out_frac)
{
	if (out_frac)
		*out_frac = 0;
	if (src_cpu < 0 || (u32)src_cpu >= nr_cpu_ids)
		return -1;

	// THE ANCHOR IS THE FIRST CANDIDATE AND IS TESTED EXPLICITLY. affinity_rank
	// IS BUILT WITH `c != cpu` IN topology.rs build_affinity_rank, SO src_cpu IS
	// NOT IN ITS OWN RANK AND THE WALK BELOW CANNOT RETURN IT. SLOT 0 IS THE SMT
	// SIBLING, NOT SELF.
	// AN IDLE PEER CANNOT START THE TASK SOONER THAN AN IDLE ANCHOR AND COSTS AN
	// L2 RELOAD OF ~4,500 LLC REFERENCES, SO THE ANCHOR WINS WHEN BOTH ARE IDLE.
	if ((!allowed || bpf_cpumask_test_cpu(src_cpu, allowed)) &&
	    scx_bpf_test_and_clear_cpu_idle(src_cpu))
		return src_cpu;

	u32 base = (u32)src_cpu * MAX_AFFINITY_CANDIDATES;
	u32 checked = 0;
	for (int i = 0; i < MAX_AFFINITY_CANDIDATES; i++) {
		u32 key = base + (u32)i;
		u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
		// SENTINEL OR MISSING -> END OF LIST, STOP.
		if (!val || *val == (u32)-1)
			break;
		// OFFLINE CPU POST-HOTPLUG -> SKIP WITHOUT COSTING BUDGET.
		// affinity_rank IS BUILT AT INIT FROM THE FULL TOPOLOGY;
		// HOTPLUG DOESN'T REBUILD IT.
		if (*val >= nr_cpu_ids)
			continue;
		if (allowed && !bpf_cpumask_test_cpu((s32)*val, allowed))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle((s32)*val)) {
			if (out_frac) {
				u32 *fp = bpf_map_lookup_elem(&reff_frac, &key);
				*out_frac = (fp && *fp != (u32)-1) ? (u64)*fp : 0;
			}
			return (s32)*val;
		}
		// BUDGET IS ONLINE CANDIDATES, NOT SLOTS WALKED.
		if (++checked >= affinity_search_online)
			break;
	}

	return -1;
}

// PHI PLACEMENT TARGET. NEVER RETURNS A BUSY CPU:
//   ANCHOR IDLE      -> TAKE IT, WARM AND IMMEDIATE
//   ELSE NEAREST IDLE-> find_idle_by_affinity WALKS R_eff ORDER, SO A
//                       SAME-DOMAIN IDLE PRECEDES A CROSS-DOMAIN ONE
//   NOTHING IDLE     -> -1, AND select_cpu FALLS THROUGH TO dfl -> enqueue,
//                       WHICH PLACES BUSY-CORE WAKEUPS WITH SCX_KICK_PREEMPT
// A BUSY PLACEMENT FROM THIS PATH WOULD ISSUE SCX_KICK_IDLE, A NO-OP ON A BUSY
// CPU, AND STRAND THE WAKEE UNTIL THE RESIDENT YIELDED.
static __always_inline s32 phi_warm_target(s32 anchor,
					   const struct cpumask *allowed,
					   u64 *out_frac)
{
	return find_idle_by_affinity(anchor, allowed, out_frac);
}

// PRICES THE anchor -> target EDGE. TRUE MEANS STAY ON THE WARM ANCHOR.
//   STAY COSTS  sojourn_stamp_pcpu[anchor] AGE -- WHAT THE WAKEE WOULD WAIT
//   MOVE COSTS  phi_base_cost_ns + (dist_frac_q16 * codel_target_ns >> 16)
// A SIBLING PRICES ~0 EXTRA AND THE MOST DISTANT PAIR ON THE MACHINE PRICES ONE
// FULL TARGET, SO THE MOVE COST IS BOUNDED AT EVERY TOPOLOGY.
// AN AGE, NOT A DEPTH. backlog_ns REDUCES TO depth x pcpu_demand_ns, QUANTISED
// AT ONE 12-50us ADMISSION, OVER A SLICE POPULATION THAT SPREADS 47x BETWEEN
// p50 AND p99. THE STAMP AGE IS THE WAIT ITSELF, TO THE NANOSECOND.
// ZERO BACKLOG STAYS WITHOUT READING THE AGE. pandemonium_exit_task REFUNDS THE
// CHARGE BUT NEVER RUNS pcpu_stamp_heal, SO A DYING TASK LEAVES BACKLOG AT 0
// WITH THE STAMP ARMED AND STALE. NOTHING QUEUED MEANS THE ANCHOR IS WARM AND
// FREE, SO THE STAY IS RIGHT WITHOUT PRICING AN ORPHANED WAIT.
// REFUSING HERE SEATS ON THE ANCHOR VIA pick_pcpu_dsq_with_spill, WHICH KICKS
// SCX_KICK_PREEMPT. REFUSING INSIDE find_idle_by_affinity WOULD INSTEAD FALL
// THROUGH TO THE TOPOLOGY-BLIND scx_bpf_select_cpu_dfl.
static __always_inline bool anchor_stay_beats_move(s32 anchor, s32 target,
						   u64 dist_frac_q16)
{
	if (anchor < 0 || (u32)anchor >= MAX_CPUS || target == anchor)
		return false;

	// NOTHING OWED ON THE ANCHOR: WARM AND FREE, AND ANY STAMP IS AN ORPHAN.
	// STAY WITHOUT READING AN AGE THAT HAS NO OWNER.
	if (backlog_ns((u32)anchor) == 0)
		return true;

	u64 stamp = sojourn_stamp_pcpu[(u32)anchor & (MAX_CPUS - 1)].ns;
	if (!stamp)
		return true;
	u64 now = bpf_ktime_get_ns();
	u64 anchor_wait = (now > stamp) ? (now - stamp) : 0;

	u64 move_cost = phi_base_cost_ns +
			((dist_frac_q16 * codel_target_ns) >> 16);
	return anchor_wait < move_cost;
}

// WARM-STAY GATE. RETURNS THE ANCHOR TO HOLD THE WAKEE ON WHILE THAT ANCHOR IS
// UNCONGESTED, OR -1 WHEN THE CALLER SHOULD IDLE-SEEK.
// CONGESTION IS THE ANCHOR'S OWN SOJOURN -- now MINUS ITS EMPTY->NONEMPTY STAMP,
// THE SAME SIGNAL STEP 1's STEAL READS -- AGAINST codel_target_ns PLUS THE
// ANCHOR'S SLOT-0 DISTANCE. SO A WAKEE STAYS WARM RIGHT UP TO THE SOJOURN AT
// WHICH THE STEAL WOULD HAVE RELOCATED IT ANYWAY.
// THE CALLER MUST ROUTE A HELD WAKEE THROUGH A PREEMPT-KICKED PLACEMENT, NEVER
// select_cpu's IDLE FAST PATH -- SCX_KICK_IDLE ON A BUSY ANCHOR IS A NO-OP AND
// STRANDS THE WAKEE. select_cpu THEREFORE ONLY DEFERS HERE.
// EXCLUDES NON-WAKEUPS THAT ARE NOT HANDOFF PARTNERS, AND KTHREADS. THE ANCHOR
// MUST BE VALID AND IN THE WAKEE'S ALLOWED MASK.
// NOT GATED ON affinity_mode: STICKINESS IS MIGRATION RESISTANCE, NOT AN
// ADAPTIVE-ONLY FEATURE, SO IT ENGAGES IN BPF-ONLY MODE TOO.

// IPC HANDOFF DISCRIMINATOR: TRUE WHEN ONE PID HAS WOKEN THIS TASK PAIR_OBS_MIN
// TIMES CONSECUTIVELY. USED TO FAST-PATH A REQUEUE, WHERE is_wakeup IS FALSE AND
// THE BASELINE MAKES THE TASK WAIT A TICK. WAKES ALREADY FAST-PATH ON is_wakeup.
// THE POPULATION ARMS GRADUALLY -- AT LOAD TIME NOBODY QUALIFIES AND EACH TASK
// EARNS IT BY DEMONSTRATING THE RELATIONSHIP.
// IT IS NOT KWORKER-ONLY AND CARRIES NO TIER TEST. ON AN IPC PING-PONG
// POPULATION IT IS TRUE OF NEARLY EVERYONE NEARLY ALWAYS, SO SIZE EVERY CALLER
// AS IF THE WHOLE WORKLOAD QUALIFIES.
static __always_inline bool is_handoff_partner(const struct task_ctx *tctx)
{
	if (!tctx)
		return false;
	return tctx->same_waker_runs >= PAIR_OBS_MIN;
}

// THE REQUEUE PREEMPT'S PRICE, ONE DEFINITION FOR EVERY TIER.
// A WAKEUP TAKES SCX_KICK_PREEMPT UNCONDITIONALLY -- IT IS THE LATENCY PATH AND
// CARRIES NO ACCRUED WAIT. A REQUEUE BUYS THE PREEMPT WITH WHAT IT IS OWED:
// wait_since IS STAMPED ON THE FIRST INSERT AFTER A RUN AND PRESERVED ACROSS
// REQUEUES, SO A TASK PASSED OVER N TIMES KEEPS ITS ORIGINAL CLAIM AND RISES AS
// THE CLOCK MOVES.
// THE THRESHOLD IS codel_target_ns + THE TARGET'S SLOT-0 R_eff PENALTY, WHICH IS
// WHAT STEP 1's phi_thresh AND warm_seat_pick's STAY BOUND ALSO RELEASE AT. THE
// STAY AND THE STEAL MUST RELEASE TOGETHER OR THEY FIGHT.
// `floor` IS WHAT A REFUSED REQUEUE GETS AND IS PER SITE. THE LADDER IS
// SCX_KICK_IDLE < 0 < SCX_KICK_PREEMPT -- kick_cpu(cpu, 0) LANDS IN cpus_to_kick
// AND QUEUES AN IPI UNCONDITIONALLY, WHILE SCX_KICK_IDLE MAY BE DROPPED BY
// can_skip_idle_kick(). TIER 3 PASSES 0; THE REST PASS SCX_KICK_IDLE.
// THIS BOUNDS WHEN THE PREEMPT FIRES, NEVER WHETHER.
// KICK_NONE IS THE BOTTOM RUNG AND IT IS SILENCE -- THE ABSENCE OF THE CALL,
// DISTINCT FROM FLAG 0, WHICH IS ITSELF A VALID KICK.
#define KICK_NONE ((u64)-1)

static __always_inline u64 requeue_kick_flag(const struct task_ctx *tctx,
					     s32 target, bool is_wakeup,
					     u64 floor)
{
	if (target < 0 || (u64)target >= nr_cpu_ids)
		return floor;
	// AN IDLE SEAT HAS NO RESIDENT TO DISLODGE. Ask the seat, not the task.
	if (!__COMPAT_scx_bpf_cpu_curr(target))
		return floor;
	if (is_wakeup)
		return SCX_KICK_PREEMPT;
	u32 rbase = (u32)target * MAX_AFFINITY_CANDIDATES;
	u32 *rdx = bpf_map_lookup_elem(&reff_value, &rbase);
	u32 rd = rdx ? *rdx : 0;
	u64 near_extra = (rd == (u32)-1) ? 0 : (u64)rd;
	u64 rnow = bpf_ktime_get_ns();
	u64 claimed = (tctx && tctx->wait_since && rnow > tctx->wait_since)
		    ? rnow - tctx->wait_since : 0;
	if (claimed >= codel_target_ns + near_extra)
		return SCX_KICK_PREEMPT;
	// SILENCE IS SAFE FOR A SELF-TARGET AND A BET FOR A PEER. THE PER-CPU DSQ IS
	// A VTIME DSQ KEYED ON wait_since, SO THE REQUEUE ALREADY SITS WHERE IT
	// EARNED AND THE KICK CANNOT IMPROVE THE CHOICE -- ONLY WHETHER ANYONE COMES
	// TO READ THE QUEUE. WE ARE INSIDE enqueue ON THIS CPU AND IT RETURNS INTO
	// THE SCHEDULER, SO THIS CPU REACHES dispatch() ON ITS OWN. A PEER HAS NO
	// SUCH GUARANTEE, AND REFUSING ONE PARKS A RUNNABLE TASK UNTIL THAT CPU
	// DISPATCHES FOR REASONS OF ITS OWN.
	if (target == (s32)bpf_get_smp_processor_id())
		return KICK_NONE;
	return floor;
}

static __always_inline s32 warm_seat_pick(struct task_struct *p,
					    struct task_ctx *tctx,
					    struct tuning_knobs *knobs,
					    bool is_wakeup, u64 now)
{
	// ADMIT A WAKE, OR A REQUEUED HANDOFF PARTNER, TO THE WARM PER-CPU SEAT.
	// EVERYTHING ELSE STAYS ON BASELINE.
	if (!tctx || (!is_wakeup && !is_handoff_partner(tctx)))
		return -1;
	if (!knobs)
		return -1;
	if (p->flags & PF_KTHREAD)
		return -1;
	// A WAKEUP AND A REQUEUE WANT DIFFERENT ANCHORS.
	// A WAKEUP HAS NO SEAT AND IS BEING PLACED REGARDLESS, SO IT ANCHORS ON THE
	// PINNED home_cpu -- A PULL TOWARD A FIXED POINT IS SELF-LIMITING, BECAUSE
	// ONCE THE TASK IS HOME NO FURTHER PULL FIRES. last_cpu IS REWRITTEN EVERY
	// stopping() AND HAS NO RESTORING FORCE AT ALL.
	// A REQUEUE ALREADY HAS A SEAT. IT WAS PASSED OVER, NOT DISPLACED, SO SENDING
	// IT TO WHICHEVER CPU IT FIRST RAN ON IS PURE ADDED MOVEMENT. IT ANCHORS ON
	// last_cpu.
	// EITHER ARM FALLS BACK TO THE OTHER FIELD WHEN ITS OWN IS UNSET.
	s32 lc = is_wakeup ? ((tctx->home_cpu >= 0) ? tctx->home_cpu : tctx->last_cpu)
			   : ((tctx->last_cpu >= 0) ? tctx->last_cpu : tctx->home_cpu);
	if (lc < 0 || (u32)lc >= nr_cpu_ids)
		return -1;
	if (!bpf_cpumask_test_cpu(lc, p->cpus_ptr))
		return -1;
	// THE HOME'S OWN OCCUPANCY AGE. pcpu_stamp_heal HOLDS stamp != 0 EXACTLY
	// WHILE THE HOME HAS A QUEUE, SO sojourn == 0 IS AN EMPTY HOME AND sojourn > 0
	// IS HOW LONG THAT QUEUE HAS STOOD.
	// AN ORPHAN READS STALE-OLD. A TASK REMOVED BY exit, OR BY A setaffinity
	// DEQUEUE THAT BYPASSES dispatch(), NEVER RUNS pcpu_stamp_heal, SO ITS STAMP
	// STAYS ARMED OVER AN EMPTY DSQ. THAT ERRS TOWARD RELEASING, WHICH IS THE SAFE
	// DIRECTION FOR A HOME THAT JUST HAD A TASK DIE ON IT.
	u64 stamp = sojourn_stamp_pcpu[(u32)lc & (MAX_CPUS - 1)].ns;
	u64 sojourn = (stamp && now > stamp) ? (now - stamp) : 0;
	// PHI-PRICED STAY. THE STAY AND THE STEP-1 STEAL MUST RELEASE AT THE SAME
	// THRESHOLD OR THEY FIGHT, SO THE HOLD READS THE HOME'S OWN SLOT-0 DISTANCE --
	// ITS NEAREST PEER, THE CHEAPEST RELIEF TARGET. BELOW THE THRESHOLD THE TASK
	// STAYS, BECAUSE RELIEF WOULD BE A CHEAP NEAR MOVE; ABOVE IT THE TASK IS
	// RELEASED TO IDLE-SEEK, BECAUSE IT WAS ABOUT TO BE STOLEN ANYWAY AND MAY AS
	// WELL BE PLACED WELL. A NEAR HOME RELEASES QUICKLY, A FAR HOME HOLDS HARD.
	// THE HOLD IS A FRACTION OF A TARGET, NOT OF tau. reff_frac IS BOUNDED [0,1]
	// BY CONSTRUCTION, SO THIS RELEASES BETWEEN ONE AND TWO TARGETS AT EVERY
	// TOPOLOGY AND DOES NOT DEPEND ON WHICH RUNG SLOT 0 LANDED ON.
	// A SENTINEL FRACTION HOLDS NOTHING EXTRA, COLLAPSING TO BARE codel_target_ns.
	u32 base0 = (u32)lc * MAX_AFFINITY_CANDIDATES;
	u32 *fp = bpf_map_lookup_elem(&reff_frac, &base0);
	u32 fr = fp ? *fp : 0;
	u64 home_hold = (fr == (u32)-1) ? 0
					: (((u64)fr * codel_target_ns) >> 16);
	if (sojourn > codel_target_ns + home_hold)
		return -1;        // home aged past its Phi threshold: idle-seek
	return lc;                // within Phi tolerance: stay warm
}

// SPILL SEARCH BUDGET, IN RANK SLOTS. THE SPILL WALKS THE SAME R_eff-RANKED
// LIST AS find_idle_by_affinity WITH "HAS ROOM" AS THE PREDICATE INSTEAD OF
// "IS IDLE", ROUTING OVERFLOW INTO A SIBLING PER-CPU DSQ (REACHED AT DISPATCH
// STEP 0 OR STEP 1) RATHER THAN domain_inter_dsq (REACHED ONLY AT STEP 3).
//   budget = K_SPILL_BUDGET / tau_ns = lambda_2 / 2
// 6 AT 12C, 16 AT 32C. CLAMPED [6, MAX_AFFINITY_CANDIDATES]. SET IN
// apply_tau_scaling().
static u32 pcpu_spill_search_budget = 6;

// CEILING ON THE keep_own DEPTH BYPASS: TWICE THE ADMISSION BOUND, READ LIVE OFF
// THE OSCILLATOR RATHER THAN FOLDED FROM A tau SNAPSHOT. keep_own HOLDS THE OWN
// SEAT ONLY WHILE STEP 0 CAN STILL PLAUSIBLY REACH THE PARTNER; PAST THIS THE
// PARTNER SPILLS LIKE ANYTHING ELSE.
static __always_inline u64 keep_own_bound_ns(void)
{
	return codel_target_ns << 1;
}


// STATIC SCAN CEILING FOR THE SPILL HELPER ONLY. THE RUNTIME BUDGET ABOVE IS
// SMALL (6 AT 12C, 16 AT 32C), SO THE COMPILE-TIME BOUND IS PURE VERIFIER DEPTH.
// 32 COVERS EVERY REALISTIC TOPOLOGY -- NO SPILL WANTS THE 33RD-NEAREST SEAT --
// AND KEEPS THE INLINED select_cpu UNDER THE INSTRUCTION BUDGET. THE STEAL-SIDE
// LOOPS KEEP THE FULL 128.
#define PCPU_SPILL_SCAN_MAX 32
// RETURNS THE NEAREST PEER THAT WOULD ADMIT A TASK BY ITS OWN ADMISSION RULE
// WITH THE BASE COST AS MARGIN, backlog_ns(peer) + phi_base_cost_ns <
// codel_target_ns, ELSE -1. THE SAME BOUND pick_pcpu_dsq_with_spill APPLIES TO
// src_cpu ONE CALL EARLIER, ASKED OF THE PEER.
// THE TEST IS ABSOLUTE, NOT SOURCE-RELATIVE. UNDER SATURATION "EMPTIER THAN ME"
// IS A COIN FLIP BETWEEN TWO LOADED CPUs AND THE COST MARGIN TIPS IT AGAINST
// MOVING, SO THE SEARCH RUNS CONSTANTLY AND FAILS CONSTANTLY.
// THE COST IS THE HYSTERESIS. THE SEARCH IS ONLY REACHED WHEN src_cpu HAS
// ALREADY FAILED THIS BOUND, SO A MOVE NEEDS THE SOURCE ABOVE THE TARGET AND THE
// PEER A FULL COST BELOW IT -- A GAP, NOT A TIE. THAT PRICES HOW OFTEN A TASK
// MIGRATES, NOT HOW FAR.
// DISTANCE IS THE WALK ORDER, NOT A TERM IN THE COST. affinity_rank IS SORTED BY
// R_eff, SO THE FIRST PEER TO PASS IS THE NEAREST PEER THAT PASSES.
static __always_inline s32 find_spill_seat(s32 src_cpu,
					     const struct cpumask *allowed)
{
	if (src_cpu < 0 || (u32)src_cpu >= nr_cpu_ids)
		return -1;

	s32 best_cpu = -1;
	u32 base = (u32)src_cpu * MAX_AFFINITY_CANDIDATES;
	u32 checked = 0;

	for (int i = 0; i < PCPU_SPILL_SCAN_MAX; i++) {
		u32 key = base + (u32)i;
		u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
		if (!val || *val == (u32)-1)
			break;
		u32 peer = *val;
		if (peer >= nr_cpu_ids)
			continue;
		if (allowed && !bpf_cpumask_test_cpu((s32)peer, allowed))
			continue;

		u64 cost = backlog_ns(peer) + phi_base_cost_ns;
		if (cost < codel_target_ns) {
			// FIRST WINNER, NOT GLOBAL MINIMUM. THE WALK IS
			// DISTANCE-ORDERED, SO THE FIRST PEER TO PASS IS THE NEAREST
			// ONE THAT DOES. CONTINUING WOULD TRADE A NEAR SEAT FOR A
			// MARGINALLY EMPTIER DISTANT ONE.
			best_cpu = (s32)peer;
			break;
		}
		if (++checked >= pcpu_spill_search_budget)
			break;
	}
	return best_cpu;
}

// PICK A DSQ FOR WAKE-SYNC OR INITIAL ENQUEUE WITH SIBLING-SPILL FALLBACK.
// THREE-LEVEL PRIORITY:
//   1. src_cpu's PER-CPU DSQ IF ITS BACKLOG IS UNDER ONE LIVE TARGET AND IN allowed.
//   2. R_EFF-RANKED SIBLING PER-CPU DSQ WITH ROOM AND IN allowed.
//      DISPATCH REACHES THESE AT STEP 0 (OWN) OR STEP 1 (L2 STEAL).
//   3. LAST RESORT: domain_inter_dsq FOR src_cpu's DOMAIN, DRAINED BY ANY CORE
//      IN THAT DOMAIN AT STEP 3 OR CROSS-DOMAIN AT STEP 5, WITH THE HARD
//      STARVATION RESCUE BOUNDING THE WAIT. ALSO THE ESCAPE VALVE WHEN allowed
//      EXCLUDES src_cpu AND EVERY R_eff SIBLING, WHICH IS WHAT PREVENTS
//      PER-CPU DSQ AFFINITY-STRANDING WHEN cpus_ptr CHANGES MID-FLIGHT.
// *out_cpu RECEIVES THE CPU SCX SHOULD WAKE (THE PER-CPU DSQ OWNER WE
// LANDED IN; src_cpu IF WE FELL BACK TO domain_inter_dsq).
static __always_inline u64 pick_pcpu_dsq_with_spill(s32 src_cpu,
						    const struct cpumask *allowed,
						    bool keep_own,
					    s32 *out_cpu)
{
	u64 now = bpf_ktime_get_ns();
	bool src_ok = (u64)src_cpu < nr_cpu_ids &&
		      (!allowed || bpf_cpumask_test_cpu(src_cpu, allowed));
	// WHAT THIS SEAT OWES, IN NS. ONE INDEXED LOAD, NO REMOTE DSQ-OBJECT TOUCH.
	// BOTH THE ADMISSION TEST AND THE keep_own CEILING READ IT.
	u64 src_backlog = src_ok ? backlog_ns((u32)src_cpu) : 0;

	// PAIR-WARM MARKER: STAMP src_cpu WHEN A HANDOFF PARTNER SEATS ON ITS OWN
	// WARM CORE, SO THE STEP-1 STEAL CAN PRICE SPLITTING THE PAIR WITHOUT A
	// REMOTE task_ctx DEREF. THE STAMP FOLLOWS THE BOUNDED DECISION -- PAST THE
	// CEILING THE PARTNER SPILLS AND IS NOT SEATED HERE.
	if (keep_own && src_ok && src_backlog < keep_own_bound_ns() &&
	    (u32)src_cpu < MAX_CPUS)
		pair_warm_ns[(u32)src_cpu & (MAX_CPUS - 1)] = now;

	// ADMISSION. A SEAT ADMITS ONLY WHILE ITS BACKLOG IS UNDER ONE LIVE TARGET,
	// SO THE WAIT A TASK INHERITS ON ARRIVAL IS BOUNDED BY ONE TARGET PLUS THE
	// SINGLE DEMAND THAT MAY OVERSHOOT IT. THE LATENCY GUARANTEE IS STRUCTURAL
	// HERE RATHER THAN ARITHMETIC IN THE SORT KEY -- SEE task_deadline().
	if (src_ok && src_backlog < codel_target_ns) {
		if ((u32)src_cpu < MAX_CPUS)
			__sync_val_compare_and_swap(
				&sojourn_stamp_pcpu[(u32)src_cpu].ns,
				0, now);
		*out_cpu = src_cpu;
		return (u64)src_cpu;
	}

	// EVERY WAKEE PAST ADMISSION FALLS THROUGH TO find_spill_seat AND THEN TO THE
	// OVER-BACKLOG OWN SEAT, BOTH OF WHICH NAME A SPECIFIC CPU. ROUTING TO
	// domain_inter_dsq INSTEAD WHILE KICKING ONLY src_cpu WOULD DECOUPLE PLACEMENT
	// FROM DRAIN, SINCE THE KICKED CPU NEED NOT WIN THE DRAIN RACE. THESE
	// BRANCHES PRESERVE KICK == DRAIN IDENTITY AND ARM NO OVERFLOW STAMP.

	// HANDOFF PARTNER (keep_own): A IS ABOUT TO BLOCK AND FREE src_cpu WITHIN
	// MICROSECONDS, SO THE POST-BLOCK STEP 0 ON src_cpu DRAINS B NEXT. SKIP THE
	// SIBLING SPILL -- A SPILL STRANDS B ON A PER-CPU DSQ THAT src_cpu's STEP 0
	// NEVER LOOKS AT, REACHABLE ONLY BY THE RATE-LIMITED STEP 1 STEAL OR THE TICK.
	// BOUNDED BY keep_own_bound_ns(): PAST THE CEILING THE PARTNER SPILLS LIKE
	// ANYTHING ELSE, SO THIS IS NOT AN UNCAPPED DEPTH BYPASS.
	bool hold_own = keep_own && src_backlog < keep_own_bound_ns();
	s32 spill = hold_own ? -1 : find_spill_seat(src_cpu, allowed);
	if (spill >= 0) {
		if ((u32)spill < MAX_CPUS)
			__sync_val_compare_and_swap(
				&sojourn_stamp_pcpu[(u32)spill].ns,
				0, now);
		*out_cpu = spill;
		return (u64)spill;
	}

	// NO ROOM ON A NEAR SIBLING. KEEP THE WAKEE ON ITS OWN WARM CORE OVER-BACKLOG
	// RATHER THAN SCATTERING TO domain_inter_dsq. THE DEEP PER-CPU QUEUE IS
	// BOUNDED BY THE CoDel SOJOURN STEAL, SO IT STAYS L1/L2-WARM.
	if (src_ok) {
		if ((u32)src_cpu < MAX_CPUS)
			__sync_val_compare_and_swap(
				&sojourn_stamp_pcpu[(u32)src_cpu].ns,
				0, now);
		*out_cpu = src_cpu;
		return (u64)src_cpu;
	}

	// AFFINITY-STRANDED ESCAPE: src_cpu IS NOT IN allowed. ROUTE TO ITS DOMAIN'S
	// OVERFLOW DSQ; IF allowed EXCLUDES THE WHOLE DOMAIN, STEP 5's CROSS-DOMAIN
	// SCAN PICKS IT UP AS WORK CONSERVATION.
	__sync_val_compare_and_swap(
		&sojourn_stamp_overflow[cpu_domain_of(src_cpu) & (MAX_OVERFLOW_DOMAINS - 1)].ns,
		0, now);
	*out_cpu = src_cpu;
	return domain_inter_dsq(cpu_domain_of(src_cpu));
}

// NO ARM FUNCTION: THE PER-CPU WAITING SIGNAL IS sojourn_stamp_pcpu[cpu], STAMPED
// AT PLACEMENT; tick() READS IT DIRECTLY (SEE THE PER-CPU PREEMPT IN tick()).

// SOJOURN GATE: TRUE IF THE DOMAIN'S OVERFLOW DSQ IS WITHIN THE RESCUE WINDOW,
// SO IT IS SAFE TO RETURN FROM dispatch() AFTER A STEP 0 OR STEP 1 HIT. FALSE
// FALLS THROUGH SO STEP 2 SERVES OVERFLOW ON THIS DISPATCH TOO.
// LOAD-BEARING: WITHOUT IT EVERY CPU WITH ITS OWN WORK RETURNS AT STEP 0 AND
// NEVER VISITS STEP 2, SO UNDER SUSTAINED LOAD THE OVERFLOW DSQ AGES ALL THE WAY
// TO codel_starve_ns AND STARVES WORKQUEUE WORKERS.
static __always_inline bool sojourn_gate_pass(u64 now, u32 dom)
{
	u32 cx = dom & (MAX_OVERFLOW_DOMAINS - 1);
	u64 e = sojourn_stamp_overflow[cx].ns;
	return e == 0 || (now - e) <= codel_target_ns;
}

// DRAIN-CLEAR TOCTOU TAIL. BETWEEN A DRAINER'S nr_queued == 0 CHECK AND ITS
// CLEAR-CAS, A CONCURRENT ENQUEUE'S ARM-CAS (0 -> now) LOSES TO THE STILL-ARMED
// OLD STAMP AND NO-OPS; THE CLEAR THEN ZEROES THE STAMP OVER A QUEUED TASK AND
// HIDES THAT DSQ FROM EVERY STAMP-READING RESCUE UNTIL IT DRAINS ON ITS OWN.
// CLEAR, THEN RE-CHECK THE QUEUE AND RE-ARM IF A TASK ARRIVED IN THE WINDOW.
static __always_inline void stamp_clear_or_rearm(u64 dsq, u64 *stamp)
{
	u64 old = *stamp;
	if (old > 0)
		__sync_val_compare_and_swap(stamp, old, 0);
	if (scx_bpf_dsq_nr_queued(dsq) != 0)
		__sync_val_compare_and_swap(stamp, 0, bpf_ktime_get_ns());
}

// DRAIN ONE TASK FROM AN OVERFLOW DSQ; CLEAR ITS EMPTY->NONEMPTY STAMP WHEN
// THE DSQ EMPTIES. RETURNS TRUE IF A TASK MOVED. THE SINGLE PRIMITIVE BEHIND
// try_service_aged_overflow AND DISPATCH STEP 3/4 -- ONE move_to_local +
// CAS-CLEAR, FACTORED OUT OF SIX OPEN-CODED COPIES.
static __always_inline bool overflow_drain_clear(u64 dsq, u64 *stamp)
{
	if (!scx_bpf_dsq_move_to_local(dsq, 0))
		return false;
	if (scx_bpf_dsq_nr_queued(dsq) == 0)
		stamp_clear_or_rearm(dsq, stamp);
	return true;
}

// DOMAIN-LOCAL OVERFLOW DRAIN, BLIND. CROSS-DOMAIN WORK CONSERVATION IS A
// SEPARATE EXPLICIT LOOP IN dispatch() RATHER THAN FOLDED IN HERE: INLINING THE
// COMBINED SHAPE AT FOUR SITES PUT THE PROGRAM PAST THE VERIFIER'S INSTRUCTION
// CEILING WITH -E2BIG.
static __always_inline bool domain_overflow_drain_local(u32 my_dom, u64 *stamp)
{
	return overflow_drain_clear(domain_inter_dsq(my_dom), stamp);
}

// SELECTIVE LOCAL DRAIN: PEEK THE HEAD AND DECLINE A TASK THAT LAST RAN TOO FAR
// FROM HERE TO BE WORTH TAKING. IT STAYS QUEUED AND A NEARER CPU GETS IT.
// THE QUEUE ITSELF CARRIES THREE JOBS AND ONLY THE FIRST IS UNWANTED:
//   SCATTER            THE BLIND TAKE. THE ONE THIS DECLINES.
//   WORK CONSERVATION  ANY CPU IN THE DOMAIN CAN DRAIN IT, SO NOTHING STRANDS
//                      BEHIND A BUSY OWNER.
//   CLASS SEPARATION   BY ROUTING. WAKES TAKE A NAMED PER-CPU SEAT AT TIER 2 AND
//                      DRAIN AT STEP 0; REQUEUES TAKE THIS POOL AND DRAIN HERE,
//                      WHICH IS WHY task_deadline NEEDS NO CLASS TERM.
// scx_bpf_dsq_peek IS WEAK. WITHOUT IT price STAYS 0 AND THIS IS THE BLIND
// DRAIN -- PRIOR BEHAVIOUR EXACTLY, NOT A SILENT DEGRADATION.
static __always_inline bool domain_overflow_drain_near(u32 my_dom, s32 cpu,
						       u64 now, u64 *stamp)
{
	u64 dsq = domain_inter_dsq(my_dom);
	u64 s = *stamp;
	u64 age = (s != 0 && now >= s) ? now - s : 0;

	// THE PRICE OF TAKING A TASK THAT IS NOT MINE, IN NS. reff_frac IS R_eff AS
	// A Q16 FRACTION OF THE MACHINE'S SPAN, SO price RUNS [0, codel_target_ns]:
	// AN SMT SIBLING IS TAKEN THE MOMENT IT APPEARS AND THE MOST DISTANT PAIR
	// OWES A FULL TARGET. THE SAME FORM warm_seat_pick USES FOR ITS HOME HOLD.
	// THE CEILING COINCIDES WITH STEP 2's THRESHOLD. STEP 3 IS REACHED ONLY
	// AFTER STEP 2 DECLINED, WHICH MEANS age <= codel_target_ns, SO A HEAD
	// PRICED AT THE CEILING CAN ONLY FIRE AT age == codel_target_ns EXACTLY AND
	// IS OTHERWISE SERVED BY STEP 2's BLIND DRAIN ONE TARGET LATER.
	// THE SLOT WALK FINDS THE HEAD'S HOME IN THIS CPU'S affinity_rank. BOUNDED
	// BY MAX_AFFINITY_CANDIDATES, BROKEN EARLY ON THE SENTINEL, AND REACHED ONLY
	// AT STEP 3, SO IT IS NOT ON THE WAKE PATH. A HOME ABSENT FROM THE RANK
	// PRICES AS MOST DISTANT.
	u64 price = 0;

	if (bpf_ksym_exists(scx_bpf_dsq_peek)) {
		struct task_struct *head = scx_bpf_dsq_peek(dsq);
		if (!head)
			return false;
		u32 hcpu = (u32)scx_bpf_task_cpu(head);
		if (hcpu != (u32)cpu) {
			u32 base = (u32)cpu * MAX_AFFINITY_CANDIDATES;
			u32 fr = 65536;
			for (int i = 0; i < MAX_AFFINITY_CANDIDATES; i++) {
				u32 k = base + (u32)i;
				u32 *v = bpf_map_lookup_elem(&affinity_rank, &k);
				if (!v || *v == (u32)-1)
					break;
				if (*v != hcpu)
					continue;
				u32 *fp = bpf_map_lookup_elem(&reff_frac, &k);
				fr = (fp && *fp != (u32)-1) ? *fp : 65536;
				break;
			}
			price = ((u64)fr * codel_target_ns) >> 16;
		}
	}

	if (age >= price)
		return overflow_drain_clear(dsq, stamp);
	return false;
}

// SERVICE THE OVERFLOW QUEUE BLIND IF ITS STAMP HAS AGED PAST `thresh`. TRUE IF
// A TASK DISPATCHED. CALLED AT TWO THRESHOLDS IN dispatch(): codel_starve_ns,
// THE SAFETY NET, AND codel_target_ns, STEP 2's NORMAL PATH.
// feed_oscillator BUMPS global_rescue_count AND nr_overflow_rescue, FEEDING THE
// TICK-DRIVEN CoDel OSCILLATOR. STEP 2 SETS IT TRUE AS THE REPRESENTATIVE
// PRESSURE SIGNAL; THE SAFETY NET SETS IT FALSE, BEING A BACKSTOP ONLY.
static __always_inline bool try_service_aged_overflow(u64 now,
						        u32 my_dom,
						        u64 thresh,
						        bool feed_oscillator)
{
	u32 cx = my_dom & (MAX_OVERFLOW_DOMAINS - 1);
	u64 e = sojourn_stamp_overflow[cx].ns;
	if (!(e > 0 && now > e && (now - e) > thresh))
		return false;

	if (!domain_overflow_drain_local(my_dom, &sojourn_stamp_overflow[cx].ns))
		return false;

	struct pandemonium_stats *s = get_stats();
	if (s) {
		s->nr_dispatches += 1;
		if (feed_oscillator)
			s->nr_overflow_rescue += 1;
	}
	if (feed_oscillator)
		__sync_fetch_and_add(&global_rescue_count, 1);
	return true;
}

// TAU-SCALED TIMING CONSTANT DERIVATION.
//   tau_ns * k_q16 / 65536. WHEN tau_ns IS 0 CALLERS SKIP THIS AND
//   THE INIT FALLBACK CONSTANTS REMAIN IN EFFECT. NO DIV, NO FLOAT --
//   VERIFIER-CLEAN. THE MULTIPLY CANNOT OVERFLOW u64 FOR ANY SANE
//   (tau, k_i) PAIR. WORST CASE: tau=40e6 (TAU_CEIL_NS) * K_LONGRUN
//   (~1.0e7) = 4.0e14, COMFORTABLY INSIDE u64 (max ~1.8e19).
static __always_inline u64 scale_tau(u64 tau_ns, u64 k_q16)
{
	return (tau_ns * k_q16) >> K_Q16_SHIFT;
}

// TAU-SCALING RE-DERIVATION.
//   pandemonium_init() RUNS BEFORE RUST WRITES topology_tau_ns, SO IT
//   SETS FALLBACK MIDPOINT CONSTANTS. THE FIRST TICK ON CPU 0 CALLS
//   THIS AFTER READING KNOBS; IF tau DIFFERS FROM last_tau_snapshot,
//   EVERY TAU-SCALED STATIC IS RE-DERIVED VIA scale_tau() AND CLAMPED
//   TO ITS SAFETY RAIL. HOTPLUG FLOWS THROUGH THE SAME PATH (RUST
//   RE-WRITES tau, NEXT TICK PICKS IT UP). tau == 0 LEAVES THE
//   FALLBACK CONSTANTS IN PLACE.
static __always_inline void apply_tau_scaling(u64 tau_ns, u64 codel_eq_ns)
{
	// SHORT-CIRCUIT ON UNCHANGED OR ZERO tau. THE ZERO CASE COVERS THE
	// ~1MS WINDOW BEFORE RUST WRITES THE KNOB AFTER struct_ops ATTACH;
	// INIT-TIME MIDPOINT CONSTANTS STAND UNTIL tau ARRIVES. AFTER THAT,
	// EVERY CHANGE TO tau (HOTPLUG) RE-DERIVES THE FULL SET.
	//
	// last_tau_snapshot HAS TWO WRITERS: THIS FUNCTION (CPU 0 tick) AND
	// THE HOTPLUG CALLBACKS (ANY CPU, CLEAR-TO-ZERO). CAS THE TRANSITION
	// snap -> tau_ns SO A CONCURRENT HOTPLUG CLEAR CAN'T BE OVERWRITTEN
	// MID-RACE; IF CAS FAILS, HOTPLUG WON AND THE NEXT TICK WILL SEE
	// snap=0 AND RE-DERIVE FROM THE FRESH KNOB VALUES.
	if (tau_ns == 0)
		return;
	u64 snap = __sync_fetch_and_add(&last_tau_snapshot, 0);
	if (tau_ns == snap)
		return;
	if (!__sync_bool_compare_and_swap(&last_tau_snapshot, snap, tau_ns))
		return;

	// DERIVE EACH TIMING CONSTANT VIA k_i * tau, THEN CLAMP AS A
	// SAFETY RAIL (KILL SWITCH IF A k_i IS MISCALIBRATED).
	u64 v;

	v = scale_tau(tau_ns, K_STARVATION_RESCUE);
	if (v < 20000000ULL) v = 20000000ULL;
	if (v > 500000000ULL) v = 500000000ULL;
	codel_starve_ns = v;

	v = scale_tau(tau_ns, K_CODEL_FLOOR);
	if (v < 200000ULL) v = 200000ULL;
	if (v > 800000ULL) v = 800000ULL;
	codel_target_floor_ns = v;

	// THE BASE COST, TAU-DERIVED LIKE EVERY OTHER BOUND IN THE GATE.
	v = scale_tau(tau_ns, K_PHI_BASE_Q16);
	if (v < PHI_BASE_MIN_NS) v = PHI_BASE_MIN_NS;
	if (v > PHI_BASE_MAX_NS) v = PHI_BASE_MAX_NS;
	phi_base_cost_ns = v;

	v = scale_tau(tau_ns, K_LONGRUN);
	if (v < 500000000ULL) v = 500000000ULL;       // FLOOR 500MS
	if (v > 8000000000ULL) v = 8000000000ULL;     // CEILING 8S
	longrun_thresh_ns = v;

	v = scale_tau(tau_ns, K_CODEL_MAX);
	// NO FIXED FLOOR: A FIXED 1ms FLOOR PINS codel_target_max AT 12C
	// (0.05*13.3ms = 665us -> 1ms) AND 8C, OVERRIDING THE tau-DERIVED VALUE --
	// THE ONE FLOOR THAT ACTUALLY BINDS ON THIS BOX. FLOOR INSTEAD AT THE
	// OSCILLATOR'S OWN FLOOR SO THE WORKING WINDOW CAN NEVER INVERT (max >=
	// floor) AT DENSE TOPOLOGIES WHERE 0.05*tau WOULD DIP BELOW codel_floor,
	// WHILE LETTING THE TARGET TRACK tau ON REAL HARDWARE.
	if (v < codel_target_floor_ns) v = codel_target_floor_ns;
	if (v > 8000000ULL) v = 8000000ULL;           // CEILING 8MS (stall-blind guard)
	codel_target_max_ns = v;

	// SPECTRAL-GAP CODEL EQUILIBRIUM. RUST SETS IT AS A POSITION INSIDE
	// [K_CODEL_FLOOR, K_CODEL_MAX] * tau, WHICH IS THIS WINDOW, SO THE TWO
	// CLAMPS BELOW ARE A GUARD AND NOT THE SOURCE OF THE VALUE. ZERO MEANS
	// RUST HAS NOT YET WRITTEN -- KEEP THE FALLBACK.
	// NO ABSOLUTE LOWER BOUND ON THE ACCEPTANCE TEST. IT READ 200US TO MIRROR A
	// RUST-SIDE CLAMP FLOOR THAT IS GONE; ON A DENSE PART WHERE tau REACHES ITS
	// 1MS FLOOR A LEGITIMATE EQUILIBRIUM IS 17.5US, AND AN ABSOLUTE TEST WOULD
	// REJECT IT AND SILENTLY HOLD THE FALLBACK.
	if (codel_eq_ns > 0) {
		u64 eq = codel_eq_ns;
		if (eq < codel_target_floor_ns) eq = codel_target_floor_ns;
		if (eq > codel_target_max_ns)   eq = codel_target_max_ns;
		codel_seed_ns = eq;
	}

	// NO OVERFLOW-GATE RE-SEED HERE. THE GATE THAT OPENS OVERFLOW SERVICE
	// (sojourn_gate_pass + STEP 2) READS codel_target_ns DIRECTLY -- THE
	// LIVE TARGET THE OSCILLATOR MAINTAINS AROUND codel_seed_ns. ONE
	// THRESHOLD, ONE WRITER (THE CPU-0 TICK). A SEPARATE RESCUE MIRROR
	// WOULD MAKE THIS FUNCTION A SECOND WRITER, RE-SEEDING THE GATE TO
	// EQUILIBRIUM ON EVERY tau CHANGE (BOOT, HOTPLUG) AND SNAPPING IT OFF
	// THE LIVE TARGET FOR UP TO A FULL TICK WHENEVER THE OSCILLATOR HAS
	// DRIVEN THE TARGET AWAY -- DO NOT ADD ONE.

	// OSCILLATOR DYNAMICS: DERIVED FROM tau SO THE CONTROLLER RUNS ON THE
	// SAME TIME CONSTANT AS ITS TARGET RANGE. DIRECT-DIVIDE (NOT Q16)
	// BECAUSE pull_scale (1-4) AND damping_shift (1-5) ARE SMALL INTEGERS.
	// AT THE 12C REFERENCE (tau=13.3MS) THIS PRODUCES pull=1, damp=1. tau IS
	// LARGEST AT LOW CORE COUNT, SO 2C SITS AT THE OTHER END, pull=4, damp=5.
	u32 pull = (u32)(tau_ns / K_OSC_PULL_THRESH_NS);
	if (pull < 1) pull = 1;
	if (pull > 4) pull = 4;
	oscillator_pull_scale = pull;

	u32 damp = (u32)(tau_ns / K_OSC_DAMP_THRESH_NS);
	if (damp < 1) damp = 1;
	if (damp > 5) damp = 5;
	oscillator_damping_shift = damp;

	// SPRING SHIFT (ω₀² TERM). PRIOR VALUE 2*damp+2 IMPLEMENTED CRITICAL
	// DAMPING (γ = ω₀, ζ = 1.0). 2*damp+1 SHIFTS TO ζ = 2^(-1/2) ≈ 0.707,
	// THE BUTTERWORTH-OPTIMAL DAMPING POINT -- FLAT PASSBAND, MINIMIZES
	// SETTLING TIME + INTEGRATED ABSOLUTE ERROR TRADE-OFF, AND PRODUCES
	// ~4.3% STEP-RESPONSE OVERSHOOT PER ADAPTATION (vs 0% AT ζ = 1.0).
	// THE SMALL OVERSHOOT IS THE EXPLORATION TERM SONTAG'S LOG-RATE
	// CONVEXITY RESULT NAMES AS NECESSARY TO KEEP THE CONTROLLER'S
	// OPERATING POINT ON THE CONVEX SIDE OF ITS RESPONSE CURVE -- THE
	// OSCILLATOR PROBES THE CONVEX-RESPONSE BOUNDARY ON EACH IMPULSE
	// INSTEAD OF PARKING SAFELY INSIDE IT. DERIVED VALUES: damp=1 -> shift=3
	// (12C, FAST RESTORE), damp=5 -> shift=11 (2C, GENTLE RESTORE).
	oscillator_spring_shift = 2 * damp + 1;

	// velocity_cap PRESERVES COUPLING TO pull_scale.
	oscillator_velocity_cap = (s64)((u64)OSC_VELOCITY_CAP_PER_PULL * (u64)pull);

	// LONGRUN PREEMPT BOOST SHIFT. STEP-FUNCTION ON tau. AT tau < 4MS (2C
	// RANGE) BOOST PREEMPT THRESHOLD 4X UNDER longrun_mode SO BATCH GETS
	// MORE ROPE ON THIN TOPOLOGIES; AT HIGHER tau (4C+) NO BOOST.
	// REPLACES THE nr_cpu_ids <= 2 STEP IN tick().
	longrun_preempt_shift = (tau_ns < 4000000ULL) ? 2 : 0;

	// SPILL SEARCH BUDGET. budget = K_SPILL_BUDGET / tau = lambda_2 / 2.
	// CLAMPED TO [6, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES)]. THE
	// nr_cpu_ids - 1 RUNTIME CEILING LETS THE BUDGET COVER THE FULL
	// TOPOLOGY ON SYSTEMS WHERE THE TABLE WIDTH ALLOWS; ON SYSTEMS LARGER
	// THAN MAX_AFFINITY_CANDIDATES (= 64), THE COMPILE-TIME BOUND TAKES OVER.
	{
		u32 b = (u32)(K_SPILL_BUDGET / tau_ns);
		u32 ceil = (nr_cpu_ids > 1) ? (u32)(nr_cpu_ids - 1) : 1;
		if (ceil > MAX_AFFINITY_CANDIDATES) ceil = MAX_AFFINITY_CANDIDATES;
		if (b < 6) b = 6;
		if (b > ceil) b = ceil;
		pcpu_spill_search_budget = b;
	}

	// AFFINITY IDLE-SEARCH BUDGET. budget = K_AFFINITY_SEARCH / tau =
	// lambda_2 / 4. SMALLER DIVISOR THAN SPILL BUDGET BECAUSE THE PREDICATE
	// (test_and_clear_cpu_idle) IS MORE EXPENSIVE. CLAMPED TO
	// [min(3, affinity_domain_peers), min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES)]
	// -- SAME TOPOLOGY-AWARE CEILING AS THE SPILL BUDGET ABOVE, AND A FLOOR THAT
	// NOW KNOWS THE DOMAIN'S WIDTH. THE FULL DERIVATION IS AT
	// affinity_domain_peers; in short, the constant 3 was the only reason the
	// walk could reach a cross-domain slot on a 3-CPU domain, because K/tau is 1
	// there before clamping. Inert wherever a domain holds 3+ peers.
	{
		u32 b = (u32)(K_AFFINITY_SEARCH / tau_ns);
		u32 ceil = (nr_cpu_ids > 1) ? (u32)(nr_cpu_ids - 1) : 1;
		if (ceil > MAX_AFFINITY_CANDIDATES) ceil = MAX_AFFINITY_CANDIDATES;
		u32 lo = affinity_domain_peers < 3 ? affinity_domain_peers : 3;
		if (lo < 1) lo = 1;
		if (b < lo) b = lo;
		if (b > ceil) b = ceil;
		affinity_search_online = b;
	}

	// STARVATION BOUND, THE ONLY JOB IT HAS: lag_cap_ns = K_LAG_CAP * tau
	// (1.0 * tau, 13.3MS AT THE 12C REFERENCE), CLAMPED [8MS, 80MS].
	v = scale_tau(tau_ns, K_LAG_CAP);
	if (v < 8000000ULL)  v = 8000000ULL;
	if (v > 80000000ULL) v = 80000000ULL;
	lag_cap_ns = v;
}

// PCPU DSQ DRAIN-AND-CLEAR: SHARED BY STEP 0 AND STEP 1.
// CALLED AFTER A SUCCESSFUL scx_bpf_dsq_move_to_local((u64)cpu, 0). CLEARS THE
// PER-CPU ENQUEUE TIMESTAMP IF THE DSQ DRAINED EMPTY. CALLERS OWN
// nr_dispatches BUMPS BECAUSE THE STAT BUMP DIFFERS ACROSS SITES.
static __always_inline void pcpu_stamp_heal(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return;
	if (scx_bpf_dsq_nr_queued((u64)cpu) != 0)
		return;
	stamp_clear_or_rearm((u64)cpu, &sojourn_stamp_pcpu[cpu].ns);
}

// HEAL A STALE PER-CPU WAITER STAMP, THEN KICK ONLY IF A REAL WAITER REMAINS.
// sojourn_stamp_pcpu[cpu] IS ARMED ON PLACEMENT AND CLEARED BY pcpu_stamp_heal
// AFTER A SUCCESSFUL move_to_local. IF A QUEUED TASK IS INSTEAD REMOVED BY A
// NON-DISPATCH PATH -- TASK EXIT, OR A SETAFFINITY DEQUEUE THAT BYPASSES
// dispatch() -- THE DSQ EMPTIES BUT THE STAMP STAYS ARMED, AND NO move_to_local
// WILL EVER SUCCEED ON THE NOW-EMPTY DSQ TO CLEAR IT. THE TICK SCAN WOULD THEN
// KICK THAT IDLE CPU EVERY TICK FOREVER: A SPURIOUS-WAKEUP IDLE-POWER DRAIN, AND
// A CORRUPTED (STALE-OLD) SOJOURN FOR THE NEXT TASK THAT LANDS THERE. CONFIRM
// THE DSQ BEFORE KICKING: pcpu_stamp_heal ZEROES THE STAMP WHEN nr_queued == 0,
// SO A SURVIVED (STILL NON-ZERO) STAMP MEANS A GENUINE WAITER. RETURNS TRUE IFF
// IT KICKED. THE nr_queued PROBE RUNS ONLY ON A STAMP ALREADY AGED PAST
// THRESHOLD (THE RARE SUSPICIOUS CASE), SO THE COMMON PATH IS UNCHANGED.
static bool pcpu_kick_if_waiter(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return false;
	pcpu_stamp_heal(cpu);
	if (sojourn_stamp_pcpu[cpu].ns == 0)
		return false;
	scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	return true;
}

// HISTOGRAM BUCKETING: MATCHES HIST_EDGES_NS AND SLEEP_EDGES_NS IN RUST

static __always_inline u32 lat_bucket(u64 lat_ns)
{
	if (lat_ns <= 10000) return 0;
	if (lat_ns <= 25000) return 1;
	if (lat_ns <= 50000) return 2;
	if (lat_ns <= 100000) return 3;
	if (lat_ns <= 250000) return 4;
	if (lat_ns <= 500000) return 5;
	if (lat_ns <= 1000000) return 6;
	if (lat_ns <= 2000000) return 7;
	if (lat_ns <= 5000000) return 8;
	if (lat_ns <= 10000000) return 9;
	if (lat_ns <= 20000000) return 10;
	return 11;
}

static __always_inline u32 sleep_bucket(u64 sleep_ns)
{
	if (sleep_ns <= 1000000) return 0;
	if (sleep_ns <= 10000000) return 1;
	if (sleep_ns <= 100000000) return 2;
	return 3;
}

// TRACE: FAST 4-BYTE comm CHECK, CATCHING "pandemonium" WITH NO MAP OVERHEAD.
// THE DEFINITION IS ITSELF GATED ON TRACE_SCHED BECAUSE EVERY CALL SITE IS, AND
// CLANG WARNS -Wunused-function OTHERWISE.
#if TRACE_SCHED
static __always_inline bool is_sched_task(const struct task_struct *p)
{
	return p->comm[0] == 'p' && p->comm[1] == 'a' &&
	       p->comm[2] == 'n' && p->comm[3] == 'd';
}
#endif

// EFFECTIVE WEIGHT: NICE WEIGHT TIMES A TWO-LEVEL MULTIPLIER READ FROM
// PF_WQ_WORKER. UNITS OF 128, SO THE SHIFT DIVIDES.
static __always_inline u64 effective_weight(const struct task_struct *p,
					     const struct task_ctx *tctx)
{
	u64 weight = p->scx.weight;
	u64 behavioral;

	behavioral = (p->flags & PF_WQ_WORKER) ? WEIGHT_INTERACTIVE
					       : WEIGHT_BATCH;
	(void)tctx;

	return weight * behavioral >> 7;
}

// SCHEDULING HELPERS

// SOJOURN SELECTOR, NO VIRTUAL TIME. THE DSQ SORT KEY IS THE WAIT BASE, SO THE
// QUEUE ORDERS OLDEST-FIRST -- AT ANY FIXED DISPATCH INSTANT THE SMALLEST KEY IS
// THE LONGEST-WAITING TASK. SEE task_deadline().

// THE PAIR LEDGER: ONE CONSECUTIVE-WAKE COUNT KEYED ON THE WAKER'S PID, AND
// NOTHING ELSE. A REPEAT FROM THE SAME WAKER ADVANCES IT, ANYONE ELSE RESETS IT.
// SATURATING, SO A LONG-LIVED PAIR CANNOT BANK UNBOUNDED CREDIT.
// KEYED ON A PID RATHER THAN A CPU BIT BECAUSE A PID DOES NOT CHANGE WHEN ITS
// OWNER MIGRATES, SO THE COUNT IS NOT DEGRADED BY THE MIGRATIONS IT EXISTS TO
// DETECT. A LEDGER OF WHAT HAPPENED, THE SAME SHAPE AS standing_runs.
// is_handoff_partner IS ITS ONLY CONSUMER.
static __always_inline void update_pair_ledger(struct task_ctx *tctx,
					       s32 waker_pid)
{
	if (waker_pid > 0) {
		if (tctx->last_waker_pid == waker_pid) {
			if (tctx->same_waker_runs < PAIR_OBS_CAP)
				tctx->same_waker_runs += 1;
		} else {
			tctx->last_waker_pid = waker_pid;
			tctx->same_waker_runs = 0;
		}
	}

}

// THE SORT KEY IS THE WAIT BASE AND NOTHING ELSE -- A BARE ARRIVAL STAMP, NO
// WARP, NO SERVICE CREDIT.
// wait_since IS STAMPED ONCE ON THE FIRST INSERT AFTER A RUN, PRESERVED ACROSS
// REQUEUES, AND CLEARED IN running() AND quiescent(). A TASK PASSED OVER N TIMES
// KEEPS ITS ORIGINAL CLAIM, SO THE QUEUE IS OLDEST-FIRST AND A STARVING TASK
// RISES ON ITS OWN AS THE CLOCK MOVES UNDER A STATIONARY BASE.
// THE LATENCY BOUND IS ADMISSION'S, NOT THE ORDERING'S. A SEAT ADMITS ONLY WHILE
// ITS BACKLOG IS UNDER ONE LIVE TARGET, SO THE WAIT A TASK INHERITS ON ARRIVAL
// IS BOUNDED BY ONE TARGET PLUS THE SINGLE DEMAND THAT MAY OVERSHOOT IT. THE
// ORDERING DOES NOT HAVE TO ENFORCE WHAT ADMISSION ALREADY BOUNDS, AND A
// REORDERING CANNOT CHANGE HOW MUCH WORK A WORK-CONSERVING QUEUE COMPLETES.
static __always_inline u64 task_deadline(struct task_ctx *tctx,
					 const struct tuning_knobs *knobs)
{
	(void)knobs;
	if (!tctx->wait_since)
		tctx->wait_since = bpf_ktime_get_ns();
	return tctx->wait_since;
}

// STANDING: HAS THIS TASK CONSUMED A FULL CoDel TARGET ON EACH OF ITS LAST
// STANDING_CONFIRM RUNS? ONE MEASURED QUANTITY AGAINST THE LIVE TARGET, WITH NO
// INVENTED THRESHOLD -- THE BOUNDARY IS ONE TARGET BY CONSTRUCTION.
// THE CONFIRM DEPTH IS THE MEMORY A SINGLE RUN LACKS: A HOG THAT BLOCKS ONCE
// READS AS DRAINED ON ONE SAMPLE. A FRESH FORK CARRIES 0 AND IS NOT STANDING.
#define STANDING_CONFIRM 2u
#define STANDING_CAP     8u

static __always_inline bool is_standing(const struct task_ctx *tctx)
{
	return tctx && tctx->standing_runs >= STANDING_CONFIRM;
}

static __always_inline u64 task_slice(const struct task_ctx *tctx,
				      const struct tuning_knobs *knobs)
{
	// SLICE COMPRESSION: longrun_mode IS THE ONLY CONSUMER. SUSTAINED BATCH
	// PRESSURE SWAPS IN burst_slice_ns; EVERYTHING ELSE USES slice_ns.
	u64 base_slice = knobs ? (longrun_mode
		? knobs->burst_slice_ns : knobs->slice_ns) : 1000000;
	u64 base;

	// A TASK THAT HAS NOT STOOD ON A CPU FOR A FULL TARGET GETS THE ADAPTIVE
	// SLICE AND NOTHING FURTHER. THE PREDICATE IS THE DRAIN FACT stopping()
	// ALREADY MEASURED, PRICED IN THE GATE'S OWN UNIT.
	if (!is_standing(tctx)) {
		base = base_slice;
		if (base < SLICE_MIN_NS)
			base = SLICE_MIN_NS;
		return base;
	}

	// STANDING: DEDICATED CEILING FROM RUST ADAPTIVE LAYER.
	// WEIGHT-SCALED: HIGHER BEHAVIORAL WEIGHT = LONGER SLICE.
	u64 batch_ceil = knobs ? knobs->batch_slice_ns : 20000000;
	if (batch_ceil < SLICE_MIN_NS)
		batch_ceil = SLICE_MIN_NS;

	base = batch_ceil * tctx->cached_weight >> 7;
	if (base > batch_ceil)
		base = batch_ceil;

	// PRICED IN CoDel TARGETS, LIKE EVERY OTHER BOUND HERE. A RESIDENT MAY HOLD
	// THE CPU FOR SLICE_STANDING_TARGETS OF THE LIVE TARGET AND NO LONGER.
	// THE KNOB ALONE WOULD PUT A HARD 15.6MS QUANTUM ON THIS PATH, AND A LAUNCH
	// LANDING ON A CPU WHOSE RESIDENT WAS JUST GRANTED ONE WAITS THE WHOLE
	// THING -- A STALL THAT QUANTIZES TO THE SLICE IS NOT A TAIL.
	// THE KNOB KEEPS ITS JOB AS THE OTHER BOUND, SO THE ADAPTIVE LAYER STILL
	// LOWERS THIS AND NEVER RAISES IT.
	u64 target_bound = codel_target_ns * SLICE_STANDING_TARGETS;
	if (target_bound && base > target_bound)
		base = target_bound;

	if (base < SLICE_MIN_NS)
		base = SLICE_MIN_NS;

	return base;
}

// SCHEDULING CALLBACKS

// SELECT_CPU: FAST-PATH IDLE CPU DISPATCH TO PER-CPU DSQ
// DISPATCHES TO NAMED PER-CPU DSQ (u64)cpu -- VISIBLE TO WORK STEALING
// AND SOJOURN RESCUE. DEPTH-GATED: IF PER-CPU DSQ ALREADY HAS TASKS,
// SPILL TO domain_inter_dsq SO ANY same-domain CORE CAN GRAB IT.
// THE CPU IS IDLE SO IT ENTERS dispatch() IMMEDIATELY AND DRAINS.
s32 BPF_STRUCT_OPS(pandemonium_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;

	// WARM-STAY: IF THE WAKEE'S ANCHOR (last_cpu) IS UNCONGESTED, HOLD IT THERE
	// RATHER THAN FAN OUT TO A COLD IDLE SIBLING. select_cpu ONLY DEFERS (RETURNS
	// THE ANCHOR WITHOUT DISPATCHING) -- THE ACTUAL PLACEMENT HAPPENS IN enqueue,
	// WHICH KICKS PREEMPT (select_cpu's IDLE PATHS KICK IDLE, A NO-OP ON A BUSY
	// ANCHOR). COMPUTED ONCE; GATES THE IDLE-SEEK BELOW. THE TIGHT-PARTNER SYNC
	// COLOCATION STILL RUNS FIRST (IT'S A DELIBERATE PIPE-BUFFER LOCALITY BET).
	s32 stay_hold;
	{
		struct task_ctx *tc = lookup_task_ctx(p);
		struct tuning_knobs *kn = get_knobs();
		bool wake = tc && !tc->ran_since_wake;
		stay_hold = warm_seat_pick(p, tc, kn, wake, bpf_ktime_get_ns());
	}

	// SET WHEN THE SYNC BLOCK WALKS last_cpu's affinity_rank AND FINDS NO NEAR
	// IDLE: normal_path BELOW WOULD RE-WALK THE IDENTICAL (INIT-FIXED) RANK FOR
	// THE IDENTICAL RESULT, SO IT SKIPS. ONLY FIRES FOR SYNC WAKES WHOSE
	// prev_cpu == last_cpu; NON-SYNC WAKES LEAVE IT FALSE (normal_path WALKS ONCE).
	bool last_cpu_idle_miss = false;

	// WAKE_SYNC LOCALITY: PREFER AN IDLE CPU NEAR THE WAKEE'S WARM CORE. THIS IS
	// A LOCALITY-OPTIMIZED SPREAD -- IT PLACES ONLY WHEN AN IDLE CORE IS FOUND,
	// SO IT STAYS WARM AND WORK-CONSERVING (LOWER R_eff THAN THE ANY-IDLE PICK
	// scx_bpf_select_cpu_dfl MAKES BELOW). IF NO NEAR IDLE, FALL THROUGH TO THE
	// dfl SEARCH (ANY IDLE ANYWHERE); UNDER TRUE SATURATION THE TASK GOES TO
	// enqueue, LANDS ON A STEALABLE PER-CPU DSQ, AND THE dispatch FLOW STEAL
	// ROUTES IT BY BACKLOG AND DISTANCE.
	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_ctx *tctx = lookup_task_ctx(p);
		s32 waker_cpu = bpf_get_smp_processor_id();
		// ONE MAINTAINER FOR THE PAIR LEDGER. enqueue's update_pair_ledger
		// DOES NOT RUN WHEN select_cpu DISPATCHES, SO THIS PATH ADVANCES IT
		// THROUGH THE SAME FUNCTION.
		if (tctx)
			update_pair_ledger(tctx,
				   (s32)(bpf_get_current_pid_tgid() & 0xffffffff));
		// PIPE-PARTNER CO-LOCATION. ON A SYNC WAKE THE WAKER IS ABOUT TO BLOCK,
		// SO ITS CORE FREES IN MICROSECONDS AND WHAT IT JUST PRODUCED IS STILL
		// CACHE-HOT. FOR A DEMONSTRATED 1:1 PARTNER, SEAT THE WAKEE ON THE
		// WAKER'S OWN PER-CPU DSQ -- THE ONE PLACE WE QUEUE ON A BUSY CORE
		// INSTEAD OF FLEEING TO A COLD IDLE SIBLING -- SO THE HANDOFF COSTS A
		// LOCAL DRAIN RATHER THAN A CROSS-CPU WAKE. WITHOUT IT THE PAIR SPLITS,
		// THE WAKER'S RUNQUEUE EMPTIES, AND KEEP_RUNNING HANDS IT THE CORE FOR
		// MILLISECONDS WHILE THE PARTNER WAITS OUT A FULL CoDel TARGET.
		// THE GATE IS THE PID-KEYED PAIR LEDGER. THE POPCOUNT IT REPLACES WAS
		// MONOTONE, SO A GENUINE PAIR LOOKED LESS PAIR-LIKE THE LONGER IT RAN.
		// MULTI-DOMAIN ONLY: ON A MONOLITHIC L3 EVERY CORE SHARES THE CACHE, SO
		// THERE IS NO LOCALITY TO BUY AND THIS WOULD BE CHURN AGAINST THE HOME
		// PIN. warm_seat_pick's STABLE HOME GOVERNS THERE.
		if (nr_overflow_domains > 1 && is_handoff_partner(tctx) &&
		    (u64)waker_cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(waker_cpu, p->cpus_ptr)) {
			struct tuning_knobs *knobs = get_knobs();
			u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;
			u64 dl = tctx ? task_deadline(tctx, knobs)
				      : bpf_ktime_get_ns();
			s32 dst_cpu;
			u64 dst_dsq = pick_pcpu_dsq_with_spill(waker_cpu, p->cpus_ptr,
							       true, &dst_cpu);
			ledger_charge(tctx, (u32)dst_cpu);
			scx_bpf_dsq_insert_vtime(p, dst_dsq, sl, dl, 0);
			// THE KICK IS ASYMMETRIC AND MUST STAY THAT WAY. PREEMPT ONLY WHEN
			// THE SPILL MOVED THE SEAT OFF THE WAKER, WHERE NO IMMINENT YIELD
			// IS COMING. WHEN THE SEAT IS THE WAKER ITSELF, KICK_IDLE -- IT
			// BLOCKS IN MICROSECONDS AND ITS OWN STEP 0 TAKES THE WAKEE.
			// MAKING THIS UNCONDITIONAL WAS TRIED AND IT COLLAPSES THE BOX. A
			// 1:1 PAIR HOPS TENS OF THOUSANDS OF TIMES A SECOND, SO PREEMPTING
			// THE WAKER ON EVERY HOP IS ONE IPI PER WAKE: MEASURED H=59079
			// HARD KICKS AGAINST W=59079 WAKEUPS IN A SINGLE SECOND, AND
			// DISPATCH THROUGHPUT FELL 194665 -> 10342/s IN THE NEXT SAMPLE AND
			// NEVER RECOVERED. THE GATE IS NOT THE PROTECTION HERE -- THE PAIR
			// IS EXACTLY THE POPULATION THAT STORMS, BECAUSE IT IS THE ONE THAT
			// WAKES ITS PARTNER CONSTANTLY.
			scx_bpf_kick_cpu(dst_cpu,
				dst_cpu != waker_cpu ? SCX_KICK_PREEMPT
						     : SCX_KICK_IDLE);
			if (tctx)
				tctx->dispatch_path = 0;
			struct pandemonium_stats *s = get_stats();
			if (s) {
				s->nr_idle_hits += 1;
				s->nr_dispatches += 1;
				cross_domain_bump(s, XDOM_SEL_TIGHT,
						  tctx ? tctx->last_cpu : -1,
						  dst_cpu);
			}
			return dst_cpu;
		}
		s32 anchor = (prev_cpu >= 0 && (u64)prev_cpu < nr_cpu_ids)
			   ? prev_cpu : waker_cpu;
		// stay_hold >= 0 MEANS WARM-STAY IS PREFERRED -- SKIP THE IDLE-SEEK
		// AND LET normal_path DEFER THE WAKEE TO enqueue's PREEMPT PLACEMENT.
		if (stay_hold < 0 && (u64)anchor < nr_cpu_ids) {
			// PHI PLACEMENT: STAY ON THE WARM CORE (IDLE OR SHALLOW-BUSY)
			// RATHER THAN FLEE TO A COLD IDLE SIBLING.
			u64 tfrac = 0;
			s32 target = phi_warm_target(anchor, p->cpus_ptr, &tfrac);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				u64 sl = tctx ? task_slice(tctx, knobs)
					      : 1000000;
				s32 dst_cpu;
				// PRICE THE anchor -> target EDGE. UNDER THE COST THE
				// WAIT ON THE WARM ANCHOR IS CHEAPER THAN THE RELOAD,
				// SO SEAT THERE; THE seat != target ARM BELOW KICKS
				// SCX_KICK_PREEMPT, WHICH MAKES A BUSY SEAT SAFE.
				// HELD IN A LOCAL SO THE STATS BLOCK COUNTS THE OUTCOME
				// OFF THE `s` IT ALREADY FETCHES.
				bool cost_held = anchor_stay_beats_move(anchor, target, tfrac);
				s32 origin = cost_held ? anchor : target;
				u64 dst_dsq = pick_pcpu_dsq_with_spill(origin, p->cpus_ptr, is_handoff_partner(tctx), &dst_cpu);
				u64 dl = tctx ? task_deadline(tctx, knobs) : bpf_ktime_get_ns();
				ledger_charge(tctx, (u32)dst_cpu);
				scx_bpf_dsq_insert_vtime(p,
					dst_dsq, sl, dl, 0);
				// LOAD-BEARING. A PER-CPU DSQ INSERT NEEDS AN EXPLICIT
				// KICK OR THE WAKEE WAITS FOR THE NEXT TICK, AND
				// pick_pcpu_dsq_with_spill CAN REDIRECT dst_cpu OFF THE
				// VERIFIED-IDLE target ONTO A BUSY SEAT WHERE
				// SCX_KICK_IDLE IS A NO-OP. PREEMPT WHEN THE SEAT MOVED,
				// IDLE WHEN IT IS STILL THE IDLE PICK.
				scx_bpf_kick_cpu(dst_cpu,
					dst_cpu != target ? SCX_KICK_PREEMPT : SCX_KICK_IDLE);
				if (tctx) {
					tctx->dispatch_path = 0;
				}
				struct pandemonium_stats *s = get_stats();
				if (s) {
					if (cost_held)
						s->nr_stay_cost_held += 1;
					else
						s->nr_stay_move_taken += 1;
					s->nr_idle_hits += 1;
					s->nr_dispatches += 1;
					cross_domain_bump(s, XDOM_SEL_SYNC, tctx ? tctx->last_cpu : -1, dst_cpu);
					// A COST-HELD STAY IS NOT A SPILL. COUNT ONLY A
					// REDIRECT OFF THE ORIGIN THE SEAT SEARCH WAS
					// GIVEN, OR SPILLS STARTS REPORTING STAYS.
					if (dst_cpu != origin)
						s->nr_spill_kick_preempt += 1;
				}
				return dst_cpu;
			}
			// MISS: THE ANCHOR'S affinity_rank HAD NO NEAR IDLE. WHEN THE
			// ANCHOR IS THE WAKEE'S last_cpu, normal_path WOULD WALK THE
			// IDENTICAL FIXED RANK FOR THE IDENTICAL RESULT, SO RECORD THE
			// MISS AND SKIP IT. THE dfl PICK BELOW STILL TAKES A SIBLING
			// THAT IDLES IN THE GAP, SO NO WORK CONSERVATION IS LOST.
			if (tctx && anchor == tctx->last_cpu)
				last_cpu_idle_miss = true;
		}
	}

	// WARM-STAY DEFER: THE ANCHOR IS UNCONGESTED, SO RETURN IT WITHOUT
	// DISPATCHING AND LET p FLOW TO enqueue's PREEMPT-KICKED WARM-STAY
	// PLACEMENT INSTEAD OF ANY IDLE-SEEK BELOW.
	if (stay_hold >= 0)
		return stay_hold;

	// WARM PLACEMENT, AHEAD OF THE dfl ANY-IDLE PICK. dfl IS TOPOLOGY-BLIND AND
	// CAN SEAT THE WAKEE ON A CROSS-DOMAIN IDLE CORE WITH A COLD L3, SO ANCHOR ON
	// THE WAKEE'S OWN LAST CORE AND SEARCH R_eff-NEAR FIRST. FALLS THROUGH TO dfl
	// ONLY WHEN NOTHING WARM-NEAR IS IDLE, WHERE enqueue TIER 2 WARM-ANCHORS IT.
	{
		struct task_ctx *tctx = lookup_task_ctx(p);
		// FORK SEED: A FRESHLY FORKED THREAD HAS last_cpu = -1 FROM enable(), SO
		// IT WOULD SKIP THIS WARM PATH AND TAKE THE NODE-WIDE dfl PICK, WHICH
		// SCATTERS IT ACROSS THE DOMAIN BOUNDARY. ANCHOR A NEVER-RAN TASK ON
		// prev_cpu -- THE PARENT'S CPU AT FORK -- SO IT TAKES THE SAME PRICED
		// WARM ROUTE AN ESTABLISHED TASK TAKES. NO FORK BRANCH, NO BAIL GATE.
		s32 anchor = (tctx && tctx->last_cpu >= 0) ? tctx->last_cpu : prev_cpu;
		if (!last_cpu_idle_miss && tctx && anchor >= 0 &&
		    (u64)anchor < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(anchor, p->cpus_ptr)) {
			// PHI PLACEMENT: THE WARM CORE IF IDLE, ELSE THE NEAREST IDLE
			// PEER, WITH THE anchor -> target EDGE PRICED BELOW.
			u64 tfrac = 0;
			s32 target = phi_warm_target(anchor, p->cpus_ptr, &tfrac);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				u64 sl = task_slice(tctx, knobs);
				u64 dl = task_deadline(tctx, knobs);
				s32 seat_cpu;
				bool cost_held = anchor_stay_beats_move(anchor, target, tfrac);
				s32 origin = cost_held ? anchor : target;
				u64 seat_dsq = pick_pcpu_dsq_with_spill(origin, p->cpus_ptr, is_handoff_partner(tctx), &seat_cpu);
				ledger_charge(tctx, (u32)seat_cpu);
				scx_bpf_dsq_insert_vtime(p, seat_dsq, sl, dl, 0);
				// THE SPILL CAN SEAT OFF THE VERIFIED-IDLE target ONTO A
				// BUSY SIBLING, WHERE SCX_KICK_IDLE NO-OPS AND STRANDS
				// THE WAKEE TO THE TICK.
				scx_bpf_kick_cpu(seat_cpu,
					seat_cpu != target ? SCX_KICK_PREEMPT : SCX_KICK_IDLE);
				tctx->dispatch_path = 0;
				struct pandemonium_stats *s = get_stats();
				if (s) {
					if (cost_held)
						s->nr_stay_cost_held += 1;
					else
						s->nr_stay_move_taken += 1;
					s->nr_idle_hits += 1;
					s->nr_dispatches += 1;
					count_l2_affinity(s, tctx, seat_cpu, p->flags & PF_WQ_WORKER);
					cross_domain_bump(s, XDOM_SEL_NORMAL, anchor, seat_cpu);
					if (seat_cpu != origin)
						s->nr_spill_kick_preempt += 1;
				}
				return seat_cpu;
			}
		}
	}

	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	s32 dst_cpu = cpu;

	if (is_idle) {
		struct task_ctx *tctx = lookup_task_ctx(p);
		struct tuning_knobs *knobs = get_knobs();
		u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;

		// PER-CPU DSQ PLACEMENT WITH L2/R_EFF SPILL. CACHE-HOT IF cpu
		// HAS ROOM; SIBLING PER-CPU DSQ NEXT (REACHED BY DISPATCH STEP 0
		// ON SIBLING OR STEP 1 L2 STEAL); LAST-RESORT domain_inter_dsq.
		u64 dst_dsq = pick_pcpu_dsq_with_spill(cpu, p->cpus_ptr, is_handoff_partner(tctx), &dst_cpu);
		u64 dl = tctx ? task_deadline(tctx, knobs)
			      : bpf_ktime_get_ns();
		ledger_charge(tctx, (u32)dst_cpu);
		scx_bpf_dsq_insert_vtime(p, dst_dsq, sl, dl, 0);

		// `cpu` IS THE VERIFIED-IDLE dfl PICK. THE SPILL CAN REDIRECT dst_cpu
		// ONTO A BUSY SIBLING, WHERE SCX_KICK_IDLE NO-OPS AND STRANDS THE
		// WAKEE TO THE TICK, SO A REDIRECTED SEAT TAKES THE PREEMPT.
		scx_bpf_kick_cpu(dst_cpu,
			dst_cpu != cpu ? SCX_KICK_PREEMPT : SCX_KICK_IDLE);

		if (tctx) {
			tctx->dispatch_path = 0;
		}

		struct pandemonium_stats *s = get_stats();
		if (s) {
			s->nr_idle_hits += 1;
			s->nr_dispatches += 1;
			if (tctx)
				count_l2_affinity(s, tctx, dst_cpu, p->flags & PF_WQ_WORKER);
			cross_domain_bump(s, XDOM_SEL_DFL, tctx ? tctx->last_cpu : -1, dst_cpu);
			if (dst_cpu != cpu)
				s->nr_spill_kick_preempt += 1;
		}

#if TRACE_SCHED
		if (is_sched_task(p))
			bpf_printk("PAND: select_cpu pid=%d cpu=%d", p->pid, dst_cpu);
#endif
	}

	return dst_cpu;
}

// ENQUEUE: FOUR-TIER PLACEMENT, NO CLASS INPUT AT ANY TIER
// TIER 0: WARM-STAY -- AN UNCONGESTED ANCHOR KEEPS THE TASK, NO SPILL
// TIER 1: IDLE CPU -> THAT CPU'S PER-CPU DSQ (ADMISSION-GATED) + KICK
// TIER 2: WAKEUP PREEMPTION -> PER-CPU DSQ (ADMISSION-GATED) + HARD PREEMPT
// TIER 3: FALLBACK -> THE HOME DOMAIN'S OVERFLOW DSQ + SELECTIVE KICK
void BPF_STRUCT_OPS(pandemonium_enqueue, struct task_struct *p,
		    u64 enq_flags)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(scx_bpf_task_cpu(p));
	if (node < 0 || (u32)node >= nr_nodes) node = 0;

	struct task_ctx *tctx = lookup_task_ctx(p);

	struct tuning_knobs *knobs = get_knobs();
	u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;
	u64 dl;

	// CLASSIFY: WAKEUP VS RE-ENQUEUE
	bool is_wakeup = tctx && !tctx->ran_since_wake;

	// FLOW SIGNATURE: RECORD THIS WAKEUP'S WAKER CPU IN THE PERSISTED SHAPE
	// BITMAP (CLASSIFY ONCE BY PARTNER CARDINALITY, FREEZE AT MATURITY). THE
	// WAKER IS THE ENQUEUEING CPU.
	if (tctx && is_wakeup)
		update_pair_ledger(tctx,
				   (s32)(bpf_get_current_pid_tgid() & 0xffffffff));

	// TIER 0 -- WARM-STAY: AN UNCONGESTED ANCHOR KEEPS THE WAKEE ON ITS WARM CORE
	// INSTEAD OF FANNING OUT TO A COLD IDLE SIBLING, THE DUAL OF THE DISPATCH
	// STEAL THRESHOLD. SEATED DIRECTLY ON THE ANCHOR'S PER-CPU DSQ WITH NO SPILL:
	// A LOW-SOJOURN ANCHOR DRAINS FAST EVEN WHEN DEEP, SO A DEPTH-BASED SPILL
	// WOULD MIGRATE AGAINST THE STAY. THE SEAT MAY BE BUSY, SO THE KICK IS
	// PRICED RATHER THAN ASSUMED IDLE.
	// THIS IS WHERE select_cpu's WARM-STAY DEFER LANDS. AN ABOVE-THRESHOLD
	// SOJOURN RETURNS -1 AND THE WAKEE FANS OUT THROUGH TIER 1 BELOW.
	{
		s32 hold = warm_seat_pick(p, tctx, knobs, is_wakeup,
					    bpf_ktime_get_ns());
		if (hold >= 0) {
			u64 hdl = task_deadline(tctx, knobs);
			u64 hnow = bpf_ktime_get_ns();
			// PAIR-WARM MARKER: THE WARM-STAY ANCHOR IS A PAIR MEMBER
			// TAKING ITS SEAT, SO STAMP IT FOR THE STEP-1 PAIR-SPLIT
			// HOLD, AS THE keep_own SITE DOES.
			pair_warm_ns[(u32)hold & (MAX_CPUS - 1)] = hnow;
			__sync_val_compare_and_swap(
				&sojourn_stamp_pcpu[(u32)hold & (MAX_CPUS - 1)].ns,
				0, hnow);
			ledger_charge(tctx, (u32)hold);
			scx_bpf_dsq_insert_vtime(p, (u64)hold, sl, hdl, enq_flags);
			// ASK THE SEAT, NOT THE TASK. AN IDLE ANCHOR IS WOKEN BY
			// SCX_KICK_IDLE; ONLY A BUSY ONE NEEDS THE PREEMPT.
			// THE SEAT TEST ALONE IS NOT ENOUGH ON THE REQUEUE ARM, WHICH
			// IS WHY THIS IS PRICED. THE REQUEUE ANCHOR IS last_cpu AND
			// stopping() SET IT TO THE CPU NOW EXECUTING THIS ENQUEUE, SO
			// THE SEAT IS OCCUPIED BY THE TASK BEING SEATED AND THE
			// OCCUPANCY TEST IS A CONSTANT HERE. requeue_kick_flag ASKS
			// WHAT THE TASK IS OWED INSTEAD, AND A TASK THAT JUST RAN IS
			// OWED NOTHING.
			u64 hold_kick = requeue_kick_flag(tctx, hold, is_wakeup,
							 SCX_KICK_IDLE);
			if (hold_kick != KICK_NONE)
				scx_bpf_kick_cpu(hold, hold_kick);
			tctx->dispatch_path = 1;
			struct pandemonium_stats *s = get_stats();
			if (s) {
				s->nr_shared += 1;
				s->nr_dispatches += 1;
				// COUNT THE KICK BY WHAT WAS ISSUED. A TRUTHFUL HARD
				// COUNT IS WHAT LETS A STORM LOG DISTINGUISH A REAL IPI
				// STORM FROM IDLE RE-ENQUEUE CHURN.
				if (hold_kick == SCX_KICK_PREEMPT)
					s->nr_hard_kicks += 1;
				else if (hold_kick != KICK_NONE)
					s->nr_soft_kicks += 1;
				else
					s->nr_kick_declined += 1;
				if (is_wakeup)
					s->nr_enq_wakeup += 1;
				else
					s->nr_enq_requeue += 1;
				count_l2_affinity(s, tctx, hold, p->flags & PF_WQ_WORKER);
			}
			return;
		}
	}

	// TIER 1: IDLE CPU -> THAT CPU'S PER-CPU DSQ + KICK. PLACEMENT IS THE R_eff
	// WALK, WITH NO CLASS GATE IN FRONT OF IT. find_idle_by_affinity WALKS
	// affinity_rank IN ASCENDING R_eff, SO DISTANCE DEGRADES CONTINUOUSLY RATHER
	// THAN FALLING OFF A CLIFF INTO AN UNORDERED NODE-WIDE PICK, AND THE BIAS IS
	// EXPRESSED BY *WHICH* IDLE CPU WINS. affinity_search_online IS TAU-DERIVED,
	// 3 AT 12C AND 8 AT 32C, SO THE BUDGET SCALES WITHOUT A KNOB.
	// THE NODE-WIDE pick_idle_cpu BELOW IS THE FALLBACK WHEN THE WALK MISSES.
	s32 cpu = -1;
	if (tctx)
		cpu = find_idle_by_affinity(tctx->last_cpu, p->cpus_ptr, NULL);
	if (cpu < 0)
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p->cpus_ptr, node, 0);
	if (cpu >= 0 && (u64)cpu < nr_cpu_ids) {
		// SEAT THE WAKEE ON THAT CPU'S OWN PER-CPU DSQ AND KICK IT. KICK ==
		// DRAIN IDENTITY -- THE KICKED CPU IS THE ONE THAT DISPATCHES IT.
		// ROUTING TO domain_inter_dsq WHILE KICKING ONE CPU WOULD DECOUPLE THE
		// TWO, SINCE THE KICKED CPU WINS THE SHARED-DSQ RACE ONLY 1/DOMAIN-SIZE
		// OF THE TIME. STEP 1's R_eff STEAL STILL RELIEVES THE SEAT IF IT AGES
		// PAST THE PHI THRESHOLD.
		u64 tier1_dsq = (u64)cpu;
		dl = tctx ? task_deadline(tctx, knobs)
			  : bpf_ktime_get_ns();
		// ARM THE PER-CPU SOJOURN STAMP BEFORE THE INSERT. A KICK THAT NO-OPS
		// -- SCX_KICK_IDLE ON A CPU THAT JUST WENT BUSY, OR THE DOCUMENTED
		// can_skip_idle_kick RACE -- WOULD OTHERWISE LEAVE THE TASK INVISIBLE
		// TO EVERY STAMP-READING RESCUE FOR UP TO THE RESIDENT'S FULL SLICE.
		// THE ARMED-BUT-NOT-YET-QUEUED WINDOW IS INSTRUCTION-SCALE, FAR BELOW
		// ANY AGE THRESHOLD A READER FIRES ON, AND A STAMP THAT OUTLIVES ITS
		// TASK IS HEALED BY pcpu_stamp_heal.
		if ((u32)cpu < MAX_CPUS)
			__sync_val_compare_and_swap(
				&sojourn_stamp_pcpu[(u32)cpu & (MAX_CPUS - 1)].ns,
				0, bpf_ktime_get_ns());
		ledger_charge(tctx, (u32)cpu);
		scx_bpf_dsq_insert_vtime(p, tier1_dsq, sl, dl, enq_flags);

		// KICK BY THE TARGET'S STATE, NOT BY THE TASK'S CLASS. `cpu` CAME FROM
		// AN IDLE PICK; IF IT IS STILL IDLE SCX_KICK_IDLE WAKES IT, AND IF IT
		// WENT BUSY IN BETWEEN ONLY A PREEMPT REACHES IT. SCX_KICK_IDLE IS A
		// DOCUMENTED NO-OP ON A BUSY CPU, SO A TASK LANDING ON A TICKLESS-IDLE
		// CORE WOULD STRAND WITH NO TICK BEHIND IT TO RESCUE THE MISS.
		// requeue_kick_flag PRICES IT: A WAKEUP TAKES THE PREEMPT
		// UNCONDITIONALLY, A REQUEUE BUYS IT WITH ITS OWN wait_since CLAIM.
		// DELETING THE REQUEUE PREEMPT ENTIRELY STALLS THE BOX -- IN
		// --no-adaptive THE TICK PREEMPT NEVER FIRES, SO THIS KICK IS THE ONLY
		// MECHANISM DISLODGING A RESIDENT. THE PRICE BOUNDS WHEN IT FIRES,
		// NEVER WHETHER.
		u64 kick_flag = requeue_kick_flag(tctx, cpu, is_wakeup,
						  SCX_KICK_IDLE);
		if (kick_flag != KICK_NONE)
			scx_bpf_kick_cpu(cpu, kick_flag);

		if (tctx) {
			tctx->dispatch_path = 0;
		}

		struct pandemonium_stats *s = get_stats();
		if (s) {
			s->nr_shared += 1;
			s->nr_dispatches += 1;
			// COUNT BY THE FLAG ACTUALLY ISSUED.
			if (kick_flag == SCX_KICK_PREEMPT)
				s->nr_hard_kicks += 1;
			else if (kick_flag != KICK_NONE)
				s->nr_soft_kicks += 1;
			else
				s->nr_kick_declined += 1;
			cross_domain_bump(s, XDOM_ENQ_T1, tctx ? tctx->last_cpu : -1, cpu);
			if (is_wakeup)
				s->nr_enq_wakeup += 1;
			else
				s->nr_enq_requeue += 1;
			if (tctx)
				count_l2_affinity(s, tctx, cpu, p->flags & PF_WQ_WORKER);
		}
#if TRACE_SCHED
		if (is_sched_task(p))
			bpf_printk("PAND: enq tier1 pid=%d cpu=%d", p->pid, cpu);
#endif
		return;
	}

	// TIER 2: WARM-ANCHOR -- THE TASK'S OWN last_cpu PER-CPU DSQ + KICK.
	// A TASK IS SEATED TOWARD THE CORE IT LAST RAN ON, NOT AN ARBITRARY
	// NODE-WIDE PICK. pick_pcpu_dsq_with_spill GIVES THE WARM PER-CPU DSQ IF IT
	// HAS ROOM, ELSE A NEAR R_eff SIBLING, ELSE domain_inter_dsq AS THE
	// LAST-RESORT ESCAPE VALVE. dispatch STEP 0 DRAINS THE WARM PER-CPU DSQ WHEN
	// last_cpu NEXT DISPATCHES; STEP 1 (NEAREST-SURPLUS STEAL) COVERS A SIBLING
	// LANDING.
	//
	// THE CLASS TEST ADMITS WAKES AND HANDOFF PARTNERS ONLY. A PLAIN REQUEUE
	// FALLS PAST THIS TIER TO TIER 3 AND domain_inter_dsq, WHICH IS THE REQUEUE
	// LOAD BALANCER: A REQUEUE SEATED ON ITS OWN PER-CPU DSQ IS DRAINED BY THAT
	// CPU'S STEP 0 ALONE, SO THE ONLY CROSS-CPU RELIEF LEFT WOULD BE STEP 1's
	// RATE-LIMITED STEAL AND THE TICK SCAN, AND ONE CPU SITS ON TWENTY REQUEUES
	// WHILE ITS NEIGHBOUR IDLES.
	// THE MIGRATIONS TIER 3 PRODUCES ARE THAT BALANCING, PRICED AT ONE DRAW OVER
	// THE DOMAIN PER REQUEUE. THE NUMBER WORTH CLOSING IS HOW MUCH OF THE DRAW IS
	// WASTED -- A LANDING ON A CPU NO BETTER THAN THE SOURCE -- WHICH NO COUNTER
	// IN THIS FILE MEASURES.
	if (tctx &&
	    (is_wakeup || is_handoff_partner(tctx))) {
		// WARM-ANCHOR: PREFER THE WAKEE'S OWN LAST CORE. pick_pcpu_dsq_with_spill
		// THEN SEATS IT ON THAT cpu'S PER-CPU DSQ (WARM), A NEAR R_eff SIBLING,
		// OR domain_inter_dsq AS LAST RESORT.
		cpu = (tctx->last_cpu >= 0 && (u64)tctx->last_cpu < nr_cpu_ids)
		    ? tctx->last_cpu
		    : __COMPAT_scx_bpf_pick_any_cpu_node(p->cpus_ptr, node, 0);
		if (cpu >= 0 && (u64)cpu < nr_cpu_ids &&
		    __COMPAT_scx_bpf_cpu_curr(cpu)) {
			s32 t2_cpu;
			u64 tier2_dsq = pick_pcpu_dsq_with_spill(cpu, p->cpus_ptr, is_handoff_partner(tctx), &t2_cpu);

			dl = task_deadline(tctx, knobs);
			ledger_charge(tctx, (u32)t2_cpu);
			scx_bpf_dsq_insert_vtime(p, tier2_dsq, sl, dl,
						  enq_flags);

			// THE KICK GOES TO t2_cpu, NOT `cpu` -- THEY DIFFER WHENEVER
			// THE SPILL FIRES, AND THE HELPER TESTS THE SEAT THAT WILL
			// ACTUALLY HOLD THE TASK.
			u64 kick_flag = requeue_kick_flag(tctx, t2_cpu, is_wakeup,
							 SCX_KICK_IDLE);
			if (kick_flag != KICK_NONE)
				scx_bpf_kick_cpu(t2_cpu, kick_flag);
			tctx->dispatch_path = 1;

			struct pandemonium_stats *s = get_stats();
			if (s) {
				s->nr_shared += 1;
				s->nr_dispatches += 1;
				// COUNT BY THE FLAG ACTUALLY ISSUED.
				if (kick_flag == SCX_KICK_PREEMPT)
					s->nr_hard_kicks += 1;
				else if (kick_flag != KICK_NONE)
					s->nr_soft_kicks += 1;
				else
					s->nr_kick_declined += 1;
				if (is_wakeup)
					s->nr_enq_wakeup += 1;
				else
					s->nr_enq_requeue += 1;
			}
#if TRACE_SCHED
			if (is_sched_task(p))
				bpf_printk("PAND: enq tier2 pid=%d cpu=%d dsq=%llu", p->pid, cpu, tier2_dsq);
#endif
			return;
		}
	}

	// TIER 3: THE PER-DOMAIN OVERFLOW DSQ FOR THE TASK'S CURRENT CPU'S DOMAIN,
	// PLUS A SELECTIVE KICK. DISPATCH STEP 3 DRAINS IT DOMAIN-LOCALLY, WHICH IS
	// CACHE-COHERENT INSIDE THE L3; STEP 5 IS THE CROSS-DOMAIN WORK-CONSERVATION
	// SCAN WHEN THE LOCAL DOMAIN IS EMPTY.
	s32 src_cpu_t3 = scx_bpf_task_cpu(p);
	u32 src_dom_t3 = cpu_domain_of(src_cpu_t3);
	u64 target_dsq = domain_inter_dsq(src_dom_t3);

	// ARM THE OVERFLOW STAMP ON THE EMPTY->NONEMPTY TRANSITION. THE RESCUE AND
	// THE TICK PREEMPT BOTH READ THIS ONE STAMP, SO ANY WAITER CAN TRIGGER THEM.
	__sync_val_compare_and_swap(&sojourn_stamp_overflow[src_dom_t3 & (MAX_OVERFLOW_DOMAINS - 1)].ns, 0, bpf_ktime_get_ns());

	dl = tctx ? task_deadline(tctx, knobs) : bpf_ktime_get_ns();

	scx_bpf_dsq_insert_vtime(p, target_dsq, sl, dl, enq_flags);

#if TRACE_SCHED
	if (is_sched_task(p))
		bpf_printk("PAND: enq tier3 pid=%d dsq=%llu", p->pid, target_dsq);
#endif

	// THE KICK GOES TO scx_bpf_task_cpu(p). IF THAT CPU IS BUSY, tick()'s
	// PER-CPU PREEMPT DISLODGES THE RESIDENT.
	// TIER 3 IS DELIBERATELY NOT PRICED, AND IT IS THE ONE TIER THAT IS NOT.
	// TIER 0, 1 AND 2 BUY A REQUEUE'S PREEMPT WITH WHAT THE TASK IS OWED. THIS
	// TIER DOES NOT, BECAUSE EVERY RE-ENQUEUE ON A SATURATED BOX ARRIVES HERE
	// AND SO IT CARRIES THE VOLUME. A REFUSED REQUEUE HERE WAITS IN A
	// DOMAIN-WIDE QUEUE RATHER THAN ON ONE CPU'S OWN, AND WHAT IT WAITS FOR IS
	// THE HZ=1000 TICK FLOOR. THE OTHER THREE SITES CARRY THE PRICE WITHOUT
	// THAT COST.
	s32 t3_cpu = scx_bpf_task_cpu(p);
	u64 kick_flags = (is_wakeup || is_handoff_partner(tctx))
		       ? SCX_KICK_PREEMPT : 0;
	scx_bpf_kick_cpu(t3_cpu, kick_flags);

	if (tctx)
		tctx->dispatch_path = is_wakeup ? 1 : 2;

	struct pandemonium_stats *s = get_stats();
	if (s) {
		s->nr_shared += 1;
		// COUNT THE KICK BY WHAT WAS ISSUED, NOT BY WHAT THE TASK IS. THE FLAG
		// IS PRICED, SO A WAKEUP ONTO AN IDLE SEAT TAKES THE FLOOR AND A
		// REQUEUE THAT MEETS ITS CLAIM TAKES THE PREEMPT -- KEYING THE COUNT ON
		// is_wakeup WOULD MISREPORT BOTH DIRECTIONS.
		if (kick_flags == SCX_KICK_PREEMPT)
			s->nr_hard_kicks += 1;
		else
			s->nr_soft_kicks += 1;
		if (is_wakeup)
			s->nr_enq_wakeup += 1;
		else
			s->nr_enq_requeue += 1;
	}

}

#define BOUND_SWEEP_BUDGET 8
// UNIFIED SOJOURN BOUND SWEEP -- THE BACKSTOP UNDER THE TICK TOWER, NEVER
// ITS REPLACEMENT. ANY CPU WHOSE PER-CPU DSQ HEAD HAS WAITED >= lag_cap_ns
// GETS A PREEMPT KICK, NO EXEMPTION. IT RUNS FROM DISPATCH ON EVERY CPU,
// SO A CPU WALLED OFF BY A NON-YIELDING RESIDENT IS RESCUED BY ANY OTHER
// CPU's DISPATCH -- OFF THE HELD CPU's OWN TICK, SO NO_HZ_FULL CANNOT
// SUPPRESS IT. THIS IS THE FREEZE FIX: THE TICK TOWER'S 5ms BAND IS THE FAST
// PATH, THIS IS THE TICK-INDEPENDENT GUARANTEE BENEATH IT. ROTATING BUDGET
// WINDOWS: O(1) PER DISPATCH, FLAT AS N GROWS. UNCONDITIONAL AT DISPATCH
// ENTRY -- MEASURED: GATED ON A STEP-0 MISS, EVERY CPU's STEP 0 KEEPS
// HITTING UNDER SATURATION AND THE ENFORCER GOES DORMANT SYSTEM-WIDE. DO NOT
// REORDER.
static __always_inline void sweep_bound_preempt(u64 now, u32 self)
{
	u32 nr = nr_cpu_ids;
	if (nr == 0)
		return;
	u32 base = (u32)(now >> 20);
	#pragma unroll
	for (u32 i = 0; i < BOUND_SWEEP_BUDGET; i++) {
		u32 c = (base + i) % nr;
		if (c == self)
			continue;
		u64 stamp = sojourn_stamp_pcpu[c & (MAX_CPUS - 1)].ns;
		if (stamp == 0)
			continue;
		if (now > stamp && (now - stamp) >= lag_cap_ns)
			scx_bpf_kick_cpu((s32)c, SCX_KICK_PREEMPT);
	}
	// OVERFLOW BOUND: AN OVERFLOW HEAD AGED PAST lag_cap_ns IS DRAINED BY STEP 2
	// OR 3 DOMAIN-LOCALLY AND BY STEP 5 FROM ANY OTHER DOMAIN -- BUT IF EVERY CPU
	// IS HELD, NOBODY DISPATCHES, SO FORCE ONE OFF ITS RESIDENT TO RE-ENTER
	// dispatch. THE KICKED CPU NEED NOT SHARE THE DOMAIN, SINCE STEP 5's SCAN
	// REACHES EVERY AGED HEAD.
	// A ROTATING 8-DOMAIN WINDOW, SO AN AGED HEAD IS SEEN WITHIN 4 ROTATIONS AND
	// THE HOTTEST PROGRAM IN THE TREE DOES NOT PAY 64 LOADS PER DISPATCH.
	#pragma unroll
	for (u32 i = 0; i < BOUND_SWEEP_BUDGET; i++) {
		u32 d = (base + i) & (MAX_OVERFLOW_DOMAINS - 1);
		u64 e = sojourn_stamp_overflow[d].ns;
		if (e != 0 && now > e && (now - e) >= lag_cap_ns) {
			u32 k = base % nr;
			if (k != self)
				scx_bpf_kick_cpu((s32)k, SCX_KICK_PREEMPT);
			break;
		}
	}
}

// STEP 1 STEAL-WALK STATE, CARRIED ACROSS bpf_loop() ITERATIONS.
//
// THE WALK IS bpf_loop() AND NOT A BOUNDED for SO THE VERIFIER CHECKS THE BODY
// ONCE INSTEAD OF ONCE PER CANDIDATE. MAX_AFFINITY_CANDIDATES IS 128 AT COMPILE
// TIME WHILE pcpu_spill_search_budget CLAMPS THE WALK TO ~6 AT 12C, AND A
// VERIFIER THAT CANNOT FOLD nr_cpu_ids MUST ASSUME ALL 128. THAT GAP -- NOT THE
// RUNTIME COST -- PUSHED pandemonium_dispatch PAST THE 1M INSTRUCTION CEILING
// ON THE 6.13/6.16/6.18 VERIFIERS. WITH bpf_loop THE COMPILE-TIME BOUND NO
// LONGER CONTRIBUTES DEPTH AT ALL, SO THE BODY CAN GROW AND THE CEILING CAN
// RISE WITHOUT REOPENING THIS.
struct steal_scan_ctx {
	u64 now;
	u32 base;
	u32 my_cpu;
	u32 checked;
	s32 best_peer;
};

// ONE CANDIDATE OF THE R_eff STEAL WALK. RETURN 1 STOPS THE WALK, RETURN 0
// ADVANCES IT.
static int steal_scan_step(u32 i, void *ctx_)
{
	struct steal_scan_ctx *c = ctx_;

		u32 key = c->base + i;
		u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
		if (!val || *val == (u32)-1)
			return 1;
		u32 peer = *val;
		if (peer >= nr_cpu_ids)
			return 0;
		if (peer == c->my_cpu) {
			if (++c->checked >= pcpu_spill_search_budget)
				return 1;
			return 0;
		}
		// SOJOURN IS THE PEER'S DSQ BACKLOG AGE. ZERO MEANS ITS PER-CPU DSQ IS
		// EMPTY, SO SKIP THE REMOTE scx_bpf_dsq_nr_queued TOUCH -- THE COMMON
		// CASE UNDER WAKE-HEAVY LOAD.
		u64 enq = sojourn_stamp_pcpu[peer & (MAX_CPUS - 1)].ns;
		if (enq == 0) {
			if (++c->checked >= pcpu_spill_search_budget)
				return 1;
			return 0;
		}
		u32 nq = scx_bpf_dsq_nr_queued((u64)peer);
		if (nq >= 1) {
			// PHI STEAL-RESIST: THE PEER'S SOJOURN MUST REACH
			// codel_target_ns + b*R_eff. THE DISTANCE PENALTY IS
			// PRE-FOLDED IN reff_value IN NS, SO THIS IS ONE INDEXED READ
			// AND NO MULTIPLY -- AN SMT SIBLING AT R_eff ~0 STAYS FREELY
			// RELIEVABLE WHILE A CROSS-DOMAIN PULL NEEDS ~tau OF SUSTAINED
			// BACKLOG. ALL-ZERO reff_value COLLAPSES TO A FLAT TARGET.
			u32 *dxp = bpf_map_lookup_elem(&reff_value, &key);
			u32 dx = dxp ? *dxp : 0;
			u64 dist_extra = (dx == (u32)-1) ? 0 : (u64)dx;
			u64 phi_thresh = codel_target_ns + dist_extra;
			// PAIR-SPLIT HOLD: peer RECENTLY SEATED A CONFIRMED PAIR,
			// STAMPED IN pair_warm_ns. STEALING ITS HEAD SPLITS THE PAIR,
			// A LOCALITY LOSS R_eff CANNOT SEE BECAUSE A NEAR SPLIT LOOKS
			// CHEAP. PRICE IT BY THE SEAM INSTEAD -- domain_phi IS HIGH
			// FOR A TIGHT SEAM, SO A NEAR SPLIT WAITS UP TO ONE EXTRA
			// TARGET WHILE A FAR SPLIT ADDS ~0, BEING PRICED ALREADY BY
			// dist_extra. THE SENTINEL MEANS NO HOLD.
			// A PRICE, NOT A GATE -- STARVATION TRIPS THE LONGER SOJOURN.
			u64 pw = pair_warm_ns[peer & (MAX_CPUS - 1)];
			if (pw && c->now >= pw && (c->now - pw) < codel_target_ns) {
				u32 *dpp = bpf_map_lookup_elem(&domain_phi, &key);
				u32 dphi = dpp ? *dpp : (u32)-1;
				if (dphi != (u32)-1) {
					u64 hold = ((u64)dphi * codel_target_ns) / 1000000ULL;
					if (hold > codel_target_ns)
						hold = codel_target_ns;
					phi_thresh += hold;
				}
			}
			if (c->now >= enq && (c->now - enq) >= (nq > 1 ? phi_thresh : phi_thresh + codel_target_ns) /* LONE-TASK STARVATION RESCUE (nq==1): the surplus>1 rule pins a lone WARM task for cache locality, but montauk's dispatch-stall shows a lone burst wakee stranded on a BUSY peer's per-CPU DSQ is served 0% by that peer's STEP 0 (MIRROR, PREEMPT-STARVED) and 100% by steal (SUB), tailing to 100ms-947ms (worst 26.7s at 2C) since the only other rescue -- tick()'s rotating sojourn scan -- is sparse and never fires on an idle/all-idle-at-low-width topology. A lone task aged past the overflow window is no longer warm-worth-pinning: steal it here, far below the ~167ms net. Phi still prices distance; fresh lone tasks (< the window) stay pinned. */) {
				c->best_peer = (s32)peer;
				return 1;
			}
		}
		if (++c->checked >= pcpu_spill_search_budget)
			return 1;
	return 0;
}

// DISPATCH: CPU IS IDLE AND NEEDS WORK
// HYBRID PER-CPU + per-domain OVERFLOW DESIGN:
//   SELECT_CPU -> PER-CPU DSQ (DEPTH-GATED, VISIBLE, STEALABLE)
//   ENQUEUE TIER 0/1/2 -> PER-CPU DSQ (WARM)
//   ENQUEUE TIER 3 -> domain_inter_dsq (L3-LOCAL, SOJOURN-ORDERED)
//
// UNIFIED BOUND, FIRST (sweep_bound_preempt -- off-tick, NO_HZ_FULL-immune)
// 0. OWN PER-CPU DSQ (CACHE-HOT, ZERO CONTENTION)
// 1. R_EFF STEAL (AFFINITY_RANK -- L2 SIBLING AT SLOT 0, R_EFF PEERS AT SLOTS 1+)
// SAFETY NET. SERVICE OVERFLOW PAST codel_starve_ns
// 2. SERVICE OVERFLOW PAST codel_target_ns
// 3. DOMAIN-LOCAL OVERFLOW (domain_inter_dsq[my_dom]), SELECTIVE
// 5. CROSS-DOMAIN SCAN (WORK CONSERVATION ACROSS L3 INTERCONNECT)
// KEEP_RUNNING IF PREV STILL WANTS CPU AND NOTHING QUEUED
void BPF_STRUCT_OPS(pandemonium_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 my_dom = cpu_domain_of(cpu);
	struct pandemonium_stats *s;
	u64 now = bpf_ktime_get_ns();
	// STEP 1 SCAN-WINDOW FLAG: ONE RATE-LIMIT STAMP PER codel_target WINDOW,
	// SET AND CONSUMED IN STEP 1.
	bool steal_scan = false;

	// UNIFIED BOUND, FIRST: RESCUE ANY CPU WHOSE PER-CPU DSQ HEAD HAS WAITED
	// PAST lag_cap_ns, BEFORE THIS CPU RUNS ITS OWN PLACEMENT WATERFALL. A HARD
	// INVARIANT AHEAD OF PLACEMENT, RUN OFF ANOTHER CPU'S DISPATCH SO THE HELD
	// CPU'S OWN TICK IS NOT NEEDED. UNCONDITIONAL AND NOT TO BE REORDERED.
	sweep_bound_preempt(now, (u32)cpu);

	// STEP 0: OWN PER-CPU DSQ -- HIGHEST PRIORITY, CACHE-HOT.
	// SOJOURN GATE AT EXIT: IF EITHER OVERFLOW SIDE HAS AGED PAST
	// codel_target_ns, FALL THROUGH SO STEP 2 SERVES OVERFLOW
	// ON THIS DISPATCH TOO. WITHOUT THIS GATE, EVERY CPU WITH HOT PER-CPU
	// WORK NEVER VISITS OVERFLOW; SCX_WATCHDOG_WORKFN AND OTHER WORKQUEUE
	// WORKERS GET STARVED IN domain_inter_dsq UNTIL codel_starve_ns FIRES.
	if ((u64)cpu < nr_cpu_ids &&
	    scx_bpf_dsq_move_to_local((u64)cpu, 0)) {
		// CLEAR THE DSQ-EMPTY-CYCLE TIMESTAMP.
		pcpu_stamp_heal((u32)cpu);
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		if (sojourn_gate_pass(now, my_dom))
			return;
	}

	// STEP 1: R_EFF STEAL. SINGLE LOOP OVER affinity_rank: SLOT 0 IS THE
	// L2 SIBLING (LOWEST R_EFF), SLOTS 1+ ARE R_EFF-RANKED PEERS, CROSS-DOMAIN
	// INCLUDED. NO TIER BOUNDARY: Φ (the reff_value penalty) ALONE PRICES
	// DISTANCE -- A CROSS-DOMAIN PULL NEEDS ~tau OF SUSTAINED BACKLOG, AN SMT
	// SIBLING (R_eff~0) RELIEVES FREELY. affinity_rank IS AUTHORITATIVE FOR
	// PLACEMENT DISTANCE.
	// BUDGET = pcpu_spill_search_budget (nr_cpu_ids/2 CLAMPED TO
	// [6, MAX_AFFINITY_CANDIDATES]), MATCHING THE ENQUEUE-SIDE SPILL HELPER.
	{
		u32 my_cpu = (u32)cpu;
		u32 base = my_cpu * MAX_AFFINITY_CANDIDATES;
		// SCAN RATE-LIMIT: THE PEER WALK IS THE DOMINANT PER-DISPATCH CACHE
		// COST UNDER WAKE-HEAVY LOAD, AND A PEER CANNOT ACCUMULATE STEALABLE
		// BACKLOG FASTER THAN codel_target_ns, SO SCANNING MORE OFTEN IS PURE
		// WASTE. BETWEEN SCANS WE FALL THROUGH TO OVERFLOW AND tick()'s REMOTE
		// SCAN STILL KICKS ANY AGED PER-CPU DSQ, SO NO WORK IS STRANDED.
		u32 zero = 0;
		u64 *last_scan = bpf_map_lookup_elem(&last_spill_scan, &zero);
		steal_scan = !last_scan || *last_scan == 0 ||
			     (now - *last_scan) >= codel_target_ns;
		if (steal_scan && last_scan)
			*last_scan = now;
		// R_eff FLOW STEAL. affinity_rank IS DISTANCE-ORDERED, SO THE FIRST
		// QUALIFYING PEER IS THE CLOSEST -- MIN-COST FLOW. A PEER NEEDS AT
		// LEAST 2 QUEUED BEFORE ONE IS PULLED, SO A LONE WARM TASK IS NEVER
		// YANKED. BOUNDED LOOP, LOCK-FREE move_to_local.
		struct steal_scan_ctx sctx = {
			.now = now, .base = base, .my_cpu = my_cpu,
			.checked = 0, .best_peer = -1,
		};
		if (steal_scan)
			bpf_loop(MAX_AFFINITY_CANDIDATES, steal_scan_step,
				 &sctx, 0);
		s32 best_peer = sctx.best_peer;
		if (best_peer >= 0 &&
		    scx_bpf_dsq_move_to_local((u64)best_peer, 0)) {
			pcpu_stamp_heal((u32)best_peer);
			s = get_stats();
			if (s) {
				s->nr_dispatches += 1;
				s->nr_steal += 1;
				// STEAL: task's home is best_peer, now consumed by `cpu`.
				cross_domain_bump(s, XDOM_STEAL, best_peer, cpu);
			}
			if (sojourn_gate_pass(now, my_dom))
				return;
		}
	}

	// SAFETY NET: HARD STARVATION RESCUE PAST codel_starve_ns, TAU-SCALED TO
	// ~55.6MS AT THE 12C REFERENCE. BLIND, AND NEVER GATED.
	if (try_service_aged_overflow(now, my_dom,
				       codel_starve_ns, false))
		return;

	// STEP 2: SERVICE THE OVERFLOW QUEUE PAST codel_target_ns, THE LIVE
	// OSCILLATOR TARGET. ONE COMPARISON, ONE BLIND DRAIN. FEEDS THE OSCILLATOR,
	// BEING THE REPRESENTATIVE PRESSURE SIGNAL THAT TIGHTENS THE TARGET.
	if (try_service_aged_overflow(now, my_dom,
				       codel_target_ns, true))
		return;

	// STEP 3: DOMAIN-LOCAL OVERFLOW, CACHE-COHERENT INSIDE THE L3.
	// THE DRAIN IS SELECTIVE HERE AND BLIND IN try_service_aged_overflow ON
	// PURPOSE: THIS IS THE ORDINARY PATH AND CAN AFFORD TO PREFER A NEAR TASK,
	// WHILE THE RESCUE EXISTS PRECISELY TO TAKE WHATEVER IS STUCK.
	if (domain_overflow_drain_near(my_dom, cpu, now, &sojourn_stamp_overflow[my_dom & (MAX_OVERFLOW_DOMAINS - 1)].ns)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// STEP 5: CROSS-DOMAIN WORK CONSERVATION. SCAN THE OTHER DOMAINS ONCE AND
	// DRAIN ANY NON-EMPTY OVERFLOW. REACHED ONLY WHEN THE LOCAL DOMAIN IS EMPTY,
	// SO A CROSS-DOMAIN MIGRATION HERE IS PURE IDLE-TIME WORK CONSERVATION AND
	// THE CACHE COST IS OFFSET BY NOT IDLING A CORE.
	// LOOP BOUND MAX_OVERFLOW_DOMAINS; nr_overflow_domains EXITS EARLY.
	for (u32 c = 0; c < MAX_OVERFLOW_DOMAINS; c++) {
		if (c >= nr_overflow_domains)
			break;
		if (c == my_dom)
			continue;
		if (overflow_drain_clear(domain_inter_dsq(c),
					 &sojourn_stamp_overflow[c & (MAX_OVERFLOW_DOMAINS - 1)].ns)) {
			s = get_stats();
			if (s) {
				s->nr_dispatches += 1;
				// ALWAYS CROSS-DOMAIN BY CONSTRUCTION, SINCE c != my_dom.
				if (s->nr_cross_domain[XDOM_STEP5] < ~0ULL)
					s->nr_cross_domain[XDOM_STEP5] += 1;
			}
			return;
		}
	}

	// NOTHING IN ANY DSQ -- KEEP PREV RUNNING IF POSSIBLE
	if (prev && !(prev->flags & PF_EXITING) &&
	    (prev->scx.flags & SCX_TASK_QUEUED)) {
		struct task_ctx *tctx = lookup_task_ctx(prev);
		struct tuning_knobs *knobs = get_knobs();
		scx_bpf_task_set_slice(prev,
			tctx ? task_slice(tctx, knobs)
			     : (knobs ? knobs->slice_ns : 1000000));
		s = get_stats();
		if (s) {
			s->nr_keep_running += 1;
			s->nr_dispatches += 1;
		}
	}
}

// RUNNABLE: TASK WAKES UP -- PAIR LEDGER AND WAKE-EDGE UNPARK
void BPF_STRUCT_OPS(pandemonium_runnable, struct task_struct *p,
		    u64 enq_flags)
{
	// WAKE-EDGE DETECTOR: A WAKEE ARRIVING INTO A PARKED CONTROLLER IS THE
	// DISTURBANCE THE DETECTOR MUST CATCH ON THE WAKE PATH. UN-PARK HERE, BEFORE
	// ANY DISPATCH PRICES AGAINST codel_target_ns, AND KICK CPU 0 SO THE FULL
	// RECOMPUTE RUNS THIS BEAT RATHER THAN WAITING FOR A CPU-0 TICK THAT MAY
	// NEVER FIRE UNDER TICKLESS IDLE. GATED ON osc_env_parked, WHICH IS A
	// PREDICTED-NOT-TAKEN BRANCH UNDER LOAD.
	if (osc_env_parked) {
		osc_env_unpark();
		if (bpf_get_smp_processor_id() != 0)
			scx_bpf_kick_cpu(0, SCX_KICK_PREEMPT);
	}

	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	u64 now = bpf_ktime_get_ns();
	tctx->ran_since_wake = false;

	// last_woke_at HAS ONE JOB: WAKE LATENCY. STAMPED HERE, READ AND CLEARED IN
	// running(). NOTHING ELSE READS IT.
	tctx->last_woke_at = now;

	// TIER IS TWO DECLARATIONS, STATED DIRECTLY RATHER THAN SCORED:
	//   PF_WQ_WORKER     -> INTERACTIVE    (USERSPACE BLOCKS ON THESE)
	//   EVERYTHING ELSE  -> BATCH
	// THERE IS NO RT BRANCH BECAUSE IT CANNOT BE TAKEN. sched_ext SITS BELOW RT
	// AND DEADLINE IN THE CLASS HIERARCHY AND IS HANDED ONLY SCHED_NORMAL,
	// SCHED_BATCH AND SCHED_IDLE, SO AN RT TASK NEVER REACHES THESE OPS.
}

// RUNNING: TASK STARTS EXECUTING -- RECORD WAKE LATENCY, SET RAN-SINCE-WAKE
void BPF_STRUCT_OPS(pandemonium_running, struct task_struct *p)
{
#if TRACE_SCHED
	if (is_sched_task(p))
		bpf_printk("PAND: running pid=%d cpu=%d", p->pid, bpf_get_smp_processor_id());
#endif
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx) {
		struct tuning_knobs *knobs = get_knobs();
		scx_bpf_task_set_slice(p,
			knobs ? knobs->slice_ns : 1000000);
		return;
	}

	u64 now = bpf_ktime_get_ns();
	tctx->run_exec_at = p->se.sum_exec_runtime;   // service base, see stopping()
	ledger_refund(tctx);   // the seat delivered; release the debit
	tctx->ran_since_wake = true;   // is_wakeup = !ran_since_wake
	tctx->wait_since = 0;          // WAIT ENDED -- RELEASE THE SOJOURN CLAIM

	// WAKEUP-TO-RUN LATENCY
	// ONLY RECORD ONCE PER WAKEUP: CLEAR last_woke_at AFTER RECORDING.
	if (tctx->last_woke_at && now > tctx->last_woke_at) {
		u64 wake_lat = now - tctx->last_woke_at;
		u8 path = tctx->dispatch_path;

		// SLEEP DURATION: TIME BETWEEN quiescent() AND runnable()
		u64 sleep_dur = 0;
		if (tctx->sleep_start_ns > 0 &&
		    tctx->last_woke_at > tctx->sleep_start_ns) {
			sleep_dur = tctx->last_woke_at - tctx->sleep_start_ns;
			tctx->sleep_start_ns = 0;
		}

		tctx->last_woke_at = 0;

		struct pandemonium_stats *s = get_stats();
		if (s) {
			s->wake_lat_samples += 1;
			s->wake_lat_sum += wake_lat;

			if (path == 0) {
				s->wake_lat_idle_sum += wake_lat;
				s->wake_lat_idle_cnt += 1;
			} else if (path == 1) {
				s->wake_lat_kick_sum += wake_lat;
				s->wake_lat_kick_cnt += 1;
			}
		}

		// HISTOGRAM: BPF-SIDE LATENCY BUCKETING (NO RING BUFFER)
		u32 tier_idx = (p->flags & PF_WQ_WORKER) ? 1 : 0;
		u32 bucket = lat_bucket(wake_lat);
		u32 hist_key = tier_idx * 12 + bucket;
		u64 *hist_val = bpf_map_lookup_elem(&wake_lat_hist, &hist_key);
		if (hist_val)
			*hist_val += 1;

		if (sleep_dur > 0) {
			u32 sbucket = sleep_bucket(sleep_dur);
			u64 *sval = bpf_map_lookup_elem(&sleep_hist, &sbucket);
			if (sval)
				*sval += 1;
		}
	}

	struct tuning_knobs *knobs = get_knobs();
	scx_bpf_task_set_slice(p, task_slice(tctx, knobs));
}

// STOPPING: TASK YIELDS CPU -- CACHE THE WEIGHT, PIN THE HOME, FEED THE
// DEMAND WINDOW WITH THE SERVICE JUST RENDERED
void BPF_STRUCT_OPS(pandemonium_stopping, struct task_struct *p,
		    bool runnable)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->cached_weight = effective_weight(p, tctx);
	tctx->last_cpu = bpf_get_smp_processor_id();
	// STABLE HOME: PIN ONCE TO THE FIRST CPU WE RUN ON; NEVER CHASE last_cpu
	// (REWRITTEN EVERY STOP -> THE MIGRATION-STORM ROOT). RE-HOME ONLY IF THE OLD
	// HOME WENT INVALID (HOTPLUG / AFFINITY CHANGE) SO WE NEVER STRAND THE TASK.
	if (tctx->home_cpu < 0 || (u32)tctx->home_cpu >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(tctx->home_cpu, p->cpus_ptr))
		tctx->home_cpu = tctx->last_cpu;

	// SERVICE, NOT ELAPSED. IRQ AND SOFTIRQ TIME LANDS INSIDE THE
	// running()..stopping() WINDOW, SO ELAPSED WOULD CREDIT A TASK FOR WORK IT
	// NEVER GOT TO DO -- AND THIS SCHEDULER GENERATES THAT INTERRUPT LOAD ITSELF.
	// OVER-CREDITING GRANTS STANDING, STANDING GRANTS THE LONG QUANTUM, AND THE
	// LONG QUANTUM IS WHAT A FLOORED WAKE QUEUES BEHIND. sum_exec_runtime IS THE
	// KERNEL'S OWN EXECUTION ACCOUNTING AND EXCLUDES EXACTLY THAT TIME.
	u64 svc = p->se.sum_exec_runtime > tctx->run_exec_at
		? p->se.sum_exec_runtime - tctx->run_exec_at : 0;

	// FEED THE DEMAND WINDOW. OWNER-ONLY, SO NO ATOMIC -- stopping() RUNS ON THE
	// CPU THE TASK JUST LEFT. THE WINDOW HALVES AT DEMAND_WINDOW RATHER THAN
	// DECAYING, SO THE MEAN FORGETS A STALE WORKLOAD WITHOUT A POLE.
	{
		u32 c = (u32)bpf_get_smp_processor_id();
		if (c < MAX_CPUS) {
			if (pcpu_ledger[c].demand_cnt >= DEMAND_WINDOW) {
				pcpu_ledger[c].demand_sum_ns >>= 1;
				pcpu_ledger[c].demand_cnt   >>= 1;
			}
			pcpu_ledger[c].demand_sum_ns += svc;
			pcpu_ledger[c].demand_cnt    += 1;
		}
	}

	// SERVICE LEDGER: A RUN THAT CONSUMED A FULL TARGET ADVANCES THE COUNT, ANY
	// SHORTER RUN CLEARS IT. SATURATES SO A LONG HOG CANNOT BANK UNBOUNDED CREDIT.
	if (svc >= codel_target_ns) {
		if (tctx->standing_runs < STANDING_CAP)
			tctx->standing_runs += 1;
	} else {
		tctx->standing_runs = 0;
	}
}

// TICK: SOJOURN ENFORCEMENT + EVENT-DRIVEN BATCH PREEMPTION
// FIRES ON EVERY KERNEL SCHEDULER TICK (HZ-DEPENDENT, 1-4MS) REGARDLESS
// OF SLICE LENGTH. TWO RESPONSIBILITIES:
// 1. SOJOURN: WRITE BATCH WAIT AGE TO STATS FOR RUST ADAPTIVE LAYER.
//    IF BATCH STARVING PAST THRESHOLD AND CURRENT TASK IS BATCH, KICK
//    CPU TO FORCE DISPATCH. THRESHOLD SET BY RUST FROM DISPATCH RATE.
// 2. PREEMPTION: WHEN INTERACTIVE IS WAITING AND BATCH HAS RUN PAST
//    THRESHOLD, PREEMPT TO MAINTAIN INTERACTIVE RESPONSIVENESS.
void BPF_STRUCT_OPS(pandemonium_tick, struct task_struct *p)
{
	// SOJOURN: COMPUTE BATCH WAIT AGE AND WRITE TO STATS FOR RUST
	struct pandemonium_stats *s = get_stats();
	struct tuning_knobs *knobs = get_knobs();

	// TAU-SCALING: RE-DERIVE THE TIMING STATICS IF RUST WROTE A NEW
	// topology_tau_ns, AT INITIAL DETECT OR ON HOTPLUG. NOT GATED TO CPU 0 --
	// A CPU-0 GATE LEAVES EVERY tau-DERIVED STATIC AT ITS 12C FALLBACK UNTIL THE
	// FIRST CPU-0 TICK. IDEMPOTENT UNDER NO CHANGE, AND THE last_tau_snapshot CAS
	// MAKES CONCURRENT CALLS SAFE: FIRST NON-ZERO CALL WINS, THE REST
	// SHORT-CIRCUIT ON A SINGLE COMPARE.
	apply_tau_scaling(knobs ? knobs->topology_tau_ns : 0,
	                  knobs ? knobs->codel_eq_ns : 0);

	// PER-CPU RUNNABLE DEPTH SAMPLE. NOT GATED TO CPU 0 -- THE POINT IS THE
	// SPATIAL DIMENSION, WHICH A SINGLE CPU'S QUEUE CANNOT GIVE. stats_map IS
	// PER-CPU, SO `s` IS ALREADY THIS CPU'S ENTRY AND NEEDS NO ATOMIC.
	// ONE DSQ COUNTER READ AND TWO ADDS PER TICK PER CPU.
	// BUILD WITH -DPAND_NO_RQ_DEPTH TO COMPILE THE SAMPLE OUT AND A/B ITS COST
	// AGAINST THE --no-adaptive ARM, WHICH RUNS NO RUST LOOP.
#ifndef PAND_NO_RQ_DEPTH
	if (s) {
		s->rq_depth_sum +=
			scx_bpf_dsq_nr_queued((u64)bpf_get_smp_processor_id());
		s->rq_depth_samples++;
	}
#endif

	// STALL DECISION AND HARD STARVATION RESCUE. NO BURST DETECTOR. NO FLAGS.
	// OSCILLATOR UPDATE STAYS GATED TO CPU 0 -- SINGLE-WRITER TO VELOCITY
	// AND POSITION FIELDS, NO NEED FOR CAS IN THE INTEGRATION LOOP.
	if (bpf_get_smp_processor_id() == 0) {
		// DAMPED HARMONIC OSCILLATOR (FULL FORM):
		//     ẍ + 2γẋ + ω₀²(x - c_eq) = F(t)
		// F(t): RESCUE-DRIVEN IMPULSE (NEGATIVE: TIGHTEN DETECTOR)
		// 2γẋ: DAMPING (v >> damping_shift)
		// ω₀²(x - c_eq): SPRING (RESTORING TOWARD R_eff EQUILIBRIUM)
		// BUTTERWORTH-OPTIMAL DAMPING (ζ ≈ 0.707) VIA
		// spring_shift = 2*damping_shift + 1. ~4.3% STEP-RESPONSE
		// OVERSHOOT PER IMPULSE KEEPS THE CONTROLLER PROBING THE
		// CONVEX-RESPONSE BOUNDARY INSTEAD OF PARKING INSIDE IT
		// (SONTAG'S LOGARITHMIC-RATE CONVEXITY).
		// 2C (THIN): FAST RESTORE, LARGE SPRING SHIFT WINDOW.
		// 12C (DENSE): GENTLE RESTORE, TARGET TRACKS STALL POINT.
		{
			u64 cur = __sync_fetch_and_add(&global_rescue_count, 0);
			u64 delta = cur - prev_rescue_snapshot;
			prev_rescue_snapshot = cur;

			// ENVELOPE THRESHOLDS: DERIVED FROM THE SPRING/DAMP
			// DEAD-BAND QUANTA (THE ENERGY OF ONE NO-OP-RESOLUTION
			// STEP ON EACH AXIS), PRE-SCALED BY THE RESERVOIR GAIN
			// (<< DECAY_SHIFT: A STEADY INSTANTANEOUS ENERGY E
			// CONVERGES THE RESERVOIR TO E << DECAY_SHIFT). RELEASE
			// SITS 2x ABOVE PARK -- MULTIPLICATIVE HYSTERESIS, A
			// SCHMITT TRIGGER ON ENERGY, NOT A CHANGE-POINT
			// ACCUMULATOR. TWO SHIFTS AND AN ADD PER PASS: FREE.
			u64 env_floor =
				(1ULL << (2 * oscillator_damping_shift)) +
				(1ULL << (2 * oscillator_spring_shift));
			u64 env_park = env_floor << (OSC_ENV_DECAY_SHIFT + 1);
			u64 env_release = env_floor << (OSC_ENV_DECAY_SHIFT + 2);

			if (osc_env_parked) {
				// ARMED DETECTOR, EVERY TICK, THREE COMPARES: A
				// RESCUE EVENT (DISCRETE COUNT -- ONE RESCUE IS A
				// REAL EVENT, NOT ANALOG NOISE, SO NO EPSILON),
				// THE EQUILIBRIUM MOVED UNDER THE PARKED VALUE
				// (MWU/tau RETUNE), OR THE MAX-PARK HEARTBEAT.
				if (delta == 0 &&
				    codel_target_ns == codel_seed_ns &&
				    ++osc_env_park_ticks < OSC_ENV_HEARTBEAT_TICKS)
					goto osc_env_done;
				// WAKE EDGE: FULL RECOMPUTE THIS SAME TICK, BEFORE
				// ANY DISPATCH PRICES AGAINST THE TARGET AGAIN --
				// NEVER "RESUME CADENCE AND WAIT ONE PERIOD".
				// REFRACTORY DWELL: RE-PRIME THE RESERVOIR ABOVE
				// RELEASE SO CONTRACTION RESTARTS FROM SCRATCH AND
				// A BURSTY WAKE CANNOT IMMEDIATELY RE-PARK.
				osc_env_unpark();   // single un-park owner
			} else if (delta == 0 && osc_env_energy < env_release) {
				// GRADED BAND: CONTRACTION IS GRADUAL (DIVIDED
				// CADENCE), EXPANSION IS INSTANT (ANY RESCUE
				// FALLS THROUGH TO THE FULL RECOMPUTE ABOVE).
				// THE BAND IS DELIBERATELY SHORT -- RACE INTO
				// PARK; THE COST CURVE IS FLAT FOR THE FIRST
				// FEW CADENCE CUTS AND ALL THE RISK IS DEEPER.
				if (++osc_env_skip < OSC_ENV_GRADED_DIV)
					goto osc_env_done;
				osc_env_skip = 0;
				if (osc_env_energy < env_park) {
					// PARK: PIN THE TARGET AT THE FIXED POINT
					// THE DYNAMICS CONVERGE TO (ASYMPTOTICALLY
					// EXACT, ONE STORE), FREEZE THE VELOCITY
					// INTEGRATOR (ANTI-WINDUP: IT MUST NOT
					// ACCUMULATE ACROSS THE BAND AND SLINGSHOT
					// AT WAKE), STOP THE ARITHMETIC.
					codel_target_ns = codel_seed_ns;
					oscillator_velocity_ns = 0;
					osc_env_parked = true;
					osc_env_park_ticks = 0;
					if (s)
						s->nr_osc_park++;
					goto osc_env_done;
				}
			} else {
				osc_env_skip = 0;
			}

			// FORCING TERM: ONLY RESCUE EVENTS. THE FORMER QUIET-TICK
			// "RELAX" DRIFT WAS A PRIMITIVE PROXY FOR THE SPRING; WITH
			// AN ACTUAL RESTORING TERM IT IS REDUNDANT (AND, WORSE,
			// PUSHED x AWAY FROM c_eq EVERY QUIET TICK).
			s64 impulse = 0;
			if (delta > 0) {
				u64 capped = delta > 8 ? 8 : delta;
				impulse = -((s64)(capped * OSCILLATOR_PULL_NS *
					oscillator_pull_scale));
			}

			oscillator_velocity_ns += impulse;

			// SPRING (-ω₀²(x - c_eq)): PULL VELOCITY TOWARD RESTORING x
			// BACK TO c_eq. IF x > c_eq -> NEGATIVE v IMPULSE (PULL DOWN);
			// IF x < c_eq -> POSITIVE v IMPULSE (PULL UP). ARITHMETIC
			// RIGHT-SHIFT ON SIGNED s64 PRESERVES THE SIGN.
			s64 disp = (s64)codel_target_ns -
				   (s64)codel_seed_ns;
			oscillator_velocity_ns -= disp >> oscillator_spring_shift;

			// DAMPING (-2γẋ): VELOCITY DECAY VIA bit-SHIFT.
			oscillator_velocity_ns -= oscillator_velocity_ns >>
				oscillator_damping_shift;

			if (oscillator_velocity_ns > oscillator_velocity_cap)
				oscillator_velocity_ns = oscillator_velocity_cap;
			if (oscillator_velocity_ns < -oscillator_velocity_cap)
				oscillator_velocity_ns = -oscillator_velocity_cap;

			// INTEGRATE: x_{n+1} = x_n + v_{n+1}. CLAMP TO THE WORKING
			// WINDOW [floor, max] AS A FINAL SAFETY RAIL; THE SPRING
			// EQUILIBRIUM ITSELF IS PRE-CLAMPED INTO THIS RANGE IN
			// apply_tau_scaling() SO THE SPRING NEVER PULLS OUT OF BOUNDS.
			s64 nc = (s64)codel_target_ns + oscillator_velocity_ns;
			if (nc < (s64)codel_target_floor_ns)
				nc = (s64)codel_target_floor_ns;
			if (nc > (s64)codel_target_max_ns)
				nc = (s64)codel_target_max_ns;
			codel_target_ns = (u64)nc;

			// THE LOOP IS CLOSED BY CONSTRUCTION: the overflow gate and
			// STEP 2 read codel_target_ns itself, so
			// global_rescue_count -> codel_target_ns -> rescue rate ->
			// global_rescue_count closes with no shadow copy to track.

			// RESERVOIR UPDATE: POST-INTEGRATE STATE, VALUES ALREADY
			// IN HAND -- THE ENVELOPE READS WHAT THE RECOMPUTE JUST
			// MAINTAINED, IT NEVER DERIVES ANYTHING OF ITS OWN
			// (FREE-COMPUTE). DECAYED ACCUMULATION RATHER THAN
			// INSTANTANEOUS ENERGY: INSTANTANEOUS RIPPLES AT 2w AND
			// A CADENCE KEYED TO IT WOULD PUMP THE TRANSIENT IT IS
			// DAMPING (PARAMETRIC RESONANCE).
			{
				s64 ed = (s64)codel_target_ns -
					 (s64)codel_seed_ns;
				s64 ev = oscillator_velocity_ns;
				osc_env_energy -=
					osc_env_energy >> OSC_ENV_DECAY_SHIFT;
				osc_env_energy +=
					(u64)(ed * ed) + (u64)(ev * ev);
			}
		osc_env_done: ;
		}
	}

	if (s) {
		s->longrun_mode_active = longrun_mode ? 1 : 0;
	}

	// THIS CPU'S DOMAIN OVERFLOW AGE. THE PER-CPU SOJOURN ENFORCEMENT BELOW IS
	// DOMAIN-LOCAL; longrun_mode IS CPU-0-ONLY AND SO TRACKS CPU 0'S DOMAIN.
	// ONE STAMP, ONE QUEUE, AND ANY WAITER QUALIFIES.
	u32 tdom = cpu_domain_of(scx_bpf_task_cpu(p));
	u64 bens = sojourn_stamp_overflow[tdom & (MAX_OVERFLOW_DOMAINS - 1)].ns;
	if (bens > 0) {
		u64 now = bpf_ktime_get_ns();
		u64 sojourn = now - bens;
		if (s)
			s->batch_sojourn_ns = sojourn;

		// LONGRUN DETECTION: THE OVERFLOW DSQ NON-EMPTY FOR LONGER THAN
		// longrun_thresh_ns (TAU-SCALED, ~2S AT THE 12C REFERENCE).
		//   task_slice        INTERACTIVE TASKS SWITCH TO burst_slice_ns,
		//                     YIELDING THE CPU FASTER UNDER PRESSURE.
		//   tick, BELOW       preempt_thresh_ns IS SHIFTED BY
		//                     longrun_preempt_shift, GIVING BATCH MORE ROPE.
		// CPU 0 IS THE SOLE WRITER, MATCHING THE OSCILLATOR AND TAU STATICS.
		if (bpf_get_smp_processor_id() == 0)
			longrun_mode = sojourn > longrun_thresh_ns;

		// SOJOURN ENFORCEMENT: IF THE OVERFLOW QUEUE HAS STARVED PAST ITS
		// BOUND, KICK THIS CPU TO FORCE A DISPATCH OF THE BURIED TASK. PER-CPU,
		// SO EACH CPU SELF-PREEMPTS WHEN IT IS THE ONE HOGGING.
		// IT PREEMPTS INTERACTIVE RUNNERS TOO. UNDER A FORK STORM THE CORES RUN
		// A CONVEYOR BELT OF SHORT INTERACTIVE WORKERS, EACH YIELDING FAST ONLY
		// FOR THE NEXT ONE, SO THE BURIED TASK NEVER GETS IN.
		// THE BOUND IS codel_target_ns, THE LIVE OVERFLOW GATE, NOT THE TIGHTER
		// ADAPTIVE codel_thresh -- STEP 0/1 ONLY FALL THROUGH TO SERVE OVERFLOW
		// AT codel_target_ns, SO AN EARLIER KICK JUST LETS THE FREED CORE GRAB
		// ANOTHER STORM WORKER.
		// A DECLARED RT POLICY ANSWERS TO lag_cap_ns INSTEAD. SCHED_FIFO/RR IS A
		// CONTRACT USERSPACE STATED, NOT A CHARACTER THIS SCHEDULER GUESSED, AND
		// IT IS STILL BOUNDED -- BY THE STARVATION BOUND RATHER THAN THE SERVICE
		// BOUND.
		u64 net_bound = (p->policy == SCHED_FIFO || p->policy == SCHED_RR)
			      ? lag_cap_ns : codel_target_ns;
		if (sojourn > net_bound) {
			scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
			// RE-ARM ON FIRE, SO `sojourn` READS TIME SINCE THIS OVERFLOW
			// QUEUE WAS LAST SERVICED RATHER THAN ITS CONTINUOUS-OCCUPANCY
			// AGE. WITHOUT IT, SATURATION PUTS THE AGE PAST net_bound ONCE
			// AND KEEPS IT THERE, AND EVERY TICK ON EVERY CPU IN THE DOMAIN
			// SELF-PREEMPTS THE TASK THE SCHEDULER JUST CHOSE. THIS
			// SELF-LIMITS TO ONE PREEMPT PER net_bound PER DOMAIN.
			// CLEAR-OR-REARM, NOT A BARE STORE -- IF THE QUEUE DRAINED IN
			// THE MEANTIME THE STAMP MUST GO TO ZERO.
			stamp_clear_or_rearm(domain_inter_dsq(tdom),
					     &sojourn_stamp_overflow[tdom & (MAX_OVERFLOW_DOMAINS - 1)].ns);
			if (!s)
				s = get_stats();
			if (s)
				s->nr_preempt += 1;
			return;
		}
	} else {
		if (bpf_get_smp_processor_id() == 0)
			longrun_mode = false;
		if (s)
			s->batch_sojourn_ns = 0;
	}

	// PER-CPU DSQ SOJOURN: CHECK OWN DSQ + ROTATING GLOBAL SCAN.
	// LOCAL CHECK: CATCHES STALE TASKS ON THIS CPU.
	// GLOBAL SCAN: CATCHES STALE TASKS ON IDLE CPUS WHERE tick() NEVER
	// FIRES. ROTATES 4 CPUS PER TICK SO ALL CPUS GET COVERED OVER TIME.
	{
		u32 this_cpu = bpf_get_smp_processor_id();
		u64 now2 = bpf_ktime_get_ns();
		u64 codel_thresh_ns = knobs
			? knobs->codel_thresh_ns : 5000000;

		// LOCAL: OWN PER-CPU DSQ
		if (this_cpu < MAX_CPUS) {
			u64 pcpu_oldest = sojourn_stamp_pcpu[this_cpu].ns;
			if (pcpu_oldest > 0 &&
			    (now2 - pcpu_oldest) > codel_thresh_ns) {
				if (pcpu_kick_if_waiter(this_cpu))
					return;
			}
		}

		// REMOTE PER-CPU DSQ SCAN.
		// CARVE-OUT (SEE topology.rs): THIS IS A COVERAGE BUDGET OVER
		// THE ACTIVE CPU RANGE, NOT A TIMING DECISION -- nr_cpu_ids IS
		// THE NATURAL UNIT, NOT tau.
		// AT nr_cpu_ids <= 4 THE BUDGET OF 4 ALREADY FITS THE WHOLE
		// TOPOLOGY, SO COVER EVERY ACTIVE CPU EACH TICK; UNCONDITIONAL
		// ROTATION OVER MAX_CPUS=64 WOULD WASTE 94-97% OF SCAN SLOTS
		// ON NONEXISTENT CPUs.
		// AT nr_cpu_ids > 4, ROTATE 4 CPUs PER TICK; WRAP WITHIN THE
		// ACTIVE RANGE VIA MODULO SO THE BUDGET IS SPENT ON REAL CPUs.
		if (nr_cpu_ids > 0) {
			u32 nr = nr_cpu_ids;
			if (nr <= 4) {
				for (u32 i = 0; i < 4; i++) {
					if (i >= nr)
						break;
					// SAME VERIFIER-PORTABLE MASK AS THE nr > 4 BRANCH (Issue #8).
					u32 scan_cpu = i & (MAX_CPUS - 1);
					if (scan_cpu == this_cpu)
						continue;
					u64 remote_stamp = sojourn_stamp_pcpu[scan_cpu].ns;
					if (remote_stamp > 0 &&
					    (now2 - remote_stamp) > codel_thresh_ns)
						pcpu_kick_if_waiter(scan_cpu);
				}
			} else {
				u32 scan_base = (u32)(now2 >> 20);
				for (int i = 0; i < 4; i++) {
					// MASK THE INDEX, DO NOT COMPARISON-SKIP IT. OLDER
					// VERIFIERS CANNOT PROVE (scan_base + i) % nr IS
					// BOUNDED AND REJECT THE INDEXED LOAD WITH "MATH
					// BETWEEN MAP_VALUE POINTER AND REGISTER WITH
					// UNBOUNDED MIN VALUE". & (MAX_CPUS-1) IS THE
					// PORTABLE BOUND; DO NOT REPLACE IT WITH A SKIP.
					u32 scan_cpu =
						((scan_base + (u32)i) % nr) & (MAX_CPUS - 1);
					if (scan_cpu == this_cpu)
						continue;
					u64 remote_stamp = sojourn_stamp_pcpu[scan_cpu].ns;
					if (remote_stamp > 0 &&
					    (now2 - remote_stamp) > codel_thresh_ns)
						pcpu_kick_if_waiter(scan_cpu);
				}
			}
		}
	}

	// PER-CPU PREEMPT: THE SIGNAL IS sojourn_stamp_pcpu[this_cpu], THE OLDEST
	// WAITER'S AGE, SO EACH CPU DECIDES FROM ITS OWN STATE WITH NO GLOBAL TOKEN.
	// THE COARSE codel_thresh NET ABOVE HANDLES THE LONG WAIT; THIS IS THE TIGHT
	// BAND, AND NOTHING IS EXEMPT FROM IT.
	// THE BAND IS codel_target_ns, NOT knobs->preempt_thresh_ns. THE KNOB PAGE IS
	// ALL ZEROS UNDER --no-adaptive, SO A KNOB-DERIVED BAND RESOLVES TO 0 THERE
	// AND THIS BLOCK NEVER FIRES. codel_target_ns IS BPF-DERIVED AND ALWAYS LIVE,
	// SO THE BAND EXISTS IN BOTH MODES. longrun_mode WIDENS IT.
	u32 wcpu = bpf_get_smp_processor_id();
	if (wcpu >= MAX_CPUS)
		return;
	u64 waiter = sojourn_stamp_pcpu[wcpu].ns;
	if (waiter == 0)
		return;

	u64 wnow = bpf_ktime_get_ns();
	u64 wait_age = wnow > waiter ? wnow - waiter : 0;

	// TWO BOUNDS, NEITHER A CLASS. A DECLARED RT POLICY ANSWERS TO THE STARVATION
	// BOUND, lag_cap_ns, 13.3MS AT THE 12C REFERENCE; EVERYTHING ELSE ANSWERS TO
	// THE SERVICE BOUND, codel_target_ns, WHICH OSCILLATES INSIDE
	// [codel_target_floor_ns, codel_target_max_ns] -- 233US TO 665US AT 12C.
	// THE SPLIT IS THE AUDIO QUANTUM. codel_target FALLS INSIDE ONE PipeWire
	// PERIOD, SO A UNIFORM BAND PREEMPTS AN RT THREAD MID-BUFFER WHENEVER A
	// WAITER EXISTS. lag_cap FALLS OUTSIDE ONE, SO RT IS STILL FORCED OFF A CPU
	// IT HAS CAMPED ON, JUST NEVER PART-WAY THROUGH A PERIOD.
	// p->policy IS READ DIRECTLY, SO THE TICK NEEDS NO task_ctx LOOKUP.
	u64 band = (p->policy == SCHED_FIFO || p->policy == SCHED_RR)
		 ? lag_cap_ns : codel_target_ns;
	u64 thresh = longrun_mode ? (band << longrun_preempt_shift) : band;

	if (wait_age >= thresh) {
		if (pcpu_kick_if_waiter(wcpu)) {
			if (!s)
				s = get_stats();
			if (s)
				s->nr_preempt += 1;
		}
	}
}

// ENABLE: NEW TASK ENTERS SCHED_EXT. NO VTIME -- THE SOJOURN KEY IS COMPUTED
// PER-INSERT IN task_deadline(); enable() ONLY INITIALIZES CONTEXT. A NEW TASK
// ENTERS AT "now" LIKE ANY ARRIVAL, NO PENALTY.
void BPF_STRUCT_OPS(pandemonium_enable, struct task_struct *p)
{
	struct task_ctx *tctx = ensure_task_ctx(p);
	if (tctx) {
		tctx->ran_since_wake = false;
		tctx->run_exec_at = 0;
		tctx->charge_ns = 0;
		tctx->charge_cpu = -1;
		tctx->last_woke_at = bpf_ktime_get_ns();
		tctx->cached_weight = WEIGHT_INTERACTIVE;
		tctx->last_waker_pid = -1;  // NO PARTNER SEEN YET
		tctx->same_waker_runs = 0;
		tctx->standing_runs = 0;   // NO SERVICE RENDERED YET
		tctx->dispatch_path = 0;
		// -1 = NEVER RAN. select_cpu's WARM PATH ANCHORS A last_cpu < 0 TASK
		// ON prev_cpu, THE PARENT'S CPU AT FORK, SO IT WARM-ROUTES INSTEAD OF
		// ALIASING CPU 0 OR SCATTERING VIA THE NODE-WIDE dfl PICK.
		tctx->last_cpu = -1;
		tctx->home_cpu = -1;   // PINNED ON FIRST RUN, IN stopping()
	}
}

// INIT: DETECT TOPOLOGY, CREATE DSQs, CALIBRATE
s32 BPF_STRUCT_OPS_SLEEPABLE(pandemonium_init)
{
	u32 zero = 0;

	nr_nodes = __COMPAT_scx_bpf_nr_node_ids();
	if (nr_nodes < 1)
		nr_nodes = 1;
	if (nr_nodes > nr_cpu_ids)
		nr_nodes = nr_cpu_ids;

	// PER-CPU DSQs. select_cpu AND ENQUEUE TIER 1/2 SEAT WAKEES ON A WARM
	// PER-CPU DSQ, CACHE-HOT AND STEALABLE; TIER 3 AND THE AFFINITY ESCAPE FALL
	// TO domain_inter_dsq.
	// VISIBILITY LAYERS:
	//   1. L2 WORK STEALING IN DISPATCH -- IDLE CPUs PULL FROM SIBLINGS
	//   2. ROTATING TICK SCAN -- CATCHES STALE TASKS ON IDLE CPUs
	//   3. PER-CPU SOJOURN RESCUE -- THRESHOLD CEILING ON INVISIBILITY
	for (u32 i = 0; i < nr_cpu_ids && i < MAX_CPUS; i++)
		scx_bpf_create_dsq(i, -1);

	// CREATE THE PER-DOMAIN OVERFLOW DSQs. ALL MAX_OVERFLOW_DOMAINS SLOTS ARE
	// PRE-ALLOCATED AND nr_overflow_domains, WRITTEN BY RUST POST-LOAD, GATES
	// WHICH ARE LIVE -- A FEW UNUSED DSQ HEADERS IN EXCHANGE FOR AVOIDING THE
	// BOOTSTRAP ORDER PROBLEM, SINCE pandemonium_init RUNS BEFORE TOPOLOGY
	// DETECT. THEY ARE L3-SCOPED, SO STEP 3's DRAIN STAYS DOMAIN-LOCAL.
	for (u32 i = 0; i < MAX_OVERFLOW_DOMAINS; i++)
		scx_bpf_create_dsq(nr_cpu_ids + 2ULL * MAX_NODES + i, -1);

	// ALL TIMING-CONSTANT AND OSCILLATOR-DYNAMICS STATICS BELOW ARE DERIVED
	// FROM tau (Fiedler-based time constant) VIA apply_tau_scaling() AT THE
	// FIRST CPU-0 TICK. MIDPOINT CONSTANTS HERE PROVIDE SANE BEHAVIOR DURING
	// THE ~1MS WINDOW BETWEEN struct_ops ATTACH AND THAT FIRST TICK. THEY
	// ARE OVERWRITTEN IMMEDIATELY -- DON'T READ SIGNIFICANCE INTO THEM.
	codel_starve_ns            = 100000000ULL;  // 100ms midpoint of [20, 500]
	codel_target_floor_ns      =    500000ULL;  // 500us midpoint of [200, 800]
	pcpu_spill_search_budget   = 6;             // 12C MIDPOINT
	affinity_search_online     = 3;             // 12C MIDPOINT
	lag_cap_ns                 = 40000000ULL;   // 40MS, MIDPOINT OF [8, 80]
	longrun_preempt_shift      = 0;             // NO BOOST UNTIL tau CONFIRMS 2C
	oscillator_damping_shift   = 3;
	oscillator_spring_shift    = 7;             // = 2*3+1, BUTTERWORTH-OPTIMAL
	                                            //   (ζ ≈ 0.707, ~4.3% overshoot)
	oscillator_pull_scale      = 3;
	oscillator_velocity_cap    = (s64)((u64)OSC_VELOCITY_CAP_PER_PULL * 3);
	// START PERMISSIVE. LET THE DAMPED OSCILLATION FIND THE RIGHT CENTER.
	// RESCUES PULL IT DOWN. NO STATIC FORMULA. THE WAVE FUNCTION DOES THE WORK.
	codel_target_ns = codel_target_max_ns;
	oscillator_velocity_ns = 0;
	prev_rescue_snapshot = 0;
	global_rescue_count = 0;

	longrun_mode = false;

	// INITIALIZE DEFAULT TUNING KNOBS
	struct tuning_knobs *knobs = bpf_map_lookup_elem(&tuning_knobs_map, &zero);
	if (knobs) {
		knobs->slice_ns = 1000000;
		knobs->preempt_thresh_ns = 1000000;
		knobs->batch_slice_ns = 20000000;        // 20MS FLAT DEFAULT
		knobs->affinity_mode = 0;                // OFF BY DEFAULT (RUST SETS PER REGIME)
		knobs->codel_thresh_ns = 5000000;        // 5MS DEFAULT (RUST OVERRIDES)
		knobs->burst_slice_ns = 1000000;         // 1MS DEFAULT (BURST/LONGRUN CEILING)
		knobs->topology_tau_ns = 0;              // RUST WRITES AT TOPOLOGY DETECT
		knobs->codel_eq_ns = 0;                  // RUST WRITES AT TOPOLOGY DETECT
	}

	// BELT-AND-SUSPENDERS: DERIVE tau-SCALED STATICS IMMEDIATELY IF RUST
	// SOMEHOW WROTE topology_tau_ns BEFORE THIS INIT RUNS (struct_ops
	// RELOAD, HOT PATH RACE). NORMAL CASE IS knobs->topology_tau_ns == 0
	// HERE, IN WHICH CASE apply_tau_scaling() SHORT-CIRCUITS ON THE
	// tau_ns == 0 CHECK AND THE MIDPOINT FALLBACKS SET ABOVE STAND UNTIL
	// THE FIRST TICK AFTER RUST WRITES tau.
	apply_tau_scaling(knobs ? knobs->topology_tau_ns : 0,
	                  knobs ? knobs->codel_eq_ns : 0);

	return 0;
}

// EXIT: RECORD EXIT INFO FOR USERSPACE
void BPF_STRUCT_OPS(pandemonium_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

// EXIT_TASK: PER-TASK CLEANUP ON DEATH. BPF_F_NO_PREALLOC TASK
// STORAGE AUTO-FREES task_ctx, SO THIS HOOK IS NOT REQUIRED FOR
// MEMORY CORRECTNESS. WE STILL DEFINE IT TO:
//   1. ZERO HOT-PATH TIMESTAMPS DEFENSIVELY (sleep_start_ns)
//      -- ANY STALE READ IN THE NARROW WINDOW
//      BEFORE STORAGE GC SEES ZEROS, NOT GARBAGE.
//   2. PROVIDE A SYMMETRIC HOOK FOR FUTURE PER-TASK CLEANUP --
//      MATCHES THE lavd / rusty / layered / flow PATTERN ACROSS
//      THE SCHED_EXT ECOSYSTEM.
void BPF_STRUCT_OPS(pandemonium_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	ledger_refund(tctx);   // a dying task owes its seat nothing
	tctx->sleep_start_ns = 0;
}

// QUIESCENT: TASK GOES TO SLEEP -- RECORD TIMESTAMP FOR SLEEP ANALYSIS
void BPF_STRUCT_OPS(pandemonium_quiescent, struct task_struct *p,
		    u64 deq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (tctx) {
		tctx->sleep_start_ns = bpf_ktime_get_ns();
		ledger_refund(tctx);
		// A SLEEPING TASK IS NOT QUEUE-WAITING. WITHOUT THIS, A TASK QUEUED,
		// DEQUEUED UNRUN (SETAFFINITY / CANCELLED WAKE) AND THEN SLEPT COMES
		// BACK HOLDING A SECONDS-OLD CLAIM AND SORTS AHEAD OF THE MACHINE.
		tctx->wait_since = 0;
	}
}

// CPU RELEASE: RESCUE STRANDED TASKS WHEN RT/DL PREEMPTS OUR CPU.
// CALLED WHEN THE KERNEL TAKES A CPU AWAY FROM SCHED_EXT (DEADLINE
// SERVER, RT CLASS). WITHOUT THIS, TASKS THAT dispatch() MOVED TO
// THE LOCAL DSQ VIA scx_bpf_dsq_move_to_local(, 0) GET STUCK, TRIGGERING
// THE WATCHDOG.
void BPF_STRUCT_OPS(pandemonium_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	// PORTABLE CALL: scx_bpf_reenqueue_local() RETURNS void ON NEWER KERNELS AND
	// THROUGH scx's compat.bpf.h SHIM, SO CAPTURING ITS RETURN COMPILES ONLY ON
	// OLDER ONES. CALLED AS void -- THE RE-ENQUEUE STILL HAPPENS, BUT THE
	// nr_reenqueue STAT IS NOT PORTABLY COUNTABLE HERE.
	// THE BUDGET IS PER TARGET CPU AND THE FALLBACK IS UNCONDITIONAL. A NEGATIVE
	// cpu CARRIES NO SLOT TO CHARGE, SO IT REENQUEUES RATHER THAN BEING DROPPED
	// -- THE THROTTLE BOUNDS A RATE, NEVER A TASK'S ONLY RESCUE.
	if (cpu >= 0) {
		u32 c = (u32)cpu & (MAX_CPUS - 1);
		u64 now = bpf_ktime_get_ns();
		u64 cr = reenq_credit[c] + (now - reenq_last[c]);
		if (cr > REENQ_BURST_NS)
			cr = REENQ_BURST_NS;
		reenq_last[c] = now;
		if (cr >= REENQ_MIN_INTERVAL_NS) {
			reenq_credit[c] = cr - REENQ_MIN_INTERVAL_NS;
			scx_bpf_reenqueue_local();   // BUDGET ALLOWS: MIGRATE LOCAL TASKS
		} else {
			reenq_credit[c] = cr;        // THROTTLED: LEAVE TASKS LOCAL
		}
	} else {
		scx_bpf_reenqueue_local();
	}
}

// CPU HOTPLUG CALLBACKS
// SUSPEND/RESUME: KERNEL PM CALLS scx_bypass(true) BEFORE SUSPEND,
// DEQUEUES ALL TASKS FROM BPF DSQs. CPUs GO OFFLINE ONE BY ONE.
// ON RESUME, CPUs COME BACK, scx_bypass(false), BPF TAKES OVER.
// STALE TIMESTAMPS AND COUNTERS FROM PRE-SUSPEND CAUSE THE DISPATCH
// WATERFALL TO MALFUNCTION FOR 30-40s POST-RESUME, STARVING
// LATENCY-CRITICAL TASKS UNTIL THE WATCHDOG KILLS THE SCHEDULER.
// FIX: CLEAR PER-CPU AND GLOBAL STATE ON HOTPLUG TRANSITIONS.

// HOTPLUG STAMP CLEARS GO THROUGH stamp_clear_or_rearm: A RAW UNCONDITIONAL
// OVERWRITE (__sync_lock_test_and_set(..., 0)) WIPES A CONCURRENT ENQUEUE'S
// ARM (0 -> now) LANDING IMMEDIATELY BEFORE IT WHILE THE ENQUEUE'S TASK STAYS
// QUEUED -- THE IDENTICAL STRANDING CLASS THE DRAIN-CLEAR TAIL CLOSES.
// last_tau_snapshot, THE OSCILLATOR FEEDBACK AND THE RESCUE COUNTERS STAY
// RAW: PLAIN RESETS, NO DSQ-EMPTINESS CONTRACT FOR THE REARM TO HONOR.

void BPF_STRUCT_OPS(pandemonium_cpu_online, s32 cpu)
{
	// HOTPLUG ZEROES THE SEAT'S LEDGER. CHARGES OWED BY TASKS THAT WERE ON IT
	// CAN NO LONGER BE REFUNDED THROUGH THIS CPU, AND backlog_ns() FLOORS AT
	// ZERO, SO A LATE REFUND IS ABSORBED RATHER THAN UNDERFLOWING.
	if ((u32)cpu < MAX_CPUS) {
		pcpu_ledger[cpu].admitted_ns  = 0;
		pcpu_ledger[cpu].completed_ns = 0;
	}
	if ((u32)cpu < MAX_CPUS)
		stamp_clear_or_rearm((u64)cpu, &sojourn_stamp_pcpu[cpu].ns);
	// FORCE THE NEXT CPU-0 TICK TO RE-DERIVE tau-SCALED STATICS. RUST WILL
	// HAVE RECOMPUTED lambda_2 AGAINST THE NEW TOPOLOGY AND WRITTEN A FRESH
	// topology_tau_ns; CLEARING THE SNAPSHOT MAKES apply_tau_scaling() PICK
	// IT UP INSTEAD OF SHORT-CIRCUITING ON THE STALE VALUE. ATOMIC STORE
	// PAIRS WITH apply_tau_scaling()'s CAS SO A CONCURRENT TICK CAN'T
	// OVERWRITE THIS CLEAR.
	__sync_lock_test_and_set(&last_tau_snapshot, 0);
}

void BPF_STRUCT_OPS(pandemonium_cpu_offline, s32 cpu)
{
	// HOTPLUG ZEROES THE SEAT'S LEDGER. CHARGES OWED BY TASKS THAT WERE ON IT
	// CAN NO LONGER BE REFUNDED THROUGH THIS CPU, AND backlog_ns() FLOORS AT
	// ZERO, SO A LATE REFUND IS ABSORBED RATHER THAN UNDERFLOWING.
	if ((u32)cpu < MAX_CPUS) {
		pcpu_ledger[cpu].admitted_ns  = 0;
		pcpu_ledger[cpu].completed_ns = 0;
	}
	if ((u32)cpu < MAX_CPUS)
		stamp_clear_or_rearm((u64)cpu, &sojourn_stamp_pcpu[cpu].ns);
	__sync_lock_test_and_set(&last_tau_snapshot, 0);

	for (u32 c = 0; c < MAX_OVERFLOW_DOMAINS; c++) {
		stamp_clear_or_rearm(domain_inter_dsq(c),
				     &sojourn_stamp_overflow[c].ns);
	}

	// RESET OSCILLATOR FEEDBACK TO AVOID STALE DELTA POST-SUSPEND
	__sync_lock_test_and_set(&global_rescue_count, 0);
	prev_rescue_snapshot = 0;
	oscillator_velocity_ns = 0;
}

SCX_OPS_DEFINE(pandemonium_ops,
	       .select_cpu   = (void *)pandemonium_select_cpu,
	       .enqueue      = (void *)pandemonium_enqueue,
	       .dispatch     = (void *)pandemonium_dispatch,
	       .runnable     = (void *)pandemonium_runnable,
	       .running      = (void *)pandemonium_running,
	       .stopping     = (void *)pandemonium_stopping,
	       .tick         = (void *)pandemonium_tick,
	       .enable       = (void *)pandemonium_enable,
	       .quiescent    = (void *)pandemonium_quiescent,
	       .cpu_release  = (void *)pandemonium_cpu_release,
	       .cpu_online   = (void *)pandemonium_cpu_online,
	       .cpu_offline  = (void *)pandemonium_cpu_offline,
	       .init         = (void *)pandemonium_init,
	       .exit_task    = (void *)pandemonium_exit_task,
	       .exit         = (void *)pandemonium_exit,
	       .flags        = SCX_OPS_BUILTIN_IDLE_PER_NODE |
			       SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms   = 10000,
	       .name         = "pandemonium");