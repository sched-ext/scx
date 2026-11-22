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
//   ENQUEUE TIER 3 FALLBACK    -> A REQUEUE ON ITS OWN CPU'S LANE
//   DISPATCH -> SWEEP, AGED LANE, OWN SEAT, SEAT STEAL, OWN LANE, LANE STEAL,
//               KEEP
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

// A TASK THAT HAS NOT BLOCKED ACROSS THIS MANY CONSECUTIVE STOPS DOES NOT
// SLEEP: THE EVIDENCE THE PAIR LEDGER ASKS BEFORE IT NAMES A PARTNER.
#define SLEEPLESS_CONFIRM PAIR_OBS_MIN


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

// A REQUEUE THIS SOON AFTER ITS OWN CUT IS THE CUT'S KICK LANDING ON THE WAKEE
// (THE MEASURED STALLS RAN 5-8US AFTER THE WAKE BEFORE THE KICK HIT).
#define CUT_SELF_KICK_NS        50000ULL

// FIEDLER-SCALED TIMING CONSTANTS, Q16 DIMENSIONLESS RATIOS.
// target_ns = K_i * tau / 65536. EACH K_i IS A DIMENSIONLESS RATIO TO tau AND
// APPLIES TO EVERY TOPOLOGY UNCHANGED -- ONLY tau VARIES, 13.3MS AT THE 12C
// REFERENCE. K_LAG_CAP = 1.0 IS ONE COMMUTE TIME OF THE TOPOLOGY GRAPH.
#define K_Q16_SHIFT             16
#define K_CODEL_FLOOR             1147u   // 0.0175
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
// nr_domains: NUMBER OF DISTINCT L3 cache DOMAINS IN llc_domain[]. SET BY RUST AT
// TOPOLOGY DETECT VIA write_nr_domains (.data SECTION, POST-LOAD MUTABLE). MORE
// THAN ONE ARMS THE TIGHT SEAT.
volatile u32 nr_domains = 1;

// affinity_domain_peers: HOW MANY affinity_rank SLOTS STAY INSIDE A CPU'S OWN
// cache DOMAIN. WRITTEN BY RUST AT TOPOLOGY DETECT AS THE MINIMUM OVER CPUs,
// FLOORED AT 1, SO A BUDGET BOUNDED BY IT CANNOT LEAVE ANY CPU'S DOMAIN.
// affinity_rank IS SORTED BY R_eff ASCENDING, SO EVERY SAME-DOMAIN PEER PRECEDES
// EVERY CROSS-DOMAIN ONE AND THIS ALONE DECIDES WHETHER find_idle_by_affinity
// MAY LEAVE THE DOMAIN.
// INITIALISED TO 3, THE LEGACY CLAMP FLOOR, NOT TO ZERO. A ZERO INITIALISER
// PLACES IT IN .bss RATHER THAN .data, WHERE THE POST-LOAD WRITER CANNOT REACH.
volatile u32 affinity_domain_peers = 3;

// NO GLOBAL PREEMPT FLAG: tick() DERIVES THE DECISION PER-CPU FROM ITS OWN
// QUEUE'S WAIT (pcpu_qclock) AGAINST ITS BAND, AND THE SEAT'S JUDGE PACES IT.
// PER-CPU SO NO TOKEN FOR CPUs TO RACE OVER.

// THE QUEUE CLOCK. ONE CACHE LINE PER QUEUE, WRITTEN AS TASKS ARRIVE AND LEAVE
// AND READ BY EVERY QUESTION ABOUT HOW LONG WORK HAS WAITED THERE. CoDel
// MEASURES SOJOURN AS AN ITEM LEAVES, AND THIS IS WHERE IT IS TAKEN.
//   arrivals, departures  EQUAL COUNTS ARE AN EMPTY QUEUE; NO DRAIN ERASES A COUNT
//   progress_ns           THE LAST DEPARTURE, OR THE ARRIVAL THAT MADE AN EMPTY
//                         QUEUE NON-EMPTY
//   last_sojourn_ns       THE WAIT OF THE LATEST TASK TO LEAVE TO RUN
//   next_act              THE EARLIEST THE JUDGE MAY ACT ON THIS QUEUE AGAIN
//   acts                  ACTS SINCE THE WAIT ROSE PAST ITS BOUND (CoDel's count)
//   resumed_n, resumed_since  A LANE'S ONLY: THE TASKS RESUMED AT ITS HEAD
//                         (enqueue's TIER 3) AND WHEN THE OLDEST OF THEM BEGAN
//                         TO WAIT. THEY STAND AHEAD OF THE QUEUE AND ARE IN NONE
//                         OF THE COUNTS ABOVE: THE CLOCK KEEPS READING THE
//                         LANE'S OWN WORK
//   cut_ns                A SEAT'S ONLY: WHEN THE LATEST CUT ONTO IT WAS MADE.
//                         WRITTEN BY seat_task, READ BY AGE AT enqueue's TIER 3,
//                         NEVER CLEARED
struct queue_clock {
	u64 arrivals;
	u64 departures;
	u64 progress_ns;
	u64 last_sojourn_ns;
	u64 next_act;
	u64 acts;
	u32 resumed_n;
	union {
		u64 resumed_since;
		u64 cut_ns;
	};
} __attribute__((aligned(64)));

// floor(sqrt(n)) FOR n IN [0, QCLOCK_ACTS_CAP]. THE CONTROL LAW'S DIVISOR, AS A
// TABLE BECAUSE BPF HAS NO FLOATING POINT.
#define QCLOCK_ACTS_CAP 64
static const u8 qclock_isqrt[QCLOCK_ACTS_CAP + 1] = {
	0, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8
};
static struct queue_clock pcpu_qclock[MAX_CPUS];
// THE LANE: EACH CPU'S SECOND QUEUE, FOR ITS OWN PLAIN REQUEUES. THE SEAT
// (pcpu_qclock, DSQ cpu) TAKES WAKES AND PARTNERS; THE LANE (lane_qclock, DSQ
// nr_cpu_ids + cpu) TAKES WHAT WAS PASSED OVER OR CUT. A WAKE NEVER SORTS
// BEHIND AN OLDER REQUEUE, AND THE SEAT'S CLOCK READS ONLY WHAT WAITS TO START:
// THE CLASS SPLIT THE DOMAIN QUEUE MADE BY ROUTING, KEPT ON EACH CPU.
static struct queue_clock lane_qclock[MAX_CPUS];

// EVERY PER-CPU ARRAY INDEX GOES THROUGH cpu_slot(). THE
// INPUT PASSES A COMPILER BARRIER BEFORE THE MASK, SO CLANG KNOWS NOTHING OF
// ITS RANGE AND MUST EMIT THE AND ON THE REGISTER THAT INDEXES. WITHOUT IT
// CLANG PROVES THE MASK REDUNDANT FROM AN EARLIER COMPARE AND DELETES IT, THE
// COMPARE AND THE INDEX REACH THE VERIFIER ON DIFFERENT SPILLED COPIES, AND
// THE STORE IS REJECTED AS AN UNBOUNDED ACCESS. THE BARRIER AFTER THE MASK
// PINS NOTHING: THE AND IS GONE BY THEN.
static __always_inline u32 cpu_slot(u32 cpu)
{
	asm volatile("" : "+r"(cpu));
	return cpu & (MAX_CPUS - 1);
}

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
// THE DISTANCE. tau's IS 0.0005 OF tau; THE ADAPTIVE LAYER's IS THE REFILL IT
// MEASURED (intf.h phi_base_ns). BOTH HOLD TO intf.h's RAIL. tick() RESOLVES
// WHICH STANDS INTO THE APPLIED COST, EXPOSED (NON-STATIC) SO THE LAYER EMITS IT
// BESIDE WHAT IT WROTE.
#define K_PHI_BASE_Q16   33ULL          // 0.0005 in Q16
static u64 phi_base_tau_ns = 20000ULL;  // tau's; init fallback until tau lands
u64 phi_base_cost_ns = 20000ULL;        // APPLIED (READ BY THE ADAPTIVE LOOP)

// PAIR-WARM SEAT MARKER -- THE STEAL-SIDE HALF OF TIGHT-PAIR COLOCATION.
// THE SEAT SITES STAMP THE PARTNER'S PER-CPU SEAT HERE; STEP 1'S STEAL READS IT
// IN ONE INDEXED LOOKUP, NO REMOTE task_ctx DEREF, AND PRICES THE SPLIT BY THE
// domain_phi SEAM. A PRICE, NOT A GATE -- A STARVING TASK IS STILL STOLEN AT A
// LONGER SOJOURN.
static u64 pair_warm_ns[MAX_CPUS];

// WHEN EACH CPU's RESIDENT LAST BEGAN TO RUN, STAMPED IN running() ON THAT CPU.
// A REMOTE READER GETS THE RESIDENT's SERVICE IN THIS RUN EXACTLY, WHERE ITS
// scx.slice MOVES ONLY AT THAT CPU's TICK OR NEXT SCHEDULING EVENT.
static u64 run_start_ns[MAX_CPUS];

// WHETHER EACH CPU's RESIDENT HAS KEPT RUNNING THROUGH ITS LAST
// SLEEPLESS_CONFIRM STOPS: SET IN running() ON THAT CPU, CLEARED IN stopping().
// A REMOTE READER LEARNS THE RESIDENT NEVER BLOCKS IN ONE INDEXED LOAD.
static u8 resident_sleepless[MAX_CPUS];

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
// REFERENCE: NICHOLS-JACOBSON CoDel (ACM QUEUE 2012, RFC 8289) + DAMPED OSCILLATOR.
#define OSCILLATOR_PULL_NS  8000     // BASE TIGHTEN IMPULSE

// THE KERNEL'S TICK RATE, FOR THE DEPTH RING'S BUCKET WIDTH. WEAK: A KERNEL
// THAT EXPOSES NO KCONFIG READS 0 AND THE BUCKET FALLS BACK TO HZ=1000.
extern int CONFIG_HZ __kconfig __weak;

// DEPTH RING BUCKET WIDTH (NS), DERIVED IN apply_tau_scaling() FROM THE
// OSCILLATOR'S DAMPED PERIOD. 0 UNTIL tau ARRIVES; THE TICK SAMPLES NOTHING
// BEFORE THEN.
static u64 depth_bucket_ns;

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
// EXPOSED TO USERSPACE (NON-STATIC) SO THE ADAPTIVE LOOP CAN READ OSCILLATOR
// STATE AND DEFER A KNOB WRITE WHILE THE OSCILLATOR IS ALREADY RESPONDING.
// WITHOUT THIS, TWO CONTROLLERS CORRECT THE SAME ERROR.
u64 codel_target_floor_ns;         // CORE-SCALED FLOOR FOR TARGET
// ADAPTIVE STATE
u64 codel_target_ns;          // ADAPTIVE CENTER (READ BY THE ADAPTIVE LOOP)
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

// THE OSCILLATOR'S CEILING, tau-DERIVED IN apply_tau_scaling(). THE INITIAL
// VALUE IS THE PRE-tau FALLBACK.
u64 codel_target_max_ns = 2000000ULL;             // READ BY THE ADAPTIVE LOOP

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
	// topology_tau_ns AND codel_eq_ns MUST HOLD THE SAME VALUE ON EVERY CPU OR
	// TAU-SCALING DIVERGES BY WHICHEVER CPU OBSERVED.
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct depth_ring);
} depth_ring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_row);
} flow_rows SEC(".maps");

// THE REFILL LEDGER (intf.h struct refill_ring): stopping() APPENDS, THE 1HZ
// LOOP DRAINS WHAT IS NEW SINCE ITS LAST READ AND PAIRS IT PER TASK.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct refill_ring);
} refill_ring SEC(".maps");

// CACHE DOMAIN MAP: l2_domain[cpu] = group_id
// POPULATED BY RUST AT STARTUP FROM SYSFS TOPOLOGY
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cache_domain SEC(".maps");

// EMERGENT DOMAIN MAP: cpu_domain[cpu] = DOMAIN ID FROM THE MIN-CONDUCTANCE
// TREE, PARTITIONED AT L3 GRANULARITY. THE SPILL STAYS INSIDE A DOMAIN, THE
// SCATTER COUNTERS COUNT CROSSINGS OF ONE AND THE DEPTH RING CARRIES IT.
// POPULATED BY RUST AT TOPOLOGY DETECT; READ BY cpu_domain_of().
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cpu_domain SEC(".maps");

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
// ALL-ZERO UNTIL RUST WRITES IT AT TOPOLOGY DETECT, GIVING A FLAT codel_target.
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
// codel_target, TWO ORDERS SMALLER, SO THEY MULTIPLY THIS FRACTION BY THAT
// YARDSTICK INSTEAD.
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
	u64 queued_on;       // DSQ ID + 1 OF THE QUEUE THIS TASK SITS ON, 0 = NONE.
	                     // SET ON INSERT, CLEARED BY ITS DEPARTURE.
	u64 run_exec_at;     // p->se.sum_exec_runtime AT running(). THE SERVICE LEDGER'S
	                     // BASE: stopping() DIFFS IT FOR TIME THE TASK ACTUALLY RAN,
	                     // WHICH IS ELAPSED MINUS THE IRQ TIME INSIDE THE WINDOW.
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
	s32 last_wakee_pid;  // PID THIS TASK MOST RECENTLY WOKE: THE WAKER'S SIDE OF
	                     // THE LEDGER. -1 = NONE YET.
	u32 same_wakee_runs; // CONSECUTIVE WAKES OF last_wakee_pid BY THIS TASK,
	                     // SATURATING. A 1:1 EXCHANGE CLIMBS IT; A PRODUCER
	                     // WAKING ITS WORKERS IN TURN RESETS IT EVERY WAKE.
	s32 last_cpu;        // LAST CPU THIS TASK RAN ON (FOR CACHE AFFINITY)
	s32 home_cpu;        // STABLE PLACEMENT HOME: PINNED TO THE FIRST CPU THE
	                     // TASK RAN ON; NEVER CHASES last_cpu. WARM-STAY ANCHOR
	                     // SO THE TASK RETURNS HOME INSTEAD OF DRIFTING. THE
	                     // RESTORING FORCE -- SEE THE ANCHOR IN warm_seat_pick.
	u8  dispatch_path;   // 0=IDLE, 1=HARD_KICK, 2=SOFT_KICK
	u8  ran_since_wake;  // is_wakeup = !ran_since_wake; SET 1 IN running(), 0 ON WAKE
	u8  sync_wake;       // THIS WAKE CARRIED SCX_WAKE_SYNC. SET IN select_cpu, WHICH
	                     // RUNS BEFORE enqueue ON THE SAME WAKE; CLEARED IN running().
	u8  fanout_wake;     // THIS WAKE CAME FROM A FAN-OUT WAKER (fanout_wake()). SET
	                     // IN select_cpu WITH sync_wake; CLEARED IN running().
	u8  idle_seat;       // select_cpu SEATED THIS WAKE ON AN IDLE CPU, COUNTED IN
	                     // nr_idle_hits. running() ADDS IT TO THE RING; CLEARED THERE.
	u32 wake_waker;      // PID + 1 OF THIS WAKE'S WAKER, 0 = NONE. STAMPED IN
	                     // select_cpu, WHERE THE WAKER IS current, FOR enqueue,
	                     // WHICH A QUEUED WAKEUP RUNS ON THE WAKEE'S CPU; CLEARED
	                     // IN running().
	u32 wake_cpu;        // CPU + 1 THIS WAKE'S WAKER RAN ON, 0 = NONE. STAMPED IN
	                     // select_cpu WITH wake_waker; THE WAKE FLOW'S SOURCE.
	                     // CLEARED IN running().
	u8  wake_class;      // THE RUN running() STARTED ENDED A WAKE FROM ANOTHER CPU
	                     // IN THE WAKER's L3 (1) OR ACROSS IT (2); 0 = NOT A WAKE,
	                     // OR ONE research t14 HOLDS OUT (THE WAKER's OWN CPU, THE
	                     // IDLE TASK AS WAKER, A KTHREAD WAKEE). stopping() LOGS
	                     // AND CLEARS IT.
	u8  leaves_after_wake; // CONSECUTIVE WAKES THIS TASK BLOCKED WITHIN
	                     // waker_leave_ns OF, SATURATING AT PAIR_OBS_CAP; RESET BY
	                     // ONE IT OUTSTAYED. A LEDGER, LIKE same_waker_runs.
	u8  sleepless_runs;  // CONSECUTIVE STOPS THAT LEFT THIS TASK RUNNABLE (A
	                     // PREEMPTION OR A SLICE'S END), SATURATING AT
	                     // PAIR_OBS_CAP; RESET BY A STOP THAT BLOCKS. stopping().
	u64 woke_at;        // WHEN THIS TASK LAST WOKE ANOTHER, 0 ONCE ITS STOP IS
	                     // COUNTED. STAMPED ONLY WHILE waker_leave_ns IS NONZERO.
	u64 cut_at;          // WHEN seat_cut LAST SEATED THIS TASK, 0 ONCE ITS NEXT
	                     // REQUEUE HAS BEEN JUDGED. enqueue READS AND CLEARS IT.
	u64 wake_svc_ns;     // SERVICE RENDERED SINCE THIS TASK LAST WOKE. ZEROED IN
	                     // runnable(), ADVANCED IN stopping(). enqueue's RESUME
	                     // READS IT AGAINST ONE LIVE TARGET.
	u16 resumed;         // SLOT + 1 OF THE LANE THIS TASK WAS RESUMED AT THE HEAD
	                     // OF (enqueue's TIER 3), 0 = NONE. CLEARED IN
	                     // qclock_depart, WHICH TAKES IT OFF THAT LANE'S RECORD.
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

// HELPERS

// THE DOMAIN OF A CPU: THE EMERGENT DOMAIN FROM THE MIN-CONDUCTANCE TREE IN
// cpu_domain, NOT A DISCRETE llc_domain. THE PARTITION TARGETS L3 GRANULARITY,
// SO ON A REAL PART THE TWO AGREE AND THE BOUNDARY IS DRAWN BY THE CONDUCTANCE
// LANDSCAPE RATHER THAN A HARDCODED TABLE.
static __always_inline u32 cpu_domain_of(s32 cpu)
{
	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return 0;
	u32 key = (u32)cpu;
	u32 *cd = bpf_map_lookup_elem(&cpu_domain, &key);
	return cd ? *cd : 0;
}

// A CPU'S LANE, ITS SECOND DSQ, NUMBERED AFTER EVERY SEAT.
static __always_inline u64 lane_dsq(u32 cpu)
{
	return nr_cpu_ids + (u64)cpu;
}

// THE QUEUE A DSQ ID NAMES, OR NULL FOR AN ID THIS SCHEDULER DOES NOT OWN.
static __always_inline struct queue_clock *qclock_of(u64 dsq)
{
	if (dsq < nr_cpu_ids)
		return &pcpu_qclock[cpu_slot(dsq)];
	if (dsq < 2 * (u64)nr_cpu_ids)
		return &lane_qclock[cpu_slot((u32)(dsq - nr_cpu_ids))];
	return NULL;
}

// A TASK LEAVES THE QUEUE IT SAT ON. ran: IT LEFT TO RUN, SO ITS WAIT IS A
// SOJOURN. A TASK REMOVED UNRUN (SLEEP, EXIT, SETAFFINITY) IS PROGRESS ONLY.
static __always_inline void qclock_depart(struct task_ctx *tctx, u64 now, bool ran)
{
	if (!tctx)
		return;
	// A RESUMED TASK LEAVES ITS LANE'S HEAD. THE NEXT OF THEM, IF ANY, IS READ
	// AS WAITING FROM NOW: ITS OWN ARRIVAL IS NOT KEPT, AND THE ERROR RUNS
	// TOWARD LEAVING IT FOR ITS OWN CPU, NEVER TOWARD A WAIT THAT GROWS.
	if (tctx->resumed) {
		struct queue_clock *rq =
			&lane_qclock[(u32)(tctx->resumed - 1) & (MAX_CPUS - 1)];
		tctx->resumed = 0;
		if (__sync_sub_and_fetch(&rq->resumed_n, 1) != 0)
			rq->resumed_since = now;
	}
	if (!tctx->queued_on)
		return;
	struct queue_clock *q = qclock_of(tctx->queued_on - 1);
	tctx->queued_on = 0;
	if (!q)
		return;
	__sync_fetch_and_add(&q->departures, 1);
	q->progress_ns = now;
	if (ran && tctx->wait_since && now > tctx->wait_since)
		q->last_sojourn_ns = now - tctx->wait_since;
}

// A TASK JOINS dsq. ONE STILL RECORDED ON ANOTHER QUEUE LEFT IT BY A PATH THAT
// NEVER REPORTED, SO THAT DEPARTURE IS ACCOUNTED FIRST AND NO COUNT STRANDS. AN
// ARRIVAL INTO AN EMPTY QUEUE STARTS ITS PROGRESS CLOCK AND FORGETS THE LAST
// BUSY PERIOD'S SOJOURN.
static __always_inline void qclock_arrive(struct task_ctx *tctx, u64 dsq, u64 now)
{
	if (!tctx)
		return;
	qclock_depart(tctx, now, false);
	struct queue_clock *q = qclock_of(dsq);
	if (!q)
		return;
	u64 before = __sync_fetch_and_add(&q->arrivals, 1);
	if (before <= q->departures) {
		q->progress_ns = now;
		q->last_sojourn_ns = 0;
	}
	tctx->queued_on = dsq + 1;
}

// HOW LONG THE OLDEST WORK ON q HAS WAITED. 0 WHEN EMPTY, ELSE THE LATEST
// DEPARTURE'S SOJOURN PLUS THE TIME SINCE THE QUEUE LAST MADE PROGRESS. THE
// QUEUE IS ORDERED OLDEST-FIRST, SO THE HEAD NOW WAITING CLAIMED NO EARLIER THAN
// THE TASK THAT LAST LEFT: ITS WAIT IS AT MOST THAT TASK'S SOJOURN PLUS THE TIME
// SINCE IT LEFT. A FLOWING QUEUE READS ITS SHORT SOJOURNS, A STANDING ONE ITS
// LONG ONES, AND A STALLED ONE GROWS BY THE STALL.
static __always_inline u64 queue_wait(const struct queue_clock *q, u64 now)
{
	if (!q || q->arrivals <= q->departures)
		return 0;
	u64 p = q->progress_ns;
	u64 stall = now > p ? now - p : 0;
	return q->last_sojourn_ns + stall;
}

// HOW LONG THE TASK RESUMED AT A LANE'S HEAD HAS WAITED THERE, 0 WITH NONE.
// IT IS THE LANE'S HEAD, SO IT IS THE TASK A STEAL WOULD TAKE AND THE ONE THE
// LANE'S NEXT SERVE RUNS, AND ITS OWN AGE IS WHAT THOSE ARE PRICED ON.
static __always_inline u64 lane_resumed_wait(const struct queue_clock *lq, u64 now)
{
	u64 since = lq->resumed_since;
	return (lq->resumed_n && now > since) ? now - since : 0;
}

// A SEAT'S WAIT: ITS QUEUE'S WAIT PLUS WHAT THE RESIDENT HAS LEFT. queue_wait
// SEES QUEUED WORK ONLY, SO A CPU RUNNING ONE TASK WITH AN EMPTY QUEUE READ AS
// FREE TO EVERY SEAT DECISION. p->scx.slice IS THE RESIDENT'S GRANTED TIME
// REMAINING, COUNTED DOWN BY THE KERNEL AT EACH ACCOUNTING POINT: A MEASURED
// UPPER BOUND, NEVER A PREDICTION. A RESIDENT THAT BLOCKS EARLY FREES THE SEAT
// SOONER, SO THE ERROR RUNS TOWARD MOVING AND NEVER TOWARD STRANDING.
// NOTHING IS ADDED FOR THE IDLE TASK, FOR A RESIDENT OUTSIDE sched_ext (ITS
// slice IS STALE), OR FOR self, THE TASK BEING SEATED, WHICH IS STILL CURRENT
// WHEN ITS OWN REQUEUE IS PLACED. CAPPED AT lag_cap_ns, THE STARVATION BOUND,
// SO AN UNBOUNDED SLICE CANNOT OVERFLOW THE SUM.
static __always_inline u64 seat_wait(s32 cpu, const struct task_struct *self,
				     u64 now)
{
	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return 0;
	u64 wait = queue_wait(&pcpu_qclock[cpu_slot((u32)cpu)], now);
	struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (!curr || curr == self)
		return wait;
	if ((BPF_CORE_READ(curr, flags) & PF_IDLE) ||
	    !(BPF_CORE_READ(curr, scx.flags) & SCX_TASK_QUEUED))
		return wait;
	u64 left = BPF_CORE_READ(curr, scx.slice);
	return wait + (left < lag_cap_ns ? left : lag_cap_ns);
}

// A PEER SEAT'S WAIT, CALLED AND NOT INLINED. THE SPILL WALK ASKS IT OF EVERY PEER
// IT PASSES, AND WITH seat_wait INLINED IN THAT LOOP 6.13's VERIFIER REFUSES
// select_cpu UNDER A REAL LOAD. VERIFIED ONCE, EACH PASS OF THE WALK IS ONE CALL.
__noinline u64 peer_seat_wait(s32 cpu, u64 now)
{
	return seat_wait(cpu, NULL, now);
}

// THE JUDGE. ACTS WHEN THE WAIT REACHES bound. AN UNPACED SITE (pace == 0)
// ACTS EVERY TIME IT ASKS AND NEITHER READS NOR MOVES THE PACED STATE. A PACED
// SITE RUNS CoDel's CONTROL LAW: WHILE THE WAIT STAYS PAST bound EACH ACT
// SCHEDULES THE NEXT AT pace / sqrt(acts), SO A QUEUE THAT KEEPS STANDING IS
// ACTED ON FASTER AND FASTER UNTIL IT DRAINS, AND THE COUNT RESETS THE MOMENT
// THE WAIT FALLS BELOW bound.
static __always_inline bool queue_act(struct queue_clock *q, u64 wait, u64 bound,
				      u64 pace, u64 now)
{
	if (!q)
		return false;
	if (wait < bound) {
		if (pace && q->acts)
			q->acts = 0;
		return false;
	}
	if (!pace)
		return true;
	if (now < q->next_act)
		return false;
	u64 n = q->acts + 1;
	if (n > QCLOCK_ACTS_CAP)
		n = QCLOCK_ACTS_CAP;
	q->acts = n;
	q->next_act = now + pace / qclock_isqrt[n];
	return true;
}

// CROSS-DOMAIN SCATTER BUMP. COUNTS A CROSS-DOMAIN LANDING ON PATH `idx` (XDOM_*)
// WHEN THE TASK'S HOME CPU AND THE CHOSEN CPU SIT IN DIFFERENT cache domains.
// last_home < 0 (NO PRIOR CPU) IS NOT A MIGRATION. FREE-COMPUTE: ONE cpu_domain_of
// COMPARE ON AN ALREADY-TAKEN PLACEMENT BRANCH. SUMMED INTO THE [KNOBS] LINE's
// scatter_pct AND SURFACED PER-RUN BY THE BENCH SUITE.
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

// THIS CPU'S QUEUE-RING SLOT FOR THE BUCKET now FALLS IN, CLEARED ON ITS FIRST
// TOUCH IN THAT BUCKET. NULL UNTIL THE BUCKET WIDTH IS DERIVED. depth_ring IS
// PER-CPU AND tick() AND running() NEVER NEST ON ONE CPU, SO NO ATOMIC.
static __always_inline struct depth_slot *depth_slot_now(struct depth_ring *r, u64 now)
{
	u64 w = depth_bucket_ns;
	if (!r || !w)
		return NULL;
	u64 ep = now / w;
	struct depth_slot *sl = &r->slot[ep & (DEPTH_RING_SLOTS - 1)];
	if (sl->epoch != ep) {
		sl->epoch = ep;
		sl->ticks = 0;
		sl->own = 0;
		sl->lane = 0;
		sl->loc = 0;
		sl->runs = 0;
		sl->wakes = 0;
		sl->wait_us = 0;
		sl->idle = 0;
		sl->min_wait_us = 0;
	}
	return sl;
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
// REFERENCE: KLEIN-RANDIC 1993, CHANDRA ET AL. 1989 (R_eff); CHRISTIANO ET AL. 2011

// AFFINITY IDLE-SEARCH BUDGET, IN ONLINE CANDIDATES CHECKED RATHER THAN SLOTS
// WALKED -- THE EXPENSIVE OP IS scx_bpf_test_and_clear_cpu_idle, AND AN OFFLINE
// ENTRY SKIPS WITHOUT CHARGING.
//   budget = K_AFFINITY_SEARCH / tau = lambda_2 / 4
// HALF THE SPILL BUDGET'S DIVISOR BECAUSE THE PREDICATE COSTS MORE. 3 AT 12C,
// 8 AT 32C, SATURATING AT MAX_AFFINITY_CANDIDATES. SET IN apply_tau_scaling().
static u32 affinity_search_online = 3;

// RETURNS THE NEAREST IDLE CPU IN R_eff ORDER, OR -1 IF NONE IS IDLE WITHIN
// BUDGET. THE CPU IT RETURNS IS CLAIMED: ITS IDLE BIT IS CLEAR, SO THE CALLER
// MUST SEAT THERE.
// A FUNCTION OF ITS OWN, VERIFIED ONCE. INLINED AT NINE SITES, SIX OF THEM IN
// select_cpu, THE THREE WALKS COST 6.13's VERIFIER OVER A MILLION INSTRUCTIONS
// THERE; CALLED, UNDER TWENTY THOUSAND. IT TAKES THE TASK AND READS ITS MASK: A
// FUNCTION VERIFIED ALONE MUST BE HANDED A POINTER THE KERNEL VOUCHES FOR.
__noinline s32 find_idle_by_affinity(struct task_struct *p __arg_trusted,
				     s32 src_cpu)
{
	const struct cpumask *allowed = p->cpus_ptr;

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
	int i;
	bpf_for(i, 0, MAX_AFFINITY_CANDIDATES) {
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
		if (scx_bpf_test_and_clear_cpu_idle((s32)*val))
			return (s32)*val;
		// BUDGET IS ONLINE CANDIDATES, NOT SLOTS WALKED.
		if (++checked >= affinity_search_online)
			break;
	}

	return -1;
}

// DIRECT HAND-OFF. A SEAT THAT IS STILL THE CLAIMED IDLE CPU, WITH NOTHING ON
// ITS PER-CPU DSQ, HAS NO WAIT TO MEASURE AND NOTHING TO STEAL, SO THE WAKEE GOES
// STRAIGHT ONTO ITS LOCAL DSQ INSTEAD OF WAITING FOR ITS ops.dispatch TO PULL IT.
// THE EMPTY TEST KEEPS THE WAKEE FROM JUMPING ANYTHING ALREADY QUEUED THERE. THE
// CALLER STILL RECORDS THE ARRIVAL: running() DEPARTS IT, SO CoDel TIMES THE
// HAND-OFF'S REAL LATENCY.
static __always_inline bool seat_direct(struct task_struct *p, s32 seat,
					s32 claimed, u64 sl, u64 enq_flags)
{
	if (seat != claimed || (u64)seat >= nr_cpu_ids ||
	    scx_bpf_dsq_nr_queued((u64)seat))
		return false;
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)seat, sl, enq_flags);
	return true;
}

// THE CUT, SEATED. A WAKE THAT MAY CUT (wake_cuts) GOES TO ITS SEAT'S LOCAL
// DSQ WITH THE PREEMPT AND THE SEAT IS KICKED, SO IT RUNS AHEAD OF THE SEAT'S
// PER-CPU DSQ: THE RESIDENT'S SLICE IS ZEROED, THE SEAT RESCHEDULES, AND
// NOTHING ON THE PER-CPU DSQ RUNS AHEAD OF IT. THE PER-CPU DSQ IS
// OLDEST-FIRST, SO A KICKED SEAT USED TO PREEMPT ITS RESIDENT AND THEN RUN
// ITS QUEUE AHEAD OF THE WAKE THE KICK WAS FOR, ONE TICK AT A TIME.
// THE PARTNER SEAT KEEPS ITS OWN RULE AND THE WAKER IS NOT PREEMPTED. THE
// CALLER RECORDS THE ARRIVAL ON THE SEAT'S CLOCK AS FOR A HAND-OFF.
// A REMOTE LOCAL DSQ IS A VERDICT THE KERNEL ENFORCES: A SEAT OUTSIDE THE
// TASK'S MASK, OR ANY SEAT BUT ITS OWN FOR A MIGRATION-DISABLED TASK, EJECTS
// THE SCHEDULER. SUCH A WAKE IS REFUSED HERE AND TAKES THE QUEUE INSTEAD.
static __always_inline bool seat_cut(struct task_struct *p, s32 seat, u64 sl,
				     u64 enq_flags)
{
	if ((u64)seat >= nr_cpu_ids)
		return false;
	if (seat != scx_bpf_task_cpu(p) &&
	    (is_migration_disabled(p) ||
	     !bpf_cpumask_test_cpu(seat, p->cpus_ptr)))
		return false;
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)seat, sl,
			   enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
	// THE FLAG ALONE DOES NOT WAKE THE SEAT; THE WAKE WAITS FOR THE TICK. THE
	// KICK IS THE PREEMPT THAT LANDS.
	scx_bpf_kick_cpu(seat, SCX_KICK_PREEMPT);
	return true;
}

// PHI PLACEMENT TARGET. NEVER RETURNS A BUSY CPU:
//   ANCHOR IDLE      -> TAKE IT, WARM AND IMMEDIATE
//   ELSE NEAREST IDLE-> find_idle_by_affinity WALKS R_eff ORDER, SO A
//                       SAME-DOMAIN IDLE PRECEDES A CROSS-DOMAIN ONE
//   NOTHING IDLE     -> -1, AND select_cpu FALLS THROUGH TO dfl -> enqueue,
//                       WHICH PLACES BUSY-CORE WAKEUPS WITH SCX_KICK_PREEMPT
// A BUSY PLACEMENT FROM THIS PATH WOULD ISSUE SCX_KICK_IDLE, A NO-OP ON A BUSY
// CPU, AND STRAND THE WAKEE UNTIL THE RESIDENT YIELDED.
static __always_inline s32 phi_warm_target(struct task_struct *p, s32 anchor)
{
	return find_idle_by_affinity(p, anchor);
}

// WARM-STAY GATE. RETURNS THE ANCHOR TO HOLD THE WAKEE ON WHILE THAT ANCHOR IS
// UNCONGESTED, OR -1 WHEN THE CALLER SHOULD IDLE-SEEK.
// CONGESTION IS THE ANCHOR'S OWN QUEUE WAIT -- THE SAME SIGNAL STEP 1's STEAL
// READS -- AGAINST codel_target_ns PLUS THE
// ANCHOR'S SLOT-0 DISTANCE. SO A WAKEE STAYS WARM RIGHT UP TO THE SOJOURN AT
// WHICH THE STEAL WOULD HAVE RELOCATED IT ANYWAY.
// THE CALLER MUST ROUTE A HELD WAKEE THROUGH A PREEMPT-KICKED PLACEMENT, NEVER
// select_cpu's IDLE FAST PATH -- SCX_KICK_IDLE ON A BUSY ANCHOR IS A NO-OP AND
// STRANDS THE WAKEE. select_cpu THEREFORE ONLY DEFERS HERE.
// EXCLUDES NON-WAKEUPS THAT ARE NOT HANDOFF PARTNERS, AND KTHREADS. THE ANCHOR
// MUST BE VALID AND IN THE WAKEE'S ALLOWED MASK.
// STICKINESS IS MIGRATION RESISTANCE, NOT AN ADAPTIVE-ONLY FEATURE, SO IT
// ENGAGES IN BPF-ONLY MODE TOO.

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

// WHICH WAKEUP MAY CUT A RESIDENT. A SYNC WAKE IS A HANDOFF: THE WAKER IS ABOUT
// TO BLOCK, SO WHAT REACHES THE WAKEE IS WORK, NOT A DEADLINE. FROM A
// DEMONSTRATED PARTNER THE HANDOFF IS THE CRITICAL PATH OF A 1:1 EXCHANGE AND
// CUTS. FROM ANY OTHER WAKER IT IS ONE OF MANY A PRODUCER FANS OUT, AND CUTTING
// FOR EACH ONE SPLITS THE WAKEE'S WORK INTO ONE-MESSAGE RUNS: EVERY CUT IS A
// SWITCH, A RESUME FOR THE STEAL TO MOVE, AND ANOTHER SLEEP-WAKE CYCLE. THAT
// WAKEE WAITS IN ORDER BEHIND THE RESIDENT, BOUNDED BY THE TICK BAND AND THE
// SWEEP. A TIMER, IRQ OR FORK WAKE IS NEVER SYNC AND ALWAYS CUTS, AND SO DOES A
// WAKE THAT NEVER PASSED THROUGH select_cpu.
static __always_inline bool wake_cuts(const struct task_ctx *tctx)
{
	if (!tctx)
		return true;
	if (tctx->fanout_wake)
		return false;
	return !tctx->sync_wake || is_handoff_partner(tctx);
}

// A FAN-OUT WAKE. A FUTEX WAKE IS NEVER SYNC, SO wake_cuts LET EVERY ONE CUT,
// AND A PRODUCER WAKING ITS WORKERS CUT A RUNNING TASK FOR EACH. THE WAKEE'S
// LEDGER CANNOT SEE FAN-OUT: EVERY WORKER OF ONE PRODUCER READS AS ITS PARTNER.
// THE WAKER'S SIDE CAN: same_wakee_runs CLIMBS ONLY WHILE IT KEEPS WAKING ONE
// PID. A NON-SYNC WAKE OF A THREAD OF THE WAKER'S OWN PROCESS, FROM A WAKER
// WHOSE LAST WAKES WENT TO OTHERS, IS A FAN-OUT AND TAKES THE QUEUE. A FORK
// NEVER IS. MEASURED STATE ONLY; THE LEDGER ADVANCES ON EVERY WAKE.
static __always_inline bool fanout_wake(struct task_struct *p, u64 wake_flags)
{
	struct task_struct *waker = bpf_get_current_task_btf();
	struct task_ctx *wc = lookup_task_ctx(waker);
	if (!wc)
		return false;
	if (wc->last_wakee_pid == p->pid) {
		if (wc->same_wakee_runs < PAIR_OBS_CAP)
			wc->same_wakee_runs += 1;
	} else {
		wc->last_wakee_pid = p->pid;
		wc->same_wakee_runs = 0;
	}
	if (wake_flags & (SCX_WAKE_SYNC | SCX_WAKE_FORK))
		return false;
	return waker->tgid == p->tgid && wc->same_wakee_runs < PAIR_OBS_MIN;
}

// THE KICK'S PRICE, ONE DEFINITION FOR EVERY TIER.
// A WAKEUP CUTS WHEN wake_cuts SAYS SO AND OTHERWISE TAKES THE FLOOR -- IT
// CARRIES NO ACCRUED WAIT. A REQUEUE BUYS THE PREEMPT WITH WHAT IT IS OWED:
// wait_since IS STAMPED ON THE FIRST INSERT AFTER A RUN AND PRESERVED ACROSS
// REQUEUES, SO A TASK PASSED OVER N TIMES KEEPS ITS ORIGINAL CLAIM AND RISES AS
// THE CLOCK MOVES. THE SEAT'S JUDGE PACES IT: AN OWED REQUEUE PREEMPTS AT MOST
// ONCE PER SEAT PER TARGET, SHARED WITH EVERY OTHER PREEMPT OF THAT SEAT.
// THE THRESHOLD IS codel_target_ns + THE TARGET'S SLOT-0 R_eff PENALTY, WHICH IS
// WHAT STEP 1's phi_thresh AND warm_seat_pick's STAY BOUND ALSO RELEASE AT. THE
// STAY AND THE STEAL MUST RELEASE TOGETHER OR THEY FIGHT.
// A REFUSED KICK TAKES SCX_KICK_IDLE, WHICH WAKES AN IDLE SEAT AND IS DROPPED
// ON A BUSY ONE BY can_skip_idle_kick(); kick_cpu(cpu, 0) WOULD QUEUE AN IPI
// UNCONDITIONALLY FOR A RESIDENT THE KERNEL KEEPS WHILE IT HAS SLICE.
// THIS BOUNDS WHEN THE PREEMPT FIRES, NEVER WHETHER.
// KICK_NONE IS THE BOTTOM RUNG AND IT IS SILENCE -- THE ABSENCE OF THE CALL,
// DISTINCT FROM FLAG 0, WHICH IS ITSELF A VALID KICK.
#define KICK_NONE ((u64)-1)

static __always_inline u64 requeue_kick_flag(const struct task_ctx *tctx,
					     s32 target, bool is_wakeup)
{
	if (target < 0 || (u64)target >= nr_cpu_ids)
		return SCX_KICK_IDLE;
	// AN IDLE SEAT HAS NO RESIDENT TO DISLODGE. Ask the seat, not the task.
	if (!__COMPAT_scx_bpf_cpu_curr(target))
		return SCX_KICK_IDLE;
	if (is_wakeup)
		return wake_cuts(tctx) ? SCX_KICK_PREEMPT : SCX_KICK_IDLE;
	u32 rbase = (u32)target * MAX_AFFINITY_CANDIDATES;
	u32 *rdx = bpf_map_lookup_elem(&reff_value, &rbase);
	u32 rd = rdx ? *rdx : 0;
	u64 near_extra = (rd == (u32)-1) ? 0 : (u64)rd;
	u64 rnow = bpf_ktime_get_ns();
	u64 claimed = (tctx && tctx->wait_since && rnow > tctx->wait_since)
		    ? rnow - tctx->wait_since : 0;
	if (queue_act(&pcpu_qclock[cpu_slot((u32)target)], claimed,
		      codel_target_ns + near_extra, codel_target_ns, rnow))
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
	return SCX_KICK_IDLE;
}

// A RESIDENT STILL OWED ITS FIRST TARGET: IT HAS RUN UNDER codel_target_ns
// SINCE IT TOOK THE CPU, SO IT HAS NOT YET HAD WHAT THE CLOCK PROMISES ANY TASK
// BEFORE IT IS JUDGED. PREEMPTED THERE IT REQUEUES WITH ITS WORK LEFT, AND ONE
// THAT WOULD HAVE BLOCKED IN A FEW MICROSECONDS PAYS A SWITCH AND ITS CACHE FOR
// NOTHING. A STAMP AHEAD OF now IS A RUN THAT JUST BEGAN.
static __always_inline bool resident_owed(u32 cpu, u64 now)
{
	u64 start = run_start_ns[cpu_slot(cpu)];
	return start > now || now - start < codel_target_ns;
}

// A RESIDENT A WAKE THAT MAY NOT CUT STILL MAY: ONE THAT HAS NOT BLOCKED ACROSS
// ITS LAST SLEEPLESS_CONFIRM STOPS AND HAS HAD ITS FIRST TARGET IN THIS RUN.
// wake_cuts KEEPS A FAN-OUT OR NON-PARTNER SYNC WAKE OFF A RESIDENT THAT MAY BE
// THE WORK IT SERVES; A TASK THAT NEVER BLOCKS SERVES NO WAKE. THE STANDING
// LEDGER CANNOT DRAW THIS LINE: A FRAME'S RENDER AND ITS WORKERS RUN A FULL
// TARGET AND THEN BLOCK, AND READ AS STANDING.
static __always_inline bool resident_sleepless_at(s32 cpu, u64 now)
{
	return cpu >= 0 && (u32)cpu < nr_cpu_ids &&
	       resident_sleepless[cpu_slot((u32)cpu)] &&
	       !resident_owed((u32)cpu, now);
}

// THE NEAREST CPU IN R_eff ORDER, THE ANCHOR FIRST, WHOSE RESIDENT DOES NOT
// SLEEP (resident_sleepless_at), OR -1, WITHIN THE ANCHOR'S DOMAIN.
// find_idle_by_affinity's WALK WITHOUT ITS BUDGET: THAT BUDGET PRICES
// scx_bpf_test_and_clear_cpu_idle, AND THIS TEST IS ONE ARRAY LOAD. THE RANK
// SORTS BY RUNG FIRST, SO THE FIRST CANDIDATE OUTSIDE THE DOMAIN ENDS IT.
// NOTHING IS CLAIMED, SINCE A CUT NEEDS NO IDLE BIT.
// A FUNCTION OF ITS OWN, VERIFIED ONCE. INLINED AT NINE SITES, SIX OF THEM IN
// select_cpu, THE THREE WALKS COST 6.13's VERIFIER OVER A MILLION INSTRUCTIONS
// THERE; CALLED, UNDER TWENTY THOUSAND. IT TAKES THE TASK AND READS ITS MASK: A
// FUNCTION VERIFIED ALONE MUST BE HANDED A POINTER THE KERNEL VOUCHES FOR.
__noinline s32 find_sleepless_by_affinity(struct task_struct *p __arg_trusted,
					  s32 src_cpu, u64 now)
{
	const struct cpumask *allowed = p->cpus_ptr;

	if (src_cpu < 0 || (u32)src_cpu >= nr_cpu_ids)
		return -1;
	if ((!allowed || bpf_cpumask_test_cpu(src_cpu, allowed)) &&
	    resident_sleepless_at(src_cpu, now))
		return src_cpu;

	u32 dom = cpu_domain_of(src_cpu);
	u32 base = (u32)src_cpu * MAX_AFFINITY_CANDIDATES;
	int i;
	bpf_for(i, 0, MAX_AFFINITY_CANDIDATES) {
		u32 key = base + (u32)i;
		u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
		if (!val || *val == (u32)-1)
			break;
		if (*val >= nr_cpu_ids)
			continue;
		if (cpu_domain_of((s32)*val) != dom)
			break;
		if (allowed && !bpf_cpumask_test_cpu((s32)*val, allowed))
			continue;
		if (resident_sleepless_at((s32)*val, now))
			return (s32)*val;
	}
	return -1;
}

// THE SEAT. EVERY PLACE A TASK IS PUT ON A CPU'S SEAT DOES THE SAME FOUR
// THINGS IN THIS ORDER: HAND IT OFF IF THE SEAT IS THE CLAIMED IDLE CPU WITH
// AN EMPTY QUEUE (seat_direct); CUT IF THE WAKE MAY AND THE SEAT IS ITS OWN
// PER-CPU QUEUE (seat_cut); ELSE INSERT IT ON dsq IN DEADLINE ORDER; RECORD
// THE ARRIVAL ON THAT QUEUE'S CLOCK; AND, ONLY WHEN IT WAS QUEUED, ISSUE THE
// CALLER'S PRICED KICK. THE CALLER DECIDES THE SEAT, THE QUEUE, WHETHER THE
// WAKE MAY CUT AND WHAT THE KICK IS. THE SIX SEATS IN select_cpu AND enqueue
// ARE THIS ONE SHAPE.
enum seat_how { SEAT_QUEUED = 0, SEAT_HANDOFF = 1, SEAT_CUT = 2 };

static __always_inline enum seat_how seat_task(struct task_struct *p,
					       struct task_ctx *tctx, s32 seat,
					       s32 claimed, u64 dsq, u64 sl,
					       u64 dl, bool may_cut, u64 kick,
					       u64 enq_flags)
{
	enum seat_how how = SEAT_QUEUED;
	if (seat_direct(p, seat, claimed, sl, enq_flags))
		how = SEAT_HANDOFF;
	else if (may_cut && dsq == (u64)seat &&
		 seat_cut(p, seat, sl, enq_flags)) {
		how = SEAT_CUT;
		u64 cut_now = bpf_ktime_get_ns();
		pcpu_qclock[cpu_slot((u32)seat)].cut_ns = cut_now;
		if (tctx)
			tctx->cut_at = cut_now;
	} else
		scx_bpf_dsq_insert_vtime(p, dsq, sl, dl, enq_flags);
	qclock_arrive(tctx, dsq, bpf_ktime_get_ns());
	if (how == SEAT_QUEUED && kick != KICK_NONE)
		scx_bpf_kick_cpu(seat, kick);
	return how;
}

static __always_inline s32 warm_seat_pick(struct task_struct *p,
					    struct task_ctx *tctx,
					    struct tuning_knobs *knobs,
					    bool is_wakeup, u64 now)
{
	// ADMIT A WAKE, OR A REQUEUED HANDOFF PARTNER, TO THE WARM PER-CPU SEAT.
	// EVERYTHING ELSE STAYS ON BASELINE. BOTH CALLERS ASK ONLY AFTER PHI'S WALK
	// FOUND NO IDLE CPU, SO THE HOLD NEVER STANDS BETWEEN A WAKEE AND AN IDLE
	// SEAT THE WALK CAN REACH.
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
	// THE HOME'S FULL WAIT: ITS QUEUE'S WAIT PLUS ITS RESIDENT'S REMAINING
	// SLICE. A HOME WHOSE RESIDENT KEEPS RUNNING -- A WAKER THAT DOES NOT BLOCK
	// -- IS NOT A FREE SEAT, HOWEVER EMPTY ITS QUEUE.
	u64 sojourn = seat_wait(lc, p, now);
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
// "IS IDLE", ROUTING A WAKEE PAST ADMISSION INTO A SIBLING PER-CPU DSQ, REACHED
// AT DISPATCH STEP 0 OR STEP 1.
//   budget = K_SPILL_BUDGET / tau_ns = lambda_2 / 2
// 6 AT 12C, 16 AT 32C. CLAMPED [6, MAX_AFFINITY_CANDIDATES]. SET IN
// apply_tau_scaling().
static u32 pcpu_spill_search_budget = 6;

// CEILING ON THE keep_own ADMISSION BYPASS: TWICE THE ADMISSION BOUND, READ LIVE OFF
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
// AND KEEPS find_spill_seat UNDER THE INSTRUCTION BUDGET. THE STEAL-SIDE
// LOOPS KEEP THE FULL 128.
#define PCPU_SPILL_SCAN_MAX 32
// RETURNS THE NEAREST PEER IN src_cpu's CACHE DOMAIN THAT WOULD ADMIT A TASK BY
// ITS OWN ADMISSION RULE WITH THE BASE COST AS MARGIN,
// seat_wait(peer) + phi_base_cost_ns < codel_target_ns, ELSE -1. THE SAME BOUND
// pick_pcpu_dsq_with_spill APPLIES TO src_cpu ONE CALL EARLIER, ASKED OF THE
// PEER, ON THE CLOCK dispatch JUDGES EVERY QUEUE BY, WITH THE PEER'S RESIDENT
// COUNTED.
// THE TEST IS ABSOLUTE, NOT SOURCE-RELATIVE. UNDER SATURATION "EMPTIER THAN ME"
// IS A COIN FLIP BETWEEN TWO LOADED CPUs AND THE COST MARGIN TIPS IT AGAINST
// MOVING, SO THE SEARCH RUNS CONSTANTLY AND FAILS CONSTANTLY.
// THE COST IS THE HYSTERESIS. THE SEARCH IS ONLY REACHED WHEN src_cpu HAS
// ALREADY FAILED THIS BOUND, SO A MOVE NEEDS THE SOURCE ABOVE THE TARGET AND THE
// PEER A FULL COST BELOW IT -- A GAP, NOT A TIE. THAT PRICES HOW OFTEN A TASK
// MIGRATES, NOT HOW FAR.
// DISTANCE IS THE WALK ORDER AND THE DOMAIN BOUND, NOT A TERM IN THE COST. A
// LINEAR R_eff TERM CANNOT SEPARATE THE TWO NON-SMT RUNGS (STANDING,
// do-not-re-attempt). THE BOUND IS THE DOMAIN PARTITION, SO A SPILL NEVER
// CROSSES AN L3. A FOREIGN PEER IS SKIPPED WITHOUT COSTING BUDGET.
// A FUNCTION OF ITS OWN, VERIFIED ONCE. INLINED AT NINE SITES, SIX OF THEM IN
// select_cpu, THE THREE WALKS COST 6.13's VERIFIER OVER A MILLION INSTRUCTIONS
// THERE; CALLED, UNDER TWENTY THOUSAND. IT TAKES THE TASK AND READS ITS MASK: A
// FUNCTION VERIFIED ALONE MUST BE HANDED A POINTER THE KERNEL VOUCHES FOR.
__noinline s32 find_spill_seat(struct task_struct *p __arg_trusted, s32 src_cpu,
			       u64 now)
{
	const struct cpumask *allowed = p->cpus_ptr;

	if (src_cpu < 0 || (u32)src_cpu >= nr_cpu_ids)
		return -1;

	s32 best_cpu = -1;
	u32 base = (u32)src_cpu * MAX_AFFINITY_CANDIDATES;
	u32 src_dom = cpu_domain_of(src_cpu);
	u32 checked = 0;

	int i;
	bpf_for(i, 0, PCPU_SPILL_SCAN_MAX) {
		u32 key = base + (u32)i;
		u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
		if (!val || *val == (u32)-1)
			break;
		u32 peer = *val;
		if (peer >= nr_cpu_ids)
			continue;
		if (allowed && !bpf_cpumask_test_cpu((s32)peer, allowed))
			continue;
		if (cpu_domain_of((s32)peer) != src_dom)
			continue;

		u64 cost = peer_seat_wait((s32)peer, now) + phi_base_cost_ns;
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

// A CPU THE TASK MAY RUN ON: near WHEN ITS MASK ALLOWS IT, ELSE ONE PICKED FROM
// THE MASK ON near's NODE, AN IDLE ONE FIRST. A USER DSQ ADMITS ANY TASK, BUT
// ONLY A CPU THE TASK MAY RUN ON CAN MOVE IT TO LOCAL, SO A TASK QUEUED ON A CPU
// OUTSIDE ITS MASK WAITS FOR A STEAL THAT NEED NOT COME. AN EMPTY MASK, WHICH A
// RUNNABLE TASK CANNOT HAVE, FALLS BACK TO THE TASK'S OWN CPU.
static __always_inline s32 allowed_seat(const struct task_struct *p, s32 near)
{
	if ((u64)near < nr_cpu_ids && bpf_cpumask_test_cpu(near, p->cpus_ptr))
		return near;
	s32 node = (u64)near < nr_cpu_ids ? __COMPAT_scx_bpf_cpu_node(near) : 0;
	if (node < 0 || (u32)node >= nr_nodes)
		node = 0;
	s32 cpu = __COMPAT_scx_bpf_pick_any_cpu_node(p->cpus_ptr, node, 0);
	return (u64)cpu < nr_cpu_ids ? cpu : scx_bpf_task_cpu(p);
}

// PICK A DSQ FOR WAKE-SYNC OR INITIAL ENQUEUE WITH SIBLING-SPILL FALLBACK.
// THREE-LEVEL PRIORITY:
//   1. src_cpu's PER-CPU DSQ IF ITS QUEUE WAIT IS UNDER ONE LIVE TARGET AND IN
//      allowed.
//   2. R_EFF-RANKED SIBLING PER-CPU DSQ IN src_cpu's CACHE DOMAIN WITH ROOM AND
//      IN allowed.
//      DISPATCH REACHES THESE AT STEP 0 (OWN) OR STEP 1 (L2 STEAL).
//   3. NO ROOM NEAR: src_cpu's OWN SEAT OVER TARGET, WHERE THE STEAL AND THE
//      BAND BOUND THE WAIT. A src_cpu OUTSIDE allowed (cpus_ptr CHANGED
//      MID-FLIGHT) SEATS ON A CPU OF THE MASK INSTEAD (allowed_seat), SO
//      NOTHING WAITS ON A QUEUE ITS TASK MAY NOT LEAVE FROM.
// *out_cpu RECEIVES THE CPU SCX SHOULD WAKE, THE PER-CPU DSQ OWNER WE LANDED IN.
static __always_inline u64 pick_pcpu_dsq_with_spill(const struct task_struct *p,
						    s32 src_cpu,
						    const struct cpumask *allowed,
						    bool keep_own,
						    bool resident_leaving,
						    s32 *out_cpu)
{
	u64 now = bpf_ktime_get_ns();
	bool src_ok = (u64)src_cpu < nr_cpu_ids &&
		      (!allowed || bpf_cpumask_test_cpu(src_cpu, allowed));
	// THE SEAT'S FULL WAIT, ON THE ONE CLOCK: ITS QUEUE'S WAIT PLUS ITS
	// RESIDENT'S REMAINING SLICE. BOTH THE ADMISSION TEST AND THE keep_own
	// CEILING READ IT. resident_leaving DROPS THE RESIDENT WHEN IT IS A SYNC
	// WAKER ABOUT TO BLOCK, WHOSE REMAINING SLICE IS NOT A WAIT.
	u64 src_wait = !src_ok ? 0
		     : resident_leaving
			? queue_wait(&pcpu_qclock[cpu_slot((u32)src_cpu)], now)
			: seat_wait(src_cpu, p, now);

	// PAIR-WARM MARKER: STAMP src_cpu WHEN A HANDOFF PARTNER SEATS ON ITS OWN
	// WARM CORE, SO THE STEP-1 STEAL CAN PRICE SPLITTING THE PAIR WITHOUT A
	// REMOTE task_ctx DEREF. THE STAMP FOLLOWS THE BOUNDED DECISION -- PAST THE
	// CEILING THE PARTNER SPILLS AND IS NOT SEATED HERE.
	if (keep_own && src_ok && src_wait < keep_own_bound_ns() &&
	    (u32)src_cpu < MAX_CPUS)
		pair_warm_ns[cpu_slot((u32)src_cpu)] = now;

	// ADMISSION. A SEAT ADMITS ONLY WHILE ITS QUEUE HAS WAITED UNDER ONE LIVE
	// TARGET, READ OFF THE CLOCK THE STEAL AND STEP 0 JUDGE IT BY. AN AGE, NOT A
	// DEPTH: THE QUEUE'S WAIT IS THE WAIT ITSELF. THE LATENCY GUARANTEE IS
	// STRUCTURAL HERE RATHER THAN ARITHMETIC IN THE SORT KEY -- SEE
	// task_deadline().
	if (src_ok && src_wait < codel_target_ns) {
		*out_cpu = src_cpu;
		return (u64)src_cpu;
	}

	// EVERY WAKEE PAST ADMISSION FALLS THROUGH TO find_spill_seat AND THEN TO THE
	// OVER-TARGET OWN SEAT, BOTH OF WHICH NAME A SPECIFIC CPU, SO THE KICKED CPU
	// IS THE ONE WHOSE QUEUE HOLDS THE WAKEE: KICK == DRAIN IDENTITY.

	// HANDOFF PARTNER (keep_own): A IS ABOUT TO BLOCK AND FREE src_cpu WITHIN
	// MICROSECONDS, SO THE POST-BLOCK STEP 0 ON src_cpu DRAINS B NEXT. SKIP THE
	// SIBLING SPILL -- A SPILL STRANDS B ON A PER-CPU DSQ THAT src_cpu's STEP 0
	// NEVER LOOKS AT, REACHABLE ONLY BY THE RATE-LIMITED STEP 1 STEAL OR THE TICK.
	// BOUNDED BY keep_own_bound_ns(): PAST THE CEILING THE PARTNER SPILLS LIKE
	// ANYTHING ELSE, SO THIS IS NOT AN UNCAPPED ADMISSION BYPASS.
	bool hold_own = keep_own && src_wait < keep_own_bound_ns();
	s32 spill = hold_own ? -1
			     : find_spill_seat((struct task_struct *)p, src_cpu, now);
	if (spill >= 0) {
		*out_cpu = spill;
		return (u64)spill;
	}

	// NO ROOM ON A NEAR SIBLING. KEEP THE WAKEE ON ITS OWN WARM CORE OVER-TARGET.
	// THE DEEP PER-CPU QUEUE IS BOUNDED BY THE CoDel SOJOURN STEAL, SO IT STAYS
	// L1/L2-WARM.
	if (src_ok) {
		*out_cpu = src_cpu;
		return (u64)src_cpu;
	}

	// AFFINITY-STRANDED ESCAPE: src_cpu IS NOT IN allowed.
	s32 any = allowed_seat(p, src_cpu);
	*out_cpu = any;
	return (u64)any;
}

// NO ARM FUNCTION: THE PER-CPU WAITING SIGNAL IS pcpu_qclock[cpu_slot(cpu)], WRITTEN AT
// INSERT AND AT DEPARTURE; tick() READS IT THROUGH queue_wait().

// TAU-SCALED TIMING CONSTANT DERIVATION.
//   tau_ns * k_q16 / 65536. WHEN tau_ns IS 0 CALLERS SKIP THIS AND
//   THE INIT FALLBACK CONSTANTS REMAIN IN EFFECT. NO DIV, NO FLOAT --
//   VERIFIER-CLEAN. THE MULTIPLY CANNOT OVERFLOW u64 FOR ANY SANE
//   (tau, k_i) PAIR. WORST CASE: tau=40e6 (TAU_CEIL_NS) * K_LAG_CAP
//   (65536) = 2.6e12, COMFORTABLY INSIDE u64 (max ~1.8e19).
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

	v = scale_tau(tau_ns, K_CODEL_FLOOR);
	if (v < 200000ULL) v = 200000ULL;
	if (v > 800000ULL) v = 800000ULL;
	codel_target_floor_ns = v;

	// THE BASE COST, TAU-DERIVED LIKE EVERY OTHER BOUND IN THE GATE. tick()
	// APPLIES IT WHILE THE LAYER HAS WRITTEN NONE.
	v = scale_tau(tau_ns, K_PHI_BASE_Q16);
	if (v < PHI_BASE_MIN_NS) v = PHI_BASE_MIN_NS;
	if (v > PHI_BASE_MAX_NS) v = PHI_BASE_MAX_NS;
	phi_base_tau_ns = v;

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

	// NO RE-SEED HERE. EVERY BOUND, AND THE RESCUE TEST THAT DRIVES THE
	// OSCILLATOR, READS codel_target_ns DIRECTLY -- THE
	// LIVE TARGET THE OSCILLATOR MAINTAINS AROUND codel_seed_ns. ONE
	// THRESHOLD, ONE WRITER (THE CPU-0 TICK). A SEPARATE RESCUE MIRROR
	// WOULD MAKE THIS FUNCTION A SECOND WRITER, RE-SEEDING THE TARGET TO
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

	// DEPTH SAMPLE GRID: A QUARTER OF THE OSCILLATOR'S DAMPED PERIOD. WITH
	// spring_shift = 2*damp + 1 AND zeta = 2^(-1/2), omega_d = 2^(-(damp+1))
	// RAD PER TICK, SO Td = 4*pi*2^damp TICKS AND THE BUCKET IS pi*2^damp
	// TICKS (355/113 FOR pi): FOUR SAMPLES PER OSCILLATION, ENOUGH TO RESOLVE
	// THE CONTROLLER THE ADAPTIVE LAYER DEFERS TO. FIXED PER TOPOLOGY, SO THE
	// GRID IS UNIFORM. damp >= 1 AND HZ <= 1000 HOLD IT AT OR ABOVE 6.28MS,
	// SO DEPTH_RING_SLOTS COVERS OVER 3S, PAST TWO 1HZ LOOP PERIODS.
	{
		u64 hz = CONFIG_HZ > 0 ? (u64)CONFIG_HZ : 1000;
		depth_bucket_ns = ((355ULL << damp) * (1000000000ULL / hz)) / 113;
	}

	// velocity_cap PRESERVES COUPLING TO pull_scale.
	oscillator_velocity_cap = (s64)((u64)OSC_VELOCITY_CAP_PER_PULL * (u64)pull);

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

// PREEMPT cpu's RESIDENT FOR THE WORK WAITING ON cpu's OWN QUEUE, WHEN THE
// SEAT'S JUDGE SAYS THE WAIT HAS REACHED bound. UNPACED: THE TICK FIRES AT MOST
// ONCE PER HZ PER CPU ALREADY. A WAIT IS 0 ON AN EMPTY QUEUE, SO AN EMPTY SEAT IS
// NEVER KICKED. RETURNS TRUE IFF IT KICKED.
static bool pcpu_kick_owed(u32 cpu, u64 wait, u64 bound, u64 now)
{
	if (cpu >= MAX_CPUS)
		return false;
	if (!queue_act(&pcpu_qclock[cpu_slot(cpu)], wait, bound, 0, now))
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
	u64 base_slice = knobs ? knobs->slice_ns : 1000000;
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
	// THE CPU FOR standing_targets OF THE LIVE TARGET AND NO LONGER: THE LAYER'S
	// PER-CPU COUNT, SLICE_STANDING_TARGETS UNTIL IT WRITES ONE.
	// THE KNOB ALONE WOULD PUT A HARD 15.6MS QUANTUM ON THIS PATH, AND A LAUNCH
	// LANDING ON A CPU WHOSE RESIDENT WAS JUST GRANTED ONE WAITS THE WHOLE
	// THING -- A STALL THAT QUANTIZES TO THE SLICE IS NOT A TAIL.
	// THE KNOB KEEPS ITS JOB AS THE OTHER BOUND, SO THE ADAPTIVE LAYER STILL
	// LOWERS THIS AND NEVER RAISES IT.
	u64 targets = knobs && knobs->standing_targets
		? knobs->standing_targets : SLICE_STANDING_TARGETS;
	u64 target_bound = codel_target_ns * targets;
	if (target_bound && base > target_bound)
		base = target_bound;

	if (base < SLICE_MIN_NS)
		base = SLICE_MIN_NS;

	return base;
}

// SCHEDULING CALLBACKS

// SELECT_CPU: FAST-PATH IDLE CPU DISPATCH TO PER-CPU DSQ
// DISPATCHES TO NAMED PER-CPU DSQ (u64)cpu -- VISIBLE TO WORK STEALING
// AND SOJOURN RESCUE. ADMISSION-BOUNDED: PAST ONE TARGET THE SPILL TAKES A
// NEAR SIBLING'S SEAT.
// THE CPU IS IDLE SO IT ENTERS dispatch() IMMEDIATELY AND DRAINS.
// THE WAKER IS LEAVING: IT BLOCKED WITHIN waker_leave_ns OF EACH OF ITS LAST
// PAIR_OBS_MIN WAKES. eventfd AND SEMAPHORE WAKES CARRY NO WF_SYNC, BUT A WAKER
// THAT DEMONSTRABLY BLOCKS RIGHT AFTER WAKING FREES ITS CORE THE SAME WAY, WITH
// WHAT IT JUST PRODUCED STILL HOT THERE (research t30b). STAMPS THE WAKE FOR
// stopping() TO JUDGE. A ZERO KNOB (THE BPF ARM) DISABLES BOTH.
static __always_inline bool waker_leaving(void)
{
	struct tuning_knobs *knobs = get_knobs();

	if (!knobs || !knobs->waker_leave_ns)
		return false;
	struct task_ctx *wc = lookup_task_ctx(bpf_get_current_task_btf());

	if (!wc)
		return false;
	u64 now = bpf_ktime_get_ns();
	// EVERY WAKE IS JUDGED. ONE STILL UNJUDGED PAST THE BOUND WAS OUTSTAYED: THE
	// WAKER RAN THROUGH IT TO THIS ONE, AND THE STOP stopping() JUDGES WOULD SEE
	// ONLY THE NEWER STAMP. frame's main WAKES render, SIMULATES 1.5ms AND STOPS
	// ONLY AFTER ITS NEXT WAKES.
	if (wc->woke_at && now - wc->woke_at > knobs->waker_leave_ns)
		wc->leaves_after_wake = 0;
	wc->woke_at = now;
	return wc->leaves_after_wake >= PAIR_OBS_MIN;
}

s32 BPF_STRUCT_OPS(pandemonium_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;

	// THE SEAT LADDER: A PARTNER'S SYNC HANDOFF TAKES THE WAKER'S CORE, THEN PHI'S
	// R_eff WALK TAKES THE NEAREST IDLE CPU, AND ONLY WHEN THE WALK FINDS NONE
	// DOES AN UNCONGESTED HOME HOLD THE WAKEE (warm_seat_pick, BELOW THE WALKS).
	{
		struct task_ctx *tc = lookup_task_ctx(p);
		if (tc) {
			tc->sync_wake = (wake_flags & SCX_WAKE_SYNC) ? 1 : 0;
			tc->fanout_wake = fanout_wake(p, wake_flags) ? 1 : 0;
			tc->wake_waker = (u32)bpf_get_current_task_btf()->pid + 1;
			tc->wake_cpu = (u32)bpf_get_smp_processor_id() + 1;
		}
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
	// A NON-SYNC WAKE FROM A WAKER THAT BLOCKS WITHIN waker_leave_ns OF ITS
	// WAKES TAKES THE PARTNER SEAT BELOW THE WAY A SYNC HANDOFF DOES, AND
	// NOTHING ELSE OF THE SYNC PATH: THE PHI REMAINDER STAYS SYNC-ONLY.
	// A FAN-OUT WAKE NEVER TAKES THE WAKER'S SEAT: ONE PRODUCER'S WORKERS WOULD
	// QUEUE ON ITS ONE CPU, AND ITS NEXT WAKE IS NOT THE ONE IT BLOCKS AFTER.
	bool is_sync = wake_flags & SCX_WAKE_SYNC;
	struct task_ctx *wt = lookup_task_ctx(p);
	bool leave = !is_sync && !(wt && wt->fanout_wake) && waker_leaving();
	if (is_sync || leave) {
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
		// ON ONE DOMAIN AS ON SEVERAL: ON A MONOLITHIC L3 THERE IS NO CACHE TO
		// BUY, BUT THE SEAT STILL SAVES THE CUT, ITS IPI AND THE RESIDENT IT
		// WOULD DISPLACE, SINCE THE WAKER'S OWN CPU FREES IN MICROSECONDS.
		if (is_handoff_partner(tctx) &&
		    (u64)waker_cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(waker_cpu, p->cpus_ptr)) {
			struct tuning_knobs *knobs = get_knobs();
			u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;
			u64 dl = tctx ? task_deadline(tctx, knobs)
				      : bpf_ktime_get_ns();
			s32 dst_cpu;
			u64 dst_dsq = pick_pcpu_dsq_with_spill(p, waker_cpu, p->cpus_ptr,
							       true, true, &dst_cpu);
			scx_bpf_dsq_insert_vtime(p, dst_dsq, sl, dl, 0);
			qclock_arrive(tctx, dst_dsq, bpf_ktime_get_ns());
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
			// THE LEAVING WAKER STILL RUNS ON THE SEAT, SO THAT SEAT IS NO
			// IDLE HIT FOR THE REGIME LENSES TO COUNT.
			if (tctx) {
				tctx->dispatch_path = 0;
				tctx->idle_seat = leave ? 0 : 1;
			}
			struct pandemonium_stats *s = get_stats();
			if (s) {
				if (!leave)
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
		if (is_sync && (u64)anchor < nr_cpu_ids) {
			// PHI PLACEMENT: THE WARM CORE IF IDLE, ELSE THE NEAREST IDLE
			// PEER IN R_eff ORDER.
			s32 target = phi_warm_target(p, anchor);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				u64 sl = tctx ? task_slice(tctx, knobs)
					      : 1000000;
				s32 dst_cpu;
				// PHI DECIDES. THE WALK CLAIMED target'S IDLE BIT, SO target
				// IS THE SEAT. SEATING ANYWHERE ELSE LEAVES THE CLAIMED CPU
				// IDLE WITH ITS BIT CLEAR, INVISIBLE TO EVERY LATER WALK
				// UNTIL IT NEXT RESCHEDULES.
				u64 dst_dsq = pick_pcpu_dsq_with_spill(p, target, p->cpus_ptr, is_handoff_partner(tctx), false, &dst_cpu);
				u64 dl = tctx ? task_deadline(tctx, knobs) : bpf_ktime_get_ns();
				// pick_pcpu_dsq_with_spill CAN REDIRECT dst_cpu OFF THE
				// VERIFIED-IDLE target ONTO A BUSY SEAT, WHERE SCX_KICK_IDLE
				// IS A NO-OP: PREEMPT WHEN THE SEAT MOVED AND THE WAKE MAY
				// CUT, IDLE OTHERWISE.
				seat_task(p, tctx, dst_cpu, target, dst_dsq, sl, dl,
					  wake_cuts(tctx),
					  dst_cpu != target && wake_cuts(tctx)
						  ? SCX_KICK_PREEMPT : SCX_KICK_IDLE, 0);
				if (tctx) {
					tctx->dispatch_path = 0;
					tctx->idle_seat = 1;
				}
				struct pandemonium_stats *s = get_stats();
				if (s) {
					s->nr_idle_hits += 1;
					s->nr_dispatches += 1;
					cross_domain_bump(s, XDOM_SEL_SYNC, tctx ? tctx->last_cpu : -1, dst_cpu);
					if (dst_cpu != target)
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
			// PEER IN R_eff ORDER. THE CLAIMED target IS THE SEAT, AS ON
			// THE SYNC PATH ABOVE.
			s32 target = phi_warm_target(p, anchor);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				u64 sl = task_slice(tctx, knobs);
				u64 dl = task_deadline(tctx, knobs);
				s32 seat_cpu;
				u64 seat_dsq = pick_pcpu_dsq_with_spill(p, target, p->cpus_ptr, is_handoff_partner(tctx), false, &seat_cpu);
				// THE SPILL CAN SEAT OFF THE VERIFIED-IDLE target ONTO A
				// BUSY SIBLING: PREEMPT WHEN THE SEAT MOVED AND THE WAKE MAY
				// CUT, IDLE OTHERWISE, WHICH IS THE WAIT A WAKE THAT MAY NOT
				// CUT IS GIVEN.
				seat_task(p, tctx, seat_cpu, target, seat_dsq, sl, dl,
					  wake_cuts(tctx),
					  seat_cpu != target && wake_cuts(tctx)
						  ? SCX_KICK_PREEMPT : SCX_KICK_IDLE, 0);
				tctx->dispatch_path = 0;
				tctx->idle_seat = 1;
				struct pandemonium_stats *s = get_stats();
				if (s) {
					s->nr_idle_hits += 1;
					s->nr_dispatches += 1;
					count_l2_affinity(s, tctx, seat_cpu, p->flags & PF_WQ_WORKER);
					cross_domain_bump(s, XDOM_SEL_NORMAL, anchor, seat_cpu);
					if (seat_cpu != target)
						s->nr_spill_kick_preempt += 1;
				}
				return seat_cpu;
			}
		}
	}

	// PHI FOUND NO IDLE SEAT NEAR THE ANCHOR. AN UNCONGESTED HOME HOLDS THE
	// WAKEE: RETURN IT WITHOUT DISPATCHING, SO enqueue SEATS IT WITH A
	// PREEMPT-PRICED KICK. THE HOLD COMES BEFORE dfl, WHICH IGNORES DISTANCE AND
	// WOULD TRADE A WARM HOME FOR ANY IDLE CPU ON THE NODE.
	{
		struct task_ctx *tc = lookup_task_ctx(p);
		s32 hold = warm_seat_pick(p, tc, get_knobs(),
					  tc && !tc->ran_since_wake,
					  bpf_ktime_get_ns());
		if (hold >= 0)
			return hold;
	}

	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	s32 dst_cpu = cpu;

	if (is_idle) {
		struct task_ctx *tctx = lookup_task_ctx(p);
		struct tuning_knobs *knobs = get_knobs();
		u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;

		// PER-CPU DSQ PLACEMENT WITH L2/R_EFF SPILL. CACHE-HOT IF cpu
		// HAS ROOM; SIBLING PER-CPU DSQ NEXT (REACHED BY DISPATCH STEP 0
		// ON SIBLING OR STEP 1 L2 STEAL); ELSE THE OWN SEAT OVER TARGET.
		u64 dst_dsq = pick_pcpu_dsq_with_spill(p, cpu, p->cpus_ptr, is_handoff_partner(tctx), false, &dst_cpu);
		u64 dl = tctx ? task_deadline(tctx, knobs)
			      : bpf_ktime_get_ns();
		// `cpu` IS THE VERIFIED-IDLE dfl PICK. THE SPILL CAN REDIRECT dst_cpu
		// ONTO A BUSY SIBLING: PREEMPT WHEN THE SEAT MOVED AND THE WAKE MAY
		// CUT, IDLE OTHERWISE.
		seat_task(p, tctx, dst_cpu, cpu, dst_dsq, sl, dl, wake_cuts(tctx),
			  dst_cpu != cpu && wake_cuts(tctx)
				  ? SCX_KICK_PREEMPT : SCX_KICK_IDLE, 0);

		if (tctx) {
			tctx->dispatch_path = 0;
			tctx->idle_seat = 1;
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
// TIER 1: IDLE CPU BY PHI'S R_eff WALK -> THAT CPU'S PER-CPU DSQ + KICK
// TIER 0: WARM-STAY WHEN THE WALK MISSES -- AN UNCONGESTED HOME KEEPS THE
//         TASK, NO SPILL -- THEN THE NODE-WIDE IDLE PICK FOR TIER 1
// TIER 2: WAKEUP PREEMPTION -> PER-CPU DSQ (ADMISSION-GATED) + HARD PREEMPT
// TIER 3: FALLBACK -> THE TASK'S OWN CPU'S PER-CPU DSQ + PRICED KICK
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

	// THE CUT'S OWN KICK. seat_cut's PREEMPT KICK ZEROES WHATEVER IS CURRENT WHEN
	// IT LANDS; WHEN THE SEAT RESCHEDULED FIRST, THAT IS THE WAKEE THE CUT SEATED,
	// AND IT ARRIVES HERE A FEW MICROSECONDS INTO ITS RUN AS A REQUEUE THE LANE
	// WOULD QUEUE BEHIND THE RESIDENT IT DISPLACED UNTIL THE NEXT TICK. IT
	// RETURNS TO THE HEAD OF THIS CPU'S LOCAL DSQ WITH ITS SLICE, ONCE PER CUT,
	// WITH NO KICK: A CUT, NEVER A QUEUE, SO NO QUEUE CLOCK IS TOUCHED.
	if (tctx && !is_wakeup && tctx->cut_at) {
		u64 since = bpf_ktime_get_ns() - tctx->cut_at;
		bool self_kicked = since < CUT_SELF_KICK_NS &&
			scx_bpf_task_cpu(p) == (s32)bpf_get_smp_processor_id();

		tctx->cut_at = 0;
		if (self_kicked) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, sl, enq_flags | SCX_ENQ_HEAD);
			return;
		}
	}

	// FLOW SIGNATURE: RECORD THIS WAKEUP'S WAKER IN THE PAIR LEDGER.
	// SCX_OPS_ALLOW_QUEUED_WAKEUP IS ON, SO A WAKE THE KERNEL QUEUES ON THE
	// WAKEE'S CPU (ACROSS AN LLC, OR ONTO AN IDLE CPU) RUNS THIS THERE, WHERE
	// current IS THAT CPU'S TASK. THE WAKER IS READ FROM select_cpu's STAMP. A
	// WAKE THAT SKIPPED select_cpu (ONE ALLOWED CPU, MIGRATION DISABLED) HAS NO
	// STAMP AND READS current: THE WAKER WHEN THE WAKE WAS NOT QUEUED, THE IDLE
	// TASK (pid 0, WHICH THE LEDGER IGNORES) OR THE RESIDENT WHEN IT WAS.
	if (tctx && is_wakeup)
		update_pair_ledger(tctx, tctx->wake_waker
					 ? (s32)(tctx->wake_waker - 1)
					 : (s32)(bpf_get_current_pid_tgid() & 0xffffffff));

	// TIER 1: IDLE CPU -> THAT CPU'S PER-CPU DSQ + KICK. PLACEMENT IS THE R_eff
	// WALK, WITH NO CLASS GATE IN FRONT OF IT. find_idle_by_affinity WALKS
	// affinity_rank IN ASCENDING R_eff, SO DISTANCE DEGRADES CONTINUOUSLY RATHER
	// THAN FALLING OFF A CLIFF INTO AN UNORDERED NODE-WIDE PICK, AND THE BIAS IS
	// EXPRESSED BY *WHICH* IDLE CPU WINS. affinity_search_online IS TAU-DERIVED,
	// 3 AT 12C AND 8 AT 32C, SO THE BUDGET SCALES WITHOUT A KNOB.
	// THE NODE-WIDE pick_idle_cpu BELOW IS THE FALLBACK WHEN THE WALK MISSES.
	s32 cpu = -1;
	if (tctx)
		cpu = find_idle_by_affinity(p, tctx->last_cpu);
	if (cpu < 0) {
		// TIER 0 -- WARM-STAY, REACHED ONLY WHEN PHI'S WALK FOUND NO IDLE CPU.
		// AN UNCONGESTED HOME KEEPS THE TASK, THE DUAL OF THE DISPATCH STEAL
		// THRESHOLD, SEATED DIRECTLY ON ITS PER-CPU DSQ WITH NO SPILL: A
		// LOW-SOJOURN HOME DRAINS FAST EVEN WHEN DEEP, SO A DEPTH-BASED SPILL
		// WOULD MIGRATE AGAINST THE STAY. THE SEAT MAY BE BUSY, SO THE KICK IS
		// PRICED RATHER THAN ASSUMED IDLE. THIS IS WHERE select_cpu's HOLD
		// LANDS. IT PRECEDES THE NODE-WIDE IDLE PICK, WHICH IGNORES DISTANCE.
		// A WAKE THAT MAY NOT CUT IS NOT HELD: IT TAKES AN IDLE CPU ANYWHERE
		// ON THE NODE FIRST, AND ONLY WHEN THERE IS NONE IS IT SEATED AT TIER
		// 2. HELD AT A BUSY HOME IT WAITS OUT THE RESIDENT WHILE ANOTHER CPU
		// IDLES.
		{
			s32 hold = (is_wakeup && !wake_cuts(tctx)) ? -1
				 : warm_seat_pick(p, tctx, knobs, is_wakeup,
						  bpf_ktime_get_ns());
			if (hold >= 0) {
				u64 hdl = task_deadline(tctx, knobs);
				u64 hnow = bpf_ktime_get_ns();
				// PAIR-WARM MARKER: THE WARM-STAY ANCHOR IS A PAIR MEMBER
				// TAKING ITS SEAT, SO STAMP IT FOR THE STEP-1 PAIR-SPLIT
				// HOLD, AS THE keep_own SITE DOES.
				pair_warm_ns[cpu_slot((u32)hold)] = hnow;
				// ASK THE SEAT, NOT THE TASK. AN IDLE ANCHOR IS WOKEN BY
				// SCX_KICK_IDLE; ONLY A BUSY ONE NEEDS THE PREEMPT.
				// THE SEAT TEST ALONE IS NOT ENOUGH ON THE REQUEUE ARM, WHICH
				// IS WHY THIS IS PRICED. THE REQUEUE ANCHOR IS last_cpu AND
				// stopping() SET IT TO THE CPU NOW EXECUTING THIS ENQUEUE, SO
				// THE SEAT IS OCCUPIED BY THE TASK BEING SEATED AND THE
				// OCCUPANCY TEST IS A CONSTANT HERE. requeue_kick_flag ASKS
				// WHAT THE TASK IS OWED INSTEAD, AND A TASK THAT JUST RAN IS
				// OWED NOTHING.
				u64 hold_kick = requeue_kick_flag(tctx, hold, is_wakeup);
				if (seat_task(p, tctx, hold, -1, (u64)hold, sl, hdl,
					      is_wakeup && wake_cuts(tctx), hold_kick,
					      enq_flags) == SEAT_CUT)
					hold_kick = SCX_KICK_PREEMPT;
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
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p->cpus_ptr, node, 0);
	}
	if (cpu >= 0 && (u64)cpu < nr_cpu_ids) {
		// SEAT THE WAKEE ON THAT CPU'S OWN PER-CPU DSQ AND KICK IT. KICK ==
		// DRAIN IDENTITY -- THE KICKED CPU IS THE ONE THAT DISPATCHES IT.
		// STEP 1's R_eff STEAL STILL RELIEVES THE SEAT IF IT AGES PAST THE PHI
		// THRESHOLD.
		u64 tier1_dsq = (u64)cpu;
		dl = tctx ? task_deadline(tctx, knobs)
			  : bpf_ktime_get_ns();

		// KICK BY THE TARGET'S STATE, NOT BY THE TASK'S CLASS. `cpu` CAME FROM
		// AN IDLE PICK; IF IT IS STILL IDLE SCX_KICK_IDLE WAKES IT, AND IF IT
		// WENT BUSY IN BETWEEN ONLY A PREEMPT REACHES IT. SCX_KICK_IDLE IS A
		// DOCUMENTED NO-OP ON A BUSY CPU, SO A TASK LANDING ON A TICKLESS-IDLE
		// CORE WOULD STRAND WITH NO TICK BEHIND IT TO RESCUE THE MISS.
		// requeue_kick_flag PRICES IT: A WAKEUP TAKES THE PREEMPT WHEN
		// wake_cuts SAYS IT MAY, A REQUEUE BUYS IT WITH ITS OWN wait_since
		// CLAIM. A REFUSED WAKE ON A SEAT THAT WENT BUSY HAS THAT SEAT'S
		// TICK BEHIND IT, SO IT WAITS RATHER THAN STRANDS.
		// DELETING THE REQUEUE PREEMPT ENTIRELY STALLS THE BOX -- IN
		// --no-adaptive THE TICK PREEMPT NEVER FIRES, SO THIS KICK IS THE ONLY
		// MECHANISM DISLODGING A RESIDENT. THE PRICE BOUNDS WHEN IT FIRES,
		// NEVER WHETHER.
		u64 kick_flag = requeue_kick_flag(tctx, cpu, is_wakeup);
		if (seat_task(p, tctx, cpu, cpu, tier1_dsq, sl, dl,
			      is_wakeup && wake_cuts(tctx), kick_flag,
			      enq_flags) == SEAT_CUT)
			kick_flag = SCX_KICK_PREEMPT;

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
	// HAS ROOM, ELSE A NEAR R_eff SIBLING, ELSE THE WARM SEAT OVER TARGET.
	// dispatch STEP 0 DRAINS THE WARM PER-CPU DSQ WHEN last_cpu NEXT
	// DISPATCHES; STEP 1's STEAL COVERS A SIBLING LANDING.
	//
	// THE CLASS TEST ADMITS WAKES AND HANDOFF PARTNERS ONLY. A WAKE THAT MAY NOT
	// CUT IS SEATED HERE LIKE ANY OTHER AND WAITS IN ORDER; A PLAIN REQUEUE
	// FALLS PAST THIS TIER TO TIER 3, ITS OWN CPU'S LANE.
	if (tctx && (is_wakeup || is_handoff_partner(tctx))) {
		// WARM-ANCHOR: PREFER THE WAKEE'S OWN LAST CORE. pick_pcpu_dsq_with_spill
		// THEN SEATS IT ON THAT cpu'S PER-CPU DSQ (WARM), A NEAR R_eff SIBLING,
		// OR THE WARM SEAT OVER TARGET.
		cpu = (tctx->last_cpu >= 0 && (u64)tctx->last_cpu < nr_cpu_ids)
		    ? tctx->last_cpu
		    : __COMPAT_scx_bpf_pick_any_cpu_node(p->cpus_ptr, node, 0);
		if (cpu >= 0 && (u64)cpu < nr_cpu_ids &&
		    __COMPAT_scx_bpf_cpu_curr(cpu)) {
			s32 t2_cpu;
			u64 tier2_dsq = pick_pcpu_dsq_with_spill(p, cpu, p->cpus_ptr, is_handoff_partner(tctx), false, &t2_cpu);
			bool t2_cuts = is_wakeup && wake_cuts(tctx);
			// A WAKE THAT MAY NOT CUT TAKES THE NEAREST SEAT WHOSE RESIDENT
			// DOES NOT SLEEP, BY THE CUT, BEFORE IT WAITS IN ORDER BEHIND A
			// RESIDENT THAT WILL NOT YIELD UNTIL ITS SLICE ENDS.
			bool sleepless_walk = is_wakeup && !t2_cuts &&
					      !is_migration_disabled(p);
			bool sleepless_seat = false;
			if (sleepless_walk) {
				s32 hc = find_sleepless_by_affinity(p, cpu,
								    bpf_ktime_get_ns());
				if (hc >= 0) {
					t2_cpu = hc;
					tier2_dsq = (u64)hc;
					t2_cuts = true;
					sleepless_seat = true;
				}
			}

			dl = task_deadline(tctx, knobs);

			// THE KICK GOES TO t2_cpu, NOT `cpu` -- THEY DIFFER WHENEVER
			// THE SPILL FIRES, AND THE HELPER TESTS THE SEAT THAT WILL
			// ACTUALLY HOLD THE TASK.
			u64 kick_flag = requeue_kick_flag(tctx, t2_cpu, is_wakeup);
			bool t2_cut = seat_task(p, tctx, t2_cpu, -1, tier2_dsq, sl, dl,
						t2_cuts, kick_flag, enq_flags) == SEAT_CUT;
			if (t2_cut)
				kick_flag = SCX_KICK_PREEMPT;
			tctx->dispatch_path = 1;

			struct pandemonium_stats *s = get_stats();
			if (s) {
				if (sleepless_seat && t2_cut)
					s->nr_sleepless_cut += 1;
				else if (sleepless_walk)
					s->nr_sleepless_miss += 1;
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

	// TIER 3: THE TASK'S OWN CPU. A PLAIN REQUEUE TAKES THAT CPU'S LANE, A WAKE
	// WITH NO WARM CPU TO ANCHOR ON ITS SEAT, EACH OLDEST-FIRST. A REQUEUED TASK
	// WAS PASSED OVER OR CUT, NOT MOVED, SO IT RESUMES WHERE ITS CACHE IS, AND A
	// MIGRATION-DISABLED TASK WAITS ON THE ONE CPU IT MAY LEAVE FROM. ON THE
	// LANE IT WAITS BEHIND NO WAKE AND NO WAKE BEHIND IT: dispatch() SERVES THE
	// SEAT FIRST UNTIL THE LANE HAS WAITED PAST THE LIVE TARGET. A CPU THAT RUNS
	// DRY TAKES IT BY THE STEAL, AND THE TICK AND THE SWEEP BOUND ITS WAIT. THE
	// KICK IS PRICED AS AT EVERY OTHER TIER: A REQUEUE ON THE CPU RUNNING THIS
	// enqueue IS SILENT, SINCE THIS CPU REACHES dispatch() ON ITS OWN.
	s32 tcpu = scx_bpf_task_cpu(p);
	s32 t3_cpu = allowed_seat(p, tcpu);
	u64 t3_dsq = is_wakeup ? (u64)t3_cpu : lane_dsq((u32)t3_cpu);
	dl = tctx ? task_deadline(tctx, knobs) : bpf_ktime_get_ns();

	// THE RESUME. A RESIDENT DISPLACED BY A CUT RESUMES FROM THE HEAD OF ITS
	// LANE. A CUT PUTS ITS WAKE ON THE SEAT'S LOCAL DSQ AND KICKS, AND THE
	// RESIDENT, TAKEN OFF WITH ITS WORK LEFT, WENT TO THE BACK OF ITS LANE AS THE
	// YOUNGEST CLAIM, BEHIND EVERY REQUEUE THAT HAS HAD ITS RUN AND BEHIND THE
	// SEAT, WHICH A FORK STORM KEEPS FED. MEASURED ON PipeWire's DATA LOOP UNDER
	// THE BURST, A PLAIN THREAD OF 48US A RUN ON A 21.3MS PERIOD: TAKEN A MEDIAN
	// 38US IN AND BACK 2MS TO 13MS LATER, WHERE EEVDF TAKES IT THREE TIMES AS
	// OFTEN AND HAS IT BACK IN 96US.
	// A REQUEUE WITHIN ONE LIVE TARGET OF A CUT ONTO ITS SEAT (cut_ns, THE STAMP
	// seat_task WRITES), WITH UNDER ONE LIVE TARGET OF SERVICE SINCE ITS WAKE, IS
	// THAT RESIDENT, AND IT TAKES THE LANE'S HEAD: EVERY CUT STILL RUNS AHEAD OF
	// IT, THE SEAT IS JUDGED AGAINST THE LANE AS BEFORE, AND WHEN THE LANE IS
	// NEXT SERVED THE TASK THAT WAS INTERRUPTED RUNS ON, NOT ONE THAT HAS HAD ITS
	// RUN. NO CLASS, NO SCORE, NO AVERAGE: TWO MEASURED AGES AGAINST THE LIVE
	// TARGET.
	// THE CUT IS READ FROM ITS STAMP AND NOT FROM THE LOCAL DSQ: THE KERNEL RUNS
	// dispatch BEFORE IT REQUEUES THE RESIDENT, SO THE LOCAL DSQ HOLDS A
	// SUCCESSOR AT NEARLY EVERY REQUEUE, AND A TEST ON THAT, OR NONE, RESUMES
	// EVERY TASK THE TICK OR THE SWEEP TOOK OFF FOR A WAITER, AHEAD OF THE
	// WAITER. IT STANDS AT THIS TIER BECAUSE AN IDLE CPU COMES FIRST, AND ON THE
	// LANE BECAUSE ON THE LOCAL DSQ IT STOOD AHEAD OF EVERY LATER CUT AND RAN
	// WITH NO KICK BEHIND IT: frame's CONTENDED 1% LOW READ 186 TO 238 FPS
	// AGAINST 308. IT IS KEPT OUT OF THE LANE'S CLOCK AND ON THE LANE'S OWN
	// RECORD OF ITS HEAD (resumed_n, resumed_since), SO THE CLOCK KEEPS READING
	// THE LANE'S OWN WORK. NO KICK: THIS CPU REACHES dispatch() ON ITS OWN.
	// THE CLOCK IS READ ONLY FOR A REQUEUE THAT PASSES THE TESTS THAT COST
	// NOTHING, SO A WAKE AND A TASK THAT HAS HAD ITS TARGET PAY NO READ HERE.
	if (tctx && !is_wakeup && t3_cpu == tcpu &&
	    tcpu == (s32)bpf_get_smp_processor_id() &&
	    tctx->wake_svc_ns < codel_target_ns && (u64)tcpu < nr_cpu_ids) {
		u32 rslot = cpu_slot((u32)tcpu);
		u64 t3_now = bpf_ktime_get_ns();
		u64 cut_ns = pcpu_qclock[rslot].cut_ns;

		if (t3_now >= cut_ns && t3_now - cut_ns < codel_target_ns) {
			struct queue_clock *rq = &lane_qclock[rslot];

			qclock_depart(tctx, t3_now, false);
			scx_bpf_dsq_insert_vtime(p, t3_dsq, sl, 1, enq_flags);
			if (__sync_fetch_and_add(&rq->resumed_n, 1) == 0)
				rq->resumed_since = t3_now;
			tctx->resumed = (u16)(rslot + 1);
			tctx->dispatch_path = 2;
			struct pandemonium_stats *rs = get_stats();
			if (rs) {
				rs->nr_shared += 1;
				rs->nr_kick_declined += 1;
				rs->nr_enq_requeue += 1;
			}
			return;
		}
	}

	u64 kick_flag = requeue_kick_flag(tctx, t3_cpu, is_wakeup);
	if (seat_task(p, tctx, t3_cpu, -1, t3_dsq, sl, dl,
		      is_wakeup && wake_cuts(tctx), kick_flag,
		      enq_flags) == SEAT_CUT)
		kick_flag = SCX_KICK_PREEMPT;

#if TRACE_SCHED
	if (is_sched_task(p))
		bpf_printk("PAND: enq tier3 pid=%d cpu=%d", p->pid, t3_cpu);
#endif

	if (tctx)
		tctx->dispatch_path = is_wakeup ? 1 : 2;

	struct pandemonium_stats *s = get_stats();
	if (s) {
		s->nr_shared += 1;
		// COUNT THE KICK BY WHAT WAS ISSUED, NOT BY WHAT THE TASK IS.
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
		u64 w = queue_wait(&pcpu_qclock[cpu_slot(c)], now);
		// THE CLOCK's OWN BOUND, BETWEEN TICKS. A HEAD THAT HAS WAITED PAST
		// codel_target_ns ON A SEAT WHOSE RESIDENT KEEPS RUNNING WAS RESCUED
		// ONLY BY THAT CPU's TICK BAND, SO EVERY SUCH WAIT ROUNDED UP TO A
		// TICK. THE SEAT's JUDGE PACES THIS ACT (CoDel's CONTROL LAW, PACE ONE
		// TARGET), SO A QUEUE THAT KEEPS STANDING IS ACTED ON FASTER AND
		// FASTER AND ONE THAT DRAINS IS LEFT ALONE. A RESIDENT STILL OWED
		// ITS FIRST TARGET IS NOT PREEMPTED HERE (resident_owed); THE NEXT
		// SWEEP JUDGES THE SEAT AGAIN. lag_cap_ns STAYS THE UNPACED BACKSTOP.
		if (pcpu_kick_owed(c, w, lag_cap_ns, now))
			continue;
		// THE LANE'S STARVATION BOUND, UNPACED LIKE THE SEAT'S: A REQUEUE THAT
		// HAS WAITED lag_cap_ns BEHIND A RESIDENT THAT NEVER YIELDS IS FORCED
		// IN, AND THE KICKED CPU'S AGED-LANE SERVE TAKES IT.
		struct queue_clock *lq = &lane_qclock[cpu_slot(c)];
		if (queue_act(lq, queue_wait(lq, now), lag_cap_ns, 0, now)) {
			scx_bpf_kick_cpu((s32)c, SCX_KICK_PREEMPT);
			continue;
		}
		if (!resident_owed(c, now) &&
		    queue_act(&pcpu_qclock[cpu_slot(c)], w, codel_target_ns,
			      codel_target_ns, now))
			scx_bpf_kick_cpu((s32)c, SCX_KICK_PREEMPT);
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
	u32 budget;
	s32 best_peer;
	u32 lost;
	u32 held;
	bool would_idle;
	bool lanes;
	bool rescue;
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
			if (++c->checked >= c->budget)
				return 1;
			return 0;
		}
		// THE PEER QUEUE'S WAIT, ITS SEAT'S OR ITS LANE'S. ZERO MEANS THE QUEUE
		// IS EMPTY, SO SKIP THE REMOTE scx_bpf_dsq_nr_queued TOUCH -- THE COMMON
		// CASE UNDER WAKE-HEAVY LOAD.
		u64 pdsq = c->lanes ? lane_dsq(peer) : (u64)peer;
		struct queue_clock *pq = c->lanes ? &lane_qclock[cpu_slot(peer)]
						  : &pcpu_qclock[cpu_slot(peer)];
		u64 peer_wait = queue_wait(pq, c->now);
		// A LANE WITH A RESUMED TASK AT ITS HEAD IS PRICED ON THAT TASK'S OWN
		// WAIT, SINCE IT IS THE ONE THE MOVE WOULD TAKE. PRICED ON THE LANE'S
		// CLOCK, WHICH READS THE OLDER WORK BEHIND IT, A TASK CUT MICROSECONDS
		// AGO WOULD BE TAKEN OFF ITS CPU AT ONCE.
		if (c->lanes && pq->resumed_n)
			peer_wait = lane_resumed_wait(pq, c->now);
		if (peer_wait == 0) {
			if (++c->checked >= c->budget)
				return 1;
			return 0;
		}
		u32 nq = scx_bpf_dsq_nr_queued(pdsq);
		if (nq >= 1) {
			// THE DISTANCE, PRICED AS THE DOMAIN QUEUE'S NEAR DRAIN WAS:
			// reff_frac, R_eff AS A FRACTION OF THE MACHINE'S SPAN, OF ONE LIVE
			// TARGET, SO AN SMT SIBLING COSTS NOTHING AND THE FARTHEST PEER ONE
			// TARGET. NOT reff_value, WHICH FOLDS R_eff AGAINST tau AND READS
			// ITS 2 x codel_eq_ns CAP FOR EVERY NON-SIBLING HERE: A JOB WAITING
			// BEHIND A RESIDENT IN ITS OWN L3 WOULD OWE A MILLISECOND BEFORE AN
			// IDLE NEIGHBOUR TOOK IT. A SENTINEL PRICES AS THE FARTHEST.
			u32 *fp = bpf_map_lookup_elem(&reff_frac, &key);
			u32 fr = (fp && *fp != (u32)-1) ? *fp : 65536;
			u64 price = ((u64)fr * codel_target_ns) >> 16;
			// PAIR-SPLIT HOLD: peer RECENTLY SEATED A CONFIRMED PAIR,
			// STAMPED IN pair_warm_ns. STEALING ITS HEAD SPLITS THE PAIR,
			// A LOCALITY LOSS R_eff CANNOT SEE BECAUSE A NEAR SPLIT LOOKS
			// CHEAP. PRICE IT BY THE SEAM INSTEAD -- domain_phi IS HIGH
			// FOR A TIGHT SEAM, SO A NEAR SPLIT WAITS UP TO ONE EXTRA
			// TARGET WHILE A FAR SPLIT ADDS ~0, BEING PRICED ALREADY BY
			// THE DISTANCE. THE SENTINEL MEANS NO HOLD.
			// A PRICE, NOT A GATE -- STARVATION TRIPS THE LONGER SOJOURN. A PAIR
			// SITS ON A SEAT, SO A LANE OWES NO HOLD.
			u64 pair_hold = 0;
			u64 pw = pair_warm_ns[cpu_slot(peer)];
			if (!c->lanes && pw && c->now >= pw && (c->now - pw) < codel_target_ns) {
				u32 *dpp = bpf_map_lookup_elem(&domain_phi, &key);
				u32 dphi = dpp ? *dpp : (u32)-1;
				if (dphi != (u32)-1) {
					u64 hold = ((u64)dphi * codel_target_ns) / 1000000ULL;
					if (hold > codel_target_ns)
						hold = codel_target_ns;
					pair_hold = hold;
				}
			}
			// TWO BOUNDS ON ONE AGE, THE PEER QUEUE'S WAIT, WHATEVER THE PEER'S
			// DEPTH. A CPU ABOUT TO IDLE WEIGHS THE MOVE AGAINST NOTHING, SO IT
			// TAKES A HEAD THAT HAS WAITED THE BASE COST OF ANY MOVE; THE WALK
			// ORDER IS THE DISTANCE AND THE BUDGET ITS REACH. A BUSY CPU GIVES UP
			// prev FOR A HEAD THAT HAS WAITED THE BASE COST PLUS THE DISTANCE.
			// PAST THE BUSY BUDGET A LANE IS PRICED AS A BUSY THIEF PRICES IT,
			// EVEN FOR A CPU ABOUT TO IDLE: A FAR LANE HOLDS HOGS AS WELL AS
			// DISPLACED WORK, AND TAKING ONE THERE AT THE BASE COST MOVES HOGS
			// ACROSS THE BOX.
			bool far_lane = c->lanes && c->checked >= pcpu_spill_search_budget;
			u64 rest = ((c->would_idle && !far_lane) ? 0 : price) + pair_hold;
			if (peer_wait >= phi_base_cost_ns + rest) {
				// THE MOVE IS TAKEN IN THE WALK, SO A RACE LOST TO ANOTHER
				// THIEF OR TO THE PEER'S OWN STEP 0 WALKS ON TO THE NEXT
				// QUALIFYING PEER INSTEAD OF ENDING THE SCAN.
				if (scx_bpf_dsq_move_to_local(pdsq, 0)) {
					c->best_peer = (s32)peer;
					c->rescue = c->lanes && peer_wait > codel_target_ns;
					return 1;
				}
				c->lost += 1;
			} else if (peer_wait >= phi_base_tau_ns + rest) {
				// tau's BASE WOULD HAVE TAKEN THIS HEAD AND THE LIVE COST HELD
				// IT: THE PRICE's REFUSAL. THE HEAD IS TAKEN ONCE IT HAS WAITED
				// THE LIVE BOUND.
				c->held += 1;
			}
		}
		if (++c->checked >= c->budget)
			return 1;
	return 0;
}

// A LANE THAT WAITED PAST THE LIVE TARGET WAS SERVED: THE OSCILLATOR'S FORCING
// TERM. EVERY DISPATCH THAT SERVES ONE, ITS OWN OR A PEER'S, IS A RESCUE, AND
// THE RESCUE RATE IS WHAT PULLS THE TARGET DOWN UNDER LOAD. A SEAT SERVED LATE
// IS NOT ONE: THE RESCUE MEASURES THE REQUEUE CLASS'S BACKLOG.
static __always_inline void rescue_served(struct pandemonium_stats *s)
{
	if (s)
		s->nr_rescue += 1;
	__sync_fetch_and_add(&global_rescue_count, 1);
}

// ONE R_eff STEAL WALK OVER THE PEERS' SEATS, OR THEIR LANES. TRUE IF A TASK
// MOVED. BLUMOFE AND LEISERSON'S WORK STEALING (1999), ORDERED AND PRICED: SLOT
// 0 OF affinity_rank IS THE L2 SIBLING, SLOTS 1+ THE R_eff-RANKED PEERS, CROSS-
// DOMAIN INCLUDED, SO THE FIRST QUALIFYING PEER IS THE CLOSEST -- MIN-COST
// FLOW. A BUSY CPU's BUDGET IS pcpu_spill_search_budget (nr_cpu_ids/2 CLAMPED
// TO [6, MAX_AFFINITY_CANDIDATES]), MATCHING THE ENQUEUE-SIDE SPILL HELPER. A
// CPU ABOUT TO IDLE WALKS THE WHOLE RANK: IT IS ON NO WAKE PATH, AN EMPTY PEER
// COSTS ONE queue_wait READ, AND AT 12C SIX SLOTS REACH ONE PEER ACROSS THE L3.
static __always_inline bool steal_from(s32 cpu, u64 now, bool would_idle,
				       bool lanes)
{
	u32 my_cpu = (u32)cpu;
	struct steal_scan_ctx sctx = {
		.now = now, .base = my_cpu * MAX_AFFINITY_CANDIDATES,
		.my_cpu = my_cpu, .checked = 0,
		.budget = would_idle ? nr_cpu_ids : pcpu_spill_search_budget,
		.best_peer = -1, .lost = 0, .held = 0,
		.would_idle = would_idle, .lanes = lanes, .rescue = false,
	};
	bpf_loop(MAX_AFFINITY_CANDIDATES, steal_scan_step, &sctx, 0);
	if (!sctx.lost && !sctx.held && sctx.best_peer < 0)
		return false;
	struct pandemonium_stats *s = get_stats();
	if (s) {
		s->nr_steal_lost += sctx.lost;
		s->nr_steal_base_held += sctx.held;
		if (sctx.best_peer >= 0) {
			s->nr_dispatches += 1;
			s->nr_steal += 1;
			// STEAL: task's home is best_peer, now consumed by `cpu`.
			cross_domain_bump(s, XDOM_STEAL, sctx.best_peer, cpu);
		}
	}
	if (sctx.rescue)
		rescue_served(s);
	return sctx.best_peer >= 0;
}

// DISPATCH: CPU IS IDLE AND NEEDS WORK. EVERY RUNNABLE TASK WAITS ON ONE CPU'S
// SEAT OR LANE, SO THE STEAL IS THE ONE CROSS-CPU PATH:
//   UNIFIED BOUND, FIRST (sweep_bound_preempt -- off-tick, NO_HZ_FULL-immune)
//   AGED LANE: THE OWN LANE, PAST THE TARGET AND OLDER THAN THE SEAT
//   0. OWN SEAT (CACHE-HOT, ZERO CONTENTION)
//   1. STEAL A PEER'S SEAT
//   2. OWN LANE
//   3. STEAL A PEER'S LANE
//   KEEP_RUNNING IF PREV STILL WANTS CPU AND NOTHING QUEUED
// ONE TASK INTO THE LOCAL DSQ PER DISPATCH. THE KERNEL RUNS A LOCAL TASK
// WITHOUT CALLING dispatch(), SO A SECOND TASK MOVED HERE WOULD WAIT OUT THE
// FIRST'S WHOLE SLICE ON A QUEUE THAT HAS NO CLOCK, AHEAD OF EVERYTHING SEATED
// ON THIS CPU AFTER IT, WHERE NO DECISION CAN READ THAT WAIT.
void BPF_STRUCT_OPS(pandemonium_dispatch, s32 cpu, struct task_struct *prev)
{
	struct pandemonium_stats *s;
	u64 now = bpf_ktime_get_ns();

	// UNIFIED BOUND, FIRST: RESCUE ANY CPU WHOSE PER-CPU DSQ HEAD HAS WAITED
	// PAST lag_cap_ns, BEFORE THIS CPU RUNS ITS OWN PLACEMENT WATERFALL. A HARD
	// INVARIANT AHEAD OF PLACEMENT, RUN OFF ANOTHER CPU'S DISPATCH SO THE HELD
	// CPU'S OWN TICK IS NOT NEEDED. UNCONDITIONAL AND NOT TO BE REORDERED.
	sweep_bound_preempt(now, (u32)cpu);

	if ((u64)cpu >= nr_cpu_ids)
		return;
	u32 slot = cpu_slot((u32)cpu);

	// THE AGED LANE. THE SEAT AND THE LANE ARE JUDGED ON THE ONE CLOCK: WHEN
	// THE LANE HAS WAITED PAST codel_target_ns AND LONGER THAN THE SEAT, IT
	// GIVES THIS DISPATCH ITS TASK AND THE SEAT GIVES THE NEXT, SO A CPU WITH
	// HOT WAKES STILL VISITS ITS AGED REQUEUES AND A WORKQUEUE WORKER IS NOT
	// STARVED THERE. THE SERVE IS A RESCUE.
	// A CPU CARRYING A LIVE HANDOFF PAIR -- A PARTNER SEATED ON IT WITHIN ONE
	// LIVE TARGET -- SERVES ITS SEAT FIRST, SO THE PARTNER THE TIGHT SEAT JUST
	// PUT THERE IS NOT PASSED FOR A REQUEUE. PAST lag_cap_ns THE LANE IS SERVED
	// ANYWAY, SO THE STARVATION BOUND STANDS.
	u64 lane_wait = queue_wait(&lane_qclock[slot], now);
	// A RESUMED TASK AT THE LANE'S HEAD IS OUTSIDE THE LANE'S CLOCK, SO THE
	// LANE IS AS OLD AS THE OLDER OF THE TWO.
	u64 resumed_wait = lane_resumed_wait(&lane_qclock[slot], now);
	if (resumed_wait > lane_wait)
		lane_wait = resumed_wait;
	u64 pw = pair_warm_ns[slot];
	bool pair_live = pw && now >= pw && now - pw < codel_target_ns &&
			 lane_wait < lag_cap_ns;
	if (!pair_live && lane_wait > codel_target_ns &&
	    lane_wait > queue_wait(&pcpu_qclock[slot], now) &&
	    scx_bpf_dsq_move_to_local(lane_dsq((u32)cpu), 0)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		rescue_served(s);
		return;
	}

	// STEP 0: OWN SEAT -- HIGHEST PRIORITY, CACHE-HOT.
	if (scx_bpf_dsq_move_to_local((u64)cpu, 0)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// A CPU WITH NO prev TO KEEP -- IT BLOCKED, IS EXITING OR NEVER WAS -- IS
	// ABOUT TO IDLE.
	bool would_idle = !(prev && !(prev->flags & PF_EXITING) &&
			    (prev->scx.flags & SCX_TASK_QUEUED));

	// SCAN RATE-LIMIT, ONE WINDOW FOR BOTH WALKS. A CPU ABOUT TO IDLE SCANS
	// EVERY TIME: IT IS ON NO WAKE PATH, AND WHAT IT LEAVES WAITS WHILE IT
	// SLEEPS. A BUSY CPU SCANS ONCE PER codel_target_ns, SINCE THE PEER WALK IS
	// THE DOMINANT PER-DISPATCH CACHE COST UNDER WAKE-HEAVY LOAD AND A PEER
	// CANNOT ACCUMULATE STEALABLE BACKLOG FASTER; BETWEEN ITS SCANS tick()'s
	// REMOTE SCAN AND THE SWEEP BOUND EVERY QUEUE.
	u32 zero = 0;
	u64 *last_scan = bpf_map_lookup_elem(&last_spill_scan, &zero);
	bool due = !last_scan || *last_scan == 0 ||
		   (now - *last_scan) >= codel_target_ns;
	if (due && last_scan)
		*last_scan = now;
	bool scan = would_idle || due;

	// STEP 1: A PEER'S SEAT. A WAKE WAITING ELSEWHERE COMES BEFORE THIS CPU'S
	// OWN REQUEUES, AS THE SEAT COMES BEFORE THE LANE.
	if (scan && steal_from(cpu, now, would_idle, false))
		return;

	// STEP 2: OWN LANE, WHATEVER ITS AGE -- THIS CPU'S OWN REQUEUES, WARM.
	if (scx_bpf_dsq_move_to_local(lane_dsq((u32)cpu), 0)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// STEP 3: A PEER'S LANE, AT THE SAME PRICES.
	if (scan && steal_from(cpu, now, would_idle, true))
		return;

	// NOTHING QUEUED OR STEALABLE -- KEEP PREV RUNNING IF POSSIBLE
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
	tctx->wake_svc_ns = 0;

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
		resident_sleepless[cpu_slot(bpf_get_smp_processor_id())] = 0;
		scx_bpf_task_set_slice(p,
			knobs ? knobs->slice_ns : 1000000);
		return;
	}

	u64 now = bpf_ktime_get_ns();

#ifndef PAND_NO_RQ_DEPTH
	// THE QUEUE CLOCK AND THE ARRIVAL COUNT INTO THE QUEUE RING. THE WAIT THIS
	// RUN ENDS RUNS FROM THE TASK'S FIRST INSERT AFTER ITS LAST RUN, OR FROM
	// ITS WAKE WHEN IT WAS SEATED WITHOUT ONE (THE IDLE FAST PATH). A RUN THAT
	// ENDS A WAKE IS AN ARRIVAL, AND ONE select_cpu SEATED ON AN IDLE CPU IS AN
	// IDLE HIT. FOUR ADDS AND A MINIMUM ON A SLOT THIS CPU OWNS.
	{
		u32 zero = 0;
		struct depth_slot *sl = depth_slot_now(bpf_map_lookup_elem(&depth_ring, &zero), now);

		if (sl) {
			u64 since = tctx->wait_since ? tctx->wait_since : tctx->last_woke_at;
			u64 wait_us = since && now > since ? (now - since) / 1000 : 0;
			u64 room = 0xFFFFFFFFULL - sl->wait_us;

			u32 w32 = wait_us < 0xFFFFFFFFULL ? (u32)wait_us : 0xFFFFFFFFU;

			sl->runs++;
			if (tctx->last_woke_at) {
				sl->wakes++;
				sl->idle += tctx->idle_seat;
			}
			sl->wait_us += wait_us < room ? wait_us : room;
			if (sl->runs == 1 || w32 < sl->min_wait_us)
				sl->min_wait_us = w32;
		}

		// THE FLOW ROW: A WAKE COUNTS FROM ITS WAKER'S CPU, A RUN AWAY FROM
		// THE LAST ONE FROM THAT CPU. last_cpu STILL HOLDS THE PREVIOUS RUN'S
		// CPU HERE; stopping() MOVES IT.
		struct flow_row *fr = bpf_map_lookup_elem(&flow_rows, &zero);

		if (fr) {
			u32 here = bpf_get_smp_processor_id();

			if (tctx->last_woke_at && tctx->wake_cpu)
				fr->wake[(tctx->wake_cpu - 1) & (MAX_CPUS - 1)]++;
			if (tctx->last_cpu >= 0 && (u32)tctx->last_cpu != here)
				fr->mig[(u32)tctx->last_cpu & (MAX_CPUS - 1)]++;
		}
	}
#endif

	run_start_ns[cpu_slot(bpf_get_smp_processor_id())] = now;
	resident_sleepless[cpu_slot(bpf_get_smp_processor_id())] =
		tctx->sleepless_runs >= SLEEPLESS_CONFIRM;
	tctx->run_exec_at = p->se.sum_exec_runtime;   // service base, see stopping()
	tctx->ran_since_wake = true;   // is_wakeup = !ran_since_wake
	tctx->sync_wake = 0;
	tctx->fanout_wake = 0;
	// THE STINT THIS RUN STARTS IS PRICED BY WHERE ITS WAKE CAME FROM: ANOTHER
	// CPU IN THE WAKER's L3 (1) OR ACROSS IT (2). research t14 HOLDS OUT A WAKE
	// ON THE WAKER's OWN CPU, ONE FROM IDLE (THE WAKER IS PID 0, wake_waker 1)
	// AND A KTHREAD's RUN, AND THOSE SKIP BOTH DOMAIN LOOKUPS.
	tctx->wake_class = 0;
	if (tctx->last_woke_at && tctx->wake_cpu && tctx->wake_waker > 1 &&
	    !(p->flags & PF_KTHREAD)) {
		u32 here = bpf_get_smp_processor_id();
		s32 from = (s32)tctx->wake_cpu - 1;

		if ((u32)from != here)
			tctx->wake_class = cpu_domain_of(from) ==
					   cpu_domain_of((s32)here) ? 1 : 2;
	}
	tctx->idle_seat = 0;
	tctx->wake_waker = 0;
	tctx->wake_cpu = 0;
	qclock_depart(tctx, now, true);   // LEFT ITS QUEUE TO RUN -- A SOJOURN
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
	resident_sleepless[cpu_slot(bpf_get_smp_processor_id())] = 0;
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	// THE SLEEPLESS LEDGER: A STOP THAT LEAVES THE TASK RUNNABLE ADVANCES IT,
	// ONE THAT BLOCKS CLEARS IT.
	if (runnable) {
		if (tctx->sleepless_runs < PAIR_OBS_CAP)
			tctx->sleepless_runs += 1;
	} else {
		tctx->sleepless_runs = 0;
	}

	// THE WAKER'S SIDE OF waker_leaving(): DID THIS TASK BLOCK WITHIN THE BOUND
	// OF ITS LAST WAKE? ONE COMPARE, ONLY WHEN A WAKE WAS STAMPED. A STOP THAT
	// LEAVES IT RUNNABLE IS A PREEMPTION, NOT A DEPARTURE: A TIMER OR IRQ WAKE
	// RUNS IN WHATEVER TASK IS CURRENT, AND A HOG PREEMPTED BY A WAKEE IT NEVER
	// WOKE MUST NOT READ AS A WAKER THAT LEAVES (MEASURED: COUNTING PREEMPTIONS
	// SEATED THE LATENCY PROBE BEHIND THE STRESS WORKERS, 8C LATENCY P99 2,268US).
	if (tctx->woke_at) {
		struct tuning_knobs *lk = get_knobs();
		u64 bound = lk ? lk->waker_leave_ns : 0;
		u64 since = bpf_ktime_get_ns() - tctx->woke_at;

		if (bound && since <= bound && !runnable) {
			if (tctx->leaves_after_wake < PAIR_OBS_CAP)
				tctx->leaves_after_wake += 1;
		} else {
			tctx->leaves_after_wake = 0;
		}
		tctx->woke_at = 0;
	}

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
	tctx->wake_svc_ns += svc;

	// SERVICE LEDGER: A RUN THAT CONSUMED A FULL TARGET ADVANCES THE COUNT, ANY
	// SHORTER RUN CLEARS IT. SATURATES SO A LONG HOG CANNOT BANK UNBOUNDED CREDIT.
	if (svc >= codel_target_ns) {
		if (tctx->standing_runs < STANDING_CAP)
			tctx->standing_runs += 1;
	} else {
		tctx->standing_runs = 0;
	}

	// THE REFILL LEDGER. A RUN THAT ENDED A CLASSED WAKE APPENDS ITS TASK, ITS
	// CLASS AND THE SERVICE IT RENDERED TO THIS CPU's RING IN ONE 64-BIT STORE,
	// SO A READER RACING IT NEVER SEES HALF A RECORD. NOTHING IS ESTIMATED HERE:
	// THE LAYER PAIRS THE RECORDS PER TASK (research t14).
	if (tctx->wake_class) {
		u32 zero = 0;
		struct refill_ring *rr = bpf_map_lookup_elem(&refill_ring, &zero);

		if (rr) {
			u64 x = svc < 0xFFFFFFFFULL ? svc : 0xFFFFFFFFULL;
			u64 key = ((u64)(u32)p->pid << 1) | (u64)(tctx->wake_class >> 1);

			rr->rec[rr->head & (REFILL_RING_SLOTS - 1)] = key << 32 | x;
			rr->head += 1;
		}
		tctx->wake_class = 0;
	}
}

// TICK: SOJOURN ENFORCEMENT AND THE PER-CPU BAND
// FIRES ON EVERY KERNEL SCHEDULER TICK (HZ-DEPENDENT, 1-4MS) REGARDLESS
// OF SLICE LENGTH. THREE RESPONSIBILITIES:
// 1. THE LANE: THIS CPU'S REQUEUES WAITING PAST THE TARGET SELF-PREEMPT IT.
// 2. SOJOURN: A PER-CPU QUEUE, THIS CPU'S OR ONE OF A ROTATING FOUR, WHOSE
//    WAIT PASSED codel_thresh_ns GETS ITS RESIDENT PREEMPTED.
// 3. THE BAND: WHEN THIS CPU'S OWN QUEUE HAS WAITED A BAND, ITS RESIDENT IS
//    PREEMPTED, PACED BY THE SEAT'S JUDGE.
void BPF_STRUCT_OPS(pandemonium_tick, struct task_struct *p)
{
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

	// THE APPLIED BASE COST: THE REFILL THE LAYER MEASURED ONCE IT HAS WRITTEN
	// ONE, ON intf.h's RAIL, ELSE tau's, SO A 0 WRITTEN AFTER A VALUE (A HOTPLUG's
	// BASE SET, A SPAN WITHOUT A READING) RESTORES tau's. STORED ONLY ON A
	// CHANGE: EVERY STEAL AND SPILL READS THE LINE.
	{
		u64 v = knobs ? knobs->phi_base_ns : 0;

		if (!v)
			v = phi_base_tau_ns;
		else if (v < PHI_BASE_MIN_NS)
			v = PHI_BASE_MIN_NS;
		else if (v > PHI_BASE_MAX_NS)
			v = PHI_BASE_MAX_NS;
		if (v != phi_base_cost_ns)
			phi_base_cost_ns = v;
	}

	// PER-CPU RUNNABLE DEPTH SAMPLE, SEAT, LANE AND LOCAL DSQ, INTO THE QUEUE
	// RING. NOT GATED TO CPU 0 -- THE POINT IS THE SPATIAL DIMENSION, WHICH A
	// SINGLE CPU'S QUEUE CANNOT GIVE. THREE DSQ COUNTER READS, ONE DOMAIN
	// LOOKUP AND A DIVIDE PER TICK PER CPU, ALL THIS CPU'S OWN. THE TICK FIRES
	// ONLY WHILE A sched_ext TASK RUNS, SO ticks PER BUCKET IS ALSO HOW BUSY
	// THE CPU WAS.
	// BUILD WITH -DPAND_NO_RQ_DEPTH TO COMPILE THE SAMPLE OUT AND A/B ITS COST
	// AGAINST THE --no-adaptive ARM, WHICH RUNS NO RUST LOOP.
#ifndef PAND_NO_RQ_DEPTH
	{
		u32 zero = 0;
		struct depth_ring *r = bpf_map_lookup_elem(&depth_ring, &zero);
		struct depth_slot *sl = depth_slot_now(r, bpf_ktime_get_ns());

		if (r && sl) {
			s32 cpu = bpf_get_smp_processor_id();
			u32 dom = cpu_domain_of(cpu);
			s32 own = scx_bpf_dsq_nr_queued((u64)cpu);
			s32 lane = scx_bpf_dsq_nr_queued(lane_dsq((u32)cpu));
			s32 loc = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL);

			sl->ticks++;
			if (own > 0)
				sl->own += own;
			if (lane > 0)
				sl->lane += lane;
			if (loc > 0)
				sl->loc += loc;
			r->domain = dom;
		}
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
				// (A tau RETUNE), OR THE MAX-PARK HEARTBEAT.
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

			// THE LOOP IS CLOSED BY CONSTRUCTION: THE AGED-LANE SERVE AND THE
			// LANE STEAL TEST A LANE'S WAIT AGAINST codel_target_ns ITSELF, SO
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

	// THIS CPU'S LANE. A REQUEUE STARVED PAST ITS BOUND BEHIND A RESIDENT
	// SELF-PREEMPTS THIS CPU, SO dispatch()'S AGED-LANE SERVE TAKES IT. IT
	// PREEMPTS INTERACTIVE RUNNERS TOO: UNDER A FORK STORM THE CORES RUN A
	// CONVEYOR BELT OF SHORT WORKERS, EACH YIELDING FAST ONLY FOR THE NEXT ONE,
	// SO THE BURIED TASK NEVER GETS IN. A DECLARED RT POLICY ANSWERS TO
	// lag_cap_ns INSTEAD: SCHED_FIFO/RR IS A CONTRACT USERSPACE STATED, AND IT
	// IS STILL BOUNDED. THE LANE'S JUDGE PACES THIS TO ONE PREEMPT PER BOUND.
	// A CPU CARRYING A LIVE HANDOFF PAIR ANSWERS TO lag_cap_ns TOO, THE RULE
	// dispatch()'S AGED-LANE SERVE HOLDS. THE PAIR KEEPS THIS CPU BUSY, SO THE
	// TASK IT DISPLACED STANDS IN THE LANE, AND A KICK AT THE TARGET LANDS ON
	// AN EMPTY SEAT: STEP 2 THEN SERVES THE LANE AND THE PAIR LOSES A TICK AND
	// ITS CPU, ONCE EVERY FEW TICKS. PAST lag_cap_ns THE LANE IS SERVED ANYWAY.
	{
		u32 lcpu = bpf_get_smp_processor_id();
		u32 lslot = cpu_slot(lcpu);
		struct queue_clock *lq = &lane_qclock[lslot];
		u64 lnow = bpf_ktime_get_ns();
		u64 lw = queue_wait(lq, lnow);
		u64 lrw = lane_resumed_wait(lq, lnow);
		if (lrw > lw)
			lw = lrw;
		u64 lpw = pair_warm_ns[lslot];
		bool lpair = lpw && lnow >= lpw && lnow - lpw < codel_target_ns;
		u64 net_bound = (lpair || p->policy == SCHED_FIFO ||
				 p->policy == SCHED_RR)
			      ? lag_cap_ns : codel_target_ns;
		if (lw > 0 && queue_act(lq, lw, net_bound, net_bound, lnow)) {
			scx_bpf_kick_cpu((s32)lcpu, SCX_KICK_PREEMPT);
			if (!s)
				s = get_stats();
			if (s)
				s->nr_preempt += 1;
			return;
		}
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
			u64 own_wait = queue_wait(&pcpu_qclock[cpu_slot(this_cpu)], now2);
			if (own_wait > codel_thresh_ns &&
			    pcpu_kick_owed(this_cpu, own_wait, codel_thresh_ns, now2))
				return;
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
					u64 rw = queue_wait(&pcpu_qclock[cpu_slot(scan_cpu)], now2);
					if (rw > codel_thresh_ns)
						pcpu_kick_owed(scan_cpu, rw, codel_thresh_ns, now2);
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
					u64 rw = queue_wait(&pcpu_qclock[cpu_slot(scan_cpu)], now2);
					if (rw > codel_thresh_ns)
						pcpu_kick_owed(scan_cpu, rw, codel_thresh_ns, now2);
				}
			}
		}
	}

	// PER-CPU PREEMPT: THE SIGNAL IS THIS CPU'S OWN QUEUE WAIT, SO EACH CPU
	// DECIDES FROM ITS OWN STATE WITH NO GLOBAL TOKEN.
	// THE COARSE codel_thresh NET ABOVE HANDLES THE LONG WAIT; THIS IS THE TIGHT
	// BAND, AND NOTHING IS EXEMPT FROM IT.
	// THE BAND IS codel_target_ns, BPF-DERIVED AND ALWAYS LIVE.
	u32 wcpu = bpf_get_smp_processor_id();
	if (wcpu >= MAX_CPUS)
		return;
	u64 wnow = bpf_ktime_get_ns();
	u64 wait_age = queue_wait(&pcpu_qclock[cpu_slot(wcpu)], wnow);
	if (wait_age == 0)
		return;

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
	if (wait_age >= band) {
		if (pcpu_kick_owed(wcpu, wait_age, band, wnow)) {
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
		tctx->last_woke_at = bpf_ktime_get_ns();
		tctx->cached_weight = WEIGHT_INTERACTIVE;
		tctx->last_waker_pid = -1;  // NO PARTNER SEEN YET
		tctx->same_waker_runs = 0;
		tctx->last_wakee_pid = -1;
		tctx->same_wakee_runs = 0;
		tctx->standing_runs = 0;   // NO SERVICE RENDERED YET
		tctx->dispatch_path = 0;
		// -1 = NEVER RAN. select_cpu's WARM PATH ANCHORS A last_cpu < 0 TASK
		// ON prev_cpu, THE PARENT'S CPU AT FORK, SO IT WARM-ROUTES INSTEAD OF
		// ALIASING CPU 0 OR SCATTERING VIA THE NODE-WIDE dfl PICK.
		tctx->last_cpu = -1;
		tctx->home_cpu = -1;   // PINNED ON FIRST RUN, IN stopping()
		tctx->queued_on = 0;   // ON NO QUEUE YET
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

	// PER-CPU DSQs, TWO A CPU, AND EVERY RUNNABLE TASK WAITS ON ONE: THE SEAT,
	// DSQ cpu, WHERE select_cpu AND ENQUEUE TIER 0/1/2 SEAT A WAKE OR A
	// PARTNER, AND THE LANE, DSQ nr_cpu_ids + cpu, WHERE TIER 3 KEEPS A REQUEUE.
	// VISIBILITY LAYERS:
	//   1. L2 WORK STEALING IN DISPATCH -- IDLE CPUs PULL FROM SIBLINGS
	//   2. ROTATING TICK SCAN -- CATCHES STALE TASKS ON IDLE CPUs
	//   3. PER-CPU SOJOURN RESCUE -- THRESHOLD CEILING ON INVISIBILITY
	for (u32 i = 0; i < nr_cpu_ids && i < MAX_CPUS; i++) {
		scx_bpf_create_dsq(i, -1);
		scx_bpf_create_dsq(lane_dsq(i), -1);
	}

	// ALL TIMING-CONSTANT AND OSCILLATOR-DYNAMICS STATICS BELOW ARE DERIVED
	// FROM tau (Fiedler-based time constant) VIA apply_tau_scaling() AT THE
	// FIRST CPU-0 TICK. MIDPOINT CONSTANTS HERE PROVIDE SANE BEHAVIOR DURING
	// THE ~1MS WINDOW BETWEEN struct_ops ATTACH AND THAT FIRST TICK. THEY
	// ARE OVERWRITTEN IMMEDIATELY -- DON'T READ SIGNIFICANCE INTO THEM.
	codel_target_floor_ns      =    500000ULL;  // 500us midpoint of [200, 800]
	pcpu_spill_search_budget   = 6;             // 12C MIDPOINT
	affinity_search_online     = 3;             // 12C MIDPOINT
	lag_cap_ns                 = 40000000ULL;   // 40MS, MIDPOINT OF [8, 80]
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

	// INITIALIZE DEFAULT TUNING KNOBS
	struct tuning_knobs *knobs = bpf_map_lookup_elem(&tuning_knobs_map, &zero);
	if (knobs) {
		knobs->slice_ns = 1000000;
		knobs->batch_slice_ns = 20000000;        // 20MS FLAT DEFAULT
		knobs->codel_thresh_ns = 5000000;        // 5MS DEFAULT (RUST OVERRIDES)
		knobs->topology_tau_ns = 0;              // RUST WRITES AT TOPOLOGY DETECT
		knobs->codel_eq_ns = 0;                  // RUST WRITES AT TOPOLOGY DETECT
		knobs->phi_base_ns = 0;                  // THE LAYER WRITES ONCE MEASURED
		knobs->standing_targets = 0;             // SLICE_STANDING_TARGETS UNTIL RUST WRITES
		knobs->waker_leave_ns = 0;               // OFF UNTIL THE ADAPTIVE LAYER WRITES
	}

	// BELT-AND-SUSPENDERS: DERIVE tau-SCALED STATICS IMMEDIATELY IF RUST
	// SOMEHOW WROTE topology_tau_ns BEFORE THIS INIT RUNS (struct_ops
	// RELOAD, HOT PATH RACE). NORMAL CASE IS knobs->topology_tau_ns == 0
	// HERE, IN WHICH CASE apply_tau_scaling() SHORT-CIRCUITS ON THE
	// tau_ns == 0 CHECK AND THE MIDPOINT FALLBACKS SET ABOVE STAND UNTIL
	// THE FIRST TICK AFTER RUST WRITES tau.
	apply_tau_scaling(knobs ? knobs->topology_tau_ns : 0,
	                  knobs ? knobs->codel_eq_ns : 0);
	phi_base_cost_ns = phi_base_tau_ns;

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
	qclock_depart(tctx, bpf_ktime_get_ns(), false);
	tctx->sleep_start_ns = 0;
}

// QUIESCENT: TASK GOES TO SLEEP -- RECORD TIMESTAMP FOR SLEEP ANALYSIS
void BPF_STRUCT_OPS(pandemonium_quiescent, struct task_struct *p,
		    u64 deq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (tctx) {
		tctx->sleep_start_ns = bpf_ktime_get_ns();
		qclock_depart(tctx, tctx->sleep_start_ns, false);
		// A SLEEPING TASK IS NOT QUEUE-WAITING. WITHOUT THIS, A TASK QUEUED,
		// DEQUEUED UNRUN (SETAFFINITY / CANCELLED WAKE) AND THEN SLEPT COMES
		// BACK HOLDING A SECONDS-OLD CLAIM AND SORTS AHEAD OF THE MACHINE.
		tctx->wait_since = 0;
	}
}

// CPU RELEASE: RESCUE STRANDED TASKS WHEN RT/DL PREEMPTS OUR CPU.
// CALLED WHEN THE KERNEL TAKES A CPU AWAY FROM SCHED_EXT (DEADLINE
// SERVER, RT CLASS). WITHOUT THIS, TASKS THAT dispatch() MOVED TO
// THE LOCAL DSQ VIA scx_bpf_dsq_move_to_local() GET STUCK, TRIGGERING
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
		u32 c = cpu_slot((u32)cpu);
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

void BPF_STRUCT_OPS(pandemonium_cpu_online, s32 cpu)
{
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
	__sync_lock_test_and_set(&last_tau_snapshot, 0);

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
			       SCX_OPS_KEEP_BUILTIN_IDLE |
			       SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms   = 10000,
	       .name         = "pandemonium");