// PANDEMONIUM -- SCHED_EXT KERNEL SCHEDULER
// ADAPTIVE DESKTOP SCHEDULING FOR LINUX
//
// BPF: BEHAVIORAL CLASSIFICATION + MULTI-TIER DISPATCH
// RUST: ADAPTIVE CONTROL LOOP + REAL-TIME TELEMETRY
//
// ARCHITECTURE:
//   SELECT_CPU IDLE FAST PATH -> PER-CPU DSQ (DEPTH-GATED, VISIBLE, STEALABLE)
//   ENQUEUE IDLE FOUND -> NODE DSQ (SHARED, ANY CPU DRAINS)
//   ENQUEUE INTERACTIVE PREEMPT -> NODE DSQ (SHARED, KICKED CPU DRAINS)
//   ENQUEUE FALLBACK -> PER-NODE OVERFLOW DSQ (VTIME-ORDERED)
//   DISPATCH -> OWN PER-CPU, L2 WORK STEAL, NODE OVERFLOW, CROSS-NODE, KEEP
//   TICK -> PER-CPU SOJOURN (LOCAL + ROTATING SCAN) + BATCH PREEMPTION
//
// BEHAVIORAL CLASSIFICATION:
//   LAT_CRI SCORE = (WAKEUP_FREQ * CSW_RATE) / AVG_RUNTIME
//   THREE TIERS: LAT_CRITICAL, INTERACTIVE, BATCH
//   PER-TIER SLICING: 1.5X AVG_RUNTIME, 2X AVG_RUNTIME, KNOB BASE
//   COMPOSITOR AUTO-BOOST TO LAT_CRITICAL

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

// CONFIGURATION (SET BY RUST VIA RODATA BEFORE LOAD)

const volatile u64 nr_cpu_ids = 1;

// BEHAVIORAL CONSTANTS

#define TRACE_SCHED 0

#define TIER_BATCH        0
#define TIER_INTERACTIVE  1
#define TIER_LAT_CRITICAL 2

#define LAT_CRI_THRESH_HIGH  32
#define LAT_CRI_THRESH_LOW   8
#define LAT_CRI_CAP          255

// HIGH-PRIORITY KTHREAD THRESHOLD: NICE <= -10 EQUIVALENT.
// static_prio = nice + 120, SO nice <= -10 IS static_prio <= 110.
// PF_KTHREAD AT NICE -20 OFTEN SCORE LAT_CRITICAL BEHAVIORALLY
// (SHORT-RUNTIME / HIGH-WAKEUP) BUT ARE COMPUTE CLASS, NOT LATENCY-
// SENSITIVE. FORCED TO BATCH IN runnable().
#define KTHREAD_HIPRI_STATIC_PRIO_MAX 110

#define WEIGHT_LAT_CRITICAL  256   // 2X
#define WEIGHT_INTERACTIVE   192   // 1.5X
#define WEIGHT_BATCH         128   // 1X

#define EWMA_AGE_MATURE      8
#define EWMA_AGE_CAP         16
#define MAX_WAKEUP_FREQ      64
#define MAX_CSW_RATE         512
// VTIME LAG CAP: TAU-DERIVED IN apply_tau_scaling() VIA K_LAG_CAP.
// USED AS THE BASE FOR (a) vtime_floor = vtime_now - lag_cap_ns * lag_scale
// (SLEEP-BOOST CAP) AND (b) PER-TIER awake_cap. AT THE 12C REFERENCE
// (tau=40MS) THIS IS 40MS, MATCHING THE PRE-v5.8.0 CONSTANT. CLAMPED
// [8MS, 80MS]. INIT FALLBACK MATCHES THE 12C REFERENCE.
static u64 lag_cap_ns = 40000000ULL;

#define SLICE_MIN_NS 100000     // 100US FLOOR
// starvation_rescue_ns AND overflow_sojourn_rescue_ns ARE DERIVED FROM
// knobs->topology_tau_ns VIA scale_tau() AT THE FIRST CPU-0 TICK. SEE
// apply_tau_scaling() AND pandemonium_init().

// FIEDLER-SCALED TIMING CONSTANTS (Q16 FIXED-POINT DIMENSIONLESS RATIOS).
// EACH k_i ENCODES (target_ns / tau_ns) AT THE 12C REFERENCE TOPOLOGY WHERE
// tau = 40MS. scale_tau(tau, k_i) REPRODUCES THE TARGET VALUE.
#define K_Q16_SHIFT             16
// K_i ARE DIMENSIONLESS PHYSICAL RATIOS: target_ns = K_i * tau / 65536.
// SAME K APPLIES TO EVERY TOPOLOGY -- THE OUTPUT VARIES BECAUSE tau VARIES.
// EXAMPLES: K_VTIME_CEILING = 3.0 (Q16 196608) MEANS "VTIME CEILING IS THREE
// COMMUTE TIMES OF THE TOPOLOGY GRAPH." AT tau=13MS (12C) -> 39MS; AT tau=4MS
// (32C) -> 12MS (FLOOR-CLAMPED TO 16MS); AT tau=40MS (2C CLAMP) -> 120MS.
// THE RATIOS ARE SET ONCE BY DESIGN AND NOT MACHINE-SPECIFIC.
#define K_SOJOURN_INTERVAL       19661u   // 0.30
#define K_OVERFLOW_RESCUE        16384u   // 0.25
#define K_CODEL_FLOOR             1147u   // 0.0175
#define K_STARVATION_RESCUE     273285u   // 4.17
#define K_LONGRUN              3276800u   // 50.0
#define K_CODEL_MAX               3277u   // 0.05
#define K_VTIME_CEILING         196608u   // 3.0
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
static u64 vtime_now;

// TICK-BASED INTERACTIVE PREEMPTION SIGNAL
// SET BY enqueue() WHEN NON-BATCH TASK HITS OVERFLOW DSQ.
// CLEARED BY tick() AFTER PREEMPTING A BATCH TASK.
// latcrit_waiting IS A SHARPER VARIANT: SET WHEN A TIER_LAT_CRITICAL TASK
// SPECIFICALLY IS WAITING. tick() USES IT TO TIGHTEN THE PREEMPT THRESHOLD
// SO AUDIO / COMPOSITOR / OTHER TIGHT-DEADLINE WAKERS DON'T SIT BEHIND A
// FULL BATCH SLICE WORTH OF PREEMPT-WAIT. TIER INFO ALREADY AVAILABLE AT
// THE enqueue() SITE -- WE'RE JUST PROPAGATING IT INTO THE SAFETY NET.
static bool interactive_waiting;
static bool latcrit_waiting;

// SOJOURN TRACKERS: RECORD WHEN OVERFLOW DSQs TRANSITION FROM EMPTY.
// DISPATCH STEP 0 CHECKS THESE TO RESCUE OVERFLOW TASKS AGING PAST
// overflow_sojourn_rescue_ns. WITHOUT THIS, PER-CPU DSQ DOMINANCE
// UNDER SUSTAINED LOAD MAKES ALL DOWNSTREAM ANTI-STARVATION LOGIC
// (DEFICIT, SOJOURN, STARVATION_RESCUE) UNREACHABLE.
static u64 batch_enqueue_ns;
static u64 interactive_enqueue_ns;

// PER-CPU DSQ SOJOURN: TRACKS WHEN EACH PER-CPU DSQ TRANSITIONS
// FROM EMPTY. DISPATCH AND TICK CHECK THESE TO DETECT STALE TASKS.
// WORK STEALING + DEPTH GATE HANDLE MOST CASES; THIS IS THE SAFETY NET.
static u64 pcpu_enqueue_ns[MAX_CPUS];

static u64 starvation_rescue_ns;
static u64 overflow_sojourn_rescue_ns;
static u32 pcpu_depth_base;

// TAU-DERIVED VTIME CEILING WINDOW. SET IN apply_tau_scaling() FROM
// scale_tau(tau, K_VTIME_CEILING), CLAMPED TO [16MS, 160MS]. READ ON THE
// HOT PATH BY task_deadline() (CAPS DEADLINE AT vtime_now + WINDOW) AND
// BY pandemonium_enable() (NEW-TASK VTIME PENALTY).
static u64 vtime_ceiling_window_ns;

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
static u64 sojourn_interval_ns;        // CORE-SCALED, UNCERTAIN ZONE TIMER
u64 codel_target_ns;          // ADAPTIVE CENTER (EXPOSED FOR MWU)
static s64 oscillator_velocity_ns;        // DAMPED OSCILLATION VELOCITY
static u64 prev_rescue_snapshot;       // LAST-SEEN RESCUE COUNT
static u64 global_rescue_count;        // ATOMIC CROSS-CPU RESCUE ACCUMULATOR
static u64 pcpu_min_sojourn_ns[MAX_CPUS];
static u64 pcpu_stall_start_ns[MAX_CPUS];

// LONGRUN DETECTION
// TRACKS SUSTAINED BATCH DSQ PRESSURE. WHEN BATCH DSQ IS NON-EMPTY
// FOR > longrun_thresh_ns, COMPRESSES INTERACTIVE SLICING AND ADJUSTS
// THE PREEMPT THRESHOLD. CLEARS WHEN BATCH DSQ EMPTIES.
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
static u64 codel_target_equilibrium_ns = 2000000ULL;

// USER EXIT

UEI_DEFINE(uei);

// MAPS

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
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

// PROCESS CLASSIFICATION DATABASE: BPF OBSERVES, RUST LEARNS, BPF APPLIES
// OBSERVE: BPF WRITES MATURE TASK CLASSIFICATION, RUST DRAINS EVERY SECOND
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 512);
	__type(key, char[16]);
	__type(value, struct task_class_entry);
} task_class_observe SEC(".maps");

// INIT: RUST WRITES PREDICTIONS, BPF READS IN enable() FOR NEW TASKS
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, char[16]);
	__type(value, struct task_class_entry);
} task_class_init SEC(".maps");

// COMPOSITOR MAP: RUST POPULATES AT STARTUP, BPF LOOKS UP IN runnable()
// KEY: COMM NAME (16 BYTES), VALUE: UNUSED (EXISTENCE = COMPOSITOR)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, char[16]);
	__type(value, u8);
} compositor_map SEC(".maps");

// L2 SIBLINGS MAP: FLAT ARRAY FOR L2-AWARE CPU PLACEMENT
// l2_siblings[group_id * MAX_L2_SIBLINGS + slot] = cpu_id
// SENTINEL: (u32)-1 MARKS END OF GROUP
// POPULATED BY RUST AT STARTUP FROM CpuTopology
#define MAX_L2_SIBLINGS 8

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 512);
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
	u64 awake_vtime;
	u64 last_run_at;
	u64 wakeup_freq;
	u64 last_woke_at;
	u64 enqueue_at;      // SET AT EVERY scx_bpf_dsq_insert_vtime SITE;
	                     // CONSUMED IN pandemonium_running TO COMPUTE
	                     // PER-TASK SOJOURN (LITERAL CoDel METRIC).
	                     // CLEARED AFTER CONSUME TO AVOID STALE READS.
	u64 avg_runtime;
	u64 runtime_dev;     // EWMA OF |RUNTIME - AVG_RUNTIME| (VARIANCE SIGNAL)
	u64 cached_weight;
	u64 prev_nvcsw;
	u64 csw_rate;
	u64 lat_cri;
	u64 sleep_start_ns;  // SET IN quiescent(), USED IN running()
	u32 tier;
	u32 ewma_age;
	s32 last_cpu;        // LAST CPU THIS TASK RAN ON (FOR CACHE AFFINITY)
	u8  dispatch_path;   // 0=IDLE, 1=HARD_KICK, 2=SOFT_KICK
	u8  _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

// HELPERS

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
					       s32 cpu)
{
	u32 lcpu = (u32)tctx->last_cpu;
	u32 ncpu = (u32)cpu;
	u32 *ld = bpf_map_lookup_elem(&cache_domain, &lcpu);
	u32 *nd = bpf_map_lookup_elem(&cache_domain, &ncpu);
	bool hit = ld && nd && *ld == *nd;

	if (tctx->tier == TIER_BATCH) {
		if (hit) s->nr_l2_hit_batch += 1;
		else     s->nr_l2_miss_batch += 1;
	} else if (tctx->tier == TIER_INTERACTIVE) {
		if (hit) s->nr_l2_hit_interactive += 1;
		else     s->nr_l2_miss_interactive += 1;
	} else {
		if (hit) s->nr_l2_hit_lat_crit += 1;
		else     s->nr_l2_miss_lat_crit += 1;
	}
}

// L2 CACHE PLACEMENT: FIND IDLE SIBLING IN SAME L2 DOMAIN
// BOUNDED LOOP (MAX 8 ITERATIONS), VERIFIER-SAFE.
// RETURNS IDLE CPU IN SAME L2 GROUP, OR -1 IF NONE FOUND.

static __always_inline s32 find_idle_l2_sibling(const struct task_ctx *tctx,
					       const struct cpumask *allowed)
{
	if (tctx->last_cpu < 0)
		return -1;

	u32 lcpu = (u32)tctx->last_cpu;
	u32 *group = bpf_map_lookup_elem(&cache_domain, &lcpu);
	if (!group)
		return -1;

	u32 base = *group * MAX_L2_SIBLINGS;
	for (int i = 0; i < MAX_L2_SIBLINGS; i++) {
		u32 key = base + i;
		u32 *val = bpf_map_lookup_elem(&l2_siblings, &key);
		if (!val || *val == (u32)-1)
			break;
		s32 cpu = (s32)*val;
		if (allowed && !bpf_cpumask_test_cpu(cpu, allowed))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}
	return -1;
}

// RESISTANCE AFFINITY: IDLE CPU SEARCH BY EFFECTIVE RESISTANCE
// WALKS THE R_EFF-RANKED AFFINITY LIST (LAPLACIAN PSEUDOINVERSE) FOR A
// GIVEN SOURCE CPU. RETURNS FIRST IDLE CPU FOUND, OR -1.
// SEARCH IS BOUNDED TO limit ENTRIES TO CONTROL HOT-PATH COST.
// SLOT 0 = L2 SIBLING (LOWEST R_EFF), SLOT 1+ = NEXT CHEAPEST.
// NO DEPTH GATE. NO DSQ DISPATCH. PURE IDLE SEARCH.
// REFERENCE: KYNG ET AL. EFFECTIVE RESISTANCE (STOC 2011, FOCS 2022)

// BUDGET IS ONLINE CANDIDATES CHECKED, NOT TOTAL SLOTS WALKED. THE
// EXPENSIVE OP IS scx_bpf_test_and_clear_cpu_idle. BUDGET IS TAU-DERIVED:
//   budget = K_AFFINITY_SEARCH / tau = lambda_2 / 4
// HALF THE SPILL BUDGET'S DIVISOR (lambda_2 / 4 vs lambda_2 / 2) BECAUSE
// THE PREDICATE COSTS MORE. AT 12C: 3 (UNCHANGED); AT 32C: 8; AT 64C+:
// SATURATES AT MAX_AFFINITY_CANDIDATES. ROBUST TO HOTPLUG -- OFFLINE
// ENTRIES SKIP WITHOUT CHARGING BUDGET. SET IN apply_tau_scaling().
static u32 affinity_search_online = 3;

static __always_inline s32 find_idle_by_affinity(s32 src_cpu,
						 const struct cpumask *allowed)
{
	if (src_cpu < 0 || (u32)src_cpu >= nr_cpu_ids)
		return -1;

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
		if (scx_bpf_test_and_clear_cpu_idle((s32)*val))
			return (s32)*val;
		// BUDGET IS ONLINE CANDIDATES, NOT SLOTS WALKED.
		if (++checked >= affinity_search_online)
			break;
	}

	return -1;
}

// SIBLING PER-CPU DSQ WITH ROOM: WALKS THE SAME R_EFF-RANKED LIST AS
// find_idle_by_affinity BUT WITH "HAS ROOM" AS THE PREDICATE INSTEAD OF
// "IS IDLE". USED BY THE WAKE_SYNC AND normal_path DEPTH-GATE SPILL SITES
// IN select_cpu TO ROUTE OVERFLOW INTO A SIBLING PER-CPU DSQ -- WHICH IS
// REACHED BY DISPATCH STEP 0 (OWN) OR STEP 1 (L2 STEAL) -- INSTEAD OF
// FUNNELING INTO THE SHARED NODE DSQ THAT DISPATCH ONLY REACHES AT STEP 6.
// BUDGET IS TAU-DERIVED (LIKE EVERY OTHER TOPOLOGY-SCALED VALUE):
//   budget = K_SPILL_BUDGET / tau_ns
// where K_SPILL_BUDGET = TAU_SCALE_NS / 2 = 80e6. THIS IS LAMBDA_2 / 2 --
// HALF THE GRAPH'S ALGEBRAIC CONNECTIVITY, EXPRESSED THROUGH tau. AT
// LAMBDA_2 = 12 (USER'S 12C): 6. AT LAMBDA_2 = 32 (ROLAND'S 32C): 16.
// CLAMPED TO [6, MAX_AFFINITY_CANDIDATES]. SET IN apply_tau_scaling().
static u32 pcpu_spill_search_budget = 6;

static __always_inline s32 find_pcpu_with_room(s32 src_cpu,
					       const struct cpumask *allowed)
{
	if (src_cpu < 0 || (u32)src_cpu >= nr_cpu_ids)
		return -1;

	u32 base = (u32)src_cpu * MAX_AFFINITY_CANDIDATES;
	u32 checked = 0;
	for (int i = 0; i < MAX_AFFINITY_CANDIDATES; i++) {
		u32 key = base + (u32)i;
		u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
		if (!val || *val == (u32)-1)
			break;
		if (*val >= nr_cpu_ids)
			continue;
		if (allowed && !bpf_cpumask_test_cpu((s32)*val, allowed))
			continue;
		if (scx_bpf_dsq_nr_queued((u64)*val) < pcpu_depth_base)
			return (s32)*val;
		if (++checked >= pcpu_spill_search_budget)
			break;
	}

	return -1;
}

// PICK A DSQ FOR WAKE-SYNC OR INITIAL ENQUEUE WITH SIBLING-SPILL FALLBACK.
// THREE-LEVEL PRIORITY:
//   1. src_cpu's PER-CPU DSQ IF UNDER pcpu_depth_base AND IN allowed.
//   2. R_EFF-RANKED SIBLING PER-CPU DSQ WITH ROOM AND IN allowed.
//      DISPATCH REACHES THESE AT STEP 0 (OWN) OR STEP 1 (L2 STEAL).
//   3. LAST RESORT: SHARED NODE DSQ. HARD STARVATION RESCUE BOUNDS WAIT.
//      ALSO THE ESCAPE VALVE WHEN allowed EXCLUDES src_cpu AND ALL R_EFF
//      SIBLINGS -- TASK CAN ALWAYS BE DRAINED BY ANY ALLOWED CPU ON THE
//      NODE VIA STEP 3 OF THE DISPATCH WATERFALL. PREVENTS THE PER-CPU
//      DSQ AFFINITY-STRANDING CLASS BEHIND scx ISSUE #728 / RUNNABLE-TASK
//      STALLS WHEN cpus_ptr CHANGES MID-FLIGHT (LIBVIRT CGROUP CPUSETS,
//      kthread_bind, ETC.).
// *out_cpu RECEIVES THE CPU SCX SHOULD WAKE (THE PER-CPU DSQ OWNER WE
// LANDED IN; src_cpu IF WE FELL BACK TO NODE DSQ).
static __always_inline u64 pick_pcpu_dsq_with_spill(s32 src_cpu,
						    const struct cpumask *allowed,
						    s32 *out_cpu)
{
	u64 now = bpf_ktime_get_ns();
	bool src_ok = (u64)src_cpu < nr_cpu_ids &&
		      (!allowed || bpf_cpumask_test_cpu(src_cpu, allowed));

	if (src_ok &&
	    scx_bpf_dsq_nr_queued((u64)src_cpu) < pcpu_depth_base) {
		if ((u32)src_cpu < MAX_CPUS)
			__sync_val_compare_and_swap(
				&pcpu_enqueue_ns[src_cpu & (MAX_CPUS - 1)],
				0, now);
		*out_cpu = src_cpu;
		return (u64)src_cpu;
	}

	s32 spill = find_pcpu_with_room(src_cpu, allowed);
	if (spill >= 0) {
		if ((u32)spill < MAX_CPUS)
			__sync_val_compare_and_swap(
				&pcpu_enqueue_ns[spill & (MAX_CPUS - 1)],
				0, now);
		*out_cpu = spill;
		return (u64)spill;
	}

	s32 node = __COMPAT_scx_bpf_cpu_node(src_cpu);
	if (node < 0 || (u32)node >= nr_nodes) node = 0;
	__sync_val_compare_and_swap(&interactive_enqueue_ns, 0, now);
	*out_cpu = src_cpu;
	return nr_cpu_ids + (u64)node;
}

// ARM TICK SAFETY NET: SIGNAL THAT A NON-BATCH TASK HAS LANDED SOMEWHERE
// THE DISPATCHING CPU MAY NOT REACH IMMEDIATELY (PER-CPU DSQ ON A BUSY
// CPU, NODE_DSQ OVERFLOW). tick() CONSUMES interactive_waiting TO PREEMPT
// BATCH RUNNERS VIA preempt_thresh_ns; latcrit_waiting TIGHTENS THE
// THRESHOLD 4X SO LAT_CRITICAL WAKERS DON'T WAIT A FULL BATCH SLICE.
// ARMED AT EVERY NON-BATCH PLACEMENT SITE (select_cpu, enqueue Tier 1/2/3)
// SO TASKS ROUTED INTO PER-CPU DSQs ON BUSY CPUs CAN STILL DISLODGE THE
// BATCH RUNNER OWNING THEIR DSQ.
static __always_inline void arm_interactive_waiting(const struct task_ctx *tctx)
{
	if (!tctx || tctx->tier == TIER_BATCH)
		return;
	interactive_waiting = true;
	if (tctx->tier == TIER_LAT_CRITICAL)
		latcrit_waiting = true;
}

// CODEL DRAIN RATE: UPDATE MIN SOJOURN WHEN A TASK STARTS RUNNING.
// CALLED FROM pandemonium_running WITH THE TASK'S MEASURED PER-TASK
// SOJOURN (now - tctx->enqueue_at). REPLACES THE OLD DSQ-EMPTY-CYCLE
// PROXY THAT READ pcpu_enqueue_ns[cpu] -- THAT METRIC IS EXACT FOR
// THE FIRST TASK IN AN EMPTY-TO-NONEMPTY TRANSITION BUT WEAKENS FOR
// LATER TASKS AND FOR VTIME-ORDERED DSQs WHERE HEAD != FIRST-ARRIVAL.
// THE PER-TASK MEASUREMENT IS THE LITERAL CoDel METRIC FROM RFC 8289.
static __always_inline void update_pcpu_sojourn(u32 cpu, u64 sojourn)
{
	if (cpu >= MAX_CPUS) return;
	if (sojourn < pcpu_min_sojourn_ns[cpu])
		pcpu_min_sojourn_ns[cpu] = sojourn;
}

// CODEL STALL DETECTION: MIN SOJOURN ABOVE DYNAMIC TARGET FOR INTERVAL = STALLED.
// THE TARGET (codel_target_ns) IS MODULATED BY DAMPED OSCILLATION IN tick().
// RESCUES PULL THE TARGET DOWN (TIGHTEN). QUIET PUSHES IT UP (RELAX).
// THE TARGET ADAPTS TO WHAT "NORMAL SOJOURN" IS ON THIS SYSTEM RIGHT NOW.
static __always_inline bool pcpu_dsq_is_stalled(u32 cpu, u64 now)
{
	if (cpu >= MAX_CPUS) return false;
	u64 min_s = pcpu_min_sojourn_ns[cpu];

	if (min_s < codel_target_ns) {
		pcpu_stall_start_ns[cpu] = 0;
		pcpu_min_sojourn_ns[cpu] = ~0ULL;
		return false;
	}

	if (pcpu_stall_start_ns[cpu] == 0) {
		pcpu_stall_start_ns[cpu] = now + sojourn_interval_ns;
		return false;
	}

	if (now >= pcpu_stall_start_ns[cpu]) {
		pcpu_min_sojourn_ns[cpu] = ~0ULL;
		pcpu_stall_start_ns[cpu] = 0;
		return true;
	}

	return false;
}

// SOJOURN GATE: RETURNS TRUE IF BOTH OVERFLOW DSQs ARE WITHIN THE RESCUE
// WINDOW (i.e. IT IS SAFE TO RETURN FROM dispatch() AFTER A SUCCESSFUL
// STEP 0 / STEP 1 HIT WITHOUT STARVING A SHARED OVERFLOW DSQ). CALLERS
// SHORT-CIRCUIT AS `if (sojourn_gate_pass(now)) return;` -- IF AN OVERFLOW
// SIDE HAS AGED PAST overflow_sojourn_rescue_ns, FALL THROUGH SO STEP 2
// SERVES OVERFLOW ON THIS DISPATCH CYCLE TOO.
//
// THIS GATE IS LOAD-BEARING. WITHOUT IT, EVERY CPU WHOSE OWN PER-CPU DSQ
// HAS WORK SUCCEEDS AT STEP 0 AND RETURNS, NEVER VISITING STEP 2.  UNDER
// SUSTAINED LOAD WHERE ALL CPUs ARE BUSY, OVERFLOW DSQs AGE TO THE
// starvation_rescue_ns SAFETY NET (~167MS) BEFORE ANYONE SERVICES THEM --
// LONG ENOUGH TO STARVE WORKQUEUE WORKERS (INCLUDING scx_watchdog_workfn)
// AND CAUSE 30S WATCHDOG KILLS, AUDIO DROPOUTS, AND BURST-TAIL LATENCY.
// COST: TWO STATIC READS, TWO COMPARES PER SUCCESSFUL DRAIN.
static __always_inline bool sojourn_gate_pass(u64 now)
{
	u64 ie = interactive_enqueue_ns;
	u64 be = batch_enqueue_ns;
	return (ie == 0 || (now - ie) <= overflow_sojourn_rescue_ns) &&
	       (be == 0 || (now - be) <= overflow_sojourn_rescue_ns);
}

// SERVICE WHICHEVER OVERFLOW SIDE (INTERACTIVE OR BATCH) HAS THE OLDER
// PENDING ENQUEUE AGED PAST `thresh`. RETURNS TRUE IF DISPATCHED.
// USED AT TWO THRESHOLDS IN dispatch(): starvation_rescue_ns (THE SAFETY
// NET, FIRES BEFORE STEP 2 AND IS NEVER GATED) AND overflow_sojourn_rescue_ns
// (STEP 2, THE NORMAL OVERFLOW SERVICE PATH). ONE FUNCTION REPLACES SIX
// REDUNDANT RESCUE BLOCKS THAT WERE ALL DOING THE SAME scx_bpf_dsq_move_to_local
// AT DIFFERENT THRESHOLDS WITH DIFFERENT GATING.
//
// feed_oscillator BUMPS global_rescue_count + nr_overflow_rescue, FEEDING
// THE TICK-DRIVEN CODEL OSCILLATOR. STEP 2 SETS THIS TRUE (REPRESENTATIVE
// PRESSURE SIGNAL); SAFETY NET SETS IT FALSE (BACKSTOP-ONLY, NOT THE NORMAL
// SIGNAL THE OSCILLATOR SHOULD MODEL).
static __always_inline bool try_service_older_overflow(u64 now,
						        u64 node_dsq,
						        u64 batch_dsq,
						        u64 thresh,
						        bool feed_oscillator)
{
	u64 ie = interactive_enqueue_ns;
	u64 be = batch_enqueue_ns;
	u64 i_age = (ie > 0 && now > ie) ? (now - ie) : 0;
	u64 b_age = (be > 0 && now > be) ? (now - be) : 0;

	bool i_aged = i_age > thresh;
	bool b_aged = b_age > thresh;
	if (!i_aged && !b_aged)
		return false;

	// PICK OLDER SIDE FIRST. TIE GOES TO INTERACTIVE (LOWER LATENCY BUDGET).
	// IF BOTH SIDES ARE AGED, DRAIN BOTH ON THIS CALL -- "OLDER WINS"
	// ALONE LET ONE SIDE STARVE INDEFINITELY UNDER SUSTAINED MIXED LOAD
	// AT THIN TOPOLOGIES: WHEN BOTH OVERFLOW DSQs STAY CONTINUOUSLY
	// NON-EMPTY, BOTH TIMESTAMPS FREEZE AT THEIR FIRST-NON-EMPTY VALUE
	// AND THE FIRST-AGED SIDE WINS EVERY RESCUE CALL UNTIL THE OTHER
	// HAPPENS TO DRAIN AND RESET. AT 2C THIS PRODUCED 19-29s STARVATION
	// TAILS ON LONG-RUNNERS DEMOTED TO BATCH UNDER A STEADY SAMPLER
	// STREAM. DRAINING BOTH PREVENTS THE LOCKOUT WITHOUT NEW STATE.
	bool serve_interactive = i_aged && (!b_aged || i_age >= b_age);
	bool dispatched_any = false;

	if (serve_interactive) {
		if (scx_bpf_dsq_move_to_local(node_dsq, 0)) {
			if (scx_bpf_dsq_nr_queued(node_dsq) == 0) {
				u64 old = interactive_enqueue_ns;
				if (old > 0)
					__sync_val_compare_and_swap(&interactive_enqueue_ns, old, 0);
			}
			dispatched_any = true;
		}
		if (b_aged && scx_bpf_dsq_move_to_local(batch_dsq, 0)) {
			if (scx_bpf_dsq_nr_queued(batch_dsq) == 0) {
				u64 old = batch_enqueue_ns;
				if (old > 0)
					__sync_val_compare_and_swap(&batch_enqueue_ns, old, 0);
			}
			dispatched_any = true;
		}
	} else {
		if (scx_bpf_dsq_move_to_local(batch_dsq, 0)) {
			if (scx_bpf_dsq_nr_queued(batch_dsq) == 0) {
				u64 old = batch_enqueue_ns;
				if (old > 0)
					__sync_val_compare_and_swap(&batch_enqueue_ns, old, 0);
			}
			dispatched_any = true;
		}
		if (i_aged && scx_bpf_dsq_move_to_local(node_dsq, 0)) {
			if (scx_bpf_dsq_nr_queued(node_dsq) == 0) {
				u64 old = interactive_enqueue_ns;
				if (old > 0)
					__sync_val_compare_and_swap(&interactive_enqueue_ns, old, 0);
			}
			dispatched_any = true;
		}
	}

	if (!dispatched_any)
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

	v = scale_tau(tau_ns, K_SOJOURN_INTERVAL);
	if (v < 2000000ULL) v = 2000000ULL;
	if (v > 12000000ULL) v = 12000000ULL;
	sojourn_interval_ns = v;

	v = scale_tau(tau_ns, K_OVERFLOW_RESCUE);
	if (v < 4000000ULL) v = 4000000ULL;
	if (v > 10000000ULL) v = 10000000ULL;
	overflow_sojourn_rescue_ns = v;

	v = scale_tau(tau_ns, K_STARVATION_RESCUE);
	if (v < 20000000ULL) v = 20000000ULL;
	if (v > 500000000ULL) v = 500000000ULL;
	starvation_rescue_ns = v;

	v = scale_tau(tau_ns, K_CODEL_FLOOR);
	if (v < 200000ULL) v = 200000ULL;
	if (v > 800000ULL) v = 800000ULL;
	codel_target_floor_ns = v;

	v = scale_tau(tau_ns, K_LONGRUN);
	if (v < 500000000ULL) v = 500000000ULL;       // FLOOR 500MS
	if (v > 8000000000ULL) v = 8000000000ULL;     // CEILING 8S
	longrun_thresh_ns = v;

	v = scale_tau(tau_ns, K_CODEL_MAX);
	if (v < 1000000ULL) v = 1000000ULL;           // FLOOR 1MS
	if (v > 8000000ULL) v = 8000000ULL;           // CEILING 8MS
	codel_target_max_ns = v;

	// R_eff-DERIVED CODEL EQUILIBRIUM. RUST PRE-CLAMPS TO [200us, 8ms];
	// HERE WE ADDITIONALLY CONSTRAIN INTO THE OSCILLATOR'S WORKING WINDOW
	// [floor, max] SO THE SPRING NEVER PULLS x OUT OF BOUNDS. ZERO MEANS
	// RUST HAS NOT YET WRITTEN -- KEEP THE FALLBACK.
	if (codel_eq_ns >= 200000ULL && codel_eq_ns <= 8000000ULL) {
		u64 eq = codel_eq_ns;
		if (eq < codel_target_floor_ns) eq = codel_target_floor_ns;
		if (eq > codel_target_max_ns)   eq = codel_target_max_ns;
		codel_target_equilibrium_ns = eq;
	}

	// OSCILLATOR DYNAMICS: DERIVED FROM tau SO THE CONTROLLER RUNS ON THE
	// SAME TIME CONSTANT AS ITS TARGET RANGE. DIRECT-DIVIDE (NOT Q16)
	// BECAUSE pull_scale (1-4) AND damping_shift (1-5) ARE SMALL INTEGERS.
	// AT THE 12C REFERENCE (tau=40MS) THIS PRODUCES pull=4, damp=5.
	u32 pull = (u32)(tau_ns / K_OSC_PULL_THRESH_NS);
	if (pull < 1) pull = 1;
	if (pull > 4) pull = 4;
	oscillator_pull_scale = pull;

	u32 damp = (u32)(tau_ns / K_OSC_DAMP_THRESH_NS);
	if (damp < 1) damp = 1;
	if (damp > 5) damp = 5;
	oscillator_damping_shift = damp;

	// SPRING SHIFT (ω₀² TERM). CRITICAL DAMPING IN THE CONTINUOUS LIMIT
	// REQUIRES γ = ω₀, AND HERE 2γ ≈ 2^-damping_shift IMPLIES
	// γ = 2^-(damping_shift+1), SO ω₀² = γ² = 2^-(2*damping_shift+2).
	// DERIVED VALUES: damp=1 -> shift=4 (2C, FAST RESTORE),
	// damp=5 -> shift=12 (12C, GENTLE RESTORE). CO-MOVES WITH damping.
	oscillator_spring_shift = 2 * damp + 2;

	// velocity_cap PRESERVES COUPLING TO pull_scale.
	oscillator_velocity_cap = (s64)((u64)OSC_VELOCITY_CAP_PER_PULL * (u64)pull);

	// VTIME CEILING WINDOW. AT THE 12C REFERENCE (tau=40MS) THIS PRODUCES
	// 120MS, TIGHTENING NATURALLY AT LOWER tau (54MS AT 8C, 18MS AT 4C,
	// CLAMPED TO 16MS FLOOR AT 2C). FLOOR PROTECTS AGAINST A NOISY FIEDLER
	// THAT BRIEFLY UNDERSHOOTS.
	v = scale_tau(tau_ns, K_VTIME_CEILING);
	if (v < 16000000ULL)  v = 16000000ULL;        // FLOOR 16MS
	if (v > 160000000ULL) v = 160000000ULL;       // CEILING 160MS
	vtime_ceiling_window_ns = v;

	// PER-CPU DSQ DEPTH GATE. STEP-FUNCTION ON tau (NOT Q16) BECAUSE THE
	// OUTPUT IS A SMALL INTEGER. AT tau >= 6MS ALLOW 2 QUEUED TASKS PER
	// PER-CPU DSQ FOR PIPELINING; AT LOWER tau (THIN TOPOLOGIES OR
	// HEAVILY-PARTITIONED HOTPLUG) DROP TO 1 TO PREVENT PER-CPU DSQ
	// SATURATION.
	pcpu_depth_base = (tau_ns >= 6000000ULL) ? 2 : 1;

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
	// [3, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES)] -- SAME TOPOLOGY-
	// AWARE CEILING AS THE SPILL BUDGET ABOVE.
	{
		u32 b = (u32)(K_AFFINITY_SEARCH / tau_ns);
		u32 ceil = (nr_cpu_ids > 1) ? (u32)(nr_cpu_ids - 1) : 1;
		if (ceil > MAX_AFFINITY_CANDIDATES) ceil = MAX_AFFINITY_CANDIDATES;
		if (b < 3) b = 3;
		if (b > ceil) b = ceil;
		affinity_search_online = b;
	}

	// VTIME LAG CAP. SLEEP-BOOST CEILING SCALES WITH TOPOLOGY TIMING.
	// lag_cap_ns = K_LAG_CAP * tau (1.0 * tau AT 12C REFERENCE = 40MS).
	// CLAMPED [8MS, 80MS]. PER-TIER awake_cap IS A FRACTION OF THIS.
	v = scale_tau(tau_ns, K_LAG_CAP);
	if (v < 8000000ULL)  v = 8000000ULL;
	if (v > 80000000ULL) v = 80000000ULL;
	lag_cap_ns = v;
}

// PCPU DSQ DRAIN-AND-CLEAR: SHARED BY STEP 0 AND STEP 1.
// CALLED AFTER A SUCCESSFUL scx_bpf_dsq_move_to_local((u64)cpu, 0). CLEARS THE
// PER-CPU ENQUEUE TIMESTAMP IF THE DSQ DRAINED EMPTY. CALLERS OWN
// nr_dispatches BUMPS BECAUSE THE STAT BUMP DIFFERS ACROSS SITES.
static __always_inline void pcpu_drain_clear(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return;
	if (scx_bpf_dsq_nr_queued((u64)cpu) != 0)
		return;
	u64 old = pcpu_enqueue_ns[cpu];
	if (old > 0)
		__sync_val_compare_and_swap(&pcpu_enqueue_ns[cpu], old, 0);
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

// EWMA

static __always_inline u64 calc_avg(u64 old_val, u64 new_val, u32 age)
{
	if (age < EWMA_AGE_MATURE)
		return (old_val >> 1) + (new_val >> 1);
	return old_val - (old_val >> 3) + (new_val >> 3);
}

static __always_inline u64 update_freq(u64 freq, u64 interval_ns, u32 age)
{
	if (interval_ns == 0)
		interval_ns = 1;
	u64 new_freq = (100ULL * 1000000ULL) / interval_ns;
	return calc_avg(freq, new_freq, age);
}

// BEHAVIORAL CLASSIFICATION

// LAT_CRI SCORE: HIGH WAKEUP FREQ + HIGH CSW RATE + SHORT RUNTIME = CRITICAL
static __always_inline u64 compute_lat_cri(u64 wakeup_freq, u64 csw_rate,
					    u64 avg_runtime_ns,
					    u64 runtime_dev_ns)
{
	u64 effective_runtime_ns = avg_runtime_ns + (runtime_dev_ns >> 1);
	u64 avg_runtime_ms = effective_runtime_ns >> 20;
	if (avg_runtime_ms == 0)
		avg_runtime_ms = 1;
	u64 score = (wakeup_freq * csw_rate) / avg_runtime_ms;
	if (score > LAT_CRI_CAP)
		score = LAT_CRI_CAP;
	return score;
}

static __always_inline u32 classify_tier(u64 lat_cri,
					  const struct tuning_knobs *knobs)
{
	u64 thresh_high = knobs ? knobs->lat_cri_thresh_high : LAT_CRI_THRESH_HIGH;
	u64 thresh_low  = knobs ? knobs->lat_cri_thresh_low  : LAT_CRI_THRESH_LOW;
	if (lat_cri >= thresh_high)
		return TIER_LAT_CRITICAL;
	if (lat_cri >= thresh_low)
		return TIER_INTERACTIVE;
	return TIER_BATCH;
}

// COMPOSITOR DETECTION: MAP LOOKUP (POPULATED BY RUST AT STARTUP)
// STACK-LOCAL KEY COPY: BPF VERIFIER REJECTS DIRECT p->comm POINTER
static __always_inline bool is_compositor(const struct task_struct *p)
{
	char key[16] = {};
	unsigned int i;
	for (i = 0; i < 15 && p->comm[i]; i++)
		key[i] = p->comm[i];
	return bpf_map_lookup_elem(&compositor_map, key) != NULL;
}

// TRACE: FAST 4-BYTE COMM CHECK FOR SCHEDULER PROCESS TRACING
// CATCHES "pandemonium" WITH ZERO MAP OVERHEAD. GATED BY TRACE_SCHED BECAUSE
// ALL CALL SITES ARE #if TRACE_SCHED -- WITHOUT THE GUARD ON THE DEFINITION,
// CLANG WARNS -Wunused-function WHEN TRACE_SCHED=0 (SCX MONOREPO DEFAULT).
#if TRACE_SCHED
static __always_inline bool is_sched_task(const struct task_struct *p)
{
	return p->comm[0] == 'p' && p->comm[1] == 'a' &&
	       p->comm[2] == 'n' && p->comm[3] == 'd';
}
#endif

// EFFECTIVE WEIGHT: TIER-BASED MULTIPLIER ON NICE WEIGHT
static __always_inline u64 effective_weight(const struct task_struct *p,
					     const struct task_ctx *tctx)
{
	u64 weight = p->scx.weight;
	u64 behavioral;

	if (tctx->tier == TIER_LAT_CRITICAL)
		behavioral = WEIGHT_LAT_CRITICAL;
	else if (tctx->tier == TIER_INTERACTIVE)
		behavioral = WEIGHT_INTERACTIVE;
	else
		behavioral = WEIGHT_BATCH;

	return weight * behavioral >> 7;
}

// SCHEDULING HELPERS

// DEADLINE = DSQ_VTIME + AWAKE_VTIME, BOUND BY UNIVERSAL VTIME CEILING.
// PER-TASK LAG SCALING: INTERACTIVE TASKS GET MORE VTIME CREDIT.
// QUEUE-PRESSURE SCALING: CREDIT SHRINKS WHEN DSQ IS DEEP.
// TIER-BASED AWAKE CAP: PREVENTS BOOST EXPLOITATION.
// VTIME CEILING (UNIVERSAL): CAPS DEADLINE AT vtime_now + WINDOW. THE
// WINDOW IS TAU-DERIVED IN apply_tau_scaling() AND CACHED IN A STATIC.
// LONG-LIVED DAEMONS ACCUMULATE p->scx.dsq_vtime IN stopping() OVER HOURS
// OF RUNTIME AND CAN GROW WELL PAST vtime_now; UNDER A FORK BURST, FRESH
// TASKS WITH dsq_vtime = vtime_now WOULD TAKE THE HEAD OF THE VTIME-ORDERED
// QUEUE AND DAEMONS WOULD SORT TO UNBOUNDED TAIL POSITIONS. THE CEILING
// BOUNDS THE TAIL AT EVERY ENQUEUE PATH.
static __always_inline u64 task_deadline(struct task_struct *p,
					 struct task_ctx *tctx,
					 u64 dsq_id,
					 const struct tuning_knobs *knobs)
{
	u64 knob_scale = knobs ? knobs->lag_scale : 4;
	u64 lag_scale = (tctx->wakeup_freq * knob_scale) >> 2;
	if (lag_scale < 1)
		lag_scale = 1;
	if (lag_scale > MAX_WAKEUP_FREQ)
		lag_scale = MAX_WAKEUP_FREQ;

	// QUEUE-PRESSURE SCALING
	u64 nr_queued = scx_bpf_dsq_nr_queued(dsq_id);
	if (nr_queued > 8)
		lag_scale = 1;
	else if (nr_queued > 4 && lag_scale > 2)
		lag_scale >>= 1;

	// CLAMP VTIME TO PREVENT UNBOUNDED BOOST AFTER LONG SLEEP
	u64 vtime_floor = vtime_now - lag_cap_ns * lag_scale;
	if (time_before(p->scx.dsq_vtime, vtime_floor))
		p->scx.dsq_vtime = vtime_floor;

	// TIER-BASED AWAKE CAP. FRACTIONS OF lag_cap_ns (TAU-DERIVED) SO THE
	// SLEEP-BOOST CEILING SCALES WITH TOPOLOGY TIMING. LAT_CRITICAL gets
	// 0.5x, INTERACTIVE gets 0.75x, BATCH gets 1.0x. AT THE 12C REFERENCE
	// (lag_cap=40MS) THESE ARE 20MS / 30MS / 40MS, MATCHING THE PRE-v5.8.0
	// HARDCODED VALUES.
	u64 awake_cap;
	if (tctx->tier == TIER_LAT_CRITICAL)
		awake_cap = lag_cap_ns >> 1;
	else if (tctx->tier == TIER_INTERACTIVE)
		awake_cap = (lag_cap_ns * 3) >> 2;
	else
		awake_cap = lag_cap_ns;

	if (tctx->awake_vtime > awake_cap)
		tctx->awake_vtime = awake_cap;

	u64 dl = p->scx.dsq_vtime + tctx->awake_vtime;

	// VTIME CEILING: BOUND TAIL POSITION TO vtime_now + WINDOW.
	// WINDOW IS TAU-DERIVED IN apply_tau_scaling() AND CACHED IN A STATIC,
	// SO THE HOT PATH PAYS A SINGLE LOAD. AT THE 12C REFERENCE (tau=40MS)
	// THE WINDOW IS 120MS, TIGHTENING NATURALLY AT LOWER tau -- THE
	// WINDOW MATCHES THE GRAPH'S MIXING TIME, NOT A CORE-COUNT PROXY.
	u64 vtime_ceiling = vtime_now + vtime_ceiling_window_ns;
	if (time_after(dl, vtime_ceiling))
		dl = vtime_ceiling;

	return dl;
}

// PER-TIER DYNAMIC SLICING
// LAT_CRITICAL: 1.5X AVG_RUNTIME (TIGHT -- FAST PREEMPTION)
// INTERACTIVE:  2X AVG_RUNTIME (RESPONSIVE)
// BATCH:        KNOB BASE SLICE (CONTROLLED BY ADAPTIVE LAYER)
static __always_inline u64 task_slice(const struct task_ctx *tctx,
				      const struct tuning_knobs *knobs)
{
	// SLICE COMPRESSION: longrun_mode IS THE ONLY CONSUMER. SUSTAINED BATCH
	// PRESSURE SWAPS IN burst_slice_ns; EVERYTHING ELSE USES slice_ns.
	u64 base_slice = knobs ? (longrun_mode
		? knobs->burst_slice_ns : knobs->slice_ns) : 1000000;
	u64 base;

	if (tctx->tier == TIER_LAT_CRITICAL) {
		base = tctx->avg_runtime + (tctx->avg_runtime >> 1);
		if (base > base_slice)
			base = base_slice;
		if (base < SLICE_MIN_NS)
			base = SLICE_MIN_NS;
		return base;
	}

	if (tctx->tier == TIER_INTERACTIVE) {
		base = tctx->avg_runtime << 1;
		if (base > base_slice)
			base = base_slice;
		if (base < SLICE_MIN_NS)
			base = SLICE_MIN_NS;
		return base;
	}

	// BATCH: DEDICATED CEILING FROM RUST ADAPTIVE LAYER.
	// WEIGHT-SCALED: HIGHER BEHAVIORAL WEIGHT = LONGER SLICE.
	u64 batch_ceil = knobs ? knobs->batch_slice_ns : 20000000;
	if (batch_ceil < SLICE_MIN_NS)
		batch_ceil = SLICE_MIN_NS;

	base = batch_ceil * tctx->cached_weight >> 7;
	if (base > batch_ceil)
		base = batch_ceil;
	if (base < SLICE_MIN_NS)
		base = SLICE_MIN_NS;

	return base;
}

// SCHEDULING CALLBACKS

// SELECT_CPU: FAST-PATH IDLE CPU DISPATCH TO PER-CPU DSQ
// DISPATCHES TO NAMED PER-CPU DSQ (u64)cpu -- VISIBLE TO WORK STEALING
// AND SOJOURN RESCUE. DEPTH-GATED: IF PER-CPU DSQ ALREADY HAS TASKS,
// SPILL TO SHARED NODE DSQ SO ANY CPU CAN GRAB IT.
// THE CPU IS IDLE SO IT ENTERS dispatch() IMMEDIATELY AND DRAINS.
s32 BPF_STRUCT_OPS(pandemonium_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;

	// RESISTANCE AFFINITY: WAKEE_FLIPS-GATED WAKE_SYNC
	// GATE: wakee_flips (per-task wakeup partner diversity) separates
	//   1:1 pipe pairs (low flips, affinity beneficial) from
	//   1:N server patterns (high flips, affinity harmful).
	// PLACEMENT: R_eff ranked search from waker's CPU finds cheapest
	//   idle CPU in waker's L2 group. Falls back to waker's DSQ if
	//   no idle found and DSQ depth allows.
	// REFERENCE: kernel wake_wide() uses same wakee_flips signal.
	//   Kyng et al. effective resistance for migration cost.
	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_struct *waker =
			(struct task_struct *)bpf_get_current_task_btf();
		if (waker) {
			u32 wflips = BPF_CORE_READ(waker, wakee_flips);
			u32 pflips = p->wakee_flips;
			// CARVE-OUT (SEE topology.rs): wakee_flips IS A COUNT,
			// NOT A DURATION. nr_cpu_ids IS THE NATURAL UNIT FOR
			// "DIVERSE vs CONCENTRATED" WAKEUP PARTNERS AND MATCHES
			// THE KERNEL'S wake_wide() CONVENTION.
			u32 thresh = nr_cpu_ids;

			// WAKE_WIDE: SKIP IF EITHER SIDE WAKES DIVERSE TASKS
			if (wflips <= thresh && pflips <= thresh) {
				s32 waker_cpu = bpf_get_smp_processor_id();
				if ((u64)waker_cpu >= nr_cpu_ids)
					goto normal_path;

				// R_EFF RANKED IDLE SEARCH FROM WAKER
				s32 target = find_idle_by_affinity(waker_cpu, p->cpus_ptr);
				if (target >= 0) {
					struct task_ctx *tctx = lookup_task_ctx(p);
					struct tuning_knobs *knobs = get_knobs();
					u64 sl = tctx ? task_slice(tctx, knobs)
						      : 1000000;
					s32 dst_cpu;
					u64 dst_dsq = pick_pcpu_dsq_with_spill(target, p->cpus_ptr, &dst_cpu);
					u64 dl = tctx ? task_deadline(p, tctx,
						dst_dsq, knobs) : vtime_now;
					scx_bpf_dsq_insert_vtime(p,
						dst_dsq, sl, dl, 0);
					if (tctx) {
						tctx->dispatch_path = 0;
						tctx->enqueue_at = bpf_ktime_get_ns();
					}
					struct pandemonium_stats *s = get_stats();
					if (s) {
						s->nr_idle_hits += 1;
						s->nr_dispatches += 1;
					}
					return dst_cpu;
				}

				// NO IDLE NEAR WAKER: DSQ DISPATCH IF DSQ IS FLOWING
				// CODEL: IF MIN SOJOURN < 500us OVER LAST 8ms, TASKS
				// ARE CYCLING THROUGH FAST. DSQ DISPATCH IS SAFE.
				// IF STALLED (PINNED WORKERS), FALL THROUGH TO
				// NORMAL PATH WHERE scx_bpf_select_cpu_dfl HANDLES
				// PREEMPTION AND LOAD BALANCING.
				if (!pcpu_dsq_is_stalled(
					(u32)waker_cpu, bpf_ktime_get_ns())) {
					struct task_ctx *tctx = lookup_task_ctx(p);
					struct tuning_knobs *knobs = get_knobs();
					u64 sl = tctx ? task_slice(tctx, knobs)
						      : 1000000;
					s32 dst_cpu;
					u64 dst_dsq = pick_pcpu_dsq_with_spill(waker_cpu, p->cpus_ptr, &dst_cpu);
					u64 dl = tctx ? task_deadline(p, tctx,
						dst_dsq, knobs) : vtime_now;
					scx_bpf_dsq_insert_vtime(p,
						dst_dsq, sl, dl, 0);
					if (tctx) {
						tctx->dispatch_path = 0;
						tctx->enqueue_at = bpf_ktime_get_ns();
					}
					struct pandemonium_stats *s = get_stats();
					if (s) {
						s->nr_idle_hits += 1;
						s->nr_dispatches += 1;
					}
					return dst_cpu;
				}
			}
		}
	}
normal_path:;

	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	s32 dst_cpu = cpu;

	if (is_idle) {
		struct task_ctx *tctx = lookup_task_ctx(p);
		struct tuning_knobs *knobs = get_knobs();
		u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;

		// PER-CPU DSQ PLACEMENT WITH L2/R_EFF SPILL. CACHE-HOT IF cpu
		// HAS ROOM; SIBLING PER-CPU DSQ NEXT (REACHED BY DISPATCH STEP 0
		// ON SIBLING OR STEP 1 L2 STEAL); LAST-RESORT SHARED NODE DSQ.
		u64 dst_dsq = pick_pcpu_dsq_with_spill(cpu, p->cpus_ptr, &dst_cpu);
		u64 dl = tctx ? task_deadline(p, tctx, dst_dsq, knobs)
			      : vtime_now;
		scx_bpf_dsq_insert_vtime(p, dst_dsq, sl, dl, 0);

		scx_bpf_kick_cpu(dst_cpu, SCX_KICK_IDLE);

		if (tctx) {
			tctx->dispatch_path = 0;
			tctx->enqueue_at = bpf_ktime_get_ns();
		}

		struct pandemonium_stats *s = get_stats();
		if (s) {
			s->nr_idle_hits += 1;
			s->nr_dispatches += 1;
			if (tctx)
				count_l2_affinity(s, tctx, dst_cpu);
		}

#if TRACE_SCHED
		if (is_sched_task(p))
			bpf_printk("PAND: select_cpu pid=%d cpu=%d", p->pid, dst_cpu);
#endif
	}

	return dst_cpu;
}

// ENQUEUE: THREE-TIER PLACEMENT WITH BEHAVIORAL PREEMPTION
// TIER 1: IDLE CPU ON NODE -> PER-CPU DSQ (DEPTH-GATED) + KICK
// TIER 2: INTERACTIVE/LAT_CRITICAL -> PER-CPU DSQ (DEPTH-GATED) + HARD PREEMPT
// TIER 3: FALLBACK -> PER-NODE OVERFLOW DSQ + SELECTIVE KICK
void BPF_STRUCT_OPS(pandemonium_enqueue, struct task_struct *p,
		    u64 enq_flags)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(scx_bpf_task_cpu(p));
	if (node < 0 || (u32)node >= nr_nodes) node = 0;
	u64 node_dsq = nr_cpu_ids + (u64)node;

	struct task_ctx *tctx = lookup_task_ctx(p);

	struct tuning_knobs *knobs = get_knobs();
	u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;
	u64 dl;

	// CLASSIFY: WAKEUP VS RE-ENQUEUE
	bool is_wakeup = tctx && tctx->awake_vtime == 0;

	// TIER 1: IDLE CPU -> NODE DSQ + KICK
	// L2 PLACEMENT: TRY IDLE SIBLING IN SAME L2 DOMAIN FIRST.
	// LAT_CRITICAL AND KERNEL THREADS SKIP AFFINITY -- FASTEST CPU WINS.
	// TASK GOES TO SHARED NODE DSQ SO ANY CPU ON THE NODE CAN DRAIN IT
	// VIA STEP 3 (UNCONDITIONAL node_dsq DRAIN). pick_pcpu_dsq_with_spill
	// IS RESERVED FOR THE PLACEMENT SITES THAT ARE TIED TO A SPECIFIC CPU
	// (TIER 2 PREEMPTION, select_cpu); FOR IDLE-CPU PLACEMENT, THE EAGER
	// R_eff SEARCH (UP TO 6 MAP LOOKUPS + nr_queued QUERIES PER ENQUEUE)
	// IS A WIRE-SPEED REGRESSION ON FORK-STORM WORKLOADS WITHOUT
	// MEASURABLE PLACEMENT BENEFIT -- STEP 3 PICKS UP node_dsq TASKS
	// WITHIN ONE DISPATCH CYCLE.
	s32 cpu = -1;
	if (knobs && knobs->affinity_mode > 0 && tctx &&
	    tctx->tier != TIER_LAT_CRITICAL &&
	    !(p->flags & PF_KTHREAD)) {
		// cpu = find_idle_by_affinity(tctx->last_cpu, p->cpus_ptr);
		cpu = find_idle_l2_sibling(tctx, p->cpus_ptr);
	}
	if (cpu < 0)
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p->cpus_ptr, node, 0);
	if (cpu >= 0 && (u64)cpu < nr_cpu_ids) {
		dl = tctx ? task_deadline(p, tctx, node_dsq, knobs)
			  : vtime_now;
		scx_bpf_dsq_insert_vtime(p, node_dsq, sl, dl, enq_flags);
		__sync_val_compare_and_swap(&interactive_enqueue_ns, 0,
					    bpf_ktime_get_ns());

		u64 kick_flag = (tctx && tctx->tier != TIER_BATCH)
			      ? SCX_KICK_PREEMPT : SCX_KICK_IDLE;
		scx_bpf_kick_cpu(cpu, kick_flag);

		if (tctx) {
			tctx->dispatch_path = 0;
			tctx->enqueue_at = bpf_ktime_get_ns();
		}

		struct pandemonium_stats *s = get_stats();
		if (s) {
			s->nr_shared += 1;
			s->nr_dispatches += 1;
			if (is_wakeup)
				s->nr_enq_wakeup += 1;
			else
				s->nr_enq_requeue += 1;
			if (tctx)
				count_l2_affinity(s, tctx, cpu);
		}
#if TRACE_SCHED
		if (is_sched_task(p))
			bpf_printk("PAND: enq tier1 pid=%d cpu=%d", p->pid, cpu);
#endif
		return;
	}

	// TIER 2: WAKEUP PREEMPTION -- NODE DSQ + SELECTIVE KICK
	// ALL WAKEUPS GET NODE DSQ DISPATCH: A TASK WAKING FROM SLEEP
	// HAS EXTERNAL INPUT TO DELIVER (TIMER, IO, USER) REGARDLESS OF
	// BEHAVIORAL TIER. THE CLASSIFIER OPERATES ON HISTORICAL BEHAVIOR;
	// THE WAKEUP IS THE REAL-TIME LATENCY SIGNAL.
	// LAT_CRITICAL ALSO GETS PREEMPTION ON REQUEUE (COMPOSITOR GUARANTEE).
	// ONLINE GUARD: pick_any_cpu_node() CAN RETURN OFFLINE CPUs DURING
	// HOTPLUG. OFFLINE CPUs HAVE NO CURRENT TASK (cpu_curr == NULL).
	if (tctx &&
	    (tctx->tier == TIER_LAT_CRITICAL || is_wakeup)) {
		cpu = __COMPAT_scx_bpf_pick_any_cpu_node(
			p->cpus_ptr, node, 0);
		if (cpu >= 0 && (u64)cpu < nr_cpu_ids &&
		    __COMPAT_scx_bpf_cpu_curr(cpu)) {
			// PER-CPU PLACEMENT WITH L2/R_EFF SPILL. SAME REACHABILITY
			// LOGIC AS select_cpu: cpu's PER-CPU IF ROOM, ELSE A SIBLING
			// VIA find_pcpu_with_room, ELSE LAST-RESORT NODE DSQ.
			s32 t2_cpu;
			u64 tier2_dsq = pick_pcpu_dsq_with_spill(cpu, p->cpus_ptr, &t2_cpu);

			dl = task_deadline(p, tctx, tier2_dsq, knobs);
			scx_bpf_dsq_insert_vtime(p, tier2_dsq, sl, dl,
						  enq_flags);

			u64 kick_flag = (is_wakeup ||
				 tctx->tier == TIER_LAT_CRITICAL)
				? SCX_KICK_PREEMPT : SCX_KICK_IDLE;
			scx_bpf_kick_cpu(t2_cpu, kick_flag);
			// Arm tick-preempt safety net when the spill helper
			// fell back to node_dsq. Useful in conjunction with
			// the CPU-bound demotion in stopping(): demoted
			// saturators are now TIER_BATCH and tick can preempt
			// them within preempt_thresh_ns to drain the kicked
			// CPU's queue and let the dispatch waterfall reach
			// node_dsq for the wedged victim.
			if (tier2_dsq >= nr_cpu_ids)
				arm_interactive_waiting(tctx);
			tctx->dispatch_path = 1;
			tctx->enqueue_at = bpf_ktime_get_ns();

			struct pandemonium_stats *s = get_stats();
			if (s) {
				s->nr_shared += 1;
				s->nr_dispatches += 1;
				s->nr_hard_kicks += 1;
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

	// TIER 3: NODE OVERFLOW DSQ + SELECTIVE KICK
	// ONLY BATCH-CLASSIFIED TASKS GO TO BATCH DSQ.
	// IMMATURE TASKS (ewma_age < 2) STAY IN INTERACTIVE DSQ TO PREVENT
	// STARVATION DURING BURST SPAWNS -- NEW THREADS STARTING WITH
	// ewma_age=0 WOULD FLOOD THE BATCH DSQ AND STARVE FOR 30-40S
	// WAITING FOR SOJOURN RESCUE THAT NEVER REACHES THE TAIL.
	// LAT_CRITICAL (COMPOSITORS) ARE NEVER REDIRECTED.
	u64 target_dsq = (tctx && tctx->tier == TIER_BATCH)
		? (nr_cpu_ids + nr_nodes + (u64)node)
		: node_dsq;

	// SOJOURN TRACKING: RECORD WHEN OVERFLOW DSQs TRANSITION FROM EMPTY.
	// DISPATCH STEP 0 CHECKS THESE TO RESCUE TASKS AGING PAST THRESHOLD.
	if (target_dsq != node_dsq)
		__sync_val_compare_and_swap(&batch_enqueue_ns, 0, bpf_ktime_get_ns());
	if (target_dsq == node_dsq)
		__sync_val_compare_and_swap(&interactive_enqueue_ns, 0, bpf_ktime_get_ns());

	// VTIME CEILING IS APPLIED INSIDE task_deadline() (UNIVERSAL).
	dl = tctx ? task_deadline(p, tctx, target_dsq, knobs) : vtime_now;

	scx_bpf_dsq_insert_vtime(p, target_dsq, sl, dl, enq_flags);

	if (tctx)
		tctx->enqueue_at = bpf_ktime_get_ns();

#if TRACE_SCHED
	if (is_sched_task(p))
		bpf_printk("PAND: enq tier3 pid=%d dsq=%llu tier=%d", p->pid, target_dsq, tctx ? tctx->tier : -1);
#endif

	// ARM TICK SAFETY NET: TIER 3 IS THE ONLY ARM SITE -- TASK LANDED IN
	// SHARED OVERFLOW (node_dsq OR batch_dsq). FOR REQUEUES (is_wakeup=false)
	// NO KICK FIRES, SO THE FLAG IS THE SOLE BACKSTOP. FOR WAKEUPS A KICK
	// GOES TO scx_bpf_task_cpu(p) BUT THAT CPU MAY BE BUSY; THE FLAG
	// REINFORCES VIA TICK PREEMPTION OF A LOCAL BATCH RUNNER.
	// SELECT_CPU AND TIER 1/2 PATHS DO NOT ARM: THEY ALL ISSUE A DIRECT
	// KICK TO THE DESTINATION CPU AND RELY ON THAT CPU'S DISPATCH WATERFALL.
	arm_interactive_waiting(tctx);

	u64 kick_flags = is_wakeup ? SCX_KICK_PREEMPT : 0;
	scx_bpf_kick_cpu(scx_bpf_task_cpu(p), kick_flags);

	if (tctx)
		tctx->dispatch_path = is_wakeup ? 1 : 2;

	struct pandemonium_stats *s = get_stats();
	if (s) {
		s->nr_shared += 1;
		if (is_wakeup) {
			s->nr_enq_wakeup += 1;
			s->nr_hard_kicks += 1;
		} else {
			s->nr_enq_requeue += 1;
			s->nr_soft_kicks += 1;
		}
	}

}

// DISPATCH: CPU IS IDLE AND NEEDS WORK
// HYBRID PER-CPU + NODE DSQ DESIGN:
//   SELECT_CPU -> PER-CPU DSQ (DEPTH-GATED, VISIBLE, STEALABLE)
//   ENQUEUE TIER 1/2 -> NODE DSQ (SHARED, ANY CPU DRAINS)
//   ENQUEUE TIER 3 -> PER-NODE BATCH/INTERACTIVE DSQ
//
// 0. OWN PER-CPU DSQ (CACHE-HOT, ZERO CONTENTION)
// 1. R_EFF STEAL (AFFINITY_RANK -- L2 SIBLING AT SLOT 0, R_EFF PEERS AT SLOTS 1+)
// SAFETY NET. SERVICE OLDER OVERFLOW SIDE PAST starvation_rescue_ns
// 2. SERVICE OLDER OVERFLOW SIDE PAST overflow_sojourn_rescue_ns
// 3. NODE INTERACTIVE OVERFLOW (LAT_CRIT + INTERACTIVE, VTIME-ORDERED)
// 4. NODE BATCH OVERFLOW (NORMAL BATCH FALLBACK)
// 5. CROSS-NODE STEAL (INTERACTIVE + BATCH PER REMOTE NODE)
// 6. KEEP_RUNNING IF PREV STILL WANTS CPU AND NOTHING QUEUED
void BPF_STRUCT_OPS(pandemonium_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	if (node < 0 || (u32)node >= nr_nodes) node = 0;
	u64 node_dsq = nr_cpu_ids + (u64)node;
	u64 batch_dsq = nr_cpu_ids + nr_nodes + (u64)node;
	struct pandemonium_stats *s;
	u64 now = bpf_ktime_get_ns();

	// STEP 0: OWN PER-CPU DSQ -- HIGHEST PRIORITY, CACHE-HOT.
	// SOJOURN GATE AT EXIT: IF EITHER OVERFLOW SIDE HAS AGED PAST
	// overflow_sojourn_rescue_ns, FALL THROUGH SO STEP 2 SERVES OVERFLOW
	// ON THIS DISPATCH TOO. WITHOUT THIS GATE, EVERY CPU WITH HOT PER-CPU
	// WORK NEVER VISITS OVERFLOW; SCX_WATCHDOG_WORKFN AND OTHER WORKQUEUE
	// WORKERS GET STARVED IN node_dsq UNTIL THE 167MS SAFETY NET FIRES.
	if ((u64)cpu < nr_cpu_ids &&
	    scx_bpf_dsq_move_to_local((u64)cpu, 0)) {
		// pcpu_min_sojourn_ns IS UPDATED BY pandemonium_running WHEN
		// THE TASK ACTUALLY STARTS RUNNING (SEE PER-TASK SOJOURN BLOCK).
		// HERE WE JUST CLEAR THE DSQ-EMPTY-CYCLE TIMESTAMP.
		pcpu_drain_clear((u32)cpu);
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		if (sojourn_gate_pass(now))
			return;
	}

	// STEP 1: R_EFF STEAL. SINGLE LOOP OVER affinity_rank: SLOT 0 IS THE
	// L2 SIBLING (LOWEST R_EFF), SLOTS 1+ ARE R_EFF-RANKED CROSS-L2 PEERS.
	// affinity_rank IS AUTHORITATIVE FOR PLACEMENT DISTANCE.
	// BUDGET = pcpu_spill_search_budget (nr_cpu_ids/2 CLAMPED TO
	// [6, MAX_AFFINITY_CANDIDATES]), MATCHING THE ENQUEUE-SIDE SPILL HELPER.
	{
		u32 my_cpu = (u32)cpu;
		u32 base = my_cpu * MAX_AFFINITY_CANDIDATES;
		u32 checked = 0;
		for (int i = 0; i < MAX_AFFINITY_CANDIDATES; i++) {
			u32 key = base + (u32)i;
			u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
			if (!val || *val == (u32)-1)
				break;
			u32 peer = *val;
			if (peer >= nr_cpu_ids)
				continue;
			if (peer == my_cpu) {
				if (++checked >= pcpu_spill_search_budget)
					break;
				continue;
			}
			if (scx_bpf_dsq_move_to_local((u64)peer, 0)) {
				// pcpu_min_sojourn_ns IS UPDATED BY
				// pandemonium_running ON THE STOLEN-TO CPU.
				pcpu_drain_clear(peer);
				s = get_stats();
				if (s)
					s->nr_dispatches += 1;
				if (sojourn_gate_pass(now))
					return;
				break;
			}
			if (++checked >= pcpu_spill_search_budget)
				break;
		}
	}

	// SAFETY NET: HARD STARVATION RESCUE. SERVICE WHICHEVER OVERFLOW SIDE
	// IS OLDER PAST starvation_rescue_ns (TAU-SCALED, ~167MS AT 12C).
	// FIRES BEFORE STEP 2 SO IT CANNOT BE GATED. ENQUEUE-SIDE PER-CPU
	// SPILL SHOULD KEEP THIS RARELY EXERCISED; IF IT DOES FIRE,
	// PLACEMENT IS WRONG OR TIME-BASED SERVICE IS BLOCKED -- DETECTABLE
	// VIA nr_dispatches DELTA WHEN STEP 2 COUNTERS DON'T MOVE.
	if (try_service_older_overflow(now, node_dsq, batch_dsq,
				       starvation_rescue_ns, false))
		return;

	// STEP 2: SERVICE OLDER OVERFLOW SIDE PAST overflow_sojourn_rescue_ns
	// (TAU-SCALED, ~10MS AT 12C). ONE COMPARISON, ONE DRAIN. FEEDS THE
	// OSCILLATOR (true) -- THIS IS THE REPRESENTATIVE PRESSURE SIGNAL
	// THAT TIGHTENS codel_target_ns ON SUSTAINED LOAD.
	if (try_service_older_overflow(now, node_dsq, batch_dsq,
				       overflow_sojourn_rescue_ns, true))
		return;

	// STEP 3: NODE INTERACTIVE OVERFLOW (LAT_CRIT + INTERACTIVE, VTIME-ORDERED)
	// UNCONDITIONAL DRAIN OF THE INTERACTIVE OVERFLOW DSQ.
	if (scx_bpf_dsq_move_to_local(node_dsq, 0)) {
		if (scx_bpf_dsq_nr_queued(node_dsq) == 0) {
			u64 old_iens = interactive_enqueue_ns;
			if (old_iens > 0)
				__sync_val_compare_and_swap(&interactive_enqueue_ns, old_iens, 0);
		}
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// STEP 4: NODE BATCH OVERFLOW (NORMAL BATCH FALLBACK)
	if (scx_bpf_dsq_move_to_local(batch_dsq, 0)) {
		if (scx_bpf_dsq_nr_queued(batch_dsq) == 0) {
			u64 old_bens = batch_enqueue_ns;
			if (old_bens > 0)
				__sync_val_compare_and_swap(&batch_enqueue_ns, old_bens, 0);
		}
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// CROSS-NODE STEAL
	for (u32 n = 0; n < nr_nodes && n < MAX_NODES; n++) {
		if (n != (u32)node) {
			if (scx_bpf_dsq_move_to_local(nr_cpu_ids + (u64)n, 0)) {
				s = get_stats();
				if (s)
					s->nr_dispatches += 1;
				return;
			}
			if (scx_bpf_dsq_move_to_local(nr_cpu_ids + nr_nodes + (u64)n, 0)) {
				s = get_stats();
				if (s)
					s->nr_dispatches += 1;
				return;
			}
		}
	}

	// NOTHING IN ANY DSQ -- KEEP PREV RUNNING IF POSSIBLE
	if (prev && !(prev->flags & PF_EXITING) &&
	    (prev->scx.flags & SCX_TASK_QUEUED)) {
		struct task_ctx *tctx = lookup_task_ctx(prev);
		struct tuning_knobs *knobs = get_knobs();
		prev->scx.slice = tctx ? task_slice(tctx, knobs) :
				  (knobs ? knobs->slice_ns : 1000000);
		s = get_stats();
		if (s) {
			s->nr_keep_running += 1;
			s->nr_dispatches += 1;
		}
	}
}

// RUNNABLE: TASK WAKES UP -- BEHAVIORAL CLASSIFICATION ENGINE
void BPF_STRUCT_OPS(pandemonium_runnable, struct task_struct *p,
		    u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	u64 now = bpf_ktime_get_ns();
	tctx->awake_vtime = 0;

	// FAST PATH: BRAND-NEW TASKS (< 2 WAKEUPS)
	if (tctx->ewma_age < 2) {
		tctx->last_woke_at = now;
		tctx->prev_nvcsw = p->nvcsw;
		tctx->ewma_age += 1;
		return;
	}

	// WAKEUP FREQUENCY
	u64 delta_t = now > tctx->last_woke_at ? now - tctx->last_woke_at : 1;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t,
					 tctx->ewma_age);
	if (tctx->wakeup_freq > MAX_WAKEUP_FREQ)
		tctx->wakeup_freq = MAX_WAKEUP_FREQ;
	tctx->last_woke_at = now;

	if (tctx->ewma_age < EWMA_AGE_CAP)
		tctx->ewma_age += 1;

	// VOLUNTARY CONTEXT SWITCH RATE
	u64 nvcsw = p->nvcsw;
	u64 csw_delta = nvcsw > tctx->prev_nvcsw ? nvcsw - tctx->prev_nvcsw : 0;
	tctx->prev_nvcsw = nvcsw;

	if (csw_delta > 0 && delta_t > 0) {
		u64 csw_freq = csw_delta * (100ULL * 1000000ULL) / delta_t;
		tctx->csw_rate = calc_avg(tctx->csw_rate, csw_freq,
					   tctx->ewma_age);
	} else {
		tctx->csw_rate = calc_avg(tctx->csw_rate, 0, tctx->ewma_age);
	}
	if (tctx->csw_rate > MAX_CSW_RATE)
		tctx->csw_rate = MAX_CSW_RATE;

	// BEHAVIORAL CLASSIFICATION
	tctx->lat_cri = compute_lat_cri(tctx->wakeup_freq, tctx->csw_rate,
					 tctx->avg_runtime, tctx->runtime_dev);
	struct tuning_knobs *knobs = get_knobs();
	u32 new_tier = classify_tier(tctx->lat_cri, knobs);

	// COMPOSITOR BOOST: ALWAYS LAT_CRITICAL
	if (new_tier != TIER_LAT_CRITICAL && is_compositor(p))
		new_tier = TIER_LAT_CRITICAL;

	// HIGH-PRIORITY KTHREAD OVERRIDE: PF_KTHREAD AT NICE <= -10 LOOK
	// LATENCY-SENSITIVE TO THE BEHAVIORAL SCORER (SHORT RUNTIMES, HIGH
	// WAKEUP FREQUENCY) BUT ARE COMPUTE CLASS. LEFT IN LAT_CRITICAL THEY
	// DOMINATE DISPATCH OVER LEGITIMATE USERSPACE INTERACTIVE WORK UNDER
	// HEAVY KERNEL LOAD. FORCED TO BATCH SO THEY STILL GET WEIGHTED
	// PREFERENCE WITHIN BATCH BUT DO NOT MIX WITH USER LAT_CRITICAL.
	// PF_WQ_WORKER IS A PF_KTHREAD SUBSET HANDLED BY THE FLOOR BELOW
	// (WORKQUEUE WORKERS STAY INTERACTIVE).
	if (p->flags & PF_KTHREAD &&
	    p->static_prio <= KTHREAD_HIPRI_STATIC_PRIO_MAX)
		new_tier = TIER_BATCH;

	// KWORKER FLOOR: WORKQUEUE WORKERS HANDLE I/O COMPLETIONS, TIMER
	// CALLBACKS, AND DEFERRED INTERRUPT WORK. USERSPACE BLOCKS ON THESE.
	// THEIR LOW EWMA SCORES (INFREQUENT WAKEUPS, LONG RUNTIMES) PUSH
	// THEM TO BATCH, BUT THEY ARE LATENCY-CRITICAL KERNEL INFRASTRUCTURE.
	// ALSO RE-PROMOTES ANY PF_WQ_WORKER DEMOTED BY THE KTHREAD OVERRIDE
	// ABOVE -- WORKQUEUE WORKERS ARE PF_KTHREAD BUT THE FLOOR WINS.
	if (new_tier == TIER_BATCH && (p->flags & PF_WQ_WORKER))
		new_tier = TIER_INTERACTIVE;

	tctx->tier = new_tier;
}

// RUNNING: TASK STARTS EXECUTING -- ADVANCE VTIME, RECORD WAKE LATENCY
void BPF_STRUCT_OPS(pandemonium_running, struct task_struct *p)
{
#if TRACE_SCHED
	if (is_sched_task(p))
		bpf_printk("PAND: running pid=%d cpu=%d", p->pid, bpf_get_smp_processor_id());
#endif
	// SINGLE-SHOT vtime_now ADVANCE. UNDER 12C BURST WITH ~48K running()
	// CALLS/SEC, A RETRY LOOP TURNS PROGRESSION CONTENTION INTO SYSTEMATIC
	// CAS EXHAUSTION. ONE ATTEMPT IS ENOUGH: IF IT FAILS BECAUSE ANOTHER
	// CPU JUST ADVANCED vtime_now, THE NEXT running() CALL WILL CARRY THE
	// UPDATE FORWARD. OCCASIONAL DROPS BEAT THE OLD 4-RETRY LOOP'S 100ms+
	// CUMULATIVE DRIFT THAT COLLAPSED THE UNIVERSAL VTIME CEILING WINDOW
	// FROM 120MS TO ~20MS UNDER SUSTAINED LOAD.
	u64 cur = vtime_now;
	if (time_before(cur, p->scx.dsq_vtime))
		__sync_bool_compare_and_swap(&vtime_now, cur, p->scx.dsq_vtime);

	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx) {
		struct tuning_knobs *knobs = get_knobs();
		p->scx.slice = knobs ? knobs->slice_ns : 1000000;
		return;
	}

	u64 now = bpf_ktime_get_ns();
	tctx->last_run_at = now;

	// PER-TASK SOJOURN: TIME FROM scx_bpf_dsq_insert_vtime TO RUN START.
	// LITERAL CoDel METRIC. FEEDS pcpu_min_sojourn_ns FOR THE STALL
	// DETECTOR. CLEAR enqueue_at AFTER CONSUME SO NEXT RUN WITHOUT A
	// PRECEDING ENQUEUE (KEEP_RUNNING PATH) DOESN'T DOUBLE-COUNT.
	if (tctx->enqueue_at > 0 && now > tctx->enqueue_at) {
		u64 sojourn = now - tctx->enqueue_at;
		u32 cpu = bpf_get_smp_processor_id();
		update_pcpu_sojourn(cpu, sojourn);
		tctx->enqueue_at = 0;
	}

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
		u32 tier_idx = (u32)tctx->tier;
		if (tier_idx > 2) tier_idx = 2;
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
	p->scx.slice = task_slice(tctx, knobs);
}

// STOPPING: TASK YIELDS CPU -- CHARGE VTIME WITH TIER-BASED WEIGHT
void BPF_STRUCT_OPS(pandemonium_stopping, struct task_struct *p,
		    bool runnable)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->cached_weight = effective_weight(p, tctx);
	tctx->last_cpu = bpf_get_smp_processor_id();
	u64 weight = tctx->cached_weight;

	u64 now = bpf_ktime_get_ns();
	u64 slice = now > tctx->last_run_at ? now - tctx->last_run_at : 0;
	{
		u64 avg = tctx->avg_runtime;
		u64 diff = slice > avg ? slice - avg : avg - slice;
		tctx->avg_runtime = calc_avg(avg, slice, tctx->ewma_age);
		tctx->runtime_dev = calc_avg(tctx->runtime_dev, diff,
					      tctx->ewma_age);
	}

	// CPU-BOUND DEMOTION. Long-runners that never sleep keep ewma_age
	// pinned at 1 (incremented only on sleep->runnable in runnable()),
	// so classify_tier never reruns. The classifier-based path leaves
	// such tasks at TIER_INTERACTIVE indefinitely, which makes them
	// unpreemptible by tick() (only TIER_BATCH receives the tick rescue
	// at line ~2031). Threshold scales with slice_ns: an INTERACTIVE
	// long-runner's avg_runtime asymptotes to the slice cap, so a
	// fixed-ns threshold above slice_ns can never fire for the exact
	// tasks the demotion is meant to catch. 75% of slice_cap catches
	// pure CPU-bound within ~6 stop cycles (~6ms wall). The ewma_age
	// guard spares legit interactive tasks that use full slice but
	// sleep frequently -- their ewma_age grows on every sleep->wake.
	{
		struct tuning_knobs *kk = get_knobs();
		u64 slice_cap = kk ? kk->slice_ns : 1000000;
		if (tctx->tier == TIER_INTERACTIVE &&
		    tctx->avg_runtime * 4 >= slice_cap * 3 &&
		    tctx->ewma_age <= 4) {
			tctx->tier = TIER_BATCH;
			tctx->cached_weight = effective_weight(p, tctx);
		}
	}

	// PROCDB: PUBLISH TASK CLASSIFICATION FOR USERSPACE
	// INITIAL AT EWMA MATURITY, THEN EVERY 64 SCHEDULING EVENTS
	// RE-PUBLISHING KEEPS PROCDB FRESH FOR LONG-LIVED TASKS
	if (tctx->ewma_age == EWMA_AGE_MATURE ||
	    (tctx->ewma_age > EWMA_AGE_MATURE && tctx->ewma_age % 64 == 0)) {
		struct task_class_entry obs = {};
		obs.tier = (u8)tctx->tier;
		obs.avg_runtime = tctx->avg_runtime;
		obs.runtime_dev = tctx->runtime_dev;
		obs.wakeup_freq = tctx->wakeup_freq;
		obs.csw_rate = tctx->csw_rate;
		char key[16];
		__builtin_memcpy(key, p->comm, 16);
		bpf_map_update_elem(&task_class_observe, key, &obs, BPF_ANY);
	}

	u64 delta_vtime;
	if (weight > 0)
		delta_vtime = (slice << 7) / weight;
	else
		delta_vtime = slice;

	p->scx.dsq_vtime += delta_vtime;
	tctx->awake_vtime += delta_vtime;
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

	// THE OSCILLATOR IS THE ONE DETECTOR. RESCUE DELTAS ARE THE ONLY SIGNAL
	// IT CONSUMES; IT ADAPTS codel_target_ns WHICH DRIVES THE PER-CPU CoDel
	// STALL DECISION AND HARD STARVATION RESCUE. NO BURST DETECTOR. NO FLAGS.
	if (bpf_get_smp_processor_id() == 0) {
		// TAU-SCALING: re-derive the timing statics if Rust wrote a new
		// topology_tau_ns (initial detect or hotplug). Idempotent when
		// tau is unchanged; cheap when it is (single compare + early out).
		apply_tau_scaling(knobs ? knobs->topology_tau_ns : 0,
		                  knobs ? knobs->codel_eq_ns : 0);

		// DAMPED HARMONIC OSCILLATOR (FULL FORM):
		//     ẍ + 2γẋ + ω₀²(x - c_eq) = F(t)
		// F(t): RESCUE-DRIVEN IMPULSE (NEGATIVE: TIGHTEN DETECTOR)
		// 2γẋ: DAMPING (v >> damping_shift)
		// ω₀²(x - c_eq): SPRING (RESTORING TOWARD R_eff EQUILIBRIUM)
		// CRITICALLY DAMPED (γ = ω₀) VIA spring_shift = 2*damping_shift + 2.
		// 2C (THIN): FAST RESTORE, LARGE SPRING SHIFT WINDOW.
		// 12C (DENSE): GENTLE RESTORE, TARGET TRACKS STALL POINT.
		{
			u64 cur = __sync_fetch_and_add(&global_rescue_count, 0);
			u64 delta = cur - prev_rescue_snapshot;
			prev_rescue_snapshot = cur;

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
				   (s64)codel_target_equilibrium_ns;
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
		}
	}

	if (s) {
		s->longrun_mode_active = longrun_mode ? 1 : 0;
	}

	u64 bens = batch_enqueue_ns;
	if (bens > 0) {
		u64 now = bpf_ktime_get_ns();
		u64 sojourn = now - bens;
		if (s)
			s->batch_sojourn_ns = sojourn;

		// LONGRUN DETECTION: SUSTAINED BATCH PRESSURE
		// BATCH DSQ NON-EMPTY FOR > longrun_thresh_ns (TAU-SCALED, ~2S
		// AT THE 12C REFERENCE) SETS longrun_mode. CONSUMERS:
		//   task_slice: INTERACTIVE/LATCRIT TASKS SWITCH FROM slice_ns
		//     TO burst_slice_ns -- A TIGHTER SLICE THAT YIELDS THE CPU
		//     FASTER UNDER PRESSURE.
		//   tick (BELOW): preempt_thresh_ns IS LEFT-SHIFTED BY
		//     longrun_preempt_shift, GIVING BATCH RUNNERS MORE ROPE
		//     BEFORE INTERACTIVE-WAITING PREEMPTS THEM.
		// CPU 0 IS THE SOLE WRITER: ALIGNS WITH THE OSCILLATOR / TAU
		// SCALING / VTIME-CEILING STATICS THAT ARE ALSO CPU-0-WRITTEN.
		// PREVENTS MULTI-CPU TICK RACES THAT FLICKERED THE BOOL UNDER
		// BURST WHILE batch_enqueue_ns WAS BEING SET/CLEARED VIA CAS.
		if (bpf_get_smp_processor_id() == 0)
			longrun_mode = sojourn > longrun_thresh_ns;

		// SOJOURN ENFORCEMENT: THRESHOLD SET BY RUST ADAPTIVE LAYER
		// FROM OBSERVED DISPATCH RATE. IF BATCH STARVING PAST THRESHOLD
		// AND CURRENT TASK IS BATCH, KICK THIS CPU TO FORCE DISPATCH.
		// ONLY PREEMPT BATCH: INTERACTIVE/LATCRIT SLICES ARE ALREADY
		// SHORT (CAPPED AT slice_ns) AND WILL YIELD QUICKLY ON THEIR OWN.
		// PER-CPU (NOT CPU-0-ONLY): EACH CPU NEEDS TO SELF-PREEMPT WHEN
		// IT'S RUNNING THE STARVING BATCH TASK.
		u64 sojourn_thresh = knobs ? knobs->sojourn_thresh_ns : 5000000;
		if (sojourn > sojourn_thresh) {
			struct task_ctx *tctx = lookup_task_ctx(p);
			if (tctx && tctx->tier == TIER_BATCH) {
				scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
				return;
			}
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
		u64 pcpu_sojourn_thresh = knobs
			? knobs->sojourn_thresh_ns : 5000000;

		// LOCAL: OWN PER-CPU DSQ
		if (this_cpu < MAX_CPUS) {
			u64 pcpu_oldest = pcpu_enqueue_ns[this_cpu];
			if (pcpu_oldest > 0 &&
			    (now2 - pcpu_oldest) > pcpu_sojourn_thresh) {
				scx_bpf_kick_cpu(this_cpu,
						 SCX_KICK_PREEMPT);
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
					u32 scan_cpu = i;
					if (scan_cpu == this_cpu)
						continue;
					u64 remote_stamp = pcpu_enqueue_ns[
						scan_cpu & (MAX_CPUS - 1)];
					if (remote_stamp > 0 &&
					    (now2 - remote_stamp) > pcpu_sojourn_thresh)
						scx_bpf_kick_cpu(scan_cpu,
								 SCX_KICK_PREEMPT);
				}
			} else {
				u32 scan_base = (u32)(now2 >> 20);
				for (int i = 0; i < 4; i++) {
					u32 scan_cpu =
						(scan_base + (u32)i) % nr;
					if (scan_cpu == this_cpu)
						continue;
					u64 remote_stamp = pcpu_enqueue_ns[
						scan_cpu & (MAX_CPUS - 1)];
					if (remote_stamp > 0 &&
					    (now2 - remote_stamp) > pcpu_sojourn_thresh)
						scx_bpf_kick_cpu(scan_cpu,
								 SCX_KICK_PREEMPT);
				}
			}
		}
	}

	if (!interactive_waiting)
		return;

	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	// TAU-SCALED LONGRUN PROTECTION: THIN TOPOLOGIES (tau < 4MS, ROUGHLY 2C)
	// NEED EXTRA SLICE HEADROOM FOR BATCH LONG-RUNNERS AGAINST LAT_CRIT/BATCH
	// CONTENTION; 4C+ HAS ENOUGH CAPACITY TO HANDLE BOTH TIERS AT BASELINE
	// PREEMPT. longrun_preempt_shift IS SET BY apply_tau_scaling().
	u64 base_thresh = knobs ? knobs->preempt_thresh_ns : 1000000;
	u64 thresh = longrun_mode ? (base_thresh << longrun_preempt_shift)
	           : base_thresh;

	// LAT_CRITICAL WAITING -> TIGHTEN THRESHOLD BY 4X. AUDIO AND COMPOSITOR
	// WAKERS ARE THE HOT CASES; THE STANDARD 1MS WAIT IS ENOUGH TO SKIP A
	// 10MS AUDIO BUFFER. INTERACTIVE WAITERS KEEP THE CURRENT THRESHOLD SO
	// BATCH THROUGHPUT IS NOT PENALIZED BY ORDINARY WAKEUP PATTERNS.
	if (latcrit_waiting)
		thresh >>= 2;

	u64 on_cpu = tctx->last_run_at > 0
		? bpf_ktime_get_ns() - tctx->last_run_at : 0;
	// TIER PREEMPT POLICY:
	//   * BATCH residents are always preemptible by tick when interactive_waiting
	//     is set (any non-batch wakeup is pending).
	//   * INTERACTIVE residents are preemptible only when latcrit_waiting is set
	//     (a TIER_LAT_CRITICAL wakeup is specifically pending). LAT_CRIT outranks
	//     INTERACTIVE; INTERACTIVE keeps protection from ordinary BATCH-waiter
	//     contention. This closes the 10ms-cadence stall class where saturators
	//     hadn't yet demoted to BATCH (or fork-storm children newly spawned at
	//     INTERACTIVE) couldn't be tick-preempted for a LAT_CRIT victim wake.
	bool preemptible = tctx->tier == TIER_BATCH ||
			   (latcrit_waiting && tctx->tier == TIER_INTERACTIVE);
	if (preemptible && on_cpu >= thresh) {
		scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
		interactive_waiting = false;
		latcrit_waiting = false;
		if (!s)
			s = get_stats();
		if (s)
			s->nr_preempt += 1;
	}
}

// ENABLE: NEW TASK ENTERS SCHED_EXT
//
// NEW-TASK VTIME PENALTY: PLACE NEW TASKS AT THE VTIME CEILING
// (vtime_now + vtime_ceiling_window_ns), NOT AT vtime_now. WITHOUT
// THIS PENALTY EVERY FRESHLY-FORKED TASK GETS THE LOWEST POSSIBLE
// dsq_vtime AND SORTS TO THE HEAD OF THE VTIME-ORDERED QUEUE,
// LEAPFROGGING ESTABLISHED PROCESSES THAT HAVE ACCUMULATED dsq_vtime
// FROM RUNTIME. UNDER FORK BURSTS, WAVES OF FRESH TASKS WOULD BURY
// LONG-LIVED DAEMONS AT THE TAIL OF THE QUEUE UNTIL THE WATCHDOG
// KILLS THEM. THE VTIME CEILING (IN task_deadline) BOUNDS TAIL
// POSITION BUT DOES NOT CHANGE ORDERING: DAEMONS CAPPED AT vtime_now
// + WINDOW ARE STILL BEHIND FRESH TASKS AT vtime_now. PENALIZING NEW
// TASKS TO LAND AT THE SAME CEILING PUTS THEM IN FIFO ORDER WITH
// CAPPED DAEMONS (NEWER ARRIVALS TIED AT HIGHER VTIME). EEVDF AND
// MOST MODERN FAIR SCHEDULERS APPLY THE EQUIVALENT NEW-TASK LAG
// PENALTY FOR THIS REASON.
void BPF_STRUCT_OPS(pandemonium_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now + vtime_ceiling_window_ns;

	struct task_ctx *tctx = ensure_task_ctx(p);
	if (tctx) {
		tctx->awake_vtime = 0;
		tctx->last_run_at = 0;
		tctx->wakeup_freq = 20;
		tctx->last_woke_at = bpf_ktime_get_ns();
		tctx->avg_runtime = 100000;
		tctx->cached_weight = WEIGHT_INTERACTIVE;
		tctx->prev_nvcsw = p->nvcsw;
		tctx->csw_rate = 0;
		tctx->lat_cri = 0;
		tctx->tier = TIER_INTERACTIVE;
		tctx->ewma_age = 0;
		tctx->dispatch_path = 0;

		// PROCDB: APPLY LEARNED CLASSIFICATION FROM PRIOR RUNS
		char key[16];
		__builtin_memcpy(key, p->comm, 16);
		struct task_class_entry *init_entry =
		    bpf_map_lookup_elem(&task_class_init, key);
		if (init_entry) {
			tctx->tier = (u32)init_entry->tier;
			tctx->avg_runtime = init_entry->avg_runtime;
			tctx->runtime_dev = init_entry->runtime_dev;
			tctx->wakeup_freq = init_entry->wakeup_freq;
			tctx->csw_rate = init_entry->csw_rate;
			tctx->cached_weight = effective_weight(p, tctx);
		}
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

	// PER-CPU DSQs.
	// SELECT_CPU DISPATCHES TO PER-CPU DSQ (CACHE-HOT, VISIBLE, STEALABLE).
	// ENQUEUE ALWAYS USES SHARED NODE DSQ (EVEN DISTRIBUTION).
	// VISIBILITY LAYERS:
	//   1. L2 WORK STEALING IN DISPATCH -- IDLE CPUs PULL FROM SIBLINGS
	//   2. ROTATING TICK SCAN -- CATCHES STALE TASKS ON IDLE CPUs
	//   3. PER-CPU SOJOURN RESCUE -- THRESHOLD CEILING ON INVISIBILITY
	for (u32 i = 0; i < nr_cpu_ids && i < MAX_CPUS; i++)
		scx_bpf_create_dsq(i, -1);

	// CREATE PER-NODE INTERACTIVE OVERFLOW DSQs (DSQ ID = nr_cpu_ids + NODE)
	for (u32 i = 0; i < nr_nodes && i < MAX_NODES; i++)
		scx_bpf_create_dsq(nr_cpu_ids + i, (s32)i);

	// CREATE PER-NODE BATCH OVERFLOW DSQs (DSQ ID = nr_cpu_ids + nr_nodes + NODE)
	for (u32 i = 0; i < nr_nodes && i < MAX_NODES; i++)
		scx_bpf_create_dsq(nr_cpu_ids + nr_nodes + i, (s32)i);

	// ALL TIMING-CONSTANT AND OSCILLATOR-DYNAMICS STATICS BELOW ARE DERIVED
	// FROM tau (Fiedler-based time constant) VIA apply_tau_scaling() AT THE
	// FIRST CPU-0 TICK. MIDPOINT CONSTANTS HERE PROVIDE SANE BEHAVIOR DURING
	// THE ~1MS WINDOW BETWEEN struct_ops ATTACH AND THAT FIRST TICK. THEY
	// ARE OVERWRITTEN IMMEDIATELY -- DON'T READ SIGNIFICANCE INTO THEM.
	starvation_rescue_ns       = 100000000ULL;  // 100ms midpoint of [20, 500]
	overflow_sojourn_rescue_ns =   6000000ULL;  //   6ms midpoint of [4, 10]
	sojourn_interval_ns        =   4000000ULL;  //   4ms midpoint of [2, 12]
	codel_target_floor_ns      =    500000ULL;  // 500us midpoint of [200, 800]
	vtime_ceiling_window_ns    =  80000000ULL;  // 80MS midpoint of [16, 160]
	                                            //   (8C-EQUIVALENT BEFORE tau LANDS)
	pcpu_depth_base            = 2;             // 8C-12C MIDPOINT; apply_tau_scaling
	                                            //   recomputes continuously as
	                                            //   tau / K_DEPTH_THRESH_NS.
	pcpu_spill_search_budget   = 6;             // 12C MIDPOINT
	affinity_search_online     = 3;             // 12C MIDPOINT
	lag_cap_ns                 = 40000000ULL;   // 40MS = 12C REFERENCE
	longrun_preempt_shift      = 0;             // NO BOOST UNTIL tau CONFIRMS 2C
	oscillator_damping_shift   = 3;
	oscillator_spring_shift    = 8;             // = 2*3+2, MIDPOINT
	oscillator_pull_scale      = 3;
	oscillator_velocity_cap    = (s64)((u64)OSC_VELOCITY_CAP_PER_PULL * 3);
	// START PERMISSIVE. LET THE DAMPED OSCILLATION FIND THE RIGHT CENTER.
	// RESCUES PULL IT DOWN. NO STATIC FORMULA. THE WAVE FUNCTION DOES THE WORK.
	codel_target_ns = codel_target_max_ns;
	oscillator_velocity_ns = 0;
	prev_rescue_snapshot = 0;
	global_rescue_count = 0;
	for (u32 i = 0; i < nr_cpu_ids && i < MAX_CPUS; i++) {
		pcpu_min_sojourn_ns[i] = ~0ULL;
		pcpu_stall_start_ns[i] = 0;
	}

	longrun_mode = false;

	// INITIALIZE DEFAULT TUNING KNOBS
	struct tuning_knobs *knobs = bpf_map_lookup_elem(&tuning_knobs_map, &zero);
	if (knobs) {
		knobs->slice_ns = 1000000;
		knobs->preempt_thresh_ns = 1000000;
		knobs->lag_scale = 4;
		knobs->batch_slice_ns = 20000000;        // 20MS FLAT DEFAULT
		knobs->lat_cri_thresh_high = LAT_CRI_THRESH_HIGH; // 32
		knobs->lat_cri_thresh_low  = LAT_CRI_THRESH_LOW;  // 8
		knobs->affinity_mode = 0;                // OFF BY DEFAULT (RUST SETS PER REGIME)
		knobs->sojourn_thresh_ns = 5000000;      // 5MS DEFAULT (RUST OVERRIDES)
		knobs->burst_slice_ns = 1000000;         // 1MS DEFAULT (BURST/LONGRUN CEILING)
		knobs->topology_tau_ns = 0;              // RUST WRITES AT TOPOLOGY DETECT
		knobs->codel_eq_ns = 0;                  // RUST WRITES AT TOPOLOGY DETECT
	}

	return 0;
}

// EXIT: RECORD EXIT INFO FOR USERSPACE
void BPF_STRUCT_OPS(pandemonium_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

// QUIESCENT: TASK GOES TO SLEEP -- RECORD TIMESTAMP FOR SLEEP ANALYSIS
void BPF_STRUCT_OPS(pandemonium_quiescent, struct task_struct *p,
		    u64 deq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (tctx)
		tctx->sleep_start_ns = bpf_ktime_get_ns();
}

// CPU RELEASE: RESCUE STRANDED TASKS WHEN RT/DL PREEMPTS OUR CPU.
// CALLED WHEN THE KERNEL TAKES A CPU AWAY FROM SCHED_EXT (DEADLINE
// SERVER, RT CLASS). WITHOUT THIS, TASKS THAT dispatch() MOVED TO
// THE LOCAL DSQ VIA scx_bpf_dsq_move_to_local(, 0) GET STUCK, TRIGGERING
// THE WATCHDOG.
void BPF_STRUCT_OPS(pandemonium_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
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
	if ((u32)cpu < MAX_CPUS) {
		__sync_lock_test_and_set(&pcpu_enqueue_ns[cpu], 0);
		pcpu_min_sojourn_ns[cpu] = ~0ULL;
		pcpu_stall_start_ns[cpu] = 0;
	}
	// Force the next CPU-0 tick to re-derive tau-scaled statics. Rust will
	// have recomputed lambda_2 against the new topology and written a fresh
	// topology_tau_ns; clearing the snapshot makes apply_tau_scaling() pick
	// it up instead of short-circuiting on the stale value. ATOMIC STORE
	// PAIRS WITH apply_tau_scaling()'s CAS SO A CONCURRENT TICK CAN'T
	// OVERWRITE THIS CLEAR.
	__sync_lock_test_and_set(&last_tau_snapshot, 0);
}

void BPF_STRUCT_OPS(pandemonium_cpu_offline, s32 cpu)
{
	if ((u32)cpu < MAX_CPUS) {
		__sync_lock_test_and_set(&pcpu_enqueue_ns[cpu], 0);
		pcpu_min_sojourn_ns[cpu] = ~0ULL;
		pcpu_stall_start_ns[cpu] = 0;
	}
	__sync_lock_test_and_set(&last_tau_snapshot, 0);

	__sync_lock_test_and_set(&interactive_enqueue_ns, 0);
	__sync_lock_test_and_set(&batch_enqueue_ns, 0);

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
	       .exit         = (void *)pandemonium_exit,
	       .flags        = SCX_OPS_BUILTIN_IDLE_PER_NODE,
	       .name         = "pandemonium");