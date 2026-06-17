// PANDEMONIUM -- SCHED_EXT KERNEL SCHEDULER
// ADAPTIVE DESKTOP SCHEDULING FOR LINUX
//
// BPF: BEHAVIORAL CLASSIFICATION + MULTI-TIER DISPATCH
// RUST: ADAPTIVE CONTROL LOOP + REAL-TIME TELEMETRY
//
// ARCHITECTURE:
//   SELECT_CPU IDLE FAST PATH -> PER-CPU DSQ (DEPTH-GATED, VISIBLE, STEALABLE)
//   ENQUEUE TIER 1 IDLE FOUND -> THAT IDLE CPU'S PER-CPU DSQ (WARM)
//   ENQUEUE TIER 2 WARM-ANCHOR (WAKEUP / LAT_CRITICAL) -> last_cpu PER-CPU DSQ
//   ENQUEUE TIER 3 FALLBACK -> PER-CCX OVERFLOW DSQ (SOJOURN-ORDERED, L3-LOCAL)
//   DISPATCH -> OWN PER-CPU, R_eff STEAL (Phi-PRICED), CCX OVERFLOW, CROSS-CCX, KEEP
//   TICK -> PER-CPU SOJOURN (LOCAL + ROTATING SCAN) + BATCH PREEMPTION
//
// BEHAVIORAL CLASSIFICATION:
//   LAT_CRI SCORE = (WAKEUP_FREQ * CSW_RATE) / AVG_RUNTIME
//   THREE TIERS: LAT_CRITICAL, INTERACTIVE, BATCH
//   PER-TIER SLICING: 1.5X AVG_RUNTIME, 2X AVG_RUNTIME, KNOB BASE

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

// scx_bpf_task_set_slice() / scx_bpf_task_set_dsq_vtime() REPLACE DIRECT
// WRITES TO p->scx.slice / p->scx.dsq_vtime ON KERNEL 7.1+. THE WRAPPERS
// (WHICH PICK THE KFUNC-OR-DIRECT-WRITE VIA bpf_ksym_exists) LIVE IN
// scx/compat.bpf.h -- BOTH THE VENDORED COPY HERE AND THE scx UPSTREAM
// VERSION -- SO WE JUST CALL THEM DIRECTLY. READS OF THE SAME FIELDS
// ARE NOT DEPRECATED AND REMAIN AS-IS.

// CONFIGURATION (SET BY RUST VIA RODATA BEFORE LOAD)

const volatile u64 nr_cpu_ids = 1;

// BEHAVIORAL CONSTANTS

#define TRACE_SCHED 0

#define TIER_BATCH        0
#define TIER_INTERACTIVE  1
#define TIER_LAT_CRITICAL 2

// FLOW SIGNATURE (PERSISTED SHAPE, FROZEN AT EWMA_AGE_MATURE). COUNTS THE
// DISTINCT WAKER CPUs OF A TASK IN A BITMAP; THE POPCOUNT IS ITS PARTNER
// CARDINALITY -- A TOPOLOGY-FREE READ OF THE LIVE COMMUNICATION GRAPH'S
// CONDUCTANCE. A FEW PARTNERS = A TIGHT LOOP; MANY (SPANNING HALF+ THE MACHINE)
// = A STORM MESH. CLASSIFIED ONCE AND FROZEN -> DETERMINISTIC ROUTING.
#define SHAPE_UNCLASSIFIED 0
#define SHAPE_TIGHT        1
#define SHAPE_STORM        2
// SPLIT: <= SHAPE_TIGHT_MAX DISTINCT PARTNERS IS A TIGHT PAIR/LOOP; A PARTNER
// SET SPANNING AT LEAST HALF OF nr_cpu_ids IS A STORM. PORTABLE -- THE STORM
// THRESHOLD SCALES WITH THE MACHINE, NO HARDCODED CORE GEOMETRY.
#define SHAPE_TIGHT_MAX    2u

#define LAT_CRI_THRESH_HIGH  32
#define LAT_CRI_THRESH_LOW   8
#define LAT_CRI_CAP          255

// HIGH-PRIORITY KTHREAD THRESHOLD: NICE <= -10 EQUIVALENT.
// static_prio = nice + 120, SO nice <= -10 IS static_prio <= 110.
// PF_KTHREAD AT NICE -20 OFTEN SCORE LAT_CRITICAL BEHAVIORALLY
// (SHORT-RUNTIME / HIGH-WAKEUP) BUT ARE COMPUTE CLASS, NOT LATENCY-
// SENSITIVE. FORCED TO BATCH IN runnable().
#define KTHREAD_HIPRI_STATIC_PRIO_MAX 110
// RT SCHEDULING POLICIES (UAPI VALUES; NOT ALWAYS MACRO-EXPORTED VIA vmlinux.h).
#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif
#ifndef SCHED_RR
#define SCHED_RR   2
#endif

#define WEIGHT_LAT_CRITICAL  256   // 2X
#define WEIGHT_INTERACTIVE   192   // 1.5X
#define WEIGHT_BATCH         128   // 1X

#define EWMA_AGE_MATURE      8
#define EWMA_AGE_CAP         16
#define MAX_WAKEUP_FREQ      64
#define MAX_CSW_RATE         512
// WARP CEILING: TAU-DERIVED IN apply_tau_scaling() VIA K_LAG_CAP. THE UPPER
// BOUND ON THE SOJOURN warp IN task_deadline() (warp = lag_cap_ns *
// task_potentiality_q16 >> 16), SO THE WARP IS STARVATION-FREE. AT THE 12C REFERENCE
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
// EXAMPLE: K_LAG_CAP = 1.0 (Q16 65536) MEANS "THE WARP CEILING IS ONE
// COMMUTE TIME OF THE TOPOLOGY GRAPH." THE RATIOS ARE SET ONCE BY DESIGN
// AND NOT MACHINE-SPECIFIC; THE OUTPUT VARIES BECAUSE tau VARIES.
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
// nr_ccx: NUMBER OF DISTINCT L3/CCX DOMAINS IN llc_domain[]. SET BY RUST AT
// TOPOLOGY DETECT VIA write_nr_ccx (.data SECTION, POST-LOAD MUTABLE). ON
// MONOLITHIC-L3 / UNSET, EQUALS nr_sockets (TYPICALLY 1) AND THE PER-CCX TIER
// COLLAPSES TO A SINGLE OVERFLOW DSQ -- EXACT PRIOR BEHAVIOR SHAPE.
volatile u32 nr_ccx = 1;

// NO GLOBAL PREEMPT FLAG: tick() DERIVES THE DECISION PER-CPU FROM
// pcpu_enqueue_ns[this_cpu] (OLDEST WAITER AGE) AGAINST A k*tau THRESHOLD,
// TIER-GATED ON THE RESIDENT. PER-CPU SO NO TOKEN FOR CPUs TO RACE OVER.

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
// CACHELINE-PADDED: one stamp per 64-byte line so the per-placement CAS
// (arm/clear) and the per-tick cross-CPU scan don't false-share neighbors.
struct pcpu_stamp { u64 ns; } __attribute__((aligned(64)));
static struct pcpu_stamp pcpu_enqueue_ns[MAX_CPUS];

static u64 starvation_rescue_ns;
static u64 overflow_sojourn_rescue_ns;
static u32 pcpu_depth_base;

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

// PHI MIGRATION POTENTIAL: distance penalty b*R_eff is pre-folded into the
// reff_value map (in ns) by Rust at topology detect, so dispatch STEP 1 reads it
// directly. No BPF-side scale global, no per-tick mirror, no per-steal multiply.

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

// LLC/CCX DOMAIN MAP: llc_domain[cpu] = L3/CCX group_id. CHIPLET PARTS
// (AMD CCX/CCD) HAVE MULTIPLE L3 GROUPS PER SOCKET; MONOLITHIC PARTS HAVE
// llc_domain == socket_domain (ALL ON-SOCKET CPUs COMPARE EQUAL, INTRA-CCX
// CHECKS ARE NO-OP). USED BY pandemonium_running TO TAG EACH MIGRATION AS
// INTRA-CCX OR CROSS-CCX FOR PER-PATH MIGRATION SOURCE DIAGNOSIS.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} llc_domain SEC(".maps");

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

// PHI STEAL PENALTY ORACLE: PER-CPU PRE-FOLDED DISTANCE PENALTY TO EACH TARGET.
// reff_value[cpu * MAX_AFFINITY_CANDIDATES + slot] = (R_eff(cpu, target) * b) >> 16
// IN NS, WHERE b = phi_dist_scale_q16 (FOLDED BY RUST AT TOPOLOGY DETECT). THE
// STEAL READS IT DIRECTLY AS dist_extra -- NO RUNTIME MULTIPLY, NO SCALE GLOBAL.
// PAIRS 1:1 WITH affinity_rank: THE RANK GIVES *WHICH* CPU, THIS ITS STEAL DELAY.
// ALL-ZERO ON MONOLITHIC / --phi-scale 0 => FLAT codel_target (EXACT PRIOR NO-OP).
// SENTINEL: (u32)-1 (TREATED AS 0 PENALTY) FOR SLOTS PAST THE TOPOLOGY END.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS * MAX_AFFINITY_CANDIDATES);
	__type(key, u32);
	__type(value, u32);
} reff_value SEC(".maps");

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
	u64 waker_bitmap;    // BIT i = CPU i woke this task; popcount = partner cardinality
	u32 tier;
	u32 ewma_age;
	s32 last_cpu;        // LAST CPU THIS TASK RAN ON (FOR CACHE AFFINITY)
	s32 home_cpu;        // STABLE PLACEMENT HOME: PINNED TO THE FIRST CPU THE
	                     // TASK RAN ON; NEVER CHASES last_cpu. WARM-STAY ANCHOR
	                     // SO THE TASK RETURNS HOME INSTEAD OF DRIFTING.
	u8  dispatch_path;   // 0=IDLE, 1=HARD_KICK, 2=SOFT_KICK
	u8  ran_since_wake;  // is_wakeup = !ran_since_wake; SET 1 IN running(), 0 ON WAKE
	u8  shape;           // FLOW SIGNATURE: SHAPE_* (FROZEN AT MATURITY)
	u8  _pad[1];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

// HELPERS

// PER-CCX OVERFLOW DSQ IDs. LAYOUT:
//   [0, nr_cpu_ids)                                   per-CPU DSQs
//   [nr_cpu_ids + 2*MAX_NODES,             ...)       per-CCX interactive overflow
//   [nr_cpu_ids + 2*MAX_NODES + MAX_CCX_DOMAINS, ...) per-CCX batch overflow
// THE 2*MAX_NODES GAP RESERVES IDs THAT EARLIER PER-NODE TIERS USED; KEEPING
// THE OFFSET CONSTANT MEANS HARDWARE-INDEPENDENT AT COMPILE TIME. DSQs ARE
// CREATED ONCE AT INIT FROM A FIXED MAP; THE RUNTIME nr_ccx GATES WHICH ARE
// ADDRESSED.
static __always_inline u64 ccx_inter_dsq(u32 ccx)
{
	return nr_cpu_ids + 2ULL * MAX_NODES + (u64)ccx;
}

static __always_inline u64 ccx_batch_dsq(u32 ccx)
{
	return nr_cpu_ids + 2ULL * MAX_NODES + MAX_CCX_DOMAINS + (u64)ccx;
}

// CCX of a CPU via llc_domain lookup; defaults to 0 if unavailable.
static __always_inline u32 cpu_ccx(s32 cpu)
{
	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return 0;
	u32 key = (u32)cpu;
	u32 *cd = bpf_map_lookup_elem(&llc_domain, &key);
	return cd ? *cd : 0;
}

// CROSS-CCX SCATTER BUMP. COUNTS A CROSS-CCX LANDING ON PATH `idx` (XCCX_*)
// WHEN THE TASK'S HOME CPU AND THE CHOSEN CPU SIT IN DIFFERENT CCXs.
// last_home < 0 (NO PRIOR CPU) IS NOT A MIGRATION. FREE-COMPUTE: ONE cpu_ccx
// COMPARE ON AN ALREADY-TAKEN PLACEMENT BRANCH. CONSUMED BY THE ADAPTIVE MWU
// SCATTER PATHWAY AND SURFACED PER-RUN BY THE BENCH SUITE.
static __always_inline void xccx_bump(struct pandemonium_stats *s, u32 idx,
				      s32 last_home, s32 dst)
{
	if (!s || idx >= 8 || last_home < 0)
		return;
	if (cpu_ccx(last_home) != cpu_ccx(dst))
		s->nr_xccx[idx] += 1;
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

// PHI PLACEMENT TARGET (SUBORDINATE SUB-MECHANISM). WARMTH'S ONLY ROLE ON THE
// WAKEUP FAST PATH IS TO BIAS WHICH IDLE CPU IS CHOSEN -- IT NEVER PLACES A WAKEE ON
// A BUSY CORE HERE. PLACING ON BUSY VIA THIS PATH ISSUED KICK_IDLE (A NO-OP ON A
// BUSY CPU) AND BYPASSED THE dfl -> enqueue PATH, STRANDING THE WAKEE UNTIL THE
// RUNNING TASK YIELDED: ~90% DEADLINE MISS UNDER SATURATION, IDENTICAL WHETHER THE
// WARM-STAY WAS A DEEP OVERRIDE OR A 1-DEEP WHISPER -- THE BUG WAS THE BUSY
// PLACEMENT ITSELF, NOT ITS DEPTH. SO WARMTH NEVER RETURNS A BUSY CPU:
//   - ANCHOR IDLE -> TAKE IT (WARM AND IMMEDIATE).
//   - ELSE NEAREST/WARMEST IDLE: find_idle_by_affinity WALKS R_eff ORDER, SO A
//     SAME-CCX IDLE IS PREFERRED OVER A CROSS-CCX ONE AUTOMATICALLY -- THAT IS THE
//     BIAS, EXPRESSED BY *WHICH* IDLE, NEVER BY REFUSING TO USE ONE.
//   - NOTHING IDLE -> RETURN -1, AND select_cpu FALLS THROUGH TO dfl -> enqueue, THE
//     PROVEN PATH THAT PLACES BUSY-CORE WAKEUPS WITH A REAL PREEMPT (KICK_PREEMPT).
// find_idle_by_affinity ALREADY RETURNS THE ANCHOR ITSELF WHEN IT IS IDLE (RANK SLOT
// 0 = SELF), SO A CORRECT SUBORDINATE PLACEMENT BIAS COLLAPSES TO EXACTLY THAT WALK.
// A PLACE-ON-BUSY WARM-STAY, IF EVER PURSUED, BELONGS IN THE enqueue PATH THAT KICKS
// PREEMPT -- NEVER THE IDLE FAST PATH.
static __always_inline s32 phi_warm_target(s32 anchor,
					   const struct cpumask *allowed,
					   u32 tier)
{
	(void)tier;
	return find_idle_by_affinity(anchor, allowed);
}

// WARM-STAY GATE. RETURNS THE ANCHOR (last_cpu) TO HOLD THE WAKEE ON WHEN THE
// ANCHOR IS UNCONGESTED -- I.E. PREFER QUEUEING ON prev_cpu OVER FANNING THE
// WAKEE OUT TO A COLD IDLE SIBLING. RETURNS -1 WHEN THE CALLER SHOULD IDLE-SEEK
// AS USUAL (ANCHOR CONGESTED, OR WARM-STAY INAPPLICABLE).
//
// CONGESTION = THE ANCHOR'S SOJOURN (now - ITS EMPTY->NONEMPTY STAMP, THE SAME
// SIGNAL THE DISPATCH STEP 1 STEAL READS) EXCEEDING codel_target_ns -- THE
// OSCILLATOR'S ADAPTIVE "STANDARD OPERATIONS" PRESSURE MARK. BELOW IT, THE
// ANCHOR IS DRAINING HEALTHILY AND THE WAKEE SHOULD STAY CACHE-WARM; ABOVE IT,
// THE ANCHOR IS GENUINELY BACKED UP AND FANNING OUT IS JUSTIFIED. THIS IS THE
// PLACEMENT-SIDE DUAL OF THE STEAL THRESHOLD: A WAKEE STAYS ON ITS WARM CORE
// RIGHT UP TO THE SOJOURN AT WHICH THE STEAL MACHINERY WOULD RELOCATE IT.
//
// THE CALLER MUST ROUTE A HELD WAKEE THROUGH A PREEMPT-KICKED PLACEMENT (THE
// ENQUEUE PATH), NEVER select_cpu's KICK_IDLE FAST PATH -- A KICK_IDLE ON A
// BUSY ANCHOR IS A NO-OP AND STRANDS THE WAKEE (THE ~90% DEADLINE-MISS SCAR
// DOCUMENTED ABOVE phi_warm_target). select_cpu THEREFORE ONLY DEFERS HERE.
//
// EXCLUDES: NON-WAKEUPS, LAT_CRITICAL (FLEES FOR IMMEDIACY), KTHREADS. THE
// ANCHOR (home_cpu, ELSE last_cpu) MUST BE VALID AND IN THE WAKEE'S ALLOWED MASK.
// DECOUPLED FROM affinity_mode: STICKINESS IS FUNDAMENTAL MIGRATION RESISTANCE,
// NOT AN ADAPTIVE-ONLY L2 FEATURE -- SO IT ENGAGES IN BPF-ONLY MODE TOO, WHERE
// THE MIGRATION STORM (2375 MOVES/THREAD VS EEVDF'S 45) WAS MEASURED.
static __always_inline s32 warm_stay_anchor(struct task_struct *p,
					    struct task_ctx *tctx,
					    struct tuning_knobs *knobs,
					    bool is_wakeup, u64 now)
{
	if (!tctx || !is_wakeup)
		return -1;
	if (!knobs)
		return -1;
	if (tctx->tier == TIER_LAT_CRITICAL || (p->flags & PF_KTHREAD))
		return -1;
	// STABLE HOME ANCHOR: PREFER THE PINNED HOME OVER last_cpu, WHICH IS REWRITTEN
	// EVERY stopping() AND SO CHASES THE TASK ACROSS CPUs -- THE MIGRATION-STORM
	// ROOT. AN UNCONGESTED HOME PULLS THE TASK BACK INSTEAD OF DRIFTING. FALLS
	// BACK TO last_cpu UNTIL HOME IS PINNED (FIRST RUN).
	s32 lc = (tctx->home_cpu >= 0) ? tctx->home_cpu : tctx->last_cpu;
	if (lc < 0 || (u32)lc >= nr_cpu_ids)
		return -1;
	if (!bpf_cpumask_test_cpu(lc, p->cpus_ptr))
		return -1;
	u64 stamp = pcpu_enqueue_ns[(u32)lc & (MAX_CPUS - 1)].ns;
	u64 sojourn = (stamp && now > stamp) ? (now - stamp) : 0;
	// PHI-PRICED STAY. THE STAY AND THE STEP-1 STEAL MUST RELEASE AT THE SAME
	// THRESHOLD, OR THEY FIGHT: THE STEAL FIRES AT codel_target + dist_extra
	// (THE R_eff DISTANCE PENALTY, PRE-FOLDED IN reff_value), BUT AN
	// UNCONDITIONAL BAIL AT BARE codel_target GAVE UP THE HOME TOO EARLY (EAGER
	// NON-STORM FAN-OUT) WHILE AN UNCONDITIONAL STORM EXEMPTION NEVER GAVE IT UP
	// (DEEP PILE -> STEAL RE-SCATTERS IT -> THE MIGRATION RAMP). READING THE
	// HOME'S OWN SLOT-0 PENALTY (DISTANCE TO ITS NEAREST PEER -- THE CHEAPEST
	// RELIEF TARGET) MAKES WARM-STAY HOLD THE TASK HOME UP TO EXACTLY THE
	// SOJOURN AT WHICH THAT NEAREST PEER'S STEAL WOULD RELIEVE IT. BELOW IT:
	// STAY (RELIEF, IF ANY, WOULD BE A CHEAP NEAR MOVE). ABOVE IT: RELEASE TO
	// IDLE-SEEK -- THE TASK WAS ABOUT TO BE STOLEN ANYWAY, SO PLACE IT WELL NOW.
	// Φ THUS GOVERNS IPC/WAKE-STORM/FORK-THREAD PLACEMENT ON ONE THRESHOLD:
	// A NEAR (LOW-R_eff) HOME RELEASES QUICKLY (CHEAP MOVES OK); A FAR HOME
	// (HIGH-R_eff, CROSS-FABRIC) HOLDS HARD (CROSSING IS EXPENSIVE). ALL SHAPES,
	// NO BINARY STORM BRANCH. reff_value ALL-ZERO (MONOLITHIC / --phi-scale 0)
	// COLLAPSES TO BARE codel_target -- EXACT PRIOR BEHAVIOR. LAT_CRITICAL
	// RETURNED AT LINE 616, SO AUDIO KEEPS ITS UNCONDITIONAL ESCAPE (NO SCAR).
	u32 base0 = (u32)lc * MAX_AFFINITY_CANDIDATES;
	u32 *dxp = bpf_map_lookup_elem(&reff_value, &base0);
	u32 dx = dxp ? *dxp : 0;
	u64 home_dist_extra = (dx == (u32)-1) ? 0 : (u64)dx;
	if (sojourn > codel_target_ns + home_dist_extra)
		return -1;        // home aged past its Phi threshold: idle-seek
	return lc;                // within Phi tolerance: stay warm
}

// SIBLING PER-CPU DSQ WITH ROOM: WALKS THE SAME R_EFF-RANKED LIST AS
// find_idle_by_affinity BUT WITH "HAS ROOM" AS THE PREDICATE INSTEAD OF
// "IS IDLE". USED BY THE WAKE_SYNC AND normal_path DEPTH-GATE SPILL SITES
// IN select_cpu TO ROUTE OVERFLOW INTO A SIBLING PER-CPU DSQ -- WHICH IS
// REACHED BY DISPATCH STEP 0 (OWN) OR STEP 1 (L2 STEAL) -- INSTEAD OF
// FUNNELING INTO ccx_inter_dsq, WHICH DISPATCH ONLY REACHES AT STEP 3.
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
//   3. LAST RESORT: ccx_inter_dsq FOR src_cpu's CCX. HARD STARVATION RESCUE
//      BOUNDS WAIT. ALSO THE ESCAPE VALVE WHEN allowed EXCLUDES src_cpu AND
//      ALL R_EFF SIBLINGS -- TASK CAN ALWAYS BE DRAINED BY ANY SAME-CCX CORE
//      VIA STEP 3 OF THE DISPATCH WATERFALL, OR CROSS-CCX VIA STEP 5 WORK
//      CONSERVATION. PREVENTS THE PER-CPU DSQ AFFINITY-STRANDING CLASS
//      BEHIND scx ISSUE #728 / RUNNABLE-TASK STALLS WHEN cpus_ptr CHANGES
//      MID-FLIGHT (LIBVIRT CGROUP CPUSETS, kthread_bind, ETC.).
// *out_cpu RECEIVES THE CPU SCX SHOULD WAKE (THE PER-CPU DSQ OWNER WE
// LANDED IN; src_cpu IF WE FELL BACK TO ccx_inter_dsq).
static __always_inline u64 pick_pcpu_dsq_with_spill(s32 src_cpu,
						    const struct cpumask *allowed,
						    u32 shape,
					    s32 *out_cpu)
{
	u64 now = bpf_ktime_get_ns();
	bool src_ok = (u64)src_cpu < nr_cpu_ids &&
		      (!allowed || bpf_cpumask_test_cpu(src_cpu, allowed));

	if (src_ok &&
	    scx_bpf_dsq_nr_queued((u64)src_cpu) < pcpu_depth_base) {
		if ((u32)src_cpu < MAX_CPUS)
			__sync_val_compare_and_swap(
				&pcpu_enqueue_ns[(u32)src_cpu].ns,
				0, now);
		*out_cpu = src_cpu;
		return (u64)src_cpu;
	}

	// FALSIFYING TEST (20-AGENT CONSENSUS): DISABLE THE SHAPE_STORM BRANCH.
	// HYPOTHESIS: STORM WAKEES ROUTED TO ccx_inter_dsq (A CCX-WIDE SHARED DSQ)
	// WHILE KICKING ONLY `src_cpu` DECOUPLES PLACEMENT FROM DRAIN -- THE KICKED
	// CPU IS NOT NECESSARILY THE SAME-CCX PEER THAT WINS STEP 3a's DRAIN RACE.
	// P(KICKED CPU DRAINS) ≈ 1/6 ON A 6-CPU CCX, SO ~5/6 OF STORM WAKEUPS
	// PRODUCE A MIGRATION ON EVERY SINGLE WAKE -- ACCOUNTING FOR THE MEASURED
	// 22× MIGRATION MULTIPLIER AND 2.1× WAKEUP AMPLIFIER. LETTING STORM FALL
	// THROUGH TO find_pcpu_with_room + B-v2 OVER-DEPTH OWN PLACES THE WAKEE ON
	// A SPECIFIC NAMED CPU'S PER-CPU DSQ, RESTORING KICK == DRAIN IDENTITY.
	// (void)now IN THIS BRANCH SINCE WE NO LONGER ARM interactive_enqueue_ns.
	// if (shape == SHAPE_STORM) {
	// 	__sync_val_compare_and_swap(&interactive_enqueue_ns, 0, now);
	// 	*out_cpu = src_cpu;
	// 	return ccx_inter_dsq(cpu_ccx(src_cpu));
	// }
	(void)shape;

	s32 spill = find_pcpu_with_room(src_cpu, allowed);
	if (spill >= 0) {
		if ((u32)spill < MAX_CPUS)
			__sync_val_compare_and_swap(
				&pcpu_enqueue_ns[(u32)spill].ns,
				0, now);
		*out_cpu = spill;
		return (u64)spill;
	}

	// B v2: NO ROOM ON A NEAR (SAME-CCX) SIBLING. KEEP THE WAKEE ON ITS OWN
	// WARM CORE OVER-DEPTH RATHER THAN SCATTERING TO ccx_inter_dsq IMMEDIATELY.
	// THE DEEP PER-CPU QUEUE IS BOUNDED BY THE CoDel SOJOURN STEAL (RELIEVED
	// TO A NEAR SAME-CCX CORE ONCE IT WAITS PAST codel_target), SO IT STAYS
	// L1/L2-WARM WITHOUT SCATTERING. ccx_inter_dsq IS THE ESCAPE VALVE BELOW
	// ONLY WHEN src_cpu ISN'T IN THE allowed MASK (THE AFFINITY CASE).
	if (src_ok) {
		if ((u32)src_cpu < MAX_CPUS)
			__sync_val_compare_and_swap(
				&pcpu_enqueue_ns[(u32)src_cpu].ns,
				0, now);
		*out_cpu = src_cpu;
		return (u64)src_cpu;
	}

	// AFFINITY-STRANDED ESCAPE: src_cpu isn't in allowed. Route to src_cpu's
	// CCX-local overflow DSQ; if allowed excludes the whole CCX, the cross-CCX
	// drain at STEP 3b picks it up as work-conservation.
	__sync_val_compare_and_swap(&interactive_enqueue_ns, 0, now);
	*out_cpu = src_cpu;
	return ccx_inter_dsq(cpu_ccx(src_cpu));
}

// NO ARM FUNCTION: THE PER-CPU WAITING SIGNAL IS pcpu_enqueue_ns[cpu], STAMPED
// AT PLACEMENT; tick() READS IT DIRECTLY (SEE THE PER-CPU PREEMPT IN tick()).

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

// DRAIN ONE TASK FROM AN OVERFLOW DSQ; CLEAR ITS EMPTY->NONEMPTY STAMP WHEN
// THE DSQ EMPTIES. RETURNS TRUE IF A TASK MOVED. THE SINGLE PRIMITIVE BEHIND
// try_service_older_overflow AND DISPATCH STEP 3/4 -- ONE move_to_local +
// CAS-CLEAR, FACTORED OUT OF SIX OPEN-CODED COPIES.
static __always_inline bool overflow_drain_clear(u64 dsq, u64 *stamp)
{
	if (!scx_bpf_dsq_move_to_local(dsq, 0))
		return false;
	if (scx_bpf_dsq_nr_queued(dsq) == 0) {
		u64 old = *stamp;
		if (old > 0)
			__sync_val_compare_and_swap(stamp, old, 0);
	}
	return true;
}

// CCX-LOCAL OVERFLOW DRAIN: DRAIN MY CCX'S OVERFLOW DSQ. CROSS-CCX WORK
// CONSERVATION IS A SINGLE EXPLICIT LOOP IN DISPATCH (BELOW THE LOCAL STEPS),
// NOT FOLDED INTO THIS HELPER -- THE ORIGINAL "DRAIN LOCAL + SCAN OTHER CCXs"
// SHAPE INLINED FOUR TIMES (STEP 3, STEP 4, BOTH RESCUE PATHS) BLEW THE
// PROGRAM PAST THE VERIFIER'S INSTRUCTION CEILING (-E2BIG). SPLITTING THE
// LOCAL FAST PATH FROM THE CROSS-CCX SCAN KEEPS INLINED HELPERS TINY AND
// PUTS THE LOOP WHERE IT RUNS ONCE PER DISPATCH.
static __always_inline bool ccx_overflow_drain_local(u32 my_ccx,
						     bool batch,
						     u64 *stamp)
{
	u64 dsq = batch ? ccx_batch_dsq(my_ccx) : ccx_inter_dsq(my_ccx);
	return overflow_drain_clear(dsq, stamp);
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
						        u32 my_ccx,
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
		if (ccx_overflow_drain_local(my_ccx, false,
					     &interactive_enqueue_ns))
			dispatched_any = true;
		if (b_aged && ccx_overflow_drain_local(my_ccx, true,
						       &batch_enqueue_ns))
			dispatched_any = true;
	} else {
		if (ccx_overflow_drain_local(my_ccx, true,
					     &batch_enqueue_ns))
			dispatched_any = true;
		if (i_aged && ccx_overflow_drain_local(my_ccx, false,
						       &interactive_enqueue_ns))
			dispatched_any = true;
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
	// NO FIXED FLOOR: THE OLD 1ms FLOOR PINNED codel_target_max AT 12C
	// (0.05*13.3ms = 665us -> 1ms) AND 8C, OVERRIDING THE tau-DERIVED VALUE --
	// THE ONE FLOOR THAT ACTUALLY BINDS ON THIS BOX. FLOOR INSTEAD AT THE
	// OSCILLATOR'S OWN FLOOR SO THE WORKING WINDOW CAN NEVER INVERT (max >=
	// floor) AT DENSE TOPOLOGIES WHERE 0.05*tau WOULD DIP BELOW codel_floor,
	// WHILE LETTING THE TARGET TRACK tau ON REAL HARDWARE.
	if (v < codel_target_floor_ns) v = codel_target_floor_ns;
	if (v > 8000000ULL) v = 8000000ULL;           // CEILING 8MS (stall-blind guard)
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

	// OVERFLOW-GATE DELTA, PRODUCED BY R_eff FOR FREE. THE GATE THAT OPENS
	// OVERFLOW SERVICE (sojourn_gate_pass + STEP 2) NOW KEYS ON THE
	// R_eff-DERIVED CODEL EQUILIBRIUM -- THE ALREADY-COMPUTED SPECTRAL SCALAR
	// -- INSTEAD OF A HAND-TUNED k*tau TIME. SOJOURN (enqueue-age) IS
	// UNCHANGED: STILL THE MEASURED PRESSURE AND THE OLDER-SIDE SELECTOR.
	// R_eff SETS ONLY WHEN THE GATE OPENS; SOJOURN FILLS IT.
	overflow_sojourn_rescue_ns = codel_target_equilibrium_ns;

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
	// (2C, FAST RESTORE), damp=5 -> shift=11 (12C, GENTLE RESTORE).
	oscillator_spring_shift = 2 * damp + 1;

	// velocity_cap PRESERVES COUPLING TO pull_scale.
	oscillator_velocity_cap = (s64)((u64)OSC_VELOCITY_CAP_PER_PULL * (u64)pull);

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

	// SLEEP-BOOST LAG CAP (NOT A VTIME CAP -- THE VTIME ENGINE WAS RETIRED
	// IN v5.11.0; THIS BOUNDS THE SOJOURN-WARP CREDIT). SCALES WITH TOPOLOGY TIMING.
	// lag_cap_ns = K_LAG_CAP * tau (1.0 * tau AT 12C REFERENCE = 40MS).
	// CLAMPED [8MS, 80MS].
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
	u64 old = pcpu_enqueue_ns[cpu].ns;
	if (old > 0)
		__sync_val_compare_and_swap(&pcpu_enqueue_ns[cpu].ns, old, 0);
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

// SOJOURN SELECTOR (NO VIRTUAL TIME): THE DSQ SORT KEY IS THE ENQUEUE
// TIMESTAMP, SO THE QUEUE ORDERS OLDEST-FIRST -- AT ANY FIXED DISPATCH
// INSTANT THE SMALLEST KEY IS THE EARLIEST INSERT, I.E. THE LARGEST
// SOJOURN (now - enqueue_at). THE TIER WARP BACK-DATES HIGHER TIERS SO
// THEY SORT AHEAD; IT IS BOUNDED (<= lag_cap_ns), SO A STREAM OF
// LAT_CRITICAL WAKEUPS CAN NEVER STARVE A BATCH TASK OLDER THAN THE WARP.
// PER-TASK SOJOURN POTENTIAL (Q16, 0..65536). TIER SETS THE CEILING SHARE;
// PER-TASK BEHAVIOR SETS THE MAGNITUDE. BOUNDED SUM OF MONOTONIC RAMPS --
// CONTINUOUS, NO TIER CLIFF, NO UNBOUNDED ADVANTAGE.
static __always_inline u32 task_potentiality_q16(const struct task_ctx *tctx,
						 const struct tuning_knobs *knobs)
{
	if (tctx->ewma_age < EWMA_AGE_MATURE)
		return 0;                  // UNOBSERVED: NO POTENTIAL
	if (tctx->tier == TIER_BATCH)
		return 0;                  // BATCH NEVER WARPS
	if (tctx->tier == TIER_LAT_CRITICAL)
		return 1u << 16;           // RT FLOOR: ABSOLUTE, FULL CEILING

	// INTERACTIVE: EARNED CONTINUOUSLY FROM PER-TASK BEHAVIOR.
	u64 slice = knobs ? knobs->slice_ns : 1000000;
	u64 avg = tctx->avg_runtime;
	u32 acc = 0;                       // Q16 EXCESS, CAP 65536

	// AXIS 1 -- SERVICE DEFICIT: SHORT RUNTIME PER ACTIVATION (YIELDS
	// BEFORE ITS QUANTUM) EARNS WARP; A FULL-SLICE HOG EARNS NONE.
	if (slice > 0 && avg < slice) {
		u32 c = (u32)(((slice - avg) << 16) / slice);
		acc += c > 32768u ? 32768u : c;
	}

	// AXIS 2 -- SHAPE: LOW RUNTIME VARIANCE RELATIVE TO MEAN (PERIODIC,
	// FRAME-PACED) EARNS WARP; CHAOTIC BURSTINESS EARNS NONE. INVERSE CV.
	if (avg > 0 && tctx->runtime_dev < avg) {
		u32 c = (u32)(((avg - tctx->runtime_dev) << 16) / avg);
		c = c > 32768u ? 32768u : c;
		acc = (acc > 65536u - c) ? 65536u : acc + c;
	}

	return acc;                        // 0..65536
}

// FLOW SIGNATURE CLASSIFIER (CLASSIFY ONCE, FREEZE AT MATURITY). EACH WAKEUP
// SETS THE WAKER CPU'S BIT; THE POPCOUNT IS THE TASK'S DISTINCT-PARTNER
// CARDINALITY. AT MATURITY: <= SHAPE_TIGHT_MAX PARTNERS IS A TIGHT LOOP; A
// PARTNER SET SPANNING AT LEAST HALF THE MACHINE IS A STORM MESH; EVERYTHING
// BETWEEN DEFAULTS TO TIGHT (LATENCY-SAFE -- ITS STEAL STAYS FREELY RELIEVABLE).
// THEN FREEZE -- DETERMINISTIC PER TASK, SO ROUTING CAN'T COIN-FLIP.
static __always_inline void update_shape(struct task_ctx *tctx, u32 waker)
{
	if (tctx->shape != SHAPE_UNCLASSIFIED)
		return;                                 // FROZEN
	if (waker < 64)
		tctx->waker_bitmap |= (1ULL << waker);

	if (tctx->ewma_age < EWMA_AGE_MATURE)
		return;                                 // STILL OBSERVING

	u32 card = (u32)__builtin_popcountll(tctx->waker_bitmap);
	if (card > SHAPE_TIGHT_MAX && card * 2 >= nr_cpu_ids)
		tctx->shape = SHAPE_STORM;
	else
		tctx->shape = SHAPE_TIGHT;
}

static __always_inline u64 task_deadline(struct task_ctx *tctx,
					 const struct tuning_knobs *knobs)
{
	u64 now = bpf_ktime_get_ns();

	// SOJOURN POTENTIAL (v5.12 ANTI-LEAPFROG, CONTINUOUS FORM): warp IS A
	// BOUNDED PER-TASK POTENTIAL, NOT A FLAT TIER CONSTANT. lag_cap_ns IS THE
	// CEILING (STARVATION BOUND); task_potentiality_q16 POSITIONS THE BACK-DATE
	// CONTINUOUSLY FROM THE TASK'S OWN SERVICE DEFICIT + SHAPE. SLEEPY/PERIODIC
	// -> NEAR-FULL WARP; CPU-HOG OR CHAOTIC -> ~0. UNMATURED TASKS GET 0, SO A
	// FORK STORM STILL CANNOT LEAPFROG ESTABLISHED WORK.
	u64 warp = (lag_cap_ns * task_potentiality_q16(tctx, knobs)) >> 16;

	// SOJOURN BACK-PRESSURE: ORDERING IS now - warp, OLDEST-FIRST -- A STARVING
	// TASK RISES AS IT AGES, AND BOUNDED WARP MAKES IT STARVATION-FREE. DEEP-QUEUE
	// DRAINAGE IS THE OVERFLOW RESCUE'S JOB (try_service_older_overflow AT
	// overflow_sojourn_rescue_ns), FORCED BY WAIT NOT DEPTH.
	return now > warp ? now - warp : 0;
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
// SPILL TO ccx_inter_dsq SO ANY SAME-CCX CORE CAN GRAB IT.
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
		stay_hold = warm_stay_anchor(p, tc, kn, wake, bpf_ktime_get_ns());
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
	// ROUTES IT BY SHAPE -- STORM SPREADS, TIGHT STAYS LOCAL.
	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_ctx *tctx = lookup_task_ctx(p);
		s32 waker_cpu = bpf_get_smp_processor_id();
		// TRACK THE WAKER EVEN ON THE SYNC-PLACED PATH (enqueue's update_shape
		// DOESN'T RUN WHEN select_cpu DISPATCHES), SO PARTNER CARDINALITY STAYS
		// LIVE AND A 1:N SERVER SELF-CORRECTS OUT OF THE TIGHT CLASS BELOW.
		if (tctx && waker_cpu >= 0 && waker_cpu < 64 &&
		    tctx->shape == SHAPE_UNCLASSIFIED)
			tctx->waker_bitmap |= (1ULL << (u32)waker_cpu);
		// PIPE-PARTNER CO-LOCATION (EEVDF WAKE-AFFINE): ON A SYNC WAKE THE WAKER
		// IS ABOUT TO BLOCK, SO ITS CORE FREES IN MICROSECONDS AND THE DATA IT
		// JUST PRODUCED (THE PIPE BUFFER) IS CACHE-HOT. FOR A 1:1-ISH PARTNER
		// (FEW DISTINCT WAKERS: waker_bitmap POPCOUNT <= SHAPE_TIGHT_MAX, OR A
		// FROZEN SHAPE_TIGHT) SEAT THE WAKEE DIRECTLY ON THE WAKER'S PER-CPU DSQ
		// -- THE ONE CASE WE DELIBERATELY QUEUE ON A BUSY CORE INSTEAD OF FLEEING
		// TO A COLD IDLE SIBLING -- SO BOTH PIPE ENDS STAY WARM ON ONE CACHE.
		// 1:N SERVERS (MANY WAKERS) FALL THROUGH TO THE WARM-NEAR-IDLE SEARCH SO
		// CLIENTS DON'T PILE ONTO THE SERVER'S CPU.
		u32 partners = tctx
			? (u32)__builtin_popcountll(tctx->waker_bitmap) : 0;
		bool tight = (tctx && tctx->shape == SHAPE_TIGHT) ||
			     partners <= SHAPE_TIGHT_MAX;
		// MULTI-CCX ONLY: SEATING THE WAKEE ON THE WAKER'S CORE IS A REAL
		// MIGRATION. IT PAYS OFF ONLY WHEN THE PARTNERS WOULD OTHERWISE SIT IN
		// DIFFERENT L3s (CROSS-CCX COLD) -- ON A MONOLITHIC L3 (nr_ccx <= 1)
		// EVERY CORE SHARES THE CACHE, SO THERE IS ZERO LOCALITY UPSIDE AND IT
		// IS PURE MIGRATION CHURN THAT OVERRIDES THE HOME-PIN. GATE IT OFF THERE
		// AND LET warm_stay_anchor's STABLE HOME GOVERN INSTEAD.
		if (nr_ccx > 1 && tight && (u64)waker_cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(waker_cpu, p->cpus_ptr)) {
			struct tuning_knobs *knobs = get_knobs();
			u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;
			u64 dl = tctx ? task_deadline(tctx, knobs)
				      : bpf_ktime_get_ns();
			s32 dst_cpu;
			u64 dst_dsq = pick_pcpu_dsq_with_spill(waker_cpu, p->cpus_ptr,
				tctx ? tctx->shape : SHAPE_UNCLASSIFIED, &dst_cpu);
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
				xccx_bump(s, XCCX_SEL_TIGHT, tctx ? tctx->last_cpu : -1, dst_cpu);
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
			s32 target = phi_warm_target(anchor, p->cpus_ptr,
						     tctx ? tctx->tier : TIER_INTERACTIVE);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				u64 sl = tctx ? task_slice(tctx, knobs)
					      : 1000000;
				s32 dst_cpu;
				u64 dst_dsq = pick_pcpu_dsq_with_spill(target, p->cpus_ptr, tctx ? tctx->shape : SHAPE_UNCLASSIFIED, &dst_cpu);
				u64 dl = tctx ? task_deadline(tctx, knobs) : bpf_ktime_get_ns();
				scx_bpf_dsq_insert_vtime(p,
					dst_dsq, sl, dl, 0);
				// IPC FIX -- LOAD-BEARING, DO NOT REMOVE (commit 5224a8d5e).
				// THE PER-CPU DSQ INSERT NEEDS AN EXPLICIT KICK OR THE
				// WAKEE WAITS FOR THE NEXT TICK. TARGET WAS IDLE, SO
				// KICK_IDLE SUFFICES.
				scx_bpf_kick_cpu(dst_cpu, SCX_KICK_IDLE);
				if (tctx) {
					tctx->dispatch_path = 0;
							tctx->enqueue_at = bpf_ktime_get_ns();
				}
				struct pandemonium_stats *s = get_stats();
				if (s) {
					s->nr_idle_hits += 1;
					s->nr_dispatches += 1;
					xccx_bump(s, XCCX_SEL_SYNC, tctx ? tctx->last_cpu : -1, dst_cpu);
				}
				return dst_cpu;
			}
			// MISS: ANCHOR'S affinity_rank HAD NO NEAR IDLE. IF ANCHOR IS THE
			// WAKEE'S last_cpu, normal_path WALKS THE IDENTICAL FIXED RANK FOR THE
			// IDENTICAL RESULT -- RECORD THE MISS SO IT SKIPS THE REDUNDANT WALK.
			// (IF A SIBLING IDLES IN THE ~us GAP, THE dfl PICK BELOW STILL USES IT,
			// SO NO WORK-CONSERVATION LOSS -- JUST ONE FEWER RANK WALK PER WAKE.)
			if (tctx && anchor == tctx->last_cpu)
				last_cpu_idle_miss = true;
		}
	}

	// WARM-STAY DEFER: anchor uncongested -> return it without dispatching, so
	// p flows to enqueue's PREEMPT-kicked warm-stay placement instead of any
	// idle-seek below (the normal_path warm pick or the dfl any-idle pick).
	if (stay_hold >= 0)
		return stay_hold;

	// SHAPE-ROUTED WARM PLACEMENT (B): BEFORE THE dfl ANY-IDLE PICK -- WHICH IS
	// TOPOLOGY-BLIND AND CAN SEAT THE WAKEE ON A CROSS-CCX IDLE CORE (COLD L3,
	// THE STORM'S CACHE-MISS SOURCE) -- KEEP IT ON ITS WARM CACHE. ANCHOR ON THE
	// WAKEE'S OWN LAST CORE AND SEARCH R_eff-NEAR (SAME L2/CCX FIRST). TIGHT GRABS
	// ITS EXACT WARM CORE WHEN IT'S FREE (TIGHTEST CONSOLIDATION); BOTH SHAPES
	// THEN TAKE THE NEAREST IDLE. FALLS THROUGH TO dfl ONLY WHEN NOTHING WARM-NEAR
	// IS IDLE (TRUE SATURATION -- enqueue TIER 2 THEN WARM-ANCHORS IT).
	{
		struct task_ctx *tctx = lookup_task_ctx(p);
		if (!last_cpu_idle_miss && tctx && tctx->last_cpu >= 0 &&
		    (u64)tctx->last_cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(tctx->last_cpu, p->cpus_ptr)) {
			s32 anchor = tctx->last_cpu;
			// PHI PLACEMENT (ALL SHAPES): WARM CORE IF IDLE, ELSE QUEUE ON IT
			// WHEN SHALLOW-BUSY (STAY L2-WARM) INSTEAD OF FLEEING COLD; ONLY A
			// FULL WARM CORE FALLS THROUGH TO THE NEAREST IDLE. LAT_CRITICAL IS
			// EXEMPT FROM THE QUEUE-ON-BUSY (KEEPS FLEEING FOR IMMEDIACY).
			s32 target = phi_warm_target(anchor, p->cpus_ptr, tctx->tier);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				u64 sl = task_slice(tctx, knobs);
				u64 dl = task_deadline(tctx, knobs);
				s32 seat_cpu;
				u64 seat_dsq = pick_pcpu_dsq_with_spill(target, p->cpus_ptr, tctx->shape, &seat_cpu);
				scx_bpf_dsq_insert_vtime(p, seat_dsq, sl, dl, 0);
				scx_bpf_kick_cpu(seat_cpu, SCX_KICK_IDLE);
				tctx->dispatch_path = 0;
					tctx->enqueue_at = bpf_ktime_get_ns();
				struct pandemonium_stats *s = get_stats();
				if (s) {
					s->nr_idle_hits += 1;
					s->nr_dispatches += 1;
					count_l2_affinity(s, tctx, seat_cpu);
					xccx_bump(s, XCCX_SEL_NORMAL, tctx->last_cpu, seat_cpu);
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
		// ON SIBLING OR STEP 1 L2 STEAL); LAST-RESORT ccx_inter_dsq.
		u64 dst_dsq = pick_pcpu_dsq_with_spill(cpu, p->cpus_ptr, tctx ? tctx->shape : SHAPE_UNCLASSIFIED, &dst_cpu);
		u64 dl = tctx ? task_deadline(tctx, knobs)
			      : bpf_ktime_get_ns();
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
			xccx_bump(s, XCCX_SEL_DFL, tctx ? tctx->last_cpu : -1, dst_cpu);
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
		update_shape(tctx, bpf_get_smp_processor_id());

	// TIER 0 -- WARM-STAY: AN UNCONGESTED ANCHOR (last_cpu) KEEPS THE WAKEE ON
	// ITS WARM CORE INSTEAD OF FANNING OUT TO A COLD IDLE SIBLING -- THE DUAL OF
	// THE DISPATCH STEAL THRESHOLD (SEE warm_stay_anchor). PLACED DIRECTLY ON
	// last_cpu's PER-CPU DSQ WITH NO SPILL: A LOW-SOJOURN ANCHOR DRAINS FAST EVEN
	// WHEN DEEP, SO A DEPTH-BASED SPILL WOULD MIGRATE AGAINST THE WARM-STAY. KICK
	// PREEMPT BECAUSE last_cpu MAY BE BUSY (KICK_IDLE WOULD NO-OP AND STRAND THE
	// WAKEE -- THE SCAR ABOVE phi_warm_target). THIS IS WHERE select_cpu's
	// WARM-STAY DEFER LANDS. ABOVE-THRESHOLD SOJOURN RETURNS -1 HERE AND THE
	// WAKEE FANS OUT THROUGH TIER 1 BELOW EXACTLY AS BEFORE.
	{
		s32 hold = warm_stay_anchor(p, tctx, knobs, is_wakeup,
					    bpf_ktime_get_ns());
		if (hold >= 0) {
			u64 hdl = task_deadline(tctx, knobs);
			u64 hnow = bpf_ktime_get_ns();
			__sync_val_compare_and_swap(
				&pcpu_enqueue_ns[(u32)hold & (MAX_CPUS - 1)].ns,
				0, hnow);
			scx_bpf_dsq_insert_vtime(p, (u64)hold, sl, hdl, enq_flags);
			scx_bpf_kick_cpu(hold, SCX_KICK_PREEMPT);
			tctx->dispatch_path = 1;
			tctx->enqueue_at = hnow;
			struct pandemonium_stats *s = get_stats();
			if (s) {
				s->nr_shared += 1;
				s->nr_dispatches += 1;
				s->nr_hard_kicks += 1;
				if (is_wakeup)
					s->nr_enq_wakeup += 1;
				else
					s->nr_enq_requeue += 1;
				count_l2_affinity(s, tctx, hold);
			}
			return;
		}
	}

	// TIER 1: IDLE CPU -> THAT CPU'S PER-CPU DSQ + KICK
	// L2 PLACEMENT: TRY IDLE SIBLING IN SAME L2 DOMAIN FIRST, SO cpu IS
	// BIASED TO THE WAKEE'S last_cpu L2 GROUP (CACHE-WARM). SEAT THE WAKEE
	// ON cpu'S OWN PER-CPU DSQ ((u64)cpu). cpu WAS JUST FOUND IDLE, SO ITS
	// PER-CPU DSQ IS SHALLOW; NO SPILL SEARCH NEEDED.
	// LAT_CRITICAL AND KERNEL THREADS SKIP AFFINITY -- FASTEST CPU WINS.
	s32 cpu = -1;
	if (knobs && knobs->affinity_mode > 0 && tctx &&
	    tctx->tier != TIER_LAT_CRITICAL &&
	    !(p->flags & PF_KTHREAD)) {
		cpu = find_idle_l2_sibling(tctx, p->cpus_ptr);
	}
	if (cpu < 0)
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p->cpus_ptr, node, 0);
	if (cpu >= 0 && (u64)cpu < nr_cpu_ids) {
		// TIER 1: WE FOUND A SPECIFIC IDLE CPU. SEAT THE WAKEE ON THAT CPU'S
		// OWN PER-CPU DSQ AND KICK IT -- KICK==DRAIN IDENTITY, THE KICKED CPU
		// IS THE ONE THAT DISPATCHES THE WAKEE. THE PRIOR SHAPE_STORM ROUTE TO
		// ccx_inter_dsq (CCX-WIDE SHARED) WHILE KICKING ONE CPU DECOUPLED
		// PLACEMENT FROM DRAIN: P(KICKED CPU WINS THE SHARED-DSQ RACE) ~ 1/CCX
		// SIZE, SO ~5/6 OF STORM WAKEUPS MIGRATED ON EVERY WAKE (THE WAKE-STORM
		// LEAK / 1037-PER-THREAD MIGRATION FLOOR). PER-CPU PLACEMENT PINS THE
		// WAKEE WHERE IT WAS KICKED; THE EXISTING STEP-1 R_eff STEAL STILL
		// RELIEVES IT CCX-LOCALLY IF IT AGES PAST THE PHI THRESHOLD.
		u64 tier1_dsq = (u64)cpu;
		bool tier1_to_ccx = false;
		dl = tctx ? task_deadline(tctx, knobs)
			  : bpf_ktime_get_ns();
		scx_bpf_dsq_insert_vtime(p, tier1_dsq, sl, dl, enq_flags);
		// ARM THE CCX-OVERFLOW SOJOURN STAMP ONLY WHEN THIS PLACEMENT
		// ACTUALLY LANDS IN ccx_inter_dsq. PER-CPU PLACEMENTS (THE COMMON
		// NON-STORM TIER 1 CASE) DON'T TOUCH ccx_inter_dsq -- ARMING THE
		// STAMP HERE WOULD LEAVE IT SET WITH NOTHING TO CLEAR IT, CAUSING
		// STEP 2 RESCUE TO READ A STALE "HEAD AGE" THAT TRACKS NOTHING.
		if (tier1_to_ccx)
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
			xccx_bump(s, XCCX_ENQ_T1, tctx ? tctx->last_cpu : -1, cpu);
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

	// TIER 2: WARM-ANCHOR WAKEUP -- WAKEE'S OWN last_cpu PER-CPU DSQ + KICK
	// A WAKING TASK (OR LAT_CRITICAL RE-ENQUEUE) IS SEATED TOWARD THE CORE IT
	// LAST RAN ON, NOT AN ARBITRARY NODE-WIDE PICK. pick_pcpu_dsq_with_spill
	// GIVES THE WARM PER-CPU DSQ IF IT HAS ROOM, ELSE A NEAR R_eff SIBLING,
	// ELSE ccx_inter_dsq AS THE LAST-RESORT ESCAPE VALVE. dispatch STEP 0
	// DRAINS THE WARM PER-CPU DSQ WHEN last_cpu NEXT DISPATCHES; STEP 1
	// (NEAREST-SURPLUS STEAL) COVERS A SIBLING LANDING.
	if (tctx &&
	    (tctx->tier == TIER_LAT_CRITICAL || is_wakeup)) {
		// WARM-ANCHOR: PREFER THE WAKEE'S OWN LAST CORE. pick_pcpu_dsq_with_spill
		// THEN SEATS IT ON THAT cpu'S PER-CPU DSQ (WARM), A NEAR R_eff SIBLING,
		// OR ccx_inter_dsq AS LAST RESORT.
		cpu = (tctx->last_cpu >= 0 && (u64)tctx->last_cpu < nr_cpu_ids)
		    ? tctx->last_cpu
		    : __COMPAT_scx_bpf_pick_any_cpu_node(p->cpus_ptr, node, 0);
		if (cpu >= 0 && (u64)cpu < nr_cpu_ids &&
		    __COMPAT_scx_bpf_cpu_curr(cpu)) {
			s32 t2_cpu;
			u64 tier2_dsq = pick_pcpu_dsq_with_spill(cpu, p->cpus_ptr, tctx->shape, &t2_cpu);

			dl = task_deadline(tctx, knobs);
			scx_bpf_dsq_insert_vtime(p, tier2_dsq, sl, dl,
						  enq_flags);

			u64 kick_flag = (is_wakeup ||
				 tctx->tier == TIER_LAT_CRITICAL)
				? SCX_KICK_PREEMPT : SCX_KICK_IDLE;
			scx_bpf_kick_cpu(t2_cpu, kick_flag);
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
	// LAT_CRITICAL TASKS ARE NEVER REDIRECTED.
	// TIER 3 ROUTES TO THE PER-CCX OVERFLOW DSQ FOR THE TASK'S HOME CPU'S CCX.
	// Dispatch STEP 3 drains it CCX-locally (cache-coherent inside the L3);
	// STEP 5 is the cross-CCX work-conservation scan when local CCX is empty.
	s32 src_cpu_t3 = scx_bpf_task_cpu(p);
	u32 src_ccx_t3 = cpu_ccx(src_cpu_t3);
	bool is_batch_t3 = tctx && tctx->tier == TIER_BATCH;
	u64 target_dsq = is_batch_t3 ? ccx_batch_dsq(src_ccx_t3)
				     : ccx_inter_dsq(src_ccx_t3);

	// SOJOURN TRACKING: RECORD WHEN OVERFLOW DSQs TRANSITION FROM EMPTY.
	// DISPATCH STEP 0 CHECKS THESE TO RESCUE TASKS AGING PAST THRESHOLD.
	if (is_batch_t3)
		__sync_val_compare_and_swap(&batch_enqueue_ns, 0, bpf_ktime_get_ns());
	else
		__sync_val_compare_and_swap(&interactive_enqueue_ns, 0, bpf_ktime_get_ns());

	// WARP IS BOUNDED BY lag_cap_ns INSIDE task_deadline() (NO CEILING CLAMP).
	dl = tctx ? task_deadline(tctx, knobs) : bpf_ktime_get_ns();

	scx_bpf_dsq_insert_vtime(p, target_dsq, sl, dl, enq_flags);

	if (tctx)
		tctx->enqueue_at = bpf_ktime_get_ns();

#if TRACE_SCHED
	if (is_sched_task(p))
		bpf_printk("PAND: enq tier3 pid=%d dsq=%llu tier=%d", p->pid, target_dsq, tctx ? tctx->tier : -1);
#endif

	// CCX OVERFLOW (ccx_inter_dsq OR ccx_batch_dsq). WAKEUPS KICK
	// scx_bpf_task_cpu(p); IF BUSY, tick()'s PER-CPU PREEMPT DISLODGES
	// THE RESIDENT. NO FLAG.
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
// HYBRID PER-CPU + PER-CCX OVERFLOW DESIGN:
//   SELECT_CPU -> PER-CPU DSQ (DEPTH-GATED, VISIBLE, STEALABLE)
//   ENQUEUE TIER 1/2 -> PER-CPU DSQ (WARM); SHAPE_STORM -> ccx_inter_dsq
//   ENQUEUE TIER 3 -> ccx_inter_dsq / ccx_batch_dsq (L3-LOCAL, SOJOURN-ORDERED)
//
// 0. OWN PER-CPU DSQ (CACHE-HOT, ZERO CONTENTION)
// 1. R_EFF STEAL (AFFINITY_RANK -- L2 SIBLING AT SLOT 0, R_EFF PEERS AT SLOTS 1+)
// SAFETY NET. SERVICE OLDER OVERFLOW SIDE PAST starvation_rescue_ns
// 2. SERVICE OLDER OVERFLOW SIDE PAST overflow_sojourn_rescue_ns
// 3. CCX-LOCAL INTERACTIVE OVERFLOW (ccx_inter_dsq[my_ccx])
// 4. CCX-LOCAL BATCH OVERFLOW (ccx_batch_dsq[my_ccx])
// 5. CROSS-CCX SCAN (WORK CONSERVATION ACROSS L3 FABRIC)
// 6. KEEP_RUNNING IF PREV STILL WANTS CPU AND NOTHING QUEUED
void BPF_STRUCT_OPS(pandemonium_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 my_ccx = cpu_ccx(cpu);
	struct pandemonium_stats *s;
	u64 now = bpf_ktime_get_ns();

	// STEP 0: OWN PER-CPU DSQ -- HIGHEST PRIORITY, CACHE-HOT.
	// SOJOURN GATE AT EXIT: IF EITHER OVERFLOW SIDE HAS AGED PAST
	// overflow_sojourn_rescue_ns, FALL THROUGH SO STEP 2 SERVES OVERFLOW
	// ON THIS DISPATCH TOO. WITHOUT THIS GATE, EVERY CPU WITH HOT PER-CPU
	// WORK NEVER VISITS OVERFLOW; SCX_WATCHDOG_WORKFN AND OTHER WORKQUEUE
	// WORKERS GET STARVED IN ccx_inter_dsq UNTIL THE 167MS SAFETY NET FIRES.
	if ((u64)cpu < nr_cpu_ids &&
	    scx_bpf_dsq_move_to_local((u64)cpu, 0)) {
		// Clear the DSQ-empty-cycle timestamp.
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
		s32 best_peer = -1;
		// SCAN RATE-LIMIT: the peer walk (affinity_rank lookup + per-peer
		// nr_queued) is the dominant per-dispatch cache cost under wake-heavy
		// LOADS. A PEER CANNOT ACCUMULATE STEALABLE BACKLOG (AGED PAST
		// codel_target + b*R_eff) FASTER THAN codel_target, SO SCANNING MORE
		// OFTEN THAN THAT IS PURE WASTE. GATE ON A PER-CPU TIMER; BETWEEN SCANS
		// WE FALL THROUGH TO OVERFLOW/IDLE AND tick()'s REMOTE SCAN STILL KICKS
		// ANY AGED PER-CPU DSQ, SO NO WORK IS STRANDED.
		u32 zero = 0;
		u64 *last_scan = bpf_map_lookup_elem(&last_spill_scan, &zero);
		bool do_scan = !last_scan || *last_scan == 0 ||
			       (now - *last_scan) >= codel_target_ns;
		if (do_scan && last_scan)
			*last_scan = now;
		// SOURCE: R_eff FLOW STEAL. affinity_rank IS DISTANCE-ORDERED (SLOT 0 =
		// L2 SIBLING), SO THE FIRST QUALIFYING PEER IS THE CLOSEST -- MIN-COST
		// FLOW. SURPLUS > 1 GUARD: a peer needs at least 2 queued before we pull
		// one (a lone warm task is never yanked). BOUNDED LOOP, LOCK-FREE
		// move_to_local.
		for (int i = 0; do_scan && i < MAX_AFFINITY_CANDIDATES; i++) {
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
			// SOJOURN = peer DSQ backlog age. 0 means the peer's per-CPU DSQ is
			// empty (stamp cleared on drain), so skip the remote DSQ-object touch
			// (scx_bpf_dsq_nr_queued) for idle peers -- the common wake-heavy case.
			u64 enq = pcpu_enqueue_ns[peer & (MAX_CPUS - 1)].ns;
			if (enq == 0) {
				if (++checked >= pcpu_spill_search_budget)
					break;
				continue;
			}
			u32 nq = scx_bpf_dsq_nr_queued((u64)peer);
			if (nq > 1) {
				// PHI STEAL-RESIST (SHAPE-BLIND): sojourn >= codel_target +
				// b*R_eff, built only from values we already produce. SOJOURN is
				// `enq` above (no remote head peek, no remote task_ctx deref). THE
				// DISTANCE PENALTY b*R_eff is pre-folded into reff_value at topology
				// detect (already ns), so the steal does ONE indexed read and no
				// multiply: an SMT sibling (R_eff~0) stays freely relievable while a
				// cross-CCX pull needs ~tau of sustained backlog. reff_value all-zero
				// (monolithic / --phi-scale 0) => flat codel_target, prior behavior.
				u32 *dxp = bpf_map_lookup_elem(&reff_value, &key);
				u32 dx = dxp ? *dxp : 0;
				u64 dist_extra = (dx == (u32)-1) ? 0 : (u64)dx;
				u64 phi_thresh = codel_target_ns + dist_extra;
				if (now >= enq && (now - enq) >= phi_thresh) {
					best_peer = (s32)peer;
					break;
				}
			}
			if (++checked >= pcpu_spill_search_budget)
				break;
		}
		if (best_peer >= 0 &&
		    scx_bpf_dsq_move_to_local((u64)best_peer, 0)) {
			pcpu_drain_clear((u32)best_peer);
			s = get_stats();
			if (s) {
				s->nr_dispatches += 1;
				// STEAL: task's home is best_peer, now consumed by `cpu`.
				xccx_bump(s, XCCX_STEAL, best_peer, cpu);
			}
			if (sojourn_gate_pass(now))
				return;
		}
	}

	// SAFETY NET: HARD STARVATION RESCUE. SERVICE WHICHEVER OVERFLOW SIDE
	// IS OLDER PAST starvation_rescue_ns (TAU-SCALED, ~167MS AT 12C).
	// CCX-LOCAL DRAIN FIRST, CROSS-CCX FALLBACK FOR WORK-CONSERVATION.
	if (try_service_older_overflow(now, my_ccx,
				       starvation_rescue_ns, false))
		return;

	// STEP 2: SERVICE OLDER OVERFLOW SIDE PAST overflow_sojourn_rescue_ns
	// (TAU-SCALED, ~10MS AT 12C). FEEDS THE OSCILLATOR.
	if (try_service_older_overflow(now, my_ccx,
				       overflow_sojourn_rescue_ns, true))
		return;

	// STEP 3: PER-CCX INTERACTIVE OVERFLOW (LOCAL). Cache-coherent drain
	// of my CCX's overflow DSQ.
	if (ccx_overflow_drain_local(my_ccx, false, &interactive_enqueue_ns)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// STEP 4: PER-CCX BATCH OVERFLOW (LOCAL).
	if (ccx_overflow_drain_local(my_ccx, true, &batch_enqueue_ns)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// STEP 5: CROSS-CCX WORK CONSERVATION. SCAN OTHER CCXs ONCE; DRAIN ANY
	// NON-EMPTY OVERFLOW (INTERACTIVE FIRST PER CCX, THEN BATCH). RUNS ONLY
	// WHEN THE LOCAL CCX IS EMPTY, SO CROSS-CCX MIGRATION HERE IS PURE
	// IDLE-TIME WORK CONSERVATION -- CACHE COST IS OFFSET BY AVOIDING IDLE
	// CORES. LOOP BOUND MAX_CCX_DOMAINS; nr_ccx CAPS EARLY-EXIT.
	for (u32 c = 0; c < MAX_CCX_DOMAINS; c++) {
		if (c >= nr_ccx)
			break;
		if (c == my_ccx)
			continue;
		if (overflow_drain_clear(ccx_inter_dsq(c),
					 &interactive_enqueue_ns)) {
			s = get_stats();
			if (s) {
				s->nr_dispatches += 1;
				// STEP 5 DRAINS CCX `c`'s OVERFLOW ONTO THIS CPU'S CCX:
				// ALWAYS CROSS-CCX BY CONSTRUCTION (c != my_ccx).
				if (s->nr_xccx[XCCX_STEP5] < ~0ULL)
					s->nr_xccx[XCCX_STEP5] += 1;
			}
			return;
		}
		if (overflow_drain_clear(ccx_batch_dsq(c),
					 &batch_enqueue_ns)) {
			s = get_stats();
			if (s) {
				s->nr_dispatches += 1;
				if (s->nr_xccx[XCCX_STEP5] < ~0ULL)
					s->nr_xccx[XCCX_STEP5] += 1;
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

// RUNNABLE: TASK WAKES UP -- BEHAVIORAL CLASSIFICATION ENGINE
void BPF_STRUCT_OPS(pandemonium_runnable, struct task_struct *p,
		    u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	u64 now = bpf_ktime_get_ns();
	tctx->ran_since_wake = false;

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

	// RT-POLICY FLOOR: SCHED_FIFO/SCHED_RR (PipeWire/JACK RT THREADS, THREADED
	// IRQ kthreads) ARE LATENCY-CRITICAL BY POLICY. PIN LAT_CRITICAL REGARDLESS
	// OF THE BEHAVIORAL SCORE AND THE kthread->BATCH OVERRIDE ABOVE.
	if (p->policy == SCHED_FIFO || p->policy == SCHED_RR)
		new_tier = TIER_LAT_CRITICAL;

	tctx->tier = new_tier;
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
	tctx->last_run_at = now;
	tctx->ran_since_wake = true;   // is_wakeup = !ran_since_wake

	// CLEAR enqueue_at AFTER CONSUME SO KEEP_RUNNING DOESN'T DOUBLE-COUNT.
	// THE PER-TASK MIN-SOJOURN DETECTOR THIS FED (pcpu_dsq_is_stalled)
	// WAS EXCISED IN PHASE 3; OSCILLATOR READS global_rescue_count DIRECTLY.
	if (tctx->enqueue_at > 0 && now > tctx->enqueue_at)
		tctx->enqueue_at = 0;

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
	scx_bpf_task_set_slice(p, task_slice(tctx, knobs));
}

// STOPPING: TASK YIELDS CPU -- UPDATE RUNTIME EWMA, DEMOTE CPU-BOUND TASKS
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

	u64 now = bpf_ktime_get_ns();
	u64 slice = now > tctx->last_run_at ? now - tctx->last_run_at : 0;
	{
		u64 avg = tctx->avg_runtime;
		u64 diff = slice > avg ? slice - avg : avg - slice;
		tctx->avg_runtime = calc_avg(avg, slice, tctx->ewma_age);
		tctx->runtime_dev = calc_avg(tctx->runtime_dev, diff,
					      tctx->ewma_age);
	}

	// CPU-BOUND DEMOTION. LONG-RUNNERS THAT NEVER SLEEP KEEP ewma_age
	// PINNED AT 1 (INCREMENTED ONLY ON SLEEP->RUNNABLE IN runnable()),
	// SO classify_tier NEVER RERUNS. THE CLASSIFIER-BASED PATH LEAVES
	// SUCH TASKS AT TIER_INTERACTIVE INDEFINITELY, WHICH MAKES THEM
	// UNPREEMPTIBLE BY tick() (ONLY TIER_BATCH RECEIVES THE TICK RESCUE
	// AT LINE ~2031). THRESHOLD SCALES WITH slice_ns: AN INTERACTIVE
	// LONG-RUNNER'S avg_runtime ASYMPTOTES TO THE SLICE CAP, SO A
	// FIXED-NS THRESHOLD ABOVE slice_ns CAN NEVER FIRE FOR THE EXACT
	// TASKS THE DEMOTION IS MEANT TO CATCH. 75% OF slice_cap CATCHES
	// PURE CPU-BOUND WITHIN ~6 STOP CYCLES (~6ms WALL). THE ewma_age
	// GUARD SPARES LEGIT INTERACTIVE TASKS THAT USE FULL SLICE BUT
	// SLEEP FREQUENTLY -- THEIR ewma_age GROWS ON EVERY SLEEP->WAKE.
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
	// topology_tau_ns (INITIAL DETECT OR HOTPLUG). NOT GATED TO CPU 0
	// BECAUSE THE ORIGINAL GATE LEFT A 1-50ms WINDOW BETWEEN RUST'S
	// write_topology_fields() AND THE FIRST CPU-0 TICK DURING WHICH
	// EVERY tau-DERIVED STATIC SAT AT ITS 12C-REFERENCE FALLBACK --
	// MATERIAL ON NON-12C TOPOLOGIES. THE FUNCTION IS IDEMPOTENT UNDER
	// NO-CHANGE (tau_ns == snap RETURNS IMMEDIATELY) AND THE
	// last_tau_snapshot CAS MAKES CONCURRENT CALLS FROM MULTIPLE CPUs
	// SAFE: FIRST NON-ZERO CALL WINS, SUBSEQUENT CALLS SHORT-CIRCUIT.
	// OVERHEAD: ~5ns SINGLE COMPARE PER TICK PER CPU WHEN UNCHANGED.
	apply_tau_scaling(knobs ? knobs->topology_tau_ns : 0,
	                  knobs ? knobs->codel_eq_ns : 0);

	// THE OSCILLATOR IS THE ONE DETECTOR. RESCUE DELTAS ARE THE ONLY SIGNAL
	// IT CONSUMES; IT ADAPTS codel_target_ns WHICH DRIVES THE PER-CPU CoDel
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
		// CPU 0 IS THE SOLE WRITER: ALIGNS WITH THE OSCILLATOR / TAU-
		// SCALING STATICS THAT ARE ALSO CPU-0-WRITTEN.
		// PREVENTS MULTI-CPU TICK RACES THAT FLICKERED THE BOOL UNDER
		// BURST WHILE batch_enqueue_ns WAS BEING SET/CLEARED VIA CAS.
		if (bpf_get_smp_processor_id() == 0)
			longrun_mode = sojourn > longrun_thresh_ns;

		// SOJOURN ENFORCEMENT: THRESHOLD SET BY RUST ADAPTIVE LAYER FROM
		// OBSERVED DISPATCH RATE. IF OVERFLOW HAS STARVED PAST THE THRESHOLD,
		// KICK THIS CPU TO FORCE A DISPATCH OF THE BURIED TASK.
		// PREEMPT BATCH *OR* INTERACTIVE RUNNERS: THE OLD "INTERACTIVE SLICES
		// ARE SHORT, THEY YIELD ON THEIR OWN" ASSUMPTION HOLDS IN ISOLATION BUT
		// BREAKS UNDER A FORK-STORM -- THE CORES RUN A CONVEYOR BELT OF
		// INTERACTIVE WORKERS, EACH YIELDING FAST ONLY FOR THE NEXT STORM
		// WORKER, SO THE BURIED TASK NEVER GETS IN. PREEMPTING AN INTERACTIVE
		// RUNNER UNDER SUSTAINED STARVATION IS THE JUST-ENOUGH BACK-PRESSURE
		// THAT LETS IT THROUGH; LATCRIT IS LEFT ALONE (GENUINELY TOP PRIORITY).
		// PER-CPU (NOT CPU-0-ONLY): EACH CPU SELF-PREEMPTS WHEN IT'S HOGGING.
		// KEY THE KICK ON THE R_eff OVERFLOW-GATE DELTA, NOT THE TIGHTER ADAPTIVE
		// sojourn_thresh: STEP 0/1 ONLY FALL THROUGH TO SERVE OVERFLOW ONCE THE
		// SOJOURN PASSES overflow_sojourn_rescue_ns, SO A KICK FIRED EARLIER JUST
		// LETS THE FREED CORE RE-GRAB ANOTHER STORM WORKER. ALIGNING THE TWO MEANS
		// THE PREEMPTED CORE ACTUALLY LANDS ON THE BURIED TASK ON RE-DISPATCH.
		if (sojourn > overflow_sojourn_rescue_ns) {
			struct task_ctx *tctx = lookup_task_ctx(p);
			if (tctx && (tctx->tier == TIER_BATCH ||
				     tctx->tier == TIER_INTERACTIVE)) {
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
			u64 pcpu_oldest = pcpu_enqueue_ns[this_cpu].ns;
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
					// SAME VERIFIER-PORTABLE MASK AS THE nr > 4 BRANCH (Issue #8).
					u32 scan_cpu = i & (MAX_CPUS - 1);
					if (scan_cpu == this_cpu)
						continue;
					u64 remote_stamp = pcpu_enqueue_ns[scan_cpu].ns;
					if (remote_stamp > 0 &&
					    (now2 - remote_stamp) > pcpu_sojourn_thresh)
						scx_bpf_kick_cpu(scan_cpu,
								 SCX_KICK_PREEMPT);
				}
			} else {
				u32 scan_base = (u32)(now2 >> 20);
				for (int i = 0; i < 4; i++) {
					// MASK THE INDEX, DO NOT COMPARISON-SKIP IT. OLDER-KERNEL
					// VERIFIERS CANNOT PROVE (scan_base + i) % nr IS BOUNDED, SO
					// pcpu_enqueue_ns[scan_cpu] TRIPS "math between map_value
					// pointer and register with unbounded min value" (Issue #8:
					// Ubuntu 25.10 / 5950X; newer kernels accept the bare % nr).
					// & (MAX_CPUS-1) IS A VERIFIER-PORTABLE BOUND, NOT A FOOTGUN
					// -- DO NOT "CLEAN IT UP" BACK INTO A >= MAX_CPUS SKIP.
					u32 scan_cpu =
						((scan_base + (u32)i) % nr) & (MAX_CPUS - 1);
					if (scan_cpu == this_cpu)
						continue;
					u64 remote_stamp = pcpu_enqueue_ns[scan_cpu].ns;
					if (remote_stamp > 0 &&
					    (now2 - remote_stamp) > pcpu_sojourn_thresh)
						scx_bpf_kick_cpu(scan_cpu,
								 SCX_KICK_PREEMPT);
				}
			}
		}
	}

	// PER-CPU PREEMPT: SIGNAL IS pcpu_enqueue_ns[this_cpu] (OLDEST WAITER AGE),
	// SO EACH CPU DECIDES FROM ITS OWN STATE -- NO GLOBAL TOKEN. THE COARSE
	// sojourn_thresh NET ABOVE HANDLED THE LONG-WAIT CASE; THIS IS THE TIGHT
	// BAND AT k*tau (preempt_thresh_ns): BATCH RESIDENT YIELDS AT THE BASE,
	// INTERACTIVE AT 2x, LAT_CRITICAL NEVER.
	u32 wcpu = bpf_get_smp_processor_id();
	if (wcpu >= MAX_CPUS)
		return;
	u64 waiter = pcpu_enqueue_ns[wcpu].ns;
	if (waiter == 0)
		return;

	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx || tctx->tier == TIER_LAT_CRITICAL)
		return;

	u64 wnow = bpf_ktime_get_ns();
	u64 wait_age = wnow > waiter ? wnow - waiter : 0;

	u64 base_thresh = knobs ? knobs->preempt_thresh_ns : 1000000;
	u64 batch_thresh = longrun_mode ? (base_thresh << longrun_preempt_shift)
			 : base_thresh;
	u64 thresh = tctx->tier == TIER_INTERACTIVE ? (batch_thresh << 1)
		   : batch_thresh;

	if (wait_age >= thresh) {
		scx_bpf_kick_cpu(wcpu, SCX_KICK_PREEMPT);
		if (!s)
			s = get_stats();
		if (s)
			s->nr_preempt += 1;
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
		// -1 = NEVER RAN: warm-anchor placement falls to scx_bpf_task_cpu(p)
		// instead of aliasing CPU 0. find_idle_l2_sibling already guards <0.
		tctx->last_cpu = -1;
		tctx->home_cpu = -1;   // pinned on first run (stopping)

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
	// ENQUEUE TIER 1/2 SEATS WAKEES ON A WARM PER-CPU DSQ; OVERFLOW
	// (TIER 3 / B-v2 ESCAPE) FALLS TO ccx_inter_dsq.
	// VISIBILITY LAYERS:
	//   1. L2 WORK STEALING IN DISPATCH -- IDLE CPUs PULL FROM SIBLINGS
	//   2. ROTATING TICK SCAN -- CATCHES STALE TASKS ON IDLE CPUs
	//   3. PER-CPU SOJOURN RESCUE -- THRESHOLD CEILING ON INVISIBILITY
	for (u32 i = 0; i < nr_cpu_ids && i < MAX_CPUS; i++)
		scx_bpf_create_dsq(i, -1);

	// CREATE PER-CCX OVERFLOW DSQs (INTERACTIVE + BATCH). MAX_CCX_DOMAINS
	// SLOTS PRE-ALLOCATED; nr_ccx (SET BY Rust POST-LOAD) GATES WHICH ARE LIVE.
	// PRE-ALLOCATING ALL MAX_CCX_DOMAINS COSTS A FEW UNUSED DSQ HEADERS, AVOIDS
	// THE BOOTSTRAP ORDER PROBLEM (pandemonium_init RUNS BEFORE TOPOLOGY DETECT).
	// THESE ARE L3-SCOPED, SO STEP 3/4 DRAIN STAYS CCX-LOCAL; STEP 5 SCANS
	// OTHER CCXs FOR WORK CONSERVATION WHEN THE LOCAL CCX IS EMPTY.
	for (u32 i = 0; i < MAX_CCX_DOMAINS; i++)
		scx_bpf_create_dsq(nr_cpu_ids + 2ULL * MAX_NODES + i, -1);
	for (u32 i = 0; i < MAX_CCX_DOMAINS; i++)
		scx_bpf_create_dsq(nr_cpu_ids + 2ULL * MAX_NODES + MAX_CCX_DOMAINS + i, -1);

	// ALL TIMING-CONSTANT AND OSCILLATOR-DYNAMICS STATICS BELOW ARE DERIVED
	// FROM tau (Fiedler-based time constant) VIA apply_tau_scaling() AT THE
	// FIRST CPU-0 TICK. MIDPOINT CONSTANTS HERE PROVIDE SANE BEHAVIOR DURING
	// THE ~1MS WINDOW BETWEEN struct_ops ATTACH AND THAT FIRST TICK. THEY
	// ARE OVERWRITTEN IMMEDIATELY -- DON'T READ SIGNIFICANCE INTO THEM.
	starvation_rescue_ns       = 100000000ULL;  // 100ms midpoint of [20, 500]
	overflow_sojourn_rescue_ns =   6000000ULL;  //   6ms midpoint of [4, 10]
	codel_target_floor_ns      =    500000ULL;  // 500us midpoint of [200, 800]
	pcpu_depth_base            = 2;             // 8C-12C MIDPOINT; apply_tau_scaling
	                                            //   recomputes continuously as
	                                            //   tau / K_DEPTH_THRESH_NS.
	pcpu_spill_search_budget   = 6;             // 12C MIDPOINT
	affinity_search_online     = 3;             // 12C MIDPOINT
	lag_cap_ns                 = 40000000ULL;   // 40MS = 12C REFERENCE
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
		knobs->lat_cri_thresh_high = LAT_CRI_THRESH_HIGH; // 32
		knobs->lat_cri_thresh_low  = LAT_CRI_THRESH_LOW;  // 8
		knobs->affinity_mode = 0;                // OFF BY DEFAULT (RUST SETS PER REGIME)
		knobs->sojourn_thresh_ns = 5000000;      // 5MS DEFAULT (RUST OVERRIDES)
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
//   1. ZERO HOT-PATH TIMESTAMPS DEFENSIVELY (enqueue_at,
//      sleep_start_ns) -- ANY STALE READ IN THE NARROW WINDOW
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
	tctx->enqueue_at = 0;
	tctx->sleep_start_ns = 0;
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
	// PORTABLE CALL: scx_bpf_reenqueue_local() RETURNS void ON v2 (NEWER)
	// KERNELS AND THROUGH scx's compat.bpf.h SHIM; CAPTURING ITS RETURN ONLY
	// COMPILED ON v1 (OLDER) KERNELS. CALL AS void -- THE RE-ENQUEUE STILL
	// HAPPENS; THE nr_reenqueue STAT IS NOT PORTABLY COUNTABLE HERE. (Issue #8
	// class: a kfunc signature that diverges across kernels / the scx build.)
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
	if ((u32)cpu < MAX_CPUS)
		__sync_lock_test_and_set(&pcpu_enqueue_ns[cpu].ns, 0);
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
	if ((u32)cpu < MAX_CPUS)
		__sync_lock_test_and_set(&pcpu_enqueue_ns[cpu].ns, 0);
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
	       .exit_task    = (void *)pandemonium_exit_task,
	       .exit         = (void *)pandemonium_exit,
	       .flags        = SCX_OPS_BUILTIN_IDLE_PER_NODE |
			       SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms   = 10000,
	       .name         = "pandemonium");